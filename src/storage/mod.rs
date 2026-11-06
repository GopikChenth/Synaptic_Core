//! Storage Engine: Embedded SQLite Metadata Index and Content-Addressable Storage (CAS).
//!
//! Maintains file manifests, Merkle DAG revisions, chunk deduplication index,
//! and quarantined conflict staging.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

/// Folder synchronization configuration and policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderRecord {
    pub folder_id: String,
    pub local_path: String,
    pub conflict_policy: String, // THREE_WAY_AUTO, LWW, MANUAL
    pub is_paused: bool,
}

/// File metadata index record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub folder_id: String,
    pub relative_path: String,
    pub size: u64,
    pub mtime_nanos: i64,
    pub current_revision: String,
    pub is_deleted: bool,
}

/// Revision record representing a node in the Merkle Revision DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionRecord {
    pub revision_hash: String,
    pub parent_1: Option<String>,
    pub parent_2: Option<String>,
    pub manifest_hash: String,
    pub author_device: String,
    pub created_at: i64,
}

/// Content-Addressable Chunk metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRecord {
    pub chunk_hash: String,
    pub size: usize,
    pub ref_count: u64,
}

/// Staged quarantine conflict awaiting resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConflict {
    pub conflict_id: String,
    pub folder_id: String,
    pub relative_path: String,
    pub base_revision: Option<String>,
    pub local_revision: String,
    pub remote_revision: String,
    pub staged_payload_path: String,
    pub status: String, // PENDING, RESOLVED, IGNORED
    pub detected_at: i64,
}

/// Central database and block storage manager.
#[derive(Clone)]
pub struct StorageEngine {
    conn: Arc<Mutex<Connection>>,
    blocks_dir: PathBuf,
    quarantine_dir: PathBuf,
}

impl StorageEngine {
    /// Initializes SQLite database and block storage directories inside the home folder.
    pub fn new(home_dir: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let db_path = home_dir.join("synapse_metadata.db");
        let blocks_dir = home_dir.join("blocks");
        let quarantine_dir = home_dir.join("quarantine");

        fs::create_dir_all(&blocks_dir)?;
        fs::create_dir_all(&quarantine_dir)?;

        let conn = Connection::open(&db_path)?;
        
        // Performance pragmas for embedded database
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA cache_size = -64000;", // 64MB cache
        )?;

        let engine = Self {
            conn: Arc::new(Mutex::new(conn)),
            blocks_dir,
            quarantine_dir,
        };

        engine.init_schema()?;
        Ok(engine)
    }

    /// Creates an in-memory storage engine for unit testing.
    pub fn in_memory(test_dir: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let blocks_dir = test_dir.join("blocks");
        let quarantine_dir = test_dir.join("quarantine");

        fs::create_dir_all(&blocks_dir)?;
        fs::create_dir_all(&quarantine_dir)?;

        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;",
        )?;

        let engine = Self {
            conn: Arc::new(Mutex::new(conn)),
            blocks_dir,
            quarantine_dir,
        };

        engine.init_schema()?;
        Ok(engine)
    }

    /// Initializes tables and indexes according to Section 7 of the specification.
    fn init_schema(&self) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            "
            -- Track registered folders
            CREATE TABLE IF NOT EXISTS folders (
                folder_id TEXT PRIMARY KEY,
                local_path TEXT NOT NULL,
                conflict_policy TEXT NOT NULL DEFAULT 'THREE_WAY_AUTO',
                is_paused INTEGER NOT NULL DEFAULT 0
            );

            -- File metadata state
            CREATE TABLE IF NOT EXISTS files (
                folder_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime_nanos INTEGER NOT NULL,
                current_revision TEXT NOT NULL,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (folder_id, relative_path),
                FOREIGN KEY (folder_id) REFERENCES folders(folder_id) ON DELETE CASCADE
            );

            -- Merkle Revision ancestry graph
            CREATE TABLE IF NOT EXISTS revisions (
                revision_hash TEXT PRIMARY KEY,
                parent_1 TEXT,
                parent_2 TEXT,
                manifest_hash TEXT NOT NULL,
                author_device TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            -- Content-Addressable Chunks (Deduplication store)
            CREATE TABLE IF NOT EXISTS chunks (
                chunk_hash TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                ref_count INTEGER NOT NULL DEFAULT 1
            );

            -- Mapping files to ordered chunk sequences
            CREATE TABLE IF NOT EXISTS file_chunks (
                revision_hash TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_hash TEXT NOT NULL,
                PRIMARY KEY (revision_hash, chunk_index),
                FOREIGN KEY (chunk_hash) REFERENCES chunks(chunk_hash)
            );

            -- Quarantined conflicts pending human or scheduled resolution
            CREATE TABLE IF NOT EXISTS quarantine_conflicts (
                conflict_id TEXT PRIMARY KEY,
                folder_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                base_revision TEXT,
                local_revision TEXT NOT NULL,
                remote_revision TEXT NOT NULL,
                staged_payload_path TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                detected_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id);
            CREATE INDEX IF NOT EXISTS idx_revisions_parent1 ON revisions(parent_1);
            CREATE INDEX IF NOT EXISTS idx_revisions_parent2 ON revisions(parent_2);
            CREATE INDEX IF NOT EXISTS idx_conflicts_status ON quarantine_conflicts(status);
            "
        )?;

        Ok(())
    }

    pub fn blocks_dir(&self) -> &Path {
        &self.blocks_dir
    }

    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    // =========================================================================
    // FOLDER OPERATIONS
    // =========================================================================

    pub fn add_folder(&self, folder: &FolderRecord) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO folders (folder_id, local_path, conflict_policy, is_paused)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(folder_id) DO UPDATE SET
                local_path = excluded.local_path,
                conflict_policy = excluded.conflict_policy,
                is_paused = excluded.is_paused",
            params![
                folder.folder_id,
                folder.local_path,
                folder.conflict_policy,
                if folder.is_paused { 1 } else { 0 },
            ],
        )?;
        Ok(())
    }

    pub fn list_folders(&self) -> SqlResult<Vec<FolderRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT folder_id, local_path, conflict_policy, is_paused FROM folders")?;
        let rows = stmt.query_map([], |row| {
            Ok(FolderRecord {
                folder_id: row.get(0)?,
                local_path: row.get(1)?,
                conflict_policy: row.get(2)?,
                is_paused: row.get::<_, i64>(3)? != 0,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    pub fn get_folder(&self, folder_id: &str) -> SqlResult<Option<FolderRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT folder_id, local_path, conflict_policy, is_paused FROM folders WHERE folder_id = ?1")?;
        let mut rows = stmt.query_map(params![folder_id], |row| {
            Ok(FolderRecord {
                folder_id: row.get(0)?,
                local_path: row.get(1)?,
                conflict_policy: row.get(2)?,
                is_paused: row.get::<_, i64>(3)? != 0,
            })
        })?;

        match rows.next() {
            Some(res) => Ok(Some(res?)),
            None => Ok(None),
        }
    }

    // =========================================================================
    // FILE OPERATIONS
    // =========================================================================

    pub fn upsert_file(&self, file: &FileRecord) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO files (folder_id, relative_path, size, mtime_nanos, current_revision, is_deleted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(folder_id, relative_path) DO UPDATE SET
                size = excluded.size,
                mtime_nanos = excluded.mtime_nanos,
                current_revision = excluded.current_revision,
                is_deleted = excluded.is_deleted",
            params![
                file.folder_id,
                file.relative_path,
                file.size as i64,
                file.mtime_nanos,
                file.current_revision,
                if file.is_deleted { 1 } else { 0 },
            ],
        )?;
        Ok(())
    }

    pub fn get_file(&self, folder_id: &str, relative_path: &str) -> SqlResult<Option<FileRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT folder_id, relative_path, size, mtime_nanos, current_revision, is_deleted
             FROM files WHERE folder_id = ?1 AND relative_path = ?2",
        )?;
        let mut rows = stmt.query_map(params![folder_id, relative_path], |row| {
            Ok(FileRecord {
                folder_id: row.get(0)?,
                relative_path: row.get(1)?,
                size: row.get::<_, i64>(2)? as u64,
                mtime_nanos: row.get(3)?,
                current_revision: row.get(4)?,
                is_deleted: row.get::<_, i64>(5)? != 0,
            })
        })?;

        match rows.next() {
            Some(res) => Ok(Some(res?)),
            None => Ok(None),
        }
    }

    pub fn list_files_in_folder(&self, folder_id: &str) -> SqlResult<Vec<FileRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT folder_id, relative_path, size, mtime_nanos, current_revision, is_deleted
             FROM files WHERE folder_id = ?1 AND is_deleted = 0",
        )?;
        let rows = stmt.query_map(params![folder_id], |row| {
            Ok(FileRecord {
                folder_id: row.get(0)?,
                relative_path: row.get(1)?,
                size: row.get::<_, i64>(2)? as u64,
                mtime_nanos: row.get(3)?,
                current_revision: row.get(4)?,
                is_deleted: row.get::<_, i64>(5)? != 0,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    // =========================================================================
    // REVISION OPERATIONS
    // =========================================================================

    pub fn insert_revision(&self, rev: &RevisionRecord, chunk_hashes: &[String]) -> SqlResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO revisions (revision_hash, parent_1, parent_2, manifest_hash, author_device, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(revision_hash) DO NOTHING",
            params![
                rev.revision_hash,
                rev.parent_1,
                rev.parent_2,
                rev.manifest_hash,
                rev.author_device,
                rev.created_at,
            ],
        )?;

        for (idx, hash) in chunk_hashes.iter().enumerate() {
            tx.execute(
                "INSERT INTO file_chunks (revision_hash, chunk_index, chunk_hash)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(revision_hash, chunk_index) DO NOTHING",
                params![rev.revision_hash, idx as i64, hash],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_revision(&self, revision_hash: &str) -> SqlResult<Option<RevisionRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT revision_hash, parent_1, parent_2, manifest_hash, author_device, created_at
             FROM revisions WHERE revision_hash = ?1",
        )?;
        let mut rows = stmt.query_map(params![revision_hash], |row| {
            Ok(RevisionRecord {
                revision_hash: row.get(0)?,
                parent_1: row.get(1)?,
                parent_2: row.get(2)?,
                manifest_hash: row.get(3)?,
                author_device: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;

        match rows.next() {
            Some(res) => Ok(Some(res?)),
            None => Ok(None),
        }
    }

    pub fn get_revision_chunks(&self, revision_hash: &str) -> SqlResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT chunk_hash FROM file_chunks WHERE revision_hash = ?1 ORDER BY chunk_index ASC",
        )?;
        let rows = stmt.query_map(params![revision_hash], |row| row.get::<_, String>(0))?;
        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    // =========================================================================
    // CAS BLOCK STORAGE OPERATIONS
    // =========================================================================

    fn get_chunk_file_path(&self, chunk_hash: &str) -> PathBuf {
        let prefix = if chunk_hash.len() >= 2 { &chunk_hash[0..2] } else { "xx" };
        let dir = self.blocks_dir.join(prefix);
        if !dir.exists() {
            let _ = fs::create_dir_all(&dir);
        }
        dir.join(format!("{}.chunk", chunk_hash))
    }

    /// Stores a chunk payload in the CAS store and updates the reference count in SQLite.
    pub fn put_chunk(&self, chunk_hash: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let file_path = self.get_chunk_file_path(chunk_hash);
        let exists = file_path.exists();

        if !exists {
            let mut file = File::create(&file_path)?;
            file.write_all(data)?;
            file.sync_all()?;
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO chunks (chunk_hash, size, ref_count)
             VALUES (?1, ?2, 1)
             ON CONFLICT(chunk_hash) DO UPDATE SET ref_count = ref_count + 1",
            params![chunk_hash, data.len() as i64],
        )?;

        Ok(())
    }

    /// Reads chunk payload bytes from the CAS block store.
    pub fn get_chunk(&self, chunk_hash: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let file_path = self.get_chunk_file_path(chunk_hash);
        if !file_path.exists() {
            return Ok(None);
        }
        let mut file = File::open(&file_path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    /// Checks if a chunk is locally available in CAS.
    pub fn has_chunk(&self, chunk_hash: &str) -> bool {
        self.get_chunk_file_path(chunk_hash).exists()
    }

    /// Assembles an entire file from its ordered chunk list.
    pub fn read_file_from_revision(&self, revision_hash: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let chunk_hashes = self.get_revision_chunks(revision_hash)?;
        let mut payload = Vec::new();
        for hash in &chunk_hashes {
            match self.get_chunk(hash)? {
                Some(chunk_bytes) => payload.extend_from_slice(&chunk_bytes),
                None => {
                    return Err(format!("Missing chunk {} in CAS store", hash).into());
                }
            }
        }
        Ok(payload)
    }

    // =========================================================================
    // QUARANTINE OPERATIONS
    // =========================================================================

    /// Registers a quarantined conflict and writes the incoming conflicting payload to the staging area.
    pub fn stage_quarantine_conflict(
        &self,
        conflict_id: &str,
        folder_id: &str,
        relative_path: &str,
        base_revision: Option<&str>,
        local_revision: &str,
        remote_revision: &str,
        remote_payload: &[u8],
    ) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let ext = Path::new(relative_path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("bin");
        let staged_file_name = format!("{}.{}", conflict_id, ext);
        let staged_path = self.quarantine_dir.join(&staged_file_name);

        let mut file = File::create(&staged_path)?;
        file.write_all(remote_payload)?;
        file.sync_all()?;

        let detected_at = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO quarantine_conflicts (
                conflict_id, folder_id, relative_path, base_revision,
                local_revision, remote_revision, staged_payload_path, status, detected_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'PENDING', ?8)
            ON CONFLICT(conflict_id) DO UPDATE SET
                base_revision = excluded.base_revision,
                local_revision = excluded.local_revision,
                remote_revision = excluded.remote_revision,
                staged_payload_path = excluded.staged_payload_path,
                status = 'PENDING',
                detected_at = excluded.detected_at",
            params![
                conflict_id,
                folder_id,
                relative_path,
                base_revision,
                local_revision,
                remote_revision,
                staged_path.to_string_lossy().to_string(),
                detected_at,
            ],
        )?;

        Ok(staged_path)
    }

    pub fn list_pending_conflicts(&self) -> SqlResult<Vec<QuarantineConflict>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT conflict_id, folder_id, relative_path, base_revision,
                    local_revision, remote_revision, staged_payload_path, status, detected_at
             FROM quarantine_conflicts WHERE status = 'PENDING' ORDER BY detected_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(QuarantineConflict {
                conflict_id: row.get(0)?,
                folder_id: row.get(1)?,
                relative_path: row.get(2)?,
                base_revision: row.get(3)?,
                local_revision: row.get(4)?,
                remote_revision: row.get(5)?,
                staged_payload_path: row.get(6)?,
                status: row.get(7)?,
                detected_at: row.get(8)?,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    pub fn get_conflict(&self, conflict_id: &str) -> SqlResult<Option<QuarantineConflict>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT conflict_id, folder_id, relative_path, base_revision,
                    local_revision, remote_revision, staged_payload_path, status, detected_at
             FROM quarantine_conflicts WHERE conflict_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![conflict_id], |row| {
            Ok(QuarantineConflict {
                conflict_id: row.get(0)?,
                folder_id: row.get(1)?,
                relative_path: row.get(2)?,
                base_revision: row.get(3)?,
                local_revision: row.get(4)?,
                remote_revision: row.get(5)?,
                staged_payload_path: row.get(6)?,
                status: row.get(7)?,
                detected_at: row.get(8)?,
            })
        })?;

        match rows.next() {
            Some(res) => Ok(Some(res?)),
            None => Ok(None),
        }
    }

    pub fn resolve_conflict(&self, conflict_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conflict = self.get_conflict(conflict_id)?;
        if let Some(c) = conflict {
            // Delete staged quarantine file if present
            let path = PathBuf::from(&c.staged_payload_path);
            if path.exists() {
                let _ = fs::remove_file(path);
            }
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE quarantine_conflicts SET status = 'RESOLVED' WHERE conflict_id = ?1",
            params![conflict_id],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_engine_crud() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_test_{}", uuid::Uuid::new_v4()));
        let engine = StorageEngine::new(&temp_dir).unwrap();

        // 1. Add folder
        let folder = FolderRecord {
            folder_id: "test_vault".into(),
            local_path: "/tmp/test".into(),
            conflict_policy: "THREE_WAY_AUTO".into(),
            is_paused: false,
        };
        engine.add_folder(&folder).unwrap();
        let folders = engine.list_folders().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].folder_id, "test_vault");

        // 2. Put chunk and check CAS
        let chunk_hash = "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";
        let chunk_data = b"Synapse CAS test block payload";
        engine.put_chunk(chunk_hash, chunk_data).unwrap();
        assert!(engine.has_chunk(chunk_hash));
        let retrieved = engine.get_chunk(chunk_hash).unwrap().unwrap();
        assert_eq!(retrieved, chunk_data);

        // 3. Staging quarantine conflict
        let conflict_path = engine.stage_quarantine_conflict(
            "cnf_test1",
            "test_vault",
            "doc.md",
            None,
            "rev_local",
            "rev_remote",
            b"Conflicting remote content",
        ).unwrap();
        assert!(conflict_path.exists());

        let pending = engine.list_pending_conflicts().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].conflict_id, "cnf_test1");

        // 4. Resolve conflict
        engine.resolve_conflict("cnf_test1").unwrap();
        assert!(!conflict_path.exists());
        let pending_after = engine.list_pending_conflicts().unwrap();
        assert_eq!(pending_after.len(), 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
