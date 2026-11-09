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
    #[serde(alias = "id")]
    pub folder_id: String,
    #[serde(alias = "path")]
    pub local_path: String,
    #[serde(default = "default_policy")]
    pub conflict_policy: String, // THREE_WAY_AUTO, LWW, MANUAL
    #[serde(default, alias = "paused")]
    pub is_paused: bool,
    #[serde(default = "default_sync_mode", alias = "type")]
    pub sync_mode: String, // SendReceive, SendOnly, ReceiveOnly
    #[serde(default = "default_pull_order")]
    pub pull_order: String, // Alphabetical, SmallestFirst, LargestFirst, NewestFirst, OldestFirst
    #[serde(default = "default_versioning_type")]
    pub versioning_type: String, // None, TrashCan, Simple, Staggered
    #[serde(default = "default_versioning_keep_days")]
    pub versioning_keep_days: i64,
    #[serde(default = "default_marker_name")]
    pub marker_name: String, // .synapse-folder
}

fn default_policy() -> String { "THREE_WAY_AUTO".to_string() }
fn default_sync_mode() -> String { "SendReceive".to_string() }
fn default_pull_order() -> String { "Alphabetical".to_string() }
fn default_versioning_type() -> String { "None".to_string() }
fn default_versioning_keep_days() -> i64 { 30 }
fn default_marker_name() -> String { ".synapse-folder".to_string() }

impl FolderRecord {
    pub fn new(folder_id: impl Into<String>, local_path: impl Into<String>) -> Self {
        Self {
            folder_id: folder_id.into(),
            local_path: local_path.into(),
            conflict_policy: "THREE_WAY_AUTO".to_string(),
            is_paused: false,
            sync_mode: default_sync_mode(),
            pull_order: default_pull_order(),
            versioning_type: default_versioning_type(),
            versioning_keep_days: default_versioning_keep_days(),
            marker_name: default_marker_name(),
        }
    }

    pub fn parsed_sync_mode(&self) -> crate::state::SyncMode {
        self.sync_mode.parse().unwrap_or_default()
    }

    pub fn parsed_conflict_policy(&self) -> crate::state::ConflictPolicy {
        self.conflict_policy.parse().unwrap_or_default()
    }
}

/// Device record in cluster pairing database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    #[serde(alias = "deviceID", alias = "id")]
    pub device_id: String, // Luhn-check formatted (XXXXXXX-XXXXXXX-...)
    pub name: String,
    pub addresses: Vec<String>,
    #[serde(default, alias = "paused")]
    pub is_paused: bool,
    #[serde(default)]
    pub is_trusted: bool,
    #[serde(default)]
    pub introducer: bool,
    #[serde(default)]
    pub cert_name: Option<String>,
    #[serde(default)]
    pub created_at: i64,
}

/// Pending incoming device pairing request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeviceRecord {
    pub device_id: String,
    pub name: String,
    pub address: String,
    pub received_at: i64,
}

/// Introduced device payload announced by an introducer peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntroducedDevice {
    pub device_id: String,
    pub name: String,
    pub addresses: Vec<String>,
    pub is_trusted: bool,
    #[serde(default)]
    pub cert_name: Option<String>,
}

/// Propagation outcome summary when an introducer announces cluster devices.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct IntroducerPropagationResult {
    pub introducer_id: String,
    pub added_trusted: Vec<String>,
    pub added_pending: Vec<String>,
    pub updated: Vec<String>,
    pub ignored: Vec<String>,
}

/// Pending incoming folder invitation from remote peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingFolderRecord {
    pub folder_id: String,
    pub device_id: String,
    pub folder_label: String,
    pub offered_at: i64,
}

/// Folder sync metrics for UI status dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderStatusMetrics {
    #[serde(alias = "folder", alias = "folderId")]
    pub folder_id: String,
    pub state: String, // "idle", "scanning", "syncing", "error"
    #[serde(alias = "globalFiles")]
    pub global_files: u64,
    #[serde(alias = "globalBytes")]
    pub global_bytes: u64,
    #[serde(alias = "localFiles")]
    pub local_files: u64,
    #[serde(alias = "localBytes")]
    pub local_bytes: u64,
    #[serde(alias = "needFiles")]
    pub need_files: u64,
    #[serde(alias = "needBytes")]
    pub need_bytes: u64,
    #[serde(alias = "inSyncBytes")]
    pub in_sync_bytes: u64,
    #[serde(alias = "completionPct", alias = "completion")]
    pub completion_pct: f64,
    pub sequence: u64,
}

/// Folder completion percentage per remote device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCompletionMetrics {
    #[serde(alias = "deviceId", alias = "device")]
    pub device_id: String,
    #[serde(alias = "folderId", alias = "folder")]
    pub folder_id: String,
    #[serde(alias = "completion")]
    pub completion_pct: f64,
    #[serde(alias = "globalBytes")]
    pub global_bytes: u64,
    #[serde(alias = "needBytes")]
    pub need_bytes: u64,
}

/// Real-time peer connection statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnectionMetrics {
    pub device_id: String,
    pub address: String,
    pub is_connected: bool,
    pub in_bps: u64,
    pub out_bps: u64,
    pub total_in_bytes: u64,
    pub total_out_bytes: u64,
    pub latency_ms: u64,
    pub client_type: String,
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

impl QuarantineConflict {
    pub fn parsed_status(&self) -> crate::state::ConflictStatus {
        self.status.parse().unwrap_or_default()
    }
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
                is_paused INTEGER NOT NULL DEFAULT 0,
                sync_mode TEXT NOT NULL DEFAULT 'SendReceive',
                pull_order TEXT NOT NULL DEFAULT 'Alphabetical',
                versioning_type TEXT NOT NULL DEFAULT 'None',
                versioning_keep_days INTEGER NOT NULL DEFAULT 30,
                marker_name TEXT NOT NULL DEFAULT '.synapse-folder'
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

            -- Cluster & Paired Devices
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                addresses TEXT NOT NULL DEFAULT 'dynamic',
                is_paused INTEGER NOT NULL DEFAULT 0,
                is_trusted INTEGER NOT NULL DEFAULT 1,
                introducer INTEGER NOT NULL DEFAULT 0,
                cert_name TEXT,
                created_at INTEGER NOT NULL
            );

            -- Pending incoming device pairings
            CREATE TABLE IF NOT EXISTS pending_devices (
                device_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                received_at INTEGER NOT NULL
            );

            -- Folder Sharing Matrix (Which folders are shared with which devices)
            CREATE TABLE IF NOT EXISTS folder_devices (
                folder_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                PRIMARY KEY (folder_id, device_id),
                FOREIGN KEY (folder_id) REFERENCES folders(folder_id) ON DELETE CASCADE
            );

            -- Pending incoming folder invitations
            CREATE TABLE IF NOT EXISTS pending_folders (
                folder_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                folder_label TEXT NOT NULL,
                offered_at INTEGER NOT NULL,
                PRIMARY KEY (folder_id, device_id)
            );

            -- Folder Ignore Patterns (.synapseignore/.stignore rules)
            CREATE TABLE IF NOT EXISTS folder_ignores (
                folder_id TEXT NOT NULL,
                pattern TEXT NOT NULL,
                PRIMARY KEY (folder_id, pattern),
                FOREIGN KEY (folder_id) REFERENCES folders(folder_id) ON DELETE CASCADE
            );

            -- Historical File Versions
            CREATE TABLE IF NOT EXISTS file_versions (
                version_id TEXT PRIMARY KEY,
                folder_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                archived_path TEXT NOT NULL,
                archived_at INTEGER NOT NULL,
                size INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id);
            CREATE INDEX IF NOT EXISTS idx_revisions_parent1 ON revisions(parent_1);
            CREATE INDEX IF NOT EXISTS idx_revisions_parent2 ON revisions(parent_2);
            CREATE INDEX IF NOT EXISTS idx_conflicts_status ON quarantine_conflicts(status);
            CREATE INDEX IF NOT EXISTS idx_folder_devices_folder ON folder_devices(folder_id);
            CREATE INDEX IF NOT EXISTS idx_file_versions_folder ON file_versions(folder_id);
            "
        )?;

        // Safe migrations for folders table columns if upgraded from earlier schema
        let _ = conn.execute("ALTER TABLE folders ADD COLUMN sync_mode TEXT NOT NULL DEFAULT 'SendReceive'", []);
        let _ = conn.execute("ALTER TABLE folders ADD COLUMN pull_order TEXT NOT NULL DEFAULT 'Alphabetical'", []);
        let _ = conn.execute("ALTER TABLE folders ADD COLUMN versioning_type TEXT NOT NULL DEFAULT 'None'", []);
        let _ = conn.execute("ALTER TABLE folders ADD COLUMN versioning_keep_days INTEGER NOT NULL DEFAULT 30", []);
        let _ = conn.execute("ALTER TABLE folders ADD COLUMN marker_name TEXT NOT NULL DEFAULT '.synapse-folder'", []);

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
            "INSERT INTO folders (
                folder_id, local_path, conflict_policy, is_paused,
                sync_mode, pull_order, versioning_type, versioning_keep_days, marker_name
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(folder_id) DO UPDATE SET
                local_path = excluded.local_path,
                conflict_policy = excluded.conflict_policy,
                is_paused = excluded.is_paused,
                sync_mode = excluded.sync_mode,
                pull_order = excluded.pull_order,
                versioning_type = excluded.versioning_type,
                versioning_keep_days = excluded.versioning_keep_days,
                marker_name = excluded.marker_name",
            params![
                folder.folder_id,
                folder.local_path,
                folder.conflict_policy,
                if folder.is_paused { 1 } else { 0 },
                folder.sync_mode,
                folder.pull_order,
                folder.versioning_type,
                folder.versioning_keep_days,
                folder.marker_name,
            ],
        )?;
        Ok(())
    }

    pub fn list_folders(&self) -> SqlResult<Vec<FolderRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT folder_id, local_path, conflict_policy, is_paused,
                    sync_mode, pull_order, versioning_type, versioning_keep_days, marker_name
             FROM folders",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(FolderRecord {
                folder_id: row.get(0)?,
                local_path: row.get(1)?,
                conflict_policy: row.get(2)?,
                is_paused: row.get::<_, i64>(3)? != 0,
                sync_mode: row.get(4).unwrap_or_else(|_| default_sync_mode()),
                pull_order: row.get(5).unwrap_or_else(|_| default_pull_order()),
                versioning_type: row.get(6).unwrap_or_else(|_| default_versioning_type()),
                versioning_keep_days: row.get(7).unwrap_or_else(|_| default_versioning_keep_days()),
                marker_name: row.get(8).unwrap_or_else(|_| default_marker_name()),
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
        let mut stmt = conn.prepare(
            "SELECT folder_id, local_path, conflict_policy, is_paused,
                    sync_mode, pull_order, versioning_type, versioning_keep_days, marker_name
             FROM folders WHERE folder_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![folder_id], |row| {
            Ok(FolderRecord {
                folder_id: row.get(0)?,
                local_path: row.get(1)?,
                conflict_policy: row.get(2)?,
                is_paused: row.get::<_, i64>(3)? != 0,
                sync_mode: row.get(4).unwrap_or_else(|_| default_sync_mode()),
                pull_order: row.get(5).unwrap_or_else(|_| default_pull_order()),
                versioning_type: row.get(6).unwrap_or_else(|_| default_versioning_type()),
                versioning_keep_days: row.get(7).unwrap_or_else(|_| default_versioning_keep_days()),
                marker_name: row.get(8).unwrap_or_else(|_| default_marker_name()),
            })
        })?;

        match rows.next() {
            Some(res) => Ok(Some(res?)),
            None => Ok(None),
        }
    }

    pub fn set_folder_paused(&self, folder_id: &str, paused: bool) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE folders SET is_paused = ?1 WHERE folder_id = ?2",
            params![if paused { 1 } else { 0 }, folder_id],
        )?;
        Ok(())
    }

    pub fn delete_folder(&self, folder_id: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM folders WHERE folder_id = ?1", params![folder_id])?;
        Ok(())
    }

    // =========================================================================
    // CLUSTER & DEVICE OPERATIONS
    // =========================================================================

    pub fn add_device(&self, device: &DeviceRecord) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        let addrs_json = serde_json::to_string(&device.addresses).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO devices (
                device_id, name, addresses, is_paused, is_trusted, introducer, cert_name, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(device_id) DO UPDATE SET
                name = excluded.name,
                addresses = excluded.addresses,
                is_paused = excluded.is_paused,
                is_trusted = excluded.is_trusted,
                introducer = excluded.introducer,
                cert_name = excluded.cert_name",
            params![
                device.device_id,
                device.name,
                addrs_json,
                if device.is_paused { 1 } else { 0 },
                if device.is_trusted { 1 } else { 0 },
                if device.introducer { 1 } else { 0 },
                device.cert_name,
                device.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn list_devices(&self) -> SqlResult<Vec<DeviceRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, name, addresses, is_paused, is_trusted, introducer, cert_name, created_at FROM devices",
        )?;
        let rows = stmt.query_map([], |row| {
            let addrs_raw: String = row.get(2)?;
            let addresses: Vec<String> = serde_json::from_str(&addrs_raw).unwrap_or_default();
            Ok(DeviceRecord {
                device_id: row.get(0)?,
                name: row.get(1)?,
                addresses,
                is_paused: row.get::<_, i64>(3)? != 0,
                is_trusted: row.get::<_, i64>(4)? != 0,
                introducer: row.get::<_, i64>(5)? != 0,
                cert_name: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    pub fn get_device(&self, device_id: &str) -> SqlResult<Option<DeviceRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, name, addresses, is_paused, is_trusted, introducer, cert_name, created_at
             FROM devices WHERE device_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![device_id], |row| {
            let addrs_raw: String = row.get(2)?;
            let addresses: Vec<String> = serde_json::from_str(&addrs_raw).unwrap_or_default();
            Ok(DeviceRecord {
                device_id: row.get(0)?,
                name: row.get(1)?,
                addresses,
                is_paused: row.get::<_, i64>(3)? != 0,
                is_trusted: row.get::<_, i64>(4)? != 0,
                introducer: row.get::<_, i64>(5)? != 0,
                cert_name: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;

        match rows.next() {
            Some(res) => Ok(Some(res?)),
            None => Ok(None),
        }
    }

    pub fn remove_device(&self, device_id: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM devices WHERE device_id = ?1", params![device_id])?;
        conn.execute("DELETE FROM folder_devices WHERE device_id = ?1", params![device_id])?;
        Ok(())
    }

    pub fn set_device_paused(&self, device_id: &str, paused: bool) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE devices SET is_paused = ?1 WHERE device_id = ?2",
            params![if paused { 1 } else { 0 }, device_id],
        )?;
        Ok(())
    }

    pub fn is_device_introducer(&self, device_id: &str) -> SqlResult<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT introducer FROM devices WHERE device_id = ?1")?;
        let mut rows = stmt.query_map(params![device_id], |row| row.get::<_, i64>(0))?;
        if let Some(r) = rows.next() {
            Ok(r? != 0)
        } else {
            Ok(false)
        }
    }

    pub fn set_device_introducer(&self, device_id: &str, introducer: bool) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE devices SET introducer = ?1 WHERE device_id = ?2",
            params![if introducer { 1 } else { 0 }, device_id],
        )?;
        Ok(())
    }

    pub fn is_device_trusted(&self, device_id: &str) -> SqlResult<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT is_trusted FROM devices WHERE device_id = ?1")?;
        let mut rows = stmt.query_map(params![device_id], |row| row.get::<_, i64>(0))?;
        if let Some(r) = rows.next() {
            Ok(r? != 0)
        } else {
            Ok(false)
        }
    }

    pub fn set_device_trusted(&self, device_id: &str, is_trusted: bool) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE devices SET is_trusted = ?1 WHERE device_id = ?2",
            params![if is_trusted { 1 } else { 0 }, device_id],
        )?;
        Ok(())
    }

    pub fn list_introducer_devices(&self) -> SqlResult<Vec<DeviceRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, name, addresses, is_paused, is_trusted, introducer, cert_name, created_at FROM devices WHERE introducer != 0",
        )?;
        let rows = stmt.query_map([], |row| {
            let addrs_raw: String = row.get(2)?;
            let addresses: Vec<String> = serde_json::from_str(&addrs_raw).unwrap_or_default();
            Ok(DeviceRecord {
                device_id: row.get(0)?,
                name: row.get(1)?,
                addresses,
                is_paused: row.get::<_, i64>(3)? != 0,
                is_trusted: row.get::<_, i64>(4)? != 0,
                introducer: row.get::<_, i64>(5)? != 0,
                cert_name: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    pub fn list_untrusted_devices(&self) -> SqlResult<Vec<DeviceRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, name, addresses, is_paused, is_trusted, introducer, cert_name, created_at FROM devices WHERE is_trusted = 0",
        )?;
        let rows = stmt.query_map([], |row| {
            let addrs_raw: String = row.get(2)?;
            let addresses: Vec<String> = serde_json::from_str(&addrs_raw).unwrap_or_default();
            Ok(DeviceRecord {
                device_id: row.get(0)?,
                name: row.get(1)?,
                addresses,
                is_paused: row.get::<_, i64>(3)? != 0,
                is_trusted: row.get::<_, i64>(4)? != 0,
                introducer: row.get::<_, i64>(5)? != 0,
                cert_name: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    /// Propagates cluster devices announced by an introducer peer.
    ///
    /// When `introducer_id` is marked as an introducer (`introducer = 1`):
    /// - If `auto_trust` is true: automatically adds new devices to trusted `devices` table.
    /// - If `auto_trust` is false: adds new devices to `pending_devices` table for user pairing review.
    /// - If device already exists in `devices`: merges addresses.
    /// - If `introducer_id` is NOT marked with `introducer = 1`: ignores announcement (preventing spoofing).
    pub fn propagate_introducer_devices(
        &self,
        introducer_id: &str,
        announced_devices: &[IntroducedDevice],
        auto_trust: bool,
    ) -> SqlResult<IntroducerPropagationResult> {
        let mut result = IntroducerPropagationResult {
            introducer_id: introducer_id.to_string(),
            added_trusted: Vec::new(),
            added_pending: Vec::new(),
            updated: Vec::new(),
            ignored: Vec::new(),
        };

        // Security check: Only verified introducers may announce cluster devices
        if !self.is_device_introducer(introducer_id)? {
            tracing::warn!("Ignored cluster device announcement from non-introducer peer {}", introducer_id);
            return Ok(result);
        }

        let now = chrono::Utc::now().timestamp_millis();

        for dev in announced_devices {
            // Cannot introduce itself
            if dev.device_id == introducer_id {
                result.ignored.push(dev.device_id.clone());
                continue;
            }

            // Check if device already paired in devices table
            if let Some(existing) = self.get_device(&dev.device_id)? {
                let mut updated_addrs = existing.addresses;
                let mut changed = false;
                for a in &dev.addresses {
                    if !updated_addrs.contains(a) {
                        updated_addrs.push(a.clone());
                        changed = true;
                    }
                }
                if changed {
                    let conn = self.conn.lock().unwrap();
                    let addrs_json = serde_json::to_string(&updated_addrs).unwrap_or_else(|_| "[]".to_string());
                    conn.execute(
                        "UPDATE devices SET addresses = ?1 WHERE device_id = ?2",
                        params![addrs_json, dev.device_id],
                    )?;
                }
                result.updated.push(dev.device_id.clone());
                continue;
            }

            // Check if already in pending_devices
            let in_pending = {
                let conn = self.conn.lock().unwrap();
                let mut stmt = conn.prepare("SELECT 1 FROM pending_devices WHERE device_id = ?1")?;
                stmt.exists(params![dev.device_id])?
            };

            if auto_trust {
                if in_pending {
                    self.accept_pending_device(&dev.device_id)?;
                } else {
                    let record = DeviceRecord {
                        device_id: dev.device_id.clone(),
                        name: dev.name.clone(),
                        addresses: dev.addresses.clone(),
                        is_paused: false,
                        is_trusted: dev.is_trusted,
                        introducer: false,
                        cert_name: dev.cert_name.clone(),
                        created_at: now,
                    };
                    self.add_device(&record)?;
                }
                result.added_trusted.push(dev.device_id.clone());
            } else if !in_pending {
                let address = dev.addresses.first().cloned().unwrap_or_else(|| "dynamic".into());
                let pending = PendingDeviceRecord {
                    device_id: dev.device_id.clone(),
                    name: dev.name.clone(),
                    address,
                    received_at: now,
                };
                self.add_pending_device(&pending)?;
                result.added_pending.push(dev.device_id.clone());
            } else {
                result.ignored.push(dev.device_id.clone());
            }
        }

        Ok(result)
    }

    // =========================================================================
    // PENDING PAIRING OPERATIONS
    // =========================================================================

    pub fn add_pending_device(&self, rec: &PendingDeviceRecord) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pending_devices (device_id, name, address, received_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(device_id) DO UPDATE SET
                name = excluded.name,
                address = excluded.address,
                received_at = excluded.received_at",
            params![rec.device_id, rec.name, rec.address, rec.received_at],
        )?;
        Ok(())
    }

    pub fn list_pending_devices(&self) -> SqlResult<Vec<PendingDeviceRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, name, address, received_at FROM pending_devices ORDER BY received_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PendingDeviceRecord {
                device_id: row.get(0)?,
                name: row.get(1)?,
                address: row.get(2)?,
                received_at: row.get(3)?,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    pub fn get_pending_device(&self, device_id: &str) -> SqlResult<Option<PendingDeviceRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, name, address, received_at FROM pending_devices WHERE device_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![device_id], |row| {
            Ok(PendingDeviceRecord {
                device_id: row.get(0)?,
                name: row.get(1)?,
                address: row.get(2)?,
                received_at: row.get(3)?,
            })
        })?;

        match rows.next() {
            Some(res) => Ok(Some(res?)),
            None => Ok(None),
        }
    }

    pub fn accept_pending_device(&self, device_id: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, name, address, received_at FROM pending_devices WHERE device_id = ?1",
        )?;
        let pending = stmt.query_row(params![device_id], |row| {
            Ok(PendingDeviceRecord {
                device_id: row.get(0)?,
                name: row.get(1)?,
                address: row.get(2)?,
                received_at: row.get(3)?,
            })
        })?;

        let addrs = vec![pending.address];
        let addrs_json = serde_json::to_string(&addrs).unwrap_or_else(|_| "[]".to_string());

        conn.execute(
            "INSERT INTO devices (device_id, name, addresses, is_paused, is_trusted, introducer, cert_name, created_at)
             VALUES (?1, ?2, ?3, 0, 1, 0, NULL, ?4)
             ON CONFLICT(device_id) DO UPDATE SET name = excluded.name",
            params![pending.device_id, pending.name, addrs_json, pending.received_at],
        )?;

        conn.execute("DELETE FROM pending_devices WHERE device_id = ?1", params![device_id])?;
        Ok(())
    }

    pub fn reject_pending_device(&self, device_id: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM pending_devices WHERE device_id = ?1", params![device_id])?;
        Ok(())
    }

    // =========================================================================
    // FOLDER SHARING MATRIX OPERATIONS
    // =========================================================================

    pub fn share_folder_with_device(&self, folder_id: &str, device_id: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO folder_devices (folder_id, device_id) VALUES (?1, ?2)",
            params![folder_id, device_id],
        )?;
        Ok(())
    }

    pub fn unshare_folder_from_device(&self, folder_id: &str, device_id: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM folder_devices WHERE folder_id = ?1 AND device_id = ?2",
            params![folder_id, device_id],
        )?;
        Ok(())
    }

    pub fn list_folder_devices(&self, folder_id: &str) -> SqlResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT device_id FROM folder_devices WHERE folder_id = ?1")?;
        let rows = stmt.query_map(params![folder_id], |row| row.get::<_, String>(0))?;
        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    // =========================================================================
    // PENDING FOLDER INVITATIONS
    // =========================================================================

    pub fn add_pending_folder(&self, rec: &PendingFolderRecord) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pending_folders (folder_id, device_id, folder_label, offered_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(folder_id, device_id) DO UPDATE SET
                folder_label = excluded.folder_label,
                offered_at = excluded.offered_at",
            params![rec.folder_id, rec.device_id, rec.folder_label, rec.offered_at],
        )?;
        Ok(())
    }

    pub fn list_pending_folders(&self) -> SqlResult<Vec<PendingFolderRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT folder_id, device_id, folder_label, offered_at FROM pending_folders ORDER BY offered_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PendingFolderRecord {
                folder_id: row.get(0)?,
                device_id: row.get(1)?,
                folder_label: row.get(2)?,
                offered_at: row.get(3)?,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    pub fn accept_pending_folder(&self, folder_id: &str, device_id: &str, local_path: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        // Create folder locally if not exists
        conn.execute(
            "INSERT OR IGNORE INTO folders (folder_id, local_path, conflict_policy, is_paused)
             VALUES (?1, ?2, 'THREE_WAY_AUTO', 0)",
            params![folder_id, local_path],
        )?;
        // Add to sharing matrix
        conn.execute(
            "INSERT OR IGNORE INTO folder_devices (folder_id, device_id) VALUES (?1, ?2)",
            params![folder_id, device_id],
        )?;
        // Remove from pending
        conn.execute(
            "DELETE FROM pending_folders WHERE folder_id = ?1 AND device_id = ?2",
            params![folder_id, device_id],
        )?;
        Ok(())
    }

    pub fn reject_pending_folder(&self, folder_id: &str, device_id: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM pending_folders WHERE folder_id = ?1 AND device_id = ?2",
            params![folder_id, device_id],
        )?;
        Ok(())
    }

    // =========================================================================
    // FOLDER IGNORES
    // =========================================================================

    pub fn get_folder_ignores(&self, folder_id: &str) -> SqlResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT pattern FROM folder_ignores WHERE folder_id = ?1")?;
        let rows = stmt.query_map(params![folder_id], |row| row.get::<_, String>(0))?;
        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    pub fn set_folder_ignores(&self, folder_id: &str, patterns: &[String]) -> SqlResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM folder_ignores WHERE folder_id = ?1", params![folder_id])?;
        for pat in patterns {
            let trimmed = pat.trim();
            if !trimmed.is_empty() {
                tx.execute(
                    "INSERT OR IGNORE INTO folder_ignores (folder_id, pattern) VALUES (?1, ?2)",
                    params![folder_id, trimmed],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    // =========================================================================
    // METRICS & COMPLETION
    // =========================================================================

    pub fn get_folder_status(&self, folder_id: &str) -> SqlResult<FolderStatusMetrics> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files WHERE folder_id = ?1 AND is_deleted = 0",
        )?;
        let (local_files, local_bytes): (i64, i64) = stmt.query_row(params![folder_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

        let is_paused: bool = conn
            .query_row(
                "SELECT is_paused FROM folders WHERE folder_id = ?1",
                params![folder_id],
                |row| row.get::<_, i64>(0),
            )
            .map(|val| val != 0)
            .unwrap_or(false);

        let state = if is_paused {
            "paused".to_string()
        } else {
            "idle".to_string()
        };

        let u_local_files = local_files.max(0) as u64;
        let u_local_bytes = local_bytes.max(0) as u64;

        Ok(FolderStatusMetrics {
            folder_id: folder_id.to_string(),
            state,
            global_files: u_local_files,
            global_bytes: u_local_bytes,
            local_files: u_local_files,
            local_bytes: u_local_bytes,
            need_files: 0,
            need_bytes: 0,
            in_sync_bytes: u_local_bytes,
            completion_pct: 100.0,
            sequence: u_local_files,
        })
    }

    pub fn get_device_completion(&self, device_id: &str, folder_id: &str) -> SqlResult<DeviceCompletionMetrics> {
        let status = self.get_folder_status(folder_id)?;
        Ok(DeviceCompletionMetrics {
            device_id: device_id.to_string(),
            folder_id: folder_id.to_string(),
            completion_pct: status.completion_pct,
            global_bytes: status.global_bytes,
            need_bytes: status.need_bytes,
        })
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

    /// Stores an encrypted chunk envelope in the CAS store for untrusted nodes.
    pub fn put_encrypted_chunk(&self, envelope: &crate::p2p::crypto::EncryptedChunkEnvelope) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let payload = envelope.to_bytes()?;
        self.put_chunk(&envelope.chunk_hash, &payload)?;
        Ok(())
    }

    /// Reads an encrypted chunk envelope from the CAS store.
    pub fn get_encrypted_chunk(&self, chunk_hash: &str) -> Result<Option<crate::p2p::crypto::EncryptedChunkEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
        match self.get_chunk(chunk_hash)? {
            Some(data) => {
                let envelope = crate::p2p::crypto::EncryptedChunkEnvelope::from_bytes(&data)?;
                Ok(Some(envelope))
            }
            None => Ok(None),
        }
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

    pub fn ignore_conflict(&self, conflict_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE quarantine_conflicts SET status = 'IGNORED' WHERE conflict_id = ?1",
            params![conflict_id],
        )?;
        Ok(())
    }

    pub fn reopen_conflict(&self, conflict_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE quarantine_conflicts SET status = 'PENDING' WHERE conflict_id = ?1",
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
        let folder = FolderRecord::new("test_vault", "/tmp/test");
        engine.add_folder(&folder).unwrap();
        let folders = engine.list_folders().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].folder_id, "test_vault");
        assert_eq!(folders[0].sync_mode, "SendReceive");

        // 1b. Test Device & Pairing CRUD
        let dev = DeviceRecord {
            device_id: "7777777-777777N-7777777-777777N".into(),
            name: "Pixel 9 Pro".into(),
            addresses: vec!["tcp://192.168.1.100:9190".into()],
            is_paused: false,
            is_trusted: true,
            introducer: false,
            cert_name: None,
            created_at: 1000,
        };
        engine.add_device(&dev).unwrap();
        let devs = engine.list_devices().unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].name, "Pixel 9 Pro");

        // Folder sharing matrix
        engine.share_folder_with_device("test_vault", &dev.device_id).unwrap();
        let shared_devs = engine.list_folder_devices("test_vault").unwrap();
        assert_eq!(shared_devs, vec![dev.device_id.clone()]);

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

    #[test]
    fn test_pending_device_pairing_workflow() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_pairing_test_{}", uuid::Uuid::new_v4()));
        let engine = StorageEngine::new(&temp_dir).unwrap();

        // 1. Add pending device requests
        let dev1 = PendingDeviceRecord {
            device_id: "DEV-PHONE-001".into(),
            name: "Alice's Android Phone".into(),
            address: "tcp://192.168.1.150:9190".into(),
            received_at: 1000,
        };
        let dev2 = PendingDeviceRecord {
            device_id: "DEV-LAPTOP-002".into(),
            name: "Bob's Work Laptop".into(),
            address: "tcp://192.168.1.151:9190".into(),
            received_at: 2000,
        };
        engine.add_pending_device(&dev1).unwrap();
        engine.add_pending_device(&dev2).unwrap();

        let pending = engine.list_pending_devices().unwrap();
        assert_eq!(pending.len(), 2);
        // Ordered by received_at DESC
        assert_eq!(pending[0].device_id, "DEV-LAPTOP-002");
        assert_eq!(pending[1].device_id, "DEV-PHONE-001");

        // 2. Accept dev1 -> promoted to devices table as trusted
        engine.accept_pending_device("DEV-PHONE-001").unwrap();

        let pending_after_accept = engine.list_pending_devices().unwrap();
        assert_eq!(pending_after_accept.len(), 1);
        assert_eq!(pending_after_accept[0].device_id, "DEV-LAPTOP-002");

        let paired = engine.get_device("DEV-PHONE-001").unwrap().expect("device should be in devices table");
        assert_eq!(paired.name, "Alice's Android Phone");
        assert_eq!(paired.addresses, vec!["tcp://192.168.1.150:9190"]);
        assert!(paired.is_trusted, "Accepted pending device must be marked trusted");
        assert!(!paired.is_paused);
        assert!(!paired.introducer);

        // 3. Reject dev2 -> deleted from pending, not added to devices
        engine.reject_pending_device("DEV-LAPTOP-002").unwrap();
        let pending_after_reject = engine.list_pending_devices().unwrap();
        assert_eq!(pending_after_reject.len(), 0);
        assert!(engine.get_device("DEV-LAPTOP-002").unwrap().is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_introducer_propagation_unauthorized_rejection() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_intro_unauth_{}", uuid::Uuid::new_v4()));
        let engine = StorageEngine::new(&temp_dir).unwrap();

        // Add regular non-introducer peer
        let peer = DeviceRecord {
            device_id: "PEER-REGULAR-01".into(),
            name: "Regular Peer".into(),
            addresses: vec!["tcp://10.0.0.1:9190".into()],
            is_paused: false,
            is_trusted: true,
            introducer: false, // NOT an introducer
            cert_name: None,
            created_at: 100,
        };
        engine.add_device(&peer).unwrap();
        assert!(!engine.is_device_introducer("PEER-REGULAR-01").unwrap());

        // Rogue peer attempts to propagate cluster devices
        let announced = vec![
            IntroducedDevice {
                device_id: "SPOOFED-DEV-01".into(),
                name: "Spoofed Device".into(),
                addresses: vec!["tcp://10.0.0.99:9190".into()],
                is_trusted: true,
                cert_name: None,
            },
        ];

        let result = engine.propagate_introducer_devices("PEER-REGULAR-01", &announced, true).unwrap();
        assert!(result.added_trusted.is_empty(), "Unauthorized propagation must not add trusted devices");
        assert!(result.added_pending.is_empty(), "Unauthorized propagation must not add pending devices");

        assert!(engine.get_device("SPOOFED-DEV-01").unwrap().is_none());
        assert!(engine.list_pending_devices().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_introducer_propagation_auto_trust() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_intro_autotrust_{}", uuid::Uuid::new_v4()));
        let engine = StorageEngine::new(&temp_dir).unwrap();

        // Add designated introducer peer
        let introducer = DeviceRecord {
            device_id: "MASTER-INTRODUCER-01".into(),
            name: "Cluster Master Introducer".into(),
            addresses: vec!["tcp://master.lan:9190".into()],
            is_paused: false,
            is_trusted: true,
            introducer: true,
            cert_name: None,
            created_at: 200,
        };
        engine.add_device(&introducer).unwrap();
        assert!(engine.is_device_introducer("MASTER-INTRODUCER-01").unwrap());

        let intro_list = engine.list_introducer_devices().unwrap();
        assert_eq!(intro_list.len(), 1);
        assert_eq!(intro_list[0].device_id, "MASTER-INTRODUCER-01");

        // Introducer announces cluster peers with auto_trust = true
        let announced = vec![
            // 1. Valid new peer A
            IntroducedDevice {
                device_id: "CLUSTER-NODE-A".into(),
                name: "Node Alpha".into(),
                addresses: vec!["tcp://node-a.lan:9190".into()],
                is_trusted: true,
                cert_name: Some("cert-alpha".into()),
            },
            // 2. Valid new peer B
            IntroducedDevice {
                device_id: "CLUSTER-NODE-B".into(),
                name: "Node Beta".into(),
                addresses: vec!["tcp://node-b.lan:9190".into()],
                is_trusted: true,
                cert_name: None,
            },
            // 3. Self introduction (should be ignored)
            IntroducedDevice {
                device_id: "MASTER-INTRODUCER-01".into(),
                name: "Self Master".into(),
                addresses: vec!["tcp://master.lan:9190".into()],
                is_trusted: true,
                cert_name: None,
            },
        ];

        let result = engine.propagate_introducer_devices("MASTER-INTRODUCER-01", &announced, true).unwrap();
        assert_eq!(result.added_trusted.len(), 2);
        assert!(result.added_trusted.contains(&"CLUSTER-NODE-A".to_string()));
        assert!(result.added_trusted.contains(&"CLUSTER-NODE-B".to_string()));
        assert_eq!(result.ignored, vec!["MASTER-INTRODUCER-01".to_string()]);

        // Verify nodes were inserted into devices table
        let node_a = engine.get_device("CLUSTER-NODE-A").unwrap().expect("Node A should exist");
        assert_eq!(node_a.name, "Node Alpha");
        assert!(node_a.is_trusted);
        assert_eq!(node_a.addresses, vec!["tcp://node-a.lan:9190"]);

        let node_b = engine.get_device("CLUSTER-NODE-B").unwrap().expect("Node B should exist");
        assert_eq!(node_b.name, "Node Beta");
        assert!(node_b.is_trusted);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_introducer_propagation_manual_pairing() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_intro_manual_{}", uuid::Uuid::new_v4()));
        let engine = StorageEngine::new(&temp_dir).unwrap();

        let introducer = DeviceRecord {
            device_id: "MASTER-INTRO-02".into(),
            name: "Master Introducer".into(),
            addresses: vec!["tcp://master.lan:9190".into()],
            is_paused: false,
            is_trusted: true,
            introducer: true,
            cert_name: None,
            created_at: 300,
        };
        engine.add_device(&introducer).unwrap();

        let announced = vec![
            IntroducedDevice {
                device_id: "CLUSTER-NODE-C".into(),
                name: "Node Gamma".into(),
                addresses: vec!["tcp://node-c.lan:9190".into()],
                is_trusted: true,
                cert_name: None,
            },
        ];

        // auto_trust = false -> routes to pending_devices
        let result = engine.propagate_introducer_devices("MASTER-INTRO-02", &announced, false).unwrap();
        assert_eq!(result.added_pending, vec!["CLUSTER-NODE-C".to_string()]);
        assert!(result.added_trusted.is_empty());

        assert!(engine.get_device("CLUSTER-NODE-C").unwrap().is_none());
        let pending = engine.list_pending_devices().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].device_id, "CLUSTER-NODE-C");

        // Manually accept pending device
        engine.accept_pending_device("CLUSTER-NODE-C").unwrap();
        assert!(engine.get_device("CLUSTER-NODE-C").unwrap().is_some());
        assert_eq!(engine.list_pending_devices().unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_introducer_propagation_address_merging() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_intro_merge_{}", uuid::Uuid::new_v4()));
        let engine = StorageEngine::new(&temp_dir).unwrap();

        let introducer = DeviceRecord {
            device_id: "MASTER-INTRO-03".into(),
            name: "Master Introducer".into(),
            addresses: vec!["tcp://master.lan:9190".into()],
            is_paused: false,
            is_trusted: true,
            introducer: true,
            cert_name: None,
            created_at: 400,
        };
        engine.add_device(&introducer).unwrap();

        // Existing device with 1 initial address
        let existing = DeviceRecord {
            device_id: "NODE-EXISTING-01".into(),
            name: "Existing Node".into(),
            addresses: vec!["tcp://192.168.1.10:9190".into()],
            is_paused: false,
            is_trusted: true,
            introducer: false,
            cert_name: None,
            created_at: 401,
        };
        engine.add_device(&existing).unwrap();

        // Introducer announces existing device with an additional new address
        let announced = vec![
            IntroducedDevice {
                device_id: "NODE-EXISTING-01".into(),
                name: "Existing Node Updated".into(),
                addresses: vec![
                    "tcp://192.168.1.10:9190".into(), // existing
                    "tcp://10.200.0.1:9190".into(),    // new VPN address
                ],
                is_trusted: true,
                cert_name: None,
            },
        ];

        let result = engine.propagate_introducer_devices("MASTER-INTRO-03", &announced, true).unwrap();
        assert_eq!(result.updated, vec!["NODE-EXISTING-01".to_string()]);

        let updated = engine.get_device("NODE-EXISTING-01").unwrap().unwrap();
        assert_eq!(updated.addresses.len(), 2);
        assert!(updated.addresses.contains(&"tcp://192.168.1.10:9190".to_string()));
        assert!(updated.addresses.contains(&"tcp://10.200.0.1:9190".to_string()));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_untrusted_node_support() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_untrusted_node_{}", uuid::Uuid::new_v4()));
        let engine = StorageEngine::new(&temp_dir).unwrap();

        // Add untrusted cloud VPS storage node
        let untrusted_vps = DeviceRecord {
            device_id: "VPS-UNTRUSTED-STORAGE-01".into(),
            name: "Hetzner Storage Box".into(),
            addresses: vec!["tcp://vps.cloud.net:9190".into()],
            is_paused: false,
            is_trusted: false, // Untrusted storage node
            introducer: false,
            cert_name: None,
            created_at: 500,
        };
        engine.add_device(&untrusted_vps).unwrap();

        // Check trust queries
        assert!(!engine.is_device_trusted("VPS-UNTRUSTED-STORAGE-01").unwrap());
        let untrusted_list = engine.list_untrusted_devices().unwrap();
        assert_eq!(untrusted_list.len(), 1);
        assert_eq!(untrusted_list[0].device_id, "VPS-UNTRUSTED-STORAGE-01");

        // Toggle trust status to trusted
        engine.set_device_trusted("VPS-UNTRUSTED-STORAGE-01", true).unwrap();
        assert!(engine.is_device_trusted("VPS-UNTRUSTED-STORAGE-01").unwrap());
        assert_eq!(engine.list_untrusted_devices().unwrap().len(), 0);

        // Toggle back to untrusted
        engine.set_device_trusted("VPS-UNTRUSTED-STORAGE-01", false).unwrap();
        assert!(!engine.is_device_trusted("VPS-UNTRUSTED-STORAGE-01").unwrap());
        assert_eq!(engine.list_untrusted_devices().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_device_pause_and_removal_cleanup() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_dev_mgmt_{}", uuid::Uuid::new_v4()));
        let engine = StorageEngine::new(&temp_dir).unwrap();

        let folder = FolderRecord::new("shared_folder_01", "/tmp/shared");
        engine.add_folder(&folder).unwrap();

        let dev = DeviceRecord {
            device_id: "DEV-MGMT-01".into(),
            name: "Test Device".into(),
            addresses: vec!["tcp://127.0.0.1:9190".into()],
            is_paused: false,
            is_trusted: true,
            introducer: false,
            cert_name: None,
            created_at: 600,
        };
        engine.add_device(&dev).unwrap();
        engine.share_folder_with_device("shared_folder_01", "DEV-MGMT-01").unwrap();
        assert_eq!(engine.list_folder_devices("shared_folder_01").unwrap(), vec!["DEV-MGMT-01".to_string()]);

        // Pause device
        engine.set_device_paused("DEV-MGMT-01", true).unwrap();
        let dev_paused = engine.get_device("DEV-MGMT-01").unwrap().unwrap();
        assert!(dev_paused.is_paused);

        // Unpause device
        engine.set_device_paused("DEV-MGMT-01", false).unwrap();
        let dev_unpaused = engine.get_device("DEV-MGMT-01").unwrap().unwrap();
        assert!(!dev_unpaused.is_paused);

        // Remove device -> cleans up devices table and folder_devices associations
        engine.remove_device("DEV-MGMT-01").unwrap();
        assert!(engine.get_device("DEV-MGMT-01").unwrap().is_none());
        assert!(engine.list_folder_devices("shared_folder_01").unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pending_folder_invitations_workflow() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_folder_invites_{}", uuid::Uuid::new_v4()));
        let engine = StorageEngine::new(&temp_dir).unwrap();

        let inv1 = PendingFolderRecord {
            folder_id: "folder_photos".into(),
            device_id: "REMOTE-DEV-01".into(),
            folder_label: "Family Photos".into(),
            offered_at: 700,
        };
        let inv2 = PendingFolderRecord {
            folder_id: "folder_finance".into(),
            device_id: "REMOTE-DEV-02".into(),
            folder_label: "Tax Documents".into(),
            offered_at: 800,
        };
        engine.add_pending_folder(&inv1).unwrap();
        engine.add_pending_folder(&inv2).unwrap();

        let pending = engine.list_pending_folders().unwrap();
        assert_eq!(pending.len(), 2);

        // Accept folder_photos
        engine.accept_pending_folder("folder_photos", "REMOTE-DEV-01", "/home/user/Photos").unwrap();
        let folder = engine.get_folder("folder_photos").unwrap().expect("Folder should be registered");
        assert_eq!(folder.local_path, "/home/user/Photos");
        let shared = engine.list_folder_devices("folder_photos").unwrap();
        assert_eq!(shared, vec!["REMOTE-DEV-01".to_string()]);

        // Reject folder_finance
        engine.reject_pending_folder("folder_finance", "REMOTE-DEV-02").unwrap();
        assert!(engine.get_folder("folder_finance").unwrap().is_none());
        assert_eq!(engine.list_pending_folders().unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
