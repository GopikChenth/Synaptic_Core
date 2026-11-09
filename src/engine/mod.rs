//! Core Synchronization Engine, File Indexer, and Filesystem Watcher.
//!
//! Orchestrates Content-Defined Chunking, CAS persistence, Merkle DAG updates,
//! and continuous filesystem change tracking via `notify`.

pub mod fs_utils;
pub mod ignore;
pub mod versioning;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::chunker::Chunker;
use crate::conflict::{ConflictEngine, CoreEvent};
use std::collections::HashMap;
use std::sync::RwLock;

use crate::dag::{LcaResult, MerkleDag, RevisionNode};
use crate::engine::fs_utils::{
    archive_file_version, atomic_write_file, ensure_folder_marker, sanitize_relative_path,
    verify_folder_marker,
};
use crate::engine::ignore::IgnoreEngine;
use crate::state::FolderSyncState;
use crate::storage::{FileRecord, RevisionRecord, StorageEngine};

#[derive(Clone)]
pub struct SyncEngine {
    storage: StorageEngine,
    chunker: Arc<Chunker>,
    conflict_engine: Arc<ConflictEngine>,
    event_sender: broadcast::Sender<CoreEvent>,
    device_id: String,
    folder_states: Arc<RwLock<HashMap<String, FolderSyncState>>>,
}

impl SyncEngine {
    pub fn new(
        storage: StorageEngine,
        conflict_engine: Arc<ConflictEngine>,
        event_sender: broadcast::Sender<CoreEvent>,
        device_id: String,
    ) -> Self {
        Self {
            storage,
            chunker: Arc::new(Chunker::default()),
            conflict_engine,
            event_sender,
            device_id,
            folder_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Queries the dynamic operational state of a folder.
    pub fn get_folder_state(&self, folder_id: &str) -> FolderSyncState {
        if let Ok(Some(folder)) = self.storage.get_folder(folder_id) {
            if folder.is_paused {
                return FolderSyncState::Paused;
            }
        }
        if let Ok(states) = self.folder_states.read() {
            if let Some(&state) = states.get(folder_id) {
                return state;
            }
        }
        FolderSyncState::Idle
    }

    /// Sets the dynamic operational state of a folder.
    pub fn set_folder_state(&self, folder_id: &str, state: FolderSyncState) {
        if let Ok(mut states) = self.folder_states.write() {
            states.insert(folder_id.to_string(), state);
        }
    }

    pub fn storage(&self) -> &StorageEngine {
        &self.storage
    }

    pub fn conflict_engine(&self) -> &ConflictEngine {
        &self.conflict_engine
    }

    pub fn event_sender(&self) -> &broadcast::Sender<CoreEvent> {
        &self.event_sender
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Builds the IgnoreEngine for a folder by loading `.synapseignore`, `.stignore`, and DB rules.
    pub fn get_folder_ignore_engine(&self, folder_id: &str, local_path: &Path) -> IgnoreEngine {
        let mut engine = IgnoreEngine::new();
        let syn_ignore = local_path.join(".synapseignore");
        if syn_ignore.exists() {
            if let Ok(c) = fs::read_to_string(&syn_ignore) {
                engine.parse_rules(&c);
            }
        }
        let st_ignore = local_path.join(".stignore");
        if st_ignore.exists() {
            if let Ok(c) = fs::read_to_string(&st_ignore) {
                engine.parse_rules(&c);
            }
        }
        if let Ok(pats) = self.storage.get_folder_ignores(folder_id) {
            for p in pats {
                engine.parse_rules(&p);
            }
        }
        engine
    }

    /// Indexes an entire folder recursively from scratch or incremental delta.
    pub fn index_folder(&self, folder_id: &str) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let folder = match self.storage.get_folder(folder_id)? {
            Some(f) => f,
            None => return Err(format!("Folder not registered: {}", folder_id).into()),
        };

        if folder.is_paused {
            self.set_folder_state(folder_id, FolderSyncState::Paused);
            info!("Folder {} is paused; skipping indexing", folder_id);
            return Ok(0);
        }

        self.set_folder_state(folder_id, FolderSyncState::Scanning);

        let base_path = PathBuf::from(&folder.local_path);
        if !base_path.exists() {
            fs::create_dir_all(&base_path)?;
        }

        // Mount Safety Marker verification: prevent cascading deletes if volume unmounted
        if let Err(_e) = verify_folder_marker(&base_path, &folder.marker_name) {
            let _ = ensure_folder_marker(&base_path, &folder.marker_name);
            if let Err(e2) = verify_folder_marker(&base_path, &folder.marker_name) {
                warn!("Mount safety check failed for folder {}: {}", folder_id, e2);
                self.set_folder_state(folder_id, FolderSyncState::Error);
                return Err(Box::new(e2));
            }
        }

        let ignore_engine = self.get_folder_ignore_engine(folder_id, &base_path);
        let mut indexed_count = 0;
        let mut stack = vec![base_path.clone()];

        while let Some(current_dir) = stack.pop() {
            for entry in fs::read_dir(&current_dir)? {
                let entry = entry?;
                let path = entry.path();
                let file_name = entry.file_name();
                let name_str = file_name.to_string_lossy();

                // Skip internal metadata folders and hidden control files
                if name_str.starts_with(".synapse")
                    || name_str.starts_with(".git")
                    || name_str.ends_with(".tmp_synapse")
                    || name_str.starts_with(".stfolder")
                    || name_str == folder.marker_name
                {
                    continue;
                }

                let rel_path = sanitize_relative_path(&path.strip_prefix(&base_path)?.to_string_lossy());
                if ignore_engine.is_ignored(&rel_path, path.is_dir()) {
                    continue;
                }

                if path.is_dir() {
                    stack.push(path);
                } else if path.is_file() {
                    let _ = self.event_sender.send(CoreEvent::FolderScanProgress {
                        folder_id: folder_id.to_string(),
                        current_file: rel_path.clone(),
                        scanned_files: indexed_count + 1,
                    });

                    if self.index_single_file(folder_id, &rel_path)? {
                        indexed_count += 1;
                    }
                }
            }
        }

        self.set_folder_state(folder_id, FolderSyncState::Idle);
        Ok(indexed_count)
    }

    /// Indexes a single local file: chunks with FastCDC, computes BLAKE3, writes to CAS,
    /// updates Merkle DAG revision and SQLite file record.
    pub fn index_single_file(
        &self,
        folder_id: &str,
        relative_path: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let folder = match self.storage.get_folder(folder_id)? {
            Some(f) => f,
            None => return Err(format!("Folder not registered: {}", folder_id).into()),
        };

        // If folder is ReceiveOnly, do NOT index or propagate local changes to peers
        if !folder.parsed_sync_mode().can_send() {
            info!("Folder {} is ReceiveOnly; ignoring local changes in {}", folder_id, relative_path);
            return Ok(false);
        }

        let rel_clean = sanitize_relative_path(relative_path);
        let full_path = PathBuf::from(&folder.local_path).join(&rel_clean);
        if !full_path.exists() {
            return Ok(false);
        }

        let meta = fs::metadata(&full_path)?;
        let file_size = meta.len();
        let mtime_nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        // Check if file is already up to date in database
        let existing = self.storage.get_file(folder_id, &rel_clean)?;
        if let Some(record) = &existing {
            if record.size == file_size && record.mtime_nanos == mtime_nanos && !record.is_deleted {
                return Ok(false); // No changes detected
            }
        }

        let data = fs::read(&full_path)?;
        let (chunks, manifest_hash) = self.chunker.chunk_slice(&data);

        // Store new chunks in CAS
        for (info, chunk_data) in &chunks {
            self.storage.put_chunk(&info.chunk_hash, chunk_data)?;
        }

        let chunk_hashes: Vec<String> = chunks.into_iter().map(|(c, _)| c.chunk_hash).collect();

        let parent_hashes = existing
            .as_ref()
            .map(|e| vec![e.current_revision.clone()])
            .unwrap_or_default();

        let seq = chrono::Utc::now().timestamp_millis() as u64;
        let rev_node = RevisionNode::new(
            parent_hashes.clone(),
            manifest_hash.clone(),
            self.device_id.clone(),
            seq,
            mtime_nanos,
            file_size,
        );

        let rev_record = RevisionRecord {
            revision_hash: rev_node.revision_hash.clone(),
            parent_1: parent_hashes.get(0).cloned(),
            parent_2: parent_hashes.get(1).cloned(),
            manifest_hash,
            author_device: self.device_id.clone(),
            created_at: mtime_nanos,
        };

        self.storage.insert_revision(&rev_record, &chunk_hashes)?;

        self.storage.upsert_file(&FileRecord {
            folder_id: folder_id.to_string(),
            relative_path: rel_clean.clone(),
            size: file_size,
            mtime_nanos,
            current_revision: rev_node.revision_hash.clone(),
            is_deleted: false,
        })?;

        let _ = self.event_sender.send(CoreEvent::FileChanged {
            folder_id: folder_id.to_string(),
            relative_path: rel_clean,
            revision: rev_node.revision_hash,
        });

        Ok(true)
    }

    /// Handles an incoming remote file revision during sync.
    /// Traverses the Merkle DAG to evaluate ancestry and invokes the 3-Way Conflict Pipeline if divergent.
    pub fn reconcile_remote_revision(
        &self,
        folder_id: &str,
        relative_path: &str,
        remote_rev: &RevisionNode,
        remote_chunk_hashes: &[String],
        remote_payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let folder = match self.storage.get_folder(folder_id)? {
            Some(f) => f,
            None => return Err(format!("Folder not registered: {}", folder_id).into()),
        };

        // If folder is SendOnly, reject incoming modifications from remote peers
        if !folder.parsed_sync_mode().can_receive() {
            warn!("Folder {} is SendOnly; rejecting incoming remote changes for {}", folder_id, relative_path);
            return Ok(());
        }

        self.set_folder_state(folder_id, FolderSyncState::Syncing);

        let rel_clean = sanitize_relative_path(relative_path);
        let base_path = PathBuf::from(&folder.local_path);
        let local_path = base_path.join(&rel_clean);

        let _ = self.event_sender.send(CoreEvent::ItemStarted {
            folder_id: folder_id.to_string(),
            relative_path: rel_clean.clone(),
            action: "SYNC_INCOMING".to_string(),
        });

        // Ensure all remote chunks and revision are inserted in storage
        self.storage.insert_revision(
            &RevisionRecord {
                revision_hash: remote_rev.revision_hash.clone(),
                parent_1: remote_rev.parent_hashes.get(0).cloned(),
                parent_2: remote_rev.parent_hashes.get(1).cloned(),
                manifest_hash: remote_rev.manifest_hash.clone(),
                author_device: remote_rev.author_device_id.clone(),
                created_at: remote_rev.mtime_nanos,
            },
            remote_chunk_hashes,
        )?;

        let local_file = self.storage.get_file(folder_id, &rel_clean)?;

        match local_file {
            None => {
                // Completely new file remotely: fast-forward accept remote with atomic write
                atomic_write_file(&local_path, remote_payload, Some(remote_rev.mtime_nanos), None)?;

                // Save chunks in CAS
                let (chunks, _) = self.chunker.chunk_slice(remote_payload);
                for (info, data) in &chunks {
                    self.storage.put_chunk(&info.chunk_hash, data)?;
                }

                self.storage.upsert_file(&FileRecord {
                    folder_id: folder_id.to_string(),
                    relative_path: rel_clean.clone(),
                    size: remote_rev.file_size,
                    mtime_nanos: remote_rev.mtime_nanos,
                    current_revision: remote_rev.revision_hash.clone(),
                    is_deleted: false,
                })?;

                let _ = self.event_sender.send(CoreEvent::ItemFinished {
                    folder_id: folder_id.to_string(),
                    relative_path: rel_clean.clone(),
                    action: "CREATED".to_string(),
                    error: None,
                });
            }
            Some(existing) => {
                let dag = MerkleDag::new(&self.storage);
                let lca = dag.find_lca(&existing.current_revision, &remote_rev.revision_hash);

                match lca {
                    LcaResult::Identical => {
                        // Already identical; do nothing
                    }
                    LcaResult::FastForwardLocal => {
                        // Local has already superseded remote; keep local
                        info!(
                            "Local revision {} supersedes remote {}; keeping local",
                            existing.current_revision, remote_rev.revision_hash
                        );
                    }
                    LcaResult::FastForwardRemote => {
                        // Remote is clean descendant of local; fast-forward remote
                        info!(
                            "Fast-forwarding remote revision {} over local {}",
                            remote_rev.revision_hash, existing.current_revision
                        );

                        // File versioning archive if configured
                        if local_path.exists() && folder.versioning_type != "None" {
                            let _ = archive_file_version(&base_path, &rel_clean);
                        }

                        // Atomic staging write with timestamp preservation
                        atomic_write_file(&local_path, remote_payload, Some(remote_rev.mtime_nanos), None)?;

                        let (chunks, _) = self.chunker.chunk_slice(remote_payload);
                        for (info, data) in &chunks {
                            self.storage.put_chunk(&info.chunk_hash, data)?;
                        }

                        self.storage.upsert_file(&FileRecord {
                            folder_id: folder_id.to_string(),
                            relative_path: rel_clean.clone(),
                            size: remote_rev.file_size,
                            mtime_nanos: remote_rev.mtime_nanos,
                            current_revision: remote_rev.revision_hash.clone(),
                            is_deleted: false,
                        })?;

                        let _ = self.event_sender.send(CoreEvent::ItemFinished {
                            folder_id: folder_id.to_string(),
                            relative_path: rel_clean.clone(),
                            action: "UPDATED".to_string(),
                            error: None,
                        });
                    }
                    LcaResult::Diverged { base_revision } => {
                        // Branches diverged: trigger Multi-Strategy Conflict Resolution Pipeline
                        self.conflict_engine.handle_divergence(
                            folder_id,
                            &rel_clean,
                            base_revision.as_deref(),
                            &existing.current_revision,
                            &remote_rev.revision_hash,
                            remote_payload,
                            &remote_rev.author_device_id,
                            remote_rev.mtime_nanos,
                        )?;
                    }
                }
            }
        }

        self.set_folder_state(folder_id, FolderSyncState::Idle);
        Ok(())
    }

    /// Spawns a background filesystem watcher for a monitored folder.
    pub fn spawn_watcher(&self, folder_id: String, local_path: String) -> RecommendedWatcher {
        let engine = self.clone();
        let fid = folder_id.clone();
        let root_path = PathBuf::from(&local_path);

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for path in event.paths {
                            if path.is_file() {
                                let name = path.file_name().unwrap_or_default().to_string_lossy();
                                if name.starts_with(".synapse") || name.ends_with(".tmp_synapse") {
                                    continue;
                                }
                                if let Ok(rel) = path.strip_prefix(&root_path) {
                                    let rel_str = rel.to_string_lossy().to_string();
                                    let _ = engine.index_single_file(&fid, &rel_str);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        })
        .expect("Failed to initialize notify watcher");

        let _ = watcher.watch(Path::new(&local_path), RecursiveMode::Recursive);
        watcher
    }
}
