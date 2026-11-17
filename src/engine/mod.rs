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
    archive_file_version, atomic_write_file, safe_join, sanitize_relative_path,
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

    /// Chunks a payload using FastCDC and commits all chunks into the CAS block store.
    pub fn save_payload_chunks(&self, payload: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (chunks, _) = self.chunker.chunk_slice(payload);
        for (info, data) in &chunks {
            self.storage.put_chunk(&info.chunk_hash, data)?;
        }
        Ok(())
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
        if let Err(e) = verify_folder_marker(&base_path, &folder.marker_name) {
            warn!("Mount safety check failed for folder {}: {}", folder_id, e);
            self.set_folder_state(folder_id, FolderSyncState::Error);
            return Err(Box::new(e));
        }

        let ignore_engine = self.get_folder_ignore_engine(folder_id, &base_path);
        let mut indexed_count = 0;
        let mut seen_paths = std::collections::HashSet::new();
        let mut stack = vec![base_path.clone()];

        while let Some(current_dir) = stack.pop() {
            for entry in fs::read_dir(&current_dir)? {
                let entry = entry?;
                let path = entry.path();
                let file_name = entry.file_name();
                let name_str = file_name.to_string_lossy();

                if name_str.starts_with(".synapse")
                    || name_str.starts_with(".git")
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
                    seen_paths.insert(rel_path.clone());
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

        if let Ok(existing_files) = self.storage.list_files_in_folder(folder_id) {
            for file in existing_files {
                if !file.is_deleted && !seen_paths.contains(&file.relative_path) {
                    let _ = self.mark_local_deleted(folder_id, &file.relative_path);
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

        let existing = self.storage.get_file(folder_id, &rel_clean)?;
        if let Some(record) = &existing {
            if record.size == file_size && record.mtime_nanos == mtime_nanos && !record.is_deleted {
                return Ok(false);
            }
        }

        let data = fs::read(&full_path)?;
        let parent_hashes = existing
            .as_ref()
            .map(|e| vec![e.current_revision.clone()])
            .unwrap_or_default();

        let rev_node = self.conflict_engine.commit_revision(
            folder_id,
            &rel_clean,
            &data,
            parent_hashes,
            mtime_nanos,
        )?;

        let _ = self.event_sender.send(CoreEvent::FileChanged {
            folder_id: folder_id.to_string(),
            relative_path: rel_clean,
            revision: rev_node.revision_hash,
        });

        Ok(true)
    }

    /// Records a local deletion as a tombstone.  The revision remains in the
    /// DAG so a peer can distinguish deletion from a file it has not seen yet.
    pub fn mark_local_deleted(
        &self,
        folder_id: &str,
        relative_path: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let rel_clean = sanitize_relative_path(relative_path);
        if rel_clean.is_empty() {
            return Ok(false);
        }
        let changed = self.storage.mark_file_deleted(folder_id, &rel_clean)?;
        if changed {
            if let Some(folder) = self.storage.get_folder(folder_id)? {
                let base_path = PathBuf::from(&folder.local_path);
                if let Ok(full_path) = safe_join(&base_path, &rel_clean) {
                    if full_path.exists() && full_path.is_file() {
                        let _ = fs::remove_file(full_path);
                    }
                }
            }
            if let Some(file) = self.storage.get_file(folder_id, &rel_clean)? {
                let _ = self.event_sender.send(CoreEvent::FileChanged {
                    folder_id: folder_id.to_string(),
                    relative_path: rel_clean,
                    revision: file.current_revision,
                });
            }
        }
        Ok(changed)
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
        if rel_clean.is_empty() {
            return Err("Refusing to apply a remote revision with an empty path".into());
        }
        let base_path = PathBuf::from(&folder.local_path);
        let local_path = safe_join(&base_path, relative_path)?;

        let _ = self.event_sender.send(CoreEvent::ItemStarted {
            folder_id: folder_id.to_string(),
            relative_path: rel_clean.clone(),
            action: "SYNC_INCOMING".to_string(),
        });

        // A remote revision is untrusted input.  Verify that the advertised
        // revision actually describes the supplied payload before it can enter
        // either the CAS or the DAG.  In particular, do not create file_chunks
        // rows before their chunks exist: SQLite foreign keys correctly reject
        // that ordering for a genuinely new remote file.
        if remote_rev.file_size != remote_payload.len() as u64 {
            return Err("Remote revision file size does not match payload".into());
        }
        let (computed_chunks, computed_manifest) = self.chunker.chunk_metadata_only(remote_payload);
        let computed_hashes: Vec<String> = computed_chunks
            .iter()
            .map(|chunk| chunk.chunk_hash.clone())
            .collect();
        if computed_hashes != remote_chunk_hashes || computed_manifest != remote_rev.manifest_hash {
            return Err("Remote revision manifest does not match payload".into());
        }
        let expected_revision = RevisionNode::compute_hash(
            &remote_rev.parent_hashes,
            &remote_rev.manifest_hash,
            &remote_rev.author_device_id,
            remote_rev.sequence_number,
        );
        if expected_revision != remote_rev.revision_hash {
            return Err("Remote revision hash is invalid".into());
        }

        self.save_payload_chunks(remote_payload)?;

        // Chunks are now durable, so their revision can safely reference them.
        self.storage.insert_revision(
            &RevisionRecord {
                revision_hash: remote_rev.revision_hash.clone(),
                parent_1: remote_rev.parent_hashes.get(0).cloned(),
                parent_2: remote_rev.parent_hashes.get(1).cloned(),
                manifest_hash: remote_rev.manifest_hash.clone(),
                author_device: remote_rev.author_device_id.clone(),
                sequence_number: remote_rev.sequence_number,
                file_size: remote_rev.file_size,
                created_at: remote_rev.mtime_nanos,
            },
            remote_chunk_hashes,
        )?;

        let local_file = self.storage.get_file(folder_id, &rel_clean)?;

        match local_file {
            None => {
                atomic_write_file(&local_path, remote_payload, Some(remote_rev.mtime_nanos), None)?;
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
                    LcaResult::Identical => {}
                    LcaResult::FastForwardLocal => {
                        info!(
                            "Local revision {} supersedes remote {}; keeping local",
                            existing.current_revision, remote_rev.revision_hash
                        );
                    }
                    LcaResult::FastForwardRemote => {
                        info!(
                            "Fast-forwarding remote revision {} over local {}",
                            remote_rev.revision_hash, existing.current_revision
                        );

                        if local_path.exists() && folder.versioning_type != "None" {
                            if let Err(e) = archive_file_version(&base_path, &rel_clean) {
                                warn!("Failed to archive previous file version for {}/{}: {}", folder_id, rel_clean, e);
                            }
                        }

                        atomic_write_file(&local_path, remote_payload, Some(remote_rev.mtime_nanos), None)?;
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
        let ignore_engine = engine.get_folder_ignore_engine(&fid, &root_path);

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                match event.kind {
                    EventKind::Modify(notify::event::ModifyKind::Name(_)) => {
                        if event.paths.len() == 2 {
                            if let Ok(old_rel) = event.paths[0].strip_prefix(&root_path) {
                                let _ = engine.mark_local_deleted(&fid, &old_rel.to_string_lossy());
                            }
                            if let Ok(new_rel) = event.paths[1].strip_prefix(&root_path) {
                                if event.paths[1].is_file() {
                                    let new_rel_str = new_rel.to_string_lossy().to_string();
                                    if !ignore_engine.is_ignored(&new_rel_str, false) {
                                        let _ = engine.index_single_file(&fid, &new_rel_str);
                                    }
                                }
                            }
                        } else {
                            for path in event.paths {
                                if path.exists() && path.is_file() {
                                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                                    if name.starts_with(".synapse") || name.starts_with(".stfolder") || name.starts_with(".git") {
                                        continue;
                                    }
                                    if let Ok(rel) = path.strip_prefix(&root_path) {
                                        let rel_str = rel.to_string_lossy().to_string();
                                        if !ignore_engine.is_ignored(&rel_str, false) {
                                            let _ = engine.index_single_file(&fid, &rel_str);
                                        }
                                    }
                                } else if let Ok(rel) = path.strip_prefix(&root_path) {
                                    let _ = engine.mark_local_deleted(&fid, &rel.to_string_lossy());
                                }
                            }
                        }
                    }
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for path in event.paths {
                            if path.is_file() {
                                let name = path.file_name().unwrap_or_default().to_string_lossy();
                                if name.starts_with(".synapse")
                                    || name.starts_with(".stfolder")
                                    || name.starts_with(".git")
                                {
                                    continue;
                                }
                                if let Ok(rel) = path.strip_prefix(&root_path) {
                                    let rel_str = rel.to_string_lossy().to_string();
                                    if !ignore_engine.is_ignored(&rel_str, false) {
                                        let _ = engine.index_single_file(&fid, &rel_str);
                                    }
                                }
                            }
                        }
                    }
                    EventKind::Remove(_) => {
                        for path in event.paths {
                            if let Ok(rel) = path.strip_prefix(&root_path) {
                                let _ = engine.mark_local_deleted(&fid, &rel.to_string_lossy());
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
