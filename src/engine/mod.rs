//! Core Synchronization Engine, File Indexer, and Filesystem Watcher.
//!
//! Orchestrates Content-Defined Chunking, CAS persistence, Merkle DAG updates,
//! and continuous filesystem change tracking via `notify`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::broadcast;
use tracing::info;

use crate::chunker::Chunker;
use crate::conflict::{ConflictEngine, CoreEvent};
use crate::dag::{LcaResult, MerkleDag, RevisionNode};
use crate::storage::{FileRecord, RevisionRecord, StorageEngine};

#[derive(Clone)]
pub struct SyncEngine {
    storage: StorageEngine,
    chunker: Arc<Chunker>,
    conflict_engine: Arc<ConflictEngine>,
    event_sender: broadcast::Sender<CoreEvent>,
    device_id: String,
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

    /// Indexes an entire folder recursively from scratch or incremental delta.
    pub fn index_folder(&self, folder_id: &str) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let folder = match self.storage.get_folder(folder_id)? {
            Some(f) => f,
            None => return Err(format!("Folder not registered: {}", folder_id).into()),
        };

        if folder.is_paused {
            info!("Folder {} is paused; skipping indexing", folder_id);
            return Ok(0);
        }

        let base_path = PathBuf::from(&folder.local_path);
        if !base_path.exists() {
            fs::create_dir_all(&base_path)?;
        }

        let mut indexed_count = 0;
        let mut stack = vec![base_path.clone()];

        while let Some(current_dir) = stack.pop() {
            for entry in fs::read_dir(&current_dir)? {
                let entry = entry?;
                let path = entry.path();
                let file_name = entry.file_name();
                let name_str = file_name.to_string_lossy();

                // Skip internal metadata folders and hidden control files
                if name_str.starts_with(".synapse") || name_str.starts_with(".git") || name_str.ends_with(".tmp_synapse") {
                    continue;
                }

                if path.is_dir() {
                    stack.push(path);
                } else if path.is_file() {
                    let rel_path = path.strip_prefix(&base_path)?.to_string_lossy().to_string();
                    if self.index_single_file(folder_id, &rel_path)? {
                        indexed_count += 1;
                    }
                }
            }
        }

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

        let full_path = PathBuf::from(&folder.local_path).join(relative_path);
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
        let existing = self.storage.get_file(folder_id, relative_path)?;
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
            relative_path: relative_path.to_string(),
            size: file_size,
            mtime_nanos,
            current_revision: rev_node.revision_hash.clone(),
            is_deleted: false,
        })?;

        let _ = self.event_sender.send(CoreEvent::FileChanged {
            folder_id: folder_id.to_string(),
            relative_path: relative_path.to_string(),
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
        // First ensure all remote chunks and revision are inserted in storage
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

        let local_file = self.storage.get_file(folder_id, relative_path)?;

        match local_file {
            None => {
                // Completely new file remotely: fast-forward accept remote
                let folder = self.storage.get_folder(folder_id)?.ok_or("Folder missing")?;
                let local_path = PathBuf::from(&folder.local_path).join(relative_path);
                if let Some(parent) = local_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&local_path, remote_payload)?;

                // Save chunks in CAS
                let (chunks, _) = self.chunker.chunk_slice(remote_payload);
                for (info, data) in &chunks {
                    self.storage.put_chunk(&info.chunk_hash, data)?;
                }

                self.storage.upsert_file(&FileRecord {
                    folder_id: folder_id.to_string(),
                    relative_path: relative_path.to_string(),
                    size: remote_rev.file_size,
                    mtime_nanos: remote_rev.mtime_nanos,
                    current_revision: remote_rev.revision_hash.clone(),
                    is_deleted: false,
                })?;

                let _ = self.event_sender.send(CoreEvent::FileChanged {
                    folder_id: folder_id.to_string(),
                    relative_path: relative_path.to_string(),
                    revision: remote_rev.revision_hash.clone(),
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
                        let folder = self.storage.get_folder(folder_id)?.ok_or("Folder missing")?;
                        let local_path = PathBuf::from(&folder.local_path).join(relative_path);

                        let tmp = local_path.with_extension("tmp_synapse");
                        fs::write(&tmp, remote_payload)?;
                        fs::rename(&tmp, &local_path)?;

                        let (chunks, _) = self.chunker.chunk_slice(remote_payload);
                        for (info, data) in &chunks {
                            self.storage.put_chunk(&info.chunk_hash, data)?;
                        }

                        self.storage.upsert_file(&FileRecord {
                            folder_id: folder_id.to_string(),
                            relative_path: relative_path.to_string(),
                            size: remote_rev.file_size,
                            mtime_nanos: remote_rev.mtime_nanos,
                            current_revision: remote_rev.revision_hash.clone(),
                            is_deleted: false,
                        })?;

                        let _ = self.event_sender.send(CoreEvent::FileChanged {
                            folder_id: folder_id.to_string(),
                            relative_path: relative_path.to_string(),
                            revision: remote_rev.revision_hash.clone(),
                        });
                    }
                    LcaResult::Diverged { base_revision } => {
                        // Branches diverged: trigger Multi-Strategy Conflict Resolution Pipeline
                        self.conflict_engine.handle_divergence(
                            folder_id,
                            relative_path,
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
