//! Multi-Strategy Conflict Resolution Pipeline.
//!
//! Implements:
//! - Tier 1: Automated 3-Way Semantic Merge for non-overlapping edits.
//! - Tier 2: Non-Polluting Virtual Quarantine for overlapping edits and binary files.
//! - Tier 3: Interactive UI Visual Merge decision executor.

pub mod diff3;

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::chunker::Chunker;
use crate::dag::RevisionNode;
use crate::engine::fs_utils::atomic_write_file;
use crate::storage::{FileRecord, RevisionRecord, StorageEngine};

/// Event sent over WebSocket to UI clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictDetectedData {
    pub conflict_id: String,
    pub folder_id: String,
    pub relative_path: String,
    pub mime_type: String,
    pub local_version: VersionSummary,
    pub remote_version: VersionSummary,
    pub auto_merge_attempted: bool,
    pub overlapping_lines_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionSummary {
    pub author: String,
    pub mtime: i64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum CoreEvent {
    #[serde(rename = "CONFLICT_DETECTED")]
    ConflictDetected(ConflictDetectedData),
    #[serde(rename = "CONFLICT_RESOLVED")]
    ConflictResolved {
        conflict_id: String,
        action: String,
    },
    #[serde(rename = "FILE_CHANGED")]
    FileChanged {
        folder_id: String,
        relative_path: String,
        revision: String,
    },
    #[serde(rename = "SYNC_STARTED")]
    SyncStarted {
        folder_id: String,
    },
    #[serde(rename = "SYNC_COMPLETED")]
    SyncCompleted {
        folder_id: String,
        files_synced: usize,
    },
    #[serde(rename = "PEER_CONNECTED")]
    PeerConnected {
        peer_id: String,
        addr: String,
    },
    #[serde(rename = "PEER_DISCONNECTED")]
    PeerDisconnected {
        peer_id: String,
    },
    #[serde(rename = "FOLDER_SCAN_PROGRESS")]
    FolderScanProgress {
        folder_id: String,
        current_file: String,
        scanned_files: usize,
    },
    #[serde(rename = "DOWNLOAD_PROGRESS")]
    DownloadProgress {
        folder_id: String,
        relative_path: String,
        bytes_transferred: u64,
        total_bytes: u64,
    },
    #[serde(rename = "ITEM_STARTED")]
    ItemStarted {
        folder_id: String,
        relative_path: String,
        action: String,
    },
    #[serde(rename = "ITEM_FINISHED")]
    ItemFinished {
        folder_id: String,
        relative_path: String,
        action: String,
        error: Option<String>,
    },
    #[serde(rename = "DEVICE_PAIRED")]
    DevicePaired {
        device_id: String,
        name: String,
    },
    #[serde(rename = "DEVICE_PENDING")]
    DevicePending {
        device_id: String,
        name: String,
        address: String,
    },
    #[serde(rename = "REMOTE_INDEX_UPDATED")]
    RemoteIndexUpdated {
        device_id: String,
        folder_id: String,
        file_count: usize,
    },
}

/// Action submitted by UI to resolve a quarantined conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolveAction {
    AcceptLocal,
    AcceptRemote,
    CustomMerge,
    KeepBoth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveRequest {
    pub action: ResolveAction,
    pub merged_content: Option<String>,
}

pub struct ConflictEngine {
    storage: StorageEngine,
    chunker: Chunker,
    event_sender: broadcast::Sender<CoreEvent>,
    device_id: String,
}

impl ConflictEngine {
    pub fn new(
        storage: StorageEngine,
        event_sender: broadcast::Sender<CoreEvent>,
        device_id: String,
    ) -> Self {
        Self {
            storage,
            chunker: Chunker::default(),
            event_sender,
            device_id,
        }
    }

    /// Determines if a file is text (mergeable via diff3) or binary.
    pub fn is_text_file(path: &str, sample_bytes: &[u8]) -> bool {
        // Null byte check
        if sample_bytes.iter().take(8192).any(|&b| b == 0) {
            return false;
        }

        // Common text extensions
        let p = Path::new(path);
        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
            let lower = ext.to_lowercase();
            match lower.as_str() {
                "txt" | "md" | "markdown" | "rs" | "kt" | "kts" | "java" | "py" | "js" | "ts"
                | "jsx" | "tsx" | "c" | "cpp" | "h" | "hpp" | "go" | "html" | "css" | "json"
                | "csv" | "xml" | "yaml" | "yml" | "toml" | "sh" | "bash" | "sql" | "ini" => {
                    return true;
                }
                "png" | "jpg" | "jpeg" | "gif" | "webp" | "mp4" | "mkv" | "mp3" | "zip"
                | "tar" | "gz" | "pdf" | "exe" | "so" | "dll" | "db" | "sqlite" => return false,
                _ => {}
            }
        }

        // UTF-8 validation fallback
        std::str::from_utf8(sample_bytes).is_ok()
    }

    /// Guess MIME type based on extension and content.
    pub fn detect_mime_type(path: &str, sample_bytes: &[u8]) -> String {
        let p = Path::new(path);
        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
            match ext.to_lowercase().as_str() {
                "md" | "markdown" => return "text/markdown".into(),
                "txt" => return "text/plain".into(),
                "json" => return "application/json".into(),
                "csv" => return "text/csv".into(),
                "rs" | "kt" | "java" | "py" | "c" | "cpp" | "go" => return "text/x-code".into(),
                "html" => return "text/html".into(),
                "png" => return "image/png".into(),
                "jpg" | "jpeg" => return "image/jpeg".into(),
                "pdf" => return "application/pdf".into(),
                _ => {}
            }
        }

        if Self::is_text_file(path, sample_bytes) {
            "text/plain".into()
        } else {
            "application/octet-stream".into()
        }
    }

    /// Attempts reconciliation of incoming remote version against local disk file.
    /// Follows the 3-Tier Multi-Strategy Pipeline.
    pub fn handle_divergence(
        &self,
        folder_id: &str,
        relative_path: &str,
        base_rev: Option<&str>,
        local_rev: &str,
        remote_rev: &str,
        remote_payload: &[u8],
        remote_author: &str,
        remote_mtime: i64,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let folder = match self.storage.get_folder(folder_id)? {
            Some(f) => f,
            None => return Err(format!("Folder not found: {}", folder_id).into()),
        };

        let full_local_path = PathBuf::from(&folder.local_path).join(relative_path);
        let local_payload = if full_local_path.exists() {
            fs::read(&full_local_path)?
        } else {
            Vec::new()
        };

        let is_text = Self::is_text_file(relative_path, &local_payload)
            && Self::is_text_file(relative_path, remote_payload);

        let mut auto_merge_attempted = false;
        let mut overlapping_lines = 0;

        // Tier 1: Try automated 3-way semantic merge for text files
        if is_text {
            auto_merge_attempted = true;
            let base_payload = match base_rev {
                Some(brev) => self.storage.read_file_from_revision(brev).unwrap_or_default(),
                None => Vec::new(),
            };

            let base_str = String::from_utf8_lossy(&base_payload);
            let local_str = String::from_utf8_lossy(&local_payload);
            let remote_str = String::from_utf8_lossy(remote_payload);

            match diff3::merge3(&base_str, &local_str, &remote_str) {
                diff3::MergeResult::Clean(merged_text) => {
                    info!(
                        "Tier 1 Clean 3-Way Auto-Merge succeeded for {}/{}",
                        folder_id, relative_path
                    );

                    atomic_write_file(&full_local_path, merged_text.as_bytes(), None, None)?;

                    let (chunks, manifest) = self.chunker.chunk_slice(merged_text.as_bytes());
                    for (info, data) in &chunks {
                        self.storage.put_chunk(&info.chunk_hash, data)?;
                    }

                    let chunk_hashes: Vec<String> = chunks.into_iter().map(|(c, _)| c.chunk_hash).collect();
                    let merge_rev = RevisionNode::new(
                        vec![local_rev.to_string(), remote_rev.to_string()],
                        manifest,
                        self.device_id.clone(),
                        chrono::Utc::now().timestamp_millis() as u64,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                        merged_text.len() as u64,
                    );

                    self.storage.insert_revision(
                        &RevisionRecord {
                            revision_hash: merge_rev.revision_hash.clone(),
                            parent_1: Some(local_rev.to_string()),
                            parent_2: Some(remote_rev.to_string()),
                            manifest_hash: merge_rev.manifest_hash.clone(),
                            author_device: self.device_id.clone(),
                            created_at: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                        },
                        &chunk_hashes,
                    )?;

                    self.storage.upsert_file(&FileRecord {
                        folder_id: folder_id.to_string(),
                        relative_path: relative_path.to_string(),
                        size: merged_text.len() as u64,
                        mtime_nanos: merge_rev.mtime_nanos,
                        current_revision: merge_rev.revision_hash.clone(),
                        is_deleted: false,
                    })?;

                    let _ = self.event_sender.send(CoreEvent::FileChanged {
                        folder_id: folder_id.to_string(),
                        relative_path: relative_path.to_string(),
                        revision: merge_rev.revision_hash,
                    });

                    return Ok(true);
                }
                diff3::MergeResult::Conflict { overlapping_lines_count, .. } => {
                    overlapping_lines = overlapping_lines_count;
                    warn!(
                        "Tier 1 Auto-Merge detected {} overlapping lines in {}/{}",
                        overlapping_lines, folder_id, relative_path
                    );
                }
            }
        }

        // Tier 2: Quarantine & Virtual Staging (Zero Filesystem Pollution)
        // Local working copy is NEVER renamed or overwritten!
        let conflict_id = format!("cnf_{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let _staged_path = self.storage.stage_quarantine_conflict(
            &conflict_id,
            folder_id,
            relative_path,
            base_rev,
            local_rev,
            remote_rev,
            remote_payload,
        )?;

        let mime = Self::detect_mime_type(relative_path, remote_payload);
        let local_meta = fs::metadata(&full_local_path).ok();
        let local_mtime = local_meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let local_size = local_meta.map(|m| m.len()).unwrap_or(local_payload.len() as u64);

        let event = CoreEvent::ConflictDetected(ConflictDetectedData {
            conflict_id: conflict_id.clone(),
            folder_id: folder_id.to_string(),
            relative_path: relative_path.to_string(),
            mime_type: mime,
            local_version: VersionSummary {
                author: self.device_id.clone(),
                mtime: local_mtime,
                size: local_size,
            },
            remote_version: VersionSummary {
                author: remote_author.to_string(),
                mtime: remote_mtime,
                size: remote_payload.len() as u64,
            },
            auto_merge_attempted,
            overlapping_lines_count: overlapping_lines,
        });

        let _ = self.event_sender.send(event);
        Ok(false)
    }

    /// Executes user resolution decision (Tier 3).
    pub fn resolve(
        &self,
        conflict_id: &str,
        req: &ResolveRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conflict = match self.storage.get_conflict(conflict_id)? {
            Some(c) => c,
            None => return Err(format!("Conflict ID not found: {}", conflict_id).into()),
        };

        // State Machine Transition Guard: Enforces valid lifecycle transitions
        let current_status = conflict.parsed_status();
        if !current_status.can_transition_to(crate::state::ConflictStatus::Resolved) {
            return Err(Box::new(crate::state::StateTransitionError {
                entity: "conflict".to_string(),
                entity_id: conflict_id.to_string(),
                current_state: current_status.as_str().to_string(),
                attempted_transition: crate::state::ConflictStatus::Resolved.as_str().to_string(),
                allowed_transitions: current_status
                    .allowed_transitions()
                    .into_iter()
                    .map(|s| s.as_str().to_string())
                    .collect(),
                available_actions: current_status
                    .available_actions()
                    .into_iter()
                    .map(String::from)
                    .collect(),
                is_terminal: current_status.is_terminal(),
            }));
        }

        let folder = match self.storage.get_folder(&conflict.folder_id)? {
            Some(f) => f,
            None => return Err(format!("Folder not found: {}", conflict.folder_id).into()),
        };

        let local_path = PathBuf::from(&folder.local_path).join(&conflict.relative_path);

        match req.action {
            ResolveAction::AcceptLocal => {
                info!("Resolving conflict {} with ACCEPT_LOCAL", conflict_id);
                // Keep disk file untouched, mark conflict resolved
                self.storage.resolve_conflict(conflict_id)?;
            }
            ResolveAction::AcceptRemote => {
                info!("Resolving conflict {} with ACCEPT_REMOTE", conflict_id);
                let staged_path = PathBuf::from(&conflict.staged_payload_path);
                if staged_path.exists() {
                    let remote_bytes = fs::read(&staged_path)?;
                    atomic_write_file(&local_path, &remote_bytes, None, None)?;

                    let (chunks, _manifest) = self.chunker.chunk_slice(&remote_bytes);
                    for (info, data) in &chunks {
                        self.storage.put_chunk(&info.chunk_hash, data)?;
                    }

                    self.storage.upsert_file(&FileRecord {
                        folder_id: conflict.folder_id.clone(),
                        relative_path: conflict.relative_path.clone(),
                        size: remote_bytes.len() as u64,
                        mtime_nanos: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                        current_revision: conflict.remote_revision.clone(),
                        is_deleted: false,
                    })?;
                }
                self.storage.resolve_conflict(conflict_id)?;
            }
            ResolveAction::CustomMerge => {
                info!("Resolving conflict {} with CUSTOM_MERGE", conflict_id);
                let content = req
                    .merged_content
                    .as_ref()
                    .ok_or("merged_content required for CUSTOM_MERGE")?;

                atomic_write_file(&local_path, content.as_bytes(), None, None)?;

                let (chunks, manifest) = self.chunker.chunk_slice(content.as_bytes());
                for (info, data) in &chunks {
                    self.storage.put_chunk(&info.chunk_hash, data)?;
                }

                let chunk_hashes: Vec<String> = chunks.into_iter().map(|(c, _)| c.chunk_hash).collect();
                let merge_rev = RevisionNode::new(
                    vec![conflict.local_revision.clone(), conflict.remote_revision.clone()],
                    manifest,
                    self.device_id.clone(),
                    chrono::Utc::now().timestamp_millis() as u64,
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    content.len() as u64,
                );

                self.storage.insert_revision(
                    &RevisionRecord {
                        revision_hash: merge_rev.revision_hash.clone(),
                        parent_1: Some(conflict.local_revision.clone()),
                        parent_2: Some(conflict.remote_revision.clone()),
                        manifest_hash: merge_rev.manifest_hash.clone(),
                        author_device: self.device_id.clone(),
                        created_at: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    },
                    &chunk_hashes,
                )?;

                self.storage.upsert_file(&FileRecord {
                    folder_id: conflict.folder_id.clone(),
                    relative_path: conflict.relative_path.clone(),
                    size: content.len() as u64,
                    mtime_nanos: merge_rev.mtime_nanos,
                    current_revision: merge_rev.revision_hash,
                    is_deleted: false,
                })?;

                self.storage.resolve_conflict(conflict_id)?;
            }
            ResolveAction::KeepBoth => {
                info!("Resolving conflict {} with KEEP_BOTH", conflict_id);
                let staged_path = PathBuf::from(&conflict.staged_payload_path);
                if staged_path.exists() {
                    let parent = local_path.parent().unwrap_or_else(|| Path::new(""));
                    let file_stem = local_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("file");
                    let ext = local_path
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");
                    let sidecar_name = if ext.is_empty() {
                        format!("{}.conflict-{}", file_stem, conflict_id)
                    } else {
                        format!("{}.conflict-{}.{}", file_stem, conflict_id, ext)
                    };
                    let sidecar_path = parent.join(&sidecar_name);
                    fs::copy(&staged_path, &sidecar_path)?;
                }
                self.storage.resolve_conflict(conflict_id)?;
            }
        }

        let _ = self.event_sender.send(CoreEvent::ConflictResolved {
            conflict_id: conflict_id.to_string(),
            action: format!("{:?}", req.action),
        });

        Ok(())
    }

    /// Ignores or dismisses a quarantined conflict.
    pub fn ignore(&self, conflict_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conflict = match self.storage.get_conflict(conflict_id)? {
            Some(c) => c,
            None => return Err(format!("Conflict ID not found: {}", conflict_id).into()),
        };

        let current_status = conflict.parsed_status();
        if !current_status.can_transition_to(crate::state::ConflictStatus::Ignored) {
            return Err(Box::new(crate::state::StateTransitionError {
                entity: "conflict".to_string(),
                entity_id: conflict_id.to_string(),
                current_state: current_status.as_str().to_string(),
                attempted_transition: crate::state::ConflictStatus::Ignored.as_str().to_string(),
                allowed_transitions: current_status
                    .allowed_transitions()
                    .into_iter()
                    .map(|s| s.as_str().to_string())
                    .collect(),
                available_actions: current_status
                    .available_actions()
                    .into_iter()
                    .map(String::from)
                    .collect(),
                is_terminal: current_status.is_terminal(),
            }));
        }

        self.storage.ignore_conflict(conflict_id)?;
        Ok(())
    }

    /// Reopens an ignored conflict back to PENDING.
    pub fn reopen(&self, conflict_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conflict = match self.storage.get_conflict(conflict_id)? {
            Some(c) => c,
            None => return Err(format!("Conflict ID not found: {}", conflict_id).into()),
        };

        let current_status = conflict.parsed_status();
        if !current_status.can_transition_to(crate::state::ConflictStatus::Pending) {
            return Err(Box::new(crate::state::StateTransitionError {
                entity: "conflict".to_string(),
                entity_id: conflict_id.to_string(),
                current_state: current_status.as_str().to_string(),
                attempted_transition: crate::state::ConflictStatus::Pending.as_str().to_string(),
                allowed_transitions: current_status
                    .allowed_transitions()
                    .into_iter()
                    .map(|s| s.as_str().to_string())
                    .collect(),
                available_actions: current_status
                    .available_actions()
                    .into_iter()
                    .map(String::from)
                    .collect(),
                is_terminal: current_status.is_terminal(),
            }));
        }

        self.storage.reopen_conflict(conflict_id)?;
        Ok(())
    }
}
