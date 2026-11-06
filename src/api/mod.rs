//! Local Control Plane: Embedded REST and WebSocket API Server.
//!
//! Exposes IPC interfaces for the Compose Multiplatform UI:
//! - System health & status
//! - Folder management
//! - Active conflict inspection (base, local, remote, 3-way diff)
//! - User conflict resolution commands
//! - Real-time WebSocket event streaming

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{
        path::Path as AxumPath,
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use crate::conflict::diff3::{self, DiffHunk};
use crate::conflict::ResolveRequest;
use crate::engine::SyncEngine;
use crate::storage::FolderRecord;

/// Application shared state injected into Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub start_time: Instant,
    pub sync_engine: SyncEngine,
    pub auth_token: Option<String>,
    pub peer_count: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStatusResponse {
    pub device_id: String,
    pub uptime_seconds: u64,
    pub peer_count: usize,
    pub sync_state: String,
    pub version: String,
    pub monitored_folders_count: usize,
    pub pending_conflicts_count: usize,
    pub memory_footprint_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FolderDto {
    pub folder_id: String,
    pub local_path: String,
    pub conflict_policy: String,
    pub is_paused: bool,
    pub files_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFolderRequest {
    pub folder_id: String,
    pub local_path: String,
    #[serde(default = "default_policy")]
    pub conflict_policy: String,
}

fn default_policy() -> String {
    "THREE_WAY_AUTO".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiffResponse {
    pub conflict_id: String,
    pub folder_id: String,
    pub relative_path: String,
    pub base: String,
    pub local: String,
    pub remote: String,
    pub hunks: Vec<DiffHunk>,
}

pub struct ApiServer {
    state: AppState,
    bind_addr: SocketAddr,
}

impl ApiServer {
    pub fn new(
        sync_engine: SyncEngine,
        bind_addr: SocketAddr,
        auth_token: Option<String>,
        peer_count: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        Self {
            state: AppState {
                start_time: Instant::now(),
                sync_engine,
                auth_token,
                peer_count,
            },
            bind_addr,
        }
    }

    /// Builds Axum router with security, CORS, and endpoint handlers.
    pub fn create_router(state: AppState) -> Router {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        Router::new()
            .route("/api/v1/system/status", get(get_system_status))
            .route("/api/v1/folders", get(list_folders).post(register_folder))
            .route("/api/v1/conflicts", get(list_conflicts))
            .route("/api/v1/conflicts/:id", get(get_conflict_details))
            .route("/api/v1/conflicts/:id/base", get(get_conflict_base))
            .route("/api/v1/conflicts/:id/local", get(get_conflict_local))
            .route("/api/v1/conflicts/:id/remote", get(get_conflict_remote))
            .route("/api/v1/conflicts/:id/diff", get(get_conflict_diff))
            .route("/api/v1/conflicts/:id/resolve", post(resolve_conflict))
            .route("/api/v1/events", get(websocket_events_handler))
            .layer(cors)
            .with_state(state)
    }

    /// Runs the Axum server asynchronously.
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = Self::create_router(self.state);
        info!("Synapse Core REST & WebSocket API listening on http://{}", self.bind_addr);
        let listener = tokio::net::TcpListener::bind(&self.bind_addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

// =============================================================================
// ROUTE HANDLERS
// =============================================================================

async fn get_system_status(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let folders = state.sync_engine.storage().list_folders().unwrap_or_default();
    let conflicts = state.sync_engine.storage().list_pending_conflicts().unwrap_or_default();
    let peers = state.peer_count.load(std::sync::atomic::Ordering::Relaxed);

    // Rough process memory estimation
    let mem = get_resident_memory_bytes();

    Json(SystemStatusResponse {
        device_id: state.sync_engine.device_id().to_string(),
        uptime_seconds: uptime,
        peer_count: peers,
        sync_state: "IDLE".into(),
        version: "1.0.0".into(),
        monitored_folders_count: folders.len(),
        pending_conflicts_count: conflicts.len(),
        memory_footprint_bytes: mem,
    })
}

async fn list_folders(State(state): State<AppState>) -> impl IntoResponse {
    let folders = match state.sync_engine.storage().list_folders() {
        Ok(f) => f,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let mut dtos = Vec::new();
    for f in folders {
        let files = state.sync_engine.storage().list_files_in_folder(&f.folder_id).unwrap_or_default();
        dtos.push(FolderDto {
            folder_id: f.folder_id,
            local_path: f.local_path,
            conflict_policy: f.conflict_policy,
            is_paused: f.is_paused,
            files_count: files.len(),
        });
    }

    Json(dtos).into_response()
}

async fn register_folder(
    State(state): State<AppState>,
    Json(payload): Json<RegisterFolderRequest>,
) -> impl IntoResponse {
    let folder = FolderRecord {
        folder_id: payload.folder_id.clone(),
        local_path: payload.local_path.clone(),
        conflict_policy: payload.conflict_policy,
        is_paused: false,
    };

    if let Err(e) = state.sync_engine.storage().add_folder(&folder) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Trigger initial index scan
    let engine = state.sync_engine.clone();
    let fid = payload.folder_id;
    tokio::task::spawn_blocking(move || {
        let _ = engine.index_folder(&fid);
    });

    (StatusCode::CREATED, Json(folder)).into_response()
}

async fn list_conflicts(State(state): State<AppState>) -> impl IntoResponse {
    match state.sync_engine.storage().list_pending_conflicts() {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_conflict_details(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.storage().get_conflict(&id) {
        Ok(Some(c)) => Json(c).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Conflict not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_conflict_base(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let conflict = match state.sync_engine.storage().get_conflict(&id) {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "Conflict not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let base_bytes = match conflict.base_revision {
        Some(rev) => state.sync_engine.storage().read_file_from_revision(&rev).unwrap_or_default(),
        None => Vec::new(),
    };

    Response::builder()
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(axum::body::Body::from(base_bytes))
        .unwrap()
        .into_response()
}

async fn get_conflict_local(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let conflict = match state.sync_engine.storage().get_conflict(&id) {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "Conflict not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let folder = match state.sync_engine.storage().get_folder(&conflict.folder_id) {
        Ok(Some(f)) => f,
        _ => return (StatusCode::NOT_FOUND, "Folder not found").into_response(),
    };

    let local_path = PathBuf::from(&folder.local_path).join(&conflict.relative_path);
    let bytes = fs::read(&local_path).unwrap_or_default();

    Response::builder()
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(axum::body::Body::from(bytes))
        .unwrap()
        .into_response()
}

async fn get_conflict_remote(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let conflict = match state.sync_engine.storage().get_conflict(&id) {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "Conflict not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let staged_path = PathBuf::from(&conflict.staged_payload_path);
    let bytes = fs::read(&staged_path).unwrap_or_default();

    Response::builder()
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(axum::body::Body::from(bytes))
        .unwrap()
        .into_response()
}

async fn get_conflict_diff(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let conflict = match state.sync_engine.storage().get_conflict(&id) {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "Conflict not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let folder = match state.sync_engine.storage().get_folder(&conflict.folder_id) {
        Ok(Some(f)) => f,
        _ => return (StatusCode::NOT_FOUND, "Folder not found").into_response(),
    };

    let local_path = PathBuf::from(&folder.local_path).join(&conflict.relative_path);
    let local_bytes = fs::read(&local_path).unwrap_or_default();
    let remote_bytes = fs::read(&conflict.staged_payload_path).unwrap_or_default();
    let base_bytes = match &conflict.base_revision {
        Some(rev) => state.sync_engine.storage().read_file_from_revision(rev).unwrap_or_default(),
        None => Vec::new(),
    };

    let base_str = String::from_utf8_lossy(&base_bytes).to_string();
    let local_str = String::from_utf8_lossy(&local_bytes).to_string();
    let remote_str = String::from_utf8_lossy(&remote_bytes).to_string();

    let hunks = match diff3::merge3(&base_str, &local_str, &remote_str) {
        diff3::MergeResult::Conflict { hunks, .. } => hunks,
        diff3::MergeResult::Clean(_) => vec![DiffHunk {
            hunk_type: diff3::HunkType::Unchanged,
            base_lines: base_str.lines().map(|s| s.to_string()).collect(),
            local_lines: local_str.lines().map(|s| s.to_string()).collect(),
            remote_lines: remote_str.lines().map(|s| s.to_string()).collect(),
        }],
    };

    Json(DiffResponse {
        conflict_id: id,
        folder_id: conflict.folder_id,
        relative_path: conflict.relative_path,
        base: base_str,
        local: local_str,
        remote: remote_str,
        hunks,
    })
    .into_response()
}

async fn resolve_conflict(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
    Json(payload): Json<ResolveRequest>,
) -> impl IntoResponse {
    match state.sync_engine.conflict_engine().resolve(&id, &payload) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn websocket_events_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_websocket(socket, state))
}

async fn handle_websocket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.sync_engine.event_sender().subscribe();

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(evt) => {
                        if let Ok(json_str) = serde_json::to_string(&evt) {
                            if socket.send(Message::Text(json_str)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("WebSocket client lagged by {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            msg = socket.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        // Handle ping or UI commands
                        if text == "ping" {
                            let _ = socket.send(Message::Text("pong".into())).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

/// Estimates resident memory in bytes (Linux /proc/self/statm or fallback).
fn get_resident_memory_bytes() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(resident_pages) = parts[1].parse::<usize>() {
                    return resident_pages * 4096;
                }
            }
        }
    }
    16 * 1024 * 1024 // Fallback default ~16MB
}
