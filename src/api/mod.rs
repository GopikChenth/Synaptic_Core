//! Local Control Plane: Embedded REST and WebSocket API Server.
//!
//! Exposes IPC interfaces for the Compose Multiplatform UI:
//! - System health & status
//! - Cluster device management and pairing handshakes
//! - Folder management, sharing matrix, status, completion, and ignore rules
//! - Real-time connection speeds and metrics
//! - Active conflict inspection (base, local, remote, 3-way diff)
//! - User conflict resolution commands
//! - Real-time WebSocket event streaming
//! - Full compatibility route aliases for Syncthing API clients (`/rest/*`)

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{
        path::Path as AxumPath,
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, Request, State,
    },
    http::{header, HeaderName, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{info, warn};

use crate::conflict::diff3::{self, DiffHunk};
use crate::conflict::{CoreEvent, ResolveRequest};
use crate::engine::SyncEngine;
use crate::state::runtime::EngineLifecycleState;
use crate::state::{DevicePairingState, FolderOfferState, FolderSyncState};
use crate::storage::{DeviceRecord, FolderRecord, PeerConnectionMetrics};

/// Application shared state injected into Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub start_time: Instant,
    pub sync_engine: SyncEngine,
    pub auth_token: Option<String>,
    pub peer_count: Arc<std::sync::atomic::AtomicUsize>,
    pub shutdown_tx: Option<watch::Sender<bool>>,
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
    /// Number of folders in each runtime state, e.g. `{"idle": 3, "error": 1}`.
    /// `sync_state` keeps its historical values; this exposes errors and pauses too.
    #[serde(default)]
    pub folder_states: std::collections::BTreeMap<String, usize>,
    /// Engine lifecycle: `starting`, `ready`, `stopping` or `restarting`.
    #[serde(default)]
    pub lifecycle: String,
}

/// A paired device plus its derived runtime state. Serialized as the `DeviceRecord`
/// fields (unchanged) followed by `state`, `online` and `last_seen_secs`.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceView {
    #[serde(flatten)]
    pub device: DeviceRecord,
    /// `DevicePairingState` of a paired device: `"paired"` or `"paused"`.
    pub state: String,
    /// Heard from within the presence TTL (see the `peer_presence` state machine).
    pub online: bool,
    /// Seconds since the device was last heard from; absent if never seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_secs: Option<u64>,
}

impl DeviceView {
    pub fn new(device: DeviceRecord, presence: &crate::state::runtime::PeerPresence) -> Self {
        let state = if device.is_paused {
            crate::state::DevicePairingState::Paused
        } else {
            crate::state::DevicePairingState::Paired
        };
        Self {
            online: !device.is_paused && presence.is_online(&device.device_id),
            last_seen_secs: presence.last_seen_secs(&device.device_id),
            state: state.as_str().to_string(),
            device,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FolderDto {
    pub folder_id: String,
    pub local_path: String,
    pub conflict_policy: String,
    pub is_paused: bool,
    pub sync_mode: String,
    pub pull_order: String,
    pub versioning_type: String,
    pub versioning_keep_days: i64,
    pub marker_name: String,
    pub files_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFolderRequest {
    pub folder_id: String,
    pub local_path: String,
    #[serde(default = "default_policy")]
    pub conflict_policy: String,
    pub sync_mode: Option<String>,
    pub pull_order: Option<String>,
    pub versioning_type: Option<String>,
    pub versioning_keep_days: Option<i64>,
    pub marker_name: Option<String>,
}

fn default_policy() -> String {
    "THREE_WAY_AUTO".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConflictDetailsDto {
    pub conflict_id: String,
    pub folder_id: String,
    pub relative_path: String,
    pub base_revision: Option<String>,
    pub local_revision: String,
    pub remote_revision: String,
    pub staged_payload_path: String,
    pub status: String,
    pub detected_at: i64,
    pub available_actions: Vec<String>,
    pub is_terminal: bool,
    pub state_description: String,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct IgnoresRequest {
    pub ignore: Vec<String>,
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
                shutdown_tx: None,
            },
            bind_addr,
        }
    }

    pub fn with_shutdown_tx(mut self, shutdown_tx: watch::Sender<bool>) -> Self {
        self.state.shutdown_tx = Some(shutdown_tx);
        self
    }

    /// Builds Axum router with security, CORS, and endpoint handlers.
    pub fn create_router(state: AppState) -> Router {
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(|origin, _req_parts| {
                let s = origin.as_bytes();
                s.starts_with(b"http://localhost:")
                    || s == b"http://localhost"
                    || s.starts_with(b"https://localhost:")
                    || s == b"https://localhost"
                    || s.starts_with(b"http://127.0.0.1:")
                    || s == b"http://127.0.0.1"
                    || s.starts_with(b"https://127.0.0.1:")
                    || s == b"https://127.0.0.1"
                    || s == b"tauri://localhost"
                    || s == b"app://localhost"
            }))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                HeaderName::from_static("x-api-key"),
            ]);

        Router::new()
            .route("/api/v1/system/status", get(get_system_status))
            .route("/rest/system/status", get(get_system_status))
            .route("/api/v1/system/version", get(get_system_version))
            .route("/rest/system/version", get(get_system_version))
            .route("/api/v1/system/ping", get(get_system_ping))
            .route("/rest/system/ping", get(get_system_ping))
            .route("/api/v1/system/shutdown", post(system_shutdown))
            .route("/rest/system/shutdown", post(system_shutdown))
            .route("/api/v1/system/restart", post(system_restart))
            .route("/rest/system/restart", post(system_restart))
            .route("/api/v1/system/gc", post(run_system_gc))
            .route("/rest/system/gc", post(run_system_gc))
            .route(
                "/api/v1/system/statemachines",
                get(get_system_statemachines),
            )
            .route("/rest/system/statemachines", get(get_system_statemachines))
            .route("/api/v1/connections", get(get_connections))
            .route("/rest/system/connections", get(get_connections))
            .route("/api/v1/folders", get(list_folders).post(register_folder))
            .route(
                "/rest/system/folders",
                get(list_folders).post(register_folder),
            )
            .route("/api/v1/folders/:id", delete(delete_folder))
            .route("/api/v1/folders/:id/pause", post(pause_folder))
            .route("/api/v1/folders/:id/resume", post(resume_folder))
            .route("/api/v1/folders/:id/rescan", post(rescan_folder))
            .route("/rest/db/scan", post(rescan_folder_query))
            .route("/api/v1/folders/:id/status", get(get_folder_status))
            .route("/rest/db/status", get(get_folder_status_query))
            .route("/api/v1/folders/:id/completion", get(get_folder_completion))
            .route("/rest/db/completion", get(get_folder_completion_query))
            .route("/api/v1/folders/:id/devices", get(list_folder_devices))
            .route(
                "/api/v1/folders/:id/devices/:device_id",
                post(share_folder_device).delete(unshare_folder_device),
            )
            .route(
                "/api/v1/folders/:id/ignores",
                get(get_folder_ignores).post(set_folder_ignores),
            )
            .route(
                "/rest/db/ignores",
                get(get_folder_ignores_query).post(set_folder_ignores_query),
            )
            .route("/api/v1/devices", get(list_devices).post(add_device))
            .route("/rest/system/devices", get(list_devices).post(add_device))
            .route("/api/v1/devices/:id", get(get_device).delete(remove_device))
            .route("/api/v1/devices/:id/pause", post(pause_device))
            .route("/api/v1/devices/:id/resume", post(resume_device))
            .route("/api/v1/cluster/pending/devices", get(list_pending_devices))
            .route("/rest/cluster/pending/devices", get(list_pending_devices))
            .route(
                "/api/v1/cluster/pending/devices/:id/accept",
                post(accept_pending_device),
            )
            .route(
                "/rest/cluster/pending/devices/:id/accept",
                post(accept_pending_device),
            )
            .route(
                "/api/v1/cluster/pending/devices/:id/reject",
                post(reject_pending_device),
            )
            .route(
                "/rest/cluster/pending/devices/:id/reject",
                post(reject_pending_device),
            )
            .route(
                "/api/v1/cluster/rejected/folders",
                get(list_rejected_folders),
            )
            .route(
                "/api/v1/cluster/rejected/folders/:id",
                delete(forget_rejected_folder),
            )
            .route(
                "/api/v1/cluster/rejected/devices",
                get(list_rejected_devices),
            )
            .route(
                "/api/v1/cluster/rejected/devices/:id",
                delete(forget_rejected_device),
            )
            .route("/api/v1/cluster/pending/folders", get(list_pending_folders))
            .route("/rest/cluster/pending/folders", get(list_pending_folders))
            .route(
                "/api/v1/cluster/pending/folders/:id/accept",
                post(accept_pending_folder),
            )
            .route(
                "/rest/cluster/pending/folders/:id/accept",
                post(accept_pending_folder),
            )
            .route(
                "/api/v1/cluster/pending/folders/:id/reject",
                post(reject_pending_folder),
            )
            .route(
                "/rest/cluster/pending/folders/:id/reject",
                post(reject_pending_folder),
            )
            .route("/api/v1/conflicts", get(list_conflicts))
            .route("/api/v1/conflicts/:id", get(get_conflict_details))
            .route("/api/v1/conflicts/:id/base", get(get_conflict_base))
            .route("/api/v1/conflicts/:id/local", get(get_conflict_local))
            .route("/api/v1/conflicts/:id/remote", get(get_conflict_remote))
            .route("/api/v1/conflicts/:id/diff", get(get_conflict_diff))
            .route("/api/v1/conflicts/:id/resolve", post(resolve_conflict))
            .route("/api/v1/conflicts/:id/ignore", post(ignore_conflict))
            .route("/rest/conflicts/:id/ignore", post(ignore_conflict))
            .route("/api/v1/conflicts/:id/reopen", post(reopen_conflict))
            .route("/rest/conflicts/:id/reopen", post(reopen_conflict))
            .route("/api/v1/events", get(websocket_events_handler))
            .route("/rest/events", get(websocket_events_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .layer(cors)
            .with_state(state)
    }

    /// Runs the Axum server asynchronously until an OS shutdown signal is received.
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (_tx, rx) = watch::channel(false);
        self.run_with_shutdown(rx).await
    }

    /// Runs the Axum server asynchronously with an external graceful shutdown signal.
    pub async fn run_with_shutdown(
        self,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.bind().await?.serve(shutdown_rx).await
    }

    /// Binds the listening socket without serving yet.
    ///
    /// Splitting bind from serve lets the caller fail fast on `EADDRINUSE` before any
    /// other subsystem starts, and learn the real port when `0` (ephemeral) was requested.
    pub async fn bind(self) -> std::io::Result<BoundApiServer> {
        let listener = tokio::net::TcpListener::bind(&self.bind_addr).await?;
        let local_addr = listener.local_addr()?;
        Ok(BoundApiServer {
            router: Self::create_router(self.state),
            listener,
            local_addr,
        })
    }
}

/// An API server whose socket is already bound and ready to accept connections.
pub struct BoundApiServer {
    router: Router,
    listener: tokio::net::TcpListener,
    local_addr: SocketAddr,
}

impl BoundApiServer {
    /// The address actually bound (resolves port `0` to the OS-assigned port).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves requests until `shutdown_rx` flips to `true`.
    pub async fn serve(
        self,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Synapse Core REST & WebSocket API listening on http://{}",
            self.local_addr
        );
        axum::serve(self.listener, self.router)
            .with_graceful_shutdown(async move {
                while !*shutdown_rx.borrow() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
                info!("API server shutting down gracefully...");
            })
            .await?;
        Ok(())
    }
}

/// Constant-time API token authentication middleware.
///
/// When `AppState.auth_token` is configured (`Some(token)`), all endpoints except
/// `/api/v1/system/ping` and `/rest/system/ping` require a matching token via:
/// - `Authorization: Bearer <token>`
/// - `X-API-Key: <token>`
/// - `?token=<token>` query parameter (for WebSocket clients)
async fn auth_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(expected) = state.auth_token.as_deref().filter(|t| !t.is_empty()) else {
        return next.run(req).await;
    };

    let path = req.uri().path();
    if path == "/api/v1/system/ping" || path == "/rest/system/ping" {
        return next.run(req).await;
    }

    let provided = extract_token_from_request(&req);
    let is_valid = provided
        .as_deref()
        .map(|candidate| constant_time_eq(candidate.as_bytes(), expected.as_bytes()))
        .unwrap_or(false);

    if is_valid {
        next.run(req).await
    } else {
        warn!("Rejected unauthorized API request to {}", path);
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized" })),
        )
            .into_response()
    }
}

fn extract_token_from_request(req: &Request) -> Option<String> {
    if let Some(auth_header) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(bearer) = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
        {
            return Some(bearer.trim().to_string());
        }
    }

    if let Some(api_key) = req.headers().get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(api_key.trim().to_string());
    }

    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "token" && !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }

    None
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

// =============================================================================
// ROUTE HANDLERS: SYSTEM & CONNECTIONS
// =============================================================================

async fn get_system_status(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let folders = state
        .sync_engine
        .storage()
        .list_folders()
        .unwrap_or_default();
    let conflicts = state
        .sync_engine
        .storage()
        .list_pending_conflicts()
        .unwrap_or_default();
    let peers = state.peer_count.load(std::sync::atomic::Ordering::Relaxed);
    let mem = get_resident_memory_bytes();

    let mut is_scanning = false;
    let mut is_syncing = false;
    let mut all_paused = !folders.is_empty();

    for f in &folders {
        if !f.is_paused {
            all_paused = false;
        }
        match state.sync_engine.get_folder_state(&f.folder_id) {
            crate::state::FolderSyncState::Scanning => is_scanning = true,
            crate::state::FolderSyncState::Syncing => is_syncing = true,
            _ => {}
        }
    }

    let sync_state = if is_scanning {
        "SCANNING".to_string()
    } else if is_syncing {
        "SYNCING".to_string()
    } else if all_paused {
        "PAUSED".to_string()
    } else {
        "IDLE".to_string()
    };

    let folder_states = state
        .sync_engine
        .folder_states()
        .summarize(folders.iter().map(|f| f.folder_id.as_str()));

    Json(SystemStatusResponse {
        device_id: state.sync_engine.device_id().to_string(),
        uptime_seconds: uptime,
        peer_count: peers,
        sync_state,
        version: crate::VERSION.to_string(),
        monitored_folders_count: folders.len(),
        pending_conflicts_count: conflicts.len(),
        memory_footprint_bytes: mem,
        folder_states,
        lifecycle: state.sync_engine.lifecycle().get().as_str().to_string(),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemVersionResponse {
    pub version: String,
    pub codename: String,
    pub os: String,
    pub arch: String,
}

async fn get_system_version() -> impl IntoResponse {
    Json(SystemVersionResponse {
        version: format!("v{}", crate::VERSION),
        codename: "Synapse-SynapticCore".into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
    })
}

async fn get_system_ping() -> impl IntoResponse {
    Json(serde_json::json!({ "ping": "pong" }))
}

async fn system_shutdown(State(state): State<AppState>) -> impl IntoResponse {
    info!("System shutdown requested via API");
    let lifecycle = state.sync_engine.lifecycle();
    let _ = lifecycle.transition(EngineLifecycleState::Stopping);
    if let Some(tx) = &state.shutdown_tx {
        let _ = tx.send(true);
    }
    // Repeated calls are harmless and return the same answer.
    (
        StatusCode::OK,
        Json(serde_json::json!({ "lifecycle": lifecycle.get().as_str() })),
    )
        .into_response()
}

/// Stops this engine generation and starts a fresh one in-process: same PID, same API
/// address, storage and folder watchers reloaded. Clients should expect the WebSocket
/// to drop and can poll `/api/v1/system/ping` until it answers again.
async fn system_restart(State(state): State<AppState>) -> impl IntoResponse {
    let lifecycle = state.sync_engine.lifecycle();
    let Some(tx) = &state.shutdown_tx else {
        // Embedded router without an engine loop around it: nothing can restart us.
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "restart is not available: no engine supervisor",
                "lifecycle": lifecycle.get().as_str(),
            })),
        )
            .into_response();
    };
    match lifecycle.transition(EngineLifecycleState::Restarting) {
        Ok(now) => {
            info!("System restart requested via API");
            let _ = tx.send(true);
            (
                StatusCode::OK,
                Json(serde_json::json!({ "lifecycle": now.as_str() })),
            )
                .into_response()
        }
        Err(current) => {
            let meta = current.metadata();
            (
                StatusCode::CONFLICT,
                Json(crate::state::StateTransitionError {
                    entity: "engine".into(),
                    entity_id: state.sync_engine.device_id().to_string(),
                    current_state: current.as_str().to_string(),
                    attempted_transition: EngineLifecycleState::Restarting.as_str().to_string(),
                    allowed_transitions: meta.allowed_transitions,
                    available_actions: meta.available_actions,
                    is_terminal: meta.is_terminal,
                }),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcResponse {
    pub success: bool,
    pub collected_chunks: usize,
}

async fn run_system_gc(State(state): State<AppState>) -> impl IntoResponse {
    let _ = state.sync_engine.storage().rebuild_chunk_ref_counts();
    match state
        .sync_engine
        .storage()
        .garbage_collect_orphaned_chunks()
    {
        Ok(collected) => (
            StatusCode::OK,
            Json(GcResponse {
                success: true,
                collected_chunks: collected,
            }),
        )
            .into_response(),
        Err(_err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GcResponse {
                success: false,
                collected_chunks: 0,
            }),
        )
            .into_response(),
    }
}

async fn get_connections(State(state): State<AppState>) -> impl IntoResponse {
    let devices = state
        .sync_engine
        .storage()
        .list_devices()
        .unwrap_or_default();
    let mut map = HashMap::new();

    let presence = state.sync_engine.peer_presence();
    for dev in devices {
        let online = presence.is_online(&dev.device_id);
        map.insert(
            dev.device_id.clone(),
            PeerConnectionMetrics {
                device_id: dev.device_id,
                address: dev
                    .addresses
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "dynamic".into()),
                // Paired, not paused, and heard from recently (peer presence machine).
                is_connected: !dev.is_paused && online,
                in_bps: 0,
                out_bps: 0,
                total_in_bytes: 0,
                total_out_bytes: 0,
                latency_ms: 5,
                client_type: "synapse-core".into(),
            },
        );
    }

    Json(map)
}

async fn get_system_statemachines() -> impl IntoResponse {
    Json(crate::state::get_all_state_machines())
}

// =============================================================================
// ROUTE HANDLERS: FOLDERS
// =============================================================================

async fn list_folders(State(state): State<AppState>) -> impl IntoResponse {
    let folders = match state.sync_engine.storage().list_folders() {
        Ok(f) => f,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let mut dtos = Vec::new();
    for f in folders {
        let files = state
            .sync_engine
            .storage()
            .list_files_in_folder(&f.folder_id)
            .unwrap_or_default();
        dtos.push(FolderDto {
            folder_id: f.folder_id,
            local_path: f.local_path,
            conflict_policy: f.conflict_policy,
            is_paused: f.is_paused,
            sync_mode: f.sync_mode,
            pull_order: f.pull_order,
            versioning_type: f.versioning_type,
            versioning_keep_days: f.versioning_keep_days,
            marker_name: f.marker_name,
            files_count: files.len(),
        });
    }

    Json(dtos).into_response()
}

async fn register_folder(
    State(state): State<AppState>,
    Json(payload): Json<RegisterFolderRequest>,
) -> impl IntoResponse {
    if let Err(invalid) = crate::state::validate_folder_config(
        &payload.conflict_policy,
        payload.sync_mode.as_deref(),
        payload.pull_order.as_deref(),
        payload.versioning_type.as_deref(),
    ) {
        return (StatusCode::BAD_REQUEST, Json(invalid)).into_response();
    }
    let mut folder = FolderRecord::new(payload.folder_id.clone(), payload.local_path.clone());
    folder.conflict_policy = payload.conflict_policy;
    if let Some(sm) = payload.sync_mode {
        folder.sync_mode = sm;
    }
    if let Some(po) = payload.pull_order {
        folder.pull_order = po;
    }
    if let Some(vt) = payload.versioning_type {
        folder.versioning_type = vt;
    }
    if let Some(kd) = payload.versioning_keep_days {
        folder.versioning_keep_days = kd;
    }
    if let Some(mn) = payload.marker_name {
        folder.marker_name = mn;
    }

    if let Err(e) = state.sync_engine.storage().add_folder(&folder) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    let _ = crate::engine::fs_utils::ensure_folder_marker(
        std::path::Path::new(&payload.local_path),
        &folder.marker_name,
    );
    state.sync_engine.track_folder(&payload.folder_id);

    // Trigger initial index scan
    let engine = state.sync_engine.clone();
    let fid = payload.folder_id;
    tokio::task::spawn_blocking(move || {
        let _ = engine.index_folder(&fid);
    });

    (StatusCode::CREATED, Json(folder)).into_response()
}

async fn delete_folder(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.storage().delete_folder(&id) {
        Ok(_) => {
            state.sync_engine.forget_folder_state(&id);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn pause_folder(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.storage().set_folder_paused(&id, true) {
        Ok(_) => {
            state.sync_engine.refresh_folder_state(&id);
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn resume_folder(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.storage().set_folder_paused(&id, false) {
        Ok(_) => {
            state.sync_engine.refresh_folder_state(&id);
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn execute_folder_rescan(state: &AppState, folder_id: &str) {
    let engine = state.sync_engine.clone();
    let fid = folder_id.to_string();
    tokio::task::spawn_blocking(move || {
        let _ = engine.index_folder(&fid);
    });
}

fn fetch_folder_status(state: &AppState, folder_id: &str) -> axum::response::Response {
    match state.sync_engine.storage().get_folder_status(folder_id) {
        Ok(mut st) => {
            let runtime = state.sync_engine.folder_runtime_state(folder_id);
            st.state = runtime.state.as_str().to_string();
            st.error = runtime
                .error
                .filter(|_| runtime.state == FolderSyncState::Error);
            Json(st).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn fetch_folder_completion(
    state: &AppState,
    device_id: &str,
    folder_id: &str,
) -> axum::response::Response {
    match state
        .sync_engine
        .storage()
        .get_device_completion(device_id, folder_id)
    {
        Ok(comp) => Json(comp).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn rescan_folder(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    execute_folder_rescan(&state, &id);
    StatusCode::OK.into_response()
}

async fn rescan_folder_query(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Some(fid) = params.get("folder") {
        execute_folder_rescan(&state, fid);
        StatusCode::OK.into_response()
    } else {
        (StatusCode::BAD_REQUEST, "Missing folder query parameter").into_response()
    }
}

async fn get_folder_status(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    fetch_folder_status(&state, &id)
}

async fn get_folder_status_query(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Some(fid) = params.get("folder") {
        fetch_folder_status(&state, fid)
    } else {
        (StatusCode::BAD_REQUEST, "Missing folder query parameter").into_response()
    }
}

async fn get_folder_completion(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    fetch_folder_completion(&state, state.sync_engine.device_id(), &id)
}

async fn get_folder_completion_query(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let fid = match params.get("folder") {
        Some(f) => f,
        None => return (StatusCode::BAD_REQUEST, "Missing folder parameter").into_response(),
    };
    let dev_id = params
        .get("device")
        .cloned()
        .unwrap_or_else(|| state.sync_engine.device_id().to_string());
    fetch_folder_completion(&state, &dev_id, fid)
}

async fn list_folder_devices(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.storage().list_folder_devices(&id) {
        Ok(devs) => Json(devs).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn share_folder_device(
    AxumPath((id, device_id)): AxumPath<(String, String)>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state
        .sync_engine
        .storage()
        .share_folder_with_device(&id, &device_id)
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn unshare_folder_device(
    AxumPath((id, device_id)): AxumPath<(String, String)>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state
        .sync_engine
        .storage()
        .unshare_folder_from_device(&id, &device_id)
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn fetch_folder_ignores(state: &AppState, folder_id: &str) -> axum::response::Response {
    match state.sync_engine.storage().get_folder_ignores(folder_id) {
        Ok(patterns) => Json(IgnoresRequest { ignore: patterns }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn save_folder_ignores(
    state: &AppState,
    folder_id: &str,
    patterns: &[String],
) -> axum::response::Response {
    match state
        .sync_engine
        .storage()
        .set_folder_ignores(folder_id, patterns)
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_folder_ignores(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    fetch_folder_ignores(&state, &id)
}

async fn set_folder_ignores(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
    Json(payload): Json<IgnoresRequest>,
) -> impl IntoResponse {
    save_folder_ignores(&state, &id, &payload.ignore)
}

async fn get_folder_ignores_query(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Some(fid) = params.get("folder") {
        fetch_folder_ignores(&state, fid)
    } else {
        (StatusCode::BAD_REQUEST, "Missing folder query parameter").into_response()
    }
}

async fn set_folder_ignores_query(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    Json(payload): Json<IgnoresRequest>,
) -> impl IntoResponse {
    if let Some(fid) = params.get("folder") {
        save_folder_ignores(&state, fid, &payload.ignore)
    } else {
        (StatusCode::BAD_REQUEST, "Missing folder query parameter").into_response()
    }
}

// =============================================================================
// ROUTE HANDLERS: DEVICES & CLUSTERING
// =============================================================================

async fn list_devices(State(state): State<AppState>) -> impl IntoResponse {
    match state.sync_engine.storage().list_devices() {
        Ok(devs) => {
            let presence = state.sync_engine.peer_presence();
            let views: Vec<DeviceView> = devs
                .into_iter()
                .map(|d| DeviceView::new(d, presence))
                .collect();
            Json(views).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn add_device(
    State(state): State<AppState>,
    Json(payload): Json<DeviceRecord>,
) -> impl IntoResponse {
    match state.sync_engine.storage().add_device(&payload) {
        Ok(_) => {
            let _ = state
                .sync_engine
                .event_sender()
                .send(CoreEvent::DevicePaired {
                    device_id: payload.device_id.clone(),
                    name: payload.name.clone(),
                });
            (StatusCode::CREATED, Json(payload)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_device(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.storage().get_device(&id) {
        Ok(Some(d)) => Json(DeviceView::new(d, state.sync_engine.peer_presence())).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Device not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn remove_device(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.storage().remove_device(&id) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// -----------------------------------------------------------------------------
// Device pairing state machine guard
// -----------------------------------------------------------------------------

/// Outcome of checking a requested state machine action.
enum PairingCheck {
    /// Proceed with the transition.
    Apply,
    /// Already in the target state: succeed without doing anything (idempotent).
    AlreadyThere,
    /// Respond immediately (404 unknown device, 409 invalid transition, 500).
    Reject(Response),
}

/// Validates a device pairing transition against `DevicePairingState`.
///
/// Invalid transitions return `409 Conflict` with a machine-readable
/// [`StateTransitionError`](crate::state::StateTransitionError) body listing the
/// allowed transitions and actions, so a UI or agent can recover without guessing.
fn check_pairing_transition(
    state: &AppState,
    device_id: &str,
    target: DevicePairingState,
) -> PairingCheck {
    let current = match state.sync_engine.storage().device_pairing_state(device_id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return PairingCheck::Reject(
                (
                    StatusCode::NOT_FOUND,
                    format!("Device not found: {device_id}"),
                )
                    .into_response(),
            )
        }
        Err(e) => {
            return PairingCheck::Reject(
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            )
        }
    };
    if current == target {
        return PairingCheck::AlreadyThere;
    }
    if current.can_transition_to(target) {
        return PairingCheck::Apply;
    }
    PairingCheck::Reject(transition_conflict(
        "device",
        device_id.to_string(),
        current.as_str(),
        target.as_str(),
        current.metadata(),
    ))
}

async fn pause_device(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match check_pairing_transition(&state, &id, DevicePairingState::Paused) {
        PairingCheck::Reject(resp) => return resp,
        PairingCheck::AlreadyThere => return StatusCode::OK.into_response(),
        PairingCheck::Apply => {}
    }
    match state.sync_engine.storage().set_device_paused(&id, true) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn resume_device(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match check_pairing_transition(&state, &id, DevicePairingState::Paired) {
        PairingCheck::Reject(resp) => return resp,
        PairingCheck::AlreadyThere => return StatusCode::OK.into_response(),
        PairingCheck::Apply => {}
    }
    match state.sync_engine.storage().set_device_paused(&id, false) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// =============================================================================
// ROUTE HANDLERS: PAIRING HANDSHAKE & INVITATIONS
// =============================================================================

async fn list_pending_devices(State(state): State<AppState>) -> impl IntoResponse {
    match state.sync_engine.storage().list_pending_devices() {
        Ok(p) => Json(p).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn accept_pending_device(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match check_pairing_transition(&state, &id, DevicePairingState::Paired) {
        PairingCheck::Reject(resp) => return resp,
        PairingCheck::AlreadyThere => return StatusCode::OK.into_response(),
        PairingCheck::Apply => {}
    }
    let pending = state
        .sync_engine
        .storage()
        .get_pending_device(&id)
        .ok()
        .flatten();
    match state.sync_engine.storage().accept_pending_device(&id) {
        Ok(_) => {
            if let Some(p) = pending {
                let _ = state
                    .sync_engine
                    .event_sender()
                    .send(CoreEvent::DevicePaired {
                        device_id: p.device_id,
                        name: p.name,
                    });
            }
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn reject_pending_device(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match check_pairing_transition(&state, &id, DevicePairingState::Rejected) {
        PairingCheck::Reject(resp) => return resp,
        PairingCheck::AlreadyThere => return StatusCode::OK.into_response(),
        PairingCheck::Apply => {}
    }
    match state.sync_engine.storage().reject_pending_device(&id) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_rejected_devices(State(state): State<AppState>) -> impl IntoResponse {
    match state.sync_engine.storage().list_rejected_devices() {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Forgets a rejection so the device can request pairing again.
async fn forget_rejected_device(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.storage().forget_rejected_device(&id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            format!("No rejected pairing request for {id}"),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_pending_folders(State(state): State<AppState>) -> impl IntoResponse {
    match state.sync_engine.storage().list_pending_folders() {
        Ok(p) => Json(p).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptFolderPayload {
    pub device_id: String,
    pub local_path: String,
}

/// Builds the `409 Conflict` response for an invalid state machine action.
fn transition_conflict(
    entity: &str,
    entity_id: String,
    current: &str,
    attempted: &str,
    meta: crate::state::StateMetadata,
) -> Response {
    (
        StatusCode::CONFLICT,
        Json(crate::state::StateTransitionError {
            entity: entity.into(),
            entity_id,
            current_state: current.into(),
            attempted_transition: attempted.into(),
            allowed_transitions: meta.allowed_transitions,
            available_actions: meta.available_actions,
            is_terminal: meta.is_terminal,
        }),
    )
        .into_response()
}

/// Same contract as device pairing: 404 unknown offer, 200 no-op when already in the
/// target state, 409 with the allowed transitions otherwise.
fn check_folder_offer_transition(
    state: &AppState,
    folder_id: &str,
    device_id: &str,
    target: FolderOfferState,
) -> PairingCheck {
    let current = match state
        .sync_engine
        .storage()
        .folder_offer_state(folder_id, device_id)
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return PairingCheck::Reject(
                (
                    StatusCode::NOT_FOUND,
                    format!("No offer of folder '{folder_id}' from device {device_id}"),
                )
                    .into_response(),
            )
        }
        Err(e) => {
            return PairingCheck::Reject(
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            )
        }
    };
    if current == target {
        return PairingCheck::AlreadyThere;
    }
    if current.can_transition_to(target) {
        return PairingCheck::Apply;
    }
    PairingCheck::Reject(transition_conflict(
        "folder_offer",
        format!("{folder_id}@{device_id}"),
        current.as_str(),
        target.as_str(),
        current.metadata(),
    ))
}

async fn accept_pending_folder(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
    Json(payload): Json<AcceptFolderPayload>,
) -> impl IntoResponse {
    match check_folder_offer_transition(&state, &id, &payload.device_id, FolderOfferState::Accepted)
    {
        PairingCheck::Reject(resp) => return resp,
        PairingCheck::AlreadyThere => return StatusCode::OK.into_response(),
        PairingCheck::Apply => {}
    }
    if payload.local_path.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_field",
                "field": "local_path",
                "value": payload.local_path,
                "allowed": [],
                "message": "local_path must be a directory path on this device",
            })),
        )
            .into_response();
    }
    match state.sync_engine.storage().accept_pending_folder(
        &id,
        &payload.device_id,
        &payload.local_path,
    ) {
        Ok(_) => {
            // Same setup as registering a folder: without the mount-safety marker the
            // first scan would refuse and the accepted folder would sit in `error`.
            let marker = state
                .sync_engine
                .storage()
                .get_folder(&id)
                .ok()
                .flatten()
                .map(|f| (f.local_path, f.marker_name));
            if let Some((path, marker_name)) = marker {
                let root = std::path::Path::new(&path);
                let _ = std::fs::create_dir_all(root);
                let _ = crate::engine::fs_utils::ensure_folder_marker(root, &marker_name);
            }
            state.sync_engine.track_folder(&id);
            execute_folder_rescan(&state, &id);
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_rejected_folders(State(state): State<AppState>) -> impl IntoResponse {
    match state.sync_engine.storage().list_rejected_folders() {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `DELETE /api/v1/cluster/rejected/folders/:id?device_id=...`
async fn forget_rejected_folder(
    AxumPath(id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let Some(device_id) = params.get("device_id") else {
        return (StatusCode::BAD_REQUEST, "Missing device_id query parameter").into_response();
    };
    match state
        .sync_engine
        .storage()
        .forget_rejected_folder(&id, device_id)
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            format!("No rejected offer of folder '{id}' from device {device_id}"),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectFolderPayload {
    pub device_id: String,
}

async fn reject_pending_folder(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
    Json(payload): Json<RejectFolderPayload>,
) -> impl IntoResponse {
    match check_folder_offer_transition(&state, &id, &payload.device_id, FolderOfferState::Rejected)
    {
        PairingCheck::Reject(resp) => return resp,
        PairingCheck::AlreadyThere => return StatusCode::OK.into_response(),
        PairingCheck::Apply => {}
    }
    match state
        .sync_engine
        .storage()
        .reject_pending_folder(&id, &payload.device_id)
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// =============================================================================
// ROUTE HANDLERS: CONFLICTS
// =============================================================================

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
        Ok(Some(c)) => {
            let status = c.parsed_status();
            let dto = ConflictDetailsDto {
                conflict_id: c.conflict_id,
                folder_id: c.folder_id,
                relative_path: c.relative_path,
                base_revision: c.base_revision,
                local_revision: c.local_revision,
                remote_revision: c.remote_revision,
                staged_payload_path: c.staged_payload_path,
                status: c.status.as_str().to_string(),
                detected_at: c.detected_at,
                available_actions: status
                    .available_actions()
                    .into_iter()
                    .map(String::from)
                    .collect(),
                is_terminal: status.is_terminal(),
                state_description: status.description().to_string(),
            };
            Json(dto).into_response()
        }
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
        Some(rev) => state
            .sync_engine
            .storage()
            .read_file_from_revision(&rev)
            .unwrap_or_default(),
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
        _ => return (StatusCode::NOT_FOUND, "Folder missing").into_response(),
    };

    let local_file_path = PathBuf::from(&folder.local_path).join(&conflict.relative_path);
    let bytes = fs::read(&local_file_path).unwrap_or_default();

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

    let bytes = fs::read(&conflict.staged_payload_path).unwrap_or_default();

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
        _ => return (StatusCode::NOT_FOUND, "Folder missing").into_response(),
    };

    let local_bytes = fs::read(PathBuf::from(&folder.local_path).join(&conflict.relative_path))
        .unwrap_or_default();
    let remote_bytes = fs::read(&conflict.staged_payload_path).unwrap_or_default();
    let base_bytes = match &conflict.base_revision {
        Some(rev) => state
            .sync_engine
            .storage()
            .read_file_from_revision(rev)
            .unwrap_or_default(),
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
        conflict_id: conflict.conflict_id,
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

async fn ignore_conflict(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.conflict_engine().ignore(&id) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn reopen_conflict(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.sync_engine.conflict_engine().reopen(&id) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// =============================================================================
// ROUTE HANDLERS: WEBSOCKET EVENT STREAM
// =============================================================================

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
    16 * 1024 * 1024
}
