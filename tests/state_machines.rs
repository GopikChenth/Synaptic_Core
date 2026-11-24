//! End-to-end tests for the runtime state machines as seen through the HTTP API and the
//! event stream: folder activity (never stuck, errors carry a reason) and peer presence.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::broadcast;
use tower::ServiceExt;

use synapse_core::api::{ApiServer, AppState, DeviceView, SystemStatusResponse};
use synapse_core::conflict::{ConflictEngine, CoreEvent};
use synapse_core::dag::RevisionNode;
use synapse_core::engine::fs_utils::ensure_folder_marker;
use synapse_core::engine::SyncEngine;
use synapse_core::p2p::P2PManager;
use synapse_core::storage::{
    DeviceRecord, FolderRecord, PendingDeviceRecord, PendingFolderRecord, StorageEngine,
};

struct Harness {
    dir: PathBuf,
    engine: SyncEngine,
    storage: StorageEngine,
    router: axum::Router,
    events: broadcast::Receiver<CoreEvent>,
}

impl Harness {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("synapse_sm_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let storage = StorageEngine::new(&dir).unwrap();
        let (tx, events) = broadcast::channel(512);
        let conflicts = Arc::new(ConflictEngine::new(
            storage.clone(),
            tx.clone(),
            "dev_a".into(),
        ));
        let engine = SyncEngine::new(storage.clone(), conflicts, tx, "dev_a".into());
        let router = ApiServer::create_router(AppState {
            start_time: std::time::Instant::now(),
            sync_engine: engine.clone(),
            auth_token: None,
            peer_count: Arc::new(AtomicUsize::new(0)),
            shutdown_tx: None,
        });
        Self {
            dir,
            engine,
            storage,
            router,
            events,
        }
    }

    fn pending(&self, id: &str) -> PendingDeviceRecord {
        PendingDeviceRecord {
            device_id: id.into(),
            name: format!("{id}-name"),
            address: "10.0.0.9:9190".into(),
            received_at: 1,
            cert_pin: None,
        }
    }

    async fn post_json(
        &self,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn call(&self, method: &str, uri: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn state_changes(&mut self) -> Vec<(String, String, Option<String>)> {
        let mut out = Vec::new();
        while let Ok(ev) = self.events.try_recv() {
            if let CoreEvent::FolderStateChanged {
                from, to, error, ..
            } = ev
            {
                out.push((from, to, error));
            }
        }
        out
    }

    fn sync_events(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(ev) = self.events.try_recv() {
            match ev {
                CoreEvent::SyncStarted { .. } => out.push("SYNC_STARTED".into()),
                CoreEvent::SyncCompleted { files_synced, .. } => {
                    out.push(format!("SYNC_COMPLETED({files_synced})"))
                }
                _ => {}
            }
        }
        out
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn scan_failure_surfaces_reason_and_recovers_on_rescan() {
    let mut h = Harness::new();
    let root = h.dir.join("vault");
    fs::create_dir_all(&root).unwrap();
    // Registered without its mount-safety marker: scanning must refuse.
    h.storage
        .add_folder(&FolderRecord::new("vault", root.to_string_lossy()))
        .unwrap();

    assert!(h.engine.index_folder("vault").is_err());

    let (code, st) = h.call("GET", "/api/v1/folders/vault/status").await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(st["state"], "error");
    let reason = st["error"].as_str().expect("error reason present");
    assert!(reason.to_lowercase().contains("marker"), "{reason}");

    let changes = h.state_changes();
    assert_eq!(changes[0].1, "scanning");
    assert_eq!(changes[1].1, "error");
    assert!(
        changes[1].2.is_some(),
        "FOLDER_STATE_CHANGED carries the reason"
    );

    let (_, sys) = h.call("GET", "/api/v1/system/status").await;
    let sys: SystemStatusResponse = serde_json::from_value(sys).unwrap();
    assert_eq!(sys.folder_states.get("error"), Some(&1));
    assert_eq!(sys.sync_state, "IDLE", "historical values unchanged");

    // Fix the cause and rescan: error clears, field disappears from the payload.
    ensure_folder_marker(&root, ".synapse-folder").unwrap();
    h.engine.index_folder("vault").unwrap();
    let (_, st) = h.call("GET", "/api/v1/folders/vault/status").await;
    assert_eq!(st["state"], "idle");
    assert!(st.get("error").is_none(), "{st}");
}

#[tokio::test]
async fn failed_remote_apply_never_leaves_folder_syncing() {
    let mut h = Harness::new();
    let root = h.dir.join("docs");
    fs::create_dir_all(&root).unwrap();
    ensure_folder_marker(&root, ".synapse-folder").unwrap();
    h.storage
        .add_folder(&FolderRecord::new("docs", root.to_string_lossy()))
        .unwrap();

    let bogus = RevisionNode {
        revision_hash: "00".into(),
        parent_hashes: vec![],
        manifest_hash: "00".into(),
        author_device_id: "dev_b".into(),
        sequence_number: 1,
        mtime_nanos: 0,
        file_size: 3,
    };
    // Rejected mid-flight (empty path); previously this left the folder in "syncing".
    assert!(h
        .engine
        .reconcile_remote_revision("docs", "", &bogus, &[], b"abc")
        .is_err());

    assert_eq!(h.engine.get_folder_state("docs").as_str(), "idle");
    let (_, st) = h.call("GET", "/api/v1/folders/docs/status").await;
    assert_eq!(st["state"], "idle");
    // The long-declared but never-emitted sync events now fire.
    assert_eq!(h.sync_events(), ["SYNC_STARTED", "SYNC_COMPLETED(0)"]);
}

#[tokio::test]
async fn pause_and_resume_emit_state_changes() {
    let mut h = Harness::new();
    let root = h.dir.join("music");
    fs::create_dir_all(&root).unwrap();
    h.storage
        .add_folder(&FolderRecord::new("music", root.to_string_lossy()))
        .unwrap();
    // As done for every folder when the engine starts.
    h.engine.track_folder("music");

    let (code, _) = h.call("POST", "/api/v1/folders/music/pause").await;
    assert_eq!(code, StatusCode::OK);
    let (_, st) = h.call("GET", "/api/v1/folders/music/status").await;
    assert_eq!(st["state"], "paused");

    let (code, _) = h.call("POST", "/api/v1/folders/music/resume").await;
    assert_eq!(code, StatusCode::OK);
    let changes: Vec<(String, String)> = h
        .state_changes()
        .into_iter()
        .map(|(f, t, _)| (f, t))
        .collect();
    assert_eq!(
        changes,
        [
            ("idle".to_string(), "paused".to_string()),
            ("paused".to_string(), "idle".to_string())
        ]
    );

    let (code, _) = h.call("DELETE", "/api/v1/folders/music").await;
    assert_eq!(code, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn devices_report_derived_state_and_presence() {
    let h = Harness::new();
    for (id, paused) in [("PEER_A", false), ("PEER_B", true)] {
        h.storage
            .add_device(&DeviceRecord {
                device_id: id.into(),
                name: id.to_lowercase(),
                addresses: vec!["dynamic".into()],
                is_paused: paused,
                is_trusted: true,
                introducer: false,
                cert_name: None,
                created_at: 1,
            })
            .unwrap();
    }

    let (_, list) = h.call("GET", "/api/v1/devices").await;
    let views: Vec<DeviceView> = serde_json::from_value(list.clone()).unwrap();
    let by_id: HashMap<_, _> = views
        .iter()
        .map(|v| (v.device.device_id.as_str(), v))
        .collect();
    assert_eq!(by_id["PEER_A"].state, "paired");
    assert_eq!(by_id["PEER_B"].state, "paused");
    assert!(!by_id["PEER_A"].online);
    // Existing fields are still present at the top level (flattened, non-breaking).
    assert_eq!(
        list[0]["device_id"]
            .as_str()
            .map(|s| s.starts_with("PEER_")),
        Some(true)
    );
    assert!(list[0].get("is_paused").is_some());

    h.engine.peer_presence().heard_from("PEER_A");
    h.engine.peer_presence().heard_from("PEER_B");
    let (_, dev) = h.call("GET", "/api/v1/devices/PEER_A").await;
    assert_eq!(dev["online"], true);
    assert!(dev["last_seen_secs"].is_u64());
    let (_, dev) = h.call("GET", "/api/v1/devices/PEER_B").await;
    assert_eq!(
        dev["online"], false,
        "paused devices are never reported online"
    );
}

#[tokio::test]
async fn introspection_lists_every_runtime_machine() {
    let h = Harness::new();
    let (code, body) = h.call("GET", "/api/v1/system/statemachines").await;
    assert_eq!(code, StatusCode::OK);
    let text = body.to_string();
    for id in [
        "conflict_lifecycle",
        "folder_sync_lifecycle",
        "device_pairing_lifecycle",
        "peer_presence",
        "engine_lifecycle",
        "folder_offer_lifecycle",
    ] {
        assert!(text.contains(id), "missing {id}");
    }
}

#[tokio::test]
async fn rejected_device_stays_rejected_until_forgotten() {
    let mut h = Harness::new();
    let (tx, _) = broadcast::channel(16);
    assert!(h
        .storage
        .add_pending_device(&h.pending("STRANGER"))
        .unwrap());

    let (code, _) = h
        .call("POST", "/api/v1/cluster/pending/devices/STRANGER/reject")
        .await;
    assert_eq!(code, StatusCode::OK);
    // Rejecting again is idempotent.
    let (code, _) = h
        .call("POST", "/api/v1/cluster/pending/devices/STRANGER/reject")
        .await;
    assert_eq!(code, StatusCode::OK);

    // Its next discovery broadcast must not re-prompt the user.
    while h.events.try_recv().is_ok() {}
    P2PManager::stage_pending_peer(
        &h.storage,
        &tx,
        "STRANGER",
        "stranger",
        "10.0.0.9:9190",
        None,
    );
    let mut rx = tx.subscribe();
    P2PManager::stage_pending_peer(
        &h.storage,
        &tx,
        "STRANGER",
        "stranger",
        "10.0.0.9:9190",
        None,
    );
    assert!(
        rx.try_recv().is_err(),
        "no DEVICE_PENDING for a rejected device"
    );
    let (_, pending) = h.call("GET", "/api/v1/cluster/pending/devices").await;
    assert_eq!(pending, serde_json::json!([]));

    let (_, rejected) = h.call("GET", "/api/v1/cluster/rejected/devices").await;
    assert_eq!(rejected[0]["device_id"], "STRANGER");

    // Accepting a rejected request is an invalid transition with a recovery hint.
    let (code, err) = h
        .call("POST", "/api/v1/cluster/pending/devices/STRANGER/accept")
        .await;
    assert_eq!(code, StatusCode::CONFLICT);
    assert_eq!(err["current_state"], "rejected");
    assert_eq!(err["available_actions"], serde_json::json!(["FORGET"]));

    // Forget -> the device may ask again.
    let (code, _) = h
        .call("DELETE", "/api/v1/cluster/rejected/devices/STRANGER")
        .await;
    assert_eq!(code, StatusCode::NO_CONTENT);
    let (code, _) = h
        .call("DELETE", "/api/v1/cluster/rejected/devices/STRANGER")
        .await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert!(h
        .storage
        .add_pending_device(&h.pending("STRANGER"))
        .unwrap());
}

#[tokio::test]
async fn pairing_actions_are_validated_against_the_state_machine() {
    let h = Harness::new();
    h.storage.add_pending_device(&h.pending("NEWBIE")).unwrap();

    // Pausing a device that is only pending: 409 with what *is* possible.
    let (code, err) = h.call("POST", "/api/v1/devices/NEWBIE/pause").await;
    assert_eq!(code, StatusCode::CONFLICT);
    assert_eq!(err["entity"], "device");
    assert_eq!(err["current_state"], "pending");
    assert_eq!(err["attempted_transition"], "paused");
    assert_eq!(
        err["allowed_transitions"],
        serde_json::json!(["paired", "rejected"])
    );
    assert_eq!(
        err["available_actions"],
        serde_json::json!(["ACCEPT", "REJECT"])
    );

    // Unknown devices are 404, not a silent 200.
    let (code, _) = h.call("POST", "/api/v1/devices/GHOST/pause").await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    let (code, _) = h
        .call("POST", "/api/v1/cluster/pending/devices/GHOST/accept")
        .await;
    assert_eq!(code, StatusCode::NOT_FOUND);

    // Happy path, with idempotent repeats.
    for (uri, expect) in [
        ("/api/v1/cluster/pending/devices/NEWBIE/accept", "paired"),
        ("/api/v1/cluster/pending/devices/NEWBIE/accept", "paired"),
        ("/api/v1/devices/NEWBIE/pause", "paused"),
        ("/api/v1/devices/NEWBIE/pause", "paused"),
        ("/api/v1/devices/NEWBIE/resume", "paired"),
        ("/api/v1/devices/NEWBIE/resume", "paired"),
    ] {
        let (code, _) = h.call("POST", uri).await;
        assert_eq!(code, StatusCode::OK, "{uri}");
        let (_, dev) = h.call("GET", "/api/v1/devices/NEWBIE").await;
        assert_eq!(dev["state"], expect, "{uri}");
    }

    // A paired device can't be "rejected".
    let (code, err) = h
        .call("POST", "/api/v1/cluster/pending/devices/NEWBIE/reject")
        .await;
    assert_eq!(code, StatusCode::CONFLICT);
    assert_eq!(err["current_state"], "paired");
}

#[tokio::test]
async fn folder_registration_rejects_unknown_policies_with_choices() {
    let h = Harness::new();
    let root = h.dir.join("cfg");
    fs::create_dir_all(&root).unwrap();
    let post = |body: serde_json::Value| {
        let router = h.router.clone();
        async move {
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/folders")
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let res = router.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
            )
        }
    };
    let path = root.to_string_lossy().to_string();

    let (code, err) = post(serde_json::json!({
        "folder_id": "cfg", "local_path": path, "sync_mode": "mirror"
    }))
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_field");
    assert_eq!(err["field"], "sync_mode");
    assert_eq!(
        err["allowed"],
        serde_json::json!(["SendReceive", "SendOnly", "ReceiveOnly"])
    );
    let (_, list) = h.call("GET", "/api/v1/folders").await;
    assert_eq!(
        list,
        serde_json::json!([]),
        "nothing persisted on rejection"
    );

    // Every spelling that worked before still works, and is stored as given.
    let (code, folder) = post(serde_json::json!({
        "folder_id": "cfg", "local_path": path, "sync_mode": "SEND_RECEIVE",
        "pull_order": "random", "versioning_type": "SIMPLE"
    }))
    .await;
    assert_eq!(code, StatusCode::CREATED);
    assert_eq!(folder["sync_mode"], "SEND_RECEIVE");
}

#[tokio::test]
async fn folder_offers_follow_their_state_machine() {
    let h = Harness::new();
    let offer = |id: &str| PendingFolderRecord {
        folder_id: id.into(),
        device_id: "PEER_X".into(),
        folder_label: id.to_uppercase(),
        offered_at: 1,
    };
    let local = h.dir.join("photos");
    let accept_body = serde_json::json!({
        "device_id": "PEER_X", "local_path": local.to_string_lossy()
    });

    // Accepting an offer that doesn't exist used to silently create the folder.
    let (code, _) = h
        .post_json(
            "/api/v1/cluster/pending/folders/photos/accept",
            accept_body.clone(),
        )
        .await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert!(h.storage.get_folder("photos").unwrap().is_none());

    assert!(h.storage.add_pending_folder(&offer("photos")).unwrap());
    let (code, _) = h
        .post_json(
            "/api/v1/cluster/pending/folders/photos/accept",
            serde_json::json!({"device_id": "PEER_X", "local_path": "  "}),
        )
        .await;
    assert_eq!(code, StatusCode::BAD_REQUEST, "empty local_path");

    let (code, _) = h
        .post_json(
            "/api/v1/cluster/pending/folders/photos/accept",
            accept_body.clone(),
        )
        .await;
    assert_eq!(code, StatusCode::OK);
    // Accepted folders get their mount-safety marker, so the first scan succeeds.
    assert!(local.join(".synapse-folder").exists());
    let mut state = String::new();
    for _ in 0..100 {
        let (_, st) = h.call("GET", "/api/v1/folders/photos/status").await;
        state = st["state"].as_str().unwrap_or_default().to_string();
        if state == "idle" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(state, "idle", "accepted folder must not land in error");

    // Repeat accept: no-op. Reject after accept: 409 with recovery hints.
    let (code, _) = h
        .post_json("/api/v1/cluster/pending/folders/photos/accept", accept_body)
        .await;
    assert_eq!(code, StatusCode::OK);
    let (code, err) = h
        .post_json(
            "/api/v1/cluster/pending/folders/photos/reject",
            serde_json::json!({"device_id": "PEER_X"}),
        )
        .await;
    assert_eq!(code, StatusCode::CONFLICT);
    assert_eq!(err["entity"], "folder_offer");
    assert_eq!(err["current_state"], "accepted");

    // Reject -> remembered -> not re-staged -> forget -> can be offered again.
    assert!(h.storage.add_pending_folder(&offer("junk")).unwrap());
    for _ in 0..2 {
        let (code, _) = h
            .post_json(
                "/api/v1/cluster/pending/folders/junk/reject",
                serde_json::json!({"device_id": "PEER_X"}),
            )
            .await;
        assert_eq!(code, StatusCode::OK);
    }
    assert!(!h.storage.add_pending_folder(&offer("junk")).unwrap());
    let (_, rejected) = h.call("GET", "/api/v1/cluster/rejected/folders").await;
    assert_eq!(rejected[0]["folder_id"], "junk");
    let (code, _) = h
        .call("DELETE", "/api/v1/cluster/rejected/folders/junk")
        .await;
    assert_eq!(code, StatusCode::BAD_REQUEST, "device_id is required");
    let (code, _) = h
        .call(
            "DELETE",
            "/api/v1/cluster/rejected/folders/junk?device_id=PEER_X",
        )
        .await;
    assert_eq!(code, StatusCode::NO_CONTENT);
    assert!(h.storage.add_pending_folder(&offer("junk")).unwrap());
}

#[tokio::test]
async fn conflict_status_keeps_its_wire_format() {
    let h = Harness::new();
    let (code, list) = h.call("GET", "/api/v1/conflicts").await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(list, serde_json::json!([]));
    // Typed field serializes exactly as the old string did.
    let status = synapse_core::state::ConflictStatus::Pending;
    assert_eq!(serde_json::to_value(status).unwrap(), "PENDING");
    assert!(status == "PENDING");
    assert_eq!(format!("{status:<9}|"), "PENDING  |");
}
