//! End-to-end integration tests for Synapse Core Control Plane & API Surface.
//!
//! Tests:
//! 1. Content-Defined Chunking & Deduplication via BLAKE3 + CAS
//! 2. Merkle DAG LCA resolution & 3-Way Semantic Auto-Merge (Tier 1)
//! 3. Virtual Quarantine & Staging with Zero Disk Pollution (Tier 2)
//! 4. System endpoints (`/rest/system/*` and `/api/v1/system/*`)
//! 5. Cluster pairing & device management (`/rest/cluster/*`, `/api/v1/cluster/*`, `/api/v1/devices/*`)
//! 6. Folder controls, status, completion, rescan, ignores, and sharing (`/rest/db/*`, `/api/v1/folders/*`)
//! 7. Quarantined conflict inspection, 3-way diff generation, and Tier 3 resolution actions
//! 8. WebSocket real-time event streaming and ping/pong (`/api/v1/events` and `/rest/events`)

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

use synapse_core::api::{
    AcceptFolderPayload, ApiServer, AppState, DiffResponse, FolderDto, IgnoresRequest,
    RegisterFolderRequest, RejectFolderPayload, SystemStatusResponse, SystemVersionResponse,
};
use synapse_core::chunker::Chunker;
use synapse_core::conflict::{diff3, ConflictEngine, CoreEvent, ResolveAction, ResolveRequest};
use synapse_core::dag::RevisionNode;
use synapse_core::engine::SyncEngine;
use synapse_core::storage::{
    DeviceCompletionMetrics, DeviceRecord, FolderRecord, FolderStatusMetrics,
    PendingDeviceRecord, PendingFolderRecord, StorageEngine,
};

struct TestHarness {
    temp_dir: PathBuf,
    storage: StorageEngine,
    sync_engine: SyncEngine,
    #[allow(dead_code)]
    conflict_engine: Arc<ConflictEngine>,
    app_state: AppState,
}

impl TestHarness {
    fn new() -> Self {
        let temp_dir = std::env::temp_dir().join(format!("synapse_integ_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let storage = StorageEngine::new(&temp_dir).unwrap();
        let (tx, _) = tokio::sync::broadcast::channel(128);
        let device_id = "test_dev_01".to_string();

        let conflict_engine = Arc::new(ConflictEngine::new(
            storage.clone(),
            tx.clone(),
            device_id.clone(),
        ));

        let sync_engine = SyncEngine::new(
            storage.clone(),
            conflict_engine.clone(),
            tx,
            device_id,
        );

        let app_state = AppState {
            start_time: std::time::Instant::now(),
            sync_engine: sync_engine.clone(),
            auth_token: None,
            peer_count: Arc::new(AtomicUsize::new(0)),
        };

        Self {
            temp_dir,
            storage,
            sync_engine,
            conflict_engine,
            app_state,
        }
    }

    /// Helper to stage a quarantined conflict with distinct base, local, and remote edits.
    fn stage_conflict(
        &self,
        folder_id: &str,
        file_rel: &str,
        base_text: &str,
        local_text: &str,
        remote_text: &str,
        remote_author: &str,
    ) -> String {
        let folder = self.storage.get_folder(folder_id).unwrap().unwrap();
        let folder_path = PathBuf::from(&folder.local_path);
        let file_path = folder_path.join(file_rel);

        // 1. Base file
        fs::write(&file_path, base_text).unwrap();
        self.sync_engine.index_single_file(folder_id, file_rel).unwrap();
        let base_file = self.storage.get_file(folder_id, file_rel).unwrap().unwrap();

        // 2. Local edit
        fs::write(&file_path, local_text).unwrap();
        self.sync_engine.index_single_file(folder_id, file_rel).unwrap();

        // 3. Remote edit
        let chunker = Chunker::default();
        let (remote_chunks, remote_manifest) = chunker.chunk_slice(remote_text.as_bytes());
        for (info, data) in &remote_chunks {
            self.storage.put_chunk(&info.chunk_hash, data).unwrap();
        }
        let remote_chunk_hashes: Vec<String> = remote_chunks.into_iter().map(|(c, _)| c.chunk_hash).collect();

        let remote_rev = RevisionNode::new(
            vec![base_file.current_revision.clone()],
            remote_manifest,
            remote_author.into(),
            3003,
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            remote_text.len() as u64,
        );

        // 4. Reconcile remote revision (triggers Tier 2 quarantine due to overlapping edits)
        self.sync_engine.reconcile_remote_revision(
            folder_id,
            file_rel,
            &remote_rev,
            &remote_chunk_hashes,
            remote_text.as_bytes(),
        ).unwrap();

        let conflicts = self.storage.list_pending_conflicts().unwrap();
        let c = conflicts.iter().find(|c| c.relative_path == file_rel).expect("Quarantined conflict must exist");
        c.conflict_id.clone()
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

// =============================================================================
// TEST 1: TIER 1 AUTOMATED 3-WAY MERGE
// =============================================================================

#[tokio::test]
async fn test_tier1_automated_3way_merge() {
    let harness = TestHarness::new();
    let folder_path = harness.temp_dir.join("notes");
    fs::create_dir_all(&folder_path).unwrap();

    let folder_id = "notes_vault";
    harness.storage.add_folder(&FolderRecord::new(
        folder_id,
        folder_path.to_string_lossy(),
    )).unwrap();

    // 1. Create Base File
    let file_rel = "doc.md";
    let file_path = folder_path.join(file_rel);
    let base_content = "# Project Notes\n\nSection A: Introduction\n\nSection B: Conclusion\n";
    fs::write(&file_path, base_content).unwrap();

    harness.sync_engine.index_single_file(folder_id, file_rel).unwrap();
    let base_file = harness.storage.get_file(folder_id, file_rel).unwrap().unwrap();
    let base_rev_hash = base_file.current_revision.clone();

    // 2. Local Edits Section A
    let local_content = "# Project Notes\n\nSection A: Introduction with Desktop details\n\nSection B: Conclusion\n";
    fs::write(&file_path, local_content).unwrap();
    harness.sync_engine.index_single_file(folder_id, file_rel).unwrap();
    let local_file = harness.storage.get_file(folder_id, file_rel).unwrap().unwrap();
    let local_rev_hash = local_file.current_revision.clone();

    // 3. Remote Edits Section B (Concurrent edit, diverged from Base)
    let remote_content = "# Project Notes\n\nSection A: Introduction\n\nSection B: Conclusion updated by Mobile\n";
    let chunker = Chunker::default();
    let (remote_chunks, remote_manifest) = chunker.chunk_slice(remote_content.as_bytes());
    for (info, data) in &remote_chunks {
        harness.storage.put_chunk(&info.chunk_hash, data).unwrap();
    }
    let remote_chunk_hashes: Vec<String> = remote_chunks.into_iter().map(|(c, _)| c.chunk_hash).collect();

    let remote_rev = RevisionNode::new(
        vec![base_rev_hash.clone()],
        remote_manifest,
        "mobile_device_02".into(),
        1001,
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        remote_content.len() as u64,
    );

    // 4. Reconcile Remote Revision
    harness.sync_engine.reconcile_remote_revision(
        folder_id,
        file_rel,
        &remote_rev,
        &remote_chunk_hashes,
        remote_content.as_bytes(),
    ).unwrap();

    // 5. Verify Clean 3-Way Auto-Merge on disk
    let merged_on_disk = fs::read_to_string(&file_path).unwrap();
    assert!(merged_on_disk.contains("Section A: Introduction with Desktop details"));
    assert!(merged_on_disk.contains("Section B: Conclusion updated by Mobile"));

    // Verify 2-parent merge commit
    let updated_file = harness.storage.get_file(folder_id, file_rel).unwrap().unwrap();
    let merge_rev = harness.storage.get_revision(&updated_file.current_revision).unwrap().unwrap();
    assert_eq!(merge_rev.parent_1, Some(local_rev_hash));
    assert_eq!(merge_rev.parent_2, Some(remote_rev.revision_hash));

    // Zero conflicts in quarantine!
    let conflicts = harness.storage.list_pending_conflicts().unwrap();
    assert_eq!(conflicts.len(), 0);
}

// =============================================================================
// TEST 2: TIER 2 VIRTUAL QUARANTINE ZERO DISK POLLUTION
// =============================================================================

#[tokio::test]
async fn test_tier2_virtual_quarantine_zero_pollution() {
    let harness = TestHarness::new();
    let folder_path = harness.temp_dir.join("vault");
    fs::create_dir_all(&folder_path).unwrap();

    let folder_id = "vault";
    harness.storage.add_folder(&FolderRecord::new(
        folder_id,
        folder_path.to_string_lossy(),
    )).unwrap();

    // 1. Base File
    let file_rel = "todo.txt";
    let file_path = folder_path.join(file_rel);
    let base_content = "Task 1: Pending\nTask 2: In Progress\n";
    fs::write(&file_path, base_content).unwrap();
    harness.sync_engine.index_single_file(folder_id, file_rel).unwrap();
    let base_file = harness.storage.get_file(folder_id, file_rel).unwrap().unwrap();

    // 2. Local Edits Task 2
    let local_content = "Task 1: Pending\nTask 2: Finished by Alice\n";
    fs::write(&file_path, local_content).unwrap();
    harness.sync_engine.index_single_file(folder_id, file_rel).unwrap();

    // 3. Remote concurrently edits Task 2 differently (OVERLAPPING EDIT)
    let remote_content = "Task 1: Pending\nTask 2: Blocked by Bob\n";
    let chunker = Chunker::default();
    let (remote_chunks, remote_manifest) = chunker.chunk_slice(remote_content.as_bytes());
    for (info, data) in &remote_chunks {
        harness.storage.put_chunk(&info.chunk_hash, data).unwrap();
    }
    let remote_chunk_hashes: Vec<String> = remote_chunks.into_iter().map(|(c, _)| c.chunk_hash).collect();

    let remote_rev = RevisionNode::new(
        vec![base_file.current_revision.clone()],
        remote_manifest,
        "bob_device".into(),
        2002,
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        remote_content.len() as u64,
    );

    // 4. Reconcile
    harness.sync_engine.reconcile_remote_revision(
        folder_id,
        file_rel,
        &remote_rev,
        &remote_chunk_hashes,
        remote_content.as_bytes(),
    ).unwrap();

    // 5. CRITICAL CHECK: ZERO FILESYSTEM POLLUTION!
    let disk_content = fs::read_to_string(&file_path).unwrap();
    assert_eq!(disk_content, local_content);

    let folder_entries: Vec<_> = fs::read_dir(&folder_path).unwrap().collect();
    assert_eq!(folder_entries.len(), 1, "User directory must not contain .sync-conflict-* clutter");

    // 6. Conflicting version safely quarantined in internal staging
    let conflicts = harness.storage.list_pending_conflicts().unwrap();
    assert_eq!(conflicts.len(), 1);
    let conflict = &conflicts[0];
    assert_eq!(conflict.relative_path, file_rel);
    assert_eq!(conflict.status, "PENDING");
    assert!(PathBuf::from(&conflict.staged_payload_path).exists());
}

// =============================================================================
// TEST 3: ALL SYSTEM ENDPOINTS (/rest/system/* & /api/v1/system/*)
// =============================================================================

#[tokio::test]
async fn test_system_endpoints_all() {
    let harness = TestHarness::new();
    let router = ApiServer::create_router(harness.app_state.clone());

    // 1. /rest/system/ping and /api/v1/system/ping
    let req_ping_rest = Request::builder()
        .uri("/rest/system/ping")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_ping_rest = router.clone().oneshot(req_ping_rest).await.unwrap();
    assert_eq!(res_ping_rest.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_ping_rest.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ping"], "pong");

    let req_ping_v1 = Request::builder()
        .uri("/api/v1/system/ping")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_ping_v1 = router.clone().oneshot(req_ping_v1).await.unwrap();
    assert_eq!(res_ping_v1.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_ping_v1.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ping"], "pong");

    // 2. /rest/system/version and /api/v1/system/version
    let req_ver_rest = Request::builder()
        .uri("/rest/system/version")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_ver_rest = router.clone().oneshot(req_ver_rest).await.unwrap();
    assert_eq!(res_ver_rest.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_ver_rest.into_body(), usize::MAX).await.unwrap();
    let ver_rest: SystemVersionResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(ver_rest.version, "v1.0.0");
    assert_eq!(ver_rest.codename, "Synapse-SynapticCore");
    assert!(!ver_rest.os.is_empty());
    assert!(!ver_rest.arch.is_empty());

    let req_ver_v1 = Request::builder()
        .uri("/api/v1/system/version")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_ver_v1 = router.clone().oneshot(req_ver_v1).await.unwrap();
    assert_eq!(res_ver_v1.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_ver_v1.into_body(), usize::MAX).await.unwrap();
    let ver_v1: SystemVersionResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(ver_v1.version, "v1.0.0");
    assert_eq!(ver_v1.codename, "Synapse-SynapticCore");

    // 3. /rest/system/status and /api/v1/system/status
    let req_status_rest = Request::builder()
        .uri("/rest/system/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_status_rest = router.clone().oneshot(req_status_rest).await.unwrap();
    assert_eq!(res_status_rest.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_status_rest.into_body(), usize::MAX).await.unwrap();
    let status_rest: SystemStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(status_rest.device_id, "test_dev_01");
    assert_eq!(status_rest.sync_state, "IDLE");
    assert_eq!(status_rest.monitored_folders_count, 0);
    assert_eq!(status_rest.pending_conflicts_count, 0);
    assert_eq!(status_rest.peer_count, 0);
    assert!(status_rest.memory_footprint_bytes > 0);

    let req_status_v1 = Request::builder()
        .uri("/api/v1/system/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_status_v1 = router.clone().oneshot(req_status_v1).await.unwrap();
    assert_eq!(res_status_v1.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_status_v1.into_body(), usize::MAX).await.unwrap();
    let status_v1: SystemStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(status_v1.device_id, "test_dev_01");

    // 4. /rest/system/connections and /api/v1/connections
    let dev = DeviceRecord {
        device_id: "DEV_PEER_01".into(),
        name: "Remote Workstation".into(),
        addresses: vec!["10.0.0.12:9190".into()],
        is_paused: false,
        is_trusted: false,
        introducer: false,
        cert_name: None,
        created_at: 123456,
    };
    harness.storage.add_device(&dev).unwrap();

    let req_conn_rest = Request::builder()
        .uri("/rest/system/connections")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_conn_rest = router.clone().oneshot(req_conn_rest).await.unwrap();
    assert_eq!(res_conn_rest.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_conn_rest.into_body(), usize::MAX).await.unwrap();
    let conn_map: HashMap<String, synapse_core::storage::PeerConnectionMetrics> =
        serde_json::from_slice(&body).unwrap();
    assert!(conn_map.contains_key("DEV_PEER_01"));
    let peer_metrics = &conn_map["DEV_PEER_01"];
    assert_eq!(peer_metrics.device_id, "DEV_PEER_01");
    assert_eq!(peer_metrics.address, "10.0.0.12:9190");
    assert!(peer_metrics.is_connected);

    let req_conn_v1 = Request::builder()
        .uri("/api/v1/connections")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_conn_v1 = router.clone().oneshot(req_conn_v1).await.unwrap();
    assert_eq!(res_conn_v1.status(), StatusCode::OK);

    // 5. /rest/system/shutdown and /api/v1/system/shutdown
    let req_sd_rest = Request::builder()
        .uri("/rest/system/shutdown")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_sd_rest = router.clone().oneshot(req_sd_rest).await.unwrap();
    assert_eq!(res_sd_rest.status(), StatusCode::OK);

    let req_sd_v1 = Request::builder()
        .uri("/api/v1/system/shutdown")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_sd_v1 = router.clone().oneshot(req_sd_v1).await.unwrap();
    assert_eq!(res_sd_v1.status(), StatusCode::OK);

    // 6. /rest/system/restart and /api/v1/system/restart
    let req_rs_rest = Request::builder()
        .uri("/rest/system/restart")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_rs_rest = router.clone().oneshot(req_rs_rest).await.unwrap();
    assert_eq!(res_rs_rest.status(), StatusCode::OK);

    let req_rs_v1 = Request::builder()
        .uri("/api/v1/system/restart")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_rs_v1 = router.clone().oneshot(req_rs_v1).await.unwrap();
    assert_eq!(res_rs_v1.status(), StatusCode::OK);
}

// =============================================================================
// TEST 4: ALL CLUSTER PAIRING & DEVICE ENDPOINTS
// =============================================================================

#[tokio::test]
async fn test_cluster_pairing_and_devices_all() {
    let harness = TestHarness::new();
    let router = ApiServer::create_router(harness.app_state.clone());

    // 1. Pending Device Invitations (GET via /rest & /api/v1)
    let pending_dev1 = PendingDeviceRecord {
        device_id: "MF7F22G-ABCD123-WXYZ789-KLMN456".into(),
        name: "MacBook Pro".into(),
        address: "192.168.1.50:9190".into(),
        received_at: 1000,
    };
    harness.storage.add_pending_device(&pending_dev1).unwrap();

    let req_p1 = Request::builder()
        .uri("/rest/cluster/pending/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_p1 = router.clone().oneshot(req_p1).await.unwrap();
    assert_eq!(res_p1.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_p1.into_body(), usize::MAX).await.unwrap();
    let list: Vec<PendingDeviceRecord> = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].device_id, pending_dev1.device_id);

    let req_p2 = Request::builder()
        .uri("/api/v1/cluster/pending/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_p2 = router.clone().oneshot(req_p2).await.unwrap();
    assert_eq!(res_p2.status(), StatusCode::OK);

    // 2. Accept Pending Device via /api/v1/cluster/pending/devices/:id/accept
    let accept_uri = format!("/api/v1/cluster/pending/devices/{}/accept", pending_dev1.device_id);
    let req_accept = Request::builder()
        .uri(&accept_uri)
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_accept = router.clone().oneshot(req_accept).await.unwrap();
    assert_eq!(res_accept.status(), StatusCode::OK);

    // Verify moved to paired devices
    let req_devs = Request::builder()
        .uri("/api/v1/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_devs = router.clone().oneshot(req_devs).await.unwrap();
    assert_eq!(res_devs.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_devs.into_body(), usize::MAX).await.unwrap();
    let paired: Vec<DeviceRecord> = serde_json::from_slice(&body).unwrap();
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].device_id, pending_dev1.device_id);

    // Verify removed from pending
    let pending_after = harness.storage.list_pending_devices().unwrap();
    assert_eq!(pending_after.len(), 0);

    // 3. Reject Pending Device via /rest/cluster/pending/devices/:id/reject
    let pending_dev2 = PendingDeviceRecord {
        device_id: "STRANGER-DEVICE-9999".into(),
        name: "Unknown Node".into(),
        address: "10.10.10.10:9190".into(),
        received_at: 2000,
    };
    harness.storage.add_pending_device(&pending_dev2).unwrap();

    let reject_uri = format!("/rest/cluster/pending/devices/{}/reject", pending_dev2.device_id);
    let req_rej = Request::builder()
        .uri(&reject_uri)
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_rej = router.clone().oneshot(req_rej).await.unwrap();
    assert_eq!(res_rej.status(), StatusCode::OK);

    let pending_after_rej = harness.storage.list_pending_devices().unwrap();
    assert_eq!(pending_after_rej.len(), 0);

    // 4. Device Management: Add via /api/v1/devices and /rest/system/devices
    let dev_alpha = DeviceRecord {
        device_id: "ALPHA-DEV-001".into(),
        name: "Alpha Machine".into(),
        addresses: vec!["192.168.1.100:9190".into()],
        is_paused: false,
        is_trusted: false,
        introducer: false,
        cert_name: None,
        created_at: 3000,
    };
    let dev_alpha_json = serde_json::to_string(&dev_alpha).unwrap();
    let req_add_v1 = Request::builder()
        .uri("/api/v1/devices")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(dev_alpha_json))
        .unwrap();
    let res_add_v1 = router.clone().oneshot(req_add_v1).await.unwrap();
    assert_eq!(res_add_v1.status(), StatusCode::CREATED);

    let dev_beta = DeviceRecord {
        device_id: "BETA-DEV-002".into(),
        name: "Beta Machine".into(),
        addresses: vec!["192.168.1.101:9190".into()],
        is_paused: false,
        is_trusted: false,
        introducer: false,
        cert_name: None,
        created_at: 4000,
    };
    let dev_beta_json = serde_json::to_string(&dev_beta).unwrap();
    let req_add_rest = Request::builder()
        .uri("/rest/system/devices")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(dev_beta_json))
        .unwrap();
    let res_add_rest = router.clone().oneshot(req_add_rest).await.unwrap();
    assert_eq!(res_add_rest.status(), StatusCode::CREATED);

    // Verify GET /api/v1/devices/:id
    let req_get_dev = Request::builder()
        .uri("/api/v1/devices/ALPHA-DEV-001")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_get_dev = router.clone().oneshot(req_get_dev).await.unwrap();
    assert_eq!(res_get_dev.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_get_dev.into_body(), usize::MAX).await.unwrap();
    let fetched_dev: DeviceRecord = serde_json::from_slice(&body).unwrap();
    assert_eq!(fetched_dev.name, "Alpha Machine");

    // Non-existent device returns 404
    let req_get_404 = Request::builder()
        .uri("/api/v1/devices/DOES-NOT-EXIST")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_get_404 = router.clone().oneshot(req_get_404).await.unwrap();
    assert_eq!(res_get_404.status(), StatusCode::NOT_FOUND);

    // Pause & Resume Device
    let req_pause = Request::builder()
        .uri("/api/v1/devices/ALPHA-DEV-001/pause")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_pause = router.clone().oneshot(req_pause).await.unwrap();
    assert_eq!(res_pause.status(), StatusCode::OK);
    let d = harness.storage.get_device("ALPHA-DEV-001").unwrap().unwrap();
    assert!(d.is_paused);

    let req_resume = Request::builder()
        .uri("/api/v1/devices/ALPHA-DEV-001/resume")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_resume = router.clone().oneshot(req_resume).await.unwrap();
    assert_eq!(res_resume.status(), StatusCode::OK);
    let d = harness.storage.get_device("ALPHA-DEV-001").unwrap().unwrap();
    assert!(!d.is_paused);

    // Delete Device
    let req_del = Request::builder()
        .uri("/api/v1/devices/ALPHA-DEV-001")
        .method("DELETE")
        .body(Body::empty())
        .unwrap();
    let res_del = router.clone().oneshot(req_del).await.unwrap();
    assert_eq!(res_del.status(), StatusCode::NO_CONTENT);
    assert!(harness.storage.get_device("ALPHA-DEV-001").unwrap().is_none());

    // 5. Pending Folders Invitations
    let p_folder = PendingFolderRecord {
        folder_id: "shared_team_folder".into(),
        device_id: "BETA-DEV-002".into(),
        folder_label: "Team Vault".into(),
        offered_at: 5000,
    };
    harness.storage.add_pending_folder(&p_folder).unwrap();

    let req_pf_rest = Request::builder()
        .uri("/rest/cluster/pending/folders")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_pf_rest = router.clone().oneshot(req_pf_rest).await.unwrap();
    assert_eq!(res_pf_rest.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_pf_rest.into_body(), usize::MAX).await.unwrap();
    let p_folders: Vec<PendingFolderRecord> = serde_json::from_slice(&body).unwrap();
    assert_eq!(p_folders.len(), 1);
    assert_eq!(p_folders[0].folder_id, "shared_team_folder");

    let req_pf_v1 = Request::builder()
        .uri("/api/v1/cluster/pending/folders")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_pf_v1 = router.clone().oneshot(req_pf_v1).await.unwrap();
    assert_eq!(res_pf_v1.status(), StatusCode::OK);

    // Accept pending folder
    let team_folder_path = harness.temp_dir.join("team_vault");
    fs::create_dir_all(&team_folder_path).unwrap();
    let accept_folder_payload = serde_json::to_string(&AcceptFolderPayload {
        device_id: "BETA-DEV-002".into(),
        local_path: team_folder_path.to_string_lossy().to_string(),
    }).unwrap();

    let req_af = Request::builder()
        .uri("/api/v1/cluster/pending/folders/shared_team_folder/accept")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(accept_folder_payload))
        .unwrap();
    let res_af = router.clone().oneshot(req_af).await.unwrap();
    assert_eq!(res_af.status(), StatusCode::OK);

    // Verify folder created and shared
    let team_devs = harness.storage.list_folder_devices("shared_team_folder").unwrap();
    assert_eq!(team_devs, vec!["BETA-DEV-002".to_string()]);

    // Reject pending folder
    let p_folder_rej = PendingFolderRecord {
        folder_id: "junk_folder".into(),
        device_id: "BETA-DEV-002".into(),
        folder_label: "Junk".into(),
        offered_at: 6000,
    };
    harness.storage.add_pending_folder(&p_folder_rej).unwrap();

    let rej_folder_payload = serde_json::to_string(&RejectFolderPayload {
        device_id: "BETA-DEV-002".into(),
    }).unwrap();
    let req_rf = Request::builder()
        .uri("/rest/cluster/pending/folders/junk_folder/reject")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(rej_folder_payload))
        .unwrap();
    let res_rf = router.clone().oneshot(req_rf).await.unwrap();
    assert_eq!(res_rf.status(), StatusCode::OK);
    assert_eq!(harness.storage.list_pending_folders().unwrap().len(), 0);
}

// =============================================================================
// TEST 5: ALL FOLDER ENDPOINTS (/rest/db/* & /api/v1/folders/*)
// =============================================================================

#[tokio::test]
async fn test_folder_lifecycle_controls_status_and_ignores() {
    let harness = TestHarness::new();
    let router = ApiServer::create_router(harness.app_state.clone());

    // 1. Register Folder via /api/v1/folders and /rest/system/folders
    let folder_v1_path = harness.temp_dir.join("folder_v1");
    fs::create_dir_all(&folder_v1_path).unwrap();

    let reg_v1 = RegisterFolderRequest {
        folder_id: "vault_v1".into(),
        local_path: folder_v1_path.to_string_lossy().to_string(),
        conflict_policy: "THREE_WAY_AUTO".into(),
        sync_mode: Some("SEND_RECEIVE".into()),
        pull_order: Some("ALPHABETICAL".into()),
        versioning_type: Some("SIMPLE".into()),
        versioning_keep_days: Some(30),
        marker_name: Some(".stfolder".into()),
    };
    let req_reg_v1 = Request::builder()
        .uri("/api/v1/folders")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&reg_v1).unwrap()))
        .unwrap();
    let res_reg_v1 = router.clone().oneshot(req_reg_v1).await.unwrap();
    assert_eq!(res_reg_v1.status(), StatusCode::CREATED);

    let folder_rest_path = harness.temp_dir.join("folder_rest");
    fs::create_dir_all(&folder_rest_path).unwrap();
    let reg_rest = RegisterFolderRequest {
        folder_id: "vault_rest".into(),
        local_path: folder_rest_path.to_string_lossy().to_string(),
        conflict_policy: "THREE_WAY_AUTO".into(),
        sync_mode: None,
        pull_order: None,
        versioning_type: None,
        versioning_keep_days: None,
        marker_name: None,
    };
    let req_reg_rest = Request::builder()
        .uri("/rest/system/folders")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&reg_rest).unwrap()))
        .unwrap();
    let res_reg_rest = router.clone().oneshot(req_reg_rest).await.unwrap();
    assert_eq!(res_reg_rest.status(), StatusCode::CREATED);

    // List folders via GET /api/v1/folders and /rest/system/folders
    let req_list_v1 = Request::builder()
        .uri("/api/v1/folders")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_list_v1 = router.clone().oneshot(req_list_v1).await.unwrap();
    assert_eq!(res_list_v1.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_list_v1.into_body(), usize::MAX).await.unwrap();
    let dtos: Vec<FolderDto> = serde_json::from_slice(&body).unwrap();
    assert_eq!(dtos.len(), 2);

    let req_list_rest = Request::builder()
        .uri("/rest/system/folders")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_list_rest = router.clone().oneshot(req_list_rest).await.unwrap();
    assert_eq!(res_list_rest.status(), StatusCode::OK);

    // 2. Folder Status: /rest/db/status?folder=vault_v1 and /api/v1/folders/:id/status
    // Write and index a file
    let sample_file = folder_v1_path.join("file1.txt");
    fs::write(&sample_file, "Hello Synapse!").unwrap();
    harness.sync_engine.index_single_file("vault_v1", "file1.txt").unwrap();

    let req_st_rest = Request::builder()
        .uri("/rest/db/status?folder=vault_v1")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_st_rest = router.clone().oneshot(req_st_rest).await.unwrap();
    assert_eq!(res_st_rest.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_st_rest.into_body(), usize::MAX).await.unwrap();
    let status_rest: FolderStatusMetrics = serde_json::from_slice(&body).unwrap();
    assert_eq!(status_rest.folder_id, "vault_v1");
    assert_eq!(status_rest.state, "idle");
    assert_eq!(status_rest.local_files, 1);
    assert_eq!(status_rest.completion_pct, 100.0);

    // Missing folder query parameter returns 400 Bad Request
    let req_st_bad = Request::builder()
        .uri("/rest/db/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_st_bad = router.clone().oneshot(req_st_bad).await.unwrap();
    assert_eq!(res_st_bad.status(), StatusCode::BAD_REQUEST);

    let req_st_v1 = Request::builder()
        .uri("/api/v1/folders/vault_v1/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_st_v1 = router.clone().oneshot(req_st_v1).await.unwrap();
    assert_eq!(res_st_v1.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_st_v1.into_body(), usize::MAX).await.unwrap();
    let status_v1: FolderStatusMetrics = serde_json::from_slice(&body).unwrap();
    assert_eq!(status_v1.local_files, 1);

    // 3. Folder Completion: /rest/db/completion?folder=vault_v1 and /api/v1/folders/:id/completion
    let req_comp_rest = Request::builder()
        .uri("/rest/db/completion?folder=vault_v1")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_comp_rest = router.clone().oneshot(req_comp_rest).await.unwrap();
    assert_eq!(res_comp_rest.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_comp_rest.into_body(), usize::MAX).await.unwrap();
    let comp_rest: DeviceCompletionMetrics = serde_json::from_slice(&body).unwrap();
    assert_eq!(comp_rest.folder_id, "vault_v1");
    assert_eq!(comp_rest.completion_pct, 100.0);

    let req_comp_bad = Request::builder()
        .uri("/rest/db/completion")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_comp_bad = router.clone().oneshot(req_comp_bad).await.unwrap();
    assert_eq!(res_comp_bad.status(), StatusCode::BAD_REQUEST);

    let req_comp_v1 = Request::builder()
        .uri("/api/v1/folders/vault_v1/completion")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_comp_v1 = router.clone().oneshot(req_comp_v1).await.unwrap();
    assert_eq!(res_comp_v1.status(), StatusCode::OK);

    // 4. Folder Rescan: /rest/db/scan?folder=vault_v1 and /api/v1/folders/:id/rescan
    let req_scan_rest = Request::builder()
        .uri("/rest/db/scan?folder=vault_v1")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_scan_rest = router.clone().oneshot(req_scan_rest).await.unwrap();
    assert_eq!(res_scan_rest.status(), StatusCode::OK);

    let req_scan_bad = Request::builder()
        .uri("/rest/db/scan")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_scan_bad = router.clone().oneshot(req_scan_bad).await.unwrap();
    assert_eq!(res_scan_bad.status(), StatusCode::BAD_REQUEST);

    let req_scan_v1 = Request::builder()
        .uri("/api/v1/folders/vault_v1/rescan")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_scan_v1 = router.clone().oneshot(req_scan_v1).await.unwrap();
    assert_eq!(res_scan_v1.status(), StatusCode::OK);

    // 5. Folder Ignores: /rest/db/ignores?folder=vault_v1 and /api/v1/folders/:id/ignores
    let ig_payload_1 = serde_json::to_string(&IgnoresRequest {
        ignore: vec!["*.tmp".into(), ".git/".into()],
    }).unwrap();
    let req_ig_v1_set = Request::builder()
        .uri("/api/v1/folders/vault_v1/ignores")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(ig_payload_1))
        .unwrap();
    let res_ig_v1_set = router.clone().oneshot(req_ig_v1_set).await.unwrap();
    assert_eq!(res_ig_v1_set.status(), StatusCode::OK);

    let req_ig_v1_get = Request::builder()
        .uri("/api/v1/folders/vault_v1/ignores")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_ig_v1_get = router.clone().oneshot(req_ig_v1_get).await.unwrap();
    assert_eq!(res_ig_v1_get.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_ig_v1_get.into_body(), usize::MAX).await.unwrap();
    let ig_v1: IgnoresRequest = serde_json::from_slice(&body).unwrap();
    assert_eq!(ig_v1.ignore, vec!["*.tmp", ".git/"]);

    // Test Syncthing /rest/db/ignores with query parameter
    let ig_payload_2 = serde_json::to_string(&IgnoresRequest {
        ignore: vec!["node_modules/".into(), "*.log".into(), "(?d).DS_Store".into()],
    }).unwrap();
    let req_ig_rest_set = Request::builder()
        .uri("/rest/db/ignores?folder=vault_v1")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(ig_payload_2))
        .unwrap();
    let res_ig_rest_set = router.clone().oneshot(req_ig_rest_set).await.unwrap();
    assert_eq!(res_ig_rest_set.status(), StatusCode::OK);

    let req_ig_rest_get = Request::builder()
        .uri("/rest/db/ignores?folder=vault_v1")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_ig_rest_get = router.clone().oneshot(req_ig_rest_get).await.unwrap();
    assert_eq!(res_ig_rest_get.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_ig_rest_get.into_body(), usize::MAX).await.unwrap();
    let ig_rest: IgnoresRequest = serde_json::from_slice(&body).unwrap();
    assert_eq!(ig_rest.ignore.len(), 3);

    // Negative query test
    let req_ig_bad = Request::builder()
        .uri("/rest/db/ignores")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_ig_bad = router.clone().oneshot(req_ig_bad).await.unwrap();
    assert_eq!(res_ig_bad.status(), StatusCode::BAD_REQUEST);

    // 6. Folder Device Sharing: /api/v1/folders/:id/devices and /api/v1/folders/:id/devices/:device_id
    let req_devs_init = Request::builder()
        .uri("/api/v1/folders/vault_v1/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_devs_init = router.clone().oneshot(req_devs_init).await.unwrap();
    assert_eq!(res_devs_init.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res_devs_init.into_body(), usize::MAX).await.unwrap();
    let shared_devs: Vec<String> = serde_json::from_slice(&body).unwrap();
    assert_eq!(shared_devs.len(), 0);

    // Share with remote device
    let req_share = Request::builder()
        .uri("/api/v1/folders/vault_v1/devices/REMOTE_PEER_42")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_share = router.clone().oneshot(req_share).await.unwrap();
    assert_eq!(res_share.status(), StatusCode::OK);

    let req_devs_after = Request::builder()
        .uri("/api/v1/folders/vault_v1/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_devs_after = router.clone().oneshot(req_devs_after).await.unwrap();
    let body = axum::body::to_bytes(res_devs_after.into_body(), usize::MAX).await.unwrap();
    let shared_devs: Vec<String> = serde_json::from_slice(&body).unwrap();
    assert_eq!(shared_devs, vec!["REMOTE_PEER_42"]);

    // Unshare
    let req_unshare = Request::builder()
        .uri("/api/v1/folders/vault_v1/devices/REMOTE_PEER_42")
        .method("DELETE")
        .body(Body::empty())
        .unwrap();
    let res_unshare = router.clone().oneshot(req_unshare).await.unwrap();
    assert_eq!(res_unshare.status(), StatusCode::OK);

    let req_devs_final = Request::builder()
        .uri("/api/v1/folders/vault_v1/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_devs_final = router.clone().oneshot(req_devs_final).await.unwrap();
    let body = axum::body::to_bytes(res_devs_final.into_body(), usize::MAX).await.unwrap();
    let shared_devs: Vec<String> = serde_json::from_slice(&body).unwrap();
    assert_eq!(shared_devs.len(), 0);

    // 7. Folder Pause, Resume, and Delete
    let req_pause = Request::builder()
        .uri("/api/v1/folders/vault_v1/pause")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_pause = router.clone().oneshot(req_pause).await.unwrap();
    assert_eq!(res_pause.status(), StatusCode::OK);
    let f = harness.storage.get_folder("vault_v1").unwrap().unwrap();
    assert!(f.is_paused);

    let req_resume = Request::builder()
        .uri("/api/v1/folders/vault_v1/resume")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_resume = router.clone().oneshot(req_resume).await.unwrap();
    assert_eq!(res_resume.status(), StatusCode::OK);
    let f = harness.storage.get_folder("vault_v1").unwrap().unwrap();
    assert!(!f.is_paused);

    let req_del = Request::builder()
        .uri("/api/v1/folders/vault_v1")
        .method("DELETE")
        .body(Body::empty())
        .unwrap();
    let res_del = router.clone().oneshot(req_del).await.unwrap();
    assert_eq!(res_del.status(), StatusCode::NO_CONTENT);
    assert!(harness.storage.get_folder("vault_v1").unwrap().is_none());
}

// =============================================================================
// TEST 6: CONFLICT ENDPOINTS (DIFF GENERATION, ACCEPT LOCAL/REMOTE/CUSTOM/KEEP_BOTH)
// =============================================================================

#[tokio::test]
async fn test_conflict_endpoints_diff_and_resolution_actions() {
    let harness = TestHarness::new();
    let router = ApiServer::create_router(harness.app_state.clone());

    let folder_path = harness.temp_dir.join("conflict_vault");
    fs::create_dir_all(&folder_path).unwrap();

    let folder_id = "conflict_vault";
    harness.storage.add_folder(&FolderRecord::new(
        folder_id,
        folder_path.to_string_lossy(),
    )).unwrap();

    // -------------------------------------------------------------------------
    // Phase 1: 3-Way Diff Inspection Endpoints (Base, Local, Remote, Diff)
    // -------------------------------------------------------------------------
    let base_text_1 = "header\nline 2 base\nline 3 base\nfooter\n";
    let local_text_1 = "header\nline 2 edited by local\nline 3 base\nfooter\n";
    let remote_text_1 = "header\nline 2 edited by remote\nline 3 base\nfooter\n";

    let cnf_id_1 = harness.stage_conflict(
        folder_id,
        "diff_test.txt",
        base_text_1,
        local_text_1,
        remote_text_1,
        "remote_worker_01",
    );

    // GET /api/v1/conflicts
    let req = Request::builder()
        .uri("/api/v1/conflicts")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let conflicts: Vec<synapse_core::storage::QuarantineConflict> = serde_json::from_slice(&body).unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].conflict_id, cnf_id_1);

    // GET /api/v1/conflicts/:id
    let req = Request::builder()
        .uri(format!("/api/v1/conflicts/{}", cnf_id_1))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // GET /api/v1/conflicts/:id/base
    let req = Request::builder()
        .uri(format!("/api/v1/conflicts/{}/base", cnf_id_1))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&body), base_text_1);

    // GET /api/v1/conflicts/:id/local
    let req = Request::builder()
        .uri(format!("/api/v1/conflicts/{}/local", cnf_id_1))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&body), local_text_1);

    // GET /api/v1/conflicts/:id/remote
    let req = Request::builder()
        .uri(format!("/api/v1/conflicts/{}/remote", cnf_id_1))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&body), remote_text_1);

    // GET /api/v1/conflicts/:id/diff (3-Way Diff Generation)
    let req = Request::builder()
        .uri(format!("/api/v1/conflicts/{}/diff", cnf_id_1))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let diff: DiffResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(diff.conflict_id, cnf_id_1);
    assert_eq!(diff.relative_path, "diff_test.txt");
    assert!(diff.hunks.iter().any(|h| matches!(h.hunk_type, diff3::HunkType::Conflict)));

    // -------------------------------------------------------------------------
    // Phase 2: Action ACCEPT_LOCAL
    // -------------------------------------------------------------------------
    let resolve_req = ResolveRequest {
        action: ResolveAction::AcceptLocal,
        merged_content: None,
    };
    let req_res_local = Request::builder()
        .uri(format!("/api/v1/conflicts/{}/resolve", cnf_id_1))
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&resolve_req).unwrap()))
        .unwrap();
    let res_res_local = router.clone().oneshot(req_res_local).await.unwrap();
    assert_eq!(res_res_local.status(), StatusCode::OK);

    // Local file on disk remains unchanged
    let on_disk_local = fs::read_to_string(folder_path.join("diff_test.txt")).unwrap();
    assert_eq!(on_disk_local, local_text_1);

    // Conflict is resolved
    let pending_after_local = harness.storage.list_pending_conflicts().unwrap();
    assert_eq!(pending_after_local.len(), 0);

    // -------------------------------------------------------------------------
    // Phase 3: Action ACCEPT_REMOTE
    // -------------------------------------------------------------------------
    let base_text_2 = "item 1\nitem 2\n";
    let local_text_2 = "item 1\nitem 2 local\n";
    let remote_text_2 = "item 1\nitem 2 remote\n";

    let cnf_id_2 = harness.stage_conflict(
        folder_id,
        "remote_test.txt",
        base_text_2,
        local_text_2,
        remote_text_2,
        "remote_worker_02",
    );

    let resolve_req = ResolveRequest {
        action: ResolveAction::AcceptRemote,
        merged_content: None,
    };
    let req_res_remote = Request::builder()
        .uri(format!("/api/v1/conflicts/{}/resolve", cnf_id_2))
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&resolve_req).unwrap()))
        .unwrap();
    let res_res_remote = router.clone().oneshot(req_res_remote).await.unwrap();
    assert_eq!(res_res_remote.status(), StatusCode::OK);

    // Local file on disk is atomically updated to remote version
    let on_disk_remote = fs::read_to_string(folder_path.join("remote_test.txt")).unwrap();
    assert_eq!(on_disk_remote, remote_text_2);
    assert_eq!(harness.storage.list_pending_conflicts().unwrap().len(), 0);

    // -------------------------------------------------------------------------
    // Phase 4: Action CUSTOM_MERGE
    // -------------------------------------------------------------------------
    let base_text_3 = "alpha\nbeta\n";
    let local_text_3 = "alpha edited by local\nbeta\n";
    let remote_text_3 = "alpha edited by remote\nbeta\n";

    let cnf_id_3 = harness.stage_conflict(
        folder_id,
        "custom_test.txt",
        base_text_3,
        local_text_3,
        remote_text_3,
        "remote_worker_03",
    );

    let custom_solution = "alpha synthesized carefully by human user\nbeta\n";
    let resolve_req = ResolveRequest {
        action: ResolveAction::CustomMerge,
        merged_content: Some(custom_solution.to_string()),
    };
    let req_res_custom = Request::builder()
        .uri(format!("/api/v1/conflicts/{}/resolve", cnf_id_3))
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&resolve_req).unwrap()))
        .unwrap();
    let res_res_custom = router.clone().oneshot(req_res_custom).await.unwrap();
    assert_eq!(res_res_custom.status(), StatusCode::OK);

    // Disk content updated to synthesized custom merge
    let on_disk_custom = fs::read_to_string(folder_path.join("custom_test.txt")).unwrap();
    assert_eq!(on_disk_custom, custom_solution);

    // Merged file tracked with 2 parents in Merkle DAG
    let custom_file = harness.storage.get_file(folder_id, "custom_test.txt").unwrap().unwrap();
    let custom_rev = harness.storage.get_revision(&custom_file.current_revision).unwrap().unwrap();
    assert!(custom_rev.parent_1.is_some());
    assert!(custom_rev.parent_2.is_some());
    assert_eq!(harness.storage.list_pending_conflicts().unwrap().len(), 0);

    // -------------------------------------------------------------------------
    // Phase 5: Action KEEP_BOTH
    // -------------------------------------------------------------------------
    let base_text_4 = "key=value\n";
    let local_text_4 = "key=local_value\n";
    let remote_text_4 = "key=remote_value\n";

    let cnf_id_4 = harness.stage_conflict(
        folder_id,
        "keep_both.txt",
        base_text_4,
        local_text_4,
        remote_text_4,
        "remote_worker_04",
    );

    let resolve_req = ResolveRequest {
        action: ResolveAction::KeepBoth,
        merged_content: None,
    };
    let req_res_both = Request::builder()
        .uri(format!("/api/v1/conflicts/{}/resolve", cnf_id_4))
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&resolve_req).unwrap()))
        .unwrap();
    let res_res_both = router.clone().oneshot(req_res_both).await.unwrap();
    assert_eq!(res_res_both.status(), StatusCode::OK);

    // Local file keeps local content
    let on_disk_orig = fs::read_to_string(folder_path.join("keep_both.txt")).unwrap();
    assert_eq!(on_disk_orig, local_text_4);

    // Sidecar file created with remote content
    let sidecar_name = format!("keep_both.conflict-{}.txt", cnf_id_4);
    let sidecar_path = folder_path.join(&sidecar_name);
    assert!(sidecar_path.exists(), "Sidecar conflict file must be created on disk");
    let on_disk_sidecar = fs::read_to_string(&sidecar_path).unwrap();
    assert_eq!(on_disk_sidecar, remote_text_4);

    assert_eq!(harness.storage.list_pending_conflicts().unwrap().len(), 0);
}

// =============================================================================
// TEST 7: WEBSOCKET REAL-TIME EVENT STREAMING & PING/PONG
// =============================================================================

#[tokio::test]
async fn test_websocket_realtime_event_streaming() {
    let harness = TestHarness::new();

    // 1. Synthetic oneshot requests without hyper connection upgrade context trigger 426 Upgrade Required
    // (verifying that both /api/v1/events and /rest/events correctly match the WebSocketUpgrade extractor)
    let router = ApiServer::create_router(harness.app_state.clone());

    let req_ws_v1 = Request::builder()
        .uri("/api/v1/events")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .body(Body::empty())
        .unwrap();
    let res_ws_v1 = router.clone().oneshot(req_ws_v1).await.unwrap();
    assert_eq!(res_ws_v1.status(), StatusCode::UPGRADE_REQUIRED);

    let req_ws_rest = Request::builder()
        .uri("/rest/events")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .body(Body::empty())
        .unwrap();
    let res_ws_rest = router.clone().oneshot(req_ws_rest).await.unwrap();
    assert_eq!(res_ws_rest.status(), StatusCode::UPGRADE_REQUIRED);

    // 2. Live In-Process WebSocket Streaming Test over TCP
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = ApiServer::create_router(harness.app_state.clone());

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Connect raw TCP client to test WebSocket frame exchange
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let handshake = format!(
        "GET /api/v1/events HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        addr
    );
    stream.write_all(handshake.as_bytes()).await.unwrap();

    // Read Handshake response
    let mut handshake_res = [0u8; 1024];
    let mut n_total = 0;
    while !String::from_utf8_lossy(&handshake_res[..n_total]).contains("\r\n\r\n") {
        let n = stream.read(&mut handshake_res[n_total..]).await.unwrap();
        if n == 0 { break; }
        n_total += n;
    }
    let res_str = String::from_utf8_lossy(&handshake_res[..n_total]);
    assert!(res_str.contains("101 Switching Protocols"));
    assert!(res_str.to_lowercase().contains("upgrade: websocket"));

    // Emit a CoreEvent to the broadcast channel
    let test_event = CoreEvent::DevicePaired {
        device_id: "WS_TEST_DEVICE_100".to_string(),
        name: "Remote iPad".to_string(),
    };
    harness.sync_engine.event_sender().send(test_event).unwrap();

    // Read incoming WebSocket Text Frame from server
    let mut frame_buf = [0u8; 1024];
    let read_result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut frame_buf)).await;
    let n = read_result.expect("Timed out waiting for WebSocket event").unwrap();
    assert!(n >= 2, "Must read at least frame header");

    // Verify WebSocket frame header: 0x81 (FIN=1, Text frame opcode=1)
    assert_eq!(frame_buf[0], 0x81);
    let (payload_start, payload_len) = if (frame_buf[1] & 0x7F) < 126 {
        (2, (frame_buf[1] & 0x7F) as usize)
    } else {
        let len = u16::from_be_bytes([frame_buf[2], frame_buf[3]]) as usize;
        (4, len)
    };
    let payload_str = String::from_utf8_lossy(&frame_buf[payload_start..payload_start + payload_len]);
    assert!(payload_str.contains("DEVICE_PAIRED"), "Expected DEVICE_PAIRED in event payload: {}", payload_str);
    assert!(payload_str.contains("WS_TEST_DEVICE_100"));

    // Test sending masked "ping" message and receiving "pong" reply
    let mask = [0x5A, 0xA5, 0x12, 0x34];
    let ping_bytes = b"ping";
    let masked_ping: Vec<u8> = ping_bytes.iter().enumerate().map(|(i, &b)| b ^ mask[i % 4]).collect();
    let mut ping_frame = vec![0x81, 0x84]; // 0x80 (masked) | 4 bytes
    ping_frame.extend_from_slice(&mask);
    ping_frame.extend_from_slice(&masked_ping);
    stream.write_all(&ping_frame).await.unwrap();

    let mut pong_buf = [0u8; 128];
    let pong_result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut pong_buf)).await;
    let n_pong = pong_result.expect("Timed out waiting for WebSocket pong").unwrap();
    assert!(n_pong >= 6);
    assert_eq!(pong_buf[0], 0x81); // Text frame
    assert_eq!(pong_buf[1], 4);    // Length 4
    assert_eq!(&pong_buf[2..6], b"pong");

    // Also verify /rest/events WebSocket handshake on live server
    let mut stream_rest = tokio::net::TcpStream::connect(addr).await.unwrap();
    let handshake_rest = format!(
        "GET /rest/events HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        addr
    );
    stream_rest.write_all(handshake_rest.as_bytes()).await.unwrap();

    let mut handshake_res_rest = [0u8; 1024];
    let mut n_total_rest = 0;
    while !String::from_utf8_lossy(&handshake_res_rest[..n_total_rest]).contains("\r\n\r\n") {
        let n = stream_rest.read(&mut handshake_res_rest[n_total_rest..]).await.unwrap();
        if n == 0 { break; }
        n_total_rest += n;
    }
    let res_str_rest = String::from_utf8_lossy(&handshake_res_rest[..n_total_rest]);
    assert!(res_str_rest.contains("101 Switching Protocols"));
    assert!(res_str_rest.to_lowercase().contains("upgrade: websocket"));
}
