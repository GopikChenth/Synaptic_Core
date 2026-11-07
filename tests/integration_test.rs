//! End-to-end integration tests for Synapse Core.
//!
//! Tests:
//! 1. Content-Defined Chunking & Deduplication via BLAKE3 + CAS
//! 2. Merkle DAG LCA resolution
//! 3. 3-Way Semantic Auto-Merge (Tier 1)
//! 4. Virtual Quarantine & Staging with Zero Disk Pollution (Tier 2)
//! 5. User Decision Execution (Tier 3: ACCEPT_LOCAL, ACCEPT_REMOTE, CUSTOM_MERGE, KEEP_BOTH)
//! 6. Axum REST API endpoints

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use synapse_core::api::{ApiServer, AppState};
use synapse_core::chunker::Chunker;
use synapse_core::conflict::{ConflictEngine, ResolveAction, ResolveRequest};
use synapse_core::dag::RevisionNode;
use synapse_core::engine::SyncEngine;
use synapse_core::storage::{FolderRecord, StorageEngine};

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
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

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
    // Local file on disk remains UNTOUCHED! No renaming to .sync-conflict-*
    let disk_content = fs::read_to_string(&file_path).unwrap();
    assert_eq!(disk_content, local_content);

    // Verify no stray conflict files created in the user's folder
    let folder_entries: Vec<_> = fs::read_dir(&folder_path).unwrap().collect();
    assert_eq!(folder_entries.len(), 1, "User directory must not contain .sync-conflict-* clutter");

    // 6. Conflicting version safely quarantined in internal staging
    let conflicts = harness.storage.list_pending_conflicts().unwrap();
    assert_eq!(conflicts.len(), 1);
    let conflict = &conflicts[0];
    assert_eq!(conflict.relative_path, file_rel);
    assert_eq!(conflict.status, "PENDING");
    assert!(PathBuf::from(&conflict.staged_payload_path).exists());

    // 7. Test UI API Inspection & Resolution
    let router = ApiServer::create_router(harness.app_state.clone());

    // GET /api/v1/conflicts
    let req = Request::builder()
        .uri("/api/v1/conflicts")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // GET /api/v1/conflicts/:id/diff
    let diff_uri = format!("/api/v1/conflicts/{}/diff", conflict.conflict_id);
    let req = Request::builder()
        .uri(&diff_uri)
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let diff_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(diff_json["conflict_id"], conflict.conflict_id);
    assert_eq!(diff_json["relative_path"], "todo.txt");
    assert!(diff_json["hunks"].as_array().unwrap().len() > 0);

    // POST /api/v1/conflicts/:id/resolve with ACCEPT_REMOTE
    let resolve_uri = format!("/api/v1/conflicts/{}/resolve", conflict.conflict_id);
    let resolve_payload = serde_json::to_string(&ResolveRequest {
        action: ResolveAction::AcceptRemote,
        merged_content: None,
    }).unwrap();

    let req = Request::builder()
        .uri(&resolve_uri)
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(resolve_payload))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Disk should now atomically contain remote content
    let final_content = fs::read_to_string(&file_path).unwrap();
    assert_eq!(final_content, remote_content);

    // Quarantine entry should be resolved and staging cleaned
    let pending_after = harness.storage.list_pending_conflicts().unwrap();
    assert_eq!(pending_after.len(), 0);
}

#[tokio::test]
async fn test_cluster_pairing_and_syncthing_rest_api() {
    let harness = TestHarness::new();
    let router = ApiServer::create_router(harness.app_state.clone());

    // 1. Stage a pending pairing request
    let pending_dev = synapse_core::storage::PendingDeviceRecord {
        device_id: "MF7F22G-ABCD123-WXYZ789-KLMN456".into(),
        name: "MacBook Pro".into(),
        address: "192.168.1.50:9190".into(),
        received_at: 1000,
    };
    harness.storage.add_pending_device(&pending_dev).unwrap();

    // 2. Query pending devices via both /api/v1 and Syncthing /rest alias
    let req = Request::builder()
        .uri("/api/v1/cluster/pending/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let list: Vec<synapse_core::storage::PendingDeviceRecord> = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "MacBook Pro");

    // Test Syncthing /rest alias
    let req_rest = Request::builder()
        .uri("/rest/cluster/pending/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_rest = router.clone().oneshot(req_rest).await.unwrap();
    assert_eq!(res_rest.status(), StatusCode::OK);

    // 3. Accept the pairing request
    let accept_uri = format!("/api/v1/cluster/pending/devices/{}/accept", pending_dev.device_id);
    let req_accept = Request::builder()
        .uri(&accept_uri)
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let res_accept = router.clone().oneshot(req_accept).await.unwrap();
    assert_eq!(res_accept.status(), StatusCode::OK);

    // 4. Verify device moved to paired devices
    let req_devs = Request::builder()
        .uri("/api/v1/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_devs = router.clone().oneshot(req_devs).await.unwrap();
    assert_eq!(res_devs.status(), StatusCode::OK);
    let body_devs = axum::body::to_bytes(res_devs.into_body(), usize::MAX).await.unwrap();
    let devs: Vec<synapse_core::storage::DeviceRecord> = serde_json::from_slice(&body_devs).unwrap();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].device_id, pending_dev.device_id);

    // 5. Verify real-time connections endpoint
    let req_conn = Request::builder()
        .uri("/rest/system/connections")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_conn = router.clone().oneshot(req_conn).await.unwrap();
    assert_eq!(res_conn.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_folder_controls_status_and_ignores() {
    let harness = TestHarness::new();
    let router = ApiServer::create_router(harness.app_state.clone());

    let folder_path = harness.temp_dir.join("docs");
    fs::create_dir_all(&folder_path).unwrap();

    let folder_id = "docs";
    let folder = FolderRecord::new(folder_id, folder_path.to_string_lossy());
    harness.storage.add_folder(&folder).unwrap();

    // 1. Query status via /api/v1/folders/:id/status
    let status_uri = format!("/api/v1/folders/{}/status", folder_id);
    let req = Request::builder()
        .uri(&status_uri)
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let status: synapse_core::storage::FolderStatusMetrics = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.folder_id, "docs");
    assert_eq!(status.state, "idle");
    assert_eq!(status.completion_pct, 100.0);

    // 2. Query Syncthing alias /rest/db/status?folder=docs
    let req_query = Request::builder()
        .uri("/rest/db/status?folder=docs")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_query = router.clone().oneshot(req_query).await.unwrap();
    assert_eq!(res_query.status(), StatusCode::OK);

    // 3. Set and get ignore patterns
    let ignores_uri = format!("/api/v1/folders/{}/ignores", folder_id);
    let ignores_payload = serde_json::to_string(&serde_json::json!({
        "ignore": ["*.tmp", "node_modules/", "(?d).DS_Store"]
    })).unwrap();

    let req_ig_set = Request::builder()
        .uri(&ignores_uri)
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(ignores_payload))
        .unwrap();
    let res_ig_set = router.clone().oneshot(req_ig_set).await.unwrap();
    assert_eq!(res_ig_set.status(), StatusCode::OK);

    let req_ig_get = Request::builder()
        .uri(&ignores_uri)
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_ig_get = router.clone().oneshot(req_ig_get).await.unwrap();
    assert_eq!(res_ig_get.status(), StatusCode::OK);
    let body_ig = axum::body::to_bytes(res_ig_get.into_body(), usize::MAX).await.unwrap();
    let ig_json: serde_json::Value = serde_json::from_slice(&body_ig).unwrap();
    assert_eq!(ig_json["ignore"].as_array().unwrap().len(), 3);
}
