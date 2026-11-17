//! P2P QUIC Transport, Peer Discovery, and Block Exchange Protocol.
//!
//! Handles:
//! - Ed25519 node identities and public key fingerprinting
//! - Local UDP peer discovery broadcasting
//! - High-performance QUIC multiplexed streams via Quinn
//! - Content-addressed block exchange and file revision replication

pub mod crypto;
pub mod identity;
pub mod nat;
pub mod relay;
pub mod swarm;
pub mod throttle;

pub use crypto::{CryptoError, EncryptedChunkEnvelope, EncryptionAlgorithm};
pub use swarm::{ChunkAssignment, FilePullItem, PullOrder, SchedulingStrategy, SwarmScheduler};
pub use throttle::{BandwidthLimiter, RateLimiter};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};
use tracing::{info, warn};

use crate::conflict::CoreEvent;
use crate::chunker::Chunker;
use crate::dag::RevisionNode;
use crate::engine::SyncEngine;
pub use crate::p2p::identity::{NodeIdentity, TlsIdentity};
use crate::storage::{
    FileRecord, IntroducedDevice, IntroducerPropagationResult, PendingDeviceRecord, RevisionRecord,
};

pub const DEFAULT_P2P_PORT: u16 = 9190;
pub const DEFAULT_DISCOVERY_PORT: u16 = 21027;

/// P2P wire message exchanged over QUIC streams.
#[derive(Debug, Serialize, Deserialize)]
pub enum P2PMessage {
    Hello {
        device_id: String,
        device_name: String,
        folders: Vec<String>,
        #[serde(default)]
        cluster_devices: Vec<IntroducedDevice>,
        #[serde(default)]
        cert_pin: Option<String>,
    },
    IndexRequest {
        folder_id: String,
    },
    IndexResponse {
        folder_id: String,
        files: Vec<FileRecord>,
        revisions: Vec<RevisionRecord>,
        #[serde(default)]
        chunk_lists: HashMap<String, Vec<String>>,
    },
    ChunkRequest {
        chunk_hash: String,
    },
    ChunkResponse {
        chunk_hash: String,
        data: Vec<u8>,
    },
    FileNotice {
        folder_id: String,
        relative_path: String,
        revision: RevisionNode,
        chunk_hashes: Vec<String>,
        #[serde(default)]
        is_deleted: bool,
    },
    /// Cluster device announcement sent by an introducer node
    ClusterDevicesAnnouncement {
        introducer_id: String,
        devices: Vec<IntroducedDevice>,
        #[serde(default)]
        auto_trust: bool,
    },
    /// Request an encrypted chunk envelope from an untrusted storage node
    EncryptedChunkRequest {
        chunk_hash: String,
    },
    /// Encrypted chunk envelope exchanged with an untrusted storage node
    EncryptedChunkResponse {
        chunk_hash: String,
        envelope: EncryptedChunkEnvelope,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    pub device_id: String,
    pub device_name: String,
    pub p2p_port: u16,
    pub folders: Vec<String>,
    #[serde(default)]
    pub introduced_devices: Vec<IntroducedDevice>,
    #[serde(default)]
    pub cert_pin: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub device_id: String,
    pub device_name: String,
    pub addr: SocketAddr,
    pub last_seen: std::time::Instant,
}

#[derive(Clone)]
pub struct P2PManager {
    identity: NodeIdentity,
    tls_identity: TlsIdentity,
    device_name: String,
    p2p_port: u16,
    sync_engine: SyncEngine,
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    peer_count: Arc<AtomicUsize>,
    event_sender: broadcast::Sender<CoreEvent>,
}

fn bind_discovery_socket(port: u16) -> Result<UdpSocket, Box<dyn std::error::Error + Send + Sync>> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = socket.set_reuse_address(true);
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    let _ = socket.set_nonblocking(true);
    socket.bind(&addr.into())?;
    let std_sock: std::net::UdpSocket = socket.into();
    let tokio_sock = UdpSocket::from_std(std_sock)?;
    Ok(tokio_sock)
}

impl P2PManager {
    pub fn new(
        identity: NodeIdentity,
        tls_identity: TlsIdentity,
        device_name: String,
        p2p_port: u16,
        sync_engine: SyncEngine,
        peer_count: Arc<AtomicUsize>,
        event_sender: broadcast::Sender<CoreEvent>,
    ) -> Self {
        Self {
            identity,
            tls_identity,
            device_name,
            p2p_port,
            sync_engine,
            peers: Arc::new(Mutex::new(HashMap::new())),
            peer_count,
            event_sender,
        }
    }

    pub fn device_id(&self) -> &str {
        &self.identity.device_id
    }

    pub fn tls_identity(&self) -> &TlsIdentity {
        &self.tls_identity
    }

    /// Records an unknown remote peer into pending pairing requests and broadcasts an event.
    pub fn stage_pending_peer(
        storage: &crate::storage::StorageEngine,
        event_sender: &broadcast::Sender<CoreEvent>,
        device_id: &str,
        device_name: &str,
        address: &str,
        cert_pin: Option<String>,
    ) {
        let is_new = storage
            .get_pending_device(device_id)
            .map(|p| p.is_none())
            .unwrap_or(true);

        let _ = storage.add_pending_device(&PendingDeviceRecord {
            device_id: device_id.to_string(),
            name: device_name.to_string(),
            address: address.to_string(),
            received_at: chrono::Utc::now().timestamp_millis(),
            cert_pin,
        });

        if is_new {
            info!(
                "Incoming pairing request staged for {} ({}) at {}",
                device_name, device_id, address
            );
            let _ = event_sender.send(CoreEvent::DevicePending {
                device_id: device_id.to_string(),
                name: device_name.to_string(),
                address: address.to_string(),
            });
        }
    }

    /// Records or updates an active peer in the memory table and atomic counter.
    pub async fn update_peer_info(
        peers: &Arc<Mutex<HashMap<String, PeerInfo>>>,
        peer_count: &Arc<AtomicUsize>,
        device_id: String,
        device_name: String,
        addr: SocketAddr,
    ) -> bool {
        let mut map = peers.lock().await;
        let is_new = !map.contains_key(&device_id);
        map.insert(
            device_id.clone(),
            PeerInfo {
                device_id,
                device_name,
                addr,
                last_seen: std::time::Instant::now(),
            },
        );
        peer_count.store(map.len(), Ordering::Relaxed);
        is_new
    }

    /// Spawns UDP broadcast discovery listener and periodic announcer.
    pub fn start_discovery(&self, discovery_port: u16) {
        let device_id = self.identity.device_id.clone();
        let p2p_port = self.p2p_port;
        let peers = self.peers.clone();
        let peer_count = self.peer_count.clone();
        let event_sender = self.event_sender.clone();
        let storage_listener = self.sync_engine.storage().clone();
        let storage_announcer = self.sync_engine.storage().clone();

        tokio::spawn(async move {
            let socket = match bind_discovery_socket(discovery_port) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to bind UDP discovery listener on port {}: {}", discovery_port, e);
                    return;
                }
            };

            let mut buf = [0u8; 2048];
            loop {
                if let Ok((len, src_addr)) = socket.recv_from(&mut buf).await {
                    if let Ok(peer) = serde_json::from_slice::<DiscoveredPeer>(&buf[..len]) {
                        if peer.device_id != device_id {
                            let mut peer_addr = src_addr;
                            peer_addr.set_port(peer.p2p_port);

                            let is_paired = match storage_listener.get_device(&peer.device_id) {
                                Ok(Some(dev)) => {
                                    if dev.is_paused {
                                        continue;
                                    }
                                    true
                                }
                                Ok(None) => {
                                    Self::stage_pending_peer(
                                        &storage_listener,
                                        &event_sender,
                                        &peer.device_id,
                                        &peer.device_name,
                                        &peer_addr.to_string(),
                                        peer.cert_pin.clone(),
                                    );
                                    false
                                }
                                Err(_) => false,
                            };

                            let is_new = Self::update_peer_info(
                                &peers,
                                &peer_count,
                                peer.device_id.clone(),
                                peer.device_name.clone(),
                                peer_addr,
                            ).await;

                            // Introducer propagation via UDP broadcast discovery:
                            // If discovered peer is marked as an introducer (introducer = 1) in SQLite
                            // and announced introduced cluster peers, automatically propagate them
                            if storage_listener.is_device_introducer(&peer.device_id).unwrap_or(false)
                                && !peer.introduced_devices.is_empty()
                            {
                                let report = storage_listener.propagate_introducer_devices(
                                    &peer.device_id,
                                    &peer.introduced_devices,
                                    false,
                                );
                                if let Ok(r) = report {
                                    if !r.added_pending.is_empty() || !r.added_trusted.is_empty() {
                                        info!(
                                            "Introducer {} announced {} new devices via discovery ({} pending, {} trusted)",
                                            peer.device_id,
                                            r.added_pending.len() + r.added_trusted.len(),
                                            r.added_pending.len(),
                                            r.added_trusted.len(),
                                        );
                                    }
                                }
                            }

                            if is_new && is_paired {
                                info!(
                                    "Discovered paired peer {} ({}) at {}",
                                    peer.device_name, peer.device_id, peer_addr
                                );
                                let _ = event_sender.send(CoreEvent::PeerConnected {
                                    peer_id: peer.device_id,
                                    addr: peer_addr.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        });

        // 2. Periodic discovery broadcast task
        let dev_id = self.identity.device_id.clone();
        let dev_name = self.device_name.clone();
        let cert_pin = self.tls_identity.certificate_pin();
        tokio::spawn(async move {
            let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let socket = match UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to bind UDP broadcast sender: {}", e);
                    return;
                }
            };
            let _ = socket.set_broadcast(true);
            let target_addr = SocketAddr::from(([255, 255, 255, 255], discovery_port));

            loop {
                let folders = storage_announcer
                    .list_folders()
                    .map(|list| list.into_iter().map(|f| f.folder_id).collect())
                    .unwrap_or_default();

                let introduced_devices = if storage_announcer.is_device_introducer(&dev_id).unwrap_or(false) {
                    storage_announcer.list_devices()
                        .map(|list| list.into_iter().map(|d| IntroducedDevice {
                            device_id: d.device_id,
                            name: d.name,
                            addresses: d.addresses,
                            is_trusted: d.is_trusted,
                            cert_name: d.cert_name,
                        }).collect())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };

                let announcement = DiscoveredPeer {
                    device_id: dev_id.clone(),
                    device_name: dev_name.clone(),
                    p2p_port,
                    folders,
                    introduced_devices,
                    cert_pin: Some(cert_pin.clone()),
                };

                if let Ok(payload) = serde_json::to_vec(&announcement) {
                    let _ = socket.send_to(&payload, target_addr).await;
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        // 3. Continuous FileNotice replication listener
        let replication_manager = self.clone();
        let mut file_event_rx = self.event_sender.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = file_event_rx.recv().await {
                if let CoreEvent::FileChanged { folder_id, relative_path, revision } = event {
                    let _ = replication_manager.broadcast_file_notice(&folder_id, &relative_path, &revision).await;
                }
            }
        });
    }

    /// Processes introduced device announcements from a peer.
    /// If the peer is marked as an introducer in SQLite (introducer = 1),
    /// the announced devices are automatically propagated to pending or trusted devices.
    pub fn handle_cluster_announcement(
        &self,
        introducer_id: &str,
        devices: &[IntroducedDevice],
        auto_trust: bool,
    ) -> Result<IntroducerPropagationResult, Box<dyn std::error::Error + Send + Sync>> {
        let storage = self.sync_engine.storage();
        let report = storage.propagate_introducer_devices(introducer_id, devices, auto_trust)?;

        for trusted_id in &report.added_trusted {
            if let Ok(Some(dev)) = storage.get_device(trusted_id) {
                let _ = self.event_sender.send(CoreEvent::DevicePaired {
                    device_id: dev.device_id,
                    name: dev.name,
                });
            }
        }

        Ok(report)
    }

    /// Handles incoming P2P messages over QUIC or tests.
    pub async fn handle_p2p_message(
        &self,
        msg: P2PMessage,
        peer_addr: Option<SocketAddr>,
    ) -> Result<Option<P2PMessage>, Box<dyn std::error::Error + Send + Sync>> {
        match msg {
            P2PMessage::ClusterDevicesAnnouncement {
                introducer_id,
                devices,
                auto_trust,
            } => {
                let report = self.handle_cluster_announcement(&introducer_id, &devices, auto_trust)?;
                info!(
                    "Introducer {} announced {} cluster devices: added {} trusted, {} pending",
                    introducer_id,
                    devices.len(),
                    report.added_trusted.len(),
                    report.added_pending.len(),
                );
                Ok(None)
            }
            P2PMessage::Hello {
                device_id,
                device_name,
                folders: _,
                cluster_devices,
                cert_pin,
            } => {
                if !cluster_devices.is_empty() {
                    let _ = self.handle_cluster_announcement(&device_id, &cluster_devices, false);
                }
                let storage = self.sync_engine.storage();
                let is_paired = match storage.get_device(&device_id) {
                    Ok(Some(dev)) => !dev.is_paused,
                    _ => false,
                };

                if !is_paired {
                    let peer_addr_str = peer_addr.map(|a| a.to_string()).unwrap_or_else(|| "dynamic".into());
                    Self::stage_pending_peer(
                        storage,
                        &self.event_sender,
                        &device_id,
                        &device_name,
                        &peer_addr_str,
                        cert_pin,
                    );
                }

                if let Some(addr) = peer_addr {
                    let is_new = Self::update_peer_info(
                        &self.peers,
                        &self.peer_count,
                        device_id.clone(),
                        device_name.clone(),
                        addr,
                    ).await;

                    if is_new && is_paired {
                        let _ = self.event_sender.send(CoreEvent::PeerConnected {
                            peer_id: device_id,
                            addr: addr.to_string(),
                        });
                    }
                }
                Ok(None)
            }
            P2PMessage::ChunkRequest { chunk_hash } => {
                if let Some(data) = self.sync_engine.storage().get_chunk(&chunk_hash)? {
                    Ok(Some(P2PMessage::ChunkResponse { chunk_hash, data }))
                } else {
                    Ok(None)
                }
            }
            P2PMessage::ChunkResponse { chunk_hash, data } => {
                if Chunker::hash_block(&data) != chunk_hash {
                    return Err("Rejected chunk with a mismatched content hash".into());
                }
                self.sync_engine.storage().put_chunk(&chunk_hash, &data)?;
                Ok(None)
            }
            P2PMessage::EncryptedChunkRequest { chunk_hash } => {
                if let Some(envelope) = self.sync_engine.storage().get_encrypted_chunk(&chunk_hash)? {
                    Ok(Some(P2PMessage::EncryptedChunkResponse { chunk_hash, envelope }))
                } else {
                    Ok(None)
                }
            }
            P2PMessage::EncryptedChunkResponse { chunk_hash, envelope } => {
                if envelope.chunk_hash != chunk_hash {
                    return Err("Rejected encrypted chunk with a mismatched envelope hash".into());
                }
                self.sync_engine.storage().put_encrypted_chunk(&envelope)?;
                Ok(None)
            }
            P2PMessage::IndexRequest { folder_id } => {
                let files = self.sync_engine.storage().list_all_files_in_folder(&folder_id, true)?;
                let mut revisions = Vec::with_capacity(files.len());
                let mut chunk_lists = HashMap::new();
                for file in &files {
                    if let Some(revision) = self.sync_engine.storage().get_revision(&file.current_revision)? {
                        if let Ok(chunks) = self.sync_engine.storage().get_revision_chunks(&revision.revision_hash) {
                            chunk_lists.insert(revision.revision_hash.clone(), chunks);
                        }
                        revisions.push(revision);
                    }
                }
                Ok(Some(P2PMessage::IndexResponse { folder_id, files, revisions, chunk_lists }))
            }
            P2PMessage::IndexResponse { folder_id, files, revisions, chunk_lists } => {
                let _ = self.event_sender.send(CoreEvent::RemoteIndexUpdated {
                    device_id: peer_addr.map(|addr| addr.to_string()).unwrap_or_else(|| "unknown".into()),
                    folder_id: folder_id.clone(),
                    file_count: files.len(),
                });
                let _ = self.apply_remote_index(
                    &folder_id,
                    &files,
                    &revisions,
                    &chunk_lists,
                    None,
                    None,
                    peer_addr,
                ).await;
                Ok(None)
            }
            P2PMessage::FileNotice {
                folder_id,
                relative_path,
                revision,
                chunk_hashes,
                is_deleted,
            } => {
                if let Ok(Some(_)) = self.sync_engine.storage().get_folder(&folder_id) {
                    if is_deleted {
                        let _ = self.sync_engine.mark_local_deleted(&folder_id, &relative_path);
                    } else {
                        let author_id = revision.author_device_id.clone();
                        let _ = self.fetch_chunks_and_reconcile(
                            &folder_id,
                            &relative_path,
                            &revision,
                            &chunk_hashes,
                            None,
                            Some(&author_id),
                            peer_addr,
                        ).await;
                    }
                }
                Ok(None)
            }
        }
    }

    /// Configures a QUIC server with a persistent certificate which paired
    /// devices can pin.  A restart must not silently change peer identity.
    pub fn create_quic_server(
        &self,
        bind_addr: SocketAddr,
    ) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
        let cert_der = CertificateDer::from(self.tls_identity.certificate_der.clone());
        let priv_key = PrivatePkcs8KeyDer::from(self.tls_identity.private_key_der.clone());

        let mut server_config =
            ServerConfig::with_single_cert(vec![cert_der], priv_key.into())?;
        
        // Transport settings
        let transport = Arc::get_mut(&mut server_config.transport).unwrap();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));

        let endpoint = Endpoint::server(server_config, bind_addr)?;
        Ok(endpoint)
    }

    fn client_config_for_device(
        &self,
        device_id: &str,
    ) -> Result<ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
        let device = self
            .sync_engine
            .storage()
            .get_device(device_id)?
            .ok_or("Unknown peer")?;
        if device.is_paused || !device.is_trusted {
            return Err("Peer is not trusted and active".into());
        }
        let pin = device
            .cert_name
            .ok_or("Peer has no pinned TLS certificate; pair it with its certificate pin")?;
        let certificate = hex::decode(pin)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(certificate))?;
        Ok(ClientConfig::with_root_certificates(Arc::new(roots))?)
    }

    async fn send_on_connection(
        connection: &quinn::Connection,
        message: &P2PMessage,
    ) -> Result<Option<P2PMessage>, Box<dyn std::error::Error + Send + Sync>> {
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(&serde_json::to_vec(message)?).await?;
        send.finish()?;
        let response = recv.read_to_end(16 * 1024 * 1024).await?;
        if response.is_empty() {
            Ok(None)
        } else {
            Ok(Some(serde_json::from_slice(&response)?))
        }
    }

    /// Establishes an authenticated QUIC connection to a paired peer.
    pub async fn connect_to_peer(
        &self,
        device_id: &str,
        address: SocketAddr,
    ) -> Result<(Endpoint, quinn::Connection), Box<dyn std::error::Error + Send + Sync>> {
        let client_config = self.client_config_for_device(device_id)?;
        let endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        let connection = endpoint
            .connect_with(client_config, address, "synapse.p2p")?
            .await?;
        let folders = self
            .sync_engine
            .storage()
            .list_folders()?
            .into_iter()
            .map(|folder| folder.folder_id)
            .collect();
        Self::send_on_connection(
            &connection,
            &P2PMessage::Hello {
                device_id: self.identity.device_id.clone(),
                device_name: self.device_name.clone(),
                folders,
                cluster_devices: Vec::new(),
                cert_pin: Some(self.tls_identity.certificate_pin()),
            },
        )
        .await?;
        Ok((endpoint, connection))
    }

    /// Sends an authenticated request to a paired peer over a certificate-pinned
    /// QUIC connection.  The Hello stream establishes the application session
    /// before any index or chunk operation is permitted.
    pub async fn request_peer(
        &self,
        device_id: &str,
        address: SocketAddr,
        message: P2PMessage,
    ) -> Result<Option<P2PMessage>, Box<dyn std::error::Error + Send + Sync>> {
        let (endpoint, connection) = self.connect_to_peer(device_id, address).await?;
        let response = Self::send_on_connection(&connection, &message).await?;
        endpoint.close(0u32.into(), b"request complete");
        Ok(response)
    }

    async fn fetch_chunk_on_connection(
        connection: &quinn::Connection,
        chunk_hash: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let req = P2PMessage::ChunkRequest {
            chunk_hash: chunk_hash.to_string(),
        };
        let resp = Self::send_on_connection(connection, &req).await?;
        match resp {
            Some(P2PMessage::ChunkResponse {
                chunk_hash: resp_hash,
                data,
            }) => {
                if resp_hash != chunk_hash {
                    return Err(format!("Chunk hash mismatch: expected {}, got {}", chunk_hash, resp_hash).into());
                }
                if Chunker::hash_block(&data) != chunk_hash {
                    return Err(format!("Corrupt chunk content: hash does not match {}", chunk_hash).into());
                }
                Ok(data)
            }
            _ => Err(format!("Failed to retrieve chunk {}", chunk_hash).into()),
        }
    }

    /// Fetches any missing chunks in `chunk_hashes` from the active QUIC connection
    /// (or connects via `request_peer`), verifies their BLAKE3 content hash, saves them
    /// to CAS, and applies the remote revision to the filesystem and DAG.
    pub async fn fetch_chunks_and_reconcile(
        &self,
        folder_id: &str,
        relative_path: &str,
        revision: &RevisionNode,
        chunk_hashes: &[String],
        connection: Option<&quinn::Connection>,
        peer_device_id: Option<&str>,
        peer_addr: Option<SocketAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for chunk_hash in chunk_hashes {
            if self.sync_engine.storage().get_chunk(chunk_hash)?.is_none() {
                let data = if let Some(conn) = connection {
                    Self::fetch_chunk_on_connection(conn, chunk_hash).await?
                } else if let (Some(dev_id), Some(addr)) = (peer_device_id, peer_addr) {
                    let req = P2PMessage::ChunkRequest {
                        chunk_hash: chunk_hash.clone(),
                    };
                    match self.request_peer(dev_id, addr, req).await? {
                        Some(P2PMessage::ChunkResponse { data, .. }) => {
                            if Chunker::hash_block(&data) != *chunk_hash {
                                return Err(format!("Corrupt chunk content for {}", chunk_hash).into());
                            }
                            data
                        }
                        _ => return Err(format!("Could not fetch chunk {} from peer {}", chunk_hash, dev_id).into()),
                    }
                } else {
                    return Err(format!("Missing chunk {} and no peer connection available", chunk_hash).into());
                };
                self.sync_engine.storage().put_chunk(chunk_hash, &data)?;
            }
        }

        let payload = self.sync_engine.storage().read_chunks_payload(chunk_hashes)?;
        self.sync_engine.reconcile_remote_revision(
            folder_id,
            relative_path,
            revision,
            chunk_hashes,
            &payload,
        )?;
        Ok(())
    }

    /// Reconciles all remote files and tombstones received from an IndexResponse.
    pub async fn apply_remote_index(
        &self,
        folder_id: &str,
        files: &[FileRecord],
        revisions: &[RevisionRecord],
        chunk_lists: &HashMap<String, Vec<String>>,
        connection: Option<&quinn::Connection>,
        peer_device_id: Option<&str>,
        peer_addr: Option<SocketAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let rev_map: HashMap<&str, &RevisionRecord> = revisions
            .iter()
            .map(|r| (r.revision_hash.as_str(), r))
            .collect();

        for file in files {
            let local_file = self.sync_engine.storage().get_file(folder_id, &file.relative_path)?;

            if file.is_deleted {
                if let Some(lf) = local_file {
                    if !lf.is_deleted {
                        let _ = self.sync_engine.mark_local_deleted(folder_id, &file.relative_path);
                    }
                }
                continue;
            }

            let needs_sync = match &local_file {
                Some(lf) => lf.current_revision != file.current_revision || lf.is_deleted,
                None => true,
            };

            if needs_sync {
                if let Some(rev_rec) = rev_map.get(file.current_revision.as_str()) {
                    let mut parent_hashes = Vec::new();
                    if let Some(p1) = &rev_rec.parent_1 { parent_hashes.push(p1.clone()); }
                    if let Some(p2) = &rev_rec.parent_2 { parent_hashes.push(p2.clone()); }

                    let rev_node = RevisionNode {
                        revision_hash: rev_rec.revision_hash.clone(),
                        parent_hashes,
                        manifest_hash: rev_rec.manifest_hash.clone(),
                        author_device_id: rev_rec.author_device.clone(),
                        sequence_number: rev_rec.sequence_number,
                        file_size: rev_rec.file_size,
                        mtime_nanos: rev_rec.created_at,
                    };

                    let empty_chunks = Vec::new();
                    let chunk_hashes = chunk_lists
                        .get(&rev_rec.revision_hash)
                        .unwrap_or(&empty_chunks);

                    if let Err(e) = self.fetch_chunks_and_reconcile(
                        folder_id,
                        &file.relative_path,
                        &rev_node,
                        chunk_hashes,
                        connection,
                        peer_device_id,
                        peer_addr,
                    ).await {
                        warn!("Failed to reconcile remote file {}/{}: {}", folder_id, file.relative_path, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Pulls the complete index for `folder_id` from a paired peer,
    /// downloads missing chunks, and applies remote changes and deletions.
    pub async fn sync_folder_from_peer(
        &self,
        peer_device_id: &str,
        peer_addr: SocketAddr,
        folder_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (endpoint, connection) = self.connect_to_peer(peer_device_id, peer_addr).await?;
        let index_req = P2PMessage::IndexRequest {
            folder_id: folder_id.to_string(),
        };
        let response = Self::send_on_connection(&connection, &index_req).await?;

        if let Some(P2PMessage::IndexResponse {
            folder_id: resp_folder_id,
            files,
            revisions,
            chunk_lists,
        }) = response
        {
            if resp_folder_id != folder_id {
                endpoint.close(0u32.into(), b"folder mismatch");
                return Err("Index response folder ID mismatch".into());
            }

            self.apply_remote_index(
                folder_id,
                &files,
                &revisions,
                &chunk_lists,
                Some(&connection),
                Some(peer_device_id),
                Some(peer_addr),
            )
            .await?;
        }

        endpoint.close(0u32.into(), b"sync complete");
        Ok(())
    }

    /// Broadcasts a FileNotice to all active paired cluster peers.
    pub async fn broadcast_file_notice(
        &self,
        folder_id: &str,
        relative_path: &str,
        revision_hash: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let rev_rec = match self.sync_engine.storage().get_revision(revision_hash)? {
            Some(r) => r,
            None => return Ok(()),
        };
        let chunk_hashes = self.sync_engine.storage().get_revision_chunks(revision_hash)?;
        let is_deleted = self.sync_engine.storage().get_file(folder_id, relative_path)?
            .map(|f| f.is_deleted)
            .unwrap_or(false);

        let mut parent_hashes = Vec::new();
        if let Some(p1) = &rev_rec.parent_1 { parent_hashes.push(p1.clone()); }
        if let Some(p2) = &rev_rec.parent_2 { parent_hashes.push(p2.clone()); }

        let rev_node = RevisionNode {
            revision_hash: rev_rec.revision_hash.clone(),
            parent_hashes,
            manifest_hash: rev_rec.manifest_hash.clone(),
            author_device_id: rev_rec.author_device.clone(),
            sequence_number: rev_rec.sequence_number,
            file_size: rev_rec.file_size,
            mtime_nanos: rev_rec.created_at,
        };

        let notice = P2PMessage::FileNotice {
            folder_id: folder_id.to_string(),
            relative_path: relative_path.to_string(),
            revision: rev_node,
            chunk_hashes,
            is_deleted,
        };

        let active_peers: Vec<(String, SocketAddr)> = {
            let map = self.peers.lock().await;
            map.values().map(|p| (p.device_id.clone(), p.addr)).collect()
        };

        for (peer_id, addr) in active_peers {
            if peer_id == self.identity.device_id {
                continue;
            }
            let notice_clone = match serde_json::to_value(&notice) {
                Ok(v) => match serde_json::from_value::<P2PMessage>(v) {
                    Ok(m) => m,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            let manager = self.clone();
            tokio::spawn(async move {
                let _ = manager.request_peer(&peer_id, addr, notice_clone).await;
            });
        }

        Ok(())
    }

    /// Spawns the QUIC server loop handling incoming peer connections.
    pub async fn run_server(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], self.p2p_port));
        let endpoint = match self.create_quic_server(bind_addr) {
            Ok(ep) => ep,
            Err(e) => {
                warn!("Unable to start QUIC server on {}: {}", bind_addr, e);
                return Ok(());
            }
        };

        info!("Synapse Core QUIC P2P listening on {}", bind_addr);
        let manager = Arc::new(self.clone());

        while let Some(conn) = endpoint.accept().await {
            let manager = manager.clone();
            tokio::spawn(async move {
                if let Ok(connection) = conn.await {
                    let _ = handle_quic_connection(connection, manager).await;
                }
            });
        }

        Ok(())
    }
}

/// Handles incoming streams on an active QUIC connection.
async fn handle_quic_connection(
    conn: quinn::Connection,
    manager: Arc<P2PManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let remote_addr = conn.remote_address();
    let mut authenticated_peer_id: Option<String> = None;
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let buf = match recv.read_to_end(16 * 1024 * 1024).await {
            Ok(buf) => buf,
            Err(_) => continue,
        };
        let message = match serde_json::from_slice::<P2PMessage>(&buf) {
            Ok(message) => message,
            Err(_) => continue,
        };

        if let P2PMessage::Hello { device_id, .. } = &message {
            let is_trusted = manager
                .sync_engine
                .storage()
                .get_device(device_id)
                .ok()
                .flatten()
                .is_some_and(|device| !device.is_paused && device.is_trusted);
            if !is_trusted {
                // Keep the pairing UX, but never permit a staged device to
                // access indexes or content over this connection.
                let _ = manager.handle_p2p_message(message, Some(remote_addr)).await;
                let _ = send.finish();
                continue;
            }
            authenticated_peer_id = Some(device_id.clone());
        } else if authenticated_peer_id.is_none() {
            warn!("Rejected unauthenticated P2P request from {}", remote_addr);
            let _ = send.finish();
            continue;
        }

        if let P2PMessage::FileNotice {
            folder_id,
            relative_path,
            revision,
            chunk_hashes,
            is_deleted,
        } = &message
        {
            if let Ok(Some(_)) = manager.sync_engine.storage().get_folder(folder_id) {
                if *is_deleted {
                    let _ = manager.sync_engine.mark_local_deleted(folder_id, relative_path);
                } else {
                    let _ = manager
                        .fetch_chunks_and_reconcile(
                            folder_id,
                            relative_path,
                            revision,
                            chunk_hashes,
                            Some(&conn),
                            authenticated_peer_id.as_deref(),
                            Some(remote_addr),
                        )
                        .await;
                }
            }
            let _ = send.finish();
            continue;
        }

        if let Ok(Some(reply)) = manager.handle_p2p_message(message, Some(remote_addr)).await {
            if let Ok(reply_bytes) = serde_json::to_vec(&reply) {
                let _ = send.write_all(&reply_bytes).await;
            }
        }
        let _ = send.finish();
    }
    Ok(())
}
