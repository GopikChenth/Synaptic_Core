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

use quinn::{Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};
use tracing::{info, warn};

use crate::conflict::CoreEvent;
use crate::dag::RevisionNode;
use crate::engine::SyncEngine;
use crate::p2p::identity::NodeIdentity;
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
    },
    IndexRequest {
        folder_id: String,
    },
    IndexResponse {
        folder_id: String,
        files: Vec<FileRecord>,
        revisions: Vec<RevisionRecord>,
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
        device_name: String,
        p2p_port: u16,
        sync_engine: SyncEngine,
        peer_count: Arc<AtomicUsize>,
        event_sender: broadcast::Sender<CoreEvent>,
    ) -> Self {
        Self {
            identity,
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

    /// Spawns UDP broadcast discovery listener and periodic announcer.
    pub fn start_discovery(&self, discovery_port: u16) {
        let device_id = self.identity.device_id.clone();
        let p2p_port = self.p2p_port;
        let peers = self.peers.clone();
        let peer_count = self.peer_count.clone();
        let event_sender = self.event_sender.clone();
        let storage_listener = self.sync_engine.storage().clone();
        let storage_announcer = self.sync_engine.storage().clone();

        // 1. Discovery listener task
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

                            // Check cluster pairing status in SQLite
                            let is_paired = match storage_listener.get_device(&peer.device_id) {
                                Ok(Some(dev)) => {
                                    if dev.is_paused {
                                        continue;
                                    }
                                    true
                                }
                                Ok(None) => {
                                    // Unknown peer: record in pending pairing requests
                                    let _ = storage_listener.add_pending_device(&PendingDeviceRecord {
                                        device_id: peer.device_id.clone(),
                                        name: peer.device_name.clone(),
                                        address: peer_addr.to_string(),
                                        received_at: chrono::Utc::now().timestamp_millis(),
                                    });
                                    false
                                }
                                Err(_) => false,
                            };

                            let mut map = peers.lock().await;
                            let is_new = !map.contains_key(&peer.device_id);
                            map.insert(
                                peer.device_id.clone(),
                                PeerInfo {
                                    device_id: peer.device_id.clone(),
                                    device_name: peer.device_name.clone(),
                                    addr: peer_addr,
                                    last_seen: std::time::Instant::now(),
                                },
                            );
                            peer_count.store(map.len(), Ordering::Relaxed);

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
                };

                if let Ok(payload) = serde_json::to_vec(&announcement) {
                    let _ = socket.send_to(&payload, target_addr).await;
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
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
            } => {
                if !cluster_devices.is_empty() {
                    let _ = self.handle_cluster_announcement(&device_id, &cluster_devices, false);
                }
                if let Some(addr) = peer_addr {
                    let mut map = self.peers.lock().await;
                    map.insert(
                        device_id.clone(),
                        PeerInfo {
                            device_id,
                            device_name,
                            addr,
                            last_seen: std::time::Instant::now(),
                        },
                    );
                    self.peer_count.store(map.len(), Ordering::Relaxed);
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
            P2PMessage::EncryptedChunkResponse { chunk_hash: _, envelope } => {
                self.sync_engine.storage().put_encrypted_chunk(&envelope)?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Configures Quinn QUIC server endpoint with self-signed certificate.
    pub fn create_quic_server(
        bind_addr: SocketAddr,
    ) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
        let cert = rcgen::generate_simple_self_signed(vec!["synapse.p2p".into()])?;
        let cert_der = CertificateDer::from(cert.cert);
        let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        let mut server_config =
            ServerConfig::with_single_cert(vec![cert_der], priv_key.into())?;
        
        // Transport settings
        let transport = Arc::get_mut(&mut server_config.transport).unwrap();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));

        let endpoint = Endpoint::server(server_config, bind_addr)?;
        Ok(endpoint)
    }

    /// Spawns the QUIC server loop handling incoming peer connections.
    pub async fn run_server(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], self.p2p_port));
        let endpoint = match Self::create_quic_server(bind_addr) {
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
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let p2p = manager.clone();
        tokio::spawn(async move {
            if let Ok(buf) = recv.read_to_end(16 * 1024 * 1024).await {
                if let Ok(msg) = serde_json::from_slice::<P2PMessage>(&buf) {
                    if let Ok(Some(reply)) = p2p.handle_p2p_message(msg, Some(remote_addr)).await {
                        if let Ok(reply_bytes) = serde_json::to_vec(&reply) {
                            let _ = send.write_all(&reply_bytes).await;
                            let _ = send.finish();
                        }
                    }
                }
            }
        });
    }
    Ok(())
}
