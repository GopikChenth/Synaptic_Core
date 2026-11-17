//! Synapse Core: Decentralized File Synchronization & Conflict Resolution Engine.
//!
//! Exposes both a Rust API and C-compatible ABI exports for cross-platform deployment
//! across Linux, macOS, Windows, and Android (`libsynapse.so`).

pub mod api;
pub mod chunker;
pub mod conflict;
pub mod dag;
pub mod engine;
pub mod p2p;
pub mod state;
pub mod storage;

use std::ffi::CStr;
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::{broadcast, watch};
use tracing::{error, info};

use crate::api::ApiServer;
use crate::conflict::{ConflictEngine, CoreEvent};
use crate::engine::SyncEngine;
use crate::p2p::identity::{NodeIdentity, TlsIdentity};
use crate::p2p::P2PManager;
use crate::storage::StorageEngine;

/// Master configuration for starting Synapse Core.
#[derive(Debug, Clone)]
pub struct SynapseConfig {
    pub home_dir: PathBuf,
    pub api_addr: SocketAddr,
    pub p2p_port: u16,
    pub discovery_port: u16,
    pub auth_token: Option<String>,
    pub device_name: String,
}

impl Default for SynapseConfig {
    fn default() -> Self {
        let home = std::env::var("SYNAPSE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs_fallback().join(".synapse")
            });

        Self {
            home_dir: home,
            api_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            p2p_port: crate::p2p::DEFAULT_P2P_PORT,
            discovery_port: crate::p2p::DEFAULT_DISCOVERY_PORT,
            auth_token: None,
            device_name: get_default_device_name(),
        }
    }
}

fn dirs_fallback() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn get_default_device_name() -> String {
    hostname::get()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|_| "SynapseNode".into())
}

mod hostname {
    pub fn get() -> Result<std::ffi::OsString, std::io::Error> {
        #[cfg(unix)]
        {
            let mut buf = [0u8; 256];
            let res = unsafe { libc_gethostname(buf.as_mut_ptr(), buf.len()) };
            if res == 0 {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                return Ok(std::ffi::OsString::from(String::from_utf8_lossy(&buf[..len]).to_string()));
            }
        }
        Ok(std::ffi::OsString::from("SynapseDevice"))
    }

    #[cfg(unix)]
    unsafe fn libc_gethostname(name: *mut u8, len: usize) -> i32 {
        extern "C" {
            fn gethostname(name: *mut u8, len: usize) -> i32;
        }
        gethostname(name, len)
    }
}

/// Active instance of Synapse Core engine.
pub struct SynapseCore {
    config: SynapseConfig,
    storage: StorageEngine,
    sync_engine: SyncEngine,
    p2p_manager: Arc<P2PManager>,
    event_sender: broadcast::Sender<CoreEvent>,
    peer_count: Arc<AtomicUsize>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl SynapseCore {
    /// Initializes and prepares the Synapse Core environment.
    pub fn init(config: SynapseConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if !config.api_addr.ip().is_loopback()
            && config.auth_token.as_deref().map_or(true, str::is_empty)
        {
            return Err("Refusing to expose the control-plane API off localhost without --token".into());
        }
        std::fs::create_dir_all(&config.home_dir)?;

        let identity = NodeIdentity::load_or_generate(&config.home_dir)?;
        let tls_identity = TlsIdentity::load_or_generate(&config.home_dir)?;
        info!("Synapse Core Device ID: {}", identity.device_id);

        let storage = StorageEngine::new(&config.home_dir)?;
        let (event_sender, _) = broadcast::channel(1024);
        let peer_count = Arc::new(AtomicUsize::new(0));

        let conflict_engine = Arc::new(ConflictEngine::new(
            storage.clone(),
            event_sender.clone(),
            identity.device_id.clone(),
        ));

        let sync_engine = SyncEngine::new(
            storage.clone(),
            conflict_engine,
            event_sender.clone(),
            identity.device_id.clone(),
        );

        let p2p_manager = Arc::new(P2PManager::new(
            identity,
            tls_identity,
            config.device_name.clone(),
            config.p2p_port,
            sync_engine.clone(),
            peer_count.clone(),
            event_sender.clone(),
        ));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(Self {
            config,
            storage,
            sync_engine,
            p2p_manager,
            event_sender,
            peer_count,
            shutdown_tx,
            shutdown_rx,
        })
    }

    pub fn event_sender(&self) -> &broadcast::Sender<CoreEvent> {
        &self.event_sender
    }

    /// Returns a handle that can be used to trigger a graceful shutdown (`tx.send(true)`).
    pub fn shutdown_handle(&self) -> watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// Spawns API server, discovery, watchers, and QUIC listener on Tokio runtime.
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting Synapse Core engine...");

        self.p2p_manager.start_discovery(self.config.discovery_port);

        let mut watchers = Vec::new();
        if let Ok(folders) = self.storage.list_folders() {
            for f in folders {
                if !f.is_paused {
                    let engine = self.sync_engine.clone();
                    let fid = f.folder_id.clone();
                    tokio::task::spawn_blocking(move || {
                        let _ = engine.index_folder(&fid);
                    });
                    let watcher = self.sync_engine.spawn_watcher(f.folder_id, f.local_path);
                    watchers.push(watcher);
                }
            }
        }

        let p2p = self.p2p_manager.clone();
        let p2p_handle = tokio::spawn(async move {
            if let Err(e) = p2p.run_server().await {
                error!("QUIC P2P error: {}", e);
            }
        });

        let signal_tx = self.shutdown_tx.clone();
        let signal_handle = tokio::spawn(async move {
            wait_for_os_shutdown_signal().await;
            info!("OS shutdown signal received");
            let _ = signal_tx.send(true);
        });

        let api_server = ApiServer::new(
            self.sync_engine.clone(),
            self.config.api_addr,
            self.config.auth_token.clone(),
            self.peer_count.clone(),
        )
        .with_shutdown_tx(self.shutdown_tx.clone());

        let api_result = api_server.run_with_shutdown(self.shutdown_rx).await;

        signal_handle.abort();
        p2p_handle.abort();
        drop(watchers);
        info!("Synapse Core engine stopped.");

        api_result?;
        Ok(())
    }
}

async fn wait_for_os_shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

// =============================================================================
// C / JNI ABI EXPORTS FOR ANDROID (libsynapse.so)
// =============================================================================

static RUNNING: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_TX: Mutex<Option<watch::Sender<bool>>> = Mutex::new(None);

/// Starts the Synapse Core daemon from C / JNI.
///
/// # Safety
/// `home_dir` must be a valid, null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn synapse_start(
    home_dir: *const c_char,
    api_port: c_int,
    p2p_port: c_int,
) -> c_int {
    if RUNNING.load(Ordering::SeqCst) {
        return 0;
    }

    if home_dir.is_null() {
        return -1;
    }

    let home_str = match CStr::from_ptr(home_dir).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let mut config = SynapseConfig::default();
    config.home_dir = PathBuf::from(home_str);
    if api_port > 0 {
        config.api_addr = SocketAddr::from(([127, 0, 0, 1], api_port as u16));
    }
    if p2p_port > 0 {
        config.p2p_port = p2p_port as u16;
    }

    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(_) => return -3,
    };

    match SynapseCore::init(config) {
        Ok(core) => {
            if let Ok(mut guard) = SHUTDOWN_TX.lock() {
                *guard = Some(core.shutdown_handle());
            }
            RUNNING.store(true, Ordering::SeqCst);
            std::thread::spawn(move || {
                let _ = rt.block_on(core.run());
                if let Ok(mut guard) = SHUTDOWN_TX.lock() {
                    *guard = None;
                }
                RUNNING.store(false, Ordering::SeqCst);
            });
            0
        }
        Err(_) => -4,
    }
}

/// Checks if Synapse Core is currently active.
#[no_mangle]
pub extern "C" fn synapse_is_running() -> c_int {
    if RUNNING.load(Ordering::SeqCst) {
        1
    } else {
        0
    }
}

/// Stops the Synapse Core daemon.
#[no_mangle]
pub extern "C" fn synapse_stop() -> c_int {
    if let Ok(mut guard) = SHUTDOWN_TX.lock() {
        if let Some(tx) = guard.take() {
            let _ = tx.send(true);
        }
    }
    RUNNING.store(false, Ordering::SeqCst);
    0
}
