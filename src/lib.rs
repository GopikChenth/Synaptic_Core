//! Synapse Core: Decentralized File Synchronization & Conflict Resolution Engine.
//!
//! Ships as a standalone engine binary (`synapse-core`) that client apps drive over its
//! local HTTP/WebSocket API. On Android the same executable is packaged as
//! `jniLibs/<abi>/libsynapse.so` and spawned from `nativeLibraryDir`.

pub mod api;
pub mod chunker;
pub mod conflict;
pub mod dag;
pub mod engine;
pub mod p2p;
pub mod state;
pub mod storage;
pub mod telemetry;

use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tracing::{error, info, warn};

use crate::api::ApiServer;
use crate::conflict::{ConflictEngine, CoreEvent};
use crate::engine::SyncEngine;
use crate::p2p::identity::{NodeIdentity, TlsIdentity};
use crate::p2p::P2PManager;
use crate::state::runtime::EngineLifecycleState;
use crate::storage::StorageEngine;

/// Crate version, reported by the CLI, `runtime.json`, and the FFI layer.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name of the advisory lock file guarding a home directory against two daemons.
pub const LOCK_FILE_NAME: &str = "synapse.lock";

/// Name of the file published once the engine is ready to serve requests.
pub const RUNTIME_FILE_NAME: &str = "runtime.json";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

// =============================================================================
// Errors
// =============================================================================

/// Startup failures that callers (CLI exit codes, FFI return codes, Kotlin launchers)
/// need to tell apart. Everything else surfaces as a generic boxed error.
#[derive(Debug)]
pub enum StartupError {
    /// No usable home directory (e.g. Android, where `$HOME` is unset).
    NoHomeDir,
    /// Another Synapse Core instance holds the lock for this home directory.
    AlreadyRunning { home_dir: PathBuf },
    /// The control-plane API socket could not be bound.
    ApiBind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    /// Exposing the API off-loopback requires an auth token.
    InsecureBind { addr: SocketAddr },
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoHomeDir => write!(
                f,
                "no home directory: pass --home <dir> or set SYNAPSE_HOME \
                 (on Android use Context.filesDir)"
            ),
            Self::AlreadyRunning { home_dir } => write!(
                f,
                "another Synapse Core instance is already using {}",
                home_dir.display()
            ),
            Self::ApiBind { addr, source } => {
                write!(f, "cannot bind control-plane API on {addr}: {source}")
            }
            Self::InsecureBind { addr } => write!(
                f,
                "refusing to expose the control-plane API on {addr} without --token"
            ),
        }
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ApiBind { source, .. } => Some(source),
            _ => None,
        }
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// Master configuration for starting Synapse Core.
#[derive(Debug, Clone)]
pub struct SynapseConfig {
    pub home_dir: PathBuf,
    /// API bind address. Port `0` asks the OS for a free port; the real one is
    /// published in `runtime.json` and via [`ReadyInfo`].
    pub api_addr: SocketAddr,
    pub p2p_port: u16,
    pub discovery_port: u16,
    pub auth_token: Option<String>,
    pub device_name: String,
    /// Install SIGINT/SIGTERM handlers. Set to `false` when embedding the engine as a
    /// Rust library inside a process that owns signal handling.
    pub install_signal_handlers: bool,
    /// Shut down when the parent process dies (polls the parent PID on Unix).
    /// Prevents orphaned daemons holding ports after an app crash.
    pub exit_with_parent: bool,
    /// Shut down when stdin reaches EOF. The most portable parent-liveness signal:
    /// the parent's end of the pipe closes when it exits for any reason.
    pub exit_on_stdin_close: bool,
}

impl Default for SynapseConfig {
    fn default() -> Self {
        Self {
            home_dir: default_home_dir().unwrap_or_default(),
            api_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            p2p_port: crate::p2p::DEFAULT_P2P_PORT,
            discovery_port: crate::p2p::DEFAULT_DISCOVERY_PORT,
            auth_token: None,
            device_name: default_device_name(),
            install_signal_handlers: true,
            exit_with_parent: false,
            exit_on_stdin_close: false,
        }
    }
}

/// Resolves the default home directory: `$SYNAPSE_HOME`, else `~/.synapse`.
///
/// Returns `None` when neither is available. We deliberately do **not** fall back to
/// the current directory: on Android the cwd of a spawned process is `/`, which is
/// read-only and produces an opaque "Permission denied" at startup.
pub fn default_home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("SYNAPSE_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    if cfg!(target_os = "android") {
        return None;
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|v| !v.is_empty())
        .map(|h| PathBuf::from(h).join(".synapse"))
}

/// Best-effort human-readable device name.
pub fn default_device_name() -> String {
    #[cfg(target_os = "android")]
    {
        // gethostname() is always "localhost" on Android; the model name is useful.
        if let Some(model) = android_system_property("ro.product.model") {
            return model;
        }
    }
    hostname::get()
        .ok()
        .map(|s| s.to_string_lossy().trim().to_string())
        .filter(|s| !s.is_empty() && s != "localhost")
        .unwrap_or_else(|| "SynapseNode".into())
}

#[cfg(target_os = "android")]
fn android_system_property(name: &str) -> Option<String> {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int};
    extern "C" {
        fn __system_property_get(name: *const c_char, value: *mut c_char) -> c_int;
    }
    const PROP_VALUE_MAX: usize = 92;
    let key = CString::new(name).ok()?;
    let mut buf = [0 as c_char; PROP_VALUE_MAX];
    // SAFETY: bionic writes at most PROP_VALUE_MAX bytes including the terminator.
    let len = unsafe { __system_property_get(key.as_ptr(), buf.as_mut_ptr()) };
    if len <= 0 {
        return None;
    }
    // SAFETY: buffer is NUL-terminated by bionic.
    let value = unsafe { CStr::from_ptr(buf.as_ptr()) };
    Some(value.to_string_lossy().trim().to_string()).filter(|s| !s.is_empty())
}

mod hostname {
    pub fn get() -> Result<std::ffi::OsString, std::io::Error> {
        #[cfg(unix)]
        {
            let mut buf = [0u8; 256];
            // SAFETY: buffer is valid for `len` bytes; gethostname NUL-terminates on success.
            let res = unsafe { libc_gethostname(buf.as_mut_ptr(), buf.len()) };
            if res == 0 {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                return Ok(std::ffi::OsString::from(
                    String::from_utf8_lossy(&buf[..len]).to_string(),
                ));
            }
        }
        #[cfg(windows)]
        if let Some(name) = std::env::var_os("COMPUTERNAME") {
            return Ok(name);
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

// =============================================================================
// Single-instance lock & runtime file
// =============================================================================

/// Advisory, OS-released lock on `<home>/synapse.lock`.
///
/// The OS drops the lock automatically if the process dies, so a crash never leaves a
/// stale lock behind (unlike PID files).
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    pub fn acquire(home_dir: &Path) -> Result<Self, BoxError> {
        let path = home_dir.join(LOCK_FILE_NAME);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(StartupError::AlreadyRunning {
                    home_dir: home_dir.to_path_buf(),
                }
                .into())
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        // Informational only; the lock itself is the source of truth.
        let _ = file.set_len(0);
        let _ = std::io::Write::write_all(&mut &file, std::process::id().to_string().as_bytes());
        Ok(Self { _file: file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Published to `<home>/runtime.json` once the API is accepting connections, and
/// handed to the [`SynapseCore::on_ready`] callback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadyInfo {
    pub pid: u32,
    pub version: String,
    pub device_id: String,
    pub device_name: String,
    pub api_addr: SocketAddr,
    pub api_url: String,
    pub p2p_port: u16,
    pub started_at: i64,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

// =============================================================================
// Engine
// =============================================================================

type ReadyCallback = Box<dyn FnOnce(&ReadyInfo) + Send + 'static>;

/// Why [`SynapseCore::run_until_exit`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Shutdown was requested (API, signal, parent exit, stdin closed).
    Shutdown,
    /// `POST /api/v1/system/restart`: the caller should start a fresh engine
    /// generation (see `main.rs`, which does so on the same API address).
    Restart,
}

/// Active instance of Synapse Core engine.
pub struct SynapseCore {
    config: SynapseConfig,
    device_id: String,
    storage: StorageEngine,
    sync_engine: SyncEngine,
    p2p_manager: Arc<P2PManager>,
    event_sender: broadcast::Sender<CoreEvent>,
    peer_count: Arc<AtomicUsize>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    lock: InstanceLock,
    on_ready: Option<ReadyCallback>,
}

impl SynapseCore {
    /// Validates configuration, takes the instance lock, and opens storage & identity.
    pub fn init(mut config: SynapseConfig) -> Result<Self, BoxError> {
        if config.home_dir.as_os_str().is_empty() {
            return Err(StartupError::NoHomeDir.into());
        }
        if !config.api_addr.ip().is_loopback()
            && config.auth_token.as_deref().is_none_or(str::is_empty)
        {
            return Err(StartupError::InsecureBind {
                addr: config.api_addr,
            }
            .into());
        }

        std::fs::create_dir_all(&config.home_dir).map_err(|e| {
            format!(
                "cannot create home directory {}: {e}",
                config.home_dir.display()
            )
        })?;
        // Absolute paths make logs, runtime.json and folder registrations unambiguous.
        if let Ok(abs) = config.home_dir.canonicalize() {
            config.home_dir = abs;
        }

        let lock = InstanceLock::acquire(&config.home_dir)?;
        // A runtime file left by a crashed instance must not be mistaken for readiness.
        let _ = std::fs::remove_file(config.home_dir.join(RUNTIME_FILE_NAME));

        let identity = NodeIdentity::load_or_generate(&config.home_dir)?;
        let tls_identity = TlsIdentity::load_or_generate(&config.home_dir)?;
        let device_id = identity.device_id.clone();
        info!("Synapse Core Device ID: {}", device_id);

        let storage = StorageEngine::new(&config.home_dir)?;
        let (event_sender, _) = broadcast::channel(1024);
        let peer_count = Arc::new(AtomicUsize::new(0));

        let conflict_engine = Arc::new(ConflictEngine::new(
            storage.clone(),
            event_sender.clone(),
            device_id.clone(),
        ));

        let sync_engine = SyncEngine::new(
            storage.clone(),
            conflict_engine,
            event_sender.clone(),
            device_id.clone(),
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
            device_id,
            storage,
            sync_engine,
            p2p_manager,
            event_sender,
            peer_count,
            shutdown_tx,
            shutdown_rx,
            lock,
            on_ready: None,
        })
    }

    pub fn config(&self) -> &SynapseConfig {
        &self.config
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn event_sender(&self) -> &broadcast::Sender<CoreEvent> {
        &self.event_sender
    }

    /// Returns a handle that can be used to trigger a graceful shutdown (`tx.send(true)`).
    pub fn shutdown_handle(&self) -> watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// Registers a callback fired once the API socket is bound and `runtime.json` written.
    pub fn on_ready(mut self, f: impl FnOnce(&ReadyInfo) + Send + 'static) -> Self {
        self.on_ready = Some(Box::new(f));
        self
    }

    /// Runs the engine until shutdown is requested.
    pub async fn run(self) -> Result<(), BoxError> {
        self.run_until_exit().await.map(|_| ())
    }

    /// Runs the engine until it stops, and reports whether a restart was requested.
    ///
    /// The API socket is bound *first*, so a port conflict fails fast with
    /// [`StartupError::ApiBind`] before discovery, watchers or QUIC start.
    pub async fn run_until_exit(mut self) -> Result<ExitReason, BoxError> {
        info!("Starting Synapse Core engine v{VERSION}...");

        let api = ApiServer::new(
            self.sync_engine.clone(),
            self.config.api_addr,
            self.config.auth_token.clone(),
            self.peer_count.clone(),
        )
        .with_shutdown_tx(self.shutdown_tx.clone())
        .bind()
        .await
        .map_err(|source| StartupError::ApiBind {
            addr: self.config.api_addr,
            source,
        })?;
        let api_addr = api.local_addr();

        self.p2p_manager.start_discovery(self.config.discovery_port);
        self.p2p_manager.start_presence_monitor();

        let mut watchers = Vec::new();
        match self.storage.list_folders() {
            Ok(folders) => {
                for f in &folders {
                    self.sync_engine.track_folder(&f.folder_id);
                }
                for f in folders.into_iter().filter(|f| !f.is_paused) {
                    let engine = self.sync_engine.clone();
                    let fid = f.folder_id.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = engine.index_folder(&fid) {
                            warn!("Initial index of folder '{}' failed: {}", fid, e);
                        }
                    });
                    watchers.push(self.sync_engine.spawn_watcher(f.folder_id, f.local_path));
                }
            }
            Err(e) => error!("Unable to load folder list: {}", e),
        }

        let p2p = self.p2p_manager.clone();
        let p2p_handle = tokio::spawn(async move {
            if let Err(e) = p2p.run_server().await {
                error!("QUIC P2P error: {}", e);
            }
        });

        let mut background = Vec::new();
        if self.config.install_signal_handlers {
            let tx = self.shutdown_tx.clone();
            background.push(tokio::spawn(async move {
                wait_for_os_shutdown_signal().await;
                info!("OS shutdown signal received");
                let _ = tx.send(true);
            }));
        }
        if self.config.exit_with_parent {
            if let Some(task) = spawn_parent_watchdog(self.shutdown_tx.clone()) {
                background.push(task);
            }
        }
        if self.config.exit_on_stdin_close {
            spawn_stdin_watchdog(self.shutdown_tx.clone());
        }

        let ready = ReadyInfo {
            pid: std::process::id(),
            version: VERSION.to_string(),
            device_id: self.device_id.clone(),
            device_name: self.config.device_name.clone(),
            api_addr,
            api_url: format!("http://{api_addr}"),
            p2p_port: self.config.p2p_port,
            started_at: chrono::Utc::now().timestamp_millis(),
        };
        let runtime_path = self.config.home_dir.join(RUNTIME_FILE_NAME);
        match serde_json::to_vec_pretty(&ready) {
            Ok(bytes) => {
                if let Err(e) = write_atomic(&runtime_path, &bytes) {
                    warn!("Unable to write {}: {}", runtime_path.display(), e);
                }
            }
            Err(e) => warn!("Unable to encode runtime info: {}", e),
        }
        let lifecycle = self.sync_engine.lifecycle().clone();
        let _ = lifecycle.transition(EngineLifecycleState::Ready);
        if let Some(cb) = self.on_ready.take() {
            cb(&ready);
        }
        info!("Synapse Core ready at {}", ready.api_url);

        let api_result = api.serve(self.shutdown_rx.clone()).await;

        // Anything other than an explicit restart request is a shutdown.
        let reason = if lifecycle.get() == EngineLifecycleState::Restarting {
            ExitReason::Restart
        } else {
            let _ = lifecycle.transition(EngineLifecycleState::Stopping);
            ExitReason::Shutdown
        };

        for task in background {
            task.abort();
        }
        p2p_handle.abort();
        drop(watchers);
        let _ = std::fs::remove_file(&runtime_path);
        info!("Synapse Core engine stopped.");
        drop(self.lock);

        api_result.map(|()| reason)
    }
}

/// Polls the parent PID; when it changes the parent has died and we were re-parented.
///
/// Polling is used instead of `PR_SET_PDEATHSIG` because that signal fires when the
/// *thread* that forked us exits, which on the JVM is an arbitrary pool thread.
#[cfg(unix)]
fn spawn_parent_watchdog(tx: watch::Sender<bool>) -> Option<tokio::task::JoinHandle<()>> {
    let original = std::os::unix::process::parent_id();
    if original <= 1 {
        warn!("--exit-with-parent: already orphaned (ppid={original}); watchdog disabled");
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            if std::os::unix::process::parent_id() != original {
                warn!("Parent process {original} exited; shutting down");
                let _ = tx.send(true);
                return;
            }
        }
    }))
}

#[cfg(not(unix))]
fn spawn_parent_watchdog(_tx: watch::Sender<bool>) -> Option<tokio::task::JoinHandle<()>> {
    warn!("--exit-with-parent is not supported on this platform; use --exit-on-stdin-close");
    None
}

/// Blocks a dedicated OS thread on stdin and requests shutdown at EOF.
fn spawn_stdin_watchdog(tx: watch::Sender<bool>) {
    let spawned = std::thread::Builder::new()
        .name("synapse-stdin-watch".into())
        .spawn(move || {
            use std::io::Read;
            let mut stdin = std::io::stdin().lock();
            let mut buf = [0u8; 256];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            info!("stdin closed by parent; shutting down");
            let _ = tx.send(true);
        });
    if let Err(e) = spawned {
        warn!("Unable to start stdin watchdog: {}", e);
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
