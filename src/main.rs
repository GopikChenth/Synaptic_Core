//! Synapse Core: Standalone Daemon and CLI Entrypoint.
//!
//! Provides CLI execution mechanics for both desktop environments and Android execution
//! via `ProcessBuilder` (when deployed as `jniLibs/<abi>/libsynapse.so`).
//!
//! Exit codes (stable, relied on by the Android/Kotlin launchers):
//!
//! | code | meaning                                             |
//! |------|-----------------------------------------------------|
//! | 0    | clean shutdown                                      |
//! | 1    | unexpected runtime error                            |
//! | 2    | invalid command line (clap)                         |
//! | 3    | configuration error (no home dir, insecure bind...) |
//! | 4    | another instance already owns the home directory    |
//! | 5    | control-plane API port could not be bound           |

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing::{error, info};

use synapse_core::telemetry::{self, LogFormat, LogOptions};
use synapse_core::{ExitReason, StartupError, SynapseConfig, SynapseCore, VERSION};

const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("SYNAPSE_GIT_REV"),
    " ",
    env!("SYNAPSE_BUILD_TARGET"),
    ")"
);

#[derive(Parser, Debug)]
#[command(
    name = "synapse-core",
    author = "Synapse Team",
    version = VERSION,
    long_version = LONG_VERSION,
    about = "Decentralized File Synchronization & 3-Way Conflict Resolution Engine"
)]
struct Cli {
    /// Synapse root home directory for database, quarantine cache, and CAS blocks
    #[arg(short = 'H', long, env = "SYNAPSE_HOME")]
    home: Option<PathBuf>,

    /// Control plane HTTP & WebSocket API bind address
    #[arg(short = 'a', long, default_value = "127.0.0.1")]
    addr: String,

    /// Control plane HTTP & WebSocket API port (0 = pick a free port; see runtime.json)
    #[arg(short = 'p', long, default_value_t = 9090)]
    port: u16,

    /// P2P QUIC transport listening port
    #[arg(long, default_value_t = synapse_core::p2p::DEFAULT_P2P_PORT)]
    p2p_port: u16,

    /// Local UDP discovery broadcast port
    #[arg(long, default_value_t = synapse_core::p2p::DEFAULT_DISCOVERY_PORT)]
    discovery_port: u16,

    /// Security authentication token for API access
    #[arg(long, env = "SYNAPSE_TOKEN")]
    token: Option<String>,

    /// Custom human-readable device name
    #[arg(long, env = "SYNAPSE_DEVICE_NAME")]
    device_name: Option<String>,

    /// Log filter (RUST_LOG syntax), e.g. `info` or `synapse_core=debug,quinn=warn`
    #[arg(long, env = "SYNAPSE_LOG", default_value = "info")]
    log_level: String,

    /// Log line format: text | json
    #[arg(long, env = "SYNAPSE_LOG_FORMAT", default_value = "text")]
    log_format: LogFormat,

    /// Also write daily-rotated log files to this directory
    #[arg(long, env = "SYNAPSE_LOG_DIR")]
    log_dir: Option<PathBuf>,

    /// Number of rotated log files to keep
    #[arg(long, default_value_t = 7)]
    log_max_files: usize,

    /// Do not log to stdout (use with --log-dir when stdout is not drained)
    #[arg(long)]
    quiet: bool,

    /// Exit when the parent process dies (prevents orphaned daemons holding ports)
    #[arg(long, env = "SYNAPSE_EXIT_WITH_PARENT")]
    exit_with_parent: bool,

    /// Exit when stdin is closed (parent keeps the pipe open while it wants us alive)
    #[arg(long)]
    exit_on_stdin_close: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the continuous synchronization daemon (default)
    Run,
    /// Query status of the running Synapse Core daemon
    Status {
        #[arg(short, long, default_value = "http://127.0.0.1:9090")]
        api: String,
    },
    /// Manage synchronized folders
    Folders {
        #[command(subcommand)]
        cmd: FolderCommands,
    },
    /// Inspect or resolve quarantined conflicts
    Conflicts {
        #[command(subcommand)]
        cmd: ConflictCommands,
    },
    /// Manage cluster devices and pending pairing requests
    Devices {
        #[command(subcommand)]
        cmd: DeviceCommands,
    },
    /// Trigger garbage collection of orphaned CAS blocks
    Gc,
}

#[derive(Subcommand, Debug)]
enum FolderCommands {
    /// List all configured folders
    List,
    /// Register a new folder for continuous synchronization
    Add {
        #[arg(short, long)]
        id: String,
        #[arg(short, long)]
        path: PathBuf,
        #[arg(short, long, default_value = "THREE_WAY_AUTO")]
        policy: String,
    },
}

#[derive(Subcommand, Debug)]
enum ConflictCommands {
    /// List all active quarantined conflicts awaiting user action
    List,
    /// Inspect 3-way diff for a conflict
    Diff {
        #[arg(short, long)]
        id: String,
    },
    /// Submit a resolution decision for a conflict
    Resolve {
        #[arg(short, long)]
        id: String,
        /// Resolution choice: ACCEPT_LOCAL, ACCEPT_REMOTE, CUSTOM_MERGE, KEEP_BOTH
        #[arg(short, long)]
        action: String,
    },
}

#[derive(Subcommand, Debug)]
enum DeviceCommands {
    /// Show this device's own ID and identity information
    Id,
    /// List all paired cluster devices
    List,
    /// List incoming pending device pairing requests
    Pending,
    /// Accept a pending device pairing request
    Accept {
        #[arg(short, long)]
        id: String,
    },
    /// Reject a pending device pairing request
    Reject {
        #[arg(short, long)]
        id: String,
    },
    /// Manually pair a remote device by its Device ID
    Add {
        #[arg(short, long)]
        id: String,
        #[arg(short, long)]
        name: String,
        #[arg(short, long, default_value = "dynamic")]
        address: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let is_daemon = matches!(cli.command, None | Some(Commands::Run));

    // Daemon logs go through non-blocking writers (see telemetry docs); one-shot CLI
    // subcommands only log warnings so their tabular output stays clean. The guard
    // lives for the whole process, across engine restarts.
    let _log_guard = match telemetry::init(&LogOptions {
        filter: if is_daemon {
            cli.log_level.clone()
        } else {
            "warn".into()
        },
        format: cli.log_format,
        stdout: !cli.quiet,
        dir: if is_daemon { cli.log_dir.clone() } else { None },
        max_files: cli.log_max_files,
    }) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("synapse-core: {e}");
            return ExitCode::from(3);
        }
    };

    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let outcome = runtime.block_on(real_main(cli));
    drop(runtime);

    match outcome {
        Ok(Outcome::Done) => ExitCode::SUCCESS,
        Ok(Outcome::Daemon(config)) => run_daemon(*config),
        Err(e) => report(e),
    }
}

enum Outcome {
    /// A one-shot subcommand finished.
    Done,
    /// Run the engine with this configuration.
    Daemon(Box<SynapseConfig>),
}

fn build_runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("synapse-worker")
        .build()
        .map_err(|e| {
            eprintln!("synapse-core: cannot start async runtime: {e}");
            ExitCode::from(1)
        })
}

fn report(e: Box<dyn std::error::Error + Send + Sync>) -> ExitCode {
    error!("{e}");
    eprintln!("synapse-core: {e}");
    ExitCode::from(exit_code_for(e.as_ref()))
}

/// Runs engine generations until shutdown.
///
/// Each generation gets its own Tokio runtime. Dropping the runtime cancels every task
/// the generation spawned (discovery loops, QUIC connections, watchers), so a restart
/// can't leak tasks or keep sockets bound. The next generation rebinds the same API
/// address, so clients reconnect to the same URL.
fn run_daemon(mut config: SynapseConfig) -> ExitCode {
    let mut generation: u32 = 1;
    loop {
        let runtime = match build_runtime() {
            Ok(rt) => rt,
            Err(code) => return code,
        };
        let bound = Arc::new(Mutex::new(None::<SocketAddr>));
        let bound_cb = bound.clone();
        let cfg = config.clone();
        let result = runtime.block_on(async move {
            SynapseCore::init(cfg)?
                .on_ready(move |info| {
                    if let Ok(mut b) = bound_cb.lock() {
                        *b = Some(info.api_addr);
                    }
                })
                .run_until_exit()
                .await
        });
        runtime.shutdown_timeout(Duration::from_secs(5));

        match result {
            Ok(ExitReason::Shutdown) => return ExitCode::SUCCESS,
            Ok(ExitReason::Restart) => {
                if let Some(addr) = bound.lock().ok().and_then(|b| *b) {
                    config.api_addr = addr; // keep the same port, even if it was ephemeral
                }
                generation += 1;
                info!("Restarting Synapse Core engine (generation {generation})");
            }
            Err(e) => return report(e),
        }
    }
}

fn exit_code_for(e: &(dyn std::error::Error + 'static)) -> u8 {
    match e.downcast_ref::<StartupError>() {
        Some(StartupError::AlreadyRunning { .. }) => 4,
        Some(StartupError::ApiBind { .. }) => 5,
        Some(StartupError::NoHomeDir | StartupError::InsecureBind { .. }) => 3,
        None => 1,
    }
}

async fn real_main(cli: Cli) -> Result<Outcome, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = SynapseConfig::default();

    if let Some(h) = cli.home {
        config.home_dir = h;
    }
    let ip = cli
        .addr
        .parse()
        .map_err(|_| format!("Invalid API bind address: {}", cli.addr))?;
    config.api_addr = SocketAddr::new(ip, cli.port);
    config.p2p_port = cli.p2p_port;
    config.discovery_port = cli.discovery_port;
    config.exit_with_parent = cli.exit_with_parent;
    config.exit_on_stdin_close = cli.exit_on_stdin_close;
    if let Some(tok) = cli.token {
        config.auth_token = Some(tok);
    }
    if let Some(dev) = cli.device_name {
        config.device_name = dev;
    }

    let needs_home = !matches!(cli.command, Some(Commands::Status { .. }));
    if needs_home {
        if config.home_dir.as_os_str().is_empty() {
            return Err(StartupError::NoHomeDir.into());
        }
        std::fs::create_dir_all(&config.home_dir).map_err(|e| {
            format!(
                "cannot create home directory {}: {e}",
                config.home_dir.display()
            )
        })?;
    }

    match cli.command {
        Some(Commands::Status { api }) => {
            println!("Querying Synapse Core status at {}", api);
            let url = format!("{}/api/v1/system/status", api);
            match reqwest_minimal_get(url, config.auth_token.as_deref()).await {
                Ok(resp) => println!("{}", resp),
                Err(e) => eprintln!("Unable to connect to daemon: {}", e),
            }
            Ok(Outcome::Done)
        }
        Some(Commands::Folders { cmd }) => {
            let storage = synapse_core::storage::StorageEngine::new(&config.home_dir)?;
            match cmd {
                FolderCommands::List => {
                    let folders = storage.list_folders()?;
                    println!(
                        "{:<20} {:<30} {:<15} {:<8}",
                        "FOLDER ID", "LOCAL PATH", "POLICY", "PAUSED"
                    );
                    println!("{:-<75}", "");
                    for f in folders {
                        println!(
                            "{:<20} {:<30} {:<15} {:<8}",
                            f.folder_id, f.local_path, f.conflict_policy, f.is_paused
                        );
                    }
                }
                FolderCommands::Add { id, path, policy } => {
                    synapse_core::state::validate_folder_config(&policy, None, None, None)?;
                    let mut rec = synapse_core::storage::FolderRecord::new(
                        id.clone(),
                        path.to_string_lossy(),
                    );
                    rec.conflict_policy = policy;
                    storage.add_folder(&rec)?;
                    println!(
                        "Successfully registered folder '{}' at '{}'",
                        id, rec.local_path
                    );
                }
            }
            Ok(Outcome::Done)
        }
        Some(Commands::Conflicts { cmd }) => {
            let storage = synapse_core::storage::StorageEngine::new(&config.home_dir)?;
            match cmd {
                ConflictCommands::List => {
                    let list = storage.list_pending_conflicts()?;
                    println!(
                        "{:<15} {:<20} {:<30} {:<10}",
                        "CONFLICT ID", "FOLDER", "PATH", "STATUS"
                    );
                    println!("{:-<75}", "");
                    for c in list {
                        println!(
                            "{:<15} {:<20} {:<30} {:<10}",
                            c.conflict_id, c.folder_id, c.relative_path, c.status
                        );
                    }
                }
                ConflictCommands::Diff { id } => {
                    if let Some(c) = storage.get_conflict(&id)? {
                        println!("Conflict: {}", c.conflict_id);
                        println!("Path: {}/{}", c.folder_id, c.relative_path);
                        println!("Local Rev: {}", c.local_revision);
                        println!("Remote Rev: {}", c.remote_revision);
                        println!("Base Rev: {:?}", c.base_revision);
                        println!("Quarantined Payload: {}", c.staged_payload_path);
                    } else {
                        eprintln!("Conflict '{}' not found", id);
                    }
                }
                ConflictCommands::Resolve { id, action } => {
                    let act = match action.to_uppercase().as_str() {
                        "ACCEPT_LOCAL" => synapse_core::conflict::ResolveAction::AcceptLocal,
                        "ACCEPT_REMOTE" => synapse_core::conflict::ResolveAction::AcceptRemote,
                        "CUSTOM_MERGE" => synapse_core::conflict::ResolveAction::CustomMerge,
                        "KEEP_BOTH" => synapse_core::conflict::ResolveAction::KeepBoth,
                        other => {
                            eprintln!("Unknown action: {}. Expected ACCEPT_LOCAL, ACCEPT_REMOTE, CUSTOM_MERGE, or KEEP_BOTH", other);
                            return Ok(Outcome::Done);
                        }
                    };
                    let (tx, _) = tokio::sync::broadcast::channel(10);
                    let engine =
                        synapse_core::conflict::ConflictEngine::new(storage, tx, "cli".into());
                    engine.resolve(
                        &id,
                        &synapse_core::conflict::ResolveRequest {
                            action: act,
                            merged_content: None,
                        },
                    )?;
                    println!("Conflict '{}' successfully resolved.", id);
                }
            }
            Ok(Outcome::Done)
        }
        Some(Commands::Devices { cmd }) => {
            let storage = synapse_core::storage::StorageEngine::new(&config.home_dir)?;
            match cmd {
                DeviceCommands::Id => {
                    let identity =
                        synapse_core::p2p::NodeIdentity::load_or_generate(&config.home_dir)?;
                    println!("Device Name:         {}", config.device_name);
                    println!("Device ID:           {}", identity.formatted_id);
                    println!("Raw Key Fingerprint: {}", identity.device_id);
                }
                DeviceCommands::List => {
                    let list = storage.list_devices()?;
                    if list.is_empty() {
                        println!("No paired devices configured.");
                    } else {
                        println!(
                            "{:<35} {:<20} {:<10} {:<10}",
                            "DEVICE ID", "NAME", "PAUSED", "TRUSTED"
                        );
                        println!("{:-<80}", "");
                        for d in list {
                            println!(
                                "{:<35} {:<20} {:<10} {:<10}",
                                d.device_id, d.name, d.is_paused, d.is_trusted
                            );
                        }
                    }
                }
                DeviceCommands::Pending => {
                    let list = storage.list_pending_devices()?;
                    if list.is_empty() {
                        println!("No pending device pairing requests.");
                    } else {
                        println!("{:<35} {:<20} {:<25}", "DEVICE ID", "NAME", "ADDRESS");
                        println!("{:-<85}", "");
                        for d in list {
                            println!("{:<35} {:<20} {:<25}", d.device_id, d.name, d.address);
                        }
                        println!(
                            "\nTo accept a device: synapse-core devices accept --id <DEVICE_ID>"
                        );
                    }
                }
                DeviceCommands::Accept { id } => {
                    storage.accept_pending_device(&id)?;
                    println!("Successfully accepted and paired device: {}", id);
                }
                DeviceCommands::Reject { id } => {
                    storage.reject_pending_device(&id)?;
                    println!("Rejected pending device: {}", id);
                }
                DeviceCommands::Add { id, name, address } => {
                    let dev = synapse_core::storage::DeviceRecord {
                        device_id: id.clone(),
                        name,
                        addresses: vec![address],
                        is_paused: false,
                        is_trusted: true,
                        introducer: false,
                        cert_name: None,
                        created_at: chrono::Utc::now().timestamp(),
                    };
                    storage.add_device(&dev)?;
                    println!("Successfully added and paired device: {}", id);
                }
            }
            Ok(Outcome::Done)
        }
        Some(Commands::Gc) => {
            let storage = synapse_core::storage::StorageEngine::new(&config.home_dir)?;
            let _ = storage.rebuild_chunk_ref_counts();
            let collected = storage.garbage_collect_orphaned_chunks()?;
            println!(
                "CAS Garbage Collection complete. Removed {} orphaned chunk(s).",
                collected
            );
            Ok(Outcome::Done)
        }
        Some(Commands::Run) | None => {
            info!(
                "Synapse Core v{VERSION} starting (pid {})",
                std::process::id()
            );
            info!("Home Directory: {}", config.home_dir.display());
            info!("API Address:    http://{}", config.api_addr);
            info!("P2P Port:       {}", config.p2p_port);
            info!("Discovery Port: {}", config.discovery_port);

            Ok(Outcome::Daemon(Box::new(config)))
        }
    }
}

async fn reqwest_minimal_get(
    url: String,
    token: Option<&str>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let parsed = url.strip_prefix("http://").unwrap_or(&url);
    let mut parts = parsed.split('/');
    let host_port = parts.next().unwrap_or("127.0.0.1:9090");
    let path = format!("/{}", parts.collect::<Vec<_>>().join("/"));

    let stream = tokio::net::TcpStream::connect(host_port).await?;
    let (mut rd, mut wr) = tokio::io::split(stream);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let auth_header = match token {
        Some(t) => format!("Authorization: Bearer {}\r\n", t),
        None => String::new(),
    };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
        path, host_port, auth_header
    );
    wr.write_all(req.as_bytes()).await?;

    let mut response = String::new();
    rd.read_to_string(&mut response).await?;

    if let Some(pos) = response.find("\r\n\r\n") {
        Ok(response[pos + 4..].to_string())
    } else {
        Ok(response)
    }
}
