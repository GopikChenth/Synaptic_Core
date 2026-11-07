//! Synapse Core: Standalone Daemon and CLI Entrypoint.
//!
//! Provides CLI execution mechanics for both desktop environments and Android execution
//! via `ProcessBuilder` (when deployed as `libsynapse.so`).

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use synapse_core::{SynapseConfig, SynapseCore};

#[derive(Parser, Debug)]
#[command(
    name = "synapse-core",
    author = "Synapse Team",
    version = "1.0.0",
    about = "Decentralized File Synchronization & 3-Way Conflict Resolution Engine"
)]
struct Cli {
    /// Synapse root home directory for database, quarantine cache, and CAS blocks
    #[arg(short = 'H', long, env = "SYNAPSE_HOME")]
    home: Option<PathBuf>,

    /// Optional configuration file path
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,

    /// Control plane HTTP & WebSocket API bind address
    #[arg(short = 'a', long, default_value = "127.0.0.1")]
    addr: String,

    /// Control plane HTTP & WebSocket API port
    #[arg(short = 'p', long, default_value_t = 9090)]
    port: u16,

    /// P2P QUIC transport listening port
    #[arg(long, default_value_t = 9190)]
    p2p_port: u16,

    /// Local UDP discovery broadcast port
    #[arg(long, default_value_t = 21027)]
    discovery_port: u16,

    /// Security authentication token for API access
    #[arg(long, env = "SYNAPSE_TOKEN")]
    token: Option<String>,

    /// Custom human-readable device name
    #[arg(long)]
    device_name: Option<String>,

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let cli = Cli::parse();

    let mut config = SynapseConfig::default();

    if let Some(h) = cli.home {
        config.home_dir = h;
    }
    let ip = cli.addr.parse().unwrap_or([127, 0, 0, 1].into());
    config.api_addr = SocketAddr::new(ip, cli.port);
    config.p2p_port = cli.p2p_port;
    config.discovery_port = cli.discovery_port;
    if let Some(tok) = cli.token {
        config.auth_token = Some(tok);
    }
    if let Some(dev) = cli.device_name {
        config.device_name = dev;
    }

    match cli.command {
        Some(Commands::Status { api }) => {
            println!("Querying Synapse Core status at {}", api);
            // Quick client query
            match reqwest_check(&api).await {
                Ok(resp) => println!("{}", resp),
                Err(e) => eprintln!("Unable to connect to daemon: {}", e),
            }
            Ok(())
        }
        Some(Commands::Folders { cmd }) => {
            let storage = synapse_core::storage::StorageEngine::new(&config.home_dir)?;
            match cmd {
                FolderCommands::List => {
                    let folders = storage.list_folders()?;
                    println!("{:<20} {:<30} {:<15} {:<8}", "FOLDER ID", "LOCAL PATH", "POLICY", "PAUSED");
                    println!("{:-<75}", "");
                    for f in folders {
                        println!("{:<20} {:<30} {:<15} {:<8}", f.folder_id, f.local_path, f.conflict_policy, f.is_paused);
                    }
                }
                FolderCommands::Add { id, path, policy } => {
                    let mut rec = synapse_core::storage::FolderRecord::new(id.clone(), path.to_string_lossy());
                    rec.conflict_policy = policy;
                    storage.add_folder(&rec)?;
                    println!("Successfully registered folder '{}' at '{}'", id, rec.local_path);
                }
            }
            Ok(())
        }
        Some(Commands::Conflicts { cmd }) => {
            let storage = synapse_core::storage::StorageEngine::new(&config.home_dir)?;
            match cmd {
                ConflictCommands::List => {
                    let list = storage.list_pending_conflicts()?;
                    println!("{:<15} {:<20} {:<30} {:<10}", "CONFLICT ID", "FOLDER", "PATH", "STATUS");
                    println!("{:-<75}", "");
                    for c in list {
                        println!("{:<15} {:<20} {:<30} {:<10}", c.conflict_id, c.folder_id, c.relative_path, c.status);
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
                            return Ok(());
                        }
                    };
                    let (tx, _) = tokio::sync::broadcast::channel(10);
                    let engine = synapse_core::conflict::ConflictEngine::new(storage, tx, "cli".into());
                    engine.resolve(&id, &synapse_core::conflict::ResolveRequest {
                        action: act,
                        merged_content: None,
                    })?;
                    println!("Conflict '{}' successfully resolved.", id);
                }
            }
            Ok(())
        }
        Some(Commands::Run) | None => {
            info!("Synapse Core v1.0.0 starting...");
            info!("Home Directory: {}", config.home_dir.display());
            info!("API Address:    http://{}", config.api_addr);
            info!("P2P Port:       {}", config.p2p_port);
            info!("Discovery Port: {}", config.discovery_port);

            let core = SynapseCore::init(config)?;

            tokio::select! {
                res = core.run() => {
                    if let Err(e) = res {
                        error!("Synapse Core exited with error: {}", e);
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received shutdown signal. Stopping Synapse Core gracefully...");
                }
            }

            Ok(())
        }
    }
}

async fn reqwest_check(url: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest_minimal_get(format!("{}/api/v1/system/status", url)).await?;
    Ok(client)
}

async fn reqwest_minimal_get(url: String) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let parsed = url.strip_prefix("http://").unwrap_or(&url);
    let mut parts = parsed.split('/');
    let host_port = parts.next().unwrap_or("127.0.0.1:9090");
    let path = format!("/{}", parts.collect::<Vec<_>>().join("/"));

    let stream = tokio::net::TcpStream::connect(host_port).await?;
    let (mut rd, mut wr) = tokio::io::split(stream);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host_port);
    wr.write_all(req.as_bytes()).await?;

    let mut response = String::new();
    rd.read_to_string(&mut response).await?;

    if let Some(pos) = response.find("\r\n\r\n") {
        Ok(response[pos + 4..].to_string())
    } else {
        Ok(response)
    }
}
