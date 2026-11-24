//! Logging setup shared by the CLI daemon and the embedded (JNI / C ABI) entrypoints.
//!
//! Design constraints that come from running as a child process on Android:
//!
//! * **Never block the engine on log I/O.** When an app spawns the daemon with
//!   `ProcessBuilder` and does not drain stdout, the 64 KiB pipe buffer fills and every
//!   synchronous `write(2)` blocks. With a synchronous subscriber that freezes Tokio
//!   worker threads one by one until the whole daemon hangs. All sinks therefore go
//!   through [`tracing_appender::non_blocking`], which drops lines instead of stalling.
//! * **No ANSI escapes unless attached to a real terminal.** Escape codes make logcat,
//!   log files and CI output unreadable.
//! * **Durable logs on mobile.** `--log-dir` writes daily-rotated files with bounded
//!   retention so field issues can be diagnosed without adb.

use std::io::IsTerminal;
use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};

/// Output encoding for log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable single-line text.
    #[default]
    Text,
    /// One JSON object per line (for log shippers / structured ingestion).
    Json,
}

impl std::str::FromStr for LogFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "text" | "pretty" | "plain" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!("unknown log format '{other}' (expected text|json)")),
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone)]
pub struct LogOptions {
    /// `EnvFilter` directive, e.g. `info` or `synapse_core=debug,quinn=warn`.
    /// `RUST_LOG` takes precedence when set.
    pub filter: String,
    pub format: LogFormat,
    /// Emit to stdout. Disable for embedded use where stdout is `/dev/null`.
    pub stdout: bool,
    /// Directory for daily-rotated log files (`synapse.YYYY-MM-DD.log`).
    pub dir: Option<PathBuf>,
    /// Number of rotated files to retain.
    pub max_files: usize,
}

impl Default for LogOptions {
    fn default() -> Self {
        Self {
            filter: "info".into(),
            format: LogFormat::Text,
            stdout: true,
            dir: None,
            max_files: 7,
        }
    }
}

/// Keeps background log writer threads alive; flushes buffered lines on drop.
#[must_use = "dropping the guard stops log delivery"]
pub struct LogGuard {
    _guards: Vec<WorkerGuard>,
}

/// Installs the global subscriber.
///
/// Returns `Ok(None)` when a global subscriber already exists (e.g. installed by an
/// embedding application): logging keeps working through that one.
pub fn init(
    opts: &LogOptions,
) -> Result<Option<LogGuard>, Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&opts.filter))
        .map_err(|e| format!("invalid log filter '{}': {e}", opts.filter))?;

    let mut guards = Vec::new();
    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = Vec::new();

    if opts.stdout {
        let ansi = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
        guards.push(guard);
        layers.push(make_layer(opts.format, writer, ansi));
    }

    if let Some(dir) = &opts.dir {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create log directory {}: {e}", dir.display()))?;
        let appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("synapse")
            .filename_suffix("log")
            .max_log_files(opts.max_files.max(1))
            .build(dir)
            .map_err(|e| format!("cannot open log file in {}: {e}", dir.display()))?;
        let (writer, guard) = tracing_appender::non_blocking(appender);
        guards.push(guard);
        layers.push(make_layer(opts.format, writer, false));
    }

    let installed = tracing_subscriber::registry()
        .with(layers.with_filter(filter))
        .try_init()
        .is_ok();

    Ok(installed.then_some(LogGuard { _guards: guards }))
}

fn make_layer<W>(format: LogFormat, writer: W, ansi: bool) -> Box<dyn Layer<Registry> + Send + Sync>
where
    W: for<'w> fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    match format {
        LogFormat::Text => fmt::layer()
            .with_writer(writer)
            .with_ansi(ansi)
            .with_target(false)
            .boxed(),
        LogFormat::Json => fmt::layer()
            .json()
            .with_writer(writer)
            .with_current_span(false)
            .flatten_event(true)
            .boxed(),
    }
}
