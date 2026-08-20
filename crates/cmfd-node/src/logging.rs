//! Shared `tracing` setup for the standalone `cmfd-node` CLI and the node
//! embedded inside the Tauri wallet, so both present the same verbosity
//! behavior for the same `-v` count.
//!
//! Two output layers are installed:
//! - a console layer, filtered by `verbosity` (or an env var override); and
//! - a file layer under `<data_dir>/logs`, always at debug level regardless
//!   of console verbosity, so unattended failures are still captured.

use std::path::Path;

/// Re-exported so callers (the CLI and the wallet) can hold the guard without
/// taking a direct dependency on `tracing-appender` themselves.
pub use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Env vars honored for a per-module filter override (`cmfd_node::p2p=trace`),
/// checked in this order ahead of the `-v` count.
const LOG_ENV_VARS: [&str; 2] = ["CMFD_LOG", "RUST_LOG"];

/// File log lines are always emitted at debug level or above, independent of
/// the console verbosity, so a failure that happens unattended is still on
/// disk afterward.
const FILE_LOG_LEVEL: &str = "debug";

/// Installs the global `tracing` subscriber. `verbosity` is a `-v` count: 0 =
/// silent (nothing currently logs at error level, so this preserves the
/// historical no-flag console behavior), 1 = warn, 2 = info, 3 = debug, 4+ =
/// trace; an env var override in [`LOG_ENV_VARS`] takes precedence over the
/// count.
///
/// Returns the file writer's guard. It must be kept alive for the life of the
/// process (bind it with `let _guard = ...` in `main`) — dropping it early
/// stops the non-blocking writer from flushing buffered lines to disk.
///
/// Safe to call more than once per process (e.g. from tests); later calls are
/// silently ignored if a subscriber is already installed.
pub fn init_tracing(data_dir: &Path, verbosity: u8) -> WorkerGuard {
    let console_filter = env_filter_override().unwrap_or_else(|| level_filter(verbosity));

    let log_dir = data_dir.join("logs");
    let file_appender = tracing_appender::rolling::daily(&log_dir, "cmfd-node.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_filter(console_filter);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_ansi(false)
        .with_writer(non_blocking)
        .with_filter(EnvFilter::new(FILE_LOG_LEVEL));

    let _ = tracing_subscriber::registry()
        .with(console_layer)
        .with(file_layer)
        .try_init();

    guard
}

fn env_filter_override() -> Option<EnvFilter> {
    LOG_ENV_VARS
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .map(EnvFilter::new)
}

fn level_filter(verbosity: u8) -> EnvFilter {
    let level = match verbosity {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    EnvFilter::new(level)
}
