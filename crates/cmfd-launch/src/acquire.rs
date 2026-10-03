//! Bounded, cancellable acquisition of the single release-pinned launch beacon.
//! Transport is untrusted. Only a cryptographically verified certificate is
//! published, using no-overwrite publication in the runtime package directory.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use thiserror::Error;

use crate::{
    AuthenticatedLaunch, BeaconCertificate, LaunchError, MAINNET_BEACON_ROUND,
    MAINNET_LAUNCH_UNIX_SECONDS, MAINNET_LAUNCH_UTC, MAX_BEACON_DOCUMENT_BYTES, QUICKNET_BEACON_ID,
    SOURCE_RELEASE_UTC, parse_certificate, verify_mainnet_launch,
};

const MAX_RUNTIME_INFO_BYTES: usize = 128 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(12);
const RELAYS: [&str; 3] = [
    "https://api.drand.sh",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
];

#[derive(Debug, Error)]
pub enum AcquireError {
    #[error("launch preparation was cancelled")]
    Cancelled,
    #[error("runtime path must be absolute and point to the packaged node or miner")]
    RuntimePath,
    #[error("the runtime did not report a valid pinned mainnet launch identity")]
    RuntimeIdentity,
    #[error("launch helper process could not start or finish")]
    Process(#[source] io::Error),
    #[error("launch helper process failed")]
    ProcessFailed,
    #[error("launch helper process exceeded its time limit")]
    Timeout,
    #[error("launch response exceeded its byte limit")]
    Oversized,
    #[error("existing launch beacon failed verification; the file has been preserved")]
    InvalidExisting,
    #[error(
        "none of the relays returned the valid pinned launch round; retry when it is available"
    )]
    Unavailable,
    #[error("mainnet opens at 2026-10-03T17:00:00Z (noon US Central); use --wait to stay ready")]
    BeforeLaunch,
    #[error("launch beacon publication failed")]
    Publication(#[source] io::Error),
    #[error("system time is before the Unix epoch")]
    Clock,
}

fn stopped(cancel: &AtomicBool) -> Result<(), AcquireError> {
    if cancel.load(Ordering::Acquire) {
        Err(AcquireError::Cancelled)
    } else {
        Ok(())
    }
}

fn unix_time() -> Result<u64, AcquireError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AcquireError::Clock)?
        .as_secs())
}

/// Executes trusted local binaries without a shell. Output is bounded even if
/// the child lies about its length; cancellation/timeout kills the exact child.
fn bounded_output(
    command: &mut Command,
    limit: usize,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, AcquireError> {
    stopped(cancel)?;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW for desktop callers.
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(AcquireError::Process)?;
    let stdout = child.stdout.take().expect("stdout was configured as piped");
    let reader = match thread::Builder::new()
        .name("cmfd-launch-response".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take((limit + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        }) {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AcquireError::Process(error));
        }
    };
    let start = Instant::now();
    let outcome = loop {
        if cancel.load(Ordering::Acquire) {
            break Err(AcquireError::Cancelled);
        }
        if start.elapsed() >= timeout {
            break Err(AcquireError::Timeout);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break if status.success() {
                    Ok(())
                } else {
                    Err(AcquireError::ProcessFailed)
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(error) => break Err(AcquireError::Process(error)),
        }
    };
    if outcome.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    // The fixed curl/runtime commands do not spawn children inheriting stdout.
    let output = reader
        .join()
        .map_err(|_| AcquireError::ProcessFailed)?
        .map_err(AcquireError::Process)?;
    outcome?;
    if output.len() > limit {
        return Err(AcquireError::Oversized);
    }
    Ok(output)
}

fn runtime_plan_digest(bytes: &[u8]) -> Result<[u8; 32], AcquireError> {
    if bytes.len() > MAX_RUNTIME_INFO_BYTES {
        return Err(AcquireError::Oversized);
    }
    let info: Value = serde_json::from_slice(bytes).map_err(|_| AcquireError::RuntimeIdentity)?;
    if info["format"] != "commonfoundry-mainnet-launch-info"
        || info["format_version"] != 1
        || info["source_release_utc"] != SOURCE_RELEASE_UTC
        || info["mining_start_utc"] != MAINNET_LAUNCH_UTC
        || info["genesis_policy"] != "requires_verified_launch_beacon"
        || info["beacon_round"] != MAINNET_BEACON_ROUND
    {
        return Err(AcquireError::RuntimeIdentity);
    }
    let digest = info["launch_plan"]["launch_plan_digest"]
        .as_str()
        .ok_or(AcquireError::RuntimeIdentity)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AcquireError::RuntimeIdentity);
    }
    let digest: [u8; 32] = hex::decode(digest)
        .map_err(|_| AcquireError::RuntimeIdentity)?
        .try_into()
        .map_err(|_| AcquireError::RuntimeIdentity)?;
    if digest == [0; 32] {
        return Err(AcquireError::RuntimeIdentity);
    }
    Ok(digest)
}

fn read_existing(
    output: &Path,
    verify: &impl Fn(&BeaconCertificate) -> Result<AuthenticatedLaunch, LaunchError>,
) -> Result<Option<BeaconCertificate>, AcquireError> {
    let file = match File::open(output) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AcquireError::InvalidExisting),
    };
    let metadata = file.metadata().map_err(|_| AcquireError::InvalidExisting)?;
    if !metadata.is_file() || metadata.len() > MAX_BEACON_DOCUMENT_BYTES as u64 {
        return Err(AcquireError::InvalidExisting);
    }
    let mut bytes = Vec::new();
    file.take((MAX_BEACON_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| AcquireError::InvalidExisting)?;
    let certificate = parse_certificate(&bytes).map_err(|_| AcquireError::InvalidExisting)?;
    verify(&certificate).map_err(|_| AcquireError::InvalidExisting)?;
    Ok(Some(certificate))
}

fn publish(
    output: &Path,
    certificate: &BeaconCertificate,
    cancel: &AtomicBool,
    verify: &impl Fn(&BeaconCertificate) -> Result<AuthenticatedLaunch, LaunchError>,
) -> Result<(), AcquireError> {
    verify(certificate).map_err(|_| AcquireError::Unavailable)?;
    stopped(cancel)?;
    let parent = output.parent().ok_or(AcquireError::RuntimePath)?;
    let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(AcquireError::Publication)?;
    let mut bytes = serde_json::to_vec(certificate).map_err(|_| AcquireError::Unavailable)?;
    bytes.push(b'\n');
    staged
        .write_all(&bytes)
        .map_err(AcquireError::Publication)?;
    staged
        .as_file()
        .sync_all()
        .map_err(AcquireError::Publication)?;
    stopped(cancel)?;
    match staged.persist_noclobber(output) {
        Ok(file) => {
            file.sync_all().map_err(AcquireError::Publication)?;
        }
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            if read_existing(output, verify)?.as_ref() != Some(certificate) {
                return Err(AcquireError::InvalidExisting);
            }
        }
        Err(error) => return Err(AcquireError::Publication(error.error)),
    }
    if read_existing(output, verify)?.as_ref() != Some(certificate) {
        return Err(AcquireError::InvalidExisting);
    }
    Ok(())
}

fn relay_url(relay: &str) -> String {
    format!("{relay}/v2/beacons/{QUICKNET_BEACON_ID}/rounds/{MAINNET_BEACON_ROUND}")
}

fn curl(url: &str, cancel: &AtomicBool) -> Result<Vec<u8>, AcquireError> {
    #[cfg(windows)]
    let program = PathBuf::from(std::env::var_os("SystemRoot").ok_or(AcquireError::RuntimePath)?)
        .join("System32/curl.exe");
    #[cfg(not(windows))]
    let program = PathBuf::from("/usr/bin/curl");
    // Disable curlrc, redirects, user-supplied URLs, plaintext protocols and
    // unlimited transfers. The read cap is independent of curl's size checks.
    bounded_output(
        Command::new(program).args([
            "--disable",
            "--silent",
            "--fail",
            "--proto",
            "=https",
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            "--max-filesize",
            "4096",
            url,
        ]),
        MAX_BEACON_DOCUMENT_BYTES,
        PROCESS_TIMEOUT,
        cancel,
    )
}

fn try_relays(
    output: &Path,
    cancel: &AtomicBool,
    mut transport: impl FnMut(&str) -> Result<Vec<u8>, AcquireError>,
    verify: &impl Fn(&BeaconCertificate) -> Result<AuthenticatedLaunch, LaunchError>,
) -> Result<(), AcquireError> {
    if read_existing(output, verify)?.is_some() {
        return Ok(());
    }
    for relay in RELAYS {
        stopped(cancel)?;
        let bytes = match transport(&relay_url(relay)) {
            Ok(bytes) => bytes,
            Err(AcquireError::Cancelled) => return Err(AcquireError::Cancelled),
            Err(_) => continue,
        };
        let certificate = match parse_certificate(&bytes) {
            Ok(certificate) if verify(&certificate).is_ok() => certificate,
            _ => continue,
        };
        return publish(output, &certificate, cancel, verify);
    }
    Err(AcquireError::Unavailable)
}

fn wait_for(duration: Duration, cancel: &AtomicBool) -> Result<(), AcquireError> {
    let start = Instant::now();
    while start.elapsed() < duration {
        stopped(cancel)?;
        thread::sleep(Duration::from_millis(100).min(duration.saturating_sub(start.elapsed())));
    }
    stopped(cancel)
}

/// `runtime` is the packaged node or miner. Its pre-launch command validates
/// the plan against its compiled release pin before the helper contacts relays.
pub fn acquire_for_runtime(
    runtime: &Path,
    wait: bool,
    cancel: &AtomicBool,
) -> Result<PathBuf, AcquireError> {
    if !runtime.is_absolute() || !runtime.is_file() {
        return Err(AcquireError::RuntimePath);
    }
    let info = bounded_output(
        Command::new(runtime).arg("mainnet-launch-info"),
        MAX_RUNTIME_INFO_BYTES,
        PROCESS_TIMEOUT,
        cancel,
    )?;
    acquire_for_package(
        runtime.parent().ok_or(AcquireError::RuntimePath)?,
        &info,
        wait,
        cancel,
    )
}

/// Desktop entry point using identity already authenticated by its own compiled
/// node library. This helper never grants startup authority: the runtime still
/// independently validates its pinned plan and certificate before opening a node.
pub fn acquire_for_package(
    package_directory: &Path,
    runtime_identity: &[u8],
    wait: bool,
    cancel: &AtomicBool,
) -> Result<PathBuf, AcquireError> {
    if !package_directory.is_absolute() || !package_directory.is_dir() {
        return Err(AcquireError::RuntimePath);
    }
    let root = runtime_plan_digest(runtime_identity)?;
    let output = package_directory.join("production-mainnet/LAUNCH-BEACON.json");
    let mut last_notice: Option<Instant> = None;
    loop {
        stopped(cancel)?;
        let now = unix_time()?;
        if now < MAINNET_LAUNCH_UNIX_SECONDS {
            if !wait {
                return Err(AcquireError::BeforeLaunch);
            }
            if last_notice.is_none_or(|last| last.elapsed() >= Duration::from_secs(60)) {
                eprintln!(
                    "Waiting for mainnet: October 3 at noon US Central (17:00 UTC). Ctrl+C stops this launcher."
                );
                last_notice = Some(Instant::now());
            }
            wait_for(Duration::from_secs(1), cancel)?;
            continue;
        }
        let verify =
            |certificate: &BeaconCertificate| verify_mainnet_launch(root, certificate, now);
        match try_relays(&output, cancel, |url| curl(url, cancel), &verify) {
            Ok(()) => return Ok(output),
            Err(AcquireError::Unavailable) if wait => {
                if last_notice.is_none_or(|last| last.elapsed() >= Duration::from_secs(30)) {
                    eprintln!(
                        "Waiting for verified launch round {MAINNET_BEACON_ROUND}; retrying the same round."
                    );
                    last_notice = Some(Instant::now());
                }
                wait_for(Duration::from_secs(5), cancel)?;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests;
