//! Forwarding at launch (UPDATER-DESIGN.md section 2.8, as trimmed by
//! TRIMMED-SCOPE.md: no soak, no policy file, basic fallback only).
//!
//! The wallet exe a launcher starts (START-WALLET.bat, a shortcut, a custom
//! .bat with `--data-dir`) hands the launch to the newest good version the
//! updater installed beside it. This runs before argument parsing and before
//! Tauri, on the raw argv, so a flag only a newer version knows still reaches
//! it untouched.
//!
//! - **Skipped** when any argument is exactly `-h`, `--help`, `-V`,
//!   `--version`, `runtime-identity` or `--no-auto-update`, when
//!   `CMFD_NO_AUTO_UPDATE=1`, and when `CMFD_UPDATE_FORWARDED` is set (the
//!   loop guard every forwarded start carries). Non-mainnet builds never
//!   forward.
//! - **Candidates** are the version folders directly in the folder that holds
//!   the running package folder, and in the install root when that differs
//!   (a cloud-synced root, see [`install::install_root`]). A root the
//!   installer would refuse ([`install::check_install_root`]: on Linux one
//!   any user may change, unless it is sticky) is not scanned. A
//!   group-writable root is accepted, as by the installer; there another
//!   member of the group could swap a folder between its check and the
//!   start. A candidate must be
//!   newer than this wallet by its folder name, have a `staged` or
//!   `started_ok` state with fewer than [`MAX_START_ATTEMPTS`] failed starts,
//!   and pass [`install::verify_installed`], which re-checks the release
//!   signature, requires the folder path in this user's install registry
//!   with its package record, and hashes every listed file. So a folder
//!   someone else made runs only if it holds the release's exact files,
//!   and whoever can change files inside a version folder can still do so
//!   after the check, as in the folder the user unpacked by hand. The
//!   version used is the signed one. The highest passing candidate is started. Without a registry dir
//!   ([`install::registry_dir`]) nothing is forwarded.
//! - **Starting** uses the same argv, the inherited working dir and stdio,
//!   and this process's environment without any `CMFD_UPDATE_*` variable
//!   but `CMFD_UPDATE_HANDOFF` and `CMFD_UPDATE_PARENT_PID` (kept as they
//!   are, see [`super::lifecycle::PASSED_ON_ENV`]; a fallback start keeps
//!   only the first, since the closing wallet's id may by then name another
//!   process), plus
//!   `CMFD_UPDATE_FORWARDED=1` and `CMFD_UPDATE_LAUNCHED_FROM` (this
//!   exe). The exe handle `verify_installed`
//!   hashed through is held until the start returned. This process waits and
//!   exits with the child's code.
//! - **Basic fallback.** A child that exits with a non-zero code (or a
//!   signal) before its version is known to work, that is before its state is
//!   `started_ok`, failed to start. The forwarder records the failure in that
//!   version's `state.json` (see [`record_failed_start`]) and runs the next
//!   good candidate, else this wallet, passing what failed and why
//!   ([`Fallback`]). If the failed version had already opened wallet data
//!   (`node_opened`), the fallback says so, and the version that runs instead
//!   must show the error and offer Retry or Run anyway before it opens the
//!   data. That first failure after opening data is the one passed on, even
//!   when a later candidate fails before opening data. A child that could
//!   not be started at all is also passed over, but not counted and nothing
//!   is written, with the after-data mark its state gives: a version that is
//!   `started_ok` or marked `node_opened` (or whose state cannot be read)
//!   had opened the data, so the older version holds. A clean exit (code 0)
//!   is never a failure.
//! - **The hold lasts.** A failure after opening data is kept in the
//!   version's `failure` until the user chooses: "Run anyway" marks it
//!   ([`record_run_anyway`]), "Retry" clears it ([`reset_failed_starts`]).
//!   Until then every launch passes it on to the version that runs, if that
//!   version is older than the failed one, also after the failed one became
//!   `failed` and is no longer started ([`earlier_hold`]). Only folders
//!   this user's updater installed count. A launch that does not forward
//!   (`--no-auto-update`) does not hold.
//! - **A damaged version that opened data holds too.** A candidate that
//!   fails [`install::verify_installed`] (an antivirus quarantine, say) is
//!   passed over as before, but if its state shows it ran (`started_ok`) or
//!   began to open the wallet data (`node_opened`), and the folder is still
//!   this user's install, every older version that runs in this launch
//!   gets a fallback after opening data for it ([`damaged_after_data`]).
//!   Nothing is recorded in that folder, so the hold is found again at
//!   every launch until the folder is reinstalled or removed.
//! - **Refused arguments.** Exit code 2 is the wallet's answer to arguments
//!   it refuses, before it opens anything. It is not counted (the
//!   arguments, not the version, may be the problem), but it is passed over
//!   like a version that could not be started: the next candidate runs,
//!   else this wallet, with the fallback. This wallet then parses the same
//!   arguments itself, so arguments it refuses too still end with exit 2,
//!   and arguments only the newer version refuses (a stricter check, or a
//!   bug in its parser) still open a working wallet that says why. Only
//!   while the version's state shows it never got that far: exit 2 from a
//!   version that is `started_ok` or marked `node_opened` (or whose state
//!   cannot be read) is any other exit, so an older version is never
//!   started on its own on data a newer one opened.
//!
//! **Frozen across versions** (a 1.0.16 forwarder starts every later
//! version, and every later forwarder may start this one):
//! - exit codes: 0 is done; 2 before `started_ok` and `node_opened` is
//!   refused arguments, not counted, passed over; any other code or a
//!   signal before `started_ok` is a failed start;
//! - the environment: `CMFD_UPDATE_FORWARDED` (set to `1`; any value
//!   skips forwarding, and only `1` makes a failed start exit for the
//!   forwarder), `CMFD_UPDATE_LAUNCHED_FROM`, `CMFD_UPDATE_FALLBACK_FROM`,
//!   `_REASON` and `_AFTER_DATA` (`0` or `1`, missing means `1`);
//!   `CMFD_UPDATE_HANDOFF` (`1` on a start "Restart to update" made) and
//!   `CMFD_UPDATE_PARENT_PID` (the process id of the wallet that closed
//!   for it) are passed on unchanged, matched exactly outside Windows, and
//!   every other `CMFD_UPDATE_*` variable is removed on each start.
//!   "Restart to update" starts the exe the user launched
//!   (`CMFD_UPDATE_LAUNCHED_FROM`) again with those two set, so that a
//!   forwarder waits on the new version and can fall back; the new
//!   version waits for that process id, not for its own parent;
//!   `CMFD_NO_AUTO_UPDATE=1` matches exactly;
//! - the `state.json` fields `state`, `start_attempts`, `node_opened`,
//!   `failure` (with `kind`, `reason`, `after_data` and `run_anyway_at`),
//!   `start_failure_reason` and `installed_for`, and the install
//!   registry
//!   ([`install::registry_dir`]).
//!
//! The started version itself marks `started_ok` and `node_opened`
//! ([`record_start_success`], [`record_opening_data`]). Nothing here reads
//! the wallet data dir or `updates.json`: turning "Update automatically" OFF
//! stops downloads, not the switch to a version that is already installed.
//!
//! Deliberate deviation from the design: the working dir is inherited, not
//! set to the target folder. `--wallet-passphrase-file` may be relative, and
//! the wallet finds its package files from its own exe path, not the working
//! dir.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use super::install::{self, InstallState, STATE_FAILED, STATE_STAGED, STATE_STARTED_OK};
use super::lifecycle::{self, PASSED_ON_ENV};
use super::release::{Platform, Version};

/// `CMFD_NO_AUTO_UPDATE=1` works like `--no-auto-update`.
pub(crate) const NO_AUTO_UPDATE_ENV: &str = "CMFD_NO_AUTO_UPDATE";
/// Set on every start the forwarder makes; a wallet that has it never
/// forwards again.
pub(crate) const FORWARDED_ENV: &str = "CMFD_UPDATE_FORWARDED";
/// The wallet exe the user launched (canonical), set on every forwarded
/// start. Cleanup must keep its folder, and "Restart to update" starts this
/// exe again, without any `CMFD_UPDATE_*` variable but the two of
/// [`PASSED_ON_ENV`], so that a forwarder waits on the new version and can
/// fall back.
pub(crate) const LAUNCHED_FROM_ENV: &str = "CMFD_UPDATE_LAUNCHED_FROM";
/// Every variable with this prefix but those of [`PASSED_ON_ENV`] is
/// removed before a forwarded start.
const UPDATE_ENV_PREFIX: &str = "CMFD_UPDATE_";
/// The version that failed to start, when a start is a fallback.
pub(crate) const FALLBACK_FROM_ENV: &str = "CMFD_UPDATE_FALLBACK_FROM";
/// Why it failed, in a few words.
pub(crate) const FALLBACK_REASON_ENV: &str = "CMFD_UPDATE_FALLBACK_REASON";
/// `1` when the failed version had already opened the wallet data.
pub(crate) const FALLBACK_AFTER_DATA_ENV: &str = "CMFD_UPDATE_FALLBACK_AFTER_DATA";

/// Arguments that make a wallet run as itself.
const NOT_FORWARDED_ARGS: [&str; 6] = [
    "-h",
    "--help",
    "-V",
    "--version",
    "runtime-identity",
    "--no-auto-update",
];
/// What a wallet returns when it refuses its arguments (`run()` in lib.rs).
/// Frozen: see the module doc.
const USAGE_EXIT_CODE: i32 = 2;
/// At most this many version folders are checked per launch.
const MAX_CANDIDATES: usize = 64;
/// A version that failed to start this many times is `failed`.
pub(crate) const MAX_START_ATTEMPTS: u64 = 3;
/// `state.json` fields about starts, kept beside the install fields.
pub(crate) const START_ATTEMPTS_FIELD: &str = "start_attempts";
pub(crate) const NODE_OPENED_FIELD: &str = "node_opened";
pub(crate) const FAILURE_FIELD: &str = "failure";
/// In `failure`: when the user chose "Run anyway" for that failure.
pub(crate) const RUN_ANYWAY_AT_FIELD: &str = "run_anyway_at";
/// Why the started version itself found its start failed, written by it
/// right before it exits; the forwarder moves it into `failure`.
pub(crate) const START_FAILURE_REASON_FIELD: &str = "start_failure_reason";
/// In the folder that holds the running package folder.
const LOG_FILE_NAME: &str = ".cmfd-updater.log";
const MAX_LOG_BYTES: u64 = 1024 * 1024;
const MAX_REASON_CHARS: usize = 300;

/// A newer version that failed to start, for the version that runs instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fallback {
    pub(crate) version: Version,
    pub(crate) reason: String,
    /// The failed version had already opened the wallet data.
    pub(crate) after_data: bool,
}

impl Fallback {
    fn env(&self) -> [(OsString, OsString); 3] {
        [
            (FALLBACK_FROM_ENV.into(), self.version.to_string().into()),
            (FALLBACK_REASON_ENV.into(), self.reason.clone().into()),
            (
                FALLBACK_AFTER_DATA_ENV.into(),
                if self.after_data { "1" } else { "0" }.into(),
            ),
        ]
    }

    /// The fallback a forwarder passed to this process, if any.
    pub(crate) fn from_env(env: &[(OsString, OsString)]) -> Option<Self> {
        let version = Version::parse(env_value(env, FALLBACK_FROM_ENV)?.to_str()?)?;
        let reason = env_value(env, FALLBACK_REASON_ENV)
            .map(|reason| {
                reason
                    .to_string_lossy()
                    .chars()
                    .take(MAX_REASON_CHARS)
                    .collect()
            })
            .unwrap_or_default();
        let after_data = env_value(env, FALLBACK_AFTER_DATA_ENV) != Some(OsStr::new("0"));
        Some(Self {
            version,
            reason,
            after_data,
        })
    }
}

/// What the wallet does after the forwarder ran.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Launch {
    /// A newer version ran as a child process; exit with its code.
    Exit(i32),
    /// Run this wallet. With a fallback, the newer version that failed to
    /// start, which the wallet must show.
    RunHere(Option<Fallback>),
}

/// Everything the forwarder reads, so tests can supply it.
pub(crate) struct Context<'a> {
    /// The arguments after the program name.
    pub(crate) args: &'a [OsString],
    pub(crate) env: &'a [(OsString, OsString)],
    /// The running wallet exe.
    pub(crate) exe: &'a Path,
    pub(crate) running: Version,
    pub(crate) platform: Platform,
    pub(crate) network_id: Option<[u8; 32]>,
    /// This user's install registry ([`install::registry_dir`]).
    pub(crate) registry: &'a Path,
    /// The folder that holds the running package folder, then the install
    /// root if it is another folder. The log goes into the last, so it is
    /// beside the versions and never in a cloud-synced root.
    pub(crate) roots: &'a [PathBuf],
}

/// A start of another wallet exe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpawnRequest {
    pub(crate) exe: PathBuf,
    pub(crate) args: Vec<OsString>,
    /// The complete environment of the child.
    pub(crate) env: Vec<(OsString, OsString)>,
}

#[derive(Debug)]
pub(crate) enum SpawnError {
    /// It did not start.
    Start(io::Error),
    /// It started, but waiting for it failed.
    Wait(io::Error),
}

pub(crate) trait Spawn {
    /// Starts `request` with exactly its arguments and environment, the
    /// inherited working dir and stdio; closes `held` once the start
    /// returned; waits for the child. `None` when it ended without an exit
    /// code (killed by a signal).
    fn run(&self, request: &SpawnRequest, held: File) -> Result<Option<i32>, SpawnError>;
}

pub(crate) struct SystemSpawn;

impl Spawn for SystemSpawn {
    fn run(&self, request: &SpawnRequest, held: File) -> Result<Option<i32>, SpawnError> {
        // Not tied to this process: a killed forwarder leaves the wallet it
        // started running.
        let mut child = Command::new(&request.exe)
            .args(&request.args)
            .env_clear()
            .envs(request.env.iter().map(|(key, value)| (key, value)))
            .spawn()
            .map_err(SpawnError::Start)?;
        drop(held);
        let status = child.wait().map_err(SpawnError::Wait)?;
        Ok(status.code())
    }
}

/// The forwarder of a real launch, for the first line of `run()`. A wallet
/// that a forwarder started as a fallback runs here with the fallback that
/// forwarder passed on ([`Fallback::from_env`]).
pub(crate) fn at_launch() -> Launch {
    if !cfg!(feature = "production-mainnet") {
        return Launch::RunHere(None);
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let passed_on = Fallback::from_env(&env);
    let (Some(running), Some(platform)) = (Version::running(), Platform::current()) else {
        return Launch::RunHere(passed_on);
    };
    if !should_forward(&args, &env) {
        return Launch::RunHere(passed_on);
    }
    let Ok(exe) = std::env::current_exe() else {
        return Launch::RunHere(None);
    };
    let Some(registry) = install::registry_dir(&|name| std::env::var_os(name)) else {
        return Launch::RunHere(None);
    };
    let Some(root) = exe.parent().and_then(Path::parent) else {
        return Launch::RunHere(None);
    };
    let mut roots = vec![root.to_path_buf()];
    let iroot = install::install_root(root);
    if iroot != root {
        roots.push(iroot);
    }
    forward(
        &Context {
            args: &args,
            env: &env,
            exe: &exe,
            running,
            platform,
            network_id: cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID,
            registry: &registry,
            roots: &roots,
        },
        &SystemSpawn,
    )
}

pub(crate) fn forward(context: &Context<'_>, spawn: &dyn Spawn) -> Launch {
    if !should_forward(context.args, context.env) {
        return Launch::RunHere(None);
    }
    let candidates = candidates(context);
    let mut hold = earlier_hold(context);
    let Some(log_root) = context
        .roots
        .last()
        .filter(|_| !candidates.is_empty() || hold.is_some())
    else {
        return Launch::RunHere(None);
    };
    let log = |line: &str| log_line(log_root, line);
    if let Some(hold) = &hold {
        log(&format!(
            "{} failed after opening wallet data and nobody chose Run anyway yet: older versions hold",
            hold.version
        ));
    }
    // A version older than the held one gets the hold, unless a failure
    // after opening data in this launch came first.
    let held_below =
        |hold: &Option<Fallback>, fallback: Option<Fallback>, version: Version| match hold {
            Some(hold) if version < hold.version => Some(next_fallback(fallback, hold.clone())),
            _ => fallback,
        };
    let own = context
        .exe
        .parent()
        .and_then(|dir| fs::canonicalize(dir).ok());
    let launched = fs::canonicalize(context.exe).ok();
    let mut fallback: Option<Fallback> = None;
    for dir in candidates {
        if own.is_some() && fs::canonicalize(&dir).ok() == own {
            continue;
        }
        let verified = match install::verify_installed(
            &dir,
            context.platform,
            context.network_id,
            context.registry,
        ) {
            Ok(verified) => verified,
            Err(error) => {
                log(&format!("skipped {}", error.0));
                // A damaged version that had opened the wallet data holds
                // the older ones, as a failed start after opening data does.
                if let Some(damaged) = damaged_after_data(context, &dir, &error) {
                    log(&format!(
                        "{}: its installed files are damaged after it opened wallet data: older versions hold",
                        damaged.version
                    ));
                    if hold
                        .as_ref()
                        .is_none_or(|held| damaged.version > held.version)
                    {
                        hold = Some(damaged);
                    }
                }
                continue;
            }
        };
        let version = verified.version;
        if version <= context.running {
            continue;
        }
        fallback = held_below(&hold, fallback.take(), version);
        let request = SpawnRequest {
            exe: verified.exe_path.clone(),
            args: context.args.to_vec(),
            env: child_env(context.env, fallback.as_ref(), launched.as_deref()),
        };
        log(&format!("starting {version} from {}", dir.display()));
        let code = match spawn.run(&request, verified.exe) {
            Ok(Some(0)) => return Launch::Exit(0),
            Ok(Some(USAGE_EXIT_CODE)) if refused_before_opening(&dir) => {
                let reason = "it refused the launch arguments".to_owned();
                log(&format!("{version}: {reason}"));
                fallback = Some(next_fallback(
                    fallback.take(),
                    Fallback {
                        version,
                        reason,
                        after_data: false,
                    },
                ));
                continue;
            }
            Ok(code) => code,
            Err(SpawnError::Start(error)) => {
                let reason = format!("it could not be started: {error}");
                log(&format!("{version}: {reason}"));
                // The system refused the start (an antivirus, an application
                // control policy, a noexec mount): a version that had opened
                // the data before still holds the older ones.
                let after_data = !refused_before_opening(&dir);
                fallback = Some(next_fallback(
                    fallback.take(),
                    Fallback {
                        version,
                        reason,
                        after_data,
                    },
                ));
                continue;
            }
            Err(SpawnError::Wait(error)) => {
                log(&format!("{version}: cannot wait for it: {error}"));
                return Launch::Exit(1);
            }
        };
        let exit = match code {
            Some(code) => format!("it exited with code {code}"),
            None => "it was ended by a signal".to_owned(),
        };
        match record_failed_start(&dir, &exit) {
            Ended::AfterStarting => {
                log(&format!("{version} ended: {exit}"));
                return Launch::Exit(code.unwrap_or(1));
            }
            Ended::FailedToStart {
                after_data,
                recorded,
                reason,
            } => {
                log(&format!(
                    "{version} failed to start{}: {reason}",
                    if after_data {
                        " after opening wallet data"
                    } else {
                        ""
                    }
                ));
                if let Err(error) = recorded {
                    log(&format!("{version}: cannot record the failure: {error}"));
                }
                fallback = Some(next_fallback(
                    fallback.take(),
                    Fallback {
                        version,
                        reason,
                        after_data,
                    },
                ));
            }
        }
    }
    Launch::RunHere(held_below(&hold, fallback, context.running))
}

/// The hold that a version folder which failed [`install::verify_installed`]
/// gives the older versions: only a folder this user's updater installed
/// (its marker and registry record still pass) whose state says it ran
/// (`started_ok`) or began to open the wallet data (`node_opened`), since
/// that version may have changed the data. A damaged folder that never got
/// that far is only passed over. Nothing is written to the folder, as
/// nothing was started from it; the hold comes back at every launch until
/// the folder is reinstalled or removed.
fn damaged_after_data(
    context: &Context<'_>,
    dir: &Path,
    error: &install::MarkerError,
) -> Option<Fallback> {
    let version = install::folder_version(dir, context.platform)?;
    let state = install::read_state(dir)?;
    let opened = state.state == STATE_STARTED_OK
        || state.extra.get(NODE_OPENED_FIELD).and_then(Value::as_bool) == Some(true);
    if !opened || !install::is_registered_install(dir, context.platform, context.registry) {
        return None;
    }
    let prefix = format!("{}: ", dir.display());
    let why = error.0.strip_prefix(&prefix).unwrap_or(&error.0);
    Some(Fallback {
        version,
        reason: format!("its installed files are damaged: {why}")
            .chars()
            .take(MAX_REASON_CHARS)
            .collect(),
        after_data: true,
    })
}

/// The fallback to pass on after another failure: a failure after opening
/// wallet data is never replaced, so the version that finally runs still
/// holds before it opens the data.
fn next_fallback(previous: Option<Fallback>, failed: Fallback) -> Fallback {
    match previous {
        Some(previous) if previous.after_data => previous,
        _ => failed,
    }
}

fn should_forward(args: &[OsString], env: &[(OsString, OsString)]) -> bool {
    !args.iter().any(|arg| {
        NOT_FORWARDED_ARGS
            .iter()
            .any(|skip| arg == OsStr::new(skip))
    }) && env_value(env, NO_AUTO_UPDATE_ENV) != Some(OsStr::new("1"))
        && env_value(env, FORWARDED_ENV).is_none()
}

/// `CMFD_NO_AUTO_UPDATE=1`, by the same comparison as [`should_forward`],
/// for the updater of the running wallet.
pub(crate) fn no_auto_update_by_environment(env: &[(OsString, OsString)]) -> bool {
    env_value(env, NO_AUTO_UPDATE_ENV) == Some(OsStr::new("1"))
}

/// Whether the environment alone lets this launch forward (tests only).
#[cfg(test)]
pub(crate) fn forward_allowed_by_environment(env: &[(OsString, OsString)]) -> bool {
    should_forward(&[], env)
}

/// Variable names compare without ASCII case, as on Windows. On Linux that
/// only ever skips forwarding or removes an extra variable; the variables
/// passed on match exactly there ([`lifecycle::is_env_name`]).
fn same_name(key: &OsStr, name: &str) -> bool {
    key.to_str()
        .is_some_and(|key| key.eq_ignore_ascii_case(name))
}

pub(crate) fn is_update_variable(key: &OsStr) -> bool {
    let prefix = UPDATE_ENV_PREFIX.as_bytes();
    key.to_str().is_some_and(|key| {
        key.len() >= prefix.len() && key.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix)
    })
}

fn env_value<'a>(env: &'a [(OsString, OsString)], name: &str) -> Option<&'a OsStr> {
    env.iter()
        .find(|(key, _)| same_name(key, name))
        .map(|(_, value)| value.as_os_str())
}

/// The exe a forwarder passed to this process as the one the user
/// launched, if any.
pub(crate) fn launched_from(env: &[(OsString, OsString)]) -> Option<PathBuf> {
    Some(PathBuf::from(env_value(env, LAUNCHED_FROM_ENV)?)).filter(|path| path.is_absolute())
}

fn child_env(
    env: &[(OsString, OsString)],
    fallback: Option<&Fallback>,
    launched: Option<&Path>,
) -> Vec<(OsString, OsString)> {
    let mut child: Vec<(OsString, OsString)> = env
        .iter()
        .filter(|(key, _)| {
            !is_update_variable(key)
                || PASSED_ON_ENV.iter().any(|name| {
                    lifecycle::is_env_name(key, name)
                        && !(fallback.is_some() && *name == lifecycle::HANDOFF_PARENT_PID_ENV)
                })
        })
        .cloned()
        .collect();
    child.push((FORWARDED_ENV.into(), "1".into()));
    if let Some(launched) = launched {
        child.push((LAUNCHED_FROM_ENV.into(), launched.into()));
    }
    if let Some(fallback) = fallback {
        child.extend(fallback.env());
    }
    child
}

/// The version folders worth verifying, highest first: named for a version
/// above the running one, with a state that may be started. The cap counts
/// only those, so leftover failed folders cannot hide an update.
fn candidates(context: &Context<'_>) -> Vec<PathBuf> {
    let mut found = newer_folders(context, &may_start);
    found.truncate(MAX_CANDIDATES);
    found.into_iter().map(|(_, path)| path).collect()
}

/// The version folders in the scanned roots named for a version above the
/// running one whose state passes `keep`, highest first.
fn newer_folders(
    context: &Context<'_>,
    keep: &dyn Fn(&InstallState) -> bool,
) -> Vec<(Version, PathBuf)> {
    let prefix = format!(
        "commonfoundry-mainnet-runtime-{}-v",
        context.platform.name()
    );
    let mut found: Vec<(Version, PathBuf)> = Vec::new();
    for root in context.roots {
        if install::check_install_root(root).is_err() {
            continue;
        }
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix))
            {
                continue;
            }
            let path = entry.path();
            if let Some(version) = install::folder_version(&path, context.platform)
                && version > context.running
                && install::read_state(&path).is_some_and(|state| keep(&state))
            {
                found.push((version, path));
            }
        }
    }
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    found
}

/// The after-data hold of an earlier launch: the highest newer version this
/// user's updater installed whose last failed start came after it had
/// opened the wallet data, with no "Run anyway" chosen for that failure yet
/// ([`unchosen_after_data_failure`]). Every older version that runs holds
/// for it, launch after launch, also once it is `failed` and no longer
/// started, until "Run anyway" ([`record_run_anyway`]) or "Retry"
/// ([`reset_failed_starts`]).
fn earlier_hold(context: &Context<'_>) -> Option<Fallback> {
    newer_folders(context, &|state| {
        unchosen_after_data_failure(state).is_some()
    })
    .into_iter()
    .take(MAX_CANDIDATES)
    .find(|(_, path)| install::is_registered_install(path, context.platform, context.registry))
    .and_then(|(version, path)| {
        let reason = unchosen_after_data_failure(&install::read_state(&path)?)?;
        Some(Fallback {
            version,
            reason,
            after_data: true,
        })
    })
}

/// The reason of a version's failed start after opening the wallet data
/// that still waits for the user's choice: a `failure` of kind `start`
/// with `after_data` and without [`RUN_ANYWAY_AT_FIELD`], on a version not
/// known to work.
pub(crate) fn unchosen_after_data_failure(state: &InstallState) -> Option<String> {
    if state.state == STATE_STARTED_OK {
        return None;
    }
    let failure = state.extra.get(FAILURE_FIELD)?;
    (failure.get("kind").and_then(Value::as_str) == Some("start")
        && failure.get("after_data").and_then(Value::as_bool) == Some(true)
        && failure.get(RUN_ANYWAY_AT_FIELD).is_none())
    .then(|| {
        failure
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(MAX_REASON_CHARS)
            .collect()
    })
}

pub(crate) fn may_start(state: &InstallState) -> bool {
    (state.state == STATE_STAGED || state.state == STATE_STARTED_OK)
        && start_attempts(state) < MAX_START_ATTEMPTS
}

fn start_attempts(state: &InstallState) -> u64 {
    state
        .extra
        .get(START_ATTEMPTS_FIELD)
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// Whether exit code 2 from the version in `dir` means it refused its
/// arguments: its state is readable and shows it neither started nor began
/// to open the wallet data. Otherwise the exit is handled as any other.
fn refused_before_opening(dir: &Path) -> bool {
    install::read_state(dir).is_some_and(|state| {
        state.state != STATE_STARTED_OK
            && state.extra.get(NODE_OPENED_FIELD).and_then(Value::as_bool) != Some(true)
    })
}

/// How a forwarded child that did not exit cleanly ended.
#[derive(Debug)]
enum Ended {
    /// Its version had already been marked `started_ok`.
    AfterStarting,
    /// It failed before its version was known to work. `after_data` when it
    /// had opened (or its state cannot tell whether it had opened) the
    /// wallet data.
    FailedToStart {
        after_data: bool,
        recorded: io::Result<()>,
        /// The exit, after the version's own reason when it gave one.
        reason: String,
    },
}

/// Counts a failed start in the version's `state.json`, with the reason. At
/// [`MAX_START_ATTEMPTS`] the version becomes `failed`, which the forwarder
/// never starts and the updater never installs again on its own.
fn record_failed_start(dir: &Path, exit: &str) -> Ended {
    let Some(mut state) = install::read_state(dir) else {
        return Ended::FailedToStart {
            after_data: true,
            recorded: Err(io::Error::other("its state cannot be read")),
            reason: exit.to_owned(),
        };
    };
    if state.state == STATE_STARTED_OK {
        return Ended::AfterStarting;
    }
    let after_data = state
        .extra
        .get(NODE_OPENED_FIELD)
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reason = match state.extra.remove(START_FAILURE_REASON_FIELD) {
        Some(Value::String(own)) if !own.is_empty() => {
            let own: String = own.chars().take(MAX_REASON_CHARS).collect();
            format!("{own} ({exit})")
        }
        _ => exit.to_owned(),
    };
    let attempts = start_attempts(&state).saturating_add(1);
    state
        .extra
        .insert(START_ATTEMPTS_FIELD.into(), attempts.into());
    state.extra.insert(
        FAILURE_FIELD.into(),
        json!({
            "kind": "start",
            "reason": &reason,
            "after_data": after_data,
            "at": unix_now(),
        }),
    );
    if attempts >= MAX_START_ATTEMPTS {
        state.state = STATE_FAILED.into();
    }
    Ended::FailedToStart {
        after_data,
        recorded: install::write_state(dir, &state),
        reason,
    }
}

/// For the started version, right before it exits after a failed start:
/// why, for the forwarder's record and the version that runs instead.
pub(crate) fn record_start_failure_reason(dir: &Path, reason: &str) -> io::Result<()> {
    let mut state =
        install::read_state(dir).ok_or_else(|| io::Error::other("no readable state"))?;
    let reason: String = reason.chars().take(MAX_REASON_CHARS).collect();
    state
        .extra
        .insert(START_FAILURE_REASON_FIELD.into(), reason.into());
    install::write_state(dir, &state)
}

/// For "Run anyway" in the older version that held: the user chose to open
/// the wallet data although this version failed after opening them, so
/// later launches no longer hold for this failure. A new failed start
/// replaces `failure` and holds again.
pub(crate) fn record_run_anyway(dir: &Path) -> io::Result<()> {
    let mut state =
        install::read_state(dir).ok_or_else(|| io::Error::other("no readable state"))?;
    let Some(Value::Object(failure)) = state.extra.get_mut(FAILURE_FIELD) else {
        return Err(io::Error::other("no failed start is recorded"));
    };
    failure.insert(RUN_ANYWAY_AT_FIELD.into(), unix_now().into());
    install::write_state(dir, &state)
}

/// For "Retry": the version may be started again, as if it never failed.
/// Any state but `started_ok` becomes `staged` again. `node_opened` stays:
/// the version did open the wallet data, so a retried start that fails
/// before it gets that far is still a failure after opening data, and the
/// older version holds again.
pub(crate) fn reset_failed_starts(dir: &Path) -> io::Result<()> {
    let mut state =
        install::read_state(dir).ok_or_else(|| io::Error::other("no readable state"))?;
    if state.state != STATE_STARTED_OK {
        state.state = STATE_STAGED.into();
    }
    for field in [
        START_ATTEMPTS_FIELD,
        FAILURE_FIELD,
        START_FAILURE_REASON_FIELD,
    ] {
        state.extra.remove(field);
    }
    install::write_state(dir, &state)
}

/// For the started version, once it is known to work: `started_ok`, with
/// the failed-start count and failure cleared.
pub(crate) fn record_start_success(dir: &Path) -> io::Result<()> {
    let mut state =
        install::read_state(dir).ok_or_else(|| io::Error::other("no readable state"))?;
    state.state = STATE_STARTED_OK.into();
    state.extra.insert(START_ATTEMPTS_FIELD.into(), 0.into());
    state.extra.remove(FAILURE_FIELD);
    install::write_state(dir, &state)
}

/// For the started version, right before its node opens the wallet data:
/// from then on a failed start is one after opening data.
pub(crate) fn record_opening_data(dir: &Path) -> io::Result<()> {
    let mut state =
        install::read_state(dir).ok_or_else(|| io::Error::other("no readable state"))?;
    state.extra.insert(NODE_OPENED_FIELD.into(), true.into());
    install::write_state(dir, &state)
}

/// Best effort: a log that cannot be written never changes the launch.
pub(crate) fn log_line(root: &Path, line: &str) {
    // Not eprintln!, which panics when stderr is a closed pipe.
    let _ = writeln!(io::stderr(), "Common Foundry Wallet updater: {line}");
    let path = root.join(LOG_FILE_NAME);
    let _ = (|| -> io::Result<()> {
        let meta = fs::symlink_metadata(&path).ok();
        if meta.as_ref().is_some_and(|meta| !meta.is_file()) {
            return Ok(());
        }
        let full = meta.is_some_and(|meta| meta.len() >= MAX_LOG_BYTES);
        let mut options = OpenOptions::new();
        options.create(true);
        // One older file. A log that cannot be moved aside (another
        // process holds it) starts over instead.
        if full && fs::rename(&path, root.join(format!("{LOG_FILE_NAME}.1"))).is_err() {
            options.write(true).truncate(true);
        } else {
            options.append(true);
        }
        // Never through a link swapped in after the check above.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            const O_NOFOLLOW: i32 = 0o400_000;
            options.custom_flags(O_NOFOLLOW);
        }
        let mut file = options.open(&path)?;
        if !file.metadata()?.is_file() {
            return Ok(());
        }
        writeln!(
            file,
            "{} forwarder[{}]: {line}",
            unix_now(),
            std::process::id()
        )
    })();
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::updater::install::tests::TempDir;
    use crate::updater::install::{MARKER_DIR_NAME, PACKAGE_MANIFEST_NAME, package_name};
    use crate::updater::release;
    use serde_json::Map;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    const MAINNET: Option<[u8; 32]> = cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID;
    const HELPER_TEST: &str = "updater::forward::tests::spawn_helper";
    const HELPER_OUT_ENV: &str = "CMFD_FORWARD_TEST_HELPER_OUT";
    const HELPER_EXIT_ENV: &str = "CMFD_FORWARD_TEST_HELPER_EXIT";

    fn platform() -> Platform {
        Platform::current().expect("tests run on windows-x86_64 or linux-x86_64")
    }

    fn wallet_name() -> &'static str {
        match platform() {
            Platform::WindowsX86_64 => "common-foundry-wallet.exe",
            Platform::LinuxX86_64 => "common-foundry-wallet",
        }
    }

    fn v(patch: u64) -> Version {
        Version::new(1, 0, patch)
    }

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect()
    }

    macro_rules! signed {
        ($version:literal) => {
            [
                include_bytes!(concat!(
                    "../../tests/fixtures/updater/v",
                    $version,
                    "/SHA256SUMS.txt"
                ))
                .as_slice(),
                include_bytes!(concat!(
                    "../../tests/fixtures/updater/v",
                    $version,
                    "/SHA256SUMS.txt.sig"
                ))
                .as_slice(),
                include_bytes!(concat!(
                    "../../tests/fixtures/updater/v",
                    $version,
                    "/BUILDINFO.json"
                ))
                .as_slice(),
            ]
        };
    }

    /// The real signed SUMS, signature and BUILDINFO of release 1.0.`patch`.
    fn signed_files(patch: u64) -> [&'static [u8]; 3] {
        match patch {
            12 => signed!("1.0.12"),
            13 => signed!("1.0.13"),
            14 => signed!("1.0.14"),
            15 => signed!("1.0.15"),
            _ => panic!("no signed fixture for 1.0.{patch}"),
        }
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
        digest
    }

    /// A folder as the updater leaves it for the real, signed release
    /// 1.0.`patch`, holding a small stand-in wallet exe that its package
    /// record lists, and recorded in the registry beside `root`
    /// ([`registry_of`]).
    pub(crate) fn installed(root: &Path, patch: u64) -> PathBuf {
        installed_as(root, &package_name(platform(), v(patch)), patch)
    }

    pub(crate) fn installed_as(root: &Path, name: &str, patch: u64) -> PathBuf {
        let [sums, signature, buildinfo] = signed_files(patch);
        let info: Value = serde_json::from_slice(buildinfo).unwrap();
        let exe = format!("wallet 1.0.{patch}").into_bytes();
        let mut files = Map::new();
        files.insert(
            wallet_name().into(),
            json!({"bytes": exe.len(), "sha256": hex::encode(sha256(&exe))}),
        );
        let record = serde_json::to_vec(&json!({
            "schema": "CMFD_MAINNET_PACKAGE_ATTESTATION_V1",
            "kind": "runtime",
            "platform": platform().name(),
            "package_version": format!("1.0.{patch}"),
            "network_id": hex::encode(MAINNET.unwrap()),
            "source_commit": info["commit"],
            "files": files,
        }))
        .unwrap();
        let dir = root.join(name);
        let marker = dir.join(MARKER_DIR_NAME);
        fs::create_dir_all(&marker).unwrap();
        fs::write(dir.join(wallet_name()), &exe).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.join(wallet_name()), fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        fs::write(dir.join(PACKAGE_MANIFEST_NAME), &record).unwrap();
        for (file, bytes) in [
            (release::SUMS_NAME, sums),
            (release::SIGNATURE_NAME, signature),
            (release::BUILDINFO_NAME, buildinfo),
            (PACKAGE_MANIFEST_NAME, record.as_slice()),
        ] {
            fs::write(marker.join(file), bytes).unwrap();
        }
        let asset = platform().runtime_asset(v(patch));
        let row = std::str::from_utf8(sums)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_suffix(&format!("  {asset}")))
            .unwrap()
            .to_owned();
        let state = InstallState {
            state: STATE_STAGED.into(),
            version: format!("1.0.{patch}"),
            sums_sha256: hex::encode(sha256(sums)),
            archive_sha256: row,
            staged_at: 1,
            extra: Map::new(),
        };
        install::write_state(&dir, &state).unwrap();
        install::register_installed(&registry_of(root), &dir, &record, sha256(sums)).unwrap();
        dir
    }

    /// The test registry of every root in a [`Setup`]'s temp dir.
    pub(crate) fn registry_of(root: &Path) -> PathBuf {
        root.parent().unwrap().join("registry")
    }

    fn edit_state(dir: &Path, edit: impl FnOnce(&mut InstallState)) {
        let mut state = install::read_state(dir).unwrap();
        edit(&mut state);
        install::write_state(dir, &state).unwrap();
    }

    type Outcome = Box<dyn FnOnce(&SpawnRequest) -> Result<Option<i32>, SpawnError>>;

    /// Records each start and answers with the next outcome.
    #[derive(Default)]
    struct FakeSpawn {
        requests: RefCell<Vec<SpawnRequest>>,
        outcomes: RefCell<VecDeque<Outcome>>,
    }

    impl FakeSpawn {
        fn exiting(codes: &[Option<i32>]) -> Self {
            let spawn = Self::default();
            for &code in codes {
                spawn.then(move |_| Ok(code));
            }
            spawn
        }

        fn then(
            &self,
            outcome: impl FnOnce(&SpawnRequest) -> Result<Option<i32>, SpawnError> + 'static,
        ) {
            self.outcomes.borrow_mut().push_back(Box::new(outcome));
        }

        /// The version folders started, in order.
        fn started(&self) -> Vec<PathBuf> {
            self.requests
                .borrow()
                .iter()
                .map(|request| request.exe.parent().unwrap().to_path_buf())
                .collect()
        }
    }

    impl Spawn for FakeSpawn {
        fn run(&self, request: &SpawnRequest, held: File) -> Result<Option<i32>, SpawnError> {
            drop(held);
            self.requests.borrow_mut().push(request.clone());
            let outcome = self
                .outcomes
                .borrow_mut()
                .pop_front()
                .expect("an unexpected start");
            outcome(request)
        }
    }

    /// A root holding the running 1.0.11 package folder.
    struct Setup {
        temp: TempDir,
        root: PathBuf,
        exe: PathBuf,
        registry: PathBuf,
        roots: Vec<PathBuf>,
        running: Version,
    }

    impl Setup {
        fn new() -> Self {
            let temp = TempDir::new();
            let root = temp.0.join("root");
            let anchor = root.join(package_name(platform(), v(11)));
            fs::create_dir_all(&anchor).unwrap();
            let exe = anchor.join(wallet_name());
            fs::write(&exe, b"the running wallet").unwrap();
            Self {
                registry: registry_of(&root),
                roots: vec![root.clone()],
                temp,
                root,
                exe,
                running: v(11),
            }
        }

        fn launch_with(
            &self,
            args: &[OsString],
            env: &[(OsString, OsString)],
            spawn: &FakeSpawn,
        ) -> Launch {
            forward(
                &Context {
                    args,
                    env,
                    exe: &self.exe,
                    running: self.running,
                    platform: platform(),
                    network_id: MAINNET,
                    registry: &self.registry,
                    roots: &self.roots,
                },
                spawn,
            )
        }

        fn launch(&self, spawn: &FakeSpawn) -> Launch {
            self.launch_with(&[], &[], spawn)
        }

        fn log(&self) -> String {
            fs::read_to_string(self.root.join(LOG_FILE_NAME)).unwrap_or_default()
        }

        /// A folder beside the root.
        fn elsewhere(&self, name: &str) -> PathBuf {
            let dir = self.temp.0.join(name);
            fs::create_dir_all(&dir).unwrap();
            dir
        }
    }

    #[test]
    fn the_highest_good_version_runs_with_the_same_arguments() {
        let setup = Setup::new();
        installed(&setup.root, 13);
        let v15 = installed(&setup.root, 15);
        installed(&setup.root, 14);
        let state = install::read_state(&v15).unwrap();
        let args = os(&[
            "--data-dir=D:\\CF Wallet\\data",
            "--a-flag-only-a-newer-version-knows",
            "--peer",
            "203.0.113.7:29444",
            "",
            "say \"hi\" \\",
            "\u{fc}n\u{ef}",
        ]);
        let parent_env = env(&[
            ("PATH", "/usr/bin"),
            ("CMFD_UPDATE_HANDOFF", "1"),
            ("CMFD_UPDATE_SPAWN_FAILED", "x"),
            ("CMFD_UPDATE_PARENT_PID", "42"),
            ("cmfd_update_fallback_from", "1.0.9"),
            ("CMFD_DATA", "kept"),
        ]);
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(
            setup.launch_with(&args, &parent_env, &spawn),
            Launch::Exit(0)
        );
        let requests = spawn.requests.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].exe, v15.join(wallet_name()));
        assert_eq!(requests[0].args, args);
        let launched = fs::canonicalize(&setup.exe).unwrap();
        // Every update variable is removed but the two of the handoff.
        let mut expected = env(&[
            ("PATH", "/usr/bin"),
            ("CMFD_UPDATE_HANDOFF", "1"),
            ("CMFD_UPDATE_PARENT_PID", "42"),
            ("CMFD_DATA", "kept"),
            (FORWARDED_ENV, "1"),
        ]);
        expected.push((LAUNCHED_FROM_ENV.into(), launched.clone().into()));
        assert_eq!(requests[0].env, expected);
        assert_eq!(launched_from(&requests[0].env), Some(launched));
        // A clean exit records nothing.
        assert_eq!(install::read_state(&v15).unwrap(), state);
        assert!(setup.log().contains("starting 1.0.15 from"));
    }

    #[test]
    fn a_fallback_start_keeps_the_handoff_but_not_the_closing_wallets_id() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let v14 = installed(&setup.root, 14);
        let parent_env = env(&[
            ("CMFD_UPDATE_HANDOFF", "1"),
            ("CMFD_UPDATE_PARENT_PID", "42"),
        ]);
        let spawn = FakeSpawn::exiting(&[Some(1), Some(0)]);
        assert_eq!(setup.launch_with(&[], &parent_env, &spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v15, v14]);
        let requests = spawn.requests.borrow();
        let has =
            |request: &SpawnRequest, name: &str| request.env.iter().any(|(key, _)| key == name);
        assert!(has(&requests[0], "CMFD_UPDATE_HANDOFF"));
        assert!(has(&requests[0], "CMFD_UPDATE_PARENT_PID"));
        // By now the closing wallet may be gone and its id reused.
        assert!(has(&requests[1], "CMFD_UPDATE_HANDOFF"));
        assert!(!has(&requests[1], "CMFD_UPDATE_PARENT_PID"));
        assert_eq!(Fallback::from_env(&requests[1].env).unwrap().version, v(15));
    }

    #[test]
    fn the_handoff_variables_pass_on_by_their_exact_name_outside_windows() {
        let parent = env(&[
            ("cmfd_update_handoff", "1"),
            ("Cmfd_Update_Parent_Pid", "42"),
        ]);
        let child = child_env(&parent, None, None);
        let kept = |name: &str| child.iter().any(|(key, _)| key == name);
        assert_eq!(kept("cmfd_update_handoff"), cfg!(windows));
        assert_eq!(kept("Cmfd_Update_Parent_Pid"), cfg!(windows));
    }

    #[cfg(unix)]
    #[test]
    fn arguments_that_are_not_unicode_pass_through_unchanged() {
        use std::os::unix::ffi::OsStringExt;
        let setup = Setup::new();
        installed(&setup.root, 15);
        let args = vec![OsString::from_vec(vec![b'-', b'-', 0xff, 0xfe])];
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch_with(&args, &[], &spawn), Launch::Exit(0));
        assert_eq!(spawn.requests.borrow()[0].args, args);
    }

    #[test]
    fn these_launches_never_forward() {
        let setup = Setup::new();
        installed(&setup.root, 15);
        for arg in NOT_FORWARDED_ARGS {
            for args in [vec![arg], vec!["--verbose", arg], vec![arg, "--no-prune"]] {
                let spawn = FakeSpawn::default();
                assert_eq!(
                    setup.launch_with(&os(&args), &[], &spawn),
                    Launch::RunHere(None),
                    "{args:?}"
                );
                assert!(spawn.started().is_empty());
            }
        }
        for pairs in [
            [(NO_AUTO_UPDATE_ENV, "1")],
            [("cmfd_no_auto_update", "1")],
            [(FORWARDED_ENV, "1")],
            [(FORWARDED_ENV, "0")],
            [("Cmfd_Update_Forwarded", "")],
        ] {
            let spawn = FakeSpawn::default();
            assert_eq!(
                setup.launch_with(&[], &env(&pairs), &spawn),
                Launch::RunHere(None),
                "{pairs:?}"
            );
            assert!(spawn.started().is_empty());
        }
        // Only exact matches.
        for (args, pairs) in [
            (vec!["--no-auto-update=1"], vec![]),
            (vec!["--versions"], vec![]),
            (vec!["-hV"], vec![]),
            (vec![], vec![(NO_AUTO_UPDATE_ENV, "0")]),
            (vec![], vec![(NO_AUTO_UPDATE_ENV, "")]),
        ] {
            let spawn = FakeSpawn::exiting(&[Some(0)]);
            assert_eq!(
                setup.launch_with(&os(&args), &env(&pairs), &spawn),
                Launch::Exit(0),
                "{args:?} {pairs:?}"
            );
        }
    }

    #[test]
    fn only_versions_above_the_running_one_are_started() {
        let mut setup = Setup::new();
        installed(&setup.root, 12);
        installed(&setup.root, 13);
        setup.running = v(13);
        let spawn = FakeSpawn::default();
        assert_eq!(setup.launch(&spawn), Launch::RunHere(None));
        assert!(spawn.started().is_empty());
        // Never its own folder.
        let v15 = installed(&setup.root, 15);
        setup.exe = v15.join(wallet_name());
        assert_eq!(setup.launch(&spawn), Launch::RunHere(None));
        assert!(spawn.started().is_empty());
    }

    #[test]
    fn failed_and_unfinished_versions_are_passed_over() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        edit_state(&v15, |state| state.state = STATE_FAILED.into());
        let v14 = installed(&setup.root, 14);
        edit_state(&v14, |state| {
            state
                .extra
                .insert(START_ATTEMPTS_FIELD.into(), MAX_START_ATTEMPTS.into());
        });
        let v13 = installed(&setup.root, 13);
        edit_state(&v13, |state| state.state = "installing".into());
        let v12 = installed(&setup.root, 12);
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v12]);
    }

    #[test]
    fn a_folder_that_does_not_verify_never_runs() {
        let setup = Setup::new();
        // No marker at all.
        let bare = setup.root.join(package_name(platform(), v(15)));
        fs::create_dir_all(&bare).unwrap();
        fs::write(bare.join(wallet_name()), b"wallet 1.0.15").unwrap();
        // A state that claims 9.9.9 over the signed 1.0.15 files.
        let claimed = installed_as(
            &setup.root,
            &package_name(platform(), Version::new(9, 9, 9)),
            15,
        );
        edit_state(&claimed, |state| state.version = "9.9.9".into());
        // The signed 1.0.15 files with another exe.
        let swapped = installed_as(
            &setup.root,
            &format!("{}-auto", package_name(platform(), v(15))),
            15,
        );
        fs::write(swapped.join(wallet_name()), b"wallet 1.0.16").unwrap();
        // The signed files of 1.0.14 under a 1.0.15 name.
        installed_as(
            &setup.root,
            &format!("{}-auto2", package_name(platform(), v(15))),
            14,
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let good = installed(&setup.elsewhere("elsewhere"), 14);
            std::os::unix::fs::symlink(&good, setup.root.join(package_name(platform(), v(14))))
                .unwrap();
            let open = installed(&setup.root, 13);
            fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        }
        let v12 = installed(&setup.root, 12);
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v12]);
        assert!(setup.log().contains("skipped"));
    }

    #[test]
    fn a_folder_this_users_updater_did_not_install_never_runs() {
        let setup = Setup::new();
        // The real signed files, an exe and a record that lists it: all of
        // it can be copied into a shared root by someone else.
        let planted = installed(&setup.root, 15);
        install::unregister_installed(&setup.registry, &planted).unwrap();
        // Recorded with another package record.
        let other = installed(&setup.root, 14);
        let sums = fs::read(other.join(MARKER_DIR_NAME).join(release::SUMS_NAME)).unwrap();
        install::register_installed(&setup.registry, &other, b"another record", sha256(&sums))
            .unwrap();
        // Recorded under another path.
        let moved = installed(&setup.root, 13);
        let renamed = setup
            .root
            .join(format!("{}-auto", package_name(platform(), v(13))));
        fs::rename(&moved, &renamed).unwrap();
        let v12 = installed(&setup.root, 12);
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), std::slice::from_ref(&v12));
        assert!(
            setup
                .log()
                .contains("this user's updater did not install it here")
        );

        // Without any registry, nothing runs.
        fs::remove_dir_all(&setup.registry).unwrap();
        let spawn = FakeSpawn::default();
        assert_eq!(setup.launch(&spawn), Launch::RunHere(None));
        assert!(v12.exists());
    }

    #[test]
    fn a_version_that_fails_to_start_falls_back_to_the_next() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let v14 = installed(&setup.root, 14);
        let spawn = FakeSpawn::exiting(&[Some(101), Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v15.clone(), v14.clone()]);
        let mut expected = env(&[(FORWARDED_ENV, "1")]);
        expected.push((
            LAUNCHED_FROM_ENV.into(),
            fs::canonicalize(&setup.exe).unwrap().into(),
        ));
        expected.extend(env(&[
            (FALLBACK_FROM_ENV, "1.0.15"),
            (FALLBACK_REASON_ENV, "it exited with code 101"),
            (FALLBACK_AFTER_DATA_ENV, "0"),
        ]));
        assert_eq!(spawn.requests.borrow()[1].env, expected);
        let state = install::read_state(&v15).unwrap();
        assert_eq!(state.state, STATE_STAGED);
        assert_eq!(state.extra[START_ATTEMPTS_FIELD], 1);
        assert_eq!(state.extra[FAILURE_FIELD]["kind"], "start");
        assert_eq!(
            state.extra[FAILURE_FIELD]["reason"],
            "it exited with code 101"
        );
        assert_eq!(state.extra[FAILURE_FIELD]["after_data"], false);
        assert!(install::read_state(&v14).unwrap().extra.is_empty());
        assert!(
            setup
                .log()
                .contains("1.0.15 failed to start: it exited with code 101")
        );

        // Two more failed starts make it `failed`, and it is not tried again.
        for attempt in 2..=MAX_START_ATTEMPTS {
            let spawn = FakeSpawn::exiting(&[None, Some(0)]);
            assert_eq!(setup.launch(&spawn), Launch::Exit(0));
            assert_eq!(spawn.started(), [v15.clone(), v14.clone()]);
            let state = install::read_state(&v15).unwrap();
            assert_eq!(state.extra[START_ATTEMPTS_FIELD], attempt);
            assert_eq!(
                state.extra[FAILURE_FIELD]["reason"],
                "it was ended by a signal"
            );
        }
        assert_eq!(install::read_state(&v15).unwrap().state, STATE_FAILED);
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v14]);
    }

    #[test]
    fn a_failure_after_opening_wallet_data_is_passed_on_to_this_wallet() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let spawn = FakeSpawn::default();
        let dir = v15.clone();
        spawn.then(move |_| {
            record_opening_data(&dir).unwrap();
            Ok(Some(1))
        });
        assert_eq!(
            setup.launch(&spawn),
            Launch::RunHere(Some(Fallback {
                version: v(15),
                reason: "it exited with code 1".into(),
                after_data: true,
            }))
        );
        let state = install::read_state(&v15).unwrap();
        assert_eq!(state.extra[FAILURE_FIELD]["after_data"], true);
        assert_eq!(state.extra[START_ATTEMPTS_FIELD], 1);
    }

    #[test]
    fn the_versions_own_reason_is_kept_with_the_exit_code() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let spawn = FakeSpawn::default();
        let dir = v15.clone();
        spawn.then(move |_| {
            record_opening_data(&dir).unwrap();
            record_start_failure_reason(&dir, "corrupt_block_log: the block log is damaged")
                .unwrap();
            Ok(Some(4))
        });
        let reason = "corrupt_block_log: the block log is damaged (it exited with code 4)";
        assert_eq!(
            setup.launch(&spawn),
            Launch::RunHere(Some(Fallback {
                version: v(15),
                reason: reason.into(),
                after_data: true,
            }))
        );
        let state = install::read_state(&v15).unwrap();
        assert_eq!(state.extra[FAILURE_FIELD]["reason"], reason);
        // Used once: the next failure has only its exit code.
        assert!(!state.extra.contains_key(START_FAILURE_REASON_FIELD));
        assert!(setup.log().contains(reason));
    }

    fn failed_after_data(dir: &Path, attempts: u64) {
        edit_state(dir, |state| {
            if attempts >= MAX_START_ATTEMPTS {
                state.state = STATE_FAILED.into();
            }
            state
                .extra
                .insert(START_ATTEMPTS_FIELD.into(), attempts.into());
            state.extra.insert(NODE_OPENED_FIELD.into(), true.into());
            state.extra.insert(
                FAILURE_FIELD.into(),
                json!({"kind": "start", "reason": "corrupt", "after_data": true, "at": 1}),
            );
        });
    }

    fn held_by(patch: u64, reason: &str) -> Option<Fallback> {
        Some(Fallback {
            version: v(patch),
            reason: reason.into(),
            after_data: true,
        })
    }

    #[test]
    fn a_failure_after_opening_data_holds_every_launch_until_the_user_chooses() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let opens_and_fails = |dir: &Path| {
            let spawn = FakeSpawn::default();
            let dir = dir.to_path_buf();
            spawn.then(move |_| {
                record_opening_data(&dir).unwrap();
                Ok(Some(1))
            });
            spawn
        };
        // The user closes the held wallet each time without choosing.
        for _ in 0..MAX_START_ATTEMPTS {
            assert_eq!(
                setup.launch(&opens_and_fails(&v15)),
                Launch::RunHere(held_by(15, "it exited with code 1"))
            );
        }
        assert_eq!(install::read_state(&v15).unwrap().state, STATE_FAILED);
        // No longer started, but still held for.
        for _ in 0..2 {
            let spawn = FakeSpawn::default();
            assert_eq!(
                setup.launch(&spawn),
                Launch::RunHere(held_by(15, "it exited with code 1"))
            );
            assert!(spawn.started().is_empty());
        }
        assert!(setup.log().contains("nobody chose Run anyway yet"));
        // "Run anyway" ends it.
        record_run_anyway(&v15).unwrap();
        assert_eq!(setup.launch(&FakeSpawn::default()), Launch::RunHere(None));
        assert!(
            install::read_state(&v15).unwrap().extra[FAILURE_FIELD][RUN_ANYWAY_AT_FIELD].is_u64()
        );
        // "Retry" starts it again; a new failure after opening data holds
        // again.
        reset_failed_starts(&v15).unwrap();
        assert_eq!(
            setup.launch(&opens_and_fails(&v15)),
            Launch::RunHere(held_by(15, "it exited with code 1"))
        );
        assert_eq!(
            setup.launch(&opens_and_fails(&v15)),
            Launch::RunHere(held_by(15, "it exited with code 1"))
        );
        // Without a failure there is nothing to choose.
        reset_failed_starts(&v15).unwrap();
        assert!(record_run_anyway(&v15).is_err());
    }

    #[test]
    fn the_hold_of_an_earlier_launch_goes_only_to_older_versions() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let v14 = installed(&setup.root, 14);
        failed_after_data(&v14, MAX_START_ATTEMPTS);
        let v13 = installed(&setup.root, 13);
        // 1.0.15 is newer than the failed version: it opens the data
        // freely. It fails before opening them; 1.0.13 then holds for
        // 1.0.14.
        let spawn = FakeSpawn::exiting(&[Some(1), Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v15.clone(), v13]);
        let requests = spawn.requests.borrow();
        assert_eq!(Fallback::from_env(&requests[0].env), None);
        assert_eq!(Fallback::from_env(&requests[1].env), held_by(14, "corrupt"));
        drop(requests);
        // A version known to work never holds (its old failure kept here
        // only to show that the state decides).
        edit_state(&v14, |state| {
            state.state = STATE_STARTED_OK.into();
            state.extra.insert(START_ATTEMPTS_FIELD.into(), 0.into());
        });
        edit_state(&v15, |state| state.state = STATE_FAILED.into());
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v14]);
    }

    #[test]
    fn only_a_failure_after_opening_data_in_a_folder_this_user_installed_holds() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        failed_after_data(&v15, MAX_START_ATTEMPTS);
        // A failure before opening data, or of another kind, does not hold.
        let v14 = installed(&setup.root, 14);
        failed_after_data(&v14, MAX_START_ATTEMPTS);
        edit_state(&v14, |state| {
            state.extra.get_mut(FAILURE_FIELD).unwrap()["after_data"] = false.into();
        });
        let v13 = installed(&setup.root, 13);
        failed_after_data(&v13, MAX_START_ATTEMPTS);
        edit_state(&v13, |state| {
            state.extra.get_mut(FAILURE_FIELD).unwrap()["kind"] = "install".into();
        });
        assert_eq!(
            setup.launch(&FakeSpawn::default()),
            Launch::RunHere(held_by(15, "corrupt"))
        );
        // A folder someone else put beside this wallet does not.
        install::unregister_installed(&setup.registry, &v15).unwrap();
        assert_eq!(setup.launch(&FakeSpawn::default()), Launch::RunHere(None));
        // Nor does a launch that does not forward.
        let v12 = installed(&setup.root, 12);
        failed_after_data(&v12, MAX_START_ATTEMPTS);
        assert_eq!(
            setup.launch(&FakeSpawn::default()),
            Launch::RunHere(held_by(12, "corrupt"))
        );
        assert_eq!(
            setup.launch_with(&os(&["--no-auto-update"]), &[], &FakeSpawn::default()),
            Launch::RunHere(None)
        );
    }

    #[test]
    fn retry_makes_a_failed_version_a_candidate_again() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        edit_state(&v15, |state| {
            state.state = STATE_FAILED.into();
            state.extra.insert(START_ATTEMPTS_FIELD.into(), 3.into());
            state.extra.insert(NODE_OPENED_FIELD.into(), true.into());
            state
                .extra
                .insert(FAILURE_FIELD.into(), json!({"kind": "start"}));
        });
        assert_eq!(setup.launch(&FakeSpawn::default()), Launch::RunHere(None));
        reset_failed_starts(&v15).unwrap();
        let state = install::read_state(&v15).unwrap();
        assert_eq!(state.state, STATE_STAGED);
        for field in [START_ATTEMPTS_FIELD, FAILURE_FIELD] {
            assert!(!state.extra.contains_key(field), "{field}");
        }
        // That it opened the data is kept (see the next test).
        assert_eq!(state.extra[NODE_OPENED_FIELD], true);
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), std::slice::from_ref(&v15));
        // A version known to work stays so.
        edit_state(&v15, |state| state.state = STATE_STARTED_OK.into());
        reset_failed_starts(&v15).unwrap();
        assert_eq!(install::read_state(&v15).unwrap().state, STATE_STARTED_OK);
    }

    #[test]
    fn retry_keeps_the_record_that_the_version_opened_the_data() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let spawn = FakeSpawn::default();
        let dir = v15.clone();
        spawn.then(move |_| {
            record_opening_data(&dir).unwrap();
            Ok(Some(1))
        });
        assert_eq!(
            setup.launch(&spawn),
            Launch::RunHere(held_by(15, "it exited with code 1"))
        );
        let opened = |dir: &Path| {
            install::read_state(dir)
                .unwrap()
                .extra
                .get(NODE_OPENED_FIELD)
                .cloned()
        };
        // "Retry", and the retried start fails before it reaches the node
        // open: that is still a failure after opening data, so this wallet
        // holds.
        reset_failed_starts(&v15).unwrap();
        assert_eq!(opened(&v15), Some(Value::Bool(true)));
        assert_eq!(
            setup.launch(&FakeSpawn::exiting(&[Some(1)])),
            Launch::RunHere(held_by(15, "it exited with code 1"))
        );
        let state = install::read_state(&v15).unwrap();
        assert_eq!(state.extra[FAILURE_FIELD]["after_data"], true);
        assert_eq!(state.extra[START_ATTEMPTS_FIELD], 1);
        // Nor is exit 2 after a retry taken for refused arguments.
        reset_failed_starts(&v15).unwrap();
        assert_eq!(
            setup.launch(&FakeSpawn::exiting(&[Some(USAGE_EXIT_CODE)])),
            Launch::RunHere(held_by(15, "it exited with code 2"))
        );
        assert_eq!(
            install::read_state(&v15).unwrap().extra[START_ATTEMPTS_FIELD],
            1
        );
    }

    /// The reason a damaged folder is passed over with, as the forwarder
    /// words it.
    fn damaged(why: &str) -> String {
        format!("its installed files are damaged: {why}")
    }

    #[test]
    fn a_damaged_version_that_opened_the_data_makes_older_versions_hold() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let v14 = installed(&setup.root, 14);
        edit_state(&v15, |state| state.state = STATE_STARTED_OK.into());
        // An antivirus quarantine of the exe of a version known to work.
        fs::remove_file(v15.join(wallet_name())).unwrap();
        let before = install::read_state(&v15).unwrap();
        let hold = Some(Fallback {
            version: v(15),
            reason: damaged(&format!("{} is missing or changed", wallet_name())),
            after_data: true,
        });
        // 1.0.14 is told before it opens the data, and so is this wallet.
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), std::slice::from_ref(&v14));
        assert_eq!(Fallback::from_env(&spawn.requests.borrow()[0].env), hold);
        edit_state(&v14, |state| state.state = STATE_FAILED.into());
        assert_eq!(
            setup.launch(&FakeSpawn::default()),
            Launch::RunHere(hold.clone())
        );
        // Nothing was started from the damaged folder, so nothing is
        // counted or written there, and every launch holds again until it
        // is reinstalled or removed.
        assert_eq!(install::read_state(&v15).unwrap(), before);
        assert!(record_run_anyway(&v15).is_err());
        assert_eq!(setup.launch(&FakeSpawn::default()), Launch::RunHere(hold));
        assert!(setup.log().contains("skipped"));
        assert!(setup.log().contains("damaged after it opened wallet data"));
    }

    #[test]
    fn a_damaged_version_marked_as_opening_the_data_holds_too() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        // Still `staged`: it began to open the data and was then retried.
        edit_state(&v15, |state| {
            state.extra.insert(NODE_OPENED_FIELD.into(), true.into());
        });
        // Same size, other bytes.
        fs::write(v15.join(wallet_name()), b"wallet 1.0.99").unwrap();
        let before = install::read_state(&v15).unwrap();
        assert_eq!(
            setup.launch(&FakeSpawn::default()),
            Launch::RunHere(Some(Fallback {
                version: v(15),
                reason: damaged(&format!("{} changed", wallet_name())),
                after_data: true,
            }))
        );
        assert_eq!(install::read_state(&v15).unwrap(), before);
    }

    #[test]
    fn a_damaged_version_that_never_opened_the_data_is_only_passed_over() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        fs::remove_file(v15.join(wallet_name())).unwrap();
        let before = install::read_state(&v15).unwrap();
        assert_eq!(setup.launch(&FakeSpawn::default()), Launch::RunHere(None));
        let v14 = installed(&setup.root, 14);
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), std::slice::from_ref(&v14));
        assert_eq!(Fallback::from_env(&spawn.requests.borrow()[0].env), None);
        assert_eq!(install::read_state(&v15).unwrap(), before);
        // A folder this user's updater did not install never holds, even
        // when its state says it started.
        edit_state(&v15, |state| state.state = STATE_STARTED_OK.into());
        install::unregister_installed(&setup.registry, &v15).unwrap();
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v14]);
        assert_eq!(Fallback::from_env(&spawn.requests.borrow()[0].env), None);
    }

    #[test]
    fn a_reinstalled_copy_of_a_damaged_version_runs_without_the_hold() {
        let setup = Setup::new();
        let damaged_copy = installed(&setup.root, 15);
        edit_state(&damaged_copy, |state| state.state = STATE_STARTED_OK.into());
        fs::remove_file(damaged_copy.join(wallet_name())).unwrap();
        // A reinstall takes the next free name.
        let reinstalled = installed_as(
            &setup.root,
            &format!("{}-auto", package_name(platform(), v(15))),
            15,
        );
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [reinstalled]);
        assert_eq!(Fallback::from_env(&spawn.requests.borrow()[0].env), None);
    }

    #[test]
    fn a_failure_after_opening_data_is_kept_down_the_fallback_chain() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let v14 = installed(&setup.root, 14);
        let v13 = installed(&setup.root, 13);
        let spawn = FakeSpawn::default();
        let dir = v15.clone();
        spawn.then(move |_| {
            record_opening_data(&dir).unwrap();
            Ok(Some(1))
        });
        spawn.then(|_| Err(SpawnError::Start(io::Error::other("blocked"))));
        spawn.then(|_| Ok(Some(101)));
        let after_data = Fallback {
            version: v(15),
            reason: "it exited with code 1".into(),
            after_data: true,
        };
        assert_eq!(
            setup.launch(&spawn),
            Launch::RunHere(Some(after_data.clone()))
        );
        assert_eq!(spawn.started(), [v15, v14, v13.clone()]);
        // 1.0.13 was told about the failure after opening data too.
        let requests = spawn.requests.borrow();
        assert_eq!(Fallback::from_env(&requests[2].env), Some(after_data));
        assert_eq!(
            install::read_state(&v13).unwrap().extra[FAILURE_FIELD]["after_data"],
            false
        );
    }

    #[test]
    fn a_version_known_to_work_is_not_failed_by_a_later_crash() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        installed(&setup.root, 14);
        // One failed start, then a start that works and later crashes.
        let spawn = FakeSpawn::exiting(&[Some(1), Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(
            install::read_state(&v15).unwrap().extra[START_ATTEMPTS_FIELD],
            1
        );
        let spawn = FakeSpawn::default();
        let dir = v15.clone();
        spawn.then(move |_| {
            record_start_success(&dir).unwrap();
            Ok(Some(3))
        });
        assert_eq!(setup.launch(&spawn), Launch::Exit(3));
        assert_eq!(spawn.started(), std::slice::from_ref(&v15));
        let state = install::read_state(&v15).unwrap();
        assert_eq!(state.state, STATE_STARTED_OK);
        assert_eq!(state.extra[START_ATTEMPTS_FIELD], 0);
        assert!(!state.extra.contains_key(FAILURE_FIELD));
    }

    #[test]
    fn refused_arguments_are_passed_over_without_counting() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let v14 = installed(&setup.root, 14);
        let state = install::read_state(&v15).unwrap();
        // 1.0.15 refuses the arguments and 1.0.14 takes them: the launch
        // works, and 1.0.14 is told why 1.0.15 did not run.
        let spawn = FakeSpawn::exiting(&[Some(USAGE_EXIT_CODE), Some(0)]);
        let args = os(&["--prune-keep-blocks", "100"]);
        assert_eq!(setup.launch_with(&args, &[], &spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v15.clone(), v14.clone()]);
        let requests = spawn.requests.borrow();
        assert_eq!(requests[1].args, args);
        let passed = Fallback::from_env(&requests[1].env).unwrap();
        assert_eq!(
            passed,
            Fallback {
                version: v(15),
                reason: "it refused the launch arguments".into(),
                after_data: false,
            }
        );
        drop(requests);
        // Not counted.
        assert_eq!(install::read_state(&v15).unwrap(), state);
        assert!(
            setup
                .log()
                .contains("1.0.15: it refused the launch arguments")
        );

        // When every newer version refuses them, this wallet runs with the
        // fallback; it parses the arguments itself and, if it refuses them
        // too, exits with 2 as before.
        let spawn = FakeSpawn::exiting(&[Some(USAGE_EXIT_CODE), Some(USAGE_EXIT_CODE)]);
        let Launch::RunHere(Some(fallback)) = setup.launch_with(&args, &[], &spawn) else {
            panic!("expected a fallback");
        };
        assert_eq!(fallback.version, v(14));
        assert!(!fallback.after_data);
        assert_eq!(install::read_state(&v15).unwrap(), state);
        assert_eq!(install::read_state(&v14).unwrap().extra, Map::new());
        // A failure after opening data, earlier in the chain, is still the
        // one passed on.
        edit_state(&v15, |state| {
            state.extra.insert(NODE_OPENED_FIELD.into(), true.into());
        });
        let spawn = FakeSpawn::exiting(&[Some(1), Some(USAGE_EXIT_CODE)]);
        let Launch::RunHere(Some(fallback)) = setup.launch_with(&args, &[], &spawn) else {
            panic!("expected a fallback");
        };
        assert_eq!(fallback.version, v(15));
        assert!(fallback.after_data);
    }

    #[test]
    fn exit_2_after_opening_data_or_starting_is_not_refused_arguments() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        // Exit 2 once 1.0.15 began to open the data: a counted failed
        // start after opening data, never the uncounted pass-over.
        edit_state(&v15, |state| {
            state.extra.insert(NODE_OPENED_FIELD.into(), true.into());
        });
        let spawn = FakeSpawn::exiting(&[Some(USAGE_EXIT_CODE)]);
        let Launch::RunHere(Some(fallback)) = setup.launch(&spawn) else {
            panic!("expected a fallback");
        };
        assert_eq!(spawn.started(), std::slice::from_ref(&v15));
        assert_eq!(fallback.version, v(15));
        assert!(fallback.after_data);
        assert_eq!(fallback.reason, "it exited with code 2");
        let state = install::read_state(&v15).unwrap();
        assert_eq!(state.extra[START_ATTEMPTS_FIELD], 1);
        assert_eq!(state.extra[FAILURE_FIELD]["after_data"], true);
        assert!(!setup.log().contains("refused the launch arguments"));

        // Exit 2 from a version known to work: it ended, and nothing older
        // is started on the data it used.
        edit_state(&v15, |state| {
            state.state = STATE_STARTED_OK.into();
            state.extra.clear();
        });
        let spawn = FakeSpawn::exiting(&[Some(USAGE_EXIT_CODE)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(USAGE_EXIT_CODE));
        assert_eq!(spawn.started(), std::slice::from_ref(&v15));
        assert_eq!(install::read_state(&v15).unwrap().state, STATE_STARTED_OK);
        assert!(setup.log().contains("1.0.15 ended: it exited with code 2"));

        // Exit 2 with a state that cannot be read any more: not the
        // uncounted pass-over either.
        edit_state(&v15, |state| state.state = STATE_STAGED.into());
        let spawn = FakeSpawn::default();
        let state_file = v15.join(MARKER_DIR_NAME).join(install::STATE_FILE_NAME);
        spawn.then(move |_| {
            fs::write(&state_file, b"not json").unwrap();
            Ok(Some(USAGE_EXIT_CODE))
        });
        let Launch::RunHere(Some(fallback)) = setup.launch(&spawn) else {
            panic!("expected a fallback");
        };
        assert!(fallback.after_data);
        assert_eq!(fallback.reason, "it exited with code 2");
    }

    #[test]
    fn a_version_that_cannot_be_started_is_passed_over_without_counting() {
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        let spawn = FakeSpawn::default();
        spawn.then(|_| Err(SpawnError::Start(io::Error::other("blocked"))));
        let Launch::RunHere(Some(fallback)) = setup.launch(&spawn) else {
            panic!("expected a fallback");
        };
        assert_eq!(fallback.version, v(15));
        assert_eq!(fallback.reason, "it could not be started: blocked");
        assert!(!fallback.after_data);
        assert!(install::read_state(&v15).unwrap().extra.is_empty());

        // Waiting failed: how the child ended is unknown, so nothing is
        // recorded.
        let spawn = FakeSpawn::default();
        spawn.then(|_| Err(SpawnError::Wait(io::Error::other("lost"))));
        assert_eq!(setup.launch(&spawn), Launch::Exit(1));
        assert!(install::read_state(&v15).unwrap().extra.is_empty());
    }

    #[test]
    fn a_version_that_opened_the_data_and_cannot_be_started_makes_older_versions_hold() {
        let blocked = || {
            let spawn = FakeSpawn::default();
            spawn.then(|_| Err(SpawnError::Start(io::Error::other("blocked by policy"))));
            spawn
        };
        let hold = Some(Fallback {
            version: v(15),
            reason: "it could not be started: blocked by policy".into(),
            after_data: true,
        });
        // A version known to work that the system will no longer start (an
        // antivirus or an application control policy).
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        edit_state(&v15, |state| state.state = STATE_STARTED_OK.into());
        let before = install::read_state(&v15).unwrap();
        assert_eq!(setup.launch(&blocked()), Launch::RunHere(hold.clone()));
        // Still not counted, and nothing is written.
        assert_eq!(install::read_state(&v15).unwrap(), before);

        // A version retried after it had opened the data.
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        edit_state(&v15, |state| {
            state.extra.insert(NODE_OPENED_FIELD.into(), true.into());
        });
        let before = install::read_state(&v15).unwrap();
        let v14 = installed(&setup.root, 14);
        let spawn = blocked();
        spawn.then(|_| Ok(Some(0)));
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v15.clone(), v14]);
        // The older version is told before it opens the data.
        assert_eq!(Fallback::from_env(&spawn.requests.borrow()[1].env), hold);
        assert_eq!(install::read_state(&v15).unwrap(), before);
    }

    #[test]
    fn the_install_root_is_scanned_only_when_it_is_given() {
        let mut setup = Setup::new();
        let local = setup.elsewhere("local-versions");
        let v15 = installed(&local, 15);
        let spawn = FakeSpawn::default();
        assert_eq!(setup.launch(&spawn), Launch::RunHere(None));
        // Nothing to forward to, so nothing is logged either.
        assert!(!setup.root.join(LOG_FILE_NAME).exists());
        setup.roots.push(local);
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v15]);
    }

    #[test]
    fn other_folders_are_filtered_by_name_and_at_most_64_are_checked() {
        let setup = Setup::new();
        let prefix = format!("commonfoundry-mainnet-runtime-{}-v", platform().name());
        for n in 0..70 {
            fs::create_dir(setup.root.join(format!("unrelated-{n}"))).unwrap();
            fs::create_dir(setup.root.join(format!("{prefix}1.0.{n}-copy"))).unwrap();
        }
        let v15 = installed(&setup.root, 15);
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), std::slice::from_ref(&v15));

        // Higher folders that may not be started do not count.
        let higher: Vec<PathBuf> = (0..MAX_CANDIDATES as u64)
            .map(|n| {
                let dir = installed_as(
                    &setup.root,
                    &package_name(platform(), Version::new(2, 0, n)),
                    12,
                );
                edit_state(&dir, |state| {
                    state.version = format!("2.0.{n}");
                    state.state = STATE_FAILED.into();
                });
                dir
            })
            .collect();
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v15]);

        // 64 higher version folders that may be started come first, so
        // 1.0.15 is not reached.
        for dir in &higher {
            edit_state(dir, |state| state.state = STATE_STAGED.into());
        }
        let spawn = FakeSpawn::default();
        assert_eq!(setup.launch(&spawn), Launch::RunHere(None));
    }

    #[cfg(unix)]
    #[test]
    fn a_root_any_user_may_change_is_not_scanned_unless_sticky() {
        use std::os::unix::fs::PermissionsExt;
        let setup = Setup::new();
        let v15 = installed(&setup.root, 15);
        fs::set_permissions(&setup.root, fs::Permissions::from_mode(0o777)).unwrap();
        let spawn = FakeSpawn::default();
        assert_eq!(setup.launch(&spawn), Launch::RunHere(None));
        fs::set_permissions(&setup.root, fs::Permissions::from_mode(0o1777)).unwrap();
        let spawn = FakeSpawn::exiting(&[Some(0)]);
        assert_eq!(setup.launch(&spawn), Launch::Exit(0));
        assert_eq!(spawn.started(), [v15]);
        fs::set_permissions(&setup.root, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn a_fallback_reads_back_from_the_environment() {
        let fallback = Fallback {
            version: v(17),
            reason: "it exited with code 101".into(),
            after_data: true,
        };
        assert_eq!(
            Fallback::from_env(&child_env(&[], Some(&fallback), None)),
            Some(fallback.clone())
        );
        let before = Fallback {
            after_data: false,
            ..fallback
        };
        assert_eq!(
            Fallback::from_env(&child_env(&[], Some(&before), None)),
            Some(before)
        );
        assert_eq!(Fallback::from_env(&child_env(&[], None, None)), None);
        assert_eq!(
            Fallback::from_env(&env(&[(FALLBACK_FROM_ENV, "1.0.17-rc.1")])),
            None
        );
        // Without the data flag it counts as after opening data.
        let long = "x".repeat(2 * MAX_REASON_CHARS);
        assert_eq!(
            Fallback::from_env(&env(&[
                (FALLBACK_FROM_ENV, "1.0.17"),
                (FALLBACK_REASON_ENV, &long)
            ])),
            Some(Fallback {
                version: v(17),
                reason: "x".repeat(MAX_REASON_CHARS),
                after_data: true,
            })
        );
        // A forwarder passes on none of the update variables it got, and
        // names itself as the exe the user launched.
        let anchor = std::env::current_exe().unwrap();
        let inherited = child_env(
            &env(&[
                (FALLBACK_FROM_ENV, "1.0.16"),
                (FALLBACK_REASON_ENV, "old"),
                (LAUNCHED_FROM_ENV, "/elsewhere/common-foundry-wallet"),
            ]),
            None,
            Some(&anchor),
        );
        let mut expected = env(&[(FORWARDED_ENV, "1")]);
        expected.push((LAUNCHED_FROM_ENV.into(), anchor.clone().into()));
        assert_eq!(inherited, expected);
        assert_eq!(launched_from(&inherited), Some(anchor));
        assert_eq!(
            launched_from(&env(&[(LAUNCHED_FROM_ENV, "relative")])),
            None
        );
        assert_eq!(launched_from(&[]), None);
    }

    #[test]
    fn the_log_keeps_one_older_file() {
        let temp = TempDir::new();
        let log = temp.0.join(LOG_FILE_NAME);
        log_line(&temp.0, "first");
        assert!(fs::read_to_string(&log).unwrap().ends_with("first\n"));
        let file = OpenOptions::new().write(true).open(&log).unwrap();
        file.set_len(MAX_LOG_BYTES).unwrap();
        drop(file);
        log_line(&temp.0, "second");
        let older = temp.0.join(format!("{LOG_FILE_NAME}.1"));
        assert_eq!(fs::metadata(&older).unwrap().len(), MAX_LOG_BYTES);
        assert!(fs::read_to_string(&log).unwrap().ends_with("second\n"));
        // A log that is not a plain file is left alone.
        fs::remove_file(&log).unwrap();
        fs::create_dir(&log).unwrap();
        log_line(&temp.0, "third");
        assert!(log.is_dir());
        fs::remove_dir(&log).unwrap();
        #[cfg(unix)]
        {
            let target = temp.0.join("target");
            fs::write(&target, b"kept").unwrap();
            std::os::unix::fs::symlink(&target, &log).unwrap();
            log_line(&temp.0, "fourth");
            assert_eq!(fs::read(&target).unwrap(), b"kept");
            fs::remove_file(&log).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_full_log_that_cannot_be_moved_aside_starts_over() {
        use std::os::windows::fs::OpenOptionsExt;
        let temp = TempDir::new();
        let log = temp.0.join(LOG_FILE_NAME);
        log_line(&temp.0, "first");
        let file = OpenOptions::new().write(true).open(&log).unwrap();
        file.set_len(MAX_LOG_BYTES).unwrap();
        drop(file);
        // Held without delete sharing, as an antivirus scan may hold it.
        let held = OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2)
            .open(&log)
            .unwrap();
        log_line(&temp.0, "second");
        drop(held);
        assert!(!temp.0.join(format!("{LOG_FILE_NAME}.1")).exists());
        let text = fs::read_to_string(&log).unwrap();
        assert!(text.len() < 200 && text.ends_with("second\n"), "{text:?}");
    }

    /// The helper the real spawn test starts: this test binary, running only
    /// this test. Without its variable it does nothing.
    #[test]
    fn spawn_helper() {
        let Some(out) = std::env::var_os(HELPER_OUT_ENV) else {
            return;
        };
        let args: Vec<String> = std::env::args_os()
            .skip(1)
            .map(|arg| arg.into_string().unwrap())
            .collect();
        let seen = json!({
            "args": args,
            "forwarded": std::env::var(FORWARDED_ENV).ok(),
            "stray": std::env::var("CMFD_UPDATE_STRAY").ok(),
        });
        fs::write(out, serde_json::to_vec(&seen).unwrap()).unwrap();
        let code = std::env::var(HELPER_EXIT_ENV)
            .ok()
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        std::process::exit(code);
    }

    #[test]
    fn the_system_spawn_starts_the_exe_it_holds_open_with_exact_args_and_env() {
        let temp = TempDir::new();
        let out = temp.0.join("helper.json");
        let exe = std::env::current_exe().unwrap();
        // Held as the forwarder holds a verified exe: on Windows nobody may
        // write, rename or delete it, and it must still start.
        let held = install::open_denying_writes(&exe).unwrap();
        #[cfg(windows)]
        assert!(OpenOptions::new().write(true).open(&exe).is_err());
        // libtest takes everything after `--` as more name filters, and
        // `--exact` keeps them from matching any other test.
        let passed = [
            "--data-dir=D:\\CF Wallet\\data",
            "say \"hi\" \\",
            "trailing\\",
            "\u{fc}n\u{ef}",
        ];
        let mut args = os(&[HELPER_TEST, "--exact", "--quiet", "--test-threads=1", "--"]);
        args.extend(os(&passed));
        let mut parent: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        parent.extend(env(&[
            (HELPER_OUT_ENV, out.to_str().unwrap()),
            (HELPER_EXIT_ENV, "7"),
            ("CMFD_UPDATE_STRAY", "1"),
        ]));
        let request = SpawnRequest {
            exe: exe.clone(),
            args: args.clone(),
            env: child_env(&parent, None, None),
        };
        let code = SystemSpawn.run(&request, held).unwrap();
        assert_eq!(code, Some(7));
        let seen: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        let args: Vec<String> = args
            .into_iter()
            .map(|arg| arg.into_string().unwrap())
            .collect();
        assert_eq!(seen["args"], json!(args));
        assert_eq!(seen["forwarded"], "1");
        assert_eq!(seen["stray"], Value::Null);

        let missing = SpawnRequest {
            exe: temp.0.join(wallet_name()),
            ..request
        };
        let held = File::open(&exe).unwrap();
        assert!(matches!(
            SystemSpawn.run(&missing, held),
            Err(SpawnError::Start(_))
        ));
    }
}
