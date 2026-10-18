//! Desktop wallet auto-updater (1.0.16).
//!
//! Only `production-mainnet` builds carry the updater. Every other build gets
//! a stub that reports `unsupported`, so dev, testnet and RC wallets never
//! check for, download or forward to a mainnet release.
//!
//! [`UpdaterState`] runs the checks: the first one
//! [`settings::FIRST_CHECK_DELAY`] after the wallet window was set up (locked
//! or not), then about every [`settings::CHECK_INTERVAL`], and whenever
//! "Check now" or "Download" asks. One worker thread does all of it, so one
//! check runs at a time. A check offers the highest newer signed release
//! ([`release::discover`]); with "Update automatically" ON (or after
//! "Download") it is downloaded and installed beside this one
//! ([`install::install`]), and the wallet offers "Restart to update". The
//! highest release is always the one offered, also while a lower one is
//! installed and not started yet: the forwarder starts the highest good
//! version, and "Remove old versions" removes the others later.
//!
//! An install that failed in a way that would only repeat (antivirus, a bad
//! package, a bank that needs the user's consent to copy) is not tried
//! again by a scheduled check in this run: only "Download" retries it. The
//! record is kept for this run only, so the next launch tries it once more.
//!
//! The `updater-e2e` feature (end-to-end tests only, never a release) adds
//! the test key ([`sshsig`]) and a `file://` release source
//! (`CMFD_UPDATER_E2E_SOURCE`), and changes [`BUILD_IDENTITY`] and the
//! wallet's runtime identity, so such a build can never pass as a release.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cmfd_node::NodeClientError;

// Pure verification with no side effects, compiled into every build so the
// CI test run (a testnet build) covers it too.
mod release;
mod settings;
mod sshsig;
// Runs the system curl, but only when called. Its request logic is tested
// with a fake curl process in every build.
mod fetch;
// Installs a verified release beside the running one with the system tar.
// Tested with a synthetic package in a temp dir in every build. Only a
// mainnet wallet links mining inputs from other versions, so elsewhere
// that part of `inputs` is used by its tests alone.
#[cfg_attr(not(feature = "production-mainnet"), allow(dead_code))]
mod inputs;
mod install;
// Starts the newest good installed version at launch. The start itself is
// behind a trait; one test starts this test binary for real.
pub(crate) mod forward;
// The running wallet's side of an update: the restart guard, start success
// and the hooks around opening the wallet data. The runtime calls into it.
pub(crate) mod lifecycle;
// The relaunch of "Restart to update" and the new version's wait for it.
pub(crate) mod restart;
// The Tauri commands of the Updates card.
pub(crate) mod commands;

use forward::Fallback;
use install::{InstallError, InstallTarget, Staging, SystemHost};
use release::{Discovery, Platform, Transport, VerifiedRelease, Version};
use settings::{UpdateMode, UpdateSettings};

/// What kind of build this is. Only a build without the `updater-e2e`
/// feature may ever be released.
#[cfg(not(feature = "updater-e2e"))]
pub(crate) const BUILD_IDENTITY: &str = "release";
/// What kind of build this is. This one trusts a published test key and
/// `file://` sources: it must never be released.
#[cfg(feature = "updater-e2e")]
pub(crate) const BUILD_IDENTITY: &str = "updater-e2e-test-build-never-release";

/// In `updater-e2e` builds only: a `file://` URL that stands in for GitHub.
/// `<base>/<owner>/<repo>/releases/download/<tag>/<file>` holds the release
/// files and `<base>/api/<owner>/<repo>/releases-page-<n>.json` the release
/// list.
#[cfg(feature = "updater-e2e")]
const E2E_SOURCE_ENV: &str = "CMFD_UPDATER_E2E_SOURCE";
/// How long closing the wallet waits for a check or install to stop.
const STOP_WAIT: Duration = Duration::from_secs(5);
const STOP_POLL: Duration = Duration::from_millis(50);
/// What "Run anyway" must be confirmed with (any case, outer spaces
/// ignored).
pub(crate) const RUN_ANYWAY_CONFIRMATION: &str = "run anyway";

/// What the updater is doing, for the Updates card.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum UpdaterStatus {
    /// This build has no updater, or this wallet is not a release package.
    Unsupported {
        reason: &'static str,
    },
    /// `--no-auto-update` or `CMFD_NO_AUTO_UPDATE=1`.
    Disabled,
    /// No check ran yet.
    Idle,
    Checking,
    UpToDate,
    /// A newer release; "Update automatically" is OFF, so it waits for
    /// "Download".
    Available {
        version: String,
    },
    Downloading {
        version: String,
    },
    /// Installed beside this one: "Restart to update", or it starts on the
    /// next launch.
    Ready {
        version: String,
        folder: String,
    },
    /// The highest newer release could not be fetched or verified. Nothing
    /// lower is installed instead.
    NotVerified {
        version: String,
        reason: String,
    },
    /// The release list, or a signed file of the highest newer release,
    /// could not be read.
    CheckFailed {
        reason: String,
    },
    /// A newer version is installed but files of it are missing or changed
    /// (an antivirus quarantine, say), so it would not start; "Download"
    /// installs it again beside the damaged folder.
    Damaged {
        version: String,
        reason: String,
    },
    /// The model bank cannot be hard-linked; "Download" with consent copies
    /// it.
    NeedsCopyConsent {
        version: String,
        bytes: u64,
    },
    /// This update must be installed by hand.
    Manual {
        version: String,
        reason: String,
    },
    InstallFailed {
        version: String,
        reason: String,
        /// The next check tries again by itself.
        retry_automatically: bool,
    },
    /// The release is installed but failed to start too often.
    FailedToStart {
        version: String,
        reason: String,
    },
}

/// A newer version that failed to start, so this one runs instead.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct FallbackStatus {
    pub(crate) version: String,
    pub(crate) reason: String,
    /// It had opened the wallet data.
    pub(crate) after_data: bool,
    /// This wallet waits for "Retry" or "Run anyway" before it opens them.
    pub(crate) held: bool,
}

/// An older version that "Remove old versions" deletes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct OldVersion {
    pub(crate) path: String,
    /// The size of the files in the folder. A file hard-linked into
    /// another version (the model bank, prepared mining caches) counts in
    /// full although removing this folder frees none of it, so this is not
    /// the space "Remove" frees and the card must not call it that.
    pub(crate) bytes: u64,
}

/// Everything the Updates card shows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct UpdateStatus {
    /// [`BUILD_IDENTITY`].
    pub(crate) build: &'static str,
    pub(crate) current_version: &'static str,
    /// "Update automatically".
    pub(crate) automatic: bool,
    pub(crate) disabled_by_launch_option: bool,
    pub(crate) status: UpdaterStatus,
    /// Unix seconds.
    pub(crate) last_checked_at: Option<u64>,
    /// Checks in a row that could not read the release list, in this run.
    pub(crate) check_failures: u32,
    /// Unix seconds: since when they have failed (the last check that read
    /// the list, else the first that failed); `None` while they work.
    pub(crate) check_failed_since: Option<u64>,
    pub(crate) fallback: Option<FallbackStatus>,
    /// Why the last "Restart to update" could not start the new version.
    pub(crate) restart_failed: Option<String>,
    pub(crate) old_versions: Vec<OldVersion>,
}

/// Where this wallet runs from, for a supported build.
#[derive(Debug, Clone)]
struct Place {
    running: Version,
    platform: Platform,
    /// The running package folder.
    own: PathBuf,
    /// Where new versions are installed ([`install::install_root`]).
    iroot: PathBuf,
    registry: PathBuf,
    /// The exe the user launched, when a forwarder started this one.
    launched_from: Option<PathBuf>,
}

impl Place {
    fn of_this_wallet() -> Result<Self, &'static str> {
        if !cfg!(feature = "production-mainnet") {
            return Err("automatic updates are built only into mainnet wallets");
        }
        let running = Version::running().ok_or("this wallet is not a release version")?;
        let platform =
            Platform::current().ok_or("automatic updates are not available on this platform")?;
        let exe = std::env::current_exe().map_err(|_| "this wallet cannot find its own folder")?;
        let own = exe
            .parent()
            .ok_or("this wallet cannot find its own folder")?
            .to_path_buf();
        if !own.join(install::PACKAGE_MANIFEST_NAME).is_file() {
            return Err("this wallet does not run from a release package folder");
        }
        let root = own
            .parent()
            .ok_or("this wallet's package folder has no parent folder")?;
        let registry = install::registry_dir(&|name| std::env::var_os(name))
            .ok_or("this user has no local application data folder")?;
        let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        Ok(Self {
            running,
            platform,
            iroot: install::install_root(root),
            own,
            registry,
            launched_from: forward::launched_from(&env),
        })
    }

    /// Creates the install root when it is not the folder that holds this
    /// package: the cloud-synced case puts versions in
    /// `%LOCALAPPDATA%\CommonFoundry\versions`, which nothing else makes.
    fn ensure_redirected_root(&self) -> io::Result<()> {
        if self.own.parent() != Some(self.iroot.as_path()) {
            fs::create_dir_all(&self.iroot)?;
        }
        Ok(())
    }
}

/// What the worker was asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request {
    Check,
    /// "Download": install even with "Update automatically" OFF, and even
    /// an install that failed before.
    Download {
        allow_copy: bool,
    },
}

struct Inner {
    automatic: bool,
    status: UpdaterStatus,
    last_checked_at: Option<u64>,
    /// See [`UpdateStatus::check_failures`].
    check_failures: u32,
    check_failed_since: Option<u64>,
    /// When a check last read the release list.
    last_good_check_at: Option<u64>,
    request: Option<Request>,
    /// An install that would only fail the same way again: not tried again
    /// by a scheduled check in this run.
    refused: Option<(Version, [u8; 32], UpdaterStatus)>,
    old_versions: Vec<OldVersion>,
}

impl Inner {
    fn new(automatic: bool, status: UpdaterStatus) -> Self {
        Self {
            automatic,
            status,
            last_checked_at: None,
            check_failures: 0,
            check_failed_since: None,
            last_good_check_at: None,
            request: None,
            refused: None,
            old_versions: Vec::new(),
        }
    }

    /// Counts a check that ended at `now`: `list_read` when it read the
    /// release list, whatever it found there.
    fn record_check(&mut self, list_read: bool, now: u64) {
        self.last_checked_at = Some(now);
        if list_read {
            self.check_failures = 0;
            self.check_failed_since = None;
            self.last_good_check_at = Some(now);
        } else {
            self.check_failures = self.check_failures.saturating_add(1);
            self.check_failed_since
                .get_or_insert(self.last_good_check_at.unwrap_or(now));
        }
    }
}

struct Shared {
    place: Result<Place, &'static str>,
    disabled_by_launch_option: bool,
    data_dir: Option<PathBuf>,
    fallback: Option<Fallback>,
    restart_failed: Option<String>,
    /// The worker thread could not be started: nothing would run a request.
    no_worker: AtomicBool,
    cancel: Arc<AtomicBool>,
    inner: Mutex<Inner>,
    wake: Condvar,
    /// Serializes saves of `updates.json`.
    saving: Mutex<()>,
}

/// The updater of a running wallet, managed by Tauri.
pub(crate) struct UpdaterState {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl UpdaterState {
    /// Starts the updater: `data_dir` holds `updates.json`; `no_auto_update`
    /// is `--no-auto-update`; `fallback` is the newer version that failed
    /// to start before this one ran, if any. Only a supported wallet that
    /// is not turned off gets the worker thread.
    pub(crate) fn start(
        data_dir: Option<PathBuf>,
        no_auto_update: bool,
        fallback: Option<Fallback>,
    ) -> Self {
        let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        let disabled_by_launch_option = no_auto_update || disabled_by_environment(&env);
        let settings = data_dir.as_deref().map(settings::load).unwrap_or_default();
        let place = Place::of_this_wallet();
        let status = match (&place, disabled_by_launch_option) {
            (Err(reason), _) => UpdaterStatus::Unsupported { reason },
            (Ok(_), true) => UpdaterStatus::Disabled,
            (Ok(_), false) => UpdaterStatus::Idle,
        };
        let runs = status == UpdaterStatus::Idle;
        let shared = Arc::new(Shared {
            place,
            disabled_by_launch_option,
            data_dir,
            fallback,
            restart_failed: restart::spawn_failed_reason(&env),
            no_worker: AtomicBool::new(false),
            cancel: Arc::new(AtomicBool::new(false)),
            inner: Mutex::new(Inner::new(settings.automatic, status)),
            wake: Condvar::new(),
            saving: Mutex::new(()),
        });
        let worker = if runs {
            let worker = Arc::clone(&shared);
            let spawned = thread::Builder::new()
                .name("cmfd-updater".to_owned())
                .spawn(move || worker.run_worker());
            if spawned.is_err() {
                shared.no_worker.store(true, Ordering::SeqCst);
                shared.set_status(UpdaterStatus::CheckFailed {
                    reason: "the update worker could not start; reopen the wallet".into(),
                });
            }
            spawned.ok()
        } else {
            None
        };
        Self {
            shared,
            worker: Mutex::new(worker),
        }
    }

    /// For the Updates card. `held`: the node waits for "Retry" or "Run
    /// anyway".
    pub(crate) fn status(&self, held: bool) -> UpdateStatus {
        let inner = self.shared.lock();
        UpdateStatus {
            build: BUILD_IDENTITY,
            current_version: env!("CARGO_PKG_VERSION"),
            automatic: inner.automatic,
            disabled_by_launch_option: self.shared.disabled_by_launch_option,
            status: inner.status.clone(),
            last_checked_at: inner.last_checked_at,
            check_failures: inner.check_failures,
            check_failed_since: inner.check_failed_since,
            fallback: self
                .shared
                .fallback
                .as_ref()
                .map(|fallback| FallbackStatus {
                    version: fallback.version.to_string(),
                    reason: fallback.reason.clone(),
                    after_data: fallback.after_data,
                    held,
                }),
            restart_failed: self.shared.restart_failed.clone(),
            old_versions: inner.old_versions.clone(),
        }
    }

    /// Saves "Update automatically". Turning it ON while an update is only
    /// available checks again at once, which downloads it.
    pub(crate) fn set_automatic(&self, automatic: bool) -> Result<(), NodeClientError> {
        self.shared.usable()?;
        let data_dir = self.shared.data_dir.as_deref().ok_or_else(|| {
            updater_error(
                "update_settings_unavailable",
                "The wallet data folder is unavailable, so the update setting cannot be saved.",
            )
        })?;
        {
            let _saving = self
                .shared
                .saving
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            settings::save(data_dir, &UpdateSettings { automatic }).map_err(|error| {
                updater_error(
                    "update_settings_unwritable",
                    format!("The update setting could not be saved: {error}"),
                )
            })?;
        }
        let mut inner = self.shared.lock();
        inner.automatic = automatic;
        if automatic && matches!(inner.status, UpdaterStatus::Available { .. }) {
            inner.request.get_or_insert(Request::Check);
            self.shared.wake.notify_all();
        }
        Ok(())
    }

    /// "Check now".
    pub(crate) fn check_now(&self) -> Result<(), NodeClientError> {
        self.shared.ask(Request::Check)
    }

    /// "Download": installs the highest newer release whatever the switch
    /// says, copying the bank if `allow_copy` and it cannot be linked.
    pub(crate) fn download(&self, allow_copy: bool) -> Result<(), NodeClientError> {
        self.shared.ask(Request::Download { allow_copy })
    }

    /// Where the updater log goes.
    pub(crate) fn log_root(&self) -> Option<PathBuf> {
        self.shared
            .place
            .as_ref()
            .ok()
            .map(|place| place.iroot.clone())
    }

    /// For "Restart to update": the version the forwarder will start,
    /// whatever the last check said (it failed, or a higher release is only
    /// offered). Each installed newer version is checked as the forwarder
    /// checks it, every listed file hashed ([`install::verify_installed`]),
    /// so a damaged folder is refused here with its reason, not skipped
    /// silently at the relaunch. Reads about 150 MB: not on an async
    /// command thread.
    pub(crate) fn restart_target(&self) -> Result<Version, NodeClientError> {
        let place = self.shared.usable()?;
        let mut damaged = None;
        for (version, dir) in installed_updates(place) {
            match verify_for_start(place, &dir) {
                Ok(()) => return Ok(version),
                Err(error) => {
                    damaged.get_or_insert(error);
                }
            }
        }
        Err(damaged.unwrap_or_else(|| {
            updater_error("update_not_ready", "No update is ready to start yet.")
        }))
    }

    /// After "Run anyway": the failure of the version this wallet held for
    /// is marked chosen in each of its folders this user's updater
    /// installed ([`forward::record_run_anyway`]), so later launches no
    /// longer hold for it. Best effort and logged: if it cannot be written,
    /// the next launch holds again, which is the safe side.
    pub(crate) fn record_run_anyway(&self) {
        let (Ok(place), Some(fallback)) = (&self.shared.place, &self.shared.fallback) else {
            return;
        };
        if !fallback.after_data {
            return;
        }
        for dir in held_folders(place, fallback.version) {
            let line = match forward::record_run_anyway(&dir) {
                Ok(()) => format!(
                    "run anyway after {} failed: recorded in {}",
                    fallback.version,
                    dir.display()
                ),
                Err(error) => format!(
                    "run anyway after {} failed: cannot record it in {}: {error}",
                    fallback.version,
                    dir.display()
                ),
            };
            forward::log_line(&place.iroot, &line);
        }
    }

    /// "Retry" for `version`: its failed starts are forgotten, so the
    /// forwarder starts it again.
    pub(crate) fn retry(&self, version: &str) -> Result<(), NodeClientError> {
        let place = self.shared.usable()?;
        let version = Version::parse(version.trim())
            .filter(|version| *version > place.running)
            .ok_or_else(|| {
                updater_error(
                    "update_version_invalid",
                    "Only a newer installed version can be retried.",
                )
            })?;
        // The forwarder would skip a damaged copy; after a reinstall, the
        // new copy is the one to retry.
        let mut damaged = None;
        let mut intact = None;
        for dir in installed_folders(place, version)
            .into_iter()
            .filter(|dir| install::is_registered_install(dir, place.platform, &place.registry))
        {
            match verify_for_start(place, &dir) {
                Ok(()) => {
                    intact = Some(dir);
                    break;
                }
                Err(error) => {
                    damaged.get_or_insert(error);
                }
            }
        }
        let Some(dir) = intact else {
            return Err(damaged.unwrap_or_else(|| {
                updater_error(
                    "update_not_installed",
                    format!("Version {version} is not installed beside this wallet."),
                )
            }));
        };
        forward::reset_failed_starts(&dir).map_err(|error| {
            updater_error(
                "update_state_unwritable",
                format!("Version {version} could not be reset for a retry: {error}"),
            )
        })?;
        forward::log_line(
            &place.iroot,
            &format!("retry of {version}: its failed starts were reset"),
        );
        Ok(())
    }

    /// "Remove old versions": deletes the versions older than the kept
    /// previous one. The error names each folder that stayed.
    pub(crate) fn remove_old_versions(&self) -> Result<(), NodeClientError> {
        let place = self.shared.usable()?;
        let mut failures = Vec::new();
        for dir in removable(place) {
            match install::remove_version(&place.iroot, &dir, &place.registry) {
                Ok(()) => forward::log_line(&place.iroot, &format!("removed {}", dir.display())),
                Err(error) => failures.push(format!("{}: {error}", dir.display())),
            }
        }
        let old = old_versions(place);
        self.shared.lock().old_versions = old;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(updater_error(
                "update_remove_failed",
                format!(
                    "Some old versions could not be removed: {}",
                    failures.join("; ")
                ),
            ))
        }
    }

    /// Stops the worker when the wallet closes: a running check or install
    /// is cancelled and given [`STOP_WAIT`] to end.
    pub(crate) fn stop(&self) {
        {
            // Under the lock, so the worker cannot miss the wake between its
            // check of the flag and its wait.
            let _inner = self.shared.lock();
            self.shared.cancel.store(true, Ordering::SeqCst);
            self.shared.wake.notify_all();
        }
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(worker) = worker {
            let deadline = Instant::now() + STOP_WAIT;
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(STOP_POLL);
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn usable(&self) -> Result<&Place, NodeClientError> {
        match &self.place {
            Err(reason) => Err(updater_error("update_unsupported", *reason)),
            Ok(_) if self.disabled_by_launch_option => Err(updater_error(
                "update_disabled",
                "Updates are turned off for this run by --no-auto-update or CMFD_NO_AUTO_UPDATE=1.",
            )),
            Ok(place) => Ok(place),
        }
    }

    fn ask(&self, request: Request) -> Result<(), NodeClientError> {
        self.usable()?;
        if self.no_worker.load(Ordering::SeqCst) {
            return Err(updater_error(
                "update_worker_unavailable",
                "The update worker could not start. Reopen the wallet to check for updates.",
            ));
        }
        let mut inner = self.lock();
        // A download asked for is never turned back into a plain check.
        if !matches!(inner.request, Some(Request::Download { .. })) {
            inner.request = Some(request);
        }
        self.wake.notify_all();
        Ok(())
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    fn set_status(&self, status: UpdaterStatus) {
        self.lock().status = status;
    }

    fn run_worker(&self) {
        let Ok(place) = &self.place else {
            return;
        };
        let old = old_versions(place);
        self.lock().old_versions = old;
        let mut next = Instant::now() + settings::FIRST_CHECK_DELAY;
        loop {
            let request = {
                let mut inner = self.lock();
                loop {
                    if self.cancelled() {
                        return;
                    }
                    if let Some(request) = inner.request.take() {
                        break request;
                    }
                    let now = Instant::now();
                    if now >= next {
                        next = now + settings::next_check_interval();
                        break Request::Check;
                    }
                    inner = self
                        .wake
                        .wait_timeout(inner, next - now)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            };
            let (status, list_read) = self.check(place, request);
            if self.cancelled() {
                return;
            }
            let old = old_versions(place);
            let mut inner = self.lock();
            inner.status = status;
            inner.record_check(list_read, lifecycle::unix_now());
            inner.old_versions = old;
        }
    }

    /// One check, and whether it read the release list.
    fn check(&self, place: &Place, request: Request) -> (UpdaterStatus, bool) {
        self.set_status(UpdaterStatus::Checking);
        if let Err(error) = place.ensure_redirected_root() {
            let reason = format!("cannot create {}: {error}", place.iroot.display());
            return (unwritable_root(reason), false);
        }
        let curl = match install::scratch_dir(&place.iroot) {
            Ok(scratch) => match system_curl(scratch, Arc::clone(&self.cancel)) {
                Some(curl) => curl,
                None => {
                    let failed = UpdaterStatus::CheckFailed {
                        reason: "curl was not found on this computer".into(),
                    };
                    return (failed, false);
                }
            },
            Err(error) => return (unwritable_root(error.to_string()), false),
        };
        let source = Source {
            curl: &curl,
            base: e2e_source(),
        };
        let (status, list_read) = match release::discover(&source, place.platform, place.running) {
            Discovery::UpToDate => (UpdaterStatus::UpToDate, true),
            Discovery::Unknown { reason } => (UpdaterStatus::CheckFailed { reason }, false),
            Discovery::NotVerified { version, error } => {
                // Kept in the log even when an installed update is shown
                // instead: a release that fails its checks may be tampered
                // with.
                forward::log_line(
                    &place.iroot,
                    &format!("release {version} not verified: {error}"),
                );
                let not_verified = UpdaterStatus::NotVerified {
                    version: version.to_string(),
                    reason: error.to_string(),
                };
                (not_verified, true)
            }
            Discovery::Available(release) => {
                let status = self.offer(place, &release, request, &|allow_copy| {
                    install_release(place, &source, &release, allow_copy, &self.cancel)
                });
                return (status, true);
            }
        };
        (or_installed(place, status), list_read)
    }

    /// What to do with the highest newer release: report it, or install it
    /// with `run_install` (the argument is the user's consent to copy the
    /// bank).
    fn offer(
        &self,
        place: &Place,
        release: &VerifiedRelease,
        request: Request,
        run_install: &dyn Fn(bool) -> Result<install::Installed, InstallError>,
    ) -> UpdaterStatus {
        let version = release.version;
        if let Some(reason) = failed_start(place, version) {
            return UpdaterStatus::FailedToStart {
                version: version.to_string(),
                reason,
            };
        }
        let copies =
            install::installed_copies(&place.iroot, place.platform, release, &place.registry);
        let mut damaged = None;
        for dir in &copies {
            let checked = install::check_release_files(
                dir,
                place.platform,
                release,
                cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID,
            );
            match checked.map_err(|error| without_folder(dir, &error)) {
                Ok(()) => return ready(version, dir),
                Err(reason) => {
                    damaged.get_or_insert(reason);
                }
            }
        }
        // Only "Download" installs a damaged version again.
        if let Some(reason) = damaged
            && !matches!(request, Request::Download { .. })
        {
            return UpdaterStatus::Damaged {
                version: version.to_string(),
                reason,
            };
        }
        let allow_copy = match request {
            Request::Download { allow_copy } => allow_copy,
            Request::Check => {
                let inner = self.lock();
                if let Some((refused, sums, status)) = &inner.refused
                    && *refused == version
                    && *sums == release.sums_sha256
                {
                    return status.clone();
                }
                let mode = UpdateMode::resolve(
                    self.disabled_by_launch_option,
                    &UpdateSettings {
                        automatic: inner.automatic,
                    },
                );
                if mode != UpdateMode::Automatic {
                    return UpdaterStatus::Available {
                        version: version.to_string(),
                    };
                }
                false
            }
        };
        self.set_status(UpdaterStatus::Downloading {
            version: version.to_string(),
        });
        let error = match run_install(allow_copy) {
            Ok(installed) => {
                forward::log_line(
                    &place.iroot,
                    &format!("installed {version} in {}", installed.dir.display()),
                );
                self.lock().refused = None;
                return ready(version, &installed.dir);
            }
            Err(error) => error,
        };
        if error == InstallError::Cancelled {
            return UpdaterStatus::Idle;
        }
        forward::log_line(
            &place.iroot,
            &format!("install of {version} failed: {error}"),
        );
        let status = install_failure_status(version, &error);
        if !error.retry_automatically() {
            self.lock().refused = Some((version, release.sums_sha256, status.clone()));
        }
        status
    }
}

/// `status` of a check that found nothing to install, unless a newer
/// version is installed already: a failed check or a broken higher release
/// never hides it, since the forwarder starts it at the next launch anyway.
/// A highest version whose files are missing is reported damaged, not
/// ready, unless another copy of it is intact.
fn or_installed(place: &Place, status: UpdaterStatus) -> UpdaterStatus {
    let installed = installed_updates(place);
    let Some(&(highest, _)) = installed.first() else {
        return status;
    };
    let mut damaged = None;
    for (version, path) in installed.iter().filter(|(version, _)| *version == highest) {
        match check_files(place, path) {
            Ok(()) => return ready(*version, path),
            Err(reason) => {
                damaged.get_or_insert(reason);
            }
        }
    }
    UpdaterStatus::Damaged {
        version: highest.to_string(),
        reason: damaged.unwrap_or_default(),
    }
}

/// The checks of an installed version that read no file contents
/// ([`install::check_installed_files`]), with the reason it failed them.
fn check_files(place: &Place, dir: &Path) -> Result<(), String> {
    install::check_installed_files(
        dir,
        place.platform,
        cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID,
        &place.registry,
    )
    .map_err(|error| without_folder(dir, &error))
}

/// Why `dir` failed a check, without the folder path the check puts first.
fn without_folder(dir: &Path, error: &install::MarkerError) -> String {
    let prefix = format!("{}: ", dir.display());
    error.0.strip_prefix(&prefix).unwrap_or(&error.0).to_owned()
}

/// A check that could not create its folders in the install root: no
/// update can be installed there either.
fn unwritable_root(reason: String) -> UpdaterStatus {
    UpdaterStatus::CheckFailed {
        reason: format!(
            "{reason}. Updates cannot be installed in this folder, so install the next version by hand"
        ),
    }
}

/// The versions above the running one that this user's updater installed
/// beside it and that the forwarder may still start
/// ([`forward::may_start`]), highest first. The marker checks only; the
/// forwarder also hashes every listed file ([`verify_for_start`]).
fn installed_updates(place: &Place) -> Vec<(Version, PathBuf)> {
    let Ok(entries) = fs::read_dir(&place.iroot) else {
        return Vec::new();
    };
    let mut found: Vec<(Version, PathBuf)> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter_map(|path| {
            let version = install::folder_version(&path, place.platform)?;
            (version > place.running && install::is_real_dir(&path)).then_some((version, path))
        })
        .filter(|(_, path)| {
            install::read_state(path).is_some_and(|state| forward::may_start(&state))
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    found.retain(|(_, path)| install::is_registered_install(path, place.platform, &place.registry));
    found
}

/// The full check the forwarder makes before it starts `dir`
/// ([`install::verify_installed`]); a failure is logged and explained.
fn verify_for_start(place: &Place, dir: &Path) -> Result<(), NodeClientError> {
    install::verify_installed(
        dir,
        place.platform,
        cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID,
        &place.registry,
    )
    .map(drop)
    .map_err(|error| {
        forward::log_line(&place.iroot, &format!("will not start {}", error.0));
        updater_error(
            "update_damaged",
            format!(
                "The installed update failed its file check, so it would not start: {}. A file in its folder was changed or removed (antivirus software can do this). Reinstall it from Network → Updates, or delete that version folder so that the update can be installed again.",
                error.0
            ),
        )
    })
}

fn ready(version: Version, dir: &Path) -> UpdaterStatus {
    UpdaterStatus::Ready {
        version: version.to_string(),
        folder: dir.display().to_string(),
    }
}

fn install_failure_status(version: Version, error: &InstallError) -> UpdaterStatus {
    let version = version.to_string();
    match error {
        InstallError::Inputs(inputs::InputsError::NeedsCopyConsent { bytes }) => {
            UpdaterStatus::NeedsCopyConsent {
                version,
                bytes: *bytes,
            }
        }
        InstallError::Inputs(
            error @ (inputs::InputsError::BankChanged | inputs::InputsError::NoBank),
        ) => UpdaterStatus::Manual {
            version,
            reason: error.to_string(),
        },
        error => UpdaterStatus::InstallFailed {
            version,
            reason: error.to_string(),
            retry_automatically: error.retry_automatically(),
        },
    }
}

fn install_release(
    place: &Place,
    source: &Source<'_>,
    release: &VerifiedRelease,
    allow_copy: bool,
    cancel: &AtomicBool,
) -> Result<install::Installed, InstallError> {
    let staging = Staging::open(&place.iroot, release.version)?;
    let url = source.url(&release.asset_url);
    staging.archive(release, &SystemHost, |dir| {
        source.curl.download_archive(
            &url,
            dir,
            &release.asset_name,
            release.asset_size,
            &release.asset_sha256,
        )
    })?;
    install::install(
        staging,
        release,
        &InstallTarget {
            iroot: &place.iroot,
            running: &place.own,
            platform: place.platform,
            network_id: cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID,
            allow_bank_copy: allow_copy,
            registry: &place.registry,
        },
        &SystemHost,
        cancel,
    )
}

/// The folders of `version` in the install root, by name.
fn installed_folders(place: &Place, version: Version) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(&place.iroot) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            install::is_real_dir(path)
                && install::folder_version(path, place.platform) == Some(version)
        })
        .collect()
}

/// The folders of `version` with a failure after opening data that waits
/// for the user's choice ([`forward::unchosen_after_data_failure`]), in
/// every root the forwarder of this wallet scans: the one of this package,
/// the one of the exe the user launched, and the install root.
fn held_folders(place: &Place, version: Version) -> Vec<PathBuf> {
    let mut roots: Vec<&Path> = vec![&place.iroot];
    roots.extend(place.own.parent());
    roots.extend(
        place
            .launched_from
            .as_deref()
            .and_then(Path::parent)
            .and_then(Path::parent),
    );
    let mut found: Vec<PathBuf> = Vec::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for dir in entries.flatten().map(|entry| entry.path()) {
            if install::folder_version(&dir, place.platform) == Some(version)
                && install::is_real_dir(&dir)
                && install::read_state(&dir)
                    .is_some_and(|state| forward::unchosen_after_data_failure(&state).is_some())
                && install::is_registered_install(&dir, place.platform, &place.registry)
            {
                let same = fs::canonicalize(&dir).ok();
                if !found
                    .iter()
                    .any(|known| fs::canonicalize(known).ok() == same)
                {
                    found.push(dir);
                }
            }
        }
    }
    found
}

/// Why `version` is `failed`, if a folder of it in the install root is.
fn failed_start(place: &Place, version: Version) -> Option<String> {
    installed_folders(place, version)
        .into_iter()
        .filter_map(|dir| install::read_state(&dir))
        .find(|state| state.state == install::STATE_FAILED)
        .map(|state| {
            state
                .extra
                .get(forward::FAILURE_FIELD)
                .and_then(|failure| failure.get("reason"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("it failed to start")
                .to_owned()
        })
}

/// The versions "Remove old versions" may delete. The running folder and
/// the folder the user launches are never among them.
fn removable(place: &Place) -> Vec<PathBuf> {
    let launched = place.launched_from.as_deref().and_then(Path::parent);
    let mut protected: Vec<&Path> = vec![&place.own];
    protected.extend(launched);
    install::removable_versions(
        &place.iroot,
        place.platform,
        place.running,
        &protected,
        &place.registry,
    )
}

fn old_versions(place: &Place) -> Vec<OldVersion> {
    removable(place)
        .into_iter()
        .map(|dir| OldVersion {
            bytes: folder_bytes(&dir),
            path: dir.display().to_string(),
        })
        .collect()
}

/// The bytes of the plain files in `dir` and below, links not followed.
fn folder_bytes(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).ok()?;
            Some(if meta.is_dir() {
                folder_bytes(&path)
            } else if meta.is_file() {
                meta.len()
            } else {
                0
            })
        })
        .sum()
}

/// `CMFD_NO_AUTO_UPDATE=1`, with the name compared as the forwarder
/// compares it, so the variable never stops the forwarding but not the
/// updater (on Linux a lowercase name did).
fn disabled_by_environment(env: &[(OsString, OsString)]) -> bool {
    forward::no_auto_update_by_environment(env)
}

fn updater_error(code: &'static str, message: impl Into<String>) -> NodeClientError {
    NodeClientError {
        code,
        status: 409,
        retryable: false,
        message: message.into(),
    }
}

#[cfg(not(feature = "updater-e2e"))]
fn system_curl(scratch: PathBuf, cancel: Arc<AtomicBool>) -> Option<fetch::Curl> {
    fetch::Curl::system(scratch, cancel)
}

#[cfg(feature = "updater-e2e")]
fn system_curl(scratch: PathBuf, cancel: Arc<AtomicBool>) -> Option<fetch::Curl> {
    fetch::Curl::system_allowing_file_urls(scratch, cancel)
}

#[cfg(not(feature = "updater-e2e"))]
fn e2e_source() -> Option<String> {
    None
}

#[cfg(feature = "updater-e2e")]
fn e2e_source() -> Option<String> {
    std::env::var(E2E_SOURCE_ENV)
        .ok()
        .filter(|base| base.starts_with("file://"))
}

/// The release source: GitHub, or in `updater-e2e` builds a `file://` base
/// that stands in for it.
struct Source<'a> {
    curl: &'a fetch::Curl,
    base: Option<String>,
}

impl Source<'_> {
    fn url(&self, url: &str) -> String {
        match &self.base {
            Some(base) => e2e_url(base, url),
            None => url.to_owned(),
        }
    }
}

impl Transport for Source<'_> {
    fn get(&self, url: &str, max_bytes: u64) -> Result<release::Response, release::TransportError> {
        self.curl.get(&self.url(url), max_bytes)
    }
}

/// `url` under the e2e `base` (see `E2E_SOURCE_ENV`).
fn e2e_url(base: &str, url: &str) -> String {
    let base = base.trim_end_matches('/');
    if let Some(rest) = url.strip_prefix("https://api.github.com/repos/")
        && let Some((path, query)) = rest.split_once('?')
    {
        let page = query.rsplit_once("page=").map_or("1", |(_, page)| page);
        return format!("{base}/api/{path}-page-{page}.json");
    }
    if let Some(rest) = url.strip_prefix("https://github.com/") {
        return format!("{base}/{rest}");
    }
    url.to_owned()
}

#[cfg(feature = "production-v4")]
pub(crate) use inputs::Adoption;

/// Hard-links the mining caches the running package is missing from the
/// folder the user launched or another version this user's updater
/// installed (`inputs::adopt_mining_inputs`), so a new version uses the
/// inputs prepared there instead of preparing 55 GB again. Never copies a
/// cache. `own_production_v4` is the running package's `production-v4`
/// folder. Links made, and prepared caches that could not be linked, are
/// written to the updater log.
#[cfg(feature = "production-mainnet")]
pub(crate) fn adopt_mining_inputs(own_production_v4: &std::path::Path) -> Adoption {
    let (Some(own), Some(platform)) = (own_production_v4.parent(), release::Platform::current())
    else {
        return Adoption::default();
    };
    let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os().collect();
    let launched_from = forward::launched_from(&env);
    let registry = install::registry_dir(&|name| std::env::var_os(name));
    let sources =
        inputs::mining_input_sources(own, launched_from.as_deref(), platform, registry.as_deref());
    let adoption = inputs::adopt_mining_inputs(own_production_v4, &sources, &install::SystemHost);
    log_adoption(own, &adoption);
    adoption
}

/// One line per link run, and one per new folder whose prepared caches
/// cannot be linked, not one every retry.
#[cfg(feature = "production-mainnet")]
fn log_adoption(own: &std::path::Path, adoption: &Adoption) {
    static LOGGED: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);
    let Some(root) = own.parent() else {
        return;
    };
    if adoption.linked > 0 {
        forward::log_line(
            root,
            &format!(
                "linked {} prepared mining files into {}",
                adoption.linked,
                own.display()
            ),
        );
    }
    let Ok(mut logged) = LOGGED.lock() else {
        return;
    };
    if *logged == adoption.unlinkable {
        return;
    }
    if let Some(source) = &adoption.unlinkable {
        forward::log_line(
            root,
            &format!(
                "the prepared mining files in {} cannot be hard-linked into {} (OneDrive, another drive, or exFAT/FAT32); run PREPARE-MINING in {}",
                source.display(),
                own.display(),
                own.display()
            ),
        );
    }
    logged.clone_from(&adoption.unlinkable);
}

/// Other builds have no updater and never link inputs from other folders.
#[cfg(all(feature = "production-v4", not(feature = "production-mainnet")))]
pub(crate) fn adopt_mining_inputs(_own_production_v4: &std::path::Path) -> Adoption {
    Adoption::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updater::install::tests::TempDir;
    use crate::updater::sshsig::ReleaseKeySlot;
    use std::cell::Cell;

    #[cfg(not(feature = "production-mainnet"))]
    #[test]
    fn other_builds_report_unsupported() {
        let updater = UpdaterState::start(None, false, None);
        let status = updater.status(false);
        assert!(matches!(status.status, UpdaterStatus::Unsupported { .. }));
        assert_eq!(
            serde_json::to_value(&status).unwrap()["status"]["state"],
            "unsupported"
        );
        assert!(updater.worker.lock().unwrap().is_none());
        for refused in [
            updater.check_now(),
            updater.download(false),
            updater.set_automatic(false),
            updater.retry("9.9.9"),
            updater.remove_old_versions(),
        ] {
            assert_eq!(refused.unwrap_err().code, "update_unsupported");
        }
        updater.stop();
    }

    /// The test binary is a mainnet build, but not in a release package.
    #[cfg(feature = "production-mainnet")]
    #[test]
    fn a_mainnet_wallet_outside_a_release_package_does_not_update() {
        let updater = UpdaterState::start(None, false, None);
        assert_eq!(
            updater.status(false).status,
            UpdaterStatus::Unsupported {
                reason: "this wallet does not run from a release package folder"
            }
        );
        assert!(updater.worker.lock().unwrap().is_none());
        updater.stop();
    }

    #[test]
    fn the_build_identity_says_release_unless_the_e2e_feature_is_on() {
        #[cfg(not(feature = "updater-e2e"))]
        assert_eq!(BUILD_IDENTITY, "release");
        #[cfg(feature = "updater-e2e")]
        assert_eq!(BUILD_IDENTITY, "updater-e2e-test-build-never-release");
        assert_eq!(
            UpdaterState::start(None, false, None).status(false).build,
            BUILD_IDENTITY
        );
    }

    #[test]
    fn the_e2e_source_is_only_read_with_the_e2e_feature() {
        #[cfg(not(feature = "updater-e2e"))]
        assert_eq!(e2e_source(), None);
        // Mapped only when a base is set.
        assert_eq!(
            e2e_url(
                "file:///D:/e2e/",
                "https://api.github.com/repos/JustAResearcher/CommonFoundry-Binaries/releases?per_page=100&page=2"
            ),
            "file:///D:/e2e/api/JustAResearcher/CommonFoundry-Binaries/releases-page-2.json"
        );
        assert_eq!(
            e2e_url(
                "file:///D:/e2e",
                "https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v1.0.17/SHA256SUMS.txt"
            ),
            "file:///D:/e2e/JustAResearcher/CommonFoundry-Binaries/releases/download/v1.0.17/SHA256SUMS.txt"
        );
        assert_eq!(
            e2e_url("file:///D:/e2e", "https://example.com/x"),
            "https://example.com/x"
        );
    }

    #[test]
    fn the_environment_switch_must_be_exactly_1() {
        let env = |value: &str| vec![(OsString::from("CMFD_NO_AUTO_UPDATE"), value.into())];
        assert!(disabled_by_environment(&env("1")));
        assert!(!disabled_by_environment(&env("0")));
        assert!(!disabled_by_environment(&env("")));
        assert!(!disabled_by_environment(&[]));
        // The name in any case, on every platform, as for the forwarder.
        let lowercase = vec![(OsString::from("cmfd_no_auto_update"), OsString::from("1"))];
        assert!(disabled_by_environment(&lowercase));
        assert!(!forward::forward_allowed_by_environment(&lowercase));
    }

    const V16: Version = Version::new(1, 0, 16);
    const V17: Version = Version::new(1, 0, 17);

    fn release(version: Version) -> VerifiedRelease {
        VerifiedRelease {
            version,
            repo: release::PRIMARY_REPO,
            commit: "c".repeat(40),
            asset_name: Platform::WindowsX86_64.runtime_asset(version),
            asset_url: "https://example.invalid/archive".into(),
            asset_sha256: [1; 32],
            asset_size: 10,
            sums_sha256: [2; 32],
            key: ReleaseKeySlot::Current,
            sums: b"signed sums".to_vec(),
            signature: b"signature".to_vec(),
            buildinfo: b"buildinfo".to_vec(),
        }
    }

    /// An updater for a wallet whose package folder is in `temp`, without
    /// the worker thread.
    fn shared(temp: &TempDir, automatic: bool) -> Shared {
        let iroot = temp.0.join("root");
        let own = iroot.join(install::package_name(Platform::WindowsX86_64, V16));
        fs::create_dir_all(&own).unwrap();
        Shared {
            place: Ok(Place {
                running: V16,
                platform: Platform::WindowsX86_64,
                own,
                iroot,
                registry: temp.0.join("registry"),
                launched_from: None,
            }),
            disabled_by_launch_option: false,
            data_dir: Some(temp.0.clone()),
            fallback: None,
            restart_failed: None,
            no_worker: AtomicBool::new(false),
            cancel: Arc::new(AtomicBool::new(false)),
            inner: Mutex::new(Inner::new(automatic, UpdaterStatus::Idle)),
            wake: Condvar::new(),
            saving: Mutex::new(()),
        }
    }

    fn place(shared: &Shared) -> &Place {
        shared.place.as_ref().unwrap()
    }

    #[test]
    fn a_redirected_install_root_is_created_and_the_package_parent_is_left_alone() {
        let temp = TempDir::new();
        let shared = shared(&temp, true);
        let mut redirected = place(&shared).clone();
        redirected.iroot = temp
            .0
            .join("LocalAppData")
            .join("CommonFoundry")
            .join("versions");
        redirected.ensure_redirected_root().unwrap();
        assert!(install::is_real_dir(&redirected.iroot));
        assert!(install::check_install_root(&redirected.iroot).is_ok());

        // The usual case: versions go beside the package, whose folder exists.
        let usual = place(&shared).clone();
        fs::remove_dir_all(&usual.own).unwrap();
        fs::remove_dir(&usual.iroot).unwrap();
        usual.ensure_redirected_root().unwrap();
        assert!(!usual.iroot.exists());
    }

    fn installed(dir: PathBuf) -> Result<install::Installed, InstallError> {
        Ok(install::Installed {
            dir,
            version: V17,
            inputs: None,
        })
    }

    #[test]
    fn with_the_switch_off_an_update_is_only_offered_until_download() {
        let temp = TempDir::new();
        let shared = shared(&temp, false);
        let release = release(V17);
        let never = |_: bool| -> Result<install::Installed, InstallError> {
            panic!("installed with the switch off")
        };
        assert_eq!(
            shared.offer(place(&shared), &release, Request::Check, &never),
            UpdaterStatus::Available {
                version: "1.0.17".into()
            }
        );
        let folder = temp.0.join("v17");
        let asked = Cell::new(None);
        let status = shared.offer(
            place(&shared),
            &release,
            Request::Download { allow_copy: true },
            &|allow_copy| {
                asked.set(Some(allow_copy));
                installed(folder.clone())
            },
        );
        assert_eq!(asked.get(), Some(true));
        assert_eq!(
            status,
            UpdaterStatus::Ready {
                version: "1.0.17".into(),
                folder: folder.display().to_string(),
            }
        );
    }

    #[test]
    fn with_the_switch_on_an_update_installs_without_copying_the_bank() {
        let temp = TempDir::new();
        let shared = shared(&temp, true);
        let asked = Cell::new(None);
        let status = shared.offer(
            place(&shared),
            &release(V17),
            Request::Check,
            &|allow_copy| {
                asked.set(Some(allow_copy));
                Err(InstallError::Inputs(
                    inputs::InputsError::NeedsCopyConsent {
                        bytes: 6_400_000_000,
                    },
                ))
            },
        );
        assert_eq!(asked.get(), Some(false));
        assert_eq!(
            status,
            UpdaterStatus::NeedsCopyConsent {
                version: "1.0.17".into(),
                bytes: 6_400_000_000,
            }
        );
    }

    #[test]
    fn an_install_that_would_fail_again_waits_for_download() {
        let temp = TempDir::new();
        let shared = shared(&temp, true);
        let release = release(V17);
        let quarantined = |_: bool| -> Result<install::Installed, InstallError> {
            Err(InstallError::Tree {
                path: "production-v4/cmfd-v4-replay".into(),
                problem: "missing",
            })
        };
        let failed = shared.offer(place(&shared), &release, Request::Check, &quarantined);
        assert!(matches!(
            failed,
            UpdaterStatus::InstallFailed {
                retry_automatically: false,
                ..
            }
        ));
        // The next scheduled check reports it again without installing.
        let never = |_: bool| -> Result<install::Installed, InstallError> {
            panic!("retried without being asked")
        };
        assert_eq!(
            shared.offer(place(&shared), &release, Request::Check, &never),
            failed
        );
        // A different signed build of the version is a new candidate.
        let mut rebuilt = release.clone();
        rebuilt.sums_sha256 = [3; 32];
        let tried = Cell::new(false);
        shared.offer(place(&shared), &rebuilt, Request::Check, &|_| {
            tried.set(true);
            quarantined(false)
        });
        assert!(tried.get());
        // "Download" tries again.
        let folder = temp.0.join("v17");
        assert!(matches!(
            shared.offer(
                place(&shared),
                &release,
                Request::Download { allow_copy: false },
                &|_| installed(folder.clone())
            ),
            UpdaterStatus::Ready { .. }
        ));
    }

    #[test]
    fn a_failure_that_may_pass_is_tried_again_by_the_next_check() {
        let temp = TempDir::new();
        let shared = shared(&temp, true);
        let release = release(V17);
        let tries = Cell::new(0);
        let interrupted = |_: bool| -> Result<install::Installed, InstallError> {
            tries.set(tries.get() + 1);
            Err(InstallError::Download(fetch::DownloadError::Interrupted(
                "timeout".into(),
            )))
        };
        for _ in 0..2 {
            assert!(matches!(
                shared.offer(place(&shared), &release, Request::Check, &interrupted),
                UpdaterStatus::InstallFailed {
                    retry_automatically: true,
                    ..
                }
            ));
        }
        assert_eq!(tries.get(), 2);
        // A cancelled install (the wallet closing) reports nothing.
        assert_eq!(
            shared.offer(place(&shared), &release, Request::Check, &|_| Err(
                InstallError::Cancelled
            )),
            UpdaterStatus::Idle
        );
    }

    #[test]
    fn a_changed_bank_must_be_installed_by_hand() {
        assert_eq!(
            install_failure_status(V17, &InstallError::Inputs(inputs::InputsError::BankChanged)),
            UpdaterStatus::Manual {
                version: "1.0.17".into(),
                reason: "this update changes the proof bank; install it by hand".into(),
            }
        );
    }

    #[test]
    fn a_version_that_failed_to_start_is_reported_not_installed_again() {
        let temp = TempDir::new();
        let shared = shared(&temp, true);
        let dir = place(&shared)
            .iroot
            .join(install::package_name(Platform::WindowsX86_64, V17));
        fs::create_dir_all(dir.join(install::MARKER_DIR_NAME)).unwrap();
        install::write_state(
            &dir,
            &install::InstallState {
                state: install::STATE_FAILED.into(),
                version: "1.0.17".into(),
                sums_sha256: hex::encode([2; 32]),
                archive_sha256: hex::encode([1; 32]),
                staged_at: 1,
                extra: serde_json::json!({
                    "failure": {"kind": "start", "reason": "it exited with code 4"}
                })
                .as_object()
                .unwrap()
                .clone(),
            },
        )
        .unwrap();
        let never = |_: bool| -> Result<install::Installed, InstallError> {
            panic!("a failed version was installed again")
        };
        assert_eq!(
            shared.offer(
                place(&shared),
                &release(V17),
                Request::Download { allow_copy: false },
                &never
            ),
            UpdaterStatus::FailedToStart {
                version: "1.0.17".into(),
                reason: "it exited with code 4".into(),
            }
        );
    }

    /// An updater running 1.0.14 beside the real signed 1.0.15, installed
    /// and registered by this user's updater.
    fn running_14_beside_installed_15(temp: &TempDir) -> (UpdaterState, PathBuf) {
        let mut shared = shared(temp, true);
        let place = shared.place.as_mut().unwrap();
        place.running = Version::new(1, 0, 14);
        place.platform = Platform::current().unwrap();
        place.own = place
            .iroot
            .join(install::package_name(place.platform, place.running));
        fs::create_dir_all(&place.own).unwrap();
        let dir = forward::tests::installed(&place.iroot, 15);
        assert_eq!(forward::tests::registry_of(&place.iroot), place.registry);
        let updater = UpdaterState {
            shared: Arc::new(shared),
            worker: Mutex::new(None),
        };
        (updater, dir)
    }

    #[test]
    fn a_failed_check_does_not_hide_an_installed_update() {
        let temp = TempDir::new();
        let (updater, dir) = running_14_beside_installed_15(&temp);
        let place = place(&updater.shared);
        let ready = UpdaterStatus::Ready {
            version: "1.0.15".into(),
            folder: dir.display().to_string(),
        };
        for status in [
            UpdaterStatus::UpToDate,
            UpdaterStatus::CheckFailed {
                reason: "offline".into(),
            },
            UpdaterStatus::NotVerified {
                version: "1.0.16".into(),
                reason: "bad signature".into(),
            },
        ] {
            assert_eq!(or_installed(place, status), ready);
        }
        // "Restart to update" is not refused while a check runs, after one
        // failed, or while a higher release is only offered.
        for status in [
            UpdaterStatus::Checking,
            UpdaterStatus::CheckFailed {
                reason: "offline".into(),
            },
            UpdaterStatus::Available {
                version: "1.0.16".into(),
            },
        ] {
            updater.shared.set_status(status);
            assert_eq!(updater.restart_target(), Ok(Version::new(1, 0, 15)));
        }
    }

    /// The wallet exe of an installed version folder.
    fn wallet_exe(dir: &Path) -> PathBuf {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("common-foundry-wallet"))
            })
            .unwrap()
    }

    fn missing(exe: &Path) -> String {
        format!(
            "{} is missing or changed",
            exe.file_name().unwrap().to_str().unwrap()
        )
    }

    #[test]
    fn a_damaged_installed_update_is_refused_with_its_reason() {
        let temp = TempDir::new();
        let (updater, dir) = running_14_beside_installed_15(&temp);
        let exe = wallet_exe(&dir);
        // An antivirus quarantine: the marker checks still pass, but the
        // forwarder would skip it, so the card says it is damaged.
        fs::remove_file(&exe).unwrap();
        assert_eq!(
            or_installed(place(&updater.shared), UpdaterStatus::UpToDate),
            UpdaterStatus::Damaged {
                version: "1.0.15".into(),
                reason: missing(&exe),
            }
        );
        let refused = updater.restart_target().unwrap_err();
        assert_eq!(refused.code, "update_damaged");
        assert!(
            refused.message.contains("failed its file check"),
            "{}",
            refused.message
        );
        // Retry is refused the same way, and resets nothing.
        let state = install::read_state(&dir).unwrap();
        assert_eq!(updater.retry("1.0.15").unwrap_err().code, "update_damaged");
        assert_eq!(install::read_state(&dir).unwrap(), state);
        // Restored, it passes again.
        fs::write(&exe, b"wallet 1.0.15").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(updater.restart_target(), Ok(Version::new(1, 0, 15)));
        updater.retry("1.0.15").unwrap();
    }

    /// The release `dir` was installed from, as discovery returns it.
    fn release_of(dir: &Path) -> VerifiedRelease {
        let marker = dir.join(install::MARKER_DIR_NAME);
        let read = |name: &str| fs::read(marker.join(name)).unwrap();
        let state = install::read_state(dir).unwrap();
        let digest = |text: &str| {
            let mut digest = [0; 32];
            hex::decode_to_slice(text, &mut digest).unwrap();
            digest
        };
        let buildinfo: serde_json::Value =
            serde_json::from_slice(&read(release::BUILDINFO_NAME)).unwrap();
        VerifiedRelease {
            commit: buildinfo["commit"].as_str().unwrap().to_owned(),
            asset_sha256: digest(&state.archive_sha256),
            sums_sha256: digest(&state.sums_sha256),
            sums: read(release::SUMS_NAME),
            signature: read(release::SIGNATURE_NAME),
            buildinfo: read(release::BUILDINFO_NAME),
            ..release(Version::new(1, 0, 15))
        }
    }

    #[test]
    fn a_damaged_install_is_reported_and_download_installs_it_again() {
        let temp = TempDir::new();
        let (updater, dir) = running_14_beside_installed_15(&temp);
        let shared = &updater.shared;
        let place = place(shared);
        let release = release_of(&dir);
        let ready = |dir: &Path| UpdaterStatus::Ready {
            version: "1.0.15".into(),
            folder: dir.display().to_string(),
        };
        let never = |_: bool| -> Result<install::Installed, InstallError> {
            panic!("installed again on a plain check")
        };
        assert_eq!(
            shared.offer(place, &release, Request::Check, &never),
            ready(&dir)
        );
        let exe = wallet_exe(&dir);
        fs::remove_file(&exe).unwrap();
        let damaged = UpdaterStatus::Damaged {
            version: "1.0.15".into(),
            reason: missing(&exe),
        };
        assert_eq!(
            shared.offer(place, &release, Request::Check, &never),
            damaged
        );
        // "Download" (Reinstall on the card) installs it again.
        let fresh = temp.0.join("fresh");
        let status = shared.offer(
            place,
            &release,
            Request::Download { allow_copy: false },
            &|_| {
                Ok(install::Installed {
                    dir: fresh.clone(),
                    version: Version::new(1, 0, 15),
                    inputs: None,
                })
            },
        );
        assert_eq!(status, ready(&fresh));
        // The reinstalled copy beside the damaged one is the one reported,
        // retried and restarted.
        let copy = forward::tests::installed_as(
            &place.iroot,
            &format!(
                "{}-auto",
                install::package_name(place.platform, Version::new(1, 0, 15))
            ),
            15,
        );
        assert_eq!(
            shared.offer(place, &release, Request::Check, &never),
            ready(&copy)
        );
        assert_eq!(or_installed(place, UpdaterStatus::UpToDate), ready(&copy));
        updater.retry("1.0.15").unwrap();
        assert_eq!(updater.restart_target(), Ok(Version::new(1, 0, 15)));
    }

    #[test]
    fn checks_that_cannot_read_the_release_list_are_counted() {
        let mut inner = Inner::new(true, UpdaterStatus::Idle);
        let counted = |inner: &Inner| {
            (
                inner.check_failures,
                inner.check_failed_since,
                inner.last_checked_at,
            )
        };
        inner.record_check(false, 100);
        assert_eq!(counted(&inner), (1, Some(100), Some(100)));
        inner.record_check(false, 200);
        assert_eq!(counted(&inner), (2, Some(100), Some(200)));
        inner.record_check(true, 300);
        assert_eq!(counted(&inner), (0, None, Some(300)));
        // Failing again since the last check that worked.
        inner.record_check(false, 400);
        inner.record_check(false, 500);
        assert_eq!(counted(&inner), (2, Some(300), Some(500)));

        let temp = TempDir::new();
        let (updater, _) = running_14_beside_installed_15(&temp);
        updater.shared.lock().record_check(false, 700);
        let status = updater.status(false);
        assert_eq!(
            (status.check_failures, status.check_failed_since),
            (1, Some(700))
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["check_failures"], 1);
        assert_eq!(json["check_failed_since"], 700);
    }

    #[test]
    fn an_install_root_that_cannot_be_written_says_to_update_by_hand() {
        let temp = TempDir::new();
        let mut shared = shared(&temp, true);
        // A redirected root under a file cannot be created.
        fs::write(temp.0.join("a-file"), b"x").unwrap();
        shared.place.as_mut().unwrap().iroot = temp.0.join("a-file").join("versions");
        let place = shared.place.as_ref().unwrap().clone();
        let (status, list_read) = shared.check(&place, Request::Check);
        assert!(!list_read);
        let UpdaterStatus::CheckFailed { reason } = status else {
            panic!("{status:?}");
        };
        assert!(
            reason.ends_with("install the next version by hand"),
            "{reason}"
        );
    }

    #[test]
    fn run_anyway_is_recorded_in_the_version_that_failed_after_opening_data() {
        let temp = TempDir::new();
        let (mut updater, dir) = running_14_beside_installed_15(&temp);
        let mut state = install::read_state(&dir).unwrap();
        state.state = install::STATE_FAILED.into();
        state.extra.insert(
            forward::FAILURE_FIELD.into(),
            serde_json::json!({"kind": "start", "reason": "corrupt", "after_data": true}),
        );
        install::write_state(&dir, &state).unwrap();
        // Nothing to record without a fallback after opening data.
        updater.record_run_anyway();
        assert!(
            forward::unchosen_after_data_failure(&install::read_state(&dir).unwrap()).is_some()
        );
        Arc::get_mut(&mut updater.shared).unwrap().fallback = Some(Fallback {
            version: Version::new(1, 0, 15),
            reason: "corrupt".into(),
            after_data: true,
        });
        updater.record_run_anyway();
        let recorded = install::read_state(&dir).unwrap();
        assert_eq!(forward::unchosen_after_data_failure(&recorded), None);
        assert!(recorded.extra[forward::FAILURE_FIELD][forward::RUN_ANYWAY_AT_FIELD].is_u64());
        // Retry clears the failure and the choice with it.
        updater.retry("1.0.15").unwrap();
        assert!(
            !install::read_state(&dir)
                .unwrap()
                .extra
                .contains_key(forward::FAILURE_FIELD)
        );
    }

    #[test]
    fn only_an_installed_update_the_forwarder_would_start_is_ready() {
        let temp = TempDir::new();
        let (updater, dir) = running_14_beside_installed_15(&temp);
        let place = place(&updater.shared);
        let failed = UpdaterStatus::CheckFailed {
            reason: "offline".into(),
        };
        updater.shared.set_status(failed.clone());
        // Started too often.
        let mut state = install::read_state(&dir).unwrap();
        state
            .extra
            .insert(forward::START_ATTEMPTS_FIELD.into(), 3.into());
        install::write_state(&dir, &state).unwrap();
        assert_eq!(or_installed(place, failed.clone()), failed);
        assert_eq!(
            updater.restart_target().unwrap_err().code,
            "update_not_ready"
        );
        // Known to have failed.
        state.extra.remove(forward::START_ATTEMPTS_FIELD);
        state.state = install::STATE_FAILED.into();
        install::write_state(&dir, &state).unwrap();
        assert_eq!(or_installed(place, failed.clone()), failed);
        // Staged again, then no longer in this user's registry.
        state.state = install::STATE_STAGED.into();
        install::write_state(&dir, &state).unwrap();
        assert!(matches!(
            or_installed(place, failed.clone()),
            UpdaterStatus::Ready { .. }
        ));
        fs::remove_dir_all(&place.registry).unwrap();
        assert_eq!(or_installed(place, failed.clone()), failed);
        assert_eq!(
            updater.restart_target().unwrap_err().code,
            "update_not_ready"
        );
    }

    #[test]
    fn requests_are_refused_when_the_worker_could_not_start() {
        let temp = TempDir::new();
        let shared = shared(&temp, true);
        shared.no_worker.store(true, Ordering::SeqCst);
        assert_eq!(
            shared.ask(Request::Check).unwrap_err().code,
            "update_worker_unavailable"
        );
        assert!(shared.lock().request.is_none());
    }

    #[test]
    fn a_download_asked_for_is_not_replaced_by_a_check() {
        let temp = TempDir::new();
        let shared = shared(&temp, false);
        shared.ask(Request::Download { allow_copy: true }).unwrap();
        shared.ask(Request::Check).unwrap();
        assert_eq!(
            shared.lock().request,
            Some(Request::Download { allow_copy: true })
        );
    }

    #[test]
    fn the_switch_is_saved_and_turning_it_on_checks_again() {
        let temp = TempDir::new();
        let updater = UpdaterState {
            shared: Arc::new(shared(&temp, true)),
            worker: Mutex::new(None),
        };
        updater.set_automatic(false).unwrap();
        assert!(!settings::load(&temp.0).automatic);
        assert!(!updater.status(false).automatic);
        assert_eq!(updater.shared.lock().request, None);
        updater.shared.set_status(UpdaterStatus::Available {
            version: "1.0.17".into(),
        });
        updater.set_automatic(true).unwrap();
        assert!(settings::load(&temp.0).automatic);
        assert_eq!(updater.shared.lock().request, Some(Request::Check));
    }

    #[test]
    fn a_launch_option_turns_every_action_off() {
        let temp = TempDir::new();
        let mut disabled = shared(&temp, true);
        disabled.disabled_by_launch_option = true;
        let updater = UpdaterState {
            shared: Arc::new(disabled),
            worker: Mutex::new(None),
        };
        for refused in [
            updater.check_now(),
            updater.download(true),
            updater.set_automatic(true),
            updater.retry("1.0.17"),
            updater.remove_old_versions(),
        ] {
            assert_eq!(refused.unwrap_err().code, "update_disabled");
        }
        assert!(updater.status(false).disabled_by_launch_option);
    }

    #[test]
    fn retry_needs_a_newer_version_this_user_installed() {
        let temp = TempDir::new();
        let updater = UpdaterState {
            shared: Arc::new(shared(&temp, true)),
            worker: Mutex::new(None),
        };
        for version in ["1.0.16", "1.0.15", "x"] {
            assert_eq!(
                updater.retry(version).unwrap_err().code,
                "update_version_invalid",
                "{version}"
            );
        }
        assert_eq!(
            updater.retry("1.0.17").unwrap_err().code,
            "update_not_installed"
        );
    }

    #[test]
    fn the_fallback_is_reported_with_the_hold() {
        let temp = TempDir::new();
        let mut with_fallback = shared(&temp, true);
        with_fallback.fallback = Some(Fallback {
            version: V17,
            reason: "corrupt_block_log".into(),
            after_data: true,
        });
        let updater = UpdaterState {
            shared: Arc::new(with_fallback),
            worker: Mutex::new(None),
        };
        assert_eq!(
            updater.status(true).fallback,
            Some(FallbackStatus {
                version: "1.0.17".into(),
                reason: "corrupt_block_log".into(),
                after_data: true,
                held: true,
            })
        );
    }

    #[test]
    fn old_folders_are_measured_without_following_links() {
        let temp = TempDir::new();
        fs::create_dir_all(temp.0.join("a/b")).unwrap();
        fs::write(temp.0.join("a/one"), [0; 3]).unwrap();
        fs::write(temp.0.join("a/b/two"), [0; 4]).unwrap();
        assert_eq!(folder_bytes(&temp.0.join("a")), 7);
        assert_eq!(folder_bytes(&temp.0.join("missing")), 0);
    }

    #[test]
    fn stop_ends_the_worker() {
        let temp = TempDir::new();
        let shared = Arc::new(shared(&temp, true));
        let worker = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.run_worker())
        };
        let updater = UpdaterState {
            shared,
            worker: Mutex::new(Some(worker)),
        };
        let started = Instant::now();
        updater.stop();
        assert!(updater.worker.lock().unwrap().is_none());
        assert!(started.elapsed() < STOP_WAIT);
    }
}
