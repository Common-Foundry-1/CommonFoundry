//! The running wallet's side of an update (UPDATER-DESIGN.md sections 2.7
//! and 2.9, as trimmed by TRIMMED-SCOPE.md: no soak, no policy file, no
//! downgrade gate).
//!
//! - **Restart guard.** "Restart to update" never closes the wallet during a
//!   send, a consolidation, a backup, a restore or any other custody
//!   operation. [`RestartGuard::begin_node_operation`] counts a send that is
//!   under way and refuses one that starts once the exit began;
//!   [`RestartGuard::try_begin_exit`] sets the exiting flag first and then
//!   requires no send under way and the custody operation lock free. The
//!   flag is set before the count is read, and the count is raised before
//!   the flag is read, so a send can never slip past. Custody methods check
//!   [`RestartGuard::refuse_if_exiting`] once they hold the operation lock.
//! - **Sends that may not be relayed.** The node keeps unconfirmed
//!   transactions in memory only and reports no relay acknowledgement.
//!   [`unrelayed_sends`] tells the restart which of this session's sends are
//!   still in the mempool, and which of those were sent less than
//!   [`RELAY_GRACE`] ago or while no peer was connected.
//! - **Start success.** Failed starts are counted by the forwarder that
//!   started this version, from the exit code
//!   ([`super::forward`]), never here. This version only records that it
//!   works ([`forward::record_start_success`]) once [`start_outcome`] says
//!   so, and hands a node failure that counts back to its caller
//!   ([`watch_start`]), which ends the process with a non-zero code so
//!   the forwarder runs the previous version ([`end_failed_start`]).
//! - **A locked wallet decides nothing.** Unlike design section 2.9, a
//!   node waiting for its passphrase is not a working start: the stored
//!   chain is only replayed when the unlock opens the node, so a release
//!   that breaks the replay must still reach TRIMMED-SCOPE's fallback after
//!   opening data. The unlock's failure is handed to the watch
//!   ([`RestartGuard::record_unlock_failure`], [`with_unlock_failure`]).
//! - **Only a staged version.** The watch and the mark run only while this
//!   version's `state.json` is still `staged`; a version already known to
//!   work when it launched is left alone for the whole run. Its two writers
//!   here are serialized and retried a few times, for a file a virus
//!   scanner or a sync client holds briefly.
//! - **Opening data.** [`before_node_open`] marks `node_opened` in this
//!   version's own `state.json` right before the node opens the wallet
//!   data, so a failure after that is one after opening data. If the mark
//!   cannot be written, or the updater's folder is there but its state
//!   cannot be read, the node does not open the data; that refusal is
//!   retryable and never counts as a failed start. The mark comes before
//!   the open's own check of the model bank and its wait for a held data
//!   dir, so a failure there counts as one after opening data: the safe
//!   side, since the bank check runs inside the node's open.
//! - **Handoff.** A start made by "Restart to update" carries
//!   [`HANDOFF_ENV`] and [`HANDOFF_PARENT_PID_ENV`]; the forwarder passes
//!   both on, but only the first on a fallback start ([`PASSED_ON_ENV`]).
//!   While the first is set, opening
//!   the node at startup waits for up to [`DATA_DIR_LOCK_WAIT`] while the
//!   closing wallet still holds the data dir ([`open_retrying_while_locked`]).
//!
//! Apart from trying the data dir's lock ([`data_dir_lock_held`]), nothing
//! here reads or writes the wallet data dir.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, TryLockError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cmfd_node::{NodeClientError, NodeError};
use serde_json::Value;

use super::install::{self, STATE_STAGED};
use super::release::Version;
use super::{forward, restart};

/// Set (to `1`) on the start "Restart to update" makes. Kept by the
/// forwarder, like [`HANDOFF_PARENT_PID_ENV`] and unlike every other
/// `CMFD_UPDATE_*` variable.
pub(crate) const HANDOFF_ENV: &str = "CMFD_UPDATE_HANDOFF";
/// The process id of the wallet that closes for "Restart to update", set
/// beside [`HANDOFF_ENV`]. The relaunch goes through the exe the user
/// launched, so the new version's own parent is a forwarder that waits for
/// it; this is the process the new version waits for instead.
pub(crate) const HANDOFF_PARENT_PID_ENV: &str = "CMFD_UPDATE_PARENT_PID";
/// The `CMFD_UPDATE_*` variables a forwarder passes on unchanged; on a
/// fallback start (another version failed first) only [`HANDOFF_ENV`],
/// since the closing wallet may be gone and its id reused by then. Frozen
/// with the forwarder: a 1.0.16 forwarder starts every later version.
pub(crate) const PASSED_ON_ENV: [&str; 2] = [HANDOFF_ENV, HANDOFF_PARENT_PID_ENV];
/// How long a handoff start waits for the closing wallet to release the
/// data dir.
pub(crate) const DATA_DIR_LOCK_WAIT: Duration = Duration::from_secs(60);
const LOCK_RETRY_FIRST_DELAY: Duration = Duration::from_millis(200);
/// The node's lock file in the data dir (cmfd-node `LOCK_FILE`).
const NODE_LOCK_FILE: &str = "node.lock";
const LOCK_RETRY_MAX_DELAY: Duration = Duration::from_secs(2);
/// A send this recent may not have reached a peer yet.
pub(crate) const RELAY_GRACE: Duration = Duration::from_secs(60);
/// The sends of this session kept for the restart check; older ones are
/// dropped first.
const MAX_RECENT_SENDS: usize = 256;
/// A node still starting this long after it opened the wallet data counts
/// as a working start. The replay of stored blocks runs inside the open, so
/// it is not part of this time; a long replay counts once the node is ready.
pub(crate) const STARTED_AFTER: Duration = Duration::from_secs(60);
const START_POLL: Duration = Duration::from_secs(1);
/// Reads and writes of this version's `state.json` are tried this often.
const STATE_TRIES: u32 = 3;
const STATE_RETRY_DELAY: Duration = Duration::from_millis(150);

/// A node that waits for its passphrase (or got a wrong one).
const WALLET_LOCKED_CODE: &str = "wallet_locked";
/// Node failures that decide nothing yet: a locked wallet (its chain is
/// first opened by the unlock), the data dir held by another process (not
/// this version's fault), and a stored chain the user must sync again. An
/// unlock or a resync that reaches ready shows the version works; a release
/// with a wrong work checkpoint never gets that far, so it keeps its
/// fallback.
/// A wallet held before opening its data, after a newer version failed
/// once it had opened them, decides nothing either: the user chooses.
const UNDECIDED_FAILURE_CODES: [&str; 4] = [
    WALLET_LOCKED_CODE,
    "data_dir_locked",
    crate::runtime::CHAIN_RESYNC_REQUIRED,
    FALLBACK_HELD_CODE,
];
/// The node phase of a wallet held before it opens its data
/// ([`RestartGuard::hold`]).
pub(crate) const FALLBACK_HELD_CODE: &str = "update_fallback_held";
/// A retryable node failure that still counts: a panic during the node
/// start is a fault of this version, and the wallet cannot start the node
/// again without a restart, so not counting it would start the same broken
/// version on every launch.
const COUNTED_RETRYABLE_CODE: &str = "node_startup_panicked";

/// The busy guard of "Restart to update", shared by every clone of the
/// runtime handle.
#[derive(Debug, Default)]
pub(crate) struct RestartGuard {
    exiting: AtomicBool,
    in_flight: AtomicUsize,
    sends: Mutex<VecDeque<(String, u64)>>,
    /// When the node last opened the wallet data, for the start check.
    data_opened: Mutex<Option<Instant>>,
    /// Why the last unlock could not open the node, for the start check.
    unlock_failure: Mutex<Option<NodeClientError>>,
    /// Set while the node must not open the wallet data: a newer version
    /// failed after it had opened them ([`forward::Fallback`]), and the
    /// user has not chosen "Run anyway" yet.
    held: Mutex<Option<NodeClientError>>,
}

/// A send or consolidation under way; dropping it ends it.
#[derive(Debug)]
pub(crate) struct NodeOperation(Arc<RestartGuard>);

impl Drop for NodeOperation {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// An exit that began. Dropping it without [`ExitStarted::commit`] clears the
/// exiting flag again, so a restart refused for any later reason leaves the
/// wallet usable.
#[derive(Debug)]
pub(crate) struct ExitStarted {
    guard: Arc<RestartGuard>,
    committed: bool,
}

impl ExitStarted {
    /// The wallet closes now: the flag stays set until the process ends.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for ExitStarted {
    fn drop(&mut self) {
        if !self.committed {
            self.guard.exiting.store(false, Ordering::SeqCst);
        }
    }
}

impl RestartGuard {
    /// Starts a send, a consolidation, a peer-settings change or a mining
    /// start, refused once the exit began.
    pub(crate) fn begin_node_operation(self: &Arc<Self>) -> Result<NodeOperation, NodeClientError> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let operation = NodeOperation(Arc::clone(self));
        if self.exiting.load(Ordering::SeqCst) {
            return Err(restarting_error());
        }
        Ok(operation)
    }

    /// For a custody method that holds the operation lock.
    pub(crate) fn refuse_if_exiting(&self) -> Result<(), NodeClientError> {
        if self.exiting.load(Ordering::SeqCst) {
            Err(restarting_error())
        } else {
            Ok(())
        }
    }

    /// Begins the exit: refused while a send is under way or `operation`
    /// (the custody operation lock) is held. The lock is only tried, never
    /// waited for, and released at once; operations that start later see
    /// the flag.
    pub(crate) fn try_begin_exit(
        self: &Arc<Self>,
        operation: &Mutex<()>,
    ) -> Result<ExitStarted, NodeClientError> {
        if self.exiting.swap(true, Ordering::SeqCst) {
            // Another restart is already closing the wallet.
            return Err(restarting_error());
        }
        let started = ExitStarted {
            guard: Arc::clone(self),
            committed: false,
        };
        if self.in_flight.load(Ordering::SeqCst) != 0 {
            return Err(busy_error());
        }
        match operation.try_lock() {
            Ok(_) => {}
            Err(TryLockError::WouldBlock) => return Err(busy_error()),
            Err(TryLockError::Poisoned(_)) => {
                return Err(crate::runtime::startup_error(
                    "runtime_state_unavailable",
                    "The wallet runtime state is unavailable. Reopen the wallet.",
                    true,
                ));
            }
        }
        Ok(started)
    }

    /// Remembers a send that the node accepted at `sent_at` (Unix seconds).
    pub(crate) fn record_send(&self, txid: &str, sent_at: u64) {
        let Ok(mut sends) = self.sends.lock() else {
            return;
        };
        if sends.len() >= MAX_RECENT_SENDS {
            sends.pop_front();
        }
        sends.push_back((txid.to_owned(), sent_at));
    }

    pub(crate) fn recent_sends(&self) -> Vec<(String, u64)> {
        self.sends
            .lock()
            .map(|sends| sends.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The node just opened the wallet data (its open returned).
    pub(crate) fn mark_data_opened(&self) {
        if let Ok(mut opened) = self.data_opened.lock() {
            *opened = Some(Instant::now());
        }
        if let Ok(mut failure) = self.unlock_failure.lock() {
            *failure = None;
        }
    }

    /// An unlock could not open the node, which leaves the wallet locked:
    /// the start check sees this reason instead ([`with_unlock_failure`]).
    pub(crate) fn record_unlock_failure(&self, error: &NodeClientError) {
        if let Ok(mut failure) = self.unlock_failure.lock() {
            *failure = Some(error.clone());
        }
    }

    pub(crate) fn unlock_failure(&self) -> Option<NodeClientError> {
        self.unlock_failure
            .lock()
            .ok()
            .and_then(|failure| failure.clone())
    }

    /// Holds every node open until [`RestartGuard::release_hold`]; the node
    /// is refused with `error`.
    pub(crate) fn hold(&self, error: NodeClientError) {
        *self.held.lock().unwrap_or_else(PoisonError::into_inner) = Some(error);
    }

    /// Ends the hold; false if there was none.
    pub(crate) fn release_hold(&self) -> bool {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .is_some()
    }

    pub(crate) fn is_held(&self) -> bool {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// For every open of the node.
    pub(crate) fn refuse_if_held(&self) -> Result<(), NodeClientError> {
        match &*self.held.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    /// How long ago the node last opened the wallet data; `None` before it
    /// did.
    pub(crate) fn data_opened_for(&self) -> Option<Duration> {
        self.data_opened
            .lock()
            .ok()
            .and_then(|opened| opened.map(|at| at.elapsed()))
    }
}

/// Retryable: a restart that is refused later (a send that may not be
/// relayed yet) leaves the wallet running.
fn restarting_error() -> NodeClientError {
    NodeClientError {
        code: "update_restarting",
        status: 409,
        retryable: true,
        message: "The wallet is restarting to update.".to_owned(),
    }
}

/// The node phase of a wallet held after `fallback` (a newer version that
/// failed once it had opened the wallet data).
pub(crate) fn fallback_held_error(fallback: &forward::Fallback, running: &str) -> NodeClientError {
    NodeClientError {
        code: FALLBACK_HELD_CODE,
        status: 409,
        retryable: false,
        message: format!(
            "Version {} stopped after it had opened this wallet's data ({}). This wallet ({running}) has not opened the data. Retry version {}, or run {running} anyway: an older version may not read data a newer one changed.",
            fallback.version,
            if fallback.reason.is_empty() {
                "no reason given"
            } else {
                fallback.reason.as_str()
            },
            fallback.version,
        ),
    }
}

fn busy_error() -> NodeClientError {
    NodeClientError {
        code: "update_busy",
        status: 409,
        retryable: true,
        message: "Finish the current send, backup or restore first, then restart to update."
            .to_owned(),
    }
}

/// This session's sends that are still in the mempool, so a restart would
/// drop them from this wallet's memory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct UnrelayedSends {
    /// Still unconfirmed, sent less than [`RELAY_GRACE`] ago or while no
    /// peer is connected: they may not have reached the network yet.
    pub(crate) maybe_not_relayed: usize,
    /// Still unconfirmed, all of them (`maybe_not_relayed` included).
    pub(crate) unconfirmed: usize,
}

/// Which of `sends` (txid, Unix seconds) are still in the mempool at `now`.
/// A send time after `now` (the clock moved back) counts as just sent.
pub(crate) fn unrelayed_sends<'a>(
    sends: &[(String, u64)],
    mempool_txids: impl IntoIterator<Item = &'a str>,
    connected_peers: usize,
    now: u64,
) -> UnrelayedSends {
    let mempool: std::collections::HashSet<&str> = mempool_txids.into_iter().collect();
    let mut result = UnrelayedSends::default();
    for (txid, sent_at) in sends {
        if !mempool.contains(txid.as_str()) {
            continue;
        }
        result.unconfirmed += 1;
        if connected_peers == 0 || now.saturating_sub(*sent_at) < RELAY_GRACE.as_secs() {
            result.maybe_not_relayed += 1;
        }
    }
    result
}

/// The node as the start check sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NodePhase {
    Starting,
    Ready,
    Failed {
        code: &'static str,
        retryable: bool,
        message: String,
    },
}

/// What a start has shown so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartOutcome {
    /// Not known yet.
    Pending,
    /// This version works.
    Started,
    /// This version failed to start, for this reason.
    Failed(String),
}

/// Design section 2.9, with four changes. A node that is ready, or that
/// is still starting [`STARTED_AFTER`] after it opened the wallet data
/// (`data_opened_for`), shows the version works; time before the open
/// (launch and artifact checks, a wait for a held data dir) never does. A
/// locked wallet decides nothing until the unlock opens the node. A startup
/// panic counts although it is retryable. A chain to sync again decides
/// nothing until the resync. Any other retryable failure (a busy P2P port),
/// and a data dir held by another process, never count. Any other failure
/// does, including a launch the preparation gave up on after the launch
/// time, which the phase reports as not retryable ([`with_launch_passed`]).
pub(crate) fn start_outcome(phase: &NodePhase, data_opened_for: Option<Duration>) -> StartOutcome {
    match phase {
        NodePhase::Ready => StartOutcome::Started,
        NodePhase::Starting if data_opened_for.is_some_and(|opened| opened >= STARTED_AFTER) => {
            StartOutcome::Started
        }
        NodePhase::Starting => StartOutcome::Pending,
        NodePhase::Failed { code, .. } if UNDECIDED_FAILURE_CODES.contains(code) => {
            StartOutcome::Pending
        }
        NodePhase::Failed {
            code,
            retryable: true,
            ..
        } if *code != COUNTED_RETRYABLE_CODE => StartOutcome::Pending,
        NodePhase::Failed { code, message, .. } => {
            StartOutcome::Failed(format!("{code}: {message}"))
        }
    }
}

/// The node's phase as the start check sees it: a wallet left locked by an
/// unlock that could not open the node failed for that unlock's reason.
/// A wrong passphrase is `wallet_locked` again, so it still decides
/// nothing.
pub(crate) fn with_unlock_failure(
    phase: NodePhase,
    unlock_failure: Option<NodeClientError>,
) -> NodePhase {
    match (phase, unlock_failure) {
        (NodePhase::Failed { code, .. }, Some(error)) if code == WALLET_LOCKED_CODE => {
            NodePhase::Failed {
                code: error.code,
                retryable: error.retryable,
                message: error.message,
            }
        }
        (phase, _) => phase,
    }
}

/// The node's code for a mainnet launch plan or beacon that is not there
/// (cmfd-node `MainnetLaunchRequired`), retryable for the wait before the
/// launch time.
const LAUNCH_REQUIRED_CODE: &str = "mainnet_launch_required";

/// The node's phase as the start check sees it at `now` (Unix seconds),
/// with `launch_failure` the reason this process's launch preparation
/// ended without a verified beacon (None while it still waits for one).
/// A missing beacon is not counted while the preparation still fetches it:
/// once it is back, unlock starts the node. A preparation that ended with
/// an error after the launch time (a missing MAINNET-PLAN.json ends it at
/// once) brings nothing back, so that start counts as a failure before
/// opening data and the previous version runs. With a clock before the
/// launch it still decides nothing, as for every version.
pub(crate) fn with_launch_passed(
    phase: NodePhase,
    launch_failure: Option<String>,
    now: u64,
) -> NodePhase {
    match (phase, launch_failure) {
        (NodePhase::Failed { code, .. }, Some(failure))
            if code == LAUNCH_REQUIRED_CODE && now >= cmfd_launch::MAINNET_LAUNCH_UNIX_SECONDS =>
        {
            NodePhase::Failed {
                code,
                retryable: false,
                // The node's own message names only the beacon, also for
                // a missing plan, so it is not repeated.
                message: format!(
                    "launch plan or beacon unavailable, and this wallet stopped \
                     fetching it: {failure}"
                ),
            }
        }
        (phase, _) => phase,
    }
}

/// How a start watch ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WatchEnd {
    /// `started_ok` was recorded (or could not be, which was logged).
    Started,
    /// The start failed; the caller is to end the process with a non-zero
    /// code.
    Failed(String),
    /// The wallet closed before the start was decided: nothing is recorded.
    Undecided,
}

/// Watches the start of the version installed in `own` until
/// [`start_outcome`] decides or the wallet closes (`closing`). There is no
/// time limit: a failure that decides nothing yet (a chain to sync again, a
/// busy port) may still end in ready. Records `started_ok` on success,
/// while the state is still `running`'s staged one.
/// Begins once setup completed and the main window was built.
pub(crate) fn watch_start(
    own: &Path,
    running: Version,
    phase: impl Fn() -> NodePhase,
    closing: impl Fn() -> bool,
    data_opened_for: impl Fn() -> Option<Duration>,
    sleep: impl Fn(Duration),
) -> WatchEnd {
    loop {
        if closing() {
            return WatchEnd::Undecided;
        }
        match start_outcome(&phase(), data_opened_for()) {
            StartOutcome::Started => {
                if let Err(error) = record_started(own, running) {
                    log(&format!("cannot record that this version started: {error}"));
                }
                return WatchEnd::Started;
            }
            StartOutcome::Failed(reason) => {
                log(&format!("this version failed to start: {reason}"));
                return WatchEnd::Failed(reason);
            }
            StartOutcome::Pending => sleep(START_POLL),
        }
    }
}

/// Records `started_ok`, unless the state changed from this version's
/// staged one since the watch began.
fn record_started(own: &Path, running: Version) -> io::Result<()> {
    with_state_lock(|| match own_state(own, running) {
        OwnState::Staged { .. } => with_retries(|| forward::record_start_success(own)),
        OwnState::Settled => Ok(()),
        OwnState::Unreadable => Err(io::Error::other("its state.json cannot be read")),
    })
}

/// Starts [`watch_start`] on a thread for a version the updater installed
/// that is not known to work yet; `None` for any other wallet, which has
/// nothing to record. `on_failed` gets the reason of a start that failed.
pub(crate) fn spawn_start_watch(
    phase: impl Fn() -> NodePhase + Send + 'static,
    closing: impl Fn() -> bool + Send + 'static,
    data_opened_for: impl Fn() -> Option<Duration> + Send + 'static,
    on_failed: impl FnOnce(String) + Send + 'static,
) -> Option<thread::JoinHandle<()>> {
    let (own, running) = installed_self()?;
    spawn_watch_in(
        own.to_path_buf(),
        running,
        phase,
        closing,
        data_opened_for,
        on_failed,
    )
}

fn spawn_watch_in(
    own: PathBuf,
    running: Version,
    phase: impl Fn() -> NodePhase + Send + 'static,
    closing: impl Fn() -> bool + Send + 'static,
    data_opened_for: impl Fn() -> Option<Duration> + Send + 'static,
    on_failed: impl FnOnce(String) + Send + 'static,
) -> Option<thread::JoinHandle<()>> {
    // A state that cannot be read is still watched: a failure then ends
    // the process, and the forwarder falls back.
    if own_state(&own, running) == OwnState::Settled {
        return None;
    }
    thread::Builder::new()
        .name("cmfd-update-start".to_owned())
        .spawn(move || {
            if let WatchEnd::Failed(reason) = watch_start(
                &own,
                running,
                phase,
                closing,
                data_opened_for,
                thread::sleep,
            ) {
                on_failed(reason);
            }
        })
        .ok()
}

/// For the start watch's failure: true when a forwarder started this wallet
/// and it must now exit with [`restart::START_FAILED_EXIT_CODE`] (asked for
/// here) so the forwarder runs the previous version; the reason is written
/// to this version's `state.json` first, for the forwarder's record. False
/// when no forwarder waits ([`forwarder_waits`]): nothing would fall back,
/// so the wallet stays open and shows the error.
pub(crate) fn end_failed_start(reason: &str) -> bool {
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    if !forwarder_waits(&env) {
        return false;
    }
    if let Some((own, running)) = installed_self() {
        let written = with_state_lock(|| match own_state(own, running) {
            OwnState::Staged { .. } => {
                with_retries(|| forward::record_start_failure_reason(own, reason))
            }
            OwnState::Settled | OwnState::Unreadable => Ok(()),
        });
        if let Err(error) = written {
            log(&format!("cannot record why this version failed: {error}"));
        }
    }
    restart::request_exit_code(restart::START_FAILED_EXIT_CODE);
    true
}

/// Whether a forwarder started this wallet and waits for its exit code. A
/// forwarder sets `CMFD_UPDATE_FORWARDED=1`; a wallet started directly has
/// no such variable, and any other value (an odd user environment) skips
/// forwarding but keeps a failed start open. The start made
/// after "Restart to update" could not start the exe the user launched
/// carries it too (so it does not forward), but the wallet that made it has
/// exited: nobody would fall back, so its own failed start stays open.
pub(crate) fn forwarder_waits(env: &[(OsString, OsString)]) -> bool {
    env.iter()
        .any(|(key, value)| is_env_name(key, forward::FORWARDED_ENV) && value == "1")
        && restart::spawn_failed_reason(env).is_none()
}

/// The folder of this wallet when the updater installed it (the running
/// exe's folder holds the updater's marker dir) and it was not settled
/// (known to work, failed, or another version's state) when it launched,
/// and the running version. Only mainnet builds carry the updater. The
/// state in that folder changes while the wallet runs, so it is read again
/// at each use.
pub(crate) fn installed_self() -> Option<(&'static Path, Version)> {
    static OWN: OnceLock<Option<(PathBuf, Version)>> = OnceLock::new();
    OWN.get_or_init(|| {
        if !cfg!(feature = "production-mainnet") {
            return None;
        }
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        if !has_marker(dir) {
            return None;
        }
        let running = Version::running()?;
        // Nothing to mark or watch, so a later read error never refuses it.
        if own_state(dir, running) == OwnState::Settled {
            return None;
        }
        Some((dir.to_path_buf(), running))
    })
    .as_ref()
    .map(|(dir, running)| (dir.as_path(), *running))
}

fn has_marker(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(install::MARKER_DIR_NAME)).is_ok_and(|meta| meta.is_dir())
}

/// What the start check needs from this version's `state.json`.
#[derive(Debug, PartialEq, Eq)]
enum OwnState {
    /// This version, not known to work yet; `node_opened` once it opened
    /// the wallet data.
    Staged { node_opened: bool },
    /// Known to work, failed, or the state of another version: nothing to
    /// watch or mark.
    Settled,
    /// The marker dir is there, but its state cannot be read.
    Unreadable,
}

fn own_state(own: &Path, running: Version) -> OwnState {
    let Ok(state) =
        with_retries(|| install::read_state(own).ok_or_else(|| io::Error::other("unreadable")))
    else {
        return OwnState::Unreadable;
    };
    if state.version != running.to_string() || state.state != STATE_STAGED {
        return OwnState::Settled;
    }
    OwnState::Staged {
        node_opened: state
            .extra
            .get(forward::NODE_OPENED_FIELD)
            .and_then(Value::as_bool)
            == Some(true),
    }
}

/// Right before the node opens the wallet data: marks `node_opened` in this
/// version's `state.json` when the updater installed it and it is not known
/// to work yet. An error means the mark could not be written, or the state
/// could not be read, and the data must not be opened.
pub(crate) fn before_node_open() -> io::Result<()> {
    match installed_self() {
        Some((own, running)) => mark_opening_data(own, running),
        None => Ok(()),
    }
}

fn mark_opening_data(own: &Path, running: Version) -> io::Result<()> {
    with_state_lock(|| match own_state(own, running) {
        OwnState::Staged { node_opened: false } => {
            with_retries(|| forward::record_opening_data(own))
        }
        // Once started_ok, the forwarder never reads the mark.
        OwnState::Staged { node_opened: true } | OwnState::Settled => Ok(()),
        OwnState::Unreadable => Err(io::Error::other(
            "the updater's state.json in this version's folder cannot be read",
        )),
    })
}

/// Runs `write` while no other thread of this wallet changes its
/// `state.json`.
fn with_state_lock<T>(write: impl FnOnce() -> T) -> T {
    static STATE_WRITES: Mutex<()> = Mutex::new(());
    let _writing = STATE_WRITES.lock().unwrap_or_else(PoisonError::into_inner);
    write()
}

/// Tries `step` up to [`STATE_TRIES`] times while it fails.
fn with_retries<T>(mut step: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut tries = 1;
    loop {
        match step() {
            Err(_) if tries < STATE_TRIES => {
                tries += 1;
                thread::sleep(STATE_RETRY_DELAY);
            }
            result => return result,
        }
    }
}

/// Whether `env` marks a start made by "Restart to update".
pub(crate) fn is_handoff(env: &[(OsString, OsString)]) -> bool {
    env.iter()
        .any(|(key, value)| is_env_name(key, HANDOFF_ENV) && value == OsStr::new("1"))
}

/// Whether `key` is the variable `name`: without ASCII case on Windows,
/// where variable names have no case, and exactly elsewhere.
pub(crate) fn is_env_name(key: &OsStr, name: &str) -> bool {
    key.to_str().is_some_and(|key| {
        if cfg!(windows) {
            key.eq_ignore_ascii_case(name)
        } else {
            key == name
        }
    })
}

/// How long the startup open of the node waits for a held data dir: up to
/// [`DATA_DIR_LOCK_WAIT`] on a handoff start, else not at all.
pub(crate) fn startup_data_dir_wait() -> Duration {
    static HANDOFF: OnceLock<bool> = OnceLock::new();
    if *HANDOFF.get_or_init(|| is_handoff(&std::env::vars_os().collect::<Vec<_>>())) {
        DATA_DIR_LOCK_WAIT
    } else {
        Duration::ZERO
    }
}

/// Opens the node with `open`, waiting for up to `wait` in all, with a
/// growing delay, while another process holds the data dir. `open` is not
/// called while `held` says the lock is taken, since it authenticates the
/// whole model bank before it tries the lock; a
/// [`NodeError::DataDirLocked`] from `open` is waited out the same way.
/// `closing` (the wallet is closing) ends the wait. Any other result, and
/// the last locked one, is returned as it is. With no wait, `open` runs
/// once and `held` is never asked.
pub(crate) fn open_retrying_while_locked<T>(
    wait: Duration,
    held: impl Fn() -> bool,
    mut open: impl FnMut() -> Result<T, NodeError>,
    closing: impl Fn() -> bool,
    now: impl Fn() -> Instant,
    sleep: impl Fn(Duration),
) -> Result<T, NodeError> {
    let deadline = now() + wait;
    let mut delay = LOCK_RETRY_FIRST_DELAY;
    // Sleeps once; false when the wait is over.
    let pause = |delay: &mut Duration| {
        let left = deadline.saturating_duration_since(now());
        if left.is_zero() || closing() {
            return false;
        }
        sleep((*delay).min(left));
        *delay = (*delay * 2).min(LOCK_RETRY_MAX_DELAY);
        true
    };
    loop {
        while !wait.is_zero() && held() && pause(&mut delay) {}
        match open() {
            Err(NodeError::DataDirLocked(path)) => {
                if !pause(&mut delay) {
                    return Err(NodeError::DataDirLocked(path));
                }
            }
            result => return result,
        }
    }
}

/// Whether another process holds the node lock of `data_dir`. The lock is
/// only tried, through a read-only handle, and released at once. Any doubt
/// (no lock file, another error) says free, and the open decides. The name
/// is cmfd-node's `LOCK_FILE`; were it ever different, the open would just
/// be tried while the lock is held.
pub(crate) fn data_dir_lock_held(data_dir: &Path) -> bool {
    let Ok(file) = fs::File::open(data_dir.join(NODE_LOCK_FILE)) else {
        return false;
    };
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => {
            let _ = fs2::FileExt::unlock(&file);
            false
        }
        Err(error) => install::is_lock_contended(&error),
    }
}

/// Seconds since the Unix epoch, for recorded sends.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn log(line: &str) {
    // Not eprintln!, which panics when stderr is a closed pipe.
    let _ = writeln!(io::stderr(), "Common Foundry Wallet updater: {line}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updater::install::tests::TempDir;
    use crate::updater::install::{InstallState, MARKER_DIR_NAME, STATE_STARTED_OK};
    use serde_json::Map;
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;

    fn txid(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    #[test]
    fn a_send_that_starts_after_the_exit_began_is_refused() {
        let guard = Arc::new(RestartGuard::default());
        let operation = Mutex::new(());
        let exit = guard.try_begin_exit(&operation).unwrap();
        let refused = guard.begin_node_operation().unwrap_err();
        assert_eq!(refused.code, "update_restarting");
        assert!(refused.retryable);
        assert_eq!(guard.in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(
            guard.refuse_if_exiting().unwrap_err().code,
            "update_restarting"
        );
        // A second restart while the first one closes the wallet.
        assert_eq!(
            guard.try_begin_exit(&operation).unwrap_err().code,
            "update_restarting"
        );
        exit.commit();
        assert!(guard.begin_node_operation().is_err());
    }

    #[test]
    fn the_exit_is_refused_during_a_send_and_the_flag_is_cleared() {
        let guard = Arc::new(RestartGuard::default());
        let operation = Mutex::new(());
        let send = guard.begin_node_operation().unwrap();
        let busy = guard.try_begin_exit(&operation).unwrap_err();
        assert_eq!(busy.code, "update_busy");
        assert!(busy.retryable);
        assert!(!guard.exiting.load(Ordering::SeqCst));
        // The send goes on, and another one can start.
        let second = guard.begin_node_operation().unwrap();
        drop(second);
        drop(send);
        assert_eq!(guard.in_flight.load(Ordering::SeqCst), 0);
        guard.try_begin_exit(&operation).unwrap().commit();
    }

    #[test]
    fn the_exit_is_refused_during_a_custody_operation() {
        let guard = Arc::new(RestartGuard::default());
        let operation = Mutex::new(());
        let backup = operation.lock().unwrap();
        assert_eq!(
            guard.try_begin_exit(&operation).unwrap_err().code,
            "update_busy"
        );
        assert!(guard.refuse_if_exiting().is_ok());
        drop(backup);
        // The lock is only tried: it is free again at once.
        let exit = guard.try_begin_exit(&operation).unwrap();
        assert!(operation.try_lock().is_ok());
        exit.commit();
    }

    #[test]
    fn an_exit_dropped_without_commit_leaves_the_wallet_usable() {
        let guard = Arc::new(RestartGuard::default());
        let operation = Mutex::new(());
        let exit = guard.try_begin_exit(&operation).unwrap();
        // Refused for a later reason (a send that may not be relayed).
        drop(exit);
        assert!(guard.refuse_if_exiting().is_ok());
        drop(guard.begin_node_operation().unwrap());
    }

    #[test]
    fn a_send_racing_the_exit_never_runs_beside_it() {
        for _ in 0..200 {
            let guard = Arc::new(RestartGuard::default());
            let operation = Mutex::new(());
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let (exit_done, wait_exit) = std::sync::mpsc::channel::<()>();
            let sender = {
                let guard = Arc::clone(&guard);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let send = guard.begin_node_operation();
                    // A send that started stays under way until the exit
                    // attempt is over.
                    let _ = wait_exit.recv();
                    send.is_ok()
                })
            };
            barrier.wait();
            let exit = guard.try_begin_exit(&operation);
            let exited = exit.is_ok();
            exit_done.send(()).unwrap();
            let sent = sender.join().unwrap();
            assert!(!(sent && exited));
            if let Ok(exit) = exit {
                exit.commit();
            }
        }
    }

    #[test]
    fn recent_sends_keep_the_newest() {
        let guard = RestartGuard::default();
        for n in 0..(MAX_RECENT_SENDS + 3) {
            guard.record_send(&format!("{n}"), n as u64);
        }
        let sends = guard.recent_sends();
        assert_eq!(sends.len(), MAX_RECENT_SENDS);
        assert_eq!(sends[0], ("3".to_owned(), 3));
        assert_eq!(
            sends.last().unwrap(),
            &(
                format!("{}", MAX_RECENT_SENDS + 2),
                (MAX_RECENT_SENDS + 2) as u64
            )
        );
    }

    #[test]
    fn only_sends_still_in_the_mempool_are_reported() {
        let now = 10_000;
        let sends = vec![(txid(1), now - 600), (txid(2), now - 3600)];
        let mempool = [txid(9)];
        assert_eq!(
            unrelayed_sends(&sends, mempool.iter().map(String::as_str), 0, now),
            UnrelayedSends::default()
        );
        assert_eq!(
            unrelayed_sends(&[], mempool.iter().map(String::as_str), 0, now),
            UnrelayedSends::default()
        );
    }

    #[test]
    fn a_send_under_a_minute_old_may_not_be_relayed() {
        let now = 10_000;
        let sends = vec![
            (txid(1), now - 59),
            (txid(2), now - 60),
            (txid(3), now - 3600),
        ];
        let mempool = [txid(1), txid(2), txid(3)];
        assert_eq!(
            unrelayed_sends(&sends, mempool.iter().map(String::as_str), 4, now),
            UnrelayedSends {
                maybe_not_relayed: 1,
                unconfirmed: 3,
            }
        );
    }

    #[test]
    fn without_peers_every_unconfirmed_send_may_not_be_relayed() {
        let now = 10_000;
        let sends = vec![(txid(1), now - 3600), (txid(2), now - 7200)];
        let mempool = [txid(2), txid(1)];
        assert_eq!(
            unrelayed_sends(&sends, mempool.iter().map(String::as_str), 0, now),
            UnrelayedSends {
                maybe_not_relayed: 2,
                unconfirmed: 2,
            }
        );
    }

    #[test]
    fn a_send_time_after_now_counts_as_just_sent() {
        let sends = vec![(txid(1), 20_000)];
        let mempool = [txid(1)];
        assert_eq!(
            unrelayed_sends(&sends, mempool.iter().map(String::as_str), 8, 10_000)
                .maybe_not_relayed,
            1
        );
    }

    fn failed(code: &'static str, retryable: bool) -> NodePhase {
        NodePhase::Failed {
            code,
            retryable,
            message: "it broke".to_owned(),
        }
    }

    #[test]
    fn a_held_wallet_refuses_every_open_until_released() {
        let guard = RestartGuard::default();
        assert!(!guard.is_held());
        assert!(guard.refuse_if_held().is_ok());
        assert!(!guard.release_hold());
        let fallback = forward::Fallback {
            version: Version::new(1, 0, 17),
            reason: "corrupt_block_log: damaged (it exited with code 4)".into(),
            after_data: true,
        };
        let held = fallback_held_error(&fallback, "1.0.16");
        assert_eq!(held.code, FALLBACK_HELD_CODE);
        assert!(!held.retryable);
        assert!(held.message.contains("Version 1.0.17 stopped"));
        assert!(held.message.contains("corrupt_block_log"));
        assert!(held.message.contains("run 1.0.16 anyway"));
        guard.hold(held.clone());
        assert!(guard.is_held());
        assert_eq!(guard.refuse_if_held(), Err(held));
        assert!(guard.release_hold());
        assert!(guard.refuse_if_held().is_ok());
    }

    #[test]
    fn a_held_wallet_decides_nothing() {
        assert_eq!(
            start_outcome(&failed(FALLBACK_HELD_CODE, false), None),
            StartOutcome::Pending
        );
    }

    #[test]
    fn a_wallet_no_forwarder_started_stays_open_after_a_failed_start() {
        // The test process has no CMFD_UPDATE_FORWARDED.
        assert!(std::env::var_os(forward::FORWARDED_ENV).is_none());
        assert!(!end_failed_start("node_startup_panicked: boom"));
    }

    #[test]
    fn only_a_start_a_forwarder_waits_for_exits_after_a_failed_start() {
        let env = |pairs: &[(&str, &str)]| -> Vec<(OsString, OsString)> {
            pairs
                .iter()
                .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                .collect()
        };
        assert!(!forwarder_waits(&env(&[("PATH", "p")])));
        assert!(forwarder_waits(&env(&[(forward::FORWARDED_ENV, "1")])));
        for odd in ["", "0", "yes"] {
            assert!(
                !forwarder_waits(&env(&[(forward::FORWARDED_ENV, odd)])),
                "{odd}"
            );
        }
        // The start made after a failed relaunch: its maker has exited.
        let spawn_failed =
            restart::spawn_failed_env(&env(&[("PATH", "p")]), 7, "the launched exe is gone");
        assert!(
            spawn_failed
                .iter()
                .any(|(key, _)| is_env_name(key, forward::FORWARDED_ENV))
        );
        assert!(!forwarder_waits(&spawn_failed));
    }

    #[test]
    fn a_ready_node_shows_the_version_works() {
        for opened in [None, Some(Duration::from_secs(1))] {
            assert_eq!(
                start_outcome(&NodePhase::Ready, opened),
                StartOutcome::Started
            );
        }
    }

    #[test]
    fn a_locked_wallet_decides_nothing_however_long_it_waits() {
        // A locked wallet's open returns before the replay, so the data
        // open time is never set; it would not count either.
        for opened in [None, Some(STARTED_AFTER * 10)] {
            assert_eq!(
                start_outcome(&failed("wallet_locked", false), opened),
                StartOutcome::Pending
            );
        }
    }

    fn client_error(code: &'static str, retryable: bool) -> NodeClientError {
        NodeClientError {
            code,
            status: 500,
            retryable,
            message: "it broke".to_owned(),
        }
    }

    #[test]
    fn the_unlock_failure_stands_in_for_a_locked_wallet_only() {
        let locked = failed("wallet_locked", false);
        assert_eq!(with_unlock_failure(locked.clone(), None), locked);
        assert_eq!(
            with_unlock_failure(
                locked.clone(),
                Some(client_error("corrupt_block_log", false))
            ),
            failed("corrupt_block_log", false)
        );
        // A wrong passphrase is a locked wallet again.
        assert_eq!(
            with_unlock_failure(locked.clone(), Some(client_error("wallet_locked", false))),
            locked
        );
        for phase in [
            NodePhase::Starting,
            NodePhase::Ready,
            failed(crate::runtime::CHAIN_RESYNC_REQUIRED, false),
        ] {
            assert_eq!(
                with_unlock_failure(
                    phase.clone(),
                    Some(client_error("corrupt_block_log", false))
                ),
                phase
            );
        }
    }

    #[test]
    fn a_successful_open_clears_the_unlock_failure() {
        let guard = RestartGuard::default();
        assert_eq!(guard.unlock_failure(), None);
        let error = client_error("corrupt_block_log", false);
        guard.record_unlock_failure(&error);
        assert_eq!(guard.unlock_failure(), Some(error));
        guard.mark_data_opened();
        assert_eq!(guard.unlock_failure(), None);
    }

    #[test]
    fn a_node_still_starting_a_minute_after_opening_data_counts_as_started() {
        assert_eq!(
            start_outcome(
                &NodePhase::Starting,
                Some(STARTED_AFTER - Duration::from_millis(1))
            ),
            StartOutcome::Pending
        );
        assert_eq!(
            start_outcome(&NodePhase::Starting, Some(STARTED_AFTER)),
            StartOutcome::Started
        );
    }

    #[test]
    fn time_before_the_data_is_opened_never_counts() {
        // Launch and artifact checks, or a wait for a held data dir.
        assert_eq!(
            start_outcome(&NodePhase::Starting, None),
            StartOutcome::Pending
        );
    }

    #[test]
    fn a_startup_panic_counts_although_it_is_retryable() {
        for opened in [None, Some(STARTED_AFTER * 2)] {
            assert_eq!(
                start_outcome(&failed("node_startup_panicked", true), opened),
                StartOutcome::Failed("node_startup_panicked: it broke".to_owned())
            );
        }
    }

    #[test]
    fn other_retryable_failures_a_held_data_dir_and_a_resync_decide_nothing() {
        for opened in [None, Some(STARTED_AFTER * 2)] {
            assert_eq!(
                start_outcome(&failed("p2p_bind_failed", true), opened),
                StartOutcome::Pending
            );
            assert_eq!(
                start_outcome(&failed("node_startup_unavailable", true), opened),
                StartOutcome::Pending
            );
            assert_eq!(
                start_outcome(&failed("update_state_unwritable", true), opened),
                StartOutcome::Pending
            );
            assert_eq!(
                start_outcome(&failed("data_dir_locked", false), opened),
                StartOutcome::Pending
            );
            assert_eq!(
                start_outcome(
                    &failed(crate::runtime::CHAIN_RESYNC_REQUIRED, false),
                    opened
                ),
                StartOutcome::Pending
            );
        }
    }

    #[test]
    fn another_failure_counts_with_its_reason() {
        assert_eq!(
            start_outcome(&failed("production_v4_artifacts_missing", false), None),
            StartOutcome::Failed("production_v4_artifacts_missing: it broke".to_owned())
        );
        assert_eq!(
            start_outcome(&failed("corrupt_block_log", false), Some(STARTED_AFTER * 2)),
            StartOutcome::Failed("corrupt_block_log: it broke".to_owned())
        );
    }

    #[test]
    fn a_launch_the_preparation_gave_up_on_counts_after_the_launch() {
        let launch = cmfd_launch::MAINNET_LAUNCH_UNIX_SECONDS;
        let missing = || failed(LAUNCH_REQUIRED_CODE, true);
        let gave_up = || Some("plan is absent".to_owned());
        // While the preparation still fetches the beacon, nothing counts.
        for now in [launch - 1, launch, launch + 86_400] {
            let waiting = with_launch_passed(missing(), None, now);
            assert_eq!(waiting, missing());
            assert_eq!(start_outcome(&waiting, None), StartOutcome::Pending);
        }
        // Before the launch time a preparation that gave up decides nothing.
        let early = with_launch_passed(missing(), gave_up(), launch - 1);
        assert_eq!(start_outcome(&early, None), StartOutcome::Pending);
        // After it, nothing brings the launch back: the previous version runs.
        for now in [launch, launch + 86_400] {
            assert_eq!(
                start_outcome(&with_launch_passed(missing(), gave_up(), now), None),
                StartOutcome::Failed(
                    "mainnet_launch_required: launch plan or beacon unavailable, and this \
                     wallet stopped fetching it: plan is absent"
                        .to_owned()
                )
            );
        }
        // Other phases pass through unchanged.
        for phase in [
            NodePhase::Starting,
            NodePhase::Ready,
            failed("p2p_bind_failed", true),
            failed("wallet_locked", false),
        ] {
            assert_eq!(
                with_launch_passed(phase.clone(), gave_up(), launch + 1),
                phase
            );
        }
    }

    #[test]
    fn a_missing_beacon_the_preparation_fetches_again_is_a_start() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let now = cmfd_launch::MAINNET_LAUNCH_UNIX_SECONDS + 86_400;
        let polls = Cell::new(0);
        // The beacon is missing for 50 polls while the preparation fetches
        // it (no failure recorded), then unlock starts the node.
        let end = watch_start(
            &own,
            V17,
            || {
                polls.set(polls.get() + 1);
                let phase = if polls.get() <= 50 {
                    failed(LAUNCH_REQUIRED_CODE, true)
                } else {
                    NodePhase::Ready
                };
                with_launch_passed(phase, None, now)
            },
            || false,
            || Some(STARTED_AFTER),
            |_| {},
        );
        assert_eq!(end, WatchEnd::Started);
        assert_eq!(install::read_state(&own).unwrap().state, STATE_STARTED_OK);
        // A preparation that gave up ends the watch at once instead.
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let before = install::read_state(&own).unwrap();
        let end = watch_start(
            &own,
            V17,
            || {
                with_launch_passed(
                    failed(LAUNCH_REQUIRED_CODE, true),
                    Some("plan is absent".to_owned()),
                    now,
                )
            },
            || false,
            || None,
            |_| {},
        );
        assert!(matches!(end, WatchEnd::Failed(reason) if reason.contains("plan is absent")));
        assert_eq!(install::read_state(&own).unwrap(), before);
    }

    #[test]
    fn the_data_open_time_is_the_last_open() {
        let guard = RestartGuard::default();
        assert_eq!(guard.data_opened_for(), None);
        guard.mark_data_opened();
        let first = guard.data_opened_for().unwrap();
        assert!(first < STARTED_AFTER);
    }

    /// A folder as the updater leaves it, with only its `state.json`.
    fn marked(root: &Path, state: &str, extra: Map<String, Value>) -> PathBuf {
        let dir = root.join("commonfoundry-mainnet-runtime-test-v1.0.17");
        std::fs::create_dir_all(dir.join(MARKER_DIR_NAME)).unwrap();
        install::write_state(
            &dir,
            &InstallState {
                state: state.into(),
                version: "1.0.17".into(),
                sums_sha256: "aa".repeat(32),
                archive_sha256: "bb".repeat(32),
                staged_at: 1,
                extra,
            },
        )
        .unwrap();
        dir
    }

    fn attempts(count: u64) -> Map<String, Value> {
        let mut extra = Map::new();
        extra.insert(forward::START_ATTEMPTS_FIELD.into(), count.into());
        extra.insert(
            forward::FAILURE_FIELD.into(),
            serde_json::json!({"kind": "start", "reason": "it exited with code 1"}),
        );
        extra
    }

    /// Answers with `phases` in turn (the last one again), with the clock
    /// moving on by one poll per sleep. The data counts as opened from the
    /// start unless `opened_after` says after how many polls.
    struct Script {
        phases: RefCell<VecDeque<NodePhase>>,
        alive: Cell<Duration>,
        sleeps: Cell<usize>,
        opened_after: Option<usize>,
    }

    impl Script {
        fn new(phases: &[NodePhase]) -> Self {
            Self {
                phases: RefCell::new(phases.iter().cloned().collect()),
                alive: Cell::new(Duration::ZERO),
                sleeps: Cell::new(0),
                opened_after: Some(0),
            }
        }

        fn never_opened(phases: &[NodePhase]) -> Self {
            Self {
                opened_after: None,
                ..Self::new(phases)
            }
        }

        fn watch(&self, own: &Path, closing: impl Fn() -> bool) -> WatchEnd {
            watch_start(
                own,
                V17,
                || {
                    let mut phases = self.phases.borrow_mut();
                    if phases.len() > 1 {
                        phases.pop_front().unwrap()
                    } else {
                        phases[0].clone()
                    }
                },
                closing,
                || {
                    let after = self.opened_after?;
                    (self.sleeps.get() >= after)
                        .then(|| self.alive.get() - START_POLL * after as u32)
                },
                |delay| {
                    self.sleeps.set(self.sleeps.get() + 1);
                    self.alive.set(self.alive.get() + delay);
                },
            )
        }
    }

    #[test]
    fn a_start_that_reaches_ready_records_started_ok() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, attempts(2));
        let script = Script::new(&[NodePhase::Starting, NodePhase::Starting, NodePhase::Ready]);
        assert_eq!(script.watch(&own, || false), WatchEnd::Started);
        assert_eq!(script.sleeps.get(), 2);
        let state = install::read_state(&own).unwrap();
        assert_eq!(state.state, STATE_STARTED_OK);
        assert_eq!(state.extra[forward::START_ATTEMPTS_FIELD], 0);
        assert!(!state.extra.contains_key(forward::FAILURE_FIELD));
    }

    #[test]
    fn a_wallet_closed_at_the_lock_screen_records_nothing() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let before = install::read_state(&own).unwrap();
        let script = Script::never_opened(&[failed("wallet_locked", false)]);
        let closing = || script.alive.get() >= STARTED_AFTER * 10;
        assert_eq!(script.watch(&own, closing), WatchEnd::Undecided);
        assert_eq!(install::read_state(&own).unwrap(), before);
    }

    #[test]
    fn an_unlock_that_reaches_ready_records_started_ok() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        // The lock screen for a while, wrong passphrases included.
        let mut phases = vec![failed("wallet_locked", false); 100];
        phases.push(NodePhase::Ready);
        let script = Script::never_opened(&phases);
        assert_eq!(script.watch(&own, || false), WatchEnd::Started);
        assert_eq!(install::read_state(&own).unwrap().state, STATE_STARTED_OK);
    }

    #[test]
    fn an_unlock_that_cannot_open_the_chain_is_a_failed_start() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let before = install::read_state(&own).unwrap();
        let guard = RestartGuard::default();
        let polls = Cell::new(0);
        let end = watch_start(
            &own,
            V17,
            || {
                polls.set(polls.get() + 1);
                // The unlock fails at the third poll.
                if polls.get() == 3 {
                    guard.record_unlock_failure(&client_error("corrupt_block_log", false));
                }
                with_unlock_failure(failed("wallet_locked", false), guard.unlock_failure())
            },
            || false,
            || guard.data_opened_for(),
            |_| {},
        );
        assert_eq!(
            end,
            WatchEnd::Failed("corrupt_block_log: it broke".to_owned())
        );
        assert_eq!(polls.get(), 3);
        assert_eq!(install::read_state(&own).unwrap(), before);
    }

    #[test]
    fn an_unlock_that_needs_a_resync_waits_for_the_resync() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let mut phases = vec![failed("wallet_locked", false); 5];
        phases.extend(vec![
            failed(crate::runtime::CHAIN_RESYNC_REQUIRED, false);
            50
        ]);
        phases.push(failed("wallet_locked", false));
        phases.push(NodePhase::Ready);
        let script = Script::never_opened(&phases);
        assert_eq!(script.watch(&own, || false), WatchEnd::Started);
        assert_eq!(install::read_state(&own).unwrap().state, STATE_STARTED_OK);
    }

    #[test]
    fn a_slow_start_records_started_ok_a_minute_after_opening_data() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let script = Script {
            opened_after: Some(30),
            ..Script::new(&[NodePhase::Starting])
        };
        assert_eq!(script.watch(&own, || false), WatchEnd::Started);
        assert_eq!(script.alive.get(), START_POLL * 30 + STARTED_AFTER);
        assert_eq!(install::read_state(&own).unwrap().state, STATE_STARTED_OK);
    }

    #[test]
    fn a_start_that_never_opens_data_is_never_started_by_time() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let before = install::read_state(&own).unwrap();
        let script = Script::never_opened(&[NodePhase::Starting]);
        // Still waiting after ten minutes; then the wallet closes.
        let closing = || script.alive.get() >= STARTED_AFTER * 10;
        assert_eq!(script.watch(&own, closing), WatchEnd::Undecided);
        assert_eq!(install::read_state(&own).unwrap(), before);
    }

    #[test]
    fn a_resync_that_reaches_ready_records_started_ok() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let mut phases = vec![failed(crate::runtime::CHAIN_RESYNC_REQUIRED, false); 300];
        phases.push(NodePhase::Starting);
        phases.push(NodePhase::Ready);
        let script = Script::new(&phases);
        assert_eq!(script.watch(&own, || false), WatchEnd::Started);
        assert_eq!(install::read_state(&own).unwrap().state, STATE_STARTED_OK);
    }

    #[test]
    fn a_failed_start_is_handed_back_and_records_nothing() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, attempts(1));
        let before = install::read_state(&own).unwrap();
        let script = Script::new(&[
            NodePhase::Starting,
            failed("mainnet_launch_evidence", false),
        ]);
        assert_eq!(
            script.watch(&own, || false),
            WatchEnd::Failed("mainnet_launch_evidence: it broke".to_owned())
        );
        // The forwarder counts it from the exit code.
        assert_eq!(install::read_state(&own).unwrap(), before);
    }

    #[test]
    fn a_failure_that_never_counts_records_nothing_until_the_wallet_closes() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let before = install::read_state(&own).unwrap();
        let script = Script::new(&[failed("p2p_bind_failed", true)]);
        let closing = || script.alive.get() >= STARTED_AFTER * 5;
        assert_eq!(script.watch(&own, closing), WatchEnd::Undecided);
        assert_eq!(install::read_state(&own).unwrap(), before);
    }

    #[test]
    fn a_wallet_closed_before_success_records_nothing() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let before = install::read_state(&own).unwrap();
        let script = Script::new(&[NodePhase::Starting]);
        let polls = Cell::new(0);
        let closing = || {
            polls.set(polls.get() + 1);
            polls.get() > 3
        };
        assert_eq!(script.watch(&own, closing), WatchEnd::Undecided);
        assert_eq!(install::read_state(&own).unwrap(), before);
    }

    const V17: Version = Version::new(1, 0, 17);

    #[test]
    fn a_state_that_changed_during_the_watch_is_not_overwritten() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let end = watch_start(
            &own,
            V17,
            || {
                // Another writer settles the state before the start is decided.
                let mut state = install::read_state(&own).unwrap();
                state.state = install::STATE_FAILED.into();
                install::write_state(&own, &state).unwrap();
                NodePhase::Ready
            },
            || false,
            || None,
            |_| {},
        );
        assert_eq!(end, WatchEnd::Started);
        assert_eq!(
            install::read_state(&own).unwrap().state,
            install::STATE_FAILED
        );
    }

    fn state_bytes(own: &Path) -> Vec<u8> {
        std::fs::read(own.join(MARKER_DIR_NAME).join(install::STATE_FILE_NAME)).unwrap()
    }

    #[test]
    fn only_this_versions_staged_state_is_watched_and_marked() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        assert!(has_marker(&own));
        assert_eq!(
            own_state(&own, V17),
            OwnState::Staged { node_opened: false }
        );
        assert_eq!(own_state(&own, Version::new(1, 0, 16)), OwnState::Settled);
        let done = marked(&temp.0.join("done"), STATE_STARTED_OK, Map::new());
        assert_eq!(own_state(&done, V17), OwnState::Settled);
        // A folder the user unpacked by hand has no marker.
        assert!(!has_marker(&temp.0));
    }

    #[test]
    fn opening_data_is_marked_once() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, attempts(1));
        mark_opening_data(&own, V17).unwrap();
        let state = install::read_state(&own).unwrap();
        assert_eq!(state.extra[forward::NODE_OPENED_FIELD], true);
        assert_eq!(state.extra[forward::START_ATTEMPTS_FIELD], 1);
        // Already marked: the file is not written again.
        let path = own.join(MARKER_DIR_NAME).join(install::STATE_FILE_NAME);
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        mark_opening_data(&own, V17).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn a_version_known_to_work_is_neither_marked_nor_watched() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STARTED_OK, Map::new());
        let bytes = state_bytes(&own);
        mark_opening_data(&own, V17).unwrap();
        let (failed_tx, failed_rx) = std::sync::mpsc::channel();
        let watch = spawn_watch_in(
            own.clone(),
            V17,
            || failed("mainnet_launch_evidence", false),
            || false,
            || None,
            move |reason| failed_tx.send(reason).unwrap(),
        );
        assert!(watch.is_none());
        assert!(failed_rx.recv().is_err());
        assert_eq!(state_bytes(&own), bytes);
    }

    #[test]
    fn a_staged_version_that_fails_hands_the_reason_over() {
        let temp = TempDir::new();
        let own = marked(&temp.0, STATE_STAGED, Map::new());
        let bytes = state_bytes(&own);
        let (failed_tx, failed_rx) = std::sync::mpsc::channel();
        spawn_watch_in(
            own.clone(),
            V17,
            || failed("mainnet_launch_evidence", false),
            || false,
            || None,
            move |reason| failed_tx.send(reason).unwrap(),
        )
        .unwrap()
        .join()
        .unwrap();
        assert_eq!(
            failed_rx.recv().unwrap(),
            "mainnet_launch_evidence: it broke"
        );
        assert_eq!(state_bytes(&own), bytes);
    }

    #[test]
    fn an_unreadable_state_stops_the_open_and_is_still_watched() {
        let temp = TempDir::new();
        // A marker dir without a readable state.
        let own = temp.0.join("broken");
        std::fs::create_dir_all(own.join(MARKER_DIR_NAME)).unwrap();
        assert!(has_marker(&own));
        assert_eq!(own_state(&own, V17), OwnState::Unreadable);
        assert!(mark_opening_data(&own, V17).is_err());
        let watch = spawn_watch_in(
            own,
            V17,
            || NodePhase::Ready,
            || false,
            || None,
            |_| panic!("not a failure"),
        );
        watch.unwrap().join().unwrap();
    }

    #[test]
    fn this_test_binary_is_not_an_installed_version() {
        assert_eq!(installed_self(), None);
        assert!(before_node_open().is_ok());
    }

    #[test]
    fn only_handoff_1_is_a_handoff() {
        let env = |pairs: &[(&str, &str)]| -> Vec<(OsString, OsString)> {
            pairs
                .iter()
                .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                .collect()
        };
        assert!(is_handoff(&env(&[("PATH", "x"), (HANDOFF_ENV, "1")])));
        // Another variable outside Windows.
        assert_eq!(
            is_handoff(&env(&[("cmfd_update_handoff", "1")])),
            cfg!(windows)
        );
        assert!(!is_handoff(&env(&[(HANDOFF_ENV, "0")])));
        assert!(!is_handoff(&env(&[(HANDOFF_ENV, "")])));
        assert!(!is_handoff(&env(&[("CMFD_UPDATE_FORWARDED", "1")])));
        assert!(!is_handoff(&[]));
    }

    struct FakeClock {
        start: Instant,
        elapsed: Cell<Duration>,
        sleeps: RefCell<Vec<Duration>>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                start: Instant::now(),
                elapsed: Cell::new(Duration::ZERO),
                sleeps: RefCell::new(Vec::new()),
            }
        }

        fn open<T>(
            &self,
            wait: Duration,
            open: impl FnMut() -> Result<T, NodeError>,
        ) -> Result<T, NodeError> {
            self.open_with(wait, || false, open, || false)
        }

        fn open_with<T>(
            &self,
            wait: Duration,
            held: impl Fn() -> bool,
            open: impl FnMut() -> Result<T, NodeError>,
            closing: impl Fn() -> bool,
        ) -> Result<T, NodeError> {
            open_retrying_while_locked(
                wait,
                held,
                open,
                closing,
                || self.start + self.elapsed.get(),
                |delay| {
                    self.sleeps.borrow_mut().push(delay);
                    self.elapsed.set(self.elapsed.get() + delay);
                },
            )
        }
    }

    fn locked() -> NodeError {
        NodeError::DataDirLocked(PathBuf::from("data"))
    }

    #[test]
    fn a_held_data_dir_is_retried_until_it_is_released() {
        let clock = FakeClock::new();
        let calls = Cell::new(0);
        let opened = clock.open(DATA_DIR_LOCK_WAIT, || {
            calls.set(calls.get() + 1);
            if calls.get() <= 4 {
                Err(locked())
            } else {
                Ok("node")
            }
        });
        assert_eq!(opened.unwrap(), "node");
        assert_eq!(calls.get(), 5);
        assert_eq!(
            *clock.sleeps.borrow(),
            [200, 400, 800, 1600].map(Duration::from_millis)
        );
    }

    #[test]
    fn a_held_data_dir_gives_up_after_the_wait() {
        let clock = FakeClock::new();
        let calls = Cell::new(0);
        let opened: Result<(), _> = clock.open(DATA_DIR_LOCK_WAIT, || {
            calls.set(calls.get() + 1);
            Err(locked())
        });
        assert!(matches!(opened, Err(NodeError::DataDirLocked(_))));
        assert_eq!(clock.elapsed.get(), DATA_DIR_LOCK_WAIT);
        assert!(
            clock
                .sleeps
                .borrow()
                .iter()
                .all(|delay| *delay <= LOCK_RETRY_MAX_DELAY)
        );
        assert!(calls.get() > 30);
    }

    #[test]
    fn the_open_waits_while_the_lock_is_held_without_trying() {
        let clock = FakeClock::new();
        let probes = Cell::new(0);
        let calls = Cell::new(0);
        let opened = clock.open_with(
            DATA_DIR_LOCK_WAIT,
            || {
                probes.set(probes.get() + 1);
                probes.get() <= 3
            },
            || {
                calls.set(calls.get() + 1);
                Ok("node")
            },
            || false,
        );
        assert_eq!(opened.unwrap(), "node");
        // Opened once, after the lock was seen free.
        assert_eq!(calls.get(), 1);
        assert_eq!(
            *clock.sleeps.borrow(),
            [200, 400, 800].map(Duration::from_millis)
        );
    }

    #[test]
    fn a_held_lock_until_the_end_of_the_wait_gives_the_open_one_try() {
        let clock = FakeClock::new();
        let calls = Cell::new(0);
        let opened: Result<(), _> = clock.open_with(
            DATA_DIR_LOCK_WAIT,
            || true,
            || {
                calls.set(calls.get() + 1);
                Err(locked())
            },
            || false,
        );
        assert!(matches!(opened, Err(NodeError::DataDirLocked(_))));
        assert_eq!(calls.get(), 1);
        assert_eq!(clock.elapsed.get(), DATA_DIR_LOCK_WAIT);
    }

    #[test]
    fn a_closing_wallet_ends_the_wait() {
        let clock = FakeClock::new();
        let calls = Cell::new(0);
        let opened: Result<(), _> = clock.open_with(
            DATA_DIR_LOCK_WAIT,
            || false,
            || {
                calls.set(calls.get() + 1);
                Err(locked())
            },
            || clock.sleeps.borrow().len() >= 2,
        );
        assert!(matches!(opened, Err(NodeError::DataDirLocked(_))));
        assert_eq!(calls.get(), 3);
        assert_eq!(clock.sleeps.borrow().len(), 2);
    }

    #[test]
    fn the_lock_probe_sees_another_holder() {
        let temp = TempDir::new();
        let data = temp.0.join("data");
        // No data dir or lock file yet: free.
        assert!(!data_dir_lock_held(&data));
        std::fs::create_dir_all(&data).unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(data.join(NODE_LOCK_FILE))
            .unwrap();
        assert!(!data_dir_lock_held(&data));
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        assert!(data_dir_lock_held(&data));
        fs2::FileExt::unlock(&lock).unwrap();
        assert!(!data_dir_lock_held(&data));
        // The probe released its own try at once.
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    }

    #[test]
    fn without_a_wait_or_another_error_the_open_runs_once() {
        let clock = FakeClock::new();
        let calls = Cell::new(0);
        let opened: Result<(), _> = clock.open_with(
            Duration::ZERO,
            || panic!("no wait asks no probe"),
            || {
                calls.set(calls.get() + 1);
                Err(locked())
            },
            || false,
        );
        assert!(matches!(opened, Err(NodeError::DataDirLocked(_))));
        assert_eq!(calls.get(), 1);
        let calls = Cell::new(0);
        let opened: Result<(), _> = clock.open(DATA_DIR_LOCK_WAIT, || {
            calls.set(calls.get() + 1);
            Err(NodeError::WalletLocked)
        });
        assert!(matches!(opened, Err(NodeError::WalletLocked)));
        assert_eq!(calls.get(), 1);
        assert!(clock.sleeps.borrow().is_empty());
    }
}
