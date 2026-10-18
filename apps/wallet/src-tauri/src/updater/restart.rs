//! The two ends of "Restart to update" (UPDATER-DESIGN.md section 2.7,
//! steps 5 to 8).
//!
//! - **Relaunch.** The closing wallet starts the exe the user launched
//!   ([`forward::launched_from`], else its own exe) again once its event
//!   loop returned, so that exe's forwarder starts the new version and can
//!   fall back. The start has the same arguments and this process's
//!   environment without any `CMFD_UPDATE_*` variable, plus
//!   [`lifecycle::HANDOFF_ENV`]`=1` and [`lifecycle::HANDOFF_PARENT_PID_ENV`]
//!   (this process). It never carries `CMFD_UPDATE_FORWARDED`: the exe must
//!   forward. Its stdin is a pipe whose write end this process keeps until
//!   it ends, so the new version sees end-of-file exactly then. On Windows
//!   it is detached, in a new process group, and out of this process's job
//!   when the job allows that; on Linux in its own process group, so a
//!   terminal closing does not end it.
//! - **Spawn failure.** If that exe cannot be started, this exe is started
//!   instead with [`SPAWN_FAILED_ENV`] (why) and `CMFD_UPDATE_FORWARDED=1`,
//!   so it runs as itself and says why the update did not start. No
//!   forwarder waits for it, so a failed start of its own stays open
//!   ([`lifecycle::forwarder_waits`]).
//! - **Handoff wait.** A start with `CMFD_UPDATE_HANDOFF=1` waits, before
//!   Tauri starts, until its stdin reaches end-of-file (unless stdin is a
//!   terminal) and until the closing wallet's process ended (unless it has
//!   no process id, or it is a fallback start, whose id may be stale).
//!   End-of-file already means the closing wallet is ending, and by then
//!   its id may name another process, so after end-of-file the process id
//!   only gets [`AFTER_END_OF_FILE_WAIT`] for the closing wallet's last
//!   handles to close, and the start goes on either way.
//!   After [`HANDOFF_TIMEOUT`] it exits with [`HANDOFF_TIMEOUT_EXIT_CODE`]
//!   and never continues: the closing wallet still holds the
//!   single-instance lock, and continuing would leave a process with no
//!   window. The forwarder counts that exit as a failed start before
//!   opening data, like any other: a version is only marked failed after
//!   [`forward::MAX_START_ATTEMPTS`] of them in a row, and "Retry" resets it.
//! - **Exit code.** Tauri's event loop always returns 0, so a code this
//!   wallet must exit with (a failed start, [`START_FAILED_EXIT_CODE`]) is
//!   kept here ([`request_exit_code`], [`exit_code`]).

use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::forward;
use super::lifecycle::{self, HANDOFF_ENV, HANDOFF_PARENT_PID_ENV};

/// Set on the start of this exe after the exe the user launched could not
/// be started; the value says why.
pub(crate) const SPAWN_FAILED_ENV: &str = "CMFD_UPDATE_SPAWN_FAILED";
/// How long a handoff start waits for the closing wallet.
pub(crate) const HANDOFF_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a handoff start whose stdin reached end-of-file still waits for
/// the closing wallet's process id: only for its last handles to close.
const AFTER_END_OF_FILE_WAIT: Duration = Duration::from_secs(5);
/// The exit code of a handoff start that waited too long. Not 0 or 2
/// (`forward`'s frozen codes): a forwarder counts it as a failed start
/// before opening data and falls back.
pub(crate) const HANDOFF_TIMEOUT_EXIT_CODE: i32 = 3;
/// The exit code of a forwarded version whose start failed
/// ([`lifecycle::watch_start`]); the forwarder then runs the previous one.
pub(crate) const START_FAILED_EXIT_CODE: i32 = 4;
#[cfg(not(windows))]
const PROCESS_POLL: Duration = Duration::from_millis(200);
const MAX_REASON_CHARS: usize = 300;

/// What a handoff start waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HandoffWait {
    /// stdin, until end-of-file.
    pub(crate) stdin: bool,
    /// The closing wallet, until it ended.
    pub(crate) parent_pid: Option<u32>,
}

/// What a start with `env` must wait for, if it is a handoff start. A
/// fallback start (`fallback_present`) never waits for the process id: the
/// closing wallet may be long gone and its id reused.
pub(crate) fn handoff_wait(
    env: &[(OsString, OsString)],
    fallback_present: bool,
    stdin_is_terminal: bool,
) -> Option<HandoffWait> {
    if !lifecycle::is_handoff(env) {
        return None;
    }
    let parent_pid = if fallback_present {
        None
    } else {
        env.iter()
            .find(|(key, _)| lifecycle::is_env_name(key, HANDOFF_PARENT_PID_ENV))
            .and_then(|(_, value)| value.to_str()?.parse::<u32>().ok())
            .filter(|pid| *pid != 0 && *pid != std::process::id())
    };
    Some(HandoffWait {
        stdin: !stdin_is_terminal,
        parent_pid,
    })
}

/// The handoff wait of a real start, for `run()` before Tauri starts. `Err`
/// holds the code to exit with.
pub(crate) fn wait_for_handoff(fallback_present: bool) -> Result<(), i32> {
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let Some(wait) = handoff_wait(&env, fallback_present, io::stdin().is_terminal()) else {
        return Ok(());
    };
    let deadline = Instant::now() + HANDOFF_TIMEOUT;
    let stdin = if wait.stdin {
        stdin_closed_by(deadline)
    } else {
        StdinWait::NotRead
    };
    if stdin == StdinWait::TimedOut {
        return Err(timed_out(
            "the closing wallet still holds this start's stdin",
        ));
    }
    if stdin == StdinWait::Ended {
        if let Some(pid) = wait.parent_pid {
            let _ = process_ended_by(pid, Instant::now() + AFTER_END_OF_FILE_WAIT);
        }
        return Ok(());
    }
    if let Some(pid) = wait.parent_pid
        && !process_ended_by(pid, deadline)
    {
        return Err(timed_out(&format!(
            "the closing wallet (process {pid}) is still running"
        )));
    }
    Ok(())
}

fn timed_out(why: &str) -> i32 {
    log(&format!(
        "gave up after {} s waiting for the restart: {why}",
        HANDOFF_TIMEOUT.as_secs()
    ));
    HANDOFF_TIMEOUT_EXIT_CODE
}

/// How the wait for stdin's end-of-file ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinWait {
    /// It reached end-of-file: the closing wallet is ending.
    Ended,
    TimedOut,
    /// Not read (a terminal, no reader thread, or a read error): the
    /// process id must tell.
    NotRead,
}

/// Reads stdin to its end on a thread, until `deadline`.
fn stdin_closed_by(deadline: Instant) -> StdinWait {
    let (done, ended) = mpsc::channel();
    let reader = thread::Builder::new()
        .name("cmfd-update-handoff".to_owned())
        .spawn(move || {
            let read = io::copy(&mut io::stdin().lock(), &mut io::sink()).is_ok();
            let _ = done.send(read);
        });
    if reader.is_err() {
        // The process id wait still holds the start back.
        return StdinWait::NotRead;
    }
    match ended.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(true) => StdinWait::Ended,
        Err(mpsc::RecvTimeoutError::Timeout) => StdinWait::TimedOut,
        // A read error is no end-of-file; the reader may also have died.
        Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => StdinWait::NotRead,
    }
}

#[cfg(windows)]
fn process_ended_by(pid: u32, deadline: Instant) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    // SAFETY: plain call; a null handle means no such process.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return true;
    }
    let left = deadline.saturating_duration_since(Instant::now());
    let millis = u32::try_from(left.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: `handle` is a process handle this function owns.
    let ended = unsafe { WaitForSingleObject(handle, millis) } == WAIT_OBJECT_0;
    // SAFETY: closed once, here.
    unsafe { CloseHandle(handle) };
    ended
}

#[cfg(not(windows))]
fn process_ended_by(pid: u32, deadline: Instant) -> bool {
    loop {
        if !process_running(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(PROCESS_POLL);
    }
}

/// Whether `pid` is a process that has not ended: a zombie has ended.
#[cfg(not(windows))]
fn process_running(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // The state follows the command name, which is in parentheses and may
    // itself hold any character.
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.trim_start().chars().next())
        .is_some_and(|state| state != 'Z' && state != 'X')
}

/// The start the closing wallet makes once its event loop returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelaunchTarget {
    /// The exe the user launched.
    pub(crate) exe: PathBuf,
    /// This exe, started instead if `exe` cannot be.
    pub(crate) current_exe: PathBuf,
    pub(crate) args: Vec<OsString>,
    /// This process's environment, as it was.
    pub(crate) env: Vec<(OsString, OsString)>,
    /// Where the updater log goes.
    pub(crate) log_root: Option<PathBuf>,
}

impl RelaunchTarget {
    /// The relaunch of this process: the exe the user launched (a forwarder
    /// passed it on), else this exe; its arguments and environment.
    pub(crate) fn of_this_process(log_root: Option<PathBuf>) -> io::Result<Self> {
        let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        let current_exe = std::env::current_exe()?;
        Ok(Self {
            exe: forward::launched_from(&env).unwrap_or_else(|| current_exe.clone()),
            current_exe,
            args: std::env::args_os().skip(1).collect(),
            env,
            log_root,
        })
    }
}

/// The environment of the relaunch: no `CMFD_UPDATE_*` variable but the
/// handoff pair.
pub(crate) fn relaunch_env(
    env: &[(OsString, OsString)],
    own_pid: u32,
) -> Vec<(OsString, OsString)> {
    let mut child: Vec<(OsString, OsString)> = env
        .iter()
        .filter(|(key, _)| !forward::is_update_variable(key))
        .cloned()
        .collect();
    child.push((HANDOFF_ENV.into(), "1".into()));
    child.push((HANDOFF_PARENT_PID_ENV.into(), own_pid.to_string().into()));
    child
}

/// The environment of the start of this exe after the relaunch failed: it
/// runs as itself (`CMFD_UPDATE_FORWARDED=1`), still waits for this process,
/// keeps the exe the user launched, and says why.
pub(crate) fn spawn_failed_env(
    env: &[(OsString, OsString)],
    own_pid: u32,
    reason: &str,
) -> Vec<(OsString, OsString)> {
    let launched = forward::launched_from(env);
    let mut child = relaunch_env(env, own_pid);
    child.push((forward::FORWARDED_ENV.into(), "1".into()));
    if let Some(launched) = launched {
        child.push((forward::LAUNCHED_FROM_ENV.into(), launched.into()));
    }
    let reason: String = reason.chars().take(MAX_REASON_CHARS).collect();
    child.push((SPAWN_FAILED_ENV.into(), reason.into()));
    child
}

/// Why the relaunch before this start failed, if it did.
pub(crate) fn spawn_failed_reason(env: &[(OsString, OsString)]) -> Option<String> {
    env.iter()
        .find(|(key, _)| lifecycle::is_env_name(key, SPAWN_FAILED_ENV))
        .map(|(_, value)| {
            value
                .to_string_lossy()
                .chars()
                .take(MAX_REASON_CHARS)
                .collect()
        })
}

/// Starts a relaunch. The real one is [`SystemStart`]; tests use a fake.
pub(crate) trait Start {
    fn start(&self, exe: &Path, args: &[OsString], env: &[(OsString, OsString)]) -> io::Result<()>;
}

/// Starts the relaunch, else this exe with the reason.
pub(crate) fn relaunch(target: &RelaunchTarget, own_pid: u32, start: &dyn Start) {
    let log = |line: &str| match &target.log_root {
        Some(root) => forward::log_line(root, line),
        None => log(line),
    };
    let env = relaunch_env(&target.env, own_pid);
    let error = match start.start(&target.exe, &target.args, &env) {
        Ok(()) => {
            log(&format!("restarting through {}", target.exe.display()));
            return;
        }
        Err(error) => error,
    };
    let reason = format!("{} could not be started: {error}", target.exe.display());
    log(&format!("restart failed: {reason}"));
    let env = spawn_failed_env(&target.env, own_pid, &reason);
    if let Err(error) = start.start(&target.current_exe, &target.args, &env) {
        log(&format!(
            "could not start {} again either: {error}",
            target.current_exe.display()
        ));
    }
}

/// Starts a relaunch for real, detached from this process.
pub(crate) struct SystemStart;

impl Start for SystemStart {
    fn start(&self, exe: &Path, args: &[OsString], env: &[(OsString, OsString)]) -> io::Result<()> {
        let command = || {
            let mut command = Command::new(exe);
            command
                .args(args)
                .env_clear()
                .envs(env.iter().map(|(key, value)| (key, value)))
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        };
        #[cfg(windows)]
        let mut child = {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x0000_0008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
            const ERROR_ACCESS_DENIED: i32 = 5;
            let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
            match command()
                .creation_flags(flags | CREATE_BREAKAWAY_FROM_JOB)
                .spawn()
            {
                // A job that does not allow breakaway.
                Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                    command().creation_flags(flags).spawn()?
                }
                result => result?,
            }
        };
        #[cfg(unix)]
        let mut child = {
            use std::os::unix::process::CommandExt;
            command().process_group(0).spawn()?
        };
        #[cfg(not(any(windows, unix)))]
        let mut child = command().spawn()?;
        // The write end stays open until this process ends: the new
        // version's end-of-file on stdin says this process is gone.
        if let Some(stdin) = child.stdin.take() {
            std::mem::forget(stdin);
        }
        Ok(())
    }
}

static RELAUNCH: OnceLock<RelaunchTarget> = OnceLock::new();
static EXIT_CODE: OnceLock<i32> = OnceLock::new();

/// Asks for the relaunch once this wallet's event loop returned; false if
/// one was already asked for.
pub(crate) fn request_relaunch(target: RelaunchTarget) -> bool {
    RELAUNCH.set(target).is_ok()
}

/// For the end of `run()`: starts the relaunch asked for, if any.
pub(crate) fn relaunch_if_requested() {
    if let Some(target) = RELAUNCH.get() {
        relaunch(target, std::process::id(), &SystemStart);
    }
}

/// The code this wallet must exit with, whatever the event loop returns.
/// The first one asked for stays.
pub(crate) fn request_exit_code(code: i32) {
    let _ = EXIT_CODE.set(code);
}

/// The code to exit with, given what the event loop returned.
pub(crate) fn exit_code(event_loop_code: i32) -> i32 {
    EXIT_CODE.get().copied().unwrap_or(event_loop_code)
}

fn log(line: &str) {
    use std::io::Write as _;
    // Not eprintln!, which panics when stderr is a closed pipe.
    let _ = writeln!(io::stderr(), "Common Foundry Wallet updater: {line}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::ffi::OsStr;

    /// Whether `env` sets `name` (Windows: without ASCII case) to `value`.
    fn has(env: &[(OsString, OsString)], name: &str, value: &str) -> bool {
        env.iter()
            .any(|(key, v)| lifecycle::is_env_name(key, name) && v == OsStr::new(value))
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    #[test]
    fn only_a_handoff_start_waits() {
        assert_eq!(handoff_wait(&env(&[("PATH", "x")]), false, false), None);
        assert_eq!(
            handoff_wait(
                &env(&[(HANDOFF_ENV, "0"), (HANDOFF_PARENT_PID_ENV, "42")]),
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn a_handoff_start_waits_for_stdin_and_the_closing_wallet() {
        let handoff = env(&[(HANDOFF_ENV, "1"), (HANDOFF_PARENT_PID_ENV, "42")]);
        assert_eq!(
            handoff_wait(&handoff, false, false),
            Some(HandoffWait {
                stdin: true,
                parent_pid: Some(42),
            })
        );
        // A terminal never reaches end-of-file by itself.
        assert_eq!(
            handoff_wait(&handoff, false, true),
            Some(HandoffWait {
                stdin: false,
                parent_pid: Some(42),
            })
        );
    }

    #[test]
    fn a_fallback_start_or_one_without_an_id_waits_only_for_stdin() {
        let handoff = env(&[(HANDOFF_ENV, "1"), (HANDOFF_PARENT_PID_ENV, "42")]);
        assert_eq!(
            handoff_wait(&handoff, true, false),
            Some(HandoffWait {
                stdin: true,
                parent_pid: None,
            })
        );
        for pid in ["", "abc", "0", &std::process::id().to_string()] {
            let handoff = env(&[(HANDOFF_ENV, "1"), (HANDOFF_PARENT_PID_ENV, pid)]);
            assert_eq!(
                handoff_wait(&handoff, false, false).unwrap().parent_pid,
                None,
                "{pid:?}"
            );
        }
        assert_eq!(
            handoff_wait(&env(&[(HANDOFF_ENV, "1")]), false, false),
            Some(HandoffWait {
                stdin: true,
                parent_pid: None,
            })
        );
    }

    #[test]
    fn a_process_that_ended_is_seen_as_ended() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert!(process_ended_by(
            pid,
            Instant::now() + Duration::from_secs(5)
        ));
        // This test process is running: the wait gives up at the deadline.
        assert!(!process_ended_by(
            std::process::id(),
            Instant::now() + Duration::from_millis(300)
        ));
    }

    #[test]
    fn the_relaunch_keeps_no_update_variable_but_the_handoff_pair() {
        let child = relaunch_env(
            &env(&[
                ("PATH", "p"),
                (forward::FORWARDED_ENV, "1"),
                (forward::LAUNCHED_FROM_ENV, "/a/wallet"),
                ("CMFD_UPDATE_FALLBACK_FROM", "1.0.17"),
                (HANDOFF_ENV, "1"),
                (HANDOFF_PARENT_PID_ENV, "7"),
                (forward::NO_AUTO_UPDATE_ENV, "0"),
            ]),
            1234,
        );
        assert_eq!(
            child,
            env(&[
                ("PATH", "p"),
                (forward::NO_AUTO_UPDATE_ENV, "0"),
                (HANDOFF_ENV, "1"),
                (HANDOFF_PARENT_PID_ENV, "1234"),
            ])
        );
        // The exe the user launched must forward again.
        assert!(!has(&child, forward::FORWARDED_ENV, "1"));
    }

    #[test]
    fn the_spawn_failed_start_runs_as_itself_and_says_why() {
        let launched = if cfg!(windows) {
            "C:\\a\\wallet.exe"
        } else {
            "/a/wallet"
        };
        let child = spawn_failed_env(
            &env(&[("PATH", "p"), (forward::LAUNCHED_FROM_ENV, launched)]),
            99,
            "blocked",
        );
        assert!(has(&child, forward::FORWARDED_ENV, "1"));
        assert!(has(&child, HANDOFF_ENV, "1"));
        assert!(has(&child, HANDOFF_PARENT_PID_ENV, "99"));
        assert!(has(&child, forward::LAUNCHED_FROM_ENV, launched));
        assert_eq!(spawn_failed_reason(&child).as_deref(), Some("blocked"));
        assert_eq!(spawn_failed_reason(&env(&[("PATH", "p")])), None);
    }

    /// One start: the exe and its environment.
    type Started = (PathBuf, Vec<(OsString, OsString)>);

    struct Fake {
        fail: Vec<PathBuf>,
        started: RefCell<Vec<Started>>,
    }

    impl Start for Fake {
        fn start(
            &self,
            exe: &Path,
            _args: &[OsString],
            env: &[(OsString, OsString)],
        ) -> io::Result<()> {
            self.started
                .borrow_mut()
                .push((exe.to_path_buf(), env.to_vec()));
            if self.fail.iter().any(|fail| fail == exe) {
                Err(io::Error::other("blocked by antivirus"))
            } else {
                Ok(())
            }
        }
    }

    fn target() -> RelaunchTarget {
        RelaunchTarget {
            exe: PathBuf::from("anchor"),
            current_exe: PathBuf::from("current"),
            args: vec!["--data-dir".into(), "d".into()],
            env: env(&[("PATH", "p")]),
            log_root: None,
        }
    }

    #[test]
    fn the_relaunch_starts_the_exe_the_user_launched() {
        let fake = Fake {
            fail: Vec::new(),
            started: RefCell::default(),
        };
        relaunch(&target(), 5, &fake);
        let started = fake.started.borrow();
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].0, PathBuf::from("anchor"));
        assert!(has(&started[0].1, HANDOFF_PARENT_PID_ENV, "5"));
    }

    #[test]
    fn a_relaunch_that_cannot_start_starts_this_exe_with_the_reason() {
        let fake = Fake {
            fail: vec![PathBuf::from("anchor")],
            started: RefCell::default(),
        };
        relaunch(&target(), 5, &fake);
        let started = fake.started.borrow();
        assert_eq!(started.len(), 2);
        assert_eq!(started[1].0, PathBuf::from("current"));
        assert!(has(&started[1].1, forward::FORWARDED_ENV, "1"));
        assert!(
            spawn_failed_reason(&started[1].1)
                .unwrap()
                .contains("blocked by antivirus")
        );
    }

    #[test]
    fn the_first_exit_code_asked_for_wins_over_the_event_loop() {
        // EXIT_CODE is process-wide; this is the only test that sets it.
        request_exit_code(START_FAILED_EXIT_CODE);
        request_exit_code(9);
        assert_eq!(exit_code(0), START_FAILED_EXIT_CODE);
    }
}
