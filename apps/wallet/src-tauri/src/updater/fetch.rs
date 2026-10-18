//! Bounded HTTPS downloads through the system curl (UPDATER-DESIGN.md
//! section 2.3 "curl", and section 2.6 staging steps 2 and 3).
//!
//! curl is `curl.exe` in the System32 dir (from `GetSystemDirectoryW`) on
//! Windows, or `/usr/bin/curl`, else `/bin/curl`, on Linux. There is no PATH
//! lookup and no shell. Every request is HTTPS only, redirects included, and
//! is bounded twice: by curl's own flags, and by this module, which watches
//! the output file, kills curl once it passes the cap, and checks the size
//! again after curl exits.
//!
//! The body always goes to a file and the HTTP status comes back on stdout
//! through `--write-out`, so the status never shares a channel with the body.
//! That works with every curl that Windows and Linux ship.
//!
//! The curl process sits behind [`Spawn`], so tests drive the size-poll kill,
//! the partial-file rules and the status mapping with a scripted fake. The
//! real curl runs only in the `updater-e2e` tests, against `file://` URLs.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::release::{self, Response, Transport, TransportError};

/// `--max-time` for metadata: one release-list page or one signed file.
const GET_MAX_TIME: Duration = Duration::from_secs(120);
/// `--max-time` for one attempt at the runtime archive. An interrupted
/// download resumes on the next attempt.
const ARCHIVE_MAX_TIME: Duration = Duration::from_secs(60 * 60);
/// curl is killed if it outlives its own `--max-time` by this much.
const PROCESS_GRACE: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
/// stdout carries only the three digits of `%{http_code}`.
const MAX_STDOUT_BYTES: usize = 16;
const MAX_STDERR_BYTES: usize = 2048;
const USER_AGENT: &str = concat!("cmfd-wallet/", env!("CARGO_PKG_VERSION"));

/// What the checked runtime archive is renamed to in its staging dir.
pub(crate) const ARCHIVE_NAME: &str = "archive";

const CURL_OK: i32 = 0;
/// `--fail` and an HTTP status of 400 or more.
const CURL_HTTP_ERROR: i32 = 22;
/// The server will not resume (`--continue-at`).
const CURL_RANGE_ERROR: i32 = 33;
/// A `file://` source that does not exist (e2e tests only).
const CURL_FILE_COULDNT_READ: i32 = 37;
/// `--max-filesize` exceeded.
const CURL_FILESIZE_EXCEEDED: i32 = 63;
/// What curl returns for an option it does not know.
const CURL_UNKNOWN_OPTION: i32 = 2;
/// Windows only: the System32 curl uses Schannel, which by default refuses a
/// certificate whose revocation it cannot check (behind antivirus or company
/// TLS inspection, or when the revocation server cannot be reached). Every
/// byte the updater takes is checked against the signed release, so a
/// revocation check that cannot be done is not a reason to stop. curl knows
/// the option from 7.70.0 on; an older one is run again without it.
const REVOKE_BEST_EFFORT: &str = "--ssl-revoke-best-effort";

/// Starts a program without a shell, with stdin closed and stdout and stderr
/// piped. The real one is [`SystemSpawn`]; tests use a fake.
pub(crate) trait Spawn: Send + Sync {
    fn spawn(&self, program: &Path, args: &[OsString]) -> io::Result<Spawned>;
}

pub(crate) struct Spawned {
    pub(crate) child: Box<dyn Child>,
    pub(crate) stdout: Box<dyn Read + Send>,
    pub(crate) stderr: Box<dyn Read + Send>,
}

pub(crate) trait Child {
    /// `Some(code)` once the process has exited. The code is `None` if a
    /// signal ended it.
    fn try_wait(&mut self) -> io::Result<Option<Option<i32>>>;
    /// Kills the process and waits for it.
    fn kill(&mut self);
}

struct SystemSpawn;

impl Spawn for SystemSpawn {
    fn spawn(&self, program: &Path, args: &[OsString]) -> io::Result<Spawned> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (child, stdout, stderr) = spawn_tied_to_wallet(&mut command)?;
        Ok(Spawned {
            child: Box::new(child),
            stdout: Box::new(stdout),
            stderr: Box::new(stderr),
        })
    }
}

/// Starts `command` so that it dies with the wallet, even when the wallet
/// is killed or crashes and no guard runs. Otherwise an orphaned curl could
/// keep writing to a partial download for up to an hour while the next
/// wallet resumes the same file.
///
/// On Windows the child goes into a job object that kills it once the last
/// handle to the job closes, which the kernel does when the wallet exits.
/// On Linux the child asks for SIGKILL when the thread that started it
/// exits; that thread is the one waiting on curl in [`Curl::run`].
pub(super) fn spawn_tied_to_wallet(
    command: &mut Command,
) -> io::Result<(
    SystemChild,
    std::process::ChildStdout,
    std::process::ChildStderr,
)> {
    #[cfg(windows)]
    let job = {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        // Before the spawn, so a failure here leaves no process behind.
        KillOnClose::new()?
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let wallet = std::process::id();
        // SAFETY: the closure runs in the forked child before exec. It only
        // makes the prctl and getppid system calls, reads errno, and builds
        // io::Errors from raw codes, none of which allocate or take locks.
        unsafe {
            command.pre_exec(move || {
                if linux::prctl(linux::PR_SET_PDEATHSIG, linux::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // The wallet may have exited before prctl took effect.
                if linux::getppid() as u32 != wallet {
                    return Err(io::Error::from_raw_os_error(linux::ESRCH));
                }
                Ok(())
            });
        }
    }
    let mut child = command.spawn()?;
    #[cfg(windows)]
    if let Err(error) = job.assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("curl's output pipes are missing"));
    };
    let child = SystemChild {
        child,
        #[cfg(windows)]
        _job: job,
    };
    Ok((child, stdout, stderr))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{c_int, c_ulong};

    pub(super) const PR_SET_PDEATHSIG: c_int = 1;
    pub(super) const SIGKILL: c_ulong = 9;
    pub(super) const ESRCH: i32 = 3;

    unsafe extern "C" {
        pub(super) fn prctl(option: c_int, ...) -> c_int;
        pub(super) fn getppid() -> c_int;
    }
}

/// A job object that kills every process in it when its last handle
/// closes.
#[cfg(windows)]
struct KillOnClose(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl KillOnClose {
    fn new() -> io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        // SAFETY: no security attributes and no name; the handle is owned
        // by the result and closed in its Drop.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self(handle);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the pointer and the length describe `limits`, which lives
        // for the whole call, and the class says which struct it is.
        let set = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        };
        if set == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn assign(&self, child: &std::process::Child) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        // SAFETY: both handles are open: the job is owned by `self`, the
        // process by `child`.
        if unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for KillOnClose {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateJobObjectW and is closed once.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

pub(super) struct SystemChild {
    child: std::process::Child,
    /// Dropped after `child`, so a curl still running then is killed.
    #[cfg(windows)]
    _job: KillOnClose,
}

impl Child for SystemChild {
    fn try_wait(&mut self) -> io::Result<Option<Option<i32>>> {
        Ok(self.child.try_wait()?.map(|status| status.code()))
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Kills the child unless it was seen to exit, on every early return and on
/// a panic.
struct Running {
    child: Box<dyn Child>,
    exited: bool,
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.exited {
            self.child.kill();
        }
    }
}

/// Reads up to `limit` bytes, then keeps draining so curl never blocks on a
/// full pipe.
pub(super) fn bounded_reader(
    mut source: Box<dyn Read + Send>,
    limit: usize,
) -> io::Result<JoinHandle<Vec<u8>>> {
    thread::Builder::new()
        .name("cmfd-updater-curl-pipe".into())
        .spawn(move || {
            let mut kept = Vec::new();
            let _ = (&mut source).take(limit as u64).read_to_end(&mut kept);
            let _ = io::copy(&mut source, &mut io::sink());
            kept
        })
}

/// A curl run that ended by itself.
struct Finished {
    exit: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// A curl run that this module stopped, or could not start.
#[derive(Debug)]
enum Stopped {
    Cancelled,
    TimedOut,
    /// The output file passed its cap.
    Oversized,
    Io(io::Error),
}

impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("cancelled"),
            Self::TimedOut => f.write_str("curl did not finish in time"),
            Self::Oversized => f.write_str("the download is too large"),
            Self::Io(error) => write!(f, "could not run curl: {error}"),
        }
    }
}

/// What a finished curl run means.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// An HTTP 2xx, or a readable `file://` source: the body is in the
    /// output file.
    Body(u16),
    /// Any other HTTP status. With `--fail`, nothing is written for 400 and up.
    Status(u16),
    /// Over `--max-filesize`.
    TooLarge,
    /// The server will not resume a partial download.
    CannotResume,
    /// No HTTP answer (DNS, connect, TLS, timeout), or a transfer that broke
    /// off.
    NoAnswer(String),
}

/// Why the runtime archive is not ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DownloadError {
    Cancelled,
    /// No answer, or the transfer broke off. The partial file is kept and
    /// resumes on the next attempt.
    Interrupted(String),
    /// HTTP 404.
    Missing,
    /// Any other HTTP status. The partial is kept, since `--fail` wrote
    /// nothing to it, except after a 416 or a 200 or 206 that was not
    /// asked for.
    Status(u16),
    /// The server will not resume; the next attempt starts over.
    CannotResume,
    /// Larger than the signed size.
    TooLarge,
    /// The finished file is not the signed size.
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    /// The finished file does not match its SUMS row.
    HashMismatch,
    /// Not an HTTPS URL, or not a plain file name.
    Refused(&'static str),
    /// A local file error.
    Io(String),
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("the download was cancelled"),
            Self::Interrupted(detail) => write!(f, "the download was interrupted: {detail}"),
            Self::Missing => f.write_str("the release file is not on the server (HTTP 404)"),
            Self::Status(status) => write!(f, "the server answered HTTP {status}"),
            Self::CannotResume => f.write_str("the server would not resume the download"),
            Self::TooLarge => f.write_str("the download is larger than the signed size"),
            Self::SizeMismatch { expected, actual } => {
                write!(
                    f,
                    "the download is {actual} bytes, not the signed {expected}"
                )
            }
            Self::HashMismatch => f.write_str("the download does not match its signed SHA-256"),
            Self::Refused(reason) => write!(f, "download refused: {reason}"),
            Self::Io(detail) => write!(f, "could not save the download: {detail}"),
        }
    }
}

impl std::error::Error for DownloadError {}

/// The system curl: `curl.exe` in the System32 dir on Windows, the first of
/// `/usr/bin/curl` and `/bin/curl` on Linux. `None` means the updater can
/// only report "curl not found".
pub(crate) fn system_curl() -> Option<PathBuf> {
    #[cfg(windows)]
    let candidates = [system_directory()?.join("curl.exe")];
    #[cfg(not(windows))]
    let candidates = [PathBuf::from("/usr/bin/curl"), PathBuf::from("/bin/curl")];
    candidates.into_iter().find(|path| path.is_file())
}

/// The System32 dir from `GetSystemDirectoryW`, not from `%SystemRoot%`,
/// which the environment can change.
#[cfg(windows)]
pub(super) fn system_directory() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = vec![0u16; 260];
    loop {
        let capacity = u32::try_from(buffer.len()).ok()?;
        // SAFETY: the pointer and the length describe `buffer`, which lives
        // for the whole call.
        let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity) } as usize;
        if written == 0 {
            return None;
        }
        if written < buffer.len() {
            buffer.truncate(written);
            return Some(OsString::from_wide(&buffer).into());
        }
        // Too small: `written` is the size needed, with the final NUL.
        buffer.resize(written, 0);
    }
}

/// Bounded HTTPS requests through the system curl.
pub(crate) struct Curl {
    spawner: Box<dyn Spawn>,
    program: PathBuf,
    /// Set only by the e2e constructor, for `file://` release sources.
    allow_file: bool,
    /// A private dir of the updater's that holds metadata bodies while they
    /// are read.
    scratch: PathBuf,
    cancel: Arc<AtomicBool>,
    /// Pass [`REVOKE_BEST_EFFORT`]: on Windows, until a curl refuses it.
    revoke_best_effort: AtomicBool,
}

impl Curl {
    /// The system curl, or `None` if it is missing. `scratch` must be an
    /// existing dir that only the updater writes to. Setting `cancel` kills
    /// a running request.
    pub(crate) fn system(scratch: PathBuf, cancel: Arc<AtomicBool>) -> Option<Self> {
        Some(Self {
            spawner: Box::new(SystemSpawn),
            program: system_curl()?,
            allow_file: false,
            scratch,
            cancel,
            revoke_best_effort: AtomicBool::new(cfg!(windows)),
        })
    }

    /// Like [`Curl::system`], but also accepts `file://` URLs.
    #[cfg(feature = "updater-e2e")]
    pub(crate) fn system_allowing_file_urls(
        scratch: PathBuf,
        cancel: Arc<AtomicBool>,
    ) -> Option<Self> {
        let mut curl = Self::system(scratch, cancel)?;
        curl.allow_file = true;
        Some(curl)
    }

    fn is_file_url(&self, url: &str) -> bool {
        self.allow_file && url.starts_with("file://")
    }

    fn check_url(&self, url: &str) -> Result<(), &'static str> {
        if !url.starts_with("https://") && !self.is_file_url(url) {
            return Err("not an https URL");
        }
        if !url.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err("the URL has a space or a control character");
        }
        Ok(())
    }

    fn args(
        &self,
        url: &str,
        output: &Path,
        max_filesize: u64,
        max_time: Duration,
        resume: bool,
    ) -> Vec<OsString> {
        let protocols = if self.allow_file {
            "=https,file"
        } else {
            "=https"
        };
        let mut args: Vec<OsString> = [
            // Must come first: ignore any .curlrc.
            "--disable",
            "--silent",
            "--show-error",
            // Not in the design's flag list: without it a 4xx or 5xx error
            // page would land in the output file, or be appended to a
            // partial download.
            "--fail",
            "--proto",
            protocols,
            "--proto-redir",
            "=https",
            "--location",
            "--max-redirs",
            "5",
            "--connect-timeout",
            "15",
            // A stalled transfer ends early instead of at --max-time; an
            // archive download then resumes on the next attempt.
            "--speed-limit",
            "1024",
            "--speed-time",
            "60",
            // The URL is used as given: no [] or {} expansion.
            "--globoff",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if self.revoke_best_effort.load(Ordering::Relaxed) {
            args.push(REVOKE_BEST_EFFORT.into());
        }
        args.extend([
            "--max-time".into(),
            max_time.as_secs().to_string().into(),
            "--max-filesize".into(),
            max_filesize.to_string().into(),
            "--user-agent".into(),
            USER_AGENT.into(),
            "--write-out".into(),
            "%{http_code}".into(),
            "--output".into(),
            output.as_os_str().to_owned(),
        ]);
        if resume {
            args.extend(["--continue-at".into(), "-".into()]);
        }
        args.extend(["--url".into(), url.into()]);
        args
    }

    /// Runs curl until it exits, killing it on cancel, on a timeout, or once
    /// `output` grows past `max_bytes`.
    fn run(
        &self,
        args: &[OsString],
        output: &Path,
        max_bytes: u64,
        max_time: Duration,
    ) -> Result<Finished, Stopped> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(Stopped::Cancelled);
        }
        let spawned = self
            .spawner
            .spawn(&self.program, args)
            .map_err(Stopped::Io)?;
        let mut running = Running {
            child: spawned.child,
            exited: false,
        };
        let stdout = bounded_reader(spawned.stdout, MAX_STDOUT_BYTES).map_err(Stopped::Io)?;
        let stderr = bounded_reader(spawned.stderr, MAX_STDERR_BYTES).map_err(Stopped::Io)?;
        let deadline = Instant::now() + max_time + PROCESS_GRACE;
        let outcome = loop {
            if self.cancel.load(Ordering::Acquire) {
                break Err(Stopped::Cancelled);
            }
            if Instant::now() >= deadline {
                break Err(Stopped::TimedOut);
            }
            if file_len(output) > max_bytes {
                break Err(Stopped::Oversized);
            }
            match running.child.try_wait() {
                Ok(Some(exit)) => {
                    running.exited = true;
                    break Ok(exit);
                }
                Ok(None) => thread::sleep(POLL_INTERVAL),
                Err(error) => break Err(Stopped::Io(error)),
            }
        };
        // Kill first, so the pipes close and the readers finish.
        drop(running);
        let stdout = stdout.join().unwrap_or_default();
        let stderr = stderr.join().unwrap_or_default();
        let exit = outcome?;
        // curl's own size check depends on its version and on Content-Length.
        if file_len(output) > max_bytes {
            return Err(Stopped::Oversized);
        }
        Ok(Finished {
            exit,
            stdout,
            stderr,
        })
    }

    /// Runs one request with the arguments of [`Curl::args`]. A curl too
    /// old for [`REVOKE_BEST_EFFORT`] refuses it before it does anything, so
    /// the request is run again without it, and so is every later one.
    fn run_request(
        &self,
        url: &str,
        output: &Path,
        max_filesize: u64,
        max_time: Duration,
        resume: bool,
        max_bytes: u64,
    ) -> Result<Finished, Stopped> {
        let args = self.args(url, output, max_filesize, max_time, resume);
        let run = self.run(&args, output, max_bytes, max_time)?;
        let refused = run.exit == Some(CURL_UNKNOWN_OPTION)
            && String::from_utf8_lossy(&run.stderr).contains(REVOKE_BEST_EFFORT);
        if !refused || !self.revoke_best_effort.swap(false, Ordering::Relaxed) {
            return Ok(run);
        }
        let args = self.args(url, output, max_filesize, max_time, resume);
        self.run(&args, output, max_bytes, max_time)
    }

    fn answer(&self, url: &str, run: &Finished) -> Outcome {
        let status = std::str::from_utf8(&run.stdout)
            .ok()
            .filter(|text| text.len() == 3 && text.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|text| text.parse::<u16>().ok());
        let file = self.is_file_url(url);
        match (run.exit, status) {
            (Some(CURL_FILESIZE_EXCEEDED), _) => Outcome::TooLarge,
            (Some(CURL_RANGE_ERROR), _) => Outcome::CannotResume,
            // file:// has no status code.
            (Some(CURL_OK), Some(0)) if file => Outcome::Body(200),
            (Some(CURL_FILE_COULDNT_READ), _) if file => Outcome::Status(404),
            (Some(CURL_OK), Some(status @ 200..=299)) => Outcome::Body(status),
            (Some(CURL_OK), Some(status @ 100..=399)) => Outcome::Status(status),
            // A resume past the end of the served file: --fail lets curl
            // exit 0 for this one.
            (Some(CURL_OK), Some(416)) => Outcome::Status(416),
            (Some(CURL_HTTP_ERROR), Some(status @ 400..=599)) => Outcome::Status(status),
            _ => Outcome::NoAnswer(describe(run)),
        }
    }

    fn get_into(&self, url: &str, body: &Path, max_bytes: u64) -> Result<Response, TransportError> {
        let no_answer = |detail: String| TransportError::NoAnswer(detail);
        // Start from an empty file of our own.
        let _ = fs::remove_file(body);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(body)
            .map_err(|error| no_answer(format!("could not create {}: {error}", body.display())))?;
        let run = match self.run_request(url, body, max_bytes, GET_MAX_TIME, false, max_bytes) {
            Ok(run) => run,
            Err(Stopped::Oversized) => return Err(TransportError::TooLarge),
            Err(Stopped::Cancelled) => return Err(TransportError::Cancelled),
            Err(stopped) => return Err(no_answer(stopped.to_string())),
        };
        match self.answer(url, &run) {
            Outcome::Body(200) => {
                let mut bytes = Vec::new();
                File::open(body)
                    .and_then(|file| file.take(max_bytes + 1).read_to_end(&mut bytes))
                    .map_err(|error| no_answer(format!("could not read the body: {error}")))?;
                if bytes.len() as u64 > max_bytes {
                    return Err(TransportError::TooLarge);
                }
                Ok(Response {
                    status: 200,
                    body: bytes,
                })
            }
            Outcome::Body(status) | Outcome::Status(status) => Ok(Response {
                status,
                body: Vec::new(),
            }),
            Outcome::TooLarge => Err(TransportError::TooLarge),
            Outcome::CannotResume => Err(no_answer(describe(&run))),
            Outcome::NoAnswer(detail) => Err(no_answer(detail)),
        }
    }

    /// Downloads the runtime archive into `dir`, the version's staging dir,
    /// and returns the checked file, `dir/archive`.
    ///
    /// The download goes to `<name>.<first 16 hex digits of sha256>.partial`.
    /// Every other `*.partial` in `dir` is deleted first. A partial for this
    /// sha256 resumes; one at the full size is only checked. These delete
    /// the partial: a size or hash mismatch, a 404, a 416, a 200 to a resume,
    /// a 206 to a fresh start, a server that will not resume, or a file over
    /// the signed size. Any other outcome keeps it for the next attempt.
    /// Failing to delete another `*.partial` does not stop the download.
    ///
    /// The hash is checked on a path in `dir`, so `dir` must be private to
    /// the updater, and install must check the archive again from the
    /// handle it extracts from.
    pub(crate) fn download_archive(
        &self,
        url: &str,
        dir: &Path,
        name: &str,
        size: u64,
        sha256: &[u8; 32],
    ) -> Result<PathBuf, DownloadError> {
        self.check_url(url).map_err(DownloadError::Refused)?;
        if name.contains('/') || !release::is_package_path(name) {
            return Err(DownloadError::Refused("not a plain file name"));
        }
        if size == 0 {
            return Err(DownloadError::Refused("the signed size is zero"));
        }
        let partial = dir.join(format!("{name}.{}.partial", hex::encode(&sha256[..8])));
        remove_other_partials(dir, &partial);
        let have = match fs::symlink_metadata(&partial) {
            Ok(meta) if meta.is_file() && meta.len() <= size => meta.len(),
            Ok(_) => {
                fs::remove_file(&partial).map_err(io_error)?;
                0
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(io_error(error)),
        };
        if have < size {
            self.fetch_archive(url, &partial, size, have)?;
        }
        let actual = file_len(&partial);
        if actual != size {
            discard(&partial);
            return Err(DownloadError::SizeMismatch {
                expected: size,
                actual,
            });
        }
        if sha256_file(&partial).map_err(io_error)? != *sha256 {
            discard(&partial);
            return Err(DownloadError::HashMismatch);
        }
        let archive = dir.join(ARCHIVE_NAME);
        fs::rename(&partial, &archive).map_err(io_error)?;
        Ok(archive)
    }

    fn fetch_archive(
        &self,
        url: &str,
        partial: &Path,
        size: u64,
        have: u64,
    ) -> Result<(), DownloadError> {
        // An empty partial is a fresh start: curl would answer a resume from
        // 0 with a plain 200.
        let resume = have > 0;
        if !resume {
            discard(partial);
        }
        // On a resume, curl's --max-filesize counts only the bytes still to
        // come. The size poll watches the whole file.
        let run = match self.run_request(url, partial, size - have, ARCHIVE_MAX_TIME, resume, size)
        {
            Ok(run) => run,
            Err(Stopped::Oversized) => {
                discard(partial);
                return Err(DownloadError::TooLarge);
            }
            Err(Stopped::Cancelled) => return Err(DownloadError::Cancelled),
            Err(Stopped::Io(error)) => return Err(io_error(error)),
            Err(stopped @ Stopped::TimedOut) => {
                return Err(DownloadError::Interrupted(stopped.to_string()));
            }
        };
        let error = match self.answer(url, &run) {
            Outcome::NoAnswer(detail) => return Err(DownloadError::Interrupted(detail)),
            Outcome::Body(206) if resume => return Ok(()),
            Outcome::Body(200) if !resume || self.is_file_url(url) => return Ok(()),
            Outcome::Body(404) | Outcome::Status(404) => DownloadError::Missing,
            // The partial is no prefix of what was asked for, or reaches
            // past the end of the served file.
            Outcome::Body(status) | Outcome::Status(status @ 416) => DownloadError::Status(status),
            // --fail wrote nothing, so the partial is still good: a 5xx, a
            // rate limit or an expired redirect must not restart a large
            // download from zero.
            Outcome::Status(status) => return Err(DownloadError::Status(status)),
            Outcome::TooLarge => DownloadError::TooLarge,
            Outcome::CannotResume => DownloadError::CannotResume,
        };
        discard(partial);
        Err(error)
    }
}

impl Transport for Curl {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Response, TransportError> {
        static NEXT_BODY: AtomicU64 = AtomicU64::new(0);
        self.check_url(url)
            .map_err(|reason| TransportError::NoAnswer(reason.into()))?;
        let body = self.scratch.join(format!(
            "get-{}-{}.body",
            std::process::id(),
            NEXT_BODY.fetch_add(1, Ordering::Relaxed)
        ));
        let result = self.get_into(url, &body, max_bytes);
        let _ = fs::remove_file(&body);
        result
    }
}

fn describe(run: &Finished) -> String {
    let message = String::from_utf8_lossy(&run.stderr);
    let message = message.lines().next().unwrap_or("").trim();
    match run.exit {
        Some(code) if message.is_empty() => format!("curl exit {code}"),
        Some(code) => format!("curl exit {code}: {message}"),
        None => "curl was stopped by a signal".into(),
    }
}

fn file_len(path: &Path) -> u64 {
    fs::symlink_metadata(path).map_or(0, |meta| meta.len())
}

fn discard(path: &Path) {
    let _ = fs::remove_file(path);
}

fn io_error(error: io::Error) -> DownloadError {
    DownloadError::Io(error.to_string())
}

/// Best effort: a stale partial that cannot be deleted (locked, read-only,
/// a link to a dir) is left for a later round.
fn remove_other_partials(dir: &Path, keep: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_partial = entry.file_name().to_string_lossy().ends_with(".partial");
        let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if is_partial && path != keep && !is_dir {
            discard(&path);
        }
    }
}

fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(context.finish().as_ref());
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, AtomicUsize};
    use std::time::{SystemTime, UNIX_EPOCH};

    const URL: &str = "https://github.com/o/r/releases/download/v1.0.16/a.zip";
    const NAME: &str = "commonfoundry-mainnet-runtime-windows-x86_64-v1.0.16.zip";
    const ARCHIVE: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "cmfd-update-fetch-{}-{unique}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
        digest
    }

    fn partial_name(bytes: &[u8]) -> String {
        format!("{NAME}.{}.partial", hex::encode(&sha256(bytes)[..8]))
    }

    /// What one fake curl run does: each `try_wait` appends the next chunk
    /// to `--output`. With the last chunk the run exits with `exit`, having
    /// printed `stdout`, unless it hangs until killed.
    struct Script {
        chunks: Vec<Vec<u8>>,
        exit: Option<i32>,
        stdout: &'static str,
        stderr: &'static str,
        hang: bool,
    }

    fn exits(exit: i32, stdout: &'static str) -> Script {
        Script {
            chunks: Vec::new(),
            exit: Some(exit),
            stdout,
            stderr: "",
            hang: false,
        }
    }

    impl Script {
        fn writes(mut self, chunk: &[u8]) -> Self {
            self.chunks.push(chunk.to_vec());
            self
        }

        fn hangs(mut self) -> Self {
            self.hang = true;
            self
        }
    }

    #[derive(Default)]
    struct Fake {
        scripts: Mutex<VecDeque<Script>>,
        calls: Mutex<Vec<Vec<String>>>,
        kills: AtomicUsize,
    }

    impl Fake {
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }

        fn kills(&self) -> usize {
            self.kills.load(Ordering::SeqCst)
        }
    }

    struct FakeSpawn(Arc<Fake>);

    struct FakeChild {
        fake: Arc<Fake>,
        output: PathBuf,
        chunks: VecDeque<Vec<u8>>,
        exit: Option<i32>,
        hang: bool,
    }

    fn value_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        let at = args.iter().position(|arg| arg == flag)?;
        args.get(at + 1).map(String::as_str)
    }

    impl Spawn for FakeSpawn {
        fn spawn(&self, program: &Path, args: &[OsString]) -> io::Result<Spawned> {
            assert_eq!(program, Path::new("curl-under-test"));
            let args: Vec<String> = args
                .iter()
                .map(|arg| arg.to_str().unwrap().to_owned())
                .collect();
            self.0.calls.lock().unwrap().push(args.clone());
            let script = self
                .0
                .scripts
                .lock()
                .unwrap()
                .pop_front()
                .expect("an unexpected curl run");
            let output = PathBuf::from(value_after(&args, "--output").unwrap());
            if !args.iter().any(|arg| arg == "--continue-at") {
                File::create(&output).unwrap();
            }
            Ok(Spawned {
                child: Box::new(FakeChild {
                    fake: self.0.clone(),
                    output,
                    chunks: script.chunks.into(),
                    exit: script.exit,
                    hang: script.hang,
                }),
                stdout: Box::new(io::Cursor::new(script.stdout.as_bytes())),
                stderr: Box::new(io::Cursor::new(script.stderr.as_bytes())),
            })
        }
    }

    impl Child for FakeChild {
        fn try_wait(&mut self) -> io::Result<Option<Option<i32>>> {
            if let Some(chunk) = self.chunks.pop_front() {
                use std::io::Write;
                OpenOptions::new()
                    .append(true)
                    .open(&self.output)?
                    .write_all(&chunk)?;
            }
            Ok((self.chunks.is_empty() && !self.hang).then_some(self.exit))
        }

        fn kill(&mut self) {
            self.fake.kills.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fake_curl(dir: &TempDir, scripts: Vec<Script>) -> (Curl, Arc<Fake>) {
        let fake = Arc::new(Fake::default());
        *fake.scripts.lock().unwrap() = scripts.into();
        let curl = Curl {
            spawner: Box::new(FakeSpawn(fake.clone())),
            program: PathBuf::from("curl-under-test"),
            allow_file: false,
            scratch: dir.0.clone(),
            cancel: Arc::new(AtomicBool::new(false)),
            revoke_best_effort: AtomicBool::new(false),
        };
        (curl, fake)
    }

    fn passes_revoke_option(args: &[String]) -> bool {
        args.iter().any(|arg| arg == REVOKE_BEST_EFFORT)
    }

    #[test]
    fn windows_curl_does_not_stop_on_a_revocation_check_it_cannot_do() {
        let dir = TempDir::new();
        // Only the Windows curl gets the option.
        let system = Curl::system(dir.0.clone(), Arc::new(AtomicBool::new(false)));
        if let Some(system) = system {
            assert_eq!(
                system.revoke_best_effort.load(Ordering::Relaxed),
                cfg!(windows)
            );
        }
        let (curl, fake) = fake_curl(&dir, vec![exits(0, "200").writes(b"hello")]);
        curl.revoke_best_effort.store(true, Ordering::Relaxed);
        assert_eq!(curl.get(URL, 4096).unwrap().body, b"hello");
        let calls = fake.calls();
        assert!(passes_revoke_option(&calls[0]));
        // It comes after --disable, which curl needs first.
        assert_eq!(calls[0][0], "--disable");
    }

    #[test]
    fn a_curl_too_old_for_the_revocation_option_runs_again_without_it() {
        let dir = TempDir::new();
        let refused = Script {
            stderr: "curl: option --ssl-revoke-best-effort: is unknown\ncurl: try 'curl --help' for more information\n",
            ..exits(2, "")
        };
        let (curl, fake) = fake_curl(
            &dir,
            vec![
                refused,
                exits(0, "200").writes(b"hello"),
                exits(0, "200").writes(b"again"),
            ],
        );
        curl.revoke_best_effort.store(true, Ordering::Relaxed);
        assert_eq!(curl.get(URL, 4096).unwrap().body, b"hello");
        assert_eq!(curl.get(URL, 4096).unwrap().body, b"again");
        let calls = fake.calls();
        assert_eq!(calls.len(), 3);
        assert!(passes_revoke_option(&calls[0]));
        assert!(!passes_revoke_option(&calls[1]));
        // Later requests leave it out at once.
        assert!(!passes_revoke_option(&calls[2]));
        assert!(dir.entries().is_empty());

        // Another exit 2 is answered as before, and keeps the option.
        let (curl, fake) = fake_curl(&dir, vec![exits(2, "")]);
        curl.revoke_best_effort.store(true, Ordering::Relaxed);
        assert!(no_answer(curl.get(URL, 4096)).starts_with("curl exit 2"));
        assert_eq!(fake.calls().len(), 1);
        assert!(curl.revoke_best_effort.load(Ordering::Relaxed));
    }

    fn no_answer(result: Result<Response, TransportError>) -> String {
        match result {
            Err(TransportError::NoAnswer(detail)) => detail,
            other => panic!("expected no answer, got {other:?}"),
        }
    }

    fn status_only(status: u16) -> Result<Response, TransportError> {
        Ok(Response {
            status,
            body: Vec::new(),
        })
    }

    #[test]
    fn every_request_is_https_only_and_bounded() {
        let dir = TempDir::new();
        let (curl, fake) = fake_curl(&dir, vec![exits(0, "200").writes(b"hello")]);
        let response = curl.get(URL, 4096).unwrap();
        assert_eq!(response.body, b"hello");
        let calls = fake.calls();
        let [args] = calls.as_slice() else {
            panic!("expected one run");
        };
        assert_eq!(args[0], "--disable");
        for flag in [
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--globoff",
        ] {
            assert!(args.iter().any(|arg| arg == flag), "{flag} missing");
        }
        for (flag, value) in [
            ("--proto", "=https"),
            ("--proto-redir", "=https"),
            ("--max-redirs", "5"),
            ("--connect-timeout", "15"),
            ("--speed-limit", "1024"),
            ("--speed-time", "60"),
            ("--max-time", "120"),
            ("--max-filesize", "4096"),
            ("--write-out", "%{http_code}"),
            ("--user-agent", USER_AGENT),
        ] {
            assert_eq!(value_after(args, flag), Some(value), "{flag}");
        }
        assert!(USER_AGENT.starts_with("cmfd-wallet/"));
        assert!(
            !args
                .iter()
                .any(|arg| arg.starts_with("file") || arg.contains(",file"))
        );
        assert!(!args.iter().any(|arg| arg == "--continue-at"));
        // The URL is last, behind an explicit --url.
        assert_eq!(&args[args.len() - 2..], ["--url", URL]);
        // The body went to a scratch file, which is gone again.
        let output = Path::new(value_after(args, "--output").unwrap());
        assert_eq!(output.parent(), Some(dir.0.as_path()));
        assert!(dir.entries().is_empty());
    }

    #[test]
    fn urls_that_are_not_https_never_reach_curl() {
        let dir = TempDir::new();
        let (curl, fake) = fake_curl(&dir, Vec::new());
        for url in [
            "http://github.com/o/r/releases/download/v1.0.16/SHA256SUMS.txt",
            "file:///etc/passwd",
            "file://C:/Windows/win.ini",
            "ftp://github.com/x",
            "HTTPS://github.com/x",
            "-https://github.com/x",
            "https://github.com/a b",
            "https://github.com/a\nb",
            "https://github.com/a\u{e9}",
            "",
        ] {
            no_answer(curl.get(url, 100));
            assert!(matches!(
                curl.download_archive(url, &dir.0, NAME, 10, &[0; 32]),
                Err(DownloadError::Refused(_))
            ));
        }
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn metadata_status_codes() {
        let dir = TempDir::new();
        let cases: Vec<(Script, Result<Response, TransportError>)> = vec![
            (exits(0, "200"), status_only(200)),
            (exits(22, "404"), status_only(404)),
            (exits(22, "403"), status_only(403)),
            (exits(22, "429"), status_only(429)),
            (exits(22, "503"), status_only(503)),
            (exits(0, "302"), status_only(302)),
            (exits(0, "206"), status_only(206)),
            (exits(63, "200"), Err(TransportError::TooLarge)),
            (exits(63, "000"), Err(TransportError::TooLarge)),
        ];
        for (script, expected) in cases {
            let (curl, _) = fake_curl(&dir, vec![script]);
            assert_eq!(curl.get(URL, 100), expected);
            assert!(dir.entries().is_empty());
        }
        // No HTTP answer: DNS, connect, TLS, a timeout or a broken transfer,
        // a 000 with exit 0 (only file:// has that), garbage on the status
        // channel, a 4xx without curl's --fail exit, or a signal.
        for script in [
            exits(6, "000"),
            exits(7, "000"),
            exits(35, "000"),
            exits(28, "000"),
            exits(28, "200").writes(b"part"),
            exits(18, "200"),
            exits(0, "000"),
            exits(0, "20"),
            exits(0, "2000"),
            exits(0, " 200"),
            exits(0, ""),
            exits(0, "404"),
            exits(22, "200"),
            Script {
                exit: None,
                ..exits(0, "200")
            },
        ] {
            let (curl, _) = fake_curl(&dir, vec![script]);
            no_answer(curl.get(URL, 100));
            assert!(dir.entries().is_empty());
        }
        let (curl, _) = fake_curl(
            &dir,
            vec![Script {
                stderr: "curl: (6) Could not resolve host: github.com\nmore\n",
                ..exits(6, "000")
            }],
        );
        assert_eq!(
            no_answer(curl.get(URL, 100)),
            "curl exit 6: curl: (6) Could not resolve host: github.com"
        );
    }

    #[test]
    fn a_body_at_the_cap_is_read_and_one_byte_more_is_too_large() {
        let dir = TempDir::new();
        let (curl, _) = fake_curl(&dir, vec![exits(0, "200").writes(&[7; 10])]);
        assert_eq!(curl.get(URL, 10).unwrap().body, [7; 10]);
        // curl exits by itself here, so the check after exit catches it.
        let (curl, fake) = fake_curl(&dir, vec![exits(0, "200").writes(&[7; 11])]);
        assert_eq!(curl.get(URL, 10), Err(TransportError::TooLarge));
        assert_eq!(fake.kills(), 0);
        assert!(dir.entries().is_empty());
    }

    #[test]
    fn the_size_poll_kills_curl_once_the_body_passes_the_cap() {
        let dir = TempDir::new();
        let growing = exits(0, "200")
            .writes(&[1; 6])
            .writes(&[2; 6])
            .writes(&[3; 6])
            .hangs();
        let (curl, fake) = fake_curl(&dir, vec![growing]);
        assert_eq!(curl.get(URL, 10), Err(TransportError::TooLarge));
        assert_eq!(fake.kills(), 1);
        assert!(dir.entries().is_empty());
    }

    #[test]
    fn cancel_stops_before_curl_starts_and_kills_a_running_curl() {
        let dir = TempDir::new();
        let (curl, fake) = fake_curl(&dir, Vec::new());
        curl.cancel.store(true, Ordering::Release);
        assert_eq!(curl.get(URL, 100), Err(TransportError::Cancelled));
        assert_eq!(
            curl.download_archive(URL, &dir.0, NAME, 10, &[0; 32]),
            Err(DownloadError::Cancelled)
        );
        assert!(fake.calls().is_empty());

        let (curl, fake) = fake_curl(&dir, vec![exits(0, "200").writes(b"12").hangs()]);
        let cancel = curl.cancel.clone();
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            cancel.store(true, Ordering::Release);
        });
        let size = ARCHIVE.len() as u64;
        assert_eq!(
            curl.download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE)),
            Err(DownloadError::Cancelled)
        );
        canceller.join().unwrap();
        assert_eq!(fake.kills(), 1);
        // A cancelled download keeps its partial for the next attempt.
        assert_eq!(dir.entries(), [partial_name(ARCHIVE)]);
    }

    #[test]
    fn a_fresh_download_deletes_other_partials_and_renames_the_checked_file() {
        let dir = TempDir::new();
        let stale = [
            format!("{NAME}.{}.partial", hex::encode([0xab; 8])),
            "older.zip.0011223344556677.partial".to_owned(),
        ];
        for name in &stale {
            fs::write(dir.0.join(name), b"old").unwrap();
        }
        fs::write(dir.0.join("staging.lock"), b"1").unwrap();
        fs::create_dir(dir.0.join("x.partial")).unwrap();
        let size = ARCHIVE.len() as u64;
        let (curl, fake) = fake_curl(
            &dir,
            vec![
                exits(0, "200")
                    .writes(&ARCHIVE[..10])
                    .writes(&ARCHIVE[10..]),
            ],
        );
        let archive = curl
            .download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE))
            .unwrap();
        assert_eq!(archive, dir.0.join(ARCHIVE_NAME));
        assert_eq!(fs::read(&archive).unwrap(), ARCHIVE);
        assert_eq!(dir.entries(), ["archive", "staging.lock", "x.partial"]);
        let calls = fake.calls();
        let [args] = calls.as_slice() else {
            panic!("expected one run");
        };
        assert_eq!(
            value_after(args, "--output"),
            dir.0.join(partial_name(ARCHIVE)).to_str()
        );
        assert_eq!(value_after(args, "--max-filesize"), Some("36"));
        assert_eq!(value_after(args, "--max-time"), Some("3600"));
        assert!(!args.iter().any(|arg| arg == "--continue-at"));
    }

    #[test]
    fn a_partial_for_the_same_sha256_resumes() {
        let dir = TempDir::new();
        let partial = dir.0.join(partial_name(ARCHIVE));
        fs::write(&partial, &ARCHIVE[..14]).unwrap();
        let size = ARCHIVE.len() as u64;
        let (curl, fake) = fake_curl(&dir, vec![exits(0, "206").writes(&ARCHIVE[14..])]);
        let archive = curl
            .download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE))
            .unwrap();
        assert_eq!(fs::read(archive).unwrap(), ARCHIVE);
        let args = &fake.calls()[0];
        assert_eq!(value_after(args, "--continue-at"), Some("-"));
        // Only the bytes still to come count against --max-filesize.
        assert_eq!(value_after(args, "--max-filesize"), Some("22"));
        assert_eq!(dir.entries(), ["archive"]);
    }

    #[test]
    fn a_complete_partial_is_checked_without_downloading() {
        let dir = TempDir::new();
        fs::write(dir.0.join(partial_name(ARCHIVE)), ARCHIVE).unwrap();
        let (curl, fake) = fake_curl(&dir, Vec::new());
        let size = ARCHIVE.len() as u64;
        let archive = curl
            .download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE))
            .unwrap();
        assert_eq!(fs::read(archive).unwrap(), ARCHIVE);
        assert!(fake.calls().is_empty());

        // Same size, other bytes: deleted, never resumed.
        fs::remove_file(dir.0.join(ARCHIVE_NAME)).unwrap();
        fs::write(dir.0.join(partial_name(ARCHIVE)), [b'x'; 36]).unwrap();
        assert_eq!(
            curl.download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE)),
            Err(DownloadError::HashMismatch)
        );
        assert!(dir.entries().is_empty());
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn an_empty_or_oversized_partial_starts_over() {
        let size = ARCHIVE.len() as u64;
        for existing in [&b""[..], &[b'x'; 37][..]] {
            let dir = TempDir::new();
            fs::write(dir.0.join(partial_name(ARCHIVE)), existing).unwrap();
            let (curl, fake) = fake_curl(&dir, vec![exits(0, "200").writes(ARCHIVE)]);
            curl.download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE))
                .unwrap();
            let args = &fake.calls()[0];
            assert!(!args.iter().any(|arg| arg == "--continue-at"));
            assert_eq!(value_after(args, "--max-filesize"), Some("36"));
            assert_eq!(dir.entries(), ["archive"]);
        }
    }

    #[test]
    fn the_size_poll_kills_an_oversized_archive_download() {
        let dir = TempDir::new();
        let size = ARCHIVE.len() as u64;
        let (curl, fake) = fake_curl(
            &dir,
            vec![
                exits(0, "200")
                    .writes(&ARCHIVE[..20])
                    .writes(&ARCHIVE[20..])
                    .writes(b"more")
                    .writes(b"and more")
                    .hangs(),
            ],
        );
        assert_eq!(
            curl.download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE)),
            Err(DownloadError::TooLarge)
        );
        assert_eq!(fake.kills(), 1);
        assert!(dir.entries().is_empty());
    }

    #[test]
    fn archive_status_codes_delete_the_partial() {
        let size = ARCHIVE.len() as u64;
        let resumable: &[u8] = &ARCHIVE[..14];
        let none: &[u8] = b"";
        let cases: Vec<(&[u8], Script, DownloadError)> = vec![
            (none, exits(22, "404"), DownloadError::Missing),
            (resumable, exits(22, "404"), DownloadError::Missing),
            (resumable, exits(0, "416"), DownloadError::Status(416)),
            (
                none,
                exits(0, "206").writes(ARCHIVE),
                DownloadError::Status(206),
            ),
            // A 200 to a resume would have appended the whole file.
            (
                resumable,
                exits(0, "200").writes(&ARCHIVE[..22]),
                DownloadError::Status(200),
            ),
            (resumable, exits(33, "200"), DownloadError::CannotResume),
            (none, exits(63, "200"), DownloadError::TooLarge),
            (
                none,
                exits(0, "200").writes(&ARCHIVE[..30]),
                DownloadError::SizeMismatch {
                    expected: 36,
                    actual: 30,
                },
            ),
            (
                none,
                exits(0, "200").writes(&[b'x'; 36]),
                DownloadError::HashMismatch,
            ),
        ];
        for (before, script, expected) in cases {
            let dir = TempDir::new();
            if !before.is_empty() {
                fs::write(dir.0.join(partial_name(ARCHIVE)), before).unwrap();
            }
            let (curl, _) = fake_curl(&dir, vec![script]);
            assert_eq!(
                curl.download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE)),
                Err(expected.clone())
            );
            assert!(dir.entries().is_empty(), "{expected:?}");
        }
    }

    #[test]
    fn other_statuses_keep_a_partial_for_the_next_attempt() {
        let size = ARCHIVE.len() as u64;
        for (exit, status) in [
            (22, "500"),
            (22, "503"),
            (22, "429"),
            (22, "408"),
            (22, "403"),
            (0, "302"),
        ] {
            let dir = TempDir::new();
            let partial = dir.0.join(partial_name(ARCHIVE));
            fs::write(&partial, &ARCHIVE[..14]).unwrap();
            let (curl, fake) = fake_curl(
                &dir,
                vec![exits(exit, status), exits(0, "206").writes(&ARCHIVE[14..])],
            );
            assert_eq!(
                curl.download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE)),
                Err(DownloadError::Status(status.parse().unwrap()))
            );
            assert_eq!(fs::read(&partial).unwrap(), &ARCHIVE[..14], "{status}");
            let archive = curl
                .download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE))
                .unwrap();
            assert_eq!(fs::read(archive).unwrap(), ARCHIVE);
            let calls = fake.calls();
            assert_eq!(value_after(&calls[1], "--continue-at"), Some("-"));
        }
    }

    /// A stale partial held open without delete sharing (antivirus, a sync
    /// client) stays, and the current download still runs.
    #[cfg(windows)]
    #[test]
    fn a_stale_partial_that_cannot_be_deleted_does_not_stop_the_download() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = TempDir::new();
        let stale = dir.0.join("older.zip.0011223344556677.partial");
        fs::write(&stale, b"old").unwrap();
        let held = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&stale)
            .unwrap();
        let size = ARCHIVE.len() as u64;
        let (curl, _) = fake_curl(&dir, vec![exits(0, "200").writes(ARCHIVE)]);
        let archive = curl
            .download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE))
            .unwrap();
        assert_eq!(fs::read(archive).unwrap(), ARCHIVE);
        assert!(stale.exists());
        drop(held);
    }

    #[test]
    fn an_interrupted_download_keeps_its_partial_and_resumes_next_time() {
        let dir = TempDir::new();
        let size = ARCHIVE.len() as u64;
        let (curl, fake) = fake_curl(
            &dir,
            vec![
                Script {
                    stderr: "curl: (28) Operation timed out\n",
                    ..exits(28, "200").writes(&ARCHIVE[..9])
                },
                exits(56, "206").writes(&ARCHIVE[9..20]),
                exits(0, "206").writes(&ARCHIVE[20..]),
            ],
        );
        assert_eq!(
            curl.download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE)),
            Err(DownloadError::Interrupted(
                "curl exit 28: curl: (28) Operation timed out".into()
            ))
        );
        assert_eq!(
            fs::read(dir.0.join(partial_name(ARCHIVE))).unwrap(),
            &ARCHIVE[..9]
        );
        assert!(matches!(
            curl.download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE)),
            Err(DownloadError::Interrupted(_))
        ));
        let archive = curl
            .download_archive(URL, &dir.0, NAME, size, &sha256(ARCHIVE))
            .unwrap();
        assert_eq!(fs::read(archive).unwrap(), ARCHIVE);
        let calls = fake.calls();
        let filesizes: Vec<_> = calls
            .iter()
            .map(|args| value_after(args, "--max-filesize").unwrap())
            .collect();
        assert_eq!(filesizes, ["36", "27", "16"]);
        assert!(!calls[0].iter().any(|arg| arg == "--continue-at"));
        assert!(
            calls[1..]
                .iter()
                .all(|args| value_after(args, "--continue-at") == Some("-"))
        );
    }

    #[test]
    fn archive_names_must_be_plain_file_names() {
        let dir = TempDir::new();
        let (curl, fake) = fake_curl(&dir, Vec::new());
        for name in [
            "", "../a.zip", "a/b.zip", "a\\b.zip", ".a.zip", "-a.zip", "C:a.zip", "a b.zip",
        ] {
            assert_eq!(
                curl.download_archive(URL, &dir.0, name, 10, &[0; 32]),
                Err(DownloadError::Refused("not a plain file name")),
                "{name}"
            );
        }
        assert_eq!(
            curl.download_archive(URL, &dir.0, NAME, 0, &[0; 32]),
            Err(DownloadError::Refused("the signed size is zero"))
        );
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn the_system_curl_is_a_fixed_path() {
        let found = system_curl();
        #[cfg(windows)]
        {
            let curl = found.expect("Windows ships curl.exe in System32");
            assert_eq!(curl.file_name().unwrap(), "curl.exe");
            let dir = curl.parent().unwrap();
            assert_eq!(Some(dir), system_directory().as_deref());
            assert!(dir.file_name().unwrap().eq_ignore_ascii_case("System32"));
        }
        #[cfg(not(windows))]
        if let Some(curl) = found {
            assert!(curl == Path::new("/usr/bin/curl") || curl == Path::new("/bin/curl"));
        }
    }

    /// `sort.exe` waits on its stdin, which the test holds open, so it is
    /// still running when its job closes.
    #[cfg(windows)]
    #[test]
    fn a_child_dies_once_its_job_closes() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;

        let mut command = Command::new(system_directory().unwrap().join("sort.exe"));
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (
            SystemChild {
                mut child,
                _job: job,
            },
            _stdout,
            _stderr,
        ) = spawn_tied_to_wallet(&mut command).unwrap();
        let mut in_job = 0;
        // SAFETY: both handles are open and `in_job` outlives the call.
        let asked = unsafe { IsProcessInJob(child.as_raw_handle(), job.0, &mut in_job) };
        assert_ne!(asked, 0);
        assert_ne!(in_job, 0, "the child is not in the job");
        assert!(child.try_wait().unwrap().is_none());
        drop(job);
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("the child outlived its job");
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    /// `cat` waits on its stdin, which the test holds open, so it is still
    /// running when the thread that started it exits.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_dies_with_the_thread_that_started_it() {
        let (mut child, stdin) = thread::spawn(|| {
            let mut command = Command::new("/bin/cat");
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let (SystemChild { mut child }, _stdout, _stderr) =
                spawn_tied_to_wallet(&mut command).unwrap();
            let stdin = child.stdin.take().unwrap();
            (child, stdin)
        })
        .join()
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("the child outlived the thread that started it");
            }
            thread::sleep(POLL_INTERVAL);
        };
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        drop(stdin);
    }

    /// The real system curl, against `file://` sources only.
    #[cfg(feature = "updater-e2e")]
    mod real_curl {
        use super::*;

        fn file_url(path: &Path) -> String {
            let path = path
                .to_str()
                .unwrap()
                .replace('\\', "/")
                .replace(' ', "%20");
            format!("file:///{}", path.trim_start_matches('/'))
        }

        fn real(dir: &TempDir) -> Curl {
            let cancel = Arc::new(AtomicBool::new(false));
            Curl::system_allowing_file_urls(dir.0.clone(), cancel).expect("system curl")
        }

        #[test]
        fn reads_a_file_url_and_maps_a_missing_file_to_404() {
            let dir = TempDir::new();
            let source = TempDir::new();
            let sums = source.0.join("SHA256SUMS.txt");
            fs::write(&sums, b"signed bytes\n").unwrap();
            let curl = real(&dir);
            assert_eq!(
                curl.get(&file_url(&sums), 13).unwrap(),
                Response {
                    status: 200,
                    body: b"signed bytes\n".to_vec(),
                }
            );
            let missing = source.0.join("nope.txt");
            assert_eq!(curl.get(&file_url(&missing), 100), status_only(404));
            assert_eq!(
                curl.get(&file_url(&sums), 12),
                Err(TransportError::TooLarge)
            );
            assert!(dir.entries().is_empty());
        }

        #[test]
        fn the_https_only_flags_make_curl_itself_refuse_file_urls() {
            let dir = TempDir::new();
            let source = TempDir::new();
            let secret = source.0.join("secret.txt");
            fs::write(&secret, b"secret").unwrap();
            let url = file_url(&secret);
            let curl = Curl {
                allow_file: false,
                ..real(&dir)
            };
            assert_eq!(no_answer(curl.get(&url, 100)), "not an https URL");
            // Past the URL check, curl's own --proto =https still refuses it.
            let output = dir.0.join("out");
            let args = curl.args(&url, &output, 100, GET_MAX_TIME, false);
            let run = curl.run(&args, &output, 100, GET_MAX_TIME).unwrap();
            assert_eq!(run.exit, Some(1));
            let Outcome::NoAnswer(detail) = curl.answer(&url, &run) else {
                panic!("curl read a file:// URL");
            };
            assert!(detail.starts_with("curl exit 1"), "{detail}");
            assert!(fs::read(&output).unwrap_or_default().is_empty());
        }

        #[test]
        fn downloads_resumes_and_checks_an_archive() {
            let source = TempDir::new();
            let mut bytes = Vec::new();
            for index in 0..200_000u32 {
                bytes.extend_from_slice(&index.to_le_bytes());
            }
            fs::write(source.0.join(NAME), &bytes).unwrap();
            let url = file_url(&source.0.join(NAME));
            let size = bytes.len() as u64;
            let digest = sha256(&bytes);

            let fresh = TempDir::new();
            let archive = real(&fresh)
                .download_archive(&url, &fresh.0, NAME, size, &digest)
                .unwrap();
            assert_eq!(fs::read(archive).unwrap(), bytes);
            assert_eq!(fresh.entries(), ["archive"]);

            let resumed = TempDir::new();
            fs::write(resumed.0.join(partial_name(&bytes)), &bytes[..300_001]).unwrap();
            let archive = real(&resumed)
                .download_archive(&url, &resumed.0, NAME, size, &digest)
                .unwrap();
            assert_eq!(fs::read(archive).unwrap(), bytes);
            assert_eq!(resumed.entries(), ["archive"]);

            let wrong = TempDir::new();
            assert_eq!(
                real(&wrong).download_archive(&url, &wrong.0, NAME, size, &[0; 32]),
                Err(DownloadError::HashMismatch)
            );
            assert!(wrong.entries().is_empty());

            let short = TempDir::new();
            assert_eq!(
                real(&short).download_archive(&url, &short.0, NAME, size - 1, &digest),
                Err(DownloadError::TooLarge)
            );
            assert!(short.entries().is_empty());

            let gone = TempDir::new();
            let missing = file_url(&source.0.join("gone.zip"));
            assert_eq!(
                real(&gone).download_archive(&missing, &gone.0, NAME, size, &digest),
                Err(DownloadError::Missing)
            );
            assert!(gone.entries().is_empty());
        }
    }
}
