//! Crash-isolated process boundary for the optional CUDA BLAKE3 prover.
//!
//! The parent hashes an explicitly named worker executable and CUDA library,
//! sends one bounded canonical request, kills the child on timeout or output
//! overflow, and verifies every returned proof with the unchanged CPU verifier.
//! This isolates ordinary worker crashes and many worker OOM failures. It is not
//! an operating-system sandbox and does not protect against a same-user attacker
//! replacing the executable, DLL, or their dependencies during a check/load race.

pub mod spill {
    pub use cmfd_proof_accel::spill::*;
}
mod verifier;

pub use verifier::{
    MAX_VERIFIER_REQUEST_BYTES, MAX_VERIFIER_RESPONSE_BYTES, VerifierProtocolError,
    VerifierWorkerConfig, VerifierWorkerError, verify_block_out_of_process,
};

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use cmfd_consensus::{
    ExtensionElement, GOLDILOCKS_MODULUS, MAX_STRUCTURED_BLAKE3_PROOF_BYTES,
    MAX_STRUCTURED_FINAL_ACTIVATION_BYTES, MAX_STRUCTURED_OPENING_VARIABLES,
    StructuredBlake3Statement, prove_structured_blake3_with_cuda_in_spill_dir,
    verify_structured_blake3,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const REQUEST_MAGIC: &[u8; 8] = b"CMFDPWQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"CMFDPWR1";
const PROTOCOL_VERSION: u32 = 1;
const EXTENSION_ELEMENT_BYTES: usize = 3 * size_of::<u64>();
const REQUEST_FIXED_BYTES: usize = 8 + 4 + 32 + 4 + 32 + 4 + EXTENSION_ELEMENT_BYTES;
const SUCCESS_RESPONSE_FIXED_BYTES: usize = 8 + 4 + 1 + 4;
const ERROR_RESPONSE_FIXED_BYTES: usize = 8 + 4 + 1 + 2 + 2;
const MAX_WORKER_ERROR_BYTES: usize = 1024;
const DEFAULT_SPILL_ROOT_NAME: &str = "commonfoundry-proof-worker";
const SPILL_DIRECTORY_ATTEMPTS: usize = 1_024;
const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const SPILL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
static NEXT_SPILL_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Maximum canonical request size accepted by either process.
pub const MAX_REQUEST_BYTES: usize = REQUEST_FIXED_BYTES
    + MAX_STRUCTURED_OPENING_VARIABLES * EXTENSION_ELEMENT_BYTES
    + MAX_STRUCTURED_FINAL_ACTIVATION_BYTES;

/// Maximum canonical response size accepted from the child process.
pub const MAX_RESPONSE_BYTES: usize =
    SUCCESS_RESPONSE_FIXED_BYTES + MAX_STRUCTURED_BLAKE3_PROOF_BYTES;

/// Hard stderr capture limit. Exceeding it kills the worker and fails closed.
pub const MAX_STDERR_BYTES: usize = 64 * 1024;

const WORKER_ERROR_ARGUMENTS: u16 = 1;
const WORKER_ERROR_REQUEST: u16 = 2;
const WORKER_ERROR_DLL_HASH: u16 = 3;
const WORKER_ERROR_PROVER: u16 = 4;
const WORKER_ERROR_IO: u16 = 5;

/// Fully explicit process and CUDA-library selection for one worker request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofWorkerConfig {
    pub worker_executable: PathBuf,
    pub worker_sha256: [u8; 32],
    pub cuda_library: PathBuf,
    pub cuda_library_sha256: [u8; 32],
    pub device_index: i32,
    pub timeout: Duration,
}

#[derive(Debug, Error)]
pub enum ProofWorkerError {
    #[error("invalid proof-worker configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("could not read {component} at {path}: {source}")]
    FileRead {
        component: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{component} SHA-256 does not match the caller-supplied pin")]
    HashMismatch { component: &'static str },
    #[error("could not launch proof worker: {0}")]
    Spawn(#[source] io::Error),
    #[error("proof-worker spill directory I/O failed while {operation} {path}: {source}")]
    SpillDirectory {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not clean proof-worker spill directory {path}: {source}")]
    SpillCleanup {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "proof worker failed ({worker}); its spill directory {path} also could not be cleaned: {source}"
    )]
    SpillCleanupAfterFailure {
        path: PathBuf,
        worker: Box<ProofWorkerError>,
        #[source]
        source: io::Error,
    },
    #[error(
        "could not establish proof-worker process-tree containment while {operation}: {source}"
    )]
    Containment {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("proof worker timed out after {milliseconds} ms")]
    Timeout { milliseconds: u128 },
    #[error("proof worker stdout exceeded the canonical response bound")]
    StdoutTooLarge,
    #[error("proof worker stderr exceeded its capture bound")]
    StderrTooLarge,
    #[error("proof worker pipe {operation} failed: {source}")]
    Pipe {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("proof worker pipe thread panicked while {0}")]
    PipeThread(&'static str),
    #[error("proof worker exited unsuccessfully ({code:?}): {stderr}")]
    WorkerExited { code: Option<i32>, stderr: String },
    #[error("proof worker rejected the request ({code}): {message}")]
    WorkerReported { code: u16, message: String },
    #[error("invalid proof-worker response: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("unchanged CPU verification rejected the worker proof: {0}")]
    CpuRejected(String),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("message exceeds its protocol size bound")]
    TooLarge,
    #[error("message is truncated")]
    Truncated,
    #[error("message has trailing bytes")]
    TrailingBytes,
    #[error("message has the wrong magic")]
    Magic,
    #[error("unsupported protocol version {0}")]
    Version(u32),
    #[error("message length is invalid")]
    InvalidLength,
    #[error("message contains a noncanonical field element")]
    NonCanonicalField,
    #[error("message contains an invalid response status")]
    InvalidStatus,
    #[error("worker error code is not defined by this protocol version")]
    InvalidErrorCode,
    #[error("worker error text is not canonical UTF-8")]
    InvalidUtf8,
}

/// Prove in an explicitly pinned child process and accept the result only if
/// the unchanged CPU verifier validates the exact returned proof bytes.
pub fn prove_structured_blake3_out_of_process(
    config: &ProofWorkerConfig,
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
) -> Result<Vec<u8>, ProofWorkerError> {
    let spill_root = std::env::temp_dir().join(DEFAULT_SPILL_ROOT_NAME);
    prove_structured_blake3_out_of_process_with_spill_root(
        config,
        statement,
        final_activation,
        spill_root,
    )
}

/// Prove in a pinned child process while placing all request artifacts under
/// one unique leaf of the caller-selected spill root.
///
/// The root must be absolute. It is created when absent and is never removed;
/// only the exact no-overwrite request leaf created by this call is cleaned.
pub fn prove_structured_blake3_out_of_process_with_spill_root(
    config: &ProofWorkerConfig,
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
    spill_root: impl AsRef<Path>,
) -> Result<Vec<u8>, ProofWorkerError> {
    validate_config(config)?;
    let request = encode_request(statement, final_activation)?;
    verify_file_hash(
        "worker executable",
        &config.worker_executable,
        config.worker_sha256,
    )?;
    verify_file_hash(
        "CUDA proof library",
        &config.cuda_library,
        config.cuda_library_sha256,
    )?;

    with_worker_spill_directory(spill_root.as_ref(), |spill_dir| {
        let mut command = Command::new(&config.worker_executable);
        command
            .arg("--cuda-library")
            .arg(&config.cuda_library)
            .arg("--cuda-sha256")
            .arg(hex::encode(config.cuda_library_sha256))
            .arg("--device")
            .arg(config.device_index.to_string())
            .arg("--spill-dir")
            .arg(spill_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = spawn_contained(&mut command, None)?;
        let response = exchange_with_child(child, request, config.timeout, MAX_RESPONSE_BYTES)?;
        let proof = match decode_response(&response)? {
            WorkerResponse::Success(proof) => proof,
            WorkerResponse::Failure { code, message } => {
                return Err(ProofWorkerError::WorkerReported { code, message });
            }
        };
        require_cpu_verified(statement, proof)
    })
}

struct WorkerSpillDirectory {
    path: PathBuf,
    armed: bool,
}

impl WorkerSpillDirectory {
    fn create(root: &Path) -> Result<Self, ProofWorkerError> {
        if !root.is_absolute() {
            return Err(ProofWorkerError::InvalidConfig(
                "proof-worker spill root must be absolute",
            ));
        }
        std::fs::create_dir_all(root).map_err(|source| ProofWorkerError::SpillDirectory {
            operation: "creating spill root",
            path: root.to_path_buf(),
            source,
        })?;

        for _ in 0..SPILL_DIRECTORY_ATTEMPTS {
            let sequence = NEXT_SPILL_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = root.join(format!("request-{}-{sequence:016x}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, armed: true }),
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(ProofWorkerError::SpillDirectory {
                        operation: "creating unique request directory",
                        path,
                        source,
                    });
                }
            }
        }

        Err(ProofWorkerError::SpillDirectory {
            operation: "creating unique request directory",
            path: root.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "unique spill-directory attempts exhausted",
            ),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn close(mut self) -> io::Result<()> {
        self.armed = false;
        remove_worker_spill_directory(&self.path)
    }
}

impl Drop for WorkerSpillDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_worker_spill_directory(&self.path);
        }
    }
}

fn with_worker_spill_directory<T>(
    root: &Path,
    operation: impl FnOnce(&Path) -> Result<T, ProofWorkerError>,
) -> Result<T, ProofWorkerError> {
    let spill = WorkerSpillDirectory::create(root)?;
    let path = spill.path().to_path_buf();
    let worker_result = operation(&path);
    match spill.close() {
        Ok(()) => worker_result,
        Err(source) => match worker_result {
            Ok(_) => Err(ProofWorkerError::SpillCleanup { path, source }),
            Err(worker) => Err(ProofWorkerError::SpillCleanupAfterFailure {
                path,
                worker: Box::new(worker),
                source,
            }),
        },
    }
}

fn remove_worker_spill_directory(path: &Path) -> io::Result<()> {
    let started = Instant::now();
    let mut delay = Duration::from_millis(5);
    loop {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(source) if spill_directory_is_absent(&source) => return Ok(()),
            Err(source)
                if retryable_spill_cleanup_error(&source)
                    && started.elapsed() < SPILL_CLEANUP_TIMEOUT =>
            {
                thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(200));
            }
            Err(source) => return Err(source),
        }
    }
}

fn spill_directory_is_absent(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::NotFound {
        return true;
    }
    #[cfg(windows)]
    return matches!(error.raw_os_error(), Some(2 | 3));
    #[cfg(not(windows))]
    false
}

fn retryable_spill_cleanup_error(error: &io::Error) -> bool {
    #[cfg(windows)]
    {
        matches!(error.raw_os_error(), Some(5 | 32 | 33 | 145 | 303))
    }
    #[cfg(not(windows))]
    {
        matches!(
            error.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::DirectoryNotEmpty
        )
    }
}

fn validate_config(config: &ProofWorkerConfig) -> Result<(), ProofWorkerError> {
    if !config.worker_executable.is_absolute() {
        return Err(ProofWorkerError::InvalidConfig(
            "worker executable path must be absolute",
        ));
    }
    if !config.cuda_library.is_absolute() {
        return Err(ProofWorkerError::InvalidConfig(
            "CUDA proof library path must be absolute",
        ));
    }
    if config.device_index < 0 {
        return Err(ProofWorkerError::InvalidConfig(
            "CUDA device index must be nonnegative",
        ));
    }
    if config.timeout.is_zero() {
        return Err(ProofWorkerError::InvalidConfig(
            "worker timeout must be nonzero",
        ));
    }
    Ok(())
}

fn require_cpu_verified(
    statement: &StructuredBlake3Statement,
    proof: Vec<u8>,
) -> Result<Vec<u8>, ProofWorkerError> {
    verify_structured_blake3(statement, &proof)
        .map_err(|error| ProofWorkerError::CpuRejected(error.to_string()))?;
    Ok(proof)
}

fn verify_file_hash(
    component: &'static str,
    path: &Path,
    expected: [u8; 32],
) -> Result<(), ProofWorkerError> {
    let actual = hash_file(path).map_err(|source| ProofWorkerError::FileRead {
        component,
        path: path.to_path_buf(),
        source,
    })?;
    if actual != expected {
        return Err(ProofWorkerError::HashMismatch { component });
    }
    Ok(())
}

fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[derive(Debug)]
struct Capture {
    bytes: Vec<u8>,
    exceeded: bool,
}

struct ContainedChild {
    child: Child,
    #[cfg(unix)]
    process_group: libc::pid_t,
    #[cfg(windows)]
    job: WindowsJob,
}

impl ContainedChild {
    fn terminate_tree(&mut self) {
        #[cfg(unix)]
        // SAFETY: `process_group` is the positive child PID assigned as its
        // new process-group ID before spawn. Negating it targets that group,
        // never the parent process group.
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        #[cfg(windows)]
        let _ = self.job.terminate();

        // Retain a direct-child fallback for setup/platform edge cases. The
        // process-group/job operation above is what contains descendants.
        let _ = self.child.kill();
    }

    fn terminate_and_reap(&mut self) {
        self.terminate_tree();
        let started = Instant::now();
        let mut direct_child_reaped = false;
        loop {
            if !direct_child_reaped {
                match self.child.try_wait() {
                    Ok(Some(_)) | Err(_) => direct_child_reaped = true,
                    Ok(None) => {}
                }
            }
            #[cfg(windows)]
            let process_tree_reaped = self.job.active_processes().is_ok_and(|active| active == 0);
            #[cfg(not(windows))]
            let process_tree_reaped = direct_child_reaped;

            if direct_child_reaped && process_tree_reaped {
                return;
            }
            if started.elapsed() >= PROCESS_REAP_TIMEOUT {
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for ContainedChild {
    fn drop(&mut self) {
        self.terminate_and_reap();
    }
}

#[cfg(windows)]
struct WindowsJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl WindowsJob {
    fn create(memory_limit_bytes: Option<u64>) -> io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        };

        // SAFETY: null security/name pointers request an unnamed job with
        // default security. The returned owned handle is closed in `Drop`.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self { handle };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Some(memory_limit_bytes) = memory_limit_bytes {
            let memory_limit = usize::try_from(memory_limit_bytes).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "worker memory limit does not fit this platform",
                )
            })?;
            limits.BasicLimitInformation.LimitFlags |=
                JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
            limits.ProcessMemoryLimit = memory_limit;
            limits.JobMemoryLimit = memory_limit;
        }
        // SAFETY: `limits` has the exact Win32 layout and remains live for the
        // duration of this call.
        let configured = unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn assign(&self, child: &Child) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        // SAFETY: both handles are live. The worker blocks on its protocol
        // stdin, so assignment precedes processing the trusted request.
        let assigned =
            unsafe { AssignProcessToJobObject(self.handle, child.as_raw_handle().cast()) };
        if assigned == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn terminate(&self) -> io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: the job handle remains owned and live. Closing the handle
        // also has KILL_ON_JOB_CLOSE as a second termination path.
        let terminated = unsafe { TerminateJobObject(self.handle, 1) };
        if terminated == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn active_processes(&self) -> io::Result<u32> {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };

        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: `accounting` has the requested Win32 layout and remains live
        // for the duration of the query. The return-length pointer is optional.
        let queried = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectBasicAccountingInformation,
                std::ptr::from_mut(&mut accounting).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if queried == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(accounting.ActiveProcesses)
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        // SAFETY: this owned handle came from `CreateJobObjectW` and has not
        // been transferred or closed elsewhere.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

fn spawn_contained(
    command: &mut Command,
    memory_limit_bytes: Option<u64>,
) -> Result<ContainedChild, ProofWorkerError> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        command.process_group(0);
        if let Some(memory_limit_bytes) = memory_limit_bytes {
            let memory_limit = libc::rlim_t::try_from(memory_limit_bytes).map_err(|_| {
                ProofWorkerError::InvalidConfig(
                    "worker memory limit does not fit the platform resource-limit type",
                )
            })?;
            // SAFETY: this closure calls only the async-signal-safe setrlimit
            // operation between fork and exec. The limit is copied by value.
            unsafe {
                command.pre_exec(move || {
                    let limit = libc::rlimit {
                        rlim_cur: memory_limit,
                        rlim_max: memory_limit,
                    };
                    if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn().map_err(ProofWorkerError::Spawn)?;
        let process_group = match libc::pid_t::try_from(child.id()) {
            Ok(process_group) => process_group,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProofWorkerError::InvalidConfig(
                    "worker PID does not fit the platform process ID type",
                ));
            }
        };
        Ok(ContainedChild {
            child,
            process_group,
        })
    }

    #[cfg(windows)]
    {
        let job = WindowsJob::create(memory_limit_bytes).map_err(|source| {
            ProofWorkerError::Containment {
                operation: "creating a Windows Job Object",
                source,
            }
        })?;
        let mut child = command.spawn().map_err(ProofWorkerError::Spawn)?;
        if let Err(source) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProofWorkerError::Containment {
                operation: "assigning the worker to a Windows Job Object",
                source,
            });
        }
        Ok(ContainedChild { child, job })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = command;
        Err(ProofWorkerError::InvalidConfig(
            "proof-worker process-tree containment is unsupported on this platform",
        ))
    }
}

fn capture_bounded(mut reader: impl Read, limit: usize) -> io::Result<Capture> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let exceeded = bytes.len() > limit;
    if exceeded {
        bytes.truncate(limit);
    }
    Ok(Capture { bytes, exceeded })
}

enum IoEvent {
    Input(io::Result<()>),
    Stdout(io::Result<Capture>),
    Stderr(io::Result<Capture>),
}

struct PipeThreadGuard {
    threads: Vec<thread::JoinHandle<()>>,
}

impl PipeThreadGuard {
    fn new(threads: impl IntoIterator<Item = thread::JoinHandle<()>>) -> Self {
        Self {
            threads: threads.into_iter().collect(),
        }
    }
}

impl Drop for PipeThreadGuard {
    fn drop(&mut self) {
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

struct ExchangeResources {
    child: Option<ContainedChild>,
    _pipe_threads: PipeThreadGuard,
}

impl ExchangeResources {
    fn child_mut(&mut self) -> &mut ContainedChild {
        self.child
            .as_mut()
            .expect("exchange resources always own the worker child")
    }
}

impl Drop for ExchangeResources {
    fn drop(&mut self) {
        // This order is lifecycle-critical: closing the Windows Job Object is
        // the final KILL_ON_JOB_CLOSE fallback. It must happen before joining
        // pipe readers, because a surviving descendant may inherit those pipe
        // handles and otherwise turn a bounded worker timeout into a hang.
        drop(self.child.take());
        // `pipe_threads` is dropped and joined after this method returns.
    }
}

fn exchange_with_child(
    mut child: ContainedChild,
    request: Vec<u8>,
    timeout: Duration,
    stdout_limit: usize,
) -> Result<Vec<u8>, ProofWorkerError> {
    let Some(mut stdin) = child.child.stdin.take() else {
        terminate_child_bounded(&mut child);
        return Err(ProofWorkerError::InvalidConfig(
            "worker stdin pipe was not created",
        ));
    };
    let Some(stdout) = child.child.stdout.take() else {
        terminate_child_bounded(&mut child);
        return Err(ProofWorkerError::InvalidConfig(
            "worker stdout pipe was not created",
        ));
    };
    let Some(stderr) = child.child.stderr.take() else {
        terminate_child_bounded(&mut child);
        return Err(ProofWorkerError::InvalidConfig(
            "worker stderr pipe was not created",
        ));
    };

    let (event_tx, event_rx) = mpsc::channel();
    let input_tx = event_tx.clone();
    let input_thread = thread::spawn(move || {
        let result = stdin.write_all(&request).and_then(|()| stdin.flush());
        let _ = input_tx.send(IoEvent::Input(result));
    });
    let stdout_tx = event_tx.clone();
    let stdout_thread = thread::spawn(move || {
        let _ = stdout_tx.send(IoEvent::Stdout(capture_bounded(stdout, stdout_limit)));
    });
    let stderr_thread = thread::spawn(move || {
        let _ = event_tx.send(IoEvent::Stderr(capture_bounded(stderr, MAX_STDERR_BYTES)));
    });
    let mut resources = ExchangeResources {
        child: Some(child),
        _pipe_threads: PipeThreadGuard::new([input_thread, stdout_thread, stderr_thread]),
    };

    let started = Instant::now();
    let mut exit_status = None;
    let mut input_complete = false;
    let mut stdout_capture = None;
    let mut stderr_capture = None;
    loop {
        if exit_status.is_none() {
            match resources.child_mut().child.try_wait() {
                Ok(Some(status)) => exit_status = Some(status),
                Ok(None) => {}
                Err(source) => {
                    terminate_child_bounded(resources.child_mut());
                    return Err(ProofWorkerError::Pipe {
                        operation: "waiting for worker",
                        source,
                    });
                }
            }
        }
        if exit_status.is_some()
            && input_complete
            && stdout_capture.is_some()
            && stderr_capture.is_some()
        {
            break;
        }
        if started.elapsed() >= timeout {
            terminate_child_bounded(resources.child_mut());
            return Err(ProofWorkerError::Timeout {
                milliseconds: timeout.as_millis(),
            });
        }

        let remaining = timeout.saturating_sub(started.elapsed());
        match event_rx.recv_timeout(remaining.min(Duration::from_millis(5))) {
            Ok(IoEvent::Input(Ok(()))) => input_complete = true,
            Ok(IoEvent::Input(Err(source))) => {
                terminate_child_bounded(resources.child_mut());
                return Err(ProofWorkerError::Pipe {
                    operation: "writing stdin",
                    source,
                });
            }
            Ok(IoEvent::Stdout(Ok(capture))) if capture.exceeded => {
                terminate_child_bounded(resources.child_mut());
                return Err(ProofWorkerError::StdoutTooLarge);
            }
            Ok(IoEvent::Stdout(Ok(capture))) => stdout_capture = Some(capture),
            Ok(IoEvent::Stdout(Err(source))) => {
                terminate_child_bounded(resources.child_mut());
                return Err(ProofWorkerError::Pipe {
                    operation: "reading stdout",
                    source,
                });
            }
            Ok(IoEvent::Stderr(Ok(capture))) if capture.exceeded => {
                terminate_child_bounded(resources.child_mut());
                return Err(ProofWorkerError::StderrTooLarge);
            }
            Ok(IoEvent::Stderr(Ok(capture))) => stderr_capture = Some(capture),
            Ok(IoEvent::Stderr(Err(source))) => {
                terminate_child_bounded(resources.child_mut());
                return Err(ProofWorkerError::Pipe {
                    operation: "reading stderr",
                    source,
                });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if !io_collection_complete(input_complete, &stdout_capture, &stderr_capture) {
                    terminate_child_bounded(resources.child_mut());
                    return Err(ProofWorkerError::PipeThread("collecting worker pipes"));
                }
            }
        }
    }

    let exit_status = exit_status.expect("loop exits only after worker status is available");
    let stdout = stdout_capture.expect("loop exits only after stdout is captured");
    let stderr = stderr_capture.expect("loop exits only after stderr is captured");
    if !exit_status.success() {
        return Err(worker_exit_error(exit_status, &stderr.bytes));
    }
    Ok(stdout.bytes)
}

fn io_collection_complete(
    input_complete: bool,
    stdout_capture: &Option<Capture>,
    stderr_capture: &Option<Capture>,
) -> bool {
    input_complete && stdout_capture.is_some() && stderr_capture.is_some()
}

fn terminate_child_bounded(child: &mut ContainedChild) {
    child.terminate_and_reap();
}

fn worker_exit_error(status: ExitStatus, stderr: &[u8]) -> ProofWorkerError {
    ProofWorkerError::WorkerExited {
        code: status.code(),
        stderr: String::from_utf8_lossy(stderr).into_owned(),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct WorkerRequest {
    statement: StructuredBlake3Statement,
    final_activation: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum WorkerResponse {
    Success(Vec<u8>),
    Failure { code: u16, message: String },
}

fn encode_request(
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if statement.final_activation_len != final_activation.len()
        || final_activation.len() > MAX_STRUCTURED_FINAL_ACTIVATION_BYTES
        || statement.final_activation_point.len() > MAX_STRUCTURED_OPENING_VARIABLES
    {
        return Err(ProtocolError::InvalidLength);
    }
    validate_element(statement.final_activation_evaluation)?;
    for element in &statement.final_activation_point {
        validate_element(*element)?;
    }

    let mut output = Vec::with_capacity(
        REQUEST_FIXED_BYTES
            + statement.final_activation_point.len() * EXTENSION_ELEMENT_BYTES
            + final_activation.len(),
    );
    output.extend_from_slice(REQUEST_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.extend_from_slice(&statement.challenge_digest);
    output.extend_from_slice(&(statement.final_activation_len as u32).to_le_bytes());
    output.extend_from_slice(&statement.final_activation_digest);
    output.extend_from_slice(&(statement.final_activation_point.len() as u32).to_le_bytes());
    for element in &statement.final_activation_point {
        encode_element(*element, &mut output);
    }
    encode_element(statement.final_activation_evaluation, &mut output);
    output.extend_from_slice(final_activation);
    debug_assert!(output.len() <= MAX_REQUEST_BYTES);
    Ok(output)
}

fn decode_request(bytes: &[u8]) -> Result<WorkerRequest, ProtocolError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(REQUEST_MAGIC.len())? != REQUEST_MAGIC {
        return Err(ProtocolError::Magic);
    }
    let version = cursor.read_u32()?;
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::Version(version));
    }
    let challenge_digest = cursor.read_array()?;
    let final_activation_len = cursor.read_u32()? as usize;
    if final_activation_len > MAX_STRUCTURED_FINAL_ACTIVATION_BYTES {
        return Err(ProtocolError::InvalidLength);
    }
    let final_activation_digest = cursor.read_array()?;
    let point_len = cursor.read_u32()? as usize;
    if point_len > MAX_STRUCTURED_OPENING_VARIABLES {
        return Err(ProtocolError::InvalidLength);
    }
    let expected_remaining = point_len
        .checked_mul(EXTENSION_ELEMENT_BYTES)
        .and_then(|value| value.checked_add(EXTENSION_ELEMENT_BYTES))
        .and_then(|value| value.checked_add(final_activation_len))
        .ok_or(ProtocolError::InvalidLength)?;
    match cursor.remaining().cmp(&expected_remaining) {
        std::cmp::Ordering::Less => return Err(ProtocolError::Truncated),
        std::cmp::Ordering::Greater => return Err(ProtocolError::TrailingBytes),
        std::cmp::Ordering::Equal => {}
    }

    let mut final_activation_point = Vec::with_capacity(point_len);
    for _ in 0..point_len {
        final_activation_point.push(decode_element(&mut cursor)?);
    }
    let final_activation_evaluation = decode_element(&mut cursor)?;
    let final_activation = cursor.take(final_activation_len)?.to_vec();
    cursor.finish()?;
    Ok(WorkerRequest {
        statement: StructuredBlake3Statement {
            challenge_digest,
            final_activation_len,
            final_activation_digest,
            final_activation_point,
            final_activation_evaluation,
        },
        final_activation,
    })
}

fn encode_success_response(proof: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if proof.is_empty() || proof.len() > MAX_STRUCTURED_BLAKE3_PROOF_BYTES {
        return Err(ProtocolError::InvalidLength);
    }
    let mut output = Vec::with_capacity(SUCCESS_RESPONSE_FIXED_BYTES + proof.len());
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.push(0);
    output.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    output.extend_from_slice(proof);
    Ok(output)
}

fn encode_error_response(code: u16, message: &str) -> Vec<u8> {
    debug_assert_ne!(code, 0);
    let message = truncate_utf8(message, MAX_WORKER_ERROR_BYTES);
    let mut output = Vec::with_capacity(ERROR_RESPONSE_FIXED_BYTES + message.len());
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.push(1);
    output.extend_from_slice(&code.to_le_bytes());
    output.extend_from_slice(&(message.len() as u16).to_le_bytes());
    output.extend_from_slice(message.as_bytes());
    output
}

fn decode_response(bytes: &[u8]) -> Result<WorkerResponse, ProtocolError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(RESPONSE_MAGIC.len())? != RESPONSE_MAGIC {
        return Err(ProtocolError::Magic);
    }
    let version = cursor.read_u32()?;
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::Version(version));
    }
    match cursor.read_u8()? {
        0 => {
            let proof_len = cursor.read_u32()? as usize;
            if proof_len == 0 || proof_len > MAX_STRUCTURED_BLAKE3_PROOF_BYTES {
                return Err(ProtocolError::InvalidLength);
            }
            let proof = cursor.take(proof_len)?.to_vec();
            cursor.finish()?;
            Ok(WorkerResponse::Success(proof))
        }
        1 => {
            let code = cursor.read_u16()?;
            if !(WORKER_ERROR_ARGUMENTS..=WORKER_ERROR_IO).contains(&code) {
                return Err(ProtocolError::InvalidErrorCode);
            }
            let message_len = cursor.read_u16()? as usize;
            if message_len > MAX_WORKER_ERROR_BYTES {
                return Err(ProtocolError::InvalidLength);
            }
            let message = std::str::from_utf8(cursor.take(message_len)?)
                .map_err(|_| ProtocolError::InvalidUtf8)?
                .to_owned();
            cursor.finish()?;
            Ok(WorkerResponse::Failure { code, message })
        }
        _ => Err(ProtocolError::InvalidStatus),
    }
}

fn encode_element(element: ExtensionElement, output: &mut Vec<u8>) {
    for limb in element.limbs {
        output.extend_from_slice(&limb.to_le_bytes());
    }
}

fn decode_element(cursor: &mut Cursor<'_>) -> Result<ExtensionElement, ProtocolError> {
    let element = ExtensionElement {
        limbs: [cursor.read_u64()?, cursor.read_u64()?, cursor.read_u64()?],
    };
    validate_element(element)?;
    Ok(element)
}

fn validate_element(element: ExtensionElement) -> Result<(), ProtocolError> {
    if element.limbs.iter().any(|limb| *limb >= GOLDILOCKS_MODULUS) {
        return Err(ProtocolError::NonCanonicalField);
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProtocolError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ProtocolError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProtocolError::Truncated)
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[derive(Debug)]
struct WorkerArguments {
    cuda_library: PathBuf,
    cuda_sha256: [u8; 32],
    device_index: i32,
    spill_dir: PathBuf,
}

fn parse_worker_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<WorkerArguments, String> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.len() != 8
        || arguments[0].as_os_str() != OsStr::new("--cuda-library")
        || arguments[2].as_os_str() != OsStr::new("--cuda-sha256")
        || arguments[4].as_os_str() != OsStr::new("--device")
        || arguments[6].as_os_str() != OsStr::new("--spill-dir")
    {
        return Err("expected --cuda-library ABSOLUTE_PATH --cuda-sha256 HEX --device INDEX --spill-dir ABSOLUTE_PATH".to_owned());
    }
    let cuda_library = PathBuf::from(arguments[1].as_os_str());
    if !cuda_library.is_absolute() {
        return Err("CUDA proof library path must be absolute".to_owned());
    }
    let cuda_hash = arguments[3]
        .to_str()
        .ok_or_else(|| "CUDA SHA-256 pin must be Unicode hex".to_owned())?;
    if cuda_hash.len() != 64 {
        return Err("CUDA SHA-256 pin must contain exactly 64 hex characters".to_owned());
    }
    let mut cuda_sha256 = [0_u8; 32];
    hex::decode_to_slice(cuda_hash, &mut cuda_sha256)
        .map_err(|_| "CUDA SHA-256 pin must contain exactly 64 hex characters".to_owned())?;
    let device_index = arguments[5]
        .to_str()
        .ok_or_else(|| "CUDA device index must be Unicode decimal".to_owned())?
        .parse::<i32>()
        .map_err(|_| "CUDA device index must be a nonnegative decimal i32".to_owned())?;
    if device_index < 0 {
        return Err("CUDA device index must be a nonnegative decimal i32".to_owned());
    }
    let spill_dir = PathBuf::from(arguments[7].as_os_str());
    if !spill_dir.is_absolute() {
        return Err("proof spill directory path must be absolute".to_owned());
    }
    if !spill_dir.is_dir() {
        return Err("proof spill directory must already exist".to_owned());
    }
    Ok(WorkerArguments {
        cuda_library,
        cuda_sha256,
        device_index,
        spill_dir,
    })
}

fn read_stdin_bounded() -> Result<Vec<u8>, io::Error> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_REQUEST_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn run_worker() -> Result<Vec<u8>, (u16, String)> {
    let arguments = parse_worker_arguments(std::env::args_os().skip(1))
        .map_err(|message| (WORKER_ERROR_ARGUMENTS, message))?;
    let request_bytes = read_stdin_bounded()
        .map_err(|error| (WORKER_ERROR_IO, format!("could not read request: {error}")))?;
    let request = decode_request(&request_bytes)
        .map_err(|error| (WORKER_ERROR_REQUEST, error.to_string()))?;
    verify_file_hash(
        "CUDA proof library",
        &arguments.cuda_library,
        arguments.cuda_sha256,
    )
    .map_err(|error| (WORKER_ERROR_DLL_HASH, error.to_string()))?;
    prove_structured_blake3_with_cuda_in_spill_dir(
        &request.statement,
        &request.final_activation,
        &arguments.cuda_library,
        arguments.device_index,
        &arguments.spill_dir,
    )
    .map_err(|error| (WORKER_ERROR_PROVER, error.to_string()))
}

/// Binary entry point. This is public only so the tiny executable target can
/// share the audited protocol and hashing implementation with the library.
#[doc(hidden)]
pub fn worker_main() -> i32 {
    if verifier::verifier_mode_requested() {
        return verifier::verifier_worker_main();
    }
    let response = match run_worker() {
        Ok(proof) => match encode_success_response(&proof) {
            Ok(response) => response,
            Err(error) => encode_error_response(WORKER_ERROR_PROVER, &error.to_string()),
        },
        Err((code, message)) => encode_error_response(code, &message),
    };
    match io::stdout().write_all(&response) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Reports whether this process was invoked in the exact internal verifier
/// mode. Node binaries use this to host the same audited worker protocol
/// without requiring a second executable in the release package.
#[doc(hidden)]
pub fn verifier_worker_mode_requested() -> bool {
    verifier::verifier_mode_requested()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const TEST_SPILL_DIRECTORY_ENV: &str = "CMFD_PROOF_WORKER_TEST_SPILL_DIRECTORY";

    fn statement() -> StructuredBlake3Statement {
        StructuredBlake3Statement {
            challenge_digest: [0x11; 32],
            final_activation_len: 4,
            final_activation_digest: [0x22; 32],
            final_activation_point: vec![
                ExtensionElement { limbs: [1, 2, 3] },
                ExtensionElement { limbs: [4, 5, 6] },
            ],
            final_activation_evaluation: ExtensionElement { limbs: [7, 8, 9] },
        }
    }

    fn temporary_path(suffix: &str) -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "cmfd-proof-worker-{}-{sequence}.{suffix}",
            std::process::id(),
        ))
    }

    fn temporary_file(contents: &[u8]) -> PathBuf {
        let path = temporary_path("tmp");
        fs::write(&path, contents).unwrap();
        path
    }

    fn hold_test_spill_file() -> Option<File> {
        let directory = std::env::var_os(TEST_SPILL_DIRECTORY_ENV).map(PathBuf::from)?;
        fs::write(directory.join("worker.merkle"), b"merkle").unwrap();
        fs::write(directory.join("worker.merkle.partial"), b"partial").unwrap();
        let mut held = File::create(directory.join("worker.lde")).unwrap();
        held.write_all(b"held by worker").unwrap();
        held.flush().unwrap();
        Some(held)
    }

    fn real_one_block_fixture() -> (StructuredBlake3Statement, [u8; 8]) {
        // The all-zero MLE point selects the first activation entry. Bytes are
        // centered at 125 in the statement field, so a leading 125 evaluates
        // to the canonical extension-field zero.
        let final_activation = [125, 126, 127, 128, 129, 130, 131, 132];
        let challenge_digest = [0x42; 32];
        let mut output_hasher = blake3::Hasher::new_derive_key("CMFD/FORGEMATRIX/OUTPUT/V2");
        output_hasher.update(&challenge_digest);
        output_hasher.update(&(final_activation.len() as u64).to_le_bytes());
        output_hasher.update(&final_activation);
        let statement = StructuredBlake3Statement {
            challenge_digest,
            final_activation_len: final_activation.len(),
            final_activation_digest: *output_hasher.finalize().as_bytes(),
            final_activation_point: vec![ExtensionElement { limbs: [0; 3] }; 3],
            final_activation_evaluation: ExtensionElement { limbs: [0; 3] },
        };
        (statement, final_activation)
    }

    fn real_tree_fixture() -> (StructuredBlake3Statement, [u8; 64]) {
        // Sixty-four activation bytes select the narrow tree backend. The
        // all-zero MLE point selects the leading centered value, which is zero.
        let final_activation = std::array::from_fn(|index| 125 + index as u8);
        let challenge_digest = [0x43; 32];
        let mut output_hasher = blake3::Hasher::new_derive_key("CMFD/FORGEMATRIX/OUTPUT/V2");
        output_hasher.update(&challenge_digest);
        output_hasher.update(&(final_activation.len() as u64).to_le_bytes());
        output_hasher.update(&final_activation);
        let statement = StructuredBlake3Statement {
            challenge_digest,
            final_activation_len: final_activation.len(),
            final_activation_digest: *output_hasher.finalize().as_bytes(),
            final_activation_point: vec![ExtensionElement { limbs: [0; 3] }; 6],
            final_activation_evaluation: ExtensionElement { limbs: [0; 3] },
        };
        (statement, final_activation)
    }

    #[test]
    fn request_protocol_round_trips_and_rejects_noncanonical_streams() {
        let statement = statement();
        let activation = [1, 2, 3, 4];
        let encoded = encode_request(&statement, &activation).unwrap();
        assert_eq!(
            decode_request(&encoded).unwrap(),
            WorkerRequest {
                statement,
                final_activation: activation.to_vec(),
            }
        );

        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(decode_request(&truncated), Err(ProtocolError::Truncated));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(ProtocolError::TrailingBytes));

        let point_limb_offset = 8 + 4 + 32 + 4 + 32 + 4;
        let mut noncanonical = encoded;
        noncanonical[point_limb_offset..point_limb_offset + 8]
            .copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert_eq!(
            decode_request(&noncanonical),
            Err(ProtocolError::NonCanonicalField)
        );

        assert_eq!(
            decode_request(&vec![0; MAX_REQUEST_BYTES + 1]),
            Err(ProtocolError::TooLarge)
        );
    }

    #[test]
    fn response_protocol_rejects_malformed_and_oversize_streams() {
        let encoded = encode_success_response(&[1, 2, 3]).unwrap();
        assert_eq!(
            decode_response(&encoded),
            Ok(WorkerResponse::Success(vec![1, 2, 3]))
        );

        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(decode_response(&truncated), Err(ProtocolError::Truncated));

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_response(&trailing),
            Err(ProtocolError::TrailingBytes)
        );

        assert_eq!(
            decode_response(&vec![0; MAX_RESPONSE_BYTES + 1]),
            Err(ProtocolError::TooLarge)
        );

        let mut claimed_oversize = Vec::new();
        claimed_oversize.extend_from_slice(RESPONSE_MAGIC);
        claimed_oversize.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        claimed_oversize.push(0);
        claimed_oversize
            .extend_from_slice(&((MAX_STRUCTURED_BLAKE3_PROOF_BYTES as u32) + 1).to_le_bytes());
        assert_eq!(
            decode_response(&claimed_oversize),
            Err(ProtocolError::InvalidLength)
        );

        let error = encode_error_response(WORKER_ERROR_PROVER, "CUDA failure");
        assert_eq!(
            decode_response(&error),
            Ok(WorkerResponse::Failure {
                code: WORKER_ERROR_PROVER,
                message: "CUDA failure".to_owned(),
            })
        );
        let mut unknown_code = error.clone();
        unknown_code[13..15].copy_from_slice(&99_u16.to_le_bytes());
        assert_eq!(
            decode_response(&unknown_code),
            Err(ProtocolError::InvalidErrorCode)
        );
        let mut invalid_utf8 = encode_error_response(WORKER_ERROR_PROVER, "x");
        *invalid_utf8.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_response(&invalid_utf8),
            Err(ProtocolError::InvalidUtf8)
        );
    }

    #[test]
    fn worker_arguments_require_an_existing_absolute_spill_directory() {
        let cuda = temporary_file(b"CUDA library");
        let spill_dir = temporary_path("parser-spill");
        fs::create_dir(&spill_dir).unwrap();
        let arguments = vec![
            OsString::from("--cuda-library"),
            cuda.clone().into_os_string(),
            OsString::from("--cuda-sha256"),
            OsString::from("00".repeat(32)),
            OsString::from("--device"),
            OsString::from("0"),
            OsString::from("--spill-dir"),
            spill_dir.clone().into_os_string(),
        ];

        let parsed = parse_worker_arguments(arguments.clone()).unwrap();
        assert_eq!(parsed.spill_dir, spill_dir);

        let missing_argument = parse_worker_arguments(arguments[..6].iter().cloned());
        assert!(missing_argument.is_err());

        let mut relative = arguments.clone();
        relative[7] = OsString::from("relative-spill-directory");
        assert_eq!(
            parse_worker_arguments(relative).unwrap_err(),
            "proof spill directory path must be absolute"
        );

        fs::remove_dir(&spill_dir).unwrap();
        assert_eq!(
            parse_worker_arguments(arguments).unwrap_err(),
            "proof spill directory must already exist"
        );
        fs::remove_file(cuda).unwrap();
    }

    #[test]
    fn worker_spill_leaf_is_removed_after_success_and_error() {
        let root = temporary_path("spill-root");
        let mut success_leaf = None;
        let value = with_worker_spill_directory(&root, |leaf| {
            success_leaf = Some(leaf.to_path_buf());
            fs::write(leaf.join("success.lde"), b"success").unwrap();
            Ok(7_u8)
        })
        .unwrap();
        assert_eq!(value, 7);
        assert!(!success_leaf.unwrap().exists());

        let mut error_leaf = None;
        let error = with_worker_spill_directory(&root, |leaf| {
            error_leaf = Some(leaf.to_path_buf());
            fs::write(leaf.join("error.partial"), b"error").unwrap();
            Err::<(), _>(ProofWorkerError::InvalidConfig("injected worker failure"))
        })
        .unwrap_err();
        assert!(matches!(error, ProofWorkerError::InvalidConfig(_)));
        assert!(!error_leaf.unwrap().exists());
        assert!(root.is_dir(), "operator-selected spill root was removed");
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn worker_spill_leaves_are_isolated_and_never_remove_the_root() {
        let root = temporary_path("spill-isolation-root");
        fs::create_dir(&root).unwrap();
        let sentinel = root.join("operator-owned-sentinel");
        fs::write(&sentinel, b"keep").unwrap();
        let first = WorkerSpillDirectory::create(&root).unwrap();
        let second = WorkerSpillDirectory::create(&root).unwrap();
        let first_path = first.path().to_path_buf();
        let second_path = second.path().to_path_buf();
        assert_ne!(first_path, second_path);
        fs::write(first_path.join("first.lde"), b"first").unwrap();
        fs::write(second_path.join("second.lde"), b"second").unwrap();

        first.close().unwrap();
        assert!(!first_path.exists());
        assert!(second_path.is_dir());
        assert!(sentinel.is_file());
        second.close().unwrap();
        assert!(!second_path.exists());
        assert!(root.is_dir());
        assert!(sentinel.is_file());

        fs::remove_file(sentinel).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn spill_cleanup_failure_is_surfaced_and_preserves_the_worker_error() {
        let root = temporary_path("spill-cleanup-error-root");
        let mut leaf_path = None;
        let error = with_worker_spill_directory(&root, |leaf| {
            leaf_path = Some(leaf.to_path_buf());
            fs::remove_dir(leaf).unwrap();
            fs::write(leaf, b"replace the owned directory with a file").unwrap();
            Err::<(), _>(ProofWorkerError::InvalidConfig("injected worker failure"))
        })
        .unwrap_err();
        match error {
            ProofWorkerError::SpillCleanupAfterFailure { worker, .. } => {
                assert!(matches!(*worker, ProofWorkerError::InvalidConfig(_)));
            }
            other => panic!("unexpected cleanup error: {other}"),
        }

        fs::remove_file(leaf_path.unwrap()).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn caller_supplied_hash_mismatches_fail_before_spawn() {
        let worker = temporary_file(b"pinned executable bytes");
        let cuda = temporary_file(b"pinned CUDA bytes");
        let mut config = ProofWorkerConfig {
            worker_executable: worker.clone(),
            worker_sha256: [0; 32],
            cuda_library: cuda.clone(),
            cuda_library_sha256: hash_file(&cuda).unwrap(),
            device_index: 0,
            timeout: Duration::from_secs(1),
        };
        let result = prove_structured_blake3_out_of_process(&config, &statement(), &[1, 2, 3, 4]);
        assert!(matches!(
            result,
            Err(ProofWorkerError::HashMismatch {
                component: "worker executable"
            })
        ));

        config.worker_sha256 = hash_file(&worker).unwrap();
        config.cuda_library_sha256 = [0; 32];
        let result = prove_structured_blake3_out_of_process(&config, &statement(), &[1, 2, 3, 4]);
        assert!(matches!(
            result,
            Err(ProofWorkerError::HashMismatch {
                component: "CUDA proof library"
            })
        ));

        fs::remove_file(worker).unwrap();
        fs::remove_file(cuda).unwrap();
    }

    #[test]
    fn parent_cpu_verifier_rejects_worker_bytes() {
        let error = require_cpu_verified(&statement(), vec![0; 32]).unwrap_err();
        assert!(matches!(error, ProofWorkerError::CpuRejected(_)));
    }

    #[test]
    fn completed_io_channel_disconnect_is_not_a_pipe_failure() {
        let capture = || Capture {
            bytes: Vec::new(),
            exceeded: false,
        };
        assert!(io_collection_complete(
            true,
            &Some(capture()),
            &Some(capture()),
        ));
        assert!(!io_collection_complete(
            false,
            &Some(capture()),
            &Some(capture()),
        ));
    }

    #[test]
    fn child_timeout_helper() {
        if std::env::var_os("CMFD_PROOF_WORKER_TIMEOUT_HELPER").is_some() {
            let _held_spill_file = hold_test_spill_file();
            thread::sleep(Duration::from_secs(5));
        }
    }

    #[test]
    fn child_fast_exit_helper() {}

    #[test]
    fn child_crash_helper() {
        if std::env::var_os("CMFD_PROOF_WORKER_CRASH_HELPER").is_some() {
            let _ = io::stderr().write_all(b"intentional worker crash");
            std::process::exit(23);
        }
    }

    #[test]
    fn child_oversize_stdout_helper() {
        if std::env::var_os("CMFD_PROOF_WORKER_STDOUT_HELPER").is_some() {
            let _held_spill_file = hold_test_spill_file();
            let output = vec![b'x'; MAX_RESPONSE_BYTES + 1];
            let _ = io::stdout().write_all(&output);
            thread::sleep(Duration::from_secs(5));
        }
    }

    #[test]
    fn child_oversize_stderr_helper() {
        if std::env::var_os("CMFD_PROOF_WORKER_STDERR_HELPER").is_some() {
            let _held_spill_file = hold_test_spill_file();
            let output = vec![b'x'; MAX_STDERR_BYTES + 1];
            let _ = io::stderr().write_all(&output);
            thread::sleep(Duration::from_secs(5));
        }
    }

    #[test]
    fn child_descendant_holds_pipes_helper() {
        if std::env::var_os("CMFD_PROOF_WORKER_PIPE_DESCENDANT").is_some() {
            let _held_spill_file = hold_test_spill_file();
            let started = std::env::var_os("CMFD_PROOF_WORKER_DESCENDANT_STARTED")
                .expect("descendant start-sentinel path must be provided");
            fs::write(PathBuf::from(started), b"descendant started").unwrap();
            thread::sleep(Duration::from_secs(1));
            let survived = std::env::var_os("CMFD_PROOF_WORKER_DESCENDANT_SURVIVED")
                .expect("descendant survival-sentinel path must be provided");
            fs::write(PathBuf::from(survived), b"descendant survived timeout").unwrap();
            return;
        }
        if std::env::var_os("CMFD_PROOF_WORKER_PIPE_SPAWNER").is_some() {
            let mut descendant = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("tests::child_descendant_holds_pipes_helper")
                .arg("--nocapture")
                .env_remove("CMFD_PROOF_WORKER_PIPE_SPAWNER")
                .env("CMFD_PROOF_WORKER_PIPE_DESCENDANT", "1")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let _ = descendant.wait();
        }
    }

    #[test]
    fn parent_kills_worker_on_timeout() {
        let root = temporary_path("timeout-spill-root");
        let mut leaf = None;
        let started = Instant::now();
        let error = with_worker_spill_directory(&root, |spill_dir| {
            leaf = Some(spill_dir.to_path_buf());
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("tests::child_timeout_helper")
                .arg("--nocapture")
                .env("CMFD_PROOF_WORKER_TIMEOUT_HELPER", "1")
                .env(TEST_SPILL_DIRECTORY_ENV, spill_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let child = spawn_contained(&mut command, None)?;
            exchange_with_child(
                child,
                Vec::new(),
                Duration::from_millis(50),
                MAX_RESPONSE_BYTES,
            )
        })
        .unwrap_err();
        assert!(matches!(error, ProofWorkerError::Timeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(!leaf.unwrap().exists());
        assert!(root.is_dir());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn fast_exit_after_pipe_completion_is_not_reported_as_disconnect() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("tests::child_fast_exit_helper")
            .arg("--nocapture")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = spawn_contained(&mut command, None).unwrap();
        let output = exchange_with_child(
            child,
            Vec::new(),
            Duration::from_secs(2),
            MAX_RESPONSE_BYTES,
        )
        .unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn child_crash_is_reported_without_affecting_the_parent() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("tests::child_crash_helper")
            .arg("--nocapture")
            .env("CMFD_PROOF_WORKER_CRASH_HELPER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = spawn_contained(&mut command, None).unwrap();
        let error = exchange_with_child(
            child,
            Vec::new(),
            Duration::from_secs(2),
            MAX_RESPONSE_BYTES,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProofWorkerError::WorkerExited { code: Some(23), .. }
        ));
    }

    #[test]
    fn impossible_memory_limit_fails_closed() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("tests::child_timeout_helper")
            .arg("--nocapture")
            .env("CMFD_PROOF_WORKER_TIMEOUT_HELPER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let result = match spawn_contained(&mut command, Some(1)) {
            Ok(child) => exchange_with_child(
                child,
                Vec::new(),
                Duration::from_secs(2),
                MAX_RESPONSE_BYTES,
            ),
            Err(error) => Err(error),
        };
        assert!(
            result.is_err(),
            "one-byte worker memory limit must fail closed"
        );
    }

    #[test]
    fn parent_kills_worker_on_oversize_stdout_without_masking_error() {
        let root = temporary_path("stdout-spill-root");
        let mut leaf = None;
        let error = with_worker_spill_directory(&root, |spill_dir| {
            leaf = Some(spill_dir.to_path_buf());
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("tests::child_oversize_stdout_helper")
                .arg("--nocapture")
                .env("CMFD_PROOF_WORKER_STDOUT_HELPER", "1")
                .env(TEST_SPILL_DIRECTORY_ENV, spill_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let child = spawn_contained(&mut command, None)?;
            exchange_with_child(
                child,
                Vec::new(),
                Duration::from_secs(2),
                MAX_RESPONSE_BYTES,
            )
        })
        .unwrap_err();
        assert!(matches!(error, ProofWorkerError::StdoutTooLarge));
        assert!(!leaf.unwrap().exists());
        assert!(root.is_dir());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn parent_kills_worker_on_oversize_stderr_without_masking_error() {
        let root = temporary_path("stderr-spill-root");
        let mut leaf = None;
        let error = with_worker_spill_directory(&root, |spill_dir| {
            leaf = Some(spill_dir.to_path_buf());
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("tests::child_oversize_stderr_helper")
                .arg("--nocapture")
                .env("CMFD_PROOF_WORKER_STDERR_HELPER", "1")
                .env(TEST_SPILL_DIRECTORY_ENV, spill_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let child = spawn_contained(&mut command, None)?;
            exchange_with_child(
                child,
                Vec::new(),
                Duration::from_secs(2),
                MAX_RESPONSE_BYTES,
            )
        })
        .unwrap_err();
        assert!(matches!(error, ProofWorkerError::StderrTooLarge));
        assert!(!leaf.unwrap().exists());
        assert!(root.is_dir());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn timeout_kills_descendants_and_their_inherited_pipes() {
        let started_sentinel = temporary_path("descendant-started");
        let survived_sentinel = temporary_path("descendant-survived");
        let root = temporary_path("descendant-spill-root");
        let mut leaf = None;
        let started = Instant::now();
        let error = with_worker_spill_directory(&root, |spill_dir| {
            leaf = Some(spill_dir.to_path_buf());
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("tests::child_descendant_holds_pipes_helper")
                .arg("--nocapture")
                .env("CMFD_PROOF_WORKER_PIPE_SPAWNER", "1")
                .env("CMFD_PROOF_WORKER_DESCENDANT_STARTED", &started_sentinel)
                .env("CMFD_PROOF_WORKER_DESCENDANT_SURVIVED", &survived_sentinel)
                .env(TEST_SPILL_DIRECTORY_ENV, spill_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let child = spawn_contained(&mut command, None)?;
            exchange_with_child(
                child,
                Vec::new(),
                Duration::from_millis(500),
                MAX_RESPONSE_BYTES,
            )
        })
        .unwrap_err();
        assert!(matches!(error, ProofWorkerError::Timeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(!leaf.unwrap().exists());
        assert!(root.is_dir());
        assert!(
            started_sentinel.exists(),
            "descendant was not observed before timeout"
        );
        fs::remove_file(&started_sentinel).unwrap();

        thread::sleep(Duration::from_millis(1_100));
        let descendant_survived = survived_sentinel.exists();
        if descendant_survived {
            fs::remove_file(&survived_sentinel).unwrap();
        }
        assert!(!descendant_survived, "worker descendant survived timeout");
        fs::remove_dir(root).unwrap();
    }

    #[test]
    #[ignore = "requires CMFD_TEST_PROOF_CUDA_LIBRARY and a CUDA device"]
    fn real_cuda_one_block_in_process_is_cpu_verified() {
        let cuda = PathBuf::from(
            std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
                .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the real proof CUDA ABI v2 library"),
        );
        let device_index = std::env::var("CMFD_TEST_PROOF_CUDA_DEVICE")
            .ok()
            .map(|value| value.parse::<i32>().expect("CUDA device must be an i32"))
            .unwrap_or(0);
        let (statement, final_activation) = real_one_block_fixture();

        let cpu_proof =
            cmfd_consensus::prove_structured_blake3(&statement, &final_activation).unwrap();
        verify_structured_blake3(&statement, &cpu_proof).unwrap();

        let proof = cmfd_consensus::prove_structured_blake3_with_cuda(
            &statement,
            &final_activation,
            cuda,
            device_index,
        )
        .unwrap();
        verify_structured_blake3(&statement, &proof).unwrap();
    }

    #[test]
    #[ignore = "requires explicit paths to the built worker and a real CUDA proof library with DFT v2 and Poseidon2 v1"]
    fn real_cuda_tree_worker_round_trip_is_parent_cpu_verified() {
        let worker = PathBuf::from(
            std::env::var_os("CMFD_TEST_PROOF_WORKER")
                .expect("set CMFD_TEST_PROOF_WORKER to the built cmfd-proof-worker executable"),
        );
        let cuda = PathBuf::from(
            std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
                .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the real proof CUDA ABI v2 library"),
        );
        let device_index = std::env::var("CMFD_TEST_PROOF_CUDA_DEVICE")
            .ok()
            .map(|value| value.parse::<i32>().expect("CUDA device must be an i32"))
            .unwrap_or(0);

        let (statement, final_activation) = real_tree_fixture();
        let config = ProofWorkerConfig {
            worker_sha256: hash_file(&worker).unwrap(),
            cuda_library_sha256: hash_file(&cuda).unwrap(),
            worker_executable: worker,
            cuda_library: cuda,
            device_index,
            timeout: Duration::from_secs(15 * 60),
        };

        let spill_root = temporary_path("real-cuda-spill-root");
        let proof = prove_structured_blake3_out_of_process_with_spill_root(
            &config,
            &statement,
            &final_activation,
            &spill_root,
        )
        .unwrap();
        verify_structured_blake3(&statement, &proof).unwrap();
        assert_eq!(fs::read_dir(&spill_root).unwrap().count(), 0);
        fs::remove_dir(&spill_root).unwrap();

        let mut corrupted = proof;
        corrupted[0] ^= 0x80;
        assert!(matches!(
            require_cpu_verified(&statement, corrupted),
            Err(ProofWorkerError::CpuRejected(_))
        ));
    }
}
