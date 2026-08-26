use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cmfd_consensus::{
    Block, ConsensusPowVerifier, ExternalPreverificationBinding, MAX_BLOCK_BYTES,
    PreverifiedBlockProof, decode_block, encode_block, v2_reference_for_network,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    ContainedChild, MAX_STDERR_BYTES, PROCESS_REAP_TIMEOUT, ProcessTerminator, ProofWorkerError,
    exchange_with_child, spawn_contained, verify_file_hash, worker_exit_error,
};

const REQUEST_MAGIC: &[u8; 8] = b"CMFDVWQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"CMFDVWR1";
const PROTOCOL_VERSION: u32 = 1;
const VERIFY_MODE: &str = "--verify-block";
const PERSISTENT_VERIFY_MODE: &str = "--verify-block-server";
const V3_BANK_ARGUMENT: &str = "--production-v3-bank";
const V3_MANIFEST_ARGUMENT: &str = "--production-v3-manifest";
const V3_RECORD_ARGUMENT: &str = "--production-v3-record-v2";
const REQUEST_FIXED_BYTES: usize = 8 + 4 + 32 + 32 + 32 + 4;
const SUCCESS_RESPONSE_BYTES: usize = 8 + 4 + 1 + 32 + 32;
const ERROR_RESPONSE_FIXED_BYTES: usize = 8 + 4 + 1 + 2 + 2;
const MAX_ERROR_BYTES: usize = 1_024;
const STATUS_SUCCESS: u8 = 0;
const STATUS_FAILURE: u8 = 1;
const ERROR_REQUEST: u16 = 1;
const ERROR_UNSUPPORTED_VERIFIER: u16 = 2;
const ERROR_PROOF_REJECTED: u16 = 3;
const ERROR_INTERNAL: u16 = 4;
const FRAME_LENGTH_BYTES: usize = size_of::<u32>();
const HANDSHAKE_REQUEST_MAGIC: &[u8; 8] = b"CMFDVHQ1";
const HANDSHAKE_RESPONSE_MAGIC: &[u8; 8] = b"CMFDVHR1";
const SHUTDOWN_MAGIC: &[u8; 8] = b"CMFDVSD1";
const HANDSHAKE_STATUS_SUCCESS: u8 = 0;
const HANDSHAKE_STATUS_FAILURE: u8 = 1;
const PROFILE_V2_REFERENCE: u8 = 2;
const PROFILE_PRODUCTION_V3: u8 = 3;
const HANDSHAKE_REQUEST_BYTES: usize = 8 + 4 + 1 + 32 + 32 + 32;
const HANDSHAKE_SUCCESS_BYTES: usize = 8 + 4 + 1 + 1 + 32 + 32 + 32;
const HANDSHAKE_ERROR_FIXED_BYTES: usize = 8 + 4 + 1 + 2 + 2;
const STARTUP_SELF_TEST_DOMAIN: &[u8] = b"Common Foundry persistent verifier startup self-test v1";
const PRIVATE_COPY_ATTEMPTS: usize = 128;
const MAX_VERIFIER_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
static PRIVATE_COPY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Largest canonical verifier request, including one complete bounded block.
pub const MAX_VERIFIER_REQUEST_BYTES: usize = REQUEST_FIXED_BYTES + MAX_BLOCK_BYTES;
/// Largest canonical verifier response, including bounded diagnostic text.
pub const MAX_VERIFIER_RESPONSE_BYTES: usize = ERROR_RESPONSE_FIXED_BYTES + MAX_ERROR_BYTES;

/// Explicit executable identity and hard resource limits for one verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierWorkerConfig {
    pub worker_executable: PathBuf,
    pub worker_sha256: [u8; 32],
    /// Maximum time allowed for the worker to authenticate its model and
    /// complete the startup capability handshake.
    pub startup_timeout: Duration,
    pub timeout: Duration,
    pub memory_limit_bytes: u64,
    pub production_v3_artifacts: Option<ProductionV3VerifierArtifacts>,
}

/// Local paths to the three authenticated artifacts required by the V3
/// verifier. Paths are process configuration only and never enter consensus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionV3VerifierArtifacts {
    pub bank: PathBuf,
    pub manifest: PathBuf,
    pub record_v2: PathBuf,
}

impl ProductionV3VerifierArtifacts {
    fn validate(&self) -> Result<(), VerifierWorkerError> {
        if !self.bank.is_absolute() || !self.manifest.is_absolute() || !self.record_v2.is_absolute()
        {
            return Err(VerifierWorkerError::InvalidConfig(
                "production V3 artifact paths must be absolute",
            ));
        }
        if self.bank == self.manifest
            || self.bank == self.record_v2
            || self.manifest == self.record_v2
        {
            return Err(VerifierWorkerError::InvalidConfig(
                "production V3 artifact paths must be pairwise distinct",
            ));
        }
        Ok(())
    }
}

impl VerifierWorkerConfig {
    pub fn validate(&self) -> Result<(), VerifierWorkerError> {
        if !self.worker_executable.is_absolute() {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker executable path must be absolute",
            ));
        }
        if self.startup_timeout.is_zero() {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker startup timeout must be nonzero",
            ));
        }
        if self.timeout.is_zero() {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker timeout must be nonzero",
            ));
        }
        if self.memory_limit_bytes == 0 {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker memory limit must be nonzero",
            ));
        }
        if usize::try_from(self.memory_limit_bytes).is_err() {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker memory limit does not fit this platform",
            ));
        }
        if let Some(artifacts) = &self.production_v3_artifacts {
            artifacts.validate()?;
        }
        Ok(())
    }

    /// Validates the shape and caller-supplied executable identity before a
    /// node advertises the external verifier as available.
    pub fn validate_executable(&self) -> Result<(), VerifierWorkerError> {
        self.validate()?;
        verify_file_hash(
            "verifier worker executable",
            &self.worker_executable,
            self.worker_sha256,
        )?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum VerifierWorkerError {
    #[error("invalid verifier-worker configuration: {0}")]
    InvalidConfig(&'static str),
    #[error(transparent)]
    Process(#[from] ProofWorkerError),
    #[error("could not encode the verifier request block: {0}")]
    BlockEncoding(String),
    #[error("invalid verifier-worker protocol: {0}")]
    Protocol(#[from] VerifierProtocolError),
    #[error("verifier worker rejected the proof: {0}")]
    ProofRejected(String),
    #[error("verifier worker failed ({code}): {message}")]
    WorkerReported { code: u16, message: String },
    #[error("verifier worker response does not match the requested statement")]
    ResponseMismatch,
    #[error("could not issue the externally verified capability: {0}")]
    Capability(String),
    #[error("could not create the private verifier runtime copy while {operation}: {source}")]
    RuntimeCopy {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("verifier worker startup handshake failed: {0}")]
    Startup(String),
    #[error("verifier worker state is poisoned")]
    StatePoisoned,
    #[error("verifier worker transport could not be reaped after containment")]
    TransportPoisoned,
    #[error("verifier worker is permanently closed")]
    Closed,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VerifierProtocolError {
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
    #[error("message contains an invalid response status")]
    InvalidStatus,
    #[error("worker error code is not defined by this protocol version")]
    InvalidErrorCode,
    #[error("worker error text is not canonical UTF-8")]
    InvalidUtf8,
}

#[derive(Debug, PartialEq, Eq)]
struct VerifierRequest {
    network_id: [u8; 32],
    verifier_identity: [u8; 32],
    statement_identity: [u8; 32],
    block: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum VerifierResponse {
    Success {
        verifier_identity: [u8; 32],
        statement_identity: [u8; 32],
    },
    Failure {
        code: u16,
        message: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct StartupHandshake {
    profile: u8,
    network_id: [u8; 32],
    verifier_identity: [u8; 32],
    challenge: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
enum StartupResponse {
    Success {
        profile: u8,
        network_id: [u8; 32],
        verifier_identity: [u8; 32],
        self_test: [u8; 32],
    },
    Failure {
        code: u16,
        message: String,
    },
}

/// One startup-authenticated verifier process shared by every block admitted
/// through a node. The child loads and authenticates the model exactly once,
/// then serves canonical requests sequentially behind the node's bounded
/// admission queue.
#[derive(Clone)]
pub struct PersistentVerifierWorker {
    inner: Arc<PersistentVerifierWorkerInner>,
}

struct PersistentVerifierWorkerInner {
    config: VerifierWorkerConfig,
    verifier: ConsensusPowVerifier,
    network_id: [u8; 32],
    verifier_identity: [u8; 32],
    process: Mutex<Option<PersistentVerifierProcess>>,
    terminator: Mutex<Option<(u64, ProcessTerminator)>>,
    process_attempts: AtomicU64,
    process_starts: AtomicU64,
    shutdown_epoch: AtomicU64,
    terminated_generation: AtomicU64,
    /// Set permanently if a contained generation leaves a pipe owner alive
    /// beyond the bounded teardown window. Later generations are forbidden so
    /// hostile descendants cannot accumulate unbounded threads or handles.
    transport_poisoned: Arc<AtomicBool>,
    closed: AtomicBool,
    // Declared last so the process and its pipes are dropped before its private
    // executable copy is made writable for cleanup.
    runtime_copy: PrivateRuntimeCopy,
}

impl PersistentVerifierWorker {
    /// Creates the private executable copy, starts the contained worker, loads
    /// its verifier, and completes the profile/capability self-test. Success is
    /// therefore the boundary after which P2P may be started.
    pub fn start(
        config: VerifierWorkerConfig,
        verifier: ConsensusPowVerifier,
        network_id: [u8; 32],
    ) -> Result<Self, VerifierWorkerError> {
        config.validate()?;
        let runtime_copy =
            PrivateRuntimeCopy::create(&config.worker_executable, config.worker_sha256)?;
        let verifier_identity = verifier
            .external_preverification_identity(network_id)
            .map_err(|error| VerifierWorkerError::Capability(error.to_string()))?;
        let worker = Self {
            inner: Arc::new(PersistentVerifierWorkerInner {
                config,
                verifier,
                network_id,
                verifier_identity,
                process: Mutex::new(None),
                terminator: Mutex::new(None),
                process_attempts: AtomicU64::new(0),
                process_starts: AtomicU64::new(0),
                shutdown_epoch: AtomicU64::new(0),
                terminated_generation: AtomicU64::new(0),
                transport_poisoned: Arc::new(AtomicBool::new(false)),
                closed: AtomicBool::new(false),
                runtime_copy,
            }),
        };
        worker.ensure_started()?;
        Ok(worker)
    }

    pub fn verify_block(
        &self,
        block: &Block,
    ) -> Result<PreverifiedBlockProof, VerifierWorkerError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(VerifierWorkerError::Closed);
        }
        if block.challenge.network_id != self.inner.network_id {
            return Err(VerifierWorkerError::Startup(
                "candidate belongs to another network".to_owned(),
            ));
        }
        let canonical = encode_block(block)
            .map_err(|error| VerifierWorkerError::BlockEncoding(error.to_string()))?;
        let binding = self
            .inner
            .verifier
            .external_preverification_binding(&block.challenge, &block.proof)
            .map_err(|error| VerifierWorkerError::Capability(error.to_string()))?;
        let request = encode_request(VerifierRequest {
            network_id: block.challenge.network_id,
            verifier_identity: binding.verifier_identity(),
            statement_identity: binding.statement_identity(),
            block: canonical,
        })?;

        let mut process = self
            .inner
            .process
            .lock()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(VerifierWorkerError::Closed);
        }
        let request_shutdown_epoch = self.inner.shutdown_epoch.load(Ordering::Acquire);
        self.inner.discard_terminated_generation(&mut process)?;
        if process.is_none() {
            *process = Some(self.inner.start_process()?);
        }
        let response = match process
            .as_mut()
            .expect("persistent verifier was started above")
            .exchange(
                request,
                self.inner.config.timeout,
                MAX_VERIFIER_RESPONSE_BYTES,
            ) {
            Ok(response) => response,
            Err(error) => {
                let generation = process.as_ref().map(|process| process.generation);
                if let Some(generation) = generation {
                    self.inner.clear_terminator(generation)?;
                }
                process.take();
                return Err(error);
            }
        };
        if let Err(error) = require_matching_success(&response, binding) {
            // A canonical proof rejection is an expected, statement-local
            // outcome. Protocol, identity, and worker-internal failures poison
            // this process generation and force a complete authenticated
            // restart before any later request.
            if !matches!(error, VerifierWorkerError::ProofRejected(_)) {
                let generation = process.as_ref().map(|process| process.generation);
                if let Some(generation) = generation {
                    self.inner.clear_terminator(generation)?;
                }
                process.take();
            }
            return Err(error);
        }
        if self.inner.shutdown_epoch.load(Ordering::Acquire) != request_shutdown_epoch {
            let generation = process.as_ref().map(|process| process.generation);
            if let Some(generation) = generation {
                self.inner.clear_terminator(generation)?;
            }
            process.take();
            return Err(VerifierWorkerError::Startup(
                "worker request was cancelled".to_owned(),
            ));
        }
        if self.inner.closed.load(Ordering::Acquire) {
            let generation = process.as_ref().map(|process| process.generation);
            if let Some(generation) = generation {
                self.inner.clear_terminator(generation)?;
            }
            process.take();
            return Err(VerifierWorkerError::Closed);
        }

        // SAFETY: the exact binding was returned by the private-copy, pinned,
        // contained worker after its startup profile/capability handshake and a
        // bounded canonical request. Every transport or identity failure above
        // kills this process generation before a capability can be issued.
        let capability = unsafe {
            self.inner.verifier.issue_external_preverification(
                &block.challenge,
                &block.proof,
                binding,
            )
        };
        match capability {
            Ok(capability) => Ok(capability),
            Err(error) => {
                let generation = process.as_ref().map(|process| process.generation);
                if let Some(generation) = generation {
                    self.inner.clear_terminator(generation)?;
                }
                process.take();
                Err(VerifierWorkerError::Capability(error.to_string()))
            }
        }
    }

    pub fn timeout(&self) -> Duration {
        self.inner.config.timeout
    }

    pub fn memory_limit_bytes(&self) -> u64 {
        self.inner.config.memory_limit_bytes
    }

    /// Terminates the current process tree without waiting behind an in-flight
    /// verifier request. The interrupted request fails, while a later request
    /// starts from a fresh authenticated handshake and is never auto-retried.
    pub fn shutdown(&self) {
        self.inner.shutdown_epoch.fetch_add(1, Ordering::AcqRel);
        if let Ok(terminator) = self.inner.terminator.lock()
            && let Some((generation, handle)) = terminator.as_ref()
        {
            self.inner
                .terminated_generation
                .store(*generation, Ordering::Release);
            handle.terminate_tree();
        }
    }

    /// Permanently prevents new generations, then terminates the current one.
    /// Unlike `shutdown`, this is the terminal service-teardown operation.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.shutdown();
    }

    fn ensure_started(&self) -> Result<(), VerifierWorkerError> {
        let mut process = self
            .inner
            .process
            .lock()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        self.inner.discard_terminated_generation(&mut process)?;
        if process.is_none() {
            *process = Some(self.inner.start_process()?);
        }
        Ok(())
    }

    /// Monotonic local process generation, useful for operator diagnostics and
    /// proving that many blocks reused one authenticated model load.
    pub fn process_generation(&self) -> u64 {
        self.inner.process_starts.load(Ordering::Acquire)
    }

    /// Monotonic count of contained process spawn attempts, including a
    /// generation cancelled or rejected during its startup handshake.
    pub fn process_attempts(&self) -> u64 {
        self.inner.process_attempts.load(Ordering::Acquire)
    }

    /// Process identifier for diagnostics. The value can disappear at any
    /// time; callers must never treat it as part of the verifier identity.
    pub fn process_id(&self) -> Option<u32> {
        self.inner
            .process
            .lock()
            .ok()
            .and_then(|process| process.as_ref().map(|process| process.child.child.id()))
    }
}

impl PersistentVerifierWorkerInner {
    fn start_process(&self) -> Result<PersistentVerifierProcess, VerifierWorkerError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(VerifierWorkerError::Closed);
        }
        if self.transport_poisoned.load(Ordering::Acquire) {
            return Err(VerifierWorkerError::TransportPoisoned);
        }
        // Recheck the immutable copy immediately before every exec. There is
        // still a residual same-user check/exec race on platforms without an
        // exec-by-retained-handle primitive; the copy lives in a private,
        // randomly named directory and is non-writable for its lifetime.
        self.runtime_copy.verify(self.config.worker_sha256)?;
        let mut command = Command::new(self.runtime_copy.executable());
        command.arg(PERSISTENT_VERIFY_MODE);
        if let Some(artifacts) = &self.config.production_v3_artifacts {
            command
                .arg(V3_BANK_ARGUMENT)
                .arg(&artifacts.bank)
                .arg(V3_MANIFEST_ARGUMENT)
                .arg(&artifacts.manifest)
                .arg(V3_RECORD_ARGUMENT)
                .arg(&artifacts.record_v2);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // A shutdown racing this restart may run while no terminator is
        // published. The epoch closes that gap: any overlapping request is
        // observed immediately after publication and kills this generation.
        let shutdown_epoch = self.shutdown_epoch.load(Ordering::Acquire);
        let child = spawn_contained(&mut command, Some(self.config.memory_limit_bytes))?;
        let generation = self.process_attempts.fetch_add(1, Ordering::AcqRel) + 1;
        let terminator = child.termination_handle();
        let mut process = PersistentVerifierProcess::new(
            child,
            generation,
            Arc::clone(&self.transport_poisoned),
        )?;
        self.set_terminator(generation, terminator.clone())?;
        if self.closed.load(Ordering::Acquire)
            || self.shutdown_epoch.load(Ordering::Acquire) != shutdown_epoch
        {
            self.terminated_generation
                .store(generation, Ordering::Release);
            terminator.terminate_tree();
            self.clear_terminator(generation)?;
            return if self.closed.load(Ordering::Acquire) {
                Err(VerifierWorkerError::Closed)
            } else {
                Err(VerifierWorkerError::Startup(
                    "worker startup was cancelled".to_owned(),
                ))
            };
        }
        let startup = (|| {
            let mut challenge = [0_u8; 32];
            getrandom::fill(&mut challenge).map_err(|source| VerifierWorkerError::RuntimeCopy {
                operation: "creating the startup self-test challenge",
                source: io::Error::other(source.to_string()),
            })?;
            let profile = configured_profile(&self.config);
            let request = encode_startup_handshake(StartupHandshake {
                profile,
                network_id: self.network_id,
                verifier_identity: self.verifier_identity,
                challenge,
            });
            let response = process.exchange(
                request,
                self.config.startup_timeout,
                HANDSHAKE_SUCCESS_BYTES.max(HANDSHAKE_ERROR_FIXED_BYTES + MAX_ERROR_BYTES),
            )?;
            require_startup_success(
                &response,
                profile,
                self.network_id,
                self.verifier_identity,
                challenge,
            )
        })();
        if let Err(error) = startup {
            self.clear_terminator(generation)?;
            return Err(error);
        }
        self.process_starts.fetch_add(1, Ordering::AcqRel);
        Ok(process)
    }

    fn set_terminator(
        &self,
        generation: u64,
        terminator: ProcessTerminator,
    ) -> Result<(), VerifierWorkerError> {
        let mut slot = self
            .terminator
            .lock()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        *slot = Some((generation, terminator));
        Ok(())
    }

    fn clear_terminator(&self, generation: u64) -> Result<(), VerifierWorkerError> {
        let mut slot = self
            .terminator
            .lock()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        if slot
            .as_ref()
            .is_some_and(|(current, _)| *current == generation)
        {
            slot.take();
        }
        Ok(())
    }

    fn discard_terminated_generation(
        &self,
        process: &mut Option<PersistentVerifierProcess>,
    ) -> Result<(), VerifierWorkerError> {
        let Some(generation) = process.as_ref().map(|process| process.generation) else {
            return Ok(());
        };
        if self.terminated_generation.load(Ordering::Acquire) == generation {
            self.clear_terminator(generation)?;
            process.take();
        }
        Ok(())
    }
}

fn configured_profile(config: &VerifierWorkerConfig) -> u8 {
    if config.production_v3_artifacts.is_some() {
        PROFILE_PRODUCTION_V3
    } else {
        PROFILE_V2_REFERENCE
    }
}

struct PrivateRuntimeCopy {
    directory: PathBuf,
    executable: PathBuf,
}

impl PrivateRuntimeCopy {
    fn create(source: &Path, expected_sha256: [u8; 32]) -> Result<Self, VerifierWorkerError> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|source| VerifierWorkerError::RuntimeCopy {
            operation: "choosing a private runtime directory",
            source: io::Error::other(source.to_string()),
        })?;
        let extension = source.extension().and_then(OsStr::to_str).unwrap_or("");
        let sequence = PRIVATE_COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        for attempt in 0..PRIVATE_COPY_ATTEMPTS {
            let directory = std::env::temp_dir().join(format!(
                "cmfd-verifier-{}-{sequence}-{attempt}",
                hex::encode(random)
            ));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    if let Err(error) = set_private_directory_permissions(&directory) {
                        let _ = fs::remove_dir(&directory);
                        return Err(error);
                    }
                    let filename = if extension.is_empty() {
                        "verifier-runtime".to_owned()
                    } else {
                        format!("verifier-runtime.{extension}")
                    };
                    let executable = directory.join(filename);
                    let result = copy_and_pin(source, &executable, expected_sha256);
                    if let Err(error) = result {
                        let _ = make_runtime_copy_writable(&executable);
                        let _ = fs::remove_dir_all(&directory);
                        return Err(error);
                    }
                    if let Err(error) = set_immutable_executable_permissions(&executable) {
                        let _ = make_runtime_copy_writable(&executable);
                        let _ = fs::remove_dir_all(&directory);
                        return Err(error);
                    }
                    return Ok(Self {
                        directory,
                        executable,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(VerifierWorkerError::RuntimeCopy {
                        operation: "creating a private runtime directory",
                        source,
                    });
                }
            }
        }
        Err(VerifierWorkerError::RuntimeCopy {
            operation: "allocating a unique private runtime directory",
            source: io::Error::new(io::ErrorKind::AlreadyExists, "attempt limit reached"),
        })
    }

    fn executable(&self) -> &Path {
        &self.executable
    }

    fn verify(&self, expected_sha256: [u8; 32]) -> Result<(), VerifierWorkerError> {
        verify_file_hash(
            "private verifier runtime executable",
            &self.executable,
            expected_sha256,
        )
        .map_err(VerifierWorkerError::from)
    }
}

impl Drop for PrivateRuntimeCopy {
    fn drop(&mut self) {
        let _ = make_runtime_copy_writable(&self.executable);
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn copy_and_pin(
    source: &Path,
    destination: &Path,
    expected_sha256: [u8; 32],
) -> Result<(), VerifierWorkerError> {
    copy_and_pin_with_limit(
        source,
        destination,
        expected_sha256,
        MAX_VERIFIER_EXECUTABLE_BYTES,
    )
}

fn copy_and_pin_with_limit(
    source: &Path,
    destination: &Path,
    expected_sha256: [u8; 32],
    maximum_bytes: u64,
) -> Result<(), VerifierWorkerError> {
    let mut source_file =
        File::open(source).map_err(|source| VerifierWorkerError::RuntimeCopy {
            operation: "opening the pinned verifier executable",
            source,
        })?;
    let source_bytes = source_file
        .metadata()
        .map_err(|source| VerifierWorkerError::RuntimeCopy {
            operation: "inspecting the pinned verifier executable",
            source,
        })?
        .len();
    if source_bytes == 0 || source_bytes > maximum_bytes {
        return Err(VerifierWorkerError::InvalidConfig(
            "worker executable size is outside the private-copy bound",
        ));
    }
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|source| VerifierWorkerError::RuntimeCopy {
            operation: "creating the private verifier executable",
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied_bytes = 0_u64;
    loop {
        let read =
            source_file
                .read(&mut buffer)
                .map_err(|source| VerifierWorkerError::RuntimeCopy {
                    operation: "reading the pinned verifier executable",
                    source,
                })?;
        if read == 0 {
            break;
        }
        copied_bytes =
            copied_bytes
                .checked_add(read as u64)
                .ok_or(VerifierWorkerError::InvalidConfig(
                    "worker executable size exceeds the private-copy bound",
                ))?;
        if copied_bytes > maximum_bytes {
            return Err(VerifierWorkerError::InvalidConfig(
                "worker executable size exceeds the private-copy bound",
            ));
        }
        hasher.update(&buffer[..read]);
        destination_file
            .write_all(&buffer[..read])
            .map_err(|source| VerifierWorkerError::RuntimeCopy {
                operation: "writing the private verifier executable",
                source,
            })?;
    }
    destination_file
        .sync_all()
        .map_err(|source| VerifierWorkerError::RuntimeCopy {
            operation: "flushing the private verifier executable",
            source,
        })?;
    if <[u8; 32]>::from(hasher.finalize()) != expected_sha256 {
        return Err(VerifierWorkerError::Process(
            ProofWorkerError::HashMismatch {
                component: "verifier worker executable",
            },
        ));
    }
    if copied_bytes != source_bytes {
        return Err(VerifierWorkerError::InvalidConfig(
            "worker executable changed while creating the private copy",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), VerifierWorkerError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        VerifierWorkerError::RuntimeCopy {
            operation: "restricting the private runtime directory",
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), VerifierWorkerError> {
    Ok(())
}

#[cfg(unix)]
fn set_immutable_executable_permissions(path: &Path) -> Result<(), VerifierWorkerError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o500)).map_err(|source| {
        VerifierWorkerError::RuntimeCopy {
            operation: "making the private verifier executable read-only",
            source,
        }
    })
}

#[cfg(windows)]
fn set_immutable_executable_permissions(path: &Path) -> Result<(), VerifierWorkerError> {
    let mut permissions = fs::metadata(path)
        .map_err(|source| VerifierWorkerError::RuntimeCopy {
            operation: "inspecting the private verifier executable",
            source,
        })?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(|source| VerifierWorkerError::RuntimeCopy {
        operation: "making the private verifier executable read-only",
        source,
    })
}

#[cfg(not(any(unix, windows)))]
fn set_immutable_executable_permissions(_path: &Path) -> Result<(), VerifierWorkerError> {
    Err(VerifierWorkerError::InvalidConfig(
        "private verifier runtime permissions are unsupported on this platform",
    ))
}

fn make_runtime_copy_writable(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }
    #[cfg(windows)]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        // Windows toggles FILE_ATTRIBUTE_READONLY.
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(())
    }
}

#[derive(Default)]
struct StderrCapture {
    bytes: Vec<u8>,
    exceeded: bool,
}

struct PersistentVerifierProcess {
    generation: u64,
    child: ContainedChild,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr_capture: Arc<Mutex<StderrCapture>>,
    transport_poisoned: Arc<AtomicBool>,
    stderr_done: Option<mpsc::Receiver<()>>,
    stderr_thread: Option<JoinHandle<()>>,
}

impl PersistentVerifierProcess {
    fn new(
        mut child: ContainedChild,
        generation: u64,
        transport_poisoned: Arc<AtomicBool>,
    ) -> Result<Self, VerifierWorkerError> {
        let stdin = child
            .child
            .stdin
            .take()
            .ok_or(VerifierWorkerError::Process(
                ProofWorkerError::InvalidConfig("worker stdin pipe was not created"),
            ))?;
        let stdout = child
            .child
            .stdout
            .take()
            .ok_or(VerifierWorkerError::Process(
                ProofWorkerError::InvalidConfig("worker stdout pipe was not created"),
            ))?;
        let stderr = child
            .child
            .stderr
            .take()
            .ok_or(VerifierWorkerError::Process(
                ProofWorkerError::InvalidConfig("worker stderr pipe was not created"),
            ))?;
        let stderr_capture = Arc::new(Mutex::new(StderrCapture::default()));
        let capture = Arc::clone(&stderr_capture);
        let (stderr_done_sender, stderr_done) = mpsc::channel();
        let stderr_thread = thread::spawn(move || {
            capture_persistent_stderr(stderr, capture);
            let _ = stderr_done_sender.send(());
        });
        Ok(Self {
            generation,
            child,
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr_capture,
            transport_poisoned,
            stderr_done: Some(stderr_done),
            stderr_thread: Some(stderr_thread),
        })
    }

    fn exchange(
        &mut self,
        request: Vec<u8>,
        timeout: Duration,
        response_limit: usize,
    ) -> Result<Vec<u8>, VerifierWorkerError> {
        let stdin = self.stdin.take().ok_or(VerifierWorkerError::Process(
            ProofWorkerError::InvalidConfig("persistent worker stdin pipe is unavailable"),
        ))?;
        let stdout = self.stdout.take().ok_or(VerifierWorkerError::Process(
            ProofWorkerError::InvalidConfig("persistent worker stdout pipe is unavailable"),
        ))?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let (done_sender, done_receiver) = mpsc::channel();
        let io_thread = thread::spawn(move || {
            let mut stdin = stdin;
            let mut stdout = stdout;
            let result = write_frame(&mut stdin, &request)
                .and_then(|()| read_required_frame(&mut stdout, response_limit));
            let _ = sender.send((stdin, stdout, result));
            let _ = done_sender.send(());
        });

        let received = receiver.recv_timeout(timeout);
        match received {
            Ok((stdin, stdout, result)) => {
                if !finish_pipe_thread_bounded(io_thread, done_receiver) {
                    self.transport_poisoned.store(true, Ordering::Release);
                    self.child.terminate_and_reap();
                    return Err(VerifierWorkerError::TransportPoisoned);
                }
                self.stdin = Some(stdin);
                self.stdout = Some(stdout);
                if self.stderr_exceeded()? {
                    self.child.terminate_and_reap();
                    return Err(VerifierWorkerError::Process(
                        ProofWorkerError::StderrTooLarge,
                    ));
                }
                let response = result.map_err(VerifierWorkerError::Process)?;
                match self.child.child.try_wait() {
                    Ok(None) => Ok(response),
                    Ok(Some(status)) => Err(VerifierWorkerError::Process(worker_exit_error(
                        status,
                        &self.stderr_bytes()?,
                    ))),
                    Err(source) => Err(VerifierWorkerError::Process(ProofWorkerError::Pipe {
                        operation: "waiting for persistent verifier worker",
                        source,
                    })),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.child.terminate_and_reap();
                if !finish_pipe_thread_bounded(io_thread, done_receiver) {
                    self.transport_poisoned.store(true, Ordering::Release);
                }
                Err(VerifierWorkerError::Process(ProofWorkerError::Timeout {
                    milliseconds: timeout.as_millis(),
                }))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.child.terminate_and_reap();
                if !finish_pipe_thread_bounded(io_thread, done_receiver) {
                    self.transport_poisoned.store(true, Ordering::Release);
                }
                Err(VerifierWorkerError::Process(ProofWorkerError::PipeThread(
                    "exchanging persistent verifier frames",
                )))
            }
        }
    }

    fn stderr_exceeded(&self) -> Result<bool, VerifierWorkerError> {
        self.stderr_capture
            .lock()
            .map(|capture| capture.exceeded)
            .map_err(|_| VerifierWorkerError::StatePoisoned)
    }

    fn stderr_bytes(&self) -> Result<Vec<u8>, VerifierWorkerError> {
        self.stderr_capture
            .lock()
            .map(|capture| capture.bytes.clone())
            .map_err(|_| VerifierWorkerError::StatePoisoned)
    }
}

/// Joins only after the thread explicitly reports completion. A caller that
/// observes `false` must permanently poison the transport before detaching the
/// handle, preventing a hostile inherited pipe from leaking one thread per
/// restarted process generation.
fn finish_pipe_thread_bounded(thread: JoinHandle<()>, done: mpsc::Receiver<()>) -> bool {
    match done.recv_timeout(PROCESS_REAP_TIMEOUT) {
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = thread.join();
            true
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            drop(thread);
            false
        }
    }
}

fn capture_persistent_stderr(mut stderr: impl Read, capture: Arc<Mutex<StderrCapture>>) {
    let mut buffer = [0_u8; 8 * 1024];
    while let Ok(read) = stderr.read(&mut buffer) {
        if read == 0 {
            break;
        }
        let exceeded = if let Ok(mut captured) = capture.lock() {
            let remaining = MAX_STDERR_BYTES.saturating_sub(captured.bytes.len());
            captured
                .bytes
                .extend_from_slice(&buffer[..read.min(remaining)]);
            if read > remaining {
                captured.exceeded = true;
            }
            captured.exceeded
        } else {
            true
        };
        if exceeded {
            // Dropping the read end forces an honest worker to observe a
            // closed pipe. A hostile inherited writer is still bounded by the
            // request deadline and permanently poisons restart if teardown
            // cannot reap this reader.
            break;
        }
    }
}

impl Drop for PersistentVerifierProcess {
    fn drop(&mut self) {
        self.child.terminate_and_reap();
        self.stdin.take();
        self.stdout.take();
        if let (Some(thread), Some(done)) = (self.stderr_thread.take(), self.stderr_done.take())
            && !finish_pipe_thread_bounded(thread, done)
        {
            self.transport_poisoned.store(true, Ordering::Release);
        }
    }
}

fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<(), ProofWorkerError> {
    let length = u32::try_from(bytes.len()).map_err(|_| {
        ProofWorkerError::InvalidConfig(
            "persistent verifier frame exceeds the protocol length type",
        )
    })?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|()| writer.write_all(bytes))
        .and_then(|()| writer.flush())
        .map_err(|source| ProofWorkerError::Pipe {
            operation: "writing a persistent verifier frame",
            source,
        })
}

fn read_required_frame(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, ProofWorkerError> {
    let mut length = [0_u8; FRAME_LENGTH_BYTES];
    reader
        .read_exact(&mut length)
        .map_err(|source| ProofWorkerError::Pipe {
            operation: "reading a persistent verifier frame length",
            source,
        })?;
    let length = usize::try_from(u32::from_le_bytes(length)).map_err(|_| {
        ProofWorkerError::InvalidConfig(
            "persistent verifier frame length does not fit this platform",
        )
    })?;
    if length == 0 || length > limit {
        return Err(ProofWorkerError::StdoutTooLarge);
    }
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|source| ProofWorkerError::Pipe {
            operation: "reading a persistent verifier frame body",
            source,
        })?;
    Ok(bytes)
}

fn encode_startup_handshake(handshake: StartupHandshake) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HANDSHAKE_REQUEST_BYTES);
    bytes.extend_from_slice(HANDSHAKE_REQUEST_MAGIC);
    bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes.push(handshake.profile);
    bytes.extend_from_slice(&handshake.network_id);
    bytes.extend_from_slice(&handshake.verifier_identity);
    bytes.extend_from_slice(&handshake.challenge);
    bytes
}

fn decode_startup_handshake(bytes: &[u8]) -> Result<StartupHandshake, VerifierProtocolError> {
    if bytes.len() != HANDSHAKE_REQUEST_BYTES {
        return Err(VerifierProtocolError::InvalidLength);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != HANDSHAKE_REQUEST_MAGIC {
        return Err(VerifierProtocolError::Magic);
    }
    let version = cursor.read_u32()?;
    if version != PROTOCOL_VERSION {
        return Err(VerifierProtocolError::Version(version));
    }
    let profile = cursor.read_u8()?;
    if !matches!(profile, PROFILE_V2_REFERENCE | PROFILE_PRODUCTION_V3) {
        return Err(VerifierProtocolError::InvalidStatus);
    }
    let handshake = StartupHandshake {
        profile,
        network_id: cursor.read_array()?,
        verifier_identity: cursor.read_array()?,
        challenge: cursor.read_array()?,
    };
    cursor.finish()?;
    Ok(handshake)
}

fn startup_self_test(
    profile: u8,
    network_id: [u8; 32],
    verifier_identity: [u8; 32],
    challenge: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STARTUP_SELF_TEST_DOMAIN);
    hasher.update([profile]);
    hasher.update(network_id);
    hasher.update(verifier_identity);
    hasher.update(challenge);
    hasher.finalize().into()
}

fn encode_startup_success(handshake: &StartupHandshake) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HANDSHAKE_SUCCESS_BYTES);
    bytes.extend_from_slice(HANDSHAKE_RESPONSE_MAGIC);
    bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes.push(HANDSHAKE_STATUS_SUCCESS);
    bytes.push(handshake.profile);
    bytes.extend_from_slice(&handshake.network_id);
    bytes.extend_from_slice(&handshake.verifier_identity);
    bytes.extend_from_slice(&startup_self_test(
        handshake.profile,
        handshake.network_id,
        handshake.verifier_identity,
        handshake.challenge,
    ));
    bytes
}

fn encode_startup_error(code: u16, message: &str) -> Vec<u8> {
    let message = truncate_utf8(message, MAX_ERROR_BYTES);
    let mut bytes = Vec::with_capacity(HANDSHAKE_ERROR_FIXED_BYTES + message.len());
    bytes.extend_from_slice(HANDSHAKE_RESPONSE_MAGIC);
    bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes.push(HANDSHAKE_STATUS_FAILURE);
    bytes.extend_from_slice(&code.to_le_bytes());
    bytes.extend_from_slice(&(message.len() as u16).to_le_bytes());
    bytes.extend_from_slice(message.as_bytes());
    bytes
}

fn decode_startup_response(bytes: &[u8]) -> Result<StartupResponse, VerifierProtocolError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != HANDSHAKE_RESPONSE_MAGIC {
        return Err(VerifierProtocolError::Magic);
    }
    let version = cursor.read_u32()?;
    if version != PROTOCOL_VERSION {
        return Err(VerifierProtocolError::Version(version));
    }
    let response = match cursor.read_u8()? {
        HANDSHAKE_STATUS_SUCCESS => StartupResponse::Success {
            profile: cursor.read_u8()?,
            network_id: cursor.read_array()?,
            verifier_identity: cursor.read_array()?,
            self_test: cursor.read_array()?,
        },
        HANDSHAKE_STATUS_FAILURE => {
            let code = cursor.read_u16()?;
            if !(ERROR_REQUEST..=ERROR_INTERNAL).contains(&code) {
                return Err(VerifierProtocolError::InvalidErrorCode);
            }
            let length = usize::from(cursor.read_u16()?);
            if length > MAX_ERROR_BYTES || length != cursor.remaining() {
                return Err(VerifierProtocolError::InvalidLength);
            }
            let message = std::str::from_utf8(cursor.take(length)?)
                .map_err(|_| VerifierProtocolError::InvalidUtf8)?
                .to_owned();
            StartupResponse::Failure { code, message }
        }
        _ => return Err(VerifierProtocolError::InvalidStatus),
    };
    cursor.finish()?;
    Ok(response)
}

fn require_startup_success(
    response: &[u8],
    profile: u8,
    network_id: [u8; 32],
    verifier_identity: [u8; 32],
    challenge: [u8; 32],
) -> Result<(), VerifierWorkerError> {
    match decode_startup_response(response)? {
        StartupResponse::Success {
            profile: received_profile,
            network_id: received_network,
            verifier_identity: received_verifier,
            self_test,
        } if received_profile == profile
            && received_network == network_id
            && received_verifier == verifier_identity
            && self_test
                == startup_self_test(profile, network_id, verifier_identity, challenge) =>
        {
            Ok(())
        }
        StartupResponse::Success { .. } => Err(VerifierWorkerError::Startup(
            "worker startup identity or self-test did not match the compiled verifier".to_owned(),
        )),
        StartupResponse::Failure { code, message } => {
            Err(VerifierWorkerError::WorkerReported { code, message })
        }
    }
}

/// Verifies one complete canonical block proof in a hash-pinned, killable,
/// memory-bounded child process and returns a capability bound to the exact
/// parent verifier, challenge, and proof bytes.
pub fn verify_block_out_of_process(
    config: &VerifierWorkerConfig,
    verifier: &ConsensusPowVerifier,
    block: &Block,
) -> Result<PreverifiedBlockProof, VerifierWorkerError> {
    config.validate_executable()?;
    let canonical = encode_block(block)
        .map_err(|error| VerifierWorkerError::BlockEncoding(error.to_string()))?;
    let binding = verifier
        .external_preverification_binding(&block.challenge, &block.proof)
        .map_err(|error| VerifierWorkerError::Capability(error.to_string()))?;
    let request = encode_request(VerifierRequest {
        network_id: block.challenge.network_id,
        verifier_identity: binding.verifier_identity(),
        statement_identity: binding.statement_identity(),
        block: canonical,
    })?;
    let mut command = Command::new(&config.worker_executable);
    command.arg(VERIFY_MODE);
    if let Some(artifacts) = &config.production_v3_artifacts {
        command
            .arg(V3_BANK_ARGUMENT)
            .arg(&artifacts.bank)
            .arg(V3_MANIFEST_ARGUMENT)
            .arg(&artifacts.manifest)
            .arg(V3_RECORD_ARGUMENT)
            .arg(&artifacts.record_v2);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = spawn_contained(&mut command, Some(config.memory_limit_bytes))?;
    let response =
        exchange_with_child(child, request, config.timeout, MAX_VERIFIER_RESPONSE_BYTES)?;
    require_matching_success(&response, binding)?;

    // SAFETY: the exact binding was returned by the caller-pinned worker only
    // after a canonical request, successful exit, bounded wall time, bounded
    // address space/job memory, and bounded stdout/stderr. Every failure above
    // returns without issuing a capability.
    unsafe { verifier.issue_external_preverification(&block.challenge, &block.proof, binding) }
        .map_err(|error| VerifierWorkerError::Capability(error.to_string()))
}

fn require_matching_success(
    response: &[u8],
    binding: ExternalPreverificationBinding,
) -> Result<(), VerifierWorkerError> {
    let (echoed_verifier, echoed_statement) = match decode_response(response)? {
        VerifierResponse::Success {
            verifier_identity,
            statement_identity,
        } => (verifier_identity, statement_identity),
        VerifierResponse::Failure { code, message } if code == ERROR_PROOF_REJECTED => {
            return Err(VerifierWorkerError::ProofRejected(message));
        }
        VerifierResponse::Failure { code, message } => {
            return Err(VerifierWorkerError::WorkerReported { code, message });
        }
    };
    if echoed_verifier != binding.verifier_identity()
        || echoed_statement != binding.statement_identity()
    {
        return Err(VerifierWorkerError::ResponseMismatch);
    }
    Ok(())
}

fn encode_request(request: VerifierRequest) -> Result<Vec<u8>, VerifierProtocolError> {
    if request.block.is_empty() || request.block.len() > MAX_BLOCK_BYTES {
        return Err(VerifierProtocolError::InvalidLength);
    }
    let block_len =
        u32::try_from(request.block.len()).map_err(|_| VerifierProtocolError::InvalidLength)?;
    let mut output = Vec::with_capacity(REQUEST_FIXED_BYTES + request.block.len());
    output.extend_from_slice(REQUEST_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.extend_from_slice(&request.network_id);
    output.extend_from_slice(&request.verifier_identity);
    output.extend_from_slice(&request.statement_identity);
    output.extend_from_slice(&block_len.to_le_bytes());
    output.extend_from_slice(&request.block);
    Ok(output)
}

fn decode_request(bytes: &[u8]) -> Result<VerifierRequest, VerifierProtocolError> {
    if bytes.len() > MAX_VERIFIER_REQUEST_BYTES {
        return Err(VerifierProtocolError::TooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != REQUEST_MAGIC {
        return Err(VerifierProtocolError::Magic);
    }
    let version = cursor.read_u32()?;
    if version != PROTOCOL_VERSION {
        return Err(VerifierProtocolError::Version(version));
    }
    let network_id = cursor.read_array()?;
    let verifier_identity = cursor.read_array()?;
    let statement_identity = cursor.read_array()?;
    let block_len =
        usize::try_from(cursor.read_u32()?).map_err(|_| VerifierProtocolError::InvalidLength)?;
    if block_len == 0 || block_len > MAX_BLOCK_BYTES || block_len != cursor.remaining() {
        return Err(VerifierProtocolError::InvalidLength);
    }
    let block = cursor.take(block_len)?.to_vec();
    cursor.finish()?;
    Ok(VerifierRequest {
        network_id,
        verifier_identity,
        statement_identity,
        block,
    })
}

fn encode_success_response(binding: ExternalPreverificationBinding) -> Vec<u8> {
    let mut output = Vec::with_capacity(SUCCESS_RESPONSE_BYTES);
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.push(STATUS_SUCCESS);
    output.extend_from_slice(&binding.verifier_identity());
    output.extend_from_slice(&binding.statement_identity());
    output
}

fn encode_error_response(code: u16, message: &str) -> Vec<u8> {
    let message = truncate_utf8(message, MAX_ERROR_BYTES);
    let mut output = Vec::with_capacity(ERROR_RESPONSE_FIXED_BYTES + message.len());
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.push(STATUS_FAILURE);
    output.extend_from_slice(&code.to_le_bytes());
    output.extend_from_slice(&(message.len() as u16).to_le_bytes());
    output.extend_from_slice(message.as_bytes());
    output
}

fn decode_response(bytes: &[u8]) -> Result<VerifierResponse, VerifierProtocolError> {
    if bytes.len() > MAX_VERIFIER_RESPONSE_BYTES {
        return Err(VerifierProtocolError::TooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != RESPONSE_MAGIC {
        return Err(VerifierProtocolError::Magic);
    }
    let version = cursor.read_u32()?;
    if version != PROTOCOL_VERSION {
        return Err(VerifierProtocolError::Version(version));
    }
    let response = match cursor.read_u8()? {
        STATUS_SUCCESS => VerifierResponse::Success {
            verifier_identity: cursor.read_array()?,
            statement_identity: cursor.read_array()?,
        },
        STATUS_FAILURE => {
            let code = cursor.read_u16()?;
            if !(ERROR_REQUEST..=ERROR_INTERNAL).contains(&code) {
                return Err(VerifierProtocolError::InvalidErrorCode);
            }
            let length = usize::from(cursor.read_u16()?);
            if length > MAX_ERROR_BYTES || length != cursor.remaining() {
                return Err(VerifierProtocolError::InvalidLength);
            }
            let message = std::str::from_utf8(cursor.take(length)?)
                .map_err(|_| VerifierProtocolError::InvalidUtf8)?
                .to_owned();
            VerifierResponse::Failure { code, message }
        }
        _ => return Err(VerifierProtocolError::InvalidStatus),
    };
    cursor.finish()?;
    Ok(response)
}

fn run_verifier_worker() -> Result<ExternalPreverificationBinding, (u16, String)> {
    let artifacts = parse_verifier_worker_arguments(std::env::args_os().skip(1))
        .map_err(|message| (ERROR_REQUEST, message.to_owned()))?;
    let request_bytes = read_stdin_bounded()
        .map_err(|error| (ERROR_INTERNAL, format!("could not read request: {error}")))?;
    let request =
        decode_request(&request_bytes).map_err(|error| (ERROR_REQUEST, error.to_string()))?;
    let block = decode_block(&request.block, request.network_id)
        .map_err(|error| (ERROR_REQUEST, error.to_string()))?;
    let canonical = encode_block(&block).map_err(|error| (ERROR_REQUEST, error.to_string()))?;
    if canonical != request.block {
        return Err((
            ERROR_REQUEST,
            "block request is not canonically encoded".to_owned(),
        ));
    }

    let verifier = load_worker_verifier(request.network_id, artifacts.as_ref())?;
    verify_request_with_loaded_verifier(&verifier, request, block)
}

fn verify_request_with_loaded_verifier(
    verifier: &ConsensusPowVerifier,
    request: VerifierRequest,
    block: Block,
) -> Result<ExternalPreverificationBinding, (u16, String)> {
    let expected = verifier
        .external_preverification_binding(&block.challenge, &block.proof)
        .map_err(|error| (ERROR_UNSUPPORTED_VERIFIER, error.to_string()))?;
    if request.verifier_identity != expected.verifier_identity() {
        return Err((
            ERROR_UNSUPPORTED_VERIFIER,
            "worker does not support the requested verifier identity".to_owned(),
        ));
    }
    if request.statement_identity != expected.statement_identity() {
        return Err((
            ERROR_REQUEST,
            "request binding does not match the canonical block".to_owned(),
        ));
    }
    verifier
        .verify(&block.challenge, &block.proof)
        .map_err(|error| (ERROR_PROOF_REJECTED, error.to_string()))?;
    Ok(expected)
}

fn load_worker_verifier(
    network_id: [u8; 32],
    artifacts: Option<&ProductionV3VerifierArtifacts>,
) -> Result<ConsensusPowVerifier, (u16, String)> {
    match artifacts {
        Some(artifacts) => load_production_v3_verifier(network_id, artifacts),
        None => {
            let reference = v2_reference_for_network(network_id).map_err(|_| {
                (
                    ERROR_INTERNAL,
                    "could not load the configured V2 verifier".to_owned(),
                )
            })?;
            Ok(ConsensusPowVerifier::v2_reference(reference))
        }
    }
}

fn persistent_verifier_worker_main() -> i32 {
    let artifacts = match parse_persistent_verifier_worker_arguments(std::env::args_os().skip(1)) {
        Ok(artifacts) => artifacts,
        Err(message) => {
            return write_single_startup_error(ERROR_REQUEST, message);
        }
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let handshake_bytes = match read_optional_worker_frame(&mut input, HANDSHAKE_REQUEST_BYTES) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return 1,
        Err(_) => {
            let _ = write_worker_frame(
                &mut output,
                &encode_startup_error(ERROR_REQUEST, "invalid startup frame"),
            );
            return 1;
        }
    };
    let handshake = match decode_startup_handshake(&handshake_bytes) {
        Ok(handshake) => handshake,
        Err(error) => {
            let _ = write_worker_frame(
                &mut output,
                &encode_startup_error(ERROR_REQUEST, &error.to_string()),
            );
            return 1;
        }
    };
    let actual_profile = if artifacts.is_some() {
        PROFILE_PRODUCTION_V3
    } else {
        PROFILE_V2_REFERENCE
    };
    if handshake.profile != actual_profile {
        let _ = write_worker_frame(
            &mut output,
            &encode_startup_error(
                ERROR_UNSUPPORTED_VERIFIER,
                "worker profile does not match the requested verifier profile",
            ),
        );
        return 1;
    }
    let verifier = match load_worker_verifier(handshake.network_id, artifacts.as_ref()) {
        Ok(verifier) => verifier,
        Err((code, message)) => {
            let _ = write_worker_frame(&mut output, &encode_startup_error(code, &message));
            return 1;
        }
    };
    let verifier_identity = match verifier.external_preverification_identity(handshake.network_id) {
        Ok(identity) => identity,
        Err(_) => {
            let _ = write_worker_frame(
                &mut output,
                &encode_startup_error(
                    ERROR_UNSUPPORTED_VERIFIER,
                    "worker could not derive the configured verifier identity",
                ),
            );
            return 1;
        }
    };
    if verifier_identity != handshake.verifier_identity {
        let _ = write_worker_frame(
            &mut output,
            &encode_startup_error(
                ERROR_UNSUPPORTED_VERIFIER,
                "worker verifier identity does not match the requested capability",
            ),
        );
        return 1;
    }
    if write_worker_frame(&mut output, &encode_startup_success(&handshake)).is_err() {
        return 1;
    }

    loop {
        let request_bytes = match read_optional_worker_frame(&mut input, MAX_VERIFIER_REQUEST_BYTES)
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return 0,
            Err(_) => return 1,
        };
        if request_bytes.as_slice() == SHUTDOWN_MAGIC {
            return 0;
        }
        let response = match decode_request(&request_bytes) {
            Ok(request) if request.network_id == handshake.network_id => {
                match decode_block(&request.block, request.network_id) {
                    Ok(block) => match encode_block(&block) {
                        Ok(canonical) if canonical == request.block => {
                            match verify_request_with_loaded_verifier(&verifier, request, block) {
                                Ok(binding) => encode_success_response(binding),
                                Err((code, message)) => encode_error_response(code, &message),
                            }
                        }
                        _ => encode_error_response(
                            ERROR_REQUEST,
                            "block request is not canonically encoded",
                        ),
                    },
                    Err(error) => encode_error_response(ERROR_REQUEST, &error.to_string()),
                }
            }
            Ok(_) => encode_error_response(ERROR_REQUEST, "request belongs to another network"),
            Err(error) => encode_error_response(ERROR_REQUEST, &error.to_string()),
        };
        if write_worker_frame(&mut output, &response).is_err() {
            return 1;
        }
    }
}

fn write_single_startup_error(code: u16, message: &str) -> i32 {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let _ = write_worker_frame(&mut output, &encode_startup_error(code, message));
    1
}

fn write_worker_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame is too large"))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

fn read_optional_worker_frame(reader: &mut impl Read, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; FRAME_LENGTH_BYTES];
    let first = reader.read(&mut length[..1])?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut length[1..])?;
    let length = usize::try_from(u32::from_le_bytes(length))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))?;
    if length == 0 || length > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length is outside the protocol bound",
        ));
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

fn parse_verifier_worker_arguments(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Option<ProductionV3VerifierArtifacts>, &'static str> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.len() == 1 && arguments[0].as_os_str() == OsStr::new(VERIFY_MODE) {
        return Ok(None);
    }
    if arguments.len() != 7
        || arguments[0].as_os_str() != OsStr::new(VERIFY_MODE)
        || arguments[1].as_os_str() != OsStr::new(V3_BANK_ARGUMENT)
        || arguments[3].as_os_str() != OsStr::new(V3_MANIFEST_ARGUMENT)
        || arguments[5].as_os_str() != OsStr::new(V3_RECORD_ARGUMENT)
    {
        return Err(
            "expected --verify-block alone or with the exact production V3 bank, manifest, and Record V2 arguments",
        );
    }
    let artifacts = ProductionV3VerifierArtifacts {
        bank: PathBuf::from(&arguments[2]),
        manifest: PathBuf::from(&arguments[4]),
        record_v2: PathBuf::from(&arguments[6]),
    };
    artifacts
        .validate()
        .map_err(|_| "production V3 verifier artifact paths are invalid")?;
    Ok(Some(artifacts))
}

fn parse_persistent_verifier_worker_arguments(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Option<ProductionV3VerifierArtifacts>, &'static str> {
    parse_verifier_artifact_arguments(PERSISTENT_VERIFY_MODE, arguments)
}

fn parse_verifier_artifact_arguments(
    mode: &'static str,
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Option<ProductionV3VerifierArtifacts>, &'static str> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.len() == 1 && arguments[0].as_os_str() == OsStr::new(mode) {
        return Ok(None);
    }
    if arguments.len() != 7
        || arguments[0].as_os_str() != OsStr::new(mode)
        || arguments[1].as_os_str() != OsStr::new(V3_BANK_ARGUMENT)
        || arguments[3].as_os_str() != OsStr::new(V3_MANIFEST_ARGUMENT)
        || arguments[5].as_os_str() != OsStr::new(V3_RECORD_ARGUMENT)
    {
        return Err(
            "expected the verifier mode alone or with the exact production V3 bank, manifest, and Record V2 arguments",
        );
    }
    let artifacts = ProductionV3VerifierArtifacts {
        bank: PathBuf::from(&arguments[2]),
        manifest: PathBuf::from(&arguments[4]),
        record_v2: PathBuf::from(&arguments[6]),
    };
    artifacts
        .validate()
        .map_err(|_| "production V3 verifier artifact paths are invalid")?;
    Ok(Some(artifacts))
}

#[cfg(feature = "production-v3")]
fn load_production_v3_verifier(
    network_id: [u8; 32],
    artifacts: &ProductionV3VerifierArtifacts,
) -> Result<ConsensusPowVerifier, (u16, String)> {
    cmfd_consensus::dory_v3_model_bank_record_validation::load_production_dory_v3_consensus_verifier(
        network_id,
        &artifacts.bank,
        &artifacts.manifest,
        &artifacts.record_v2,
    )
    .map(|loaded| loaded.into_verifier())
    .map_err(|_| {
        (
            ERROR_INTERNAL,
            "could not authenticate the configured production V3 verifier artifacts".to_owned(),
        )
    })
}

#[cfg(not(feature = "production-v3"))]
fn load_production_v3_verifier(
    _network_id: [u8; 32],
    _artifacts: &ProductionV3VerifierArtifacts,
) -> Result<ConsensusPowVerifier, (u16, String)> {
    Err((
        ERROR_UNSUPPORTED_VERIFIER,
        "this proof worker was built without production V3 verifier support".to_owned(),
    ))
}

pub(super) fn verifier_mode_requested() -> bool {
    matches!(
        std::env::args_os().nth(1).as_deref(),
        Some(value) if value == OsStr::new(VERIFY_MODE) || value == OsStr::new(PERSISTENT_VERIFY_MODE)
    )
}

pub(super) fn verifier_worker_main() -> i32 {
    if std::env::args_os().nth(1).as_deref() == Some(OsStr::new(PERSISTENT_VERIFY_MODE)) {
        return persistent_verifier_worker_main();
    }
    let response = match run_verifier_worker() {
        Ok(binding) => encode_success_response(binding),
        Err((code, message)) => encode_error_response(code, &message),
    };
    match io::stdout().write_all(&response) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn read_stdin_bounded() -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_VERIFIER_REQUEST_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], VerifierProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(VerifierProtocolError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(VerifierProtocolError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, VerifierProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, VerifierProtocolError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, VerifierProtocolError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], VerifierProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| VerifierProtocolError::Truncated)
    }

    fn finish(self) -> Result<(), VerifierProtocolError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(VerifierProtocolError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use cmfd_consensus::{
        BLOCK_VERSION, BlockChallenge, BlockProof, Coinbase, ForgeMatrixV3CandidateProof,
        v2_test_reference,
    };

    use super::*;

    fn candidate_block() -> (ConsensusPowVerifier, Block) {
        let reference = v2_test_reference().unwrap();
        let network_id = reference.descriptor().network_id;
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let challenge = BlockChallenge {
            network_id,
            previous_block: [1; 32],
            transaction_root: [2; 32],
            height: 1,
            timestamp: 60,
            target: [0xff; 32],
        };
        let proof = verifier.mine(&challenge, 7, 1).unwrap();
        (
            verifier,
            Block {
                version: BLOCK_VERSION,
                challenge,
                proof,
                coinbase: Coinbase {
                    height: 1,
                    outputs: Vec::new(),
                },
                transactions: Vec::new(),
            },
        )
    }

    #[test]
    fn verifier_request_round_trips_and_rejects_noncanonical_lengths() {
        let (verifier, block) = candidate_block();
        let binding = verifier
            .external_preverification_binding(&block.challenge, &block.proof)
            .unwrap();
        let canonical = encode_block(&block).unwrap();
        let request = VerifierRequest {
            network_id: block.challenge.network_id,
            verifier_identity: binding.verifier_identity(),
            statement_identity: binding.statement_identity(),
            block: canonical,
        };
        let encoded = encode_request(request).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(decoded.network_id, block.challenge.network_id);
        assert_eq!(decoded.verifier_identity, binding.verifier_identity());
        assert_eq!(decoded.statement_identity, binding.statement_identity());
        assert_eq!(decoded.block, encode_block(&block).unwrap());

        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(
            decode_request(&truncated),
            Err(VerifierProtocolError::InvalidLength)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_request(&trailing),
            Err(VerifierProtocolError::InvalidLength)
        );
        assert_eq!(
            decode_request(&vec![0; MAX_VERIFIER_REQUEST_BYTES + 1]),
            Err(VerifierProtocolError::TooLarge)
        );
    }

    #[test]
    fn verifier_response_binds_both_identities_and_rejects_malformed_streams() {
        let (verifier, block) = candidate_block();
        let binding = verifier
            .external_preverification_binding(&block.challenge, &block.proof)
            .unwrap();
        let encoded = encode_success_response(binding);
        assert_eq!(
            decode_response(&encoded).unwrap(),
            VerifierResponse::Success {
                verifier_identity: binding.verifier_identity(),
                statement_identity: binding.statement_identity(),
            }
        );

        let mut substituted = encoded.clone();
        substituted[SUCCESS_RESPONSE_BYTES - 1] ^= 1;
        let VerifierResponse::Success {
            verifier_identity,
            statement_identity,
        } = decode_response(&substituted).unwrap()
        else {
            unreachable!();
        };
        assert!(
            verifier_identity != binding.verifier_identity()
                || statement_identity != binding.statement_identity()
        );
        assert!(matches!(
            require_matching_success(&substituted, binding),
            Err(VerifierWorkerError::ResponseMismatch)
        ));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_response(&trailing),
            Err(VerifierProtocolError::TrailingBytes)
        );
        let mut bad_status = encoded;
        bad_status[12] = 9;
        assert_eq!(
            decode_response(&bad_status),
            Err(VerifierProtocolError::InvalidStatus)
        );
    }

    #[test]
    fn v3_candidate_remains_unsupported_by_the_worker_verifier() {
        let (verifier, mut block) = candidate_block();
        block.proof = BlockProof::V3Candidate(Box::new(ForgeMatrixV3CandidateProof {
            algorithm_version: 3,
            proof_version: 1,
            nonce: 7,
            model_manifest_digest: [3; 32],
            challenge_digest: [4; 32],
            final_activation_digest: [5; 32],
            work_digest: [6; 32],
            structured_proof: vec![1],
        }));
        assert!(verifier.verify(&block.challenge, &block.proof).is_err());
    }

    #[test]
    fn verifier_worker_arguments_never_infer_or_fallback_between_profiles() {
        assert_eq!(
            parse_verifier_worker_arguments([std::ffi::OsString::from(VERIFY_MODE)]).unwrap(),
            None
        );

        let root = std::env::current_dir().unwrap();
        let bank = root.join("model.bank");
        let manifest = root.join("model.manifest.json");
        let record_v2 = root.join("model.record-v2.json");
        let parsed = parse_verifier_worker_arguments([
            std::ffi::OsString::from(VERIFY_MODE),
            std::ffi::OsString::from(V3_BANK_ARGUMENT),
            bank.clone().into_os_string(),
            std::ffi::OsString::from(V3_MANIFEST_ARGUMENT),
            manifest.clone().into_os_string(),
            std::ffi::OsString::from(V3_RECORD_ARGUMENT),
            record_v2.clone().into_os_string(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            parsed,
            ProductionV3VerifierArtifacts {
                bank,
                manifest,
                record_v2,
            }
        );

        assert!(
            parse_verifier_worker_arguments([
                std::ffi::OsString::from(VERIFY_MODE),
                std::ffi::OsString::from(V3_BANK_ARGUMENT),
            ])
            .is_err()
        );
    }

    #[test]
    fn verifier_config_requires_absolute_path_and_nonzero_limits() {
        let mut config = VerifierWorkerConfig {
            worker_executable: PathBuf::from("worker"),
            worker_sha256: [0; 32],
            startup_timeout: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            memory_limit_bytes: 1,
            production_v3_artifacts: None,
        };
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
        config.worker_executable = std::env::current_exe().unwrap();
        config.timeout = Duration::ZERO;
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
        config.timeout = Duration::from_secs(1);
        config.memory_limit_bytes = 0;
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
        config.memory_limit_bytes = 1;
        config.production_v3_artifacts = Some(ProductionV3VerifierArtifacts {
            bank: PathBuf::from("relative-bank"),
            manifest: PathBuf::from("relative-manifest"),
            record_v2: PathBuf::from("relative-record"),
        });
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
    }

    #[test]
    fn private_copy_rejects_an_oversized_source_before_writing() {
        let sequence = PRIVATE_COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cmfd-verifier-copy-bound-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::write(&source, b"oversized").unwrap();

        let error = copy_and_pin_with_limit(&source, &destination, [0; 32], 4).unwrap_err();
        assert!(matches!(error, VerifierWorkerError::InvalidConfig(_)));
        assert!(!destination.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persistent_stderr_overflow_is_capture_bounded() {
        let capture = Arc::new(Mutex::new(StderrCapture::default()));
        capture_persistent_stderr(
            io::Cursor::new(vec![b'x'; MAX_STDERR_BYTES + 1]),
            Arc::clone(&capture),
        );

        let capture = capture.lock().unwrap();
        assert!(capture.exceeded);
        assert_eq!(capture.bytes.len(), MAX_STDERR_BYTES);
    }

    #[test]
    fn persistent_teardown_child_helper() {
        if std::env::var_os("CMFD_PERSISTENT_TEARDOWN_CHILD").is_some() {
            thread::sleep(Duration::from_secs(5));
        }
    }

    #[test]
    fn persistent_process_drop_bounds_and_poisons_a_stuck_pipe_reader() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("verifier::tests::persistent_teardown_child_helper")
            .arg("--nocapture")
            .env("CMFD_PERSISTENT_TEARDOWN_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = spawn_contained(&mut command, None).unwrap();
        let transport_poisoned = Arc::new(AtomicBool::new(false));
        let mut process =
            PersistentVerifierProcess::new(child, 1, Arc::clone(&transport_poisoned)).unwrap();

        // Replace the real stderr reader with a deliberately stuck handle.
        // Reap and join the real reader first so this test does not itself
        // create an untracked pipe thread.
        process.child.terminate_and_reap();
        process.stdin.take();
        process.stdout.take();
        assert!(finish_pipe_thread_bounded(
            process.stderr_thread.take().unwrap(),
            process.stderr_done.take().unwrap(),
        ));
        let (release_sender, release_receiver) = mpsc::channel();
        let (stuck_done_sender, stuck_done_receiver) = mpsc::channel();
        process.stderr_thread = Some(thread::spawn(move || {
            let _ = release_receiver.recv();
            let _ = stuck_done_sender.send(());
        }));
        process.stderr_done = Some(stuck_done_receiver);

        let (done_sender, done_receiver) = mpsc::channel();
        let dropper = thread::spawn(move || {
            drop(process);
            let _ = done_sender.send(());
        });
        let completed =
            done_receiver.recv_timeout(crate::PROCESS_REAP_TIMEOUT + Duration::from_secs(1));
        let _ = release_sender.send(());
        dropper.join().unwrap();
        assert!(
            completed.is_ok(),
            "persistent process teardown exceeded its bounded reap window"
        );
        assert!(transport_poisoned.load(Ordering::Acquire));
    }
}
