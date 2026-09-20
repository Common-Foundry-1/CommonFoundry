use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cmfd_consensus::{
    Block, ConsensusPowVerifier, ExternalPreverificationBinding, FileIdentity, MAX_BLOCK_BYTES,
    PreverifiedBlockProof, decode_block, encode_block, v2_reference_for_network,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    ContainedChild, MAX_STDERR_BYTES, PROCESS_REAP_TIMEOUT, ProcessTerminator, ProofWorkerError,
    VerifierSandboxStatus, exchange_with_child,
    sandbox::{install_production, required_production_status},
    spawn_contained, verify_file_hash, worker_exit_error,
};

const REQUEST_MAGIC: &[u8; 8] = b"CMFDVWQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"CMFDVWR1";
const PROTOCOL_VERSION: u32 = 3;
const VERIFY_MODE: &str = "--verify-block";
const PERSISTENT_VERIFY_MODE: &str = "--verify-block-server";
#[cfg(not(windows))]
const V3_RECORD_ARGUMENT: &str = "--production-v3-record-v2";
#[cfg(not(windows))]
const V3_RECORD_IDENTITY_ARGUMENT: &str = "--production-v3-record-v2-identity";
const REQUEST_FIXED_BYTES: usize = 8 + 4 + 32 + 32 + 32 + 32 + 4;
const SUCCESS_RESPONSE_BYTES: usize = 8 + 4 + 1 + 1 + 32 + 32 + 32;
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
const HANDSHAKE_REQUEST_BYTES: usize = 8 + 4 + 1 + 1 + 32 + 32 + 32 + 32;
const HANDSHAKE_SUCCESS_BYTES: usize = 8 + 4 + 1 + 1 + 1 + 32 + 32 + 32 + 32;
const HANDSHAKE_ERROR_FIXED_BYTES: usize = 8 + 4 + 1 + 2 + 2;
const STARTUP_SELF_TEST_DOMAIN: &[u8] = b"Common Foundry persistent verifier startup self-test v2";
const CONTAINMENT_PROFILE_DOMAIN: &[u8] = b"Common Foundry verifier containment profile v1";
/// Keeps repeated, immediately failing supervised starts from turning peer
/// retries into a process-spawn storm. `Restarting` remains published during
/// this bounded delay, and terminal close still wins the state transition.
const RESTART_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const LINUX_CGROUP_V2_DOMAIN_PROFILE: &[u8] = b"Common Foundry Linux cgroup-v2 domain containment v1: unified; delegated cpu,memory,pids; supervisor child; worker cgroup.type=domain; cpu.max; memory.max; memory.swap.max=0; pids.max; memory.oom.group=1; cgroup.max.depth=0; cgroup.max.descendants=0; exact cgroup.procs membership; cgroup.freeze; cgroup.kill";
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
    /// Measured cgroup-v2 CPU quota in microseconds. Linux ProductionV3
    /// requires this together with `cpu_period_micros`; Devnet does not use it.
    pub cpu_quota_micros: Option<u64>,
    /// Measured cgroup-v2 CPU period in microseconds.
    pub cpu_period_micros: Option<u64>,
    /// Measured maximum task count for the ProductionV3 verifier cgroup.
    pub pids_limit: Option<u64>,
    pub production_v3_record: Option<ProductionV3VerifierRecord>,
}

/// Local paths to the three authenticated artifacts required by V3 mining.
/// Verifier-only workers receive [`ProductionV3VerifierRecord`] instead.
/// Paths are process configuration only and never enter consensus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionV3VerifierArtifacts {
    pub bank: PathBuf,
    pub manifest: PathBuf,
    pub record_v2: PathBuf,
}

/// Exact release-pinned Record V2 passed to a verifier-only worker. The parent
/// binds all three identity fields to its compiled release profile before a
/// worker can start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionV3VerifierRecord {
    pub record_v2: PathBuf,
    pub expected_file: FileIdentity,
}

enum WorkerProductionArtifacts {
    #[cfg(not(windows))]
    Path(ProductionV3VerifierRecord),
    #[cfg(windows)]
    #[cfg_attr(not(feature = "production-v3"), allow(dead_code))]
    Handle(crate::windows_artifacts::OwnedWindowsProductionRecordHandle),
}

impl ProductionV3VerifierRecord {
    fn validate(&self) -> Result<(), VerifierWorkerError> {
        if !self.record_v2.is_absolute() {
            return Err(VerifierWorkerError::InvalidConfig(
                "production V3 Record V2 path must be absolute",
            ));
        }
        if self.expected_file.bytes == 0
            || self.expected_file.blake3 == [0; 32]
            || self.expected_file.sha256 == [0; 32]
        {
            return Err(VerifierWorkerError::InvalidConfig(
                "production V3 Record V2 identity must be complete and nonzero",
            ));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn identity_argument(&self) -> String {
        format!(
            "{}:{}:{}",
            self.expected_file.bytes,
            hex::encode(self.expected_file.blake3),
            hex::encode(self.expected_file.sha256)
        )
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
        match (
            self.cpu_quota_micros,
            self.cpu_period_micros,
            self.pids_limit,
        ) {
            (Some(quota), Some(period), Some(pids)) => {
                if quota < 1_000 {
                    return Err(VerifierWorkerError::InvalidConfig(
                        "worker CPU quota must be at least 1000 microseconds",
                    ));
                }
                if !(1_000..=1_000_000).contains(&period) {
                    return Err(VerifierWorkerError::InvalidConfig(
                        "worker CPU period must be between 1000 and 1000000 microseconds",
                    ));
                }
                if pids == 0 || pids > i64::MAX as u64 {
                    return Err(VerifierWorkerError::InvalidConfig(
                        "worker PID limit must be a nonzero signed 64-bit integer",
                    ));
                }
            }
            (None, None, None) =>
            {
                #[cfg(target_os = "linux")]
                if self.production_v3_record.is_some() {
                    return Err(VerifierWorkerError::InvalidConfig(
                        "Linux ProductionV3 requires measured CPU quota, CPU period, and PID limit",
                    ));
                }
            }
            _ => {
                return Err(VerifierWorkerError::InvalidConfig(
                    "worker CPU quota, CPU period, and PID limit must be configured together",
                ));
            }
        }
        if let Some(record) = &self.production_v3_record {
            record.validate()?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn linux_cgroup_limits(&self) -> Result<super::cgroup::LinuxCgroupLimits, VerifierWorkerError> {
        let limits = super::cgroup::LinuxCgroupLimits {
            cpu_quota_micros: self
                .cpu_quota_micros
                .ok_or(VerifierWorkerError::InvalidConfig(
                    "Linux ProductionV3 CPU quota is not configured",
                ))?,
            cpu_period_micros: self
                .cpu_period_micros
                .ok_or(VerifierWorkerError::InvalidConfig(
                    "Linux ProductionV3 CPU period is not configured",
                ))?,
            memory_bytes: self.memory_limit_bytes,
            pids: self.pids_limit.ok_or(VerifierWorkerError::InvalidConfig(
                "Linux ProductionV3 PID limit is not configured",
            ))?,
        };
        limits
            .validate()
            .map_err(|_| VerifierWorkerError::InvalidConfig("invalid Linux cgroup limits"))
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

    fn containment_profile_digest(&self, sandbox: VerifierSandboxStatus) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CONTAINMENT_PROFILE_DOMAIN);
        hasher.update([configured_profile(self)]);
        hasher.update([sandbox as u8]);
        #[cfg(target_os = "linux")]
        if self.production_v3_record.is_some() {
            hasher.update([1]);
            hasher.update(LINUX_CGROUP_V2_DOMAIN_PROFILE);
        } else {
            hasher.update([0]);
        }
        #[cfg(not(target_os = "linux"))]
        hasher.update([0]);
        hasher.update(self.memory_limit_bytes.to_le_bytes());
        match (
            self.cpu_quota_micros,
            self.cpu_period_micros,
            self.pids_limit,
        ) {
            (Some(quota), Some(period), Some(pids)) => {
                hasher.update([1]);
                hasher.update(quota.to_le_bytes());
                hasher.update(period.to_le_bytes());
                hasher.update(pids.to_le_bytes());
            }
            _ => hasher.update([0]),
        }
        hasher.finalize().into()
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
    #[error("verifier worker is restarting")]
    Restarting,
    #[error("verifier worker is unavailable after a failed supervised restart")]
    Unavailable,
    #[error("verifier worker request deadline has expired")]
    RequestDeadlineExpired,
    /// An error that occurred only after a persistent verifier began handling
    /// one canonical block request. Startup, configuration, authentication,
    /// containment, and pre-dispatch failures are never wrapped here.
    #[error("verifier worker failed while handling a dispatched request: {0}")]
    DispatchedRequest(#[source] Box<VerifierWorkerError>),
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
    #[error("verifier worker failed ({worker}); bounded process cleanup also failed: {source}")]
    CleanupAfterFailure {
        worker: Box<VerifierWorkerError>,
        #[source]
        source: io::Error,
    },
    #[error("verifier worker is permanently closed")]
    Closed,
    #[error("ProductionV3 verifier sandbox is unavailable: {0}")]
    SandboxUnavailable(&'static str),
}

impl VerifierWorkerError {
    /// True only when a canonical proof request reached a persistent worker
    /// and the request itself was rejected or the worker failed while serving
    /// it. Startup, configuration, authentication, containment, and capability
    /// failures that occur before dispatch are deliberately excluded.
    pub fn is_dispatched_proof_failure(&self) -> bool {
        match self {
            Self::ProofRejected(_) | Self::DispatchedRequest(_) => true,
            Self::CleanupAfterFailure { worker, .. } => worker.is_dispatched_proof_failure(),
            _ => false,
        }
    }
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
    containment_profile: [u8; 32],
    block: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum VerifierResponse {
    Success {
        sandbox_status: VerifierSandboxStatus,
        verifier_identity: [u8; 32],
        statement_identity: [u8; 32],
        containment_profile: [u8; 32],
    },
    Failure {
        code: u16,
        message: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct StartupHandshake {
    profile: u8,
    required_sandbox: VerifierSandboxStatus,
    network_id: [u8; 32],
    verifier_identity: [u8; 32],
    containment_profile: [u8; 32],
    challenge: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
enum StartupResponse {
    Success {
        profile: u8,
        sandbox_status: VerifierSandboxStatus,
        network_id: [u8; 32],
        verifier_identity: [u8; 32],
        containment_profile: [u8; 32],
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
    readiness: AtomicU8,
    teardown_failures: Arc<AtomicU64>,
    shutdown_epoch: AtomicU64,
    terminated_generation: AtomicU64,
    sandbox_status: std::sync::atomic::AtomicU8,
    /// Set permanently if a contained generation leaves a pipe owner alive
    /// beyond the bounded teardown window. Later generations are forbidden so
    /// hostile descendants cannot accumulate unbounded threads or handles.
    transport_poisoned: Arc<AtomicBool>,
    closed: AtomicBool,
    // Declared last so the process and its pipes are dropped before its private
    // executable copy is made writable for cleanup.
    runtime_copy: PrivateRuntimeCopy,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum PersistentWorkerReadiness {
    Starting = 0,
    Healthy = 1,
    Restarting = 2,
    Unavailable = 3,
    Closed = 4,
}

impl PersistentWorkerReadiness {
    fn load(value: u8) -> Self {
        match value {
            0 => Self::Starting,
            1 => Self::Healthy,
            2 => Self::Restarting,
            3 => Self::Unavailable,
            _ => Self::Closed,
        }
    }
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
        // Reject unsupported ProductionV3 isolation before copying or
        // executing any worker image. Devnet V2 intentionally remains
        // available with process-tree crash containment only.
        expected_sandbox_status(&config)?;
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
                readiness: AtomicU8::new(PersistentWorkerReadiness::Starting as u8),
                teardown_failures: Arc::new(AtomicU64::new(0)),
                shutdown_epoch: AtomicU64::new(0),
                terminated_generation: AtomicU64::new(0),
                sandbox_status: std::sync::atomic::AtomicU8::new(
                    VerifierSandboxStatus::Unconfined as u8,
                ),
                transport_poisoned: Arc::new(AtomicBool::new(false)),
                closed: AtomicBool::new(false),
                runtime_copy,
            }),
        };
        worker.ensure_started()?;
        worker
            .inner
            .readiness
            .store(PersistentWorkerReadiness::Healthy as u8, Ordering::Release);
        Ok(worker)
    }

    pub fn verify_block(
        &self,
        block: &Block,
    ) -> Result<PreverifiedBlockProof, VerifierWorkerError> {
        self.verify_block_with_timeout(block, self.inner.config.timeout)
    }

    /// Verifies one block without allowing this request to spend longer than
    /// `timeout_limit` in the already-authenticated worker. Starting or
    /// authenticating a replacement generation is always supervised outside
    /// the submitting request.
    pub fn verify_block_with_timeout(
        &self,
        block: &Block,
        timeout_limit: Duration,
    ) -> Result<PreverifiedBlockProof, VerifierWorkerError> {
        if timeout_limit.is_zero() {
            return Err(VerifierWorkerError::RequestDeadlineExpired);
        }
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(VerifierWorkerError::Closed);
        }
        self.ensure_request_ready()?;
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
        let required_sandbox = expected_sandbox_status(&self.inner.config)?;
        let containment_profile = self
            .inner
            .config
            .containment_profile_digest(required_sandbox);
        let request = encode_request(VerifierRequest {
            network_id: block.challenge.network_id,
            verifier_identity: binding.verifier_identity(),
            statement_identity: binding.statement_identity(),
            containment_profile,
            block: canonical,
        })?;

        let mut process = self
            .inner
            .process
            .lock()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        if self.inner.closed.load(Ordering::Acquire) {
            let error = self
                .inner
                .finish_generation(&mut process, VerifierWorkerError::Closed);
            return Err(error);
        }
        if PersistentWorkerReadiness::load(self.inner.readiness.load(Ordering::Acquire))
            != PersistentWorkerReadiness::Healthy
        {
            return Err(VerifierWorkerError::Restarting);
        }
        let request_shutdown_epoch = self.inner.shutdown_epoch.load(Ordering::Acquire);
        self.inner.discard_terminated_generation(&mut process)?;
        if process.is_none() {
            drop(process);
            self.request_supervised_restart();
            return Err(VerifierWorkerError::Restarting);
        }
        let response = match process
            .as_mut()
            .expect("persistent verifier was started above")
            .exchange(
                request,
                self.inner.config.timeout.min(timeout_limit),
                MAX_VERIFIER_RESPONSE_BYTES,
                PersistentExchangePhase::Request,
            ) {
            Ok(response) => response,
            Err(error) => {
                let error = self.inner.finish_generation(&mut process, error);
                drop(process);
                self.request_supervised_restart();
                return Err(error);
            }
        };
        if let Err(error) =
            require_matching_success(&response, binding, required_sandbox, containment_profile)
        {
            let error = wrap_dispatched_request_error(error);
            // A canonical proof rejection is an expected, statement-local
            // outcome. Protocol, identity, and worker-internal failures poison
            // this process generation and force a complete authenticated
            // restart before any later request.
            if !matches!(error, VerifierWorkerError::ProofRejected(_)) {
                let error = self.inner.finish_generation(&mut process, error);
                drop(process);
                self.request_supervised_restart();
                return Err(error);
            }
            return Err(error);
        }
        if self.inner.shutdown_epoch.load(Ordering::Acquire) != request_shutdown_epoch {
            let error = self.inner.finish_generation(
                &mut process,
                VerifierWorkerError::Startup("worker request was cancelled".to_owned()),
            );
            return Err(error);
        }
        if self.inner.closed.load(Ordering::Acquire) {
            let error = self
                .inner
                .finish_generation(&mut process, VerifierWorkerError::Closed);
            return Err(error);
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
                let error = self.inner.finish_generation(
                    &mut process,
                    VerifierWorkerError::Capability(error.to_string()),
                );
                drop(process);
                self.request_supervised_restart();
                Err(error)
            }
        }
    }

    pub fn timeout(&self) -> Duration {
        self.inner.config.timeout
    }

    pub fn memory_limit_bytes(&self) -> u64 {
        self.inner.config.memory_limit_bytes
    }

    /// True only after the current generation completed its authenticated
    /// startup handshake. This is local admission state, not consensus proof.
    pub fn is_ready(&self) -> bool {
        PersistentWorkerReadiness::load(self.inner.readiness.load(Ordering::Acquire))
            == PersistentWorkerReadiness::Healthy
    }

    /// Counts additional failures while tearing down a poisoned generation.
    /// The request error that triggered teardown remains authoritative.
    pub fn teardown_failures(&self) -> u64 {
        self.inner.teardown_failures.load(Ordering::Acquire)
    }

    /// Last startup-authenticated isolation state. ProductionV3 construction
    /// fails before returning unless this is the platform-required sandbox.
    pub fn sandbox_status(&self) -> VerifierSandboxStatus {
        VerifierSandboxStatus::from_wire(self.inner.sandbox_status.load(Ordering::Acquire))
            .unwrap_or(VerifierSandboxStatus::Unconfined)
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
            terminate_for_shutdown(
                handle,
                &self.inner.transport_poisoned,
                &self.inner.teardown_failures,
            );
        }
        if !self.inner.closed.load(Ordering::Acquire) {
            self.request_supervised_restart();
        }
    }

    /// Permanently prevents new generations, then terminates the current one.
    /// Unlike `shutdown`, this is the terminal service-teardown operation.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner
            .readiness
            .store(PersistentWorkerReadiness::Closed as u8, Ordering::Release);
        self.shutdown();
        let mut process = match self.inner.process.lock() {
            Ok(process) => process,
            Err(poisoned) => {
                self.inner.transport_poisoned.store(true, Ordering::Release);
                self.inner.teardown_failures.fetch_add(1, Ordering::AcqRel);
                poisoned.into_inner()
            }
        };
        let _ = self.inner.discard_generation(&mut process);
    }

    fn ensure_request_ready(&self) -> Result<(), VerifierWorkerError> {
        match PersistentWorkerReadiness::load(self.inner.readiness.load(Ordering::Acquire)) {
            PersistentWorkerReadiness::Healthy => Ok(()),
            PersistentWorkerReadiness::Unavailable => {
                self.request_supervised_restart();
                Err(VerifierWorkerError::Unavailable)
            }
            PersistentWorkerReadiness::Starting | PersistentWorkerReadiness::Restarting => {
                Err(VerifierWorkerError::Restarting)
            }
            PersistentWorkerReadiness::Closed => Err(VerifierWorkerError::Closed),
        }
    }

    fn request_supervised_restart(&self) {
        if self.inner.closed.load(Ordering::Acquire) {
            return;
        }
        let mut observed = self.inner.readiness.load(Ordering::Acquire);
        loop {
            let readiness = PersistentWorkerReadiness::load(observed);
            if matches!(
                readiness,
                PersistentWorkerReadiness::Starting
                    | PersistentWorkerReadiness::Restarting
                    | PersistentWorkerReadiness::Closed
            ) {
                return;
            }
            match self.inner.readiness.compare_exchange_weak(
                observed,
                PersistentWorkerReadiness::Restarting as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => observed = actual,
            }
        }

        let inner = Arc::clone(&self.inner);
        let _supervisor = thread::Builder::new()
            .name("cmfd-verifier-restart".to_owned())
            .spawn(move || inner.supervise_restart());
        // If resource exhaustion prevented supervision itself, deliberately
        // keep the single-flight token fail-closed instead of allowing every
        // peer retry to attempt another thread spawn. Terminal close still
        // replaces this state; process restart is the recovery path.
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
            .and_then(|process| process.as_ref().map(|process| process.child.id()))
    }
}

impl PersistentVerifierWorkerInner {
    fn supervise_restart(self: Arc<Self>) {
        let result = (|| {
            if self.closed.load(Ordering::Acquire) {
                return Err(VerifierWorkerError::Closed);
            }
            let mut process = self
                .process
                .lock()
                .map_err(|_| VerifierWorkerError::StatePoisoned)?;
            self.discard_terminated_generation(&mut process)?;
            self.discard_generation(&mut process)?;
            if self.closed.load(Ordering::Acquire) {
                return Err(VerifierWorkerError::Closed);
            }
            *process = Some(self.start_process()?);
            Ok(())
        })();
        let readiness = if result.is_ok() {
            PersistentWorkerReadiness::Healthy
        } else {
            if !self.closed.load(Ordering::Acquire) {
                thread::sleep(RESTART_FAILURE_BACKOFF);
            }
            PersistentWorkerReadiness::Unavailable
        };
        // `Restarting` is the single-flight token. A racing close replaces it
        // with the terminal `Closed` state, so this compare-and-exchange can
        // never resurrect readiness after service teardown. A racing shutdown
        // only advances the epoch/terminates the generation; the supervised
        // attempt observes that and publishes `Unavailable` once.
        let _ = self.readiness.compare_exchange(
            PersistentWorkerReadiness::Restarting as u8,
            readiness as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn start_process(&self) -> Result<PersistentVerifierProcess, VerifierWorkerError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(VerifierWorkerError::Closed);
        }
        if self.transport_poisoned.load(Ordering::Acquire) {
            return Err(VerifierWorkerError::TransportPoisoned);
        }
        let required_sandbox = expected_sandbox_status(&self.config)?;
        let containment_profile = self.config.containment_profile_digest(required_sandbox);
        // Recheck the immutable source copy immediately before every exec. On
        // Windows the launcher additionally makes a fresh per-generation copy,
        // pins the source/destination/directory handles, verifies the exact
        // destination object, and executes only that private path.
        // Platforms without an exec-by-retained-handle primitive still have a
        // residual same-user check/exec race; their copy remains in a private,
        // randomly named, non-writable directory for its lifetime.
        self.runtime_copy.verify(self.config.worker_sha256)?;
        let mut command = Command::new(self.runtime_copy.executable());
        command.arg(PERSISTENT_VERIFY_MODE);
        #[cfg(not(windows))]
        if let Some(record) = &self.config.production_v3_record {
            command
                .arg(V3_RECORD_ARGUMENT)
                .arg(&record.record_v2)
                .arg(V3_RECORD_IDENTITY_ARGUMENT)
                .arg(record.identity_argument());
        }
        command
            .env_clear()
            .current_dir(self.runtime_copy.directory())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // A shutdown racing this restart may run while no terminator is
        // published. The epoch closes that gap: any overlapping request is
        // observed immediately after publication and kills this generation.
        let shutdown_epoch = self.shutdown_epoch.load(Ordering::Acquire);
        let child = if let Some(production_record) = &self.config.production_v3_record {
            let _ = production_record;
            #[cfg(target_os = "linux")]
            {
                super::spawn_contained_production(
                    command,
                    Some(self.config.memory_limit_bytes),
                    self.config.linux_cgroup_limits()?,
                )?
            }
            #[cfg(not(target_os = "linux"))]
            {
                #[cfg(windows)]
                {
                    crate::windows_launcher::spawn_contained_production_windows(
                        command,
                        production_record,
                        self.config.memory_limit_bytes,
                        self.config.worker_sha256,
                    )?
                }
                #[cfg(not(windows))]
                {
                    // `expected_sandbox_status` above fails closed on every
                    // platform without an implemented ProductionV3 launcher.
                    spawn_contained(&mut command, Some(self.config.memory_limit_bytes))?
                }
            }
        } else {
            spawn_contained(&mut command, Some(self.config.memory_limit_bytes))?
        };
        let generation = self.process_attempts.fetch_add(1, Ordering::AcqRel) + 1;
        let terminator = child.termination_handle();
        let mut process = PersistentVerifierProcess::new(
            child,
            generation,
            Arc::clone(&self.transport_poisoned),
            Arc::clone(&self.teardown_failures),
        )?;
        if let Err(error) = self.set_terminator(generation, terminator) {
            return Err(process.preserve_error_after_teardown(error));
        }
        if self.closed.load(Ordering::Acquire)
            || self.shutdown_epoch.load(Ordering::Acquire) != shutdown_epoch
        {
            self.terminated_generation
                .store(generation, Ordering::Release);
            let primary = if self.closed.load(Ordering::Acquire) {
                VerifierWorkerError::Closed
            } else {
                VerifierWorkerError::Startup("worker startup was cancelled".to_owned())
            };
            return Err(self.finish_local_generation(&mut process, primary));
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
                required_sandbox,
                network_id: self.network_id,
                verifier_identity: self.verifier_identity,
                containment_profile,
                challenge,
            });
            let response = process.exchange(
                request,
                self.config.startup_timeout,
                HANDSHAKE_SUCCESS_BYTES.max(HANDSHAKE_ERROR_FIXED_BYTES + MAX_ERROR_BYTES),
                PersistentExchangePhase::Startup,
            )?;
            let sandbox_status = require_startup_success(
                &response,
                profile,
                required_sandbox,
                self.network_id,
                self.verifier_identity,
                containment_profile,
                challenge,
            )?;
            self.sandbox_status
                .store(sandbox_status as u8, Ordering::Release);
            Ok(())
        })();
        if let Err(error) = startup {
            return Err(self.finish_local_generation(&mut process, error));
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

    fn finish_local_generation(
        &self,
        process: &mut PersistentVerifierProcess,
        primary: VerifierWorkerError,
    ) -> VerifierWorkerError {
        let generation = process.generation;
        let error = process.preserve_error_after_teardown(primary);
        match self.clear_terminator(generation) {
            Ok(()) => error,
            Err(cleanup) => compose_additional_cleanup_failure(
                error,
                io::Error::other(cleanup),
                &self.transport_poisoned,
                &self.teardown_failures,
            ),
        }
    }

    fn finish_generation(
        &self,
        slot: &mut Option<PersistentVerifierProcess>,
        primary: VerifierWorkerError,
    ) -> VerifierWorkerError {
        let Some(mut process) = slot.take() else {
            return primary;
        };
        self.finish_local_generation(&mut process, primary)
    }

    fn discard_generation(
        &self,
        slot: &mut Option<PersistentVerifierProcess>,
    ) -> Result<(), VerifierWorkerError> {
        let Some(mut process) = slot.take() else {
            return Ok(());
        };
        let generation = process.generation;
        let teardown = process.finish_teardown();
        let terminator = match self.clear_terminator(generation) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.transport_poisoned.store(true, Ordering::Release);
                self.teardown_failures.fetch_add(1, Ordering::AcqRel);
                Err(io::Error::other(error))
            }
        };
        super::combine_cleanup_results(teardown, terminator).map_err(|source| {
            VerifierWorkerError::Process(ProofWorkerError::Containment {
                operation: "discarding a persistent verifier generation",
                source,
            })
        })
    }

    fn discard_terminated_generation(
        &self,
        process: &mut Option<PersistentVerifierProcess>,
    ) -> Result<(), VerifierWorkerError> {
        let Some(generation) = process.as_ref().map(|process| process.generation) else {
            return Ok(());
        };
        if self.terminated_generation.load(Ordering::Acquire) == generation {
            self.discard_generation(process)?;
        }
        Ok(())
    }
}

impl Drop for PersistentVerifierWorkerInner {
    fn drop(&mut self) {
        let process = self
            .process
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mut process) = process.take() {
            let generation = process.generation;
            let _ = process.finish_teardown();
            let terminator = self
                .terminator
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if terminator
                .as_ref()
                .is_some_and(|(current, _)| *current == generation)
            {
                terminator.take();
            }
        }
        #[cfg(windows)]
        if crate::process::shutdown_appcontainer_profile_cleanup().is_err() {
            self.transport_poisoned.store(true, Ordering::Release);
        }
    }
}

fn configured_profile(config: &VerifierWorkerConfig) -> u8 {
    if config.production_v3_record.is_some() {
        PROFILE_PRODUCTION_V3
    } else {
        PROFILE_V2_REFERENCE
    }
}

fn expected_sandbox_status(
    config: &VerifierWorkerConfig,
) -> Result<VerifierSandboxStatus, VerifierWorkerError> {
    if config.production_v3_record.is_some() {
        required_production_status().map_err(VerifierWorkerError::SandboxUnavailable)
    } else {
        Ok(VerifierSandboxStatus::Unconfined)
    }
}

#[cfg(windows)]
struct WindowsRuntimeCopyCleanup {
    directory_handle: Option<File>,
    directory_identity: crate::process::WindowsFileIdentity,
    executable_handle: Option<File>,
    executable_identity: Option<crate::process::WindowsFileIdentity>,
    cleaned: bool,
}

#[cfg(windows)]
impl WindowsRuntimeCopyCleanup {
    fn pin_directory(path: &Path) -> io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
        };

        let directory_handle = OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let directory_identity = match crate::process::windows_file_identity(&directory_handle) {
            Ok(identity) => identity,
            Err(error) => {
                crate::process::mark_appcontainer_cleanup_unhealthy();
                std::mem::forget(directory_handle);
                return Err(error);
            }
        };
        Ok(Self {
            directory_handle: Some(directory_handle),
            directory_identity,
            executable_handle: None,
            executable_identity: None,
            cleaned: false,
        })
    }

    fn attach_executable(&mut self, executable: File) -> io::Result<()> {
        let identity = match crate::process::windows_file_identity(&executable) {
            Ok(identity) => identity,
            Err(error) => {
                crate::process::mark_appcontainer_cleanup_unhealthy();
                std::mem::forget(executable);
                return Err(error);
            }
        };
        self.executable_identity = Some(identity);
        self.executable_handle = Some(executable);
        Ok(())
    }

    fn cleanup(&mut self) -> io::Result<()> {
        let delays = [0_u64, 10, 20, 40, 80, 160, 320, 500];
        let mut last_error = None;
        for delay in delays {
            if delay != 0 {
                thread::sleep(Duration::from_millis(delay));
            }
            match self.cleanup_with_hook(|| Ok(())) {
                Ok(()) => return Ok(()),
                Err(error) if error.raw_os_error().is_some() => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last_error.expect("the bounded cleanup loop records every native failure"))
    }

    fn cleanup_with_hook(
        &mut self,
        after_executable_disposition: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        if let Some(executable) = self.executable_handle.as_ref() {
            let identity = self.executable_identity.ok_or_else(|| {
                io::Error::other("private copy executable identity is unavailable")
            })?;
            set_runtime_handle_readonly(executable, false)?;
            crate::process::delete_exact_runtime_handle(executable, false, identity)?;
            self.executable_handle.take();
        }
        after_executable_disposition()?;
        if let Some(directory) = self.directory_handle.as_ref() {
            crate::process::delete_exact_runtime_handle(directory, true, self.directory_identity)?;
            self.directory_handle.take();
        }
        self.cleaned = true;
        Ok(())
    }

    fn quarantine(&mut self) {
        if let Some(executable) = self.executable_handle.take() {
            std::mem::forget(executable);
        }
        if let Some(directory) = self.directory_handle.take() {
            std::mem::forget(directory);
        }
        self.cleaned = true;
    }

    #[cfg(test)]
    fn release_without_deletion_for_test(&mut self) {
        self.executable_handle.take();
        self.directory_handle.take();
        self.cleaned = true;
    }
}

#[cfg(windows)]
impl Drop for WindowsRuntimeCopyCleanup {
    fn drop(&mut self) {
        if self.cleanup().is_err() {
            self.quarantine();
            crate::process::mark_appcontainer_cleanup_unhealthy();
        }
    }
}

#[cfg(windows)]
fn set_runtime_handle_readonly(file: &File, readonly: bool) -> io::Result<()> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx,
        SetFileInformationByHandle,
    };

    let mut basic = MaybeUninit::<FILE_BASIC_INFO>::zeroed();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            basic.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut basic = unsafe { basic.assume_init() };
    if readonly {
        basic.FileAttributes |= FILE_ATTRIBUTE_READONLY;
    } else {
        basic.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
    }
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            (&raw const basic).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct PrivateRuntimeCopy {
    directory: PathBuf,
    executable: PathBuf,
    #[cfg(windows)]
    cleanup: Option<WindowsRuntimeCopyCleanup>,
}

impl PrivateRuntimeCopy {
    #[cfg(not(windows))]
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

    #[cfg(windows)]
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
                    let mut cleanup = WindowsRuntimeCopyCleanup::pin_directory(&directory)
                        .inspect_err(|_| crate::process::mark_appcontainer_cleanup_unhealthy())
                        .map_err(|source| VerifierWorkerError::RuntimeCopy {
                            operation: "identity-binding the private runtime directory",
                            source,
                        })?;
                    crate::windows_launcher::secure_owner_only_handle(
                        cleanup
                            .directory_handle
                            .as_ref()
                            .expect("new private runtime directory handle is retained"),
                    )
                    .map_err(|source| VerifierWorkerError::RuntimeCopy {
                        operation: "restricting the private runtime directory",
                        source,
                    })?;
                    let filename = if extension.is_empty() {
                        "verifier-runtime".to_owned()
                    } else {
                        format!("verifier-runtime.{extension}")
                    };
                    let executable = directory.join(filename);
                    let executable_handle = copy_and_pin(source, &executable, expected_sha256)?;
                    cleanup
                        .attach_executable(executable_handle)
                        .map_err(|source| VerifierWorkerError::RuntimeCopy {
                            operation: "identity-binding the private verifier executable",
                            source,
                        })?;
                    let executable_handle = cleanup
                        .executable_handle
                        .as_ref()
                        .expect("new private verifier executable handle is retained");
                    crate::windows_launcher::secure_owner_only_handle(executable_handle).map_err(
                        |source| VerifierWorkerError::RuntimeCopy {
                            operation: "restricting the private verifier executable",
                            source,
                        },
                    )?;
                    set_runtime_handle_readonly(executable_handle, true).map_err(|source| {
                        VerifierWorkerError::RuntimeCopy {
                            operation: "making the private verifier executable read-only",
                            source,
                        }
                    })?;
                    return Ok(Self {
                        directory,
                        executable,
                        cleanup: Some(cleanup),
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

    fn directory(&self) -> &Path {
        &self.directory
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
        #[cfg(windows)]
        if let Some(mut cleanup) = self.cleanup.take()
            && cleanup.cleanup().is_err()
        {
            cleanup.quarantine();
            crate::process::mark_appcontainer_cleanup_unhealthy();
        }
        #[cfg(not(windows))]
        {
            let _ = make_runtime_copy_writable(&self.executable);
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

fn copy_and_pin(
    source: &Path,
    destination: &Path,
    expected_sha256: [u8; 32],
) -> Result<File, VerifierWorkerError> {
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
) -> Result<File, VerifierWorkerError> {
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
    #[cfg(windows)]
    let (mut destination_file, destination_identity) = {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::{
            Foundation::GENERIC_WRITE,
            Storage::FileSystem::{
                DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
                FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, READ_CONTROL,
                SYNCHRONIZE, WRITE_DAC,
            },
        };
        let file = OpenOptions::new()
            .write(true)
            .access_mode(
                GENERIC_WRITE
                    | DELETE
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | SYNCHRONIZE
                    | READ_CONTROL
                    | WRITE_DAC,
            )
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(destination)
            .map_err(|source| VerifierWorkerError::RuntimeCopy {
                operation: "creating the private verifier executable",
                source,
            })?;
        match crate::process::windows_file_identity(&file) {
            Ok(identity) => (file, identity),
            Err(source) => {
                crate::process::mark_appcontainer_cleanup_unhealthy();
                std::mem::forget(file);
                return Err(VerifierWorkerError::RuntimeCopy {
                    operation: "identity-binding the new private verifier executable",
                    source,
                });
            }
        }
    };
    #[cfg(not(windows))]
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|source| VerifierWorkerError::RuntimeCopy {
            operation: "creating the private verifier executable",
            source,
        })?;

    let copy_result = (|| {
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut copied_bytes = 0_u64;
        loop {
            let read = source_file.read(&mut buffer).map_err(|source| {
                VerifierWorkerError::RuntimeCopy {
                    operation: "reading the pinned verifier executable",
                    source,
                }
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
    })();
    #[cfg(windows)]
    if let Err(primary) = copy_result {
        if let Err(cleanup) = crate::process::delete_exact_runtime_handle(
            &destination_file,
            false,
            destination_identity,
        ) {
            crate::process::mark_appcontainer_cleanup_unhealthy();
            std::mem::forget(destination_file);
            return Err(VerifierWorkerError::RuntimeCopy {
                operation: "cleaning an incomplete identity-bound private verifier executable",
                source: io::Error::other(format!("{primary}; cleanup failure: {cleanup}")),
            });
        }
        return Err(primary);
    }
    #[cfg(not(windows))]
    copy_result?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            FILE_WRITE_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
        };

        // Pin the just-written identity across the only handle transition. The
        // writer must close before the restrictive DELETE handle is opened,
        // but a replacement in that interval is detected by the two retained
        // identities and is never dispositioned.
        let identity_pin = OpenOptions::new()
            .read(true)
            .open(destination)
            .map_err(|source| VerifierWorkerError::RuntimeCopy {
                operation: "pinning the completed private verifier executable",
                source,
            })?;
        let pinned_identity =
            crate::process::windows_file_identity(&identity_pin).map_err(|source| {
                VerifierWorkerError::RuntimeCopy {
                    operation: "identity-binding the completed private verifier executable",
                    source,
                }
            })?;
        if pinned_identity != destination_identity {
            crate::process::mark_appcontainer_cleanup_unhealthy();
            std::mem::forget(identity_pin);
            std::mem::forget(destination_file);
            return Err(VerifierWorkerError::RuntimeCopy {
                operation: "pinning the completed private verifier executable",
                source: io::Error::other("private verifier executable identity changed"),
            });
        }
        drop(destination_file);

        let cleanup_handle = match OpenOptions::new()
            .access_mode(
                DELETE
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | SYNCHRONIZE
                    | READ_CONTROL
                    | WRITE_DAC,
            )
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(destination)
        {
            Ok(handle) => handle,
            Err(source) => {
                crate::process::mark_appcontainer_cleanup_unhealthy();
                std::mem::forget(identity_pin);
                return Err(VerifierWorkerError::RuntimeCopy {
                    operation: "retaining exact cleanup authority for the private verifier executable",
                    source,
                });
            }
        };
        let cleanup_identity = match crate::process::windows_file_identity(&cleanup_handle) {
            Ok(identity) => identity,
            Err(source) => {
                crate::process::mark_appcontainer_cleanup_unhealthy();
                std::mem::forget(identity_pin);
                std::mem::forget(cleanup_handle);
                return Err(VerifierWorkerError::RuntimeCopy {
                    operation: "identity-binding private verifier cleanup authority",
                    source,
                });
            }
        };
        if cleanup_identity != pinned_identity {
            crate::process::mark_appcontainer_cleanup_unhealthy();
            std::mem::forget(identity_pin);
            std::mem::forget(cleanup_handle);
            return Err(VerifierWorkerError::RuntimeCopy {
                operation: "retaining exact cleanup authority for the private verifier executable",
                source: io::Error::other(
                    "private verifier executable was replaced during cleanup-handle transition",
                ),
            });
        }
        drop(identity_pin);
        Ok(cleanup_handle)
    }
    #[cfg(not(windows))]
    Ok(destination_file)
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

#[cfg(not(any(unix, windows)))]
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

#[cfg(not(any(unix, windows)))]
fn set_immutable_executable_permissions(_path: &Path) -> Result<(), VerifierWorkerError> {
    Err(VerifierWorkerError::InvalidConfig(
        "private verifier runtime permissions are unsupported on this platform",
    ))
}

#[cfg(not(windows))]
fn make_runtime_copy_writable(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
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
    stdin: Option<super::process::BlockingPipeWriter>,
    stdout: Option<super::process::BlockingPipeReader>,
    stderr_capture: Arc<Mutex<StderrCapture>>,
    transport_poisoned: Arc<AtomicBool>,
    teardown_failures: Arc<AtomicU64>,
    stderr_done: Option<mpsc::Receiver<()>>,
    stderr_thread: Option<JoinHandle<()>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PersistentExchangePhase {
    Startup,
    Request,
}

fn wrap_exchange_error(
    phase: PersistentExchangePhase,
    error: VerifierWorkerError,
) -> VerifierWorkerError {
    let request_scoped = matches!(phase, PersistentExchangePhase::Request)
        && matches!(
            &error,
            VerifierWorkerError::TransportPoisoned
                | VerifierWorkerError::Process(
                    ProofWorkerError::Timeout { .. }
                        | ProofWorkerError::Pipe { .. }
                        | ProofWorkerError::PipeThread(_)
                        | ProofWorkerError::WorkerExited { .. }
                        | ProofWorkerError::StdoutTooLarge
                        | ProofWorkerError::StderrTooLarge
                )
        );
    if request_scoped {
        VerifierWorkerError::DispatchedRequest(Box::new(error))
    } else {
        error
    }
}

fn wrap_dispatched_request_error(error: VerifierWorkerError) -> VerifierWorkerError {
    if matches!(
        &error,
        VerifierWorkerError::Protocol(_)
            | VerifierWorkerError::WorkerReported { .. }
            | VerifierWorkerError::ResponseMismatch
    ) {
        VerifierWorkerError::DispatchedRequest(Box::new(error))
    } else {
        error
    }
}

impl PersistentVerifierProcess {
    fn new(
        mut child: ContainedChild,
        generation: u64,
        transport_poisoned: Arc<AtomicBool>,
        teardown_failures: Arc<AtomicU64>,
    ) -> Result<Self, VerifierWorkerError> {
        let stdin = match child.take_stdin() {
            Some(stdin) => stdin,
            None => {
                return Err(compose_persistent_cleanup(
                    &mut child,
                    &transport_poisoned,
                    VerifierWorkerError::Process(ProofWorkerError::InvalidConfig(
                        "worker stdin pipe was not created",
                    )),
                ));
            }
        };
        let stdout = match child.take_stdout() {
            Some(stdout) => stdout,
            None => {
                return Err(compose_persistent_cleanup(
                    &mut child,
                    &transport_poisoned,
                    VerifierWorkerError::Process(ProofWorkerError::InvalidConfig(
                        "worker stdout pipe was not created",
                    )),
                ));
            }
        };
        let stderr = match child.take_stderr() {
            Some(stderr) => stderr,
            None => {
                return Err(compose_persistent_cleanup(
                    &mut child,
                    &transport_poisoned,
                    VerifierWorkerError::Process(ProofWorkerError::InvalidConfig(
                        "worker stderr pipe was not created",
                    )),
                ));
            }
        };
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
            teardown_failures,
            stderr_done: Some(stderr_done),
            stderr_thread: Some(stderr_thread),
        })
    }

    fn exchange(
        &mut self,
        request: Vec<u8>,
        timeout: Duration,
        response_limit: usize,
        phase: PersistentExchangePhase,
    ) -> Result<Vec<u8>, VerifierWorkerError> {
        if let Err(error) = self.child.thaw_for_request() {
            let original = wrap_exchange_error(phase, VerifierWorkerError::Process(error));
            return Err(self.preserve_error_after_teardown(original));
        }
        let stdin = match self.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let original = wrap_exchange_error(
                    phase,
                    VerifierWorkerError::Process(ProofWorkerError::InvalidConfig(
                        "persistent worker stdin pipe is unavailable",
                    )),
                );
                return Err(self.preserve_error_after_teardown(original));
            }
        };
        let stdout = match self.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let original = wrap_exchange_error(
                    phase,
                    VerifierWorkerError::Process(ProofWorkerError::InvalidConfig(
                        "persistent worker stdout pipe is unavailable",
                    )),
                );
                return Err(self.preserve_error_after_teardown(original));
            }
        };
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
                    let original =
                        wrap_exchange_error(phase, VerifierWorkerError::TransportPoisoned);
                    return Err(self.preserve_error_after_teardown(original));
                }
                self.stdin = Some(stdin);
                self.stdout = Some(stdout);
                if let Err(error) = self.child.freeze_after_response() {
                    let original = wrap_exchange_error(phase, VerifierWorkerError::Process(error));
                    return Err(self.preserve_error_after_teardown(original));
                }
                match self.stderr_exceeded() {
                    Ok(true) => {
                        let original = wrap_exchange_error(
                            phase,
                            VerifierWorkerError::Process(ProofWorkerError::StderrTooLarge),
                        );
                        return Err(self.preserve_error_after_teardown(original));
                    }
                    Ok(false) => {}
                    Err(error) => return Err(self.preserve_error_after_teardown(error)),
                }
                let response = match result {
                    Ok(response) => response,
                    Err(error) => {
                        let original =
                            wrap_exchange_error(phase, VerifierWorkerError::Process(error));
                        return Err(self.preserve_error_after_teardown(original));
                    }
                };
                match self.child.try_wait() {
                    Ok(None) => Ok(response),
                    Ok(Some(status)) => {
                        let original = match self.stderr_bytes() {
                            Ok(stderr) => wrap_exchange_error(
                                phase,
                                VerifierWorkerError::Process(worker_exit_error(status, &stderr)),
                            ),
                            Err(error) => error,
                        };
                        Err(self.preserve_error_after_confirmed_exit(original))
                    }
                    Err(source) => {
                        let original = wrap_exchange_error(
                            phase,
                            VerifierWorkerError::Process(ProofWorkerError::Pipe {
                                operation: "waiting for persistent verifier worker",
                                source,
                            }),
                        );
                        Err(self.preserve_error_after_teardown(original))
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let original = wrap_exchange_error(
                    phase,
                    VerifierWorkerError::Process(ProofWorkerError::Timeout {
                        milliseconds: timeout.as_millis(),
                    }),
                );
                let mut error = self.preserve_error_after_teardown(original);
                if !finish_pipe_thread_bounded(io_thread, done_receiver) {
                    error = compose_additional_cleanup_failure(
                        error,
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "persistent verifier I/O thread did not stop after request timeout",
                        ),
                        &self.transport_poisoned,
                        &self.teardown_failures,
                    );
                }
                Err(error)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let original = wrap_exchange_error(
                    phase,
                    VerifierWorkerError::Process(ProofWorkerError::PipeThread(
                        "exchanging persistent verifier frames",
                    )),
                );
                let mut error = self.preserve_error_after_teardown(original);
                if !finish_pipe_thread_bounded(io_thread, done_receiver) {
                    error = compose_additional_cleanup_failure(
                        error,
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "persistent verifier I/O thread did not stop after disconnect",
                        ),
                        &self.transport_poisoned,
                        &self.teardown_failures,
                    );
                }
                Err(error)
            }
        }
    }

    fn preserve_error_after_teardown(
        &mut self,
        original: VerifierWorkerError,
    ) -> VerifierWorkerError {
        let teardown = self.finish_teardown();
        preserve_request_error(original, teardown)
    }

    fn preserve_error_after_confirmed_exit(
        &mut self,
        original: VerifierWorkerError,
    ) -> VerifierWorkerError {
        let child_cleanup = self
            .child
            .finish_reaped_and_cleanup()
            .map_err(io::Error::other);
        let teardown = super::combine_cleanup_results(child_cleanup, self.finish_pipe_resources());
        self.record_teardown_result(&teardown);
        preserve_request_error(original, teardown)
    }

    fn finish_teardown(&mut self) -> io::Result<()> {
        let child_cleanup = persistent_process_cleanup(&mut self.child, &self.transport_poisoned);
        let teardown = super::combine_cleanup_results(child_cleanup, self.finish_pipe_resources());
        self.record_teardown_result(&teardown);
        teardown
    }

    fn finish_pipe_resources(&mut self) -> io::Result<()> {
        self.stdin.take();
        self.stdout.take();
        match (self.stderr_thread.take(), self.stderr_done.take()) {
            (Some(thread), Some(done)) => {
                if finish_pipe_thread_bounded(thread, done) {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "persistent verifier stderr reader did not stop after process teardown",
                    ))
                }
            }
            (None, None) => Ok(()),
            _ => Err(io::Error::other(
                "persistent verifier stderr teardown state is inconsistent",
            )),
        }
    }

    fn record_teardown_result(&self, teardown: &io::Result<()>) {
        if teardown.is_err() {
            self.transport_poisoned.store(true, Ordering::Release);
            self.teardown_failures.fetch_add(1, Ordering::AcqRel);
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

fn persistent_process_cleanup(
    child: &mut ContainedChild,
    transport_poisoned: &AtomicBool,
) -> io::Result<()> {
    let report = child.terminate_and_reap_report();
    if !report.exit_confirmed {
        super::PROCESS_CLEANUP_UNHEALTHY.store(true, Ordering::Release);
    }
    match report.error {
        None if report.exit_confirmed => Ok(()),
        source => {
            transport_poisoned.store(true, Ordering::Release);
            Err(source.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "persistent verifier exit could not be confirmed; resources remain quarantined",
                )
            }))
        }
    }
}

fn compose_persistent_cleanup(
    child: &mut ContainedChild,
    transport_poisoned: &AtomicBool,
    primary: VerifierWorkerError,
) -> VerifierWorkerError {
    preserve_request_error(
        primary,
        persistent_process_cleanup(child, transport_poisoned),
    )
}

fn preserve_request_error(
    original: VerifierWorkerError,
    teardown: io::Result<()>,
) -> VerifierWorkerError {
    match teardown {
        Ok(()) => original,
        Err(source) => VerifierWorkerError::CleanupAfterFailure {
            worker: Box::new(original),
            source,
        },
    }
}

fn compose_additional_cleanup_failure(
    primary: VerifierWorkerError,
    source: io::Error,
    transport_poisoned: &AtomicBool,
    teardown_failures: &AtomicU64,
) -> VerifierWorkerError {
    transport_poisoned.store(true, Ordering::Release);
    teardown_failures.fetch_add(1, Ordering::AcqRel);
    VerifierWorkerError::CleanupAfterFailure {
        worker: Box::new(primary),
        source,
    }
}

fn terminate_for_shutdown(
    terminator: &ProcessTerminator,
    transport_poisoned: &AtomicBool,
    teardown_failures: &AtomicU64,
) {
    if terminator.terminate_tree().is_err() {
        transport_poisoned.store(true, Ordering::Release);
        teardown_failures.fetch_add(1, Ordering::AcqRel);
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
        let _ = self.finish_teardown();
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
    bytes.push(handshake.required_sandbox as u8);
    bytes.extend_from_slice(&handshake.network_id);
    bytes.extend_from_slice(&handshake.verifier_identity);
    bytes.extend_from_slice(&handshake.containment_profile);
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
        required_sandbox: VerifierSandboxStatus::from_wire(cursor.read_u8()?)
            .ok_or(VerifierProtocolError::InvalidStatus)?,
        network_id: cursor.read_array()?,
        verifier_identity: cursor.read_array()?,
        containment_profile: cursor.read_array()?,
        challenge: cursor.read_array()?,
    };
    cursor.finish()?;
    Ok(handshake)
}

fn startup_self_test(
    profile: u8,
    sandbox_status: VerifierSandboxStatus,
    network_id: [u8; 32],
    verifier_identity: [u8; 32],
    containment_profile: [u8; 32],
    challenge: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STARTUP_SELF_TEST_DOMAIN);
    hasher.update([profile]);
    hasher.update([sandbox_status as u8]);
    hasher.update(network_id);
    hasher.update(verifier_identity);
    hasher.update(containment_profile);
    hasher.update(challenge);
    hasher.finalize().into()
}

fn encode_startup_success(
    handshake: &StartupHandshake,
    sandbox_status: VerifierSandboxStatus,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HANDSHAKE_SUCCESS_BYTES);
    bytes.extend_from_slice(HANDSHAKE_RESPONSE_MAGIC);
    bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes.push(HANDSHAKE_STATUS_SUCCESS);
    bytes.push(handshake.profile);
    bytes.push(sandbox_status as u8);
    bytes.extend_from_slice(&handshake.network_id);
    bytes.extend_from_slice(&handshake.verifier_identity);
    bytes.extend_from_slice(&handshake.containment_profile);
    bytes.extend_from_slice(&startup_self_test(
        handshake.profile,
        sandbox_status,
        handshake.network_id,
        handshake.verifier_identity,
        handshake.containment_profile,
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
            sandbox_status: VerifierSandboxStatus::from_wire(cursor.read_u8()?)
                .ok_or(VerifierProtocolError::InvalidStatus)?,
            network_id: cursor.read_array()?,
            verifier_identity: cursor.read_array()?,
            containment_profile: cursor.read_array()?,
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
    required_sandbox: VerifierSandboxStatus,
    network_id: [u8; 32],
    verifier_identity: [u8; 32],
    containment_profile: [u8; 32],
    challenge: [u8; 32],
) -> Result<VerifierSandboxStatus, VerifierWorkerError> {
    match decode_startup_response(response)? {
        StartupResponse::Success {
            profile: received_profile,
            sandbox_status,
            network_id: received_network,
            verifier_identity: received_verifier,
            containment_profile: received_containment,
            self_test,
        } if received_profile == profile
            && sandbox_status == required_sandbox
            && received_network == network_id
            && received_verifier == verifier_identity
            && received_containment == containment_profile
            && self_test
                == startup_self_test(
                    profile,
                    required_sandbox,
                    network_id,
                    verifier_identity,
                    containment_profile,
                    challenge,
                ) =>
        {
            Ok(sandbox_status)
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
    let required_sandbox = expected_sandbox_status(config)?;
    let containment_profile = config.containment_profile_digest(required_sandbox);
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
        containment_profile,
        block: canonical,
    })?;
    let mut command = Command::new(&config.worker_executable);
    command.arg(VERIFY_MODE);
    #[cfg(not(windows))]
    if let Some(record) = &config.production_v3_record {
        command
            .arg(V3_RECORD_ARGUMENT)
            .arg(&record.record_v2)
            .arg(V3_RECORD_IDENTITY_ARGUMENT)
            .arg(record.identity_argument());
    }
    command
        .env_clear()
        .current_dir(config.worker_executable.parent().ok_or(
            VerifierWorkerError::InvalidConfig(
                "verifier worker executable has no parent directory",
            ),
        )?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = if let Some(production_record) = &config.production_v3_record {
        let _ = production_record;
        #[cfg(target_os = "linux")]
        {
            super::spawn_contained_production(
                command,
                Some(config.memory_limit_bytes),
                config.linux_cgroup_limits()?,
            )?
        }
        #[cfg(not(target_os = "linux"))]
        {
            #[cfg(windows)]
            {
                crate::windows_launcher::spawn_contained_production_windows(
                    command,
                    production_record,
                    config.memory_limit_bytes,
                    config.worker_sha256,
                )?
            }
            #[cfg(not(windows))]
            {
                // `expected_sandbox_status` above fails closed on every
                // platform without an implemented ProductionV3 launcher.
                spawn_contained(&mut command, Some(config.memory_limit_bytes))?
            }
        }
    } else {
        spawn_contained(&mut command, Some(config.memory_limit_bytes))?
    };
    let response =
        exchange_with_child(child, request, config.timeout, MAX_VERIFIER_RESPONSE_BYTES)?;
    require_matching_success(&response, binding, required_sandbox, containment_profile)?;

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
    required_sandbox: VerifierSandboxStatus,
    required_containment_profile: [u8; 32],
) -> Result<(), VerifierWorkerError> {
    let (sandbox_status, echoed_verifier, echoed_statement, echoed_containment) =
        match decode_response(response)? {
            VerifierResponse::Success {
                sandbox_status,
                verifier_identity,
                statement_identity,
                containment_profile,
            } => (
                sandbox_status,
                verifier_identity,
                statement_identity,
                containment_profile,
            ),
            VerifierResponse::Failure { code, message } if code == ERROR_PROOF_REJECTED => {
                return Err(VerifierWorkerError::ProofRejected(message));
            }
            VerifierResponse::Failure { code, message } => {
                return Err(VerifierWorkerError::WorkerReported { code, message });
            }
        };
    if sandbox_status != required_sandbox
        || echoed_verifier != binding.verifier_identity()
        || echoed_statement != binding.statement_identity()
        || echoed_containment != required_containment_profile
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
    output.extend_from_slice(&request.containment_profile);
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
    let containment_profile = cursor.read_array()?;
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
        containment_profile,
        block,
    })
}

fn encode_success_response(
    binding: ExternalPreverificationBinding,
    sandbox_status: VerifierSandboxStatus,
    containment_profile: [u8; 32],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(SUCCESS_RESPONSE_BYTES);
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    output.push(STATUS_SUCCESS);
    output.push(sandbox_status as u8);
    output.extend_from_slice(&binding.verifier_identity());
    output.extend_from_slice(&binding.statement_identity());
    output.extend_from_slice(&containment_profile);
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
            sandbox_status: VerifierSandboxStatus::from_wire(cursor.read_u8()?)
                .ok_or(VerifierProtocolError::InvalidStatus)?,
            verifier_identity: cursor.read_array()?,
            statement_identity: cursor.read_array()?,
            containment_profile: cursor.read_array()?,
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

fn run_verifier_worker() -> Result<
    (
        ExternalPreverificationBinding,
        VerifierSandboxStatus,
        [u8; 32],
    ),
    (u16, String),
> {
    let artifacts = parse_verifier_worker_arguments(std::env::args_os().skip(1))
        .map_err(|message| (ERROR_REQUEST, message.to_owned()))?;
    require_worker_environment(artifacts.is_some())?;
    let sandbox_status = install_worker_sandbox(artifacts.as_ref())?;
    let request_bytes = read_stdin_bounded()
        .map_err(|error| (ERROR_INTERNAL, format!("could not read request: {error}")))?;
    let request =
        decode_request(&request_bytes).map_err(|error| (ERROR_REQUEST, error.to_string()))?;
    let containment_profile = request.containment_profile;
    let block = decode_block(&request.block, request.network_id)
        .map_err(|error| (ERROR_REQUEST, error.to_string()))?;
    let canonical = encode_block(&block).map_err(|error| (ERROR_REQUEST, error.to_string()))?;
    if canonical != request.block {
        return Err((
            ERROR_REQUEST,
            "block request is not canonically encoded".to_owned(),
        ));
    }

    let verifier = load_worker_verifier(request.network_id, artifacts)?;
    verify_request_with_loaded_verifier(&verifier, request, block)
        .map(|binding| (binding, sandbox_status, containment_profile))
}

fn install_worker_sandbox(
    artifacts: Option<&WorkerProductionArtifacts>,
) -> Result<VerifierSandboxStatus, (u16, String)> {
    let Some(artifacts) = artifacts else {
        return Ok(VerifierSandboxStatus::Unconfined);
    };
    #[cfg(not(windows))]
    let paths = match artifacts {
        WorkerProductionArtifacts::Path(record) => [record.record_v2.as_path()],
    };
    #[cfg(windows)]
    let paths: [&Path; 0] = match artifacts {
        WorkerProductionArtifacts::Handle(_) => [],
    };
    install_production(&paths).map_err(|message| (ERROR_INTERNAL, message))
}

fn require_worker_environment(production_v3: bool) -> Result<(), (u16, String)> {
    #[cfg(windows)]
    if production_v3 {
        return crate::windows_launcher::validate_current_worker_environment()
            .map_err(|message| (ERROR_INTERNAL, message));
    }
    let _ = production_v3;
    if std::env::vars_os().next().is_some() {
        return Err((
            ERROR_INTERNAL,
            "verifier worker environment must be empty".to_owned(),
        ));
    }
    Ok(())
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
    artifacts: Option<WorkerProductionArtifacts>,
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
    if let Err((code, message)) = require_worker_environment(artifacts.is_some()) {
        return write_single_startup_error(code, &message);
    }
    let sandbox_status = match install_worker_sandbox(artifacts.as_ref()) {
        Ok(status) => status,
        Err((code, message)) => return write_single_startup_error(code, &message),
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
    if handshake.required_sandbox != sandbox_status {
        let _ = write_worker_frame(
            &mut output,
            &encode_startup_error(
                ERROR_UNSUPPORTED_VERIFIER,
                "worker sandbox does not match the required production isolation",
            ),
        );
        return 1;
    }
    let verifier = match load_worker_verifier(handshake.network_id, artifacts) {
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
    if write_worker_frame(
        &mut output,
        &encode_startup_success(&handshake, sandbox_status),
    )
    .is_err()
    {
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
            Ok(request)
                if request.network_id == handshake.network_id
                    && request.containment_profile == handshake.containment_profile =>
            {
                match decode_block(&request.block, request.network_id) {
                    Ok(block) => match encode_block(&block) {
                        Ok(canonical) if canonical == request.block => {
                            match verify_request_with_loaded_verifier(&verifier, request, block) {
                                Ok(binding) => encode_success_response(
                                    binding,
                                    sandbox_status,
                                    handshake.containment_profile,
                                ),
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
            Ok(_) => encode_error_response(
                ERROR_REQUEST,
                "request belongs to another network or containment profile",
            ),
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
) -> Result<Option<WorkerProductionArtifacts>, &'static str> {
    parse_verifier_artifact_arguments(VERIFY_MODE, arguments)
}

fn parse_persistent_verifier_worker_arguments(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Option<WorkerProductionArtifacts>, &'static str> {
    parse_verifier_artifact_arguments(PERSISTENT_VERIFY_MODE, arguments)
}

fn parse_verifier_artifact_arguments(
    mode: &'static str,
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Option<WorkerProductionArtifacts>, &'static str> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.len() == 1 && arguments[0].as_os_str() == OsStr::new(mode) {
        return Ok(None);
    }
    #[cfg(windows)]
    {
        if arguments.len() != 3
            || arguments[0].as_os_str() != OsStr::new(mode)
            || arguments[1].as_os_str()
                != OsStr::new(crate::windows_launcher::WINDOWS_ARTIFACT_HANDLES_ARGUMENT)
        {
            return Err(
                "expected the verifier mode alone or with exactly one inherited production V3 Record V2 handle",
            );
        }
        let argument = arguments[2]
            .to_str()
            .ok_or("production V3 Record V2 handle descriptor is not canonical ASCII")?;
        let descriptor =
            crate::windows_artifacts::WindowsArtifactHandleDescriptor::parse_transport_argument(
                argument,
            )
            .map_err(|_| "production V3 Record V2 handle descriptor is invalid")?;
        let handle =
            crate::windows_artifacts::OwnedWindowsProductionRecordHandle::from_inherited_descriptor(
                descriptor,
            )
            .map_err(|_| "production V3 Record V2 handle is invalid")?;
        Ok(Some(WorkerProductionArtifacts::Handle(handle)))
    }
    #[cfg(not(windows))]
    {
        if arguments.len() != 5
            || arguments[0].as_os_str() != OsStr::new(mode)
            || arguments[1].as_os_str() != OsStr::new(V3_RECORD_ARGUMENT)
            || arguments[3].as_os_str() != OsStr::new(V3_RECORD_IDENTITY_ARGUMENT)
        {
            return Err(
                "expected the verifier mode alone or with the exact production V3 Record V2 path and identity",
            );
        }
        let record = ProductionV3VerifierRecord {
            record_v2: PathBuf::from(&arguments[2]),
            expected_file: parse_record_identity(arguments[4].as_os_str())?,
        };
        record
            .validate()
            .map_err(|_| "production V3 verifier Record V2 is invalid")?;
        Ok(Some(WorkerProductionArtifacts::Path(record)))
    }
}

#[cfg(not(windows))]
fn parse_record_identity(value: &OsStr) -> Result<FileIdentity, &'static str> {
    let value = value
        .to_str()
        .ok_or("production V3 Record V2 identity is not canonical ASCII")?;
    let fields = value.split(':').collect::<Vec<_>>();
    if fields.len() != 3 || fields[1].len() != 64 || fields[2].len() != 64 {
        return Err("production V3 Record V2 identity is malformed");
    }
    let bytes = fields[0]
        .parse::<u64>()
        .map_err(|_| "production V3 Record V2 length is malformed")?;
    let mut blake3 = [0_u8; 32];
    let mut sha256 = [0_u8; 32];
    hex::decode_to_slice(fields[1], &mut blake3)
        .map_err(|_| "production V3 Record V2 BLAKE3 is malformed")?;
    hex::decode_to_slice(fields[2], &mut sha256)
        .map_err(|_| "production V3 Record V2 SHA-256 is malformed")?;
    let identity = FileIdentity {
        bytes,
        blake3,
        sha256,
    };
    let canonical = format!(
        "{}:{}:{}",
        identity.bytes,
        hex::encode(identity.blake3),
        hex::encode(identity.sha256)
    );
    if canonical != value {
        return Err("production V3 Record V2 identity is not canonical");
    }
    Ok(identity)
}

#[cfg(feature = "production-v3")]
fn load_production_v3_verifier(
    network_id: [u8; 32],
    artifacts: WorkerProductionArtifacts,
) -> Result<ConsensusPowVerifier, (u16, String)> {
    #[cfg(windows)]
    {
        let WorkerProductionArtifacts::Handle(handle) = artifacts;
        crate::windows_artifacts::load_production_v3_verifier_from_inherited_record_handle(
            network_id, handle,
        )
        .map_err(|_| {
            (
                ERROR_INTERNAL,
                "could not authenticate the inherited production V3 Record V2".to_owned(),
            )
        })
    }
    #[cfg(not(windows))]
    let WorkerProductionArtifacts::Path(record) = artifacts;
    #[cfg(not(windows))]
    cmfd_consensus::dory_v3_model_bank_record_validation::load_release_pinned_production_dory_v3_consensus_verifier(
        network_id,
        &record.record_v2,
        record.expected_file,
    )
    .map(|loaded| loaded.into_verifier())
    .map_err(|_| {
        (
            ERROR_INTERNAL,
            "could not authenticate the configured production V3 Record V2".to_owned(),
        )
    })
}

#[cfg(not(feature = "production-v3"))]
fn load_production_v3_verifier(
    _network_id: [u8; 32],
    _artifacts: WorkerProductionArtifacts,
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
        Ok((binding, sandbox_status, containment_profile)) => {
            encode_success_response(binding, sandbox_status, containment_profile)
        }
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
            containment_profile: [0x44; 32],
            block: canonical,
        };
        let encoded = encode_request(request).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(decoded.network_id, block.challenge.network_id);
        assert_eq!(decoded.verifier_identity, binding.verifier_identity());
        assert_eq!(decoded.statement_identity, binding.statement_identity());
        assert_eq!(decoded.containment_profile, [0x44; 32]);
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
    fn verifier_response_binds_identities_and_containment_and_rejects_malformed_streams() {
        let (verifier, block) = candidate_block();
        let binding = verifier
            .external_preverification_binding(&block.challenge, &block.proof)
            .unwrap();
        let containment_profile = [0x44; 32];
        let encoded = encode_success_response(
            binding,
            VerifierSandboxStatus::Unconfined,
            containment_profile,
        );
        assert_eq!(
            decode_response(&encoded).unwrap(),
            VerifierResponse::Success {
                sandbox_status: VerifierSandboxStatus::Unconfined,
                verifier_identity: binding.verifier_identity(),
                statement_identity: binding.statement_identity(),
                containment_profile,
            }
        );

        let mut substituted = encoded.clone();
        substituted[SUCCESS_RESPONSE_BYTES - 1] ^= 1;
        let VerifierResponse::Success {
            verifier_identity,
            statement_identity,
            containment_profile: substituted_containment,
            ..
        } = decode_response(&substituted).unwrap()
        else {
            unreachable!();
        };
        assert!(
            verifier_identity != binding.verifier_identity()
                || statement_identity != binding.statement_identity()
                || substituted_containment != containment_profile
        );
        assert!(matches!(
            require_matching_success(
                &substituted,
                binding,
                VerifierSandboxStatus::Unconfined,
                containment_profile,
            ),
            Err(VerifierWorkerError::ResponseMismatch)
        ));

        let mut wrong_sandbox = encoded.clone();
        wrong_sandbox[13] = VerifierSandboxStatus::LinuxLandlockSeccompV1 as u8;
        assert!(matches!(
            require_matching_success(
                &wrong_sandbox,
                binding,
                VerifierSandboxStatus::Unconfined,
                containment_profile,
            ),
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
    fn startup_handshake_authenticates_required_sandbox_status() {
        let handshake = StartupHandshake {
            profile: PROFILE_PRODUCTION_V3,
            required_sandbox: VerifierSandboxStatus::LinuxLandlockSeccompV1,
            network_id: [0x11; 32],
            verifier_identity: [0x22; 32],
            containment_profile: [0x44; 32],
            challenge: [0x33; 32],
        };
        assert_eq!(
            decode_startup_handshake(&encode_startup_handshake(StartupHandshake {
                profile: handshake.profile,
                required_sandbox: handshake.required_sandbox,
                network_id: handshake.network_id,
                verifier_identity: handshake.verifier_identity,
                containment_profile: handshake.containment_profile,
                challenge: handshake.challenge,
            }))
            .unwrap(),
            handshake
        );
        let success =
            encode_startup_success(&handshake, VerifierSandboxStatus::LinuxLandlockSeccompV1);
        assert_eq!(
            require_startup_success(
                &success,
                handshake.profile,
                handshake.required_sandbox,
                handshake.network_id,
                handshake.verifier_identity,
                handshake.containment_profile,
                handshake.challenge,
            )
            .unwrap(),
            VerifierSandboxStatus::LinuxLandlockSeccompV1
        );
        assert!(matches!(
            require_startup_success(
                &success,
                handshake.profile,
                VerifierSandboxStatus::WindowsAppContainerV1,
                handshake.network_id,
                handshake.verifier_identity,
                handshake.containment_profile,
                handshake.challenge,
            ),
            Err(VerifierWorkerError::Startup(_))
        ));
        assert!(matches!(
            require_startup_success(
                &success,
                handshake.profile,
                handshake.required_sandbox,
                handshake.network_id,
                handshake.verifier_identity,
                [0x45; 32],
                handshake.challenge,
            ),
            Err(VerifierWorkerError::Startup(_))
        ));
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
        assert!(
            parse_verifier_worker_arguments([std::ffi::OsString::from(VERIFY_MODE)])
                .unwrap()
                .is_none()
        );

        #[cfg(not(windows))]
        {
            let root = std::env::current_dir().unwrap();
            let record_v2 = root.join("model.record-v2.json");
            let expected_file = FileIdentity {
                bytes: 17,
                blake3: [0x12; 32],
                sha256: [0x34; 32],
            };
            let parsed = parse_verifier_worker_arguments([
                std::ffi::OsString::from(VERIFY_MODE),
                std::ffi::OsString::from(V3_RECORD_ARGUMENT),
                record_v2.clone().into_os_string(),
                std::ffi::OsString::from(V3_RECORD_IDENTITY_ARGUMENT),
                std::ffi::OsString::from(format!(
                    "{}:{}:{}",
                    expected_file.bytes,
                    hex::encode(expected_file.blake3),
                    hex::encode(expected_file.sha256)
                )),
            ])
            .unwrap()
            .unwrap();
            let WorkerProductionArtifacts::Path(parsed) = parsed;
            assert_eq!(
                parsed,
                ProductionV3VerifierRecord {
                    record_v2,
                    expected_file,
                }
            );

            assert!(
                parse_verifier_worker_arguments([
                    std::ffi::OsString::from(VERIFY_MODE),
                    std::ffi::OsString::from(V3_RECORD_ARGUMENT),
                ])
                .is_err()
            );
        }
        #[cfg(windows)]
        {
            assert!(
                parse_verifier_worker_arguments([
                    std::ffi::OsString::from(VERIFY_MODE),
                    std::ffi::OsString::from("--production-v3-bank"),
                    std::ffi::OsString::from(r"C:\forbidden-path-fallback.bank"),
                    std::ffi::OsString::from("--production-v3-manifest"),
                    std::ffi::OsString::from(r"C:\forbidden-path-fallback.manifest"),
                    std::ffi::OsString::from("--production-v3-record-v2"),
                    std::ffi::OsString::from(r"C:\forbidden-path-fallback.record"),
                ])
                .is_err(),
                "Windows ProductionV3 must not retain a pathname fallback"
            );
            assert!(
                parse_verifier_worker_arguments([
                    std::ffi::OsString::from(VERIFY_MODE),
                    std::ffi::OsString::from(
                        crate::windows_launcher::WINDOWS_ARTIFACT_HANDLES_ARGUMENT,
                    ),
                    std::ffi::OsString::from("invalid"),
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn verifier_config_requires_absolute_path_and_nonzero_limits() {
        let mut config = VerifierWorkerConfig {
            worker_executable: PathBuf::from("worker"),
            worker_sha256: [0; 32],
            startup_timeout: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            memory_limit_bytes: 1,
            cpu_quota_micros: None,
            cpu_period_micros: None,
            pids_limit: None,
            production_v3_record: None,
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
        config.cpu_quota_micros = Some(100_000);
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
        config.cpu_quota_micros = None;
        config.production_v3_record = Some(ProductionV3VerifierRecord {
            record_v2: PathBuf::from("relative-record"),
            expected_file: FileIdentity {
                bytes: 1,
                blake3: [1; 32],
                sha256: [2; 32],
            },
        });
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(_))
        ));
    }

    #[test]
    fn containment_profile_digest_commits_every_resource_limit() {
        let worker = std::env::current_exe().unwrap();
        let base = VerifierWorkerConfig {
            worker_executable: worker,
            worker_sha256: [0; 32],
            startup_timeout: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            memory_limit_bytes: 1_000_000,
            cpu_quota_micros: Some(25_000),
            cpu_period_micros: Some(100_000),
            pids_limit: Some(8),
            production_v3_record: None,
        };
        let digest = base.containment_profile_digest(VerifierSandboxStatus::Unconfined);
        for changed in [
            VerifierWorkerConfig {
                memory_limit_bytes: base.memory_limit_bytes + 1,
                ..base.clone()
            },
            VerifierWorkerConfig {
                cpu_quota_micros: Some(25_001),
                ..base.clone()
            },
            VerifierWorkerConfig {
                cpu_period_micros: Some(100_001),
                ..base.clone()
            },
            VerifierWorkerConfig {
                pids_limit: Some(9),
                ..base.clone()
            },
        ] {
            assert_ne!(
                digest,
                changed.containment_profile_digest(VerifierSandboxStatus::Unconfined)
            );
        }
        assert_ne!(
            digest,
            base.containment_profile_digest(VerifierSandboxStatus::LinuxLandlockSeccompV1)
        );
        let production = VerifierWorkerConfig {
            production_v3_record: Some(ProductionV3VerifierRecord {
                record_v2: std::env::temp_dir().join("containment-profile-record"),
                expected_file: FileIdentity {
                    bytes: 1,
                    blake3: [3; 32],
                    sha256: [4; 32],
                },
            }),
            ..base.clone()
        };
        assert_ne!(
            digest,
            production.containment_profile_digest(VerifierSandboxStatus::Unconfined)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_production_config_requires_explicit_measured_cgroup_limits() {
        let root = std::env::temp_dir().join("cmfd-explicit-cgroup-limits");
        let config = VerifierWorkerConfig {
            worker_executable: std::env::current_exe().unwrap(),
            worker_sha256: [0; 32],
            startup_timeout: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            memory_limit_bytes: 1024,
            cpu_quota_micros: None,
            cpu_period_micros: None,
            pids_limit: None,
            production_v3_record: Some(ProductionV3VerifierRecord {
                record_v2: root.join("record"),
                expected_file: FileIdentity {
                    bytes: 1,
                    blake3: [5; 32],
                    sha256: [6; 32],
                },
            }),
        };
        assert!(matches!(
            config.validate(),
            Err(VerifierWorkerError::InvalidConfig(
                "Linux ProductionV3 requires measured CPU quota, CPU period, and PID limit"
            ))
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

    #[cfg(windows)]
    #[test]
    fn private_copy_cleanup_never_deletes_a_path_replacement_after_releasing_identity() {
        let _ledger = crate::process::isolated_appcontainer_ledger_test();
        let sequence = PRIVATE_COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cmfd-verifier-copy-replacement-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("source.exe");
        fs::write(&source, b"identity-bound outer runtime").unwrap();
        let expected = <[u8; 32]>::from(Sha256::digest(b"identity-bound outer runtime"));
        let mut runtime = PrivateRuntimeCopy::create(&source, expected).unwrap();
        let directory = runtime.directory.clone();
        let executable = runtime.executable.clone();

        let moved_directory = root.join("moved-runtime");
        assert!(fs::rename(&directory, &moved_directory).is_err());
        let replacement_candidate = root.join("replacement.exe");
        fs::write(&replacement_candidate, b"replacement candidate").unwrap();
        assert!(fs::rename(&replacement_candidate, &executable).is_err());

        let mut cleanup = runtime
            .cleanup
            .take()
            .expect("Windows private copy owns exact cleanup handles");
        let error = cleanup
            .cleanup_with_hook(|| fs::write(&executable, b"replacement after disposition"))
            .unwrap_err();
        assert!(
            error.kind() == io::ErrorKind::DirectoryNotEmpty || error.raw_os_error().is_some(),
            "unexpected retained-directory cleanup failure: {error}"
        );
        assert_eq!(
            fs::read(&executable).unwrap(),
            b"replacement after disposition"
        );
        cleanup.release_without_deletion_for_test();
        drop(cleanup);
        drop(runtime);
        assert_eq!(
            fs::read(&executable).unwrap(),
            b"replacement after disposition",
            "cleanup deleted a replacement reachable only through the released pathname"
        );

        fs::remove_file(executable).unwrap();
        fs::remove_dir(directory).unwrap();
        fs::remove_file(replacement_candidate).unwrap();
        fs::remove_file(source).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn private_copy_cleanup_retries_native_directory_busy_errors_without_reopening_path() {
        let sequence = PRIVATE_COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cmfd-verifier-copy-retry-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("source.exe");
        fs::write(&source, b"identity-bound outer runtime retry").unwrap();
        let expected = <[u8; 32]>::from(Sha256::digest(b"identity-bound outer runtime retry"));
        let mut runtime = PrivateRuntimeCopy::create(&source, expected).unwrap();
        let directory = runtime.directory.clone();
        let transient = directory.join("transient-loader-pin");
        fs::write(&transient, b"temporary").unwrap();
        let remover = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            fs::remove_file(transient).unwrap();
        });

        runtime
            .cleanup
            .as_mut()
            .expect("Windows private copy owns exact cleanup handles")
            .cleanup()
            .unwrap();
        remover.join().unwrap();
        assert!(!runtime.executable.exists());
        assert!(!directory.exists());

        drop(runtime);
        fs::remove_file(source).unwrap();
        fs::remove_dir(root).unwrap();
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
    fn dispatched_request_errors_preserve_the_startup_request_phase_boundary() {
        let request_timeout = wrap_exchange_error(
            PersistentExchangePhase::Request,
            VerifierWorkerError::Process(ProofWorkerError::Timeout { milliseconds: 1 }),
        );
        assert!(matches!(
            request_timeout,
            VerifierWorkerError::DispatchedRequest(error)
                if matches!(*error, VerifierWorkerError::Process(ProofWorkerError::Timeout { .. }))
        ));

        let request_stderr = wrap_exchange_error(
            PersistentExchangePhase::Request,
            VerifierWorkerError::Process(ProofWorkerError::StderrTooLarge),
        );
        assert!(matches!(
            request_stderr,
            VerifierWorkerError::DispatchedRequest(error)
                if matches!(*error, VerifierWorkerError::Process(ProofWorkerError::StderrTooLarge))
        ));

        let startup_timeout = wrap_exchange_error(
            PersistentExchangePhase::Startup,
            VerifierWorkerError::Process(ProofWorkerError::Timeout { milliseconds: 1 }),
        );
        assert!(matches!(
            startup_timeout,
            VerifierWorkerError::Process(ProofWorkerError::Timeout { .. })
        ));
        let request_config = wrap_exchange_error(
            PersistentExchangePhase::Request,
            VerifierWorkerError::Process(ProofWorkerError::InvalidConfig("test")),
        );
        assert!(matches!(
            request_config,
            VerifierWorkerError::Process(ProofWorkerError::InvalidConfig("test"))
        ));

        for failure in [
            VerifierWorkerError::Protocol(VerifierProtocolError::InvalidStatus),
            VerifierWorkerError::WorkerReported {
                code: 9,
                message: "request failed".to_owned(),
            },
            VerifierWorkerError::ResponseMismatch,
        ] {
            assert!(matches!(
                wrap_dispatched_request_error(failure),
                VerifierWorkerError::DispatchedRequest(_)
            ));
        }
        assert!(matches!(
            wrap_dispatched_request_error(VerifierWorkerError::ProofRejected(
                "invalid proof".to_owned()
            )),
            VerifierWorkerError::ProofRejected(_)
        ));

        let original = VerifierWorkerError::DispatchedRequest(Box::new(
            VerifierWorkerError::Process(ProofWorkerError::Timeout { milliseconds: 7 }),
        ));
        let preserved =
            preserve_request_error(original, Err(io::Error::other("injected teardown failure")));
        assert!(preserved.is_dispatched_proof_failure());
        assert!(matches!(
            preserved,
            VerifierWorkerError::CleanupAfterFailure { worker, source }
                if matches!(
                    worker.as_ref(),
                    VerifierWorkerError::DispatchedRequest(error)
                        if matches!(
                            error.as_ref(),
                            VerifierWorkerError::Process(ProofWorkerError::Timeout {
                                milliseconds: 7
                            })
                        )
                )
                    && source.to_string().contains("injected teardown failure")
        ));
    }

    #[test]
    fn persistent_teardown_child_helper() {
        if std::env::var_os("CMFD_PERSISTENT_TEARDOWN_CHILD").is_some() {
            thread::sleep(Duration::from_secs(5));
        }
    }

    #[test]
    fn persistent_exited_worker_rejects_even_a_buffered_success_response() {
        let (verifier, block) = candidate_block();
        let binding = verifier
            .external_preverification_binding(&block.challenge, &block.proof)
            .unwrap();
        let response = encode_success_response(binding, VerifierSandboxStatus::Unconfined, [0; 32]);
        let mut frame = Vec::new();
        write_frame(&mut frame, &response).unwrap();

        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "tests::child_fast_exit_helper"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = spawn_contained(&mut command, None).unwrap();
        let transport_poisoned = Arc::new(AtomicBool::new(false));
        let teardown_failures = Arc::new(AtomicU64::new(0));
        let mut process = PersistentVerifierProcess::new(
            child,
            1,
            Arc::clone(&transport_poisoned),
            Arc::clone(&teardown_failures),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = process.child.try_wait().unwrap() {
                assert!(status.success(), "exit fixture failed: {status}");
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "exit fixture did not finish"
            );
            thread::sleep(Duration::from_millis(1));
        }

        // Make the response available only after authoritative exit, without
        // relying on thread scheduling or sleeps to choose the race winner.
        process.stdin = Some(Box::new(io::sink()));
        process.stdout = Some(Box::new(io::Cursor::new(frame)));
        let error = process
            .exchange(
                Vec::new(),
                Duration::from_secs(10),
                MAX_VERIFIER_RESPONSE_BYTES,
                PersistentExchangePhase::Request,
            )
            .expect_err("an exited worker must not issue a proof capability");
        assert!(
            matches!(
                &error,
                VerifierWorkerError::DispatchedRequest(source)
                    if matches!(source.as_ref(), VerifierWorkerError::Process(
                        ProofWorkerError::WorkerExited { code: Some(0), .. }
                    ))
            ),
            "unexpected exited-worker failure: {error:?}"
        );
        assert!(error.is_dispatched_proof_failure());
        assert!(!transport_poisoned.load(Ordering::Acquire));
        assert_eq!(teardown_failures.load(Ordering::Acquire), 0);
    }

    fn forced_cleanup_persistent_process() -> (PersistentVerifierProcess, Arc<AtomicBool>) {
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
        child.force_termination_failures(1);
        let transport_poisoned = Arc::new(AtomicBool::new(false));
        let process = PersistentVerifierProcess::new(
            child,
            1,
            Arc::clone(&transport_poisoned),
            Arc::new(AtomicU64::new(0)),
        )
        .unwrap();
        (process, transport_poisoned)
    }

    fn assert_persistent_cleanup_wrap(
        error: VerifierWorkerError,
        primary: impl FnOnce(&VerifierWorkerError) -> bool,
    ) {
        let VerifierWorkerError::CleanupAfterFailure { worker, source } = error else {
            panic!("cleanup failure was not composed with the primary error: {error}");
        };
        assert!(primary(&worker), "wrong primary error: {worker}");
        assert!(
            source
                .to_string()
                .contains("forced contained-process cleanup failure"),
            "wrong cleanup error: {source}"
        );
    }

    #[test]
    fn persistent_timeout_composes_forced_cleanup_and_poisons_transport() {
        let (mut process, transport_poisoned) = forced_cleanup_persistent_process();
        process.stdin = Some(Box::new(io::sink()));
        process.stdout = Some(Box::new(SlowReader));
        let error = process
            .exchange(
                Vec::new(),
                Duration::from_millis(10),
                1024,
                PersistentExchangePhase::Request,
            )
            .unwrap_err();
        assert_persistent_cleanup_wrap(error, |worker| {
            matches!(
                worker,
                VerifierWorkerError::DispatchedRequest(source)
                    if matches!(
                        source.as_ref(),
                        VerifierWorkerError::Process(ProofWorkerError::Timeout { .. })
                    )
            )
        });
        assert!(transport_poisoned.load(Ordering::Acquire));
    }

    #[test]
    fn persistent_missing_pipe_composes_forced_cleanup_and_poisons_transport() {
        let (mut process, transport_poisoned) = forced_cleanup_persistent_process();
        process.stdout.take();
        let error = process
            .exchange(
                Vec::new(),
                Duration::from_secs(1),
                1024,
                PersistentExchangePhase::Request,
            )
            .unwrap_err();
        assert_persistent_cleanup_wrap(error, |worker| {
            matches!(
                worker,
                VerifierWorkerError::Process(ProofWorkerError::InvalidConfig(message))
                    if *message == "persistent worker stdout pipe is unavailable"
            )
        });
        assert!(transport_poisoned.load(Ordering::Acquire));
    }

    #[test]
    fn persistent_protocol_failure_composes_forced_generation_cleanup() {
        let (mut process, transport_poisoned) = forced_cleanup_persistent_process();
        let error = process.preserve_error_after_teardown(VerifierWorkerError::DispatchedRequest(
            Box::new(VerifierWorkerError::Protocol(
                VerifierProtocolError::InvalidStatus,
            )),
        ));
        assert!(error.is_dispatched_proof_failure());
        assert_persistent_cleanup_wrap(error, |worker| {
            matches!(
                worker,
                VerifierWorkerError::DispatchedRequest(source)
                    if matches!(
                        source.as_ref(),
                        VerifierWorkerError::Protocol(VerifierProtocolError::InvalidStatus)
                    )
            )
        });
        assert!(transport_poisoned.load(Ordering::Acquire));
        assert_eq!(process.teardown_failures.load(Ordering::Acquire), 1);
    }

    #[test]
    fn persistent_constructor_missing_pipe_composes_forced_cleanup() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("verifier::tests::persistent_teardown_child_helper")
            .arg("--nocapture")
            .env("CMFD_PERSISTENT_TEARDOWN_CHILD", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = spawn_contained(&mut command, None).unwrap();
        child.force_termination_failures(1);
        let transport_poisoned = Arc::new(AtomicBool::new(false));
        let error = PersistentVerifierProcess::new(
            child,
            1,
            Arc::clone(&transport_poisoned),
            Arc::new(AtomicU64::new(0)),
        )
        .err()
        .expect("missing pipe must fail construction");
        assert_persistent_cleanup_wrap(error, |worker| {
            matches!(
                worker,
                VerifierWorkerError::Process(ProofWorkerError::InvalidConfig(message))
                    if *message == "worker stdin pipe was not created"
            )
        });
        assert!(transport_poisoned.load(Ordering::Acquire));
    }

    struct PanickingWriter;

    struct SlowReader;

    impl Read for SlowReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            thread::sleep(Duration::from_millis(100));
            Ok(0)
        }
    }

    impl Write for PanickingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            panic!("forced persistent I/O-thread disconnect");
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn persistent_disconnect_composes_forced_cleanup_and_poisons_transport() {
        let (mut process, transport_poisoned) = forced_cleanup_persistent_process();
        process.stdin = Some(Box::new(PanickingWriter));
        let error = process
            .exchange(
                Vec::new(),
                Duration::from_secs(1),
                1024,
                PersistentExchangePhase::Request,
            )
            .unwrap_err();
        assert_persistent_cleanup_wrap(error, |worker| {
            matches!(
                worker,
                VerifierWorkerError::DispatchedRequest(source)
                    if matches!(
                        source.as_ref(),
                        VerifierWorkerError::Process(ProofWorkerError::PipeThread(
                            "exchanging persistent verifier frames"
                        ))
                    )
            )
        });
        assert!(transport_poisoned.load(Ordering::Acquire));
    }

    #[test]
    fn shutdown_termination_failure_poisons_transport() {
        let (mut process, transport_poisoned) = forced_cleanup_persistent_process();
        let terminator = process.child.termination_handle();
        terminate_for_shutdown(&terminator, &transport_poisoned, &process.teardown_failures);
        assert!(transport_poisoned.load(Ordering::Acquire));
        process.child.terminate_and_reap().unwrap();
    }

    #[test]
    fn persistent_drop_termination_failure_poisons_transport() {
        let (process, transport_poisoned) = forced_cleanup_persistent_process();
        drop(process);
        assert!(transport_poisoned.load(Ordering::Acquire));
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
        let teardown_failures = Arc::new(AtomicU64::new(0));
        let mut process = PersistentVerifierProcess::new(
            child,
            1,
            Arc::clone(&transport_poisoned),
            Arc::clone(&teardown_failures),
        )
        .unwrap();

        // Replace the real stderr reader with a deliberately stuck handle.
        // Reap and join the real reader first so this test does not itself
        // create an untracked pipe thread.
        process
            .child
            .terminate_and_reap()
            .expect("terminate persistent teardown test child");
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
        assert_eq!(teardown_failures.load(Ordering::Acquire), 1);
    }
}
