//! Small, authenticated Devnet-0 pool protocol.
//!
//! This is deliberately not Stratum. The server sends an immutable
//! [`BlockChallenge`] and a separate, easier share target. A worker submits
//! only the server-issued job identifier and a nonce; the server recomputes
//! the exact ForgeMatrix evaluation before crediting anything.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cmfd_consensus::forgematrix::target_with_leading_zero_bits;
use cmfd_consensus::{
    BlockChallenge, ConsensusPowVerifier, ForgeMatrixV2AcceleratorBatch,
    ForgeMatrixV2AcceleratorModel, ForgeMatrixV2Error, PowError, v2_reference_for_network,
};
use k256::schnorr::VerifyingKey;
use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection,
    SignatureScheme, StreamOwned,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    COMPILED_NETWORK_PROFILE, MAX_MINING_SEARCH_ATTEMPTS, MiningJob, NetworkProfile, Node,
    NodeError, ProofProfile, devnet_params, submit_shared_tip_block, unix_time_seconds,
};

pub const POOL_PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_POOL_ADDRESS: SocketAddr = COMPILED_NETWORK_PROFILE.pool_address();
pub const DEFAULT_POOL_SOCKET_ADDRESS: SocketAddr = DEFAULT_POOL_ADDRESS;
pub const DEFAULT_SHARE_LEADING_ZERO_BITS: u16 = 7;
pub const DEFAULT_TEST_CREDIT_ATOMS_PER_SHARE: u64 = 1;
pub const POOL_MAX_FRAME_BYTES: usize = 16 * 1024;
pub const POOL_MAX_WORKER_BYTES: usize = 32;
pub const POOL_MAX_CONNECTIONS: usize = 64;
pub const POOL_MAX_MESSAGES_PER_SESSION: u64 = 1_000_000;
pub const POOL_MAX_SHARES_PER_JOB: usize = 65_536;
pub const POOL_MAX_LEDGER_SESSIONS: usize = 1_024;
pub const POOL_MAX_LEDGER_PAYOUTS: usize = 1_024;
pub const POOL_ACCOUNTING_SEMANTICS: &str = "session-only accounting records; nonwithdrawable; not funds; not an on-chain balance or payout";

const POOL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const POOL_READ_TIMEOUT: Duration = Duration::from_millis(200);
const POOL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const POOL_ACCEPT_POLL: Duration = Duration::from_millis(25);
const POOL_JOB_DOMAIN: &str = "CMFD/DEVNET-POOL/JOB/V1";
const POOL_NONCE_ORIGIN_DOMAIN: &str = "CMFD/DEVNET-POOL/NONCE-ORIGIN/V1";

#[derive(Debug, Error)]
pub enum PoolError {
    #[error(
        "Production V3 pool shares are not implemented; RCNet pool service is disabled rather than accepting V2 shares"
    )]
    ProductionV3Unsupported,
    #[error("pool address must be a numeric private or loopback address, received {0}")]
    PublicAddress(SocketAddr),
    #[error("pool worker name must match [A-Za-z0-9._-]{{1,{POOL_MAX_WORKER_BYTES}}}")]
    InvalidWorker,
    #[error("pool connection limit must be between 1 and {POOL_MAX_CONNECTIONS}")]
    InvalidConnectionLimit,
    #[error("pool message count exceeds {POOL_MAX_MESSAGES_PER_SESSION}")]
    MessageCountLimit,
    #[error("pool frame length must be between 1 and {POOL_MAX_FRAME_BYTES} bytes")]
    FrameLimit,
    #[error("pool protocol message is not valid: {0}")]
    InvalidMessage(String),
    #[error("pool protocol version mismatch")]
    ProtocolMismatch,
    #[error("pool network identifier mismatch")]
    NetworkMismatch,
    #[error("pool consensus fingerprint mismatch")]
    FingerprintMismatch,
    #[error("pool certificate SHA-256 pin mismatch")]
    CertificatePinMismatch,
    #[error("pool certificate and private key paths must differ")]
    CertificatePathCollision,
    #[error("pool certificate output already exists: {0:?}")]
    CertificateExists(PathBuf),
    #[error("pool TLS error: {0}")]
    Tls(String),
    #[error("pool connection closed")]
    ConnectionClosed,
    #[error("pool server thread panicked")]
    ThreadPanicked,
    #[error("pool shared state is poisoned")]
    SharedStatePoisoned,
    #[error("pool deadline exceeds the platform monotonic clock range")]
    DeadlineOverflow,
    #[error("pool bounded session ledger has no inactive record available to prune")]
    LedgerCapacity,
    #[error("operating-system random number generation failed: {0}")]
    Random(String),
    #[error("pool I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("pool JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Node(#[from] NodeError),
    #[error("pool proof evaluation failed: {0}")]
    Pow(#[from] PowError),
    #[error("pool certificate generation failed: {0}")]
    Certificate(#[from] rcgen::Error),
}

#[derive(Debug, Clone)]
pub struct PoolCertificateInfo {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub certificate_sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct PoolServerConfig {
    pub bind: SocketAddr,
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub block_destination: [u8; 32],
    pub share_target: [u8; 32],
    pub test_credit_atoms_per_share: u64,
    pub max_connections: usize,
}

impl PoolServerConfig {
    pub fn devnet(
        bind: SocketAddr,
        certificate_der: Vec<u8>,
        private_key_der: Vec<u8>,
        block_destination: [u8; 32],
    ) -> Self {
        Self {
            bind,
            certificate_der,
            private_key_der,
            block_destination,
            share_target: target_with_leading_zero_bits(DEFAULT_SHARE_LEADING_ZERO_BITS),
            test_credit_atoms_per_share: DEFAULT_TEST_CREDIT_ATOMS_PER_SHARE,
            max_connections: POOL_MAX_CONNECTIONS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolClientConfig {
    pub address: SocketAddr,
    pub certificate_sha256: [u8; 32],
    pub worker: String,
    pub payout: [u8; 32],
    pub expected_network_id: [u8; 32],
    pub expected_consensus_fingerprint: [u8; 32],
}

impl PoolClientConfig {
    pub fn devnet(
        address: SocketAddr,
        certificate_sha256: [u8; 32],
        worker: impl Into<String>,
        payout: [u8; 32],
    ) -> Result<Self, PoolError> {
        let params = devnet_params()?;
        Ok(Self {
            address,
            certificate_sha256,
            worker: worker.into(),
            payout,
            expected_network_id: params.network_id,
            expected_consensus_fingerprint: params.fingerprint().map_err(NodeError::from)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolJob {
    pub job_id: [u8; 32],
    pub challenge: BlockChallenge,
    pub share_target: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolSessionStats {
    pub session_id: u64,
    pub connected: bool,
    pub worker: String,
    pub payout: String,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub pool_blocks: u64,
    pub credited_devnet_atoms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolPayoutStats {
    pub payout: String,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub pool_blocks: u64,
    pub credited_devnet_atoms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolLedgerSnapshot {
    pub accounting_semantics: String,
    pub persistence: String,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub pool_blocks: u64,
    pub credited_devnet_atoms: u64,
    pub sessions: Vec<PoolSessionStats>,
    pub payouts: Vec<PoolPayoutStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolShareResult {
    pub job_id: [u8; 32],
    pub nonce: u64,
    pub accepted: bool,
    pub block_accepted: bool,
    pub code: String,
    pub session: PoolSessionStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolClientEvent {
    Job(PoolJob),
    ShareResult(PoolShareResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolWorkSearchResult {
    Found {
        nonce: u64,
        work_digest: [u8; 32],
        meets_chain_target: bool,
        attempts_completed: u64,
        next_nonce: u64,
    },
    Exhausted {
        attempts_completed: u64,
        next_nonce: u64,
    },
    Cancelled {
        attempts_completed: u64,
        next_nonce: u64,
    },
}

#[derive(Clone)]
pub struct PoolMiningWork {
    job: PoolJob,
    verifier: ConsensusPowVerifier,
}

impl fmt::Debug for PoolMiningWork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PoolMiningWork")
            .field("job", &self.job)
            .finish()
    }
}

impl PoolMiningWork {
    pub fn from_job(job: PoolJob) -> Result<Self, PoolError> {
        let params = devnet_params()?;
        if job.challenge.network_id != params.network_id {
            return Err(PoolError::NetworkMismatch);
        }
        if job.share_target < job.challenge.target {
            return Err(PoolError::InvalidMessage(
                "share target is harder than the immutable chain target".to_owned(),
            ));
        }
        let reference = v2_reference_for_network(params.network_id).map_err(PowError::from)?;
        Ok(Self {
            job,
            verifier: ConsensusPowVerifier::v2_reference(reference),
        })
    }

    pub fn job(&self) -> &PoolJob {
        &self.job
    }

    pub fn accelerator_model(&self) -> Result<ForgeMatrixV2AcceleratorModel, PoolError> {
        Ok(self.verifier.v2_accelerator_model()?)
    }

    pub fn prepare_accelerator_batch(
        &self,
        start_nonce: u64,
        count: u32,
    ) -> Result<ForgeMatrixV2AcceleratorBatch, PoolError> {
        Ok(self
            .verifier
            .prepare_v2_accelerator_batch(&self.job.challenge, start_nonce, count)?)
    }

    pub fn verify_accelerator_output(
        &self,
        batch: &ForgeMatrixV2AcceleratorBatch,
        index: usize,
        output: &[u8],
    ) -> Result<[u8; 32], PoolError> {
        self.verifier
            .validate_v2_accelerator_batch(&self.job.challenge, batch)?;
        let work_digest = batch
            .candidate_work_digest(index, output)
            .map_err(PowError::from)?;
        self.verifier.verify_v2_accelerator_candidate(
            &self.job.challenge,
            batch,
            index,
            work_digest,
        )?;
        Ok(work_digest)
    }

    /// Scans untrusted accelerator outputs and fully recomputes any claimed
    /// share before returning it to the pool client.
    pub fn complete_accelerator_batch(
        &self,
        batch: &ForgeMatrixV2AcceleratorBatch,
        outputs: &[u8],
    ) -> Result<PoolWorkSearchResult, PoolError> {
        self.verifier
            .validate_v2_accelerator_batch(&self.job.challenge, batch)?;
        let expected_len = batch
            .count()
            .checked_mul(batch.activation_len() as u32)
            .map(|length| length as usize)
            .ok_or(PowError::V2(ForgeMatrixV2Error::AcceleratorOutputShape))?;
        if outputs.len() != expected_len {
            return Err(PoolError::Pow(PowError::V2(
                ForgeMatrixV2Error::AcceleratorOutputShape,
            )));
        }

        for (index, output) in outputs.chunks_exact(batch.activation_len()).enumerate() {
            let work_digest = batch
                .candidate_work_digest(index, output)
                .map_err(PowError::from)?;
            if work_digest <= self.job.share_target {
                self.verifier.verify_v2_accelerator_candidate(
                    &self.job.challenge,
                    batch,
                    index,
                    work_digest,
                )?;
                let nonce = batch
                    .nonce_at(index)
                    .ok_or(PowError::V2(ForgeMatrixV2Error::AcceleratorOutputShape))?;
                return Ok(PoolWorkSearchResult::Found {
                    nonce,
                    work_digest,
                    meets_chain_target: work_digest <= self.job.challenge.target,
                    attempts_completed: index as u64 + 1,
                    next_nonce: nonce.wrapping_add(1),
                });
            }
        }

        Ok(PoolWorkSearchResult::Exhausted {
            attempts_completed: batch.count().into(),
            next_nonce: batch.start_nonce().wrapping_add(u64::from(batch.count())),
        })
    }

    pub fn search_range<F>(
        &self,
        start_nonce: u64,
        attempts: u64,
        mut should_cancel: F,
    ) -> Result<PoolWorkSearchResult, PoolError>
    where
        F: FnMut() -> bool,
    {
        if attempts == 0 || attempts > MAX_MINING_SEARCH_ATTEMPTS {
            return Err(PoolError::Node(NodeError::InvalidMiningSearchAttempts));
        }
        let mut attempts_completed = 0_u64;
        while attempts_completed < attempts {
            let nonce = start_nonce.wrapping_add(attempts_completed);
            if should_cancel() {
                return Ok(PoolWorkSearchResult::Cancelled {
                    attempts_completed,
                    next_nonce: nonce,
                });
            }
            let proof = self.verifier.evaluate(&self.job.challenge, nonce)?;
            let work_digest = proof.work_digest();
            attempts_completed += 1;
            if work_digest <= self.job.share_target {
                return Ok(PoolWorkSearchResult::Found {
                    nonce,
                    work_digest,
                    meets_chain_target: work_digest <= self.job.challenge.target,
                    attempts_completed,
                    next_nonce: nonce.wrapping_add(1),
                });
            }
        }
        Ok(PoolWorkSearchResult::Exhausted {
            attempts_completed,
            next_nonce: start_nonce.wrapping_add(attempts_completed),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientMessage {
    Hello {
        protocol_version: u16,
        network_id: [u8; 32],
        consensus_fingerprint: [u8; 32],
        worker: String,
        payout: [u8; 32],
    },
    SubmitShare {
        job_id: [u8; 32],
        nonce: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ServerMessage {
    HelloAck {
        protocol_version: u16,
        network_id: [u8; 32],
        consensus_fingerprint: [u8; 32],
        session_id: u64,
        accounting_semantics: String,
        persistence: String,
    },
    Job {
        job: PoolJob,
    },
    ShareResult {
        result: PoolShareResult,
    },
    Error {
        code: String,
        message: String,
    },
}

struct ActiveJob {
    wire: PoolJob,
    mining: MiningJob,
    seen_nonces: Mutex<HashSet<u64>>,
}

struct ServerState {
    current: Arc<ActiveJob>,
    next_job_sequence: u64,
}

#[derive(Default)]
struct Ledger {
    accepted_shares: u64,
    rejected_shares: u64,
    pool_blocks: u64,
    credited_devnet_atoms: u64,
    sessions: BTreeMap<u64, SessionRecord>,
    payouts: BTreeMap<[u8; 32], PayoutRecord>,
}

struct SessionRecord {
    connected: bool,
    worker: String,
    payout: [u8; 32],
    accepted_shares: u64,
    rejected_shares: u64,
    pool_blocks: u64,
    credited_devnet_atoms: u64,
}

#[derive(Default)]
struct PayoutRecord {
    accepted_shares: u64,
    rejected_shares: u64,
    pool_blocks: u64,
    credited_devnet_atoms: u64,
    last_session_id: u64,
}

struct SharedServer {
    node: Arc<Mutex<Node>>,
    state: Mutex<ServerState>,
    ledger: Mutex<Ledger>,
    stop: AtomicBool,
    active_connections: AtomicUsize,
    active_sockets: Mutex<HashMap<u64, TcpStream>>,
    next_connection_id: AtomicU64,
    next_session_id: AtomicU64,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    block_destination: [u8; 32],
    configured_share_target: [u8; 32],
    test_credit_atoms_per_share: u64,
    max_connections: usize,
    tls: Arc<ServerConfig>,
    startup_nonce: [u8; 32],
}

pub struct PoolServerHandle {
    address: SocketAddr,
    shared: Arc<SharedServer>,
    thread: Option<JoinHandle<Result<(), PoolError>>>,
}

impl PoolServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(JoinHandle::is_finished)
    }

    pub fn ledger_snapshot(&self) -> Result<PoolLedgerSnapshot, PoolError> {
        snapshot_ledger(&self.shared.ledger)
    }

    pub fn current_job(&self) -> Result<PoolJob, PoolError> {
        Ok(self
            .shared
            .state
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?
            .current
            .wire
            .clone())
    }

    pub fn stop(mut self) -> Result<(), PoolError> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), PoolError> {
        self.shared.stop.store(true, Ordering::Release);
        let socket_result = shutdown_active_connections(&self.shared);
        let thread_result = match self.thread.take() {
            Some(thread) => thread.join().map_err(|_| PoolError::ThreadPanicked)?,
            None => Ok(()),
        };
        socket_result?;
        thread_result
    }
}

impl Drop for PoolServerHandle {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

pub fn spawn_pool_server(
    node: Arc<Mutex<Node>>,
    config: PoolServerConfig,
) -> Result<PoolServerHandle, PoolError> {
    let profile = node
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?
        .network_profile();
    ensure_pool_profile_supported(profile)?;
    validate_private_address(config.bind)?;
    if config.max_connections == 0 || config.max_connections > POOL_MAX_CONNECTIONS {
        return Err(PoolError::InvalidConnectionLimit);
    }
    VerifyingKey::from_bytes(&config.block_destination)
        .map_err(|_| PoolError::Node(NodeError::InvalidMinerDestination))?;
    let tls = Arc::new(server_tls_config(
        config.certificate_der,
        config.private_key_der,
    )?);
    let listener = TcpListener::bind(config.bind)?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    let (network_id, consensus_fingerprint, mining) = {
        let node = node.lock().map_err(|_| PoolError::SharedStatePoisoned)?;
        let status = node.status()?;
        (
            node.params.network_id,
            decode_hex_32(&status.consensus_fingerprint)?,
            node.build_mining_job(config.block_destination, unix_time_seconds()?)?,
        )
    };
    let startup_nonce = random_nonce()?;
    let first_job_nonce = random_nonce()?;
    let share_target = easier_target(config.share_target, mining.challenge().target);
    let first = Arc::new(ActiveJob {
        wire: PoolJob {
            job_id: make_job_id(
                startup_nonce,
                first_job_nonce,
                0,
                mining.challenge(),
                share_target,
            ),
            challenge: *mining.challenge(),
            share_target,
        },
        mining,
        seen_nonces: Mutex::new(HashSet::new()),
    });
    let shared = Arc::new(SharedServer {
        node,
        state: Mutex::new(ServerState {
            current: first,
            next_job_sequence: 1,
        }),
        ledger: Mutex::new(Ledger::default()),
        stop: AtomicBool::new(false),
        active_connections: AtomicUsize::new(0),
        active_sockets: Mutex::new(HashMap::new()),
        next_connection_id: AtomicU64::new(0),
        next_session_id: AtomicU64::new(1),
        network_id,
        consensus_fingerprint,
        block_destination: config.block_destination,
        configured_share_target: config.share_target,
        test_credit_atoms_per_share: config.test_credit_atoms_per_share,
        max_connections: config.max_connections,
        tls,
        startup_nonce,
    });
    let runtime = Arc::clone(&shared);
    let thread = thread::Builder::new()
        .name("cmfd-pool-listener".to_owned())
        .spawn(move || pool_listener(listener, runtime))?;
    Ok(PoolServerHandle {
        address,
        shared,
        thread: Some(thread),
    })
}

fn ensure_pool_profile_supported(profile: NetworkProfile) -> Result<(), PoolError> {
    if matches!(profile.proof, ProofProfile::ProductionV3) {
        return Err(PoolError::ProductionV3Unsupported);
    }
    Ok(())
}

fn pool_listener(listener: TcpListener, shared: Arc<SharedServer>) -> Result<(), PoolError> {
    let mut connections = Vec::new();
    while !shared.stop.load(Ordering::Acquire) {
        reap_finished_connections(&mut connections)?;
        let _ = rotate_if_tip_changed(&shared);
        match listener.accept() {
            Ok((stream, peer)) => {
                if validate_private_address(peer).is_err()
                    || shared.active_connections.load(Ordering::Acquire) >= shared.max_connections
                {
                    drop(stream);
                    continue;
                }
                let shutdown_stream = match stream.try_clone() {
                    Ok(stream) => stream,
                    Err(_) => {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                };
                let socket_guard = match register_active_connection(&shared, shutdown_stream)? {
                    Some(guard) => guard,
                    None => {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                };
                shared.active_connections.fetch_add(1, Ordering::AcqRel);
                let connection_shared = Arc::clone(&shared);
                let connection_guard = ConnectionGuard {
                    shared: Arc::clone(&shared),
                    _socket: socket_guard,
                };
                connections.push(
                    thread::Builder::new()
                        .name("cmfd-pool-session".to_owned())
                        .spawn(move || {
                            let _guard = connection_guard;
                            let _ = handle_connection(stream, Arc::clone(&connection_shared));
                        })?,
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POOL_ACCEPT_POLL);
            }
            Err(error) => return Err(PoolError::Io(error)),
        }
    }
    for connection in connections {
        connection.join().map_err(|_| PoolError::ThreadPanicked)?;
    }
    Ok(())
}

fn reap_finished_connections(connections: &mut Vec<JoinHandle<()>>) -> Result<(), PoolError> {
    let mut index = 0;
    while index < connections.len() {
        if connections[index].is_finished() {
            connections
                .swap_remove(index)
                .join()
                .map_err(|_| PoolError::ThreadPanicked)?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn register_active_connection(
    shared: &Arc<SharedServer>,
    stream: TcpStream,
) -> Result<Option<ActiveSocketGuard>, PoolError> {
    let mut sockets = shared
        .active_sockets
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    if shared.stop.load(Ordering::Acquire) {
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(None);
    }
    let id = shared.next_connection_id.fetch_add(1, Ordering::AcqRel);
    sockets.insert(id, stream);
    Ok(Some(ActiveSocketGuard {
        shared: Arc::clone(shared),
        id,
    }))
}

fn shutdown_active_connections(shared: &SharedServer) -> Result<(), PoolError> {
    let sockets = shared
        .active_sockets
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    for stream in sockets.values() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    Ok(())
}

struct ActiveSocketGuard {
    shared: Arc<SharedServer>,
    id: u64,
}

impl Drop for ActiveSocketGuard {
    fn drop(&mut self) {
        if let Ok(mut sockets) = self.shared.active_sockets.lock() {
            sockets.remove(&self.id);
        }
    }
}

struct ConnectionGuard {
    shared: Arc<SharedServer>,
    _socket: ActiveSocketGuard,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.shared
            .active_connections
            .fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_connection(stream: TcpStream, shared: Arc<SharedServer>) -> Result<(), PoolError> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(POOL_READ_TIMEOUT))?;
    stream.set_write_timeout(Some(POOL_WRITE_TIMEOUT))?;
    stream.set_nodelay(true)?;
    let connection = ServerConnection::new(Arc::clone(&shared.tls))
        .map_err(|error| PoolError::Tls(error.to_string()))?;
    let mut stream = StreamOwned::new(connection, stream);
    let handshake_deadline = checked_pool_deadline(Instant::now(), POOL_HANDSHAKE_TIMEOUT)?;
    let hello: ClientMessage =
        read_frame_interruptible_until(&mut stream, &shared.stop, handshake_deadline)?;
    let (worker, payout) = match hello {
        ClientMessage::Hello {
            protocol_version,
            network_id,
            consensus_fingerprint,
            worker,
            payout,
        } => {
            if protocol_version != POOL_PROTOCOL_VERSION {
                send_error(
                    &mut stream,
                    "protocol_mismatch",
                    "pool protocol version mismatch",
                )?;
                return Err(PoolError::ProtocolMismatch);
            }
            if network_id != shared.network_id {
                send_error(
                    &mut stream,
                    "network_mismatch",
                    "pool network identifier mismatch",
                )?;
                return Err(PoolError::NetworkMismatch);
            }
            if consensus_fingerprint != shared.consensus_fingerprint {
                send_error(
                    &mut stream,
                    "fingerprint_mismatch",
                    "pool consensus fingerprint mismatch",
                )?;
                return Err(PoolError::FingerprintMismatch);
            }
            validate_worker(&worker)?;
            VerifyingKey::from_bytes(&payout)
                .map_err(|_| PoolError::Node(NodeError::InvalidMinerDestination))?;
            (worker, payout)
        }
        ClientMessage::SubmitShare { .. } => {
            send_error(&mut stream, "hello_required", "first message must be hello")?;
            return Err(PoolError::InvalidMessage("hello required".to_owned()));
        }
    };

    let session_id = shared.next_session_id.fetch_add(1, Ordering::AcqRel);
    register_session(&shared.ledger, session_id, worker, payout)?;
    let _session_guard = SessionGuard {
        ledger: &shared.ledger,
        session_id,
    };
    write_frame(
        &mut stream,
        &ServerMessage::HelloAck {
            protocol_version: POOL_PROTOCOL_VERSION,
            network_id: shared.network_id,
            consensus_fingerprint: shared.consensus_fingerprint,
            session_id,
            accounting_semantics: POOL_ACCOUNTING_SEMANTICS.to_owned(),
            persistence: "session-only; reset on pool process restart".to_owned(),
        },
    )?;
    write_frame(
        &mut stream,
        &ServerMessage::Job {
            job: current_job(&shared)?,
        },
    )?;
    stream.sock.set_read_timeout(Some(POOL_READ_TIMEOUT))?;

    let mut message_count = 0_u64;
    while !shared.stop.load(Ordering::Acquire) {
        rotate_if_tip_changed(&shared)?;
        let message = match read_frame_interruptible::<_, ClientMessage>(&mut stream, &shared.stop)
        {
            Ok(message) => message,
            Err(PoolError::ConnectionClosed) => return Ok(()),
            Err(error) => return Err(error),
        };
        message_count = message_count
            .checked_add(1)
            .ok_or(PoolError::MessageCountLimit)?;
        if let Err(error) = validate_message_count(message_count) {
            send_error(
                &mut stream,
                "message_count_limit",
                "session message limit exceeded",
            )?;
            return Err(error);
        }
        let ClientMessage::SubmitShare { job_id, nonce } = message else {
            send_error(
                &mut stream,
                "unexpected_hello",
                "hello may only be sent once",
            )?;
            return Err(PoolError::InvalidMessage("duplicate hello".to_owned()));
        };
        // The tip may have changed while this session was blocked waiting for
        // its next frame. Rotate again immediately before classifying work.
        rotate_if_tip_changed(&shared)?;
        let before = current_job(&shared)?;
        let result = process_share(&shared, session_id, job_id, nonce)?;
        let after = current_job(&shared)?;
        if before.job_id != after.job_id || job_id != before.job_id {
            write_frame(&mut stream, &ServerMessage::Job { job: after })?;
        }
        write_frame(&mut stream, &ServerMessage::ShareResult { result })?;
    }
    Ok(())
}

fn checked_pool_deadline(now: Instant, duration: Duration) -> Result<Instant, PoolError> {
    now.checked_add(duration).ok_or(PoolError::DeadlineOverflow)
}

struct SessionGuard<'a> {
    ledger: &'a Mutex<Ledger>,
    session_id: u64,
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut ledger) = self.ledger.lock()
            && let Some(session) = ledger.sessions.get_mut(&self.session_id)
        {
            session.connected = false;
        }
    }
}

fn process_share(
    shared: &Arc<SharedServer>,
    session_id: u64,
    job_id: [u8; 32],
    nonce: u64,
) -> Result<PoolShareResult, PoolError> {
    let active = {
        let state = shared
            .state
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?;
        Arc::clone(&state.current)
    };
    if job_id != active.wire.job_id {
        return rejected_result(shared, session_id, job_id, nonce, "stale_job");
    }
    let evaluation = active
        .mining
        .evaluate_share(nonce, active.wire.share_target)?;
    if !evaluation.meets_share_target {
        return rejected_result(shared, session_id, job_id, nonce, "low_difficulty_share");
    }
    let block = if evaluation.meets_chain_target {
        let Some(block) = active
            .mining
            .build_block_if_chain_valid(&evaluation.proof)?
        else {
            return rejected_result(shared, session_id, job_id, nonce, "invalid_chain_proof");
        };
        Some(block)
    } else {
        None
    };

    // Evaluation is intentionally outside the node lock. Recheck the active
    // parent afterwards, then keep the node lock through duplicate reservation
    // and ledger credit so P2P cannot advance the tip between those steps.
    let node = shared
        .node
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    if node.state.tip() != active.wire.challenge.previous_block {
        drop(node);
        rotate_if_tip_changed(shared)?;
        return rejected_result(shared, session_id, job_id, nonce, "stale_job");
    }
    // Only valid, current shares consume the bounded duplicate set. Unique
    // low-work or stale nonces cannot force a job-capacity denial of service.
    let nonce_reserved = match reserve_valid_share(&active, nonce)? {
        NonceReservation::Reserved => true,
        NonceReservation::Duplicate => {
            drop(node);
            return rejected_result(shared, session_id, job_id, nonce, "duplicate_share");
        }
        NonceReservation::Full => {
            // The bounded accounting set must never become a consensus-work
            // gate. A chain-valid nonce may bypass a full share ledger and
            // submit its block; successful submission rotates the tip/job.
            if block.is_none() {
                drop(node);
                return rejected_result(shared, session_id, job_id, nonce, "job_share_limit");
            }
            false
        }
    };

    let Some(block) = block else {
        let session = credit_accepted_share(
            &shared.ledger,
            session_id,
            false,
            shared.test_credit_atoms_per_share,
        )?;
        drop(node);
        return Ok(PoolShareResult {
            job_id,
            nonce,
            accepted: true,
            block_accepted: false,
            code: "share_accepted".to_owned(),
            session,
        });
    };

    // A ProductionV3 proof and side-branch reconstruction can take seconds.
    // Release the shared node before the bounded verifier worker runs; the
    // revision-bound helper rechecks the authoritative chain on commit.
    drop(node);
    loop {
        match submit_shared_tip_block(&shared.node, (*block).clone(), unix_time_seconds()?) {
            Ok(_) => break,
            Err(
                NodeError::StaleBlockAdmission
                | NodeError::DuplicateBlock(_)
                | NodeError::UnknownParent(_),
            ) => {
                rotate_if_tip_changed(shared)?;
                return rejected_result(shared, session_id, job_id, nonce, "stale_job");
            }
            Err(
                NodeError::ProofVerificationQueueFull | NodeError::ProofVerificationQueueTimeout,
            ) => {
                if shared.stop.load(Ordering::Acquire) {
                    if nonce_reserved {
                        release_valid_share(&active, nonce)?;
                    }
                    return retryable_result(shared, session_id, job_id, nonce, "verifier_busy");
                }
                let parent_is_current = shared
                    .node
                    .lock()
                    .map_err(|_| PoolError::SharedStatePoisoned)?
                    .state
                    .tip()
                    == active.wire.challenge.previous_block;
                if !parent_is_current {
                    rotate_if_tip_changed(shared)?;
                    return rejected_result(shared, session_id, job_id, nonce, "stale_job");
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.client_error().retryable => {
                if nonce_reserved {
                    release_valid_share(&active, nonce)?;
                }
                return retryable_result(shared, session_id, job_id, nonce, "verifier_busy");
            }
            Err(error) => return Err(PoolError::Node(error)),
        }
    }

    let session = credit_accepted_share(
        &shared.ledger,
        session_id,
        true,
        shared.test_credit_atoms_per_share,
    )?;
    rotate_if_tip_changed(shared)?;
    Ok(PoolShareResult {
        job_id,
        nonce,
        accepted: true,
        block_accepted: true,
        code: "block_accepted".to_owned(),
        session,
    })
}

fn rejected_result(
    shared: &SharedServer,
    session_id: u64,
    job_id: [u8; 32],
    nonce: u64,
    code: &str,
) -> Result<PoolShareResult, PoolError> {
    let session = credit_rejected_share(&shared.ledger, session_id)?;
    Ok(PoolShareResult {
        job_id,
        nonce,
        accepted: false,
        block_accepted: false,
        code: code.to_owned(),
        session,
    })
}

fn retryable_result(
    shared: &SharedServer,
    session_id: u64,
    job_id: [u8; 32],
    nonce: u64,
    code: &str,
) -> Result<PoolShareResult, PoolError> {
    let ledger = shared
        .ledger
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    let session = session_snapshot(
        session_id,
        ledger
            .sessions
            .get(&session_id)
            .ok_or_else(|| PoolError::InvalidMessage("unknown session".to_owned()))?,
    )?;
    Ok(PoolShareResult {
        job_id,
        nonce,
        accepted: false,
        block_accepted: false,
        code: code.to_owned(),
        session,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceReservation {
    Reserved,
    Duplicate,
    Full,
}

fn reserve_valid_share(active: &ActiveJob, nonce: u64) -> Result<NonceReservation, PoolError> {
    let mut seen = active
        .seen_nonces
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    if seen.contains(&nonce) {
        return Ok(NonceReservation::Duplicate);
    }
    if seen.len() >= POOL_MAX_SHARES_PER_JOB {
        return Ok(NonceReservation::Full);
    }
    seen.insert(nonce);
    Ok(NonceReservation::Reserved)
}

fn release_valid_share(active: &ActiveJob, nonce: u64) -> Result<(), PoolError> {
    active
        .seen_nonces
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?
        .remove(&nonce);
    Ok(())
}

fn rotate_if_tip_changed(shared: &Arc<SharedServer>) -> Result<bool, PoolError> {
    // Node then pool-state is the only nested lock order in this module. Keep
    // both locks through template capture and installation so no stale job can
    // be published between the two operations.
    let node = shared
        .node
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    let tip = node.state.tip();
    let mut state = shared
        .state
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    if state.current.wire.challenge.previous_block == tip {
        return Ok(false);
    }
    let mining = node.build_mining_job(shared.block_destination, unix_time_seconds()?)?;
    debug_assert_eq!(mining.challenge().previous_block, tip);
    let sequence = state.next_job_sequence;
    state.next_job_sequence = state.next_job_sequence.wrapping_add(1);
    let share_target = easier_target(shared.configured_share_target, mining.challenge().target);
    let job_nonce = random_nonce()?;
    state.current = Arc::new(ActiveJob {
        wire: PoolJob {
            job_id: make_job_id(
                shared.startup_nonce,
                job_nonce,
                sequence,
                mining.challenge(),
                share_target,
            ),
            challenge: *mining.challenge(),
            share_target,
        },
        mining,
        seen_nonces: Mutex::new(HashSet::new()),
    });
    Ok(true)
}

fn current_job(shared: &SharedServer) -> Result<PoolJob, PoolError> {
    Ok(shared
        .state
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?
        .current
        .wire
        .clone())
}

fn register_session(
    ledger: &Mutex<Ledger>,
    session_id: u64,
    worker: String,
    payout: [u8; 32],
) -> Result<(), PoolError> {
    let mut ledger = ledger.lock().map_err(|_| PoolError::SharedStatePoisoned)?;
    while ledger.sessions.len() >= POOL_MAX_LEDGER_SESSIONS {
        let inactive = ledger
            .sessions
            .iter()
            .find_map(|(id, session)| (!session.connected).then_some(*id))
            .ok_or(PoolError::LedgerCapacity)?;
        ledger.sessions.remove(&inactive);
    }
    if !ledger.payouts.contains_key(&payout) && ledger.payouts.len() >= POOL_MAX_LEDGER_PAYOUTS {
        let removable = ledger
            .payouts
            .iter()
            .filter(|(candidate, _)| {
                !ledger
                    .sessions
                    .values()
                    .any(|session| session.payout == **candidate)
            })
            .min_by_key(|(_, record)| record.last_session_id)
            .map(|(candidate, _)| *candidate)
            .ok_or(PoolError::LedgerCapacity)?;
        ledger.payouts.remove(&removable);
    }
    ledger.sessions.insert(
        session_id,
        SessionRecord {
            connected: true,
            worker,
            payout,
            accepted_shares: 0,
            rejected_shares: 0,
            pool_blocks: 0,
            credited_devnet_atoms: 0,
        },
    );
    ledger.payouts.entry(payout).or_default().last_session_id = session_id;
    Ok(())
}

fn credit_accepted_share(
    ledger: &Mutex<Ledger>,
    session_id: u64,
    block: bool,
    atoms: u64,
) -> Result<PoolSessionStats, PoolError> {
    let mut ledger = ledger.lock().map_err(|_| PoolError::SharedStatePoisoned)?;
    let payout = ledger
        .sessions
        .get(&session_id)
        .ok_or_else(|| PoolError::InvalidMessage("unknown session".to_owned()))?
        .payout;
    ledger.accepted_shares = ledger.accepted_shares.saturating_add(1);
    ledger.credited_devnet_atoms = ledger.credited_devnet_atoms.saturating_add(atoms);
    if block {
        ledger.pool_blocks = ledger.pool_blocks.saturating_add(1);
    }
    {
        let session = ledger.sessions.get_mut(&session_id).expect("checked above");
        session.accepted_shares = session.accepted_shares.saturating_add(1);
        session.credited_devnet_atoms = session.credited_devnet_atoms.saturating_add(atoms);
        if block {
            session.pool_blocks = session.pool_blocks.saturating_add(1);
        }
    }
    {
        let payout = ledger.payouts.entry(payout).or_default();
        payout.last_session_id = session_id;
        payout.accepted_shares = payout.accepted_shares.saturating_add(1);
        payout.credited_devnet_atoms = payout.credited_devnet_atoms.saturating_add(atoms);
        if block {
            payout.pool_blocks = payout.pool_blocks.saturating_add(1);
        }
    }
    session_snapshot(
        session_id,
        ledger.sessions.get(&session_id).expect("checked above"),
    )
}

fn credit_rejected_share(
    ledger: &Mutex<Ledger>,
    session_id: u64,
) -> Result<PoolSessionStats, PoolError> {
    let mut ledger = ledger.lock().map_err(|_| PoolError::SharedStatePoisoned)?;
    let payout = ledger
        .sessions
        .get(&session_id)
        .ok_or_else(|| PoolError::InvalidMessage("unknown session".to_owned()))?
        .payout;
    ledger.rejected_shares = ledger.rejected_shares.saturating_add(1);
    let session = ledger.sessions.get_mut(&session_id).expect("checked above");
    session.rejected_shares = session.rejected_shares.saturating_add(1);
    let payout = ledger.payouts.entry(payout).or_default();
    payout.last_session_id = session_id;
    payout.rejected_shares = payout.rejected_shares.saturating_add(1);
    session_snapshot(
        session_id,
        ledger.sessions.get(&session_id).expect("checked above"),
    )
}

fn session_snapshot(
    session_id: u64,
    record: &SessionRecord,
) -> Result<PoolSessionStats, PoolError> {
    validate_worker(&record.worker)?;
    Ok(PoolSessionStats {
        session_id,
        connected: record.connected,
        worker: record.worker.clone(),
        payout: hex::encode(record.payout),
        accepted_shares: record.accepted_shares,
        rejected_shares: record.rejected_shares,
        pool_blocks: record.pool_blocks,
        credited_devnet_atoms: record.credited_devnet_atoms,
    })
}

fn snapshot_ledger(ledger: &Mutex<Ledger>) -> Result<PoolLedgerSnapshot, PoolError> {
    let ledger = ledger.lock().map_err(|_| PoolError::SharedStatePoisoned)?;
    let sessions = ledger
        .sessions
        .iter()
        .map(|(session_id, record)| session_snapshot(*session_id, record))
        .collect::<Result<Vec<_>, _>>()?;
    let payouts = ledger
        .payouts
        .iter()
        .map(|(payout, record)| PoolPayoutStats {
            payout: hex::encode(payout),
            accepted_shares: record.accepted_shares,
            rejected_shares: record.rejected_shares,
            pool_blocks: record.pool_blocks,
            credited_devnet_atoms: record.credited_devnet_atoms,
        })
        .collect();
    Ok(PoolLedgerSnapshot {
        accounting_semantics: POOL_ACCOUNTING_SEMANTICS.to_owned(),
        persistence: "session-only; reset on pool process restart".to_owned(),
        accepted_shares: ledger.accepted_shares,
        rejected_shares: ledger.rejected_shares,
        pool_blocks: ledger.pool_blocks,
        credited_devnet_atoms: ledger.credited_devnet_atoms,
        sessions,
        payouts,
    })
}

pub struct PoolClient {
    stream: StreamOwned<ClientConnection, TcpStream>,
    frame_reader: FrameReadState,
    session_id: u64,
    accounting_semantics: String,
    persistence: String,
    current_job: PoolJob,
}

impl fmt::Debug for PoolClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PoolClient")
            .field("session_id", &self.session_id)
            .field("current_job", &self.current_job)
            .finish_non_exhaustive()
    }
}

impl PoolClient {
    pub fn connect(config: PoolClientConfig) -> Result<Self, PoolError> {
        validate_private_address(config.address)?;
        validate_worker(&config.worker)?;
        VerifyingKey::from_bytes(&config.payout)
            .map_err(|_| PoolError::Node(NodeError::InvalidMinerDestination))?;
        let mut socket = TcpStream::connect_timeout(&config.address, Duration::from_secs(5))?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(POOL_WRITE_TIMEOUT))?;
        socket.set_nodelay(true)?;
        let tls = client_tls_config(config.certificate_sha256)?;
        let server_name = ServerName::IpAddress(config.address.ip().into());
        let mut connection = ClientConnection::new(Arc::new(tls), server_name)
            .map_err(|error| PoolError::Tls(error.to_string()))?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut socket)
                .map_err(map_tls_io_error)?;
        }
        let mut stream = StreamOwned::new(connection, socket);
        write_frame(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: POOL_PROTOCOL_VERSION,
                network_id: config.expected_network_id,
                consensus_fingerprint: config.expected_consensus_fingerprint,
                worker: config.worker,
                payout: config.payout,
            },
        )?;
        let (session_id, accounting_semantics, persistence) = match read_frame(&mut stream)? {
            ServerMessage::HelloAck {
                protocol_version,
                network_id,
                consensus_fingerprint,
                session_id,
                accounting_semantics,
                persistence,
            } => {
                if protocol_version != POOL_PROTOCOL_VERSION {
                    return Err(PoolError::ProtocolMismatch);
                }
                if network_id != config.expected_network_id {
                    return Err(PoolError::NetworkMismatch);
                }
                if consensus_fingerprint != config.expected_consensus_fingerprint {
                    return Err(PoolError::FingerprintMismatch);
                }
                (session_id, accounting_semantics, persistence)
            }
            ServerMessage::Error { code, .. } => return Err(server_error(code)),
            _ => {
                return Err(PoolError::InvalidMessage(
                    "expected pool hello acknowledgement".to_owned(),
                ));
            }
        };
        let current_job = match read_frame(&mut stream)? {
            ServerMessage::Job { job } => job,
            ServerMessage::Error { code, .. } => return Err(server_error(code)),
            _ => {
                return Err(PoolError::InvalidMessage(
                    "expected initial pool job".to_owned(),
                ));
            }
        };
        PoolMiningWork::from_job(current_job.clone())?;
        stream.sock.set_read_timeout(Some(POOL_READ_TIMEOUT))?;
        Ok(Self {
            stream,
            frame_reader: FrameReadState::default(),
            session_id,
            accounting_semantics,
            persistence,
            current_job,
        })
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn accounting_semantics(&self) -> &str {
        &self.accounting_semantics
    }

    pub fn persistence(&self) -> &str {
        &self.persistence
    }

    pub fn current_job(&self) -> &PoolJob {
        &self.current_job
    }

    pub fn current_work(&self) -> Result<PoolMiningWork, PoolError> {
        PoolMiningWork::from_job(self.current_job.clone())
    }

    /// A deterministic, session-specific starting nonce for the current job.
    /// Honest workers should resume from each search result's `next_nonce`
    /// until a replacement job arrives, then call this again.
    pub fn current_nonce_origin(&self) -> u64 {
        pool_nonce_origin(self.current_job.job_id, self.session_id)
    }

    pub fn initial_nonce_for_job(&self, job: &PoolJob) -> u64 {
        pool_nonce_origin(job.job_id, self.session_id)
    }

    pub fn submit_share(
        &mut self,
        job_id: [u8; 32],
        nonce: u64,
    ) -> Result<PoolShareResult, PoolError> {
        write_frame(
            &mut self.stream,
            &ClientMessage::SubmitShare { job_id, nonce },
        )?;
        loop {
            match self.receive()? {
                PoolClientEvent::Job(_) => {}
                PoolClientEvent::ShareResult(result) => return Ok(result),
            }
        }
    }

    pub fn receive(&mut self) -> Result<PoolClientEvent, PoolError> {
        match read_frame_stateful(&mut self.stream, &mut self.frame_reader)? {
            ServerMessage::Job { job } => {
                PoolMiningWork::from_job(job.clone())?;
                self.current_job = job.clone();
                Ok(PoolClientEvent::Job(job))
            }
            ServerMessage::ShareResult { result } => Ok(PoolClientEvent::ShareResult(result)),
            ServerMessage::Error { code, .. } => Err(server_error(code)),
            ServerMessage::HelloAck { .. } => Err(PoolError::InvalidMessage(
                "duplicate hello acknowledgement".to_owned(),
            )),
        }
    }
}

pub fn pool_nonce_origin(job_id: [u8; 32], session_id: u64) -> u64 {
    let mut hasher = blake3::Hasher::new_derive_key(POOL_NONCE_ORIGIN_DOMAIN);
    hasher.update(&job_id);
    hasher.update(&session_id.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(
        digest.as_bytes()[..8]
            .try_into()
            .expect("fixed digest length"),
    )
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    expected_pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual != self.expected_pin {
            return Err(rustls::Error::General(
                "pool certificate SHA-256 pin mismatch".to_owned(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signed,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signed,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_tls_config(pin: [u8; 32]) -> Result<ClientConfig, PoolError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedCertificateVerifier {
        expected_pin: pin,
        provider: Arc::clone(&provider),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| PoolError::Tls(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

fn server_tls_config(certificate: Vec<u8>, key: Vec<u8>) -> Result<ServerConfig, PoolError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| PoolError::Tls(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .map_err(|error| PoolError::Tls(error.to_string()))
}

pub fn generate_pool_certificate(
    certificate_path: impl AsRef<Path>,
    private_key_path: impl AsRef<Path>,
) -> Result<PoolCertificateInfo, PoolError> {
    let certificate_path = certificate_path.as_ref();
    let private_key_path = private_key_path.as_ref();
    if certificate_path == private_key_path {
        return Err(PoolError::CertificatePathCollision);
    }
    for path in [certificate_path, private_key_path] {
        if path.exists() {
            return Err(PoolError::CertificateExists(path.to_path_buf()));
        }
    }
    let generated = generate_simple_self_signed(vec!["cmfd-pool.local".to_owned()])?;
    let certificate_der = generated.cert.der().to_vec();
    let private_key_der = generated.signing_key.serialize_der();
    write_new_file(private_key_path, &private_key_der, true)?;
    if let Err(error) = write_new_file(certificate_path, &certificate_der, false) {
        let _ = fs::remove_file(private_key_path);
        return Err(error);
    }
    Ok(PoolCertificateInfo {
        certificate_path: certificate_path.to_path_buf(),
        private_key_path: private_key_path.to_path_buf(),
        certificate_sha256: Sha256::digest(&certificate_der).into(),
    })
}

pub fn certificate_sha256(certificate_der: &[u8]) -> [u8; 32] {
    Sha256::digest(certificate_der).into()
}

fn write_new_file(path: &Path, bytes: &[u8], private: bool) -> Result<(), PoolError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn make_job_id(
    startup_nonce: [u8; 32],
    job_nonce: [u8; 32],
    sequence: u64,
    challenge: &BlockChallenge,
    share_target: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(POOL_JOB_DOMAIN);
    hasher.update(&startup_nonce);
    hasher.update(&job_nonce);
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&challenge.network_id);
    hasher.update(&challenge.previous_block);
    hasher.update(&challenge.transaction_root);
    hasher.update(&challenge.height.to_le_bytes());
    hasher.update(&challenge.timestamp.to_le_bytes());
    hasher.update(&challenge.target);
    hasher.update(&share_target);
    *hasher.finalize().as_bytes()
}

fn random_nonce() -> Result<[u8; 32], PoolError> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| PoolError::Random(error.to_string()))?;
    Ok(nonce)
}

fn easier_target(configured: [u8; 32], chain: [u8; 32]) -> [u8; 32] {
    configured.max(chain)
}

fn validate_private_address(address: SocketAddr) -> Result<(), PoolError> {
    let allowed = match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
    };
    if allowed {
        Ok(())
    } else {
        Err(PoolError::PublicAddress(address))
    }
}

fn validate_worker(worker: &str) -> Result<(), PoolError> {
    if worker.is_empty()
        || worker.len() > POOL_MAX_WORKER_BYTES
        || !worker
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PoolError::InvalidWorker);
    }
    Ok(())
}

fn validate_message_count(count: u64) -> Result<(), PoolError> {
    if count > POOL_MAX_MESSAGES_PER_SESSION {
        Err(PoolError::MessageCountLimit)
    } else {
        Ok(())
    }
}

fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), PoolError> {
    let body = serde_json::to_vec(value)?;
    if body.is_empty() || body.len() > POOL_MAX_FRAME_BYTES {
        return Err(PoolError::FrameLimit);
    }
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, PoolError> {
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(PoolError::ConnectionClosed);
        }
        Err(error) => return Err(PoolError::Io(error)),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > POOL_MAX_FRAME_BYTES {
        return Err(PoolError::FrameLimit);
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

#[derive(Default)]
struct FrameReadState {
    header: [u8; 4],
    header_offset: usize,
    body: Vec<u8>,
    body_offset: usize,
}

fn read_frame_stateful<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    state: &mut FrameReadState,
) -> Result<T, PoolError> {
    while state.header_offset < state.header.len() {
        match reader.read(&mut state.header[state.header_offset..]) {
            Ok(0) => return Err(PoolError::ConnectionClosed),
            Ok(read) => state.header_offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(PoolError::Io(error)),
        }
    }
    if state.body.is_empty() {
        let length = u32::from_be_bytes(state.header) as usize;
        if length == 0 || length > POOL_MAX_FRAME_BYTES {
            return Err(PoolError::FrameLimit);
        }
        state.body = vec![0_u8; length];
    }
    while state.body_offset < state.body.len() {
        match reader.read(&mut state.body[state.body_offset..]) {
            Ok(0) => return Err(PoolError::ConnectionClosed),
            Ok(read) => state.body_offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(PoolError::Io(error)),
        }
    }
    let decoded = serde_json::from_slice(&state.body)?;
    *state = FrameReadState::default();
    Ok(decoded)
}

fn read_frame_interruptible<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    stop: &AtomicBool,
) -> Result<T, PoolError> {
    read_frame_interruptible_inner(reader, stop, None)
}

fn read_frame_interruptible_until<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<T, PoolError> {
    read_frame_interruptible_inner(reader, stop, Some(deadline))
}

fn read_frame_interruptible_inner<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    stop: &AtomicBool,
    deadline: Option<Instant>,
) -> Result<T, PoolError> {
    let mut length = [0_u8; 4];
    read_exact_interruptible(reader, &mut length, stop, deadline)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > POOL_MAX_FRAME_BYTES {
        return Err(PoolError::FrameLimit);
    }
    let mut body = vec![0_u8; length];
    read_exact_interruptible(reader, &mut body, stop, deadline)?;
    Ok(serde_json::from_slice(&body)?)
}

fn read_exact_interruptible<R: Read>(
    reader: &mut R,
    output: &mut [u8],
    stop: &AtomicBool,
    deadline: Option<Instant>,
) -> Result<(), PoolError> {
    let mut offset = 0;
    while offset < output.len() {
        if stop.load(Ordering::Acquire) {
            return Err(PoolError::ConnectionClosed);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(PoolError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "pool handshake timed out",
            )));
        }
        match reader.read(&mut output[offset..]) {
            Ok(0) => return Err(PoolError::ConnectionClosed),
            Ok(read) => offset += read,
            Err(error) if is_timeout(&error) => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(PoolError::Io(error)),
        }
    }
    Ok(())
}

fn send_error<W: Write>(writer: &mut W, code: &str, message: &str) -> Result<(), PoolError> {
    write_frame(
        writer,
        &ServerMessage::Error {
            code: code.to_owned(),
            message: message.to_owned(),
        },
    )
}

fn server_error(code: String) -> PoolError {
    match code.as_str() {
        "protocol_mismatch" => PoolError::ProtocolMismatch,
        "network_mismatch" => PoolError::NetworkMismatch,
        "fingerprint_mismatch" => PoolError::FingerprintMismatch,
        "message_count_limit" => PoolError::MessageCountLimit,
        _ => PoolError::InvalidMessage(format!("pool server rejected request: {code}")),
    }
}

fn map_tls_io_error(error: io::Error) -> PoolError {
    let message = error.to_string();
    if message.contains("certificate SHA-256 pin mismatch") {
        PoolError::CertificatePinMismatch
    } else if error.kind() == io::ErrorKind::InvalidData {
        PoolError::Tls(message)
    } else {
        PoolError::Io(error)
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], PoolError> {
    let bytes = hex::decode(value)
        .map_err(|_| PoolError::InvalidMessage("invalid 32-byte hex value".to_owned()))?;
    bytes
        .try_into()
        .map_err(|_| PoolError::InvalidMessage("invalid 32-byte hex value".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_v3_pool_fails_closed_without_v2_share_fallback() {
        assert!(matches!(
            ensure_pool_profile_supported(crate::RCNET1_PROFILE),
            Err(PoolError::ProductionV3Unsupported)
        ));
        assert!(ensure_pool_profile_supported(crate::DEVNET_PROFILE).is_ok());
    }

    #[test]
    fn pool_deadline_overflow_is_controlled() {
        assert!(matches!(
            checked_pool_deadline(Instant::now(), Duration::MAX),
            Err(PoolError::DeadlineOverflow)
        ));
    }

    use crate::{Node, default_miner_destination};

    #[derive(Debug)]
    struct TestRoot {
        path: PathBuf,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            Self::new_with_ids(label, || {
                let mut id = [0_u8; 16];
                getrandom::fill(&mut id).expect("obtain random pool test-root identity");
                id
            })
        }

        fn new_with_ids(label: &str, mut next_id: impl FnMut() -> [u8; 16]) -> Self {
            assert!(
                label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
                "pool test-root label must be path-safe"
            );
            for _ in 0..128 {
                let path = Self::candidate_path(label, next_id());
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create isolated pool test root {path:?}: {error}"),
                }
            }
            panic!("could not allocate a unique pool test root after 128 random candidates")
        }

        fn candidate_path(label: &str, id: [u8; 16]) -> PathBuf {
            std::env::temp_dir().join(format!("cmfd-pool-{label}-{}", hex::encode(id)))
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            for _ in 0..100 {
                match fs::remove_dir_all(&self.path) {
                    Ok(()) => return,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return,
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
            eprintln!("could not remove isolated pool test root {:?}", self.path);
        }
    }

    fn certificate(root: &TestRoot) -> (PathBuf, PathBuf, [u8; 32]) {
        let certificate = root.path().join("pool.crt.der");
        let key = root.path().join("pool.key.der");
        let info = generate_pool_certificate(&certificate, &key).unwrap();
        (certificate, key, info.certificate_sha256)
    }

    fn server(label: &str) -> (TestRoot, PoolServerHandle, Arc<Mutex<Node>>, [u8; 32]) {
        let root = TestRoot::new(label);
        let data = root.path().join("node");
        let node = Arc::new(Mutex::new(Node::open(data).unwrap()));
        let (certificate, key, pin) = certificate(&root);
        let config = PoolServerConfig::devnet(
            "127.0.0.1:0".parse().unwrap(),
            fs::read(certificate).unwrap(),
            fs::read(key).unwrap(),
            default_miner_destination(),
        );
        let server = spawn_pool_server(Arc::clone(&node), config).unwrap();
        (root, server, node, pin)
    }

    #[test]
    fn pool_test_root_skips_a_precreated_random_candidate() {
        let label = "precreated";
        let occupied_id = [0x11; 16];
        let selected_id = [0x22; 16];
        let occupied_path = TestRoot::candidate_path(label, occupied_id);
        fs::create_dir(&occupied_path).unwrap();
        let occupied = TestRoot {
            path: occupied_path.clone(),
        };
        let mut candidates = [occupied_id, selected_id].into_iter();
        let selected = TestRoot::new_with_ids(label, || candidates.next().unwrap());
        assert_eq!(
            selected.path(),
            TestRoot::candidate_path(label, selected_id)
        );
        assert!(occupied.path().exists());
        assert!(selected.path().exists());
        drop(selected);
        assert!(!TestRoot::candidate_path(label, selected_id).exists());
        drop(occupied);
        assert!(!occupied_path.exists());
    }

    #[test]
    fn pool_test_roots_do_not_reuse_pid_scoped_names() {
        let first = TestRoot::new("pid-reuse");
        let first_path = first.path().to_owned();
        let first_name = first_path.file_name().unwrap().to_string_lossy();
        let suffix = first_name.strip_prefix("cmfd-pool-pid-reuse-").unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
        drop(first);

        let second = TestRoot::new("pid-reuse");
        assert_ne!(second.path(), first_path);
    }

    #[test]
    fn parallel_pool_test_roots_are_unique_and_raii_cleaned() {
        const WORKERS: usize = 16;
        let held = Arc::new(std::sync::Barrier::new(WORKERS + 1));
        let (paths_tx, paths_rx) = std::sync::mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..WORKERS {
            let held = Arc::clone(&held);
            let paths_tx = paths_tx.clone();
            workers.push(thread::spawn(move || {
                let root = TestRoot::new("parallel");
                paths_tx.send(root.path().to_owned()).unwrap();
                drop(paths_tx);
                held.wait();
            }));
        }
        drop(paths_tx);
        let paths: Vec<_> = paths_rx.into_iter().collect();
        assert_eq!(paths.len(), WORKERS);
        assert!(paths.iter().all(|path| path.exists()));
        assert_eq!(paths.iter().collect::<HashSet<_>>().len(), WORKERS);
        held.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(paths.iter().all(|path| !path.exists()));
    }

    #[test]
    fn pool_test_root_is_removed_during_panic_unwind() {
        let observed = Arc::new(Mutex::new(None));
        let panic_observed = Arc::clone(&observed);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let root = TestRoot::new("forced-panic");
            *panic_observed.lock().unwrap() = Some(root.path().to_owned());
            panic!("forced pool fixture panic");
        }));
        assert!(result.is_err());
        let path = observed.lock().unwrap().clone().unwrap();
        assert!(!path.exists());
    }

    fn client(address: SocketAddr, pin: [u8; 32], worker: &str) -> PoolClient {
        PoolClient::connect(
            PoolClientConfig::devnet(address, pin, worker, default_miner_destination()).unwrap(),
        )
        .unwrap()
    }

    fn find_share(work: &PoolMiningWork, chain_valid: bool) -> u64 {
        find_share_from(work, 0, chain_valid)
    }

    fn find_share_from(work: &PoolMiningWork, mut nonce: u64, chain_valid: bool) -> u64 {
        loop {
            match work.search_range(nonce, 1_000, || false).unwrap() {
                PoolWorkSearchResult::Found {
                    nonce: found,
                    meets_chain_target,
                    next_nonce,
                    ..
                } => {
                    if meets_chain_target == chain_valid {
                        return found;
                    }
                    nonce = next_nonce;
                }
                PoolWorkSearchResult::Exhausted { next_nonce, .. } => nonce = next_nonce,
                PoolWorkSearchResult::Cancelled { .. } => unreachable!(),
            }
        }
    }

    #[test]
    fn tls_pin_mismatch_is_rejected() {
        let (_root, server, _node, _pin) = server("pin-mismatch");
        let error = PoolClient::connect(
            PoolClientConfig::devnet(
                server.local_addr(),
                [0x55; 32],
                "worker",
                default_miner_destination(),
            )
            .unwrap(),
        )
        .unwrap_err();
        assert!(matches!(error, PoolError::CertificatePinMismatch));
        server.stop().unwrap();
    }

    #[test]
    fn stop_interrupts_a_client_stalled_before_tls_handshake() {
        let (_root, server, _node, _pin) = server("stalled-pre-tls");
        let address = server.local_addr();
        let stream = TcpStream::connect(address).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while server.shared.active_connections.load(Ordering::Acquire) == 0
            && std::time::Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(server.shared.active_connections.load(Ordering::Acquire), 1);

        let started = std::time::Instant::now();
        server.stop().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "pool stop waited for the normal TLS handshake deadline"
        );
        drop(stream);
        TcpListener::bind(address).unwrap();
    }

    #[test]
    fn protocol_identity_frame_count_and_worker_bounds_are_enforced() {
        let (_root, server, _node, pin) = server("identity-bounds");
        let mut wrong_network = PoolClientConfig::devnet(
            server.local_addr(),
            pin,
            "worker",
            default_miner_destination(),
        )
        .unwrap();
        wrong_network.expected_network_id[0] ^= 1;
        assert!(matches!(
            PoolClient::connect(wrong_network).unwrap_err(),
            PoolError::NetworkMismatch
        ));

        let mut wrong_fingerprint = PoolClientConfig::devnet(
            server.local_addr(),
            pin,
            "worker",
            default_miner_destination(),
        )
        .unwrap();
        wrong_fingerprint.expected_consensus_fingerprint[0] ^= 1;
        assert!(matches!(
            PoolClient::connect(wrong_fingerprint).unwrap_err(),
            PoolError::FingerprintMismatch
        ));
        assert!(matches!(
            PoolClientConfig::devnet(
                server.local_addr(),
                pin,
                "x".repeat(POOL_MAX_WORKER_BYTES + 1),
                default_miner_destination(),
            )
            .and_then(PoolClient::connect)
            .unwrap_err(),
            PoolError::InvalidWorker
        ));
        let mut oversized = Vec::from(((POOL_MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
        oversized.extend_from_slice(b"{}");
        assert!(matches!(
            read_frame::<_, ClientMessage>(&mut oversized.as_slice()).unwrap_err(),
            PoolError::FrameLimit
        ));
        assert!(validate_message_count(POOL_MAX_MESSAGES_PER_SESSION).is_ok());
        assert!(matches!(
            validate_message_count(POOL_MAX_MESSAGES_PER_SESSION + 1),
            Err(PoolError::MessageCountLimit)
        ));
        server.stop().unwrap();
    }

    #[test]
    fn share_only_credit_duplicate_rejection_and_session_ledger_are_real() {
        let (_root, server, _node, pin) = server("share-ledger");
        let mut client = client(server.local_addr(), pin, "worker-a");
        assert!(client.accounting_semantics().contains("nonwithdrawable"));
        assert!(client.persistence().contains("session-only"));
        let work = client.current_work().unwrap();
        assert!(work.job().share_target > work.job().challenge.target);
        let nonce = find_share(&work, false);
        let accepted = client.submit_share(work.job().job_id, nonce).unwrap();
        assert!(accepted.accepted);
        assert!(!accepted.block_accepted);
        assert_eq!(accepted.code, "share_accepted");
        assert_eq!(accepted.session.credited_devnet_atoms, 1);
        let duplicate = client.submit_share(work.job().job_id, nonce).unwrap();
        assert!(!duplicate.accepted);
        assert_eq!(duplicate.code, "duplicate_share");
        let ledger = server.ledger_snapshot().unwrap();
        assert_eq!(ledger.accepted_shares, 1);
        assert_eq!(ledger.rejected_shares, 1);
        assert_eq!(ledger.pool_blocks, 0);
        assert_eq!(ledger.credited_devnet_atoms, 1);
        server.stop().unwrap();
    }

    #[test]
    fn stale_jobs_are_rejected_and_chain_valid_shares_submit_blocks() {
        let (_root, server, node, pin) = server("stale-and-block");
        let mut stale_client = client(server.local_addr(), pin, "stale-worker");
        let stale_job = stale_client.current_job().clone();
        {
            let mut node = node.lock().unwrap();
            node.mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                10_000,
            )
            .unwrap();
        }
        let stale = stale_client.submit_share(stale_job.job_id, 0).unwrap();
        assert!(!stale.accepted);
        assert_eq!(stale.code, "stale_job");

        let work = stale_client.current_work().unwrap();
        let height = work.job().challenge.height;
        let nonce = find_share(&work, true);
        let accepted = stale_client.submit_share(work.job().job_id, nonce).unwrap();
        assert!(accepted.accepted);
        assert!(accepted.block_accepted);
        assert_eq!(accepted.code, "block_accepted");
        assert_eq!(
            node.lock().unwrap().status().unwrap().accepted_height,
            height
        );
        assert_eq!(server.ledger_snapshot().unwrap().pool_blocks, 1);
        let address = server.local_addr();
        server.stop().unwrap();
        assert!(TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());
    }

    #[test]
    fn public_addresses_and_destructive_certificate_overwrite_are_refused() {
        assert!(matches!(
            validate_private_address("8.8.8.8:18445".parse().unwrap()),
            Err(PoolError::PublicAddress(_))
        ));
        let root = TestRoot::new("certificate-overwrite");
        let certificate = root.path().join("pool.crt.der");
        let key = root.path().join("pool.key.der");
        generate_pool_certificate(&certificate, &key).unwrap();
        assert!(matches!(
            generate_pool_certificate(&certificate, &key),
            Err(PoolError::CertificateExists(_))
        ));
    }

    #[test]
    fn worker_job_share_and_ledger_caps_are_exact_and_bounded() {
        for worker in [
            "a",
            "Rig-01.main_pool",
            "Z".repeat(POOL_MAX_WORKER_BYTES).as_str(),
        ] {
            assert!(validate_worker(worker).is_ok());
        }
        for worker in ["", "bad worker", "slash/name", "colon:name", "unicode-é"] {
            assert!(matches!(
                validate_worker(worker),
                Err(PoolError::InvalidWorker)
            ));
        }
        assert!(matches!(
            validate_worker(&"x".repeat(POOL_MAX_WORKER_BYTES + 1)),
            Err(PoolError::InvalidWorker)
        ));

        let (_root, server, _node, _pin) = server("bounded-state");
        let active = Arc::clone(&server.shared.state.lock().unwrap().current);
        {
            let mut seen = active.seen_nonces.lock().unwrap();
            seen.extend(0..POOL_MAX_SHARES_PER_JOB as u64);
        }
        assert_eq!(
            reserve_valid_share(&active, 0).unwrap(),
            NonceReservation::Duplicate
        );
        assert_eq!(
            reserve_valid_share(&active, POOL_MAX_SHARES_PER_JOB as u64).unwrap(),
            NonceReservation::Full
        );
        release_valid_share(&active, 0).unwrap();
        assert_eq!(
            reserve_valid_share(&active, 0).unwrap(),
            NonceReservation::Reserved,
            "a transient verifier result must make the exact nonce retryable"
        );

        let challenge = active.wire.challenge;
        let startup = [1; 32];
        let job_nonce = [2; 32];
        let easy = target_with_leading_zero_bits(4);
        let easier = target_with_leading_zero_bits(3);
        assert_ne!(
            make_job_id(startup, job_nonce, 7, &challenge, easy),
            make_job_id(startup, job_nonce, 7, &challenge, easier)
        );

        let ledger = Mutex::new(Ledger::default());
        for session_id in 1..=(POOL_MAX_LEDGER_SESSIONS as u64 + 1) {
            register_session(&ledger, session_id, format!("w{session_id}"), [0x22; 32]).unwrap();
            ledger
                .lock()
                .unwrap()
                .sessions
                .get_mut(&session_id)
                .unwrap()
                .connected = false;
        }
        assert_eq!(
            ledger.lock().unwrap().sessions.len(),
            POOL_MAX_LEDGER_SESSIONS
        );

        let payout_ledger = Mutex::new(Ledger::default());
        {
            let mut ledger = payout_ledger.lock().unwrap();
            for index in 0..POOL_MAX_LEDGER_PAYOUTS {
                let mut payout = [0_u8; 32];
                payout[..8].copy_from_slice(&(index as u64).to_le_bytes());
                ledger.payouts.insert(
                    payout,
                    PayoutRecord {
                        last_session_id: index as u64,
                        ..PayoutRecord::default()
                    },
                );
            }
        }
        register_session(&payout_ledger, 9_999, "new".to_owned(), [0xff; 32]).unwrap();
        assert_eq!(
            payout_ledger.lock().unwrap().payouts.len(),
            POOL_MAX_LEDGER_PAYOUTS
        );
        server.stop().unwrap();
    }

    #[test]
    fn session_nonce_origins_partition_two_honest_workers() {
        let (_root, server, _node, pin) = server("nonce-origins");
        let mut first = client(server.local_addr(), pin, "worker-1");
        let mut second = client(server.local_addr(), pin, "worker-2");
        assert_eq!(first.current_job().job_id, second.current_job().job_id);
        let first_origin = first.current_nonce_origin();
        let second_origin = second.current_nonce_origin();
        assert_ne!(first_origin, second_origin);
        assert_eq!(
            first_origin,
            first.initial_nonce_for_job(first.current_job())
        );

        let first_work = first.current_work().unwrap();
        let second_work = second.current_work().unwrap();
        let first_nonce = find_share_from(&first_work, first_origin, false);
        let second_nonce = find_share_from(&second_work, second_origin, false);
        assert_ne!(first_nonce, second_nonce);
        assert!(
            first
                .submit_share(first_work.job().job_id, first_nonce)
                .unwrap()
                .accepted
        );
        assert!(
            second
                .submit_share(second_work.job().job_id, second_nonce)
                .unwrap()
                .accepted
        );
        server.stop().unwrap();
    }

    #[test]
    fn full_share_ledger_cannot_block_a_chain_valid_nonce() {
        let (_root, server, _node, pin) = server("full-ledger-block");
        let mut client = client(server.local_addr(), pin, "block-worker");
        let work = client.current_work().unwrap();
        let nonce = find_share_from(&work, client.current_nonce_origin(), true);
        let active = Arc::clone(&server.shared.state.lock().unwrap().current);
        {
            let mut seen = active.seen_nonces.lock().unwrap();
            for offset in 1..=POOL_MAX_SHARES_PER_JOB as u64 {
                seen.insert(nonce.wrapping_add(offset));
            }
            assert_eq!(seen.len(), POOL_MAX_SHARES_PER_JOB);
        }
        let result = client.submit_share(work.job().job_id, nonce).unwrap();
        assert!(result.accepted);
        assert!(result.block_accepted);
        assert_eq!(result.code, "block_accepted");
        server.stop().unwrap();
    }

    #[test]
    fn fragmented_frame_survives_a_timeout_without_losing_offsets() {
        struct FragmentedReader {
            bytes: Vec<u8>,
            offset: usize,
            calls: usize,
        }

        impl Read for FragmentedReader {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls == 2 {
                    thread::sleep(POOL_READ_TIMEOUT + Duration::from_millis(25));
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "fragment pause"));
                }
                if self.offset == self.bytes.len() {
                    return Ok(0);
                }
                let count = output.len().min(2).min(self.bytes.len() - self.offset);
                output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
                self.offset += count;
                Ok(count)
            }
        }

        let message = ClientMessage::SubmitShare {
            job_id: [7; 32],
            nonce: 42,
        };
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &message).unwrap();
        let mut fragmented = FragmentedReader {
            bytes: encoded.clone(),
            offset: 0,
            calls: 0,
        };
        let decoded: ClientMessage =
            read_frame_interruptible(&mut fragmented, &AtomicBool::new(false)).unwrap();
        assert!(matches!(
            decoded,
            ClientMessage::SubmitShare {
                job_id,
                nonce: 42
            } if job_id == [7; 32]
        ));

        let mut client_fragmented = FragmentedReader {
            bytes: encoded,
            offset: 0,
            calls: 0,
        };
        let mut state = FrameReadState::default();
        assert!(matches!(
            read_frame_stateful::<_, ClientMessage>(&mut client_fragmented, &mut state),
            Err(PoolError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        let decoded: ClientMessage =
            read_frame_stateful(&mut client_fragmented, &mut state).unwrap();
        assert!(matches!(
            decoded,
            ClientMessage::SubmitShare {
                job_id,
                nonce: 42
            } if job_id == [7; 32]
        ));
    }

    #[test]
    fn tls_handshake_transport_errors_remain_retryable_io_errors() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::BrokenPipe,
        ] {
            assert!(matches!(
                map_tls_io_error(io::Error::new(kind, "transient transport")),
                PoolError::Io(error) if error.kind() == kind
            ));
        }
        assert!(matches!(
            map_tls_io_error(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid peer certificate",
            )),
            PoolError::Tls(message) if message == "invalid peer certificate"
        ));
        assert!(matches!(
            map_tls_io_error(io::Error::new(
                io::ErrorKind::InvalidData,
                "pool certificate SHA-256 pin mismatch",
            )),
            PoolError::CertificatePinMismatch
        ));
    }
}
