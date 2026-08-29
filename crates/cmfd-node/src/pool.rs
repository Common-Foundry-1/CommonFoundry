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
    BlockChallenge, BlockProof, ConsensusPowVerifier, ForgeMatrixV2AcceleratorBatch,
    ForgeMatrixV2AcceleratorModel, ForgeMatrixV2Error, OutputLock, PowError, Transaction,
    v2_reference_for_network,
};
use k256::schnorr::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
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
    NodeError, ProofProfile, submit_shared_tip_block, unix_time_seconds,
};

pub const POOL_PROTOCOL_VERSION: u16 = 2;
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
pub const POOL_MAX_LEDGER_BLOCKS: usize = 65_536;
pub const POOL_MAX_LEDGER_PAYOUT_TRANSACTIONS: usize = 65_536;
pub const DEFAULT_POOL_MINIMUM_PAYOUT_ATOMS: u64 = 100;
pub const DEFAULT_POOL_PAYOUT_FEE_ATOMS: u64 = 1;
pub const POOL_ACCOUNTING_SEMANTICS: &str = "durable authenticated Devnet accounting; on-chain settlement is active only when enabled by the pool operator";

const POOL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const POOL_READ_TIMEOUT: Duration = Duration::from_millis(200);
const POOL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const POOL_ACCEPT_POLL: Duration = Duration::from_millis(25);
const POOL_JOB_DOMAIN: &str = "CMFD/DEVNET-POOL/JOB/V1";
const POOL_NONCE_ORIGIN_DOMAIN: &str = "CMFD/DEVNET-POOL/NONCE-ORIGIN/V1";
const POOL_PAYOUT_AUTH_DOMAIN: &str = "CMFD/POOL/PAYOUT-AUTH/V1";
const POOL_LEDGER_FORMAT_VERSION: u16 = 2;
const POOL_LEDGER_FILE_PREFIX: &str = "pool-ledger-v2";
const POOL_LEDGER_CHECKSUM_DOMAIN: &str = "CMFD/POOL/LEDGER/V2";
const LEGACY_POOL_LEDGER_FORMAT_VERSION: u16 = 1;
const LEGACY_POOL_LEDGER_FILE_PREFIX: &str = "pool-ledger-v1";
const LEGACY_POOL_LEDGER_CHECKSUM_DOMAIN: &str = "CMFD/POOL/LEDGER/V1";
const POOL_LEDGER_MAX_BYTES: usize = 64 * 1024 * 1024;
const POOL_MAX_PAYOUTS_PER_TIP: usize = 16;

#[derive(Debug, Error)]
pub enum PoolError {
    #[error(
        "Production V3 pool shares are not implemented; the ProductionV3 pool service is disabled rather than accepting V2 shares"
    )]
    ProductionV3Unsupported,
    #[error(
        "Production V4 pool shares require a configured replay verifier; the ProductionV4 pool service is disabled rather than trusting miner claims"
    )]
    ProductionV4Unsupported,
    #[error("Production V4 share replay failed: {0}")]
    ProductionV4Replay(String),
    #[error("Production V4 replay returned a chain-winning share without its consensus proof")]
    ProductionV4ChainProofMissing,
    #[error("Production V4 replay returned a proof whose work digest does not match its replay")]
    ProductionV4ProofMismatch,
    #[error("Production V4 replay returned a consensus proof for a non-chain-winning share")]
    ProductionV4UnexpectedChainProof,
    #[error("pool address must be a numeric private or loopback address, received {0}")]
    PublicAddress(SocketAddr),
    #[error("pool worker name must match [A-Za-z0-9._-]{{1,{POOL_MAX_WORKER_BYTES}}}")]
    InvalidWorker,
    #[error("pool connection limit must be between 1 and {POOL_MAX_CONNECTIONS}")]
    InvalidConnectionLimit,
    #[error("pool payout policy requires nonzero minimum and fee amounts")]
    InvalidPayoutPolicy,
    #[error("pool settlement requires the block-reward destination to be this node's wallet")]
    PayoutWalletMismatch,
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
    #[error("pool payout-key authentication failed")]
    PayoutAuthentication,
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
    #[error("pool ledger storage is corrupt: {0}")]
    LedgerCorrupt(String),
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
    pub ledger_directory: Option<PathBuf>,
    pub payout_policy: Option<PoolPayoutPolicy>,
    pub production_v4_share_verifier: Option<Arc<dyn ProductionV4PoolShareVerifier>>,
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
            ledger_directory: None,
            payout_policy: None,
            production_v4_share_verifier: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolPayoutPolicy {
    pub minimum_payout_atoms: u64,
    pub fee_atoms: u64,
}

impl Default for PoolPayoutPolicy {
    fn default() -> Self {
        Self {
            minimum_payout_atoms: DEFAULT_POOL_MINIMUM_PAYOUT_ATOMS,
            fee_atoms: DEFAULT_POOL_PAYOUT_FEE_ATOMS,
        }
    }
}

/// Pool-owned ProductionV4 replay result.
///
/// Ordinary shares need only the exact work digest recomputed from the fixed
/// model and submitted nonce. A chain-winning replay must additionally carry
/// the complete consensus proof so the unchanged node verifier can authorize
/// the block. Implementations are trusted only for pool credit; they never
/// bypass block verification.
#[derive(Debug, Clone)]
pub struct ProductionV4PoolShareEvaluation {
    pub work_digest: [u8; 32],
    pub chain_proof: Option<BlockProof>,
}

/// Pool-local accelerator boundary for ProductionV4 share verification.
///
/// A production implementation is expected to retain an authenticated model
/// on a pool-owned GPU, replay the nonce, derive the work digest on the CPU,
/// and construct the full proof only when the chain target is met.
pub trait ProductionV4PoolShareVerifier: fmt::Debug + Send + Sync {
    fn evaluate(
        &self,
        template: &crate::BlockTemplate,
        nonce: u64,
        share_target: [u8; 32],
    ) -> Result<ProductionV4PoolShareEvaluation, PoolError>;
}

#[derive(Debug, Clone)]
pub struct PoolClientConfig {
    pub address: SocketAddr,
    pub certificate_sha256: [u8; 32],
    pub worker: String,
    pub payout: [u8; 32],
    pub payout_signer: PoolPayoutSigner,
    pub expected_network_id: [u8; 32],
    pub expected_consensus_fingerprint: [u8; 32],
}

impl PoolClientConfig {
    pub fn devnet(
        address: SocketAddr,
        certificate_sha256: [u8; 32],
        worker: impl Into<String>,
        payout_signer: PoolPayoutSigner,
    ) -> Result<Self, PoolError> {
        let params = devnet_pool_params()?;
        let payout = payout_signer.payout();
        Ok(Self {
            address,
            certificate_sha256,
            worker: worker.into(),
            payout,
            payout_signer,
            expected_network_id: params.network_id,
            expected_consensus_fingerprint: params.fingerprint().map_err(NodeError::from)?,
        })
    }
}

#[derive(Clone)]
pub struct PoolPayoutSigner {
    key: Arc<SigningKey>,
}

impl PoolPayoutSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key: Arc::new(key) }
    }

    pub fn payout(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes().into()
    }

    fn sign(&self, digest: [u8; 32]) -> Vec<u8> {
        let signature: Signature = self.key.sign(&digest);
        signature.to_bytes().to_vec()
    }
}

impl fmt::Debug for PoolPayoutSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PoolPayoutSigner")
            .field("payout", &hex::encode(self.payout()))
            .finish_non_exhaustive()
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
    pub reserved_payout_atoms: u64,
    pub confirmed_payout_atoms: u64,
    pub available_payout_atoms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolPayoutTransactionStats {
    pub txid: String,
    pub payout: String,
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub state: String,
    pub confirmations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolBlockStats {
    pub block_id: String,
    pub parent: String,
    pub height: u64,
    pub payout: String,
    pub state: String,
    pub confirmations: u64,
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
    pub canonical_pool_blocks: u64,
    pub orphaned_pool_blocks: u64,
    pub sessions: Vec<PoolSessionStats>,
    pub payouts: Vec<PoolPayoutStats>,
    pub blocks: Vec<PoolBlockStats>,
    pub payout_transactions: Vec<PoolPayoutTransactionStats>,
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
        let params = devnet_pool_params()?;
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

fn devnet_pool_params() -> Result<cmfd_consensus::NetworkParams, PoolError> {
    crate::network_params_and_verifier_for_profile(crate::DEVNET_PROFILE, None, None)
        .map(|(params, _)| params)
        .map_err(PoolError::from)
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
        payout_signature: Vec<u8>,
    },
    SubmitShare {
        job_id: [u8; 32],
        nonce: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ServerMessage {
    AuthChallenge {
        protocol_version: u16,
        network_id: [u8; 32],
        consensus_fingerprint: [u8; 32],
        nonce: [u8; 32],
    },
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

#[derive(Clone, Default)]
struct Ledger {
    generation: u64,
    accepted_shares: u64,
    rejected_shares: u64,
    pool_blocks: u64,
    credited_devnet_atoms: u64,
    sessions: BTreeMap<u64, SessionRecord>,
    payouts: BTreeMap<[u8; 32], PayoutRecord>,
    blocks: BTreeMap<[u8; 32], BlockRecord>,
    payout_transactions: BTreeMap<[u8; 32], PayoutTransactionRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRecord {
    connected: bool,
    worker: String,
    payout: [u8; 32],
    accepted_shares: u64,
    rejected_shares: u64,
    pool_blocks: u64,
    credited_devnet_atoms: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayoutRecord {
    accepted_shares: u64,
    rejected_shares: u64,
    pool_blocks: u64,
    credited_devnet_atoms: u64,
    last_session_id: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PoolBlockState {
    Pending,
    Canonical,
    Orphaned,
    Unknown,
}

impl PoolBlockState {
    const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Canonical => "canonical",
            Self::Orphaned => "orphaned",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockRecord {
    parent: [u8; 32],
    height: u64,
    session_id: u64,
    payout: [u8; 32],
    atoms: u64,
    state: PoolBlockState,
    confirmations: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PoolPayoutTransactionState {
    Prepared,
    Broadcast,
    Confirmed,
    Abandoned,
}

impl PoolPayoutTransactionState {
    const fn label(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Broadcast => "broadcast",
            Self::Confirmed => "confirmed",
            Self::Abandoned => "abandoned",
        }
    }

    const fn reserves_credit(self) -> bool {
        !matches!(self, Self::Abandoned)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayoutTransactionRecord {
    payout: [u8; 32],
    amount_atoms: u64,
    fee_atoms: u64,
    transaction: Transaction,
    state: PoolPayoutTransactionState,
    confirmations: u64,
}

struct DurableLedger {
    state: Mutex<Ledger>,
    store: Option<LedgerStore>,
}

struct LedgerStore {
    directory: PathBuf,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLedgerV1 {
    format_version: u16,
    generation: u64,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    payload: StoredLedgerPayloadV1,
    payload_blake3: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLedgerPayloadV1 {
    accepted_shares: u64,
    rejected_shares: u64,
    pool_blocks: u64,
    credited_devnet_atoms: u64,
    sessions: Vec<StoredSessionRecordV1>,
    payouts: Vec<StoredPayoutRecordV1>,
    blocks: Vec<StoredBlockRecordV1>,
    payout_transactions: Vec<StoredPayoutTransactionRecordV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSessionRecordV1 {
    session_id: u64,
    record: SessionRecord,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPayoutRecordV1 {
    payout: [u8; 32],
    record: PayoutRecord,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBlockRecordV1 {
    block_id: [u8; 32],
    record: BlockRecord,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPayoutTransactionRecordV1 {
    txid: [u8; 32],
    record: PayoutTransactionRecord,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyStoredLedgerV1 {
    format_version: u16,
    generation: u64,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    payload: LegacyStoredLedgerPayloadV1,
    payload_blake3: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyStoredLedgerPayloadV1 {
    accepted_shares: u64,
    rejected_shares: u64,
    pool_blocks: u64,
    credited_devnet_atoms: u64,
    sessions: Vec<StoredSessionRecordV1>,
    payouts: Vec<StoredPayoutRecordV1>,
    blocks: Vec<StoredBlockRecordV1>,
}

impl DurableLedger {
    fn open(
        directory: Option<PathBuf>,
        network_id: [u8; 32],
        consensus_fingerprint: [u8; 32],
    ) -> Result<Self, PoolError> {
        let Some(directory) = directory else {
            return Ok(Self {
                state: Mutex::new(Ledger::default()),
                store: None,
            });
        };
        let store = LedgerStore {
            directory,
            network_id,
            consensus_fingerprint,
        };
        let state = store.load()?;
        Ok(Self {
            state: Mutex::new(state),
            store: Some(store),
        })
    }

    fn next_session_id(&self) -> Result<u64, PoolError> {
        self.state
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?
            .sessions
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| PoolError::LedgerCorrupt("session identifier exhausted".to_owned()))
    }

    fn transaction<T>(
        &self,
        update: impl FnOnce(&mut Ledger) -> Result<T, PoolError>,
    ) -> Result<T, PoolError> {
        let mut current = self
            .state
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?;
        let mut candidate = current.clone();
        let output = update(&mut candidate)?;
        candidate.generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| PoolError::LedgerCorrupt("ledger generation exhausted".to_owned()))?;
        validate_ledger(&candidate)?;
        if let Some(store) = &self.store {
            store.persist(&candidate)?;
        }
        *current = candidate;
        Ok(output)
    }
}

impl LedgerStore {
    fn load(&self) -> Result<Ledger, PoolError> {
        fs::create_dir_all(&self.directory)?;
        if !self.directory.is_dir() {
            return Err(PoolError::LedgerCorrupt(format!(
                "ledger path is not a directory: {}",
                self.directory.display()
            )));
        }
        let mut valid = Vec::new();
        let mut errors = Vec::new();
        for slot in 0..=1 {
            match self.load_slot(slot) {
                Ok(Some(ledger)) => valid.push(ledger),
                Ok(None) => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        if let Some(ledger) = valid.into_iter().max_by_key(|ledger| ledger.generation) {
            return Ok(ledger);
        }
        if !errors.is_empty() {
            return Err(PoolError::LedgerCorrupt(errors.join("; ")));
        }

        let mut legacy = Vec::new();
        for slot in 0..=1 {
            match self.load_legacy_slot(slot) {
                Ok(Some(ledger)) => legacy.push(ledger),
                Ok(None) => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        if let Some(ledger) = legacy.into_iter().max_by_key(|ledger| ledger.generation) {
            self.persist(&ledger)?;
            return Ok(ledger);
        }
        if errors.is_empty() {
            Ok(Ledger::default())
        } else {
            Err(PoolError::LedgerCorrupt(errors.join("; ")))
        }
    }

    fn load_slot(&self, slot: u8) -> Result<Option<Ledger>, PoolError> {
        let path = self.slot_path(slot);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if bytes.is_empty() || bytes.len() > POOL_LEDGER_MAX_BYTES {
            return Err(PoolError::LedgerCorrupt(format!(
                "{} has an invalid byte length",
                path.display()
            )));
        }
        let stored: StoredLedgerV1 = serde_json::from_slice(&bytes)
            .map_err(|error| PoolError::LedgerCorrupt(format!("{}: {error}", path.display())))?;
        if stored.format_version != POOL_LEDGER_FORMAT_VERSION
            || stored.network_id != self.network_id
            || stored.consensus_fingerprint != self.consensus_fingerprint
        {
            return Err(PoolError::LedgerCorrupt(format!(
                "{} has the wrong format or network identity",
                path.display()
            )));
        }
        let expected = ledger_payload_checksum(
            stored.generation,
            stored.network_id,
            stored.consensus_fingerprint,
            &stored.payload,
        )?;
        if stored.payload_blake3 != expected {
            return Err(PoolError::LedgerCorrupt(format!(
                "{} checksum mismatch",
                path.display()
            )));
        }
        let mut ledger = ledger_from_payload(stored.generation, stored.payload)?;
        for session in ledger.sessions.values_mut() {
            session.connected = false;
        }
        Ok(Some(ledger))
    }

    fn persist(&self, ledger: &Ledger) -> Result<(), PoolError> {
        let payload = ledger_payload(ledger);
        let stored = StoredLedgerV1 {
            format_version: POOL_LEDGER_FORMAT_VERSION,
            generation: ledger.generation,
            network_id: self.network_id,
            consensus_fingerprint: self.consensus_fingerprint,
            payload_blake3: ledger_payload_checksum(
                ledger.generation,
                self.network_id,
                self.consensus_fingerprint,
                &payload,
            )?,
            payload,
        };
        let bytes = serde_json::to_vec(&stored)?;
        if bytes.len() > POOL_LEDGER_MAX_BYTES {
            return Err(PoolError::LedgerCapacity);
        }
        let slot = (ledger.generation & 1) as u8;
        let destination = self.slot_path(slot);
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| PoolError::Random(error.to_string()))?;
        let temporary = self.directory.join(format!(
            "{POOL_LEDGER_FILE_PREFIX}.tmp-{}",
            hex::encode(random)
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            match fs::remove_file(&destination) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(PoolError::Io(error)),
            }
            fs::rename(&temporary, &destination)?;
            sync_ledger_directory(&self.directory)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn slot_path(&self, slot: u8) -> PathBuf {
        self.directory
            .join(format!("{POOL_LEDGER_FILE_PREFIX}.{slot}.json"))
    }

    fn load_legacy_slot(&self, slot: u8) -> Result<Option<Ledger>, PoolError> {
        let path = self
            .directory
            .join(format!("{LEGACY_POOL_LEDGER_FILE_PREFIX}.{slot}.json"));
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if bytes.is_empty() || bytes.len() > POOL_LEDGER_MAX_BYTES {
            return Err(PoolError::LedgerCorrupt(format!(
                "{} has an invalid byte length",
                path.display()
            )));
        }
        let stored: LegacyStoredLedgerV1 = serde_json::from_slice(&bytes)
            .map_err(|error| PoolError::LedgerCorrupt(format!("{}: {error}", path.display())))?;
        if stored.format_version != LEGACY_POOL_LEDGER_FORMAT_VERSION
            || stored.network_id != self.network_id
            || stored.consensus_fingerprint != self.consensus_fingerprint
        {
            return Err(PoolError::LedgerCorrupt(format!(
                "{} has the wrong format or network identity",
                path.display()
            )));
        }
        let expected = legacy_ledger_payload_checksum(
            stored.generation,
            stored.network_id,
            stored.consensus_fingerprint,
            &stored.payload,
        )?;
        if stored.payload_blake3 != expected {
            return Err(PoolError::LedgerCorrupt(format!(
                "{} checksum mismatch",
                path.display()
            )));
        }
        let payload = StoredLedgerPayloadV1 {
            accepted_shares: stored.payload.accepted_shares,
            rejected_shares: stored.payload.rejected_shares,
            pool_blocks: stored.payload.pool_blocks,
            credited_devnet_atoms: stored.payload.credited_devnet_atoms,
            sessions: stored.payload.sessions,
            payouts: stored.payload.payouts,
            blocks: stored.payload.blocks,
            payout_transactions: Vec::new(),
        };
        let mut ledger = ledger_from_payload(stored.generation, payload)?;
        for session in ledger.sessions.values_mut() {
            session.connected = false;
        }
        Ok(Some(ledger))
    }
}

fn ledger_payload(ledger: &Ledger) -> StoredLedgerPayloadV1 {
    StoredLedgerPayloadV1 {
        accepted_shares: ledger.accepted_shares,
        rejected_shares: ledger.rejected_shares,
        pool_blocks: ledger.pool_blocks,
        credited_devnet_atoms: ledger.credited_devnet_atoms,
        sessions: ledger
            .sessions
            .iter()
            .map(|(session_id, record)| StoredSessionRecordV1 {
                session_id: *session_id,
                record: record.clone(),
            })
            .collect(),
        payouts: ledger
            .payouts
            .iter()
            .map(|(payout, record)| StoredPayoutRecordV1 {
                payout: *payout,
                record: record.clone(),
            })
            .collect(),
        blocks: ledger
            .blocks
            .iter()
            .map(|(block_id, record)| StoredBlockRecordV1 {
                block_id: *block_id,
                record: *record,
            })
            .collect(),
        payout_transactions: ledger
            .payout_transactions
            .iter()
            .map(|(txid, record)| StoredPayoutTransactionRecordV1 {
                txid: *txid,
                record: record.clone(),
            })
            .collect(),
    }
}

fn ledger_from_payload(
    generation: u64,
    payload: StoredLedgerPayloadV1,
) -> Result<Ledger, PoolError> {
    let mut sessions = BTreeMap::new();
    for entry in payload.sessions {
        if sessions.insert(entry.session_id, entry.record).is_some() {
            return Err(PoolError::LedgerCorrupt(
                "duplicate stored session identifier".to_owned(),
            ));
        }
    }
    let mut payouts = BTreeMap::new();
    for entry in payload.payouts {
        if payouts.insert(entry.payout, entry.record).is_some() {
            return Err(PoolError::LedgerCorrupt(
                "duplicate stored payout identifier".to_owned(),
            ));
        }
    }
    let mut blocks = BTreeMap::new();
    for entry in payload.blocks {
        if blocks.insert(entry.block_id, entry.record).is_some() {
            return Err(PoolError::LedgerCorrupt(
                "duplicate stored pool block identifier".to_owned(),
            ));
        }
    }
    let mut payout_transactions = BTreeMap::new();
    for entry in payload.payout_transactions {
        if payout_transactions
            .insert(entry.txid, entry.record)
            .is_some()
        {
            return Err(PoolError::LedgerCorrupt(
                "duplicate stored payout transaction".to_owned(),
            ));
        }
    }
    let ledger = Ledger {
        generation,
        accepted_shares: payload.accepted_shares,
        rejected_shares: payload.rejected_shares,
        pool_blocks: payload.pool_blocks,
        credited_devnet_atoms: payload.credited_devnet_atoms,
        sessions,
        payouts,
        blocks,
        payout_transactions,
    };
    validate_ledger(&ledger)?;
    Ok(ledger)
}

fn ledger_payload_checksum(
    generation: u64,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    payload: &StoredLedgerPayloadV1,
) -> Result<[u8; 32], PoolError> {
    let bytes = serde_json::to_vec(payload)?;
    let mut hasher = blake3::Hasher::new_derive_key(POOL_LEDGER_CHECKSUM_DOMAIN);
    hasher.update(&POOL_LEDGER_FORMAT_VERSION.to_le_bytes());
    hasher.update(&generation.to_le_bytes());
    hasher.update(&network_id);
    hasher.update(&consensus_fingerprint);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn legacy_ledger_payload_checksum(
    generation: u64,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    payload: &LegacyStoredLedgerPayloadV1,
) -> Result<[u8; 32], PoolError> {
    let bytes = serde_json::to_vec(payload)?;
    let mut hasher = blake3::Hasher::new_derive_key(LEGACY_POOL_LEDGER_CHECKSUM_DOMAIN);
    hasher.update(&LEGACY_POOL_LEDGER_FORMAT_VERSION.to_le_bytes());
    hasher.update(&generation.to_le_bytes());
    hasher.update(&network_id);
    hasher.update(&consensus_fingerprint);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn validate_ledger(ledger: &Ledger) -> Result<(), PoolError> {
    if ledger.sessions.len() > POOL_MAX_LEDGER_SESSIONS
        || ledger.payouts.len() > POOL_MAX_LEDGER_PAYOUTS
        || ledger.blocks.len() > POOL_MAX_LEDGER_BLOCKS
        || ledger.payout_transactions.len() > POOL_MAX_LEDGER_PAYOUT_TRANSACTIONS
    {
        return Err(PoolError::LedgerCapacity);
    }
    let payout_totals =
        ledger
            .payouts
            .values()
            .try_fold((0_u64, 0_u64, 0_u64, 0_u64), |totals, record| {
                Ok::<_, PoolError>((
                    totals
                        .0
                        .checked_add(record.accepted_shares)
                        .ok_or_else(|| {
                            PoolError::LedgerCorrupt("accepted-share total overflow".to_owned())
                        })?,
                    totals
                        .1
                        .checked_add(record.rejected_shares)
                        .ok_or_else(|| {
                            PoolError::LedgerCorrupt("rejected-share total overflow".to_owned())
                        })?,
                    totals.2.checked_add(record.pool_blocks).ok_or_else(|| {
                        PoolError::LedgerCorrupt("pool-block total overflow".to_owned())
                    })?,
                    totals
                        .3
                        .checked_add(record.credited_devnet_atoms)
                        .ok_or_else(|| {
                            PoolError::LedgerCorrupt("credit total overflow".to_owned())
                        })?,
                ))
            })?;
    if payout_totals
        != (
            ledger.accepted_shares,
            ledger.rejected_shares,
            ledger.pool_blocks,
            ledger.credited_devnet_atoms,
        )
        || ledger
            .blocks
            .values()
            .filter(|record| record.state != PoolBlockState::Pending)
            .count() as u64
            != ledger.pool_blocks
    {
        return Err(PoolError::LedgerCorrupt(
            "stored aggregate totals do not match their records".to_owned(),
        ));
    }
    for session in ledger.sessions.values() {
        validate_worker(&session.worker)?;
        VerifyingKey::from_bytes(&session.payout).map_err(|_| {
            PoolError::LedgerCorrupt("stored session payout key is invalid".to_owned())
        })?;
    }
    for payout in ledger.payouts.keys() {
        VerifyingKey::from_bytes(payout)
            .map_err(|_| PoolError::LedgerCorrupt("stored payout key is invalid".to_owned()))?;
    }
    let mut reserved_by_payout = BTreeMap::<[u8; 32], u64>::new();
    for (txid, record) in &ledger.payout_transactions {
        if record.transaction.txid() != *txid
            || record.amount_atoms == 0
            || record.transaction.outputs.first().is_none_or(|output| {
                output.value != record.amount_atoms || output.lock != OutputLock::Key(record.payout)
            })
            || (record.state == PoolPayoutTransactionState::Confirmed) != (record.confirmations > 0)
            || !ledger.payouts.contains_key(&record.payout)
        {
            return Err(PoolError::LedgerCorrupt(
                "stored payout transaction is inconsistent".to_owned(),
            ));
        }
        if record.state.reserves_credit() {
            let reserved = reserved_by_payout.entry(record.payout).or_default();
            *reserved = checked_ledger_add(*reserved, record.amount_atoms, "reserved payout")?;
        }
    }
    for (payout, reserved) in reserved_by_payout {
        if reserved > ledger.payouts[&payout].credited_devnet_atoms {
            return Err(PoolError::LedgerCorrupt(
                "stored payout transaction exceeds earned credit".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sync_ledger_directory(path: &Path) -> Result<(), PoolError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_ledger_directory(_path: &Path) -> Result<(), PoolError> {
    Ok(())
}

struct SharedServer {
    node: Arc<Mutex<Node>>,
    state: Mutex<ServerState>,
    ledger: DurableLedger,
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
    payout_policy: Option<PoolPayoutPolicy>,
    max_connections: usize,
    proof_profile: ProofProfile,
    production_v4_share_verifier: Option<Arc<dyn ProductionV4PoolShareVerifier>>,
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
        reconcile_pool_blocks(&self.shared)?;
        reconcile_pool_payouts(&self.shared, false)?;
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
    let (profile, wallet_destination) = {
        let node = node.lock().map_err(|_| PoolError::SharedStatePoisoned)?;
        (node.network_profile(), node.wallet_destination())
    };
    ensure_pool_profile_supported(profile, config.production_v4_share_verifier.is_some())?;
    validate_private_address(config.bind)?;
    if config.max_connections == 0 || config.max_connections > POOL_MAX_CONNECTIONS {
        return Err(PoolError::InvalidConnectionLimit);
    }
    if let Some(policy) = config.payout_policy {
        if policy.minimum_payout_atoms == 0 || policy.fee_atoms == 0 {
            return Err(PoolError::InvalidPayoutPolicy);
        }
        if config.block_destination != wallet_destination {
            return Err(PoolError::PayoutWalletMismatch);
        }
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
    let ledger = DurableLedger::open(config.ledger_directory, network_id, consensus_fingerprint)?;
    let next_session_id = ledger.next_session_id()?;
    let shared = Arc::new(SharedServer {
        node,
        state: Mutex::new(ServerState {
            current: first,
            next_job_sequence: 1,
        }),
        ledger,
        stop: AtomicBool::new(false),
        active_connections: AtomicUsize::new(0),
        active_sockets: Mutex::new(HashMap::new()),
        next_connection_id: AtomicU64::new(0),
        next_session_id: AtomicU64::new(next_session_id),
        network_id,
        consensus_fingerprint,
        block_destination: config.block_destination,
        configured_share_target: config.share_target,
        test_credit_atoms_per_share: config.test_credit_atoms_per_share,
        payout_policy: config.payout_policy,
        max_connections: config.max_connections,
        proof_profile: profile.proof,
        production_v4_share_verifier: config.production_v4_share_verifier,
        tls,
        startup_nonce,
    });
    reconcile_pool_blocks_with_recovery(&shared, true)?;
    reconcile_pool_payouts(&shared, true)?;
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

fn ensure_pool_profile_supported(
    profile: NetworkProfile,
    has_production_v4_share_verifier: bool,
) -> Result<(), PoolError> {
    match profile.proof {
        ProofProfile::ProductionV3 => Err(PoolError::ProductionV3Unsupported),
        ProofProfile::ProductionV4 if !has_production_v4_share_verifier => {
            Err(PoolError::ProductionV4Unsupported)
        }
        ProofProfile::ProductionV4 | ProofProfile::DevnetV2Reference => Ok(()),
    }
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
    let authentication_nonce = random_nonce()?;
    write_frame(
        &mut stream,
        &ServerMessage::AuthChallenge {
            protocol_version: POOL_PROTOCOL_VERSION,
            network_id: shared.network_id,
            consensus_fingerprint: shared.consensus_fingerprint,
            nonce: authentication_nonce,
        },
    )?;
    let hello: ClientMessage =
        read_frame_interruptible_until(&mut stream, &shared.stop, handshake_deadline)?;
    let (worker, payout) = match hello {
        ClientMessage::Hello {
            protocol_version,
            network_id,
            consensus_fingerprint,
            worker,
            payout,
            payout_signature,
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
            let digest = payout_auth_digest(
                network_id,
                consensus_fingerprint,
                authentication_nonce,
                &worker,
                payout,
            );
            if verify_payout_authentication(payout, digest, &payout_signature).is_err() {
                send_error(
                    &mut stream,
                    "payout_authentication_failed",
                    "pool payout-key authentication failed",
                )?;
                return Err(PoolError::PayoutAuthentication);
            }
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
            persistence: ledger_persistence(&shared.ledger).to_owned(),
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
    ledger: &'a DurableLedger,
    session_id: u64,
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        let _ = self.ledger.transaction(|ledger| {
            if let Some(session) = ledger.sessions.get_mut(&self.session_id) {
                session.connected = false;
            }
            Ok(())
        });
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
    let evaluation = evaluate_pool_share(shared, &active, nonce)?;
    if evaluation.work_digest > active.wire.share_target {
        return rejected_result(shared, session_id, job_id, nonce, "low_difficulty_share");
    }
    let block = if let Some(proof) = &evaluation.chain_proof {
        let Some(block) = active.mining.build_block_if_chain_valid(proof)? else {
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

    let block_credit = PoolBlockCredit {
        block_id: block.block_id(),
        parent: block.challenge.previous_block,
        height: block.challenge.height,
    };
    reserve_pending_pool_block(
        &shared.ledger,
        session_id,
        block_credit,
        shared.test_credit_atoms_per_share,
    )?;

    // A ProductionV3 proof and side-branch reconstruction can take seconds.
    // Release the shared node before the bounded verifier worker runs; the
    // revision-bound helper rechecks the authoritative chain on commit.
    drop(node);
    loop {
        match submit_shared_tip_block(&shared.node, (*block).clone(), unix_time_seconds()?) {
            Ok(_) => break,
            Err(NodeError::StaleBlockAdmission | NodeError::UnknownParent(_)) => {
                discard_pending_pool_block(&shared.ledger, block_credit.block_id)?;
                rotate_if_tip_changed(shared)?;
                return rejected_result(shared, session_id, job_id, nonce, "stale_job");
            }
            Err(NodeError::DuplicateBlock(_)) => {
                reconcile_pool_blocks(shared)?;
                let session = pool_block_session_snapshot(&shared.ledger, block_credit.block_id)?;
                rotate_if_tip_changed(shared)?;
                return Ok(PoolShareResult {
                    job_id,
                    nonce,
                    accepted: true,
                    block_accepted: true,
                    code: "block_accepted".to_owned(),
                    session,
                });
            }
            Err(
                NodeError::ProofVerificationQueueFull | NodeError::ProofVerificationQueueTimeout,
            ) => {
                if shared.stop.load(Ordering::Acquire) {
                    if nonce_reserved {
                        release_valid_share(&active, nonce)?;
                    }
                    discard_pending_pool_block(&shared.ledger, block_credit.block_id)?;
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
                    discard_pending_pool_block(&shared.ledger, block_credit.block_id)?;
                    rotate_if_tip_changed(shared)?;
                    return rejected_result(shared, session_id, job_id, nonce, "stale_job");
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.client_error().retryable => {
                if nonce_reserved {
                    release_valid_share(&active, nonce)?;
                }
                discard_pending_pool_block(&shared.ledger, block_credit.block_id)?;
                return retryable_result(shared, session_id, job_id, nonce, "verifier_busy");
            }
            Err(error) => {
                reconcile_pool_blocks_with_recovery(shared, true)?;
                return Err(PoolError::Node(error));
            }
        }
    }

    let session = finalize_pending_pool_block(
        &shared.ledger,
        block_credit.block_id,
        PoolBlockState::Canonical,
        1,
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
        .state
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
    let changed = {
        // Node then pool-state is the only nested lock order in this module.
        // Keep both locks through template capture and installation so no
        // stale job can be published between the two operations.
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
            false
        } else {
            let mining = node.build_mining_job(shared.block_destination, unix_time_seconds()?)?;
            debug_assert_eq!(mining.challenge().previous_block, tip);
            let sequence = state.next_job_sequence;
            state.next_job_sequence = state.next_job_sequence.wrapping_add(1);
            let share_target =
                easier_target(shared.configured_share_target, mining.challenge().target);
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
            true
        }
    };
    if changed {
        reconcile_pool_blocks(shared)?;
        reconcile_pool_payouts(shared, true)?;
    }
    Ok(changed)
}

fn reconcile_pool_blocks(shared: &SharedServer) -> Result<(), PoolError> {
    reconcile_pool_blocks_with_recovery(shared, false)
}

fn reconcile_pool_blocks_with_recovery(
    shared: &SharedServer,
    recover_missing_pending: bool,
) -> Result<(), PoolError> {
    let block_ids = shared
        .ledger
        .state
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?
        .blocks
        .keys()
        .copied()
        .collect::<Vec<_>>();
    if block_ids.is_empty() {
        return Ok(());
    }
    let node = shared
        .node
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    let updates = block_ids
        .into_iter()
        .map(|block_id| {
            if let Some(confirmations) = node.active_chain_confirmations(block_id) {
                (block_id, PoolBlockState::Canonical, confirmations)
            } else if node.contains_block(block_id) {
                (block_id, PoolBlockState::Orphaned, 0)
            } else {
                (block_id, PoolBlockState::Unknown, 0)
            }
        })
        .collect::<Vec<_>>();
    drop(node);
    let changed = {
        let ledger = shared
            .ledger
            .state
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?;
        updates.iter().any(|(block_id, state, confirmations)| {
            ledger.blocks.get(block_id).is_some_and(|record| {
                if record.state == PoolBlockState::Pending {
                    *state != PoolBlockState::Unknown || recover_missing_pending
                } else {
                    record.state != *state || record.confirmations != *confirmations
                }
            })
        })
    };
    if !changed {
        return Ok(());
    }
    shared.ledger.transaction(|ledger| {
        for (block_id, state, confirmations) in updates {
            let record = *ledger.blocks.get(&block_id).ok_or_else(|| {
                PoolError::LedgerCorrupt("pool block disappeared during reconciliation".to_owned())
            })?;
            if record.state == PoolBlockState::Pending {
                if state == PoolBlockState::Unknown {
                    if recover_missing_pending {
                        ledger.blocks.remove(&block_id);
                    }
                    continue;
                }
                apply_accepted_share_credit(ledger, record.session_id, record.atoms, true)?;
            }
            let record = ledger.blocks.get_mut(&block_id).ok_or_else(|| {
                PoolError::LedgerCorrupt("pool block disappeared during reconciliation".to_owned())
            })?;
            record.state = state;
            record.confirmations = confirmations;
        }
        Ok(())
    })
}

fn reconcile_pool_payouts(shared: &SharedServer, create_new: bool) -> Result<(), PoolError> {
    let Some(policy) = shared.payout_policy else {
        return Ok(());
    };
    let records = shared
        .ledger
        .state
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?
        .payout_transactions
        .iter()
        .map(|(txid, record)| (*txid, record.clone()))
        .collect::<Vec<_>>();
    let mut updates = Vec::with_capacity(records.len());
    {
        let mut node = shared
            .node
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?;
        for (txid, record) in records {
            let (state, confirmations) = if let Some(confirmations) =
                node.active_transaction_confirmations(txid)?
            {
                (PoolPayoutTransactionState::Confirmed, confirmations)
            } else if node.mempool_contains_transaction(txid) {
                (PoolPayoutTransactionState::Broadcast, 0)
            } else if record.state == PoolPayoutTransactionState::Abandoned {
                (PoolPayoutTransactionState::Abandoned, 0)
            } else {
                match node.submit_transaction(record.transaction.clone()) {
                    Ok(_) | Err(NodeError::DuplicateMempoolTransaction(_)) => {
                        (PoolPayoutTransactionState::Broadcast, 0)
                    }
                    Err(NodeError::MempoolTransactionLimit | NodeError::MempoolByteLimit) => {
                        (PoolPayoutTransactionState::Prepared, 0)
                    }
                    Err(
                        NodeError::MempoolUnconfirmedInput(_) | NodeError::MempoolInputConflict(_),
                    ) => (PoolPayoutTransactionState::Abandoned, 0),
                    Err(error) => return Err(PoolError::Node(error)),
                }
            };
            if state != record.state || confirmations != record.confirmations {
                updates.push((txid, state, confirmations));
            }
        }
    }
    if !updates.is_empty() {
        shared.ledger.transaction(|ledger| {
            for (txid, state, confirmations) in updates {
                let record = ledger.payout_transactions.get_mut(&txid).ok_or_else(|| {
                    PoolError::LedgerCorrupt(
                        "payout transaction disappeared during reconciliation".to_owned(),
                    )
                })?;
                record.state = state;
                record.confirmations = confirmations;
            }
            Ok(())
        })?;
    }
    if !create_new {
        return Ok(());
    }

    for _ in 0..POOL_MAX_PAYOUTS_PER_TIP {
        let Some((payout, amount)) = next_payout_candidate(&shared.ledger, policy)? else {
            break;
        };
        let mut node = shared
            .node
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?;
        let (transaction, _) =
            match node.prepare_dev_wallet_payment(payout, amount, policy.fee_atoms) {
                Ok(prepared) => prepared,
                Err(
                    NodeError::WalletFundsImmature { .. }
                    | NodeError::WalletInsufficientFunds { .. }
                    | NodeError::WalletInputLimit { .. },
                ) => break,
                Err(error) => return Err(PoolError::Node(error)),
            };
        let txid = transaction.txid();
        let journaled = shared.ledger.transaction(|ledger| {
            if payout_available_atoms(ledger, payout)? < amount {
                return Ok(false);
            }
            if ledger.payout_transactions.len() >= POOL_MAX_LEDGER_PAYOUT_TRANSACTIONS {
                return Err(PoolError::LedgerCapacity);
            }
            if ledger
                .payout_transactions
                .insert(
                    txid,
                    PayoutTransactionRecord {
                        payout,
                        amount_atoms: amount,
                        fee_atoms: policy.fee_atoms,
                        transaction: transaction.clone(),
                        state: PoolPayoutTransactionState::Prepared,
                        confirmations: 0,
                    },
                )
                .is_some()
            {
                return Err(PoolError::LedgerCorrupt(
                    "payout transaction was journaled twice".to_owned(),
                ));
            }
            Ok(true)
        })?;
        if !journaled {
            continue;
        }
        let state = match node.submit_transaction(transaction) {
            Ok(_) | Err(NodeError::DuplicateMempoolTransaction(_)) => {
                PoolPayoutTransactionState::Broadcast
            }
            Err(NodeError::MempoolTransactionLimit | NodeError::MempoolByteLimit) => {
                PoolPayoutTransactionState::Prepared
            }
            Err(NodeError::MempoolUnconfirmedInput(_) | NodeError::MempoolInputConflict(_)) => {
                PoolPayoutTransactionState::Abandoned
            }
            Err(error) => return Err(PoolError::Node(error)),
        };
        if state != PoolPayoutTransactionState::Prepared {
            shared.ledger.transaction(|ledger| {
                let record = ledger.payout_transactions.get_mut(&txid).ok_or_else(|| {
                    PoolError::LedgerCorrupt("journaled payout transaction is missing".to_owned())
                })?;
                record.state = state;
                Ok(())
            })?;
        }
    }
    Ok(())
}

fn next_payout_candidate(
    ledger: &DurableLedger,
    policy: PoolPayoutPolicy,
) -> Result<Option<([u8; 32], u64)>, PoolError> {
    let ledger = ledger
        .state
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    for payout in ledger.payouts.keys().copied() {
        let available = payout_available_atoms(&ledger, payout)?;
        if available >= policy.minimum_payout_atoms {
            return Ok(Some((payout, available)));
        }
    }
    Ok(None)
}

fn payout_available_atoms(ledger: &Ledger, payout: [u8; 32]) -> Result<u64, PoolError> {
    let credited = ledger
        .payouts
        .get(&payout)
        .ok_or_else(|| PoolError::LedgerCorrupt("payout identity is missing".to_owned()))?
        .credited_devnet_atoms;
    let reserved = ledger
        .payout_transactions
        .values()
        .filter(|record| record.payout == payout && record.state.reserves_credit())
        .try_fold(0_u64, |total, record| {
            checked_ledger_add(total, record.amount_atoms, "reserved payout")
        })?;
    credited
        .checked_sub(reserved)
        .ok_or_else(|| PoolError::LedgerCorrupt("reserved payout exceeds earned credit".to_owned()))
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
    ledger: &DurableLedger,
    session_id: u64,
    worker: String,
    payout: [u8; 32],
) -> Result<(), PoolError> {
    ledger.transaction(|ledger| {
        while ledger.sessions.len() >= POOL_MAX_LEDGER_SESSIONS {
            let inactive = ledger
                .sessions
                .iter()
                .find_map(|(id, session)| (!session.connected).then_some(*id))
                .ok_or(PoolError::LedgerCapacity)?;
            ledger.sessions.remove(&inactive);
        }
        if !ledger.payouts.contains_key(&payout) && ledger.payouts.len() >= POOL_MAX_LEDGER_PAYOUTS
        {
            return Err(PoolError::LedgerCapacity);
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
    })
}

#[derive(Debug, Clone, Copy)]
struct PoolBlockCredit {
    block_id: [u8; 32],
    parent: [u8; 32],
    height: u64,
}

fn credit_accepted_share(
    ledger: &DurableLedger,
    session_id: u64,
    atoms: u64,
) -> Result<PoolSessionStats, PoolError> {
    ledger.transaction(|ledger| {
        apply_accepted_share_credit(ledger, session_id, atoms, false)?;
        session_snapshot(
            session_id,
            ledger.sessions.get(&session_id).expect("checked above"),
        )
    })
}

fn reserve_pending_pool_block(
    ledger: &DurableLedger,
    session_id: u64,
    block: PoolBlockCredit,
    atoms: u64,
) -> Result<(), PoolError> {
    ledger.transaction(|ledger| {
        let payout = ledger
            .sessions
            .get(&session_id)
            .ok_or_else(|| PoolError::InvalidMessage("unknown session".to_owned()))?
            .payout;
        if ledger.blocks.len() >= POOL_MAX_LEDGER_BLOCKS {
            return Err(PoolError::LedgerCapacity);
        }
        if ledger
            .blocks
            .insert(
                block.block_id,
                BlockRecord {
                    parent: block.parent,
                    height: block.height,
                    session_id,
                    payout,
                    atoms,
                    state: PoolBlockState::Pending,
                    confirmations: 0,
                },
            )
            .is_some()
        {
            return Err(PoolError::LedgerCorrupt(
                "pool block was reserved twice".to_owned(),
            ));
        }
        Ok(())
    })
}

fn discard_pending_pool_block(ledger: &DurableLedger, block_id: [u8; 32]) -> Result<(), PoolError> {
    ledger.transaction(|ledger| {
        if ledger
            .blocks
            .get(&block_id)
            .is_some_and(|record| record.state == PoolBlockState::Pending)
        {
            ledger.blocks.remove(&block_id);
        }
        Ok(())
    })
}

fn finalize_pending_pool_block(
    ledger: &DurableLedger,
    block_id: [u8; 32],
    state: PoolBlockState,
    confirmations: u64,
) -> Result<PoolSessionStats, PoolError> {
    if matches!(state, PoolBlockState::Pending | PoolBlockState::Unknown) {
        return Err(PoolError::LedgerCorrupt(
            "pool block cannot be finalized into an unresolved state".to_owned(),
        ));
    }
    ledger.transaction(|ledger| {
        let record = *ledger
            .blocks
            .get(&block_id)
            .ok_or_else(|| PoolError::LedgerCorrupt("pending pool block is missing".to_owned()))?;
        if record.state == PoolBlockState::Pending {
            apply_accepted_share_credit(ledger, record.session_id, record.atoms, true)?;
        }
        let stored = ledger
            .blocks
            .get_mut(&block_id)
            .ok_or_else(|| PoolError::LedgerCorrupt("pending pool block is missing".to_owned()))?;
        stored.state = state;
        stored.confirmations = confirmations;
        session_snapshot(
            record.session_id,
            ledger
                .sessions
                .get(&record.session_id)
                .ok_or_else(|| PoolError::InvalidMessage("unknown session".to_owned()))?,
        )
    })
}

fn pool_block_session_snapshot(
    ledger: &DurableLedger,
    block_id: [u8; 32],
) -> Result<PoolSessionStats, PoolError> {
    let ledger = ledger
        .state
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    let record = ledger
        .blocks
        .get(&block_id)
        .ok_or_else(|| PoolError::LedgerCorrupt("pool block is missing".to_owned()))?;
    if record.state == PoolBlockState::Pending {
        return Err(PoolError::LedgerCorrupt(
            "duplicate pool block did not resolve".to_owned(),
        ));
    }
    session_snapshot(
        record.session_id,
        ledger
            .sessions
            .get(&record.session_id)
            .ok_or_else(|| PoolError::InvalidMessage("unknown session".to_owned()))?,
    )
}

fn apply_accepted_share_credit(
    ledger: &mut Ledger,
    session_id: u64,
    atoms: u64,
    is_block: bool,
) -> Result<(), PoolError> {
    let payout = ledger
        .sessions
        .get(&session_id)
        .ok_or_else(|| PoolError::InvalidMessage("unknown session".to_owned()))?
        .payout;
    ledger.accepted_shares = checked_ledger_add(ledger.accepted_shares, 1, "accepted shares")?;
    ledger.credited_devnet_atoms =
        checked_ledger_add(ledger.credited_devnet_atoms, atoms, "credited test atoms")?;
    if is_block {
        ledger.pool_blocks = checked_ledger_add(ledger.pool_blocks, 1, "pool blocks")?;
    }
    {
        let session = ledger.sessions.get_mut(&session_id).expect("checked above");
        session.accepted_shares =
            checked_ledger_add(session.accepted_shares, 1, "session accepted shares")?;
        session.credited_devnet_atoms = checked_ledger_add(
            session.credited_devnet_atoms,
            atoms,
            "session credited test atoms",
        )?;
        if is_block {
            session.pool_blocks =
                checked_ledger_add(session.pool_blocks, 1, "session pool blocks")?;
        }
    }
    {
        let payout = ledger.payouts.entry(payout).or_default();
        payout.last_session_id = session_id;
        payout.accepted_shares =
            checked_ledger_add(payout.accepted_shares, 1, "payout accepted shares")?;
        payout.credited_devnet_atoms = checked_ledger_add(
            payout.credited_devnet_atoms,
            atoms,
            "payout credited test atoms",
        )?;
        if is_block {
            payout.pool_blocks = checked_ledger_add(payout.pool_blocks, 1, "payout pool blocks")?;
        }
    }
    Ok(())
}

fn credit_rejected_share(
    ledger: &DurableLedger,
    session_id: u64,
) -> Result<PoolSessionStats, PoolError> {
    ledger.transaction(|ledger| {
        let payout = ledger
            .sessions
            .get(&session_id)
            .ok_or_else(|| PoolError::InvalidMessage("unknown session".to_owned()))?
            .payout;
        ledger.rejected_shares = checked_ledger_add(ledger.rejected_shares, 1, "rejected shares")?;
        let session = ledger.sessions.get_mut(&session_id).expect("checked above");
        session.rejected_shares =
            checked_ledger_add(session.rejected_shares, 1, "session rejected shares")?;
        let payout = ledger.payouts.entry(payout).or_default();
        payout.last_session_id = session_id;
        payout.rejected_shares =
            checked_ledger_add(payout.rejected_shares, 1, "payout rejected shares")?;
        session_snapshot(
            session_id,
            ledger.sessions.get(&session_id).expect("checked above"),
        )
    })
}

fn checked_ledger_add(value: u64, increment: u64, label: &str) -> Result<u64, PoolError> {
    value
        .checked_add(increment)
        .ok_or_else(|| PoolError::LedgerCorrupt(format!("{label} overflow")))
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

fn snapshot_ledger(ledger: &DurableLedger) -> Result<PoolLedgerSnapshot, PoolError> {
    let persistence = ledger_persistence(ledger).to_owned();
    let ledger = ledger
        .state
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    let sessions = ledger
        .sessions
        .iter()
        .map(|(session_id, record)| session_snapshot(*session_id, record))
        .collect::<Result<Vec<_>, _>>()?;
    let payouts = ledger
        .payouts
        .iter()
        .map(|(payout, record)| {
            let available_payout_atoms = payout_available_atoms(&ledger, *payout)?;
            let confirmed_payout_atoms = ledger
                .payout_transactions
                .values()
                .filter(|transaction| {
                    transaction.payout == *payout
                        && transaction.state == PoolPayoutTransactionState::Confirmed
                })
                .try_fold(0_u64, |total, transaction| {
                    checked_ledger_add(total, transaction.amount_atoms, "confirmed payout")
                })?;
            Ok::<_, PoolError>(PoolPayoutStats {
                payout: hex::encode(payout),
                accepted_shares: record.accepted_shares,
                rejected_shares: record.rejected_shares,
                pool_blocks: record.pool_blocks,
                credited_devnet_atoms: record.credited_devnet_atoms,
                reserved_payout_atoms: record.credited_devnet_atoms - available_payout_atoms,
                confirmed_payout_atoms,
                available_payout_atoms,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let blocks = ledger
        .blocks
        .iter()
        .map(|(block_id, record)| PoolBlockStats {
            block_id: hex::encode(block_id),
            parent: hex::encode(record.parent),
            height: record.height,
            payout: hex::encode(record.payout),
            state: record.state.label().to_owned(),
            confirmations: record.confirmations,
        })
        .collect::<Vec<_>>();
    let payout_transactions = ledger
        .payout_transactions
        .iter()
        .map(|(txid, record)| PoolPayoutTransactionStats {
            txid: hex::encode(txid),
            payout: hex::encode(record.payout),
            amount_atoms: record.amount_atoms,
            fee_atoms: record.fee_atoms,
            state: record.state.label().to_owned(),
            confirmations: record.confirmations,
        })
        .collect::<Vec<_>>();
    let canonical_pool_blocks = ledger
        .blocks
        .values()
        .filter(|record| record.state == PoolBlockState::Canonical)
        .count() as u64;
    let orphaned_pool_blocks = ledger
        .blocks
        .values()
        .filter(|record| record.state == PoolBlockState::Orphaned)
        .count() as u64;
    Ok(PoolLedgerSnapshot {
        accounting_semantics: POOL_ACCOUNTING_SEMANTICS.to_owned(),
        persistence,
        accepted_shares: ledger.accepted_shares,
        rejected_shares: ledger.rejected_shares,
        pool_blocks: ledger.pool_blocks,
        credited_devnet_atoms: ledger.credited_devnet_atoms,
        canonical_pool_blocks,
        orphaned_pool_blocks,
        sessions,
        payouts,
        blocks,
        payout_transactions,
    })
}

fn ledger_persistence(ledger: &DurableLedger) -> &'static str {
    if ledger.store.is_some() {
        "durable two-slot ledger; network-bound and checksummed"
    } else {
        "memory-only; reset on pool process restart"
    }
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

#[derive(Debug)]
struct VerifiedPoolShare {
    work_digest: [u8; 32],
    chain_proof: Option<BlockProof>,
}

fn evaluate_pool_share(
    shared: &SharedServer,
    active: &ActiveJob,
    nonce: u64,
) -> Result<VerifiedPoolShare, PoolError> {
    match shared.proof_profile {
        ProofProfile::DevnetV2Reference => {
            let evaluation = active
                .mining
                .evaluate_share(nonce, active.wire.share_target)?;
            Ok(VerifiedPoolShare {
                work_digest: evaluation.work_digest,
                chain_proof: evaluation.meets_chain_target.then_some(evaluation.proof),
            })
        }
        ProofProfile::ProductionV3 => Err(PoolError::ProductionV3Unsupported),
        ProofProfile::ProductionV4 => evaluate_production_v4_pool_share(
            shared.production_v4_share_verifier.as_deref(),
            &active.mining.template,
            nonce,
            active.wire.share_target,
        ),
    }
}

fn evaluate_production_v4_pool_share(
    verifier: Option<&dyn ProductionV4PoolShareVerifier>,
    template: &crate::BlockTemplate,
    nonce: u64,
    share_target: [u8; 32],
) -> Result<VerifiedPoolShare, PoolError> {
    let verifier = verifier.ok_or(PoolError::ProductionV4Unsupported)?;
    let evaluation = verifier.evaluate(template, nonce, share_target)?;
    let meets_chain_target = evaluation.work_digest <= template.challenge.target;
    match (meets_chain_target, evaluation.chain_proof) {
        (true, Some(proof)) if proof.work_digest() == evaluation.work_digest => {
            Ok(VerifiedPoolShare {
                work_digest: evaluation.work_digest,
                chain_proof: Some(proof),
            })
        }
        (true, Some(_)) => Err(PoolError::ProductionV4ProofMismatch),
        (true, None) => Err(PoolError::ProductionV4ChainProofMissing),
        (false, Some(_)) => Err(PoolError::ProductionV4UnexpectedChainProof),
        (false, None) => Ok(VerifiedPoolShare {
            work_digest: evaluation.work_digest,
            chain_proof: None,
        }),
    }
}

impl PoolClient {
    pub fn connect(config: PoolClientConfig) -> Result<Self, PoolError> {
        validate_private_address(config.address)?;
        validate_worker(&config.worker)?;
        VerifyingKey::from_bytes(&config.payout)
            .map_err(|_| PoolError::Node(NodeError::InvalidMinerDestination))?;
        if config.payout != config.payout_signer.payout() {
            return Err(PoolError::PayoutAuthentication);
        }
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
        let authentication_nonce = match read_frame(&mut stream)? {
            ServerMessage::AuthChallenge {
                protocol_version,
                network_id,
                consensus_fingerprint,
                nonce,
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
                nonce
            }
            ServerMessage::Error { code, .. } => return Err(server_error(code)),
            _ => {
                return Err(PoolError::InvalidMessage(
                    "expected pool payout authentication challenge".to_owned(),
                ));
            }
        };
        let payout_signature = config.payout_signer.sign(payout_auth_digest(
            config.expected_network_id,
            config.expected_consensus_fingerprint,
            authentication_nonce,
            &config.worker,
            config.payout,
        ));
        write_frame(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: POOL_PROTOCOL_VERSION,
                network_id: config.expected_network_id,
                consensus_fingerprint: config.expected_consensus_fingerprint,
                worker: config.worker,
                payout: config.payout,
                payout_signature,
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
            ServerMessage::AuthChallenge { .. } | ServerMessage::HelloAck { .. } => Err(
                PoolError::InvalidMessage("unexpected pool handshake message".to_owned()),
            ),
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

fn payout_auth_digest(
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    challenge_nonce: [u8; 32],
    worker: &str,
    payout: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(POOL_PAYOUT_AUTH_DOMAIN);
    hasher.update(&POOL_PROTOCOL_VERSION.to_le_bytes());
    hasher.update(&network_id);
    hasher.update(&consensus_fingerprint);
    hasher.update(&challenge_nonce);
    hasher.update(&(worker.len() as u64).to_le_bytes());
    hasher.update(worker.as_bytes());
    hasher.update(&payout);
    *hasher.finalize().as_bytes()
}

fn verify_payout_authentication(
    payout: [u8; 32],
    digest: [u8; 32],
    signature: &[u8],
) -> Result<(), PoolError> {
    let key = VerifyingKey::from_bytes(&payout).map_err(|_| PoolError::PayoutAuthentication)?;
    let signature = Signature::try_from(signature).map_err(|_| PoolError::PayoutAuthentication)?;
    key.verify(&digest, &signature)
        .map_err(|_| PoolError::PayoutAuthentication)
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
        "payout_authentication_failed" => PoolError::PayoutAuthentication,
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

    #[derive(Debug)]
    struct FixedProductionV4ShareVerifier {
        evaluation: ProductionV4PoolShareEvaluation,
    }

    impl ProductionV4PoolShareVerifier for FixedProductionV4ShareVerifier {
        fn evaluate(
            &self,
            _template: &crate::BlockTemplate,
            _nonce: u64,
            _share_target: [u8; 32],
        ) -> Result<ProductionV4PoolShareEvaluation, PoolError> {
            Ok(self.evaluation.clone())
        }
    }

    fn production_v4_share_template() -> crate::BlockTemplate {
        crate::BlockTemplate {
            challenge: BlockChallenge {
                network_id: [1; 32],
                previous_block: [2; 32],
                transaction_root: [3; 32],
                height: 4,
                timestamp: 5,
                target: [0x80; 32],
            },
            coinbase: cmfd_consensus::Coinbase {
                height: 4,
                outputs: Vec::new(),
            },
            transactions: Vec::new(),
            total_fees_burned: 0,
        }
    }

    fn test_proof(work_digest: [u8; 32]) -> BlockProof {
        BlockProof::V1Legacy(cmfd_consensus::ForgeMatrixProof {
            algorithm_version: 1,
            model_version: 1,
            nonce: 7,
            model_root: [8; 32],
            output_digest: [9; 32],
            work_digest,
        })
    }

    #[test]
    fn production_pool_profiles_fail_closed_without_share_verifiers() {
        assert!(matches!(
            ensure_pool_profile_supported(crate::RCNET1_PROFILE, false),
            Err(PoolError::ProductionV3Unsupported)
        ));
        assert!(matches!(
            ensure_pool_profile_supported(crate::PRODUCTION_V4_TESTNET_PROFILE, false),
            Err(PoolError::ProductionV4Unsupported)
        ));
        assert!(ensure_pool_profile_supported(crate::PRODUCTION_V4_TESTNET_PROFILE, true).is_ok());
        assert!(ensure_pool_profile_supported(crate::DEVNET_PROFILE, false).is_ok());
    }

    #[test]
    fn production_v4_share_replay_boundary_is_fail_closed() {
        let template = production_v4_share_template();
        assert!(matches!(
            evaluate_production_v4_pool_share(None, &template, 7, [0xff; 32]),
            Err(PoolError::ProductionV4Unsupported)
        ));

        let ordinary = FixedProductionV4ShareVerifier {
            evaluation: ProductionV4PoolShareEvaluation {
                work_digest: [0xff; 32],
                chain_proof: None,
            },
        };
        let ordinary =
            evaluate_production_v4_pool_share(Some(&ordinary), &template, 7, [0xff; 32]).unwrap();
        assert_eq!(ordinary.work_digest, [0xff; 32]);
        assert!(ordinary.chain_proof.is_none());

        let missing = FixedProductionV4ShareVerifier {
            evaluation: ProductionV4PoolShareEvaluation {
                work_digest: [0; 32],
                chain_proof: None,
            },
        };
        assert!(matches!(
            evaluate_production_v4_pool_share(Some(&missing), &template, 7, [0xff; 32]),
            Err(PoolError::ProductionV4ChainProofMissing)
        ));

        let mismatched = FixedProductionV4ShareVerifier {
            evaluation: ProductionV4PoolShareEvaluation {
                work_digest: [0; 32],
                chain_proof: Some(test_proof([1; 32])),
            },
        };
        assert!(matches!(
            evaluate_production_v4_pool_share(Some(&mismatched), &template, 7, [0xff; 32]),
            Err(PoolError::ProductionV4ProofMismatch)
        ));

        let unexpected = FixedProductionV4ShareVerifier {
            evaluation: ProductionV4PoolShareEvaluation {
                work_digest: [0xff; 32],
                chain_proof: Some(test_proof([0xff; 32])),
            },
        };
        assert!(matches!(
            evaluate_production_v4_pool_share(Some(&unexpected), &template, 7, [0xff; 32]),
            Err(PoolError::ProductionV4UnexpectedChainProof)
        ));

        let winning = FixedProductionV4ShareVerifier {
            evaluation: ProductionV4PoolShareEvaluation {
                work_digest: [0; 32],
                chain_proof: Some(test_proof([0; 32])),
            },
        };
        let winning =
            evaluate_production_v4_pool_share(Some(&winning), &template, 7, [0xff; 32]).unwrap();
        assert_eq!(winning.work_digest, [0; 32]);
        assert_eq!(winning.chain_proof.unwrap().work_digest(), [0; 32]);
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
        let node = Arc::new(Mutex::new(
            Node::open_with_profile(data, crate::DEVNET_PROFILE).unwrap(),
        ));
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
            PoolClientConfig::devnet(address, pin, worker, test_payout_signer()).unwrap(),
        )
        .unwrap()
    }

    fn test_payout_signer() -> PoolPayoutSigner {
        let signer = PoolPayoutSigner::new(SigningKey::from_bytes(&[0x13; 32]).unwrap());
        assert_eq!(signer.payout(), default_miner_destination());
        signer
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
                test_payout_signer(),
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
        let mut wrong_network =
            PoolClientConfig::devnet(server.local_addr(), pin, "worker", test_payout_signer())
                .unwrap();
        wrong_network.expected_network_id[0] ^= 1;
        assert!(matches!(
            PoolClient::connect(wrong_network).unwrap_err(),
            PoolError::NetworkMismatch
        ));

        let mut wrong_fingerprint =
            PoolClientConfig::devnet(server.local_addr(), pin, "worker", test_payout_signer())
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
                test_payout_signer(),
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
    fn payout_authentication_binds_key_network_challenge_and_worker() {
        let signer = test_payout_signer();
        let other = PoolPayoutSigner::new(SigningKey::from_bytes(&[0x21; 32]).unwrap());
        let network = [0x31; 32];
        let fingerprint = [0x32; 32];
        let challenge = [0x33; 32];
        let digest =
            payout_auth_digest(network, fingerprint, challenge, "worker-a", signer.payout());
        let signature = signer.sign(digest);
        verify_payout_authentication(signer.payout(), digest, &signature).unwrap();

        for changed in [
            payout_auth_digest(
                network,
                fingerprint,
                [0x34; 32],
                "worker-a",
                signer.payout(),
            ),
            payout_auth_digest(network, fingerprint, challenge, "worker-b", signer.payout()),
            payout_auth_digest(network, fingerprint, challenge, "worker-a", other.payout()),
        ] {
            assert!(matches!(
                verify_payout_authentication(signer.payout(), changed, &signature),
                Err(PoolError::PayoutAuthentication)
            ));
        }
        assert!(matches!(
            verify_payout_authentication(other.payout(), digest, &signature),
            Err(PoolError::PayoutAuthentication)
        ));
        assert!(matches!(
            verify_payout_authentication(signer.payout(), digest, &[0_u8; 63]),
            Err(PoolError::PayoutAuthentication)
        ));
    }

    #[test]
    fn share_only_credit_duplicate_rejection_and_session_ledger_are_real() {
        let (_root, server, _node, pin) = server("share-ledger");
        let mut client = client(server.local_addr(), pin, "worker-a");
        assert!(
            client
                .accounting_semantics()
                .contains("authenticated Devnet accounting")
        );
        assert!(client.persistence().contains("memory-only"));
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
    fn durable_ledger_recovers_the_newest_valid_network_bound_slot() {
        let root = TestRoot::new("durable-ledger");
        let directory = root.path().join("ledger");
        let network_id = [0x31; 32];
        let fingerprint = [0x32; 32];
        let payout = default_miner_destination();
        {
            let ledger =
                DurableLedger::open(Some(directory.clone()), network_id, fingerprint).unwrap();
            register_session(&ledger, 1, "worker".to_owned(), payout).unwrap();
            credit_accepted_share(&ledger, 1, 7).unwrap();
            let snapshot = snapshot_ledger(&ledger).unwrap();
            assert_eq!(snapshot.accepted_shares, 1);
            assert_eq!(snapshot.credited_devnet_atoms, 7);
            assert!(snapshot.persistence.contains("durable"));
        }

        let recovered =
            DurableLedger::open(Some(directory.clone()), network_id, fingerprint).unwrap();
        assert_eq!(recovered.next_session_id().unwrap(), 2);
        let snapshot = snapshot_ledger(&recovered).unwrap();
        assert_eq!(snapshot.accepted_shares, 1);
        assert!(!snapshot.sessions[0].connected);
        drop(recovered);

        fs::write(directory.join("pool-ledger-v2.0.json"), b"corrupt").unwrap();
        let fallback =
            DurableLedger::open(Some(directory.clone()), network_id, fingerprint).unwrap();
        assert_eq!(snapshot_ledger(&fallback).unwrap().accepted_shares, 0);
        drop(fallback);

        fs::write(directory.join("pool-ledger-v2.1.json"), b"also-corrupt").unwrap();
        assert!(matches!(
            DurableLedger::open(Some(directory), network_id, fingerprint),
            Err(PoolError::LedgerCorrupt(_))
        ));
    }

    #[test]
    fn durable_ledger_migrates_authenticated_v1_accounting() {
        let root = TestRoot::new("ledger-v1-migration");
        let directory = root.path().join("ledger");
        fs::create_dir_all(&directory).unwrap();
        let network_id = [0x41; 32];
        let fingerprint = [0x42; 32];
        let payout = default_miner_destination();
        let ledger = DurableLedger::open(None, network_id, fingerprint).unwrap();
        register_session(&ledger, 1, "worker".to_owned(), payout).unwrap();
        credit_accepted_share(&ledger, 1, 9).unwrap();
        let generation = ledger.state.lock().unwrap().generation;
        let current = ledger_payload(&ledger.state.lock().unwrap());
        let payload = LegacyStoredLedgerPayloadV1 {
            accepted_shares: current.accepted_shares,
            rejected_shares: current.rejected_shares,
            pool_blocks: current.pool_blocks,
            credited_devnet_atoms: current.credited_devnet_atoms,
            sessions: current.sessions,
            payouts: current.payouts,
            blocks: current.blocks,
        };
        let stored = LegacyStoredLedgerV1 {
            format_version: LEGACY_POOL_LEDGER_FORMAT_VERSION,
            generation,
            network_id,
            consensus_fingerprint: fingerprint,
            payload_blake3: legacy_ledger_payload_checksum(
                generation,
                network_id,
                fingerprint,
                &payload,
            )
            .unwrap(),
            payload,
        };
        fs::write(
            directory.join(format!(
                "{LEGACY_POOL_LEDGER_FILE_PREFIX}.{}.json",
                generation & 1
            )),
            serde_json::to_vec(&stored).unwrap(),
        )
        .unwrap();

        let migrated =
            DurableLedger::open(Some(directory.clone()), network_id, fingerprint).unwrap();
        let snapshot = snapshot_ledger(&migrated).unwrap();
        assert_eq!(snapshot.accepted_shares, 1);
        assert_eq!(snapshot.credited_devnet_atoms, 9);
        assert!(snapshot.payout_transactions.is_empty());
        assert!(
            directory
                .join(format!("{POOL_LEDGER_FILE_PREFIX}.{}.json", generation & 1))
                .is_file()
        );
    }

    #[test]
    fn payout_policy_requires_nonzero_values_and_the_pool_wallet() {
        let root = TestRoot::new("payout-policy");
        let node = Arc::new(Mutex::new(
            Node::open_with_profile(root.path().join("node"), crate::DEVNET_PROFILE).unwrap(),
        ));
        let pool_wallet = node.lock().unwrap().wallet_destination();
        let (certificate, key, _) = certificate(&root);
        let certificate = fs::read(certificate).unwrap();
        let key = fs::read(key).unwrap();
        let mut invalid = PoolServerConfig::devnet(
            "127.0.0.1:0".parse().unwrap(),
            certificate.clone(),
            key.clone(),
            pool_wallet,
        );
        invalid.payout_policy = Some(PoolPayoutPolicy {
            minimum_payout_atoms: 0,
            fee_atoms: 1,
        });
        assert!(matches!(
            spawn_pool_server(Arc::clone(&node), invalid),
            Err(PoolError::InvalidPayoutPolicy)
        ));

        let other_destination: [u8; 32] = SigningKey::from_bytes(&[0x62; 32])
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into();
        let mut mismatched = PoolServerConfig::devnet(
            "127.0.0.1:0".parse().unwrap(),
            certificate,
            key,
            other_destination,
        );
        mismatched.payout_policy = Some(PoolPayoutPolicy::default());
        assert!(matches!(
            spawn_pool_server(node, mismatched),
            Err(PoolError::PayoutWalletMismatch)
        ));
    }

    #[test]
    fn pending_pool_block_journal_recovers_and_credits_exactly_once() {
        let root = TestRoot::new("pending-block-journal");
        let directory = root.path().join("ledger");
        let network_id = [0x51; 32];
        let fingerprint = [0x52; 32];
        let payout = default_miner_destination();
        let block = PoolBlockCredit {
            block_id: [0x53; 32],
            parent: [0x54; 32],
            height: 7,
        };
        {
            let ledger =
                DurableLedger::open(Some(directory.clone()), network_id, fingerprint).unwrap();
            register_session(&ledger, 1, "worker".to_owned(), payout).unwrap();
            reserve_pending_pool_block(&ledger, 1, block, 11).unwrap();
            let pending = snapshot_ledger(&ledger).unwrap();
            assert_eq!(pending.accepted_shares, 0);
            assert_eq!(pending.pool_blocks, 0);
            assert_eq!(pending.blocks[0].state, "pending");
        }

        let recovered =
            DurableLedger::open(Some(directory.clone()), network_id, fingerprint).unwrap();
        finalize_pending_pool_block(&recovered, block.block_id, PoolBlockState::Canonical, 1)
            .unwrap();
        finalize_pending_pool_block(&recovered, block.block_id, PoolBlockState::Canonical, 1)
            .unwrap();
        drop(recovered);

        let recovered = DurableLedger::open(Some(directory), network_id, fingerprint).unwrap();
        let snapshot = snapshot_ledger(&recovered).unwrap();
        assert_eq!(snapshot.accepted_shares, 1);
        assert_eq!(snapshot.pool_blocks, 1);
        assert_eq!(snapshot.credited_devnet_atoms, 11);
        assert_eq!(snapshot.payouts[0].accepted_shares, 1);
        assert_eq!(snapshot.blocks[0].state, "canonical");
    }

    #[test]
    fn authenticated_credits_settle_on_chain_and_confirm() {
        let root = TestRoot::new("on-chain-payout");
        let node = Arc::new(Mutex::new(
            Node::open_with_profile(root.path().join("node"), crate::DEVNET_PROFILE).unwrap(),
        ));
        let pool_wallet = node.lock().unwrap().wallet_destination();
        let now = unix_time_seconds().unwrap();
        for offset in 0..100 {
            node.lock()
                .unwrap()
                .mine_once(pool_wallet, now + offset, 10_000)
                .unwrap();
        }
        let (certificate, key, _pin) = certificate(&root);
        let mut config = PoolServerConfig::devnet(
            "127.0.0.1:0".parse().unwrap(),
            fs::read(certificate).unwrap(),
            fs::read(key).unwrap(),
            pool_wallet,
        );
        config.ledger_directory = Some(root.path().join("ledger"));
        config.payout_policy = Some(PoolPayoutPolicy {
            minimum_payout_atoms: 100,
            fee_atoms: 1,
        });
        let server = spawn_pool_server(Arc::clone(&node), config).unwrap();
        let recipient =
            PoolPayoutSigner::new(SigningKey::from_bytes(&[0x61; 32]).unwrap()).payout();
        register_session(&server.shared.ledger, 1, "worker".to_owned(), recipient).unwrap();
        credit_accepted_share(&server.shared.ledger, 1, 120).unwrap();

        reconcile_pool_payouts(&server.shared, true).unwrap();
        let broadcast = server.ledger_snapshot().unwrap();
        assert_eq!(broadcast.payout_transactions.len(), 1);
        assert_eq!(broadcast.payout_transactions[0].state, "broadcast");
        assert_eq!(broadcast.payout_transactions[0].amount_atoms, 120);
        assert_eq!(broadcast.payouts[0].reserved_payout_atoms, 120);
        assert_eq!(broadcast.payouts[0].available_payout_atoms, 0);
        let txid: [u8; 32] = hex::decode(&broadcast.payout_transactions[0].txid)
            .unwrap()
            .try_into()
            .unwrap();
        assert!(node.lock().unwrap().mempool_contains_transaction(txid));

        node.lock()
            .unwrap()
            .mine_once(pool_wallet, now + 100, 10_000)
            .unwrap();
        reconcile_pool_payouts(&server.shared, false).unwrap();
        let confirmed = server.ledger_snapshot().unwrap();
        assert_eq!(confirmed.payout_transactions.len(), 1);
        assert_eq!(confirmed.payout_transactions[0].state, "confirmed");
        assert_eq!(confirmed.payout_transactions[0].confirmations, 1);
        assert_eq!(confirmed.payouts[0].confirmed_payout_atoms, 120);

        let mut fork =
            Node::open_with_profile(root.path().join("fork"), crate::DEVNET_PROFILE).unwrap();
        let alternate_destination: [u8; 32] = SigningKey::from_bytes(&[0x63; 32])
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into();
        let mut alternate = Vec::new();
        for offset in 0..102 {
            alternate.push(
                fork.mine_once(alternate_destination, now + offset, 10_000)
                    .unwrap(),
            );
        }
        {
            let mut node = node.lock().unwrap();
            for (offset, block) in alternate.into_iter().enumerate() {
                node.submit_block(block, now + offset as u64).unwrap();
            }
        }
        reconcile_pool_payouts(&server.shared, false).unwrap();
        let reorganized = server.ledger_snapshot().unwrap();
        assert_eq!(reorganized.payout_transactions[0].state, "abandoned");
        assert_eq!(reorganized.payout_transactions[0].confirmations, 0);
        assert_eq!(reorganized.payouts[0].confirmed_payout_atoms, 0);
        assert_eq!(reorganized.payouts[0].available_payout_atoms, 120);

        server.stop().unwrap();
        let params = devnet_pool_params().unwrap();
        let recovered = DurableLedger::open(
            Some(root.path().join("ledger")),
            params.network_id,
            params.fingerprint().unwrap(),
        )
        .unwrap();
        let recovered = snapshot_ledger(&recovered).unwrap();
        assert_eq!(recovered.payout_transactions.len(), 1);
        assert_eq!(recovered.payout_transactions[0].state, "abandoned");
        assert_eq!(recovered.payouts[0].confirmed_payout_atoms, 0);
        assert_eq!(recovered.payouts[0].available_payout_atoms, 120);
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

        let ledger = DurableLedger {
            state: Mutex::new(Ledger::default()),
            store: None,
        };
        for session_id in 1..=(POOL_MAX_LEDGER_SESSIONS as u64 + 1) {
            register_session(&ledger, session_id, format!("w{session_id}"), [0x22; 32]).unwrap();
            ledger
                .state
                .lock()
                .unwrap()
                .sessions
                .get_mut(&session_id)
                .unwrap()
                .connected = false;
        }
        assert_eq!(
            ledger.state.lock().unwrap().sessions.len(),
            POOL_MAX_LEDGER_SESSIONS
        );

        let payout_ledger = DurableLedger {
            state: Mutex::new(Ledger::default()),
            store: None,
        };
        {
            let mut ledger = payout_ledger.state.lock().unwrap();
            for index in 0..POOL_MAX_LEDGER_PAYOUTS {
                let mut secret = [0_u8; 32];
                secret[24..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
                let payout: [u8; 32] = k256::schnorr::SigningKey::from_bytes(&secret)
                    .unwrap()
                    .verifying_key()
                    .to_bytes()
                    .into();
                ledger.payouts.insert(
                    payout,
                    PayoutRecord {
                        last_session_id: index as u64,
                        ..PayoutRecord::default()
                    },
                );
            }
        }
        assert!(matches!(
            register_session(&payout_ledger, 9_999, "new".to_owned(), [0x22; 32]),
            Err(PoolError::LedgerCapacity)
        ));
        assert_eq!(
            payout_ledger.state.lock().unwrap().payouts.len(),
            POOL_MAX_LEDGER_PAYOUTS
        );
        server.stop().unwrap();
    }

    #[test]
    fn pool_block_ledger_marks_a_reorganized_block_orphaned() {
        let (root, server, node, pin) = server("pool-block-reorg");
        let mut client = client(server.local_addr(), pin, "pool-worker");
        let work = client.current_work().unwrap();
        let nonce = find_share(&work, true);
        let accepted = client.submit_share(work.job().job_id, nonce).unwrap();
        assert!(accepted.block_accepted);
        let initial = server.ledger_snapshot().unwrap();
        assert_eq!(initial.canonical_pool_blocks, 1);
        assert_eq!(initial.orphaned_pool_blocks, 0);

        let mut fork =
            Node::open_with_profile(root.path().join("fork"), crate::DEVNET_PROFILE).unwrap();
        let alternate_destination: [u8; 32] = k256::schnorr::SigningKey::from_bytes(&[0x41; 32])
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into();
        let now = unix_time_seconds().unwrap();
        let first = fork
            .mine_once(alternate_destination, now, crate::DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let second = fork
            .mine_once(
                alternate_destination,
                now + 1,
                crate::DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        {
            let mut node = node.lock().unwrap();
            node.submit_block(first, now).unwrap();
            node.submit_block(second, now + 1).unwrap();
        }

        let reorganized = server.ledger_snapshot().unwrap();
        assert_eq!(reorganized.canonical_pool_blocks, 0);
        assert_eq!(reorganized.orphaned_pool_blocks, 1);
        assert_eq!(reorganized.blocks[0].state, "orphaned");
        assert_eq!(reorganized.blocks[0].confirmations, 0);
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
