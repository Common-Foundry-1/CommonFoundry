use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use blake3::Hasher;
#[cfg(any(test, feature = "production-v3"))]
use cmfd_consensus::PowParameters;
use cmfd_consensus::chain::{ReversibleStateDeltaCapability, ValidatedBlock};
use cmfd_consensus::{
    BLOCK_VERSION, Block, BlockChallenge, BlockProof, BlockValidationContext, COIN, ChainError,
    ChainState, Coinbase, ConsensusPowVerifier, DEFAULT_MONETARY_POLICY,
    DecodedReversibleStateDelta, EconomicsError, FixedRewardDestinations, ForgeMatrixError,
    ForgeMatrixV2AcceleratorBatch, ForgeMatrixV2AcceleratorModel, ForgeMatrixV2Error, InputWitness,
    MAX_BLOCK_BYTES, MAX_FUTURE_OFFSET_SECS, MAX_REVERSIBLE_STATE_DELTA_BYTES,
    MAX_TRANSACTION_BYTES, MAX_TRANSACTION_INPUTS, NETWORK_PROTOCOL_VERSION, NetworkError,
    NetworkParams, OutPoint, OutputLock, PowError, PreverifiedBlockProof,
    ReversibleStateDeltaError, SuccessorHeaderPreflight, TRANSACTION_VERSION, Transaction, TxInput,
    TxOutput, WireError, add_chain_work, chain_work_bytes, decode_block, decode_transaction,
    encode_block, encode_transaction, merkle_root, v2_reference_for_network,
    validate_block_preamble, validate_block_resources,
};
#[cfg(feature = "production-v3")]
use cmfd_consensus::{
    ForgeMatrixV3AcceleratorBatch, ForgeMatrixV3CandidateParameters,
    ForgeMatrixV3WinningNonceClaim, MAX_PRODUCTION_V3_NATIVE_BLOCK_ROWS,
    PreparedForgeMatrixV3Model,
};
pub use cmfd_proof_worker::ProductionV3VerifierArtifacts;
use cmfd_proof_worker::{
    PersistentVerifierWorker, ProofWorkerError, VerifierWorkerConfig, VerifierWorkerError,
};
use fs2::FileExt;
use k256::schnorr::{SigningKey, VerifyingKey};
use primitive_types::U512;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

pub mod logging;
pub mod network_info;
pub mod network_profile;
pub mod p2p;
pub mod peer;
pub mod pool;
#[cfg(feature = "production-v3")]
pub mod rcnet_candidate;

#[path = "../release_gate.rs"]
#[allow(dead_code)]
mod release_gate;

pub use network_info::{canonical_network_info_json, canonical_network_info_json_with_artifacts};
pub use network_profile::{
    COMPILED_NETWORK_PROFILE, DEVNET_PROFILE, NetworkProfile, ProofProfile, RCNET1_PROFILE,
};

pub const DEVNET_NETWORK_ID: [u8; 32] = COMPILED_NETWORK_PROFILE.network_id;
pub const DEVNET_GENESIS_HASH: [u8; 32] = COMPILED_NETWORK_PROFILE.virtual_genesis_hash;
pub const DEVNET_GENESIS_TIMESTAMP: u64 = COMPILED_NETWORK_PROFILE.virtual_genesis_timestamp;
pub const DEFAULT_RPC_ADDRESS: SocketAddr = COMPILED_NETWORK_PROFILE.rpc_address();
pub const DEFAULT_P2P_ADDRESS: SocketAddr = COMPILED_NETWORK_PROFILE.p2p_address();
pub const DEFAULT_DATA_DIR: &str = COMPILED_NETWORK_PROFILE.default_data_dir_identity;
pub const DEFAULT_MINING_ATTEMPTS: u64 = 1_000_000;
/// Maximum work accepted by one cancellable immutable mining-job search.
pub const MAX_MINING_SEARCH_ATTEMPTS: u64 = DEFAULT_MINING_ATTEMPTS;
pub const MAX_MEMPOOL_TRANSACTIONS: usize = 1_024;
pub const MAX_MEMPOOL_BYTES: usize = 512 * 1024;
pub const MIN_RELAY_FEE_PER_KIB: u64 = 1;
pub const MAX_WALLET_HISTORY: usize = 100;
pub const MAX_OBSERVED_PEERS: usize = 64;
/// Proof verification is intentionally serialized until production resource
/// measurements justify a larger parallel allowance.
pub const MAX_CONCURRENT_PROOF_VERIFICATIONS: usize = 1;
/// Bounded waiters prevent peer floods from creating unbounded verifier work.
pub const MAX_QUEUED_PROOF_VERIFICATIONS: usize = 8;
/// Local tip submissions have a separate bounded lane so a full remote queue
/// cannot crowd out a block already found by the wallet, miner, or pool.
pub const MAX_PRIORITY_QUEUED_PROOF_VERIFICATIONS: usize = 2;
pub const MAX_REJECTED_BLOCK_IDS: usize = 1_024;
pub const MAX_SUCCESSFUL_PROOF_CAPABILITIES: usize = 1_024;
pub const MAX_EXTERNAL_RECONSTRUCTION_BLOCKS_PER_SLICE: usize = 8;
pub const PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY: &str = "production-v3";
pub const PRODUCTION_V3_PACKAGE_BANK: &str = "MODEL-V2.bank";
pub const PRODUCTION_V3_PACKAGE_MANIFEST: &str = "MODEL-V2.manifest.json";
pub const PRODUCTION_V3_PACKAGE_RECORD_V2: &str = "DORY-V3-MODEL-RECORD-V2.json";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionV3PackageLayout {
    pub worker: PathBuf,
    pub artifacts: ProductionV3VerifierArtifacts,
}

/// Fixed, download-free sidecar layout used when an RC package is launched
/// without artifact arguments. Callers must canonicalize these paths and pass
/// them through the compiled hash/length gates before starting any service.
pub fn production_v3_package_layout(
    executable: &Path,
) -> Result<ProductionV3PackageLayout, NodeError> {
    let directory = executable
        .parent()
        .ok_or(NodeError::ProductionV3ActivationEvidence(
            "package executable has no parent directory",
        ))?;
    let artifacts = directory.join(PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY);
    Ok(ProductionV3PackageLayout {
        worker: directory.join(format!("cmfd-proof-worker{}", std::env::consts::EXE_SUFFIX)),
        artifacts: ProductionV3VerifierArtifacts {
            bank: artifacts.join(PRODUCTION_V3_PACKAGE_BANK),
            manifest: artifacts.join(PRODUCTION_V3_PACKAGE_MANIFEST),
            record_v2: artifacts.join(PRODUCTION_V3_PACKAGE_RECORD_V2),
        },
    })
}

/// Returns the only verifier-worker executable identity trusted by a compiled
/// ProductionV3 package. The pin is part of the activation evidence; operators
/// may select another path only when its bytes match this exact identity.
pub fn compiled_production_v3_worker_sha256() -> Result<[u8; 32], NodeError> {
    if COMPILED_NETWORK_PROFILE.proof != ProofProfile::ProductionV3 {
        return Err(NodeError::ProductionV3ActivationEvidence(
            "compiled proof profile is not ProductionV3",
        ));
    }
    let pins = release_gate::COMPILED_RELEASE_PROFILE
        .production_v3_verifier_workers
        .ok_or(NodeError::ProductionV3ActivationEvidence(
            "compiled runtime verifier-worker pin is absent",
        ))?;
    let digest = pins
        .for_target(std::env::consts::OS, std::env::consts::ARCH)
        .ok_or(NodeError::ProductionV3ActivationEvidence(
            "compiled runtime verifier-worker pin is unavailable for this platform",
        ))?;
    if digest == [0; 32] {
        return Err(NodeError::ProductionV3ActivationEvidence(
            "compiled runtime verifier-worker pin is zero",
        ));
    }
    Ok(digest)
}

fn install_external_proof_verifier(
    profile: NetworkProfile,
    block_preverifier: &BlockPreverifier,
    config: VerifierWorkerConfig,
) -> Result<(), NodeError> {
    let configured_for_v3 = config.production_v3_artifacts.is_some();
    if configured_for_v3 != matches!(profile.proof, ProofProfile::ProductionV3) {
        return Err(NodeError::ProofVerifierProfileMismatch);
    }
    if configured_for_v3 {
        let expected = compiled_production_v3_worker_sha256()?;
        if config.worker_sha256 != expected {
            return Err(NodeError::ProofVerifierWorker(
                VerifierWorkerError::Process(ProofWorkerError::HashMismatch {
                    component: "compiled production verifier worker",
                }),
            ));
        }
    }
    block_preverifier.use_external_worker(config, profile.network_id)?;
    Ok(())
}

const METADATA_FILE: &str = "network.meta";
const BLOCK_LOG_FILE: &str = "blocks.log";
const LOCK_FILE: &str = "node.lock";
const WALLET_KEY_FILE: &str = "wallet.key";
static NEXT_NODE_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);
const METADATA_MAGIC: [u8; 4] = *b"CMFM";
const METADATA_VERSION: u16 = 1;
const METADATA_BYTES: usize = 40;
const METADATA_WALLET_KEY_FLAG: u16 = 1;
const RECORD_MAGIC: [u8; 4] = *b"CMFR";
const RECORD_VERSION_V1: u16 = 1;
const RECORD_VERSION_V2: u16 = 2;
const RECORD_V1_HEADER_BYTES: usize = 20;
const RECORD_V2_HEADER_BYTES: usize = 56;
const RECORD_CHECKSUM_BYTES: usize = 32;
const RECORD_V1_CHECKSUM_DOMAIN: &str = "CMFD/NODE/BLOCK-RECORD/V1";
const RECORD_V2_CHECKSUM_DOMAIN: &str = "CMFD/NODE/BLOCK-RECORD/V2";
const RECORD_CHAIN_DIGEST_DOMAIN: &str = "CMFD/NODE/BLOCK-RECORD-CHAIN/V1";
/// Legacy V1 records do not persist reversible deltas. Devnet startup derives
/// and retains their canonical bytes only along the current DFS ancestry,
/// with a temporary hard migration budget. Production V3 rejects V1 records.
const MAX_LEGACY_REPLAY_UNDO_STACK_BYTES: usize = 64 * 1024 * 1024;
/// Fixed predecessor for the first V2 record in an empty block log.
///
/// This is only a local corruption/reordering root. It is not a consensus
/// commitment, a state root, or trustless authentication of local storage. A
/// self-hashed log without an external monotonic anchor also cannot detect
/// removal of an entire complete suffix; partial records still fail closed.
const EMPTY_RECORD_CHAIN_ROOT: [u8; 32] = [0; 32];
const RPC_HEADER_LIMIT: usize = 8 * 1024;
const RPC_READ_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_TOTAL_READ_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_ACCEPT_POLL: Duration = Duration::from_millis(50);
const PROOF_VERIFICATION_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
const WALLET_JSON_BODY_LIMIT: usize = 2 * 1024;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("data directory {0:?} is locked by another running node")]
    DataDirLocked(PathBuf),
    #[error("{operation} failed for {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("network metadata is corrupt or unsupported")]
    InvalidMetadata,
    #[error(
        "CommonFoundry RCNet-1 requires the production V3 proof verifier; the tiny Devnet V2 relation is never used as a fallback"
    )]
    ProductionV3Unavailable,
    #[error("CommonFoundry RCNet-1 requires explicit production V3 bank, manifest, and Record V2 paths")]
    ProductionV3ArtifactsMissing,
    #[error("production V3 artifacts were supplied for a network that selects the V2 reference proof")]
    ProductionV3ArtifactsUnexpected,
    #[error("the compiled production V3 bank, manifest, and Record V2 identity pins are absent")]
    ProductionV3ArtifactPinsMissing,
    #[error("compiled production V3 activation evidence is invalid: {0}")]
    ProductionV3ActivationEvidence(&'static str),
    #[error("the authenticated production V3 {0} does not match its compiled identity pin")]
    ProductionV3ArtifactIdentityMismatch(&'static str),
    #[error(
        "production V3 mining requires absolute, pairwise-distinct artifact paths, an existing absolute scratch directory, and max rows between 1 and 131072"
    )]
    ProductionV3MiningConfiguration,
    #[cfg(feature = "production-v3")]
    #[error("production V3 verifier artifacts failed authentication: {0}")]
    ProductionV3Artifacts(
        #[source]
        cmfd_consensus::dory_v3_model_bank_record_validation::ProductionDoryV3ModelBankRecordValidationError,
    ),
    #[error("network metadata is missing while a nonempty block log already exists")]
    MissingMetadata,
    #[error("data directory belongs to a different immutable network fingerprint")]
    FingerprintMismatch,
    #[error("wallet key is missing, corrupt, or unsupported")]
    InvalidWalletKey,
    #[error("block log is corrupt: {0}")]
    CorruptLog(String),
    #[error(
        "production V3 refuses legacy V1 block-log record {0}; migrate the log to authenticated V2 before activation"
    )]
    ProductionLegacyBlockLog(u64),
    #[error(
        "legacy V1 startup reconstruction at record {record_index} exceeds its temporary {maximum}-byte migration budget"
    )]
    LegacyReplayResourceLimit {
        record_index: u64,
        maximum: usize,
    },
    #[error("system clock is before the Unix epoch")]
    InvalidSystemTime,
    #[error("no currently valid template timestamp exists; wait for wall clock time to catch up")]
    TemplateTimeUnavailable,
    #[error("miner destination must be a 64-character hex Schnorr public key")]
    InvalidMinerDestination,
    #[error("mining search attempts must be between 1 and {MAX_MINING_SEARCH_ATTEMPTS}")]
    InvalidMiningSearchAttempts,
    #[error("mining share target must be easier than or equal to the immutable block target")]
    InvalidMiningShareTarget,
    #[error("RPC bind address must be loopback, received {0}")]
    NonLoopbackRpc(SocketAddr),
    #[error(
        "block storage is faulted after an append or sync failure; restart only after inspecting the log"
    )]
    StorageFaulted,
    #[error("block is already indexed: {0:?}")]
    DuplicateBlock([u8; 32]),
    #[error("block parent is not indexed: {0:?}")]
    UnknownParent([u8; 32]),
    #[error("block admission snapshot became stale while proof verification was in progress")]
    StaleBlockAdmission,
    #[error("block was already rejected by deterministic consensus validation: {0:?}")]
    CachedInvalidBlock([u8; 32]),
    #[error("fork state reconstruction exceeded its bounded work slice; retry the candidate")]
    ForkReconstructionDeferred,
    #[error("transaction is already in the mempool: {0:?}")]
    DuplicateMempoolTransaction([u8; 32]),
    #[error("transaction input conflicts with the first mempool spend: {0:?}")]
    MempoolInputConflict(OutPoint),
    #[error("transaction input is not confirmed on the active chain: {0:?}")]
    MempoolUnconfirmedInput(OutPoint),
    #[error("mempool transaction count would exceed {MAX_MEMPOOL_TRANSACTIONS}")]
    MempoolTransactionLimit,
    #[error("mempool bytes would exceed {MAX_MEMPOOL_BYTES}")]
    MempoolByteLimit,
    #[error("transaction burns a fee of {actual}, below the relay minimum of {required}")]
    MempoolFeeTooLow { required: u64, actual: u64 },
    #[error("wallet recipient must be a 64-character hex Schnorr public key")]
    InvalidWalletRecipient,
    #[error("wallet amount must be an unsigned decimal CMFD value with at most 8 decimal places")]
    InvalidWalletAmount,
    #[error("wallet amount arithmetic overflow")]
    WalletAmountOverflow,
    #[error("wallet send amount must be nonzero")]
    WalletZeroAmount,
    #[error("wallet funds are immature: {immature} atoms immature, {required} atoms required")]
    WalletFundsImmature { immature: u64, required: u64 },
    #[error(
        "wallet has insufficient funds: {available} atoms available, {required} atoms required"
    )]
    WalletInsufficientFunds { available: u64, required: u64 },
    #[error(
        "wallet send would require more than {MAX_TRANSACTION_INPUTS} inputs: {selected} atoms selected, {required} atoms required"
    )]
    WalletInputLimit { selected: u64, required: u64 },
    #[error("wallet consolidation max_inputs must be between 2 and {MAX_TRANSACTION_INPUTS}")]
    InvalidConsolidationMaxInputs,
    #[error("wallet consolidation requires at least two mature unreserved outputs, found {0}")]
    WalletNotEnoughUtxos(usize),
    #[error("wallet consolidation fee must be less than its {input} atom input total")]
    WalletConsolidationFee { input: u64 },
    #[error("RPC request is invalid: {0}")]
    InvalidRpcRequest(String),
    #[error("RPC I/O failed: {0}")]
    RpcIo(#[source] io::Error),
    #[error("shared node mutex is poisoned")]
    SharedNodePoisoned,
    #[error("proof verification queue is full")]
    ProofVerificationQueueFull,
    #[error("timed out waiting for proof verification capacity")]
    ProofVerificationQueueTimeout,
    #[error("proof verification queue state is poisoned")]
    ProofVerificationQueuePoisoned,
    #[error("proof verifier is shutting down")]
    ProofVerifierShuttingDown,
    #[error("proof verifier panicked; the candidate was rejected")]
    ProofVerifierPanicked,
    #[error("external proof-verifier profile does not match the node consensus profile")]
    ProofVerifierProfileMismatch,
    #[error("external proof verifier failed: {0}")]
    ProofVerifierWorker(#[from] VerifierWorkerError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Network(#[from] NetworkError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Pow(#[from] PowError),
    #[error(transparent)]
    Economics(#[from] EconomicsError),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeClientError {
    pub code: &'static str,
    pub status: u16,
    pub retryable: bool,
    pub message: String,
}

impl NodeError {
    pub fn client_error(&self) -> NodeClientError {
        let (code, status, retryable) = match self {
            Self::DataDirLocked(_) => ("data_dir_locked", 409, false),
            Self::Io { .. } => ("storage_io", 500, false),
            Self::InvalidMetadata => ("invalid_metadata", 500, false),
            Self::ProductionV3Unavailable => ("production_v3_unavailable", 503, false),
            Self::ProductionV3ArtifactsMissing
            | Self::ProductionV3ArtifactsUnexpected
            | Self::ProductionV3ArtifactPinsMissing
            | Self::ProductionV3ActivationEvidence(_)
            | Self::ProductionV3ArtifactIdentityMismatch(_)
            | Self::ProductionV3MiningConfiguration
            | Self::ProofVerifierProfileMismatch => ("proof_verifier_configuration", 500, false),
            #[cfg(feature = "production-v3")]
            Self::ProductionV3Artifacts(_) => ("proof_verifier_configuration", 500, false),
            Self::MissingMetadata => ("missing_metadata", 500, false),
            Self::FingerprintMismatch => ("fingerprint_mismatch", 409, false),
            Self::InvalidWalletKey => ("invalid_wallet_key", 500, false),
            Self::CorruptLog(_) => ("corrupt_block_log", 500, false),
            Self::ProductionLegacyBlockLog(_) => ("production_legacy_block_log", 500, false),
            Self::LegacyReplayResourceLimit { .. } => ("legacy_replay_resource_limit", 500, false),
            Self::InvalidSystemTime => ("invalid_system_time", 500, false),
            Self::TemplateTimeUnavailable => ("template_time_unavailable", 503, true),
            Self::InvalidMinerDestination => ("invalid_miner_destination", 400, false),
            Self::InvalidMiningSearchAttempts => ("invalid_mining_search_attempts", 400, false),
            Self::InvalidMiningShareTarget => ("invalid_mining_share_target", 400, false),
            Self::NonLoopbackRpc(_) => ("non_loopback_rpc", 400, false),
            Self::StorageFaulted => ("storage_faulted", 503, false),
            Self::DuplicateBlock(_) => ("duplicate_block", 409, false),
            Self::UnknownParent(_) => ("unknown_parent", 422, true),
            Self::StaleBlockAdmission => ("stale_block_admission", 409, true),
            Self::CachedInvalidBlock(_) => ("cached_invalid_block", 422, false),
            Self::ForkReconstructionDeferred => ("fork_reconstruction_deferred", 503, true),
            Self::DuplicateMempoolTransaction(_) => ("duplicate_mempool_transaction", 409, false),
            Self::MempoolInputConflict(_) => ("mempool_input_conflict", 409, false),
            Self::MempoolUnconfirmedInput(_) => ("mempool_unconfirmed_input", 422, true),
            Self::MempoolTransactionLimit => ("mempool_transaction_limit", 422, true),
            Self::MempoolByteLimit => ("mempool_byte_limit", 422, true),
            Self::MempoolFeeTooLow { .. } => ("mempool_fee_too_low", 422, false),
            Self::InvalidWalletRecipient => ("invalid_wallet_recipient", 400, false),
            Self::InvalidWalletAmount => ("invalid_wallet_amount", 400, false),
            Self::WalletAmountOverflow => ("wallet_amount_overflow", 400, false),
            Self::WalletZeroAmount => ("wallet_zero_amount", 400, false),
            Self::WalletFundsImmature { .. } => ("wallet_funds_immature", 422, true),
            Self::WalletInsufficientFunds { .. } => ("wallet_insufficient_funds", 422, false),
            Self::WalletInputLimit { .. } => ("wallet_input_limit", 422, false),
            Self::InvalidConsolidationMaxInputs => ("invalid_consolidation_max_inputs", 400, false),
            Self::WalletNotEnoughUtxos(_) => ("wallet_not_enough_utxos", 422, false),
            Self::WalletConsolidationFee { .. } => ("wallet_consolidation_fee", 422, false),
            Self::InvalidRpcRequest(_) => ("invalid_request", 400, false),
            Self::RpcIo(_) => ("rpc_io", 500, true),
            Self::SharedNodePoisoned => ("shared_node_poisoned", 500, false),
            Self::ProofVerificationQueueFull => ("proof_queue_full", 503, true),
            Self::ProofVerificationQueueTimeout => ("proof_queue_timeout", 503, true),
            Self::ProofVerificationQueuePoisoned => ("proof_queue_poisoned", 500, false),
            Self::ProofVerifierShuttingDown => ("proof_verifier_shutting_down", 503, true),
            Self::ProofVerifierPanicked => ("proof_verifier_panicked", 500, false),
            Self::ProofVerifierWorker(VerifierWorkerError::ProofRejected(_)) => {
                ("proof_rejected", 422, false)
            }
            Self::ProofVerifierWorker(VerifierWorkerError::Process(
                ProofWorkerError::Timeout { .. },
            )) => ("proof_verifier_timeout", 503, true),
            Self::ProofVerifierWorker(VerifierWorkerError::InvalidConfig(_))
            | Self::ProofVerifierWorker(VerifierWorkerError::Process(
                ProofWorkerError::HashMismatch { .. } | ProofWorkerError::FileRead { .. },
            )) => ("proof_verifier_configuration", 500, false),
            Self::ProofVerifierWorker(_) => ("proof_verifier_unavailable", 503, true),
            Self::Json(_) => ("invalid_json", 400, false),
            Self::Network(_) => ("network_parameters", 500, false),
            Self::Chain(
                ChainError::TimestampTooFarInFuture
                | ChainError::InvalidValidationTime
                | ChainError::StaleValidatedBlock,
            ) => ("chain_temporarily_rejected", 409, true),
            Self::Chain(_) => ("chain_rejected", 422, false),
            Self::Wire(_) => ("wire_rejected", 400, false),
            Self::Pow(_) => ("proof_rejected", 422, false),
            Self::Economics(_) => ("economics", 500, false),
        };
        let message = match self {
            Self::DataDirLocked(_) => "node data directory is already in use".to_owned(),
            Self::Io { .. } => "node storage operation failed; inspect the node logs".to_owned(),
            Self::CorruptLog(_) => {
                "block log is corrupt; inspect the node logs before restarting".to_owned()
            }
            Self::NonLoopbackRpc(_) => "RPC must remain bound to loopback".to_owned(),
            Self::RpcIo(_) => "node RPC I/O failed".to_owned(),
            Self::ProofVerifierWorker(_) => {
                "external proof verifier failed; inspect the node logs".to_owned()
            }
            Self::Json(_) => "request JSON is invalid".to_owned(),
            _ => self.to_string(),
        };
        NodeClientError {
            code,
            status,
            retryable,
            message,
        }
    }
}

#[derive(Debug)]
struct ProofVerificationQueueState {
    active: usize,
    closing: bool,
    normal_queued: usize,
    priority_queued: usize,
    next_normal_ticket: u64,
    serving_normal_ticket: u64,
    cancelled_normal_tickets: HashSet<u64>,
    next_priority_ticket: u64,
    serving_priority_ticket: u64,
    cancelled_priority_tickets: HashSet<u64>,
}

#[derive(Clone, Copy)]
enum ProofQueueClass {
    Normal,
    Priority,
}

#[derive(Debug)]
struct ProofVerificationQueue {
    state: Mutex<ProofVerificationQueueState>,
    wake: Condvar,
    max_active: usize,
    max_queued: usize,
    wait_timeout: Duration,
}

impl ProofVerificationQueue {
    fn new(max_active: usize, max_queued: usize, wait_timeout: Duration) -> Self {
        assert!(max_active > 0, "proof verification needs active capacity");
        Self {
            state: Mutex::new(ProofVerificationQueueState {
                active: 0,
                closing: false,
                normal_queued: 0,
                priority_queued: 0,
                next_normal_ticket: 0,
                serving_normal_ticket: 0,
                cancelled_normal_tickets: HashSet::new(),
                next_priority_ticket: 0,
                serving_priority_ticket: 0,
                cancelled_priority_tickets: HashSet::new(),
            }),
            wake: Condvar::new(),
            max_active,
            max_queued,
            wait_timeout,
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<ProofVerificationPermit, NodeError> {
        self.acquire_class(ProofQueueClass::Normal, Some(self.wait_timeout))
    }

    fn acquire_priority(self: &Arc<Self>) -> Result<ProofVerificationPermit, NodeError> {
        // A locally found block is already the result of expensive work. Once
        // admitted to the bounded priority lane, wait until it is served or
        // terminal shutdown wakes it instead of discarding it behind a slow
        // remote verification or worker restart.
        self.acquire_class(ProofQueueClass::Priority, None)
    }

    fn acquire_class(
        self: &Arc<Self>,
        class: ProofQueueClass,
        wait_timeout: Option<Duration>,
    ) -> Result<ProofVerificationPermit, NodeError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
        if state.closing {
            return Err(NodeError::ProofVerifierShuttingDown);
        }
        if state.active < self.max_active && state.normal_queued == 0 && state.priority_queued == 0
        {
            state.active += 1;
            return Ok(ProofVerificationPermit {
                queue: Arc::clone(self),
            });
        }
        let ticket = match class {
            ProofQueueClass::Normal => {
                if state.normal_queued >= self.max_queued {
                    return Err(NodeError::ProofVerificationQueueFull);
                }
                let ticket = state.next_normal_ticket;
                state.next_normal_ticket = state.next_normal_ticket.wrapping_add(1);
                state.normal_queued += 1;
                ticket
            }
            ProofQueueClass::Priority => {
                if state.priority_queued >= MAX_PRIORITY_QUEUED_PROOF_VERIFICATIONS {
                    return Err(NodeError::ProofVerificationQueueFull);
                }
                let ticket = state.next_priority_ticket;
                state.next_priority_ticket = state.next_priority_ticket.wrapping_add(1);
                state.priority_queued += 1;
                ticket
            }
        };
        let waiting = |state: &mut ProofVerificationQueueState| {
            !state.closing
                && (state.active >= self.max_active
                    || match class {
                        ProofQueueClass::Normal => {
                            state.priority_queued != 0 || state.serving_normal_ticket != ticket
                        }
                        ProofQueueClass::Priority => state.serving_priority_ticket != ticket,
                    })
        };
        let (mut state, timed_out) = if let Some(wait_timeout) = wait_timeout {
            let (state, wait_result) = self
                .wake
                .wait_timeout_while(state, wait_timeout, waiting)
                .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
            (state, wait_result.timed_out())
        } else {
            let state = self
                .wake
                .wait_while(state, waiting)
                .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
            (state, false)
        };
        if state.closing {
            cancel_proof_ticket(&mut state, class, ticket);
            return Err(NodeError::ProofVerifierShuttingDown);
        }
        if timed_out
            && (state.active >= self.max_active
                || match class {
                    ProofQueueClass::Normal => {
                        state.priority_queued != 0 || state.serving_normal_ticket != ticket
                    }
                    ProofQueueClass::Priority => state.serving_priority_ticket != ticket,
                })
        {
            cancel_proof_ticket(&mut state, class, ticket);
            self.wake.notify_all();
            return Err(NodeError::ProofVerificationQueueTimeout);
        }
        serve_proof_ticket(&mut state, class);
        state.active += 1;
        self.wake.notify_all();
        Ok(ProofVerificationPermit {
            queue: Arc::clone(self),
        })
    }

    fn counts(&self) -> Result<(usize, usize), NodeError> {
        self.state
            .lock()
            .map(|state| {
                (
                    state.active,
                    state.normal_queued.saturating_add(state.priority_queued),
                )
            })
            .map_err(|_| NodeError::ProofVerificationQueuePoisoned)
    }

    fn close(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.closing = true;
        self.wake.notify_all();
    }

    fn ensure_open(&self) -> Result<(), NodeError> {
        let state = self
            .state
            .lock()
            .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
        if state.closing {
            Err(NodeError::ProofVerifierShuttingDown)
        } else {
            Ok(())
        }
    }
}

fn cancel_proof_ticket(
    state: &mut ProofVerificationQueueState,
    class: ProofQueueClass,
    ticket: u64,
) {
    match class {
        ProofQueueClass::Normal => {
            state.normal_queued = state.normal_queued.saturating_sub(1);
            state.cancelled_normal_tickets.insert(ticket);
            while state
                .cancelled_normal_tickets
                .remove(&state.serving_normal_ticket)
            {
                state.serving_normal_ticket = state.serving_normal_ticket.wrapping_add(1);
            }
        }
        ProofQueueClass::Priority => {
            state.priority_queued = state.priority_queued.saturating_sub(1);
            state.cancelled_priority_tickets.insert(ticket);
            while state
                .cancelled_priority_tickets
                .remove(&state.serving_priority_ticket)
            {
                state.serving_priority_ticket = state.serving_priority_ticket.wrapping_add(1);
            }
        }
    }
}

fn serve_proof_ticket(state: &mut ProofVerificationQueueState, class: ProofQueueClass) {
    match class {
        ProofQueueClass::Normal => {
            state.normal_queued = state.normal_queued.saturating_sub(1);
            state.serving_normal_ticket = state.serving_normal_ticket.wrapping_add(1);
            while state
                .cancelled_normal_tickets
                .remove(&state.serving_normal_ticket)
            {
                state.serving_normal_ticket = state.serving_normal_ticket.wrapping_add(1);
            }
        }
        ProofQueueClass::Priority => {
            state.priority_queued = state.priority_queued.saturating_sub(1);
            state.serving_priority_ticket = state.serving_priority_ticket.wrapping_add(1);
            while state
                .cancelled_priority_tickets
                .remove(&state.serving_priority_ticket)
            {
                state.serving_priority_ticket = state.serving_priority_ticket.wrapping_add(1);
            }
        }
    }
}

struct ProofVerificationPermit {
    queue: Arc<ProofVerificationQueue>,
}

impl Drop for ProofVerificationPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.queue.state.lock() {
            state.active = state.active.saturating_sub(1);
            self.queue.wake.notify_all();
        }
    }
}

/// An owned queue reservation. Shared-node admission captures its revision
/// only after this reservation is acquired and keeps it until commit, so
/// queued candidates cannot all verify against one stale revision.
struct BlockPreverificationPermit {
    preverifier: BlockPreverifier,
    _queue_permit: ProofVerificationPermit,
}

impl BlockPreverificationPermit {
    fn preverify(&self, block: &Block) -> Result<PreverifiedBlockProof, NodeError> {
        validate_block_resources(block)?;
        encode_block(block)?;
        self.run_guarded(|| self.preverifier.preverify_unqueued(block))
    }

    fn preverify_cached(
        &self,
        block: &Block,
        cache_key: [u8; 32],
    ) -> Result<PreverifiedBlockProof, NodeError> {
        if let Some(preverified) = self.preverifier.cached_preverification(cache_key)? {
            return Ok(preverified);
        }
        let generation = self.preverifier.backend_generation.load(Ordering::Acquire);
        let preverified = self.preverify(block)?;
        self.preverifier
            .remember_preverification(cache_key, generation, preverified.clone())?;
        Ok(preverified)
    }

    fn run_guarded<T>(
        &self,
        operation: impl FnOnce() -> Result<T, NodeError>,
    ) -> Result<T, NodeError> {
        match catch_unwind(AssertUnwindSafe(operation)) {
            Ok(result) => result,
            Err(_) => Err(NodeError::ProofVerifierPanicked),
        }
    }
}

/// Cloneable, immutable admission handle for proof verification outside the
/// node's global state lock.
#[derive(Clone)]
pub struct BlockPreverifier {
    verifier: ConsensusPowVerifier,
    queue: Arc<ProofVerificationQueue>,
    reconstruction_queue: Arc<ProofVerificationQueue>,
    backend: Arc<RwLock<ProofVerificationBackend>>,
    backend_generation: Arc<AtomicU64>,
    successful_proofs: Arc<Mutex<SuccessfulProofCache>>,
}

#[derive(Debug, Default)]
struct SuccessfulProofCache {
    entries: HashMap<[u8; 32], (u64, PreverifiedBlockProof)>,
    order: VecDeque<[u8; 32]>,
}

impl SuccessfulProofCache {
    fn insert(&mut self, key: [u8; 32], generation: u64, preverified: PreverifiedBlockProof) {
        if self
            .entries
            .insert(key, (generation, preverified))
            .is_none()
        {
            self.order.push_back(key);
        }
        while self.order.len() > MAX_SUCCESSFUL_PROOF_CAPABILITIES {
            if let Some(expired) = self.order.pop_front() {
                self.entries.remove(&expired);
            }
        }
    }
}

#[derive(Clone)]
enum ProofVerificationBackend {
    Unavailable,
    InProcess,
    External(PersistentVerifierWorker),
    Stopped,
}

impl BlockPreverifier {
    fn new(verifier: ConsensusPowVerifier, proof_profile: ProofProfile) -> Self {
        let backend = match proof_profile {
            ProofProfile::DevnetV2Reference => ProofVerificationBackend::InProcess,
            ProofProfile::ProductionV3 => ProofVerificationBackend::Unavailable,
        };
        Self::with_limits_and_backend(
            verifier,
            MAX_CONCURRENT_PROOF_VERIFICATIONS,
            MAX_QUEUED_PROOF_VERIFICATIONS,
            PROOF_VERIFICATION_QUEUE_TIMEOUT,
            backend,
        )
    }

    #[cfg(test)]
    fn with_limits(
        verifier: ConsensusPowVerifier,
        max_active: usize,
        max_queued: usize,
        wait_timeout: Duration,
    ) -> Self {
        Self::with_limits_and_backend(
            verifier,
            max_active,
            max_queued,
            wait_timeout,
            ProofVerificationBackend::InProcess,
        )
    }

    fn with_limits_and_backend(
        verifier: ConsensusPowVerifier,
        max_active: usize,
        max_queued: usize,
        wait_timeout: Duration,
        backend: ProofVerificationBackend,
    ) -> Self {
        Self {
            verifier,
            queue: Arc::new(ProofVerificationQueue::new(
                max_active,
                max_queued,
                wait_timeout,
            )),
            reconstruction_queue: Arc::new(ProofVerificationQueue::new(1, 2, wait_timeout)),
            backend: Arc::new(RwLock::new(backend)),
            backend_generation: Arc::new(AtomicU64::new(0)),
            successful_proofs: Arc::new(Mutex::new(SuccessfulProofCache::default())),
        }
    }

    fn use_external_worker(
        &self,
        config: VerifierWorkerConfig,
        network_id: [u8; 32],
    ) -> Result<(), VerifierWorkerError> {
        {
            let state = self
                .queue
                .state
                .lock()
                .map_err(|_| VerifierWorkerError::StatePoisoned)?;
            if state.closing {
                return Err(VerifierWorkerError::Closed);
            }
        }
        let worker = PersistentVerifierWorker::start(config, self.verifier.clone(), network_id)?;
        let queue_state = self
            .queue
            .state
            .lock()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        if queue_state.closing {
            worker.close();
            return Err(VerifierWorkerError::Closed);
        }
        let replaced = std::mem::replace(
            &mut *self
                .backend
                .write()
                .map_err(|_| VerifierWorkerError::StatePoisoned)?,
            ProofVerificationBackend::External(worker),
        );
        self.backend_generation.fetch_add(1, Ordering::AcqRel);
        let mut successful_proofs = self
            .successful_proofs
            .lock()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        successful_proofs.entries.clear();
        successful_proofs.order.clear();
        drop(successful_proofs);
        drop(queue_state);
        if let ProofVerificationBackend::External(replaced) = replaced {
            replaced.close();
        }
        Ok(())
    }

    pub fn preverify(&self, block: &Block) -> Result<PreverifiedBlockProof, NodeError> {
        self.reserve()?.preverify(block)
    }

    fn reserve(&self) -> Result<BlockPreverificationPermit, NodeError> {
        Ok(BlockPreverificationPermit {
            preverifier: self.clone(),
            _queue_permit: self.queue.acquire()?,
        })
    }

    fn reserve_priority(&self) -> Result<BlockPreverificationPermit, NodeError> {
        Ok(BlockPreverificationPermit {
            preverifier: self.clone(),
            _queue_permit: self.queue.acquire_priority()?,
        })
    }

    fn reserve_reconstruction(&self) -> Result<ProofVerificationPermit, NodeError> {
        self.reconstruction_queue.acquire()
    }

    fn ensure_reconstruction_open(&self) -> Result<(), NodeError> {
        self.reconstruction_queue.ensure_open()
    }

    fn preverify_unqueued(&self, block: &Block) -> Result<PreverifiedBlockProof, NodeError> {
        let backend = self
            .backend
            .read()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?
            .clone();
        match backend {
            ProofVerificationBackend::Unavailable => Err(NodeError::ProductionV3Unavailable),
            ProofVerificationBackend::Stopped => Err(NodeError::ProofVerifierShuttingDown),
            ProofVerificationBackend::InProcess => self
                .verifier
                .preverify(&block.challenge, &block.proof)
                .map_err(NodeError::from),
            ProofVerificationBackend::External(worker) => {
                worker.verify_block(block).map_err(NodeError::from)
            }
        }
    }

    fn cached_preverification(
        &self,
        cache_key: [u8; 32],
    ) -> Result<Option<PreverifiedBlockProof>, NodeError> {
        let queue_state = self
            .queue
            .state
            .lock()
            .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
        if queue_state.closing {
            return Err(NodeError::ProofVerifierShuttingDown);
        }
        let backend = self
            .backend
            .read()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        if matches!(*backend, ProofVerificationBackend::Stopped) {
            return Err(NodeError::ProofVerifierShuttingDown);
        }
        let generation = self.backend_generation.load(Ordering::Acquire);
        let cache = self
            .successful_proofs
            .lock()
            .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
        Ok(cache
            .entries
            .get(&cache_key)
            .and_then(|(entry_generation, preverified)| {
                (*entry_generation == generation).then(|| preverified.clone())
            }))
    }

    fn remember_preverification(
        &self,
        cache_key: [u8; 32],
        expected_generation: u64,
        preverified: PreverifiedBlockProof,
    ) -> Result<(), NodeError> {
        let queue_state = self
            .queue
            .state
            .lock()
            .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
        if queue_state.closing {
            return Err(NodeError::ProofVerifierShuttingDown);
        }
        let backend = self
            .backend
            .read()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        if matches!(*backend, ProofVerificationBackend::Stopped) {
            return Err(NodeError::ProofVerifierShuttingDown);
        }
        if self.backend_generation.load(Ordering::Acquire) != expected_generation {
            return Ok(());
        }
        self.successful_proofs
            .lock()
            .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?
            .insert(cache_key, expected_generation, preverified);
        Ok(())
    }

    #[cfg(test)]
    fn run_guarded<T>(
        &self,
        operation: impl FnOnce() -> Result<T, NodeError>,
    ) -> Result<T, NodeError> {
        self.reserve()?.run_guarded(operation)
    }

    fn backend_status(&self) -> Result<(&'static str, Option<u64>, Option<u64>), NodeError> {
        let backend = self
            .backend
            .read()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        Ok(match &*backend {
            ProofVerificationBackend::Unavailable => ("unavailable", None, None),
            ProofVerificationBackend::Stopped => ("stopped", None, None),
            ProofVerificationBackend::InProcess => ("in_process", None, None),
            ProofVerificationBackend::External(worker) => (
                "external_worker",
                Some(worker.timeout().as_millis().min(u128::from(u64::MAX)) as u64),
                Some(worker.memory_limit_bytes()),
            ),
        })
    }

    fn shutdown(&self) {
        self.queue.close();
        self.reconstruction_queue.close();
        let worker = match self.backend.write() {
            Ok(mut backend) => {
                match std::mem::replace(&mut *backend, ProofVerificationBackend::Stopped) {
                    ProofVerificationBackend::External(worker) => Some(worker),
                    ProofVerificationBackend::Unavailable
                    | ProofVerificationBackend::InProcess
                    | ProofVerificationBackend::Stopped => None,
                }
            }
            Err(poisoned) => {
                let mut backend = poisoned.into_inner();
                match std::mem::replace(&mut *backend, ProofVerificationBackend::Stopped) {
                    ProofVerificationBackend::External(worker) => Some(worker),
                    ProofVerificationBackend::Unavailable
                    | ProofVerificationBackend::InProcess
                    | ProofVerificationBackend::Stopped => None,
                }
            }
        };
        self.backend_generation.fetch_add(1, Ordering::AcqRel);
        if let Some(worker) = worker {
            worker.close();
        }
        if let Ok(mut cache) = self.successful_proofs.lock() {
            cache.entries.clear();
            cache.order.clear();
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub network: &'static str,
    pub network_short_name: &'static str,
    pub network_notice: &'static str,
    pub network_purpose: &'static str,
    pub network_id: String,
    pub consensus_fingerprint: String,
    pub proof_profile: &'static str,
    pub proof_of_work: &'static str,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub pool_port: u16,
    pub node_data_dir_identity: &'static str,
    pub wallet_data_dir_identity: &'static str,
    pub miner_data_dir_identity: &'static str,
    pub bounded_reference_mining: bool,
    pub tip: String,
    pub cumulative_work: String,
    pub accepted_height: u64,
    pub next_height: u64,
    pub expected_target: String,
    pub utxo_count: usize,
    pub mempool_transactions: usize,
    pub mempool_bytes: usize,
    pub proof_verification_active: usize,
    pub proof_verification_queued: usize,
    pub proof_verification_capacity: usize,
    pub proof_verification_queue_capacity: usize,
    pub proof_verification_mode: &'static str,
    pub proof_verification_timeout_ms: Option<u64>,
    pub proof_verification_memory_limit_bytes: Option<u64>,
    pub storage_healthy: bool,
    pub public_peer_mode: bool,
    pub peers: Vec<PeerObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    Connected,
    Reachable,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerObservation {
    pub address: String,
    pub direction: PeerDirection,
    pub state: PeerState,
    pub first_seen: u64,
    pub last_seen: u64,
    pub last_success: Option<u64>,
    pub successful_sessions: u64,
    pub failed_sessions: u64,
    pub active_connections: usize,
    pub remote_height: Option<u64>,
    pub remote_tip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PeerObservationKey {
    direction: PeerDirection,
    address: String,
}

#[derive(Debug, Clone)]
struct PeerObservationRecord {
    first_seen: u64,
    last_seen: u64,
    last_success: Option<u64>,
    last_attempt_succeeded: bool,
    successful_sessions: u64,
    failed_sessions: u64,
    active_connections: usize,
    remote_height: Option<u64>,
    remote_tip: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct BlockTemplate {
    pub challenge: BlockChallenge,
    pub coinbase: Coinbase,
    pub transactions: Vec<Transaction>,
    pub total_fees_burned: u64,
}

/// An immutable block template paired with the exact consensus verifier.
///
/// A caller should create this while briefly holding its node lock, release
/// that lock, and then search the job. A found block still has to pass through
/// [`Node::submit_block`], which independently handles stale work, proof
/// validation, persistence, and fork choice.
#[derive(Debug, Clone)]
pub struct MiningJob {
    template: BlockTemplate,
    verifier: ConsensusPowVerifier,
}

/// Proof-of-work state that is independent of a local chain database. Thin
/// miners construct this from a node-provided challenge and return only the
/// resulting proof inside that node's complete template.
#[derive(Debug, Clone)]
pub struct MiningWork {
    challenge: BlockChallenge,
    verifier: ConsensusPowVerifier,
    #[cfg(feature = "production-v3")]
    production_v3: Option<Arc<ProductionV3MiningContext>>,
}

/// Process-persistent, authenticated Production V3 mining state. Artifact
/// authentication and fixed-model preparation happen only while constructing
/// this factory. Every challenge then receives a cheap immutable `Arc` clone.
#[cfg(feature = "production-v3")]
#[derive(Debug, Clone)]
pub struct ProductionV3MiningWorkFactory {
    context: Arc<ProductionV3MiningContext>,
}

#[cfg(feature = "production-v3")]
#[derive(Debug)]
struct ProductionV3MiningContext {
    params: NetworkParams,
    verifier: ConsensusPowVerifier,
    prepared_model: PreparedForgeMatrixV3Model,
    artifacts: ProductionV3VerifierArtifacts,
    scratch_directory: PathBuf,
    maximum_native_block_rows: usize,
}

/// Exact progress from one bounded immutable mining-job search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiningSearchResult {
    Found {
        block: Box<Block>,
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

/// One independently recomputed pool-share candidate. A true
/// `meets_share_target` makes it creditable by the pool; only a true
/// `meets_chain_target` makes it eligible for block construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningShareEvaluation {
    pub proof: BlockProof,
    pub work_digest: [u8; 32],
    pub meets_share_target: bool,
    pub meets_chain_target: bool,
}

/// Exact progress from one bounded immutable pool-share search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiningShareSearchResult {
    Found {
        proof: BlockProof,
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

impl MiningJob {
    /// The immutable consensus challenge represented by this job.
    pub fn challenge(&self) -> &BlockChallenge {
        &self.template.challenge
    }

    pub fn work(&self) -> MiningWork {
        MiningWork {
            challenge: self.template.challenge,
            verifier: self.verifier.clone(),
            #[cfg(feature = "production-v3")]
            production_v3: None,
        }
    }

    pub fn accelerator_model(&self) -> Result<ForgeMatrixV2AcceleratorModel, NodeError> {
        Ok(self.verifier.v2_accelerator_model()?)
    }

    pub fn prepare_accelerator_batch(
        &self,
        start_nonce: u64,
        count: u32,
    ) -> Result<ForgeMatrixV2AcceleratorBatch, NodeError> {
        Ok(self.verifier.prepare_v2_accelerator_batch(
            &self.template.challenge,
            start_nonce,
            count,
        )?)
    }

    /// Full-recomputation differential check for one untrusted accelerator
    /// output. This does not apply a target and is intended for startup/canary
    /// validation of an optional backend.
    pub fn verify_accelerator_output(
        &self,
        batch: &ForgeMatrixV2AcceleratorBatch,
        index: usize,
        output: &[u8],
    ) -> Result<[u8; 32], NodeError> {
        self.verifier
            .validate_v2_accelerator_batch(&self.template.challenge, batch)?;
        let work_digest = batch
            .candidate_work_digest(index, output)
            .map_err(PowError::from)?;
        self.verifier.verify_v2_accelerator_candidate(
            &self.template.challenge,
            batch,
            index,
            work_digest,
        )?;
        Ok(work_digest)
    }

    /// Scans untrusted accelerator outputs, then fully recomputes the first
    /// claimed below-target nonce before returning it. Outputs are one
    /// canonical final activation per nonce in batch order.
    pub fn complete_accelerator_batch(
        &self,
        batch: &ForgeMatrixV2AcceleratorBatch,
        outputs: &[u8],
        share_target: [u8; 32],
    ) -> Result<MiningShareSearchResult, NodeError> {
        self.validate_share_target(share_target)?;
        self.verifier
            .validate_v2_accelerator_batch(&self.template.challenge, batch)?;
        let expected_len = batch
            .count()
            .checked_mul(batch.activation_len() as u32)
            .map(|length| length as usize)
            .ok_or(PowError::V2(ForgeMatrixV2Error::AcceleratorOutputShape))?;
        if outputs.len() != expected_len {
            return Err(NodeError::Pow(PowError::V2(
                ForgeMatrixV2Error::AcceleratorOutputShape,
            )));
        }

        for (index, output) in outputs.chunks_exact(batch.activation_len()).enumerate() {
            let work_digest = batch
                .candidate_work_digest(index, output)
                .map_err(PowError::from)?;
            if work_digest <= share_target {
                let proof = self.verifier.verify_v2_accelerator_candidate(
                    &self.template.challenge,
                    batch,
                    index,
                    work_digest,
                )?;
                let nonce = batch
                    .nonce_at(index)
                    .ok_or(PowError::V2(ForgeMatrixV2Error::AcceleratorOutputShape))?;
                return Ok(MiningShareSearchResult::Found {
                    proof,
                    work_digest,
                    meets_chain_target: work_digest <= self.template.challenge.target,
                    attempts_completed: index as u64 + 1,
                    next_nonce: nonce.wrapping_add(1),
                });
            }
        }

        Ok(MiningShareSearchResult::Exhausted {
            attempts_completed: batch.count().into(),
            next_nonce: batch.start_nonce().wrapping_add(u64::from(batch.count())),
        })
    }

    /// Return the immutable Production V3 model identities that an accelerator
    /// must report before its winning claim is eligible for CPU replay.
    #[cfg(feature = "production-v3")]
    pub fn v3_candidate_parameters(&self) -> Result<ForgeMatrixV3CandidateParameters, NodeError> {
        Ok(self.verifier.v3_candidate_parameters()?)
    }

    #[cfg(feature = "production-v3")]
    pub fn v3_winning_nonce_claim_from_accelerator_output(
        &self,
        accelerator_model_record_digest: [u8; 32],
        accelerator_model_identity_digest: [u8; 32],
        nonce: u64,
        final_activation: &[u8],
    ) -> Result<ForgeMatrixV3WinningNonceClaim, NodeError> {
        Ok(self
            .verifier
            .v3_winning_nonce_claim_from_accelerator_output(
                &self.template.challenge,
                accelerator_model_record_digest,
                accelerator_model_identity_digest,
                nonce,
                final_activation,
            )?)
    }

    /// Prove one identity-bound Production V3 winning claim without borrowing
    /// mutable node state. This is the long-running phase: callers must release
    /// any shared node mutex before invoking it and submit the returned block
    /// through [`Node::submit_block`] afterward.
    #[cfg(feature = "production-v3")]
    #[allow(clippy::too_many_arguments)]
    pub fn prove_v3_winning_nonce_claim<FixedModelBank: Read, ReplayBank: Read>(
        &self,
        claim: ForgeMatrixV3WinningNonceClaim,
        fixed_model_bank: FixedModelBank,
        replay_bank: ReplayBank,
        scratch_directory: &Path,
        maximum_native_block_rows: usize,
        cancel: &AtomicBool,
    ) -> Result<Box<Block>, NodeError> {
        let proof = self.verifier.prove_v3_winning_nonce_claim(
            &self.template.challenge,
            claim,
            fixed_model_bank,
            replay_bank,
            scratch_directory,
            maximum_native_block_rows,
            cancel,
        )?;
        let BlockProof::V3Candidate(_) = proof else {
            return Err(NodeError::CorruptLog(
                "Production V3 prover produced a non-v3 proof".to_owned(),
            ));
        };
        Ok(Box::new(Block {
            version: BLOCK_VERSION,
            challenge: self.template.challenge,
            proof,
            coinbase: self.template.coinbase.clone(),
            transactions: self.template.transactions.clone(),
        }))
    }

    /// Searches a bounded wrapping nonce range without accessing mutable node
    /// state. `should_cancel` is checked before every nonce evaluation.
    ///
    /// `next_nonce` always names the first nonce that was not evaluated. This
    /// lets a continuous miner resume without repeating work, including across
    /// the `u64::MAX` wrap boundary.
    pub fn search_range<F>(
        &self,
        start_nonce: u64,
        attempts: u64,
        mut should_cancel: F,
    ) -> Result<MiningSearchResult, NodeError>
    where
        F: FnMut() -> bool,
    {
        if attempts == 0 || attempts > MAX_MINING_SEARCH_ATTEMPTS {
            return Err(NodeError::InvalidMiningSearchAttempts);
        }

        let mut attempts_completed = 0_u64;
        while attempts_completed < attempts {
            let nonce = start_nonce.wrapping_add(attempts_completed);
            if should_cancel() {
                return Ok(MiningSearchResult::Cancelled {
                    attempts_completed,
                    next_nonce: nonce,
                });
            }

            match self.verifier.mine(&self.template.challenge, nonce, 1) {
                Ok(proof) => {
                    attempts_completed += 1;
                    let block = Box::new(Block {
                        version: BLOCK_VERSION,
                        challenge: self.template.challenge,
                        proof,
                        coinbase: self.template.coinbase.clone(),
                        transactions: self.template.transactions.clone(),
                    });
                    return Ok(MiningSearchResult::Found {
                        block,
                        attempts_completed,
                        next_nonce: nonce.wrapping_add(1),
                    });
                }
                Err(PowError::V1(ForgeMatrixError::NonceExhausted))
                | Err(PowError::V2(ForgeMatrixV2Error::NonceExhausted)) => {
                    attempts_completed += 1;
                }
                Err(error) => return Err(NodeError::Pow(error)),
            }
        }

        Ok(MiningSearchResult::Exhausted {
            attempts_completed,
            next_nonce: start_nonce.wrapping_add(attempts_completed),
        })
    }

    /// Recomputes the exact committed proof for a submitted nonce without
    /// replacing the challenge's chain target. The separately assigned share
    /// target is accepted only when it is easier than or equal to that chain
    /// target.
    pub fn evaluate_share(
        &self,
        nonce: u64,
        share_target: [u8; 32],
    ) -> Result<MiningShareEvaluation, NodeError> {
        self.validate_share_target(share_target)?;
        self.evaluate_share_unchecked(nonce, share_target)
    }

    /// Searches a bounded wrapping nonce range for a pool share. Cancellation
    /// is checked before each exact ForgeMatrix evaluation, and `next_nonce`
    /// always identifies the first nonce not evaluated.
    pub fn search_share_range<F>(
        &self,
        start_nonce: u64,
        attempts: u64,
        share_target: [u8; 32],
        mut should_cancel: F,
    ) -> Result<MiningShareSearchResult, NodeError>
    where
        F: FnMut() -> bool,
    {
        if attempts == 0 || attempts > MAX_MINING_SEARCH_ATTEMPTS {
            return Err(NodeError::InvalidMiningSearchAttempts);
        }
        self.validate_share_target(share_target)?;

        let mut attempts_completed = 0_u64;
        while attempts_completed < attempts {
            let nonce = start_nonce.wrapping_add(attempts_completed);
            if should_cancel() {
                return Ok(MiningShareSearchResult::Cancelled {
                    attempts_completed,
                    next_nonce: nonce,
                });
            }

            let evaluation = self.evaluate_share_unchecked(nonce, share_target)?;
            attempts_completed += 1;
            if evaluation.meets_share_target {
                return Ok(MiningShareSearchResult::Found {
                    proof: evaluation.proof,
                    work_digest: evaluation.work_digest,
                    meets_chain_target: evaluation.meets_chain_target,
                    attempts_completed,
                    next_nonce: nonce.wrapping_add(1),
                });
            }
        }

        Ok(MiningShareSearchResult::Exhausted {
            attempts_completed,
            next_nonce: start_nonce.wrapping_add(attempts_completed),
        })
    }

    /// Revalidates an untrusted submitted proof and constructs the immutable
    /// template's block only when the proof meets the original chain target.
    /// The returned block still has to pass [`Node::submit_block`].
    pub fn build_block_if_chain_valid(
        &self,
        proof: &BlockProof,
    ) -> Result<Option<Box<Block>>, NodeError> {
        self.verifier
            .verify_evaluation(&self.template.challenge, proof)?;
        if proof.work_digest() > self.template.challenge.target {
            return Ok(None);
        }
        Ok(Some(Box::new(Block {
            version: BLOCK_VERSION,
            challenge: self.template.challenge,
            proof: proof.clone(),
            coinbase: self.template.coinbase.clone(),
            transactions: self.template.transactions.clone(),
        })))
    }

    fn validate_share_target(&self, share_target: [u8; 32]) -> Result<(), NodeError> {
        if share_target < self.template.challenge.target {
            return Err(NodeError::InvalidMiningShareTarget);
        }
        Ok(())
    }

    fn evaluate_share_unchecked(
        &self,
        nonce: u64,
        share_target: [u8; 32],
    ) -> Result<MiningShareEvaluation, NodeError> {
        let proof = self.verifier.evaluate(&self.template.challenge, nonce)?;
        let work_digest = proof.work_digest();
        Ok(MiningShareEvaluation {
            proof,
            work_digest,
            meets_share_target: work_digest <= share_target,
            meets_chain_target: work_digest <= self.template.challenge.target,
        })
    }
}

#[cfg(feature = "production-v3")]
impl ProductionV3MiningWorkFactory {
    /// Authenticate the compiled network's pinned artifacts and prepare its
    /// fixed model exactly once for all subsequent immutable mining work.
    pub fn load(
        artifacts: ProductionV3VerifierArtifacts,
        scratch_directory: PathBuf,
        maximum_native_block_rows: usize,
        cancel: &AtomicBool,
    ) -> Result<Self, NodeError> {
        if !matches!(COMPILED_NETWORK_PROFILE.proof, ProofProfile::ProductionV3) {
            return Err(NodeError::ProductionV3Unavailable);
        }
        validate_production_v3_mining_configuration(
            &artifacts,
            &scratch_directory,
            maximum_native_block_rows,
        )?;
        let (params, verifier) =
            network_params_and_verifier_for_profile(COMPILED_NETWORK_PROFILE, Some(&artifacts))?;
        Self::from_authenticated_verifier(
            params,
            verifier,
            artifacts,
            scratch_directory,
            maximum_native_block_rows,
            cancel,
        )
    }

    fn from_authenticated_verifier(
        params: NetworkParams,
        verifier: ConsensusPowVerifier,
        artifacts: ProductionV3VerifierArtifacts,
        scratch_directory: PathBuf,
        maximum_native_block_rows: usize,
        cancel: &AtomicBool,
    ) -> Result<Self, NodeError> {
        validate_production_v3_mining_configuration(
            &artifacts,
            &scratch_directory,
            maximum_native_block_rows,
        )?;
        let bank = File::open(&artifacts.bank).map_err(|source| {
            io_error("open production V3 mining bank", &artifacts.bank, source)
        })?;
        let prepared_model =
            verifier.prepare_v3_fixed_model(BufReader::new(bank), &scratch_directory, cancel)?;
        Ok(Self {
            context: Arc::new(ProductionV3MiningContext {
                params,
                verifier,
                prepared_model,
                artifacts,
                scratch_directory,
                maximum_native_block_rows,
            }),
        })
    }

    /// Create one challenge-bound view without rereading any artifact.
    pub fn work(&self, challenge: BlockChallenge) -> Result<MiningWork, NodeError> {
        if challenge.network_id != self.context.params.network_id
            || challenge.target > self.context.params.pow_limit
        {
            return Err(NodeError::InvalidRpcRequest(
                "mining challenge does not belong to the compiled Production V3 network".to_owned(),
            ));
        }
        Ok(MiningWork {
            challenge,
            verifier: self.context.verifier.clone(),
            production_v3: Some(Arc::clone(&self.context)),
        })
    }

    /// Borrow the authenticated authority used by production CUDA context
    /// initialization. The bank path is exposed only as process configuration;
    /// the CUDA loader independently authenticates its complete stream.
    pub fn production_authority(
        &self,
    ) -> Result<
        (
            &cmfd_consensus::dory_v3_model_record::BankAuthenticatedDoryV3ModelCommitmentRecordV2,
            &cmfd_consensus::dory_bls12_381_prototype::DeterministicBlsDorySetup,
        ),
        NodeError,
    > {
        Ok(self.context.verifier.v3_production_authority()?)
    }

    pub fn bank_path(&self) -> &Path {
        &self.context.artifacts.bank
    }
}

#[cfg(feature = "production-v3")]
fn validate_production_v3_mining_configuration(
    artifacts: &ProductionV3VerifierArtifacts,
    scratch_directory: &Path,
    maximum_native_block_rows: usize,
) -> Result<(), NodeError> {
    if !artifacts.bank.is_absolute()
        || !artifacts.manifest.is_absolute()
        || !artifacts.record_v2.is_absolute()
        || artifacts.bank == artifacts.manifest
        || artifacts.bank == artifacts.record_v2
        || artifacts.manifest == artifacts.record_v2
        || !scratch_directory.is_absolute()
        || !scratch_directory.is_dir()
        || maximum_native_block_rows == 0
        || maximum_native_block_rows > MAX_PRODUCTION_V3_NATIVE_BLOCK_ROWS
    {
        return Err(NodeError::ProductionV3MiningConfiguration);
    }
    Ok(())
}

impl MiningWork {
    pub fn from_devnet_challenge(challenge: BlockChallenge) -> Result<Self, NodeError> {
        let params = devnet_params()?;
        if challenge.network_id != params.network_id || challenge.target > params.pow_limit {
            return Err(NodeError::InvalidRpcRequest(
                "mining challenge does not belong to this Devnet".to_owned(),
            ));
        }
        let reference = v2_reference_for_network(params.network_id).map_err(PowError::from)?;
        Ok(Self {
            challenge,
            verifier: ConsensusPowVerifier::v2_reference(reference),
            #[cfg(feature = "production-v3")]
            production_v3: None,
        })
    }

    pub fn challenge(&self) -> &BlockChallenge {
        &self.challenge
    }

    pub fn accelerator_model(&self) -> Result<ForgeMatrixV2AcceleratorModel, NodeError> {
        Ok(self.verifier.v2_accelerator_model()?)
    }

    pub fn accelerator_model_identity(&self) -> Result<[u8; 32], NodeError> {
        Ok(self.verifier.v2_accelerator_model_identity()?)
    }

    pub fn prepare_accelerator_batch(
        &self,
        start_nonce: u64,
        count: u32,
    ) -> Result<ForgeMatrixV2AcceleratorBatch, NodeError> {
        Ok(self
            .verifier
            .prepare_v2_accelerator_batch(&self.challenge, start_nonce, count)?)
    }

    pub fn verify_accelerator_output(
        &self,
        batch: &ForgeMatrixV2AcceleratorBatch,
        index: usize,
        output: &[u8],
    ) -> Result<[u8; 32], NodeError> {
        self.verifier
            .validate_v2_accelerator_batch(&self.challenge, batch)?;
        let work_digest = batch
            .candidate_work_digest(index, output)
            .map_err(PowError::from)?;
        self.verifier.verify_v2_accelerator_candidate(
            &self.challenge,
            batch,
            index,
            work_digest,
        )?;
        Ok(work_digest)
    }

    pub fn complete_accelerator_batch(
        &self,
        batch: &ForgeMatrixV2AcceleratorBatch,
        outputs: &[u8],
    ) -> Result<MiningShareSearchResult, NodeError> {
        self.verifier
            .validate_v2_accelerator_batch(&self.challenge, batch)?;
        let expected_len = batch
            .count()
            .checked_mul(batch.activation_len() as u32)
            .map(|length| length as usize)
            .ok_or(PowError::V2(ForgeMatrixV2Error::AcceleratorOutputShape))?;
        if outputs.len() != expected_len {
            return Err(NodeError::Pow(PowError::V2(
                ForgeMatrixV2Error::AcceleratorOutputShape,
            )));
        }

        for (index, output) in outputs.chunks_exact(batch.activation_len()).enumerate() {
            let work_digest = batch
                .candidate_work_digest(index, output)
                .map_err(PowError::from)?;
            if work_digest <= self.challenge.target {
                let proof = self.verifier.verify_v2_accelerator_candidate(
                    &self.challenge,
                    batch,
                    index,
                    work_digest,
                )?;
                let nonce = batch
                    .nonce_at(index)
                    .ok_or(PowError::V2(ForgeMatrixV2Error::AcceleratorOutputShape))?;
                return Ok(MiningShareSearchResult::Found {
                    proof,
                    work_digest,
                    meets_chain_target: true,
                    attempts_completed: index as u64 + 1,
                    next_nonce: nonce.wrapping_add(1),
                });
            }
        }

        Ok(MiningShareSearchResult::Exhausted {
            attempts_completed: batch.count().into(),
            next_nonce: batch.start_nonce().wrapping_add(u64::from(batch.count())),
        })
    }

    #[cfg(feature = "production-v3")]
    pub fn v3_candidate_parameters(&self) -> Result<ForgeMatrixV3CandidateParameters, NodeError> {
        Ok(self.verifier.v3_candidate_parameters()?)
    }

    #[cfg(feature = "production-v3")]
    pub fn prepare_v3_accelerator_batch(
        &self,
        start_nonce: u64,
        count: u32,
    ) -> Result<ForgeMatrixV3AcceleratorBatch, NodeError> {
        Ok(self
            .verifier
            .prepare_v3_accelerator_batch(&self.challenge, start_nonce, count)?)
    }

    #[cfg(feature = "production-v3")]
    pub fn v3_winning_nonce_claim_from_accelerator_batch_output(
        &self,
        batch: &ForgeMatrixV3AcceleratorBatch,
        index: usize,
        final_activation: &[u8],
    ) -> Result<Option<ForgeMatrixV3WinningNonceClaim>, NodeError> {
        Ok(self
            .verifier
            .v3_winning_nonce_claim_from_accelerator_batch_output(
                &self.challenge,
                batch,
                index,
                final_activation,
            )?)
    }

    #[cfg(feature = "production-v3")]
    pub fn v3_winning_nonce_claim_from_accelerator_output(
        &self,
        accelerator_model_record_digest: [u8; 32],
        accelerator_model_identity_digest: [u8; 32],
        nonce: u64,
        final_activation: &[u8],
    ) -> Result<ForgeMatrixV3WinningNonceClaim, NodeError> {
        Ok(self
            .verifier
            .v3_winning_nonce_claim_from_accelerator_output(
                &self.challenge,
                accelerator_model_record_digest,
                accelerator_model_identity_digest,
                nonce,
                final_activation,
            )?)
    }

    /// Replay and prove a Production V3 winning claim with process-reusable
    /// fixed-model state. Exact claim/target validation happens before opening
    /// the bank, and the replay path validates it again before its first read.
    #[cfg(feature = "production-v3")]
    pub fn prove_v3_winning_nonce_claim(
        &self,
        claim: ForgeMatrixV3WinningNonceClaim,
        cancel: &AtomicBool,
    ) -> Result<BlockProof, NodeError> {
        let context = self
            .production_v3
            .as_ref()
            .ok_or(NodeError::ProductionV3MiningConfiguration)?;
        self.verifier
            .validate_v3_winning_nonce_claim(&self.challenge, claim)?;
        let replay_bank = File::open(&context.artifacts.bank).map_err(|source| {
            io_error(
                "open production V3 winning-nonce replay bank",
                &context.artifacts.bank,
                source,
            )
        })?;
        Ok(self
            .verifier
            .prove_v3_winning_nonce_claim_with_prepared_model(
                &self.challenge,
                claim,
                &context.prepared_model,
                BufReader::new(replay_bank),
                &context.scratch_directory,
                context.maximum_native_block_rows,
                cancel,
            )?)
    }
}

#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub txid: [u8; 32],
    pub transaction: Transaction,
    pub encoded_bytes: usize,
    pub fee_burned: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WalletBalances {
    pub spendable_atoms: String,
    pub immature_atoms: String,
    pub pending_atoms: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WalletMempoolStatus {
    pub transactions: usize,
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WalletHistoryEntry {
    pub kind: &'static str,
    pub txid: String,
    pub height: Option<u64>,
    pub timestamp: Option<u64>,
    pub confirmations: u64,
    pub status: &'static str,
    pub net_amount_atoms: String,
    pub fee_burned_atoms: String,
    pub counterparty: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WalletSnapshot {
    pub network: &'static str,
    pub devnet_only: bool,
    pub insecure_demo_wallet: bool,
    pub warning: &'static str,
    pub destination: String,
    pub accepted_height: u64,
    pub next_height: u64,
    pub balances: WalletBalances,
    pub spendable_utxo_count: usize,
    pub immature_utxo_count: usize,
    pub reserved_utxo_count: usize,
    pub mempool: WalletMempoolStatus,
    pub history_limit: usize,
    pub history: Vec<WalletHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletSendRequest {
    pub recipient: String,
    pub amount: String,
    pub fee: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletConsolidateRequest {
    pub fee: String,
    pub max_inputs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevMineRequest {
    pub miner: String,
    pub attempts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MempoolSnapshotEntry {
    pub txid: String,
    pub encoded_bytes: usize,
    pub fee_burned: u64,
    pub fee_burned_atoms: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MempoolSnapshot {
    pub transactions: usize,
    pub bytes: usize,
    pub entries: Vec<MempoolSnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WalletSendResponse {
    pub network: &'static str,
    pub devnet_only: bool,
    pub insecure_demo_wallet: bool,
    pub warning: &'static str,
    pub txid: String,
    pub amount_atoms: String,
    pub fee_burned_atoms: String,
    pub change_atoms: String,
    pub mempool_transactions: usize,
    pub mempool_bytes: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WalletConsolidateResponse {
    pub network: &'static str,
    pub devnet_only: bool,
    pub insecure_demo_wallet: bool,
    pub warning: &'static str,
    pub txid: String,
    pub inputs_consolidated: usize,
    pub input_atoms: String,
    pub output_atoms: String,
    pub fee_burned_atoms: String,
    pub mempool_transactions: usize,
    pub mempool_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevMineResult {
    pub accepted: bool,
    pub block_id: String,
    pub height: u64,
    pub tip: String,
}

struct DataDirLock {
    _file: File,
}

impl DataDirLock {
    fn acquire(data_dir: &Path) -> Result<Self, NodeError> {
        fs::create_dir_all(data_dir)
            .map_err(|source| io_error("create data directory", data_dir, source))?;
        let path = data_dir.join(LOCK_FILE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| io_error("open data-directory lock file", &path, source))?;
        if let Err(source) = FileExt::try_lock_exclusive(&file) {
            let expected = fs2::lock_contended_error();
            let contended = match (source.raw_os_error(), expected.raw_os_error()) {
                (Some(actual), Some(expected)) => actual == expected,
                _ => source.kind() == expected.kind(),
            };
            if contended {
                return Err(NodeError::DataDirLocked(path));
            }
            return Err(io_error("lock data directory", &path, source));
        }
        file.set_len(0)
            .map_err(|source| io_error("refresh lock file", &path, source))?;
        writeln!(&mut file, "pid={}", std::process::id())
            .map_err(|source| io_error("write lock file", &path, source))?;
        file.sync_all()
            .map_err(|source| io_error("sync lock file", &path, source))?;
        Ok(Self { _file: file })
    }
}

fn open_block_log(path: &Path) -> Result<File, NodeError> {
    let mut options = OpenOptions::new();
    options.create(true).append(true).read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options.share_mode(FILE_SHARE_READ);
    }
    options
        .open(path)
        .map_err(|source| io_error("open block log", path, source))
}

#[cfg(unix)]
fn verify_retained_block_log_path(file: &File, path: &Path) -> Result<(), NodeError> {
    use std::os::unix::fs::MetadataExt;

    let retained = file
        .metadata()
        .map_err(|source| io_error("inspect retained block log", path, source))?;
    let current = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(NodeError::CorruptLog(
                "block log path was removed during startup replay".to_owned(),
            ));
        }
        Err(source) => return Err(io_error("inspect block log path", path, source)),
    };
    if retained.dev() != current.dev() || retained.ino() != current.ino() {
        return Err(NodeError::CorruptLog(
            "block log path no longer identifies the retained startup file".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsFileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[cfg(windows)]
fn windows_file_identity(
    file: &File,
    path: &Path,
    operation: &'static str,
) -> Result<WindowsFileIdentity, NodeError> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut information = FILE_ID_INFO::default();
    // SAFETY: `file` owns a valid handle for the duration of the call and the
    // output pointer names a correctly sized writable FILE_ID_INFO value.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if succeeded == 0 {
        return Err(io_error(operation, path, io::Error::last_os_error()));
    }
    Ok(WindowsFileIdentity {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

#[cfg(windows)]
fn verify_retained_block_log_path(file: &File, path: &Path) -> Result<(), NodeError> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    let retained = windows_file_identity(file, path, "identify retained block log handle")?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        // The transient identity handle must coexist with the retained append
        // handle. The retained handle itself still grants FILE_SHARE_READ only
        // and therefore continues to deny external write and delete access.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let current = match options.open(path) {
        Ok(current) => current,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(NodeError::CorruptLog(
                "block log path was removed or retargeted after startup".to_owned(),
            ));
        }
        Err(source) => {
            return Err(io_error(
                "open block log path for identity check",
                path,
                source,
            ));
        }
    };
    let current = windows_file_identity(&current, path, "identify current block log path")?;
    if retained != current {
        return Err(NodeError::CorruptLog(
            "block log path no longer identifies the retained startup file".to_owned(),
        ));
    }
    Ok(())
}

fn next_node_instance_id() -> Result<u64, NodeError> {
    NEXT_NODE_INSTANCE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| NodeError::CorruptLog("node instance identity counter exhausted".to_owned()))
}

pub struct Node {
    /// Process-local identity used to bind off-lock admissions to this exact
    /// live node value, even if the value inside a shared mutex is replaced.
    instance_id: u64,
    data_dir: PathBuf,
    profile: NetworkProfile,
    params: NetworkParams,
    fingerprint: [u8; 32],
    wallet_signing_key: SigningKey,
    legacy_shared_wallet: bool,
    verifier: ConsensusPowVerifier,
    #[cfg(feature = "production-v3")]
    production_v3_artifacts: Option<ProductionV3VerifierArtifacts>,
    block_preverifier: BlockPreverifier,
    state: ChainState,
    index: BlockIndex,
    /// Monotonically changes after every successful block commit. External
    /// proof admissions bind to this value so branch snapshots cannot be
    /// committed after chain state or fork choice changes.
    chain_revision: u64,
    mempool: BTreeMap<[u8; 32], MempoolEntry>,
    mempool_bytes: usize,
    log: File,
    /// Digest of the exact last complete block-log record. V2 appends bind to
    /// this value; it advances only after the durable record commits in memory.
    last_record_digest: [u8; 32],
    /// Authenticated end offset established by startup replay and advanced only
    /// after a complete record is durably written at that exact position.
    block_log_length: u64,
    storage_faulted: bool,
    rejected_proof_ids: HashSet<[u8; 32]>,
    rejected_proof_order: VecDeque<[u8; 32]>,
    rejected_body_digests: HashSet<[u8; 32]>,
    rejected_body_order: VecDeque<[u8; 32]>,
    public_peer_mode: bool,
    peer_observations: BTreeMap<PeerObservationKey, PeerObservationRecord>,
    _lock: DataDirLock,
}

/// Compact durable location and authenticated identity of one block-log record.
///
/// The locator is metadata only. Canonical block bytes and process-local proof
/// capabilities are deliberately never retained in the fork index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockRecordLocator {
    ordinal: u64,
    offset: u64,
    length: u64,
    version: BlockRecordVersion,
    complete_digest: [u8; 32],
    accepted_at: u64,
    block_id: [u8; 32],
    parent: [u8; 32],
    height: u64,
    target: [u8; 32],
}

/// A fully validated block retained by the fork index.
///
/// The retained block log is authoritative for block bodies. The index keeps
/// only authenticated record locators plus the compact fork-choice metadata
/// needed without disk access.
#[derive(Debug, Clone)]
struct IndexedBlock {
    locator: BlockRecordLocator,
    cumulative_work: U512,
    successor_header: SuccessorHeaderPreflight,
    /// Binary-lifting ancestors. Entry `k` is the `2^k`-th ancestor, allowing
    /// bounded checkpoint slices to be selected without a height-linear walk
    /// under the node mutex.
    ancestors: Vec<[u8; 32]>,
}

impl IndexedBlock {
    fn block_id(&self) -> [u8; 32] {
        self.locator.block_id
    }

    fn parent(&self) -> [u8; 32] {
        self.locator.parent
    }

    fn height(&self) -> u64 {
        self.locator.height
    }

    fn accepted_at(&self) -> u64 {
        self.locator.accepted_at
    }
}

#[derive(Debug)]
struct BlockIndex {
    genesis: [u8; 32],
    blocks: HashMap<[u8; 32], Arc<IndexedBlock>>,
    /// Active block identifiers in height order, including virtual genesis at
    /// index zero.
    active_chain: Vec<[u8; 32]>,
    active_work: U512,
}

#[derive(Debug)]
struct BranchStateCheckpoint {
    block_id: [u8; 32],
    state: Box<ChainState>,
    path: Vec<[u8; 32]>,
}

#[derive(Debug)]
struct BranchStatePlan {
    /// `None` denotes virtual genesis, which is cheap to reconstruct.
    base: Option<Box<ChainState>>,
    path: Vec<[u8; 32]>,
    replay: Vec<BranchReplayBlock>,
    target_parent: [u8; 32],
    reaches_target: bool,
}

#[derive(Debug)]
struct BranchReplayBlock {
    indexed: Arc<IndexedBlock>,
    block: Block,
}

impl BlockIndex {
    fn new(genesis: [u8; 32]) -> Self {
        Self {
            genesis,
            blocks: HashMap::new(),
            active_chain: vec![genesis],
            active_work: U512::zero(),
        }
    }

    fn contains(&self, block_id: [u8; 32]) -> bool {
        block_id == self.genesis || self.blocks.contains_key(&block_id)
    }

    fn work_at(&self, block_id: [u8; 32]) -> Option<U512> {
        if block_id == self.genesis {
            Some(U512::zero())
        } else {
            self.blocks
                .get(&block_id)
                .map(|entry| entry.cumulative_work)
        }
    }

    fn path_to(&self, tip: [u8; 32]) -> Result<Vec<[u8; 32]>, NodeError> {
        if tip == self.genesis {
            return Ok(Vec::new());
        }
        let mut reversed = Vec::new();
        let mut cursor = tip;
        while cursor != self.genesis {
            if reversed.len() >= self.blocks.len() {
                return Err(NodeError::CorruptLog(
                    "fork index contains a parent cycle".to_owned(),
                ));
            }
            let entry = self.blocks.get(&cursor).ok_or_else(|| {
                NodeError::CorruptLog("fork index contains a missing parent".to_owned())
            })?;
            reversed.push(cursor);
            cursor = entry.parent();
        }
        reversed.reverse();
        Ok(reversed)
    }

    fn active_position(&self, block_id: [u8; 32]) -> Option<usize> {
        if block_id == self.genesis {
            return (self.active_chain.first().copied() == Some(self.genesis)).then_some(0);
        }

        let position = usize::try_from(self.blocks.get(&block_id)?.height()).ok()?;
        (self.active_chain.get(position).copied() == Some(block_id)).then_some(position)
    }

    fn ancestor_at_height(&self, tip: [u8; 32], target_height: u64) -> Result<[u8; 32], NodeError> {
        if tip == self.genesis {
            return (target_height == 0)
                .then_some(self.genesis)
                .ok_or_else(|| NodeError::CorruptLog("genesis has no descendants".to_owned()));
        }
        let mut cursor = tip;
        let tip_height = self
            .blocks
            .get(&tip)
            .ok_or(NodeError::UnknownParent(tip))?
            .height();
        let mut distance = tip_height.checked_sub(target_height).ok_or_else(|| {
            NodeError::CorruptLog("ancestor height is above the indexed tip".to_owned())
        })?;
        let mut bit = 0_usize;
        while distance != 0 {
            if distance & 1 != 0 {
                let entry = self.blocks.get(&cursor).ok_or_else(|| {
                    NodeError::CorruptLog("ancestor table refers to an absent block".to_owned())
                })?;
                cursor = *entry.ancestors.get(bit).ok_or_else(|| {
                    NodeError::CorruptLog("ancestor table is shorter than its height".to_owned())
                })?;
            }
            distance >>= 1;
            bit = bit.saturating_add(1);
        }
        Ok(cursor)
    }

    fn ancestor_table(&self, parent: [u8; 32]) -> Result<Vec<[u8; 32]>, NodeError> {
        let mut ancestors = vec![parent];
        let mut level = 1_usize;
        while let Some(previous) = ancestors.get(level - 1).copied() {
            if previous == self.genesis {
                break;
            }
            let previous_entry = self
                .blocks
                .get(&previous)
                .ok_or(NodeError::UnknownParent(previous))?;
            let Some(ancestor) = previous_entry.ancestors.get(level - 1).copied() else {
                break;
            };
            ancestors.push(ancestor);
            level = level.saturating_add(1);
        }
        Ok(ancestors)
    }

    /// Captures one bounded, resumable slice toward `parent`. The optional
    /// work-local checkpoint is moved, never cloned. It must describe the
    /// exact ancestry already reconstructed by this admission.
    fn branch_state_plan(
        &self,
        parent: [u8; 32],
        checkpoint: Option<BranchStateCheckpoint>,
        log: &File,
        log_path: &Path,
        network_id: [u8; 32],
        require_v2: bool,
    ) -> Result<BranchStatePlan, NodeError> {
        if parent == self.genesis {
            if checkpoint.is_some() {
                return Err(NodeError::StaleBlockAdmission);
            }
            return Ok(BranchStatePlan {
                base: None,
                path: vec![self.genesis],
                replay: Vec::new(),
                target_parent: parent,
                reaches_target: true,
            });
        }

        let parent_height = self
            .blocks
            .get(&parent)
            .ok_or(NodeError::UnknownParent(parent))?
            .height();
        let (base_height, base, path) = match checkpoint {
            Some(checkpoint) => {
                let usable = checkpoint.state.tip() == checkpoint.block_id
                    && checkpoint.path.last() == Some(&checkpoint.block_id)
                    && checkpoint.path.first() == Some(&self.genesis)
                    && self.blocks.get(&checkpoint.block_id).is_some_and(|entry| {
                        entry.height() <= parent_height
                            && usize::try_from(entry.height())
                                .ok()
                                .and_then(|height| height.checked_add(1))
                                == Some(checkpoint.path.len())
                    })
                    && self.blocks.get(&checkpoint.block_id).is_some_and(|entry| {
                        self.ancestor_at_height(parent, entry.height())
                            .is_ok_and(|ancestor| ancestor == checkpoint.block_id)
                    });
                if usable {
                    let height = self.blocks[&checkpoint.block_id].height();
                    (height, Some(checkpoint.state), checkpoint.path)
                } else {
                    (0, None, vec![self.genesis])
                }
            }
            None => (0, None, vec![self.genesis]),
        };
        let end_height = parent_height
            .min(base_height.saturating_add(MAX_EXTERNAL_RECONSTRUCTION_BLOCKS_PER_SLICE as u64));
        let mut replay = Vec::with_capacity(
            usize::try_from(end_height.saturating_sub(base_height)).unwrap_or(0),
        );
        for height in base_height.saturating_add(1)..=end_height {
            let block_id = self.ancestor_at_height(parent, height)?;
            let indexed = self
                .blocks
                .get(&block_id)
                .cloned()
                .ok_or(NodeError::UnknownParent(block_id))?;
            if indexed.block_id() != block_id {
                return Err(NodeError::CorruptLog(
                    "fork index key does not match its durable record locator".to_owned(),
                ));
            }
            let block =
                read_indexed_block(log, log_path, &indexed, block_id, network_id, require_v2)?;
            replay.push(BranchReplayBlock { indexed, block });
        }
        Ok(BranchStatePlan {
            base,
            path,
            replay,
            target_parent: parent,
            reaches_target: end_height == parent_height,
        })
    }
}

enum ValidatedCandidate {
    Active(ValidatedBlock),
    Branch {
        state: Box<ChainState>,
        validated: ValidatedBlock,
    },
}

struct PreparedBlock {
    block_id: [u8; 32],
    parent: [u8; 32],
    height: u64,
    target: [u8; 32],
    accepted_at: u64,
    cumulative_work: U512,
    ancestors: Vec<[u8; 32]>,
    activation_chain: Option<Vec<[u8; 32]>>,
    candidate: ValidatedCandidate,
}

impl PreparedBlock {
    fn validated_block(&self) -> &ValidatedBlock {
        match &self.candidate {
            ValidatedCandidate::Active(validated)
            | ValidatedCandidate::Branch { validated, .. } => validated,
        }
    }

    fn encode_reversible_state_delta(&self) -> Result<Vec<u8>, ReversibleStateDeltaError> {
        self.validated_block().encode_reversible_state_delta()
    }
}

struct BlockPreparationContext<'a> {
    params: NetworkParams,
    verifier: &'a ConsensusPowVerifier,
    block_log: &'a File,
    block_log_path: &'a Path,
    accepted_at: u64,
    preverified: Option<&'a PreverifiedBlockProof>,
    branch_state: Option<Box<ChainState>>,
    activation_chain: Option<Vec<[u8; 32]>>,
    allow_index_reconstruction: bool,
}

#[derive(Debug)]
enum AdmissionStateSnapshot {
    Active,
    Branch(BranchStatePlan),
}

/// Immutable, revision-bound work captured while holding the shared node
/// mutex. Completing this value never touches live node state.
pub(crate) struct ExternalBlockAdmissionWork {
    node_instance_id: u64,
    revision: u64,
    block_id: [u8; 32],
    parent: [u8; 32],
    accepted_at: u64,
    params: NetworkParams,
    verifier: ConsensusPowVerifier,
    block_preverifier: BlockPreverifier,
    state_snapshot: AdmissionStateSnapshot,
}

/// Completed admission state. This is not proof evidence: it only carries the
/// state reconstruction and cheap consensus preflight performed outside the
/// node mutex. The external worker capability is still required separately.
#[derive(Debug)]
pub(crate) struct ExternalBlockAdmission {
    revision: u64,
    block_id: [u8; 32],
    parent: [u8; 32],
    accepted_at: u64,
    branch_state: Option<Box<ChainState>>,
    activation_chain: Option<Vec<[u8; 32]>>,
}

enum ExternalBlockAdmissionProgress {
    Ready(ExternalBlockAdmission),
    Checkpoint { checkpoint: BranchStateCheckpoint },
}

#[cfg(test)]
impl ExternalBlockAdmissionProgress {
    fn into_ready(self) -> ExternalBlockAdmission {
        match self {
            Self::Ready(admission) => admission,
            Self::Checkpoint { .. } => panic!("test admission unexpectedly required another slice"),
        }
    }
}

impl ExternalBlockAdmissionWork {
    fn requires_reconstruction(&self) -> bool {
        matches!(&self.state_snapshot, AdmissionStateSnapshot::Branch(_))
    }

    pub(crate) fn complete(
        self,
        block: &Block,
    ) -> Result<ExternalBlockAdmissionProgress, NodeError> {
        if block.block_id() != self.block_id || block.challenge.previous_block != self.parent {
            return Err(NodeError::StaleBlockAdmission);
        }
        let (branch_state, reconstructed_path) = match self.state_snapshot {
            AdmissionStateSnapshot::Active => (None, Vec::new()),
            AdmissionStateSnapshot::Branch(plan) => {
                let target_parent = plan.target_parent;
                let reaches_target = plan.reaches_target;
                let (state, path) = complete_branch_state_plan(
                    self.params,
                    &self.verifier,
                    &self.block_preverifier,
                    plan,
                )?;
                if !reaches_target {
                    let block_id = state.tip();
                    return Ok(ExternalBlockAdmissionProgress::Checkpoint {
                        checkpoint: BranchStateCheckpoint {
                            block_id,
                            state: Box::new(state),
                            path,
                        },
                    });
                }
                if state.tip() != self.parent {
                    return Err(NodeError::CorruptLog(
                        "captured fork state does not end at the requested parent".to_owned(),
                    ));
                }
                state.preflight_block(
                    block,
                    BlockValidationContext {
                        now_unix_seconds: self.accepted_at,
                    },
                )?;
                if target_parent != self.parent {
                    return Err(NodeError::CorruptLog(
                        "captured fork plan targets another parent".to_owned(),
                    ));
                }
                (Some(Box::new(state)), path)
            }
        };
        let activation_chain = branch_state.as_ref().map(|_| {
            let mut chain = reconstructed_path;
            let expected = usize::try_from(block.challenge.height)
                .unwrap_or(0)
                .saturating_add(1);
            chain.reserve(expected.saturating_sub(chain.len()));
            chain.push(self.block_id);
            chain
        });
        Ok(ExternalBlockAdmissionProgress::Ready(
            ExternalBlockAdmission {
                revision: self.revision,
                block_id: self.block_id,
                parent: self.parent,
                accepted_at: self.accepted_at,
                branch_state,
                activation_chain,
            },
        ))
    }
}

fn complete_branch_state_plan(
    params: NetworkParams,
    verifier: &ConsensusPowVerifier,
    block_preverifier: &BlockPreverifier,
    plan: BranchStatePlan,
) -> Result<(ChainState, Vec<[u8; 32]>), NodeError> {
    let mut state = match plan.base {
        Some(base) => *base,
        None => ChainState::new(params, verifier.clone())?,
    };
    let mut path = plan.path;
    for replay in plan.replay {
        let entry = replay.indexed;
        let block = replay.block;
        if state.tip() != entry.parent() {
            return Err(NodeError::CorruptLog(
                "bounded fork reconstruction has inconsistent ancestry".to_owned(),
            ));
        }
        if block.block_id() != entry.block_id()
            || block.challenge.previous_block != entry.parent()
            || block.challenge.height != entry.height()
        {
            return Err(NodeError::CorruptLog(
                "captured indexed block metadata does not match its canonical frame".to_owned(),
            ));
        }
        let context = BlockValidationContext {
            now_unix_seconds: entry.accepted_at(),
        };
        // This reconstruction path exists only for externally admitted
        // ProductionV3 side branches. Never recover proof authority from the
        // index: freshly preverify the exact locator-backed block each time.
        let preverified = match block_preverifier.preverify_unqueued(&block) {
            Ok(preverified) => preverified,
            Err(NodeError::ProofVerifierWorker(VerifierWorkerError::ProofRejected(error))) => {
                return Err(NodeError::CorruptLog(format!(
                    "indexed production block proof is rejected during fresh fork replay: {error}"
                )));
            }
            Err(error) => return Err(error),
        };
        let validated = state
            .validate_block_preverified(&block, context, &preverified)
            .map_err(|error| {
                NodeError::CorruptLog(format!(
                    "captured production fork block fails freshly preverified replay: {error}"
                ))
            })?;
        state.commit_validated(validated).map_err(|error| {
            NodeError::CorruptLog(format!(
                "captured production fork block cannot commit during replay: {error}"
            ))
        })?;
        let successor_header = state.successor_header_preflight().map_err(|error| {
            NodeError::CorruptLog(format!(
                "captured production fork successor state is invalid: {error}"
            ))
        })?;
        if successor_header != entry.successor_header {
            return Err(NodeError::CorruptLog(
                "captured production fork header snapshot does not match replayed state".to_owned(),
            ));
        }
        path.push(entry.block_id());
    }
    Ok((state, path))
}

fn requires_external_preverification(params: &NetworkParams) -> bool {
    #[cfg(feature = "production-v3")]
    {
        matches!(params.pow, PowParameters::V3Candidate(_))
    }
    #[cfg(not(feature = "production-v3"))]
    {
        let _ = params;
        false
    }
}

pub(crate) fn network_params_and_verifier_for_profile(
    profile: NetworkProfile,
    production_v3_artifacts: Option<&ProductionV3VerifierArtifacts>,
) -> Result<(NetworkParams, ConsensusPowVerifier), NodeError> {
    let verifier = match profile.proof {
        ProofProfile::DevnetV2Reference => {
            if production_v3_artifacts.is_some() {
                return Err(NodeError::ProductionV3ArtifactsUnexpected);
            }
            let reference = v2_reference_for_network(profile.network_id).map_err(PowError::from)?;
            ConsensusPowVerifier::v2_reference(reference)
        }
        ProofProfile::ProductionV3 => {
            #[cfg(feature = "production-v3")]
            {
                let artifacts =
                    production_v3_artifacts.ok_or(NodeError::ProductionV3ArtifactsMissing)?;
                let pins = release_gate::COMPILED_RELEASE_PROFILE
                    .production_v3_artifacts
                    .ok_or(NodeError::ProductionV3ArtifactPinsMissing)?;
                let loaded = cmfd_consensus::dory_v3_model_bank_record_validation::load_production_dory_v3_consensus_verifier(
                    profile.network_id,
                    &artifacts.bank,
                    &artifacts.manifest,
                    &artifacts.record_v2,
                )
                .map_err(NodeError::ProductionV3Artifacts)?;
                require_production_v3_file_identity("bank", pins.bank, loaded.bank_file())?;
                require_production_v3_file_identity(
                    "manifest",
                    pins.manifest,
                    loaded.manifest_file(),
                )?;
                require_production_v3_file_identity(
                    "Record V2",
                    pins.record_v2,
                    loaded.record_v2_file(),
                )?;
                loaded.into_verifier()
            }
            #[cfg(not(feature = "production-v3"))]
            {
                let _ = production_v3_artifacts;
                return Err(NodeError::ProductionV3Unavailable);
            }
        }
    };
    let pow = verifier.parameters();
    let params = NetworkParams {
        network_id: profile.network_id,
        protocol_version: NETWORK_PROTOCOL_VERSION,
        genesis_hash: profile.virtual_genesis_hash,
        genesis_timestamp: profile.virtual_genesis_timestamp,
        pow_limit: profile.pow_limit,
        pow,
        monetary_policy: DEFAULT_MONETARY_POLICY,
        rewards: FixedRewardDestinations {
            steward: profile.rewards.steward,
            community: profile.rewards.community,
        },
        max_future_offset_secs: MAX_FUTURE_OFFSET_SECS,
    };
    params.validate()?;
    Ok((params, verifier))
}

#[cfg(feature = "production-v3")]
fn require_production_v3_file_identity(
    name: &'static str,
    pin: release_gate::ProductionV3FileIdentityPin,
    actual: &cmfd_consensus::dory_v3_model_ceremony_transcript::FileIdentity,
) -> Result<(), NodeError> {
    if pin.bytes != actual.bytes || pin.blake3 != actual.blake3 || pin.sha256 != actual.sha256 {
        return Err(NodeError::ProductionV3ArtifactIdentityMismatch(name));
    }
    Ok(())
}

fn network_params_for_profile(profile: NetworkProfile) -> Result<NetworkParams, NodeError> {
    network_params_and_verifier_for_profile(profile, None).map(|(params, _)| params)
}

pub fn devnet_params() -> Result<NetworkParams, NodeError> {
    network_params_for_profile(COMPILED_NETWORK_PROFILE)
}

pub fn default_miner_destination() -> [u8; 32] {
    insecure_dev_wallet_signing_key()
        .verifying_key()
        .to_bytes()
        .into()
}

pub fn parse_miner_destination(value: &str) -> Result<[u8; 32], NodeError> {
    if value.len() != 64 {
        return Err(NodeError::InvalidMinerDestination);
    }
    let bytes = hex::decode(value).map_err(|_| NodeError::InvalidMinerDestination)?;
    let destination: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NodeError::InvalidMinerDestination)?;
    VerifyingKey::from_bytes(&destination).map_err(|_| NodeError::InvalidMinerDestination)?;
    Ok(destination)
}

pub fn unix_time_seconds() -> Result<u64, NodeError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NodeError::InvalidSystemTime)?
        .as_secs())
}

impl Node {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, NodeError> {
        Self::open_with_profile(data_dir, COMPILED_NETWORK_PROFILE)
    }

    /// Opens the compiled network with explicit V3 verifier artifacts when
    /// that network selects the production proof. Devnet rejects the paths so
    /// an operator cannot accidentally believe they changed its proof rules.
    pub fn open_with_artifacts(
        data_dir: impl AsRef<Path>,
        production_v3_artifacts: Option<&ProductionV3VerifierArtifacts>,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            COMPILED_NETWORK_PROFILE,
            production_v3_artifacts,
            None,
        )
    }

    /// Opens the compiled network with a verifier worker installed before any
    /// stored block is replayed. ProductionV3 requires this entry point so the
    /// parent never verifies a production proof in-process.
    pub fn open_with_artifacts_and_verifier_worker(
        data_dir: impl AsRef<Path>,
        production_v3_artifacts: Option<&ProductionV3VerifierArtifacts>,
        verifier_worker: VerifierWorkerConfig,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            COMPILED_NETWORK_PROFILE,
            production_v3_artifacts,
            Some(verifier_worker),
        )
    }

    /// Opens the node on an explicit immutable network profile.
    ///
    /// RCNet-1 fails before acquiring a data-directory lock unless its exact
    /// V3 artifact chain can construct the consensus verifier. This ordering
    /// prevents a failed RC attempt from creating or modifying storage.
    pub fn open_with_profile(
        data_dir: impl AsRef<Path>,
        profile: NetworkProfile,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_and_artifacts(data_dir, profile, None)
    }

    /// Opens one explicit network and authenticates any required production
    /// artifacts before acquiring or creating the node data directory.
    pub fn open_with_profile_and_artifacts(
        data_dir: impl AsRef<Path>,
        profile: NetworkProfile,
        production_v3_artifacts: Option<&ProductionV3VerifierArtifacts>,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            profile,
            production_v3_artifacts,
            None,
        )
    }

    fn open_with_profile_artifacts_and_worker(
        data_dir: impl AsRef<Path>,
        profile: NetworkProfile,
        production_v3_artifacts: Option<&ProductionV3VerifierArtifacts>,
        verifier_worker: Option<VerifierWorkerConfig>,
    ) -> Result<Self, NodeError> {
        let (params, verifier) =
            network_params_and_verifier_for_profile(profile, production_v3_artifacts)?;
        let block_preverifier = BlockPreverifier::new(verifier.clone(), profile.proof);
        let external_replay = verifier_worker.is_some();
        if let Some(config) = verifier_worker {
            install_external_proof_verifier(profile, &block_preverifier, config)?;
        } else if matches!(profile.proof, ProofProfile::ProductionV3) {
            return Err(NodeError::ProductionV3Unavailable);
        }
        let data_dir = data_dir.as_ref().to_path_buf();
        let lock = DataDirLock::acquire(&data_dir)?;
        let log_path = data_dir.join(BLOCK_LOG_FILE);
        let log = open_block_log(&log_path)?;
        let fingerprint = params.fingerprint()?;
        let metadata = load_metadata(&data_dir, fingerprint, &log, &log_path)?;
        let (wallet_signing_key, legacy_shared_wallet) =
            load_or_create_wallet_key(&data_dir, metadata, &log, &log_path)?;

        let mut state = ChainState::new(params, verifier.clone())?;
        let mut index = BlockIndex::new(params.genesis_hash);
        let replay = replay_log(
            &log,
            &log_path,
            &mut state,
            &mut index,
            &verifier,
            params,
            external_replay.then_some(&block_preverifier),
        )?;
        if metadata != MetadataState::Current {
            write_metadata(&data_dir, fingerprint, metadata)?;
        }
        let chain_revision = u64::try_from(index.blocks.len()).map_err(|_| {
            NodeError::CorruptLog("block count exceeds the revision counter".to_owned())
        })?;
        if chain_revision != replay.record_count {
            return Err(NodeError::CorruptLog(
                "startup record count does not match the fork index".to_owned(),
            ));
        }

        Ok(Self {
            instance_id: next_node_instance_id()?,
            data_dir,
            profile,
            params,
            fingerprint,
            wallet_signing_key,
            legacy_shared_wallet,
            verifier,
            #[cfg(feature = "production-v3")]
            production_v3_artifacts: production_v3_artifacts.cloned(),
            block_preverifier,
            state,
            index,
            chain_revision,
            mempool: BTreeMap::new(),
            mempool_bytes: 0,
            log,
            last_record_digest: replay.last_record_digest,
            block_log_length: replay.log_length,
            storage_faulted: false,
            rejected_proof_ids: HashSet::new(),
            rejected_proof_order: VecDeque::new(),
            rejected_body_digests: HashSet::new(),
            rejected_body_order: VecDeque::new(),
            public_peer_mode: false,
            peer_observations: BTreeMap::new(),
            _lock: lock,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    fn latch_authenticated_storage_failure<T>(
        &mut self,
        result: Result<T, NodeError>,
    ) -> Result<T, NodeError> {
        if result.as_ref().is_err_and(is_authenticated_storage_failure) {
            self.storage_faulted = true;
        }
        result
    }

    fn latch_external_completion_failure(
        &mut self,
        node_instance_id: u64,
        chain_revision: u64,
        error: &NodeError,
    ) {
        if self.instance_id == node_instance_id
            && self.chain_revision == chain_revision
            && is_authenticated_storage_failure(error)
        {
            self.storage_faulted = true;
        }
    }

    pub fn network_profile(&self) -> NetworkProfile {
        self.profile
    }

    /// Prepare process-reusable Production V3 mining state from the verifier
    /// already authenticated by this node. This avoids authenticating the
    /// manifest and Record V2 a second time in embedded-node mining mode.
    #[cfg(feature = "production-v3")]
    pub fn production_v3_mining_work_factory(
        &self,
        scratch_directory: PathBuf,
        maximum_native_block_rows: usize,
        cancel: &AtomicBool,
    ) -> Result<ProductionV3MiningWorkFactory, NodeError> {
        if !matches!(self.profile.proof, ProofProfile::ProductionV3) {
            return Err(NodeError::ProductionV3Unavailable);
        }
        let artifacts = self
            .production_v3_artifacts
            .clone()
            .ok_or(NodeError::ProductionV3ArtifactsMissing)?;
        ProductionV3MiningWorkFactory::from_authenticated_verifier(
            self.params,
            self.verifier.clone(),
            artifacts,
            scratch_directory,
            maximum_native_block_rows,
            cancel,
        )
    }

    pub fn block_preverifier(&self) -> BlockPreverifier {
        self.block_preverifier.clone()
    }

    /// Permanently closes proof admission and terminates the current external
    /// verifier generation. Service owners call this before joining RPC/P2P
    /// threads so queued requests cannot restart a worker during shutdown.
    pub fn shutdown_proof_verifier(&self) {
        self.block_preverifier.shutdown();
    }

    /// Enables hash-pinned, killable proof verification for Devnet testing.
    /// Production must install its worker before startup replay through
    /// `open_with_artifacts_and_verifier_worker` and cannot switch backends at
    /// runtime.
    pub fn use_external_proof_verifier(
        &mut self,
        config: VerifierWorkerConfig,
    ) -> Result<(), NodeError> {
        if matches!(self.profile.proof, ProofProfile::ProductionV3) {
            return Err(NodeError::ProductionV3Unavailable);
        }
        install_external_proof_verifier(self.profile, &self.block_preverifier, config)
    }

    pub fn wallet_destination(&self) -> [u8; 32] {
        self.wallet_signing_key.verifying_key().to_bytes().into()
    }

    pub fn set_public_peer_mode(&mut self, enabled: bool) {
        self.public_peer_mode = enabled;
    }

    fn wallet_warning(&self) -> &'static str {
        self.profile.wallet_warning(self.legacy_shared_wallet)
    }

    pub fn wallet_is_insecure_demo(&self) -> bool {
        self.legacy_shared_wallet
    }

    pub fn status(&self) -> Result<NodeStatus, NodeError> {
        let (proof_verification_active, proof_verification_queued) =
            self.block_preverifier.queue.counts()?;
        let (
            proof_verification_mode,
            proof_verification_timeout_ms,
            proof_verification_memory_limit_bytes,
        ) = self.block_preverifier.backend_status()?;
        Ok(NodeStatus {
            network: self.profile.name,
            network_short_name: self.profile.short_name(),
            network_notice: self.profile.network_notice(),
            network_purpose: self.profile.network_purpose(),
            network_id: hex::encode(self.params.network_id),
            consensus_fingerprint: hex::encode(self.fingerprint),
            proof_profile: self.profile.proof.profile_name(),
            proof_of_work: self.profile.proof_name(),
            rpc_port: self.profile.rpc_port,
            p2p_port: self.profile.p2p_port,
            pool_port: self.profile.pool_port,
            node_data_dir_identity: self.profile.default_data_dir_identity,
            wallet_data_dir_identity: self.profile.wallet_data_dir_identity,
            miner_data_dir_identity: self.profile.miner_data_dir_identity(),
            bounded_reference_mining: self.profile.proof.supports_bounded_reference_mining(),
            tip: hex::encode(self.state.tip()),
            cumulative_work: hex::encode(chain_work_bytes(self.index.active_work)),
            accepted_height: self.state.next_height().saturating_sub(1),
            next_height: self.state.next_height(),
            expected_target: hex::encode(self.state.expected_target()?),
            utxo_count: self.state.utxos().len(),
            mempool_transactions: self.mempool.len(),
            mempool_bytes: self.mempool_bytes,
            proof_verification_active,
            proof_verification_queued,
            proof_verification_capacity: self.block_preverifier.queue.max_active,
            proof_verification_queue_capacity: self
                .block_preverifier
                .queue
                .max_queued
                .saturating_add(MAX_PRIORITY_QUEUED_PROOF_VERIFICATIONS),
            proof_verification_mode,
            proof_verification_timeout_ms,
            proof_verification_memory_limit_bytes,
            storage_healthy: !self.storage_faulted,
            public_peer_mode: self.public_peer_mode,
            peers: self.peer_observations(),
        })
    }

    pub(crate) fn record_peer_started(
        &mut self,
        direction: PeerDirection,
        address: String,
        now: u64,
    ) {
        let Some(record) = self.peer_observation_mut(direction, address, now) else {
            return;
        };
        record.last_seen = now;
        record.active_connections = record.active_connections.saturating_add(1);
    }

    pub(crate) fn record_peer_succeeded(
        &mut self,
        direction: PeerDirection,
        address: String,
        remote_height: u64,
        remote_tip: [u8; 32],
        now: u64,
    ) {
        let Some(record) = self.peer_observation_mut(direction, address, now) else {
            return;
        };
        record.last_seen = now;
        record.last_success = Some(now);
        record.last_attempt_succeeded = true;
        record.successful_sessions = record.successful_sessions.saturating_add(1);
        record.remote_height = Some(remote_height);
        record.remote_tip = Some(remote_tip);
    }

    pub(crate) fn record_peer_ended(
        &mut self,
        direction: PeerDirection,
        address: String,
        failed: bool,
        now: u64,
    ) {
        let Some(record) = self.peer_observation_mut(direction, address, now) else {
            return;
        };
        record.last_seen = now;
        record.active_connections = record.active_connections.saturating_sub(1);
        if failed {
            record.last_attempt_succeeded = false;
            record.failed_sessions = record.failed_sessions.saturating_add(1);
        }
    }

    fn peer_observation_mut(
        &mut self,
        direction: PeerDirection,
        address: String,
        now: u64,
    ) -> Option<&mut PeerObservationRecord> {
        let key = PeerObservationKey { direction, address };
        if !self.peer_observations.contains_key(&key)
            && self.peer_observations.len() >= MAX_OBSERVED_PEERS
        {
            let eviction = self
                .peer_observations
                .iter()
                .filter(|(_, record)| record.active_connections == 0)
                .min_by(|(left_key, left), (right_key, right)| {
                    left.last_seen
                        .cmp(&right.last_seen)
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(key, _)| key.clone());
            let eviction = eviction?;
            self.peer_observations.remove(&eviction);
        }
        Some(
            self.peer_observations
                .entry(key)
                .or_insert(PeerObservationRecord {
                    first_seen: now,
                    last_seen: now,
                    last_success: None,
                    last_attempt_succeeded: false,
                    successful_sessions: 0,
                    failed_sessions: 0,
                    active_connections: 0,
                    remote_height: None,
                    remote_tip: None,
                }),
        )
    }

    fn peer_observations(&self) -> Vec<PeerObservation> {
        let mut peers: Vec<_> = self
            .peer_observations
            .iter()
            .map(|(key, record)| PeerObservation {
                address: key.address.clone(),
                direction: key.direction,
                state: if record.active_connections > 0 {
                    PeerState::Connected
                } else if record.last_attempt_succeeded {
                    PeerState::Reachable
                } else {
                    PeerState::Failed
                },
                first_seen: record.first_seen,
                last_seen: record.last_seen,
                last_success: record.last_success,
                successful_sessions: record.successful_sessions,
                failed_sessions: record.failed_sessions,
                active_connections: record.active_connections,
                remote_height: record.remote_height,
                remote_tip: record.remote_tip.map(hex::encode),
            })
            .collect();
        peers.sort_by(|left, right| {
            right
                .active_connections
                .cmp(&left.active_connections)
                .then_with(|| right.last_seen.cmp(&left.last_seen))
                .then_with(|| left.direction.cmp(&right.direction))
                .then_with(|| left.address.cmp(&right.address))
        });
        peers
    }

    /// Returns the Devnet-0 wallet view for this data directory.
    ///
    /// New data directories receive a unique unencrypted test key. A directory
    /// migrated from an older nonempty Devnet retains the public legacy key so
    /// an upgrade cannot strand its existing test outputs. Confirmed history
    /// is reconstructed from the active branch on every call, while balances
    /// come from the active UTXO set with the volatile mempool applied as a
    /// reservation/pending-output overlay.
    pub fn wallet_snapshot(&mut self) -> Result<WalletSnapshot, NodeError> {
        let result = self.wallet_snapshot_unlatched();
        self.latch_authenticated_storage_failure(result)
    }

    fn wallet_snapshot_unlatched(&mut self) -> Result<WalletSnapshot, NodeError> {
        let destination = self.wallet_destination();
        let reserved = mempool_spent_inputs(&self.mempool);
        let mut spendable = 0_u64;
        let mut immature = 0_u64;
        let mut spendable_utxo_count = 0_usize;
        let mut immature_utxo_count = 0_usize;
        let mut reserved_utxo_count = 0_usize;
        for (outpoint, output) in self.state.utxos().iter() {
            if output.lock != OutputLock::Key(destination) {
                continue;
            }
            if self.state.next_height() < output.spendable_height {
                immature = checked_wallet_add(immature, output.value)?;
                immature_utxo_count += 1;
            } else if reserved.contains(outpoint) {
                reserved_utxo_count += 1;
            } else {
                spendable = checked_wallet_add(spendable, output.value)?;
                spendable_utxo_count += 1;
            }
        }

        let mut pending = 0_u64;
        for entry in self.mempool.values() {
            for output in &entry.transaction.outputs {
                if output.lock == OutputLock::Key(destination) {
                    pending = checked_wallet_add(pending, output.value)?;
                }
            }
        }

        let accepted_height = self.state.next_height().saturating_sub(1);
        let mut history = self.pending_wallet_history(destination)?;
        let mut confirmed = self.confirmed_wallet_history(
            destination,
            accepted_height,
            MAX_WALLET_HISTORY.saturating_sub(history.len()),
        )?;
        confirmed.reverse();
        history.extend(confirmed);
        history.truncate(MAX_WALLET_HISTORY);

        Ok(WalletSnapshot {
            network: self.profile.name,
            devnet_only: self.profile.is_devnet(),
            insecure_demo_wallet: self.wallet_is_insecure_demo(),
            warning: self.wallet_warning(),
            destination: hex::encode(destination),
            accepted_height,
            next_height: self.state.next_height(),
            balances: WalletBalances {
                spendable_atoms: spendable.to_string(),
                immature_atoms: immature.to_string(),
                pending_atoms: pending.to_string(),
            },
            spendable_utxo_count,
            immature_utxo_count,
            reserved_utxo_count,
            mempool: WalletMempoolStatus {
                transactions: self.mempool.len(),
                bytes: self.mempool_bytes,
            },
            history_limit: MAX_WALLET_HISTORY,
            history,
        })
    }

    /// Validates a display-unit request and submits a payment from this data
    /// directory's Devnet-0 test key.
    pub fn send_from_dev_wallet_request(
        &mut self,
        request: WalletSendRequest,
    ) -> Result<WalletSendResponse, NodeError> {
        let recipient = parse_wallet_recipient(&request.recipient)?;
        let amount = parse_cmfd_atoms(&request.amount)?;
        if amount == 0 {
            return Err(NodeError::WalletZeroAmount);
        }
        let fee = parse_cmfd_atoms(&request.fee)?;
        self.send_from_dev_wallet(recipient, amount, fee)
    }

    pub fn send_from_dev_wallet(
        &mut self,
        recipient: [u8; 32],
        amount: u64,
        fee_burned: u64,
    ) -> Result<WalletSendResponse, NodeError> {
        VerifyingKey::from_bytes(&recipient).map_err(|_| NodeError::InvalidWalletRecipient)?;
        if amount == 0 {
            return Err(NodeError::WalletZeroAmount);
        }
        let required = amount
            .checked_add(fee_burned)
            .ok_or(NodeError::WalletAmountOverflow)?;
        let destination = self.wallet_destination();
        let reserved = mempool_spent_inputs(&self.mempool);
        let mut candidates = Vec::new();
        let mut immature = 0_u64;
        for (outpoint, output) in self.state.utxos().iter() {
            if output.lock != OutputLock::Key(destination) {
                continue;
            }
            if self.state.next_height() < output.spendable_height {
                immature = checked_wallet_add(immature, output.value)?;
            } else if !reserved.contains(outpoint) {
                candidates.push((*outpoint, output.value));
            }
        }
        let selection = select_send_utxos(candidates, required)?;
        let available = selection.available;
        let selected = selection.outpoints;
        let selected_value = selection.selected_value;
        if selected_value < required {
            if available >= required {
                return Err(NodeError::WalletInputLimit {
                    selected: selected_value,
                    required,
                });
            }
            let available_with_immature = checked_wallet_add(available, immature)?;
            if available_with_immature >= required {
                return Err(NodeError::WalletFundsImmature { immature, required });
            }
            return Err(NodeError::WalletInsufficientFunds {
                available,
                required,
            });
        }

        let change = selected_value - required;
        let mut outputs = vec![TxOutput {
            value: amount,
            lock: OutputLock::Key(recipient),
            spendable_height: self.state.next_height(),
        }];
        if change > 0 {
            outputs.push(TxOutput {
                value: change,
                lock: OutputLock::Key(destination),
                spendable_height: self.state.next_height(),
            });
        }
        let mut transaction = Transaction {
            network_id: self.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: selected
                .into_iter()
                .map(|previous| TxInput {
                    previous,
                    witness: InputWitness::Key {
                        public_key: [0; 32],
                        signature: Vec::new(),
                    },
                })
                .collect(),
            outputs,
        };
        let signing_keys = vec![&self.wallet_signing_key; transaction.inputs.len()];
        transaction.sign_all(&signing_keys)?;

        let encoded_bytes = encode_transaction(&transaction)?.len();
        let minimum_fee = required_relay_fee(encoded_bytes);
        if fee_burned < minimum_fee {
            return Err(NodeError::MempoolFeeTooLow {
                required: minimum_fee,
                actual: fee_burned,
            });
        }
        let entry = self.submit_transaction(transaction)?;
        Ok(WalletSendResponse {
            network: self.profile.name,
            devnet_only: self.profile.is_devnet(),
            insecure_demo_wallet: self.wallet_is_insecure_demo(),
            warning: self.wallet_warning(),
            txid: hex::encode(entry.txid),
            amount_atoms: amount.to_string(),
            fee_burned_atoms: entry.fee_burned.to_string(),
            change_atoms: change.to_string(),
            mempool_transactions: self.mempool.len(),
            mempool_bytes: self.mempool_bytes,
        })
    }

    /// Validates a display-unit request and consolidates this data directory's
    /// Devnet-0 test wallet.
    pub fn consolidate_dev_wallet_request(
        &mut self,
        request: WalletConsolidateRequest,
    ) -> Result<WalletConsolidateResponse, NodeError> {
        if !(2..=MAX_TRANSACTION_INPUTS).contains(&request.max_inputs) {
            return Err(NodeError::InvalidConsolidationMaxInputs);
        }
        let fee = parse_cmfd_atoms(&request.fee)?;
        self.consolidate_dev_wallet(fee, request.max_inputs)
    }

    pub fn consolidate_dev_wallet(
        &mut self,
        fee_burned: u64,
        max_inputs: usize,
    ) -> Result<WalletConsolidateResponse, NodeError> {
        if !(2..=MAX_TRANSACTION_INPUTS).contains(&max_inputs) {
            return Err(NodeError::InvalidConsolidationMaxInputs);
        }
        let destination = self.wallet_destination();
        let reserved = mempool_spent_inputs(&self.mempool);
        let mut candidates: Vec<_> = self
            .state
            .utxos()
            .iter()
            .filter(|(outpoint, output)| {
                output.lock == OutputLock::Key(destination)
                    && self.state.next_height() >= output.spendable_height
                    && !reserved.contains(outpoint)
            })
            .map(|(outpoint, output)| (*outpoint, output.value))
            .collect();
        candidates.sort_unstable_by(|left, right| {
            left.1
                .cmp(&right.1)
                .then_with(|| left.0.txid.cmp(&right.0.txid))
                .then_with(|| left.0.index.cmp(&right.0.index))
        });
        let selected: Vec<_> = candidates.into_iter().take(max_inputs).collect();
        if selected.len() < 2 {
            return Err(NodeError::WalletNotEnoughUtxos(selected.len()));
        }
        let input_atoms = selected
            .iter()
            .try_fold(0_u64, |total, (_, value)| checked_wallet_add(total, *value))?;
        let output_atoms = input_atoms
            .checked_sub(fee_burned)
            .filter(|value| *value > 0)
            .ok_or(NodeError::WalletConsolidationFee { input: input_atoms })?;
        let mut transaction = Transaction {
            network_id: self.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: selected
                .iter()
                .map(|(previous, _)| TxInput {
                    previous: *previous,
                    witness: InputWitness::Key {
                        public_key: [0; 32],
                        signature: Vec::new(),
                    },
                })
                .collect(),
            outputs: vec![TxOutput {
                value: output_atoms,
                lock: OutputLock::Key(destination),
                spendable_height: self.state.next_height(),
            }],
        };
        let signing_keys = vec![&self.wallet_signing_key; transaction.inputs.len()];
        transaction.sign_all(&signing_keys)?;
        let encoded_bytes = encode_transaction(&transaction)?.len();
        let minimum_fee = required_relay_fee(encoded_bytes);
        if fee_burned < minimum_fee {
            return Err(NodeError::MempoolFeeTooLow {
                required: minimum_fee,
                actual: fee_burned,
            });
        }
        let inputs_consolidated = transaction.inputs.len();
        let entry = self.submit_transaction(transaction)?;
        Ok(WalletConsolidateResponse {
            network: self.profile.name,
            devnet_only: self.profile.is_devnet(),
            insecure_demo_wallet: self.wallet_is_insecure_demo(),
            warning: self.wallet_warning(),
            txid: hex::encode(entry.txid),
            inputs_consolidated,
            input_atoms: input_atoms.to_string(),
            output_atoms: output_atoms.to_string(),
            fee_burned_atoms: entry.fee_burned.to_string(),
            mempool_transactions: self.mempool.len(),
            mempool_bytes: self.mempool_bytes,
        })
    }

    fn pending_wallet_history(
        &self,
        destination: [u8; 32],
    ) -> Result<Vec<WalletHistoryEntry>, NodeError> {
        let mut history = Vec::new();
        for entry in self.mempool.values().rev() {
            let mut wallet_inputs = 0_u64;
            let mut source = None;
            for input in &entry.transaction.inputs {
                let Some(previous) = self.state.utxos().get(&input.previous) else {
                    continue;
                };
                match previous.lock {
                    OutputLock::Key(owner) if owner == destination => {
                        wallet_inputs = checked_wallet_add(wallet_inputs, previous.value)?;
                    }
                    OutputLock::Key(owner) if source.is_none() => {
                        source = Some(hex::encode(owner));
                    }
                    _ => {}
                }
            }
            let mut wallet_outputs = 0_u64;
            let mut recipient = None;
            for output in &entry.transaction.outputs {
                match output.lock {
                    OutputLock::Key(owner) if owner == destination => {
                        wallet_outputs = checked_wallet_add(wallet_outputs, output.value)?;
                    }
                    OutputLock::Key(owner) if recipient.is_none() => {
                        recipient = Some(hex::encode(owner));
                    }
                    _ => {}
                }
            }
            let (kind, counterparty) = if wallet_inputs > 0 {
                ("sent", recipient)
            } else if wallet_outputs > 0 {
                ("received", source)
            } else {
                continue;
            };
            history.push(WalletHistoryEntry {
                kind,
                txid: hex::encode(entry.txid),
                height: None,
                timestamp: None,
                confirmations: 0,
                status: "pending",
                net_amount_atoms: signed_wallet_delta(wallet_outputs, wallet_inputs),
                fee_burned_atoms: entry.fee_burned.to_string(),
                counterparty,
            });
            if history.len() == MAX_WALLET_HISTORY {
                break;
            }
        }
        Ok(history)
    }

    fn confirmed_wallet_history(
        &mut self,
        destination: [u8; 32],
        accepted_height: u64,
        history_limit: usize,
    ) -> Result<Vec<WalletHistoryEntry>, NodeError> {
        let mut outputs = HashMap::<OutPoint, TxOutput>::new();
        let mut history = VecDeque::with_capacity(history_limit);
        for position in 1..self.index.active_chain.len() {
            let block_id = self.index.active_chain[position];
            let indexed = self.index.blocks.get(&block_id).cloned().ok_or_else(|| {
                NodeError::CorruptLog("active wallet history refers to an absent block".to_owned())
            })?;
            let log_path = self.data_dir.join(BLOCK_LOG_FILE);
            let block = read_indexed_block(
                &self.log,
                &log_path,
                &indexed,
                block_id,
                self.params.network_id,
                matches!(self.profile.proof, ProofProfile::ProductionV3),
            )?;
            let height = block.challenge.height;
            let confirmations = accepted_height.saturating_sub(height).saturating_add(1);
            let coinbase_txid = block.coinbase_outpoint_id();
            let mut mined = 0_u64;
            let mut mined_is_immature = false;
            for (index, output) in block.coinbase.outputs.iter().enumerate() {
                let outpoint = OutPoint {
                    txid: coinbase_txid,
                    index: index as u32,
                };
                if output.lock == OutputLock::Key(destination) {
                    mined = checked_wallet_add(mined, output.value)?;
                    mined_is_immature |= self.state.next_height() < output.spendable_height;
                }
                outputs.insert(outpoint, output.clone());
            }
            if mined > 0 {
                retain_newest_wallet_history(
                    &mut history,
                    history_limit,
                    WalletHistoryEntry {
                        kind: "mined",
                        txid: hex::encode(coinbase_txid),
                        height: Some(height),
                        timestamp: Some(block.challenge.timestamp),
                        confirmations,
                        status: if mined_is_immature {
                            "immature"
                        } else {
                            "confirmed"
                        },
                        net_amount_atoms: mined.to_string(),
                        fee_burned_atoms: "0".to_owned(),
                        counterparty: None,
                    },
                );
            }

            for transaction in &block.transactions {
                let mut input_total = 0_u64;
                let mut wallet_inputs = 0_u64;
                let mut source = None;
                for input in &transaction.inputs {
                    let previous = outputs.remove(&input.previous).ok_or_else(|| {
                        NodeError::CorruptLog(
                            "active wallet history transaction refers to an absent output"
                                .to_owned(),
                        )
                    })?;
                    input_total = checked_wallet_add(input_total, previous.value)?;
                    match previous.lock {
                        OutputLock::Key(owner) if owner == destination => {
                            wallet_inputs = checked_wallet_add(wallet_inputs, previous.value)?;
                        }
                        OutputLock::Key(owner) if source.is_none() => {
                            source = Some(hex::encode(owner));
                        }
                        _ => {}
                    }
                }
                let txid = transaction.txid();
                let mut output_total = 0_u64;
                let mut wallet_outputs = 0_u64;
                let mut wallet_outputs_are_immature = false;
                let mut recipient = None;
                for (index, output) in transaction.outputs.iter().enumerate() {
                    output_total = checked_wallet_add(output_total, output.value)?;
                    match output.lock {
                        OutputLock::Key(owner) if owner == destination => {
                            wallet_outputs = checked_wallet_add(wallet_outputs, output.value)?;
                            wallet_outputs_are_immature |=
                                self.state.next_height() < output.spendable_height;
                        }
                        OutputLock::Key(owner) if recipient.is_none() => {
                            recipient = Some(hex::encode(owner));
                        }
                        _ => {}
                    }
                    outputs.insert(
                        OutPoint {
                            txid,
                            index: index as u32,
                        },
                        output.clone(),
                    );
                }
                let fee_burned = input_total.checked_sub(output_total).ok_or_else(|| {
                    NodeError::CorruptLog(
                        "active wallet history transaction creates value".to_owned(),
                    )
                })?;
                let (kind, counterparty) = if wallet_inputs > 0 {
                    ("sent", recipient)
                } else if wallet_outputs > 0 {
                    ("received", source)
                } else {
                    continue;
                };
                retain_newest_wallet_history(
                    &mut history,
                    history_limit,
                    WalletHistoryEntry {
                        kind,
                        txid: hex::encode(txid),
                        height: Some(height),
                        timestamp: Some(block.challenge.timestamp),
                        confirmations,
                        status: if wallet_outputs_are_immature {
                            "immature"
                        } else {
                            "confirmed"
                        },
                        net_amount_atoms: signed_wallet_delta(wallet_outputs, wallet_inputs),
                        fee_burned_atoms: fee_burned.to_string(),
                        counterparty,
                    },
                );
            }
        }
        Ok(history.into())
    }

    /// Builds the network- and consensus-bound peer greeting. This compatibility
    /// handshake does not authenticate a peer identity or encrypt the transport.
    pub fn peer_hello(&self) -> peer::PeerHello {
        peer::PeerHello {
            network_id: self.params.network_id,
            consensus_fingerprint: self.fingerprint,
            node_nonce: peer::process_node_nonce(),
            tip: self.state.tip(),
            height: self.state.next_height().saturating_sub(1),
            cumulative_work: self.cumulative_work(),
        }
    }

    pub fn cumulative_work(&self) -> peer::ChainWork {
        peer::ChainWork(chain_work_bytes(self.index.active_work))
    }

    /// Returns whether the identifier is known. The immutable virtual genesis
    /// is known even though it has no canonical block frame.
    pub fn contains_block(&self, block_id: [u8; 32]) -> bool {
        self.index.contains(block_id)
    }

    /// Reads and authenticates the exact canonical frame for a validated block.
    /// Virtual genesis and unknown identifiers have no frame and return
    /// `None`; retained-log corruption and I/O failures are never hidden.
    pub fn canonical_block(&mut self, block_id: [u8; 32]) -> Result<Option<Vec<u8>>, NodeError> {
        let Some(indexed) = self.index.blocks.get(&block_id).cloned() else {
            return Ok(None);
        };
        let result = (|| {
            if indexed.block_id() != block_id {
                return Err(NodeError::CorruptLog(
                    "fork index key does not match its durable record locator".to_owned(),
                ));
            }
            let path = self.data_dir.join(BLOCK_LOG_FILE);
            let (record, _) = read_located_record(
                &self.log,
                &path,
                &indexed.locator,
                self.params.network_id,
                matches!(self.profile.proof, ProofProfile::ProductionV3),
            )?;
            Ok(Some(record.block_bytes))
        })();
        self.latch_authenticated_storage_failure(result)
    }

    /// Builds a bounded, newest-first active-chain locator. For every nonzero
    /// bound the last identifier is virtual genesis; a zero bound is empty.
    pub fn block_locator(&self, max: usize) -> Vec<[u8; 32]> {
        if max == 0 {
            return Vec::new();
        }
        if max == 1 || self.index.active_chain.len() == 1 {
            return vec![self.index.genesis];
        }

        let mut locator = Vec::with_capacity(max.min(self.index.active_chain.len()));
        let mut position = self.index.active_chain.len() - 1;
        let mut step = 1_usize;
        while position > 0 && locator.len() + 1 < max {
            locator.push(self.index.active_chain[position]);
            position = position.saturating_sub(step);
            if locator.len() >= 10 {
                step = step.saturating_mul(2);
            }
        }
        locator.push(self.index.genesis);
        locator
    }

    /// Returns active-chain identifiers following the first locator entry that
    /// is on the active chain. `stop == [0; 32]` means no explicit stop; a
    /// nonzero stop is included when reached.
    pub fn inventory_after(
        &self,
        locator: &[[u8; 32]],
        stop: [u8; 32],
        max: usize,
    ) -> Vec<[u8; 32]> {
        if max == 0 {
            return Vec::new();
        }
        let Some(position) = locator
            .iter()
            .find_map(|block_id| self.index.active_position(*block_id))
        else {
            return Vec::new();
        };
        let remaining = self.index.active_chain.len().saturating_sub(position + 1);
        let mut inventory = Vec::with_capacity(max.min(remaining));
        for block_id in self.index.active_chain.iter().skip(position + 1) {
            inventory.push(*block_id);
            if inventory.len() == max || (stop != [0; 32] && *block_id == stop) {
                break;
            }
        }
        inventory
    }

    /// Returns active-chain identifiers after the active-chain ancestor of a
    /// known peer tip. Unlike `inventory_after`, this accepts a known side-tip
    /// so a one-sided static link can relay the winning local branch across an
    /// equal-work fork without waiting for a reciprocal connection.
    pub fn relay_inventory_after(&self, peer_tip: [u8; 32], max: usize) -> Vec<[u8; 32]> {
        if max == 0 || !self.index.contains(peer_tip) {
            return Vec::new();
        }
        let mut cursor = peer_tip;
        let mut active_position = None;
        for _ in 0..=self.index.blocks.len() {
            if let Some(position) = self.index.active_position(cursor) {
                active_position = Some(position);
                break;
            }
            let Some(entry) = self.index.blocks.get(&cursor) else {
                return Vec::new();
            };
            cursor = entry.parent();
        }
        let Some(position) = active_position else {
            return Vec::new();
        };
        self.index
            .active_chain
            .iter()
            .skip(position + 1)
            .take(max)
            .copied()
            .collect()
    }

    pub fn build_template(
        &self,
        miner_destination: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<BlockTemplate, NodeError> {
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        VerifyingKey::from_bytes(&miner_destination)
            .map_err(|_| NodeError::InvalidMinerDestination)?;
        let earliest = self
            .state
            .median_time_past()
            .checked_add(1)
            .ok_or(NodeError::TemplateTimeUnavailable)?;
        let latest = now_unix_seconds
            .checked_add(self.params.max_future_offset_secs)
            .ok_or(NodeError::TemplateTimeUnavailable)?;
        let timestamp = now_unix_seconds.max(earliest);
        if timestamp > latest {
            return Err(NodeError::TemplateTimeUnavailable);
        }

        let height = self.state.next_height();
        let transactions: Vec<_> = self
            .mempool
            .values()
            .map(|entry| entry.transaction.clone())
            .collect();
        let validation = self
            .state
            .validate_transactions_for_next_block(&transactions)?;
        let allocation = self
            .params
            .monetary_policy
            .allocation(height, validation.total_burned_fees)?;
        let coinbase = Coinbase::new(height, allocation, miner_destination, self.params.rewards);
        let mut commitments = Vec::with_capacity(transactions.len() + 1);
        commitments.push(coinbase.commitment(self.params.network_id));
        commitments.extend(transactions.iter().map(Transaction::txid));
        let transaction_root = merkle_root(&commitments);
        let challenge = BlockChallenge {
            network_id: self.params.network_id,
            previous_block: self.state.tip(),
            transaction_root,
            height,
            timestamp,
            target: self.state.expected_target()?,
        };
        Ok(BlockTemplate {
            challenge,
            coinbase,
            transactions,
            total_fees_burned: validation.total_burned_fees,
        })
    }

    /// Captures an immutable template and verifier for mining outside any
    /// shared node lock.
    pub fn build_mining_job(
        &self,
        miner_destination: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<MiningJob, NodeError> {
        Ok(MiningJob {
            template: self.build_template(miner_destination, now_unix_seconds)?,
            verifier: self.verifier.clone(),
        })
    }

    /// Adds a transaction to the volatile, active-chain-only Devnet-0 mempool.
    ///
    /// Unconfirmed parents are intentionally unsupported: every input must be
    /// present in the current active UTXO set. This keeps admission and reorg
    /// behavior deterministic while the test network has no package relay.
    pub fn submit_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<MempoolEntry, NodeError> {
        let canonical = encode_transaction(&transaction)?;
        let txid = transaction.txid();
        if self.mempool.contains_key(&txid) {
            return Err(NodeError::DuplicateMempoolTransaction(txid));
        }
        if self.mempool.len() >= MAX_MEMPOOL_TRANSACTIONS {
            return Err(NodeError::MempoolTransactionLimit);
        }
        let next_bytes = self
            .mempool_bytes
            .checked_add(canonical.len())
            .ok_or(NodeError::MempoolByteLimit)?;
        if next_bytes > MAX_MEMPOOL_BYTES {
            return Err(NodeError::MempoolByteLimit);
        }

        let spent = mempool_spent_inputs(&self.mempool);
        let fee_burned =
            validate_mempool_transaction(&self.state, &transaction, canonical.len(), &spent)?;

        let mut ordered_transactions = Vec::with_capacity(self.mempool.len() + 1);
        let mut inserted = false;
        for (existing_txid, entry) in &self.mempool {
            if !inserted && txid < *existing_txid {
                ordered_transactions.push(transaction.clone());
                inserted = true;
            }
            ordered_transactions.push(entry.transaction.clone());
        }
        if !inserted {
            ordered_transactions.push(transaction.clone());
        }
        self.state
            .validate_transactions_for_next_block(&ordered_transactions)?;

        let entry = MempoolEntry {
            txid,
            transaction,
            encoded_bytes: canonical.len(),
            fee_burned,
        };
        self.mempool.insert(txid, entry.clone());
        self.mempool_bytes = next_bytes;
        Ok(entry)
    }

    pub fn mempool_entries(&self) -> impl ExactSizeIterator<Item = &MempoolEntry> {
        self.mempool.values()
    }

    /// Returns the transport-neutral mempool view exposed by the Devnet-0 API.
    pub fn mempool_snapshot(&self) -> MempoolSnapshot {
        let entries = self
            .mempool
            .values()
            .map(|entry| MempoolSnapshotEntry {
                txid: hex::encode(entry.txid),
                encoded_bytes: entry.encoded_bytes,
                fee_burned: entry.fee_burned,
                fee_burned_atoms: entry.fee_burned.to_string(),
            })
            .collect();
        MempoolSnapshot {
            transactions: self.mempool.len(),
            bytes: self.mempool_bytes,
            entries,
        }
    }

    /// Validates and executes one bounded Devnet-0 mining request.
    pub fn mine_devnet_request(
        &mut self,
        request: DevMineRequest,
    ) -> Result<DevMineResult, NodeError> {
        let (miner, attempts) = validate_dev_mine_request(&request)?;
        let block = self.mine_once(miner, unix_time_seconds()?, attempts)?;
        let status = self.status()?;
        Ok(DevMineResult {
            accepted: true,
            block_id: hex::encode(block.block_id()),
            height: status.accepted_height,
            tip: status.tip,
        })
    }

    pub fn mine_once(
        &mut self,
        miner_destination: [u8; 32],
        now_unix_seconds: u64,
        attempts: u64,
    ) -> Result<Block, NodeError> {
        if !self.profile.proof.supports_bounded_reference_mining() {
            return Err(NodeError::ProductionV3Unavailable);
        }
        let template = self.build_template(miner_destination, now_unix_seconds)?;
        let proof = self.verifier.mine(&template.challenge, 0, attempts)?;
        if !matches!(proof, BlockProof::V2Reference(_)) {
            return Err(NodeError::CorruptLog(format!(
                "{} verifier produced a proof outside the compiled {} profile",
                self.profile.short_name(),
                self.profile.proof.profile_name()
            )));
        }
        let block = Block {
            version: BLOCK_VERSION,
            challenge: template.challenge,
            proof,
            coinbase: template.coinbase,
            transactions: template.transactions,
        };
        self.submit_block(block.clone(), now_unix_seconds)?;
        Ok(block)
    }

    pub fn submit_block(&mut self, block: Block, accepted_at: u64) -> Result<u64, NodeError> {
        if matches!(self.profile.proof, ProofProfile::ProductionV3) {
            // A caller may already hold an Arc<Mutex<Node>> guard. Acquiring
            // the proof permit here would invert the canonical permit->node
            // lock order and can deadlock another shared submission. Live
            // ProductionV3 callers must use `submit_shared_block`.
            return Err(NodeError::ProductionV3Unavailable);
        }
        self.submit_block_with_preverification(block, accepted_at, None, None, None)
    }

    /// Rejects cheap duplicate, ancestry, and successor-header failures before
    /// dispatching an expensive external proof verification. This is only an
    /// admission gate: stateful validation happens outside the node mutex after
    /// the worker accepts the proof, and `submit_block_with_preverification`
    /// repeats every authoritative consensus check when committing.
    pub(crate) fn preflight_external_block_admission(
        &self,
        block: &Block,
        accepted_at: u64,
    ) -> Result<(), NodeError> {
        let block_id = block.block_id();
        if self.index.contains(block_id) {
            return Err(NodeError::DuplicateBlock(block_id));
        }
        if self.rejected_proof_ids.contains(&block_id) {
            return Err(NodeError::CachedInvalidBlock(block_id));
        }
        if !matches!(self.profile.proof, ProofProfile::ProductionV3) {
            return Ok(());
        }
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        validate_block_resources(block)?;
        let body_digest = canonical_block_cache_digest(block)?;
        if self.rejected_body_digests.contains(&body_digest) {
            return Err(NodeError::CachedInvalidBlock(block_id));
        }
        validate_block_preamble(block, self.params.network_id)?;
        let parent = block.challenge.previous_block;
        self.index
            .work_at(parent)
            .ok_or(NodeError::UnknownParent(parent))?;
        let validation_context = BlockValidationContext {
            now_unix_seconds: accepted_at,
        };
        if parent == self.state.tip() {
            self.state
                .successor_header_preflight()?
                .preflight_block(block, validation_context)?;
        } else {
            if parent == self.index.genesis {
                ChainState::new(self.params, self.verifier.clone())?
                    .successor_header_preflight()?
                    .preflight_block(block, validation_context)?;
            } else {
                let parent_entry = self
                    .index
                    .blocks
                    .get(&parent)
                    .ok_or(NodeError::UnknownParent(parent))?;
                parent_entry
                    .successor_header
                    .preflight_block(block, validation_context)?;
            }
        }
        Ok(())
    }

    pub(crate) fn begin_external_block_admission(
        &mut self,
        block: &Block,
        accepted_at: u64,
    ) -> Result<Option<ExternalBlockAdmissionWork>, NodeError> {
        self.begin_external_block_admission_from_checkpoint(block, accepted_at, None)
    }

    fn continue_external_block_admission(
        &mut self,
        block: &Block,
        accepted_at: u64,
        checkpoint: BranchStateCheckpoint,
    ) -> Result<ExternalBlockAdmissionWork, NodeError> {
        self.begin_external_block_admission_from_checkpoint(block, accepted_at, Some(checkpoint))?
            .ok_or(NodeError::ProofVerifierProfileMismatch)
    }

    fn begin_external_block_admission_from_checkpoint(
        &mut self,
        block: &Block,
        accepted_at: u64,
        checkpoint: Option<BranchStateCheckpoint>,
    ) -> Result<Option<ExternalBlockAdmissionWork>, NodeError> {
        self.preflight_external_block_admission(block, accepted_at)?;
        if !matches!(self.profile.proof, ProofProfile::ProductionV3) {
            if checkpoint.is_some() {
                return Err(NodeError::ProofVerifierProfileMismatch);
            }
            return Ok(None);
        }
        let block_id = block.block_id();
        let parent = block.challenge.previous_block;
        let state_snapshot = if parent == self.state.tip() {
            if checkpoint.is_some() {
                return Err(NodeError::StaleBlockAdmission);
            }
            AdmissionStateSnapshot::Active
        } else {
            let log_path = self.data_dir.join(BLOCK_LOG_FILE);
            let plan = self.index.branch_state_plan(
                parent,
                checkpoint,
                &self.log,
                &log_path,
                self.params.network_id,
                true,
            );
            AdmissionStateSnapshot::Branch(self.latch_authenticated_storage_failure(plan)?)
        };
        Ok(Some(ExternalBlockAdmissionWork {
            node_instance_id: self.instance_id,
            revision: self.chain_revision,
            block_id,
            parent,
            accepted_at,
            params: self.params,
            verifier: self.verifier.clone(),
            block_preverifier: self.block_preverifier.clone(),
            state_snapshot,
        }))
    }

    fn remember_rejected_proof(&mut self, block_id: [u8; 32]) {
        remember_bounded_digest(
            &mut self.rejected_proof_ids,
            &mut self.rejected_proof_order,
            block_id,
        );
    }

    fn remember_rejected_body(&mut self, body_digest: [u8; 32]) {
        remember_bounded_digest(
            &mut self.rejected_body_digests,
            &mut self.rejected_body_order,
            body_digest,
        );
    }

    /// Consumes process-local proof evidence produced outside the node lock.
    /// Every state-dependent consensus and durability check remains identical
    /// to [`Self::submit_block`].
    pub(crate) fn submit_preverified_block(
        &mut self,
        block: Block,
        accepted_at: u64,
        preverified: PreverifiedBlockProof,
    ) -> Result<u64, NodeError> {
        if matches!(self.profile.proof, ProofProfile::ProductionV3) {
            return Err(NodeError::ProductionV3Unavailable);
        }
        self.submit_block_with_preverification(block, accepted_at, Some(&preverified), None, None)
    }

    pub(crate) fn submit_preverified_block_with_admission(
        &mut self,
        block: Block,
        accepted_at: u64,
        preverified: PreverifiedBlockProof,
        admission: ExternalBlockAdmission,
    ) -> Result<u64, NodeError> {
        if !matches!(self.profile.proof, ProofProfile::ProductionV3) {
            return Err(NodeError::ProofVerifierProfileMismatch);
        }
        if admission.revision != self.chain_revision
            || admission.block_id != block.block_id()
            || admission.parent != block.challenge.previous_block
            || admission.accepted_at != accepted_at
        {
            return Err(NodeError::StaleBlockAdmission);
        }
        self.submit_block_with_preverification(
            block,
            accepted_at,
            Some(&preverified),
            admission.branch_state,
            admission.activation_chain,
        )
    }

    fn submit_block_with_preverification(
        &mut self,
        block: Block,
        accepted_at: u64,
        preverified: Option<&PreverifiedBlockProof>,
        branch_state: Option<Box<ChainState>>,
        activation_chain: Option<Vec<[u8; 32]>>,
    ) -> Result<u64, NodeError> {
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        let previous_tip = self.state.tip();
        let confirmed_txids: HashSet<_> =
            block.transactions.iter().map(Transaction::txid).collect();
        let canonical = encode_block(&block)?;
        let log_path = self.data_dir.join(BLOCK_LOG_FILE);
        let next_revision = self
            .chain_revision
            .checked_add(1)
            .ok_or_else(|| NodeError::CorruptLog("chain revision counter exhausted".to_owned()))?;
        let prepared = prepare_block(
            &self.state,
            &self.index,
            &block,
            BlockPreparationContext {
                params: self.params,
                verifier: &self.verifier,
                block_log: &self.log,
                block_log_path: &log_path,
                accepted_at,
                preverified,
                branch_state,
                activation_chain,
                allow_index_reconstruction: false,
            },
        );
        let prepared = self.latch_authenticated_storage_failure(prepared)?;
        let delta = prepared.encode_reversible_state_delta().map_err(|error| {
            NodeError::CorruptLog(format!(
                "validated block cannot encode its reversible state delta: {error}"
            ))
        })?;
        let record = encode_record_v2(accepted_at, &canonical, &delta, self.last_record_digest)?;
        let record_digest = complete_record_digest(&record);
        if let Err(error) = verify_retained_block_log_path(&self.log, &log_path) {
            self.storage_faulted = true;
            return Err(error);
        }
        let observed_length = match self.log.metadata() {
            Ok(metadata) => metadata.len(),
            Err(source) => {
                self.storage_faulted = true;
                return Err(io_error(
                    "inspect block log before append",
                    &log_path,
                    source,
                ));
            }
        };
        if observed_length != self.block_log_length {
            self.storage_faulted = true;
            return Err(NodeError::CorruptLog(
                "block log end changed after its last authenticated append".to_owned(),
            ));
        }
        let record_length = u64::try_from(record.len())
            .map_err(|_| NodeError::CorruptLog("block record length exceeds u64".to_owned()))?;
        let final_length = self
            .block_log_length
            .checked_add(record_length)
            .ok_or_else(|| NodeError::CorruptLog("block log length overflowed".to_owned()))?;
        let locator = BlockRecordLocator {
            ordinal: self.chain_revision,
            offset: self.block_log_length,
            length: record_length,
            version: BlockRecordVersion::V2,
            complete_digest: record_digest,
            accepted_at: prepared.accepted_at,
            block_id: prepared.block_id,
            parent: prepared.parent,
            height: prepared.height,
            target: prepared.target,
        };
        if let Err(source) = self.log.write_all(&record) {
            self.storage_faulted = true;
            return Err(io_error("append block record", &log_path, source));
        }
        if let Err(source) = self.log.sync_all() {
            self.storage_faulted = true;
            return Err(io_error("sync block record", &log_path, source));
        }
        let durable_length = match self.log.metadata() {
            Ok(metadata) => metadata.len(),
            Err(source) => {
                self.storage_faulted = true;
                return Err(io_error(
                    "inspect block log after durable append",
                    &log_path,
                    source,
                ));
            }
        };
        if durable_length != final_length {
            self.storage_faulted = true;
            return Err(NodeError::CorruptLog(
                "durable block append did not end at its predicted locator".to_owned(),
            ));
        }
        if let Err(error) = verify_retained_block_log_path(&self.log, &log_path) {
            self.storage_faulted = true;
            return Err(error);
        }
        match commit_prepared(&mut self.state, &mut self.index, prepared, locator) {
            Ok(outcome) => {
                self.chain_revision = next_revision;
                self.last_record_digest = record_digest;
                self.block_log_length = final_length;
                if self.state.tip() != previous_tip {
                    self.revalidate_mempool(&confirmed_txids);
                }
                Ok(outcome.fees)
            }
            Err(error) => {
                // The record is already durable. Refuse further work so a
                // restart can reconstruct the authoritative state from disk.
                self.storage_faulted = true;
                Err(error)
            }
        }
    }

    fn revalidate_mempool(&mut self, confirmed_txids: &HashSet<[u8; 32]>) {
        let old_pool = std::mem::take(&mut self.mempool);
        let mut retained = BTreeMap::new();
        let mut retained_transactions = Vec::new();
        let mut retained_spends = HashSet::new();
        let mut retained_bytes = 0_usize;

        for (txid, entry) in old_pool {
            if confirmed_txids.contains(&txid) {
                continue;
            }
            let Ok(fee_burned) = validate_mempool_transaction(
                &self.state,
                &entry.transaction,
                entry.encoded_bytes,
                &retained_spends,
            ) else {
                continue;
            };
            retained_transactions.push(entry.transaction.clone());
            if self
                .state
                .validate_transactions_for_next_block(&retained_transactions)
                .is_err()
            {
                retained_transactions.pop();
                continue;
            }
            retained_spends.extend(entry.transaction.inputs.iter().map(|input| input.previous));
            retained_bytes += entry.encoded_bytes;
            retained.insert(
                txid,
                MempoolEntry {
                    fee_burned,
                    ..entry
                },
            );
        }

        self.mempool = retained;
        self.mempool_bytes = retained_bytes;
    }
}

fn mempool_spent_inputs(mempool: &BTreeMap<[u8; 32], MempoolEntry>) -> HashSet<OutPoint> {
    mempool
        .values()
        .flat_map(|entry| entry.transaction.inputs.iter().map(|input| input.previous))
        .collect()
}

fn validate_mempool_transaction(
    state: &ChainState,
    transaction: &Transaction,
    encoded_bytes: usize,
    mempool_spends: &HashSet<OutPoint>,
) -> Result<u64, NodeError> {
    for input in &transaction.inputs {
        if state.utxos().get(&input.previous).is_none() {
            return Err(NodeError::MempoolUnconfirmedInput(input.previous));
        }
        if mempool_spends.contains(&input.previous) {
            return Err(NodeError::MempoolInputConflict(input.previous));
        }
    }
    let validation =
        state.validate_transactions_for_next_block(std::slice::from_ref(transaction))?;
    let required = required_relay_fee(encoded_bytes);
    if validation.total_burned_fees < required {
        return Err(NodeError::MempoolFeeTooLow {
            required,
            actual: validation.total_burned_fees,
        });
    }
    Ok(validation.total_burned_fees)
}

fn required_relay_fee(encoded_bytes: usize) -> u64 {
    let kib = encoded_bytes.saturating_add(1023) / 1024;
    u64::try_from(kib)
        .ok()
        .and_then(|kib| kib.checked_mul(MIN_RELAY_FEE_PER_KIB))
        .unwrap_or(u64::MAX)
        .max(MIN_RELAY_FEE_PER_KIB)
}

fn checked_wallet_add(left: u64, right: u64) -> Result<u64, NodeError> {
    left.checked_add(right)
        .ok_or(NodeError::WalletAmountOverflow)
}

#[derive(Debug, PartialEq, Eq)]
struct WalletCoinSelection {
    outpoints: Vec<OutPoint>,
    selected_value: u64,
    available: u64,
}

fn select_send_utxos(
    mut candidates: Vec<(OutPoint, u64)>,
    required: u64,
) -> Result<WalletCoinSelection, NodeError> {
    let available = candidates
        .iter()
        .try_fold(0_u64, |total, (_, value)| checked_wallet_add(total, *value))?;
    candidates.sort_unstable_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| left.0.txid.cmp(&right.0.txid))
            .then_with(|| left.0.index.cmp(&right.0.index))
    });
    let mut outpoints = Vec::new();
    let mut selected_value = 0_u64;
    for (outpoint, value) in candidates.into_iter().take(MAX_TRANSACTION_INPUTS) {
        outpoints.push(outpoint);
        selected_value = checked_wallet_add(selected_value, value)?;
        if selected_value >= required {
            break;
        }
    }
    Ok(WalletCoinSelection {
        outpoints,
        selected_value,
        available,
    })
}

/// Submits a block to a mutex-shared node without holding the node mutex while
/// proof verification or ProductionV3 side-branch reconstruction runs.
///
/// Callers must not retain another guard for `shared` while invoking this
/// function. Production admission is revision-bound and all consensus checks
/// are repeated after the mutex is reacquired, so a concurrent chain update
/// fails closed instead of committing against stale state.
pub fn submit_shared_block(
    shared: &Arc<Mutex<Node>>,
    block: Block,
    accepted_at: u64,
) -> Result<u64, NodeError> {
    submit_shared_block_with_policy(shared, block, accepted_at, SharedBlockPolicy::AnyBranch)
}

/// Submits only if the candidate extends the active tip observed after it
/// acquires the proof permit. Mining callers use this policy so a concurrent
/// winning block cannot turn their candidate into a credited side branch.
pub fn submit_shared_tip_block(
    shared: &Arc<Mutex<Node>>,
    block: Block,
    accepted_at: u64,
) -> Result<u64, NodeError> {
    submit_shared_block_with_policy(shared, block, accepted_at, SharedBlockPolicy::ActiveTipOnly)
}

#[derive(Clone, Copy)]
enum SharedBlockPolicy {
    AnyBranch,
    ActiveTipOnly,
}

fn submit_shared_block_with_policy(
    shared: &Arc<Mutex<Node>>,
    block: Block,
    accepted_at: u64,
    policy: SharedBlockPolicy,
) -> Result<u64, NodeError> {
    let block_id = block.block_id();
    let (block_preverifier, production_v3) = {
        let node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        (
            node.block_preverifier(),
            matches!(node.profile.proof, ProofProfile::ProductionV3),
        )
    };
    if production_v3 {
        // Keep trivial duplicates, cached deterministic rejects, unknown
        // parents, malformed bodies, and impossible headers out of the scarce
        // proof queue. This snapshot is deliberately discarded and repeated
        // authoritatively after the permit is acquired.
        let node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
            && block.challenge.previous_block != node.state.tip()
        {
            return Err(NodeError::StaleBlockAdmission);
        }
        node.preflight_external_block_admission(&block, accepted_at)?;
    }
    let block_cache_digest = canonical_block_cache_digest(&block)?;
    // The scarce verifier reservation is released immediately after proof verification;
    // side-state replay uses a separate bounded lane so a proof-valid deep fork
    // cannot monopolize proof admission.
    let preverified =
        if let Some(preverified) = block_preverifier.cached_preverification(block_cache_digest)? {
            preverified
        } else {
            let permit = match policy {
                SharedBlockPolicy::AnyBranch => block_preverifier.reserve()?,
                SharedBlockPolicy::ActiveTipOnly => block_preverifier.reserve_priority()?,
            };
            {
                let node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
                if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
                    && block.challenge.previous_block != node.state.tip()
                {
                    return Err(NodeError::StaleBlockAdmission);
                }
                if production_v3 {
                    node.preflight_external_block_admission(&block, accepted_at)?;
                }
            }
            match permit.preverify_cached(&block, block_cache_digest) {
                Ok(preverified) => preverified,
                Err(error) => {
                    if production_v3 {
                        let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
                        if is_cacheable_proof_rejection(&error) {
                            node.remember_rejected_proof(block_id);
                        } else if is_cacheable_block_rejection(&error) {
                            node.remember_rejected_body(block_cache_digest);
                        }
                    }
                    return Err(error);
                }
            }
        };

    let admission_work = {
        let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
            && block.challenge.previous_block != node.state.tip()
        {
            return Err(NodeError::StaleBlockAdmission);
        }
        node.begin_external_block_admission(&block, accepted_at)?
    };

    let admission = match admission_work {
        Some(mut work) => {
            let _reconstruction_permit = work
                .requires_reconstruction()
                .then(|| block_preverifier.reserve_reconstruction())
                .transpose()?;
            loop {
                let work_node_instance_id = work.node_instance_id;
                let work_revision = work.revision;
                let progress = match catch_unwind(AssertUnwindSafe(|| work.complete(&block))) {
                    Ok(Ok(progress)) => progress,
                    Ok(Err(error)) => {
                        if is_authenticated_storage_failure(&error) {
                            let mut node =
                                shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
                            node.latch_external_completion_failure(
                                work_node_instance_id,
                                work_revision,
                                &error,
                            );
                        }
                        return Err(error);
                    }
                    Err(_) => return Err(NodeError::ProofVerifierPanicked),
                };
                match progress {
                    ExternalBlockAdmissionProgress::Ready(admission) => break Some(admission),
                    ExternalBlockAdmissionProgress::Checkpoint { checkpoint } => {
                        block_preverifier.ensure_reconstruction_open()?;
                        let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
                        if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
                            && block.challenge.previous_block != node.state.tip()
                        {
                            return Err(NodeError::StaleBlockAdmission);
                        }
                        work = node.continue_external_block_admission(
                            &block,
                            accepted_at,
                            checkpoint,
                        )?;
                    }
                }
            }
        }
        None => None,
    };
    let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
    if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
        && block.challenge.previous_block != node.state.tip()
    {
        return Err(NodeError::StaleBlockAdmission);
    }
    let externally_admitted = admission.is_some();
    let result = match admission {
        Some(mut admission) => {
            if admission.branch_state.is_some() {
                node.preflight_external_block_admission(&block, accepted_at)?;
                admission.revision = node.chain_revision;
                if block.challenge.previous_block == node.state.tip() {
                    admission.branch_state = None;
                    admission.activation_chain = None;
                }
            }
            node.submit_preverified_block_with_admission(block, accepted_at, preverified, admission)
        }
        None => node.submit_preverified_block(block, accepted_at, preverified),
    };
    if externally_admitted && result.as_ref().is_err_and(is_cacheable_block_rejection) {
        node.remember_rejected_body(block_cache_digest);
    }
    result
}

fn canonical_block_cache_digest(block: &Block) -> Result<[u8; 32], NodeError> {
    let canonical = encode_block(block)?;
    let canonical_len =
        u64::try_from(canonical.len()).map_err(|_| NodeError::Wire(WireError::LengthOverflow))?;
    let mut hasher = Hasher::new();
    hasher.update(b"CMFD/NODE/CANONICAL-BLOCK-CACHE/V1");
    hasher.update(&canonical_len.to_le_bytes());
    hasher.update(&canonical);
    Ok(*hasher.finalize().as_bytes())
}

fn remember_bounded_digest(
    entries: &mut HashSet<[u8; 32]>,
    order: &mut VecDeque<[u8; 32]>,
    digest: [u8; 32],
) {
    if entries.insert(digest) {
        order.push_back(digest);
    }
    while order.len() > MAX_REJECTED_BLOCK_IDS {
        if let Some(expired) = order.pop_front() {
            entries.remove(&expired);
        }
    }
}

fn is_cacheable_block_rejection(error: &NodeError) -> bool {
    matches!(
        error,
        NodeError::Chain(chain_error)
            if !matches!(
                chain_error,
                ChainError::TimestampTooFarInFuture
                    | ChainError::InvalidValidationTime
                    | ChainError::StaleValidatedBlock
                    | ChainError::PreverifiedProofMismatch
                    | ChainError::PreverificationUnavailable
            )
    )
}

fn is_cacheable_proof_rejection(error: &NodeError) -> bool {
    matches!(
        error,
        NodeError::ProofVerifierWorker(VerifierWorkerError::ProofRejected(_))
    )
}

fn is_authenticated_storage_failure(error: &NodeError) -> bool {
    matches!(
        error,
        NodeError::Io { .. } | NodeError::CorruptLog(_) | NodeError::ProductionLegacyBlockLog(_)
    )
}

fn signed_wallet_delta(credits: u64, debits: u64) -> String {
    if credits >= debits {
        (credits - debits).to_string()
    } else {
        format!("-{}", debits - credits)
    }
}

fn retain_newest_wallet_history(
    history: &mut VecDeque<WalletHistoryEntry>,
    limit: usize,
    entry: WalletHistoryEntry,
) {
    if limit == 0 {
        return;
    }
    if history.len() == limit {
        history.pop_front();
    }
    history.push_back(entry);
}

fn prepare_block(
    active_state: &ChainState,
    index: &BlockIndex,
    block: &Block,
    context: BlockPreparationContext<'_>,
) -> Result<PreparedBlock, NodeError> {
    let BlockPreparationContext {
        params,
        verifier,
        block_log,
        block_log_path,
        accepted_at,
        preverified,
        branch_state,
        activation_chain,
        allow_index_reconstruction,
    } = context;
    if requires_external_preverification(&params) && preverified.is_none() {
        return Err(NodeError::ProductionV3Unavailable);
    }
    let block_id = block.block_id();
    if index.contains(block_id) {
        return Err(NodeError::DuplicateBlock(block_id));
    }
    let parent = block.challenge.previous_block;
    let parent_work = index
        .work_at(parent)
        .ok_or(NodeError::UnknownParent(parent))?;
    let context = BlockValidationContext {
        now_unix_seconds: accepted_at,
    };
    let active_candidate = parent == active_state.tip();
    let candidate = if active_candidate {
        if branch_state.is_some() {
            return Err(NodeError::StaleBlockAdmission);
        }
        let validated = if let Some(preverified) = preverified {
            active_state.validate_block_preverified(block, context, preverified)?
        } else {
            active_state.validate_block(block, context)?
        };
        ValidatedCandidate::Active(validated)
    } else {
        let branch_state = match branch_state {
            Some(branch_state) => {
                if branch_state.tip() != parent {
                    return Err(NodeError::StaleBlockAdmission);
                }
                *branch_state
            }
            None if !requires_external_preverification(&params) || allow_index_reconstruction => {
                // Devnet keeps the original simple reconstruction. Production
                // only permits this during startup replay, before a shared node
                // mutex exists and after every proof was externally verified.
                rebuild_state_to(
                    block_log,
                    block_log_path,
                    index,
                    params,
                    verifier,
                    parent,
                    None,
                )?
            }
            None => return Err(NodeError::ProductionV3Unavailable),
        };
        let validated = if let Some(preverified) = preverified {
            branch_state.validate_block_preverified(block, context, preverified)?
        } else {
            branch_state.validate_block(block, context)?
        };
        ValidatedCandidate::Branch {
            state: Box::new(branch_state),
            validated,
        }
    };
    let cumulative_work =
        add_chain_work(parent_work, block.challenge.target).map_err(ChainError::from)?;
    let ancestors = index.ancestor_table(parent)?;
    if active_candidate && activation_chain.is_some() {
        return Err(NodeError::StaleBlockAdmission);
    }
    if !active_candidate
        && cumulative_work > index.active_work
        && requires_external_preverification(&params)
        && activation_chain.is_none()
    {
        return Err(NodeError::ProductionV3Unavailable);
    }
    Ok(PreparedBlock {
        block_id,
        parent,
        height: block.challenge.height,
        target: block.challenge.target,
        accepted_at,
        cumulative_work,
        ancestors,
        activation_chain,
        candidate,
    })
}

fn rebuild_state_to(
    block_log: &File,
    block_log_path: &Path,
    index: &BlockIndex,
    params: NetworkParams,
    verifier: &ConsensusPowVerifier,
    tip: [u8; 32],
    external_preverifier: Option<&BlockPreverifier>,
) -> Result<ChainState, NodeError> {
    let mut state = ChainState::new(params, verifier.clone())?;
    replay_indexed_state_to(
        block_log,
        block_log_path,
        &mut state,
        index,
        params,
        tip,
        external_preverifier,
    )?;
    Ok(state)
}

fn replay_indexed_state_to(
    block_log: &File,
    block_log_path: &Path,
    state: &mut ChainState,
    index: &BlockIndex,
    params: NetworkParams,
    tip: [u8; 32],
    external_preverifier: Option<&BlockPreverifier>,
) -> Result<(), NodeError> {
    if state.tip() != index.genesis {
        return Err(NodeError::CorruptLog(
            "indexed replay must begin at virtual genesis".to_owned(),
        ));
    }
    for block_id in index.path_to(tip)? {
        let entry = index.blocks.get(&block_id).ok_or_else(|| {
            NodeError::CorruptLog("fork path refers to an absent block".to_owned())
        })?;
        let block = read_indexed_block(
            block_log,
            block_log_path,
            entry,
            block_id,
            params.network_id,
            requires_external_preverification(&params),
        )?;
        if block.block_id() != block_id
            || block.challenge.previous_block != entry.parent()
            || block.challenge.height != entry.height()
        {
            return Err(NodeError::CorruptLog(
                "indexed block metadata does not match its canonical frame".to_owned(),
            ));
        }
        let context = BlockValidationContext {
            now_unix_seconds: entry.accepted_at(),
        };
        let validated = if let Some(preverifier) = external_preverifier {
            let preverified = match preverifier.preverify_unqueued(&block) {
                Ok(preverified) => preverified,
                Err(NodeError::ProofVerifierWorker(VerifierWorkerError::ProofRejected(error))) => {
                    return Err(NodeError::CorruptLog(format!(
                        "indexed production block proof is rejected during fresh replay: {error}"
                    )));
                }
                Err(error) => return Err(error),
            };
            state
                .validate_block_preverified(&block, context, &preverified)
                .map_err(|error| {
                    NodeError::CorruptLog(format!(
                        "indexed side branch fails freshly preverified consensus replay: {error}"
                    ))
                })?
        } else if requires_external_preverification(&params) {
            return Err(NodeError::ProductionV3Unavailable);
        } else {
            state.validate_block(&block, context).map_err(|error| {
                NodeError::CorruptLog(format!(
                    "indexed side branch fails full consensus replay: {error}"
                ))
            })?
        };
        state.commit_validated(validated).map_err(|error| {
            NodeError::CorruptLog(format!(
                "indexed side branch cannot commit replayed state: {error}"
            ))
        })?;
        if state.successor_header_preflight()? != entry.successor_header {
            return Err(NodeError::CorruptLog(
                "indexed side branch header snapshot does not match replayed state".to_owned(),
            ));
        }
    }
    Ok(())
}

struct CommitOutcome {
    fees: u64,
}

fn commit_prepared(
    active_state: &mut ChainState,
    index: &mut BlockIndex,
    mut prepared: PreparedBlock,
    locator: BlockRecordLocator,
) -> Result<CommitOutcome, NodeError> {
    if locator.version != BlockRecordVersion::V2
        || locator.block_id != prepared.block_id
        || locator.parent != prepared.parent
        || locator.height != prepared.height
        || locator.target != prepared.target
        || locator.accepted_at != prepared.accepted_at
    {
        return Err(NodeError::CorruptLog(
            "prepared block metadata does not match its durable record locator".to_owned(),
        ));
    }
    let activates = prepared.cumulative_work > index.active_work;
    if matches!(prepared.candidate, ValidatedCandidate::Active(_)) && !activates {
        return Err(NodeError::CorruptLog(
            "active extension did not increase cumulative work".to_owned(),
        ));
    }
    let was_active = matches!(prepared.candidate, ValidatedCandidate::Active(_));
    let mut externally_prepared_chain = prepared.activation_chain.take();
    let next_active_chain = if activates && !was_active {
        if let Some(chain) = externally_prepared_chain.take() {
            Some(chain)
        } else {
            let mut chain = Vec::new();
            chain.push(index.genesis);
            chain.extend(index.path_to(prepared.parent)?);
            chain.push(prepared.block_id);
            Some(chain)
        }
    } else {
        None
    };

    let (fees, successor_header) = match prepared.candidate {
        ValidatedCandidate::Active(validated) => {
            let fees = active_state.commit_validated(validated)?;
            let successor_header = active_state.successor_header_preflight()?;
            (fees, successor_header)
        }
        ValidatedCandidate::Branch {
            mut state,
            validated,
        } => {
            let fees = state.commit_validated(validated)?;
            let successor_header = state.successor_header_preflight()?;
            if activates {
                *active_state = *state;
            }
            (fees, successor_header)
        }
    };

    let previous = index.blocks.insert(
        prepared.block_id,
        Arc::new(IndexedBlock {
            locator,
            cumulative_work: prepared.cumulative_work,
            successor_header,
            ancestors: prepared.ancestors,
        }),
    );
    if previous.is_some() {
        return Err(NodeError::DuplicateBlock(prepared.block_id));
    }
    if activates {
        if was_active {
            index.active_chain.push(prepared.block_id);
        } else if let Some(active_chain) = next_active_chain {
            let expected_len = usize::try_from(prepared.height)
                .ok()
                .and_then(|height| height.checked_add(1))
                .ok_or_else(|| {
                    NodeError::CorruptLog(
                        "active chain height does not fit this platform".to_owned(),
                    )
                })?;
            if active_chain.len() != expected_len
                || active_chain.first() != Some(&index.genesis)
                || active_chain.last() != Some(&prepared.block_id)
                || active_chain.get(active_chain.len().saturating_sub(2)) != Some(&prepared.parent)
            {
                return Err(NodeError::CorruptLog(
                    "externally prepared active chain has invalid endpoints".to_owned(),
                ));
            }
            index.active_chain = active_chain;
        } else {
            return Err(NodeError::CorruptLog(
                "activating side branch is missing its canonical path".to_owned(),
            ));
        }
        index.active_work = prepared.cumulative_work;
    }
    Ok(CommitOutcome { fees })
}

#[derive(Debug)]
struct RpcRequest {
    method: String,
    target: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

struct DeadlineReader<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}

impl<'a> DeadlineReader<'a> {
    fn new(stream: &'a mut TcpStream, total_timeout: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + total_timeout,
        }
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "RPC deadline exceeded"))?;
        self.stream
            .set_read_timeout(Some(remaining.min(RPC_READ_TIMEOUT)))?;
        self.stream.read(buffer)
    }
}

struct RpcResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl RpcResponse {
    fn json(status: u16, reason: &'static str, value: serde_json::Value) -> Self {
        Self {
            status,
            reason,
            content_type: "application/json",
            body: serde_json::to_vec(&value).expect("JSON value serialization cannot fail"),
        }
    }

    fn json_error(status: u16, reason: &'static str, error: impl ToString) -> Self {
        Self::json(status, reason, json!({ "error": error.to_string() }))
    }

    fn node_error(error: NodeError) -> Self {
        let error = error.client_error();
        let reason = match error.status {
            400 => "Bad Request",
            409 => "Conflict",
            422 => "Unprocessable Content",
            503 => "Service Unavailable",
            _ => "Internal Server Error",
        };
        Self::json(error.status, reason, json!({ "error": error.message }))
    }
}

/// Runs the intentionally small, single-threaded Devnet-0 RPC service.
///
/// The listener refuses non-loopback addresses. Each connection has fixed
/// timeouts and request-size limits, and is closed after one HTTP/1.1 request.
pub fn serve_rpc(node: Node, bind: SocketAddr) -> Result<(), NodeError> {
    serve_rpc_shared(Arc::new(Mutex::new(node)), bind)
}

/// Runs the bounded RPC service against a node shared with the P2P runtime.
pub fn serve_rpc_shared(shared: Arc<Mutex<Node>>, bind: SocketAddr) -> Result<(), NodeError> {
    spawn_rpc_server(shared, bind)?.wait()
}

/// A cancellable RPC listener. `stop` wakes the nonblocking accept loop and
/// joins it after any already accepted, bounded request completes or times out.
pub struct RpcServerHandle {
    local_address: SocketAddr,
    stop: Arc<(Mutex<bool>, Condvar)>,
    #[cfg(test)]
    active_request: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), NodeError>>>,
}

impl RpcServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_address
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(JoinHandle::is_finished)
    }

    pub fn stop(mut self) -> Result<(), NodeError> {
        self.stop_inner()
    }

    fn wait(mut self) -> Result<(), NodeError> {
        join_rpc_thread(self.thread.take())
    }

    fn stop_inner(&mut self) -> Result<(), NodeError> {
        signal_rpc_stop(&self.stop)?;
        join_rpc_thread(self.thread.take())
    }
}

impl Drop for RpcServerHandle {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

/// Starts the bounded RPC service and returns a handle that owns its listener
/// thread. The bind remains loopback-only, including when port zero is used by
/// an isolated test.
pub fn spawn_rpc_server(
    shared: Arc<Mutex<Node>>,
    bind: SocketAddr,
) -> Result<RpcServerHandle, NodeError> {
    if !bind.ip().is_loopback() {
        return Err(NodeError::NonLoopbackRpc(bind));
    }
    let listener = TcpListener::bind(bind)
        .map_err(|source| io_error("bind RPC listener", PathBuf::from(bind.to_string()), source))?;
    spawn_rpc_server_with_listener(shared, listener)
}

fn spawn_rpc_server_with_listener(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
) -> Result<RpcServerHandle, NodeError> {
    let local_address = listener.local_addr().map_err(NodeError::RpcIo)?;
    if !local_address.ip().is_loopback() {
        return Err(NodeError::NonLoopbackRpc(local_address));
    }
    listener.set_nonblocking(true).map_err(NodeError::RpcIo)?;
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let active_request = Arc::new(AtomicBool::new(false));
    #[cfg(test)]
    let observed_active_request = Arc::clone(&active_request);
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("cmfd-rpc-listener".to_owned())
        .spawn(move || rpc_listener_loop(shared, listener, thread_stop, active_request))
        .map_err(NodeError::RpcIo)?;
    Ok(RpcServerHandle {
        local_address,
        stop,
        #[cfg(test)]
        active_request: observed_active_request,
        thread: Some(thread),
    })
}

fn rpc_listener_loop(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
    stop: Arc<(Mutex<bool>, Condvar)>,
    active_request: Arc<AtomicBool>,
) -> Result<(), NodeError> {
    loop {
        if rpc_stopped(&stop)? {
            return Ok(());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Accepted sockets can inherit the listener's nonblocking mode
                // on some platforms. Requests retain their existing bounded,
                // blocking read and write deadlines.
                stream.set_nonblocking(false).map_err(NodeError::RpcIo)?;
                let _active_request = ActiveRpcRequest::new(Arc::clone(&active_request));
                if let Err(error) = handle_rpc_connection_shared(&mut stream, &shared) {
                    let response = RpcResponse::node_error(error);
                    let _ = write_rpc_response(&mut stream, response);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if wait_for_rpc_stop(&stop)? {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(NodeError::RpcIo(error)),
        }
    }
}

struct ActiveRpcRequest(Arc<AtomicBool>);

impl ActiveRpcRequest {
    fn new(active: Arc<AtomicBool>) -> Self {
        active.store(true, Ordering::Release);
        Self(active)
    }
}

impl Drop for ActiveRpcRequest {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn rpc_stopped(stop: &Arc<(Mutex<bool>, Condvar)>) -> Result<bool, NodeError> {
    stop.0
        .lock()
        .map(|stopped| *stopped)
        .map_err(|_| rpc_lifecycle_error("RPC shutdown state is poisoned"))
}

fn wait_for_rpc_stop(stop: &Arc<(Mutex<bool>, Condvar)>) -> Result<bool, NodeError> {
    let stopped = stop
        .0
        .lock()
        .map_err(|_| rpc_lifecycle_error("RPC shutdown state is poisoned"))?;
    let (stopped, _) = stop
        .1
        .wait_timeout_while(stopped, RPC_ACCEPT_POLL, |stopped| !*stopped)
        .map_err(|_| rpc_lifecycle_error("RPC shutdown state is poisoned"))?;
    Ok(*stopped)
}

fn signal_rpc_stop(stop: &Arc<(Mutex<bool>, Condvar)>) -> Result<(), NodeError> {
    let mut stopped = stop
        .0
        .lock()
        .map_err(|_| rpc_lifecycle_error("RPC shutdown state is poisoned"))?;
    *stopped = true;
    stop.1.notify_all();
    Ok(())
}

fn join_rpc_thread(thread: Option<JoinHandle<Result<(), NodeError>>>) -> Result<(), NodeError> {
    let Some(thread) = thread else {
        return Ok(());
    };
    thread
        .join()
        .map_err(|_| rpc_lifecycle_error("RPC service thread panicked"))?
}

fn rpc_lifecycle_error(message: &'static str) -> NodeError {
    NodeError::RpcIo(io::Error::other(message))
}

fn handle_rpc_connection_shared(
    stream: &mut TcpStream,
    shared: &Arc<Mutex<Node>>,
) -> Result<(), NodeError> {
    stream
        .set_read_timeout(Some(RPC_READ_TIMEOUT))
        .map_err(NodeError::RpcIo)?;
    stream
        .set_write_timeout(Some(RPC_WRITE_TIMEOUT))
        .map_err(NodeError::RpcIo)?;
    let mut deadline_reader = DeadlineReader::new(stream, RPC_TOTAL_READ_TIMEOUT);
    let request = match read_rpc_request(&mut deadline_reader) {
        Ok(request) => request,
        Err(error) => {
            return write_rpc_response(stream, RpcResponse::node_error(error));
        }
    };
    let response = if request.method == "POST" && request.target == "/v1/block" {
        route_shared_block_request(request, shared)
    } else {
        let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        route_rpc_request(request, &mut node)
    };
    write_rpc_response(stream, response)
}

fn route_rpc_request(request: RpcRequest, node: &mut Node) -> RpcResponse {
    match (request.method.as_str(), request.target.as_str()) {
        ("GET", "/health") if node.storage_faulted => RpcResponse::json(
            503,
            "Service Unavailable",
            json!({
                "ok": false,
                "storage_healthy": false,
                "network": node.profile.name
            }),
        ),
        ("GET", "/health") => RpcResponse::json(
            200,
            "OK",
            json!({
                "ok": true,
                "storage_healthy": true,
                "network": node.profile.name
            }),
        ),
        ("GET", "/v1/status") => match node.status() {
            Ok(status) => match serde_json::to_value(status) {
                Ok(value) => RpcResponse::json(200, "OK", value),
                Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
            },
            Err(error) => RpcResponse::node_error(error),
        },
        ("GET", "/v1/mempool") => match serde_json::to_value(node.mempool_snapshot()) {
            Ok(value) => RpcResponse::json(200, "OK", value),
            Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
        },
        ("GET", "/v1/wallet") => match node.wallet_snapshot() {
            Ok(snapshot) => match serde_json::to_value(snapshot) {
                Ok(value) => RpcResponse::json(200, "OK", value),
                Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
            },
            Err(error) => RpcResponse::node_error(error),
        },
        ("POST", "/v1/wallet/send") => {
            if !has_json_content_type(request.content_type.as_deref()) {
                return RpcResponse::json_error(
                    415,
                    "Unsupported Media Type",
                    "Content-Type must be application/json",
                );
            }
            let send: WalletSendRequest = match serde_json::from_slice(&request.body) {
                Ok(send) => send,
                Err(error) => return RpcResponse::json_error(400, "Bad Request", error),
            };
            match node.send_from_dev_wallet_request(send) {
                Ok(response) => match serde_json::to_value(response) {
                    Ok(value) => RpcResponse::json(200, "OK", value),
                    Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
                },
                Err(error) => RpcResponse::node_error(error),
            }
        }
        ("POST", "/v1/wallet/consolidate") => {
            if !has_json_content_type(request.content_type.as_deref()) {
                return RpcResponse::json_error(
                    415,
                    "Unsupported Media Type",
                    "Content-Type must be application/json",
                );
            }
            let consolidation: WalletConsolidateRequest =
                match serde_json::from_slice(&request.body) {
                    Ok(consolidation) => consolidation,
                    Err(error) => return RpcResponse::json_error(400, "Bad Request", error),
                };
            match node.consolidate_dev_wallet_request(consolidation) {
                Ok(response) => match serde_json::to_value(response) {
                    Ok(value) => RpcResponse::json(200, "OK", value),
                    Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
                },
                Err(error) => RpcResponse::node_error(error),
            }
        }
        ("GET", target) if target.starts_with("/v1/template?") => {
            let miner = match parse_template_miner(target) {
                Ok(miner) => miner,
                Err(error) => return RpcResponse::json_error(400, "Bad Request", error),
            };
            let now = match unix_time_seconds() {
                Ok(now) => now,
                Err(error) => {
                    return RpcResponse::json_error(500, "Internal Server Error", error);
                }
            };
            match node.build_template(miner, now) {
                Ok(template) => {
                    RpcResponse::json(200, "OK", template_json(&template, node.profile))
                }
                Err(NodeError::StorageFaulted) => {
                    RpcResponse::json_error(503, "Service Unavailable", NodeError::StorageFaulted)
                }
                Err(error) => RpcResponse::json_error(422, "Unprocessable Content", error),
            }
        }
        ("POST", "/v1/transaction") => {
            if !has_octet_stream_content_type(request.content_type.as_deref()) {
                return RpcResponse::json_error(
                    415,
                    "Unsupported Media Type",
                    "Content-Type must be application/octet-stream",
                );
            }
            let transaction = match decode_transaction(&request.body, node.params.network_id) {
                Ok(transaction) => transaction,
                Err(error) => return RpcResponse::json_error(400, "Bad Request", error),
            };
            match encode_transaction(&transaction) {
                Ok(canonical) if canonical == request.body => {}
                Ok(_) => {
                    return RpcResponse::json_error(
                        400,
                        "Bad Request",
                        "transaction frame is not canonical",
                    );
                }
                Err(error) => return RpcResponse::json_error(400, "Bad Request", error),
            }
            match node.submit_transaction(transaction) {
                Ok(entry) => RpcResponse::json(
                    200,
                    "OK",
                    json!({
                        "accepted": true,
                        "txid": hex::encode(entry.txid),
                        "encoded_bytes": entry.encoded_bytes,
                        "fee_burned": entry.fee_burned,
                        "mempool_transactions": node.mempool.len(),
                        "mempool_bytes": node.mempool_bytes,
                    }),
                ),
                Err(
                    error @ (NodeError::DuplicateMempoolTransaction(_)
                    | NodeError::MempoolInputConflict(_)),
                ) => RpcResponse::json_error(409, "Conflict", error),
                Err(
                    error @ (NodeError::MempoolUnconfirmedInput(_)
                    | NodeError::MempoolTransactionLimit
                    | NodeError::MempoolByteLimit
                    | NodeError::MempoolFeeTooLow { .. }
                    | NodeError::Chain(_)),
                ) => RpcResponse::json_error(422, "Unprocessable Content", error),
                Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
            }
        }
        ("POST", target) if target.starts_with("/v1/mine?") => {
            if !request.body.is_empty() {
                return RpcResponse::json_error(
                    400,
                    "Bad Request",
                    "mine endpoint requires an empty body",
                );
            }
            let request = match parse_mine_request(target) {
                Ok(request) => request,
                Err(error) => return RpcResponse::node_error(error),
            };
            match node.mine_devnet_request(request) {
                Ok(result) => match serde_json::to_value(result) {
                    Ok(value) => RpcResponse::json(200, "OK", value),
                    Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
                },
                Err(error) => RpcResponse::node_error(error),
            }
        }
        ("POST", "/v1/block") => {
            let block = match decode_canonical_rpc_block(&request, node.params.network_id) {
                Ok(block) => block,
                Err(response) => return response,
            };
            let accepted_at = match unix_time_seconds() {
                Ok(accepted_at) => accepted_at,
                Err(error) => {
                    return RpcResponse::json_error(500, "Internal Server Error", error);
                }
            };
            match node.submit_block(block, accepted_at) {
                Ok(fees_burned) => accepted_block_rpc_response(node, fees_burned),
                Err(NodeError::Chain(error)) => {
                    RpcResponse::json_error(422, "Unprocessable Content", error)
                }
                Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
            }
        }
        ("GET" | "POST", _) => RpcResponse::json_error(404, "Not Found", "unknown endpoint"),
        _ => RpcResponse::json_error(405, "Method Not Allowed", "method not allowed"),
    }
}

fn route_shared_block_request(request: RpcRequest, shared: &Arc<Mutex<Node>>) -> RpcResponse {
    let network_id = match shared.lock() {
        Ok(node) => node.params.network_id,
        Err(_) => return RpcResponse::node_error(NodeError::SharedNodePoisoned),
    };
    let block = match decode_canonical_rpc_block(&request, network_id) {
        Ok(block) => block,
        Err(response) => return response,
    };
    let accepted_at = match unix_time_seconds() {
        Ok(accepted_at) => accepted_at,
        Err(error) => return RpcResponse::node_error(error),
    };
    let fees_burned = match submit_shared_block(shared, block, accepted_at) {
        Ok(fees_burned) => fees_burned,
        Err(error) => return RpcResponse::node_error(error),
    };
    match shared.lock() {
        Ok(node) => accepted_block_rpc_response(&node, fees_burned),
        Err(_) => RpcResponse::node_error(NodeError::SharedNodePoisoned),
    }
}

fn decode_canonical_rpc_block(
    request: &RpcRequest,
    network_id: [u8; 32],
) -> Result<Block, RpcResponse> {
    if !has_octet_stream_content_type(request.content_type.as_deref()) {
        return Err(RpcResponse::json_error(
            415,
            "Unsupported Media Type",
            "Content-Type must be application/octet-stream",
        ));
    }
    let block = decode_block(&request.body, network_id)
        .map_err(|error| RpcResponse::json_error(400, "Bad Request", error))?;
    match encode_block(&block) {
        Ok(canonical) if canonical == request.body => Ok(block),
        Ok(_) => Err(RpcResponse::json_error(
            400,
            "Bad Request",
            "block frame is not canonical",
        )),
        Err(error) => Err(RpcResponse::json_error(400, "Bad Request", error)),
    }
}

fn accepted_block_rpc_response(node: &Node, fees_burned: u64) -> RpcResponse {
    match node.status() {
        Ok(status) => RpcResponse::json(
            200,
            "OK",
            json!({
                "accepted": true,
                "height": status.accepted_height,
                "tip": status.tip,
                "fees_burned": fees_burned,
            }),
        ),
        Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
    }
}

fn has_octet_stream_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/octet-stream")
        })
}

fn has_json_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn parse_wallet_recipient(value: &str) -> Result<[u8; 32], NodeError> {
    if value.len() != 64 {
        return Err(NodeError::InvalidWalletRecipient);
    }
    let bytes = hex::decode(value).map_err(|_| NodeError::InvalidWalletRecipient)?;
    let recipient: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NodeError::InvalidWalletRecipient)?;
    VerifyingKey::from_bytes(&recipient).map_err(|_| NodeError::InvalidWalletRecipient)?;
    Ok(recipient)
}

fn parse_cmfd_atoms(value: &str) -> Result<u64, NodeError> {
    let mut parts = value.split('.');
    let whole = parts.next().ok_or(NodeError::InvalidWalletAmount)?;
    let fractional = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(NodeError::InvalidWalletAmount);
    }
    let whole_atoms = whole
        .parse::<u64>()
        .map_err(|_| NodeError::WalletAmountOverflow)?
        .checked_mul(COIN)
        .ok_or(NodeError::WalletAmountOverflow)?;
    let fractional_atoms = match fractional {
        None => 0,
        Some(digits)
            if !digits.is_empty()
                && digits.len() <= 8
                && digits.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let value = digits
                .parse::<u64>()
                .map_err(|_| NodeError::InvalidWalletAmount)?;
            value * 10_u64.pow(8 - digits.len() as u32)
        }
        Some(_) => return Err(NodeError::InvalidWalletAmount),
    };
    whole_atoms
        .checked_add(fractional_atoms)
        .ok_or(NodeError::WalletAmountOverflow)
}

fn parse_template_miner(target: &str) -> Result<[u8; 32], NodeError> {
    let (path, query) = target
        .split_once('?')
        .ok_or_else(|| NodeError::InvalidRpcRequest("template requires miner query".to_owned()))?;
    if path != "/v1/template" || query.contains('&') {
        return Err(NodeError::InvalidRpcRequest(
            "template accepts exactly one miner query".to_owned(),
        ));
    }
    let value = query
        .strip_prefix("miner=")
        .ok_or_else(|| NodeError::InvalidRpcRequest("template requires miner query".to_owned()))?;
    parse_miner_destination(value)
}

fn parse_mine_request(target: &str) -> Result<DevMineRequest, NodeError> {
    let (path, query) = target
        .split_once('?')
        .ok_or_else(|| NodeError::InvalidRpcRequest("mine requires query parameters".to_owned()))?;
    if path != "/v1/mine" {
        return Err(NodeError::InvalidRpcRequest(
            "invalid mine endpoint".to_owned(),
        ));
    }

    let mut miner = None;
    let mut attempts = None;
    for parameter in query.split('&') {
        let (name, value) = parameter.split_once('=').ok_or_else(|| {
            NodeError::InvalidRpcRequest("malformed mine query parameter".to_owned())
        })?;
        match name {
            "miner" if miner.is_none() => miner = Some(value.to_owned()),
            "attempts" if attempts.is_none() => {
                let parsed = value.parse::<u64>().map_err(|_| {
                    NodeError::InvalidRpcRequest("mine attempts must be an integer".to_owned())
                })?;
                attempts = Some(parsed);
            }
            _ => {
                return Err(NodeError::InvalidRpcRequest(
                    "mine requires exactly one miner and one attempts parameter".to_owned(),
                ));
            }
        }
    }
    let miner = miner.ok_or_else(|| {
        NodeError::InvalidRpcRequest("mine requires a miner parameter".to_owned())
    })?;
    let attempts = attempts.ok_or_else(|| {
        NodeError::InvalidRpcRequest("mine requires an attempts parameter".to_owned())
    })?;
    Ok(DevMineRequest { miner, attempts })
}

fn validate_dev_mine_request(request: &DevMineRequest) -> Result<([u8; 32], u64), NodeError> {
    let miner = parse_miner_destination(&request.miner)?;
    if request.attempts == 0 || request.attempts > DEFAULT_MINING_ATTEMPTS {
        return Err(NodeError::InvalidRpcRequest(format!(
            "mine attempts must be between 1 and {DEFAULT_MINING_ATTEMPTS}"
        )));
    }
    Ok((miner, request.attempts))
}

fn template_json(template: &BlockTemplate, profile: NetworkProfile) -> serde_json::Value {
    let outputs: Vec<_> = template
        .coinbase
        .outputs
        .iter()
        .map(|output| {
            let destination = match output.lock {
                OutputLock::Key(destination) => hex::encode(destination),
                OutputLock::InferenceChannel { channel_id } => hex::encode(channel_id),
            };
            json!({
                "value": output.value,
                "destination": destination,
                "spendable_height": output.spendable_height,
            })
        })
        .collect();
    json!({
        "network": profile.name,
        "proof_type": profile.proof_name(),
        "block_version": BLOCK_VERSION,
        "network_id": hex::encode(template.challenge.network_id),
        "previous_block": hex::encode(template.challenge.previous_block),
        "transaction_root": hex::encode(template.challenge.transaction_root),
        "height": template.challenge.height,
        "timestamp": template.challenge.timestamp,
        "target": hex::encode(template.challenge.target),
        "coinbase": {
            "height": template.coinbase.height,
            "outputs": outputs,
        },
        "transactions": template.transactions,
        "transaction_ids": template
            .transactions
            .iter()
            .map(|transaction| hex::encode(transaction.txid()))
            .collect::<Vec<_>>(),
        "fees_burned": template.total_fees_burned,
    })
}

fn read_rpc_request(reader: &mut impl Read) -> Result<RpcRequest, NodeError> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = position + 4;
            if end > RPC_HEADER_LIMIT {
                return Err(NodeError::InvalidRpcRequest(
                    "headers exceed 8192 bytes".to_owned(),
                ));
            }
            break end;
        }
        if bytes.len() >= RPC_HEADER_LIMIT {
            return Err(NodeError::InvalidRpcRequest(
                "headers exceed 8192 bytes".to_owned(),
            ));
        }
        let mut chunk = [0_u8; 1024];
        let count = reader.read(&mut chunk).map_err(NodeError::RpcIo)?;
        if count == 0 {
            return Err(NodeError::InvalidRpcRequest(
                "request ended before headers were complete".to_owned(),
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    };

    let header = std::str::from_utf8(&bytes[..header_end - 4])
        .map_err(|_| NodeError::InvalidRpcRequest("headers are not UTF-8".to_owned()))?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| NodeError::InvalidRpcRequest("missing request line".to_owned()))?;
    let request_parts: Vec<_> = request_line.split_whitespace().collect();
    if request_parts.len() != 3 || request_parts[2] != "HTTP/1.1" {
        return Err(NodeError::InvalidRpcRequest(
            "request line must use HTTP/1.1".to_owned(),
        ));
    }

    let mut content_length = None;
    let mut content_type = None;
    let body_limit = rpc_body_limit(request_parts[0], request_parts[1]);
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| NodeError::InvalidRpcRequest("malformed HTTP header".to_owned()))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(NodeError::InvalidRpcRequest(
                    "duplicate Content-Length".to_owned(),
                ));
            }
            let length = value
                .parse::<usize>()
                .map_err(|_| NodeError::InvalidRpcRequest("invalid Content-Length".to_owned()))?;
            if length > body_limit {
                return Err(NodeError::InvalidRpcRequest(format!(
                    "request body exceeds the {body_limit}-byte endpoint limit"
                )));
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(NodeError::InvalidRpcRequest(
                "Transfer-Encoding is not supported".to_owned(),
            ));
        }
    }

    let body_length = content_length.unwrap_or(0);
    if request_parts[0] == "POST" && content_length.is_none() {
        return Err(NodeError::InvalidRpcRequest(
            "POST requires Content-Length".to_owned(),
        ));
    }
    let mut body = bytes[header_end..].to_vec();
    if body.len() > body_length {
        return Err(NodeError::InvalidRpcRequest(
            "request contains bytes after its declared body".to_owned(),
        ));
    }
    let remaining = body_length - body.len();
    if remaining > 0 {
        let original_len = body.len();
        body.resize(body_length, 0);
        reader
            .read_exact(&mut body[original_len..])
            .map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    NodeError::InvalidRpcRequest("request body is truncated".to_owned())
                } else {
                    NodeError::RpcIo(error)
                }
            })?;
    }
    if request_parts[0] == "GET" && !body.is_empty() {
        return Err(NodeError::InvalidRpcRequest(
            "GET requests may not contain a body".to_owned(),
        ));
    }

    Ok(RpcRequest {
        method: request_parts[0].to_owned(),
        target: request_parts[1].to_owned(),
        content_type,
        body,
    })
}

fn rpc_body_limit(method: &str, target: &str) -> usize {
    match (method, target) {
        ("POST", "/v1/transaction") => MAX_TRANSACTION_BYTES,
        ("POST", "/v1/wallet/send" | "/v1/wallet/consolidate") => WALLET_JSON_BODY_LIMIT,
        ("POST", "/v1/block") => MAX_BLOCK_BYTES,
        ("POST", target) if target.starts_with("/v1/mine?") => 0,
        ("GET", _) => 0,
        _ => MAX_BLOCK_BYTES,
    }
}

fn write_rpc_response(stream: &mut impl Write, response: RpcResponse) -> Result<(), NodeError> {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    );
    stream
        .write_all(header.as_bytes())
        .map_err(NodeError::RpcIo)?;
    stream.write_all(&response.body).map_err(NodeError::RpcIo)?;
    stream.flush().map_err(NodeError::RpcIo)
}

#[cfg(test)]
fn insecure_dev_destination(secret_byte: u8) -> [u8; 32] {
    let signing = SigningKey::from_bytes(&[secret_byte; 32])
        .expect("fixed nonzero development signing key must be valid");
    signing.verifying_key().to_bytes().into()
}

fn insecure_dev_wallet_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x13; 32])
        .expect("fixed nonzero development wallet signing key must be valid")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataState {
    Missing,
    Legacy,
    Current,
}

fn io_error(operation: &'static str, path: impl AsRef<Path>, source: io::Error) -> NodeError {
    NodeError::Io {
        operation,
        path: path.as_ref().to_path_buf(),
        source,
    }
}

fn load_metadata(
    data_dir: &Path,
    fingerprint: [u8; 32],
    block_log: &File,
    block_log_path: &Path,
) -> Result<MetadataState, NodeError> {
    let path = data_dir.join(METADATA_FILE);
    match OpenOptions::new().read(true).open(&path) {
        Ok(mut file) => {
            if file
                .metadata()
                .map_err(|source| io_error("inspect network metadata", &path, source))?
                .len()
                != METADATA_BYTES as u64
            {
                return Err(NodeError::InvalidMetadata);
            }
            let mut bytes = [0_u8; METADATA_BYTES];
            file.read_exact(&mut bytes).map_err(|source| {
                if source.kind() == io::ErrorKind::UnexpectedEof {
                    NodeError::InvalidMetadata
                } else {
                    io_error("read network metadata", &path, source)
                }
            })?;
            let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
            if bytes[..4] != METADATA_MAGIC
                || u16::from_le_bytes([bytes[4], bytes[5]]) != METADATA_VERSION
                || flags & !METADATA_WALLET_KEY_FLAG != 0
            {
                return Err(NodeError::InvalidMetadata);
            }
            if bytes[8..40] != fingerprint {
                return Err(NodeError::FingerprintMismatch);
            }
            if flags & METADATA_WALLET_KEY_FLAG == 0 {
                Ok(MetadataState::Legacy)
            } else {
                Ok(MetadataState::Current)
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            if block_log
                .metadata()
                .map_err(|source| io_error("inspect retained block log", block_log_path, source))?
                .len()
                > 0
            {
                return Err(NodeError::MissingMetadata);
            }
            Ok(MetadataState::Missing)
        }
        Err(source) => Err(io_error("open network metadata", &path, source)),
    }
}

fn write_metadata(
    data_dir: &Path,
    fingerprint: [u8; 32],
    metadata: MetadataState,
) -> Result<(), NodeError> {
    let path = data_dir.join(METADATA_FILE);
    if metadata == MetadataState::Legacy {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|source| {
                io_error("open network metadata for wallet migration", &path, source)
            })?;
        file.seek(SeekFrom::Start(6)).map_err(|source| {
            io_error("seek network metadata for wallet migration", &path, source)
        })?;
        file.write_all(&METADATA_WALLET_KEY_FLAG.to_le_bytes())
            .map_err(|source| io_error("write wallet metadata flag", &path, source))?;
        return file
            .sync_all()
            .map_err(|source| io_error("sync network metadata", &path, source));
    }
    debug_assert_eq!(metadata, MetadataState::Missing);
    let mut bytes = Vec::with_capacity(METADATA_BYTES);
    bytes.extend_from_slice(&METADATA_MAGIC);
    bytes.extend_from_slice(&METADATA_VERSION.to_le_bytes());
    bytes.extend_from_slice(&METADATA_WALLET_KEY_FLAG.to_le_bytes());
    bytes.extend_from_slice(&fingerprint);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| io_error("create network metadata", &path, source))?;
    file.write_all(&bytes)
        .map_err(|source| io_error("write network metadata", &path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync network metadata", &path, source))
}

fn load_or_create_wallet_key(
    data_dir: &Path,
    metadata: MetadataState,
    block_log: &File,
    block_log_path: &Path,
) -> Result<(SigningKey, bool), NodeError> {
    let path = data_dir.join(WALLET_KEY_FILE);
    match OpenOptions::new().read(true).open(&path) {
        Ok(mut file) => {
            if file
                .metadata()
                .map_err(|source| io_error("inspect wallet key", &path, source))?
                .len()
                != 32
            {
                return Err(NodeError::InvalidWalletKey);
            }
            let mut secret = [0_u8; 32];
            file.read_exact(&mut secret)
                .map_err(|_| NodeError::InvalidWalletKey)?;
            let key = SigningKey::from_bytes(&secret).map_err(|_| NodeError::InvalidWalletKey)?;
            let destination: [u8; 32] = key.verifying_key().to_bytes().into();
            let legacy = destination == default_miner_destination();
            Ok((key, legacy))
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            if metadata == MetadataState::Current {
                return Err(NodeError::InvalidWalletKey);
            }
            let legacy = metadata == MetadataState::Legacy
                && block_log
                    .metadata()
                    .map_err(|source| {
                        io_error("inspect retained block log", block_log_path, source)
                    })?
                    .len()
                    > 0;
            let key = if legacy {
                insecure_dev_wallet_signing_key()
            } else {
                random_wallet_signing_key()?
            };
            write_wallet_key(&path, &key)?;
            Ok((key, legacy))
        }
        Err(source) => Err(io_error("open wallet key", &path, source)),
    }
}

fn random_wallet_signing_key() -> Result<SigningKey, NodeError> {
    loop {
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|source| {
            io_error(
                "generate wallet key",
                WALLET_KEY_FILE,
                io::Error::other(source.to_string()),
            )
        })?;
        if let Ok(key) = SigningKey::from_bytes(&secret) {
            return Ok(key);
        }
    }
}

fn write_wallet_key(path: &Path, key: &SigningKey) -> Result<(), NodeError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_error("create wallet key", path, source))?;
    file.write_all(&key.to_bytes())
        .map_err(|source| io_error("write wallet key", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync wallet key", path, source))
}

#[cfg(test)]
fn encode_record_v1(accepted_at: u64, block: &[u8]) -> Result<Vec<u8>, NodeError> {
    let block_len = u32::try_from(block.len())
        .map_err(|_| NodeError::CorruptLog("block length exceeds u32".to_owned()))?;
    if block.len() > MAX_BLOCK_BYTES {
        return Err(NodeError::CorruptLog("block exceeds wire limit".to_owned()));
    }
    let capacity = checked_record_len(RECORD_V1_HEADER_BYTES, block.len(), 0)?;
    let mut record = Vec::with_capacity(capacity);
    record.extend_from_slice(&RECORD_MAGIC);
    record.extend_from_slice(&RECORD_VERSION_V1.to_le_bytes());
    record.extend_from_slice(&0_u16.to_le_bytes());
    record.extend_from_slice(&accepted_at.to_le_bytes());
    record.extend_from_slice(&block_len.to_le_bytes());
    record.extend_from_slice(block);
    let checksum = record_checksum_v1(&record);
    record.extend_from_slice(&checksum);
    Ok(record)
}

fn encode_record_v2(
    accepted_at: u64,
    block: &[u8],
    delta: &[u8],
    previous_record_digest: [u8; 32],
) -> Result<Vec<u8>, NodeError> {
    if block.len() > MAX_BLOCK_BYTES {
        return Err(NodeError::CorruptLog("block exceeds wire limit".to_owned()));
    }
    if delta.len() > MAX_REVERSIBLE_STATE_DELTA_BYTES {
        return Err(NodeError::CorruptLog(
            "reversible state delta exceeds wire limit".to_owned(),
        ));
    }
    let block_len = u32::try_from(block.len())
        .map_err(|_| NodeError::CorruptLog("block length exceeds u32".to_owned()))?;
    let delta_len = u32::try_from(delta.len()).map_err(|_| {
        NodeError::CorruptLog("reversible state delta length exceeds u32".to_owned())
    })?;
    let capacity = checked_record_len(RECORD_V2_HEADER_BYTES, block.len(), delta.len())?;
    let mut record = Vec::with_capacity(capacity);
    record.extend_from_slice(&RECORD_MAGIC);
    record.extend_from_slice(&RECORD_VERSION_V2.to_le_bytes());
    record.extend_from_slice(&0_u16.to_le_bytes());
    record.extend_from_slice(&accepted_at.to_le_bytes());
    record.extend_from_slice(&block_len.to_le_bytes());
    record.extend_from_slice(&delta_len.to_le_bytes());
    record.extend_from_slice(&previous_record_digest);
    record.extend_from_slice(block);
    record.extend_from_slice(delta);
    let checksum = record_checksum_v2(&record);
    record.extend_from_slice(&checksum);
    Ok(record)
}

fn checked_record_len(
    header_len: usize,
    block_len: usize,
    delta_len: usize,
) -> Result<usize, NodeError> {
    header_len
        .checked_add(block_len)
        .and_then(|length| length.checked_add(delta_len))
        .and_then(|length| length.checked_add(RECORD_CHECKSUM_BYTES))
        .ok_or_else(|| NodeError::CorruptLog("block record length overflowed".to_owned()))
}

fn record_checksum_v1(record_without_checksum: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(RECORD_V1_CHECKSUM_DOMAIN);
    hasher.update(record_without_checksum);
    *hasher.finalize().as_bytes()
}

fn record_checksum_v2(record_without_checksum: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(RECORD_V2_CHECKSUM_DOMAIN);
    hasher.update(record_without_checksum);
    *hasher.finalize().as_bytes()
}

fn complete_record_digest(record: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(RECORD_CHAIN_DIGEST_DOMAIN);
    hasher.update(record);
    *hasher.finalize().as_bytes()
}

enum ParsedRecordPayload {
    LegacyV1,
    V2 {
        delta_bytes: Vec<u8>,
        previous_record_digest: [u8; 32],
    },
}

struct ParsedLogRecord {
    accepted_at: u64,
    block_bytes: Vec<u8>,
    payload: ParsedRecordPayload,
    complete_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockRecordVersion {
    LegacyV1,
    V2,
}

struct ScannedReplayLog {
    records: Vec<BlockRecordLocator>,
    children: HashMap<[u8; 32], Vec<usize>>,
    last_record_digest: [u8; 32],
    log_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayLogState {
    last_record_digest: [u8; 32],
    log_length: u64,
    record_count: u64,
}

struct ReplayDfsFrame {
    block_id: [u8; 32],
    next_child: usize,
    undo: Option<ReplayUndo>,
}

enum ReplayUndo {
    LegacyV1 {
        record_position: usize,
        canonical_delta: Box<[u8]>,
        capability: ReversibleStateDeltaCapability,
    },
    V2 {
        record_position: usize,
        capability: ReversibleStateDeltaCapability,
    },
}

fn read_log_record(
    reader: &mut impl Read,
    path: &Path,
    record_index: u64,
) -> Result<Option<ParsedLogRecord>, NodeError> {
    let mut prefix = [0_u8; 8];
    match reader.read(&mut prefix[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("one-byte read cannot return more than one byte"),
        Err(source) => return Err(io_error("read block log", path, source)),
    }
    reader.read_exact(&mut prefix[1..]).map_err(|source| {
        log_read_error(
            path,
            source,
            format!("record {record_index} has a truncated header"),
        )
    })?;
    if prefix[..4] != RECORD_MAGIC || prefix[6..8] != [0, 0] {
        return Err(NodeError::CorruptLog(format!(
            "record {record_index} has an invalid header"
        )));
    }

    let version = u16::from_le_bytes([prefix[4], prefix[5]]);
    let header_len = match version {
        RECORD_VERSION_V1 => RECORD_V1_HEADER_BYTES,
        RECORD_VERSION_V2 => RECORD_V2_HEADER_BYTES,
        _ => {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} has unsupported version {version}"
            )));
        }
    };
    let mut header = Vec::with_capacity(header_len);
    header.extend_from_slice(&prefix);
    header.resize(header_len, 0);
    reader
        .read_exact(&mut header[prefix.len()..])
        .map_err(|source| {
            log_read_error(
                path,
                source,
                format!("record {record_index} has a truncated header"),
            )
        })?;

    let accepted_at = u64::from_le_bytes(header[8..16].try_into().expect("fixed slice"));
    let block_len = u32::from_le_bytes(header[16..20].try_into().expect("fixed slice")) as usize;
    if block_len > MAX_BLOCK_BYTES {
        return Err(NodeError::CorruptLog(format!(
            "record {record_index} block exceeds the wire limit"
        )));
    }
    let (delta_len, previous_record_digest) = if version == RECORD_VERSION_V2 {
        let delta_len =
            u32::from_le_bytes(header[20..24].try_into().expect("fixed slice")) as usize;
        if delta_len > MAX_REVERSIBLE_STATE_DELTA_BYTES {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} reversible state delta exceeds the wire limit"
            )));
        }
        (
            delta_len,
            Some(header[24..56].try_into().expect("fixed slice")),
        )
    } else {
        (0, None)
    };
    let complete_len = checked_record_len(header_len, block_len, delta_len)?;

    let mut block_bytes = vec![0_u8; block_len];
    reader.read_exact(&mut block_bytes).map_err(|source| {
        log_read_error(
            path,
            source,
            format!("record {record_index} has a truncated block"),
        )
    })?;
    let mut delta_bytes = vec![0_u8; delta_len];
    reader.read_exact(&mut delta_bytes).map_err(|source| {
        log_read_error(
            path,
            source,
            format!("record {record_index} has a truncated reversible state delta"),
        )
    })?;
    let mut checksum = [0_u8; RECORD_CHECKSUM_BYTES];
    reader.read_exact(&mut checksum).map_err(|source| {
        log_read_error(
            path,
            source,
            format!("record {record_index} has a truncated checksum"),
        )
    })?;

    let mut complete_record = Vec::with_capacity(complete_len);
    complete_record.extend_from_slice(&header);
    complete_record.extend_from_slice(&block_bytes);
    complete_record.extend_from_slice(&delta_bytes);
    let expected_checksum = match version {
        RECORD_VERSION_V1 => record_checksum_v1(&complete_record),
        RECORD_VERSION_V2 => record_checksum_v2(&complete_record),
        _ => unreachable!("record version was checked above"),
    };
    if checksum != expected_checksum {
        return Err(NodeError::CorruptLog(format!(
            "record {record_index} checksum mismatch"
        )));
    }
    complete_record.extend_from_slice(&checksum);
    let complete_digest = complete_record_digest(&complete_record);
    let payload = match previous_record_digest {
        Some(previous_record_digest) => ParsedRecordPayload::V2 {
            delta_bytes,
            previous_record_digest,
        },
        None => ParsedRecordPayload::LegacyV1,
    };
    Ok(Some(ParsedLogRecord {
        accepted_at,
        block_bytes,
        payload,
        complete_digest,
    }))
}

#[cfg(unix)]
fn positioned_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;

    file.read_at(buffer, offset)
}

#[cfg(windows)]
fn positioned_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::ReOpenFile;

    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    // This transient reader must share with the already-open append handle.
    // The retained append handle itself still grants only FILE_SHARE_READ, so
    // no other process can acquire write or delete access to the log.
    // SAFETY: the source handle remains owned by `file`; ReOpenFile returns a
    // new independently owned handle to the same file object. `from_raw_handle`
    // takes ownership of only that returned handle.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle().cast(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` was returned successfully by ReOpenFile and is not
    // owned anywhere else.
    let mut independent = unsafe { File::from_raw_handle(handle.cast()) };
    independent.seek(SeekFrom::Start(offset))?;
    independent.read(buffer)
}

#[cfg(not(any(unix, windows)))]
fn positioned_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(offset))?;
    cloned.read(buffer)
}

fn positioned_read_exact(file: &File, mut buffer: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buffer.is_empty() {
        match positioned_read(file, buffer, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => {
                offset = offset
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("positioned read offset overflow"))?;
                buffer = &mut buffer[read..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_located_record(
    file: &File,
    path: &Path,
    locator: &BlockRecordLocator,
    network_id: [u8; 32],
    require_v2: bool,
) -> Result<(ParsedLogRecord, Block), NodeError> {
    let (minimum_length, maximum_length) = match locator.version {
        BlockRecordVersion::LegacyV1 => (
            RECORD_V1_HEADER_BYTES + RECORD_CHECKSUM_BYTES,
            checked_record_len(RECORD_V1_HEADER_BYTES, MAX_BLOCK_BYTES, 0)?,
        ),
        BlockRecordVersion::V2 => (
            RECORD_V2_HEADER_BYTES + RECORD_CHECKSUM_BYTES,
            checked_record_len(
                RECORD_V2_HEADER_BYTES,
                MAX_BLOCK_BYTES,
                MAX_REVERSIBLE_STATE_DELTA_BYTES,
            )?,
        ),
    };
    let length = usize::try_from(locator.length).map_err(|_| {
        NodeError::CorruptLog(format!(
            "record {} locator length does not fit this platform",
            locator.ordinal
        ))
    })?;
    if !(minimum_length..=maximum_length).contains(&length) {
        return Err(NodeError::CorruptLog(format!(
            "record {} locator length is outside its version bounds",
            locator.ordinal
        )));
    }
    let end = locator.offset.checked_add(locator.length).ok_or_else(|| {
        NodeError::CorruptLog(format!(
            "record {} locator end offset overflowed",
            locator.ordinal
        ))
    })?;
    let file_length = file
        .metadata()
        .map_err(|source| {
            io_error(
                "inspect retained block log for positioned read",
                path,
                source,
            )
        })?
        .len();
    if end > file_length {
        return Err(NodeError::CorruptLog(format!(
            "record {} locator extends beyond the retained block log",
            locator.ordinal
        )));
    }

    let mut bytes = vec![0_u8; length];
    positioned_read_exact(file, &mut bytes, locator.offset).map_err(|source| {
        log_read_error(
            path,
            source,
            format!(
                "record {} is truncated at its authenticated locator",
                locator.ordinal
            ),
        )
    })?;
    let mut reader = Cursor::new(bytes.as_slice());
    let record = read_log_record(&mut reader, path, locator.ordinal)?.ok_or_else(|| {
        NodeError::CorruptLog(format!(
            "record {} disappeared at its authenticated locator",
            locator.ordinal
        ))
    })?;
    if reader.position() != locator.length {
        return Err(NodeError::CorruptLog(format!(
            "record {} locator does not contain exactly one record",
            locator.ordinal
        )));
    }
    if record.complete_digest != locator.complete_digest {
        return Err(NodeError::CorruptLog(format!(
            "record {} complete digest changed",
            locator.ordinal
        )));
    }
    let actual_version = match &record.payload {
        ParsedRecordPayload::LegacyV1 => BlockRecordVersion::LegacyV1,
        ParsedRecordPayload::V2 { .. } => BlockRecordVersion::V2,
    };
    if actual_version != locator.version {
        return Err(NodeError::CorruptLog(format!(
            "record {} version changed",
            locator.ordinal
        )));
    }
    if require_v2 && actual_version != BlockRecordVersion::V2 {
        return Err(NodeError::ProductionLegacyBlockLog(locator.ordinal));
    }
    if record.accepted_at != locator.accepted_at {
        return Err(NodeError::CorruptLog(format!(
            "record {} acceptance time changed",
            locator.ordinal
        )));
    }
    let block = decode_block(&record.block_bytes, network_id).map_err(|error| {
        NodeError::CorruptLog(format!(
            "record {} cannot decode at its authenticated locator: {error}",
            locator.ordinal
        ))
    })?;
    let canonical = encode_block(&block).map_err(|error| {
        NodeError::CorruptLog(format!(
            "record {} cannot re-encode at its authenticated locator: {error}",
            locator.ordinal
        ))
    })?;
    if canonical != record.block_bytes {
        return Err(NodeError::CorruptLog(format!(
            "record {} is not canonical at its authenticated locator",
            locator.ordinal
        )));
    }
    if block.block_id() != locator.block_id
        || block.challenge.previous_block != locator.parent
        || block.challenge.height != locator.height
        || block.challenge.target != locator.target
    {
        return Err(NodeError::CorruptLog(format!(
            "record {} metadata does not match its authenticated block",
            locator.ordinal
        )));
    }
    Ok((record, block))
}

fn read_indexed_block(
    file: &File,
    path: &Path,
    indexed: &IndexedBlock,
    expected_block_id: [u8; 32],
    network_id: [u8; 32],
    require_v2: bool,
) -> Result<Block, NodeError> {
    if indexed.block_id() != expected_block_id {
        return Err(NodeError::CorruptLog(
            "fork index key does not match its durable record locator".to_owned(),
        ));
    }
    let (_, block) = read_located_record(file, path, &indexed.locator, network_id, require_v2)?;
    Ok(block)
}

fn replay_log(
    log: &File,
    path: &Path,
    state: &mut ChainState,
    index: &mut BlockIndex,
    verifier: &ConsensusPowVerifier,
    params: NetworkParams,
    external_preverifier: Option<&BlockPreverifier>,
) -> Result<ReplayLogState, NodeError> {
    let mut replayed_state = ChainState::new(params, verifier.clone())?;
    let mut replayed_index = BlockIndex::new(params.genesis_hash);
    let replay = replay_log_into(
        log,
        path,
        &mut replayed_state,
        &mut replayed_index,
        params,
        external_preverifier,
    )?;
    *state = replayed_state;
    *index = replayed_index;
    Ok(replay)
}

/// Reconstructs every logged fork with one mutable consensus state and a
/// compact validation capability per V2 ancestry edge. This bounds expensive
/// full-state retention; record-count/index and process RSS caps are enforced
/// by later node resource policy, not by this traversal alone.
fn replay_log_into(
    log: &File,
    path: &Path,
    state: &mut ChainState,
    index: &mut BlockIndex,
    params: NetworkParams,
    external_preverifier: Option<&BlockPreverifier>,
) -> Result<ReplayLogState, NodeError> {
    if state.tip() != params.genesis_hash
        || !index.blocks.is_empty()
        || index.active_chain != [params.genesis_hash]
        || index.active_work != U512::zero()
    {
        return Err(NodeError::CorruptLog(
            "startup replay requires an empty genesis state and index".to_owned(),
        ));
    }

    let mut scan_file = log
        .try_clone()
        .map_err(|source| io_error("clone retained block log for startup scan", path, source))?;
    scan_file
        .seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind retained block log for startup scan", path, source))?;
    let scanned = scan_replay_log(scan_file, path, params, params.network_id)?;
    let replay_file = log
        .try_clone()
        .map_err(|source| io_error("clone retained block log for bounded replay", path, source))?;
    if replay_file
        .metadata()
        .map_err(|source| io_error("inspect block log for bounded replay", path, source))?
        .len()
        != scanned.log_length
    {
        return Err(NodeError::CorruptLog(
            "block log length changed during startup replay".to_owned(),
        ));
    }
    if scanned.records.is_empty() {
        verify_scanned_replay_log_unchanged(&replay_file, path, &scanned, params.network_id)?;
        verify_retained_block_log_path(log, path)?;
        return Ok(ReplayLogState {
            last_record_digest: scanned.last_record_digest,
            log_length: scanned.log_length,
            record_count: 0,
        });
    }

    let mut stack = vec![ReplayDfsFrame {
        block_id: params.genesis_hash,
        next_child: 0,
        undo: None,
    }];
    let mut winning_tip = params.genesis_hash;
    let mut winning_work = U512::zero();
    let mut winning_record_index = u64::MAX;
    let mut legacy_undo_stack_bytes = 0_usize;

    while let Some(frame) = stack.last_mut() {
        let next_record = scanned
            .children
            .get(&frame.block_id)
            .and_then(|children| children.get(frame.next_child))
            .copied();
        if let Some(record_position) = next_record {
            frame.next_child = frame.next_child.checked_add(1).ok_or_else(|| {
                NodeError::CorruptLog("startup replay child counter overflowed".to_owned())
            })?;
            let record = scanned.records.get(record_position).ok_or_else(|| {
                NodeError::CorruptLog("startup replay child locator is invalid".to_owned())
            })?;
            if state.tip() != record.parent {
                return Err(NodeError::CorruptLog(format!(
                    "record {} DFS parent state is inconsistent",
                    record.ordinal
                )));
            }
            let reread = reread_replay_record(&replay_file, path, record, params.network_id)?;
            let block = decode_block(&reread.block_bytes, params.network_id).map_err(|error| {
                NodeError::CorruptLog(format!(
                    "record {} cannot decode during DFS replay: {error}",
                    record.ordinal
                ))
            })?;
            if block.block_id() != record.block_id
                || block.challenge.previous_block != record.parent
                || block.challenge.height != record.height
                || block.challenge.target != record.target
            {
                return Err(NodeError::CorruptLog(format!(
                    "record {} metadata changed after its startup scan",
                    record.ordinal
                )));
            }
            let preverified = if let Some(preverifier) = external_preverifier {
                match preverifier.preverify(&block) {
                    Ok(preverified) => Some(preverified),
                    Err(NodeError::ProofVerifierWorker(VerifierWorkerError::ProofRejected(
                        error,
                    ))) => {
                        return Err(NodeError::CorruptLog(format!(
                            "record {} proof is rejected during external replay: {error}",
                            record.ordinal
                        )));
                    }
                    Err(error) => return Err(error),
                }
            } else if requires_external_preverification(&params) {
                return Err(NodeError::ProductionV3Unavailable);
            } else {
                None
            };
            let context = BlockValidationContext {
                now_unix_seconds: record.accepted_at,
            };
            let validated = match preverified.as_ref() {
                Some(preverified) => state
                    .validate_block_preverified(&block, context, preverified)
                    .map_err(|error| {
                        NodeError::CorruptLog(format!(
                            "record {} fails preverified DFS replay: {error}",
                            record.ordinal
                        ))
                    })?,
                None if requires_external_preverification(&params) => {
                    return Err(NodeError::CorruptLog(format!(
                        "record {} is missing external proof evidence during DFS replay",
                        record.ordinal
                    )));
                }
                None => state.validate_block(&block, context).map_err(|error| {
                    NodeError::CorruptLog(format!(
                        "record {} fails full DFS replay: {error}",
                        record.ordinal
                    ))
                })?,
            };
            let undo = match reread.payload {
                ParsedRecordPayload::LegacyV1 => {
                    let canonical_delta =
                        validated.encode_reversible_state_delta().map_err(|error| {
                            NodeError::CorruptLog(format!(
                                "record {} cannot derive canonical legacy undo bytes: {error}",
                                record.ordinal
                            ))
                        })?;
                    legacy_undo_stack_bytes = legacy_undo_stack_bytes
                        .checked_add(canonical_delta.len())
                        .filter(|total| *total <= MAX_LEGACY_REPLAY_UNDO_STACK_BYTES)
                        .ok_or(NodeError::LegacyReplayResourceLimit {
                            record_index: record.ordinal,
                            maximum: MAX_LEGACY_REPLAY_UNDO_STACK_BYTES,
                        })?;
                    let capability =
                        validated
                            .reversible_state_delta_capability()
                            .map_err(|error| {
                                NodeError::CorruptLog(format!(
                                    "record {} cannot issue a legacy undo capability: {error}",
                                    record.ordinal
                                ))
                            })?;
                    ReplayUndo::LegacyV1 {
                        record_position,
                        canonical_delta: canonical_delta.into_boxed_slice(),
                        capability,
                    }
                }
                ParsedRecordPayload::V2 { delta_bytes, .. } => {
                    DecodedReversibleStateDelta::decode_bound(
                        &delta_bytes,
                        &params,
                        record.parent,
                        record.block_id,
                    )
                    .and_then(|decoded| decoded.promote_exact(&validated))
                    .map_err(|error| {
                        NodeError::CorruptLog(format!(
                            "record {} reversible state delta does not match full validation: {error}",
                            record.ordinal
                        ))
                    })?;
                    let capability =
                        validated
                            .reversible_state_delta_capability()
                            .map_err(|error| {
                                NodeError::CorruptLog(format!(
                                    "record {} cannot issue a V2 undo capability: {error}",
                                    record.ordinal
                                ))
                            })?;
                    ReplayUndo::V2 {
                        record_position,
                        capability,
                    }
                }
            };
            let parent_work = index.work_at(record.parent).ok_or_else(|| {
                NodeError::CorruptLog(format!(
                    "record {} DFS parent is absent from the fork index",
                    record.ordinal
                ))
            })?;
            let cumulative_work = add_chain_work(parent_work, record.target).map_err(|error| {
                NodeError::CorruptLog(format!(
                    "record {} cumulative work is invalid: {error}",
                    record.ordinal
                ))
            })?;
            let ancestors = index.ancestor_table(record.parent).map_err(|error| {
                NodeError::CorruptLog(format!(
                    "record {} ancestor table cannot be restored: {error}",
                    record.ordinal
                ))
            })?;
            state.commit_validated(validated).map_err(|error| {
                NodeError::CorruptLog(format!(
                    "record {} cannot commit DFS state: {error}",
                    record.ordinal
                ))
            })?;
            let successor_header = state.successor_header_preflight().map_err(|error| {
                NodeError::CorruptLog(format!(
                    "record {} cannot snapshot its successor header: {error}",
                    record.ordinal
                ))
            })?;
            let block_id = record.block_id;
            if index
                .blocks
                .insert(
                    block_id,
                    Arc::new(IndexedBlock {
                        locator: *record,
                        cumulative_work,
                        successor_header,
                        ancestors,
                    }),
                )
                .is_some()
            {
                return Err(NodeError::CorruptLog(format!(
                    "record {} duplicates an indexed block",
                    record.ordinal
                )));
            }
            if cumulative_work > winning_work
                || (cumulative_work == winning_work && record.ordinal < winning_record_index)
            {
                winning_tip = block_id;
                winning_work = cumulative_work;
                winning_record_index = record.ordinal;
            }
            stack.push(ReplayDfsFrame {
                block_id,
                next_child: 0,
                undo: Some(undo),
            });
            continue;
        }

        let finished = stack.pop().expect("the nonempty DFS stack has a frame");
        if let Some(undo) = finished.undo {
            let (record_position, capability, canonical_delta, legacy_bytes) = match undo {
                ReplayUndo::LegacyV1 {
                    record_position,
                    canonical_delta,
                    capability,
                } => {
                    let length = canonical_delta.len();
                    (record_position, capability, Some(canonical_delta), length)
                }
                ReplayUndo::V2 {
                    record_position,
                    capability,
                } => (record_position, capability, None, 0),
            };
            let record = scanned.records.get(record_position).ok_or_else(|| {
                NodeError::CorruptLog("startup undo locator is invalid".to_owned())
            })?;
            let reread = reread_replay_record(&replay_file, path, record, params.network_id)?;
            let delta_bytes = match (reread.payload, canonical_delta) {
                (ParsedRecordPayload::LegacyV1, Some(canonical_delta)) => canonical_delta,
                (ParsedRecordPayload::V2 { delta_bytes, .. }, None) => {
                    delta_bytes.into_boxed_slice()
                }
                _ => {
                    return Err(NodeError::CorruptLog(format!(
                        "record {} undo payload version changed",
                        record.ordinal
                    )));
                }
            };
            let validated_undo = DecodedReversibleStateDelta::decode_bound(
                &delta_bytes,
                &params,
                record.parent,
                record.block_id,
            )
            .and_then(|decoded| decoded.promote_capability(capability))
            .map_err(|error| {
                NodeError::CorruptLog(format!(
                    "record {} cannot recover its validation-bound undo delta: {error}",
                    record.ordinal
                ))
            })?;
            state
                .undo_reversible_state_delta(validated_undo)
                .map_err(|error| {
                    NodeError::CorruptLog(format!(
                        "record {} authenticated reversible state delta cannot restore its parent: {error}",
                        record.ordinal
                    ))
                })?;
            if state.tip() != record.parent {
                return Err(NodeError::CorruptLog(format!(
                    "record {} undo did not return to its parent",
                    record.ordinal
                )));
            }
            legacy_undo_stack_bytes = legacy_undo_stack_bytes
                .checked_sub(legacy_bytes)
                .ok_or_else(|| {
                    NodeError::CorruptLog("legacy V1 DFS undo budget underflowed".to_owned())
                })?;
        }
    }

    if legacy_undo_stack_bytes != 0 {
        return Err(NodeError::CorruptLog(
            "legacy V1 DFS undo budget did not return to zero".to_owned(),
        ));
    }

    if state.tip() != params.genesis_hash || index.blocks.len() != scanned.records.len() {
        return Err(NodeError::CorruptLog(
            "startup DFS did not return to genesis after visiting every record".to_owned(),
        ));
    }
    let mut active_chain = Vec::with_capacity(
        usize::try_from(
            index
                .blocks
                .get(&winning_tip)
                .map_or(0, |entry| entry.height()),
        )
        .unwrap_or(0)
        .saturating_add(1),
    );
    active_chain.push(index.genesis);
    active_chain.extend(index.path_to(winning_tip)?);
    index.active_chain = active_chain;
    index.active_work = winning_work;
    replay_indexed_state_to(
        log,
        path,
        state,
        index,
        params,
        winning_tip,
        external_preverifier,
    )?;

    verify_scanned_replay_log_unchanged(&replay_file, path, &scanned, params.network_id)?;
    verify_retained_block_log_path(log, path)?;
    Ok(ReplayLogState {
        last_record_digest: scanned.last_record_digest,
        log_length: scanned.log_length,
        record_count: u64::try_from(scanned.records.len())
            .map_err(|_| NodeError::CorruptLog("block record count exceeds u64".to_owned()))?,
    })
}

fn scan_replay_log(
    file: File,
    path: &Path,
    params: NetworkParams,
    network_id: [u8; 32],
) -> Result<ScannedReplayLog, NodeError> {
    let mut reader = BufReader::new(file);
    let mut record_index = 0_u64;
    let mut last_record_digest = EMPTY_RECORD_CHAIN_ROOT;
    let mut saw_v2 = false;
    let mut records = Vec::new();
    let mut children: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
    let mut known_blocks = HashSet::from([params.genesis_hash]);
    loop {
        let offset = reader
            .stream_position()
            .map_err(|source| io_error("locate block log record", path, source))?;
        let Some(record) = read_log_record(&mut reader, path, record_index)? else {
            let log_length = reader
                .stream_position()
                .map_err(|source| io_error("locate block log end", path, source))?;
            return Ok(ScannedReplayLog {
                records,
                children,
                last_record_digest,
                log_length,
            });
        };
        let end = reader
            .stream_position()
            .map_err(|source| io_error("locate block log record end", path, source))?;
        let length = end.checked_sub(offset).ok_or_else(|| {
            NodeError::CorruptLog(format!("record {record_index} has an invalid locator"))
        })?;
        match &record.payload {
            ParsedRecordPayload::LegacyV1 if saw_v2 => {
                return Err(NodeError::CorruptLog(format!(
                    "record {record_index} is legacy V1 after the V2 chain began"
                )));
            }
            ParsedRecordPayload::LegacyV1 if requires_external_preverification(&params) => {
                return Err(NodeError::ProductionLegacyBlockLog(record_index));
            }
            ParsedRecordPayload::LegacyV1 => {}
            ParsedRecordPayload::V2 {
                previous_record_digest,
                ..
            } => {
                if *previous_record_digest != last_record_digest {
                    return Err(NodeError::CorruptLog(format!(
                        "record {record_index} previous-record digest mismatch"
                    )));
                }
                saw_v2 = true;
            }
        }
        let ParsedLogRecord {
            accepted_at,
            block_bytes,
            payload,
            complete_digest,
        } = record;
        let block = decode_block(&block_bytes, network_id).map_err(|error| {
            NodeError::CorruptLog(format!("record {record_index} cannot decode: {error}"))
        })?;
        let reencoded = encode_block(&block).map_err(|error| {
            NodeError::CorruptLog(format!("record {record_index} cannot re-encode: {error}"))
        })?;
        if reencoded != block_bytes {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} is not canonical"
            )));
        }
        let block_id = block.block_id();
        let parent = block.challenge.previous_block;
        if !known_blocks.contains(&parent) {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} names a parent that was not accepted earlier"
            )));
        }
        if !known_blocks.insert(block_id) {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} duplicates an earlier block"
            )));
        }
        let version = match payload {
            ParsedRecordPayload::LegacyV1 => BlockRecordVersion::LegacyV1,
            ParsedRecordPayload::V2 { .. } => BlockRecordVersion::V2,
        };
        let position = records.len();
        children.entry(parent).or_default().push(position);
        records.push(BlockRecordLocator {
            ordinal: record_index,
            offset,
            length,
            version,
            complete_digest,
            accepted_at,
            block_id,
            parent,
            height: block.challenge.height,
            target: block.challenge.target,
        });
        last_record_digest = complete_digest;
        record_index = record_index
            .checked_add(1)
            .ok_or_else(|| NodeError::CorruptLog("block record count overflowed".to_owned()))?;
    }
}

fn reread_replay_record(
    file: &File,
    path: &Path,
    expected: &BlockRecordLocator,
    network_id: [u8; 32],
) -> Result<ParsedLogRecord, NodeError> {
    let (record, _) = read_located_record(file, path, expected, network_id, false).map_err(
        |error| match error {
            NodeError::CorruptLog(message) => NodeError::CorruptLog(format!(
                "record {} changed after its startup scan: {message}",
                expected.ordinal
            )),
            other => other,
        },
    )?;
    Ok(record)
}

fn verify_scanned_replay_log_unchanged(
    file: &File,
    path: &Path,
    scanned: &ScannedReplayLog,
    network_id: [u8; 32],
) -> Result<(), NodeError> {
    let mut last_record_digest = EMPTY_RECORD_CHAIN_ROOT;
    let mut saw_v2 = false;
    for expected in &scanned.records {
        let record = reread_replay_record(file, path, expected, network_id)?;
        match record.payload {
            ParsedRecordPayload::LegacyV1 if saw_v2 => {
                return Err(NodeError::CorruptLog(format!(
                    "record {} became legacy V1 after the V2 chain began",
                    expected.ordinal
                )));
            }
            ParsedRecordPayload::LegacyV1 => {}
            ParsedRecordPayload::V2 {
                previous_record_digest,
                ..
            } => {
                if previous_record_digest != last_record_digest {
                    return Err(NodeError::CorruptLog(format!(
                        "record {} previous-record digest changed after its startup scan",
                        expected.ordinal
                    )));
                }
                saw_v2 = true;
            }
        }
        last_record_digest = record.complete_digest;
    }
    if last_record_digest != scanned.last_record_digest
        || file
            .metadata()
            .map_err(|source| io_error("reinspect block log after bounded replay", path, source))?
            .len()
            != scanned.log_length
    {
        return Err(NodeError::CorruptLog(
            "block log changed during startup replay".to_owned(),
        ));
    }
    Ok(())
}

fn log_read_error(path: &Path, source: io::Error, truncated_message: String) -> NodeError {
    if source.kind() == io::ErrorKind::UnexpectedEof {
        NodeError::CorruptLog(truncated_message)
    } else {
        io_error("read block log", path, source)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    #[cfg(windows)]
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;

    use cmfd_consensus::{
        ForgeMatrixV2CompactProof, InputWitness, TEST_PROFILE, TRANSACTION_VERSION, TxInput,
        TxOutput, v2_test_reference,
    };

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("cmfd-node-{name}-{}-{id}", std::process::id()))
    }

    fn clean_test_dir(path: &Path) {
        if path.exists() {
            fs::remove_dir_all(path).expect("remove isolated test directory");
        }
    }

    fn set_indexed_locator(node: &mut Node, block_id: [u8; 32], locator: BlockRecordLocator) {
        Arc::get_mut(node.index.blocks.get_mut(&block_id).unwrap())
            .expect("test must not retain another indexed-block Arc")
            .locator = locator;
    }

    fn assert_forged_locator_rejected(
        node: &mut Node,
        block_id: [u8; 32],
        forge: impl FnOnce(&mut BlockRecordLocator),
    ) {
        let original = node.index.blocks[&block_id].locator;
        let mut forged = original;
        forge(&mut forged);
        set_indexed_locator(node, block_id, forged);
        assert!(matches!(
            node.canonical_block(block_id),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(node.storage_faulted);
        set_indexed_locator(node, block_id, original);
        assert!(node.canonical_block(block_id).unwrap().is_some());
    }

    #[cfg(windows)]
    fn create_directory_junction(target: &Path, junction: &Path) {
        let output = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(junction)
            .arg(target)
            .output()
            .expect("launch mklink for isolated junction fixture");
        assert!(
            output.status.success(),
            "mklink failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn split_complete_log_records(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        let mut offset = 0_usize;
        while offset < bytes.len() {
            assert!(bytes.len() - offset >= 8);
            assert_eq!(&bytes[offset..offset + 4], &RECORD_MAGIC);
            let version = u16::from_le_bytes(bytes[offset + 4..offset + 6].try_into().unwrap());
            let header_len = match version {
                RECORD_VERSION_V1 => RECORD_V1_HEADER_BYTES,
                RECORD_VERSION_V2 => RECORD_V2_HEADER_BYTES,
                _ => panic!("unsupported fixture record version {version}"),
            };
            assert!(bytes.len() - offset >= header_len);
            let block_len =
                u32::from_le_bytes(bytes[offset + 16..offset + 20].try_into().unwrap()) as usize;
            let delta_len = if version == RECORD_VERSION_V2 {
                u32::from_le_bytes(bytes[offset + 20..offset + 24].try_into().unwrap()) as usize
            } else {
                0
            };
            let record_len = checked_record_len(header_len, block_len, delta_len).unwrap();
            let end = offset.checked_add(record_len).unwrap();
            assert!(end <= bytes.len());
            records.push(bytes[offset..end].to_vec());
            offset = end;
        }
        records
    }

    fn read_complete_log_records(path: &Path) -> Vec<Vec<u8>> {
        split_complete_log_records(&fs::read(path.join(BLOCK_LOG_FILE)).unwrap())
    }

    fn write_complete_log_records(path: &Path, records: &[Vec<u8>]) {
        let total = records
            .iter()
            .try_fold(0_usize, |total, record| total.checked_add(record.len()))
            .unwrap();
        let mut bytes = Vec::with_capacity(total);
        for record in records {
            bytes.extend_from_slice(record);
        }
        fs::write(path.join(BLOCK_LOG_FILE), bytes).unwrap();
    }

    fn recompute_fixture_record_checksum(record: &mut [u8]) {
        let checksum_start = record.len() - RECORD_CHECKSUM_BYTES;
        let version = u16::from_le_bytes(record[4..6].try_into().unwrap());
        let checksum = match version {
            RECORD_VERSION_V1 => record_checksum_v1(&record[..checksum_start]),
            RECORD_VERSION_V2 => record_checksum_v2(&record[..checksum_start]),
            _ => panic!("unsupported fixture record version {version}"),
        };
        record[checksum_start..].copy_from_slice(&checksum);
    }

    fn v2_record_parts(record: &[u8]) -> (u64, [u8; 32], &[u8], &[u8]) {
        assert_eq!(
            u16::from_le_bytes(record[4..6].try_into().unwrap()),
            RECORD_VERSION_V2
        );
        let accepted_at = u64::from_le_bytes(record[8..16].try_into().unwrap());
        let block_len = u32::from_le_bytes(record[16..20].try_into().unwrap()) as usize;
        let delta_len = u32::from_le_bytes(record[20..24].try_into().unwrap()) as usize;
        let previous_record_digest = record[24..56].try_into().unwrap();
        let block_start = RECORD_V2_HEADER_BYTES;
        let delta_start = block_start + block_len;
        let delta_end = delta_start + delta_len;
        (
            accepted_at,
            previous_record_digest,
            &record[block_start..delta_start],
            &record[delta_start..delta_end],
        )
    }

    fn locally_forge_v2_delta(record: &[u8], delta_offset: usize) -> Vec<u8> {
        const DELTA_LOCAL_INTEGRITY_BYTES: usize = 32;
        const DELTA_LOCAL_INTEGRITY_DOMAIN: &str = "CMFD/REVERSIBLE-STATE-DELTA/LOCAL-INTEGRITY/V1";

        let (accepted_at, previous_record_digest, block_bytes, delta_bytes) =
            v2_record_parts(record);
        let mut forged_delta = delta_bytes.to_vec();
        assert!(forged_delta.len() > delta_offset + DELTA_LOCAL_INTEGRITY_BYTES);
        forged_delta[delta_offset] ^= 1;
        let payload_len = forged_delta.len() - DELTA_LOCAL_INTEGRITY_BYTES;
        let mut hasher = Hasher::new_derive_key(DELTA_LOCAL_INTEGRITY_DOMAIN);
        hasher.update(&forged_delta[..payload_len]);
        let digest = *hasher.finalize().as_bytes();
        forged_delta[payload_len..].copy_from_slice(&digest);
        encode_record_v2(
            accepted_at,
            block_bytes,
            &forged_delta,
            previous_record_digest,
        )
        .unwrap()
    }

    #[test]
    fn rpc_stop_wakes_idle_accept_and_finishes_an_accepted_request() {
        let path = test_dir("rpc-graceful-stop");
        clean_test_dir(&path);
        let shared = Arc::new(Mutex::new(Node::open(&path).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();

        // Hold the node lock so the queued request is observably active when
        // cancellation begins. Releasing it lets that bounded request finish.
        let node_guard = shared.lock().unwrap();
        let server = spawn_rpc_server_with_listener(Arc::clone(&shared), listener).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !server.active_request.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(server.active_request.load(Ordering::Acquire));
        let stop_state = Arc::clone(&server.stop);
        let (stopped_tx, stopped_rx) = mpsc::channel();
        let stopper = thread::spawn(move || stopped_tx.send(server.stop()).unwrap());
        let deadline = Instant::now() + Duration::from_secs(2);
        while !*stop_state.0.lock().unwrap() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(*stop_state.0.lock().unwrap());
        assert!(matches!(
            stopped_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        drop(node_guard);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        stopped_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        stopper.join().unwrap();
        drop(client);

        let rebound = TcpListener::bind(address).unwrap();
        drop(rebound);
        drop(shared);
        let replayed = Node::open(&path).unwrap();
        assert!(replayed.status().unwrap().storage_healthy);
        drop(replayed);
        clean_test_dir(&path);
    }

    #[test]
    fn proof_verification_queue_is_bounded_releases_capacity_and_contains_panics() {
        let queue = Arc::new(ProofVerificationQueue::new(1, 1, Duration::from_secs(2)));
        let active = queue.acquire().unwrap();
        let waiter_queue = Arc::clone(&queue);
        let waiter = thread::spawn(move || waiter_queue.acquire().map(drop));
        for _ in 0..10_000 {
            if queue.counts().unwrap() == (1, 1) {
                break;
            }
            thread::yield_now();
        }
        assert_eq!(queue.counts().unwrap(), (1, 1));
        assert!(matches!(
            queue.acquire(),
            Err(NodeError::ProofVerificationQueueFull)
        ));
        drop(active);
        waiter.join().unwrap().unwrap();
        assert_eq!(queue.counts().unwrap(), (0, 0));

        let timeout_queue = Arc::new(ProofVerificationQueue::new(1, 1, Duration::from_millis(1)));
        let active = timeout_queue.acquire().unwrap();
        assert!(matches!(
            timeout_queue.acquire(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        drop(active);
        assert_eq!(timeout_queue.counts().unwrap(), (0, 0));

        let fifo_queue = Arc::new(ProofVerificationQueue::new(1, 2, Duration::from_secs(2)));
        let active = fifo_queue.acquire().unwrap();
        let (order_tx, order_rx) = mpsc::channel();
        let first_queue = Arc::clone(&fifo_queue);
        let first_tx = order_tx.clone();
        let first = thread::spawn(move || {
            let permit = first_queue.acquire().unwrap();
            first_tx.send(1).unwrap();
            drop(permit);
        });
        while fifo_queue.counts().unwrap().1 != 1 {
            thread::yield_now();
        }
        let second_queue = Arc::clone(&fifo_queue);
        let second = thread::spawn(move || {
            let permit = second_queue.acquire().unwrap();
            order_tx.send(2).unwrap();
            drop(permit);
        });
        while fifo_queue.counts().unwrap().1 != 2 {
            thread::yield_now();
        }
        drop(active);
        assert_eq!(order_rx.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
        assert_eq!(order_rx.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(fifo_queue.counts().unwrap(), (0, 0));

        let verifier = BlockPreverifier::with_limits(
            ConsensusPowVerifier::v2_reference(v2_test_reference().unwrap()),
            1,
            0,
            Duration::from_secs(1),
        );
        assert!(matches!(
            verifier.run_guarded(|| -> Result<(), NodeError> { panic!("isolated verifier panic") }),
            Err(NodeError::ProofVerifierPanicked)
        ));
        assert_eq!(verifier.queue.counts().unwrap(), (0, 0));
    }

    #[test]
    fn priority_proof_waiters_overtake_normal_work_and_close_wakes_them() {
        let queue = Arc::new(ProofVerificationQueue::new(1, 2, Duration::from_secs(2)));
        let active = queue.acquire().unwrap();
        let (order_tx, order_rx) = mpsc::channel();

        let normal_queue = Arc::clone(&queue);
        let normal_tx = order_tx.clone();
        let normal = thread::spawn(move || {
            let permit = normal_queue.acquire().unwrap();
            normal_tx.send("normal").unwrap();
            drop(permit);
        });
        while queue.counts().unwrap().1 != 1 {
            thread::yield_now();
        }

        let priority_queue = Arc::clone(&queue);
        let priority = thread::spawn(move || {
            let permit = priority_queue.acquire_priority().unwrap();
            order_tx.send("priority").unwrap();
            drop(permit);
        });
        while queue.counts().unwrap().1 != 2 {
            thread::yield_now();
        }
        thread::sleep(Duration::from_millis(10));
        assert!(matches!(
            order_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(active);
        assert_eq!(
            order_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "priority"
        );
        assert_eq!(
            order_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "normal"
        );
        priority.join().unwrap();
        normal.join().unwrap();

        let close_queue = Arc::new(ProofVerificationQueue::new(1, 1, Duration::from_millis(1)));
        let active = close_queue.acquire().unwrap();
        let waiting_queue = Arc::clone(&close_queue);
        let waiter = thread::spawn(move || waiting_queue.acquire_priority().map(drop));
        while close_queue.counts().unwrap().1 != 1 {
            thread::yield_now();
        }
        thread::sleep(Duration::from_millis(10));
        assert_eq!(close_queue.counts().unwrap(), (1, 1));
        close_queue.close();
        assert!(matches!(
            waiter.join().unwrap(),
            Err(NodeError::ProofVerifierShuttingDown)
        ));
        drop(active);
    }

    #[test]
    fn proof_capability_cache_is_exact_generation_bound_bounded_and_fail_closed() {
        let path = test_dir("proof-capability-cache");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let block = mined_candidate(&node, DEVNET_GENESIS_TIMESTAMP + 60);
        let key = canonical_block_cache_digest(&block).unwrap();
        let verifier = node.block_preverifier.clone();
        let capability = verifier.preverify(&block).unwrap();
        let generation = verifier.backend_generation.load(Ordering::Acquire);

        verifier
            .remember_preverification(key, generation, capability.clone())
            .unwrap();
        assert_eq!(
            verifier.cached_preverification(key).unwrap(),
            Some(capability.clone())
        );
        let mut changed_proof = block.clone();
        let BlockProof::V2Reference(proof) = &mut changed_proof.proof else {
            unreachable!();
        };
        proof.work_digest[0] ^= 1;
        assert_ne!(canonical_block_cache_digest(&changed_proof).unwrap(), key);

        // Model the queue-linearized portion of a backend replacement. An
        // old in-flight verification cannot repopulate the new generation.
        let queue_state = verifier.queue.state.lock().unwrap();
        *verifier.backend.write().unwrap() = ProofVerificationBackend::InProcess;
        verifier.backend_generation.fetch_add(1, Ordering::AcqRel);
        let mut cache = verifier.successful_proofs.lock().unwrap();
        cache.entries.clear();
        cache.order.clear();
        drop(cache);
        drop(queue_state);
        verifier
            .remember_preverification(key, generation, capability.clone())
            .unwrap();
        assert_eq!(verifier.cached_preverification(key).unwrap(), None);

        let current_generation = verifier.backend_generation.load(Ordering::Acquire);
        for value in 0..=MAX_SUCCESSFUL_PROOF_CAPABILITIES {
            let mut cache_key = [0_u8; 32];
            cache_key[..8].copy_from_slice(&(value as u64).to_le_bytes());
            verifier
                .remember_preverification(cache_key, current_generation, capability.clone())
                .unwrap();
        }
        let first = [0_u8; 32];
        assert_eq!(verifier.cached_preverification(first).unwrap(), None);
        assert_eq!(
            verifier.successful_proofs.lock().unwrap().entries.len(),
            MAX_SUCCESSFUL_PROOF_CAPABILITIES
        );

        verifier.shutdown();
        assert!(matches!(
            verifier.cached_preverification(key),
            Err(NodeError::ProofVerifierShuttingDown)
        ));
        assert!(matches!(
            verifier.remember_preverification(key, current_generation, capability),
            Err(NodeError::ProofVerifierShuttingDown)
        ));
        assert!(
            verifier
                .successful_proofs
                .lock()
                .unwrap()
                .entries
                .is_empty()
        );
        let replacement = VerifierWorkerConfig {
            worker_executable: PathBuf::from("not-started-after-close"),
            worker_sha256: [0; 32],
            startup_timeout: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            memory_limit_bytes: 1,
            cpu_quota_micros: None,
            cpu_period_micros: None,
            pids_limit: None,
            production_v3_artifacts: None,
        };
        assert!(matches!(
            verifier.use_external_worker(replacement, node.params.network_id),
            Err(VerifierWorkerError::Closed)
        ));
        assert_eq!(verifier.backend_status().unwrap().0, "stopped");
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn shared_submission_queues_before_snapshot_and_never_holds_node_mutex() {
        let path = test_dir("shared-submission-order");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let candidate = mined_child(&node, genesis, accepted_at, 0x71);
        let competing = mined_child(&node, genesis, accepted_at, 0x72);
        let competing_cap = node.block_preverifier.preverify(&competing).unwrap();
        node.profile.proof = ProofProfile::ProductionV3;
        let queue = Arc::clone(&node.block_preverifier.queue);
        let held_permit = queue.acquire().unwrap();
        let shared = Arc::new(Mutex::new(node));

        let submit_node = Arc::clone(&shared);
        let submitter =
            thread::spawn(move || submit_shared_block(&submit_node, candidate, accepted_at));
        let deadline = Instant::now() + Duration::from_secs(2);
        while queue.counts().unwrap() != (1, 1) && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(queue.counts().unwrap(), (1, 1));

        // The waiter has cloned its verifier but cannot capture a revision
        // until it owns the sole proof permit. The node mutex remains usable.
        {
            let mut node = shared.try_lock().expect("proof waiter held node mutex");
            node.profile.proof = ProofProfile::DevnetV2Reference;
            node.submit_preverified_block(competing.clone(), accepted_at, competing_cap)
                .unwrap();
            node.profile.proof = ProofProfile::ProductionV3;
        }
        drop(held_permit);

        submitter.join().unwrap().unwrap();
        let node = shared.lock().unwrap();
        assert!(node.index.contains(competing.block_id()));
        assert_eq!(node.index.blocks.len(), 2);
        drop(node);

        let second_at = accepted_at + 60;
        let (tip_candidate, tip_candidate_id, competing_tip, competing_tip_cap) = {
            let node = shared.lock().unwrap();
            let parent = node.state.tip();
            let tip_candidate = mined_child(&node, parent, second_at, 0x73);
            let competing_tip = mined_child(&node, parent, second_at, 0x74);
            let competing_tip_cap = node.block_preverifier.preverify(&competing_tip).unwrap();
            (
                tip_candidate.clone(),
                tip_candidate.block_id(),
                competing_tip,
                competing_tip_cap,
            )
        };
        let held_permit = queue.acquire().unwrap();
        let submit_node = Arc::clone(&shared);
        let tip_submitter =
            thread::spawn(move || submit_shared_tip_block(&submit_node, tip_candidate, second_at));
        let deadline = Instant::now() + Duration::from_secs(2);
        while queue.counts().unwrap() != (1, 1) && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(queue.counts().unwrap(), (1, 1));
        {
            let mut node = shared.lock().unwrap();
            node.profile.proof = ProofProfile::DevnetV2Reference;
            node.submit_preverified_block(competing_tip.clone(), second_at, competing_tip_cap)
                .unwrap();
            node.profile.proof = ProofProfile::ProductionV3;
        }
        drop(held_permit);
        assert!(matches!(
            tip_submitter.join().unwrap(),
            Err(NodeError::StaleBlockAdmission)
        ));
        let node = shared.lock().unwrap();
        assert!(node.index.contains(competing_tip.block_id()));
        assert!(!node.index.contains(tip_candidate_id));
        drop(node);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn production_preverifier_clones_share_a_fail_closed_backend() {
        let verifier = BlockPreverifier::new(
            ConsensusPowVerifier::v2_reference(v2_test_reference().unwrap()),
            ProofProfile::ProductionV3,
        );
        let clone_created_before_worker_install = verifier.clone();
        assert_eq!(
            verifier.backend_status().unwrap().0,
            "unavailable",
            "ProductionV3 must not expose an in-process fallback"
        );

        *verifier.backend.write().unwrap() = ProofVerificationBackend::InProcess;
        assert_eq!(
            clone_created_before_worker_install
                .backend_status()
                .unwrap()
                .0,
            "in_process",
            "pre-install clones must observe the atomically installed backend"
        );
    }

    #[test]
    fn production_submission_preflights_parent_and_state_before_worker_dispatch() {
        let path = test_dir("production-preflight-order");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let now = DEVNET_GENESIS_TIMESTAMP + 60;
        let valid = mined_candidate(&node, now);

        node.profile.proof = ProofProfile::ProductionV3;
        assert_eq!(
            node.block_preverifier.backend_status().unwrap().0,
            "in_process"
        );
        *node.block_preverifier.backend.write().unwrap() = ProofVerificationBackend::Unavailable;
        let shared = Arc::new(Mutex::new(node));

        let mut wrong_target = valid.clone();
        wrong_target.challenge.target[0] ^= 1;
        assert!(matches!(
            submit_shared_block(&shared, wrong_target, now),
            Err(NodeError::Chain(ChainError::UnexpectedTarget))
        ));

        let mut orphan = valid.clone();
        orphan.challenge.previous_block = [0xA5; 32];
        assert!(matches!(
            submit_shared_block(&shared, orphan, now),
            Err(NodeError::UnknownParent(parent)) if parent == [0xA5; 32]
        ));
        assert!(matches!(
            submit_shared_block(&shared, valid, now),
            Err(NodeError::ProductionV3Unavailable)
        ));
        let node = shared.lock().unwrap();
        assert_eq!(node.state.next_height(), 1);
        assert_eq!(node.log.metadata().unwrap().len(), 0);
        drop(node);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn production_side_admission_is_external_revision_bound_and_fail_closed() {
        let path = test_dir("production-side-admission");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
        let t2 = t1 + 60;
        let t3 = t2 + 60;

        let a1 = mined_child(&node, genesis, t1, 0x31);
        let a1_cap = node.block_preverifier.preverify(&a1).unwrap();
        node.submit_preverified_block(a1.clone(), t1, a1_cap)
            .unwrap();
        let a2 = mined_child(&node, a1.block_id(), t2, 0x32);
        let a2_cap = node.block_preverifier.preverify(&a2).unwrap();
        node.submit_preverified_block(a2.clone(), t2, a2_cap)
            .unwrap();
        let b1 = mined_child(&node, genesis, t1, 0x41);
        let b1_cap = node.block_preverifier.preverify(&b1).unwrap();
        node.submit_preverified_block(b1.clone(), t1, b1_cap)
            .unwrap();
        let b2 = mined_child(&node, b1.block_id(), t2, 0x42);
        let b2_cap = node.block_preverifier.preverify(&b2).unwrap();
        let a3 = mined_child(&node, a2.block_id(), t3, 0x33);
        let a3_cap = node.block_preverifier.preverify(&a3).unwrap();

        node.profile.proof = ProofProfile::ProductionV3;
        let saved_backend = {
            let mut backend = node.block_preverifier.backend.write().unwrap();
            std::mem::replace(&mut *backend, ProofVerificationBackend::Unavailable)
        };
        assert!(matches!(
            node.begin_external_block_admission(&b2, t2)
                .unwrap()
                .unwrap()
                .complete(&b2),
            Err(NodeError::ProductionV3Unavailable)
        ));
        *node.block_preverifier.backend.write().unwrap() = saved_backend;

        let mut wrong_side_target = b2.clone();
        wrong_side_target.challenge.target[0] ^= 1;
        assert!(matches!(
            node.begin_external_block_admission(&wrong_side_target, t2),
            Err(NodeError::Chain(ChainError::UnexpectedTarget))
        ));
        let admission = node
            .begin_external_block_admission(&b2, t2)
            .unwrap()
            .unwrap()
            .complete(&b2)
            .unwrap()
            .into_ready();

        // A successful concurrent block changes the revision after all
        // expensive side reconstruction has completed. The old admission can
        // never commit against the new authoritative chain/index state.
        node.profile.proof = ProofProfile::DevnetV2Reference;
        node.submit_preverified_block(a3, t3, a3_cap).unwrap();
        node.profile.proof = ProofProfile::ProductionV3;
        assert!(matches!(
            node.submit_preverified_block_with_admission(b2.clone(), t2, b2_cap.clone(), admission),
            Err(NodeError::StaleBlockAdmission)
        ));

        let fresh = node
            .begin_external_block_admission(&b2, t2)
            .unwrap()
            .unwrap()
            .complete(&b2)
            .unwrap()
            .into_ready();
        node.submit_preverified_block_with_admission(b2.clone(), t2, b2_cap, fresh)
            .unwrap();
        assert!(node.index.contains(b2.block_id()));
        assert_eq!(
            node.index.blocks[&b2.block_id()].locator.block_id,
            b2.block_id()
        );
        assert_eq!(
            node.index.blocks[&b2.block_id()].ancestors.first(),
            Some(&b1.block_id())
        );

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn production_side_snapshot_rejects_a_corrupt_record_locator() {
        let path = test_dir("production-side-corrupt-locator");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
        let t2 = t1 + 60;

        let active = mined_child(&node, genesis, t1, 0x51);
        node.submit_block(active, t1).unwrap();
        let side = mined_child(&node, genesis, t1, 0x61);
        let side_cap = node.block_preverifier.preverify(&side).unwrap();
        node.submit_preverified_block(side.clone(), t1, side_cap)
            .unwrap();
        let child = mined_child(&node, side.block_id(), t2, 0x62);

        let original_locator = node.index.blocks[&side.block_id()].locator;
        Arc::get_mut(node.index.blocks.get_mut(&side.block_id()).unwrap())
            .unwrap()
            .locator
            .complete_digest[0] ^= 1;
        node.profile.proof = ProofProfile::ProductionV3;
        assert!(matches!(
            node.begin_external_block_admission(&child, t2),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(node.storage_faulted);
        Arc::get_mut(node.index.blocks.get_mut(&side.block_id()).unwrap())
            .unwrap()
            .locator = original_locator;
        drop(node);

        let mut invalid_proof = child;
        let BlockProof::V2Reference(proof) = &mut invalid_proof.proof else {
            unreachable!();
        };
        proof.work_digest[0] ^= 1;
        let mut node = Node::open(&path).unwrap();
        node.profile.proof = ProofProfile::ProductionV3;
        let shared = Arc::new(Mutex::new(node));
        let error = submit_shared_block(&shared, invalid_proof, t2).unwrap_err();
        assert_eq!(
            error.client_error().code,
            "proof_rejected",
            "an invalid proof must fail before durable branch replay"
        );

        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn production_side_completion_corruption_latches_storage_and_blocks_append() {
        let path = test_dir("production-side-completion-corruption");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
        let t2 = t1 + 60;

        let active = mined_child(&node, genesis, t1, 0x71);
        node.submit_block(active, t1).unwrap();
        let side = mined_child(&node, genesis, t1, 0x72);
        let side_cap = node.block_preverifier.preverify(&side).unwrap();
        node.submit_preverified_block(side.clone(), t1, side_cap)
            .unwrap();
        let child = mined_child(&node, side.block_id(), t2, 0x73);

        // Preserve every field used by cheap successor preflight while making
        // the retained index snapshot unequal to the freshly replayed state.
        let mut alternate_params = node.params;
        alternate_params.max_future_offset_secs -= 1;
        let mut alternate_state = ChainState::new(alternate_params, node.verifier.clone()).unwrap();
        let alternate_validated = alternate_state
            .validate_block(
                &side,
                BlockValidationContext {
                    now_unix_seconds: t1,
                },
            )
            .unwrap();
        alternate_state
            .commit_validated(alternate_validated)
            .unwrap();
        let forged_header = alternate_state.successor_header_preflight().unwrap();
        assert!(
            forged_header
                .preflight_block(
                    &child,
                    BlockValidationContext {
                        now_unix_seconds: t2
                    }
                )
                .is_ok()
        );
        let side_entry =
            Arc::get_mut(node.index.blocks.get_mut(&side.block_id()).unwrap()).unwrap();
        assert_ne!(side_entry.successor_header, forged_header);
        side_entry.successor_header = forged_header;

        let original_tip = node.state.tip();
        let original_revision = node.chain_revision;
        let original_log_length = node.log.metadata().unwrap().len();
        node.profile.proof = ProofProfile::ProductionV3;
        let shared = Arc::new(Mutex::new(node));
        assert!(matches!(
            submit_shared_block(&shared, child.clone(), t2),
            Err(NodeError::CorruptLog(message))
                if message.contains("header snapshot does not match replayed state")
        ));

        let mut node = shared.lock().unwrap();
        assert!(node.storage_faulted);
        assert_eq!(node.state.tip(), original_tip);
        assert_eq!(node.chain_revision, original_revision);
        assert_eq!(node.log.metadata().unwrap().len(), original_log_length);
        node.profile.proof = ProofProfile::DevnetV2Reference;
        assert!(matches!(
            node.submit_block(child, t2),
            Err(NodeError::StorageFaulted)
        ));

        drop(node);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn completion_fault_latch_is_instance_revision_and_error_bound() {
        let first_path = test_dir("completion-latch-first");
        let replacement_path = test_dir("completion-latch-replacement");
        clean_test_dir(&first_path);
        clean_test_dir(&replacement_path);
        let mut first = Node::open(&first_path).unwrap();
        let original_instance = first.instance_id;
        let stale_revision = first.chain_revision;
        first
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let corruption = NodeError::CorruptLog("captured replay corruption".to_owned());
        first.latch_external_completion_failure(original_instance, stale_revision, &corruption);
        assert!(!first.storage_faulted, "a stale completion cannot poison");

        let mut replacement = Node::open(&replacement_path).unwrap();
        replacement.latch_external_completion_failure(
            original_instance,
            replacement.chain_revision,
            &corruption,
        );
        assert!(
            !replacement.storage_faulted,
            "another node instance cannot be poisoned"
        );
        replacement.latch_external_completion_failure(
            replacement.instance_id,
            replacement.chain_revision,
            &NodeError::UnknownParent([0x5a; 32]),
        );
        assert!(
            !replacement.storage_faulted,
            "ordinary client failures are not storage faults"
        );

        drop(first);
        drop(replacement);
        clean_test_dir(&first_path);
        clean_test_dir(&replacement_path);
    }

    fn mined_candidate(node: &Node, now: u64) -> Block {
        let template = node
            .build_template(default_miner_destination(), now)
            .unwrap();
        let proof = node
            .verifier
            .mine(&template.challenge, 0, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        Block {
            version: BLOCK_VERSION,
            challenge: template.challenge,
            proof,
            coinbase: template.coinbase,
            transactions: Vec::new(),
        }
    }

    fn mined_child(node: &Node, parent: [u8; 32], timestamp: u64, miner_seed: u8) -> Block {
        mined_child_with_transactions(node, parent, timestamp, miner_seed, Vec::new())
    }

    fn mined_child_with_transactions(
        node: &Node,
        parent: [u8; 32],
        timestamp: u64,
        miner_seed: u8,
        transactions: Vec<Transaction>,
    ) -> Block {
        let log_path = node.data_dir.join(BLOCK_LOG_FILE);
        let state = rebuild_state_to(
            &node.log,
            &log_path,
            &node.index,
            node.params,
            &node.verifier,
            parent,
            None,
        )
        .unwrap();
        let height = state.next_height();
        let destination = insecure_dev_destination(miner_seed);
        let fees = state
            .validate_transactions_for_next_block(&transactions)
            .unwrap()
            .total_burned_fees;
        let allocation = node
            .params
            .monetary_policy
            .allocation(height, fees)
            .unwrap();
        let coinbase = Coinbase::new(height, allocation, destination, node.params.rewards);
        let mut commitments = vec![coinbase.commitment(node.params.network_id)];
        commitments.extend(transactions.iter().map(Transaction::txid));
        let challenge = BlockChallenge {
            network_id: node.params.network_id,
            previous_block: parent,
            transaction_root: merkle_root(&commitments),
            height,
            timestamp,
            target: state.expected_target().unwrap(),
        };
        let proof = node
            .verifier
            .mine(&challenge, 0, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        Block {
            version: BLOCK_VERSION,
            challenge,
            proof,
            coinbase,
            transactions,
        }
    }

    fn spend_coinbase_output(
        node: &Node,
        block: &Block,
        output_index: u32,
        owner_secret: u8,
        recipient_secret: u8,
        fee: u64,
    ) -> Transaction {
        spend_coinbase_to(
            node,
            block,
            output_index,
            owner_secret,
            insecure_dev_destination(recipient_secret),
            fee,
        )
    }

    fn spend_coinbase_to(
        node: &Node,
        block: &Block,
        output_index: u32,
        owner_secret: u8,
        recipient: [u8; 32],
        fee: u64,
    ) -> Transaction {
        let previous_output = &block.coinbase.outputs[output_index as usize];
        let owner = SigningKey::from_bytes(&[owner_secret; 32]).unwrap();
        let mut transaction = Transaction {
            network_id: node.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: OutPoint {
                    txid: block.coinbase_outpoint_id(),
                    index: output_index,
                },
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: Vec::new(),
                },
            }],
            outputs: vec![TxOutput {
                value: previous_output.value.checked_sub(fee).unwrap(),
                lock: OutputLock::Key(recipient),
                spendable_height: node.state.next_height(),
            }],
        };
        transaction.sign_all(&[&owner]).unwrap();
        transaction
    }

    #[test]
    fn mempool_policy_rejects_zero_fee_unconfirmed_duplicate_and_conflicting_spends_atomically() {
        let path = test_dir("mempool-policy");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let now = DEVNET_GENESIS_TIMESTAMP + 60;
        let funding = node
            .mine_once(default_miner_destination(), now, DEFAULT_MINING_ATTEMPTS)
            .unwrap();

        let zero_fee = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 0);
        assert!(matches!(
            node.submit_transaction(zero_fee),
            Err(NodeError::MempoolFeeTooLow {
                required: 1,
                actual: 0
            })
        ));
        assert!(node.mempool.is_empty());

        let transaction = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 10);
        let recipient = SigningKey::from_bytes(&[0x31; 32]).unwrap();
        let mut unconfirmed_child = Transaction {
            network_id: node.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: OutPoint {
                    txid: transaction.txid(),
                    index: 0,
                },
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: Vec::new(),
                },
            }],
            outputs: vec![TxOutput {
                value: transaction.outputs[0].value - 1,
                lock: OutputLock::Key(insecure_dev_destination(0x32)),
                spendable_height: node.state.next_height(),
            }],
        };
        unconfirmed_child.sign_all(&[&recipient]).unwrap();
        let missing = unconfirmed_child.inputs[0].previous;
        assert!(matches!(
            node.submit_transaction(unconfirmed_child),
            Err(NodeError::MempoolUnconfirmedInput(outpoint)) if outpoint == missing
        ));

        let entry = node.submit_transaction(transaction.clone()).unwrap();
        let original_bytes = node.mempool_bytes;
        assert_eq!(entry.fee_burned, 10);
        assert!(matches!(
            node.submit_transaction(transaction.clone()),
            Err(NodeError::DuplicateMempoolTransaction(txid)) if txid == transaction.txid()
        ));

        let conflict = spend_coinbase_output(&node, &funding, 2, 0x12, 0x33, 11);
        let previous = conflict.inputs[0].previous;
        assert!(matches!(
            node.submit_transaction(conflict),
            Err(NodeError::MempoolInputConflict(outpoint)) if outpoint == previous
        ));
        assert_eq!(node.mempool.len(), 1);
        assert_eq!(node.mempool_bytes, original_bytes);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn mempool_fee_policy_rounds_canonical_bytes_up_to_the_next_kib() {
        let path = test_dir("mempool-fee-size");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let funding = node
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let mut transaction = spend_coinbase_output(&node, &funding, 2, 0x12, 0x34, 1);
        let total = transaction.outputs[0].value;
        transaction.outputs = (0_u8..64)
            .map(|index| TxOutput {
                value: if index == 0 { total - 63 } else { 1 },
                lock: OutputLock::Key(insecure_dev_destination(0x40 + index)),
                spendable_height: node.state.next_height(),
            })
            .collect();
        let owner = SigningKey::from_bytes(&[0x12; 32]).unwrap();
        transaction.sign_all(&[&owner]).unwrap();
        let encoded_bytes = encode_transaction(&transaction).unwrap().len();
        let required = u64::try_from(encoded_bytes.div_ceil(1024)).unwrap();
        assert!(required > 1);
        assert!(matches!(
            node.submit_transaction(transaction),
            Err(NodeError::MempoolFeeTooLow {
                required: actual_required,
                actual: 1
            }) if actual_required == required
        ));
        assert!(node.mempool.is_empty());
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn complete_ordered_pool_validation_is_atomic() {
        let path = test_dir("mempool-aggregate-atomic");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let funding = node
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let channel_id = [0x5a; 32];
        let mut first = spend_coinbase_output(&node, &funding, 1, 0x11, 0x35, 1);
        first.outputs[0].lock = OutputLock::InferenceChannel { channel_id };
        first
            .sign_all(&[&SigningKey::from_bytes(&[0x11; 32]).unwrap()])
            .unwrap();
        let mut second = spend_coinbase_output(&node, &funding, 2, 0x12, 0x36, 1);
        second.outputs[0].lock = OutputLock::InferenceChannel { channel_id };
        second
            .sign_all(&[&SigningKey::from_bytes(&[0x12; 32]).unwrap()])
            .unwrap();

        node.submit_transaction(first.clone()).unwrap();
        let bytes_before = node.mempool_bytes;
        assert!(matches!(
            node.submit_transaction(second),
            Err(NodeError::Chain(ChainError::DuplicateChannel))
        ));
        assert_eq!(node.mempool.len(), 1);
        assert!(node.mempool.contains_key(&first.txid()));
        assert_eq!(node.mempool_bytes, bytes_before);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn mempool_count_and_byte_caps_reject_without_mutation() {
        let path = test_dir("mempool-caps");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let funding = node
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let transaction = spend_coinbase_output(&node, &funding, 2, 0x12, 0x37, 1);
        let encoded_bytes = encode_transaction(&transaction).unwrap().len();
        for index in 0..MAX_MEMPOOL_TRANSACTIONS {
            let mut txid = [0_u8; 32];
            txid[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert_ne!(txid, transaction.txid());
            node.mempool.insert(
                txid,
                MempoolEntry {
                    txid,
                    transaction: transaction.clone(),
                    encoded_bytes,
                    fee_burned: 1,
                },
            );
        }
        assert!(matches!(
            node.submit_transaction(transaction.clone()),
            Err(NodeError::MempoolTransactionLimit)
        ));
        assert_eq!(node.mempool.len(), MAX_MEMPOOL_TRANSACTIONS);

        node.mempool.clear();
        node.mempool_bytes = MAX_MEMPOOL_BYTES;
        assert!(matches!(
            node.submit_transaction(transaction),
            Err(NodeError::MempoolByteLimit)
        ));
        assert!(node.mempool.is_empty());
        assert_eq!(node.mempool_bytes, MAX_MEMPOOL_BYTES);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn template_orders_transactions_burns_fees_and_mining_clears_confirmed_entries() {
        let path = test_dir("mempool-template");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let now = DEVNET_GENESIS_TIMESTAMP + 60;
        let funding = node
            .mine_once(default_miner_destination(), now, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let first = spend_coinbase_output(&node, &funding, 1, 0x11, 0x38, 1_000);
        let second = spend_coinbase_output(&node, &funding, 2, 0x12, 0x39, 2_000);
        if first.txid() < second.txid() {
            node.submit_transaction(second.clone()).unwrap();
            node.submit_transaction(first.clone()).unwrap();
        } else {
            node.submit_transaction(first.clone()).unwrap();
            node.submit_transaction(second.clone()).unwrap();
        }

        let template = node
            .build_template(default_miner_destination(), now + 60)
            .unwrap();
        let mut expected = vec![first, second];
        expected.sort_by_key(Transaction::txid);
        assert_eq!(template.transactions, expected);
        assert_eq!(template.total_fees_burned, 3_000);
        let allocation = node
            .params
            .monetary_policy
            .allocation(node.state.next_height(), 3_000)
            .unwrap();
        assert_eq!(
            template.coinbase,
            Coinbase::new(
                node.state.next_height(),
                allocation,
                default_miner_destination(),
                node.params.rewards,
            )
        );
        let mut commitments = vec![template.coinbase.commitment(node.params.network_id)];
        commitments.extend(expected.iter().map(Transaction::txid));
        assert_eq!(
            template.challenge.transaction_root,
            merkle_root(&commitments)
        );

        let block = node
            .mine_once(
                default_miner_destination(),
                now + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        assert_eq!(block.transactions, expected);
        let status = node.status().unwrap();
        assert_eq!(status.mempool_transactions, 0);
        assert_eq!(status.mempool_bytes, 0);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn side_branch_leaves_mempool_untouched_but_activating_reorg_evicts_conflict() {
        let path = test_dir("mempool-reorg");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
        let t2 = t1 + 60;
        let t3 = t2 + 60;
        let common = mined_child(&node, genesis, t1, 0x70);
        node.submit_block(common.clone(), t1).unwrap();
        let active = mined_child(&node, common.block_id(), t2, 0x71);
        node.submit_block(active.clone(), t2).unwrap();

        let pooled = spend_coinbase_output(&node, &common, 2, 0x12, 0x72, 10);
        node.submit_transaction(pooled.clone()).unwrap();
        let pool_bytes = node.mempool_bytes;
        let conflicting = spend_coinbase_output(&node, &common, 2, 0x12, 0x73, 11);
        let side =
            mined_child_with_transactions(&node, common.block_id(), t2, 0x74, vec![conflicting]);
        node.submit_block(side.clone(), t2).unwrap();
        assert_eq!(node.state.tip(), active.block_id());
        assert_eq!(node.mempool.len(), 1);
        assert!(node.mempool.contains_key(&pooled.txid()));
        assert_eq!(node.mempool_bytes, pool_bytes);

        let heavier = mined_child(&node, side.block_id(), t3, 0x75);
        node.submit_block(heavier.clone(), t3).unwrap();
        assert_eq!(node.state.tip(), heavier.block_id());
        assert!(node.mempool.is_empty());
        assert_eq!(node.mempool_bytes, 0);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn devnet_params_bind_the_exact_v2_verifier() {
        let params = devnet_params().unwrap();
        assert_eq!(params.network_id, DEVNET_NETWORK_ID);
        assert!(matches!(params.pow, PowParameters::V2Reference(_)));

        let reference = v2_test_reference().unwrap();
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        assert_eq!(verifier.parameters(), params.pow);
        assert!(ChainState::new(params, verifier).is_ok());

        let legacy = ConsensusPowVerifier::v1_legacy(TEST_PROFILE).unwrap();
        assert!(matches!(
            ChainState::new(params, legacy),
            Err(ChainError::PowParameterMismatch)
        ));
    }

    #[test]
    fn devnet_fingerprint_commits_transaction_merkle_v2_rules() {
        assert_eq!(
            hex::encode(devnet_params().unwrap().fingerprint().unwrap()),
            "bbbadca69495910a1e6b73fe95db17d5b8b9b056361ce1c9dca9dc183114eddf"
        );
    }

    #[test]
    fn compile_time_profile_preserves_defaults_and_separates_fresh_networks() {
        assert_eq!(DEVNET_NETWORK_ID, DEVNET_PROFILE.network_id);
        assert_eq!(DEVNET_GENESIS_HASH, DEVNET_PROFILE.virtual_genesis_hash);
        assert_eq!(
            DEVNET_GENESIS_TIMESTAMP,
            DEVNET_PROFILE.virtual_genesis_timestamp
        );
        assert_eq!(DEFAULT_DATA_DIR, DEVNET_PROFILE.default_data_dir_identity);
        assert_eq!(DEFAULT_RPC_ADDRESS, DEVNET_PROFILE.rpc_address());
        assert_eq!(DEFAULT_P2P_ADDRESS, DEVNET_PROFILE.p2p_address());
        assert_eq!(pool::DEFAULT_POOL_ADDRESS, DEVNET_PROFILE.pool_address());

        const ALTERNATE_PROFILE: NetworkProfile = NetworkProfile {
            proof: ProofProfile::DevnetV2Reference,
            name: "CommonFoundry profile-separation test",
            network_id: [0x64; 32],
            virtual_genesis_hash: [0x48; 32],
            virtual_genesis_timestamp: DEVNET_GENESIS_TIMESTAMP + 1,
            pow_limit: DEVNET_PROFILE.pow_limit,
            rewards: DEVNET_PROFILE.rewards,
            rpc_port: 28_443,
            p2p_port: 28_444,
            pool_port: 28_445,
            bootstrap_ipv4: std::net::Ipv4Addr::new(192, 0, 2, 1),
            default_data_dir_identity: "commonfoundry-profile-separation-test",
            wallet_data_dir_identity: "profile-separation-test",
        };

        let current = devnet_params().unwrap();
        let alternate = network_params_for_profile(ALTERNATE_PROFILE).unwrap();
        assert_ne!(
            alternate.fingerprint().unwrap(),
            current.fingerprint().unwrap()
        );

        let current_reference = v2_test_reference().unwrap();
        let alternate_reference = v2_reference_for_network(ALTERNATE_PROFILE.network_id).unwrap();
        assert_ne!(
            alternate_reference.descriptor(),
            current_reference.descriptor()
        );
        assert!(matches!(
            ChainState::new(
                alternate,
                ConsensusPowVerifier::v2_reference(current_reference)
            ),
            Err(ChainError::PowParameterMismatch)
        ));
    }

    #[test]
    fn rcnet_profile_fails_closed_without_touching_storage() {
        let path = test_dir("rcnet-production-v3-gate");
        clean_test_dir(&path);

        #[cfg(not(feature = "production-v3"))]
        assert!(matches!(
            network_params_for_profile(RCNET1_PROFILE),
            Err(NodeError::ProductionV3Unavailable)
        ));
        #[cfg(feature = "production-v3")]
        assert!(matches!(
            network_params_for_profile(RCNET1_PROFILE),
            Err(NodeError::ProductionV3ArtifactsMissing)
        ));
        #[cfg(not(feature = "production-v3"))]
        assert!(matches!(
            Node::open_with_profile(&path, RCNET1_PROFILE),
            Err(NodeError::ProductionV3Unavailable)
        ));
        #[cfg(feature = "production-v3")]
        assert!(matches!(
            Node::open_with_profile(&path, RCNET1_PROFILE),
            Err(NodeError::ProductionV3ArtifactsMissing)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn devnet_rejects_v3_artifacts_and_keeps_its_v2_parameters() {
        let path = test_dir("devnet-v3-artifact-rejection");
        clean_test_dir(&path);
        let artifacts = ProductionV3VerifierArtifacts {
            bank: path.with_extension("bank"),
            manifest: path.with_extension("manifest"),
            record_v2: path.with_extension("record-v2"),
        };

        assert!(matches!(
            Node::open_with_profile_and_artifacts(&path, DEVNET_PROFILE, Some(&artifacts)),
            Err(NodeError::ProductionV3ArtifactsUnexpected)
        ));
        assert!(!path.exists());
        assert!(matches!(
            devnet_params().unwrap().pow,
            PowParameters::V2Reference(_)
        ));
    }

    #[cfg(feature = "production-v3")]
    #[test]
    fn devnet_mining_work_cannot_select_or_fall_back_to_v3() {
        let root = test_dir("devnet-v3-mining-rejection");
        clean_test_dir(&root);
        let node = Node::open(&root).unwrap();
        let job = node
            .build_mining_job(default_miner_destination(), 1_800_000_000)
            .unwrap();
        let artifacts = ProductionV3VerifierArtifacts {
            bank: root.with_extension("bank"),
            manifest: root.with_extension("manifest"),
            record_v2: root.with_extension("record-v2"),
        };

        assert!(matches!(
            job.v3_candidate_parameters(),
            Err(NodeError::Pow(PowError::WrongProofType))
        ));
        let scratch = root.join("scratch");
        fs::create_dir_all(&scratch).unwrap();
        assert!(matches!(
            ProductionV3MiningWorkFactory::load(artifacts, scratch, 1, &AtomicBool::new(false)),
            Err(NodeError::ProductionV3Unavailable)
        ));
        drop(node);
        clean_test_dir(&root);
    }

    #[cfg(feature = "production-v3")]
    #[test]
    fn rcnet_rejects_unpinned_v3_artifacts_before_touching_storage() {
        let root = test_dir("rcnet-wrong-v3-artifacts");
        clean_test_dir(&root);
        fs::create_dir_all(&root).unwrap();
        let artifacts = ProductionV3VerifierArtifacts {
            bank: root.join("model.bank"),
            manifest: root.join("model.manifest.json"),
            record_v2: root.join("model.record-v2.json"),
        };
        fs::write(&artifacts.bank, b"not a production bank").unwrap();
        fs::write(&artifacts.manifest, b"{}\n").unwrap();
        fs::write(&artifacts.record_v2, b"{}\n").unwrap();
        let data_dir = root.join("node-data");

        assert!(matches!(
            Node::open_with_profile_and_artifacts(&data_dir, RCNET1_PROFILE, Some(&artifacts)),
            Err(NodeError::ProductionV3ArtifactPinsMissing)
        ));
        assert!(!data_dir.exists());
        clean_test_dir(&root);
    }

    #[cfg(feature = "production-v3")]
    #[test]
    fn production_v3_mining_configuration_requires_explicit_bounded_absolute_paths() {
        let root = test_dir("v3-mining-configuration");
        clean_test_dir(&root);
        fs::create_dir_all(&root).unwrap();
        let valid = ProductionV3VerifierArtifacts {
            bank: root.join("model.bank"),
            manifest: root.join("model.manifest.json"),
            record_v2: root.join("model.record-v2.json"),
        };
        assert!(validate_production_v3_mining_configuration(&valid, &root, 1).is_ok());
        assert!(matches!(
            validate_production_v3_mining_configuration(&valid, &root, 0),
            Err(NodeError::ProductionV3MiningConfiguration)
        ));
        assert!(matches!(
            validate_production_v3_mining_configuration(
                &ProductionV3VerifierArtifacts {
                    bank: PathBuf::from("relative.bank"),
                    ..valid.clone()
                },
                &root,
                1,
            ),
            Err(NodeError::ProductionV3MiningConfiguration)
        ));
        assert!(matches!(
            validate_production_v3_mining_configuration(
                &ProductionV3VerifierArtifacts {
                    manifest: valid.bank.clone(),
                    ..valid
                },
                &root,
                1,
            ),
            Err(NodeError::ProductionV3MiningConfiguration)
        ));
        clean_test_dir(&root);
    }

    #[cfg(feature = "production-v3")]
    #[test]
    fn production_v3_file_pin_matches_every_identity_field() {
        use cmfd_consensus::dory_v3_model_ceremony_transcript::FileIdentity;

        let actual = FileIdentity {
            bytes: 7,
            blake3: [0x31; 32],
            sha256: [0x32; 32],
        };
        let matching = release_gate::ProductionV3FileIdentityPin {
            bytes: actual.bytes,
            blake3: actual.blake3,
            sha256: actual.sha256,
        };
        assert!(require_production_v3_file_identity("bank", matching, &actual).is_ok());

        for mismatched in [
            release_gate::ProductionV3FileIdentityPin {
                bytes: actual.bytes + 1,
                ..matching
            },
            release_gate::ProductionV3FileIdentityPin {
                blake3: [0x33; 32],
                ..matching
            },
            release_gate::ProductionV3FileIdentityPin {
                sha256: [0x34; 32],
                ..matching
            },
        ] {
            assert!(matches!(
                require_production_v3_file_identity("bank", mismatched, &actual),
                Err(NodeError::ProductionV3ArtifactIdentityMismatch("bank"))
            ));
        }
    }

    #[test]
    fn preverified_submission_consumes_only_exact_process_local_proof_evidence() {
        let path = test_dir("preverified-submission");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let timestamp = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_candidate(&node, timestamp);
        let preverified = node.block_preverifier().preverify(&block).unwrap();

        let mut mutated = block.clone();
        let BlockProof::V2Reference(proof) = &mut mutated.proof else {
            unreachable!();
        };
        proof.work_digest[0] ^= 1;
        assert!(matches!(
            node.submit_preverified_block(mutated, timestamp, preverified.clone()),
            Err(NodeError::Chain(ChainError::PreverifiedProofMismatch))
        ));
        assert_eq!(node.state.next_height(), 1);
        assert!(node.index.blocks.is_empty());

        node.submit_preverified_block(block.clone(), timestamp, preverified)
            .unwrap();
        assert_eq!(node.state.tip(), block.block_id());
        assert_eq!(node.state.next_height(), 2);
        assert!(node.index.contains(block.block_id()));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn public_peer_mode_is_runtime_only_and_visible_in_status() {
        let path = test_dir("public-peer-status");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let status = node.status().unwrap();
        assert!(!status.public_peer_mode);
        assert_eq!(status.proof_verification_active, 0);
        assert_eq!(status.proof_verification_queued, 0);
        assert_eq!(
            status.proof_verification_capacity,
            MAX_CONCURRENT_PROOF_VERIFICATIONS
        );
        assert_eq!(
            status.proof_verification_queue_capacity,
            MAX_QUEUED_PROOF_VERIFICATIONS + MAX_PRIORITY_QUEUED_PROOF_VERIFICATIONS
        );
        node.set_public_peer_mode(true);
        assert!(node.status().unwrap().public_peer_mode);
        drop(node);

        let reopened = Node::open(&path).unwrap();
        assert!(!reopened.status().unwrap().public_peer_mode);
        drop(reopened);
        clean_test_dir(&path);
    }

    #[test]
    fn peer_observations_are_bounded_ordered_and_runtime_only() {
        let path = test_dir("peer-observations");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        for index in 0..(MAX_OBSERVED_PEERS + 2) {
            let address = format!("127.0.0.1:{}", 20_000 + index);
            let now = index as u64 + 1;
            node.record_peer_started(PeerDirection::Outbound, address.clone(), now);
            node.record_peer_ended(PeerDirection::Outbound, address, true, now);
        }

        let peers = node.status().unwrap().peers;
        assert_eq!(peers.len(), MAX_OBSERVED_PEERS);
        assert_eq!(peers[0].address, "127.0.0.1:20065");
        assert_eq!(peers[0].state, PeerState::Failed);
        assert_eq!(peers[0].failed_sessions, 1);
        assert!(!peers.iter().any(|peer| peer.address == "127.0.0.1:20000"));
        assert!(!peers.iter().any(|peer| peer.address == "127.0.0.1:20001"));
        drop(node);

        let reopened = Node::open(&path).unwrap();
        assert!(reopened.status().unwrap().peers.is_empty());
        drop(reopened);
        clean_test_dir(&path);
    }

    #[test]
    fn peer_hello_binds_live_tip_and_canonical_u512_work() {
        let path = test_dir("peer-hello");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let hello = node.peer_hello();
        assert_eq!(hello.network_id, node.params.network_id);
        assert_eq!(hello.consensus_fingerprint, node.fingerprint);
        assert_eq!(hello.tip, node.state.tip());
        assert_eq!(hello.height, 0);
        assert_eq!(hello.cumulative_work, peer::ChainWork::ZERO);
        assert_ne!(hello.node_nonce, [0; 32]);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn data_directory_lock_rejects_a_concurrent_node_open() {
        let path = test_dir("lock-concurrent");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let error = match Node::open(&path) {
            Ok(_) => panic!("a second node opened a locked data directory"),
            Err(error) => error,
        };
        assert!(matches!(&error, NodeError::DataDirLocked(_)));
        assert!(error.to_string().contains("locked by another running node"));
        assert!(path.join(LOCK_FILE).exists());
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn dropping_a_node_releases_the_persistent_data_directory_lock() {
        let path = test_dir("lock-drop");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        drop(node);

        assert!(path.join(LOCK_FILE).exists());
        drop(Node::open(&path).unwrap());
        assert!(path.join(LOCK_FILE).exists());
        clean_test_dir(&path);
    }

    #[test]
    fn immutable_mining_job_searches_after_node_unlock_and_submits_normally() {
        let path = test_dir("immutable-mining-job");
        clean_test_dir(&path);
        let now = 1_800_000_000;
        let job = {
            let node = Node::open(&path).unwrap();
            let job = node
                .build_mining_job(default_miner_destination(), now)
                .unwrap();
            assert_eq!(job.challenge().height, 1);
            job
        };

        let result = job
            .search_range(0, MAX_MINING_SEARCH_ATTEMPTS, || false)
            .unwrap();
        let (block, attempts_completed, next_nonce) = match result {
            MiningSearchResult::Found {
                block,
                attempts_completed,
                next_nonce,
            } => (block, attempts_completed, next_nonce),
            other => panic!("expected a winning Devnet range, received {other:?}"),
        };
        let proof_nonce = match &block.proof {
            BlockProof::V1Legacy(proof) => proof.nonce,
            BlockProof::V2Reference(proof) => proof.nonce,
            BlockProof::V3Candidate(proof) => proof.nonce,
        };
        assert_eq!(attempts_completed, proof_nonce.wrapping_add(1));
        assert_eq!(next_nonce, proof_nonce.wrapping_add(1));

        let block_id = block.block_id();
        let mut node = Node::open(&path).unwrap();
        node.submit_block(*block, now).unwrap();
        assert_eq!(node.status().unwrap().tip, hex::encode(block_id));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn mining_job_range_is_bounded_cancellable_and_wrap_safe() {
        let path = test_dir("mining-job-bounds");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let job = node
            .build_mining_job(default_miner_destination(), 1_800_000_000)
            .unwrap();
        drop(node);

        assert!(matches!(
            job.search_range(0, 0, || false),
            Err(NodeError::InvalidMiningSearchAttempts)
        ));
        assert!(matches!(
            job.search_range(0, MAX_MINING_SEARCH_ATTEMPTS + 1, || false),
            Err(NodeError::InvalidMiningSearchAttempts)
        ));

        assert_eq!(
            job.search_range(41, 1, || true).unwrap(),
            MiningSearchResult::Cancelled {
                attempts_completed: 0,
                next_nonce: 41,
            }
        );

        let mut losing_nonce = 0_u64;
        loop {
            match job.search_range(losing_nonce, 1, || false).unwrap() {
                MiningSearchResult::Exhausted { .. } => break,
                MiningSearchResult::Found { .. } => {
                    losing_nonce = losing_nonce.wrapping_add(1);
                }
                MiningSearchResult::Cancelled { .. } => {
                    panic!("non-cancelling search unexpectedly cancelled")
                }
            }
        }
        let mut cancellation_checks = 0;
        assert_eq!(
            job.search_range(losing_nonce, 2, || {
                cancellation_checks += 1;
                cancellation_checks > 1
            })
            .unwrap(),
            MiningSearchResult::Cancelled {
                attempts_completed: 1,
                next_nonce: losing_nonce.wrapping_add(1),
            }
        );

        let wrapped = job.search_range(u64::MAX, 1, || false).unwrap();
        match wrapped {
            MiningSearchResult::Found {
                attempts_completed,
                next_nonce,
                ..
            }
            | MiningSearchResult::Exhausted {
                attempts_completed,
                next_nonce,
            } => {
                assert_eq!(attempts_completed, 1);
                assert_eq!(next_nonce, 0);
            }
            MiningSearchResult::Cancelled { .. } => {
                panic!("non-cancelling wrapping search unexpectedly cancelled")
            }
        }

        clean_test_dir(&path);
    }

    #[test]
    fn accelerator_outputs_are_prefiltered_but_never_trusted() {
        let path = test_dir("accelerator-recheck");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let job = node
            .build_mining_job(default_miner_destination(), 1_800_000_000)
            .unwrap();
        drop(node);

        let batch = job.prepare_accelerator_batch(17, 2).unwrap();
        let reference = v2_test_reference().unwrap();
        let mut outputs = Vec::new();
        for index in 0..batch.count() as usize {
            let proof = reference
                .prove_reference(job.challenge(), batch.nonce_at(index).unwrap())
                .unwrap();
            outputs.extend(
                proof
                    .layers
                    .last()
                    .unwrap()
                    .output
                    .iter()
                    .map(|value| u8::try_from(*value + 125).unwrap()),
            );
        }

        let result = job
            .complete_accelerator_batch(&batch, &outputs, [0xff; 32])
            .unwrap();
        assert!(matches!(
            result,
            MiningShareSearchResult::Found {
                attempts_completed: 1,
                next_nonce: 18,
                ..
            }
        ));

        outputs[0] = (outputs[0] + 1) % 251;
        assert!(matches!(
            job.complete_accelerator_batch(&batch, &outputs, [0xff; 32]),
            Err(NodeError::Pow(PowError::V2(
                ForgeMatrixV2Error::AcceleratorMismatch
            )))
        ));
        clean_test_dir(&path);
    }

    #[test]
    fn pool_share_evaluation_separates_share_work_from_chain_work() {
        let path = test_dir("pool-share-separation");
        clean_test_dir(&path);
        let now = 1_800_000_000;
        let mut node = Node::open(&path).unwrap();
        let job = node
            .build_mining_job(default_miner_destination(), now)
            .unwrap();
        let chain_target = job.challenge().target;
        assert!(chain_target > [0; 32]);

        let invalid_target = job.evaluate_share(0, [0; 32]).unwrap_err();
        assert!(matches!(
            invalid_target,
            NodeError::InvalidMiningShareTarget
        ));
        assert_eq!(
            invalid_target.client_error().code,
            "invalid_mining_share_target"
        );

        let mut share_only_nonce = 0_u64;
        let share_only = loop {
            let evaluation = job.evaluate_share(share_only_nonce, [0xff; 32]).unwrap();
            if !evaluation.meets_chain_target {
                break evaluation;
            }
            share_only_nonce = share_only_nonce.wrapping_add(1);
        };
        assert!(share_only.meets_share_target);
        assert!(!share_only.meets_chain_target);
        assert_eq!(
            share_only.work_digest,
            share_only.proof.work_digest(),
            "the exported digest must match the independently recomputed proof"
        );
        assert!(
            job.build_block_if_chain_valid(&share_only.proof)
                .unwrap()
                .is_none()
        );

        let searched = job
            .search_share_range(share_only_nonce, 1, [0xff; 32], || false)
            .unwrap();
        assert_eq!(
            searched,
            MiningShareSearchResult::Found {
                proof: share_only.proof.clone(),
                work_digest: share_only.work_digest,
                meets_chain_target: false,
                attempts_completed: 1,
                next_nonce: share_only_nonce.wrapping_add(1),
            }
        );

        let mut mutated_work = share_only.proof.clone();
        match &mut mutated_work {
            BlockProof::V1Legacy(proof) => proof.work_digest[0] ^= 1,
            BlockProof::V2Reference(proof) => proof.work_digest[0] ^= 1,
            BlockProof::V3Candidate(proof) => proof.work_digest[0] ^= 1,
        }
        assert!(job.build_block_if_chain_valid(&mutated_work).is_err());

        let mut mutated_nonce = share_only.proof;
        match &mut mutated_nonce {
            BlockProof::V1Legacy(proof) => proof.nonce = proof.nonce.wrapping_add(1),
            BlockProof::V2Reference(proof) => proof.nonce = proof.nonce.wrapping_add(1),
            BlockProof::V3Candidate(proof) => proof.nonce = proof.nonce.wrapping_add(1),
        }
        assert!(job.build_block_if_chain_valid(&mutated_nonce).is_err());

        let block_proof = match job
            .search_share_range(0, MAX_MINING_SEARCH_ATTEMPTS, chain_target, || false)
            .unwrap()
        {
            MiningShareSearchResult::Found {
                proof,
                work_digest,
                meets_chain_target,
                ..
            } => {
                assert!(meets_chain_target);
                assert!(work_digest <= chain_target);
                proof
            }
            other => panic!("expected a chain-valid share, received {other:?}"),
        };
        let block = job
            .build_block_if_chain_valid(&block_proof)
            .unwrap()
            .expect("chain-valid proof must construct a block");
        assert_eq!(block.challenge.target, chain_target);
        node.submit_block(*block, now).unwrap();
        assert_eq!(node.status().unwrap().accepted_height, 1);

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn pool_share_search_is_bounded_cancellable_and_wrap_safe() {
        let path = test_dir("pool-share-search-bounds");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let job = node
            .build_mining_job(default_miner_destination(), 1_800_000_000)
            .unwrap();
        drop(node);
        let chain_target = job.challenge().target;

        assert!(matches!(
            job.search_share_range(0, 0, chain_target, || false),
            Err(NodeError::InvalidMiningSearchAttempts)
        ));
        assert!(matches!(
            job.search_share_range(0, MAX_MINING_SEARCH_ATTEMPTS + 1, chain_target, || false),
            Err(NodeError::InvalidMiningSearchAttempts)
        ));
        assert!(matches!(
            job.search_share_range(0, 1, [0; 32], || false),
            Err(NodeError::InvalidMiningShareTarget)
        ));
        assert_eq!(
            job.search_share_range(41, 1, chain_target, || true)
                .unwrap(),
            MiningShareSearchResult::Cancelled {
                attempts_completed: 0,
                next_nonce: 41,
            }
        );

        let mut losing_nonce = 0_u64;
        loop {
            let first = job.evaluate_share(losing_nonce, chain_target).unwrap();
            let second = job
                .evaluate_share(losing_nonce.wrapping_add(1), chain_target)
                .unwrap();
            if !first.meets_share_target && !second.meets_share_target {
                break;
            }
            losing_nonce = losing_nonce.wrapping_add(1);
        }
        assert_eq!(
            job.search_share_range(losing_nonce, 1, chain_target, || false)
                .unwrap(),
            MiningShareSearchResult::Exhausted {
                attempts_completed: 1,
                next_nonce: losing_nonce.wrapping_add(1),
            }
        );

        let mut cancellation_checks = 0;
        assert_eq!(
            job.search_share_range(losing_nonce, 2, chain_target, || {
                cancellation_checks += 1;
                cancellation_checks > 1
            })
            .unwrap(),
            MiningShareSearchResult::Cancelled {
                attempts_completed: 1,
                next_nonce: losing_nonce.wrapping_add(1),
            }
        );

        match job
            .search_share_range(u64::MAX, 1, [0xff; 32], || false)
            .unwrap()
        {
            MiningShareSearchResult::Found {
                attempts_completed,
                next_nonce,
                proof,
                work_digest,
                ..
            } => {
                assert_eq!(attempts_completed, 1);
                assert_eq!(next_nonce, 0);
                assert_eq!(proof.work_digest(), work_digest);
            }
            other => panic!("maximum share target must accept one wrapped nonce: {other:?}"),
        }

        clean_test_dir(&path);
    }

    #[test]
    fn preexisting_unlocked_lock_file_is_refreshed_without_blocking_open() {
        let path = test_dir("lock-preexisting");
        clean_test_dir(&path);
        fs::create_dir_all(&path).unwrap();
        let lock_path = path.join(LOCK_FILE);
        fs::write(&lock_path, b"stale diagnostic contents\n").unwrap();

        drop(Node::open(&path).unwrap());

        assert_eq!(
            fs::read_to_string(&lock_path).unwrap(),
            format!("pid={}\n", std::process::id())
        );
        clean_test_dir(&path);
    }

    #[test]
    fn empty_log_uses_zero_chain_root_and_first_append_is_v2() {
        let path = test_dir("v2-empty-root");
        clean_test_dir(&path);
        let timestamp = DEVNET_GENESIS_TIMESTAMP + 60;
        let expected_digest = {
            let mut node = Node::open(&path).unwrap();
            assert_eq!(node.last_record_digest, EMPTY_RECORD_CHAIN_ROOT);
            let block = mined_child(&node, node.params.genesis_hash, timestamp, 0x11);
            node.submit_block(block, timestamp).unwrap();
            assert_ne!(node.last_record_digest, EMPTY_RECORD_CHAIN_ROOT);
            node.last_record_digest
        };

        let records = read_complete_log_records(&path);
        assert_eq!(records.len(), 1);
        assert_eq!(
            u16::from_le_bytes(records[0][4..6].try_into().unwrap()),
            RECORD_VERSION_V2
        );
        assert_eq!(&records[0][24..56], &EMPTY_RECORD_CHAIN_ROOT);
        assert_eq!(complete_record_digest(&records[0]), expected_digest);

        let reopened = Node::open(&path).unwrap();
        assert_eq!(reopened.last_record_digest, expected_digest);
        assert_eq!(reopened.state.next_height(), 2);
        drop(reopened);
        clean_test_dir(&path);
    }

    #[test]
    fn legacy_v1_replays_and_the_first_v2_binds_to_its_exact_record() {
        let path = test_dir("mixed-v1-v2");
        clean_test_dir(&path);
        let first_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let second_at = first_at + 60;
        let third_at = second_at + 60;
        let (first, first_record) = {
            let node = Node::open(&path).unwrap();
            let first = mined_child(&node, node.params.genesis_hash, first_at, 0x12);
            let canonical = encode_block(&first).unwrap();
            let record = encode_record_v1(first_at, &canonical).unwrap();
            (first, record)
        };
        fs::write(path.join(BLOCK_LOG_FILE), &first_record).unwrap();

        let (second, second_record) = {
            let node = Node::open(&path).unwrap();
            assert_eq!(node.state.tip(), first.block_id());
            assert_eq!(
                node.last_record_digest,
                complete_record_digest(&first_record)
            );
            let second = mined_child(&node, first.block_id(), second_at, 0x13);
            let record = encode_record_v1(second_at, &encode_block(&second).unwrap()).unwrap();
            (second, record)
        };
        write_complete_log_records(&path, &[first_record, second_record]);

        let third = {
            let mut node = Node::open(&path).unwrap();
            assert_eq!(node.state.tip(), second.block_id());
            let third = mined_child(&node, second.block_id(), third_at, 0x14);
            node.submit_block(third.clone(), third_at).unwrap();
            third
        };

        let records = read_complete_log_records(&path);
        assert_eq!(records.len(), 3);
        assert_eq!(
            u16::from_le_bytes(records[0][4..6].try_into().unwrap()),
            RECORD_VERSION_V1
        );
        assert_eq!(
            u16::from_le_bytes(records[1][4..6].try_into().unwrap()),
            RECORD_VERSION_V1
        );
        assert_eq!(
            u16::from_le_bytes(records[2][4..6].try_into().unwrap()),
            RECORD_VERSION_V2
        );
        assert_eq!(&records[2][24..56], &complete_record_digest(&records[1]));
        let reopened = Node::open(&path).unwrap();
        assert_eq!(reopened.state.tip(), third.block_id());
        assert_eq!(reopened.state.next_height(), 4);
        drop(reopened);

        let mut downgraded = records;
        downgraded.push(encode_record_v1(third_at, &encode_block(&third).unwrap()).unwrap());
        write_complete_log_records(&path, &downgraded);
        assert!(matches!(
            Node::open(&path),
            Err(NodeError::CorruptLog(message)) if message.contains("legacy V1 after the V2 chain")
        ));
        clean_test_dir(&path);
    }

    #[test]
    fn mixed_v1_v2_fork_log_replays_with_dfs_undo_and_reorg() {
        let path = test_dir("mixed-v1-v2-fork");
        clean_test_dir(&path);
        let expected_tip = {
            let mut node = Node::open(&path).unwrap();
            let genesis = node.params.genesis_hash;
            let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
            let t2 = t1 + 60;
            let t3 = t2 + 60;
            let a1 = mined_child(&node, genesis, t1, 0x15);
            node.submit_block(a1.clone(), t1).unwrap();
            let a2 = mined_child(&node, a1.block_id(), t2, 0x16);
            node.submit_block(a2, t2).unwrap();
            let b1 = mined_child(&node, genesis, t1, 0x17);
            node.submit_block(b1.clone(), t1).unwrap();
            let b2 = mined_child(&node, b1.block_id(), t2, 0x18);
            node.submit_block(b2.clone(), t2).unwrap();
            let b3 = mined_child(&node, b2.block_id(), t3, 0x19);
            node.submit_block(b3.clone(), t3).unwrap();
            b3.block_id()
        };

        let original = read_complete_log_records(&path);
        assert_eq!(original.len(), 5);
        let mut mixed: Vec<Vec<u8>> = Vec::with_capacity(original.len());
        for (position, record) in original.iter().enumerate() {
            let (accepted_at, _, block_bytes, delta_bytes) = v2_record_parts(record);
            let rewritten = if position < 3 {
                encode_record_v1(accepted_at, block_bytes).unwrap()
            } else {
                let previous = complete_record_digest(mixed.last().unwrap());
                encode_record_v2(accepted_at, block_bytes, delta_bytes, previous).unwrap()
            };
            mixed.push(rewritten);
        }
        assert!(mixed[..3].iter().all(|record| {
            u16::from_le_bytes(record[4..6].try_into().unwrap()) == RECORD_VERSION_V1
        }));
        assert!(mixed[3..].iter().all(|record| {
            u16::from_le_bytes(record[4..6].try_into().unwrap()) == RECORD_VERSION_V2
        }));
        assert_eq!(&mixed[3][24..56], &complete_record_digest(&mixed[2]));
        write_complete_log_records(&path, &mixed);

        let node = Node::open(&path).unwrap();
        assert_eq!(node.state.tip(), expected_tip);
        assert_eq!(node.state.next_height(), 4);
        assert_eq!(node.index.blocks.len(), 5);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn mine_restart_and_strict_replay_restore_the_tip() {
        let path = test_dir("replay");
        clean_test_dir(&path);
        let (block_id, fingerprint) = {
            let mut node = Node::open(&path).unwrap();
            let block = node
                .mine_once(
                    default_miner_destination(),
                    1_800_000_000,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            assert!(matches!(block.proof, BlockProof::V2Reference(_)));
            assert_eq!(node.status().unwrap().accepted_height, 1);
            (block.block_id(), node.fingerprint)
        };

        let records = read_complete_log_records(&path);
        assert_eq!(records.len(), 1);
        assert_eq!(
            u16::from_le_bytes(records[0][4..6].try_into().unwrap()),
            RECORD_VERSION_V2
        );

        let node = Node::open(&path).unwrap();
        let status = node.status().unwrap();
        assert_eq!(status.accepted_height, 1);
        assert_eq!(status.next_height, 2);
        assert_eq!(status.tip, hex::encode(block_id));
        assert_eq!(status.consensus_fingerprint, hex::encode(fingerprint));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn strictly_heavier_fork_reorgs_while_equal_work_keeps_the_tip() {
        let path = test_dir("heavier-fork");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
        let t2 = t1 + 60;
        let t3 = t2 + 60;

        let a1 = mined_child(&node, genesis, t1, 0x21);
        node.submit_block(a1.clone(), t1).unwrap();
        let a2 = mined_child(&node, a1.block_id(), t2, 0x22);
        node.submit_block(a2.clone(), t2).unwrap();
        let active_work = node.cumulative_work();

        let b1 = mined_child(&node, genesis, t1, 0x31);
        node.submit_block(b1.clone(), t1).unwrap();
        assert_eq!(node.state.tip(), a2.block_id());
        let b2 = mined_child(&node, b1.block_id(), t2, 0x32);
        node.submit_block(b2.clone(), t2).unwrap();

        assert_eq!(
            node.index.blocks[&b2.block_id()].cumulative_work,
            node.index.active_work
        );
        assert_eq!(node.cumulative_work(), active_work);
        assert_eq!(node.state.tip(), a2.block_id());

        let b3 = mined_child(&node, b2.block_id(), t3, 0x33);
        node.submit_block(b3.clone(), t3).unwrap();
        assert_eq!(node.state.tip(), b3.block_id());
        assert_eq!(node.state.next_height(), 4);
        assert_eq!(
            node.index.active_chain,
            vec![genesis, b1.block_id(), b2.block_id(), b3.block_id()]
        );
        assert!(node.index.active_work > node.index.blocks[&a2.block_id()].cumulative_work);
        assert_eq!(node.status().unwrap().cumulative_work.len(), 128);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn invalid_side_block_is_neither_indexed_nor_persisted() {
        let path = test_dir("invalid-side");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
        let t2 = t1 + 60;

        let active = mined_child(&node, genesis, t1, 0x41);
        node.submit_block(active.clone(), t1).unwrap();
        let active_2 = mined_child(&node, active.block_id(), t2, 0x42);
        let active_tip = active_2.block_id();
        node.submit_block(active_2, t2).unwrap();
        let side = mined_child(&node, genesis, t1, 0x51);
        node.submit_block(side.clone(), t1).unwrap();

        let mut invalid = mined_child(&node, side.block_id(), t2, 0x52);
        invalid.challenge.target[31] ^= 1;
        let invalid_id = invalid.block_id();
        let log_len = node.log.metadata().unwrap().len();
        assert!(matches!(
            node.submit_block(invalid, t2),
            Err(NodeError::Chain(ChainError::UnexpectedTarget))
        ));
        assert!(!node.contains_block(invalid_id));
        assert_eq!(node.log.metadata().unwrap().len(), log_len);
        assert_eq!(node.state.tip(), active_tip);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn restart_reconstructs_side_branches_active_tip_and_work() {
        let path = test_dir("fork-restart");
        clean_test_dir(&path);
        let (tip, work, side_id, block_count) = {
            let mut node = Node::open(&path).unwrap();
            let genesis = node.params.genesis_hash;
            let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
            let t2 = t1 + 60;
            let t3 = t2 + 60;
            let a1 = mined_child(&node, genesis, t1, 0x61);
            node.submit_block(a1.clone(), t1).unwrap();
            let a2 = mined_child(&node, a1.block_id(), t2, 0x62);
            node.submit_block(a2.clone(), t2).unwrap();
            let b1 = mined_child(&node, genesis, t1, 0x71);
            node.submit_block(b1.clone(), t1).unwrap();
            let b2 = mined_child(&node, b1.block_id(), t2, 0x72);
            node.submit_block(b2.clone(), t2).unwrap();
            let b3 = mined_child(&node, b2.block_id(), t3, 0x73);
            node.submit_block(b3.clone(), t3).unwrap();
            (
                b3.block_id(),
                node.cumulative_work(),
                a2.block_id(),
                node.index.blocks.len(),
            )
        };

        let records = read_complete_log_records(&path);
        assert_eq!(records.len(), block_count);
        assert!(records.iter().all(|record| {
            u16::from_le_bytes(record[4..6].try_into().unwrap()) == RECORD_VERSION_V2
        }));

        let mut node = Node::open(&path).unwrap();
        assert_eq!(node.state.tip(), tip);
        assert_eq!(node.cumulative_work(), work);
        assert_eq!(node.index.blocks.len(), block_count);
        assert!(node.contains_block(side_id));
        assert!(node.canonical_block(side_id).unwrap().is_some());
        assert_eq!(node.status().unwrap().cumulative_work, hex::encode(work.0));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn authenticated_locator_rejects_every_forged_location_and_block_metadata_field() {
        let path = test_dir("forged-record-locators");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let first_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let second_at = first_at + 60;
        let first = node
            .mine_once(
                default_miner_destination(),
                first_at,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let second = node
            .mine_once(
                default_miner_destination(),
                second_at,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let first_id = first.block_id();
        let second_locator = node.index.blocks[&second.block_id()].locator;

        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.offset = second_locator.offset;
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.length = locator.length.checked_add(1).unwrap();
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.length = locator.length.checked_sub(1).unwrap();
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.complete_digest[0] ^= 1;
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.version = BlockRecordVersion::LegacyV1;
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.accepted_at = locator.accepted_at.checked_add(1).unwrap();
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.block_id[0] ^= 1;
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.parent[0] ^= 1;
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.height = locator.height.checked_add(1).unwrap();
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            locator.target[0] ^= 1;
        });
        assert_forged_locator_rejected(&mut node, first_id, |locator| {
            *locator = second_locator;
        });

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn positioned_reads_preserve_the_append_cursor_and_restart_offsets_are_exact() {
        let path = test_dir("positioned-read-append-offsets");
        clean_test_dir(&path);
        let first_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let second_at = first_at + 60;
        let third_at = second_at + 60;
        let (first_id, second_id, restart_end) = {
            let mut node = Node::open(&path).unwrap();
            let first = node
                .mine_once(
                    default_miner_destination(),
                    first_at,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            let second = node
                .mine_once(
                    default_miner_destination(),
                    second_at,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            let first_locator = node.index.blocks[&first.block_id()].locator;
            let second_locator = node.index.blocks[&second.block_id()].locator;
            assert_eq!(first_locator.ordinal, 0);
            assert_eq!(first_locator.offset, 0);
            assert_eq!(second_locator.ordinal, 1);
            assert_eq!(
                second_locator.offset,
                first_locator.offset + first_locator.length
            );
            assert_eq!(
                node.block_log_length,
                second_locator.offset + second_locator.length
            );
            (first.block_id(), second.block_id(), node.block_log_length)
        };

        let mut node = Node::open(&path).unwrap();
        assert_eq!(node.block_log_length, restart_end);
        assert_eq!(node.index.blocks[&first_id].locator.ordinal, 0);
        assert_eq!(node.index.blocks[&second_id].locator.ordinal, 1);
        node.log.seek(SeekFrom::Start(7)).unwrap();
        assert!(node.canonical_block(first_id).unwrap().is_some());
        assert_eq!(node.log.stream_position().unwrap(), 7);

        let third = node
            .mine_once(
                default_miner_destination(),
                third_at,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let third_locator = node.index.blocks[&third.block_id()].locator;
        assert_eq!(third_locator.ordinal, 2);
        assert_eq!(third_locator.offset, restart_end);
        assert_eq!(
            node.block_log_length,
            third_locator.offset + third_locator.length
        );
        assert_eq!(node.log.metadata().unwrap().len(), node.block_log_length);

        drop(node);
        clean_test_dir(&path);
    }

    #[cfg(windows)]
    #[test]
    fn ancestor_junction_retarget_cannot_split_the_retained_log_from_its_path() {
        let root = test_dir("retained-log-junction-retarget");
        clean_test_dir(&root);
        let target_a = root.join("target-a");
        let target_b = root.join("target-b");
        let junction = root.join("current");
        fs::create_dir_all(&target_a).unwrap();
        fs::create_dir_all(&target_b).unwrap();
        create_directory_junction(&target_a, &junction);

        let data_dir = junction.join("node");
        let first_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let second_at = first_at + 60;
        let mut node = Node::open(&data_dir).unwrap();
        let first = node
            .mine_once(
                default_miner_destination(),
                first_at,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let second = mined_child(&node, first.block_id(), second_at, 0x5a);
        let original_tip = node.state.tip();
        let retained_log = target_a.join("node").join(BLOCK_LOG_FILE);
        let retained_length = fs::metadata(&retained_log).unwrap().len();

        let replacement_data_dir = target_b.join("node");
        fs::create_dir_all(&replacement_data_dir).unwrap();
        let replacement_log = replacement_data_dir.join(BLOCK_LOG_FILE);
        fs::write(&replacement_log, []).unwrap();
        fs::remove_dir(&junction).unwrap();
        create_directory_junction(&target_b, &junction);

        assert!(matches!(
            node.submit_block(second.clone(), second_at),
            Err(NodeError::CorruptLog(message))
                if message.contains("no longer identifies the retained startup file")
        ));
        assert!(node.storage_faulted);
        assert_eq!(node.state.tip(), original_tip);
        assert_eq!(fs::metadata(&retained_log).unwrap().len(), retained_length);
        assert_eq!(fs::metadata(&replacement_log).unwrap().len(), 0);
        assert!(matches!(
            node.submit_block(second, second_at),
            Err(NodeError::StorageFaulted)
        ));

        drop(node);
        fs::remove_dir(&junction).unwrap();
        clean_test_dir(&root);
    }

    #[test]
    fn wallet_locator_corruption_latches_storage_and_blocks_the_next_append() {
        let path = test_dir("wallet-latches-locator-corruption");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        assert!(node.canonical_block([0xa5; 32]).unwrap().is_none());
        assert!(
            !node.storage_faulted,
            "unknown blocks are not storage faults"
        );

        let first_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let second_at = first_at + 60;
        let first = node
            .mine_once(
                default_miner_destination(),
                first_at,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let second = mined_child(&node, first.block_id(), second_at, 0x5b);
        let log_length = node.block_log_length;
        let mut forged = node.index.blocks[&first.block_id()].locator;
        forged.complete_digest[0] ^= 1;
        set_indexed_locator(&mut node, first.block_id(), forged);

        assert!(matches!(
            node.wallet_snapshot(),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(node.storage_faulted);
        assert!(matches!(
            node.submit_block(second, second_at),
            Err(NodeError::StorageFaulted)
        ));
        assert_eq!(node.log.metadata().unwrap().len(), log_length);

        drop(node);
        clean_test_dir(&path);
    }

    #[cfg(unix)]
    #[test]
    fn same_length_log_mutation_read_latches_storage_and_blocks_the_next_append() {
        let path = test_dir("read-latches-same-length-log-mutation");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let first_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let second_at = first_at + 60;
        let first = node
            .mine_once(
                default_miner_destination(),
                first_at,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let second = mined_child(&node, first.block_id(), second_at, 0x5c);
        let original_tip = node.state.tip();
        let log_path = path.join(BLOCK_LOG_FILE);
        let mut changed = fs::read(&log_path).unwrap();
        let original_length = changed.len();
        let accepted_at = u64::from_le_bytes(changed[8..16].try_into().unwrap());
        changed[8..16].copy_from_slice(&accepted_at.checked_add(1).unwrap().to_le_bytes());
        recompute_fixture_record_checksum(&mut changed);
        assert_eq!(changed.len(), original_length);
        let mut writer = OpenOptions::new().write(true).open(&log_path).unwrap();
        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.write_all(&changed).unwrap();
        writer.sync_all().unwrap();

        assert!(matches!(
            node.canonical_block(first.block_id()),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(node.storage_faulted);
        assert!(matches!(
            node.submit_block(second, second_at),
            Err(NodeError::StorageFaulted)
        ));
        assert_eq!(node.state.tip(), original_tip);
        assert_eq!(
            fs::metadata(&log_path).unwrap().len(),
            original_length as u64
        );

        drop(writer);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn on_demand_locator_rejects_same_length_mutation_and_truncation() {
        let path = test_dir("on-demand-locator-mutation");
        clean_test_dir(&path);
        let params = {
            let mut node = Node::open(&path).unwrap();
            node.mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
            node.params
        };
        let log_path = path.join(BLOCK_LOG_FILE);
        let original = fs::read(&log_path).unwrap();
        let scanned = scan_replay_log(
            File::open(&log_path).unwrap(),
            &log_path,
            params,
            params.network_id,
        )
        .unwrap();
        let locator = scanned.records[0];

        let mut changed = original.clone();
        let accepted_at = u64::from_le_bytes(changed[8..16].try_into().unwrap());
        changed[8..16].copy_from_slice(&accepted_at.checked_add(1).unwrap().to_le_bytes());
        recompute_fixture_record_checksum(&mut changed);
        assert_eq!(changed.len(), original.len());
        fs::write(&log_path, &changed).unwrap();
        assert!(matches!(
            read_located_record(
                &File::open(&log_path).unwrap(),
                &log_path,
                &locator,
                params.network_id,
                false,
            ),
            Err(NodeError::CorruptLog(_))
        ));

        fs::write(&log_path, &original[..original.len() - 1]).unwrap();
        assert!(matches!(
            read_located_record(
                &File::open(&log_path).unwrap(),
                &log_path,
                &locator,
                params.network_id,
                false,
            ),
            Err(NodeError::CorruptLog(_))
        ));

        clean_test_dir(&path);
    }

    #[test]
    fn restart_uses_record_ordinal_for_equal_work_across_dfs_order() {
        let path = test_dir("fork-restart-equal-work-ordinal");
        clean_test_dir(&path);
        let (genesis, a1_id, a2_id, b1_id, b2_id, work) = {
            let mut node = Node::open(&path).unwrap();
            let genesis = node.params.genesis_hash;
            let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
            let t2 = t1 + 60;

            let a1 = mined_child(&node, genesis, t1, 0x64);
            node.submit_block(a1.clone(), t1 + 5).unwrap();
            let b1 = mined_child(&node, genesis, t1, 0x65);
            node.submit_block(b1.clone(), t1 + 6).unwrap();
            let b2 = mined_child(&node, b1.block_id(), t2, 0x66);
            node.submit_block(b2.clone(), t2 + 20).unwrap();
            let a2 = mined_child(&node, a1.block_id(), t2, 0x67);
            node.submit_block(a2.clone(), t2 + 10).unwrap();

            assert_eq!(node.state.tip(), b2.block_id());
            assert_eq!(
                node.index.blocks[&a2.block_id()].cumulative_work,
                node.index.blocks[&b2.block_id()].cumulative_work
            );
            (
                genesis,
                a1.block_id(),
                a2.block_id(),
                b1.block_id(),
                b2.block_id(),
                node.index.active_work,
            )
        };

        let node = Node::open(&path).unwrap();
        assert_eq!(node.state.tip(), b2_id);
        assert_ne!(node.state.tip(), a2_id);
        assert_eq!(node.index.active_chain, vec![genesis, b1_id, b2_id]);
        assert_eq!(node.index.active_work, work);
        assert!(node.contains_block(a1_id));
        assert!(node.contains_block(a2_id));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn startup_replay_retains_only_authenticated_locators_for_all_blocks() {
        let path = test_dir("locator-only-replay");
        clean_test_dir(&path);
        let (params, verifier, expected_tip, expected_blocks) = {
            let mut node = Node::open(&path).unwrap();
            let genesis = node.params.genesis_hash;
            let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
            let t2 = t1 + 60;
            let active = mined_child(&node, genesis, t1, 0x74);
            node.submit_block(active.clone(), t1).unwrap();
            let active_child = mined_child(&node, active.block_id(), t2, 0x75);
            node.submit_block(active_child.clone(), t2).unwrap();
            let side = mined_child(&node, genesis, t1, 0x76);
            node.submit_block(side, t1).unwrap();
            (
                node.params,
                node.verifier.clone(),
                active_child.block_id(),
                node.index.blocks.len(),
            )
        };

        let mut state = ChainState::new(params, verifier.clone()).unwrap();
        let mut index = BlockIndex::new(params.genesis_hash);
        let preverifier = BlockPreverifier::new(verifier.clone(), ProofProfile::DevnetV2Reference);
        let log_path = path.join(BLOCK_LOG_FILE);
        let log = open_block_log(&log_path).unwrap();
        replay_log(
            &log,
            &log_path,
            &mut state,
            &mut index,
            &verifier,
            params,
            Some(&preverifier),
        )
        .unwrap();

        assert_eq!(state.tip(), expected_tip);
        assert_eq!(index.blocks.len(), expected_blocks);
        for (block_id, entry) in &index.blocks {
            let IndexedBlock {
                locator,
                cumulative_work: _,
                successor_header: _,
                ancestors: _,
            } = entry.as_ref();
            assert_eq!(*block_id, locator.block_id);
            assert_eq!(locator.version, BlockRecordVersion::V2);
            assert!(
                locator.parent == params.genesis_hash || index.blocks.contains_key(&locator.parent),
                "every non-genesis parent must remain indexed"
            );
        }

        drop(log);
        clean_test_dir(&path);
    }

    #[test]
    fn locator_and_inventory_are_bounded_and_follow_active_order() {
        let path = test_dir("locator");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let mut ids = Vec::new();
        let mut parent = genesis;
        for offset in 1_u64..=14 {
            let timestamp = DEVNET_GENESIS_TIMESTAMP + offset * 60;
            let block = mined_child(&node, parent, timestamp, 0x80 + offset as u8);
            parent = block.block_id();
            node.submit_block(block, timestamp).unwrap();
            ids.push(parent);
        }

        assert!(node.block_locator(0).is_empty());
        assert_eq!(node.block_locator(1), vec![genesis]);
        let locator = node.block_locator(6);
        assert!(locator.len() <= 6);
        assert_eq!(locator.first(), ids.last());
        assert_eq!(locator.last(), Some(&genesis));
        assert!(locator.windows(2).all(|pair| pair[0] != pair[1]));

        assert_eq!(
            node.inventory_after(&[ids[3]], [0; 32], 3),
            ids[4..7].to_vec()
        );
        assert_eq!(
            node.inventory_after(&[ids[3]], ids[5], 10),
            ids[4..=5].to_vec()
        );
        assert!(node.inventory_after(&[[0xaa; 32]], [0; 32], 10).is_empty());
        assert!(node.inventory_after(&[genesis], [0; 32], 0).is_empty());

        assert_eq!(node.index.active_position(genesis), Some(0));
        for (position, block_id) in ids.iter().copied().enumerate() {
            assert_eq!(node.index.active_position(block_id), Some(position + 1));
        }

        let side = mined_child(&node, genesis, DEVNET_GENESIS_TIMESTAMP + 61, 0xf0);
        let side_id = side.block_id();
        node.submit_block(side, DEVNET_GENESIS_TIMESTAMP + 61)
            .unwrap();
        assert_eq!(node.index.active_position(side_id), None);
        assert_eq!(
            node.inventory_after(&[side_id, ids[3]], [0; 32], 3),
            ids[4..7].to_vec()
        );
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn active_extension_is_not_committed_when_durable_append_fails() {
        let path = test_dir("durable-before-commit");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let timestamp = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_child(&node, node.params.genesis_hash, timestamp, 0xa1);
        let block_id = block.block_id();
        let tip = node.state.tip();
        let work = node.cumulative_work();
        let record_digest = node.last_record_digest;
        let log_path = path.join(BLOCK_LOG_FILE);
        let log_len = node.log.metadata().unwrap().len();
        let read_only = OpenOptions::new().read(true).open(&log_path).unwrap();
        drop(std::mem::replace(&mut node.log, read_only));

        assert!(matches!(
            node.submit_block(block, timestamp),
            Err(NodeError::Io {
                operation: "append block record",
                ..
            })
        ));
        assert_eq!(node.state.tip(), tip);
        assert_eq!(node.cumulative_work(), work);
        assert_eq!(node.last_record_digest, record_digest);
        assert_eq!(node.block_log_length, log_len);
        assert!(!node.contains_block(block_id));
        assert_eq!(fs::metadata(log_path).unwrap().len(), log_len);
        assert!(node.storage_faulted);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn duplicate_and_unknown_parent_have_stable_errors() {
        let path = test_dir("block-identity-errors");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let timestamp = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_child(&node, node.params.genesis_hash, timestamp, 0xb1);
        let block_id = block.block_id();
        node.submit_block(block.clone(), timestamp).unwrap();
        assert!(matches!(
            node.submit_block(block, timestamp),
            Err(NodeError::DuplicateBlock(id)) if id == block_id
        ));

        let mut orphan = mined_child(&node, block_id, timestamp + 60, 0xb2);
        orphan.challenge.previous_block = [0xcc; 32];
        assert!(matches!(
            node.submit_block(orphan, timestamp + 60),
            Err(NodeError::UnknownParent(parent)) if parent == [0xcc; 32]
        ));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn v2_lengths_are_rejected_before_payload_allocation() {
        let path = test_dir("v2-length-limits");
        clean_test_dir(&path);
        drop(Node::open(&path).unwrap());
        assert!(matches!(
            checked_record_len(usize::MAX, 1, 0),
            Err(NodeError::CorruptLog(message)) if message.contains("length overflowed")
        ));

        let header = |block_len: u32, delta_len: u32| {
            let mut bytes = Vec::with_capacity(RECORD_V2_HEADER_BYTES);
            bytes.extend_from_slice(&RECORD_MAGIC);
            bytes.extend_from_slice(&RECORD_VERSION_V2.to_le_bytes());
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            bytes.extend_from_slice(&(DEVNET_GENESIS_TIMESTAMP + 60).to_le_bytes());
            bytes.extend_from_slice(&block_len.to_le_bytes());
            bytes.extend_from_slice(&delta_len.to_le_bytes());
            bytes.extend_from_slice(&EMPTY_RECORD_CHAIN_ROOT);
            assert_eq!(bytes.len(), RECORD_V2_HEADER_BYTES);
            bytes
        };

        let oversized_block = u32::try_from(MAX_BLOCK_BYTES + 1).unwrap();
        fs::write(path.join(BLOCK_LOG_FILE), header(oversized_block, 0)).unwrap();
        assert!(matches!(
            Node::open(&path),
            Err(NodeError::CorruptLog(message)) if message.contains("block exceeds the wire limit")
        ));

        let oversized_delta = u32::try_from(MAX_REVERSIBLE_STATE_DELTA_BYTES + 1).unwrap();
        fs::write(path.join(BLOCK_LOG_FILE), header(0, oversized_delta)).unwrap();
        assert!(matches!(
            Node::open(&path),
            Err(NodeError::CorruptLog(message))
                if message.contains("reversible state delta exceeds the wire limit")
        ));
        clean_test_dir(&path);
    }

    #[test]
    fn v2_chain_rejects_changed_reordered_and_deleted_middle_records() {
        let path = test_dir("v2-record-chain");
        clean_test_dir(&path);
        {
            let mut node = Node::open(&path).unwrap();
            let mut parent = node.params.genesis_hash;
            for (offset, seed) in [(1_u64, 0xb1_u8), (2, 0xb2), (3, 0xb3)] {
                let accepted_at = DEVNET_GENESIS_TIMESTAMP + offset * 60;
                let block = mined_child(&node, parent, accepted_at, seed);
                parent = block.block_id();
                node.submit_block(block, accepted_at).unwrap();
            }
        }
        let records = read_complete_log_records(&path);
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|record| {
            u16::from_le_bytes(record[4..6].try_into().unwrap()) == RECORD_VERSION_V2
        }));

        let assert_chain_rejected = |candidate: &[Vec<u8>]| {
            write_complete_log_records(&path, candidate);
            assert!(matches!(
                Node::open(&path),
                Err(NodeError::CorruptLog(message))
                    if message.contains("previous-record digest mismatch")
            ));
        };

        let mut changed = records.clone();
        let accepted_at = u64::from_le_bytes(changed[1][8..16].try_into().unwrap());
        changed[1][8..16].copy_from_slice(&accepted_at.checked_add(1).unwrap().to_le_bytes());
        recompute_fixture_record_checksum(&mut changed[1]);
        assert_chain_rejected(&changed);

        let mut reordered = records.clone();
        reordered.swap(1, 2);
        assert_chain_rejected(&reordered);

        let deleted = vec![records[0].clone(), records[2].clone()];
        assert_chain_rejected(&deleted);
        clean_test_dir(&path);
    }

    #[test]
    fn startup_scan_rejects_a_rechained_child_before_its_parent() {
        let path = test_dir("v2-child-before-parent");
        clean_test_dir(&path);
        {
            let mut node = Node::open(&path).unwrap();
            let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
            let t2 = t1 + 60;
            let first = mined_child(&node, node.params.genesis_hash, t1, 0xba);
            node.submit_block(first.clone(), t1).unwrap();
            let second = mined_child(&node, first.block_id(), t2, 0xbb);
            node.submit_block(second, t2).unwrap();
        }
        let records = read_complete_log_records(&path);
        let (second_at, _, second_block, second_delta) = v2_record_parts(&records[1]);
        let child_first = encode_record_v2(
            second_at,
            second_block,
            second_delta,
            EMPTY_RECORD_CHAIN_ROOT,
        )
        .unwrap();
        let (first_at, _, first_block, first_delta) = v2_record_parts(&records[0]);
        let parent_second = encode_record_v2(
            first_at,
            first_block,
            first_delta,
            complete_record_digest(&child_first),
        )
        .unwrap();
        write_complete_log_records(&path, &[child_first, parent_second]);

        assert!(matches!(
            Node::open(&path),
            Err(NodeError::CorruptLog(message))
                if message.contains("parent that was not accepted earlier")
        ));
        clean_test_dir(&path);
    }

    #[test]
    fn final_replay_snapshot_check_rejects_same_length_post_scan_mutation() {
        let path = test_dir("v2-post-scan-mutation");
        clean_test_dir(&path);
        let params = {
            let mut node = Node::open(&path).unwrap();
            let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
            let block = mined_child(&node, node.params.genesis_hash, accepted_at, 0xbc);
            node.submit_block(block, accepted_at).unwrap();
            node.params
        };
        let log_path = path.join(BLOCK_LOG_FILE);
        let scanned = scan_replay_log(
            File::open(&log_path).unwrap(),
            &log_path,
            params,
            params.network_id,
        )
        .unwrap();
        let mut records = read_complete_log_records(&path);
        let accepted_at = u64::from_le_bytes(records[0][8..16].try_into().unwrap());
        records[0][8..16].copy_from_slice(&(accepted_at + 1).to_le_bytes());
        recompute_fixture_record_checksum(&mut records[0]);
        write_complete_log_records(&path, &records);
        assert_eq!(fs::metadata(&log_path).unwrap().len(), scanned.log_length);

        let error = verify_scanned_replay_log_unchanged(
            &File::open(&log_path).unwrap(),
            &log_path,
            &scanned,
            params.network_id,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            NodeError::CorruptLog(message) if message.contains("changed after its startup scan")
        ));
        clean_test_dir(&path);
    }

    #[test]
    fn retained_log_handle_prevents_same_length_path_substitution_split_brain() {
        let path = test_dir("retained-log-path-a");
        let alternate = test_dir("retained-log-path-b");
        clean_test_dir(&path);
        clean_test_dir(&alternate);
        let (params, verifier, expected_tip) = {
            let mut node = Node::open(&path).unwrap();
            let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
            let block = mined_child(&node, node.params.genesis_hash, accepted_at, 0xbd);
            let expected_tip = block.block_id();
            node.submit_block(block, accepted_at).unwrap();
            (node.params, node.verifier.clone(), expected_tip)
        };
        {
            let mut node = Node::open(&alternate).unwrap();
            let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
            let block = mined_child(&node, node.params.genesis_hash, accepted_at, 0xbe);
            node.submit_block(block, accepted_at).unwrap();
        }
        let log_path = path.join(BLOCK_LOG_FILE);
        let alternate_bytes = fs::read(alternate.join(BLOCK_LOG_FILE)).unwrap();
        let original_bytes = fs::read(&log_path).unwrap();
        assert_eq!(original_bytes.len(), alternate_bytes.len());
        assert_ne!(original_bytes, alternate_bytes);
        let retained = open_block_log(&log_path).unwrap();

        #[cfg(unix)]
        {
            let detached_path = path.join("blocks-a-detached.log");
            fs::rename(&log_path, &detached_path).unwrap();
            fs::write(&log_path, &alternate_bytes).unwrap();
            let mut state = ChainState::new(params, verifier.clone()).unwrap();
            let mut index = BlockIndex::new(params.genesis_hash);
            let error = replay_log(
                &retained, &log_path, &mut state, &mut index, &verifier, params, None,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                NodeError::CorruptLog(message)
                    if message.contains("no longer identifies the retained startup file")
            ));
            assert_eq!(state.tip(), params.genesis_hash);
            assert_ne!(state.tip(), expected_tip);
            assert!(index.blocks.is_empty());
            assert_eq!(index.active_chain, vec![params.genesis_hash]);
            assert_eq!(fs::read(&log_path).unwrap(), alternate_bytes);

            let detached_len = fs::metadata(&detached_path).unwrap().len();
            let mut append = retained.try_clone().unwrap();
            append.write_all(&[0xa5]).unwrap();
            append.sync_all().unwrap();
            assert_eq!(
                fs::metadata(&detached_path).unwrap().len(),
                detached_len + 1
            );
            assert_eq!(fs::read(&log_path).unwrap(), alternate_bytes);
        }

        #[cfg(windows)]
        {
            let detached_path = path.join("blocks-a-detached.log");
            let read_only = OpenOptions::new().read(true).open(&log_path).unwrap();
            drop(read_only);
            assert!(
                OpenOptions::new().append(true).open(&log_path).is_err(),
                "the retained Windows handle must deny a second append writer"
            );
            assert!(
                OpenOptions::new().write(true).open(&log_path).is_err(),
                "the retained Windows handle must deny in-place mutation"
            );
            assert!(
                fs::rename(&log_path, &detached_path).is_err(),
                "the retained Windows handle must deny delete/rename sharing"
            );
            assert_eq!(fs::read(&log_path).unwrap(), original_bytes);
            let mut state = ChainState::new(params, verifier.clone()).unwrap();
            let mut index = BlockIndex::new(params.genesis_hash);
            replay_log(
                &retained, &log_path, &mut state, &mut index, &verifier, params, None,
            )
            .unwrap();
            assert_eq!(state.tip(), expected_tip);
        }

        drop(retained);
        clean_test_dir(&path);
        clean_test_dir(&alternate);
    }

    #[test]
    fn locally_rehashed_forged_delta_fails_exact_revalidation_promotion() {
        const DELTA_FEES_OFFSET: usize = 180;
        const DELTA_LOCAL_INTEGRITY_BYTES: usize = 32;
        const DELTA_LOCAL_INTEGRITY_DOMAIN: &str = "CMFD/REVERSIBLE-STATE-DELTA/LOCAL-INTEGRITY/V1";

        let path = test_dir("v2-forged-delta");
        clean_test_dir(&path);
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let (params, base_tip, child_tip) = {
            let mut node = Node::open(&path).unwrap();
            let base_tip = node.params.genesis_hash;
            let block = mined_child(&node, base_tip, accepted_at, 0xc1);
            let child_tip = block.block_id();
            node.submit_block(block, accepted_at).unwrap();
            (node.params, base_tip, child_tip)
        };
        let records = read_complete_log_records(&path);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        let block_len = u32::from_le_bytes(record[16..20].try_into().unwrap()) as usize;
        let delta_len = u32::from_le_bytes(record[20..24].try_into().unwrap()) as usize;
        let previous_record_digest: [u8; 32] = record[24..56].try_into().unwrap();
        let block_start = RECORD_V2_HEADER_BYTES;
        let delta_start = block_start + block_len;
        let delta_end = delta_start + delta_len;
        let block_bytes = &record[block_start..delta_start];
        let mut forged_delta = record[delta_start..delta_end].to_vec();
        assert!(forged_delta.len() > DELTA_FEES_OFFSET + DELTA_LOCAL_INTEGRITY_BYTES);
        forged_delta[DELTA_FEES_OFFSET] ^= 1;
        let payload_len = forged_delta.len() - DELTA_LOCAL_INTEGRITY_BYTES;
        let mut hasher = Hasher::new_derive_key(DELTA_LOCAL_INTEGRITY_DOMAIN);
        hasher.update(&forged_delta[..payload_len]);
        let digest = *hasher.finalize().as_bytes();
        forged_delta[payload_len..].copy_from_slice(&digest);

        assert!(
            DecodedReversibleStateDelta::decode_bound(&forged_delta, &params, base_tip, child_tip,)
                .is_ok(),
            "the forged fixture must pass structural decoding and local rehashing"
        );
        let forged_record = encode_record_v2(
            accepted_at,
            block_bytes,
            &forged_delta,
            previous_record_digest,
        )
        .unwrap();
        fs::write(path.join(BLOCK_LOG_FILE), forged_record).unwrap();

        assert!(matches!(
            Node::open(&path),
            Err(NodeError::CorruptLog(message))
                if message.contains("does not exactly match the fully validated block")
        ));
        clean_test_dir(&path);
    }

    #[test]
    fn forged_side_branch_delta_fails_dfs_replay_without_installing_partial_state() {
        const DELTA_FEES_OFFSET: usize = 180;

        let path = test_dir("v2-forged-side-delta");
        clean_test_dir(&path);
        let (params, verifier) = {
            let mut node = Node::open(&path).unwrap();
            let genesis = node.params.genesis_hash;
            let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
            let t2 = t1 + 60;
            let a1 = mined_child(&node, genesis, t1, 0xc2);
            node.submit_block(a1.clone(), t1).unwrap();
            let a2 = mined_child(&node, a1.block_id(), t2, 0xc3);
            node.submit_block(a2, t2).unwrap();
            let side = mined_child(&node, genesis, t1, 0xc4);
            node.submit_block(side, t1).unwrap();
            (node.params, node.verifier.clone())
        };
        let mut records = read_complete_log_records(&path);
        assert_eq!(records.len(), 3);
        records[2] = locally_forge_v2_delta(&records[2], DELTA_FEES_OFFSET);
        write_complete_log_records(&path, &records);
        let forged_log = fs::read(path.join(BLOCK_LOG_FILE)).unwrap();

        let mut state = ChainState::new(params, verifier.clone()).unwrap();
        let mut index = BlockIndex::new(params.genesis_hash);
        let log_path = path.join(BLOCK_LOG_FILE);
        let log = open_block_log(&log_path).unwrap();
        let error = replay_log(
            &log, &log_path, &mut state, &mut index, &verifier, params, None,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            NodeError::CorruptLog(message)
                if message.contains("does not exactly match the fully validated block")
        ));
        assert_eq!(state.tip(), params.genesis_hash);
        assert_eq!(state.next_height(), 1);
        assert!(index.blocks.is_empty());
        assert_eq!(index.active_chain, vec![params.genesis_hash]);
        assert_eq!(index.active_work, U512::zero());
        assert_eq!(fs::read(path.join(BLOCK_LOG_FILE)).unwrap(), forged_log);
        drop(log);
        assert!(matches!(Node::open(&path), Err(NodeError::CorruptLog(_))));
        clean_test_dir(&path);
    }

    #[test]
    fn truncated_log_is_refused_instead_of_recovered_silently() {
        let path = test_dir("truncated");
        clean_test_dir(&path);
        {
            let mut node = Node::open(&path).unwrap();
            node.mine_once(
                default_miner_destination(),
                1_800_000_000,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
        let log_path = path.join(BLOCK_LOG_FILE);
        let complete = fs::read(&log_path).unwrap();
        let file = OpenOptions::new().write(true).open(&log_path).unwrap();
        let len = file.metadata().unwrap().len();
        file.set_len(len - 1).unwrap();
        drop(file);

        assert!(matches!(Node::open(&path), Err(NodeError::CorruptLog(_))));

        let mut trailing = complete;
        trailing.push(0);
        fs::write(&log_path, trailing).unwrap();
        assert!(matches!(Node::open(&path), Err(NodeError::CorruptLog(_))));
        clean_test_dir(&path);
    }

    #[test]
    fn checksum_corruption_is_refused() {
        let path = test_dir("checksum");
        clean_test_dir(&path);
        {
            let mut node = Node::open(&path).unwrap();
            node.mine_once(
                default_miner_destination(),
                1_800_000_000,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
        let log_path = path.join(BLOCK_LOG_FILE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&log_path)
            .unwrap();
        let len = file.metadata().unwrap().len();
        file.seek(SeekFrom::Start(len - 1)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(len - 1)).unwrap();
        file.write_all(&[byte[0] ^ 1]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(matches!(Node::open(&path), Err(NodeError::CorruptLog(_))));
        clean_test_dir(&path);
    }

    #[test]
    fn previous_protocol_fingerprint_is_refused_before_nonempty_log_replay() {
        let path = test_dir("fingerprint");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let timestamp = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_child(&node, node.params.genesis_hash, timestamp, 0x91);
        node.submit_block(block, timestamp).unwrap();
        drop(node);
        let metadata_path = path.join(METADATA_FILE);
        let mut metadata = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&metadata_path)
            .unwrap();
        metadata.seek(SeekFrom::Start(8)).unwrap();
        metadata
            .write_all(
                &hex::decode("7ae1b8fadadc6e9316e480968fe2647b3a627df33a1a1c7f7c6c53433a4ff778")
                    .unwrap(),
            )
            .unwrap();
        metadata.sync_all().unwrap();
        drop(metadata);

        assert!(matches!(
            Node::open(&path),
            Err(NodeError::FingerprintMismatch)
        ));
        clean_test_dir(&path);
    }

    #[test]
    fn new_data_directories_get_distinct_persistent_wallet_keys() {
        let first_path = test_dir("wallet-key-first");
        let second_path = test_dir("wallet-key-second");
        clean_test_dir(&first_path);
        clean_test_dir(&second_path);

        let first = Node::open(&first_path).unwrap();
        let first_destination = first.wallet_destination();
        assert_ne!(first_destination, default_miner_destination());
        assert_eq!(
            fs::metadata(first_path.join(WALLET_KEY_FILE))
                .unwrap()
                .len(),
            32
        );
        drop(first);

        let reopened = Node::open(&first_path).unwrap();
        assert_eq!(reopened.wallet_destination(), first_destination);
        assert!(!reopened.legacy_shared_wallet);
        drop(reopened);

        let second = Node::open(&second_path).unwrap();
        assert_ne!(second.wallet_destination(), first_destination);
        assert!(!second.legacy_shared_wallet);
        drop(second);

        clean_test_dir(&first_path);
        clean_test_dir(&second_path);
    }

    #[test]
    fn current_metadata_refuses_a_missing_or_corrupt_wallet_key() {
        let path = test_dir("wallet-key-required");
        clean_test_dir(&path);
        drop(Node::open(&path).unwrap());

        fs::remove_file(path.join(WALLET_KEY_FILE)).unwrap();
        assert!(matches!(
            Node::open(&path),
            Err(NodeError::InvalidWalletKey)
        ));

        fs::write(path.join(WALLET_KEY_FILE), [1_u8; 31]).unwrap();
        assert!(matches!(
            Node::open(&path),
            Err(NodeError::InvalidWalletKey)
        ));

        clean_test_dir(&path);
    }

    #[test]
    fn legacy_metadata_with_blocks_imports_the_shared_key_once() {
        let path = test_dir("wallet-key-legacy");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        node.mine_once(
            default_miner_destination(),
            DEVNET_GENESIS_TIMESTAMP + 60,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        drop(node);

        fs::remove_file(path.join(WALLET_KEY_FILE)).unwrap();
        let metadata_path = path.join(METADATA_FILE);
        let mut metadata = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&metadata_path)
            .unwrap();
        metadata.seek(SeekFrom::Start(6)).unwrap();
        metadata.write_all(&0_u16.to_le_bytes()).unwrap();
        metadata.sync_all().unwrap();
        drop(metadata);

        let migrated = Node::open(&path).unwrap();
        assert_eq!(migrated.wallet_destination(), default_miner_destination());
        assert!(migrated.legacy_shared_wallet);
        assert_eq!(
            migrated.wallet_warning(),
            DEVNET_PROFILE.wallet_warning(true)
        );
        drop(migrated);

        let reopened = Node::open(&path).unwrap();
        assert_eq!(reopened.wallet_destination(), default_miner_destination());
        assert!(reopened.legacy_shared_wallet);
        drop(reopened);

        clean_test_dir(&path);
    }

    #[test]
    fn failed_legacy_replay_does_not_mark_wallet_migration_complete() {
        let path = test_dir("wallet-key-legacy-replay-failure");
        clean_test_dir(&path);
        drop(Node::open(&path).unwrap());

        fs::remove_file(path.join(WALLET_KEY_FILE)).unwrap();
        let metadata_path = path.join(METADATA_FILE);
        let mut metadata = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&metadata_path)
            .unwrap();
        metadata.seek(SeekFrom::Start(6)).unwrap();
        metadata.write_all(&0_u16.to_le_bytes()).unwrap();
        metadata.sync_all().unwrap();
        drop(metadata);
        fs::write(path.join(BLOCK_LOG_FILE), b"corrupt").unwrap();

        assert!(matches!(Node::open(&path), Err(NodeError::CorruptLog(_))));
        let metadata = fs::read(metadata_path).unwrap();
        assert_eq!(&metadata[6..8], &0_u16.to_le_bytes());
        let secret: [u8; 32] = fs::read(path.join(WALLET_KEY_FILE))
            .unwrap()
            .try_into()
            .unwrap();
        let key = SigningKey::from_bytes(&secret).unwrap();
        assert_eq!(
            <[u8; 32]>::from(key.verifying_key().to_bytes()),
            default_miner_destination()
        );

        clean_test_dir(&path);
    }

    #[test]
    fn missing_metadata_cannot_rebind_an_existing_log() {
        let path = test_dir("missing-metadata");
        clean_test_dir(&path);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join(BLOCK_LOG_FILE), b"existing-chain-data").unwrap();

        assert!(matches!(Node::open(&path), Err(NodeError::MissingMetadata)));
        clean_test_dir(&path);
    }

    #[test]
    fn failed_validation_changes_neither_disk_nor_live_state() {
        let path = test_dir("atomic-validation");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let mut block = mined_candidate(&node, 1_800_000_000);
        block.challenge.previous_block = [0xaa; 32];
        let log_len = node.log.metadata().unwrap().len();

        assert!(matches!(
            node.submit_block(block, 1_800_000_000),
            Err(NodeError::UnknownParent(parent)) if parent == [0xaa; 32]
        ));
        assert_eq!(node.state.next_height(), 1);
        assert_eq!(node.log.metadata().unwrap().len(), log_len);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn a_v2_proof_has_the_compact_devnet_shape() {
        let path = test_dir("v2-shape");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let block = mined_candidate(&node, 1_800_000_000);
        let BlockProof::V2Reference(ForgeMatrixV2CompactProof { proof_version, .. }) = block.proof
        else {
            panic!("Devnet-0 must not produce a v1 proof");
        };
        assert_eq!(proof_version, 1);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn rpc_parser_accepts_a_bounded_binary_post() {
        let request = b"POST /v1/block HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\n\r\nabc";
        let parsed = read_rpc_request(&mut &request[..]).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/v1/block");
        assert_eq!(parsed.body, b"abc");
    }

    #[test]
    fn rpc_parser_rejects_oversized_headers_and_bodies() {
        let oversized_header = format!(
            "GET /health HTTP/1.1\r\nX-Padding: {}\r\n\r\n",
            "a".repeat(RPC_HEADER_LIMIT)
        );
        assert!(matches!(
            read_rpc_request(&mut oversized_header.as_bytes()),
            Err(NodeError::InvalidRpcRequest(_))
        ));

        let oversized_body = format!(
            "POST /v1/block HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BLOCK_BYTES + 1
        );
        assert!(matches!(
            read_rpc_request(&mut oversized_body.as_bytes()),
            Err(NodeError::InvalidRpcRequest(_))
        ));

        let oversized_transaction = format!(
            "POST /v1/transaction HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_TRANSACTION_BYTES + 1
        );
        assert!(matches!(
            read_rpc_request(&mut oversized_transaction.as_bytes()),
            Err(NodeError::InvalidRpcRequest(_))
        ));

        for endpoint in ["/v1/wallet/send", "/v1/wallet/consolidate"] {
            let oversized_wallet_request = format!(
                "POST {endpoint} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                WALLET_JSON_BODY_LIMIT + 1
            );
            assert!(matches!(
                read_rpc_request(&mut oversized_wallet_request.as_bytes()),
                Err(NodeError::InvalidRpcRequest(_))
            ));
        }

        let mine_with_body = format!(
            "POST /v1/mine?miner={}&attempts=1 HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
            hex::encode(default_miner_destination())
        );
        assert!(matches!(
            read_rpc_request(&mut mine_with_body.as_bytes()),
            Err(NodeError::InvalidRpcRequest(_))
        ));
    }

    #[test]
    fn mine_query_is_strict_and_attempts_are_capped() {
        let miner = hex::encode(default_miner_destination());
        assert_eq!(
            parse_mine_request(&format!(
                "/v1/mine?attempts={DEFAULT_MINING_ATTEMPTS}&miner={miner}"
            ))
            .unwrap(),
            DevMineRequest {
                miner: miner.clone(),
                attempts: DEFAULT_MINING_ATTEMPTS,
            }
        );
        for target in [
            format!("/v1/mine?miner={miner}"),
            format!("/v1/mine?miner={miner}&miner={miner}&attempts=1"),
            format!("/v1/mine?miner={miner}&attempts=1&extra=1"),
        ] {
            assert!(matches!(
                parse_mine_request(&target),
                Err(NodeError::InvalidRpcRequest(_))
            ));
        }
        for attempts in [0, DEFAULT_MINING_ATTEMPTS + 1] {
            let request =
                parse_mine_request(&format!("/v1/mine?miner={miner}&attempts={attempts}")).unwrap();
            assert!(matches!(
                validate_dev_mine_request(&request),
                Err(NodeError::InvalidRpcRequest(_))
            ));
        }
    }

    #[test]
    fn transport_dtos_preserve_the_json_contract_and_reject_unknown_fields() {
        let send = WalletSendRequest {
            recipient: "ab".repeat(32),
            amount: "1.25000000".to_owned(),
            fee: "0.00000001".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&send).unwrap(),
            json!({
                "recipient": "ab".repeat(32),
                "amount": "1.25000000",
                "fee": "0.00000001",
            })
        );
        assert_eq!(
            serde_json::from_value::<WalletSendRequest>(serde_json::to_value(&send).unwrap())
                .unwrap(),
            send
        );
        assert!(
            serde_json::from_value::<WalletSendRequest>(json!({
                "recipient": "ab".repeat(32),
                "amount": "1",
                "fee": "0.00000001",
                "extra": true,
            }))
            .is_err()
        );

        let consolidation = WalletConsolidateRequest {
            fee: "0.00001000".to_owned(),
            max_inputs: 128,
        };
        assert_eq!(
            serde_json::to_value(&consolidation).unwrap(),
            json!({"fee": "0.00001000", "max_inputs": 128})
        );
        assert!(
            serde_json::from_value::<WalletConsolidateRequest>(json!({
                "fee": "0.00001000",
                "max_inputs": 128,
                "extra": true,
            }))
            .is_err()
        );

        let mine = DevMineRequest {
            miner: "cd".repeat(32),
            attempts: 42,
        };
        assert_eq!(
            serde_json::to_value(&mine).unwrap(),
            json!({"miner": "cd".repeat(32), "attempts": 42})
        );
        assert!(
            serde_json::from_value::<DevMineRequest>(json!({
                "miner": "cd".repeat(32),
                "attempts": 42,
                "extra": true,
            }))
            .is_err()
        );

        let mempool = MempoolSnapshot {
            transactions: 1,
            bytes: 99,
            entries: vec![MempoolSnapshotEntry {
                txid: "ef".repeat(32),
                encoded_bytes: 99,
                fee_burned: 7,
                fee_burned_atoms: "7".to_owned(),
            }],
        };
        assert_eq!(
            serde_json::to_value(&mempool).unwrap(),
            json!({
                "transactions": 1,
                "bytes": 99,
                "entries": [{
                    "txid": "ef".repeat(32),
                    "encoded_bytes": 99,
                    "fee_burned": 7,
                    "fee_burned_atoms": "7",
                }],
            })
        );

        let mined = DevMineResult {
            accepted: true,
            block_id: "01".repeat(32),
            height: 3,
            tip: "01".repeat(32),
        };
        assert_eq!(
            serde_json::to_value(&mined).unwrap(),
            json!({
                "accepted": true,
                "block_id": "01".repeat(32),
                "height": 3,
                "tip": "01".repeat(32),
            })
        );
    }

    #[test]
    fn client_errors_are_stable_and_redact_storage_details() {
        let raw_error = NodeError::Io {
            operation: "read private wallet",
            path: PathBuf::from(r"C:\secret-wallet\seed.txt"),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "credential=do-not-leak"),
        };
        let classified = raw_error.client_error();
        assert_eq!(classified.code, "storage_io");
        assert_eq!(classified.status, 500);
        assert!(!classified.retryable);
        assert_eq!(
            classified.message,
            "node storage operation failed; inspect the node logs"
        );
        assert!(!classified.message.contains("secret-wallet"));
        assert!(!classified.message.contains("credential"));
        assert_eq!(
            serde_json::to_value(&classified).unwrap(),
            json!({
                "code": "storage_io",
                "status": 500,
                "retryable": false,
                "message": "node storage operation failed; inspect the node logs",
            })
        );

        let response = RpcResponse::node_error(raw_error);
        assert_eq!(response.status, 500);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
            json!({"error": "node storage operation failed; inspect the node logs"})
        );

        let immature = NodeError::WalletFundsImmature {
            immature: 20,
            required: 30,
        }
        .client_error();
        assert_eq!(immature.code, "wallet_funds_immature");
        assert_eq!(immature.status, 422);
        assert!(immature.retryable);
        assert_eq!(
            immature.message,
            "wallet funds are immature: 20 atoms immature, 30 atoms required"
        );

        let faulted = NodeError::StorageFaulted.client_error();
        assert_eq!(faulted.code, "storage_faulted");
        assert_eq!(faulted.status, 503);
        assert!(!faulted.retryable);
    }

    #[test]
    fn transport_neutral_methods_share_validation_without_mutating_the_node() {
        let path = test_dir("transport-method-validation");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();

        assert!(matches!(
            node.send_from_dev_wallet_request(WalletSendRequest {
                recipient: "00".to_owned(),
                amount: "1".to_owned(),
                fee: "0.00000001".to_owned(),
            }),
            Err(NodeError::InvalidWalletRecipient)
        ));
        assert!(matches!(
            node.consolidate_dev_wallet_request(WalletConsolidateRequest {
                fee: "0.00001000".to_owned(),
                max_inputs: 1,
            }),
            Err(NodeError::InvalidConsolidationMaxInputs)
        ));
        assert!(matches!(
            node.mine_devnet_request(DevMineRequest {
                miner: hex::encode(default_miner_destination()),
                attempts: 0,
            }),
            Err(NodeError::InvalidRpcRequest(_))
        ));
        assert!(matches!(
            node.mine_devnet_request(DevMineRequest {
                miner: hex::encode(default_miner_destination()),
                attempts: DEFAULT_MINING_ATTEMPTS + 1,
            }),
            Err(NodeError::InvalidRpcRequest(_))
        ));

        assert_eq!(
            node.mempool_snapshot(),
            MempoolSnapshot {
                transactions: 0,
                bytes: 0,
                entries: Vec::new(),
            }
        );
        assert_eq!(node.status().unwrap().accepted_height, 0);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn rpc_parser_rejects_truncation_and_transfer_encoding() {
        let truncated = b"POST /v1/block HTTP/1.1\r\nContent-Length: 4\r\n\r\nabc";
        assert!(matches!(
            read_rpc_request(&mut &truncated[..]),
            Err(NodeError::InvalidRpcRequest(_))
        ));

        let chunked = b"POST /v1/block HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(
            read_rpc_request(&mut &chunked[..]),
            Err(NodeError::InvalidRpcRequest(_))
        ));
    }

    #[test]
    fn health_route_reports_a_storage_fault() {
        let path = test_dir("health");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let request = || RpcRequest {
            method: "GET".to_owned(),
            target: "/health".to_owned(),
            content_type: None,
            body: Vec::new(),
        };

        let healthy = route_rpc_request(request(), &mut node);
        assert_eq!(healthy.status, 200);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&healthy.body).unwrap()["ok"],
            true
        );

        node.storage_faulted = true;
        let faulted = route_rpc_request(request(), &mut node);
        assert_eq!(faulted.status, 503);
        let body: serde_json::Value = serde_json::from_slice(&faulted.body).unwrap();
        assert_eq!(body["ok"], false);
        assert_eq!(body["storage_healthy"], false);
        assert!(!node.status().unwrap().storage_healthy);
        let template = route_rpc_request(
            RpcRequest {
                method: "GET".to_owned(),
                target: format!(
                    "/v1/template?miner={}",
                    hex::encode(default_miner_destination())
                ),
                content_type: None,
                body: Vec::new(),
            },
            &mut node,
        );
        assert_eq!(template.status, 503);
        assert!(matches!(
            node.build_template(default_miner_destination(), 1_800_000_000),
            Err(NodeError::StorageFaulted)
        ));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn rpc_reader_enforces_an_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let mut reader = DeadlineReader::new(&mut server, Duration::ZERO);
        let error = read_rpc_request(&mut reader).unwrap_err();
        assert!(matches!(
            error,
            NodeError::RpcIo(ref source) if source.kind() == io::ErrorKind::TimedOut
        ));
        drop(client);
    }

    #[test]
    fn block_route_decodes_validates_persists_and_applies() {
        let path = test_dir("block-route");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let now = unix_time_seconds().unwrap();
        let template = node
            .build_template(default_miner_destination(), now)
            .unwrap();
        let proof = node
            .verifier
            .mine(&template.challenge, 0, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let block = Block {
            version: BLOCK_VERSION,
            challenge: template.challenge,
            proof,
            coinbase: template.coinbase,
            transactions: Vec::new(),
        };
        let request = RpcRequest {
            method: "POST".to_owned(),
            target: "/v1/block".to_owned(),
            content_type: Some("application/octet-stream".to_owned()),
            body: encode_block(&block).unwrap(),
        };

        let response = route_rpc_request(request, &mut node);
        assert_eq!(response.status, 200);
        assert_eq!(node.state.next_height(), 2);
        assert!(node.log.metadata().unwrap().len() > 0);
        drop(node);

        let replayed = Node::open(&path).unwrap();
        assert_eq!(replayed.status().unwrap().accepted_height, 1);
        drop(replayed);
        clean_test_dir(&path);
    }

    #[test]
    fn shared_block_route_preverifies_then_submits_through_the_atomic_path() {
        let path = test_dir("shared-block-route");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let now = unix_time_seconds().unwrap();
        let block = mined_candidate(&node, now);
        let request = RpcRequest {
            method: "POST".to_owned(),
            target: "/v1/block".to_owned(),
            content_type: Some("application/octet-stream".to_owned()),
            body: encode_block(&block).unwrap(),
        };
        let shared = Arc::new(Mutex::new(node));

        let response = route_shared_block_request(request, &shared);
        assert_eq!(response.status, 200);
        let node = shared.lock().unwrap();
        assert_eq!(node.state.tip(), block.block_id());
        assert_eq!(node.state.next_height(), 2);
        assert!(node.log.metadata().unwrap().len() > 0);
        drop(node);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn transaction_mempool_and_dev_mine_routes_form_a_loopback_mining_flow() {
        let path = test_dir("mempool-routes");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let now = unix_time_seconds().unwrap();
        let funding = node
            .mine_once(default_miner_destination(), now, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let transaction = spend_coinbase_output(&node, &funding, 2, 0x12, 0x79, 10);
        let txid = transaction.txid();
        let encoded = encode_transaction(&transaction).unwrap();

        let submitted = route_rpc_request(
            RpcRequest {
                method: "POST".to_owned(),
                target: "/v1/transaction".to_owned(),
                content_type: Some("application/octet-stream; charset=binary".to_owned()),
                body: encoded,
            },
            &mut node,
        );
        assert_eq!(submitted.status, 200);
        let submitted_body: serde_json::Value = serde_json::from_slice(&submitted.body).unwrap();
        assert_eq!(submitted_body["txid"], hex::encode(txid));
        assert_eq!(submitted_body["fee_burned"], 10);

        let direct_snapshot = serde_json::to_value(node.mempool_snapshot()).unwrap();
        let listed = route_rpc_request(
            RpcRequest {
                method: "GET".to_owned(),
                target: "/v1/mempool".to_owned(),
                content_type: None,
                body: Vec::new(),
            },
            &mut node,
        );
        assert_eq!(listed.status, 200);
        let listed_body: serde_json::Value = serde_json::from_slice(&listed.body).unwrap();
        assert_eq!(listed_body, direct_snapshot);
        assert_eq!(listed_body["transactions"], 1);
        assert_eq!(listed_body["entries"][0]["txid"], hex::encode(txid));
        assert_eq!(listed_body["entries"][0]["fee_burned"], 10);
        assert_eq!(listed_body["entries"][0]["fee_burned_atoms"], "10");
        assert!(listed_body["entries"][0]["fee_burned_atoms"].is_string());

        let mined = route_rpc_request(
            RpcRequest {
                method: "POST".to_owned(),
                target: format!(
                    "/v1/mine?miner={}&attempts={DEFAULT_MINING_ATTEMPTS}",
                    hex::encode(default_miner_destination())
                ),
                content_type: None,
                body: Vec::new(),
            },
            &mut node,
        );
        assert_eq!(mined.status, 200);
        let mined_body: serde_json::Value = serde_json::from_slice(&mined.body).unwrap();
        let block_id = mined_body["block_id"].as_str().unwrap().to_owned();
        assert_eq!(block_id.len(), 64);
        assert_eq!(
            mined_body,
            json!({
                "accepted": true,
                "block_id": block_id,
                "height": 2,
                "tip": block_id,
            })
        );
        assert!(node.mempool.is_empty());
        assert_eq!(node.mempool_bytes, 0);
        drop(node);
        clean_test_dir(&path);
    }

    fn mine_default_chain_to(node: &mut Node, height: u64) -> Vec<Block> {
        let mut blocks = Vec::new();
        while node.state.next_height() <= height {
            let block_height = node.state.next_height();
            let destination = node.wallet_destination();
            blocks.push(
                node.mine_once(
                    destination,
                    DEVNET_GENESIS_TIMESTAMP + block_height * 60,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap(),
            );
        }
        blocks
    }

    fn wallet_post(target: &str, value: serde_json::Value) -> RpcRequest {
        RpcRequest {
            method: "POST".to_owned(),
            target: target.to_owned(),
            content_type: Some("application/json; charset=utf-8".to_owned()),
            body: serde_json::to_vec(&value).unwrap(),
        }
    }

    fn synthetic_outpoint(order: u16) -> OutPoint {
        let mut txid = [0_u8; 32];
        txid[..2].copy_from_slice(&order.to_be_bytes());
        OutPoint { txid, index: 0 }
    }

    #[test]
    fn send_selection_finds_a_large_coin_beyond_the_old_128_outpoint_prefix() {
        let mut candidates: Vec<_> = (0..129)
            .map(|order| (synthetic_outpoint(order), 1_u64))
            .collect();
        let large = OutPoint {
            txid: [0xff; 32],
            index: 0,
        };
        candidates.push((large, 1_000));

        let mut old_outpoint_order = candidates.clone();
        old_outpoint_order.sort_unstable_by(|left, right| {
            left.0
                .txid
                .cmp(&right.0.txid)
                .then_with(|| left.0.index.cmp(&right.0.index))
        });
        let old_prefix_value: u64 = old_outpoint_order
            .iter()
            .take(MAX_TRANSACTION_INPUTS)
            .map(|(_, value)| value)
            .sum();
        assert_eq!(old_prefix_value, MAX_TRANSACTION_INPUTS as u64);
        assert!(old_prefix_value < 1_000);

        let selection = select_send_utxos(candidates.clone(), 1_000).unwrap();
        assert_eq!(selection.outpoints, vec![large]);
        assert_eq!(selection.selected_value, 1_000);
        assert_eq!(selection.available, 1_129);

        candidates.reverse();
        assert_eq!(select_send_utxos(candidates, 1_000).unwrap(), selection);
    }

    #[test]
    fn send_selection_uses_outpoint_ties_deterministically_and_caps_inputs() {
        let equal_value_candidates = vec![
            (synthetic_outpoint(3), 1_000),
            (synthetic_outpoint(1), 1_000),
            (synthetic_outpoint(2), 1_000),
        ];
        let selection = select_send_utxos(equal_value_candidates, 1_500).unwrap();
        assert_eq!(
            selection.outpoints,
            vec![synthetic_outpoint(1), synthetic_outpoint(2)]
        );
        assert_eq!(selection.selected_value, 2_000);

        let candidates: Vec<_> = (0..130)
            .rev()
            .map(|order| (synthetic_outpoint(order), 10_u64))
            .collect();
        let capped = select_send_utxos(candidates, 1_290).unwrap();
        assert_eq!(capped.outpoints.len(), MAX_TRANSACTION_INPUTS);
        assert_eq!(capped.selected_value, 1_280);
        assert_eq!(capped.available, 1_300);
        assert_eq!(capped.outpoints.first(), Some(&synthetic_outpoint(0)));
        assert_eq!(capped.outpoints.last(), Some(&synthetic_outpoint(127)));
    }

    #[test]
    fn wallet_starts_empty_and_serializes_only_string_atom_values() {
        let path = test_dir("wallet-empty");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();

        let snapshot = node.wallet_snapshot().unwrap();
        assert_eq!(snapshot.accepted_height, 0);
        assert_eq!(snapshot.next_height, 1);
        assert_eq!(snapshot.balances.spendable_atoms, "0");
        assert_eq!(snapshot.balances.immature_atoms, "0");
        assert_eq!(snapshot.balances.pending_atoms, "0");
        assert_eq!(snapshot.spendable_utxo_count, 0);
        assert_eq!(snapshot.immature_utxo_count, 0);
        assert_eq!(snapshot.reserved_utxo_count, 0);
        assert!(snapshot.history.is_empty());
        assert_eq!(snapshot.destination, hex::encode(node.wallet_destination()));

        let response = route_rpc_request(
            RpcRequest {
                method: "GET".to_owned(),
                target: "/v1/wallet".to_owned(),
                content_type: None,
                body: Vec::new(),
            },
            &mut node,
        );
        assert_eq!(response.status, 200);
        let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        for field in ["spendable_atoms", "immature_atoms", "pending_atoms"] {
            assert!(value["balances"][field].is_string());
        }
        let serialized = String::from_utf8(response.body).unwrap();
        assert!(serialized.contains("Devnet-0 test wallet"));
        let wallet_secret = hex::encode(fs::read(path.join(WALLET_KEY_FILE)).unwrap());
        assert!(!serialized.contains(&wallet_secret));
        assert!(!serialized.contains(&hex::encode([0x13; 32])));

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn wallet_coinbase_is_immature_until_next_height_101() {
        let path = test_dir("wallet-maturity");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let first = mine_default_chain_to(&mut node, 1).remove(0);
        let first_reward = first.coinbase.outputs[0].value;

        let early = node.wallet_snapshot().unwrap();
        assert_eq!(early.next_height, 2);
        assert_eq!(early.balances.spendable_atoms, "0");
        assert_eq!(early.balances.immature_atoms, first_reward.to_string());
        assert_eq!(early.immature_utxo_count, 1);
        assert_eq!(early.history[0].status, "immature");

        mine_default_chain_to(&mut node, 99);
        let through_100 = node.wallet_snapshot().unwrap();
        assert_eq!(through_100.next_height, 100);
        assert_eq!(through_100.balances.spendable_atoms, "0");
        assert_eq!(through_100.immature_utxo_count, 99);

        mine_default_chain_to(&mut node, 100);
        let mature = node.wallet_snapshot().unwrap();
        assert_eq!(mature.next_height, 101);
        assert_eq!(mature.balances.spendable_atoms, first_reward.to_string());
        assert_eq!(mature.spendable_utxo_count, 1);
        assert_eq!(mature.immature_utxo_count, 99);
        assert_eq!(mature.history.len(), MAX_WALLET_HISTORY);
        assert_eq!(mature.history[0].height, Some(100));

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn wallet_send_reserves_burns_confirms_and_reconstructs_after_restart() {
        let path = test_dir("wallet-send-restart");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let first = mine_default_chain_to(&mut node, 100).remove(0);
        let input_atoms = first.coinbase.outputs[0].value;
        let recipient = insecure_dev_destination(0x79);
        let amount = COIN;
        let fee = 1_u64;

        let response = route_rpc_request(
            wallet_post(
                "/v1/wallet/send",
                json!({
                    "recipient": hex::encode(recipient),
                    "amount": "1.00000000",
                    "fee": "0.00000001",
                }),
            ),
            &mut node,
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["amount_atoms"].is_string());
        assert!(body["fee_burned_atoms"].is_string());
        assert!(body["change_atoms"].is_string());
        assert_eq!(body["amount_atoms"], amount.to_string());
        assert_eq!(body["fee_burned_atoms"], fee.to_string());
        assert_eq!(
            body["change_atoms"],
            (input_atoms - amount - fee).to_string()
        );
        let entry = node.mempool.values().next().unwrap();
        assert_eq!(body["txid"], hex::encode(entry.txid));
        assert_eq!(entry.transaction.txid(), entry.txid);
        assert_eq!(entry.fee_burned, fee);

        let pending = node.wallet_snapshot().unwrap();
        assert_eq!(pending.spendable_utxo_count, 0);
        assert_eq!(pending.reserved_utxo_count, 1);
        assert_eq!(pending.balances.spendable_atoms, "0");
        assert_eq!(
            pending.balances.pending_atoms,
            (input_atoms - amount - fee).to_string()
        );
        assert_eq!(pending.history[0].kind, "sent");
        assert_eq!(pending.history[0].status, "pending");
        assert_eq!(
            pending.history[0].net_amount_atoms,
            format!("-{}", amount + fee)
        );
        assert_eq!(pending.history[0].fee_burned_atoms, fee.to_string());
        assert_eq!(
            pending.history[0].counterparty,
            Some(hex::encode(recipient))
        );

        let confirmed_block = node
            .mine_once(
                node.wallet_destination(),
                DEVNET_GENESIS_TIMESTAMP + 101 * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        assert_eq!(confirmed_block.transactions.len(), 1);
        assert_eq!(
            hex::encode(confirmed_block.transactions[0].txid()),
            body["txid"]
        );
        assert!(node.mempool.is_empty());
        let confirmed = node.wallet_snapshot().unwrap();
        let tx_history = confirmed
            .history
            .iter()
            .find(|item| item.txid == body["txid"])
            .unwrap();
        assert_eq!(tx_history.status, "confirmed");
        assert_eq!(tx_history.height, Some(101));
        assert_eq!(tx_history.fee_burned_atoms, "1");
        drop(node);

        let mut replayed = Node::open(&path).unwrap();
        assert_eq!(replayed.wallet_snapshot().unwrap(), confirmed);
        drop(replayed);
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(!bytes.windows(32).any(|window| window == [0x13; 32]));
            }
        }
        clean_test_dir(&path);
    }

    #[test]
    fn wallet_send_rejects_invalid_requests_without_mempool_mutation() {
        let path = test_dir("wallet-send-invalid");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let recipient = hex::encode(insecure_dev_destination(0x71));

        for (value, expected_status) in [
            (
                json!({"recipient": "00", "amount": "1", "fee": "0.00000001"}),
                400,
            ),
            (
                json!({"recipient": recipient, "amount": "0", "fee": "0.00000001"}),
                400,
            ),
            (
                json!({"recipient": recipient, "amount": "1.000000001", "fee": "0.00000001"}),
                400,
            ),
            (
                json!({"recipient": recipient, "amount": "184467440737.09551616", "fee": "0.00000001"}),
                400,
            ),
            (
                json!({"recipient": recipient, "amount": "1", "fee": "0.00000001", "extra": true}),
                400,
            ),
            (
                json!({"recipient": recipient, "amount": "1", "fee": "0.00000001"}),
                422,
            ),
        ] {
            let response = route_rpc_request(wallet_post("/v1/wallet/send", value), &mut node);
            assert_eq!(response.status, expected_status);
            assert!(node.mempool.is_empty());
        }

        mine_default_chain_to(&mut node, 1);
        let immature = route_rpc_request(
            wallet_post(
                "/v1/wallet/send",
                json!({"recipient": recipient, "amount": "1", "fee": "0.00000001"}),
            ),
            &mut node,
        );
        assert_eq!(immature.status, 422);
        assert!(
            String::from_utf8(immature.body)
                .unwrap()
                .contains("immature")
        );

        let insufficient = route_rpc_request(
            wallet_post(
                "/v1/wallet/send",
                json!({"recipient": recipient, "amount": "1000", "fee": "0.00000001"}),
            ),
            &mut node,
        );
        assert_eq!(insufficient.status, 422);
        assert!(
            String::from_utf8(insufficient.body)
                .unwrap()
                .contains("insufficient")
        );

        mine_default_chain_to(&mut node, 100);
        let too_low = route_rpc_request(
            wallet_post(
                "/v1/wallet/send",
                json!({"recipient": recipient, "amount": "1", "fee": "0"}),
            ),
            &mut node,
        );
        assert_eq!(too_low.status, 422);
        assert!(
            String::from_utf8(too_low.body)
                .unwrap()
                .contains("relay minimum")
        );
        assert!(node.mempool.is_empty());

        let wrong_type = route_rpc_request(
            RpcRequest {
                method: "POST".to_owned(),
                target: "/v1/wallet/send".to_owned(),
                content_type: Some("text/plain".to_owned()),
                body: b"{}".to_vec(),
            },
            &mut node,
        );
        assert_eq!(wrong_type.status, 415);

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn wallet_history_marks_external_payments_received_and_then_confirmed() {
        let path = test_dir("wallet-received");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let funding = mine_default_chain_to(&mut node, 1).remove(0);
        let received = spend_coinbase_to(&node, &funding, 1, 0x11, node.wallet_destination(), 10);
        let received_txid = received.txid();
        let received_atoms = received.outputs[0].value;
        node.submit_transaction(received).unwrap();

        let pending = node.wallet_snapshot().unwrap();
        let item = pending
            .history
            .iter()
            .find(|item| item.txid == hex::encode(received_txid))
            .unwrap();
        assert_eq!(item.kind, "received");
        assert_eq!(item.status, "pending");
        assert_eq!(item.net_amount_atoms, received_atoms.to_string());
        assert_eq!(item.fee_burned_atoms, "10");
        assert_eq!(
            item.counterparty,
            Some(hex::encode(insecure_dev_destination(0x11)))
        );

        node.mine_once(
            node.wallet_destination(),
            DEVNET_GENESIS_TIMESTAMP + 120,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        drop(node);
        let mut node = Node::open(&path).unwrap();
        let confirmed = node.wallet_snapshot().unwrap();
        let item = confirmed
            .history
            .iter()
            .find(|item| item.txid == hex::encode(received_txid))
            .unwrap();
        assert_eq!(item.kind, "received");
        assert_eq!(item.status, "confirmed");
        assert_eq!(item.height, Some(2));
        assert_eq!(item.confirmations, 1);

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn wallet_snapshot_tracks_the_active_branch_after_reorg() {
        let path = test_dir("wallet-reorg");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let active = mine_default_chain_to(&mut node, 1).remove(0);
        assert_eq!(
            node.wallet_snapshot().unwrap().balances.immature_atoms,
            active.coinbase.outputs[0].value.to_string()
        );

        let sibling = mined_child(
            &node,
            DEVNET_GENESIS_HASH,
            DEVNET_GENESIS_TIMESTAMP + 61,
            0x51,
        );
        node.submit_block(sibling.clone(), DEVNET_GENESIS_TIMESTAMP + 61)
            .unwrap();
        assert_eq!(node.state.tip(), active.block_id());
        assert_ne!(node.state.tip(), sibling.block_id());
        let sibling_child = mined_child(
            &node,
            sibling.block_id(),
            DEVNET_GENESIS_TIMESTAMP + 121,
            0x52,
        );
        node.submit_block(sibling_child.clone(), DEVNET_GENESIS_TIMESTAMP + 121)
            .unwrap();
        assert_eq!(node.state.tip(), sibling_child.block_id());

        let reorged = node.wallet_snapshot().unwrap();
        assert_eq!(reorged.accepted_height, 2);
        assert_eq!(reorged.balances.spendable_atoms, "0");
        assert_eq!(reorged.balances.immature_atoms, "0");
        assert_eq!(reorged.balances.pending_atoms, "0");
        assert!(reorged.history.is_empty());

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn wallet_consolidation_uses_at_most_128_smallest_unreserved_mature_outputs() {
        let path = test_dir("wallet-consolidate");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let first = mine_default_chain_to(&mut node, 100).remove(0);
        let first_outpoint = OutPoint {
            txid: first.coinbase_outpoint_id(),
            index: 0,
        };
        let first_value = first.coinbase.outputs[0].value;
        let split_fee = 1_000_u64;
        let split_total = first_value - split_fee;
        let per_output = split_total / MAX_TRANSACTION_INPUTS as u64;
        let remainder = split_total % MAX_TRANSACTION_INPUTS as u64;
        let mut split = Transaction {
            network_id: node.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: first_outpoint,
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: Vec::new(),
                },
            }],
            outputs: (0..MAX_TRANSACTION_INPUTS)
                .map(|index| TxOutput {
                    value: per_output + u64::from(index == 0) * remainder,
                    lock: OutputLock::Key(node.wallet_destination()),
                    spendable_height: node.state.next_height(),
                })
                .collect(),
        };
        split.sign_all(&[&node.wallet_signing_key]).unwrap();
        node.submit_transaction(split).unwrap();
        node.mine_once(
            node.wallet_destination(),
            DEVNET_GENESIS_TIMESTAMP + 101 * 60,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        let before = node.wallet_snapshot().unwrap();
        assert_eq!(before.spendable_utxo_count, MAX_TRANSACTION_INPUTS + 1);
        assert!(before.immature_utxo_count > 0);
        assert_eq!(before.reserved_utxo_count, 0);

        assert!(matches!(
            node.consolidate_dev_wallet(1_000, 1),
            Err(NodeError::InvalidConsolidationMaxInputs)
        ));
        assert!(matches!(
            node.consolidate_dev_wallet(1_000, MAX_TRANSACTION_INPUTS + 1),
            Err(NodeError::InvalidConsolidationMaxInputs)
        ));
        assert!(matches!(
            node.consolidate_dev_wallet(0, MAX_TRANSACTION_INPUTS),
            Err(NodeError::MempoolFeeTooLow { .. })
        ));
        assert!(node.mempool.is_empty());

        let invalid_max = route_rpc_request(
            wallet_post(
                "/v1/wallet/consolidate",
                json!({"fee": "0.00001000", "max_inputs": 1}),
            ),
            &mut node,
        );
        assert_eq!(invalid_max.status, 400);
        let response = route_rpc_request(
            wallet_post(
                "/v1/wallet/consolidate",
                json!({"fee": "0.00001000", "max_inputs": MAX_TRANSACTION_INPUTS}),
            ),
            &mut node,
        );
        assert_eq!(response.status, 200);
        let response_body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response_body["inputs_consolidated"], MAX_TRANSACTION_INPUTS);
        assert_eq!(response_body["fee_burned_atoms"], "1000");
        for field in ["input_atoms", "output_atoms", "fee_burned_atoms"] {
            assert!(response_body[field].is_string());
        }
        let entry = node.mempool.values().next().unwrap();
        assert_eq!(response_body["txid"], hex::encode(entry.txid));
        assert_eq!(entry.transaction.inputs.len(), MAX_TRANSACTION_INPUTS);
        assert_eq!(entry.transaction.outputs.len(), 1);
        assert_eq!(
            entry.transaction.outputs[0].lock,
            OutputLock::Key(node.wallet_destination())
        );
        let input_atoms = response_body["input_atoms"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let output_atoms = response_body["output_atoms"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(input_atoms, split_total);
        assert_eq!(input_atoms, output_atoms + 1_000);
        assert_eq!(entry.transaction.outputs[0].value, output_atoms);

        let reserved = node.wallet_snapshot().unwrap();
        assert_eq!(reserved.reserved_utxo_count, MAX_TRANSACTION_INPUTS);
        assert_eq!(reserved.spendable_utxo_count, 1);
        assert_eq!(reserved.balances.pending_atoms, output_atoms.to_string());
        assert!(matches!(
            node.consolidate_dev_wallet(1_000, MAX_TRANSACTION_INPUTS),
            Err(NodeError::WalletNotEnoughUtxos(1))
        ));
        let serialized = String::from_utf8(response.body).unwrap();
        assert!(!serialized.contains(&hex::encode([0x13; 32])));

        drop(node);
        clean_test_dir(&path);
    }
}
