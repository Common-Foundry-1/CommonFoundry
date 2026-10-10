use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use blake3::Hasher;
#[cfg(feature = "production-v4")]
use cmfd_consensus::ForgeMatrixV4FixedArtifactRecordV1;
use cmfd_consensus::PowParameters;
use cmfd_consensus::chain::{ReversibleStateDeltaCapability, ValidatedBlock};
use cmfd_consensus::{
    BLOCK_VERSION, Block, BlockChallenge, BlockProof, BlockValidationContext, COIN, ChainError,
    ChainState, Coinbase, ConsensusPowVerifier, DEFAULT_MONETARY_POLICY,
    DecodedReversibleStateDelta, EconomicsError, FixedRewardDestinations, ForgeMatrixError,
    ForgeMatrixV2AcceleratorBatch, ForgeMatrixV2AcceleratorModel, ForgeMatrixV2Error, InputWitness,
    MAX_BLOCK_BYTES, MAX_CHAIN_STATE_SNAPSHOT_BYTES, MAX_FUTURE_OFFSET_SECS,
    MAX_REVERSIBLE_STATE_DELTA_BYTES, MAX_TRANSACTION_BYTES, MAX_TRANSACTION_INPUTS,
    NETWORK_PROTOCOL_VERSION, NetworkError, NetworkParams, OutPoint, OutputLock, PowError,
    PreverifiedBlockProof, ReversibleStateDeltaError, SuccessorHeaderPreflight,
    TRANSACTION_VERSION, Transaction, TxInput, TxOutput, WireError, add_chain_work,
    chain_work_bytes, decode_block, decode_transaction, encode_block, encode_transaction,
    max_block_bytes_for_network, merkle_root, v2_reference_for_network, validate_block_preamble,
    validate_block_resources,
};
#[cfg(feature = "production-v3")]
use cmfd_consensus::{
    ForgeMatrixV3AcceleratorBatch, ForgeMatrixV3CandidateParameters,
    ForgeMatrixV3WinningNonceClaim, MAX_PRODUCTION_V3_NATIVE_BLOCK_ROWS,
    PreparedForgeMatrixV3Model,
};
use cmfd_proof_worker::{
    PersistentVerifierWorker, ProofWorkerError, VerifierWorkerConfig, VerifierWorkerError,
};
pub use cmfd_proof_worker::{ProductionV3VerifierArtifacts, ProductionV3VerifierRecord};
use fs2::FileExt;
use k256::schnorr::{SigningKey, VerifyingKey};
use primitive_types::U512;
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(feature = "production-v4")]
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(windows)]
pub(crate) mod exchange_acl;
pub mod exchange_acl_qualification;
pub(crate) mod exchange_archive;
pub(crate) mod exchange_custody_engine;
#[cfg(test)]
mod exchange_custody_rehearsal;
pub(crate) mod exchange_custody_runtime_v3;
pub use exchange_custody_runtime_v3::ExchangeCustodyV3Config;
#[cfg(all(test, feature = "production-v4-testnet", target_os = "linux"))]
mod difficulty_gpu_rehearsal;
pub mod exchange_custody_tools;
pub(crate) mod exchange_custody_v3;
pub(crate) mod exchange_index;
pub(crate) mod exchange_local_signer;
pub(crate) mod exchange_policy;
pub(crate) mod exchange_queries;
pub mod exchange_rpc;
pub(crate) mod exchange_signer;
pub mod exchange_tx_tool;
pub mod exchange_wallet;
pub mod exchange_wallet_rpc;
pub mod exchange_wallet_upstream;
pub(crate) mod exchange_withdrawal;
pub(crate) mod exchange_withdrawal_v3;
pub mod explorer;
pub mod explorer_address;
mod explorer_address_index;
#[cfg(test)]
mod explorer_address_tests;
mod explorer_index;
#[cfg(test)]
mod explorer_index_qualification;
#[cfg(test)]
mod explorer_recovery_qualification;
#[cfg(all(test, feature = "production-v4"))]
mod explorer_resource_qualification;
#[cfg(test)]
mod fast_startup_tests;
mod history_scrub;
pub mod logging;
#[cfg(feature = "production-v4")]
pub mod mainnet_custody;
pub mod mainnet_runtime;
pub mod network_info;
pub mod network_profile;
pub mod p2p;
pub mod peer;
pub mod pool;
pub mod pool_dashboard;
#[cfg(feature = "production-v4")]
pub mod production_v4_pool;
mod pruning;
#[cfg(test)]
mod pruning_tests;
#[cfg(feature = "production-v4")]
pub mod rcnet_candidate;
#[cfg(all(test, feature = "production-v4"))]
mod real_fork_checkpoint_tests;
pub mod seed_peers;
pub use history_scrub::{HistoryScrub, spawn_history_scrub};
use pruning::StoredBlock;
pub use pruning::{
    MIN_PRUNE_KEEP_BLOCKS, PRUNE_CHECK_INTERVAL, PruneReport, PrunerHandle, prune_shared_node,
    prune_shared_node_until_stopped, spawn_pruner,
};
mod startup_snapshot;
pub mod storage;
pub mod wallet_backup;
mod wallet_history;
pub mod wallet_keyring;
pub mod wallet_signing_protocol;

#[path = "../release_gate.rs"]
#[allow(dead_code)]
mod release_gate;

pub use network_info::{
    canonical_network_info_json, canonical_network_info_json_with_artifacts,
    canonical_network_info_json_with_record, canonical_network_info_json_with_v4_artifacts,
};
pub use network_profile::{
    COMPILED_NETWORK_PROFILE, DEVNET_PROFILE, NetworkProfile, NetworkProfileKind,
    PRODUCTION_V3_TESTNET_PROFILE, PRODUCTION_V4_TESTNET_PROFILE, ProofProfile, RCNET1_PROFILE,
};

pub const DEVNET_NETWORK_ID: [u8; 32] = COMPILED_NETWORK_PROFILE.network_id;
/// Compile-time template only. Mainnet intentionally has a zero value here
/// before activation; obtain its authenticated genesis from the launched
/// [`Node::network_profile`] or [`mainnet_runtime::AuthenticatedMainnetRuntime`].
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
/// Maximum active-plus-waiting remote proof admissions. This is deliberately
/// smaller than the listener's hard connection bound so honest non-proof P2P
/// traffic retains headroom while the verifier is saturated.
pub const MAX_REMOTE_PROOF_ADMISSIONS: usize = 8;
/// Cooldown memory covers every concurrently live P2P session. Entries are
/// removed only after their TTL; an unexpired identity is never evicted to
/// make room for reconnect churn.
const MAX_REMOTE_PROOF_COOLDOWNS: usize = crate::peer::MAX_CONFIGURED_PEERS;
/// A remote verifier waiter has its own deadline, independent of worker
/// startup and request timeouts. Sixty seconds tolerates honest queue bursts
/// without pinning a session through a slow worker restart.
pub const REMOTE_PROOF_ADMISSION_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
/// A session that consumed the verifier with a deterministically invalid proof
/// cannot immediately take another turn.
const INVALID_REMOTE_PROOF_COOLDOWN: Duration = Duration::from_secs(30);
/// A disconnected P2P session is removed from the remote FIFO promptly without
/// changing the honest-load admission deadline.
const REMOTE_PROOF_CANCELLATION_POLL: Duration = Duration::from_millis(25);
pub const MAX_REJECTED_BLOCK_IDS: usize = 1_024;
pub const MAX_SUCCESSFUL_PROOF_CAPABILITIES: usize = 1_024;
pub const MAX_EXTERNAL_RECONSTRUCTION_BLOCKS_PER_SLICE: usize = 8;
/// Concurrent proof checks while pre-warming one fork-replay slice.
const MAX_PARALLEL_REPLAY_PROOF_VERIFICATIONS: usize = 4;
/// Node-wide concurrency for pre-warming proofs of blocks a sync session
/// fetched itself (never for blocks peers push unsolicited): one core is left
/// to the ordinary verifier and the node's own work.
pub const MAX_PARALLEL_FETCHED_PROOF_VERIFICATIONS: usize = 4;
const MAX_QUEUED_FETCHED_PROOF_VERIFICATIONS: usize = 32;
const FETCHED_PROOF_VERIFICATION_QUEUE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BRANCH_STATE_CHECKPOINTS: usize = 4;
const MAX_BRANCH_STATE_CHECKPOINT_BYTES: usize = 128 * 1024 * 1024;
const ACTIVE_BRANCH_CHECKPOINT_INTERVAL: u64 = 16;
const BRANCH_CHECKPOINT_RETURN_WAIT: Duration = Duration::from_millis(250);
pub const PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY: &str = "production-v3";
pub const PRODUCTION_V3_PACKAGE_BANK: &str = "MODEL-V2.bank";
pub const PRODUCTION_V3_PACKAGE_MANIFEST: &str = "MODEL-V2.manifest.json";
pub const PRODUCTION_V3_PACKAGE_RECORD_V2: &str = "DORY-V3-MODEL-RECORD-V2.json";
pub const PRODUCTION_V4_PACKAGE_ARTIFACT_DIRECTORY: &str = "production-v4";
pub const PRODUCTION_V4_PACKAGE_BANK: &str = "MODEL-V2.bank";
pub const PRODUCTION_V4_PACKAGE_FIXED_RECORD: &str = "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionV4VerifierArtifacts {
    pub bank: PathBuf,
    pub fixed_record: PathBuf,
}

pub fn production_v4_package_artifacts(
    executable: &Path,
) -> Result<ProductionV4VerifierArtifacts, NodeError> {
    let directory = executable
        .parent()
        .ok_or(NodeError::ProductionV4ArtifactsMissing)?;
    let artifacts = directory.join(PRODUCTION_V4_PACKAGE_ARTIFACT_DIRECTORY);
    Ok(ProductionV4VerifierArtifacts {
        bank: artifacts.join(PRODUCTION_V4_PACKAGE_BANK),
        fixed_record: artifacts.join(PRODUCTION_V4_PACKAGE_FIXED_RECORD),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionV3PackageLayout {
    pub worker: PathBuf,
    pub record: ProductionV3VerifierRecord,
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
    // Archive extraction leaves the sidecar directory with permissive default
    // permissions that the trusted filesystem gates reject, so a package
    // launched through its bare executable heals its own directory the same
    // way the packaged launcher scripts do. Best effort by design: the gates
    // stay the deciders, and a directory this cannot repair fails closed
    // there with its own diagnostics.
    if artifacts.is_dir() {
        let _ = cmfd_proof_worker::make_packaged_artifact_directory_private(&artifacts);
    }
    let expected_file = compiled_production_v3_record_identity()?;
    Ok(ProductionV3PackageLayout {
        worker: directory.join(format!("cmfd-proof-worker{}", std::env::consts::EXE_SUFFIX)),
        record: ProductionV3VerifierRecord {
            record_v2: artifacts.join(PRODUCTION_V3_PACKAGE_RECORD_V2),
            expected_file,
        },
    })
}

/// Reduces a canonicalized sidecar path to the plain `D:\...` form the trusted
/// ceremony filesystem accepts.
///
/// `std::fs::canonicalize` always returns a `\\?\` verbatim path on Windows,
/// and [`dory_v3_model_ceremony_fs`] deliberately rejects verbatim, UNC, and
/// device syntax, so a packaged ProductionV3 node or wallet would otherwise
/// refuse its own sidecars. Only a verbatim *disk* prefix is reduced; verbatim
/// UNC and every other prefix are returned untouched so they still fail closed.
///
/// [`dory_v3_model_ceremony_fs`]: cmfd_consensus::dory_v3_model_ceremony_fs
#[cfg(windows)]
#[must_use]
pub fn plain_package_path(path: PathBuf) -> PathBuf {
    use std::path::{Component, Prefix};

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path;
    };
    let Prefix::VerbatimDisk(drive) = prefix.kind() else {
        return path;
    };
    let mut plain = PathBuf::from(format!("{}:\\", char::from(drive)));
    for component in components {
        if !matches!(component, Component::RootDir) {
            plain.push(component.as_os_str());
        }
    }
    plain
}

/// Non-Windows canonical paths already have the plain form.
#[cfg(not(windows))]
#[must_use]
pub fn plain_package_path(path: PathBuf) -> PathBuf {
    path
}

pub fn compiled_production_v3_record_identity() -> Result<cmfd_consensus::FileIdentity, NodeError> {
    let pin = release_gate::COMPILED_RELEASE_PROFILE
        .production_v3_artifacts
        .ok_or(NodeError::ProductionV3ArtifactPinsMissing)?
        .record_v2;
    if pin.bytes == 0 || pin.blake3 == [0; 32] || pin.sha256 == [0; 32] {
        return Err(NodeError::ProductionV3ArtifactPinsMissing);
    }
    Ok(production_v3_file_identity_from_pin(pin))
}

pub(crate) fn production_v3_record_from_artifacts(
    artifacts: &ProductionV3VerifierArtifacts,
) -> Result<ProductionV3VerifierRecord, NodeError> {
    Ok(ProductionV3VerifierRecord {
        record_v2: artifacts.record_v2.clone(),
        expected_file: compiled_production_v3_record_identity()?,
    })
}

pub(crate) fn production_v3_record_for_profile(
    profile: NetworkProfile,
    artifacts: Option<&ProductionV3VerifierArtifacts>,
) -> Result<Option<ProductionV3VerifierRecord>, NodeError> {
    match (profile.proof, artifacts) {
        (ProofProfile::DevnetV2Reference, Some(_)) => {
            Err(NodeError::ProductionV3ArtifactsUnexpected)
        }
        (ProofProfile::DevnetV2Reference, None) => Ok(None),
        (ProofProfile::ProductionV3, Some(artifacts)) => {
            production_v3_record_from_artifacts(artifacts).map(Some)
        }
        (ProofProfile::ProductionV3, None) => Ok(None),
        (ProofProfile::ProductionV4, Some(_)) => Err(NodeError::ProductionV3ArtifactsUnexpected),
        (ProofProfile::ProductionV4, None) => Ok(None),
    }
}

fn production_v3_file_identity_from_pin(
    pin: release_gate::ProductionV3FileIdentityPin,
) -> cmfd_consensus::FileIdentity {
    cmfd_consensus::FileIdentity {
        bytes: pin.bytes,
        blake3: pin.blake3,
        sha256: pin.sha256,
    }
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
    let configured_for_v3 = config.production_v3_record.is_some();
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
        let record = config
            .production_v3_record
            .as_ref()
            .ok_or(NodeError::ProofVerifierProfileMismatch)?;
        let pins = release_gate::COMPILED_RELEASE_PROFILE
            .production_v3_artifacts
            .ok_or(NodeError::ProductionV3ArtifactPinsMissing)?;
        require_production_v3_file_identity("Record V2", pins.record_v2, &record.expected_file)?;
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
/// V2 plus a DEFLATE-compressed block: the V2 header, then the uncompressed
/// block length. `block_len` in the header is the compressed length.
const RECORD_VERSION_V3: u16 = 3;
const RECORD_V3_HEADER_BYTES: usize = RECORD_V2_HEADER_BYTES + 4;
const RECORD_V3_CHECKSUM_DOMAIN: &str = "CMFD/NODE/BLOCK-RECORD/V3";
/// A pruned record: the V3 layout carrying a compressed pruned body (header,
/// coinbase, transactions and proof summary) instead of the full block.
const RECORD_VERSION_PRUNED: u16 = 4;
const RECORD_PRUNED_CHECKSUM_DOMAIN: &str = "CMFD/NODE/BLOCK-RECORD/V4-PRUNED";
const BLOCK_LOG_COMPRESSION_LEVEL: u32 = 6;
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
const EXCHANGE_RPC_JSON_BODY_LIMIT: usize = MAX_TRANSACTION_BYTES * 2 + 16 * 1024;
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
        "the compiled ProductionV3 network requires the production V3 proof verifier; the tiny Devnet V2 relation is never used as a fallback"
    )]
    ProductionV3Unavailable,
    #[error(
        "the compiled ProductionV3 network verification requires an explicit release-pinned production V3 Record V2 path"
    )]
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
    #[error("production V3 retained mining-bank state is poisoned")]
    ProductionV3MiningStatePoisoned,
    #[cfg(feature = "production-v3")]
    #[error("production V3 verifier artifacts failed authentication: {0}")]
    ProductionV3Artifacts(
        #[source]
        cmfd_consensus::dory_v3_model_bank_record_validation::ProductionDoryV3ModelBankRecordValidationError,
    ),
    #[error("the compiled ProductionV4 network requires its in-process verifier authority")]
    ProductionV4Unavailable,
    #[error("mainnet awaits its verified launch beacon: October 3, 2026 at 17:00 UTC (noon US Central)")]
    MainnetLaunchRequired,
    #[error("mainnet launch evidence is invalid: {0}")]
    MainnetLaunchEvidence(&'static str),
    #[error(
        "ProductionV4 runtime files are missing: production-v4/MODEL-V2.bank and production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
    )]
    ProductionV4ArtifactsMissing,
    #[error("ProductionV4 verifier artifacts were supplied for another proof profile")]
    ProductionV4ArtifactsUnexpected,
    #[error("the compiled ProductionV4 artifact identity pins are absent or invalid")]
    ProductionV4ArtifactPinsMissing,
    #[error("compiled ProductionV4 activation evidence is invalid: {0}")]
    ProductionV4ActivationEvidence(&'static str),
    #[error("the authenticated ProductionV4 {0} does not match its compiled identity pin")]
    ProductionV4ArtifactIdentityMismatch(&'static str),
    #[error("offline RCNet-1 ProductionV4 qualification invariant failed: {0}")]
    ProductionV4QualificationInvariant(&'static str),
    #[error("network metadata is missing while a nonempty block log already exists")]
    MissingMetadata,
    #[error("data directory belongs to a different immutable network fingerprint")]
    FingerprintMismatch,
    #[error("wallet key is missing, corrupt, or unsupported")]
    InvalidWalletKey,
    #[error("encrypted wallet key requires a valid passphrase")]
    WalletLocked,
    #[error("RCNet requires an encrypted live wallet key")]
    WalletKeyEncryptionRequired,
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
    #[error("explorer address must be a 64-character hexadecimal key destination")]
    InvalidExplorerAddress,
    #[error("explorer cursor is invalid for this address")]
    InvalidExplorerCursor,
    #[error("the chain tip changed; restart address pagination from the first page")]
    StaleExplorerCursor,
    #[error("mining search attempts must be between 1 and {MAX_MINING_SEARCH_ATTEMPTS}")]
    InvalidMiningSearchAttempts,
    #[error("mining share target must be easier than or equal to the immutable block target")]
    InvalidMiningShareTarget,
    #[error("RPC bind address must be loopback, received {0}")]
    NonLoopbackRpc(SocketAddr),
    #[error("an exchange RPC listener is already active for this node")]
    ExchangeRpcAlreadyActive,
    #[error("exchange RPC authentication file is invalid: {0}")]
    InvalidExchangeRpcAuthFile(&'static str),
    #[error("exchange RPC authentication file permissions must be 0600 or stricter")]
    InsecureExchangeRpcAuthFilePermissions,
    #[error("exchange deposit index startup failed ({code}): {message}")]
    ExchangeDepositIndex {
        code: &'static str,
        retryable: bool,
        message: String,
    },
    #[error("exchange withdrawal journal startup failed ({code}): {message}")]
    ExchangeWithdrawalJournal {
        code: &'static str,
        retryable: bool,
        message: String,
    },
    #[error(
        "native wallet mutation is disabled while exchange custody v3 exclusively owns the wallet"
    )]
    ExchangeCustodyV3WalletExclusive,
    #[error(
        "block storage is faulted after an append or sync failure; restart only after inspecting the log"
    )]
    StorageFaulted,
    #[error("block is already indexed: {0:?}")]
    DuplicateBlock([u8; 32]),
    #[error("block parent is not indexed: {0:?}")]
    UnknownParent([u8; 32]),
    #[error("block {} was pruned; this node no longer stores its proof", hex::encode(.0))]
    BlockProofPruned([u8; 32]),
    #[error(
        "block builds on {} below this node's prune point; a pruned node cannot follow a reorganization that deep",
        hex::encode(.0)
    )]
    BelowPrunePoint([u8; 32]),
    #[error("invalid prune setting: {0}")]
    InvalidPruneSetting(String),
    #[error("block admission snapshot became stale while proof verification was in progress")]
    StaleBlockAdmission,
    #[error("block was already rejected by deterministic consensus validation: {0:?}")]
    CachedInvalidBlock([u8; 32]),
    #[error("fork state reconstruction exceeded its bounded work slice; retry the candidate")]
    ForkReconstructionDeferred,
    #[error("transaction is already in the mempool: {0:?}")]
    DuplicateMempoolTransaction([u8; 32]),
    #[error("transaction input {}:{} conflicts with the first mempool spend", hex::encode(.0.txid), .0.index)]
    MempoolInputConflict(OutPoint),
    #[error("transaction input {}:{} is not an unspent output on the active chain", hex::encode(.0.txid), .0.index)]
    MempoolUnconfirmedInput(OutPoint),
    #[error("transaction input is reserved by the exchange withdrawal journal: {0:?}")]
    ExchangeWithdrawalInputReserved(OutPoint),
    #[error("exchange withdrawal transaction does not match its input reservation: {0:?}")]
    ExchangeWithdrawalReservationMismatch(OutPoint),
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
    #[error("wallet payment plan is invalid: {0}")]
    InvalidWalletPaymentPlan(&'static str),
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
            | Self::ProductionV3MiningStatePoisoned
            | Self::ProofVerifierProfileMismatch => ("proof_verifier_configuration", 500, false),
            #[cfg(feature = "production-v3")]
            Self::ProductionV3Artifacts(_) => ("proof_verifier_configuration", 500, false),
            Self::ProductionV4Unavailable => ("production_v4_unavailable", 503, false),
            Self::MainnetLaunchRequired => ("mainnet_launch_required", 503, true),
            Self::MainnetLaunchEvidence(_) => ("mainnet_launch_evidence", 500, false),
            Self::ProductionV4ArtifactsMissing => ("production_v4_artifacts_missing", 500, false),
            Self::ProductionV4ArtifactsUnexpected
            | Self::ProductionV4ArtifactPinsMissing
            | Self::ProductionV4ActivationEvidence(_)
            | Self::ProductionV4ArtifactIdentityMismatch(_)
            | Self::ProductionV4QualificationInvariant(_) => {
                ("proof_verifier_configuration", 500, false)
            }
            Self::MissingMetadata => ("missing_metadata", 500, false),
            Self::FingerprintMismatch => ("fingerprint_mismatch", 409, false),
            Self::InvalidWalletKey => ("invalid_wallet_key", 500, false),
            Self::WalletLocked => ("wallet_locked", 423, false),
            Self::WalletKeyEncryptionRequired => ("wallet_key_encryption_required", 500, false),
            Self::CorruptLog(_) => ("corrupt_block_log", 500, false),
            Self::ProductionLegacyBlockLog(_) => ("production_legacy_block_log", 500, false),
            Self::LegacyReplayResourceLimit { .. } => ("legacy_replay_resource_limit", 500, false),
            Self::InvalidSystemTime => ("invalid_system_time", 500, false),
            Self::TemplateTimeUnavailable => ("template_time_unavailable", 503, true),
            Self::InvalidMinerDestination => ("invalid_miner_destination", 400, false),
            Self::InvalidExplorerAddress => ("invalid_explorer_address", 400, false),
            Self::InvalidExplorerCursor => ("invalid_explorer_cursor", 400, false),
            Self::StaleExplorerCursor => ("explorer_cursor_stale", 409, true),
            Self::InvalidMiningSearchAttempts => ("invalid_mining_search_attempts", 400, false),
            Self::InvalidMiningShareTarget => ("invalid_mining_share_target", 400, false),
            Self::NonLoopbackRpc(_) => ("non_loopback_rpc", 400, false),
            Self::ExchangeRpcAlreadyActive => ("exchange_rpc_already_active", 409, false),
            Self::InvalidExchangeRpcAuthFile(_) => ("invalid_exchange_rpc_auth_file", 400, false),
            Self::InsecureExchangeRpcAuthFilePermissions => {
                ("insecure_exchange_rpc_auth_file_permissions", 400, false)
            }
            Self::ExchangeDepositIndex {
                code, retryable, ..
            } => (*code, 500, *retryable),
            Self::ExchangeWithdrawalJournal {
                code, retryable, ..
            } => (*code, 500, *retryable),
            Self::ExchangeCustodyV3WalletExclusive => {
                ("exchange_custody_v3_wallet_exclusive", 409, false)
            }
            Self::StorageFaulted => ("storage_faulted", 503, false),
            Self::DuplicateBlock(_) => ("duplicate_block", 409, false),
            Self::UnknownParent(_) => ("unknown_parent", 422, true),
            Self::BlockProofPruned(_) => ("block_proof_pruned", 404, false),
            Self::BelowPrunePoint(_) => ("below_prune_point", 409, false),
            Self::InvalidPruneSetting(_) => ("invalid_prune_setting", 400, false),
            Self::StaleBlockAdmission => ("stale_block_admission", 409, true),
            Self::CachedInvalidBlock(_) => ("cached_invalid_block", 422, false),
            Self::ForkReconstructionDeferred => ("fork_reconstruction_deferred", 503, true),
            Self::DuplicateMempoolTransaction(_) => ("duplicate_mempool_transaction", 409, false),
            Self::MempoolInputConflict(_) => ("mempool_input_conflict", 409, false),
            Self::MempoolUnconfirmedInput(_) => ("mempool_unconfirmed_input", 422, true),
            Self::ExchangeWithdrawalInputReserved(_) => {
                ("exchange_withdrawal_input_reserved", 409, false)
            }
            Self::ExchangeWithdrawalReservationMismatch(_) => {
                ("exchange_withdrawal_reservation_mismatch", 409, false)
            }
            Self::MempoolTransactionLimit => ("mempool_transaction_limit", 422, true),
            Self::MempoolByteLimit => ("mempool_byte_limit", 422, true),
            Self::MempoolFeeTooLow { .. } => ("mempool_fee_too_low", 422, false),
            Self::InvalidWalletRecipient => ("invalid_wallet_recipient", 400, false),
            Self::InvalidWalletAmount => ("invalid_wallet_amount", 400, false),
            Self::WalletAmountOverflow => ("wallet_amount_overflow", 400, false),
            Self::WalletZeroAmount => ("wallet_zero_amount", 400, false),
            Self::InvalidWalletPaymentPlan(_) => ("invalid_wallet_payment_plan", 500, false),
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
            Self::ProofVerifierWorker(VerifierWorkerError::DispatchedRequest(error))
                if matches!(
                    error.as_ref(),
                    VerifierWorkerError::Process(ProofWorkerError::Timeout { .. })
                ) =>
            {
                ("proof_verifier_timeout", 503, true)
            }
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
            Self::ProductionV4ArtifactsMissing => {
                if COMPILED_NETWORK_PROFILE.kind == NetworkProfileKind::Mainnet {
                    "required ProductionV4 runtime files are missing; complete mainnet runtime setup before starting the node".to_owned()
                } else {
                    "required ProductionV4 runtime files are missing; complete RCNet runtime setup before starting the node".to_owned()
                }
            }
            Self::CorruptLog(_) => {
                "block log is corrupt; inspect the node logs before restarting".to_owned()
            }
            Self::NonLoopbackRpc(_) => "RPC must remain bound to loopback".to_owned(),
            Self::InvalidExchangeRpcAuthFile(_) => {
                "exchange RPC authentication file is invalid".to_owned()
            }
            Self::InsecureExchangeRpcAuthFilePermissions => {
                "exchange RPC authentication file permissions are too broad".to_owned()
            }
            Self::ExchangeDepositIndex { message, .. } => message.clone(),
            Self::ExchangeWithdrawalJournal { message, .. } => message.clone(),
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
    normal_active: usize,
    priority_active: usize,
    closing: bool,
    normal_queued: usize,
    priority_queued: usize,
    next_normal_ticket: u64,
    serving_normal_ticket: u64,
    cancelled_normal_tickets: HashSet<u64>,
    next_priority_ticket: u64,
    serving_priority_ticket: u64,
    cancelled_priority_tickets: HashSet<u64>,
    normal_wait_events: u64,
    priority_wait_events: u64,
    normal_rejections: u64,
    priority_rejections: u64,
    normal_proof_failures: u64,
    priority_proof_failures: u64,
}

#[derive(Clone, Copy)]
enum ProofQueueClass {
    Normal,
    Priority,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ProofAdmissionClassTelemetry {
    pub active: usize,
    pub queued: usize,
    pub wait_events: u64,
    /// Admission failures before a verifier request begins, including full,
    /// duplicate, deadline, cooldown, and shutdown rejections.
    pub rejections: u64,
    /// Proof or request-scoped verifier failures after admission. This is
    /// separate from `rejections` so saturation remains observable.
    pub proof_failures: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct ProofQueueTelemetry {
    normal: ProofAdmissionClassTelemetry,
    priority: ProofAdmissionClassTelemetry,
}

#[derive(Debug)]
struct ProofVerificationQueue {
    state: Mutex<ProofVerificationQueueState>,
    wake: Condvar,
    max_active: usize,
    max_queued: usize,
    wait_timeout: Duration,
    #[cfg(test)]
    deadline_wake_barrier: Mutex<Option<Arc<DeadlineWakeBarrier>>>,
}

#[cfg(test)]
#[derive(Debug)]
struct DeadlineWakeBarrier {
    entered: Barrier,
    release: Barrier,
}

#[cfg(test)]
impl DeadlineWakeBarrier {
    #[cfg_attr(
        any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
        allow(dead_code)
    )]
    fn new() -> Self {
        Self {
            entered: Barrier::new(2),
            release: Barrier::new(2),
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitPausePoint {
    AfterDeadlineCheck,
    AfterTransition,
}

#[cfg(test)]
#[derive(Debug)]
struct CommitRaceBarrier {
    point: CommitPausePoint,
    entered: Barrier,
    release: Barrier,
}

#[cfg(test)]
impl CommitRaceBarrier {
    #[cfg_attr(
        any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
        allow(dead_code)
    )]
    fn new(point: CommitPausePoint) -> Self {
        Self {
            point,
            entered: Barrier::new(2),
            release: Barrier::new(2),
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct CompletionFaultBarrier {
    entered: Barrier,
    release: Barrier,
}

#[cfg(test)]
impl CompletionFaultBarrier {
    #[cfg_attr(
        any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
        allow(dead_code)
    )]
    fn new() -> Self {
        Self {
            entered: Barrier::new(2),
            release: Barrier::new(2),
        }
    }
}

impl ProofVerificationQueue {
    fn new(max_active: usize, max_queued: usize, wait_timeout: Duration) -> Self {
        assert!(max_active > 0, "proof verification needs active capacity");
        Self {
            state: Mutex::new(ProofVerificationQueueState {
                active: 0,
                normal_active: 0,
                priority_active: 0,
                closing: false,
                normal_queued: 0,
                priority_queued: 0,
                next_normal_ticket: 0,
                serving_normal_ticket: 0,
                cancelled_normal_tickets: HashSet::new(),
                next_priority_ticket: 0,
                serving_priority_ticket: 0,
                cancelled_priority_tickets: HashSet::new(),
                normal_wait_events: 0,
                priority_wait_events: 0,
                normal_rejections: 0,
                priority_rejections: 0,
                normal_proof_failures: 0,
                priority_proof_failures: 0,
            }),
            wake: Condvar::new(),
            max_active,
            max_queued,
            wait_timeout,
            #[cfg(test)]
            deadline_wake_barrier: Mutex::new(None),
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<ProofVerificationPermit, NodeError> {
        self.acquire_class(ProofQueueClass::Normal, Some(self.wait_timeout), None)
    }

    fn acquire_cancellable(
        self: &Arc<Self>,
        request: RemoteProofRequest,
    ) -> Result<ProofVerificationPermit, NodeError> {
        // A remote request carries its own bounded acceptance deadline, and
        // remote admission already limits how many can wait. A fully received
        // block must not be discarded after the short local queue timeout
        // merely because a local block is being verified.
        self.acquire_class(ProofQueueClass::Normal, None, Some(request))
    }

    fn acquire_priority(self: &Arc<Self>) -> Result<ProofVerificationPermit, NodeError> {
        // A locally found block is already the result of expensive work. Once
        // admitted to the bounded priority lane, wait until it is served or
        // terminal shutdown wakes it instead of discarding it behind a slow
        // remote verification or worker restart.
        self.acquire_class(ProofQueueClass::Priority, None, None)
    }

    fn acquire_class(
        self: &Arc<Self>,
        class: ProofQueueClass,
        wait_timeout: Option<Duration>,
        request: Option<RemoteProofRequest>,
    ) -> Result<ProofVerificationPermit, NodeError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
        if state.closing {
            record_proof_queue_rejection(&mut state, class);
            return Err(NodeError::ProofVerifierShuttingDown);
        }
        if remote_proof_cancelled(request.as_ref()) {
            record_proof_queue_rejection(&mut state, class);
            return Err(NodeError::ProofVerificationQueueTimeout);
        }
        if state.active < self.max_active && state.normal_queued == 0 && state.priority_queued == 0
        {
            state.active += 1;
            record_proof_queue_active(&mut state, class, true);
            return Ok(ProofVerificationPermit {
                queue: Arc::clone(self),
                class,
                proof_failed: false,
            });
        }
        let ticket = match class {
            ProofQueueClass::Normal => {
                if state.normal_queued >= self.max_queued {
                    record_proof_queue_rejection(&mut state, class);
                    return Err(NodeError::ProofVerificationQueueFull);
                }
                let ticket = state.next_normal_ticket;
                state.next_normal_ticket = state.next_normal_ticket.wrapping_add(1);
                state.normal_queued += 1;
                ticket
            }
            ProofQueueClass::Priority => {
                if state.priority_queued >= MAX_PRIORITY_QUEUED_PROOF_VERIFICATIONS {
                    record_proof_queue_rejection(&mut state, class);
                    return Err(NodeError::ProofVerificationQueueFull);
                }
                let ticket = state.next_priority_ticket;
                state.next_priority_ticket = state.next_priority_ticket.wrapping_add(1);
                state.priority_queued += 1;
                ticket
            }
        };
        record_proof_queue_wait(&mut state, class);
        let waiting = |state: &ProofVerificationQueueState| {
            !state.closing
                && (state.active >= self.max_active
                    || match class {
                        ProofQueueClass::Normal => {
                            state.priority_queued != 0 || state.serving_normal_ticket != ticket
                        }
                        ProofQueueClass::Priority => state.serving_priority_ticket != ticket,
                    })
        };
        let timeout_deadline = match wait_timeout {
            Some(timeout) => match checked_queue_deadline(Instant::now(), timeout) {
                Ok(deadline) => Some(deadline),
                Err(error) => {
                    cancel_proof_ticket(&mut state, class, ticket);
                    record_proof_queue_rejection(&mut state, class);
                    self.wake.notify_all();
                    return Err(error);
                }
            },
            None => None,
        };
        let deadline = match (timeout_deadline, request.as_ref()) {
            (Some(timeout), Some(request)) => Some(timeout.min(request.deadline())),
            (Some(timeout), None) => Some(timeout),
            (None, Some(request)) => Some(request.deadline()),
            (None, None) => None,
        };
        loop {
            if state.closing {
                cancel_proof_ticket(&mut state, class, ticket);
                record_proof_queue_rejection(&mut state, class);
                self.wake.notify_all();
                return Err(NodeError::ProofVerifierShuttingDown);
            }
            if remote_proof_cancelled(request.as_ref()) {
                cancel_proof_ticket(&mut state, class, ticket);
                record_proof_queue_rejection(&mut state, class);
                self.wake.notify_all();
                return Err(NodeError::ProofVerificationQueueTimeout);
            }
            if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    cancel_proof_ticket(&mut state, class, ticket);
                    record_proof_queue_rejection(&mut state, class);
                    self.wake.notify_all();
                    return Err(NodeError::ProofVerificationQueueTimeout);
                }
            }
            if !waiting(&state) {
                break;
            }
            if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let poll = if request.is_some() {
                    remaining.min(REMOTE_PROOF_CANCELLATION_POLL)
                } else {
                    remaining
                };
                let (next_state, _) = self
                    .wake
                    .wait_timeout_while(state, poll, |state| {
                        waiting(state) && !remote_proof_cancelled(request.as_ref())
                    })
                    .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
                state = next_state;
                #[cfg(test)]
                if let Some(barrier) = self
                    .deadline_wake_barrier
                    .lock()
                    .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?
                    .take()
                {
                    drop(state);
                    barrier.entered.wait();
                    barrier.release.wait();
                    state = self
                        .state
                        .lock()
                        .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
                }
            } else {
                state = self
                    .wake
                    .wait_while(state, |state| waiting(state))
                    .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
            }
        }
        serve_proof_ticket(&mut state, class);
        state.active += 1;
        record_proof_queue_active(&mut state, class, true);
        self.wake.notify_all();
        Ok(ProofVerificationPermit {
            queue: Arc::clone(self),
            class,
            proof_failed: false,
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

    fn telemetry(&self) -> Result<ProofQueueTelemetry, NodeError> {
        self.state
            .lock()
            .map(|state| ProofQueueTelemetry {
                normal: ProofAdmissionClassTelemetry {
                    active: state.normal_active,
                    queued: state.normal_queued,
                    wait_events: state.normal_wait_events,
                    rejections: state.normal_rejections,
                    proof_failures: state.normal_proof_failures,
                },
                priority: ProofAdmissionClassTelemetry {
                    active: state.priority_active,
                    queued: state.priority_queued,
                    wait_events: state.priority_wait_events,
                    rejections: state.priority_rejections,
                    proof_failures: state.priority_proof_failures,
                },
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

fn record_proof_queue_active(
    state: &mut ProofVerificationQueueState,
    class: ProofQueueClass,
    acquired: bool,
) {
    let active = match class {
        ProofQueueClass::Normal => &mut state.normal_active,
        ProofQueueClass::Priority => &mut state.priority_active,
    };
    if acquired {
        *active = active.saturating_add(1);
    } else {
        *active = active.saturating_sub(1);
    }
}

fn record_proof_queue_wait(state: &mut ProofVerificationQueueState, class: ProofQueueClass) {
    let waits = match class {
        ProofQueueClass::Normal => &mut state.normal_wait_events,
        ProofQueueClass::Priority => &mut state.priority_wait_events,
    };
    *waits = waits.saturating_add(1);
}

fn record_proof_queue_rejection(state: &mut ProofVerificationQueueState, class: ProofQueueClass) {
    let rejections = match class {
        ProofQueueClass::Normal => &mut state.normal_rejections,
        ProofQueueClass::Priority => &mut state.priority_rejections,
    };
    *rejections = rejections.saturating_add(1);
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
    class: ProofQueueClass,
    proof_failed: bool,
}

impl ProofVerificationPermit {
    fn mark_proof_failure(&mut self) {
        self.proof_failed = true;
    }
}

impl Drop for ProofVerificationPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.queue.state.lock() {
            state.active = state.active.saturating_sub(1);
            record_proof_queue_active(&mut state, self.class, false);
            if self.proof_failed {
                let failures = match self.class {
                    ProofQueueClass::Normal => &mut state.normal_proof_failures,
                    ProofQueueClass::Priority => &mut state.priority_proof_failures,
                };
                *failures = failures.saturating_add(1);
            }
            self.queue.wake.notify_all();
        }
    }
}

/// Process-local P2P session identity assigned by the receiving node. It is
/// never supplied by the peer and does not change the wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RemoteProofPeerId(u64);

impl RemoteProofPeerId {
    pub(crate) fn new(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }
}

/// Linearized lifetime for one inbound proof-bearing block request. The
/// deadline is server-owned; a disconnect/deadline cancellation and the
/// durable append race through the same atomic transition. A provisional
/// `Committing` reservation is rechecked against the deadline; once that
/// recheck succeeds, durability either completes or the node latches a
/// storage fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum RemoteProofRequestState {
    Active = 0,
    Cancelled = 1,
    Committing = 2,
    Completed = 3,
    Faulted = 4,
}

impl RemoteProofRequestState {
    fn load(value: u8) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::Cancelled,
            2 => Self::Committing,
            3 => Self::Completed,
            _ => Self::Faulted,
        }
    }
}

#[derive(Debug)]
struct RemoteProofRequestInner {
    state: AtomicU8,
    deadline: Instant,
}

/// Server-owned lifetime for one inbound proof-bearing block request. The
/// peer cannot extend the deadline and disconnect observation can only shorten
/// it by winning `Active -> Cancelled` before the commit reservation wins.
#[derive(Clone, Debug)]
pub(crate) struct RemoteProofRequest {
    inner: Arc<RemoteProofRequestInner>,
}

impl RemoteProofRequest {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            inner: Arc::new(RemoteProofRequestInner {
                state: AtomicU8::new(RemoteProofRequestState::Active as u8),
                deadline,
            }),
        }
    }

    fn state(&self) -> RemoteProofRequestState {
        RemoteProofRequestState::load(self.inner.state.load(Ordering::Acquire))
    }

    pub(crate) fn cancel(&self) -> bool {
        self.inner
            .state
            .compare_exchange(
                RemoteProofRequestState::Active as u8,
                RemoteProofRequestState::Cancelled as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn cancel_if_expired(&self) {
        if Instant::now() >= self.inner.deadline {
            self.cancel();
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancel_if_expired();
        self.state() == RemoteProofRequestState::Cancelled
    }

    fn ensure_live(&self) -> Result<(), NodeError> {
        self.cancel_if_expired();
        if self.state() == RemoteProofRequestState::Active {
            Ok(())
        } else {
            Err(NodeError::ProofVerificationQueueTimeout)
        }
    }

    fn remaining(&self) -> Result<Duration, NodeError> {
        self.ensure_live()?;
        self.inner
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                self.cancel();
                NodeError::ProofVerificationQueueTimeout
            })
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.inner.deadline
    }

    fn begin_commit_after_check<F>(
        &self,
        after_deadline_check: F,
    ) -> Result<RemoteProofCommitGuard, NodeError>
    where
        F: FnOnce(),
    {
        // Check before the atomic transition, then check again after it. The
        // second check closes the preemption window between the first clock
        // read and CAS: an already-expired request gives up its owned
        // Committing state before any append begins.
        if Instant::now() >= self.inner.deadline {
            self.cancel();
            return Err(NodeError::ProofVerificationQueueTimeout);
        }
        after_deadline_check();
        self.inner
            .state
            .compare_exchange(
                RemoteProofRequestState::Active as u8,
                RemoteProofRequestState::Committing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|state| match RemoteProofRequestState::load(state) {
                RemoteProofRequestState::Cancelled => NodeError::ProofVerificationQueueTimeout,
                _ => NodeError::ProofVerificationQueuePoisoned,
            })?;
        if Instant::now() >= self.inner.deadline {
            self.inner
                .state
                .compare_exchange(
                    RemoteProofRequestState::Committing as u8,
                    RemoteProofRequestState::Cancelled as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
            return Err(NodeError::ProofVerificationQueueTimeout);
        }
        Ok(RemoteProofCommitGuard {
            inner: Arc::clone(&self.inner),
            finished: false,
        })
    }
}

struct RemoteProofCommitGuard {
    inner: Arc<RemoteProofRequestInner>,
    finished: bool,
}

impl RemoteProofCommitGuard {
    fn finish(mut self, state: RemoteProofRequestState) {
        debug_assert!(matches!(
            state,
            RemoteProofRequestState::Completed | RemoteProofRequestState::Faulted
        ));
        let _ = self.inner.state.compare_exchange(
            RemoteProofRequestState::Committing as u8,
            state as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.finished = true;
    }
}

impl Drop for RemoteProofCommitGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.inner.state.compare_exchange(
                RemoteProofRequestState::Committing as u8,
                RemoteProofRequestState::Faulted as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

#[derive(Debug)]
struct RemoteProofAdmissionState {
    active: Option<RemoteProofPeerId>,
    closing: bool,
    waiting: VecDeque<RemoteProofPeerId>,
    waiting_set: HashSet<RemoteProofPeerId>,
    cooldowns: HashMap<RemoteProofPeerId, Instant>,
    cooldown_order: VecDeque<RemoteProofPeerId>,
    cooldown_saturated_until: Option<Instant>,
    wait_events: u64,
    rejections: u64,
    proof_failures: u64,
}

#[derive(Debug)]
struct RemoteProofAdmissionQueue {
    state: Mutex<RemoteProofAdmissionState>,
    wake: Condvar,
    max_in_flight: usize,
    wait_timeout: Duration,
    invalid_cooldown: Duration,
    #[cfg(test)]
    deadline_wake_barrier: Mutex<Option<Arc<DeadlineWakeBarrier>>>,
}

impl RemoteProofAdmissionQueue {
    fn new(max_in_flight: usize, wait_timeout: Duration, invalid_cooldown: Duration) -> Self {
        assert!(max_in_flight > 0, "remote proof admission needs capacity");
        assert!(
            max_in_flight <= MAX_REMOTE_PROOF_ADMISSIONS,
            "remote proof admission exceeds its hard capacity"
        );
        assert!(
            !wait_timeout.is_zero(),
            "remote proof admission needs a wait deadline"
        );
        Self {
            state: Mutex::new(RemoteProofAdmissionState {
                active: None,
                closing: false,
                waiting: VecDeque::new(),
                waiting_set: HashSet::new(),
                cooldowns: HashMap::new(),
                cooldown_order: VecDeque::new(),
                cooldown_saturated_until: None,
                wait_events: 0,
                rejections: 0,
                proof_failures: 0,
            }),
            wake: Condvar::new(),
            max_in_flight,
            wait_timeout,
            invalid_cooldown,
            #[cfg(test)]
            deadline_wake_barrier: Mutex::new(None),
        }
    }

    fn acquire(
        self: &Arc<Self>,
        peer: RemoteProofPeerId,
    ) -> Result<RemoteProofAdmissionPermit, NodeError> {
        self.acquire_with_cancellation(peer, None)
    }

    fn acquire_cancellable(
        self: &Arc<Self>,
        peer: RemoteProofPeerId,
        request: RemoteProofRequest,
    ) -> Result<RemoteProofAdmissionPermit, NodeError> {
        self.acquire_with_cancellation(peer, Some(request))
    }

    fn acquire_with_cancellation(
        self: &Arc<Self>,
        peer: RemoteProofPeerId,
        request: Option<RemoteProofRequest>,
    ) -> Result<RemoteProofAdmissionPermit, NodeError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
        let now = Instant::now();
        prune_remote_proof_cooldowns(&mut state, now);
        if state.closing {
            state.rejections = state.rejections.saturating_add(1);
            return Err(NodeError::ProofVerifierShuttingDown);
        }
        if remote_proof_cancelled(request.as_ref()) {
            state.rejections = state.rejections.saturating_add(1);
            return Err(NodeError::ProofVerificationQueueTimeout);
        }
        let in_flight = state.waiting.len() + usize::from(state.active.is_some());
        if state
            .cooldown_saturated_until
            .is_some_and(|deadline| deadline > now)
            || state.cooldowns.contains_key(&peer)
            || state.active == Some(peer)
            || state.waiting_set.contains(&peer)
            || in_flight >= self.max_in_flight
        {
            state.rejections = state.rejections.saturating_add(1);
            return Err(NodeError::ProofVerificationQueueFull);
        }
        if state.active.is_none() && state.waiting.is_empty() {
            state.active = Some(peer);
            return Ok(RemoteProofAdmissionPermit {
                queue: Arc::clone(self),
                peer,
                proof_failed: false,
                request,
            });
        }

        state.waiting.push_back(peer);
        state.waiting_set.insert(peer);
        state.wait_events = state.wait_events.saturating_add(1);
        // A waiter's own deadline is independent of worker startup/request
        // containment. The cooldown is deliberately session-local: a
        // reconnect receives a new identity, but it joins at the FIFO tail and
        // therefore cannot overtake an already admitted valid session.
        let queue_deadline = match checked_queue_deadline(Instant::now(), self.wait_timeout) {
            Ok(deadline) => deadline,
            Err(error) => {
                remove_remote_proof_waiter(&mut state, peer);
                state.rejections = state.rejections.saturating_add(1);
                self.wake.notify_all();
                return Err(error);
            }
        };
        let deadline = request.as_ref().map_or(queue_deadline, |request| {
            queue_deadline.min(request.deadline())
        });
        loop {
            if state.closing {
                remove_remote_proof_waiter(&mut state, peer);
                state.rejections = state.rejections.saturating_add(1);
                self.wake.notify_all();
                return Err(NodeError::ProofVerifierShuttingDown);
            }
            if remote_proof_cancelled(request.as_ref()) {
                remove_remote_proof_waiter(&mut state, peer);
                state.rejections = state.rejections.saturating_add(1);
                self.wake.notify_all();
                return Err(NodeError::ProofVerificationQueueTimeout);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                remove_remote_proof_waiter(&mut state, peer);
                state.rejections = state.rejections.saturating_add(1);
                self.wake.notify_all();
                return Err(NodeError::ProofVerificationQueueTimeout);
            }
            if !remote_proof_waiting(&state, peer) {
                break;
            }
            let poll = remaining.min(REMOTE_PROOF_CANCELLATION_POLL);
            let (next_state, _) = self
                .wake
                .wait_timeout_while(state, poll, |state| {
                    remote_proof_waiting(state, peer) && !remote_proof_cancelled(request.as_ref())
                })
                .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
            state = next_state;
            #[cfg(test)]
            if let Some(barrier) = self
                .deadline_wake_barrier
                .lock()
                .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?
                .take()
            {
                drop(state);
                barrier.entered.wait();
                barrier.release.wait();
                state = self
                    .state
                    .lock()
                    .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
            }
        }
        let next = state.waiting.pop_front();
        if next != Some(peer) || !state.waiting_set.remove(&peer) || state.active.is_some() {
            state.rejections = state.rejections.saturating_add(1);
            state.closing = true;
            self.wake.notify_all();
            return Err(NodeError::ProofVerificationQueuePoisoned);
        }
        state.active = Some(peer);
        Ok(RemoteProofAdmissionPermit {
            queue: Arc::clone(self),
            peer,
            proof_failed: false,
            request,
        })
    }

    fn telemetry(&self) -> Result<ProofAdmissionClassTelemetry, NodeError> {
        self.state
            .lock()
            .map(|state| ProofAdmissionClassTelemetry {
                active: usize::from(state.active.is_some()),
                queued: state.waiting.len(),
                wait_events: state.wait_events,
                rejections: state.rejections,
                proof_failures: state.proof_failures,
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
}

fn prune_remote_proof_cooldowns(state: &mut RemoteProofAdmissionState, now: Instant) {
    if state
        .cooldown_saturated_until
        .is_some_and(|deadline| deadline <= now)
    {
        state.cooldown_saturated_until = None;
    }
    while let Some(peer) = state.cooldown_order.front().copied() {
        let expired = state
            .cooldowns
            .get(&peer)
            .is_none_or(|deadline| *deadline <= now);
        if !expired {
            break;
        }
        state.cooldown_order.pop_front();
        state.cooldowns.remove(&peer);
    }
}

fn remove_remote_proof_waiter(state: &mut RemoteProofAdmissionState, peer: RemoteProofPeerId) {
    state.waiting.retain(|candidate| *candidate != peer);
    state.waiting_set.remove(&peer);
}

fn remote_proof_waiting(state: &RemoteProofAdmissionState, peer: RemoteProofPeerId) -> bool {
    !state.closing && (state.active.is_some() || state.waiting.front() != Some(&peer))
}

fn remote_proof_cancelled(request: Option<&RemoteProofRequest>) -> bool {
    request.is_some_and(RemoteProofRequest::is_cancelled)
}

fn checked_queue_deadline(start: Instant, duration: Duration) -> Result<Instant, NodeError> {
    start
        .checked_add(duration)
        .ok_or(NodeError::ProofVerificationQueueTimeout)
}

struct RemoteProofAdmissionPermit {
    queue: Arc<RemoteProofAdmissionQueue>,
    peer: RemoteProofPeerId,
    proof_failed: bool,
    request: Option<RemoteProofRequest>,
}

impl RemoteProofAdmissionPermit {
    fn mark_proof_failure(&mut self) {
        self.proof_failed = true;
    }

    fn is_cancelled(&self) -> bool {
        remote_proof_cancelled(self.request.as_ref())
    }
}

impl Drop for RemoteProofAdmissionPermit {
    fn drop(&mut self) {
        let mut state = match self.queue.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.active == Some(self.peer) {
            state.active = None;
            if self.proof_failed {
                state.proof_failures = state.proof_failures.saturating_add(1);
                prune_remote_proof_cooldowns(&mut state, Instant::now());
                state.cooldowns.remove(&self.peer);
                state.cooldown_order.retain(|peer| *peer != self.peer);
                let now = Instant::now();
                let Some(cooldown_deadline) = now.checked_add(self.queue.invalid_cooldown) else {
                    // Configuration overflow is impossible with the fixed
                    // production value, but fail closed as retryable Busy
                    // instead of panicking if a future configuration violates
                    // that invariant.
                    state.closing = true;
                    self.queue.wake.notify_all();
                    return;
                };
                if state.cooldowns.len() >= MAX_REMOTE_PROOF_COOLDOWNS {
                    // Every unexpired identity remains binding. Exhausting the
                    // live-session-sized TTL table rejects all remote proof
                    // admissions for one full cooldown instead of silently
                    // letting any untracked failing session retry. The queue
                    // automatically reopens; lifecycle shutdown remains a
                    // separate terminal state.
                    state.cooldown_saturated_until = Some(cooldown_deadline);
                } else {
                    state.cooldowns.insert(self.peer, cooldown_deadline);
                    state.cooldown_order.push_back(self.peer);
                }
            }
        } else {
            state.closing = true;
        }
        self.queue.wake.notify_all();
    }
}

/// An owned queue reservation. Shared-node admission captures its revision
/// only after this reservation is acquired and keeps it until commit, so
/// queued candidates cannot all verify against one stale revision.
struct BlockPreverificationPermit {
    preverifier: BlockPreverifier,
    queue_permit: ProofVerificationPermit,
}

impl BlockPreverificationPermit {
    fn preverify(&self, block: &Block) -> Result<PreverifiedBlockProof, NodeError> {
        self.preverify_with_request(block, None)
    }

    fn preverify_with_request(
        &self,
        block: &Block,
        request: Option<&RemoteProofRequest>,
    ) -> Result<PreverifiedBlockProof, NodeError> {
        validate_block_resources(block)?;
        encode_block(block)?;
        if let Some(request) = request {
            request.ensure_live()?;
        }
        let result = self.run_guarded(|| self.preverifier.preverify_unqueued(block, request));
        if let Some(request) = request {
            request.ensure_live()?;
        }
        result
    }

    fn preverify_cached_with_request(
        &self,
        block: &Block,
        cache_key: [u8; 32],
        request: Option<&RemoteProofRequest>,
    ) -> Result<PreverifiedBlockProof, NodeError> {
        if let Some(request) = request {
            request.ensure_live()?;
        }
        if let Some(preverified) = self.preverifier.cached_preverification(cache_key)? {
            return Ok(preverified);
        }
        let generation = self.preverifier.backend_generation.load(Ordering::Acquire);
        let preverified = self.preverify_with_request(block, request)?;
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

    fn mark_proof_failure(&mut self) {
        self.queue_permit.mark_proof_failure();
    }
}

/// Cloneable, immutable admission handle for proof verification outside the
/// node's global state lock.
#[derive(Clone)]
pub struct BlockPreverifier {
    verifier: ConsensusPowVerifier,
    queue: Arc<ProofVerificationQueue>,
    remote_admission: Arc<RemoteProofAdmissionQueue>,
    reconstruction_queue: Arc<ProofVerificationQueue>,
    /// Lane for proofs of blocks a sync session fetched on request. Bounded
    /// separately so prefetching never competes with, or widens, the single
    /// slot that unsolicited peer submissions share.
    fetched_queue: Arc<ProofVerificationQueue>,
    /// Fetched blocks every sync session of this node currently buffers beyond
    /// the one it is about to submit (see `p2p::PrefetchSlots`).
    prefetched_block_slots: Arc<AtomicUsize>,
    backend: Arc<RwLock<ProofVerificationBackend>>,
    backend_generation: Arc<AtomicU64>,
    successful_proofs: Arc<Mutex<SuccessfulProofCache>>,
    #[cfg(test)]
    worker_dispatches: Arc<AtomicU64>,
    #[cfg(test)]
    prefetched_blocks: Arc<AtomicU64>,
    #[cfg(test)]
    replay_state_blocks: Arc<AtomicU64>,
    #[cfg(test)]
    proof_dispatch_delay: Arc<Mutex<Option<Duration>>>,
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
            ProofProfile::ProductionV4 => ProofVerificationBackend::InProcess,
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
    #[cfg_attr(
        any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
        allow(dead_code)
    )]
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
            remote_admission: Arc::new(RemoteProofAdmissionQueue::new(
                MAX_REMOTE_PROOF_ADMISSIONS,
                REMOTE_PROOF_ADMISSION_WAIT_TIMEOUT,
                INVALID_REMOTE_PROOF_COOLDOWN,
            )),
            reconstruction_queue: Arc::new(ProofVerificationQueue::new(1, 2, wait_timeout)),
            fetched_queue: Arc::new(ProofVerificationQueue::new(
                fetched_proof_verification_workers(),
                MAX_QUEUED_FETCHED_PROOF_VERIFICATIONS,
                FETCHED_PROOF_VERIFICATION_QUEUE_TIMEOUT,
            )),
            prefetched_block_slots: Arc::new(AtomicUsize::new(0)),
            backend: Arc::new(RwLock::new(backend)),
            backend_generation: Arc::new(AtomicU64::new(0)),
            successful_proofs: Arc::new(Mutex::new(SuccessfulProofCache::default())),
            #[cfg(test)]
            worker_dispatches: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            prefetched_blocks: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            replay_state_blocks: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            proof_dispatch_delay: Arc::new(Mutex::new(None)),
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
            queue_permit: self.queue.acquire()?,
        })
    }

    fn reserve_cancellable(
        &self,
        request: RemoteProofRequest,
    ) -> Result<BlockPreverificationPermit, NodeError> {
        Ok(BlockPreverificationPermit {
            preverifier: self.clone(),
            queue_permit: self.queue.acquire_cancellable(request)?,
        })
    }

    fn reserve_priority(&self) -> Result<BlockPreverificationPermit, NodeError> {
        Ok(BlockPreverificationPermit {
            preverifier: self.clone(),
            queue_permit: self.queue.acquire_priority()?,
        })
    }

    fn reserve_remote(
        &self,
        peer: RemoteProofPeerId,
    ) -> Result<RemoteProofAdmissionPermit, NodeError> {
        self.remote_admission.acquire(peer)
    }

    fn reserve_remote_cancellable(
        &self,
        peer: RemoteProofPeerId,
        request: RemoteProofRequest,
    ) -> Result<RemoteProofAdmissionPermit, NodeError> {
        self.remote_admission.acquire_cancellable(peer, request)
    }

    fn reserve_reconstruction(&self) -> Result<ProofVerificationPermit, NodeError> {
        self.reconstruction_queue.acquire()
    }

    fn ensure_reconstruction_open(&self) -> Result<(), NodeError> {
        self.reconstruction_queue.ensure_open()
    }

    fn preverify_unqueued(
        &self,
        block: &Block,
        request: Option<&RemoteProofRequest>,
    ) -> Result<PreverifiedBlockProof, NodeError> {
        #[cfg(test)]
        self.worker_dispatches.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        {
            // Copy the delay out so concurrent dispatches do not serialize on
            // this test-only lock while sleeping.
            let delay = *self
                .proof_dispatch_delay
                .lock()
                .map_err(|_| NodeError::ProofVerificationQueuePoisoned)?;
            if let Some(delay) = delay {
                std::thread::sleep(delay);
            }
        }
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
            ProofVerificationBackend::External(worker) => match request {
                Some(request) => worker
                    .verify_block_with_timeout(block, request.remaining()?)
                    .map_err(NodeError::from),
                None => worker.verify_block(block).map_err(NodeError::from),
            },
        }
    }

    /// Verifies the proof of a block a sync session fetched on request, through
    /// the bounded fetched-block lane, into the successful-proof cache. The
    /// ordered submission that follows finds the cached result and skips the
    /// scarce verifier; on any failure here it simply verifies the block
    /// itself and applies the usual accounting, so errors are not reported.
    /// Shared counter of fetched blocks buffered node-wide by sync sessions.
    pub(crate) fn prefetched_block_slots(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.prefetched_block_slots)
    }

    pub(crate) fn prewarm_fetched_proof(&self, block: &Block) -> Result<(), NodeError> {
        #[cfg(test)]
        self.prefetched_blocks.fetch_add(1, Ordering::Relaxed);
        let cache_key = canonical_block_cache_digest(block)?;
        if self.cached_preverification(cache_key)?.is_some() {
            return Ok(());
        }
        let _permit = self.fetched_queue.acquire()?;
        self.preverify_replay_cached(block).map(|_| ())
    }

    /// Reuses only successful process-local proof evidence while reconstructing
    /// authenticated ancestors. Cache misses still execute the configured
    /// verifier; neither a durable locator nor a startup snapshot grants proof
    /// authority. The bounded cache may evict old history, which must be verified
    /// again rather than treated as a trusted checkpoint.
    fn preverify_replay_cached(&self, block: &Block) -> Result<PreverifiedBlockProof, NodeError> {
        let cache_key = canonical_block_cache_digest(block)?;
        if let Some(preverified) = self.cached_preverification(cache_key)? {
            return Ok(preverified);
        }
        let generation = self.backend_generation.load(Ordering::Acquire);
        let preverified = self.preverify_unqueued(block, None)?;
        self.remember_preverification(cache_key, generation, preverified.clone())?;
        Ok(preverified)
    }

    #[cfg(test)]
    pub(crate) fn set_proof_dispatch_delay(&self, delay: Option<Duration>) {
        *self.proof_dispatch_delay.lock().unwrap() = delay;
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
    #[cfg_attr(
        any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
        allow(dead_code)
    )]
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

    fn backend_teardown_failures(&self) -> Result<Option<u64>, NodeError> {
        let backend = self
            .backend
            .read()
            .map_err(|_| VerifierWorkerError::StatePoisoned)?;
        Ok(match &*backend {
            ProofVerificationBackend::External(worker) => Some(worker.teardown_failures()),
            ProofVerificationBackend::Unavailable
            | ProofVerificationBackend::InProcess
            | ProofVerificationBackend::Stopped => None,
        })
    }

    fn shutdown(&self) {
        self.remote_admission.close();
        self.queue.close();
        self.reconstruction_queue.close();
        self.fetched_queue.close();
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
    /// Whether native wallet mutation is available, latched closed pending v3
    /// activation, or owned by the active v3 custody runtime.
    pub exchange_custody_v3_wallet_state: &'static str,
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
    pub proof_verification_normal_admission: ProofAdmissionClassTelemetry,
    pub proof_verification_priority_admission: ProofAdmissionClassTelemetry,
    pub proof_verification_remote_admission: ProofAdmissionClassTelemetry,
    /// Hard bound across active plus waiting remote proof sessions.
    pub proof_verification_remote_admission_capacity: usize,
    /// Independent deadline for one admitted remote session waiting its turn.
    pub proof_verification_remote_admission_wait_timeout_ms: u64,
    pub proof_verification_capacity: usize,
    pub proof_verification_queue_capacity: usize,
    pub proof_verification_mode: &'static str,
    pub proof_verification_timeout_ms: Option<u64>,
    pub proof_verification_memory_limit_bytes: Option<u64>,
    /// Failed cleanup attempts recorded without replacing the classified
    /// verifier request error that triggered containment.
    pub proof_verification_teardown_failures: Option<u64>,
    pub storage_healthy: bool,
    pub startup_snapshot_used: bool,
    pub public_peer_mode: bool,
    /// Newest active blocks kept with full proofs, when pruning is enabled.
    pub prune_keep_blocks: Option<u64>,
    /// Height of the newest block stored without its proof.
    pub pruned_height: Option<u64>,
    /// Whether every record present at startup has been verified, either by
    /// the startup scan or by the background history scrub after a fast start.
    pub history_scrub_complete: bool,
    pub history_scrub_verified_records: u64,
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
    sync_cursor: Option<[u8; 32]>,
    relay_cursor: Option<[u8; 32]>,
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

/// Opaque peer-handshake identity issued only after the ProductionV3 model
/// artifacts have authenticated successfully. Thin miners pass this value to
/// the P2P request helpers instead of reconstructing consensus parameters from
/// an unauthenticated profile.
#[cfg(feature = "production-v3")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionV3MiningPeerIdentity {
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis_hash: [u8; 32],
}

#[cfg(feature = "production-v3")]
impl ProductionV3MiningPeerIdentity {
    pub(crate) fn peer_hello(self) -> peer::PeerHello {
        peer::PeerHello {
            network_id: self.network_id,
            consensus_fingerprint: self.consensus_fingerprint,
            node_nonce: peer::process_node_nonce(),
            tip: self.genesis_hash,
            height: 0,
            cumulative_work: peer::ChainWork::ZERO,
        }
    }

    #[cfg(test)]
    const fn for_test(
        network_id: [u8; 32],
        consensus_fingerprint: [u8; 32],
        genesis_hash: [u8; 32],
    ) -> Self {
        Self {
            network_id,
            consensus_fingerprint,
            genesis_hash,
        }
    }
}

#[cfg(feature = "production-v3")]
#[derive(Debug)]
struct ProductionV3MiningContext {
    params: NetworkParams,
    consensus_fingerprint: [u8; 32],
    verifier: ConsensusPowVerifier,
    prepared_model: PreparedForgeMatrixV3Model,
    replay_bank: Mutex<
        cmfd_consensus::dory_v3_model_bank_record_validation::RetainedReleasePinnedProductionDoryV3Bank,
    >,
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
        let pins = release_gate::COMPILED_RELEASE_PROFILE
            .production_v3_artifacts
            .ok_or(NodeError::ProductionV3ArtifactPinsMissing)?;
        let loaded = cmfd_consensus::dory_v3_model_bank_record_validation::load_release_pinned_production_dory_v3_mining_verifier(
            COMPILED_NETWORK_PROFILE.network_id,
            &artifacts.bank,
            &artifacts.manifest,
            &artifacts.record_v2,
            production_v3_file_identity_from_pin(pins.bank),
            production_v3_file_identity_from_pin(pins.manifest),
            production_v3_file_identity_from_pin(pins.record_v2),
        )
        .map_err(NodeError::ProductionV3Artifacts)?;
        require_production_v3_file_identity("bank", pins.bank, loaded.bank_file())?;
        require_production_v3_file_identity("manifest", pins.manifest, loaded.manifest_file())?;
        require_production_v3_file_identity("Record V2", pins.record_v2, loaded.record_v2_file())?;
        let (verifier, mut retained_bank) = loaded.into_parts();
        let (params, verifier) = network_params_from_verifier(COMPILED_NETWORK_PROFILE, verifier)?;
        let consensus_fingerprint = params.fingerprint()?;
        let prepared_model =
            verifier.prepare_v3_fixed_model(&mut retained_bank, &scratch_directory, cancel)?;
        retained_bank
            .recheck()
            .map_err(NodeError::ProductionV3Artifacts)?;
        Ok(Self {
            context: Arc::new(ProductionV3MiningContext {
                params,
                consensus_fingerprint,
                verifier,
                prepared_model,
                replay_bank: Mutex::new(retained_bank),
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

    /// Return the network/fingerprint authority established by the same
    /// authenticated artifact load that prepared this mining factory.
    pub fn peer_identity(&self) -> ProductionV3MiningPeerIdentity {
        ProductionV3MiningPeerIdentity {
            network_id: self.context.params.network_id,
            consensus_fingerprint: self.context.consensus_fingerprint,
            genesis_hash: self.context.params.genesis_hash,
        }
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
        let mut replay_bank = context
            .replay_bank
            .lock()
            .map_err(|_| NodeError::ProductionV3MiningStatePoisoned)?;
        replay_bank
            .rewind_and_recheck()
            .map_err(NodeError::ProductionV3Artifacts)?;
        let proof = self
            .verifier
            .prove_v3_winning_nonce_claim_with_prepared_model(
                &self.challenge,
                claim,
                &context.prepared_model,
                &mut *replay_bank,
                &context.scratch_directory,
                context.maximum_native_block_rows,
                cancel,
            );
        replay_bank
            .recheck()
            .map_err(NodeError::ProductionV3Artifacts)?;
        Ok(proof?)
    }

    /// Replay and prove a Production V3 winning claim with an optional
    /// accelerator-proposed replay accumulator bundle. `None` is the unchanged
    /// CPU replay; `Some` still authenticates the complete bank on this call's
    /// replay reader and revalidates everything the accelerator surfaced.
    #[cfg(feature = "production-v3")]
    pub fn prove_v3_winning_nonce_claim_with_accelerated_replay(
        &self,
        claim: ForgeMatrixV3WinningNonceClaim,
        accelerated_replay: Option<cmfd_consensus::BlsDoryV3AcceleratedReplayAccumulators>,
        cancel: &AtomicBool,
    ) -> Result<BlockProof, NodeError> {
        let context = self
            .production_v3
            .as_ref()
            .ok_or(NodeError::ProductionV3MiningConfiguration)?;
        self.verifier
            .validate_v3_winning_nonce_claim(&self.challenge, claim)?;
        let mut replay_bank = context
            .replay_bank
            .lock()
            .map_err(|_| NodeError::ProductionV3MiningStatePoisoned)?;
        replay_bank
            .rewind_and_recheck()
            .map_err(NodeError::ProductionV3Artifacts)?;
        let proof = self
            .verifier
            .prove_v3_winning_nonce_claim_with_prepared_model_and_accelerated_replay(
                &self.challenge,
                claim,
                &context.prepared_model,
                &mut *replay_bank,
                &context.scratch_directory,
                context.maximum_native_block_rows,
                accelerated_replay,
                cancel,
            );
        replay_bank
            .recheck()
            .map_err(NodeError::ProductionV3Artifacts)?;
        Ok(proof?)
    }
}

#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub txid: [u8; 32],
    pub transaction: Transaction,
    pub encoded_bytes: usize,
    pub fee_burned: u64,
}

/// Files that establish the authenticated exchange-withdrawal storage
/// boundary. The journal key is a dedicated 32-byte secret; the external
/// anchor is intentionally kept outside the node data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeWithdrawalSecurityConfig {
    journal_key_file: PathBuf,
    anchor_file: PathBuf,
}

impl ExchangeWithdrawalSecurityConfig {
    pub fn new(journal_key_file: impl Into<PathBuf>, anchor_file: impl Into<PathBuf>) -> Self {
        Self {
            journal_key_file: journal_key_file.into(),
            anchor_file: anchor_file.into(),
        }
    }

    pub fn journal_key_file(&self) -> &Path {
        &self.journal_key_file
    }

    pub fn anchor_file(&self) -> &Path {
        &self.anchor_file
    }
}

/// Deterministic, unsigned wallet payment intent suitable for durable
/// journaling before the node's wallet key is used.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct WalletPaymentPlan {
    pub(crate) transaction: Transaction,
    pub(crate) recipient: [u8; 32],
    pub(crate) amount_atoms: u64,
    pub(crate) fee_burned_atoms: u64,
    pub(crate) change_atoms: u64,
    /// Values correspond positionally to `transaction.inputs`.
    pub(crate) selected_input_values: Vec<u64>,
    pub(crate) output_spendable_height: u64,
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
        let data_dir_existed = data_dir.exists();
        fs::create_dir_all(data_dir)
            .map_err(|source| io_error("create data directory", data_dir, source))?;
        if !data_dir_existed {
            sync_parent_directory(data_dir)?;
        }
        let path = data_dir.join(LOCK_FILE);
        let lock_file_existed = path.exists();
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
        if !lock_file_existed {
            sync_parent_directory(&path)?;
        }
        Ok(Self { _file: file })
    }
}

/// A second, read-only handle to the block log for a reader thread. It leaves
/// the retained append handle's sharing rules untouched: the reader grants read
/// and write sharing itself and asks for no write access, so the node keeps its
/// exclusive write access and can be reopened after this handle closes.
fn open_block_log_reader(path: &Path) -> Result<File, NodeError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    options
        .open(path)
        .map_err(|source| io_error("open block log for reading", path, source))
}

fn open_block_log(path: &Path) -> Result<File, NodeError> {
    let existed = path.exists();
    let mut options = OpenOptions::new();
    options.create(true).append(true).read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options.share_mode(FILE_SHARE_READ);
    }
    let file = options
        .open(path)
        .map_err(|source| io_error("open block log", path, source))?;
    if !existed {
        file.sync_all()
            .map_err(|source| io_error("sync new block log", path, source))?;
        sync_parent_directory(path)?;
    }
    Ok(file)
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

/// A clone of the retained block log for reading without the node lock. The
/// node counts these so pruning never replaces the log under a reader.
pub(crate) struct LogReadHandle {
    file: File,
    // Declared after `file` so the handle closes before the count drops.
    _reader: Arc<()>,
}

impl std::ops::Deref for LogReadHandle {
    type Target = File;

    fn deref(&self) -> &File {
        &self.file
    }
}

impl Node {
    pub(crate) fn clone_log_for_read(&self) -> io::Result<LogReadHandle> {
        Ok(LogReadHandle {
            file: self.log.try_clone()?,
            _reader: Arc::clone(&self.log_readers),
        })
    }

    pub(crate) fn log_readers_outstanding(&self) -> bool {
        Arc::strong_count(&self.log_readers) > 1
    }

    /// Value of every unspent output. Fees are burned, so this is every coin
    /// minted so far minus burned fees: the current total supply.
    pub fn total_supply_atoms(&self) -> u64 {
        let total: u128 = self
            .state
            .utxos()
            .iter()
            .map(|(_, output)| u128::from(output.value))
            .sum();
        u64::try_from(total).unwrap_or(u64::MAX)
    }
}

fn next_node_instance_id() -> Result<u64, NodeError> {
    NEXT_NODE_INSTANCE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| NodeError::CorruptLog("node instance identity counter exhausted".to_owned()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExchangeCustodyV3WalletState {
    Unclaimed,
    Required,
    Active,
}

impl ExchangeCustodyV3WalletState {
    fn locks_native_wallet(self) -> bool {
        self != Self::Unclaimed
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Unclaimed => "unclaimed",
            Self::Required => "required",
            Self::Active => "active",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExchangeCustodyDestinationUtxoSummary {
    pub tip: [u8; 32],
    pub next_height: u64,
    pub unspent_count: usize,
    pub unspent_atoms: u64,
    pub spendable_count: usize,
    pub spendable_atoms: u64,
    pub local_mempool_output_count: usize,
    pub local_mempool_output_atoms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExchangeCustodyLegacySweepSummary {
    pub txid: [u8; 32],
    pub block_id: [u8; 32],
    pub height: u64,
    pub confirmations: u64,
    pub legacy_input_count: usize,
    pub legacy_output_count: usize,
}

/// Where an active-chain transaction lookup last left off for one txid. A
/// mark is trusted only while its block is still active at that height.
#[derive(Clone, Copy, Debug)]
enum TransactionScanMark {
    Found { height: usize, block_id: [u8; 32] },
    AbsentThrough { height: usize, block_id: [u8; 32] },
}

const MAX_TRANSACTION_SCAN_MARKS: usize = 4096;

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
    branch_checkpoints: BranchCheckpointCache,
    explorer_outputs: explorer_address_index::AddressOutputIndex,
    explorer_history_cache: Option<explorer::ExplorerHistoryCache>,
    /// Confirmed wallet history, scanned once and then extended with only the
    /// blocks appended since the previous wallet snapshot.
    wallet_history_cache: Option<wallet_history::WalletHistoryCache>,
    /// Whole-chain wallet history scan running off the node lock, if any.
    wallet_history_scan: Option<wallet_history::WalletHistoryScan>,
    #[cfg(test)]
    wallet_history_inline_scan_bytes: u64,
    /// Per-txid progress of active-chain transaction lookups, so repeated
    /// lookups read only blocks added since the last verified scan point.
    transaction_scan_marks: HashMap<[u8; 32], TransactionScanMark>,
    /// Monotonically changes after every successful block commit. External
    /// proof admissions bind to this value so branch snapshots cannot be
    /// committed after chain state or fork choice changes.
    chain_revision: u64,
    /// Records in the retained block log; the ordinal of the next append.
    /// Unlike `chain_revision` it shrinks when pruning drops side branches.
    record_count: u64,
    /// Opt-in proof pruning: full blocks kept below the tip, if enabled.
    prune_keep_blocks: Option<u64>,
    mempool: BTreeMap<[u8; 32], MempoolEntry>,
    mempool_bytes: usize,
    /// Active exchange-withdrawal reservations, bound to the exact unsigned
    /// transaction digest authorized to spend each outpoint. The durable
    /// journal restores this complete map before withdrawal RPCs are enabled.
    exchange_withdrawal_reservations: HashMap<OutPoint, [u8; 32]>,
    /// Dedicated authenticated-journal key and independently located rollback
    /// anchor. This is loaded before journal reservations are restored.
    exchange_withdrawal_security: Option<exchange_withdrawal::LoadedWithdrawalSecurity>,
    /// Persistently required after v3 activation and promoted to Active when
    /// the runtime claims the wallet. Both non-Unclaimed states keep native
    /// wallet mutation fail-closed across omitted-flag restarts.
    exchange_custody_v3_wallet_state: ExchangeCustodyV3WalletState,
    exchange_rpc_active: bool,
    log: File,
    /// One reference per [`LogReadHandle`] outstanding; pruning replaces the
    /// log only when none are.
    log_readers: Arc<()>,
    /// Incremented whenever the block log file is replaced (a prune swap), so
    /// work planned against the old file restarts.
    log_epoch: u64,
    /// Background verification of the history a fast start did not re-read.
    history_scrub: history_scrub::Progress,
    /// Digest of the exact last complete block-log record. V2 appends bind to
    /// this value; it advances only after the durable record commits in memory.
    last_record_digest: [u8; 32],
    /// Authenticated end offset established by startup replay and advanced only
    /// after a complete record is durably written at that exact position.
    block_log_length: u64,
    storage_faulted: bool,
    startup_snapshot_used: bool,
    rejected_proof_ids: HashSet<[u8; 32]>,
    rejected_proof_order: VecDeque<[u8; 32]>,
    rejected_body_digests: HashSet<[u8; 32]>,
    rejected_body_order: VecDeque<[u8; 32]>,
    public_peer_mode: bool,
    peer_observations: BTreeMap<PeerObservationKey, PeerObservationRecord>,
    #[cfg(test)]
    commit_race_barrier: Option<Arc<CommitRaceBarrier>>,
    #[cfg(test)]
    completion_fault_barrier: Option<Arc<CompletionFaultBarrier>>,
    #[cfg(test)]
    explorer_block_reads: usize,
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
    /// Full-history transaction locations derived from the retained block log.
    /// Entries include side branches; queries check current canonical membership.
    transactions: explorer_index::TransactionIndex,
    addresses: explorer_address_index::AddressHistoryIndex,
    /// Active block identifiers in height order, including virtual genesis at
    /// index zero.
    active_chain: Vec<[u8; 32]>,
    active_work: U512,
    /// Chain state at the newest pruned block, when the log is pruned. State
    /// reconstruction starts here; blocks below it carry no proof.
    anchor: Option<Arc<PruneAnchor>>,
}

/// The newest pruned block and the chain state after it.
struct PruneAnchor {
    block_id: [u8; 32],
    height: u64,
    state: ChainState,
}

impl std::fmt::Debug for PruneAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PruneAnchor")
            .field("block_id", &hex::encode(self.block_id))
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct BranchStateCheckpoint {
    context: BranchStateContext,
    block_id: [u8; 32],
    state: Box<ChainState>,
    path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BranchStateContext {
    node_instance_id: u64,
    network_id: [u8; 32],
    fingerprint: [u8; 32],
    verifier_generation: u64,
}

#[derive(Debug)]
struct CachedBranchCheckpoint {
    checkpoint: BranchStateCheckpoint,
    anchor: BlockRecordLocator,
    charge: usize,
}

#[derive(Debug, Default)]
struct BranchCheckpointCache {
    entries: VecDeque<CachedBranchCheckpoint>,
    charged_bytes: usize,
}

impl BranchCheckpointCache {
    fn remove(&mut self, position: usize) -> CachedBranchCheckpoint {
        let removed = self
            .entries
            .remove(position)
            .expect("checked checkpoint index");
        self.charged_bytes -= removed.charge;
        removed
    }

    fn insert(&mut self, checkpoint: BranchStateCheckpoint, anchor: BlockRecordLocator) {
        let Some(charge) = checkpoint_charge(&checkpoint.state, checkpoint.path.capacity()) else {
            return;
        };
        if charge > MAX_BRANCH_STATE_CHECKPOINT_BYTES {
            return;
        }
        if let Some(position) = self
            .entries
            .iter()
            .position(|entry| entry.checkpoint.block_id == checkpoint.block_id)
        {
            self.remove(position);
        }
        while self.entries.len() >= MAX_BRANCH_STATE_CHECKPOINTS
            || self.charged_bytes > MAX_BRANCH_STATE_CHECKPOINT_BYTES - charge
        {
            self.remove(0);
        }
        self.charged_bytes += charge;
        self.entries.push_back(CachedBranchCheckpoint {
            checkpoint,
            anchor,
            charge,
        });
    }
}

fn checkpoint_charge(state: &ChainState, path_capacity: usize) -> Option<usize> {
    state
        .estimated_unique_heap_payload_bytes()
        .ok()?
        .checked_add(std::mem::size_of::<CachedBranchCheckpoint>())?
        .checked_add(path_capacity.checked_mul(std::mem::size_of::<[u8; 32]>())?)?
        .checked_add(128)
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
            transactions: explorer_index::TransactionIndex::default(),
            addresses: explorer_address_index::AddressHistoryIndex::default(),
            active_chain: vec![genesis],
            anchor: None,
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

    /// Where state reconstruction toward `tip` starts: virtual genesis, or the
    /// prune anchor when the log is pruned. Returns the base height, its state
    /// (`None` for genesis) and the active path from genesis to the base.
    #[allow(clippy::type_complexity)]
    fn reconstruction_base(
        &self,
        tip: [u8; 32],
    ) -> Result<(u64, Option<Box<ChainState>>, Vec<[u8; 32]>), NodeError> {
        let Some(anchor) = &self.anchor else {
            return Ok((0, None, vec![self.genesis]));
        };
        let reaches_anchor = self
            .blocks
            .get(&tip)
            .is_some_and(|entry| entry.height() >= anchor.height)
            && self.ancestor_at_height(tip, anchor.height)? == anchor.block_id;
        if !reaches_anchor {
            return Err(NodeError::BelowPrunePoint(tip));
        }
        let mut path = vec![self.genesis];
        path.extend(self.path_to(anchor.block_id)?);
        Ok((anchor.height, Some(Box::new(anchor.state.clone())), path))
    }

    /// True when `block_id` is a pruned record other than the anchor, so no
    /// new block may build on it.
    fn is_below_prune_point(&self, block_id: [u8; 32]) -> bool {
        let Some(anchor) = &self.anchor else {
            return false;
        };
        if block_id == self.genesis {
            return true;
        }
        self.blocks.get(&block_id).is_some_and(|entry| {
            entry.locator.version == BlockRecordVersion::Pruned && block_id != anchor.block_id
        })
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
            if self.anchor.is_some() {
                return Err(NodeError::BelowPrunePoint(parent));
            }
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
                    })
                    && self.anchor.as_ref().is_none_or(|anchor| {
                        self.blocks[&checkpoint.block_id].height() >= anchor.height
                    });
                if usable {
                    let height = self.blocks[&checkpoint.block_id].height();
                    (height, Some(checkpoint.state), checkpoint.path)
                } else {
                    self.reconstruction_base(parent)?
                }
            }
            None => self.reconstruction_base(parent)?,
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
                read_indexed_block(log, log_path, &indexed, block_id, network_id, require_v2)?
                    .into_full()
                    .ok_or(NodeError::BlockProofPruned(block_id))?;
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
    transaction_ids: Vec<[u8; 32]>,
    address_entries: Vec<([u8; 32], explorer_address_index::AddressLocation)>,
}

impl PreparedBlock {
    fn into_parent_checkpoint(self, context: BranchStateContext) -> Option<BranchStateCheckpoint> {
        let ValidatedCandidate::Branch { state, .. } = self.candidate else {
            return None;
        };
        let mut path = self.activation_chain?;
        if path.pop() != Some(self.block_id) || state.tip() != self.parent {
            return None;
        }
        Some(BranchStateCheckpoint {
            context,
            block_id: self.parent,
            state,
            path,
        })
    }

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
    checkpoint_context: BranchStateContext,
    revision: u64,
    block_id: [u8; 32],
    parent: [u8; 32],
    accepted_at: u64,
    params: NetworkParams,
    verifier: ConsensusPowVerifier,
    block_preverifier: BlockPreverifier,
    state_snapshot: AdmissionStateSnapshot,
    #[cfg(test)]
    completion_fault_barrier: Option<Arc<CompletionFaultBarrier>>,
}

/// Completed admission state. This is not proof evidence: it only carries the
/// state reconstruction and cheap consensus preflight performed outside the
/// node mutex. The external worker capability is still required separately.
#[derive(Debug)]
pub(crate) struct ExternalBlockAdmission {
    checkpoint_context: BranchStateContext,
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

impl ExternalBlockAdmissionProgress {
    fn into_checkpoint(self) -> Option<BranchStateCheckpoint> {
        match self {
            Self::Checkpoint { checkpoint } => Some(checkpoint),
            Self::Ready(admission) => {
                let state = admission.branch_state?;
                let mut path = admission.activation_chain?;
                if path.pop() != Some(admission.block_id) || state.tip() != admission.parent {
                    return None;
                }
                Some(BranchStateCheckpoint {
                    context: admission.checkpoint_context,
                    block_id: admission.parent,
                    state,
                    path,
                })
            }
        }
    }
}

/// A canceled request may preserve completed ancestor state, never its right
/// to commit a candidate. Cleanup is best-effort and never waits for Node.
struct PendingExternalAdmission {
    shared: Arc<Mutex<Node>>,
    progress: Option<ExternalBlockAdmissionProgress>,
}

/// Covers the interval after a cache checkout but before a replay slice can
/// complete, including reconstruction-queue failure and request cancellation.
struct PendingExternalWork {
    shared: Arc<Mutex<Node>>,
    work: Option<ExternalBlockAdmissionWork>,
}

impl Drop for PendingExternalWork {
    fn drop(&mut self) {
        let Some(work) = self.work.take() else {
            return;
        };
        let AdmissionStateSnapshot::Branch(plan) = work.state_snapshot else {
            return;
        };
        let Some(state) = plan.base else {
            return;
        };
        let checkpoint = BranchStateCheckpoint {
            context: work.checkpoint_context,
            block_id: state.tip(),
            state,
            path: plan.path,
        };
        return_branch_checkpoint(&self.shared, checkpoint);
    }
}

/// Cleanup never blocks indefinitely on Node (the dropping thread may itself
/// hold it), but a busy lock is retried briefly instead of discarding the
/// completed replay progress on the first contended attempt.
fn return_branch_checkpoint(shared: &Arc<Mutex<Node>>, checkpoint: BranchStateCheckpoint) {
    let deadline = Instant::now() + BRANCH_CHECKPOINT_RETURN_WAIT;
    loop {
        match shared.try_lock() {
            Ok(mut node) => {
                node.remember_branch_checkpoint(checkpoint);
                return;
            }
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return,
        }
    }
}

impl Drop for PendingExternalAdmission {
    fn drop(&mut self) {
        let Some(checkpoint) = self.progress.take().and_then(|p| p.into_checkpoint()) else {
            return;
        };
        return_branch_checkpoint(&self.shared, checkpoint);
    }
}

#[cfg(test)]
impl ExternalBlockAdmissionProgress {
    #[cfg_attr(
        any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
        allow(dead_code)
    )]
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
                let replay = complete_branch_state_plan(
                    self.params,
                    &self.verifier,
                    &self.block_preverifier,
                    plan,
                );
                #[cfg(test)]
                if replay.as_ref().is_err_and(is_authenticated_storage_failure)
                    && let Some(barrier) = &self.completion_fault_barrier
                {
                    barrier.entered.wait();
                    barrier.release.wait();
                }
                let (state, path) = replay?;
                if !reaches_target {
                    let block_id = state.tip();
                    return Ok(ExternalBlockAdmissionProgress::Checkpoint {
                        checkpoint: BranchStateCheckpoint {
                            context: self.checkpoint_context,
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
                checkpoint_context: self.checkpoint_context,
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

/// Proof checks of replayed fork blocks are independent of each other, so a
/// slice's uncached proofs are verified concurrently into the successful-proof
/// cache before the ordered replay. The ordered replay still obtains every
/// proof through `preverify_replay_cached` and handles all failures itself;
/// errors here are deliberately ignored.
/// Workers for the fetched-block proof lane: all but one core, at most
/// `MAX_PARALLEL_FETCHED_PROOF_VERIFICATIONS`, never fewer than one.
fn fetched_proof_verification_workers() -> usize {
    thread::available_parallelism()
        .map_or(1, usize::from)
        .saturating_sub(1)
        .clamp(1, MAX_PARALLEL_FETCHED_PROOF_VERIFICATIONS)
}

/// Verifies the proofs of blocks one sync session fetched, concurrently, into
/// the successful-proof cache before they are submitted in order. Bounded by
/// the node-wide fetched-block lane; failures are left to the ordered
/// submission, which verifies and accounts for the block itself.
pub(crate) fn prewarm_fetched_proofs(block_preverifier: &BlockPreverifier, blocks: &[Block]) {
    if blocks.len() < 2 {
        return;
    }
    let workers = fetched_proof_verification_workers().min(blocks.len());
    if workers < 2 {
        return;
    }
    let next = AtomicUsize::new(0);
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(block) = blocks.get(index) else {
                        break;
                    };
                    let _ = block_preverifier.prewarm_fetched_proof(block);
                }
            });
        }
    });
}

fn prewarm_replay_proofs(block_preverifier: &BlockPreverifier, replay: &[BranchReplayBlock]) {
    if replay.len() < 2 {
        return;
    }
    let workers = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(MAX_PARALLEL_REPLAY_PROOF_VERIFICATIONS)
        .min(replay.len());
    if workers < 2 {
        return;
    }
    let next = AtomicUsize::new(0);
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = replay.get(index) else {
                        break;
                    };
                    let _ = block_preverifier.preverify_replay_cached(&entry.block);
                }
            });
        }
    });
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
    prewarm_replay_proofs(block_preverifier, &plan.replay);
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
        // Never recover proof authority from the index. Reuse only an exact
        // successful process-local capability, or verify the locator-backed
        // block on a cache miss. Retaining successful evidence lets a later
        // request make progress after an earlier replay loses its checkpoint.
        let preverified = match block_preverifier.preverify_replay_cached(&block) {
            Ok(preverified) => preverified,
            Err(NodeError::ProofVerifierWorker(VerifierWorkerError::ProofRejected(error))) => {
                return Err(NodeError::CorruptLog(format!(
                    "indexed production block proof is rejected during fork replay: {error}"
                )));
            }
            Err(error) => return Err(error),
        };
        let validated = state
            .validate_block_preverified(&block, context, &preverified)
            .map_err(|error| {
                NodeError::CorruptLog(format!(
                    "captured production fork block fails preverified replay: {error}"
                ))
            })?;
        state.commit_validated(validated).map_err(|error| {
            NodeError::CorruptLog(format!(
                "captured production fork block cannot commit during replay: {error}"
            ))
        })?;
        #[cfg(test)]
        block_preverifier
            .replay_state_blocks
            .fetch_add(1, Ordering::Relaxed);
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
    production_v3_record: Option<&ProductionV3VerifierRecord>,
    production_v4_artifacts: Option<&ProductionV4VerifierArtifacts>,
) -> Result<(NetworkParams, ConsensusPowVerifier), NodeError> {
    let (profile, launch) = mainnet_runtime::resolve_compiled_profile(profile)?;
    network_params_and_verifier_with_launch(
        profile,
        production_v3_record,
        production_v4_artifacts,
        launch,
    )
}

fn network_params_and_verifier_with_launch(
    profile: NetworkProfile,
    production_v3_record: Option<&ProductionV3VerifierRecord>,
    production_v4_artifacts: Option<&ProductionV4VerifierArtifacts>,
    launch: Option<&mainnet_runtime::AuthenticatedMainnetRuntime>,
) -> Result<(NetworkParams, ConsensusPowVerifier), NodeError> {
    mainnet_runtime::require_authenticated_profile(profile, launch)?;
    let verifier = match profile.proof {
        ProofProfile::DevnetV2Reference => {
            if production_v3_record.is_some() || production_v4_artifacts.is_some() {
                return Err(NodeError::ProductionV4ArtifactsUnexpected);
            }
            let reference = v2_reference_for_network(profile.network_id).map_err(PowError::from)?;
            ConsensusPowVerifier::v2_reference(reference)
        }
        ProofProfile::ProductionV3 => {
            if production_v4_artifacts.is_some() {
                return Err(NodeError::ProductionV4ArtifactsUnexpected);
            }
            #[cfg(feature = "production-v3")]
            {
                let record = production_v3_record.ok_or(NodeError::ProductionV3ArtifactsMissing)?;
                let pins = release_gate::COMPILED_RELEASE_PROFILE
                    .production_v3_artifacts
                    .ok_or(NodeError::ProductionV3ArtifactPinsMissing)?;
                require_production_v3_file_identity(
                    "Record V2",
                    pins.record_v2,
                    &record.expected_file,
                )?;
                let loaded = cmfd_consensus::dory_v3_model_bank_record_validation::load_release_pinned_production_dory_v3_consensus_verifier(
                    profile.network_id,
                    &record.record_v2,
                    record.expected_file.clone(),
                )
                .map_err(NodeError::ProductionV3Artifacts)?;
                require_production_v3_file_identity(
                    "Record V2",
                    pins.record_v2,
                    loaded.record_v2_file(),
                )?;
                loaded.into_verifier()
            }
            #[cfg(not(feature = "production-v3"))]
            {
                let _ = production_v3_record;
                return Err(NodeError::ProductionV3Unavailable);
            }
        }
        ProofProfile::ProductionV4 => {
            if production_v3_record.is_some() {
                return Err(NodeError::ProductionV3ArtifactsUnexpected);
            }
            #[cfg(feature = "production-v4")]
            {
                let artifacts =
                    production_v4_artifacts.ok_or(NodeError::ProductionV4ArtifactsMissing)?;
                let pins = release_gate::COMPILED_RELEASE_PROFILE
                    .production_v4_artifacts
                    .ok_or(NodeError::ProductionV4ArtifactPinsMissing)?;
                let mut fixed_record_reader = open_production_v4_pinned_reader(
                    &artifacts.fixed_record,
                    pins.fixed_record,
                    "fixed artifact record",
                )?;
                let fixed_record_limit = pins.fixed_record.bytes.checked_add(1).ok_or(
                    NodeError::ProductionV4ArtifactIdentityMismatch("fixed artifact record"),
                )?;
                let mut fixed_record_bytes = Vec::new();
                Read::by_ref(&mut fixed_record_reader)
                    .take(fixed_record_limit)
                    .read_to_end(&mut fixed_record_bytes)
                    .map_err(|source| {
                        io_error(
                            "read ProductionV4 fixed artifact record",
                            &artifacts.fixed_record,
                            source,
                        )
                    })?;
                fixed_record_reader.verify_pin(pins.fixed_record, "fixed artifact record")?;
                let record: ForgeMatrixV4FixedArtifactRecordV1 =
                    serde_json::from_slice(&fixed_record_bytes)?;

                let mut bank_reader =
                    open_production_v4_pinned_reader(&artifacts.bank, pins.bank, "model bank")?;
                let verifier = ConsensusPowVerifier::v4_candidate_for_network(
                    profile.network_id,
                    record,
                    BufReader::with_capacity(64 * 1024 * 1024, &mut bank_reader),
                )?;
                bank_reader.verify_pin(pins.bank, "model bank")?;
                verifier
            }
            #[cfg(not(feature = "production-v4"))]
            {
                let _ = production_v4_artifacts;
                return Err(NodeError::ProductionV4Unavailable);
            }
        }
    };
    let params = network_params_from_pow_with_launch(profile, verifier.parameters(), launch)?;
    Ok((params, verifier))
}

#[cfg(feature = "production-v4")]
fn open_production_v4_pinned_reader(
    path: &Path,
    pin: release_gate::ProductionV3FileIdentityPin,
    name: &'static str,
) -> Result<ProductionV4PinnedReader<File>, NodeError> {
    if pin.bytes == 0 || pin.blake3 == [0; 32] || pin.sha256 == [0; 32] {
        return Err(NodeError::ProductionV4ArtifactPinsMissing);
    }
    let file = File::open(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            NodeError::ProductionV4ArtifactsMissing
        } else {
            io_error("open ProductionV4 artifact", path, source)
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect ProductionV4 artifact", path, source))?;
    if !metadata.is_file() || metadata.len() != pin.bytes {
        return Err(NodeError::ProductionV4ArtifactIdentityMismatch(name));
    }
    Ok(ProductionV4PinnedReader::new(file))
}

#[cfg(all(test, feature = "production-v4"))]
mod production_v4_artifact_tests {
    use super::*;

    #[test]
    fn missing_packaged_artifact_has_actionable_client_classification() {
        let path = std::env::temp_dir().join(format!(
            "cmfd-production-v4-missing-{}-artifact.bank",
            std::process::id()
        ));
        let error = match open_production_v4_pinned_reader(
            &path,
            release_gate::ProductionV3FileIdentityPin {
                bytes: 1,
                blake3: [1; 32],
                sha256: [2; 32],
            },
            "model bank",
        ) {
            Err(error) => error,
            Ok(_) => panic!("missing artifact unexpectedly opened"),
        };

        assert!(matches!(error, NodeError::ProductionV4ArtifactsMissing));
        let client = error.client_error();
        assert_eq!(client.code, "production_v4_artifacts_missing");
        assert_eq!(
            client.message,
            "required ProductionV4 runtime files are missing; complete RCNet runtime setup before starting the node"
        );
        assert!(!client.message.contains(path.to_string_lossy().as_ref()));
    }
}

/// Hashes the same stream that supplies verifier state. This closes both
/// pathname replacement and in-place mutation windows: no verifier authority
/// escapes until the exact consumed bytes match both compiled digests.
#[cfg(feature = "production-v4")]
struct ProductionV4PinnedReader<R> {
    inner: R,
    bytes: u64,
    blake3: blake3::Hasher,
    sha256: Sha256,
}

#[cfg(feature = "production-v4")]
impl<R> ProductionV4PinnedReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bytes: 0,
            blake3: blake3::Hasher::new(),
            sha256: Sha256::new(),
        }
    }

    fn verify_pin(
        self,
        pin: release_gate::ProductionV3FileIdentityPin,
        name: &'static str,
    ) -> Result<(), NodeError> {
        let actual_blake3 = *self.blake3.finalize().as_bytes();
        let actual_sha256: [u8; 32] = self.sha256.finalize().into();
        if self.bytes != pin.bytes || actual_blake3 != pin.blake3 || actual_sha256 != pin.sha256 {
            return Err(NodeError::ProductionV4ArtifactIdentityMismatch(name));
        }
        Ok(())
    }
}

#[cfg(feature = "production-v4")]
impl<R: Read> Read for ProductionV4PinnedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        let read_u64 = u64::try_from(read).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ProductionV4 artifact read length exceeds u64",
            )
        })?;
        self.bytes = self.bytes.checked_add(read_u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ProductionV4 artifact read length overflowed",
            )
        })?;
        self.blake3.update(&buffer[..read]);
        self.sha256.update(&buffer[..read]);
        Ok(read)
    }
}

#[cfg(feature = "production-v3")]
fn network_params_from_verifier(
    profile: NetworkProfile,
    verifier: ConsensusPowVerifier,
) -> Result<(NetworkParams, ConsensusPowVerifier), NodeError> {
    let pow = verifier.parameters();
    let params = network_params_from_pow(profile, pow)?;
    Ok((params, verifier))
}

#[cfg(any(feature = "production-v3", feature = "production-v4"))]
fn network_params_from_pow(
    profile: NetworkProfile,
    pow: PowParameters,
) -> Result<NetworkParams, NodeError> {
    network_params_from_pow_with_launch(profile, pow, None)
}

fn network_params_from_pow_with_launch(
    profile: NetworkProfile,
    pow: PowParameters,
    launch: Option<&mainnet_runtime::AuthenticatedMainnetRuntime>,
) -> Result<NetworkParams, NodeError> {
    mainnet_runtime::require_authenticated_profile(profile, launch)?;
    let params = NetworkParams {
        network_id: profile.network_id,
        protocol_version: NETWORK_PROTOCOL_VERSION,
        genesis_hash: profile.virtual_genesis_hash,
        genesis_timestamp: profile.virtual_genesis_timestamp,
        pow_limit: profile.pow_limit,
        initial_target: profile.initial_target,
        pow,
        monetary_policy: DEFAULT_MONETARY_POLICY,
        rewards: FixedRewardDestinations {
            steward: profile.rewards.steward,
            community: profile.rewards.community,
        },
        max_future_offset_secs: MAX_FUTURE_OFFSET_SECS,
    };
    params.validate()?;
    Ok(params)
}

fn require_production_v3_file_identity(
    name: &'static str,
    pin: release_gate::ProductionV3FileIdentityPin,
    actual: &cmfd_consensus::FileIdentity,
) -> Result<(), NodeError> {
    if pin.bytes != actual.bytes || pin.blake3 != actual.blake3 || pin.sha256 != actual.sha256 {
        return Err(NodeError::ProductionV3ArtifactIdentityMismatch(name));
    }
    Ok(())
}

fn network_params_for_profile(profile: NetworkProfile) -> Result<NetworkParams, NodeError> {
    network_params_and_verifier_for_profile(profile, None, None).map(|(params, _)| params)
}

pub(crate) fn thin_miner_network_params() -> Result<NetworkParams, NodeError> {
    #[cfg(feature = "production-v4")]
    if COMPILED_NETWORK_PROFILE.kind == NetworkProfileKind::Mainnet {
        return mainnet_runtime::compiled_mainnet_runtime()?.network_parameters();
    }
    match COMPILED_NETWORK_PROFILE.proof {
        ProofProfile::DevnetV2Reference => network_params_for_profile(COMPILED_NETWORK_PROFILE),
        ProofProfile::ProductionV3 => Err(NodeError::ProductionV3Unavailable),
        ProofProfile::ProductionV4 => {
            #[cfg(feature = "production-v4")]
            {
                network_params_from_pow(
                    COMPILED_NETWORK_PROFILE,
                    PowParameters::V4Candidate(
                        cmfd_consensus::ForgeMatrixV4CandidateParameters::for_network(
                            COMPILED_NETWORK_PROFILE.network_id,
                        )?,
                    ),
                )
            }
            #[cfg(not(feature = "production-v4"))]
            {
                Err(NodeError::ProductionV4Unavailable)
            }
        }
    }
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

/// Builds the deterministic RCNet-1 block-one qualification template entirely
/// in memory. This source-stage tool exists only in the isolated ProductionV4
/// testnet build: it has no peer address, storage path, activation evidence, or
/// production-RC feature path. The fixed record is parsed from its authenticated
/// byte snapshot, and the model-bank identity is computed over the exact stream
/// consumed by verifier construction. No verifier authority or chain state is
/// returned until both compiled identities match.
#[cfg(feature = "production-v4-testnet")]
pub fn build_offline_rcnet1_block1_qualification_template(
    artifacts: &ProductionV4VerifierArtifacts,
    miner_destination: [u8; 32],
) -> Result<BlockTemplate, NodeError> {
    if COMPILED_NETWORK_PROFILE != PRODUCTION_V4_TESTNET_PROFILE {
        return Err(NodeError::ProductionV4QualificationInvariant(
            "qualification helper is not running in the ProductionV4 testnet build",
        ));
    }
    let (params, verifier) =
        network_params_and_verifier_for_profile(RCNET1_PROFILE, None, Some(artifacts))?;
    let state = ChainState::new(params, verifier)?;
    let timestamp = RCNET1_PROFILE
        .virtual_genesis_timestamp
        .checked_add(1)
        .ok_or(NodeError::ProductionV4QualificationInvariant(
            "virtual genesis timestamp has no block-one successor",
        ))?;
    let template =
        build_template_from_state(&state, &params, miner_destination, timestamp, Vec::new())?;
    let allocation = params.monetary_policy.allocation(1, 0)?;
    let expected_coinbase = Coinbase::new(1, allocation, miner_destination, params.rewards);
    let expected_root = merkle_root(&[expected_coinbase.commitment(params.network_id)]);
    if template.challenge.network_id != RCNET1_PROFILE.network_id
        || template.challenge.previous_block != RCNET1_PROFILE.virtual_genesis_hash
        || template.challenge.transaction_root != expected_root
        || template.challenge.height != 1
        || template.challenge.timestamp != timestamp
        || template.challenge.target != RCNET1_PROFILE.pow_limit
        || template.coinbase != expected_coinbase
        || !template.transactions.is_empty()
        || template.total_fees_burned != 0
    {
        return Err(NodeError::ProductionV4QualificationInvariant(
            "constructed block-one template does not match immutable RCNet-1 state",
        ));
    }
    Ok(template)
}

#[cfg(all(test, feature = "production-v4-testnet"))]
mod offline_rcnet1_qualification_tests {
    use std::io::Read as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct MidstreamMutationReader {
        expected: Vec<u8>,
        mutated: Vec<u8>,
        position: usize,
    }

    impl Read for MidstreamMutationReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.position == self.expected.len() || buffer.is_empty() {
                return Ok(0);
            }
            let split = self.expected.len() / 2;
            let byte = if self.position < split {
                self.expected[self.position]
            } else {
                self.mutated[self.position]
            };
            buffer[0] = byte;
            self.position += 1;
            Ok(1)
        }
    }

    fn pin_for(bytes: &[u8]) -> release_gate::ProductionV3FileIdentityPin {
        release_gate::ProductionV3FileIdentityPin {
            bytes: bytes.len() as u64,
            blake3: *blake3::hash(bytes).as_bytes(),
            sha256: Sha256::digest(bytes).into(),
        }
    }

    #[test]
    fn pinned_reader_rejects_deterministic_midstream_mutation() {
        let expected = b"authenticated ProductionV4 artifact".to_vec();
        let mut mutated = expected.clone();
        *mutated.last_mut().unwrap() ^= 1;
        let pin = pin_for(&expected);
        let mut reader = ProductionV4PinnedReader::new(MidstreamMutationReader {
            expected,
            mutated,
            position: 0,
        });
        let mut consumed = Vec::new();
        reader.read_to_end(&mut consumed).unwrap();
        assert!(matches!(
            reader.verify_pin(pin, "test artifact"),
            Err(NodeError::ProductionV4ArtifactIdentityMismatch(
                "test artifact"
            ))
        ));
    }

    #[test]
    fn altered_artifacts_are_rejected_before_state_construction() {
        let root = std::env::temp_dir().join(format!(
            "cmfd-offline-rcnet1-altered-artifacts-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let artifacts = ProductionV4VerifierArtifacts {
            bank: root.join("altered-model.bank"),
            fixed_record: root.join("altered-fixed-record.json"),
        };
        fs::write(&artifacts.bank, b"altered bank").unwrap();
        fs::write(&artifacts.fixed_record, b"{}\n").unwrap();

        assert!(matches!(
            build_offline_rcnet1_block1_qualification_template(
                &artifacts,
                default_miner_destination()
            ),
            Err(NodeError::ProductionV4ArtifactIdentityMismatch(
                "fixed artifact record"
            ))
        ));

        fs::remove_file(artifacts.bank).unwrap();
        fs::remove_file(artifacts.fixed_record).unwrap();
        fs::remove_dir(root).unwrap();
    }
}

fn build_template_from_state(
    state: &ChainState,
    params: &NetworkParams,
    miner_destination: [u8; 32],
    now_unix_seconds: u64,
    transactions: Vec<Transaction>,
) -> Result<BlockTemplate, NodeError> {
    VerifyingKey::from_bytes(&miner_destination).map_err(|_| NodeError::InvalidMinerDestination)?;
    let earliest = state
        .median_time_past()
        .checked_add(1)
        .ok_or(NodeError::TemplateTimeUnavailable)?;
    let latest = now_unix_seconds
        .checked_add(params.max_future_offset_secs)
        .ok_or(NodeError::TemplateTimeUnavailable)?;
    let timestamp = now_unix_seconds.max(earliest);
    if timestamp > latest {
        return Err(NodeError::TemplateTimeUnavailable);
    }

    let height = state.next_height();
    let validation = state.validate_transactions_for_next_block(&transactions)?;
    let allocation = params
        .monetary_policy
        .allocation(height, validation.total_burned_fees)?;
    let coinbase = Coinbase::new(height, allocation, miner_destination, params.rewards);
    let mut commitments = Vec::with_capacity(transactions.len() + 1);
    commitments.push(coinbase.commitment(params.network_id));
    commitments.extend(transactions.iter().map(Transaction::txid));
    let transaction_root = merkle_root(&commitments);
    let challenge = BlockChallenge {
        network_id: params.network_id,
        previous_block: state.tip(),
        transaction_root,
        height,
        timestamp,
        target: state.expected_target()?,
    };
    Ok(BlockTemplate {
        challenge,
        coinbase,
        transactions,
        total_fees_burned: validation.total_burned_fees,
    })
}

/// A canonical transaction that moved coins from a sponsor key into the pool
/// wallet: an input witnessed by `sponsor`, no input witnessed by the wallet
/// key, and `amount_atoms` across its outputs locked to the wallet key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SponsorTransfer {
    pub txid: [u8; 32],
    pub height: u64,
    pub amount_atoms: u64,
}

impl Node {
    /// Open mainnet only with the opaque result of plan/beacon authentication.
    /// The same immutable parameters govern startup replay and live admission.
    #[cfg(feature = "production-v4")]
    pub fn open_with_authenticated_mainnet(
        data_dir: impl AsRef<Path>,
        launch: &mainnet_runtime::AuthenticatedMainnetRuntime,
        artifacts: &ProductionV4VerifierArtifacts,
        wallet_passphrase: Option<&[u8]>,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_artifacts_worker_exchange_and_launch(
            data_dir,
            launch.profile(),
            None,
            None,
            Some(artifacts),
            None,
            wallet_passphrase,
            None,
            Some(launch),
        )
    }

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
        let record =
            production_v3_record_for_profile(COMPILED_NETWORK_PROFILE, production_v3_artifacts)?;
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            COMPILED_NETWORK_PROFILE,
            record.as_ref(),
            production_v3_artifacts.cloned(),
            None,
            None,
            None,
        )
    }

    /// Opens the isolated ProductionV4 testnet only after authenticating its
    /// release-pinned fixed record and complete model bank.
    pub fn open_with_v4_artifacts(
        data_dir: impl AsRef<Path>,
        production_v4_artifacts: &ProductionV4VerifierArtifacts,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            COMPILED_NETWORK_PROFILE,
            None,
            None,
            Some(production_v4_artifacts),
            None,
            None,
        )
    }

    /// Open a verifier-only ProductionV3 node from the release-pinned Record
    /// V2. The model bank and standalone manifest are not node dependencies.
    pub fn open_with_record(
        data_dir: impl AsRef<Path>,
        production_v3_record: Option<&ProductionV3VerifierRecord>,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            COMPILED_NETWORK_PROFILE,
            production_v3_record,
            None,
            None,
            None,
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
        let record =
            production_v3_record_for_profile(COMPILED_NETWORK_PROFILE, production_v3_artifacts)?;
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            COMPILED_NETWORK_PROFILE,
            record.as_ref(),
            production_v3_artifacts.cloned(),
            None,
            Some(verifier_worker),
            None,
        )
    }

    /// Open a verifier-only ProductionV3 node and install its record-only
    /// worker before replaying any stored block.
    pub fn open_with_record_and_verifier_worker(
        data_dir: impl AsRef<Path>,
        production_v3_record: Option<&ProductionV3VerifierRecord>,
        verifier_worker: VerifierWorkerConfig,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            COMPILED_NETWORK_PROFILE,
            production_v3_record,
            None,
            None,
            Some(verifier_worker),
            None,
        )
    }

    /// Opens the node on an explicit immutable network profile.
    ///
    /// RCNet-1 fails before acquiring a data-directory lock unless its exact
    /// release-pinned V3 Record V2 can construct the consensus verifier. This ordering
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
        let record = production_v3_record_for_profile(profile, production_v3_artifacts)?;
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            profile,
            record.as_ref(),
            production_v3_artifacts.cloned(),
            None,
            None,
            None,
        )
    }

    /// Opens the compiled network with any required proof authority and an
    /// optional passphrase for its encrypted live wallet key.
    pub fn open_with_runtime_security_and_wallet_passphrase(
        data_dir: impl AsRef<Path>,
        production_v3_record: Option<&ProductionV3VerifierRecord>,
        production_v4_artifacts: Option<&ProductionV4VerifierArtifacts>,
        verifier_worker: Option<&VerifierWorkerConfig>,
        wallet_passphrase: Option<&[u8]>,
    ) -> Result<Self, NodeError> {
        if production_v4_artifacts.is_some()
            && (production_v3_record.is_some() || verifier_worker.is_some())
        {
            return Err(NodeError::ProductionV4ArtifactsUnexpected);
        }
        Self::open_with_profile_artifacts_and_worker(
            data_dir,
            COMPILED_NETWORK_PROFILE,
            production_v3_record,
            None,
            production_v4_artifacts,
            verifier_worker.cloned(),
            wallet_passphrase,
        )
    }

    /// Opens the compiled network with an authenticated withdrawal journal and
    /// an external rollback anchor. Existing entry points remain suitable for
    /// data directories that have never enrolled a withdrawal journal.
    pub fn open_with_runtime_security_wallet_and_exchange_withdrawal(
        data_dir: impl AsRef<Path>,
        production_v3_record: Option<&ProductionV3VerifierRecord>,
        production_v4_artifacts: Option<&ProductionV4VerifierArtifacts>,
        verifier_worker: Option<&VerifierWorkerConfig>,
        wallet_passphrase: Option<&[u8]>,
        exchange_withdrawal_security: Option<&ExchangeWithdrawalSecurityConfig>,
    ) -> Result<Self, NodeError> {
        if production_v4_artifacts.is_some()
            && (production_v3_record.is_some() || verifier_worker.is_some())
        {
            return Err(NodeError::ProductionV4ArtifactsUnexpected);
        }
        Self::open_with_profile_artifacts_worker_and_exchange_withdrawal(
            data_dir,
            COMPILED_NETWORK_PROFILE,
            production_v3_record,
            None,
            production_v4_artifacts,
            verifier_worker.cloned(),
            wallet_passphrase,
            exchange_withdrawal_security,
        )
    }

    #[cfg(test)]
    pub(crate) fn open_with_profile_and_exchange_withdrawal_security(
        data_dir: impl AsRef<Path>,
        profile: NetworkProfile,
        exchange_withdrawal_security: &ExchangeWithdrawalSecurityConfig,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_artifacts_worker_and_exchange_withdrawal(
            data_dir,
            profile,
            None,
            None,
            None,
            None,
            None,
            Some(exchange_withdrawal_security),
        )
    }

    fn open_with_profile_artifacts_and_worker(
        data_dir: impl AsRef<Path>,
        profile: NetworkProfile,
        production_v3_record: Option<&ProductionV3VerifierRecord>,
        production_v3_artifacts: Option<ProductionV3VerifierArtifacts>,
        production_v4_artifacts: Option<&ProductionV4VerifierArtifacts>,
        verifier_worker: Option<VerifierWorkerConfig>,
        wallet_passphrase: Option<&[u8]>,
    ) -> Result<Self, NodeError> {
        Self::open_with_profile_artifacts_worker_and_exchange_withdrawal(
            data_dir,
            profile,
            production_v3_record,
            production_v3_artifacts,
            production_v4_artifacts,
            verifier_worker,
            wallet_passphrase,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_with_profile_artifacts_worker_and_exchange_withdrawal(
        data_dir: impl AsRef<Path>,
        profile: NetworkProfile,
        production_v3_record: Option<&ProductionV3VerifierRecord>,
        production_v3_artifacts: Option<ProductionV3VerifierArtifacts>,
        production_v4_artifacts: Option<&ProductionV4VerifierArtifacts>,
        verifier_worker: Option<VerifierWorkerConfig>,
        wallet_passphrase: Option<&[u8]>,
        exchange_withdrawal_security: Option<&ExchangeWithdrawalSecurityConfig>,
    ) -> Result<Self, NodeError> {
        let (profile, launch) = mainnet_runtime::resolve_compiled_profile(profile)?;
        Self::open_with_profile_artifacts_worker_exchange_and_launch(
            data_dir,
            profile,
            production_v3_record,
            production_v3_artifacts,
            production_v4_artifacts,
            verifier_worker,
            wallet_passphrase,
            exchange_withdrawal_security,
            launch,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_with_profile_artifacts_worker_exchange_and_launch(
        data_dir: impl AsRef<Path>,
        profile: NetworkProfile,
        production_v3_record: Option<&ProductionV3VerifierRecord>,
        production_v3_artifacts: Option<ProductionV3VerifierArtifacts>,
        production_v4_artifacts: Option<&ProductionV4VerifierArtifacts>,
        verifier_worker: Option<VerifierWorkerConfig>,
        wallet_passphrase: Option<&[u8]>,
        exchange_withdrawal_security: Option<&ExchangeWithdrawalSecurityConfig>,
        launch: Option<&mainnet_runtime::AuthenticatedMainnetRuntime>,
    ) -> Result<Self, NodeError> {
        let (params, verifier) = network_params_and_verifier_with_launch(
            profile,
            production_v3_record,
            production_v4_artifacts,
            launch,
        )?;
        let block_preverifier = BlockPreverifier::new(verifier.clone(), profile.proof);
        let external_replay = verifier_worker.is_some();
        if let Some(config) = verifier_worker {
            install_external_proof_verifier(profile, &block_preverifier, config)?;
        } else if matches!(profile.proof, ProofProfile::ProductionV3) {
            return Err(NodeError::ProductionV3Unavailable);
        }
        let data_dir = data_dir.as_ref().to_path_buf();
        let lock = DataDirLock::acquire(&data_dir)?;
        let exchange_withdrawal_security = exchange_withdrawal_security
            .map(|config| exchange_withdrawal::LoadedWithdrawalSecurity::load(config, &data_dir))
            .transpose()
            .map_err(|error| NodeError::ExchangeWithdrawalJournal {
                code: error.code(),
                retryable: error.retryable(),
                message: error.client_message(),
            })?;
        let log_path = data_dir.join(BLOCK_LOG_FILE);
        let log = open_block_log(&log_path)?;
        let fingerprint = params.fingerprint()?;
        let metadata = load_metadata(
            &data_dir,
            fingerprint,
            &log,
            &log_path,
            profile.network_id == cmfd_consensus::PRODUCTION_V4_RCNET1_NETWORK_ID,
        )?;
        let (wallet_signing_key, legacy_shared_wallet) = load_or_create_wallet_key(
            &data_dir,
            profile,
            metadata,
            &log,
            &log_path,
            wallet_passphrase,
        )?;

        let restored =
            startup_snapshot::load_startup_snapshot(&data_dir, &log, &log_path, params, &verifier)?;
        let (state, index, replay, startup_snapshot_used, history_verified) = match restored {
            Some(mut restored) => {
                attach_prune_anchor(&data_dir, &mut restored.index, params, &verifier)?;
                let verified = restored.history_verified;
                (
                    restored.state,
                    restored.index,
                    restored.replay,
                    true,
                    verified,
                )
            }
            None => {
                let mut state = ChainState::new(params, verifier.clone())?;
                let mut index = BlockIndex::new(params.genesis_hash);
                let replay = replay_log(
                    &data_dir,
                    &log,
                    &log_path,
                    &mut state,
                    &mut index,
                    &verifier,
                    params,
                    external_replay.then_some(&block_preverifier),
                )?;
                (state, index, replay, false, true)
            }
        };
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

        #[cfg(not(feature = "production-v3"))]
        let _ = production_v3_artifacts;

        let exchange_custody_v3_wallet_state =
            if exchange_custody_v3::persisted_v3_wallet_claim_required(&data_dir) {
                ExchangeCustodyV3WalletState::Required
            } else {
                ExchangeCustodyV3WalletState::Unclaimed
            };
        let explorer_outputs =
            explorer_address_index::AddressOutputIndex::from_utxos(state.utxos());
        let mut node = Self {
            instance_id: next_node_instance_id()?,
            data_dir,
            profile,
            params,
            fingerprint,
            wallet_signing_key,
            legacy_shared_wallet,
            verifier,
            #[cfg(feature = "production-v3")]
            production_v3_artifacts,
            block_preverifier,
            state,
            index,
            branch_checkpoints: BranchCheckpointCache::default(),
            explorer_outputs,
            explorer_history_cache: None,
            wallet_history_cache: None,
            wallet_history_scan: None,
            #[cfg(test)]
            wallet_history_inline_scan_bytes: wallet_history::INLINE_SCAN_BYTES,
            transaction_scan_marks: HashMap::new(),
            chain_revision,
            record_count: replay.record_count,
            prune_keep_blocks: None,
            mempool: BTreeMap::new(),
            mempool_bytes: 0,
            exchange_withdrawal_reservations: HashMap::new(),
            exchange_withdrawal_security,
            exchange_custody_v3_wallet_state,
            exchange_rpc_active: false,
            log,
            log_readers: Arc::new(()),
            log_epoch: 0,
            history_scrub: if history_verified || replay.record_count == 0 {
                history_scrub::Progress::verified(replay.record_count)
            } else {
                history_scrub::Progress::default()
            },
            last_record_digest: replay.last_record_digest,
            block_log_length: replay.log_length,
            storage_faulted: false,
            startup_snapshot_used,
            rejected_proof_ids: HashSet::new(),
            rejected_proof_order: VecDeque::new(),
            rejected_body_digests: HashSet::new(),
            rejected_body_order: VecDeque::new(),
            public_peer_mode: false,
            peer_observations: BTreeMap::new(),
            #[cfg(test)]
            commit_race_barrier: None,
            #[cfg(test)]
            completion_fault_barrier: None,
            #[cfg(test)]
            explorer_block_reads: 0,
            _lock: lock,
        };
        // A persisted v3 marker or slot latches the native wallet closed before
        // the v3 runtime is opened. Do not ask the legacy v2 loader to decode
        // those same slot names; the v3 runtime authenticates them and installs
        // their reservations when it claims the wallet. Exact v2 state remains
        // Unclaimed and continues through the legacy recovery path below.
        if node.exchange_custody_v3_wallet_state == ExchangeCustodyV3WalletState::Unclaimed {
            exchange_withdrawal::ExchangeWithdrawalJournal::install_persisted_reservations(
                &mut node,
            )
            .map_err(|error| NodeError::ExchangeWithdrawalJournal {
                code: error.code(),
                retryable: error.retryable(),
                message: error.client_message(),
            })?;
        }
        if !startup_snapshot_used {
            let _ = node.persist_startup_snapshot();
        }
        // Keep the next start fast; the cache covers every current record.
        let _ = node.persist_index_cache();
        node.remember_active_branch_checkpoint(true);
        Ok(node)
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Writes a two-slot, locally authenticated startup snapshot.
    ///
    /// The canonical state and every retained fork locator are bound to the
    /// exact log extent. Restart authenticates the terminal record and the
    /// records the index cache does not cover, and the background history
    /// scrub re-checks the rest; an ineligible cache falls back to replay.
    pub fn persist_startup_snapshot(&self) -> Result<(), NodeError> {
        startup_snapshot::persist_startup_snapshot(self)
    }

    /// Saves the transaction and address location indexes bound to the
    /// newest record, so the next start reads only newer records.
    pub fn persist_index_cache(&self) -> Result<(), NodeError> {
        startup_snapshot::persist_index_cache(self)
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

    #[cfg(test)]
    fn pause_commit_race(&self, point: CommitPausePoint) {
        if let Some(barrier) = self
            .commit_race_barrier
            .as_ref()
            .filter(|barrier| barrier.point == point)
        {
            barrier.entered.wait();
            barrier.release.wait();
        }
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

    /// Prepare process-reusable Production V3 mining state from the compiled
    /// bank, manifest, and Record V2 identities. The node's verifier-only
    /// authority cannot authorize model reads, so mining independently uses
    /// the release-pinned one-pass bank loader.
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
        ProductionV3MiningWorkFactory::load(
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
    /// `open_with_record_and_verifier_worker` and cannot switch backends at
    /// runtime.
    pub fn use_external_proof_verifier(
        &mut self,
        config: VerifierWorkerConfig,
    ) -> Result<(), NodeError> {
        if !matches!(self.profile.proof, ProofProfile::DevnetV2Reference) {
            return Err(match self.profile.proof {
                ProofProfile::ProductionV3 => NodeError::ProductionV3Unavailable,
                ProofProfile::ProductionV4 => NodeError::ProductionV4Unavailable,
                ProofProfile::DevnetV2Reference => unreachable!(),
            });
        }
        install_external_proof_verifier(self.profile, &self.block_preverifier, config)
    }

    /// Block identifier of the active chain at `height`, if that height exists.
    pub(crate) fn active_block_id_at(&self, height: u64) -> Option<[u8; 32]> {
        usize::try_from(height)
            .ok()
            .and_then(|height| self.index.active_chain.get(height).copied())
    }

    /// Sponsor transfers into the pool wallet in canonical blocks at heights
    /// `from_height..=to_height`, clamped to the active chain, in chain order.
    pub(crate) fn sponsor_transfers_to_wallet(
        &mut self,
        sponsor: [u8; 32],
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<SponsorTransfer>, NodeError> {
        // TODO(bonus-reserve): implemented in the bonus-reserve change.
        let _ = (sponsor, from_height, to_height);
        Ok(Vec::new())
    }

    pub fn wallet_destination(&self) -> [u8; 32] {
        self.wallet_signing_key.verifying_key().to_bytes().into()
    }

    pub(crate) fn exchange_custody_destination_utxo_summary(
        &self,
        destination: [u8; 32],
    ) -> Result<ExchangeCustodyDestinationUtxoSummary, NodeError> {
        let next_height = self.state.next_height();
        let mut summary = ExchangeCustodyDestinationUtxoSummary {
            tip: self.state.tip(),
            next_height,
            unspent_count: 0,
            unspent_atoms: 0,
            spendable_count: 0,
            spendable_atoms: 0,
            local_mempool_output_count: 0,
            local_mempool_output_atoms: 0,
        };
        for (_, output) in self.state.utxos().iter() {
            if output.lock != OutputLock::Key(destination) {
                continue;
            }
            summary.unspent_count += 1;
            summary.unspent_atoms = checked_wallet_add(summary.unspent_atoms, output.value)?;
            if next_height >= output.spendable_height {
                summary.spendable_count += 1;
                summary.spendable_atoms =
                    checked_wallet_add(summary.spendable_atoms, output.value)?;
            }
        }
        for entry in self.mempool.values() {
            for output in &entry.transaction.outputs {
                if output.lock != OutputLock::Key(destination) {
                    continue;
                }
                summary.local_mempool_output_count += 1;
                summary.local_mempool_output_atoms =
                    checked_wallet_add(summary.local_mempool_output_atoms, output.value)?;
            }
        }
        Ok(summary)
    }

    pub(crate) fn exchange_custody_confirmed_legacy_sweep(
        &mut self,
        sweep_txid: [u8; 32],
        legacy_destination: [u8; 32],
    ) -> Result<Option<ExchangeCustodyLegacySweepSummary>, NodeError> {
        let result = (|| {
            for position in (1..self.index.active_chain.len()).rev() {
                let block_id = self.index.active_chain[position];
                let indexed = self.index.blocks.get(&block_id).cloned().ok_or_else(|| {
                    NodeError::CorruptLog(
                        "active legacy-sweep lookup refers to an absent block".to_owned(),
                    )
                })?;
                let block = read_indexed_block(
                    &self.log,
                    &self.data_dir.join(BLOCK_LOG_FILE),
                    &indexed,
                    block_id,
                    self.params.network_id,
                    matches!(self.profile.proof, ProofProfile::ProductionV3),
                )?;
                let Some(transaction) = block
                    .transactions
                    .iter()
                    .find(|transaction| transaction.txid() == sweep_txid)
                else {
                    continue;
                };
                let confirmations = u64::try_from(self.index.active_chain.len() - position)
                    .map_err(|_| {
                        NodeError::CorruptLog(
                            "legacy-sweep confirmation depth does not fit u64".to_owned(),
                        )
                    })?;
                let height = u64::try_from(position).map_err(|_| {
                    NodeError::CorruptLog("legacy-sweep height does not fit u64".to_owned())
                })?;
                let legacy_input_count = transaction
                    .inputs
                    .iter()
                    .filter(|input| {
                        matches!(
                            &input.witness,
                            InputWitness::Key { public_key, .. }
                                if *public_key == legacy_destination
                        )
                    })
                    .count();
                let legacy_output_count = transaction
                    .outputs
                    .iter()
                    .filter(|output| output.lock == OutputLock::Key(legacy_destination))
                    .count();
                return Ok(Some(ExchangeCustodyLegacySweepSummary {
                    txid: sweep_txid,
                    block_id,
                    height,
                    confirmations,
                    legacy_input_count,
                    legacy_output_count,
                }));
            }
            Ok(None)
        })();
        self.latch_authenticated_storage_failure(result)
    }

    pub fn pool_payout_signer(&self) -> pool::PoolPayoutSigner {
        pool::PoolPayoutSigner::new(self.wallet_signing_key.clone())
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
        let proof_queue_telemetry = self.block_preverifier.queue.telemetry()?;
        let proof_verification_remote_admission =
            self.block_preverifier.remote_admission.telemetry()?;
        let (
            proof_verification_mode,
            proof_verification_timeout_ms,
            proof_verification_memory_limit_bytes,
        ) = self.block_preverifier.backend_status()?;
        let proof_verification_teardown_failures =
            self.block_preverifier.backend_teardown_failures()?;
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
            exchange_custody_v3_wallet_state: self.exchange_custody_v3_wallet_state.as_str(),
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
            proof_verification_normal_admission: proof_queue_telemetry.normal,
            proof_verification_priority_admission: proof_queue_telemetry.priority,
            proof_verification_remote_admission,
            proof_verification_remote_admission_capacity: self
                .block_preverifier
                .remote_admission
                .max_in_flight,
            proof_verification_remote_admission_wait_timeout_ms: self
                .block_preverifier
                .remote_admission
                .wait_timeout
                .as_millis()
                .min(u128::from(u64::MAX))
                as u64,
            proof_verification_capacity: self.block_preverifier.queue.max_active,
            proof_verification_queue_capacity: self
                .block_preverifier
                .queue
                .max_queued
                .saturating_add(MAX_PRIORITY_QUEUED_PROOF_VERIFICATIONS),
            proof_verification_mode,
            proof_verification_timeout_ms,
            proof_verification_memory_limit_bytes,
            proof_verification_teardown_failures,
            storage_healthy: !self.storage_faulted,
            startup_snapshot_used: self.startup_snapshot_used,
            public_peer_mode: self.public_peer_mode,
            prune_keep_blocks: self.prune_keep_blocks,
            pruned_height: self.prune_height(),
            history_scrub_complete: self.history_scrub.complete,
            history_scrub_verified_records: self.history_scrub.verified_records,
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
                    sync_cursor: None,
                    relay_cursor: None,
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
    /// mempool and durable exchange-withdrawal reservation overlays.
    pub fn wallet_snapshot(&mut self) -> Result<WalletSnapshot, NodeError> {
        let result = self.wallet_snapshot_unlatched();
        self.latch_authenticated_storage_failure(result)
    }

    fn wallet_snapshot_unlatched(&mut self) -> Result<WalletSnapshot, NodeError> {
        let destination = self.wallet_destination();
        let reserved = self.wallet_reserved_inputs();
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
        if self.exchange_custody_v3_wallet_state.locks_native_wallet() {
            return Err(NodeError::ExchangeCustodyV3WalletExclusive);
        }
        let (transaction, change) =
            self.prepare_dev_wallet_payment(recipient, amount, fee_burned)?;
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

    pub(crate) fn prepare_dev_wallet_payment(
        &self,
        recipient: [u8; 32],
        amount: u64,
        fee_burned: u64,
    ) -> Result<(Transaction, u64), NodeError> {
        let plan = self.plan_dev_wallet_payment(recipient, amount, fee_burned)?;
        let transaction = self.sign_wallet_payment_plan(&plan, false)?;
        Ok((transaction, plan.change_atoms))
    }

    /// Pool payments must also exclude inputs of journaled payments that are
    /// not currently in the mempool (including held signed transactions).
    pub(crate) fn prepare_pool_wallet_payment(
        &self,
        recipient: [u8; 32],
        amount: u64,
        fee_burned: u64,
        reserved: &HashSet<OutPoint>,
    ) -> Result<(Transaction, u64), NodeError> {
        let destination = self.wallet_destination();
        let plan = self.plan_wallet_payment_for_destinations(
            recipient,
            amount,
            fee_burned,
            &[destination],
            destination,
            reserved,
        )?;
        let transaction = self.sign_wallet_payment_plan(&plan, false)?;
        Ok((transaction, plan.change_atoms))
    }

    /// Selects inputs and fixes the exact payment semantics without using the
    /// wallet signing key. Exchange custody persists this intent and installs
    /// its digest-bound reservations before calling
    /// [`Self::sign_dev_wallet_payment`].
    pub(crate) fn plan_dev_wallet_payment(
        &self,
        recipient: [u8; 32],
        amount: u64,
        fee_burned: u64,
    ) -> Result<WalletPaymentPlan, NodeError> {
        let destination = self.wallet_destination();
        self.plan_wallet_payment_for_destinations(
            recipient,
            amount,
            fee_burned,
            &[destination],
            destination,
            &HashSet::new(),
        )
    }

    /// Plans an exchange-custody payment for public keys whose private
    /// material may be local, remote, or held by a threshold signer. This
    /// function only reads chain state and never accesses wallet secrets.
    pub(crate) fn plan_exchange_custody_payment(
        &self,
        recipient: [u8; 32],
        amount: u64,
        fee_burned: u64,
        input_destinations: &[[u8; 32]],
        change_destination: [u8; 32],
    ) -> Result<WalletPaymentPlan, NodeError> {
        self.plan_wallet_payment_for_destinations(
            recipient,
            amount,
            fee_burned,
            input_destinations,
            change_destination,
            &HashSet::new(),
        )
    }

    fn plan_wallet_payment_for_destinations(
        &self,
        recipient: [u8; 32],
        amount: u64,
        fee_burned: u64,
        input_destinations: &[[u8; 32]],
        change_destination: [u8; 32],
        additional_reserved: &HashSet<OutPoint>,
    ) -> Result<WalletPaymentPlan, NodeError> {
        VerifyingKey::from_bytes(&recipient).map_err(|_| NodeError::InvalidWalletRecipient)?;
        validate_wallet_minimum_fee(self.params.network_id, fee_burned)?;
        if amount == 0 {
            return Err(NodeError::WalletZeroAmount);
        }
        let mut destinations = HashSet::with_capacity(input_destinations.len());
        for destination in input_destinations {
            VerifyingKey::from_bytes(destination)
                .map_err(|_| NodeError::InvalidWalletPaymentPlan("custody input key is invalid"))?;
            if !destinations.insert(*destination) {
                return Err(NodeError::InvalidWalletPaymentPlan(
                    "custody input keys are duplicated",
                ));
            }
        }
        VerifyingKey::from_bytes(&change_destination)
            .map_err(|_| NodeError::InvalidWalletPaymentPlan("custody change key is invalid"))?;
        if !destinations.contains(&change_destination) {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "custody change key is not spendable",
            ));
        }
        let required = amount
            .checked_add(fee_burned)
            .ok_or(NodeError::WalletAmountOverflow)?;
        let mut reserved = self.wallet_reserved_inputs();
        reserved.extend(additional_reserved);
        let mut candidates = Vec::new();
        let mut immature = 0_u64;
        for (outpoint, output) in self.state.utxos().iter() {
            let OutputLock::Key(public_key) = output.lock else {
                continue;
            };
            if !destinations.contains(&public_key) {
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
        let output_spendable_height = self.state.next_height();
        let mut outputs = vec![TxOutput {
            value: amount,
            lock: OutputLock::Key(recipient),
            spendable_height: output_spendable_height,
        }];
        if change > 0 {
            outputs.push(TxOutput {
                value: change,
                lock: OutputLock::Key(change_destination),
                spendable_height: output_spendable_height,
            });
        }
        let selected_input_values = selected
            .iter()
            .map(|outpoint| {
                self.state
                    .utxos()
                    .get(outpoint)
                    .map(|output| output.value)
                    .ok_or(NodeError::InvalidWalletPaymentPlan(
                        "selected input disappeared during planning",
                    ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transaction = Transaction {
            network_id: self.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: selected
                .into_iter()
                .map(|previous| {
                    let public_key =
                        match self.state.utxos().get(&previous).map(|output| &output.lock) {
                            Some(OutputLock::Key(public_key))
                                if destinations.contains(public_key) =>
                            {
                                *public_key
                            }
                            _ => unreachable!("selected custody input was validated above"),
                        };
                    TxInput {
                        previous,
                        witness: InputWitness::Key {
                            // The public key participates in the signing digest,
                            // so fix it now while leaving only the signature blank.
                            public_key,
                            signature: Vec::new(),
                        },
                    }
                })
                .collect(),
            outputs,
        };
        let plan = WalletPaymentPlan {
            transaction,
            recipient,
            amount_atoms: amount,
            fee_burned_atoms: fee_burned,
            change_atoms: change,
            selected_input_values,
            output_spendable_height,
        };
        self.validate_wallet_payment_plan_for_destinations(
            &plan,
            &destinations,
            change_destination,
        )?;
        // Every supported key witness has the same fixed public-key and
        // signature width, so this existing helper computes the exact signed
        // size even when inputs belong to different custody keys.
        let encoded_bytes = signed_wallet_payment_size(&plan.transaction, change_destination)?;
        let minimum_fee = required_relay_fee(encoded_bytes, self.profile.network_id);
        if fee_burned < minimum_fee {
            return Err(NodeError::MempoolFeeTooLow {
                required: minimum_fee,
                actual: fee_burned,
            });
        }
        Ok(plan)
    }

    /// Signs a previously journaled payment intent. Every selected input must
    /// still be reserved for this exact unsigned transaction digest.
    pub(crate) fn sign_dev_wallet_payment(
        &self,
        plan: &WalletPaymentPlan,
    ) -> Result<Transaction, NodeError> {
        self.sign_wallet_payment_plan(plan, true)
    }

    fn sign_wallet_payment_plan(
        &self,
        plan: &WalletPaymentPlan,
        require_exchange_reservation: bool,
    ) -> Result<Transaction, NodeError> {
        if self.exchange_custody_v3_wallet_state.locks_native_wallet()
            && !require_exchange_reservation
        {
            return Err(NodeError::ExchangeCustodyV3WalletExclusive);
        }
        self.validate_wallet_payment_plan(plan)?;
        if require_exchange_reservation {
            let intent = plan.transaction.signing_digest();
            for input in &plan.transaction.inputs {
                if self.exchange_withdrawal_reservations.get(&input.previous) != Some(&intent) {
                    return Err(NodeError::ExchangeWithdrawalReservationMismatch(
                        input.previous,
                    ));
                }
            }
        }
        let mut transaction = plan.transaction.clone();
        let signing_keys = vec![&self.wallet_signing_key; transaction.inputs.len()];
        transaction.sign_all(&signing_keys)?;
        if transaction.signing_digest() != plan.transaction.signing_digest() {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "signing changed the payment intent digest",
            ));
        }
        let encoded_bytes = encode_transaction(&transaction)?.len();
        let minimum_fee = required_relay_fee(encoded_bytes, self.profile.network_id);
        if plan.fee_burned_atoms < minimum_fee {
            return Err(NodeError::MempoolFeeTooLow {
                required: minimum_fee,
                actual: plan.fee_burned_atoms,
            });
        }
        Ok(transaction)
    }

    fn validate_wallet_payment_plan(&self, plan: &WalletPaymentPlan) -> Result<(), NodeError> {
        let destination = self.wallet_destination();
        self.validate_wallet_payment_plan_for_destinations(
            plan,
            &HashSet::from([destination]),
            destination,
        )
    }

    pub(crate) fn validate_exchange_custody_payment_plan(
        &self,
        plan: &WalletPaymentPlan,
        input_destinations: &[[u8; 32]],
        change_destination: [u8; 32],
    ) -> Result<(), NodeError> {
        let destinations: HashSet<_> = input_destinations.iter().copied().collect();
        if destinations.len() != input_destinations.len()
            || !destinations.contains(&change_destination)
        {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "custody wallet key set is invalid",
            ));
        }
        self.validate_wallet_payment_plan_for_destinations(plan, &destinations, change_destination)
    }

    fn validate_wallet_payment_plan_for_destinations(
        &self,
        plan: &WalletPaymentPlan,
        input_destinations: &HashSet<[u8; 32]>,
        change_destination: [u8; 32],
    ) -> Result<(), NodeError> {
        VerifyingKey::from_bytes(&plan.recipient)
            .map_err(|_| NodeError::InvalidWalletPaymentPlan("recipient key is invalid"))?;
        VerifyingKey::from_bytes(&change_destination)
            .map_err(|_| NodeError::InvalidWalletPaymentPlan("change key is invalid"))?;
        if input_destinations.is_empty() || !input_destinations.contains(&change_destination) {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "custody wallet key set is invalid",
            ));
        }
        if plan.amount_atoms == 0 {
            return Err(NodeError::InvalidWalletPaymentPlan("amount is zero"));
        }
        if plan.transaction.network_id != self.params.network_id {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "network does not match",
            ));
        }
        if plan.transaction.version != TRANSACTION_VERSION {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "transaction version does not match",
            ));
        }
        if plan.transaction.inputs.is_empty()
            || plan.transaction.inputs.len() > MAX_TRANSACTION_INPUTS
            || plan.transaction.inputs.len() != plan.selected_input_values.len()
        {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "input values do not match transaction inputs",
            ));
        }
        if plan.output_spendable_height > self.state.next_height() {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "output spendable height is in the future",
            ));
        }

        let mut seen = HashSet::new();
        let mut selected_value = 0_u64;
        for (input, recorded_value) in plan
            .transaction
            .inputs
            .iter()
            .zip(&plan.selected_input_values)
        {
            if !seen.insert(input.previous) {
                return Err(NodeError::InvalidWalletPaymentPlan(
                    "transaction repeats an input",
                ));
            }
            match &input.witness {
                InputWitness::Key {
                    public_key,
                    signature,
                } if input_destinations.contains(public_key) && signature.is_empty() => {}
                _ => {
                    return Err(NodeError::InvalidWalletPaymentPlan(
                        "input is not an unsigned wallet-key witness",
                    ));
                }
            }
            let previous = self
                .state
                .utxos()
                .get(&input.previous)
                .ok_or(NodeError::MempoolUnconfirmedInput(input.previous))?;
            let InputWitness::Key { public_key, .. } = &input.witness else {
                unreachable!("the witness form was validated above")
            };
            if previous.lock != OutputLock::Key(*public_key) {
                return Err(NodeError::InvalidWalletPaymentPlan(
                    "input is not owned by this wallet",
                ));
            }
            if self.state.next_height() < previous.spendable_height {
                return Err(NodeError::InvalidWalletPaymentPlan("input is immature"));
            }
            if previous.value != *recorded_value {
                return Err(NodeError::InvalidWalletPaymentPlan(
                    "recorded input value does not match chain state",
                ));
            }
            selected_value = checked_wallet_add(selected_value, *recorded_value)?;
        }

        let required = plan
            .amount_atoms
            .checked_add(plan.fee_burned_atoms)
            .ok_or(NodeError::WalletAmountOverflow)?;
        if selected_value.checked_sub(required) != Some(plan.change_atoms) {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "input, payment, fee, and change values do not balance",
            ));
        }
        let expected_output_count = if plan.change_atoms == 0 { 1 } else { 2 };
        if plan.transaction.outputs.len() != expected_output_count {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "payment has an unexpected output count",
            ));
        }
        let recipient_output = &plan.transaction.outputs[0];
        if recipient_output.value != plan.amount_atoms
            || recipient_output.lock != OutputLock::Key(plan.recipient)
            || recipient_output.spendable_height != plan.output_spendable_height
        {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "recipient output does not match the payment intent",
            ));
        }
        if plan.change_atoms > 0 {
            let change_output = &plan.transaction.outputs[1];
            if change_output.value != plan.change_atoms
                || change_output.lock != OutputLock::Key(change_destination)
                || change_output.spendable_height != plan.output_spendable_height
            {
                return Err(NodeError::InvalidWalletPaymentPlan(
                    "change output does not match the payment intent",
                ));
            }
        }
        Ok(())
    }

    fn wallet_reserved_inputs(&self) -> HashSet<OutPoint> {
        let mut reserved = mempool_spent_inputs(&self.mempool);
        reserved.extend(self.exchange_withdrawal_reservations.keys().copied());
        reserved
    }

    /// Replaces the complete in-process reservation set restored from the
    /// durable exchange withdrawal journal.
    pub(crate) fn set_exchange_withdrawal_reservations(
        &mut self,
        reservations: HashMap<OutPoint, [u8; 32]>,
    ) {
        self.exchange_withdrawal_reservations = reservations;
    }

    pub(crate) fn claim_exchange_custody_v3_wallet(&mut self) -> Result<(), NodeError> {
        if self.exchange_withdrawal_security.is_some()
            || self.exchange_custody_v3_wallet_state == ExchangeCustodyV3WalletState::Active
        {
            return Err(NodeError::ExchangeCustodyV3WalletExclusive);
        }
        self.exchange_custody_v3_wallet_state = ExchangeCustodyV3WalletState::Active;
        Ok(())
    }

    pub(crate) fn exchange_custody_v3_wallet_is_active(&self) -> bool {
        self.exchange_custody_v3_wallet_state == ExchangeCustodyV3WalletState::Active
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
        validate_wallet_minimum_fee(self.params.network_id, fee_burned)?;
        if self.exchange_custody_v3_wallet_state.locks_native_wallet() {
            return Err(NodeError::ExchangeCustodyV3WalletExclusive);
        }
        if !(2..=MAX_TRANSACTION_INPUTS).contains(&max_inputs) {
            return Err(NodeError::InvalidConsolidationMaxInputs);
        }
        let destination = self.wallet_destination();
        let reserved = self.wallet_reserved_inputs();
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
        let minimum_fee = required_relay_fee(encoded_bytes, self.profile.network_id);
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

    /// Confirmed history for `destination`, newest last. The scan over the
    /// active chain is cached and extended with only the blocks appended since
    /// the previous snapshot; a reorg at the tip is undone block by block. When
    /// the unscanned records exceed `wallet_history::INLINE_SCAN_BYTES` (first
    /// snapshot after start, or a long catch-up), the scan runs on a background
    /// thread and the snapshot reports what is already cached until it
    /// completes, so a wallet refresh never holds the node lock for a
    /// whole-chain read.
    fn confirmed_wallet_history(
        &mut self,
        destination: [u8; 32],
        accepted_height: u64,
        history_limit: usize,
    ) -> Result<Vec<WalletHistoryEntry>, NodeError> {
        if let Some(scan) = self.wallet_history_scan.take() {
            if scan.is_finished() {
                self.wallet_history_cache = Some(scan.finish()?);
            } else {
                self.wallet_history_scan = Some(scan);
            }
        }
        let mut cache = self
            .wallet_history_cache
            .take()
            .filter(|cache| cache.destination() == destination)
            .and_then(|mut cache| cache.rewind_to(&self.index.active_chain).then_some(cache))
            .unwrap_or_else(|| {
                wallet_history::WalletHistoryCache::new(destination, self.index.genesis)
            });
        let targets = self.wallet_history_scan_targets(cache.scanned_position() + 1)?;
        let log_path = self.data_dir.join(BLOCK_LOG_FILE);
        let require_v2 = matches!(self.profile.proof, ProofProfile::ProductionV3);
        let next_height = self.state.next_height();
        let pending_bytes: u64 = targets
            .iter()
            .map(|(_, _, indexed)| indexed.locator.length)
            .sum();
        if pending_bytes > self.wallet_history_inline_scan_bytes() {
            if self.wallet_history_scan.is_none() {
                let log = open_block_log_reader(&log_path)?;
                self.wallet_history_scan = Some(wallet_history::WalletHistoryScan::start(
                    cache.clone(),
                    log,
                    log_path,
                    self.params.network_id,
                    require_v2,
                    targets,
                )?);
            }
            let history = cache.history(accepted_height, next_height, history_limit);
            self.wallet_history_cache = Some(cache);
            return Ok(history);
        }
        wallet_history::scan(
            &mut cache,
            &self.log,
            &log_path,
            self.params.network_id,
            require_v2,
            &targets,
            None,
        )?;
        let history = cache.history(accepted_height, next_height, history_limit);
        self.wallet_history_cache = Some(cache);
        Ok(history)
    }

    fn wallet_history_inline_scan_bytes(&self) -> u64 {
        #[cfg(test)]
        {
            self.wallet_history_inline_scan_bytes
        }
        #[cfg(not(test))]
        {
            wallet_history::INLINE_SCAN_BYTES
        }
    }

    /// Active blocks from `from` to the tip, with their authenticated locators.
    fn wallet_history_scan_targets(
        &self,
        from: usize,
    ) -> Result<Vec<wallet_history::ScanTarget>, NodeError> {
        let mut targets = Vec::with_capacity(self.index.active_chain.len().saturating_sub(from));
        for position in from..self.index.active_chain.len() {
            let block_id = self.index.active_chain[position];
            let indexed = self.index.blocks.get(&block_id).cloned().ok_or_else(|| {
                NodeError::CorruptLog("active wallet history refers to an absent block".to_owned())
            })?;
            targets.push((position, block_id, indexed));
        }
        Ok(targets)
    }

    /// The pre-cache implementation: a complete scan of the active chain on
    /// every call. Kept as the reference the cached history is checked against.
    #[cfg(test)]
    fn reference_confirmed_wallet_history(
        &self,
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

    /// Returns one-based confirmations when a block is on the active chain.
    /// Known side-branch blocks and unknown identifiers both return `None`;
    /// callers can distinguish them with [`Self::contains_block`].
    pub fn active_chain_confirmations(&self, block_id: [u8; 32]) -> Option<u64> {
        let position = self.index.active_position(block_id)?;
        u64::try_from(self.index.active_chain.len().checked_sub(position)?).ok()
    }

    /// Returns the active-chain identifier at `height`, including the virtual
    /// genesis anchor at height zero. Heights that do not fit this platform or
    /// are above the active tip return `None`.
    pub fn active_block_id_at_height(&self, height: u64) -> Option<[u8; 32]> {
        let position = usize::try_from(height).ok()?;
        self.index.active_chain.get(position).copied()
    }

    pub(crate) fn mempool_contains_transaction(&self, txid: [u8; 32]) -> bool {
        self.mempool.contains_key(&txid)
    }

    pub(crate) fn active_transaction_confirmations_for(
        &mut self,
        txids: &HashSet<[u8; 32]>,
    ) -> Result<HashMap<[u8; 32], u64>, NodeError> {
        let result = (|| {
            let mut confirmations = HashMap::new();
            if txids.is_empty() {
                return Ok(confirmations);
            }
            let chain_len = self.index.active_chain.len();
            // Only blocks above each txid's still-active scan mark are read;
            // a reorganization below a mark discards it and rescans.
            let mut pending = HashSet::new();
            let mut lowest = chain_len;
            for txid in txids {
                let mark = self.transaction_scan_marks.get(txid).copied();
                match mark {
                    Some(TransactionScanMark::Found { height, block_id })
                        if self.index.active_chain.get(height) == Some(&block_id) =>
                    {
                        let depth = u64::try_from(chain_len - height).map_err(|_| {
                            NodeError::CorruptLog(
                                "active transaction depth does not fit u64".to_owned(),
                            )
                        })?;
                        confirmations.insert(*txid, depth);
                    }
                    Some(TransactionScanMark::AbsentThrough { height, block_id })
                        if self.index.active_chain.get(height) == Some(&block_id) =>
                    {
                        pending.insert(*txid);
                        lowest = lowest.min(height + 1);
                    }
                    _ => {
                        pending.insert(*txid);
                        lowest = 1;
                    }
                }
            }
            if pending.is_empty() {
                return Ok(confirmations);
            }
            let mut found = HashMap::new();
            for position in (lowest.max(1)..chain_len).rev() {
                let block_id = self.index.active_chain[position];
                let indexed = self.index.blocks.get(&block_id).cloned().ok_or_else(|| {
                    NodeError::CorruptLog(
                        "active transaction lookup refers to an absent block".to_owned(),
                    )
                })?;
                let block = read_indexed_block(
                    &self.log,
                    &self.data_dir.join(BLOCK_LOG_FILE),
                    &indexed,
                    block_id,
                    self.params.network_id,
                    matches!(self.profile.proof, ProofProfile::ProductionV3),
                )?;
                for transaction in &block.transactions {
                    let txid = transaction.txid();
                    if pending.contains(&txid) {
                        found.entry(txid).or_insert(position);
                    }
                }
                if found.len() == pending.len() {
                    break;
                }
            }
            if self.transaction_scan_marks.len() > MAX_TRANSACTION_SCAN_MARKS {
                self.transaction_scan_marks.clear();
            }
            let tip_height = chain_len - 1;
            let tip = self.index.active_chain[tip_height];
            for txid in pending {
                let mark = match found.get(&txid) {
                    Some(&height) => {
                        let depth = u64::try_from(chain_len - height).map_err(|_| {
                            NodeError::CorruptLog(
                                "active transaction depth does not fit u64".to_owned(),
                            )
                        })?;
                        confirmations.insert(txid, depth);
                        TransactionScanMark::Found {
                            height,
                            block_id: self.index.active_chain[height],
                        }
                    }
                    None => TransactionScanMark::AbsentThrough {
                        height: tip_height,
                        block_id: tip,
                    },
                };
                self.transaction_scan_marks.insert(txid, mark);
            }
            Ok(confirmations)
        })();
        self.latch_authenticated_storage_failure(result)
    }

    /// Reads and authenticates the exact canonical frame for a validated block.
    /// Virtual genesis and unknown identifiers have no frame and return
    /// `None`; retained-log corruption and I/O failures are never hidden.
    pub fn canonical_block(&mut self, block_id: [u8; 32]) -> Result<Option<Vec<u8>>, NodeError> {
        let Some(indexed) = self.index.blocks.get(&block_id).cloned() else {
            return Ok(None);
        };
        if indexed.locator.version == BlockRecordVersion::Pruned {
            return Err(NodeError::BlockProofPruned(block_id));
        }
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

    /// Include this peer's last locally validated block before the active
    /// locator. A sparse locator can skip the shared fork point, so continuation
    /// must also advance through already-known active blocks. This bounded
    /// runtime-only hint never selects a winning chain.
    pub(crate) fn peer_sync_locator(
        &self,
        address: &str,
        max: usize,
    ) -> (Vec<[u8; 32]>, Option<[u8; 32]>) {
        let key = PeerObservationKey {
            direction: PeerDirection::Outbound,
            address: address.to_owned(),
        };
        let cursor = self
            .peer_observations
            .get(&key)
            .and_then(|record| record.sync_cursor);
        if let Some(block_id) =
            cursor.filter(|id| max > 1 && *id != self.index.genesis && self.index.contains(*id))
        {
            let mut locator = self.block_locator(max - 1);
            locator.retain(|id| *id != block_id);
            locator.insert(0, block_id);
            (locator, cursor)
        } else {
            (self.block_locator(max), cursor)
        }
    }

    /// Only durable, consensus-validated blocks may become continuation hints.
    /// Compare-and-set prevents an older concurrent session rewinding progress.
    pub(crate) fn advance_peer_sync_cursor(
        &mut self,
        address: &str,
        expected: Option<[u8; 32]>,
        block_id: [u8; 32],
    ) -> bool {
        if !self.index.contains(block_id) {
            return false;
        }
        let key = PeerObservationKey {
            direction: PeerDirection::Outbound,
            address: address.to_owned(),
        };
        let Some(record) = self.peer_observations.get_mut(&key) else {
            return false;
        };
        if record.sync_cursor != expected {
            return false;
        }
        record.sync_cursor = Some(block_id);
        true
    }

    /// Resume acknowledged pushes independently of this peer's pull cursor.
    /// Peer acknowledgements are scheduling hints, never consensus evidence.
    pub(crate) fn peer_relay_inventory(
        &self,
        address: &str,
        peer_tip: [u8; 32],
        max: usize,
    ) -> (Vec<[u8; 32]>, Option<[u8; 32]>) {
        let key = PeerObservationKey {
            direction: PeerDirection::Outbound,
            address: address.to_owned(),
        };
        let cursor = self
            .peer_observations
            .get(&key)
            .and_then(|record| record.relay_cursor);
        let effective_tip = cursor
            .filter(|id| {
                self.index
                    .active_position(*id)
                    .is_some_and(|cursor_position| {
                        self.index
                            .active_position(peer_tip)
                            .is_none_or(|peer_position| peer_position < cursor_position)
                    })
            })
            .unwrap_or(peer_tip);
        let mut inventory = self.relay_inventory_after(effective_tip, max);
        // The receiver may have restored older data after its acknowledgement.
        // Do not let an exhausted remembered cursor hide its current branch.
        if inventory.is_empty() && effective_tip != peer_tip {
            inventory = self.relay_inventory_after(peer_tip, max);
        }
        (inventory, cursor)
    }

    pub(crate) fn set_peer_relay_cursor(
        &mut self,
        address: &str,
        expected: Option<[u8; 32]>,
        next: Option<[u8; 32]>,
    ) -> bool {
        if next.is_some_and(|id| !self.index.contains(id)) {
            return false;
        }
        let key = PeerObservationKey {
            direction: PeerDirection::Outbound,
            address: address.to_owned(),
        };
        let Some(record) = self.peer_observations.get_mut(&key) else {
            return false;
        };
        if record.relay_cursor != expected {
            return false;
        }
        record.relay_cursor = next;
        true
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
        self.servable_inventory(inventory)
    }

    /// Pruned blocks form the oldest part of the active chain. An inventory
    /// that would start inside it is withheld, since this node cannot serve
    /// those blocks.
    fn servable_inventory(&self, inventory: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
        match inventory.first() {
            Some(first) if self.block_is_pruned(*first) => Vec::new(),
            _ => inventory,
        }
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
        self.servable_inventory(
            self.index
                .active_chain
                .iter()
                .skip(position + 1)
                .take(max)
                .copied()
                .collect(),
        )
    }

    pub fn build_template(
        &self,
        miner_destination: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<BlockTemplate, NodeError> {
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        let transactions: Vec<_> = self
            .mempool
            .values()
            .map(|entry| entry.transaction.clone())
            .collect();
        build_template_from_state(
            &self.state,
            &self.params,
            miner_destination,
            now_unix_seconds,
            transactions,
        )
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
        self.submit_transaction_inner(transaction, false)
    }

    /// Submits the exact transaction authorized by the durable withdrawal
    /// journal. This bypasses only the ordinary custody-reservation rejection;
    /// all wire, active-chain, fee, conflict, capacity, and block-set checks
    /// remain identical to [`Self::submit_transaction`].
    pub(crate) fn submit_exchange_withdrawal_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<MempoolEntry, NodeError> {
        let intent = transaction.signing_digest();
        for input in &transaction.inputs {
            if self.exchange_withdrawal_reservations.get(&input.previous) != Some(&intent) {
                return Err(NodeError::ExchangeWithdrawalReservationMismatch(
                    input.previous,
                ));
            }
        }
        self.submit_transaction_inner(transaction, true)
    }

    fn submit_transaction_inner(
        &mut self,
        transaction: Transaction,
        allow_exchange_withdrawal_reservations: bool,
    ) -> Result<MempoolEntry, NodeError> {
        if self.exchange_custody_v3_wallet_state.locks_native_wallet()
            && !allow_exchange_withdrawal_reservations
        {
            let wallet_destination = self.wallet_destination();
            if transaction.inputs.iter().any(|input| {
                self.state
                    .utxos()
                    .get(&input.previous)
                    .is_some_and(|output| output.lock == OutputLock::Key(wallet_destination))
            }) {
                return Err(NodeError::ExchangeCustodyV3WalletExclusive);
            }
        }
        if !allow_exchange_withdrawal_reservations {
            for input in &transaction.inputs {
                if self
                    .exchange_withdrawal_reservations
                    .contains_key(&input.previous)
                {
                    return Err(NodeError::ExchangeWithdrawalInputReserved(input.previous));
                }
            }
        }
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
        self.submit_block_with_preverification(block, accepted_at, None, None, None, None, None)
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
        if !matches!(
            self.profile.proof,
            ProofProfile::ProductionV3 | ProofProfile::ProductionV4
        ) {
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
        if self.index.is_below_prune_point(parent) {
            return Err(NodeError::BelowPrunePoint(parent));
        }
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
        // This verifier-owned path is also the first step of authoritative
        // proof verification. In particular, a committed work digest above
        // the independently derived block target never consumes queue or
        // external-worker capacity.
        self.verifier.preflight(&block.challenge, &block.proof)?;
        Ok(())
    }

    pub(crate) fn begin_external_block_admission(
        &mut self,
        block: &Block,
        accepted_at: u64,
    ) -> Result<Option<ExternalBlockAdmissionWork>, NodeError> {
        self.begin_external_block_admission_from_checkpoint(block, accepted_at, None)
    }

    fn branch_state_context(&self) -> BranchStateContext {
        BranchStateContext {
            node_instance_id: self.instance_id,
            network_id: self.params.network_id,
            fingerprint: self.fingerprint,
            verifier_generation: self
                .block_preverifier
                .backend_generation
                .load(Ordering::Acquire),
        }
    }

    fn checkpoint_matches_index(&self, checkpoint: &BranchStateCheckpoint) -> bool {
        if self.storage_faulted
            || checkpoint.context != self.branch_state_context()
            || checkpoint.state.params() != &self.params
            || checkpoint.state.tip() != checkpoint.block_id
        {
            return false;
        }
        let Some(entry) = self.index.blocks.get(&checkpoint.block_id) else {
            return false;
        };
        let Ok(height) = usize::try_from(entry.height()) else {
            return false;
        };
        if height.checked_add(1) != Some(checkpoint.path.len())
            || checkpoint.path.first() != Some(&self.index.genesis)
            || checkpoint.path.last() != Some(&checkpoint.block_id)
            || checkpoint.state.successor_header_preflight().ok() != Some(entry.successor_header)
        {
            return false;
        }
        // The move-only path was built by local validated replay (or copied
        // from the active index), never deserialized from a remote cache.
        // Do not rescan the entire prefix under the Node mutex on every use.
        checkpoint.path.get(height.saturating_sub(1)) == Some(&entry.parent())
    }

    fn remember_branch_checkpoint(&mut self, checkpoint: BranchStateCheckpoint) {
        if !matches!(
            self.profile.proof,
            ProofProfile::ProductionV3 | ProofProfile::ProductionV4
        ) || self.block_preverifier.ensure_reconstruction_open().is_err()
            || !self.checkpoint_matches_index(&checkpoint)
        {
            return;
        }
        let anchor = self.index.blocks[&checkpoint.block_id].locator;
        self.branch_checkpoints.insert(checkpoint, anchor);
    }

    /// Seed a recent verified active state for shallow forks. Clone only at a
    /// fixed cadence and only below the checked cache budget; cache checkout is
    /// move-only. This is state reuse, not a new proof capability or disk trust.
    fn remember_active_branch_checkpoint(&mut self, force: bool) {
        let height = self.state.next_height().saturating_sub(1);
        if self.storage_faulted
            || height == 0
            || !matches!(
                self.profile.proof,
                ProofProfile::ProductionV3 | ProofProfile::ProductionV4
            )
            || (!force && !height.is_multiple_of(ACTIVE_BRANCH_CHECKPOINT_INTERVAL))
            || self.block_preverifier.ensure_reconstruction_open().is_err()
        {
            return;
        }
        let Some(charge) = checkpoint_charge(&self.state, self.index.active_chain.len()) else {
            return;
        };
        if charge > MAX_BRANCH_STATE_CHECKPOINT_BYTES {
            return;
        }
        while !self.branch_checkpoints.entries.is_empty()
            && (self.branch_checkpoints.entries.len() >= MAX_BRANCH_STATE_CHECKPOINTS
                || self.branch_checkpoints.charged_bytes
                    > MAX_BRANCH_STATE_CHECKPOINT_BYTES - charge)
        {
            self.branch_checkpoints.remove(0);
        }
        let checkpoint = BranchStateCheckpoint {
            context: self.branch_state_context(),
            block_id: self.state.tip(),
            state: Box::new(self.state.clone()),
            path: self.index.active_chain.clone(),
        };
        self.remember_branch_checkpoint(checkpoint);
    }

    fn take_branch_checkpoint(
        &mut self,
        parent: [u8; 32],
    ) -> Result<Option<BranchStateCheckpoint>, NodeError> {
        self.block_preverifier.ensure_reconstruction_open()?;
        let mut best = None;
        for position in (0..self.branch_checkpoints.entries.len()).rev() {
            let entry = &self.branch_checkpoints.entries[position];
            if !self.checkpoint_matches_index(&entry.checkpoint)
                || self
                    .index
                    .blocks
                    .get(&entry.checkpoint.block_id)
                    .map(|b| b.locator)
                    != Some(entry.anchor)
            {
                self.branch_checkpoints.remove(position);
            }
        }
        for (position, entry) in self.branch_checkpoints.entries.iter().enumerate() {
            let height = entry.anchor.height;
            if self.index.ancestor_at_height(parent, height).ok() == Some(entry.checkpoint.block_id)
                && best.is_none_or(|(_, best_height)| height > best_height)
            {
                best = Some((position, height));
            }
        }
        let Some((position, _)) = best else {
            return Ok(None);
        };
        // An active-chain anchor stays cached and the replay uses a copy. Its
        // return after a cancelled attempt is best-effort and can be lost; a
        // lost anchor turned a one-block reorganization after a restart into
        // a replay from genesis.
        let entry = &self.branch_checkpoints.entries[position];
        let anchor_is_active = usize::try_from(entry.anchor.height)
            .ok()
            .and_then(|height| self.index.active_chain.get(height))
            == Some(&entry.checkpoint.block_id);
        let cached = if anchor_is_active {
            CachedBranchCheckpoint {
                checkpoint: BranchStateCheckpoint {
                    context: entry.checkpoint.context,
                    block_id: entry.checkpoint.block_id,
                    state: entry.checkpoint.state.clone(),
                    path: entry.checkpoint.path.clone(),
                },
                anchor: entry.anchor,
                charge: entry.charge,
            }
        } else {
            self.branch_checkpoints.remove(position)
        };
        let log_path = self.data_dir.join(BLOCK_LOG_FILE);
        let authenticated = (|| {
            verify_retained_block_log_path(&self.log, &log_path)?;
            if self
                .log
                .metadata()
                .map_err(|e| io_error("inspect checkpoint log", &log_path, e))?
                .len()
                != self.block_log_length
            {
                return Err(NodeError::CorruptLog(
                    "checkpoint log extent changed".to_owned(),
                ));
            }
            // Authenticate the anchor; all newly replayed suffix records retain
            // their normal checks. Previously validated prefix state is reused
            // just as on active extension, not re-read from untrusted snapshots.
            read_located_record(
                &self.log,
                &log_path,
                &cached.anchor,
                self.params.network_id,
                true,
            )?;
            Ok(())
        })();
        self.latch_authenticated_storage_failure(authenticated)?;
        Ok(Some(cached.checkpoint))
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
        if !matches!(
            self.profile.proof,
            ProofProfile::ProductionV3 | ProofProfile::ProductionV4
        ) {
            if checkpoint.is_some() {
                return Err(NodeError::ProofVerifierProfileMismatch);
            }
            return Ok(None);
        }
        let block_id = block.block_id();
        let parent = block.challenge.previous_block;
        let checkpoint_context = self.branch_state_context();
        if checkpoint
            .as_ref()
            .is_some_and(|checkpoint| !self.checkpoint_matches_index(checkpoint))
        {
            return Err(NodeError::StaleBlockAdmission);
        }
        let state_snapshot = if parent == self.state.tip() {
            if checkpoint.is_some() {
                return Err(NodeError::StaleBlockAdmission);
            }
            AdmissionStateSnapshot::Active
        } else {
            let checkpoint = match checkpoint {
                Some(checkpoint) => Some(checkpoint),
                None => self.take_branch_checkpoint(parent)?,
            };
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
            checkpoint_context,
            revision: self.chain_revision,
            block_id,
            parent,
            accepted_at,
            params: self.params,
            verifier: self.verifier.clone(),
            block_preverifier: self.block_preverifier.clone(),
            state_snapshot,
            #[cfg(test)]
            completion_fault_barrier: self.completion_fault_barrier.clone(),
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
    #[cfg(test)]
    #[cfg_attr(
        any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
        allow(dead_code)
    )]
    pub(crate) fn submit_preverified_block(
        &mut self,
        block: Block,
        accepted_at: u64,
        preverified: PreverifiedBlockProof,
    ) -> Result<u64, NodeError> {
        if matches!(self.profile.proof, ProofProfile::ProductionV3) {
            return Err(NodeError::ProductionV3Unavailable);
        }
        self.submit_block_with_preverification(
            block,
            accepted_at,
            Some(&preverified),
            None,
            None,
            None,
            None,
        )
    }

    fn submit_preverified_block_guarded(
        &mut self,
        block: Block,
        accepted_at: u64,
        preverified: PreverifiedBlockProof,
        request: Option<&RemoteProofRequest>,
    ) -> Result<u64, NodeError> {
        if matches!(self.profile.proof, ProofProfile::ProductionV3) {
            return Err(NodeError::ProductionV3Unavailable);
        }
        self.submit_block_with_preverification(
            block,
            accepted_at,
            Some(&preverified),
            None,
            None,
            None,
            request,
        )
    }

    #[cfg(test)]
    #[cfg_attr(
        any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
        allow(dead_code)
    )]
    pub(crate) fn submit_preverified_block_with_admission(
        &mut self,
        block: Block,
        accepted_at: u64,
        preverified: PreverifiedBlockProof,
        admission: ExternalBlockAdmission,
    ) -> Result<u64, NodeError> {
        if !matches!(
            self.profile.proof,
            ProofProfile::ProductionV3 | ProofProfile::ProductionV4
        ) {
            return Err(NodeError::ProofVerifierProfileMismatch);
        }
        if admission.checkpoint_context != self.branch_state_context()
            || admission.revision != self.chain_revision
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
            Some(admission.checkpoint_context),
            None,
        )
    }

    fn submit_preverified_block_with_admission_guarded(
        &mut self,
        block: Block,
        accepted_at: u64,
        preverified: PreverifiedBlockProof,
        admission: ExternalBlockAdmission,
        request: Option<&RemoteProofRequest>,
    ) -> Result<u64, NodeError> {
        if !matches!(
            self.profile.proof,
            ProofProfile::ProductionV3 | ProofProfile::ProductionV4
        ) {
            return Err(NodeError::ProofVerifierProfileMismatch);
        }
        if admission.checkpoint_context != self.branch_state_context()
            || admission.revision != self.chain_revision
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
            Some(admission.checkpoint_context),
            request,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_block_with_preverification(
        &mut self,
        block: Block,
        accepted_at: u64,
        preverified: Option<&PreverifiedBlockProof>,
        branch_state: Option<Box<ChainState>>,
        activation_chain: Option<Vec<[u8; 32]>>,
        checkpoint_context: Option<BranchStateContext>,
        request: Option<&RemoteProofRequest>,
    ) -> Result<u64, NodeError> {
        if let Err(error) = ensure_remote_request_live(request) {
            if let (Some(state), Some(mut path), Some(context)) =
                (branch_state, activation_chain, checkpoint_context)
                && path.pop() == Some(block.block_id())
                && state.tip() == block.challenge.previous_block
            {
                self.remember_branch_checkpoint(BranchStateCheckpoint {
                    context,
                    block_id: state.tip(),
                    state,
                    path,
                });
            }
            return Err(error);
        }
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
        let record = encode_record_v3(
            accepted_at,
            &canonical,
            &delta,
            self.last_record_digest,
            self.params.network_id,
        )?;
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
            ordinal: self.record_count,
            offset: self.block_log_length,
            length: record_length,
            version: BlockRecordVersion::V3,
            complete_digest: record_digest,
            accepted_at: prepared.accepted_at,
            block_id: prepared.block_id,
            parent: prepared.parent,
            height: prepared.height,
            target: prepared.target,
        };
        // The atomic transition and its immediate post-CAS deadline recheck
        // form the request-lifetime linearization point. A cancellation that
        // wins first can never append. Once the recheck succeeds, every later
        // failure is a storage fault rather than an ordinary retryable result.
        let commit_guard_result = request
            .map(|request| {
                request.begin_commit_after_check(|| {
                    #[cfg(test)]
                    self.pause_commit_race(CommitPausePoint::AfterDeadlineCheck);
                })
            })
            .transpose();
        let mut commit_guard = match commit_guard_result {
            Ok(guard) => guard,
            Err(error) => {
                if let Some(context) = checkpoint_context
                    && let Some(checkpoint) = prepared.into_parent_checkpoint(context)
                {
                    self.remember_branch_checkpoint(checkpoint);
                }
                return Err(error);
            }
        };
        #[cfg(test)]
        self.pause_commit_race(CommitPausePoint::AfterTransition);
        if let Err(source) = self.log.write_all(&record) {
            self.storage_faulted = true;
            if let Some(guard) = commit_guard.take() {
                guard.finish(RemoteProofRequestState::Faulted);
            }
            return Err(io_error("append block record", &log_path, source));
        }
        if let Err(source) = self.log.sync_all() {
            self.storage_faulted = true;
            if let Some(guard) = commit_guard.take() {
                guard.finish(RemoteProofRequestState::Faulted);
            }
            return Err(io_error("sync block record", &log_path, source));
        }
        let durable_length = match self.log.metadata() {
            Ok(metadata) => metadata.len(),
            Err(source) => {
                self.storage_faulted = true;
                if let Some(guard) = commit_guard.take() {
                    guard.finish(RemoteProofRequestState::Faulted);
                }
                return Err(io_error(
                    "inspect block log after durable append",
                    &log_path,
                    source,
                ));
            }
        };
        if durable_length != final_length {
            self.storage_faulted = true;
            if let Some(guard) = commit_guard.take() {
                guard.finish(RemoteProofRequestState::Faulted);
            }
            return Err(NodeError::CorruptLog(
                "durable block append did not end at its predicted locator".to_owned(),
            ));
        }
        if let Err(error) = verify_retained_block_log_path(&self.log, &log_path) {
            self.storage_faulted = true;
            if let Some(guard) = commit_guard.take() {
                guard.finish(RemoteProofRequestState::Faulted);
            }
            return Err(error);
        }
        match commit_prepared(&mut self.state, &mut self.index, prepared, locator) {
            Ok(outcome) => {
                self.chain_revision = next_revision;
                self.record_count = self.record_count.saturating_add(1);
                self.last_record_digest = record_digest;
                self.block_log_length = final_length;
                let canonical_tip_changed = self.state.tip() != previous_tip;
                if canonical_tip_changed {
                    if block.challenge.previous_block != previous_tip
                        || !self.explorer_outputs.apply_extension(&block)
                    {
                        self.explorer_outputs =
                            explorer_address_index::AddressOutputIndex::from_utxos(
                                self.state.utxos(),
                            );
                    }
                    self.revalidate_mempool(&confirmed_txids);
                }
                if let Some(guard) = commit_guard.take() {
                    guard.finish(RemoteProofRequestState::Completed);
                }
                if let Some(context) = checkpoint_context
                    && let Some((state, path)) = outcome.retained_state
                {
                    self.remember_branch_checkpoint(BranchStateCheckpoint {
                        context,
                        block_id: state.tip(),
                        state,
                        path,
                    });
                }
                if canonical_tip_changed {
                    self.remember_active_branch_checkpoint(
                        block.challenge.previous_block != previous_tip,
                    );
                    self.save_prune_candidate(false);
                }
                // Keep the authenticated fast-start state current while the
                // node is running, including after nonwinning side-branch
                // appends that change the retained log but not the active tip.
                // A snapshot failure is non-authoritative: startup safely
                // falls back to replaying the block log.
                let _ = self.persist_startup_snapshot();
                if self
                    .record_count
                    .is_multiple_of(startup_snapshot::INDEX_CACHE_INTERVAL)
                {
                    let _ = self.persist_index_cache();
                }
                Ok(outcome.fees)
            }
            Err(error) => {
                // The record is already durable. Refuse further work so a
                // restart can reconstruct the authoritative state from disk.
                self.storage_faulted = true;
                if let Some(guard) = commit_guard.take() {
                    guard.finish(RemoteProofRequestState::Faulted);
                }
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
    let required = required_relay_fee(encoded_bytes, state.params().network_id);
    if validation.total_burned_fees < required {
        return Err(NodeError::MempoolFeeTooLow {
            required,
            actual: validation.total_burned_fees,
        });
    }
    Ok(validation.total_burned_fees)
}

fn validate_wallet_minimum_fee(network_id: [u8; 32], actual: u64) -> Result<(), NodeError> {
    let required = cmfd_consensus::economics::minimum_transaction_fee(network_id);
    if actual < required {
        return Err(NodeError::MempoolFeeTooLow { required, actual });
    }
    Ok(())
}

fn required_relay_fee(encoded_bytes: usize, network_id: [u8; 32]) -> u64 {
    let kib = encoded_bytes.saturating_add(1023) / 1024;
    u64::try_from(kib)
        .ok()
        .and_then(|kib| kib.checked_mul(MIN_RELAY_FEE_PER_KIB))
        .unwrap_or(u64::MAX)
        .max(MIN_RELAY_FEE_PER_KIB)
        .max(cmfd_consensus::economics::minimum_transaction_fee(
            network_id,
        ))
}

#[cfg(test)]
mod relay_fee_tests {
    use super::*;

    #[test]
    fn relay_fee_uses_the_open_node_network_not_the_compiled_profile() {
        let encoded_bytes = 500;
        assert_eq!(
            required_relay_fee(encoded_bytes, DEVNET_PROFILE.network_id),
            MIN_RELAY_FEE_PER_KIB
        );
        assert_eq!(
            required_relay_fee(encoded_bytes, RCNET1_PROFILE.network_id),
            cmfd_consensus::economics::MIN_TRANSACTION_FEE_ATOMS
        );
    }
}

pub(crate) fn signed_wallet_payment_size(
    transaction: &Transaction,
    wallet_destination: [u8; 32],
) -> Result<usize, NodeError> {
    let mut sized = transaction.clone();
    for input in &mut sized.inputs {
        let InputWitness::Key {
            public_key,
            signature,
        } = &mut input.witness
        else {
            return Err(NodeError::InvalidWalletPaymentPlan(
                "input is not a wallet-key witness",
            ));
        };
        *public_key = wallet_destination;
        signature.resize(64, 0);
    }
    Ok(encode_transaction(&sized)?.len())
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
    submit_shared_block_with_policy(
        shared,
        block,
        accepted_at,
        SharedBlockPolicy::AnyBranch,
        None,
        None,
    )
}

/// P2P submission route with a connection-lifetime cancellation signal. A
/// disconnected session is removed from both verifier queues before it can be
/// granted scarce worker capacity.
pub(crate) fn submit_shared_peer_block_cancellable(
    shared: &Arc<Mutex<Node>>,
    block: Block,
    accepted_at: u64,
    peer: RemoteProofPeerId,
    request: RemoteProofRequest,
) -> Result<u64, NodeError> {
    submit_shared_block_with_policy(
        shared,
        block,
        accepted_at,
        SharedBlockPolicy::AnyBranch,
        Some(peer),
        Some(request),
    )
}

/// Submits only if the candidate extends the active tip observed after it
/// acquires the proof permit. Mining callers use this policy so a concurrent
/// winning block cannot turn their candidate into a credited side branch.
pub fn submit_shared_tip_block(
    shared: &Arc<Mutex<Node>>,
    block: Block,
    accepted_at: u64,
) -> Result<u64, NodeError> {
    submit_shared_block_with_policy(
        shared,
        block,
        accepted_at,
        SharedBlockPolicy::ActiveTipOnly,
        None,
        None,
    )
}

#[derive(Clone, Copy)]
enum SharedBlockPolicy {
    AnyBranch,
    ActiveTipOnly,
}

struct ProofAttemptStart {
    remote_permit: Option<RemoteProofAdmissionPermit>,
    cached: Option<PreverifiedBlockProof>,
}

fn ensure_remote_request_live(request: Option<&RemoteProofRequest>) -> Result<(), NodeError> {
    match request {
        Some(request) => request.ensure_live(),
        None => Ok(()),
    }
}

fn lock_shared_node<'a>(
    shared: &'a Arc<Mutex<Node>>,
    request: Option<&RemoteProofRequest>,
) -> Result<MutexGuard<'a, Node>, NodeError> {
    let Some(request) = request else {
        return shared.lock().map_err(|_| NodeError::SharedNodePoisoned);
    };
    loop {
        request.ensure_live()?;
        match shared.try_lock() {
            Ok(node) => {
                request.ensure_live()?;
                return Ok(node);
            }
            Err(TryLockError::WouldBlock) => {
                thread::sleep(request.remaining()?.min(REMOTE_PROOF_CANCELLATION_POLL));
            }
            Err(TryLockError::Poisoned(_)) => return Err(NodeError::SharedNodePoisoned),
        }
    }
}

fn latch_shared_external_completion_failure(
    shared: &Arc<Mutex<Node>>,
    node_instance_id: u64,
    chain_revision: u64,
    error: &NodeError,
) {
    // Authenticated replay corruption outlives the remote request that exposed
    // it. Cancellation cannot suppress the fail-closed storage latch.
    let mut node = match shared.lock() {
        Ok(node) => node,
        Err(poisoned) => poisoned.into_inner(),
    };
    node.latch_external_completion_failure(node_instance_id, chain_revision, error);
}

fn begin_proof_attempt(
    block_preverifier: &BlockPreverifier,
    production_admission: bool,
    remote_peer: Option<RemoteProofPeerId>,
    remote_request: Option<&RemoteProofRequest>,
    block_cache_digest: [u8; 32],
) -> Result<ProofAttemptStart, NodeError> {
    // Production remote sessions reserve FIFO admission before consulting the
    // successful-proof cache. A cache hit avoids relation dispatch only; it
    // cannot overtake a peer already waiting for network admission.
    let remote_permit = if production_admission {
        match (remote_peer, remote_request) {
            (Some(peer), Some(request)) => {
                Some(block_preverifier.reserve_remote_cancellable(peer, request.clone())?)
            }
            (Some(peer), None) => Some(block_preverifier.reserve_remote(peer)?),
            (None, _) => None,
        }
    } else {
        None
    };
    if remote_permit
        .as_ref()
        .is_some_and(RemoteProofAdmissionPermit::is_cancelled)
    {
        return finalize_proof_attempt(
            remote_permit,
            None,
            Err(NodeError::ProofVerificationQueueTimeout),
        );
    }
    let cached = match block_preverifier.cached_preverification(block_cache_digest) {
        Ok(cached) => cached,
        Err(error) => return finalize_proof_attempt(remote_permit, None, Err(error)),
    };
    Ok(ProofAttemptStart {
        remote_permit,
        cached,
    })
}

fn submit_shared_block_with_policy(
    shared: &Arc<Mutex<Node>>,
    block: Block,
    accepted_at: u64,
    policy: SharedBlockPolicy,
    remote_peer: Option<RemoteProofPeerId>,
    remote_request: Option<RemoteProofRequest>,
) -> Result<u64, NodeError> {
    let block_id = block.block_id();
    ensure_remote_request_live(remote_request.as_ref())?;
    let (block_preverifier, production_admission) = {
        let node = lock_shared_node(shared, remote_request.as_ref())?;
        (
            node.block_preverifier(),
            matches!(
                node.profile.proof,
                ProofProfile::ProductionV3 | ProofProfile::ProductionV4
            ),
        )
    };
    if production_admission {
        // Keep trivial duplicates, cached deterministic rejects, unknown
        // parents, malformed bodies, and impossible headers out of the scarce
        // proof queue. This snapshot is deliberately discarded and repeated
        // authoritatively after the permit is acquired.
        let node = lock_shared_node(shared, remote_request.as_ref())?;
        if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
            && block.challenge.previous_block != node.state.tip()
        {
            return Err(NodeError::StaleBlockAdmission);
        }
        node.preflight_external_block_admission(&block, accepted_at)?;
    }
    ensure_remote_request_live(remote_request.as_ref())?;
    let block_cache_digest = canonical_block_cache_digest(&block)?;
    let attempt = begin_proof_attempt(
        &block_preverifier,
        production_admission,
        remote_peer,
        remote_request.as_ref(),
        block_cache_digest,
    )?;
    let remote_permit = attempt.remote_permit;
    // The scarce verifier reservation is released immediately after proof verification;
    // side-state replay uses a separate bounded lane so a proof-valid deep fork
    // cannot monopolize proof admission.
    let preverified = if let Some(preverified) = attempt.cached {
        ensure_remote_request_live(remote_request.as_ref())?;
        finalize_proof_attempt(remote_permit, None, Ok(preverified))?
    } else {
        // At most one proof from each locally identified P2P session may
        // contend for the scarce verifier, and new sessions cannot
        // overtake one already waiting. Local mined work bypasses this
        // scheduler and retains the priority queue below.
        if remote_permit
            .as_ref()
            .is_some_and(RemoteProofAdmissionPermit::is_cancelled)
        {
            return finalize_proof_attempt(
                remote_permit,
                None,
                Err(NodeError::ProofVerificationQueueTimeout),
            );
        }
        let permit = if let Some(request) = remote_request.as_ref() {
            block_preverifier.reserve_cancellable(request.clone())?
        } else {
            match policy {
                SharedBlockPolicy::AnyBranch => block_preverifier.reserve()?,
                SharedBlockPolicy::ActiveTipOnly => block_preverifier.reserve_priority()?,
            }
        };
        {
            let node = lock_shared_node(shared, remote_request.as_ref())?;
            if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
                && block.challenge.previous_block != node.state.tip()
            {
                return Err(NodeError::StaleBlockAdmission);
            }
            if production_admission {
                node.preflight_external_block_admission(&block, accepted_at)?;
            }
        }
        let result = if remote_permit
            .as_ref()
            .is_some_and(RemoteProofAdmissionPermit::is_cancelled)
        {
            Err(NodeError::ProofVerificationQueueTimeout)
        } else {
            permit.preverify_cached_with_request(
                &block,
                block_cache_digest,
                remote_request.as_ref(),
            )
        };
        match finalize_proof_attempt(remote_permit, Some(permit), result) {
            Ok(preverified) => preverified,
            Err(error) => {
                if production_admission {
                    let mut node = lock_shared_node(shared, remote_request.as_ref())?;
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

    ensure_remote_request_live(remote_request.as_ref())?;

    let admission_work = {
        let mut node = lock_shared_node(shared, remote_request.as_ref())?;
        if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
            && block.challenge.previous_block != node.state.tip()
        {
            return Err(NodeError::StaleBlockAdmission);
        }
        node.begin_external_block_admission(&block, accepted_at)?
    };

    let admission = match admission_work {
        Some(work) => {
            let mut pending_work = PendingExternalWork {
                shared: Arc::clone(shared),
                work: Some(work),
            };
            let _reconstruction_permit = pending_work
                .work
                .as_ref()
                .expect("pending replay work")
                .requires_reconstruction()
                .then(|| block_preverifier.reserve_reconstruction())
                .transpose()?;
            loop {
                ensure_remote_request_live(remote_request.as_ref())?;
                let work = pending_work.work.take().expect("pending replay work");
                let work_node_instance_id = work.node_instance_id;
                let work_revision = work.revision;
                let progress = match catch_unwind(AssertUnwindSafe(|| work.complete(&block))) {
                    Ok(Ok(progress)) => progress,
                    Ok(Err(error)) => {
                        if is_authenticated_storage_failure(&error) {
                            latch_shared_external_completion_failure(
                                shared,
                                work_node_instance_id,
                                work_revision,
                                &error,
                            );
                        }
                        return Err(error);
                    }
                    Err(_) => return Err(NodeError::ProofVerifierPanicked),
                };
                let mut pending = PendingExternalAdmission {
                    shared: Arc::clone(shared),
                    progress: Some(progress),
                };
                ensure_remote_request_live(remote_request.as_ref())?;
                match pending.progress.as_ref().expect("pending admission") {
                    ExternalBlockAdmissionProgress::Ready(_) => break Some(pending),
                    ExternalBlockAdmissionProgress::Checkpoint { .. } => {
                        block_preverifier.ensure_reconstruction_open()?;
                        let mut node = lock_shared_node(shared, remote_request.as_ref())?;
                        if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
                            && block.challenge.previous_block != node.state.tip()
                        {
                            return Err(NodeError::StaleBlockAdmission);
                        }
                        let Some(ExternalBlockAdmissionProgress::Checkpoint { checkpoint }) =
                            pending.progress.take()
                        else {
                            unreachable!("checked pending checkpoint");
                        };
                        pending_work.work = Some(node.continue_external_block_admission(
                            &block,
                            accepted_at,
                            checkpoint,
                        )?);
                    }
                }
            }
        }
        None => None,
    };
    ensure_remote_request_live(remote_request.as_ref())?;
    let mut node = lock_shared_node(shared, remote_request.as_ref())?;
    ensure_remote_request_live(remote_request.as_ref())?;
    if matches!(policy, SharedBlockPolicy::ActiveTipOnly)
        && block.challenge.previous_block != node.state.tip()
    {
        return Err(NodeError::StaleBlockAdmission);
    }
    let externally_admitted = admission.is_some();
    let result = match admission {
        Some(mut pending) => {
            let Some(ExternalBlockAdmissionProgress::Ready(mut admission)) =
                pending.progress.take()
            else {
                unreachable!("checked ready admission");
            };
            if admission.branch_state.is_some() {
                node.preflight_external_block_admission(&block, accepted_at)?;
                admission.revision = node.chain_revision;
                if block.challenge.previous_block == node.state.tip() {
                    admission.branch_state = None;
                    admission.activation_chain = None;
                }
            }
            node.submit_preverified_block_with_admission_guarded(
                block,
                accepted_at,
                preverified,
                admission,
                remote_request.as_ref(),
            )
        }
        None => node.submit_preverified_block_guarded(
            block,
            accepted_at,
            preverified,
            remote_request.as_ref(),
        ),
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
        NodeError::ProofVerifierWorker(VerifierWorkerError::ProofRejected(_)) | NodeError::Pow(_)
    )
}

fn is_remote_peer_proof_failure(error: &NodeError) -> bool {
    matches!(
        error,
        NodeError::ProofVerifierWorker(worker_error)
            if worker_error.is_dispatched_proof_failure()
    ) || matches!(error, NodeError::Pow(_))
}

fn finalize_proof_attempt<T>(
    mut remote_permit: Option<RemoteProofAdmissionPermit>,
    mut proof_permit: Option<BlockPreverificationPermit>,
    result: Result<T, NodeError>,
) -> Result<T, NodeError> {
    if let Err(error) = &result
        && is_remote_peer_proof_failure(error)
    {
        if let Some(remote_permit) = &mut remote_permit {
            remote_permit.mark_proof_failure();
        }
        if let Some(proof_permit) = &mut proof_permit {
            proof_permit.mark_proof_failure();
        }
    }
    drop(proof_permit);
    drop(remote_permit);
    result
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

#[cfg(test)]
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
        transaction_ids: block.transactions.iter().map(Transaction::txid).collect(),
        address_entries: explorer_address_index::AddressHistoryIndex::block_entries(block),
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
    let mut state = match index.reconstruction_base(tip)? {
        (_, Some(base), _) => *base,
        (_, None, _) => ChainState::new(params, verifier.clone())?,
    };
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
    let path = index.path_to(tip)?;
    let start = if state.tip() == index.genesis {
        0
    } else {
        path.iter()
            .position(|block_id| *block_id == state.tip())
            .map(|position| position + 1)
            .ok_or_else(|| {
                NodeError::CorruptLog("indexed replay base is not on the replayed path".to_owned())
            })?
    };
    for block_id in path.into_iter().skip(start) {
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
        )?
        .into_full()
        .ok_or(NodeError::BlockProofPruned(block_id))?;
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
            let preverified = match preverifier.preverify_unqueued(&block, None) {
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
    retained_state: Option<(Box<ChainState>, Vec<[u8; 32]>)>,
}

fn commit_prepared(
    active_state: &mut ChainState,
    index: &mut BlockIndex,
    mut prepared: PreparedBlock,
    locator: BlockRecordLocator,
) -> Result<CommitOutcome, NodeError> {
    if locator.version == BlockRecordVersion::LegacyV1
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

    let mut retained_state = None;
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
                let old_state = std::mem::replace(active_state, *state);
                retained_state = Some((Box::new(old_state), index.active_chain.clone()));
            } else if let Some(path) = externally_prepared_chain.take() {
                retained_state = Some((state, path));
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
    index
        .transactions
        .insert_block(prepared.block_id, prepared.transaction_ids);
    index.addresses.insert_entries(prepared.address_entries);
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
    Ok(CommitOutcome {
        fees,
        retained_state,
    })
}

#[derive(Debug)]
struct RpcRequest {
    method: String,
    target: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

struct RpcRequestHead {
    method: String,
    target: String,
    content_type: Option<String>,
    authorization: Option<Zeroizing<String>>,
    expect_continue: bool,
    body_length: usize,
    body_prefix: Vec<u8>,
}

struct DeadlineReader<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}

impl<'a> DeadlineReader<'a> {
    fn new(stream: &'a mut TcpStream, total_timeout: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "RPC deadline overflow"))?;
        Ok(Self { stream, deadline })
    }

    fn write_continue(&mut self) -> Result<(), NodeError> {
        self.stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(NodeError::RpcIo)?;
        self.stream.flush().map_err(NodeError::RpcIo)
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
    basic_auth_challenge: bool,
    network_id: Option<[u8; 32]>,
}

impl RpcResponse {
    fn json(status: u16, reason: &'static str, value: serde_json::Value) -> Self {
        Self {
            status,
            reason,
            content_type: "application/json",
            body: serde_json::to_vec(&value).expect("JSON value serialization cannot fail"),
            basic_auth_challenge: false,
            network_id: None,
        }
    }

    fn with_basic_auth_challenge(mut self) -> Self {
        self.basic_auth_challenge = true;
        self
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

    fn explorer_address_error(error: NodeError) -> Self {
        let client = error.client_error();
        let response = Self::node_error(error);
        Self::json(
            response.status,
            response.reason,
            json!({
                "error": client.message,
                "code": client.code,
                "retryable": client.retryable,
            }),
        )
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
    #[cfg_attr(
        any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
        allow(dead_code)
    )]
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
    let mut deadline_reader =
        DeadlineReader::new(stream, RPC_TOTAL_READ_TIMEOUT).map_err(NodeError::RpcIo)?;
    let network_id = shared
        .lock()
        .map_err(|_| NodeError::SharedNodePoisoned)?
        .params
        .network_id;
    let request = match read_rpc_request(&mut deadline_reader, network_id) {
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
    let explorer_request = request.method == "GET"
        && (request.target == "/v1/explorer"
            || request.target.starts_with("/v1/explorer/block/")
            || request.target.starts_with("/v1/explorer/transaction/")
            || request.target.starts_with("/v1/explorer/address/"));
    let mut response = route_rpc_request_inner(request, node);
    if explorer_request {
        // Bind this exact response (including not-found/errors) to the node
        // that produced it. A separate snapshot preflight could race a cutover.
        response.network_id = Some(node.params.network_id);
    }
    response
}

fn route_rpc_request_inner(request: RpcRequest, node: &mut Node) -> RpcResponse {
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
        ("GET", "/v1/explorer") => match node.explorer_snapshot() {
            Ok(snapshot) => match serde_json::to_value(snapshot) {
                Ok(value) => RpcResponse::json(200, "OK", value),
                Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
            },
            Err(error) => RpcResponse::node_error(error),
        },
        ("GET", target) if target.starts_with("/v1/explorer/block/") => {
            let query = &target[19..];
            match node.explorer_block(query) {
                Ok(Some(block)) => match serde_json::to_value(block) {
                    Ok(value) => RpcResponse::json(200, "OK", value),
                    Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
                },
                Ok(None) => RpcResponse::json_error(404, "Not Found", "block not found"),
                Err(error) => RpcResponse::node_error(error),
            }
        }
        ("GET", target) if target.starts_with("/v1/explorer/transaction/") => {
            let query = &target[25..];
            match node.explorer_transaction(query) {
                Ok(Some(transaction)) => match serde_json::to_value(transaction) {
                    Ok(value) => RpcResponse::json(200, "OK", value),
                    Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
                },
                Ok(None) => RpcResponse::json_error(404, "Not Found", "transaction not found"),
                Err(error) => RpcResponse::node_error(error),
            }
        }
        ("GET", target) if target.starts_with("/v1/explorer/address/") => {
            let mut parts = target[21..].split('/');
            let address = parts.next().unwrap_or_default();
            let cursor = parts.next();
            if parts.next().is_some() {
                return RpcResponse::explorer_address_error(NodeError::InvalidExplorerCursor);
            }
            match node.explorer_address(address, cursor) {
                Ok(address) => match serde_json::to_value(address) {
                    Ok(value) => RpcResponse::json(200, "OK", value),
                    Err(error) => RpcResponse::json_error(500, "Internal Server Error", error),
                },
                Err(error) => RpcResponse::explorer_address_error(error),
            }
        }
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

fn read_rpc_request(reader: &mut impl Read, network_id: [u8; 32]) -> Result<RpcRequest, NodeError> {
    let head = read_rpc_request_head(reader, network_id)?;
    if head.expect_continue {
        return Err(NodeError::InvalidRpcRequest(
            "Expect: 100-continue is not supported".to_owned(),
        ));
    }
    read_rpc_request_body(reader, head)
}

fn read_rpc_request_head(
    reader: &mut impl Read,
    network_id: [u8; 32],
) -> Result<RpcRequestHead, NodeError> {
    let mut bytes = Zeroizing::new(Vec::new());
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
    let mut authorization = None;
    let mut expect_continue = false;
    let mut expect_seen = false;
    let body_limit = rpc_body_limit(request_parts[0], request_parts[1], network_id);
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
            if content_type.is_some() {
                return Err(NodeError::InvalidRpcRequest(
                    "duplicate Content-Type".to_owned(),
                ));
            }
            content_type = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return Err(NodeError::InvalidRpcRequest(
                    "duplicate Authorization".to_owned(),
                ));
            }
            authorization = Some(Zeroizing::new(value.to_owned()));
        } else if name.eq_ignore_ascii_case("expect") {
            if expect_seen {
                return Err(NodeError::InvalidRpcRequest("duplicate Expect".to_owned()));
            }
            expect_seen = true;
            if !value.eq_ignore_ascii_case("100-continue") {
                return Err(NodeError::InvalidRpcRequest(
                    "unsupported Expect header".to_owned(),
                ));
            }
            expect_continue = true;
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
    if request_parts[0] == "GET" && body_length != 0 {
        return Err(NodeError::InvalidRpcRequest(
            "GET requests may not contain a body".to_owned(),
        ));
    }
    let body_prefix = bytes[header_end..].to_vec();
    if body_prefix.len() > body_length {
        return Err(NodeError::InvalidRpcRequest(
            "request contains bytes after its declared body".to_owned(),
        ));
    }

    Ok(RpcRequestHead {
        method: request_parts[0].to_owned(),
        target: request_parts[1].to_owned(),
        content_type,
        authorization,
        expect_continue,
        body_length,
        body_prefix,
    })
}

fn read_rpc_request_body(
    reader: &mut impl Read,
    mut head: RpcRequestHead,
) -> Result<RpcRequest, NodeError> {
    let remaining = head.body_length - head.body_prefix.len();
    if remaining > 0 {
        let original_len = head.body_prefix.len();
        head.body_prefix.resize(head.body_length, 0);
        reader
            .read_exact(&mut head.body_prefix[original_len..])
            .map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    NodeError::InvalidRpcRequest("request body is truncated".to_owned())
                } else {
                    NodeError::RpcIo(error)
                }
            })?;
    }

    Ok(RpcRequest {
        method: head.method,
        target: head.target,
        content_type: head.content_type,
        body: head.body_prefix,
    })
}

fn rpc_body_limit(method: &str, target: &str, network_id: [u8; 32]) -> usize {
    match (method, target) {
        ("POST", "/v1/transaction") => MAX_TRANSACTION_BYTES,
        ("POST", "/") => EXCHANGE_RPC_JSON_BODY_LIMIT,
        ("POST", "/v1/wallet/send" | "/v1/wallet/consolidate") => WALLET_JSON_BODY_LIMIT,
        ("POST", "/v1/block") => max_block_bytes_for_network(network_id),
        ("POST", target) if target.starts_with("/v1/mine?") => 0,
        ("GET", _) => 0,
        _ => MAX_BLOCK_BYTES,
    }
}

fn write_rpc_response(stream: &mut impl Write, response: RpcResponse) -> Result<(), NodeError> {
    let challenge = if response.basic_auth_challenge {
        "WWW-Authenticate: Basic realm=\"cmfd-exchange-rpc\", charset=\"UTF-8\"\r\n"
    } else {
        ""
    };
    let network = response.network_id.map_or_else(String::new, |network_id| {
        format!("X-CMFD-Network-Id: {}\r\n", hex::encode(network_id))
    });
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n{}{}\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len(),
        challenge,
        network,
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
    EmptyRc4Upgrade,
}

const RC4_FINGERPRINT: [u8; 32] = [
    0xfa, 0xdb, 0x0d, 0x51, 0xf3, 0xdf, 0x9a, 0x33, 0xa4, 0x14, 0xda, 0xc2, 0xb8, 0xa8, 0x2f, 0x8c,
    0x6f, 0x17, 0xb8, 0x4c, 0x8a, 0xb6, 0x65, 0xaa, 0xe9, 0xda, 0x07, 0xc4, 0x06, 0xd2, 0x15, 0xd4,
];

fn io_error(operation: &'static str, path: impl AsRef<Path>, source: io::Error) -> NodeError {
    NodeError::Io {
        operation,
        path: path.as_ref().to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), NodeError> {
    let parent = path.parent().ok_or_else(|| {
        io_error(
            "locate durable file parent",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"),
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync durable file directory", parent, source))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), NodeError> {
    Ok(())
}

fn load_metadata(
    data_dir: &Path,
    fingerprint: [u8; 32],
    block_log: &File,
    block_log_path: &Path,
    allow_empty_rc4_upgrade: bool,
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
                if allow_empty_rc4_upgrade
                    && bytes[8..40] == RC4_FINGERPRINT
                    && flags == METADATA_WALLET_KEY_FLAG
                    && block_log
                        .metadata()
                        .map_err(|source| {
                            io_error("inspect retained block log", block_log_path, source)
                        })?
                        .len()
                        == 0
                {
                    return Ok(MetadataState::EmptyRc4Upgrade);
                }
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
    if metadata == MetadataState::EmptyRc4Upgrade {
        let previous = fs::read(&path)
            .map_err(|source| io_error("read RC4 metadata for upgrade", &path, source))?;
        let backup = data_dir.join("network.meta.rc4");
        let temporary = data_dir.join("network.meta.rc5.tmp");
        let mut upgraded = previous.clone();
        upgraded[8..40].copy_from_slice(&fingerprint);
        for (target, contents) in [(&backup, &previous), (&temporary, &upgraded)] {
            match OpenOptions::new().write(true).create_new(true).open(target) {
                Ok(mut file) => {
                    file.write_all(contents)
                        .and_then(|()| file.sync_all())
                        .map_err(|source| io_error("write RC4 metadata upgrade", target, source))?;
                }
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                    if fs::read(target)
                        .map_err(|source| io_error("read prior RC4 upgrade file", target, source))?
                        != *contents
                    {
                        return Err(NodeError::FingerprintMismatch);
                    }
                }
                Err(source) => return Err(io_error("create RC4 upgrade file", target, source)),
            }
        }
        fs::rename(&temporary, &path)
            .map_err(|source| io_error("publish RC4 metadata upgrade", &path, source))?;
        return sync_parent_directory(&path);
    }
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
        .map_err(|source| io_error("sync network metadata", &path, source))?;
    sync_parent_directory(&path)
}

fn load_or_create_wallet_key(
    data_dir: &Path,
    profile: NetworkProfile,
    metadata: MetadataState,
    block_log: &File,
    block_log_path: &Path,
    wallet_passphrase: Option<&[u8]>,
) -> Result<(SigningKey, bool), NodeError> {
    let path = data_dir.join(WALLET_KEY_FILE);
    match OpenOptions::new().read(true).open(&path) {
        Ok(mut file) => {
            let length = file
                .metadata()
                .map_err(|source| io_error("inspect wallet key", &path, source))?
                .len();
            if length == 32 {
                if matches!(
                    profile.kind,
                    NetworkProfileKind::Rcnet | NetworkProfileKind::Mainnet
                ) {
                    return Err(NodeError::WalletKeyEncryptionRequired);
                }
                let mut secret = Zeroizing::new([0_u8; 32]);
                file.read_exact(secret.as_mut())
                    .map_err(|_| NodeError::InvalidWalletKey)?;
                let key = SigningKey::from_bytes(secret.as_ref())
                    .map_err(|_| NodeError::InvalidWalletKey)?;
                let destination: [u8; 32] = key.verifying_key().to_bytes().into();
                let legacy = destination == default_miner_destination();
                return Ok((key, legacy));
            }
            if length != wallet_backup::ENCRYPTED_WALLET_KEY_BYTES as u64 {
                return Err(NodeError::InvalidWalletKey);
            }
            let passphrase = wallet_passphrase.ok_or(NodeError::WalletLocked)?;
            let mut encrypted = vec![0_u8; wallet_backup::ENCRYPTED_WALLET_KEY_BYTES];
            file.read_exact(&mut encrypted)
                .map_err(|_| NodeError::InvalidWalletKey)?;
            let (secret, _) =
                wallet_backup::decrypt_wallet_key_bytes(&encrypted, profile.network_id, passphrase)
                    .map_err(wallet_backup_error_to_node)?;
            let key =
                SigningKey::from_bytes(secret.as_ref()).map_err(|_| NodeError::InvalidWalletKey)?;
            let destination: [u8; 32] = key.verifying_key().to_bytes().into();
            let legacy = destination == default_miner_destination();
            Ok((key, legacy))
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            if matches!(
                metadata,
                MetadataState::Current | MetadataState::EmptyRc4Upgrade
            ) {
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
            if matches!(
                profile.kind,
                NetworkProfileKind::Rcnet | NetworkProfileKind::Mainnet
            ) && legacy
            {
                return Err(NodeError::InvalidWalletKey);
            }
            match wallet_passphrase {
                Some(passphrase) => {
                    write_encrypted_wallet_key(&path, &key, profile.network_id, passphrase)?
                }
                None if matches!(
                    profile.kind,
                    NetworkProfileKind::Rcnet | NetworkProfileKind::Mainnet
                ) =>
                {
                    return Err(NodeError::WalletLocked);
                }
                None => write_wallet_key(&path, &key)?,
            }
            Ok((key, legacy))
        }
        Err(source) => Err(io_error("open wallet key", &path, source)),
    }
}

fn wallet_backup_error_to_node(error: wallet_backup::WalletBackupError) -> NodeError {
    match error {
        wallet_backup::WalletBackupError::Node(error) => error,
        wallet_backup::WalletBackupError::Io {
            operation,
            path,
            source,
        } => NodeError::Io {
            operation,
            path,
            source,
        },
        wallet_backup::WalletBackupError::InvalidPassphrase
        | wallet_backup::WalletBackupError::InsecurePassphraseFilePermissions
        | wallet_backup::WalletBackupError::AuthenticationFailed => NodeError::WalletLocked,
        wallet_backup::WalletBackupError::InvalidWalletKey
        | wallet_backup::WalletBackupError::InvalidBackup
        | wallet_backup::WalletBackupError::WrongNetwork
        | wallet_backup::WalletBackupError::DestinationMismatch
        | wallet_backup::WalletBackupError::AlreadyEncrypted
        | wallet_backup::WalletBackupError::WalletKeyAlreadyExists
        | wallet_backup::WalletBackupError::OverlappingPaths => NodeError::InvalidWalletKey,
    }
}

fn random_wallet_signing_key() -> Result<SigningKey, NodeError> {
    loop {
        let mut secret = Zeroizing::new([0_u8; 32]);
        getrandom::fill(secret.as_mut()).map_err(|source| {
            io_error(
                "generate wallet key",
                WALLET_KEY_FILE,
                io::Error::other(source.to_string()),
            )
        })?;
        if let Ok(key) = SigningKey::from_bytes(secret.as_ref()) {
            return Ok(key);
        }
    }
}

fn write_encrypted_wallet_key(
    path: &Path,
    key: &SigningKey,
    network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<(), NodeError> {
    let secret = Zeroizing::new(key.to_bytes().into());
    let (encrypted, _) = wallet_backup::encrypt_wallet_key_bytes(&secret, network_id, passphrase)
        .map_err(wallet_backup_error_to_node)?;
    wallet_backup::write_private_create_new(path, &encrypted).map_err(wallet_backup_error_to_node)
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
        .map_err(|source| io_error("sync wallet key", path, source))?;
    sync_parent_directory(path)
}

#[cfg(test)]
#[cfg_attr(
    any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
    allow(dead_code)
)]
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

/// Kept for fixtures: new records are V3, but V2 logs remain readable.
#[cfg(test)]
fn encode_record_v2(
    accepted_at: u64,
    block: &[u8],
    delta: &[u8],
    previous_record_digest: [u8; 32],
    network_id: [u8; 32],
) -> Result<Vec<u8>, NodeError> {
    if block.len() > max_block_bytes_for_network(network_id) {
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

fn encode_record_v3(
    accepted_at: u64,
    block: &[u8],
    delta: &[u8],
    previous_record_digest: [u8; 32],
    network_id: [u8; 32],
) -> Result<Vec<u8>, NodeError> {
    if block.is_empty() || block.len() > max_block_bytes_for_network(network_id) {
        return Err(NodeError::CorruptLog("block exceeds wire limit".to_owned()));
    }
    if delta.len() > MAX_REVERSIBLE_STATE_DELTA_BYTES {
        return Err(NodeError::CorruptLog(
            "reversible state delta exceeds wire limit".to_owned(),
        ));
    }
    let mut encoder = flate2::write::DeflateEncoder::new(
        Vec::with_capacity(block.len() / 2),
        flate2::Compression::new(BLOCK_LOG_COMPRESSION_LEVEL),
    );
    let compressed = encoder
        .write_all(block)
        .and_then(|()| encoder.finish())
        .map_err(|error| NodeError::CorruptLog(format!("block compression failed: {error}")))?;
    if compressed.len() > max_block_bytes_for_network(network_id) {
        return Err(NodeError::CorruptLog(
            "compressed block exceeds wire limit".to_owned(),
        ));
    }
    let block_len = u32::try_from(block.len())
        .map_err(|_| NodeError::CorruptLog("block length exceeds u32".to_owned()))?;
    let compressed_len = u32::try_from(compressed.len())
        .map_err(|_| NodeError::CorruptLog("compressed block length exceeds u32".to_owned()))?;
    let delta_len = u32::try_from(delta.len()).map_err(|_| {
        NodeError::CorruptLog("reversible state delta length exceeds u32".to_owned())
    })?;
    let capacity = checked_record_len(RECORD_V3_HEADER_BYTES, compressed.len(), delta.len())?;
    let mut record = Vec::with_capacity(capacity);
    record.extend_from_slice(&RECORD_MAGIC);
    record.extend_from_slice(&RECORD_VERSION_V3.to_le_bytes());
    record.extend_from_slice(&0_u16.to_le_bytes());
    record.extend_from_slice(&accepted_at.to_le_bytes());
    record.extend_from_slice(&compressed_len.to_le_bytes());
    record.extend_from_slice(&delta_len.to_le_bytes());
    record.extend_from_slice(&previous_record_digest);
    record.extend_from_slice(&block_len.to_le_bytes());
    record.extend_from_slice(&compressed);
    record.extend_from_slice(delta);
    let checksum = record_checksum_v3(&record);
    record.extend_from_slice(&checksum);
    Ok(record)
}

/// Inflates a V3 record body to exactly `expected_len` bytes.
fn inflate_block_record(
    compressed: &[u8],
    expected_len: usize,
    record_index: u64,
) -> Result<Vec<u8>, NodeError> {
    let mut block = Vec::with_capacity(expected_len);
    flate2::read::DeflateDecoder::new(compressed)
        .take(expected_len as u64 + 1)
        .read_to_end(&mut block)
        .map_err(|error| {
            NodeError::CorruptLog(format!(
                "record {record_index} compressed block is corrupt: {error}"
            ))
        })?;
    if block.len() != expected_len {
        return Err(NodeError::CorruptLog(format!(
            "record {record_index} compressed block inflates to {} bytes, not {expected_len}",
            block.len()
        )));
    }
    Ok(block)
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

fn record_checksum_v3(record_without_checksum: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(RECORD_V3_CHECKSUM_DOMAIN);
    hasher.update(record_without_checksum);
    *hasher.finalize().as_bytes()
}

fn record_checksum_pruned(record_without_checksum: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(RECORD_PRUNED_CHECKSUM_DOMAIN);
    hasher.update(record_without_checksum);
    *hasher.finalize().as_bytes()
}

/// Encodes a pruned record around an uncompressed pruned body.
fn encode_record_pruned(
    accepted_at: u64,
    body: &[u8],
    previous_record_digest: [u8; 32],
) -> Result<Vec<u8>, NodeError> {
    if body.is_empty() || body.len() > pruning::MAX_PRUNED_BODY_BYTES {
        return Err(NodeError::CorruptLog(
            "pruned body exceeds its size limit".to_owned(),
        ));
    }
    let mut encoder = flate2::write::DeflateEncoder::new(
        Vec::with_capacity(body.len() / 2),
        flate2::Compression::new(BLOCK_LOG_COMPRESSION_LEVEL),
    );
    let compressed = encoder
        .write_all(body)
        .and_then(|()| encoder.finish())
        .map_err(|error| {
            NodeError::CorruptLog(format!("pruned body compression failed: {error}"))
        })?;
    let body_len = u32::try_from(body.len())
        .map_err(|_| NodeError::CorruptLog("pruned body length exceeds u32".to_owned()))?;
    let compressed_len = u32::try_from(compressed.len())
        .map_err(|_| NodeError::CorruptLog("compressed pruned body exceeds u32".to_owned()))?;
    let capacity = checked_record_len(RECORD_V3_HEADER_BYTES, compressed.len(), 0)?;
    let mut record = Vec::with_capacity(capacity);
    record.extend_from_slice(&RECORD_MAGIC);
    record.extend_from_slice(&RECORD_VERSION_PRUNED.to_le_bytes());
    record.extend_from_slice(&0_u16.to_le_bytes());
    record.extend_from_slice(&accepted_at.to_le_bytes());
    record.extend_from_slice(&compressed_len.to_le_bytes());
    record.extend_from_slice(&0_u32.to_le_bytes());
    record.extend_from_slice(&previous_record_digest);
    record.extend_from_slice(&body_len.to_le_bytes());
    record.extend_from_slice(&compressed);
    let checksum = record_checksum_pruned(&record);
    record.extend_from_slice(&checksum);
    Ok(record)
}

/// Rewrites a complete V2, V3 or pruned record to follow a new predecessor
/// digest. The caller has authenticated `record` at its old position.
fn rechain_record(record: &[u8], previous_record_digest: [u8; 32]) -> Result<Vec<u8>, NodeError> {
    if record.len() < RECORD_V2_HEADER_BYTES + RECORD_CHECKSUM_BYTES || record[..4] != RECORD_MAGIC
    {
        return Err(NodeError::CorruptLog(
            "cannot rechain a malformed record".to_owned(),
        ));
    }
    let version = u16::from_le_bytes([record[4], record[5]]);
    let mut rewritten = record[..record.len() - RECORD_CHECKSUM_BYTES].to_vec();
    rewritten[24..56].copy_from_slice(&previous_record_digest);
    let checksum = match version {
        RECORD_VERSION_V2 => record_checksum_v2(&rewritten),
        RECORD_VERSION_V3 => record_checksum_v3(&rewritten),
        RECORD_VERSION_PRUNED => record_checksum_pruned(&rewritten),
        _ => {
            return Err(NodeError::CorruptLog(
                "only V2, V3 and pruned records can be rechained".to_owned(),
            ));
        }
    };
    rewritten.extend_from_slice(&checksum);
    Ok(rewritten)
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
    /// Canonical block encoding, inflated for V3 records.
    block_bytes: Vec<u8>,
    payload: ParsedRecordPayload,
    complete_digest: [u8; 32],
    version: BlockRecordVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockRecordVersion {
    LegacyV1,
    V2,
    /// V2 chain semantics with a compressed block body.
    V3,
    /// V3 layout with a compressed pruned body; the proof is gone.
    Pruned,
}

impl BlockRecordVersion {
    const fn header_bytes(self) -> usize {
        match self {
            Self::LegacyV1 => RECORD_V1_HEADER_BYTES,
            Self::V2 => RECORD_V2_HEADER_BYTES,
            Self::V3 | Self::Pruned => RECORD_V3_HEADER_BYTES,
        }
    }
}

struct ScannedReplayLog {
    records: Vec<BlockRecordLocator>,
    children: HashMap<[u8; 32], Vec<usize>>,
    transactions: explorer_index::TransactionIndex,
    addresses: explorer_address_index::AddressHistoryIndex,
    /// Successor header state stored in each pruned record.
    pruned_headers: HashMap<[u8; 32], SuccessorHeaderPreflight>,
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
    network_id: [u8; 32],
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
    let record_version = match version {
        RECORD_VERSION_V1 => BlockRecordVersion::LegacyV1,
        RECORD_VERSION_V2 => BlockRecordVersion::V2,
        RECORD_VERSION_V3 => BlockRecordVersion::V3,
        RECORD_VERSION_PRUNED => BlockRecordVersion::Pruned,
        _ => {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} has unsupported version {version}"
            )));
        }
    };
    let header_len = record_version.header_bytes();
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
    if block_len > max_block_bytes_for_network(network_id) {
        return Err(NodeError::CorruptLog(format!(
            "record {record_index} block exceeds the wire limit"
        )));
    }
    let (delta_len, previous_record_digest) = if record_version != BlockRecordVersion::LegacyV1 {
        let delta_len =
            u32::from_le_bytes(header[20..24].try_into().expect("fixed slice")) as usize;
        if delta_len > MAX_REVERSIBLE_STATE_DELTA_BYTES
            || (record_version == BlockRecordVersion::Pruned && delta_len != 0)
        {
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
    let inflated_len = if matches!(
        record_version,
        BlockRecordVersion::V3 | BlockRecordVersion::Pruned
    ) {
        let inflated_len =
            u32::from_le_bytes(header[56..60].try_into().expect("fixed slice")) as usize;
        let inflated_limit = if record_version == BlockRecordVersion::Pruned {
            pruning::MAX_PRUNED_BODY_BYTES
        } else {
            max_block_bytes_for_network(network_id)
        };
        if inflated_len == 0 || inflated_len > inflated_limit {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} inflated block exceeds the wire limit"
            )));
        }
        Some(inflated_len)
    } else {
        None
    };
    let complete_len = checked_record_len(header_len, block_len, delta_len)?;

    let mut stored_block = vec![0_u8; block_len];
    reader.read_exact(&mut stored_block).map_err(|source| {
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
    complete_record.extend_from_slice(&stored_block);
    complete_record.extend_from_slice(&delta_bytes);
    let expected_checksum = match record_version {
        BlockRecordVersion::LegacyV1 => record_checksum_v1(&complete_record),
        BlockRecordVersion::V2 => record_checksum_v2(&complete_record),
        BlockRecordVersion::V3 => record_checksum_v3(&complete_record),
        BlockRecordVersion::Pruned => record_checksum_pruned(&complete_record),
    };
    if checksum != expected_checksum {
        return Err(NodeError::CorruptLog(format!(
            "record {record_index} checksum mismatch"
        )));
    }
    complete_record.extend_from_slice(&checksum);
    let complete_digest = complete_record_digest(&complete_record);
    // Inflate only after the stored bytes authenticated.
    let block_bytes = match inflated_len {
        Some(inflated_len) => inflate_block_record(&stored_block, inflated_len, record_index)?,
        None => stored_block,
    };
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
        version: record_version,
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
) -> Result<(ParsedLogRecord, StoredBlock), NodeError> {
    let max_block_bytes = max_block_bytes_for_network(network_id);
    let header_bytes = locator.version.header_bytes();
    let (minimum_length, maximum_length) = match locator.version {
        BlockRecordVersion::LegacyV1 => (
            header_bytes + RECORD_CHECKSUM_BYTES,
            checked_record_len(header_bytes, max_block_bytes, 0)?,
        ),
        BlockRecordVersion::V2 | BlockRecordVersion::V3 | BlockRecordVersion::Pruned => (
            header_bytes + RECORD_CHECKSUM_BYTES,
            checked_record_len(
                header_bytes,
                max_block_bytes,
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
    let record =
        read_log_record(&mut reader, path, locator.ordinal, network_id)?.ok_or_else(|| {
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
    let actual_version = record.version;
    if actual_version != locator.version {
        return Err(NodeError::CorruptLog(format!(
            "record {} version changed",
            locator.ordinal
        )));
    }
    if require_v2 && actual_version == BlockRecordVersion::LegacyV1 {
        return Err(NodeError::ProductionLegacyBlockLog(locator.ordinal));
    }
    if record.accepted_at != locator.accepted_at {
        return Err(NodeError::CorruptLog(format!(
            "record {} acceptance time changed",
            locator.ordinal
        )));
    }
    let block = decode_stored_block(&record, locator.ordinal, network_id)?;
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

/// Decodes an authenticated record. Full records must re-encode to the exact
/// stored bytes; pruned records keep their stored block identifier.
fn decode_stored_block(
    record: &ParsedLogRecord,
    record_index: u64,
    network_id: [u8; 32],
) -> Result<StoredBlock, NodeError> {
    if record.version == BlockRecordVersion::Pruned {
        return pruning::decode_pruned_body(&record.block_bytes, network_id).map_err(|error| {
            match error {
                NodeError::CorruptLog(message) => {
                    NodeError::CorruptLog(format!("record {record_index}: {message}"))
                }
                other => other,
            }
        });
    }
    let block = decode_block(&record.block_bytes, network_id).map_err(|error| {
        NodeError::CorruptLog(format!("record {record_index} cannot decode: {error}"))
    })?;
    let canonical = encode_block(&block).map_err(|error| {
        NodeError::CorruptLog(format!("record {record_index} cannot re-encode: {error}"))
    })?;
    if canonical != record.block_bytes {
        return Err(NodeError::CorruptLog(format!(
            "record {record_index} is not canonical"
        )));
    }
    Ok(StoredBlock::from_full(block))
}

/// Size reported for a stored block: the canonical size of the full block,
/// including for pruned records.
fn stored_block_size(record: &ParsedLogRecord, block: &StoredBlock) -> usize {
    match &block.proof {
        pruning::StoredProof::Pruned { original_bytes, .. } => *original_bytes,
        pruning::StoredProof::Full(_) => record.block_bytes.len(),
    }
}

fn read_indexed_block(
    file: &File,
    path: &Path,
    indexed: &IndexedBlock,
    expected_block_id: [u8; 32],
    network_id: [u8; 32],
    require_v2: bool,
) -> Result<StoredBlock, NodeError> {
    read_indexed_block_with_size(
        file,
        path,
        indexed,
        expected_block_id,
        network_id,
        require_v2,
    )
    .map(|(block, _)| block)
}

/// Returns size only after the exact stored frame has passed all locator,
/// digest, decode/reencode and identity checks in read_located_record.
fn read_indexed_block_with_size(
    file: &File,
    path: &Path,
    indexed: &IndexedBlock,
    expected_block_id: [u8; 32],
    network_id: [u8; 32],
    require_v2: bool,
) -> Result<(StoredBlock, usize), NodeError> {
    if indexed.block_id() != expected_block_id {
        return Err(NodeError::CorruptLog(
            "fork index key does not match its durable record locator".to_owned(),
        ));
    }
    let (record, block) =
        read_located_record(file, path, &indexed.locator, network_id, require_v2)?;
    let size = stored_block_size(&record, &block);
    Ok((block, size))
}

#[allow(clippy::too_many_arguments)]
fn replay_log(
    data_dir: &Path,
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
        data_dir,
        log,
        path,
        &mut replayed_state,
        &mut replayed_index,
        verifier,
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
#[allow(clippy::too_many_arguments)]
fn replay_log_into(
    data_dir: &Path,
    log: &File,
    path: &Path,
    state: &mut ChainState,
    index: &mut BlockIndex,
    verifier: &ConsensusPowVerifier,
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

    // A pruned log starts with its pruned prefix; replay begins at the anchor.
    let root = install_pruned_prefix(data_dir, &scanned, index, state, verifier, params)?;
    let (mut winning_tip, mut winning_work, mut winning_record_index) =
        match index.blocks.get(&root) {
            Some(entry) => (root, entry.cumulative_work, entry.locator.ordinal),
            None => (params.genesis_hash, U512::zero(), u64::MAX),
        };
    let mut stack = vec![ReplayDfsFrame {
        block_id: root,
        next_child: 0,
        undo: None,
    }];
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

    if state.tip() != root || index.blocks.len() != scanned.records.len() {
        return Err(NodeError::CorruptLog(
            "startup DFS did not return to its root after visiting every record".to_owned(),
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
    index.transactions = scanned.transactions;
    index.addresses = scanned.addresses;
    Ok(ReplayLogState {
        last_record_digest: scanned.last_record_digest,
        log_length: scanned.log_length,
        record_count: u64::try_from(scanned.records.len())
            .map_err(|_| NodeError::CorruptLog("block record count exceeds u64".to_owned()))?,
    })
}

/// Indexes the pruned prefix of a scanned log and positions `state` at its
/// anchor. Returns the block replay starts from: the anchor, or genesis for an
/// unpruned log.
fn install_pruned_prefix(
    data_dir: &Path,
    scanned: &ScannedReplayLog,
    index: &mut BlockIndex,
    state: &mut ChainState,
    verifier: &ConsensusPowVerifier,
    params: NetworkParams,
) -> Result<[u8; 32], NodeError> {
    let mut last = None;
    for record in scanned
        .records
        .iter()
        .take_while(|record| record.version == BlockRecordVersion::Pruned)
    {
        let parent_work = index.work_at(record.parent).ok_or_else(|| {
            NodeError::CorruptLog(format!(
                "pruned record {} parent is absent from the fork index",
                record.ordinal
            ))
        })?;
        let cumulative_work = add_chain_work(parent_work, record.target).map_err(|error| {
            NodeError::CorruptLog(format!(
                "pruned record {} cumulative work is invalid: {error}",
                record.ordinal
            ))
        })?;
        let successor_header = *scanned
            .pruned_headers
            .get(&record.block_id)
            .ok_or_else(|| {
                NodeError::CorruptLog(format!(
                    "pruned record {} lacks its header state",
                    record.ordinal
                ))
            })?;
        let ancestors = index.ancestor_table(record.parent)?;
        index.blocks.insert(
            record.block_id,
            Arc::new(IndexedBlock {
                locator: *record,
                cumulative_work,
                successor_header,
                ancestors,
            }),
        );
        last = Some(*record);
    }
    let Some(last) = last else {
        return Ok(params.genesis_hash);
    };
    let anchor = load_prune_anchor(data_dir, &last, index, params, verifier)?;
    *state = anchor.state.clone();
    index.anchor = Some(Arc::new(anchor));
    Ok(last.block_id)
}

/// Loads the anchor saved for the newest pruned record and checks it against
/// that record's identity and header state.
fn load_prune_anchor(
    data_dir: &Path,
    last_pruned: &BlockRecordLocator,
    index: &BlockIndex,
    params: NetworkParams,
    verifier: &ConsensusPowVerifier,
) -> Result<PruneAnchor, NodeError> {
    let path = pruning::anchor_path(data_dir, last_pruned.height);
    let saved = pruning::read_state_file(&path, params, verifier).map_err(|error| {
        NodeError::CorruptLog(format!(
            "the pruned block log needs its anchor state {}: {error}",
            path.display()
        ))
    })?;
    let expected_header = index
        .blocks
        .get(&last_pruned.block_id)
        .map(|entry| entry.successor_header);
    if saved.block_id != last_pruned.block_id
        || saved.height != last_pruned.height
        || Some(saved.successor) != expected_header
    {
        return Err(NodeError::CorruptLog(
            "prune anchor state does not match the newest pruned record".to_owned(),
        ));
    }
    Ok(PruneAnchor {
        block_id: saved.block_id,
        height: saved.height,
        state: saved.state,
    })
}

/// Attaches the anchor to an index restored from a startup snapshot.
fn attach_prune_anchor(
    data_dir: &Path,
    index: &mut BlockIndex,
    params: NetworkParams,
    verifier: &ConsensusPowVerifier,
) -> Result<(), NodeError> {
    let last = index
        .blocks
        .values()
        .filter(|entry| entry.locator.version == BlockRecordVersion::Pruned)
        .max_by_key(|entry| entry.height())
        .map(|entry| entry.locator);
    if let Some(last) = last {
        let anchor = load_prune_anchor(data_dir, &last, index, params, verifier)?;
        index.anchor = Some(Arc::new(anchor));
    }
    Ok(())
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
    let mut transactions = explorer_index::TransactionIndex::default();
    let mut addresses = explorer_address_index::AddressHistoryIndex::default();
    let mut known_blocks = HashSet::from([params.genesis_hash]);
    let mut pruned_headers = HashMap::new();
    let mut saw_full_record = false;
    let mut last_pruned = params.genesis_hash;
    let mut pruned_height = 0_u64;
    loop {
        let offset = reader
            .stream_position()
            .map_err(|source| io_error("locate block log record", path, source))?;
        let Some(record) = read_log_record(&mut reader, path, record_index, network_id)? else {
            let log_length = reader
                .stream_position()
                .map_err(|source| io_error("locate block log end", path, source))?;
            return Ok(ScannedReplayLog {
                records,
                children,
                transactions,
                addresses,
                last_record_digest,
                log_length,
                pruned_headers,
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
        let block = decode_stored_block(&record, record_index, network_id)?;
        let ParsedLogRecord {
            accepted_at,
            complete_digest,
            version,
            ..
        } = record;
        if version == BlockRecordVersion::Pruned {
            if saw_full_record
                || block.challenge.previous_block != last_pruned
                || block.challenge.height != pruned_height.saturating_add(1)
            {
                return Err(NodeError::CorruptLog(format!(
                    "record {record_index} breaks the pruned prefix chain"
                )));
            }
            last_pruned = block.block_id();
            pruned_height = block.challenge.height;
            let successor = block.pruned_successor(params)?.ok_or_else(|| {
                NodeError::CorruptLog(format!("record {record_index} lacks pruned header state"))
            })?;
            pruned_headers.insert(block.block_id(), successor);
        } else {
            saw_full_record = true;
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
        let position = records.len();
        transactions.insert_block(block_id, block.transactions.iter().map(Transaction::txid));
        addresses.insert_entries(
            explorer_address_index::AddressHistoryIndex::stored_block_entries(&block),
        );
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

#[cfg(all(
    test,
    not(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))
))]
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

    /// A packaged ProductionV3 node canonicalizes its own sidecars before
    /// handing them to the trusted ceremony filesystem, which rejects `\\?\`
    /// verbatim syntax. Canonicalization on Windows always produces exactly
    /// that, so the reduction below is what keeps a packaged node able to open
    /// its own Record V2 and proof worker.
    #[test]
    fn canonical_package_paths_are_plain_enough_for_the_ceremony_filesystem() {
        let directory = std::env::temp_dir().join(format!(
            "cmfd-plain-package-path-{}-{}",
            std::process::id(),
            NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join(PRODUCTION_V3_PACKAGE_RECORD_V2);
        fs::write(&file, b"record").unwrap();

        let canonical = fs::canonicalize(&file).unwrap();
        let plain = plain_package_path(canonical.clone());

        // Same file, and still absolute.
        assert!(plain.is_absolute());
        assert_eq!(fs::read(&plain).unwrap(), b"record");
        assert_eq!(plain.file_name(), canonical.file_name());

        #[cfg(windows)]
        {
            use std::path::{Component, Prefix};

            assert!(
                matches!(
                    canonical.components().next(),
                    Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::VerbatimDisk(_))
                ),
                "canonicalize should produce a verbatim path for this test to be meaningful"
            );
            assert!(
                matches!(
                    plain.components().next(),
                    Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
                ),
                "the ceremony filesystem only accepts a plain disk prefix: {plain:?}"
            );
        }
        #[cfg(not(windows))]
        assert_eq!(plain, canonical);

        fs::remove_dir_all(&directory).unwrap();
    }

    pub(super) fn test_dir(name: &str) -> PathBuf {
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("cmfd-node-{name}-{}-{id}", std::process::id()))
    }

    pub(super) fn clean_test_dir(path: &Path) {
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
                RECORD_VERSION_V3 => RECORD_V3_HEADER_BYTES,
                _ => panic!("unsupported fixture record version {version}"),
            };
            assert!(bytes.len() - offset >= header_len);
            let block_len =
                u32::from_le_bytes(bytes[offset + 16..offset + 20].try_into().unwrap()) as usize;
            let delta_len = if version != RECORD_VERSION_V1 {
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
            RECORD_VERSION_V3 => record_checksum_v3(&record[..checksum_start]),
            _ => panic!("unsupported fixture record version {version}"),
        };
        record[checksum_start..].copy_from_slice(&checksum);
    }

    /// Splits a V2 or V3 record into its fields, inflating a V3 block body.
    fn v2_record_parts(record: &[u8]) -> (u64, [u8; 32], Vec<u8>, Vec<u8>) {
        let version = u16::from_le_bytes(record[4..6].try_into().unwrap());
        assert!(matches!(version, RECORD_VERSION_V2 | RECORD_VERSION_V3));
        let accepted_at = u64::from_le_bytes(record[8..16].try_into().unwrap());
        let block_len = u32::from_le_bytes(record[16..20].try_into().unwrap()) as usize;
        let delta_len = u32::from_le_bytes(record[20..24].try_into().unwrap()) as usize;
        let previous_record_digest = record[24..56].try_into().unwrap();
        let block_start = if version == RECORD_VERSION_V3 {
            RECORD_V3_HEADER_BYTES
        } else {
            RECORD_V2_HEADER_BYTES
        };
        let delta_start = block_start + block_len;
        let delta_end = delta_start + delta_len;
        let block_bytes = if version == RECORD_VERSION_V3 {
            let inflated_len = u32::from_le_bytes(record[56..60].try_into().unwrap()) as usize;
            inflate_block_record(&record[block_start..delta_start], inflated_len, 0).unwrap()
        } else {
            record[block_start..delta_start].to_vec()
        };
        (
            accepted_at,
            previous_record_digest,
            block_bytes,
            record[delta_start..delta_end].to_vec(),
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
            &block_bytes,
            &forged_delta,
            previous_record_digest,
            DEVNET_NETWORK_ID,
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
        assert_eq!(
            queue.telemetry().unwrap().normal,
            ProofAdmissionClassTelemetry {
                active: 1,
                queued: 1,
                wait_events: 1,
                rejections: 1,
                proof_failures: 0,
            }
        );
        drop(active);
        waiter.join().unwrap().unwrap();
        assert_eq!(queue.counts().unwrap(), (0, 0));

        let timeout_queue = Arc::new(ProofVerificationQueue::new(1, 1, Duration::from_millis(1)));
        let active = timeout_queue.acquire().unwrap();
        assert!(matches!(
            timeout_queue.acquire(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        assert_eq!(timeout_queue.telemetry().unwrap().normal.wait_events, 1);
        assert_eq!(timeout_queue.telemetry().unwrap().normal.rejections, 1);
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
        assert_eq!(
            close_queue.telemetry().unwrap().priority,
            ProofAdmissionClassTelemetry {
                active: 0,
                queued: 0,
                wait_events: 1,
                rejections: 1,
                proof_failures: 0,
            }
        );
        drop(active);
    }

    #[test]
    fn remote_proof_scheduler_bounds_sixteen_invalid_peers_and_serves_valid_and_local_work() {
        const INVALID_PEERS: u64 = 16;
        let remote = Arc::new(RemoteProofAdmissionQueue::new(
            MAX_REMOTE_PROOF_ADMISSIONS,
            Duration::from_secs(2),
            Duration::from_secs(60),
        ));
        let proof = Arc::new(ProofVerificationQueue::new(
            1,
            MAX_QUEUED_PROOF_VERIFICATIONS,
            Duration::from_secs(2),
        ));
        let remote_blocker = remote
            .acquire(RemoteProofPeerId::new(10_000).unwrap())
            .unwrap();
        let proof_blocker = proof.acquire().unwrap();
        let (served_tx, served_rx) = mpsc::channel();
        let mut workers = Vec::new();

        for value in 1..MAX_REMOTE_PROOF_ADMISSIONS as u64 {
            let worker_remote = Arc::clone(&remote);
            let worker_proof = Arc::clone(&proof);
            let served = served_tx.clone();
            workers.push(thread::spawn(move || {
                let peer = RemoteProofPeerId::new(value).unwrap();
                let mut remote_permit = worker_remote.acquire(peer).unwrap();
                let _proof_permit = worker_proof.acquire().unwrap();
                // Each identity represents a distinct below-target envelope
                // whose expensive relation check failed.
                served.send(value).unwrap();
                remote_permit.mark_proof_failure();
            }));
            let deadline = Instant::now() + Duration::from_secs(2);
            while remote.telemetry().unwrap().queued != value as usize && Instant::now() < deadline
            {
                thread::yield_now();
            }
            assert_eq!(remote.telemetry().unwrap().queued, value as usize);
        }

        let local_proof = Arc::clone(&proof);
        let local_served = served_tx.clone();
        let local = thread::spawn(move || {
            let _permit = local_proof.acquire_priority().unwrap();
            local_served.send(0).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while proof.telemetry().unwrap().priority.queued != 1 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(proof.telemetry().unwrap().priority.queued, 1);

        // Let the first remote session become active while both it and the
        // locally mined block wait on the proof queue. The local priority lane
        // must win once that queue opens.
        drop(remote_blocker);
        let deadline = Instant::now() + Duration::from_secs(2);
        while (remote.telemetry().unwrap().queued != MAX_REMOTE_PROOF_ADMISSIONS - 2
            || proof.telemetry().unwrap().normal.queued != 1)
            && Instant::now() < deadline
        {
            thread::yield_now();
        }
        assert_eq!(
            remote.telemetry().unwrap().queued,
            MAX_REMOTE_PROOF_ADMISSIONS - 2
        );
        assert_eq!(proof.telemetry().unwrap().normal.queued, 1);

        let valid_peer = RemoteProofPeerId::new(INVALID_PEERS + 1).unwrap();
        let valid_remote = Arc::clone(&remote);
        let valid_proof = Arc::clone(&proof);
        let valid_served = served_tx.clone();
        workers.push(thread::spawn(move || {
            let _remote_permit = valid_remote.acquire(valid_peer).unwrap();
            let _proof_permit = valid_proof.acquire().unwrap();
            valid_served.send(INVALID_PEERS + 1).unwrap();
        }));
        let deadline = Instant::now() + Duration::from_secs(2);
        while remote.telemetry().unwrap().queued != MAX_REMOTE_PROOF_ADMISSIONS - 1
            && Instant::now() < deadline
        {
            thread::yield_now();
        }
        assert_eq!(
            remote.telemetry().unwrap().queued,
            MAX_REMOTE_PROOF_ADMISSIONS - 1
        );

        // The remaining nine identities continuously retry bounded admission.
        // They may fill newly opened tail slots, but none can overtake the
        // valid session already admitted ahead of them.
        for value in MAX_REMOTE_PROOF_ADMISSIONS as u64..=INVALID_PEERS {
            let worker_remote = Arc::clone(&remote);
            let worker_proof = Arc::clone(&proof);
            let served = served_tx.clone();
            workers.push(thread::spawn(move || {
                let peer = RemoteProofPeerId::new(value).unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut remote_permit = loop {
                    match worker_remote.acquire(peer) {
                        Ok(permit) => break permit,
                        Err(NodeError::ProofVerificationQueueFull) if Instant::now() < deadline => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("remote retry failed: {error}"),
                    }
                };
                let _proof_permit = worker_proof.acquire().unwrap();
                served.send(value).unwrap();
                remote_permit.mark_proof_failure();
            }));
        }

        let overflow_sessions = INVALID_PEERS - MAX_REMOTE_PROOF_ADMISSIONS as u64 + 1;
        let deadline = Instant::now() + Duration::from_secs(2);
        while remote.telemetry().unwrap().rejections < overflow_sessions
            && Instant::now() < deadline
        {
            thread::yield_now();
        }
        assert!(remote.telemetry().unwrap().rejections >= overflow_sessions);

        drop(proof_blocker);
        assert_eq!(served_rx.recv_timeout(Duration::from_secs(2)).unwrap(), 0);
        local.join().unwrap();

        for expected in 1..MAX_REMOTE_PROOF_ADMISSIONS as u64 {
            assert_eq!(
                served_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                expected
            );
        }
        assert_eq!(
            served_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            INVALID_PEERS + 1,
            "FIFO must serve the admitted valid session before retrying attackers"
        );
        let mut overflow = HashSet::new();
        for _ in MAX_REMOTE_PROOF_ADMISSIONS as u64..=INVALID_PEERS {
            overflow.insert(served_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        }
        assert_eq!(
            overflow,
            (MAX_REMOTE_PROOF_ADMISSIONS as u64..=INVALID_PEERS).collect()
        );
        for worker in workers {
            worker.join().unwrap();
        }
        let cooled = remote
            .state
            .lock()
            .unwrap()
            .cooldowns
            .keys()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(cooled.len(), INVALID_PEERS as usize);
        for peer in cooled {
            assert!(matches!(
                remote.acquire(peer),
                Err(NodeError::ProofVerificationQueueFull)
            ));
        }
        drop(remote.acquire(valid_peer).unwrap());

        let remote_status = remote.telemetry().unwrap();
        assert_eq!(remote_status.active, 0);
        assert_eq!(remote_status.queued, 0);
        assert!(remote_status.wait_events >= MAX_REMOTE_PROOF_ADMISSIONS as u64);
        assert!(remote_status.wait_events <= INVALID_PEERS + 1);
        assert_eq!(remote_status.proof_failures, INVALID_PEERS);
        assert!(remote_status.rejections >= INVALID_PEERS);
        let proof_status = proof.telemetry().unwrap();
        assert_eq!(proof_status.normal.active, 0);
        assert_eq!(proof_status.priority.active, 0);
        assert_eq!(proof_status.priority.wait_events, 1);
    }

    #[test]
    fn remote_proof_scheduler_bounds_sessions_rejects_duplicates_and_wakes_on_close() {
        let remote = Arc::new(RemoteProofAdmissionQueue::new(
            2,
            Duration::from_secs(60),
            Duration::from_secs(60),
        ));
        let active_peer = RemoteProofPeerId::new(1).unwrap();
        let waiting_peer = RemoteProofPeerId::new(2).unwrap();
        let active = remote.acquire(active_peer).unwrap();

        assert!(matches!(
            remote.acquire(active_peer),
            Err(NodeError::ProofVerificationQueueFull)
        ));
        let waiting_remote = Arc::clone(&remote);
        let waiter = thread::spawn(move || waiting_remote.acquire(waiting_peer).map(drop));
        let deadline = Instant::now() + Duration::from_secs(2);
        while remote.telemetry().unwrap().queued != 1 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(remote.telemetry().unwrap().queued, 1);
        assert!(matches!(
            remote.acquire(waiting_peer),
            Err(NodeError::ProofVerificationQueueFull)
        ));
        assert!(matches!(
            remote.acquire(RemoteProofPeerId::new(3).unwrap()),
            Err(NodeError::ProofVerificationQueueFull)
        ));
        assert_eq!(
            remote.telemetry().unwrap(),
            ProofAdmissionClassTelemetry {
                active: 1,
                queued: 1,
                wait_events: 1,
                rejections: 3,
                proof_failures: 0,
            }
        );

        let close_started = Instant::now();
        remote.close();
        assert!(matches!(
            waiter.join().unwrap(),
            Err(NodeError::ProofVerifierShuttingDown)
        ));
        assert!(
            close_started.elapsed() < Duration::from_secs(1),
            "close must wake a remote waiter instead of waiting for its deadline"
        );
        assert_eq!(remote.telemetry().unwrap().queued, 0);
        assert_eq!(remote.telemetry().unwrap().rejections, 4);
        drop(active);
        assert_eq!(remote.telemetry().unwrap().active, 0);
    }

    #[test]
    fn remote_timeout_cleans_identity_and_retry_cannot_overtake_queued_valid_work() {
        let remote = Arc::new(RemoteProofAdmissionQueue::new(
            3,
            Duration::from_millis(300),
            Duration::from_secs(60),
        ));
        let active = remote.acquire(RemoteProofPeerId::new(1).unwrap()).unwrap();
        let timed_peer = RemoteProofPeerId::new(2).unwrap();
        let valid_peer = RemoteProofPeerId::new(3).unwrap();

        let timed_remote = Arc::clone(&remote);
        let timed = thread::spawn(move || timed_remote.acquire(timed_peer).map(drop));
        let deadline = Instant::now() + Duration::from_secs(2);
        while remote.telemetry().unwrap().queued != 1 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(remote.telemetry().unwrap().queued, 1);
        thread::sleep(Duration::from_millis(75));

        let (served_tx, served_rx) = mpsc::channel();
        let (release_valid_tx, release_valid_rx) = mpsc::channel();
        let valid_remote = Arc::clone(&remote);
        let valid_served = served_tx.clone();
        let valid = thread::spawn(move || {
            let _permit = valid_remote.acquire(valid_peer).unwrap();
            valid_served.send(3_u64).unwrap();
            release_valid_rx.recv().unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while remote.telemetry().unwrap().queued != 2 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(remote.telemetry().unwrap().queued, 2);

        assert!(matches!(
            timed.join().unwrap(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        assert_eq!(remote.telemetry().unwrap().queued, 1);
        assert_eq!(remote.telemetry().unwrap().rejections, 1);

        let retry_remote = Arc::clone(&remote);
        let retry_served = served_tx;
        let retry = thread::spawn(move || {
            let _permit = retry_remote.acquire(timed_peer).unwrap();
            retry_served.send(2_u64).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while remote.telemetry().unwrap().queued != 2 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(remote.telemetry().unwrap().queued, 2);

        drop(active);
        assert_eq!(
            served_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            3,
            "a timed-out identity retry must join behind already queued valid work"
        );
        assert_eq!(remote.telemetry().unwrap().queued, 1);
        release_valid_tx.send(()).unwrap();
        assert_eq!(served_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
        valid.join().unwrap();
        retry.join().unwrap();
        assert_eq!(remote.telemetry().unwrap().queued, 0);
        assert_eq!(remote.telemetry().unwrap().wait_events, 3);
    }

    #[test]
    fn remote_cancellation_removes_fifo_state_across_grant_and_close_races() {
        let remote = Arc::new(RemoteProofAdmissionQueue::new(
            3,
            Duration::from_secs(2),
            Duration::from_secs(60),
        ));
        let active = remote.acquire(RemoteProofPeerId::new(1).unwrap()).unwrap();
        let request =
            RemoteProofRequest::new(Instant::now().checked_add(Duration::from_secs(60)).unwrap());
        let waiting_remote = Arc::clone(&remote);
        let waiting_request = request.clone();
        let waiter = thread::spawn(move || {
            waiting_remote.acquire_cancellable(RemoteProofPeerId::new(2).unwrap(), waiting_request)
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while remote.telemetry().unwrap().queued != 1 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(remote.telemetry().unwrap().queued, 1);

        // Cancellation wins even if capacity becomes available in the same
        // wakeup; the identity is removed from both FIFO structures.
        assert!(request.cancel());
        drop(active);
        assert!(matches!(
            waiter.join().unwrap(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        let state = remote.state.lock().unwrap();
        assert!(state.waiting.is_empty());
        assert!(state.waiting_set.is_empty());
        assert!(state.active.is_none());
        drop(state);
        drop(remote.acquire(RemoteProofPeerId::new(3).unwrap()).unwrap());

        let active = remote.acquire(RemoteProofPeerId::new(4).unwrap()).unwrap();
        let waiting_remote = Arc::clone(&remote);
        let waiter = thread::spawn(move || {
            waiting_remote.acquire_cancellable(
                RemoteProofPeerId::new(5).unwrap(),
                RemoteProofRequest::new(
                    Instant::now().checked_add(Duration::from_secs(60)).unwrap(),
                ),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while remote.telemetry().unwrap().queued != 1 && Instant::now() < deadline {
            thread::yield_now();
        }
        remote.close();
        assert!(matches!(
            waiter.join().unwrap(),
            Err(NodeError::ProofVerifierShuttingDown)
        ));
        drop(active);
        let state = remote.state.lock().unwrap();
        assert!(state.waiting.is_empty());
        assert!(state.waiting_set.is_empty());
        assert!(state.active.is_none());
    }

    #[test]
    fn general_proof_queue_deadline_wins_when_capacity_is_released_after_expiry() {
        let queue = Arc::new(ProofVerificationQueue::new(1, 8, Duration::from_secs(2)));
        let active = queue.acquire().unwrap();
        let wake_barrier = Arc::new(DeadlineWakeBarrier::new());
        *queue.deadline_wake_barrier.lock().unwrap() = Some(Arc::clone(&wake_barrier));
        let deadline = Instant::now() + Duration::from_millis(100);
        let waiting_queue = Arc::clone(&queue);
        let waiter = thread::spawn(move || {
            waiting_queue.acquire_cancellable(RemoteProofRequest::new(deadline))
        });

        // Hold the waiter immediately after its first condvar wake. Capacity
        // becomes ready only after its authoritative deadline has expired.
        wake_barrier.entered.wait();
        while Instant::now() < deadline {
            thread::yield_now();
        }
        drop(active);
        wake_barrier.release.wait();

        assert!(matches!(
            waiter.join().unwrap(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        let state = queue.state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert_eq!(state.normal_queued, 0);
        assert_eq!(state.priority_queued, 0);
        assert!(state.cancelled_normal_tickets.is_empty());
        assert!(state.cancelled_priority_tickets.is_empty());
    }

    #[test]
    fn received_remote_block_waits_for_its_own_deadline_not_the_local_queue_timeout() {
        let queue = Arc::new(ProofVerificationQueue::new(
            1,
            8,
            Duration::from_millis(100),
        ));
        let active = queue.acquire().unwrap();
        let waiting_queue = Arc::clone(&queue);
        let waiter = thread::spawn(move || {
            waiting_queue
                .acquire_cancellable(RemoteProofRequest::new(
                    Instant::now() + Duration::from_secs(5),
                ))
                .map(drop)
        });
        thread::sleep(Duration::from_millis(300));
        drop(active);
        assert!(waiter.join().unwrap().is_ok());
        let state = queue.state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert_eq!(state.normal_queued, 0);
    }

    #[test]
    fn remote_proof_queue_deadline_wins_when_capacity_is_released_after_expiry() {
        let queue = Arc::new(RemoteProofAdmissionQueue::new(
            8,
            Duration::from_secs(2),
            Duration::from_secs(60),
        ));
        let active = queue.acquire(RemoteProofPeerId::new(1).unwrap()).unwrap();
        let wake_barrier = Arc::new(DeadlineWakeBarrier::new());
        *queue.deadline_wake_barrier.lock().unwrap() = Some(Arc::clone(&wake_barrier));
        let deadline = Instant::now() + Duration::from_millis(100);
        let waiting_queue = Arc::clone(&queue);
        let waiter = thread::spawn(move || {
            waiting_queue.acquire_cancellable(
                RemoteProofPeerId::new(2).unwrap(),
                RemoteProofRequest::new(deadline),
            )
        });

        wake_barrier.entered.wait();
        while Instant::now() < deadline {
            thread::yield_now();
        }
        drop(active);
        wake_barrier.release.wait();

        assert!(matches!(
            waiter.join().unwrap(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        let state = queue.state.lock().unwrap();
        assert!(state.active.is_none());
        assert!(state.waiting.is_empty());
        assert!(state.waiting_set.is_empty());
    }

    #[test]
    fn proof_queue_deadline_overflow_is_retryable_instead_of_panicking() {
        assert!(matches!(
            checked_queue_deadline(Instant::now(), Duration::MAX),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
    }

    #[test]
    fn production_finalization_cools_every_live_session_without_eviction() {
        let timeout =
            NodeError::ProofVerifierWorker(VerifierWorkerError::DispatchedRequest(Box::new(
                VerifierWorkerError::Process(ProofWorkerError::Timeout { milliseconds: 1 }),
            )));
        let crash =
            NodeError::ProofVerifierWorker(VerifierWorkerError::DispatchedRequest(Box::new(
                VerifierWorkerError::Process(ProofWorkerError::WorkerExited {
                    code: Some(9),
                    stderr: String::new(),
                }),
            )));
        let protocol = NodeError::ProofVerifierWorker(VerifierWorkerError::DispatchedRequest(
            Box::new(VerifierWorkerError::Protocol(
                cmfd_proof_worker::VerifierProtocolError::InvalidStatus,
            )),
        ));
        assert!(is_remote_peer_proof_failure(&timeout));
        assert!(is_remote_peer_proof_failure(&crash));
        assert!(is_remote_peer_proof_failure(&protocol));
        assert!(!is_remote_peer_proof_failure(
            &NodeError::ProofVerifierWorker(VerifierWorkerError::Process(
                ProofWorkerError::Timeout { milliseconds: 1 },
            ))
        ));
        assert!(!is_remote_peer_proof_failure(
            &NodeError::ProofVerifierWorker(VerifierWorkerError::Startup(
                "startup authentication failed".to_owned(),
            ))
        ));
        assert!(!is_remote_peer_proof_failure(
            &NodeError::ProofVerificationQueueTimeout
        ));

        let path = test_dir("proof-finalization-live-session-cooldown");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let mut invalid = mined_candidate(&node, accepted_at);
        let BlockProof::V2Reference(proof) = &mut invalid.proof else {
            unreachable!();
        };
        proof.final_activation_digest[0] ^= 1;
        let preverifier = node.block_preverifier.clone();
        let remote = Arc::clone(&preverifier.remote_admission);

        for value in 1..=9 {
            let peer = RemoteProofPeerId::new(value).unwrap();
            let remote_permit = preverifier.reserve_remote(peer).unwrap();
            let proof_permit = preverifier.reserve().unwrap();
            let result = proof_permit.preverify(&invalid);
            assert!(matches!(result, Err(NodeError::Pow(PowError::V2(_)))));
            assert!(matches!(
                finalize_proof_attempt(Some(remote_permit), Some(proof_permit), result),
                Err(NodeError::Pow(PowError::V2(_)))
            ));
        }
        let priority_permit = preverifier.reserve_priority().unwrap();
        let priority_result = priority_permit.preverify(&invalid);
        assert!(matches!(
            finalize_proof_attempt(None, Some(priority_permit), priority_result),
            Err(NodeError::Pow(PowError::V2(_)))
        ));
        assert_eq!(preverifier.worker_dispatches.load(Ordering::Relaxed), 10);
        assert_eq!(remote.telemetry().unwrap().proof_failures, 9);
        assert_eq!(
            preverifier.queue.telemetry().unwrap().normal.proof_failures,
            9
        );
        assert_eq!(
            preverifier
                .queue
                .telemetry()
                .unwrap()
                .priority
                .proof_failures,
            1
        );
        assert_eq!(remote.state.lock().unwrap().cooldowns.len(), 9);

        assert!(matches!(
            remote.acquire(RemoteProofPeerId::new(1).unwrap()),
            Err(NodeError::ProofVerificationQueueFull)
        ));
        assert_eq!(
            preverifier.worker_dispatches.load(Ordering::Relaxed),
            10,
            "the first live session must remain cooled without a second dispatch"
        );
        assert_eq!(remote.telemetry().unwrap().rejections, 1);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn dispatched_worker_error_records_proof_telemetry_and_peer_cooldown() {
        let path = test_dir("dispatched-worker-error-classification");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let preverifier = node.block_preverifier.clone();
        let remote = Arc::clone(&preverifier.remote_admission);
        let peer = RemoteProofPeerId::new(1).unwrap();
        let remote_permit = preverifier.reserve_remote(peer).unwrap();
        let proof_permit = preverifier.reserve().unwrap();
        let classified =
            NodeError::ProofVerifierWorker(VerifierWorkerError::DispatchedRequest(Box::new(
                VerifierWorkerError::Process(ProofWorkerError::Timeout { milliseconds: 7 }),
            )));

        assert!(matches!(
            finalize_proof_attempt::<()>(Some(remote_permit), Some(proof_permit), Err(classified),),
            Err(NodeError::ProofVerifierWorker(
                VerifierWorkerError::DispatchedRequest(_)
            ))
        ));
        assert_eq!(remote.telemetry().unwrap().proof_failures, 1);
        assert_eq!(
            preverifier.queue.telemetry().unwrap().normal.proof_failures,
            1
        );
        assert!(remote.state.lock().unwrap().cooldowns.contains_key(&peer));
        assert!(matches!(
            remote.acquire(peer),
            Err(NodeError::ProofVerificationQueueFull)
        ));
        assert_eq!(remote.telemetry().unwrap().rejections, 1);

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn remote_deadline_during_proof_prevents_durable_acceptance() {
        let path = test_dir("remote-deadline-before-append");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_candidate(&node, accepted_at);
        let block_id = block.block_id();
        node.block_preverifier
            .set_proof_dispatch_delay(Some(Duration::from_millis(250)));
        let shared = Arc::new(Mutex::new(node));

        let result = submit_shared_peer_block_cancellable(
            &shared,
            block.clone(),
            accepted_at,
            RemoteProofPeerId::new(1).unwrap(),
            RemoteProofRequest::new(
                Instant::now()
                    .checked_add(Duration::from_millis(100))
                    .unwrap(),
            ),
        );
        assert!(matches!(
            result,
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        {
            let node = shared.lock().unwrap();
            assert_eq!(node.peer_hello().height, 0);
            assert!(!node.contains_block(block_id));
            node.block_preverifier.set_proof_dispatch_delay(None);
        }

        // The timed-out request never appended or cached acceptance: the same
        // honest candidate remains admissible under a fresh live request.
        submit_shared_peer_block_cancellable(
            &shared,
            block,
            accepted_at,
            RemoteProofPeerId::new(2).unwrap(),
            RemoteProofRequest::new(Instant::now().checked_add(Duration::from_secs(2)).unwrap()),
        )
        .unwrap();
        assert_eq!(shared.lock().unwrap().peer_hello().height, 1);

        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn cancellation_wins_atomic_commit_race_without_log_or_height_mutation() {
        let path = test_dir("remote-cancel-wins-commit-race");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_candidate(&node, accepted_at);
        let block_id = block.block_id();
        let log_len = node.log.metadata().unwrap().len();
        let barrier = Arc::new(CommitRaceBarrier::new(CommitPausePoint::AfterDeadlineCheck));
        node.commit_race_barrier = Some(Arc::clone(&barrier));
        let shared = Arc::new(Mutex::new(node));
        let request =
            RemoteProofRequest::new(Instant::now().checked_add(Duration::from_secs(2)).unwrap());
        let submitted_request = request.clone();
        let submitted = Arc::clone(&shared);
        let worker = thread::spawn(move || {
            submit_shared_peer_block_cancellable(
                &submitted,
                block,
                accepted_at,
                RemoteProofPeerId::new(1).unwrap(),
                submitted_request,
            )
        });

        barrier.entered.wait();
        assert!(request.cancel(), "cancellation must win before commit");
        barrier.release.wait();
        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        let node = shared.lock().unwrap();
        assert_eq!(request.state(), RemoteProofRequestState::Cancelled);
        assert_eq!(node.peer_hello().height, 0);
        assert!(!node.contains_block(block_id));
        assert_eq!(node.log.metadata().unwrap().len(), log_len);
        assert!(!node.storage_faulted);
        drop(node);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn deadline_expiring_between_precheck_and_commit_cannot_append() {
        let path = test_dir("remote-deadline-preempts-commit-cas");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_candidate(&node, accepted_at);
        let block_id = block.block_id();
        let log_len = node.log.metadata().unwrap().len();
        let barrier = Arc::new(CommitRaceBarrier::new(CommitPausePoint::AfterDeadlineCheck));
        node.commit_race_barrier = Some(Arc::clone(&barrier));
        let shared = Arc::new(Mutex::new(node));
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(100))
            .unwrap();
        let request = RemoteProofRequest::new(deadline);
        let submitted_request = request.clone();
        let submitted = Arc::clone(&shared);
        let worker = thread::spawn(move || {
            submit_shared_peer_block_cancellable(
                &submitted,
                block,
                accepted_at,
                RemoteProofPeerId::new(1).unwrap(),
                submitted_request,
            )
        });

        barrier.entered.wait();
        while Instant::now() < deadline {
            thread::yield_now();
        }
        barrier.release.wait();
        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        let node = shared.lock().unwrap();
        assert_eq!(request.state(), RemoteProofRequestState::Cancelled);
        assert_eq!(node.peer_hello().height, 0);
        assert!(!node.contains_block(block_id));
        assert_eq!(node.log.metadata().unwrap().len(), log_len);
        assert!(!node.storage_faulted);
        drop(node);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn committing_wins_atomic_cancel_race_and_completes_durably() {
        let path = test_dir("remote-commit-wins-cancel-race");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_candidate(&node, accepted_at);
        let block_id = block.block_id();
        let log_len = node.log.metadata().unwrap().len();
        let barrier = Arc::new(CommitRaceBarrier::new(CommitPausePoint::AfterTransition));
        node.commit_race_barrier = Some(Arc::clone(&barrier));
        let shared = Arc::new(Mutex::new(node));
        let request =
            RemoteProofRequest::new(Instant::now().checked_add(Duration::from_secs(2)).unwrap());
        let submitted_request = request.clone();
        let submitted = Arc::clone(&shared);
        let worker = thread::spawn(move || {
            submit_shared_peer_block_cancellable(
                &submitted,
                block,
                accepted_at,
                RemoteProofPeerId::new(1).unwrap(),
                submitted_request,
            )
        });

        barrier.entered.wait();
        assert!(!request.cancel(), "committing must be a point of no return");
        barrier.release.wait();
        worker.join().unwrap().unwrap();
        let node = shared.lock().unwrap();
        assert_eq!(request.state(), RemoteProofRequestState::Completed);
        assert_eq!(node.peer_hello().height, 1);
        assert!(node.contains_block(block_id));
        assert!(node.log.metadata().unwrap().len() > log_len);
        assert!(!node.storage_faulted);
        drop(node);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn committing_io_failure_latches_storage_fault_instead_of_ordinary_retry() {
        let path = test_dir("remote-commit-faults-after-linearization");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_candidate(&node, accepted_at);
        let block_id = block.block_id();
        let log_path = path.join(BLOCK_LOG_FILE);
        let log_len = node.log.metadata().unwrap().len();
        let read_only = OpenOptions::new().read(true).open(&log_path).unwrap();
        drop(std::mem::replace(&mut node.log, read_only));
        let barrier = Arc::new(CommitRaceBarrier::new(CommitPausePoint::AfterTransition));
        node.commit_race_barrier = Some(Arc::clone(&barrier));
        let shared = Arc::new(Mutex::new(node));
        let request =
            RemoteProofRequest::new(Instant::now().checked_add(Duration::from_secs(2)).unwrap());
        let submitted_request = request.clone();
        let submitted = Arc::clone(&shared);
        let worker = thread::spawn(move || {
            submit_shared_peer_block_cancellable(
                &submitted,
                block,
                accepted_at,
                RemoteProofPeerId::new(1).unwrap(),
                submitted_request,
            )
        });

        barrier.entered.wait();
        assert!(
            !request.cancel(),
            "committing must reject late cancellation"
        );
        barrier.release.wait();
        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeError::Io {
                operation: "append block record",
                ..
            })
        ));
        let node = shared.lock().unwrap();
        assert_eq!(request.state(), RemoteProofRequestState::Faulted);
        assert_eq!(node.peer_hello().height, 0);
        assert!(!node.contains_block(block_id));
        assert_eq!(fs::metadata(log_path).unwrap().len(), log_len);
        assert!(node.storage_faulted);
        drop(node);
        drop(shared);
        clean_test_dir(&path);
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
            production_v3_record: None,
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
    fn replay_capability_cache_is_exact_generation_bound_and_preserves_body_checks() {
        let path = test_dir("replay-capability-cache-authority");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let now = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_candidate(&node, now);
        let verifier = node.block_preverifier.clone();
        let capability = verifier.preverify_replay_cached(&block).unwrap();
        assert_eq!(verifier.worker_dispatches.load(Ordering::Relaxed), 1);
        assert_eq!(
            verifier.preverify_replay_cached(&block).unwrap(),
            capability
        );
        assert_eq!(verifier.worker_dispatches.load(Ordering::Relaxed), 1);

        let mut changed_proof = block.clone();
        let BlockProof::V2Reference(proof) = &mut changed_proof.proof else {
            unreachable!();
        };
        proof.work_digest[0] ^= 1;
        assert!(verifier.preverify_replay_cached(&changed_proof).is_err());
        assert_eq!(verifier.worker_dispatches.load(Ordering::Relaxed), 2);
        assert!(
            verifier
                .cached_preverification(canonical_block_cache_digest(&changed_proof).unwrap())
                .unwrap()
                .is_none()
        );

        let mut changed_body = block.clone();
        changed_body.coinbase.outputs[0].value += 1;
        assert_ne!(
            canonical_block_cache_digest(&changed_body).unwrap(),
            canonical_block_cache_digest(&block).unwrap()
        );
        assert!(
            node.state
                .validate_block_preverified(
                    &changed_body,
                    BlockValidationContext {
                        now_unix_seconds: now
                    },
                    &capability,
                )
                .is_err(),
            "a proof capability must never authorize changed transaction/coinbase state"
        );

        // Even if stale entries remain present, a new backend generation must
        // really verify again before issuing reusable evidence for that epoch.
        verifier.backend_generation.fetch_add(1, Ordering::AcqRel);
        verifier.preverify_replay_cached(&block).unwrap();
        assert_eq!(verifier.worker_dispatches.load(Ordering::Relaxed), 3);
        verifier.shutdown();
        assert!(matches!(
            verifier.preverify_replay_cached(&block),
            Err(NodeError::ProofVerifierShuttingDown)
        ));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn cached_proof_waits_for_remote_admission_without_redispatch() {
        let path = test_dir("proof-capability-cache-remote-admission");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let block = mined_candidate(&node, accepted_at);
        let key = canonical_block_cache_digest(&block).unwrap();
        let verifier = node.block_preverifier.clone();
        let capability = verifier.preverify(&block).unwrap();
        let generation = verifier.backend_generation.load(Ordering::Acquire);
        verifier
            .remember_preverification(key, generation, capability.clone())
            .unwrap();
        assert_eq!(verifier.worker_dispatches.load(Ordering::Relaxed), 1);

        let remote = Arc::clone(&verifier.remote_admission);
        let blocker = remote.acquire(RemoteProofPeerId::new(1).unwrap()).unwrap();
        let waiting_verifier = verifier.clone();
        let (result_tx, result_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            result_tx
                .send(begin_proof_attempt(
                    &waiting_verifier,
                    true,
                    Some(RemoteProofPeerId::new(2).unwrap()),
                    None,
                    key,
                ))
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while remote.telemetry().unwrap().queued != 1 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(remote.telemetry().unwrap().queued, 1);
        assert!(matches!(
            result_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert_eq!(
            verifier.worker_dispatches.load(Ordering::Relaxed),
            1,
            "a seeded cache must not bypass saturated remote admission"
        );

        drop(blocker);
        let attempt = result_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(attempt.cached, Some(capability.clone()));
        let cached =
            finalize_proof_attempt(attempt.remote_permit, None, Ok(attempt.cached.unwrap()))
                .unwrap();
        assert_eq!(cached, capability);
        waiter.join().unwrap();

        assert_eq!(verifier.worker_dispatches.load(Ordering::Relaxed), 1);
        let telemetry = remote.telemetry().unwrap();
        assert_eq!(telemetry.active, 0);
        assert_eq!(telemetry.queued, 0);
        assert_eq!(telemetry.wait_events, 1);
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
    fn production_v4_shared_submission_rejects_bad_headers_before_proof_dispatch() {
        let path = test_dir("production-v4-preflight-order");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let now = DEVNET_GENESIS_TIMESTAMP + 60;
        let valid = mined_candidate(&node, now);
        node.profile.proof = ProofProfile::ProductionV4;
        *node.block_preverifier.backend.write().unwrap() = ProofVerificationBackend::Unavailable;
        let shared = Arc::new(Mutex::new(node));

        let mut wrong_version = valid.clone();
        wrong_version.version = u32::MAX;
        assert!(matches!(
            submit_shared_block(&shared, wrong_version, now),
            Err(NodeError::Chain(ChainError::UnsupportedBlockVersion))
        ));

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

        let mut wrong_root = valid.clone();
        wrong_root.challenge.transaction_root[0] ^= 1;
        assert!(matches!(
            submit_shared_block(&shared, wrong_root, now),
            Err(NodeError::Chain(ChainError::MerkleRoot))
        ));

        let node = shared.lock().unwrap();
        assert_eq!(
            node.block_preverifier
                .worker_dispatches
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(node.state.next_height(), 1);
        assert_eq!(node.log.metadata().unwrap().len(), 0);
        drop(node);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn production_v4_side_branch_replay_completes_without_node_mutex() {
        let path = test_dir("production-v4-side-replay");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
        let t2 = t1 + 60;
        let a1 = mined_child(&node, genesis, t1, 0x31);
        node.submit_block(a1.clone(), t1).unwrap();
        let a2 = mined_child(&node, a1.block_id(), t2, 0x32);
        node.submit_block(a2, t2).unwrap();
        let b1 = mined_child(&node, genesis, t1, 0x41);
        node.submit_block(b1.clone(), t1).unwrap();
        let b2 = mined_child(&node, b1.block_id(), t2, 0x42);

        node.profile.proof = ProofProfile::ProductionV4;
        let work = node
            .begin_external_block_admission(&b2, t2)
            .unwrap()
            .expect("V4 side branches need an out-of-lock replay plan");
        assert!(work.requires_reconstruction());
        let submitted = b2.clone();
        let shared = Arc::new(Mutex::new(node));
        let held_node_guard = shared.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = sender.send(work.complete(&b2));
        });
        let completed = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("V4 side replay waited for the shared node mutex")
            .unwrap();
        assert!(matches!(
            completed,
            ExternalBlockAdmissionProgress::Ready(_)
        ));
        drop(held_node_guard);
        worker.join().unwrap();
        submit_shared_block(&shared, submitted.clone(), t2).unwrap();
        assert!(shared.lock().unwrap().index.contains(submitted.block_id()));
        drop(shared);
        clean_test_dir(&path);
    }

    fn branch_checkpoint_fixture(label: &str, height: u64) -> (Node, PathBuf, Vec<Block>) {
        let path = test_dir(label);
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let mut blocks = Vec::new();
        let mut parent = node.params.genesis_hash;
        for height in 1..=height {
            let now = DEVNET_GENESIS_TIMESTAMP + height * 60;
            let block = mined_child(&node, parent, now, height as u8);
            parent = block.block_id();
            node.submit_block(block.clone(), now).unwrap();
            blocks.push(block);
        }
        node.profile.proof = ProofProfile::ProductionV4;
        (node, path, blocks)
    }

    #[test]
    fn fork_replay_slice_verifies_proofs_concurrently_and_once() {
        let (mut node, path, blocks) = branch_checkpoint_fixture("parallel-replay-proofs", 20);
        let now = DEVNET_GENESIS_TIMESTAMP + 20 * 60;
        let candidate = mined_child(&node, blocks[18].block_id(), now, 0xee);
        let verifier = node.block_preverifier.clone();
        let delay = Duration::from_millis(200);
        verifier.set_proof_dispatch_delay(Some(delay));
        let dispatches_before = verifier.worker_dispatches.load(Ordering::Relaxed);
        let started = Instant::now();
        let progress = node
            .begin_external_block_admission(&candidate, now)
            .unwrap()
            .unwrap()
            .complete(&candidate)
            .unwrap();
        let elapsed = started.elapsed();
        verifier.set_proof_dispatch_delay(None);
        assert!(matches!(
            progress,
            ExternalBlockAdmissionProgress::Checkpoint { .. }
        ));
        assert_eq!(verifier.replay_state_blocks.load(Ordering::Relaxed), 8);
        // Every replayed proof is still checked exactly once.
        assert_eq!(
            verifier.worker_dispatches.load(Ordering::Relaxed) - dispatches_before,
            8
        );
        if thread::available_parallelism().map_or(1, usize::from) >= 2 {
            assert!(
                elapsed < delay * 6,
                "eight replay proofs ran serially: {elapsed:?}"
            );
        }
        drop(progress);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn branch_checkpoint_survives_cancelled_progress_and_queue_failure() {
        let (mut node, path, blocks) = branch_checkpoint_fixture("checkpoint-cancellation", 20);
        let now = DEVNET_GENESIS_TIMESTAMP + 20 * 60;
        let candidate = mined_child(&node, blocks[18].block_id(), now, 0xee);
        let verifier = node.block_preverifier.clone();
        let first = node
            .begin_external_block_admission(&candidate, now)
            .unwrap()
            .unwrap()
            .complete(&candidate)
            .unwrap();
        assert_eq!(verifier.replay_state_blocks.load(Ordering::Relaxed), 8);
        let shared = Arc::new(Mutex::new(node));
        let request = RemoteProofRequest::new(Instant::now() + Duration::from_secs(30));
        let result = {
            let _pending = PendingExternalAdmission {
                shared: shared.clone(),
                progress: Some(first),
            };
            assert!(request.cancel());
            request.ensure_live()
        };
        assert!(result.is_err());
        assert!(!shared.lock().unwrap().index.contains(candidate.block_id()));
        assert_eq!(shared.lock().unwrap().branch_checkpoints.entries.len(), 1);

        // A reservation failure after checkout must put its completed base back.
        let work = shared
            .lock()
            .unwrap()
            .begin_external_block_admission(&candidate, now)
            .unwrap()
            .unwrap();
        // An active-chain checkpoint stays cached while a copy is in use.
        assert_eq!(shared.lock().unwrap().branch_checkpoints.entries.len(), 1);
        let blocked = Arc::new(ProofVerificationQueue::new(1, 0, Duration::from_millis(1)));
        let _held = blocked.acquire().unwrap();
        {
            let _pending = PendingExternalWork {
                shared: shared.clone(),
                work: Some(work),
            };
            assert!(blocked.acquire().is_err());
        }
        assert_eq!(shared.lock().unwrap().branch_checkpoints.entries.len(), 1);

        // Exercise the production admission wiring, not just the drop helper.
        let blocked_queue = Arc::new(ProofVerificationQueue::new(1, 0, Duration::from_millis(1)));
        shared
            .lock()
            .unwrap()
            .block_preverifier
            .reconstruction_queue = blocked_queue.clone();
        let held = blocked_queue.acquire().unwrap();
        assert!(submit_shared_block(&shared, candidate.clone(), now).is_err());
        assert_eq!(shared.lock().unwrap().branch_checkpoints.entries.len(), 1);
        assert!(!shared.lock().unwrap().index.contains(candidate.block_id()));
        drop(held);

        // Every completed slice can survive a later canceled request, including
        // Ready's parent state (its path must not retain the candidate ID).
        loop {
            let work = shared
                .lock()
                .unwrap()
                .begin_external_block_admission(&candidate, now)
                .unwrap()
                .unwrap();
            let progress = work.complete(&candidate).unwrap();
            let ready = matches!(progress, ExternalBlockAdmissionProgress::Ready(_));
            drop(PendingExternalAdmission {
                shared: shared.clone(),
                progress: Some(progress),
            });
            if ready {
                break;
            }
        }
        assert_eq!(verifier.replay_state_blocks.load(Ordering::Relaxed), 19);
        {
            let node = shared.lock().unwrap();
            let checkpoint = &node.branch_checkpoints.entries.back().unwrap().checkpoint;
            assert_eq!(checkpoint.block_id, blocks[18].block_id());
            assert_eq!(checkpoint.path.last(), Some(&blocks[18].block_id()));
            assert!(!node.index.contains(candidate.block_id()));
        }
        submit_shared_block(&shared, candidate.clone(), now).unwrap();
        assert_eq!(verifier.replay_state_blocks.load(Ordering::Relaxed), 19);
        assert!(shared.lock().unwrap().index.contains(candidate.block_id()));
        assert!(
            shared
                .lock()
                .unwrap()
                .branch_checkpoints
                .entries
                .iter()
                .any(|entry| entry.checkpoint.block_id == candidate.block_id())
        );
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn branch_checkpoint_identity_generation_and_shutdown_are_fail_closed() {
        let (mut node, path, blocks) = branch_checkpoint_fixture("checkpoint-identity", 4);
        node.remember_active_branch_checkpoint(true);
        let mut checkpoint = node
            .take_branch_checkpoint(blocks[3].block_id())
            .unwrap()
            .unwrap();
        // Active anchors stay cached on checkout; clear them so each check
        // below observes only whether the tampered copy is accepted.
        assert!(node.branch_checkpoints.charged_bytes > 0);
        node.branch_checkpoints = BranchCheckpointCache::default();
        checkpoint.context.node_instance_id ^= 1;
        node.remember_branch_checkpoint(checkpoint);
        assert!(node.branch_checkpoints.entries.is_empty());
        node.remember_active_branch_checkpoint(true);
        let mut checkpoint = node
            .take_branch_checkpoint(blocks[3].block_id())
            .unwrap()
            .unwrap();
        node.branch_checkpoints = BranchCheckpointCache::default();
        checkpoint.context.network_id[0] ^= 1;
        node.remember_branch_checkpoint(checkpoint);
        assert!(node.branch_checkpoints.entries.is_empty());
        node.remember_active_branch_checkpoint(true);
        let mut checkpoint = node
            .take_branch_checkpoint(blocks[3].block_id())
            .unwrap()
            .unwrap();
        node.branch_checkpoints = BranchCheckpointCache::default();
        checkpoint.path[0][0] ^= 1;
        node.remember_branch_checkpoint(checkpoint);
        assert!(node.branch_checkpoints.entries.is_empty());
        node.remember_active_branch_checkpoint(true);
        node.block_preverifier
            .backend_generation
            .fetch_add(1, Ordering::AcqRel);
        assert!(
            node.take_branch_checkpoint(blocks[3].block_id())
                .unwrap()
                .is_none()
        );
        assert_eq!(node.branch_checkpoints.charged_bytes, 0);
        node.remember_active_branch_checkpoint(true);
        node.shutdown_proof_verifier();
        assert!(matches!(
            node.take_branch_checkpoint(blocks[3].block_id()),
            Err(NodeError::ProofVerifierShuttingDown)
        ));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn branch_checkpoint_anchor_corruption_faults_storage() {
        let (mut node, path, blocks) = branch_checkpoint_fixture("checkpoint-anchor-corrupt", 4);
        node.remember_active_branch_checkpoint(true);
        let mut anchor = node.index.blocks[&blocks[3].block_id()].locator;
        anchor.complete_digest[0] ^= 1;
        set_indexed_locator(&mut node, blocks[3].block_id(), anchor);
        node.branch_checkpoints.entries[0].anchor = anchor;
        assert!(node.take_branch_checkpoint(blocks[3].block_id()).is_err());
        assert!(node.storage_faulted);
        drop(node);
        clean_test_dir(&path);
    }

    #[cfg(unix)]
    #[test]
    fn branch_checkpoint_authenticates_same_length_disk_corruption() {
        let (mut node, path, blocks) = branch_checkpoint_fixture("checkpoint-disk-corrupt", 4);
        node.remember_active_branch_checkpoint(true);
        let anchor = node.index.blocks[&blocks[3].block_id()].locator;
        let mut bytes = fs::read(path.join(BLOCK_LOG_FILE)).unwrap();
        bytes[usize::try_from(anchor.offset).unwrap() + 64] ^= 1;
        fs::write(path.join(BLOCK_LOG_FILE), bytes).unwrap();
        assert!(node.take_branch_checkpoint(blocks[3].block_id()).is_err());
        assert!(node.storage_faulted);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn branch_checkpoint_cache_budget_and_eviction_are_bounded() {
        let (mut node, path, _) = branch_checkpoint_fixture("checkpoint-budget", 4);
        assert!(checkpoint_charge(&node.state, usize::MAX).is_none());
        node.remember_active_branch_checkpoint(true);
        let mut oversized = node
            .take_branch_checkpoint(node.state.tip())
            .unwrap()
            .unwrap();
        node.branch_checkpoints = BranchCheckpointCache::default();
        let mut oversized_path = Vec::with_capacity(MAX_BRANCH_STATE_CHECKPOINT_BYTES / 32 + 1);
        oversized_path.extend_from_slice(&oversized.path);
        oversized.path = oversized_path;
        node.remember_branch_checkpoint(oversized);
        assert!(node.branch_checkpoints.entries.is_empty());
        for height in 5..=12 {
            let now = DEVNET_GENESIS_TIMESTAMP + height * 60;
            let block = mined_child(&node, node.state.tip(), now, height as u8);
            node.submit_block(block, now).unwrap();
            node.remember_active_branch_checkpoint(true);
            assert!(node.branch_checkpoints.entries.len() <= MAX_BRANCH_STATE_CHECKPOINTS);
            assert!(node.branch_checkpoints.charged_bytes <= MAX_BRANCH_STATE_CHECKPOINT_BYTES);
            assert_eq!(
                node.branch_checkpoints.charged_bytes,
                node.branch_checkpoints
                    .entries
                    .iter()
                    .map(|entry| entry.charge)
                    .sum::<usize>()
            );
        }
        assert_eq!(
            node.branch_checkpoints.entries.len(),
            MAX_BRANCH_STATE_CHECKPOINTS
        );
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn branch_checkpoint_recent_active_anchor_bounds_short_fork_replay() {
        let (mut node, path, _) = branch_checkpoint_fixture("checkpoint-recent-active", 0);
        let mut parent = node.params.genesis_hash;
        let mut fork_parent = parent;
        for height in 1..=64 {
            let now = DEVNET_GENESIS_TIMESTAMP + height * 60;
            let block = mined_child(&node, parent, now, height as u8);
            parent = block.block_id();
            if height == 63 {
                fork_parent = parent;
            }
            node.submit_block(block, now).unwrap();
        }
        let now = DEVNET_GENESIS_TIMESTAMP + 64 * 60;
        let candidate = mined_child(&node, fork_parent, now, 0xf1);
        let verifier = node.block_preverifier.clone();
        let shared = Arc::new(Mutex::new(node));
        submit_shared_block(&shared, candidate.clone(), now).unwrap();
        assert_eq!(verifier.replay_state_blocks.load(Ordering::Relaxed), 15);
        assert!(shared.lock().unwrap().index.contains(candidate.block_id()));
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn active_anchor_survives_an_abandoned_short_fork_attempt() {
        let (mut node, path, _) = branch_checkpoint_fixture("checkpoint-anchor-kept", 0);
        let mut parent = node.params.genesis_hash;
        let mut fork_parent = parent;
        for height in 1..=64 {
            let now = DEVNET_GENESIS_TIMESTAMP + height * 60;
            let block = mined_child(&node, parent, now, height as u8);
            parent = block.block_id();
            if height == 63 {
                fork_parent = parent;
            }
            node.submit_block(block, now).unwrap();
        }
        let now = DEVNET_GENESIS_TIMESTAMP + 64 * 60;
        let candidate = mined_child(&node, fork_parent, now, 0xf1);
        // An attempt checks out the nearest anchor and is then abandoned
        // without returning anything to the cache.
        let abandoned = node
            .begin_external_block_admission(&candidate, now)
            .unwrap()
            .unwrap();
        drop(abandoned);
        let verifier = node.block_preverifier.clone();
        let before = verifier.replay_state_blocks.load(Ordering::Relaxed);
        let shared = Arc::new(Mutex::new(node));
        submit_shared_block(&shared, candidate.clone(), now).unwrap();
        // The retry still starts from the same anchor instead of genesis.
        assert_eq!(
            verifier.replay_state_blocks.load(Ordering::Relaxed) - before,
            15
        );
        assert!(shared.lock().unwrap().index.contains(candidate.block_id()));
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn branch_checkpoint_never_authorizes_an_invalid_candidate_body() {
        let (node, path, _) = branch_checkpoint_fixture("checkpoint-invalid-body", 3);
        let first_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let second_at = first_at + 60;
        let first = mined_child(&node, node.params.genesis_hash, first_at, 0xd1);
        let shared = Arc::new(Mutex::new(node));
        submit_shared_block(&shared, first.clone(), first_at).unwrap();
        let valid = {
            let node = shared.lock().unwrap();
            assert!(
                node.branch_checkpoints
                    .entries
                    .iter()
                    .any(|entry| entry.checkpoint.block_id == first.block_id())
            );
            mined_child(&node, first.block_id(), second_at, 0xd2)
        };
        let mut invalid = valid.clone();
        invalid.coinbase.outputs[0].value += 1;
        let before = shared
            .lock()
            .unwrap()
            .state
            .encode_local_snapshot()
            .unwrap();
        assert!(submit_shared_block(&shared, invalid, second_at).is_err());
        {
            let node = shared.lock().unwrap();
            assert_eq!(node.state.encode_local_snapshot().unwrap(), before);
            assert!(!node.index.contains(valid.block_id()));
            assert!(!node.storage_faulted);
        }
        submit_shared_block(&shared, valid.clone(), second_at).unwrap();
        assert!(shared.lock().unwrap().index.contains(valid.block_id()));
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn replay_capability_cache_reuses_completed_slices_and_verifies_new_candidate() {
        let path = test_dir("replay-capability-cache-retry");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let slice = MAX_EXTERNAL_RECONSTRUCTION_BLOCKS_PER_SLICE as u64;
        let mut parent = node.params.genesis_hash;
        let mut fork_parent = parent;
        for height in 1..=slice + 2 {
            let now = DEVNET_GENESIS_TIMESTAMP + height * 60;
            let block = mined_child(&node, parent, now, height as u8);
            node.submit_block(block.clone(), now).unwrap();
            parent = block.block_id();
            if height == slice + 1 {
                fork_parent = parent;
            }
        }
        let now = DEVNET_GENESIS_TIMESTAMP + (slice + 2) * 60;
        let candidate = mined_child(&node, fork_parent, now, 0xE1);
        node.profile.proof = ProofProfile::ProductionV4;
        let verifier = node.block_preverifier.clone();
        let initial_dispatches = verifier.worker_dispatches.load(Ordering::Relaxed);

        // A canceled request drops its work-local state, but successful proof
        // evidence from its completed slice must survive for the next request.
        let first = node
            .begin_external_block_admission(&candidate, now)
            .unwrap()
            .unwrap()
            .complete(&candidate)
            .unwrap();
        assert!(matches!(
            first,
            ExternalBlockAdmissionProgress::Checkpoint { .. }
        ));
        drop(first);
        assert_eq!(
            verifier.worker_dispatches.load(Ordering::Relaxed),
            initial_dispatches + slice
        );

        let retry = node
            .begin_external_block_admission(&candidate, now)
            .unwrap()
            .unwrap()
            .complete(&candidate)
            .unwrap();
        let ExternalBlockAdmissionProgress::Checkpoint { checkpoint } = retry else {
            panic!("retry should still need its final ancestor slice");
        };
        assert_eq!(
            verifier.worker_dispatches.load(Ordering::Relaxed),
            initial_dispatches + slice,
            "retry must not redispatch successfully verified ancestors"
        );
        let completed = node
            .continue_external_block_admission(&candidate, now, checkpoint)
            .unwrap()
            .complete(&candidate)
            .unwrap();
        assert!(matches!(
            completed,
            ExternalBlockAdmissionProgress::Ready(_)
        ));
        drop(completed);
        assert_eq!(
            verifier.worker_dispatches.load(Ordering::Relaxed),
            initial_dispatches + slice + 1
        );

        let shared = Arc::new(Mutex::new(node));
        submit_shared_block(&shared, candidate.clone(), now).unwrap();
        assert_eq!(
            verifier.worker_dispatches.load(Ordering::Relaxed),
            initial_dispatches + slice + 2,
            "only the new candidate should need another real verification"
        );
        assert!(shared.lock().unwrap().index.contains(candidate.block_id()));
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

        // A warm proof cache must not bypass the durable record authentication
        // performed before any replay capability is consulted.
        node.profile.proof = ProofProfile::ProductionV3;
        drop(
            node.begin_external_block_admission(&child, t2)
                .unwrap()
                .unwrap()
                .complete(&child)
                .unwrap(),
        );
        assert!(
            node.block_preverifier
                .cached_preverification(canonical_block_cache_digest(&side).unwrap())
                .unwrap()
                .is_some()
        );
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

        node.block_preverifier
            .preverify_replay_cached(&side)
            .unwrap();
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
    fn cancellation_during_corrupt_side_replay_still_latches_storage_fault() {
        let path = test_dir("production-side-corruption-cancelled");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
        let t2 = t1 + 60;

        let active = mined_child(&node, genesis, t1, 0x81);
        node.submit_block(active, t1).unwrap();
        let side = mined_child(&node, genesis, t1, 0x82);
        let side_cap = node.block_preverifier.preverify(&side).unwrap();
        node.submit_preverified_block(side.clone(), t1, side_cap)
            .unwrap();
        let child = mined_child(&node, side.block_id(), t2, 0x83);
        let child_id = child.block_id();

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
        Arc::get_mut(node.index.blocks.get_mut(&side.block_id()).unwrap())
            .unwrap()
            .successor_header = forged_header;

        let original_tip = node.state.tip();
        let original_revision = node.chain_revision;
        let original_log_length = node.log.metadata().unwrap().len();
        let barrier = Arc::new(CompletionFaultBarrier::new());
        node.profile.proof = ProofProfile::ProductionV3;
        node.completion_fault_barrier = Some(Arc::clone(&barrier));
        let shared = Arc::new(Mutex::new(node));
        let request =
            RemoteProofRequest::new(Instant::now().checked_add(Duration::from_secs(60)).unwrap());
        let submitted_request = request.clone();
        let submitted = Arc::clone(&shared);
        let worker = thread::spawn(move || {
            submit_shared_peer_block_cancellable(
                &submitted,
                child,
                t2,
                RemoteProofPeerId::new(1).unwrap(),
                submitted_request,
            )
        });

        barrier.entered.wait();
        assert!(
            request.cancel(),
            "request must cancel during corrupt replay"
        );
        barrier.release.wait();
        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeError::CorruptLog(message))
                if message.contains("header snapshot does not match replayed state")
        ));

        let node = shared.lock().unwrap();
        assert_eq!(request.state(), RemoteProofRequestState::Cancelled);
        assert!(node.storage_faulted);
        assert_eq!(node.state.tip(), original_tip);
        assert_eq!(node.chain_revision, original_revision);
        assert!(!node.contains_block(child_id));
        assert_eq!(node.log.metadata().unwrap().len(), original_log_length);
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

    pub(super) fn mined_child(
        node: &Node,
        parent: [u8; 32],
        timestamp: u64,
        miner_seed: u8,
    ) -> Block {
        mined_child_with_transactions(node, parent, timestamp, miner_seed, Vec::new())
    }

    pub(super) fn mined_child_with_transactions(
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

    pub(super) fn spend_coinbase_output(
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
    fn transaction_confirmation_lookup_resumes_from_its_scan_mark() {
        let path = test_dir("transaction-scan-marks");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let now = DEVNET_GENESIS_TIMESTAMP + 60;
        let funding = node
            .mine_once(default_miner_destination(), now, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let transaction = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 10);
        let txid = transaction.txid();
        let absent = [0xab; 32];
        let txids = HashSet::from([txid, absent]);
        let fresh = |node: &mut Node| {
            node.transaction_scan_marks.clear();
            node.active_transaction_confirmations_for(&txids).unwrap()
        };

        assert!(
            node.active_transaction_confirmations_for(&txids)
                .unwrap()
                .is_empty()
        );
        node.submit_transaction(transaction).unwrap();
        node.mine_once(
            default_miner_destination(),
            now + 1,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        // The absent mark resumes above its scanned height and finds the new block.
        let resumed = node.active_transaction_confirmations_for(&txids).unwrap();
        assert_eq!(resumed, HashMap::from([(txid, 1)]));
        for offset in 2..4 {
            node.mine_once(
                default_miner_destination(),
                now + offset,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
        let cached = node.active_transaction_confirmations_for(&txids).unwrap();
        assert_eq!(cached, HashMap::from([(txid, 3)]));
        assert_eq!(cached, fresh(&mut node));
        drop(node);
        clean_test_dir(&path);
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
    fn exchange_withdrawal_reorg_rebroadcasts_the_exact_signed_transaction() {
        use crate::exchange_withdrawal::{
            ExchangeWithdrawalJournal, WithdrawalRequest, WithdrawalStatus, encode_external_anchor,
        };

        let path = test_dir("exchange-withdrawal-reorg");
        let security_path = path.with_extension("withdrawal-security");
        clean_test_dir(&path);
        let _ = fs::remove_dir_all(&security_path);
        fs::create_dir_all(&security_path).unwrap();
        let journal_key_path = security_path.join("journal.key");
        fs::write(&journal_key_path, [0x5a_u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&journal_key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let security = ExchangeWithdrawalSecurityConfig::new(
            journal_key_path,
            security_path.join("journal.anchor"),
        );
        let mut node = Node::open_with_profile_and_exchange_withdrawal_security(
            &path,
            DEVNET_PROFILE,
            &security,
        )
        .unwrap();
        let destination = node.wallet_destination();
        for height in 1..=100 {
            node.mine_once(
                destination,
                DEVNET_GENESIS_TIMESTAMP + height * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
        let fork_parent = node.state.tip();
        let shared = Arc::new(Mutex::new(node));
        let mut journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        let bootstrap_anchor = journal.journal_info().unwrap().current_anchor;
        fs::write(
            security.anchor_file(),
            encode_external_anchor(&bootstrap_anchor).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(security.anchor_file(), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let request = WithdrawalRequest {
            request_id: "reorg-withdrawal-1".to_owned(),
            destination,
            amount_atoms: 1,
            fee_atoms: 1,
        };
        let prepared = journal.prepare(&shared, &request).unwrap();
        assert_eq!(prepared.status, WithdrawalStatus::Prepared);
        fs::write(
            security.anchor_file(),
            encode_external_anchor(&prepared.prepared_anchor.unwrap()).unwrap(),
        )
        .unwrap();
        let submitted = journal.release(&shared, &request.request_id).unwrap();
        assert_eq!(submitted.status, WithdrawalStatus::InMempool);
        let txid = submitted.txid.unwrap();
        let transaction_bytes = submitted.transaction_bytes.unwrap();

        shared
            .lock()
            .unwrap()
            .mine_once(
                destination,
                DEVNET_GENESIS_TIMESTAMP + 101 * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let confirmed = journal.get(&shared, &request.request_id).unwrap().unwrap();
        assert_eq!(confirmed.status, WithdrawalStatus::Confirmed);
        assert_eq!(confirmed.confirmations, Some(1));

        {
            let mut node = shared.lock().unwrap();
            let side = mined_child(
                &node,
                fork_parent,
                DEVNET_GENESIS_TIMESTAMP + 101 * 60,
                0x7a,
            );
            node.submit_block(side.clone(), DEVNET_GENESIS_TIMESTAMP + 101 * 60)
                .unwrap();
            let heavier = mined_child(
                &node,
                side.block_id(),
                DEVNET_GENESIS_TIMESTAMP + 102 * 60,
                0x7b,
            );
            node.submit_block(heavier, DEVNET_GENESIS_TIMESTAMP + 102 * 60)
                .unwrap();
        }

        let rebroadcast = journal
            .reconcile_released(&shared)
            .unwrap()
            .into_iter()
            .find(|view| view.request_id == request.request_id)
            .unwrap();
        assert_eq!(rebroadcast.status, WithdrawalStatus::InMempool);
        assert_eq!(rebroadcast.txid, Some(txid));
        assert_eq!(rebroadcast.transaction_bytes, Some(transaction_bytes));

        shared
            .lock()
            .unwrap()
            .mine_once(
                destination,
                DEVNET_GENESIS_TIMESTAMP + 103 * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let reconfirmed = journal.get(&shared, &request.request_id).unwrap().unwrap();
        assert_eq!(reconfirmed.status, WithdrawalStatus::Confirmed);
        assert_eq!(reconfirmed.txid, Some(txid));

        drop(journal);
        drop(shared);
        clean_test_dir(&path);
        fs::remove_dir_all(security_path).unwrap();
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
            kind: NetworkProfileKind::Devnet,
            proof: ProofProfile::DevnetV2Reference,
            name: "CommonFoundry profile-separation test",
            network_id: [0x64; 32],
            virtual_genesis_hash: [0x48; 32],
            virtual_genesis_timestamp: DEVNET_GENESIS_TIMESTAMP + 1,
            pow_limit: DEVNET_PROFILE.pow_limit,
            initial_target: None,
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
        let path = test_dir("rcnet-production-v4-gate");
        clean_test_dir(&path);

        #[cfg(not(feature = "production-v4"))]
        assert!(matches!(
            network_params_for_profile(RCNET1_PROFILE),
            Err(NodeError::ProductionV4Unavailable)
        ));
        #[cfg(feature = "production-v4")]
        assert!(matches!(
            network_params_for_profile(RCNET1_PROFILE),
            Err(NodeError::ProductionV4ArtifactsMissing)
        ));
        #[cfg(not(feature = "production-v4"))]
        assert!(matches!(
            Node::open_with_profile(&path, RCNET1_PROFILE),
            Err(NodeError::ProductionV4Unavailable)
        ));
        #[cfg(feature = "production-v4")]
        assert!(matches!(
            Node::open_with_profile(&path, RCNET1_PROFILE),
            Err(NodeError::ProductionV4ArtifactsMissing)
        ));
        assert!(!path.exists());
    }

    #[cfg(feature = "production-v4")]
    #[test]
    fn rcnet_v4_parameters_bind_the_profile_network_and_reject_testnet_parameters() {
        let parameters = cmfd_consensus::ForgeMatrixV4CandidateParameters::for_network(
            RCNET1_PROFILE.network_id,
        )
        .unwrap();
        let params =
            network_params_from_pow(RCNET1_PROFILE, PowParameters::V4Candidate(parameters))
                .unwrap();
        assert_eq!(params.network_id, RCNET1_PROFILE.network_id);
        assert_eq!(params.pow, PowParameters::V4Candidate(parameters));
        let fingerprint = hex::encode(params.fingerprint().unwrap());
        assert_ne!(fingerprint, hex::encode(RC4_FINGERPRINT));
        assert!(
            include_str!("../../../scripts/release_integrity.py")
                .contains(&format!("\"{fingerprint}\"")),
            "Release verification must pin the RC5 consensus fingerprint: {fingerprint}"
        );

        assert!(matches!(
            network_params_from_pow(
                RCNET1_PROFILE,
                PowParameters::V4Candidate(
                    cmfd_consensus::ForgeMatrixV4CandidateParameters::production_testnet(),
                ),
            ),
            Err(NodeError::Network(_))
        ));
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
        use cmfd_consensus::FileIdentity;

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
            status.proof_verification_remote_admission,
            ProofAdmissionClassTelemetry {
                active: 0,
                queued: 0,
                wait_events: 0,
                rejections: 0,
                proof_failures: 0,
            }
        );
        assert_eq!(
            status.proof_verification_remote_admission_capacity,
            MAX_REMOTE_PROOF_ADMISSIONS
        );
        assert_eq!(
            status.proof_verification_remote_admission_wait_timeout_ms,
            REMOTE_PROOF_ADMISSION_WAIT_TIMEOUT.as_millis() as u64
        );
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
            BlockProof::V4Candidate(proof) => proof.nonce,
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
            BlockProof::V4Candidate(proof) => proof.work_digest[0] ^= 1,
        }
        assert!(job.build_block_if_chain_valid(&mutated_work).is_err());

        let mut mutated_nonce = share_only.proof;
        match &mut mutated_nonce {
            BlockProof::V1Legacy(proof) => proof.nonce = proof.nonce.wrapping_add(1),
            BlockProof::V2Reference(proof) => proof.nonce = proof.nonce.wrapping_add(1),
            BlockProof::V3Candidate(proof) => proof.nonce = proof.nonce.wrapping_add(1),
            BlockProof::V4Candidate(proof) => proof.nonce = proof.nonce.wrapping_add(1),
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
    fn empty_log_uses_zero_chain_root_and_first_append_is_v3() {
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
            RECORD_VERSION_V3
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
            RECORD_VERSION_V3
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
                encode_record_v1(accepted_at, &block_bytes).unwrap()
            } else {
                let previous = complete_record_digest(mixed.last().unwrap());
                encode_record_v2(
                    accepted_at,
                    &block_bytes,
                    &delta_bytes,
                    previous,
                    DEVNET_NETWORK_ID,
                )
                .unwrap()
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
            RECORD_VERSION_V3
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
            u16::from_le_bytes(record[4..6].try_into().unwrap()) == RECORD_VERSION_V3
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

        for expected_snapshot in [true, false] {
            let node = Node::open(&path).unwrap();
            assert_eq!(node.startup_snapshot_used, expected_snapshot);
            assert_eq!(node.state.tip(), b2_id);
            assert_ne!(node.state.tip(), a2_id);
            assert_eq!(node.index.active_chain, vec![genesis, b1_id, b2_id]);
            assert_eq!(node.index.active_work, work);
            assert!(node.contains_block(a1_id));
            assert!(node.contains_block(a2_id));
            drop(node);
            if expected_snapshot {
                startup_snapshot::invalidate_fixture_snapshots(&path);
            }
        }
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
            &path,
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
            assert_eq!(locator.version, BlockRecordVersion::V3);
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
        let peer = "127.0.0.1:29444";
        node.record_peer_started(PeerDirection::Outbound, peer.to_owned(), 100);
        assert!(!node.advance_peer_sync_cursor(peer, None, [0xaa; 32]));
        assert!(node.advance_peer_sync_cursor(peer, None, side_id));
        assert!(!node.advance_peer_sync_cursor(peer, None, ids[0]));
        assert_eq!(
            node.peer_sync_locator(peer, 2),
            (vec![side_id, genesis], Some(side_id))
        );
        assert_eq!(node.peer_sync_locator(peer, 1).0, vec![genesis]);
        assert!(node.peer_sync_locator(peer, 0).0.is_empty());
        let continued = node.peer_sync_locator(peer, 6).0;
        assert_eq!(continued.first(), Some(&side_id));
        assert_eq!(continued.last(), Some(&genesis));
        assert!(continued.len() <= 6);
        assert_eq!(node.peer_sync_locator("127.0.0.2:29444", 6).0, locator);
        assert!(!node.set_peer_relay_cursor(peer, None, Some([0xaa; 32])));
        assert!(node.set_peer_relay_cursor(peer, None, Some(ids[3])));
        assert_eq!(node.peer_relay_inventory(peer, side_id, 1).0, vec![ids[4]]);
        assert_eq!(node.peer_relay_inventory(peer, ids[5], 1).0, vec![ids[6]]);
        assert_eq!(node.peer_sync_locator(peer, 2).0, vec![side_id, genesis]);
        assert!(!node.set_peer_relay_cursor(peer, None, None));
        assert!(node.set_peer_relay_cursor(peer, Some(ids[3]), ids.last().copied()));
        assert_eq!(node.peer_relay_inventory(peer, side_id, 1).0, vec![ids[0]]);
        assert!(node.set_peer_relay_cursor(peer, ids.last().copied(), None));
        assert_eq!(
            node.inventory_after(&[side_id, ids[3]], [0; 32], 3),
            ids[4..7].to_vec()
        );
        for block_id in [ids[0], ids[3], *ids.last().unwrap(), genesis] {
            let previous = node.peer_sync_locator(peer, 0).1;
            assert!(node.advance_peer_sync_cursor(peer, previous, block_id));
            assert!(!node.advance_peer_sync_cursor(peer, previous, side_id));
            for max in [0, 1, 2, 6, 64] {
                let (continued, token) = node.peer_sync_locator(peer, max);
                assert_eq!(token, Some(block_id));
                assert!(continued.len() <= max);
                let unique: std::collections::HashSet<_> = continued.iter().collect();
                assert_eq!(unique.len(), continued.len());
                if max == 0 {
                    assert!(continued.is_empty());
                } else {
                    assert_eq!(continued.last(), Some(&genesis));
                    if max > 1 && block_id != genesis {
                        assert_eq!(continued.first(), Some(&block_id));
                    } else {
                        assert_eq!(continued, node.block_locator(max));
                    }
                }
            }
        }
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
    fn v3_records_compress_blocks_and_read_back_mixed_with_v2() {
        let path = test_dir("v3-compressed-records");
        clean_test_dir(&path);
        let accepted_at = DEVNET_GENESIS_TIMESTAMP + 60;
        let (params, tip) = {
            let mut node = Node::open(&path).unwrap();
            let b1 = mined_child(&node, node.params.genesis_hash, accepted_at, 0xd1);
            node.submit_block(b1.clone(), accepted_at).unwrap();
            let b2 = mined_child(&node, b1.block_id(), accepted_at + 60, 0xd2);
            node.submit_block(b2.clone(), accepted_at + 60).unwrap();
            (node.params, b2.block_id())
        };
        let records = read_complete_log_records(&path);
        assert_eq!(records.len(), 2);
        for record in &records {
            assert_eq!(
                u16::from_le_bytes(record[4..6].try_into().unwrap()),
                RECORD_VERSION_V3
            );
            let (_, _, block_bytes, _) = v2_record_parts(record);
            let inflated_len = u32::from_le_bytes(record[56..60].try_into().unwrap()) as usize;
            assert_eq!(inflated_len, block_bytes.len());
            let parsed = read_log_record(
                &mut Cursor::new(record.as_slice()),
                &path,
                0,
                params.network_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(parsed.version, BlockRecordVersion::V3);
            assert_eq!(parsed.block_bytes, block_bytes);
            assert!(matches!(parsed.payload, ParsedRecordPayload::V2 { .. }));
        }

        // A V2 record followed by a V3 record chained to it is a valid log.
        let (at1, _, blk1, d1) = v2_record_parts(&records[0]);
        let v2 =
            encode_record_v2(at1, &blk1, &d1, EMPTY_RECORD_CHAIN_ROOT, DEVNET_NETWORK_ID).unwrap();
        let (at2, _, blk2, d2) = v2_record_parts(&records[1]);
        let v3 = encode_record_v3(
            at2,
            &blk2,
            &d2,
            complete_record_digest(&v2),
            DEVNET_NETWORK_ID,
        )
        .unwrap();
        assert!(
            v3.len() < RECORD_V3_HEADER_BYTES + blk2.len() + d2.len() + RECORD_CHECKSUM_BYTES
                || blk2.len() < 256
        );
        for slot in 0..=1_u8 {
            let _ = fs::remove_file(path.join(format!("startup-state.{slot}.bin")));
        }
        write_complete_log_records(&path, &[v2, v3]);
        let node = Node::open(&path).unwrap();
        assert_eq!(node.state.tip(), tip);
        drop(node);

        // A damaged compressed body never yields a block.
        let mut records = read_complete_log_records(&path);
        let last = records.len() - 1;
        records[last][RECORD_V3_HEADER_BYTES + 5] ^= 1;
        recompute_fixture_record_checksum(&mut records[last]);
        write_complete_log_records(&path, &records);
        for slot in 0..=1_u8 {
            let _ = fs::remove_file(path.join(format!("startup-state.{slot}.bin")));
        }
        assert!(matches!(Node::open(&path), Err(NodeError::CorruptLog(_))));
        clean_test_dir(&path);
    }

    #[test]
    fn v3_record_bounds_are_enforced_before_inflation() {
        let path = test_dir("v3-record-bounds");
        clean_test_dir(&path);
        let block = vec![0x5a_u8; 4096];
        let record =
            encode_record_v3(7, &block, &[], EMPTY_RECORD_CHAIN_ROOT, DEVNET_NETWORK_ID).unwrap();
        let parsed = read_log_record(
            &mut Cursor::new(record.as_slice()),
            &path,
            0,
            DEVNET_NETWORK_ID,
        )
        .unwrap()
        .unwrap();
        assert_eq!(parsed.block_bytes, block);
        assert!(record.len() < block.len());

        // An inflated length beyond the wire limit is refused from the header alone.
        let mut oversized = record.clone();
        oversized[56..60].copy_from_slice(&((MAX_BLOCK_BYTES + 1) as u32).to_le_bytes());
        recompute_fixture_record_checksum(&mut oversized);
        assert!(matches!(
            read_log_record(&mut Cursor::new(oversized.as_slice()), &path, 0, DEVNET_NETWORK_ID),
            Err(NodeError::CorruptLog(message)) if message.contains("inflated block exceeds")
        ));
        // A header that lies about the inflated length is refused after inflation.
        let mut shorter = record.clone();
        shorter[56..60].copy_from_slice(&((block.len() - 1) as u32).to_le_bytes());
        recompute_fixture_record_checksum(&mut shorter);
        assert!(matches!(
            read_log_record(&mut Cursor::new(shorter.as_slice()), &path, 0, DEVNET_NETWORK_ID),
            Err(NodeError::CorruptLog(message)) if message.contains("inflates to")
        ));
        assert!(matches!(
            encode_record_v3(7, &[], &[], EMPTY_RECORD_CHAIN_ROOT, DEVNET_NETWORK_ID),
            Err(NodeError::CorruptLog(_))
        ));
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
            u16::from_le_bytes(record[4..6].try_into().unwrap()) == RECORD_VERSION_V3
        }));

        let assert_chain_rejected = |candidate: &[Vec<u8>]| {
            write_complete_log_records(&path, candidate);
            let error = Node::open(&path).err().expect("tampered chain must fail");
            assert!(
                matches!(
                    &error,
                    NodeError::CorruptLog(message)
                        if message.contains("previous-record digest mismatch")
                ),
                "unexpected tampered-chain error: {error:?}"
            );
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
            &second_block,
            &second_delta,
            EMPTY_RECORD_CHAIN_ROOT,
            DEVNET_NETWORK_ID,
        )
        .unwrap();
        let (first_at, _, first_block, first_delta) = v2_record_parts(&records[0]);
        let parent_second = encode_record_v2(
            first_at,
            &first_block,
            &first_delta,
            complete_record_digest(&child_first),
            DEVNET_NETWORK_ID,
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
        // Compressed V3 records differ in length between blocks; re-encode both
        // single-record logs as V2 so the substitute has exactly the same length.
        for directory in [&path, &alternate] {
            let records = read_complete_log_records(directory);
            let (at, previous, block, delta) = v2_record_parts(&records[0]);
            let v2 = encode_record_v2(at, &block, &delta, previous, DEVNET_NETWORK_ID).unwrap();
            write_complete_log_records(directory, &[v2]);
            for slot in 0..=1_u8 {
                let _ = fs::remove_file(directory.join(format!("startup-state.{slot}.bin")));
            }
        }
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
                &path, &retained, &log_path, &mut state, &mut index, &verifier, params, None,
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
                &path, &retained, &log_path, &mut state, &mut index, &verifier, params, None,
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
        let (_, previous_record_digest, block_bytes, delta_bytes) = v2_record_parts(&records[0]);
        let block_bytes = block_bytes.as_slice();
        let mut forged_delta = delta_bytes;
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
            DEVNET_NETWORK_ID,
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
            &path, &log, &log_path, &mut state, &mut index, &verifier, params, None,
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
    fn empty_rc4_metadata_upgrade_preserves_keys_and_rejects_nonempty_logs() {
        let path = test_dir("empty-rc4-upgrade");
        clean_test_dir(&path);
        let node = Node::open(&path).unwrap();
        let fingerprint = node.fingerprint;
        let destination = node.wallet_destination();
        drop(node);
        let key_before = fs::read(path.join(WALLET_KEY_FILE)).unwrap();
        let metadata_path = path.join(METADATA_FILE);
        let mut previous = fs::read(&metadata_path).unwrap();
        previous[8..40].copy_from_slice(&RC4_FINGERPRINT);
        fs::write(&metadata_path, &previous).unwrap();
        let log_path = path.join(BLOCK_LOG_FILE);
        let mut log = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&log_path)
            .unwrap();
        assert!(matches!(
            load_metadata(&path, fingerprint, &log, &log_path, false),
            Err(NodeError::FingerprintMismatch)
        ));
        log.write_all(&[1]).unwrap();
        assert!(matches!(
            load_metadata(&path, fingerprint, &log, &log_path, true),
            Err(NodeError::FingerprintMismatch)
        ));
        log.set_len(0).unwrap();
        assert_eq!(
            load_metadata(&path, fingerprint, &log, &log_path, true).unwrap(),
            MetadataState::EmptyRc4Upgrade
        );
        write_metadata(&path, fingerprint, MetadataState::EmptyRc4Upgrade).unwrap();
        assert_eq!(fs::read(path.join("network.meta.rc4")).unwrap(), previous);
        assert_eq!(fs::read(path.join(WALLET_KEY_FILE)).unwrap(), key_before);
        assert_eq!(
            load_metadata(&path, fingerprint, &log, &log_path, true).unwrap(),
            MetadataState::Current
        );
        drop(log);
        let reopened = Node::open(&path).unwrap();
        assert_eq!(reopened.wallet_destination(), destination);
        drop(reopened);
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
        let parsed = read_rpc_request(&mut &request[..], DEVNET_PROFILE.network_id).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/v1/block");
        assert_eq!(parsed.body, b"abc");
    }

    #[test]
    fn explorer_rpc_responses_bind_their_own_network_identity() {
        let path = test_dir("explorer-response-network-identity");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let expected = node.params.network_id;
        for (target, status) in [
            ("/v1/explorer".to_owned(), 200),
            ("/v1/explorer/block/1".to_owned(), 404),
            (format!("/v1/explorer/transaction/{}", "ab".repeat(32)), 404),
        ] {
            let response = route_rpc_request(
                RpcRequest {
                    method: "GET".to_owned(),
                    target,
                    content_type: None,
                    body: Vec::new(),
                },
                &mut node,
            );
            assert_eq!(response.status, status);
            assert_eq!(response.network_id, Some(expected));
            let body_length = response.body.len();
            let mut wire = Vec::new();
            write_rpc_response(&mut wire, response).unwrap();
            let wire = String::from_utf8(wire).unwrap();
            let (headers, body) = wire.split_once("\r\n\r\n").unwrap();
            assert_eq!(headers.matches("X-CMFD-Network-Id:").count(), 1);
            assert!(headers.contains(&format!("X-CMFD-Network-Id: {}", hex::encode(expected))));
            assert!(headers.contains(&format!("Content-Length: {body_length}\r\n")));
            assert_eq!(body.len(), body_length);
            if status == 200 {
                let snapshot: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(snapshot["network_id"], hex::encode(expected));
            }
        }
        let response = route_rpc_request(
            RpcRequest {
                method: "GET".to_owned(),
                target: "/health".to_owned(),
                content_type: None,
                body: Vec::new(),
            },
            &mut node,
        );
        assert!(response.network_id.is_none());
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn explorer_transaction_index_covers_history_beyond_4096_blocks_and_both_restart_paths() {
        let path = test_dir("explorer-full-history");
        let mut node = Node::open(&path).unwrap();
        let funding = node
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let transaction = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
        let query = hex::encode(transaction.txid());
        node.submit_transaction(transaction).unwrap();
        assert_eq!(
            node.explorer_transaction(&query).unwrap().unwrap().status,
            "mempool"
        );
        assert_eq!(node.explorer_block_reads, 0);
        node.mine_once(
            default_miner_destination(),
            DEVNET_GENESIS_TIMESTAMP + 120,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        let expected = node.explorer_transaction(&query).unwrap().unwrap();
        assert_eq!(expected.block_height, Some(2));
        assert_eq!(expected.status, "confirmed");
        assert_eq!(node.explorer_block_reads, 1);
        drop(node);

        let mut node = Node::open(&path).unwrap();
        assert!(node.startup_snapshot_used);
        assert_eq!(
            node.explorer_transaction(&query).unwrap(),
            Some(expected.clone())
        );
        let params = node.params;
        let verifier = node.verifier.clone();
        let mut state = node.state.clone();
        let mut previous_digest = node.last_record_digest;
        drop(node);

        // Produce a real, consensus-valid durable history without rewriting a
        // startup snapshot and syncing the filesystem on every fixture block.
        // The reopened node must fully replay every block and reversible delta.
        let mut log = OpenOptions::new()
            .append(true)
            .open(path.join(BLOCK_LOG_FILE))
            .unwrap();
        for height in 3..=4_100 {
            let now = DEVNET_GENESIS_TIMESTAMP + height * 60;
            let template = build_template_from_state(
                &state,
                &params,
                default_miner_destination(),
                now,
                Vec::new(),
            )
            .unwrap();
            let proof = verifier
                .mine(&template.challenge, 0, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
            let block = Block {
                version: BLOCK_VERSION,
                challenge: template.challenge,
                coinbase: template.coinbase,
                transactions: template.transactions,
                proof,
            };
            let validated = state
                .validate_block(
                    &block,
                    BlockValidationContext {
                        now_unix_seconds: now,
                    },
                )
                .unwrap();
            let delta = validated.encode_reversible_state_delta().unwrap();
            let record = encode_record_v2(
                now,
                &encode_block(&block).unwrap(),
                &delta,
                previous_digest,
                params.network_id,
            )
            .unwrap();
            previous_digest = complete_record_digest(&record);
            log.write_all(&record).unwrap();
            state.commit_validated(validated).unwrap();
        }
        log.sync_all().unwrap();
        drop(log);

        for expected_snapshot in [false, true] {
            let mut reopened = Node::open(&path).unwrap();
            assert_eq!(reopened.startup_snapshot_used, expected_snapshot);
            assert_eq!(reopened.state.next_height(), 4_101);
            assert_eq!(
                reopened.explorer_transaction(&query).unwrap(),
                Some(expected.clone())
            );
            assert_eq!(
                reopened.explorer_block_reads, 1,
                "a confirmed lookup reads only its own block"
            );
            assert!(
                reopened
                    .explorer_transaction(&"ff".repeat(32))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                reopened.explorer_block_reads, 1,
                "a missing lookup must not scan blocks"
            );
        }
        clean_test_dir(&path);
    }

    #[test]
    fn explorer_transaction_index_tracks_competing_forks_orphans_and_reconfirmation() {
        let path = test_dir("explorer-index-reorg");
        let mut node = Node::open(&path).unwrap();
        let funding = node
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let transaction = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
        let query = hex::encode(transaction.txid());
        let a2 = mined_child_with_transactions(
            &node,
            funding.block_id(),
            DEVNET_GENESIS_TIMESTAMP + 120,
            0x41,
            vec![transaction.clone()],
        );
        node.submit_block(a2.clone(), a2.challenge.timestamp)
            .unwrap();
        let b2 = mined_child_with_transactions(
            &node,
            funding.block_id(),
            DEVNET_GENESIS_TIMESTAMP + 120,
            0x42,
            vec![transaction.clone()],
        );
        node.submit_block(b2.clone(), b2.challenge.timestamp)
            .unwrap();
        assert_eq!(
            node.explorer_transaction(&query).unwrap().unwrap().block_id,
            Some(hex::encode(a2.block_id()))
        );
        let b3 = mined_child(&node, b2.block_id(), DEVNET_GENESIS_TIMESTAMP + 180, 0x42);
        node.submit_block(b3.clone(), b3.challenge.timestamp)
            .unwrap();
        assert_eq!(
            node.explorer_transaction(&query).unwrap().unwrap().block_id,
            Some(hex::encode(b2.block_id()))
        );
        drop(node);
        let mut node = Node::open(&path).unwrap();
        assert!(
            node.startup_snapshot_used,
            "a current fork snapshot should restore"
        );
        assert_eq!(
            node.explorer_transaction(&query).unwrap().unwrap().block_id,
            Some(hex::encode(b2.block_id()))
        );

        let mut parent = a2.block_id();
        for height in 3..=4 {
            let block = mined_child(&node, parent, DEVNET_GENESIS_TIMESTAMP + height * 60, 0x41);
            parent = block.block_id();
            node.submit_block(block.clone(), block.challenge.timestamp)
                .unwrap();
        }
        assert_eq!(
            node.explorer_transaction(&query).unwrap().unwrap().block_id,
            Some(hex::encode(a2.block_id()))
        );
        parent = funding.block_id();
        for height in 2..=5 {
            let block = mined_child(&node, parent, DEVNET_GENESIS_TIMESTAMP + height * 60, 0x43);
            parent = block.block_id();
            node.submit_block(block.clone(), block.challenge.timestamp)
                .unwrap();
        }
        let reads = node.explorer_block_reads;
        assert!(
            node.explorer_transaction(&query).unwrap().is_none(),
            "orphaned occurrences are not confirmations"
        );
        assert_eq!(node.explorer_block_reads, reads);
        node.submit_transaction(transaction).unwrap();
        assert_eq!(
            node.explorer_transaction(&query).unwrap().unwrap().status,
            "mempool"
        );
        let confirmed = node
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 360,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        assert_eq!(
            node.explorer_transaction(&query).unwrap().unwrap().block_id,
            Some(hex::encode(confirmed.block_id()))
        );
        drop(node);
        for expected_snapshot in [true, false] {
            let mut reopened = Node::open(&path).unwrap();
            assert_eq!(reopened.startup_snapshot_used, expected_snapshot);
            assert_eq!(
                reopened
                    .explorer_transaction(&query)
                    .unwrap()
                    .unwrap()
                    .block_height,
                Some(6)
            );
            drop(reopened);
            if expected_snapshot {
                startup_snapshot::invalidate_fixture_snapshots(&path);
            }
        }
        clean_test_dir(&path);
    }

    #[test]
    fn explorer_transaction_index_preserves_multiple_positions_and_rejects_out_of_bounds_hints() {
        let path = test_dir("explorer-index-positions");
        let mut node = Node::open(&path).unwrap();
        let funding = node
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let first = spend_coinbase_output(&node, &funding, 1, 0x11, 0x31, 1);
        let second = spend_coinbase_output(&node, &funding, 2, 0x12, 0x32, 2);
        let block = mined_child_with_transactions(
            &node,
            funding.block_id(),
            DEVNET_GENESIS_TIMESTAMP + 120,
            0x41,
            vec![first, second],
        );
        node.submit_block(block.clone(), block.challenge.timestamp)
            .unwrap();
        for (position, transaction) in block.transactions.iter().enumerate() {
            let location = node
                .index
                .transactions
                .active_location(&transaction.txid(), &node.index)
                .unwrap();
            assert_eq!(location.transaction_position, position);
            let result = node
                .explorer_transaction(&hex::encode(transaction.txid()))
                .unwrap()
                .unwrap();
            assert_eq!(
                result.output_atoms,
                transaction.outputs[0].value.to_string()
            );
            assert_eq!(result.block_id, Some(hex::encode(block.block_id())));
        }
        assert_eq!(node.explorer_block_reads, 2);
        drop(node);
        let mut reopened = Node::open(&path).unwrap();
        assert!(reopened.startup_snapshot_used);
        for (position, transaction) in block.transactions.iter().enumerate() {
            assert_eq!(
                reopened
                    .index
                    .transactions
                    .active_location(&transaction.txid(), &reopened.index)
                    .unwrap()
                    .transaction_position,
                position
            );
            assert!(
                reopened
                    .explorer_transaction(&hex::encode(transaction.txid()))
                    .unwrap()
                    .is_some()
            );
        }
        let forged = [0xcd; 32];
        reopened
            .index
            .transactions
            .insert_block(block.block_id(), [[0xab; 32], [0xbc; 32], forged]);
        assert!(matches!(
            reopened.explorer_transaction(&hex::encode(forged)),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(reopened.storage_faulted);
        drop(reopened);
        clean_test_dir(&path);
    }

    #[test]
    fn explorer_transaction_index_rejects_invalid_admission_and_forged_lookup_hints() {
        let path = test_dir("explorer-index-invalid");
        let mut node = Node::open(&path).unwrap();
        let funding = node
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let transaction = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
        let query = hex::encode(transaction.txid());
        let valid = mined_child_with_transactions(
            &node,
            funding.block_id(),
            DEVNET_GENESIS_TIMESTAMP + 120,
            0x41,
            vec![transaction],
        );
        let mut invalid = valid.clone();
        invalid.challenge.transaction_root[0] ^= 1;
        let length = node.block_log_length;
        assert!(
            node.submit_block(invalid, DEVNET_GENESIS_TIMESTAMP + 120)
                .is_err()
        );
        assert_eq!(node.block_log_length, length);
        assert!(node.explorer_transaction(&query).unwrap().is_none());
        assert_eq!(node.explorer_block_reads, 0);
        node.submit_block(valid.clone(), DEVNET_GENESIS_TIMESTAMP + 120)
            .unwrap();
        let forged = [0xab; 32];
        node.index
            .transactions
            .insert_block(valid.block_id(), [forged]);
        assert!(
            matches!(node.explorer_transaction(&hex::encode(forged)), Err(NodeError::CorruptLog(message)) if message.contains("transaction index"))
        );
        assert!(node.storage_faulted);
        assert!(matches!(
            node.explorer_transaction(&query),
            Err(NodeError::StorageFaulted)
        ));
        drop(node);

        // Neither the poisoned hint nor its fault latch is persisted. Startup
        // rebuilds locations from authenticated log bytes, not serialized hints.
        let mut reopened = Node::open(&path).unwrap();
        assert!(
            reopened
                .explorer_transaction(&hex::encode(forged))
                .unwrap()
                .is_none()
        );
        assert!(reopened.explorer_transaction(&query).unwrap().is_some());
        let mut locator = reopened.index.blocks[&valid.block_id()].locator;
        locator.complete_digest[0] ^= 1;
        set_indexed_locator(&mut reopened, valid.block_id(), locator);
        assert!(matches!(
            reopened.explorer_transaction(&query),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(reopened.storage_faulted);
        drop(reopened);
        clean_test_dir(&path);
    }

    #[test]
    fn production_v4_storage_and_rpc_bounds_do_not_raise_legacy_limits() {
        let block = vec![0_u8; MAX_BLOCK_BYTES + 1];
        assert!(
            encode_record_v2(
                1,
                &block,
                &[],
                EMPTY_RECORD_CHAIN_ROOT,
                cmfd_consensus::PRODUCTION_V4_TESTNET_NETWORK_ID,
            )
            .is_ok()
        );
        assert!(
            encode_record_v2(
                1,
                &block,
                &[],
                EMPTY_RECORD_CHAIN_ROOT,
                DEVNET_PROFILE.network_id,
            )
            .is_err()
        );
        assert_eq!(
            rpc_body_limit(
                "POST",
                "/v1/block",
                cmfd_consensus::PRODUCTION_V4_TESTNET_NETWORK_ID,
            ),
            cmfd_consensus::PRODUCTION_V4_MAX_BLOCK_BYTES
        );
        assert_eq!(
            rpc_body_limit("POST", "/v1/block", DEVNET_PROFILE.network_id),
            MAX_BLOCK_BYTES
        );
    }

    #[test]
    fn rpc_parser_rejects_oversized_headers_and_bodies() {
        let oversized_header = format!(
            "GET /health HTTP/1.1\r\nX-Padding: {}\r\n\r\n",
            "a".repeat(RPC_HEADER_LIMIT)
        );
        assert!(matches!(
            read_rpc_request(&mut oversized_header.as_bytes(), DEVNET_PROFILE.network_id),
            Err(NodeError::InvalidRpcRequest(_))
        ));

        let oversized_body = format!(
            "POST /v1/block HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BLOCK_BYTES + 1
        );
        assert!(matches!(
            read_rpc_request(&mut oversized_body.as_bytes(), DEVNET_PROFILE.network_id),
            Err(NodeError::InvalidRpcRequest(_))
        ));

        let oversized_transaction = format!(
            "POST /v1/transaction HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_TRANSACTION_BYTES + 1
        );
        assert!(matches!(
            read_rpc_request(
                &mut oversized_transaction.as_bytes(),
                DEVNET_PROFILE.network_id,
            ),
            Err(NodeError::InvalidRpcRequest(_))
        ));

        for endpoint in ["/v1/wallet/send", "/v1/wallet/consolidate"] {
            let oversized_wallet_request = format!(
                "POST {endpoint} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                WALLET_JSON_BODY_LIMIT + 1
            );
            assert!(matches!(
                read_rpc_request(
                    &mut oversized_wallet_request.as_bytes(),
                    DEVNET_PROFILE.network_id,
                ),
                Err(NodeError::InvalidRpcRequest(_))
            ));
        }

        let mine_with_body = format!(
            "POST /v1/mine?miner={}&attempts=1 HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
            hex::encode(default_miner_destination())
        );
        assert!(matches!(
            read_rpc_request(&mut mine_with_body.as_bytes(), DEVNET_PROFILE.network_id),
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
            read_rpc_request(&mut &truncated[..], DEVNET_PROFILE.network_id),
            Err(NodeError::InvalidRpcRequest(_))
        ));

        let chunked = b"POST /v1/block HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(
            read_rpc_request(&mut &chunked[..], DEVNET_PROFILE.network_id),
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
        let mut reader = DeadlineReader::new(&mut server, Duration::ZERO).unwrap();
        let error = read_rpc_request(&mut reader, DEVNET_PROFILE.network_id).unwrap_err();
        assert!(matches!(
            error,
            NodeError::RpcIo(ref source) if source.kind() == io::ErrorKind::TimedOut
        ));
        drop(client);
    }

    #[test]
    fn rpc_reader_deadline_overflow_is_controlled() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        assert!(matches!(
            DeadlineReader::new(&mut server, Duration::MAX),
            Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
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
        let local_exposure = node
            .exchange_custody_destination_utxo_summary(node.wallet_destination())
            .unwrap();
        assert_eq!(local_exposure.local_mempool_output_count, 1);
        assert_eq!(
            local_exposure.local_mempool_output_atoms,
            input_atoms - amount - fee
        );

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
    fn exchange_withdrawal_requires_an_exact_intent_reservation() {
        let path = test_dir("exchange-withdrawal-reservation");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        mine_default_chain_to(&mut node, 100);

        let plan = node
            .plan_dev_wallet_payment(insecure_dev_destination(0x7a), COIN, 1)
            .unwrap();
        let intent = plan.transaction.signing_digest();
        assert!(plan.transaction.inputs.iter().all(|input| {
            matches!(
                &input.witness,
                InputWitness::Key {
                    public_key,
                    signature,
                } if *public_key == node.wallet_destination() && signature.is_empty()
            )
        }));
        assert!(matches!(
            node.sign_dev_wallet_payment(&plan),
            Err(NodeError::ExchangeWithdrawalReservationMismatch(_))
        ));

        node.set_exchange_withdrawal_reservations(
            plan.transaction
                .inputs
                .iter()
                .map(|input| (input.previous, intent))
                .collect(),
        );
        let reserved = node.wallet_snapshot().unwrap();
        assert_eq!(reserved.spendable_utxo_count, 0);
        assert_eq!(reserved.reserved_utxo_count, plan.transaction.inputs.len());
        assert!(matches!(
            node.plan_dev_wallet_payment(insecure_dev_destination(0x7b), 1, 1),
            Err(NodeError::WalletFundsImmature { .. })
        ));

        let signed = node.sign_dev_wallet_payment(&plan).unwrap();
        assert_eq!(signed.signing_digest(), intent);
        let mut different_intent = signed.clone();
        different_intent.outputs[0].value -= 1;
        assert!(matches!(
            node.submit_exchange_withdrawal_transaction(different_intent),
            Err(NodeError::ExchangeWithdrawalReservationMismatch(_))
        ));
        assert!(matches!(
            node.submit_transaction(signed.clone()),
            Err(NodeError::ExchangeWithdrawalInputReserved(_))
        ));
        let accepted = node
            .submit_exchange_withdrawal_transaction(signed.clone())
            .unwrap();
        assert_eq!(accepted.txid, signed.txid());
        assert!(node.mempool_contains_transaction(accepted.txid));

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn exchange_custody_plans_for_an_external_key_not_held_by_the_node_wallet() {
        let path = test_dir("exchange-custody-external-public-key");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let external_destination = insecure_dev_destination(0x6d);
        assert_ne!(external_destination, node.wallet_destination());
        for height in 1..=100 {
            node.mine_once(
                external_destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }

        let external_utxos = node
            .exchange_custody_destination_utxo_summary(external_destination)
            .unwrap();
        assert_eq!(external_utxos.tip, node.state.tip());
        assert_eq!(external_utxos.next_height, node.state.next_height());
        assert_eq!(external_utxos.unspent_count, 100);
        assert!(external_utxos.unspent_atoms > 0);
        assert!(external_utxos.spendable_count > 0);
        assert!(external_utxos.spendable_atoms > 0);
        assert_eq!(
            node.exchange_custody_destination_utxo_summary(insecure_dev_destination(0x6f))
                .unwrap()
                .unspent_count,
            0
        );

        assert!(
            node.plan_dev_wallet_payment(insecure_dev_destination(0x6e), 1, 1)
                .is_err()
        );
        let plan = node
            .plan_exchange_custody_payment(
                insecure_dev_destination(0x6e),
                1,
                1,
                &[external_destination],
                external_destination,
            )
            .unwrap();
        assert!(plan.transaction.inputs.iter().all(|input| {
            matches!(
                &input.witness,
                InputWitness::Key {
                    public_key,
                    signature,
                } if *public_key == external_destination && signature.is_empty()
            )
        }));
        assert_eq!(
            plan.transaction.outputs[1].lock,
            OutputLock::Key(external_destination)
        );
        node.validate_exchange_custody_payment_plan(
            &plan,
            &[external_destination],
            external_destination,
        )
        .unwrap();

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn legacy_sweep_evidence_is_read_from_the_authenticated_active_chain() {
        let path = test_dir("exchange-custody-legacy-sweep");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let legacy_destination = node.wallet_destination();
        let external_destination = insecure_dev_destination(0x70);
        let first = node
            .mine_once(
                legacy_destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        for height in 2..=100 {
            node.mine_once(
                external_destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
        let legacy_atoms = first.coinbase.outputs[0].value;
        let (sweep, _) = node
            .prepare_dev_wallet_payment(external_destination, legacy_atoms - 1, 1)
            .unwrap();
        let sweep_txid = sweep.txid();
        node.submit_transaction(sweep).unwrap();
        node.mine_once(
            external_destination,
            DEVNET_PROFILE.virtual_genesis_timestamp + 101 * 60,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();

        let unspent = node
            .exchange_custody_destination_utxo_summary(legacy_destination)
            .unwrap();
        assert_eq!(unspent.unspent_count, 0);
        assert_eq!(unspent.unspent_atoms, 0);
        let sweep = node
            .exchange_custody_confirmed_legacy_sweep(sweep_txid, legacy_destination)
            .unwrap()
            .unwrap();
        assert_eq!(sweep.txid, sweep_txid);
        assert_eq!(sweep.height, 101);
        assert_eq!(sweep.confirmations, 1);
        assert_eq!(sweep.legacy_input_count, 1);
        assert_eq!(sweep.legacy_output_count, 0);

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn v3_custody_exclusively_blocks_native_wallet_mutations() {
        let path = test_dir("exchange-custody-v3-wallet-exclusive");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        mine_default_chain_to(&mut node, 101);

        // Confirm a third-party output so ordinary relay can be distinguished
        // from transactions spending this node's custody wallet.
        let third_party_key = SigningKey::from_bytes(&[0x7c; 32]).unwrap();
        let third_party_destination = third_party_key.verifying_key().to_bytes().into();
        let (third_party_funding, _) = node
            .prepare_dev_wallet_payment(third_party_destination, 10, 1)
            .unwrap();
        let third_party_funding_txid = third_party_funding.txid();
        node.submit_transaction(third_party_funding).unwrap();
        let funding_height = node.state.next_height();
        node.mine_once(
            node.wallet_destination(),
            DEVNET_GENESIS_TIMESTAMP + funding_height * 60,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        let mut third_party_relay = Transaction {
            network_id: node.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: OutPoint {
                    txid: third_party_funding_txid,
                    index: 0,
                },
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: Vec::new(),
                },
            }],
            outputs: vec![TxOutput {
                value: 9,
                lock: OutputLock::Key(insecure_dev_destination(0x7e)),
                spendable_height: node.state.next_height(),
            }],
        };
        third_party_relay.sign_all(&[&third_party_key]).unwrap();

        // Preserve a valid wallet transaction signed before custody activation
        // to prove the submission boundary also fails closed.
        let (pre_signed_wallet_transaction, _) = node
            .prepare_dev_wallet_payment(insecure_dev_destination(0x7d), 1, 1)
            .unwrap();
        let custody_intent = pre_signed_wallet_transaction.signing_digest();

        node.claim_exchange_custody_v3_wallet().unwrap();
        assert!(matches!(
            node.send_from_dev_wallet(insecure_dev_destination(0x7d), 1, 1),
            Err(NodeError::ExchangeCustodyV3WalletExclusive)
        ));
        assert!(matches!(
            node.consolidate_dev_wallet(1, MAX_TRANSACTION_INPUTS),
            Err(NodeError::ExchangeCustodyV3WalletExclusive)
        ));
        assert!(matches!(
            node.prepare_dev_wallet_payment(insecure_dev_destination(0x7f), 1, 1),
            Err(NodeError::ExchangeCustodyV3WalletExclusive)
        ));
        assert!(matches!(
            node.submit_transaction(pre_signed_wallet_transaction.clone()),
            Err(NodeError::ExchangeCustodyV3WalletExclusive)
        ));
        assert!(node.mempool.is_empty());

        node.set_exchange_withdrawal_reservations(
            pre_signed_wallet_transaction
                .inputs
                .iter()
                .map(|input| (input.previous, custody_intent))
                .collect(),
        );
        node.submit_exchange_withdrawal_transaction(pre_signed_wallet_transaction)
            .unwrap();
        node.submit_transaction(third_party_relay).unwrap();
        assert_eq!(node.mempool.len(), 2);

        node.exchange_custody_v3_wallet_state = ExchangeCustodyV3WalletState::Unclaimed;
        assert!(!node.exchange_custody_v3_wallet_is_active());
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn persisted_v3_activation_keeps_native_wallet_locked_without_runtime_flags() {
        let path = test_dir("exchange-custody-v3-persisted-lock");
        clean_test_dir(&path);
        {
            let node = Node::open(&path).unwrap();
            assert_eq!(
                node.exchange_custody_v3_wallet_state,
                ExchangeCustodyV3WalletState::Unclaimed
            );
            assert_eq!(
                node.status().unwrap().exchange_custody_v3_wallet_state,
                "unclaimed"
            );
        }
        fs::write(
            path.join("exchange-withdrawals.v3.initialized"),
            b"persisted-v3-activation",
        )
        .unwrap();

        let mut node = Node::open(&path).unwrap();
        assert_eq!(
            node.exchange_custody_v3_wallet_state,
            ExchangeCustodyV3WalletState::Required
        );
        assert_eq!(
            node.status().unwrap().exchange_custody_v3_wallet_state,
            "required"
        );
        assert!(matches!(
            node.send_from_dev_wallet(insecure_dev_destination(0x7d), 1, 1),
            Err(NodeError::ExchangeCustodyV3WalletExclusive)
        ));
        assert!(matches!(
            node.consolidate_dev_wallet(1, MAX_TRANSACTION_INPUTS),
            Err(NodeError::ExchangeCustodyV3WalletExclusive)
        ));
        node.claim_exchange_custody_v3_wallet().unwrap();
        assert!(node.exchange_custody_v3_wallet_is_active());
        assert_eq!(
            node.status().unwrap().exchange_custody_v3_wallet_state,
            "active"
        );
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn incomplete_v3_migration_slot_keeps_native_wallet_locked() {
        let path = test_dir("exchange-custody-v3-incomplete-slot-lock");
        clean_test_dir(&path);
        drop(Node::open(&path).unwrap());
        let mut legacy_header = Vec::from(*b"CMFDEXW\0");
        legacy_header.extend_from_slice(&2_u32.to_le_bytes());
        legacy_header.extend_from_slice(&[0x71; 64]);
        let mut v3_header = Vec::from(*b"CMFDEXW\0");
        v3_header.extend_from_slice(&3_u32.to_le_bytes());
        v3_header.extend_from_slice(&[0x72; 64]);
        fs::write(path.join("exchange-withdrawals.0.bin"), legacy_header).unwrap();
        fs::write(path.join("exchange-withdrawals.1.bin"), v3_header).unwrap();

        let mut node = Node::open(&path).unwrap();
        assert_eq!(
            node.exchange_custody_v3_wallet_state,
            ExchangeCustodyV3WalletState::Required
        );
        assert_eq!(
            node.status().unwrap().exchange_custody_v3_wallet_state,
            "required"
        );
        assert!(matches!(
            node.send_from_dev_wallet(insecure_dev_destination(0x7d), 1, 1),
            Err(NodeError::ExchangeCustodyV3WalletExclusive)
        ));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn exchange_withdrawal_reservations_are_excluded_from_consolidation() {
        let path = test_dir("exchange-reservation-consolidation");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let blocks = mine_default_chain_to(&mut node, 101);
        let reserved_outpoint = OutPoint {
            txid: blocks[0].coinbase_outpoint_id(),
            index: 0,
        };
        node.set_exchange_withdrawal_reservations(HashMap::from([(reserved_outpoint, [0x44; 32])]));

        let snapshot = node.wallet_snapshot().unwrap();
        assert_eq!(snapshot.spendable_utxo_count, 1);
        assert_eq!(snapshot.reserved_utxo_count, 1);
        let plan = node
            .plan_dev_wallet_payment(insecure_dev_destination(0x7c), 1, 1)
            .unwrap();
        assert!(
            plan.transaction
                .inputs
                .iter()
                .all(|input| input.previous != reserved_outpoint)
        );
        assert!(matches!(
            node.consolidate_dev_wallet(1, MAX_TRANSACTION_INPUTS),
            Err(NodeError::WalletNotEnoughUtxos(1))
        ));

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

    /// Cached history must equal the pre-cache full scan, and a snapshot must
    /// read only the blocks appended since the previous one.
    fn check_cached_wallet_history(node: &mut Node) -> (Vec<WalletHistoryEntry>, u64) {
        let destination = node.wallet_destination();
        let accepted_height = node.state.next_height().saturating_sub(1);
        let cached = node
            .confirmed_wallet_history(destination, accepted_height, MAX_WALLET_HISTORY)
            .unwrap();
        let reference = node
            .reference_confirmed_wallet_history(destination, accepted_height, MAX_WALLET_HISTORY)
            .unwrap();
        assert_eq!(cached, reference);
        assert!(node.wallet_history_scan.is_none());
        let reads = node.wallet_history_cache.as_ref().unwrap().blocks_read();
        (cached, reads)
    }

    /// Like `check_cached_wallet_history`, but first lets a background scan of
    /// a long chain finish; the snapshot must stay empty until it does.
    fn wait_for_cached_wallet_history(node: &mut Node) -> (Vec<WalletHistoryEntry>, u64) {
        let destination = node.wallet_destination();
        let accepted_height = node.state.next_height().saturating_sub(1);
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let cached = node
                .confirmed_wallet_history(destination, accepted_height, MAX_WALLET_HISTORY)
                .unwrap();
            if node.wallet_history_scan.is_none() {
                break;
            }
            assert!(cached.is_empty());
            assert!(
                Instant::now() < deadline,
                "background wallet history scan did not finish"
            );
            thread::sleep(Duration::from_millis(50));
        }
        check_cached_wallet_history(node)
    }

    #[test]
    fn wallet_history_cache_matches_the_full_scan_and_reads_only_new_blocks() {
        let path = test_dir("wallet-history-cache");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let destination = node.wallet_destination();
        let mine_at = |node: &mut Node| {
            let height = node.state.next_height();
            node.mine_once(
                destination,
                DEVNET_GENESIS_TIMESTAMP + height * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap()
        };

        let blocks = mine_default_chain_to(&mut node, 3);
        let (history, reads) = check_cached_wallet_history(&mut node);
        assert_eq!(history.len(), 3);
        assert!(history.iter().all(|item| item.kind == "mined"));
        assert_eq!(reads, 3);

        // An external payment to the wallet, confirmed in the next block.
        let received = spend_coinbase_to(&node, &blocks[0], 1, 0x11, destination, 10);
        let received_txid = hex::encode(received.txid());
        node.submit_transaction(received).unwrap();
        mine_at(&mut node);
        let (history, reads) = check_cached_wallet_history(&mut node);
        assert_eq!(reads, 4);
        let item = history
            .iter()
            .find(|item| item.txid == received_txid)
            .unwrap();
        assert_eq!(item.kind, "received");
        assert_eq!(item.height, Some(4));

        // Catch up in batches; every snapshot reads exactly the new blocks.
        let mut previous_reads = reads;
        for target in (14..=100).step_by(10) {
            let before = node.state.next_height();
            mine_default_chain_to(&mut node, target);
            let (_, reads) = check_cached_wallet_history(&mut node);
            assert_eq!(reads - previous_reads, node.state.next_height() - before);
            previous_reads = reads;
        }

        // The wallet spends its first, now mature, coinbase output.
        mine_default_chain_to(&mut node, 102);
        let (_, reads) = check_cached_wallet_history(&mut node);
        previous_reads = reads;
        let first_value = blocks[0].coinbase.outputs[0].value;
        let mut sent = Transaction {
            network_id: node.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: OutPoint {
                    txid: blocks[0].coinbase_outpoint_id(),
                    index: 0,
                },
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: Vec::new(),
                },
            }],
            outputs: vec![TxOutput {
                value: first_value - 500,
                lock: OutputLock::Key(insecure_dev_destination(0x22)),
                spendable_height: node.state.next_height(),
            }],
        };
        sent.sign_all(&[&node.wallet_signing_key]).unwrap();
        let sent_txid = hex::encode(sent.txid());
        node.submit_transaction(sent.clone()).unwrap();
        let spending_block = mine_at(&mut node);
        let (history, reads) = check_cached_wallet_history(&mut node);
        assert_eq!(reads - previous_reads, 1);
        let item = history.iter().find(|item| item.txid == sent_txid).unwrap();
        assert_eq!(item.kind, "sent");
        assert_eq!(item.fee_burned_atoms, "500");
        assert_eq!(
            item.counterparty,
            Some(hex::encode(insecure_dev_destination(0x22)))
        );
        previous_reads = reads;

        // A tip reorg replaces the spending block: the cache undoes it instead
        // of rescanning, and the spent output is spendable again afterwards.
        let spending_height = spending_block.challenge.height;
        let parent = spending_block.challenge.previous_block;
        let sibling = mined_child(
            &node,
            parent,
            DEVNET_GENESIS_TIMESTAMP + spending_height * 60 + 1,
            0x51,
        );
        node.submit_block(
            sibling.clone(),
            DEVNET_GENESIS_TIMESTAMP + spending_height * 60 + 1,
        )
        .unwrap();
        assert_eq!(node.state.tip(), spending_block.block_id());
        let sibling_child = mined_child(
            &node,
            sibling.block_id(),
            DEVNET_GENESIS_TIMESTAMP + (spending_height + 1) * 60 + 1,
            0x52,
        );
        node.submit_block(
            sibling_child.clone(),
            DEVNET_GENESIS_TIMESTAMP + (spending_height + 1) * 60 + 1,
        )
        .unwrap();
        assert_eq!(node.state.tip(), sibling_child.block_id());
        let (history, reads) = check_cached_wallet_history(&mut node);
        assert_eq!(reads - previous_reads, 2);
        assert!(history.iter().all(|item| item.txid != sent_txid));
        previous_reads = reads;

        let _ = node.submit_transaction(sent);
        mine_at(&mut node);
        let (history, reads) = check_cached_wallet_history(&mut node);
        assert_eq!(reads - previous_reads, 1);
        let item = history.iter().find(|item| item.txid == sent_txid).unwrap();
        assert_eq!(item.height, Some(spending_height + 2));

        // A reorg below the undo window rebuilds the cache from genesis; a long
        // rebuild runs off the node lock.
        node.wallet_history_cache
            .as_mut()
            .unwrap()
            .set_undo_depth(2);
        node.wallet_history_inline_scan_bytes = 0;
        let fork_height = node.state.next_height() - 4;
        let mut parent = node.index.active_chain[fork_height as usize];
        for offset in 0..5_u64 {
            let timestamp = DEVNET_GENESIS_TIMESTAMP + (fork_height + 1 + offset) * 60 + 2;
            let block = mined_child(&node, parent, timestamp, 0x61 + offset as u8);
            node.submit_block(block.clone(), timestamp).unwrap();
            parent = block.block_id();
        }
        assert_eq!(node.state.tip(), parent);
        let accepted_height = node.state.next_height() - 1;
        let rebuilt = node
            .confirmed_wallet_history(destination, accepted_height, MAX_WALLET_HISTORY)
            .unwrap();
        assert!(rebuilt.is_empty());
        assert!(node.wallet_history_scan.is_some());
        let (_, reads) = wait_for_cached_wallet_history(&mut node);
        assert_eq!(reads, node.index.active_chain.len() as u64 - 1);

        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn wallet_history_scans_a_long_chain_off_the_node_lock() {
        let path = test_dir("wallet-history-background");
        clean_test_dir(&path);
        let mut node = Node::open(&path).unwrap();
        let destination = node.wallet_destination();
        let height = 70;
        mine_default_chain_to(&mut node, height);
        drop(node);

        let mut node = Node::open(&path).unwrap();
        node.wallet_history_inline_scan_bytes = 0;
        let accepted_height = node.state.next_height() - 1;
        let first = node
            .confirmed_wallet_history(destination, accepted_height, MAX_WALLET_HISTORY)
            .unwrap();
        assert!(first.is_empty());
        assert!(node.wallet_history_scan.is_some());
        let (history, reads) = wait_for_cached_wallet_history(&mut node);
        assert_eq!(history.len(), MAX_WALLET_HISTORY.min(height as usize));
        assert_eq!(reads, height);

        // Later blocks extend the adopted cache inline.
        node.wallet_history_inline_scan_bytes = wallet_history::INLINE_SCAN_BYTES;
        mine_default_chain_to(&mut node, height + 2);
        let (_, reads) = check_cached_wallet_history(&mut node);
        assert_eq!(reads, height + 2);

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

#[cfg(test)]
mod wallet_runtime_tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-wallet-runtime-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn clean_test_dir(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn encrypted_live_wallet_requires_the_correct_passphrase() {
        let path = test_dir("encrypted-live-wallet");
        clean_test_dir(&path);
        let passphrase = b"correct horse battery staple";

        let node = Node::open_with_profile_artifacts_and_worker(
            &path,
            DEVNET_PROFILE,
            None,
            None,
            None,
            None,
            Some(passphrase),
        )
        .unwrap();
        let destination = node.wallet_destination();
        assert_eq!(
            fs::metadata(path.join(WALLET_KEY_FILE)).unwrap().len(),
            wallet_backup::ENCRYPTED_WALLET_KEY_BYTES as u64
        );
        drop(node);

        assert!(matches!(
            Node::open_with_profile(&path, DEVNET_PROFILE),
            Err(NodeError::WalletLocked)
        ));
        assert!(matches!(
            Node::open_with_profile_artifacts_and_worker(
                &path,
                DEVNET_PROFILE,
                None,
                None,
                None,
                None,
                Some(b"incorrect horse battery staple")
            ),
            Err(NodeError::WalletLocked)
        ));
        let reopened = Node::open_with_profile_artifacts_and_worker(
            &path,
            DEVNET_PROFILE,
            None,
            None,
            None,
            None,
            Some(passphrase),
        )
        .unwrap();
        assert_eq!(reopened.wallet_destination(), destination);
        drop(reopened);

        clean_test_dir(&path);
    }

    #[test]
    fn rcnet_refuses_a_raw_live_wallet_key() {
        let path = test_dir("rcnet-raw-wallet");
        clean_test_dir(&path);
        drop(
            Node::open_with_profile_artifacts_and_worker(
                &path,
                DEVNET_PROFILE,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap(),
        );
        let log_path = path.join(BLOCK_LOG_FILE);
        let log = open_block_log(&log_path).unwrap();
        let rcnet_wallet_policy = NetworkProfile {
            kind: NetworkProfileKind::Rcnet,
            ..DEVNET_PROFILE
        };

        assert!(matches!(
            load_or_create_wallet_key(
                &path,
                rcnet_wallet_policy,
                MetadataState::Current,
                &log,
                &log_path,
                Some(b"correct horse battery staple")
            ),
            Err(NodeError::WalletKeyEncryptionRequired)
        ));
        drop(log);
        clean_test_dir(&path);
    }
}
