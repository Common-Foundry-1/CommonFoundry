use std::collections::{BTreeMap, BTreeSet};
#[cfg(any(feature = "production-v3", feature = "production-v4-testnet"))]
use std::fs::File;
#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
use std::fs::{self, OpenOptions};
#[cfg(feature = "production-v3")]
use std::io::BufReader;
#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Parser, Subcommand};
#[cfg(feature = "production-v3")]
use cmfd_consensus::ForgeMatrixV3WinningNonceClaim;
#[cfg(feature = "production-v3-testnet")]
use cmfd_consensus::dory_v3_qualification::ProductionDoryV3QualificationSeed;
#[cfg(feature = "production-v4-testnet")]
use cmfd_consensus::forgematrix_v4_proof::forgematrix_v4_mask_coefficients;
#[cfg(feature = "production-v4-testnet")]
use cmfd_consensus::forgematrix_v4_proof_codec::decode_forgematrix_v4_transparent_proof;
#[cfg(feature = "production-v4-testnet")]
use cmfd_consensus::{
    BlockChallenge, Coinbase, FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_FIELD_MODULUS,
    FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN, FORGEMATRIX_V4_PROOF_VERSION,
    FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES, ForgeMatrixV4CandidateProof,
    ForgeMatrixV4FixedArtifactRecordV1, PRODUCTION_V2_LAYERS,
    PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST, PRODUCTION_V4_MAX_BLOCK_BYTES,
    PRODUCTION_V4_MAX_PROOF_BYTES, PRODUCTION_V4_TESTNET_NETWORK_ID, Transaction,
    forgematrix_v4_challenge_digest, forgematrix_v4_proof_system_digest,
    forgematrix_v4_work_digest,
};
#[cfg(feature = "production-v3-testnet")]
use cmfd_consensus::{
    BlockChallenge, Coinbase, MAX_BLOCK_BYTES, MAX_PROOF_BYTES, Transaction,
    decode_forgematrix_proof, encode_forgematrix_proof,
};
use cmfd_consensus::{BlockProof, ForgeMatrixV2AcceleratorModel};
use cmfd_cuda::{CudaDevice, CudaLibrary};
#[cfg(feature = "production-v3-testnet")]
use cmfd_node::NetworkProfileKind;
use cmfd_node::p2p::{
    relay_blocks_to_peer_once_with_policy, request_mining_template_once_with_policy,
    spawn_inbound_listener_with_policy, spawn_static_peer_polling,
    submit_mined_block_once_with_policy, submit_mined_block_once_with_policy_before_cancellable,
    sync_from_peer_once_with_policy,
};
#[cfg(feature = "production-v3")]
use cmfd_node::p2p::{
    request_production_v3_mining_template_once_with_policy,
    submit_production_v3_mined_block_once_with_policy_before_cancellable,
};
use cmfd_node::peer::{
    BlockSubmissionStatus, MiningTemplate, PeerAddressPolicy, PeerLimits, StaticPeerConfig,
};
use cmfd_node::{
    COMPILED_NETWORK_PROFILE, MiningShareSearchResult, MiningWork, Node, NodeError, ProofProfile,
    parse_miner_destination, submit_shared_tip_block, unix_time_seconds,
};
#[cfg(feature = "production-v3")]
use cmfd_node::{
    ProductionV3MiningPeerIdentity, ProductionV3MiningWorkFactory, ProductionV3VerifierArtifacts,
};
#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
use same_file::Handle as SameFileHandle;

mod telemetry;

use telemetry::{GpuTelemetry, query_nvidia_smi};

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
const QUALIFIED_TEMPLATE_FORMAT_VERSION: u16 = 1;
#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
static QUALIFIED_OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const DEFAULT_MINER_DATA_DIR: &str = COMPILED_NETWORK_PROFILE.miner_data_dir_identity();
const DEFAULT_MINER_P2P_ADDRESS: SocketAddr = COMPILED_NETWORK_PROFILE.miner_p2p_address();
const DEFAULT_BATCH_SIZE: u32 = match COMPILED_NETWORK_PROFILE.proof {
    ProofProfile::DevnetV2Reference => 8_192,
    ProofProfile::ProductionV3 => 64,
    ProofProfile::ProductionV4 => 1,
};
const MAX_BATCH_SIZE: u32 = 65_536;
#[cfg(feature = "production-v3")]
const MAX_PRODUCTION_V3_BATCH_SIZE: u32 = 64;
const AUTO_WORKERS_PER_GPU: usize = 0;
const MAX_WORKERS_PER_GPU: usize = 16;
const DEFAULT_STATS_SECONDS: u64 = 5;
const PEER_RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// Covers the external verifier's bounded 900-second authenticated restart
/// while still placing a hard ceiling on retaining one exact candidate.
const FOUND_BLOCK_RETRY_BUDGET: Duration = Duration::from_secs(20 * 60);

#[derive(Debug, Parser)]
#[command(
    name = "cmfd-miner",
    version,
    about = "Common Foundry standalone multi-GPU CUDA miner"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[cfg(feature = "production-v3")]
#[derive(Debug, clap::Args)]
struct ProductionV3Cli {
    /// Absolute path to the pinned production V3 model bank.
    #[arg(long)]
    production_v3_bank: Option<PathBuf>,
    /// Absolute path to the pinned production V3 model manifest.
    #[arg(long)]
    production_v3_manifest: Option<PathBuf>,
    /// Absolute path to the pinned production V3 Record V2.
    #[arg(long)]
    production_v3_record_v2: Option<PathBuf>,
    /// Existing absolute scratch directory for fixed-model preparation and proof construction.
    #[arg(long)]
    production_v3_scratch: Option<PathBuf>,
    /// Explicit native proof row cap, from 1 through 131072.
    #[arg(long)]
    production_v3_max_rows: Option<usize>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List CUDA devices visible to the standalone miner.
    Devices {
        /// Path to the ForgeMatrix CUDA library. Defaults beside this executable.
        #[arg(long)]
        cuda_library: Option<PathBuf>,
    },
    /// Mine node-provided templates without maintaining another chain database.
    Mine {
        /// Compiled-network node that provides jobs and accepts blocks. Repeat for failover.
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        /// Allow numeric public peer addresses for explicitly enabled public testing.
        #[arg(long)]
        allow_public_peers: bool,
        /// CUDA device index. Repeat to select several; omitted means every supported GPU.
        #[arg(long = "device")]
        devices: Vec<i32>,
        /// Path to the ForgeMatrix CUDA library. Defaults beside this executable.
        #[arg(long)]
        cuda_library: Option<PathBuf>,
        /// Nonces evaluated per CUDA launch, from 1 through 65536.
        #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
        batch_size: u32,
        /// CPU preparation workers per GPU; 0 automatically divides host threads across GPUs.
        #[arg(long, default_value_t = AUTO_WORKERS_PER_GPU)]
        workers_per_gpu: usize,
        /// 32-byte x-only Schnorr payout key as 64 hexadecimal characters.
        #[arg(long)]
        miner: Option<String>,
        /// Seconds between rig-rate reports.
        #[arg(long, default_value_t = DEFAULT_STATS_SECONDS)]
        stats_seconds: u64,
        #[cfg(feature = "production-v3")]
        #[command(flatten)]
        production_v3: ProductionV3Cli,
    },
    /// Freeze one exact ProductionV3 node template and its qualification seed.
    #[cfg(feature = "production-v3-testnet")]
    SnapshotQualifiedTemplate {
        /// Compiled-network node that provides the immutable template.
        #[arg(long)]
        peer: SocketAddr,
        /// Allow a numeric public peer address for explicitly enabled public testing.
        #[arg(long)]
        allow_public_peers: bool,
        /// 32-byte x-only Schnorr payout key as 64 hexadecimal characters.
        #[arg(long)]
        miner: String,
        /// Nonce to qualify. The low-difficulty tester network normally uses zero.
        #[arg(long, default_value_t = 0)]
        nonce: u64,
        /// New absolute JSON path for the exact immutable template.
        #[arg(long)]
        template_output: PathBuf,
        /// New absolute JSON path accepted by `cmfd-consensus dory-v3-qualify-request`.
        #[arg(long)]
        seed_output: PathBuf,
        #[command(flatten)]
        production_v3: ProductionV3Cli,
    },
    /// Submit a completed qualification proof against its frozen ProductionV3 template.
    #[cfg(feature = "production-v3-testnet")]
    SubmitQualifiedTemplate {
        /// Compiled-network node that issued the frozen template.
        #[arg(long)]
        peer: SocketAddr,
        /// Allow a numeric public peer address for explicitly enabled public testing.
        #[arg(long)]
        allow_public_peers: bool,
        /// Existing absolute JSON path produced by `snapshot-qualified-template`.
        #[arg(long)]
        template: PathBuf,
        /// Existing absolute canonical proof wire produced by `dory-v3-qualify`.
        #[arg(long)]
        proof: PathBuf,
        #[command(flatten)]
        production_v3: ProductionV3Cli,
    },
    /// Freeze one exact ProductionV4 node template for the GPU prover.
    #[cfg(feature = "production-v4-testnet")]
    SnapshotV4Template {
        #[arg(long)]
        peer: SocketAddr,
        #[arg(long)]
        allow_public_peers: bool,
        #[arg(long)]
        miner: String,
        #[arg(long, default_value_t = 0)]
        nonce: u64,
        /// Existing compiled ProductionV4 fixed artifact record.
        #[arg(long)]
        fixed_record: PathBuf,
        /// New replay-coefficient file bound to the frozen template.
        #[arg(long)]
        coefficients_output: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Bind another nonce to an already-frozen ProductionV4 block challenge.
    #[cfg(feature = "production-v4-testnet")]
    BindV4Nonce {
        /// Existing canonical template whose block challenge remains unchanged.
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        fixed_record: PathBuf,
        #[arg(long)]
        coefficients_output: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare replay coefficients for a contiguous ProductionV4 nonce batch.
    #[cfg(feature = "production-v4-testnet")]
    PrepareV4SearchBatch {
        /// Existing canonical template whose block challenge remains unchanged.
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        start_nonce: u64,
        #[arg(long)]
        count: u32,
        #[arg(long)]
        fixed_record: PathBuf,
        #[arg(long)]
        coefficients_output: PathBuf,
    },
    /// Inspect an ordered ProductionV4 nonce batch and retain its first winner.
    #[cfg(feature = "production-v4-testnet")]
    InspectV4SearchBatch {
        /// Existing canonical template whose block challenge remains unchanged.
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        start_nonce: u64,
        #[arg(long)]
        count: u32,
        #[arg(long)]
        final_activations: PathBuf,
        #[arg(long)]
        fixed_record: PathBuf,
        #[arg(long)]
        winner_final_output: PathBuf,
    },
    /// Report whether a replay's final activation meets a frozen V4 target.
    #[cfg(feature = "production-v4-testnet")]
    InspectV4Work {
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        final_activation: PathBuf,
        #[arg(long)]
        fixed_record: PathBuf,
    },
    /// Wrap and submit a CPU-self-verified ProductionV4 transparent proof.
    #[cfg(feature = "production-v4-testnet")]
    SubmitV4Template {
        #[arg(long)]
        peer: SocketAddr,
        #[arg(long)]
        allow_public_peers: bool,
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        transparent_proof: PathBuf,
        #[arg(long)]
        fixed_record: PathBuf,
    },
    /// Mine with an embedded full node and local chain database.
    FullNode {
        #[arg(long, default_value = DEFAULT_MINER_DATA_DIR)]
        data_dir: PathBuf,
        #[arg(long, default_value_t = DEFAULT_MINER_P2P_ADDRESS)]
        p2p_bind: SocketAddr,
        /// Static compiled-network peer. Repeat to configure more than one.
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        /// Allow numeric public peer addresses for explicitly enabled public testing.
        #[arg(long)]
        allow_public_peers: bool,
        /// CUDA device index. Repeat to select several; omitted means every supported GPU.
        #[arg(long = "device")]
        devices: Vec<i32>,
        /// Path to the ForgeMatrix CUDA library. Defaults beside this executable.
        #[arg(long)]
        cuda_library: Option<PathBuf>,
        /// Nonces evaluated per CUDA launch, from 1 through 65536.
        #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
        batch_size: u32,
        /// CPU preparation workers per GPU; 0 automatically divides host threads across GPUs.
        #[arg(long, default_value_t = AUTO_WORKERS_PER_GPU)]
        workers_per_gpu: usize,
        /// 32-byte x-only Schnorr payout key as 64 hexadecimal characters.
        #[arg(long)]
        miner: Option<String>,
        /// Seconds between rig-rate reports.
        #[arg(long, default_value_t = DEFAULT_STATS_SECONDS)]
        stats_seconds: u64,
        #[cfg(feature = "production-v3")]
        #[command(flatten)]
        production_v3: ProductionV3Cli,
    },
}

#[derive(Debug)]
enum WorkerMessage {
    Initialized {
        device: i32,
        lane: usize,
    },
    Ready {
        job_id: u64,
        device: i32,
        lane: usize,
    },
    Progress {
        job_id: u64,
        device: i32,
        attempts: u64,
    },
    Found {
        job_id: u64,
        device: i32,
        proof: BlockProof,
        attempts: u64,
    },
    #[cfg(feature = "production-v3")]
    FoundV3 {
        job_id: u64,
        device: i32,
        claim: ForgeMatrixV3WinningNonceClaim,
        attempts: u64,
        /// Untrusted GPU-computed replay accumulator columns for the claim,
        /// when the backend exports the replay seam and its final activation
        /// matched the search output. The consensus replay revalidates
        /// everything; `None` falls back to the CPU matrix replay.
        replay_accumulators: Option<Vec<i32>>,
    },
    Idle {
        job_id: u64,
        device: i32,
        lane: usize,
    },
    Failed {
        job_id: Option<u64>,
        device: i32,
        lane: usize,
        error: String,
    },
}

enum JobOutcome {
    Found {
        device: i32,
        proof: BlockProof,
    },
    #[cfg(feature = "production-v3")]
    FoundV3 {
        device: i32,
        claim: ForgeMatrixV3WinningNonceClaim,
        replay_accumulators: Option<Vec<i32>>,
    },
    Stale,
    Disconnected,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkStatus {
    Current,
    Stale,
    Disconnected,
}

#[cfg(feature = "production-v3")]
enum ProofRunOutcome<T> {
    Completed(T),
    Stale,
    Disconnected,
    Shutdown,
}

enum WorkerCommand {
    Mine {
        job_id: u64,
        work: MiningWork,
        cancel: Arc<AtomicBool>,
    },
    Shutdown,
}

struct PersistentWorkerPool {
    model_identity: [u8; 32],
    devices: Vec<CudaDevice>,
    workers_per_gpu: usize,
    commands: Vec<Sender<WorkerCommand>>,
    receiver: Receiver<WorkerMessage>,
    handles: Vec<JoinHandle<()>>,
    next_job_id: u64,
}

struct WorkerSpec {
    cuda: CudaLibrary,
    device: CudaDevice,
    ordinal: usize,
    lane: usize,
    worker_count: usize,
    batch_size: u32,
    model: Arc<ForgeMatrixV2AcceleratorModel>,
}

struct WorkerThreadError {
    job_id: Option<u64>,
    error: String,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Devices { cuda_library } => list_devices(cuda_library.as_deref()),
        Command::Mine {
            peers,
            allow_public_peers,
            devices,
            cuda_library,
            batch_size,
            workers_per_gpu,
            miner,
            stats_seconds,
            #[cfg(feature = "production-v3")]
            production_v3,
        } => run_thin_miner(ThinMinerOptions {
            peers,
            allow_public_peers,
            requested_devices: devices,
            cuda_library,
            batch_size,
            workers_per_gpu,
            miner,
            stats_seconds,
            #[cfg(feature = "production-v3")]
            production_v3,
        }),
        #[cfg(feature = "production-v3-testnet")]
        Command::SnapshotQualifiedTemplate {
            peer,
            allow_public_peers,
            miner,
            nonce,
            template_output,
            seed_output,
            production_v3,
        } => snapshot_qualified_template(
            peer,
            allow_public_peers,
            &miner,
            nonce,
            &template_output,
            &seed_output,
            production_v3,
        ),
        #[cfg(feature = "production-v3-testnet")]
        Command::SubmitQualifiedTemplate {
            peer,
            allow_public_peers,
            template,
            proof,
            production_v3,
        } => submit_qualified_template(peer, allow_public_peers, &template, &proof, production_v3),
        #[cfg(feature = "production-v4-testnet")]
        Command::SnapshotV4Template {
            peer,
            allow_public_peers,
            miner,
            nonce,
            fixed_record,
            coefficients_output,
            output,
        } => snapshot_v4_template(
            peer,
            allow_public_peers,
            &miner,
            nonce,
            &fixed_record,
            &coefficients_output,
            &output,
        ),
        #[cfg(feature = "production-v4-testnet")]
        Command::BindV4Nonce {
            template,
            nonce,
            fixed_record,
            coefficients_output,
            output,
        } => bind_v4_nonce(
            &template,
            nonce,
            &fixed_record,
            &coefficients_output,
            &output,
        ),
        #[cfg(feature = "production-v4-testnet")]
        Command::PrepareV4SearchBatch {
            template,
            start_nonce,
            count,
            fixed_record,
            coefficients_output,
        } => prepare_v4_search_batch(
            &template,
            start_nonce,
            count,
            &fixed_record,
            &coefficients_output,
        ),
        #[cfg(feature = "production-v4-testnet")]
        Command::InspectV4SearchBatch {
            template,
            start_nonce,
            count,
            final_activations,
            fixed_record,
            winner_final_output,
        } => inspect_v4_search_batch(
            &template,
            start_nonce,
            count,
            &final_activations,
            &fixed_record,
            &winner_final_output,
        ),
        #[cfg(feature = "production-v4-testnet")]
        Command::InspectV4Work {
            template,
            final_activation,
            fixed_record,
        } => inspect_v4_work(&template, &final_activation, &fixed_record),
        #[cfg(feature = "production-v4-testnet")]
        Command::SubmitV4Template {
            peer,
            allow_public_peers,
            template,
            transparent_proof,
            fixed_record,
        } => submit_v4_template(
            peer,
            allow_public_peers,
            &template,
            &transparent_proof,
            &fixed_record,
        ),
        Command::FullNode {
            data_dir,
            p2p_bind,
            peers,
            allow_public_peers,
            devices,
            cuda_library,
            batch_size,
            workers_per_gpu,
            miner,
            stats_seconds,
            #[cfg(feature = "production-v3")]
            production_v3,
        } => run_full_node_miner(FullNodeMinerOptions {
            data_dir,
            p2p_bind,
            peers,
            allow_public_peers,
            requested_devices: devices,
            cuda_library,
            batch_size,
            workers_per_gpu,
            miner,
            stats_seconds,
            #[cfg(feature = "production-v3")]
            production_v3,
        }),
    }
}

#[cfg(feature = "production-v3-testnet")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenProductionV3Template {
    format_version: u16,
    challenge: BlockChallenge,
    coinbase: Coinbase,
    transactions: Vec<Transaction>,
}

#[cfg(feature = "production-v3-testnet")]
impl FrozenProductionV3Template {
    fn from_mining_template(template: MiningTemplate) -> Self {
        Self {
            format_version: QUALIFIED_TEMPLATE_FORMAT_VERSION,
            challenge: template.challenge,
            coinbase: template.coinbase,
            transactions: template.transactions,
        }
    }

    fn into_mining_template(self) -> Result<MiningTemplate> {
        if self.format_version != QUALIFIED_TEMPLATE_FORMAT_VERSION {
            bail!(
                "unsupported qualified-template format version {}",
                self.format_version
            );
        }
        Ok(MiningTemplate {
            challenge: self.challenge,
            coinbase: self.coinbase,
            transactions: self.transactions,
        })
    }
}

#[cfg(feature = "production-v4-testnet")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenProductionV4Template {
    format_version: u16,
    challenge: BlockChallenge,
    coinbase: Coinbase,
    transactions: Vec<Transaction>,
    nonce: u64,
}

#[cfg(feature = "production-v4-testnet")]
impl FrozenProductionV4Template {
    fn from_mining_template(template: MiningTemplate, nonce: u64) -> Self {
        Self {
            format_version: QUALIFIED_TEMPLATE_FORMAT_VERSION,
            challenge: template.challenge,
            coinbase: template.coinbase,
            transactions: template.transactions,
            nonce,
        }
    }

    fn into_mining_template(self) -> Result<(MiningTemplate, u64)> {
        if self.format_version != QUALIFIED_TEMPLATE_FORMAT_VERSION {
            bail!(
                "unsupported ProductionV4 template format version {}",
                self.format_version
            );
        }
        Ok((
            MiningTemplate {
                challenge: self.challenge,
                coinbase: self.coinbase,
                transactions: self.transactions,
            },
            self.nonce,
        ))
    }
}

#[cfg(feature = "production-v4-testnet")]
fn snapshot_v4_template(
    peer: SocketAddr,
    allow_public_peers: bool,
    miner: &str,
    nonce: u64,
    fixed_record_path: &Path,
    coefficients_output: &Path,
    output: &Path,
) -> Result<()> {
    ensure_production_v4_test_tool()?;
    ensure_existing_absolute_file(fixed_record_path, "ProductionV4 fixed artifact record")?;
    ensure_new_absolute_output(coefficients_output, "ProductionV4 replay coefficients")?;
    ensure_new_absolute_output(output, "ProductionV4 template")?;
    if coefficients_output == output {
        bail!("ProductionV4 template and replay coefficient outputs must be different paths");
    }
    let fixed_record_bytes = read_bounded_file(
        fixed_record_path,
        64 * 1024,
        "ProductionV4 fixed artifact record",
    )?;
    let fixed_record: ForgeMatrixV4FixedArtifactRecordV1 =
        serde_json::from_slice(&fixed_record_bytes)?;
    fixed_record.validate()?;
    if fixed_record.record_digest() != PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST {
        bail!("ProductionV4 fixed artifact record is not the compiled testnet record");
    }
    let payout = parse_miner_destination(miner).map_err(anyhow::Error::from)?;
    let address_policy = qualified_template_address_policy(peer, allow_public_peers)?;
    let response = request_mining_template_once_with_policy(
        peer,
        payout,
        PeerLimits::default(),
        address_policy,
    )?;
    let frozen = FrozenProductionV4Template::from_mining_template(response.template, nonce);
    let challenge_digest = forgematrix_v4_challenge_digest(
        &frozen.challenge,
        frozen.nonce,
        fixed_record.manifest_digest(),
    );
    let coefficients = production_v4_replay_coefficients(challenge_digest);
    let bytes = canonical_json(&frozen, "ProductionV4 template")?;
    // The template is the completion marker for this bound output pair.
    write_new_file(
        coefficients_output,
        &coefficients,
        "ProductionV4 replay coefficients",
    )?;
    write_new_file(output, &bytes, "ProductionV4 template")?;
    println!(
        "Frozen ProductionV4 height {} nonce {} from {peer}: {} (coefficients: {})",
        frozen.challenge.height,
        frozen.nonce,
        output.display(),
        coefficients_output.display()
    );
    Ok(())
}

#[cfg(feature = "production-v4-testnet")]
fn bind_v4_nonce(
    template_path: &Path,
    nonce: u64,
    fixed_record_path: &Path,
    coefficients_output: &Path,
    output: &Path,
) -> Result<()> {
    ensure_production_v4_test_tool()?;
    ensure_existing_absolute_file(template_path, "ProductionV4 source template")?;
    ensure_existing_absolute_file(fixed_record_path, "ProductionV4 fixed artifact record")?;
    ensure_new_absolute_output(coefficients_output, "ProductionV4 replay coefficients")?;
    ensure_new_absolute_output(output, "ProductionV4 rebound template")?;
    if coefficients_output == output {
        bail!("ProductionV4 template and replay coefficient outputs must be different paths");
    }

    let template_bytes = read_bounded_file(
        template_path,
        PRODUCTION_V4_MAX_BLOCK_BYTES,
        "ProductionV4 source template",
    )?;
    let mut frozen: FrozenProductionV4Template = serde_json::from_slice(&template_bytes)
        .with_context(|| format!("failed to parse {}", template_path.display()))?;
    if canonical_json(&frozen, "ProductionV4 source template")? != template_bytes {
        bail!("ProductionV4 source template is not canonical JSON");
    }
    frozen.clone().into_mining_template()?;
    if frozen.challenge.network_id != PRODUCTION_V4_TESTNET_NETWORK_ID {
        bail!("ProductionV4 source template belongs to another network");
    }

    let fixed_record_bytes = read_bounded_file(
        fixed_record_path,
        64 * 1024,
        "ProductionV4 fixed artifact record",
    )?;
    let fixed_record: ForgeMatrixV4FixedArtifactRecordV1 =
        serde_json::from_slice(&fixed_record_bytes)?;
    fixed_record.validate()?;
    if fixed_record.record_digest() != PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST {
        bail!("ProductionV4 fixed artifact record is not the compiled testnet record");
    }

    frozen.nonce = nonce;
    let challenge_digest = forgematrix_v4_challenge_digest(
        &frozen.challenge,
        frozen.nonce,
        fixed_record.manifest_digest(),
    );
    let coefficients = production_v4_replay_coefficients(challenge_digest);
    let bytes = canonical_json(&frozen, "ProductionV4 rebound template")?;
    write_new_file(
        coefficients_output,
        &coefficients,
        "ProductionV4 replay coefficients",
    )?;
    write_new_file(output, &bytes, "ProductionV4 rebound template")?;
    println!(
        "Bound ProductionV4 height {} nonce {}: {} (coefficients: {})",
        frozen.challenge.height,
        frozen.nonce,
        output.display(),
        coefficients_output.display()
    );
    Ok(())
}

#[cfg(feature = "production-v4-testnet")]
fn prepare_v4_search_batch(
    template_path: &Path,
    start_nonce: u64,
    count: u32,
    fixed_record_path: &Path,
    coefficients_output: &Path,
) -> Result<()> {
    ensure_production_v4_test_tool()?;
    validate_v4_search_batch_range(start_nonce, count)?;
    ensure_existing_absolute_file(template_path, "ProductionV4 source template")?;
    ensure_existing_absolute_file(fixed_record_path, "ProductionV4 fixed artifact record")?;
    ensure_new_absolute_output(
        coefficients_output,
        "ProductionV4 search-batch replay coefficients",
    )?;

    let template_bytes = read_bounded_file(
        template_path,
        PRODUCTION_V4_MAX_BLOCK_BYTES,
        "ProductionV4 source template",
    )?;
    let frozen: FrozenProductionV4Template = serde_json::from_slice(&template_bytes)
        .with_context(|| format!("failed to parse {}", template_path.display()))?;
    if canonical_json(&frozen, "ProductionV4 source template")? != template_bytes {
        bail!("ProductionV4 source template is not canonical JSON");
    }
    frozen.clone().into_mining_template()?;
    if frozen.challenge.network_id != PRODUCTION_V4_TESTNET_NETWORK_ID {
        bail!("ProductionV4 source template belongs to another network");
    }

    let fixed_record_bytes = read_bounded_file(
        fixed_record_path,
        64 * 1024,
        "ProductionV4 fixed artifact record",
    )?;
    let fixed_record: ForgeMatrixV4FixedArtifactRecordV1 =
        serde_json::from_slice(&fixed_record_bytes)?;
    fixed_record.validate()?;
    if fixed_record.record_digest() != PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST {
        bail!("ProductionV4 fixed artifact record is not the compiled testnet record");
    }

    let coefficients_per_nonce = (PRODUCTION_V2_LAYERS as usize + 1) * 20;
    let mut coefficients = Vec::with_capacity(coefficients_per_nonce * count as usize);
    for lane in 0..count {
        let nonce = start_nonce + u64::from(lane);
        let challenge_digest = forgematrix_v4_challenge_digest(
            &frozen.challenge,
            nonce,
            fixed_record.manifest_digest(),
        );
        coefficients.extend_from_slice(&production_v4_replay_coefficients(challenge_digest));
    }
    write_new_file(
        coefficients_output,
        &coefficients,
        "ProductionV4 search-batch replay coefficients",
    )?;
    println!(
        "Prepared ProductionV4 search batch start_nonce={start_nonce} count={count}: {}",
        coefficients_output.display()
    );
    Ok(())
}

#[cfg(feature = "production-v4-testnet")]
fn inspect_v4_search_batch(
    template_path: &Path,
    start_nonce: u64,
    count: u32,
    final_activations_path: &Path,
    fixed_record_path: &Path,
    winner_final_output: &Path,
) -> Result<()> {
    ensure_production_v4_test_tool()?;
    validate_v4_search_batch_range(start_nonce, count)?;

    ensure_existing_absolute_file(template_path, "ProductionV4 source template")?;
    ensure_existing_absolute_file(
        final_activations_path,
        "ProductionV4 search-batch final activations",
    )?;
    ensure_existing_absolute_file(fixed_record_path, "ProductionV4 fixed artifact record")?;
    ensure_new_absolute_output(winner_final_output, "ProductionV4 winning final activation")?;

    let template_bytes = read_bounded_file(
        template_path,
        PRODUCTION_V4_MAX_BLOCK_BYTES,
        "ProductionV4 source template",
    )?;
    let frozen: FrozenProductionV4Template = serde_json::from_slice(&template_bytes)
        .with_context(|| format!("failed to parse {}", template_path.display()))?;
    if canonical_json(&frozen, "ProductionV4 source template")? != template_bytes {
        bail!("ProductionV4 source template is not canonical JSON");
    }
    frozen.clone().into_mining_template()?;
    if frozen.challenge.network_id != PRODUCTION_V4_TESTNET_NETWORK_ID {
        bail!("ProductionV4 source template belongs to another network");
    }

    let fixed_record_bytes = read_bounded_file(
        fixed_record_path,
        64 * 1024,
        "ProductionV4 fixed artifact record",
    )?;
    let fixed_record: ForgeMatrixV4FixedArtifactRecordV1 =
        serde_json::from_slice(&fixed_record_bytes)?;
    fixed_record.validate()?;
    if fixed_record.record_digest() != PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST {
        bail!("ProductionV4 fixed artifact record is not the compiled testnet record");
    }

    let expected_bytes = FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES
        .checked_mul(count as usize)
        .context("ProductionV4 search-batch final activation length overflow")?;
    let final_activations = read_bounded_file(
        final_activations_path,
        expected_bytes,
        "ProductionV4 search-batch final activations",
    )?;
    ensure!(
        final_activations.len() == expected_bytes,
        "ProductionV4 search-batch final activations have the wrong byte length"
    );

    for (lane, final_activation) in final_activations
        .chunks_exact(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES)
        .enumerate()
    {
        let nonce = start_nonce + lane as u64;
        let challenge_digest = forgematrix_v4_challenge_digest(
            &frozen.challenge,
            nonce,
            fixed_record.manifest_digest(),
        );
        let final_activation_digest =
            v4_final_activation_digest_from_bytes(challenge_digest, final_activation)?;
        let work_digest = forgematrix_v4_work_digest(
            fixed_record.manifest_digest(),
            challenge_digest,
            final_activation_digest,
        );
        if work_digest <= frozen.challenge.target {
            write_new_file(
                winner_final_output,
                final_activation,
                "ProductionV4 winning final activation",
            )?;
            println!(
                "CMFD_V4_SEARCH_BATCH qualified=true start_nonce={start_nonce} count={count} nonce={nonce} lane={lane} work={} target={}",
                hex::encode(work_digest),
                hex::encode(frozen.challenge.target),
            );
            return Ok(());
        }
    }

    println!(
        "CMFD_V4_SEARCH_BATCH qualified=false start_nonce={start_nonce} count={count} target={}",
        hex::encode(frozen.challenge.target),
    );
    Ok(())
}

#[cfg(feature = "production-v4-testnet")]
fn validate_v4_search_batch_range(start_nonce: u64, count: u32) -> Result<()> {
    ensure!(
        (1..=64).contains(&count),
        "ProductionV4 search batch count must be from 1 through 64"
    );
    start_nonce
        .checked_add(u64::from(count - 1))
        .context("ProductionV4 search batch exceeds the nonce space")?;
    Ok(())
}

#[cfg(feature = "production-v4-testnet")]
fn inspect_v4_work(
    template_path: &Path,
    final_activation_path: &Path,
    fixed_record_path: &Path,
) -> Result<()> {
    ensure_production_v4_test_tool()?;
    ensure_existing_absolute_file(template_path, "ProductionV4 template")?;
    ensure_existing_absolute_file(final_activation_path, "ProductionV4 final activation")?;
    ensure_existing_absolute_file(fixed_record_path, "ProductionV4 fixed artifact record")?;

    let template_bytes = read_bounded_file(
        template_path,
        PRODUCTION_V4_MAX_BLOCK_BYTES,
        "ProductionV4 template",
    )?;
    let frozen: FrozenProductionV4Template = serde_json::from_slice(&template_bytes)
        .with_context(|| format!("failed to parse {}", template_path.display()))?;
    if canonical_json(&frozen, "ProductionV4 template")? != template_bytes {
        bail!("ProductionV4 template is not canonical JSON");
    }
    frozen.clone().into_mining_template()?;
    if frozen.challenge.network_id != PRODUCTION_V4_TESTNET_NETWORK_ID {
        bail!("ProductionV4 template belongs to another network");
    }

    let fixed_record_bytes = read_bounded_file(
        fixed_record_path,
        64 * 1024,
        "ProductionV4 fixed artifact record",
    )?;
    let fixed_record: ForgeMatrixV4FixedArtifactRecordV1 =
        serde_json::from_slice(&fixed_record_bytes)?;
    fixed_record.validate()?;
    if fixed_record.record_digest() != PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST {
        bail!("ProductionV4 fixed artifact record is not the compiled testnet record");
    }

    let final_activation = read_bounded_file(
        final_activation_path,
        FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES,
        "ProductionV4 final activation",
    )?;
    if final_activation.len() != FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES {
        bail!("ProductionV4 final activation has the wrong byte length");
    }
    let challenge_digest = forgematrix_v4_challenge_digest(
        &frozen.challenge,
        frozen.nonce,
        fixed_record.manifest_digest(),
    );
    let final_activation_digest =
        v4_final_activation_digest_from_bytes(challenge_digest, &final_activation)?;
    let work_digest = forgematrix_v4_work_digest(
        fixed_record.manifest_digest(),
        challenge_digest,
        final_activation_digest,
    );
    println!(
        "CMFD_V4_WORK qualified={} nonce={} work={} target={}",
        work_digest <= frozen.challenge.target,
        frozen.nonce,
        hex::encode(work_digest),
        hex::encode(frozen.challenge.target),
    );
    Ok(())
}

#[cfg(feature = "production-v4-testnet")]
fn v4_final_activation_digest_from_bytes(
    challenge_digest: [u8; 32],
    final_activation: &[u8],
) -> Result<[u8; 32]> {
    if !final_activation.len().is_multiple_of(size_of::<u32>()) {
        bail!("ProductionV4 final activation is not a complete field vector");
    }
    let mut hasher = blake3::Hasher::new_derive_key(FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN);
    hasher.update(&challenge_digest);
    hasher.update(&((final_activation.len() / size_of::<u32>()) as u64).to_le_bytes());
    for encoded in final_activation.chunks_exact(size_of::<u32>()) {
        let value = u32::from_le_bytes(encoded.try_into()?);
        if value >= FORGEMATRIX_V4_FIELD_MODULUS {
            bail!("ProductionV4 final activation contains a noncanonical field value");
        }
        hasher.update(encoded);
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(feature = "production-v4-testnet")]
fn production_v4_replay_coefficients(challenge_digest: [u8; 32]) -> Vec<u8> {
    let mut coefficients = Vec::with_capacity((PRODUCTION_V2_LAYERS as usize + 1) * 20);
    coefficients.extend_from_slice(&forgematrix_v4_mask_coefficients(
        challenge_digest,
        u32::MAX,
    ));
    for layer in 0..PRODUCTION_V2_LAYERS {
        coefficients.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge_digest, layer));
    }
    coefficients
}

#[cfg(feature = "production-v4-testnet")]
fn submit_v4_template(
    peer: SocketAddr,
    allow_public_peers: bool,
    template_path: &Path,
    transparent_proof_path: &Path,
    fixed_record_path: &Path,
) -> Result<()> {
    ensure_production_v4_test_tool()?;
    ensure_existing_absolute_file(template_path, "ProductionV4 template")?;
    ensure_existing_absolute_file(transparent_proof_path, "ProductionV4 transparent proof")?;
    ensure_existing_absolute_file(fixed_record_path, "ProductionV4 fixed artifact record")?;
    let address_policy = qualified_template_address_policy(peer, allow_public_peers)?;

    let template_bytes = read_bounded_file(
        template_path,
        PRODUCTION_V4_MAX_BLOCK_BYTES,
        "ProductionV4 template",
    )?;
    let frozen: FrozenProductionV4Template = serde_json::from_slice(&template_bytes)
        .with_context(|| format!("failed to parse {}", template_path.display()))?;
    if canonical_json(&frozen, "ProductionV4 template")? != template_bytes {
        bail!("ProductionV4 template is not canonical JSON");
    }
    let (template, nonce) = frozen.into_mining_template()?;

    let fixed_record_bytes = read_bounded_file(
        fixed_record_path,
        64 * 1024,
        "ProductionV4 fixed artifact record",
    )?;
    let fixed_record: ForgeMatrixV4FixedArtifactRecordV1 =
        serde_json::from_slice(&fixed_record_bytes)?;
    if fixed_record.record_digest() != PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST {
        bail!("ProductionV4 fixed artifact record is not the compiled testnet record");
    }

    let transparent_proof = read_bounded_file(
        transparent_proof_path,
        PRODUCTION_V4_MAX_PROOF_BYTES,
        "ProductionV4 transparent proof",
    )?;
    let decoded = decode_forgematrix_v4_transparent_proof(&transparent_proof)?;
    let challenge_digest =
        forgematrix_v4_challenge_digest(&template.challenge, nonce, fixed_record.manifest_digest());
    let final_activation_digest =
        cmfd_consensus::forgematrix_v4_proof::forgematrix_v4_final_activation_digest(
            challenge_digest,
            &decoded.final_activation,
        );
    let work_digest = forgematrix_v4_work_digest(
        fixed_record.manifest_digest(),
        challenge_digest,
        final_activation_digest,
    );
    if work_digest > template.challenge.target {
        bail!("ProductionV4 proof does not meet the frozen template target");
    }
    let proof = BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
        algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
        proof_version: FORGEMATRIX_V4_PROOF_VERSION,
        nonce,
        proof_system_digest: forgematrix_v4_proof_system_digest(),
        model_manifest_digest: fixed_record.manifest_digest(),
        challenge_digest,
        final_activation_digest,
        work_digest,
        transparent_proof,
    }));
    let block = template.into_block(proof);
    let block_id = block.block_id();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = Arc::clone(&shutdown);
    ctrlc::set_handler(move || shutdown_handler.store(true, Ordering::Release))?;
    let deadline = Instant::now()
        .checked_add(FOUND_BLOCK_RETRY_BUDGET)
        .ok_or_else(|| anyhow!("ProductionV4 block retry deadline overflow"))?;
    let cancellation = Arc::clone(&shutdown);
    let report = retry_exact_block_with(
        &[peer],
        Some(peer),
        &block,
        deadline,
        &shutdown,
        |address, candidate, attempt_deadline| {
            match submit_mined_block_once_with_policy_before_cancellable(
                address,
                candidate,
                PeerLimits::default(),
                address_policy,
                attempt_deadline,
                Arc::clone(&cancellation),
            ) {
                Ok(result) => ExactBlockSubmissionAttempt::Response(result),
                Err(error) if error.is_cancelled() || error.is_transport_disconnect() => {
                    ExactBlockSubmissionAttempt::Disconnected(error.to_string())
                }
                Err(error) => ExactBlockSubmissionAttempt::ProtocolViolation(error.to_string()),
            }
        },
        interruptible_wait,
        Instant::now,
    );
    match report.outcome {
        ExactBlockRetryOutcome::Accepted(accepted_peer) => {
            println!(
                "PRODUCTION V4 BLOCK ACCEPTED | height {} | {} | node {accepted_peer}",
                block.challenge.height,
                hex::encode(block_id)
            );
            Ok(())
        }
        ExactBlockRetryOutcome::Rejected => bail!("ProductionV4 block was rejected by the node"),
        ExactBlockRetryOutcome::Stale(tip) => bail!(
            "frozen ProductionV4 template is stale; node tip is {}",
            hex::encode(tip)
        ),
        ExactBlockRetryOutcome::ProtocolViolation { peer, detail } => {
            bail!("incompatible response from {peer}: {detail}")
        }
        ExactBlockRetryOutcome::BudgetExhausted => {
            bail!("ProductionV4 block submission exceeded its retry budget")
        }
        ExactBlockRetryOutcome::Stopped => bail!("ProductionV4 block submission was interrupted"),
    }
}

#[cfg(feature = "production-v4-testnet")]
fn ensure_production_v4_test_tool() -> Result<()> {
    if !matches!(
        COMPILED_NETWORK_PROFILE.kind,
        cmfd_node::NetworkProfileKind::ProductionV4Testnet
    ) {
        bail!("ProductionV4 template commands require the ProductionV4 testnet build");
    }
    Ok(())
}

#[cfg(feature = "production-v3-testnet")]
fn snapshot_qualified_template(
    peer: SocketAddr,
    allow_public_peers: bool,
    miner: &str,
    nonce: u64,
    template_output: &Path,
    seed_output: &Path,
    production_v3: ProductionV3Cli,
) -> Result<()> {
    ensure_production_v3_test_tool()?;
    ensure_new_absolute_output(template_output, "qualified template")?;
    ensure_new_absolute_output(seed_output, "qualification seed")?;
    if template_output == seed_output {
        bail!("qualified template and qualification seed outputs must be different paths");
    }
    let payout = parse_miner_destination(miner).map_err(anyhow::Error::from)?;
    let address_policy = qualified_template_address_policy(peer, allow_public_peers)?;
    let limits = PeerLimits::default();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = Arc::clone(&shutdown);
    ctrlc::set_handler(move || shutdown_handler.store(true, Ordering::Release))?;

    let runtime = production_v3.into_runtime()?;
    println!("Authenticating and preparing the pinned Production V3 model...");
    let factory = ProductionV3MiningWorkFactory::load(
        runtime.artifacts,
        runtime.scratch_directory,
        runtime.maximum_native_block_rows,
        &shutdown,
    )?;
    let response = request_production_v3_mining_template_once_with_policy(
        peer,
        payout,
        factory.peer_identity(),
        limits,
        address_policy,
    )?;
    factory.work(response.template.challenge)?;
    let frozen = FrozenProductionV3Template::from_mining_template(response.template);
    let seed = ProductionDoryV3QualificationSeed {
        block: frozen.challenge,
        nonce,
    };
    let frozen_json = canonical_json(&frozen, "qualified template")?;
    let seed_json = canonical_json(&seed, "qualification seed")?;
    // The template is the completion marker. Publishing the seed first means
    // an interrupted pair can never look like a complete frozen template.
    write_new_file(seed_output, &seed_json, "qualification seed")?;
    write_new_file(template_output, &frozen_json, "qualified template")?;
    println!(
        "Frozen Production V3 height {} from {peer}.",
        frozen.challenge.height
    );
    println!("Template: {}", template_output.display());
    println!("Qualification seed: {}", seed_output.display());
    Ok(())
}

#[cfg(feature = "production-v3-testnet")]
fn submit_qualified_template(
    peer: SocketAddr,
    allow_public_peers: bool,
    template_path: &Path,
    proof_path: &Path,
    production_v3: ProductionV3Cli,
) -> Result<()> {
    ensure_production_v3_test_tool()?;
    ensure_existing_absolute_file(template_path, "qualified template")?;
    ensure_existing_absolute_file(proof_path, "qualification proof")?;
    let address_policy = qualified_template_address_policy(peer, allow_public_peers)?;
    let frozen_bytes = read_bounded_file(template_path, MAX_BLOCK_BYTES, "qualified template")?;
    let frozen: FrozenProductionV3Template = serde_json::from_slice(&frozen_bytes)
        .with_context(|| format!("failed to parse {}", template_path.display()))?;
    if canonical_json(&frozen, "qualified template")? != frozen_bytes {
        bail!("qualified template is not canonical JSON");
    }
    let template = frozen.into_mining_template()?;
    let proof_bytes = read_bounded_file(proof_path, MAX_PROOF_BYTES, "qualification proof")?;
    let proof = decode_forgematrix_proof(&proof_bytes, template.challenge.network_id)
        .context("failed to decode canonical qualification proof")?;
    if encode_forgematrix_proof(&proof, template.challenge.network_id)? != proof_bytes {
        bail!("qualification proof is not canonical");
    }
    if !matches!(proof, BlockProof::V3Candidate(_)) {
        bail!("qualification proof is not a Production V3 candidate");
    }
    if proof.work_digest() > template.challenge.target {
        bail!("qualification proof does not meet the frozen template target");
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = Arc::clone(&shutdown);
    ctrlc::set_handler(move || shutdown_handler.store(true, Ordering::Release))?;
    let runtime = production_v3.into_runtime()?;
    println!("Authenticating the pinned Production V3 model before submission...");
    let factory = ProductionV3MiningWorkFactory::load(
        runtime.artifacts,
        runtime.scratch_directory,
        runtime.maximum_native_block_rows,
        &shutdown,
    )?;
    factory.work(template.challenge)?;
    let identity = ThinMinerHandshakeIdentity::ProductionV3(factory.peer_identity());
    let block = template.into_block(proof);
    let block_id = block.block_id();
    let deadline = Instant::now()
        .checked_add(FOUND_BLOCK_RETRY_BUDGET)
        .ok_or_else(|| anyhow!("qualified-block retry deadline overflow"))?;
    let cancellation = Arc::clone(&shutdown);
    let report = retry_exact_block_with(
        &[peer],
        Some(peer),
        &block,
        deadline,
        &shutdown,
        |address, candidate, attempt_deadline| match identity.submit_before_cancellable(
            address,
            candidate,
            PeerLimits::default(),
            address_policy,
            attempt_deadline,
            Arc::clone(&cancellation),
        ) {
            Ok(result) => ExactBlockSubmissionAttempt::Response(result),
            Err(error) if error.is_cancelled() || error.is_transport_disconnect() => {
                ExactBlockSubmissionAttempt::Disconnected(error.to_string())
            }
            Err(error) => ExactBlockSubmissionAttempt::ProtocolViolation(error.to_string()),
        },
        interruptible_wait,
        Instant::now,
    );
    match report.outcome {
        ExactBlockRetryOutcome::Accepted(accepted_peer) => {
            println!(
                "QUALIFIED BLOCK ACCEPTED | height {} | {} | node {accepted_peer}",
                block.challenge.height,
                hex::encode(block_id)
            );
            Ok(())
        }
        ExactBlockRetryOutcome::Rejected => bail!("qualified block was rejected by the node"),
        ExactBlockRetryOutcome::Stale(tip) => bail!(
            "frozen qualified template is stale; node tip is {}",
            hex::encode(tip)
        ),
        ExactBlockRetryOutcome::ProtocolViolation { peer, detail } => {
            bail!("incompatible response from {peer}: {detail}")
        }
        ExactBlockRetryOutcome::BudgetExhausted => bail!(
            "qualified block submission exceeded the {}-second retry budget",
            FOUND_BLOCK_RETRY_BUDGET.as_secs()
        ),
        ExactBlockRetryOutcome::Stopped => bail!("qualified block submission was interrupted"),
    }
}

#[cfg(feature = "production-v3-testnet")]
fn ensure_production_v3_test_tool() -> Result<()> {
    if !matches!(
        COMPILED_NETWORK_PROFILE.kind,
        NetworkProfileKind::ProductionV3Testnet
    ) {
        bail!("qualified-template commands require the Production V3 tester-network build");
    }
    Ok(())
}

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
fn qualified_template_address_policy(
    peer: SocketAddr,
    allow_public_peers: bool,
) -> Result<PeerAddressPolicy> {
    let address_policy = if allow_public_peers {
        PeerAddressPolicy::AllowPublic
    } else {
        PeerAddressPolicy::PrivateOnly
    };
    StaticPeerConfig {
        listen_address: DEFAULT_MINER_P2P_ADDRESS,
        peers: vec![peer],
        limits: PeerLimits::default(),
        address_policy,
    }
    .validate_client_peers()?;
    Ok(address_policy)
}

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
fn ensure_new_absolute_output(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{label} output must be an absolute path");
    }
    if path.exists() {
        bail!("{label} output already exists: {}", path.display());
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{label} output has no parent directory"))?;
    if !parent.is_dir() {
        bail!("{label} output parent does not exist: {}", parent.display());
    }
    Ok(())
}

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
fn ensure_existing_absolute_file(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() || !path.is_file() {
        bail!(
            "{label} must be an existing absolute file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
fn canonical_json<T>(value: &T, label: &str) -> Result<Vec<u8>>
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq,
{
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let decoded: T = serde_json::from_slice(&bytes)?;
    if &decoded != value {
        bail!("{label} failed canonical JSON round trip");
    }
    Ok(bytes)
}

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
fn write_new_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{label} output has no parent directory"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{label} output has no file name"))?
        .to_string_lossy();
    let sequence = QUALIFIED_OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .with_context(|| format!("failed to create temporary {label}"))?;
    let temporary_identity = SameFileHandle::from_file(
        file.try_clone()
            .with_context(|| format!("failed to retain {label} output handle"))?,
    )
    .with_context(|| format!("failed to identify {label} output"))?;
    let temporary_output = UnconfirmedOutput::new(temporary_path.clone(), temporary_identity);
    file.write_all(bytes)
        .with_context(|| format!("failed to write temporary {label}"))?;
    file.sync_all()
        .with_context(|| format!("failed to sync temporary {label}"))?;
    file.seek(SeekFrom::Start(0))?;
    let mut verified = Vec::with_capacity(bytes.len() + 1);
    Read::by_ref(&mut file)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut verified)?;
    if verified != bytes {
        bail!("temporary {label} failed retained-handle read-back verification");
    }

    let published_identity = SameFileHandle::from_file(
        file.try_clone()
            .with_context(|| format!("failed to retain publishable {label} handle"))?,
    )
    .with_context(|| format!("failed to identify publishable {label}"))?;
    fs::hard_link(&temporary_path, path)
        .with_context(|| format!("failed to publish {label} {}", path.display()))?;
    let mut published_output = UnconfirmedOutput::new(path.to_path_buf(), published_identity);

    let published_file = File::open(path)
        .with_context(|| format!("failed to reopen published {label} {}", path.display()))?;
    let reopened_identity = SameFileHandle::from_file(
        published_file
            .try_clone()
            .with_context(|| format!("failed to retain published {label} handle"))?,
    )
    .with_context(|| format!("failed to identify published {label}"))?;
    if reopened_identity != published_output.identity {
        bail!("{label} output was replaced before publication completed");
    }
    let mut reopened_bytes = Vec::with_capacity(bytes.len() + 1);
    published_file
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut reopened_bytes)?;
    if reopened_bytes != bytes {
        bail!("{label} failed published-file read-back verification");
    }
    sync_output_parent(parent)?;
    published_output.confirm();
    drop(file);
    if SameFileHandle::from_path(&temporary_path)
        .is_ok_and(|current| current == temporary_output.identity)
    {
        let _ = fs::remove_file(&temporary_path);
    }
    Ok(())
}

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
struct UnconfirmedOutput {
    path: PathBuf,
    identity: SameFileHandle,
    confirmed: bool,
}

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
impl UnconfirmedOutput {
    fn new(path: PathBuf, identity: SameFileHandle) -> Self {
        Self {
            path,
            identity,
            confirmed: false,
        }
    }

    fn confirm(&mut self) {
        self.confirmed = true;
    }
}

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
impl Drop for UnconfirmedOutput {
    fn drop(&mut self) {
        if !self.confirmed
            && SameFileHandle::from_path(&self.path).is_ok_and(|current| current == self.identity)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(all(
    any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
    unix
))]
fn sync_output_parent(parent: &Path) -> Result<()> {
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(all(
    any(feature = "production-v3-testnet", feature = "production-v4-testnet"),
    not(unix)
))]
fn sync_output_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(any(feature = "production-v3-testnet", feature = "production-v4-testnet"))]
fn read_bounded_file(path: &Path, maximum_bytes: usize, label: &str) -> Result<Vec<u8>> {
    let file =
        File::open(path).with_context(|| format!("failed to open {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} is not a regular file");
    }
    let length = metadata.len();
    if length > maximum_bytes as u64 {
        bail!("{label} exceeds its {maximum_bytes}-byte limit");
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    if bytes.len() > maximum_bytes {
        bail!("{label} exceeds its {maximum_bytes}-byte limit");
    }
    Ok(bytes)
}

fn load_cuda(path: Option<&Path>) -> Result<CudaLibrary> {
    CudaLibrary::load(path).map_err(anyhow::Error::msg)?.ok_or_else(|| {
        anyhow!(
            "no ForgeMatrix GPU library was found beside cmfd-miner: expected              cmfd-forgematrix-v2-miner (CUDA) or cmfd-forgematrix-v2-opencl (Intel Arc              and other OpenCL GPUs)"
        )
    })
}

fn list_devices(path: Option<&Path>) -> Result<()> {
    let library = load_cuda(path)?;
    let devices = library.devices().map_err(anyhow::Error::msg)?;
    println!(
        "{} library: {}",
        library.backend().name(),
        library.path().display()
    );
    if devices.is_empty() {
        println!("No {} devices found.", library.backend().name());
        return Ok(());
    }
    for device in devices {
        let memory_gib = device.total_memory_bytes as f64 / 1024_f64.powi(3);
        println!(
            "GPU {}: {} | {:.2} GiB | {}",
            device.index,
            device.label(),
            memory_gib,
            if device.is_supported() {
                "supported".to_owned()
            } else {
                device.requirement()
            }
        );
    }
    Ok(())
}

struct ThinMinerOptions {
    peers: Vec<SocketAddr>,
    allow_public_peers: bool,
    requested_devices: Vec<i32>,
    cuda_library: Option<PathBuf>,
    batch_size: u32,
    workers_per_gpu: usize,
    miner: Option<String>,
    stats_seconds: u64,
    #[cfg(feature = "production-v3")]
    production_v3: ProductionV3Cli,
}

struct FullNodeMinerOptions {
    data_dir: PathBuf,
    p2p_bind: SocketAddr,
    peers: Vec<SocketAddr>,
    allow_public_peers: bool,
    requested_devices: Vec<i32>,
    cuda_library: Option<PathBuf>,
    batch_size: u32,
    workers_per_gpu: usize,
    miner: Option<String>,
    stats_seconds: u64,
    #[cfg(feature = "production-v3")]
    production_v3: ProductionV3Cli,
}

#[cfg(feature = "production-v3")]
struct ProductionWorkerPool {
    parameters: cmfd_consensus::ForgeMatrixV3CandidateParameters,
    devices: Vec<CudaDevice>,
    commands: Vec<Sender<WorkerCommand>>,
    receiver: Receiver<WorkerMessage>,
    handles: Vec<JoinHandle<()>>,
    initialization_cancel: Arc<AtomicBool>,
    next_job_id: u64,
}

#[cfg(feature = "production-v3")]
struct ProductionWorkerSpec {
    cuda: CudaLibrary,
    device: CudaDevice,
    ordinal: usize,
    worker_count: usize,
    batch_size: u32,
    factory: ProductionV3MiningWorkFactory,
    initialization_cancel: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MiningRuntime {
    DevnetV2,
    ProductionV3,
    ProductionV4,
}

#[derive(Debug, Clone, Copy)]
enum ThinMinerHandshakeIdentity {
    Devnet,
    #[cfg(feature = "production-v3")]
    ProductionV3(ProductionV3MiningPeerIdentity),
}

impl ThinMinerHandshakeIdentity {
    fn request_template(
        self,
        address: SocketAddr,
        payout: [u8; 32],
        limits: PeerLimits,
        address_policy: PeerAddressPolicy,
    ) -> Result<cmfd_node::p2p::MiningTemplateResponse, cmfd_node::p2p::P2pError> {
        match self {
            Self::Devnet => {
                request_mining_template_once_with_policy(address, payout, limits, address_policy)
            }
            #[cfg(feature = "production-v3")]
            Self::ProductionV3(identity) => request_production_v3_mining_template_once_with_policy(
                address,
                payout,
                identity,
                limits,
                address_policy,
            ),
        }
    }

    fn submit_before_cancellable(
        self,
        address: SocketAddr,
        block: cmfd_consensus::Block,
        limits: PeerLimits,
        address_policy: PeerAddressPolicy,
        deadline: Instant,
        cancellation: Arc<AtomicBool>,
    ) -> Result<cmfd_node::peer::BlockSubmissionResult, cmfd_node::p2p::P2pError> {
        match self {
            Self::Devnet => submit_mined_block_once_with_policy_before_cancellable(
                address,
                block,
                limits,
                address_policy,
                deadline,
                cancellation,
            ),
            #[cfg(feature = "production-v3")]
            Self::ProductionV3(identity) => {
                submit_production_v3_mined_block_once_with_policy_before_cancellable(
                    address,
                    block,
                    identity,
                    limits,
                    address_policy,
                    deadline,
                    cancellation,
                )
            }
        }
    }
}

const fn mining_runtime(profile: cmfd_node::NetworkProfile) -> MiningRuntime {
    match profile.proof {
        ProofProfile::DevnetV2Reference => MiningRuntime::DevnetV2,
        ProofProfile::ProductionV3 => MiningRuntime::ProductionV3,
        ProofProfile::ProductionV4 => MiningRuntime::ProductionV4,
    }
}

#[cfg(feature = "production-v3")]
#[derive(Clone)]
struct ProductionV3RuntimeOptions {
    artifacts: ProductionV3VerifierArtifacts,
    scratch_directory: PathBuf,
    maximum_native_block_rows: usize,
}

#[cfg(feature = "production-v3")]
impl ProductionV3Cli {
    fn into_runtime(self) -> Result<ProductionV3RuntimeOptions> {
        let missing = || {
            anyhow!(
                "Production V3 requires explicit --production-v3-bank, --production-v3-manifest, --production-v3-record-v2, --production-v3-scratch, and --production-v3-max-rows"
            )
        };
        Ok(ProductionV3RuntimeOptions {
            artifacts: ProductionV3VerifierArtifacts {
                bank: self.production_v3_bank.ok_or_else(missing)?,
                manifest: self.production_v3_manifest.ok_or_else(missing)?,
                record_v2: self.production_v3_record_v2.ok_or_else(missing)?,
            },
            scratch_directory: self.production_v3_scratch.ok_or_else(missing)?,
            maximum_native_block_rows: self.production_v3_max_rows.ok_or_else(missing)?,
        })
    }
}

struct ContinuousMiningConfig {
    payout: [u8; 32],
    peers: StaticPeerConfig,
    batch_size: u32,
    workers_per_gpu: usize,
    stats_interval: Duration,
}

#[derive(Clone, Copy)]
struct JobMiningConfig {
    stats_interval: Duration,
}

struct MonitorControl {
    stats_interval: Duration,
    shutdown: Arc<AtomicBool>,
    worker_cancel: Arc<AtomicBool>,
}

struct SessionStatistics {
    started_at: Instant,
    last_report: Instant,
    totals: BTreeMap<i32, u64>,
    last_totals: BTreeMap<i32, u64>,
    blocks_found: u64,
    stale_jobs: u64,
    stale_submissions: u64,
    abandoned_submissions: u64,
    submission_disconnects: u64,
    submission_protocol_errors: u64,
    telemetry_warning_printed: bool,
}

impl SessionStatistics {
    fn new(devices: &[CudaDevice]) -> Self {
        let totals: BTreeMap<_, _> = devices.iter().map(|device| (device.index, 0_u64)).collect();
        Self {
            started_at: Instant::now(),
            last_report: Instant::now(),
            last_totals: totals.clone(),
            totals,
            blocks_found: 0,
            stale_jobs: 0,
            stale_submissions: 0,
            abandoned_submissions: 0,
            submission_disconnects: 0,
            submission_protocol_errors: 0,
            telemetry_warning_printed: false,
        }
    }

    fn record_attempts(&mut self, device: i32, attempts: u64) {
        let total = self.totals.entry(device).or_default();
        *total = total.saturating_add(attempts);
    }

    /// Total completed nonce evaluations across every GPU this session.
    #[cfg_attr(feature = "production-v4-testnet", allow(dead_code))]
    fn total_attempts(&self) -> u64 {
        self.totals
            .values()
            .fold(0_u64, |total, attempts| total.saturating_add(*attempts))
    }

    fn report_if_due(&mut self, devices: &[CudaDevice], height: u64, interval: Duration) {
        if self.last_report.elapsed() < interval {
            return;
        }

        let report_at = Instant::now();
        let elapsed = report_at
            .duration_since(self.last_report)
            .as_secs_f64()
            .max(f64::EPSILON);
        let rates: BTreeMap<_, _> = devices
            .iter()
            .map(|device| {
                let total = self.totals.get(&device.index).copied().unwrap_or_default();
                let previous = self
                    .last_totals
                    .get(&device.index)
                    .copied()
                    .unwrap_or_default();
                (
                    device.index,
                    total.saturating_sub(previous) as f64 / elapsed,
                )
            })
            .collect();
        let telemetry = match query_nvidia_smi() {
            Ok(telemetry) => telemetry,
            Err(error) => {
                if !self.telemetry_warning_printed {
                    println!(
                        "NVIDIA telemetry unavailable ({error}); hashrate reporting will continue."
                    );
                    self.telemetry_warning_printed = true;
                }
                BTreeMap::new()
            }
        };
        let total_rate = rates.values().sum::<f64>();
        let rig_power = devices
            .iter()
            .map(|device| telemetry.get(&device.index)?.power_watts)
            .sum::<Option<f64>>();
        let rig_efficiency = rig_power
            .filter(|power| *power > 0.0)
            .map(|power| total_rate / power);
        let total_attempts = self
            .totals
            .values()
            .fold(0_u64, |total, attempts| total.saturating_add(*attempts));

        println!(
            "MINER STATS | height {height} | uptime {} | blocks {} | stale jobs {} | stale submissions {} | abandoned submissions {} | submission disconnects {} | protocol errors {} | attempts {}",
            format_duration(self.started_at.elapsed()),
            self.blocks_found,
            self.stale_jobs,
            self.stale_submissions,
            self.abandoned_submissions,
            self.submission_disconnects,
            self.submission_protocol_errors,
            total_attempts
        );
        println!(
            "  RIG   | {:.2} H/s | {} | {}",
            total_rate,
            format_metric(rig_power, "W"),
            format_metric(rig_efficiency, "H/W")
        );
        for device in devices {
            let rate = rates.get(&device.index).copied().unwrap_or_default();
            println!(
                "  GPU {:>2} | {:.2} H/s | {}",
                device.index,
                rate,
                format_gpu_telemetry(rate, telemetry.get(&device.index))
            );
            self.last_totals.insert(
                device.index,
                self.totals.get(&device.index).copied().unwrap_or_default(),
            );
        }
        self.last_report = report_at;
    }
}

fn format_gpu_telemetry(rate: f64, telemetry: Option<&GpuTelemetry>) -> String {
    let Some(telemetry) = telemetry else {
        return "power N/A | efficiency N/A | sensors N/A".to_owned();
    };
    let efficiency = telemetry
        .power_watts
        .filter(|power| *power > 0.0)
        .map(|power| rate / power);
    let power = match (telemetry.power_watts, telemetry.power_limit_watts) {
        (Some(draw), Some(limit)) => format!("{draw:.2}/{limit:.2} W"),
        (Some(draw), None) => format!("{draw:.2} W"),
        (None, _) => "N/A W".to_owned(),
    };
    let memory = match (telemetry.memory_used_mib, telemetry.memory_total_mib) {
        (Some(used), Some(total)) => format!("{used:.0}/{total:.0} MiB"),
        _ => "N/A".to_owned(),
    };
    format!(
        "{power} | {} | temp {} | fan {} | util {} | core {} | mem {} | VRAM {memory}",
        format_metric(efficiency, "H/W"),
        format_metric(telemetry.temperature_celsius, "C"),
        format_metric(telemetry.fan_percent, "%"),
        format_metric(telemetry.utilization_percent, "%"),
        format_metric(telemetry.graphics_clock_mhz, "MHz"),
        format_metric(telemetry.memory_clock_mhz, "MHz"),
    )
}

fn format_metric(value: Option<f64>, unit: &str) -> String {
    value.map_or_else(|| "N/A".to_owned(), |value| format!("{value:.2} {unit}"))
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn run_thin_miner(options: ThinMinerOptions) -> Result<()> {
    match mining_runtime(COMPILED_NETWORK_PROFILE) {
        MiningRuntime::DevnetV2 => run_thin_miner_v2(options),
        MiningRuntime::ProductionV3 => {
            #[cfg(feature = "production-v3")]
            {
                run_thin_miner_v3(options)
            }
            #[cfg(not(feature = "production-v3"))]
            {
                let _ = options;
                bail!(
                    "this binary selects Production V3 but was built without the production-v3 feature"
                )
            }
        }
        MiningRuntime::ProductionV4 => {
            let _ = options;
            bail!(
                "ProductionV4 continuous mining is not yet installed; use snapshot-v4-template, the GPU prover, and submit-v4-template"
            )
        }
    }
}

fn run_thin_miner_v2(options: ThinMinerOptions) -> Result<()> {
    validate_mining_controls(
        options.batch_size,
        options.workers_per_gpu,
        options.stats_seconds,
    )?;
    if options.peers.is_empty() {
        bail!("thin mining requires at least one --peer node address");
    }
    let payout = options
        .miner
        .as_deref()
        .ok_or_else(|| anyhow!("thin mining requires --miner with your wallet receive address"))
        .and_then(|value| parse_miner_destination(value).map_err(anyhow::Error::from))?;
    let address_policy = if options.allow_public_peers {
        PeerAddressPolicy::AllowPublic
    } else {
        PeerAddressPolicy::PrivateOnly
    };
    let limits = PeerLimits::default();
    StaticPeerConfig {
        listen_address: DEFAULT_MINER_P2P_ADDRESS,
        peers: options.peers.clone(),
        limits,
        address_policy,
    }
    .validate_client_peers()?;

    let cuda = load_cuda(options.cuda_library.as_deref())?;
    let available = cuda.devices().map_err(anyhow::Error::msg)?;
    let devices = select_devices(&available, &options.requested_devices)?;
    let workers_per_gpu = resolve_workers_per_gpu(options.workers_per_gpu, devices.len())?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = Arc::clone(&shutdown);
    ctrlc::set_handler(move || shutdown_handler.store(true, Ordering::Release))?;

    println!(
        "Common Foundry thin CUDA miner v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "Network: {} ({})",
        COMPILED_NETWORK_PROFILE.short_name(),
        COMPILED_NETWORK_PROFILE.proof.profile_name()
    );
    println!(
        "{} library: {}",
        cuda.backend().name(),
        cuda.path().display()
    );
    println!("Payout: {}", hex::encode(payout));
    println!("Configured node(s):");
    for peer in &options.peers {
        println!("  {peer}");
    }
    println!(
        "Using {} GPU(s) with {workers_per_gpu} worker(s) per GPU ({} total):",
        devices.len(),
        devices.len().saturating_mul(workers_per_gpu)
    );
    for device in &devices {
        println!("  GPU {}: {}", device.index, device.label());
    }
    println!("Hashrate unit: 1 H/s = 1 complete ForgeMatrix nonce evaluation per second.");
    println!("The connected node owns synchronization, templates, and block acceptance.");
    println!("Press Ctrl+C to stop.\n");

    let mut statistics = SessionStatistics::new(&devices);
    let mut preferred_peer = None;
    let mut worker_pool = None;
    while !shutdown.load(Ordering::Acquire) {
        let Some((source, template, remote_height)) = wait_for_template(
            &options.peers,
            preferred_peer,
            payout,
            ThinMinerHandshakeIdentity::Devnet,
            limits,
            address_policy,
            &shutdown,
        )?
        else {
            break;
        };
        preferred_peer = Some(source);
        let parent = template.challenge.previous_block;
        let height = template.challenge.height;
        let work = MiningWork::from_devnet_challenge(template.challenge)?;
        println!(
            "Connected to {source} at node height {remote_height}. Mining height {height} on {} GPU(s)...",
            devices.len()
        );

        let mut last_node_check = Instant::now();
        if worker_pool.is_none() {
            worker_pool = Some(PersistentWorkerPool::new(
                cuda.clone(),
                devices.clone(),
                workers_per_gpu,
                options.batch_size,
                &work,
            )?);
        }
        let outcome = worker_pool
            .as_mut()
            .expect("worker pool is initialized")
            .mine(
                work,
                JobMiningConfig {
                    stats_interval: Duration::from_secs(options.stats_seconds),
                },
                Arc::clone(&shutdown),
                &mut statistics,
                &mut || {
                    if last_node_check.elapsed() < PEER_RETRY_INTERVAL {
                        return Ok(WorkStatus::Current);
                    }
                    last_node_check = Instant::now();
                    match fetch_template_from_any(
                        &options.peers,
                        preferred_peer,
                        payout,
                        ThinMinerHandshakeIdentity::Devnet,
                        limits,
                        address_policy,
                    ) {
                        Some((peer, response)) => {
                            preferred_peer = Some(peer);
                            if response.template.challenge.previous_block == parent {
                                Ok(WorkStatus::Current)
                            } else {
                                Ok(WorkStatus::Stale)
                            }
                        }
                        None => Ok(WorkStatus::Disconnected),
                    }
                },
            )?;

        match outcome {
            JobOutcome::Shutdown => break,
            JobOutcome::Stale => {
                statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                println!("Node tip changed; rebuilding work.");
            }
            JobOutcome::Disconnected => {
                println!("Node connection lost; GPU work paused until a node is reachable.");
            }
            JobOutcome::Found { device, proof } => {
                let block = template.into_block(proof);
                let block_id = block.block_id();
                let mut acknowledged = 0_usize;
                let mut rejected = 0_usize;
                let mut busy_on_parent = false;
                for peer in ordered_peers(&options.peers, preferred_peer) {
                    match submit_mined_block_once_with_policy(
                        peer,
                        block.clone(),
                        limits,
                        address_policy,
                    ) {
                        Ok(result) if block_is_active_acknowledgement(&result, block_id) => {
                            acknowledged += 1;
                            preferred_peer = Some(peer);
                        }
                        Ok(result)
                            if block_is_retryable_busy(
                                &result,
                                block_id,
                                block.challenge.previous_block,
                            ) =>
                        {
                            busy_on_parent = true;
                        }
                        Ok(_) => rejected += 1,
                        Err(_) => {}
                    }
                }
                if acknowledged > 0 {
                    statistics.blocks_found = statistics.blocks_found.saturating_add(1);
                    println!(
                        "BLOCK ACCEPTED | GPU {device} | height {height} | {} | node acknowledgement {acknowledged}/{} | session blocks {}",
                        hex::encode(block_id),
                        options.peers.len(),
                        statistics.blocks_found
                    );
                } else if busy_on_parent {
                    println!(
                        "Block found and a node is still on its parent but busy; retrying the exact candidate."
                    );
                    retry_found_block(
                        &options.peers,
                        &mut preferred_peer,
                        block,
                        ThinMinerHandshakeIdentity::Devnet,
                        limits,
                        address_policy,
                        &shutdown,
                        &mut statistics,
                        device,
                    )?;
                } else if rejected > 0 {
                    statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                    statistics.stale_submissions = statistics.stale_submissions.saturating_add(1);
                    println!("Block candidate was rejected as stale; rebuilding work.");
                } else {
                    println!(
                        "Block found, but every node disconnected before acceptance; retrying."
                    );
                    retry_found_block(
                        &options.peers,
                        &mut preferred_peer,
                        block,
                        ThinMinerHandshakeIdentity::Devnet,
                        limits,
                        address_policy,
                        &shutdown,
                        &mut statistics,
                        device,
                    )?;
                }
            }
            #[cfg(feature = "production-v3")]
            JobOutcome::FoundV3 { .. } => {
                bail!("Devnet worker returned a Production V3 claim")
            }
        }
    }
    if let Some(mut pool) = worker_pool {
        pool.stop()?;
    }
    println!("Miner stopped.");
    Ok(())
}

#[cfg(feature = "production-v3")]
fn run_thin_miner_v3(options: ThinMinerOptions) -> Result<()> {
    validate_mining_controls(
        options.batch_size,
        options.workers_per_gpu,
        options.stats_seconds,
    )?;
    if options.batch_size > MAX_PRODUCTION_V3_BATCH_SIZE {
        bail!("Production V3 --batch-size must be between 1 and {MAX_PRODUCTION_V3_BATCH_SIZE}");
    }
    if !matches!(options.workers_per_gpu, AUTO_WORKERS_PER_GPU | 1) {
        bail!(
            "Production V3 uses exactly one authenticated CUDA context per GPU; --workers-per-gpu must be 0 or 1"
        );
    }
    if options.peers.is_empty() {
        bail!("thin mining requires at least one --peer node address");
    }
    let payout = options
        .miner
        .as_deref()
        .ok_or_else(|| anyhow!("thin mining requires --miner with your wallet receive address"))
        .and_then(|value| parse_miner_destination(value).map_err(anyhow::Error::from))?;
    let address_policy = if options.allow_public_peers {
        PeerAddressPolicy::AllowPublic
    } else {
        PeerAddressPolicy::PrivateOnly
    };
    let limits = PeerLimits::default();
    StaticPeerConfig {
        listen_address: DEFAULT_MINER_P2P_ADDRESS,
        peers: options.peers.clone(),
        limits,
        address_policy,
    }
    .validate_client_peers()?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = Arc::clone(&shutdown);
    ctrlc::set_handler(move || shutdown_handler.store(true, Ordering::Release))?;
    let runtime = options.production_v3.into_runtime()?;
    println!("Authenticating and preparing the pinned Production V3 model...");
    let factory = ProductionV3MiningWorkFactory::load(
        runtime.artifacts,
        runtime.scratch_directory,
        runtime.maximum_native_block_rows,
        &shutdown,
    )?;
    let peer_identity = ThinMinerHandshakeIdentity::ProductionV3(factory.peer_identity());
    let cuda = load_cuda(options.cuda_library.as_deref())?;
    let available = cuda.devices().map_err(anyhow::Error::msg)?;
    let devices = select_devices(&available, &options.requested_devices)?;

    println!(
        "Common Foundry Production V3 thin CUDA miner v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "{} library: {}",
        cuda.backend().name(),
        cuda.path().display()
    );
    println!("Payout: {}", hex::encode(payout));
    println!("Configured node(s):");
    for peer in &options.peers {
        println!("  {peer}");
    }
    println!(
        "Using {} GPU(s), one authenticated production evaluator per GPU:",
        devices.len()
    );
    for device in &devices {
        println!("  GPU {}: {}", device.index, device.label());
    }
    println!("Hashrate unit: 1 H/s = 1 complete Production V3 nonce evaluation per second.");
    println!("Winning CUDA claims are CPU-replayed before Layout V5 proof construction.");
    println!("Press Ctrl+C to stop.\n");

    let mut statistics = SessionStatistics::new(&devices);
    let mut preferred_peer = None;
    let mut worker_pool = None;
    while !shutdown.load(Ordering::Acquire) {
        let Some((source, template, remote_height)) = wait_for_template(
            &options.peers,
            preferred_peer,
            payout,
            peer_identity,
            limits,
            address_policy,
            &shutdown,
        )?
        else {
            break;
        };
        preferred_peer = Some(source);
        let parent = template.challenge.previous_block;
        let height = template.challenge.height;
        let work = factory.work(template.challenge)?;
        println!(
            "Connected to {source} at node height {remote_height}. Mining Production V3 height {height} on {} GPU(s)...",
            devices.len()
        );
        if worker_pool.is_none() {
            worker_pool = Some(ProductionWorkerPool::new(
                cuda.clone(),
                devices.clone(),
                options.batch_size,
                &work,
                &factory,
                Arc::clone(&shutdown),
            )?);
        }
        let mut last_node_check = Instant::now();
        let search_started = Instant::now();
        let search_attempt_base = statistics.total_attempts();
        let outcome = worker_pool
            .as_mut()
            .expect("Production V3 worker pool is initialized")
            .mine(
                work.clone(),
                JobMiningConfig {
                    stats_interval: Duration::from_secs(options.stats_seconds),
                },
                Arc::clone(&shutdown),
                &mut statistics,
                &mut || {
                    if last_node_check.elapsed() < PEER_RETRY_INTERVAL {
                        return Ok(WorkStatus::Current);
                    }
                    last_node_check = Instant::now();
                    match fetch_template_from_any(
                        &options.peers,
                        preferred_peer,
                        payout,
                        peer_identity,
                        limits,
                        address_policy,
                    ) {
                        Some((peer, response)) => {
                            preferred_peer = Some(peer);
                            if response.template.challenge.previous_block == parent {
                                Ok(WorkStatus::Current)
                            } else {
                                Ok(WorkStatus::Stale)
                            }
                        }
                        None => Ok(WorkStatus::Disconnected),
                    }
                },
            )?;
        match outcome {
            JobOutcome::Shutdown => break,
            JobOutcome::Stale => {
                statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                println!("Node tip changed; rebuilding Production V3 work.");
            }
            JobOutcome::Disconnected => {
                println!("Node connection lost; GPU work paused until a node is reachable.");
            }
            JobOutcome::FoundV3 {
                device,
                claim,
                replay_accumulators,
            } => {
                let search_seconds = search_started.elapsed().as_secs_f64().max(f64::EPSILON);
                let search_evaluations = statistics
                    .total_attempts()
                    .saturating_sub(search_attempt_base);
                let replay_mode = if replay_accumulators.is_some() {
                    "GPU-accelerated replay"
                } else {
                    "CPU replay"
                };
                println!(
                    "GPU {device} found a target nonce after {search_evaluations} evaluations in {search_seconds:.1}s ({:.2} H/s); {replay_mode} and Layout V5 proof construction started.",
                    search_evaluations as f64 / search_seconds
                );
                let accelerated_replay = replay_accumulators
                    .map(cmfd_consensus::BlsDoryV3AcceleratedReplayAccumulators::new);
                let proof_stats_height = work.challenge().height;
                let proof_stats_interval = Duration::from_secs(options.stats_seconds);
                let proof_work = work.clone();
                let mut last_proof_node_check = Instant::now()
                    .checked_sub(PEER_RETRY_INTERVAL)
                    .unwrap_or_else(Instant::now);
                let proof = match run_production_proof_while_current(
                    Arc::clone(&shutdown),
                    &mut || {
                        if last_proof_node_check.elapsed() < PEER_RETRY_INTERVAL {
                            return Ok(WorkStatus::Current);
                        }
                        last_proof_node_check = Instant::now();
                        match fetch_template_from_any(
                            &options.peers,
                            preferred_peer,
                            payout,
                            peer_identity,
                            limits,
                            address_policy,
                        ) {
                            Some((peer, response)) => {
                                preferred_peer = Some(peer);
                                if response.template.challenge.previous_block == parent {
                                    Ok(WorkStatus::Current)
                                } else {
                                    Ok(WorkStatus::Stale)
                                }
                            }
                            None => Ok(WorkStatus::Disconnected),
                        }
                    },
                    &mut || {
                        statistics.report_if_due(
                            &devices,
                            proof_stats_height,
                            proof_stats_interval,
                        );
                    },
                    move |proof_cancel| {
                        proof_work
                            .prove_v3_winning_nonce_claim_with_accelerated_replay(
                                claim,
                                accelerated_replay,
                                &proof_cancel,
                            )
                            .map_err(Into::into)
                    },
                )? {
                    ProofRunOutcome::Completed(proof) => proof,
                    ProofRunOutcome::Stale => {
                        statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                        println!("Node tip changed during proof construction; rebuilding work.");
                        continue;
                    }
                    ProofRunOutcome::Disconnected => {
                        println!(
                            "Node connection was lost during proof construction; rebuilding work."
                        );
                        continue;
                    }
                    ProofRunOutcome::Shutdown => break,
                };
                let block = template.into_block(proof);
                println!(
                    "Production V3 proof completed; submitting and retaining the exact block across Busy or reconnect."
                );
                retry_found_block(
                    &options.peers,
                    &mut preferred_peer,
                    block,
                    peer_identity,
                    limits,
                    address_policy,
                    &shutdown,
                    &mut statistics,
                    device,
                )?;
            }
            JobOutcome::Found { .. } => {
                bail!("Production V3 worker returned a Devnet V2 proof")
            }
        }
    }
    if let Some(mut pool) = worker_pool {
        pool.stop()?;
    }
    println!("Miner stopped.");
    Ok(())
}

fn validate_mining_controls(
    batch_size: u32,
    workers_per_gpu: usize,
    stats_seconds: u64,
) -> Result<()> {
    if batch_size == 0 || batch_size > MAX_BATCH_SIZE {
        bail!("--batch-size must be between 1 and {MAX_BATCH_SIZE}");
    }
    if workers_per_gpu > MAX_WORKERS_PER_GPU {
        bail!("--workers-per-gpu must be between 0 and {MAX_WORKERS_PER_GPU}");
    }
    if stats_seconds == 0 {
        bail!("--stats-seconds must be greater than zero");
    }
    Ok(())
}

fn resolve_workers_per_gpu(requested: usize, device_count: usize) -> Result<usize> {
    let host_threads = thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    resolve_workers_per_gpu_for_host(requested, device_count, host_threads)
}

fn resolve_workers_per_gpu_for_host(
    requested: usize,
    device_count: usize,
    host_threads: usize,
) -> Result<usize> {
    if device_count == 0 {
        bail!("cannot size mining workers without a selected GPU");
    }
    if requested != AUTO_WORKERS_PER_GPU {
        return Ok(requested);
    }
    Ok((host_threads.max(1) / device_count).clamp(1, MAX_WORKERS_PER_GPU))
}

fn ordered_peers(peers: &[SocketAddr], preferred: Option<SocketAddr>) -> Vec<SocketAddr> {
    preferred
        .into_iter()
        .chain(
            peers
                .iter()
                .copied()
                .filter(|peer| Some(*peer) != preferred),
        )
        .collect()
}

fn block_is_active_acknowledgement(
    result: &cmfd_node::peer::BlockSubmissionResult,
    block_id: [u8; 32],
) -> bool {
    matches!(
        result.status,
        BlockSubmissionStatus::Accepted | BlockSubmissionStatus::AlreadyKnown
    ) && result.block_id == block_id
        && result.peer_tip == block_id
}

fn block_is_retryable_busy(
    result: &cmfd_node::peer::BlockSubmissionResult,
    block_id: [u8; 32],
    parent: [u8; 32],
) -> bool {
    result.block_id == block_id
        && result.status == BlockSubmissionStatus::Busy
        && result.peer_tip == parent
}

fn fetch_template_from_any(
    peers: &[SocketAddr],
    preferred: Option<SocketAddr>,
    payout: [u8; 32],
    identity: ThinMinerHandshakeIdentity,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Option<(SocketAddr, cmfd_node::p2p::MiningTemplateResponse)> {
    ordered_peers(peers, preferred)
        .into_iter()
        .find_map(|peer| {
            identity
                .request_template(peer, payout, limits, address_policy)
                .ok()
                .map(|response| (peer, response))
        })
}

fn wait_for_template(
    peers: &[SocketAddr],
    preferred: Option<SocketAddr>,
    payout: [u8; 32],
    identity: ThinMinerHandshakeIdentity,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    shutdown: &AtomicBool,
) -> Result<Option<(SocketAddr, MiningTemplate, u64)>> {
    while !shutdown.load(Ordering::Acquire) {
        if let Some((peer, response)) =
            fetch_template_from_any(peers, preferred, payout, identity, limits, address_policy)
        {
            return Ok(Some((
                peer,
                response.template,
                response.remote_hello.height,
            )));
        }
        println!(
            "Waiting for a configured node; retrying in {} seconds...",
            PEER_RETRY_INTERVAL.as_secs()
        );
        if !interruptible_wait(PEER_RETRY_INTERVAL, shutdown) {
            return Ok(None);
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn retry_found_block(
    peers: &[SocketAddr],
    preferred: &mut Option<SocketAddr>,
    block: cmfd_consensus::Block,
    identity: ThinMinerHandshakeIdentity,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    shutdown: &Arc<AtomicBool>,
    statistics: &mut SessionStatistics,
    device: i32,
) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(FOUND_BLOCK_RETRY_BUDGET)
        .ok_or_else(|| anyhow!("found-block retry deadline overflow"))?;
    let cancellation = Arc::clone(shutdown);
    let report = retry_exact_block_with(
        peers,
        *preferred,
        &block,
        deadline,
        shutdown,
        |peer, candidate, deadline| match identity.submit_before_cancellable(
            peer,
            candidate,
            limits,
            address_policy,
            deadline,
            Arc::clone(&cancellation),
        ) {
            Ok(result) => ExactBlockSubmissionAttempt::Response(result),
            Err(error) if error.is_cancelled() || error.is_transport_disconnect() => {
                ExactBlockSubmissionAttempt::Disconnected(error.to_string())
            }
            Err(error) => ExactBlockSubmissionAttempt::ProtocolViolation(error.to_string()),
        },
        interruptible_wait,
        Instant::now,
    );
    record_exact_retry_report(statistics, &report);
    if let Some((peer, detail)) = &report.last_protocol_violation {
        println!(
            "SUBMISSION PROTOCOL ERROR | peer {peer} | {detail} | observed {}",
            report.protocol_violations
        );
    }
    if let Some((peer, detail)) = &report.last_disconnect {
        println!(
            "Submission transport disconnected {} time(s); last peer {peer}: {detail}",
            report.disconnects
        );
    }
    match report.outcome {
        ExactBlockRetryOutcome::Accepted(peer) => {
            *preferred = Some(peer);
            println!(
                "BLOCK ACCEPTED | GPU {device} | height {} | {} | node {peer} | session blocks {}",
                block.challenge.height,
                hex::encode(block.block_id()),
                statistics.blocks_found
            );
        }
        ExactBlockRetryOutcome::Stale(peer_tip) => {
            println!(
                "Exact block retry stopped because the node tip changed to {}; rebuilding work.",
                hex::encode(peer_tip)
            );
        }
        ExactBlockRetryOutcome::Rejected => {
            println!("Exact block candidate was terminally rejected; rebuilding work.");
        }
        ExactBlockRetryOutcome::ProtocolViolation { peer, detail } => {
            println!(
                "Exact block retry stopped on an incompatible peer response from {peer}: {detail}"
            );
        }
        ExactBlockRetryOutcome::BudgetExhausted => {
            println!(
                "Exact block {} was abandoned after the bounded {}-second Busy/reconnect retry budget expired.",
                hex::encode(block.block_id()),
                FOUND_BLOCK_RETRY_BUDGET.as_secs()
            );
        }
        ExactBlockRetryOutcome::Stopped => {
            println!("Exact block retry interrupted by miner shutdown.");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExactBlockRetryOutcome {
    Accepted(SocketAddr),
    Stale([u8; 32]),
    Rejected,
    ProtocolViolation { peer: SocketAddr, detail: String },
    BudgetExhausted,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExactBlockSubmissionAttempt {
    Response(cmfd_node::peer::BlockSubmissionResult),
    Disconnected(String),
    ProtocolViolation(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactBlockRetryReport {
    outcome: ExactBlockRetryOutcome,
    disconnects: u64,
    protocol_violations: u64,
    last_disconnect: Option<(SocketAddr, String)>,
    last_protocol_violation: Option<(SocketAddr, String)>,
}

fn exact_block_retry_report(
    outcome: ExactBlockRetryOutcome,
    disconnects: u64,
    protocol_violations: u64,
    last_disconnect: Option<(SocketAddr, String)>,
    last_protocol_violation: Option<(SocketAddr, String)>,
) -> ExactBlockRetryReport {
    ExactBlockRetryReport {
        outcome,
        disconnects,
        protocol_violations,
        last_disconnect,
        last_protocol_violation,
    }
}

fn record_exact_retry_report(statistics: &mut SessionStatistics, report: &ExactBlockRetryReport) {
    statistics.submission_disconnects = statistics
        .submission_disconnects
        .saturating_add(report.disconnects);
    statistics.submission_protocol_errors = statistics
        .submission_protocol_errors
        .saturating_add(report.protocol_violations);
    match &report.outcome {
        ExactBlockRetryOutcome::Accepted(_) => {
            statistics.blocks_found = statistics.blocks_found.saturating_add(1);
        }
        ExactBlockRetryOutcome::Stale(_) | ExactBlockRetryOutcome::Rejected => {
            statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
            statistics.stale_submissions = statistics.stale_submissions.saturating_add(1);
        }
        ExactBlockRetryOutcome::BudgetExhausted => {
            statistics.abandoned_submissions = statistics.abandoned_submissions.saturating_add(1);
        }
        ExactBlockRetryOutcome::ProtocolViolation { .. } | ExactBlockRetryOutcome::Stopped => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn retry_exact_block_with<Submit, Wait, Now>(
    peers: &[SocketAddr],
    preferred: Option<SocketAddr>,
    block: &cmfd_consensus::Block,
    deadline: Instant,
    shutdown: &AtomicBool,
    mut submit: Submit,
    mut wait: Wait,
    mut now: Now,
) -> ExactBlockRetryReport
where
    Submit: FnMut(SocketAddr, cmfd_consensus::Block, Instant) -> ExactBlockSubmissionAttempt,
    Wait: FnMut(Duration, &AtomicBool) -> bool,
    Now: FnMut() -> Instant,
{
    let block_id = block.block_id();
    let parent = block.challenge.previous_block;
    let mut disconnects = 0_u64;
    let mut protocol_violations = 0_u64;
    let mut last_disconnect = None;
    let mut last_protocol_violation = None;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return exact_block_retry_report(
                ExactBlockRetryOutcome::Stopped,
                disconnects,
                protocol_violations,
                last_disconnect,
                last_protocol_violation,
            );
        }
        if now() >= deadline {
            return exact_block_retry_report(
                ExactBlockRetryOutcome::BudgetExhausted,
                disconnects,
                protocol_violations,
                last_disconnect,
                last_protocol_violation,
            );
        }
        let mut busy_on_parent = false;
        let mut rejected = false;
        let mut round_protocol_violation = None;
        for peer in ordered_peers(peers, preferred) {
            if shutdown.load(Ordering::Acquire) {
                return exact_block_retry_report(
                    ExactBlockRetryOutcome::Stopped,
                    disconnects,
                    protocol_violations,
                    last_disconnect,
                    last_protocol_violation,
                );
            }
            let attempt = submit(peer, block.clone(), deadline);
            if shutdown.load(Ordering::Acquire) {
                return exact_block_retry_report(
                    ExactBlockRetryOutcome::Stopped,
                    disconnects,
                    protocol_violations,
                    last_disconnect,
                    last_protocol_violation,
                );
            }
            match attempt {
                ExactBlockSubmissionAttempt::Response(result)
                    if block_is_active_acknowledgement(&result, block_id) =>
                {
                    return exact_block_retry_report(
                        ExactBlockRetryOutcome::Accepted(peer),
                        disconnects,
                        protocol_violations,
                        last_disconnect,
                        last_protocol_violation,
                    );
                }
                ExactBlockSubmissionAttempt::Response(result) if result.block_id != block_id => {
                    let detail = format!(
                        "block-submission response ID {} does not match {}",
                        hex::encode(result.block_id),
                        hex::encode(block_id)
                    );
                    protocol_violations = protocol_violations.saturating_add(1);
                    last_protocol_violation = Some((peer, detail.clone()));
                    round_protocol_violation.get_or_insert((peer, detail));
                }
                ExactBlockSubmissionAttempt::Response(result) if result.peer_tip != parent => {
                    return exact_block_retry_report(
                        ExactBlockRetryOutcome::Stale(result.peer_tip),
                        disconnects,
                        protocol_violations,
                        last_disconnect,
                        last_protocol_violation,
                    );
                }
                ExactBlockSubmissionAttempt::Response(result)
                    if block_is_retryable_busy(&result, block_id, parent) =>
                {
                    busy_on_parent = true;
                }
                ExactBlockSubmissionAttempt::Response(result)
                    if result.status == BlockSubmissionStatus::Rejected =>
                {
                    rejected = true;
                }
                ExactBlockSubmissionAttempt::Response(result) => {
                    let detail = format!(
                        "incompatible {:?} response for exact block {} on parent {}",
                        result.status,
                        hex::encode(block_id),
                        hex::encode(parent)
                    );
                    protocol_violations = protocol_violations.saturating_add(1);
                    last_protocol_violation = Some((peer, detail.clone()));
                    round_protocol_violation.get_or_insert((peer, detail));
                }
                ExactBlockSubmissionAttempt::Disconnected(detail) => {
                    disconnects = disconnects.saturating_add(1);
                    last_disconnect = Some((peer, detail));
                }
                ExactBlockSubmissionAttempt::ProtocolViolation(detail) => {
                    protocol_violations = protocol_violations.saturating_add(1);
                    last_protocol_violation = Some((peer, detail.clone()));
                    round_protocol_violation.get_or_insert((peer, detail));
                }
            }
        }
        if !busy_on_parent {
            if rejected {
                return exact_block_retry_report(
                    ExactBlockRetryOutcome::Rejected,
                    disconnects,
                    protocol_violations,
                    last_disconnect,
                    last_protocol_violation,
                );
            }
            if let Some((peer, detail)) = round_protocol_violation {
                return exact_block_retry_report(
                    ExactBlockRetryOutcome::ProtocolViolation { peer, detail },
                    disconnects,
                    protocol_violations,
                    last_disconnect,
                    last_protocol_violation,
                );
            }
        }
        let remaining = deadline.saturating_duration_since(now());
        if remaining.is_zero() {
            return exact_block_retry_report(
                ExactBlockRetryOutcome::BudgetExhausted,
                disconnects,
                protocol_violations,
                last_disconnect,
                last_protocol_violation,
            );
        }
        if !wait(PEER_RETRY_INTERVAL.min(remaining), shutdown) {
            return exact_block_retry_report(
                ExactBlockRetryOutcome::Stopped,
                disconnects,
                protocol_violations,
                last_disconnect,
                last_protocol_violation,
            );
        }
    }
}

fn interruptible_wait(duration: Duration, shutdown: &AtomicBool) -> bool {
    let Some(deadline) = Instant::now().checked_add(duration) else {
        return false;
    };
    while Instant::now() < deadline {
        if shutdown.load(Ordering::Acquire) {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
    true
}

fn run_full_node_miner(options: FullNodeMinerOptions) -> Result<()> {
    if matches!(COMPILED_NETWORK_PROFILE.proof, ProofProfile::ProductionV3) {
        bail!(
            "ProductionV3 full-node mining is disabled because it does not install the required external proof-verifier worker; use `cmfd-miner mine --peer <node>:{} ...` against a packaged ProductionV3 node",
            COMPILED_NETWORK_PROFILE.p2p_port
        );
    }
    match mining_runtime(COMPILED_NETWORK_PROFILE) {
        MiningRuntime::DevnetV2 => run_full_node_miner_v2(options),
        MiningRuntime::ProductionV3 => {
            #[cfg(feature = "production-v3")]
            {
                run_full_node_miner_v3(options)
            }
            #[cfg(not(feature = "production-v3"))]
            {
                let _ = options;
                bail!(
                    "this binary selects Production V3 but was built without the production-v3 feature"
                )
            }
        }
        MiningRuntime::ProductionV4 => {
            let _ = options;
            bail!(
                "ProductionV4 embedded mining is not supported; run a V4 node and use the template/prover submission flow"
            )
        }
    }
}

fn run_full_node_miner_v2(options: FullNodeMinerOptions) -> Result<()> {
    validate_mining_controls(
        options.batch_size,
        options.workers_per_gpu,
        options.stats_seconds,
    )?;

    let cuda = load_cuda(options.cuda_library.as_deref())?;
    let available = cuda.devices().map_err(anyhow::Error::msg)?;
    let devices = select_devices(&available, &options.requested_devices)?;
    let workers_per_gpu = resolve_workers_per_gpu(options.workers_per_gpu, devices.len())?;
    let address_policy = if options.allow_public_peers {
        PeerAddressPolicy::AllowPublic
    } else {
        PeerAddressPolicy::PrivateOnly
    };

    let mut node = Node::open(&options.data_dir)
        .with_context(|| format!("open miner data directory {}", options.data_dir.display()))?;
    node.set_public_peer_mode(options.allow_public_peers);
    let payout = match options.miner.as_deref() {
        Some(value) => parse_miner_destination(value)?,
        None => node.wallet_destination(),
    };
    let shared = Arc::new(Mutex::new(node));
    let limits = PeerLimits::default();
    let p2p_socket = TcpListener::bind(options.p2p_bind)
        .with_context(|| format!("bind miner P2P listener at {}", options.p2p_bind))?;
    let p2p_address = p2p_socket.local_addr()?;
    let inbound = spawn_inbound_listener_with_policy(
        Arc::clone(&shared),
        p2p_socket,
        limits,
        address_policy,
    )?;
    let peer_config = StaticPeerConfig {
        listen_address: p2p_address,
        peers: options.peers,
        limits,
        address_policy,
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = Arc::clone(&shutdown);
    ctrlc::set_handler(move || shutdown_handler.store(true, Ordering::Release))?;

    println!(
        "Common Foundry standalone CUDA miner v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "Network: {} ({})",
        COMPILED_NETWORK_PROFILE.short_name(),
        COMPILED_NETWORK_PROFILE.proof.profile_name()
    );
    println!(
        "{} library: {}",
        cuda.backend().name(),
        cuda.path().display()
    );
    println!("P2P listener: {p2p_address}");
    println!("Payout: {}", hex::encode(payout));
    println!(
        "Using {} GPU(s) with {workers_per_gpu} worker(s) per GPU ({} total):",
        devices.len(),
        devices.len().saturating_mul(workers_per_gpu)
    );
    for device in &devices {
        println!("  GPU {}: {}", device.index, device.label());
    }
    println!("Hashrate unit: 1 H/s = 1 complete ForgeMatrix nonce evaluation per second.");
    println!("Press Ctrl+C to stop.\n");

    if !synchronize_before_mining(Arc::clone(&shared), &peer_config, &shutdown)? {
        let _ = inbound.stop();
        println!("Miner stopped.");
        return Ok(());
    }

    let poller = if peer_config.peers.is_empty() {
        None
    } else {
        Some(spawn_static_peer_polling(
            Arc::clone(&shared),
            peer_config.clone(),
            Duration::from_secs(2),
        )?)
    };

    let mining_result = continuous_mining(
        Arc::clone(&shared),
        cuda,
        devices,
        ContinuousMiningConfig {
            payout,
            peers: peer_config,
            batch_size: options.batch_size,
            workers_per_gpu,
            stats_interval: Duration::from_secs(options.stats_seconds),
        },
        shutdown,
    );
    let poll_result = match poller {
        Some(poller) => poller.stop().map_err(anyhow::Error::from),
        None => Ok(()),
    };
    let inbound_result = inbound.stop().map_err(anyhow::Error::from);
    mining_result?;
    poll_result?;
    inbound_result?;
    Ok(())
}

#[cfg(feature = "production-v3")]
fn run_full_node_miner_v3(options: FullNodeMinerOptions) -> Result<()> {
    validate_mining_controls(
        options.batch_size,
        options.workers_per_gpu,
        options.stats_seconds,
    )?;
    if options.batch_size > MAX_PRODUCTION_V3_BATCH_SIZE {
        bail!("Production V3 --batch-size must be between 1 and {MAX_PRODUCTION_V3_BATCH_SIZE}");
    }
    if !matches!(options.workers_per_gpu, AUTO_WORKERS_PER_GPU | 1) {
        bail!(
            "Production V3 uses exactly one authenticated CUDA context per GPU; --workers-per-gpu must be 0 or 1"
        );
    }
    let runtime = options.production_v3.into_runtime()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = Arc::clone(&shutdown);
    ctrlc::set_handler(move || shutdown_handler.store(true, Ordering::Release))?;

    let cuda = load_cuda(options.cuda_library.as_deref())?;
    let available = cuda.devices().map_err(anyhow::Error::msg)?;
    let devices = select_devices(&available, &options.requested_devices)?;
    let address_policy = if options.allow_public_peers {
        PeerAddressPolicy::AllowPublic
    } else {
        PeerAddressPolicy::PrivateOnly
    };
    let mut node = Node::open_with_artifacts(&options.data_dir, Some(&runtime.artifacts))
        .with_context(|| format!("open miner data directory {}", options.data_dir.display()))?;
    node.set_public_peer_mode(options.allow_public_peers);
    let payout = match options.miner.as_deref() {
        Some(value) => parse_miner_destination(value)?,
        None => node.wallet_destination(),
    };
    println!("Preparing reusable Production V3 fixed-model proof state...");
    let factory = node.production_v3_mining_work_factory(
        runtime.scratch_directory,
        runtime.maximum_native_block_rows,
        &shutdown,
    )?;
    let shared = Arc::new(Mutex::new(node));
    let limits = PeerLimits::default();
    let p2p_socket = TcpListener::bind(options.p2p_bind)
        .with_context(|| format!("bind miner P2P listener at {}", options.p2p_bind))?;
    let p2p_address = p2p_socket.local_addr()?;
    let inbound = spawn_inbound_listener_with_policy(
        Arc::clone(&shared),
        p2p_socket,
        limits,
        address_policy,
    )?;
    let peer_config = StaticPeerConfig {
        listen_address: p2p_address,
        peers: options.peers,
        limits,
        address_policy,
    };

    println!(
        "Common Foundry Production V3 standalone CUDA miner v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "{} library: {}",
        cuda.backend().name(),
        cuda.path().display()
    );
    println!("P2P listener: {p2p_address}");
    println!("Payout: {}", hex::encode(payout));
    println!(
        "Using {} GPU(s), one authenticated production evaluator per GPU:",
        devices.len()
    );
    for device in &devices {
        println!("  GPU {}: {}", device.index, device.label());
    }
    println!("Hashrate unit: 1 H/s = 1 complete Production V3 nonce evaluation per second.");
    println!("Winning CUDA claims are CPU-replayed before Layout V5 proof construction.");
    println!("Press Ctrl+C to stop.\n");

    if !synchronize_before_mining(Arc::clone(&shared), &peer_config, &shutdown)? {
        let _ = inbound.stop();
        println!("Miner stopped.");
        return Ok(());
    }
    let poller = if peer_config.peers.is_empty() {
        None
    } else {
        Some(spawn_static_peer_polling(
            Arc::clone(&shared),
            peer_config.clone(),
            Duration::from_secs(2),
        )?)
    };
    let mining_result = continuous_production_mining(
        Arc::clone(&shared),
        cuda,
        devices,
        ContinuousMiningConfig {
            payout,
            peers: peer_config,
            batch_size: options.batch_size,
            workers_per_gpu: 1,
            stats_interval: Duration::from_secs(options.stats_seconds),
        },
        shutdown,
        factory,
    );
    let poll_result = match poller {
        Some(poller) => poller.stop().map_err(anyhow::Error::from),
        None => Ok(()),
    };
    let inbound_result = inbound.stop().map_err(anyhow::Error::from);
    mining_result?;
    poll_result?;
    inbound_result?;
    Ok(())
}

fn synchronize_before_mining(
    node: Arc<Mutex<Node>>,
    config: &StaticPeerConfig,
    shutdown: &AtomicBool,
) -> Result<bool> {
    if config.peers.is_empty() {
        return Ok(true);
    }

    println!("Synchronizing miner node before starting GPU work...");
    let mut selected_peer = None;
    let mut last_reported = None;

    while !shutdown.load(Ordering::Acquire) {
        let candidates: Vec<_> = selected_peer
            .into_iter()
            .chain(
                config
                    .peers
                    .iter()
                    .copied()
                    .filter(|peer| Some(*peer) != selected_peer),
            )
            .collect();
        let mut reachable = false;

        for peer in candidates {
            match sync_from_peer_once_with_policy(
                Arc::clone(&node),
                peer,
                config.limits,
                config.address_policy,
            ) {
                Ok(report) => {
                    reachable = true;
                    selected_peer = Some(peer);
                    let local = node
                        .lock()
                        .map_err(|_| anyhow!("node mutex is poisoned"))?
                        .peer_hello();
                    if local.cumulative_work >= report.remote_hello.cumulative_work {
                        println!(
                            "Node synchronized with {peer} at height {}. Starting GPUs.\n",
                            local.height
                        );
                        return Ok(true);
                    }
                    let progress = (local.height, report.remote_hello.height);
                    if last_reported != Some(progress) {
                        println!(
                            "Syncing from {peer}: height {} of {}...",
                            local.height, report.remote_hello.height
                        );
                        last_reported = Some(progress);
                    }
                    break;
                }
                Err(_) => {
                    if selected_peer == Some(peer) {
                        selected_peer = None;
                    }
                }
            }
        }

        if !reachable {
            println!(
                "Waiting for a configured node; retrying in {} seconds...",
                PEER_RETRY_INTERVAL.as_secs()
            );
            for _ in 0..(PEER_RETRY_INTERVAL.as_millis() / 100) {
                if shutdown.load(Ordering::Acquire) {
                    return Ok(false);
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(false)
}

fn submit_local_found_block(
    node: &Arc<Mutex<Node>>,
    block: &cmfd_consensus::Block,
    shutdown: &AtomicBool,
) -> Result<bool> {
    while !shutdown.load(Ordering::Acquire) {
        let tip = node
            .lock()
            .map_err(|_| anyhow!("node mutex is poisoned"))?
            .peer_hello()
            .tip;
        if tip != block.challenge.previous_block {
            return Ok(tip == block.block_id());
        }
        match submit_shared_tip_block(node, block.clone(), unix_time_seconds()?) {
            Ok(_) => return Ok(true),
            Err(NodeError::DuplicateBlock(_)) => {
                let tip = node
                    .lock()
                    .map_err(|_| anyhow!("node mutex is poisoned"))?
                    .peer_hello()
                    .tip;
                return Ok(tip == block.block_id());
            }
            Err(NodeError::StaleBlockAdmission | NodeError::UnknownParent(_)) => return Ok(false),
            Err(NodeError::ProofVerifierShuttingDown) => return Ok(false),
            Err(error) if error.client_error().retryable => {
                if !interruptible_wait(Duration::from_millis(100), shutdown) {
                    return Ok(false);
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

fn continuous_mining(
    node: Arc<Mutex<Node>>,
    cuda: CudaLibrary,
    devices: Vec<CudaDevice>,
    config: ContinuousMiningConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let mut statistics = SessionStatistics::new(&devices);
    let mut worker_pool = None;
    while !shutdown.load(Ordering::Acquire) {
        let job = {
            let node = node.lock().map_err(|_| anyhow!("node mutex is poisoned"))?;
            node.build_mining_job(config.payout, unix_time_seconds()?)?
        };
        println!(
            "Mining height {} on {} GPU(s)...",
            job.challenge().height,
            devices.len()
        );
        let expected_parent = hex::encode(job.challenge().previous_block);
        let work = job.work();
        if worker_pool.is_none() {
            worker_pool = Some(PersistentWorkerPool::new(
                cuda.clone(),
                devices.clone(),
                config.workers_per_gpu,
                config.batch_size,
                &work,
            )?);
        }
        match worker_pool
            .as_mut()
            .expect("worker pool is initialized")
            .mine(
                work,
                JobMiningConfig {
                    stats_interval: config.stats_interval,
                },
                Arc::clone(&shutdown),
                &mut statistics,
                &mut || {
                    let current_tip = node
                        .lock()
                        .map_err(|_| anyhow!("node mutex is poisoned"))?
                        .status()?
                        .tip;
                    if current_tip == expected_parent {
                        Ok(WorkStatus::Current)
                    } else {
                        Ok(WorkStatus::Stale)
                    }
                },
            )? {
            JobOutcome::Shutdown => break,
            JobOutcome::Disconnected => {
                println!("Embedded node became unavailable; rebuilding work.");
            }
            JobOutcome::Stale => {
                statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                println!("New chain tip received; rebuilding work.");
            }
            JobOutcome::Found { device, proof } => {
                let Some(block) = job.build_block_if_chain_valid(&proof)? else {
                    statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                    println!("Candidate no longer met the chain target; rebuilding work.");
                    continue;
                };
                let block_id = block.block_id();
                let height = block.challenge.height;
                let expected_parent = hex::encode(block.challenge.previous_block);
                let parent_is_current = node
                    .lock()
                    .map_err(|_| anyhow!("node mutex is poisoned"))?
                    .status()?
                    .tip
                    == expected_parent;
                let accepted = parent_is_current
                    && submit_local_found_block(&node, &block, shutdown.as_ref())?;
                if accepted {
                    statistics.blocks_found = statistics.blocks_found.saturating_add(1);
                    let relayed = config
                        .peers
                        .peers
                        .iter()
                        .filter(|peer| {
                            relay_blocks_to_peer_once_with_policy(
                                Arc::clone(&node),
                                **peer,
                                config.peers.limits,
                                config.peers.address_policy,
                            )
                            .is_ok_and(|report| report.peer_tip == block_id)
                        })
                        .count();
                    if config.peers.peers.is_empty() || relayed > 0 {
                        let relay = match (relayed, config.peers.peers.len()) {
                            (_, 0) => "local mode".to_owned(),
                            (relayed, total) if relayed == total => {
                                format!("node sync {relayed}/{total}")
                            }
                            (relayed, total) => format!(
                                "node sync {relayed}/{total} (other peers retry automatically)"
                            ),
                        };
                        println!(
                            "BLOCK FOUND | GPU {device} | height {height} | {} | {relay} | session blocks {blocks_found}",
                            hex::encode(block_id),
                            blocks_found = statistics.blocks_found
                        );
                    } else {
                        println!(
                            "BLOCK FOUND LOCALLY | GPU {device} | height {height} | {} | node sync pending {relayed}/{} (automatic retry) | session blocks {blocks_found}",
                            hex::encode(block_id),
                            config.peers.peers.len(),
                            blocks_found = statistics.blocks_found
                        );
                    }
                } else {
                    println!("Candidate became stale before submission; rebuilding work.");
                }
            }
            #[cfg(feature = "production-v3")]
            JobOutcome::FoundV3 { .. } => {
                bail!("Devnet worker returned a Production V3 claim")
            }
        }
    }
    if let Some(mut pool) = worker_pool {
        pool.stop()?;
    }
    println!("Miner stopped.");
    Ok(())
}

#[cfg(feature = "production-v3")]
fn continuous_production_mining(
    node: Arc<Mutex<Node>>,
    cuda: CudaLibrary,
    devices: Vec<CudaDevice>,
    config: ContinuousMiningConfig,
    shutdown: Arc<AtomicBool>,
    factory: ProductionV3MiningWorkFactory,
) -> Result<()> {
    let mut statistics = SessionStatistics::new(&devices);
    let mut worker_pool = None;
    while !shutdown.load(Ordering::Acquire) {
        let job = {
            let node = node.lock().map_err(|_| anyhow!("node mutex is poisoned"))?;
            node.build_mining_job(config.payout, unix_time_seconds()?)?
        };
        println!(
            "Mining Production V3 height {} on {} GPU(s)...",
            job.challenge().height,
            devices.len()
        );
        let expected_parent = hex::encode(job.challenge().previous_block);
        let work = factory.work(*job.challenge())?;
        if worker_pool.is_none() {
            worker_pool = Some(ProductionWorkerPool::new(
                cuda.clone(),
                devices.clone(),
                config.batch_size,
                &work,
                &factory,
                Arc::clone(&shutdown),
            )?);
        }
        let search_started = Instant::now();
        let search_attempt_base = statistics.total_attempts();
        let outcome = worker_pool
            .as_mut()
            .expect("Production V3 worker pool is initialized")
            .mine(
                work.clone(),
                JobMiningConfig {
                    stats_interval: config.stats_interval,
                },
                Arc::clone(&shutdown),
                &mut statistics,
                &mut || {
                    let current_tip = node
                        .lock()
                        .map_err(|_| anyhow!("node mutex is poisoned"))?
                        .status()?
                        .tip;
                    if current_tip == expected_parent {
                        Ok(WorkStatus::Current)
                    } else {
                        Ok(WorkStatus::Stale)
                    }
                },
            )?;
        match outcome {
            JobOutcome::Shutdown => break,
            JobOutcome::Disconnected => {
                println!("Embedded node became unavailable; rebuilding Production V3 work.");
            }
            JobOutcome::Stale => {
                statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                println!("New chain tip received; rebuilding Production V3 work.");
            }
            JobOutcome::FoundV3 {
                device,
                claim,
                replay_accumulators,
            } => {
                let search_seconds = search_started.elapsed().as_secs_f64().max(f64::EPSILON);
                let search_evaluations = statistics
                    .total_attempts()
                    .saturating_sub(search_attempt_base);
                let replay_mode = if replay_accumulators.is_some() {
                    "GPU-accelerated replay"
                } else {
                    "CPU replay"
                };
                println!(
                    "GPU {device} found a target nonce after {search_evaluations} evaluations in {search_seconds:.1}s ({:.2} H/s); {replay_mode} and Layout V5 proof construction started.",
                    search_evaluations as f64 / search_seconds
                );
                let accelerated_replay = replay_accumulators
                    .map(cmfd_consensus::BlsDoryV3AcceleratedReplayAccumulators::new);
                let proof_stats_height = work.challenge().height;
                let proof_work = work.clone();
                let proof = match run_production_proof_while_current(
                    Arc::clone(&shutdown),
                    &mut || {
                        let current_tip = node
                            .lock()
                            .map_err(|_| anyhow!("node mutex is poisoned"))?
                            .status()?
                            .tip;
                        if current_tip == expected_parent {
                            Ok(WorkStatus::Current)
                        } else {
                            Ok(WorkStatus::Stale)
                        }
                    },
                    &mut || {
                        statistics.report_if_due(
                            &devices,
                            proof_stats_height,
                            config.stats_interval,
                        );
                    },
                    move |proof_cancel| {
                        proof_work
                            .prove_v3_winning_nonce_claim_with_accelerated_replay(
                                claim,
                                accelerated_replay,
                                &proof_cancel,
                            )
                            .map_err(Into::into)
                    },
                )? {
                    ProofRunOutcome::Completed(proof) => proof,
                    ProofRunOutcome::Stale => {
                        statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                        println!("Chain tip changed during proof construction; rebuilding work.");
                        continue;
                    }
                    ProofRunOutcome::Disconnected => {
                        println!("Embedded node became unavailable during proof construction.");
                        continue;
                    }
                    ProofRunOutcome::Shutdown => break,
                };
                let Some(block) = job.build_block_if_chain_valid(&proof)? else {
                    statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                    println!("Candidate no longer met the chain target; rebuilding work.");
                    continue;
                };
                let block_id = block.block_id();
                let height = block.challenge.height;
                let expected_parent = hex::encode(block.challenge.previous_block);
                let accepted = {
                    let mut node = node.lock().map_err(|_| anyhow!("node mutex is poisoned"))?;
                    if node.status()?.tip != expected_parent {
                        false
                    } else {
                        node.submit_block(*block, unix_time_seconds()?)?;
                        true
                    }
                };
                if accepted {
                    statistics.blocks_found = statistics.blocks_found.saturating_add(1);
                    let relayed = config
                        .peers
                        .peers
                        .iter()
                        .filter(|peer| {
                            relay_blocks_to_peer_once_with_policy(
                                Arc::clone(&node),
                                **peer,
                                config.peers.limits,
                                config.peers.address_policy,
                            )
                            .is_ok_and(|report| report.peer_tip == block_id)
                        })
                        .count();
                    println!(
                        "BLOCK FOUND | GPU {device} | height {height} | {} | node sync {relayed}/{} | session blocks {}",
                        hex::encode(block_id),
                        config.peers.peers.len(),
                        statistics.blocks_found
                    );
                } else {
                    statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                    println!("Candidate became stale before submission; rebuilding work.");
                }
            }
            JobOutcome::Found { .. } => {
                bail!("Production V3 worker returned a Devnet V2 proof")
            }
        }
    }
    if let Some(mut pool) = worker_pool {
        pool.stop()?;
    }
    println!("Miner stopped.");
    Ok(())
}

impl PersistentWorkerPool {
    fn new(
        cuda: CudaLibrary,
        devices: Vec<CudaDevice>,
        workers_per_gpu: usize,
        batch_size: u32,
        initial_work: &MiningWork,
    ) -> Result<Self> {
        let worker_count = devices
            .len()
            .checked_mul(workers_per_gpu)
            .ok_or_else(|| anyhow!("GPU worker count overflow"))?;
        if worker_count == 0 {
            bail!("persistent GPU pool requires at least one worker");
        }
        let model_identity = initial_work.accelerator_model_identity()?;
        let model = Arc::new(initial_work.accelerator_model()?);
        let (sender, receiver) = mpsc::sync_channel(worker_count.saturating_mul(4).max(4));
        let mut commands = Vec::with_capacity(worker_count);
        let mut handles = Vec::with_capacity(worker_count);
        for (device_ordinal, device) in devices.iter().enumerate() {
            for lane in 0..workers_per_gpu {
                let (command_sender, command_receiver) = mpsc::channel();
                handles.push(spawn_persistent_worker(
                    WorkerSpec {
                        cuda: cuda.clone(),
                        device: device.clone(),
                        ordinal: device_ordinal * workers_per_gpu + lane,
                        lane,
                        worker_count,
                        batch_size,
                        model: Arc::clone(&model),
                    },
                    command_receiver,
                    sender.clone(),
                )?);
                commands.push(command_sender);
            }
        }
        drop(sender);

        let mut pool = Self {
            model_identity,
            devices,
            workers_per_gpu,
            commands,
            receiver,
            handles,
            next_job_id: 1,
        };
        pool.wait_until_initialized(worker_count)?;
        Ok(pool)
    }

    fn wait_until_initialized(&mut self, worker_count: usize) -> Result<()> {
        let mut initialized = BTreeSet::new();
        while initialized.len() < worker_count {
            match self.receiver.recv() {
                Ok(WorkerMessage::Initialized { device, lane }) => {
                    initialized.insert((device, lane));
                    let device_ready = initialized
                        .iter()
                        .filter(|(ready_device, _)| *ready_device == device)
                        .count();
                    if device_ready == self.workers_per_gpu {
                        println!(
                            "GPU {device} context initialized with {} worker(s) ({}/{})",
                            self.workers_per_gpu,
                            initialized.len(),
                            worker_count
                        );
                    }
                }
                Ok(WorkerMessage::Failed {
                    device,
                    lane,
                    error,
                    ..
                }) => bail!("GPU {device} worker {lane} failed to initialize: {error}"),
                Ok(_) => bail!("GPU worker sent job output before initialization completed"),
                Err(_) => bail!("GPU workers disconnected during initialization"),
            }
        }
        Ok(())
    }

    fn mine(
        &mut self,
        work: MiningWork,
        config: JobMiningConfig,
        shutdown: Arc<AtomicBool>,
        statistics: &mut SessionStatistics,
        check_status: &mut dyn FnMut() -> Result<WorkStatus>,
    ) -> Result<JobOutcome> {
        if work.accelerator_model_identity()? != self.model_identity {
            bail!("mining model changed while GPU contexts were active");
        }
        let job_id = self.next_job_id;
        self.next_job_id = self
            .next_job_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("GPU job identifier exhausted"))?;
        let worker_cancel = Arc::new(AtomicBool::new(false));
        for command in &self.commands {
            if command
                .send(WorkerCommand::Mine {
                    job_id,
                    work: work.clone(),
                    cancel: Arc::clone(&worker_cancel),
                })
                .is_err()
            {
                worker_cancel.store(true, Ordering::Release);
                let _ = self.stop();
                bail!("GPU worker disconnected before job {job_id}");
            }
        }

        let outcome = monitor_workers(
            &self.devices,
            &work,
            &self.receiver,
            job_id,
            MonitorControl {
                stats_interval: config.stats_interval,
                shutdown,
                worker_cancel: Arc::clone(&worker_cancel),
            },
            statistics,
            check_status,
        );
        worker_cancel.store(true, Ordering::Release);
        match outcome {
            Ok(outcome) => {
                self.wait_until_idle(job_id, statistics)?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = self.stop();
                Err(error)
            }
        }
    }

    fn wait_until_idle(&self, job_id: u64, statistics: &mut SessionStatistics) -> Result<()> {
        let worker_count = self.commands.len();
        let mut idle = BTreeSet::new();
        while idle.len() < worker_count {
            match self.receiver.recv() {
                Ok(WorkerMessage::Idle {
                    job_id: message_job,
                    device,
                    lane,
                }) if message_job == job_id => {
                    idle.insert((device, lane));
                }
                Ok(WorkerMessage::Progress {
                    job_id: message_job,
                    device,
                    attempts,
                }) if message_job == job_id => statistics.record_attempts(device, attempts),
                Ok(WorkerMessage::Found {
                    job_id: message_job,
                    device,
                    attempts,
                    ..
                }) if message_job == job_id => statistics.record_attempts(device, attempts),
                Ok(WorkerMessage::Ready {
                    job_id: message_job,
                    ..
                }) if message_job == job_id => {}
                Ok(WorkerMessage::Failed {
                    job_id: failed_job,
                    device,
                    lane,
                    error,
                }) if failed_job.is_none() || failed_job == Some(job_id) => {
                    bail!("GPU {device} worker {lane} failed: {error}")
                }
                Ok(_) => bail!("GPU worker returned an out-of-order job message"),
                Err(_) => bail!("GPU workers disconnected while settling job {job_id}"),
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        for command in &self.commands {
            let _ = command.send(WorkerCommand::Shutdown);
        }
        self.commands.clear();
        let mut panic_seen = false;
        for handle in self.handles.drain(..) {
            panic_seen |= handle.join().is_err();
        }
        if panic_seen {
            bail!("a persistent GPU worker thread panicked");
        }
        Ok(())
    }
}

impl Drop for PersistentWorkerPool {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn spawn_persistent_worker(
    spec: WorkerSpec,
    commands: Receiver<WorkerCommand>,
    sender: SyncSender<WorkerMessage>,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("cmfd-gpu-{}-lane-{}", spec.device.index, spec.lane))
        .spawn(move || {
            if let Err(failure) = run_persistent_worker(&spec, &commands, &sender) {
                let _ = sender.send(WorkerMessage::Failed {
                    job_id: failure.job_id,
                    device: spec.device.index,
                    lane: spec.lane,
                    error: failure.error,
                });
            }
        })
}

fn run_persistent_worker(
    spec: &WorkerSpec,
    commands: &Receiver<WorkerCommand>,
    sender: &SyncSender<WorkerMessage>,
) -> Result<(), WorkerThreadError> {
    let mut miner = spec
        .cuda
        .create(&spec.model, spec.device.index)
        .map_err(|error| WorkerThreadError {
            job_id: None,
            error,
        })?;
    sender
        .send(WorkerMessage::Initialized {
            device: spec.device.index,
            lane: spec.lane,
        })
        .map_err(|_| WorkerThreadError {
            job_id: None,
            error: "miner coordinator closed during initialization".to_owned(),
        })?;

    while let Ok(command) = commands.recv() {
        match command {
            WorkerCommand::Mine {
                job_id,
                work,
                cancel,
            } => {
                run_worker_job(spec, &mut miner, job_id, &work, &cancel, sender).map_err(
                    |error| WorkerThreadError {
                        job_id: Some(job_id),
                        error,
                    },
                )?;
                sender
                    .send(WorkerMessage::Idle {
                        job_id,
                        device: spec.device.index,
                        lane: spec.lane,
                    })
                    .map_err(|_| WorkerThreadError {
                        job_id: Some(job_id),
                        error: "miner coordinator closed while settling a job".to_owned(),
                    })?;
            }
            WorkerCommand::Shutdown => break,
        }
    }
    Ok(())
}

fn run_worker_job(
    spec: &WorkerSpec,
    miner: &mut cmfd_cuda::CudaMiner,
    job_id: u64,
    work: &MiningWork,
    cancel: &AtomicBool,
    sender: &SyncSender<WorkerMessage>,
) -> Result<(), String> {
    let canary = work
        .prepare_accelerator_batch(spec.ordinal as u64, 1)
        .map_err(|error| error.client_error().message)?;
    let canary_output = miner.evaluate(&canary)?;
    work.verify_accelerator_output(&canary, 0, &canary_output)
        .map_err(|error| {
            format!(
                "GPU differential check failed: {}",
                error.client_error().message
            )
        })?;
    sender
        .send(WorkerMessage::Ready {
            job_id,
            device: spec.device.index,
            lane: spec.lane,
        })
        .map_err(|_| "miner coordinator closed during job startup".to_owned())?;

    let stride = nonce_stride(spec.batch_size, spec.worker_count);
    let mut next_nonce = nonce_start(spec.batch_size, spec.ordinal);
    let mut pending_attempts = 0_u64;
    while !cancel.load(Ordering::Acquire) {
        let batch = work
            .prepare_accelerator_batch(next_nonce, spec.batch_size)
            .map_err(|error| error.client_error().message)?;
        let outputs = miner.evaluate(&batch)?;
        pending_attempts = pending_attempts.saturating_add(u64::from(spec.batch_size));
        let result = work
            .complete_accelerator_batch(&batch, &outputs)
            .map_err(|error| error.client_error().message)?;
        match result {
            MiningShareSearchResult::Found { proof, .. } => {
                sender
                    .send(WorkerMessage::Found {
                        job_id,
                        device: spec.device.index,
                        proof,
                        attempts: pending_attempts,
                    })
                    .map_err(|_| "miner coordinator closed before block submission".to_owned())?;
                cancel.store(true, Ordering::Release);
                return Ok(());
            }
            MiningShareSearchResult::Exhausted { .. } => {}
            MiningShareSearchResult::Cancelled { .. } => break,
        }

        if sender
            .try_send(WorkerMessage::Progress {
                job_id,
                device: spec.device.index,
                attempts: pending_attempts,
            })
            .is_ok()
        {
            pending_attempts = 0;
        }
        next_nonce = next_nonce.wrapping_add(stride);
    }
    if pending_attempts > 0 {
        let _ = sender.try_send(WorkerMessage::Progress {
            job_id,
            device: spec.device.index,
            attempts: pending_attempts,
        });
    }
    Ok(())
}

fn monitor_workers(
    devices: &[CudaDevice],
    work: &MiningWork,
    receiver: &Receiver<WorkerMessage>,
    job_id: u64,
    control: MonitorControl,
    statistics: &mut SessionStatistics,
    check_status: &mut dyn FnMut() -> Result<WorkStatus>,
) -> Result<JobOutcome> {
    let mut ready = BTreeSet::new();
    loop {
        if control.shutdown.load(Ordering::Acquire) {
            control.worker_cancel.store(true, Ordering::Release);
            return Ok(JobOutcome::Shutdown);
        }
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(WorkerMessage::Ready {
                job_id: message_job,
                device,
                lane,
            }) if message_job == job_id => {
                ready.insert((device, lane));
            }
            Ok(WorkerMessage::Progress {
                job_id: message_job,
                device,
                attempts,
            }) if message_job == job_id => {
                statistics.record_attempts(device, attempts);
            }
            Ok(WorkerMessage::Found {
                job_id: message_job,
                device,
                proof,
                attempts,
            }) if message_job == job_id => {
                statistics.record_attempts(device, attempts);
                control.worker_cancel.store(true, Ordering::Release);
                return Ok(JobOutcome::Found { device, proof });
            }
            Ok(WorkerMessage::Failed {
                job_id: failed_job,
                device,
                lane,
                error,
            }) if failed_job.is_none() || failed_job == Some(job_id) => {
                control.worker_cancel.store(true, Ordering::Release);
                bail!("GPU {device} worker {lane} failed: {error}");
            }
            Ok(_) => bail!("GPU worker returned an out-of-order job message"),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("all CUDA workers exited before finding or cancelling work")
            }
        }

        statistics.report_if_due(devices, work.challenge().height, control.stats_interval);

        match check_status()? {
            WorkStatus::Current => {}
            WorkStatus::Stale => {
                control.worker_cancel.store(true, Ordering::Release);
                return Ok(JobOutcome::Stale);
            }
            WorkStatus::Disconnected => {
                control.worker_cancel.store(true, Ordering::Release);
                return Ok(JobOutcome::Disconnected);
            }
        }
    }
}

#[cfg(feature = "production-v3")]
fn run_production_proof_while_current<T, Prove>(
    shutdown: Arc<AtomicBool>,
    check_status: &mut dyn FnMut() -> Result<WorkStatus>,
    on_poll: &mut dyn FnMut(),
    prove: Prove,
) -> Result<ProofRunOutcome<T>>
where
    T: Send + 'static,
    Prove: FnOnce(Arc<AtomicBool>) -> Result<T> + Send + 'static,
{
    if shutdown.load(Ordering::Acquire) {
        return Ok(ProofRunOutcome::Shutdown);
    }
    let proof_cancel = Arc::new(AtomicBool::new(shutdown.load(Ordering::Acquire)));
    let thread_cancel = Arc::clone(&proof_cancel);
    let (sender, receiver) = mpsc::sync_channel(1);
    let mut handle = Some(
        thread::Builder::new()
            .name("cmfd-v3-proof".to_owned())
            .spawn(move || {
                let _ = sender.send(prove(thread_cancel));
            })
            .context("spawn Production V3 proof worker")?,
    );

    let stop_and_join = |handle: &mut Option<JoinHandle<()>>| -> Result<()> {
        proof_cancel.store(true, Ordering::Release);
        if handle
            .take()
            .expect("Production V3 proof handle is present")
            .join()
            .is_err()
        {
            bail!("Production V3 proof worker panicked");
        }
        Ok(())
    };

    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => {
                if handle
                    .take()
                    .expect("Production V3 proof handle is present")
                    .join()
                    .is_err()
                {
                    bail!("Production V3 proof worker panicked");
                }
                if shutdown.load(Ordering::Acquire) {
                    return Ok(ProofRunOutcome::Shutdown);
                }
                return match check_status()? {
                    WorkStatus::Current => result.map(ProofRunOutcome::Completed),
                    WorkStatus::Stale => Ok(ProofRunOutcome::Stale),
                    WorkStatus::Disconnected => Ok(ProofRunOutcome::Disconnected),
                };
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop_and_join(&mut handle)?;
                bail!("Production V3 proof worker exited without a result");
            }
        }

        if shutdown.load(Ordering::Acquire) {
            stop_and_join(&mut handle)?;
            return Ok(ProofRunOutcome::Shutdown);
        }
        let status = match check_status() {
            Ok(status) => status,
            Err(error) => {
                stop_and_join(&mut handle)?;
                return Err(error);
            }
        };
        match status {
            WorkStatus::Current => {}
            WorkStatus::Stale => {
                stop_and_join(&mut handle)?;
                return Ok(ProofRunOutcome::Stale);
            }
            WorkStatus::Disconnected => {
                stop_and_join(&mut handle)?;
                return Ok(ProofRunOutcome::Disconnected);
            }
        }
        on_poll();
    }
}

#[cfg(feature = "production-v3")]
impl ProductionWorkerPool {
    fn new(
        cuda: CudaLibrary,
        devices: Vec<CudaDevice>,
        batch_size: u32,
        initial_work: &MiningWork,
        factory: &ProductionV3MiningWorkFactory,
        initialization_cancel: Arc<AtomicBool>,
    ) -> Result<Self> {
        if devices.is_empty() {
            bail!("production GPU pool requires at least one worker");
        }
        if batch_size == 0 || batch_size > MAX_PRODUCTION_V3_BATCH_SIZE {
            bail!(
                "Production V3 --batch-size must be between 1 and {MAX_PRODUCTION_V3_BATCH_SIZE}"
            );
        }
        let parameters = initial_work.v3_candidate_parameters()?;
        let worker_count = devices.len();
        let (sender, receiver) = mpsc::sync_channel(worker_count.saturating_mul(4).max(4));
        let mut pool = Self {
            parameters,
            devices,
            commands: Vec::with_capacity(worker_count),
            receiver,
            handles: Vec::with_capacity(worker_count),
            initialization_cancel,
            next_job_id: 1,
        };
        for ordinal in 0..pool.devices.len() {
            let device = pool.devices[ordinal].clone();
            let (command_sender, command_receiver) = mpsc::channel();
            let spec = ProductionWorkerSpec {
                cuda: cuda.clone(),
                device,
                ordinal,
                worker_count,
                batch_size,
                factory: factory.clone(),
                initialization_cancel: Arc::clone(&pool.initialization_cancel),
            };
            let handle = match spawn_production_worker(spec, command_receiver, sender.clone()) {
                Ok(handle) => handle,
                Err(error) => {
                    if let Err(cleanup_error) = pool.stop() {
                        bail!(
                            "failed to spawn Production V3 GPU worker: {error}; worker cleanup also failed: {cleanup_error}"
                        );
                    }
                    return Err(error).context("spawn Production V3 GPU worker");
                }
            };
            pool.handles.push(handle);
            pool.commands.push(command_sender);
        }
        drop(sender);
        if let Err(error) = pool.wait_until_initialized(worker_count) {
            if let Err(cleanup_error) = pool.stop() {
                bail!(
                    "Production V3 GPU initialization failed: {error}; worker cleanup also failed: {cleanup_error}"
                );
            }
            return Err(error);
        }
        Ok(pool)
    }

    fn wait_until_initialized(&mut self, worker_count: usize) -> Result<()> {
        let mut initialized = BTreeSet::new();
        while initialized.len() < worker_count {
            if self.initialization_cancel.load(Ordering::Acquire) {
                bail!("Production V3 GPU initialization was cancelled");
            }
            match self.receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(WorkerMessage::Initialized { device, lane }) => {
                    initialized.insert((device, lane));
                    println!(
                        "GPU {device} authenticated Production V3 context ({}/{worker_count})",
                        initialized.len()
                    );
                }
                Ok(WorkerMessage::Failed {
                    device,
                    lane,
                    error,
                    ..
                }) => bail!("GPU {device} Production V3 worker {lane} failed: {error}"),
                Ok(_) => bail!("Production V3 worker sent job output before initialization"),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("Production V3 workers disconnected during initialization")
                }
            }
        }
        Ok(())
    }

    fn mine(
        &mut self,
        work: MiningWork,
        config: JobMiningConfig,
        shutdown: Arc<AtomicBool>,
        statistics: &mut SessionStatistics,
        check_status: &mut dyn FnMut() -> Result<WorkStatus>,
    ) -> Result<JobOutcome> {
        if work.v3_candidate_parameters()? != self.parameters {
            bail!("Production V3 model changed while GPU contexts were active");
        }
        let job_id = self.next_job_id;
        self.next_job_id = self
            .next_job_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("GPU job identifier exhausted"))?;
        let worker_cancel = Arc::new(AtomicBool::new(false));
        for command in &self.commands {
            if command
                .send(WorkerCommand::Mine {
                    job_id,
                    work: work.clone(),
                    cancel: Arc::clone(&worker_cancel),
                })
                .is_err()
            {
                worker_cancel.store(true, Ordering::Release);
                let _ = self.stop();
                bail!("Production V3 worker disconnected before job {job_id}");
            }
        }
        let outcome = monitor_production_workers(
            &self.devices,
            &work,
            &self.receiver,
            job_id,
            MonitorControl {
                stats_interval: config.stats_interval,
                shutdown,
                worker_cancel: Arc::clone(&worker_cancel),
            },
            statistics,
            check_status,
        );
        worker_cancel.store(true, Ordering::Release);
        match outcome {
            Ok(outcome) => {
                self.wait_until_idle(job_id, statistics)?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = self.stop();
                Err(error)
            }
        }
    }

    fn wait_until_idle(&self, job_id: u64, statistics: &mut SessionStatistics) -> Result<()> {
        let mut idle = BTreeSet::new();
        while idle.len() < self.commands.len() {
            match self.receiver.recv() {
                Ok(WorkerMessage::Idle {
                    job_id: message_job,
                    device,
                    lane,
                }) if message_job == job_id => {
                    idle.insert((device, lane));
                }
                Ok(WorkerMessage::Progress {
                    job_id: message_job,
                    device,
                    attempts,
                }) if message_job == job_id => statistics.record_attempts(device, attempts),
                Ok(WorkerMessage::FoundV3 {
                    job_id: message_job,
                    device,
                    attempts,
                    ..
                }) if message_job == job_id => statistics.record_attempts(device, attempts),
                Ok(WorkerMessage::Ready {
                    job_id: message_job,
                    ..
                }) if message_job == job_id => {}
                Ok(WorkerMessage::Failed {
                    job_id: failed_job,
                    device,
                    lane,
                    error,
                }) if failed_job.is_none() || failed_job == Some(job_id) => {
                    bail!("GPU {device} Production V3 worker {lane} failed: {error}")
                }
                Ok(_) => bail!("Production V3 worker returned an out-of-order message"),
                Err(_) => bail!("Production V3 workers disconnected while settling job {job_id}"),
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        stop_production_worker_threads(
            &self.initialization_cancel,
            &mut self.commands,
            &mut self.handles,
        )
    }
}

#[cfg(feature = "production-v3")]
fn stop_production_worker_threads(
    initialization_cancel: &AtomicBool,
    commands: &mut Vec<Sender<WorkerCommand>>,
    handles: &mut Vec<JoinHandle<()>>,
) -> Result<()> {
    initialization_cancel.store(true, Ordering::Release);
    for command in commands.iter() {
        let _ = command.send(WorkerCommand::Shutdown);
    }
    commands.clear();
    let mut panic_seen = false;
    for handle in handles.drain(..) {
        panic_seen |= handle.join().is_err();
    }
    if panic_seen {
        bail!("a Production V3 GPU worker thread panicked");
    }
    Ok(())
}

#[cfg(feature = "production-v3")]
impl Drop for ProductionWorkerPool {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(feature = "production-v3")]
fn spawn_production_worker(
    spec: ProductionWorkerSpec,
    commands: Receiver<WorkerCommand>,
    sender: SyncSender<WorkerMessage>,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("cmfd-v3-gpu-{}", spec.device.index))
        .spawn(move || {
            if let Err(failure) = run_production_worker(&spec, &commands, &sender) {
                let _ = sender.send(WorkerMessage::Failed {
                    job_id: failure.job_id,
                    device: spec.device.index,
                    lane: 0,
                    error: failure.error,
                });
            }
        })
}

#[cfg(feature = "production-v3")]
fn run_production_worker(
    spec: &ProductionWorkerSpec,
    commands: &Receiver<WorkerCommand>,
    sender: &SyncSender<WorkerMessage>,
) -> Result<(), WorkerThreadError> {
    let bank = File::open(spec.factory.bank_path()).map_err(|error| WorkerThreadError {
        job_id: None,
        error: format!("open production bank: {error}"),
    })?;
    let (authenticated, setup) =
        spec.factory
            .production_authority()
            .map_err(|error| WorkerThreadError {
                job_id: None,
                error: error.client_error().message,
            })?;
    let mut miner = spec
        .cuda
        .create_production_with_cancel(
            BufReader::new(bank),
            authenticated,
            setup,
            spec.device.index,
            &spec.initialization_cancel,
        )
        .map_err(|error| WorkerThreadError {
            job_id: None,
            error,
        })?;
    if !miner.is_bound_to_bank_authenticated_record(authenticated) {
        return Err(WorkerThreadError {
            job_id: None,
            error: "CUDA evaluator did not retain the authenticated Record V2 identity".to_owned(),
        });
    }
    sender
        .send(WorkerMessage::Initialized {
            device: spec.device.index,
            lane: 0,
        })
        .map_err(|_| WorkerThreadError {
            job_id: None,
            error: "miner coordinator closed during Production V3 initialization".to_owned(),
        })?;

    while let Ok(command) = commands.recv() {
        match command {
            WorkerCommand::Mine {
                job_id,
                work,
                cancel,
            } => {
                run_production_worker_job(spec, &mut miner, job_id, &work, &cancel, sender)
                    .map_err(|error| WorkerThreadError {
                        job_id: Some(job_id),
                        error,
                    })?;
                sender
                    .send(WorkerMessage::Idle {
                        job_id,
                        device: spec.device.index,
                        lane: 0,
                    })
                    .map_err(|_| WorkerThreadError {
                        job_id: Some(job_id),
                        error: "miner coordinator closed while settling Production V3 job"
                            .to_owned(),
                    })?;
            }
            WorkerCommand::Shutdown => break,
        }
    }
    Ok(())
}

#[cfg(feature = "production-v3")]
fn run_production_worker_job(
    spec: &ProductionWorkerSpec,
    miner: &mut cmfd_cuda::ProductionCudaMiner,
    job_id: u64,
    work: &MiningWork,
    cancel: &AtomicBool,
    sender: &SyncSender<WorkerMessage>,
) -> Result<(), String> {
    sender
        .send(WorkerMessage::Ready {
            job_id,
            device: spec.device.index,
            lane: 0,
        })
        .map_err(|_| "miner coordinator closed during Production V3 startup".to_owned())?;
    let stride = nonce_stride(spec.batch_size, spec.worker_count);
    let mut next_nonce = nonce_start(spec.batch_size, spec.ordinal);
    let mut pending_attempts = 0_u64;
    while !cancel.load(Ordering::Acquire) {
        let batch = work
            .prepare_v3_accelerator_batch(next_nonce, spec.batch_size)
            .map_err(|error| error.client_error().message)?;
        let outputs = miner.evaluate(batch.coefficients(), batch.count())?;
        pending_attempts = pending_attempts.saturating_add(u64::from(batch.count()));
        let expected = (batch.count() as usize)
            .checked_mul(batch.activation_len())
            .ok_or_else(|| "Production V3 output length overflow".to_owned())?;
        if outputs.len() != expected {
            return Err("Production V3 CUDA output shape mismatch".to_owned());
        }
        for (index, output) in outputs.chunks_exact(batch.activation_len()).enumerate() {
            if let Some(claim) = work
                .v3_winning_nonce_claim_from_accelerator_batch_output(&batch, index, output)
                .map_err(|error| error.client_error().message)?
            {
                let replay_accumulators =
                    gpu_replay_accumulators_for_found_nonce(miner, &batch, index, output);
                sender
                    .send(WorkerMessage::FoundV3 {
                        job_id,
                        device: spec.device.index,
                        claim,
                        attempts: pending_attempts,
                        replay_accumulators,
                    })
                    .map_err(|_| {
                        "miner coordinator closed before Production V3 proof replay".to_owned()
                    })?;
                cancel.store(true, Ordering::Release);
                return Ok(());
            }
        }
        if sender
            .try_send(WorkerMessage::Progress {
                job_id,
                device: spec.device.index,
                attempts: pending_attempts,
            })
            .is_ok()
        {
            pending_attempts = 0;
        }
        next_nonce = next_nonce.wrapping_add(stride);
    }
    if pending_attempts > 0 {
        let _ = sender.try_send(WorkerMessage::Progress {
            job_id,
            device: spec.device.index,
            attempts: pending_attempts,
        });
    }
    Ok(())
}

/// Re-evaluate the found nonce on the worker's authenticated GPU context and
/// surface its raw accumulator columns for the consensus replay, or `None` to
/// fall back to the CPU matrix replay. The columns are untrusted here and
/// everywhere: the consensus replay reauthenticates the complete bank on its
/// own reader, bound-checks every value, re-derives the digests, proves the
/// columns against the CPU-committed weights, and self-verifies the
/// candidate. As a cheap consistency gate, the replay's final activation must
/// reproduce the search output byte for byte or the bundle is discarded.
#[cfg(feature = "production-v3")]
fn gpu_replay_accumulators_for_found_nonce(
    miner: &mut cmfd_cuda::ProductionCudaMiner,
    batch: &cmfd_consensus::ForgeMatrixV3AcceleratorBatch,
    index: usize,
    search_activation: &[u8],
) -> Option<Vec<i32>> {
    if !miner.supports_replay() {
        eprintln!(
            "GPU replay unavailable (backend lacks the replay seam); using the CPU matrix replay."
        );
        return None;
    }
    let count = batch.count() as usize;
    let coefficients = batch.coefficients();
    if count == 0 || !coefficients.len().is_multiple_of(count) {
        return None;
    }
    let per_nonce = coefficients.len() / count;
    let nonce_coefficients = coefficients.get(index * per_nonce..(index + 1) * per_nonce)?;
    let replay_started = Instant::now();
    match miner.replay_winning_nonce(nonce_coefficients) {
        Ok(output) => {
            if output.final_activation != search_activation {
                eprintln!(
                    "GPU replay final activation diverged from the search output; discarding the GPU replay and using the CPU matrix replay."
                );
                return None;
            }
            eprintln!(
                "GPU replay surfaced the execution table in {:.1}s; the CPU authenticates the bank and proves against its own commitments.",
                replay_started.elapsed().as_secs_f64()
            );
            Some(output.layer_accumulators)
        }
        Err(error) => {
            eprintln!("GPU replay failed ({error}); using the CPU matrix replay.");
            None
        }
    }
}

#[cfg(feature = "production-v3")]
fn monitor_production_workers(
    devices: &[CudaDevice],
    work: &MiningWork,
    receiver: &Receiver<WorkerMessage>,
    job_id: u64,
    control: MonitorControl,
    statistics: &mut SessionStatistics,
    check_status: &mut dyn FnMut() -> Result<WorkStatus>,
) -> Result<JobOutcome> {
    loop {
        if control.shutdown.load(Ordering::Acquire) {
            control.worker_cancel.store(true, Ordering::Release);
            return Ok(JobOutcome::Shutdown);
        }
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(WorkerMessage::Ready {
                job_id: message_job,
                ..
            }) if message_job == job_id => {}
            Ok(WorkerMessage::Progress {
                job_id: message_job,
                device,
                attempts,
            }) if message_job == job_id => statistics.record_attempts(device, attempts),
            Ok(WorkerMessage::FoundV3 {
                job_id: message_job,
                device,
                claim,
                attempts,
                replay_accumulators,
            }) if message_job == job_id => {
                statistics.record_attempts(device, attempts);
                control.worker_cancel.store(true, Ordering::Release);
                return Ok(JobOutcome::FoundV3 {
                    device,
                    claim,
                    replay_accumulators,
                });
            }
            Ok(WorkerMessage::Failed {
                job_id: failed_job,
                device,
                lane,
                error,
            }) if failed_job.is_none() || failed_job == Some(job_id) => {
                control.worker_cancel.store(true, Ordering::Release);
                bail!("GPU {device} Production V3 worker {lane} failed: {error}");
            }
            Ok(_) => bail!("Production V3 worker returned an out-of-order job message"),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("all Production V3 CUDA workers exited")
            }
        }
        statistics.report_if_due(devices, work.challenge().height, control.stats_interval);
        match check_status()? {
            WorkStatus::Current => {}
            WorkStatus::Stale => {
                control.worker_cancel.store(true, Ordering::Release);
                return Ok(JobOutcome::Stale);
            }
            WorkStatus::Disconnected => {
                control.worker_cancel.store(true, Ordering::Release);
                return Ok(JobOutcome::Disconnected);
            }
        }
    }
}

fn select_devices(available: &[CudaDevice], requested: &[i32]) -> Result<Vec<CudaDevice>> {
    let by_index: BTreeMap<_, _> = available
        .iter()
        .cloned()
        .map(|device| (device.index, device))
        .collect();
    let indices: Vec<_> = if requested.is_empty() {
        available
            .iter()
            .filter(|device| device.is_supported())
            .map(|device| device.index)
            .collect()
    } else {
        let unique: BTreeSet<_> = requested.iter().copied().collect();
        if unique.len() != requested.len() {
            bail!("--device contains a duplicate CUDA index");
        }
        unique.into_iter().collect()
    };
    if indices.is_empty() {
        bail!("no supported CUDA devices were selected");
    }
    indices
        .into_iter()
        .map(|index| {
            let device = by_index
                .get(&index)
                .cloned()
                .ok_or_else(|| anyhow!("CUDA device {index} was not found"))?;
            if !device.is_supported() {
                bail!(
                    "CUDA device {index} has compute capability {}.{}, below the required 7.0",
                    device.compute_major,
                    device.compute_minor
                );
            }
            Ok(device)
        })
        .collect()
}

fn nonce_start(batch_size: u32, ordinal: usize) -> u64 {
    u64::from(batch_size).wrapping_mul(ordinal as u64)
}

fn nonce_stride(batch_size: u32, workers: usize) -> u64 {
    u64::from(batch_size).wrapping_mul(workers as u64)
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::sync::atomic::AtomicU64;

    use super::*;

    #[cfg(feature = "production-v4-testnet")]
    #[test]
    fn production_v4_snapshot_requires_bound_replay_outputs() {
        let snapshot = Cli::try_parse_from([
            "cmfd-miner",
            "snapshot-v4-template",
            "--peer",
            "127.0.0.1:22444",
            "--miner",
            "11e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",
            "--fixed-record",
            "D:\\fixed-record.json",
            "--coefficients-output",
            "D:\\replay-coefficients.bin",
            "--output",
            "D:\\v4-template.json",
        ])
        .unwrap();
        assert!(matches!(
            snapshot.command,
            Command::SnapshotV4Template { nonce: 0, .. }
        ));
    }

    #[cfg(feature = "production-v4-testnet")]
    #[test]
    fn production_v4_replay_coefficients_cover_every_layer() {
        let challenge_digest = [0x42; 32];
        let coefficients = production_v4_replay_coefficients(challenge_digest);
        assert_eq!(coefficients.len(), (PRODUCTION_V2_LAYERS as usize + 1) * 20);
        assert_eq!(
            &coefficients[..20],
            &forgematrix_v4_mask_coefficients(challenge_digest, u32::MAX)
        );
        assert_eq!(
            &coefficients[20..40],
            &forgematrix_v4_mask_coefficients(challenge_digest, 0)
        );
        let last = PRODUCTION_V2_LAYERS as usize * 20;
        assert_eq!(
            &coefficients[last..last + 20],
            &forgematrix_v4_mask_coefficients(challenge_digest, PRODUCTION_V2_LAYERS - 1)
        );
    }

    #[cfg(feature = "production-v4-testnet")]
    #[test]
    fn production_v4_raw_final_digest_has_a_pinned_vector() {
        let challenge_digest = [0x6b; 32];
        let values = [0, 1, FORGEMATRIX_V4_FIELD_MODULUS - 1];
        let encoded = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        assert_eq!(
            hex::encode(v4_final_activation_digest_from_bytes(challenge_digest, &encoded).unwrap()),
            "52b1b4618e5126b806aaa7b5b40ce19b76946214e41b8b961de14d7436fe738c"
        );

        let noncanonical = FORGEMATRIX_V4_FIELD_MODULUS.to_le_bytes();
        assert!(v4_final_activation_digest_from_bytes(challenge_digest, &noncanonical).is_err());
    }

    #[cfg(feature = "production-v4-testnet")]
    #[test]
    fn production_v4_continuous_search_commands_require_bound_inputs() {
        for command in [
            "bind-v4-nonce",
            "prepare-v4-search-batch",
            "inspect-v4-search-batch",
            "inspect-v4-work",
        ] {
            assert!(Cli::try_parse_from(["cmfd-miner", command]).is_err());
        }
    }

    #[cfg(feature = "production-v4-testnet")]
    #[test]
    fn production_v4_search_batch_range_is_bounded() {
        assert!(validate_v4_search_batch_range(0, 1).is_ok());
        assert!(validate_v4_search_batch_range(0, 64).is_ok());
        assert!(validate_v4_search_batch_range(0, 0).is_err());
        assert!(validate_v4_search_batch_range(0, 65).is_err());
        assert!(validate_v4_search_batch_range(u64::MAX, 2).is_err());
    }

    fn retry_test_block() -> cmfd_consensus::Block {
        let reference = cmfd_consensus::v2_test_reference().unwrap();
        let verifier = cmfd_consensus::ConsensusPowVerifier::v2_reference(reference.clone());
        let challenge = cmfd_consensus::BlockChallenge {
            network_id: reference.descriptor().network_id,
            previous_block: [0x41; 32],
            transaction_root: [0x42; 32],
            height: 1,
            timestamp: 60,
            target: [0xff; 32],
        };
        let proof = verifier.mine(&challenge, 0, 1).unwrap();
        cmfd_consensus::Block {
            version: cmfd_consensus::BLOCK_VERSION,
            challenge,
            proof,
            coinbase: cmfd_consensus::Coinbase {
                height: 1,
                outputs: Vec::new(),
            },
            transactions: Vec::new(),
        }
    }

    fn retry_result(
        block: &cmfd_consensus::Block,
        status: BlockSubmissionStatus,
        peer_tip: [u8; 32],
    ) -> cmfd_node::peer::BlockSubmissionResult {
        cmfd_node::peer::BlockSubmissionResult {
            block_id: block.block_id(),
            status,
            peer_height: block.challenge.height.saturating_sub(1),
            peer_tip,
        }
    }

    #[cfg(feature = "production-v3-testnet")]
    fn frozen_template_fixture() -> FrozenProductionV3Template {
        let block = retry_test_block();
        FrozenProductionV3Template {
            format_version: QUALIFIED_TEMPLATE_FORMAT_VERSION,
            challenge: block.challenge,
            coinbase: block.coinbase,
            transactions: block.transactions,
        }
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn qualified_template_json_is_canonical_and_strict() {
        let frozen = frozen_template_fixture();
        let encoded = canonical_json(&frozen, "qualified template").unwrap();
        assert_eq!(
            serde_json::from_slice::<FrozenProductionV3Template>(&encoded).unwrap(),
            frozen
        );

        let mut value = serde_json::to_value(&frozen).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<FrozenProductionV3Template>(value).is_err());
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn qualified_template_rejects_unknown_format_version() {
        let mut frozen = frozen_template_fixture();
        frozen.format_version = QUALIFIED_TEMPLATE_FORMAT_VERSION + 1;
        assert!(frozen.into_mining_template().is_err());
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn qualified_template_commands_are_available_in_production_builds() {
        let snapshot = Cli::try_parse_from([
            "cmfd-miner",
            "snapshot-qualified-template",
            "--peer",
            "127.0.0.1:21444",
            "--miner",
            "11e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",
            "--template-output",
            "D:\\qualified-template.json",
            "--seed-output",
            "D:\\qualification-seed.json",
        ])
        .unwrap();
        assert!(matches!(
            snapshot.command,
            Command::SnapshotQualifiedTemplate { nonce: 0, .. }
        ));

        let submit = Cli::try_parse_from([
            "cmfd-miner",
            "submit-qualified-template",
            "--peer",
            "127.0.0.1:21444",
            "--template",
            "D:\\qualified-template.json",
            "--proof",
            "D:\\qualification-proof.bin",
        ])
        .unwrap();
        assert!(matches!(
            submit.command,
            Command::SubmitQualifiedTemplate { .. }
        ));
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn qualified_output_publication_is_exact_and_never_overwrites() {
        let sequence = QUALIFIED_OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "cmfd-qualified-output-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let output = directory.join("template.json");
        write_new_file(&output, b"first\n", "test output").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"first\n");
        assert!(write_new_file(&output, b"second\n", "test output").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"first\n");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_file(output).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn full_node_defaults_follow_the_compiled_network_profile() {
        let cli = Cli::try_parse_from(["cmfd-miner", "full-node"]).unwrap();
        let Command::FullNode {
            data_dir, p2p_bind, ..
        } = cli.command
        else {
            unreachable!()
        };
        assert_eq!(data_dir, PathBuf::from(DEFAULT_MINER_DATA_DIR));
        assert_eq!(p2p_bind, COMPILED_NETWORK_PROFILE.miner_p2p_address());
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn production_v3_testnet_full_node_fails_before_artifact_or_cuda_work() {
        let data_dir =
            std::env::temp_dir().join(format!("cmfd-disabled-v3-full-node-{}", std::process::id()));
        assert!(!data_dir.exists());
        let error = run_full_node_miner(FullNodeMinerOptions {
            data_dir: data_dir.clone(),
            p2p_bind: "127.0.0.1:0".parse().unwrap(),
            peers: Vec::new(),
            allow_public_peers: false,
            requested_devices: Vec::new(),
            cuda_library: Some(PathBuf::from("missing-cuda-library")),
            batch_size: 0,
            workers_per_gpu: 0,
            miner: None,
            stats_seconds: 0,
            production_v3: ProductionV3Cli {
                production_v3_bank: None,
                production_v3_manifest: None,
                production_v3_record_v2: None,
                production_v3_scratch: None,
                production_v3_max_rows: None,
            },
        })
        .unwrap_err();
        assert!(error.to_string().contains("cmfd-miner mine --peer"));
        assert!(!data_dir.exists());
    }

    #[test]
    fn compiled_profile_selection_never_maps_rcnet_to_devnet_mining() {
        assert_eq!(
            mining_runtime(cmfd_node::DEVNET_PROFILE),
            MiningRuntime::DevnetV2
        );
        assert_eq!(
            mining_runtime(cmfd_node::RCNET1_PROFILE),
            MiningRuntime::ProductionV3
        );
    }

    #[cfg(feature = "production-v3")]
    #[test]
    fn production_proof_staleness_cancels_and_joins_prover() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let observed_cancel = Arc::new(AtomicBool::new(false));
        let proof_observed_cancel = Arc::clone(&observed_cancel);
        let outcome = run_production_proof_while_current(
            shutdown,
            &mut || Ok(WorkStatus::Stale),
            &mut || {},
            move |cancel| {
                while !cancel.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                proof_observed_cancel.store(true, Ordering::Release);
                Ok(7_u8)
            },
        )
        .unwrap();
        assert!(matches!(outcome, ProofRunOutcome::Stale));
        assert!(observed_cancel.load(Ordering::Acquire));
    }

    #[cfg(feature = "production-v3")]
    #[test]
    fn production_proof_shutdown_cancels_and_joins_prover() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let trigger = Arc::clone(&shutdown);
        let observed_cancel = Arc::new(AtomicBool::new(false));
        let proof_observed_cancel = Arc::clone(&observed_cancel);
        let trigger_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            trigger.store(true, Ordering::Release);
        });
        let outcome = run_production_proof_while_current(
            shutdown,
            &mut || Ok(WorkStatus::Current),
            &mut || {},
            move |cancel| {
                while !cancel.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                proof_observed_cancel.store(true, Ordering::Release);
                Ok(7_u8)
            },
        )
        .unwrap();
        trigger_handle.join().unwrap();
        assert!(matches!(outcome, ProofRunOutcome::Shutdown));
        assert!(observed_cancel.load(Ordering::Acquire));
    }

    #[cfg(feature = "production-v3")]
    #[test]
    fn production_proof_completion_rechecks_staleness_before_submission() {
        let outcome = run_production_proof_while_current(
            Arc::new(AtomicBool::new(false)),
            &mut || Ok(WorkStatus::Stale),
            &mut || {},
            |_| Ok(7_u8),
        )
        .unwrap();
        assert!(matches!(outcome, ProofRunOutcome::Stale));
    }

    #[cfg(feature = "production-v3")]
    #[test]
    fn production_initialization_cleanup_cancels_and_joins_every_started_worker() {
        let cancel = Arc::new(AtomicBool::new(false));
        let observations = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        let mut handles = observations
            .iter()
            .map(|observation| {
                let cancel = Arc::clone(&cancel);
                let observation = Arc::clone(observation);
                thread::spawn(move || {
                    while !cancel.load(Ordering::Acquire) {
                        thread::yield_now();
                    }
                    observation.store(true, Ordering::Release);
                })
            })
            .collect();
        let mut commands = Vec::new();

        stop_production_worker_threads(&cancel, &mut commands, &mut handles).unwrap();

        assert!(cancel.load(Ordering::Acquire));
        assert!(handles.is_empty());
        assert!(
            observations
                .iter()
                .all(|observation| observation.load(Ordering::Acquire))
        );
    }

    fn device(index: i32, major: u32, minor: u32) -> CudaDevice {
        CudaDevice {
            backend: cmfd_cuda::GpuBackend::Cuda,
            index,
            name: format!("GPU {index}"),
            compute_major: major,
            compute_minor: minor,
            total_memory_bytes: 1,
        }
    }

    #[test]
    fn automatic_selection_uses_every_supported_gpu() {
        let available = vec![device(0, 6, 1), device(1, 7, 0), device(2, 12, 0)];
        let selected = select_devices(&available, &[]).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|device| device.index)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn explicit_selection_is_sorted_and_rejects_duplicates() {
        let available = vec![device(0, 7, 5), device(1, 8, 6), device(2, 8, 9)];
        let selected = select_devices(&available, &[2, 0]).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|device| device.index)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert!(select_devices(&available, &[1, 1]).is_err());
    }

    #[test]
    fn gpu_nonce_ranges_do_not_overlap() {
        let batch_size = 4_u32;
        let workers = 48_usize;
        let stride = nonce_stride(batch_size, workers);
        let mut observed = BTreeSet::new();
        for round in 0..1_000_u64 {
            for ordinal in 0..workers {
                let start = nonce_start(batch_size, ordinal).wrapping_add(round * stride);
                for offset in 0..u64::from(batch_size) {
                    assert!(observed.insert(start.wrapping_add(offset)));
                }
            }
        }
        assert_eq!(observed.len(), 192_000);
    }

    #[test]
    fn automatic_workers_use_host_capacity_and_respect_the_cap() {
        assert_eq!(resolve_workers_per_gpu_for_host(0, 1, 32).unwrap(), 16);
        assert_eq!(resolve_workers_per_gpu_for_host(0, 4, 32).unwrap(), 8);
        assert_eq!(resolve_workers_per_gpu_for_host(0, 8, 4).unwrap(), 1);
        assert_eq!(resolve_workers_per_gpu_for_host(3, 8, 4).unwrap(), 3);
        assert!(resolve_workers_per_gpu_for_host(0, 0, 32).is_err());
    }

    #[test]
    fn mining_controls_reject_excessive_worker_counts() {
        assert!(validate_mining_controls(8_192, 0, 5).is_ok());
        assert!(validate_mining_controls(8_192, 16, 5).is_ok());
        assert!(validate_mining_controls(8_192, 17, 5).is_err());
    }

    #[test]
    fn telemetry_format_reports_power_efficiency_and_sensors() {
        let telemetry = GpuTelemetry {
            power_watts: Some(250.0),
            power_limit_watts: Some(300.0),
            temperature_celsius: Some(64.0),
            fan_percent: Some(52.0),
            utilization_percent: Some(99.0),
            graphics_clock_mhz: Some(2_745.0),
            memory_clock_mhz: Some(10_501.0),
            memory_used_mib: Some(2_048.0),
            memory_total_mib: Some(24_564.0),
        };

        let rendered = format_gpu_telemetry(1_000.0, Some(&telemetry));
        assert!(rendered.contains("250.00/300.00 W"));
        assert!(rendered.contains("4.00 H/W"));
        assert!(rendered.contains("temp 64.00 C"));
        assert!(rendered.contains("fan 52.00 %"));
        assert!(rendered.contains("util 99.00 %"));
        assert!(rendered.contains("core 2745.00 MHz"));
        assert!(rendered.contains("mem 10501.00 MHz"));
        assert!(rendered.contains("VRAM 2048/24564 MiB"));
        assert_eq!(
            format_gpu_telemetry(1_000.0, None),
            "power N/A | efficiency N/A | sensors N/A"
        );
    }

    #[test]
    fn duration_format_does_not_wrap_after_one_day() {
        assert_eq!(format_duration(Duration::from_secs(93_784)), "26:03:04");
    }

    #[test]
    fn busy_retry_accepts_the_exact_original_block_bytes() {
        let block = retry_test_block();
        let canonical = cmfd_consensus::encode_block(&block).unwrap();
        let block_id = block.block_id();
        let parent = block.challenge.previous_block;
        let peer: SocketAddr = "127.0.0.1:18444".parse().unwrap();
        let base = Instant::now();
        let elapsed = AtomicU64::new(0);
        let mut attempts = Vec::new();
        let mut calls = 0_u8;
        let report = retry_exact_block_with(
            &[peer],
            Some(peer),
            &block,
            base.checked_add(Duration::from_secs(1)).unwrap(),
            &AtomicBool::new(false),
            |_, candidate, _| {
                attempts.push(cmfd_consensus::encode_block(&candidate).unwrap());
                calls += 1;
                ExactBlockSubmissionAttempt::Response(if calls == 1 {
                    retry_result(&candidate, BlockSubmissionStatus::Busy, parent)
                } else {
                    retry_result(&candidate, BlockSubmissionStatus::Accepted, block_id)
                })
            },
            |_, _| {
                elapsed.fetch_add(1, Ordering::AcqRel);
                true
            },
            || {
                base.checked_add(Duration::from_millis(elapsed.load(Ordering::Acquire)))
                    .unwrap()
            },
        );
        assert_eq!(report.outcome, ExactBlockRetryOutcome::Accepted(peer));
        assert_eq!(attempts, vec![canonical.clone(), canonical]);
    }

    #[test]
    fn compatible_busy_outranks_another_peers_terminal_response() {
        let block = retry_test_block();
        let canonical = cmfd_consensus::encode_block(&block).unwrap();
        let block_id = block.block_id();
        let parent = block.challenge.previous_block;
        let rejecting_peer: SocketAddr = "127.0.0.1:18444".parse().unwrap();
        let busy_peer: SocketAddr = "127.0.0.1:18445".parse().unwrap();
        let base = Instant::now();
        let elapsed = AtomicU64::new(0);
        let mut attempts = Vec::new();
        let mut busy_peer_calls = 0_u8;
        let report = retry_exact_block_with(
            &[rejecting_peer, busy_peer],
            None,
            &block,
            base.checked_add(Duration::from_secs(1)).unwrap(),
            &AtomicBool::new(false),
            |peer, candidate, _| {
                attempts.push(cmfd_consensus::encode_block(&candidate).unwrap());
                if peer == rejecting_peer {
                    ExactBlockSubmissionAttempt::Response(retry_result(
                        &candidate,
                        BlockSubmissionStatus::Rejected,
                        parent,
                    ))
                } else {
                    busy_peer_calls += 1;
                    ExactBlockSubmissionAttempt::Response(if busy_peer_calls == 1 {
                        retry_result(&candidate, BlockSubmissionStatus::Busy, parent)
                    } else {
                        retry_result(&candidate, BlockSubmissionStatus::Accepted, block_id)
                    })
                }
            },
            |_, _| {
                elapsed.fetch_add(1, Ordering::AcqRel);
                true
            },
            || {
                base.checked_add(Duration::from_millis(elapsed.load(Ordering::Acquire)))
                    .unwrap()
            },
        );
        assert_eq!(report.outcome, ExactBlockRetryOutcome::Accepted(busy_peer));
        assert_eq!(attempts, vec![canonical; 4]);
        let mut statistics = SessionStatistics::new(&[]);
        record_exact_retry_report(&mut statistics, &report);
        assert_eq!(statistics.blocks_found, 1);
        assert_eq!(statistics.stale_submissions, 0);
        assert_eq!(statistics.abandoned_submissions, 0);
    }

    #[test]
    fn disconnect_retry_reconnects_and_accepts_the_exact_block() {
        let block = retry_test_block();
        let canonical = cmfd_consensus::encode_block(&block).unwrap();
        let block_id = block.block_id();
        let peer: SocketAddr = "127.0.0.1:18444".parse().unwrap();
        let base = Instant::now();
        let elapsed = AtomicU64::new(0);
        let mut attempts = Vec::new();
        let mut calls = 0_u8;
        let report = retry_exact_block_with(
            &[peer],
            None,
            &block,
            base.checked_add(Duration::from_secs(1)).unwrap(),
            &AtomicBool::new(false),
            |_, candidate, _| {
                attempts.push(cmfd_consensus::encode_block(&candidate).unwrap());
                calls += 1;
                if calls > 1 {
                    ExactBlockSubmissionAttempt::Response(retry_result(
                        &candidate,
                        BlockSubmissionStatus::Accepted,
                        block_id,
                    ))
                } else {
                    ExactBlockSubmissionAttempt::Disconnected("test disconnect".to_owned())
                }
            },
            |_, _| {
                elapsed.fetch_add(1, Ordering::AcqRel);
                true
            },
            || {
                base.checked_add(Duration::from_millis(elapsed.load(Ordering::Acquire)))
                    .unwrap()
            },
        );
        assert_eq!(report.outcome, ExactBlockRetryOutcome::Accepted(peer));
        assert_eq!(report.disconnects, 1);
        assert_eq!(attempts, vec![canonical.clone(), canonical]);
    }

    #[test]
    fn stop_during_reconnect_exits_without_classifying_the_inflight_attempt() {
        let block = retry_test_block();
        let peer: SocketAddr = "127.0.0.1:18444".parse().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let worker = thread::spawn(move || {
            let base = Instant::now();
            let mut calls = 0_u8;
            retry_exact_block_with(
                &[peer],
                None,
                &block,
                base.checked_add(Duration::from_secs(5)).unwrap(),
                &worker_shutdown,
                |_, _, _| {
                    calls += 1;
                    if calls == 1 {
                        ExactBlockSubmissionAttempt::Disconnected("initial disconnect".to_owned())
                    } else {
                        worker_entered.wait();
                        worker_release.wait();
                        ExactBlockSubmissionAttempt::Disconnected(
                            "reconnect interrupted".to_owned(),
                        )
                    }
                },
                |_, _| true,
                Instant::now,
            )
        });

        entered.wait();
        shutdown.store(true, Ordering::Release);
        release.wait();
        let report = worker.join().unwrap();
        assert_eq!(report.outcome, ExactBlockRetryOutcome::Stopped);
        assert_eq!(report.disconnects, 1);
        let mut statistics = SessionStatistics::new(&[]);
        record_exact_retry_report(&mut statistics, &report);
        assert_eq!(statistics.blocks_found, 0);
        assert_eq!(statistics.stale_submissions, 0);
        assert_eq!(statistics.abandoned_submissions, 0);
        assert_eq!(statistics.submission_disconnects, 1);
        assert_eq!(statistics.submission_protocol_errors, 0);
    }

    #[test]
    fn wrong_response_id_is_protocol_telemetry_not_cryptographic_rejection() {
        let block = retry_test_block();
        let parent = block.challenge.previous_block;
        let peer: SocketAddr = "127.0.0.1:18444".parse().unwrap();
        let base = Instant::now();
        let report = retry_exact_block_with(
            &[peer],
            None,
            &block,
            base.checked_add(Duration::from_secs(1)).unwrap(),
            &AtomicBool::new(false),
            |_, candidate, _| {
                let mut result = retry_result(&candidate, BlockSubmissionStatus::Accepted, parent);
                result.block_id[0] ^= 1;
                ExactBlockSubmissionAttempt::Response(result)
            },
            |_, _| panic!("protocol violation must not be retried as Busy"),
            || base,
        );
        assert!(matches!(
            report.outcome,
            ExactBlockRetryOutcome::ProtocolViolation { peer: actual, .. } if actual == peer
        ));
        assert_eq!(report.protocol_violations, 1);
        let mut statistics = SessionStatistics::new(&[]);
        record_exact_retry_report(&mut statistics, &report);
        assert_eq!(statistics.submission_protocol_errors, 1);
        assert_eq!(statistics.submission_disconnects, 0);
        assert_eq!(statistics.stale_jobs, 0);
        assert_eq!(statistics.stale_submissions, 0);
        assert_eq!(statistics.abandoned_submissions, 0);
        assert_eq!(statistics.blocks_found, 0);
    }

    #[test]
    fn malformed_response_and_disconnect_remain_distinct_retry_diagnostics() {
        let block = retry_test_block();
        let peer: SocketAddr = "127.0.0.1:18444".parse().unwrap();
        let base = Instant::now();
        let malformed = retry_exact_block_with(
            &[peer],
            None,
            &block,
            base.checked_add(Duration::from_secs(1)).unwrap(),
            &AtomicBool::new(false),
            |_, _, _| {
                ExactBlockSubmissionAttempt::ProtocolViolation(
                    "peer frame magic is invalid".to_owned(),
                )
            },
            |_, _| panic!("malformed response must not be retried as a disconnect"),
            || base,
        );
        assert_eq!(malformed.protocol_violations, 1);
        assert_eq!(malformed.disconnects, 0);
        assert!(matches!(
            malformed.outcome,
            ExactBlockRetryOutcome::ProtocolViolation { .. }
        ));

        let elapsed = AtomicU64::new(0);
        let disconnected = retry_exact_block_with(
            &[peer],
            None,
            &block,
            base.checked_add(Duration::from_millis(1)).unwrap(),
            &AtomicBool::new(false),
            |_, _, _| ExactBlockSubmissionAttempt::Disconnected("connection closed".to_owned()),
            |duration, _| {
                elapsed.fetch_add(duration.as_millis() as u64, Ordering::AcqRel);
                true
            },
            || {
                base.checked_add(Duration::from_millis(elapsed.load(Ordering::Acquire)))
                    .unwrap()
            },
        );
        assert_eq!(disconnected.protocol_violations, 0);
        assert_eq!(disconnected.disconnects, 1);
        assert_eq!(
            disconnected.outcome,
            ExactBlockRetryOutcome::BudgetExhausted
        );
    }

    #[test]
    fn exact_block_retry_aborts_when_the_peer_tip_changes() {
        let block = retry_test_block();
        let peer: SocketAddr = "127.0.0.1:18444".parse().unwrap();
        let changed_tip = [0x91; 32];
        let base = Instant::now();
        let report = retry_exact_block_with(
            &[peer],
            None,
            &block,
            base.checked_add(Duration::from_secs(1)).unwrap(),
            &AtomicBool::new(false),
            |_, candidate, _| {
                ExactBlockSubmissionAttempt::Response(retry_result(
                    &candidate,
                    BlockSubmissionStatus::Busy,
                    changed_tip,
                ))
            },
            |_, _| panic!("tip change must not wait or retry"),
            || base,
        );
        assert_eq!(report.outcome, ExactBlockRetryOutcome::Stale(changed_tip));
    }

    #[test]
    fn exact_block_retry_budget_expires_without_wall_clock_sleep() {
        let block = retry_test_block();
        let parent = block.challenge.previous_block;
        let peer: SocketAddr = "127.0.0.1:18444".parse().unwrap();
        let base = Instant::now();
        let elapsed = AtomicU64::new(0);
        let mut attempts = 0_u64;
        let report = retry_exact_block_with(
            &[peer],
            None,
            &block,
            base.checked_add(Duration::from_millis(5)).unwrap(),
            &AtomicBool::new(false),
            |_, candidate, _| {
                attempts += 1;
                ExactBlockSubmissionAttempt::Response(retry_result(
                    &candidate,
                    BlockSubmissionStatus::Busy,
                    parent,
                ))
            },
            |duration, _| {
                elapsed.fetch_add(duration.as_millis() as u64, Ordering::AcqRel);
                true
            },
            || {
                base.checked_add(Duration::from_millis(elapsed.load(Ordering::Acquire)))
                    .unwrap()
            },
        );
        assert_eq!(report.outcome, ExactBlockRetryOutcome::BudgetExhausted);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn busy_retry_budget_exhaustion_is_abandonment_not_rejection() {
        assert_eq!(FOUND_BLOCK_RETRY_BUDGET, Duration::from_secs(20 * 60));
        let mut statistics = SessionStatistics::new(&[]);
        let report =
            exact_block_retry_report(ExactBlockRetryOutcome::BudgetExhausted, 0, 0, None, None);
        record_exact_retry_report(&mut statistics, &report);
        assert_eq!(statistics.abandoned_submissions, 1);
        assert_eq!(statistics.stale_submissions, 0);
        assert_eq!(statistics.stale_jobs, 0);
        assert_eq!(statistics.blocks_found, 0);
    }

    #[test]
    fn exact_block_retry_wait_is_interruptible_by_stop() {
        let block = retry_test_block();
        let parent = block.challenge.previous_block;
        let peer: SocketAddr = "127.0.0.1:18444".parse().unwrap();
        let base = Instant::now();
        let shutdown = AtomicBool::new(false);
        let report = retry_exact_block_with(
            &[peer],
            None,
            &block,
            base.checked_add(Duration::from_secs(1)).unwrap(),
            &shutdown,
            |_, candidate, _| {
                ExactBlockSubmissionAttempt::Response(retry_result(
                    &candidate,
                    BlockSubmissionStatus::Busy,
                    parent,
                ))
            },
            |_, shutdown| {
                shutdown.store(true, Ordering::Release);
                false
            },
            || base,
        );
        assert_eq!(report.outcome, ExactBlockRetryOutcome::Stopped);
        assert!(shutdown.load(Ordering::Acquire));
        let mut statistics = SessionStatistics::new(&[]);
        record_exact_retry_report(&mut statistics, &report);
        assert_eq!(statistics.blocks_found, 0);
        assert_eq!(statistics.stale_submissions, 0);
        assert_eq!(statistics.abandoned_submissions, 0);
    }

    #[test]
    fn only_an_active_tip_acknowledgement_counts_as_a_mined_block() {
        let block_id = [7; 32];
        let active = cmfd_node::peer::BlockSubmissionResult {
            block_id,
            status: BlockSubmissionStatus::Accepted,
            peer_height: 1,
            peer_tip: block_id,
        };
        assert!(block_is_active_acknowledgement(&active, block_id));

        let side_branch = cmfd_node::peer::BlockSubmissionResult {
            peer_tip: [8; 32],
            ..active
        };
        assert!(!block_is_active_acknowledgement(&side_branch, block_id));

        let rejected = cmfd_node::peer::BlockSubmissionResult {
            status: BlockSubmissionStatus::Rejected,
            ..active
        };
        assert!(!block_is_active_acknowledgement(&rejected, block_id));

        let busy = cmfd_node::peer::BlockSubmissionResult {
            status: BlockSubmissionStatus::Busy,
            peer_tip: [6; 32],
            ..active
        };
        assert!(block_is_retryable_busy(&busy, block_id, [6; 32]));
        assert!(!block_is_retryable_busy(&busy, block_id, [5; 32]));
        assert!(!block_is_retryable_busy(&busy, [9; 32], [6; 32]));
        assert!(
            block_is_retryable_busy(&busy, block_id, [6; 32])
                && !block_is_active_acknowledgement(&rejected, block_id),
            "a busy peer on the exact parent must keep the candidate alive even when another peer rejects it"
        );
    }

    #[test]
    fn packaged_launchers_use_thin_mining_with_local_wallet_then_bootstrap() {
        let windows = include_str!("../../../packaging/standalone-miner/windows/START-MINER.bat");
        let linux = include_str!("../../../packaging/standalone-miner/linux/start-miner.sh");

        for launcher in [windows, linux] {
            let local = launcher.find("127.0.0.1:18444").unwrap();
            let bootstrap = launcher.find("107.214.187.2:18444").unwrap();
            assert!(local < bootstrap);
            assert_eq!(launcher.matches("--peer").count(), 2);
            assert!(launcher.contains("--allow-public-peers"));
            assert!(launcher.contains("--stats-seconds"));
            assert!(launcher.contains("--workers-per-gpu"));
            assert!(launcher.contains("PAYOUT_ADDRESS"));
            assert!(!launcher.contains("--data-dir"));
            assert!(!launcher.contains("--p2p-bind"));
        }
        assert!(windows.contains("if not defined PAYOUT_ADDRESS"));
        assert!(linux.contains("if [[ -z \"$PAYOUT_ADDRESS\" ]]"));
    }
}
