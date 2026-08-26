use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "production-v3")]
use std::fs::File;
#[cfg(feature = "production-v3")]
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
#[cfg(feature = "production-v3")]
use cmfd_consensus::ForgeMatrixV3WinningNonceClaim;
use cmfd_consensus::{BlockProof, ForgeMatrixV2AcceleratorModel};
use cmfd_cuda::{CudaDevice, CudaLibrary};
use cmfd_node::p2p::{
    relay_blocks_to_peer_once_with_policy, request_mining_template_once_with_policy,
    spawn_inbound_listener_with_policy, spawn_static_peer_polling,
    submit_mined_block_once_with_policy, sync_from_peer_once_with_policy,
};
use cmfd_node::peer::{
    BlockSubmissionStatus, MiningTemplate, PeerAddressPolicy, PeerLimits, StaticPeerConfig,
};
use cmfd_node::{
    COMPILED_NETWORK_PROFILE, MiningShareSearchResult, MiningWork, Node, NodeError, ProofProfile,
    parse_miner_destination, submit_shared_tip_block, unix_time_seconds,
};
#[cfg(feature = "production-v3")]
use cmfd_node::{ProductionV3MiningWorkFactory, ProductionV3VerifierArtifacts};

mod telemetry;

use telemetry::{GpuTelemetry, query_nvidia_smi};

const DEFAULT_MINER_DATA_DIR: &str = COMPILED_NETWORK_PROFILE.miner_data_dir_identity();
const DEFAULT_MINER_P2P_ADDRESS: SocketAddr = COMPILED_NETWORK_PROFILE.miner_p2p_address();
const DEFAULT_BATCH_SIZE: u32 = match COMPILED_NETWORK_PROFILE.proof {
    ProofProfile::DevnetV2Reference => 8_192,
    ProofProfile::ProductionV3 => 64,
};
const MAX_BATCH_SIZE: u32 = 65_536;
#[cfg(feature = "production-v3")]
const MAX_PRODUCTION_V3_BATCH_SIZE: u32 = 64;
const AUTO_WORKERS_PER_GPU: usize = 0;
const MAX_WORKERS_PER_GPU: usize = 16;
const DEFAULT_STATS_SECONDS: u64 = 5;
const PEER_RETRY_INTERVAL: Duration = Duration::from_secs(2);

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
}

const fn mining_runtime(profile: cmfd_node::NetworkProfile) -> MiningRuntime {
    match profile.proof {
        ProofProfile::DevnetV2Reference => MiningRuntime::DevnetV2,
        ProofProfile::ProductionV3 => MiningRuntime::ProductionV3,
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
            telemetry_warning_printed: false,
        }
    }

    fn record_attempts(&mut self, device: i32, attempts: u64) {
        let total = self.totals.entry(device).or_default();
        *total = total.saturating_add(attempts);
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
            "MINER STATS | height {height} | uptime {} | blocks {} | stale jobs {} | attempts {}",
            format_duration(self.started_at.elapsed()),
            self.blocks_found,
            self.stale_jobs,
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
                } else if rejected > 0 {
                    statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                    println!("Block candidate was rejected as stale; rebuilding work.");
                } else {
                    println!(
                        "Block found, but every node disconnected before acceptance; retrying."
                    );
                    retry_found_block(
                        &options.peers,
                        &mut preferred_peer,
                        block,
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
            JobOutcome::FoundV3 { device, claim } => {
                println!(
                    "GPU {device} found a target nonce; CPU replay and Layout V5 proof construction started."
                );
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
                    move |proof_cancel| {
                        proof_work
                            .prove_v3_winning_nonce_claim(claim, &proof_cancel)
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
                let block_id = block.block_id();
                let mut acknowledged = 0_usize;
                let mut rejected = 0_usize;
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
                } else if rejected > 0 {
                    statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                    println!("Production V3 block was rejected as stale; rebuilding work.");
                } else {
                    println!(
                        "Block proved, but every node disconnected before acceptance; retrying."
                    );
                    retry_found_block(
                        &options.peers,
                        &mut preferred_peer,
                        block,
                        limits,
                        address_policy,
                        &shutdown,
                        &mut statistics,
                        device,
                    )?;
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

fn fetch_template_from_any(
    peers: &[SocketAddr],
    preferred: Option<SocketAddr>,
    payout: [u8; 32],
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Option<(SocketAddr, cmfd_node::p2p::MiningTemplateResponse)> {
    ordered_peers(peers, preferred)
        .into_iter()
        .find_map(|peer| {
            request_mining_template_once_with_policy(peer, payout, limits, address_policy)
                .ok()
                .map(|response| (peer, response))
        })
}

fn wait_for_template(
    peers: &[SocketAddr],
    preferred: Option<SocketAddr>,
    payout: [u8; 32],
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    shutdown: &AtomicBool,
) -> Result<Option<(SocketAddr, MiningTemplate, u64)>> {
    while !shutdown.load(Ordering::Acquire) {
        if let Some((peer, response)) =
            fetch_template_from_any(peers, preferred, payout, limits, address_policy)
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
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    shutdown: &AtomicBool,
    statistics: &mut SessionStatistics,
    device: i32,
) -> Result<()> {
    while !shutdown.load(Ordering::Acquire) {
        for peer in ordered_peers(peers, *preferred) {
            match submit_mined_block_once_with_policy(peer, block.clone(), limits, address_policy) {
                Ok(result) if block_is_active_acknowledgement(&result, block.block_id()) => {
                    *preferred = Some(peer);
                    statistics.blocks_found = statistics.blocks_found.saturating_add(1);
                    println!(
                        "BLOCK ACCEPTED | GPU {device} | height {} | {} | node {peer} | session blocks {}",
                        block.challenge.height,
                        hex::encode(block.block_id()),
                        statistics.blocks_found
                    );
                    return Ok(());
                }
                Ok(_) => {
                    statistics.stale_jobs = statistics.stale_jobs.saturating_add(1);
                    println!("Block candidate was rejected as stale; rebuilding work.");
                    return Ok(());
                }
                Err(_) => {}
            }
        }
        if !interruptible_wait(PEER_RETRY_INTERVAL, shutdown) {
            return Ok(());
        }
    }
    Ok(())
}

fn interruptible_wait(duration: Duration, shutdown: &AtomicBool) -> bool {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if shutdown.load(Ordering::Acquire) {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
    true
}

fn run_full_node_miner(options: FullNodeMinerOptions) -> Result<()> {
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
                let accepted = if !parent_is_current {
                    false
                } else {
                    match submit_shared_tip_block(&node, *block, unix_time_seconds()?) {
                        Ok(_) => true,
                        Err(
                            NodeError::StaleBlockAdmission
                            | NodeError::DuplicateBlock(_)
                            | NodeError::UnknownParent(_)
                            | NodeError::ProofVerificationQueueFull
                            | NodeError::ProofVerificationQueueTimeout,
                        ) => false,
                        Err(error) => return Err(error.into()),
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
            JobOutcome::FoundV3 { device, claim } => {
                println!(
                    "GPU {device} found a target nonce; CPU replay and Layout V5 proof construction started."
                );
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
                    move |proof_cancel| {
                        proof_work
                            .prove_v3_winning_nonce_claim(claim, &proof_cancel)
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
                sender
                    .send(WorkerMessage::FoundV3 {
                        job_id,
                        device: spec.device.index,
                        claim,
                        attempts: pending_attempts,
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
            }) if message_job == job_id => {
                statistics.record_attempts(device, attempts);
                control.worker_cancel.store(true, Ordering::Release);
                return Ok(JobOutcome::FoundV3 { device, claim });
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
    use super::*;

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
