use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use cmfd_consensus::BlockProof;
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
    MiningShareSearchResult, MiningWork, Node, parse_miner_destination, unix_time_seconds,
};

mod telemetry;

use telemetry::{GpuTelemetry, query_nvidia_smi};

const DEFAULT_MINER_DATA_DIR: &str = "commonfoundry-miner-devnet0";
const DEFAULT_MINER_P2P_ADDRESS: &str = "127.0.0.1:19444";
const DEFAULT_BATCH_SIZE: u32 = 8_192;
const MAX_BATCH_SIZE: u32 = 65_536;
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
        /// Devnet node that provides jobs and accepts blocks. Repeat for failover.
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        /// Allow numeric public peer addresses for Devnet testing.
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
    },
    /// Mine with an embedded full node and local chain database.
    FullNode {
        #[arg(long, default_value = DEFAULT_MINER_DATA_DIR)]
        data_dir: PathBuf,
        #[arg(long, default_value = DEFAULT_MINER_P2P_ADDRESS)]
        p2p_bind: SocketAddr,
        /// Static Devnet peer. Repeat to configure more than one.
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        /// Allow numeric public peer addresses for Devnet testing.
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
    },
}

#[derive(Debug)]
enum WorkerMessage {
    Ready {
        device: i32,
        lane: usize,
    },
    Progress {
        device: i32,
        attempts: u64,
    },
    Found {
        device: i32,
        proof: BlockProof,
        attempts: u64,
    },
    Failed {
        device: i32,
        lane: usize,
        error: String,
    },
}

enum JobOutcome {
    Found { device: i32, proof: BlockProof },
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

struct WorkerSet {
    cancel: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

struct WorkerSpec {
    cuda: CudaLibrary,
    device: CudaDevice,
    ordinal: usize,
    lane: usize,
    worker_count: usize,
    work: MiningWork,
    batch_size: u32,
}

impl WorkerSet {
    fn stop(self) -> Result<()> {
        self.cancel.store(true, Ordering::Release);
        for handle in self.handles {
            handle
                .join()
                .map_err(|_| anyhow!("a CUDA worker thread panicked"))?;
        }
        Ok(())
    }
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
        } => run_thin_miner(ThinMinerOptions {
            peers,
            allow_public_peers,
            requested_devices: devices,
            cuda_library,
            batch_size,
            workers_per_gpu,
            miner,
            stats_seconds,
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
        }),
    }
}

fn load_cuda(path: Option<&Path>) -> Result<CudaLibrary> {
    CudaLibrary::load(path)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow!("ForgeMatrix CUDA library was not found beside cmfd-miner"))
}

fn list_devices(path: Option<&Path>) -> Result<()> {
    let library = load_cuda(path)?;
    let devices = library.devices().map_err(anyhow::Error::msg)?;
    println!("CUDA library: {}", library.path().display());
    if devices.is_empty() {
        println!("No NVIDIA CUDA devices found.");
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
                "supported"
            } else {
                "requires CUDA compute capability 7.0+"
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
    batch_size: u32,
    workers_per_gpu: usize,
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
        listen_address: DEFAULT_MINER_P2P_ADDRESS.parse()?,
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
    println!("CUDA library: {}", cuda.path().display());
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
        let outcome = mine_work(
            cuda.clone(),
            devices.clone(),
            work,
            JobMiningConfig {
                batch_size: options.batch_size,
                workers_per_gpu,
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
        }
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
    println!("CUDA library: {}", cuda.path().display());
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
        match mine_work(
            cuda.clone(),
            devices.clone(),
            job.work(),
            JobMiningConfig {
                batch_size: config.batch_size,
                workers_per_gpu: config.workers_per_gpu,
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
        }
    }
    println!("Miner stopped.");
    Ok(())
}

fn mine_work(
    cuda: CudaLibrary,
    devices: Vec<CudaDevice>,
    work: MiningWork,
    config: JobMiningConfig,
    shutdown: Arc<AtomicBool>,
    statistics: &mut SessionStatistics,
    check_status: &mut dyn FnMut() -> Result<WorkStatus>,
) -> Result<JobOutcome> {
    let worker_cancel = Arc::new(AtomicBool::new(false));
    let worker_count = devices
        .len()
        .checked_mul(config.workers_per_gpu)
        .ok_or_else(|| anyhow!("CUDA worker count overflow"))?;
    let (sender, receiver) = mpsc::sync_channel(worker_count.saturating_mul(4).max(4));
    let mut handles = Vec::with_capacity(worker_count);
    for (device_ordinal, device) in devices.iter().enumerate() {
        for lane in 0..config.workers_per_gpu {
            handles.push(spawn_worker(
                WorkerSpec {
                    cuda: cuda.clone(),
                    device: device.clone(),
                    ordinal: device_ordinal * config.workers_per_gpu + lane,
                    lane,
                    worker_count,
                    work: work.clone(),
                    batch_size: config.batch_size,
                },
                Arc::clone(&worker_cancel),
                sender.clone(),
            ));
        }
    }
    drop(sender);
    let workers = WorkerSet {
        cancel: Arc::clone(&worker_cancel),
        handles,
    };

    let outcome = monitor_workers(
        &devices,
        &work,
        &receiver,
        MonitorControl {
            stats_interval: config.stats_interval,
            shutdown,
            worker_cancel,
        },
        config.workers_per_gpu,
        statistics,
        check_status,
    );
    workers.stop()?;
    outcome
}

fn spawn_worker(
    spec: WorkerSpec,
    cancel: Arc<AtomicBool>,
    sender: SyncSender<WorkerMessage>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name(format!("cmfd-gpu-{}-lane-{}", spec.device.index, spec.lane))
        .spawn(move || {
            if let Err(error) = run_worker(&spec, &cancel, &sender) {
                cancel.store(true, Ordering::Release);
                let _ = sender.send(WorkerMessage::Failed {
                    device: spec.device.index,
                    lane: spec.lane,
                    error,
                });
            }
        })
        .expect("named CUDA worker thread creation should succeed")
}

fn run_worker(
    spec: &WorkerSpec,
    cancel: &AtomicBool,
    sender: &SyncSender<WorkerMessage>,
) -> Result<(), String> {
    let model = spec
        .work
        .accelerator_model()
        .map_err(|error| error.client_error().message)?;
    let mut miner = spec.cuda.create(&model, spec.device.index)?;
    let canary = spec
        .work
        .prepare_accelerator_batch(spec.ordinal as u64, 1)
        .map_err(|error| error.client_error().message)?;
    let canary_output = miner.evaluate(&canary)?;
    spec.work
        .verify_accelerator_output(&canary, 0, &canary_output)
        .map_err(|error| {
            format!(
                "CUDA differential check failed: {}",
                error.client_error().message
            )
        })?;
    sender
        .send(WorkerMessage::Ready {
            device: spec.device.index,
            lane: spec.lane,
        })
        .map_err(|_| "miner coordinator closed during startup".to_owned())?;

    let stride = nonce_stride(spec.batch_size, spec.worker_count);
    let mut next_nonce = nonce_start(spec.batch_size, spec.ordinal);
    let mut pending_attempts = 0_u64;
    while !cancel.load(Ordering::Acquire) {
        let batch = spec
            .work
            .prepare_accelerator_batch(next_nonce, spec.batch_size)
            .map_err(|error| error.client_error().message)?;
        let outputs = miner.evaluate(&batch)?;
        pending_attempts = pending_attempts.saturating_add(u64::from(spec.batch_size));
        let result = spec
            .work
            .complete_accelerator_batch(&batch, &outputs)
            .map_err(|error| error.client_error().message)?;
        match result {
            MiningShareSearchResult::Found { proof, .. } => {
                cancel.store(true, Ordering::Release);
                sender
                    .send(WorkerMessage::Found {
                        device: spec.device.index,
                        proof,
                        attempts: pending_attempts,
                    })
                    .map_err(|_| "miner coordinator closed before block submission".to_owned())?;
                return Ok(());
            }
            MiningShareSearchResult::Exhausted { .. } => {}
            MiningShareSearchResult::Cancelled { .. } => return Ok(()),
        }

        if sender
            .try_send(WorkerMessage::Progress {
                device: spec.device.index,
                attempts: pending_attempts,
            })
            .is_ok()
        {
            pending_attempts = 0;
        }
        next_nonce = next_nonce.wrapping_add(stride);
    }
    Ok(())
}

fn monitor_workers(
    devices: &[CudaDevice],
    work: &MiningWork,
    receiver: &Receiver<WorkerMessage>,
    control: MonitorControl,
    workers_per_gpu: usize,
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
            Ok(WorkerMessage::Ready { device, lane }) => {
                ready.insert((device, lane));
                let device_ready = ready
                    .iter()
                    .filter(|(ready_device, _)| *ready_device == device)
                    .count();
                if device_ready == workers_per_gpu {
                    println!(
                        "GPU {device} initialized with {workers_per_gpu} worker(s) ({}/{})",
                        ready.len(),
                        devices.len().saturating_mul(workers_per_gpu)
                    );
                }
            }
            Ok(WorkerMessage::Progress { device, attempts }) => {
                statistics.record_attempts(device, attempts);
            }
            Ok(WorkerMessage::Found {
                device,
                proof,
                attempts,
            }) => {
                statistics.record_attempts(device, attempts);
                control.worker_cancel.store(true, Ordering::Release);
                return Ok(JobOutcome::Found { device, proof });
            }
            Ok(WorkerMessage::Failed {
                device,
                lane,
                error,
            }) => {
                control.worker_cancel.store(true, Ordering::Release);
                bail!("GPU {device} worker {lane} failed: {error}");
            }
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

    fn device(index: i32, major: u32, minor: u32) -> CudaDevice {
        CudaDevice {
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
