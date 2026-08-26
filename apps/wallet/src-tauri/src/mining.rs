use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cmfd_node::pool::{PoolClient, PoolClientConfig, PoolError, PoolWorkSearchResult};
use cmfd_node::{
    MiningSearchResult, MiningShareSearchResult, Node, NodeClientError, NodeError,
    parse_miner_destination, submit_shared_tip_block,
};
use serde::{Deserialize, Serialize};

use crate::cuda::CudaMiner;

const SEARCH_BATCH_ATTEMPTS: u64 = 4_096;
const POOL_RECONNECT_INITIAL: Duration = Duration::from_millis(250);
const POOL_RECONNECT_MAX: Duration = Duration::from_secs(4);
const POOL_RECONNECT_POLL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MiningMode {
    Solo,
    Pool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MiningLifecycle {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MiningEngine {
    Cpu,
    Cuda,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MiningStartRequest {
    pub mode: MiningMode,
    pub payout: String,
    pub pool_url: Option<String>,
    pub worker_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MinedBlockSummary {
    pub height: u64,
    pub block_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MiningStatus {
    pub lifecycle: MiningLifecycle,
    pub mode: Option<MiningMode>,
    pub payout: Option<String>,
    pub pool_url: Option<String>,
    pub worker_name: Option<String>,
    pub engine: MiningEngine,
    pub device: Option<String>,
    pub matrix_attempts_per_second: f64,
    pub session_attempts: u64,
    pub blocks_found: u64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    pub credited_atoms: String,
    pub pool_connected: bool,
    pub current_height: u64,
    pub last_block: Option<MinedBlockSummary>,
    pub last_error: Option<String>,
}

struct ActiveMiner {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

struct MinerControl {
    worker: Option<ActiveMiner>,
    shutting_down: bool,
}

pub struct MiningManager {
    node: Arc<Mutex<Node>>,
    status: Arc<Mutex<MiningStatus>>,
    control: Mutex<MinerControl>,
}

impl MiningManager {
    pub fn new(node: Arc<Mutex<Node>>) -> Self {
        let current_height = node
            .lock()
            .ok()
            .and_then(|node| node.status().ok())
            .map_or(0, |status| status.accepted_height);
        Self {
            node,
            status: Arc::new(Mutex::new(MiningStatus {
                lifecycle: MiningLifecycle::Stopped,
                mode: None,
                payout: None,
                pool_url: None,
                worker_name: None,
                engine: MiningEngine::Cpu,
                device: None,
                matrix_attempts_per_second: 0.0,
                session_attempts: 0,
                blocks_found: 0,
                shares_accepted: 0,
                shares_rejected: 0,
                credited_atoms: "0".to_owned(),
                pool_connected: false,
                current_height,
                last_block: None,
                last_error: None,
            })),
            control: Mutex::new(MinerControl {
                worker: None,
                shutting_down: false,
            }),
        }
    }

    pub fn status(&self) -> Result<MiningStatus, NodeClientError> {
        self.status
            .lock()
            .map(|status| status.clone())
            .map_err(|_| {
                manager_error(
                    "mining_state_unavailable",
                    "Miner state is unavailable.",
                    true,
                )
            })
    }

    pub fn start(&self, request: MiningStartRequest) -> Result<MiningStatus, NodeClientError> {
        let node_status = self
            .node
            .lock()
            .map_err(|_| {
                manager_error(
                    "mining_node_unavailable",
                    "The embedded node is unavailable.",
                    true,
                )
            })?
            .status()
            .map_err(|error| error.client_error())?;
        if !node_status.bounded_reference_mining {
            return Err(manager_error(
                "production_mining_unavailable",
                format!(
                    "{} is selected for {}; wallet mining will not fall back to DevnetV2.",
                    node_status.proof_profile, node_status.network_short_name
                ),
                false,
            ));
        }
        let payout = decode_payout(&request.payout)?;
        let pool_config = match request.mode {
            MiningMode::Solo => {
                if request
                    .pool_url
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                    || request
                        .worker_name
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
                {
                    return Err(manager_error(
                        "invalid_solo_mining_request",
                        "Solo mining does not accept pool configuration.",
                        false,
                    ));
                }
                None
            }
            MiningMode::Pool => {
                let pool_url = request.pool_url.as_deref().ok_or_else(|| {
                    manager_error("invalid_pool_url", pool_url_requirement(), false)
                })?;
                let worker = request.worker_name.as_deref().ok_or_else(|| {
                    manager_error("invalid_pool_worker", worker_name_requirement(), false)
                })?;
                let endpoint = parse_pool_url(pool_url)?;
                validate_worker_name(worker)?;
                Some(
                    PoolClientConfig::devnet(
                        endpoint.address,
                        endpoint.certificate_pin,
                        worker,
                        payout,
                    )
                    .map_err(|error| {
                        pool_client_error("invalid_pool_configuration", error, false)
                    })?,
                )
            }
        };

        let mut control = self.control.lock().map_err(|_| {
            manager_error(
                "mining_worker_unavailable",
                "Miner control is unavailable.",
                true,
            )
        })?;
        if control.shutting_down {
            return Err(manager_error(
                "mining_shutting_down",
                "The miner is shutting down.",
                false,
            ));
        }
        if control
            .worker
            .as_ref()
            .is_some_and(|active| active.handle.is_finished())
            && let Some(finished) = control.worker.take()
        {
            let _ = finished.handle.join();
        }
        if control.worker.is_some() {
            return Err(manager_error(
                "mining_already_running",
                "The miner is already running.",
                false,
            ));
        }

        let starting = {
            let mut status = self.status.lock().map_err(|_| {
                manager_error(
                    "mining_state_unavailable",
                    "Miner state is unavailable.",
                    true,
                )
            })?;
            let current_height = status.current_height;
            *status = MiningStatus {
                lifecycle: MiningLifecycle::Starting,
                mode: Some(request.mode),
                payout: Some(request.payout.clone()),
                pool_url: request.pool_url.clone(),
                worker_name: request.worker_name.clone(),
                engine: MiningEngine::Cpu,
                device: None,
                matrix_attempts_per_second: 0.0,
                session_attempts: 0,
                blocks_found: 0,
                shares_accepted: 0,
                shares_rejected: 0,
                credited_atoms: "0".to_owned(),
                pool_connected: false,
                current_height,
                last_block: None,
                last_error: None,
            };
            status.clone()
        };

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let node = Arc::clone(&self.node);
        let status = Arc::clone(&self.status);
        let worker_name = match request.mode {
            MiningMode::Solo => "cmfd-solo-miner",
            MiningMode::Pool => "cmfd-pool-miner",
        };
        let handle = thread::Builder::new()
            .name(worker_name.to_owned())
            .spawn(move || match pool_config {
                Some(config) => pool_mining_loop(status, thread_stop, config),
                None => mining_loop(node, status, thread_stop, payout),
            })
            .map_err(|_| {
                if let Ok(mut status) = self.status.lock() {
                    status.lifecycle = MiningLifecycle::Error;
                    status.last_error = Some("The mining worker could not start.".to_owned());
                }
                manager_error(
                    "mining_worker_start_failed",
                    "The mining worker could not start.",
                    true,
                )
            })?;
        control.worker = Some(ActiveMiner { stop, handle });
        Ok(starting)
    }

    pub fn stop(&self) -> Result<MiningStatus, NodeClientError> {
        self.stop_inner(false)
    }

    fn stop_inner(&self, shutting_down: bool) -> Result<MiningStatus, NodeClientError> {
        let mut control = self.control.lock().map_err(|_| {
            manager_error(
                "mining_worker_unavailable",
                "Miner control is unavailable.",
                true,
            )
        })?;
        control.shutting_down |= shutting_down;

        let Some(active) = control.worker.take() else {
            let mut status = self.status.lock().map_err(|_| {
                manager_error(
                    "mining_state_unavailable",
                    "Miner state is unavailable.",
                    true,
                )
            })?;
            status.lifecycle = MiningLifecycle::Stopped;
            status.mode = None;
            status.payout = None;
            status.matrix_attempts_per_second = 0.0;
            status.pool_connected = false;
            status.last_error = None;
            return Ok(status.clone());
        };

        if let Ok(mut status) = self.status.lock() {
            status.lifecycle = MiningLifecycle::Stopping;
        }
        active.stop.store(true, Ordering::Release);
        if active.handle.join().is_err() {
            if let Ok(mut status) = self.status.lock() {
                status.lifecycle = MiningLifecycle::Error;
                status.pool_connected = false;
                status.last_error = Some("The mining worker stopped unexpectedly.".to_owned());
            }
            return Err(manager_error(
                "mining_worker_failed",
                "The mining worker stopped unexpectedly.",
                true,
            ));
        }

        let mut status = self.status.lock().map_err(|_| {
            manager_error(
                "mining_state_unavailable",
                "Miner state is unavailable.",
                true,
            )
        })?;
        status.lifecycle = MiningLifecycle::Stopped;
        status.mode = None;
        status.payout = None;
        status.matrix_attempts_per_second = 0.0;
        status.pool_connected = false;
        Ok(status.clone())
    }

    pub fn stop_for_shutdown(&self) {
        let _ = self.stop_inner(true);
    }
}

fn mining_loop(
    node: Arc<Mutex<Node>>,
    status: Arc<Mutex<MiningStatus>>,
    stop: Arc<AtomicBool>,
    payout: [u8; 32],
) {
    let mut next_nonce = 0_u64;
    let mut cuda = None;
    let mut cuda_initialized = false;

    'jobs: while !stop.load(Ordering::Acquire) {
        let job = match node
            .lock()
            .map_err(|_| NodeError::SharedNodePoisoned)
            .and_then(|node| node.build_mining_job(payout, unix_time_seconds()))
        {
            Ok(job) => job,
            Err(error) => {
                fail_worker(&status, error.client_error().message);
                return;
            }
        };
        if let Ok(mut current) = status.lock() {
            current.lifecycle = MiningLifecycle::Running;
            current.current_height = job.challenge().height.saturating_sub(1);
            current.last_error = None;
        }
        if !cuda_initialized {
            cuda = initialize_solo_cuda(&job, &status);
            cuda_initialized = true;
        }

        loop {
            let started = Instant::now();
            let accelerated = cuda
                .as_mut()
                .map(|backend| search_solo_cuda(&job, backend, next_nonce, &stop));
            let result = match accelerated {
                Some(Ok(result)) => Ok(result),
                Some(Err(error)) => {
                    cuda = None;
                    mark_cuda_fallback(&status, &error);
                    job.search_range(next_nonce, SEARCH_BATCH_ATTEMPTS, || {
                        stop.load(Ordering::Acquire)
                    })
                }
                None => job.search_range(next_nonce, SEARCH_BATCH_ATTEMPTS, || {
                    stop.load(Ordering::Acquire)
                }),
            };
            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    fail_worker(&status, error.client_error().message);
                    return;
                }
            };
            let elapsed = started.elapsed().as_secs_f64();
            let (attempts_completed, following_nonce) = match &result {
                MiningSearchResult::Found {
                    attempts_completed,
                    next_nonce,
                    ..
                }
                | MiningSearchResult::Exhausted {
                    attempts_completed,
                    next_nonce,
                }
                | MiningSearchResult::Cancelled {
                    attempts_completed,
                    next_nonce,
                } => (*attempts_completed, *next_nonce),
            };
            next_nonce = following_nonce;
            if let Ok(mut current) = status.lock() {
                current.session_attempts =
                    current.session_attempts.saturating_add(attempts_completed);
                current.matrix_attempts_per_second = if attempts_completed == 0 {
                    0.0
                } else {
                    attempts_completed as f64 / elapsed.max(f64::EPSILON)
                };
            }

            match result {
                MiningSearchResult::Cancelled { .. } => break 'jobs,
                MiningSearchResult::Exhausted { .. } => {
                    let expected_parent = hex::encode(job.challenge().previous_block);
                    let still_current = node
                        .lock()
                        .ok()
                        .and_then(|node| node.status().ok())
                        .is_some_and(|node_status| node_status.tip == expected_parent);
                    if !still_current {
                        next_nonce = 0;
                        continue 'jobs;
                    }
                }
                MiningSearchResult::Found { block, .. } => {
                    let block_id = block.block_id();
                    let block_id_hex = hex::encode(block_id);
                    let block_height = block.challenge.height;
                    let expected_parent = hex::encode(job.challenge().previous_block);
                    let parent_is_current = node
                        .lock()
                        .map_err(|_| NodeError::SharedNodePoisoned)
                        .and_then(|node| Ok(node.status()?.tip == expected_parent));
                    let submission = parent_is_current.and_then(|parent_is_current| {
                        if !parent_is_current {
                            return Ok(None);
                        }
                        submit_solo_candidate(&node, block.as_ref(), stop.as_ref())
                    });
                    match submission {
                        Ok(Some(node_status)) => {
                            if let Ok(mut current) = status.lock() {
                                current.blocks_found = current.blocks_found.saturating_add(1);
                                current.current_height = node_status.accepted_height;
                                current.last_block = Some(MinedBlockSummary {
                                    height: block_height,
                                    block_id: block_id_hex,
                                });
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            fail_worker(&status, error.client_error().message);
                            return;
                        }
                    }
                    next_nonce = 0;
                    continue 'jobs;
                }
            }
        }
    }

    if let Ok(mut current) = status.lock() {
        current.lifecycle = MiningLifecycle::Stopped;
        current.mode = None;
        current.payout = None;
        current.matrix_attempts_per_second = 0.0;
        current.pool_connected = false;
    }
}

fn submit_solo_candidate(
    node: &Arc<Mutex<Node>>,
    block: &cmfd_consensus::Block,
    stop: &AtomicBool,
) -> Result<Option<cmfd_node::NodeStatus>, NodeError> {
    while !stop.load(Ordering::Acquire) {
        let node_status = node
            .lock()
            .map_err(|_| NodeError::SharedNodePoisoned)?
            .status()?;
        let parent = hex::encode(block.challenge.previous_block);
        let block_id = hex::encode(block.block_id());
        if node_status.tip != parent {
            return Ok((node_status.tip == block_id).then_some(node_status));
        }
        match submit_shared_tip_block(node, block.clone(), unix_time_seconds()) {
            Ok(_) | Err(NodeError::DuplicateBlock(_)) => {
                let node_status = node
                    .lock()
                    .map_err(|_| NodeError::SharedNodePoisoned)?
                    .status()?;
                return Ok((node_status.tip == block_id).then_some(node_status));
            }
            Err(NodeError::StaleBlockAdmission | NodeError::UnknownParent(_)) => return Ok(None),
            Err(NodeError::ProofVerifierShuttingDown) => return Ok(None),
            Err(error) if error.client_error().retryable => {
                if !interruptible_backoff(stop, Duration::from_millis(100)) {
                    return Ok(None);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

fn initialize_solo_cuda(
    job: &cmfd_node::MiningJob,
    status: &Mutex<MiningStatus>,
) -> Option<CudaMiner> {
    let model = match job.accelerator_model() {
        Ok(model) => model,
        Err(error) => {
            mark_cuda_fallback(status, &error.client_error().message);
            return None;
        }
    };
    let mut backend = match CudaMiner::load(&model) {
        Ok(Some(backend)) => backend,
        Ok(None) => return None,
        Err(error) => {
            mark_cuda_fallback(status, &error);
            return None;
        }
    };
    let validation = job
        .prepare_accelerator_batch(0, 1)
        .map_err(|error| error.client_error().message)
        .and_then(|batch| {
            let outputs = backend.evaluate(&batch)?;
            job.verify_accelerator_output(&batch, 0, &outputs)
                .map_err(|error| error.client_error().message)?;
            Ok(())
        });
    if let Err(error) = validation {
        mark_cuda_fallback(status, &format!("CUDA differential check failed: {error}"));
        return None;
    }
    mark_cuda_active(status, backend.device().label());
    Some(backend)
}

fn search_solo_cuda(
    job: &cmfd_node::MiningJob,
    backend: &mut CudaMiner,
    start_nonce: u64,
    stop: &AtomicBool,
) -> Result<MiningSearchResult, String> {
    if stop.load(Ordering::Acquire) {
        return Ok(MiningSearchResult::Cancelled {
            attempts_completed: 0,
            next_nonce: start_nonce,
        });
    }
    let batch = job
        .prepare_accelerator_batch(start_nonce, SEARCH_BATCH_ATTEMPTS as u32)
        .map_err(|error| error.client_error().message)?;
    let outputs = backend.evaluate(&batch)?;
    let result = job
        .complete_accelerator_batch(&batch, &outputs, job.challenge().target)
        .map_err(|error| error.client_error().message)?;
    match result {
        MiningShareSearchResult::Found {
            proof,
            attempts_completed,
            next_nonce,
            ..
        } => {
            let block = job
                .build_block_if_chain_valid(&proof)
                .map_err(|error| error.client_error().message)?
                .ok_or_else(|| {
                    "CUDA candidate did not meet the immutable chain target".to_owned()
                })?;
            Ok(MiningSearchResult::Found {
                block,
                attempts_completed,
                next_nonce,
            })
        }
        MiningShareSearchResult::Exhausted {
            attempts_completed,
            next_nonce,
        } => Ok(MiningSearchResult::Exhausted {
            attempts_completed,
            next_nonce,
        }),
        MiningShareSearchResult::Cancelled {
            attempts_completed,
            next_nonce,
        } => Ok(MiningSearchResult::Cancelled {
            attempts_completed,
            next_nonce,
        }),
    }
}

fn mark_cuda_active(status: &Mutex<MiningStatus>, device: String) {
    if let Ok(mut current) = status.lock() {
        current.engine = MiningEngine::Cuda;
        current.device = Some(device);
        current.last_error = None;
    }
}

fn mark_cuda_fallback(status: &Mutex<MiningStatus>, error: &str) {
    if let Ok(mut current) = status.lock() {
        current.engine = MiningEngine::Cpu;
        current.device = None;
        current.last_error = Some(format!("CUDA unavailable; CPU fallback active. {error}"));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PoolEndpoint {
    address: SocketAddr,
    certificate_pin: [u8; 32],
}

#[derive(Debug, Default)]
struct PoolNonceCursor {
    job_id: Option<[u8; 32]>,
    next_nonce: u64,
}

fn pool_mining_loop(
    status: Arc<Mutex<MiningStatus>>,
    stop: Arc<AtomicBool>,
    config: PoolClientConfig,
) {
    let mut reconnect_delay = POOL_RECONNECT_INITIAL;
    let mut credited_atoms = 0_u64;
    let mut cuda = None;
    let mut cuda_initialized = false;

    while !stop.load(Ordering::Acquire) {
        let mut client = match PoolClient::connect(config.clone()) {
            Ok(client) => client,
            Err(error) if pool_error_is_reconnectable(&error) => {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                mark_pool_reconnecting(&status, &error);
                if !interruptible_backoff(&stop, reconnect_delay) {
                    break;
                }
                reconnect_delay =
                    std::cmp::min(reconnect_delay.saturating_mul(2), POOL_RECONNECT_MAX);
                continue;
            }
            Err(error) => {
                fail_worker(&status, format!("Pool connection rejected: {error}"));
                return;
            }
        };
        if stop.load(Ordering::Acquire) {
            break;
        }

        reconnect_delay = POOL_RECONNECT_INITIAL;
        let current_height = client.current_job().challenge.height.saturating_sub(1);
        if let Ok(mut current) = status.lock() {
            current.lifecycle = MiningLifecycle::Running;
            current.pool_connected = true;
            current.current_height = current_height;
            current.last_error = None;
        }

        match mine_pool_connection(
            &mut client,
            &status,
            &stop,
            &mut credited_atoms,
            &mut cuda,
            &mut cuda_initialized,
        ) {
            Ok(()) => break,
            Err(error) if pool_error_is_reconnectable(&error) => {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                mark_pool_reconnecting(&status, &error);
                if !interruptible_backoff(&stop, reconnect_delay) {
                    break;
                }
                reconnect_delay =
                    std::cmp::min(reconnect_delay.saturating_mul(2), POOL_RECONNECT_MAX);
            }
            Err(error) => {
                fail_worker(&status, format!("Pool mining failed: {error}"));
                return;
            }
        }
    }

    if let Ok(mut current) = status.lock() {
        current.lifecycle = MiningLifecycle::Stopped;
        current.mode = None;
        current.payout = None;
        current.matrix_attempts_per_second = 0.0;
        current.pool_connected = false;
    }
}

fn mine_pool_connection(
    client: &mut PoolClient,
    status: &Mutex<MiningStatus>,
    stop: &AtomicBool,
    credited_atoms: &mut u64,
    cuda: &mut Option<CudaMiner>,
    cuda_initialized: &mut bool,
) -> Result<(), PoolError> {
    let mut remote_credited_atoms = 0_u64;
    let mut cursor = PoolNonceCursor::default();

    while !stop.load(Ordering::Acquire) {
        let work = client.current_work()?;
        let job = work.job();
        if !*cuda_initialized {
            *cuda = initialize_pool_cuda(&work, status);
            *cuda_initialized = true;
        }
        if cursor.job_id != Some(job.job_id) {
            cursor.job_id = Some(job.job_id);
            cursor.next_nonce = client.current_nonce_origin();
        }
        if let Ok(mut current) = status.lock() {
            current.current_height = job.challenge.height.saturating_sub(1);
        }

        let started = Instant::now();
        let accelerated = cuda
            .as_mut()
            .map(|backend| search_pool_cuda(&work, backend, cursor.next_nonce, stop));
        let result = match accelerated {
            Some(Ok(result)) => result,
            Some(Err(error)) => {
                *cuda = None;
                mark_cuda_fallback(status, &error);
                work.search_range(cursor.next_nonce, SEARCH_BATCH_ATTEMPTS, || {
                    stop.load(Ordering::Acquire)
                })?
            }
            None => work.search_range(cursor.next_nonce, SEARCH_BATCH_ATTEMPTS, || {
                stop.load(Ordering::Acquire)
            })?,
        };
        let elapsed = started.elapsed().as_secs_f64();
        let (attempts_completed, next_nonce) = match &result {
            PoolWorkSearchResult::Found {
                attempts_completed,
                next_nonce,
                ..
            }
            | PoolWorkSearchResult::Exhausted {
                attempts_completed,
                next_nonce,
            }
            | PoolWorkSearchResult::Cancelled {
                attempts_completed,
                next_nonce,
            } => (*attempts_completed, *next_nonce),
        };
        cursor.next_nonce = next_nonce;
        if let Ok(mut current) = status.lock() {
            current.session_attempts = current.session_attempts.saturating_add(attempts_completed);
            current.matrix_attempts_per_second = if attempts_completed == 0 {
                0.0
            } else {
                attempts_completed as f64 / elapsed.max(f64::EPSILON)
            };
        }

        match result {
            PoolWorkSearchResult::Cancelled { .. } => return Ok(()),
            PoolWorkSearchResult::Exhausted { .. } => {}
            PoolWorkSearchResult::Found { nonce, .. } => {
                let mut submitted = client.submit_share(job.job_id, nonce)?;
                while submitted.code == "verifier_busy" && !stop.load(Ordering::Acquire) {
                    if !interruptible_backoff(stop, Duration::from_millis(100)) {
                        return Ok(());
                    }
                    submitted = client.submit_share(job.job_id, nonce)?;
                }
                let newly_credited = submitted
                    .session
                    .credited_devnet_atoms
                    .saturating_sub(remote_credited_atoms);
                remote_credited_atoms = submitted.session.credited_devnet_atoms;
                *credited_atoms = credited_atoms.saturating_add(newly_credited);

                if let Ok(mut current) = status.lock() {
                    if submitted.accepted {
                        current.shares_accepted = current.shares_accepted.saturating_add(1);
                    } else {
                        current.shares_rejected = current.shares_rejected.saturating_add(1);
                    }
                    if submitted.block_accepted {
                        current.blocks_found = current.blocks_found.saturating_add(1);
                    }
                    current.credited_atoms = credited_atoms.to_string();
                    current.current_height =
                        client.current_job().challenge.height.saturating_sub(1);
                    current.pool_connected = true;
                    current.last_error = None;
                }
            }
        }
    }
    Ok(())
}

fn initialize_pool_cuda(
    work: &cmfd_node::pool::PoolMiningWork,
    status: &Mutex<MiningStatus>,
) -> Option<CudaMiner> {
    let model = match work.accelerator_model() {
        Ok(model) => model,
        Err(error) => {
            mark_cuda_fallback(status, &error.to_string());
            return None;
        }
    };
    let mut backend = match CudaMiner::load(&model) {
        Ok(Some(backend)) => backend,
        Ok(None) => return None,
        Err(error) => {
            mark_cuda_fallback(status, &error);
            return None;
        }
    };
    let validation = work
        .prepare_accelerator_batch(0, 1)
        .map_err(|error| error.to_string())
        .and_then(|batch| {
            let outputs = backend.evaluate(&batch)?;
            work.verify_accelerator_output(&batch, 0, &outputs)
                .map_err(|error| error.to_string())?;
            Ok(())
        });
    if let Err(error) = validation {
        mark_cuda_fallback(status, &format!("CUDA differential check failed: {error}"));
        return None;
    }
    mark_cuda_active(status, backend.device().label());
    Some(backend)
}

fn search_pool_cuda(
    work: &cmfd_node::pool::PoolMiningWork,
    backend: &mut CudaMiner,
    start_nonce: u64,
    stop: &AtomicBool,
) -> Result<PoolWorkSearchResult, String> {
    if stop.load(Ordering::Acquire) {
        return Ok(PoolWorkSearchResult::Cancelled {
            attempts_completed: 0,
            next_nonce: start_nonce,
        });
    }
    let batch = work
        .prepare_accelerator_batch(start_nonce, SEARCH_BATCH_ATTEMPTS as u32)
        .map_err(|error| error.to_string())?;
    let outputs = backend.evaluate(&batch)?;
    work.complete_accelerator_batch(&batch, &outputs)
        .map_err(|error| error.to_string())
}

fn interruptible_backoff(stop: &AtomicBool, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        thread::sleep(std::cmp::min(remaining, POOL_RECONNECT_POLL));
    }
}

fn pool_error_is_reconnectable(error: &PoolError) -> bool {
    matches!(
        error,
        PoolError::Io(_) | PoolError::ConnectionClosed | PoolError::MessageCountLimit
    )
}

fn mark_pool_reconnecting(status: &Mutex<MiningStatus>, error: &PoolError) {
    if let Ok(mut current) = status.lock() {
        current.pool_connected = false;
        current.matrix_attempts_per_second = 0.0;
        current.last_error = Some(format!("Pool connection lost; retrying: {error}"));
    }
}

fn parse_pool_url(value: &str) -> Result<PoolEndpoint, NodeClientError> {
    let Some(remainder) = value.strip_prefix("cmfd+tls://") else {
        return Err(manager_error(
            "invalid_pool_url",
            pool_url_requirement(),
            false,
        ));
    };
    let Some((authority, pin_text)) = remainder.split_once("?pin=") else {
        return Err(manager_error(
            "invalid_pool_url",
            pool_url_requirement(),
            false,
        ));
    };
    if pin_text.len() != 64 || !pin_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(manager_error(
            "invalid_pool_url",
            pool_url_requirement(),
            false,
        ));
    }
    let certificate_pin: [u8; 32] = hex::decode(pin_text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| manager_error("invalid_pool_url", pool_url_requirement(), false))?;

    let (ip, port_text) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, port)) = bracketed.split_once("]:") else {
            return Err(manager_error(
                "invalid_pool_url",
                pool_url_requirement(),
                false,
            ));
        };
        let ip = host
            .parse::<Ipv6Addr>()
            .map(IpAddr::V6)
            .map_err(|_| manager_error("invalid_pool_url", pool_url_requirement(), false))?;
        (ip, port)
    } else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return Err(manager_error(
                "invalid_pool_url",
                pool_url_requirement(),
                false,
            ));
        };
        if host.split('.').any(|octet| {
            octet.is_empty()
                || (octet.len() > 1 && octet.starts_with('0'))
                || !octet.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            return Err(manager_error(
                "invalid_pool_url",
                pool_url_requirement(),
                false,
            ));
        }
        let ip = host
            .parse::<std::net::Ipv4Addr>()
            .map(IpAddr::V4)
            .map_err(|_| manager_error("invalid_pool_url", pool_url_requirement(), false))?;
        (ip, port)
    };

    if port_text.is_empty()
        || port_text.len() > 5
        || !port_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(manager_error(
            "invalid_pool_url",
            pool_url_requirement(),
            false,
        ));
    }
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| manager_error("invalid_pool_url", pool_url_requirement(), false))?;
    let private_or_loopback = match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
    };
    if !private_or_loopback {
        return Err(manager_error(
            "invalid_pool_url",
            pool_url_requirement(),
            false,
        ));
    }

    Ok(PoolEndpoint {
        address: SocketAddr::new(ip, port),
        certificate_pin,
    })
}

fn validate_worker_name(value: &str) -> Result<(), NodeClientError> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(manager_error(
            "invalid_pool_worker",
            worker_name_requirement(),
            false,
        ));
    }
    Ok(())
}

fn pool_url_requirement() -> &'static str {
    "Use cmfd+tls://PRIVATE_IP:PORT?pin=64_HEX with a private or loopback numeric IP."
}

fn worker_name_requirement() -> &'static str {
    "Use 1-32 letters, numbers, dots, underscores, or hyphens."
}

fn decode_payout(value: &str) -> Result<[u8; 32], NodeClientError> {
    parse_miner_destination(value).map_err(|_| {
        manager_error(
            "invalid_mining_payout",
            "The mining payout destination must be a 64-character x-only public key.",
            false,
        )
    })
}

fn fail_worker(status: &Mutex<MiningStatus>, message: String) {
    if let Ok(mut current) = status.lock() {
        current.lifecycle = MiningLifecycle::Error;
        current.matrix_attempts_per_second = 0.0;
        current.pool_connected = false;
        current.last_error = Some(message);
    }
}

fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn manager_error(
    code: &'static str,
    message: impl Into<String>,
    retryable: bool,
) -> NodeClientError {
    NodeClientError {
        code,
        status: 503,
        retryable,
        message: message.into(),
    }
}

fn pool_client_error(code: &'static str, error: PoolError, retryable: bool) -> NodeClientError {
    manager_error(code, error.to_string(), retryable)
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "production-v3-testnet"))]
    use std::fs;
    #[cfg(not(feature = "production-v3-testnet"))]
    use std::path::PathBuf;
    #[cfg(not(feature = "production-v3-testnet"))]
    use std::sync::Barrier;
    use std::time::Duration;

    use cmfd_node::default_miner_destination;
    #[cfg(not(feature = "production-v3-testnet"))]
    use cmfd_node::pool::{PoolServerConfig, generate_pool_certificate, spawn_pool_server};

    use super::*;

    #[cfg(not(feature = "production-v3-testnet"))]
    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-desktop-mining-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[cfg(not(feature = "production-v3-testnet"))]
    fn request(mode: MiningMode) -> MiningStartRequest {
        MiningStartRequest {
            mode,
            payout: hex::encode(default_miner_destination()),
            pool_url: None,
            worker_name: None,
        }
    }

    #[cfg(not(feature = "production-v3-testnet"))]
    fn pool_request(pool_url: String, worker: &str) -> MiningStartRequest {
        MiningStartRequest {
            mode: MiningMode::Pool,
            payout: hex::encode(default_miner_destination()),
            pool_url: Some(pool_url),
            worker_name: Some(worker.to_owned()),
        }
    }

    #[cfg(not(feature = "production-v3-testnet"))]
    #[test]
    fn continuous_solo_mining_starts_finds_work_and_stops() {
        let path = test_dir("solo");
        let node = Arc::new(Mutex::new(Node::open(&path).unwrap()));
        let manager = MiningManager::new(node);

        let starting = manager.start(request(MiningMode::Solo)).unwrap();
        assert_eq!(starting.lifecycle, MiningLifecycle::Starting);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let current = manager.status().unwrap();
            if current.blocks_found > 0 {
                assert_eq!(current.lifecycle, MiningLifecycle::Running);
                assert!(current.session_attempts > 0);
                assert!(current.matrix_attempts_per_second.is_finite());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "solo miner did not find Devnet work"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let stopped = manager.stop().unwrap();
        assert_eq!(stopped.lifecycle, MiningLifecycle::Stopped);
        assert_eq!(stopped.mode, None);
        assert!(stopped.blocks_found > 0);
        drop(manager);
        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(not(feature = "production-v3-testnet"))]
    #[test]
    fn invalid_pool_configuration_and_duplicate_start_are_rejected() {
        let path = test_dir("guards");
        let node = Arc::new(Mutex::new(Node::open(&path).unwrap()));
        let manager = MiningManager::new(node);

        let pool = manager.start(request(MiningMode::Pool)).unwrap_err();
        assert_eq!(pool.code, "invalid_pool_url");
        manager.start(request(MiningMode::Solo)).unwrap();
        let duplicate = manager.start(request(MiningMode::Solo)).unwrap_err();
        assert_eq!(duplicate.code, "mining_already_running");
        manager.stop().unwrap();
        drop(manager);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn mining_payout_requires_a_valid_x_only_schnorr_key() {
        assert_eq!(
            decode_payout(&hex::encode(default_miner_destination())).unwrap(),
            default_miner_destination()
        );
        for invalid in ["00".to_owned(), "ff".repeat(32), "gg".repeat(32)] {
            let error = decode_payout(&invalid).unwrap_err();
            assert_eq!(error.code, "invalid_mining_payout");
        }
    }

    #[test]
    fn pool_url_and_worker_validation_match_the_wallet_contract() {
        let pin = "ab".repeat(32);
        for valid in [
            format!("cmfd+tls://127.0.0.1:443?pin={pin}"),
            format!("cmfd+tls://10.24.1.9:18181?pin={pin}"),
            format!("cmfd+tls://172.16.0.2:65535?pin={pin}"),
            format!("cmfd+tls://192.168.50.12:1?pin={pin}"),
            format!("cmfd+tls://[::1]:443?pin={pin}"),
            format!("cmfd+tls://[fd12:3456::9]:8443?pin={pin}"),
        ] {
            assert!(
                parse_pool_url(&valid).is_ok(),
                "valid URL rejected: {valid}"
            );
        }
        for invalid in [
            format!("cmfd+tls://pool.example:443?pin={pin}"),
            format!("cmfd+tls://8.8.8.8:443?pin={pin}"),
            format!("cmfd+tls://192.168.1.2:0?pin={pin}"),
            format!("cmfd+tls://192.168.1.2:65536?pin={pin}"),
            "cmfd+tls://192.168.1.2:443?pin=abcd".to_owned(),
            format!("cmfd+tls://192.168.1.2:443/path?pin={pin}"),
            format!("cmfd+tls://192.168.1.2:443?pin={pin}&extra=1"),
            format!("cmfd+tls://[fe80::1]:443?pin={pin}"),
            format!("cmfd+tls://[fd12:::1]:443?pin={pin}"),
            format!("cmfd+tls://127.00.0.1:443?pin={pin}"),
        ] {
            let error = parse_pool_url(&invalid).unwrap_err();
            assert_eq!(
                error.code, "invalid_pool_url",
                "invalid URL accepted: {invalid}"
            );
        }

        for valid in ["a", "worker.01", "WORKER_name-32"] {
            assert!(validate_worker_name(valid).is_ok());
        }
        for invalid in ["", "worker name", "worker/1", "node@home", &"x".repeat(33)] {
            let error = validate_worker_name(invalid).unwrap_err();
            assert_eq!(error.code, "invalid_pool_worker");
        }
    }

    #[cfg(not(feature = "production-v3-testnet"))]
    #[test]
    fn pool_mining_uses_pinned_tls_tracks_real_shares_and_never_mines_local_node() {
        let wallet_path = test_dir("pool-wallet-node");
        let pool_path = test_dir("pool-server-node");
        let certificate_dir = test_dir("pool-certificate");
        fs::create_dir_all(&certificate_dir).unwrap();

        let wallet_node = Arc::new(Mutex::new(Node::open(&wallet_path).unwrap()));
        let pool_node = Arc::new(Mutex::new(Node::open(&pool_path).unwrap()));
        let certificate = certificate_dir.join("pool.crt.der");
        let private_key = certificate_dir.join("pool.key.der");
        let certificate_info = generate_pool_certificate(&certificate, &private_key).unwrap();
        let server = spawn_pool_server(
            Arc::clone(&pool_node),
            PoolServerConfig::devnet(
                "127.0.0.1:0".parse().unwrap(),
                fs::read(&certificate).unwrap(),
                fs::read(&private_key).unwrap(),
                default_miner_destination(),
            ),
        )
        .unwrap();
        let pool_url = format!(
            "cmfd+tls://{}?pin={}",
            server.local_addr(),
            hex::encode(certificate_info.certificate_sha256)
        );
        let manager = MiningManager::new(Arc::clone(&wallet_node));

        let starting = manager
            .start(pool_request(pool_url.clone(), "wallet-worker"))
            .unwrap();
        assert_eq!(starting.lifecycle, MiningLifecycle::Starting);
        assert_eq!(starting.mode, Some(MiningMode::Pool));
        assert_eq!(starting.pool_url.as_deref(), Some(pool_url.as_str()));
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let current = manager.status().unwrap();
            if current.shares_accepted > 0 && current.blocks_found > 0 {
                assert_eq!(current.lifecycle, MiningLifecycle::Running);
                assert!(current.pool_connected);
                assert!(current.session_attempts > 0);
                assert!(current.matrix_attempts_per_second.is_finite());
                assert!(current.credited_atoms.parse::<u64>().unwrap() > 0);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "pool miner did not confirm a Devnet share and block: {current:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let stopped = manager.stop().unwrap();
        assert_eq!(stopped.lifecycle, MiningLifecycle::Stopped);
        assert_eq!(stopped.mode, None);
        assert!(!stopped.pool_connected);
        assert_eq!(
            wallet_node
                .lock()
                .unwrap()
                .status()
                .unwrap()
                .accepted_height,
            0
        );
        assert!(pool_node.lock().unwrap().status().unwrap().accepted_height > 0);

        manager
            .start(pool_request(pool_url, "wallet-worker-restart"))
            .unwrap();
        let restart_deadline = Instant::now() + Duration::from_secs(5);
        while !manager.status().unwrap().pool_connected {
            assert!(
                Instant::now() < restart_deadline,
                "restarted pool miner did not reconnect"
            );
            thread::sleep(Duration::from_millis(10));
        }
        manager.stop_for_shutdown();
        assert_eq!(
            manager.start(request(MiningMode::Solo)).unwrap_err().code,
            "mining_shutting_down"
        );

        server.stop().unwrap();
        drop(manager);
        drop(wallet_node);
        drop(pool_node);
        fs::remove_dir_all(wallet_path).unwrap();
        fs::remove_dir_all(pool_path).unwrap();
        fs::remove_dir_all(certificate_dir).unwrap();
    }

    #[test]
    fn pool_reconnect_backoff_is_interruptible() {
        assert!(pool_error_is_reconnectable(&PoolError::MessageCountLimit));
        assert!(!pool_error_is_reconnectable(&PoolError::ProtocolMismatch));

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let interrupter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            thread_stop.store(true, Ordering::Release);
        });
        let started = Instant::now();
        assert!(!interruptible_backoff(&stop, Duration::from_secs(4)));
        assert!(started.elapsed() < Duration::from_secs(1));
        interrupter.join().unwrap();
    }

    #[cfg(not(feature = "production-v3-testnet"))]
    #[test]
    fn concurrent_start_and_stop_leave_worker_and_status_consistent() {
        let path = test_dir("concurrent-control");
        let node = Arc::new(Mutex::new(Node::open(&path).unwrap()));
        let manager = Arc::new(MiningManager::new(node));
        manager.start(request(MiningMode::Solo)).unwrap();

        let barrier = Arc::new(Barrier::new(3));
        let stop_manager = Arc::clone(&manager);
        let stop_barrier = Arc::clone(&barrier);
        let stopper = thread::spawn(move || {
            stop_barrier.wait();
            stop_manager.stop()
        });
        let start_manager = Arc::clone(&manager);
        let start_barrier = Arc::clone(&barrier);
        let starter = thread::spawn(move || {
            start_barrier.wait();
            start_manager.start(request(MiningMode::Solo))
        });

        barrier.wait();
        let stopped = stopper.join().unwrap().unwrap();
        assert_eq!(stopped.lifecycle, MiningLifecycle::Stopped);
        match starter.join().unwrap() {
            Ok(_) => {
                let control = manager.control.lock().unwrap();
                assert!(control.worker.is_some());
                assert!(matches!(
                    manager.status().unwrap().lifecycle,
                    MiningLifecycle::Starting | MiningLifecycle::Running
                ));
                drop(control);
                manager.stop().unwrap();
            }
            Err(error) => {
                assert_eq!(error.code, "mining_already_running");
                let control = manager.control.lock().unwrap();
                assert!(control.worker.is_none());
                assert_eq!(
                    manager.status().unwrap().lifecycle,
                    MiningLifecycle::Stopped
                );
            }
        }

        drop(manager);
        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(not(feature = "production-v3-testnet"))]
    #[test]
    fn shutdown_permanently_rejects_starts_and_drains_the_worker() {
        let path = test_dir("shutdown-control");
        let node = Arc::new(Mutex::new(Node::open(&path).unwrap()));
        let manager = MiningManager::new(node);
        manager.start(request(MiningMode::Solo)).unwrap();

        manager.stop_for_shutdown();

        let control = manager.control.lock().unwrap();
        assert!(control.shutting_down);
        assert!(control.worker.is_none());
        drop(control);
        assert_eq!(
            manager.status().unwrap().lifecycle,
            MiningLifecycle::Stopped
        );
        let restart = manager.start(request(MiningMode::Solo)).unwrap_err();
        assert_eq!(restart.code, "mining_shutting_down");

        drop(manager);
        fs::remove_dir_all(path).unwrap();
    }
}
