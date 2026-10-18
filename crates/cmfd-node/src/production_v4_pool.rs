//! Persistent ProductionV4 pool share verification.
//!
//! The pool owns both workers. Ordinary shares run only the exact GPU replay
//! needed to recompute their work digest. A chain-winning replay is repeated
//! in full mode and proved; the resulting proof is still passed through the
//! normal consensus verifier by `pool::process_share`.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use cmfd_consensus::forgematrix_v4_proof::forgematrix_v4_final_activation_digest;
use cmfd_consensus::forgematrix_v4_proof_codec::decode_forgematrix_v4_transparent_proof;
use cmfd_consensus::{
    BlockProof, FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_PROOF_VERSION,
    FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES, ForgeMatrixV4CandidateProof,
    PRODUCTION_V2_LAYERS, PRODUCTION_V4_MAX_PROOF_BYTES, PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
    forgematrix_v4_challenge_digest, forgematrix_v4_final_activation_digest_from_le_bytes,
    forgematrix_v4_proof_system_digest, forgematrix_v4_replay_coefficients,
    forgematrix_v4_work_digest,
};
use serde::Serialize;

use crate::honest_work::{GpuReplay, PoolReplayResult, WORK_KNOWN_ANSWERS};
use crate::pool::{
    PoolError, PoolJob, PoolWorkSearchResult, ProductionV4PoolShareEvaluation,
    ProductionV4PoolShareRequest, ProductionV4PoolShareVerifier,
};
use crate::{BlockTemplate, COMPILED_NETWORK_PROFILE};

const WORKER_OUTPUT_MAX_LINES: usize = 4_096;
const WORKER_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
/// Longest wait for a worker to load its model and report ready.
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(600);
/// Longest wait for one command (a 64-nonce batch on a slow GPU, or a proof).
/// A worker that says nothing for this long is killed and restarted, so a
/// wedged GPU process cannot hold the worker lock forever.
const WORKER_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
/// After a worker fails to start, wait this long before trying again.
const WORKER_RESTART_BACKOFF: Duration = Duration::from_secs(10);
/// How long a found block's replay worker may take to replay one known
/// answer before the proof. `RUNBATCH 1` takes about 50 ms once the model
/// is loaded, so this only cuts short a worker that has stalled.
const FOUND_BLOCK_KNOWN_ANSWER_TIMEOUT: Duration = Duration::from_secs(2);
const FROZEN_TEMPLATE_FORMAT_VERSION: u16 = 1;
pub const PRODUCTION_V4_POOL_SEARCH_MAX_BATCH_SIZE: u32 = 64;

/// One exact command used to start a persistent worker. Arguments must include
/// the worker's `--server` flag and authenticated model/artifact paths.
#[derive(Debug, Clone)]
pub struct ProductionV4PoolWorkerCommand {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    /// Process-local environment overrides. Never mutate the node's environment
    /// to select a miner GPU: several workers may coexist in one process.
    pub environment: Vec<(OsString, OsString)>,
}

/// Paths and commands for one pool-owned ProductionV4 verifier.
///
/// `scratch_directory` is the path visible to the node. The worker path names
/// the same directory as seen by its process, which permits a native Windows
/// node to supervise Linux workers through WSL.
#[derive(Debug, Clone)]
pub struct ProductionV4PoolVerifierConfig {
    pub replay: ProductionV4PoolWorkerCommand,
    /// More replay workers, usually one per extra GPU. Batches run on all of
    /// them at once; the first `replay` worker also serves single shares.
    pub extra_replays: Vec<ProductionV4PoolWorkerCommand>,
    pub proof: ProductionV4PoolWorkerCommand,
    pub scratch_directory: PathBuf,
    pub worker_scratch_directory: String,
    /// The replay worker file block work checks may use. Without it, or
    /// while a replay worker runs a file that does not match it, a work
    /// check refuses that worker; shares use it either way.
    pub work_check_pin: Option<ReplayWorkerPin>,
}

/// A replay worker file named by its SHA-256. Each time a replay worker
/// starts, the file is hashed first; only a worker started from a matching
/// file serves block work checks.
#[derive(Debug, Clone)]
pub struct ReplayWorkerPin {
    executable: PathBuf,
    sha256: [u8; 32],
}

impl ReplayWorkerPin {
    /// Pins `executable` (the file the replay workers run, not the WSL
    /// launcher) to `sha256`.
    pub fn new(executable: PathBuf, sha256: [u8; 32]) -> Self {
        Self { executable, sha256 }
    }

    /// Pins `executable` to the release's replay worker if it is that
    /// build; otherwise returns the file's own SHA-256.
    pub fn release(executable: PathBuf) -> Result<Result<Self, [u8; 32]>, PoolError> {
        let sha256 = file_sha256(&executable)?;
        if sha256 == production_v4_release_replay_worker_sha256() {
            Ok(Ok(Self::new(executable, sha256)))
        } else {
            Ok(Err(sha256))
        }
    }

    /// Whether the file now has the pinned SHA-256. A file that cannot be
    /// read does not match.
    fn matches(&self) -> bool {
        file_sha256(&self.executable).is_ok_and(|sha256| sha256 == self.sha256)
    }
}

/// The SHA-256 of the replay worker shipped with this release.
pub fn production_v4_release_replay_worker_sha256() -> [u8; 32] {
    crate::release_gate::PRODUCTION_V4_REPLAY_WORKER_SHA256
}

/// The SHA-256 of the file at `path`.
pub fn file_sha256(path: &Path) -> Result<[u8; 32], PoolError> {
    use sha2::{Digest, Sha256};
    let mut file = File::open(path).map_err(replay_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(replay_error)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[derive(Debug, Clone)]
pub struct ProductionV4PoolSearcherConfig {
    pub replay: ProductionV4PoolWorkerCommand,
    pub scratch_directory: PathBuf,
    pub worker_scratch_directory: String,
    pub batch_size: u32,
}

pub fn production_v4_pool_searcher_config(
    replay_worker: &Path,
    model_bank: &Path,
    scratch_directory: &Path,
    batch_size: u32,
    wsl_distribution: Option<&str>,
    cuda_visible_device: Option<&str>,
) -> Result<ProductionV4PoolSearcherConfig, PoolError> {
    let selected_device = production_v4_worker_cuda_visible_device(cuda_visible_device)?;
    let replay_worker = canonical_worker_file(replay_worker, "ProductionV4 pool search worker")?;
    let model_bank = canonical_worker_file(model_bank, "ProductionV4 model bank")?;
    if !scratch_directory.is_absolute() {
        return Err(pool_replay_failure(
            "ProductionV4 pool search scratch directory must be absolute",
        ));
    }
    fs::create_dir_all(scratch_directory).map_err(replay_error)?;
    let scratch_directory =
        crate::plain_package_path(fs::canonicalize(scratch_directory).map_err(replay_error)?);

    match wsl_distribution {
        Some(distribution) => {
            validate_wsl_distribution(distribution)?;
            #[cfg(not(windows))]
            {
                let _ = (replay_worker, model_bank, scratch_directory);
                Err(pool_replay_failure(
                    "ProductionV4 WSL pool search requires Windows",
                ))
            }
            #[cfg(windows)]
            {
                let system_root = std::env::var_os("SystemRoot")
                    .ok_or_else(|| pool_replay_failure("SystemRoot is unavailable"))?;
                let wsl = canonical_worker_file(
                    &PathBuf::from(system_root).join("System32").join("wsl.exe"),
                    "WSL launcher",
                )?;
                let replay_worker = wsl_path(&wsl, distribution, &replay_worker)?;
                let model_bank = wsl_path(&wsl, distribution, &model_bank)?;
                let worker_scratch_directory = wsl_path(&wsl, distribution, &scratch_directory)?;
                let arguments = vec![
                    "-d".into(),
                    distribution.into(),
                    "--exec".into(),
                    "env".into(),
                    format!("CUDA_VISIBLE_DEVICES={selected_device}").into(),
                    "CUDA_HOME=/usr/local/cuda-12.8".into(),
                    "CUDA_PATH=/usr/local/cuda-12.8".into(),
                    "CUDAToolkit_ROOT=/usr/local/cuda-12.8".into(),
                    "LD_LIBRARY_PATH=/usr/local/cuda-12.8/lib64".into(),
                    replay_worker.into(),
                    "--server".into(),
                    model_bank.into(),
                ];
                Ok(ProductionV4PoolSearcherConfig {
                    replay: ProductionV4PoolWorkerCommand {
                        program: wsl,
                        arguments,
                        environment: vec![],
                    },
                    scratch_directory,
                    worker_scratch_directory,
                    batch_size,
                })
            }
        }
        None => Ok(ProductionV4PoolSearcherConfig {
            replay: ProductionV4PoolWorkerCommand {
                program: replay_worker,
                arguments: vec!["--server".into(), model_bank.into_os_string()],
                environment: cuda_visible_device
                    .map(|_| ("CUDA_VISIBLE_DEVICES".into(), selected_device.into()))
                    .into_iter()
                    .collect(),
            },
            worker_scratch_directory: scratch_directory
                .to_str()
                .ok_or_else(|| pool_replay_failure("pool search scratch path is not UTF-8"))?
                .to_owned(),
            scratch_directory,
            batch_size,
        }),
    }
}

#[derive(Debug)]
pub struct ProductionV4PersistentPoolVerifier {
    searcher: ProductionV4PersistentPoolSearcher,
    /// Replay workers 1.. (worker 0 is `searcher`), each with its own lock.
    extra_searchers: Vec<ProductionV4PersistentPoolSearcher>,
    expected_network_id: [u8; 32],
    scratch_directory: PathBuf,
    worker_scratch_directory: String,
    startup_id: [u8; 8],
    /// Batch scratch-file names, unique across concurrent replay workers.
    next_batch_attempt: AtomicU64,
    /// Single-share and proof scratch-file names.
    next_attempt: AtomicU64,
    /// The proof worker. It is never held while a replay worker runs, and
    /// no replay worker lock is held while it is taken.
    state: Mutex<WorkerState>,
}

/// Reuse the authenticated production worker protocol for embedded solo mining.
/// No worker is spawned by this path-resolution step.
pub fn production_v4_solo_config(
    replay_worker: &Path,
    proof_worker: &Path,
    model_bank: &Path,
    fixed_directory: &Path,
    scratch_directory: &Path,
    wsl_distribution: Option<&str>,
) -> Result<ProductionV4PoolVerifierConfig, PoolError> {
    let proof_worker = canonical_worker_file(proof_worker, "ProductionV4 solo proof worker")?;
    let fixed_directory =
        crate::plain_package_path(fs::canonicalize(fixed_directory).map_err(replay_error)?);
    let search = production_v4_pool_searcher_config(
        replay_worker,
        model_bank,
        scratch_directory,
        32,
        wsl_distribution,
        None,
    )?;
    let bank = canonical_worker_file(model_bank, "ProductionV4 model bank")?;
    let proof = match wsl_distribution {
        None => ProductionV4PoolWorkerCommand {
            program: proof_worker,
            arguments: vec![
                "--server".into(),
                hex::encode(COMPILED_NETWORK_PROFILE.network_id).into(),
                bank.into_os_string(),
                fixed_directory.into_os_string(),
            ],
            environment: vec![],
        },
        Some(distribution) => {
            #[cfg(not(windows))]
            {
                let _ = distribution;
                return Err(pool_replay_failure("WSL solo mining requires Windows"));
            }
            #[cfg(windows)]
            {
                let wsl = &search.replay.program;
                ProductionV4PoolWorkerCommand {
                    program: wsl.clone(),
                    arguments: vec![
                        "-d".into(),
                        distribution.into(),
                        "--exec".into(),
                        "env".into(),
                        format!(
                            "CUDA_VISIBLE_DEVICES={}",
                            production_v4_worker_cuda_visible_device(None)?
                        )
                        .into(),
                        "LD_LIBRARY_PATH=/usr/local/cuda-12.8/lib64".into(),
                        wsl_path(wsl, distribution, &proof_worker)?.into(),
                        "--server".into(),
                        hex::encode(COMPILED_NETWORK_PROFILE.network_id).into(),
                        wsl_path(wsl, distribution, &bank)?.into(),
                        wsl_path(wsl, distribution, &fixed_directory)?.into(),
                    ],
                    environment: vec![],
                }
            }
        }
    };
    Ok(ProductionV4PoolVerifierConfig {
        replay: search.replay,
        extra_replays: Vec::new(),
        proof,
        scratch_directory: search.scratch_directory,
        worker_scratch_directory: search.worker_scratch_directory,
        work_check_pin: None,
    })
}

#[derive(Debug)]
pub struct ProductionV4PersistentPoolSearcher {
    expected_network_id: [u8; 32],
    scratch_directory: PathBuf,
    worker_scratch_directory: String,
    startup_id: [u8; 8],
    batch_size: u32,
    state: Mutex<SearchWorkerState>,
}

#[derive(Debug)]
struct WorkerState {
    proof: PersistentWorker,
}

#[derive(Debug)]
struct SearchWorkerState {
    replay: PersistentWorker,
    next_attempt: u64,
}

/// A long-lived worker process that is restarted when it dies or stops
/// answering: a failed command kills the process, and the next command starts
/// a fresh one, so one crash cannot silently stop the pool.
#[derive(Debug)]
struct PersistentWorker {
    command: ProductionV4PoolWorkerCommand,
    ready_marker: &'static str,
    label: &'static str,
    process: Option<WorkerProcess>,
    retry_after: Option<Instant>,
    restarts: u64,
    /// Checked before each start; see [`WorkerProcess::pinned`].
    pin: Option<ReplayWorkerPin>,
}

#[derive(Debug)]
struct WorkerProcess {
    /// The pinned file matched just before this process started.
    pinned: bool,
    child: Child,
    stdin: ChildStdin,
    /// Lines from the worker's stdout, read on their own thread so every wait
    /// has a deadline. The channel closes when stdout does.
    lines: Receiver<std::io::Result<String>>,
}

#[derive(Serialize)]
struct FrozenProductionV4Template<'a> {
    format_version: u16,
    challenge: cmfd_consensus::BlockChallenge,
    coinbase: &'a cmfd_consensus::Coinbase,
    transactions: &'a [cmfd_consensus::Transaction],
    nonce: u64,
}

struct AttemptFiles {
    scratch_directory: PathBuf,
    token: String,
}

/// A replayed share that meets the chain target, ready to be proved.
struct ChainShare<'a> {
    /// The replay worker that replayed it.
    worker: usize,
    files: &'a AttemptFiles,
    template: &'a BlockTemplate,
    nonce: u64,
    challenge_digest: [u8; 32],
    search_final: &'a [u8],
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
    evaluation_started: Instant,
    search_replay_seconds: f64,
}

impl ProductionV4PersistentPoolVerifier {
    pub fn start(config: ProductionV4PoolVerifierConfig) -> Result<Self, PoolError> {
        Self::start_for_network(COMPILED_NETWORK_PROFILE.network_id, config)
    }

    pub fn start_for_network(
        expected_network_id: [u8; 32],
        config: ProductionV4PoolVerifierConfig,
    ) -> Result<Self, PoolError> {
        validate_expected_network_id(expected_network_id)?;
        validate_scratch_paths(&config.scratch_directory, &config.worker_scratch_directory)?;
        fs::create_dir_all(&config.scratch_directory).map_err(replay_error)?;
        // Every replay worker loads the model on its own GPU; start them together.
        let start_searcher = |replay: ProductionV4PoolWorkerCommand| {
            ProductionV4PersistentPoolSearcher::start_pinned(
                expected_network_id,
                ProductionV4PoolSearcherConfig {
                    replay,
                    scratch_directory: config.scratch_directory.clone(),
                    worker_scratch_directory: config.worker_scratch_directory.clone(),
                    batch_size: 32,
                },
                config.work_check_pin.clone(),
            )
        };
        let (searcher, extra_searchers) = std::thread::scope(|scope| {
            let extra = config
                .extra_replays
                .clone()
                .into_iter()
                .map(|replay| scope.spawn(move || start_searcher(replay)))
                .collect::<Vec<_>>();
            let first = start_searcher(config.replay.clone());
            let extra = extra
                .into_iter()
                .map(|started| {
                    started.join().unwrap_or_else(|_| {
                        Err(pool_replay_failure("replay worker start panicked"))
                    })
                })
                .collect::<Result<Vec<_>, _>>();
            (first, extra)
        });
        let (searcher, extra_searchers) = (searcher?, extra_searchers?);
        let proof = PersistentWorker::start(
            &config.proof,
            "CMFD_V4_PROOF_READY",
            "ProductionV4 proof worker",
        )?;
        let mut startup_id = [0_u8; 8];
        getrandom::fill(&mut startup_id).map_err(replay_error)?;
        Ok(Self {
            searcher,
            extra_searchers,
            expected_network_id,
            scratch_directory: config.scratch_directory,
            worker_scratch_directory: config.worker_scratch_directory,
            startup_id,
            next_batch_attempt: AtomicU64::new(0),
            next_attempt: AtomicU64::new(0),
            state: Mutex::new(WorkerState { proof }),
        })
    }

    /// Checks one share on replay worker 0 with `RUN search`. Only that
    /// worker's lock is held while it replays. A chain-winning share goes on
    /// to [`prove_chain_share`](Self::prove_chain_share), which takes the
    /// proof worker only after releasing the replay worker, so a block work
    /// check holding worker 0 delays worker 0's shares but never a proof.
    fn evaluate_single(
        &self,
        template: &BlockTemplate,
        nonce: u64,
        share_target: [u8; 32],
    ) -> Result<ProductionV4PoolShareEvaluation, PoolError> {
        let evaluation_started = Instant::now();
        self.validate_share(template, share_target)?;
        let files = self.attempt_files();
        let coefficients_path = files.path("coefficients.bin");
        let template_path = files.path("template.json");
        let search_prefix = files.path("search");
        let search_final_path = files.path("search-final-activation.bin");

        let challenge_digest = forgematrix_v4_challenge_digest(
            &template.challenge,
            nonce,
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
        );
        write_new_file(
            &coefficients_path,
            &forgematrix_v4_replay_coefficients(challenge_digest),
        )?;
        let frozen = FrozenProductionV4Template {
            format_version: FROZEN_TEMPLATE_FORMAT_VERSION,
            challenge: template.challenge,
            coinbase: &template.coinbase,
            transactions: &template.transactions,
            nonce,
        };
        write_new_file(
            &template_path,
            &serde_json::to_vec(&frozen).map_err(replay_error)?,
        )?;

        let mut search_state = self
            .searcher
            .state
            .lock()
            .map_err(|_| pool_replay_failure("persistent search worker lock is poisoned"))?;
        let search_replay_started = Instant::now();
        search_state.replay.invoke(
            &[
                "RUN".to_owned(),
                "search".to_owned(),
                self.worker_path(&coefficients_path)?,
                self.worker_path(&search_prefix)?,
            ],
            "CMFD_V4_REPLAY_DONE",
        )?;
        let search_replay_seconds = search_replay_started.elapsed().as_secs_f64();
        let search_final = read_exact_file(
            &search_final_path,
            FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES,
        )?;
        let final_activation_digest =
            final_activation_digest_from_bytes(challenge_digest, &search_final)?;
        let work_digest = forgematrix_v4_work_digest(
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            challenge_digest,
            final_activation_digest,
        );
        if work_digest > template.challenge.target {
            return Ok(ProductionV4PoolShareEvaluation {
                work_digest,
                chain_proof: None,
                replay: None,
            });
        }
        self.prove_chain_share(
            search_state,
            ChainShare {
                worker: 0,
                files: &files,
                template,
                nonce,
                challenge_digest,
                search_final: &search_final,
                final_activation_digest,
                work_digest,
                evaluation_started,
                search_replay_seconds,
            },
        )
    }

    fn validate_share(
        &self,
        template: &BlockTemplate,
        share_target: [u8; 32],
    ) -> Result<(), PoolError> {
        if template.challenge.network_id != self.expected_network_id {
            return Err(pool_replay_failure(
                "pool replay received a template for another network",
            ));
        }
        if share_target < template.challenge.target {
            return Err(pool_replay_failure(
                "pool share target is harder than the chain target",
            ));
        }
        Ok(())
    }

    /// Scratch files for one single share or one proof.
    fn attempt_files(&self) -> AttemptFiles {
        let attempt_number = self.next_attempt.fetch_add(1, Ordering::Relaxed);
        AttemptFiles {
            scratch_directory: self.scratch_directory.clone(),
            token: format!(
                "cmfd-v4-pool-{}-{attempt_number:016x}",
                hex::encode(self.startup_id)
            ),
        }
    }

    fn searcher_for(&self, worker: usize) -> Option<&ProductionV4PersistentPoolSearcher> {
        match worker {
            0 => Some(&self.searcher),
            _ => self.extra_searchers.get(worker - 1),
        }
    }

    /// Checks several shares on replay worker `worker`, one `RUNBATCH` per 64
    /// shares. Only that worker's lock is held while it replays, so batches on
    /// different GPUs run at the same time. A share that fails validation, or
    /// a lane that meets the chain target, is handled exactly as the
    /// single-share path would.
    fn evaluate_batch_on_worker(
        &self,
        worker: usize,
        shares: &[ProductionV4PoolShareRequest<'_>],
    ) -> Vec<Result<ProductionV4PoolShareEvaluation, PoolError>> {
        let evaluation_started = Instant::now();
        let Some(searcher) = self.searcher_for(worker) else {
            return shares
                .iter()
                .map(|_| Err(pool_replay_failure("no such pool replay worker")))
                .collect();
        };
        let mut results = shares.iter().map(|_| None).collect::<Vec<_>>();
        let mut lanes = Vec::with_capacity(shares.len());
        for (index, share) in shares.iter().enumerate() {
            match self.validate_share(share.template, share.share_target) {
                Ok(()) => lanes.push((
                    index,
                    forgematrix_v4_challenge_digest(
                        &share.template.challenge,
                        share.nonce,
                        PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
                    ),
                )),
                Err(error) => results[index] = Some(Err(error)),
            }
        }
        for chunk in lanes.chunks(PRODUCTION_V4_POOL_SEARCH_MAX_BATCH_SIZE as usize) {
            let search_replay_started = Instant::now();
            let replayed = match searcher.state.lock() {
                Ok(mut search_state) => self.replay_search_batch(&mut search_state, chunk),
                Err(_) => Err(pool_replay_failure(
                    "persistent search worker lock is poisoned",
                )),
            };
            match replayed {
                Ok(final_activations) => {
                    let search_replay_seconds = search_replay_started.elapsed().as_secs_f64();
                    let lane_activations = final_activations
                        .chunks_exact(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES);
                    for (&(index, challenge_digest), search_final) in
                        chunk.iter().zip(lane_activations)
                    {
                        results[index] = Some(self.finish_batched_share(
                            worker,
                            &shares[index],
                            challenge_digest,
                            search_final,
                            evaluation_started,
                            search_replay_seconds,
                        ));
                    }
                }
                Err(error) => {
                    let message = match error {
                        PoolError::ProductionV4Replay(message) => message,
                        other => other.to_string(),
                    };
                    for &(index, _) in chunk {
                        results[index] = Some(Err(pool_replay_failure(message.clone())));
                    }
                }
            }
        }
        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| Err(pool_replay_failure("share was not evaluated")))
            })
            .collect()
    }

    /// Replays several shares in one `RUNBATCH` call and returns their final
    /// activations, one lane per share, in order.
    fn replay_search_batch(
        &self,
        search_state: &mut SearchWorkerState,
        lanes: &[(usize, [u8; 32])],
    ) -> Result<Vec<u8>, PoolError> {
        let attempt_number = self.next_batch_attempt.fetch_add(1, Ordering::Relaxed);
        let files = AttemptFiles {
            scratch_directory: self.scratch_directory.clone(),
            token: format!(
                "cmfd-v4-pool-batch-{}-{attempt_number:016x}",
                hex::encode(self.startup_id)
            ),
        };
        let coefficients_path = files.path("coefficients.bin");
        let search_prefix = files.path("search");
        let search_final_path = files.path("search-final-activation.bin");
        let coefficients = lanes
            .iter()
            .flat_map(|&(_, challenge_digest)| forgematrix_v4_replay_coefficients(challenge_digest))
            .collect::<Vec<_>>();
        write_new_file(&coefficients_path, &coefficients)?;
        search_state.replay.invoke(
            &[
                "RUNBATCH".to_owned(),
                lanes.len().to_string(),
                self.worker_path(&coefficients_path)?,
                self.worker_path(&search_prefix)?,
            ],
            "CMFD_V4_REPLAY_DONE",
        )?;
        let expected_bytes = FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES
            .checked_mul(lanes.len())
            .ok_or_else(|| pool_replay_failure("share-batch byte length overflow"))?;
        read_exact_file(&search_final_path, expected_bytes)
    }

    /// Derives one batched lane's work digest. A chain-winning lane then takes
    /// the lock of replay worker `worker` again and is written out and proved
    /// exactly like a single share.
    fn finish_batched_share(
        &self,
        worker: usize,
        share: &ProductionV4PoolShareRequest<'_>,
        challenge_digest: [u8; 32],
        search_final: &[u8],
        evaluation_started: Instant,
        search_replay_seconds: f64,
    ) -> Result<ProductionV4PoolShareEvaluation, PoolError> {
        let final_activation_digest =
            final_activation_digest_from_bytes(challenge_digest, search_final)?;
        let work_digest = forgematrix_v4_work_digest(
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            challenge_digest,
            final_activation_digest,
        );
        if work_digest > share.template.challenge.target {
            return Ok(ProductionV4PoolShareEvaluation {
                work_digest,
                chain_proof: None,
                replay: None,
            });
        }
        let searcher = self
            .searcher_for(worker)
            .ok_or_else(|| pool_replay_failure("no such pool replay worker"))?;
        let files = self.attempt_files();
        write_new_file(
            &files.path("coefficients.bin"),
            &forgematrix_v4_replay_coefficients(challenge_digest),
        )?;
        let frozen = FrozenProductionV4Template {
            format_version: FROZEN_TEMPLATE_FORMAT_VERSION,
            challenge: share.template.challenge,
            coinbase: &share.template.coinbase,
            transactions: &share.template.transactions,
            nonce: share.nonce,
        };
        write_new_file(
            &files.path("template.json"),
            &serde_json::to_vec(&frozen).map_err(replay_error)?,
        )?;
        let search_state = searcher
            .state
            .lock()
            .map_err(|_| pool_replay_failure("persistent search worker lock is poisoned"))?;
        self.prove_chain_share(
            search_state,
            ChainShare {
                worker,
                files: &files,
                template: share.template,
                nonce: share.nonce,
                challenge_digest,
                search_final,
                final_activation_digest,
                work_digest,
                evaluation_started,
                search_replay_seconds,
            },
        )
    }

    /// Repeats a chain-winning replay in full mode, proves it, and checks the
    /// proof against the replay. `share.files` must already hold the share's
    /// single-nonce coefficients and frozen template.
    ///
    /// While it still holds the replay worker, a worker started from the
    /// pinned file also replays the first known answer, so the node can
    /// trust the block's result from that same process without borrowing
    /// the worker again. The replay worker is then released before the proof
    /// worker is taken: the proof needs only the proof worker, so shares and
    /// block work checks keep using the replay worker while it runs, and no
    /// replay worker is started or restarted while the proof worker is held.
    fn prove_chain_share(
        &self,
        mut search_state: MutexGuard<'_, SearchWorkerState>,
        share: ChainShare<'_>,
    ) -> Result<ProductionV4PoolShareEvaluation, PoolError> {
        let ChainShare {
            worker,
            files,
            template,
            nonce,
            challenge_digest,
            search_final,
            final_activation_digest,
            work_digest,
            evaluation_started,
            search_replay_seconds,
        } = share;
        let coefficients_path = files.path("coefficients.bin");
        let template_path = files.path("template.json");
        let full_prefix = files.path("full");
        let full_final_path = files.path("full-final-activation.bin");
        let proof_path = files.path("transparent-proof.bin");
        let full_replay_started = Instant::now();
        search_state.replay.invoke(
            &[
                "RUN".to_owned(),
                "full".to_owned(),
                self.worker_path(&coefficients_path)?,
                self.worker_path(&full_prefix)?,
            ],
            "CMFD_V4_REPLAY_DONE",
        )?;
        let full_replay_seconds = full_replay_started.elapsed().as_secs_f64();
        let full_final = read_exact_file(
            &full_final_path,
            FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES,
        )?;
        if search_final != full_final.as_slice() {
            return Err(pool_replay_failure(
                "search replay and full replay final activations differ",
            ));
        }
        let known_answer = self.known_answer_locked(&mut search_state, worker);
        drop(search_state);
        let mut state = self
            .state
            .lock()
            .map_err(|_| pool_replay_failure("persistent worker lock is poisoned"))?;
        let proof_started = Instant::now();
        // A chain-winning share is rare and valuable: one proof-worker crash
        // (for example a GPU allocation failure) gets one restart and retry.
        state.proof.invoke_retrying_once(
            &[
                "RUN".to_owned(),
                self.worker_path(&template_path)?,
                self.worker_path(&full_prefix)?,
                self.worker_path(&full_final_path)?,
                self.worker_path(&proof_path)?,
            ],
            "CMFD_V4_PROOF_DONE",
        )?;
        let proof_seconds = proof_started.elapsed().as_secs_f64();
        let transparent_proof = read_bounded_file(&proof_path, PRODUCTION_V4_MAX_PROOF_BYTES)?;
        let decoded =
            decode_forgematrix_v4_transparent_proof(&transparent_proof).map_err(replay_error)?;
        if forgematrix_v4_final_activation_digest(challenge_digest, &decoded.final_activation)
            != final_activation_digest
        {
            return Err(pool_replay_failure(
                "proof final activation does not match the replay",
            ));
        }
        let proof = BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
            algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V4_PROOF_VERSION,
            nonce,
            proof_system_digest: forgematrix_v4_proof_system_digest(),
            model_manifest_digest: PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            challenge_digest,
            final_activation_digest,
            work_digest,
            transparent_proof,
        }));
        if std::env::var("CMFD_DROPOUT_REHEARSAL_TELEMETRY").as_deref() == Ok("1") {
            let proof_bytes = match &proof {
                BlockProof::V4Candidate(candidate) => candidate.transparent_proof.len(),
                _ => unreachable!("constructed a V4 proof above"),
            };
            eprintln!(
                "CMFD_DROPOUT_POOL_PROOF {}",
                serde_json::json!({
                    "network_id": hex::encode(self.expected_network_id),
                    "height": template.challenge.height,
                    "parent": hex::encode(template.challenge.previous_block),
                    "nonce": nonce,
                    "search_replay_seconds": search_replay_seconds,
                    "full_replay_seconds": full_replay_seconds,
                    "proof_seconds": proof_seconds,
                    "pool_evaluation_wall_seconds": evaluation_started.elapsed().as_secs_f64(),
                    "proof_bytes": proof_bytes,
                })
            );
        }
        Ok(ProductionV4PoolShareEvaluation {
            work_digest,
            chain_proof: Some(proof),
            replay: Some(
                PoolReplayResult::new(challenge_digest, final_activation_digest, worker)
                    .with_known_answer(known_answer),
            ),
        })
    }

    /// The final-activation digest replay worker `worker` produces for the
    /// first known answer, if its process was started from the pinned file
    /// and the replay succeeds. A failure is logged and leaves the block's
    /// result to be checked by the node as usual; it never costs the block.
    /// It runs before the proof, so it waits at most
    /// [`FOUND_BLOCK_KNOWN_ANSWER_TIMEOUT`]; a timeout also stops the worker,
    /// and the next share on it waits while it starts and loads the model.
    fn known_answer_locked(
        &self,
        search_state: &mut SearchWorkerState,
        worker: usize,
    ) -> Option<[u8; 32]> {
        if !search_state
            .replay
            .process
            .as_ref()
            .is_some_and(|process| process.pinned)
        {
            return None;
        }
        let answer = WORK_KNOWN_ANSWERS[0];
        let replayed = self
            .replay_one_locked(
                search_state,
                answer.challenge_digest,
                FOUND_BLOCK_KNOWN_ANSWER_TIMEOUT,
            )
            .and_then(|final_activation| {
                forgematrix_v4_final_activation_digest_from_le_bytes(
                    answer.challenge_digest,
                    &final_activation,
                )
                .map_err(replay_error)
            });
        match replayed {
            Ok(digest) => Some(digest),
            Err(error) => {
                tracing::warn!(
                    worker,
                    %error,
                    "pool replay worker could not replay its known answer for a found block"
                );
                None
            }
        }
    }

    /// Replays one challenge (`RUNBATCH 1`) on the locked replay worker and
    /// returns its final activation.
    fn replay_one_locked(
        &self,
        search_state: &mut SearchWorkerState,
        challenge_digest: [u8; 32],
        timeout: Duration,
    ) -> Result<Vec<u8>, PoolError> {
        let attempt_number = self.next_batch_attempt.fetch_add(1, Ordering::Relaxed);
        let files = AttemptFiles {
            scratch_directory: self.scratch_directory.clone(),
            token: format!(
                "cmfd-v4-work-check-{}-{attempt_number:016x}",
                hex::encode(self.startup_id)
            ),
        };
        let coefficients_path = files.path("coefficients.bin");
        write_new_file(
            &coefficients_path,
            &forgematrix_v4_replay_coefficients(challenge_digest),
        )?;
        search_state.replay.invoke_with_timeout(
            &[
                "RUNBATCH".to_owned(),
                "1".to_owned(),
                self.worker_path(&coefficients_path)?,
                self.worker_path(&files.path("search"))?,
            ],
            "CMFD_V4_REPLAY_DONE",
            timeout,
        )?;
        read_exact_file(
            &files.path("search-final-activation.bin"),
            FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES,
        )
    }

    /// Replays one challenge (`RUNBATCH 1`) on replay worker `worker` for a
    /// block work check, without waiting: a worker whose lock is held is
    /// reported busy, and one that is not running because it failed, or that
    /// was not started from the pinned file (see [`ReplayWorkerPin`]), is
    /// reported stopped. A worker is never started or restarted here; one
    /// that fails or exceeds `timeout` is stopped as usual and the next pool
    /// request restarts it.
    pub(crate) fn try_replay_for_work_check(
        &self,
        worker: usize,
        challenge_digest: [u8; 32],
        timeout: Duration,
    ) -> GpuReplay {
        let Some(searcher) = self.searcher_for(worker) else {
            return GpuReplay::Failed("no such pool replay worker".to_owned());
        };
        let mut search_state = match searcher.state.try_lock() {
            Ok(search_state) => search_state,
            Err(TryLockError::WouldBlock) => return GpuReplay::Busy,
            Err(TryLockError::Poisoned(_)) => {
                return GpuReplay::Failed("persistent search worker lock is poisoned".to_owned());
            }
        };
        match &search_state.replay.process {
            None => {
                return GpuReplay::Stopped(format!("pool replay worker {worker} is not running"));
            }
            Some(process) if !process.pinned => {
                return GpuReplay::Stopped(format!(
                    "pool replay worker {worker} was not started from the pinned replay worker file"
                ));
            }
            Some(_) => {}
        }
        match self.replay_one_locked(&mut search_state, challenge_digest, timeout) {
            Ok(final_activation) => GpuReplay::Done(final_activation),
            Err(error) => GpuReplay::Failed(error.to_string()),
        }
    }

    /// Solo mining uses the same persistent replay worker and CPU-checked
    /// batched search as pool mining, then proves only a chain-winning nonce.
    pub fn search(
        &self,
        job: &PoolJob,
        start_nonce: u64,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<PoolWorkSearchResult, PoolError> {
        self.searcher.search(job, start_nonce, stop)
    }

    fn worker_path(&self, local_path: &Path) -> Result<String, PoolError> {
        let file_name = local_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| pool_replay_failure("scratch file name is not UTF-8"))?;
        Ok(format!(
            "{}/{file_name}",
            self.worker_scratch_directory.trim_end_matches(['/', '\\'])
        ))
    }
}

impl ProductionV4PersistentPoolSearcher {
    pub fn start(config: ProductionV4PoolSearcherConfig) -> Result<Self, PoolError> {
        Self::start_for_network(COMPILED_NETWORK_PROFILE.network_id, config)
    }

    pub fn start_for_network(
        expected_network_id: [u8; 32],
        config: ProductionV4PoolSearcherConfig,
    ) -> Result<Self, PoolError> {
        Self::start_pinned(expected_network_id, config, None)
    }

    fn start_pinned(
        expected_network_id: [u8; 32],
        config: ProductionV4PoolSearcherConfig,
        pin: Option<ReplayWorkerPin>,
    ) -> Result<Self, PoolError> {
        validate_expected_network_id(expected_network_id)?;
        validate_scratch_paths(&config.scratch_directory, &config.worker_scratch_directory)?;
        if !(1..=PRODUCTION_V4_POOL_SEARCH_MAX_BATCH_SIZE).contains(&config.batch_size) {
            return Err(pool_replay_failure(format!(
                "ProductionV4 pool search batch size must be between 1 and {PRODUCTION_V4_POOL_SEARCH_MAX_BATCH_SIZE}"
            )));
        }
        fs::create_dir_all(&config.scratch_directory).map_err(replay_error)?;
        let replay = PersistentWorker::start_pinned(
            &config.replay,
            "CMFD_V4_REPLAY_READY",
            "ProductionV4 pool search worker",
            pin,
        )?;
        let mut startup_id = [0_u8; 8];
        getrandom::fill(&mut startup_id).map_err(replay_error)?;
        Ok(Self {
            expected_network_id,
            scratch_directory: config.scratch_directory,
            worker_scratch_directory: config.worker_scratch_directory,
            startup_id,
            batch_size: config.batch_size,
            state: Mutex::new(SearchWorkerState {
                replay,
                next_attempt: 0,
            }),
        })
    }

    pub fn search(
        &self,
        job: &PoolJob,
        start_nonce: u64,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<PoolWorkSearchResult, PoolError> {
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(PoolWorkSearchResult::Cancelled {
                attempts_completed: 0,
                next_nonce: start_nonce,
            });
        }
        validate_search_job(self.expected_network_id, job)?;
        let batch_size = bounded_batch_size(start_nonce, self.batch_size);
        let mut state = self
            .state
            .lock()
            .map_err(|_| pool_replay_failure("persistent search worker lock is poisoned"))?;
        let attempt_number = state.next_attempt;
        state.next_attempt = state.next_attempt.wrapping_add(1);
        let token = format!(
            "cmfd-v4-pool-search-{}-{attempt_number:016x}",
            hex::encode(self.startup_id)
        );
        let files = AttemptFiles {
            scratch_directory: self.scratch_directory.clone(),
            token,
        };
        let coefficients_path = files.path("coefficients.bin");
        let search_prefix = files.path("search");
        let search_final_path = files.path("search-final-activation.bin");
        let coefficients_per_nonce = (PRODUCTION_V2_LAYERS as usize + 1) * 20;
        let mut coefficients = Vec::with_capacity(coefficients_per_nonce * batch_size as usize);
        for lane in 0..batch_size {
            let nonce = start_nonce.wrapping_add(u64::from(lane));
            let challenge_digest = forgematrix_v4_challenge_digest(
                &job.challenge,
                nonce,
                PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            );
            coefficients.extend_from_slice(&forgematrix_v4_replay_coefficients(challenge_digest));
        }
        write_new_file(&coefficients_path, &coefficients)?;
        state.replay.invoke(
            &[
                "RUNBATCH".to_owned(),
                batch_size.to_string(),
                self.worker_path(&coefficients_path)?,
                self.worker_path(&search_prefix)?,
            ],
            "CMFD_V4_REPLAY_DONE",
        )?;
        let expected_bytes = FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES
            .checked_mul(batch_size as usize)
            .ok_or_else(|| pool_replay_failure("search-batch byte length overflow"))?;
        let final_activations = read_exact_file(&search_final_path, expected_bytes)?;
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(PoolWorkSearchResult::Cancelled {
                attempts_completed: u64::from(batch_size),
                next_nonce: start_nonce.wrapping_add(u64::from(batch_size)),
            });
        }
        inspect_search_batch(
            self.expected_network_id,
            job,
            start_nonce,
            &final_activations,
        )
    }

    fn worker_path(&self, local_path: &Path) -> Result<String, PoolError> {
        let file_name = local_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| pool_replay_failure("scratch file name is not UTF-8"))?;
        Ok(format!(
            "{}/{file_name}",
            self.worker_scratch_directory.trim_end_matches(['/', '\\'])
        ))
    }
}

impl ProductionV4PoolShareVerifier for ProductionV4PersistentPoolVerifier {
    fn evaluate(
        &self,
        template: &BlockTemplate,
        nonce: u64,
        share_target: [u8; 32],
    ) -> Result<ProductionV4PoolShareEvaluation, PoolError> {
        self.evaluate_single(template, nonce, share_target)
    }

    fn evaluate_batch(
        &self,
        shares: &[ProductionV4PoolShareRequest<'_>],
    ) -> Vec<Result<ProductionV4PoolShareEvaluation, PoolError>> {
        self.evaluate_batch_on(0, shares)
    }

    fn replay_workers(&self) -> usize {
        1 + self.extra_searchers.len()
    }

    fn evaluate_batch_on(
        &self,
        worker: usize,
        shares: &[ProductionV4PoolShareRequest<'_>],
    ) -> Vec<Result<ProductionV4PoolShareEvaluation, PoolError>> {
        // A lone share on the first worker takes the original single-share replay.
        if worker == 0 && shares.len() <= 1 {
            return shares
                .iter()
                .map(|share| self.evaluate_single(share.template, share.nonce, share.share_target))
                .collect();
        }
        self.evaluate_batch_on_worker(worker, shares)
    }
}

impl PersistentWorker {
    /// Starts the worker now, so a bad command or model fails at startup.
    fn start(
        command: &ProductionV4PoolWorkerCommand,
        ready_marker: &'static str,
        label: &'static str,
    ) -> Result<Self, PoolError> {
        Self::start_pinned(command, ready_marker, label, None)
    }

    fn start_pinned(
        command: &ProductionV4PoolWorkerCommand,
        ready_marker: &'static str,
        label: &'static str,
        pin: Option<ReplayWorkerPin>,
    ) -> Result<Self, PoolError> {
        if !command.program.is_absolute() || !command.program.is_file() {
            return Err(pool_replay_failure(format!(
                "{label} program must be an existing absolute file: {}",
                command.program.display()
            )));
        }
        let mut worker = Self {
            command: command.clone(),
            ready_marker,
            label,
            process: None,
            retry_after: None,
            restarts: 0,
            pin,
        };
        worker.process = Some(worker.spawn_process()?);
        Ok(worker)
    }

    /// Starts a process, hashing the pinned file just before.
    fn spawn_process(&self) -> Result<WorkerProcess, PoolError> {
        let pinned = self.pin.as_ref().is_some_and(ReplayWorkerPin::matches);
        if self.pin.is_some() && !pinned {
            tracing::warn!(
                worker = self.label,
                "the replay worker file does not match its pin; block work checks will not use this worker"
            );
        }
        let mut process = WorkerProcess::spawn(
            &self.command,
            self.ready_marker,
            self.label,
            WORKER_READY_TIMEOUT,
        )?;
        process.pinned = pinned;
        Ok(process)
    }

    fn invoke(&mut self, fields: &[String], done_marker: &str) -> Result<(), PoolError> {
        self.invoke_with_timeout(fields, done_marker, WORKER_COMMAND_TIMEOUT)
    }

    /// Runs a command and, if the worker fails, restarts it and runs the same
    /// command once more. For rare, valuable requests such as the proof of a
    /// chain-winning share, where one worker crash must not cost the block.
    fn invoke_retrying_once(
        &mut self,
        fields: &[String],
        done_marker: &str,
    ) -> Result<(), PoolError> {
        match self.invoke(fields, done_marker) {
            Ok(()) => Ok(()),
            Err(first) => {
                tracing::warn!(
                    worker = self.label,
                    error = %first,
                    "pool worker failed on a request that is retried once after a restart"
                );
                self.invoke(fields, done_marker)
            }
        }
    }

    fn invoke_with_timeout(
        &mut self,
        fields: &[String],
        done_marker: &str,
        timeout: Duration,
    ) -> Result<(), PoolError> {
        if fields.is_empty()
            || fields.iter().any(|field| {
                field.is_empty()
                    || field
                        .bytes()
                        .any(|byte| matches!(byte, b'\t' | b'\r' | b'\n'))
            })
        {
            return Err(pool_replay_failure(format!(
                "{} command contains an invalid field",
                self.label
            )));
        }
        let label = self.label;
        let process = self.running_process()?;
        let result = process.invoke(fields, done_marker, label, timeout);
        if let Err(error) = &result {
            // Never reuse a worker whose last command failed: its stream
            // position and GPU state are unknown. The next command restarts it.
            self.process = None;
            tracing::warn!(
                worker = self.label,
                %error,
                "pool worker failed; it will be restarted for the next request"
            );
        }
        result
    }

    fn running_process(&mut self) -> Result<&mut WorkerProcess, PoolError> {
        if self.process.is_none() {
            if matches!(self.retry_after, Some(retry_after) if Instant::now() < retry_after) {
                return Err(pool_replay_failure(format!(
                    "{} is restarting after a failure",
                    self.label
                )));
            }
            match self.spawn_process() {
                Ok(process) => {
                    self.restarts = self.restarts.saturating_add(1);
                    self.retry_after = None;
                    tracing::info!(
                        worker = self.label,
                        restarts = self.restarts,
                        "pool worker restarted"
                    );
                    self.process = Some(process);
                }
                Err(error) => {
                    self.retry_after = Some(Instant::now() + WORKER_RESTART_BACKOFF);
                    return Err(error);
                }
            }
        }
        Ok(self
            .process
            .as_mut()
            .expect("worker process was just started"))
    }
}

impl WorkerProcess {
    fn spawn(
        command: &ProductionV4PoolWorkerCommand,
        ready_marker: &str,
        label: &'static str,
        ready_timeout: Duration,
    ) -> Result<Self, PoolError> {
        let mut child = Command::new(&command.program)
            .args(&command.arguments)
            .envs(command.environment.iter().cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(replay_error)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| pool_replay_failure(format!("{label} stdin is unavailable")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| pool_replay_failure(format!("{label} stdout is unavailable")))?;
        let (sender, lines) = mpsc::sync_channel(256);
        std::thread::Builder::new()
            .name("cmfd-pool-worker-stdout".to_owned())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let mut line = String::new();
                    // A line longer than the output limit is passed on truncated
                    // and then rejected by the byte limit below.
                    let read = (&mut reader)
                        .take(WORKER_OUTPUT_MAX_BYTES as u64 + 1)
                        .read_line(&mut line);
                    match read {
                        Ok(0) => break,
                        Ok(_) => {
                            if sender.send(Ok(line)).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = sender.send(Err(error));
                            break;
                        }
                    }
                }
            })
            .map_err(replay_error)?;
        let mut process = Self {
            pinned: false,
            child,
            stdin,
            lines,
        };
        process.read_until(ready_marker, label, ready_timeout)?;
        Ok(process)
    }

    fn invoke(
        &mut self,
        fields: &[String],
        done_marker: &str,
        label: &'static str,
        timeout: Duration,
    ) -> Result<(), PoolError> {
        self.stdin
            .write_all(fields.join("\t").as_bytes())
            .and_then(|()| self.stdin.write_all(b"\n"))
            .and_then(|()| self.stdin.flush())
            .map_err(replay_error)?;
        self.read_until(done_marker, label, timeout)
    }

    fn read_until(
        &mut self,
        marker: &str,
        label: &'static str,
        timeout: Duration,
    ) -> Result<(), PoolError> {
        let deadline = Instant::now() + timeout;
        let mut total_bytes = 0_usize;
        for _ in 0..WORKER_OUTPUT_MAX_LINES {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = match self.lines.recv_timeout(remaining) {
                Ok(line) => line.map_err(replay_error)?,
                Err(RecvTimeoutError::Timeout) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Err(pool_replay_failure(format!(
                        "{label} did not emit {marker} within {} s and was stopped",
                        timeout.as_secs()
                    )));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self.child.try_wait().map_err(replay_error)?;
                    return Err(pool_replay_failure(format!(
                        "{label} closed stdout before {marker}; status={status:?}"
                    )));
                }
            };
            total_bytes = total_bytes
                .checked_add(line.len())
                .ok_or_else(|| pool_replay_failure("worker output byte count overflow"))?;
            if total_bytes > WORKER_OUTPUT_MAX_BYTES {
                return Err(pool_replay_failure(format!(
                    "{label} exceeded its output limit"
                )));
            }
            if line.trim_end_matches(['\r', '\n']) == marker {
                return Ok(());
            }
        }
        Err(pool_replay_failure(format!(
            "{label} did not emit {marker} within its line limit"
        )))
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"QUIT\n");
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl AttemptFiles {
    fn path(&self, suffix: &str) -> PathBuf {
        self.scratch_directory
            .join(format!("{}-{suffix}", self.token))
    }
}

impl Drop for AttemptFiles {
    fn drop(&mut self) {
        let Ok(entries) = fs::read_dir(&self.scratch_directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let belongs_to_attempt = path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.starts_with(&self.token));
            if belongs_to_attempt && path.is_file() {
                let _ = fs::remove_file(path);
            }
        }
    }
}

fn canonical_worker_file(path: &Path, label: &str) -> Result<PathBuf, PoolError> {
    if !path.is_absolute() || !path.is_file() {
        return Err(pool_replay_failure(format!(
            "{label} must be an existing absolute file: {}",
            path.display()
        )));
    }
    fs::canonicalize(path)
        .map(crate::plain_package_path)
        .map_err(replay_error)
}

fn validate_wsl_distribution(distribution: &str) -> Result<(), PoolError> {
    if distribution.is_empty()
        || distribution.len() > 128
        || !distribution
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(pool_replay_failure(
            "ProductionV4 WSL distribution name is invalid",
        ));
    }
    Ok(())
}

/// CUDA enumerates a one-device visibility mask as ordinal zero. Pool miners
/// pass an explicit UUID. With no override, preserve the historical WSL
/// default of GPU zero and let native solo workers inherit their own mask.
pub fn production_v4_worker_cuda_visible_device(
    explicit: Option<&str>,
) -> Result<String, PoolError> {
    let selected = explicit.unwrap_or("0");
    let numeric = !selected.is_empty()
        && selected.bytes().all(|byte| byte.is_ascii_digit())
        && selected.parse::<i32>().is_ok();
    let uuid = selected.len() == 40
        && selected.starts_with("GPU-")
        && selected[4..].bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if !numeric && !uuid {
        return Err(pool_replay_failure(
            "CUDA_VISIBLE_DEVICES must select exactly one numeric CUDA device or GPU UUID",
        ));
    }
    Ok(selected.to_owned())
}

#[cfg(windows)]
fn wsl_path(wsl: &Path, distribution: &str, path: &Path) -> Result<String, PoolError> {
    let output = std::process::Command::new(wsl)
        .args(["-d", distribution, "--exec", "wslpath", "-a", "-u"])
        .arg(path)
        .output()
        .map_err(replay_error)?;
    if !output.status.success() {
        return Err(pool_replay_failure(format!(
            "failed to convert {} for {distribution}",
            path.display()
        )));
    }
    let converted = String::from_utf8(output.stdout).map_err(replay_error)?;
    let converted = converted.trim();
    if converted.is_empty() || converted.contains(['\r', '\n', '\t']) {
        return Err(pool_replay_failure(format!(
            "WSL returned an invalid path for {}",
            path.display()
        )));
    }
    Ok(converted.to_owned())
}

fn validate_scratch_paths(local: &Path, worker: &str) -> Result<(), PoolError> {
    if !local.is_absolute() {
        return Err(pool_replay_failure(
            "ProductionV4 pool scratch directory must be absolute",
        ));
    }
    if worker.is_empty()
        || worker
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\r' | b'\n'))
    {
        return Err(pool_replay_failure(
            "ProductionV4 worker scratch directory is invalid",
        ));
    }
    Ok(())
}

fn validate_expected_network_id(expected_network_id: [u8; 32]) -> Result<(), PoolError> {
    if expected_network_id == [0; 32] {
        return Err(pool_replay_failure(
            "ProductionV4 pool expected network ID must be nonzero",
        ));
    }
    Ok(())
}

fn validate_search_job(expected_network_id: [u8; 32], job: &PoolJob) -> Result<(), PoolError> {
    validate_expected_network_id(expected_network_id)?;
    if job.challenge.network_id != expected_network_id {
        return Err(pool_replay_failure(
            "pool search received a job for another network",
        ));
    }
    if job.share_target < job.challenge.target {
        return Err(pool_replay_failure(
            "pool share target is harder than the chain target",
        ));
    }
    Ok(())
}

fn bounded_batch_size(start_nonce: u64, requested: u32) -> u32 {
    let remaining_after_first = u64::MAX - start_nonce;
    if remaining_after_first < u64::from(requested - 1) {
        (remaining_after_first + 1) as u32
    } else {
        requested
    }
}

fn inspect_search_batch(
    expected_network_id: [u8; 32],
    job: &PoolJob,
    start_nonce: u64,
    final_activations: &[u8],
) -> Result<PoolWorkSearchResult, PoolError> {
    validate_search_job(expected_network_id, job)?;
    let mut chunks = final_activations.chunks_exact(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES);
    if !chunks.remainder().is_empty()
        || chunks.len() == 0
        || chunks.len() > PRODUCTION_V4_POOL_SEARCH_MAX_BATCH_SIZE as usize
    {
        return Err(pool_replay_failure(
            "ProductionV4 search batch has the wrong byte length",
        ));
    }
    let attempts_completed = chunks.len() as u64;
    for (lane, final_activation) in chunks.by_ref().enumerate() {
        let nonce = start_nonce.wrapping_add(lane as u64);
        let challenge_digest = forgematrix_v4_challenge_digest(
            &job.challenge,
            nonce,
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
        );
        let final_activation_digest =
            final_activation_digest_from_bytes(challenge_digest, final_activation)?;
        let work_digest = forgematrix_v4_work_digest(
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            challenge_digest,
            final_activation_digest,
        );
        if work_digest <= job.share_target {
            return Ok(PoolWorkSearchResult::Found {
                nonce,
                work_digest,
                meets_chain_target: work_digest <= job.challenge.target,
                attempts_completed: lane as u64 + 1,
                next_nonce: nonce.wrapping_add(1),
            });
        }
    }
    Ok(PoolWorkSearchResult::Exhausted {
        attempts_completed,
        next_nonce: start_nonce.wrapping_add(attempts_completed),
    })
}

fn final_activation_digest_from_bytes(
    challenge_digest: [u8; 32],
    final_activation: &[u8],
) -> Result<[u8; 32], PoolError> {
    forgematrix_v4_final_activation_digest_from_le_bytes(challenge_digest, final_activation)
        .map_err(|error| pool_replay_failure(error.to_string()))
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), PoolError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(replay_error)?;
    file.write_all(bytes).map_err(replay_error)?;
    file.sync_all().map_err(replay_error)
}

fn read_exact_file(path: &Path, expected_bytes: usize) -> Result<Vec<u8>, PoolError> {
    let bytes = read_bounded_file(path, expected_bytes)?;
    if bytes.len() != expected_bytes {
        return Err(pool_replay_failure(format!(
            "{} has {} bytes; expected {expected_bytes}",
            path.display(),
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn read_bounded_file(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, PoolError> {
    let length =
        usize::try_from(fs::metadata(path).map_err(replay_error)?.len()).map_err(replay_error)?;
    if length == 0 || length > maximum_bytes {
        return Err(pool_replay_failure(format!(
            "{} has an invalid byte length {length}",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(length);
    File::open(path)
        .map_err(replay_error)?
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(replay_error)?;
    if bytes.len() != length {
        return Err(pool_replay_failure(format!(
            "{} changed while it was read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn replay_error(error: impl std::fmt::Display) -> PoolError {
    pool_replay_failure(error.to_string())
}

fn pool_replay_failure(message: impl Into<String>) -> PoolError {
    PoolError::ProductionV4Replay(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_protocol_paths_reject_command_injection() {
        let local = if cfg!(windows) {
            Path::new(r"C:\cmfd-pool-scratch")
        } else {
            Path::new("/cmfd-pool-scratch")
        };
        assert!(validate_scratch_paths(local, "/mnt/c/cmfd-pool-scratch").is_ok());
        assert!(validate_scratch_paths(local, "/tmp/bad\nRUN\tfull").is_err());
        assert!(validate_scratch_paths(Path::new("relative"), "/tmp/pool").is_err());
    }

    #[test]
    fn cuda_worker_selector_rejects_multi_gpu_and_shell_values() {
        let uuid = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        assert_eq!(production_v4_worker_cuda_visible_device(None).unwrap(), "0");
        assert_eq!(
            production_v4_worker_cuda_visible_device(Some(uuid)).unwrap(),
            uuid
        );
        assert_eq!(
            production_v4_worker_cuda_visible_device(Some("2")).unwrap(),
            "2"
        );
        for invalid in ["", "0,1", "GPU-short", "0;touch /tmp/pwn", "-1", " 1"] {
            assert!(production_v4_worker_cuda_visible_device(Some(invalid)).is_err());
        }
    }

    #[test]
    fn search_batch_inspection_reports_first_qualifying_nonce() {
        const ALTERNATE_NETWORK_ID: [u8; 32] = [0xa5; 32];
        let job = PoolJob {
            job_id: [9; 32],
            challenge: cmfd_consensus::BlockChallenge {
                network_id: ALTERNATE_NETWORK_ID,
                previous_block: [2; 32],
                transaction_root: [3; 32],
                height: 4,
                timestamp: 5,
                target: [0; 32],
            },
            share_target: [0xff; 32],
        };
        let activations = vec![0_u8; FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES * 2];
        let result = inspect_search_batch(ALTERNATE_NETWORK_ID, &job, 41, &activations).unwrap();
        assert!(matches!(
            result,
            PoolWorkSearchResult::Found {
                nonce: 41,
                attempts_completed: 1,
                next_nonce: 42,
                ..
            }
        ));
        assert!(inspect_search_batch([0x5a; 32], &job, 41, &activations).is_err());
        assert!(validate_search_job([0; 32], &job).is_err());
    }

    #[test]
    fn search_batch_size_stops_at_nonce_space_end() {
        assert_eq!(bounded_batch_size(0, 32), 32);
        assert_eq!(bounded_batch_size(u64::MAX - 2, 32), 3);
        assert_eq!(bounded_batch_size(u64::MAX, 32), 1);
    }

    /// A fake worker: says READY, answers DONE per command, exits on CRASH,
    /// stops answering on HANG, and refuses to start while `$1` exists.
    #[cfg(unix)]
    fn fake_worker(block_start: &Path) -> ProductionV4PoolWorkerCommand {
        let script = r#"[ -e "$1" ] && exit 4
echo READY
while read -r line; do
  case "$line" in
    CRASH) exit 3 ;;
    HANG) exec sleep 30 ;;
  esac
  echo DONE
done"#;
        ProductionV4PoolWorkerCommand {
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                "-c".into(),
                script.into(),
                "fake-worker".into(),
                block_start.as_os_str().to_owned(),
            ],
            environment: Vec::new(),
        }
    }

    #[cfg(unix)]
    fn worker_test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cmfd-pool-worker-{label}-{}", std::process::id()))
    }

    #[cfg(unix)]
    fn fields(value: &str) -> Vec<String> {
        vec![value.to_owned()]
    }

    #[cfg(unix)]
    #[test]
    fn crashed_worker_is_restarted_for_the_next_command() {
        let command = fake_worker(&worker_test_path("crash-unused"));
        let mut worker = PersistentWorker::start(&command, "READY", "test worker").unwrap();
        worker.invoke(&fields("job"), "DONE").unwrap();
        let error = worker.invoke(&fields("CRASH"), "DONE").unwrap_err();
        assert!(
            error.to_string().contains("closed stdout before DONE"),
            "{error}"
        );
        assert!(worker.process.is_none());
        worker.invoke(&fields("job"), "DONE").unwrap();
        assert_eq!(worker.restarts, 1);
    }

    #[cfg(unix)]
    #[test]
    fn request_is_retried_once_after_a_worker_crash() {
        let marker = worker_test_path("retry-once");
        let _ = std::fs::remove_file(&marker);
        let script = r#"echo READY
while read -r line; do
  [ "$line" = QUIT ] && exit 0
  if [ ! -e "$1" ]; then touch "$1"; exit 3; fi
  echo DONE
done"#;
        let command = ProductionV4PoolWorkerCommand {
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                "-c".into(),
                script.into(),
                "fake-retry".into(),
                marker.as_os_str().to_owned(),
            ],
            environment: Vec::new(),
        };
        let mut worker = PersistentWorker::start(&command, "READY", "test worker").unwrap();
        worker.invoke_retrying_once(&fields("job"), "DONE").unwrap();
        assert_eq!(worker.restarts, 1);
        assert!(worker.process.is_some());
        let _ = std::fs::remove_file(&marker);

        // A worker that keeps failing still fails the request after one retry.
        let command = fake_worker(&worker_test_path("retry-crash-unused"));
        let mut worker = PersistentWorker::start(&command, "READY", "test worker").unwrap();
        worker
            .invoke_retrying_once(&fields("CRASH"), "DONE")
            .unwrap_err();
        assert_eq!(worker.restarts, 1);
        assert!(worker.process.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn wedged_worker_is_stopped_at_the_deadline_and_restarted() {
        let command = fake_worker(&worker_test_path("hang-unused"));
        let mut worker = PersistentWorker::start(&command, "READY", "test worker").unwrap();
        let started = Instant::now();
        let error = worker
            .invoke_with_timeout(&fields("HANG"), "DONE", Duration::from_millis(300))
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(error.to_string().contains("was stopped"), "{error}");
        assert!(worker.process.is_none());
        worker.invoke(&fields("job"), "DONE").unwrap();
        assert_eq!(worker.restarts, 1);
    }

    #[cfg(unix)]
    #[test]
    fn failed_restart_backs_off_then_recovers() {
        let block_start = worker_test_path("backoff");
        let _ = std::fs::remove_file(&block_start);
        let command = fake_worker(&block_start);
        let mut worker = PersistentWorker::start(&command, "READY", "test worker").unwrap();
        std::fs::write(&block_start, b"").unwrap();
        worker.invoke(&fields("CRASH"), "DONE").unwrap_err();

        let error = worker.invoke(&fields("job"), "DONE").unwrap_err();
        assert!(
            error.to_string().contains("closed stdout before READY"),
            "{error}"
        );
        assert!(worker.retry_after.is_some());
        let error = worker.invoke(&fields("job"), "DONE").unwrap_err();
        assert!(error.to_string().contains("is restarting"), "{error}");
        assert_eq!(worker.restarts, 0);

        std::fs::remove_file(&block_start).unwrap();
        worker.retry_after = Some(Instant::now());
        worker.invoke(&fields("job"), "DONE").unwrap();
        assert_eq!(worker.restarts, 1);
        assert!(worker.retry_after.is_none());
    }

    #[cfg(unix)]
    const BATCH_TEST_NETWORK_ID: [u8; 32] = [0xa5; 32];

    /// A fake replay worker for `RUN search` and `RUNBATCH`. Lane `i` (from 1)
    /// of every answer is filled with the field value `i`, the coefficient file
    /// must hold exactly one coefficient set per lane, each command is logged
    /// to `$1`, `RUNBATCH` crashes while `$1.crash` exists, and `RUNBATCH`
    /// waits while `$1.hold` exists, after creating `$1.holding`.
    #[cfg(unix)]
    fn fake_replay_worker(log: &Path) -> ProductionV4PoolWorkerCommand {
        let script = r#"log="$1"; per="$2"
lane() {
  printf "\\$(printf '%03o' "$1")\\000\\000\\000" > "$2.lane"
  i=0
  while [ "$i" -lt 19 ]; do cat "$2.lane" "$2.lane" > "$2.lane2"; mv "$2.lane2" "$2.lane"; i=$((i+1)); done
  cat "$2.lane" >> "$2"; rm -f "$2.lane"
}
echo CMFD_V4_REPLAY_READY
while read -r command first second third; do
  case "$command" in
    QUIT) exit 0 ;;
    RUNBATCH) count="$first" ;;
    RUN) count=1 ;;
    *) exit 5 ;;
  esac
  if [ "$command" = RUNBATCH ] && [ -e "$log.hold" ]; then
    : > "$log.holding"
    while [ -e "$log.hold" ]; do sleep 0.05; done
  fi
  [ "$command" = RUNBATCH ] && [ -e "$log.crash" ] && exit 3
  [ "$(wc -c < "$second")" -eq $((count * per)) ] || exit 6
  out="$third-final-activation.bin"
  : > "$out"
  lane_index=1
  while [ "$lane_index" -le "$count" ]; do lane "$lane_index" "$out"; lane_index=$((lane_index+1)); done
  echo "$command $count" >> "$log"
  echo CMFD_V4_REPLAY_DONE
done"#;
        ProductionV4PoolWorkerCommand {
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                "-c".into(),
                script.into(),
                "fake-replay".into(),
                log.as_os_str().to_owned(),
                ((PRODUCTION_V2_LAYERS as usize + 1) * 20)
                    .to_string()
                    .into(),
            ],
            environment: Vec::new(),
        }
    }

    #[cfg(unix)]
    fn fake_proof_worker() -> ProductionV4PoolWorkerCommand {
        let script = r#"echo CMFD_V4_PROOF_READY
while read -r line; do [ "$line" = QUIT ] && exit 0; echo CMFD_V4_PROOF_DONE; done"#;
        ProductionV4PoolWorkerCommand {
            program: PathBuf::from("/bin/sh"),
            arguments: vec!["-c".into(), script.into(), "fake-proof".into()],
            environment: Vec::new(),
        }
    }

    #[cfg(unix)]
    fn batch_test_verifier(label: &str) -> (ProductionV4PersistentPoolVerifier, PathBuf, PathBuf) {
        let (verifier, scratch, mut logs) = batch_test_verifier_with_workers(label, 1);
        (verifier, scratch, logs.remove(0))
    }

    /// A verifier with `workers` fake replay workers, each logging to its own file.
    #[cfg(unix)]
    fn batch_test_verifier_with_workers(
        label: &str,
        workers: usize,
    ) -> (ProductionV4PersistentPoolVerifier, PathBuf, Vec<PathBuf>) {
        let scratch = worker_test_path(label);
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let logs = (0..workers)
            .map(|worker| scratch.join(format!("worker{worker}.log")))
            .collect::<Vec<_>>();
        let verifier = ProductionV4PersistentPoolVerifier::start_for_network(
            BATCH_TEST_NETWORK_ID,
            ProductionV4PoolVerifierConfig {
                replay: fake_replay_worker(&logs[0]),
                extra_replays: logs[1..]
                    .iter()
                    .map(|log| fake_replay_worker(log))
                    .collect(),
                proof: fake_proof_worker(),
                scratch_directory: scratch.clone(),
                worker_scratch_directory: scratch.to_str().unwrap().to_owned(),
                work_check_pin: Some(shell_pin()),
            },
        )
        .unwrap();
        (verifier, scratch, logs)
    }

    #[cfg(unix)]
    #[test]
    fn extra_replay_workers_check_batches_at_the_same_time() {
        let (verifier, scratch, logs) = batch_test_verifier_with_workers("batch-multi", 3);
        assert_eq!(verifier.replay_workers(), 3);
        let template = batch_test_template(BATCH_TEST_NETWORK_ID);
        let nonces = [40_u64, 41, 42, 43, 44, 45];
        let requests = nonces.map(|nonce| ProductionV4PoolShareRequest {
            template: &template,
            nonce,
            share_target: [0xff; 32],
        });
        // Three batches of two, one per worker, all at once.
        let results = std::thread::scope(|scope| {
            let handles = (0..3)
                .map(|worker| {
                    let chunk = &requests[2 * worker..2 * worker + 2];
                    let verifier = &verifier;
                    scope.spawn(move || verifier.evaluate_batch_on(worker, chunk))
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        for (worker, batch) in results.iter().enumerate() {
            for (lane, result) in batch.iter().enumerate() {
                let evaluation = result.as_ref().unwrap();
                assert_eq!(
                    evaluation.work_digest,
                    fake_lane_work_digest(&template, nonces[2 * worker + lane], lane as u32 + 1)
                );
            }
            assert_eq!(
                std::fs::read_to_string(&logs[worker]).unwrap(),
                "RUNBATCH 2\n",
                "worker {worker} ran exactly its own batch"
            );
        }
        // A worker that does not exist fails its shares without touching any worker.
        for result in verifier.evaluate_batch_on(3, &requests[..2]) {
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains("no such pool replay worker"),
                "{error}"
            );
        }
        // A lone share on an extra worker still uses that worker's batch path.
        let lone = verifier
            .evaluate_batch_on(2, &requests[..1])
            .pop()
            .unwrap()
            .unwrap();
        assert_eq!(lone.work_digest, fake_lane_work_digest(&template, 40, 1));
        assert_eq!(
            std::fs::read_to_string(&logs[2]).unwrap(),
            "RUNBATCH 2\nRUNBATCH 1\n"
        );
        drop(verifier);
        let _ = std::fs::remove_dir_all(scratch);
    }

    #[cfg(unix)]
    #[test]
    fn a_crashed_extra_replay_worker_fails_only_its_own_batch() {
        let (verifier, scratch, logs) = batch_test_verifier_with_workers("batch-multi-crash", 2);
        let template = batch_test_template(BATCH_TEST_NETWORK_ID);
        let requests = [50_u64, 51].map(|nonce| ProductionV4PoolShareRequest {
            template: &template,
            nonce,
            share_target: [0xff; 32],
        });
        let crash = PathBuf::from(format!("{}.crash", logs[1].display()));
        std::fs::write(&crash, b"").unwrap();
        for result in verifier.evaluate_batch_on(1, &requests) {
            let error = result.unwrap_err();
            assert!(error.to_string().contains("closed stdout"), "{error}");
        }
        // Worker 0 is unaffected, and worker 1 restarts for its next batch.
        for (lane, result) in verifier
            .evaluate_batch_on(0, &requests)
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                result.unwrap().work_digest,
                fake_lane_work_digest(&template, requests[lane].nonce, lane as u32 + 1)
            );
        }
        std::fs::remove_file(&crash).unwrap();
        for (lane, result) in verifier
            .evaluate_batch_on(1, &requests)
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                result.unwrap().work_digest,
                fake_lane_work_digest(&template, requests[lane].nonce, lane as u32 + 1)
            );
        }
        drop(verifier);
        let _ = std::fs::remove_dir_all(scratch);
    }

    #[cfg(unix)]
    #[test]
    fn work_check_replay_never_waits_for_or_restarts_a_worker() {
        let (verifier, scratch, logs) = batch_test_verifier_with_workers("work-check", 2);
        let timeout = Duration::from_secs(30);
        let GpuReplay::Done(final_activation) =
            verifier.try_replay_for_work_check(1, [7; 32], timeout)
        else {
            panic!("an idle worker replays");
        };
        assert_eq!(
            final_activation.len(),
            FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES
        );
        assert_eq!(
            std::fs::read_to_string(&logs[1]).unwrap(),
            "RUNBATCH 1
"
        );

        {
            let _held = verifier.searcher.state.lock().unwrap();
            assert_eq!(
                verifier.try_replay_for_work_check(0, [7; 32], timeout),
                GpuReplay::Busy
            );
        }

        let crash = PathBuf::from(format!("{}.crash", logs[1].display()));
        std::fs::write(&crash, b"").unwrap();
        assert!(matches!(
            verifier.try_replay_for_work_check(1, [7; 32], timeout),
            GpuReplay::Failed(_)
        ));
        std::fs::remove_file(&crash).unwrap();
        assert!(
            matches!(
                verifier.try_replay_for_work_check(1, [7; 32], timeout),
                GpuReplay::Stopped(_)
            ),
            "a stopped worker is reported, not restarted, by a work check"
        );
        assert!(matches!(
            verifier.try_replay_for_work_check(2, [7; 32], timeout),
            GpuReplay::Failed(_)
        ));
        let leftovers = std::fs::read_dir(&scratch)
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("cmfd-v4-work-check-"))
            })
            .count();
        assert_eq!(leftovers, 0);
        drop(verifier);
        let _ = std::fs::remove_dir_all(scratch);
    }

    /// Pins `/bin/sh`, the program every fake worker runs.
    #[cfg(unix)]
    fn shell_pin() -> ReplayWorkerPin {
        let shell = PathBuf::from("/bin/sh");
        let sha256 = file_sha256(&shell).unwrap();
        ReplayWorkerPin::new(shell, sha256)
    }

    #[test]
    fn only_the_release_replay_worker_is_pinned_for_work_checks() {
        let path = std::env::temp_dir().join(format!(
            "cmfd-pool-worker-release-pin-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"abc").unwrap();
        let sha256 = file_sha256(&path).unwrap();
        assert_eq!(
            hex::encode(sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(sha256, production_v4_release_replay_worker_sha256());
        assert_eq!(
            ReplayWorkerPin::release(path.clone()).unwrap().unwrap_err(),
            sha256
        );
        assert!(ReplayWorkerPin::new(path.clone(), sha256).matches());
        assert!(!ReplayWorkerPin::new(path.clone(), [0; 32]).matches());
        std::fs::remove_file(&path).unwrap();
        assert!(ReplayWorkerPin::release(path.clone()).is_err());
        assert!(
            !ReplayWorkerPin::new(path, sha256).matches(),
            "a file that is gone does not match"
        );
        assert_eq!(
            hex::encode(production_v4_release_replay_worker_sha256()),
            "33ce76f3832e7703d5aa8200ed51acfe3becfcfb2c2b063886aaf1db5ab1f9f0"
        );
    }

    #[cfg(unix)]
    #[test]
    fn work_checks_use_only_replay_workers_started_from_the_pinned_file() {
        let scratch = worker_test_path("work-check-pin");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let log = scratch.join("worker0.log");
        let worker_file = scratch.join("replay-worker");
        std::fs::write(&worker_file, b"release build").unwrap();
        let start = |work_check_pin: Option<ReplayWorkerPin>| {
            ProductionV4PersistentPoolVerifier::start_for_network(
                BATCH_TEST_NETWORK_ID,
                ProductionV4PoolVerifierConfig {
                    replay: fake_replay_worker(&log),
                    extra_replays: Vec::new(),
                    proof: fake_proof_worker(),
                    scratch_directory: scratch.clone(),
                    worker_scratch_directory: scratch.to_str().unwrap().to_owned(),
                    work_check_pin,
                },
            )
            .unwrap()
        };
        let template = batch_test_template(BATCH_TEST_NETWORK_ID);
        let share = [ProductionV4PoolShareRequest {
            template: &template,
            nonce: 9,
            share_target: [0xff; 32],
        }];
        let timeout = Duration::from_secs(30);
        let refused = |replay: GpuReplay| matches!(replay, GpuReplay::Stopped(reason) if reason.contains("pinned"));

        // Without a pin, or with a pin the file does not match, work checks
        // refuse the worker while shares still use it.
        for pin in [
            None,
            Some(ReplayWorkerPin::new(worker_file.clone(), [0; 32])),
        ] {
            let verifier = start(pin);
            assert!(refused(
                verifier.try_replay_for_work_check(0, [7; 32], timeout)
            ));
            assert!(verifier.evaluate_batch_on(0, &share)[0].is_ok());
        }

        let sha256 = file_sha256(&worker_file).unwrap();
        let verifier = start(Some(ReplayWorkerPin::new(worker_file.clone(), sha256)));
        assert!(matches!(
            verifier.try_replay_for_work_check(0, [7; 32], timeout),
            GpuReplay::Done(_)
        ));
        // The file changes under the running worker. That process was started
        // from the pinned file, so it still serves work checks.
        std::fs::write(&worker_file, b"another build").unwrap();
        assert!(matches!(
            verifier.try_replay_for_work_check(0, [7; 32], timeout),
            GpuReplay::Done(_)
        ));
        // Once it fails, a share restarts it from the changed file, and work
        // checks refuse it from then on.
        let crash = PathBuf::from(format!("{}.crash", log.display()));
        std::fs::write(&crash, b"").unwrap();
        assert!(matches!(
            verifier.try_replay_for_work_check(0, [7; 32], timeout),
            GpuReplay::Failed(_)
        ));
        std::fs::remove_file(&crash).unwrap();
        assert!(verifier.evaluate_batch_on(0, &share)[0].is_ok());
        assert!(refused(
            verifier.try_replay_for_work_check(0, [7; 32], timeout)
        ));
        drop(verifier);
        let _ = std::fs::remove_dir_all(scratch);
    }

    /// A proof worker that marks each request as started and answers it only
    /// once `go` exists. It writes no proof, so the share then fails.
    #[cfg(unix)]
    fn gated_proof_worker(started: &Path, go: &Path) -> ProductionV4PoolWorkerCommand {
        let script = r#"echo CMFD_V4_PROOF_READY
while read -r line; do
  [ "$line" = QUIT ] && exit 0
  : > "$1"
  while [ ! -e "$2" ]; do sleep 0.05; done
  echo CMFD_V4_PROOF_DONE
done"#;
        ProductionV4PoolWorkerCommand {
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                "-c".into(),
                script.into(),
                "gated-proof".into(),
                started.as_os_str().to_owned(),
                go.as_os_str().to_owned(),
            ],
            environment: Vec::new(),
        }
    }

    /// Runs its closure when dropped. Declared inside a `thread::scope`, it
    /// releases a fake worker that waits on a file when an assertion fails,
    /// so the scope's join ends instead of waiting forever.
    #[cfg(unix)]
    struct OnDrop<F: FnMut()>(F);

    #[cfg(unix)]
    impl<F: FnMut()> Drop for OnDrop<F> {
        fn drop(&mut self) {
            (self.0)();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_running_proof_leaves_its_replay_worker_free_for_work_checks() {
        let scratch = worker_test_path("proof-releases-replay");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let logs = [scratch.join("worker0.log"), scratch.join("worker1.log")];
        let started = scratch.join("proof-started");
        let go = scratch.join("proof-go");
        let verifier = ProductionV4PersistentPoolVerifier::start_for_network(
            BATCH_TEST_NETWORK_ID,
            ProductionV4PoolVerifierConfig {
                replay: fake_replay_worker(&logs[0]),
                extra_replays: vec![fake_replay_worker(&logs[1])],
                proof: gated_proof_worker(&started, &go),
                scratch_directory: scratch.clone(),
                worker_scratch_directory: scratch.to_str().unwrap().to_owned(),
                work_check_pin: Some(shell_pin()),
            },
        )
        .unwrap();
        // Every nonce meets this chain target, so each share is proved.
        let mut template = batch_test_template(BATCH_TEST_NETWORK_ID);
        template.challenge.target = [0xff; 32];
        let timeout = Duration::from_secs(30);
        // Worker 0 proves through the single-share path, worker 1 through a batch.
        for worker in [0_usize, 1] {
            let _ = std::fs::remove_file(&started);
            let _ = std::fs::remove_file(&go);
            std::thread::scope(|scope| {
                let _release = OnDrop(|| {
                    let _ = std::fs::write(&go, b"");
                });
                let share = scope.spawn(|| {
                    verifier.evaluate_batch_on(
                        worker,
                        &[ProductionV4PoolShareRequest {
                            template: &template,
                            nonce: 70 + worker as u64,
                            share_target: [0xff; 32],
                        }],
                    )
                });
                let deadline = Instant::now() + timeout;
                while !started.exists() {
                    assert!(Instant::now() < deadline, "the proof never started");
                    std::thread::sleep(Duration::from_millis(20));
                }
                // The proof is running; the share's replay worker is not held.
                let replay = verifier.try_replay_for_work_check(worker, [7; 32], timeout);
                std::fs::write(&go, b"").unwrap();
                assert!(
                    matches!(replay, GpuReplay::Done(_)),
                    "worker {worker} answered {replay:?} while a proof ran"
                );
                let results = share.join().unwrap();
                assert!(results[0].is_err(), "the gated worker writes no proof");
            });
            // Search, full replay, the known answer before the proof, then
            // the work check during it.
            assert_eq!(
                std::fs::read_to_string(&logs[worker]).unwrap(),
                if worker == 0 {
                    "RUN 1\nRUN 1\nRUNBATCH 1\nRUNBATCH 1\n"
                } else {
                    "RUNBATCH 1\nRUN 1\nRUNBATCH 1\nRUNBATCH 1\n"
                }
            );
        }
        drop(verifier);
        let _ = std::fs::remove_dir_all(scratch);
    }

    /// A block work check that holds replay worker 0 delays only worker 0's
    /// own shares: a chain-winning share on worker 1 is still replayed and
    /// proved meanwhile, and worker 0's share goes on once the check is done.
    #[cfg(unix)]
    #[test]
    fn a_held_work_check_delays_only_its_own_workers_shares() {
        let (verifier, scratch, logs) = batch_test_verifier_with_workers("held-work-check", 2);
        let verifier = &verifier;
        // Every nonce meets this chain target, so each share is proved.
        let mut template = batch_test_template(BATCH_TEST_NETWORK_ID);
        template.challenge.target = [0xff; 32];
        let template = &template;
        let share = |nonce| ProductionV4PoolShareRequest {
            template,
            nonce,
            share_target: [0xff; 32],
        };
        let hold = PathBuf::from(format!("{}.hold", logs[0].display()));
        let holding = PathBuf::from(format!("{}.holding", logs[0].display()));
        std::fs::write(&hold, b"").unwrap();
        let timeout = Duration::from_secs(30);
        std::thread::scope(|scope| {
            let _release = OnDrop(|| {
                let _ = std::fs::remove_file(&hold);
            });
            let check = scope.spawn(|| verifier.try_replay_for_work_check(0, [7; 32], timeout));
            let deadline = Instant::now() + timeout;
            while !holding.exists() {
                assert!(Instant::now() < deadline, "the work check never started");
                std::thread::sleep(Duration::from_millis(20));
            }
            let single = scope.spawn(move || verifier.evaluate_batch_on(0, &[share(80)]));
            std::thread::sleep(Duration::from_millis(300));
            assert!(
                !single.is_finished(),
                "worker 0's share waits for the check"
            );
            let (sender, receiver) = mpsc::channel();
            scope.spawn(move || {
                let _ = sender.send(verifier.evaluate_batch_on(1, &[share(81)]));
            });
            let other = receiver.recv_timeout(Duration::from_secs(10));
            std::fs::remove_file(&hold).unwrap();
            let other = other.expect("a share on worker 1 waited for a work check on worker 0");
            assert!(other[0].is_err(), "the fake proof worker writes no proof");
            assert!(matches!(check.join().unwrap(), GpuReplay::Done(_)));
            assert!(single.join().unwrap()[0].is_err());
        });
        // Worker 1: batch, full replay, known answer, all before worker 0's
        // check ended; worker 0: the check, then its share's replays.
        assert_eq!(
            std::fs::read_to_string(&logs[1]).unwrap(),
            "RUNBATCH 1\nRUN 1\nRUNBATCH 1\n"
        );
        assert_eq!(
            std::fs::read_to_string(&logs[0]).unwrap(),
            "RUNBATCH 1\nRUN 1\nRUN 1\nRUNBATCH 1\n"
        );
        let _ = std::fs::remove_dir_all(scratch);
    }

    /// A chain-winning share's replay worker replays the first known answer
    /// before it is released, but only a process started from the pinned
    /// file does.
    #[cfg(unix)]
    #[test]
    fn a_found_blocks_replay_worker_replays_a_known_answer_only_when_pinned() {
        let scratch = worker_test_path("found-block-known-answer");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let log = scratch.join("worker0.log");
        let start = |work_check_pin: Option<ReplayWorkerPin>| {
            ProductionV4PersistentPoolVerifier::start_for_network(
                BATCH_TEST_NETWORK_ID,
                ProductionV4PoolVerifierConfig {
                    replay: fake_replay_worker(&log),
                    extra_replays: Vec::new(),
                    proof: fake_proof_worker(),
                    scratch_directory: scratch.clone(),
                    worker_scratch_directory: scratch.to_str().unwrap().to_owned(),
                    work_check_pin,
                },
            )
            .unwrap()
        };
        // The fake worker fills its one lane with the field value 1.
        let lane = 1_u32
            .to_le_bytes()
            .repeat(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES / 4);
        let expected = forgematrix_v4_final_activation_digest_from_le_bytes(
            WORK_KNOWN_ANSWERS[0].challenge_digest,
            &lane,
        )
        .unwrap();
        let verifier = start(Some(shell_pin()));
        {
            let mut search_state = verifier.searcher.state.lock().unwrap();
            assert_eq!(
                verifier.known_answer_locked(&mut search_state, 0),
                Some(expected)
            );
        }
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "RUNBATCH 1\n");
        drop(verifier);
        let verifier = start(None);
        {
            let mut search_state = verifier.searcher.state.lock().unwrap();
            assert_eq!(verifier.known_answer_locked(&mut search_state, 0), None);
        }
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "RUNBATCH 1\n",
            "an unpinned worker runs nothing"
        );
        drop(verifier);
        let _ = std::fs::remove_dir_all(scratch);
    }

    /// A template whose chain target nothing meets, so no lane needs a proof.
    #[cfg(unix)]
    fn batch_test_template(network_id: [u8; 32]) -> BlockTemplate {
        BlockTemplate {
            challenge: cmfd_consensus::BlockChallenge {
                network_id,
                previous_block: [2; 32],
                transaction_root: [3; 32],
                height: 4,
                timestamp: 5,
                target: [0; 32],
            },
            coinbase: cmfd_consensus::Coinbase {
                height: 4,
                outputs: Vec::new(),
            },
            transactions: Vec::new(),
            total_fees_burned: 0,
        }
    }

    /// The work digest of a lane the fake worker filled with `value`.
    #[cfg(unix)]
    fn fake_lane_work_digest(template: &BlockTemplate, nonce: u64, value: u32) -> [u8; 32] {
        let challenge_digest = forgematrix_v4_challenge_digest(
            &template.challenge,
            nonce,
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
        );
        let activation = value
            .to_le_bytes()
            .repeat(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES / size_of::<u32>());
        forgematrix_v4_work_digest(
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            challenge_digest,
            final_activation_digest_from_bytes(challenge_digest, &activation).unwrap(),
        )
    }

    #[cfg(unix)]
    #[test]
    fn batched_shares_are_replayed_together_and_mapped_to_their_lanes() {
        let (verifier, scratch, log) = batch_test_verifier("batch-lanes");
        let template = batch_test_template(BATCH_TEST_NETWORK_ID);
        let requests = [10_u64, 11, 12].map(|nonce| ProductionV4PoolShareRequest {
            template: &template,
            nonce,
            share_target: [0xff; 32],
        });
        let results = verifier.evaluate_batch(&requests);
        for (lane, (request, result)) in requests.iter().zip(results).enumerate() {
            let evaluation = result.unwrap();
            assert_eq!(
                evaluation.work_digest,
                fake_lane_work_digest(&template, request.nonce, lane as u32 + 1)
            );
            assert!(evaluation.chain_proof.is_none());
        }
        // A batch of one keeps the original single-share replay.
        let single = verifier
            .evaluate_batch(&requests[..1])
            .pop()
            .unwrap()
            .unwrap();
        assert_eq!(single.work_digest, fake_lane_work_digest(&template, 10, 1));
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "RUNBATCH 3\nRUN 1\n"
        );
        let leftovers = std::fs::read_dir(&scratch)
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("cmfd-v4-pool-")
            })
            .count();
        assert_eq!(leftovers, 0, "batch scratch files must be removed");
        drop(verifier);
        let _ = std::fs::remove_dir_all(scratch);
    }

    #[cfg(unix)]
    #[test]
    fn an_invalid_share_fails_alone_in_its_batch() {
        let (verifier, scratch, log) = batch_test_verifier("batch-invalid");
        let template = batch_test_template(BATCH_TEST_NETWORK_ID);
        let foreign = batch_test_template([0x5a; 32]);
        let requests = [
            ProductionV4PoolShareRequest {
                template: &template,
                nonce: 20,
                share_target: [0xff; 32],
            },
            ProductionV4PoolShareRequest {
                template: &foreign,
                nonce: 21,
                share_target: [0xff; 32],
            },
            ProductionV4PoolShareRequest {
                template: &template,
                nonce: 22,
                share_target: [0xff; 32],
            },
        ];
        let results = verifier.evaluate_batch(&requests);
        assert_eq!(
            results[0].as_ref().unwrap().work_digest,
            fake_lane_work_digest(&template, 20, 1)
        );
        let error = results[1].as_ref().unwrap_err();
        assert!(error.to_string().contains("another network"), "{error}");
        assert_eq!(
            results[2].as_ref().unwrap().work_digest,
            fake_lane_work_digest(&template, 22, 2)
        );
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "RUNBATCH 2\n");
        drop(verifier);
        let _ = std::fs::remove_dir_all(scratch);
    }

    /// Real-GPU check, run by hand on a pool host with the production workers:
    ///
    /// ```text
    /// CMFD_HW_REPLAY_WORKER=…/cmfd-v4-replay CMFD_HW_PROOF_WORKER=…/real_bank0_relations \
    /// CMFD_HW_MODEL_BANK=…/MODEL-V2.bank CMFD_HW_FIXED_DIR=…/production-v4/fixed \
    /// CMFD_HW_SCRATCH=/abs/scratch [CMFD_HW_PROVE=1] [CMFD_HW_EXTRA_GPUS=1,2] \
    /// [CMFD_HW_NETWORK_ID=<64 hex>] <test binary> --ignored real_gpu_batched_replay --nocapture
    /// ```
    ///
    /// Every batched lane must give exactly the work digest of a one-share
    /// replay of the same nonce. With `CMFD_HW_PROVE=1` two chain-winning
    /// lanes are also proved from one batch. The shares and the proof worker
    /// use the compiled network, or `CMFD_HW_NETWORK_ID`: a release proof
    /// worker serves only the ProductionV4 networks, not a Devnet build's.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a CUDA GPU, the model bank and the production workers"]
    fn real_gpu_batched_replay_matches_single_replays() {
        let path = |name: &str| {
            PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")))
        };
        let prove = std::env::var("CMFD_HW_PROVE").as_deref() == Ok("1");
        let network_id: [u8; 32] = std::env::var("CMFD_HW_NETWORK_ID").map_or(
            COMPILED_NETWORK_PROFILE.network_id,
            |network_id| {
                hex::decode(network_id)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .expect("CMFD_HW_NETWORK_ID is 32 bytes in hex")
            },
        );
        // CMFD_HW_EXTRA_GPUS: comma-separated CUDA devices that each run one
        // more replay worker; batches then run on every worker at once.
        let extra_gpus = std::env::var("CMFD_HW_EXTRA_GPUS")
            .ok()
            .map(|list| {
                list.split(',')
                    .filter(|device| !device.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut config = if prove {
            let mut config = production_v4_solo_config(
                &path("CMFD_HW_REPLAY_WORKER"),
                &path("CMFD_HW_PROOF_WORKER"),
                &path("CMFD_HW_MODEL_BANK"),
                &path("CMFD_HW_FIXED_DIR"),
                &path("CMFD_HW_SCRATCH"),
                None,
            )
            .unwrap();
            // The native proof command is `--server <network ID> <bank> <fixed>`.
            assert_eq!(config.proof.arguments[0], "--server");
            config.proof.arguments[1] = hex::encode(network_id).into();
            config
        } else {
            // Replay only: the proof worker is never asked for anything.
            let search = production_v4_pool_searcher_config(
                &path("CMFD_HW_REPLAY_WORKER"),
                &path("CMFD_HW_MODEL_BANK"),
                &path("CMFD_HW_SCRATCH"),
                32,
                None,
                None,
            )
            .unwrap();
            ProductionV4PoolVerifierConfig {
                replay: search.replay,
                extra_replays: Vec::new(),
                proof: fake_proof_worker(),
                scratch_directory: search.scratch_directory,
                worker_scratch_directory: search.worker_scratch_directory,
                work_check_pin: None,
            }
        };
        for gpu in &extra_gpus {
            let mut replay = config.replay.clone();
            replay.environment = vec![(
                "CUDA_VISIBLE_DEVICES".into(),
                production_v4_worker_cuda_visible_device(Some(gpu))
                    .unwrap()
                    .into(),
            )];
            config.extra_replays.push(replay);
        }
        let started = Instant::now();
        let verifier =
            ProductionV4PersistentPoolVerifier::start_for_network(network_id, config).unwrap();
        eprintln!(
            "{} replay worker(s) ready in {:.1} s",
            verifier.replay_workers(),
            started.elapsed().as_secs_f64()
        );
        let mut template = batch_test_template(network_id);
        let nonces = (0..32_u64)
            .map(|index| 0x5eed_0000 + index * 7_919)
            .collect::<Vec<_>>();
        verifier.evaluate(&template, 1, [0xff; 32]).unwrap();

        let started = Instant::now();
        let single = nonces
            .iter()
            .map(|&nonce| {
                verifier
                    .evaluate(&template, nonce, [0xff; 32])
                    .unwrap()
                    .work_digest
            })
            .collect::<Vec<_>>();
        let single_seconds = started.elapsed().as_secs_f64();
        eprintln!(
            "batch 1: {:.2} shares/s ({single_seconds:.2} s for {})",
            nonces.len() as f64 / single_seconds,
            nonces.len()
        );
        for size in [2, 4, 8, 16, 32] {
            let started = Instant::now();
            let mut batched = Vec::with_capacity(nonces.len());
            for chunk in nonces.chunks(size) {
                let requests = chunk
                    .iter()
                    .map(|&nonce| ProductionV4PoolShareRequest {
                        template: &template,
                        nonce,
                        share_target: [0xff; 32],
                    })
                    .collect::<Vec<_>>();
                for result in verifier.evaluate_batch(&requests) {
                    batched.push(result.unwrap().work_digest);
                }
            }
            let seconds = started.elapsed().as_secs_f64();
            assert_eq!(
                batched, single,
                "batch {size} differs from one-share replays"
            );
            eprintln!(
                "batch {size}: {:.2} shares/s ({:.1}x), lanes identical",
                nonces.len() as f64 / seconds,
                single_seconds / seconds
            );
        }

        let workers = verifier.replay_workers();
        if workers > 1 {
            // Every worker checks the same 32 nonces in batches of 8, all at
            // the same time; each must match the one-share replays exactly.
            let requests = nonces
                .iter()
                .map(|&nonce| ProductionV4PoolShareRequest {
                    template: &template,
                    nonce,
                    share_target: [0xff; 32],
                })
                .collect::<Vec<_>>();
            let started = Instant::now();
            let per_worker = std::thread::scope(|scope| {
                (0..workers)
                    .map(|worker| {
                        let (verifier, requests) = (&verifier, &requests);
                        scope.spawn(move || {
                            let worker_started = Instant::now();
                            let digests = requests
                                .chunks(8)
                                .flat_map(|chunk| verifier.evaluate_batch_on(worker, chunk))
                                .map(|result| result.unwrap().work_digest)
                                .collect::<Vec<_>>();
                            (digests, worker_started.elapsed().as_secs_f64())
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|handle| handle.join().unwrap())
                    .collect::<Vec<_>>()
            });
            let seconds = started.elapsed().as_secs_f64();
            for (worker, (digests, worker_seconds)) in per_worker.iter().enumerate() {
                assert_eq!(
                    digests, &single,
                    "worker {worker} differs from one-share replays"
                );
                eprintln!(
                    "worker {worker}: {:.2} shares/s alone, lanes identical",
                    nonces.len() as f64 / worker_seconds
                );
            }
            eprintln!(
                "{workers} workers together: {:.2} shares/s ({:.1}x one worker at batch 8)",
                (workers * nonces.len()) as f64 / seconds,
                (workers * nonces.len()) as f64 / seconds / (nonces.len() as f64 / per_worker[0].1)
            );
        }

        if prove {
            // The target is part of the challenge, so these digests differ
            // from the ones above; compare against a one-share replay instead.
            template.challenge.target = [0xff; 32];
            let requests = nonces[..2]
                .iter()
                .map(|&nonce| ProductionV4PoolShareRequest {
                    template: &template,
                    nonce,
                    share_target: [0xff; 32],
                })
                .collect::<Vec<_>>();
            let batched = verifier.evaluate_batch(&requests);
            for result in &batched {
                let evaluation = result.as_ref().unwrap();
                let proof = evaluation
                    .chain_proof
                    .as_ref()
                    .expect("a chain-winning lane is proved");
                assert_eq!(proof.work_digest(), evaluation.work_digest);
            }
            let single = verifier.evaluate(&template, nonces[0], [0xff; 32]).unwrap();
            assert!(single.chain_proof.is_some());
            assert_eq!(batched[0].as_ref().unwrap().work_digest, single.work_digest);
            eprintln!(
                "two chain-winning lanes proved from one batch; lane 0 matches a one-share proof"
            );
        }
    }

    /// Real-GPU check of block work checks on a pool's replay worker, run by
    /// hand on a pool host with the release replay worker:
    ///
    /// ```text
    /// CMFD_HW_REPLAY_WORKER=…/cmfd-v4-replay CMFD_HW_MODEL_BANK=…/MODEL-V2.bank \
    /// CMFD_HW_FIXED_RECORD=…/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json \
    /// CMFD_HW_SCRATCH=/abs/scratch [CMFD_WORK_THREADS=6] [CMFD_HW_WORK_CLAIMS=claims.jsonl] \
    ///   <test binary> --ignored real_gpu_work_checks --nocapture --test-threads=1
    /// ```
    ///
    /// The GPU engine borrows the replay worker through the work-check
    /// adapter. Both engines must pass their known answers and give the same
    /// final-activation digest on every committed execution vector: a
    /// published vector must match, a changed one (its block's claimed work
    /// over the changed header) must be a confirmed mismatch. Each line of
    /// `CMFD_HW_WORK_CLAIMS` is a JSON object with a block header
    /// (`network_id`, `previous_block`, `transaction_root`, `height`,
    /// `timestamp`, `target`), its `nonce`, its claimed `work_digest`, a
    /// `label` and the expected verdict (`expect`: `match` or `mismatch`),
    /// checked the same way. The GPU engine alone never confirms a mismatch,
    /// and a busy replay worker leaves the check to the CPU engine.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a CUDA GPU, the model bank and the release replay worker"]
    fn real_gpu_work_checks_agree_with_the_cpu_engine() {
        use crate::honest_work::{
            CpuWorkEngine, GPU_WORK_CHECK_TIMEOUT, GpuReplayWorkers, GpuWorkEngine,
            HonestWorkChecker, WorkClaim, WorkEngine, WorkEngineError, WorkEngineHealth,
            WorkEngineKind, WorkEngineState, WorkKatReport, WorkProvenance, WorkUnavailable,
            WorkVerdict, honest_work_digest,
        };
        use cmfd_consensus::{
            ConsensusPowVerifier, ForgeMatrixV4FileLayerSource, ForgeMatrixV4FixedArtifactRecordV1,
        };
        use std::sync::Arc;

        struct Case {
            label: String,
            claim: WorkClaim,
            expect_match: bool,
            /// The final-activation digest an independent engine computed
            /// before, where it is known.
            known_final: Option<[u8; 32]>,
        }

        let path = |name: &str| {
            PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")))
        };
        let digest = |value: &serde_json::Value, field: &str| -> [u8; 32] {
            let text = value[field]
                .as_str()
                .unwrap_or_else(|| panic!("{field} is missing"));
            hex::decode(text)
                .unwrap()
                .try_into()
                .unwrap_or_else(|_| panic!("{field} is not 32 bytes"))
        };
        let challenge_of = |value: &serde_json::Value| -> [u8; 32] {
            let number = |field: &str| match &value[field] {
                serde_json::Value::String(text) => text.parse::<u64>().unwrap(),
                other => other
                    .as_u64()
                    .unwrap_or_else(|| panic!("{field} is missing")),
            };
            forgematrix_v4_challenge_digest(
                &cmfd_consensus::BlockChallenge {
                    network_id: digest(value, "network_id"),
                    previous_block: digest(value, "previous_block"),
                    transaction_root: digest(value, "transaction_root"),
                    height: number("height"),
                    timestamp: number("timestamp"),
                    target: digest(value, "target"),
                },
                number("nonce"),
                PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            )
        };
        let threads = std::env::var("CMFD_WORK_THREADS")
            .map(|value| value.parse().expect("CMFD_WORK_THREADS is a number"))
            .unwrap_or(6);

        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../cmfd-consensus/data/forgematrix_v4_execution_vectors_v1.json"
        ))
        .unwrap();
        let published = vectors["vectors"].as_array().unwrap();
        let mut cases = Vec::new();
        for vector in published {
            let challenge_digest = challenge_of(vector);
            assert_eq!(challenge_digest, digest(vector, "challenge_digest"));
            cases.push(Case {
                label: format!("published-{}", vector["height"]),
                claim: WorkClaim {
                    challenge_digest,
                    work_digest: digest(vector, "work_digest"),
                },
                expect_match: true,
                known_final: Some(digest(vector, "final_activation_digest")),
            });
        }
        for changed in vectors["changed_vectors"].as_array().unwrap() {
            let block = published
                .iter()
                .find(|vector| vector["height"] == changed["height"])
                .unwrap();
            let challenge_digest = digest(changed, "challenge_digest");
            let final_activation_digest = digest(changed, "final_activation_digest");
            assert_eq!(
                honest_work_digest(challenge_digest, final_activation_digest),
                digest(changed, "work_digest")
            );
            cases.push(Case {
                label: format!(
                    "changed-{}-{}",
                    changed["height"],
                    changed["change"].as_str().unwrap()
                ),
                claim: WorkClaim {
                    challenge_digest,
                    work_digest: digest(block, "work_digest"),
                },
                expect_match: false,
                known_final: Some(final_activation_digest),
            });
        }
        if let Some(claims) = std::env::var_os("CMFD_HW_WORK_CLAIMS") {
            let claims = fs::read_to_string(claims).unwrap();
            for line in claims.lines().filter(|line| !line.trim().is_empty()) {
                let claim: serde_json::Value = serde_json::from_str(line).unwrap();
                cases.push(Case {
                    label: claim["label"].as_str().unwrap().to_owned(),
                    claim: WorkClaim {
                        challenge_digest: challenge_of(&claim),
                        work_digest: digest(&claim, "work_digest"),
                    },
                    expect_match: match claim["expect"].as_str() {
                        Some("match") => true,
                        Some("mismatch") => false,
                        other => panic!("expect must be match or mismatch, not {other:?}"),
                    },
                    known_final: None,
                });
            }
        }

        // Work checks use the replay worker only if it is the release build.
        let replay_worker = path("CMFD_HW_REPLAY_WORKER");
        let pin = ReplayWorkerPin::release(replay_worker.clone())
            .unwrap()
            .unwrap_or_else(|sha256| {
                panic!(
                    "{} is not the release replay worker (SHA-256 {})",
                    replay_worker.display(),
                    hex::encode(sha256)
                )
            });
        let bank_path = path("CMFD_HW_MODEL_BANK");
        let search = production_v4_pool_searcher_config(
            &replay_worker,
            &bank_path,
            &path("CMFD_HW_SCRATCH"),
            32,
            None,
            None,
        )
        .unwrap();
        let started = Instant::now();
        let verifier = Arc::new(
            ProductionV4PersistentPoolVerifier::start(ProductionV4PoolVerifierConfig {
                replay: search.replay,
                extra_replays: Vec::new(),
                // Work checks never prove.
                proof: fake_proof_worker(),
                scratch_directory: search.scratch_directory,
                worker_scratch_directory: search.worker_scratch_directory,
                work_check_pin: Some(pin),
            })
            .unwrap(),
        );
        eprintln!(
            "replay worker ready in {:.1} s",
            started.elapsed().as_secs_f64()
        );

        let record: ForgeMatrixV4FixedArtifactRecordV1 =
            serde_json::from_slice(&fs::read(path("CMFD_HW_FIXED_RECORD")).unwrap()).unwrap();
        let mainnet_network_id = digest(&published[0], "network_id");
        let started = Instant::now();
        let (_, identity) = ConsensusPowVerifier::v4_candidate_for_network_with_layer_roots(
            mainnet_network_id,
            record,
            BufReader::with_capacity(1024 * 1024, File::open(&bank_path).unwrap()),
        )
        .unwrap();
        eprintln!(
            "bank authenticated in {:.1} s",
            started.elapsed().as_secs_f64()
        );
        let source = ForgeMatrixV4FileLayerSource::new(
            File::open(&bank_path).unwrap(),
            &identity.manifest,
            identity.base_input,
            identity.layer_roots,
        )
        .unwrap();
        let cpu: Arc<dyn WorkEngine> = Arc::new(CpuWorkEngine::new(Arc::new(source), threads));
        let workers: Arc<dyn GpuReplayWorkers> = verifier.clone();
        let gpu: Arc<dyn WorkEngine> =
            Arc::new(GpuWorkEngine::new(workers, GPU_WORK_CHECK_TIMEOUT));
        assert_eq!(gpu.workers(), 1);

        // As the node builds it: block checks read without authenticating
        // again; the known answers authenticate every layer they read.
        let gpu_only = HonestWorkChecker::new(None, Some(Arc::clone(&gpu)), false).unwrap();
        let checker =
            HonestWorkChecker::new(Some(Arc::clone(&cpu)), Some(Arc::clone(&gpu)), false).unwrap();
        let started = Instant::now();
        assert_eq!(
            gpu_only.run_known_answer_tests(),
            WorkKatReport {
                cpu: None,
                gpu: Some(WorkEngineHealth::Ready)
            }
        );
        eprintln!(
            "GPU engine alone: known answers passed in {:.3} s",
            started.elapsed().as_secs_f64()
        );
        let started = Instant::now();
        let report = checker.run_known_answer_tests();
        eprintln!(
            "CPU and GPU engines: known answers {report:?} in {:.2} s on {threads} threads",
            started.elapsed().as_secs_f64()
        );
        assert_eq!(report.cpu, Some(WorkEngineHealth::Ready));
        assert_eq!(report.gpu, Some(WorkEngineHealth::Ready));
        assert_eq!(checker.engine_state(), WorkEngineState::Ready);
        assert!(checker.has_independent_engines());

        let mut finals = Vec::with_capacity(cases.len());
        for case in &cases {
            let challenge_digest = case.claim.challenge_digest;
            let started = Instant::now();
            let gpu_final = gpu
                .final_activation_digest(challenge_digest, 0, false)
                .unwrap();
            let gpu_seconds = started.elapsed().as_secs_f64();
            let started = Instant::now();
            let cpu_final = cpu
                .final_activation_digest(challenge_digest, 0, false)
                .unwrap();
            let cpu_seconds = started.elapsed().as_secs_f64();
            assert_eq!(gpu_final, cpu_final, "{}: the engines differ", case.label);
            if let Some(known) = case.known_final {
                assert_eq!(cpu_final, known, "{}", case.label);
            }
            let honest = honest_work_digest(challenge_digest, cpu_final);
            assert_eq!(honest == case.claim.work_digest, case.expect_match);

            let started = Instant::now();
            let verdict = checker.check(case.claim);
            let check_seconds = started.elapsed().as_secs_f64();
            let outcome = match &verdict {
                WorkVerdict::Match(WorkProvenance::OwnEngine) if case.expect_match => "match",
                WorkVerdict::Mismatch(mismatch) if !case.expect_match => {
                    assert_eq!(mismatch.provenance(), WorkProvenance::Confirmed);
                    assert!(mismatch.confirmed().is_some());
                    assert!(mismatch.cacheable());
                    assert_eq!(mismatch.honest_final_activation_digest(), cpu_final);
                    assert_eq!(mismatch.honest_work_digest(), honest);
                    "confirmed mismatch"
                }
                other => panic!("{}: unexpected verdict {other:?}", case.label),
            };
            let started = Instant::now();
            assert_eq!(checker.check(case.claim), verdict);
            let repeat_seconds = started.elapsed().as_secs_f64();
            assert!(
                repeat_seconds < 0.1,
                "a repeated check answers from the memo"
            );
            eprintln!(
                "CASE {} verdict={outcome} gpu_final={} cpu_final={} claimed_work={} \
                 honest_work={} gpu_replay_s={gpu_seconds:.6} cpu_s={cpu_seconds:.3} \
                 check_s={check_seconds:.3} repeat_s={repeat_seconds:.6}",
                case.label,
                hex::encode(gpu_final),
                hex::encode(cpu_final),
                hex::encode(case.claim.work_digest),
                hex::encode(honest),
            );
            finals.push(cpu_final);
        }
        let alarms = checker.alarms();
        eprintln!("CPU and GPU engines after the checks: {alarms:?}");
        assert_eq!(alarms.engine_divergence, 0);
        assert_eq!(alarms.engine_failures, 0);
        assert_eq!(alarms.own_engine_mismatches, 0);
        assert_eq!(
            checker.engine_health(WorkEngineKind::Gpu),
            Some(WorkEngineHealth::Ready)
        );
        assert_eq!(
            checker.engine_health(WorkEngineKind::Cpu),
            Some(WorkEngineHealth::Ready)
        );

        // A busy replay worker: the CPU engine runs the check instead, and
        // the GPU keeps its health; with no CPU engine there is no verdict.
        let idle = &cases[0];
        assert!(checker.forget(idle.claim.challenge_digest));
        {
            let _held = verifier.searcher.state.lock().unwrap();
            assert_eq!(
                gpu.final_activation_digest(idle.claim.challenge_digest, 0, false),
                Err(WorkEngineError::Busy)
            );
            let started = Instant::now();
            assert_eq!(
                checker.check(idle.claim),
                WorkVerdict::Match(WorkProvenance::OwnEngine)
            );
            eprintln!(
                "BUSY replay worker held: {} matched on the CPU engine in {:.3} s",
                idle.label,
                started.elapsed().as_secs_f64()
            );
            assert_eq!(
                checker.engine_health(WorkEngineKind::Gpu),
                Some(WorkEngineHealth::Ready),
                "a busy GPU is not retired"
            );
            assert_eq!(
                gpu_only.check(idle.claim),
                WorkVerdict::Unavailable(WorkUnavailable::Engine(WorkEngineError::Busy))
            );
            eprintln!("BUSY replay worker held: the GPU engine alone gives no verdict");
        }

        // The GPU engine alone: the same answers, but a mismatch is only its
        // own, never confirmed.
        assert!(!gpu_only.has_independent_engines());
        let mut lone_mismatches = 0;
        for (case, cpu_final) in cases.iter().zip(&finals) {
            let started = Instant::now();
            let verdict = gpu_only.check(case.claim);
            let check_seconds = started.elapsed().as_secs_f64();
            let outcome = match &verdict {
                WorkVerdict::Match(WorkProvenance::OwnEngine) if case.expect_match => "match",
                WorkVerdict::Mismatch(mismatch) if !case.expect_match => {
                    assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
                    assert_eq!(mismatch.confirmed(), None);
                    assert!(mismatch.cacheable(), "no CPU engine can settle it");
                    assert_eq!(mismatch.honest_final_activation_digest(), *cpu_final);
                    lone_mismatches += 1;
                    "own-engine mismatch, not confirmed"
                }
                other => panic!("{}: unexpected GPU-only verdict {other:?}", case.label),
            };
            eprintln!(
                "GPU-ONLY {} verdict={outcome} check_s={check_seconds:.6}",
                case.label
            );
        }
        let alarms = gpu_only.alarms();
        eprintln!("GPU engine alone after the checks: {alarms:?}");
        assert_eq!(alarms.own_engine_mismatches, lone_mismatches);
        assert_eq!(alarms.engine_failures, 0);
        assert_eq!(
            gpu_only.engine_health(WorkEngineKind::Gpu),
            Some(WorkEngineHealth::Ready)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_batch_fails_its_shares_and_the_worker_recovers() {
        let (verifier, scratch, log) = batch_test_verifier("batch-crash");
        let template = batch_test_template(BATCH_TEST_NETWORK_ID);
        let requests = [30_u64, 31].map(|nonce| ProductionV4PoolShareRequest {
            template: &template,
            nonce,
            share_target: [0xff; 32],
        });
        let crash = PathBuf::from(format!("{}.crash", log.display()));
        std::fs::write(&crash, b"").unwrap();
        for result in verifier.evaluate_batch(&requests) {
            let error = result.unwrap_err();
            assert!(error.to_string().contains("closed stdout"), "{error}");
        }
        std::fs::remove_file(&crash).unwrap();
        for (lane, result) in verifier.evaluate_batch(&requests).into_iter().enumerate() {
            assert_eq!(
                result.unwrap().work_digest,
                fake_lane_work_digest(&template, requests[lane].nonce, lane as u32 + 1)
            );
        }
        drop(verifier);
        let _ = std::fs::remove_dir_all(scratch);
    }
}
