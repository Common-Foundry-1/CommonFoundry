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
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use cmfd_consensus::forgematrix_v4_proof::{
    forgematrix_v4_final_activation_digest, forgematrix_v4_mask_coefficients,
};
use cmfd_consensus::forgematrix_v4_proof_codec::decode_forgematrix_v4_transparent_proof;
use cmfd_consensus::{
    BlockProof, FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_FIELD_MODULUS,
    FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN, FORGEMATRIX_V4_PROOF_VERSION,
    FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES, ForgeMatrixV4CandidateProof,
    PRODUCTION_V2_LAYERS, PRODUCTION_V4_MAX_PROOF_BYTES, PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
    forgematrix_v4_challenge_digest, forgematrix_v4_proof_system_digest,
    forgematrix_v4_work_digest,
};
use serde::Serialize;

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
    pub proof: ProductionV4PoolWorkerCommand,
    pub scratch_directory: PathBuf,
    pub worker_scratch_directory: String,
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
    expected_network_id: [u8; 32],
    scratch_directory: PathBuf,
    worker_scratch_directory: String,
    startup_id: [u8; 8],
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
        proof,
        scratch_directory: search.scratch_directory,
        worker_scratch_directory: search.worker_scratch_directory,
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
    next_attempt: u64,
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
}

#[derive(Debug)]
struct WorkerProcess {
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
        let searcher = ProductionV4PersistentPoolSearcher::start_for_network(
            expected_network_id,
            ProductionV4PoolSearcherConfig {
                replay: config.replay,
                scratch_directory: config.scratch_directory.clone(),
                worker_scratch_directory: config.worker_scratch_directory.clone(),
                batch_size: 32,
            },
        )?;
        let proof = PersistentWorker::start(
            &config.proof,
            "CMFD_V4_PROOF_READY",
            "ProductionV4 proof worker",
        )?;
        let mut startup_id = [0_u8; 8];
        getrandom::fill(&mut startup_id).map_err(replay_error)?;
        Ok(Self {
            searcher,
            expected_network_id,
            scratch_directory: config.scratch_directory,
            worker_scratch_directory: config.worker_scratch_directory,
            startup_id,
            state: Mutex::new(WorkerState {
                proof,
                next_attempt: 0,
            }),
        })
    }

    fn evaluate_locked(
        &self,
        state: &mut WorkerState,
        template: &BlockTemplate,
        nonce: u64,
        share_target: [u8; 32],
    ) -> Result<ProductionV4PoolShareEvaluation, PoolError> {
        let evaluation_started = Instant::now();
        let mut search_state = self
            .searcher
            .state
            .lock()
            .map_err(|_| pool_replay_failure("persistent search worker lock is poisoned"))?;
        self.validate_share(template, share_target)?;

        let attempt_number = state.next_attempt;
        state.next_attempt = state.next_attempt.wrapping_add(1);
        let token = format!(
            "cmfd-v4-pool-{}-{attempt_number:016x}",
            hex::encode(self.startup_id)
        );
        let files = AttemptFiles {
            scratch_directory: self.scratch_directory.clone(),
            token: token.clone(),
        };
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
            &production_v4_replay_coefficients(challenge_digest),
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
            });
        }
        self.prove_chain_share(
            state,
            &mut search_state,
            ChainShare {
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

    /// Checks several shares with one `RUNBATCH` replay per 64 shares. A share
    /// that fails validation, or a lane that meets the chain target, is
    /// handled exactly as the single-share path would.
    fn evaluate_batch_locked(
        &self,
        state: &mut WorkerState,
        shares: &[ProductionV4PoolShareRequest<'_>],
    ) -> Vec<Result<ProductionV4PoolShareEvaluation, PoolError>> {
        let evaluation_started = Instant::now();
        let mut search_state = match self.searcher.state.lock() {
            Ok(search_state) => search_state,
            Err(_) => {
                return shares
                    .iter()
                    .map(|_| {
                        Err(pool_replay_failure(
                            "persistent search worker lock is poisoned",
                        ))
                    })
                    .collect();
            }
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
            match self.replay_search_batch(state, &mut search_state, chunk) {
                Ok(final_activations) => {
                    let search_replay_seconds = search_replay_started.elapsed().as_secs_f64();
                    let lane_activations = final_activations
                        .chunks_exact(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES);
                    for (&(index, challenge_digest), search_final) in
                        chunk.iter().zip(lane_activations)
                    {
                        results[index] = Some(self.finish_batched_share(
                            state,
                            &mut search_state,
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
        state: &mut WorkerState,
        search_state: &mut SearchWorkerState,
        lanes: &[(usize, [u8; 32])],
    ) -> Result<Vec<u8>, PoolError> {
        let attempt_number = state.next_attempt;
        state.next_attempt = state.next_attempt.wrapping_add(1);
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
            .flat_map(|&(_, challenge_digest)| production_v4_replay_coefficients(challenge_digest))
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

    /// Derives one batched lane's work digest; a chain-winning lane is then
    /// written out and proved exactly like a single share.
    #[allow(clippy::too_many_arguments)]
    fn finish_batched_share(
        &self,
        state: &mut WorkerState,
        search_state: &mut SearchWorkerState,
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
            });
        }
        let attempt_number = state.next_attempt;
        state.next_attempt = state.next_attempt.wrapping_add(1);
        let files = AttemptFiles {
            scratch_directory: self.scratch_directory.clone(),
            token: format!(
                "cmfd-v4-pool-{}-{attempt_number:016x}",
                hex::encode(self.startup_id)
            ),
        };
        write_new_file(
            &files.path("coefficients.bin"),
            &production_v4_replay_coefficients(challenge_digest),
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
        self.prove_chain_share(
            state,
            search_state,
            ChainShare {
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
    fn prove_chain_share(
        &self,
        state: &mut WorkerState,
        search_state: &mut SearchWorkerState,
        share: ChainShare<'_>,
    ) -> Result<ProductionV4PoolShareEvaluation, PoolError> {
        let ChainShare {
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
        let proof_started = Instant::now();
        state.proof.invoke(
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
        })
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
        validate_expected_network_id(expected_network_id)?;
        validate_scratch_paths(&config.scratch_directory, &config.worker_scratch_directory)?;
        if !(1..=PRODUCTION_V4_POOL_SEARCH_MAX_BATCH_SIZE).contains(&config.batch_size) {
            return Err(pool_replay_failure(format!(
                "ProductionV4 pool search batch size must be between 1 and {PRODUCTION_V4_POOL_SEARCH_MAX_BATCH_SIZE}"
            )));
        }
        fs::create_dir_all(&config.scratch_directory).map_err(replay_error)?;
        let replay = PersistentWorker::start(
            &config.replay,
            "CMFD_V4_REPLAY_READY",
            "ProductionV4 pool search worker",
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
            coefficients.extend_from_slice(&production_v4_replay_coefficients(challenge_digest));
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| pool_replay_failure("persistent worker lock is poisoned"))?;
        self.evaluate_locked(&mut state, template, nonce, share_target)
    }

    fn evaluate_batch(
        &self,
        shares: &[ProductionV4PoolShareRequest<'_>],
    ) -> Vec<Result<ProductionV4PoolShareEvaluation, PoolError>> {
        // A lone share takes the original single-share replay.
        if shares.len() <= 1 {
            return shares
                .iter()
                .map(|share| self.evaluate(share.template, share.nonce, share.share_target))
                .collect();
        }
        match self.state.lock() {
            Ok(mut state) => self.evaluate_batch_locked(&mut state, shares),
            Err(_) => shares
                .iter()
                .map(|_| Err(pool_replay_failure("persistent worker lock is poisoned")))
                .collect(),
        }
    }
}

impl PersistentWorker {
    /// Starts the worker now, so a bad command or model fails at startup.
    fn start(
        command: &ProductionV4PoolWorkerCommand,
        ready_marker: &'static str,
        label: &'static str,
    ) -> Result<Self, PoolError> {
        if !command.program.is_absolute() || !command.program.is_file() {
            return Err(pool_replay_failure(format!(
                "{label} program must be an existing absolute file: {}",
                command.program.display()
            )));
        }
        let process = WorkerProcess::spawn(command, ready_marker, label, WORKER_READY_TIMEOUT)?;
        Ok(Self {
            command: command.clone(),
            ready_marker,
            label,
            process: Some(process),
            retry_after: None,
            restarts: 0,
        })
    }

    fn invoke(&mut self, fields: &[String], done_marker: &str) -> Result<(), PoolError> {
        self.invoke_with_timeout(fields, done_marker, WORKER_COMMAND_TIMEOUT)
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
            match WorkerProcess::spawn(
                &self.command,
                self.ready_marker,
                self.label,
                WORKER_READY_TIMEOUT,
            ) {
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

fn final_activation_digest_from_bytes(
    challenge_digest: [u8; 32],
    final_activation: &[u8],
) -> Result<[u8; 32], PoolError> {
    if final_activation.len() != FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES {
        return Err(pool_replay_failure(
            "ProductionV4 final activation has the wrong byte length",
        ));
    }
    let mut hasher = blake3::Hasher::new_derive_key(FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN);
    hasher.update(&challenge_digest);
    hasher.update(&((final_activation.len() / size_of::<u32>()) as u64).to_le_bytes());
    for encoded in final_activation.chunks_exact(size_of::<u32>()) {
        let value = u32::from_le_bytes(encoded.try_into().expect("four-byte chunk"));
        if value >= FORGEMATRIX_V4_FIELD_MODULUS {
            return Err(pool_replay_failure(
                "ProductionV4 final activation contains a noncanonical field value",
            ));
        }
    }
    hasher.update(final_activation);
    Ok(*hasher.finalize().as_bytes())
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
    fn replay_coefficients_have_the_exact_production_shape() {
        let first = production_v4_replay_coefficients([7; 32]);
        let second = production_v4_replay_coefficients([7; 32]);
        assert_eq!(first, second);
        assert_eq!(first.len(), (PRODUCTION_V2_LAYERS as usize + 1) * 20);
        assert_eq!(
            &first[..20],
            &forgematrix_v4_mask_coefficients([7; 32], u32::MAX)
        );
    }

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
    fn final_activation_digest_matches_consensus_and_rejects_noncanonical_fields() {
        let challenge_digest = [0x6b; 32];
        let mut values = (0..FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES / size_of::<u32>())
            .map(|index| {
                ((index as u64 * 1_000_003 + 97) % u64::from(FORGEMATRIX_V4_FIELD_MODULUS)) as u32
            })
            .collect::<Vec<_>>();
        values[..3].copy_from_slice(&[0, 1, FORGEMATRIX_V4_FIELD_MODULUS - 1]);
        let mut encoded = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        let fields: Vec<cmfd_consensus::forgematrix_v4_basefold::ForgeMatrixV4Field> =
            serde_json::from_value(serde_json::to_value(&values).unwrap()).unwrap();
        assert_eq!(
            final_activation_digest_from_bytes(challenge_digest, &encoded).unwrap(),
            forgematrix_v4_final_activation_digest(challenge_digest, &fields)
        );
        for index in [0, values.len() - 1] {
            let offset = index * size_of::<u32>();
            encoded[offset..offset + size_of::<u32>()]
                .copy_from_slice(&FORGEMATRIX_V4_FIELD_MODULUS.to_le_bytes());
            assert!(final_activation_digest_from_bytes(challenge_digest, &encoded).is_err());
            encoded[offset..offset + size_of::<u32>()]
                .copy_from_slice(&values[index].to_le_bytes());
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
    /// to `$1`, and `RUNBATCH` crashes while `$1.crash` exists.
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
        let scratch = worker_test_path(label);
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let log = scratch.join("worker.log");
        let verifier = ProductionV4PersistentPoolVerifier::start_for_network(
            BATCH_TEST_NETWORK_ID,
            ProductionV4PoolVerifierConfig {
                replay: fake_replay_worker(&log),
                proof: fake_proof_worker(),
                scratch_directory: scratch.clone(),
                worker_scratch_directory: scratch.to_str().unwrap().to_owned(),
            },
        )
        .unwrap();
        (verifier, scratch, log)
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
    /// CMFD_HW_SCRATCH=/abs/scratch [CMFD_HW_PROVE=1] \
    ///   <test binary> --ignored real_gpu_batched_replay --nocapture
    /// ```
    ///
    /// Every batched lane must give exactly the work digest of a one-share
    /// replay of the same nonce. With `CMFD_HW_PROVE=1` two chain-winning
    /// lanes are also proved from one batch.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a CUDA GPU, the model bank and the production workers"]
    fn real_gpu_batched_replay_matches_single_replays() {
        let path = |name: &str| {
            PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")))
        };
        let prove = std::env::var("CMFD_HW_PROVE").as_deref() == Ok("1");
        let config = if prove {
            production_v4_solo_config(
                &path("CMFD_HW_REPLAY_WORKER"),
                &path("CMFD_HW_PROOF_WORKER"),
                &path("CMFD_HW_MODEL_BANK"),
                &path("CMFD_HW_FIXED_DIR"),
                &path("CMFD_HW_SCRATCH"),
                None,
            )
            .unwrap()
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
                proof: fake_proof_worker(),
                scratch_directory: search.scratch_directory,
                worker_scratch_directory: search.worker_scratch_directory,
            }
        };
        let verifier = ProductionV4PersistentPoolVerifier::start(config).unwrap();
        let mut template = batch_test_template(COMPILED_NETWORK_PROFILE.network_id);
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
