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
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use cmfd_consensus::forgematrix_v4_proof::{
    forgematrix_v4_final_activation_digest, forgematrix_v4_mask_coefficients,
};
use cmfd_consensus::forgematrix_v4_proof_codec::decode_forgematrix_v4_transparent_proof;
use cmfd_consensus::{
    BlockProof, FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_FIELD_MODULUS,
    FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN, FORGEMATRIX_V4_PROOF_VERSION,
    FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES, ForgeMatrixV4CandidateProof,
    PRODUCTION_V2_LAYERS, PRODUCTION_V4_MAX_PROOF_BYTES, PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
    PRODUCTION_V4_TESTNET_NETWORK_ID, forgematrix_v4_challenge_digest,
    forgematrix_v4_proof_system_digest, forgematrix_v4_work_digest,
};
use serde::Serialize;

use crate::BlockTemplate;
use crate::pool::{PoolError, ProductionV4PoolShareEvaluation, ProductionV4PoolShareVerifier};

const WORKER_OUTPUT_MAX_LINES: usize = 4_096;
const WORKER_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const FROZEN_TEMPLATE_FORMAT_VERSION: u16 = 1;

/// One exact command used to start a persistent worker. Arguments must include
/// the worker's `--server` flag and authenticated model/artifact paths.
#[derive(Debug, Clone)]
pub struct ProductionV4PoolWorkerCommand {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
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

#[derive(Debug)]
pub struct ProductionV4PersistentPoolVerifier {
    scratch_directory: PathBuf,
    worker_scratch_directory: String,
    startup_id: [u8; 8],
    state: Mutex<WorkerState>,
}

#[derive(Debug)]
struct WorkerState {
    replay: PersistentWorker,
    proof: PersistentWorker,
    next_attempt: u64,
}

#[derive(Debug)]
struct PersistentWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    label: &'static str,
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

impl ProductionV4PersistentPoolVerifier {
    pub fn start(config: ProductionV4PoolVerifierConfig) -> Result<Self, PoolError> {
        validate_scratch_paths(&config.scratch_directory, &config.worker_scratch_directory)?;
        fs::create_dir_all(&config.scratch_directory).map_err(replay_error)?;
        let replay = PersistentWorker::start(
            &config.replay,
            "CMFD_V4_REPLAY_READY",
            "ProductionV4 replay worker",
        )?;
        let proof = PersistentWorker::start(
            &config.proof,
            "CMFD_V4_PROOF_READY",
            "ProductionV4 proof worker",
        )?;
        let mut startup_id = [0_u8; 8];
        getrandom::fill(&mut startup_id).map_err(replay_error)?;
        Ok(Self {
            scratch_directory: config.scratch_directory,
            worker_scratch_directory: config.worker_scratch_directory,
            startup_id,
            state: Mutex::new(WorkerState {
                replay,
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
        if template.challenge.network_id != PRODUCTION_V4_TESTNET_NETWORK_ID {
            return Err(pool_replay_failure(
                "pool replay received a template for another network",
            ));
        }
        if share_target < template.challenge.target {
            return Err(pool_replay_failure(
                "pool share target is harder than the chain target",
            ));
        }

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

        state.replay.invoke(
            &[
                "RUN".to_owned(),
                "search".to_owned(),
                self.worker_path(&coefficients_path)?,
                self.worker_path(&search_prefix)?,
            ],
            "CMFD_V4_REPLAY_DONE",
        )?;
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

        let full_prefix = files.path("full");
        let full_final_path = files.path("full-final-activation.bin");
        let proof_path = files.path("transparent-proof.bin");
        state.replay.invoke(
            &[
                "RUN".to_owned(),
                "full".to_owned(),
                self.worker_path(&coefficients_path)?,
                self.worker_path(&full_prefix)?,
            ],
            "CMFD_V4_REPLAY_DONE",
        )?;
        let full_final = read_exact_file(
            &full_final_path,
            FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES,
        )?;
        if search_final != full_final {
            return Err(pool_replay_failure(
                "search replay and full replay final activations differ",
            ));
        }
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
        Ok(ProductionV4PoolShareEvaluation {
            work_digest,
            chain_proof: Some(proof),
        })
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
}

impl PersistentWorker {
    fn start(
        command: &ProductionV4PoolWorkerCommand,
        ready_marker: &str,
        label: &'static str,
    ) -> Result<Self, PoolError> {
        if !command.program.is_absolute() || !command.program.is_file() {
            return Err(pool_replay_failure(format!(
                "{label} program must be an existing absolute file: {}",
                command.program.display()
            )));
        }
        let mut child = Command::new(&command.program)
            .args(&command.arguments)
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
        let mut worker = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            label,
        };
        worker.read_until(ready_marker)?;
        Ok(worker)
    }

    fn invoke(&mut self, fields: &[String], done_marker: &str) -> Result<(), PoolError> {
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
        self.stdin
            .write_all(fields.join("\t").as_bytes())
            .and_then(|()| self.stdin.write_all(b"\n"))
            .and_then(|()| self.stdin.flush())
            .map_err(replay_error)?;
        self.read_until(done_marker)
    }

    fn read_until(&mut self, marker: &str) -> Result<(), PoolError> {
        let mut total_bytes = 0_usize;
        for _ in 0..WORKER_OUTPUT_MAX_LINES {
            let mut line = String::new();
            let bytes = self.stdout.read_line(&mut line).map_err(replay_error)?;
            if bytes == 0 {
                let status = self.child.try_wait().map_err(replay_error)?;
                return Err(pool_replay_failure(format!(
                    "{} closed stdout before {marker}; status={status:?}",
                    self.label
                )));
            }
            total_bytes = total_bytes
                .checked_add(bytes)
                .ok_or_else(|| pool_replay_failure("worker output byte count overflow"))?;
            if total_bytes > WORKER_OUTPUT_MAX_BYTES {
                return Err(pool_replay_failure(format!(
                    "{} exceeded its output limit",
                    self.label
                )));
            }
            if line.trim_end_matches(['\r', '\n']) == marker {
                return Ok(());
            }
        }
        Err(pool_replay_failure(format!(
            "{} did not emit {marker} within its line limit",
            self.label
        )))
    }
}

impl Drop for PersistentWorker {
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
        hasher.update(encoded);
    }
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
}
