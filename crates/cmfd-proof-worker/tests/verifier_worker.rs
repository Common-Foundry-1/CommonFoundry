#[cfg(not(feature = "production-v3"))]
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(windows)]
use std::process::Stdio;
#[cfg(not(feature = "production-v3"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use cmfd_consensus::{
    BLOCK_VERSION, Block, BlockChallenge, BlockProof, Coinbase, ConsensusPowVerifier,
    v2_test_reference,
};
#[cfg(not(feature = "production-v3"))]
use cmfd_proof_worker::ProductionV3VerifierArtifacts;
use cmfd_proof_worker::{
    PersistentVerifierWorker, VerifierWorkerConfig, VerifierWorkerError,
    verify_block_out_of_process,
};
use sha2::{Digest, Sha256};

#[cfg(not(feature = "production-v3"))]
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(not(feature = "production-v3"))]
struct TestArtifacts {
    root: PathBuf,
}

#[cfg(not(feature = "production-v3"))]
impl TestArtifacts {
    fn create() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cmfd-persistent-verifier-test-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, bytes).unwrap();
        fs::canonicalize(path).unwrap()
    }
}

#[cfg(not(feature = "production-v3"))]
impl Drop for TestArtifacts {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn sha256(path: &Path) -> [u8; 32] {
    let mut file = File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    hasher.finalize().into()
}

fn worker_config() -> VerifierWorkerConfig {
    let worker = PathBuf::from(env!("CARGO_BIN_EXE_cmfd-proof-worker"));
    VerifierWorkerConfig {
        worker_sha256: sha256(&worker),
        worker_executable: worker,
        startup_timeout: Duration::from_secs(10),
        timeout: Duration::from_secs(10),
        memory_limit_bytes: 512 * 1024 * 1024,
        production_v3_artifacts: None,
    }
}

fn candidate_block() -> (ConsensusPowVerifier, Block) {
    let reference = v2_test_reference().unwrap();
    let network_id = reference.descriptor().network_id;
    let verifier = ConsensusPowVerifier::v2_reference(reference);
    let challenge = BlockChallenge {
        network_id,
        previous_block: [1; 32],
        transaction_root: [2; 32],
        height: 1,
        timestamp: 60,
        target: [0xff; 32],
    };
    let proof = verifier.mine(&challenge, 7, 1).unwrap();
    (
        verifier,
        Block {
            version: BLOCK_VERSION,
            challenge,
            proof,
            coinbase: Coinbase {
                height: 1,
                outputs: Vec::new(),
            },
            transactions: Vec::new(),
        },
    )
}

#[test]
fn pinned_worker_verifies_the_exact_block_and_issues_a_capability() {
    let (verifier, block) = candidate_block();
    verify_block_out_of_process(&worker_config(), &verifier, &block).unwrap();
}

#[test]
fn pinned_worker_rejects_an_invalid_proof() {
    let (verifier, mut block) = candidate_block();
    let BlockProof::V2Reference(proof) = &mut block.proof else {
        unreachable!();
    };
    proof.work_digest[0] ^= 1;
    let error = verify_block_out_of_process(&worker_config(), &verifier, &block).unwrap_err();
    assert!(matches!(error, VerifierWorkerError::ProofRejected(_)));
}

#[test]
fn executable_hash_mismatch_fails_before_spawn() {
    let (verifier, block) = candidate_block();
    let mut config = worker_config();
    config.worker_sha256[0] ^= 1;
    let error = verify_block_out_of_process(&config, &verifier, &block).unwrap_err();
    assert!(matches!(
        error,
        VerifierWorkerError::Process(cmfd_proof_worker::ProofWorkerError::HashMismatch {
            component: "verifier worker executable"
        })
    ));
}

#[test]
fn persistent_worker_loads_once_for_many_canonical_blocks() {
    let (verifier, block) = candidate_block();
    let worker =
        PersistentVerifierWorker::start(worker_config(), verifier, block.challenge.network_id)
            .unwrap();
    assert_eq!(worker.process_generation(), 1);
    for _ in 0..24 {
        worker.verify_block(&block).unwrap();
    }
    assert_eq!(worker.process_generation(), 1);
}

#[test]
fn persistent_worker_rejects_a_wrong_pin_before_startup() {
    let (verifier, block) = candidate_block();
    let mut config = worker_config();
    config.worker_sha256[0] ^= 1;
    let error = PersistentVerifierWorker::start(config, verifier, block.challenge.network_id)
        .err()
        .expect("a wrong compiled worker pin must fail closed");
    assert!(matches!(
        error,
        VerifierWorkerError::Process(cmfd_proof_worker::ProofWorkerError::HashMismatch {
            component: "verifier worker executable"
        })
    ));
}

#[test]
fn persistent_worker_startup_timeout_kills_the_untrusted_generation() {
    let (verifier, block) = candidate_block();
    let mut config = worker_config();
    config.startup_timeout = Duration::from_nanos(1);
    let error = PersistentVerifierWorker::start(config, verifier, block.challenge.network_id)
        .err()
        .expect("an expired startup deadline must fail closed");
    assert!(matches!(
        error,
        VerifierWorkerError::Process(cmfd_proof_worker::ProofWorkerError::Timeout { .. })
    ));
}

#[cfg(not(feature = "production-v3"))]
#[test]
fn persistent_worker_rejects_wrong_feature_before_serving_and_redacts_paths() {
    let files = TestArtifacts::create();
    let secret_marker = "secret-customer-model";
    let mut config = worker_config();
    config.production_v3_artifacts = Some(ProductionV3VerifierArtifacts {
        bank: files.write(&format!("{secret_marker}.bank"), b"bank"),
        manifest: files.write("manifest.json", b"manifest"),
        record_v2: files.write("record-v2.json", b"record"),
    });
    let (verifier, block) = candidate_block();
    let error = PersistentVerifierWorker::start(config, verifier, block.challenge.network_id)
        .err()
        .expect("a worker compiled without ProductionV3 must fail at startup");
    assert!(!error.to_string().contains(secret_marker));
}

#[test]
fn crashed_persistent_worker_fails_the_request_then_restarts_authenticated() {
    let (verifier, block) = candidate_block();
    let worker =
        PersistentVerifierWorker::start(worker_config(), verifier, block.challenge.network_id)
            .unwrap();
    let pid = worker.process_id().expect("worker process must be running");
    terminate_process(pid);

    worker
        .verify_block(&block)
        .expect_err("the request observing a crashed generation must fail closed");
    assert_eq!(worker.process_generation(), 1);
    worker.verify_block(&block).unwrap();
    assert_eq!(worker.process_generation(), 2);
}

#[test]
fn explicit_shutdown_makes_the_next_request_start_a_fresh_generation() {
    let (verifier, block) = candidate_block();
    let worker =
        PersistentVerifierWorker::start(worker_config(), verifier, block.challenge.network_id)
            .unwrap();
    assert_eq!(worker.process_generation(), 1);
    worker.shutdown();
    worker.verify_block(&block).unwrap();
    assert_eq!(worker.process_generation(), 2);
}

#[cfg(not(feature = "production-v3"))]
#[test]
fn authenticated_private_copy_survives_original_removal_across_restart() {
    let files = TestArtifacts::create();
    let original = PathBuf::from(env!("CARGO_BIN_EXE_cmfd-proof-worker"));
    let copied_original = files
        .root
        .join(format!("packaged-worker{}", std::env::consts::EXE_SUFFIX));
    fs::copy(&original, &copied_original).unwrap();
    let copied_original = fs::canonicalize(copied_original).unwrap();
    let mut config = worker_config();
    config.worker_sha256 = sha256(&copied_original);
    config.worker_executable = copied_original.clone();
    let (verifier, block) = candidate_block();
    let worker =
        PersistentVerifierWorker::start(config, verifier, block.challenge.network_id).unwrap();

    fs::remove_file(copied_original).unwrap();
    worker.shutdown();
    worker.verify_block(&block).unwrap();
    assert_eq!(worker.process_generation(), 2);
}

#[test]
fn shutdown_racing_restart_remains_fail_closed_and_recoverable() {
    let (verifier, block) = candidate_block();
    let worker =
        PersistentVerifierWorker::start(worker_config(), verifier, block.challenge.network_id)
            .unwrap();
    let mut observed_cancelled_restart = false;
    for _ in 0..32 {
        worker.shutdown();
        let previous_attempts = worker.process_attempts();
        let contender = worker.clone();
        let candidate = block.clone();
        let request = std::thread::spawn(move || contender.verify_block(&candidate));

        let deadline = Instant::now() + Duration::from_secs(5);
        while worker.process_attempts() == previous_attempts
            && !request.is_finished()
            && Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        if request.is_finished() {
            let _ = request.join().expect("verification thread must not panic");
            continue;
        }
        assert!(
            worker.process_attempts() > previous_attempts,
            "restart attempt must become observable before the test deadline"
        );
        worker.shutdown();
        request
            .join()
            .expect("verification thread must not panic")
            .expect_err("shutdown overlapping a restart must cancel that request");
        observed_cancelled_restart = true;
        break;
    }
    assert!(
        observed_cancelled_restart,
        "test must observe and cancel an in-flight restart"
    );
    worker.shutdown();
    worker.verify_block(&block).unwrap();
}

#[test]
fn timed_out_generation_is_killed_and_the_next_request_starts_fresh() {
    let (verifier, block) = candidate_block();
    let mut config = worker_config();
    config.timeout = Duration::from_nanos(1);
    let worker =
        PersistentVerifierWorker::start(config, verifier, block.challenge.network_id).unwrap();

    for expected_generation in [1, 2] {
        let error = worker
            .verify_block(&block)
            .expect_err("a one-nanosecond request deadline must fail closed");
        assert!(matches!(
            error,
            VerifierWorkerError::Process(cmfd_proof_worker::ProofWorkerError::Timeout { .. })
        ));
        assert_eq!(worker.process_generation(), expected_generation);
    }
}

fn terminate_process(pid: u32) {
    let pid = pid.to_string();
    #[cfg(windows)]
    let status = Command::new("taskkill")
        .args(["/PID", &pid, "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    #[cfg(unix)]
    let status = Command::new("kill").args(["-KILL", &pid]).status().unwrap();
    assert!(status.success());
}
