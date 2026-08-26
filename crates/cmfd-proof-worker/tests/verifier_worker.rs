#[cfg(any(not(feature = "production-v3"), target_os = "linux"))]
use std::fs;
use std::fs::File;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(any(windows, target_os = "linux"))]
use std::process::Stdio;
#[cfg(any(not(feature = "production-v3"), target_os = "linux"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use std::{ffi::CString, os::unix::ffi::OsStrExt, os::unix::fs::PermissionsExt};

use cmfd_consensus::{
    BLOCK_VERSION, Block, BlockChallenge, BlockProof, Coinbase, ConsensusPowVerifier, TEST_PROFILE,
    v2_test_reference,
};
#[cfg(not(feature = "production-v3"))]
use cmfd_proof_worker::ProductionV3VerifierArtifacts;
use cmfd_proof_worker::{
    PersistentVerifierWorker, VerifierWorkerConfig, VerifierWorkerError,
    verify_block_out_of_process,
};
use sha2::{Digest, Sha256};

#[cfg(any(not(feature = "production-v3"), target_os = "linux"))]
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
        cpu_quota_micros: Some(100_000),
        cpu_period_micros: Some(100_000),
        pids_limit: Some(16),
        production_v3_artifacts: None,
    }
}

fn wait_until_ready(worker: &PersistentVerifierWorker) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !worker.is_ready() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        worker.is_ready(),
        "supervised verifier restart did not authenticate before the test deadline"
    );
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
fn verifier_worker_rejects_a_nonempty_environment() {
    let output = Command::new(env!("CARGO_BIN_EXE_cmfd-proof-worker"))
        .arg("--verify-block-server")
        .env_clear()
        .env("CMFD_FORBIDDEN_WORKER_ENVIRONMENT", "sentinel")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        output
            .stdout
            .windows(b"verifier worker environment must be empty".len())
            .any(|window| window == b"verifier worker environment must be empty")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_production_sandbox_installs_in_a_single_task_worker_image() {
    let root = std::env::temp_dir().join(format!(
        "cmfd-linux-sandbox-image-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let artifact_directory = root.join("artifacts");
    fs::create_dir_all(&artifact_directory).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&artifact_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let artifacts = ["bank", "manifest", "record"].map(|name| {
        let path = artifact_directory.join(name);
        fs::write(&path, b"artifact").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path.canonicalize().unwrap()
    });

    let run_as_nobody = unsafe { libc::geteuid() } == 0;
    if run_as_nobody {
        for path in artifacts
            .iter()
            .map(PathBuf::as_path)
            .chain([artifact_directory.as_path(), root.as_path()])
        {
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(path.as_ptr(), 65_534, 65_534) }, 0);
        }
    }

    let mut command = Command::new(env!("CARGO_BIN_EXE_cmfd-proof-worker"));
    command
        .arg("--cmfd-internal-linux-sandbox-diagnostic")
        .args(&artifacts)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if run_as_nobody {
        unsafe {
            command.pre_exec(|| {
                if libc::syscall(
                    libc::SYS_setgroups,
                    0_usize,
                    std::ptr::null::<libc::gid_t>(),
                ) != 0
                    || libc::syscall(libc::SYS_setresgid, 65_534_u32, 65_534_u32, 65_534_u32) != 0
                    || libc::syscall(libc::SYS_setresuid, 65_534_u32, 65_534_u32, 65_534_u32) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "single-task sandbox diagnostic failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    fs::remove_dir_all(root).unwrap();
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
fn persistent_worker_rejection_is_request_scoped_without_poisoning_the_generation() {
    let (verifier, mut block) = candidate_block();
    let worker =
        PersistentVerifierWorker::start(worker_config(), verifier, block.challenge.network_id)
            .unwrap();
    let BlockProof::V2Reference(proof) = &mut block.proof else {
        unreachable!();
    };
    proof.work_digest[0] ^= 1;
    let error = worker
        .verify_block(&block)
        .expect_err("the worker must reject an invalid canonical proof");
    assert!(matches!(&error, VerifierWorkerError::ProofRejected(_)));
    assert!(error.is_dispatched_proof_failure());
    assert_eq!(worker.process_generation(), 1);
}

#[test]
fn persistent_predispatch_config_and_capability_failures_are_not_peer_attributed() {
    let (verifier, block) = candidate_block();
    let mut invalid_config = worker_config();
    invalid_config.timeout = Duration::ZERO;
    let error = PersistentVerifierWorker::start(
        invalid_config,
        verifier.clone(),
        block.challenge.network_id,
    )
    .err()
    .expect("zero request timeout must fail before worker startup");
    assert!(matches!(&error, VerifierWorkerError::InvalidConfig(_)));
    assert!(!error.is_dispatched_proof_failure());

    let worker =
        PersistentVerifierWorker::start(worker_config(), verifier, block.challenge.network_id)
            .unwrap();
    let legacy = ConsensusPowVerifier::v1_legacy(TEST_PROFILE).unwrap();
    let mut wrong_proof = block.clone();
    wrong_proof.proof = legacy.mine(&wrong_proof.challenge, 0, 1).unwrap();
    let error = worker
        .verify_block(&wrong_proof)
        .expect_err("wrong proof type must fail before request dispatch");
    assert!(matches!(&error, VerifierWorkerError::Capability(_)));
    assert!(!error.is_dispatched_proof_failure());
    assert_eq!(worker.process_generation(), 1);
    worker.verify_block(&block).unwrap();
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

#[cfg(windows)]
#[test]
fn production_v3_fails_before_copy_or_spawn_without_appcontainer() {
    let mut config = worker_config();
    config.worker_executable = PathBuf::from(r"C:\cmfd-sandbox-gate\missing-worker.exe");
    config.production_v3_artifacts = Some(cmfd_proof_worker::ProductionV3VerifierArtifacts {
        bank: PathBuf::from(r"C:\cmfd-sandbox-gate\bank"),
        manifest: PathBuf::from(r"C:\cmfd-sandbox-gate\manifest"),
        record_v2: PathBuf::from(r"C:\cmfd-sandbox-gate\record-v2"),
    });
    let (verifier, block) = candidate_block();
    let error = PersistentVerifierWorker::start(
        config.clone(),
        verifier.clone(),
        block.challenge.network_id,
    )
    .err()
    .expect("Windows ProductionV3 must fail before accessing the missing worker");
    assert!(matches!(error, VerifierWorkerError::SandboxUnavailable(_)));
    let error = verify_block_out_of_process(&config, &verifier, &block)
        .expect_err("one-shot Windows ProductionV3 must fail before accessing the missing worker");
    assert!(matches!(error, VerifierWorkerError::SandboxUnavailable(_)));
}

#[test]
fn crashed_persistent_worker_fails_the_request_then_restarts_authenticated() {
    let (verifier, block) = candidate_block();
    let worker =
        PersistentVerifierWorker::start(worker_config(), verifier, block.challenge.network_id)
            .unwrap();
    let pid = worker.process_id().expect("worker process must be running");
    terminate_process(pid);

    let error = worker
        .verify_block(&block)
        .expect_err("the request observing a crashed generation must fail closed");
    assert!(matches!(
        &error,
        VerifierWorkerError::DispatchedRequest(source)
            if matches!(
                source.as_ref(),
                VerifierWorkerError::Process(
                    cmfd_proof_worker::ProofWorkerError::Pipe { .. }
                        | cmfd_proof_worker::ProofWorkerError::WorkerExited { .. }
                )
            )
    ));
    assert!(error.is_dispatched_proof_failure());
    assert_eq!(worker.process_generation(), 1);
    let retry_started = Instant::now();
    assert!(matches!(
        worker.verify_block(&block),
        Err(VerifierWorkerError::Restarting)
    ));
    assert!(
        retry_started.elapsed() < Duration::from_secs(1),
        "a peer request synchronously waited for worker restart"
    );
    wait_until_ready(&worker);
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
    assert!(matches!(
        worker.verify_block(&block),
        Err(VerifierWorkerError::Restarting)
    ));
    wait_until_ready(&worker);
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
    wait_until_ready(&worker);
    worker.verify_block(&block).unwrap();
    assert_eq!(worker.process_generation(), 2);
}

#[test]
fn shutdown_racing_restart_remains_fail_closed_and_recoverable() {
    let (verifier, block) = candidate_block();
    let worker =
        PersistentVerifierWorker::start(worker_config(), verifier, block.challenge.network_id)
            .unwrap();
    worker.shutdown();
    let first_attempt = worker.process_attempts();
    let deadline = Instant::now() + Duration::from_secs(30);
    while worker.process_attempts() == first_attempt && Instant::now() < deadline {
        std::thread::yield_now();
    }
    worker.shutdown();
    assert!(matches!(
        worker.verify_block(&block),
        Err(VerifierWorkerError::Restarting)
    ));
    // If shutdown cancelled the already-running supervised attempt, this
    // probe schedules exactly one fresh attempt after it publishes
    // `Unavailable`.
    let retry_deadline = Instant::now() + Duration::from_secs(30);
    while !worker.is_ready() && Instant::now() < retry_deadline {
        let _ = worker.verify_block(&block);
        std::thread::sleep(Duration::from_millis(10));
    }
    wait_until_ready(&worker);
    worker.shutdown();
    wait_until_ready(&worker);
    worker.verify_block(&block).unwrap();
}

#[test]
fn concurrent_shutdown_and_close_are_single_flight_and_terminal() {
    const SHUTDOWN_CALLERS: usize = 16;

    let (verifier, block) = candidate_block();
    let worker =
        PersistentVerifierWorker::start(worker_config(), verifier, block.challenge.network_id)
            .unwrap();
    let initial_attempts = worker.process_attempts();
    let barrier = Arc::new(Barrier::new(SHUTDOWN_CALLERS + 1));
    let mut callers = Vec::new();
    for _ in 0..SHUTDOWN_CALLERS {
        let worker = worker.clone();
        let barrier = Arc::clone(&barrier);
        callers.push(std::thread::spawn(move || {
            barrier.wait();
            worker.shutdown();
        }));
    }

    barrier.wait();
    worker.close();
    for caller in callers {
        caller.join().unwrap();
    }
    let attempts_after_close = worker.process_attempts();
    assert!(
        attempts_after_close <= initial_attempts + 1,
        "concurrent shutdown scheduled more than one supervised generation"
    );
    assert!(!worker.is_ready());
    assert!(matches!(
        worker.verify_block(&block),
        Err(VerifierWorkerError::Closed)
    ));

    std::thread::sleep(Duration::from_millis(1_250));
    assert_eq!(
        worker.process_attempts(),
        attempts_after_close,
        "a supervisor resurrected or restarted after close"
    );
    assert!(!worker.is_ready());
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
            &error,
            VerifierWorkerError::DispatchedRequest(source)
                if matches!(
                    source.as_ref(),
                    VerifierWorkerError::Process(
                        cmfd_proof_worker::ProofWorkerError::Timeout { .. }
                    )
                )
        ));
        assert!(error.is_dispatched_proof_failure());
        assert_eq!(worker.process_generation(), expected_generation);
        wait_until_ready(&worker);
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
