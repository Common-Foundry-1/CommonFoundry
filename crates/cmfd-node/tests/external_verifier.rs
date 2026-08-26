use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cmfd_consensus::{
    BLOCK_VERSION, Block, BlockChallenge, BlockProof, Coinbase, ConsensusPowVerifier,
    v2_test_reference,
};
use cmfd_node::{
    DEFAULT_MINING_ATTEMPTS, DEVNET_GENESIS_TIMESTAMP, MAX_CONCURRENT_PROOF_VERIFICATIONS,
    MAX_PRIORITY_QUEUED_PROOF_VERIFICATIONS, MAX_QUEUED_PROOF_VERIFICATIONS, Node,
};
use cmfd_proof_worker::VerifierWorkerConfig;
use sha2::{Digest, Sha256};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    let worker = PathBuf::from(env!("CARGO_BIN_EXE_cmfd-node"));
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

fn candidate_block() -> Block {
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
    Block {
        version: BLOCK_VERSION,
        challenge,
        proof,
        coinbase: Coinbase {
            height: 1,
            outputs: Vec::new(),
        },
        transactions: Vec::new(),
    }
}

fn temporary_data_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "cmfd-node-external-verifier-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn node_admission_uses_the_pinned_worker_and_reports_its_limits() {
    let data_dir = temporary_data_dir();
    let mut node = Node::open(&data_dir).unwrap();
    let mut wrong_pin = worker_config();
    wrong_pin.worker_sha256[0] ^= 1;
    let error = node.use_external_proof_verifier(wrong_pin).unwrap_err();
    assert_eq!(error.client_error().code, "proof_verifier_configuration");
    assert_eq!(node.status().unwrap().proof_verification_mode, "in_process");

    node.use_external_proof_verifier(worker_config()).unwrap();
    let status = node.status().unwrap();
    assert_eq!(status.proof_verification_mode, "external_worker");
    assert_eq!(status.proof_verification_timeout_ms, Some(10_000));
    assert_eq!(
        status.proof_verification_capacity,
        MAX_CONCURRENT_PROOF_VERIFICATIONS
    );
    assert_eq!(
        status.proof_verification_queue_capacity,
        MAX_QUEUED_PROOF_VERIFICATIONS + MAX_PRIORITY_QUEUED_PROOF_VERIFICATIONS
    );
    assert_eq!(
        status.proof_verification_memory_limit_bytes,
        Some(512 * 1024 * 1024)
    );
    assert_eq!(status.proof_verification_teardown_failures, Some(0));

    let block = candidate_block();
    node.block_preverifier().preverify(&block).unwrap();

    let mut invalid = block;
    let BlockProof::V2Reference(proof) = &mut invalid.proof else {
        unreachable!();
    };
    proof.work_digest[0] ^= 1;
    let error = node.block_preverifier().preverify(&invalid).unwrap_err();
    assert_eq!(error.client_error().code, "proof_rejected");

    drop(node);
    fs::remove_dir_all(data_dir).unwrap();
}

#[test]
fn verifier_worker_starts_before_restart_replay_and_restores_the_chain() {
    let data_dir = temporary_data_dir();
    let (tip, height) = {
        let mut node = Node::open(&data_dir).unwrap();
        node.mine_once(
            node.wallet_destination(),
            DEVNET_GENESIS_TIMESTAMP + 60,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        node.mine_once(
            node.wallet_destination(),
            DEVNET_GENESIS_TIMESTAMP + 120,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        let status = node.status().unwrap();
        (status.tip, status.accepted_height)
    };

    let node =
        Node::open_with_artifacts_and_verifier_worker(&data_dir, None, worker_config()).unwrap();
    let status = node.status().unwrap();
    assert_eq!(status.tip, tip);
    assert_eq!(status.accepted_height, height);
    assert_eq!(status.proof_verification_mode, "external_worker");

    drop(node);
    fs::remove_dir_all(data_dir).unwrap();
}
