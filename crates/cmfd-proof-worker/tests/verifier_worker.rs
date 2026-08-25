use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cmfd_consensus::{
    BLOCK_VERSION, Block, BlockChallenge, BlockProof, Coinbase, ConsensusPowVerifier,
    v2_test_reference,
};
use cmfd_proof_worker::{VerifierWorkerConfig, VerifierWorkerError, verify_block_out_of_process};
use sha2::{Digest, Sha256};

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
