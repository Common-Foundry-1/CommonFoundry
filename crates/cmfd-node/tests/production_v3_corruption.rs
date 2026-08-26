#![cfg(feature = "production-v3")]

//! Manual ProductionV3 block-admission qualification.
//!
//! This ignored test consumes an exact canonical block captured from the
//! miner. It admits that block on one fresh node, then flips one byte in the
//! CP02 structured proof and proves that a second fresh node rejects the
//! still-canonical block without advancing its chain.
//!
//! Exactly one block source:
//! - `CMFD_V3_QUALIFICATION_BLOCK`, or
//! - `CMFD_V3_QUALIFICATION_SOURCE_NODE_DIR` (the stopped mined node)
//!
//! Required environment variables:
//! - `CMFD_V3_QUALIFICATION_WORKER`
//! - `CMFD_V3_QUALIFICATION_BANK`
//! - `CMFD_V3_QUALIFICATION_MANIFEST`
//! - `CMFD_V3_QUALIFICATION_RECORD_V2`
//!
//! The worker limits default to the node CLI defaults. Override them with
//! `CMFD_V3_QUALIFICATION_MEMORY_BYTES`,
//! `CMFD_V3_QUALIFICATION_STARTUP_TIMEOUT_MS`, and
//! `CMFD_V3_QUALIFICATION_PROOF_TIMEOUT_MS`. Linux additionally accepts
//! `CMFD_V3_QUALIFICATION_CPU_QUOTA_US`,
//! `CMFD_V3_QUALIFICATION_CPU_PERIOD_US`, and
//! `CMFD_V3_QUALIFICATION_PIDS_LIMIT`.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cmfd_consensus::dory_bls12_381_candidate::BlsDoryV3CandidatePayload;
use cmfd_consensus::{Block, BlockProof, decode_block, encode_block};
use cmfd_node::{
    COMPILED_NETWORK_PROFILE, Node, NodeError, ProductionV3VerifierArtifacts, ProofProfile,
    compiled_production_v3_worker_sha256, submit_shared_block,
};
use cmfd_proof_worker::{VerifierWorkerConfig, VerifierWorkerError};

const CP02_MAGIC: &[u8; 8] = b"CFV3CP02";
const DEFAULT_STARTUP_TIMEOUT_MS: u64 = 900_000;
const DEFAULT_PROOF_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 2_147_483_648;
#[cfg(target_os = "linux")]
const DEFAULT_LINUX_CPU_QUOTA_US: u64 = 100_000;
#[cfg(target_os = "linux")]
const DEFAULT_LINUX_CPU_PERIOD_US: u64 = 100_000;
#[cfg(target_os = "linux")]
const DEFAULT_LINUX_PIDS_LIMIT: u64 = 16;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct QualificationDirectory(PathBuf);

impl QualificationDirectory {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!(
            "cmfd-production-v3-corruption-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create isolated ProductionV3 qualification directory");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for QualificationDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn canonical_regular_file(variable: &str, configured: PathBuf) -> PathBuf {
    let canonical = fs::canonicalize(&configured)
        .unwrap_or_else(|error| panic!("canonicalize {variable} ({configured:?}): {error}"));
    assert!(
        canonical.is_file(),
        "{variable} does not identify a regular file: {canonical:?}"
    );
    canonical
}

fn required_file(variable: &str) -> PathBuf {
    let configured = std::env::var_os(variable)
        .unwrap_or_else(|| panic!("{variable} must name an existing regular file"));
    canonical_regular_file(variable, PathBuf::from(configured))
}

fn required_directory(variable: &str, configured: PathBuf) -> PathBuf {
    let canonical = fs::canonicalize(&configured)
        .unwrap_or_else(|error| panic!("canonicalize {variable} ({configured:?}): {error}"));
    assert!(
        canonical.is_dir(),
        "{variable} does not identify a directory: {canonical:?}"
    );
    canonical
}

fn configured_u64(variable: &str, default: u64) -> u64 {
    match std::env::var(variable) {
        Ok(value) => value
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{variable} must be an unsigned decimal integer")),
        Err(std::env::VarError::NotPresent) => default,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{variable} must contain Unicode decimal digits")
        }
    }
}

fn qualification_artifacts() -> ProductionV3VerifierArtifacts {
    ProductionV3VerifierArtifacts {
        bank: required_file("CMFD_V3_QUALIFICATION_BANK"),
        manifest: required_file("CMFD_V3_QUALIFICATION_MANIFEST"),
        record_v2: required_file("CMFD_V3_QUALIFICATION_RECORD_V2"),
    }
}

fn qualification_worker_config(artifacts: &ProductionV3VerifierArtifacts) -> VerifierWorkerConfig {
    #[cfg(target_os = "linux")]
    let (cpu_quota_micros, cpu_period_micros, pids_limit) = (
        Some(configured_u64(
            "CMFD_V3_QUALIFICATION_CPU_QUOTA_US",
            DEFAULT_LINUX_CPU_QUOTA_US,
        )),
        Some(configured_u64(
            "CMFD_V3_QUALIFICATION_CPU_PERIOD_US",
            DEFAULT_LINUX_CPU_PERIOD_US,
        )),
        Some(configured_u64(
            "CMFD_V3_QUALIFICATION_PIDS_LIMIT",
            DEFAULT_LINUX_PIDS_LIMIT,
        )),
    );
    #[cfg(not(target_os = "linux"))]
    let (cpu_quota_micros, cpu_period_micros, pids_limit) = (None, None, None);

    VerifierWorkerConfig {
        worker_executable: required_file("CMFD_V3_QUALIFICATION_WORKER"),
        worker_sha256: compiled_production_v3_worker_sha256()
            .expect("the test build must contain a nonzero ProductionV3 worker pin"),
        startup_timeout: Duration::from_millis(configured_u64(
            "CMFD_V3_QUALIFICATION_STARTUP_TIMEOUT_MS",
            DEFAULT_STARTUP_TIMEOUT_MS,
        )),
        timeout: Duration::from_millis(configured_u64(
            "CMFD_V3_QUALIFICATION_PROOF_TIMEOUT_MS",
            DEFAULT_PROOF_TIMEOUT_MS,
        )),
        memory_limit_bytes: configured_u64(
            "CMFD_V3_QUALIFICATION_MEMORY_BYTES",
            DEFAULT_MEMORY_LIMIT_BYTES,
        ),
        cpu_quota_micros,
        cpu_period_micros,
        pids_limit,
        production_v3_artifacts: Some(artifacts.clone()),
    }
}

fn decode_canonical_first_block(bytes: Vec<u8>) -> (Block, Vec<u8>) {
    let block = decode_block(&bytes, COMPILED_NETWORK_PROFILE.network_id)
        .expect("decode captured ProductionV3 block");
    assert_eq!(
        encode_block(&block).expect("re-encode captured ProductionV3 block"),
        bytes,
        "captured block is not its exact canonical wire encoding"
    );
    assert_eq!(
        block.challenge.network_id, COMPILED_NETWORK_PROFILE.network_id,
        "captured block belongs to another network"
    );
    assert_eq!(
        block.challenge.previous_block, COMPILED_NETWORK_PROFILE.virtual_genesis_hash,
        "the clean-node qualification requires the captured height-one block"
    );
    assert_eq!(
        block.challenge.height, 1,
        "the clean-node qualification requires the captured height-one block"
    );
    assert!(
        matches!(block.proof, BlockProof::V3Candidate(_)),
        "captured block does not contain a ProductionV3 proof"
    );
    (block, bytes)
}

fn load_source_node_block(
    source_directory: PathBuf,
    artifacts: &ProductionV3VerifierArtifacts,
    worker: VerifierWorkerConfig,
) -> Vec<u8> {
    let source_directory =
        required_directory("CMFD_V3_QUALIFICATION_SOURCE_NODE_DIR", source_directory);
    let mut source = Node::open_with_artifacts_and_verifier_worker(
        &source_directory,
        Some(artifacts),
        worker,
    )
    .unwrap_or_else(|error| {
        panic!(
            "open stopped mined source node {source_directory:?} with the pinned worker: {error}"
        )
    });
    let status = source.status().expect("read stopped source-node status");
    assert_eq!(
        status.accepted_height, 1,
        "source node tip must be the captured height-one block"
    );
    assert_eq!(
        status.next_height, 2,
        "source node must end after height one"
    );
    let tip: [u8; 32] = hex::decode(&status.tip)
        .expect("source-node tip must be hexadecimal")
        .try_into()
        .expect("source-node tip must be exactly 32 bytes");
    let canonical = source
        .canonical_block(tip)
        .expect("read source-node canonical block")
        .expect("source-node tip must have a retained canonical block");
    source.shutdown_proof_verifier();
    drop(source);
    canonical
}

fn load_qualification_block(
    artifacts: &ProductionV3VerifierArtifacts,
    worker: &VerifierWorkerConfig,
) -> (Block, Vec<u8>) {
    let bytes = match (
        std::env::var_os("CMFD_V3_QUALIFICATION_BLOCK"),
        std::env::var_os("CMFD_V3_QUALIFICATION_SOURCE_NODE_DIR"),
    ) {
        (Some(block), None) => {
            let block = canonical_regular_file("CMFD_V3_QUALIFICATION_BLOCK", PathBuf::from(block));
            fs::read(block).expect("read captured ProductionV3 block")
        }
        (None, Some(source)) => {
            load_source_node_block(PathBuf::from(source), artifacts, worker.clone())
        }
        (Some(_), Some(_)) => panic!(
            "set exactly one of CMFD_V3_QUALIFICATION_BLOCK or CMFD_V3_QUALIFICATION_SOURCE_NODE_DIR"
        ),
        (None, None) => {
            panic!("set CMFD_V3_QUALIFICATION_BLOCK or CMFD_V3_QUALIFICATION_SOURCE_NODE_DIR")
        }
    };
    decode_canonical_first_block(bytes)
}

fn mutate_one_cp02_payload_byte(bytes: &[u8]) -> Vec<u8> {
    assert!(
        bytes.starts_with(CP02_MAGIC),
        "structured proof is not a CP02 envelope"
    );
    assert!(
        bytes.len() > CP02_MAGIC.len(),
        "CP02 envelope has no payload byte to mutate"
    );
    let mut mutated = bytes.to_vec();
    let payload_index = mutated.len() - 1;
    mutated[payload_index] ^= 1;
    assert_eq!(
        bytes
            .iter()
            .zip(&mutated)
            .filter(|(left, right)| left != right)
            .count(),
        1,
        "CP02 mutation must change exactly one byte"
    );
    mutated
}

fn corrupt_structured_proof(block: &Block) -> (Block, Vec<u8>) {
    let mut corrupted = block.clone();
    let BlockProof::V3Candidate(proof) = &mut corrupted.proof else {
        panic!("captured block does not contain a ProductionV3 proof");
    };
    let original_proof_length = proof.structured_proof.len();
    proof.structured_proof = mutate_one_cp02_payload_byte(&proof.structured_proof);
    assert_eq!(proof.structured_proof.len(), original_proof_length);
    let decoded_payload = BlsDoryV3CandidatePayload::decode(&proof.structured_proof)
        .expect("one-byte mutation must preserve the nested CP02 envelope");
    assert_eq!(
        decoded_payload
            .encode()
            .expect("re-encode the one-byte-mutated CP02 envelope"),
        proof.structured_proof,
        "one-byte-mutated CP02 envelope must remain canonical"
    );

    let encoded = encode_block(&corrupted).expect("encode one-byte-corrupted block");
    let decoded = decode_block(&encoded, COMPILED_NETWORK_PROFILE.network_id)
        .expect("one-byte-corrupted block must preserve canonical wire framing");
    assert_eq!(decoded, corrupted);
    (decoded, encoded)
}

fn stop_node(node: Arc<Mutex<Node>>) {
    node.lock()
        .expect("lock qualification node for shutdown")
        .shutdown_proof_verifier();
    drop(node);
}

#[test]
fn cp02_mutation_changes_exactly_one_payload_byte() {
    let original = b"CFV3CP02deterministic-proof-payload";
    let mutated = mutate_one_cp02_payload_byte(original);
    assert_eq!(original.len(), mutated.len());
    assert_eq!(&mutated[..CP02_MAGIC.len()], CP02_MAGIC);
    assert_eq!(
        original
            .iter()
            .zip(&mutated)
            .filter(|(left, right)| left != right)
            .count(),
        1
    );
}

#[test]
#[ignore = "requires the pinned ProductionV3 worker, full model artifacts, and a captured height-one block"]
fn valid_block_advances_one_clean_node_and_one_byte_cp02_corruption_does_not() {
    assert_eq!(
        COMPILED_NETWORK_PROFILE.proof,
        ProofProfile::ProductionV3,
        "run this qualification only in the isolated ProductionV3 test build"
    );

    let artifacts = qualification_artifacts();
    let worker = qualification_worker_config(&artifacts);
    let (valid_block, canonical_valid_block) = load_qualification_block(&artifacts, &worker);
    let (corrupted_block, canonical_corrupted_block) = corrupt_structured_proof(&valid_block);
    assert_eq!(canonical_valid_block.len(), canonical_corrupted_block.len());
    assert_eq!(
        canonical_valid_block
            .iter()
            .zip(&canonical_corrupted_block)
            .filter(|(left, right)| left != right)
            .count(),
        1,
        "canonical block framing must differ only at the selected CP02 payload byte"
    );

    let directories = QualificationDirectory::create();
    let accepted_at = valid_block.challenge.timestamp;

    let valid_node = Arc::new(Mutex::new(
        Node::open_with_artifacts_and_verifier_worker(
            directories.join("valid-node"),
            Some(&artifacts),
            worker.clone(),
        )
        .expect("open clean ProductionV3 node for the exact valid block"),
    ));
    let fees = submit_shared_block(&valid_node, valid_block.clone(), accepted_at)
        .expect("the exact captured ProductionV3 block must be accepted");
    {
        let mut node = valid_node.lock().expect("lock valid qualification node");
        let status = node.status().expect("read valid-node status");
        assert_eq!(status.accepted_height, valid_block.challenge.height);
        assert_eq!(status.next_height, valid_block.challenge.height + 1);
        assert_eq!(status.tip, hex::encode(valid_block.block_id()));
        assert_eq!(
            node.canonical_block(valid_block.block_id())
                .expect("read retained valid block")
                .expect("valid block must be retained"),
            canonical_valid_block,
            "the node must retain the exact miner-supplied canonical block"
        );
    }
    eprintln!(
        "PRODUCTION_V3_VALID_BLOCK_ACCEPTED height={} fees={fees}",
        valid_block.challenge.height
    );
    stop_node(valid_node);

    let corrupted_data_dir = directories.join("corrupted-node");
    let corrupted_node = Arc::new(Mutex::new(
        Node::open_with_artifacts_and_verifier_worker(
            &corrupted_data_dir,
            Some(&artifacts),
            worker.clone(),
        )
        .expect("open independent clean ProductionV3 node for the corrupted block"),
    ));
    let before = {
        let node = corrupted_node
            .lock()
            .expect("lock corrupted qualification node before submission");
        let status = node.status().expect("read pre-submission status");
        (
            status.accepted_height,
            status.next_height,
            status.tip,
            status.cumulative_work,
            status.utxo_count,
            status.mempool_transactions,
            status.mempool_bytes,
        )
    };
    assert_eq!(before.0, 0);
    assert_eq!(before.1, 1);
    assert_eq!(
        before.2,
        hex::encode(COMPILED_NETWORK_PROFILE.virtual_genesis_hash)
    );
    assert!(before.3.bytes().all(|byte| byte == b'0'));
    assert_eq!((before.4, before.5, before.6), (0, 0, 0));
    let error = submit_shared_block(&corrupted_node, corrupted_block.clone(), accepted_at)
        .expect_err("the one-byte-corrupted CP02 proof must be rejected");
    assert!(
        matches!(
            &error,
            NodeError::ProofVerifierWorker(VerifierWorkerError::ProofRejected(_))
        ),
        "the still-canonical block must be rejected by the ProductionV3 worker: {error}"
    );
    {
        let node = corrupted_node
            .lock()
            .expect("lock corrupted qualification node after rejection");
        let status = node.status().expect("read post-rejection status");
        let after = (
            status.accepted_height,
            status.next_height,
            status.tip,
            status.cumulative_work,
            status.utxo_count,
            status.mempool_transactions,
            status.mempool_bytes,
        );
        assert_eq!(
            after, before,
            "rejected proof changed the clean chain state"
        );
        assert!(
            !node.contains_block(corrupted_block.block_id()),
            "rejected corrupted block entered the block index"
        );
    }
    eprintln!(
        "PRODUCTION_V3_CORRUPTED_PROOF_REJECTED height_unchanged={}",
        before.0
    );
    stop_node(corrupted_node);

    let reopened_node = Arc::new(Mutex::new(
        Node::open_with_artifacts_and_verifier_worker(
            &corrupted_data_dir,
            Some(&artifacts),
            worker,
        )
        .expect("reopen the corrupted-proof node with the same pinned worker and artifacts"),
    ));
    {
        let node = reopened_node
            .lock()
            .expect("lock reopened corrupted-proof node");
        let status = node.status().expect("read reopened node status");
        let after_restart = (
            status.accepted_height,
            status.next_height,
            status.tip,
            status.cumulative_work,
            status.utxo_count,
            status.mempool_transactions,
            status.mempool_bytes,
        );
        assert_eq!(
            after_restart, before,
            "rejected proof changed durable genesis state"
        );
        assert!(node.contains_block(COMPILED_NETWORK_PROFILE.virtual_genesis_hash));
        assert!(!node.contains_block(corrupted_block.block_id()));
        assert!(!node.contains_block(valid_block.block_id()));
    }
    stop_node(reopened_node);
}
