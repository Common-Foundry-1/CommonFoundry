//! Operator-invoked CPU-only read-cost qualification using preserved real V4 inputs.
//! No listener or miner is started. The temporary node uses RCNet, never mainnet.

use std::env;
use std::hint::black_box;
use std::time::Instant;

use cmfd_consensus::ForgeMatrixV4CandidateProof;
use sha2::{Digest, Sha256};

use crate::tests::{clean_test_dir, test_dir};
use crate::*;

fn input(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("operator must set {name}")));
    assert!(
        path.is_absolute(),
        "qualification inputs must use absolute paths"
    );
    path
}

fn hash(value: &serde_json::Value) -> [u8; 32] {
    hex::decode(value.as_str().expect("statement hash is a hex string"))
        .unwrap()
        .try_into()
        .expect("statement hash must contain32bytes")
}

#[test]
#[ignore = "requires explicitly selected preserved full proof, statement, candidate and pinned model inputs; CPU only"]
fn preserved_full_v4_explorer_read_cost() {
    let proof_path = input("CMFD_EXPLORER_FULL_PROOF");
    let proof = fs::read(&proof_path).unwrap();
    let proof_sha256 = hex::encode(Sha256::digest(&proof));
    assert_eq!(
        proof_sha256,
        env::var("CMFD_EXPLORER_FULL_PROOF_SHA256").expect("operator must pin proof bytes")
    );
    assert_eq!(
        proof.len(),
        cmfd_consensus::forgematrix_v4_proof_codec::FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES
    );
    let statement: serde_json::Value =
        serde_json::from_slice(&fs::read(input("CMFD_EXPLORER_STATEMENT")).unwrap()).unwrap();
    let candidate: serde_json::Value =
        serde_json::from_slice(&fs::read(input("CMFD_EXPLORER_CANDIDATE")).unwrap()).unwrap();
    assert_eq!(
        statement["schema"],
        "CommonFoundry/ForgeMatrix/V4/IndependentVerifierInput/v1"
    );
    assert_eq!(candidate["format_version"], 1);
    let public = &statement["candidate"];
    let block = Block {
        version: BLOCK_VERSION,
        challenge: serde_json::from_value(candidate["challenge"].clone()).unwrap(),
        coinbase: serde_json::from_value(candidate["coinbase"].clone()).unwrap(),
        transactions: serde_json::from_value(candidate["transactions"].clone()).unwrap(),
        proof: BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
            algorithm_version: public["algorithm_version"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            proof_version: public["proof_version"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            nonce: public["nonce"].as_u64().unwrap(),
            proof_system_digest: hash(&public["proof_system_digest"]),
            model_manifest_digest: hash(&public["model_manifest_digest"]),
            challenge_digest: hash(&public["challenge_digest"]),
            final_activation_digest: hash(&public["final_activation_digest"]),
            work_digest: hash(&public["work_digest"]),
            transparent_proof: proof,
        })),
    };
    assert_eq!(candidate["nonce"], public["nonce"]);
    assert_eq!(block.challenge.network_id, RCNET1_PROFILE.network_id);
    assert_eq!(
        block.challenge.network_id,
        hash(&statement["block"]["network_id"])
    );
    assert_eq!(
        block.challenge.previous_block,
        hash(&statement["block"]["previous_block"])
    );
    assert_eq!(
        block.challenge.transaction_root,
        hash(&statement["block"]["transaction_root"])
    );
    assert_eq!(block.challenge.target, hash(&statement["block"]["target"]));
    assert_eq!(
        block.challenge.height,
        statement["block"]["height"].as_u64().unwrap()
    );
    assert_eq!(
        block.challenge.timestamp,
        statement["block"]["timestamp"].as_u64().unwrap()
    );
    let mut commitments = vec![block.coinbase.commitment(block.challenge.network_id)];
    commitments.extend(block.transactions.iter().map(Transaction::txid));
    assert_eq!(merkle_root(&commitments), block.challenge.transaction_root);

    let artifacts = ProductionV4VerifierArtifacts {
        bank: input("CMFD_EXPLORER_BANK"),
        fixed_record: input("CMFD_EXPLORER_FIXED_RECORD"),
    };
    let path = test_dir("preserved-v4-explorer-resource");
    let opening = Instant::now();
    println!(
        "FULL_V4_RESOURCE_STAGE opening pinned CPU verifier and isolated RCNet data directory"
    );
    let mut node = Node::open_with_profile_artifacts_and_worker(
        &path,
        RCNET1_PROFILE,
        None,
        None,
        Some(&artifacts),
        None,
        Some(b"isolated-read-cost-fixture-not-a-real-wallet"),
    )
    .unwrap();
    let open_ms = opening.elapsed().as_millis();
    println!(
        "FULL_V4_RESOURCE_STAGE submitting preserved block through normal CPU consensus validation"
    );
    let admission = Instant::now();
    node.submit_block(block.clone(), block.challenge.timestamp)
        .unwrap();
    let admission_ms = admission.elapsed().as_millis();
    let block_id = block.block_id();
    let encoded_bytes = encode_block(&block).unwrap().len();
    let OutputLock::Key(address) = block.coinbase.outputs[0].lock else {
        panic!("fixture must contain a key reward")
    };
    let block_query = hex::encode(block_id);
    let address_query = hex::encode(address);

    const ITERATIONS: usize = 10;
    let reads = node.explorer_block_reads;
    let read_start = Instant::now();
    for _ in 0..ITERATIONS {
        let detail = node.explorer_block(&block_query).unwrap().unwrap();
        assert_eq!(detail.block.block_id, block_query);
        assert_eq!(detail.block.encoded_bytes, encoded_bytes);
        black_box(detail);
    }
    let block_reads_us = read_start.elapsed().as_micros();
    assert_eq!(node.explorer_block_reads - reads, ITERATIONS);
    let reads = node.explorer_block_reads;
    let address_start = Instant::now();
    for _ in 0..ITERATIONS {
        let page = node.explorer_address(&address_query, None).unwrap();
        assert_eq!(page.history.len(), 1);
        assert_eq!(page.history[0].block_id, block_query);
        assert_eq!(page.history[0].kind, "coinbase");
        black_box(page);
    }
    let address_reads_us = address_start.elapsed().as_micros();
    assert_eq!(node.explorer_block_reads - reads, ITERATIONS);
    let identity_start = Instant::now();
    for _ in 0..20 {
        assert_eq!(black_box(block.block_id()), block_id);
    }
    let repeated_identity_us = identity_start.elapsed().as_micros();
    let checked = node.read_explorer_block(block_id).unwrap();
    assert_eq!(checked.encoded_bytes(), encoded_bytes);
    let checked_identity_start = Instant::now();
    for _ in 0..20 {
        assert_eq!(black_box(checked.block_id()), block_id);
    }
    let checked_identity_ns = checked_identity_start.elapsed().as_nanos();
    let checkpoint_start = Instant::now();
    let restored = crate::startup_snapshot::load_startup_snapshot(
        &path,
        &node.log,
        &path.join(BLOCK_LOG_FILE),
        node.params,
        &node.verifier,
    )
    .unwrap()
    .expect("normal full-proof admission must leave an eligible checkpoint");
    assert_eq!(
        restored.state.encode_local_snapshot().unwrap(),
        node.state.encode_local_snapshot().unwrap()
    );
    assert_eq!(restored.index.active_chain, node.index.active_chain);
    assert_eq!(restored.index.active_work, node.index.active_work);
    assert_eq!(
        restored.index.blocks[&block_id].locator,
        node.index.blocks[&block_id].locator
    );
    let checkpoint_scan_ms = checkpoint_start.elapsed().as_millis();
    drop(restored);
    println!(
        "FULL_V4_EXPLORER_READ_COST {}",
        serde_json::json!({
            "scope": "isolated preserved RCNet block; CPU consensus acceptance and method-level read cost, not live mainnet or HTTP throughput",
            "os": env::consts::OS, "proof_sha256": proof_sha256, "encoded_block_bytes": encoded_bytes,
            "block_id": block_query, "isolated_rc_block_accepted": true, "mainnet_started": false,
            "network_service_started": false, "gpu_work_performed": false, "new_proof_generated": false,
            "debug_assertions": cfg!(debug_assertions), "verifier_open_ms": open_ms, "consensus_admission_ms": admission_ms,
            "iterations": ITERATIONS, "block_detail_total_us": block_reads_us,
        "address_detail_total_us": address_reads_us, "twenty_block_id_hashes_us": repeated_identity_us,
        "twenty_authenticated_id_accesses_ns": checked_identity_ns,
        "checkpoint_state_matched": true, "checkpoint_scan_ms": checkpoint_scan_ms,
        "checkpoint_scope": "one full-size block with already initialized CPU verifier; not process startup or fork-history qualification",
        })
    );
    drop(node);
    clean_test_dir(&path);
}
