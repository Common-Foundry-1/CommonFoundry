//! Ignored, explicitly opted-in full-size GPU proof/admission/restart check.
//! Uses isolated Testnet-1 identity with a distinct genesis and fingerprint.
//! No sockets, public peers, live wallets, mainnet pins, or mock proofs are used.

use super::*;
use crate::pool::{PoolJob, PoolWorkSearchResult, ProductionV4PoolShareVerifier};
use crate::production_v4_pool::{
    ProductionV4PersistentPoolVerifier, ProductionV4PoolVerifierConfig,
    ProductionV4PoolWorkerCommand,
};
use primitive_types::U256;

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).expect(name));
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn write_new(path: &Path, value: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(value).unwrap();
    file.sync_all().unwrap();
}

fn open_isolated(
    path: &Path,
    profile: NetworkProfile,
    artifacts: &ProductionV4VerifierArtifacts,
) -> Node {
    Node::open_with_profile_artifacts_and_worker(
        path,
        profile,
        None,
        None,
        Some(artifacts),
        None,
        None,
    )
    .unwrap()
}

#[test]
#[ignore = "requires exclusive GPU, authenticated 61 GB inputs and explicit empty output directory"]
fn real_5x_proofs_two_nodes_and_restart() {
    assert_eq!(
        std::env::var("CMFD_RUN_DIFFICULTY_GPU_REHEARSAL").as_deref(),
        Ok("1")
    );
    let root = required_path("CMFD_DIFFICULTY_REHEARSAL_ROOT");
    assert!(!root.exists(), "refusing existing output directory");
    fs::create_dir(&root).unwrap();
    let model = required_path("CMFD_DIFFICULTY_MODEL");
    let fixed = required_path("CMFD_DIFFICULTY_FIXED");
    let replay = required_path("CMFD_DIFFICULTY_REPLAY");
    let proof_worker = required_path("CMFD_DIFFICULTY_PROOF_WORKER");
    let artifacts = ProductionV4VerifierArtifacts {
        bank: model.clone(),
        fixed_record: fixed.join("FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"),
    };
    let rc_limit = ((U256::one() << 246) - U256::one()).to_big_endian();
    let initial = (((U256::one() << 246) / U256::from(5u8)) - U256::one()).to_big_endian();
    let mut profile = network_profile::PRODUCTION_V4_TESTNET_PROFILE;
    profile.pow_limit = rc_limit;
    profile.initial_target = Some(initial);
    profile.virtual_genesis_timestamp = unix_time_seconds().unwrap();
    profile.virtual_genesis_hash =
        *blake3::hash(b"CMFD/ISOLATED/5X-PROOF-RESTART/20260921").as_bytes();
    let primary_path = root.join("node-a");
    let follower_path = root.join("node-b");
    println!("REHEARSAL authenticating complete model on two isolated CPU-verifying nodes");
    let mut primary = open_isolated(&primary_path, profile, &artifacts);
    let mut follower = open_isolated(&follower_path, profile, &artifacts);
    assert_eq!(primary.params.initial_work_target(), initial);
    assert_eq!(primary.params.pow_limit, rc_limit);
    assert_eq!(primary.state.expected_target().unwrap(), initial);
    assert_ne!(
        primary.params.fingerprint().unwrap(),
        network_params_from_pow(
            network_profile::PRODUCTION_V4_TESTNET_PROFILE,
            primary.verifier.parameters(),
        )
        .unwrap()
        .fingerprint()
        .unwrap()
    );
    let miner_destination = primary.wallet_destination();
    let scratch = root.join("scratch");
    let worker = ProductionV4PersistentPoolVerifier::start_for_network(
        profile.network_id,
        ProductionV4PoolVerifierConfig {
            replay: ProductionV4PoolWorkerCommand {
                program: replay,
                arguments: vec!["--server".into(), model.as_os_str().to_owned()],
            },
            proof: ProductionV4PoolWorkerCommand {
                program: proof_worker,
                arguments: vec![
                    "--server".into(),
                    hex::encode(profile.network_id).into(),
                    model.as_os_str().to_owned(),
                    fixed.as_os_str().to_owned(),
                ],
            },
            scratch_directory: scratch.clone(),
            worker_scratch_directory: scratch.to_str().unwrap().into(),
        },
    )
    .unwrap();
    let mut receipts = Vec::new();
    for expected_height in 1..=2u64 {
        let cycle_started = Instant::now();
        let job = primary
            .build_mining_job(miner_destination, unix_time_seconds().unwrap())
            .unwrap();
        let pool_job = PoolJob {
            job_id: [expected_height as u8; 32],
            challenge: *job.challenge(),
            share_target: job.challenge().target,
        };
        assert_eq!(job.challenge().height, expected_height);
        let stop = AtomicBool::new(false);
        let search_started = Instant::now();
        let mut attempts = 0u64;
        let mut next_nonce = 0u64;
        let mut last_report = Instant::now();
        let winner = loop {
            assert!(
                search_started.elapsed() < Duration::from_secs(1800),
                "search exceeded 30-minute bound"
            );
            let result = worker.search(&pool_job, next_nonce, &stop).unwrap();
            match result {
                PoolWorkSearchResult::Found {
                    nonce,
                    meets_chain_target,
                    attempts_completed,
                    ..
                } => {
                    attempts += attempts_completed;
                    assert!(meets_chain_target);
                    break nonce;
                }
                PoolWorkSearchResult::Exhausted {
                    attempts_completed,
                    next_nonce: following,
                } => {
                    attempts += attempts_completed;
                    next_nonce = following;
                }
                PoolWorkSearchResult::Cancelled { .. } => panic!("unexpected cancellation"),
            }
            if last_report.elapsed() >= Duration::from_secs(20) {
                println!(
                    "REHEARSAL search height={expected_height} attempts={attempts} seconds={:.3}",
                    search_started.elapsed().as_secs_f64()
                );
                last_report = Instant::now();
            }
        };
        let search_seconds = search_started.elapsed().as_secs_f64();
        println!("REHEARSAL winner height={expected_height} nonce={winner} attempts={attempts}");
        let proving = Instant::now();
        let evaluation = worker
            .evaluate(&job.template, winner, job.challenge().target)
            .unwrap();
        let full_proof = evaluation
            .chain_proof
            .expect("winning nonce must have a complete proof");
        let proving_seconds = proving.elapsed().as_secs_f64();
        let BlockProof::V4Candidate(proof) = &full_proof else {
            panic!("non-V4 proof")
        };
        assert_eq!(proof.transparent_proof.len(), 12_025_320);
        let cpu_build = Instant::now();
        let block = *job
            .build_block_if_chain_valid(&full_proof)
            .unwrap()
            .expect("proof must meet exact chain target");
        let build_verify_seconds = cpu_build.elapsed().as_secs_f64();
        let encoded = encode_block(&block).unwrap();
        write_new(&root.join(format!("block-{expected_height}.bin")), &encoded);
        let block_id = block.block_id();
        let accepted_at = unix_time_seconds().unwrap();
        let admission_a = Instant::now();
        primary.submit_block(block, accepted_at).unwrap();
        let admission_a_seconds = admission_a.elapsed().as_secs_f64();
        let decoded = decode_block(&encoded, profile.network_id).unwrap();
        let mut corrupt = decoded.clone();
        let BlockProof::V4Candidate(proof) = &mut corrupt.proof else {
            unreachable!()
        };
        let last = proof.transparent_proof.len() - 1;
        proof.transparent_proof[last] ^= 1;
        let before_tip = follower.state.tip();
        assert!(follower.submit_block(corrupt, accepted_at).is_err());
        assert_eq!(follower.state.tip(), before_tip);
        let admission_b = Instant::now();
        follower.submit_block(decoded, accepted_at).unwrap();
        let admission_b_seconds = admission_b.elapsed().as_secs_f64();
        assert_eq!(primary.state.tip(), block_id);
        assert_eq!(follower.state.tip(), block_id);
        assert_eq!(primary.state.next_height(), expected_height + 1);
        let production_seconds = cycle_started.elapsed().as_secs_f64();
        let expected_next = primary.state.expected_target().unwrap();
        drop(primary);
        drop(follower);
        let restart = Instant::now();
        primary = open_isolated(&primary_path, profile, &artifacts);
        follower = open_isolated(&follower_path, profile, &artifacts);
        let restart_seconds = restart.elapsed().as_secs_f64();
        for node in [&primary, &follower] {
            assert_eq!(node.state.tip(), block_id);
            assert_eq!(node.state.next_height(), expected_height + 1);
            assert_eq!(node.state.expected_target().unwrap(), expected_next);
            assert_eq!(node.params.initial_work_target(), initial);
            assert_eq!(node.params.pow_limit, rc_limit);
        }
        assert_eq!(primary.wallet_destination(), miner_destination);
        let receipt = json!({"height":expected_height,"block_id":hex::encode(block_id),"target":hex::encode(job.challenge().target),"next_target":hex::encode(expected_next),"nonce":winner,"attempts":attempts,"search_seconds":search_seconds,"proof_pipeline_seconds":proving_seconds,"build_cpu_verify_seconds":build_verify_seconds,"node_a_admission_seconds":admission_a_seconds,"node_b_admission_seconds":admission_b_seconds,"production_seconds_including_negative_test":production_seconds,"two_node_restart_seconds":restart_seconds,"proof_bytes":12_025_320,"corrupted_proof_rejected":true,"restart_preserved_tip_target_wallet":true});
        println!("REHEARSAL_BLOCK {}", receipt);
        write_new(
            &root.join(format!("block-{expected_height}-receipt.json")),
            &serde_json::to_vec_pretty(&receipt).unwrap(),
        );
        receipts.push(receipt);
    }
    drop(worker);
    let report = json!({"schema":"CommonFoundry/DifficultyFullProofSmoke/v1","network":"isolated ProductionV4 test fixture, no P2P sockets","initial_target":hex::encode(initial),"pow_limit":hex::encode(rc_limit),"full_proof_and_local_node_restart_verified":true,"multi_gpu_hashrate_recovery_verified":false,"mainnet_plan_packaging_verified":false,"final_setting_approved":false,"blocks":receipts});
    write_new(
        &root.join("REPORT.json"),
        &serde_json::to_vec_pretty(&report).unwrap(),
    );
    println!("REHEARSAL_FULL_PROOF_RESTART_VERIFIED");
}

#[test]
#[ignore = "requires completed isolated GPU evidence; copies only its disposable test data"]
fn cold_log_replay_of_completed_5x_fixture() {
    assert_eq!(
        std::env::var("CMFD_RUN_DIFFICULTY_CPU_REPLAY").as_deref(),
        Ok("1")
    );
    let root = required_path("CMFD_DIFFICULTY_REHEARSAL_ROOT");
    let proof_report: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("REPORT.json")).unwrap()).unwrap();
    assert_eq!(
        proof_report["full_proof_and_local_node_restart_verified"],
        true
    );
    let snapshot = fs::read(root.join("node-a/startup-state.0.bin")).unwrap();
    assert!(snapshot.len() >= 232);
    assert_eq!(&snapshot[..8], b"CMFDNSN\0");
    // Read only a genesis-time hint from this locally generated cache. Node's
    // authenticated parameter fingerprint must validate it against network.meta.
    // Outer header is 100 bytes; inner history starts at offset 124.
    let genesis_timestamp = u64::from_le_bytes(snapshot[224..232].try_into().unwrap());
    let mut profile = network_profile::PRODUCTION_V4_TESTNET_PROFILE;
    profile.pow_limit = ((U256::one() << 246) - U256::one()).to_big_endian();
    profile.initial_target =
        Some((((U256::one() << 246) / U256::from(5u8)) - U256::one()).to_big_endian());
    profile.virtual_genesis_timestamp = genesis_timestamp;
    profile.virtual_genesis_hash =
        *blake3::hash(b"CMFD/ISOLATED/5X-PROOF-RESTART/20260921").as_bytes();
    let artifacts = ProductionV4VerifierArtifacts {
        bank: required_path("CMFD_DIFFICULTY_MODEL"),
        fixed_record: required_path("CMFD_DIFFICULTY_FIXED")
            .join("FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"),
    };
    let expected_tip = decode_block(
        &fs::read(root.join("block-2.bin")).unwrap(),
        profile.network_id,
    )
    .unwrap()
    .block_id();
    let recovery_root = root.join("cold-log-recovery");
    fs::create_dir(&recovery_root).unwrap();
    let mut results = Vec::new();
    for name in ["node-a", "node-b"] {
        let source = root.join(name);
        let recovered = recovery_root.join(name);
        fs::create_dir(&recovered).unwrap();
        // No cache is copied; the original test directories remain unchanged.
        for file in ["blocks.log", "network.meta", "wallet.key"] {
            fs::copy(source.join(file), recovered.join(file)).unwrap();
        }
        let before_wallet = fs::read(recovered.join("wallet.key")).unwrap();
        let started = Instant::now();
        let node = open_isolated(&recovered, profile, &artifacts);
        let elapsed = started.elapsed().as_secs_f64();
        assert_eq!(node.state.next_height(), 3);
        assert_eq!(node.state.tip(), expected_tip);
        assert_eq!(
            hex::encode(node.state.expected_target().unwrap()),
            proof_report["blocks"][1]["next_target"].as_str().unwrap()
        );
        assert_eq!(
            fs::read(recovered.join("wallet.key")).unwrap(),
            before_wallet
        );
        let actual_fingerprint = node.params.fingerprint().unwrap();
        let original_metadata = fs::read(source.join("network.meta")).unwrap();
        assert_eq!(&original_metadata[8..], &actual_fingerprint);
        results.push(json!({"node":name,"model_authentication_and_cold_replay_seconds":elapsed,"wallet_destination":hex::encode(node.wallet_destination()),"wallet_file_unchanged":true,"consensus_fingerprint":hex::encode(actual_fingerprint),"height":2,"tip":hex::encode(expected_tip)}));
        drop(node);
    }
    let result = json!({"schema":"CommonFoundry/DifficultyColdLogRecovery/v1","network_id":hex::encode(profile.network_id),"genesis_hash":hex::encode(profile.virtual_genesis_hash),"genesis_timestamp":genesis_timestamp,"initial_target":hex::encode(profile.initial_target.unwrap()),"pow_limit":hex::encode(profile.pow_limit),"no_startup_cache_copied":true,"cold_log_replay_verified":true,"gpu_used":false,"final_setting_approved":false,"nodes":results});
    write_new(
        &root.join("COLD-RECOVERY.json"),
        &serde_json::to_vec_pretty(&result).unwrap(),
    );
    println!("REHEARSAL_COLD_LOG_RECOVERY_VERIFIED {}", result);
}
