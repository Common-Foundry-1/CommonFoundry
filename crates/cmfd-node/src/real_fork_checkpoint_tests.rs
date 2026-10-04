//! Explicitly opted-in, CPU-only qualification using six preserved mainnet blocks.
//! No listeners, miners, GPU workers, live data directories or operator wallets.
//! Run alone with an external process-memory monitor; only one verifier is opened
//! at a time. Setup/model authentication is timed separately from fork admission.

#![cfg(any(windows, target_os = "linux"))]

use super::*;
use sha2::{Digest, Sha256};

const NETWORK: &str = "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62";
const PLAN: &str = "2133726558490606e89a8fe3499f32c9a35722ed0022e09b7cd1cd30239d04af";
const GENESIS: &str = "d8c9baa3b5a93f9ed0cbaa6a62e536b6df3f319dfeb2c72f49f88d684a6fdfe4";
const FRAME_BYTES: usize = 12_025_864;
const MAX_WORKING_SET_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const PASSPHRASE: &[u8] = b"public-disposable-real-fork-test-passphrase";

fn input(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("set {name}")));
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn read_bounded(path: &Path, limit: usize) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert!(metadata.len() <= limit as u64, "oversized fixture input");
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= limit);
    assert_eq!(bytes.len() as u64, metadata.len());
    bytes
}

fn load_branch(fixture: &Path, manifest: &serde_json::Value, prefix: char) -> Vec<Block> {
    let network: [u8; 32] = hex::decode(NETWORK).unwrap().try_into().unwrap();
    let mut parent: [u8; 32] = hex::decode(GENESIS).unwrap().try_into().unwrap();
    let mut blocks = Vec::with_capacity(3);
    for height in 1..=3 {
        let name = format!("{prefix}{height}.bin");
        let bytes = read_bounded(&fixture.join(&name), FRAME_BYTES);
        let row = &manifest["files"][&name];
        assert_eq!(bytes.len(), FRAME_BYTES);
        assert_eq!(row["bytes"].as_u64(), Some(bytes.len() as u64));
        assert_eq!(
            row["sha256"].as_str(),
            Some(hex::encode(Sha256::digest(&bytes)).as_str())
        );
        let block = decode_block(&bytes, network).unwrap();
        assert_eq!(encode_block(&block).unwrap(), bytes);
        assert_eq!(block.challenge.network_id, network);
        assert_eq!(block.challenge.height, height);
        assert_eq!(block.challenge.previous_block, parent);
        let BlockProof::V4Candidate(proof) = &block.proof else {
            panic!("fixture must contain real ProductionV4 proofs, never V2 substitutes");
        };
        assert_eq!(proof.transparent_proof.len(), 12_025_320);
        parent = block.block_id();
        blocks.push(block);
    }
    blocks
}

#[cfg(windows)]
fn peak_working_set_bytes() -> u64 {
    #[repr(C)]
    struct Counters {
        size: u32,
        page_faults: u32,
        peak_working_set: usize,
        working_set: usize,
        peak_paged_pool: usize,
        paged_pool: usize,
        peak_nonpaged_pool: usize,
        nonpaged_pool: usize,
        pagefile: usize,
        peak_pagefile: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "K32GetProcessMemoryInfo"]
        fn get_process_memory_info(
            process: *mut std::ffi::c_void,
            counters: *mut Counters,
            size: u32,
        ) -> i32;
    }
    let size = std::mem::size_of::<Counters>() as u32;
    let mut counters = Counters {
        size,
        page_faults: 0,
        peak_working_set: 0,
        working_set: 0,
        peak_paged_pool: 0,
        paged_pool: 0,
        peak_nonpaged_pool: 0,
        nonpaged_pool: 0,
        pagefile: 0,
        peak_pagefile: 0,
    };
    // SAFETY: the pseudo-handle is for this process; the writable structure has
    // the documented PROCESS_MEMORY_COUNTERS layout and exact supplied size.
    let success = unsafe {
        get_process_memory_info(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            &mut counters,
            size,
        )
    };
    assert_ne!(success, 0, "cannot measure process working set");
    counters.peak_working_set as u64
}

#[cfg(target_os = "linux")]
fn peak_working_set_bytes() -> u64 {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")
                .and_then(|value| value.split_whitespace().next())
                .map(|value| value.parse::<u64>().unwrap() * 1024)
        })
        .expect("VmHWM is required for this qualification")
}

fn check_memory() -> u64 {
    let peak = peak_working_set_bytes();
    assert!(
        peak <= MAX_WORKING_SET_BYTES,
        "process exceeded the 16 GiB qualification budget"
    );
    peak
}

fn open_node(
    path: &Path,
    launch: &mainnet_runtime::AuthenticatedMainnetRuntime,
    artifacts: &ProductionV4VerifierArtifacts,
) -> Arc<Mutex<Node>> {
    let node =
        Node::open_with_authenticated_mainnet(path, launch, artifacts, Some(PASSPHRASE)).unwrap();
    assert_eq!(node.network_profile(), launch.profile());
    assert_eq!(node.profile.proof, ProofProfile::ProductionV4);
    check_memory();
    Arc::new(Mutex::new(node))
}

#[test]
#[ignore = "requires production-mainnet feature, six real-mainnet blocks and pinned models; CPU only; run alone"]
fn real_mainnet_short_fork_cold_and_warm_checkpoint_reuse() {
    assert!(
        cfg!(feature = "production-mainnet"),
        "real fixture requires compiled mainnet artifact pins"
    );
    assert_eq!(
        std::env::var("CMFD_RUN_REAL_FORK_CHECKPOINT").as_deref(),
        Ok("1")
    );
    let fixture = input("CMFD_REAL_FORK_FIXTURE_DIR").canonicalize().unwrap();
    let output = input("CMFD_REAL_FORK_OUTPUT_DIR");
    assert!(!output.exists(), "qualification output must be new");
    let output_parent = output.parent().unwrap().canonicalize().unwrap();
    let output = output_parent.join(output.file_name().unwrap());
    assert!(!output.starts_with(&fixture) && !fixture.starts_with(&output));
    let artifacts = ProductionV4VerifierArtifacts {
        bank: input("CMFD_REAL_FORK_MODEL_BANK"),
        fixed_record: input("CMFD_REAL_FORK_FIXED_RECORD"),
    };
    let pin = release_gate::MAINNET_RELEASE_CONFIGURATION.expect("compiled mainnet release pin");
    assert_eq!(hex::encode(pin.network_id), NETWORK);
    assert_eq!(hex::encode(pin.launch_plan_digest), PLAN);
    assert_eq!(cmfd_launch::MAINNET_BEACON_ROUND, 32_747_812);
    let launch = mainnet_runtime::AuthenticatedMainnetRuntime::authenticate(
        &read_bounded(&fixture.join("MAINNET-PLAN.json"), 32 * 1024),
        &read_bounded(&fixture.join("LAUNCH-BEACON.json"), 4096),
        pin.launch_plan_digest,
        unix_time_seconds().unwrap(),
    )
    .unwrap();
    assert_eq!(hex::encode(launch.profile().virtual_genesis_hash), GENESIS);
    let mut expected_profile = network_profile::mainnet_profile_template(Some(pin)).unwrap();
    expected_profile.virtual_genesis_hash = launch.profile().virtual_genesis_hash;
    assert_eq!(launch.profile(), expected_profile);
    let manifest_bytes = read_bounded(&fixture.join("manifest.json"), 64 * 1024);
    let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
    assert_eq!(
        manifest_sha256,
        std::env::var("CMFD_REAL_FORK_MANIFEST_SHA256").expect("pin the external fixture manifest")
    );
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let fixture_started = Instant::now();
    let a = load_branch(&fixture, &manifest, 'a');
    let b = load_branch(&fixture, &manifest, 'b');
    let fixture_ms = fixture_started.elapsed().as_millis();
    assert_ne!(a[0].block_id(), b[0].block_id());
    let work = |blocks: &[Block]| {
        blocks.iter().fold(U512::zero(), |sum, block| {
            add_chain_work(sum, block.challenge.target).unwrap()
        })
    };
    assert_eq!(work(&a), U512::from(7850_u64));
    assert_eq!(work(&b[..2]), U512::from(6826_u64));
    assert_eq!(work(&b), U512::from(8026_u64));
    fs::create_dir(&output).unwrap();
    let data = output.join("fork-node");
    println!("REAL_FORK_STAGE authenticating model and opening fresh isolated node");
    let started = Instant::now();
    let shared = open_node(&data, &launch, &artifacts);
    let initial_open_ms = started.elapsed().as_millis();
    println!("REAL_FORK_STAGE validating A1/A2/A3 and nonwinning B1");
    let started = Instant::now();
    for block in a.iter().chain(b[..1].iter()) {
        submit_shared_block(&shared, block.clone(), unix_time_seconds().unwrap()).unwrap();
        check_memory();
    }
    let seed_ms = started.elapsed().as_millis();
    assert_eq!(shared.lock().unwrap().state.tip(), a[2].block_id());
    drop(shared);

    // Reopen only this newly created fixture node. No operator data is copied,
    // The reopened active A3 anchor must not be usable as an ancestor of B2.
    // No B-branch checkpoint or proof capability may survive this restart.
    println!("REAL_FORK_STAGE reopening isolated node with cold optimization caches");
    let started = Instant::now();
    let shared = open_node(&data, &launch, &artifacts);
    let cold_reopen_ms = started.elapsed().as_millis();
    let (replayed, dispatches) = {
        let node = shared.lock().unwrap();
        assert_eq!(node.branch_checkpoints.entries.len(), 1);
        assert_eq!(
            node.branch_checkpoints.entries[0].checkpoint.block_id,
            a[2].block_id()
        );
        assert!(
            node.block_preverifier
                .successful_proofs
                .lock()
                .unwrap()
                .entries
                .is_empty()
        );
        (
            Arc::clone(&node.block_preverifier.replay_state_blocks),
            Arc::clone(&node.block_preverifier.worker_dispatches),
        )
    };
    let before_replay = replayed.load(Ordering::Relaxed);
    let before_dispatch = dispatches.load(Ordering::Relaxed);
    println!("REAL_FORK_STAGE cold B2 admission");
    let started = Instant::now();
    submit_shared_block(&shared, b[1].clone(), unix_time_seconds().unwrap()).unwrap();
    let cold_b2_ms = started.elapsed().as_millis();
    let cold_replayed = replayed.load(Ordering::Relaxed) - before_replay;
    let cold_dispatches = dispatches.load(Ordering::Relaxed) - before_dispatch;
    assert_eq!(cold_replayed, 1, "cold B2 must reconstruct real B1");
    assert_eq!(
        cold_dispatches, 2,
        "cold B2 must verify real B1 and B2 proofs"
    );
    assert_eq!(shared.lock().unwrap().state.tip(), a[2].block_id());
    check_memory();

    let before_replay = replayed.load(Ordering::Relaxed);
    let before_dispatch = dispatches.load(Ordering::Relaxed);
    println!("REAL_FORK_STAGE warm B3 admission and heavier-work reorganization");
    let started = Instant::now();
    submit_shared_block(&shared, b[2].clone(), unix_time_seconds().unwrap()).unwrap();
    let warm_b3_ms = started.elapsed().as_millis();
    let warm_replayed = replayed.load(Ordering::Relaxed) - before_replay;
    let warm_dispatches = dispatches.load(Ordering::Relaxed) - before_dispatch;
    assert_eq!(
        warm_replayed, 0,
        "warm B3 must reuse fully validated B2 state"
    );
    assert_eq!(warm_dispatches, 1, "B3's real proof must still be verified");
    let final_state = {
        let node = shared.lock().unwrap();
        assert_eq!(node.state.tip(), b[2].block_id());
        assert_eq!(node.index.active_work, work(&b));
        node.state.encode_local_snapshot().unwrap()
    };
    check_memory();
    drop(shared);

    // A fresh independent state construction validates B1/B2/B3 without the
    // competing branch, then must produce byte-identical consensus state.
    println!("REAL_FORK_STAGE fresh reference B1/B2/B3 validation");
    let started = Instant::now();
    let reference = open_node(&output.join("reference-node"), &launch, &artifacts);
    let reference_open_ms = started.elapsed().as_millis();
    let started = Instant::now();
    for block in &b {
        submit_shared_block(&reference, block.clone(), unix_time_seconds().unwrap()).unwrap();
        check_memory();
    }
    let reference_replay_ms = started.elapsed().as_millis();
    assert_eq!(
        reference
            .lock()
            .unwrap()
            .state
            .encode_local_snapshot()
            .unwrap(),
        final_state
    );
    drop(reference);
    let report = json!({
        "schema": "CMFD_REAL_MAINNET_FORK_CHECKPOINT_QUALIFICATION_V1",
        "network_id": NETWORK, "launch_plan_digest": PLAN, "genesis": GENESIS,
        "fixture_manifest_sha256": manifest_sha256,
        "real_v4_proofs": 6, "frame_bytes_each": FRAME_BYTES,
        "branch_a_work": "7850", "branch_b_work": "8026",
        "final_tip": hex::encode(b[2].block_id()), "exact_reference_state_matched": true,
        "fixture_read_hash_decode_ms": fixture_ms, "initial_open_ms": initial_open_ms,
        "initial_a3_b1_admission_ms": seed_ms, "cold_reopen_ms": cold_reopen_ms,
        "cold_b2_ms": cold_b2_ms, "cold_b2_ancestor_state_replays": cold_replayed,
        "cold_b2_proof_dispatches": cold_dispatches, "warm_b3_ms": warm_b3_ms,
        "warm_b3_ancestor_state_replays": warm_replayed, "warm_b3_proof_dispatches": warm_dispatches,
        "reference_open_ms": reference_open_ms, "reference_replay_ms": reference_replay_ms,
        "peak_process_working_set_bytes": check_memory(),
        "process_working_set_budget_bytes": MAX_WORKING_SET_BYTES,
        "memory_limit_kind": "phase-boundary assertion; external combined-memory monitor required",
        "debug_assertions": cfg!(debug_assertions), "single_verifier_at_a_time": true,
        "cold_scope": "B-branch state and proof caches; not the operating-system file cache",
        "remote_request_deadline_enforced": false,
        "gpu_used": false, "network_service_started": false, "live_host_modified": false,
        "scope": "six preserved mainnet blocks; not live mining, network load, or deep-history qualification"
    });
    let encoded = serde_json::to_vec_pretty(&report).unwrap();
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("REPORT.json"))
        .unwrap()
        .write_all(&encoded)
        .unwrap();
    println!("REAL_MAINNET_FORK_CHECKPOINT {}", report);
}
