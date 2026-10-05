//! Opt-in loopback qualification of ordinary ProductionV4 peer catch-up.
//! The fixture peer serves preserved public blocks, not consensus shortcuts.
//! Exactly one authenticating node/verifier is open at a time; no live paths,
//! public listeners, miners, operator wallets, or GPU workers are used.

use super::*;
use crate::{
    ProductionV4VerifierArtifacts, ProofProfile, add_chain_work, mainnet_runtime, network_profile,
    release_gate,
};
use cmfd_consensus::{BlockProof, encode_block};
use primitive_types::U512;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

const NETWORK: &str = "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62";
const PLAN: &str = "2133726558490606e89a8fe3499f32c9a35722ed0022e09b7cd1cd30239d04af";
const GENESIS: &str = "d8c9baa3b5a93f9ed0cbaa6a62e536b6df3f319dfeb2c72f49f88d684a6fdfe4";
const FRAME_BYTES: usize = 12_025_864;
const MAX_WORKING_SET_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const PASSPHRASE: &[u8] = b"public-disposable-real-peer-test-passphrase";
const FIXTURE_NONCE: [u8; 32] = [0x91; 32];
const TARGET_NONCE: [u8; 32] = [0x92; 32];

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
        assert_eq!(block.challenge.height, height);
        assert_eq!(block.challenge.network_id, network);
        assert_eq!(block.challenge.previous_block, parent);
        let BlockProof::V4Candidate(proof) = &block.proof else {
            panic!("real ProductionV4 proof required; V2 substitutes are forbidden");
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
    // SAFETY: the pseudo-handle belongs to this process; the writable structure
    // has the documented PROCESS_MEMORY_COUNTERS layout and exact size.
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
    fs::read_to_string("/proc/self/status")
        .unwrap()
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
        "16 GiB process budget exceeded"
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

#[derive(Default, serde::Serialize)]
struct FixtureStats {
    connections: u64,
    header_requests: u64,
    served_heights: Vec<u64>,
    advertised_heights: Vec<u64>,
    moved_from_two_to_three: bool,
}

struct FixturePeer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<FixtureStats>>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl FixturePeer {
    fn start(base_hello: PeerHello, blocks: Arc<Vec<Block>>, moving: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        assert!(address.ip().is_loopback());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Mutex::new(FixtureStats::default()));
        let thread_stop = Arc::clone(&stop);
        let thread_stats = Arc::clone(&stats);
        let thread = thread::spawn(move || {
            let mut height = if moving { 2 } else { 3 };
            while !thread_stop.load(Ordering::Acquire) {
                let stream = match listener.accept() {
                    Ok((stream, address)) => {
                        if !address.ip().is_loopback() {
                            return Err("non-loopback connection rejected".to_owned());
                        }
                        stream
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                let mut hello = base_hello;
                hello.node_nonce = FIXTURE_NONCE;
                hello.height = height as u64;
                hello.tip = blocks[height - 1].block_id();
                let work = blocks[..height].iter().fold(U512::zero(), |sum, block| {
                    add_chain_work(sum, block.challenge.target).unwrap()
                });
                hello.cumulative_work.0 = work.to_big_endian();
                {
                    let mut stats = thread_stats.lock().unwrap();
                    stats.connections += 1;
                    stats.advertised_heights.push(hello.height);
                }
                let result = serve_fixture_connection(
                    stream,
                    hello,
                    &blocks,
                    &mut height,
                    &thread_stop,
                    &thread_stats,
                );
                if let Err(error) = result {
                    if thread_stop.load(Ordering::Acquire) {
                        break;
                    }
                    return Err(error.to_string());
                }
            }
            Ok(())
        });
        Self {
            address,
            stop,
            stats,
            thread: Some(thread),
        }
    }

    fn finish(mut self) -> FixtureStats {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap().unwrap();
        std::mem::take(&mut *self.stats.lock().unwrap())
    }
}

impl Drop for FixturePeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_fixture_connection(
    stream: TcpStream,
    hello: PeerHello,
    blocks: &[Block],
    height: &mut usize,
    stop: &Arc<AtomicBool>,
    stats: &Arc<Mutex<FixtureStats>>,
) -> Result<(), PeerError> {
    let limits = PeerLimits::default();
    let mut connection = PeerConnection::from_stream(stream, PeerSession::new(hello, limits)?)?;
    connection.set_cancellation(Arc::clone(stop));
    connection.send_hello()?;
    assert!(matches!(connection.receive()?, PeerMessage::Hello(_)));
    let genesis: [u8; 32] = hex::decode(GENESIS).unwrap().try_into().unwrap();
    let mut served_block = false;
    loop {
        let received = if served_block {
            connection.receive_after_served_block()
        } else {
            connection.receive()
        };
        match received {
            Err(PeerError::ConnectionClosed) => return Ok(()),
            Err(error) => return Err(error),
            Ok(PeerMessage::GetHeaders { locator, stop }) => {
                stats.lock().unwrap().header_requests += 1;
                let common = locator.iter().find_map(|id| {
                    if *id == genesis {
                        Some(0)
                    } else {
                        blocks[..*height]
                            .iter()
                            .position(|block| block.block_id() == *id)
                            .map(|index| index + 1)
                    }
                });
                let stop_height = blocks[..*height]
                    .iter()
                    .position(|block| block.block_id() == stop)
                    .map_or(*height, |index| index + 1);
                let block_ids = common
                    .filter(|common| *common < stop_height)
                    .map(|common| vec![blocks[common].block_id()])
                    .unwrap_or_default();
                assert!(block_ids.len() <= block_sync_batch_limit(hello.network_id, limits));
                connection.send(PeerMessage::Inventory { block_ids })?;
            }
            Ok(PeerMessage::GetBlock { block_id }) => {
                let block = blocks[..*height]
                    .iter()
                    .find(|block| block.block_id() == block_id)
                    .expect("requested fixture block");
                stats
                    .lock()
                    .unwrap()
                    .served_heights
                    .push(block.challenge.height);
                connection.send(PeerMessage::Block(block.clone()))?;
                served_block = true;
            }
            Ok(PeerMessage::GetMempool) => {
                // The target only reaches this request after normal, complete
                // proof and state admission. The next handshake sees B3.
                if served_block && *height == 2 {
                    *height = 3;
                    stats.lock().unwrap().moved_from_two_to_three = true;
                }
                served_block = false;
                connection.send(PeerMessage::TransactionInventory { txids: Vec::new() })?;
            }
            Ok(other) => panic!("unexpected fixture-peer request: {other:?}"),
        }
    }
}

#[test]
#[ignore = "requires production-mainnet, six public mainnet blocks and pinned models; isolated loopback; run alone"]
fn real_mainnet_peer_backlog_catches_moving_head_without_poll_sleep() {
    assert_eq!(
        std::env::var("CMFD_RUN_REAL_PEER_CATCHUP").as_deref(),
        Ok("1")
    );
    let fixture = input("CMFD_REAL_PEER_FIXTURE_DIR").canonicalize().unwrap();
    let output = input("CMFD_REAL_PEER_OUTPUT_DIR");
    assert!(!output.exists(), "qualification output must be new");
    let output = output
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .join(output.file_name().unwrap());
    assert!(!output.starts_with(&fixture) && !fixture.starts_with(&output));
    let artifacts = ProductionV4VerifierArtifacts {
        bank: input("CMFD_REAL_PEER_MODEL_BANK"),
        fixed_record: input("CMFD_REAL_PEER_FIXED_RECORD"),
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
        std::env::var("CMFD_REAL_PEER_MANIFEST_SHA256").expect("pin external fixture manifest")
    );
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let a = load_branch(&fixture, &manifest, 'a');
    let b = Arc::new(load_branch(&fixture, &manifest, 'b'));
    assert_ne!(a[0].block_id(), b[0].block_id());
    drop(a);
    let limits = PeerLimits::default();
    assert_eq!(limits.max_bytes_per_peer, 32 * 1024 * 1024);
    assert_eq!(limits.max_blocks_per_session, MAX_BLOCKS_PER_SYNC as u64);
    assert_eq!(
        block_sync_batch_limit(pin.network_id, limits),
        MAX_BLOCKS_PER_SYNC
    );
    fs::create_dir(&output).unwrap();

    println!("REAL_PEER_STAGE three ordinary one-block sessions with full real proofs");
    let baseline = open_node(&output.join("ordinary-sessions"), &launch, &artifacts);
    let fixture_peer =
        FixturePeer::start(baseline.lock().unwrap().peer_hello(), Arc::clone(&b), false);
    let dispatches = Arc::clone(&baseline.lock().unwrap().block_preverifier.worker_dispatches);
    let before = dispatches.load(Ordering::Relaxed);
    let mut ordinary_session_ms = Vec::new();
    for height in 1..=3 {
        let started = Instant::now();
        let report = sync_from_peer_once_inner(
            Arc::clone(&baseline),
            fixture_peer.address,
            limits,
            Some(TARGET_NONCE),
        )
        .unwrap();
        ordinary_session_ms.push(started.elapsed().as_millis());
        assert_eq!(report.inventory_items, 1);
        assert_eq!(report.requested_blocks, 1);
        assert_eq!(report.accepted_blocks, 1);
        assert_eq!(baseline.lock().unwrap().peer_hello().height, height);
        check_memory();
    }
    let ordinary_dispatches = dispatches.load(Ordering::Relaxed) - before;
    assert_eq!(ordinary_dispatches, 3);
    let reference_state = baseline
        .lock()
        .unwrap()
        .state
        .encode_local_snapshot()
        .unwrap();
    let ordinary_stats = fixture_peer.finish();
    drop(baseline);

    println!("REAL_PEER_STAGE production poller; peer advances B2 to B3; interval 60 seconds");
    let target = open_node(&output.join("moving-peer-poller"), &launch, &artifacts);
    let fixture_peer =
        FixturePeer::start(target.lock().unwrap().peer_hello(), Arc::clone(&b), true);
    let dispatches = Arc::clone(&target.lock().unwrap().block_preverifier.worker_dispatches);
    let before = dispatches.load(Ordering::Relaxed);
    let started = Instant::now();
    let poller = spawn_static_peer_polling_inner(
        Arc::clone(&target),
        StaticPeerConfig {
            listen_address: "127.0.0.1:28446".parse().unwrap(),
            peers: vec![fixture_peer.address],
            limits,
            address_policy: PeerAddressPolicy::PrivateOnly,
        },
        Duration::from_secs(60),
        Some(TARGET_NONCE),
    )
    .unwrap();
    let deadline = started + Duration::from_secs(45);
    while target.lock().unwrap().peer_hello().tip != b[2].block_id() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
        check_memory();
    }
    let poller_elapsed_ms = started.elapsed().as_millis();
    poller.stop().unwrap();
    let moving_stats = fixture_peer.finish();
    let target_node = target.lock().unwrap();
    let final_hello = target_node.peer_hello();
    let poller_dispatches = dispatches.load(Ordering::Relaxed) - before;
    let exact_state_matched = target_node.state.encode_local_snapshot().unwrap() == reference_state;
    let report = json!({
        "schema": "CMFD_REAL_MAINNET_PEER_CATCHUP_QUALIFICATION_V1",
        "network_id": NETWORK, "launch_plan_digest": PLAN, "genesis": GENESIS,
        "fixture_manifest_sha256": manifest_sha256,
        "real_v4_blocks_per_case": 3, "frame_bytes_each": FRAME_BYTES,
        "session_byte_limit": limits.max_bytes_per_peer, "blocks_per_session": limits.max_blocks_per_session,
        "fixture_blocks_offered_per_session": 1,
        "ordinary_session_ms": ordinary_session_ms, "ordinary_proof_dispatches": ordinary_dispatches,
        "ordinary_peer_stats": ordinary_stats,
        "poll_interval_seconds": 60, "qualification_timeout_seconds": 45,
        "poller_elapsed_ms": poller_elapsed_ms, "poller_proof_dispatches": poller_dispatches,
        "moving_peer_stats": moving_stats, "final_height": final_hello.height,
        "final_tip": hex::encode(final_hello.tip), "expected_tip": hex::encode(b[2].block_id()),
        "exact_reference_state_matched": exact_state_matched,
        "peak_process_working_set_bytes": check_memory(), "process_budget_bytes": MAX_WORKING_SET_BYTES,
        "memory_limit_kind": "phase-boundary assertion; external combined-memory monitor required",
        "debug_assertions": cfg!(debug_assertions), "single_verifier_at_a_time": true,
        "fixture_peer_is_full_node": false, "target_uses_real_production_verifier": true,
        "target_blocks_received_only_through_p2p": true, "loopback_only": true,
        "gpu_used": false, "live_host_modified": false,
        "scope": "three-block backlog and one advancing peer head; not deep-chain, public-network or loaded-pool throughput"
    });
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("REPORT.json"))
        .unwrap()
        .write_all(&serde_json::to_vec_pretty(&report).unwrap())
        .unwrap();
    println!("REAL_MAINNET_PEER_CATCHUP {report}");
    assert_eq!(
        final_hello.tip,
        b[2].block_id(),
        "catch-up missed the 45-second fixture deadline; inspect session timings before attributing the cause"
    );
    assert_eq!(final_hello.height, 3);
    assert!(exact_state_matched);
    assert_eq!(
        poller_dispatches, 3,
        "each received block requires its real proof"
    );
}
