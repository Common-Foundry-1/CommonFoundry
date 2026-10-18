//! Sync and peer handling under the release work rule, on Devnet with
//! scripted work engines.

use super::*;
use crate::tests::clean_test_dir;
use crate::work_gate::test_support::{install, recorded};
use crate::work_gate::tests::{cpu, devnet, mine, shared};
use crate::work_gate::{
    FetchedFrom, MAX_PENDING_SIDE_WORK_PER_SENDER, WORK_RELEVANCE_DEPTH, WorkRejectionKind,
};

const SOURCE_NONCE: [u8; 32] = [0x61; 32];
const TARGET_NONCE: [u8; 32] = [0x62; 32];

fn limits() -> PeerLimits {
    PeerLimits {
        connect_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(10),
        ..PeerLimits::default()
    }
}

/// A sync peer on loopback that is `trusted` or not, and claims no more
/// work than this node has.
fn fetched_from(trusted: bool) -> FetchedFrom {
    FetchedFrom {
        sender: IpAddr::from([127, 0, 0, 1]),
        trusted,
        heavier: false,
        catch_up: None,
    }
}

/// Serves `source` on loopback and runs one sync session from `target`.
fn sync_once(
    source: &Arc<Mutex<Node>>,
    target: &Arc<Mutex<Node>>,
) -> (Result<SyncReport, P2pError>, SocketAddr) {
    sync_once_from(source, target, false)
}

/// [`sync_once`] from a peer that is `trusted` or not.
fn sync_once_from(
    source: &Arc<Mutex<Node>>,
    target: &Arc<Mutex<Node>>,
    trusted: bool,
) -> (Result<SyncReport, P2pError>, SocketAddr) {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let listener =
        spawn_inbound_listener_inner(Arc::clone(source), socket, limits(), Some(SOURCE_NONCE))
            .unwrap();
    let result = sync_from_peer_once_inner_with_policy(
        Arc::clone(target),
        address,
        limits(),
        PeerAddressPolicy::PrivateOnly,
        Some(TARGET_NONCE),
        None,
        trusted,
    );
    listener.stop().unwrap();
    (result, address)
}

#[test]
fn a_fetched_block_is_prewarmed_and_then_admitted_from_the_memo() {
    let (source_path, mut source) = devnet("work-prewarm-source");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 3, now);
    let (path, mut node) = devnet("work-prewarm");
    let engine = cpu();
    for block in &chain {
        engine.answer(block, true);
    }
    install(&mut node, None, Some(engine.clone()), None);
    let node = shared(node);
    let preverifier = node.lock().unwrap().block_preverifier();
    let peer = next_remote_proof_peer_id().unwrap();

    for (index, block) in chain.iter().enumerate() {
        prewarm_fetched_work(&node, &preverifier, block, fetched_from(false), None).unwrap();
        assert_eq!(engine.block_calls(), index + 1);
        assert_eq!(
            recorded(&node.lock().unwrap()),
            (index, 0),
            "a prewarm records nothing"
        );
        // The submission answers from the memo: no further run.
        assert!(
            submit_fetched_block(&node, block.clone(), peer, fetched_from(false), None).unwrap()
        );
        assert_eq!(engine.block_calls(), index + 1);
        assert_eq!(recorded(&node.lock().unwrap()), (index + 1, 0));
    }
    drop((source, node));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_fetched_block_runs_no_engine_unless_its_admission_checks_and_proof_pass() {
    use crate::work_gate::test_support::set_halted;
    use cmfd_consensus::BlockProof;

    let (source_path, mut source) = devnet("work-prewarm-checks-source");
    let now = unix_time_seconds().unwrap();
    let block = mine(&mut source, 1, now).remove(0);
    let (path, mut node) = devnet("work-prewarm-checks");
    let engine = cpu();
    let tamper = |change: fn(&mut [u8; 32], &mut [u8; 32])| {
        let mut block = block.clone();
        let BlockProof::V2Reference(proof) = &mut block.proof else {
            panic!("Devnet blocks carry a reference proof");
        };
        change(
            &mut proof.challenge_digest,
            &mut proof.final_activation_digest,
        );
        engine.answer(&block, true);
        block
    };
    // A proof that does not bind the header, and one that does not show the
    // result it claims.
    let wrong_challenge = tamper(|challenge, _| challenge[0] ^= 1);
    let wrong_result = tamper(|_, digest| digest[0] ^= 1);
    engine.answer(&block, true);
    install(&mut node, None, Some(engine.clone()), None);
    let node = shared(node);
    let preverifier = node.lock().unwrap().block_preverifier();

    for bad in [&wrong_challenge, &wrong_result] {
        // Only its proof stops it here.
        assert!(
            node.lock()
                .unwrap()
                .work_prewarm(bad, now, fetched_from(false))
                .is_some()
        );
        prewarm_fetched_work(&node, &preverifier, bad, fetched_from(false), None).unwrap();
    }
    assert_eq!(
        engine.block_calls(),
        0,
        "a block whose proof fails runs nothing"
    );

    set_halted(&node.lock().unwrap(), true);
    prewarm_fetched_work(&node, &preverifier, &block, fetched_from(false), None).unwrap();
    assert_eq!(engine.block_calls(), 0, "a halted node runs nothing");
    set_halted(&node.lock().unwrap(), false);

    // A block refused before is not run again.
    node.lock()
        .unwrap()
        .remember_work_rejection(block.block_id(), WorkRejectionKind::Confirmed);
    prewarm_fetched_work(&node, &preverifier, &block, fetched_from(false), None).unwrap();
    assert_eq!(engine.block_calls(), 0);

    let (other_path, mut other) = devnet("work-prewarm-checks-other");
    let engine = cpu();
    engine.answer(&block, true);
    install(&mut other, None, Some(engine.clone()), None);
    let other = shared(other);
    let preverifier = other.lock().unwrap().block_preverifier();
    prewarm_fetched_work(&other, &preverifier, &block, fetched_from(false), None).unwrap();
    assert_eq!(engine.block_calls(), 1, "an honest block is prewarmed");
    drop((source, node, other));
    clean_test_dir(&path);
    clean_test_dir(&other_path);
    clean_test_dir(&source_path);
}

#[test]
fn a_block_from_a_trusted_sync_peer_waits_for_the_work_lane_as_priority() {
    use crate::work_gate::test_support::lane_waiters;

    let (first_path, mut first_source) = devnet("work-trusted-sync-first");
    let (second_path, mut second_source) = devnet("work-trusted-sync-second");
    let now = unix_time_seconds().unwrap();
    let held = mine(&mut first_source, 1, now).remove(0);
    let fetched = mine(&mut second_source, 1, now + 1).remove(0);
    let (path, mut node) = devnet("work-trusted-sync-target");
    let engine = cpu();
    engine.answer(&held, true);
    engine.answer(&fetched, true);
    install(&mut node, None, Some(engine.clone()), None);
    let node = shared(node);

    // A remote block's job holds the lane.
    let barrier = engine.hold_next();
    let request = RemoteProofRequest::new(Instant::now() + Duration::from_secs(30));
    let holder = {
        let (node, request) = (Arc::clone(&node), request.clone());
        let peer = next_remote_proof_peer_id().unwrap();
        thread::spawn(move || {
            crate::submit_shared_peer_block_cancellable(&node, held, now, peer, request)
        })
    };
    barrier.wait();

    let prewarm = {
        let node = Arc::clone(&node);
        let preverifier = node.lock().unwrap().block_preverifier();
        let fetched = fetched.clone();
        thread::spawn(move || {
            prewarm_fetched_work(&node, &preverifier, &fetched, fetched_from(true), None)
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while lane_waiters(&node.lock().unwrap()) != (0, 1) {
        assert!(
            Instant::now() < deadline,
            "the fetched block never waited as priority"
        );
        thread::sleep(Duration::from_millis(10));
    }
    request.cancel();
    assert!(holder.join().unwrap().is_err());
    prewarm.join().unwrap().unwrap();
    assert_eq!(engine.block_calls(), 2);
    let peer = next_remote_proof_peer_id().unwrap();
    assert!(submit_fetched_block(&node, fetched, peer, fetched_from(true), None).unwrap());
    assert_eq!(engine.block_calls(), 2, "admitted from the memo");
    drop((node, first_source, second_source));
    clean_test_dir(&path);
    clean_test_dir(&first_path);
    clean_test_dir(&second_path);
}

/// The remote proof admission order covers a block's proof check only: while
/// one session's block has its work checked, a trusted peer's block on
/// another session goes on to the work lane and is admitted next.
#[test]
fn a_trusted_peers_block_reaches_the_work_lane_while_another_sessions_block_is_checked() {
    use crate::work_gate::BlockSender;
    use crate::work_gate::test_support::lane_waiters;

    let (first_path, mut first_source) = devnet("work-admission-order-first");
    let (second_path, mut second_source) = devnet("work-admission-order-second");
    let now = unix_time_seconds().unwrap();
    let held = mine(&mut first_source, 1, now).remove(0);
    let trusted = mine(&mut second_source, 1, now + 1).remove(0);
    let (path, mut node) = devnet("work-admission-order-target");
    let engine = cpu();
    engine.answer(&held, true);
    engine.answer(&trusted, true);
    install(&mut node, None, Some(engine.clone()), None);
    // Remote proofs take their turn in the session order, as on a
    // production network.
    node.profile.proof = crate::ProofProfile::ProductionV4;
    let node = shared(node);
    let sender = |address: [u8; 4], trusted: bool| {
        Some(BlockSender {
            address: IpAddr::from(address),
            fetched: false,
            trusted,
        })
    };

    // An untrusted session's block has its work checked.
    let barrier = engine.hold_next();
    let request = RemoteProofRequest::new(Instant::now() + Duration::from_secs(30));
    let holder = {
        let (node, request) = (Arc::clone(&node), request.clone());
        let peer = next_remote_proof_peer_id().unwrap();
        thread::spawn(move || {
            crate::submit_shared_peer_block_from(
                &node,
                held,
                now,
                peer,
                request,
                false,
                sender([192, 0, 2, 1], false),
            )
        })
    };
    barrier.wait();

    let admitted = {
        let node = Arc::clone(&node);
        let trusted = trusted.clone();
        let peer = next_remote_proof_peer_id().unwrap();
        let request = RemoteProofRequest::new(Instant::now() + Duration::from_secs(30));
        thread::spawn(move || {
            crate::submit_shared_peer_block_from(
                &node,
                trusted,
                now + 1,
                peer,
                request,
                true,
                sender([192, 0, 2, 2], true),
            )
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while lane_waiters(&node.lock().unwrap()) != (0, 1) {
        assert!(
            Instant::now() < deadline,
            "the trusted block never reached the work lane"
        );
        thread::sleep(Duration::from_millis(10));
    }
    request.cancel();
    assert!(matches!(
        holder.join().unwrap(),
        Err(NodeError::WorkCheckWithdrawn)
    ));
    admitted.join().unwrap().unwrap();
    assert_eq!(node.lock().unwrap().peer_hello().tip, trusted.block_id());
    assert_eq!(engine.block_calls(), 2);
    drop((node, first_source, second_source));
    clean_test_dir(&path);
    clean_test_dir(&first_path);
    clean_test_dir(&second_path);
}

#[test]
fn a_sync_session_admits_a_window_with_one_run_per_block() {
    let (source_path, mut source) = devnet("work-sync-source");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 4, now);
    let (path, mut node) = devnet("work-sync-target");
    let engine = cpu();
    for block in &chain {
        engine.answer(block, true);
    }
    install(&mut node, None, Some(engine.clone()), None);
    let source = shared(source);
    let node = shared(node);
    let (result, _) = sync_once(&source, &node);
    let report = result.unwrap();
    assert_eq!(report.accepted_blocks, 4);
    assert_eq!(engine.block_calls(), 4);
    assert_eq!(recorded(&node.lock().unwrap()), (4, 0));
    assert_eq!(node.lock().unwrap().peer_hello().tip, chain[3].block_id());
    drop((source, node));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_heavier_branch_that_forked_deeper_than_the_relevance_depth_is_followed_in_one_session() {
    let now = unix_time_seconds().unwrap();
    let (main_path, mut main_source) = devnet("work-heavier-sync-main");
    let main = mine(&mut main_source, 12, now);
    // Heights 2 to 13 off block 1: one block more than the active chain.
    let (source_path, mut source) = devnet("work-heavier-sync-source");
    source.submit_block(main[0].clone(), now).unwrap();
    let branch = mine(&mut source, 12, now + 500);
    assert!(branch[0].challenge.height + WORK_RELEVANCE_DEPTH <= 12);

    let (path, mut node) = devnet("work-heavier-sync-target");
    for (offset, block) in main.iter().enumerate() {
        node.submit_block(block.clone(), now + offset as u64)
            .unwrap();
    }
    let engine = cpu();
    for block in &branch {
        engine.answer(block, true);
    }
    install(&mut node, None, Some(engine.clone()), None);
    let source = shared(source);
    let node = shared(node);

    let (result, _) = sync_once(&source, &node);
    assert_eq!(result.unwrap().accepted_blocks, 12);
    assert_eq!(engine.block_calls(), 12, "one run per block");
    let node_guard = node.lock().unwrap();
    assert_eq!(node_guard.state.tip(), branch[11].block_id());
    assert!(node_guard.pending_side_work().is_empty());
    drop(node_guard);
    drop((node, source, main_source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
    clean_test_dir(&main_path);
}

#[test]
fn deep_side_blocks_fetched_from_a_lighter_peer_run_nothing_and_count_against_its_address() {
    let now = unix_time_seconds().unwrap();
    let (main_path, mut main_source) = devnet("work-lighter-sync-main");
    let main = mine(&mut main_source, 12, now);
    let (path, mut node) = devnet("work-lighter-sync-target");
    for (offset, block) in main.iter().enumerate() {
        node.submit_block(block.clone(), now + offset as u64)
            .unwrap();
    }
    let engine = cpu();
    install(&mut node, None, Some(engine.clone()), None);
    let node = shared(node);
    let preverifier = node.lock().unwrap().block_preverifier();
    let peer = next_remote_proof_peer_id().unwrap();
    let from = fetched_from(false);

    // Ten different blocks at height 2, each one a lighter branch.
    let mut paths = Vec::new();
    let mut side = Vec::new();
    for index in 0..10 {
        let (side_path, mut side_source) = devnet(&format!("work-lighter-sync-side-{index}"));
        side_source.submit_block(main[0].clone(), now).unwrap();
        let block = mine(&mut side_source, 1, now + 600 + index).remove(0);
        engine.answer(&block, true);
        side.push(block);
        paths.push(side_path);
    }
    for (index, block) in side.iter().enumerate() {
        prewarm_fetched_work(&node, &preverifier, block, from, None).unwrap();
        let error = submit_fetched_block(&node, block.clone(), peer, from, None).unwrap_err();
        assert!(matches!(error, P2pError::Node(NodeError::WorkCheckPending)));
        let pending = node.lock().unwrap().pending_side_work();
        assert_eq!(
            pending.len(),
            (index + 1).min(MAX_PENDING_SIDE_WORK_PER_SENDER),
            "noted once"
        );
        assert!(
            pending
                .iter()
                .all(|noted| noted.sender == Some(from.block_sender()))
        );
    }
    assert_eq!(engine.block_calls(), 0, "no engine runs");

    // The same block from a peer that claims more work is computed.
    let heavier = FetchedFrom {
        heavier: true,
        ..from
    };
    prewarm_fetched_work(&node, &preverifier, &side[0], heavier, None).unwrap();
    assert_eq!(engine.block_calls(), 1);
    assert!(submit_fetched_block(&node, side[0].clone(), peer, heavier, None).unwrap());
    assert_eq!(engine.block_calls(), 1, "admitted from the memo");
    drop((node, main_source));
    clean_test_dir(&path);
    clean_test_dir(&main_path);
    for side_path in paths {
        clean_test_dir(&side_path);
    }
}

#[test]
fn known_invalid_inventory_is_never_downloaded_again_and_its_peer_is_not_ahead() {
    use crate::work_gate::tests::gpu;

    let (source_path, mut source) = devnet("work-known-invalid-source");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 3, now);
    let (path, mut node) = devnet("work-known-invalid-target");
    let (cpu_engine, gpu_engine) = (cpu(), gpu());
    for engine in [&cpu_engine, &gpu_engine] {
        engine.answer(&chain[0], true);
        engine.answer(&chain[1], false);
        engine.answer(&chain[2], true);
    }
    install(
        &mut node,
        None,
        Some(cpu_engine.clone()),
        Some(gpu_engine.clone()),
    );
    let runs = || cpu_engine.block_calls() + gpu_engine.block_calls();
    let source = shared(source);
    let node = shared(node);

    // The first session admits the first block and refuses the second; both
    // engines agree it does not match, so it is recorded invalid.
    let (first, _) = sync_once(&source, &node);
    assert!(matches!(
        first,
        Err(P2pError::Node(NodeError::WorkRecomputationMismatch(id))) if id == chain[1].block_id()
    ));
    assert_eq!(runs(), 3);
    assert_eq!(recorded(&node.lock().unwrap()), (1, 1));
    assert!(
        node.lock()
            .unwrap()
            .known_invalid_block(&chain[1].block_id())
    );

    // The next session ends before asking for it, with no penalty.
    let (second, address) = sync_once(&source, &node);
    let error = second.unwrap_err();
    assert!(matches!(
        error,
        P2pError::KnownInvalidInventory(id) if id == chain[1].block_id()
    ));
    assert_eq!(outbound_reputation_penalty(&error).0, 0);
    assert_eq!(runs(), 3, "the block was not checked again");

    let node_guard = node.lock().unwrap();
    assert_eq!(node_guard.peers_on_invalid_chain(), 1);
    assert_eq!(node_guard.invalid_chain_peer_events(), 1);
    let observation = observed_address(PeerDirection::Outbound, address);
    let status = node_guard.status().unwrap();
    let peer = status
        .peers
        .iter()
        .find(|peer| peer.address == observation)
        .unwrap();
    assert!(peer.on_invalid_chain);
    assert_eq!(peer.remote_tip, Some(hex::encode(chain[2].block_id())));
    drop(node_guard);

    // A peer that moves to another tip is no longer counted.
    node.lock().unwrap().record_peer_succeeded(
        PeerDirection::Outbound,
        observation,
        1,
        chain[0].block_id(),
        observation_time(),
    );
    assert_eq!(node.lock().unwrap().peers_on_invalid_chain(), 0);
    drop((source, node));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn one_engine_mismatch_is_not_downloaded_again_but_does_not_mark_its_peer() {
    let (source_path, mut source) = devnet("work-one-engine-source");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 2, now);
    let (path, mut node) = devnet("work-one-engine-target");
    let engine = cpu();
    engine.answer(&chain[0], true);
    engine.answer(&chain[1], false);
    install(&mut node, None, Some(engine.clone()), None);
    let source = shared(source);
    let node = shared(node);

    let (first, address) = sync_once(&source, &node);
    assert!(matches!(
        first,
        Err(P2pError::Node(NodeError::WorkMismatchUnconfirmed(id))) if id == chain[1].block_id()
    ));
    assert_eq!(
        recorded(&node.lock().unwrap()),
        (1, 0),
        "nothing is recorded invalid"
    );
    // Nor is the peer charged for it; it is held off as a sync target until
    // the refusal leaves its window.
    let security = PeerSecurity::default();
    hold_off_outbound_peer_after(&security, address, &first);
    assert!(outbound_sync_held_off(&security, address));
    assert_eq!(outbound_reputation_penalty(&first.unwrap_err()).0, 0);
    let (second, address) = sync_once(&source, &node);
    assert!(matches!(
        second,
        Err(P2pError::KnownInvalidInventory(id)) if id == chain[1].block_id()
    ));
    assert_eq!(engine.block_calls(), 2);

    // The peer's height still counts: this node may be the one that is wrong.
    let node_guard = node.lock().unwrap();
    assert_eq!(node_guard.peers_on_invalid_chain(), 0);
    assert_eq!(node_guard.invalid_chain_peer_events(), 0);
    let observation = observed_address(PeerDirection::Outbound, address);
    let status = node_guard.status().unwrap();
    let peer = status
        .peers
        .iter()
        .find(|peer| peer.address == observation)
        .unwrap();
    assert!(!peer.on_invalid_chain);
    drop(node_guard);
    drop((source, node));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_sync_peer_serving_blocks_that_fail_the_check_gets_one_check_and_is_then_skipped() {
    let (path, mut node) = devnet("work-outbound-cooldown-target");
    let now = unix_time_seconds().unwrap();
    // Two peers on one address, each with its own block at height 1.
    let mut sources = Vec::new();
    let mut blocks = Vec::new();
    for label in ["work-outbound-cooldown-a", "work-outbound-cooldown-b"] {
        let (source_path, mut source) = devnet(label);
        let block = mine(&mut source, 1, now + blocks.len() as u64).remove(0);
        blocks.push(block);
        sources.push((source_path, shared(source)));
    }
    assert_ne!(blocks[0].block_id(), blocks[1].block_id());
    // Both engines agree each block does not match: a confirmed mismatch.
    let (engine, gpu_engine) = (cpu(), crate::work_gate::tests::gpu());
    for block in &blocks {
        engine.answer(block, false);
        gpu_engine.answer(block, false);
    }
    install(
        &mut node,
        None,
        Some(engine.clone()),
        Some(gpu_engine.clone()),
    );
    let node = shared(node);
    let security = PeerSecurity::default();

    // The poll's own steps for one untrusted address.
    let mut sessions = 0;
    for (_, source) in &sources {
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        if outbound_sync_held_off(&security, peer) {
            continue;
        }
        let (result, address) = sync_once(source, &node);
        sessions += 1;
        assert!(matches!(
            result,
            Err(P2pError::Node(NodeError::WorkRecomputationMismatch(_)))
        ));
        hold_off_outbound_peer_after(&security, address, &result);
    }
    assert_eq!(sessions, 1);
    assert_eq!(engine.block_calls(), 1);
    let address = IpAddr::from([127, 0, 0, 1]);
    assert!(
        security
            .in_sync_holdoff_at(address, Instant::now())
            .unwrap()
    );
    assert!(
        !security
            .in_sync_holdoff_at(address, Instant::now() + OUTBOUND_WORK_REFUSAL_COOLDOWN)
            .unwrap()
    );
    // Its own submissions keep their cooldown, and nothing is charged to
    // its reputation.
    assert!(!security.in_proof_cooldown(address).unwrap());
    assert!(!security.is_banned(address).unwrap());

    // An operator-configured peer is never held off.
    let configured = PeerSecurity::default();
    let peer: SocketAddr = "127.0.0.1:2".parse().unwrap();
    configured.register_static_peers(&[peer]).unwrap();
    let (result, _) = sync_once(&sources[1].1, &node);
    assert!(result.is_err());
    hold_off_outbound_peer_after(&configured, peer, &result);
    assert!(!outbound_sync_held_off(&configured, peer));

    drop(node);
    clean_test_dir(&path);
    for (source_path, source) in sources {
        drop(source);
        clean_test_dir(&source_path);
    }
}

/// Serves `source` to one sync session on loopback; the thread returns how
/// many blocks the session asked for.
fn serve_one_session_counting_blocks(
    source: &Arc<Mutex<Node>>,
) -> (SocketAddr, thread::JoinHandle<usize>) {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let source = Arc::clone(source);
    let server = thread::spawn(move || {
        let (stream, _) = socket.accept().unwrap();
        let hello = with_nonce(source.lock().unwrap().peer_hello(), Some(SOURCE_NONCE));
        let mut connection =
            PeerConnection::from_stream(stream, PeerSession::new(hello, limits()).unwrap())
                .unwrap();
        connection.send_hello().unwrap();
        let mut requested = 0;
        loop {
            match connection.receive() {
                Ok(PeerMessage::Hello(_)) => {}
                Ok(PeerMessage::GetHeaders { locator, stop }) => {
                    let block_ids =
                        source
                            .lock()
                            .unwrap()
                            .inventory_after(&locator, stop, MAX_BLOCKS_PER_SYNC);
                    connection
                        .send(PeerMessage::Inventory { block_ids })
                        .unwrap();
                }
                Ok(PeerMessage::GetBlock { block_id }) => {
                    requested += 1;
                    let canonical = source
                        .lock()
                        .unwrap()
                        .canonical_block(block_id)
                        .unwrap()
                        .unwrap();
                    let block = decode_block(&canonical, hello.network_id).unwrap();
                    if connection.send(PeerMessage::Block(block)).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        requested
    });
    (address, server)
}

#[test]
fn a_sync_peer_whose_blocks_one_engine_refuses_is_held_off_uncharged_and_then_not_downloaded_from()
{
    use crate::work_gate::MAX_LONE_REFUSALS_PER_SENDER;
    use crate::work_gate::tests::competing_blocks;

    let now = unix_time_seconds().unwrap();
    // Peers on one address, each serving its own block at height 1.
    let (source_paths, blocks) = competing_blocks(
        "work-lone-sync-source",
        MAX_LONE_REFUSALS_PER_SENDER + 2,
        now,
    );
    let engine = cpu();
    for block in &blocks {
        engine.answer(block, false);
    }
    let sources = source_paths
        .iter()
        .map(|source_path| {
            shared(Node::open_with_profile(source_path, crate::DEVNET_PROFILE).unwrap())
        })
        .collect::<Vec<_>>();
    let (path, mut node) = devnet("work-lone-sync-target");
    install(&mut node, None, Some(engine.clone()), None);
    let node = shared(node);
    let security = Arc::new(PeerSecurity::default());
    let options = PeerPollOptions {
        nonce_override: None,
        discovery: None,
        security: Arc::clone(&security),
        relay_backoff: Arc::new(RelayBackoff::default()),
    };
    let sender = IpAddr::from([127, 0, 0, 1]);
    // The poll's own steps after a session with one untrusted address. A
    // poll would skip a held-off peer; the sessions here run regardless.
    let after_session = |address: SocketAddr, result: &Result<SyncReport, P2pError>| {
        hold_off_outbound_peer_after(&security, address, result);
        assert!(!record_poll_sync_result(&options, address, result));
        if let Err(error) = result {
            assert_eq!(outbound_reputation_penalty(error).0, 0);
        }
    };
    let held_off_until_the_window_ends = || {
        let now = Instant::now();
        security.in_sync_holdoff_at(sender, now).unwrap()
            && !security
                .in_sync_holdoff_at(
                    sender,
                    now + crate::work_gate::LONE_REFUSAL_WINDOW + Duration::from_secs(1),
                )
                .unwrap()
    };

    for (index, source) in sources
        .iter()
        .take(MAX_LONE_REFUSALS_PER_SENDER)
        .enumerate()
    {
        let (result, address) = sync_once_from(source, &node, false);
        assert!(
            matches!(&result, Err(P2pError::Node(NodeError::WorkMismatchUnconfirmed(id))) if *id == blocks[index].block_id()),
            "{result:?}"
        );
        after_session(address, &result);
        assert!(held_off_until_the_window_ends());
    }

    // With its refusals used up, a session from the address ends before it
    // asks for a block.
    let (address, server) =
        serve_one_session_counting_blocks(&sources[MAX_LONE_REFUSALS_PER_SENDER]);
    let result = sync_from_peer_once_inner_with_policy(
        Arc::clone(&node),
        address,
        limits(),
        PeerAddressPolicy::PrivateOnly,
        Some(TARGET_NONCE),
        None,
        false,
    );
    assert!(
        matches!(result, Err(P2pError::Node(NodeError::WorkCheckDeferred))),
        "{result:?}"
    );
    assert_eq!(server.join().unwrap(), 0, "no block was downloaded");
    after_session(address, &result);
    assert!(held_off_until_the_window_ends());
    assert_eq!(engine.block_calls(), MAX_LONE_REFUSALS_PER_SENDER);
    assert_eq!(reputation_score(&security, sender), 0);
    assert!(!security.in_proof_cooldown(sender).unwrap());
    assert!(!security.is_banned(sender).unwrap());

    // A block recorded verified meanwhile is downloaded and admitted, as
    // admission would let it through.
    crate::work_gate::test_support::mark_verified(
        &node.lock().unwrap(),
        1,
        blocks[MAX_LONE_REFUSALS_PER_SENDER].block_id(),
    );
    let (address, server) =
        serve_one_session_counting_blocks(&sources[MAX_LONE_REFUSALS_PER_SENDER]);
    // (The one-session server closes at the session's later requests.)
    let _ = sync_from_peer_once_inner_with_policy(
        Arc::clone(&node),
        address,
        limits(),
        PeerAddressPolicy::PrivateOnly,
        Some(TARGET_NONCE),
        None,
        false,
    );
    assert_eq!(server.join().unwrap(), 1);
    assert!(
        node.lock()
            .unwrap()
            .contains_block(blocks[MAX_LONE_REFUSALS_PER_SENDER].block_id())
    );
    assert_eq!(engine.block_calls(), MAX_LONE_REFUSALS_PER_SENDER);

    // An operator-configured or bootstrap peer on the address is neither
    // counted nor held off.
    let (address, server) = serve_one_session_counting_blocks(sources.last().unwrap());
    let result = sync_from_peer_once_inner_with_policy(
        Arc::clone(&node),
        address,
        limits(),
        PeerAddressPolicy::PrivateOnly,
        Some(TARGET_NONCE),
        None,
        true,
    );
    assert!(
        matches!(
            result,
            Err(P2pError::Node(NodeError::WorkMismatchUnconfirmed(_)))
        ),
        "{result:?}"
    );
    assert_eq!(server.join().unwrap(), 1);
    assert_eq!(engine.block_calls(), MAX_LONE_REFUSALS_PER_SENDER + 1);
    let configured = PeerSecurity::default();
    configured.register_static_peers(&[address]).unwrap();
    hold_off_outbound_peer_after(&configured, address, &result);
    assert!(!outbound_sync_held_off(&configured, address));

    drop((sources, node));
    clean_test_dir(&path);
    for source_path in source_paths {
        clean_test_dir(&source_path);
    }
}

#[test]
fn one_host_is_one_sender_across_its_ipv6_64_and_mapped_ipv4() {
    let address = |text: &str| PeerReputationKey::from_ip(text.parse().unwrap()).address();
    assert_eq!(
        address("2001:db8:1:2::1"),
        address("2001:db8:1:2:ffff:ffff:ffff:fffe")
    );
    assert_ne!(address("2001:db8:1:2::1"), address("2001:db8:1:3::1"));
    assert_eq!(address("::ffff:198.51.100.7"), address("198.51.100.7"));
    assert_ne!(address("198.51.100.7"), address("198.51.100.8"));
}

#[test]
fn configured_and_bootstrap_peers_are_trusted_and_others_are_not() {
    let security = PeerSecurity::default();
    let configured: SocketAddr = "198.51.100.20:29454".parse().unwrap();
    let bootstrap: SocketAddr = "198.51.100.21:29454".parse().unwrap();
    let other: IpAddr = "198.51.100.22".parse().unwrap();
    security.register_static_peers(&[configured]).unwrap();
    security.register_bootstrap_peers(&[bootstrap]).unwrap();
    // Any port of a trusted address.
    assert!(security.is_trusted_peer(configured.ip()).unwrap());
    assert!(security.is_trusted_peer(bootstrap.ip()).unwrap());
    assert!(!security.is_trusted_peer(other).unwrap());
    // A bootstrap peer is not treated as configured for anything else.
    assert!(!security.compresses_blocks(bootstrap.ip()).unwrap());
}

#[test]
fn a_block_submitted_over_loopback_waits_for_the_work_lane_as_priority() {
    use crate::work_gate::test_support::lane_waiters;

    // Two blocks at height 1 from different sources.
    let (first_path, mut first_source) = devnet("work-loopback-first");
    let (second_path, mut second_source) = devnet("work-loopback-second");
    let now = unix_time_seconds().unwrap();
    let held = mine(&mut first_source, 1, now).remove(0);
    let relayed = mine(&mut second_source, 1, now + 1).remove(0);
    let (path, mut node) = devnet("work-loopback-target");
    let engine = cpu();
    engine.answer(&held, true);
    engine.answer(&relayed, true);
    install(&mut node, None, Some(engine.clone()), None);
    let node = shared(node);

    // A remote block's job holds the lane.
    let barrier = engine.hold_next();
    let request = RemoteProofRequest::new(Instant::now() + Duration::from_secs(30));
    let holder = {
        let (node, request) = (Arc::clone(&node), request.clone());
        let peer = next_remote_proof_peer_id().unwrap();
        thread::spawn(move || {
            crate::submit_shared_peer_block_cancellable(&node, held, now, peer, request)
        })
    };
    barrier.wait();

    // A peer on this machine submits the other block over P2P.
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let listener =
        spawn_inbound_listener_inner(Arc::clone(&node), socket, limits(), Some(TARGET_NONCE))
            .unwrap();
    let second_source = shared(second_source);
    let relay = {
        let source = Arc::clone(&second_source);
        thread::spawn(move || {
            relay_blocks_to_peer_once_inner_with_policy(
                source,
                address,
                limits(),
                PeerAddressPolicy::PrivateOnly,
                Some(SOURCE_NONCE),
                None,
            )
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while lane_waiters(&node.lock().unwrap()) != (0, 1) {
        assert!(
            Instant::now() < deadline,
            "the relayed block never waited as priority"
        );
        thread::sleep(Duration::from_millis(10));
    }

    request.cancel();
    assert!(holder.join().unwrap().is_err());
    let report = relay.join().unwrap().unwrap();
    assert_eq!(report.accepted_blocks, 1);
    assert_eq!(node.lock().unwrap().peer_hello().tip, relayed.block_id());
    listener.stop().unwrap();
    drop((node, second_source, first_source));
    clean_test_dir(&path);
    clean_test_dir(&first_path);
    clean_test_dir(&second_path);
}

/// Relays `source`'s blocks over loopback to a listener on `target`, twice,
/// and returns both results and the listener's peer security once every
/// session has ended.
fn relay_twice(
    source: &Arc<Mutex<Node>>,
    target: &Arc<Mutex<Node>>,
) -> (Vec<Result<RelayReport, P2pError>>, Arc<PeerSecurity>) {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let listener =
        spawn_inbound_listener_inner(Arc::clone(target), socket, limits(), Some(TARGET_NONCE))
            .unwrap();
    let results = (0..2)
        .map(|_| {
            relay_blocks_to_peer_once_inner_with_policy(
                Arc::clone(source),
                address,
                limits(),
                PeerAddressPolicy::PrivateOnly,
                Some(SOURCE_NONCE),
                None,
            )
        })
        .collect();
    let security = Arc::clone(&listener.security);
    // Joins every session, so each verdict's penalty has been applied.
    listener.stop().unwrap();
    (results, security)
}

fn reputation_score(security: &PeerSecurity, ip: IpAddr) -> u16 {
    security
        .state
        .lock()
        .unwrap()
        .reputations
        .get(&PeerReputationKey::from_ip(ip))
        .map_or(0, |entry| entry.score)
}

#[test]
fn a_submitted_block_one_engine_finds_wrong_is_refused_once_and_costs_its_sender_nothing() {
    let (source_path, mut source) = devnet("work-unconfirmed-submit-source");
    let now = unix_time_seconds().unwrap();
    let block = mine(&mut source, 1, now).remove(0);
    let block_id = block.block_id();
    let source = shared(source);
    let sender = IpAddr::from([127, 0, 0, 1]);

    // One engine: refused, remembered, and never run again for a re-send.
    let (path, mut node) = devnet("work-unconfirmed-submit-target");
    let engine = cpu();
    engine.answer(&block, false);
    let checker = install(&mut node, None, Some(engine.clone()), None);
    let node = shared(node);
    let (results, security) = relay_twice(&source, &node);
    for result in &results {
        assert!(
            matches!(result, Err(P2pError::RejectedBlockSubmission(id)) if *id == block_id),
            "{result:?}"
        );
    }
    assert_eq!(engine.block_calls(), 1, "the re-send ran no engine");
    assert_eq!(checker.alarms().own_engine_mismatches, 1);
    {
        let node = node.lock().unwrap();
        assert!(!node.index.contains(block_id));
        assert!(node.unconfirmed_work_rejection(&block_id));
        assert_eq!(recorded(&node), (0, 0));
    }
    // Each clean session credits some back, but two charged refusals would
    // still leave a score (see the two-engine case below).
    assert_eq!(reputation_score(&security, sender), 0);
    assert!(!security.in_proof_cooldown(sender).unwrap());
    assert!(!security.is_banned(sender).unwrap());

    // Two engines that agree: refused and recorded invalid, and the sender
    // is charged and held off.
    let (confirmed_path, mut confirmed) = devnet("work-confirmed-submit-target");
    let (cpu_engine, gpu_engine) = (cpu(), crate::work_gate::tests::gpu());
    cpu_engine.answer(&block, false);
    gpu_engine.answer(&block, false);
    install(
        &mut confirmed,
        None,
        Some(cpu_engine.clone()),
        Some(gpu_engine.clone()),
    );
    let confirmed = shared(confirmed);
    let (results, security) = relay_twice(&source, &confirmed);
    assert!(
        matches!(&results[0], Err(P2pError::RejectedBlockSubmission(id)) if *id == block_id),
        "{:?}",
        results[0]
    );
    assert!(results[1].is_err(), "held off or refused at once");
    assert_eq!((cpu_engine.block_calls(), gpu_engine.block_calls()), (1, 1));
    assert_eq!(recorded(&confirmed.lock().unwrap()), (0, 1));
    // Charged once; each of the two sessions then ended cleanly.
    assert_eq!(
        reputation_score(&security, sender),
        INVALID_BLOCK_PENALTY - 2 * CLEAN_SESSION_CREDIT
    );
    assert!(security.in_proof_cooldown(sender).unwrap());

    drop((node, confirmed, source));
    clean_test_dir(&path);
    clean_test_dir(&confirmed_path);
    clean_test_dir(&source_path);
}

#[test]
fn a_submitted_block_two_engines_later_find_wrong_charges_the_peer_that_sent_it() {
    let now = unix_time_seconds().unwrap();
    let (main_path, mut main_source) = devnet("work-blame-relay-main");
    let main = mine(&mut main_source, 10, now);
    let (source_path, mut source) = devnet("work-blame-relay-source");
    for (offset, block) in main[..2].iter().enumerate() {
        source
            .submit_block(block.clone(), now + offset as u64)
            .unwrap();
    }
    let side = mine(&mut source, 1, now + 1_000).remove(0);
    let side_id = side.block_id();

    let (path, mut node) = devnet("work-blame-relay-target");
    for (offset, block) in main.iter().enumerate() {
        node.submit_block(block.clone(), now + offset as u64)
            .unwrap();
    }
    let (cpu_engine, gpu_engine) = (cpu(), crate::work_gate::tests::gpu());
    for engine in [&cpu_engine, &gpu_engine] {
        for block in &main {
            engine.answer(block, true);
        }
        engine.answer(&side, false);
    }
    install(
        &mut node,
        None,
        Some(cpu_engine.clone()),
        Some(gpu_engine.clone()),
    );
    let node = shared(node);

    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let listener =
        spawn_inbound_listener_inner(Arc::clone(&node), socket, limits(), Some(TARGET_NONCE))
            .unwrap();
    let result = submit_mined_block_once_with_policy(
        address,
        side.clone(),
        limits(),
        PeerAddressPolicy::PrivateOnly,
    )
    .unwrap();
    let security = Arc::clone(&listener.security);
    listener.stop().unwrap();
    assert_eq!(
        result.status,
        BlockSubmissionStatus::Busy,
        "the side block waits"
    );
    let sender = IpAddr::from([127, 0, 0, 1]);
    assert_eq!(
        node.lock().unwrap().pending_side_work()[0].sender,
        Some(BlockSender {
            address: sender,
            fetched: false,
            trusted: true,
        })
    );
    assert_eq!((cpu_engine.block_calls(), gpu_engine.block_calls()), (0, 0));
    assert_eq!(reputation_score(&security, sender), 0);
    assert!(!security.in_proof_cooldown(sender).unwrap());

    // The background check (the stored blocks first): both engines find it
    // wrong, and the listener's peer security charges the peer that sent it
    // and holds it off.
    let mut backlog = crate::work_gate::WorkBacklog::new();
    let mut invalid = 0;
    loop {
        match backlog.run_turn(&node, &|| false).unwrap() {
            crate::work_gate::WorkBacklogTurn::Idle => break,
            crate::work_gate::WorkBacklogTurn::Checked(
                crate::work_gate::WorkBacklogOutcome::Invalid,
            ) => invalid += 1,
            crate::work_gate::WorkBacklogTurn::Checked(_) => {}
            turn => panic!("unexpected turn {turn:?}"),
        }
    }
    assert_eq!(invalid, 1);
    assert_eq!(reputation_score(&security, sender), INVALID_BLOCK_PENALTY);
    assert!(security.in_proof_cooldown(sender).unwrap());
    assert!(!node.lock().unwrap().index.contains(side_id));

    drop((node, source, main_source));
    for path in [path, source_path, main_path] {
        clean_test_dir(&path);
    }
}
