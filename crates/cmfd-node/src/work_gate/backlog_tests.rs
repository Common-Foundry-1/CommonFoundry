use super::*;
use crate::honest_work::store::{WorkStatus, read_work_halt};
use crate::honest_work::{ConfirmedWorkMismatch, WorkAlarmCounts};
use crate::tests::clean_test_dir;
use crate::work_gate::WorkBlame;
use crate::work_gate::test_support::{ScriptedEngine, install, provisional, recorded};
use crate::work_gate::tests::{cpu, devnet, gpu, mine, shared};
use crate::{DEVNET_PROFILE, submit_shared_block, submit_shared_tip_block, unix_time_seconds};
use cmfd_consensus::{Block, ForgeMatrixV4WorkRule};

/// Runs turns until one is idle; returns the others.
fn drain(node: &Mutex<Node>) -> Vec<WorkBacklogTurn> {
    let mut backlog = WorkBacklog::new();
    let mut turns = Vec::new();
    loop {
        match backlog.run_turn(node, &|| false).unwrap() {
            WorkBacklogTurn::Idle => return turns,
            turn => turns.push(turn),
        }
        assert!(turns.len() < 1_000, "the backlog never went idle");
    }
}

fn validated(node: &Mutex<Node>) -> Option<u64> {
    node.lock().unwrap().work_validated_height()
}

fn store_status(node: &Mutex<Node>, block_id: [u8; 32]) -> Option<WorkStatus> {
    node.lock()
        .unwrap()
        .work_gate
        .as_ref()
        .unwrap()
        .status(&block_id)
}

/// Stores `blocks` on `node` with no work rule, as an earlier release would
/// have.
fn store_before_the_rule(node: &Arc<Mutex<Node>>, blocks: &[Block], start: u64) {
    for (offset, block) in blocks.iter().enumerate() {
        submit_shared_block(node, block.clone(), start + offset as u64).unwrap();
    }
}

#[test]
fn stored_blocks_are_checked_in_order_once_and_not_again_after_a_restart() {
    let (source_path, mut source) = devnet("backlog-source-a");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 10, now);
    let (path, node) = devnet("backlog-restart");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);

    let engine = cpu();
    for block in &chain {
        engine.answer(block, true);
    }
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    assert_eq!(validated(&node), Some(0));

    // Before the node opens its network services: until the validated height
    // is within the relevance depth of the tip.
    let report = run_work_backlog_exclusive(&node, &AtomicBool::new(false)).unwrap();
    assert_eq!(
        report,
        WorkBacklogReport {
            checked: 4,
            validated_height: Some(4),
            tip_height: 10,
            halted: false,
        }
    );
    // The rest in the background, lowest first.
    let mut backlog = WorkBacklog::new();
    for height in 5..=10 {
        assert_eq!(
            backlog.run_turn(&node, &|| false).unwrap(),
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
        );
        assert_eq!(validated(&node), Some(height));
    }
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Idle
    );
    assert_eq!(engine.block_calls(), 10);

    // A restart reads the verified set back and checks nothing again.
    drop(node);
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    let engine = cpu();
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    assert_eq!(validated(&node), Some(10));
    assert!(drain(&node).is_empty());
    let report = run_work_backlog_exclusive(&node, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.checked, 0);
    assert_eq!(engine.block_calls(), 0);
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn side_blocks_go_first_and_only_those_descending_from_the_checkpoint() {
    let (source_path, mut source) = devnet("backlog-source-b");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 5, now);
    // A lighter branch from genesis, stored as a side branch.
    let (fork_path, mut fork) = devnet("backlog-fork-b");
    let branch = mine(&mut fork, 4, now + 100);
    let (path, node) = devnet("backlog-side");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    store_before_the_rule(&node, &branch, now + 100);
    assert_eq!(node.lock().unwrap().state.tip(), chain[4].block_id());

    // Checkpoint at height 2 of the active chain: the branch's blocks above
    // it descend from another block at height 2.
    let rule = ForgeMatrixV4WorkRule::with_pinned_heights(2, chain[1].block_id(), []).unwrap();
    let engine = cpu();
    for block in chain.iter().chain(&branch) {
        engine.answer(block, true);
    }
    install(
        &mut node.lock().unwrap(),
        Some(rule),
        Some(engine.clone()),
        None,
    );
    assert_eq!(validated(&node), Some(2));
    assert_eq!(drain(&node).len(), 3);
    for block in &branch {
        assert_eq!(store_status(&node, block.block_id()), None);
    }
    assert_eq!(validated(&node), Some(5));
    assert_eq!(engine.block_calls(), 3, "nothing ran for the branch");

    // From genesis, the branch's blocks go first.
    let (path_b, node_b) = devnet("backlog-side-genesis");
    let node_b = shared(node_b);
    store_before_the_rule(&node_b, &chain, now);
    store_before_the_rule(&node_b, &branch, now + 100);
    install(
        &mut node_b.lock().unwrap(),
        None,
        Some(engine.clone()),
        None,
    );
    let mut backlog = WorkBacklog::new();
    for block in &branch {
        backlog.run_turn(&node_b, &|| false).unwrap();
        assert_eq!(
            store_status(&node_b, block.block_id()),
            Some(WorkStatus::Verified)
        );
        assert_eq!(validated(&node_b), Some(0));
    }
    assert_eq!(drain(&node_b).len(), 5);
    assert_eq!(validated(&node_b), Some(5));
    drop((node, node_b, source, fork));
    for path in [path, path_b, source_path, fork_path] {
        clean_test_dir(&path);
    }
}

#[test]
fn an_active_block_both_engines_find_wrong_halts_the_node_until_an_operator_acts() {
    let (source_path, mut source) = devnet("backlog-source-c");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 5, now);
    let (fork_path, mut fork) = devnet("backlog-fork-c");
    let branch = mine(&mut fork, 2, now + 100);
    let (path, node) = devnet("backlog-halt");
    let node = shared(node);
    store_before_the_rule(&node, &chain[..4], now);
    store_before_the_rule(&node, &branch, now + 100);
    let (cpu, gpu) = (cpu(), gpu());
    for block in chain.iter().chain(&branch) {
        cpu.answer(block, true);
        gpu.answer(block, true);
    }
    // The first side block and the third active block do not match.
    for engine in [&cpu, &gpu] {
        engine.answer(&branch[0], false);
        engine.answer(&chain[2], false);
    }
    install(
        &mut node.lock().unwrap(),
        None,
        Some(cpu.clone()),
        Some(gpu.clone()),
    );

    let mut backlog = WorkBacklog::new();
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Invalid)
    );
    assert_eq!(
        store_status(&node, branch[0].block_id()),
        Some(WorkStatus::Invalid)
    );
    assert!(
        !path.join(WORK_HALT_FILE).exists(),
        "a side block only freezes"
    );
    // Its child is not checked: it builds on an invalid block.
    let turns: Vec<_> = (0..3)
        .map(|_| backlog.run_turn(&node, &|| false).unwrap())
        .collect();
    assert_eq!(
        turns,
        [
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified),
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified),
            WorkBacklogTurn::Halted,
        ]
    );
    assert_eq!(store_status(&node, branch[1].block_id()), None);
    assert_eq!(
        store_status(&node, chain[2].block_id()),
        Some(WorkStatus::Invalid)
    );
    assert_eq!(validated(&node), Some(2));
    let network_id = node.lock().unwrap().params.network_id;
    let halt = read_work_halt(&path.join(WORK_HALT_FILE), network_id)
        .unwrap()
        .unwrap();
    assert_eq!((halt.height, halt.block_id), (3, chain[2].block_id()));
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Halted
    );
    assert!(matches!(
        submit_shared_block(&node, chain[4].clone(), now + 4),
        Err(NodeError::WorkRuleHalted)
    ));

    // A restart stays halted: nothing is removed automatically.
    drop(node);
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    install(
        &mut node.lock().unwrap(),
        None,
        Some(cpu.clone()),
        Some(gpu.clone()),
    );
    assert_eq!(node.lock().unwrap().state.tip(), chain[3].block_id());
    let report = run_work_backlog_exclusive(&node, &AtomicBool::new(false)).unwrap();
    assert!(report.halted);
    assert_eq!(report.checked, 0);

    // The operator quarantines the halted block on the stopped node.
    assert!(matches!(
        crate::storage::quarantine_block_log_from_block(
            &path,
            DEVNET_PROFILE,
            None,
            &path.join("evidence")
        ),
        Err(NodeError::DataDirLocked(_))
    ));
    drop(node);
    let log_bytes = std::fs::metadata(path.join(BLOCK_LOG_FILE)).unwrap().len();
    let evidence = path.join("evidence");
    let report =
        crate::storage::quarantine_block_log_from_block(&path, DEVNET_PROFILE, None, &evidence)
            .unwrap();
    assert_eq!(report.block_id, hex::encode(chain[2].block_id()));
    assert!(report.halt_cleared);
    // The halted block, the active block after it and the side branch.
    assert_eq!((report.from_record, report.removed_records), (2, 4));
    assert_eq!(
        std::fs::metadata(&evidence).unwrap().len(),
        log_bytes - report.retained_log_bytes
    );
    assert_eq!(
        std::fs::metadata(path.join(BLOCK_LOG_FILE)).unwrap().len(),
        report.retained_log_bytes
    );
    assert!(!path.join(WORK_HALT_FILE).exists());

    // It reopens at the parent, refuses the removed block, and follows an
    // honest block in its place.
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    install(
        &mut node.lock().unwrap(),
        None,
        Some(cpu.clone()),
        Some(gpu.clone()),
    );
    assert_eq!(node.lock().unwrap().state.tip(), chain[1].block_id());
    assert!(matches!(
        submit_shared_block(&node, chain[2].clone(), now + 2),
        Err(NodeError::CachedInvalidBlock(id)) if id == chain[2].block_id()
    ));
    let (sibling_path, sibling_source) = devnet("backlog-sibling-c");
    let sibling_source = shared(sibling_source);
    store_before_the_rule(&sibling_source, &chain[..2], now);
    let sibling = mine(&mut sibling_source.lock().unwrap(), 1, now + 50);
    cpu.answer(&sibling[0], true);
    gpu.answer(&sibling[0], true);
    submit_shared_block(&node, sibling[0].clone(), now + 50).unwrap();
    assert_eq!(node.lock().unwrap().state.tip(), sibling[0].block_id());
    assert_eq!(validated(&node), Some(3));
    drop((node, source, fork, sibling_source));
    for path in [path, source_path, fork_path, sibling_path] {
        clean_test_dir(&path);
    }
}

/// The warn lines on target `work_rule` that `action` logs on this thread.
fn work_rule_warnings<T>(action: impl FnOnce() -> T) -> (T, String) {
    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let lines = Lines::default();
    let writer = lines.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let result = tracing::subscriber::with_default(subscriber, action);
    let bytes = lines.0.lock().unwrap().clone();
    (result, String::from_utf8(bytes).unwrap())
}

#[test]
fn a_stored_block_one_engine_refuses_tells_the_operator_what_reconsider_does_not_do() {
    let (source_path, mut source) = devnet("backlog-source-one-engine-text");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 1, now);
    let (path, node) = devnet("backlog-one-engine-text");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    let engine = cpu();
    engine.answer(&chain[0], false);
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    let (turn, warnings) =
        work_rule_warnings(|| WorkBacklog::new().run_turn(&node, &|| false).unwrap());
    assert_eq!(
        turn,
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)
    );
    assert!(
        warnings
            .contains("`cmfd-node work-reconsider <block id>` only makes this node check it again"),
        "{warnings}"
    );
    assert!(
        warnings.contains("needs a release that moves the checkpoint past it"),
        "{warnings}"
    );
    assert!(!warnings.contains("clears the record"), "{warnings}");
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_single_engine_mismatch_on_the_active_chain_lags_and_alarms_without_halting() {
    let (source_path, mut source) = devnet("backlog-source-d");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 12, now);
    let (path, node) = devnet("backlog-own-engine");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    let engine = cpu();
    for block in &chain {
        engine.answer(block, true);
    }
    engine.answer(&chain[1], false);
    let checker = install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);

    // The startup run does not wait for a verdict it cannot reach.
    let report = run_work_backlog_exclusive(&node, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.validated_height, Some(1));
    assert!(!report.halted);
    assert_eq!(report.checked, 12);
    assert_eq!(
        checker.alarms(),
        WorkAlarmCounts {
            own_engine_mismatches: 1,
            ..WorkAlarmCounts::default()
        }
    );
    assert_eq!(store_status(&node, chain[1].block_id()), None);
    assert_eq!(recorded(&node.lock().unwrap()), (11, 0));
    assert!(!path.join(WORK_HALT_FILE).exists());
    // Status names the block that holds the validated height.
    let unsettled_height = |node: &Mutex<Node>| {
        let node = node.lock().unwrap();
        let held = node.work_validated_height_held_by_unsettled_block();
        let status = node.work_rule_status().unwrap();
        assert_eq!(held, status.unsettled_height.is_some());
        assert_eq!(
            status.unsettled_block_id,
            status
                .unsettled_height
                .map(|height| hex::encode(node.index.active_chain[height as usize]))
        );
        status.unsettled_height
    };
    assert_eq!(unsettled_height(&node), Some(2));

    // A restart computes it once more on the same kind of engine, and then
    // not again until its retry is due.
    drop(node);
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    let engine = cpu();
    engine.answer(&chain[1], false);
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    let report = run_work_backlog_exclusive(&node, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.checked, 1);
    assert!(drain(&node).is_empty());
    assert_eq!(engine.block_calls(), 1);
    assert_eq!(validated(&node), Some(1));
    // Once the retry is due it is computed again, not answered from the memo.
    let gate = node.lock().unwrap().work_gate.clone().unwrap();
    lock(&gate.one_engine_retry).clear();
    assert_eq!(
        drain(&node),
        [WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)]
    );
    assert_eq!(engine.block_calls(), 2);
    assert!(drain(&node).is_empty());
    // An independent engine settles it.
    let (cpu, gpu) = (cpu(), gpu());
    for engine in [&cpu, &gpu] {
        engine.answer(&chain[1], false);
    }
    drop(node);
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    install(
        &mut node.lock().unwrap(),
        None,
        Some(cpu.clone()),
        Some(gpu.clone()),
    );
    assert_eq!(
        WorkBacklog::new().run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Halted
    );
    assert_eq!(
        store_status(&node, chain[1].block_id()),
        Some(WorkStatus::Invalid)
    );
    assert_eq!(unsettled_height(&node), None);
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_provisional_block_this_node_finds_wrong_no_longer_counts_as_verified() {
    let (source_path, mut source) = devnet("backlog-source-k");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 2, now);
    let (path, mut node) = devnet("backlog-provisional-wrong");
    let checker = install(&mut node, None, None, Some(gpu()));
    let node = shared(node);
    for block in &chain {
        let (challenge, digest) = ScriptedEngine::digests(block);
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge, digest, 0,
        ));
    }
    submit_shared_tip_block(&node, chain[0].clone(), now).unwrap();
    submit_shared_tip_block(&node, chain[1].clone(), now + 1).unwrap();
    drop(node);

    // On a node with one engine, which does not reproduce the first block.
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    let engine = cpu();
    engine.answer(&chain[0], false);
    engine.answer(&chain[1], true);
    let checker = install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    assert_eq!(validated(&node), Some(2));
    assert_eq!(
        drain(&node),
        [
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled),
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified),
        ]
    );
    assert_eq!(validated(&node), Some(0));
    assert_eq!(store_status(&node, chain[0].block_id()), None);
    assert!(provisional(&node.lock().unwrap()).is_empty());
    assert_eq!(
        checker.alarms(),
        WorkAlarmCounts {
            engine_divergence: 1,
            own_engine_mismatches: 1,
            ..WorkAlarmCounts::default()
        }
    );
    // The pool's word does not bring it back.
    let (challenge, digest) = ScriptedEngine::digests(&chain[0]);
    checker.record_honest(crate::honest_work::PoolReplayResult::new(
        challenge, digest, 0,
    ));
    assert!(drain(&node).is_empty());
    assert_eq!(validated(&node), Some(0));

    // Nor does a restart, which computes it once more on this node's own
    // engine.
    drop(node);
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    let engine = cpu();
    engine.answer(&chain[0], false);
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    assert_eq!(validated(&node), Some(0));
    assert_eq!(
        drain(&node),
        [WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)]
    );
    assert_eq!(engine.block_calls(), 1);
    assert_eq!(validated(&node), Some(0));
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_provisional_block_found_invalid_halts_after_a_restart_and_quarantine_clears_the_halt() {
    let (source_path, mut source) = devnet("backlog-source-l");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 3, now);
    let (path, mut node) = devnet("backlog-provisional-invalid");
    let checker = install(&mut node, None, None, Some(gpu()));
    let node = shared(node);
    for block in &chain {
        let (challenge, digest) = ScriptedEngine::digests(block);
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge, digest, 0,
        ));
    }
    for (offset, block) in chain.iter().enumerate() {
        submit_shared_tip_block(&node, block.clone(), now + offset as u64).unwrap();
    }
    drop(node);

    let (cpu, gpu) = (cpu(), gpu());
    for engine in [&cpu, &gpu] {
        engine.answer(&chain[0], true);
        engine.answer(&chain[1], false);
        engine.answer(&chain[2], true);
    }
    let reopen = || {
        let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
        install(
            &mut node.lock().unwrap(),
            None,
            Some(cpu.clone()),
            Some(gpu.clone()),
        );
        node
    };
    let node = reopen();
    let network_id = node.lock().unwrap().params.network_id;
    assert_eq!(validated(&node), Some(3));
    let mut backlog = WorkBacklog::new();
    let turns: Vec<_> = (0..2)
        .map(|_| backlog.run_turn(&node, &|| false).unwrap())
        .collect();
    assert_eq!(
        turns,
        [
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified),
            WorkBacklogTurn::Halted,
        ]
    );
    // The provisional block is invalid now: the validated height drops below
    // it, so pruning cannot reach it either.
    assert_eq!(validated(&node), Some(1));
    assert_eq!(
        store_status(&node, chain[1].block_id()),
        Some(WorkStatus::Invalid)
    );

    // Had the marker not been written, a restart halts all the same.
    drop(node);
    std::fs::remove_file(path.join(WORK_HALT_FILE)).unwrap();
    let node = reopen();
    {
        let node = node.lock().unwrap();
        assert!(node.work_rule_halted());
        assert_eq!(node.work_halted_block(), Some(chain[1].block_id()));
    }
    let next = mine(&mut source, 1, now + 3);
    assert!(matches!(
        submit_shared_block(&node, next[0].clone(), now + 3),
        Err(NodeError::WorkRuleHalted)
    ));
    drop(node);

    // An operator who removes an earlier block removes the halted one with
    // it, and the marker goes too.
    let write_marker = || {
        let (challenge, _) = ScriptedEngine::digests(&chain[1]);
        let confirmed = ConfirmedWorkMismatch::for_test(challenge, [0; 32]);
        write_work_halt(
            &path.join(WORK_HALT_FILE),
            network_id,
            2,
            chain[1].block_id(),
            challenge,
            &confirmed,
        )
        .unwrap();
    };
    write_marker();
    let report = crate::storage::quarantine_block_log_from_block(
        &path,
        DEVNET_PROFILE,
        Some(chain[0].block_id()),
        &path.join("evidence-a"),
    )
    .unwrap();
    assert_eq!((report.from_record, report.removed_records), (0, 3));
    assert!(report.halt_cleared);
    assert!(!path.join(WORK_HALT_FILE).exists());

    // A marker left for a block no longer stored is cleared on its own.
    write_marker();
    let report = crate::storage::quarantine_block_log_from_block(
        &path,
        DEVNET_PROFILE,
        None,
        &path.join("evidence-b"),
    )
    .unwrap();
    assert_eq!(report.removed_records, 0);
    assert!(report.halt_cleared);
    assert_eq!(std::fs::metadata(path.join("evidence-b")).unwrap().len(), 0);
    let node = reopen();
    assert!(!node.lock().unwrap().work_rule_halted());
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn the_startup_run_checks_active_blocks_only_and_ends_while_the_engine_is_not_ready() {
    let (source_path, mut source) = devnet("backlog-source-m");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 10, now);
    let (fork_path, mut fork) = devnet("backlog-fork-m");
    let branch = mine(&mut fork, 4, now + 100);
    let (path, node) = devnet("backlog-startup-active");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    store_before_the_rule(&node, &branch, now + 100);
    let engine = cpu();
    for block in chain.iter().chain(&branch) {
        engine.answer(block, true);
    }
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    let report = run_work_backlog_exclusive(&node, &AtomicBool::new(false)).unwrap();
    assert_eq!((report.checked, report.validated_height), (4, Some(4)));
    assert_eq!(engine.block_calls(), 4);
    for block in &branch {
        assert_eq!(store_status(&node, block.block_id()), None);
    }
    drop(node);

    // An engine whose known answers cannot be read stays qualifying: the
    // startup run gives up at once instead of holding the services back.
    let (path_b, node) = devnet("backlog-startup-qualifying");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    let engine = cpu();
    engine.fail_known_answers();
    let checker = install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    assert_eq!(checker.engine_state(), WorkEngineState::Qualifying);
    let started = Instant::now();
    let report = run_work_backlog_exclusive(&node, &AtomicBool::new(false)).unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!((report.checked, report.validated_height), (0, Some(0)));
    assert_eq!(engine.block_calls(), 0);
    drop((node, source, fork));
    for path in [path, path_b, source_path, fork_path] {
        clean_test_dir(&path);
    }
}

#[test]
fn a_provisional_pool_block_is_run_again_by_this_node_after_a_restart() {
    let (source_path, mut source) = devnet("backlog-source-e");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 2, now);
    let (path, mut node) = devnet("backlog-provisional");
    let replay = gpu();
    let checker = install(&mut node, None, None, Some(replay.clone()));
    let node = shared(node);
    for block in &chain {
        let (challenge, digest) = ScriptedEngine::digests(block);
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge, digest, 0,
        ));
    }
    submit_shared_tip_block(&node, chain[0].clone(), now).unwrap();
    submit_shared_tip_block(&node, chain[1].clone(), now + 1).unwrap();
    assert_eq!(replay.block_calls(), 0);
    assert_eq!(provisional(&node.lock().unwrap()).len(), 2);
    assert_eq!(validated(&node), Some(2), "a pool keeps serving its blocks");

    // In the same run the pool's result is set aside and computed here.
    replay.answer(&chain[0], true);
    let mut backlog = WorkBacklog::new();
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
    );
    assert_eq!(replay.block_calls(), 1);
    assert_eq!(
        provisional(&node.lock().unwrap()),
        vec![(2, chain[1].block_id())]
    );

    // After a restart the other one is still provisional and is run.
    drop(node);
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    let engine = cpu();
    engine.answer(&chain[1], true);
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    assert_eq!(
        provisional(&node.lock().unwrap()),
        vec![(2, chain[1].block_id())]
    );
    assert_eq!(drain(&node).len(), 1);
    assert_eq!(engine.block_calls(), 1);
    assert!(provisional(&node.lock().unwrap()).is_empty());
    assert_eq!(recorded(&node.lock().unwrap()), (2, 0));
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn the_background_check_gets_the_next_turn_ahead_of_waiting_admissions() {
    let (source_path, mut source) = devnet("backlog-source-f");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 1, now);
    let (path, node) = devnet("backlog-reserved");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    let engine = cpu();
    engine.answer(&chain[0], true);
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    let lane = Arc::clone(&node.lock().unwrap().work_gate.as_ref().unwrap().lane);

    // A running admission, and two more waiting in the normal class.
    let running = lane.acquire().unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let (lane, order) = (Arc::clone(&lane), Arc::clone(&order));
            std::thread::spawn(move || {
                let _permit = lane.acquire().unwrap();
                std::thread::sleep(Duration::from_millis(100));
                order.lock().unwrap().push("admission");
            })
        })
        .collect();
    while lane.telemetry().unwrap().normal.queued < 2 {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(node.lock().unwrap().work_lane_has_waiters());
    let turn = {
        let (node, order) = (Arc::clone(&node), Arc::clone(&order));
        std::thread::spawn(move || {
            let turn = WorkBacklog::new().run_turn(&node, &|| false).unwrap();
            order.lock().unwrap().push("backlog");
            turn
        })
    };
    while lane.telemetry().unwrap().priority.queued < 1 {
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(running);
    assert_eq!(
        turn.join().unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
    );
    for waiter in waiters {
        waiter.join().unwrap();
    }
    assert_eq!(
        *order.lock().unwrap(),
        ["backlog", "admission", "admission"]
    );
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_deep_heavier_branch_is_followed_one_checked_block_at_a_time() {
    for depth in [7_u64, 12] {
        let (source_path, mut source) = devnet(&format!("backlog-source-g{depth}"));
        let now = unix_time_seconds().unwrap();
        let tip = depth + 3;
        let chain = mine(&mut source, tip, now);
        // The other branch forks `depth` blocks below the tip and is one
        // block longer.
        let fork_height = tip - depth;
        let (fork_path, fork) = devnet(&format!("backlog-fork-g{depth}"));
        let fork = shared(fork);
        store_before_the_rule(&fork, &chain[..fork_height as usize], now);
        let branch = mine(&mut fork.lock().unwrap(), depth + 1, now + 1_000);
        let (path, mut node) = devnet(&format!("backlog-deep-{depth}"));
        let engine = cpu();
        for block in chain.iter().chain(&branch) {
            engine.answer(block, true);
        }
        install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        store_before_the_rule(&node, &chain, now);
        let calls = engine.block_calls();

        // Each branch block is offered again after a refusal, as a peer
        // would; one too deep waits for the background check.
        let mut backlog = WorkBacklog::new();
        let mut waits = 0;
        for (offset, block) in branch.iter().enumerate() {
            let at = now + 1_000 + offset as u64;
            match submit_shared_block(&node, block.clone(), at) {
                Ok(_) => {}
                Err(NodeError::WorkCheckPending) => {
                    waits += 1;
                    assert_eq!(
                        backlog.run_turn(&node, &|| false).unwrap(),
                        WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
                    );
                    submit_shared_block(&node, block.clone(), at).unwrap();
                }
                Err(error) => panic!("branch block {offset}: {error}"),
            }
        }
        // The branch's blocks at heights up to tip - WORK_RELEVANCE_DEPTH
        // waited, and every branch block ran exactly once.
        assert_eq!(waits, depth - WORK_RELEVANCE_DEPTH);
        assert_eq!(engine.block_calls() - calls, branch.len());
        {
            let node = node.lock().unwrap();
            assert_eq!(node.state.tip(), branch[depth as usize].block_id());
            assert_eq!(node.work_validated_height(), Some(tip + 1));
        }
        drop((node, source, fork));
        for path in [path, source_path, fork_path] {
            clean_test_dir(&path);
        }
    }
}

#[test]
fn the_background_thread_checks_stored_blocks_and_stops_promptly() {
    let (source_path, mut source) = devnet("backlog-source-i");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 3, now);
    let (path, node) = devnet("backlog-thread");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    let engine = cpu();
    for block in &chain {
        engine.answer(block, true);
    }
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);

    // A startup run that is asked to stop checks nothing.
    let report = run_work_backlog_exclusive(&node, &AtomicBool::new(true)).unwrap();
    assert_eq!(report.checked, 0);

    let handle = spawn_work_backlog(Arc::clone(&node)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while validated(&node) != Some(3) {
        assert!(
            Instant::now() < deadline,
            "the background check made no progress"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let stopping = Instant::now();
    handle.stop();
    assert!(stopping.elapsed() < Duration::from_secs(5));
    assert_eq!(engine.block_calls(), 3);
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn the_startup_background_check_takes_the_active_chain_first_while_blocks_arrive() {
    use crate::work_gate::BlockSender;
    use crate::{RemoteProofPeerId, RemoteProofRequest};
    use std::net::IpAddr;

    let (source_path, mut source) = devnet("backlog-source-open");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 11, now);
    let (fork_path, mut fork) = devnet("backlog-fork-open");
    let branch = mine(&mut fork, 2, now + 100);
    let (path, node) = devnet("backlog-open");
    let node = shared(node);
    store_before_the_rule(&node, &chain[..10], now);
    store_before_the_rule(&node, &branch, now + 100);
    let engine = cpu();
    for block in chain.iter().chain(&branch) {
        engine.answer(block, true);
    }
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    assert_eq!(validated(&node), Some(0));

    // While the first stored block is checked, a peer sends a block that
    // extends the tip: it waits for the lane in the normal class. While the
    // stored block after it is checked, the chain reads are looked at.
    let arrival = Arc::new(Mutex::new(None));
    let seen = Arc::new(Mutex::new(None));
    {
        let (node, engine_inner) = (Arc::clone(&node), Arc::clone(&engine));
        let (arrival, seen) = (Arc::clone(&arrival), Arc::clone(&seen));
        let block = chain[10].clone();
        engine.during_next(move || {
            let submitter = {
                let node = Arc::clone(&node);
                std::thread::spawn(move || {
                    crate::submit_shared_peer_block_from(
                        &node,
                        block,
                        now + 10,
                        RemoteProofPeerId::new(77).unwrap(),
                        RemoteProofRequest::new(Instant::now() + Duration::from_secs(30)),
                        false,
                        Some(BlockSender {
                            address: IpAddr::from([192, 0, 2, 10]),
                            fetched: false,
                            trusted: false,
                        }),
                    )
                })
            };
            let deadline = Instant::now() + Duration::from_secs(10);
            while crate::work_gate::test_support::lane_waiters(&node.lock().unwrap()) != (1, 0) {
                assert!(
                    Instant::now() < deadline,
                    "the arriving block never waited for the lane"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            *arrival.lock().unwrap() = Some(submitter);
            // The arriving block's own job comes next, then the next stored
            // block's.
            let engine_next = Arc::clone(&engine_inner);
            engine_inner.during_next(move || {
                engine_next.during_next(move || {
                    // Its commit follows its check, outside the lane.
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while node.lock().unwrap().state.next_height() != 12 {
                        assert!(
                            Instant::now() < deadline,
                            "the arriving block was not committed"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let node = node.lock().unwrap();
                    *seen.lock().unwrap() = Some((
                        node.exchange_served_height().ok(),
                        node.work_validated_height(),
                        node.state.next_height() - 1,
                    ));
                });
            });
        });
    }
    let handle = spawn_startup_work_backlog(Arc::clone(&node)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while validated(&node) != Some(11)
        || branch
            .iter()
            .any(|block| store_status(&node, block.block_id()) != Some(WorkStatus::Verified))
    {
        assert!(
            Instant::now() < deadline,
            "the background check made no progress"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    handle.stop();
    arrival
        .lock()
        .unwrap()
        .take()
        .expect("the block arrived")
        .join()
        .unwrap()
        .unwrap();
    // It was admitted after one stored block, and chain reads then still
    // served only the checked blocks below it.
    assert_eq!(*seen.lock().unwrap(), Some((Some(1), Some(1), 11)));

    // The active chain first, until the validated height was within the
    // relevance depth of the tip; then the side branch, then the rest.
    let challenge = |block: &Block| ScriptedEngine::digests(block).0;
    let mut expected = vec![challenge(&chain[0]), challenge(&chain[10])];
    expected.extend(chain[1..5].iter().map(challenge));
    expected.extend(branch.iter().map(challenge));
    expected.extend(chain[5..10].iter().map(challenge));
    assert_eq!(engine.block_challenges(), expected);
    drop((node, source, fork));
    for path in [path, source_path, fork_path] {
        clean_test_dir(&path);
    }
}

#[test]
fn progress_is_logged_each_interval_while_many_stored_blocks_are_left() {
    let start = Instant::now();
    let mut progress = BacklogProgress::new();
    assert_eq!(progress.next_line(0, 1_000, start), None);
    for _ in 0..200 {
        progress.checked_one();
    }
    assert_eq!(
        progress.next_line(150, 1_050, start + Duration::from_secs(60)),
        None
    );
    // 200 checked in ten minutes while 100 more arrived: the 900 left fall by
    // 600 an hour.
    assert_eq!(
        progress.next_line(190, 1_090, start + PROGRESS_INTERVAL),
        Some(ProgressLine {
            blocks_left: 900,
            checked: 200,
            checked_per_hour: 1_200,
            eta: "1.5 h".to_owned(),
        })
    );
    // Few left: nothing is logged.
    assert_eq!(
        progress.next_line(1_080, 1_100, start + PROGRESS_INTERVAL * 2),
        None
    );
    // More left than ten minutes before: no end at this rate.
    let line = progress
        .next_line(1_080, 1_200, start + PROGRESS_INTERVAL * 3)
        .unwrap();
    assert_eq!(line.blocks_left, 120);
    assert_eq!(line.checked_per_hour, 0);
    assert_eq!(line.eta, "none at this rate");
}

#[test]
fn a_paused_background_thread_only_qualifies_the_engines_until_resumed() {
    use crate::honest_work::{HonestWorkChecker, WorkEngine};
    use crate::work_gate::test_support::rule_from_genesis;

    let (source_path, mut source) = devnet("backlog-source-pause");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 3, now);
    let (path, node) = devnet("backlog-pause");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    let engine = cpu();
    for block in &chain {
        engine.answer(block, true);
    }
    // Installed but not yet qualified, as a desktop wallet starts it.
    let checker = Arc::new(
        HonestWorkChecker::new(Some(engine.clone() as Arc<dyn WorkEngine>), None, false).unwrap(),
    );
    {
        let mut node = node.lock().unwrap();
        let rule = rule_from_genesis(&node);
        node.install_work_rule_for_test(Some(rule));
        node.install_work_checker(Arc::clone(&checker)).unwrap();
    }
    assert_eq!(checker.engine_state(), WorkEngineState::Qualifying);

    let paused = Arc::new(AtomicBool::new(true));
    let handle = {
        let paused = Arc::clone(&paused);
        spawn_work_backlog_with_pause(Arc::clone(&node), move || paused.load(Ordering::Acquire))
            .unwrap()
    };
    // The known answers are due, so one turn runs: it qualifies the engine
    // and checks one block. Then nothing more while paused.
    let deadline = Instant::now() + Duration::from_secs(20);
    while validated(&node) != Some(1) {
        assert!(
            Instant::now() < deadline,
            "the engines were never qualified"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(checker.engine_state(), WorkEngineState::Ready);
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(engine.block_calls(), 1);
    assert_eq!(validated(&node), Some(1));
    let backlog_paused = || {
        node.lock()
            .unwrap()
            .work_rule_status()
            .unwrap()
            .backlog_paused
    };
    assert!(backlog_paused());

    // Resumed: the rest is checked.
    paused.store(false, Ordering::Release);
    while validated(&node) != Some(3) {
        assert!(
            Instant::now() < deadline,
            "the resumed check made no progress"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!backlog_paused());
    handle.stop();
    assert_eq!(engine.block_calls(), 3);
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_noted_block_one_engine_finds_wrong_is_checked_once_and_refused_on_a_re_send() {
    let (source_path, mut source) = devnet("backlog-source-j");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 10, now);
    let (fork_path, fork) = devnet("backlog-fork-j");
    let fork = shared(fork);
    store_before_the_rule(&fork, &chain[..2], now);
    let side = mine(&mut fork.lock().unwrap(), 1, now + 1_000);
    let (path, mut node) = devnet("backlog-noted-mismatch");
    let engine = cpu();
    for block in &chain {
        engine.answer(block, true);
    }
    engine.answer(&side[0], false);
    install(&mut node, None, Some(engine.clone()), None);
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    let calls = engine.block_calls();

    // Too deep for the admission path: noted for the background check.
    assert!(matches!(
        submit_shared_block(&node, side[0].clone(), now + 1_000),
        Err(NodeError::WorkCheckPending)
    ));
    // Not while another block is being checked: it is put back, and the
    // turn is idle so the background thread does not back off.
    let lane = Arc::clone(&node.lock().unwrap().work_gate.as_ref().unwrap().lane);
    let running = lane.acquire().unwrap();
    let mut backlog = WorkBacklog::new();
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Idle
    );
    assert_eq!(engine.block_calls() - calls, 0);
    drop(running);
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)
    );
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Idle,
        "the result stays in the memo; the block is not checked again"
    );
    assert_eq!(engine.block_calls() - calls, 1);
    assert!(matches!(
        submit_shared_block(&node, side[0].clone(), now + 1_000),
        Err(NodeError::WorkMismatchUnconfirmed(id)) if id == side[0].block_id()
    ));
    // Noted again on a later offer, it is not picked up again either.
    assert!(drain(&node).is_empty());
    assert_eq!(engine.block_calls() - calls, 1);
    drop((node, source, fork));
    for path in [path, source_path, fork_path] {
        clean_test_dir(&path);
    }
}

/// Records the peers the background check reports.
#[derive(Default)]
struct BlameRecorder(Mutex<Vec<BlockSender>>);

impl WorkBlame for BlameRecorder {
    fn blame(&self, sender: BlockSender) {
        self.0.lock().unwrap().push(sender);
    }
}

impl BlameRecorder {
    fn reported(&self) -> Vec<BlockSender> {
        self.0.lock().unwrap().clone()
    }
}

/// Registers a new recorder with `node`.
fn record_blame(node: &Mutex<Node>) -> Arc<BlameRecorder> {
    let recorder = Arc::new(BlameRecorder::default());
    let sink: std::sync::Weak<dyn WorkBlame> = Arc::<BlameRecorder>::downgrade(&recorder);
    node.lock().unwrap().register_work_blame(sink);
    recorder
}

/// Submits `block` as one `sender` sent, or a sync session fetched from it.
fn submit_from(
    node: &Arc<Mutex<Node>>,
    block: &Block,
    accepted_at: u64,
    sender: BlockSender,
) -> Result<u64, NodeError> {
    crate::submit_shared_peer_block_from(
        node,
        block.clone(),
        accepted_at,
        crate::RemoteProofPeerId::new(1).unwrap(),
        crate::RemoteProofRequest::new(Instant::now() + Duration::from_secs(10)),
        sender.trusted,
        Some(sender),
    )
}

/// A node holding 10 active blocks, `engines` answering for each, and one
/// side block at height 2 too deep to check on admission that every engine
/// finds wrong.
struct NotedCase {
    paths: [std::path::PathBuf; 3],
    node: Arc<Mutex<Node>>,
    side: Block,
    now: u64,
}

impl NotedCase {
    fn new(name: &str, engines: &[&Arc<ScriptedEngine>]) -> Self {
        let (source_path, mut source) = devnet(&format!("backlog-source-{name}"));
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 10, now);
        let (fork_path, fork) = devnet(&format!("backlog-fork-{name}"));
        let fork = shared(fork);
        store_before_the_rule(&fork, &chain[..2], now);
        let side = mine(&mut fork.lock().unwrap(), 1, now + 1_000).remove(0);
        for engine in engines {
            for block in &chain {
                engine.answer(block, true);
            }
            engine.answer(&side, false);
        }
        let (path, mut node) = devnet(&format!("backlog-{name}"));
        install(
            &mut node,
            None,
            engines.first().map(|engine| Arc::clone(engine)),
            engines.get(1).map(|engine| Arc::clone(engine)),
        );
        let node = shared(node);
        store_before_the_rule(&node, &chain, now);
        Self {
            paths: [path, source_path, fork_path],
            node,
            side,
            now,
        }
    }

    fn finish(self) {
        drop(self.node);
        for path in self.paths {
            clean_test_dir(&path);
        }
    }
}

#[test]
fn a_noted_block_two_engines_find_wrong_reports_the_peer_it_came_from() {
    let (cpu, gpu) = (cpu(), gpu());
    let case = NotedCase::new("blame-confirmed", &[&cpu, &gpu]);
    let recorder = record_blame(&case.node);
    let sent = BlockSender {
        address: "203.0.113.7".parse().unwrap(),
        fetched: false,
        trusted: false,
    };
    assert!(matches!(
        submit_from(&case.node, &case.side, case.now + 1_000, sent),
        Err(NodeError::WorkCheckPending)
    ));
    assert!(recorder.reported().is_empty(), "nothing before the check");
    assert_eq!(
        drain(&case.node),
        [WorkBacklogTurn::Checked(WorkBacklogOutcome::Invalid)]
    );
    assert_eq!(recorder.reported(), [sent], "reported once");
    // A re-send is refused from the memo as confirmed (which charges its
    // sender at admission), and reports nobody again.
    let calls = (cpu.block_calls(), gpu.block_calls());
    assert!(matches!(
        submit_from(&case.node, &case.side, case.now + 1_000, sent),
        Err(NodeError::WorkRecomputationMismatch(id)) if id == case.side.block_id()
    ));
    assert!(drain(&case.node).is_empty());
    assert_eq!((cpu.block_calls(), gpu.block_calls()), calls);
    assert_eq!(recorder.reported(), [sent]);

    // A peer a sync session fetched it from is reported as such.
    let engines = (
        crate::work_gate::tests::cpu(),
        crate::work_gate::tests::gpu(),
    );
    let fetched_case = NotedCase::new("blame-confirmed-fetched", &[&engines.0, &engines.1]);
    let recorder = record_blame(&fetched_case.node);
    let fetched = BlockSender {
        address: "203.0.113.8".parse().unwrap(),
        fetched: true,
        trusted: false,
    };
    assert!(matches!(
        submit_from(
            &fetched_case.node,
            &fetched_case.side,
            fetched_case.now + 1_000,
            fetched
        ),
        Err(NodeError::WorkCheckPending)
    ));
    assert_eq!(
        drain(&fetched_case.node),
        [WorkBacklogTurn::Checked(WorkBacklogOutcome::Invalid)]
    );
    assert_eq!(recorder.reported(), [fetched]);
    case.finish();
    fetched_case.finish();
}

#[test]
fn a_noted_block_one_engine_finds_wrong_counts_against_its_address_like_an_admitted_one() {
    use crate::work_gate::MAX_LONE_REFUSALS_PER_SENDER;
    use crate::work_gate::test_support::{
        count_lone_refusal, end_lone_refusal_window, lone_refusals,
    };

    let cpu = cpu();
    let case = NotedCase::new("lone-refusal", &[&cpu]);
    // Whatever stored blocks are left first.
    drain(&case.node);
    let calls = cpu.block_calls();
    let sent = BlockSender {
        address: "203.0.113.9".parse().unwrap(),
        fetched: false,
        trusted: false,
    };
    let note = || {
        assert!(matches!(
            submit_from(&case.node, &case.side, case.now + 1_000, sent),
            Err(NodeError::WorkCheckPending)
        ));
        assert_eq!(case.node.lock().unwrap().pending_side_work().len(), 1);
    };

    // From an address with no refusals left, a noted block is dropped and
    // runs nothing.
    for index in 0..MAX_LONE_REFUSALS_PER_SENDER {
        count_lone_refusal(&case.node.lock().unwrap(), sent.address, [index as u8; 32]);
    }
    note();
    assert!(drain(&case.node).is_empty());
    assert_eq!(cpu.block_calls(), calls);
    assert!(case.node.lock().unwrap().pending_side_work().is_empty());

    // Otherwise it is checked, and its refusal is counted against the
    // address; nothing else is charged to it.
    end_lone_refusal_window(&case.node.lock().unwrap());
    let recorder = record_blame(&case.node);
    note();
    assert_eq!(
        drain(&case.node),
        [WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)]
    );
    assert_eq!(cpu.block_calls(), calls + 1);
    assert_eq!(lone_refusals(&case.node.lock().unwrap(), sent.address), 1);
    assert!(recorder.reported().is_empty());
    case.finish();
}

#[test]
fn a_trusted_peers_noted_block_is_neither_dropped_nor_counted_against_its_address() {
    use crate::work_gate::MAX_LONE_REFUSALS_PER_SENDER;
    use crate::work_gate::test_support::{count_lone_refusal, lone_refusals};

    // Whether or not ordinary sessions from the same address have used up
    // its refusals.
    for counted in [0, MAX_LONE_REFUSALS_PER_SENDER] {
        let cpu = cpu();
        let case = NotedCase::new(&format!("lone-refusal-trusted-{counted}"), &[&cpu]);
        drain(&case.node);
        let calls = cpu.block_calls();
        let trusted = BlockSender {
            address: "203.0.113.11".parse().unwrap(),
            fetched: false,
            trusted: true,
        };
        for index in 0..counted {
            count_lone_refusal(
                &case.node.lock().unwrap(),
                trusted.address,
                [index as u8; 32],
            );
        }
        assert!(matches!(
            submit_from(&case.node, &case.side, case.now + 1_000, trusted),
            Err(NodeError::WorkCheckPending)
        ));
        assert_eq!(
            drain(&case.node),
            [WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)]
        );
        assert_eq!(cpu.block_calls(), calls + 1);
        assert_eq!(
            lone_refusals(&case.node.lock().unwrap(), trusted.address),
            counted
        );
        case.finish();
    }
}

#[test]
fn a_node_lock_poisoned_during_the_check_keeps_a_noted_blocks_outcome() {
    let (cpu, gpu) = (cpu(), gpu());
    let case = NotedCase::new("blame-poisoned", &[&cpu, &gpu]);
    let recorder = record_blame(&case.node);
    let sent = BlockSender {
        address: "203.0.113.9".parse().unwrap(),
        fetched: false,
        trusted: false,
    };
    assert!(matches!(
        submit_from(&case.node, &case.side, case.now + 1_000, sent),
        Err(NodeError::WorkCheckPending)
    ));
    // The first engine to run poisons the node lock while the turn does not
    // hold it.
    for engine in [&cpu, &gpu] {
        let node = Arc::downgrade(&case.node);
        engine.during_next(move || {
            let Some(node) = node.upgrade().filter(|node| !node.is_poisoned()) else {
                return;
            };
            let poisoner = std::thread::spawn(move || {
                let _guard = node.lock().unwrap();
                panic!("poisons the node lock");
            });
            assert!(poisoner.join().is_err());
        });
    }
    let mut backlog = WorkBacklog::new();
    assert_eq!(
        backlog.run_turn(&case.node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Invalid)
    );
    assert!(case.node.is_poisoned());
    assert!(recorder.reported().is_empty(), "the peer is not reported");
    assert!(backlog.run_turn(&case.node, &|| false).is_err());
    case.finish();
}

#[test]
fn a_noted_block_one_engine_finds_wrong_reports_no_peer() {
    let engine = cpu();
    let case = NotedCase::new("blame-unconfirmed", &[&engine]);
    let recorder = record_blame(&case.node);
    for fetched in [false, true] {
        let sender = BlockSender {
            address: "203.0.113.9".parse().unwrap(),
            fetched,
            trusted: false,
        };
        let _ = submit_from(&case.node, &case.side, case.now + 1_000, sender);
        drain(&case.node);
    }
    assert!(engine.block_calls() > 0, "the block was checked");
    assert!(
        recorder.reported().is_empty(),
        "a single engine's mismatch costs the peer nothing"
    );
    case.finish();
}

#[test]
fn a_noted_block_without_a_peer_or_that_matches_reports_nobody() {
    // Two engines agree it is wrong, but no peer sent it.
    let (cpu, gpu) = (cpu(), gpu());
    let case = NotedCase::new("blame-no-peer", &[&cpu, &gpu]);
    let recorder = record_blame(&case.node);
    assert!(matches!(
        submit_shared_block(&case.node, case.side.clone(), case.now + 1_000),
        Err(NodeError::WorkCheckPending)
    ));
    assert_eq!(
        drain(&case.node),
        [WorkBacklogTurn::Checked(WorkBacklogOutcome::Invalid)]
    );
    assert!(recorder.reported().is_empty());
    case.finish();

    // A peer's noted block that matches.
    let engines = (
        crate::work_gate::tests::cpu(),
        crate::work_gate::tests::gpu(),
    );
    let case = NotedCase::new("blame-match", &[&engines.0, &engines.1]);
    for engine in [&engines.0, &engines.1] {
        engine.answer(&case.side, true);
    }
    let recorder = record_blame(&case.node);
    let sender = BlockSender {
        address: "203.0.113.10".parse().unwrap(),
        fetched: false,
        trusted: false,
    };
    assert!(matches!(
        submit_from(&case.node, &case.side, case.now + 1_000, sender),
        Err(NodeError::WorkCheckPending)
    ));
    assert_eq!(
        drain(&case.node),
        [WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)]
    );
    assert!(recorder.reported().is_empty());
    case.finish();
}

#[test]
fn a_pruned_record_claim_is_bound_to_its_header_and_nonce_as_preflight_binds_it() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../cmfd-consensus/data/forgematrix_v4_execution_vectors_v1.json"
    ))
    .unwrap();
    let hex32 = |value: &serde_json::Value| -> [u8; 32] {
        let mut out = [0; 32];
        hex::decode_to_slice(value.as_str().unwrap(), &mut out).unwrap();
        out
    };
    let vectors = vectors["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let challenge = BlockChallenge {
            network_id: hex32(&vector["network_id"]),
            previous_block: hex32(&vector["previous_block"]),
            transaction_root: hex32(&vector["transaction_root"]),
            height: vector["height"].as_u64().unwrap(),
            timestamp: vector["timestamp"].as_u64().unwrap(),
            target: hex32(&vector["target"]),
        };
        let nonce = vector["nonce"].as_str().unwrap().parse().unwrap();
        let work_digest = hex32(&vector["work_digest"]);
        let claim = pruned_v4_claim(&challenge, nonce, work_digest);
        assert_eq!(claim.challenge_digest, hex32(&vector["challenge_digest"]));
        assert_eq!(claim.work_digest, work_digest);
        assert_eq!(
            crate::honest_work::honest_work_digest(
                claim.challenge_digest,
                hex32(&vector["final_activation_digest"])
            ),
            work_digest
        );
    }
}

#[test]
fn a_verified_side_block_waits_for_an_ancestor_whose_record_went_away() {
    use crate::work_gate::test_support::mark_verified;

    let (source_path, mut source) = devnet("backlog-source-ancestor-record");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 5, now);
    let (fork_path, mut fork) = devnet("backlog-fork-ancestor-record");
    let branch = mine(&mut fork, 3, now + 100);
    let extension = mine(&mut fork, 1, now + 200).remove(0);
    let (path, node) = devnet("backlog-ancestor-record");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    store_before_the_rule(&node, &branch, now + 100);
    let engine = cpu();
    for block in chain.iter().chain(&branch) {
        engine.answer(block, true);
    }
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    drain(&node);
    for block in &branch {
        assert_eq!(
            store_status(&node, block.block_id()),
            Some(WorkStatus::Verified)
        );
    }
    // The branch's next block was recorded verified, and then the record of
    // one of its ancestors went away.
    mark_verified(&node.lock().unwrap(), 4, extension.block_id());
    {
        let node = node.lock().unwrap();
        let store = node.work_gate.as_ref().unwrap().store.clone().unwrap();
        assert!(lock(&store).reconsider(branch[1].block_id()).unwrap());
    }
    assert!(matches!(
        submit_shared_block(&node, extension.clone(), now + 200),
        Err(NodeError::WorkCheckPending)
    ));
    assert!(!node.lock().unwrap().contains_block(extension.block_id()));

    // Once the ancestor is checked again, the block is admitted on its own
    // record, with no run.
    assert_eq!(
        drain(&node),
        [WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)]
    );
    let calls = engine.block_calls();
    submit_shared_block(&node, extension.clone(), now + 200).unwrap();
    assert_eq!(engine.block_calls(), calls);
    drop((node, source, fork));
    for path in [path, source_path, fork_path] {
        clean_test_dir(&path);
    }
}

#[test]
fn a_side_block_one_engine_finds_wrong_holds_its_branch_until_a_later_start_checks_it_again() {
    let (source_path, mut source) = devnet("backlog-source-m");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 5, now);
    // A lighter branch from genesis, stored as a side branch.
    let (fork_path, mut fork) = devnet("backlog-fork-m");
    let branch = mine(&mut fork, 4, now + 100);
    let (path, node) = devnet("backlog-side-unsettled");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    store_before_the_rule(&node, &branch, now + 100);
    // Two more blocks make the branch the heavier one.
    let extension = mine(&mut fork, 2, now + 200);

    // On a node with one engine, which gets one branch block wrong once.
    let engine = cpu();
    for block in chain.iter().chain(&branch).chain(&extension) {
        engine.answer(block, true);
    }
    engine.answer(&branch[1], false);
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    drain(&node);
    assert_eq!(store_status(&node, branch[1].block_id()), None);
    assert_eq!(validated(&node), Some(5));
    let calls = engine.block_calls();

    // The heavier extension waits for its unchecked ancestor, which is not
    // computed again in this run.
    assert!(matches!(
        submit_shared_block(&node, extension[0].clone(), now + 200),
        Err(NodeError::WorkCheckPending)
    ));
    assert!(drain(&node).is_empty());
    assert_eq!(engine.block_calls(), calls);
    assert_eq!(node.lock().unwrap().state.tip(), chain[4].block_id());

    // A later start computes it once more; the fault has passed, so the
    // branch is followed.
    drop(node);
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    let engine = cpu();
    for block in chain.iter().chain(&branch).chain(&extension) {
        engine.answer(block, true);
    }
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    assert_eq!(
        drain(&node),
        [WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)]
    );
    assert_eq!(
        store_status(&node, branch[1].block_id()),
        Some(WorkStatus::Verified)
    );
    for (offset, block) in extension.iter().enumerate() {
        submit_shared_block(&node, block.clone(), now + 200 + offset as u64).unwrap();
    }
    assert_eq!(node.lock().unwrap().state.tip(), extension[1].block_id());
    assert_eq!(validated(&node), Some(6));
    drop((node, source, fork));
    for path in [path, source_path, fork_path] {
        clean_test_dir(&path);
    }
}

#[test]
fn a_noted_block_gives_way_to_a_remote_block_waiting_for_the_lane() {
    let (source_path, mut source) = devnet("backlog-source-n");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 10, now);
    let (fork_path, fork) = devnet("backlog-fork-n");
    let fork = shared(fork);
    store_before_the_rule(&fork, &chain[..2], now);
    let side = mine(&mut fork.lock().unwrap(), 1, now + 1_000);
    let (path, mut node) = devnet("backlog-noted-give-way");
    let engine = cpu();
    for block in chain.iter().chain(&side) {
        engine.answer(block, true);
    }
    install(&mut node, None, Some(engine.clone()), None);
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    assert!(matches!(
        submit_shared_block(&node, side[0].clone(), now + 1_000),
        Err(NodeError::WorkCheckPending)
    ));
    let calls = engine.block_calls();
    let lane = Arc::clone(&node.lock().unwrap().work_gate.as_ref().unwrap().lane);

    // The noted block's job runs; a remote admission then waits for the lane
    // in the normal class.
    let started = engine.hold_next();
    let turn = {
        let node = Arc::clone(&node);
        std::thread::spawn(move || WorkBacklog::new().run_turn(&node, &|| false).unwrap())
    };
    started.wait();
    let admission = {
        let lane = Arc::clone(&lane);
        std::thread::spawn(move || drop(lane.acquire().unwrap()))
    };
    assert_eq!(turn.join().unwrap(), WorkBacklogTurn::Idle);
    admission.join().unwrap();
    // It was put back, and is checked once the lane is free.
    let noted = node
        .lock()
        .unwrap()
        .work_gate
        .as_ref()
        .unwrap()
        .pending_side
        .clone();
    assert!(lock(&noted).ids.contains(&side[0].block_id()));
    assert_eq!(
        WorkBacklog::new().run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
    );
    assert_eq!(engine.block_calls() - calls, 2);
    drop((node, source, fork));
    for path in [path, source_path, fork_path] {
        clean_test_dir(&path);
    }
}

#[test]
fn a_provisional_re_check_gives_way_to_a_block_waiting_as_priority() {
    let (source_path, mut source) = devnet("backlog-source-provisional-give-way");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 1, now);
    let (path, mut node) = devnet("backlog-provisional-give-way");
    let replay = gpu();
    let checker = install(&mut node, None, None, Some(replay.clone()));
    let node = shared(node);
    let (challenge, digest) = ScriptedEngine::digests(&chain[0]);
    checker.record_honest(crate::honest_work::PoolReplayResult::new(
        challenge, digest, 0,
    ));
    submit_shared_tip_block(&node, chain[0].clone(), now).unwrap();
    assert_eq!(
        provisional(&node.lock().unwrap()),
        vec![(1, chain[0].block_id())]
    );
    replay.answer(&chain[0], true);
    let lane = Arc::clone(&node.lock().unwrap().work_gate.as_ref().unwrap().lane);

    // The re-check's job runs; a block then waits for the lane as priority.
    let started = replay.hold_next();
    let turn = {
        let node = Arc::clone(&node);
        std::thread::spawn(move || WorkBacklog::new().run_turn(&node, &|| false).unwrap())
    };
    started.wait();
    let admission = std::thread::spawn(move || drop(lane.acquire_priority().unwrap()));
    assert_eq!(turn.join().unwrap(), WorkBacklogTurn::Idle);
    admission.join().unwrap();
    assert_eq!(
        provisional(&node.lock().unwrap()),
        vec![(1, chain[0].block_id())],
        "it stays provisional"
    );

    // It is checked again on the next turn.
    assert_eq!(
        WorkBacklog::new().run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
    );
    assert!(provisional(&node.lock().unwrap()).is_empty());
    assert_eq!(replay.block_calls(), 2);
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_record_that_cannot_be_read_is_tried_later_and_the_next_block_is_checked() {
    let (source_path, mut source) = devnet("backlog-source-o");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 3, now);
    let (path, node) = devnet("backlog-unreadable");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    let engine = cpu();
    for block in &chain {
        engine.answer(block, true);
    }
    install(&mut node.lock().unwrap(), None, Some(engine.clone()), None);
    let first = chain[0].block_id();
    let original = node.lock().unwrap().index.blocks[&first].locator;
    let set_locator = |locator| {
        let mut node = node.lock().unwrap();
        Arc::get_mut(node.index.blocks.get_mut(&first).unwrap())
            .expect("no other handle on the indexed block")
            .locator = locator;
    };
    let mut damaged = original;
    damaged.complete_digest[0] ^= 1;
    set_locator(damaged);

    let mut backlog = WorkBacklog::new();
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
    );
    assert_eq!(
        store_status(&node, chain[1].block_id()),
        Some(WorkStatus::Verified)
    );
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
    );
    // The unreadable block waits for its retry, and holds the validated
    // height.
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Idle
    );
    assert_eq!(store_status(&node, first), None);
    assert_eq!(validated(&node), Some(0));
    assert_eq!(engine.block_calls(), 2);

    // Readable again, it is checked on its retry.
    set_locator(original);
    assert_eq!(drain(&node).len(), 1);
    assert_eq!(validated(&node), Some(3));
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn a_refused_block_whose_record_cannot_be_written_waits_and_an_active_one_still_halts() {
    let (source_path, mut source) = devnet("backlog-source-unwritable");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 3, now);
    let (fork_path, mut fork) = devnet("backlog-fork-unwritable");
    let side = mine(&mut fork, 1, now + 100).remove(0);
    let (path, node) = devnet("backlog-unwritable");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    store_before_the_rule(&node, std::slice::from_ref(&side), now + 100);
    // Both engines find the side block and the tip wrong.
    let (engine, replay) = (cpu(), gpu());
    for scripted in [&engine, &replay] {
        for block in &chain {
            scripted.answer(block, true);
        }
        scripted.answer(&side, false);
        scripted.answer(&chain[2], false);
    }
    install(
        &mut node.lock().unwrap(),
        None,
        Some(engine.clone()),
        Some(replay.clone()),
    );
    let store = node
        .lock()
        .unwrap()
        .work_gate
        .as_ref()
        .unwrap()
        .store
        .clone()
        .unwrap();

    // The side block goes first; its record cannot be written.
    let mut backlog = WorkBacklog::new();
    lock(&store).fail_next_write();
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Unavailable
    );
    assert_eq!(store_status(&node, side.block_id()), None);
    assert!(
        backlog.deferred.contains_key(&side.block_id()),
        "not picked at every turn"
    );
    for _ in 0..2 {
        assert_eq!(
            backlog.run_turn(&node, &|| false).unwrap(),
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
        );
    }

    // An active block halts the node however its record went.
    lock(&store).fail_next_write();
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Halted
    );
    assert!(node.lock().unwrap().work_rule_halted());
    drop((node, source, fork));
    for path in [path, source_path, fork_path] {
        clean_test_dir(&path);
    }
}

#[test]
fn a_result_the_store_refuses_raises_the_divergence_alarm_and_waits_long() {
    let (path, mut node) = devnet("backlog-store-refusal");
    let checker = install(&mut node, None, Some(cpu()), None);
    let gate = node.work_gate.clone().unwrap();
    let item = Item {
        block_id: [7; 32],
        height: 1,
        claim: WorkClaim {
            challenge_digest: [8; 32],
            work_digest: [9; 32],
        },
        source: Source::Active,
        sender: None,
    };
    let refused = io::Error::new(io::ErrorKind::InvalidInput, "block is recorded verified");
    note_store_error(&gate, item, &refused, "invalid");
    assert_eq!(gate.store_conflicts.load(Ordering::Relaxed), 1);
    assert_eq!(
        checker.alarms(),
        WorkAlarmCounts {
            engine_divergence: 1,
            ..WorkAlarmCounts::default()
        }
    );
    assert_eq!(retry_after_store_error(&refused), RETRY_UNSETTLED);
    // A write that failed is no disagreement, and is tried again soon.
    let failed = io::Error::other("disk full");
    note_store_error(&gate, item, &failed, "invalid");
    assert_eq!(gate.store_conflicts.load(Ordering::Relaxed), 1);
    assert_eq!(checker.alarms().engine_divergence, 1);
    assert_eq!(retry_after_store_error(&failed), RETRY_UNAVAILABLE);
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn a_halt_on_a_block_a_later_release_pins_is_cleared_at_startup_and_any_other_kept() {
    use crate::work_gate::test_support::rule_from_genesis;

    let (source_path, mut source) = devnet("backlog-source-halt-recut");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 4, now);
    let (path, node) = devnet("backlog-halt-recut");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    // Both engines find the active block at height 2 wrong: the node halts.
    let engines = [cpu(), gpu()];
    for engine in &engines {
        for block in &chain {
            engine.answer(block, true);
        }
        engine.answer(&chain[1], false);
    }
    let [cpu_engine, gpu_engine] = engines;
    install(
        &mut node.lock().unwrap(),
        None,
        Some(cpu_engine),
        Some(gpu_engine),
    );
    let mut backlog = WorkBacklog::new();
    backlog.run_turn(&node, &|| false).unwrap();
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Halted
    );
    let network_id = node.lock().unwrap().params.network_id;
    let first_rule = rule_from_genesis(&node.lock().unwrap());
    drop(node);
    let halt_path = path.join(WORK_HALT_FILE);
    let halt = read_work_halt(&halt_path, network_id).unwrap().unwrap();
    assert_eq!((halt.height, halt.block_id), (2, chain[1].block_id()));
    let marker = std::fs::read(&halt_path).unwrap();

    let restart = |rule: Option<ForgeMatrixV4WorkRule>| {
        let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        install(&mut node, rule, Some(cpu()), None);
        node.work_rule_halted()
    };
    // A release whose checkpoint is past the block but pins another block at
    // its height, or pins nothing there, keeps the halt. So does the release
    // the node halted under.
    let at_three = |pins: Vec<(u64, [u8; 32])>| {
        ForgeMatrixV4WorkRule::with_pinned_heights(3, chain[2].block_id(), pins).unwrap()
    };
    let other_id = [0x5a; 32];
    assert!(restart(Some(at_three(Vec::new()))));
    assert!(restart(Some(first_rule)));
    assert_eq!(std::fs::read(&halt_path).unwrap(), marker);
    // A marker naming another block at that height than the one pinned is
    // kept too.
    std::fs::remove_file(&halt_path).unwrap();
    crate::honest_work::store::write_work_halt(
        &halt_path,
        network_id,
        2,
        other_id,
        [0x6b; 32],
        &ConfirmedWorkMismatch::for_test([0x6b; 32], [0x7c; 32]),
    )
    .unwrap();
    assert!(restart(Some(at_three(vec![(2, chain[1].block_id())]))));
    assert!(halt_path.exists());
    std::fs::remove_file(&halt_path).unwrap();
    std::fs::write(&halt_path, &marker).unwrap();

    // A release that pins the halted block at its height clears the marker.
    assert!(!restart(Some(at_three(vec![(2, chain[1].block_id())]))));
    assert!(!halt_path.exists());
    assert!(!restart(Some(at_three(vec![(2, chain[1].block_id())]))));
    drop(source);
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

/// Runs the operator's reconsider on a stopped node under `rule`, as a
/// build with that rule compiled in would.
fn reconsider_under(
    rule: &ForgeMatrixV4WorkRule,
    path: &std::path::Path,
    block_id: [u8; 32],
) -> Result<crate::storage::WorkReconsiderReport, NodeError> {
    crate::work_gate::OPEN_WITH_WORK_RULE.with(|slot| *slot.borrow_mut() = Some(rule.clone()));
    let result = crate::storage::reconsider_work_block(path, DEVNET_PROFILE, block_id);
    crate::work_gate::OPEN_WITH_WORK_RULE.with(|slot| *slot.borrow_mut() = None);
    result
}

#[test]
fn an_operator_reconsider_clears_one_record_and_a_halt_that_names_it() {
    let (source_path, mut source) = devnet("backlog-source-p");
    let now = unix_time_seconds().unwrap();
    let chain = mine(&mut source, 3, now);
    let (path, node) = devnet("backlog-reconsider");
    let node = shared(node);
    store_before_the_rule(&node, &chain, now);
    let engines = [cpu(), gpu()];
    for engine in &engines {
        for block in &chain {
            engine.answer(block, true);
        }
        engine.answer(&chain[1], false);
    }
    let [cpu_engine, gpu_engine] = engines;
    install(
        &mut node.lock().unwrap(),
        None,
        Some(cpu_engine),
        Some(gpu_engine),
    );
    let mut backlog = WorkBacklog::new();
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
    );
    assert_eq!(
        backlog.run_turn(&node, &|| false).unwrap(),
        WorkBacklogTurn::Halted
    );
    assert!(
        read_work_halt(
            &path.join(WORK_HALT_FILE),
            node.lock().unwrap().params.network_id
        )
        .unwrap()
        .is_some()
    );
    let rule = crate::work_gate::test_support::rule_from_genesis(&node.lock().unwrap());

    // Only on a stopped node.
    assert!(matches!(
        reconsider_under(&rule, &path, chain[1].block_id()),
        Err(NodeError::DataDirLocked(_))
    ));
    drop(node);
    // A store for another release checkpoint is left as it is, and the halt
    // that names the block is cleared all the same.
    let status_path = path.join(crate::work_gate::WORK_STATUS_FILE);
    let before = std::fs::read(&status_path).unwrap();
    let other = ForgeMatrixV4WorkRule::with_pinned_heights(1, chain[0].block_id(), []).unwrap();
    let report = reconsider_under(&other, &path, chain[1].block_id()).unwrap();
    assert!(!report.record_cleared && report.halt_cleared && report.store_for_another_checkpoint);
    assert_eq!(std::fs::read(&status_path).unwrap(), before);
    assert!(!path.join(WORK_HALT_FILE).exists());
    // A block with no record and no halt: nothing to clear.
    let report = reconsider_under(&rule, &path, [5; 32]).unwrap();
    assert!(!report.record_cleared && !report.halt_cleared && !report.store_for_another_checkpoint);
    let report = reconsider_under(&rule, &path, chain[1].block_id()).unwrap();
    assert!(report.record_cleared && !report.halt_cleared);

    // The next start checks it again; this time both engines reproduce it.
    let node = shared(Node::open_with_profile(&path, DEVNET_PROFILE).unwrap());
    let engines = [cpu(), gpu()];
    for engine in &engines {
        for block in &chain {
            engine.answer(block, true);
        }
    }
    let [cpu_engine, gpu_engine] = engines;
    install(
        &mut node.lock().unwrap(),
        None,
        Some(cpu_engine),
        Some(gpu_engine),
    );
    assert!(!node.lock().unwrap().work_rule_halted());
    assert_eq!(drain(&node).len(), 2);
    assert_eq!(validated(&node), Some(3));
    drop((node, source));
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}
