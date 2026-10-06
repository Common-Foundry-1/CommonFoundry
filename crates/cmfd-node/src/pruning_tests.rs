//! End-to-end checks of opt-in proof pruning on a devnet node.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use cmfd_consensus::wire::{decode_block, decode_transaction};
use cmfd_consensus::{Block, COINBASE_MATURITY};

use super::*;
use crate::exchange_tx_tool::{SignInput, SignOutput, SignRequest, create_key_file, sign_request};
use crate::pruning::ProofSummary;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cmfd-pruning-{label}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mine(node: &mut Node, destination: [u8; 32]) -> Block {
    let timestamp = DEVNET_GENESIS_TIMESTAMP + node.state.next_height() * 60;
    node.mine_once(destination, timestamp, DEFAULT_MINING_ATTEMPTS)
        .unwrap()
}

fn mine_to(node: &mut Node, height: u64, destination: [u8; 32]) {
    while node.state.next_height() - 1 < height {
        mine(node, destination);
    }
}

/// An empty block on `parent` for building a competing branch.
fn fork_block(node: &Node, parent: [u8; 32], timestamp: u64, destination: [u8; 32]) -> Block {
    let state = rebuild_state_to(
        &node.log,
        &node.data_dir.join(BLOCK_LOG_FILE),
        &node.index,
        node.params,
        &node.verifier,
        parent,
        None,
    )
    .unwrap();
    let height = state.next_height();
    let allocation = node.params.monetary_policy.allocation(height, 0).unwrap();
    let coinbase = Coinbase::new(height, allocation, destination, node.params.rewards);
    let challenge = BlockChallenge {
        network_id: node.params.network_id,
        previous_block: parent,
        transaction_root: merkle_root(&[coinbase.commitment(node.params.network_id)]),
        height,
        timestamp,
        target: state.expected_target().unwrap(),
    };
    let proof = node
        .verifier
        .mine(&challenge, 0, DEFAULT_MINING_ATTEMPTS)
        .unwrap();
    Block {
        version: BLOCK_VERSION,
        challenge,
        proof,
        coinbase,
        transactions: Vec::new(),
    }
}

fn tip_height(node: &Node) -> u64 {
    node.state.next_height() - 1
}

/// Mines a funded key, spends it once, and returns the spending txid and the
/// height of the block that confirmed it.
fn mine_with_transaction(node: &mut Node, keys: &TestDirectory) -> ([u8; 32], u64) {
    let key_path = keys.0.join("payer.key");
    let payer = create_key_file(&key_path).unwrap();
    let payee = create_key_file(&keys.0.join("payee.key")).unwrap();
    let miner = node.wallet_destination();
    let funding = mine(node, payer);
    for _ in 0..COINBASE_MATURITY {
        mine(node, miner);
    }
    let value = funding.coinbase.outputs[0].value;
    let signed = sign_request(
        &SignRequest {
            network_id: hex::encode(node.params.network_id),
            inputs: vec![SignInput {
                txid: hex::encode(funding.coinbase_outpoint_id()),
                vout: 0,
                value_atoms: value.to_string(),
                destination_hex: hex::encode(payer),
                key_file: key_path,
            }],
            outputs: vec![SignOutput {
                destination_hex: hex::encode(payee),
                value_atoms: "100000000".to_owned(),
            }],
            change_destination_hex: Some(hex::encode(payer)),
            fee_atoms: "1000".to_owned(),
        },
        node.params.network_id,
    )
    .unwrap();
    let transaction = decode_transaction(
        &hex::decode(&signed.transaction_hex).unwrap(),
        node.params.network_id,
    )
    .unwrap();
    let txid = transaction.txid();
    node.submit_transaction(transaction).unwrap();
    let block = mine(node, miner);
    assert_eq!(block.transactions.len(), 1);
    (txid, block.challenge.height)
}

#[test]
fn keep_window_has_a_floor() {
    let dir = TestDirectory::new("floor");
    let mut node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    assert!(matches!(
        node.configure_pruning(Some(MIN_PRUNE_KEEP_BLOCKS - 1)),
        Err(NodeError::InvalidPruneSetting(_))
    ));
    node.configure_pruning(Some(MIN_PRUNE_KEEP_BLOCKS)).unwrap();
    // Nothing to prune on a short chain.
    assert_eq!(node.prune_block_log().unwrap(), None);
}

#[test]
fn pruned_node_keeps_history_restarts_reorganizes_and_refuses_deep_forks() {
    let dir = TestDirectory::new("node");
    let keys = TestDirectory::new("keys");
    let mut node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    let miner = node.wallet_destination();
    // The floor is for operators; tests use a short window.
    node.prune_keep_blocks = Some(10);
    let (txid, tx_height) = mine_with_transaction(&mut node, &keys);
    mine_to(&mut node, 140, miner);
    assert!(pruning::list_candidates(&dir.0).contains(&128));
    let tip = node.state.tip();
    let utxos_before = node.state.utxos().len();
    let log_before = node.block_log_length;
    let pruned_block_id = node.active_block_id_at_height(tx_height).unwrap();
    let full_before = node.canonical_block(pruned_block_id).unwrap().unwrap();
    let full_before = decode_block(&full_before, node.params.network_id).unwrap();

    // A valid competing block below the future prune point, built while
    // the proofs it needs are still stored.
    let deep = fork_block(
        &node,
        node.active_block_id_at_height(127).unwrap(),
        DEVNET_GENESIS_TIMESTAMP + 128 * 60 + 9,
        [7; 32],
    );

    let report = node.prune_block_log().unwrap().unwrap();
    assert_eq!(report.anchor_height, 128);
    assert_eq!(report.newly_pruned_blocks, 128);
    assert_eq!(report.dropped_side_blocks, 0);
    assert!(report.log_bytes_after < log_before);
    assert_eq!(node.prune_height(), Some(128));
    assert_eq!(node.state.tip(), tip);
    for height in 1..=128 {
        assert!(node.block_is_pruned(node.active_block_id_at_height(height).unwrap()));
    }
    for height in 129..=140 {
        assert!(!node.block_is_pruned(node.active_block_id_at_height(height).unwrap()));
    }
    // Only the newest anchor and the candidates above it remain.
    assert_eq!(pruning::list_anchors(&dir.0), vec![128]);
    assert!(
        pruning::list_candidates(&dir.0)
            .iter()
            .all(|height| *height > 128)
    );

    // Pruned blocks keep their contents but not their proofs.
    assert!(matches!(
        node.canonical_block(pruned_block_id),
        Err(NodeError::BlockProofPruned(id)) if id == pruned_block_id
    ));
    let read = node.read_explorer_block(pruned_block_id).unwrap();
    let stored = read.block();
    assert!(stored.is_pruned());
    assert_eq!(stored.block_id(), pruned_block_id);
    assert_eq!(stored.challenge, full_before.challenge);
    assert_eq!(stored.coinbase, full_before.coinbase);
    assert_eq!(stored.transactions, full_before.transactions);
    assert_eq!(
        stored.coinbase_outpoint_id(),
        full_before.coinbase_outpoint_id()
    );
    assert_eq!(stored.proof_summary(), ProofSummary::of(&full_before.proof));
    assert_eq!(
        read.encoded_bytes(),
        encode_block(&full_before).unwrap().len()
    );
    let location = node
        .index
        .transactions
        .active_location(&txid, &node.index)
        .unwrap();
    assert_eq!(location.block_id, pruned_block_id);
    assert_eq!(location.transaction_position, 0);

    // Peers are never offered pruned blocks.
    let genesis = node.index.genesis;
    assert!(node.inventory_after(&[genesis], [0; 32], 10).is_empty());
    let above = node.active_block_id_at_height(130).unwrap();
    assert_eq!(node.inventory_after(&[above], [0; 32], 3).len(), 3);
    assert!(node.relay_inventory_after(genesis, 10).is_empty());

    // A block building on a pruned block is refused without fault.
    let pruned_parent = node.active_block_id_at_height(100).unwrap();
    assert!(matches!(
        node.submit_block(deep, DEVNET_GENESIS_TIMESTAMP + 200 * 60),
        Err(NodeError::BelowPrunePoint(_))
    ));
    assert!(node.index.is_below_prune_point(pruned_parent));

    // A reorganization above the anchor still works.
    let fork_parent = node.active_block_id_at_height(138).unwrap();
    let mut parent = fork_parent;
    let mut timestamp = DEVNET_GENESIS_TIMESTAMP + 139 * 60 + 7;
    for _ in 0..3 {
        let block = fork_block(&node, parent, timestamp, [9; 32]);
        parent = block.block_id();
        node.submit_block(block, timestamp).unwrap();
        timestamp += 60;
    }
    assert_eq!(tip_height(&node), 141);
    assert_eq!(node.state.tip(), parent);
    let tip = node.state.tip();

    // Restart from the startup snapshot.
    drop(node);
    let node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    assert!(node.startup_snapshot_used);
    assert_eq!(node.prune_height(), Some(128));
    assert_eq!(node.state.tip(), tip);

    // Restart by replaying from the anchor, without a snapshot.
    drop(node);
    for slot in 0..=1 {
        let _ = fs::remove_file(dir.0.join(format!(
            "{}.{slot}.bin",
            startup_snapshot::STARTUP_SNAPSHOT_FILE_PREFIX
        )));
    }
    let mut node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    assert!(!node.startup_snapshot_used);
    assert_eq!(node.prune_height(), Some(128));
    assert_eq!(node.state.tip(), tip);
    assert!(node.state.utxos().len() >= utxos_before);

    // Mining continues and a later prune advances the anchor.
    node.prune_keep_blocks = Some(10);
    mine_to(&mut node, 210, miner);
    let report = node.prune_block_log().unwrap().unwrap();
    assert_eq!(report.anchor_height, 192);
    assert_eq!(report.newly_pruned_blocks, 64);
    // The abandoned blocks 139..140 forked below the new anchor and are gone.
    assert_eq!(report.dropped_side_blocks, 2);
    assert_eq!(pruning::list_anchors(&dir.0), vec![192]);
    drop(node);
    let node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    assert_eq!(node.prune_height(), Some(192));
    assert_eq!(tip_height(&node), 210);
}

#[test]
fn a_missing_anchor_refuses_to_start_rather_than_guess() {
    let dir = TestDirectory::new("missing-anchor");
    let mut node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    let miner = node.wallet_destination();
    node.prune_keep_blocks = Some(10);
    mine_to(&mut node, 80, miner);
    node.prune_block_log().unwrap().unwrap();
    drop(node);
    fs::remove_file(pruning::anchor_path(&dir.0, 64)).unwrap();
    for slot in 0..=1 {
        let _ = fs::remove_file(dir.0.join(format!(
            "{}.{slot}.bin",
            startup_snapshot::STARTUP_SNAPSHOT_FILE_PREFIX
        )));
    }
    match Node::open_with_profile(&dir.0, DEVNET_PROFILE) {
        Err(NodeError::CorruptLog(message)) => assert!(message.contains("anchor"), "{message}"),
        Err(other) => panic!("unexpected error {other}"),
        Ok(_) => panic!("a pruned log without its anchor must not open"),
    }
}

#[test]
fn an_open_log_reader_defers_the_swap_without_faulting_storage() {
    let dir = TestDirectory::new("reader");
    let mut node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    let miner = node.wallet_destination();
    node.prune_keep_blocks = Some(10);
    mine_to(&mut node, 80, miner);
    let first = node.active_block_id_at_height(1).unwrap();
    let locator = node.index.blocks[&first].locator;
    let reader = node.clone_log_for_read().unwrap();

    let plan = node.plan_prune().unwrap().unwrap();
    let built = pruning::build_pruned_log(plan).unwrap();
    assert_eq!(node.finish_prune(built).unwrap(), None);
    assert!(!node.storage_faulted);
    assert_eq!(node.prune_height(), None);
    assert!(!dir.0.join("blocks.log.prune-tmp").exists());
    // The reader's view of the log is untouched.
    read_located_record(
        &reader,
        &dir.0.join(BLOCK_LOG_FILE),
        &locator,
        node.params.network_id,
        false,
    )
    .unwrap();

    // A running prune waits for the reader instead of giving up.
    let shared = std::sync::Mutex::new(node);
    let report = std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(reader);
        });
        pruning::prune_shared_node(&shared).unwrap().unwrap()
    });
    assert_eq!(report.anchor_height, 64);
    let node = shared.into_inner().unwrap();
    assert!(!node.storage_faulted);
    let status = node.status().unwrap();
    assert_eq!(status.prune_keep_blocks, Some(10));
    assert_eq!(status.pruned_height, Some(64));
}

#[test]
fn shared_prune_appends_blocks_mined_while_it_was_built() {
    let dir = TestDirectory::new("shared");
    let mut node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    let miner = node.wallet_destination();
    node.prune_keep_blocks = Some(10);
    mine_to(&mut node, 80, miner);
    let plan = node.plan_prune().unwrap().unwrap();
    let built = pruning::build_pruned_log(plan).unwrap();
    // Blocks keep arriving between building and installing the prune.
    for _ in 0..3 {
        mine(&mut node, miner);
    }
    let tip = node.state.tip();
    let report = node.finish_prune(built).unwrap().unwrap();
    assert_eq!(report.anchor_height, 64);
    assert_eq!(node.state.tip(), tip);
    let tip_entry = node.index.blocks.get(&tip).unwrap();
    assert_eq!(tip_entry.locator.version, BlockRecordVersion::V3);
    // The appended tail is readable at its new location.
    let read = node.read_explorer_block(tip).unwrap();
    assert!(!read.block().is_pruned());
    drop(node);
    // The offline storage tools accept a pruned log.
    let inspection = storage::inspect_block_log(&dir.0, DEVNET_PROFILE).unwrap();
    assert!(inspection.is_healthy());
    assert_eq!(inspection.records, 83);
    let node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    assert_eq!(node.state.tip(), tip);
    assert_eq!(node.prune_height(), Some(64));
}

#[test]
fn a_prune_waits_for_enough_free_space() {
    let dir = TestDirectory::new("free-space");
    let mut node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    let miner = node.wallet_destination();
    node.prune_keep_blocks = Some(10);
    mine_to(&mut node, 80, miner);
    let log_path = dir.0.join(BLOCK_LOG_FILE);
    let log_before = fs::metadata(&log_path).unwrap().len();

    // Too little room for a second copy of the kept blocks: no prune, no
    // temporary log, nothing changed.
    pruning::set_free_space_for_test(Some(1024));
    assert!(node.plan_prune().unwrap().is_none());
    assert_eq!(node.prune_block_log().unwrap(), None);
    assert_eq!(node.prune_height(), None);
    assert!(!node.storage_faulted);
    assert_eq!(fs::metadata(&log_path).unwrap().len(), log_before);
    assert!(!dir.0.join("blocks.log.prune-tmp").exists());

    // With room again, the same candidate prunes normally.
    pruning::set_free_space_for_test(Some(u64::MAX));
    let report = node.prune_block_log().unwrap().unwrap();
    pruning::set_free_space_for_test(None);
    assert_eq!(report.anchor_height, 64);
    assert_eq!(node.prune_height(), Some(64));
}

#[test]
fn a_stopped_prune_leaves_the_log_untouched() {
    let dir = TestDirectory::new("stopped");
    let mut node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    let miner = node.wallet_destination();
    node.prune_keep_blocks = Some(10);
    mine_to(&mut node, 80, miner);
    let log_path = dir.0.join(BLOCK_LOG_FILE);
    let log_before = fs::read(&log_path).unwrap();

    let shared = std::sync::Mutex::new(node);
    let stop = std::sync::atomic::AtomicBool::new(true);
    assert_eq!(
        pruning::prune_shared_node_until_stopped(&shared, Some(&stop)).unwrap(),
        None
    );
    {
        let node = shared.lock().unwrap();
        assert_eq!(node.prune_height(), None);
        assert!(!node.storage_faulted);
    }
    assert_eq!(fs::read(&log_path).unwrap(), log_before);
    assert!(!dir.0.join("blocks.log.prune-tmp").exists());

    // Without a stop request the same prune completes.
    let stop = std::sync::atomic::AtomicBool::new(false);
    let report = pruning::prune_shared_node_until_stopped(&shared, Some(&stop))
        .unwrap()
        .unwrap();
    assert_eq!(report.anchor_height, 64);
}

#[test]
fn the_background_pruner_prunes_and_stops_promptly() {
    let dir = TestDirectory::new("pruner-thread");
    let mut node = Node::open_with_profile(&dir.0, DEVNET_PROFILE).unwrap();
    let miner = node.wallet_destination();
    node.prune_keep_blocks = Some(10);
    mine_to(&mut node, 80, miner);
    let shared = std::sync::Arc::new(std::sync::Mutex::new(node));
    let pruner =
        pruning::spawn_pruner(std::sync::Arc::clone(&shared), std::time::Duration::ZERO).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while shared.lock().unwrap().prune_height() != Some(64) {
        assert!(
            std::time::Instant::now() < deadline,
            "background prune did not happen"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let stopping = std::time::Instant::now();
    pruner.stop();
    assert!(stopping.elapsed() < std::time::Duration::from_secs(2));

    // A pruner that is dropped instead of stopped also ends its thread.
    let pruner = pruning::spawn_pruner(
        std::sync::Arc::clone(&shared),
        pruning::PRUNE_CHECK_INTERVAL,
    )
    .unwrap();
    let dropping = std::time::Instant::now();
    drop(pruner);
    assert!(dropping.elapsed() < std::time::Duration::from_secs(2));
    assert_eq!(std::sync::Arc::strong_count(&shared), 1);
}
