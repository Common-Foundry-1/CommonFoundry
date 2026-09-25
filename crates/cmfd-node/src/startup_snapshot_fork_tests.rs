use super::*;
use crate::tests::{clean_test_dir, mined_child, test_dir};
use crate::{Block, DEVNET_GENESIS_TIMESTAMP, DEVNET_PROFILE};

fn fork_fixture(label: &str) -> (PathBuf, Node, [Block; 4]) {
    let path = test_dir(label);
    assert!(!path.exists());
    let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
    let genesis = node.params.genesis_hash;
    let t1 = DEVNET_GENESIS_TIMESTAMP + 60;
    let t2 = t1 + 60;
    let a1 = mined_child(&node, genesis, t1, 0x71);
    node.submit_block(a1.clone(), t1).unwrap();
    let b1 = mined_child(&node, genesis, t1, 0x72);
    node.submit_block(b1.clone(), t1).unwrap();
    let b2 = mined_child(&node, b1.block_id(), t2, 0x73);
    node.submit_block(b2.clone(), t2 + 20).unwrap();
    // The tie arrives later but has an earlier acceptance timestamp. Neither
    // its timestamp nor DFS traversal order may displace the earlier winner.
    let a2 = mined_child(&node, a1.block_id(), t2, 0x74);
    node.submit_block(a2.clone(), t2 + 10).unwrap();
    assert_eq!(node.state.tip(), b2.block_id());
    assert_eq!(node.index.blocks.len(), 4);
    (path, node, [a1, b1, b2, a2])
}

fn current_cache(node: &Node) -> PathBuf {
    snapshot_path(&node.data_dir, (node.index.blocks.len() & 1) as u8)
}

fn state_length(bytes: &[u8]) -> usize {
    usize::try_from(u64::from_le_bytes(
        bytes[SNAPSHOT_HEADER_BYTES - 8..SNAPSHOT_HEADER_BYTES]
            .try_into()
            .unwrap(),
    ))
    .unwrap()
}

fn refresh_digest(bytes: &mut [u8]) {
    let position = bytes.len() - SNAPSHOT_DIGEST_BYTES;
    let digest = snapshot_digest(&bytes[..position]);
    bytes[position..].copy_from_slice(&digest);
}

#[test]
fn fork_checkpoint_keeps_terminal_side_branch_and_reorgs_after_restart() {
    let (path, node, [_, _, b2, a2]) = fork_fixture("fork-cache-restart");
    let state_bytes = node.state.encode_local_snapshot().unwrap();
    // Check while the original node is alive: an inactive append must refresh
    // the cache without relying on any clean-shutdown hook or explicit request.
    let loaded = load_startup_snapshot(
        &path,
        &node.log,
        &path.join(crate::BLOCK_LOG_FILE),
        node.params,
        &node.verifier,
    )
    .unwrap()
    .expect("inactive branch append must leave an eligible checkpoint");
    assert_eq!(loaded.state.encode_local_snapshot().unwrap(), state_bytes);
    assert_eq!(loaded.index.active_chain, node.index.active_chain);
    assert_eq!(loaded.index.active_work, node.index.active_work);
    assert_eq!(loaded.index.blocks.len(), node.index.blocks.len());
    for (block_id, original) in &node.index.blocks {
        let restored = &loaded.index.blocks[block_id];
        assert_eq!(restored.locator, original.locator);
        assert_eq!(restored.successor_header, original.successor_header);
        assert_eq!(restored.cumulative_work, original.cumulative_work);
        assert_eq!(restored.ancestors, original.ancestors);
    }
    drop(loaded);
    drop(node);

    let mut node = Node::open(&path).unwrap();
    assert!(node.startup_snapshot_used);
    assert_eq!(node.state.encode_local_snapshot().unwrap(), state_bytes);
    let checkpoint = current_cache(&node);
    let before = fs::read(&checkpoint).unwrap();
    let log_length = node.block_log_length;
    let mut invalid = mined_child(&node, a2.block_id(), DEVNET_GENESIS_TIMESTAMP + 180, 0x75);
    invalid.coinbase.outputs[0].value += 1;
    assert!(
        node.submit_block(invalid, DEVNET_GENESIS_TIMESTAMP + 180)
            .is_err()
    );
    assert_eq!(node.index.blocks.len(), 4);
    assert_eq!(node.block_log_length, log_length);
    assert_eq!(fs::read(&checkpoint).unwrap(), before);

    let a3 = mined_child(&node, a2.block_id(), DEVNET_GENESIS_TIMESTAMP + 180, 0x75);
    node.submit_block(a3.clone(), a3.challenge.timestamp)
        .unwrap();
    assert_eq!(node.state.tip(), a3.block_id());
    let b3 = mined_child(&node, b2.block_id(), DEVNET_GENESIS_TIMESTAMP + 180, 0x76);
    node.submit_block(b3.clone(), b3.challenge.timestamp)
        .unwrap();
    assert_eq!(node.state.tip(), a3.block_id());
    let expected = node.state.encode_local_snapshot().unwrap();
    drop(node);

    let mut node = Node::open(&path).unwrap();
    assert!(node.startup_snapshot_used);
    assert_eq!(node.state.encode_local_snapshot().unwrap(), expected);
    let b4 = mined_child(&node, b3.block_id(), DEVNET_GENESIS_TIMESTAMP + 240, 0x76);
    node.submit_block(b4.clone(), b4.challenge.timestamp)
        .unwrap();
    assert_eq!(node.state.tip(), b4.block_id());
    assert!(node.contains_block(a2.block_id()));
    assert!(node.contains_block(a3.block_id()));
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn fork_snapshot_semantic_mutations_fall_back_without_losing_the_winner() {
    let (path, node, [_, _, b2, _]) = fork_fixture("fork-cache-mutations");
    let checkpoint = current_cache(&node);
    let original = fs::read(&checkpoint).unwrap();
    let expected = node.state.encode_local_snapshot().unwrap();
    let first_entry = SNAPSHOT_HEADER_BYTES + state_length(&original);
    let side_entry = first_entry + 3 * SNAPSHOT_ENTRY_BYTES;
    let active_header = first_entry + 2 * SNAPSHOT_ENTRY_BYTES + SNAPSHOT_ENTRY_BYTES
        - SuccessorHeaderPreflight::LOCAL_SNAPSHOT_BYTES;
    drop(node);

    for offset in [
        side_entry,         // record ordinal
        side_entry + 25,    // complete record digest
        side_entry + 57,    // accepted_at
        side_entry + 97,    // parent block id
        side_entry + 129,   // height
        active_header + 72, // plausible but incorrect active median time
        active_header + 80, // plausible but incorrect active next target
    ] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        refresh_digest(&mut bytes);
        fs::write(&checkpoint, bytes).unwrap();
        let reopened = Node::open(&path).unwrap();
        assert!(!reopened.startup_snapshot_used, "offset {offset}");
        assert_eq!(reopened.state.tip(), b2.block_id());
        assert_eq!(reopened.state.encode_local_snapshot().unwrap(), expected);
        assert_eq!(reopened.index.blocks.len(), 4);
        drop(reopened);
    }
    clean_test_dir(&path);
}

#[test]
fn a_well_formed_losing_branch_state_cannot_select_the_snapshot_winner() {
    let (path, node, [_, _, b2, a2]) = fork_fixture("fork-cache-wrong-state");
    let checkpoint = current_cache(&node);
    let original = fs::read(&checkpoint).unwrap();
    let expected = node.state.encode_local_snapshot().unwrap();
    let losing_state = crate::rebuild_state_to(
        &node.log,
        &path.join(crate::BLOCK_LOG_FILE),
        &node.index,
        node.params,
        &node.verifier,
        a2.block_id(),
        None,
    )
    .unwrap()
    .encode_local_snapshot()
    .unwrap();
    let old_state_length = state_length(&original);
    let mut forged = original[..SNAPSHOT_HEADER_BYTES].to_vec();
    forged[SNAPSHOT_HEADER_BYTES - 8..].copy_from_slice(&(losing_state.len() as u64).to_le_bytes());
    forged.extend_from_slice(&losing_state);
    forged.extend_from_slice(&original[SNAPSHOT_HEADER_BYTES + old_state_length..]);
    refresh_digest(&mut forged);
    drop(node);
    fs::write(checkpoint, forged).unwrap();
    let reopened = Node::open(&path).unwrap();
    assert!(!reopened.startup_snapshot_used);
    assert_eq!(reopened.state.tip(), b2.block_id());
    assert_eq!(reopened.state.encode_local_snapshot().unwrap(), expected);
    drop(reopened);
    clean_test_dir(&path);
}

#[test]
fn fork_checkpoint_never_hides_nonterminal_losing_record_corruption() {
    let (path, node, [a1, _, _, _]) = fork_fixture("fork-cache-corrupt-log");
    let locator = node.index.blocks[&a1.block_id()].locator;
    let log_path = path.join(crate::BLOCK_LOG_FILE);
    drop(node);
    let mut bytes = fs::read(&log_path).unwrap();
    bytes[usize::try_from(locator.offset + locator.length - 1).unwrap()] ^= 1;
    fs::write(&log_path, &bytes).unwrap();
    assert!(Node::open(&path).is_err());
    assert_eq!(
        fs::read(&log_path).unwrap(),
        bytes,
        "never discard a complete corrupt record"
    );
    clean_test_dir(&path);
}

#[test]
fn inconsistent_or_faulted_live_state_cannot_replace_a_healthy_checkpoint() {
    let (path, mut node, _) = fork_fixture("fork-cache-invalid-live");
    let checkpoint = current_cache(&node);
    let before = fs::read(&checkpoint).unwrap();
    let work = node.index.active_work;
    node.index.active_work += U512::one();
    assert!(node.persist_startup_snapshot().is_err());
    node.index.active_work = work;
    let parent = node.index.active_chain[1];
    node.index.active_chain[1] = node.index.genesis;
    assert!(node.persist_startup_snapshot().is_err());
    node.index.active_chain[1] = parent;
    node.storage_faulted = true;
    assert!(matches!(
        node.persist_startup_snapshot(),
        Err(NodeError::StorageFaulted)
    ));
    node.storage_faulted = false;
    assert_eq!(fs::read(&checkpoint).unwrap(), before);
    drop(node);
    clean_test_dir(&path);
}
