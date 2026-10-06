//! Fast start from the startup snapshot and index cache, and the background
//! history scrub that re-checks what a fast start did not read.

use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use super::*;
use crate::tests::{clean_test_dir, spend_coinbase_output, test_dir};

fn mine(node: &mut Node) -> Block {
    let now = DEVNET_GENESIS_TIMESTAMP + node.state.next_height() * 60;
    node.mine_once(default_miner_destination(), now, DEFAULT_MINING_ATTEMPTS)
        .unwrap()
}

/// Four blocks with a payment in block 2 (covered by the index cache) and one
/// in block 4 (written after it). Returns both txids and each height's record.
fn history(path: &Path) -> (String, String, Vec<BlockRecordLocator>) {
    let mut node = Node::open(path).unwrap();
    let funding = mine(&mut node);
    let early = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
    let early_id = hex::encode(early.txid());
    node.submit_transaction(early).unwrap();
    mine(&mut node);
    node.persist_index_cache().unwrap();
    mine(&mut node);
    let late = spend_coinbase_output(&node, &funding, 1, 0x11, 0x31, 1);
    let late_id = hex::encode(late.txid());
    node.submit_transaction(late).unwrap();
    mine(&mut node);
    let records = (0..=4)
        .map(|height| match node.active_block_id_at_height(height) {
            Some(block_id) if height > 0 => node.index.blocks[&block_id].locator,
            _ => node.index.blocks[&node.active_block_id_at_height(1).unwrap()].locator,
        })
        .collect();
    (early_id, late_id, records)
}

fn scrub(node: Node) -> Node {
    let shared = Mutex::new(node);
    history_scrub::scrub(&shared, &AtomicBool::new(false), false).unwrap();
    shared.into_inner().unwrap()
}

#[test]
fn fast_start_reads_only_new_records_and_matches_a_full_scan() {
    let path = test_dir("fast-start");
    let (early, late, _) = history(&path);

    let mut fast = Node::open(&path).unwrap();
    assert!(fast.startup_snapshot_used);
    assert!(!fast.status().unwrap().history_scrub_complete);
    let found = |node: &mut Node, txid: &str| node.explorer_transaction(txid).unwrap().unwrap();
    assert_eq!(found(&mut fast, &early).block_height, Some(2));
    assert_eq!(found(&mut fast, &late).block_height, Some(4));
    let shape = (
        fast.index.transactions.entry_count(),
        fast.index.addresses.entry_count(),
    );
    drop(fast);

    // Without the cache the same snapshot is checked by a full scan, which
    // builds identical indexes.
    fs::remove_file(path.join("startup-index.bin")).unwrap();
    let mut full = Node::open(&path).unwrap();
    assert!(full.startup_snapshot_used);
    assert!(full.status().unwrap().history_scrub_complete);
    assert_eq!(
        (
            full.index.transactions.entry_count(),
            full.index.addresses.entry_count()
        ),
        shape
    );
    assert_eq!(found(&mut full, &early).block_height, Some(2));
    assert_eq!(found(&mut full, &late).block_height, Some(4));
    drop(full);
    clean_test_dir(&path);
}

#[test]
fn history_scrub_verifies_every_older_record() {
    let path = test_dir("scrub-clean");
    history(&path);
    let node = scrub(Node::open(&path).unwrap());
    let status = node.status().unwrap();
    assert!(status.history_scrub_complete);
    assert_eq!(status.history_scrub_verified_records, 4);
    assert!(status.storage_healthy);
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn a_corrupt_older_record_is_caught_by_the_scrub_and_the_log_stays_authoritative() {
    let path = test_dir("scrub-corrupt");
    let (_, _, records) = history(&path);
    let log_path = path.join(BLOCK_LOG_FILE);
    let target = records[2];
    let mut bytes = fs::read(&log_path).unwrap();
    bytes[usize::try_from(target.offset + 100).unwrap()] ^= 1;
    fs::write(&log_path, &bytes).unwrap();

    // The damaged record is covered by the cache, so startup does not read it.
    let node = Node::open(&path).unwrap();
    assert!(!node.status().unwrap().history_scrub_complete);
    let node = scrub(node);
    let status = node.status().unwrap();
    assert!(!status.storage_healthy);
    assert!(!status.history_scrub_complete);
    drop(node);

    // The caches were moved aside, so the next start scans the log and
    // refuses the damaged record instead of trusting the cache again.
    let names: Vec<String> = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(!names.iter().any(|name| name == "startup-index.bin"));
    assert!(
        names
            .iter()
            .any(|name| name.starts_with("startup-index.bin.invalid-"))
    );
    assert!(
        !names
            .iter()
            .any(|name| name.starts_with("startup-state.") && name.ends_with(".bin"))
    );
    assert!(Node::open(&path).is_err());
    assert_eq!(
        fs::read(&log_path).unwrap(),
        bytes,
        "never rewrite a complete corrupt record"
    );
    clean_test_dir(&path);
}

#[test]
fn a_damaged_index_cache_falls_back_to_the_full_scan() {
    let path = test_dir("cache-damaged");
    let (early, _, _) = history(&path);
    let cache = path.join("startup-index.bin");
    let mut bytes = fs::read(&cache).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(&cache, bytes).unwrap();

    let mut node = Node::open(&path).unwrap();
    assert!(node.startup_snapshot_used);
    assert!(node.status().unwrap().history_scrub_complete);
    assert_eq!(
        node.explorer_transaction(&early)
            .unwrap()
            .unwrap()
            .block_height,
        Some(2)
    );
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn a_full_scan_still_refuses_a_corrupt_record_the_cache_does_not_cover() {
    let path = test_dir("tail-corrupt");
    let (_, _, records) = history(&path);
    let log_path = path.join(BLOCK_LOG_FILE);
    let target = records[3];
    let mut bytes = fs::read(&log_path).unwrap();
    bytes[usize::try_from(target.offset + 100).unwrap()] ^= 1;
    fs::write(&log_path, &bytes).unwrap();
    // Record 3 is newer than the cache, so startup reads it, rejects the
    // cache path and the full scan refuses the damaged log.
    assert!(Node::open(&path).is_err());
    clean_test_dir(&path);
}

#[test]
fn a_pruned_log_restarts_fast_and_passes_the_scrub() {
    let path = test_dir("scrub-pruned");
    let mut node = Node::open(&path).unwrap();
    // The floor is for operators; tests use a short window.
    node.prune_keep_blocks = Some(10);
    while node.state.next_height() <= 140 {
        mine(&mut node);
    }
    let report = node.prune_block_log().unwrap().unwrap();
    assert_eq!(report.anchor_height, 128);
    assert!(node.status().unwrap().history_scrub_complete);
    drop(node);

    let node = Node::open(&path).unwrap();
    assert!(node.startup_snapshot_used);
    assert!(!node.status().unwrap().history_scrub_complete);
    let node = scrub(node);
    let status = node.status().unwrap();
    assert!(status.history_scrub_complete);
    assert!(status.storage_healthy);
    assert_eq!(status.pruned_height, Some(128));
    drop(node);
    clean_test_dir(&path);
}
