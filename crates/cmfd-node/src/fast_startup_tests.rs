//! Fast start from the startup snapshot and index cache, and the background
//! history scrub that re-checks what a fast start did not read.

use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use super::*;
use crate::explorer_address::ExplorerAddress;
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
fn the_scrub_checks_and_fills_the_newest_records_first() {
    let path = test_dir("scrub-newest-first");
    let (_, _, records) = history(&path);
    // This open reads the records the cache missed and saves a cache that
    // covers all four; then every address entry becomes a hint.
    drop(Node::open(&path).unwrap());
    startup_snapshot::rewrite_index_cache_as_v1(&path, &[]);
    let log_path = path.join(BLOCK_LOG_FILE);
    let mut bytes = fs::read(&log_path).unwrap();
    bytes[usize::try_from(records[2].offset + 100).unwrap()] ^= 1;
    fs::write(&log_path, &bytes).unwrap();
    let hint_blocks = |node: &Node| {
        let mut blocks: Vec<[u8; 32]> = node.index.addresses.hint_blocks().into_keys().collect();
        blocks.sort_unstable();
        blocks
    };
    let blocks = |heights: &[usize]| {
        let mut blocks: Vec<[u8; 32]> = heights
            .iter()
            .map(|height| records[*height].block_id)
            .collect();
        blocks.sort_unstable();
        blocks
    };

    let node = Node::open(&path).unwrap();
    assert!(node.startup_snapshot_used);
    assert_eq!(hint_blocks(&node), blocks(&[1, 2, 3, 4]));
    // One record per batch, newest first: records 4 and 3 are checked and
    // filled before the damaged record 2 faults storage, and record 1 is
    // never reached. Oldest first would fill record 1 and nothing else.
    let shared = Mutex::new(node);
    history_scrub::scrub_in_batches(&shared, &AtomicBool::new(false), false, 1).unwrap();
    let node = shared.into_inner().unwrap();
    let status = node.status().unwrap();
    assert!(!status.storage_healthy);
    assert!(!status.history_scrub_complete);
    assert_eq!(status.history_scrub_verified_records, 2);
    assert_eq!(hint_blocks(&node), blocks(&[1, 2]));
    drop(node);
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
fn the_index_cache_leaves_out_entries_for_blocks_the_fork_index_lacks() {
    let path = test_dir("cache-unknown-block");
    let (early, _, _) = history(&path);
    let mut node = Node::open(&path).unwrap();
    // Entries of a block that is gone, as a prune dropping a side block left
    // them before 1.0.16. Written out, the loader would refuse the cache.
    let gone = [0x5a; 32];
    node.index.transactions.insert_block(gone, [[0x5b; 32]]);
    node.index.addresses.insert_entries([(
        [0x5c; 32],
        explorer_address_index::AddressLocation {
            height: 1,
            position: 0,
            block_id: gone,
        },
    )]);
    node.persist_index_cache().unwrap();
    drop(node);

    let mut node = Node::open(&path).unwrap();
    assert!(node.startup_snapshot_used);
    assert!(!node.status().unwrap().history_scrub_complete);
    assert!(
        !node
            .index
            .transactions
            .entries()
            .any(|(txid, _)| txid == [0x5b; 32])
    );
    assert!(
        node.index
            .addresses
            .entries()
            .all(|(_, location, _)| location.block_id != gone)
    );
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

/// Every page of the key's history, and the block-log bytes reading them took.
fn address_pages(node: &mut Node, address: [u8; 32]) -> (Vec<ExplorerAddress>, u64) {
    let bytes = log_record_bytes_read();
    let mut pages = vec![node.explorer_address(&hex::encode(address), None).unwrap()];
    while let Some(cursor) = pages.last().unwrap().next_cursor.clone() {
        pages.push(
            node.explorer_address(&hex::encode(address), Some(&cursor))
                .unwrap(),
        );
    }
    (pages, log_record_bytes_read() - bytes)
}

fn history_keys() -> [[u8; 32]; 3] {
    [
        default_miner_destination(),
        insecure_dev_destination(0x31),
        insecure_dev_destination(0x12),
    ]
}

#[test]
fn a_format_1_index_cache_upgrades_without_a_full_scan() {
    let path = test_dir("cache-format-1");
    let (_, _, records) = history(&path);
    let expected: Vec<_> = {
        let mut node = Node::open(&path).unwrap();
        history_keys()
            .iter()
            .map(|key| address_pages(&mut node, *key).0)
            .collect()
    };
    // As 1.0.15 wrote it, plus a location its block does not show.
    let stale = (
        insecure_dev_destination(0x7a),
        crate::explorer_address_index::AddressLocation {
            height: 1,
            position: 0,
            block_id: records[1].block_id,
        },
    );
    startup_snapshot::rewrite_index_cache_as_v1(&path, &[stale]);
    assert_eq!(startup_snapshot::index_cache_format(&path).0, 1);

    let mut node = Node::open(&path).unwrap();
    assert!(node.startup_snapshot_used);
    assert!(!node.status().unwrap().history_scrub_complete);
    // Startup saved the cache in the new format at once, hints included.
    let (format, hints) = startup_snapshot::index_cache_format(&path);
    assert_eq!(format, 2);
    assert_eq!(hints, node.index.addresses.entry_count());
    assert!(node.index.addresses.contains(&stale.0, stale.1));
    // A page over hint entries authenticates their blocks once and fills
    // every key in them; the same page then reads nothing.
    let reads = node.explorer_block_reads;
    let (recipient, bytes) = address_pages(&mut node, history_keys()[1]);
    assert_eq!(recipient, expected[1]);
    assert_eq!(node.explorer_block_reads - reads, 2);
    assert!(node.explorer_block_reads - reads <= explorer_address::EXPLORER_ADDRESS_PAGE_SIZE);
    assert!(bytes > 0);
    assert_eq!(address_pages(&mut node, history_keys()[1]), (recipient, 0));
    // Blocks 1 and 3 still hold hints; the scrub fills them and drops the
    // location block 1 does not show.
    let hint_blocks = node.index.addresses.hint_blocks();
    assert_eq!(hint_blocks.len(), 2);
    assert!(hint_blocks.contains_key(&records[1].block_id));
    assert!(hint_blocks.contains_key(&records[3].block_id));

    let node = scrub(node);
    let status = node.status().unwrap();
    assert!(status.storage_healthy);
    assert!(status.history_scrub_complete);
    assert!(node.index.addresses.hint_blocks().is_empty());
    assert!(!node.index.addresses.contains(&stale.0, stale.1));
    assert_eq!(startup_snapshot::index_cache_format(&path), (2, 0));
    drop(node);

    let mut reopened = Node::open(&path).unwrap();
    assert!(reopened.startup_snapshot_used);
    assert!(reopened.index.addresses.hint_blocks().is_empty());
    for (key, expected) in history_keys().iter().zip(&expected) {
        assert_eq!(address_pages(&mut reopened, *key), (expected.clone(), 0));
    }
    drop(reopened);
    clean_test_dir(&path);
}

#[test]
fn a_format_1_index_cache_on_a_pruning_node_is_filled_after_the_startup_prune() {
    let path = test_dir("cache-format-1-pruned");
    let mut node = Node::open(&path).unwrap();
    // The floor is for operators; tests use a short window.
    node.prune_keep_blocks = Some(10);
    while node.state.next_height() <= 140 {
        mine(&mut node);
    }
    node.persist_index_cache().unwrap();
    let expected: Vec<_> = history_keys()
        .iter()
        .map(|key| address_pages(&mut node, *key).0)
        .collect();
    drop(node);
    startup_snapshot::rewrite_index_cache_as_v1(&path, &[]);

    // As cmfd-node starts a pruning node: open, prune, then the scrub.
    let mut node = Node::open(&path).unwrap();
    assert!(node.startup_snapshot_used);
    let below_anchor = node.active_block_id_at_height(1).unwrap();
    assert!(
        node.index
            .addresses
            .hint_blocks()
            .contains_key(&below_anchor)
    );
    node.prune_keep_blocks = Some(10);
    assert_eq!(node.prune_block_log().unwrap().unwrap().anchor_height, 128);
    // The pruned log was written from authenticated reads, but its records
    // still hold hints, so the scrub still has a pass to run.
    assert!(!node.status().unwrap().history_scrub_complete);
    let mut node = scrub(node);
    let status = node.status().unwrap();
    assert!(status.storage_healthy);
    assert!(status.history_scrub_complete);
    assert_eq!(status.pruned_height, Some(128));
    assert!(node.index.addresses.hint_blocks().is_empty());
    assert_eq!(startup_snapshot::index_cache_format(&path), (2, 0));
    for (key, expected) in history_keys().iter().zip(&expected) {
        assert_eq!(address_pages(&mut node, *key), (expected.clone(), 0));
    }
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn an_inconsistent_format_2_index_cache_falls_back_to_the_full_scan() {
    // Row layout: address 0..32, block 32..64, height 64..72, position
    // 72..80, flags 80, txid 81..113, timestamp 113..121, received atoms
    // 121..137, received outputs 137..139, spent inputs 139..141, kind 141.
    fn coinbase(row: &[u8]) -> bool {
        row[72..80] == [0; 8] && row[80] == 1
    }
    fn transaction(row: &[u8]) -> bool {
        row[72..80] != [0; 8] && row[80] == 1
    }
    // A received row passes the kind rule with no spent inputs, so only the
    // counts rule can refuse it once its counts are zeroed.
    fn received(row: &[u8]) -> bool {
        transaction(row) && row[141] == 1
    }
    /// A name, which row to pick and how to change it.
    type Tamper = (&'static str, fn(&[u8]) -> bool, fn(&mut [u8]));
    let tampers: [Tamper; 6] = [
        ("coinbase txid", coinbase, |row: &mut [u8]| row[81] ^= 1),
        ("both counts zero", received, |row: &mut [u8]| {
            row[137..141].fill(0)
        }),
        ("height", coinbase, |row: &mut [u8]| {
            let height = u64::from_le_bytes(row[64..72].try_into().unwrap()) + 1;
            row[64..72].copy_from_slice(&height.to_le_bytes());
        }),
        ("hint flag with facts", coinbase, |row: &mut [u8]| {
            row[80] = 0
        }),
        (
            "received at the coinbase position",
            coinbase,
            |row: &mut [u8]| row[141] = 1,
        ),
        (
            "txid absent from the transaction section",
            transaction,
            |row: &mut [u8]| row[81] ^= 1,
        ),
    ];
    let path = test_dir("cache-format-2-inconsistent");
    history(&path);
    let expected: Vec<_> = {
        let mut node = Node::open(&path).unwrap();
        history_keys()
            .iter()
            .map(|key| address_pages(&mut node, *key).0)
            .collect()
    };
    for (name, pick, edit) in tampers {
        startup_snapshot::tamper_index_address_row(&path, pick, edit);
        for full_scan in [true, false] {
            let mut node = Node::open(&path).unwrap();
            assert!(node.startup_snapshot_used, "{name}");
            // A refused cache costs a full scan, which writes a valid cache,
            // so the next start is fast again.
            assert_eq!(
                node.status().unwrap().history_scrub_complete,
                full_scan,
                "{name}"
            );
            for (key, expected) in history_keys().iter().zip(&expected) {
                assert_eq!(&address_pages(&mut node, *key).0, expected, "{name}");
            }
            drop(node);
        }
    }
    clean_test_dir(&path);
}
