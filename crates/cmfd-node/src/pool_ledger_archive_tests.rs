// Live-ledger retirement: settled blocks and payments move to the append-only
// archive while every total they contributed to stays exact.

fn archive_test_block(index: u64) -> ([u8; 32], u64) {
    let mut block_id = [0_u8; 32];
    block_id[..8].copy_from_slice(&index.to_le_bytes());
    block_id[8] = 0xa7;
    (block_id, 1_000 + index)
}

/// `count` canonical PPLNS blocks at heights 1000.., each distributed and
/// confirmed against `chain_height`, all mined by session 1.
fn ledger_with_settled_blocks(
    directory: Option<PathBuf>,
    count: u64,
    chain_height: u64,
) -> (DurableLedger, PoolPplnsPolicy) {
    let ledger = DurableLedger::open(directory, [0x41; 32], [0x42; 32]).unwrap();
    register_session(&ledger, 1, "miner".to_owned(), test_payout_signer().payout()).unwrap();
    let policy = PoolPplnsPolicy {
        operator_fee_bps: 300,
        window_shares: 4,
    };
    for index in 0..count {
        let (block_id, height) = archive_test_block(index);
        record_accepted_share(&ledger, 1, 1, Some(policy), [0xff; 32]).unwrap();
        let block = PoolBlockCredit {
            block_id,
            parent: [0x62; 32],
            height,
            miner_reward_atoms: 1_000,
            share_target: [0xff; 32],
            block_target: [0x3f; 32],
        };
        reserve_pending_pool_block(&ledger, 1, block, 1, Some(policy)).unwrap();
        finalize_pending_pool_block(
            &ledger,
            block_id,
            PoolBlockState::Canonical,
            chain_height - height,
        )
        .unwrap();
    }
    (ledger, policy)
}

fn confirmed_payment(payout: [u8; 32], amount_atoms: u64, confirmations: u64) -> ([u8; 32], PayoutTransactionRecord) {
    let transaction = Transaction {
        network_id: [0x41; 32],
        version: 1,
        inputs: Vec::new(),
        outputs: vec![cmfd_consensus::TxOutput {
            value: amount_atoms,
            lock: OutputLock::Key(payout),
            spendable_height: 0,
        }],
    };
    (
        transaction.txid(),
        PayoutTransactionRecord {
            payout,
            amount_atoms,
            fee_atoms: 1,
            transaction,
            state: PoolPayoutTransactionState::Confirmed,
            confirmations,
        },
    )
}

/// What `reconcile_pool_blocks_for_node` does for a tip at `chain_height`:
/// fresh chain state for every block, archive, then retire in a transaction.
fn retire(ledger: &DurableLedger, chain_height: u64) -> RetiredPoolRecords {
    let updates = ledger
        .state
        .lock()
        .unwrap()
        .blocks
        .iter()
        .map(|(block_id, record)| {
            let confirmations = match record.state {
                PoolBlockState::Canonical => chain_height - record.height,
                _ => 0,
            };
            (*block_id, record.state, confirmations)
        })
        .collect::<Vec<_>>();
    let retired = settled_pool_records(&ledger.state.lock().unwrap(), &updates, chain_height);
    ledger.archive(&retired).unwrap();
    ledger
        .transaction(|ledger| retire_pool_records(ledger, &retired))
        .unwrap();
    retired
}

fn retired_block_ids(retired: &RetiredPoolRecords) -> Vec<[u8; 32]> {
    let mut ids = retired
        .blocks
        .iter()
        .map(|(block_id, _, _)| *block_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

#[test]
fn settled_blocks_retire_beyond_the_live_window_and_depth() {
    // Blocks 0 and 1 are at least POOL_LEDGER_RETIRE_CONFIRMATIONS deep and
    // outside the newest 100; block 2 is exactly that deep but inside them.
    let chain_height = archive_test_block(2).1 + POOL_LEDGER_RETIRE_CONFIRMATIONS;
    let (ledger, _) = ledger_with_settled_blocks(None, 102, chain_height);
    let before = snapshot_ledger(&ledger).unwrap();
    assert_eq!(before.pool_blocks, 102);
    assert_eq!(before.operator_fee_atoms, 102 * 30);
    assert_eq!(before.credited_devnet_atoms, 102 * 970);

    let retired = retire(&ledger, chain_height);
    assert_eq!(
        retired_block_ids(&retired),
        vec![archive_test_block(0).0, archive_test_block(1).0]
    );
    assert!(retired.payout_transactions.is_empty());

    let after = snapshot_ledger(&ledger).unwrap();
    assert_eq!(after.pool_blocks, 102);
    assert_eq!(after.canonical_pool_blocks, 102);
    assert_eq!(after.orphaned_pool_blocks, 0);
    assert_eq!(after.pplns_distributed_blocks, 102);
    assert_eq!(after.operator_fee_atoms, before.operator_fee_atoms);
    assert_eq!(after.credited_devnet_atoms, before.credited_devnet_atoms);
    assert_eq!(after.payouts, before.payouts);
    assert_eq!(after.blocks.len(), 100);
    {
        let state = ledger.state.lock().unwrap();
        assert_eq!(state.blocks.len(), 100);
        assert_eq!(state.pplns_blocks.len(), 100);
        assert_eq!(state.archived_canonical_blocks, 2);
        assert_eq!(state.archived_orphaned_blocks, 0);
        assert_eq!(state.archived_operator_fee_atoms, 60);
        assert!(!state.blocks.contains_key(&archive_test_block(1).0));
        assert!(state.blocks.contains_key(&archive_test_block(2).0));
    }
    // Nothing more qualifies at the same tip.
    assert!(retire(&ledger, chain_height).is_empty());
}

#[test]
fn immature_and_undistributed_blocks_stay_live() {
    // Every block is inside the newest 100 or shallower than the retirement
    // depth, so a tip that still distributes block 0 retires nothing.
    let chain_height = archive_test_block(0).1 + POOL_LEDGER_RETIRE_CONFIRMATIONS - 1;
    let (ledger, _) = ledger_with_settled_blocks(None, 101, chain_height);
    assert!(retire(&ledger, chain_height).is_empty());
    assert_eq!(ledger.state.lock().unwrap().blocks.len(), 101);

    // One block later block 0 is deep enough and outside the window.
    let retired = retire(&ledger, chain_height + 1);
    assert_eq!(retired_block_ids(&retired), vec![archive_test_block(0).0]);
    assert_eq!(ledger.state.lock().unwrap().blocks.len(), 100);
}

#[test]
fn orphaned_blocks_that_never_distributed_retire_when_deep() {
    let orphan_height = archive_test_block(0).1 - 1;
    let chain_height = orphan_height + POOL_LEDGER_RETIRE_CONFIRMATIONS;
    let (ledger, policy) = ledger_with_settled_blocks(None, 101, chain_height);
    record_accepted_share(&ledger, 1, 1, Some(policy), [0xff; 32]).unwrap();
    let orphan = PoolBlockCredit {
        block_id: [0xe1; 32],
        parent: [0x62; 32],
        height: orphan_height,
        miner_reward_atoms: 1_000,
        share_target: [0xff; 32],
        block_target: [0x3f; 32],
    };
    reserve_pending_pool_block(&ledger, 1, orphan, 1, Some(policy)).unwrap();
    finalize_pending_pool_block(&ledger, orphan.block_id, PoolBlockState::Orphaned, 0).unwrap();
    let before = snapshot_ledger(&ledger).unwrap();
    assert_eq!(before.orphaned_pool_blocks, 1);
    assert_eq!(before.pool_blocks, 102);

    // The newest canonical block is only 500 deep; only the orphan qualifies.
    let retired = retire(&ledger, chain_height);
    assert_eq!(retired_block_ids(&retired), vec![orphan.block_id]);
    let after = snapshot_ledger(&ledger).unwrap();
    assert_eq!(after.orphaned_pool_blocks, 1);
    assert_eq!(after.canonical_pool_blocks, 101);
    assert_eq!(after.pool_blocks, 102);
    assert_eq!(after.operator_fee_atoms, before.operator_fee_atoms);
    assert_eq!(after.credited_devnet_atoms, before.credited_devnet_atoms);
    let state = ledger.state.lock().unwrap();
    assert_eq!(state.archived_orphaned_blocks, 1);
    assert_eq!(state.archived_canonical_blocks, 0);
    assert_eq!(state.archived_operator_fee_atoms, 0);
    assert!(!state.blocks.contains_key(&orphan.block_id));
    assert!(!state.pplns_blocks.contains_key(&orphan.block_id));
}

#[test]
fn settled_payments_fold_into_settled_atoms_and_keep_credit_exact() {
    let ledger = DurableLedger::open(None, [0x41; 32], [0x42; 32]).unwrap();
    let payout = test_payout_signer().payout();
    register_session(&ledger, 1, "miner".to_owned(), payout).unwrap();
    credit_accepted_share(&ledger, 1, 120).unwrap();
    let (shallow_txid, shallow) =
        confirmed_payment(payout, 20, POOL_LEDGER_RETIRE_CONFIRMATIONS - 1);
    let (deep_txid, deep) = confirmed_payment(payout, 50, POOL_LEDGER_RETIRE_CONFIRMATIONS);
    ledger
        .transaction(|ledger| {
            ledger.payout_transactions.insert(shallow_txid, shallow.clone());
            ledger.payout_transactions.insert(deep_txid, deep.clone());
            Ok(())
        })
        .unwrap();
    let totals = |ledger: &DurableLedger| {
        let snapshot = snapshot_ledger(ledger).unwrap();
        let stats = &snapshot.payouts[0];
        (
            stats.reserved_payout_atoms,
            stats.confirmed_payout_atoms,
            stats.available_payout_atoms,
            snapshot.payout_transactions.len(),
        )
    };
    assert_eq!(totals(&ledger), (70, 70, 50, 2));

    let retired = retire(&ledger, 0);
    assert!(retired.blocks.is_empty());
    assert_eq!(
        retired
            .payout_transactions
            .iter()
            .map(|(txid, _)| *txid)
            .collect::<Vec<_>>(),
        vec![deep_txid]
    );
    assert_eq!(totals(&ledger), (70, 70, 50, 1));
    {
        let state = ledger.state.lock().unwrap();
        assert_eq!(state.payouts[&payout].settled_atoms, 50);
        assert!(state.payout_transactions.contains_key(&shallow_txid));
        assert_eq!(payout_available_atoms(&state, payout).unwrap(), 50);
        assert_eq!(payout_transaction_totals(&state).unwrap()[&payout], (70, 70));
    }

    // Settled payments still count against credit: exactly the remaining 50
    // is accepted, one atom more is rejected (and, since validation runs per
    // persisted batch, faults the ledger, so this check comes last).
    let (exact_txid, exact) = confirmed_payment(payout, 50, 1);
    ledger
        .transaction(|ledger| {
            ledger.payout_transactions.insert(exact_txid, exact.clone());
            Ok(())
        })
        .unwrap();
    assert_eq!(totals(&ledger), (120, 120, 0, 2));
    let (over_txid, over) = confirmed_payment(payout, 1, 1);
    assert!(matches!(
        ledger.transaction(|ledger| {
            ledger.payout_transactions.insert(over_txid, over.clone());
            Ok(())
        }),
        Err(PoolError::LedgerCorrupt(message)) if message.contains("exceeds earned credit")
    ));
}

#[test]
fn retired_records_are_appended_to_the_archive_and_survive_restart() {
    let root = TestRoot::new("ledger-archive");
    let directory = root.path().join("ledger");
    let chain_height = archive_test_block(2).1 + POOL_LEDGER_RETIRE_CONFIRMATIONS;
    let (ledger, _) = ledger_with_settled_blocks(Some(directory.clone()), 102, chain_height);
    let payout = test_payout_signer().payout();
    let (txid, payment) = confirmed_payment(payout, 500, POOL_LEDGER_RETIRE_CONFIRMATIONS);
    ledger
        .transaction(|ledger| {
            ledger.payout_transactions.insert(txid, payment.clone());
            Ok(())
        })
        .unwrap();
    let stored_ledgers = || {
        (0..=1_u8)
            .filter_map(|slot| {
                fs::read(directory.join(format!("{POOL_LEDGER_FILE_PREFIX}.{slot}.json"))).ok()
            })
            .collect::<Vec<_>>()
    };
    // Until something is archived the snapshot carries no new fields, so a
    // 1.0.1 node still reads it.
    assert!(!stored_ledgers().is_empty());
    assert!(
        stored_ledgers()
            .iter()
            .all(|bytes| !bytes.windows(9).any(|window| window == b"archived_"))
    );
    assert!(!directory.join(POOL_LEDGER_ARCHIVE_FILE).exists());

    let retired = retire(&ledger, chain_height);
    assert_eq!(retired.blocks.len(), 2);
    assert_eq!(retired.payout_transactions.len(), 1);
    let archive = fs::read_to_string(directory.join(POOL_LEDGER_ARCHIVE_FILE)).unwrap();
    let lines = archive
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    for line in &lines {
        assert_eq!(line["schema"], POOL_LEDGER_ARCHIVE_SCHEMA);
        assert!(line["archived_at_unix_seconds"].as_u64().unwrap() > 0);
    }
    let mut archived_blocks = lines
        .iter()
        .filter(|line| line["kind"] == "block")
        .map(|line| {
            assert_eq!(line["record"]["state"], "canonical");
            assert_eq!(line["pplns"]["distributed"], true);
            assert_eq!(line["pplns"]["operator_fee_atoms"], 30);
            line["block_id"].as_str().unwrap().to_owned()
        })
        .collect::<Vec<_>>();
    archived_blocks.sort();
    assert_eq!(
        archived_blocks,
        vec![
            hex::encode(archive_test_block(0).0),
            hex::encode(archive_test_block(1).0)
        ]
    );
    let archived_payment = lines
        .iter()
        .find(|line| line["kind"] == "payout_transaction")
        .unwrap();
    assert_eq!(archived_payment["txid"], hex::encode(txid));
    assert_eq!(archived_payment["record"]["amount_atoms"], 500);
    assert_eq!(archived_payment["record"]["state"], "confirmed");

    let generation = ledger.state.lock().unwrap().generation;
    drop(ledger);
    let reopened = DurableLedger::open(Some(directory.clone()), [0x41; 32], [0x42; 32]).unwrap();
    let snapshot = snapshot_ledger(&reopened).unwrap();
    assert_eq!(snapshot.pool_blocks, 102);
    assert_eq!(snapshot.canonical_pool_blocks, 102);
    assert_eq!(snapshot.operator_fee_atoms, 102 * 30);
    assert_eq!(snapshot.payouts[0].confirmed_payout_atoms, 500);
    assert_eq!(snapshot.payouts[0].available_payout_atoms, 102 * 970 - 500);
    let state = reopened.state.lock().unwrap();
    assert_eq!(state.generation, generation);
    assert_eq!(state.archived_canonical_blocks, 2);
    assert_eq!(state.archived_operator_fee_atoms, 60);
    assert_eq!(state.payouts[&payout].settled_atoms, 500);
    assert_eq!(state.blocks.len(), 100);
    assert!(state.payout_transactions.is_empty());
}
