// End-to-end accounting regressions use real local TLS sessions, signed
// transactions and durable nodes with the tiny V2 reference proof. They do not
// qualify ProductionV4 GPU proofs or stand in for a signed-package rehearsal.

#[test]
fn payout_mempool_conflict_preserves_reservation_and_exact_transaction_on_restart() {
    let root = TestRoot::new("payout-conflict-restart");
    let node_directory = root.path().join("node");
    let open_node = || {
        Arc::new(Mutex::new(
            Node::open_with_profile(&node_directory, crate::DEVNET_PROFILE).unwrap(),
        ))
    };
    let node = open_node();
    let pool_wallet = node.lock().unwrap().wallet_destination();
    let now = unix_time_seconds().unwrap();
    for offset in 0..=COINBASE_MATURITY {
        node.lock()
            .unwrap()
            .mine_once(pool_wallet, now + offset, 10_000)
            .unwrap();
    }
    let recipient = test_payout_signer().payout();
    let (certificate, key, _) = certificate(&root);
    let mut config = PoolServerConfig::devnet(
        "127.0.0.1:0".parse().unwrap(),
        fs::read(certificate).unwrap(),
        fs::read(key).unwrap(),
        pool_wallet,
    );
    config.ledger_directory = Some(root.path().join("ledger"));
    config.payout_policy = Some(PoolPayoutPolicy {
        minimum_payout_atoms: 100,
        fee_atoms: 1,
    });
    let server = spawn_pool_server(Arc::clone(&node), config.clone()).unwrap();
    register_session(
        &server.shared.ledger,
        1,
        "conflict-worker".to_owned(),
        recipient,
    )
    .unwrap();
    credit_accepted_share(&server.shared.ledger, 1, 120).unwrap();

    // Reconstruct the durable prepare-before-broadcast boundary. Another local
    // transaction occupies the input in the mempool, but has not spent it on
    // chain and can disappear. The original payout remains a valid signature.
    let (transaction, conflict) = {
        let mut node = node.lock().unwrap();
        let (transaction, _) = node.prepare_dev_wallet_payment(recipient, 120, 1).unwrap();
        let (conflict, _) = node
            .prepare_dev_wallet_payment(pool_wallet, 121, 1)
            .unwrap();
        assert_eq!(transaction.inputs[0].previous, conflict.inputs[0].previous);
        node.submit_transaction(conflict.clone()).unwrap();
        (transaction, conflict)
    };
    let txid = transaction.txid();
    server
        .shared
        .ledger
        .transaction(|ledger| {
            ledger.payout_transactions.insert(
                txid,
                PayoutTransactionRecord {
                    payout: recipient,
                    amount_atoms: 120,
                    fee_atoms: 1,
                    transaction: transaction.clone(),
                    state: PoolPayoutTransactionState::Prepared,
                    confirmations: 0,
                },
            );
            Ok(())
        })
        .unwrap();

    reconcile_pool_payouts(&server.shared, false).unwrap();
    let conflicted = snapshot_ledger(&server.shared.ledger).unwrap();
    assert_eq!(conflicted.payout_transactions[0].state, "prepared");
    assert_eq!(conflicted.payouts[0].reserved_payout_atoms, 120);
    assert_eq!(conflicted.payouts[0].available_payout_atoms, 0);
    for _ in 0..3 {
        reconcile_pool_payouts(&server.shared, true).unwrap();
        let retry = snapshot_ledger(&server.shared.ledger).unwrap();
        assert_eq!(retry.payout_transactions, conflicted.payout_transactions);
        assert_eq!(retry.payouts[0].available_payout_atoms, 0);
    }
    server.stop().unwrap();
    drop(node);

    let node = open_node();
    assert!(
        !node
            .lock()
            .unwrap()
            .mempool_contains_transaction(conflict.txid())
    );
    let server = spawn_pool_server(Arc::clone(&node), config).unwrap();
    let resumed = server.ledger_snapshot().unwrap();
    assert_eq!(resumed.payout_transactions.len(), 1);
    assert_eq!(resumed.payout_transactions[0].txid, hex::encode(txid));
    assert_eq!(resumed.payout_transactions[0].state, "broadcast");
    assert_eq!(resumed.payouts[0].available_payout_atoms, 0);
    assert!(node.lock().unwrap().mempool_contains_transaction(txid));
    let block = node
        .lock()
        .unwrap()
        .mine_once(pool_wallet, now + COINBASE_MATURITY + 1, 10_000)
        .unwrap();
    assert_eq!(block.transactions, vec![transaction]);
    reconcile_pool_payouts(&server.shared, true).unwrap();
    let settled = server.ledger_snapshot().unwrap();
    assert_eq!(settled.payout_transactions.len(), 1);
    assert_eq!(settled.payout_transactions[0].state, "confirmed");
    assert_eq!(settled.payouts[0].confirmed_payout_atoms, 120);
    assert_eq!(settled.payouts[0].available_payout_atoms, 0);
    server.stop().unwrap();
}

#[test]
fn pplns_reference_chain_maturity_payout_and_restart_are_exactly_once() {
    let root = TestRoot::new("pplns-chain-lifecycle");
    let node_directory = root.path().join("node");
    let open_node = || {
        Arc::new(Mutex::new(
            Node::open_with_profile(&node_directory, crate::DEVNET_PROFILE).unwrap(),
        ))
    };
    let node = open_node();
    let pool_wallet = node.lock().unwrap().wallet_destination();
    let recipient = test_payout_signer().payout();
    let (certificate, key, pin) = certificate(&root);
    let mut config = PoolServerConfig::devnet(
        "127.0.0.1:0".parse().unwrap(),
        fs::read(certificate).unwrap(),
        fs::read(key).unwrap(),
        pool_wallet,
    );
    config.ledger_directory = Some(root.path().join("ledger"));
    config.pplns_policy = Some(PoolPplnsPolicy {
        operator_fee_bps: 300,
        window_shares: 2,
    });
    config.payout_policy = Some(PoolPayoutPolicy {
        minimum_payout_atoms: 100,
        fee_atoms: 1,
    });
    let server = spawn_pool_server(Arc::clone(&node), config.clone()).unwrap();
    let mut miner = client(server.local_addr(), pin, "pplns-lifecycle");
    let work = miner.current_work().unwrap();
    let timestamp = work.job().challenge.timestamp;
    let share = miner
        .submit_share(work.job().job_id, find_share(&work, false))
        .unwrap();
    assert!(share.accepted && !share.block_accepted);
    let winner = miner
        .submit_share(work.job().job_id, find_share(&work, true))
        .unwrap();
    assert!(winner.accepted && winner.block_accepted);
    let found = server.ledger_snapshot().unwrap();
    assert_eq!(found.accepted_shares, 2);
    assert_eq!(found.blocks.len(), 1);
    assert_eq!(found.blocks[0].pplns_window_shares, Some(2));
    assert_eq!(found.credited_devnet_atoms, 0);
    assert!(found.payout_transactions.is_empty());
    let reward = found.blocks[0].miner_reward_atoms.unwrap();
    let frozen_fee = operator_fee_atoms(reward, 300);
    let expected_payment = reward - frozen_fee;
    drop(miner);
    server.stop().unwrap();

    // These blocks are not pool discoveries and must not create pool credit.
    for height in 2..COINBASE_MATURITY {
        node.lock()
            .unwrap()
            .mine_once(pool_wallet, timestamp + height, 10_000)
            .unwrap();
    }
    drop(node);

    // Reopen both node storage and the ledger immediately before maturity.
    // Changing the future fee/window must not rewrite the discovered block.
    let node = open_node();
    config.pplns_policy = Some(PoolPplnsPolicy {
        operator_fee_bps: 1_000,
        window_shares: 1,
    });
    let server = spawn_pool_server(Arc::clone(&node), config.clone()).unwrap();
    let immature = server.ledger_snapshot().unwrap();
    assert_eq!(immature.blocks[0].confirmations, COINBASE_MATURITY - 1);
    assert_eq!(immature.credited_devnet_atoms, 0);
    assert!(immature.payout_transactions.is_empty());

    node.lock()
        .unwrap()
        .mine_once(pool_wallet, timestamp + COINBASE_MATURITY, 10_000)
        .unwrap();
    reconcile_pool_blocks(&server.shared).unwrap();
    reconcile_pool_payouts(&server.shared, true).unwrap();
    let broadcast = server.ledger_snapshot().unwrap();
    assert_eq!(broadcast.blocks[0].confirmations, COINBASE_MATURITY);
    assert_eq!(broadcast.blocks[0].operator_fee_bps, Some(300));
    assert_eq!(broadcast.blocks[0].pplns_window_shares, Some(2));
    assert_eq!(broadcast.operator_fee_atoms, frozen_fee);
    assert_eq!(broadcast.credited_devnet_atoms, expected_payment);
    assert_eq!(broadcast.pplns_distributed_blocks, 1);
    assert_eq!(broadcast.payout_transactions.len(), 1);
    let payout = broadcast.payout_transactions[0].clone();
    assert_eq!(payout.payout, hex::encode(recipient));
    assert_eq!(payout.amount_atoms, expected_payment);
    assert_eq!(payout.fee_atoms, 1);
    assert_eq!(payout.state, "broadcast");
    assert_eq!(broadcast.payouts[0].available_payout_atoms, 0);
    let txid = decode_hex_32(&payout.txid).unwrap();
    assert!(node.lock().unwrap().mempool_contains_transaction(txid));
    server.stop().unwrap();
    drop(node);

    // A restart with an unconfirmed payout must reuse its exact journaled
    // transaction, not mint another payment for the same credited reward.
    let node = open_node();
    let server = spawn_pool_server(Arc::clone(&node), config.clone()).unwrap();
    for _ in 0..3 {
        reconcile_pool_blocks(&server.shared).unwrap();
        reconcile_pool_payouts(&server.shared, true).unwrap();
        let restored = server.ledger_snapshot().unwrap();
        assert_eq!(restored.payout_transactions, vec![payout.clone()]);
        assert_eq!(restored.credited_devnet_atoms, expected_payment);
        assert_eq!(restored.operator_fee_atoms, frozen_fee);
        assert_eq!(restored.payouts[0].available_payout_atoms, 0);
    }
    let confirmed_block = node
        .lock()
        .unwrap()
        .mine_once(pool_wallet, timestamp + COINBASE_MATURITY + 1, 10_000)
        .unwrap();
    let transaction = confirmed_block
        .transactions
        .iter()
        .find(|transaction| transaction.txid() == txid)
        .expect("the exact journaled payout was included in the canonical block");
    assert!(transaction.outputs.iter().any(|output| {
        output.value == expected_payment
            && output.lock == cmfd_consensus::OutputLock::Key(recipient)
    }));
    reconcile_pool_payouts(&server.shared, false).unwrap();
    let confirmed = server.ledger_snapshot().unwrap();
    assert_eq!(confirmed.payout_transactions.len(), 1);
    assert_eq!(confirmed.payout_transactions[0].txid, payout.txid);
    assert_eq!(confirmed.payout_transactions[0].state, "confirmed");
    assert_eq!(confirmed.payout_transactions[0].confirmations, 1);
    assert_eq!(
        confirmed.payouts[0].confirmed_payout_atoms,
        expected_payment
    );
    assert_eq!(confirmed.payouts[0].available_payout_atoms, 0);
    server.stop().unwrap();
    drop(node);

    let node = open_node();
    let server = spawn_pool_server(Arc::clone(&node), config).unwrap();
    reconcile_pool_payouts(&server.shared, true).unwrap();
    let recovered = server.ledger_snapshot().unwrap();
    assert_eq!(recovered.payout_transactions, confirmed.payout_transactions);
    assert_eq!(recovered.credited_devnet_atoms, expected_payment);
    assert_eq!(recovered.operator_fee_atoms, frozen_fee);
    assert_eq!(recovered.pplns_distributed_blocks, 1);
    assert_eq!(
        recovered.payouts[0].confirmed_payout_atoms,
        expected_payment
    );
    assert_eq!(recovered.payouts[0].available_payout_atoms, 0);
    server.stop().unwrap();
}
