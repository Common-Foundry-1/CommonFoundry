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

#[test]
fn payouts_wait_for_a_node_behind_the_ledger() {
    let root = TestRoot::new("payouts-behind-ledger");
    let node = Arc::new(Mutex::new(
        Node::open_with_profile(root.path().join("node"), crate::DEVNET_PROFILE).unwrap(),
    ));
    let pool_wallet = node.lock().unwrap().wallet_destination();
    let now = unix_time_seconds().unwrap();
    for offset in 0..=COINBASE_MATURITY {
        node.lock()
            .unwrap()
            .mine_once(pool_wallet, now + offset, 10_000)
            .unwrap();
    }
    let tip = node.lock().unwrap().state.next_height() - 1;
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
    let server = spawn_pool_server(Arc::clone(&node), config).unwrap();
    // A ledger that last reconciled against a longer chain than this node has.
    server
        .shared
        .ledger
        .transaction(|ledger| {
            ledger.observed_chain_height = tip + 50;
            Ok(())
        })
        .unwrap();
    let generation = server.shared.ledger.state.lock().unwrap().generation;
    reconcile_pool_payouts(&server.shared, true).unwrap();
    {
        let state = server.shared.ledger.state.lock().unwrap();
        assert_eq!(state.generation, generation, "no payout work while the node is behind");
        assert!(state.payout_protection.is_empty());
    }
    // At or past the ledger's height, payouts reconcile normally again.
    server
        .shared
        .ledger
        .transaction(|ledger| {
            ledger.observed_chain_height = tip;
            Ok(())
        })
        .unwrap();
    reconcile_pool_payouts(&server.shared, true).unwrap();
    assert!(server.shared.ledger.state.lock().unwrap().payout_protection.is_empty());
    server.stop().unwrap();
}

/// Mines `COINBASE_MATURITY + 1` blocks to the pool wallet at one-minute
/// spacing, then two more: at height 102 the pool wallet pays the sponsor
/// (its own coins, never funding), and at height 103 the sponsor pays
/// 6_000_000_000 atoms to the pool wallet with change back to itself. Returns
/// every mined block, the funding txid and its height.
fn fund_bonus_reserve(
    node: &Arc<Mutex<Node>>,
    pool_wallet: [u8; 32],
    sponsor_key: &SigningKey,
) -> (Vec<cmfd_consensus::Block>, [u8; 32], u64) {
    use cmfd_consensus::{InputWitness, OutPoint, TRANSACTION_VERSION, TxInput, TxOutput};

    let sponsor: [u8; 32] = sponsor_key.verifying_key().to_bytes().into();
    let mut blocks = Vec::new();
    let mut mine = |node: &mut Node| {
        let height = node.state.next_height();
        let block = node
            .mine_once(
                pool_wallet,
                crate::DEVNET_GENESIS_TIMESTAMP + height * 60,
                crate::DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        blocks.push(block);
    };
    let mut node = node.lock().unwrap();
    for _ in 1..=COINBASE_MATURITY + 1 {
        mine(&mut node);
    }
    let (to_sponsor, _) = node
        .prepare_dev_wallet_payment(sponsor, 10_000_000_000, 1)
        .unwrap();
    assert_eq!(to_sponsor.outputs[0].lock, OutputLock::Key(sponsor));
    node.submit_transaction(to_sponsor.clone()).unwrap();
    mine(&mut node);
    let mut funding = Transaction {
        network_id: node.params.network_id,
        version: TRANSACTION_VERSION,
        inputs: vec![TxInput {
            previous: OutPoint {
                txid: to_sponsor.txid(),
                index: 0,
            },
            witness: InputWitness::Key {
                public_key: [0; 32],
                signature: Vec::new(),
            },
        }],
        outputs: vec![
            TxOutput {
                value: 6_000_000_000,
                lock: OutputLock::Key(pool_wallet),
                spendable_height: node.state.next_height(),
            },
            TxOutput {
                value: 3_999_999_999,
                lock: OutputLock::Key(sponsor),
                spendable_height: node.state.next_height(),
            },
        ],
    };
    funding.sign_all(&[sponsor_key]).unwrap();
    node.submit_transaction(funding.clone()).unwrap();
    let funding_height = node.state.next_height();
    mine(&mut node);
    assert_eq!(funding_height, COINBASE_MATURITY + 3);
    (blocks, funding.txid(), funding_height)
}

#[test]
fn bonus_reserve_funds_once_and_pays_the_rate_on_mature_blocks() {
    let root = TestRoot::new("bonus-reserve-lifecycle");
    let node_directory = root.path().join("node");
    let open_node = || {
        Arc::new(Mutex::new(
            Node::open_with_profile(&node_directory, crate::DEVNET_PROFILE).unwrap(),
        ))
    };
    let node = open_node();
    let pool_wallet = node.lock().unwrap().wallet_destination();
    let sponsor_key = SigningKey::from_bytes(&[0x5b; 32]).unwrap();
    let sponsor: [u8; 32] = sponsor_key.verifying_key().to_bytes().into();
    let (_, funding_txid, funding_height) = fund_bonus_reserve(&node, pool_wallet, &sponsor_key);
    let signer_b = PoolPayoutSigner::new(SigningKey::from_bytes(&[0x21; 32]).unwrap());
    let recipients = [
        hex::encode(test_payout_signer().payout()),
        hex::encode(signer_b.payout()),
    ];
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
        window_shares: 3,
    });
    config.payout_policy = Some(PoolPayoutPolicy {
        minimum_payout_atoms: 100,
        fee_atoms: 1,
    });
    config.bonus_policy = Some(PoolBonusPolicy {
        rate_bps: 1_000,
        sponsor,
        scan_from_height: Some(1),
    });
    let server = spawn_pool_server(Arc::clone(&node), config.clone()).unwrap();
    // Startup scans 64 heights per pass from height 1 and has already
    // continued to the confirmed tip (103 - 5); nothing has six confirmations.
    let scanning = server.ledger_snapshot().unwrap();
    assert_eq!(
        scanning.bonus_scanned_height,
        Some(funding_height - POOL_BONUS_FUNDING_CONFIRMATIONS + 1)
    );
    assert_eq!(scanning.bonus_funded_atoms, 0);
    assert!(scanning.bonus_funding.is_empty());

    // Two payout keys share the window of the pool block at height 104.
    let mut miner_a = client(server.local_addr(), pin, "bonus-a");
    let mut miner_b = PoolClient::connect(
        PoolClientConfig::devnet(server.local_addr(), pin, "bonus-b", signer_b).unwrap(),
    )
    .unwrap();
    let work_a = miner_a.current_work().unwrap();
    let work_b = miner_b.current_work().unwrap();
    let job_id = work_a.job().job_id;
    assert_eq!(work_b.job().job_id, job_id);
    let timestamp = work_a.job().challenge.timestamp;
    let nonce_a = find_share_from(&work_a, miner_a.current_nonce_origin(), false);
    let nonce_b = find_share_from(&work_b, miner_b.current_nonce_origin(), false);
    assert!(miner_a.submit_share(job_id, nonce_a).unwrap().accepted);
    assert!(miner_b.submit_share(job_id, nonce_b).unwrap().accepted);
    let winner = miner_a
        .submit_share(job_id, find_share_from(&work_a, nonce_a + 1, true))
        .unwrap();
    assert!(winner.accepted && winner.block_accepted);
    drop(miner_a);
    drop(miner_b);
    let found = server.ledger_snapshot().unwrap();
    assert_eq!(found.blocks.len(), 1);
    let pool_height = found.blocks[0].height;
    assert_eq!(pool_height, funding_height + 1);
    let reward = found.blocks[0].miner_reward_atoms.unwrap();
    let distributable = reward - operator_fee_atoms(reward, 300);
    assert_eq!(found.blocks[0].bonus_rate_bps, Some(0));
    assert_eq!(found.blocks[0].bonus_atoms, Some(0));

    let mine = |offset: u64| {
        node.lock()
            .unwrap()
            .mine_once(pool_wallet, timestamp + offset, 10_000)
            .unwrap()
    };
    // The pool block gave the funding its second confirmation. Five are not
    // enough; the sixth registers the funding, once, and the pool's own
    // payment to the sponsor is never funding.
    for offset in 1..POOL_BONUS_FUNDING_CONFIRMATIONS - 2 {
        mine(offset);
    }
    let unconfirmed = server.ledger_snapshot().unwrap();
    assert_eq!(unconfirmed.bonus_scanned_height, Some(funding_height - 1));
    assert!(unconfirmed.bonus_funding.is_empty());
    assert_eq!(unconfirmed.bonus_funded_atoms, 0);
    mine(POOL_BONUS_FUNDING_CONFIRMATIONS - 2);
    let funding = vec![PoolBonusFundingStats {
        txid: hex::encode(funding_txid),
        height: funding_height,
        amount_atoms: 6_000_000_000,
    }];
    for _ in 0..3 {
        let funded = server.ledger_snapshot().unwrap();
        assert_eq!(funded.bonus_scanned_height, Some(funding_height));
        assert_eq!(funded.bonus_funding, funding);
        assert_eq!(
            (
                funded.bonus_funded_atoms,
                funded.bonus_credited_atoms,
                funded.bonus_reserve_atoms
            ),
            (6_000_000_000, 0, 6_000_000_000)
        );
        assert_eq!(funded.credited_devnet_atoms, 0);
    }

    // Mature the pool block: nothing moves at 99 confirmations.
    let mut offset = POOL_BONUS_FUNDING_CONFIRMATIONS - 1;
    while node.lock().unwrap().state.next_height() < pool_height + COINBASE_MATURITY - 1 {
        mine(offset);
        offset += 1;
    }
    let immature = server.ledger_snapshot().unwrap();
    assert_eq!(immature.blocks[0].confirmations, COINBASE_MATURITY - 1);
    assert!(!immature.blocks[0].pplns_distributed);
    assert_eq!(immature.bonus_reserve_atoms, 6_000_000_000);
    assert_eq!(immature.credited_devnet_atoms, 0);
    assert!(immature.payout_transactions.is_empty());

    mine(offset);
    offset += 1;
    reconcile_pool_blocks(&server.shared).unwrap();
    reconcile_pool_payouts(&server.shared, true).unwrap();
    let mature = server.ledger_snapshot().unwrap();
    assert_eq!(mature.blocks[0].confirmations, COINBASE_MATURITY);
    assert!(mature.blocks[0].pplns_distributed);
    assert_eq!(mature.blocks[0].bonus_rate_bps, Some(1_000));
    let bonus_total = mature.blocks[0].bonus_atoms.unwrap();
    assert!(bonus_total > 0);
    assert_eq!(mature.bonus_funded_atoms, 6_000_000_000);
    assert_eq!(mature.bonus_credited_atoms, bonus_total);
    assert_eq!(mature.bonus_reserve_atoms, 6_000_000_000 - bonus_total);
    assert_eq!(mature.credited_devnet_atoms, distributable + bonus_total);
    assert_eq!(mature.operator_fee_atoms, operator_fee_atoms(reward, 300));
    assert_eq!(mature.payouts.len(), 2);
    for payout in &mature.payouts {
        assert!(recipients.contains(&payout.payout));
        // Every key earns the rate on its own net allocation; the operator
        // fee came out of the base only.
        let base = payout.credited_devnet_atoms - payout.bonus_atoms;
        assert!(base > 0);
        assert_eq!(payout.bonus_atoms, base * 1_000 / 10_000);
        assert_eq!(payout.reserved_payout_atoms, payout.credited_devnet_atoms);
        assert_eq!(payout.available_payout_atoms, 0);
        assert!(!payout.payout_on_hold);
    }
    assert_eq!(
        mature
            .payouts
            .iter()
            .map(|payout| payout.bonus_atoms)
            .sum::<u64>(),
        bonus_total
    );
    assert_eq!(mature.payout_transactions.len(), 2);
    for transaction in &mature.payout_transactions {
        let payout = mature
            .payouts
            .iter()
            .find(|payout| payout.payout == transaction.payout)
            .unwrap();
        assert_eq!(transaction.amount_atoms, payout.credited_devnet_atoms);
        assert_eq!(transaction.state, "broadcast");
    }
    assert!(!mature.payout_protection.requires_reconciliation);
    assert!(mature.payout_protection.unresolved_incidents.is_empty());
    let dashboard = server.dashboard_source().snapshot().unwrap();
    assert_eq!(dashboard.bonus_rate_bps, Some(1_000));
    assert_eq!(dashboard.bonus_sponsor, Some(hex::encode(sponsor)));
    assert_eq!(
        (
            dashboard.bonus_funded_atoms,
            dashboard.bonus_credited_atoms,
            dashboard.bonus_reserve_atoms
        ),
        (6_000_000_000, bonus_total, 6_000_000_000 - bonus_total)
    );
    assert_eq!(
        dashboard.credited_atoms_last_24h,
        distributable + bonus_total
    );

    // The payments, bonus included, confirm on chain.
    let block = mine(offset);
    assert_eq!(block.transactions.len(), 2);
    reconcile_pool_payouts(&server.shared, false).unwrap();
    let paid = server.ledger_snapshot().unwrap();
    for payout in &paid.payouts {
        assert_eq!(payout.confirmed_payout_atoms, payout.credited_devnet_atoms);
    }
    assert!(paid.payout_protection.unresolved_incidents.is_empty());
    server.stop().unwrap();
    drop(node);

    // Everything survives a restart without a second registration.
    let node = open_node();
    let server = spawn_pool_server(Arc::clone(&node), config).unwrap();
    let restored = server.ledger_snapshot().unwrap();
    assert_eq!(restored.bonus_funding, funding);
    assert_eq!(
        (
            restored.bonus_funded_atoms,
            restored.bonus_credited_atoms,
            restored.bonus_reserve_atoms,
            restored.bonus_scanned_height
        ),
        (
            6_000_000_000,
            bonus_total,
            6_000_000_000 - bonus_total,
            paid.bonus_scanned_height
        )
    );
    assert_eq!(restored.payouts, paid.payouts);
    assert_eq!(restored.blocks, paid.blocks);
    server.stop().unwrap();
}

#[test]
fn bonus_scan_mark_restarts_below_a_reorganized_height_without_reversing_funding() {
    let root = TestRoot::new("bonus-scan-reorg");
    let node = Arc::new(Mutex::new(
        Node::open_with_profile(root.path().join("node"), crate::DEVNET_PROFILE).unwrap(),
    ));
    let pool_wallet = node.lock().unwrap().wallet_destination();
    let sponsor_key = SigningKey::from_bytes(&[0x5b; 32]).unwrap();
    let sponsor: [u8; 32] = sponsor_key.verifying_key().to_bytes().into();
    let (blocks, funding_txid, funding_height) =
        fund_bonus_reserve(&node, pool_wallet, &sponsor_key);
    let mine = |height: u64| {
        node.lock()
            .unwrap()
            .mine_once(
                pool_wallet,
                crate::DEVNET_GENESIS_TIMESTAMP + height * 60,
                crate::DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap()
    };
    // No payout policy: a dashboard pool funds its reserve on tip changes.
    let (certificate, key, _) = certificate(&root);
    let mut config = PoolServerConfig::devnet(
        "127.0.0.1:0".parse().unwrap(),
        fs::read(certificate).unwrap(),
        fs::read(key).unwrap(),
        pool_wallet,
    );
    config.ledger_directory = Some(root.path().join("ledger"));
    config.bonus_policy = Some(PoolBonusPolicy {
        rate_bps: 500,
        sponsor,
        scan_from_height: Some(funding_height),
    });
    let server = spawn_pool_server(Arc::clone(&node), config).unwrap();
    for height in funding_height + 1..funding_height + POOL_BONUS_FUNDING_CONFIRMATIONS {
        mine(height);
    }
    let funding = vec![PoolBonusFundingStats {
        txid: hex::encode(funding_txid),
        height: funding_height,
        amount_atoms: 6_000_000_000,
    }];
    let funded = server.ledger_snapshot().unwrap();
    assert_eq!(funded.bonus_scanned_height, Some(funding_height));
    assert_eq!(funded.bonus_funding, funding);
    assert_eq!(funded.bonus_reserve_atoms, 6_000_000_000);
    let marked = node
        .lock()
        .unwrap()
        .active_block_id_at_height(funding_height)
        .unwrap();

    // A heavier branch from height 102 carries neither transfer.
    let mut fork =
        Node::open_with_profile(root.path().join("fork"), crate::DEVNET_PROFILE).unwrap();
    let now = unix_time_seconds().unwrap();
    for block in &blocks[..(COINBASE_MATURITY + 1) as usize] {
        fork.submit_block(block.clone(), now).unwrap();
    }
    let alternate: [u8; 32] = SigningKey::from_bytes(&[0x41; 32])
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into();
    let branch = (funding_height - 1..=funding_height + POOL_BONUS_FUNDING_CONFIRMATIONS)
        .map(|height| {
            fork.mine_once(
                alternate,
                crate::DEVNET_GENESIS_TIMESTAMP + height * 60,
                crate::DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    {
        let mut node = node.lock().unwrap();
        for block in branch {
            node.submit_block(block, now).unwrap();
        }
        assert_eq!(
            node.state.next_height(),
            funding_height + POOL_BONUS_FUNDING_CONFIRMATIONS + 1
        );
        assert_ne!(node.active_block_id_at_height(funding_height), Some(marked));
    }

    // The mark's block is gone: the scan restarts COINBASE_MATURITY lower
    // and catches up one pass per tick. The registered funding stays.
    let restarted = server.ledger_snapshot().unwrap();
    assert_eq!(
        restarted.bonus_scanned_height,
        Some(funding_height - COINBASE_MATURITY + POOL_BONUS_SCAN_BLOCKS_PER_PASS - 1)
    );
    assert_eq!(restarted.bonus_funding, funding);
    assert_eq!(restarted.bonus_reserve_atoms, 6_000_000_000);
    let caught_up = server.ledger_snapshot().unwrap();
    assert_eq!(caught_up.bonus_scanned_height, Some(funding_height + 1));
    assert_eq!(caught_up.bonus_funding, funding);
    assert_eq!(caught_up.bonus_funded_atoms, 6_000_000_000);
    assert_eq!(caught_up.bonus_reserve_atoms, 6_000_000_000);
    server.stop().unwrap();
}

#[test]
fn bonus_funding_record_cap_skips_the_transfer_and_still_advances_the_scan() {
    let root = TestRoot::new("bonus-funding-cap");
    let node = Arc::new(Mutex::new(
        Node::open_with_profile(root.path().join("node"), crate::DEVNET_PROFILE).unwrap(),
    ));
    let pool_wallet = node.lock().unwrap().wallet_destination();
    let sponsor_key = SigningKey::from_bytes(&[0x5b; 32]).unwrap();
    let sponsor: [u8; 32] = sponsor_key.verifying_key().to_bytes().into();
    let (_, funding_txid, funding_height) = fund_bonus_reserve(&node, pool_wallet, &sponsor_key);
    let mut node = node.lock().unwrap();
    for height in funding_height + 1..funding_height + POOL_BONUS_FUNDING_CONFIRMATIONS {
        node.mine_once(
            pool_wallet,
            crate::DEVNET_GENESIS_TIMESTAMP + height * 60,
            crate::DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
    }
    let ledger = DurableLedger::open(
        Some(root.path().join("ledger")),
        node.params.network_id,
        node.fingerprint,
    )
    .unwrap();
    // The ledger already holds the maximum number of funding transactions.
    let cap = POOL_MAX_BONUS_FUNDING_RECORDS;
    ledger
        .transaction(|ledger| {
            for index in 0..cap as u64 {
                let mut txid = [0x74; 32];
                txid[..8].copy_from_slice(&index.to_le_bytes());
                ledger.bonus_funding.insert(
                    txid,
                    BonusFundingRecord {
                        height: 1,
                        amount_atoms: 1,
                    },
                );
            }
            ledger.bonus_funded_atoms = cap as u64;
            ledger.bonus_reserve_atoms = cap as u64;
            Ok(())
        })
        .unwrap();
    let policy = PoolBonusPolicy {
        rate_bps: 500,
        sponsor,
        scan_from_height: Some(funding_height),
    };
    // The confirmed transfer is skipped rather than failing the scan, and the
    // mark moves past it so the next tick does not fail at the same height.
    credit_bonus_funding(&ledger, &mut node, policy).unwrap();
    let state = ledger.state.lock().unwrap();
    assert_eq!(state.bonus_funding.len(), cap);
    assert!(!state.bonus_funding.contains_key(&funding_txid));
    assert_eq!(state.bonus_funded_atoms, cap as u64);
    assert_eq!(state.bonus_reserve_atoms, cap as u64);
    assert_eq!(
        state.bonus_scan.map(|mark| mark.height),
        Some(funding_height)
    );
}
