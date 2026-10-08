// Accounting/transport tests use the tiny reference proof, not a GPU/mainnet
// proof qualification. All nodes, keys and ledgers are isolated test fixtures.

#[test]
fn payout_guard_missing_or_torn_state_never_falls_back() {
    for failure in [
        "missing-snapshot",
        "missing-guard",
        "torn-guard",
        "foreign-guard",
        "older-guard",
    ] {
        let root = TestRoot::new(failure);
        let directory = root.path().join("ledger");
        let ledger = DurableLedger::open(Some(directory.clone()), [1; 32], [2; 32]).unwrap();
        register_session(&ledger, 1, "worker".into(), test_payout_signer().payout()).unwrap();
        let older_guard = fs::read(directory.join(POOL_LEDGER_GUARD_FILE)).unwrap();
        credit_accepted_share(&ledger, 1, 7).unwrap();
        let slot = ledger.state.lock().unwrap().generation & 1;
        drop(ledger);
        let guard = directory.join(POOL_LEDGER_GUARD_FILE);
        match failure {
            "missing-snapshot" => {
                fs::remove_file(directory.join(format!("{POOL_LEDGER_FILE_PREFIX}.{slot}.json")))
                    .unwrap()
            }
            "missing-guard" => fs::remove_file(guard).unwrap(),
            "torn-guard" => fs::write(guard, b"{\"generation\":").unwrap(),
            "older-guard" => fs::write(guard, older_guard).unwrap(),
            "foreign-guard" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&guard).unwrap()).unwrap();
                value["network_id"] = serde_json::json!([3; 32].to_vec());
                fs::write(guard, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                DurableLedger::open(Some(directory), [1; 32], [2; 32]),
                Err(PoolError::LedgerCorrupt(_))
            ),
            "{failure}"
        );
    }
}

#[test]
fn payout_guard_failed_write_poisoning_and_exclusive_lock_are_enforced() {
    let root = TestRoot::new("payout-guard-write-failure");
    let directory = root.path().join("ledger");
    let ledger = DurableLedger::open(Some(directory.clone()), [1; 32], [2; 32]).unwrap();
    assert!(matches!(
        DurableLedger::open(Some(directory.clone()), [1; 32], [2; 32]),
        Err(PoolError::LedgerInUse)
    ));
    register_session(&ledger, 1, "worker".into(), test_payout_signer().payout()).unwrap();
    let next_slot = (ledger.state.lock().unwrap().generation + 1) & 1;
    let target = directory.join(format!("{POOL_LEDGER_FILE_PREFIX}.{next_slot}.json"));
    fs::remove_file(&target).unwrap();
    fs::create_dir(&target).unwrap(); // Force snapshot replacement failure after the guard write.
    assert!(credit_accepted_share(&ledger, 1, 7).is_err());
    assert!(matches!(
        credit_accepted_share(&ledger, 1, 7),
        Err(PoolError::LedgerFaulted)
    ));
    assert!(matches!(
        snapshot_ledger(&ledger),
        Err(PoolError::LedgerFaulted)
    ));
    drop(ledger);
    assert!(matches!(
        DurableLedger::open(Some(directory), [1; 32], [2; 32]),
        Err(PoolError::LedgerCorrupt(_))
    ));
}

#[test]
fn pool_payout_operator_preflight_never_creates_a_missing_directory() {
    let root = TestRoot::new("payout-preflight");
    let missing = root.path().join("typo-node");
    assert!(require_existing_pool_ledger(&missing).is_err());
    assert!(!missing.exists());
}

#[test]
fn automatic_payouts_require_persistent_accounting() {
    let (root, server, node, _) = server("payout-durability-required");
    server.stop().unwrap();
    let destination = node.lock().unwrap().wallet_destination();
    let mut config = PoolServerConfig::devnet(
        "127.0.0.1:0".parse().unwrap(),
        fs::read(root.path().join("pool.crt.der")).unwrap(),
        fs::read(root.path().join("pool.key.der")).unwrap(),
        destination,
    );
    config.payout_policy = Some(PoolPayoutPolicy {
        minimum_payout_atoms: 100,
        fee_atoms: 1,
    });
    assert!(matches!(
        spawn_pool_server(node, config),
        Err(PoolError::PayoutLedgerRequired)
    ));
}

fn protection_ledger(node: &Node) -> DurableLedger {
    DurableLedger::open(
        Some(node.data_dir.join("pool-ledger")),
        node.params.network_id,
        node.fingerprint,
    )
    .unwrap()
}

fn protection_request(report: &PoolPayoutProtectionReport) -> PoolPayoutReconciliationRequest {
    PoolPayoutReconciliationRequest {
        expected_tip: decode_hex_32(&report.chain_tip).unwrap(),
        expected_ledger_generation: report.ledger_generation,
        fee_atoms: 1,
        operator_note: "Reconciled fixture funding without altering miner credits".into(),
    }
}

#[test]
fn payout_reorg_hold_restart_restore_manual_resume_and_second_paid_reorg() {
    let root = TestRoot::new("payout-deep-reorg-lifecycle");
    let data = root.path().join("node");
    let mut node = Node::open_with_profile(&data, crate::DEVNET_PROFILE).unwrap();
    let owner = node.wallet_destination();
    let recipient = test_payout_signer().payout();
    let now = unix_time_seconds().unwrap();
    let mut original = Vec::new();
    for offset in 0..COINBASE_MATURITY {
        original.push(node.mine_once(owner, now + offset, 10_000).unwrap());
    }
    let block = &original[0];
    let reward = block
        .coinbase
        .outputs
        .iter()
        .filter(|o| o.lock == OutputLock::Key(owner))
        .map(|o| o.value)
        .sum();
    let ledger = protection_ledger(&node);
    register_session(&ledger, 1, "affected".into(), recipient).unwrap();
    reserve_pending_pool_block(
        &ledger,
        1,
        PoolBlockCredit {
            block_id: block.block_id(),
            parent: block.challenge.previous_block,
            height: block.challenge.height,
            miner_reward_atoms: reward,
            share_target: [0xff; 32],
            block_target: block.challenge.target,
        },
        0,
        Some(PoolPplnsPolicy {
            operator_fee_bps: 300,
            window_shares: 1,
        }),
    )
    .unwrap();
    finalize_pending_pool_block(
        &ledger,
        block.block_id(),
        PoolBlockState::Canonical,
        COINBASE_MATURITY,
    )
    .unwrap();
    let earned = snapshot_ledger(&ledger).unwrap().credited_devnet_atoms;
    assert!(earned > 100);
    drop(ledger);

    let mut fork =
        Node::open_with_profile(root.path().join("fork"), crate::DEVNET_PROFILE).unwrap();
    let alternate_owner =
        PoolPayoutSigner::new(SigningKey::from_bytes(&[0x71; 32]).unwrap()).payout();
    for offset in 0..COINBASE_MATURITY + 2 {
        let block = fork
            .mine_once(alternate_owner, now + offset, 10_000)
            .unwrap();
        node.submit_block(block, now + offset).unwrap();
    }
    let held = inspect_pool_payout_protection(&mut node, 1).unwrap();
    assert!(held.protection.all_payouts_paused);
    assert_eq!(held.protection.unresolved_incidents.len(), 2);
    assert_eq!(held.outstanding_credit_atoms, earned.to_string());
    assert_eq!(held.funding_shortfall_atoms, (earned + 1).to_string());
    assert!(reconcile_pool_payout_protection(&mut node, protection_request(&held)).is_err());
    drop(node);
    let mut node = Node::open_with_profile(&data, crate::DEVNET_PROFILE).unwrap();
    let restarted = inspect_pool_payout_protection(&mut node, 1).unwrap();
    assert_eq!(restarted.ledger_generation, held.ledger_generation);
    assert_eq!(restarted.protection, held.protection);

    // Restore the original branch. Recovery of its backing is not operator
    // approval: neither the holds nor the original earned credit may disappear.
    let mut restoration =
        Node::open_with_profile(root.path().join("restoration"), crate::DEVNET_PROFILE).unwrap();
    for block in original {
        restoration.submit_block(block, now + 200).unwrap();
    }
    for offset in COINBASE_MATURITY..COINBASE_MATURITY + 4 {
        let block = restoration.mine_once(owner, now + offset, 10_000).unwrap();
        node.submit_block(block, now + offset).unwrap();
    }
    let restored = inspect_pool_payout_protection(&mut node, 1).unwrap();
    assert!(restored.protection.requires_reconciliation);
    assert_eq!(restored.funding_shortfall_atoms, "0");
    let mut stale = protection_request(&restored);
    stale.expected_ledger_generation -= 1;
    assert!(reconcile_pool_payout_protection(&mut node, stale).is_err());
    let mut stale = protection_request(&restored);
    stale.expected_tip = [0; 32];
    assert!(reconcile_pool_payout_protection(&mut node, stale).is_err());
    let mut bad_note = protection_request(&restored);
    bad_note.operator_note = "bad\nnote".into();
    assert!(reconcile_pool_payout_protection(&mut node, bad_note).is_err());
    let resumed =
        reconcile_pool_payout_protection(&mut node, protection_request(&restored)).unwrap();
    assert!(!resumed.protection.requires_reconciliation);
    assert_eq!(resumed.protection.resolved_incidents, 2);
    assert_eq!(resumed.outstanding_credit_atoms, earned.to_string());
    assert!(
        node.mempool.is_empty(),
        "operator command must not send a payment"
    );

    let node = Arc::new(Mutex::new(node));
    let (cert, key, _) = certificate(&root);
    let mut config = PoolServerConfig::devnet(
        "127.0.0.1:0".parse().unwrap(),
        fs::read(cert).unwrap(),
        fs::read(key).unwrap(),
        owner,
    );
    config.ledger_directory = Some(data.join("pool-ledger"));
    config.payout_policy = Some(PoolPayoutPolicy {
        minimum_payout_atoms: 100,
        fee_atoms: 1,
    });
    let server = spawn_pool_server(Arc::clone(&node), config.clone()).unwrap();
    let paid = server.ledger_snapshot().unwrap();
    assert_eq!(paid.payout_transactions.len(), 1);
    assert_eq!(paid.payout_transactions[0].amount_atoms, earned);
    node.lock()
        .unwrap()
        .mine_once(owner, now + COINBASE_MATURITY + 4, 10_000)
        .unwrap();
    assert_eq!(
        server.ledger_snapshot().unwrap().payout_transactions[0].state,
        "confirmed"
    );
    server.stop().unwrap();
    let server = spawn_pool_server(Arc::clone(&node), config).unwrap();
    assert_eq!(
        server.ledger_snapshot().unwrap().payout_transactions.len(),
        1
    );

    // Reorg again after an actual payment. Keep its exact signature/reservation,
    // create a fresh incident, and refuse funded resume while inputs are invalid.
    for offset in COINBASE_MATURITY + 2..COINBASE_MATURITY + 7 {
        let block = fork
            .mine_once(alternate_owner, now + offset, 10_000)
            .unwrap();
        node.lock()
            .unwrap()
            .submit_block(block, now + offset)
            .unwrap();
    }
    for _ in 0..3 {
        reconcile_pool_payouts(&server.shared, true).unwrap();
    }
    let second_loss = server.ledger_snapshot().unwrap();
    assert_eq!(second_loss.payout_transactions.len(), 1);
    assert_eq!(
        second_loss.payout_transactions[0].txid,
        paid.payout_transactions[0].txid
    );
    assert_eq!(second_loss.payout_transactions[0].state, "prepared");
    assert_eq!(second_loss.payouts[0].reserved_payout_atoms, earned);
    assert_eq!(second_loss.payouts[0].credited_devnet_atoms, earned);
    assert!(second_loss.payouts[0].payout_on_hold);
    assert_eq!(second_loss.payout_protection.resolved_incidents, 2);
    assert_eq!(
        second_loss
            .payout_protection
            .unresolved_incidents
            .iter()
            .filter(|i| i.reason == "reward_backing_lost")
            .count(),
        1
    );
    server.stop().unwrap();
    let mut node = node.lock().unwrap();
    let blocked = inspect_pool_payout_protection(&mut node, 1).unwrap();
    assert_eq!(blocked.blocking_signed_transactions.len(), 1);
    assert!(reconcile_pool_payout_protection(&mut node, protection_request(&blocked)).is_err());
}

#[test]
fn payout_hold_is_scoped_and_wallet_planner_keeps_signed_inputs_reserved() {
    let root = TestRoot::new("payout-input-reservations");
    let mut node =
        Node::open_with_profile(root.path().join("node"), crate::DEVNET_PROFILE).unwrap();
    let owner = node.wallet_destination();
    let now = unix_time_seconds().unwrap();
    for offset in 0..COINBASE_MATURITY + 2 {
        node.mine_once(owner, now + offset, 10_000).unwrap();
    }
    let recipient = test_payout_signer().payout();
    let other = PoolPayoutSigner::new(SigningKey::from_bytes(&[0x75; 32]).unwrap()).payout();
    let ledger = protection_ledger(&node);
    register_session(&ledger, 1, "affected".into(), recipient).unwrap();
    register_session(&ledger, 2, "unaffected".into(), other).unwrap();
    credit_accepted_share(&ledger, 1, 120).unwrap();
    credit_accepted_share(&ledger, 2, 130).unwrap();
    let (signed, _) = node.prepare_dev_wallet_payment(recipient, 120, 1).unwrap();
    let txid = signed.txid();
    ledger
        .transaction(|state| {
            state.payout_transactions.insert(
                txid,
                PayoutTransactionRecord {
                    payout: recipient,
                    amount_atoms: 120,
                    fee_atoms: 1,
                    transaction: signed.clone(),
                    state: PoolPayoutTransactionState::Prepared,
                    confirmations: 0,
                },
            );
            Ok(())
        })
        .unwrap();
    payout_protection::missing_funding(&ledger, &node, txid).unwrap();
    let policy = PoolPayoutPolicy {
        minimum_payout_atoms: 100,
        fee_atoms: 1,
    };
    assert_eq!(
        next_payout_candidate(&ledger, policy).unwrap(),
        Some((other, 130))
    );
    let reserved = signed.inputs.iter().map(|i| i.previous).collect();
    let (unrelated, _) = node
        .prepare_pool_wallet_payment(other, 130, 1, &reserved)
        .unwrap();
    assert!(unrelated.inputs.iter().all(|input| {
        !signed
            .inputs
            .iter()
            .any(|pending| pending.previous == input.previous)
    }));
    drop(ledger);
    let report = inspect_pool_payout_protection(&mut node, 1).unwrap();
    assert_eq!(report.outstanding_credit_atoms, "250");
    assert_eq!(report.fee_reserve_atoms, "2");
    assert_eq!(
        report.protection.affected_payouts,
        vec![hex::encode(recipient)]
    );
    assert!(!report.protection.all_payouts_paused);
    assert!(report.blocking_signed_transactions.is_empty());
    // The dry run lists only the unheld, unreserved credit the next automatic
    // run would pay, at the configured minimum.
    assert_eq!(report.planned_payout_minimum_atoms.as_deref(), Some("100"));
    assert_eq!(report.planned_payouts.len(), 1);
    assert_eq!(report.planned_payouts[0].payout, hex::encode(other));
    assert_eq!(report.planned_payouts[0].amount_atoms, "130");
    assert_eq!(report.planned_payout_atoms, "130");
    assert_eq!(report.planned_payout_fees_atoms, "1");
    // Funds committed to another custody flow do not back pool liabilities.
    let unavailable = node
        .state
        .utxos()
        .iter()
        .filter(|(_, output)| {
            output.lock == OutputLock::Key(owner)
                && output.spendable_height <= node.state.next_height()
        })
        .map(|(outpoint, _)| (*outpoint, [0x55; 32]))
        .collect();
    node.set_exchange_withdrawal_reservations(unavailable);
    let underfunded = inspect_pool_payout_protection(&mut node, 1).unwrap();
    assert_eq!(underfunded.mature_wallet_assets_atoms, "0");
    assert_eq!(underfunded.funding_shortfall_atoms, "252");
    assert!(underfunded.protection.all_payouts_paused);
    assert!(reconcile_pool_payout_protection(&mut node, protection_request(&underfunded)).is_err());
    node.set_exchange_withdrawal_reservations(HashMap::new());

    // A manual transaction conflict is not permission to erase a signed pool
    // transaction. Its inputs also must not be counted as available coverage.
    let (manual, _) = node.prepare_dev_wallet_payment(other, 131, 1).unwrap();
    assert_eq!(manual.inputs[0].previous, signed.inputs[0].previous);
    node.submit_transaction(manual.clone()).unwrap();
    let conflict = inspect_pool_payout_protection(&mut node, 1).unwrap();
    assert_eq!(
        conflict.blocking_signed_transactions,
        vec![hex::encode(txid)]
    );
    assert!(
        conflict.mature_wallet_assets_atoms.parse::<u64>().unwrap()
            < report.mature_wallet_assets_atoms.parse::<u64>().unwrap()
    );
    assert!(reconcile_pool_payout_protection(&mut node, protection_request(&conflict)).is_err());
    // Simulate unconfirmed transaction eviction on this disposable node only.
    node.mempool.clear();
    node.mempool_bytes = 0;
    let report = inspect_pool_payout_protection(&mut node, 1).unwrap();
    // Valid old signatures can be resumed; the command itself does not send them.
    let resumed = reconcile_pool_payout_protection(&mut node, protection_request(&report)).unwrap();
    assert!(!resumed.protection.requires_reconciliation);
    assert!(node.mempool.is_empty());
    // Reconciliation reports no dry run: it has no payout minimum.
    assert!(resumed.planned_payout_minimum_atoms.is_none());
    assert!(resumed.planned_payouts.is_empty());
}

#[test]
fn distributed_reward_losing_maturity_holds_without_revoking_credit() {
    let root = TestRoot::new("payout-maturity-regression");
    let node = Node::open_with_profile(root.path().join("node"), crate::DEVNET_PROFILE).unwrap();
    let ledger = protection_ledger(&node);
    let payout = test_payout_signer().payout();
    register_session(&ledger, 1, "worker".into(), payout).unwrap();
    let block_id = [0x45; 32];
    reserve_pending_pool_block(
        &ledger,
        1,
        PoolBlockCredit {
            block_id,
            parent: [0x46; 32],
            height: 1,
            miner_reward_atoms: 100,
            share_target: [0xff; 32],
            block_target: [0x3f; 32],
        },
        0,
        Some(PoolPplnsPolicy {
            operator_fee_bps: 300,
            window_shares: 1,
        }),
    )
    .unwrap();
    finalize_pending_pool_block(
        &ledger,
        block_id,
        PoolBlockState::Canonical,
        COINBASE_MATURITY,
    )
    .unwrap();
    ledger
        .transaction(|state| {
            state.blocks.get_mut(&block_id).unwrap().confirmations = COINBASE_MATURITY - 1;
            payout_protection::observe_backing(state, &node, block_id)
        })
        .unwrap();
    let held = snapshot_ledger(&ledger).unwrap();
    assert_eq!(held.credited_devnet_atoms, 97);
    assert_eq!(held.payouts[0].held_payout_atoms, 97);
    assert!(held.payouts[0].payout_on_hold);
    assert!(!held.payout_protection.all_payouts_paused);
    ledger
        .transaction(|state| {
            state.blocks.get_mut(&block_id).unwrap().confirmations = COINBASE_MATURITY;
            payout_protection::observe_backing(state, &node, block_id)
        })
        .unwrap();
    assert!(snapshot_ledger(&ledger).unwrap().payouts[0].payout_on_hold);
    drop(ledger);
    let restarted = protection_ledger(&node);
    let held = snapshot_ledger(&restarted).unwrap();
    assert_eq!(held.credited_devnet_atoms, 97);
    assert_eq!(held.payout_protection.unresolved_incidents.len(), 1);
}

#[test]
fn legacy_abandoned_signatures_are_held_and_never_automatically_replaced() {
    let root = TestRoot::new("payout-legacy-abandoned");
    let mut node =
        Node::open_with_profile(root.path().join("node"), crate::DEVNET_PROFILE).unwrap();
    let owner = node.wallet_destination();
    let now = unix_time_seconds().unwrap();
    for offset in 0..COINBASE_MATURITY {
        node.mine_once(owner, now + offset, 10_000).unwrap();
    }
    let recipient = test_payout_signer().payout();
    let ledger = protection_ledger(&node);
    register_session(&ledger, 1, "legacy".into(), recipient).unwrap();
    credit_accepted_share(&ledger, 1, 120).unwrap();
    let (transaction, _) = node.prepare_dev_wallet_payment(recipient, 120, 1).unwrap();
    ledger
        .transaction(|state| {
            state.payout_transactions.insert(
                transaction.txid(),
                PayoutTransactionRecord {
                    payout: recipient,
                    amount_atoms: 120,
                    fee_atoms: 1,
                    transaction,
                    state: PoolPayoutTransactionState::Abandoned,
                    confirmations: 0,
                },
            );
            Ok(())
        })
        .unwrap();
    drop(ledger);
    let report = inspect_pool_payout_protection(&mut node, 1).unwrap();
    assert!(report.legacy_abandoned_transactions_require_review);
    assert!(report.protection.requires_reconciliation);
    assert!(reconcile_pool_payout_protection(&mut node, protection_request(&report)).is_err());
    let ledger = protection_ledger(&node);
    assert!(
        next_payout_candidate(
            &ledger,
            PoolPayoutPolicy {
                minimum_payout_atoms: 100,
                fee_atoms: 1
            }
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        snapshot_ledger(&ledger).unwrap().payouts[0].held_payout_atoms,
        120
    );
}

#[test]
fn payout_hold_lifts_itself_once_the_payout_is_confirmed_deep_enough() {
    let root = TestRoot::new("payout-hold-auto-clear");
    let mut node =
        Node::open_with_profile(root.path().join("node"), crate::DEVNET_PROFILE).unwrap();
    let owner = node.wallet_destination();
    let now = unix_time_seconds().unwrap();
    for offset in 0..COINBASE_MATURITY + 2 {
        node.mine_once(owner, now + offset, 10_000).unwrap();
    }
    let recipient = test_payout_signer().payout();
    let ledger = protection_ledger(&node);
    register_session(&ledger, 1, "affected".into(), recipient).unwrap();
    credit_accepted_share(&ledger, 1, 120).unwrap();
    let (signed, _) = node.prepare_dev_wallet_payment(recipient, 120, 1).unwrap();
    let txid = signed.txid();
    let set_payment = |state: PoolPayoutTransactionState, confirmations: u64| {
        ledger
            .transaction(|ledger| {
                ledger.payout_transactions.insert(
                    txid,
                    PayoutTransactionRecord {
                        payout: recipient,
                        amount_atoms: 120,
                        fee_atoms: 1,
                        transaction: signed.clone(),
                        state,
                        confirmations,
                    },
                );
                Ok(())
            })
            .unwrap();
    };
    set_payment(PoolPayoutTransactionState::Prepared, 0);
    payout_protection::missing_funding(&ledger, &node, txid).unwrap();
    let held = |ledger: &DurableLedger| {
        let state = ledger.state.lock().unwrap();
        payout_protection::snapshot(&state)
            .affected_payouts
            .contains(&hex::encode(recipient))
    };
    assert!(held(&ledger));

    // Confirmed, but not yet COINBASE_MATURITY deep: the hold stays.
    set_payment(PoolPayoutTransactionState::Confirmed, COINBASE_MATURITY - 1);
    payout_protection::auto_resolve(&ledger, &node, 1).unwrap();
    assert!(held(&ledger));

    // Deep enough: the hold lifts with an automatic receipt that passes the
    // same validation as an operator's reconcile.
    set_payment(PoolPayoutTransactionState::Confirmed, COINBASE_MATURITY);
    payout_protection::auto_resolve(&ledger, &node, 1).unwrap();
    assert!(!held(&ledger));
    let snapshot = {
        let state = ledger.state.lock().unwrap();
        validate_ledger(&state).unwrap();
        payout_protection::snapshot(&state)
    };
    assert!(!snapshot.requires_reconciliation);
    assert_eq!(snapshot.resolved_incidents, 1);
    // Nothing left to do on the next pass.
    let generation = ledger.state.lock().unwrap().generation;
    payout_protection::auto_resolve(&ledger, &node, 1).unwrap();
    assert_eq!(ledger.state.lock().unwrap().generation, generation);
}
