use cmfd_consensus::{InputWitness, TRANSACTION_VERSION, TxInput};
use std::io::{Read, Write};

use crate::explorer_address::{EXPLORER_ADDRESS_PAGE_SIZE, ExplorerAddress};
use crate::explorer_address_index::{AddressHistoryIndex, AddressLocation, AddressOutputIndex};
use crate::tests::{
    clean_test_dir, mined_child, mined_child_with_transactions, spend_coinbase_output, test_dir,
};
use crate::*;

fn query(node: &mut Node, address: [u8; 32]) -> ExplorerAddress {
    node.explorer_address(&hex::encode(address), None).unwrap()
}

fn assert_balance(node: &mut Node, address: [u8; 32]) {
    let view = query(node, address);
    let outputs: Vec<_> = node
        .state
        .utxos()
        .iter()
        .filter(|(_, output)| output.lock == OutputLock::Key(address))
        .collect();
    let total: u128 = outputs
        .iter()
        .map(|(_, output)| u128::from(output.value))
        .sum();
    let spendable: u128 = outputs
        .iter()
        .filter(|(_, output)| output.spendable_height <= node.state.next_height())
        .map(|(_, output)| u128::from(output.value))
        .sum();
    assert_eq!(view.confirmed_atoms, total.to_string());
    assert_eq!(view.spendable_atoms, spendable.to_string());
    assert_eq!(view.immature_atoms, (total - spendable).to_string());
    assert_eq!(view.utxo_count, outputs.len());
    assert_eq!(
        node.explorer_outputs,
        AddressOutputIndex::from_utxos(node.state.utxos())
    );
}

fn mine(node: &mut Node, destination: [u8; 32]) -> Block {
    let timestamp = DEVNET_GENESIS_TIMESTAMP + node.state.next_height() * 60;
    node.mine_once(destination, timestamp, DEFAULT_MINING_ATTEMPTS)
        .unwrap()
}

#[test]
fn address_rpc_is_read_only_exact_and_network_bound() {
    let path = test_dir("explorer-address-rpc");
    let mut node = Node::open(&path).unwrap();
    let address = insecure_dev_destination(0x31);
    let prefix = format!("/v1/explorer/address/{}", hex::encode(address));
    for (suffix, status) in [
        ("", 200),
        ("/bad", 400),
        ("/", 400),
        ("/bad/extra", 400),
        ("?limit=1000000", 400),
    ] {
        let response = route_rpc_request(
            RpcRequest {
                method: "GET".into(),
                target: format!("{prefix}{suffix}"),
                content_type: None,
                body: Vec::new(),
            },
            &mut node,
        );
        assert_eq!(response.status, status, "{suffix}");
        assert_eq!(response.network_id, Some(node.params.network_id));
        if status == 200 {
            let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(value["confirmed_atoms"], "0");
            assert_eq!(value["history"], json!([]));
            assert_eq!(value["balance_scope"], "key_outputs");
            assert_eq!(value["includes_mempool"], false);
        }
    }
    for method in ["POST", "DELETE"] {
        let response = route_rpc_request(
            RpcRequest {
                method: method.into(),
                target: prefix.clone(),
                content_type: None,
                body: Vec::new(),
            },
            &mut node,
        );
        assert!(matches!(response.status, 404 | 405));
    }
    assert!(matches!(
        node.explorer_address("bad", None),
        Err(NodeError::InvalidExplorerAddress)
    ));
    assert_eq!(node.explorer_block_reads, 0);
    assert_eq!(node.state.next_height(), 1);
    assert_eq!(node.block_log_length, 0);
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn address_rpc_reads_checksummed_addresses_and_answers_in_hex() {
    use crate::address::{MAINNET_HRP, TEST_NETWORK_HRP, encode};

    let path = test_dir("explorer-address-checksummed");
    let mut node = Node::open(&path).unwrap();
    let address = insecure_dev_destination(0x32);
    let by_hex = query(&mut node, address);
    assert_eq!(by_hex.address, hex::encode(address));
    let checksummed = encode(address_hrp(), &address);
    for text in [checksummed.clone(), checksummed.to_ascii_uppercase()] {
        assert_eq!(node.explorer_address(&text, None).unwrap(), by_hex);
    }
    let other_network = if address_hrp() == MAINNET_HRP {
        TEST_NETWORK_HRP
    } else {
        MAINNET_HRP
    };
    let mut typo = checksummed.into_bytes();
    let last = typo.len() - 1;
    typo[last] = if typo[last] == b'q' { b'p' } else { b'q' };
    for text in [
        encode(other_network, &address),
        String::from_utf8(typo).unwrap(),
    ] {
        assert!(matches!(
            node.explorer_address(&text, None),
            Err(NodeError::InvalidExplorerAddress)
        ));
    }
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn address_balances_cover_rewards_maturity_spending_change_and_mempool_exclusion() {
    let path = test_dir("explorer-address-balances");
    let mut node = Node::open(&path).unwrap();
    let owner = default_miner_destination();
    let other = insecure_dev_destination(0x66);
    let recipient = insecure_dev_destination(0x31);
    let funding = mine(&mut node, owner);
    let reward = funding.coinbase.outputs[0].value;
    let view = query(&mut node, owner);
    assert_eq!(view.confirmed_atoms, reward.to_string());
    assert_eq!(view.spendable_atoms, "0");
    assert_eq!(view.immature_atoms, reward.to_string());
    assert_eq!(view.history[0].kind, "coinbase");
    for _ in 2..=100 {
        mine(&mut node, other);
    }
    assert_eq!(query(&mut node, owner).spendable_atoms, reward.to_string());
    let mut payment = spend_coinbase_output(&node, &funding, 0, 0x13, 0x31, 1);
    payment.outputs[0].value -= 10;
    payment.outputs.push(TxOutput {
        value: 10,
        lock: OutputLock::Key(owner),
        spendable_height: node.state.next_height(),
    });
    payment
        .sign_all(&[&SigningKey::from_bytes(&[0x13; 32]).unwrap()])
        .unwrap();
    node.submit_transaction(payment.clone()).unwrap();
    assert_eq!(query(&mut node, owner).confirmed_atoms, reward.to_string());
    assert_eq!(query(&mut node, recipient).confirmed_atoms, "0");
    mine(&mut node, other);
    let sent = query(&mut node, owner);
    assert_eq!(sent.confirmed_atoms, "10");
    assert_eq!(
        sent.history[0].kind, "sent",
        "change must not be labelled a self-only transfer"
    );
    assert_eq!(sent.history[0].received_atoms, "10");
    assert_eq!(sent.history[0].spent_inputs, 1);
    let received = query(&mut node, recipient);
    assert_eq!(received.confirmed_atoms, (reward - 11).to_string());
    assert_eq!(received.history[0].kind, "received");
    for address in [
        owner,
        other,
        recipient,
        insecure_dev_destination(0x11),
        insecure_dev_destination(0x12),
    ] {
        assert_balance(&mut node, address);
    }
    drop(node);
    let mut reopened = Node::open(&path).unwrap();
    assert!(reopened.startup_snapshot_used);
    assert_eq!(query(&mut reopened, owner), sent);
    assert_eq!(query(&mut reopened, recipient), received);
    drop(reopened);
    clean_test_dir(&path);
}

#[test]
fn address_history_pages_are_bounded_disjoint_and_tip_bound() {
    let path = test_dir("explorer-address-pages");
    let mut node = Node::open(&path).unwrap();
    let address = default_miner_destination();
    for _ in 0..EXPLORER_ADDRESS_PAGE_SIZE * 2 + 3 {
        mine(&mut node, address);
    }
    let first = query(&mut node, address);
    assert_eq!(first.history.len(), EXPLORER_ADDRESS_PAGE_SIZE);
    assert_eq!(node.explorer_block_reads, 0);
    assert!(first.has_more);
    let second = node
        .explorer_address(&hex::encode(address), first.next_cursor.as_deref())
        .unwrap();
    let third = node
        .explorer_address(&hex::encode(address), second.next_cursor.as_deref())
        .unwrap();
    assert_eq!(second.history.len(), EXPLORER_ADDRESS_PAGE_SIZE);
    assert_eq!(third.history.len(), 3);
    assert!(!third.has_more);
    assert!(third.next_cursor.is_none());
    let heights: Vec<_> = first
        .history
        .iter()
        .chain(&second.history)
        .chain(&third.history)
        .map(|item| item.block_height)
        .collect();
    assert_eq!(heights, (1..=43).rev().collect::<Vec<_>>());
    let tip = hex::encode(node.state.tip());
    for cursor in [
        format!("{tip}.0.0"),
        format!("{tip}.01.0"),
        format!("{tip}.1.01"),
        format!("{tip}.1.1025"),
        format!("{tip}.999.0"),
        format!("{tip}.1.1"),
        format!("{tip}.1.0.extra"),
        "a".repeat(109),
    ] {
        assert!(
            matches!(
                node.explorer_address(&hex::encode(address), Some(&cursor)),
                Err(NodeError::InvalidExplorerCursor)
            ),
            "{cursor}"
        );
    }
    assert!(matches!(
        node.explorer_address(
            &hex::encode(insecure_dev_destination(0x34)),
            first.next_cursor.as_deref()
        ),
        Err(NodeError::InvalidExplorerCursor)
    ));
    mine(&mut node, address);
    let error = node
        .explorer_address(&hex::encode(address), first.next_cursor.as_deref())
        .unwrap_err();
    assert!(matches!(error, NodeError::StaleExplorerCursor));
    assert_eq!(error.client_error().status, 409);
    assert!(error.client_error().retryable);
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn address_history_and_balances_follow_forks_orphans_reconfirmation_and_replay() {
    let path = test_dir("explorer-address-reorg");
    let mut node = Node::open(&path).unwrap();
    let funding = mine(&mut node, default_miner_destination());
    let recipient = insecure_dev_destination(0x31);
    let payment = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
    let a2 = mined_child_with_transactions(
        &node,
        funding.block_id(),
        DEVNET_GENESIS_TIMESTAMP + 120,
        0x41,
        vec![payment.clone()],
    );
    node.submit_block(a2.clone(), a2.challenge.timestamp)
        .unwrap();
    assert_eq!(
        query(&mut node, recipient).history[0].block_id,
        hex::encode(a2.block_id())
    );
    let b2 = mined_child(
        &node,
        funding.block_id(),
        DEVNET_GENESIS_TIMESTAMP + 120,
        0x42,
    );
    node.submit_block(b2.clone(), b2.challenge.timestamp)
        .unwrap();
    assert_balance(&mut node, recipient);
    let b3 = mined_child(&node, b2.block_id(), DEVNET_GENESIS_TIMESTAMP + 180, 0x42);
    node.submit_block(b3.clone(), b3.challenge.timestamp)
        .unwrap();
    assert_balance(&mut node, recipient);
    let orphaned = query(&mut node, recipient);
    assert_eq!(orphaned.confirmed_atoms, "0");
    assert!(orphaned.history.is_empty());
    node.submit_transaction(payment).unwrap();
    let b4 = mine(&mut node, insecure_dev_destination(0x42));
    assert_eq!(
        query(&mut node, recipient).history[0].block_id,
        hex::encode(b4.block_id())
    );
    let mut parent = a2.block_id();
    for height in 3..=5 {
        let block = mined_child(&node, parent, DEVNET_GENESIS_TIMESTAMP + height * 60, 0x41);
        parent = block.block_id();
        node.submit_block(block.clone(), block.challenge.timestamp)
            .unwrap();
        assert_balance(&mut node, recipient);
    }
    let expected = query(&mut node, recipient);
    assert_eq!(expected.history.len(), 1);
    assert_eq!(expected.history[0].block_id, hex::encode(a2.block_id()));
    drop(node);
    for expected_snapshot in [true, false] {
        let mut reopened = Node::open(&path).unwrap();
        assert_eq!(reopened.startup_snapshot_used, expected_snapshot);
        assert_eq!(query(&mut reopened, recipient), expected);
        assert_balance(&mut reopened, recipient);
        drop(reopened);
        if expected_snapshot {
            crate::startup_snapshot::invalidate_fixture_snapshots(&path);
        }
    }
    clean_test_dir(&path);
}

// Pages over hint entries read each block once per page; the differential walk
// in `address_pages_read_no_block_bytes_for_a_key_paid_in_every_block` checks
// that.
#[test]
fn address_index_handles_intrablock_spends_without_block_reads() {
    let path = test_dir("explorer-address-intrablock");
    let mut node = Node::open(&path).unwrap();
    let funding = mine(&mut node, default_miner_destination());
    let sender = insecure_dev_destination(0x31);
    let first = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
    let mut second = Transaction {
        network_id: node.params.network_id,
        version: TRANSACTION_VERSION,
        inputs: vec![TxInput {
            previous: OutPoint {
                txid: first.txid(),
                index: 0,
            },
            witness: InputWitness::Key {
                public_key: [0; 32],
                signature: Vec::new(),
            },
        }],
        outputs: vec![TxOutput {
            value: first.outputs[0].value - 1,
            lock: OutputLock::Key(insecure_dev_destination(0x32)),
            spendable_height: 2,
        }],
    };
    second
        .sign_all(&[&SigningKey::from_bytes(&[0x31; 32]).unwrap()])
        .unwrap();
    let block = mined_child_with_transactions(
        &node,
        funding.block_id(),
        DEVNET_GENESIS_TIMESTAMP + 120,
        0x41,
        vec![first, second],
    );
    node.submit_block(block.clone(), block.challenge.timestamp)
        .unwrap();
    let reads = node.explorer_block_reads;
    let view = query(&mut node, sender);
    assert_eq!(node.explorer_block_reads - reads, 0);
    assert_eq!(view.confirmed_atoms, "0");
    assert_eq!(view.history.len(), 2);
    assert_eq!(view.history[0].kind, "sent");
    assert_eq!(view.history[1].kind, "received");
    assert_balance(&mut node, sender);
    assert_balance(&mut node, insecure_dev_destination(0x32));
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn address_queries_reject_forged_activity_and_rebuild_missing_output_cache() {
    let path = test_dir("explorer-address-corruption");
    let mut node = Node::open(&path).unwrap();
    let funding = mine(&mut node, default_miner_destination());
    node.explorer_outputs = AddressOutputIndex::default();
    let payment = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
    node.submit_transaction(payment).unwrap();
    mine(&mut node, default_miner_destination());
    assert_balance(&mut node, default_miner_destination());
    assert_balance(&mut node, insecure_dev_destination(0x31));
    let unrelated = insecure_dev_destination(0x7a);
    node.index.addresses.insert_entries([(
        unrelated,
        AddressLocation {
            height: 1,
            position: 0,
            block_id: funding.block_id(),
        },
    )]);
    assert!(matches!(
        node.explorer_address(&hex::encode(unrelated), None),
        Err(NodeError::CorruptLog(_))
    ));
    assert!(node.storage_faulted);
    assert!(matches!(
        node.explorer_address(&hex::encode(default_miner_destination()), None),
        Err(NodeError::StorageFaulted)
    ));
    drop(node);
    let mut reopened = Node::open(&path).unwrap();
    assert!(query(&mut reopened, unrelated).history.is_empty());
    assert_balance(&mut reopened, insecure_dev_destination(0x31));
    let entries = AddressHistoryIndex::block_entries(&funding);
    assert_eq!(entries.len(), funding.coinbase.outputs.len());
    drop(reopened);
    clean_test_dir(&path);
}

#[test]
fn address_index_distinguishes_self_transfers_and_channel_escrow() {
    let path = test_dir("explorer-address-self-channel");
    let mut node = Node::open(&path).unwrap();
    let funding = mine(&mut node, default_miner_destination());
    let owner = insecure_dev_destination(0x12);
    let first = spend_coinbase_output(&node, &funding, 2, 0x12, 0x12, 1);
    node.submit_transaction(first.clone()).unwrap();
    mine(&mut node, default_miner_destination());
    let view = query(&mut node, owner);
    let self_transfer = view
        .history
        .iter()
        .find(|item| item.txid == hex::encode(first.txid()))
        .unwrap();
    assert_eq!(self_transfer.kind, "self");
    assert_eq!(self_transfer.received_outputs, 1);
    assert_eq!(self_transfer.spent_inputs, 1);
    assert_balance(&mut node, owner);

    let channel = [0x77; 32];
    let mut second = Transaction {
        network_id: node.params.network_id,
        version: TRANSACTION_VERSION,
        inputs: vec![TxInput {
            previous: OutPoint {
                txid: first.txid(),
                index: 0,
            },
            witness: InputWitness::Key {
                public_key: [0; 32],
                signature: Vec::new(),
            },
        }],
        outputs: vec![TxOutput {
            value: first.outputs[0].value - 1,
            lock: OutputLock::InferenceChannel {
                channel_id: channel,
            },
            spendable_height: node.state.next_height(),
        }],
    };
    second
        .sign_all(&[&SigningKey::from_bytes(&[0x12; 32]).unwrap()])
        .unwrap();
    node.submit_transaction(second).unwrap();
    mine(&mut node, default_miner_destination());
    assert_balance(&mut node, owner);
    let channel_as_key = query(&mut node, channel);
    assert_eq!(channel_as_key.confirmed_atoms, "0");
    assert!(channel_as_key.history.is_empty());
    assert!(node.state.utxos().iter().any(|(_, output)| output.lock
        == OutputLock::InferenceChannel {
            channel_id: channel
        }));
    drop(node);
    clean_test_dir(&path);
}

#[test]
fn address_pagination_and_stale_errors_cross_the_loopback_http_server() {
    let path = test_dir("explorer-address-http");
    let mut node = Node::open(&path).unwrap();
    let address = default_miner_destination();
    for _ in 0..=EXPLORER_ADDRESS_PAGE_SIZE {
        mine(&mut node, address);
    }
    let network = hex::encode(node.params.network_id);
    let shared = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = spawn_rpc_server_with_listener(Arc::clone(&shared), listener).unwrap();
    let get = |target: &str, expected_status: u16| {
        let mut stream = TcpStream::connect(endpoint).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(
            headers.starts_with(&format!("HTTP/1.1 {expected_status} ")),
            "{headers}"
        );
        assert_eq!(headers.matches("X-CMFD-Network-Id:").count(), 1);
        assert!(headers.contains(&format!("X-CMFD-Network-Id: {network}")));
        serde_json::from_str::<serde_json::Value>(body).unwrap()
    };
    let target = format!("/v1/explorer/address/{}", hex::encode(address));
    let first = get(&target, 200);
    assert_eq!(
        first["history"].as_array().unwrap().len(),
        EXPLORER_ADDRESS_PAGE_SIZE
    );
    let cursor = first["next_cursor"].as_str().unwrap();
    let next_target = format!("{target}/{cursor}");
    let next = get(&next_target, 200);
    assert_eq!(next["history"].as_array().unwrap().len(), 1);
    assert_eq!(next["has_more"], false);
    mine(&mut shared.lock().unwrap(), address);
    let stale = get(&next_target, 409);
    assert_eq!(stale["code"], "explorer_cursor_stale");
    assert_eq!(stale["retryable"], true);
    assert!(stale["error"].is_string());
    get("/v1/explorer/address/not-an-address", 400);
    server.stop().unwrap();
    drop(shared);
    clean_test_dir(&path);
}

/// Every page of the key's history from the first, following `next_cursor`,
/// with the explorer block reads and block-log bytes each page took.
fn walk(node: &mut Node, address: [u8; 32]) -> Vec<(ExplorerAddress, usize, u64)> {
    let mut pages = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let reads = node.explorer_block_reads;
        let bytes = log_record_bytes_read();
        let page = node
            .explorer_address(&hex::encode(address), cursor.as_deref())
            .unwrap();
        cursor = page.next_cursor.clone();
        pages.push((
            page,
            node.explorer_block_reads - reads,
            log_record_bytes_read() - bytes,
        ));
        if cursor.is_none() {
            return pages;
        }
    }
}

fn walk_without_reads(node: &mut Node, address: [u8; 32]) -> Vec<ExplorerAddress> {
    walk(node, address)
        .into_iter()
        .map(|(page, reads, bytes)| {
            assert_eq!((reads, bytes), (0, 0), "an address page read the block log");
            page
        })
        .collect()
}

#[test]
fn address_pages_read_no_block_bytes_for_a_key_paid_in_every_block() {
    let path = test_dir("explorer-address-read-bound");
    let mut node = Node::open(&path).unwrap();
    // Every coinbase pays the community key (secret 0x12), as mainnet's
    // steward, community and pool keys are paid in every block.
    let community = insecure_dev_destination(0x12);
    let recipient = insecure_dev_destination(0x31);
    let funding = mine(&mut node, default_miner_destination());
    // A payment from the key with change back to it: a sent entry in block 2.
    let mut payment = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
    payment.outputs[0].value -= 10;
    payment.outputs.push(TxOutput {
        value: 10,
        lock: OutputLock::Key(community),
        spendable_height: node.state.next_height(),
    });
    payment
        .sign_all(&[&SigningKey::from_bytes(&[0x12; 32]).unwrap()])
        .unwrap();
    node.submit_transaction(payment.clone()).unwrap();
    let second = mine(&mut node, default_miner_destination());
    let third = mine(&mut node, default_miner_destination());
    // A consolidation in block 4: two of the key's coinbase outputs into a
    // payment and two outputs back to the key, so the facts must add up two
    // inputs, two outputs and their atoms.
    let community_owner = SigningKey::from_bytes(&[0x12; 32]).unwrap();
    let pooled: u64 = [&second, &third]
        .iter()
        .map(|block| block.coinbase.outputs[2].value)
        .sum();
    let mut consolidation = Transaction {
        network_id: node.params.network_id,
        version: TRANSACTION_VERSION,
        inputs: [&second, &third]
            .iter()
            .map(|block| TxInput {
                previous: OutPoint {
                    txid: block.coinbase_outpoint_id(),
                    index: 2,
                },
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: Vec::new(),
                },
            })
            .collect(),
        outputs: [(recipient, 1_000), (community, 7), (community, 0)]
            .into_iter()
            .map(|(key, value)| TxOutput {
                value,
                lock: OutputLock::Key(key),
                spendable_height: node.state.next_height(),
            })
            .collect(),
    };
    consolidation.outputs[2].value = pooled - 1_000 - 7 - 5;
    consolidation
        .sign_all(&[&community_owner, &community_owner])
        .unwrap();
    node.submit_transaction(consolidation.clone()).unwrap();
    let tip_height = 3 * EXPLORER_ADDRESS_PAGE_SIZE as u64 + 5;
    while node.state.next_height() <= tip_height {
        mine(&mut node, default_miner_destination());
    }
    // A two-block side branch that never activates; it pays the key too.
    let fork_parent = node.active_block_id_at_height(tip_height - 3).unwrap();
    let side_one = mined_child(
        &node,
        fork_parent,
        DEVNET_GENESIS_TIMESTAMP + (tip_height - 2) * 60 + 1,
        0x42,
    );
    node.submit_block(side_one.clone(), side_one.challenge.timestamp)
        .unwrap();
    let side_two = mined_child(
        &node,
        side_one.block_id(),
        DEVNET_GENESIS_TIMESTAMP + (tip_height - 1) * 60 + 1,
        0x42,
    );
    node.submit_block(side_two.clone(), side_two.challenge.timestamp)
        .unwrap();
    assert_eq!(node.state.next_height(), tip_height + 1);
    assert!(node.index.addresses.contains(
        &community,
        AddressLocation {
            height: tip_height - 1,
            position: 0,
            block_id: side_two.block_id(),
        }
    ));
    let side_blocks = [
        hex::encode(side_one.block_id()),
        hex::encode(side_two.block_id()),
    ];

    // Steady state: every page of every key reads nothing from the log.
    let keys = [community, default_miner_destination(), recipient];
    let expected: Vec<Vec<ExplorerAddress>> = keys
        .iter()
        .map(|key| walk_without_reads(&mut node, *key))
        .collect();
    let pages = &expected[0];
    assert_eq!(
        pages
            .iter()
            .map(|page| page.history.len())
            .collect::<Vec<_>>(),
        [20, 20, 20, 7]
    );
    assert!(pages[..3].iter().all(|page| page.has_more));
    let rows: Vec<_> = pages.iter().flat_map(|page| &page.history).collect();
    assert!(
        rows.windows(2)
            .all(|pair| pair[0].block_height >= pair[1].block_height)
    );
    assert_eq!(
        rows.iter()
            .map(|row| row.block_height)
            .collect::<std::collections::BTreeSet<_>>(),
        (1..=tip_height).collect::<std::collections::BTreeSet<_>>()
    );
    assert!(rows.iter().all(|row| !side_blocks.contains(&row.block_id)));
    assert_eq!(
        rows.iter().filter(|row| row.kind == "coinbase").count() as u64,
        tip_height
    );
    let sent: Vec<_> = rows
        .iter()
        .filter(|row| row.kind != "coinbase")
        .map(|row| {
            (
                row.kind,
                row.txid.clone(),
                row.block_height,
                row.received_atoms.clone(),
                row.received_outputs,
                row.spent_inputs,
            )
        })
        .collect();
    assert_eq!(
        sent,
        [
            (
                "sent",
                hex::encode(consolidation.txid()),
                4,
                (pooled - 1_000 - 5).to_string(),
                2,
                2
            ),
            (
                "sent",
                hex::encode(payment.txid()),
                2,
                "10".to_owned(),
                1,
                1
            ),
        ]
    );
    assert_eq!(
        expected[1]
            .iter()
            .map(|page| page.history.len())
            .sum::<usize>() as u64,
        tip_height
    );
    assert_eq!(expected[2].len(), 1);
    assert_eq!(
        expected[2][0]
            .history
            .iter()
            .map(|row| (row.kind, row.block_height))
            .collect::<Vec<_>>(),
        [("received", 4), ("received", 2)]
    );
    // The explorer Worker's supply query: a cursor at the key's first entry
    // (block 1's coinbase) gives an empty page with the full balance.
    let reads = node.explorer_block_reads;
    let bytes = log_record_bytes_read();
    let supply_cursor = format!("{}.1.0", hex::encode(node.state.tip()));
    let supply = node
        .explorer_address(&hex::encode(community), Some(&supply_cursor))
        .unwrap();
    assert!(supply.history.is_empty());
    assert!(!supply.has_more);
    assert_eq!(supply.confirmed_atoms, pages[0].confirmed_atoms);
    assert_eq!(
        (
            node.explorer_block_reads - reads,
            log_record_bytes_read() - bytes
        ),
        (0, 0)
    );

    // The facts equal what the authenticated block path derives: forget them,
    // and the same walk reads each page's blocks (at most a page's worth),
    // gives identical pages and fills the facts back in as it goes.
    for (key, expected) in keys.iter().zip(&expected) {
        node.index.addresses.forget_facts();
        let legacy = walk(&mut node, *key);
        assert!(
            legacy
                .iter()
                .all(|(_, reads, _)| *reads <= EXPLORER_ADDRESS_PAGE_SIZE)
        );
        let distinct_blocks: std::collections::BTreeSet<_> = expected
            .iter()
            .flat_map(|page| &page.history)
            .map(|row| row.block_id.clone())
            .collect();
        assert_eq!(
            legacy.iter().map(|(_, reads, _)| reads).sum::<usize>(),
            distinct_blocks.len()
        );
        assert!(
            legacy
                .iter()
                .all(|(_, reads, bytes)| (*reads > 0) == (*bytes > 0))
        );
        assert_eq!(
            legacy
                .into_iter()
                .map(|(page, _, _)| page)
                .collect::<Vec<_>>(),
            *expected
        );
        assert_eq!(walk_without_reads(&mut node, *key), *expected);
    }
    drop(node);

    // A fast start from the index cache, then a full scan of the log with and
    // without the startup snapshot, all answer every page without block reads.
    let mut reopened = Node::open(&path).unwrap();
    assert!(reopened.startup_snapshot_used);
    assert!(!reopened.status().unwrap().history_scrub_complete);
    for (key, expected) in keys.iter().zip(&expected) {
        assert_eq!(walk_without_reads(&mut reopened, *key), *expected);
    }
    drop(reopened);
    std::fs::remove_file(path.join("startup-index.bin")).unwrap();
    let mut scanned = Node::open(&path).unwrap();
    assert!(scanned.startup_snapshot_used);
    assert!(scanned.status().unwrap().history_scrub_complete);
    for (key, expected) in keys.iter().zip(&expected) {
        assert_eq!(walk_without_reads(&mut scanned, *key), *expected);
    }
    drop(scanned);
    crate::startup_snapshot::invalidate_fixture_snapshots(&path);
    let mut replayed = Node::open(&path).unwrap();
    assert!(!replayed.startup_snapshot_used);
    for (key, expected) in keys.iter().zip(&expected) {
        assert_eq!(walk_without_reads(&mut replayed, *key), *expected);
    }
    drop(replayed);
    clean_test_dir(&path);
}
