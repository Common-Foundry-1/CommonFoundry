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
    assert_eq!(node.explorer_block_reads, EXPLORER_ADDRESS_PAGE_SIZE);
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
    let mut reopened = Node::open(&path).unwrap();
    assert!(!reopened.startup_snapshot_used);
    assert_eq!(query(&mut reopened, recipient), expected);
    assert_balance(&mut reopened, recipient);
    drop(reopened);
    clean_test_dir(&path);
}

#[test]
fn address_index_handles_intrablock_spends_and_reads_each_page_block_once() {
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
    assert_eq!(node.explorer_block_reads - reads, 1);
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
