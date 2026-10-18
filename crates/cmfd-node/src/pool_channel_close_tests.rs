// A channel close pays out only at the height that mines it, and a pool takes
// its transactions from the mempool only when the tip changes. A host or renter
// sends the close for the next block after seeing the tip, so it always arrives
// after the pool built that block's job. This mines through a real local pool
// session to show the close still reaches a block.

fn wait_for_job_at(client: &mut PoolClient, height: u64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while client.current_job().challenge.height != height {
        assert!(Instant::now() < deadline, "no job for height {height}");
        match client.receive() {
            Ok(_) => {}
            Err(PoolError::Io(error)) if is_timeout(&error) => {}
            Err(error) => panic!("{error}"),
        }
    }
}

fn mine_pool_block(client: &mut PoolClient) {
    let work = client.current_work().unwrap();
    let nonce = find_share_from(&work, client.current_nonce_origin(), true);
    let result = client.submit_share(work.job().job_id, nonce).unwrap();
    assert!(result.block_accepted, "{}", result.code);
}

#[test]
fn a_channel_close_sent_after_the_pool_job_is_mined_in_the_next_pool_block() {
    use cmfd_consensus::{InputWitness, OutPoint, TRANSACTION_VERSION, TxInput, TxOutput};
    use cmfd_marketplace::{ChannelTerms, Settlement, SignedPaymentState};

    let (_root, server, node, pin) = server("channel-close");
    let customer = SigningKey::from_bytes(&[0x21; 32]).unwrap();
    let provider = SigningKey::from_bytes(&[0x22; 32]).unwrap();
    let (terms, funding) = {
        let mut node = node.lock().unwrap();
        let now = unix_time_seconds().unwrap();
        let block = node
            .mine_once(default_miner_destination(), now, 10_000)
            .unwrap();
        let mut transaction =
            crate::tests::spend_coinbase_output(&node, &block, 1, 0x11, 0x23, 1);
        let terms = ChannelTerms {
            network_id: node.params.network_id,
            job_id: [0x24; 32],
            customer_key: customer.verifying_key().to_bytes().into(),
            provider_key: provider.verifying_key().to_bytes().into(),
            model_digest: [0x25; 32],
            runtime_digest: [0x26; 32],
            input_digest: [0x27; 32],
            deposit: transaction.outputs[0].value,
            close_fee_burn: 1_000,
            base_price: 100,
            input_price_per_1000: 0,
            output_price_per_1000: 4_000,
            max_input_tokens: 1,
            max_output_tokens: 1_024,
            output_chunk_tokens: 32,
            refund_height: 1_000,
        };
        transaction.outputs[0].lock = OutputLock::InferenceChannel {
            channel_id: terms.channel_id().unwrap(),
        };
        transaction
            .sign_all(&[&SigningKey::from_bytes(&[0x11; 32]).unwrap()])
            .unwrap();
        let funding = OutPoint {
            txid: transaction.txid(),
            index: 0,
        };
        node.submit_transaction(transaction).unwrap();
        node.mine_once(default_miner_destination(), now + 60, 10_000)
            .unwrap();
        (terms, funding)
    };
    let mut client = client(server.local_addr(), pin, "close-worker");
    wait_for_job_at(&mut client, 3);

    let state = SignedPaymentState::sign(terms.initial_state(0, 32).unwrap(), &customer);
    let settlement = Settlement::close(state, &provider);
    let provider_payment = settlement.state.state.provider_payment;
    let customer_refund = settlement.state.state.customer_refund;
    let close_at = |height: u64| Transaction {
        network_id: terms.network_id,
        version: TRANSACTION_VERSION,
        inputs: vec![TxInput {
            previous: funding,
            witness: InputWitness::InferenceSettlement {
                terms: terms.clone(),
                settlement: settlement.clone(),
            },
        }],
        outputs: vec![
            TxOutput {
                value: provider_payment,
                lock: OutputLock::Key(terms.provider_key),
                spendable_height: height,
            },
            TxOutput {
                value: customer_refund,
                lock: OutputLock::Key(terms.customer_key),
                spendable_height: height,
            },
        ],
    };
    // What the host does on seeing tip 2: a close for block 3.
    node.lock().unwrap().submit_transaction(close_at(3)).unwrap();

    // The pool's job for block 3 was built before the close arrived.
    mine_pool_block(&mut client);
    let pending = |node: &Node| {
        node.mempool_entries()
            .find(|entry| entry.transaction.inputs[0].previous == funding)
            .map(|entry| entry.transaction.clone())
    };
    {
        let node = node.lock().unwrap();
        assert_eq!(node.status().unwrap().accepted_height, 3);
        assert!(node.state.utxos().get(&funding).is_some());
        assert_eq!(
            pending(&node).map(|close| close.txid()),
            Some(close_at(4).txid()),
            "the close must wait for block 4, not drop out of the mempool"
        );
    }

    // A host rebroadcasting from a stale tip, or for the current one, finds
    // the close already pending.
    for height in [3, 4] {
        assert!(matches!(
            node.lock().unwrap().submit_transaction(close_at(height)),
            Err(NodeError::DuplicateMempoolTransaction(txid)) if txid == close_at(4).txid()
        ));
    }

    wait_for_job_at(&mut client, 4);
    mine_pool_block(&mut client);
    let node = node.lock().unwrap();
    assert_eq!(node.status().unwrap().accepted_height, 4);
    assert!(node.state.utxos().get(&funding).is_none());
    assert!(pending(&node).is_none());
    let paid = node
        .state
        .utxos()
        .get(&OutPoint {
            txid: close_at(4).txid(),
            index: 0,
        })
        .cloned()
        .unwrap();
    assert_eq!(paid.value, provider_payment);
    assert_eq!(paid.spendable_height, 4);
    drop(node);
    server.stop().unwrap();
}
