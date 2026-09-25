//! Operator-invoked valid-record recovery fixture using the tiny local profile.
//! This complements (never substitutes for) full-size production proof testing.
//! No network service, GPU, mainnet activation or existing wallet is used.

use crate::explorer_address_index::AddressOutputIndex;
use crate::tests::{clean_test_dir, spend_coinbase_output, test_dir};
use crate::*;

fn input(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    let value = match std::env::var(name) {
        Ok(value) => value.parse().expect("recovery input must be an integer"),
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("{name}: {error}"),
    };
    assert!((minimum..=maximum).contains(&value), "{name} out of bounds");
    value
}

fn recipient(ordinal: usize) -> [u8; 32] {
    // Deterministic disposable fixture keys; never a production wallet.
    let mut secret = [0; 32];
    secret[0] = 0x41;
    secret[24..].copy_from_slice(&(ordinal as u64).to_be_bytes());
    SigningKey::from_bytes(&secret)
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into()
}

fn assert_recovered(
    node: &mut Node,
    expected_state: &[u8],
    expected_transactions: usize,
    queries: &[[u8; 32]],
    addresses: &[[u8; 32]],
) -> serde_json::Value {
    assert_eq!(node.state.encode_local_snapshot().unwrap(), expected_state);
    assert_eq!(
        node.index.transactions.qualification_shape().0,
        expected_transactions
    );
    assert_eq!(
        node.explorer_outputs,
        AddressOutputIndex::from_utxos(node.state.utxos())
    );
    let transactions: Vec<_> = queries
        .iter()
        .map(|txid| {
            let view = node
                .explorer_transaction(&hex::encode(txid))
                .unwrap()
                .unwrap();
            assert_eq!(view.status, "confirmed");
            view
        })
        .collect();
    let balances: Vec<_> = addresses
        .iter()
        .map(|address| {
            let view = node.explorer_address(&hex::encode(address), None).unwrap();
            let expected: u128 = node
                .state
                .utxos()
                .iter()
                .filter(|(_, output)| output.lock == OutputLock::Key(*address))
                .map(|(_, output)| u128::from(output.value))
                .sum();
            assert_eq!(view.confirmed_atoms, expected.to_string());
            view
        })
        .collect();
    json!({ "transactions": transactions, "addresses": balances })
}

#[test]
#[ignore = "bounded valid tiny-profile transaction history and restart/recovery fixture; not full-size production startup qualification"]
fn explorer_dense_valid_history_recovery() {
    let block_count = input("CMFD_RECOVERY_BLOCKS", 512, 1, 1024);
    let lanes = input("CMFD_RECOVERY_TX_PER_BLOCK", 20, 1, 20);
    let fork_every = input("CMFD_RECOVERY_FORK_EVERY", 0, 0, 1024);
    let mut side_blocks = 0;
    let path = test_dir("explorer-dense-valid-recovery");
    assert!(!path.exists(), "never overwrite a prior recovery fixture");
    let started = Instant::now();
    let mut node = Node::open(&path).unwrap();
    assert_eq!(node.network_profile(), DEVNET_PROFILE);
    let funding = node
        .mine_once(
            default_miner_destination(),
            DEVNET_GENESIS_TIMESTAMP + 60,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
    let mut split = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
    let lane_value = split.outputs[0].value / lanes as u64;
    assert!(lane_value > block_count as u64 * 2);
    let owner = insecure_dev_destination(0x31);
    split.outputs = (0..lanes)
        .map(|_| TxOutput {
            value: lane_value,
            lock: OutputLock::Key(owner),
            spendable_height: 2,
        })
        .collect();
    split
        .sign_all(&[&SigningKey::from_bytes(&[0x12; 32]).unwrap()])
        .unwrap();
    node.submit_transaction(split.clone()).unwrap();
    node.mine_once(
        default_miner_destination(),
        DEVNET_GENESIS_TIMESTAMP + 120,
        DEFAULT_MINING_ATTEMPTS,
    )
    .unwrap();
    let mut previous: Vec<_> = (0..lanes)
        .map(|lane| OutPoint {
            txid: split.txid(),
            index: lane as u32,
        })
        .collect();
    let params = node.params;
    let verifier = node.verifier.clone();
    let mut state = node.state.clone();
    let mut digest = node.last_record_digest;
    let mut queries = vec![split.txid()];
    drop(node);

    // Batch only the fixture's file flush. Each appended record still contains
    // a normally validated block and its exact reversible state delta. On next
    // open the stale two-block startup cache cannot cover this longer log.
    let mut log = OpenOptions::new()
        .append(true)
        .open(path.join(BLOCK_LOG_FILE))
        .unwrap();
    let signing_key = SigningKey::from_bytes(&[0x31; 32]).unwrap();
    for index in 0..block_count {
        let height = index as u64 + 3;
        let now = DEVNET_GENESIS_TIMESTAMP + height * 60;
        let mut transactions = Vec::with_capacity(lanes);
        for (lane, previous) in previous.iter_mut().enumerate() {
            let mut transaction = Transaction {
                network_id: params.network_id,
                version: TRANSACTION_VERSION,
                inputs: vec![TxInput {
                    previous: *previous,
                    witness: InputWitness::Key {
                        public_key: [0; 32],
                        signature: Vec::new(),
                    },
                }],
                outputs: vec![
                    TxOutput {
                        value: lane_value - (index as u64 + 1) * 2,
                        lock: OutputLock::Key(owner),
                        spendable_height: height,
                    },
                    TxOutput {
                        value: 1,
                        lock: OutputLock::Key(recipient(index * lanes + lane)),
                        spendable_height: height,
                    },
                ],
            };
            transaction.sign_all(&[&signing_key]).unwrap();
            *previous = OutPoint {
                txid: transaction.txid(),
                index: 0,
            };
            if lane == 0 && (index == 0 || index == block_count / 2 || index == block_count - 1) {
                queries.push(transaction.txid());
            }
            transactions.push(transaction);
        }
        let side_state = (fork_every != 0 && (index + 1) % fork_every == 0).then(|| state.clone());
        let template = build_template_from_state(
            &state,
            &params,
            default_miner_destination(),
            now,
            transactions,
        )
        .unwrap();
        let proof = verifier
            .mine(&template.challenge, 0, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let block = Block {
            version: BLOCK_VERSION,
            challenge: template.challenge,
            coinbase: template.coinbase,
            transactions: template.transactions,
            proof,
        };
        let validated = state
            .validate_block(
                &block,
                BlockValidationContext {
                    now_unix_seconds: now,
                },
            )
            .unwrap();
        let delta = validated.encode_reversible_state_delta().unwrap();
        let record = encode_record_v2(
            now,
            &encode_block(&block).unwrap(),
            &delta,
            digest,
            params.network_id,
        )
        .unwrap();
        digest = complete_record_digest(&record);
        log.write_all(&record).unwrap();
        state.commit_validated(validated).unwrap();
        if let Some(mut side_state) = side_state {
            // A real, separately validated sibling follows the first-seen
            // canonical block at equal work. The same transactions can occur
            // on both forks, but their rewards and block identities differ.
            let template = build_template_from_state(
                &side_state,
                &params,
                insecure_dev_destination(0x32),
                now,
                block.transactions.clone(),
            )
            .unwrap();
            let proof = verifier
                .mine(&template.challenge, 0, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
            let sibling = Block {
                version: BLOCK_VERSION,
                challenge: template.challenge,
                coinbase: template.coinbase,
                transactions: template.transactions,
                proof,
            };
            let validated = side_state
                .validate_block(
                    &sibling,
                    BlockValidationContext {
                        now_unix_seconds: now,
                    },
                )
                .unwrap();
            let delta = validated.encode_reversible_state_delta().unwrap();
            let record = encode_record_v2(
                now,
                &encode_block(&sibling).unwrap(),
                &delta,
                digest,
                params.network_id,
            )
            .unwrap();
            digest = complete_record_digest(&record);
            log.write_all(&record).unwrap();
            side_state.commit_validated(validated).unwrap();
            side_blocks += 1;
        }
    }
    log.sync_all().unwrap();
    let log_bytes = log.metadata().unwrap().len();
    drop(log);
    let build_time = started.elapsed();
    let expected_state = state.encode_local_snapshot().unwrap();
    let addresses = [
        owner,
        recipient(0),
        recipient(block_count * lanes - 1),
        insecure_dev_destination(0x12),
    ];
    let mut reopen_times = Vec::new();
    let mut expected_views = None;
    for expected_snapshot in [false, true, false] {
        let started = Instant::now();
        let mut reopened = Node::open(&path).unwrap();
        reopen_times.push(started.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(reopened.startup_snapshot_used, expected_snapshot);
        assert_eq!(reopened.state.next_height(), block_count as u64 + 3);
        assert_eq!(reopened.index.blocks.len(), block_count + 2 + side_blocks);
        assert_eq!(
            reopened.index.transactions.qualification_shape().1,
            1 + (block_count + side_blocks) * lanes
        );
        let views = assert_recovered(
            &mut reopened,
            &expected_state,
            1 + block_count * lanes,
            &queries,
            &addresses,
        );
        if let Some(expected) = &expected_views {
            assert_eq!(&views, expected);
        } else {
            expected_views = Some(views);
        }
        drop(reopened);
        if expected_snapshot {
            // Damage only this disposable fixture's optional cache, never the
            // valid log. The final reopen must fully replay and rebuild indexes.
            for slot in 0..=1 {
                let cache = path.join(format!(
                    "{}.{slot}.bin",
                    startup_snapshot::STARTUP_SNAPSHOT_FILE_PREFIX
                ));
                if cache.exists() {
                    let mut bytes = fs::read(&cache).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(&cache, bytes).unwrap();
                }
            }
        }
    }
    println!(
        "CMFD_DENSE_RECOVERY {}",
        json!({
            "scope": "consensus-valid tiny local proof profile only; not full-size V4 startup cost or mainnet acceptance",
            "blocks": block_count + 2,
            "retained_records": block_count + 2 + side_blocks,
            "side_blocks": side_blocks,
            "transactions": 1 + block_count * lanes,
            "record_log_bytes": log_bytes,
            "build_millis": build_time.as_secs_f64() * 1000.0,
            "full_replay_millis": reopen_times[0],
            "snapshot_restart_millis": reopen_times[1],
            "corrupt_cache_fallback_replay_millis": reopen_times[2],
            "exact_state_and_explorer_views_agreed": true,
        })
    );
    clean_test_dir(&path);
}
