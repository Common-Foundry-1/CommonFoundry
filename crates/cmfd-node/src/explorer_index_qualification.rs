//! Bounded operator probe of the actual in-memory lookup structures, not a chain.
//!
//! IDs and locators below are deliberately synthetic. There is no block log,
//! proof, accepted transaction, listener, wallet, or running node. Results exclude
//! authoritative UTXOs, proof verification, disk history and startup/recovery.

use std::env;
use std::hint::black_box;

use crate::explorer_address_index::{AddressLocation, AddressOutputIndex};
use crate::explorer_index::TransactionLocation;
use crate::*;

fn bounded_input(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    let value = match env::var(name) {
        Ok(value) => value
            .parse()
            .expect("qualification input must be an integer"),
        Err(env::VarError::NotPresent) => default,
        Err(error) => panic!("{name}: {error}"),
    };
    assert!((minimum..=maximum).contains(&value), "{name} out of bounds");
    value
}

fn id(kind: u8, ordinal: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value[0] = kind;
    value[24..].copy_from_slice(&(ordinal as u64).to_be_bytes());
    value
}

struct ShapeFixture {
    chain: BlockIndex,
    outputs: AddressOutputIndex,
    sample_header: SuccessorHeaderPreflight,
    transactions_per_block: usize,
    unique_recipients: bool,
}

impl ShapeFixture {
    fn new(transactions_per_block: usize, unique_recipients: bool) -> Self {
        let (params, verifier) =
            network_params_and_verifier_for_profile(DEVNET_PROFILE, None, None).unwrap();
        let state = ChainState::new(params, verifier).unwrap();
        Self {
            chain: BlockIndex::new(DEVNET_PROFILE.virtual_genesis_hash),
            outputs: AddressOutputIndex::default(),
            sample_header: state.successor_header_preflight().unwrap(),
            transactions_per_block,
            unique_recipients,
        }
    }

    fn append(&mut self, height: usize, canonical: bool) {
        let ordinal = self.chain.blocks.len() + 1;
        let block_id = if canonical {
            id(0x11, height)
        } else {
            id(0xf0, ordinal)
        };
        let parent = if height == 1 {
            self.chain.genesis
        } else {
            id(0x11, height - 1)
        };
        let ancestors = self.chain.ancestor_table(parent).unwrap();
        let entry = IndexedBlock {
            // Invalid durable positions intentionally prevent this metadata
            // fixture from being interpreted as authenticated block history.
            locator: BlockRecordLocator {
                ordinal: ordinal as u64,
                offset: 0,
                length: 0,
                version: BlockRecordVersion::V2,
                complete_digest: [0; 32],
                accepted_at: 0,
                block_id,
                parent,
                height: height as u64,
                target: [0; 32],
            },
            cumulative_work: U512::from(height),
            successor_header: self.sample_header,
            ancestors,
        };
        self.chain.blocks.insert(block_id, Arc::new(entry));
        if canonical {
            assert_eq!(self.chain.active_chain.len(), height);
            self.chain.active_chain.push(block_id);
        }
        let mut txids = Vec::with_capacity(self.transactions_per_block);
        let mut addresses = Vec::with_capacity(self.transactions_per_block * 2 + 3);
        for position in 0..self.transactions_per_block {
            // Position zero is also present on sibling forks at this height,
            // exercising canonical selection instead of a unique-key-only case.
            let transaction_id = if canonical || position == 0 {
                id(0x21, height * self.transactions_per_block + position)
            } else {
                id(0x22, ordinal * self.transactions_per_block + position)
            };
            txids.push(transaction_id);
            let recipient_number = ordinal * self.transactions_per_block + position;
            let recipient = id(
                0x32,
                if self.unique_recipients {
                    recipient_number
                } else {
                    recipient_number % 4096
                },
            );
            let location = AddressLocation {
                height: height as u64,
                position: position + 1,
                block_id,
            };
            addresses.extend([(id(0x31, 0), location), (recipient, location)]);
            if canonical {
                self.outputs.insert_qualification_output(
                    recipient,
                    OutPoint {
                        txid: transaction_id,
                        index: 0,
                    },
                );
            }
        }
        for reward in 0..3 {
            let owner = id(0x33, reward);
            addresses.push((
                owner,
                AddressLocation {
                    height: height as u64,
                    position: 0,
                    block_id,
                },
            ));
            if canonical {
                self.outputs.insert_qualification_output(
                    owner,
                    OutPoint {
                        txid: id(0x23, height),
                        index: reward as u32,
                    },
                );
            }
        }
        self.chain.transactions.insert_block(block_id, txids);
        self.chain.addresses.insert_entries(addresses);
    }
}

#[test]
#[ignore = "bounded synthetic metadata-only load shape; run separately from valid-record recovery and full-proof qualification"]
fn explorer_dense_index_shape() {
    let blocks = bounded_input("CMFD_INDEX_PROBE_BLOCKS", 43_200, 20, 43_200);
    let transactions_per_block = bounded_input("CMFD_INDEX_PROBE_TX_PER_BLOCK", 20, 1, 20);
    let orphan_tail = bounded_input("CMFD_INDEX_PROBE_ORPHAN_TAIL", 10_000, 0, 10_000);
    let mode = env::var("CMFD_INDEX_PROBE_MODE").unwrap_or_else(|_| "concentrated".into());
    assert!(matches!(mode.as_str(), "concentrated" | "unique"));
    let started = Instant::now();
    let mut fixture = ShapeFixture::new(transactions_per_block, mode == "unique");
    for height in 1..=blocks {
        fixture.append(height, true);
        if height % 10 == 0 {
            fixture.append(height, false);
        }
    }
    for _ in 0..orphan_tail {
        fixture.append(blocks, false);
    }
    let build_time = started.elapsed();
    let retained_blocks = blocks + blocks / 10 + orphan_tail;
    assert_eq!(fixture.chain.blocks.len(), retained_blocks);
    assert_eq!(fixture.chain.active_chain.len(), blocks + 1);
    assert_eq!(
        fixture
            .chain
            .ancestor_at_height(id(0x11, blocks), 1)
            .unwrap(),
        id(0x11, 1)
    );
    let (unique_transactions, occurrences, capacity) =
        fixture.chain.transactions.qualification_shape();
    assert_eq!(occurrences, retained_blocks * transactions_per_block);
    assert_eq!(
        unique_transactions,
        blocks * transactions_per_block + (retained_blocks - blocks) * (transactions_per_block - 1)
    );
    let (history_addresses, history_entries) = fixture.chain.addresses.qualification_shape();
    assert_eq!(
        history_entries,
        retained_blocks * (transactions_per_block * 2 + 3)
    );
    let (output_addresses, output_refs) = fixture.outputs.qualification_shape();
    assert_eq!(output_refs, blocks * (transactions_per_block + 3));
    let hot_address = id(0x31, 0);
    let expected = fixture
        .chain
        .addresses
        .page(&hot_address, &fixture.chain, None, 20);
    assert_eq!(expected.len(), 20);
    assert!(
        expected
            .iter()
            .all(|location| fixture.chain.active_position(location.block_id).is_some())
    );
    let second =
        fixture
            .chain
            .addresses
            .page(&hot_address, &fixture.chain, expected.last().copied(), 20);
    assert_eq!(
        second.len(),
        (blocks * transactions_per_block).saturating_sub(20).min(20)
    );
    assert!(second.iter().all(|location| !expected.contains(location)));
    let address_started = Instant::now();
    for _ in 0..20 {
        assert_eq!(
            black_box(
                fixture
                    .chain
                    .addresses
                    .page(&hot_address, &fixture.chain, None, 20)
            ),
            expected
        );
    }
    let address_time = address_started.elapsed();
    let repeated_txid = id(0x21, blocks * transactions_per_block);
    let tx_started = Instant::now();
    for _ in 0..100 {
        let location = fixture
            .chain
            .transactions
            .active_location(&repeated_txid, &fixture.chain)
            .unwrap();
        assert_eq!(
            black_box(location),
            TransactionLocation {
                block_id: id(0x11, blocks),
                transaction_position: 0
            }
        );
    }
    let tx_time = tx_started.elapsed();
    println!(
        "CMFD_INDEX_SHAPE {}",
        json!({
            "scope": "synthetic metadata only; not consensus, whole-node RSS, startup or recovery qualification",
            "mode": mode,
            "canonical_blocks": blocks,
            "retained_blocks": retained_blocks,
            "orphan_tail_blocks": orphan_tail,
            "transactions_per_block": transactions_per_block,
            "transaction_keys": unique_transactions,
            "transaction_occurrences": occurrences,
            "transaction_location_capacity": capacity,
            "transaction_location_capacity_bytes": capacity * std::mem::size_of::<TransactionLocation>(),
            "history_addresses": history_addresses,
            "history_entries": history_entries,
            "output_addresses": output_addresses,
            "active_output_references": output_refs,
            "build_millis": build_time.as_secs_f64() * 1000.0,
            "hot_address_20_queries_millis": address_time.as_secs_f64() * 1000.0,
            "forked_transaction_100_queries_millis": tx_time.as_secs_f64() * 1000.0,
        })
    );
    black_box(&fixture);
}
