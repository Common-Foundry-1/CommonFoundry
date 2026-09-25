//! Public-chain address metadata, independent of private exchange watch lists.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::Bound;

use cmfd_consensus::{Block, InputWitness, OutPoint, OutputLock, UtxoSet};

use crate::BlockIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct AddressLocation {
    pub height: u64,
    /// Zero is coinbase; ordinary transaction positions are one-based here.
    pub position: usize,
    pub block_id: [u8; 32],
}

#[derive(Debug, Default)]
pub(super) struct AddressHistoryIndex {
    locations: HashMap<[u8; 32], BTreeSet<AddressLocation>>,
}

impl AddressHistoryIndex {
    pub fn block_entries(block: &Block) -> Vec<([u8; 32], AddressLocation)> {
        let mut entries = Vec::new();
        let block_id = block.block_id();
        for (position, outputs, inputs) in
            std::iter::once((0, block.coinbase.outputs.as_slice(), &[][..])).chain(
                block.transactions.iter().enumerate().map(|(position, tx)| {
                    (position + 1, tx.outputs.as_slice(), tx.inputs.as_slice())
                }),
            )
        {
            let mut addresses = BTreeSet::new();
            for output in outputs {
                if let OutputLock::Key(address) = output.lock {
                    addresses.insert(address);
                }
            }
            // Consensus validation requires this key to own the spent key
            // output. Channel settlement/refund witnesses are not key outputs.
            for input in inputs {
                if let InputWitness::Key { public_key, .. } = input.witness {
                    addresses.insert(public_key);
                }
            }
            entries.extend(addresses.into_iter().map(|address| {
                (
                    address,
                    AddressLocation {
                        height: block.challenge.height,
                        position,
                        block_id,
                    },
                )
            }));
        }
        entries
    }

    pub fn insert_entries(
        &mut self,
        entries: impl IntoIterator<Item = ([u8; 32], AddressLocation)>,
    ) {
        for (address, location) in entries {
            self.locations.entry(address).or_default().insert(location);
        }
    }

    pub fn contains(&self, address: &[u8; 32], location: AddressLocation) -> bool {
        self.locations
            .get(address)
            .is_some_and(|locations| locations.contains(&location))
    }

    pub fn page(
        &self,
        address: &[u8; 32],
        chain: &BlockIndex,
        before: Option<AddressLocation>,
        limit: usize,
    ) -> Vec<AddressLocation> {
        let Some(locations) = self.locations.get(address) else {
            return Vec::new();
        };
        let end = before.map_or(Bound::Unbounded, Bound::Excluded);
        locations
            .range((Bound::Unbounded, end))
            .rev()
            .filter(|location| chain.active_position(location.block_id).is_some())
            .take(limit)
            .copied()
            .collect()
    }
}

/// Only active key-output identifiers are cached. Amounts and maturity always
/// come from the live consensus UTXO set, not a second balance ledger.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct AddressOutputIndex {
    outputs: HashMap<[u8; 32], HashSet<OutPoint>>,
}

impl AddressOutputIndex {
    pub fn from_utxos(utxos: &UtxoSet) -> Self {
        let mut index = Self::default();
        for (outpoint, output) in utxos.iter() {
            if let OutputLock::Key(address) = output.lock {
                index.outputs.entry(address).or_default().insert(*outpoint);
            }
        }
        index
    }

    /// Used only after an active extension has passed consensus and committed.
    /// A missing input reports a cache inconsistency; the caller rebuilds this
    /// read-only cache from authoritative UTXOs without changing chain acceptance.
    pub fn apply_extension(&mut self, block: &Block) -> bool {
        let mut consistent = true;
        let coinbase_id = block.coinbase_outpoint_id();
        for (position, output) in block.coinbase.outputs.iter().enumerate() {
            if let OutputLock::Key(address) = output.lock {
                self.outputs.entry(address).or_default().insert(OutPoint {
                    txid: coinbase_id,
                    index: position as u32,
                });
            }
        }
        for transaction in &block.transactions {
            for input in &transaction.inputs {
                if let InputWitness::Key { public_key, .. } = input.witness {
                    match self.outputs.get_mut(&public_key) {
                        Some(outputs) => {
                            consistent &= outputs.remove(&input.previous);
                            if outputs.is_empty() {
                                self.outputs.remove(&public_key);
                            }
                        }
                        None => consistent = false,
                    }
                }
            }
            let txid = transaction.txid();
            for (position, output) in transaction.outputs.iter().enumerate() {
                if let OutputLock::Key(address) = output.lock {
                    self.outputs.entry(address).or_default().insert(OutPoint {
                        txid,
                        index: position as u32,
                    });
                }
            }
        }
        consistent
    }

    pub fn outputs(&self, address: &[u8; 32]) -> impl Iterator<Item = &OutPoint> {
        self.outputs.get(address).into_iter().flatten()
    }
}
