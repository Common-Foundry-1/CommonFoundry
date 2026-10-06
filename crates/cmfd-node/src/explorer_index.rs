//! Derived lookup metadata for the retained, validated block log.
//!
//! This is not a second chain database or a consensus authority. Live entries
//! come from committed blocks; restart entries come from the existing complete
//! block-log scan, after replay or startup-snapshot validation has succeeded.
//! Keep all fork occurrences and consult active-chain membership at query time,
//! so a reorganization cannot leave a transaction falsely confirmed.

use std::collections::HashMap;

use crate::BlockIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TransactionLocation {
    pub block_id: [u8; 32],
    pub transaction_position: usize,
}

#[derive(Debug, Default)]
pub(super) struct TransactionIndex {
    locations: HashMap<[u8; 32], Vec<TransactionLocation>>,
}

impl TransactionIndex {
    #[cfg(test)]
    pub(super) fn qualification_shape(&self) -> (usize, usize, usize) {
        (
            self.locations.len(),
            self.locations.values().map(Vec::len).sum(),
            self.locations.values().map(Vec::capacity).sum(),
        )
    }

    /// Every (txid, location) pair, for the startup index cache.
    pub fn entries(&self) -> impl Iterator<Item = ([u8; 32], TransactionLocation)> + '_ {
        self.locations
            .iter()
            .flat_map(|(txid, locations)| locations.iter().map(move |location| (*txid, *location)))
    }

    pub fn entry_count(&self) -> usize {
        self.locations.values().map(Vec::len).sum()
    }

    pub fn insert_location(&mut self, txid: [u8; 32], location: TransactionLocation) {
        self.locations
            .entry(txid)
            .or_insert_with(|| Vec::with_capacity(1))
            .push(location);
    }

    pub fn insert_block(&mut self, block_id: [u8; 32], txids: impl IntoIterator<Item = [u8; 32]>) {
        for (transaction_position, txid) in txids.into_iter().enumerate() {
            self.locations
                .entry(txid)
                // A new transaction normally has one retained occurrence.
                // Vec's default first push reserves four locations on the
                // supported targets; pay for extra capacity only when a fork
                // actually adds another occurrence. Never discard fork entries.
                .or_insert_with(|| Vec::with_capacity(1))
                .push(TransactionLocation {
                    block_id,
                    transaction_position,
                });
        }
    }

    pub fn active_location(
        &self,
        txid: &[u8; 32],
        chain: &BlockIndex,
    ) -> Option<TransactionLocation> {
        // Most transactions have one occurrence. A transaction present on
        // several forks must resolve to the current canonical occurrence,
        // not whichever block happened to arrive first or last.
        self.locations
            .get(txid)?
            .iter()
            .filter_map(|location| {
                chain
                    .active_position(location.block_id)
                    .map(|height| (height, *location))
            })
            .max_by_key(|(height, _)| *height)
            .map(|(_, location)| location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_transactions_reserve_one_location_and_forks_are_preserved() {
        let first = [1; 32];
        let second = [2; 32];
        let mut index = TransactionIndex::default();
        index.insert_block([0x11; 32], [first, second]);
        for locations in index.locations.values() {
            assert_eq!(locations.len(), 1);
            assert_eq!(locations.capacity(), 1);
        }
        index.insert_block([0x22; 32], [second, first]);
        index.insert_block([0x33; 32], [first]);
        assert_eq!(
            index.locations[&first],
            vec![
                TransactionLocation {
                    block_id: [0x11; 32],
                    transaction_position: 0
                },
                TransactionLocation {
                    block_id: [0x22; 32],
                    transaction_position: 1
                },
                TransactionLocation {
                    block_id: [0x33; 32],
                    transaction_position: 0
                },
            ]
        );
        assert_eq!(index.locations[&second].len(), 2);
    }
}
