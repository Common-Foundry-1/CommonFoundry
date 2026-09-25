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
    pub fn insert_block(&mut self, block_id: [u8; 32], txids: impl IntoIterator<Item = [u8; 32]>) {
        for (transaction_position, txid) in txids.into_iter().enumerate() {
            self.locations
                .entry(txid)
                .or_default()
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
