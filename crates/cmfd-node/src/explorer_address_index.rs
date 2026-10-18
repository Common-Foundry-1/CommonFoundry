//! Public-chain address metadata, independent of private exchange watch lists.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, btree_map};
use std::ops::Bound;

use cmfd_consensus::{
    Block, InputWitness, MAX_COINBASE_OUTPUTS, MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS,
    OutPoint, OutputLock, Transaction, TxInput, TxOutput, UtxoSet,
};

use crate::BlockIndex;

// The wire and consensus shape limits keep a valid block's per-transaction
// counts within u16 (see `saturating_count` for a damaged local record).
const _: () = assert!(
    MAX_TRANSACTION_INPUTS <= u16::MAX as usize
        && MAX_TRANSACTION_OUTPUTS <= u16::MAX as usize
        && MAX_COINBASE_OUTPUTS <= u16::MAX as usize
);
// The kind's niche keeps a hint slot as small as a derived one.
const _: () = assert!(std::mem::size_of::<Option<AddressActivity>>() == 64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct AddressLocation {
    pub height: u64,
    /// Zero is coinbase; ordinary transaction positions are one-based here.
    pub position: usize,
    pub block_id: [u8; 32],
}

/// What one transaction (or the coinbase) did for one key. The byte values
/// are the startup index cache encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActivityKind {
    Coinbase = 0,
    Received = 1,
    Sent = 2,
    SelfTransfer = 3,
}

impl ActivityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Coinbase => "coinbase",
            Self::Received => "received",
            Self::Sent => "sent",
            Self::SelfTransfer => "self",
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Coinbase),
            1 => Some(Self::Received),
            2 => Some(Self::Sent),
            3 => Some(Self::SelfTransfer),
            _ => None,
        }
    }
}

/// The facts an address page shows for one entry, derived from a validated or
/// authenticated block when it is indexed. They depend only on the block, the
/// position and the key, so a reorganization never changes them; pages still
/// check active-chain membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AddressActivity {
    pub txid: [u8; 32],
    pub received_atoms: u128,
    pub timestamp: u64,
    pub received_outputs: u16,
    pub spent_inputs: u16,
    pub kind: ActivityKind,
}

/// One indexed entry: the key, where it was active and what happened there.
pub(super) type AddressEntry = ([u8; 32], AddressLocation, AddressActivity);

/// What [`AddressHistoryIndex::fill_block`] changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct FillReport {
    /// Hint entries that received their facts.
    pub filled: usize,
    /// Entries that disagreed with their block and were corrected or removed.
    pub repaired: usize,
}

/// How the transaction at `position` (zero is the coinbase) touched
/// `address`: its kind, the atoms and outputs it paid the key and the key
/// inputs it spent; `None` when it did not touch the key.
///
/// Any change to these rules, or to the facts layout in the startup index
/// cache, must bump the cache's `INDEX_VERSION`.
pub(super) fn derive_activity(
    address: [u8; 32],
    position: usize,
    inputs: &[TxInput],
    outputs: &[TxOutput],
) -> Option<(ActivityKind, u128, usize, usize)> {
    // Consensus validation requires this key to own the spent key output.
    // Channel settlement/refund witnesses are not key inputs.
    let spent = inputs
        .iter()
        .filter(|input| matches!(input.witness, InputWitness::Key { public_key, .. } if public_key == address))
        .count();
    let mut received_atoms = 0_u128;
    let mut received = 0;
    for output in outputs {
        if output.lock == OutputLock::Key(address) {
            received_atoms += u128::from(output.value);
            received += 1;
        }
    }
    classify(position, spent, received, inputs.len(), outputs.len())
        .map(|kind| (kind, received_atoms, received, spent))
}

/// A per-transaction count as stored. Validated blocks stay far below the
/// limit; a locally damaged pruned record (whose coinbase has no wire cap)
/// saturates instead of panicking, and the cache loader refuses the row.
pub(super) fn saturating_count(count: usize) -> u16 {
    u16::try_from(count).unwrap_or(u16::MAX)
}

/// The kind rule behind [`derive_activity`]; block indexing applies it to the
/// counts it gathers for every key in one pass.
fn classify(
    position: usize,
    spent: usize,
    received: usize,
    inputs: usize,
    outputs: usize,
) -> Option<ActivityKind> {
    if spent == 0 && received == 0 {
        return None;
    }
    Some(if position == 0 {
        ActivityKind::Coinbase
    } else if spent > 0 && received > 0 && spent == inputs && received == outputs {
        ActivityKind::SelfTransfer
    } else if spent > 0 {
        ActivityKind::Sent
    } else {
        ActivityKind::Received
    })
}

#[derive(Debug, Default)]
pub(super) struct AddressHistoryIndex {
    /// `None` is a hint: a location loaded from an older index cache whose
    /// facts are not derived yet. A page that reaches it reads and
    /// authenticates its block, and the history scrub fills it.
    locations: HashMap<[u8; 32], BTreeMap<AddressLocation, Option<AddressActivity>>>,
}

impl AddressHistoryIndex {
    #[cfg(test)]
    pub(super) fn qualification_shape(&self) -> (usize, usize) {
        (
            self.locations.len(),
            self.locations.values().map(BTreeMap::len).sum(),
        )
    }

    pub fn block_entries(block: &Block) -> Vec<AddressEntry> {
        Self::entries_for(
            block.block_id(),
            block.challenge.height,
            block.challenge.timestamp,
            block.challenge.network_id,
            &block.coinbase.outputs,
            &block.transactions,
        )
    }

    pub fn stored_block_entries(block: &crate::StoredBlock) -> Vec<AddressEntry> {
        Self::entries_for(
            block.block_id(),
            block.challenge.height,
            block.challenge.timestamp,
            block.challenge.network_id,
            &block.coinbase.outputs,
            &block.transactions,
        )
    }

    fn entries_for(
        block_id: [u8; 32],
        height: u64,
        timestamp: u64,
        network_id: [u8; 32],
        coinbase_outputs: &[TxOutput],
        transactions: &[Transaction],
    ) -> Vec<AddressEntry> {
        let mut entries = Vec::new();
        let coinbase = (
            0,
            cmfd_consensus::coinbase_outpoint_id(network_id, block_id),
            &[][..],
            coinbase_outputs,
        );
        for (position, txid, inputs, outputs) in
            std::iter::once(coinbase).chain(transactions.iter().enumerate().map(|(index, tx)| {
                (
                    index + 1,
                    tx.txid(),
                    tx.inputs.as_slice(),
                    tx.outputs.as_slice(),
                )
            }))
        {
            // (received atoms, received outputs, spent inputs) per key, in
            // key order: the counts derive_activity takes for each key.
            let mut touched = BTreeMap::<[u8; 32], (u128, usize, usize)>::new();
            for output in outputs {
                if let OutputLock::Key(address) = output.lock {
                    let counts = touched.entry(address).or_default();
                    counts.0 += u128::from(output.value);
                    counts.1 += 1;
                }
            }
            // Consensus validation requires this key to own the spent key
            // output. Channel settlement/refund witnesses are not key outputs.
            for input in inputs {
                if let InputWitness::Key { public_key, .. } = input.witness {
                    touched.entry(public_key).or_default().2 += 1;
                }
            }
            let location = AddressLocation {
                height,
                position,
                block_id,
            };
            entries.extend(touched.into_iter().filter_map(
                |(address, (received_atoms, received, spent))| {
                    let kind = classify(position, spent, received, inputs.len(), outputs.len())?;
                    Some((
                        address,
                        location,
                        AddressActivity {
                            txid,
                            received_atoms,
                            timestamp,
                            received_outputs: saturating_count(received),
                            spent_inputs: saturating_count(spent),
                            kind,
                        },
                    ))
                },
            ));
        }
        entries
    }

    /// Every entry with its facts (`None` for a hint), for the startup index
    /// cache.
    pub fn entries(
        &self,
    ) -> impl Iterator<Item = ([u8; 32], AddressLocation, Option<AddressActivity>)> + '_ {
        self.locations.iter().flat_map(|(address, locations)| {
            locations
                .iter()
                .map(move |(location, activity)| (*address, *location, *activity))
        })
    }

    pub fn entry_count(&self) -> usize {
        self.locations.values().map(BTreeMap::len).sum()
    }

    /// Stores entries derived from a validated or authenticated block,
    /// replacing whatever the index held for those locations.
    pub fn insert_block_entries(&mut self, entries: impl IntoIterator<Item = AddressEntry>) {
        for (address, location, activity) in entries {
            self.locations
                .entry(address)
                .or_default()
                .insert(location, Some(activity));
        }
    }

    /// Adds hint entries, locations without facts. A location already present
    /// keeps what it has.
    pub fn insert_entries(
        &mut self,
        entries: impl IntoIterator<Item = ([u8; 32], AddressLocation)>,
    ) {
        for (address, location) in entries {
            self.locations
                .entry(address)
                .or_default()
                .entry(location)
                .or_insert(None);
        }
    }

    pub fn contains(&self, address: &[u8; 32], location: AddressLocation) -> bool {
        self.locations
            .get(address)
            .is_some_and(|locations| locations.contains_key(&location))
    }

    /// Heights of active-chain blocks that pay or spend this key, ascending.
    /// A block that touches the key in several transactions repeats its height.
    pub fn active_heights<'a>(
        &'a self,
        address: &[u8; 32],
        chain: &'a BlockIndex,
    ) -> impl Iterator<Item = u64> + 'a {
        self.locations
            .get(address)
            .into_iter()
            .flat_map(BTreeMap::keys)
            .filter(|location| {
                chain.active_position(location.block_id) == usize::try_from(location.height).ok()
            })
            .map(|location| location.height)
    }

    #[cfg(test)]
    pub fn page(
        &self,
        address: &[u8; 32],
        chain: &BlockIndex,
        before: Option<AddressLocation>,
        limit: usize,
    ) -> Vec<AddressLocation> {
        self.page_entries(address, chain, before, limit)
            .into_iter()
            .map(|(location, _)| location)
            .collect()
    }

    /// Active-chain entries before `before`, newest first, with their facts
    /// (`None` for a hint).
    pub fn page_entries(
        &self,
        address: &[u8; 32],
        chain: &BlockIndex,
        before: Option<AddressLocation>,
        limit: usize,
    ) -> Vec<(AddressLocation, Option<AddressActivity>)> {
        let Some(locations) = self.locations.get(address) else {
            return Vec::new();
        };
        let end = before.map_or(Bound::Unbounded, Bound::Excluded);
        locations
            .range((Bound::Unbounded, end))
            .rev()
            .filter(|(location, _)| chain.active_position(location.block_id).is_some())
            .take(limit)
            .map(|(location, activity)| (*location, *activity))
            .collect()
    }

    /// Keeps only the entries in blocks `keep` accepts, for a prune that
    /// dropped blocks from the fork index.
    pub fn retain_blocks(&mut self, keep: impl Fn(&[u8; 32]) -> bool) {
        self.locations.retain(|_, locations| {
            locations.retain(|location, _| keep(&location.block_id));
            !locations.is_empty()
        });
    }

    /// Whether any hint entry names a block that `retained` accepts.
    pub fn has_hints_in(&self, retained: impl Fn(&[u8; 32]) -> bool) -> bool {
        self.locations
            .values()
            .flat_map(BTreeMap::iter)
            .any(|(location, activity)| activity.is_none() && retained(&location.block_id))
    }

    /// Hint entries grouped by block.
    pub fn hint_blocks(&self) -> HashMap<[u8; 32], Vec<([u8; 32], AddressLocation)>> {
        let mut blocks: HashMap<[u8; 32], Vec<([u8; 32], AddressLocation)>> = HashMap::new();
        for (address, locations) in &self.locations {
            for (location, activity) in locations {
                if activity.is_none() {
                    blocks
                        .entry(location.block_id)
                        .or_default()
                        .push((*address, *location));
                }
            }
        }
        blocks
    }

    /// Stores the entries `recomputed` from one authenticated block: a hint
    /// gets its facts (`filled`), and a missing entry or one with different
    /// facts is replaced (`repaired`). Then each `stale` entry of that block
    /// the block does not show is removed (`repaired`). Equal facts change
    /// nothing.
    pub fn fill_block(
        &mut self,
        stale: &[([u8; 32], AddressLocation)],
        recomputed: Vec<AddressEntry>,
    ) -> FillReport {
        let mut report = FillReport::default();
        let mut shown = BTreeSet::new();
        for (address, location, activity) in recomputed {
            shown.insert((address, location));
            match self.locations.entry(address).or_default().entry(location) {
                btree_map::Entry::Occupied(mut slot) => match *slot.get() {
                    None => {
                        slot.insert(Some(activity));
                        report.filled += 1;
                    }
                    Some(existing) if existing == activity => {}
                    Some(_) => {
                        slot.insert(Some(activity));
                        report.repaired += 1;
                    }
                },
                btree_map::Entry::Vacant(slot) => {
                    slot.insert(Some(activity));
                    report.repaired += 1;
                }
            }
        }
        for (address, location) in stale {
            if shown.contains(&(*address, *location)) {
                continue;
            }
            if let Some(locations) = self.locations.get_mut(address) {
                if locations.remove(location).is_some() {
                    report.repaired += 1;
                }
                if locations.is_empty() {
                    self.locations.remove(address);
                }
            }
        }
        report
    }

    /// Turns every entry into a hint, as an older index cache would load it.
    #[cfg(test)]
    pub(super) fn forget_facts(&mut self) {
        for locations in self.locations.values_mut() {
            for activity in locations.values_mut() {
                *activity = None;
            }
        }
    }
}

/// Only active key-output identifiers are cached. Amounts and maturity always
/// come from the live consensus UTXO set, not a second balance ledger.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct AddressOutputIndex {
    outputs: HashMap<[u8; 32], HashSet<OutPoint>>,
}

impl AddressOutputIndex {
    /// Only the synthetic, metadata-only operator probe uses this. No output
    /// value or consensus state is constructed or made authoritative here.
    #[cfg(test)]
    pub(super) fn insert_qualification_output(&mut self, address: [u8; 32], outpoint: OutPoint) {
        self.outputs.entry(address).or_default().insert(outpoint);
    }

    #[cfg(test)]
    pub(super) fn qualification_shape(&self) -> (usize, usize) {
        (
            self.outputs.len(),
            self.outputs.values().map(HashSet::len).sum(),
        )
    }

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

#[cfg(test)]
mod tests {
    use cmfd_consensus::TRANSACTION_VERSION;
    use cmfd_marketplace::ChannelTerms;

    use super::*;

    const KEY: [u8; 32] = [0xa1; 32];
    const OTHER: [u8; 32] = [0xb2; 32];

    fn output(lock: OutputLock, value: u64) -> TxOutput {
        TxOutput {
            value,
            lock,
            spendable_height: 1,
        }
    }

    fn key_input(public_key: [u8; 32], index: u32) -> TxInput {
        TxInput {
            previous: OutPoint {
                txid: [0x55; 32],
                index,
            },
            witness: InputWitness::Key {
                public_key,
                signature: Vec::new(),
            },
        }
    }

    fn refund_input(customer_key: [u8; 32]) -> TxInput {
        TxInput {
            previous: OutPoint {
                txid: [0x66; 32],
                index: 0,
            },
            witness: InputWitness::InferenceRefund {
                terms: ChannelTerms {
                    network_id: [0; 32],
                    job_id: [1; 32],
                    customer_key,
                    provider_key: OTHER,
                    model_digest: [2; 32],
                    runtime_digest: [3; 32],
                    input_digest: [4; 32],
                    deposit: 100,
                    close_fee_burn: 1,
                    base_price: 1,
                    input_price_per_1000: 1,
                    output_price_per_1000: 1,
                    max_input_tokens: 1,
                    max_output_tokens: 1,
                    output_chunk_tokens: 1,
                    refund_height: 1,
                },
            },
        }
    }

    #[test]
    fn coinbase_outputs_to_the_key_are_one_coinbase_entry() {
        let outputs = [
            output(OutputLock::Key(KEY), 7),
            output(OutputLock::Key(OTHER), 5),
            output(OutputLock::Key(KEY), 3),
        ];
        assert_eq!(
            derive_activity(KEY, 0, &[], &outputs),
            Some((ActivityKind::Coinbase, 10, 2, 0))
        );
    }

    #[test]
    fn a_payment_with_change_is_sent_and_counts_the_change() {
        let inputs = [key_input(KEY, 0), key_input(KEY, 1)];
        let outputs = [
            output(OutputLock::Key(OTHER), 90),
            output(OutputLock::Key(KEY), 10),
        ];
        assert_eq!(
            derive_activity(KEY, 1, &inputs, &outputs),
            Some((ActivityKind::Sent, 10, 1, 2))
        );
        assert_eq!(
            derive_activity(OTHER, 1, &inputs, &outputs),
            Some((ActivityKind::Received, 90, 1, 0))
        );
        // Spending only some of the inputs is not a self transfer either.
        let mixed = [key_input(KEY, 0), key_input(OTHER, 1)];
        let own = [output(OutputLock::Key(KEY), 10)];
        assert_eq!(
            derive_activity(KEY, 1, &mixed, &own),
            Some((ActivityKind::Sent, 10, 1, 1))
        );
    }

    #[test]
    fn only_all_own_inputs_and_outputs_are_a_self_transfer() {
        let inputs = [key_input(KEY, 0)];
        let outputs = [
            output(OutputLock::Key(KEY), 4),
            output(OutputLock::Key(KEY), 5),
        ];
        assert_eq!(
            derive_activity(KEY, 3, &inputs, &outputs),
            Some((ActivityKind::SelfTransfer, 9, 2, 1))
        );
    }

    #[test]
    fn channel_escrow_and_channel_witnesses_are_not_key_activity() {
        // Funding a channel from the key: the escrow output is not the key's.
        let inputs = [key_input(KEY, 0)];
        let escrow = [output(
            OutputLock::InferenceChannel {
                channel_id: [0x77; 32],
            },
            50,
        )];
        assert_eq!(
            derive_activity(KEY, 1, &inputs, &escrow),
            Some((ActivityKind::Sent, 0, 0, 1))
        );
        assert_eq!(derive_activity([0x77; 32], 1, &inputs, &escrow), None);
        // A refund names the customer in its terms but spends no key output.
        let refund = [refund_input(KEY)];
        let paid = [output(OutputLock::Key(KEY), 49)];
        assert_eq!(
            derive_activity(KEY, 1, &refund, &paid),
            Some((ActivityKind::Received, 49, 1, 0))
        );
        assert_eq!(derive_activity(KEY, 1, &refund, &escrow), None);
    }

    #[test]
    fn a_transaction_that_does_not_touch_the_key_has_no_activity() {
        let inputs = [key_input(OTHER, 0)];
        let outputs = [output(OutputLock::Key(OTHER), 9)];
        assert_eq!(derive_activity(KEY, 1, &inputs, &outputs), None);
        assert_eq!(derive_activity(KEY, 0, &[], &outputs), None);
    }

    #[test]
    fn block_indexing_matches_derive_activity_for_every_key() {
        let transactions = vec![
            Transaction {
                network_id: [9; 32],
                version: TRANSACTION_VERSION,
                // The key spends two inputs and is paid twice, so its counts
                // and atoms must add up, not keep the last one.
                inputs: vec![key_input(KEY, 0), key_input(OTHER, 1), key_input(KEY, 2)],
                outputs: vec![
                    output(OutputLock::Key(OTHER), 30),
                    output(OutputLock::Key(KEY), 20),
                    output(OutputLock::Key([0xc3; 32]), 10),
                    output(OutputLock::Key(KEY), 7),
                    output(
                        OutputLock::InferenceChannel {
                            channel_id: [0x77; 32],
                        },
                        5,
                    ),
                ],
            },
            Transaction {
                network_id: [9; 32],
                version: TRANSACTION_VERSION,
                inputs: vec![refund_input(KEY)],
                outputs: vec![output(OutputLock::Key(KEY), 4)],
            },
        ];
        let coinbase = vec![
            output(OutputLock::Key(KEY), 50),
            output(OutputLock::Key(OTHER), 25),
            output(OutputLock::Key(KEY), 3),
        ];
        let entries = AddressHistoryIndex::entries_for(
            [0xee; 32],
            7,
            1_234,
            [9; 32],
            &coinbase,
            &transactions,
        );
        assert_eq!(entries.len(), 2 + 3 + 1);
        for (address, location, activity) in &entries {
            assert_eq!(location.block_id, [0xee; 32]);
            assert_eq!(location.height, 7);
            assert_eq!(activity.timestamp, 1_234);
            let (txid, inputs, outputs) = match location.position {
                0 => (
                    cmfd_consensus::coinbase_outpoint_id([9; 32], [0xee; 32]),
                    &[][..],
                    coinbase.as_slice(),
                ),
                position => {
                    let tx = &transactions[position - 1];
                    (tx.txid(), tx.inputs.as_slice(), tx.outputs.as_slice())
                }
            };
            assert_eq!(activity.txid, txid);
            let (kind, atoms, received, spent) =
                derive_activity(*address, location.position, inputs, outputs).unwrap();
            assert_eq!(
                (
                    activity.kind,
                    activity.received_atoms,
                    usize::from(activity.received_outputs),
                    usize::from(activity.spent_inputs)
                ),
                (kind, atoms, received, spent)
            );
        }
        let key_rows: Vec<_> = entries
            .iter()
            .filter(|(address, _, _)| *address == KEY)
            .map(|(_, location, activity)| {
                (
                    location.position,
                    activity.kind,
                    activity.received_atoms,
                    activity.received_outputs,
                    activity.spent_inputs,
                )
            })
            .collect();
        assert_eq!(
            key_rows,
            [
                (0, ActivityKind::Coinbase, 53, 2, 0),
                (1, ActivityKind::Sent, 27, 2, 2),
                (2, ActivityKind::Received, 4, 1, 0),
            ]
        );
    }

    #[test]
    fn filling_a_block_fills_hints_repairs_disagreements_and_drops_stale_hints() {
        let location = |position| AddressLocation {
            height: 3,
            position,
            block_id: [3; 32],
        };
        let facts = |atoms| AddressActivity {
            txid: [8; 32],
            received_atoms: atoms,
            timestamp: 60,
            received_outputs: 1,
            spent_inputs: 0,
            kind: ActivityKind::Received,
        };
        let mut index = AddressHistoryIndex::default();
        index.insert_block_entries([(OTHER, location(2), facts(5))]);
        index.insert_entries([(KEY, location(1)), ([0xc3; 32], location(1))]);
        // A hint never displaces derived facts.
        index.insert_entries([(OTHER, location(2))]);
        assert_eq!(index.hint_blocks()[&[3; 32]].len(), 2);
        let stale = index.hint_blocks().remove(&[3; 32]).unwrap();

        let recomputed = vec![
            (KEY, location(1), facts(1)),
            (OTHER, location(2), facts(5)),
            (OTHER, location(3), facts(6)),
        ];
        let report = index.fill_block(&stale, recomputed.clone());
        assert_eq!(
            report,
            FillReport {
                filled: 1,
                // The entry the index lacked, and the stale hint.
                repaired: 2,
            }
        );
        assert!(index.hint_blocks().is_empty());
        assert!(!index.contains(&[0xc3; 32], location(1)));
        assert!(!index.locations.contains_key(&[0xc3; 32]));
        assert_eq!(index.entry_count(), 3);
        // Refilling with the same facts changes nothing.
        assert_eq!(index.fill_block(&[], recomputed), FillReport::default());
        // Different facts are corrected.
        assert_eq!(
            index.fill_block(&[], vec![(OTHER, location(2), facts(4))]),
            FillReport {
                filled: 0,
                repaired: 1
            }
        );
        index.forget_facts();
        assert_eq!(index.hint_blocks()[&[3; 32]].len(), 3);
    }

    #[test]
    fn retaining_blocks_drops_only_the_other_blocks_entries_and_hints() {
        let location = |block: u8| AddressLocation {
            height: 3,
            position: 0,
            block_id: [block; 32],
        };
        let facts = AddressActivity {
            txid: [8; 32],
            received_atoms: 5,
            timestamp: 60,
            received_outputs: 1,
            spent_inputs: 0,
            kind: ActivityKind::Coinbase,
        };
        let mut index = AddressHistoryIndex::default();
        index.insert_block_entries([(KEY, location(1), facts), (OTHER, location(2), facts)]);
        index.insert_entries([(KEY, location(2)), ([0xc3; 32], location(1))]);
        index.retain_blocks(|block_id| *block_id == [2; 32]);
        assert!(!index.locations.contains_key(&[0xc3; 32]));
        assert_eq!(index.entry_count(), 2);
        assert!(index.contains(&KEY, location(2)));
        assert!(index.contains(&OTHER, location(2)));
        assert!(!index.contains(&KEY, location(1)));
        assert!(!index.has_hints_in(|block_id| *block_id == [1; 32]));
    }
}
