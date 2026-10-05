//! Confirmed wallet history that is scanned once and then extended with only
//! the blocks appended since the previous wallet snapshot.
//!
//! The desktop wallet refreshes its snapshot every few seconds. Rebuilding the
//! history from the first block on every refresh re-reads and re-authenticates
//! the whole block log under the node lock, which starves block sync on the
//! same machine. This cache keeps the scan position, the output view the scan
//! needs to attribute spent inputs, and the newest entries. The blocks nearest
//! the scanned tip stay individually undoable, so ordinary tip reorgs roll back
//! without a rescan; only a reorg below that window rebuilds the cache.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use cmfd_consensus::{Block, OutPoint, OutputLock, TxOutput};

use crate::{
    IndexedBlock, MAX_WALLET_HISTORY, NodeError, WalletHistoryEntry, checked_wallet_add, io_error,
    read_indexed_block, signed_wallet_delta,
};

/// Scanned blocks nearest the tip that stay individually undoable.
const UNDO_DEPTH: usize = 256;
/// Unscanned block-log records beyond this many bytes (about 16 full mainnet
/// blocks, roughly one sync session) are read on a background thread, so one
/// wallet snapshot never holds the node lock for a whole-chain read.
pub(crate) const INLINE_SCAN_BYTES: u64 = 192 * 1024 * 1024;

/// One block the scan still has to read: active-chain position, the active
/// block identifier at that position and the authenticated record locator.
pub(crate) type ScanTarget = (usize, [u8; 32], Arc<IndexedBlock>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedEntry {
    kind: &'static str,
    txid: String,
    height: u64,
    timestamp: u64,
    /// Highest spendable height among the wallet outputs this entry credits.
    /// The entry reads as `immature` until the chain reaches it.
    wallet_spendable_height: u64,
    net_amount_atoms: String,
    fee_burned_atoms: String,
    counterparty: Option<String>,
}

impl CachedEntry {
    fn render(&self, accepted_height: u64, next_height: u64) -> WalletHistoryEntry {
        WalletHistoryEntry {
            kind: self.kind,
            txid: self.txid.clone(),
            height: Some(self.height),
            timestamp: Some(self.timestamp),
            confirmations: accepted_height
                .saturating_sub(self.height)
                .saturating_add(1),
            status: if next_height < self.wallet_spendable_height {
                "immature"
            } else {
                "confirmed"
            },
            net_amount_atoms: self.net_amount_atoms.clone(),
            fee_burned_atoms: self.fee_burned_atoms.clone(),
            counterparty: self.counterparty.clone(),
        }
    }
}

#[derive(Debug, Clone)]
enum OutputChange {
    Inserted {
        outpoint: OutPoint,
        previous: Option<TxOutput>,
    },
    Removed {
        outpoint: OutPoint,
        output: TxOutput,
    },
}

#[derive(Debug, Clone)]
struct ScannedBlock {
    position: usize,
    block_id: [u8; 32],
    entries: Vec<CachedEntry>,
    changes: Vec<OutputChange>,
}

#[derive(Debug, Clone)]
pub(crate) struct WalletHistoryCache {
    destination: [u8; 32],
    /// Outputs the scan has seen and not yet seen spent, as of the scanned tip.
    outputs: HashMap<OutPoint, TxOutput>,
    /// Last block folded below the undo window; virtual genesis at first.
    folded_position: usize,
    folded_block_id: [u8; 32],
    /// Newest entries from folded blocks, oldest first.
    folded_entries: VecDeque<CachedEntry>,
    /// Scanned blocks above the fold, oldest first, each still undoable.
    window: VecDeque<ScannedBlock>,
    undo_depth: usize,
    #[cfg(test)]
    blocks_read: u64,
}

impl WalletHistoryCache {
    pub(crate) fn new(destination: [u8; 32], genesis: [u8; 32]) -> Self {
        Self {
            destination,
            outputs: HashMap::new(),
            folded_position: 0,
            folded_block_id: genesis,
            folded_entries: VecDeque::new(),
            window: VecDeque::new(),
            undo_depth: UNDO_DEPTH,
            #[cfg(test)]
            blocks_read: 0,
        }
    }

    pub(crate) fn destination(&self) -> [u8; 32] {
        self.destination
    }

    /// Active-chain position of the last scanned block.
    pub(crate) fn scanned_position(&self) -> usize {
        self.window
            .back()
            .map_or(self.folded_position, |scanned| scanned.position)
    }

    #[cfg(test)]
    pub(crate) fn blocks_read(&self) -> u64 {
        self.blocks_read
    }

    #[cfg(test)]
    pub(crate) fn set_undo_depth(&mut self, depth: usize) {
        self.undo_depth = depth.max(1);
        while self.window.len() > self.undo_depth {
            self.fold_oldest();
        }
    }

    /// Undoes scanned blocks the active chain no longer contains. Returns
    /// `false` when the chain diverged below the undo window and the cache has
    /// to be rebuilt from genesis.
    pub(crate) fn rewind_to(&mut self, active_chain: &[[u8; 32]]) -> bool {
        if active_chain.get(self.folded_position) != Some(&self.folded_block_id) {
            return false;
        }
        while let Some(back) = self.window.back() {
            if active_chain.get(back.position) == Some(&back.block_id) {
                break;
            }
            let scanned = self
                .window
                .pop_back()
                .expect("window back was just observed");
            for change in scanned.changes.into_iter().rev() {
                match change {
                    OutputChange::Inserted { outpoint, previous } => match previous {
                        Some(previous) => {
                            self.outputs.insert(outpoint, previous);
                        }
                        None => {
                            self.outputs.remove(&outpoint);
                        }
                    },
                    OutputChange::Removed { outpoint, output } => {
                        self.outputs.insert(outpoint, output);
                    }
                }
            }
        }
        true
    }

    fn fold_oldest(&mut self) {
        let Some(oldest) = self.window.pop_front() else {
            return;
        };
        for entry in oldest.entries {
            if self.folded_entries.len() == MAX_WALLET_HISTORY {
                self.folded_entries.pop_front();
            }
            self.folded_entries.push_back(entry);
        }
        self.folded_position = oldest.position;
        self.folded_block_id = oldest.block_id;
    }

    /// Scans the next active block. The attribution rules match a full scan of
    /// the chain exactly; only confirmations and maturity are left to read time.
    fn extend(
        &mut self,
        position: usize,
        block_id: [u8; 32],
        block: &Block,
    ) -> Result<(), NodeError> {
        if position != self.scanned_position() + 1 {
            return Err(NodeError::CorruptLog(
                "wallet history scan did not continue at the next active block".to_owned(),
            ));
        }
        let destination = self.destination;
        let height = block.challenge.height;
        let timestamp = block.challenge.timestamp;
        let mut entries = Vec::new();
        let mut changes = Vec::new();

        let coinbase_txid = block.coinbase_outpoint_id();
        let mut mined = 0_u64;
        let mut mined_spendable_height = 0_u64;
        for (index, output) in block.coinbase.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid: coinbase_txid,
                index: index as u32,
            };
            if output.lock == OutputLock::Key(destination) {
                mined = checked_wallet_add(mined, output.value)?;
                mined_spendable_height = mined_spendable_height.max(output.spendable_height);
            }
            let previous = self.outputs.insert(outpoint, output.clone());
            changes.push(OutputChange::Inserted { outpoint, previous });
        }
        if mined > 0 {
            entries.push(CachedEntry {
                kind: "mined",
                txid: hex::encode(coinbase_txid),
                height,
                timestamp,
                wallet_spendable_height: mined_spendable_height,
                net_amount_atoms: mined.to_string(),
                fee_burned_atoms: "0".to_owned(),
                counterparty: None,
            });
        }

        for transaction in &block.transactions {
            let mut input_total = 0_u64;
            let mut wallet_inputs = 0_u64;
            let mut source = None;
            for input in &transaction.inputs {
                let previous = self.outputs.remove(&input.previous).ok_or_else(|| {
                    NodeError::CorruptLog(
                        "active wallet history transaction refers to an absent output".to_owned(),
                    )
                })?;
                input_total = checked_wallet_add(input_total, previous.value)?;
                match previous.lock {
                    OutputLock::Key(owner) if owner == destination => {
                        wallet_inputs = checked_wallet_add(wallet_inputs, previous.value)?;
                    }
                    OutputLock::Key(owner) if source.is_none() => {
                        source = Some(hex::encode(owner));
                    }
                    _ => {}
                }
                changes.push(OutputChange::Removed {
                    outpoint: input.previous,
                    output: previous,
                });
            }
            let txid = transaction.txid();
            let mut output_total = 0_u64;
            let mut wallet_outputs = 0_u64;
            let mut wallet_spendable_height = 0_u64;
            let mut recipient = None;
            for (index, output) in transaction.outputs.iter().enumerate() {
                output_total = checked_wallet_add(output_total, output.value)?;
                match output.lock {
                    OutputLock::Key(owner) if owner == destination => {
                        wallet_outputs = checked_wallet_add(wallet_outputs, output.value)?;
                        wallet_spendable_height =
                            wallet_spendable_height.max(output.spendable_height);
                    }
                    OutputLock::Key(owner) if recipient.is_none() => {
                        recipient = Some(hex::encode(owner));
                    }
                    _ => {}
                }
                let outpoint = OutPoint {
                    txid,
                    index: index as u32,
                };
                let previous = self.outputs.insert(outpoint, output.clone());
                changes.push(OutputChange::Inserted { outpoint, previous });
            }
            let fee_burned = input_total.checked_sub(output_total).ok_or_else(|| {
                NodeError::CorruptLog("active wallet history transaction creates value".to_owned())
            })?;
            let (kind, counterparty) = if wallet_inputs > 0 {
                ("sent", recipient)
            } else if wallet_outputs > 0 {
                ("received", source)
            } else {
                continue;
            };
            entries.push(CachedEntry {
                kind,
                txid: hex::encode(txid),
                height,
                timestamp,
                wallet_spendable_height,
                net_amount_atoms: signed_wallet_delta(wallet_outputs, wallet_inputs),
                fee_burned_atoms: fee_burned.to_string(),
                counterparty,
            });
        }

        self.window.push_back(ScannedBlock {
            position,
            block_id,
            entries,
            changes,
        });
        while self.window.len() > self.undo_depth {
            self.fold_oldest();
        }
        Ok(())
    }

    /// The newest `limit` entries in chain order, with confirmations and
    /// maturity evaluated against the current tip.
    pub(crate) fn history(
        &self,
        accepted_height: u64,
        next_height: u64,
        limit: usize,
    ) -> Vec<WalletHistoryEntry> {
        let mut newest = Vec::with_capacity(limit.min(MAX_WALLET_HISTORY));
        let window_entries = self
            .window
            .iter()
            .rev()
            .flat_map(|scanned| scanned.entries.iter().rev());
        for entry in window_entries.chain(self.folded_entries.iter().rev()) {
            if newest.len() == limit {
                break;
            }
            newest.push(entry);
        }
        newest.reverse();
        newest
            .into_iter()
            .map(|entry| entry.render(accepted_height, next_height))
            .collect()
    }
}

/// Reads and scans `targets` in order. Stops early, successfully, once `stop`
/// is raised; the caller then discards the partially extended cache.
pub(crate) fn scan(
    cache: &mut WalletHistoryCache,
    log: &File,
    log_path: &Path,
    network_id: [u8; 32],
    require_v2: bool,
    targets: &[ScanTarget],
    stop: Option<&AtomicBool>,
) -> Result<(), NodeError> {
    for (position, block_id, indexed) in targets {
        if stop.is_some_and(|stop| stop.load(Ordering::Relaxed)) {
            return Ok(());
        }
        let block = read_indexed_block(log, log_path, indexed, *block_id, network_id, require_v2)?;
        #[cfg(test)]
        {
            cache.blocks_read += 1;
        }
        cache.extend(*position, *block_id, &block)?;
    }
    Ok(())
}

/// A whole-chain history scan running off the node lock.
#[derive(Debug)]
pub(crate) struct WalletHistoryScan {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<WalletHistoryCache, NodeError>>>,
}

impl WalletHistoryScan {
    pub(crate) fn start(
        mut cache: WalletHistoryCache,
        log: File,
        log_path: PathBuf,
        network_id: [u8; 32],
        require_v2: bool,
        targets: Vec<ScanTarget>,
    ) -> Result<Self, NodeError> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_log_path = log_path.clone();
        let handle = thread::Builder::new()
            .name("cmfd-wallet-history".to_owned())
            .spawn(move || {
                scan(
                    &mut cache,
                    &log,
                    &thread_log_path,
                    network_id,
                    require_v2,
                    &targets,
                    Some(&thread_stop),
                )?;
                Ok(cache)
            })
            .map_err(|source| io_error("start wallet history scan", &log_path, source))?;
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.handle.as_ref().is_some_and(JoinHandle::is_finished)
    }

    pub(crate) fn finish(mut self) -> Result<WalletHistoryCache, NodeError> {
        let handle = self
            .handle
            .take()
            .expect("a wallet history scan is finished at most once");
        match handle.join() {
            Ok(result) => result,
            Err(_) => Err(NodeError::CorruptLog(
                "wallet history scan thread panicked".to_owned(),
            )),
        }
    }
}

impl Drop for WalletHistoryScan {
    /// Stops the scan and waits for its thread, so no reader of the block log
    /// outlives the node that started it (it finishes the block in hand).
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
