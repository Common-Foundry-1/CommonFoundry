//! Rebuildable transaction locations and public address queries. The durable
//! authenticated block log and current chain state remain authoritative.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cmfd_consensus::{Block, OutPoint, OutputLock, Transaction};
use serde_json::{Value, json};

use crate::{BLOCK_LOG_FILE, BlockRecordLocator, Node, NodeError, ProofProfile};

const MAX_LOOKUP_TRANSACTIONS: usize = 5_000_000;
pub(crate) const MAX_UTXO_PAGE: usize = 1_000;

#[derive(Debug, thiserror::Error)]
pub(crate) enum QueryError {
    #[error("active chain changed during the query; retry the read")]
    ChainChanged,
    #[error("transaction lookup index capacity reached")]
    Capacity,
    #[error("available outputs changed; restart UTXO pagination")]
    UtxoSnapshotChanged,
    #[error("UTXO cursor outpoint is not in this snapshot")]
    InvalidUtxoCursor,
    #[error(transparent)]
    Node(#[from] NodeError),
}

#[derive(Default)]
pub(crate) struct TransactionLookupIndex {
    instance: Option<u64>,
    chain: Vec<[u8; 32]>,
    by_block: HashMap<[u8; 32], Vec<[u8; 32]>>,
    locations: HashMap<[u8; 32], [u8; 32]>,
}

struct ReadPlan {
    instance: u64,
    revision: u64,
    chain: Vec<[u8; 32]>,
    log: File,
    path: PathBuf,
    network: [u8; 32],
    require_v2: bool,
    blocks: Vec<([u8; 32], BlockRecordLocator)>,
}

pub(crate) enum TransactionBody {
    Regular(Transaction),
    Coinbase(Block),
}

pub(crate) struct TransactionRead {
    pub body: TransactionBody,
    pub block_id: Option<[u8; 32]>,
    pub height: Option<u64>,
    pub timestamp: Option<u64>,
    pub confirmations: i64,
    pub tip: [u8; 32],
    pub tip_height: u64,
}

impl ReadPlan {
    fn capture(
        node: &Node,
        blocks: Vec<([u8; 32], BlockRecordLocator)>,
    ) -> Result<Self, NodeError> {
        if node.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        Ok(Self {
            instance: node.instance_id,
            revision: node.chain_revision,
            chain: node.index.active_chain.clone(),
            log: node.log.try_clone().map_err(NodeError::RpcIo)?,
            path: node.data_dir.join(BLOCK_LOG_FILE),
            network: node.params.network_id,
            require_v2: matches!(node.profile.proof, ProofProfile::ProductionV3),
            blocks,
        })
    }

    fn read(&self, id: [u8; 32], locator: &BlockRecordLocator) -> Result<Block, NodeError> {
        let (_, block) = crate::read_located_record(
            &self.log,
            &self.path,
            locator,
            self.network,
            self.require_v2,
        )?;
        if block.block_id() != id {
            return Err(NodeError::CorruptLog(
                "transaction lookup block identity mismatch".into(),
            ));
        }
        Ok(block)
    }

    fn recheck(&self, shared: &Arc<Mutex<Node>>) -> Result<(), QueryError> {
        let node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        if node.storage_faulted {
            return Err(NodeError::StorageFaulted.into());
        }
        if node.instance_id != self.instance
            || node.chain_revision != self.revision
            || node.index.active_chain != self.chain
        {
            return Err(QueryError::ChainChanged);
        }
        Ok(())
    }

    fn read_checked(
        &self,
        shared: &Arc<Mutex<Node>>,
        id: [u8; 32],
        locator: &BlockRecordLocator,
    ) -> Result<Block, QueryError> {
        match self.read(id, locator) {
            Ok(block) => Ok(block),
            Err(error) => {
                // Bind off-lock storage failures to the node instance that
                // authorized the retained-file read, just as getblock does.
                if crate::is_authenticated_storage_failure(&error) {
                    let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
                    if node.instance_id == self.instance {
                        node.storage_faulted = true;
                    }
                }
                Err(error.into())
            }
        }
    }
}

impl TransactionLookupIndex {
    fn synchronize(&mut self, shared: &Arc<Mutex<Node>>) -> Result<(), QueryError> {
        let (plan, common) = {
            let node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
            if node.storage_faulted {
                return Err(NodeError::StorageFaulted.into());
            }
            if self.instance != Some(node.instance_id) {
                *self = Self::default();
            }
            if self.chain == node.index.active_chain {
                return Ok(());
            }
            let common = self
                .chain
                .iter()
                .zip(&node.index.active_chain)
                .take_while(|(left, right)| left == right)
                .count();
            let mut blocks = Vec::new();
            for id in node.index.active_chain.iter().skip(common.max(1)) {
                let indexed = node.index.blocks.get(id).ok_or_else(|| {
                    NodeError::CorruptLog("transaction lookup active block absent".into())
                })?;
                blocks.push((*id, indexed.locator));
            }
            (ReadPlan::capture(&node, blocks)?, common)
        };
        let mut added = Vec::new();
        let mut added_count = 0usize;
        for (id, locator) in &plan.blocks {
            let block = plan.read_checked(shared, *id, locator)?;
            let mut ids = vec![block.coinbase_outpoint_id()];
            ids.extend(block.transactions.iter().map(Transaction::txid));
            added_count = added_count
                .checked_add(ids.len())
                .ok_or(QueryError::Capacity)?;
            if self.locations.len().saturating_add(added_count) > MAX_LOOKUP_TRANSACTIONS {
                return Err(QueryError::Capacity);
            }
            added.push((*id, ids));
        }
        plan.recheck(shared)?;
        // Commit only after all records authenticate and the chain is rechecked.
        for id in self.chain.iter().skip(common) {
            if let Some(txids) = self.by_block.remove(id) {
                for txid in txids {
                    self.locations.remove(&txid);
                }
            }
        }
        for (id, txids) in added {
            for txid in &txids {
                self.locations.insert(*txid, id);
            }
            self.by_block.insert(id, txids);
        }
        self.instance = Some(plan.instance);
        self.chain = plan.chain;
        Ok(())
    }

    pub(crate) fn lookup(
        &mut self,
        shared: &Arc<Mutex<Node>>,
        txid: [u8; 32],
        block_hint: Option<[u8; 32]>,
    ) -> Result<Option<TransactionRead>, QueryError> {
        if block_hint.is_none() {
            // Common mempool queries do not need a history scan.
            let node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
            if node.storage_faulted {
                return Err(NodeError::StorageFaulted.into());
            }
            if let Some(entry) = node.mempool.get(&txid) {
                return Ok(Some(TransactionRead {
                    body: TransactionBody::Regular(entry.transaction.clone()),
                    block_id: None,
                    height: None,
                    timestamp: None,
                    confirmations: 0,
                    tip: node.state.tip(),
                    tip_height: node.state.next_height().saturating_sub(1),
                }));
            }
            drop(node);
            self.synchronize(shared)?;
        }
        let plan = {
            let node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
            if node.storage_faulted {
                return Err(NodeError::StorageFaulted.into());
            }
            if block_hint.is_none()
                && (self.instance != Some(node.instance_id)
                    || self.chain != node.index.active_chain)
            {
                return Err(QueryError::ChainChanged);
            }
            let Some(id) = block_hint.or_else(|| self.locations.get(&txid).copied()) else {
                return Ok(None);
            };
            let Some(indexed) = node.index.blocks.get(&id) else {
                return Ok(None);
            };
            ReadPlan::capture(&node, vec![(id, indexed.locator)])?
        };
        let (id, locator) = plan.blocks[0];
        let block = plan.read_checked(shared, id, &locator)?;
        plan.recheck(shared)?;
        let confirmations = plan
            .chain
            .iter()
            .position(|candidate| *candidate == id)
            .map(|position| i64::try_from(plan.chain.len() - position).unwrap_or(i64::MAX))
            .unwrap_or(-1);
        let height = block.challenge.height;
        let timestamp = block.challenge.timestamp;
        let body = if block.coinbase_outpoint_id() == txid {
            TransactionBody::Coinbase(block)
        } else {
            let Some(transaction) = block.transactions.into_iter().find(|tx| tx.txid() == txid)
            else {
                return Ok(None);
            };
            TransactionBody::Regular(transaction)
        };
        Ok(Some(TransactionRead {
            body,
            block_id: Some(id),
            height: Some(height),
            timestamp: Some(timestamp),
            confirmations,
            tip: *plan.chain.last().ok_or(QueryError::ChainChanged)?,
            tip_height: plan.chain.len().saturating_sub(1) as u64,
        }))
    }
}

fn pending_spends(node: &Node) -> HashSet<OutPoint> {
    node.mempool
        .values()
        .flat_map(|entry| entry.transaction.inputs.iter().map(|input| input.previous))
        .collect()
}

pub(crate) struct UtxoCursor {
    pub snapshot: [u8; 32],
    pub after: OutPoint,
}

/// Lists only confirmed outputs that can fund a transaction at the next
/// height. Reading never reserves inputs or changes the wallet/mempool.
pub(crate) fn address_utxos(
    node: &Node,
    destination: [u8; 32],
    limit: usize,
    cursor: Option<UtxoCursor>,
) -> Result<Value, QueryError> {
    if node.storage_faulted {
        return Err(NodeError::StorageFaulted.into());
    }
    let next_height = node.state.next_height();
    let pending = pending_spends(node);
    let mut available: Vec<_> = node
        .state
        .utxos()
        .iter()
        .filter(|(outpoint, output)| {
            output.lock == OutputLock::Key(destination)
                && output.spendable_height <= next_height
                && !pending.contains(outpoint)
                && !node.exchange_withdrawal_reservations.contains_key(outpoint)
        })
        .collect();
    available.sort_unstable_by_key(|(outpoint, _)| (outpoint.txid, outpoint.index));

    // Bind pagination to both chain state and the outputs still available
    // locally. A new pending spend or reservation invalidates old cursors.
    let mut digest = blake3::Hasher::new_derive_key("CMFD/EXCHANGE/ADDRESS_UTXOS/V1");
    digest.update(&node.params.network_id);
    digest.update(&destination);
    digest.update(&node.state.tip());
    digest.update(&next_height.to_le_bytes());
    let mut available_atoms = 0u128;
    for (outpoint, output) in &available {
        digest.update(&outpoint.txid);
        digest.update(&outpoint.index.to_le_bytes());
        digest.update(&output.value.to_le_bytes());
        digest.update(&output.spendable_height.to_le_bytes());
        available_atoms += u128::from(output.value);
    }
    let snapshot = *digest.finalize().as_bytes();
    let start = match cursor {
        None => 0,
        Some(cursor) => {
            if cursor.snapshot != snapshot {
                return Err(QueryError::UtxoSnapshotChanged);
            }
            available
                .binary_search_by_key(&(cursor.after.txid, cursor.after.index), |(outpoint, _)| {
                    (outpoint.txid, outpoint.index)
                })
                .map_err(|_| QueryError::InvalidUtxoCursor)?
                + 1
        }
    };
    let end = start
        .saturating_add(limit.min(MAX_UTXO_PAGE))
        .min(available.len());
    let has_more = end < available.len();
    let next_cursor = if has_more && end > start {
        let (outpoint, _) = available[end - 1];
        Some(
            json!({"snapshot":hex::encode(snapshot), "txid":hex::encode(outpoint.txid), "vout":outpoint.index}),
        )
    } else {
        None
    };
    let destination_hex = hex::encode(destination);
    let utxos: Vec<_> = available[start..end]
        .iter()
        .map(|(outpoint, output)| {
            json!({
                "txid": hex::encode(outpoint.txid),
                "vout": outpoint.index,
                "value_atoms": output.value.to_string(),
                "spendable_height": output.spendable_height,
                "lock_type": "key",
                "destination_hex": destination_hex,
            })
        })
        .collect();
    Ok(json!({
        "destination_hex": destination_hex,
        "network_id": hex::encode(node.params.network_id),
        "bestblock": hex::encode(node.state.tip()),
        "height": next_height.saturating_sub(1),
        "snapshot": hex::encode(snapshot),
        "available_atoms": available_atoms.to_string(),
        "total_utxos": available.len(),
        "returned_utxos": utxos.len(),
        "utxos": utxos,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "mempool_scope": "this_node_only",
    }))
}

pub(crate) fn address_balance(node: &Node, destination: [u8; 32]) -> Result<Value, NodeError> {
    if node.storage_faulted {
        return Err(NodeError::StorageFaulted);
    }
    let next_height = node.state.next_height();
    let pending_spends = pending_spends(node);
    let mut confirmed = 0u128;
    let mut spendable = 0u128;
    let mut available = 0u128;
    let mut pending_outgoing = 0u128;
    let mut count = 0usize;
    for (outpoint, output) in node.state.utxos().iter() {
        if output.lock != OutputLock::Key(destination) {
            continue;
        }
        count += 1;
        confirmed += u128::from(output.value);
        let pending = pending_spends.contains(outpoint);
        if pending {
            pending_outgoing += u128::from(output.value);
        }
        if next_height >= output.spendable_height {
            spendable += u128::from(output.value);
            if !pending && !node.exchange_withdrawal_reservations.contains_key(outpoint) {
                available += u128::from(output.value);
            }
        }
    }
    let pending_incoming: u128 = node
        .mempool
        .values()
        .flat_map(|entry| &entry.transaction.outputs)
        .filter(|output| output.lock == OutputLock::Key(destination))
        .map(|output| u128::from(output.value))
        .sum();
    let delta = if pending_incoming >= pending_outgoing {
        (pending_incoming - pending_outgoing).to_string()
    } else {
        format!("-{}", pending_outgoing - pending_incoming)
    };
    Ok(json!({
        "destination_hex": hex::encode(destination),
        "network_id": hex::encode(node.params.network_id),
        "bestblock": hex::encode(node.state.tip()),
        "height": next_height.saturating_sub(1),
        "balance_atoms": confirmed.to_string(),
        "confirmed_atoms": confirmed.to_string(),
        "spendable_atoms": spendable.to_string(),
        "immature_atoms": (confirmed - spendable).to_string(),
        "available_atoms": available.to_string(),
        "pending_incoming_atoms": pending_incoming.to_string(),
        "pending_outgoing_atoms": pending_outgoing.to_string(),
        "unconfirmed_delta_atoms": delta,
        "utxo_count": count,
        "mempool_scope": "this_node_only",
    }))
}
