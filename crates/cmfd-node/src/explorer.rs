#[cfg(test)]
use cmfd_consensus::encode_block;
use cmfd_consensus::{Transaction, encode_transaction};
use serde::Serialize;
use std::time::{Duration, Instant};

use crate::{
    BLOCK_LOG_FILE, Node, NodeError, ProofProfile, io_error, read_indexed_block_with_size,
    verify_retained_block_log_path,
};

const EXPLORER_BLOCK_LIMIT: usize = 12;
const EXPLORER_TRANSACTION_LIMIT: usize = 24;
const EXPLORER_CACHE_MAX_AGE: Duration = Duration::from_secs(30);

/// Immutable, query-local body and scalar results of one authenticated read.
/// No unchecked constructor, mutation accessor or consensus capability exists.
/// This avoids rehashing a V4 proof just to obtain the same display identifier.
pub(super) struct AuthenticatedExplorerBlock {
    block: crate::StoredBlock,
    block_id: [u8; 32],
    encoded_bytes: usize,
}

impl AuthenticatedExplorerBlock {
    pub(super) fn block(&self) -> &crate::StoredBlock {
        &self.block
    }
    pub(super) fn block_id(&self) -> [u8; 32] {
        self.block_id
    }
    pub(super) fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}

/// Bounded, process-local display metadata, never proof or admission authority.
/// Only fully authenticated reads populate this cache. It expires periodically
/// and whenever the canonical tip changes; live mempool/peer fields stay uncached.
pub(super) struct ExplorerHistoryCache {
    tip: [u8; 32],
    checked_at: Instant,
    blocks: Vec<ExplorerBlock>,
    transactions: Vec<ExplorerTransaction>,
}

impl ExplorerHistoryCache {
    #[cfg(test)]
    fn retained_payload_bytes(&self) -> usize {
        let mut bytes = std::mem::size_of::<Self>()
            + self.blocks.capacity() * std::mem::size_of::<ExplorerBlock>()
            + self.transactions.capacity() * std::mem::size_of::<ExplorerTransaction>();
        for block in &self.blocks {
            bytes += [
                &block.block_id,
                &block.previous_block,
                &block.transaction_root,
                &block.target,
                &block.nonce,
                &block.work_digest,
                &block.coinbase_atoms,
            ]
            .into_iter()
            .map(String::capacity)
            .sum::<usize>();
        }
        for tx in &self.transactions {
            bytes += tx.txid.capacity()
                + tx.output_atoms.capacity()
                + tx.block_id.as_ref().map_or(0, String::capacity)
                + tx.fee_burned_atoms.as_ref().map_or(0, String::capacity);
        }
        bytes
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExplorerBlock {
    pub height: u64,
    pub block_id: String,
    pub previous_block: String,
    pub transaction_root: String,
    pub timestamp: u64,
    pub target: String,
    pub nonce: String,
    pub work_digest: String,
    pub transactions: usize,
    pub encoded_bytes: usize,
    pub coinbase_atoms: String,
    pub confirmations: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExplorerTransaction {
    pub txid: String,
    pub block_id: Option<String>,
    pub block_height: Option<u64>,
    pub timestamp: Option<u64>,
    pub inputs: usize,
    pub outputs: usize,
    pub output_atoms: String,
    pub fee_burned_atoms: Option<String>,
    pub encoded_bytes: usize,
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExplorerSnapshot {
    pub network: &'static str,
    pub network_short_name: &'static str,
    pub network_id: String,
    pub consensus_fingerprint: String,
    pub proof_profile: &'static str,
    pub proof_of_work: &'static str,
    pub tip: String,
    pub accepted_height: u64,
    pub expected_target: String,
    pub cumulative_work: String,
    pub utxo_count: usize,
    /// Total supply in atoms (decimal string): the value of every unspent
    /// output, since fees are burned.
    pub total_supply_atoms: String,
    pub mempool_transactions: usize,
    pub mempool_bytes: usize,
    pub connected_peers: usize,
    pub latest_blocks: Vec<ExplorerBlock>,
    pub recent_transactions: Vec<ExplorerTransaction>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExplorerBlockDetail {
    #[serde(flatten)]
    pub block: ExplorerBlock,
    pub coinbase_outputs: usize,
    pub transactions_detail: Vec<ExplorerTransaction>,
}

impl Node {
    pub fn explorer_snapshot(&mut self) -> Result<ExplorerSnapshot, NodeError> {
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        // Keep cheap retained-file identity/length checks on every poll, even
        // a metadata-cache hit. No snapshot may hide a known storage fault.
        let log_path = self.data_dir.join(BLOCK_LOG_FILE);
        let storage = (|| {
            verify_retained_block_log_path(&self.log, &log_path)?;
            let length = self
                .log
                .metadata()
                .map_err(|source| io_error("inspect explorer block log", &log_path, source))?
                .len();
            if length != self.block_log_length {
                return Err(NodeError::CorruptLog(
                    "explorer block log length changed outside durable admission".to_owned(),
                ));
            }
            Ok(())
        })();
        self.latch_authenticated_storage_failure(storage)?;
        let status = self.status()?;
        let mut recent_transactions = self
            .mempool
            .values()
            .rev()
            .take(EXPLORER_TRANSACTION_LIMIT)
            .map(|entry| {
                transaction_summary(
                    &entry.transaction,
                    None,
                    None,
                    None,
                    Some(entry.fee_burned),
                    entry.encoded_bytes,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.refresh_explorer_history_cache()?;
        let cached = self
            .explorer_history_cache
            .as_ref()
            .expect("successful cache refresh installs complete metadata");
        let latest_blocks = cached.blocks.clone();
        recent_transactions.extend(
            cached
                .transactions
                .iter()
                .take(EXPLORER_TRANSACTION_LIMIT - recent_transactions.len())
                .cloned(),
        );

        let connected_peers = status
            .peers
            .iter()
            .filter(|peer| peer.active_connections > 0)
            .count();
        Ok(ExplorerSnapshot {
            network: status.network,
            network_short_name: status.network_short_name,
            network_id: status.network_id,
            consensus_fingerprint: status.consensus_fingerprint,
            proof_profile: status.proof_profile,
            proof_of_work: status.proof_of_work,
            tip: status.tip,
            accepted_height: status.accepted_height,
            expected_target: status.expected_target,
            cumulative_work: status.cumulative_work,
            utxo_count: status.utxo_count,
            total_supply_atoms: self.total_supply_atoms().to_string(),
            mempool_transactions: status.mempool_transactions,
            mempool_bytes: status.mempool_bytes,
            connected_peers,
            latest_blocks,
            recent_transactions,
        })
    }

    fn refresh_explorer_history_cache(&mut self) -> Result<(), NodeError> {
        let tip = self.state.tip();
        if self.explorer_history_cache.as_ref().is_some_and(|cache| {
            cache.tip == tip && cache.checked_at.elapsed() < EXPLORER_CACHE_MAX_AGE
        }) {
            return Ok(());
        }
        let mut latest_blocks = Vec::with_capacity(EXPLORER_BLOCK_LIMIT);
        let mut recent_transactions = Vec::with_capacity(EXPLORER_TRANSACTION_LIMIT);
        let active_ids: Vec<_> = self
            .index
            .active_chain
            .iter()
            .enumerate()
            .skip(1)
            .rev()
            .take(EXPLORER_BLOCK_LIMIT)
            .map(|(position, block_id)| (position, *block_id))
            .collect();
        for (position, block_id) in active_ids {
            let checked = self.read_explorer_block(block_id)?;
            let block = checked.block();
            let confirmations =
                u64::try_from(self.index.active_chain.len() - position).map_err(|_| {
                    NodeError::CorruptLog("explorer confirmation depth does not fit u64".to_owned())
                })?;
            latest_blocks.push(block_summary(&checked, confirmations)?);
            for transaction in &block.transactions {
                if recent_transactions.len() >= EXPLORER_TRANSACTION_LIMIT {
                    break;
                }
                recent_transactions.push(transaction_summary(
                    transaction,
                    Some(block_id),
                    Some(block.challenge.height),
                    Some(block.challenge.timestamp),
                    None,
                    encode_transaction(transaction)?.len(),
                )?);
            }
        }

        self.explorer_history_cache = Some(ExplorerHistoryCache {
            tip,
            checked_at: Instant::now(),
            blocks: latest_blocks,
            transactions: recent_transactions,
        });
        Ok(())
    }

    pub fn explorer_block(
        &mut self,
        query: &str,
    ) -> Result<Option<ExplorerBlockDetail>, NodeError> {
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        let Some((position, block_id)) = self.resolve_active_block(query) else {
            return Ok(None);
        };
        if position == 0 {
            return Ok(None);
        }
        let checked = self.read_explorer_block(block_id)?;
        let block = checked.block();
        let confirmations =
            u64::try_from(self.index.active_chain.len() - position).map_err(|_| {
                NodeError::CorruptLog("explorer confirmation depth does not fit u64".to_owned())
            })?;
        let transactions_detail = block
            .transactions
            .iter()
            .map(|transaction| {
                transaction_summary(
                    transaction,
                    Some(block_id),
                    Some(block.challenge.height),
                    Some(block.challenge.timestamp),
                    None,
                    encode_transaction(transaction)?.len(),
                )
            })
            .collect::<Result<Vec<_>, NodeError>>()?;
        Ok(Some(ExplorerBlockDetail {
            block: block_summary(&checked, confirmations)?,
            coinbase_outputs: block.coinbase.outputs.len(),
            transactions_detail,
        }))
    }

    pub fn explorer_transaction(
        &mut self,
        query: &str,
    ) -> Result<Option<ExplorerTransaction>, NodeError> {
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        let Some(txid) = parse_identifier(query) else {
            return Ok(None);
        };
        if let Some(entry) = self.mempool.get(&txid) {
            return Ok(Some(transaction_summary(
                &entry.transaction,
                None,
                None,
                None,
                Some(entry.fee_burned),
                entry.encoded_bytes,
            )?));
        }

        let Some(location) = self.index.transactions.active_location(&txid, &self.index) else {
            return Ok(None);
        };
        // The index only chooses a locator. Reauthenticate the complete stored
        // block and check the exact transaction before reporting confirmation.
        let checked = self.read_explorer_block(location.block_id)?;
        let block = checked.block();
        let transaction = block
            .transactions
            .get(location.transaction_position)
            .filter(|transaction| transaction.txid() == txid)
            .ok_or_else(|| {
                NodeError::CorruptLog(
                    "explorer transaction index does not match its authenticated block".to_owned(),
                )
            });
        let transaction = self.latch_authenticated_storage_failure(transaction)?;
        Ok(Some(transaction_summary(
            transaction,
            Some(location.block_id),
            Some(block.challenge.height),
            Some(block.challenge.timestamp),
            None,
            encode_transaction(transaction)?.len(),
        )?))
    }

    fn resolve_active_block(&self, query: &str) -> Option<(usize, [u8; 32])> {
        if let Ok(height) = query.parse::<usize>() {
            return self
                .index
                .active_chain
                .get(height)
                .copied()
                .map(|id| (height, id));
        }
        let block_id = parse_identifier(query)?;
        self.index
            .active_position(block_id)
            .map(|position| (position, block_id))
    }

    pub(super) fn read_explorer_block(
        &mut self,
        block_id: [u8; 32],
    ) -> Result<AuthenticatedExplorerBlock, NodeError> {
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        #[cfg(test)]
        {
            self.explorer_block_reads += 1;
        }
        let result = (|| {
            let indexed = self.index.blocks.get(&block_id).cloned().ok_or_else(|| {
                NodeError::CorruptLog("active explorer lookup refers to an absent block".to_owned())
            })?;
            let (block, encoded_bytes) = read_indexed_block_with_size(
                &self.log,
                &self.data_dir.join(crate::BLOCK_LOG_FILE),
                &indexed,
                block_id,
                self.params.network_id,
                matches!(self.profile.proof, ProofProfile::ProductionV3),
            )?;
            Ok(AuthenticatedExplorerBlock {
                block,
                block_id,
                encoded_bytes,
            })
        })();
        self.latch_authenticated_storage_failure(result)
    }
}

fn block_summary(
    checked: &AuthenticatedExplorerBlock,
    confirmations: u64,
) -> Result<ExplorerBlock, NodeError> {
    let block = checked.block();
    let coinbase_atoms = block
        .coinbase
        .outputs
        .iter()
        .try_fold(0_u64, |total, output| {
            total.checked_add(output.value).ok_or_else(|| {
                NodeError::CorruptLog("coinbase output total overflows u64".to_owned())
            })
        })?;
    let summary = block.proof_summary();
    let (nonce, work_digest) = (summary.nonce, summary.work_digest);
    Ok(ExplorerBlock {
        height: block.challenge.height,
        block_id: hex::encode(checked.block_id()),
        previous_block: hex::encode(block.challenge.previous_block),
        transaction_root: hex::encode(block.challenge.transaction_root),
        timestamp: block.challenge.timestamp,
        target: hex::encode(block.challenge.target),
        nonce: nonce.to_string(),
        work_digest: hex::encode(work_digest),
        transactions: block.transactions.len(),
        encoded_bytes: checked.encoded_bytes(),
        coinbase_atoms: coinbase_atoms.to_string(),
        confirmations,
    })
}

fn transaction_summary(
    transaction: &Transaction,
    block_id: Option<[u8; 32]>,
    block_height: Option<u64>,
    timestamp: Option<u64>,
    fee_burned: Option<u64>,
    encoded_bytes: usize,
) -> Result<ExplorerTransaction, NodeError> {
    let output_atoms = transaction
        .outputs
        .iter()
        .try_fold(0_u64, |total, output| {
            total.checked_add(output.value).ok_or_else(|| {
                NodeError::CorruptLog("transaction output total overflows u64".to_owned())
            })
        })?;
    Ok(ExplorerTransaction {
        txid: hex::encode(transaction.txid()),
        block_id: block_id.map(hex::encode),
        block_height,
        timestamp,
        inputs: transaction.inputs.len(),
        outputs: transaction.outputs.len(),
        output_atoms: output_atoms.to_string(),
        fee_burned_atoms: fee_burned.map(|fee| fee.to_string()),
        encoded_bytes,
        status: if block_id.is_some() {
            "confirmed"
        } else {
            "mempool"
        },
    })
}

pub(super) fn parse_identifier(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::tests::{clean_test_dir, mined_child, spend_coinbase_output, test_dir};
    use crate::{DEVNET_PROFILE, RpcRequest, route_rpc_request};
    use cmfd_consensus::Block;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn identifier_parser_is_exact_and_case_insensitive() {
        assert_eq!(parse_identifier(&"aB".repeat(32)), Some([0xab; 32]));
        assert_eq!(parse_identifier(&"0".repeat(63)), None);
        assert_eq!(parse_identifier(&"z".repeat(64)), None);
    }

    #[test]
    fn explorer_limits_are_bounded() {
        const {
            assert!(EXPLORER_BLOCK_LIMIT <= 32);
            assert!(EXPLORER_TRANSACTION_LIMIT <= 64);
            assert!(EXPLORER_CACHE_MAX_AGE.as_secs() <= 30);
        }
    }

    fn mine(node: &mut Node) -> Block {
        let now = crate::DEVNET_GENESIS_TIMESTAMP + node.state.next_height() * 60;
        node.mine_once(
            crate::default_miner_destination(),
            now,
            crate::DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap()
    }

    #[test]
    fn total_supply_is_minted_coins_minus_burned_fees() {
        let path = test_dir("explorer-supply");
        let mut node = Node::open(&path).unwrap();
        let minted = |blocks: &[Block]| -> u64 {
            blocks
                .iter()
                .flat_map(|block| &block.coinbase.outputs)
                .map(|output| output.value)
                .sum()
        };
        let mut blocks: Vec<Block> = (0..3).map(|_| mine(&mut node)).collect();
        assert_eq!(node.total_supply_atoms(), minted(&blocks));
        assert_eq!(
            node.explorer_snapshot().unwrap().total_supply_atoms,
            minted(&blocks).to_string()
        );

        // Fees are burned: a transaction's fee leaves the supply.
        let fee = 1_000;
        let transaction = spend_coinbase_output(&node, &blocks[0], 1, 0x11, 0x31, fee);
        node.submit_transaction(transaction).unwrap();
        blocks.push(mine(&mut node));
        assert_eq!(blocks[3].transactions.len(), 1);
        assert_eq!(node.total_supply_atoms(), minted(&blocks) - fee);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn overview_cache_bounds_retained_metadata_and_repeated_poll_body_reads() {
        let path = test_dir("explorer-cache-polls");
        let mut node = Node::open(&path).unwrap();
        let mut funding = Vec::new();
        for _ in 0..12 {
            funding.push(mine(&mut node));
        }
        for block in &funding {
            for (index, owner) in [(1, 0x11), (2, 0x12)] {
                let transaction = spend_coinbase_output(&node, block, index, owner, 0x31, 1);
                node.submit_transaction(transaction).unwrap();
            }
        }
        mine(&mut node);
        for _ in 0..11 {
            mine(&mut node);
        }
        let cold_start = Instant::now();
        let expected = node.explorer_snapshot().unwrap();
        let cold_micros = cold_start.elapsed().as_micros();
        assert_eq!(expected.latest_blocks.len(), EXPLORER_BLOCK_LIMIT);
        assert_eq!(
            expected.recent_transactions.len(),
            EXPLORER_TRANSACTION_LIMIT
        );
        assert_eq!(node.explorer_block_reads, EXPLORER_BLOCK_LIMIT);
        let cache_bytes = node
            .explorer_history_cache
            .as_ref()
            .unwrap()
            .retained_payload_bytes();
        let originally_checked_at = node.explorer_history_cache.as_ref().unwrap().checked_at;
        assert!(
            cache_bytes <= 64 * 1024,
            "bounded display metadata must not retain block/proof bodies"
        );
        let warm_start = Instant::now();
        for _ in 0..1000 {
            assert_eq!(node.explorer_snapshot().unwrap(), expected);
        }
        let warm_elapsed = warm_start.elapsed();
        // On a heavily paused machine, age expiry is legitimate. Do not make
        // CI success depend on a wall-clock latency promise; record the result.
        let cache_lifetime = originally_checked_at.elapsed();
        let permitted_refreshes = 1 + cache_lifetime.as_secs() / EXPLORER_CACHE_MAX_AGE.as_secs();
        assert!(node.explorer_block_reads <= EXPLORER_BLOCK_LIMIT * permitted_refreshes as usize);
        if cache_lifetime < EXPLORER_CACHE_MAX_AGE {
            assert_eq!(node.explorer_block_reads, EXPLORER_BLOCK_LIMIT);
        }
        println!(
            "EXPLORER_CACHE_BENCH {}",
            serde_json::json!({
                "fixture_profile": "DevnetV2Reference", "production_proof_latency_qualified": false,
                "os": std::env::consts::OS, "cold_snapshot_us": cold_micros,
                "warm_polls": 1000, "warm_total_us": warm_elapsed.as_micros(),
                "total_block_body_reads": node.explorer_block_reads,
                "retained_metadata_payload_bytes": cache_bytes,
                "allocator_overhead_included": false,
                "response_json_bytes": serde_json::to_vec(&expected).unwrap().len(),
            })
        );
        node.explorer_history_cache.as_mut().unwrap().checked_at = Instant::now()
            .checked_sub(EXPLORER_CACHE_MAX_AGE + Duration::from_secs(1))
            .unwrap();
        let previous_reads = node.explorer_block_reads;
        assert_eq!(node.explorer_snapshot().unwrap(), expected);
        assert_eq!(
            node.explorer_block_reads - previous_reads,
            EXPLORER_BLOCK_LIMIT
        );
        drop(node);
        let mut reopened = Node::open(&path).unwrap();
        assert!(reopened.explorer_history_cache.is_none());
        assert_eq!(reopened.explorer_snapshot().unwrap(), expected);
        assert_eq!(reopened.explorer_block_reads, EXPLORER_BLOCK_LIMIT);
        drop(reopened);
        clean_test_dir(&path);
    }

    #[test]
    fn overview_cache_keeps_mempool_and_peer_fields_live() {
        let path = test_dir("explorer-cache-live");
        let mut node = Node::open(&path).unwrap();
        let funding = mine(&mut node);
        assert!(
            node.explorer_snapshot()
                .unwrap()
                .recent_transactions
                .is_empty()
        );
        let reads = node.explorer_block_reads;
        let transaction = spend_coinbase_output(&node, &funding, 2, 0x12, 0x31, 1);
        let txid = hex::encode(transaction.txid());
        node.submit_transaction(transaction).unwrap();
        node.record_peer_started(
            crate::PeerDirection::Inbound,
            "127.0.0.1:20000".to_owned(),
            crate::unix_time_seconds().unwrap(),
        );
        let pending = node.explorer_snapshot().unwrap();
        assert_eq!(node.explorer_block_reads, reads);
        assert_eq!(pending.mempool_transactions, 1);
        assert_eq!(pending.connected_peers, 1);
        assert_eq!(pending.recent_transactions[0].txid, txid);
        assert_eq!(pending.recent_transactions[0].status, "mempool");
        mine(&mut node);
        let confirmed = node.explorer_snapshot().unwrap();
        assert_eq!(confirmed.accepted_height, 2);
        assert_eq!(confirmed.mempool_transactions, 0);
        assert_eq!(confirmed.recent_transactions[0].status, "confirmed");
        assert_eq!(confirmed.recent_transactions[0].txid, txid);
        assert_eq!(node.explorer_block_reads - reads, 2);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn authenticated_query_body_keeps_exact_identity_size_and_corruption_checks() {
        let path = test_dir("explorer-checked-body");
        let mut node = Node::open(&path).unwrap();
        let original = mine(&mut node);
        let block_id = original.block_id();
        let checked = node.read_explorer_block(block_id).unwrap();
        assert_eq!(checked.block().full().as_ref(), Some(&original));
        assert_eq!(checked.block_id(), block_id);
        assert_eq!(
            checked.encoded_bytes(),
            encode_block(&original).unwrap().len()
        );
        let summary = block_summary(&checked, 1).unwrap();
        assert_eq!(summary.block_id, hex::encode(block_id));
        assert_eq!(summary.encoded_bytes, checked.encoded_bytes());
        drop(checked);
        let original_locator = node.index.blocks[&block_id].locator;
        for mutation in 0..4 {
            let mut changed = original_locator;
            match mutation {
                0 => changed.block_id[0] ^= 1,
                1 => changed.complete_digest[0] ^= 1,
                2 => changed.offset += 1,
                _ => changed.length -= 1,
            }
            Arc::get_mut(node.index.blocks.get_mut(&block_id).unwrap())
                .unwrap()
                .locator = changed;
            assert!(matches!(
                node.read_explorer_block(block_id),
                Err(NodeError::CorruptLog(_))
            ));
            assert!(node.storage_faulted);
            node.storage_faulted = false; // isolate the next in-memory fault injection
        }
        Arc::get_mut(node.index.blocks.get_mut(&block_id).unwrap())
            .unwrap()
            .locator = original_locator;
        assert_eq!(
            node.read_explorer_block(block_id).unwrap().block_id(),
            block_id
        );
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn overview_cache_follows_canonical_reorganizations_not_side_branch_arrival() {
        let path = test_dir("explorer-cache-reorg");
        let mut node = Node::open(&path).unwrap();
        let active = mine(&mut node);
        let first = node.explorer_snapshot().unwrap();
        let sibling = mined_child(
            &node,
            node.params.genesis_hash,
            crate::DEVNET_GENESIS_TIMESTAMP + 60,
            0x41,
        );
        node.submit_block(sibling.clone(), sibling.challenge.timestamp)
            .unwrap();
        assert_eq!(node.explorer_snapshot().unwrap(), first);
        assert_eq!(node.explorer_block_reads, 1);
        let child = mined_child(
            &node,
            sibling.block_id(),
            crate::DEVNET_GENESIS_TIMESTAMP + 120,
            0x41,
        );
        node.submit_block(child.clone(), child.challenge.timestamp)
            .unwrap();
        let after = node.explorer_snapshot().unwrap();
        assert_eq!(after.tip, hex::encode(child.block_id()));
        assert_eq!(after.latest_blocks.len(), 2);
        assert_eq!(
            after.latest_blocks[1].block_id,
            hex::encode(sibling.block_id())
        );
        assert!(
            after
                .latest_blocks
                .iter()
                .all(|block| block.block_id != hex::encode(active.block_id()))
        );
        assert_eq!(node.explorer_block_reads, 3);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn overview_cache_never_hides_log_length_changes_or_known_faults() {
        let path = test_dir("explorer-cache-length");
        let mut node = Node::open(&path).unwrap();
        mine(&mut node);
        node.explorer_snapshot().unwrap();
        // The Windows retained handle intentionally permits append only, not
        // arbitrary SetEndOfFile. Inject a stray append through that handle.
        node.log.write_all(&[0]).unwrap();
        node.log.sync_all().unwrap();
        assert!(matches!(
            node.explorer_snapshot(),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(node.storage_faulted);
        assert_eq!(node.explorer_block_reads, 1);
        assert!(matches!(
            node.explorer_snapshot(),
            Err(NodeError::StorageFaulted)
        ));
        assert!(matches!(
            node.explorer_block("1"),
            Err(NodeError::StorageFaulted)
        ));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn overview_cache_expiry_and_cold_refresh_reauthenticate_without_partial_install() {
        let path = test_dir("explorer-cache-auth");
        let mut node = Node::open(&path).unwrap();
        let first = mine(&mut node);
        node.explorer_snapshot().unwrap();
        let cached_tip = node.explorer_history_cache.as_ref().unwrap().tip;
        mine(&mut node);
        Arc::get_mut(node.index.blocks.get_mut(&first.block_id()).unwrap())
            .unwrap()
            .locator
            .complete_digest[0] ^= 1;
        assert!(matches!(
            node.explorer_snapshot(),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(node.storage_faulted);
        assert_eq!(
            node.explorer_history_cache.as_ref().unwrap().tip,
            cached_tip
        );
        assert!(matches!(
            node.explorer_snapshot(),
            Err(NodeError::StorageFaulted)
        ));
        drop(node);
        clean_test_dir(&path);

        let path = test_dir("explorer-cache-expiry-auth");
        let mut node = Node::open(&path).unwrap();
        let block = mine(&mut node);
        node.explorer_snapshot().unwrap();
        Arc::get_mut(node.index.blocks.get_mut(&block.block_id()).unwrap())
            .unwrap()
            .locator
            .complete_digest[0] ^= 1;
        node.explorer_history_cache.as_mut().unwrap().checked_at = Instant::now()
            .checked_sub(EXPLORER_CACHE_MAX_AGE + Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            node.explorer_snapshot(),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(node.storage_faulted);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn fresh_node_exposes_a_real_empty_explorer_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "cmfd-explorer-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();

        let snapshot = node.explorer_snapshot().unwrap();
        assert_eq!(snapshot.accepted_height, 0);
        assert!(snapshot.latest_blocks.is_empty());
        assert!(snapshot.recent_transactions.is_empty());
        assert_eq!(snapshot.network_id, hex::encode(DEVNET_PROFILE.network_id));
        assert!(node.explorer_block("0").unwrap().is_none());
        assert!(
            node.explorer_transaction(&"00".repeat(32))
                .unwrap()
                .is_none()
        );

        let response = route_rpc_request(
            RpcRequest {
                method: "GET".to_owned(),
                target: "/v1/explorer".to_owned(),
                content_type: None,
                body: Vec::new(),
            },
            &mut node,
        );
        assert_eq!(response.status, 200);
        let document: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(document["accepted_height"], 0);

        let response = route_rpc_request(
            RpcRequest {
                method: "GET".to_owned(),
                target: "/v1/explorer/block/1".to_owned(),
                content_type: None,
                body: Vec::new(),
            },
            &mut node,
        );
        assert_eq!(response.status, 404);

        drop(node);
        fs::remove_dir_all(&path).unwrap();
    }
}
