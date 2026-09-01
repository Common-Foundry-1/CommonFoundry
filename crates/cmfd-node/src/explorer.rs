use cmfd_consensus::{Block, BlockProof, Transaction, encode_block, encode_transaction};
use serde::Serialize;

use crate::{Node, NodeError, ProofProfile, read_indexed_block};

const EXPLORER_BLOCK_LIMIT: usize = 12;
const EXPLORER_TRANSACTION_LIMIT: usize = 24;
const EXPLORER_TRANSACTION_LOOKBACK: usize = 4_096;

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
        let status = self.status()?;
        let mut latest_blocks = Vec::new();
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
            let block = self.read_explorer_block(block_id)?;
            let encoded_bytes = encode_block(&block)?.len();
            let confirmations =
                u64::try_from(self.index.active_chain.len() - position).map_err(|_| {
                    NodeError::CorruptLog("explorer confirmation depth does not fit u64".to_owned())
                })?;
            latest_blocks.push(block_summary(&block, encoded_bytes, confirmations)?);
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
            mempool_transactions: status.mempool_transactions,
            mempool_bytes: status.mempool_bytes,
            connected_peers,
            latest_blocks,
            recent_transactions,
        })
    }

    pub fn explorer_block(
        &mut self,
        query: &str,
    ) -> Result<Option<ExplorerBlockDetail>, NodeError> {
        let Some((position, block_id)) = self.resolve_active_block(query) else {
            return Ok(None);
        };
        if position == 0 {
            return Ok(None);
        }
        let block = self.read_explorer_block(block_id)?;
        let encoded_bytes = encode_block(&block)?.len();
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
            block: block_summary(&block, encoded_bytes, confirmations)?,
            coinbase_outputs: block.coinbase.outputs.len(),
            transactions_detail,
        }))
    }

    pub fn explorer_transaction(
        &mut self,
        query: &str,
    ) -> Result<Option<ExplorerTransaction>, NodeError> {
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

        let active_ids: Vec<_> = self
            .index
            .active_chain
            .iter()
            .skip(1)
            .rev()
            .take(EXPLORER_TRANSACTION_LOOKBACK)
            .copied()
            .collect();
        for block_id in active_ids {
            let block = self.read_explorer_block(block_id)?;
            if let Some(transaction) = block
                .transactions
                .iter()
                .find(|transaction| transaction.txid() == txid)
            {
                return Ok(Some(transaction_summary(
                    transaction,
                    Some(block_id),
                    Some(block.challenge.height),
                    Some(block.challenge.timestamp),
                    None,
                    encode_transaction(transaction)?.len(),
                )?));
            }
        }
        Ok(None)
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

    fn read_explorer_block(&mut self, block_id: [u8; 32]) -> Result<Block, NodeError> {
        let indexed = self.index.blocks.get(&block_id).cloned().ok_or_else(|| {
            NodeError::CorruptLog("active explorer lookup refers to an absent block".to_owned())
        })?;
        let result = read_indexed_block(
            &self.log,
            &self.data_dir.join(crate::BLOCK_LOG_FILE),
            &indexed,
            block_id,
            self.params.network_id,
            matches!(self.profile.proof, ProofProfile::ProductionV3),
        );
        self.latch_authenticated_storage_failure(result)
    }
}

fn block_summary(
    block: &Block,
    encoded_bytes: usize,
    confirmations: u64,
) -> Result<ExplorerBlock, NodeError> {
    let coinbase_atoms = block
        .coinbase
        .outputs
        .iter()
        .try_fold(0_u64, |total, output| {
            total.checked_add(output.value).ok_or_else(|| {
                NodeError::CorruptLog("coinbase output total overflows u64".to_owned())
            })
        })?;
    let (nonce, work_digest) = proof_identity(&block.proof);
    Ok(ExplorerBlock {
        height: block.challenge.height,
        block_id: hex::encode(block.block_id()),
        previous_block: hex::encode(block.challenge.previous_block),
        transaction_root: hex::encode(block.challenge.transaction_root),
        timestamp: block.challenge.timestamp,
        target: hex::encode(block.challenge.target),
        nonce: nonce.to_string(),
        work_digest: hex::encode(work_digest),
        transactions: block.transactions.len(),
        encoded_bytes,
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

fn proof_identity(proof: &BlockProof) -> (u64, [u8; 32]) {
    match proof {
        BlockProof::V1Legacy(proof) => (proof.nonce, proof.work_digest),
        BlockProof::V2Reference(proof) => (proof.nonce, proof.work_digest),
        BlockProof::V3Candidate(proof) => (proof.nonce, proof.work_digest),
        BlockProof::V4Candidate(proof) => (proof.nonce, proof.work_digest),
    }
}

fn parse_identifier(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{DEVNET_PROFILE, RpcRequest, route_rpc_request};

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
            assert!(EXPLORER_TRANSACTION_LOOKBACK <= 4_096);
        }
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
