//! Read-only key-address balances and canonical activity, with tip-bound pages.

use cmfd_consensus::{InputWitness, MAX_BLOCK_TRANSACTIONS, OutputLock};
use serde::Serialize;

use crate::explorer::{AuthenticatedExplorerBlock, parse_identifier};
use crate::explorer_address_index::AddressLocation;
use crate::{Node, NodeError};

pub const EXPLORER_ADDRESS_PAGE_SIZE: usize = 20;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExplorerAddressActivity {
    pub txid: String,
    pub block_id: String,
    pub block_height: u64,
    pub timestamp: u64,
    pub confirmations: u64,
    pub kind: &'static str,
    pub received_atoms: String,
    pub received_outputs: usize,
    pub spent_inputs: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExplorerAddress {
    pub address: String,
    pub tip: String,
    pub accepted_height: u64,
    /// Direct key-locked UTXOs only; channel escrow is not a key balance.
    pub balance_scope: &'static str,
    pub includes_mempool: bool,
    pub confirmed_atoms: String,
    pub spendable_atoms: String,
    pub immature_atoms: String,
    pub utxo_count: usize,
    pub history: Vec<ExplorerAddressActivity>,
    pub page_limit: usize,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

impl Node {
    pub fn explorer_address(
        &mut self,
        query: &str,
        cursor: Option<&str>,
    ) -> Result<ExplorerAddress, NodeError> {
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        let address = parse_identifier(query).ok_or(NodeError::InvalidExplorerAddress)?;
        let tip = self.state.tip();
        let before = cursor
            .map(|cursor| self.parse_explorer_address_cursor(address, tip, cursor))
            .transpose()?;
        let page = self.index.addresses.page(
            &address,
            &self.index,
            before,
            EXPLORER_ADDRESS_PAGE_SIZE + 1,
        );
        let has_more = page.len() > EXPLORER_ADDRESS_PAGE_SIZE;
        let mut history = Vec::with_capacity(EXPLORER_ADDRESS_PAGE_SIZE);
        let mut retained_block: Option<AuthenticatedExplorerBlock> = None;
        let height = self.state.next_height().saturating_sub(1);
        for location in page.iter().take(EXPLORER_ADDRESS_PAGE_SIZE) {
            if retained_block
                .as_ref()
                .is_none_or(|block| block.block_id() != location.block_id)
            {
                retained_block = Some(self.read_explorer_block(location.block_id)?);
            }
            let block = retained_block
                .as_ref()
                .expect("page block was just authenticated");
            let activity = activity_summary(block, *location, address, height);
            history.push(self.latch_authenticated_storage_failure(activity)?);
        }
        let balances = self.explorer_outputs.outputs(&address).try_fold(
            (0_u128, 0_u128, 0_usize),
            |(mut spendable, mut immature, count), outpoint| {
                let output = self
                    .state
                    .utxos()
                    .get(outpoint)
                    .filter(|output| output.lock == OutputLock::Key(address))
                    .ok_or_else(|| {
                        NodeError::CorruptLog(
                            "explorer address output index disagrees with consensus UTXOs"
                                .to_owned(),
                        )
                    })?;
                if output.spendable_height <= self.state.next_height() {
                    spendable += u128::from(output.value);
                } else {
                    immature += u128::from(output.value);
                }
                Ok((spendable, immature, count + 1))
            },
        );
        let (spendable, immature, utxo_count) =
            self.latch_authenticated_storage_failure(balances)?;
        let next_cursor = has_more.then(|| {
            let last = page[EXPLORER_ADDRESS_PAGE_SIZE - 1];
            format!("{}.{}.{}", hex::encode(tip), last.height, last.position)
        });
        Ok(ExplorerAddress {
            address: hex::encode(address),
            tip: hex::encode(tip),
            accepted_height: height,
            balance_scope: "key_outputs",
            includes_mempool: false,
            confirmed_atoms: (spendable + immature).to_string(),
            spendable_atoms: spendable.to_string(),
            immature_atoms: immature.to_string(),
            utxo_count,
            history,
            page_limit: EXPLORER_ADDRESS_PAGE_SIZE,
            has_more,
            next_cursor,
        })
    }

    fn parse_explorer_address_cursor(
        &self,
        address: [u8; 32],
        tip: [u8; 32],
        cursor: &str,
    ) -> Result<AddressLocation, NodeError> {
        if cursor.len() > 108 {
            return Err(NodeError::InvalidExplorerCursor);
        }
        let mut parts = cursor.split('.');
        let cursor_tip = parts
            .next()
            .and_then(parse_identifier)
            .ok_or(NodeError::InvalidExplorerCursor)?;
        let height_text = parts.next().ok_or(NodeError::InvalidExplorerCursor)?;
        let position_text = parts.next().ok_or(NodeError::InvalidExplorerCursor)?;
        if parts.next().is_some()
            || !canonical_decimal(height_text)
            || !canonical_decimal(position_text)
        {
            return Err(NodeError::InvalidExplorerCursor);
        }
        let height = height_text
            .parse::<u64>()
            .map_err(|_| NodeError::InvalidExplorerCursor)?;
        let position = position_text
            .parse::<usize>()
            .map_err(|_| NodeError::InvalidExplorerCursor)?;
        if height == 0 || position > MAX_BLOCK_TRANSACTIONS {
            return Err(NodeError::InvalidExplorerCursor);
        }
        if cursor_tip != tip {
            return Err(NodeError::StaleExplorerCursor);
        }
        let block_id = self
            .active_block_id_at_height(height)
            .ok_or(NodeError::InvalidExplorerCursor)?;
        let location = AddressLocation {
            height,
            position,
            block_id,
        };
        if !self.index.addresses.contains(&address, location) {
            return Err(NodeError::InvalidExplorerCursor);
        }
        Ok(location)
    }
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn activity_summary(
    checked: &AuthenticatedExplorerBlock,
    location: AddressLocation,
    address: [u8; 32],
    height: u64,
) -> Result<ExplorerAddressActivity, NodeError> {
    let block = checked.block();
    if checked.block_id() != location.block_id || block.challenge.height != location.height {
        return Err(NodeError::CorruptLog(
            "explorer address locator does not match its authenticated block".to_owned(),
        ));
    }
    let (txid, inputs, outputs) = if location.position == 0 {
        (
            block.coinbase_outpoint_id(),
            &[][..],
            block.coinbase.outputs.as_slice(),
        )
    } else {
        let transaction = block
            .transactions
            .get(location.position - 1)
            .ok_or_else(|| {
                NodeError::CorruptLog(
                    "explorer address transaction position is outside its authenticated block"
                        .to_owned(),
                )
            })?;
        (
            transaction.txid(),
            transaction.inputs.as_slice(),
            transaction.outputs.as_slice(),
        )
    };
    let spent_inputs = inputs.iter().filter(|input| matches!(input.witness, InputWitness::Key { public_key, .. } if public_key == address)).count();
    let mut received_atoms = 0_u128;
    let mut received_outputs = 0;
    for output in outputs {
        if output.lock == OutputLock::Key(address) {
            received_atoms += u128::from(output.value);
            received_outputs += 1;
        }
    }
    if spent_inputs == 0 && received_outputs == 0 {
        return Err(NodeError::CorruptLog(
            "explorer address index does not match authenticated activity".to_owned(),
        ));
    }
    let kind = match (
        location.position == 0,
        spent_inputs > 0,
        received_outputs > 0,
    ) {
        (true, _, _) => "coinbase",
        (false, true, true)
            if spent_inputs == inputs.len() && received_outputs == outputs.len() =>
        {
            "self"
        }
        (false, true, _) => "sent",
        _ => "received",
    };
    Ok(ExplorerAddressActivity {
        txid: hex::encode(txid),
        block_id: hex::encode(location.block_id),
        block_height: location.height,
        timestamp: block.challenge.timestamp,
        confirmations: height
            .checked_sub(location.height)
            .and_then(|depth| depth.checked_add(1))
            .ok_or_else(|| {
                NodeError::CorruptLog("explorer address confirmation depth is invalid".to_owned())
            })?,
        kind,
        received_atoms: received_atoms.to_string(),
        received_outputs,
        spent_inputs,
    })
}
