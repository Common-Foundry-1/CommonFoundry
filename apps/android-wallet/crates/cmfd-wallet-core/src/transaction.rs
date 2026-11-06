//! Mainnet key-payment construction, signing and canonical wire encoding.
//!
//! The signing digest, transaction id and frame layouts follow Common Foundry
//! v1.0.16 `cmfd-consensus/src/chain.rs` and `wire.rs`. Only ordinary key UTXO
//! payments are in scope for the Android wallet.

use std::collections::{HashMap, HashSet};

use blake3::Hasher;
use k256::schnorr::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::address::AddressCodec;
use crate::network::{
    MAINNET, MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS, Network, TRANSACTION_VERSION,
};

const TX_SIGNING_DOMAIN: &str = "CMFD/TRANSACTION/SIGNING/V1";
const TX_ID_DOMAIN: &str = "CMFD/TRANSACTION/ID/V1";
const NETWORK_MAGIC_DOMAIN: &str = "CMFD/WIRE/NETWORK-MAGIC/V1";
const FRAME_MAGIC: [u8; 4] = *b"CMFD";
const WIRE_VERSION: u16 = 1;
const TRANSACTION_KIND: u8 = 1;
const KEY_WITNESS_TAG: u8 = 0;
const KEY_OUTPUT_TAG: u8 = 0;
const CONSENSUS_SIGNATURE_BYTES: usize = 64;
const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
const MIN_RELAY_FEE_PER_KIB: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value_atoms: u64,
    pub destination: [u8; 32],
    pub spendable_height: u64,
    pub known_spent: bool,
    pub locally_reserved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TxInput {
    previous: OutPoint,
    public_key: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TxOutput {
    value: u64,
    destination: [u8; 32],
    spendable_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Transaction {
    network_id: [u8; 32],
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
}

impl Transaction {
    fn signing_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(TX_SIGNING_DOMAIN);
        encode_unsigned_transaction(self, &mut hasher);
        *hasher.finalize().as_bytes()
    }

    fn txid(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(TX_ID_DOMAIN);
        encode_unsigned_transaction(self, &mut hasher);
        for input in &self.inputs {
            encode_witness(input, true, &mut hasher);
        }
        *hasher.finalize().as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPlan {
    transaction: Transaction,
    pub recipient: [u8; 32],
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub change_atoms: u64,
    pub input_atoms: u64,
    pub selected: Vec<OutPoint>,
    pub output_spendable_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendingLimit {
    /// All mature, unspent and unreserved atoms owned by the wallet.
    pub available_atoms: u64,
    /// The exact fee used by a transaction spending the selectable inputs.
    pub fee_atoms: u64,
    /// The greatest amount the planner can send without exceeding its input limit.
    pub maximum_atoms: u64,
    pub selected_inputs: usize,
}

impl PaymentPlan {
    pub fn signing_digest(&self) -> [u8; 32] {
        self.transaction.signing_digest()
    }

    pub fn recipient_address(&self) -> String {
        AddressCodec::mainnet().render(&self.recipient)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    pub txid: [u8; 32],
    pub signing_digest: [u8; 32],
    pub frame: Vec<u8>,
}

impl SignedTransaction {
    pub fn txid_hex(&self) -> String {
        hex::encode(self.txid)
    }

    pub fn frame_hex(&self) -> String {
        hex::encode(&self.frame)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransactionError {
    #[error("recipient address is invalid: {0}")]
    InvalidRecipient(String),
    #[error("recipient belongs to another network")]
    WrongNetwork,
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("fee is below the mainnet minimum of 10000000 atoms")]
    FeeTooLow,
    #[error("amount arithmetic overflowed")]
    AmountOverflow,
    #[error("insufficient spendable funds: available {available}, required {required}")]
    InsufficientFunds { available: u64, required: u64 },
    #[error("funds are present but immature: immature {immature}, required {required}")]
    FundsImmature { immature: u64, required: u64 },
    #[error("payment needs more than 128 inputs: selected {selected}, required {required}")]
    InputLimit { selected: u64, required: u64 },
    #[error("UTXO data contains an invalid owner key")]
    InvalidUtxoOwner,
    #[error("wallet signing key does not own every selected input")]
    WrongSigningKey,
    #[error("payment plan failed its integrity checks")]
    InvalidPlan,
    #[error("transaction exceeds the 64 KiB consensus limit")]
    TooLarge,
    #[error("an input is already reserved by another pending payment")]
    ReservationConflict,
    #[error("payment intent is already reserved")]
    DuplicateIntent,
    #[error("signed transaction does not match its reserved intent")]
    ReservationMismatch,
    #[error("pending transaction is unknown")]
    UnknownPendingTransaction,
}

#[derive(Debug, Clone, Copy)]
pub struct PaymentPlanner {
    network: Network,
    owner: [u8; 32],
}

struct SpendableCandidates {
    entries: Vec<(OutPoint, u64)>,
    available_atoms: u64,
    immature_atoms: u64,
}

impl PaymentPlanner {
    pub fn mainnet(owner: [u8; 32]) -> Result<Self, TransactionError> {
        VerifyingKey::from_bytes((&owner).into())
            .map_err(|_| TransactionError::InvalidUtxoOwner)?;
        Ok(Self {
            network: MAINNET,
            owner,
        })
    }

    pub fn plan(
        self,
        recipient_text: &str,
        amount_atoms: u64,
        fee_atoms: u64,
        next_height: u64,
        utxos: &[Utxo],
    ) -> Result<PaymentPlan, TransactionError> {
        if amount_atoms == 0 {
            return Err(TransactionError::ZeroAmount);
        }
        if fee_atoms < self.network.minimum_fee_atoms {
            return Err(TransactionError::FeeTooLow);
        }
        let recipient = AddressCodec::mainnet()
            .decode(recipient_text)
            .map(|(key, _)| key)
            .map_err(|error| match error {
                crate::AddressError::WrongNetwork { .. } => TransactionError::WrongNetwork,
                error => TransactionError::InvalidRecipient(error.to_string()),
            })?;
        let required = amount_atoms
            .checked_add(fee_atoms)
            .ok_or(TransactionError::AmountOverflow)?;

        let candidates = self.spendable_candidates(next_height, utxos)?;
        let mut selected = Vec::new();
        let mut selected_value = 0_u64;
        for (outpoint, value) in candidates.entries.into_iter().take(MAX_TRANSACTION_INPUTS) {
            selected.push(outpoint);
            selected_value = checked_add(selected_value, value)?;
            if selected_value >= required {
                break;
            }
        }
        if selected_value < required {
            if candidates.available_atoms >= required {
                return Err(TransactionError::InputLimit {
                    selected: selected_value,
                    required,
                });
            }
            if checked_add(candidates.available_atoms, candidates.immature_atoms)? >= required {
                return Err(TransactionError::FundsImmature {
                    immature: candidates.immature_atoms,
                    required,
                });
            }
            return Err(TransactionError::InsufficientFunds {
                available: candidates.available_atoms,
                required,
            });
        }

        let change_atoms = selected_value - required;
        let mut outputs = vec![TxOutput {
            value: amount_atoms,
            destination: recipient,
            spendable_height: next_height,
        }];
        if change_atoms > 0 {
            outputs.push(TxOutput {
                value: change_atoms,
                destination: self.owner,
                spendable_height: next_height,
            });
        }
        if outputs.len() > MAX_TRANSACTION_OUTPUTS {
            return Err(TransactionError::InvalidPlan);
        }
        let transaction = Transaction {
            network_id: self.network.id,
            version: TRANSACTION_VERSION,
            inputs: selected
                .iter()
                .copied()
                .map(|previous| TxInput {
                    previous,
                    public_key: self.owner,
                    signature: Vec::new(),
                })
                .collect(),
            outputs,
        };
        let plan = PaymentPlan {
            transaction,
            recipient,
            amount_atoms,
            fee_atoms,
            change_atoms,
            input_atoms: selected_value,
            selected,
            output_spendable_height: next_height,
        };
        validate_plan(&plan, self.owner, self.network)?;
        let signed_size = encoded_size_with_signatures(&plan.transaction)?;
        if fee_atoms < required_relay_fee(signed_size, self.network) {
            return Err(TransactionError::FeeTooLow);
        }
        Ok(plan)
    }

    /// Computes the planner-backed spending ceiling without signing or broadcasting.
    ///
    /// `available_atoms` includes every otherwise-spendable UTXO, while
    /// `maximum_atoms` is deliberately capped by the consensus input limit.
    pub fn spending_limit(
        self,
        next_height: u64,
        utxos: &[Utxo],
    ) -> Result<SpendingLimit, TransactionError> {
        let candidates = self.spendable_candidates(next_height, utxos)?;
        let selected_inputs = candidates.entries.len().min(MAX_TRANSACTION_INPUTS);
        let selectable_atoms = candidates
            .entries
            .iter()
            .take(MAX_TRANSACTION_INPUTS)
            .try_fold(0_u64, |sum, (_, value)| checked_add(sum, *value))?;
        let fee_atoms = self.network.minimum_fee_atoms;
        let maximum_atoms = selectable_atoms.saturating_sub(fee_atoms);

        if maximum_atoms > 0 {
            let recipient = AddressCodec::mainnet().render(&self.owner);
            let plan = self.plan(&recipient, maximum_atoms, fee_atoms, next_height, utxos)?;
            if plan.input_atoms != selectable_atoms
                || plan.fee_atoms != fee_atoms
                || plan.change_atoms != 0
                || plan.selected.len() != selected_inputs
            {
                return Err(TransactionError::InvalidPlan);
            }
        }

        Ok(SpendingLimit {
            available_atoms: candidates.available_atoms,
            fee_atoms,
            maximum_atoms,
            selected_inputs,
        })
    }

    fn spendable_candidates(
        self,
        next_height: u64,
        utxos: &[Utxo],
    ) -> Result<SpendableCandidates, TransactionError> {
        let mut candidates = Vec::new();
        let mut immature = 0_u64;
        for utxo in utxos {
            VerifyingKey::from_bytes((&utxo.destination).into())
                .map_err(|_| TransactionError::InvalidUtxoOwner)?;
            if utxo.destination != self.owner || utxo.known_spent || utxo.locally_reserved {
                continue;
            }
            if next_height < utxo.spendable_height {
                immature = checked_add(immature, utxo.value_atoms)?;
            } else {
                candidates.push((utxo.outpoint, utxo.value_atoms));
            }
        }
        let available = candidates
            .iter()
            .try_fold(0_u64, |sum, (_, value)| checked_add(sum, *value))?;
        candidates.sort_unstable_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.0.txid.cmp(&right.0.txid))
                .then_with(|| left.0.index.cmp(&right.0.index))
        });
        Ok(SpendableCandidates {
            entries: candidates,
            available_atoms: available,
            immature_atoms: immature,
        })
    }
}

pub(crate) fn sign_plan(
    plan: &PaymentPlan,
    signing_key: &SigningKey,
) -> Result<SignedTransaction, TransactionError> {
    let owner: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    validate_plan(plan, owner, MAINNET)?;
    let signing_digest = plan.transaction.signing_digest();
    let signature: Signature = signing_key.sign(&signing_digest);
    let mut transaction = plan.transaction.clone();
    for input in &mut transaction.inputs {
        if input.public_key != owner {
            return Err(TransactionError::WrongSigningKey);
        }
        input.signature = signature.to_bytes().to_vec();
    }
    if transaction.signing_digest() != signing_digest {
        return Err(TransactionError::InvalidPlan);
    }
    for input in &transaction.inputs {
        let signature = Signature::try_from(input.signature.as_slice())
            .map_err(|_| TransactionError::InvalidPlan)?;
        signing_key
            .verifying_key()
            .verify(&signing_digest, &signature)
            .map_err(|_| TransactionError::InvalidPlan)?;
    }
    let frame = encode_transaction(&transaction)?;
    if plan.fee_atoms < required_relay_fee(frame.len(), MAINNET) {
        return Err(TransactionError::FeeTooLow);
    }
    Ok(SignedTransaction {
        txid: transaction.txid(),
        signing_digest,
        frame,
    })
}

fn validate_plan(
    plan: &PaymentPlan,
    owner: [u8; 32],
    network: Network,
) -> Result<(), TransactionError> {
    if plan.amount_atoms == 0
        || plan.fee_atoms < network.minimum_fee_atoms
        || plan.transaction.network_id != network.id
        || plan.transaction.version != TRANSACTION_VERSION
        || plan.transaction.inputs.is_empty()
        || plan.transaction.inputs.len() > MAX_TRANSACTION_INPUTS
        || plan.transaction.inputs.len() != plan.selected.len()
        || plan.transaction.outputs.is_empty()
        || plan.transaction.outputs.len() > MAX_TRANSACTION_OUTPUTS
    {
        return Err(TransactionError::InvalidPlan);
    }
    let mut seen = HashSet::new();
    for (input, selected) in plan.transaction.inputs.iter().zip(&plan.selected) {
        if input.previous != *selected
            || input.public_key != owner
            || !input.signature.is_empty()
            || !seen.insert(input.previous)
        {
            return Err(TransactionError::InvalidPlan);
        }
    }
    let required = plan
        .amount_atoms
        .checked_add(plan.fee_atoms)
        .ok_or(TransactionError::AmountOverflow)?;
    if plan.input_atoms.checked_sub(required) != Some(plan.change_atoms) {
        return Err(TransactionError::InvalidPlan);
    }
    let expected_outputs = if plan.change_atoms == 0 { 1 } else { 2 };
    if plan.transaction.outputs.len() != expected_outputs {
        return Err(TransactionError::InvalidPlan);
    }
    let recipient = &plan.transaction.outputs[0];
    if recipient.value != plan.amount_atoms
        || recipient.destination != plan.recipient
        || recipient.spendable_height != plan.output_spendable_height
    {
        return Err(TransactionError::InvalidPlan);
    }
    if let Some(change) = plan.transaction.outputs.get(1)
        && (change.value != plan.change_atoms
            || change.destination != owner
            || change.spendable_height != plan.output_spendable_height)
    {
        return Err(TransactionError::InvalidPlan);
    }
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, TransactionError> {
    left.checked_add(right)
        .ok_or(TransactionError::AmountOverflow)
}

fn required_relay_fee(encoded_bytes: usize, network: Network) -> u64 {
    let kib = encoded_bytes.saturating_add(1023) / 1024;
    u64::try_from(kib)
        .ok()
        .and_then(|kib| kib.checked_mul(MIN_RELAY_FEE_PER_KIB))
        .unwrap_or(u64::MAX)
        .max(MIN_RELAY_FEE_PER_KIB)
        .max(network.minimum_fee_atoms)
}

fn encoded_size_with_signatures(transaction: &Transaction) -> Result<usize, TransactionError> {
    let mut sized = transaction.clone();
    for input in &mut sized.inputs {
        input.signature.resize(CONSENSUS_SIGNATURE_BYTES, 0);
    }
    encode_transaction(&sized).map(|frame| frame.len())
}

fn encode_unsigned_transaction(transaction: &Transaction, hasher: &mut Hasher) {
    hasher.update(&transaction.network_id);
    hasher.update(&transaction.version.to_le_bytes());
    hasher.update(&(transaction.inputs.len() as u64).to_le_bytes());
    for input in &transaction.inputs {
        hasher.update(&input.previous.txid);
        hasher.update(&input.previous.index.to_le_bytes());
        encode_witness(input, false, hasher);
    }
    hasher.update(&(transaction.outputs.len() as u64).to_le_bytes());
    for output in &transaction.outputs {
        hasher.update(&output.value.to_le_bytes());
        hasher.update(&[KEY_OUTPUT_TAG]);
        hasher.update(&output.destination);
        hasher.update(&output.spendable_height.to_le_bytes());
    }
}

fn encode_witness(input: &TxInput, include_signature: bool, hasher: &mut Hasher) {
    hasher.update(&[KEY_WITNESS_TAG]);
    hasher.update(&input.public_key);
    if include_signature {
        hasher.update(&(input.signature.len() as u64).to_le_bytes());
        hasher.update(&input.signature);
    }
}

fn network_magic(network_id: &[u8; 32]) -> [u8; 4] {
    let mut hasher = Hasher::new_derive_key(NETWORK_MAGIC_DOMAIN);
    hasher.update(network_id);
    let digest = hasher.finalize();
    digest.as_bytes()[..4].try_into().expect("four-byte slice")
}

fn encode_transaction(transaction: &Transaction) -> Result<Vec<u8>, TransactionError> {
    if transaction.inputs.is_empty()
        || transaction.inputs.len() > MAX_TRANSACTION_INPUTS
        || transaction.outputs.is_empty()
        || transaction.outputs.len() > MAX_TRANSACTION_OUTPUTS
    {
        return Err(TransactionError::InvalidPlan);
    }
    let mut payload = Writer::default();
    payload.bytes(&transaction.network_id);
    payload.u32(transaction.version);
    payload.u32(transaction.inputs.len() as u32);
    for input in &transaction.inputs {
        if input.signature.len() != CONSENSUS_SIGNATURE_BYTES {
            return Err(TransactionError::InvalidPlan);
        }
        payload.bytes(&input.previous.txid);
        payload.u32(input.previous.index);
        payload.u8(KEY_WITNESS_TAG);
        payload.bytes(&input.public_key);
        payload.bytes(&input.signature);
    }
    payload.u32(transaction.outputs.len() as u32);
    for output in &transaction.outputs {
        if output.value == 0 {
            return Err(TransactionError::InvalidPlan);
        }
        payload.u64(output.value);
        payload.u8(KEY_OUTPUT_TAG);
        payload.bytes(&output.destination);
        payload.u64(output.spendable_height);
    }
    let payload = payload.finish();
    let total = 16_usize
        .checked_add(payload.len())
        .ok_or(TransactionError::TooLarge)?;
    if total > MAX_TRANSACTION_BYTES {
        return Err(TransactionError::TooLarge);
    }
    let mut frame = Writer::default();
    frame.bytes(&FRAME_MAGIC);
    frame.bytes(&network_magic(&transaction.network_id));
    frame.u16(WIRE_VERSION);
    frame.u8(TRANSACTION_KIND);
    frame.u8(0);
    frame.u32(payload.len() as u32);
    frame.bytes(&payload);
    Ok(frame.finish())
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingState {
    Prepared,
    BroadcastUnknown,
    Accepted,
    Confirmed,
    Conflicted,
    Dropped,
}

impl PendingState {
    fn reserves_inputs(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::BroadcastUnknown | Self::Accepted
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingRecord {
    txid: Option<[u8; 32]>,
    inputs: Vec<OutPoint>,
    state: PendingState,
}

/// Local, non-authoritative protection against duplicate submissions.
///
/// An ambiguous network response keeps inputs reserved. The caller must query
/// the original txid and reconcile it; this type never asks for an automatic
/// replacement transaction.
#[derive(Debug, Default)]
pub struct PendingRegistry {
    by_intent: HashMap<[u8; 32], PendingRecord>,
}

impl PendingRegistry {
    pub fn reserve(&mut self, plan: &PaymentPlan) -> Result<[u8; 32], TransactionError> {
        let intent = plan.signing_digest();
        if self.by_intent.contains_key(&intent) {
            return Err(TransactionError::DuplicateIntent);
        }
        let already_reserved: HashSet<_> = self
            .by_intent
            .values()
            .filter(|record| record.state.reserves_inputs())
            .flat_map(|record| record.inputs.iter().copied())
            .collect();
        if plan
            .selected
            .iter()
            .any(|outpoint| already_reserved.contains(outpoint))
        {
            return Err(TransactionError::ReservationConflict);
        }
        self.by_intent.insert(
            intent,
            PendingRecord {
                txid: None,
                inputs: plan.selected.clone(),
                state: PendingState::Prepared,
            },
        );
        Ok(intent)
    }

    pub fn attach_signed(
        &mut self,
        intent: [u8; 32],
        transaction: &SignedTransaction,
    ) -> Result<(), TransactionError> {
        if transaction.signing_digest != intent {
            return Err(TransactionError::ReservationMismatch);
        }
        let record = self
            .by_intent
            .get_mut(&intent)
            .ok_or(TransactionError::ReservationMismatch)?;
        record.txid = Some(transaction.txid);
        Ok(())
    }

    pub fn mark_broadcast_unknown(&mut self, txid: [u8; 32]) -> Result<(), TransactionError> {
        self.update_txid(txid, PendingState::BroadcastUnknown)
    }

    pub fn mark_accepted(&mut self, txid: [u8; 32]) -> Result<(), TransactionError> {
        self.update_txid(txid, PendingState::Accepted)
    }

    pub fn reconcile(
        &mut self,
        txid: [u8; 32],
        state: PendingState,
    ) -> Result<(), TransactionError> {
        self.update_txid(txid, state)
    }

    pub fn reserved_inputs(&self) -> HashSet<OutPoint> {
        self.by_intent
            .values()
            .filter(|record| record.state.reserves_inputs())
            .flat_map(|record| record.inputs.iter().copied())
            .collect()
    }

    fn update_txid(&mut self, txid: [u8; 32], state: PendingState) -> Result<(), TransactionError> {
        let record = self
            .by_intent
            .values_mut()
            .find(|record| record.txid == Some(txid))
            .ok_or(TransactionError::UnknownPendingTransaction)?;
        record.state = state;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::encode;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes((&[byte; 32]).into()).unwrap()
    }

    fn owner(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes().into()
    }

    fn utxo(marker: u8, value_atoms: u64, owner: [u8; 32]) -> Utxo {
        Utxo {
            outpoint: OutPoint {
                txid: [marker; 32],
                index: u32::from(marker),
            },
            value_atoms,
            destination: owner,
            spendable_height: 100,
            known_spent: false,
            locally_reserved: false,
        }
    }

    #[test]
    fn plans_signs_and_encodes_an_official_key_payment() {
        let sender = key(0x31);
        let recipient = owner(&key(0x41));
        let mut coins = vec![
            utxo(1, 90_000_000, owner(&sender)),
            utxo(2, 50_000_000, owner(&sender)),
        ];
        coins.push(Utxo {
            spendable_height: 500,
            ..utxo(3, 500_000_000, owner(&sender))
        });
        coins.push(Utxo {
            locally_reserved: true,
            ..utxo(4, 600_000_000, owner(&sender))
        });
        let plan = PaymentPlanner::mainnet(owner(&sender))
            .unwrap()
            .plan(
                &encode("cmfd", &recipient),
                100_000_000,
                10_000_000,
                101,
                &coins,
            )
            .unwrap();
        assert_eq!(plan.input_atoms, 140_000_000);
        assert_eq!(plan.change_atoms, 30_000_000);
        assert_eq!(plan.selected.len(), 2);
        let signed = sign_plan(&plan, &sender).unwrap();
        assert_eq!(&signed.frame[..4], b"CMFD");
        assert_eq!(signed.frame.len(), 424);
        assert_eq!(signed.txid.len(), 32);
    }

    #[test]
    fn planner_builds_the_same_payment_for_bech32m_and_hex_recipient_forms() {
        let sender = key(0x31);
        let sender_destination = owner(&sender);
        let coins = vec![utxo(1, 100_000_000, sender_destination)];
        let recipient = owner(&key(0x32));
        let recipient_hex = hex::encode(recipient);
        let recipient_bech32m = encode("cmfd", &recipient);
        let planner = PaymentPlanner::mainnet(sender_destination).unwrap();
        let bech32m_plan = planner
            .plan(&recipient_bech32m, 30_000_000, 10_000_000, 101, &coins)
            .unwrap();
        let hex_plan = planner
            .plan(&recipient_hex, 30_000_000, 10_000_000, 101, &coins)
            .unwrap();

        assert_eq!(bech32m_plan.recipient, hex_plan.recipient);
        assert_eq!(bech32m_plan.amount_atoms, hex_plan.amount_atoms);
        assert_eq!(bech32m_plan.fee_atoms, hex_plan.fee_atoms);
        assert_eq!(bech32m_plan.change_atoms, hex_plan.change_atoms);
        assert_eq!(bech32m_plan.selected, hex_plan.selected);
        assert_eq!(bech32m_plan.signing_digest(), hex_plan.signing_digest());
    }

    #[test]
    fn matches_official_v1_0_16_transaction_vector() {
        // Generated independently with cmfd-consensus v1.0.16 at commit
        // e5f0cda2be60b9f7ee8d7f13bbeb9856d2edcf17.
        let sender = key(7);
        let sender_destination = owner(&sender);
        let recipient = owner(&key(9));
        let coins = vec![
            Utxo {
                outpoint: OutPoint {
                    txid: [1_u8; 32],
                    index: 2,
                },
                value_atoms: 100_000_000,
                destination: sender_destination,
                spendable_height: 1,
                known_spent: false,
                locally_reserved: false,
            },
            Utxo {
                outpoint: OutPoint {
                    txid: [2_u8; 32],
                    index: 0,
                },
                value_atoms: 70_000_000,
                destination: sender_destination,
                spendable_height: 1,
                known_spent: false,
                locally_reserved: false,
            },
        ];
        let plan = PaymentPlanner::mainnet(sender_destination)
            .unwrap()
            .plan(
                &encode("cmfd", &recipient),
                150_000_000,
                10_000_000,
                27,
                &coins,
            )
            .unwrap();
        assert_eq!(
            hex::encode(plan.signing_digest()),
            "cf98aaf8c45440a06ab13292d487c4c9028928d1a31d29a2dc9cd3e49e91efbd"
        );

        let signed = sign_plan(&plan, &sender).unwrap();
        assert_eq!(
            signed.txid_hex(),
            "e23d6752ca6dbcdc8c5cbdb11cbf458003c0aace79a197f0067c48e2b2d8b681"
        );
        assert_eq!(
            signed.frame_hex(),
            concat!(
                "434d46446702973f010001009801000088296bc39c10e8bc1dd4818d4d42412f",
                "e5f08210651110377f495da299812f6201000000020000000101010101010101",
                "0101010101010101010101010101010101010101010101010200000000989c0b",
                "76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fd1e46b",
                "efa5597b9b62103f4dbd37e0f9ee0ae93accd424cf8888336461cd1ce3a2784c",
                "eccee85178a42a2103d7c77d7961f039fb199714dd74f6daf454fa7013020202",
                "0202020202020202020202020202020202020202020202020202020202000000",
                "0000989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e0",
                "5f6fd1e46befa5597b9b62103f4dbd37e0f9ee0ae93accd424cf8888336461cd",
                "1ce3a2784ceccee85178a42a2103d7c77d7961f039fb199714dd74f6daf454fa7",
                "0130200000080d1f008000000000056b328b30c8bf5839e24058747879408bd",
                "b36241dc9c2e7c619faa12b29209671b00000000000000809698000000000000",
                "989c",
                "0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f1b00",
                "000000000000"
            )
        );
    }

    #[test]
    fn rejects_invalid_amount_fee_network_and_unavailable_funds() {
        let sender = key(0x21);
        let recipient = owner(&key(0x22));
        let planner = PaymentPlanner::mainnet(owner(&sender)).unwrap();
        let address = encode("cmfd", &recipient);
        let coins = vec![utxo(1, 20_000_000, owner(&sender))];
        assert_eq!(
            planner.plan(&address, 0, 10_000_000, 1, &coins),
            Err(TransactionError::ZeroAmount)
        );
        assert_eq!(
            planner.plan(&address, 1, 9_999_999, 1, &coins),
            Err(TransactionError::FeeTooLow)
        );
        assert_eq!(
            planner.plan(&encode("tcmfd", &recipient), 1, 10_000_000, 1, &coins),
            Err(TransactionError::WrongNetwork)
        );
        assert!(matches!(
            planner.plan(&address, 20_000_000, 10_000_000, 1, &coins),
            Err(TransactionError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn permits_the_consensus_minimum_one_atom_payment_with_exact_change() {
        let sender = key(0x25);
        let recipient = encode("cmfd", &owner(&key(0x26)));
        let coins = vec![utxo(1, 20_000_001, owner(&sender))];
        let plan = PaymentPlanner::mainnet(owner(&sender))
            .unwrap()
            .plan(&recipient, 1, 10_000_000, 101, &coins)
            .unwrap();
        assert_eq!(plan.amount_atoms, 1);
        assert_eq!(plan.fee_atoms, 10_000_000);
        assert_eq!(plan.change_atoms, 10_000_000);
        assert_eq!(sign_plan(&plan, &sender).unwrap().frame.len(), 291);
    }

    #[test]
    fn spending_limit_reports_available_fee_and_exact_maximum() {
        let sender = key(0x27);
        let destination = owner(&sender);
        let limit = PaymentPlanner::mainnet(destination)
            .unwrap()
            .spending_limit(101, &[utxo(1, 70_000_000, destination)])
            .unwrap();

        assert_eq!(limit.available_atoms, 70_000_000);
        assert_eq!(limit.fee_atoms, 10_000_000);
        assert_eq!(limit.maximum_atoms, 60_000_000);
        assert_eq!(limit.selected_inputs, 1);
    }

    #[test]
    fn spending_limit_excludes_immature_reserved_spent_and_foreign_funds() {
        let sender = key(0x28);
        let destination = owner(&sender);
        let coins = vec![
            utxo(1, 70_000_000, destination),
            Utxo {
                spendable_height: 102,
                ..utxo(2, 80_000_000, destination)
            },
            Utxo {
                locally_reserved: true,
                ..utxo(3, 90_000_000, destination)
            },
            Utxo {
                known_spent: true,
                ..utxo(4, 100_000_000, destination)
            },
            utxo(5, 110_000_000, owner(&key(0x29))),
        ];
        let limit = PaymentPlanner::mainnet(destination)
            .unwrap()
            .spending_limit(101, &coins)
            .unwrap();

        assert_eq!(limit.available_atoms, 70_000_000);
        assert_eq!(limit.maximum_atoms, 60_000_000);
        assert_eq!(limit.selected_inputs, 1);
    }

    #[test]
    fn spending_limit_caps_the_maximum_at_128_inputs_and_fails_closed_below_the_fee() {
        let sender = key(0x2a);
        let destination = owner(&sender);
        let many = (0..129)
            .map(|index| Utxo {
                outpoint: OutPoint {
                    txid: {
                        let mut id = [0_u8; 32];
                        id[..8].copy_from_slice(&(index as u64).to_be_bytes());
                        id
                    },
                    index: 0,
                },
                value_atoms: 1_000_000,
                destination,
                spendable_height: 1,
                known_spent: false,
                locally_reserved: false,
            })
            .collect::<Vec<_>>();
        let limited = PaymentPlanner::mainnet(destination)
            .unwrap()
            .spending_limit(2, &many)
            .unwrap();
        assert_eq!(limited.available_atoms, 129_000_000);
        assert_eq!(limited.maximum_atoms, 118_000_000);
        assert_eq!(limited.selected_inputs, 128);

        let below_fee = PaymentPlanner::mainnet(destination)
            .unwrap()
            .spending_limit(101, &[utxo(1, 9_000_000, destination)])
            .unwrap();
        assert_eq!(below_fee.available_atoms, 9_000_000);
        assert_eq!(below_fee.fee_atoms, 10_000_000);
        assert_eq!(below_fee.maximum_atoms, 0);
    }

    #[test]
    fn immature_and_input_limit_have_distinct_failures() {
        let sender = key(0x23);
        let recipient = encode("cmfd", &owner(&key(0x24)));
        let immature = vec![Utxo {
            spendable_height: 102,
            ..utxo(1, 20_000_000, owner(&sender))
        }];
        assert!(matches!(
            PaymentPlanner::mainnet(owner(&sender))
                .unwrap()
                .plan(&recipient, 1, 10_000_000, 101, &immature),
            Err(TransactionError::FundsImmature { .. })
        ));

        let many = (0..129)
            .map(|index| Utxo {
                outpoint: OutPoint {
                    txid: {
                        let mut id = [0_u8; 32];
                        id[..8].copy_from_slice(&(index as u64).to_be_bytes());
                        id
                    },
                    index: 0,
                },
                value_atoms: 100_000,
                destination: owner(&sender),
                spendable_height: 1,
                known_spent: false,
                locally_reserved: false,
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            PaymentPlanner::mainnet(owner(&sender))
                .unwrap()
                .plan(&recipient, 2_850_000, 10_000_000, 2, &many),
            Err(TransactionError::InputLimit { .. })
        ));
    }

    #[test]
    fn ambiguous_broadcast_keeps_inputs_reserved_and_blocks_duplicates() {
        let sender = key(0x25);
        let recipient = encode("cmfd", &owner(&key(0x26)));
        let coins = vec![utxo(1, 30_000_000, owner(&sender))];
        let plan = PaymentPlanner::mainnet(owner(&sender))
            .unwrap()
            .plan(&recipient, 10_000_000, 10_000_000, 101, &coins)
            .unwrap();
        let signed = sign_plan(&plan, &sender).unwrap();
        let mut pending = PendingRegistry::default();
        let intent = pending.reserve(&plan).unwrap();
        pending.attach_signed(intent, &signed).unwrap();
        pending.mark_broadcast_unknown(signed.txid).unwrap();
        assert_eq!(
            pending.reserved_inputs(),
            HashSet::from([coins[0].outpoint])
        );
        assert_eq!(
            pending.reserve(&plan),
            Err(TransactionError::DuplicateIntent)
        );
        pending
            .reconcile(signed.txid, PendingState::Conflicted)
            .unwrap();
        assert!(pending.reserved_inputs().is_empty());
    }
}
