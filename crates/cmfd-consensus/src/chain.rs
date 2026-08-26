use std::collections::{HashMap, HashSet};

use blake3::Hasher;
use cmfd_marketplace::{ChannelError, ChannelTerms, Settlement};
use k256::schnorr::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BlockChallenge, BlockProof, BlockValidationContext, CONSENSUS_SIGNATURE_BYTES, CoinbaseClaim,
    ConsensusPowVerifier, DifficultyError, EconomicsError, FixedRewardDestinations,
    ForgeMatrixError, HeaderWork, MAX_BLOCK_AGGREGATE_INPUTS, MAX_BLOCK_AGGREGATE_OUTPUTS,
    MAX_BLOCK_SIGNATURE_CHECKS, MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS,
    MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS, NetworkError, NetworkParams, PowError,
    PreverifiedBlockProof, next_work_target,
};

mod state_delta;

pub use state_delta::{
    DecodedReversibleStateDelta, MAX_REVERSIBLE_STATE_DELTA_BYTES, ReversibleStateDeltaCapability,
    ReversibleStateDeltaError, ValidatedReversibleStateDelta,
};

const TX_SIGNING_DOMAIN: &str = "CMFD/TRANSACTION/SIGNING/V1";
const TX_ID_DOMAIN: &str = "CMFD/TRANSACTION/ID/V1";
const COINBASE_ID_DOMAIN: &str = "CMFD/COINBASE/ID/V1";
const MERKLE_LEAF_DOMAIN: &str = "CMFD/MERKLE/LEAF/V1";
const MERKLE_NODE_DOMAIN: &str = "CMFD/MERKLE/NODE/V1";
const MERKLE_ROOT_DOMAIN: &str = "CMFD/TRANSACTION-MERKLE/ROOT/V2";
const BLOCK_ID_DOMAIN: &str = "CMFD/BLOCK/ID/V1";
const COINBASE_OUTPOINT_DOMAIN: &str = "CMFD/COINBASE/OUTPOINT/V1";

pub const COINBASE_MATURITY: u64 = 100;
pub const BLOCK_VERSION: u32 = 1;
pub const TRANSACTION_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    pub value: u64,
    pub lock: OutputLock,
    pub spendable_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputLock {
    Key([u8; 32]),
    InferenceChannel { channel_id: [u8; 32] },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    pub previous: OutPoint,
    pub witness: InputWitness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputWitness {
    Key {
        public_key: [u8; 32],
        signature: Vec<u8>,
    },
    InferenceSettlement {
        terms: ChannelTerms,
        settlement: Settlement,
    },
    InferenceRefund {
        terms: ChannelTerms,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub network_id: [u8; 32],
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coinbase {
    pub height: u64,
    pub outputs: Vec<TxOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub version: u32,
    pub challenge: BlockChallenge,
    pub proof: BlockProof,
    pub coinbase: Coinbase,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, Default)]
pub struct UtxoSet {
    outputs: HashMap<OutPoint, TxOutput>,
    active_channels: HashSet<[u8; 32]>,
    retired_channels: HashSet<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutputChange {
    previous: Option<TxOutput>,
    next: Option<TxOutput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MembershipChange {
    previous: bool,
    next: bool,
}

/// A block-local state transition. Each map contains only keys touched while
/// validating the block, together with the value needed to reject a stale
/// commit and to support a future undo journal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct UtxoDelta {
    outputs: HashMap<OutPoint, OutputChange>,
    active_channels: HashMap<[u8; 32], MembershipChange>,
    retired_channels: HashMap<[u8; 32], MembershipChange>,
}

struct UtxoOverlay<'a> {
    base: &'a UtxoSet,
    delta: UtxoDelta,
}

#[derive(Debug, Clone)]
pub struct ChainState {
    params: NetworkParams,
    utxos: UtxoSet,
    history: Vec<HeaderWork>,
    raw_timestamps: Vec<u64>,
    tip: [u8; 32],
    next_height: u64,
    verifier: ConsensusPowVerifier,
}

/// A fully checked, non-mutating successor transition for [`ChainState`].
///
/// The token owns only the UTXOs and channel memberships touched by the block.
/// It can therefore be held while the caller durably records the block, then
/// consumed by [`ChainState::commit_validated`] without cloning chain state.
#[derive(Debug)]
pub struct ValidatedBlock {
    params: NetworkParams,
    base_tip: [u8; 32],
    base_next_height: u64,
    base_expected_target: [u8; 32],
    base_median_time_past: u64,
    base_history_len: usize,
    base_timestamp_len: usize,
    delta: UtxoDelta,
    fees: u64,
    timestamp: u64,
    effective_timestamp: u64,
    target: [u8; 32],
    next_tip: [u8; 32],
    next_height: u64,
}

/// The exact resource use and fee burn for a transaction set validated for
/// inclusion in the next block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionSetValidation {
    pub total_burned_fees: u64,
    pub aggregate_inputs: usize,
    pub aggregate_outputs: usize,
    pub signature_checks: usize,
}

/// Compact consensus state needed to reject an impossible successor header
/// without replaying the owning branch. The fields stay private so callers
/// cannot manufacture or reinterpret this snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuccessorHeaderPreflight {
    params: NetworkParams,
    tip: [u8; 32],
    next_height: u64,
    median_time_past: u64,
    expected_target: [u8; 32],
}

impl SuccessorHeaderPreflight {
    pub fn preflight_block(
        self,
        block: &Block,
        context: BlockValidationContext,
    ) -> Result<(), ChainError> {
        self.preflight_block_values(block, context).map(drop)
    }

    fn preflight_block_values(
        self,
        block: &Block,
        context: BlockValidationContext,
    ) -> Result<(u64, [u8; 32]), ChainError> {
        if block.version != BLOCK_VERSION {
            return Err(ChainError::UnsupportedBlockVersion);
        }
        if block.challenge.network_id != self.params.network_id {
            return Err(ChainError::WrongNetwork);
        }
        if block.challenge.height != self.next_height {
            return Err(ChainError::UnexpectedHeight {
                expected: self.next_height,
                actual: block.challenge.height,
            });
        }
        let next_height = self
            .next_height
            .checked_add(1)
            .ok_or(ChainError::HeightExhausted)?;
        block
            .challenge
            .height
            .checked_add(COINBASE_MATURITY)
            .ok_or(ChainError::HeightExhausted)?;
        if block.challenge.previous_block != self.tip {
            return Err(ChainError::PreviousBlock);
        }
        if block.challenge.timestamp <= self.median_time_past {
            return Err(ChainError::TimestampNotAfterMedian);
        }
        let maximum_timestamp = context
            .now_unix_seconds
            .checked_add(self.params.max_future_offset_secs)
            .ok_or(ChainError::InvalidValidationTime)?;
        if block.challenge.timestamp > maximum_timestamp {
            return Err(ChainError::TimestampTooFarInFuture);
        }
        if block.challenge.target != self.expected_target {
            return Err(ChainError::UnexpectedTarget);
        }
        Ok((next_height, self.expected_target))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("network parameters are invalid: {0}")]
    Network(#[from] NetworkError),
    #[error("ForgeMatrix proof failed: {0}")]
    Proof(#[from] ForgeMatrixError),
    #[error("ForgeMatrix v2 proof failed validation")]
    InvalidV2Proof,
    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[error("ForgeMatrix Dory v3 candidate proof failed validation")]
    InvalidV3Proof,
    #[error("block proof type does not match the configured proof-of-work algorithm")]
    WrongProofType,
    #[error("proof verifier identity does not match the immutable network parameters")]
    PowParameterMismatch,
    #[error("preverified proof capability does not match this exact block")]
    PreverifiedProofMismatch,
    #[error("process-local proof capability entropy is unavailable")]
    PreverificationUnavailable,
    #[error("economics validation failed: {0}")]
    Economics(#[from] EconomicsError),
    #[error("inference channel validation failed: {0}")]
    Channel(#[from] ChannelError),
    #[error("difficulty calculation failed: {0}")]
    Difficulty(#[from] DifficultyError),
    #[error("unexpected block height: expected {expected}, received {actual}")]
    UnexpectedHeight { expected: u64, actual: u64 },
    #[error("block belongs to another network")]
    WrongNetwork,
    #[error("unsupported block version")]
    UnsupportedBlockVersion,
    #[error("unsupported transaction version")]
    UnsupportedTransactionVersion,
    #[error("previous block does not match the active chain tip")]
    PreviousBlock,
    #[error("validated block no longer applies to the active chain state")]
    StaleValidatedBlock,
    #[error("block target does not equal the independently derived chain target")]
    UnexpectedTarget,
    #[error("block timestamp must be greater than median time past")]
    TimestampNotAfterMedian,
    #[error("block timestamp is too far in the future")]
    TimestampTooFarInFuture,
    #[error("validation time plus the configured future offset overflowed")]
    InvalidValidationTime,
    #[error("block height and challenge height differ")]
    HeightMismatch,
    #[error("transaction Merkle root mismatch")]
    MerkleRoot,
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("zero-value outputs are not permitted")]
    ZeroValueOutput,
    #[error("input references a missing output")]
    MissingInput,
    #[error("an output is spent more than once in the block")]
    DuplicateInput,
    #[error("input is locked until height {0}")]
    ImmatureInput(u64),
    #[error("input public key does not own the referenced output")]
    WrongOwner,
    #[error("input witness cannot spend the referenced output lock")]
    WrongWitness,
    #[error("malformed Schnorr public key or signature")]
    MalformedSignature,
    #[error("Schnorr signature is invalid")]
    InvalidSignature,
    #[error("transaction outputs exceed transaction inputs")]
    CreatesValue,
    #[error("amount arithmetic overflow")]
    AmountOverflow,
    #[error("block height leaves no representable coinbase maturity or successor height")]
    HeightExhausted,
    #[error("coinbase layout or destination is invalid")]
    CoinbaseLayout,
    #[error("transaction id collision")]
    TxidCollision,
    #[error("an inference channel identifier cannot be reused")]
    DuplicateChannel,
    #[error("inference channel funding value does not match its signed terms")]
    ChannelDeposit,
    #[error("an inference channel close must have one input and its exact consensus outputs")]
    ChannelCloseShape,
    #[error("block contains too many transactions")]
    BlockTransactionLimit,
    #[error("transaction contains too many inputs")]
    TransactionInputLimit,
    #[error("transaction contains too many outputs")]
    TransactionOutputLimit,
    #[error("block exceeds an aggregate input or output limit")]
    BlockAggregateLimit,
    #[error("block exceeds the signature verification limit")]
    BlockSignatureLimit,
    #[error("coinbase contains too many outputs")]
    CoinbaseOutputLimit,
    #[error("consensus signatures must use the canonical 64-byte encoding")]
    SignatureLength,
    #[error("block does not have a canonical bounded wire encoding")]
    BlockEncoding,
}

impl Transaction {
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(TX_SIGNING_DOMAIN);
        encode_unsigned_transaction(self, &mut hasher);
        *hasher.finalize().as_bytes()
    }

    pub fn txid(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(TX_ID_DOMAIN);
        encode_unsigned_transaction(self, &mut hasher);
        for input in &self.inputs {
            encode_witness(&input.witness, true, &mut hasher);
        }
        *hasher.finalize().as_bytes()
    }

    pub fn sign_all(&mut self, keys: &[&SigningKey]) -> Result<(), ChainError> {
        if keys.len() != self.inputs.len() {
            return Err(ChainError::MalformedSignature);
        }
        for (input, key) in self.inputs.iter_mut().zip(keys) {
            let InputWitness::Key {
                public_key,
                signature,
            } = &mut input.witness
            else {
                return Err(ChainError::WrongWitness);
            };
            public_key.copy_from_slice(key.verifying_key().to_bytes().as_ref());
            signature.clear();
        }
        let digest = self.signing_digest();
        for (input, key) in self.inputs.iter_mut().zip(keys) {
            let signature: Signature = key.sign(&digest);
            let InputWitness::Key {
                signature: witness_signature,
                ..
            } = &mut input.witness
            else {
                return Err(ChainError::WrongWitness);
            };
            *witness_signature = signature.to_bytes().to_vec();
        }
        Ok(())
    }
}

impl Coinbase {
    pub fn new(
        height: u64,
        allocation: crate::Allocation,
        miner_destination: [u8; 32],
        fixed_destinations: FixedRewardDestinations,
    ) -> Self {
        let mut outputs = vec![TxOutput {
            value: allocation.miner,
            lock: OutputLock::Key(miner_destination),
            spendable_height: height.saturating_add(COINBASE_MATURITY),
        }];
        if allocation.steward > 0 {
            outputs.push(TxOutput {
                value: allocation.steward,
                lock: OutputLock::Key(fixed_destinations.steward),
                spendable_height: height,
            });
        }
        if allocation.community > 0 {
            outputs.push(TxOutput {
                value: allocation.community,
                lock: OutputLock::Key(fixed_destinations.community),
                spendable_height: height,
            });
        }
        Self { height, outputs }
    }

    /// Commitment used in the transaction Merkle tree before proof-of-work is known.
    pub fn commitment(&self, network_id: [u8; 32]) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(COINBASE_ID_DOMAIN);
        hasher.update(&network_id);
        hasher.update(&self.height.to_le_bytes());
        encode_outputs(&self.outputs, &mut hasher);
        *hasher.finalize().as_bytes()
    }
}

impl UtxoSet {
    pub fn get(&self, outpoint: &OutPoint) -> Option<&TxOutput> {
        self.outputs.get(outpoint)
    }

    /// Iterates the currently unspent outputs without exposing mutation.
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &TxOutput)> {
        self.outputs.iter()
    }

    pub fn len(&self) -> usize {
        self.outputs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    #[cfg(test)]
    fn insert_for_testing(&mut self, outpoint: OutPoint, output: TxOutput) {
        if let OutputLock::InferenceChannel { channel_id } = &output.lock {
            self.active_channels.insert(*channel_id);
        }
        self.outputs.insert(outpoint, output);
    }

    #[cfg(test)]
    fn validate_and_apply(
        &mut self,
        block: &Block,
        verifier: &ConsensusPowVerifier,
        params: &NetworkParams,
    ) -> Result<u64, ChainError> {
        let (fees, delta) = self.validate_delta(block, verifier, params)?;
        delta.apply(self);
        Ok(fees)
    }

    fn validate_delta(
        &self,
        block: &Block,
        verifier: &ConsensusPowVerifier,
        params: &NetworkParams,
    ) -> Result<(u64, UtxoDelta), ChainError> {
        self.validate_delta_with_preverification(block, verifier, params, None)
    }

    fn validate_delta_preverified(
        &self,
        block: &Block,
        verifier: &ConsensusPowVerifier,
        params: &NetworkParams,
        preverified: &PreverifiedBlockProof,
    ) -> Result<(u64, UtxoDelta), ChainError> {
        self.validate_delta_with_preverification(block, verifier, params, Some(preverified))
    }

    /// Performs every block-body check except proof verification.
    ///
    /// This is an admission-control preflight only. Its candidate delta is
    /// discarded, and callers must still run either `validate_delta` or
    /// `validate_delta_preverified` before accepting the block.
    fn preflight_delta(&self, block: &Block, params: &NetworkParams) -> Result<(), ChainError> {
        self.validate_delta_preamble(block, params)?;
        self.validate_delta_body(block, params).map(drop)
    }

    fn validate_delta_with_preverification(
        &self,
        block: &Block,
        verifier: &ConsensusPowVerifier,
        params: &NetworkParams,
        preverified: Option<&PreverifiedBlockProof>,
    ) -> Result<(u64, UtxoDelta), ChainError> {
        self.validate_delta_preamble(block, params)?;
        if let Some(preverified) = preverified {
            verifier
                .verify_preverified(&block.challenge, &block.proof, preverified)
                .map_err(map_pow_error)?;
        } else {
            verifier
                .verify(&block.challenge, &block.proof)
                .map_err(map_pow_error)?;
        }
        self.validate_delta_body(block, params)
    }

    fn validate_delta_preamble(
        &self,
        block: &Block,
        params: &NetworkParams,
    ) -> Result<(), ChainError> {
        validate_block_preamble(block, params.network_id)
    }

    fn validate_delta_body(
        &self,
        block: &Block,
        params: &NetworkParams,
    ) -> Result<(u64, UtxoDelta), ChainError> {
        let mut candidate = UtxoOverlay::new(self);
        let mut spent = HashSet::new();
        let mut fees = 0u64;
        for transaction in &block.transactions {
            fees = fees
                .checked_add(candidate.apply_transaction(
                    transaction,
                    block.challenge.height,
                    params.network_id,
                    &mut spent,
                )?)
                .ok_or(ChainError::AmountOverflow)?;
        }

        let allocation = params
            .monetary_policy
            .allocation(block.challenge.height, fees)?;
        validate_coinbase(&block.coinbase, allocation, params.rewards)?;
        let coinbase_txid = block.coinbase_outpoint_id();
        for (index, output) in block.coinbase.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid: coinbase_txid,
                index: index as u32,
            };
            candidate.insert_output(outpoint, output.clone())?;
        }

        Ok((fees, candidate.into_delta()))
    }

    #[cfg(test)]
    fn apply_transaction(
        &mut self,
        transaction: &Transaction,
        height: u64,
        network_id: [u8; 32],
        spent: &mut HashSet<OutPoint>,
    ) -> Result<u64, ChainError> {
        let mut overlay = UtxoOverlay::new(self);
        let fee = overlay.apply_transaction(transaction, height, network_id, spent)?;
        overlay.into_delta().apply(self);
        Ok(fee)
    }
}

impl<'a> UtxoOverlay<'a> {
    fn new(base: &'a UtxoSet) -> Self {
        Self {
            base,
            delta: UtxoDelta::default(),
        }
    }

    fn into_delta(self) -> UtxoDelta {
        self.delta
    }

    fn get(&self, outpoint: &OutPoint) -> Option<&TxOutput> {
        self.delta.outputs.get(outpoint).map_or_else(
            || self.base.outputs.get(outpoint),
            |change| change.next.as_ref(),
        )
    }

    fn contains_active_channel(&self, channel_id: &[u8; 32]) -> bool {
        self.delta.active_channels.get(channel_id).map_or_else(
            || self.base.active_channels.contains(channel_id),
            |change| change.next,
        )
    }

    fn contains_retired_channel(&self, channel_id: &[u8; 32]) -> bool {
        self.delta.retired_channels.get(channel_id).map_or_else(
            || self.base.retired_channels.contains(channel_id),
            |change| change.next,
        )
    }

    fn stage_output(&mut self, outpoint: OutPoint, next: Option<TxOutput>) {
        let previous = self.base.outputs.get(&outpoint).cloned();
        let remove_change = {
            let change = self
                .delta
                .outputs
                .entry(outpoint)
                .or_insert_with(|| OutputChange {
                    previous: previous.clone(),
                    next: previous,
                });
            change.next = next;
            change.previous == change.next
        };
        if remove_change {
            self.delta.outputs.remove(&outpoint);
        }
    }

    fn stage_active_channel(&mut self, channel_id: [u8; 32], next: bool) {
        let previous = self.base.active_channels.contains(&channel_id);
        stage_membership(&mut self.delta.active_channels, channel_id, previous, next);
    }

    fn stage_retired_channel(&mut self, channel_id: [u8; 32], next: bool) {
        let previous = self.base.retired_channels.contains(&channel_id);
        stage_membership(&mut self.delta.retired_channels, channel_id, previous, next);
    }

    fn apply_transaction(
        &mut self,
        transaction: &Transaction,
        height: u64,
        network_id: [u8; 32],
        spent: &mut HashSet<OutPoint>,
    ) -> Result<u64, ChainError> {
        if transaction.network_id != network_id {
            return Err(ChainError::WrongNetwork);
        }
        if transaction.version != TRANSACTION_VERSION {
            return Err(ChainError::UnsupportedTransactionVersion);
        }
        if transaction.inputs.is_empty() {
            return Err(ChainError::NoInputs);
        }
        if transaction.outputs.is_empty() {
            return Err(ChainError::NoOutputs);
        }
        if transaction.outputs.iter().any(|output| output.value == 0) {
            return Err(ChainError::ZeroValueOutput);
        }

        if transaction
            .inputs
            .iter()
            .any(|input| !matches!(&input.witness, InputWitness::Key { .. }))
        {
            return self.apply_channel_transaction(transaction, height, network_id, spent);
        }

        let digest = transaction.signing_digest();
        let mut input_total = 0u64;
        for input in &transaction.inputs {
            if !spent.insert(input.previous) {
                return Err(ChainError::DuplicateInput);
            }
            let previous = self.get(&input.previous).ok_or(ChainError::MissingInput)?;
            if height < previous.spendable_height {
                return Err(ChainError::ImmatureInput(previous.spendable_height));
            }
            let OutputLock::Key(owner) = previous.lock else {
                return Err(ChainError::WrongWitness);
            };
            let InputWitness::Key {
                public_key,
                signature,
            } = &input.witness
            else {
                return Err(ChainError::WrongWitness);
            };
            if *public_key != owner {
                return Err(ChainError::WrongOwner);
            }
            let key =
                VerifyingKey::from_bytes(public_key).map_err(|_| ChainError::MalformedSignature)?;
            let signature = Signature::try_from(signature.as_slice())
                .map_err(|_| ChainError::MalformedSignature)?;
            key.verify(&digest, &signature)
                .map_err(|_| ChainError::InvalidSignature)?;
            input_total = input_total
                .checked_add(previous.value)
                .ok_or(ChainError::AmountOverflow)?;
        }

        let output_total = transaction.outputs.iter().try_fold(0u64, |sum, output| {
            sum.checked_add(output.value)
                .ok_or(ChainError::AmountOverflow)
        })?;
        if output_total > input_total {
            return Err(ChainError::CreatesValue);
        }

        for input in &transaction.inputs {
            self.stage_output(input.previous, None);
        }
        let txid = transaction.txid();
        for (index, output) in transaction.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                index: index as u32,
            };
            self.insert_output(outpoint, output.clone())?;
        }
        Ok(input_total - output_total)
    }

    fn apply_channel_transaction(
        &mut self,
        transaction: &Transaction,
        height: u64,
        network_id: [u8; 32],
        spent: &mut HashSet<OutPoint>,
    ) -> Result<u64, ChainError> {
        if transaction.inputs.len() != 1 {
            return Err(ChainError::ChannelCloseShape);
        }
        let input = &transaction.inputs[0];
        if !spent.insert(input.previous) {
            return Err(ChainError::DuplicateInput);
        }
        let previous = self
            .get(&input.previous)
            .cloned()
            .ok_or(ChainError::MissingInput)?;
        if height < previous.spendable_height {
            return Err(ChainError::ImmatureInput(previous.spendable_height));
        }
        let OutputLock::InferenceChannel { channel_id } = previous.lock else {
            return Err(ChainError::WrongWitness);
        };

        let (expected_outputs, fee) = match &input.witness {
            InputWitness::InferenceSettlement { terms, settlement } => {
                if terms.network_id != network_id {
                    return Err(ChainError::WrongNetwork);
                }
                if terms.channel_id()? != channel_id {
                    return Err(ChainError::WrongWitness);
                }
                if terms.deposit != previous.value {
                    return Err(ChainError::ChannelDeposit);
                }
                settlement.verify(terms)?;
                let state = &settlement.state.state;
                (
                    channel_outputs(
                        state.provider_payment,
                        terms.provider_key,
                        state.customer_refund,
                        terms.customer_key,
                        height,
                    ),
                    state.close_fee_burn,
                )
            }
            InputWitness::InferenceRefund { terms } => {
                if terms.network_id != network_id {
                    return Err(ChainError::WrongNetwork);
                }
                if terms.channel_id()? != channel_id {
                    return Err(ChainError::WrongWitness);
                }
                if terms.deposit != previous.value {
                    return Err(ChainError::ChannelDeposit);
                }
                let refund = terms.refund(height)?;
                (
                    channel_outputs(
                        0,
                        terms.provider_key,
                        refund.customer_amount,
                        terms.customer_key,
                        height,
                    ),
                    refund.fee_burn,
                )
            }
            InputWitness::Key { .. } => return Err(ChainError::WrongWitness),
        };

        if transaction.outputs != expected_outputs {
            return Err(ChainError::ChannelCloseShape);
        }
        let output_total = transaction.outputs.iter().try_fold(0u64, |sum, output| {
            sum.checked_add(output.value)
                .ok_or(ChainError::AmountOverflow)
        })?;
        if output_total
            .checked_add(fee)
            .ok_or(ChainError::AmountOverflow)?
            != previous.value
        {
            return Err(ChainError::ChannelCloseShape);
        }

        self.stage_output(input.previous, None);
        self.stage_active_channel(channel_id, false);
        self.stage_retired_channel(channel_id, true);
        let txid = transaction.txid();
        for (index, output) in transaction.outputs.iter().enumerate() {
            self.insert_output(
                OutPoint {
                    txid,
                    index: index as u32,
                },
                output.clone(),
            )?;
        }
        Ok(fee)
    }

    fn insert_output(&mut self, outpoint: OutPoint, output: TxOutput) -> Result<(), ChainError> {
        if output.value == 0 {
            return Err(ChainError::ZeroValueOutput);
        }
        let channel_id = match &output.lock {
            OutputLock::InferenceChannel { channel_id } => Some(*channel_id),
            OutputLock::Key(_) => None,
        };
        if let Some(channel_id) = channel_id
            && (self.contains_active_channel(&channel_id)
                || self.contains_retired_channel(&channel_id))
        {
            return Err(ChainError::DuplicateChannel);
        }
        if self.get(&outpoint).is_some() {
            return Err(ChainError::TxidCollision);
        }
        if let Some(channel_id) = channel_id {
            self.stage_active_channel(channel_id, true);
        }
        self.stage_output(outpoint, Some(output));
        Ok(())
    }
}

fn stage_membership(
    changes: &mut HashMap<[u8; 32], MembershipChange>,
    channel_id: [u8; 32],
    previous: bool,
    next: bool,
) {
    let remove_change = {
        let change = changes.entry(channel_id).or_insert(MembershipChange {
            previous,
            next: previous,
        });
        change.next = next;
        change.previous == change.next
    };
    if remove_change {
        changes.remove(&channel_id);
    }
}

impl UtxoDelta {
    fn matches(&self, utxos: &UtxoSet) -> bool {
        self.outputs
            .iter()
            .all(|(outpoint, change)| utxos.outputs.get(outpoint) == change.previous.as_ref())
            && self.active_channels.iter().all(|(channel_id, change)| {
                utxos.active_channels.contains(channel_id) == change.previous
            })
            && self.retired_channels.iter().all(|(channel_id, change)| {
                utxos.retired_channels.contains(channel_id) == change.previous
            })
    }

    fn apply(self, utxos: &mut UtxoSet) {
        for (outpoint, change) in self.outputs {
            match change.next {
                Some(output) => {
                    utxos.outputs.insert(outpoint, output);
                }
                None => {
                    utxos.outputs.remove(&outpoint);
                }
            }
        }
        for (channel_id, change) in self.active_channels {
            if change.next {
                utxos.active_channels.insert(channel_id);
            } else {
                utxos.active_channels.remove(&channel_id);
            }
        }
        for (channel_id, change) in self.retired_channels {
            if change.next {
                utxos.retired_channels.insert(channel_id);
            } else {
                utxos.retired_channels.remove(&channel_id);
            }
        }
    }

    #[cfg(test)]
    fn touched_counts(&self) -> (usize, usize, usize) {
        (
            self.outputs.len(),
            self.active_channels.len(),
            self.retired_channels.len(),
        )
    }
}

fn channel_outputs(
    provider_value: u64,
    provider_key: [u8; 32],
    customer_value: u64,
    customer_key: [u8; 32],
    height: u64,
) -> Vec<TxOutput> {
    let mut outputs = Vec::with_capacity(2);
    if provider_value > 0 {
        outputs.push(TxOutput {
            value: provider_value,
            lock: OutputLock::Key(provider_key),
            spendable_height: height,
        });
    }
    if customer_value > 0 {
        outputs.push(TxOutput {
            value: customer_value,
            lock: OutputLock::Key(customer_key),
            spendable_height: height,
        });
    }
    outputs
}

impl ChainState {
    pub fn new(params: NetworkParams, verifier: ConsensusPowVerifier) -> Result<Self, ChainError> {
        params.validate_for_bound_verifier()?;
        if verifier.parameters() != params.pow {
            return Err(ChainError::PowParameterMismatch);
        }
        let genesis_timestamp = params.genesis_timestamp;
        let genesis_hash = params.genesis_hash;
        let pow_limit = params.pow_limit;
        Ok(Self {
            params,
            utxos: UtxoSet::default(),
            history: vec![HeaderWork {
                timestamp: genesis_timestamp,
                target: pow_limit,
            }],
            raw_timestamps: vec![genesis_timestamp],
            tip: genesis_hash,
            next_height: 1,
            verifier,
        })
    }

    pub fn params(&self) -> &NetworkParams {
        &self.params
    }

    pub fn utxos(&self) -> &UtxoSet {
        &self.utxos
    }

    pub fn tip(&self) -> [u8; 32] {
        self.tip
    }

    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    pub fn expected_target(&self) -> Result<[u8; 32], ChainError> {
        Ok(next_work_target(&self.history, self.params.pow_limit)?)
    }

    pub fn median_time_past(&self) -> u64 {
        median_timestamp(&self.raw_timestamps)
    }

    /// Captures only the immutable consensus values required to preflight the
    /// next header. It contains no UTXO state and cannot authorize a commit.
    pub fn successor_header_preflight(&self) -> Result<SuccessorHeaderPreflight, ChainError> {
        Ok(SuccessorHeaderPreflight {
            params: self.params,
            tip: self.tip,
            next_height: self.next_height,
            median_time_past: self.median_time_past(),
            expected_target: self.expected_target()?,
        })
    }

    /// Validates a transaction set against the current UTXO state at the next
    /// block height without mutating the chain or exposing a committable delta.
    pub fn validate_transactions_for_next_block(
        &self,
        transactions: &[Transaction],
    ) -> Result<TransactionSetValidation, ChainError> {
        let mut validation = validate_transaction_set_resources(transactions)?;

        for transaction in transactions {
            if transaction.network_id != self.params.network_id {
                return Err(ChainError::WrongNetwork);
            }
            if transaction.version != TRANSACTION_VERSION {
                return Err(ChainError::UnsupportedTransactionVersion);
            }
        }
        for transaction in transactions {
            crate::wire::encode_transaction(transaction).map_err(|_| ChainError::BlockEncoding)?;
        }

        let mut candidate = UtxoOverlay::new(&self.utxos);
        let mut spent = HashSet::new();
        for transaction in transactions {
            validation.total_burned_fees = validation
                .total_burned_fees
                .checked_add(candidate.apply_transaction(
                    transaction,
                    self.next_height,
                    self.params.network_id,
                    &mut spent,
                )?)
                .ok_or(ChainError::AmountOverflow)?;
        }

        Ok(validation)
    }

    pub fn validate_and_apply(
        &mut self,
        block: &Block,
        context: BlockValidationContext,
    ) -> Result<u64, ChainError> {
        let validated = self.validate_block(block, context)?;
        self.commit_validated(validated)
    }

    /// Validates a successor block without mutating chain state.
    pub fn validate_block(
        &self,
        block: &Block,
        context: BlockValidationContext,
    ) -> Result<ValidatedBlock, ChainError> {
        self.validate_block_with_preverification(block, context, None)
    }

    /// Validates a successor block after an exact proof capability was issued
    /// by the chain's configured verifier. All state-dependent consensus checks
    /// still execute here; only duplicate cryptographic proof work is skipped.
    pub fn validate_block_preverified(
        &self,
        block: &Block,
        context: BlockValidationContext,
        preverified: &PreverifiedBlockProof,
    ) -> Result<ValidatedBlock, ChainError> {
        self.validate_block_with_preverification(block, context, Some(preverified))
    }

    /// Runs all inexpensive header and state checks without accepting the
    /// block or verifying its proof. This is only an admission-control gate;
    /// callers must still invoke `validate_block` or
    /// `validate_block_preverified` before committing anything.
    pub fn preflight_block(
        &self,
        block: &Block,
        context: BlockValidationContext,
    ) -> Result<(), ChainError> {
        self.preflight_block_header(block, context)?;
        self.utxos.preflight_delta(block, &self.params)
    }

    fn validate_block_with_preverification(
        &self,
        block: &Block,
        context: BlockValidationContext,
        preverified: Option<&PreverifiedBlockProof>,
    ) -> Result<ValidatedBlock, ChainError> {
        let (next_height, expected_target) = self.preflight_block_header(block, context)?;

        let (fees, delta) = if let Some(preverified) = preverified {
            self.utxos.validate_delta_preverified(
                block,
                &self.verifier,
                &self.params,
                preverified,
            )?
        } else {
            self.utxos
                .validate_delta(block, &self.verifier, &self.params)?
        };
        let window_start = self
            .raw_timestamps
            .len()
            .saturating_sub(crate::MEDIAN_TIME_WINDOW.saturating_sub(1));
        let mut timestamp_window = Vec::with_capacity(self.raw_timestamps.len() - window_start + 1);
        timestamp_window.extend_from_slice(&self.raw_timestamps[window_start..]);
        timestamp_window.push(block.challenge.timestamp);
        let effective_timestamp = median_timestamp(&timestamp_window);

        Ok(ValidatedBlock {
            params: self.params,
            base_tip: self.tip,
            base_next_height: self.next_height,
            base_expected_target: expected_target,
            base_median_time_past: self.median_time_past(),
            base_history_len: self.history.len(),
            base_timestamp_len: self.raw_timestamps.len(),
            delta,
            fees,
            timestamp: block.challenge.timestamp,
            effective_timestamp,
            target: block.challenge.target,
            next_tip: block.block_id(),
            next_height,
        })
    }

    fn preflight_block_header(
        &self,
        block: &Block,
        context: BlockValidationContext,
    ) -> Result<(u64, [u8; 32]), ChainError> {
        self.successor_header_preflight()?
            .preflight_block_values(block, context)
    }

    /// Atomically applies a transition returned by [`Self::validate_block`].
    /// A token validated against an older or different state is rejected before
    /// any UTXO, channel, timestamp, or tip mutation occurs.
    pub fn commit_validated(&mut self, validated: ValidatedBlock) -> Result<u64, ChainError> {
        if self.params != validated.params
            || self.tip != validated.base_tip
            || self.next_height != validated.base_next_height
            || self.history.len() != validated.base_history_len
            || self.raw_timestamps.len() != validated.base_timestamp_len
            || self.median_time_past() != validated.base_median_time_past
            || self.expected_target().ok() != Some(validated.base_expected_target)
            || !validated.delta.matches(&self.utxos)
        {
            return Err(ChainError::StaleValidatedBlock);
        }

        let ValidatedBlock {
            delta,
            fees,
            timestamp,
            effective_timestamp,
            target,
            next_tip,
            next_height,
            ..
        } = validated;
        delta.apply(&mut self.utxos);
        self.raw_timestamps.push(timestamp);
        self.history.push(HeaderWork {
            timestamp: effective_timestamp,
            target,
        });
        self.tip = next_tip;
        self.next_height = next_height;
        Ok(fees)
    }
}

impl Block {
    pub fn transaction_root(&self) -> [u8; 32] {
        let mut ids = Vec::with_capacity(self.transactions.len() + 1);
        ids.push(self.coinbase.commitment(self.challenge.network_id));
        ids.extend(self.transactions.iter().map(Transaction::txid));
        merkle_root(&ids)
    }

    pub fn block_id(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(BLOCK_ID_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.challenge.network_id);
        hasher.update(&self.challenge.previous_block);
        hasher.update(&self.challenge.transaction_root);
        hasher.update(&self.challenge.height.to_le_bytes());
        hasher.update(&self.challenge.timestamp.to_le_bytes());
        hasher.update(&self.challenge.target);
        self.proof.absorb(&mut hasher);
        *hasher.finalize().as_bytes()
    }

    pub fn coinbase_outpoint_id(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(COINBASE_OUTPOINT_DOMAIN);
        hasher.update(&self.challenge.network_id);
        hasher.update(&self.block_id());
        *hasher.finalize().as_bytes()
    }
}

fn map_pow_error(error: PowError) -> ChainError {
    match error {
        PowError::V1(error) => ChainError::Proof(error),
        PowError::V2(_) => ChainError::InvalidV2Proof,
        #[cfg(feature = "dory-v3-consensus-adapter")]
        PowError::V3(_) => ChainError::InvalidV3Proof,
        PowError::WrongProofType => ChainError::WrongProofType,
        PowError::ParameterMismatch => ChainError::PowParameterMismatch,
        PowError::PreverificationMismatch => ChainError::PreverifiedProofMismatch,
        PowError::PreverificationEntropy => ChainError::PreverificationUnavailable,
        PowError::WrongNetwork => ChainError::WrongNetwork,
    }
}

fn median_timestamp(timestamps: &[u64]) -> u64 {
    let start = timestamps.len().saturating_sub(crate::MEDIAN_TIME_WINDOW);
    let mut window = timestamps[start..].to_vec();
    window.sort_unstable();
    window[window.len() / 2]
}

pub fn validate_block_resources(block: &Block) -> Result<(), ChainError> {
    if block.transactions.len() > MAX_BLOCK_TRANSACTIONS {
        return Err(ChainError::BlockTransactionLimit);
    }
    if block.coinbase.outputs.len() > MAX_COINBASE_OUTPUTS {
        return Err(ChainError::CoinbaseOutputLimit);
    }
    validate_transaction_resources(&block.transactions).map(drop)
}

/// Performs the canonical, state-independent body checks that bind the full
/// transaction and coinbase payload to the proof-of-work header. This is safe
/// to run before expensive proof verification and does not authorize a block.
pub fn validate_block_preamble(block: &Block, network_id: [u8; 32]) -> Result<(), ChainError> {
    validate_block_resources(block)?;
    if block.version != BLOCK_VERSION {
        return Err(ChainError::UnsupportedBlockVersion);
    }
    if block.challenge.network_id != network_id {
        return Err(ChainError::WrongNetwork);
    }
    for transaction in &block.transactions {
        if transaction.network_id != network_id {
            return Err(ChainError::WrongNetwork);
        }
        if transaction.version != TRANSACTION_VERSION {
            return Err(ChainError::UnsupportedTransactionVersion);
        }
    }
    crate::wire::encode_block(block).map_err(|_| ChainError::BlockEncoding)?;
    if block.challenge.height != block.coinbase.height {
        return Err(ChainError::HeightMismatch);
    }
    if block.transaction_root() != block.challenge.transaction_root {
        return Err(ChainError::MerkleRoot);
    }
    Ok(())
}

fn validate_transaction_set_resources(
    transactions: &[Transaction],
) -> Result<TransactionSetValidation, ChainError> {
    if transactions.len() > MAX_BLOCK_TRANSACTIONS {
        return Err(ChainError::BlockTransactionLimit);
    }
    validate_transaction_resources(transactions)
}

fn validate_transaction_resources(
    transactions: &[Transaction],
) -> Result<TransactionSetValidation, ChainError> {
    let mut aggregate_inputs = 0usize;
    let mut aggregate_outputs = 0usize;
    let mut signature_checks = 0usize;
    for transaction in transactions {
        if transaction.inputs.len() > MAX_TRANSACTION_INPUTS {
            return Err(ChainError::TransactionInputLimit);
        }
        if transaction.outputs.len() > MAX_TRANSACTION_OUTPUTS {
            return Err(ChainError::TransactionOutputLimit);
        }
        aggregate_inputs = aggregate_inputs
            .checked_add(transaction.inputs.len())
            .ok_or(ChainError::BlockAggregateLimit)?;
        aggregate_outputs = aggregate_outputs
            .checked_add(transaction.outputs.len())
            .ok_or(ChainError::BlockAggregateLimit)?;
        for input in &transaction.inputs {
            let checks = match &input.witness {
                InputWitness::Key { signature, .. } => {
                    if signature.len() != CONSENSUS_SIGNATURE_BYTES {
                        return Err(ChainError::SignatureLength);
                    }
                    1
                }
                InputWitness::InferenceSettlement { settlement, .. } => {
                    if settlement.state.customer_signature.len() != CONSENSUS_SIGNATURE_BYTES
                        || settlement.provider_signature.len() != CONSENSUS_SIGNATURE_BYTES
                    {
                        return Err(ChainError::SignatureLength);
                    }
                    2
                }
                InputWitness::InferenceRefund { .. } => 0,
            };
            signature_checks = signature_checks
                .checked_add(checks)
                .ok_or(ChainError::BlockSignatureLimit)?;
        }
    }
    if aggregate_inputs > MAX_BLOCK_AGGREGATE_INPUTS
        || aggregate_outputs > MAX_BLOCK_AGGREGATE_OUTPUTS
    {
        return Err(ChainError::BlockAggregateLimit);
    }
    if signature_checks > MAX_BLOCK_SIGNATURE_CHECKS {
        return Err(ChainError::BlockSignatureLimit);
    }
    Ok(TransactionSetValidation {
        total_burned_fees: 0,
        aggregate_inputs,
        aggregate_outputs,
        signature_checks,
    })
}

fn validate_coinbase(
    coinbase: &Coinbase,
    allocation: crate::Allocation,
    fixed_destinations: FixedRewardDestinations,
) -> Result<(), ChainError> {
    let Some(TxOutput {
        lock: OutputLock::Key(miner_destination),
        ..
    }) = coinbase.outputs.first()
    else {
        return Err(ChainError::CoinbaseLayout);
    };
    VerifyingKey::from_bytes(miner_destination).map_err(|_| ChainError::CoinbaseLayout)?;
    let expected = Coinbase::new(
        coinbase.height,
        allocation,
        *miner_destination,
        fixed_destinations,
    );
    if coinbase.outputs != expected.outputs {
        return Err(ChainError::CoinbaseLayout);
    }
    let claim = CoinbaseClaim {
        miner: coinbase.outputs.first().map_or(0, |output| output.value),
        steward: coinbase.outputs.get(1).map_or(0, |output| output.value),
        community: coinbase.outputs.get(2).map_or(0, |output| output.value),
    };
    if claim.miner != allocation.miner
        || claim.steward != allocation.steward
        || claim.community != allocation.community
    {
        return Err(ChainError::CoinbaseLayout);
    }
    Ok(())
}

pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = txids
        .iter()
        .map(|txid| {
            let mut hasher = Hasher::new_derive_key(MERKLE_LEAF_DOMAIN);
            hasher.update(txid);
            *hasher.finalize().as_bytes()
        })
        .collect();
    if level.is_empty() {
        level.push(
            *Hasher::new_derive_key(MERKLE_LEAF_DOMAIN)
                .finalize()
                .as_bytes(),
        );
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("nonempty Merkle level"));
        }
        level = level
            .chunks_exact(2)
            .map(|pair| {
                let mut hasher = Hasher::new_derive_key(MERKLE_NODE_DOMAIN);
                hasher.update(&pair[0]);
                hasher.update(&pair[1]);
                *hasher.finalize().as_bytes()
            })
            .collect();
    }

    let mut hasher = Hasher::new_derive_key(MERKLE_ROOT_DOMAIN);
    hasher.update(&(txids.len() as u64).to_le_bytes());
    hasher.update(&level[0]);
    *hasher.finalize().as_bytes()
}

fn encode_unsigned_transaction(transaction: &Transaction, hasher: &mut Hasher) {
    hasher.update(&transaction.network_id);
    hasher.update(&transaction.version.to_le_bytes());
    hasher.update(&(transaction.inputs.len() as u64).to_le_bytes());
    for input in &transaction.inputs {
        hasher.update(&input.previous.txid);
        hasher.update(&input.previous.index.to_le_bytes());
        encode_witness(&input.witness, false, hasher);
    }
    encode_outputs(&transaction.outputs, hasher);
}

fn encode_outputs(outputs: &[TxOutput], hasher: &mut Hasher) {
    hasher.update(&(outputs.len() as u64).to_le_bytes());
    for output in outputs {
        hasher.update(&output.value.to_le_bytes());
        match &output.lock {
            OutputLock::Key(owner) => {
                hasher.update(&[0]);
                hasher.update(owner);
            }
            OutputLock::InferenceChannel { channel_id } => {
                hasher.update(&[1]);
                hasher.update(channel_id);
            }
        }
        hasher.update(&output.spendable_height.to_le_bytes());
    }
}

fn encode_witness(witness: &InputWitness, include_signatures: bool, hasher: &mut Hasher) {
    match witness {
        InputWitness::Key {
            public_key,
            signature,
        } => {
            hasher.update(&[0]);
            hasher.update(public_key);
            if include_signatures {
                encode_bytes(signature, hasher);
            }
        }
        InputWitness::InferenceSettlement { terms, settlement } => {
            hasher.update(&[1]);
            encode_channel_terms(terms, hasher);
            encode_payment_state(&settlement.state.state, hasher);
            if include_signatures {
                encode_bytes(&settlement.state.customer_signature, hasher);
                encode_bytes(&settlement.provider_signature, hasher);
                hasher.update(&settlement.witness_digest());
            }
        }
        InputWitness::InferenceRefund { terms } => {
            hasher.update(&[2]);
            encode_channel_terms(terms, hasher);
        }
    }
}

fn encode_channel_terms(terms: &ChannelTerms, hasher: &mut Hasher) {
    hasher.update(&terms.network_id);
    hasher.update(&terms.job_id);
    hasher.update(&terms.customer_key);
    hasher.update(&terms.provider_key);
    hasher.update(&terms.model_digest);
    hasher.update(&terms.runtime_digest);
    hasher.update(&terms.input_digest);
    for value in [
        terms.deposit,
        terms.close_fee_burn,
        terms.base_price,
        terms.input_price_per_1000,
        terms.output_price_per_1000,
        terms.max_input_tokens,
        terms.max_output_tokens,
        terms.output_chunk_tokens,
        terms.refund_height,
    ] {
        hasher.update(&value.to_le_bytes());
    }
}

fn encode_payment_state(state: &cmfd_marketplace::PaymentState, hasher: &mut Hasher) {
    hasher.update(&state.channel_id);
    for value in [
        state.sequence,
        state.input_tokens,
        state.authorized_output_tokens,
        state.provider_payment,
        state.customer_refund,
        state.close_fee_burn,
    ] {
        hasher.update(&value.to_le_bytes());
    }
    hasher.update(&state.previous_receipt);
}

fn encode_bytes(bytes: &[u8], hasher: &mut Hasher) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DEFAULT_MONETARY_POLICY, ForgeMatrixProfile, ForgeMatrixV3CandidateProof, PowParameters,
        TEST_PROFILE, v2_test_reference,
    };
    use cmfd_marketplace::{ChannelTerms, Settlement, SignedPaymentState};

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32]).unwrap()
    }

    fn owner(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes().into()
    }

    fn miner_destination() -> [u8; 32] {
        owner(&signing_key(2))
    }

    fn fixed_destinations() -> FixedRewardDestinations {
        FixedRewardDestinations {
            steward: owner(&signing_key(3)),
            community: owner(&signing_key(4)),
        }
    }

    fn network_params() -> NetworkParams {
        NetworkParams {
            network_id: [1; 32],
            protocol_version: crate::NETWORK_PROTOCOL_VERSION,
            genesis_hash: [7; 32],
            genesis_timestamp: 0,
            pow_limit: [0xff; 32],
            pow: PowParameters::V1Legacy(TEST_PROFILE),
            monetary_policy: DEFAULT_MONETARY_POLICY,
            rewards: fixed_destinations(),
            max_future_offset_secs: 7_200,
        }
    }

    #[test]
    fn transaction_merkle_root_binds_the_exact_leaf_count() {
        let coinbase = [0x11; 32];
        let tx1 = [0x22; 32];
        let tx2 = [0x33; 32];

        assert_ne!(
            merkle_root(&[coinbase, tx1, tx2]),
            merkle_root(&[coinbase, tx1, tx2, tx2])
        );
    }

    #[test]
    fn transaction_merkle_root_v2_known_answer_is_stable() {
        assert_eq!(
            merkle_root(&[[0x11; 32], [0x22; 32], [0x33; 32]]),
            [
                0x4a, 0x82, 0x02, 0xa7, 0x93, 0xb0, 0x73, 0x29, 0x55, 0x04, 0x58, 0x4a, 0x5d, 0x92,
                0x3e, 0xe0, 0xff, 0x20, 0xbd, 0xc4, 0xe8, 0xc8, 0x43, 0xac, 0xb9, 0x1b, 0xc0, 0x46,
                0xba, 0x41, 0xe7, 0x12,
            ]
        );
    }

    #[test]
    fn transaction_merkle_root_rejects_every_bounded_odd_tail_duplication() {
        for leaf_count in (3..=crate::MAX_BLOCK_TRANSACTIONS + 1).step_by(2) {
            let leaves = (0..leaf_count)
                .map(|index| {
                    let mut leaf = [0_u8; 32];
                    leaf[..8].copy_from_slice(&(leaf_count as u64).to_le_bytes());
                    leaf[8..16].copy_from_slice(&(index as u64).to_le_bytes());
                    leaf
                })
                .collect::<Vec<_>>();
            let mut mutated = leaves.clone();
            mutated.push(*leaves.last().expect("odd test vector is nonempty"));

            assert_ne!(
                merkle_root(&leaves),
                merkle_root(&mutated),
                "odd-tail duplication was not bound at leaf count {leaf_count}"
            );
        }
    }

    fn legacy_verifier() -> ConsensusPowVerifier {
        ConsensusPowVerifier::v1_legacy(TEST_PROFILE).unwrap()
    }

    fn chain_state(params: NetworkParams) -> ChainState {
        ChainState::new(params, legacy_verifier()).unwrap()
    }

    fn assert_chain_states_equal(left: &ChainState, right: &ChainState) {
        assert_eq!(left.params, right.params);
        assert_eq!(left.utxos.outputs, right.utxos.outputs);
        assert_eq!(left.utxos.active_channels, right.utxos.active_channels);
        assert_eq!(left.utxos.retired_channels, right.utxos.retired_channels);
        assert_eq!(left.history, right.history);
        assert_eq!(left.raw_timestamps, right.raw_timestamps);
        assert_eq!(left.tip, right.tip);
        assert_eq!(left.next_height, right.next_height);
    }

    fn validation_context(now_unix_seconds: u64) -> BlockValidationContext {
        BlockValidationContext { now_unix_seconds }
    }

    fn channel_terms(customer: &SigningKey, provider: &SigningKey) -> ChannelTerms {
        ChannelTerms {
            network_id: [1; 32],
            job_id: [2; 32],
            customer_key: owner(customer),
            provider_key: owner(provider),
            model_digest: [3; 32],
            runtime_digest: [4; 32],
            input_digest: [5; 32],
            deposit: 1_000_000,
            close_fee_burn: 1_000,
            base_price: 100,
            input_price_per_1000: 2_000,
            output_price_per_1000: 4_000,
            max_input_tokens: 8_192,
            max_output_tokens: 1_024,
            output_chunk_tokens: 32,
            refund_height: 500,
        }
    }

    fn signed_key_spend(
        previous: OutPoint,
        input_key: &SigningKey,
        output_value: u64,
        output_owner: [u8; 32],
    ) -> Transaction {
        let mut transaction = Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous,
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: vec![],
                },
            }],
            outputs: vec![TxOutput {
                value: output_value,
                lock: OutputLock::Key(output_owner),
                spendable_height: 0,
            }],
        };
        transaction.sign_all(&[input_key]).unwrap();
        transaction
    }

    fn block_with_transactions(
        height: u64,
        previous_block: [u8; 32],
        transactions: Vec<Transaction>,
        fees: u64,
        verifier: &ConsensusPowVerifier,
    ) -> Block {
        let params = network_params();
        let allocation = DEFAULT_MONETARY_POLICY.allocation(height, fees).unwrap();
        let coinbase = Coinbase::new(
            height,
            allocation,
            miner_destination(),
            fixed_destinations(),
        );
        let mut ids = vec![coinbase.commitment(params.network_id)];
        ids.extend(transactions.iter().map(Transaction::txid));
        let challenge = BlockChallenge {
            network_id: params.network_id,
            previous_block,
            transaction_root: merkle_root(&ids),
            height,
            timestamp: height * 60,
            target: [0xff; 32],
        };
        Block {
            version: BLOCK_VERSION,
            proof: verifier.mine(&challenge, 0, 1).unwrap(),
            challenge,
            coinbase,
            transactions,
        }
    }

    fn block_for_state(
        state: &ChainState,
        timestamp: u64,
        miner: [u8; 32],
        transactions: Vec<Transaction>,
        fees: u64,
        nonce: u64,
    ) -> Block {
        let height = state.next_height();
        let allocation = state
            .params
            .monetary_policy
            .allocation(height, fees)
            .unwrap();
        let coinbase = Coinbase::new(height, allocation, miner, state.params.rewards);
        let mut ids = vec![coinbase.commitment(state.params.network_id)];
        ids.extend(transactions.iter().map(Transaction::txid));
        let challenge = BlockChallenge {
            network_id: state.params.network_id,
            previous_block: state.tip(),
            transaction_root: merkle_root(&ids),
            height,
            timestamp,
            target: state.expected_target().unwrap(),
        };
        Block {
            version: BLOCK_VERSION,
            proof: state.verifier.mine(&challenge, nonce, 100_000).unwrap(),
            challenge,
            coinbase,
            transactions,
        }
    }

    #[test]
    fn signed_utxo_spend_burns_fee_and_block_applies_atomically() {
        let spend_key = signing_key(1);
        let previous = OutPoint {
            txid: [9; 32],
            index: 0,
        };
        let mut utxos = UtxoSet::default();
        utxos.insert_for_testing(
            previous,
            TxOutput {
                value: 10_000,
                lock: OutputLock::Key(owner(&spend_key)),
                spendable_height: 0,
            },
        );

        let mut transaction = Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous,
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: vec![],
                },
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                lock: OutputLock::Key(owner(&signing_key(5))),
                spendable_height: 0,
            }],
        };
        transaction.sign_all(&[&spend_key]).unwrap();

        let verifier = legacy_verifier();
        let allocation = DEFAULT_MONETARY_POLICY.allocation(1, 1_000).unwrap();
        let coinbase = Coinbase::new(1, allocation, miner_destination(), fixed_destinations());
        let tx_root = merkle_root(&[
            coinbase.commitment(network_params().network_id),
            transaction.txid(),
        ]);
        let challenge = BlockChallenge {
            network_id: network_params().network_id,
            previous_block: [7; 32],
            transaction_root: tx_root,
            height: 1,
            timestamp: 1,
            target: [0xff; 32],
        };
        let proof = verifier.mine(&challenge, 0, 1).unwrap();
        let block = Block {
            version: BLOCK_VERSION,
            challenge,
            proof,
            coinbase,
            transactions: vec![transaction],
        };

        assert_eq!(
            utxos
                .validate_and_apply(&block, &verifier, &network_params())
                .unwrap(),
            1_000
        );
        assert!(utxos.get(&previous).is_none());
    }

    #[test]
    fn zero_value_outputs_cannot_bloat_the_utxo_set() {
        let spend_key = signing_key(36);
        let previous = OutPoint {
            txid: [0x72; 32],
            index: 0,
        };
        let mut utxos = UtxoSet::default();
        utxos.insert_for_testing(
            previous,
            TxOutput {
                value: 1,
                lock: OutputLock::Key(owner(&spend_key)),
                spendable_height: 0,
            },
        );
        let mut transaction = Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous,
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: vec![],
                },
            }],
            outputs: vec![TxOutput {
                value: 0,
                lock: OutputLock::Key(owner(&signing_key(37))),
                spendable_height: 0,
            }],
        };
        transaction.sign_all(&[&spend_key]).unwrap();

        assert_eq!(
            utxos.apply_transaction(
                &transaction,
                1,
                network_params().network_id,
                &mut HashSet::new()
            ),
            Err(ChainError::ZeroValueOutput)
        );
        assert_eq!(utxos.len(), 1);
        assert!(utxos.get(&previous).is_some());
    }

    #[test]
    fn coinbase_cannot_claim_burned_fee() {
        let verifier = legacy_verifier();
        let allocation = DEFAULT_MONETARY_POLICY.allocation(1, 1_000).unwrap();
        let mut coinbase = Coinbase::new(1, allocation, miner_destination(), fixed_destinations());
        coinbase.outputs[0].value += 1_000;
        let root = merkle_root(&[coinbase.commitment(network_params().network_id)]);
        let challenge = BlockChallenge {
            network_id: network_params().network_id,
            previous_block: [7; 32],
            transaction_root: root,
            height: 1,
            timestamp: 1,
            target: [0xff; 32],
        };
        let block = Block {
            version: BLOCK_VERSION,
            proof: verifier.mine(&challenge, 0, 1).unwrap(),
            challenge,
            coinbase,
            transactions: vec![],
        };
        assert_eq!(
            UtxoSet::default().validate_and_apply(&block, &verifier, &network_params()),
            Err(ChainError::CoinbaseLayout)
        );
    }

    #[test]
    fn steward_and_community_are_paid_and_spendable_per_block() {
        let rewards = fixed_destinations();
        for height in [1, 2, DEFAULT_MONETARY_POLICY.tail_height / 2] {
            let allocation = DEFAULT_MONETARY_POLICY.allocation(height, 77).unwrap();
            let coinbase = Coinbase::new(height, allocation, miner_destination(), rewards);
            assert_eq!(coinbase.outputs.len(), 3);
            assert_eq!(coinbase.outputs[0].value, allocation.miner);
            assert_eq!(
                coinbase.outputs[0].spendable_height,
                height + COINBASE_MATURITY
            );
            assert_eq!(coinbase.outputs[1].value, allocation.steward);
            assert_eq!(coinbase.outputs[1].lock, OutputLock::Key(rewards.steward));
            assert_eq!(coinbase.outputs[1].spendable_height, height);
            assert_eq!(coinbase.outputs[2].value, allocation.community);
            assert_eq!(coinbase.outputs[2].lock, OutputLock::Key(rewards.community));
            assert_eq!(coinbase.outputs[2].spendable_height, height);
        }
    }

    #[test]
    fn chain_state_owns_policy_and_fixed_reward_destinations() {
        let params = network_params();
        let mut state = chain_state(params);
        let block = block_for_state(&state, 60, owner(&signing_key(20)), vec![], 0, 0);

        let mut redirected = block.clone();
        redirected.coinbase.outputs[1].lock = OutputLock::Key(owner(&signing_key(21)));
        redirected.challenge.transaction_root = redirected.transaction_root();
        redirected.proof = state.verifier.mine(&redirected.challenge, 0, 1).unwrap();
        assert_eq!(
            state.validate_and_apply(&redirected, validation_context(60)),
            Err(ChainError::CoinbaseLayout)
        );

        let mut inflated = block;
        inflated.coinbase.outputs[0].value += 1;
        inflated.challenge.transaction_root = inflated.transaction_root();
        inflated.proof = state.verifier.mine(&inflated.challenge, 0, 1).unwrap();
        assert_eq!(
            state.validate_and_apply(&inflated, validation_context(60)),
            Err(ChainError::CoinbaseLayout)
        );
    }

    #[test]
    fn miners_choose_distinct_payout_keys_per_block() {
        let mut state = chain_state(network_params());
        let miner_a = owner(&signing_key(20));
        let miner_b = owner(&signing_key(21));
        let first = block_for_state(&state, 60, miner_a, vec![], 0, 0);
        state
            .validate_and_apply(&first, validation_context(60))
            .unwrap();
        let second = block_for_state(&state, 120, miner_b, vec![], 0, 1);
        state
            .validate_and_apply(&second, validation_context(120))
            .unwrap();

        assert_eq!(first.coinbase.outputs[0].lock, OutputLock::Key(miner_a));
        assert_eq!(second.coinbase.outputs[0].lock, OutputLock::Key(miner_b));
        assert_eq!(
            first.coinbase.outputs[1].lock,
            OutputLock::Key(state.params.rewards.steward)
        );
        assert_eq!(
            second.coinbase.outputs[2].lock,
            OutputLock::Key(state.params.rewards.community)
        );
    }

    #[test]
    fn timestamps_are_bounded_by_median_time_and_adjusted_time() {
        let mut params = network_params();
        params.max_future_offset_secs = 120;
        let mut state = chain_state(params);
        for timestamp in (10..=110).step_by(10) {
            let block =
                block_for_state(&state, timestamp, miner_destination(), vec![], 0, timestamp);
            state
                .validate_and_apply(&block, validation_context(timestamp))
                .unwrap();
        }
        assert_eq!(state.median_time_past(), 60);

        let at_median = block_for_state(&state, 60, miner_destination(), vec![], 0, 200);
        assert_eq!(
            state.validate_and_apply(&at_median, validation_context(110)),
            Err(ChainError::TimestampNotAfterMedian)
        );

        let mut future_state = chain_state(params);
        let boundary = block_for_state(&future_state, 1_120, miner_destination(), vec![], 0, 0);
        future_state
            .validate_and_apply(&boundary, validation_context(1_000))
            .unwrap();

        let mut too_future_state = chain_state(params);
        let too_future =
            block_for_state(&too_future_state, 1_121, miner_destination(), vec![], 0, 0);
        assert_eq!(
            too_future_state.validate_and_apply(&too_future, validation_context(1_000)),
            Err(ChainError::TimestampTooFarInFuture)
        );

        let mut maximum_state = chain_state(params);
        let maximum = block_for_state(&maximum_state, u64::MAX, miner_destination(), vec![], 0, 0);
        assert_eq!(
            maximum_state.validate_and_apply(&maximum, validation_context(1_000)),
            Err(ChainError::TimestampTooFarInFuture)
        );
    }

    #[test]
    fn transaction_identity_and_signatures_are_network_bound() {
        let spend_key = signing_key(30);
        let previous = OutPoint {
            txid: [0x55; 32],
            index: 0,
        };
        let transaction_for = |network_id| Transaction {
            network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous,
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: vec![],
                },
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                lock: OutputLock::Key(owner(&signing_key(31))),
                spendable_height: 0,
            }],
        };
        let mut network_a = transaction_for([1; 32]);
        let network_b = transaction_for([2; 32]);
        assert_ne!(network_a.signing_digest(), network_b.signing_digest());
        assert_ne!(network_a.txid(), network_b.txid());
        network_a.sign_all(&[&spend_key]).unwrap();

        let mut utxos = UtxoSet::default();
        utxos.insert_for_testing(
            previous,
            TxOutput {
                value: 10_000,
                lock: OutputLock::Key(owner(&spend_key)),
                spendable_height: 0,
            },
        );
        assert_eq!(
            utxos.apply_transaction(&network_a, 1, [2; 32], &mut HashSet::new()),
            Err(ChainError::WrongNetwork)
        );
        assert!(utxos.get(&previous).is_some());
    }

    #[test]
    fn sibling_blocks_have_block_qualified_coinbase_outpoints() {
        let mut state = chain_state(network_params());
        let sibling_a = block_for_state(&state, 60, miner_destination(), vec![], 0, 1);
        let sibling_b = block_for_state(&state, 60, miner_destination(), vec![], 0, 2);
        assert_eq!(
            sibling_a.coinbase.commitment(state.params.network_id),
            sibling_b.coinbase.commitment(state.params.network_id)
        );
        assert_ne!(sibling_a.block_id(), sibling_b.block_id());
        assert_ne!(
            sibling_a.coinbase_outpoint_id(),
            sibling_b.coinbase_outpoint_id()
        );

        state
            .validate_and_apply(&sibling_a, validation_context(60))
            .unwrap();
        assert!(
            state
                .utxos
                .get(&OutPoint {
                    txid: sibling_a.coinbase_outpoint_id(),
                    index: 0,
                })
                .is_some()
        );
        assert!(
            state
                .utxos
                .get(&OutPoint {
                    txid: sibling_b.coinbase_outpoint_id(),
                    index: 0,
                })
                .is_none()
        );
    }

    #[test]
    fn direct_consensus_enforces_resource_and_version_limits() {
        let dummy_input = TxInput {
            previous: OutPoint {
                txid: [0x66; 32],
                index: 0,
            },
            witness: InputWitness::Key {
                public_key: owner(&signing_key(32)),
                signature: vec![0; 64],
            },
        };
        let dummy_output = TxOutput {
            value: 1,
            lock: OutputLock::Key(owner(&signing_key(33))),
            spendable_height: 0,
        };
        let transaction = |inputs: usize, outputs: usize| Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![dummy_input.clone(); inputs],
            outputs: vec![dummy_output.clone(); outputs],
        };
        let empty_block = |transactions| Block {
            version: BLOCK_VERSION,
            challenge: BlockChallenge {
                network_id: network_params().network_id,
                previous_block: [0; 32],
                transaction_root: [0; 32],
                height: 1,
                timestamp: 1,
                target: [0xff; 32],
            },
            proof: legacy_verifier()
                .mine(
                    &BlockChallenge {
                        network_id: network_params().network_id,
                        previous_block: [0; 32],
                        transaction_root: [0; 32],
                        height: 1,
                        timestamp: 1,
                        target: [0xff; 32],
                    },
                    0,
                    1,
                )
                .unwrap(),
            coinbase: Coinbase {
                height: 1,
                outputs: vec![],
            },
            transactions,
        };

        assert_eq!(
            validate_block_resources(&empty_block(vec![
                transaction(0, 0);
                MAX_BLOCK_TRANSACTIONS + 1
            ])),
            Err(ChainError::BlockTransactionLimit)
        );
        assert_eq!(
            validate_block_resources(&empty_block(vec![transaction(
                MAX_TRANSACTION_INPUTS + 1,
                1,
            )])),
            Err(ChainError::TransactionInputLimit)
        );
        assert_eq!(
            validate_block_resources(&empty_block(vec![transaction(
                1,
                MAX_TRANSACTION_OUTPUTS + 1,
            )])),
            Err(ChainError::TransactionOutputLimit)
        );

        let mut excess_coinbase = empty_block(vec![]);
        excess_coinbase.coinbase.outputs = vec![dummy_output.clone(); 4];
        assert_eq!(
            validate_block_resources(&excess_coinbase),
            Err(ChainError::CoinbaseOutputLimit)
        );

        let mut malformed_signature = transaction(1, 1);
        let InputWitness::Key { signature, .. } = &mut malformed_signature.inputs[0].witness else {
            unreachable!();
        };
        signature.push(0);
        assert_eq!(
            validate_block_resources(&empty_block(vec![malformed_signature])),
            Err(ChainError::SignatureLength)
        );

        let aggregate = (0..(MAX_BLOCK_AGGREGATE_INPUTS / MAX_TRANSACTION_INPUTS + 1))
            .map(|_| transaction(MAX_TRANSACTION_INPUTS, 1))
            .collect();
        assert_eq!(
            validate_block_resources(&empty_block(aggregate)),
            Err(ChainError::BlockAggregateLimit)
        );

        let signatures = (0..(MAX_BLOCK_SIGNATURE_CHECKS / MAX_TRANSACTION_INPUTS + 1))
            .map(|_| transaction(MAX_TRANSACTION_INPUTS, 1))
            .collect();
        assert_eq!(
            validate_block_resources(&empty_block(signatures)),
            Err(ChainError::BlockSignatureLimit)
        );

        let state = chain_state(network_params());
        let mut unsupported = transaction(0, 0);
        unsupported.version = TRANSACTION_VERSION + 1;
        let block = block_for_state(&state, 60, miner_destination(), vec![unsupported], 0, 0);
        let mut candidate = state;
        assert_eq!(
            candidate.validate_and_apply(&block, validation_context(60)),
            Err(ChainError::UnsupportedTransactionVersion)
        );
    }

    #[test]
    fn direct_consensus_enforces_the_canonical_block_byte_limit() {
        let customer = signing_key(34);
        let provider = signing_key(35);
        let refund_input = TxInput {
            previous: OutPoint {
                txid: [0x71; 32],
                index: 0,
            },
            witness: InputWitness::InferenceRefund {
                terms: channel_terms(&customer, &provider),
            },
        };
        let output = TxOutput {
            value: 1,
            lock: OutputLock::Key(owner(&customer)),
            spendable_height: 0,
        };
        let transaction = Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![refund_input; MAX_TRANSACTION_INPUTS],
            outputs: vec![output],
        };
        let transactions = vec![transaction; MAX_BLOCK_AGGREGATE_INPUTS / MAX_TRANSACTION_INPUTS];
        let state = chain_state(network_params());
        let block = block_for_state(&state, 60, miner_destination(), transactions, 0, 0);
        let mut candidate = state;

        assert_eq!(
            candidate.validate_and_apply(&block, validation_context(60)),
            Err(ChainError::BlockEncoding)
        );
        assert_eq!(candidate.next_height(), 1);
        assert!(candidate.utxos().is_empty());
    }

    #[test]
    fn chain_derives_target_and_parent_instead_of_trusting_miner() {
        let verifier = legacy_verifier();
        let params = network_params();
        let genesis = params.genesis_hash;
        let pow_limit = params.pow_limit;
        let mut state = chain_state(params);
        let allocation = DEFAULT_MONETARY_POLICY.allocation(1, 0).unwrap();
        let coinbase = Coinbase::new(1, allocation, miner_destination(), fixed_destinations());
        let root = merkle_root(&[coinbase.commitment(params.network_id)]);
        let challenge = BlockChallenge {
            network_id: params.network_id,
            previous_block: genesis,
            transaction_root: root,
            height: 1,
            timestamp: 60,
            target: pow_limit,
        };
        let block = Block {
            version: BLOCK_VERSION,
            proof: verifier.mine(&challenge, 0, 1).unwrap(),
            challenge,
            coinbase,
            transactions: vec![],
        };

        let mut easy_target = block.clone();
        easy_target.challenge.target[0] = 0xfe;
        easy_target.proof = verifier.mine(&easy_target.challenge, 0, 1).unwrap();
        assert_eq!(
            state.validate_and_apply(&easy_target, validation_context(60)),
            Err(ChainError::UnexpectedTarget)
        );

        state
            .validate_and_apply(&block, validation_context(60))
            .unwrap();
        assert_eq!(state.tip(), block.block_id());

        let mut wrong_parent = block;
        wrong_parent.challenge.height = 2;
        wrong_parent.coinbase.height = 2;
        wrong_parent.challenge.previous_block = [8; 32];
        wrong_parent.challenge.transaction_root =
            merkle_root(&[wrong_parent.coinbase.commitment(params.network_id)]);
        wrong_parent.proof = verifier.mine(&wrong_parent.challenge, 0, 1).unwrap();
        assert_eq!(
            state.validate_and_apply(&wrong_parent, validation_context(120)),
            Err(ChainError::PreviousBlock)
        );
    }

    #[test]
    fn chain_owned_verifier_rejects_a_different_profile() {
        let _chain_owned_verifier_api: fn(
            &mut ChainState,
            &Block,
            BlockValidationContext,
        ) -> Result<u64, ChainError> = ChainState::validate_and_apply;

        let params = network_params();
        let genesis = params.genesis_hash;
        let pow_limit = params.pow_limit;
        let shortcut_profile = ForgeMatrixProfile {
            layers: 1,
            ..TEST_PROFILE
        };
        let shortcut_verifier = ConsensusPowVerifier::v1_legacy(shortcut_profile).unwrap();
        let mut state = chain_state(params);

        let allocation = DEFAULT_MONETARY_POLICY.allocation(1, 0).unwrap();
        let coinbase = Coinbase::new(1, allocation, miner_destination(), fixed_destinations());
        let challenge = BlockChallenge {
            network_id: params.network_id,
            previous_block: genesis,
            transaction_root: merkle_root(&[coinbase.commitment(params.network_id)]),
            height: 1,
            timestamp: 60,
            target: pow_limit,
        };
        let block = Block {
            version: BLOCK_VERSION,
            proof: shortcut_verifier.mine(&challenge, 0, 1).unwrap(),
            challenge,
            coinbase,
            transactions: vec![],
        };

        assert_eq!(
            state.validate_and_apply(&block, validation_context(60)),
            Err(ChainError::Proof(ForgeMatrixError::ModelRoot))
        );
        assert_eq!(state.tip(), genesis);
        assert_eq!(state.next_height(), 1);
    }

    #[test]
    fn chain_constructor_rejects_a_verifier_with_different_parameters() {
        let mut shortcut_profile = TEST_PROFILE;
        shortcut_profile.layers = 1;
        let verifier = ConsensusPowVerifier::v1_legacy(shortcut_profile).unwrap();

        assert!(matches!(
            ChainState::new(network_params(), verifier),
            Err(ChainError::PowParameterMismatch)
        ));
    }

    #[test]
    fn v2_devnet_chain_accepts_full_recompute_and_rejects_mutation() {
        let reference = v2_test_reference().unwrap();
        let descriptor = reference.descriptor();
        let mut params = network_params();
        params.network_id = descriptor.network_id;
        params.pow = PowParameters::V2Reference(descriptor);
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let mut state = ChainState::new(params, verifier).unwrap();

        let first = block_for_state(&state, 60, miner_destination(), vec![], 0, 7);
        state
            .validate_and_apply(&first, validation_context(60))
            .unwrap();
        assert_eq!(state.tip(), first.block_id());

        let mut mutated = block_for_state(&state, 120, miner_destination(), vec![], 0, 8);
        let original_id = mutated.block_id();
        let BlockProof::V2Reference(proof) = &mut mutated.proof else {
            panic!("v2 network mined a non-v2 proof")
        };
        proof.challenge_digest[0] ^= 1;
        assert_ne!(mutated.block_id(), original_id);

        let tip = state.tip();
        assert_eq!(
            state.validate_and_apply(&mutated, validation_context(120)),
            Err(ChainError::InvalidV2Proof)
        );
        assert_eq!(state.tip(), tip);
        assert_eq!(state.next_height(), 2);
    }

    #[test]
    fn proof_free_preflight_rejects_state_failures_but_never_accepts_a_proof() {
        let reference = v2_test_reference().unwrap();
        let descriptor = reference.descriptor();
        let mut params = network_params();
        params.network_id = descriptor.network_id;
        params.pow = PowParameters::V2Reference(descriptor);
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let state = ChainState::new(params, verifier).unwrap();

        let mut invalid_proof = block_for_state(&state, 60, miner_destination(), vec![], 0, 7);
        let BlockProof::V2Reference(proof) = &mut invalid_proof.proof else {
            panic!("v2 network mined a non-v2 proof")
        };
        proof.challenge_digest[0] ^= 1;
        assert_eq!(
            state.preflight_block(&invalid_proof, validation_context(60)),
            Ok(()),
            "preflight must remain proof-free and cannot become an acceptance path"
        );
        assert!(matches!(
            state.validate_block(&invalid_proof, validation_context(60)),
            Err(ChainError::InvalidV2Proof)
        ));

        let mut wrong_target = block_for_state(&state, 60, miner_destination(), vec![], 0, 8);
        wrong_target.challenge.target[0] ^= 1;
        assert_eq!(
            state.preflight_block(&wrong_target, validation_context(60)),
            Err(ChainError::UnexpectedTarget)
        );
    }

    #[test]
    fn successor_header_snapshot_matches_live_header_preflight() {
        let state = chain_state(network_params());
        let block = block_for_state(&state, 60, miner_destination(), vec![], 0, 7);
        let context = validation_context(60);
        let snapshot = state.successor_header_preflight().unwrap();

        assert_eq!(snapshot.preflight_block(&block, context), Ok(()));
        assert_eq!(
            state.preflight_block_header(&block, context).map(drop),
            Ok(())
        );

        let mut wrong_target = block;
        wrong_target.challenge.target[0] ^= 1;
        assert_eq!(
            snapshot.preflight_block(&wrong_target, context),
            Err(ChainError::UnexpectedTarget)
        );
        assert_eq!(
            state
                .preflight_block_header(&wrong_target, context)
                .map(drop),
            Err(ChainError::UnexpectedTarget)
        );
    }

    #[test]
    fn preverified_successor_keeps_state_checks_and_rejects_capability_reuse() {
        let reference = v2_test_reference().unwrap();
        let descriptor = reference.descriptor();
        let mut params = network_params();
        params.network_id = descriptor.network_id;
        params.pow = PowParameters::V2Reference(descriptor);
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let mut state = ChainState::new(params, verifier).unwrap();

        let first = block_for_state(&state, 60, miner_destination(), vec![], 0, 7);
        let preverified = state
            .verifier
            .preverify(&first.challenge, &first.proof)
            .unwrap();
        let validated = state
            .validate_block_preverified(&first, validation_context(60), &preverified)
            .unwrap();
        state.commit_validated(validated).unwrap();
        assert_eq!(state.tip(), first.block_id());

        let mut second = block_for_state(&state, 120, miner_destination(), vec![], 0, 8);
        let preverified = state
            .verifier
            .preverify(&second.challenge, &second.proof)
            .unwrap();
        let BlockProof::V2Reference(proof) = &mut second.proof else {
            unreachable!();
        };
        proof.work_digest[0] ^= 1;
        let tip = state.tip();
        assert!(matches!(
            state.validate_block_preverified(&second, validation_context(120), &preverified),
            Err(ChainError::PreverifiedProofMismatch)
        ));
        assert_eq!(state.tip(), tip);
        assert_eq!(state.next_height(), 2);
    }

    #[test]
    fn v3_candidate_block_id_binds_public_fields_length_and_structured_bytes() {
        let verifier = legacy_verifier();
        let mut block = block_with_transactions(1, [0; 32], vec![], 0, &verifier);
        block.proof = BlockProof::V3Candidate(Box::new(ForgeMatrixV3CandidateProof {
            algorithm_version: 3,
            proof_version: 1,
            nonce: 7,
            model_manifest_digest: [1; 32],
            challenge_digest: [2; 32],
            final_activation_digest: [3; 32],
            work_digest: [4; 32],
            structured_proof: vec![5, 6, 7],
        }));
        let original_id = block.block_id();

        let mut changed_public_field = block.clone();
        let BlockProof::V3Candidate(proof) = &mut changed_public_field.proof else {
            unreachable!();
        };
        proof.final_activation_digest[0] ^= 1;
        assert_ne!(changed_public_field.block_id(), original_id);

        let mut changed_structured_byte = block.clone();
        let BlockProof::V3Candidate(proof) = &mut changed_structured_byte.proof else {
            unreachable!();
        };
        proof.structured_proof[0] ^= 1;
        assert_ne!(changed_structured_byte.block_id(), original_id);

        let mut changed_structured_length = block;
        let BlockProof::V3Candidate(proof) = &mut changed_structured_length.proof else {
            unreachable!();
        };
        proof.structured_proof.push(8);
        assert_ne!(changed_structured_length.block_id(), original_id);
    }

    #[test]
    fn inference_channel_settlement_pays_gpu_and_burns_close_fee() {
        let customer = signing_key(10);
        let provider = signing_key(11);
        let terms = channel_terms(&customer, &provider);
        let channel_id = terms.channel_id().unwrap();
        let funding = OutPoint {
            txid: [12; 32],
            index: 0,
        };
        let mut utxos = UtxoSet::default();
        utxos.insert_for_testing(
            funding,
            TxOutput {
                value: terms.deposit,
                lock: OutputLock::InferenceChannel { channel_id },
                spendable_height: 0,
            },
        );

        let state = SignedPaymentState::sign(terms.initial_state(100, 32).unwrap(), &customer);
        let settlement = Settlement::close(state, &provider);
        let outputs = channel_outputs(
            settlement.state.state.provider_payment,
            terms.provider_key,
            settlement.state.state.customer_refund,
            terms.customer_key,
            1,
        );
        let transaction = Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: funding,
                witness: InputWitness::InferenceSettlement {
                    terms: terms.clone(),
                    settlement,
                },
            }],
            outputs,
        };
        let transaction_id = transaction.txid();
        let verifier = legacy_verifier();
        let block = block_with_transactions(
            1,
            [7; 32],
            vec![transaction],
            terms.close_fee_burn,
            &verifier,
        );

        let mut redirected = block.clone();
        redirected.transactions[0].outputs[0].lock = OutputLock::Key(terms.customer_key);
        redirected.challenge.transaction_root = redirected.transaction_root();
        redirected.proof = verifier.mine(&redirected.challenge, 0, 1).unwrap();
        assert_eq!(
            utxos.validate_and_apply(&redirected, &verifier, &network_params()),
            Err(ChainError::ChannelCloseShape)
        );

        assert_eq!(
            utxos
                .validate_and_apply(&block, &verifier, &network_params())
                .unwrap(),
            1_000
        );
        assert!(utxos.get(&funding).is_none());
        assert_eq!(
            utxos
                .get(&OutPoint {
                    txid: transaction_id,
                    index: 0
                })
                .unwrap()
                .value,
            428
        );
        assert_eq!(
            utxos
                .get(&OutPoint {
                    txid: transaction_id,
                    index: 1
                })
                .unwrap()
                .value,
            998_572
        );
    }

    #[test]
    fn inference_channel_refund_is_timelocked_and_exact() {
        let customer = signing_key(10);
        let provider = signing_key(11);
        let terms = channel_terms(&customer, &provider);
        let funding = OutPoint {
            txid: [13; 32],
            index: 0,
        };
        let mut utxos = UtxoSet::default();
        utxos.insert_for_testing(
            funding,
            TxOutput {
                value: terms.deposit,
                lock: OutputLock::InferenceChannel {
                    channel_id: terms.channel_id().unwrap(),
                },
                spendable_height: 0,
            },
        );
        let refund_transaction = |height| Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: funding,
                witness: InputWitness::InferenceRefund {
                    terms: terms.clone(),
                },
            }],
            outputs: channel_outputs(
                0,
                terms.provider_key,
                terms.deposit - terms.close_fee_burn,
                terms.customer_key,
                height,
            ),
        };
        let verifier = legacy_verifier();
        let early = block_with_transactions(
            499,
            [7; 32],
            vec![refund_transaction(499)],
            terms.close_fee_burn,
            &verifier,
        );
        assert_eq!(
            utxos.validate_and_apply(&early, &verifier, &network_params()),
            Err(ChainError::Channel(ChannelError::RefundLocked))
        );

        let mature = block_with_transactions(
            500,
            [7; 32],
            vec![refund_transaction(500)],
            terms.close_fee_burn,
            &verifier,
        );
        assert_eq!(
            utxos
                .validate_and_apply(&mature, &verifier, &network_params())
                .unwrap(),
            1_000
        );
        assert!(utxos.get(&funding).is_none());
    }

    #[test]
    fn settlement_and_refund_reject_foreign_network_terms() {
        let customer = signing_key(40);
        let provider = signing_key(41);
        let mut terms = channel_terms(&customer, &provider);
        terms.network_id = [2; 32];
        let channel_id = terms.channel_id().unwrap();
        let funding = OutPoint {
            txid: [0x77; 32],
            index: 0,
        };
        let funded = || {
            let mut utxos = UtxoSet::default();
            utxos.insert_for_testing(
                funding,
                TxOutput {
                    value: terms.deposit,
                    lock: OutputLock::InferenceChannel { channel_id },
                    spendable_height: 0,
                },
            );
            utxos
        };

        let state = SignedPaymentState::sign(terms.initial_state(100, 32).unwrap(), &customer);
        let settlement = Settlement::close(state, &provider);
        let settlement_transaction = Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: funding,
                witness: InputWitness::InferenceSettlement {
                    terms: terms.clone(),
                    settlement,
                },
            }],
            outputs: vec![TxOutput {
                value: 1,
                lock: OutputLock::Key(terms.provider_key),
                spendable_height: 500,
            }],
        };
        assert_eq!(
            funded().apply_transaction(
                &settlement_transaction,
                500,
                network_params().network_id,
                &mut HashSet::new(),
            ),
            Err(ChainError::WrongNetwork)
        );

        let refund_transaction = Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: funding,
                witness: InputWitness::InferenceRefund {
                    terms: terms.clone(),
                },
            }],
            outputs: vec![TxOutput {
                value: 1,
                lock: OutputLock::Key(terms.customer_key),
                spendable_height: 500,
            }],
        };
        assert_eq!(
            funded().apply_transaction(
                &refund_transaction,
                500,
                network_params().network_id,
                &mut HashSet::new(),
            ),
            Err(ChainError::WrongNetwork)
        );
    }

    #[test]
    fn late_transaction_failure_rolls_back_earlier_utxo_changes() {
        let spend_key = signing_key(50);
        let previous = OutPoint {
            txid: [0x80; 32],
            index: 0,
        };
        let mut utxos = UtxoSet::default();
        utxos.insert_for_testing(
            previous,
            TxOutput {
                value: 10_000,
                lock: OutputLock::Key(owner(&spend_key)),
                spendable_height: 0,
            },
        );

        let first = signed_key_spend(previous, &spend_key, 9_000, owner(&signing_key(51)));
        let first_output = OutPoint {
            txid: first.txid(),
            index: 0,
        };
        let missing_key = signing_key(52);
        let missing = signed_key_spend(
            OutPoint {
                txid: [0x81; 32],
                index: 0,
            },
            &missing_key,
            1,
            owner(&signing_key(53)),
        );
        let verifier = legacy_verifier();
        let block = block_with_transactions(1, [7; 32], vec![first, missing], 1_000, &verifier);
        let before = utxos.clone();

        assert_eq!(
            utxos.validate_and_apply(&block, &verifier, &network_params()),
            Err(ChainError::MissingInput)
        );
        assert_eq!(utxos.outputs, before.outputs);
        assert_eq!(utxos.active_channels, before.active_channels);
        assert_eq!(utxos.retired_channels, before.retired_channels);
        assert!(utxos.get(&first_output).is_none());
    }

    #[test]
    fn same_block_chained_spend_reads_staged_outputs() {
        let first_key = signing_key(54);
        let second_key = signing_key(55);
        let previous = OutPoint {
            txid: [0x82; 32],
            index: 0,
        };
        let mut utxos = UtxoSet::default();
        utxos.insert_for_testing(
            previous,
            TxOutput {
                value: 10_000,
                lock: OutputLock::Key(owner(&first_key)),
                spendable_height: 0,
            },
        );

        let first = signed_key_spend(previous, &first_key, 9_000, owner(&second_key));
        let intermediate = OutPoint {
            txid: first.txid(),
            index: 0,
        };
        let second = signed_key_spend(intermediate, &second_key, 8_000, owner(&signing_key(56)));
        let final_output = OutPoint {
            txid: second.txid(),
            index: 0,
        };
        let verifier = legacy_verifier();
        let block = block_with_transactions(1, [7; 32], vec![first, second], 2_000, &verifier);

        assert_eq!(
            utxos
                .validate_and_apply(&block, &verifier, &network_params())
                .unwrap(),
            2_000
        );
        assert!(utxos.get(&previous).is_none());
        assert!(utxos.get(&intermediate).is_none());
        assert_eq!(utxos.get(&final_output).unwrap().value, 8_000);
    }

    #[test]
    fn late_failure_rolls_back_channel_retirement_and_outputs() {
        let customer = signing_key(57);
        let provider = signing_key(58);
        let terms = channel_terms(&customer, &provider);
        let channel_id = terms.channel_id().unwrap();
        let funding = OutPoint {
            txid: [0x83; 32],
            index: 0,
        };
        let mut utxos = UtxoSet::default();
        utxos.insert_for_testing(
            funding,
            TxOutput {
                value: terms.deposit,
                lock: OutputLock::InferenceChannel { channel_id },
                spendable_height: 0,
            },
        );
        let state = SignedPaymentState::sign(terms.initial_state(100, 32).unwrap(), &customer);
        let settlement = Settlement::close(state, &provider);
        let close = Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: funding,
                witness: InputWitness::InferenceSettlement {
                    terms: terms.clone(),
                    settlement: settlement.clone(),
                },
            }],
            outputs: channel_outputs(
                settlement.state.state.provider_payment,
                terms.provider_key,
                settlement.state.state.customer_refund,
                terms.customer_key,
                1,
            ),
        };
        let close_txid = close.txid();
        let missing_key = signing_key(59);
        let missing = signed_key_spend(
            OutPoint {
                txid: [0x84; 32],
                index: 0,
            },
            &missing_key,
            1,
            owner(&signing_key(60)),
        );
        let verifier = legacy_verifier();
        let block = block_with_transactions(
            1,
            [7; 32],
            vec![close, missing],
            terms.close_fee_burn,
            &verifier,
        );
        let before = utxos.clone();

        assert_eq!(
            utxos.validate_and_apply(&block, &verifier, &network_params()),
            Err(ChainError::MissingInput)
        );
        assert_eq!(utxos.outputs, before.outputs);
        assert_eq!(utxos.active_channels, before.active_channels);
        assert_eq!(utxos.retired_channels, before.retired_channels);
        assert!(utxos.active_channels.contains(&channel_id));
        assert!(!utxos.retired_channels.contains(&channel_id));
        assert!(
            utxos
                .get(&OutPoint {
                    txid: close_txid,
                    index: 0,
                })
                .is_none()
        );
    }

    #[test]
    fn large_utxo_set_produces_only_a_touched_state_delta() {
        let spend_key = signing_key(61);
        let owner_key = owner(&spend_key);
        let mut utxos = UtxoSet::default();
        let mut spent_outpoint = None;
        for index in 0_u64..10_000 {
            let mut txid = [0_u8; 32];
            txid[..8].copy_from_slice(&index.to_le_bytes());
            txid[31] = 0xa5;
            let outpoint = OutPoint { txid, index: 0 };
            if index == 9_999 {
                spent_outpoint = Some(outpoint);
            }
            utxos.insert_for_testing(
                outpoint,
                TxOutput {
                    value: 10_000,
                    lock: OutputLock::Key(owner_key),
                    spendable_height: 0,
                },
            );
        }
        let spent_outpoint = spent_outpoint.unwrap();
        let spend = signed_key_spend(spent_outpoint, &spend_key, 9_000, owner(&signing_key(62)));
        let verifier = legacy_verifier();
        let block = block_with_transactions(1, [7; 32], vec![spend], 1_000, &verifier);

        let (fees, delta) = utxos
            .validate_delta(&block, &verifier, &network_params())
            .unwrap();
        assert_eq!(fees, 1_000);
        assert_eq!(utxos.len(), 10_000);
        assert_eq!(
            delta.touched_counts(),
            (2 + block.coinbase.outputs.len(), 0, 0)
        );
        assert!(delta.matches(&utxos));
        assert_eq!(
            delta.outputs.get(&spent_outpoint).unwrap().previous,
            utxos.get(&spent_outpoint).cloned()
        );

        delta.apply(&mut utxos);
        assert_eq!(utxos.len(), 10_000 - 1 + 1 + block.coinbase.outputs.len());
        assert!(utxos.get(&spent_outpoint).is_none());
    }

    #[test]
    fn validated_transition_is_non_mutating_and_stale_commit_is_atomic() {
        let mut state = chain_state(network_params());
        let block = block_for_state(&state, 60, miner_destination(), vec![], 0, 0);
        let first = state
            .validate_block(&block, validation_context(60))
            .unwrap();
        let stale = state
            .validate_block(&block, validation_context(60))
            .unwrap();
        assert_eq!(state.next_height(), 1);
        assert!(state.utxos().is_empty());

        assert_eq!(state.commit_validated(first).unwrap(), 0);
        let before = state.clone();
        assert_eq!(
            state.commit_validated(stale),
            Err(ChainError::StaleValidatedBlock)
        );
        assert_eq!(state.params, before.params);
        assert_eq!(state.utxos.outputs, before.utxos.outputs);
        assert_eq!(state.utxos.active_channels, before.utxos.active_channels);
        assert_eq!(state.utxos.retired_channels, before.utxos.retired_channels);
        assert_eq!(state.history, before.history);
        assert_eq!(state.raw_timestamps, before.raw_timestamps);
        assert_eq!(state.tip, before.tip);
        assert_eq!(state.next_height, before.next_height);
    }

    #[test]
    fn reversible_delta_round_trip_covers_chained_spends_and_channel_retirement() {
        let first_key = signing_key(90);
        let second_key = signing_key(91);
        let funding_key = signing_key(92);
        let customer = signing_key(93);
        let provider = signing_key(94);
        let mut terms = channel_terms(&customer, &provider);
        terms.refund_height = 2;

        let chained_previous = OutPoint {
            txid: [0xa0; 32],
            index: 0,
        };
        let channel_previous = OutPoint {
            txid: [0xa1; 32],
            index: 0,
        };
        let mut state = chain_state(network_params());
        state.utxos.insert_for_testing(
            chained_previous,
            TxOutput {
                value: 10_000,
                lock: OutputLock::Key(owner(&first_key)),
                spendable_height: 0,
            },
        );
        state.utxos.insert_for_testing(
            channel_previous,
            TxOutput {
                value: terms.deposit + 500,
                lock: OutputLock::Key(owner(&funding_key)),
                spendable_height: 0,
            },
        );
        let initial = state.clone();

        let first = signed_key_spend(chained_previous, &first_key, 9_000, owner(&second_key));
        let intermediate = OutPoint {
            txid: first.txid(),
            index: 0,
        };
        let second = signed_key_spend(intermediate, &second_key, 8_000, owner(&signing_key(95)));
        let mut fund_channel = Transaction {
            network_id: state.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: channel_previous,
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: vec![],
                },
            }],
            outputs: vec![TxOutput {
                value: terms.deposit,
                lock: OutputLock::InferenceChannel {
                    channel_id: terms.channel_id().unwrap(),
                },
                spendable_height: 0,
            }],
        };
        fund_channel.sign_all(&[&funding_key]).unwrap();
        let funded_channel = OutPoint {
            txid: fund_channel.txid(),
            index: 0,
        };

        let first_block = block_for_state(
            &state,
            60,
            miner_destination(),
            vec![first, second, fund_channel],
            2_500,
            0,
        );
        let first_validated = state
            .validate_block(&first_block, validation_context(60))
            .unwrap();
        let first_delta_bytes = first_validated.encode_reversible_state_delta().unwrap();
        let mut locally_rehashed_forgery = first_delta_bytes.clone();
        const FEES_OFFSET: usize = 8 + 4 + 3 * 32 + 2 * 8 + 32 + 3 * 8;
        let forged_fees = u64::from_le_bytes(
            locally_rehashed_forgery[FEES_OFFSET..FEES_OFFSET + 8]
                .try_into()
                .unwrap(),
        )
        .checked_add(1)
        .unwrap();
        locally_rehashed_forgery[FEES_OFFSET..FEES_OFFSET + 8]
            .copy_from_slice(&forged_fees.to_le_bytes());
        let payload_len = locally_rehashed_forgery.len() - 32;
        let mut local_hasher =
            Hasher::new_derive_key("CMFD/REVERSIBLE-STATE-DELTA/LOCAL-INTEGRITY/V1");
        local_hasher.update(&locally_rehashed_forgery[..payload_len]);
        locally_rehashed_forgery[payload_len..].copy_from_slice(local_hasher.finalize().as_bytes());
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &locally_rehashed_forgery,
                state.params(),
                initial.tip(),
                first_block.block_id(),
            )
            .unwrap()
            .promote_exact(&first_validated),
            Err(ReversibleStateDeltaError::ValidationMismatch),
        );
        let first_delta = DecodedReversibleStateDelta::decode_bound(
            &first_delta_bytes,
            state.params(),
            initial.tip(),
            first_block.block_id(),
        )
        .unwrap()
        .promote_exact(&first_validated)
        .unwrap();
        state.commit_validated(first_validated).unwrap();
        let after_first = state.clone();

        let refund = Transaction {
            network_id: state.params.network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: funded_channel,
                witness: InputWitness::InferenceRefund {
                    terms: terms.clone(),
                },
            }],
            outputs: channel_outputs(
                0,
                terms.provider_key,
                terms.deposit - terms.close_fee_burn,
                terms.customer_key,
                2,
            ),
        };
        let second_block = block_for_state(
            &state,
            120,
            miner_destination(),
            vec![refund],
            terms.close_fee_burn,
            0,
        );
        let second_validated = state
            .validate_block(&second_block, validation_context(120))
            .unwrap();
        let second_delta_bytes = second_validated.encode_reversible_state_delta().unwrap();
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &first_delta_bytes,
                state.params(),
                initial.tip(),
                first_block.block_id(),
            )
            .unwrap()
            .promote_exact(&second_validated),
            Err(ReversibleStateDeltaError::ValidationMismatch),
        );
        let second_delta = DecodedReversibleStateDelta::decode_bound(
            &second_delta_bytes,
            state.params(),
            first_block.block_id(),
            second_block.block_id(),
        )
        .unwrap()
        .promote_exact(&second_validated)
        .unwrap();
        state.commit_validated(second_validated).unwrap();
        let final_state = state.clone();

        state.undo_reversible_state_delta(second_delta).unwrap();
        assert_chain_states_equal(&state, &after_first);

        state.undo_reversible_state_delta(first_delta).unwrap();
        assert_chain_states_equal(&state, &initial);

        let first_replay = state
            .validate_block(&first_block, validation_context(60))
            .unwrap();
        assert_eq!(
            first_replay.encode_reversible_state_delta().unwrap(),
            first_delta_bytes
        );
        state.commit_validated(first_replay).unwrap();
        let second_replay = state
            .validate_block(&second_block, validation_context(120))
            .unwrap();
        assert_eq!(
            second_replay.encode_reversible_state_delta().unwrap(),
            second_delta_bytes
        );
        state.commit_validated(second_replay).unwrap();
        assert_chain_states_equal(&state, &final_state);
    }

    #[test]
    fn next_block_transaction_validation_is_non_mutating_and_reports_exact_totals() {
        let spend_key = signing_key(70);
        let previous = OutPoint {
            txid: [0x90; 32],
            index: 0,
        };
        let mut state = chain_state(network_params());
        state.utxos.insert_for_testing(
            previous,
            TxOutput {
                value: 10_000,
                lock: OutputLock::Key(owner(&spend_key)),
                spendable_height: state.next_height(),
            },
        );
        let transaction = signed_key_spend(previous, &spend_key, 8_750, owner(&signing_key(71)));
        let created = OutPoint {
            txid: transaction.txid(),
            index: 0,
        };
        let before = state.clone();

        assert_eq!(
            state
                .validate_transactions_for_next_block(&[transaction])
                .unwrap(),
            TransactionSetValidation {
                total_burned_fees: 1_250,
                aggregate_inputs: 1,
                aggregate_outputs: 1,
                signature_checks: 1,
            }
        );
        assert_eq!(state.utxos.outputs, before.utxos.outputs);
        assert_eq!(state.utxos.active_channels, before.utxos.active_channels);
        assert_eq!(state.utxos.retired_channels, before.utxos.retired_channels);
        assert_eq!(state.tip, before.tip);
        assert_eq!(state.next_height, before.next_height);
        assert!(state.utxos.get(&previous).is_some());
        assert!(state.utxos.get(&created).is_none());
    }

    #[test]
    fn next_block_transaction_validation_accepts_same_block_chaining() {
        let first_key = signing_key(72);
        let second_key = signing_key(73);
        let previous = OutPoint {
            txid: [0x91; 32],
            index: 0,
        };
        let mut state = chain_state(network_params());
        state.utxos.insert_for_testing(
            previous,
            TxOutput {
                value: 10_000,
                lock: OutputLock::Key(owner(&first_key)),
                spendable_height: 0,
            },
        );
        let first = signed_key_spend(previous, &first_key, 9_000, owner(&second_key));
        let intermediate = OutPoint {
            txid: first.txid(),
            index: 0,
        };
        let second = signed_key_spend(intermediate, &second_key, 7_500, owner(&signing_key(74)));

        assert_eq!(
            state
                .validate_transactions_for_next_block(&[first, second])
                .unwrap(),
            TransactionSetValidation {
                total_burned_fees: 2_500,
                aggregate_inputs: 2,
                aggregate_outputs: 2,
                signature_checks: 2,
            }
        );
        assert!(state.utxos.get(&previous).is_some());
        assert!(state.utxos.get(&intermediate).is_none());
    }

    #[test]
    fn next_block_transaction_validation_rejects_cross_transaction_conflicts() {
        let first_key = signing_key(75);
        let first_previous = OutPoint {
            txid: [0x92; 32],
            index: 0,
        };
        let second_key = signing_key(76);
        let second_previous = OutPoint {
            txid: [0x93; 32],
            index: 0,
        };
        let mut state = chain_state(network_params());
        for (outpoint, key) in [(first_previous, &first_key), (second_previous, &second_key)] {
            state.utxos.insert_for_testing(
                outpoint,
                TxOutput {
                    value: 10_000,
                    lock: OutputLock::Key(owner(key)),
                    spendable_height: 0,
                },
            );
        }

        let first_spend =
            signed_key_spend(first_previous, &first_key, 9_000, owner(&signing_key(77)));
        let second_spend =
            signed_key_spend(first_previous, &first_key, 8_000, owner(&signing_key(78)));
        assert_eq!(
            state.validate_transactions_for_next_block(&[first_spend, second_spend]),
            Err(ChainError::DuplicateInput)
        );

        let channel_id = [0xa4; 32];
        let channel_funding = |previous, key: &SigningKey| {
            let mut transaction = Transaction {
                network_id: state.params.network_id,
                version: TRANSACTION_VERSION,
                inputs: vec![TxInput {
                    previous,
                    witness: InputWitness::Key {
                        public_key: [0; 32],
                        signature: vec![],
                    },
                }],
                outputs: vec![TxOutput {
                    value: 9_000,
                    lock: OutputLock::InferenceChannel { channel_id },
                    spendable_height: 0,
                }],
            };
            transaction.sign_all(&[key]).unwrap();
            transaction
        };
        assert_eq!(
            state.validate_transactions_for_next_block(&[
                channel_funding(first_previous, &first_key),
                channel_funding(second_previous, &second_key),
            ]),
            Err(ChainError::DuplicateChannel)
        );
    }

    #[test]
    fn next_block_transaction_validation_enforces_maturity() {
        let spend_key = signing_key(79);
        let previous = OutPoint {
            txid: [0x94; 32],
            index: 0,
        };
        let mut state = chain_state(network_params());
        let spendable_height = state.next_height() + 1;
        state.utxos.insert_for_testing(
            previous,
            TxOutput {
                value: 10_000,
                lock: OutputLock::Key(owner(&spend_key)),
                spendable_height,
            },
        );
        let transaction = signed_key_spend(previous, &spend_key, 9_000, owner(&signing_key(80)));

        assert_eq!(
            state.validate_transactions_for_next_block(&[transaction]),
            Err(ChainError::ImmatureInput(spendable_height))
        );
    }

    #[test]
    fn next_block_transaction_validation_enforces_identity_signatures_and_caps() {
        let spend_key = signing_key(81);
        let previous = OutPoint {
            txid: [0x95; 32],
            index: 0,
        };
        let mut state = chain_state(network_params());
        state.utxos.insert_for_testing(
            previous,
            TxOutput {
                value: 10_000,
                lock: OutputLock::Key(owner(&spend_key)),
                spendable_height: 0,
            },
        );
        let valid = signed_key_spend(previous, &spend_key, 9_000, owner(&signing_key(82)));

        let mut wrong_network = valid.clone();
        wrong_network.network_id = [0xee; 32];
        assert_eq!(
            state.validate_transactions_for_next_block(&[wrong_network]),
            Err(ChainError::WrongNetwork)
        );

        let mut wrong_version = valid.clone();
        wrong_version.version += 1;
        assert_eq!(
            state.validate_transactions_for_next_block(&[wrong_version]),
            Err(ChainError::UnsupportedTransactionVersion)
        );

        let mut invalid_signature = valid.clone();
        let InputWitness::Key { signature, .. } = &mut invalid_signature.inputs[0].witness else {
            panic!("test transaction must have a key witness")
        };
        signature[0] ^= 1;
        assert_eq!(
            state.validate_transactions_for_next_block(&[invalid_signature]),
            Err(ChainError::InvalidSignature)
        );

        let mut short_signature = valid.clone();
        let InputWitness::Key { signature, .. } = &mut short_signature.inputs[0].witness else {
            panic!("test transaction must have a key witness")
        };
        signature.pop();
        assert_eq!(
            state.validate_transactions_for_next_block(&[short_signature]),
            Err(ChainError::SignatureLength)
        );

        assert_eq!(
            state.validate_transactions_for_next_block(&vec![
                valid.clone();
                MAX_BLOCK_TRANSACTIONS + 1
            ]),
            Err(ChainError::BlockTransactionLimit)
        );

        let mut too_many_inputs = valid.clone();
        too_many_inputs.inputs = vec![valid.inputs[0].clone(); MAX_TRANSACTION_INPUTS + 1];
        assert_eq!(
            state.validate_transactions_for_next_block(&[too_many_inputs]),
            Err(ChainError::TransactionInputLimit)
        );

        let mut aggregate_inputs = valid.clone();
        aggregate_inputs.inputs = vec![valid.inputs[0].clone(); MAX_TRANSACTION_INPUTS];
        assert_eq!(
            state.validate_transactions_for_next_block(&vec![
                aggregate_inputs;
                MAX_BLOCK_AGGREGATE_INPUTS
                    / MAX_TRANSACTION_INPUTS
                    + 1
            ]),
            Err(ChainError::BlockAggregateLimit)
        );
    }

    #[test]
    fn next_block_transaction_validation_enforces_canonical_byte_bounds() {
        let customer = signing_key(83);
        let provider = signing_key(84);
        let terms = channel_terms(&customer, &provider);
        let payment = SignedPaymentState::sign(terms.initial_state(100, 32).unwrap(), &customer);
        let settlement = Settlement::close(payment, &provider);
        let input = TxInput {
            previous: OutPoint {
                txid: [0x96; 32],
                index: 0,
            },
            witness: InputWitness::InferenceSettlement { terms, settlement },
        };
        let oversized = Transaction {
            network_id: network_params().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![input; MAX_TRANSACTION_INPUTS],
            outputs: vec![TxOutput {
                value: 1,
                lock: OutputLock::Key(owner(&signing_key(85))),
                spendable_height: 0,
            }],
        };
        let state = chain_state(network_params());

        assert_eq!(
            state.validate_transactions_for_next_block(&[oversized]),
            Err(ChainError::BlockEncoding)
        );
    }
}
