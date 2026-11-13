use blake3::Hasher;
use k256::schnorr::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CHANNEL_DOMAIN: &str = "CMFD/MARKETPLACE/CHANNEL/V1";
const STATE_DOMAIN: &str = "CMFD/MARKETPLACE/PAYMENT-STATE/V1";
const RECEIPT_DOMAIN: &str = "CMFD/MARKETPLACE/INFERENCE-RECEIPT/V1";
const SETTLEMENT_DOMAIN: &str = "CMFD/MARKETPLACE/SETTLEMENT/V1";
const SETTLEMENT_WITNESS_DOMAIN: &str = "CMFD/MARKETPLACE/SETTLEMENT-WITNESS/V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelTerms {
    pub network_id: [u8; 32],
    pub job_id: [u8; 32],
    pub customer_key: [u8; 32],
    pub provider_key: [u8; 32],
    pub model_digest: [u8; 32],
    pub runtime_digest: [u8; 32],
    pub input_digest: [u8; 32],
    pub deposit: u64,
    pub close_fee_burn: u64,
    pub base_price: u64,
    pub input_price_per_1000: u64,
    pub output_price_per_1000: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub output_chunk_tokens: u64,
    pub refund_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentState {
    pub channel_id: [u8; 32],
    pub sequence: u64,
    pub input_tokens: u64,
    pub authorized_output_tokens: u64,
    pub provider_payment: u64,
    pub customer_refund: u64,
    pub close_fee_burn: u64,
    pub previous_receipt: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPaymentState {
    pub state: PaymentState,
    pub customer_signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceReceipt {
    pub channel_id: [u8; 32],
    pub state_sequence: u64,
    pub input_tokens: u64,
    pub delivered_output_tokens: u64,
    pub rolling_output_digest: [u8; 32],
    pub completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInferenceReceipt {
    pub receipt: InferenceReceipt,
    pub provider_signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settlement {
    pub state: SignedPaymentState,
    pub provider_signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refund {
    pub channel_id: [u8; 32],
    pub available_height: u64,
    pub customer_amount: u64,
    pub fee_burn: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChannelError {
    #[error("malformed channel terms")]
    Terms,
    #[error("amount arithmetic overflow")]
    AmountOverflow,
    #[error("price exceeds channel deposit")]
    DepositExceeded,
    #[error("channel identifier mismatch")]
    ChannelId,
    #[error("sequence must increase by exactly one")]
    Sequence,
    #[error("input token count changed or exceeds its limit")]
    InputTokens,
    #[error("output authorization is not monotonic, exceeds its limit, or exceeds one chunk")]
    OutputTokens,
    #[error("payment allocation does not match the signed token authorization")]
    Payment,
    #[error("previous provider receipt is missing or mismatched")]
    ReceiptLink,
    #[error("provider receipt exceeds the signed authorization")]
    ReceiptDelivery,
    #[error("malformed Schnorr key or signature")]
    MalformedSignature,
    #[error("Schnorr signature is invalid")]
    InvalidSignature,
    #[error("refund is not yet available")]
    RefundLocked,
}

impl ChannelTerms {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.deposit == 0
            || self.output_chunk_tokens == 0
            || self.max_input_tokens == 0
            || self.max_output_tokens == 0
            || self.close_fee_burn >= self.deposit
            || self.customer_key == self.provider_key
        {
            return Err(ChannelError::Terms);
        }
        VerifyingKey::from_slice(&self.customer_key).map_err(|_| ChannelError::Terms)?;
        VerifyingKey::from_slice(&self.provider_key).map_err(|_| ChannelError::Terms)?;
        Ok(())
    }

    pub fn channel_id(&self) -> Result<[u8; 32], ChannelError> {
        self.validate()?;
        let mut hasher = Hasher::new_derive_key(CHANNEL_DOMAIN);
        encode_terms(self, &mut hasher);
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn quoted_payment(
        &self,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<u64, ChannelError> {
        if input_tokens > self.max_input_tokens {
            return Err(ChannelError::InputTokens);
        }
        if output_tokens > self.max_output_tokens {
            return Err(ChannelError::OutputTokens);
        }
        let input = rounded_token_charge(input_tokens, self.input_price_per_1000)?;
        let output = rounded_token_charge(output_tokens, self.output_price_per_1000)?;
        self.base_price
            .checked_add(input)
            .and_then(|value| value.checked_add(output))
            .ok_or(ChannelError::AmountOverflow)
    }

    pub fn initial_state(
        &self,
        input_tokens: u64,
        authorized_output_tokens: u64,
    ) -> Result<PaymentState, ChannelError> {
        if authorized_output_tokens == 0 || authorized_output_tokens > self.output_chunk_tokens {
            return Err(ChannelError::OutputTokens);
        }
        self.state_for(0, input_tokens, authorized_output_tokens, [0; 32])
    }

    pub fn next_state(
        &self,
        previous: &SignedPaymentState,
        receipt: &SignedInferenceReceipt,
        authorized_output_tokens: u64,
    ) -> Result<PaymentState, ChannelError> {
        self.verify_state(None, previous, None)?;
        self.verify_receipt(previous, receipt)?;
        if authorized_output_tokens < previous.state.authorized_output_tokens
            || authorized_output_tokens - previous.state.authorized_output_tokens
                > self.output_chunk_tokens
        {
            return Err(ChannelError::OutputTokens);
        }
        self.state_for(
            previous.state.sequence + 1,
            previous.state.input_tokens,
            authorized_output_tokens,
            receipt.digest(),
        )
    }

    fn state_for(
        &self,
        sequence: u64,
        input_tokens: u64,
        output_tokens: u64,
        previous_receipt: [u8; 32],
    ) -> Result<PaymentState, ChannelError> {
        let provider_payment = self.quoted_payment(input_tokens, output_tokens)?;
        let used = provider_payment
            .checked_add(self.close_fee_burn)
            .ok_or(ChannelError::AmountOverflow)?;
        let customer_refund = self
            .deposit
            .checked_sub(used)
            .ok_or(ChannelError::DepositExceeded)?;
        Ok(PaymentState {
            channel_id: self.channel_id()?,
            sequence,
            input_tokens,
            authorized_output_tokens: output_tokens,
            provider_payment,
            customer_refund,
            close_fee_burn: self.close_fee_burn,
            previous_receipt,
        })
    }

    pub fn verify_state(
        &self,
        previous: Option<&SignedPaymentState>,
        signed: &SignedPaymentState,
        receipt: Option<&SignedInferenceReceipt>,
    ) -> Result<(), ChannelError> {
        if signed.state.channel_id != self.channel_id()? {
            return Err(ChannelError::ChannelId);
        }
        match previous {
            None => {
                if signed.state.sequence != 0 || signed.state.previous_receipt != [0; 32] {
                    return Err(ChannelError::Sequence);
                }
                if signed.state.authorized_output_tokens == 0
                    || signed.state.authorized_output_tokens > self.output_chunk_tokens
                {
                    return Err(ChannelError::OutputTokens);
                }
            }
            Some(prior) => {
                if signed.state.sequence != prior.state.sequence + 1 {
                    return Err(ChannelError::Sequence);
                }
                if signed.state.input_tokens != prior.state.input_tokens {
                    return Err(ChannelError::InputTokens);
                }
                if signed.state.authorized_output_tokens < prior.state.authorized_output_tokens
                    || signed.state.authorized_output_tokens - prior.state.authorized_output_tokens
                        > self.output_chunk_tokens
                {
                    return Err(ChannelError::OutputTokens);
                }
                let receipt = receipt.ok_or(ChannelError::ReceiptLink)?;
                self.verify_receipt(prior, receipt)?;
                if signed.state.previous_receipt != receipt.digest() {
                    return Err(ChannelError::ReceiptLink);
                }
            }
        }

        let expected = self.state_for(
            signed.state.sequence,
            signed.state.input_tokens,
            signed.state.authorized_output_tokens,
            signed.state.previous_receipt,
        )?;
        if signed.state != expected {
            return Err(ChannelError::Payment);
        }
        verify_signature(
            &self.customer_key,
            &state_digest(&signed.state),
            &signed.customer_signature,
        )
    }

    pub fn verify_receipt(
        &self,
        state: &SignedPaymentState,
        signed: &SignedInferenceReceipt,
    ) -> Result<(), ChannelError> {
        if signed.receipt.channel_id != self.channel_id()?
            || signed.receipt.state_sequence != state.state.sequence
        {
            return Err(ChannelError::ReceiptLink);
        }
        if signed.receipt.input_tokens != state.state.input_tokens
            || signed.receipt.delivered_output_tokens > state.state.authorized_output_tokens
        {
            return Err(ChannelError::ReceiptDelivery);
        }
        verify_signature(
            &self.provider_key,
            &receipt_digest(&signed.receipt),
            &signed.provider_signature,
        )
    }

    pub fn refund(&self, current_height: u64) -> Result<Refund, ChannelError> {
        if current_height < self.refund_height {
            return Err(ChannelError::RefundLocked);
        }
        Ok(Refund {
            channel_id: self.channel_id()?,
            available_height: self.refund_height,
            customer_amount: self.deposit - self.close_fee_burn,
            fee_burn: self.close_fee_burn,
        })
    }
}

impl SignedPaymentState {
    pub fn sign(state: PaymentState, customer: &SigningKey) -> Self {
        let signature: Signature = customer.sign(&state_digest(&state));
        Self {
            state,
            customer_signature: signature.to_bytes().to_vec(),
        }
    }
}

impl SignedInferenceReceipt {
    pub fn sign(receipt: InferenceReceipt, provider: &SigningKey) -> Self {
        let signature: Signature = provider.sign(&receipt_digest(&receipt));
        Self {
            receipt,
            provider_signature: signature.to_bytes().to_vec(),
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(RECEIPT_DOMAIN);
        encode_receipt(&self.receipt, &mut hasher);
        hasher.update(&(self.provider_signature.len() as u64).to_le_bytes());
        hasher.update(&self.provider_signature);
        *hasher.finalize().as_bytes()
    }
}

impl Settlement {
    pub fn close(state: SignedPaymentState, provider: &SigningKey) -> Self {
        let digest = settlement_digest(&state);
        let signature: Signature = provider.sign(&digest);
        Self {
            state,
            provider_signature: signature.to_bytes().to_vec(),
        }
    }

    pub fn verify(&self, terms: &ChannelTerms) -> Result<(), ChannelError> {
        terms
            .verify_state(None, &self.state, None)
            .or_else(|error| {
                // A later state cannot be reconstructed without the receipt chain,
                // but its exact payment and customer signature remain independently
                // verifiable for unilateral close.
                if self.state.state.sequence == 0 {
                    return Err(error);
                }
                verify_close_state(terms, &self.state)
            })?;
        verify_signature(
            &terms.provider_key,
            &settlement_digest(&self.state),
            &self.provider_signature,
        )
    }

    pub fn witness_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(SETTLEMENT_WITNESS_DOMAIN);
        encode_state(&self.state.state, &mut hasher);
        hasher.update(&(self.state.customer_signature.len() as u64).to_le_bytes());
        hasher.update(&self.state.customer_signature);
        hasher.update(&(self.provider_signature.len() as u64).to_le_bytes());
        hasher.update(&self.provider_signature);
        *hasher.finalize().as_bytes()
    }
}

fn verify_close_state(
    terms: &ChannelTerms,
    signed: &SignedPaymentState,
) -> Result<(), ChannelError> {
    if signed.state.channel_id != terms.channel_id()? {
        return Err(ChannelError::ChannelId);
    }
    let expected = terms.state_for(
        signed.state.sequence,
        signed.state.input_tokens,
        signed.state.authorized_output_tokens,
        signed.state.previous_receipt,
    )?;
    if signed.state != expected {
        return Err(ChannelError::Payment);
    }
    verify_signature(
        &terms.customer_key,
        &state_digest(&signed.state),
        &signed.customer_signature,
    )
}

fn rounded_token_charge(tokens: u64, price_per_1000: u64) -> Result<u64, ChannelError> {
    let numerator = u128::from(tokens)
        .checked_mul(u128::from(price_per_1000))
        .and_then(|value| value.checked_add(999))
        .ok_or(ChannelError::AmountOverflow)?;
    u64::try_from(numerator / 1000).map_err(|_| ChannelError::AmountOverflow)
}

fn verify_signature(key: &[u8; 32], digest: &[u8; 32], bytes: &[u8]) -> Result<(), ChannelError> {
    let key = VerifyingKey::from_slice(key).map_err(|_| ChannelError::MalformedSignature)?;
    let signature = Signature::try_from(bytes).map_err(|_| ChannelError::MalformedSignature)?;
    key.verify(digest, &signature)
        .map_err(|_| ChannelError::InvalidSignature)
}

fn state_digest(state: &PaymentState) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(STATE_DOMAIN);
    encode_state(state, &mut hasher);
    *hasher.finalize().as_bytes()
}

fn receipt_digest(receipt: &InferenceReceipt) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(RECEIPT_DOMAIN);
    encode_receipt(receipt, &mut hasher);
    *hasher.finalize().as_bytes()
}

fn settlement_digest(state: &SignedPaymentState) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(SETTLEMENT_DOMAIN);
    encode_state(&state.state, &mut hasher);
    hasher.update(&(state.customer_signature.len() as u64).to_le_bytes());
    hasher.update(&state.customer_signature);
    *hasher.finalize().as_bytes()
}

fn encode_terms(terms: &ChannelTerms, hasher: &mut Hasher) {
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

fn encode_state(state: &PaymentState, hasher: &mut Hasher) {
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

fn encode_receipt(receipt: &InferenceReceipt, hasher: &mut Hasher) {
    hasher.update(&receipt.channel_id);
    for value in [
        receipt.state_sequence,
        receipt.input_tokens,
        receipt.delivered_output_tokens,
    ] {
        hasher.update(&value.to_le_bytes());
    }
    hasher.update(&receipt.rolling_output_digest);
    hasher.update(&[u8::from(receipt.completed)]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 32]).unwrap()
    }

    fn public(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes().into()
    }

    fn terms(customer: &SigningKey, provider: &SigningKey) -> ChannelTerms {
        ChannelTerms {
            network_id: [1; 32],
            job_id: [2; 32],
            customer_key: public(customer),
            provider_key: public(provider),
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

    #[test]
    fn inference_is_prepaid_in_bounded_chunks_and_settles_directly() {
        let customer = key(7);
        let provider = key(8);
        let terms = terms(&customer, &provider);
        let initial = SignedPaymentState::sign(terms.initial_state(100, 32).unwrap(), &customer);
        terms.verify_state(None, &initial, None).unwrap();
        assert_eq!(initial.state.provider_payment, 428);
        assert_eq!(initial.state.customer_refund, 998_572);

        let receipt = SignedInferenceReceipt::sign(
            InferenceReceipt {
                channel_id: terms.channel_id().unwrap(),
                state_sequence: 0,
                input_tokens: 100,
                delivered_output_tokens: 32,
                rolling_output_digest: [9; 32],
                completed: false,
            },
            &provider,
        );
        terms.verify_receipt(&initial, &receipt).unwrap();

        let next =
            SignedPaymentState::sign(terms.next_state(&initial, &receipt, 64).unwrap(), &customer);
        terms
            .verify_state(Some(&initial), &next, Some(&receipt))
            .unwrap();
        assert_eq!(next.state.provider_payment, 556);
        assert_eq!(
            next.state.provider_payment + next.state.customer_refund + next.state.close_fee_burn,
            terms.deposit
        );

        let settlement = Settlement::close(next, &provider);
        settlement.verify(&terms).unwrap();
    }

    #[test]
    fn customer_cannot_authorize_more_than_one_unserved_chunk() {
        let customer = key(7);
        let provider = key(8);
        let terms = terms(&customer, &provider);
        assert_eq!(
            terms.initial_state(100, 64),
            Err(ChannelError::OutputTokens)
        );
    }

    #[test]
    fn provider_cannot_overstate_delivered_tokens() {
        let customer = key(7);
        let provider = key(8);
        let terms = terms(&customer, &provider);
        let initial = SignedPaymentState::sign(terms.initial_state(100, 32).unwrap(), &customer);
        let receipt = SignedInferenceReceipt::sign(
            InferenceReceipt {
                channel_id: terms.channel_id().unwrap(),
                state_sequence: 0,
                input_tokens: 100,
                delivered_output_tokens: 33,
                rolling_output_digest: [9; 32],
                completed: false,
            },
            &provider,
        );
        assert_eq!(
            terms.verify_receipt(&initial, &receipt),
            Err(ChannelError::ReceiptDelivery)
        );
    }

    #[test]
    fn refund_is_time_locked_and_burns_close_fee() {
        let customer = key(7);
        let provider = key(8);
        let terms = terms(&customer, &provider);
        assert_eq!(terms.refund(499), Err(ChannelError::RefundLocked));
        let refund = terms.refund(500).unwrap();
        assert_eq!(refund.customer_amount, 999_000);
        assert_eq!(refund.fee_burn, 1_000);
    }
}
