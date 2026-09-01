//! Pure withdrawal-policy and terminal-action approval primitives.
//!
//! This module deliberately owns no files, clocks, RPC state, wallet keys, or
//! journal storage. Callers load bounded documents, supply the runtime binding
//! and current Unix time, then persist [`PolicyWindowState`] together with the
//! withdrawal journal transition.

use std::collections::HashSet;
use std::fmt;

use k256::schnorr::{Signature, VerifyingKey, signature::Verifier};
use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;

pub(crate) const POLICY_SCHEMA: &str = "common-foundry-exchange-withdrawal-policy-v1";
pub(crate) const APPROVAL_SCHEMA: &str = "common-foundry-exchange-withdrawal-approval-v1";
pub(crate) const ROLLING_WINDOW_SECONDS: u64 = 86_400;
pub(crate) const MAX_POLICY_DOCUMENT_BYTES: usize = 64 * 1024;
pub(crate) const MAX_APPROVAL_DOCUMENT_BYTES: usize = 64 * 1024;
pub(crate) const MAX_APPROVER_KEYS: usize = 32;
pub(crate) const MAX_POLICY_RELEASE_EVENTS: usize = 65_536;
pub(crate) const MAX_APPROVAL_REQUEST_ID_BYTES: usize = 128;
/// A short fixed lifetime prevents a threshold signer from backdating a
/// still-valid approval across rolling-window boundaries.
pub(crate) const MAX_APPROVAL_VALIDITY_SECONDS: u64 = 15 * 60;

const POLICY_ID_DOMAIN: &[u8] = b"CMFD/NODE/EXCHANGE-WITHDRAWAL-POLICY/V1\0";
const ACTION_DIGEST_DOMAIN: &[u8] = b"CMFD/NODE/EXCHANGE-WITHDRAWAL-ACTION/V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalAction {
    Release,
    Cancel,
}

impl WithdrawalAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Cancel => "cancel",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Release => 1,
            Self::Cancel => 2,
        }
    }
}

impl fmt::Display for WithdrawalAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum ExchangePolicyError {
    #[error("withdrawal policy document exceeds its byte limit")]
    PolicyDocumentTooLarge,
    #[error("withdrawal policy JSON is invalid")]
    InvalidPolicyJson,
    #[error("withdrawal policy schema is unsupported")]
    InvalidPolicySchema,
    #[error("withdrawal policy field is invalid: {0}")]
    InvalidPolicyField(&'static str),
    #[error("withdrawal policy does not match the runtime binding: {0}")]
    PolicyBindingMismatch(&'static str),
    #[error("{0} approval public keys must be nonempty, unique, and strictly sorted")]
    ApproverKeysNotStrictlySorted(WithdrawalAction),
    #[error("{0} approval contains an invalid Schnorr public key")]
    InvalidApproverKey(WithdrawalAction),
    #[error("{0} approval threshold is zero or exceeds its public-key count")]
    InvalidApprovalThreshold(WithdrawalAction),
    #[error("withdrawal amount must be nonzero")]
    InvalidWithdrawalAmount,
    #[error("withdrawal debit arithmetic overflow")]
    WithdrawalDebitOverflow,
    #[error("withdrawal amount exceeds the configured single-withdrawal limit")]
    SingleAmountLimitExceeded,
    #[error("withdrawal fee exceeds the configured single-withdrawal limit")]
    SingleFeeLimitExceeded,
    #[error("withdrawal debit exceeds the configured single-withdrawal limit")]
    SingleDebitLimitExceeded,
    #[error("withdrawal would exceed the configured rolling 24-hour debit limit")]
    RollingDebitLimitExceeded,
    #[error("withdrawal would exceed the configured rolling 24-hour release-count limit")]
    RollingCountLimitExceeded,
    #[error("durable withdrawal-policy window state is invalid")]
    InvalidWindowState,
    #[error("system time is behind the durable withdrawal-policy watermark")]
    ClockRegression,
    #[error("withdrawal release was already charged to the policy window")]
    DuplicateReleaseEvent,
    #[error("withdrawal approval document exceeds its byte limit")]
    ApprovalDocumentTooLarge,
    #[error("withdrawal approval JSON is invalid")]
    InvalidApprovalJson,
    #[error("withdrawal approval schema is unsupported")]
    InvalidApprovalSchema,
    #[error("withdrawal approval field is invalid: {0}")]
    InvalidApprovalField(&'static str),
    #[error("withdrawal approval signatures must be unique and strictly sorted")]
    ApprovalSignaturesNotStrictlySorted,
    #[error("withdrawal approval belongs to another policy")]
    ApprovalPolicyMismatch,
    #[error("withdrawal approval authorizes another action")]
    ApprovalActionMismatch,
    #[error("withdrawal approval authorizes another request")]
    ApprovalRequestMismatch,
    #[error("withdrawal approval authorizes another transaction signing digest")]
    ApprovalTransactionSigningDigestMismatch,
    #[error("withdrawal approval authorizes another journal state")]
    ApprovalAnchorMismatch,
    #[error("withdrawal approval authorization time is not before its expiry")]
    ApprovalTimeRangeInvalid,
    #[error("withdrawal approval validity exceeds the maximum allowed lifetime")]
    ApprovalValidityTooLong,
    #[error("withdrawal approval is not yet valid")]
    ApprovalNotYetValid,
    #[error("withdrawal approval is expired")]
    ApprovalExpired,
    #[error("withdrawal approval signer is not authorized for this action")]
    ApprovalSignerUnauthorized,
    #[error("withdrawal approval does not meet its action-specific threshold")]
    ApprovalThresholdNotMet,
    #[error("withdrawal approval signature is invalid")]
    ApprovalSignatureInvalid,
}

impl ExchangePolicyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::PolicyDocumentTooLarge
            | Self::InvalidPolicyJson
            | Self::InvalidPolicySchema
            | Self::InvalidPolicyField(_)
            | Self::ApproverKeysNotStrictlySorted(_)
            | Self::InvalidApproverKey(_)
            | Self::InvalidApprovalThreshold(_) => "invalid_exchange_withdrawal_policy",
            Self::PolicyBindingMismatch(_) => "exchange_withdrawal_policy_binding_mismatch",
            Self::InvalidWithdrawalAmount => "invalid_withdrawal_amount",
            Self::WithdrawalDebitOverflow => "withdrawal_amount_overflow",
            Self::SingleAmountLimitExceeded => "withdrawal_single_amount_limit_exceeded",
            Self::SingleFeeLimitExceeded => "withdrawal_single_fee_limit_exceeded",
            Self::SingleDebitLimitExceeded => "withdrawal_single_debit_limit_exceeded",
            Self::RollingDebitLimitExceeded => "withdrawal_rolling_24h_debit_limit_exceeded",
            Self::RollingCountLimitExceeded => "withdrawal_rolling_24h_count_limit_exceeded",
            Self::InvalidWindowState => "exchange_withdrawal_policy_state_corrupt",
            Self::ClockRegression => "exchange_withdrawal_clock_regression",
            Self::DuplicateReleaseEvent => "withdrawal_policy_release_already_counted",
            Self::ApprovalDocumentTooLarge
            | Self::InvalidApprovalJson
            | Self::InvalidApprovalSchema
            | Self::InvalidApprovalField(_)
            | Self::ApprovalSignaturesNotStrictlySorted => "invalid_withdrawal_approval",
            Self::ApprovalPolicyMismatch => "withdrawal_approval_policy_mismatch",
            Self::ApprovalActionMismatch => "withdrawal_approval_action_mismatch",
            Self::ApprovalRequestMismatch => "withdrawal_approval_request_mismatch",
            Self::ApprovalTransactionSigningDigestMismatch => {
                "withdrawal_approval_transaction_signing_digest_mismatch"
            }
            Self::ApprovalAnchorMismatch => "withdrawal_approval_anchor_mismatch",
            Self::ApprovalTimeRangeInvalid => "withdrawal_approval_time_range_invalid",
            Self::ApprovalValidityTooLong => "withdrawal_approval_validity_too_long",
            Self::ApprovalNotYetValid => "withdrawal_approval_not_yet_valid",
            Self::ApprovalExpired => "withdrawal_approval_expired",
            Self::ApprovalSignerUnauthorized => "withdrawal_approval_signer_unauthorized",
            Self::ApprovalThresholdNotMet => "withdrawal_approval_threshold_not_met",
            Self::ApprovalSignatureInvalid => "withdrawal_approval_signature_invalid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WithdrawalPolicyBinding {
    pub network_id: [u8; 32],
    pub consensus_fingerprint: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub wallet_destination: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalRule {
    pub threshold: u16,
    pub public_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithdrawalPolicy {
    pub binding: WithdrawalPolicyBinding,
    pub max_single_amount_atoms: u64,
    pub max_single_fee_atoms: u64,
    pub max_single_debit_atoms: u64,
    pub max_rolling_24h_debit_atoms: u64,
    pub max_rolling_24h_release_count: u64,
    pub release_approval: ApprovalRule,
    pub cancel_approval: ApprovalRule,
}

impl WithdrawalPolicy {
    pub(crate) fn parse(
        bytes: &[u8],
        expected_binding: WithdrawalPolicyBinding,
    ) -> Result<Self, ExchangePolicyError> {
        if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
            return Err(ExchangePolicyError::PolicyDocumentTooLarge);
        }
        let document: PolicyDocument =
            serde_json::from_slice(bytes).map_err(|_| ExchangePolicyError::InvalidPolicyJson)?;
        if document.schema != POLICY_SCHEMA {
            return Err(ExchangePolicyError::InvalidPolicySchema);
        }
        let binding = WithdrawalPolicyBinding {
            network_id: decode_lower_hex(&document.network_id, "network_id")?,
            consensus_fingerprint: decode_lower_hex(
                &document.consensus_fingerprint,
                "consensus_fingerprint",
            )?,
            genesis_hash: decode_lower_hex(&document.genesis_hash, "genesis_hash")?,
            wallet_destination: decode_lower_hex(
                &document.wallet_destination,
                "wallet_destination",
            )?,
        };
        validate_binding(binding, expected_binding)?;
        let max_single_amount_atoms =
            parse_positive_u64(&document.max_single_amount_atoms, "max_single_amount_atoms")?;
        let max_single_fee_atoms =
            parse_u64(&document.max_single_fee_atoms, "max_single_fee_atoms")?;
        let max_single_debit_atoms =
            parse_positive_u64(&document.max_single_debit_atoms, "max_single_debit_atoms")?;
        let max_rolling_24h_debit_atoms = parse_positive_u64(
            &document.max_rolling_24h_debit_atoms,
            "max_rolling_24h_debit_atoms",
        )?;
        let max_rolling_24h_release_count = parse_positive_u64(
            &document.max_rolling_24h_release_count,
            "max_rolling_24h_release_count",
        )?;
        if max_rolling_24h_release_count > MAX_POLICY_RELEASE_EVENTS as u64 {
            return Err(ExchangePolicyError::InvalidPolicyField(
                "max_rolling_24h_release_count",
            ));
        }
        let release_approval = parse_rule(document.release_approval, WithdrawalAction::Release)?;
        let cancel_approval = parse_rule(document.cancel_approval, WithdrawalAction::Cancel)?;
        Ok(Self {
            binding,
            max_single_amount_atoms,
            max_single_fee_atoms,
            max_single_debit_atoms,
            max_rolling_24h_debit_atoms,
            max_rolling_24h_release_count,
            release_approval,
            cancel_approval,
        })
    }

    pub(crate) fn policy_id(&self) -> [u8; 32] {
        compute_policy_id(self)
    }

    pub(crate) fn approval_rule(&self, action: WithdrawalAction) -> &ApprovalRule {
        match action {
            WithdrawalAction::Release => &self.release_approval,
            WithdrawalAction::Cancel => &self.cancel_approval,
        }
    }

    pub(crate) fn check_static_limits(
        &self,
        amount_atoms: u64,
        fee_atoms: u64,
    ) -> Result<u64, ExchangePolicyError> {
        if amount_atoms == 0 {
            return Err(ExchangePolicyError::InvalidWithdrawalAmount);
        }
        if amount_atoms > self.max_single_amount_atoms {
            return Err(ExchangePolicyError::SingleAmountLimitExceeded);
        }
        if fee_atoms > self.max_single_fee_atoms {
            return Err(ExchangePolicyError::SingleFeeLimitExceeded);
        }
        let debit_atoms = amount_atoms
            .checked_add(fee_atoms)
            .ok_or(ExchangePolicyError::WithdrawalDebitOverflow)?;
        if debit_atoms > self.max_single_debit_atoms {
            return Err(ExchangePolicyError::SingleDebitLimitExceeded);
        }
        Ok(debit_atoms)
    }

    pub(crate) fn window_usage(
        &self,
        state: &PolicyWindowState,
        now_unix_seconds: u64,
    ) -> Result<PolicyWindowUsage, ExchangePolicyError> {
        validate_window_state(state)?;
        ensure_monotonic_time(state, now_unix_seconds)?;
        let mut active_release_count = 0_u64;
        let mut active_debit_atoms = 0_u64;
        for event in state
            .release_events
            .iter()
            .filter(|event| event_is_active(event.released_at_unix_seconds, now_unix_seconds))
        {
            active_release_count = active_release_count
                .checked_add(1)
                .ok_or(ExchangePolicyError::InvalidWindowState)?;
            active_debit_atoms = active_debit_atoms
                .checked_add(event.debit_atoms)
                .ok_or(ExchangePolicyError::InvalidWindowState)?;
        }
        Ok(PolicyWindowUsage {
            evaluated_at_unix_seconds: now_unix_seconds,
            active_release_count,
            active_debit_atoms,
            remaining_release_count: self
                .max_rolling_24h_release_count
                .saturating_sub(active_release_count),
            remaining_debit_atoms: self
                .max_rolling_24h_debit_atoms
                .saturating_sub(active_debit_atoms),
        })
    }

    pub(crate) fn evaluate_release(
        &self,
        state: &PolicyWindowState,
        now_unix_seconds: u64,
        amount_atoms: u64,
        fee_atoms: u64,
    ) -> Result<ReleasePolicyEvaluation, ExchangePolicyError> {
        let debit_atoms = self.check_static_limits(amount_atoms, fee_atoms)?;
        let before = self.window_usage(state, now_unix_seconds)?;
        let release_count_after = before
            .active_release_count
            .checked_add(1)
            .ok_or(ExchangePolicyError::RollingCountLimitExceeded)?;
        if release_count_after > self.max_rolling_24h_release_count {
            return Err(ExchangePolicyError::RollingCountLimitExceeded);
        }
        let debit_atoms_after = before
            .active_debit_atoms
            .checked_add(debit_atoms)
            .ok_or(ExchangePolicyError::RollingDebitLimitExceeded)?;
        if debit_atoms_after > self.max_rolling_24h_debit_atoms {
            return Err(ExchangePolicyError::RollingDebitLimitExceeded);
        }
        Ok(ReleasePolicyEvaluation {
            evaluated_at_unix_seconds: now_unix_seconds,
            debit_atoms,
            active_release_count_before: before.active_release_count,
            active_debit_atoms_before: before.active_debit_atoms,
            active_release_count_after: release_count_after,
            active_debit_atoms_after: debit_atoms_after,
            remaining_release_count_after: self
                .max_rolling_24h_release_count
                .saturating_sub(release_count_after),
            remaining_debit_atoms_after: self
                .max_rolling_24h_debit_atoms
                .saturating_sub(debit_atoms_after),
        })
    }

    /// Atomically updates the caller-owned candidate state. On any error,
    /// `state` remains byte-for-byte unchanged.
    pub(crate) fn commit_release(
        &self,
        state: &mut PolicyWindowState,
        now_unix_seconds: u64,
        request_digest: [u8; 32],
        amount_atoms: u64,
        fee_atoms: u64,
    ) -> Result<ReleasePolicyEvaluation, ExchangePolicyError> {
        validate_window_state(state)?;
        if state
            .release_events
            .iter()
            .any(|event| event.request_digest == request_digest)
        {
            return Err(ExchangePolicyError::DuplicateReleaseEvent);
        }
        let evaluation = self.evaluate_release(state, now_unix_seconds, amount_atoms, fee_atoms)?;
        let mut candidate = state.clone();
        retain_active_events(&mut candidate.release_events, now_unix_seconds);
        if candidate.release_events.len() >= MAX_POLICY_RELEASE_EVENTS {
            return Err(ExchangePolicyError::InvalidWindowState);
        }
        candidate.release_events.push(PolicyReleaseEvent {
            request_digest,
            released_at_unix_seconds: now_unix_seconds,
            debit_atoms: evaluation.debit_atoms,
        });
        candidate.time_watermark_unix_seconds = now_unix_seconds;
        validate_window_state(&candidate)?;
        *state = candidate;
        Ok(evaluation)
    }

    /// Advances the durable clock for a non-release terminal action and prunes
    /// expired events without changing policy consumption.
    pub(crate) fn advance_time_watermark(
        &self,
        state: &mut PolicyWindowState,
        now_unix_seconds: u64,
    ) -> Result<PolicyWindowUsage, ExchangePolicyError> {
        let usage = self.window_usage(state, now_unix_seconds)?;
        let mut candidate = state.clone();
        retain_active_events(&mut candidate.release_events, now_unix_seconds);
        candidate.time_watermark_unix_seconds = now_unix_seconds;
        validate_window_state(&candidate)?;
        *state = candidate;
        Ok(usage)
    }

    pub(crate) fn verify_approval(
        &self,
        approval: &WithdrawalApproval,
        expected: ExpectedApproval<'_>,
        state: &PolicyWindowState,
        now_unix_seconds: u64,
    ) -> Result<VerifiedApproval, ExchangePolicyError> {
        validate_approval_structure(approval)?;
        if approval.policy_id != self.policy_id() {
            return Err(ExchangePolicyError::ApprovalPolicyMismatch);
        }
        if approval.action != expected.action {
            return Err(ExchangePolicyError::ApprovalActionMismatch);
        }
        if approval.request_id != expected.request_id
            || approval.request_digest != expected.request_digest
        {
            return Err(ExchangePolicyError::ApprovalRequestMismatch);
        }
        if approval.transaction_signing_digest != expected.transaction_signing_digest {
            return Err(ExchangePolicyError::ApprovalTransactionSigningDigestMismatch);
        }
        if approval.action_anchor != expected.action_anchor {
            return Err(ExchangePolicyError::ApprovalAnchorMismatch);
        }
        if approval.authorized_at_unix_seconds >= approval.expires_at_unix_seconds {
            return Err(ExchangePolicyError::ApprovalTimeRangeInvalid);
        }
        if approval.expires_at_unix_seconds - approval.authorized_at_unix_seconds
            > MAX_APPROVAL_VALIDITY_SECONDS
        {
            return Err(ExchangePolicyError::ApprovalValidityTooLong);
        }
        if now_unix_seconds < approval.authorized_at_unix_seconds {
            return Err(ExchangePolicyError::ApprovalNotYetValid);
        }
        if now_unix_seconds >= approval.expires_at_unix_seconds {
            return Err(ExchangePolicyError::ApprovalExpired);
        }
        // Rolling accounting uses the durable node submission time. A signed
        // time remains authorization evidence, but cannot move releases
        // across rolling-window boundaries. Clock regression is rejected by
        // the persisted watermark.
        self.window_usage(state, now_unix_seconds)?;
        let rule = self.approval_rule(approval.action);
        if approval.signatures.len() < usize::from(rule.threshold) {
            return Err(ExchangePolicyError::ApprovalThresholdNotMet);
        }
        let signing_digest = approval.signing_digest();
        let mut approved_by = Vec::with_capacity(approval.signatures.len());
        for approval_signature in &approval.signatures {
            if rule
                .public_keys
                .binary_search(&approval_signature.public_key)
                .is_err()
            {
                return Err(ExchangePolicyError::ApprovalSignerUnauthorized);
            }
            let verifying_key = VerifyingKey::from_bytes(&approval_signature.public_key)
                .map_err(|_| ExchangePolicyError::ApprovalSignatureInvalid)?;
            let signature = Signature::try_from(approval_signature.signature.as_slice())
                .map_err(|_| ExchangePolicyError::ApprovalSignatureInvalid)?;
            verifying_key
                .verify(&signing_digest, &signature)
                .map_err(|_| ExchangePolicyError::ApprovalSignatureInvalid)?;
            approved_by.push(approval_signature.public_key);
        }
        Ok(VerifiedApproval {
            action: approval.action,
            decision_id: approval.decision_id,
            signing_digest,
            authorized_at_unix_seconds: approval.authorized_at_unix_seconds,
            expires_at_unix_seconds: approval.expires_at_unix_seconds,
            accounted_at_unix_seconds: now_unix_seconds,
            approved_by,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyReleaseEvent {
    pub request_digest: [u8; 32],
    pub released_at_unix_seconds: u64,
    pub debit_atoms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PolicyWindowState {
    pub time_watermark_unix_seconds: u64,
    pub release_events: Vec<PolicyReleaseEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyWindowUsage {
    pub evaluated_at_unix_seconds: u64,
    pub active_release_count: u64,
    pub active_debit_atoms: u64,
    pub remaining_release_count: u64,
    pub remaining_debit_atoms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReleasePolicyEvaluation {
    pub evaluated_at_unix_seconds: u64,
    pub debit_atoms: u64,
    pub active_release_count_before: u64,
    pub active_debit_atoms_before: u64,
    pub active_release_count_after: u64,
    pub active_debit_atoms_after: u64,
    pub remaining_release_count_after: u64,
    pub remaining_debit_atoms_after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApprovalAnchor {
    pub key_id: [u8; 32],
    pub journal_instance_id: [u8; 32],
    pub generation: u64,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalSignature {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithdrawalApproval {
    pub action: WithdrawalAction,
    pub decision_id: [u8; 32],
    pub policy_id: [u8; 32],
    pub action_anchor: ApprovalAnchor,
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub transaction_signing_digest: [u8; 32],
    pub authorized_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub signatures: Vec<ApprovalSignature>,
}

impl WithdrawalApproval {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ExchangePolicyError> {
        if bytes.len() > MAX_APPROVAL_DOCUMENT_BYTES {
            return Err(ExchangePolicyError::ApprovalDocumentTooLarge);
        }
        let document: ApprovalDocument =
            serde_json::from_slice(bytes).map_err(|_| ExchangePolicyError::InvalidApprovalJson)?;
        if document.schema != APPROVAL_SCHEMA {
            return Err(ExchangePolicyError::InvalidApprovalSchema);
        }
        let action = parse_action(&document.action)?;
        let decision_id = decode_approval_hex(&document.decision_id, "decision_id")?;
        if decision_id == [0; 32] {
            return Err(ExchangePolicyError::InvalidApprovalField("decision_id"));
        }
        let policy_id = decode_approval_hex(&document.policy_id, "policy_id")?;
        if policy_id == [0; 32] {
            return Err(ExchangePolicyError::InvalidApprovalField("policy_id"));
        }
        let action_anchor = ApprovalAnchor {
            key_id: decode_approval_hex(&document.action_anchor.key_id, "action_anchor.key_id")?,
            journal_instance_id: decode_approval_hex(
                &document.action_anchor.journal_instance_id,
                "action_anchor.journal_instance_id",
            )?,
            generation: parse_positive_approval_u64(
                &document.action_anchor.generation,
                "action_anchor.generation",
            )?,
            commitment: decode_approval_hex(
                &document.action_anchor.commitment,
                "action_anchor.commitment",
            )?,
        };
        if action_anchor.key_id == [0; 32]
            || action_anchor.journal_instance_id == [0; 32]
            || action_anchor.commitment == [0; 32]
        {
            return Err(ExchangePolicyError::InvalidApprovalField("action_anchor"));
        }
        validate_request_id(&document.request_id)?;
        let request_digest = decode_approval_hex(&document.request_digest, "request_digest")?;
        if request_digest == [0; 32] {
            return Err(ExchangePolicyError::InvalidApprovalField("request_digest"));
        }
        let transaction_signing_digest = decode_approval_hex(
            &document.transaction_signing_digest,
            "transaction_signing_digest",
        )?;
        if transaction_signing_digest == [0; 32] {
            return Err(ExchangePolicyError::InvalidApprovalField(
                "transaction_signing_digest",
            ));
        }
        let authorized_at_unix_seconds = parse_positive_approval_u64(
            &document.authorized_at_unix_seconds,
            "authorized_at_unix_seconds",
        )?;
        let expires_at_unix_seconds = parse_positive_approval_u64(
            &document.expires_at_unix_seconds,
            "expires_at_unix_seconds",
        )?;
        if authorized_at_unix_seconds >= expires_at_unix_seconds {
            return Err(ExchangePolicyError::ApprovalTimeRangeInvalid);
        }
        if expires_at_unix_seconds - authorized_at_unix_seconds > MAX_APPROVAL_VALIDITY_SECONDS {
            return Err(ExchangePolicyError::ApprovalValidityTooLong);
        }
        if document.signatures.len() > MAX_APPROVER_KEYS {
            return Err(ExchangePolicyError::InvalidApprovalField("signatures"));
        }
        let mut signatures = Vec::with_capacity(document.signatures.len());
        for entry in document.signatures {
            let public_key = decode_approval_hex(&entry.public_key, "signatures.public_key")?;
            VerifyingKey::from_bytes(&public_key)
                .map_err(|_| ExchangePolicyError::InvalidApprovalField("signatures.public_key"))?;
            let signature = decode_approval_hex(&entry.signature, "signatures.signature")?;
            Signature::try_from(signature.as_slice())
                .map_err(|_| ExchangePolicyError::InvalidApprovalField("signatures.signature"))?;
            signatures.push(ApprovalSignature {
                public_key,
                signature,
            });
        }
        if signatures
            .windows(2)
            .any(|pair| pair[0].public_key >= pair[1].public_key)
        {
            return Err(ExchangePolicyError::ApprovalSignaturesNotStrictlySorted);
        }
        Ok(Self {
            action,
            decision_id,
            policy_id,
            action_anchor,
            request_id: document.request_id,
            request_digest,
            transaction_signing_digest,
            authorized_at_unix_seconds,
            expires_at_unix_seconds,
            signatures,
        })
    }

    pub(crate) fn signing_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ACTION_DIGEST_DOMAIN);
        hasher.update(&[self.action.tag()]);
        hasher.update(&self.policy_id);
        hasher.update(&self.action_anchor.key_id);
        hasher.update(&self.action_anchor.journal_instance_id);
        hasher.update(&self.action_anchor.generation.to_le_bytes());
        hasher.update(&self.action_anchor.commitment);
        hasher.update(&(self.request_id.len() as u16).to_le_bytes());
        hasher.update(self.request_id.as_bytes());
        hasher.update(&self.request_digest);
        hasher.update(&self.transaction_signing_digest);
        hasher.update(&self.decision_id);
        hasher.update(&self.authorized_at_unix_seconds.to_le_bytes());
        hasher.update(&self.expires_at_unix_seconds.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    pub(crate) fn canonical_document(&self) -> Value {
        let signatures: Vec<_> = self
            .signatures
            .iter()
            .map(|signature| {
                json!({
                    "public_key": hex::encode(signature.public_key),
                    "signature": hex::encode(signature.signature),
                })
            })
            .collect();
        json!({
            "schema": APPROVAL_SCHEMA,
            "action": self.action.as_str(),
            "decision_id": hex::encode(self.decision_id),
            "policy_id": hex::encode(self.policy_id),
            "action_anchor": {
                "key_id": hex::encode(self.action_anchor.key_id),
                "journal_instance_id": hex::encode(self.action_anchor.journal_instance_id),
                "generation": self.action_anchor.generation.to_string(),
                "commitment": hex::encode(self.action_anchor.commitment),
            },
            "request_id": self.request_id,
            "request_digest": hex::encode(self.request_digest),
            "transaction_signing_digest": hex::encode(self.transaction_signing_digest),
            "authorized_at_unix_seconds": self.authorized_at_unix_seconds.to_string(),
            "expires_at_unix_seconds": self.expires_at_unix_seconds.to_string(),
            "signatures": signatures,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExpectedApproval<'a> {
    pub action: WithdrawalAction,
    pub action_anchor: ApprovalAnchor,
    pub request_id: &'a str,
    pub request_digest: [u8; 32],
    pub transaction_signing_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedApproval {
    pub action: WithdrawalAction,
    pub decision_id: [u8; 32],
    pub signing_digest: [u8; 32],
    /// Threshold-signed authorization time retained in terminal evidence.
    pub authorized_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    /// Trusted caller-supplied submission time used for rolling accounting.
    pub accounted_at_unix_seconds: u64,
    pub approved_by: Vec<[u8; 32]>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    schema: String,
    network_id: String,
    consensus_fingerprint: String,
    genesis_hash: String,
    wallet_destination: String,
    max_single_amount_atoms: String,
    max_single_fee_atoms: String,
    max_single_debit_atoms: String,
    max_rolling_24h_debit_atoms: String,
    max_rolling_24h_release_count: String,
    release_approval: ApprovalRuleDocument,
    cancel_approval: ApprovalRuleDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRuleDocument {
    threshold: String,
    public_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDocument {
    schema: String,
    action: String,
    decision_id: String,
    policy_id: String,
    action_anchor: ApprovalAnchorDocument,
    request_id: String,
    request_digest: String,
    transaction_signing_digest: String,
    authorized_at_unix_seconds: String,
    expires_at_unix_seconds: String,
    signatures: Vec<ApprovalSignatureDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalAnchorDocument {
    key_id: String,
    journal_instance_id: String,
    generation: String,
    commitment: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalSignatureDocument {
    public_key: String,
    signature: String,
}

fn validate_binding(
    actual: WithdrawalPolicyBinding,
    expected: WithdrawalPolicyBinding,
) -> Result<(), ExchangePolicyError> {
    if actual.network_id != expected.network_id {
        return Err(ExchangePolicyError::PolicyBindingMismatch("network_id"));
    }
    if actual.consensus_fingerprint != expected.consensus_fingerprint {
        return Err(ExchangePolicyError::PolicyBindingMismatch(
            "consensus_fingerprint",
        ));
    }
    if actual.genesis_hash != expected.genesis_hash {
        return Err(ExchangePolicyError::PolicyBindingMismatch("genesis_hash"));
    }
    if actual.wallet_destination != expected.wallet_destination {
        return Err(ExchangePolicyError::PolicyBindingMismatch(
            "wallet_destination",
        ));
    }
    Ok(())
}

fn parse_rule(
    document: ApprovalRuleDocument,
    action: WithdrawalAction,
) -> Result<ApprovalRule, ExchangePolicyError> {
    if document.public_keys.is_empty() || document.public_keys.len() > MAX_APPROVER_KEYS {
        return Err(ExchangePolicyError::ApproverKeysNotStrictlySorted(action));
    }
    let threshold_u64 = parse_positive_u64(&document.threshold, "approval.threshold")
        .map_err(|_| ExchangePolicyError::InvalidApprovalThreshold(action))?;
    let threshold = u16::try_from(threshold_u64)
        .map_err(|_| ExchangePolicyError::InvalidApprovalThreshold(action))?;
    if usize::from(threshold) > document.public_keys.len() {
        return Err(ExchangePolicyError::InvalidApprovalThreshold(action));
    }
    let mut public_keys = Vec::with_capacity(document.public_keys.len());
    for encoded in document.public_keys {
        let public_key = decode_lower_hex(&encoded, "approval.public_keys")
            .map_err(|_| ExchangePolicyError::InvalidApproverKey(action))?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| ExchangePolicyError::InvalidApproverKey(action))?;
        public_keys.push(public_key);
    }
    if public_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ExchangePolicyError::ApproverKeysNotStrictlySorted(action));
    }
    Ok(ApprovalRule {
        threshold,
        public_keys,
    })
}

fn compute_policy_id(policy: &WithdrawalPolicy) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(POLICY_ID_DOMAIN);
    hasher.update(&policy.binding.network_id);
    hasher.update(&policy.binding.consensus_fingerprint);
    hasher.update(&policy.binding.genesis_hash);
    hasher.update(&policy.binding.wallet_destination);
    hasher.update(&policy.max_single_amount_atoms.to_le_bytes());
    hasher.update(&policy.max_single_fee_atoms.to_le_bytes());
    hasher.update(&policy.max_single_debit_atoms.to_le_bytes());
    hasher.update(&policy.max_rolling_24h_debit_atoms.to_le_bytes());
    hasher.update(&policy.max_rolling_24h_release_count.to_le_bytes());
    write_rule_hash_input(&mut hasher, &policy.release_approval);
    write_rule_hash_input(&mut hasher, &policy.cancel_approval);
    *hasher.finalize().as_bytes()
}

fn write_rule_hash_input(hasher: &mut blake3::Hasher, rule: &ApprovalRule) {
    hasher.update(&rule.threshold.to_le_bytes());
    hasher.update(&(rule.public_keys.len() as u16).to_le_bytes());
    for public_key in &rule.public_keys {
        hasher.update(public_key);
    }
}

fn parse_action(value: &str) -> Result<WithdrawalAction, ExchangePolicyError> {
    match value {
        "release" => Ok(WithdrawalAction::Release),
        "cancel" => Ok(WithdrawalAction::Cancel),
        _ => Err(ExchangePolicyError::InvalidApprovalField("action")),
    }
}

fn parse_u64(value: &str, field: &'static str) -> Result<u64, ExchangePolicyError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ExchangePolicyError::InvalidPolicyField(field));
    }
    value
        .parse()
        .map_err(|_| ExchangePolicyError::InvalidPolicyField(field))
}

fn parse_positive_u64(value: &str, field: &'static str) -> Result<u64, ExchangePolicyError> {
    let parsed = parse_u64(value, field)?;
    if parsed == 0 {
        return Err(ExchangePolicyError::InvalidPolicyField(field));
    }
    Ok(parsed)
}

fn decode_lower_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], ExchangePolicyError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ExchangePolicyError::InvalidPolicyField(field));
    }
    let mut output = [0_u8; N];
    hex::decode_to_slice(value, &mut output)
        .map_err(|_| ExchangePolicyError::InvalidPolicyField(field))?;
    Ok(output)
}

fn parse_positive_approval_u64(
    value: &str,
    field: &'static str,
) -> Result<u64, ExchangePolicyError> {
    parse_positive_u64(value, field).map_err(|_| ExchangePolicyError::InvalidApprovalField(field))
}

fn decode_approval_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], ExchangePolicyError> {
    decode_lower_hex(value, field).map_err(|_| ExchangePolicyError::InvalidApprovalField(field))
}

fn validate_request_id(request_id: &str) -> Result<(), ExchangePolicyError> {
    if request_id.is_empty()
        || request_id.len() > MAX_APPROVAL_REQUEST_ID_BYTES
        || !request_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ExchangePolicyError::InvalidApprovalField("request_id"));
    }
    Ok(())
}

fn validate_approval_structure(approval: &WithdrawalApproval) -> Result<(), ExchangePolicyError> {
    validate_request_id(&approval.request_id)?;
    if approval.decision_id == [0; 32] {
        return Err(ExchangePolicyError::InvalidApprovalField("decision_id"));
    }
    if approval.policy_id == [0; 32] {
        return Err(ExchangePolicyError::InvalidApprovalField("policy_id"));
    }
    if approval.action_anchor.key_id == [0; 32]
        || approval.action_anchor.journal_instance_id == [0; 32]
        || approval.action_anchor.generation == 0
        || approval.action_anchor.commitment == [0; 32]
    {
        return Err(ExchangePolicyError::InvalidApprovalField("action_anchor"));
    }
    if approval.transaction_signing_digest == [0; 32] {
        return Err(ExchangePolicyError::InvalidApprovalField(
            "transaction_signing_digest",
        ));
    }
    if approval.request_digest == [0; 32] {
        return Err(ExchangePolicyError::InvalidApprovalField("request_digest"));
    }
    if approval.authorized_at_unix_seconds == 0 {
        return Err(ExchangePolicyError::InvalidApprovalField(
            "authorized_at_unix_seconds",
        ));
    }
    if approval.expires_at_unix_seconds == 0 {
        return Err(ExchangePolicyError::InvalidApprovalField(
            "expires_at_unix_seconds",
        ));
    }
    if approval.authorized_at_unix_seconds >= approval.expires_at_unix_seconds {
        return Err(ExchangePolicyError::ApprovalTimeRangeInvalid);
    }
    if approval.signatures.len() > MAX_APPROVER_KEYS {
        return Err(ExchangePolicyError::InvalidApprovalField("signatures"));
    }
    if approval
        .signatures
        .windows(2)
        .any(|pair| pair[0].public_key >= pair[1].public_key)
    {
        return Err(ExchangePolicyError::ApprovalSignaturesNotStrictlySorted);
    }
    Ok(())
}

fn validate_window_state(state: &PolicyWindowState) -> Result<(), ExchangePolicyError> {
    if state.release_events.len() > MAX_POLICY_RELEASE_EVENTS {
        return Err(ExchangePolicyError::InvalidWindowState);
    }
    let mut request_digests = HashSet::with_capacity(state.release_events.len());
    let mut previous_timestamp = None;
    for event in &state.release_events {
        if event.request_digest == [0; 32]
            || event.debit_atoms == 0
            || event.released_at_unix_seconds > state.time_watermark_unix_seconds
            || previous_timestamp.is_some_and(|prior| event.released_at_unix_seconds < prior)
            || !request_digests.insert(event.request_digest)
        {
            return Err(ExchangePolicyError::InvalidWindowState);
        }
        previous_timestamp = Some(event.released_at_unix_seconds);
    }
    Ok(())
}

fn ensure_monotonic_time(
    state: &PolicyWindowState,
    now_unix_seconds: u64,
) -> Result<(), ExchangePolicyError> {
    if now_unix_seconds < state.time_watermark_unix_seconds {
        Err(ExchangePolicyError::ClockRegression)
    } else {
        Ok(())
    }
}

fn event_is_active(released_at_unix_seconds: u64, now_unix_seconds: u64) -> bool {
    if now_unix_seconds < ROLLING_WINDOW_SECONDS {
        true
    } else {
        released_at_unix_seconds > now_unix_seconds - ROLLING_WINDOW_SECONDS
    }
}

fn retain_active_events(events: &mut Vec<PolicyReleaseEvent>, now_unix_seconds: u64) {
    events.retain(|event| event_is_active(event.released_at_unix_seconds, now_unix_seconds));
}

#[cfg(test)]
mod tests {
    use k256::schnorr::{Signature, SigningKey, signature::Signer};
    use serde_json::{Value, json};

    use super::*;

    fn signing_key(marker: u8) -> SigningKey {
        SigningKey::from_bytes(&[marker; 32]).expect("test key is valid")
    }

    fn public_key(marker: u8) -> [u8; 32] {
        signing_key(marker).verifying_key().to_bytes().into()
    }

    fn binding() -> WithdrawalPolicyBinding {
        WithdrawalPolicyBinding {
            network_id: [1; 32],
            consensus_fingerprint: [2; 32],
            genesis_hash: [3; 32],
            wallet_destination: [4; 32],
        }
    }

    fn policy_value() -> Value {
        let mut release_keys = vec![public_key(0x11), public_key(0x22)];
        release_keys.sort_unstable();
        let mut cancel_keys = vec![public_key(0x22), public_key(0x33)];
        cancel_keys.sort_unstable();
        json!({
            "schema": POLICY_SCHEMA,
            "network_id": hex::encode([1; 32]),
            "consensus_fingerprint": hex::encode([2; 32]),
            "genesis_hash": hex::encode([3; 32]),
            "wallet_destination": hex::encode([4; 32]),
            "max_single_amount_atoms": "1000",
            "max_single_fee_atoms": "25",
            "max_single_debit_atoms": "1025",
            "max_rolling_24h_debit_atoms": "5000",
            "max_rolling_24h_release_count": "4",
            "release_approval": {
                "threshold": "2",
                "public_keys": release_keys.into_iter().map(hex::encode).collect::<Vec<_>>()
            },
            "cancel_approval": {
                "threshold": "1",
                "public_keys": cancel_keys.into_iter().map(hex::encode).collect::<Vec<_>>()
            }
        })
    }

    fn policy() -> WithdrawalPolicy {
        WithdrawalPolicy::parse(&serde_json::to_vec(&policy_value()).unwrap(), binding()).unwrap()
    }

    fn anchor() -> ApprovalAnchor {
        ApprovalAnchor {
            key_id: [5; 32],
            journal_instance_id: [6; 32],
            generation: 7,
            commitment: [8; 32],
        }
    }

    fn unsigned_approval(action: WithdrawalAction) -> WithdrawalApproval {
        WithdrawalApproval {
            action,
            decision_id: [10; 32],
            policy_id: policy().policy_id(),
            action_anchor: anchor(),
            request_id: "withdrawal-0001".to_owned(),
            request_digest: [9; 32],
            transaction_signing_digest: [11; 32],
            authorized_at_unix_seconds: 1_800_000_000,
            expires_at_unix_seconds: 1_800_000_600,
            signatures: Vec::new(),
        }
    }

    fn sign_approval(mut approval: WithdrawalApproval, signers: &[u8]) -> WithdrawalApproval {
        approval.signatures.clear();
        let digest = approval.signing_digest();
        approval.signatures = signers
            .iter()
            .map(|marker| {
                let signature: Signature = signing_key(*marker).sign(&digest);
                ApprovalSignature {
                    public_key: public_key(*marker),
                    signature: signature.to_bytes(),
                }
            })
            .collect();
        approval
            .signatures
            .sort_unstable_by_key(|signature| signature.public_key);
        approval
    }

    fn signed_approval_value(action: WithdrawalAction, signers: &[u8]) -> Value {
        let approval = unsigned_approval(action);
        let digest = approval.signing_digest();
        let mut signatures = signers
            .iter()
            .map(|marker| {
                let key = signing_key(*marker);
                let signature: Signature = key.sign(&digest);
                (public_key(*marker), signature.to_bytes())
            })
            .collect::<Vec<_>>();
        signatures.sort_unstable_by_key(|(key, _)| *key);
        json!({
            "schema": APPROVAL_SCHEMA,
            "action": action.as_str(),
            "decision_id": hex::encode(approval.decision_id),
            "policy_id": hex::encode(approval.policy_id),
            "action_anchor": {
                "key_id": hex::encode(approval.action_anchor.key_id),
                "journal_instance_id": hex::encode(approval.action_anchor.journal_instance_id),
                "generation": approval.action_anchor.generation.to_string(),
                "commitment": hex::encode(approval.action_anchor.commitment)
            },
            "request_id": approval.request_id,
            "request_digest": hex::encode(approval.request_digest),
            "transaction_signing_digest": hex::encode(approval.transaction_signing_digest),
            "authorized_at_unix_seconds": approval.authorized_at_unix_seconds.to_string(),
            "expires_at_unix_seconds": approval.expires_at_unix_seconds.to_string(),
            "signatures": signatures.into_iter().map(|(key, signature)| json!({
                "public_key": hex::encode(key),
                "signature": hex::encode(signature)
            })).collect::<Vec<_>>()
        })
    }

    fn parse_approval(value: &Value) -> Result<WithdrawalApproval, ExchangePolicyError> {
        WithdrawalApproval::parse(&serde_json::to_vec(value).unwrap())
    }

    fn expected(action: WithdrawalAction) -> ExpectedApproval<'static> {
        ExpectedApproval {
            action,
            action_anchor: anchor(),
            request_id: "withdrawal-0001",
            request_digest: [9; 32],
            transaction_signing_digest: [11; 32],
        }
    }

    #[test]
    fn strict_policy_parsing_and_policy_id_golden_vector() {
        let parsed = policy();
        assert_eq!(parsed.binding, binding());
        assert_eq!(parsed.release_approval.threshold, 2);
        assert_eq!(parsed.cancel_approval.threshold, 1);
        assert_eq!(
            hex::encode(parsed.policy_id()),
            "b081b67dcf4d7983b6c2d01fb6156ac9c55afe0bffbdbc777dca0653b95bbe3c"
        );

        let mut unknown = policy_value();
        unknown["unknown"] = json!(true);
        assert_eq!(
            WithdrawalPolicy::parse(&serde_json::to_vec(&unknown).unwrap(), binding()),
            Err(ExchangePolicyError::InvalidPolicyJson)
        );

        let mut noncanonical = policy_value();
        noncanonical["max_single_amount_atoms"] = json!("01000");
        assert!(matches!(
            WithdrawalPolicy::parse(&serde_json::to_vec(&noncanonical).unwrap(), binding()),
            Err(ExchangePolicyError::InvalidPolicyField(
                "max_single_amount_atoms"
            ))
        ));

        let mut unrepresentable_window = policy_value();
        unrepresentable_window["max_rolling_24h_release_count"] =
            json!((MAX_POLICY_RELEASE_EVENTS as u64 + 1).to_string());
        assert_eq!(
            WithdrawalPolicy::parse(
                &serde_json::to_vec(&unrepresentable_window).unwrap(),
                binding(),
            ),
            Err(ExchangePolicyError::InvalidPolicyField(
                "max_rolling_24h_release_count"
            ))
        );

        let oversized = vec![b' '; MAX_POLICY_DOCUMENT_BYTES + 1];
        assert_eq!(
            WithdrawalPolicy::parse(&oversized, binding()),
            Err(ExchangePolicyError::PolicyDocumentTooLarge)
        );
    }

    #[test]
    fn policy_id_tracks_post_parse_safety_field_mutation() {
        let mut changed_policy = policy();
        let original_id = changed_policy.policy_id();
        let approval = parse_approval(&signed_approval_value(
            WithdrawalAction::Release,
            &[0x11, 0x22],
        ))
        .unwrap();

        changed_policy.max_single_amount_atoms -= 1;
        assert_ne!(changed_policy.policy_id(), original_id);
        assert_eq!(
            changed_policy.verify_approval(
                &approval,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalPolicyMismatch)
        );
    }

    #[test]
    fn policy_rejects_wrong_binding_bad_threshold_and_unsorted_or_duplicate_keys() {
        let mut wrong_binding = binding();
        wrong_binding.genesis_hash = [0x44; 32];
        assert_eq!(
            WithdrawalPolicy::parse(&serde_json::to_vec(&policy_value()).unwrap(), wrong_binding),
            Err(ExchangePolicyError::PolicyBindingMismatch("genesis_hash"))
        );

        let mut zero_threshold = policy_value();
        zero_threshold["release_approval"]["threshold"] = json!("0");
        assert!(
            WithdrawalPolicy::parse(&serde_json::to_vec(&zero_threshold).unwrap(), binding())
                .is_err()
        );

        let mut unsorted = policy_value();
        unsorted["release_approval"]["public_keys"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert_eq!(
            WithdrawalPolicy::parse(&serde_json::to_vec(&unsorted).unwrap(), binding()),
            Err(ExchangePolicyError::ApproverKeysNotStrictlySorted(
                WithdrawalAction::Release
            ))
        );

        let mut duplicate = policy_value();
        let first = duplicate["cancel_approval"]["public_keys"][0].clone();
        duplicate["cancel_approval"]["public_keys"][1] = first;
        assert_eq!(
            WithdrawalPolicy::parse(&serde_json::to_vec(&duplicate).unwrap(), binding()),
            Err(ExchangePolicyError::ApproverKeysNotStrictlySorted(
                WithdrawalAction::Cancel
            ))
        );
    }

    #[test]
    fn static_amount_fee_and_debit_limits_are_independent_and_inclusive() {
        let policy = policy();
        assert_eq!(policy.check_static_limits(1000, 25), Ok(1025));
        assert_eq!(
            policy.check_static_limits(1001, 0),
            Err(ExchangePolicyError::SingleAmountLimitExceeded)
        );
        assert_eq!(
            policy.check_static_limits(1, 26),
            Err(ExchangePolicyError::SingleFeeLimitExceeded)
        );

        let mut value = policy_value();
        value["max_single_debit_atoms"] = json!("1000");
        let debit_limited =
            WithdrawalPolicy::parse(&serde_json::to_vec(&value).unwrap(), binding()).unwrap();
        assert_eq!(
            debit_limited.check_static_limits(1000, 1),
            Err(ExchangePolicyError::SingleDebitLimitExceeded)
        );
        assert_eq!(
            policy.check_static_limits(0, 0),
            Err(ExchangePolicyError::InvalidWithdrawalAmount)
        );

        let mut value = policy_value();
        value["max_single_amount_atoms"] = json!(u64::MAX.to_string());
        value["max_single_fee_atoms"] = json!(u64::MAX.to_string());
        value["max_single_debit_atoms"] = json!(u64::MAX.to_string());
        let overflow_policy =
            WithdrawalPolicy::parse(&serde_json::to_vec(&value).unwrap(), binding()).unwrap();
        assert_eq!(
            overflow_policy.check_static_limits(u64::MAX, 1),
            Err(ExchangePolicyError::WithdrawalDebitOverflow)
        );
    }

    #[test]
    fn rolling_window_boundary_limits_restart_and_clock_regression_are_fail_closed() {
        let policy = policy();
        let now = 100_000;
        let mut state = PolicyWindowState {
            time_watermark_unix_seconds: now,
            release_events: vec![
                PolicyReleaseEvent {
                    request_digest: [1; 32],
                    released_at_unix_seconds: now - ROLLING_WINDOW_SECONDS,
                    debit_atoms: 4_000,
                },
                PolicyReleaseEvent {
                    request_digest: [2; 32],
                    released_at_unix_seconds: now - ROLLING_WINDOW_SECONDS + 1,
                    debit_atoms: 500,
                },
            ],
        };
        let usage = policy.window_usage(&state, now).unwrap();
        assert_eq!(usage.active_release_count, 1);
        assert_eq!(usage.active_debit_atoms, 500);

        let evaluation = policy
            .commit_release(&mut state, now, [3; 32], 900, 25)
            .unwrap();
        assert_eq!(evaluation.active_release_count_after, 2);
        assert_eq!(evaluation.active_debit_atoms_after, 1_425);
        assert_eq!(state.release_events.len(), 2);

        let restarted = state.clone();
        assert_eq!(
            policy
                .window_usage(&restarted, now)
                .unwrap()
                .active_debit_atoms,
            1_425
        );
        let before_duplicate = state.clone();
        assert_eq!(
            policy.commit_release(&mut state, now, [3; 32], 900, 25),
            Err(ExchangePolicyError::DuplicateReleaseEvent)
        );
        assert_eq!(state, before_duplicate);
        assert_eq!(
            policy.window_usage(&state, now - 1),
            Err(ExchangePolicyError::ClockRegression)
        );
        let before_regression = state.clone();
        assert_eq!(
            policy.commit_release(&mut state, now - 1, [4; 32], 1, 0),
            Err(ExchangePolicyError::ClockRegression)
        );
        assert_eq!(state, before_regression);
        let before_zero_digest = state.clone();
        assert_eq!(
            policy.commit_release(&mut state, now, [0; 32], 1, 0),
            Err(ExchangePolicyError::InvalidWindowState)
        );
        assert_eq!(state, before_zero_digest);
    }

    #[test]
    fn rolling_count_and_debit_denials_do_not_mutate_state() {
        let policy = policy();
        let now = 200_000;
        let mut count_state = PolicyWindowState {
            time_watermark_unix_seconds: now,
            release_events: (1_u8..=4)
                .map(|marker| PolicyReleaseEvent {
                    request_digest: [marker; 32],
                    released_at_unix_seconds: now,
                    debit_atoms: 1,
                })
                .collect(),
        };
        let before = count_state.clone();
        assert_eq!(
            policy.commit_release(&mut count_state, now, [9; 32], 1, 0),
            Err(ExchangePolicyError::RollingCountLimitExceeded)
        );
        assert_eq!(count_state, before);

        let mut debit_state = PolicyWindowState {
            time_watermark_unix_seconds: now,
            release_events: vec![PolicyReleaseEvent {
                request_digest: [1; 32],
                released_at_unix_seconds: now,
                debit_atoms: 4_999,
            }],
        };
        let before = debit_state.clone();
        assert_eq!(
            policy.commit_release(&mut debit_state, now, [2; 32], 1, 1),
            Err(ExchangePolicyError::RollingDebitLimitExceeded)
        );
        assert_eq!(debit_state, before);
    }

    #[test]
    fn watermark_advance_prunes_only_expired_events_and_rejects_corrupt_state() {
        let policy = policy();
        let now = 100_000;
        let mut state = PolicyWindowState {
            time_watermark_unix_seconds: now,
            release_events: vec![
                PolicyReleaseEvent {
                    request_digest: [1; 32],
                    released_at_unix_seconds: now,
                    debit_atoms: 10,
                },
                PolicyReleaseEvent {
                    request_digest: [2; 32],
                    released_at_unix_seconds: now,
                    debit_atoms: 20,
                },
            ],
        };
        policy
            .advance_time_watermark(&mut state, now + ROLLING_WINDOW_SECONDS)
            .unwrap();
        assert!(state.release_events.is_empty());
        assert_eq!(
            state.time_watermark_unix_seconds,
            now + ROLLING_WINDOW_SECONDS
        );

        let corrupt = PolicyWindowState {
            time_watermark_unix_seconds: now,
            release_events: vec![PolicyReleaseEvent {
                request_digest: [1; 32],
                released_at_unix_seconds: now + 1,
                debit_atoms: 1,
            }],
        };
        assert_eq!(
            policy.window_usage(&corrupt, now),
            Err(ExchangePolicyError::InvalidWindowState)
        );
    }

    #[test]
    fn approval_digest_golden_vector_and_action_threshold_verification() {
        let policy = policy();
        let unsigned = unsigned_approval(WithdrawalAction::Release);
        assert_eq!(
            hex::encode(unsigned.signing_digest()),
            "9cbb3e7d09210c6f79ced6bd39d7888806b85aa5859a340a9cb4e9cc029e04a2"
        );
        let approval = parse_approval(&signed_approval_value(
            WithdrawalAction::Release,
            &[0x11, 0x22],
        ))
        .unwrap();
        let verified = policy
            .verify_approval(
                &approval,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_000,
            )
            .unwrap();
        assert_eq!(verified.action, WithdrawalAction::Release);
        assert_eq!(verified.approved_by.len(), 2);

        let insufficient =
            parse_approval(&signed_approval_value(WithdrawalAction::Release, &[0x11])).unwrap();
        assert_eq!(
            policy.verify_approval(
                &insufficient,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalThresholdNotMet)
        );
    }

    #[test]
    fn backdated_long_lived_approval_cannot_bypass_rolling_time() {
        let policy = policy();
        let now = 1_800_000_000;
        let mut backdated = unsigned_approval(WithdrawalAction::Release);
        backdated.authorized_at_unix_seconds = now - (2 * ROLLING_WINDOW_SECONDS);
        backdated.expires_at_unix_seconds = now + 1;
        let backdated = sign_approval(backdated, &[0x11, 0x22]);
        assert_eq!(
            policy.verify_approval(
                &backdated,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                now,
            ),
            Err(ExchangePolicyError::ApprovalValidityTooLong)
        );

        let mut valid = unsigned_approval(WithdrawalAction::Release);
        valid.authorized_at_unix_seconds = now - 600;
        valid.expires_at_unix_seconds = now + 300;
        let valid = sign_approval(valid, &[0x11, 0x22]);
        let verified = policy
            .verify_approval(
                &valid,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                now,
            )
            .unwrap();
        assert_eq!(verified.authorized_at_unix_seconds, now - 600);
        assert_eq!(verified.accounted_at_unix_seconds, now);
    }

    #[test]
    fn cancel_authorization_cannot_be_replayed_as_release_authorization() {
        let policy = policy();
        let cancel =
            parse_approval(&signed_approval_value(WithdrawalAction::Cancel, &[0x33])).unwrap();
        assert!(
            policy
                .verify_approval(
                    &cancel,
                    expected(WithdrawalAction::Cancel),
                    &PolicyWindowState::default(),
                    1_800_000_000,
                )
                .is_ok()
        );
        assert_eq!(
            policy.verify_approval(
                &cancel,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalActionMismatch)
        );
    }

    #[test]
    fn approval_rejects_exclusive_expiry_unknown_signer_and_signed_field_changes() {
        let policy = policy();
        let release = parse_approval(&signed_approval_value(
            WithdrawalAction::Release,
            &[0x11, 0x22],
        ))
        .unwrap();
        assert!(
            policy
                .verify_approval(
                    &release,
                    expected(WithdrawalAction::Release),
                    &PolicyWindowState::default(),
                    1_800_000_599,
                )
                .is_ok()
        );
        assert_eq!(
            policy.verify_approval(
                &release,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_600,
            ),
            Err(ExchangePolicyError::ApprovalExpired)
        );

        assert_eq!(
            policy.verify_approval(
                &release,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_799_999_999,
            ),
            Err(ExchangePolicyError::ApprovalNotYetValid)
        );

        let mut invalid_range = release.clone();
        invalid_range.authorized_at_unix_seconds = invalid_range.expires_at_unix_seconds;
        assert_eq!(
            policy.verify_approval(
                &invalid_range,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalTimeRangeInvalid)
        );

        let unauthorized = parse_approval(&signed_approval_value(
            WithdrawalAction::Release,
            &[0x11, 0x33],
        ))
        .unwrap();
        assert_eq!(
            policy.verify_approval(
                &unauthorized,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalSignerUnauthorized)
        );

        let mut changed = signed_approval_value(WithdrawalAction::Release, &[0x11, 0x22]);
        changed["request_digest"] = json!(hex::encode([0xaa; 32]));
        let changed = parse_approval(&changed).unwrap();
        assert_eq!(
            policy.verify_approval(
                &changed,
                ExpectedApproval {
                    request_digest: [0xaa; 32],
                    ..expected(WithdrawalAction::Release)
                },
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalSignatureInvalid)
        );

        let mut changed = signed_approval_value(WithdrawalAction::Release, &[0x11, 0x22]);
        changed["decision_id"] = json!(hex::encode([0xaa; 32]));
        let changed = parse_approval(&changed).unwrap();
        assert_eq!(
            policy.verify_approval(
                &changed,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalSignatureInvalid)
        );

        let mut changed = signed_approval_value(WithdrawalAction::Release, &[0x11, 0x22]);
        changed["authorized_at_unix_seconds"] = json!("1799999999");
        let changed = parse_approval(&changed).unwrap();
        assert_eq!(
            policy.verify_approval(
                &changed,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalSignatureInvalid)
        );

        let valid = parse_approval(&signed_approval_value(
            WithdrawalAction::Release,
            &[0x11, 0x22],
        ))
        .unwrap();
        assert_eq!(
            policy.verify_approval(
                &valid,
                ExpectedApproval {
                    transaction_signing_digest: [0xbb; 32],
                    ..expected(WithdrawalAction::Release)
                },
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalTransactionSigningDigestMismatch)
        );

        let mut changed = signed_approval_value(WithdrawalAction::Release, &[0x11, 0x22]);
        changed["transaction_signing_digest"] = json!(hex::encode([0xbb; 32]));
        let changed = parse_approval(&changed).unwrap();
        assert_eq!(
            policy.verify_approval(
                &changed,
                ExpectedApproval {
                    transaction_signing_digest: [0xbb; 32],
                    ..expected(WithdrawalAction::Release)
                },
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalSignatureInvalid)
        );
    }

    #[test]
    fn approval_cannot_replay_after_the_expected_journal_anchor_advances() {
        let policy = policy();
        let approval = parse_approval(&signed_approval_value(
            WithdrawalAction::Release,
            &[0x11, 0x22],
        ))
        .unwrap();
        let mut advanced_anchor = anchor();
        advanced_anchor.generation += 1;
        advanced_anchor.commitment = [0xaa; 32];

        assert_eq!(
            policy.verify_approval(
                &approval,
                ExpectedApproval {
                    action_anchor: advanced_anchor,
                    ..expected(WithdrawalAction::Release)
                },
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalAnchorMismatch)
        );
    }

    #[test]
    fn approval_json_is_bounded_deny_unknown_and_strictly_orders_signatures() {
        let mut unknown = signed_approval_value(WithdrawalAction::Release, &[0x11, 0x22]);
        unknown["unknown"] = json!(true);
        assert_eq!(
            parse_approval(&unknown),
            Err(ExchangePolicyError::InvalidApprovalJson)
        );

        for field in ["policy_id", "request_digest", "transaction_signing_digest"] {
            let mut zero = signed_approval_value(WithdrawalAction::Release, &[0x11, 0x22]);
            zero[field] = json!(hex::encode([0; 32]));
            assert_eq!(
                parse_approval(&zero),
                Err(ExchangePolicyError::InvalidApprovalField(field))
            );
        }

        let mut reversed = signed_approval_value(WithdrawalAction::Release, &[0x11, 0x22]);
        reversed["signatures"].as_array_mut().unwrap().reverse();
        assert_eq!(
            parse_approval(&reversed),
            Err(ExchangePolicyError::ApprovalSignaturesNotStrictlySorted)
        );

        let mut duplicate = signed_approval_value(WithdrawalAction::Release, &[0x11, 0x22]);
        let first = duplicate["signatures"][0].clone();
        duplicate["signatures"][1] = first;
        assert_eq!(
            parse_approval(&duplicate),
            Err(ExchangePolicyError::ApprovalSignaturesNotStrictlySorted)
        );

        assert_eq!(
            WithdrawalApproval::parse(&vec![b' '; MAX_APPROVAL_DOCUMENT_BYTES + 1]),
            Err(ExchangePolicyError::ApprovalDocumentTooLarge)
        );

        let policy = policy();
        let mut constructed = parse_approval(&signed_approval_value(
            WithdrawalAction::Release,
            &[0x11, 0x22],
        ))
        .unwrap();
        constructed.signatures[1] = constructed.signatures[0].clone();
        assert_eq!(
            policy.verify_approval(
                &constructed,
                expected(WithdrawalAction::Release),
                &PolicyWindowState::default(),
                1_800_000_000,
            ),
            Err(ExchangePolicyError::ApprovalSignaturesNotStrictlySorted)
        );
    }
}
