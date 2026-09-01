//! Pure v3 exchange-custody orchestration.
//!
//! This engine owns no files, sockets, clocks, chain state, or broadcaster. It
//! accepts an already chain-validated public payment plan and returns candidate
//! journal states. Callers must atomically persist and externally anchor the
//! returned candidate before broadcasting a released transaction or reporting
//! success. Local keys and externally supplied HSM/remote/threshold responses
//! share one keyring-bound verification and assembly path.

use cmfd_consensus::{
    InputWitness, MAX_TRANSACTION_INPUTS, OutPoint, OutputLock, TRANSACTION_VERSION, Transaction,
    decode_transaction, encode_transaction,
};
use k256::schnorr::VerifyingKey;
use serde_json::json;
use thiserror::Error;

use crate::exchange_policy::{
    ApprovalAnchor, ExchangePolicyError, ExpectedApproval, PolicyReleaseEvent, PolicyWindowState,
    VerifiedApproval, WithdrawalAction, WithdrawalApproval, WithdrawalPolicy,
};
use crate::exchange_signer::{
    ExchangeSignerError, SigningExpectationV1, sign_and_assemble_keyring_package,
    signer_profile_for_key,
};
use crate::exchange_withdrawal_v3::{
    AddIntentV3, AttachSignerPackageV3, AuthorizeReleaseV3, CancelWithdrawalV3, CompleteReleaseV3,
    DecisionScopeV3, ExchangeWithdrawalJournalV3, ExchangeWithdrawalV3Error, JournalAnchorV3,
    JournalBindingV3, JournalTransitionV3, KeyringAnchorV3, PolicyReleaseEventV3,
    PolicyWindowStateV3, PrepareWithdrawalV3, RecordOriginV3, ReservedInputV3, ReservedOutpointV3,
    SignerPackageEvidenceV3, TerminalDecisionV3, WithdrawalActionV3, WithdrawalCoreV3,
    WithdrawalPhaseV3, WithdrawalRecordV3,
};
use crate::wallet_keyring::{
    KeyLifecycle, KeyStorageBinding, KeyringRuntimeBinding, WalletKeySummary, WalletKeyring,
};
use crate::wallet_signing_protocol::{
    ReleaseAuthorizationV1, SigningInputV1, SigningPackageV1, SigningProtocolError,
    WithdrawalAnchorV1, encode_unsigned_key_transaction, release_authorization_digest,
    wallet_key_id,
};

const REQUEST_DIGEST_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-REQUEST/V1";
const APPROVAL_SCHEMA: &str = "common-foundry-exchange-withdrawal-approval-v1";

#[derive(Debug, Error)]
pub(crate) enum ExchangeCustodyEngineError {
    #[error(transparent)]
    Journal(#[from] ExchangeWithdrawalV3Error),
    #[error(transparent)]
    Policy(#[from] ExchangePolicyError),
    #[error(transparent)]
    SigningProtocol(#[from] SigningProtocolError),
    #[error(transparent)]
    Signer(#[from] ExchangeSignerError),
    #[error("the externally trusted journal anchor is stale or mismatched")]
    StaleJournalAnchor,
    #[error("journal, policy, and keyring binding mismatch: {0}")]
    BindingMismatch(&'static str),
    #[error("journal policy id does not match the loaded policy")]
    PolicyIdMismatch,
    #[error("journal active keyring does not match the loaded keyring")]
    KeyringAnchorMismatch,
    #[error("policy wallet destination is not represented in the keyring")]
    PolicyWalletKeyMissing,
    #[error("custody payment plan is invalid: {0}")]
    InvalidPlan(&'static str),
    #[error("custody payment plan no longer matches its journaled intent")]
    PlanMismatch,
    #[error("withdrawal request is unknown")]
    UnknownRequest,
    #[error("withdrawal is not in a state that supports this operation")]
    InvalidPhase,
    #[error("withdrawal already ended with the opposite or another terminal decision")]
    TerminalConflict,
    #[error("stored signing package is missing or differs from the exact payment plan")]
    SigningPackageMismatch,
    #[error("release-time chain and reservation revalidation failed")]
    PlanRevalidationFailed,
    #[error("policy state produced by journal and policy engines diverged")]
    PolicyStateDiverged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyTerminalActionV3 {
    Release,
    Cancel,
}

impl CustodyTerminalActionV3 {
    fn policy_action(self) -> WithdrawalAction {
        match self {
            Self::Release => WithdrawalAction::Release,
            Self::Cancel => WithdrawalAction::Cancel,
        }
    }
}

/// Public, secret-free plan supplied only after trusted chain state validates
/// ownership, value, maturity, and reservation availability for every input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CustodyPaymentPlanV3 {
    pub request_id: String,
    pub transaction: Transaction,
    pub recipient: [u8; 32],
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub change_atoms: u64,
    /// Values correspond positionally to `transaction.inputs`.
    pub selected_input_values: Vec<u64>,
    pub output_spendable_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedCustodyCandidateV3 {
    pub journal: ExchangeWithdrawalJournalV3,
    pub package: SigningPackageV1,
    pub package_digest: [u8; 32],
    pub prepared_anchor: JournalAnchorV3,
    pub candidate_anchor: JournalAnchorV3,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnsignedApprovalDocumentV3 {
    pub action: CustodyTerminalActionV3,
    pub decision_id: [u8; 32],
    pub action_anchor: JournalAnchorV3,
    pub signing_digest: [u8; 32],
    pub document: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseCustodyCandidateV3 {
    pub journal: ExchangeWithdrawalJournalV3,
    pub exact_transaction_bytes: Vec<u8>,
    pub txid: [u8; 32],
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedReleaseCustodyCandidateV3 {
    pub journal: ExchangeWithdrawalJournalV3,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CancelCustodyCandidateV3 {
    pub journal: ExchangeWithdrawalJournalV3,
    pub changed: bool,
}

pub(crate) struct ExchangeCustodyEngineV3<'a> {
    journal: &'a ExchangeWithdrawalJournalV3,
    journal_key: &'a [u8; 32],
    policy: &'a WithdrawalPolicy,
    keyring: &'a WalletKeyring,
}

/// Narrow recovery surface for the only operation permitted after the
/// operator-controlled external anchor has pinned `ReleaseAuthorized`.
/// This cannot prepare, authorize, or cancel withdrawals.
pub(crate) struct AuthorizedReleaseCompletionEngineV3<'a> {
    journal: &'a ExchangeWithdrawalJournalV3,
    journal_key: &'a [u8; 32],
    policy: &'a WithdrawalPolicy,
    keyring: &'a WalletKeyring,
    request_id: String,
}

impl<'a> AuthorizedReleaseCompletionEngineV3<'a> {
    pub(crate) fn new(
        journal: &'a ExchangeWithdrawalJournalV3,
        journal_key: &'a [u8; 32],
        trusted_external_authorized_anchor: JournalAnchorV3,
        policy: &'a WithdrawalPolicy,
        keyring: &'a WalletKeyring,
        request_id: &str,
    ) -> Result<Self, ExchangeCustodyEngineError> {
        journal.validate(journal_key)?;
        validate_bindings(journal, policy, keyring)?;
        let record = journal
            .records
            .get(request_id)
            .ok_or(ExchangeCustodyEngineError::UnknownRequest)?;
        let WithdrawalPhaseV3::ReleaseAuthorized(authorized) = &record.phase else {
            return Err(ExchangeCustodyEngineError::InvalidPhase);
        };
        if journal.anchor(journal_key)? != trusted_external_authorized_anchor {
            return Err(ExchangeCustodyEngineError::StaleJournalAnchor);
        }
        let evidence = authorized
            .prepared
            .signer_package
            .as_ref()
            .ok_or(ExchangeCustodyEngineError::SigningPackageMismatch)?;
        verify_stored_package_core(policy, keyring, record, evidence)?;
        Ok(Self {
            journal,
            journal_key,
            policy,
            keyring,
            request_id: request_id.to_owned(),
        })
    }

    pub(crate) fn complete<F>(
        &self,
        plan: &CustodyPaymentPlanV3,
        revalidate_plan: F,
    ) -> Result<ReleaseCustodyCandidateV3, ExchangeCustodyEngineError>
    where
        F: FnOnce(&CustodyPaymentPlanV3) -> bool,
    {
        if plan.request_id != self.request_id {
            return Err(ExchangeCustodyEngineError::PlanMismatch);
        }
        ExchangeCustodyEngineV3 {
            journal: self.journal,
            journal_key: self.journal_key,
            policy: self.policy,
            keyring: self.keyring,
        }
        .complete_authorized_release(plan, revalidate_plan)
    }

    pub(crate) fn complete_with_external_responses<F>(
        &self,
        plan: &CustodyPaymentPlanV3,
        external_response_bytes: &[Vec<u8>],
        revalidate_plan: F,
    ) -> Result<ReleaseCustodyCandidateV3, ExchangeCustodyEngineError>
    where
        F: FnOnce(&CustodyPaymentPlanV3) -> bool,
    {
        if plan.request_id != self.request_id {
            return Err(ExchangeCustodyEngineError::PlanMismatch);
        }
        ExchangeCustodyEngineV3 {
            journal: self.journal,
            journal_key: self.journal_key,
            policy: self.policy,
            keyring: self.keyring,
        }
        .complete_authorized_release_with_external_responses(
            plan,
            external_response_bytes,
            revalidate_plan,
        )
    }
}

impl<'a> ExchangeCustodyEngineV3<'a> {
    pub(crate) fn new(
        journal: &'a ExchangeWithdrawalJournalV3,
        journal_key: &'a [u8; 32],
        trusted_external_anchor: JournalAnchorV3,
        policy: &'a WithdrawalPolicy,
        keyring: &'a WalletKeyring,
    ) -> Result<Self, ExchangeCustodyEngineError> {
        journal.validate(journal_key)?;
        if journal.anchor(journal_key)? != trusted_external_anchor {
            return Err(ExchangeCustodyEngineError::StaleJournalAnchor);
        }
        validate_bindings(journal, policy, keyring)?;
        Ok(Self {
            journal,
            journal_key,
            policy,
            keyring,
        })
    }

    pub(crate) fn current_anchor(&self) -> Result<JournalAnchorV3, ExchangeCustodyEngineError> {
        Ok(self.journal.anchor(self.journal_key)?)
    }

    /// Performs Intent -> Prepared -> exact-package attachment entirely in
    /// memory, returning one candidate for atomic persistence.
    pub(crate) fn prepare(
        &self,
        expected_current_anchor: JournalAnchorV3,
        plan: &CustodyPaymentPlanV3,
    ) -> Result<PreparedCustodyCandidateV3, ExchangeCustodyEngineError> {
        let current_anchor = self.current_anchor()?;
        if current_anchor != expected_current_anchor {
            return Err(ExchangeCustodyEngineError::StaleJournalAnchor);
        }
        self.policy
            .check_static_limits(plan.amount_atoms, plan.fee_atoms)?;
        let plan_parts = validate_and_bind_plan(self.policy, self.keyring, plan)?;

        let (prepared, prepared_anchor) = match self.journal.records.get(&plan.request_id) {
            Some(record) => {
                if record.core != plan_parts.core {
                    return Err(ExchangeCustodyEngineError::PlanMismatch);
                }
                match &record.phase {
                    WithdrawalPhaseV3::Intent => {
                        let prepared = self.journal.apply_transition(
                            self.journal_key,
                            JournalTransitionV3::Prepare(PrepareWithdrawalV3 {
                                expected_anchor: current_anchor,
                                request_id: plan.request_id.clone(),
                                request_digest: plan_parts.core.request_digest,
                            }),
                        )?;
                        let prepared_anchor = prepared.anchor(self.journal_key)?;
                        (prepared, prepared_anchor)
                    }
                    WithdrawalPhaseV3::Prepared(existing) => {
                        if let Some(evidence) = &existing.signer_package {
                            let package = verify_stored_package(
                                self.policy,
                                self.keyring,
                                plan,
                                &plan_parts,
                                evidence,
                            )?;
                            return Ok(PreparedCustodyCandidateV3 {
                                journal: self.journal.clone(),
                                package_digest: package.digest()?,
                                package,
                                prepared_anchor: evidence.prepared_anchor,
                                candidate_anchor: current_anchor,
                                changed: false,
                            });
                        }
                        (self.journal.clone(), current_anchor)
                    }
                    WithdrawalPhaseV3::ReleaseAuthorized(_)
                    | WithdrawalPhaseV3::Released(_)
                    | WithdrawalPhaseV3::Canceled(_) => {
                        return Err(ExchangeCustodyEngineError::TerminalConflict);
                    }
                }
            }
            None => {
                let intent = self.journal.apply_transition(
                    self.journal_key,
                    JournalTransitionV3::AddIntent(AddIntentV3 {
                        expected_anchor: current_anchor,
                        core: plan_parts.core.clone(),
                    }),
                )?;
                let intent_anchor = intent.anchor(self.journal_key)?;
                let prepared = intent.apply_transition(
                    self.journal_key,
                    JournalTransitionV3::Prepare(PrepareWithdrawalV3 {
                        expected_anchor: intent_anchor,
                        request_id: plan.request_id.clone(),
                        request_digest: plan_parts.core.request_digest,
                    }),
                )?;
                let prepared_anchor = prepared.anchor(self.journal_key)?;
                (prepared, prepared_anchor)
            }
        };
        let package = build_signing_package(
            self.policy,
            self.keyring,
            plan,
            &plan_parts,
            prepared_anchor,
        )?;
        let exact_package_bytes = package.encode()?;
        // Reparse the exact transport bytes before journal attachment.
        let package = SigningPackageV1::decode(&exact_package_bytes)?;
        let package_digest = package.digest()?;
        let attached = prepared.apply_transition(
            self.journal_key,
            JournalTransitionV3::AttachSignerPackage(AttachSignerPackageV3 {
                expected_anchor: prepared_anchor,
                request_id: plan.request_id.clone(),
                request_digest: plan_parts.core.request_digest,
                signer_package: SignerPackageEvidenceV3 {
                    prepared_anchor,
                    keyring_anchor: storage_keyring_anchor(self.keyring),
                    transaction_signing_digest: plan_parts.core.signing_digest,
                    exact_package: crate::exchange_withdrawal_v3::ExactBytesV3::signer_package(
                        exact_package_bytes,
                    )?,
                },
            }),
        )?;
        let candidate_anchor = attached.anchor(self.journal_key)?;
        Ok(PreparedCustodyCandidateV3 {
            journal: attached,
            package,
            package_digest,
            prepared_anchor,
            candidate_anchor,
            changed: true,
        })
    }

    /// Produces canonical unsigned JSON and the exact digest approvers sign.
    /// The caller supplies the decision id and validity interval; the engine
    /// never invents operator identities, thresholds, or authorization time.
    pub(crate) fn unsigned_approval_document(
        &self,
        expected_current_anchor: JournalAnchorV3,
        action: CustodyTerminalActionV3,
        request_id: &str,
        decision_id: [u8; 32],
        authorized_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<UnsignedApprovalDocumentV3, ExchangeCustodyEngineError> {
        let current_anchor = self.current_anchor()?;
        if current_anchor != expected_current_anchor {
            return Err(ExchangeCustodyEngineError::StaleJournalAnchor);
        }
        let record = self
            .journal
            .records
            .get(request_id)
            .ok_or(ExchangeCustodyEngineError::UnknownRequest)?;
        match (&record.phase, action) {
            (WithdrawalPhaseV3::Prepared(prepared), CustodyTerminalActionV3::Release)
                if prepared.signer_package.is_some() => {}
            (
                WithdrawalPhaseV3::Intent | WithdrawalPhaseV3::Prepared(_),
                CustodyTerminalActionV3::Cancel,
            ) => {}
            (
                WithdrawalPhaseV3::ReleaseAuthorized(_)
                | WithdrawalPhaseV3::Released(_)
                | WithdrawalPhaseV3::Canceled(_),
                _,
            ) => {
                return Err(ExchangeCustodyEngineError::TerminalConflict);
            }
            _ => return Err(ExchangeCustodyEngineError::InvalidPhase),
        }

        let approval = WithdrawalApproval {
            action: action.policy_action(),
            decision_id,
            policy_id: self.policy.policy_id(),
            action_anchor: approval_anchor(current_anchor),
            request_id: record.core.request_id.clone(),
            request_digest: record.core.request_digest,
            transaction_signing_digest: record.core.signing_digest,
            authorized_at_unix_seconds,
            expires_at_unix_seconds,
            signatures: Vec::new(),
        };
        let document = encode_approval_document(&approval);
        let reparsed = WithdrawalApproval::parse(&document)?;
        let signing_digest = reparsed.signing_digest();
        Ok(UnsignedApprovalDocumentV3 {
            action,
            decision_id,
            action_anchor: current_anchor,
            signing_digest,
            document,
        })
    }

    /// Verifies the distinct release approval and performs durable local-time policy
    /// accounting without touching signing material. The returned candidate
    /// must be atomically persisted and externally anchored before a caller
    /// constructs a new engine and invokes `complete_authorized_release`.
    pub(crate) fn authorize_release(
        &self,
        request_id: &str,
        signed_approval_document: &[u8],
        local_now_unix_seconds: u64,
    ) -> Result<AuthorizedReleaseCustodyCandidateV3, ExchangeCustodyEngineError> {
        let approval = WithdrawalApproval::parse(signed_approval_document)?;
        let record = self
            .journal
            .records
            .get(request_id)
            .ok_or(ExchangeCustodyEngineError::UnknownRequest)?;
        match &record.phase {
            WithdrawalPhaseV3::ReleaseAuthorized(authorized)
                if terminal_matches_approval(
                    record,
                    &authorized.terminal,
                    WithdrawalActionV3::Release,
                    &approval,
                ) =>
            {
                verify_persisted_terminal_approval(
                    self.journal,
                    self.policy,
                    request_id,
                    CustodyTerminalActionV3::Release,
                    signed_approval_document,
                )?;
                return Ok(AuthorizedReleaseCustodyCandidateV3 {
                    journal: self.journal.clone(),
                    changed: false,
                });
            }
            WithdrawalPhaseV3::Released(released)
                if terminal_matches_approval(
                    record,
                    &released.terminal,
                    WithdrawalActionV3::Release,
                    &approval,
                ) =>
            {
                verify_persisted_terminal_approval(
                    self.journal,
                    self.policy,
                    request_id,
                    CustodyTerminalActionV3::Release,
                    signed_approval_document,
                )?;
                return Ok(AuthorizedReleaseCustodyCandidateV3 {
                    journal: self.journal.clone(),
                    changed: false,
                });
            }
            WithdrawalPhaseV3::ReleaseAuthorized(_)
            | WithdrawalPhaseV3::Released(_)
            | WithdrawalPhaseV3::Canceled(_) => {
                return Err(ExchangeCustodyEngineError::TerminalConflict);
            }
            WithdrawalPhaseV3::Intent => {
                return Err(ExchangeCustodyEngineError::InvalidPhase);
            }
            WithdrawalPhaseV3::Prepared(prepared) if prepared.signer_package.is_none() => {
                return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
            }
            WithdrawalPhaseV3::Prepared(_) => {}
        }
        let WithdrawalPhaseV3::Prepared(prepared) = &record.phase else {
            unreachable!("non-Prepared phases returned above")
        };
        let evidence = prepared
            .signer_package
            .as_ref()
            .ok_or(ExchangeCustodyEngineError::SigningPackageMismatch)?;
        verify_stored_package_core(self.policy, self.keyring, record, evidence)?;

        let current_anchor = self.current_anchor()?;
        let mut policy_window = policy_window_from_journal(&self.journal.policy_window);
        let verified = self.policy.verify_approval(
            &approval,
            ExpectedApproval {
                action: WithdrawalAction::Release,
                action_anchor: approval_anchor(current_anchor),
                request_id: &record.core.request_id,
                request_digest: record.core.request_digest,
                transaction_signing_digest: record.core.signing_digest,
            },
            &policy_window,
            local_now_unix_seconds,
        )?;
        self.policy.commit_release(
            &mut policy_window,
            verified.accounted_at_unix_seconds,
            record.core.request_digest,
            record.core.amount_atoms,
            record.core.fee_atoms,
        )?;
        let terminal = terminal_decision(
            self.policy,
            WithdrawalActionV3::Release,
            current_anchor,
            record,
            &verified,
        );
        let candidate = self.journal.apply_transition(
            self.journal_key,
            JournalTransitionV3::AuthorizeRelease(AuthorizeReleaseV3 {
                expected_anchor: current_anchor,
                request_id: record.core.request_id.clone(),
                request_digest: record.core.request_digest,
                terminal,
            }),
        )?;
        if candidate.policy_window != journal_window_from_policy(&policy_window) {
            return Err(ExchangeCustodyEngineError::PolicyStateDiverged);
        }
        Ok(AuthorizedReleaseCustodyCandidateV3 {
            journal: candidate,
            changed: true,
        })
    }

    /// Signs only a previously persisted and externally anchored release
    /// authorization. It rebinds the exact public plan and signer package,
    /// assembles the transaction, requires caller-supplied live revalidation,
    /// and returns a second atomic candidate. It never persists or broadcasts.
    pub(crate) fn complete_authorized_release<F>(
        &self,
        plan: &CustodyPaymentPlanV3,
        revalidate_plan: F,
    ) -> Result<ReleaseCustodyCandidateV3, ExchangeCustodyEngineError>
    where
        F: FnOnce(&CustodyPaymentPlanV3) -> bool,
    {
        self.complete_authorized_release_with_external_responses(plan, &[], revalidate_plan)
    }

    pub(crate) fn complete_authorized_release_with_external_responses<F>(
        &self,
        plan: &CustodyPaymentPlanV3,
        external_response_bytes: &[Vec<u8>],
        revalidate_plan: F,
    ) -> Result<ReleaseCustodyCandidateV3, ExchangeCustodyEngineError>
    where
        F: FnOnce(&CustodyPaymentPlanV3) -> bool,
    {
        let plan_parts = validate_and_bind_plan(self.policy, self.keyring, plan)?;
        let record = self
            .journal
            .records
            .get(&plan.request_id)
            .ok_or(ExchangeCustodyEngineError::UnknownRequest)?;
        if record.core != plan_parts.core {
            return Err(ExchangeCustodyEngineError::PlanMismatch);
        }

        if let WithdrawalPhaseV3::Released(released) = &record.phase {
            let evidence = released
                .prepared
                .signer_package
                .as_ref()
                .ok_or(ExchangeCustodyEngineError::SigningPackageMismatch)?;
            let _package =
                verify_stored_package(self.policy, self.keyring, plan, &plan_parts, evidence)?;
            validate_stored_released_transaction(plan, released)?;
            return Ok(ReleaseCustodyCandidateV3 {
                journal: self.journal.clone(),
                exact_transaction_bytes: released.exact_transaction.bytes.clone(),
                txid: released.txid,
                changed: false,
            });
        }
        if matches!(record.phase, WithdrawalPhaseV3::Canceled(_)) {
            return Err(ExchangeCustodyEngineError::TerminalConflict);
        }
        let WithdrawalPhaseV3::ReleaseAuthorized(authorized) = &record.phase else {
            return Err(ExchangeCustodyEngineError::InvalidPhase);
        };
        let evidence = authorized
            .prepared
            .signer_package
            .as_ref()
            .ok_or(ExchangeCustodyEngineError::SigningPackageMismatch)?;
        let package =
            verify_stored_package(self.policy, self.keyring, plan, &plan_parts, evidence)?;
        let package_digest = package.digest()?;
        let current_anchor = self.current_anchor()?;
        let release_authorization_digest = release_authorization_digest(
            &package_digest,
            ReleaseAuthorizationV1 {
                release_authorized_anchor: withdrawal_anchor(current_anchor),
                decision_id: authorized.terminal.decision_id,
                approval_digest: authorized.terminal.approval_digest,
            },
        )?;
        let signed = sign_and_assemble_keyring_package(
            self.keyring,
            &package,
            SigningExpectationV1 {
                package_digest,
                policy_id: self.policy.policy_id(),
                prepared_anchor: withdrawal_anchor(evidence.prepared_anchor),
                release_authorization_digest,
            },
            external_response_bytes,
        )?;
        validate_assembled_transaction(plan, &signed.assembled.transaction)?;
        if !revalidate_plan(plan) {
            return Err(ExchangeCustodyEngineError::PlanRevalidationFailed);
        }

        let candidate = self.journal.apply_transition(
            self.journal_key,
            JournalTransitionV3::CompleteRelease(CompleteReleaseV3 {
                expected_anchor: current_anchor,
                request_id: record.core.request_id.clone(),
                request_digest: record.core.request_digest,
                decision_id: authorized.terminal.decision_id,
                approval_digest: authorized.terminal.approval_digest,
                signer_package_digest: evidence.exact_package.digest,
                transaction_signing_digest: record.core.signing_digest,
                txid: signed.assembled.txid,
                exact_transaction_bytes: signed.assembled.transaction_bytes.clone(),
            }),
        )?;
        if candidate.policy_window != self.journal.policy_window {
            return Err(ExchangeCustodyEngineError::PolicyStateDiverged);
        }
        Ok(ReleaseCustodyCandidateV3 {
            journal: candidate,
            exact_transaction_bytes: signed.assembled.transaction_bytes,
            txid: signed.assembled.txid,
            changed: true,
        })
    }

    /// Verifies the action-distinct cancel approval and advances the durable
    /// durable local-submission watermark without charging release limits.
    pub(crate) fn cancel(
        &self,
        request_id: &str,
        signed_approval_document: &[u8],
        local_now_unix_seconds: u64,
    ) -> Result<CancelCustodyCandidateV3, ExchangeCustodyEngineError> {
        let approval = WithdrawalApproval::parse(signed_approval_document)?;
        let record = self
            .journal
            .records
            .get(request_id)
            .ok_or(ExchangeCustodyEngineError::UnknownRequest)?;
        if let WithdrawalPhaseV3::Canceled(canceled) = &record.phase {
            if terminal_matches_approval(
                record,
                &canceled.terminal,
                WithdrawalActionV3::Cancel,
                &approval,
            ) {
                verify_persisted_terminal_approval(
                    self.journal,
                    self.policy,
                    request_id,
                    CustodyTerminalActionV3::Cancel,
                    signed_approval_document,
                )?;
                return Ok(CancelCustodyCandidateV3 {
                    journal: self.journal.clone(),
                    changed: false,
                });
            }
            return Err(ExchangeCustodyEngineError::TerminalConflict);
        }
        if matches!(
            record.phase,
            WithdrawalPhaseV3::ReleaseAuthorized(_) | WithdrawalPhaseV3::Released(_)
        ) {
            return Err(ExchangeCustodyEngineError::TerminalConflict);
        }
        if !matches!(
            record.phase,
            WithdrawalPhaseV3::Intent | WithdrawalPhaseV3::Prepared(_)
        ) {
            return Err(ExchangeCustodyEngineError::InvalidPhase);
        }

        let current_anchor = self.current_anchor()?;
        let mut policy_window = policy_window_from_journal(&self.journal.policy_window);
        let verified = self.policy.verify_approval(
            &approval,
            ExpectedApproval {
                action: WithdrawalAction::Cancel,
                action_anchor: approval_anchor(current_anchor),
                request_id: &record.core.request_id,
                request_digest: record.core.request_digest,
                transaction_signing_digest: record.core.signing_digest,
            },
            &policy_window,
            local_now_unix_seconds,
        )?;
        self.policy
            .advance_time_watermark(&mut policy_window, verified.accounted_at_unix_seconds)?;
        let terminal = terminal_decision(
            self.policy,
            WithdrawalActionV3::Cancel,
            current_anchor,
            record,
            &verified,
        );
        let candidate = self.journal.apply_transition(
            self.journal_key,
            JournalTransitionV3::Cancel(CancelWithdrawalV3 {
                expected_anchor: current_anchor,
                request_id: record.core.request_id.clone(),
                request_digest: record.core.request_digest,
                terminal,
            }),
        )?;
        if candidate.policy_window != journal_window_from_policy(&policy_window) {
            return Err(ExchangeCustodyEngineError::PolicyStateDiverged);
        }
        Ok(CancelCustodyCandidateV3 {
            journal: candidate,
            changed: true,
        })
    }
}

/// Revalidates the threshold signatures and every semantic field of an
/// approval that is already represented by a durable terminal decision. This
/// deliberately does not re-run expiry or rolling-limit accounting: those
/// gates were consumed before the authenticated terminal transition was
/// published, and crash recovery must not become impossible after expiry. A
/// validated-v2 approval is retry evidence only for its already Released
/// migration record; it can never authorize a new v3 release or cancellation.
pub(crate) fn verify_persisted_terminal_approval(
    journal: &ExchangeWithdrawalJournalV3,
    policy: &WithdrawalPolicy,
    request_id: &str,
    expected_action: CustodyTerminalActionV3,
    signed_approval_document: &[u8],
) -> Result<(), ExchangeCustodyEngineError> {
    let approval = WithdrawalApproval::parse(signed_approval_document)?;
    let record = journal
        .records
        .get(request_id)
        .ok_or(ExchangeCustodyEngineError::UnknownRequest)?;
    let terminal = match &record.phase {
        WithdrawalPhaseV3::ReleaseAuthorized(authorized) => &authorized.terminal,
        WithdrawalPhaseV3::Released(released) => &released.terminal,
        WithdrawalPhaseV3::Canceled(canceled) => &canceled.terminal,
        WithdrawalPhaseV3::Intent | WithdrawalPhaseV3::Prepared(_) => {
            return Err(ExchangeCustodyEngineError::InvalidPhase);
        }
    };
    let expected_v3_action = match expected_action {
        CustodyTerminalActionV3::Release => WithdrawalActionV3::Release,
        CustodyTerminalActionV3::Cancel => WithdrawalActionV3::Cancel,
    };
    if !terminal_matches_approval(record, terminal, expected_v3_action, &approval) {
        return Err(ExchangeCustodyEngineError::TerminalConflict);
    }
    let verified = policy.verify_approval(
        &approval,
        ExpectedApproval {
            action: expected_action.policy_action(),
            action_anchor: approval_anchor(terminal.action_anchor),
            request_id: &record.core.request_id,
            request_digest: record.core.request_digest,
            transaction_signing_digest: record.core.signing_digest,
        },
        &PolicyWindowState::default(),
        approval.authorized_at_unix_seconds,
    )?;
    if verified.signing_digest != terminal.approval_digest
        || verified.decision_id != terminal.decision_id
        || verified.authorized_at_unix_seconds != terminal.decided_at_unix_seconds
    {
        return Err(ExchangeCustodyEngineError::TerminalConflict);
    }
    Ok(())
}

struct ValidatedPlanParts {
    core: WithdrawalCoreV3,
    unsigned_transaction: Vec<u8>,
    inputs: Vec<(WalletKeySummary, u64, OutPoint)>,
}

fn validate_bindings(
    journal: &ExchangeWithdrawalJournalV3,
    policy: &WithdrawalPolicy,
    keyring: &WalletKeyring,
) -> Result<(), ExchangeCustodyEngineError> {
    if journal.policy_id != policy.policy_id() {
        return Err(ExchangeCustodyEngineError::PolicyIdMismatch);
    }
    let keyring_binding = keyring.binding();
    verify_journal_keyring_binding(journal.binding, keyring_binding)?;
    if policy.binding.network_id != journal.binding.network_id {
        return Err(ExchangeCustodyEngineError::BindingMismatch("network_id"));
    }
    if policy.binding.consensus_fingerprint != journal.binding.consensus_fingerprint {
        return Err(ExchangeCustodyEngineError::BindingMismatch(
            "consensus_fingerprint",
        ));
    }
    if policy.binding.genesis_hash != journal.binding.genesis {
        return Err(ExchangeCustodyEngineError::BindingMismatch("genesis_hash"));
    }
    if journal.active_keyring != storage_keyring_anchor(keyring) {
        return Err(ExchangeCustodyEngineError::KeyringAnchorMismatch);
    }
    if !keyring
        .summaries()
        .iter()
        .any(|key| key.public_key == policy.binding.wallet_destination)
    {
        return Err(ExchangeCustodyEngineError::PolicyWalletKeyMissing);
    }
    // Validate durable policy state against the same clock semantics before
    // accepting the engine. No local wall clock is consulted here.
    let state = policy_window_from_journal(&journal.policy_window);
    policy.window_usage(&state, state.time_watermark_unix_seconds)?;
    Ok(())
}

fn verify_journal_keyring_binding(
    journal: JournalBindingV3,
    keyring: KeyringRuntimeBinding,
) -> Result<(), ExchangeCustodyEngineError> {
    if journal.network_id != keyring.network_id {
        return Err(ExchangeCustodyEngineError::BindingMismatch("network_id"));
    }
    if journal.consensus_fingerprint != keyring.consensus_fingerprint {
        return Err(ExchangeCustodyEngineError::BindingMismatch(
            "consensus_fingerprint",
        ));
    }
    if journal.genesis != keyring.genesis_hash {
        return Err(ExchangeCustodyEngineError::BindingMismatch("genesis_hash"));
    }
    Ok(())
}

fn validate_and_bind_plan(
    policy: &WithdrawalPolicy,
    keyring: &WalletKeyring,
    plan: &CustodyPaymentPlanV3,
) -> Result<ValidatedPlanParts, ExchangeCustodyEngineError> {
    if plan.request_id.is_empty()
        || plan.request_id.len() > 128
        || !plan.request_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ExchangeCustodyEngineError::InvalidPlan("request_id"));
    }
    VerifyingKey::from_bytes(&plan.recipient)
        .map_err(|_| ExchangeCustodyEngineError::InvalidPlan("recipient"))?;
    policy.check_static_limits(plan.amount_atoms, plan.fee_atoms)?;
    let binding = keyring.binding();
    if plan.transaction.network_id != binding.network_id {
        return Err(ExchangeCustodyEngineError::InvalidPlan("network_id"));
    }
    if plan.transaction.version != TRANSACTION_VERSION {
        return Err(ExchangeCustodyEngineError::InvalidPlan(
            "transaction version",
        ));
    }
    if plan.transaction.inputs.is_empty()
        || plan.transaction.inputs.len() > MAX_TRANSACTION_INPUTS
        || plan.transaction.inputs.len() != plan.selected_input_values.len()
    {
        return Err(ExchangeCustodyEngineError::InvalidPlan("input count"));
    }

    let expected_output_count = if plan.change_atoms == 0 { 1 } else { 2 };
    if plan.transaction.outputs.len() != expected_output_count {
        return Err(ExchangeCustodyEngineError::InvalidPlan("output count"));
    }
    let recipient = &plan.transaction.outputs[0];
    if recipient.value != plan.amount_atoms
        || recipient.lock != OutputLock::Key(plan.recipient)
        || recipient.spendable_height != plan.output_spendable_height
    {
        return Err(ExchangeCustodyEngineError::InvalidPlan("recipient output"));
    }
    if plan.change_atoms > 0 {
        let change = &plan.transaction.outputs[1];
        let change_key = keyring.active_change_key();
        if change.value != plan.change_atoms
            || change.lock != OutputLock::Key(change_key.public_key)
            || change.spendable_height != plan.output_spendable_height
        {
            return Err(ExchangeCustodyEngineError::InvalidPlan("change output"));
        }
    }

    let mut selected_total = 0_u64;
    let mut inputs = Vec::with_capacity(plan.transaction.inputs.len());
    let mut reservations = Vec::with_capacity(plan.transaction.inputs.len());
    for (transaction_input, value_atoms) in plan
        .transaction
        .inputs
        .iter()
        .zip(&plan.selected_input_values)
    {
        if *value_atoms == 0 {
            return Err(ExchangeCustodyEngineError::InvalidPlan("input value"));
        }
        let InputWitness::Key {
            public_key,
            signature,
        } = &transaction_input.witness
        else {
            return Err(ExchangeCustodyEngineError::InvalidPlan("input witness"));
        };
        if !signature.is_empty()
            && (signature.len() != 64 || signature.iter().any(|byte| *byte != 0))
        {
            return Err(ExchangeCustodyEngineError::InvalidPlan("input is signed"));
        }
        let key_id = wallet_key_id(public_key);
        let key = keyring
            .key(key_id)
            .ok_or(ExchangeCustodyEngineError::InvalidPlan("input key"))?;
        if key.public_key != *public_key || key.lifecycle == KeyLifecycle::Disabled {
            return Err(ExchangeCustodyEngineError::InvalidPlan(
                "input key is not signable",
            ));
        }
        if key.storage == KeyStorageBinding::WatchOnly {
            return Err(ExchangeCustodyEngineError::InvalidPlan(
                "input key is not signable",
            ));
        }
        let signer_profile = signer_profile_for_key(keyring, key)?;
        selected_total = selected_total
            .checked_add(*value_atoms)
            .ok_or(ExchangeCustodyEngineError::InvalidPlan("input total"))?;
        inputs.push((key, *value_atoms, transaction_input.previous));
        reservations.push(ReservedInputV3 {
            outpoint: ReservedOutpointV3 {
                txid: transaction_input.previous.txid,
                index: transaction_input.previous.index,
            },
            value_atoms: *value_atoms,
            wallet_key_id: key_id.0,
            public_key: *public_key,
            signer_id: signer_profile.capabilities.signer_id.0,
        });
    }
    reservations.sort_unstable_by_key(|input| input.outpoint);
    if reservations
        .windows(2)
        .any(|pair| pair[0].outpoint >= pair[1].outpoint)
    {
        return Err(ExchangeCustodyEngineError::InvalidPlan("duplicate input"));
    }
    let expected_total = plan
        .amount_atoms
        .checked_add(plan.fee_atoms)
        .and_then(|value| value.checked_add(plan.change_atoms))
        .ok_or(ExchangeCustodyEngineError::InvalidPlan("payment total"))?;
    if selected_total != expected_total {
        return Err(ExchangeCustodyEngineError::InvalidPlan("payment balance"));
    }
    let unsigned_transaction = encode_unsigned_key_transaction(&plan.transaction)?;
    let signing_digest = plan.transaction.signing_digest();
    let request_digest = custody_request_digest(policy, plan);
    let core = WithdrawalCoreV3 {
        request_id: plan.request_id.clone(),
        request_digest,
        destination: plan.recipient,
        amount_atoms: plan.amount_atoms,
        fee_atoms: plan.fee_atoms,
        change_atoms: plan.change_atoms,
        output_spendable_height: plan.output_spendable_height,
        signing_digest,
        reservations,
    };
    Ok(ValidatedPlanParts {
        core,
        unsigned_transaction,
        inputs,
    })
}

pub(crate) fn custody_request_digest(
    policy: &WithdrawalPolicy,
    plan: &CustodyPaymentPlanV3,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(REQUEST_DIGEST_DOMAIN);
    hasher.update(&policy.binding.network_id);
    hasher.update(&policy.binding.consensus_fingerprint);
    hasher.update(&policy.binding.genesis_hash);
    hasher.update(&policy.binding.wallet_destination);
    hasher.update(&(plan.request_id.len() as u64).to_le_bytes());
    hasher.update(plan.request_id.as_bytes());
    hasher.update(&plan.recipient);
    hasher.update(&plan.amount_atoms.to_le_bytes());
    hasher.update(&plan.fee_atoms.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn build_signing_package(
    policy: &WithdrawalPolicy,
    keyring: &WalletKeyring,
    _plan: &CustodyPaymentPlanV3,
    parts: &ValidatedPlanParts,
    prepared_anchor: JournalAnchorV3,
) -> Result<SigningPackageV1, ExchangeCustodyEngineError> {
    let inputs = parts
        .inputs
        .iter()
        .enumerate()
        .map(|(index, (key, value_atoms, outpoint))| {
            let profile = signer_profile_for_key(keyring, *key)?;
            Ok(SigningInputV1 {
                input_index: index as u32,
                outpoint: *outpoint,
                value_atoms: *value_atoms,
                key_id: key.key_id,
                public_key: key.public_key,
                signer_id: profile.capabilities.signer_id,
                capability_digest: profile.capabilities.digest()?,
            })
        })
        .collect::<Result<Vec<_>, ExchangeCustodyEngineError>>()?;
    Ok(SigningPackageV1 {
        network_id: policy.binding.network_id,
        consensus_fingerprint: policy.binding.consensus_fingerprint,
        genesis: policy.binding.genesis_hash,
        prepared_anchor: withdrawal_anchor(prepared_anchor),
        request_id: parts.core.request_id.clone(),
        request_digest: parts.core.request_digest,
        policy_id: policy.policy_id(),
        keyring_anchor: keyring.anchor().signing_protocol_anchor(),
        unsigned_transaction: parts.unsigned_transaction.clone(),
        signing_digest: parts.core.signing_digest,
        inputs,
    })
}

fn verify_stored_package(
    policy: &WithdrawalPolicy,
    keyring: &WalletKeyring,
    plan: &CustodyPaymentPlanV3,
    parts: &ValidatedPlanParts,
    evidence: &SignerPackageEvidenceV3,
) -> Result<SigningPackageV1, ExchangeCustodyEngineError> {
    let expected = build_signing_package(policy, keyring, plan, parts, evidence.prepared_anchor)?;
    let expected_bytes = expected.encode()?;
    if expected_bytes != evidence.exact_package.bytes
        || evidence.transaction_signing_digest != parts.core.signing_digest
        || evidence.keyring_anchor != storage_keyring_anchor(keyring)
    {
        return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
    }
    let decoded = SigningPackageV1::decode(&evidence.exact_package.bytes)?;
    if decoded != expected {
        return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
    }
    Ok(decoded)
}

fn verify_stored_package_core(
    policy: &WithdrawalPolicy,
    keyring: &WalletKeyring,
    record: &crate::exchange_withdrawal_v3::WithdrawalRecordV3,
    evidence: &SignerPackageEvidenceV3,
) -> Result<SigningPackageV1, ExchangeCustodyEngineError> {
    if evidence.keyring_anchor != storage_keyring_anchor(keyring)
        || evidence.transaction_signing_digest != record.core.signing_digest
    {
        return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
    }
    let package = SigningPackageV1::decode(&evidence.exact_package.bytes)?;
    let binding = keyring.binding();
    if package.network_id != binding.network_id
        || package.consensus_fingerprint != binding.consensus_fingerprint
        || package.genesis != binding.genesis_hash
        || package.prepared_anchor != withdrawal_anchor(evidence.prepared_anchor)
        || package.request_id != record.core.request_id
        || package.request_digest != record.core.request_digest
        || package.policy_id != policy.policy_id()
        || package.keyring_anchor != keyring.anchor().signing_protocol_anchor()
        || package.signing_digest != record.core.signing_digest
    {
        return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
    }

    let transaction = package.transaction()?;
    let expected_output_count = if record.core.change_atoms == 0 { 1 } else { 2 };
    if transaction.outputs.len() != expected_output_count {
        return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
    }
    let recipient = &transaction.outputs[0];
    if recipient.value != record.core.amount_atoms
        || recipient.lock != OutputLock::Key(record.core.destination)
        || recipient.spendable_height != record.core.output_spendable_height
    {
        return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
    }
    if record.core.change_atoms > 0 {
        let change = &transaction.outputs[1];
        if change.value != record.core.change_atoms
            || change.lock != OutputLock::Key(keyring.active_change_key().public_key)
            || change.spendable_height != record.core.output_spendable_height
        {
            return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
        }
    }

    let mut reservations = Vec::with_capacity(package.inputs.len());
    for input in &package.inputs {
        let key = keyring
            .key(input.key_id)
            .ok_or(ExchangeCustodyEngineError::SigningPackageMismatch)?;
        let profile = signer_profile_for_key(keyring, key)?;
        if key.public_key != input.public_key
            || key.storage == KeyStorageBinding::WatchOnly
            || key.lifecycle == KeyLifecycle::Disabled
            || input.signer_id != profile.capabilities.signer_id
            || input.capability_digest != profile.capabilities.digest()?
        {
            return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
        }
        reservations.push(ReservedInputV3 {
            outpoint: ReservedOutpointV3 {
                txid: input.outpoint.txid,
                index: input.outpoint.index,
            },
            value_atoms: input.value_atoms,
            wallet_key_id: input.key_id.0,
            public_key: input.public_key,
            signer_id: input.signer_id.0,
        });
    }
    reservations.sort_unstable_by_key(|input| input.outpoint);
    if reservations != record.core.reservations {
        return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
    }
    Ok(package)
}

fn validate_assembled_transaction(
    plan: &CustodyPaymentPlanV3,
    signed: &Transaction,
) -> Result<(), ExchangeCustodyEngineError> {
    if signed.network_id != plan.transaction.network_id
        || signed.version != plan.transaction.version
        || signed.outputs != plan.transaction.outputs
        || signed.inputs.len() != plan.transaction.inputs.len()
    {
        return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
    }
    for (signed_input, planned_input) in signed.inputs.iter().zip(&plan.transaction.inputs) {
        if signed_input.previous != planned_input.previous {
            return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
        }
        let (
            InputWitness::Key {
                public_key: signed_key,
                signature,
            },
            InputWitness::Key {
                public_key: planned_key,
                ..
            },
        ) = (&signed_input.witness, &planned_input.witness)
        else {
            return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
        };
        if signed_key != planned_key || signature.len() != 64 {
            return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
        }
    }
    Ok(())
}

fn validate_stored_released_transaction(
    plan: &CustodyPaymentPlanV3,
    released: &crate::exchange_withdrawal_v3::ReleasedPhaseV3,
) -> Result<(), ExchangeCustodyEngineError> {
    let transaction = decode_transaction(
        &released.exact_transaction.bytes,
        plan.transaction.network_id,
    )
    .map_err(|_| ExchangeCustodyEngineError::SigningPackageMismatch)?;
    let canonical = encode_transaction(&transaction)
        .map_err(|_| ExchangeCustodyEngineError::SigningPackageMismatch)?;
    if canonical != released.exact_transaction.bytes || transaction.txid() != released.txid {
        return Err(ExchangeCustodyEngineError::SigningPackageMismatch);
    }
    validate_assembled_transaction(plan, &transaction)
}

fn terminal_decision(
    policy: &WithdrawalPolicy,
    action: WithdrawalActionV3,
    current_anchor: JournalAnchorV3,
    record: &crate::exchange_withdrawal_v3::WithdrawalRecordV3,
    verified: &VerifiedApproval,
) -> TerminalDecisionV3 {
    TerminalDecisionV3 {
        scope: DecisionScopeV3::NativeV3,
        action,
        decision_id: verified.decision_id,
        approval_digest: verified.signing_digest,
        policy_id: policy.policy_id(),
        action_anchor: current_anchor,
        request_digest: record.core.request_digest,
        transaction_signing_digest: record.core.signing_digest,
        decided_at_unix_seconds: verified.authorized_at_unix_seconds,
        accounted_at_unix_seconds: verified.accounted_at_unix_seconds,
    }
}

fn terminal_matches_approval(
    record: &WithdrawalRecordV3,
    terminal: &TerminalDecisionV3,
    expected_action: WithdrawalActionV3,
    approval: &WithdrawalApproval,
) -> bool {
    // Migration scope is deliberately narrower than native scope: the retained
    // canonical payload, with a policy-valid threshold signature set, can
    // replay an already Released transaction, but no other migrated phase or
    // action is eligible for approval matching.
    let scope_matches_record = match (&record.origin, &record.phase, terminal.scope) {
        (RecordOriginV3::NativeV3, _, DecisionScopeV3::NativeV3) => true,
        (
            RecordOriginV3::ValidatedV2 { .. },
            WithdrawalPhaseV3::Released(_),
            DecisionScopeV3::ValidatedV2Migration,
        ) => expected_action == WithdrawalActionV3::Release,
        _ => false,
    };
    scope_matches_record
        && terminal.action == expected_action
        && approval.action
            == match expected_action {
                WithdrawalActionV3::Release => WithdrawalAction::Release,
                WithdrawalActionV3::Cancel => WithdrawalAction::Cancel,
            }
        && terminal.decision_id == approval.decision_id
        && terminal.approval_digest == approval.signing_digest()
        && terminal.policy_id == approval.policy_id
        && terminal.action_anchor == journal_anchor(approval.action_anchor)
        && terminal.request_digest == approval.request_digest
        && terminal.transaction_signing_digest == approval.transaction_signing_digest
        && terminal.decided_at_unix_seconds == approval.authorized_at_unix_seconds
}

fn encode_approval_document(approval: &WithdrawalApproval) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": APPROVAL_SCHEMA,
        "action": approval.action.as_str(),
        "decision_id": hex::encode(approval.decision_id),
        "policy_id": hex::encode(approval.policy_id),
        "action_anchor": {
            "key_id": hex::encode(approval.action_anchor.key_id),
            "journal_instance_id": hex::encode(approval.action_anchor.journal_instance_id),
            "generation": approval.action_anchor.generation.to_string(),
            "commitment": hex::encode(approval.action_anchor.commitment),
        },
        "request_id": approval.request_id,
        "request_digest": hex::encode(approval.request_digest),
        "transaction_signing_digest": hex::encode(approval.transaction_signing_digest),
        "authorized_at_unix_seconds": approval.authorized_at_unix_seconds.to_string(),
        "expires_at_unix_seconds": approval.expires_at_unix_seconds.to_string(),
        "signatures": [],
    }))
    .expect("approval JSON contains only infallible values")
}

fn storage_keyring_anchor(keyring: &WalletKeyring) -> KeyringAnchorV3 {
    let anchor = keyring.anchor();
    KeyringAnchorV3 {
        instance_id: anchor.instance_id,
        generation: anchor.generation,
        commitment: anchor.commitment,
    }
}

fn withdrawal_anchor(anchor: JournalAnchorV3) -> WithdrawalAnchorV1 {
    WithdrawalAnchorV1 {
        key_id: anchor.key_id,
        journal_instance_id: anchor.journal_instance_id,
        generation: anchor.generation,
        commitment: anchor.commitment,
    }
}

fn approval_anchor(anchor: JournalAnchorV3) -> ApprovalAnchor {
    ApprovalAnchor {
        key_id: anchor.key_id,
        journal_instance_id: anchor.journal_instance_id,
        generation: anchor.generation,
        commitment: anchor.commitment,
    }
}

fn journal_anchor(anchor: ApprovalAnchor) -> JournalAnchorV3 {
    JournalAnchorV3 {
        key_id: anchor.key_id,
        journal_instance_id: anchor.journal_instance_id,
        generation: anchor.generation,
        commitment: anchor.commitment,
    }
}

fn policy_window_from_journal(state: &PolicyWindowStateV3) -> PolicyWindowState {
    PolicyWindowState {
        time_watermark_unix_seconds: state.time_watermark_unix_seconds,
        release_events: state
            .release_events
            .iter()
            .map(|event| PolicyReleaseEvent {
                request_digest: event.request_digest,
                released_at_unix_seconds: event.released_at_unix_seconds,
                debit_atoms: event.debit_atoms,
            })
            .collect(),
    }
}

fn journal_window_from_policy(state: &PolicyWindowState) -> PolicyWindowStateV3 {
    PolicyWindowStateV3 {
        time_watermark_unix_seconds: state.time_watermark_unix_seconds,
        release_events: state
            .release_events
            .iter()
            .map(|event| PolicyReleaseEventV3 {
                request_digest: event.request_digest,
                released_at_unix_seconds: event.released_at_unix_seconds,
                debit_atoms: event.debit_atoms,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use cmfd_consensus::{CONSENSUS_SIGNATURE_BYTES, TxInput, TxOutput, decode_transaction};
    use k256::schnorr::{Signature, SigningKey, signature::Signer};
    use serde_json::{Value, json};
    use zeroize::Zeroizing;

    use super::*;
    use crate::exchange_policy::{POLICY_SCHEMA, WithdrawalPolicyBinding};
    use crate::exchange_withdrawal_v3::{
        ExactBytesV3, ValidatedV2MigrationInputV3, ValidatedV2ReleasedRecordV3,
        migrate_validated_v2,
    };
    use crate::wallet_keyring::{KeyRoles, WalletKeyEntry};

    const JOURNAL_KEY: [u8; 32] = [0xa5; 32];
    const RELEASE_APPROVER: u8 = 0x11;
    const CANCEL_APPROVER: u8 = 0x22;

    fn marker(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn signing_key(marker: u8) -> SigningKey {
        SigningKey::from_bytes(&[marker; 32]).expect("test scalar is valid")
    }

    fn public_key(marker: u8) -> [u8; 32] {
        signing_key(marker).verifying_key().to_bytes().into()
    }

    fn runtime_binding() -> KeyringRuntimeBinding {
        KeyringRuntimeBinding {
            network_id: marker(1),
            consensus_fingerprint: marker(2),
            genesis_hash: marker(3),
        }
    }

    fn keyring_with_instance(instance: u8) -> WalletKeyring {
        WalletKeyring::new_genesis(
            runtime_binding(),
            marker(instance),
            vec![
                WalletKeyEntry::local(
                    Zeroizing::new(marker(7)),
                    KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                    KeyLifecycle::Active,
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn policy(keyring: &WalletKeyring, rolling_debit: u64) -> WithdrawalPolicy {
        let binding = WithdrawalPolicyBinding {
            network_id: runtime_binding().network_id,
            consensus_fingerprint: runtime_binding().consensus_fingerprint,
            genesis_hash: runtime_binding().genesis_hash,
            wallet_destination: keyring.active_change_key().public_key,
        };
        let document = json!({
            "schema": POLICY_SCHEMA,
            "network_id": hex::encode(binding.network_id),
            "consensus_fingerprint": hex::encode(binding.consensus_fingerprint),
            "genesis_hash": hex::encode(binding.genesis_hash),
            "wallet_destination": hex::encode(binding.wallet_destination),
            "max_single_amount_atoms": "1000",
            "max_single_fee_atoms": "25",
            "max_single_debit_atoms": "1025",
            "max_rolling_24h_debit_atoms": rolling_debit.to_string(),
            "max_rolling_24h_release_count": "8",
            "release_approval": {
                "threshold": "1",
                "public_keys": [hex::encode(public_key(RELEASE_APPROVER))]
            },
            "cancel_approval": {
                "threshold": "1",
                "public_keys": [hex::encode(public_key(CANCEL_APPROVER))]
            }
        });
        WithdrawalPolicy::parse(&serde_json::to_vec(&document).unwrap(), binding).unwrap()
    }

    fn initial_journal(
        keyring: &WalletKeyring,
        policy: &WithdrawalPolicy,
    ) -> ExchangeWithdrawalJournalV3 {
        let source_anchor = JournalAnchorV3 {
            key_id: marker(0x31),
            journal_instance_id: marker(0x32),
            generation: 7,
            commitment: marker(0x33),
        };
        migrate_validated_v2(
            ValidatedV2MigrationInputV3 {
                source_schema_version: 2,
                source_snapshot_digest: marker(0x34),
                source_current_anchor: source_anchor,
                source_external_anchor: source_anchor,
                migration_id: marker(0x35),
                migration_decision_id: marker(0x36),
                migration_approval_digest: marker(0x37),
                binding: JournalBindingV3 {
                    network_id: runtime_binding().network_id,
                    consensus_fingerprint: runtime_binding().consensus_fingerprint,
                    genesis: runtime_binding().genesis_hash,
                },
                new_journal_instance_id: marker(0x38),
                policy_id: policy.policy_id(),
                initial_policy_window: PolicyWindowStateV3 {
                    time_watermark_unix_seconds: 10,
                    release_events: Vec::new(),
                },
                active_keyring: storage_keyring_anchor(keyring),
                released_records: Vec::new(),
            },
            &JOURNAL_KEY,
        )
        .unwrap()
        .journal
    }

    fn engine<'a>(
        journal: &'a ExchangeWithdrawalJournalV3,
        policy: &'a WithdrawalPolicy,
        keyring: &'a WalletKeyring,
    ) -> ExchangeCustodyEngineV3<'a> {
        ExchangeCustodyEngineV3::new(
            journal,
            &JOURNAL_KEY,
            journal.anchor(&JOURNAL_KEY).unwrap(),
            policy,
            keyring,
        )
        .unwrap()
    }

    fn payment_plan(
        keyring: &WalletKeyring,
        request_id: &str,
        outpoint_marker: u8,
    ) -> CustodyPaymentPlanV3 {
        let amount_atoms = 700;
        let fee_atoms = 20;
        let change_atoms = 280;
        let recipient = public_key(0x23);
        CustodyPaymentPlanV3 {
            request_id: request_id.to_owned(),
            transaction: Transaction {
                network_id: runtime_binding().network_id,
                version: TRANSACTION_VERSION,
                inputs: vec![TxInput {
                    previous: OutPoint {
                        txid: marker(outpoint_marker),
                        index: 0,
                    },
                    witness: InputWitness::Key {
                        public_key: keyring.active_change_key().public_key,
                        signature: Vec::new(),
                    },
                }],
                outputs: vec![
                    TxOutput {
                        value: amount_atoms,
                        lock: OutputLock::Key(recipient),
                        spendable_height: 44,
                    },
                    TxOutput {
                        value: change_atoms,
                        lock: OutputLock::Key(keyring.active_change_key().public_key),
                        spendable_height: 44,
                    },
                ],
            },
            recipient,
            amount_atoms,
            fee_atoms,
            change_atoms,
            selected_input_values: vec![1_000],
            output_spendable_height: 44,
        }
    }

    fn conflicting_plan(plan: &CustodyPaymentPlanV3) -> CustodyPaymentPlanV3 {
        let mut conflict = plan.clone();
        conflict.amount_atoms = 600;
        conflict.change_atoms = 380;
        conflict.transaction.outputs[0].value = 600;
        conflict.transaction.outputs[1].value = 380;
        conflict
    }

    fn signed_approval(
        engine: &ExchangeCustodyEngineV3<'_>,
        action: CustodyTerminalActionV3,
        request_id: &str,
        decision_marker: u8,
        authorized_at: u64,
        signer_marker: u8,
    ) -> Vec<u8> {
        let unsigned = engine
            .unsigned_approval_document(
                engine.current_anchor().unwrap(),
                action,
                request_id,
                marker(decision_marker),
                authorized_at,
                authorized_at + 100,
            )
            .unwrap();
        let signature: Signature = signing_key(signer_marker).sign(&unsigned.signing_digest);
        let mut document: Value = serde_json::from_slice(&unsigned.document).unwrap();
        document["signatures"] = json!([{
            "public_key": hex::encode(public_key(signer_marker)),
            "signature": hex::encode(signature.to_bytes()),
        }]);
        serde_json::to_vec(&document).unwrap()
    }

    fn approval_with_invalid_signature(document: &[u8]) -> Vec<u8> {
        let mut document: Value = serde_json::from_slice(document).unwrap();
        document["signatures"][0]["signature"] = json!(hex::encode([0xA5; 64]));
        serde_json::to_vec(&document).unwrap()
    }

    fn signed_approval_at_anchor(
        policy: &WithdrawalPolicy,
        record: &WithdrawalRecordV3,
        anchor: JournalAnchorV3,
        action: WithdrawalAction,
        decision_id: [u8; 32],
        authorized_at: u64,
        signer_marker: u8,
    ) -> (Vec<u8>, WithdrawalApproval) {
        let approval = WithdrawalApproval {
            action,
            decision_id,
            policy_id: policy.policy_id(),
            action_anchor: approval_anchor(anchor),
            request_id: record.core.request_id.clone(),
            request_digest: record.core.request_digest,
            transaction_signing_digest: record.core.signing_digest,
            authorized_at_unix_seconds: authorized_at,
            expires_at_unix_seconds: authorized_at + 100,
            signatures: Vec::new(),
        };
        let digest = approval.signing_digest();
        let signature: Signature = signing_key(signer_marker).sign(&digest);
        let mut document: Value =
            serde_json::from_slice(&encode_approval_document(&approval)).unwrap();
        document["signatures"] = json!([{
            "public_key": hex::encode(public_key(signer_marker)),
            "signature": hex::encode(signature.to_bytes()),
        }]);
        (serde_json::to_vec(&document).unwrap(), approval)
    }

    fn migrated_released_fixture(
        keyring: &WalletKeyring,
        policy: &WithdrawalPolicy,
        request_id: &str,
    ) -> (ExchangeWithdrawalJournalV3, Vec<u8>, Vec<u8>, [u8; 32]) {
        let base = initial_journal(keyring, policy);
        let plan = payment_plan(keyring, request_id, 0x70);
        let prepared = prepared(&base, policy, keyring, &plan);
        let prepared_engine = engine(&prepared.journal, policy, keyring);
        let native_approval = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Release,
            request_id,
            0x71,
            100,
            RELEASE_APPROVER,
        );
        let authorized = prepared_engine
            .authorize_release(request_id, &native_approval, 100)
            .unwrap();
        let authorized_anchor = authorized.journal.anchor(&JOURNAL_KEY).unwrap();
        let native_released = AuthorizedReleaseCompletionEngineV3::new(
            &authorized.journal,
            &JOURNAL_KEY,
            authorized_anchor,
            policy,
            keyring,
            request_id,
        )
        .unwrap()
        .complete(&plan, |_| true)
        .unwrap();
        let native_record = &native_released.journal.records[request_id];
        let WithdrawalPhaseV3::Released(native_phase) = &native_record.phase else {
            panic!("expected native Released record")
        };
        let source_anchor = base.migration.source_anchor;
        let (migration_approval, approval) = signed_approval_at_anchor(
            policy,
            native_record,
            source_anchor,
            WithdrawalAction::Release,
            marker(0x72),
            100,
            RELEASE_APPROVER,
        );
        let exact_transaction_bytes = native_phase.exact_transaction.bytes.clone();
        let txid = native_phase.txid;
        let migrated = migrate_validated_v2(
            ValidatedV2MigrationInputV3 {
                source_schema_version: 2,
                source_snapshot_digest: marker(0x73),
                source_current_anchor: source_anchor,
                source_external_anchor: source_anchor,
                migration_id: marker(0x74),
                migration_decision_id: marker(0x75),
                migration_approval_digest: marker(0x76),
                binding: base.binding,
                new_journal_instance_id: marker(0x77),
                policy_id: policy.policy_id(),
                initial_policy_window: PolicyWindowStateV3 {
                    time_watermark_unix_seconds: 100,
                    release_events: vec![PolicyReleaseEventV3 {
                        request_digest: native_record.core.request_digest,
                        released_at_unix_seconds: 100,
                        debit_atoms: native_phase.debit_atoms,
                    }],
                },
                active_keyring: storage_keyring_anchor(keyring),
                released_records: vec![ValidatedV2ReleasedRecordV3 {
                    core: native_record.core.clone(),
                    source_prepared_generation: source_anchor.generation,
                    source_record_digest: marker(0x78),
                    terminal: TerminalDecisionV3 {
                        scope: DecisionScopeV3::ValidatedV2Migration,
                        action: WithdrawalActionV3::Release,
                        decision_id: approval.decision_id,
                        approval_digest: approval.signing_digest(),
                        policy_id: approval.policy_id,
                        action_anchor: source_anchor,
                        request_digest: approval.request_digest,
                        transaction_signing_digest: approval.transaction_signing_digest,
                        decided_at_unix_seconds: approval.authorized_at_unix_seconds,
                        accounted_at_unix_seconds: approval.authorized_at_unix_seconds,
                    },
                    txid,
                    exact_transaction_bytes: exact_transaction_bytes.clone(),
                    debit_atoms: native_phase.debit_atoms,
                }],
            },
            &JOURNAL_KEY,
        )
        .unwrap()
        .journal;
        (migrated, migration_approval, exact_transaction_bytes, txid)
    }

    fn prepared(
        journal: &ExchangeWithdrawalJournalV3,
        policy: &WithdrawalPolicy,
        keyring: &WalletKeyring,
        plan: &CustodyPaymentPlanV3,
    ) -> PreparedCustodyCandidateV3 {
        let engine = engine(journal, policy, keyring);
        engine
            .prepare(engine.current_anchor().unwrap(), plan)
            .unwrap()
    }

    #[test]
    fn prepare_is_atomic_exact_and_idempotent() {
        let keyring = keyring_with_instance(0x40);
        let policy = policy(&keyring, 5_000);
        let journal = initial_journal(&keyring, &policy);
        let unchanged_source = journal.clone();
        let plan = payment_plan(&keyring, "withdrawal-0001", 0x50);

        let candidate = prepared(&journal, &policy, &keyring, &plan);
        assert!(candidate.changed);
        assert_eq!(journal, unchanged_source);
        assert_eq!(candidate.journal.generation, journal.generation + 3);
        assert_eq!(candidate.package.request_id, plan.request_id);
        assert_eq!(
            candidate.package_digest,
            candidate.package.digest().unwrap()
        );
        assert_eq!(
            candidate.candidate_anchor,
            candidate.journal.anchor(&JOURNAL_KEY).unwrap()
        );
        let WithdrawalPhaseV3::Prepared(phase) = &candidate.journal.records[&plan.request_id].phase
        else {
            panic!("expected Prepared")
        };
        let evidence = phase
            .signer_package
            .as_ref()
            .expect("exact package attached");
        assert_eq!(evidence.prepared_anchor, candidate.prepared_anchor);
        assert_eq!(
            evidence.exact_package.bytes,
            candidate.package.encode().unwrap()
        );

        let retry_engine = engine(&candidate.journal, &policy, &keyring);
        let retry = retry_engine
            .prepare(retry_engine.current_anchor().unwrap(), &plan)
            .unwrap();
        assert!(!retry.changed);
        assert_eq!(retry.journal, candidate.journal);
        assert_eq!(retry.package, candidate.package);

        assert!(matches!(
            retry_engine.prepare(
                retry_engine.current_anchor().unwrap(),
                &conflicting_plan(&plan)
            ),
            Err(ExchangeCustodyEngineError::PlanMismatch)
        ));
        let mut stale = retry_engine.current_anchor().unwrap();
        stale.commitment = marker(0x61);
        assert!(matches!(
            retry_engine.prepare(stale, &plan),
            Err(ExchangeCustodyEngineError::StaleJournalAnchor)
        ));
    }

    #[test]
    fn release_is_authorized_durably_before_any_signing() {
        let keyring = keyring_with_instance(0x40);
        let policy = policy(&keyring, 5_000);
        let journal = initial_journal(&keyring, &policy);
        let plan = payment_plan(&keyring, "withdrawal-0001", 0x50);
        let prepared_candidate = prepared(&journal, &policy, &keyring, &plan);
        let prepared_engine = engine(&prepared_candidate.journal, &policy, &keyring);
        let approval = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Release,
            &plan.request_id,
            0x51,
            100,
            RELEASE_APPROVER,
        );

        assert!(matches!(
            prepared_engine.complete_authorized_release(&plan, |_| panic!("must not revalidate")),
            Err(ExchangeCustodyEngineError::InvalidPhase)
        ));
        let authorized = prepared_engine
            .authorize_release(&plan.request_id, &approval, 150)
            .unwrap();
        assert!(authorized.changed);
        assert_eq!(
            authorized.journal.policy_window.time_watermark_unix_seconds,
            150
        );
        assert_eq!(authorized.journal.policy_window.release_events.len(), 1);
        assert_eq!(
            authorized.journal.policy_window.release_events[0].debit_atoms,
            720
        );
        assert!(matches!(
            prepared_candidate.journal.records[&plan.request_id].phase,
            WithdrawalPhaseV3::Prepared(_)
        ));
        assert!(matches!(
            authorized.journal.records[&plan.request_id].phase,
            WithdrawalPhaseV3::ReleaseAuthorized(_)
        ));

        let authorized_engine = engine(&authorized.journal, &policy, &keyring);
        let authorization_retry = authorized_engine
            .authorize_release(&plan.request_id, &approval, 250)
            .unwrap();
        assert!(!authorization_retry.changed);
        assert!(matches!(
            authorized_engine.authorize_release(
                &plan.request_id,
                &approval_with_invalid_signature(&approval),
                250,
            ),
            Err(ExchangeCustodyEngineError::Policy(
                ExchangePolicyError::ApprovalSignatureInvalid
            ))
        ));
        assert!(matches!(
            authorized.journal.records[&plan.request_id].phase,
            WithdrawalPhaseV3::ReleaseAuthorized(_)
        ));
        let completion_engine = AuthorizedReleaseCompletionEngineV3::new(
            &authorized.journal,
            &JOURNAL_KEY,
            authorized.journal.anchor(&JOURNAL_KEY).unwrap(),
            &policy,
            &keyring,
            &plan.request_id,
        )
        .unwrap();
        let mut revalidated = false;
        let released = completion_engine
            .complete(&plan, |_| {
                revalidated = true;
                true
            })
            .unwrap();
        assert!(revalidated);
        assert!(released.changed);
        assert!(matches!(
            authorized.journal.records[&plan.request_id].phase,
            WithdrawalPhaseV3::ReleaseAuthorized(_)
        ));
        let decoded = decode_transaction(
            &released.exact_transaction_bytes,
            runtime_binding().network_id,
        )
        .unwrap();
        let InputWitness::Key { signature, .. } = &decoded.inputs[0].witness else {
            panic!("expected key input")
        };
        assert_eq!(signature.len(), CONSENSUS_SIGNATURE_BYTES);
        assert_ne!(signature.as_slice(), [0_u8; CONSENSUS_SIGNATURE_BYTES]);
        assert_eq!(decoded.txid(), released.txid);

        let released_engine = engine(&released.journal, &policy, &keyring);
        let retry = released_engine
            .complete_authorized_release(&plan, |_| panic!("retry must not revalidate"))
            .unwrap();
        assert!(!retry.changed);
        assert_eq!(retry.txid, released.txid);
        assert_eq!(
            retry.exact_transaction_bytes,
            released.exact_transaction_bytes
        );

        let duplicate_plan = payment_plan(&keyring, "withdrawal-0002", 0x50);
        let released_engine = engine(&released.journal, &policy, &keyring);
        assert!(matches!(
            released_engine.prepare(released_engine.current_anchor().unwrap(), &duplicate_plan,),
            Err(ExchangeCustodyEngineError::Journal(
                ExchangeWithdrawalV3Error::InvalidState("reserved input is duplicated")
            ))
        ));
    }

    #[test]
    fn cancel_is_action_distinct_idempotent_and_terminal() {
        let keyring = keyring_with_instance(0x40);
        let policy = policy(&keyring, 5_000);
        let journal = initial_journal(&keyring, &policy);
        let plan = payment_plan(&keyring, "withdrawal-0001", 0x50);
        let prepared_candidate = prepared(&journal, &policy, &keyring, &plan);
        let prepared_engine = engine(&prepared_candidate.journal, &policy, &keyring);
        let release = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Release,
            &plan.request_id,
            0x51,
            100,
            RELEASE_APPROVER,
        );
        let cancel = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Cancel,
            &plan.request_id,
            0x52,
            120,
            CANCEL_APPROVER,
        );
        let wrong_cancel_signer = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Cancel,
            &plan.request_id,
            0x53,
            120,
            RELEASE_APPROVER,
        );

        assert!(matches!(
            prepared_engine.cancel(&plan.request_id, &release, 150),
            Err(ExchangeCustodyEngineError::Policy(
                ExchangePolicyError::ApprovalActionMismatch
            ))
        ));
        assert!(matches!(
            prepared_engine.cancel(&plan.request_id, &wrong_cancel_signer, 150),
            Err(ExchangeCustodyEngineError::Policy(
                ExchangePolicyError::ApprovalSignerUnauthorized
            ))
        ));
        let canceled = prepared_engine
            .cancel(&plan.request_id, &cancel, 150)
            .unwrap();
        assert!(canceled.changed);
        assert_eq!(
            canceled.journal.policy_window.time_watermark_unix_seconds,
            150
        );
        assert!(canceled.journal.policy_window.release_events.is_empty());

        let canceled_engine = engine(&canceled.journal, &policy, &keyring);
        let retry = canceled_engine
            .cancel(&plan.request_id, &cancel, 250)
            .unwrap();
        assert!(!retry.changed);
        assert!(matches!(
            canceled_engine.cancel(
                &plan.request_id,
                &approval_with_invalid_signature(&cancel),
                250,
            ),
            Err(ExchangeCustodyEngineError::Policy(
                ExchangePolicyError::ApprovalSignatureInvalid
            ))
        ));
        assert!(matches!(
            canceled_engine.authorize_release(&plan.request_id, &release, 150),
            Err(ExchangeCustodyEngineError::TerminalConflict)
        ));
        assert!(matches!(
            canceled_engine.complete_authorized_release(&plan, |_| true),
            Err(ExchangeCustodyEngineError::TerminalConflict)
        ));

        let replacement_plan = payment_plan(&keyring, "withdrawal-0002", 0x50);
        let replacement = prepared(&canceled.journal, &policy, &keyring, &replacement_plan);
        assert!(matches!(
            replacement.journal.records[&replacement_plan.request_id].phase,
            WithdrawalPhaseV3::Prepared(_)
        ));
    }

    #[test]
    fn signed_time_limits_regression_and_decision_reuse_fail_closed() {
        let keyring = keyring_with_instance(0x40);
        let tight_policy = policy(&keyring, 1_000);
        let journal = initial_journal(&keyring, &tight_policy);
        let first_plan = payment_plan(&keyring, "withdrawal-0001", 0x50);
        let first_prepared = prepared(&journal, &tight_policy, &keyring, &first_plan);
        let first_engine = engine(&first_prepared.journal, &tight_policy, &keyring);
        let first_approval = signed_approval(
            &first_engine,
            CustodyTerminalActionV3::Release,
            &first_plan.request_id,
            0x51,
            100,
            RELEASE_APPROVER,
        );
        let first_authorized = first_engine
            .authorize_release(&first_plan.request_id, &first_approval, 150)
            .unwrap();
        let second_plan = payment_plan(&keyring, "withdrawal-0002", 0x60);
        let second_prepared = prepared(
            &first_authorized.journal,
            &tight_policy,
            &keyring,
            &second_plan,
        );
        let second_engine = engine(&second_prepared.journal, &tight_policy, &keyring);
        let over_limit = signed_approval(
            &second_engine,
            CustodyTerminalActionV3::Release,
            &second_plan.request_id,
            0x52,
            110,
            RELEASE_APPROVER,
        );
        assert!(matches!(
            second_engine.authorize_release(&second_plan.request_id, &over_limit, 150),
            Err(ExchangeCustodyEngineError::Policy(
                ExchangePolicyError::RollingDebitLimitExceeded
            ))
        ));
        let regressed = signed_approval(
            &second_engine,
            CustodyTerminalActionV3::Release,
            &second_plan.request_id,
            0x53,
            90,
            RELEASE_APPROVER,
        );
        assert!(matches!(
            second_engine.authorize_release(&second_plan.request_id, &regressed, 149),
            Err(ExchangeCustodyEngineError::Policy(
                ExchangePolicyError::ClockRegression
            ))
        ));

        let roomy_policy = policy(&keyring, 5_000);
        let journal = initial_journal(&keyring, &roomy_policy);
        let first_prepared = prepared(&journal, &roomy_policy, &keyring, &first_plan);
        let first_engine = engine(&first_prepared.journal, &roomy_policy, &keyring);
        let reused_decision = 0x71;
        let first_approval = signed_approval(
            &first_engine,
            CustodyTerminalActionV3::Release,
            &first_plan.request_id,
            reused_decision,
            100,
            RELEASE_APPROVER,
        );
        let first_authorized = first_engine
            .authorize_release(&first_plan.request_id, &first_approval, 150)
            .unwrap();
        let second_prepared = prepared(
            &first_authorized.journal,
            &roomy_policy,
            &keyring,
            &second_plan,
        );
        let second_engine = engine(&second_prepared.journal, &roomy_policy, &keyring);
        let replay = signed_approval(
            &second_engine,
            CustodyTerminalActionV3::Release,
            &second_plan.request_id,
            reused_decision,
            110,
            RELEASE_APPROVER,
        );
        assert!(matches!(
            second_engine.authorize_release(&second_plan.request_id, &replay, 150),
            Err(ExchangeCustodyEngineError::Journal(_))
        ));
    }

    #[test]
    fn binding_package_approval_and_plan_tampering_are_rejected() {
        let keyring = keyring_with_instance(0x40);
        let policy = policy(&keyring, 5_000);
        let journal = initial_journal(&keyring, &policy);
        let mut wrong_anchor = journal.anchor(&JOURNAL_KEY).unwrap();
        wrong_anchor.commitment = marker(0x62);
        assert!(matches!(
            ExchangeCustodyEngineV3::new(&journal, &JOURNAL_KEY, wrong_anchor, &policy, &keyring),
            Err(ExchangeCustodyEngineError::StaleJournalAnchor)
        ));
        let mut wrong_policy = policy.clone();
        wrong_policy.max_rolling_24h_debit_atoms += 1;
        assert!(matches!(
            ExchangeCustodyEngineV3::new(
                &journal,
                &JOURNAL_KEY,
                journal.anchor(&JOURNAL_KEY).unwrap(),
                &wrong_policy,
                &keyring
            ),
            Err(ExchangeCustodyEngineError::PolicyIdMismatch)
        ));
        let other_keyring = keyring_with_instance(0x41);
        assert!(matches!(
            ExchangeCustodyEngineV3::new(
                &journal,
                &JOURNAL_KEY,
                journal.anchor(&JOURNAL_KEY).unwrap(),
                &policy,
                &other_keyring
            ),
            Err(ExchangeCustodyEngineError::KeyringAnchorMismatch)
        ));

        let plan = payment_plan(&keyring, "withdrawal-0001", 0x50);
        let prepared = prepared(&journal, &policy, &keyring, &plan);
        let prepared_engine = engine(&prepared.journal, &policy, &keyring);
        let mut approval = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Release,
            &plan.request_id,
            0x51,
            100,
            RELEASE_APPROVER,
        );
        let mut approval_value: Value = serde_json::from_slice(&approval).unwrap();
        approval_value["request_digest"] = json!(hex::encode(marker(0x63)));
        approval = serde_json::to_vec(&approval_value).unwrap();
        assert!(matches!(
            prepared_engine.authorize_release(&plan.request_id, &approval, 150),
            Err(ExchangeCustodyEngineError::Policy(
                ExchangePolicyError::ApprovalRequestMismatch
            ))
        ));

        let valid_approval = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Release,
            &plan.request_id,
            0x52,
            100,
            RELEASE_APPROVER,
        );
        let authorized = prepared_engine
            .authorize_release(&plan.request_id, &valid_approval, 150)
            .unwrap();
        let authorized_engine = engine(&authorized.journal, &policy, &keyring);
        assert!(matches!(
            authorized_engine.complete_authorized_release(&conflicting_plan(&plan), |_| true),
            Err(ExchangeCustodyEngineError::PlanMismatch)
        ));
        assert!(matches!(
            authorized_engine.complete_authorized_release(&plan, |_| false),
            Err(ExchangeCustodyEngineError::PlanRevalidationFailed)
        ));
        assert!(matches!(
            authorized.journal.records[&plan.request_id].phase,
            WithdrawalPhaseV3::ReleaseAuthorized(_)
        ));
    }

    #[test]
    fn independently_attached_package_tamper_cannot_be_authorized() {
        let keyring = keyring_with_instance(0x40);
        let policy = policy(&keyring, 5_000);
        let journal = initial_journal(&keyring, &policy);
        let plan = payment_plan(&keyring, "withdrawal-0001", 0x50);
        let prepared = prepared(&journal, &policy, &keyring, &plan);
        let mut tampered = prepared.journal.clone();
        let WithdrawalPhaseV3::Prepared(phase) =
            &mut tampered.records.get_mut(&plan.request_id).unwrap().phase
        else {
            panic!("expected Prepared")
        };
        let evidence = phase.signer_package.as_mut().unwrap();
        let mut package = SigningPackageV1::decode(&evidence.exact_package.bytes).unwrap();
        package.request_digest = marker(0x64);
        evidence.exact_package = ExactBytesV3::signer_package(package.encode().unwrap()).unwrap();
        let tampered_engine = engine(&tampered, &policy, &keyring);
        let approval = signed_approval(
            &tampered_engine,
            CustodyTerminalActionV3::Release,
            &plan.request_id,
            0x51,
            100,
            RELEASE_APPROVER,
        );
        assert!(matches!(
            tampered_engine.authorize_release(&plan.request_id, &approval, 150),
            Err(ExchangeCustodyEngineError::SigningPackageMismatch)
        ));
    }

    #[test]
    fn migrated_v2_released_retry_accepts_only_its_retained_release_approval() {
        let keyring = keyring_with_instance(0x40);
        let policy = policy(&keyring, 5_000);
        let request_id = "withdrawal-migrated-retry";
        let (journal, approval, exact_transaction, txid) =
            migrated_released_fixture(&keyring, &policy, request_id);
        let unchanged = journal.clone();

        let retry = engine(&journal, &policy, &keyring)
            .authorize_release(request_id, &approval, 10_000)
            .unwrap();
        assert!(!retry.changed);
        assert_eq!(retry.journal, unchanged);
        let WithdrawalPhaseV3::Released(released) = &retry.journal.records[request_id].phase else {
            panic!("expected migrated Released record")
        };
        assert_eq!(
            released.terminal.scope,
            DecisionScopeV3::ValidatedV2Migration
        );
        assert_eq!(released.txid, txid);
        assert_eq!(released.exact_transaction.bytes, exact_transaction);
        assert_eq!(
            released.terminal.transaction_signing_digest,
            retry.journal.records[request_id].core.signing_digest
        );

        let current_anchor = journal.anchor(&JOURNAL_KEY).unwrap();
        let (fresh_release, _) = signed_approval_at_anchor(
            &policy,
            &journal.records[request_id],
            current_anchor,
            WithdrawalAction::Release,
            marker(0x79),
            100,
            RELEASE_APPROVER,
        );
        let (fresh_cancel, _) = signed_approval_at_anchor(
            &policy,
            &journal.records[request_id],
            current_anchor,
            WithdrawalAction::Cancel,
            marker(0x7a),
            100,
            CANCEL_APPROVER,
        );
        assert!(matches!(
            engine(&journal, &policy, &keyring).authorize_release(request_id, &fresh_release, 100,),
            Err(ExchangeCustodyEngineError::TerminalConflict)
        ));
        assert!(matches!(
            engine(&journal, &policy, &keyring).cancel(request_id, &fresh_cancel, 100),
            Err(ExchangeCustodyEngineError::TerminalConflict)
        ));

        assert!(matches!(
            engine(&journal, &policy, &keyring).authorize_release(
                request_id,
                &approval_with_invalid_signature(&approval),
                10_000,
            ),
            Err(ExchangeCustodyEngineError::Policy(
                ExchangePolicyError::ApprovalSignatureInvalid
            ))
        ));
        assert!(matches!(
            verify_persisted_terminal_approval(
                &journal,
                &policy,
                request_id,
                CustodyTerminalActionV3::Cancel,
                &approval,
            ),
            Err(ExchangeCustodyEngineError::TerminalConflict)
        ));
        assert!(matches!(
            engine(&journal, &policy, &keyring).cancel(request_id, &approval, 10_000),
            Err(ExchangeCustodyEngineError::TerminalConflict)
        ));
    }
}
