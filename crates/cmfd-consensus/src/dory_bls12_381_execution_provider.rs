//! Consensus-owned CPU replay for a production ForgeMatrix winning nonce.
//!
//! Accelerators are allowed to propose a nonce and the two public digests, but
//! they are never trusted to supply execution state. This module reconstructs
//! every accumulator and activation from one authenticated model-bank reader,
//! writes the canonical execution artifact provisionally, and publishes an
//! opaque capability only after the complete bank and claimed output have
//! authenticated.

use std::{
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use rayon::prelude::*;
use thiserror::Error;

use crate::{
    BlockChallenge,
    dory_bls12_381_execution_artifact::{
        BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS, BlsDoryExecutionAccumulatorArtifact,
        BlsDoryExecutionAccumulatorArtifactContext, BlsDoryExecutionAccumulatorArtifactError,
        BlsDoryExecutionAccumulatorArtifactWriter, BlsDoryExecutionAccumulatorColumn,
    },
    dory_bls12_381_layout::signed_model_value,
    dory_bls12_381_prototype::DeterministicBlsDorySetup,
    dory_bls12_381_transition::{BlsDoryTransitionError, derive_transition_regular_row_from_mask},
    dory_v3_model_record::BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    dory_v3_transcript::{DoryV3ChallengeContext, DoryV3TranscriptContext, DoryV3TranscriptError},
    forgematrix_v2::{V2_MODEL_VALUE_CENTER, output_digest, work_digest_from_roots},
    model_bank::{
        ModelBankError, ModelBankFieldStreamError, ModelBankManifest, ModelFieldChunk,
        ModelPcsIdentity, ModelPcsRole, StagedModelFieldLayoutSink, StagedModelFieldSink,
        VerifiedModelBankLayoutReceipt, VerifiedModelBankReceipt,
        verify_model_bank_into_staged_field_layout_sink, verify_model_bank_into_staged_field_sink,
    },
    structured_transition::{
        StructuredMaskPolynomial, StructuredTransitionError, StructuredTransitionStatement,
    },
};

const MAX_TRANSITION_MASK: u64 = 5_000;

/// Opaque authority for one exact production V3 execution-artifact context.
///
/// A V3 replay provider must reject claimed work that does not derive from the
/// claimed output under the typed challenge, and reject high work, before
/// constructing this capability. After replay it must recompute the output and
/// work digests before publishing a verified execution. The legacy raw context
/// is retained privately and cannot be substituted at typed V3 call sites.
/// The setup and exact production record were already validated when the
/// non-constructible bank-authentication capability was minted.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct BlsDoryV3ExecutionAccumulatorArtifactContext {
    raw: BlsDoryExecutionAccumulatorArtifactContext,
    challenge: DoryV3ChallengeContext,
    #[cfg(test)]
    bounded_output: bool,
}

#[allow(dead_code)]
impl BlsDoryV3ExecutionAccumulatorArtifactContext {
    pub(crate) fn from_challenge(
        challenge: DoryV3ChallengeContext,
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryExecutionAccumulatorArtifactError> {
        let transcript = Self::validate_authority(challenge, authenticated, setup)?;
        let record = authenticated.record();
        Ok(Self {
            raw: BlsDoryExecutionAccumulatorArtifactContext::production(
                transcript.network_id(),
                record.record_digest().into_bytes(),
                setup.identity(),
                challenge.digest(),
            )?,
            challenge,
            #[cfg(test)]
            bounded_output: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        challenge: DoryV3ChallengeContext,
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryExecutionAccumulatorArtifactError> {
        let transcript = Self::validate_authority(challenge, authenticated, setup)?;
        let record = authenticated.record();
        let identity = record.model_identity();
        let rows = usize::try_from(identity.batch())
            .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        let columns = usize::try_from(identity.dimension())
            .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        let banks = usize::try_from(
            identity
                .weight_bank_count()
                .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?,
        )
        .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        let layers_per_bank = usize::try_from(identity.layers_per_bank())
            .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        let chunk_cells = rows
            .checked_mul(columns)
            .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        Ok(Self {
            raw: BlsDoryExecutionAccumulatorArtifactContext::for_test(
                [
                    transcript.network_id(),
                    record.record_digest().into_bytes(),
                    setup.identity(),
                    challenge.digest(),
                ],
                rows,
                columns,
                banks,
                layers_per_bank,
                chunk_cells,
            )?,
            challenge,
            bounded_output: true,
        })
    }

    fn validate_authority(
        challenge: DoryV3ChallengeContext,
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<DoryV3TranscriptContext, BlsDoryExecutionAccumulatorArtifactError> {
        let record = authenticated.record();
        let transcript = challenge.transcript_context();
        if transcript.suite_digest() != record.suite_digest()
            || transcript.manifest_digest() != record.manifest_digest()
            || transcript.model_identity_digest() != record.model_identity_digest()
            || transcript.model_record_digest() != record.record_digest()
            || record.setup_identity().into_bytes() != setup.identity()
            || usize::try_from(record.padded_variables()).ok() != Some(setup.max_log_n())
        {
            return Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext);
        }
        Ok(transcript)
    }

    const fn raw(&self) -> &BlsDoryExecutionAccumulatorArtifactContext {
        &self.raw
    }

    #[cfg(test)]
    pub(crate) const fn raw_for_test(&self) -> &BlsDoryExecutionAccumulatorArtifactContext {
        self.raw()
    }

    fn output_digest(
        self,
        activation: &[u8],
    ) -> Result<[u8; 32], crate::dory_v3_transcript::DoryV3TranscriptError> {
        #[cfg(test)]
        if self.bounded_output {
            return self.challenge.output_digest_for_test(activation);
        }
        self.challenge.output_digest(activation)
    }

    fn work_digest(self, final_activation_digest: [u8; 32]) -> [u8; 32] {
        self.challenge.work_digest(final_activation_digest)
    }
}

/// Untrusted accelerator claim for one possible Dory V3 winning nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct BlsDoryV3WinningNonceClaim {
    pub(crate) nonce: u64,
    pub(crate) final_activation_digest: [u8; 32],
    pub(crate) work_digest: [u8; 32],
}

/// Opaque capability published only after a complete authenticated V3 replay.
#[allow(dead_code)]
pub(crate) struct VerifiedBlsDoryV3WinningNonceExecution {
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    nonce: u64,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
    artifact: BlsDoryExecutionAccumulatorArtifact,
}

#[allow(dead_code)]
impl VerifiedBlsDoryV3WinningNonceExecution {
    pub(crate) const fn nonce(&self) -> u64 {
        self.nonce
    }

    pub(crate) const fn final_activation_digest(&self) -> [u8; 32] {
        self.final_activation_digest
    }

    pub(crate) const fn work_digest(&self) -> [u8; 32] {
        self.work_digest
    }

    /// Mint the only production reader for this verified V3 execution.
    ///
    /// The mutable borrow keeps the context and artifact inseparable. The
    /// complete artifact is reauthenticated before any bounded segment reader
    /// or V3 mask derivation is published.
    pub(crate) fn authenticated_artifact_reader<'a>(
        &'a mut self,
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<BlsDoryV3ExecutionArtifactReader<'a>, BlsDoryV3WinningNonceReplayError> {
        BlsDoryV3ExecutionAccumulatorArtifactContext::validate_authority(
            self.context.challenge,
            authenticated,
            setup,
        )?;
        if self.context.work_digest(self.final_activation_digest) != self.work_digest {
            return Err(BlsDoryV3WinningNonceReplayError::WorkDigest);
        }
        if self.artifact.context() != *self.context.raw() {
            return Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext.into());
        }
        self.artifact.authenticate(self.context.raw())?;
        Ok(BlsDoryV3ExecutionArtifactReader {
            context: self.context,
            nonce: self.nonce,
            final_activation_digest: self.final_activation_digest,
            work_digest: self.work_digest,
            artifact: &mut self.artifact,
        })
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        BlsDoryV3ExecutionAccumulatorArtifactContext,
        u64,
        [u8; 32],
        [u8; 32],
        BlsDoryExecutionAccumulatorArtifact,
    ) {
        (
            self.context,
            self.nonce,
            self.final_activation_digest,
            self.work_digest,
            self.artifact,
        )
    }
}

/// Opaque, authority-checked access to one verified V3 execution artifact.
///
/// There is no raw context or artifact accessor. Every mask is derived under
/// the V3 transcript retained by the verified execution, and every read is
/// bounded to one canonical artifact role.
#[allow(dead_code)]
pub(crate) struct BlsDoryV3ExecutionArtifactReader<'a> {
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    nonce: u64,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
    artifact: &'a mut BlsDoryExecutionAccumulatorArtifact,
}

#[allow(dead_code)]
impl BlsDoryV3ExecutionArtifactReader<'_> {
    pub(crate) const fn nonce(&self) -> u64 {
        self.nonce
    }

    pub(crate) const fn final_activation_digest(&self) -> [u8; 32] {
        self.final_activation_digest
    }

    pub(crate) const fn work_digest(&self) -> [u8; 32] {
        self.work_digest
    }

    pub(crate) const fn canonical_rows(&self) -> usize {
        self.context.raw.canonical_rows()
    }

    pub(crate) const fn canonical_columns(&self) -> usize {
        self.context.raw.canonical_columns()
    }

    pub(crate) const fn banks(&self) -> usize {
        self.context.raw.banks()
    }

    pub(crate) const fn layers_per_bank(&self) -> usize {
        self.context.raw.layers_per_bank()
    }

    pub(crate) const fn cells_per_column(&self) -> usize {
        self.context.raw.cells_per_column()
    }

    pub(crate) const fn authentication_chunk_cells(&self) -> usize {
        self.context.raw.authentication_chunk_cells()
    }

    pub(crate) fn validate_setup(
        &self,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDoryV3WinningNonceReplayError> {
        if self.context.raw.setup_identity() != setup.identity() {
            return Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext.into());
        }
        Ok(())
    }

    pub(crate) fn v3_initialization_mask(
        &self,
    ) -> Result<StructuredMaskPolynomial, BlsDoryV3WinningNonceReplayError> {
        Ok(StructuredMaskPolynomial::from_dory_v3_virtual_challenge(
            &self.context.challenge.digest(),
            self.canonical_rows(),
            self.canonical_columns(),
        )?)
    }

    pub(crate) fn v3_bank_mask(
        &self,
        bank: usize,
    ) -> Result<StructuredMaskPolynomial, BlsDoryV3WinningNonceReplayError> {
        if bank >= self.banks() {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        let first_layer = bank
            .checked_mul(self.layers_per_bank())
            .and_then(|layer| u32::try_from(layer).ok())
            .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
        Ok(
            StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
                &self.context.challenge.digest(),
                first_layer,
                self.layers_per_bank(),
                self.canonical_rows(),
                self.canonical_columns(),
            )?,
        )
    }

    pub(crate) fn read_initialization_segment(
        &mut self,
        start_cell: usize,
        output: &mut [i32],
    ) -> Result<usize, BlsDoryV3WinningNonceReplayError> {
        self.validate_segment(start_cell, output.len())?;
        Ok(self.artifact.read_column_segment(
            BlsDoryExecutionAccumulatorColumn::Initialization,
            start_cell,
            output,
        )?)
    }

    pub(crate) fn read_bank_layer_segment(
        &mut self,
        bank: usize,
        layer: usize,
        start_cell: usize,
        output: &mut [i32],
    ) -> Result<usize, BlsDoryV3WinningNonceReplayError> {
        if bank >= self.banks() || layer >= self.layers_per_bank() {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        self.validate_segment(start_cell, output.len())?;
        Ok(self.artifact.read_column_segment(
            BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
            start_cell,
            output,
        )?)
    }

    pub(crate) fn verify_final_activation(
        &self,
        activation: &[u8],
    ) -> Result<(), BlsDoryV3WinningNonceReplayError> {
        if activation.len() != self.cells_per_column() {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        let final_activation_digest = self.context.output_digest(activation)?;
        if final_activation_digest != self.final_activation_digest {
            return Err(BlsDoryV3WinningNonceReplayError::FinalActivationDigest);
        }
        if self.context.work_digest(final_activation_digest) != self.work_digest {
            return Err(BlsDoryV3WinningNonceReplayError::WorkDigest);
        }
        Ok(())
    }

    fn validate_segment(
        &self,
        start_cell: usize,
        output_len: usize,
    ) -> Result<(), BlsDoryV3WinningNonceReplayError> {
        if output_len == 0
            || output_len > self.authentication_chunk_cells()
            || start_cell
                .checked_add(output_len)
                .filter(|end| *end <= self.cells_per_column())
                .is_none()
        {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
#[allow(dead_code)]
pub(crate) enum BlsDoryV3WinningNonceReplayError {
    #[error("Dory V3 replay transcript does not match the authenticated model record")]
    Context,
    #[error("Dory V3 winning-nonce work digest does not match the claimed final activation")]
    WorkDigest,
    #[error("Dory V3 winning-nonce work digest does not meet the requested target")]
    HighHash,
    #[error("Dory V3 winning-nonce CPU replay was cancelled")]
    Cancelled,
    #[error("Dory V3 winning-nonce scratch directory must be an existing absolute directory")]
    ScratchDirectory,
    #[error("Dory V3 winning-nonce scratch-space query failed: {0}")]
    ScratchSpaceQuery(#[source] std::io::Error),
    #[error(
        "insufficient Dory V3 replay scratch space: need {required} bytes, have {available} bytes"
    )]
    InsufficientScratch { required: u64, available: u64 },
    #[error("Dory V3 model bank does not match the execution-artifact geometry or role order")]
    ModelShape,
    #[error("Dory V3 model bank contains a non-canonical centered field value")]
    ModelEncoding,
    #[error("Dory V3 replay allocation or size arithmetic failed")]
    Resource,
    #[error("replayed Dory V3 final activation does not match the accelerator claim")]
    FinalActivationDigest,
    #[error("authenticated Dory V3 model-bank verification failed: {0}")]
    ModelBank(#[from] ModelBankError),
    #[error("Dory V3 execution-accumulator artifact failed: {0}")]
    ExecutionArtifact(#[from] BlsDoryExecutionAccumulatorArtifactError),
    #[error("Dory V3 transcript derivation failed: {0}")]
    Transcript(#[from] DoryV3TranscriptError),
    #[error("Dory V3 challenge-derived mask failed: {0}")]
    Mask(#[from] StructuredTransitionError),
    #[error("Dory V3 transition replay failed: {0}")]
    Transition(#[from] BlsDoryTransitionError),
}

/// Dormant Dory V3 CPU replay. No candidate or consensus path calls this entry.
///
/// The claimed work and target are checked before the model-bank reader is
/// touched. The model bank and artifact remain provisional until both have
/// authenticated completely.
#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) fn replay_dory_v3_winning_nonce_from_bank_authenticated_record<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    transcript: DoryV3TranscriptContext,
    block: &BlockChallenge,
    claim: BlsDoryV3WinningNonceClaim,
    setup: &DeterministicBlsDorySetup,
    model_bank: R,
    scratch_directory: &Path,
    cancel: &AtomicBool,
) -> Result<VerifiedBlsDoryV3WinningNonceExecution, BlsDoryV3WinningNonceReplayError> {
    let challenge = validate_dory_v3_replay_claim(authenticated, transcript, block, claim, cancel)?;
    let context = BlsDoryV3ExecutionAccumulatorArtifactContext::from_challenge(
        challenge,
        authenticated,
        setup,
    )?;
    replay_dory_v3_with_context(
        authenticated,
        context,
        claim,
        model_bank,
        scratch_directory,
        cancel,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    transcript: DoryV3TranscriptContext,
    block: &BlockChallenge,
    claim: BlsDoryV3WinningNonceClaim,
    setup: &DeterministicBlsDorySetup,
    model_bank: R,
    scratch_directory: &Path,
    cancel: &AtomicBool,
) -> Result<VerifiedBlsDoryV3WinningNonceExecution, BlsDoryV3WinningNonceReplayError> {
    let challenge = validate_dory_v3_replay_claim(authenticated, transcript, block, claim, cancel)?;
    let context =
        BlsDoryV3ExecutionAccumulatorArtifactContext::for_test(challenge, authenticated, setup)?;
    replay_dory_v3_with_context(
        authenticated,
        context,
        claim,
        model_bank,
        scratch_directory,
        cancel,
    )
}

fn validate_dory_v3_replay_claim(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    transcript: DoryV3TranscriptContext,
    block: &BlockChallenge,
    claim: BlsDoryV3WinningNonceClaim,
    cancel: &AtomicBool,
) -> Result<DoryV3ChallengeContext, BlsDoryV3WinningNonceReplayError> {
    let challenge = transcript.challenge_context(block, claim.nonce)?;
    let expected_transcript =
        DoryV3TranscriptContext::from_bank_authenticated_record(block.network_id, authenticated)?;
    if transcript != expected_transcript {
        return Err(BlsDoryV3WinningNonceReplayError::Context);
    }
    if claim.work_digest != challenge.work_digest(claim.final_activation_digest) {
        return Err(BlsDoryV3WinningNonceReplayError::WorkDigest);
    }
    if claim.work_digest > block.target {
        return Err(BlsDoryV3WinningNonceReplayError::HighHash);
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
    }
    Ok(challenge)
}

fn replay_dory_v3_with_context<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    claim: BlsDoryV3WinningNonceClaim,
    model_bank: R,
    scratch_directory: &Path,
    cancel: &AtomicBool,
) -> Result<VerifiedBlsDoryV3WinningNonceExecution, BlsDoryV3WinningNonceReplayError> {
    let record = authenticated.record();
    let identity = record.model_identity();
    let bank_count = identity
        .weight_bank_count()
        .map_err(|_| BlsDoryV3WinningNonceReplayError::ModelShape)?;
    validate_dory_v3_replay_geometry(context, authenticated, bank_count)?;
    preflight_dory_v3_execution_artifact(context, scratch_directory)?;
    let sink = DoryV3WinningNonceReplaySink::new(
        context,
        *record.manifest(),
        claim,
        scratch_directory,
        cancel,
    )?;
    verify_model_bank_into_staged_field_layout_sink(
        model_bank,
        record.manifest(),
        identity.layers_per_bank(),
        bank_count,
        sink,
    )
    .map_err(|error| match error {
        ModelBankFieldStreamError::ModelBank(error) => error.into(),
        ModelBankFieldStreamError::Sink(error) => error,
    })
}

fn validate_dory_v3_replay_geometry(
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    bank_count: u32,
) -> Result<(), BlsDoryV3WinningNonceReplayError> {
    let record = authenticated.record();
    let identity = record.model_identity();
    let raw = context.raw();
    if record.manifest().model_version != identity.model_version()
        || usize::try_from(record.manifest().batch).ok() != Some(raw.canonical_rows())
        || usize::try_from(record.manifest().dimension).ok() != Some(raw.canonical_columns())
        || usize::try_from(bank_count).ok() != Some(raw.banks())
        || usize::try_from(identity.layers_per_bank()).ok() != Some(raw.layers_per_bank())
        || usize::try_from(record.manifest().layers).ok()
            != raw.banks().checked_mul(raw.layers_per_bank())
    {
        return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
    }
    Ok(())
}

fn preflight_dory_v3_execution_artifact(
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    scratch_directory: &Path,
) -> Result<(), BlsDoryV3WinningNonceReplayError> {
    if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
        return Err(BlsDoryV3WinningNonceReplayError::ScratchDirectory);
    }
    let required = context.raw().projected_file_bytes()?;
    let available = fs2::available_space(scratch_directory)
        .map_err(BlsDoryV3WinningNonceReplayError::ScratchSpaceQuery)?;
    if available < required {
        return Err(BlsDoryV3WinningNonceReplayError::InsufficientScratch {
            required,
            available,
        });
    }
    Ok(())
}

/// Untrusted accelerator claim for one possible winning nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryWinningNonceClaim {
    pub nonce: u64,
    pub final_activation_digest: [u8; 32],
    pub work_digest: [u8; 32],
}

/// Opaque capability produced only by a complete authenticated CPU replay.
///
/// The execution artifact remains bound to its network, fixed-model record,
/// setup, and nonce-derived challenge. Consuming this value in the candidate
/// module is the only supported path to the large artifact.
pub struct VerifiedBlsDoryWinningNonceExecution {
    nonce: u64,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
    artifact: BlsDoryExecutionAccumulatorArtifact,
}

impl VerifiedBlsDoryWinningNonceExecution {
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    #[must_use]
    pub const fn final_activation_digest(&self) -> [u8; 32] {
        self.final_activation_digest
    }

    #[must_use]
    pub const fn work_digest(&self) -> [u8; 32] {
        self.work_digest
    }

    pub(crate) fn into_parts(
        self,
    ) -> (u64, [u8; 32], [u8; 32], BlsDoryExecutionAccumulatorArtifact) {
        (
            self.nonce,
            self.final_activation_digest,
            self.work_digest,
            self.artifact,
        )
    }
}

#[derive(Debug, Error)]
pub enum BlsDoryWinningNonceReplayError {
    #[error("winning-nonce replay requested a block from a different network")]
    WrongNetwork,
    #[error("winning-nonce replay context could not be derived from the pinned candidate")]
    CandidateContext,
    #[error("winning-nonce work digest does not match its claimed final activation")]
    WorkDigest,
    #[error("winning-nonce work digest does not meet the requested target")]
    HighHash,
    #[error("winning-nonce CPU replay was cancelled")]
    Cancelled,
    #[error("winning-nonce scratch directory must be an existing absolute directory")]
    ScratchDirectory,
    #[error("winning-nonce scratch-space query failed: {0}")]
    ScratchSpaceQuery(#[source] std::io::Error),
    #[error(
        "insufficient winning-nonce scratch space: need {required} bytes, have {available} bytes"
    )]
    InsufficientScratch { required: u64, available: u64 },
    #[error("model bank does not match the execution-artifact geometry or role order")]
    ModelShape,
    #[error("model bank contains a non-canonical centered field value")]
    ModelEncoding,
    #[error("winning-nonce replay allocation or size arithmetic failed")]
    Resource,
    #[error("replayed final activation does not match the accelerator claim")]
    FinalActivationDigest,
    #[error("authenticated model-bank verification failed: {0}")]
    ModelBank(#[from] ModelBankError),
    #[error("execution-accumulator artifact failed: {0}")]
    ExecutionArtifact(#[from] BlsDoryExecutionAccumulatorArtifactError),
    #[error("challenge-derived mask failed: {0}")]
    Mask(#[from] StructuredTransitionError),
    #[error("transition replay failed: {0}")]
    Transition(#[from] BlsDoryTransitionError),
}

/// Recompute one accelerator-proposed winner from an authenticated model bank.
///
/// The caller is the pinned candidate verifier: it derives `context` from its
/// own network/model/setup identities and `claim.nonce`, and supplies only its
/// trusted manifest, PCS identity, and target. The cheap public-claim check is
/// deliberately completed before `model_bank` is read.
#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_winning_nonce_from_verified_bank<R: Read>(
    context: BlsDoryExecutionAccumulatorArtifactContext,
    manifest: &ModelBankManifest,
    trusted_model: &ModelPcsIdentity,
    work_target: [u8; 32],
    claim: BlsDoryWinningNonceClaim,
    model_bank: R,
    scratch_directory: &Path,
    cancel: &AtomicBool,
) -> Result<VerifiedBlsDoryWinningNonceExecution, BlsDoryWinningNonceReplayError> {
    let expected_work = work_digest_from_roots(
        context.challenge_identity(),
        manifest.raw_blake3_root,
        manifest.pcs_commitment_root,
        claim.final_activation_digest,
    );
    if claim.work_digest != expected_work {
        return Err(BlsDoryWinningNonceReplayError::WorkDigest);
    }
    if claim.work_digest > work_target {
        return Err(BlsDoryWinningNonceReplayError::HighHash);
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(BlsDoryWinningNonceReplayError::Cancelled);
    }

    manifest.verify_pcs_identity(trusted_model)?;
    validate_replay_geometry(context, manifest, trusted_model)?;
    preflight_execution_artifact(context, scratch_directory)?;

    let sink = WinningNonceReplaySink::new(
        context,
        *manifest,
        trusted_model.clone(),
        claim,
        scratch_directory,
        cancel,
    )?;
    verify_model_bank_into_staged_field_sink(model_bank, manifest, trusted_model, sink).map_err(
        |error| match error {
            ModelBankFieldStreamError::ModelBank(error) => error.into(),
            ModelBankFieldStreamError::Sink(error) => error,
        },
    )
}

fn preflight_execution_artifact(
    context: BlsDoryExecutionAccumulatorArtifactContext,
    scratch_directory: &Path,
) -> Result<(), BlsDoryWinningNonceReplayError> {
    if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
        return Err(BlsDoryWinningNonceReplayError::ScratchDirectory);
    }
    let required = context.projected_file_bytes()?;
    let available = fs2::available_space(scratch_directory)
        .map_err(BlsDoryWinningNonceReplayError::ScratchSpaceQuery)?;
    if available < required {
        return Err(BlsDoryWinningNonceReplayError::InsufficientScratch {
            required,
            available,
        });
    }
    Ok(())
}

fn validate_replay_geometry(
    context: BlsDoryExecutionAccumulatorArtifactContext,
    manifest: &ModelBankManifest,
    trusted_model: &ModelPcsIdentity,
) -> Result<(), BlsDoryWinningNonceReplayError> {
    let banks = trusted_model.weight_bank_commitments.len();
    if usize::try_from(manifest.batch).ok() != Some(context.canonical_rows())
        || usize::try_from(manifest.dimension).ok() != Some(context.canonical_columns())
        || banks != context.banks()
        || usize::try_from(trusted_model.layers_per_bank).ok() != Some(context.layers_per_bank())
        || usize::try_from(manifest.layers).ok()
            != context.banks().checked_mul(context.layers_per_bank())
    {
        return Err(BlsDoryWinningNonceReplayError::ModelShape);
    }
    Ok(())
}

struct WinningNonceReplaySink<'a> {
    context: BlsDoryExecutionAccumulatorArtifactContext,
    expected_manifest: ModelBankManifest,
    expected_model: ModelPcsIdentity,
    claim: BlsDoryWinningNonceClaim,
    cancel: &'a AtomicBool,
    writer: Option<BlsDoryExecutionAccumulatorArtifactWriter>,
    initialization_statement: StructuredTransitionStatement,
    transition_statement: StructuredTransitionStatement,
    initialization_mask: StructuredMaskPolynomial,
    transition_masks: Vec<StructuredMaskPolynomial>,
    cells: usize,
    layer_cells: usize,
    bank_elements: u64,
    base_offset: usize,
    current_bank: usize,
    bank_offset: usize,
    activations: Vec<i8>,
    next_activations: Vec<i8>,
    weight_layer: Vec<i8>,
    pending_initial_accumulators: Vec<i32>,
    accumulator_chunk: Vec<i64>,
    encoded_accumulator_chunk: Vec<i32>,
}

impl<'a> WinningNonceReplaySink<'a> {
    fn new(
        context: BlsDoryExecutionAccumulatorArtifactContext,
        expected_manifest: ModelBankManifest,
        expected_model: ModelPcsIdentity,
        claim: BlsDoryWinningNonceClaim,
        scratch_directory: &Path,
        cancel: &'a AtomicBool,
    ) -> Result<Self, BlsDoryWinningNonceReplayError> {
        let rows = context.canonical_rows();
        let columns = context.canonical_columns();
        let cells = rows
            .checked_mul(columns)
            .ok_or(BlsDoryWinningNonceReplayError::Resource)?;
        let layer_cells = columns
            .checked_mul(columns)
            .ok_or(BlsDoryWinningNonceReplayError::Resource)?;
        let bank_elements = u64::try_from(layer_cells)
            .ok()
            .and_then(|elements| elements.checked_mul(context.layers_per_bank() as u64))
            .ok_or(BlsDoryWinningNonceReplayError::Resource)?;
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows,
            cols: columns,
            max_abs_accumulator: u64::from(V2_MODEL_VALUE_CENTER.unsigned_abs()),
            max_mask: MAX_TRANSITION_MASK,
        };
        let transition_statement = StructuredTransitionStatement {
            layers: context.layers_per_bank(),
            rows,
            cols: columns,
            max_abs_accumulator: u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS),
            max_mask: MAX_TRANSITION_MASK,
        };
        let initialization_mask = StructuredMaskPolynomial::from_virtual_challenge(
            &context.challenge_identity(),
            rows,
            columns,
        )?;
        initialization_mask.validate(initialization_statement)?;
        let mut transition_masks = Vec::new();
        transition_masks
            .try_reserve_exact(context.banks())
            .map_err(|_| BlsDoryWinningNonceReplayError::Resource)?;
        for bank in 0..context.banks() {
            let first_layer = bank
                .checked_mul(context.layers_per_bank())
                .and_then(|layer| u32::try_from(layer).ok())
                .ok_or(BlsDoryWinningNonceReplayError::Resource)?;
            let mask = StructuredMaskPolynomial::from_challenge_at_layer_offset(
                &context.challenge_identity(),
                first_layer,
                context.layers_per_bank(),
                rows,
                columns,
            )?;
            mask.validate(transition_statement)?;
            transition_masks.push(mask);
        }

        Ok(Self {
            context,
            expected_manifest,
            expected_model,
            claim,
            cancel,
            writer: Some(BlsDoryExecutionAccumulatorArtifactWriter::create_new(
                scratch_directory,
                context,
            )?),
            initialization_statement,
            transition_statement,
            initialization_mask,
            transition_masks,
            cells,
            layer_cells,
            bank_elements,
            base_offset: 0,
            current_bank: 0,
            bank_offset: 0,
            activations: zeroed_vector(cells)?,
            next_activations: zeroed_vector(cells)?,
            weight_layer: reserved_vector(layer_cells)?,
            pending_initial_accumulators: reserved_vector(context.authentication_chunk_cells())?,
            accumulator_chunk: zeroed_vector(context.authentication_chunk_cells())?,
            encoded_accumulator_chunk: zeroed_vector(context.authentication_chunk_cells())?,
        })
    }

    fn writer_mut(
        &mut self,
    ) -> Result<&mut BlsDoryExecutionAccumulatorArtifactWriter, BlsDoryWinningNonceReplayError>
    {
        self.writer
            .as_mut()
            .ok_or(BlsDoryWinningNonceReplayError::ModelShape)
    }

    fn write_base_chunk(
        &mut self,
        chunk: ModelFieldChunk<'_>,
    ) -> Result<(), BlsDoryWinningNonceReplayError> {
        if chunk.role != ModelPcsRole::BaseInput
            || chunk.role_offset != self.base_offset as u64
            || chunk.role_elements != self.cells as u64
            || chunk.elements.len() > self.cells.saturating_sub(self.base_offset)
        {
            return Err(BlsDoryWinningNonceReplayError::ModelShape);
        }
        for &element in chunk.elements {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(BlsDoryWinningNonceReplayError::Cancelled);
            }
            let index = self.base_offset;
            let accumulator = i64::from(decode_model_field(element)?);
            let mask = self
                .initialization_mask
                .value_at_boolean_index_prevalidated(self.initialization_statement, index)?;
            let transition = derive_transition_regular_row_from_mask(
                self.initialization_statement,
                index,
                accumulator,
                mask,
            )?;
            self.activations[index] = i8::try_from(transition.activation)
                .map_err(|_| BlsDoryWinningNonceReplayError::ModelShape)?;
            self.pending_initial_accumulators.push(
                i32::try_from(accumulator)
                    .map_err(|_| BlsDoryWinningNonceReplayError::ModelShape)?,
            );
            self.base_offset += 1;

            if self.pending_initial_accumulators.len() == self.context.authentication_chunk_cells()
            {
                let values = std::mem::take(&mut self.pending_initial_accumulators);
                self.writer_mut()?.write_column_chunk(
                    BlsDoryExecutionAccumulatorColumn::Initialization,
                    &values,
                )?;
                self.pending_initial_accumulators =
                    reserved_vector(self.context.authentication_chunk_cells())?;
            }
        }
        if self.base_offset == self.cells && !self.pending_initial_accumulators.is_empty() {
            let values = std::mem::take(&mut self.pending_initial_accumulators);
            self.writer_mut()?
                .write_column_chunk(BlsDoryExecutionAccumulatorColumn::Initialization, &values)?;
            self.pending_initial_accumulators =
                reserved_vector(self.context.authentication_chunk_cells())?;
        }
        Ok(())
    }

    fn write_weight_chunk(
        &mut self,
        chunk: ModelFieldChunk<'_>,
    ) -> Result<(), BlsDoryWinningNonceReplayError> {
        if self.current_bank >= self.context.banks()
            || chunk.role
                != (ModelPcsRole::WeightBank {
                    index: self.current_bank as u32,
                })
            || chunk.role_offset != self.bank_offset as u64
            || chunk.role_elements != self.bank_elements
            || chunk.elements.len()
                > usize::try_from(self.bank_elements)
                    .ok()
                    .and_then(|total| total.checked_sub(self.bank_offset))
                    .ok_or(BlsDoryWinningNonceReplayError::ModelShape)?
        {
            return Err(BlsDoryWinningNonceReplayError::ModelShape);
        }

        let mut consumed = 0usize;
        while consumed < chunk.elements.len() {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(BlsDoryWinningNonceReplayError::Cancelled);
            }
            let layer_offset = self.bank_offset % self.layer_cells;
            let take = (self.layer_cells - layer_offset).min(chunk.elements.len() - consumed);
            for &element in &chunk.elements[consumed..consumed + take] {
                self.weight_layer.push(decode_model_field(element)?);
            }
            self.bank_offset = self
                .bank_offset
                .checked_add(take)
                .ok_or(BlsDoryWinningNonceReplayError::Resource)?;
            consumed += take;

            if self.weight_layer.len() == self.layer_cells {
                let layer = self
                    .bank_offset
                    .checked_div(self.layer_cells)
                    .and_then(|completed| completed.checked_sub(1))
                    .ok_or(BlsDoryWinningNonceReplayError::ModelShape)?;
                self.execute_layer(self.current_bank, layer)?;
                self.weight_layer.clear();
            }
        }

        if self.bank_offset as u64 == self.bank_elements {
            if !self.weight_layer.is_empty() {
                return Err(BlsDoryWinningNonceReplayError::ModelShape);
            }
            self.current_bank += 1;
            self.bank_offset = 0;
        }
        Ok(())
    }

    fn execute_layer(
        &mut self,
        bank: usize,
        layer: usize,
    ) -> Result<(), BlsDoryWinningNonceReplayError> {
        if bank >= self.context.banks()
            || layer >= self.context.layers_per_bank()
            || self.weight_layer.len() != self.layer_cells
        {
            return Err(BlsDoryWinningNonceReplayError::ModelShape);
        }
        let width = self.context.canonical_columns();
        let chunk_cells = self.context.authentication_chunk_cells();
        let mask = &self.transition_masks[bank];

        for start in (0..self.cells).step_by(chunk_cells) {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(BlsDoryWinningNonceReplayError::Cancelled);
            }
            let len = chunk_cells.min(self.cells - start);
            let accumulators = &mut self.accumulator_chunk[..len];
            accumulators.fill(0);

            if start.is_multiple_of(width) && len.is_multiple_of(width) {
                let first_row = start / width;
                accumulators
                    .par_chunks_mut(width)
                    .enumerate()
                    .try_for_each(|(local_row, output)| {
                        if self.cancel.load(Ordering::Relaxed) {
                            return Err(BlsDoryWinningNonceReplayError::Cancelled);
                        }
                        let row = first_row + local_row;
                        let activation_row = &self.activations[row * width..(row + 1) * width];
                        for (common, activation) in activation_row.iter().copied().enumerate() {
                            let weights = &self.weight_layer[common * width..(common + 1) * width];
                            for (accumulator, weight) in
                                output.iter_mut().zip(weights.iter().copied())
                            {
                                *accumulator += i64::from(activation) * i64::from(weight);
                            }
                        }
                        validate_accumulator_bound(output)
                    })?;
            } else {
                accumulators
                    .par_iter_mut()
                    .enumerate()
                    .try_for_each(|(offset, accumulator)| {
                        if self.cancel.load(Ordering::Relaxed) {
                            return Err(BlsDoryWinningNonceReplayError::Cancelled);
                        }
                        let cell = start + offset;
                        let row = cell / width;
                        let column = cell % width;
                        let activation_row = &self.activations[row * width..(row + 1) * width];
                        let mut sum = 0i64;
                        for (common, activation) in activation_row.iter().copied().enumerate() {
                            sum += i64::from(activation)
                                * i64::from(self.weight_layer[common * width + column]);
                        }
                        validate_accumulator_bound(std::slice::from_ref(&sum))?;
                        *accumulator = sum;
                        Ok(())
                    })?;
            }

            let encoded = &mut self.encoded_accumulator_chunk[..len];
            let next = &mut self.next_activations[start..start + len];
            encoded
                .par_iter_mut()
                .zip(next.par_iter_mut())
                .zip(accumulators.par_iter())
                .enumerate()
                .try_for_each(|(offset, ((encoded, activation), accumulator))| {
                    if self.cancel.load(Ordering::Relaxed) {
                        return Err(BlsDoryWinningNonceReplayError::Cancelled);
                    }
                    let index = layer
                        .checked_mul(self.cells)
                        .and_then(|base| base.checked_add(start + offset))
                        .ok_or(BlsDoryWinningNonceReplayError::Resource)?;
                    let mask_value =
                        mask.value_at_boolean_index_prevalidated(self.transition_statement, index)?;
                    let transition = derive_transition_regular_row_from_mask(
                        self.transition_statement,
                        index,
                        *accumulator,
                        mask_value,
                    )?;
                    *encoded = i32::try_from(*accumulator)
                        .map_err(|_| BlsDoryWinningNonceReplayError::ModelShape)?;
                    *activation = i8::try_from(transition.activation)
                        .map_err(|_| BlsDoryWinningNonceReplayError::ModelShape)?;
                    Ok(())
                })?;

            let (writer, encoded) = (&mut self.writer, &self.encoded_accumulator_chunk[..len]);
            writer
                .as_mut()
                .ok_or(BlsDoryWinningNonceReplayError::ModelShape)?
                .write_column_chunk(
                    BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
                    encoded,
                )?;
        }
        std::mem::swap(&mut self.activations, &mut self.next_activations);
        self.next_activations.fill(0);
        Ok(())
    }
}

impl StagedModelFieldSink for WinningNonceReplaySink<'_> {
    type Error = BlsDoryWinningNonceReplayError;
    type Output = VerifiedBlsDoryWinningNonceExecution;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
        if chunk.elements.is_empty() {
            return Err(BlsDoryWinningNonceReplayError::ModelShape);
        }
        if self.base_offset < self.cells {
            self.write_base_chunk(chunk)
        } else {
            self.write_weight_chunk(chunk)
        }
    }

    fn finish_verified(
        mut self,
        receipt: VerifiedModelBankReceipt,
    ) -> Result<Self::Output, Self::Error> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(BlsDoryWinningNonceReplayError::Cancelled);
        }
        if receipt.manifest() != &self.expected_manifest
            || receipt.identity() != &self.expected_model
            || receipt.layout().weight_bank_count() as usize != self.context.banks()
            || receipt.layout().layers_per_bank() as usize != self.context.layers_per_bank()
            || self.base_offset != self.cells
            || self.current_bank != self.context.banks()
            || self.bank_offset != 0
            || !self.weight_layer.is_empty()
            || !self.pending_initial_accumulators.is_empty()
        {
            return Err(BlsDoryWinningNonceReplayError::ModelShape);
        }

        let mut final_activation = reserved_vector(self.cells)?;
        for activation in &self.activations {
            let encoded = i16::from(*activation)
                .checked_add(V2_MODEL_VALUE_CENTER)
                .and_then(|value| u8::try_from(value).ok())
                .filter(|value| *value <= 250)
                .ok_or(BlsDoryWinningNonceReplayError::ModelShape)?;
            final_activation.push(encoded);
        }
        let final_activation_digest =
            output_digest(self.context.challenge_identity(), &final_activation);
        if final_activation_digest != self.claim.final_activation_digest {
            return Err(BlsDoryWinningNonceReplayError::FinalActivationDigest);
        }
        let work_digest = work_digest_from_roots(
            self.context.challenge_identity(),
            self.expected_manifest.raw_blake3_root,
            self.expected_manifest.pcs_commitment_root,
            final_activation_digest,
        );
        if work_digest != self.claim.work_digest {
            return Err(BlsDoryWinningNonceReplayError::WorkDigest);
        }

        let writer = self
            .writer
            .take()
            .ok_or(BlsDoryWinningNonceReplayError::ModelShape)?;
        finish_verified_execution(
            writer,
            self.claim,
            final_activation_digest,
            work_digest,
            self.cancel,
        )
    }
}

fn finish_verified_execution(
    writer: BlsDoryExecutionAccumulatorArtifactWriter,
    claim: BlsDoryWinningNonceClaim,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
    cancel: &AtomicBool,
) -> Result<VerifiedBlsDoryWinningNonceExecution, BlsDoryWinningNonceReplayError> {
    let artifact = writer.finish()?;
    if cancel.load(Ordering::Relaxed) {
        drop(artifact);
        return Err(BlsDoryWinningNonceReplayError::Cancelled);
    }
    Ok(VerifiedBlsDoryWinningNonceExecution {
        nonce: claim.nonce,
        final_activation_digest,
        work_digest,
        artifact,
    })
}

fn decode_model_field(value: u64) -> Result<i8, BlsDoryWinningNonceReplayError> {
    let signed =
        signed_model_value(value).map_err(|_| BlsDoryWinningNonceReplayError::ModelEncoding)?;
    i8::try_from(signed).map_err(|_| BlsDoryWinningNonceReplayError::ModelEncoding)
}

fn validate_accumulator_bound(accumulators: &[i64]) -> Result<(), BlsDoryWinningNonceReplayError> {
    if accumulators
        .iter()
        .any(|value| value.unsigned_abs() > u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS))
    {
        return Err(BlsDoryWinningNonceReplayError::ModelShape);
    }
    Ok(())
}

fn zeroed_vector<T: Default + Clone>(len: usize) -> Result<Vec<T>, BlsDoryWinningNonceReplayError> {
    let mut values = reserved_vector(len)?;
    values.resize(len, T::default());
    Ok(values)
}

fn reserved_vector<T>(capacity: usize) -> Result<Vec<T>, BlsDoryWinningNonceReplayError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| BlsDoryWinningNonceReplayError::Resource)?;
    Ok(values)
}

struct DoryV3WinningNonceReplaySink<'a> {
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    expected_manifest: ModelBankManifest,
    claim: BlsDoryV3WinningNonceClaim,
    cancel: &'a AtomicBool,
    writer: Option<BlsDoryExecutionAccumulatorArtifactWriter>,
    initialization_statement: StructuredTransitionStatement,
    transition_statement: StructuredTransitionStatement,
    initialization_mask: StructuredMaskPolynomial,
    transition_masks: Vec<StructuredMaskPolynomial>,
    cells: usize,
    layer_cells: usize,
    bank_elements: u64,
    base_offset: usize,
    current_bank: usize,
    bank_offset: usize,
    activations: Vec<i8>,
    next_activations: Vec<i8>,
    weight_layer: Vec<i8>,
    pending_initial_accumulators: Vec<i32>,
    accumulator_chunk: Vec<i64>,
    encoded_accumulator_chunk: Vec<i32>,
}

impl<'a> DoryV3WinningNonceReplaySink<'a> {
    fn new(
        context: BlsDoryV3ExecutionAccumulatorArtifactContext,
        expected_manifest: ModelBankManifest,
        claim: BlsDoryV3WinningNonceClaim,
        scratch_directory: &Path,
        cancel: &'a AtomicBool,
    ) -> Result<Self, BlsDoryV3WinningNonceReplayError> {
        let raw = *context.raw();
        let rows = raw.canonical_rows();
        let columns = raw.canonical_columns();
        let cells = rows
            .checked_mul(columns)
            .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
        let layer_cells = columns
            .checked_mul(columns)
            .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
        let bank_elements = u64::try_from(layer_cells)
            .ok()
            .and_then(|elements| elements.checked_mul(raw.layers_per_bank() as u64))
            .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows,
            cols: columns,
            max_abs_accumulator: u64::from(V2_MODEL_VALUE_CENTER.unsigned_abs()),
            max_mask: MAX_TRANSITION_MASK,
        };
        let transition_statement = StructuredTransitionStatement {
            layers: raw.layers_per_bank(),
            rows,
            cols: columns,
            max_abs_accumulator: u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS),
            max_mask: MAX_TRANSITION_MASK,
        };
        let initialization_mask = StructuredMaskPolynomial::from_dory_v3_virtual_challenge(
            &raw.challenge_identity(),
            rows,
            columns,
        )?;
        initialization_mask.validate(initialization_statement)?;
        let mut transition_masks = Vec::new();
        transition_masks
            .try_reserve_exact(raw.banks())
            .map_err(|_| BlsDoryV3WinningNonceReplayError::Resource)?;
        for bank in 0..raw.banks() {
            let first_layer = bank
                .checked_mul(raw.layers_per_bank())
                .and_then(|layer| u32::try_from(layer).ok())
                .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
            let mask = StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
                &raw.challenge_identity(),
                first_layer,
                raw.layers_per_bank(),
                rows,
                columns,
            )?;
            mask.validate(transition_statement)?;
            transition_masks.push(mask);
        }

        Ok(Self {
            context,
            expected_manifest,
            claim,
            cancel,
            writer: Some(BlsDoryExecutionAccumulatorArtifactWriter::create_new(
                scratch_directory,
                raw,
            )?),
            initialization_statement,
            transition_statement,
            initialization_mask,
            transition_masks,
            cells,
            layer_cells,
            bank_elements,
            base_offset: 0,
            current_bank: 0,
            bank_offset: 0,
            activations: zeroed_dory_v3_vector(cells)?,
            next_activations: zeroed_dory_v3_vector(cells)?,
            weight_layer: reserved_dory_v3_vector(layer_cells)?,
            pending_initial_accumulators: reserved_dory_v3_vector(
                raw.authentication_chunk_cells(),
            )?,
            accumulator_chunk: zeroed_dory_v3_vector(raw.authentication_chunk_cells())?,
            encoded_accumulator_chunk: zeroed_dory_v3_vector(raw.authentication_chunk_cells())?,
        })
    }

    fn writer_mut(
        &mut self,
    ) -> Result<&mut BlsDoryExecutionAccumulatorArtifactWriter, BlsDoryV3WinningNonceReplayError>
    {
        self.writer
            .as_mut()
            .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)
    }

    fn write_base_chunk(
        &mut self,
        chunk: ModelFieldChunk<'_>,
    ) -> Result<(), BlsDoryV3WinningNonceReplayError> {
        if chunk.role != ModelPcsRole::BaseInput
            || chunk.role_offset != self.base_offset as u64
            || chunk.role_elements != self.cells as u64
            || chunk.elements.len() > self.cells.saturating_sub(self.base_offset)
        {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        for &element in chunk.elements {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
            }
            let index = self.base_offset;
            let accumulator = i64::from(decode_dory_v3_model_field(element)?);
            let mask = self
                .initialization_mask
                .value_at_boolean_index_prevalidated(self.initialization_statement, index)?;
            let transition = derive_transition_regular_row_from_mask(
                self.initialization_statement,
                index,
                accumulator,
                mask,
            )?;
            self.activations[index] = i8::try_from(transition.activation)
                .map_err(|_| BlsDoryV3WinningNonceReplayError::ModelShape)?;
            self.pending_initial_accumulators.push(
                i32::try_from(accumulator)
                    .map_err(|_| BlsDoryV3WinningNonceReplayError::ModelShape)?,
            );
            self.base_offset += 1;

            if self.pending_initial_accumulators.len()
                == self.context.raw().authentication_chunk_cells()
            {
                let values = std::mem::take(&mut self.pending_initial_accumulators);
                self.writer_mut()?.write_column_chunk(
                    BlsDoryExecutionAccumulatorColumn::Initialization,
                    &values,
                )?;
                self.pending_initial_accumulators =
                    reserved_dory_v3_vector(self.context.raw().authentication_chunk_cells())?;
            }
        }
        if self.base_offset == self.cells && !self.pending_initial_accumulators.is_empty() {
            let values = std::mem::take(&mut self.pending_initial_accumulators);
            self.writer_mut()?
                .write_column_chunk(BlsDoryExecutionAccumulatorColumn::Initialization, &values)?;
            self.pending_initial_accumulators =
                reserved_dory_v3_vector(self.context.raw().authentication_chunk_cells())?;
        }
        Ok(())
    }

    fn write_weight_chunk(
        &mut self,
        chunk: ModelFieldChunk<'_>,
    ) -> Result<(), BlsDoryV3WinningNonceReplayError> {
        if self.current_bank >= self.context.raw().banks()
            || chunk.role
                != (ModelPcsRole::WeightBank {
                    index: self.current_bank as u32,
                })
            || chunk.role_offset != self.bank_offset as u64
            || chunk.role_elements != self.bank_elements
            || chunk.elements.len()
                > usize::try_from(self.bank_elements)
                    .ok()
                    .and_then(|total| total.checked_sub(self.bank_offset))
                    .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?
        {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }

        let mut consumed = 0usize;
        while consumed < chunk.elements.len() {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
            }
            let layer_offset = self.bank_offset % self.layer_cells;
            let take = (self.layer_cells - layer_offset).min(chunk.elements.len() - consumed);
            for &element in &chunk.elements[consumed..consumed + take] {
                self.weight_layer.push(decode_dory_v3_model_field(element)?);
            }
            self.bank_offset = self
                .bank_offset
                .checked_add(take)
                .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
            consumed += take;

            if self.weight_layer.len() == self.layer_cells {
                let layer = self
                    .bank_offset
                    .checked_div(self.layer_cells)
                    .and_then(|completed| completed.checked_sub(1))
                    .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?;
                self.execute_layer(self.current_bank, layer)?;
                self.weight_layer.clear();
            }
        }

        if self.bank_offset as u64 == self.bank_elements {
            if !self.weight_layer.is_empty() {
                return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
            }
            self.current_bank += 1;
            self.bank_offset = 0;
        }
        Ok(())
    }

    fn execute_layer(
        &mut self,
        bank: usize,
        layer: usize,
    ) -> Result<(), BlsDoryV3WinningNonceReplayError> {
        if bank >= self.context.raw().banks()
            || layer >= self.context.raw().layers_per_bank()
            || self.weight_layer.len() != self.layer_cells
        {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        let width = self.context.raw().canonical_columns();
        let chunk_cells = self.context.raw().authentication_chunk_cells();
        let mask = &self.transition_masks[bank];

        for start in (0..self.cells).step_by(chunk_cells) {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
            }
            let len = chunk_cells.min(self.cells - start);
            let accumulators = &mut self.accumulator_chunk[..len];
            accumulators.fill(0);

            if start.is_multiple_of(width) && len.is_multiple_of(width) {
                let first_row = start / width;
                accumulators
                    .par_chunks_mut(width)
                    .enumerate()
                    .try_for_each(|(local_row, output)| {
                        if self.cancel.load(Ordering::Relaxed) {
                            return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
                        }
                        let row = first_row + local_row;
                        let activation_row = &self.activations[row * width..(row + 1) * width];
                        for (common, activation) in activation_row.iter().copied().enumerate() {
                            let weights = &self.weight_layer[common * width..(common + 1) * width];
                            for (accumulator, weight) in
                                output.iter_mut().zip(weights.iter().copied())
                            {
                                *accumulator += i64::from(activation) * i64::from(weight);
                            }
                        }
                        validate_dory_v3_accumulator_bound(output)
                    })?;
            } else {
                accumulators
                    .par_iter_mut()
                    .enumerate()
                    .try_for_each(|(offset, accumulator)| {
                        if self.cancel.load(Ordering::Relaxed) {
                            return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
                        }
                        let cell = start + offset;
                        let row = cell / width;
                        let column = cell % width;
                        let activation_row = &self.activations[row * width..(row + 1) * width];
                        let mut sum = 0i64;
                        for (common, activation) in activation_row.iter().copied().enumerate() {
                            sum += i64::from(activation)
                                * i64::from(self.weight_layer[common * width + column]);
                        }
                        validate_dory_v3_accumulator_bound(std::slice::from_ref(&sum))?;
                        *accumulator = sum;
                        Ok(())
                    })?;
            }

            let encoded = &mut self.encoded_accumulator_chunk[..len];
            let next = &mut self.next_activations[start..start + len];
            encoded
                .par_iter_mut()
                .zip(next.par_iter_mut())
                .zip(accumulators.par_iter())
                .enumerate()
                .try_for_each(|(offset, ((encoded, activation), accumulator))| {
                    if self.cancel.load(Ordering::Relaxed) {
                        return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
                    }
                    let index = layer
                        .checked_mul(self.cells)
                        .and_then(|base| base.checked_add(start + offset))
                        .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
                    let mask_value =
                        mask.value_at_boolean_index_prevalidated(self.transition_statement, index)?;
                    let transition = derive_transition_regular_row_from_mask(
                        self.transition_statement,
                        index,
                        *accumulator,
                        mask_value,
                    )?;
                    *encoded = i32::try_from(*accumulator)
                        .map_err(|_| BlsDoryV3WinningNonceReplayError::ModelShape)?;
                    *activation = i8::try_from(transition.activation)
                        .map_err(|_| BlsDoryV3WinningNonceReplayError::ModelShape)?;
                    Ok(())
                })?;

            let (writer, encoded) = (&mut self.writer, &self.encoded_accumulator_chunk[..len]);
            writer
                .as_mut()
                .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?
                .write_column_chunk(
                    BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
                    encoded,
                )?;
        }
        std::mem::swap(&mut self.activations, &mut self.next_activations);
        self.next_activations.fill(0);
        Ok(())
    }
}

impl StagedModelFieldLayoutSink for DoryV3WinningNonceReplaySink<'_> {
    type Error = BlsDoryV3WinningNonceReplayError;
    type Output = VerifiedBlsDoryV3WinningNonceExecution;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
        if chunk.elements.is_empty() {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        if self.base_offset < self.cells {
            self.write_base_chunk(chunk)
        } else {
            self.write_weight_chunk(chunk)
        }
    }

    fn finish_verified(
        mut self,
        receipt: VerifiedModelBankLayoutReceipt,
    ) -> Result<Self::Output, Self::Error> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
        }
        if receipt.manifest() != &self.expected_manifest
            || receipt.layout().weight_bank_count() as usize != self.context.raw().banks()
            || receipt.layout().layers_per_bank() as usize != self.context.raw().layers_per_bank()
            || self.base_offset != self.cells
            || self.current_bank != self.context.raw().banks()
            || self.bank_offset != 0
            || !self.weight_layer.is_empty()
            || !self.pending_initial_accumulators.is_empty()
        {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }

        let mut final_activation = reserved_dory_v3_vector(self.cells)?;
        for activation in &self.activations {
            let encoded = i16::from(*activation)
                .checked_add(V2_MODEL_VALUE_CENTER)
                .and_then(|value| u8::try_from(value).ok())
                .filter(|value| *value <= 250)
                .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?;
            final_activation.push(encoded);
        }
        let final_activation_digest = self.context.output_digest(&final_activation)?;
        if final_activation_digest != self.claim.final_activation_digest {
            return Err(BlsDoryV3WinningNonceReplayError::FinalActivationDigest);
        }
        let work_digest = self.context.work_digest(final_activation_digest);
        if work_digest != self.claim.work_digest {
            return Err(BlsDoryV3WinningNonceReplayError::WorkDigest);
        }

        let writer = self
            .writer
            .take()
            .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?;
        finish_verified_dory_v3_execution(
            writer,
            self.context,
            self.claim,
            final_activation_digest,
            work_digest,
            self.cancel,
        )
    }
}

fn finish_verified_dory_v3_execution(
    writer: BlsDoryExecutionAccumulatorArtifactWriter,
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    claim: BlsDoryV3WinningNonceClaim,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
    cancel: &AtomicBool,
) -> Result<VerifiedBlsDoryV3WinningNonceExecution, BlsDoryV3WinningNonceReplayError> {
    let artifact = writer.finish()?;
    if cancel.load(Ordering::Relaxed) {
        drop(artifact);
        return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
    }
    Ok(VerifiedBlsDoryV3WinningNonceExecution {
        context,
        nonce: claim.nonce,
        final_activation_digest,
        work_digest,
        artifact,
    })
}

fn decode_dory_v3_model_field(value: u64) -> Result<i8, BlsDoryV3WinningNonceReplayError> {
    let signed =
        signed_model_value(value).map_err(|_| BlsDoryV3WinningNonceReplayError::ModelEncoding)?;
    i8::try_from(signed).map_err(|_| BlsDoryV3WinningNonceReplayError::ModelEncoding)
}

fn validate_dory_v3_accumulator_bound(
    accumulators: &[i64],
) -> Result<(), BlsDoryV3WinningNonceReplayError> {
    if accumulators
        .iter()
        .any(|value| value.unsigned_abs() > u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS))
    {
        return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
    }
    Ok(())
}

fn zeroed_dory_v3_vector<T: Default + Clone>(
    len: usize,
) -> Result<Vec<T>, BlsDoryV3WinningNonceReplayError> {
    let mut values = reserved_dory_v3_vector(len)?;
    values.resize(len, T::default());
    Ok(values)
}

fn reserved_dory_v3_vector<T>(capacity: usize) -> Result<Vec<T>, BlsDoryV3WinningNonceReplayError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| BlsDoryV3WinningNonceReplayError::Resource)?;
    Ok(values)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{self, Cursor, Read},
        path::{Path, PathBuf},
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    };

    use dory_pcs::primitives::arithmetic::Field;
    use rayon::ThreadPoolBuilder;
    use serde_json::json;

    use super::*;
    use crate::{
        BlockChallenge, ForgeMatrixV2Descriptor, ForgeMatrixV2Reference,
        ForgeMatrixV2ReferenceProof, SmallModelBankFixture, StructuredMatrixStatement,
        StructuredSumcheckError,
        dory_bls12_381_aggregate::{
            commit_bls_dory_padded_prefix_with_optional_scratch, commit_bls_dory_polynomial,
        },
        dory_bls12_381_execution_artifact::BlsDoryExecutionAccumulatorColumn,
        dory_bls12_381_matrix::{
            BlsDoryMatrixError,
            prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch,
            prove_bls_dory_matrix_deferred_with_precommitted_weight_from_dory_v3_execution_reader_and_scratch,
        },
        dory_bls12_381_prototype::{BlsDoryFr, BlsDoryGt, deterministic_bls_dory_setup},
        dory_v3_model::{CanonicalBlsDoryGtHex, DoryV3ModelIdentityV1},
        dory_v3_model_record::{
            BankAuthenticatedDoryV3ModelCommitmentRecordV2,
            derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test,
        },
        dory_v3_suite::{DORY_V3_MODEL_IDENTITY_VERSION, DORY_V3_PRODUCTION_SUITE_DIGEST},
        model_bank::{BuiltModelBankFixture, build_small_model_bank},
    };

    static SCRATCH_NONCE: AtomicU64 = AtomicU64::new(1);

    struct ScratchDirectory(PathBuf);

    impl ScratchDirectory {
        fn create() -> Self {
            let nonce = SCRATCH_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-winning-nonce-replay-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn entry_count(&self) -> usize {
            fs::read_dir(&self.0).unwrap().count()
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct ReplayFixture {
        bank: BuiltModelBankFixture,
        identity: ModelPcsIdentity,
        reference: ForgeMatrixV2ReferenceProof,
        context: BlsDoryExecutionAccumulatorArtifactContext,
        base: Vec<u8>,
    }

    fn block() -> BlockChallenge {
        BlockChallenge {
            network_id: [0x63; 32],
            previous_block: [0x11; 32],
            transaction_root: [0x22; 32],
            height: 42,
            timestamp: 1_777_777_777,
            target: [0xff; 32],
        }
    }

    fn replay_fixture() -> ReplayFixture {
        let base = vec![0, 125, 250, 126];
        let layers = vec![
            vec![1, 250, 125, 3],
            vec![250, 2, 4, 124],
            vec![7, 123, 249, 5],
            vec![126, 6, 8, 250],
        ];
        let layer_slices = layers.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let suite = [0x51; 32];
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: [0x52; 32],
        })
        .unwrap();
        let identity = ModelPcsIdentity {
            model_version: 2,
            batch: 2,
            dimension: 2,
            layers_per_bank: 2,
            model_byte_root: provisional.manifest.raw_blake3_root,
            pcs_suite_parameter_digest: suite,
            base_input_commitment: [0x61; 32],
            weight_bank_commitments: vec![[0x71; 32], [0x72; 32]],
        };
        let bank = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        let descriptor =
            ForgeMatrixV2Descriptor::new_research(block().network_id, 2, 2, bank.manifest).unwrap();
        let evaluator =
            ForgeMatrixV2Reference::from_explicit_model(descriptor, base.clone(), layers).unwrap();
        let reference = evaluator.prove_reference(&block(), 9).unwrap();
        let context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [
                block().network_id,
                [0x81; 32],
                [0x82; 32],
                reference.challenge_digest,
            ],
            2,
            2,
            2,
            2,
            4,
        )
        .unwrap();
        ReplayFixture {
            bank,
            identity,
            reference,
            context,
            base,
        }
    }

    fn claim(fixture: &ReplayFixture) -> BlsDoryWinningNonceClaim {
        BlsDoryWinningNonceClaim {
            nonce: fixture.reference.nonce,
            final_activation_digest: fixture.reference.final_activation_digest,
            work_digest: fixture.reference.work_digest,
        }
    }

    fn replay(
        fixture: &ReplayFixture,
        scratch: &ScratchDirectory,
    ) -> VerifiedBlsDoryWinningNonceExecution {
        replay_winning_nonce_from_verified_bank(
            fixture.context,
            &fixture.bank.manifest,
            &fixture.identity,
            block().target,
            claim(fixture),
            Cursor::new(&fixture.bank.bytes),
            scratch.path(),
            &AtomicBool::new(false),
        )
        .unwrap()
    }

    #[test]
    fn authenticated_cpu_replay_matches_every_reference_accumulator() {
        let fixture = replay_fixture();
        let scratch = ScratchDirectory::create();
        let execution = replay(&fixture, &scratch);
        assert_eq!(execution.nonce(), fixture.reference.nonce);
        assert_eq!(
            execution.final_activation_digest(),
            fixture.reference.final_activation_digest
        );
        assert_eq!(execution.work_digest(), fixture.reference.work_digest);

        let (_, _, _, mut artifact) = execution.into_parts();
        assert_eq!(artifact.context(), fixture.context);
        let mut actual = vec![0i32; 4];
        artifact
            .read_column_segment(
                BlsDoryExecutionAccumulatorColumn::Initialization,
                0,
                &mut actual,
            )
            .unwrap();
        let expected_initial = fixture
            .base
            .iter()
            .map(|value| i32::from(*value) - i32::from(V2_MODEL_VALUE_CENTER))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected_initial);

        for bank in 0..2 {
            for layer in 0..2 {
                artifact
                    .read_column_segment(
                        BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
                        0,
                        &mut actual,
                    )
                    .unwrap();
                assert_eq!(
                    actual,
                    fixture.reference.layers[bank * 2 + layer].accumulators
                );
            }
        }
        let wrong_context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [block().network_id, [0x81; 32], [0x82; 32], [0x99; 32]],
            2,
            2,
            2,
            2,
            4,
        )
        .unwrap();
        assert!(matches!(
            artifact.authenticate(&wrong_context),
            Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext)
        ));
        drop(artifact);
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn replay_artifact_is_identical_across_thread_counts() {
        let fixture = replay_fixture();
        let scratch = ScratchDirectory::create();
        let one = ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap()
            .install(|| replay(&fixture, &scratch));
        let many = ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap()
            .install(|| replay(&fixture, &scratch));
        let (_, _, _, one_artifact) = one.into_parts();
        let (_, _, _, many_artifact) = many.into_parts();
        assert_eq!(one_artifact.root_digest(), many_artifact.root_digest());
        assert_eq!(one_artifact.digest(), many_artifact.digest());
        drop((one_artifact, many_artifact));
        assert_eq!(scratch.entry_count(), 0);
    }

    struct PanicReader;

    impl Read for PanicReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            panic!("an inconsistent claim must be rejected before the reader is touched")
        }
    }

    #[test]
    fn inconsistent_claim_is_rejected_before_model_read() {
        let fixture = replay_fixture();
        let scratch = ScratchDirectory::create();
        let mut invalid = claim(&fixture);
        invalid.work_digest[0] ^= 1;
        let error = replay_winning_nonce_from_verified_bank(
            fixture.context,
            &fixture.bank.manifest,
            &fixture.identity,
            block().target,
            invalid,
            PanicReader,
            scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(error, BlsDoryWinningNonceReplayError::WorkDigest));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn high_hash_is_rejected_before_model_read() {
        let fixture = replay_fixture();
        let scratch = ScratchDirectory::create();
        assert_ne!(fixture.reference.work_digest, [0; 32]);
        let error = replay_winning_nonce_from_verified_bank(
            fixture.context,
            &fixture.bank.manifest,
            &fixture.identity,
            [0; 32],
            claim(&fixture),
            PanicReader,
            scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(error, BlsDoryWinningNonceReplayError::HighHash));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn internally_consistent_false_output_claim_is_rejected_after_replay() {
        let fixture = replay_fixture();
        let scratch = ScratchDirectory::create();
        let false_output = [0xa5; 32];
        let false_work = work_digest_from_roots(
            fixture.context.challenge_identity(),
            fixture.bank.manifest.raw_blake3_root,
            fixture.bank.manifest.pcs_commitment_root,
            false_output,
        );
        let false_claim = BlsDoryWinningNonceClaim {
            nonce: fixture.reference.nonce,
            final_activation_digest: false_output,
            work_digest: false_work,
        };
        let error = replay_winning_nonce_from_verified_bank(
            fixture.context,
            &fixture.bank.manifest,
            &fixture.identity,
            [0xff; 32],
            false_claim,
            Cursor::new(&fixture.bank.bytes),
            scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            BlsDoryWinningNonceReplayError::FinalActivationDigest
        ));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn sink_rejects_noncanonical_role_before_publication() {
        let fixture = replay_fixture();
        let scratch = ScratchDirectory::create();
        let cancel = AtomicBool::new(false);
        let mut sink = WinningNonceReplaySink::new(
            fixture.context,
            fixture.bank.manifest,
            fixture.identity.clone(),
            claim(&fixture),
            scratch.path(),
            &cancel,
        )
        .unwrap();
        let error = sink
            .write_chunk(ModelFieldChunk {
                role: ModelPcsRole::WeightBank { index: 0 },
                role_offset: 0,
                role_elements: 8,
                elements: &[0],
            })
            .unwrap_err();
        assert!(matches!(error, BlsDoryWinningNonceReplayError::ModelShape));
        drop(sink);
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn late_model_authentication_failure_removes_partial_artifact() {
        let fixture = replay_fixture();
        let scratch = ScratchDirectory::create();
        let mut corrupt = fixture.bank.bytes.clone();
        corrupt[crate::MODEL_BANK_HEADER_BYTES] ^= 1;
        let error = replay_winning_nonce_from_verified_bank(
            fixture.context,
            &fixture.bank.manifest,
            &fixture.identity,
            block().target,
            claim(&fixture),
            Cursor::new(corrupt),
            scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            BlsDoryWinningNonceReplayError::ModelBank(ModelBankError::RawRootMismatch)
        ));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn malformed_complete_streams_remove_partial_artifacts() {
        let fixture = replay_fixture();

        let mut truncated = fixture.bank.bytes.clone();
        truncated.pop();
        let mut trailing = fixture.bank.bytes.clone();
        trailing.push(0);
        let mut forbidden = fixture.bank.bytes.clone();
        forbidden[crate::MODEL_BANK_HEADER_BYTES] = 251;

        for (bytes, expected) in [
            (truncated, "truncated"),
            (trailing, "trailing"),
            (forbidden, "forbidden"),
        ] {
            let scratch = ScratchDirectory::create();
            let error = replay_winning_nonce_from_verified_bank(
                fixture.context,
                &fixture.bank.manifest,
                &fixture.identity,
                block().target,
                claim(&fixture),
                Cursor::new(bytes),
                scratch.path(),
                &AtomicBool::new(false),
            )
            .err()
            .unwrap();
            match expected {
                "truncated" => assert!(matches!(
                    error,
                    BlsDoryWinningNonceReplayError::ModelBank(ModelBankError::Truncated)
                )),
                "trailing" => assert!(matches!(
                    error,
                    BlsDoryWinningNonceReplayError::ModelBank(ModelBankError::TrailingBytes)
                )),
                "forbidden" => assert!(matches!(
                    error,
                    BlsDoryWinningNonceReplayError::ModelBank(ModelBankError::OutOfRange { .. })
                )),
                _ => unreachable!(),
            }
            assert_eq!(scratch.entry_count(), 0);
        }
    }

    struct FailingReader {
        inner: Cursor<Vec<u8>>,
        fail_at: u64,
    }

    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let position = self.inner.position();
            if position >= self.fail_at {
                return Err(io::Error::other("injected model-bank reader failure"));
            }
            let remaining = usize::try_from(self.fail_at - position).unwrap();
            let read_len = buffer.len().min(remaining);
            self.inner.read(&mut buffer[..read_len])
        }
    }

    #[test]
    fn reader_failure_removes_partial_artifact() {
        let fixture = replay_fixture();
        let scratch = ScratchDirectory::create();
        let reader = FailingReader {
            inner: Cursor::new(fixture.bank.bytes.clone()),
            fail_at: crate::MODEL_BANK_HEADER_BYTES as u64
                + fixture.bank.manifest.base_input_bytes
                + 2,
        };
        let error = replay_winning_nonce_from_verified_bank(
            fixture.context,
            &fixture.bank.manifest,
            &fixture.identity,
            block().target,
            claim(&fixture),
            reader,
            scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            BlsDoryWinningNonceReplayError::ModelBank(ModelBankError::Io(_))
        ));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn exact_accumulator_bound_is_inclusive() {
        let maximum = i64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS);
        validate_accumulator_bound(&[-maximum, maximum]).unwrap();
        assert!(validate_accumulator_bound(&[maximum + 1]).is_err());
        assert!(validate_accumulator_bound(&[-maximum - 1]).is_err());
    }

    #[test]
    fn cancellation_after_artifact_finalization_removes_the_authenticated_file() {
        let scratch = ScratchDirectory::create();
        let context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]],
            1,
            1,
            1,
            1,
            1,
        )
        .unwrap();
        let mut writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(scratch.path(), context).unwrap();
        writer
            .write_column_chunk(BlsDoryExecutionAccumulatorColumn::Initialization, &[0])
            .unwrap();
        writer
            .write_column_chunk(
                BlsDoryExecutionAccumulatorColumn::BankLayer { bank: 0, layer: 0 },
                &[0],
            )
            .unwrap();
        let error = finish_verified_execution(
            writer,
            BlsDoryWinningNonceClaim {
                nonce: 1,
                final_activation_digest: [0x55; 32],
                work_digest: [0x66; 32],
            },
            [0x55; 32],
            [0x66; 32],
            &AtomicBool::new(true),
        )
        .err()
        .unwrap();
        assert!(matches!(error, BlsDoryWinningNonceReplayError::Cancelled));
        assert_eq!(scratch.entry_count(), 0);
    }

    struct CancellingReader<'a> {
        inner: Cursor<Vec<u8>>,
        cancel: &'a AtomicBool,
        cancel_after: u64,
    }

    impl Read for CancellingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(buffer)?;
            if self.inner.position() >= self.cancel_after {
                self.cancel.store(true, Ordering::Relaxed);
            }
            Ok(read)
        }
    }

    #[test]
    fn midstream_cancellation_removes_partial_artifact() {
        let fixture = replay_fixture();
        let scratch = ScratchDirectory::create();
        let cancel = AtomicBool::new(false);
        let reader = CancellingReader {
            inner: Cursor::new(fixture.bank.bytes.clone()),
            cancel: &cancel,
            cancel_after: (crate::MODEL_BANK_HEADER_BYTES as u64)
                + fixture.bank.manifest.base_input_bytes,
        };
        let error = replay_winning_nonce_from_verified_bank(
            fixture.context,
            &fixture.bank.manifest,
            &fixture.identity,
            block().target,
            claim(&fixture),
            reader,
            scratch.path(),
            &cancel,
        )
        .err()
        .unwrap();
        assert!(matches!(error, BlsDoryWinningNonceReplayError::Cancelled));
        assert_eq!(scratch.entry_count(), 0);
    }

    const DORY_V3_TEST_VARIABLES: usize = 3;
    const DORY_V3_TEST_BASE: [u8; 4] = [125, 126, 124, 127];
    const DORY_V3_TEST_LAYERS: [[u8; 4]; 4] = [
        [126, 125, 124, 127],
        [124, 126, 125, 123],
        [127, 124, 126, 125],
        [125, 123, 127, 124],
    ];
    type DoryV3MaterializedMatrixBanks = ([Vec<i64>; 2], [Vec<i64>; 2], [Vec<i64>; 2]);

    struct DoryV3ReplayFixture {
        bank: BuiltModelBankFixture,
        authenticated: BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: DeterministicBlsDorySetup,
        transcript: DoryV3TranscriptContext,
        block: BlockChallenge,
        claim: BlsDoryV3WinningNonceClaim,
        base: Vec<u8>,
        final_activation: Vec<u8>,
        expected_accumulators: Vec<Vec<i32>>,
    }

    fn commit_dory_v3_test_bytes(bytes: &[u8], setup: &DeterministicBlsDorySetup) -> BlsDoryGt {
        let mut coefficients = bytes
            .iter()
            .map(|value| BlsDoryFr::from_i64(i64::from(*value) - 125))
            .collect::<Vec<_>>();
        coefficients.resize(1 << DORY_V3_TEST_VARIABLES, BlsDoryFr::from_i64(0));
        commit_bls_dory_polynomial(
            coefficients,
            DORY_V3_TEST_VARIABLES / 2,
            DORY_V3_TEST_VARIABLES - DORY_V3_TEST_VARIABLES / 2,
            setup,
        )
        .unwrap()
        .commitment()
    }

    fn dory_v3_test_identity(
        manifest: &ModelBankManifest,
        setup: &DeterministicBlsDorySetup,
        base: &[u8],
        layers: &[Vec<u8>],
    ) -> DoryV3ModelIdentityV1 {
        let encoded = |commitment| {
            CanonicalBlsDoryGtHex::from_commitment(commitment)
                .unwrap()
                .to_hex()
                .unwrap()
        };
        let weight_bank_commitments = layers
            .chunks_exact(2)
            .map(|bank| {
                let bytes = bank.iter().flatten().copied().collect::<Vec<_>>();
                encoded(commit_dory_v3_test_bytes(&bytes, setup))
            })
            .collect::<Vec<_>>();
        serde_json::from_value(json!({
            "identity_version": DORY_V3_MODEL_IDENTITY_VERSION,
            "model_version": 2,
            "batch": 2,
            "dimension": 2,
            "layers_per_bank": 2,
            "model_byte_root": manifest.raw_blake3_root,
            "layer_roots_aggregate": manifest.layer_roots_aggregate,
            "suite_parameter_digest": DORY_V3_PRODUCTION_SUITE_DIGEST.into_bytes(),
            "setup_identity": setup.identity(),
            "padded_variables": DORY_V3_TEST_VARIABLES,
            "base_input_commitment": encoded(commit_dory_v3_test_bytes(base, setup)),
            "weight_bank_commitments": weight_bank_commitments,
        }))
        .unwrap()
    }

    fn evaluate_dory_v3_test_reference(
        base: &[u8],
        layers: &[Vec<u8>],
        transcript: DoryV3TranscriptContext,
        block: &BlockChallenge,
        nonce: u64,
    ) -> (BlsDoryV3WinningNonceClaim, Vec<u8>, Vec<Vec<i32>>) {
        let challenge = transcript.challenge_context(block, nonce).unwrap();
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows: 2,
            cols: 2,
            max_abs_accumulator: 125,
            max_mask: MAX_TRANSITION_MASK,
        };
        let initialization_mask =
            StructuredMaskPolynomial::from_dory_v3_virtual_challenge(&challenge.digest(), 2, 2)
                .unwrap();
        let mut activations = base
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let accumulator = i64::from(*value) - 125;
                let mask = initialization_mask
                    .value_at_boolean_index_prevalidated(initialization_statement, index)
                    .unwrap();
                i8::try_from(
                    derive_transition_regular_row_from_mask(
                        initialization_statement,
                        index,
                        accumulator,
                        mask,
                    )
                    .unwrap()
                    .activation,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let transition_statement = StructuredTransitionStatement {
            layers: 2,
            rows: 2,
            cols: 2,
            max_abs_accumulator: u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS),
            max_mask: MAX_TRANSITION_MASK,
        };
        let mut expected_accumulators = Vec::new();
        for (bank, bank_layers) in layers.chunks_exact(2).enumerate() {
            let mask = StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
                &challenge.digest(),
                u32::try_from(bank * 2).unwrap(),
                2,
                2,
                2,
            )
            .unwrap();
            for (layer, weights) in bank_layers.iter().enumerate() {
                let accumulators = (0..4)
                    .map(|cell| {
                        let row = cell / 2;
                        let column = cell % 2;
                        (0..2)
                            .map(|common| {
                                i64::from(activations[row * 2 + common])
                                    * (i64::from(weights[common * 2 + column]) - 125)
                            })
                            .sum::<i64>()
                    })
                    .collect::<Vec<_>>();
                activations = accumulators
                    .iter()
                    .enumerate()
                    .map(|(cell, accumulator)| {
                        let index = layer * 4 + cell;
                        let mask = mask
                            .value_at_boolean_index_prevalidated(transition_statement, index)
                            .unwrap();
                        i8::try_from(
                            derive_transition_regular_row_from_mask(
                                transition_statement,
                                index,
                                *accumulator,
                                mask,
                            )
                            .unwrap()
                            .activation,
                        )
                        .unwrap()
                    })
                    .collect();
                expected_accumulators.push(
                    accumulators
                        .into_iter()
                        .map(|value| i32::try_from(value).unwrap())
                        .collect(),
                );
            }
        }
        let final_activation = activations
            .iter()
            .map(|value| u8::try_from(i16::from(*value) + 125).unwrap())
            .collect::<Vec<_>>();
        let final_activation_digest = challenge.output_digest_for_test(&final_activation).unwrap();
        (
            BlsDoryV3WinningNonceClaim {
                nonce,
                final_activation_digest,
                work_digest: challenge.work_digest(final_activation_digest),
            },
            final_activation,
            expected_accumulators,
        )
    }

    fn dory_v3_replay_fixture(tweak: u8) -> DoryV3ReplayFixture {
        let mut base = DORY_V3_TEST_BASE.to_vec();
        base[3] += tweak;
        let layers = DORY_V3_TEST_LAYERS.map(Vec::from).to_vec();
        let layer_slices = layers.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let suite = DORY_V3_PRODUCTION_SUITE_DIGEST.into_bytes();
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: [0x52; 32],
        })
        .unwrap();
        let setup = deterministic_bls_dory_setup(DORY_V3_TEST_VARIABLES).unwrap();
        let identity = dory_v3_test_identity(&provisional.manifest, &setup, &base, &layers);
        let bank = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        let authenticated = derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test(
            Cursor::new(&bank.bytes),
            &bank.manifest,
            &identity,
            &setup,
        )
        .unwrap();
        let block = block();
        let transcript = DoryV3TranscriptContext::from_bank_authenticated_record(
            block.network_id,
            &authenticated,
        )
        .unwrap();
        let (claim, final_activation, expected_accumulators) =
            evaluate_dory_v3_test_reference(&base, &layers, transcript, &block, 9);
        DoryV3ReplayFixture {
            bank,
            authenticated,
            setup,
            transcript,
            block,
            claim,
            base,
            final_activation,
            expected_accumulators,
        }
    }

    fn replay_dory_v3(
        fixture: &DoryV3ReplayFixture,
        scratch: &ScratchDirectory,
    ) -> VerifiedBlsDoryV3WinningNonceExecution {
        replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &fixture.block,
            fixture.claim,
            &fixture.setup,
            Cursor::new(&fixture.bank.bytes),
            scratch.path(),
            &AtomicBool::new(false),
        )
        .unwrap()
    }

    fn dory_v3_matrix_statement_for_test() -> StructuredMatrixStatement {
        StructuredMatrixStatement {
            layers: 2,
            rows: 2,
            inner: 2,
            cols: 2,
            max_abs_activation: 125,
            max_abs_weight: 125,
            max_abs_accumulator: u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS),
        }
    }

    fn dory_v3_transition_activations_for_test(
        statement: StructuredTransitionStatement,
        mask: &StructuredMaskPolynomial,
        layer: usize,
        accumulators: &[i64],
    ) -> Vec<i64> {
        let cells = statement.rows * statement.cols;
        accumulators
            .iter()
            .copied()
            .enumerate()
            .map(|(cell, accumulator)| {
                let index = layer * cells + cell;
                let mask_value = mask
                    .value_at_boolean_index_prevalidated(statement, index)
                    .unwrap();
                derive_transition_regular_row_from_mask(statement, index, accumulator, mask_value)
                    .unwrap()
                    .activation
            })
            .collect()
    }

    fn materialized_dory_v3_matrix_banks(
        fixture: &DoryV3ReplayFixture,
    ) -> DoryV3MaterializedMatrixBanks {
        let challenge = fixture
            .transcript
            .challenge_context(&fixture.block, fixture.claim.nonce)
            .unwrap();
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows: 2,
            cols: 2,
            max_abs_accumulator: 125,
            max_mask: MAX_TRANSITION_MASK,
        };
        let transition_statement = StructuredTransitionStatement {
            layers: 2,
            rows: 2,
            cols: 2,
            max_abs_accumulator: u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS),
            max_mask: MAX_TRANSITION_MASK,
        };
        let initialization_mask =
            StructuredMaskPolynomial::from_dory_v3_virtual_challenge(&challenge.digest(), 2, 2)
                .unwrap();
        let mut activation = dory_v3_transition_activations_for_test(
            initialization_statement,
            &initialization_mask,
            0,
            &fixture
                .base
                .iter()
                .map(|value| i64::from(*value) - 125)
                .collect::<Vec<_>>(),
        );
        let mut activations = std::array::from_fn(|_| Vec::new());
        let mut weights = std::array::from_fn(|_| Vec::new());
        let mut accumulators = std::array::from_fn(|_| Vec::new());
        for (global_layer, layer_weights) in DORY_V3_TEST_LAYERS.iter().enumerate() {
            let bank = global_layer / 2;
            let layer = global_layer % 2;
            activations[bank].extend_from_slice(&activation);
            weights[bank].extend(layer_weights.iter().map(|weight| i64::from(*weight) - 125));
            let layer_accumulators = fixture.expected_accumulators[global_layer]
                .iter()
                .copied()
                .map(i64::from)
                .collect::<Vec<_>>();
            accumulators[bank].extend_from_slice(&layer_accumulators);
            let mask = StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
                &challenge.digest(),
                u32::try_from(bank * 2).unwrap(),
                2,
                2,
                2,
            )
            .unwrap();
            activation = dory_v3_transition_activations_for_test(
                transition_statement,
                &mask,
                layer,
                &layer_accumulators,
            );
        }
        (activations, weights, accumulators)
    }

    #[test]
    fn dory_v3_streamed_matrix_banks_match_independent_materialized_proofs() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let statement = dory_v3_matrix_statement_for_test();
        let (activations, weights, accumulators) = materialized_dory_v3_matrix_banks(&fixture);
        let mut execution = replay_dory_v3(&fixture, &scratch);

        for bank in 0..2 {
            let binding = format!("dory-v3-streamed-matrix-bank-{bank}");
            let weight = commit_bls_dory_polynomial(
                weights[bank]
                    .iter()
                    .copied()
                    .map(BlsDoryFr::from_i64)
                    .collect(),
                1,
                2,
                &fixture.setup,
            )
            .unwrap();
            let materialized = prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch(
                binding.as_bytes(),
                statement,
                &activations[bank],
                &weight,
                &accumulators[bank],
                DORY_V3_TEST_VARIABLES,
                &fixture.setup,
                scratch.path(),
            )
            .unwrap();
            let streamed = {
                let mut reader = execution
                    .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                    .unwrap();
                prove_bls_dory_matrix_deferred_with_precommitted_weight_from_dory_v3_execution_reader_and_scratch(
                    binding.as_bytes(),
                    &weight,
                    &mut reader,
                    bank,
                    DORY_V3_TEST_VARIABLES,
                    &fixture.setup,
                    scratch.path(),
                )
                .unwrap()
            };

            assert_eq!(streamed.proof, materialized.proof);
            assert_eq!(
                streamed.proof.encode_deferred(statement).unwrap(),
                materialized.proof.encode_deferred(statement).unwrap()
            );
            assert_eq!(
                streamed.proof.transcript_digest,
                materialized.proof.transcript_digest
            );
            assert_eq!(
                streamed.proof.activation_commitment,
                materialized.proof.activation_commitment
            );
            assert_eq!(
                streamed.proof.weight_commitment,
                materialized.proof.weight_commitment
            );
            assert_eq!(
                streamed.proof.accumulator_commitment,
                materialized.proof.accumulator_commitment
            );
            assert_eq!(streamed.openings.claims(), materialized.openings.claims());
            drop((streamed, materialized, weight));
        }

        let challenge = fixture
            .transcript
            .challenge_context(&fixture.block, fixture.claim.nonce)
            .unwrap();
        let v3_virtual =
            StructuredMaskPolynomial::from_dory_v3_virtual_challenge(&challenge.digest(), 2, 2)
                .unwrap();
        let v2_virtual =
            StructuredMaskPolynomial::from_virtual_challenge(&challenge.digest(), 2, 2).unwrap();
        let v3_later = StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
            &challenge.digest(),
            2,
            2,
            2,
            2,
        )
        .unwrap();
        let v2_later = StructuredMaskPolynomial::from_challenge_at_layer_offset(
            &challenge.digest(),
            2,
            2,
            2,
            2,
        )
        .unwrap();
        assert_ne!(v3_virtual, v2_virtual);
        assert_ne!(v3_later, v2_later);

        let correct_weight = commit_bls_dory_polynomial(
            weights[0]
                .iter()
                .copied()
                .map(BlsDoryFr::from_i64)
                .collect(),
            1,
            2,
            &fixture.setup,
        )
        .unwrap();
        let short_weight = commit_bls_dory_padded_prefix_with_optional_scratch(
            &weights[0][..4]
                .iter()
                .copied()
                .map(BlsDoryFr::from_i64)
                .collect::<Vec<_>>(),
            1,
            2,
            &fixture.setup,
            Some(scratch.path()),
        )
        .unwrap();
        let substituted_setup = deterministic_bls_dory_setup(DORY_V3_TEST_VARIABLES + 1).unwrap();
        let wrong_setup_weight = commit_bls_dory_polynomial(
            weights[0]
                .iter()
                .copied()
                .map(BlsDoryFr::from_i64)
                .collect(),
            1,
            2,
            &substituted_setup,
        )
        .unwrap();
        let preflight_scratch = ScratchDirectory::create();
        let unavailable_scratch = preflight_scratch.path().join("not-created");
        {
            let mut reader = execution
                .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                .unwrap();
            assert!(matches!(
                prove_bls_dory_matrix_deferred_with_precommitted_weight_from_dory_v3_execution_reader_and_scratch(
                    b"wrong-bank",
                    &correct_weight,
                    &mut reader,
                    2,
                    DORY_V3_TEST_VARIABLES,
                    &fixture.setup,
                    scratch.path(),
                ),
                Err(BlsDoryMatrixError::ExecutionArtifact)
            ));
            assert!(matches!(
                prove_bls_dory_matrix_deferred_with_precommitted_weight_from_dory_v3_execution_reader_and_scratch(
                    b"wrong-setup",
                    &correct_weight,
                    &mut reader,
                    0,
                    DORY_V3_TEST_VARIABLES,
                    &substituted_setup,
                    scratch.path(),
                ),
                Err(BlsDoryMatrixError::ExecutionArtifact)
            ));
            assert!(matches!(
                prove_bls_dory_matrix_deferred_with_precommitted_weight_from_dory_v3_execution_reader_and_scratch(
                    b"wrong-weight-length",
                    &short_weight,
                    &mut reader,
                    0,
                    DORY_V3_TEST_VARIABLES,
                    &fixture.setup,
                    scratch.path(),
                ),
                Err(BlsDoryMatrixError::Structured(
                    StructuredSumcheckError::InvalidLength
                ))
            ));
            assert!(matches!(
                prove_bls_dory_matrix_deferred_with_precommitted_weight_from_dory_v3_execution_reader_and_scratch(
                    b"wrong-weight-setup",
                    &wrong_setup_weight,
                    &mut reader,
                    0,
                    DORY_V3_TEST_VARIABLES,
                    &fixture.setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryMatrixError::InvalidDimensions)
            ));
        }
        assert_eq!(preflight_scratch.entry_count(), 0);
        drop((short_weight, wrong_setup_weight, correct_weight));
        drop(execution);
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_replay_authenticates_exact_accumulators_and_output() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let execution = replay_dory_v3(&fixture, &scratch);
        assert_eq!(execution.nonce(), fixture.claim.nonce);
        assert_eq!(
            execution.final_activation_digest(),
            fixture.claim.final_activation_digest
        );
        assert_eq!(execution.work_digest(), fixture.claim.work_digest);

        let (context, _, _, _, mut artifact) = execution.into_parts();
        assert_eq!(artifact.context(), *context.raw());
        let mut actual = vec![0i32; 4];
        artifact
            .read_column_segment(
                BlsDoryExecutionAccumulatorColumn::Initialization,
                0,
                &mut actual,
            )
            .unwrap();
        assert_eq!(
            actual,
            fixture
                .base
                .iter()
                .map(|value| i32::from(*value) - 125)
                .collect::<Vec<_>>()
        );
        for bank in 0..2 {
            for layer in 0..2 {
                artifact
                    .read_column_segment(
                        BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
                        0,
                        &mut actual,
                    )
                    .unwrap();
                assert_eq!(actual, fixture.expected_accumulators[bank * 2 + layer]);
            }
        }
        let wrong = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [
                fixture.block.network_id,
                fixture.authenticated.record().record_digest().into_bytes(),
                fixture.setup.identity(),
                [0x99; 32],
            ],
            2,
            2,
            2,
            2,
            4,
        )
        .unwrap();
        assert!(matches!(
            artifact.authenticate(&wrong),
            Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext)
        ));
        drop(artifact);
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_artifact_reader_derives_exact_masks_reads_segments_and_verifies_output() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let challenge = fixture
            .transcript
            .challenge_context(&fixture.block, fixture.claim.nonce)
            .unwrap();
        let mut execution = replay_dory_v3(&fixture, &scratch);
        let mut reader = execution
            .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
            .unwrap();

        assert_eq!(reader.nonce(), fixture.claim.nonce);
        assert_eq!(
            reader.final_activation_digest(),
            fixture.claim.final_activation_digest
        );
        assert_eq!(reader.work_digest(), fixture.claim.work_digest);
        assert_eq!(reader.canonical_rows(), 2);
        assert_eq!(reader.canonical_columns(), 2);
        assert_eq!(reader.banks(), 2);
        assert_eq!(reader.layers_per_bank(), 2);
        assert_eq!(reader.cells_per_column(), 4);
        assert_eq!(reader.authentication_chunk_cells(), 4);
        reader.validate_setup(&fixture.setup).unwrap();

        let initialization = reader.v3_initialization_mask().unwrap();
        assert_eq!(
            initialization,
            StructuredMaskPolynomial::from_dory_v3_virtual_challenge(&challenge.digest(), 2, 2)
                .unwrap()
        );
        assert_ne!(
            initialization,
            StructuredMaskPolynomial::from_virtual_challenge(&challenge.digest(), 2, 2).unwrap()
        );
        for (bank, first_layer) in [0, 2].into_iter().enumerate() {
            let mask = reader.v3_bank_mask(bank).unwrap();
            assert_eq!(
                mask,
                StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
                    &challenge.digest(),
                    first_layer,
                    2,
                    2,
                    2,
                )
                .unwrap()
            );
            assert_ne!(
                mask,
                StructuredMaskPolynomial::from_challenge_at_layer_offset(
                    &challenge.digest(),
                    first_layer,
                    2,
                    2,
                    2,
                )
                .unwrap()
            );
        }

        let mut initialization_segment = [0_i32; 2];
        assert_eq!(
            reader
                .read_initialization_segment(1, &mut initialization_segment)
                .unwrap(),
            2
        );
        assert_eq!(initialization_segment, [1, -1]);
        let mut layer_segment = [0_i32; 2];
        assert_eq!(
            reader
                .read_bank_layer_segment(1, 1, 1, &mut layer_segment)
                .unwrap(),
            2
        );
        assert_eq!(layer_segment, fixture.expected_accumulators[3][1..3]);
        reader
            .verify_final_activation(&fixture.final_activation)
            .unwrap();

        drop(execution);
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_artifact_reader_rejects_authority_output_role_and_bounds_substitution() {
        let fixture = dory_v3_replay_fixture(0);
        let other = dory_v3_replay_fixture(1);
        let scratch = ScratchDirectory::create();

        let mut wrong_record = replay_dory_v3(&fixture, &scratch);
        assert!(matches!(
            wrong_record.authenticated_artifact_reader(&other.authenticated, &other.setup),
            Err(BlsDoryV3WinningNonceReplayError::ExecutionArtifact(
                BlsDoryExecutionAccumulatorArtifactError::WrongContext
            ))
        ));

        let mut wrong_setup = replay_dory_v3(&fixture, &scratch);
        let substituted_setup = deterministic_bls_dory_setup(DORY_V3_TEST_VARIABLES + 1).unwrap();
        assert!(matches!(
            wrong_setup.authenticated_artifact_reader(&fixture.authenticated, &substituted_setup),
            Err(BlsDoryV3WinningNonceReplayError::ExecutionArtifact(
                BlsDoryExecutionAccumulatorArtifactError::WrongContext
            ))
        ));

        let mut wrong_work = replay_dory_v3(&fixture, &scratch);
        wrong_work.work_digest[0] ^= 1;
        assert!(matches!(
            wrong_work.authenticated_artifact_reader(&fixture.authenticated, &fixture.setup),
            Err(BlsDoryV3WinningNonceReplayError::WorkDigest)
        ));

        let mut wrong_artifact = replay_dory_v3(&fixture, &scratch);
        let mut substituted_artifact = replay_dory_v3(&other, &scratch);
        std::mem::swap(
            &mut wrong_artifact.artifact,
            &mut substituted_artifact.artifact,
        );
        assert!(matches!(
            wrong_artifact.authenticated_artifact_reader(&fixture.authenticated, &fixture.setup),
            Err(BlsDoryV3WinningNonceReplayError::ExecutionArtifact(
                BlsDoryExecutionAccumulatorArtifactError::WrongContext
            ))
        ));

        let mut execution = replay_dory_v3(&fixture, &scratch);
        let mut reader = execution
            .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
            .unwrap();
        assert!(matches!(
            reader.validate_setup(&substituted_setup),
            Err(BlsDoryV3WinningNonceReplayError::ExecutionArtifact(
                BlsDoryExecutionAccumulatorArtifactError::WrongContext
            ))
        ));
        assert!(matches!(
            reader.v3_bank_mask(2),
            Err(BlsDoryV3WinningNonceReplayError::ModelShape)
        ));
        assert!(matches!(
            reader.read_bank_layer_segment(2, 0, 0, &mut [0]),
            Err(BlsDoryV3WinningNonceReplayError::ModelShape)
        ));
        assert!(matches!(
            reader.read_bank_layer_segment(0, 2, 0, &mut [0]),
            Err(BlsDoryV3WinningNonceReplayError::ModelShape)
        ));
        assert!(matches!(
            reader.read_initialization_segment(4, &mut [0]),
            Err(BlsDoryV3WinningNonceReplayError::ModelShape)
        ));
        assert!(matches!(
            reader.read_initialization_segment(0, &mut []),
            Err(BlsDoryV3WinningNonceReplayError::ModelShape)
        ));
        let mut changed_activation = fixture.final_activation.clone();
        changed_activation[0] ^= 1;
        assert!(matches!(
            reader.verify_final_activation(&changed_activation),
            Err(BlsDoryV3WinningNonceReplayError::FinalActivationDigest)
        ));
        assert!(matches!(
            reader.verify_final_activation(&fixture.final_activation[..3]),
            Err(BlsDoryV3WinningNonceReplayError::ModelShape)
        ));

        drop((
            execution,
            wrong_record,
            wrong_setup,
            wrong_work,
            wrong_artifact,
            substituted_artifact,
        ));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_replay_uses_exact_v3_virtual_and_global_bank_offsets() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let challenge = fixture
            .transcript
            .challenge_context(&fixture.block, fixture.claim.nonce)
            .unwrap();
        let context = BlsDoryV3ExecutionAccumulatorArtifactContext::for_test(
            challenge,
            &fixture.authenticated,
            &fixture.setup,
        )
        .unwrap();
        let cancel = AtomicBool::new(false);
        let sink = DoryV3WinningNonceReplaySink::new(
            context,
            fixture.bank.manifest,
            fixture.claim,
            scratch.path(),
            &cancel,
        )
        .unwrap();
        assert_eq!(
            sink.initialization_mask,
            StructuredMaskPolynomial::from_dory_v3_virtual_challenge(&challenge.digest(), 2, 2)
                .unwrap()
        );
        for (bank, offset) in [0, 2].into_iter().enumerate() {
            assert_eq!(
                sink.transition_masks[bank],
                StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
                    &challenge.digest(),
                    offset,
                    2,
                    2,
                    2,
                )
                .unwrap()
            );
        }
        assert_ne!(
            sink.initialization_mask,
            StructuredMaskPolynomial::from_virtual_challenge(&challenge.digest(), 2, 2).unwrap()
        );
        assert_ne!(
            sink.transition_masks[0],
            StructuredMaskPolynomial::from_challenge_at_layer_offset(
                &challenge.digest(),
                0,
                2,
                2,
                2,
            )
            .unwrap()
        );
        drop(sink);
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_claim_failures_precede_model_reads() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let run =
            |block: &BlockChallenge, claim: BlsDoryV3WinningNonceClaim, cancel: &AtomicBool| {
                replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
                    &fixture.authenticated,
                    fixture.transcript,
                    block,
                    claim,
                    &fixture.setup,
                    PanicReader,
                    scratch.path(),
                    cancel,
                )
                .err()
                .unwrap()
            };

        let mut bad_work = fixture.claim;
        bad_work.work_digest[0] ^= 1;
        assert!(matches!(
            run(&fixture.block, bad_work, &AtomicBool::new(false)),
            BlsDoryV3WinningNonceReplayError::WorkDigest
        ));
        let mut stale_nonce = fixture.claim;
        stale_nonce.nonce += 1;
        assert!(matches!(
            run(&fixture.block, stale_nonce, &AtomicBool::new(false)),
            BlsDoryV3WinningNonceReplayError::WorkDigest
        ));
        assert!(matches!(
            run(&fixture.block, fixture.claim, &AtomicBool::new(true)),
            BlsDoryV3WinningNonceReplayError::Cancelled
        ));

        let mut high_block = fixture.block;
        high_block.target = [0; 32];
        let high_challenge = fixture
            .transcript
            .challenge_context(&high_block, fixture.claim.nonce)
            .unwrap();
        let high_claim = BlsDoryV3WinningNonceClaim {
            nonce: fixture.claim.nonce,
            final_activation_digest: fixture.claim.final_activation_digest,
            work_digest: high_challenge.work_digest(fixture.claim.final_activation_digest),
        };
        assert_ne!(high_claim.work_digest, [0; 32]);
        assert!(matches!(
            run(&high_block, high_claim, &AtomicBool::new(false)),
            BlsDoryV3WinningNonceReplayError::HighHash
        ));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_record_and_setup_mismatches_precede_model_reads() {
        let fixture = dory_v3_replay_fixture(0);
        let other = dory_v3_replay_fixture(1);
        let scratch = ScratchDirectory::create();
        let record_error = replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
            &other.authenticated,
            fixture.transcript,
            &fixture.block,
            fixture.claim,
            &other.setup,
            PanicReader,
            scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(
            record_error,
            BlsDoryV3WinningNonceReplayError::Context
        ));

        let wrong_setup = deterministic_bls_dory_setup(DORY_V3_TEST_VARIABLES + 1).unwrap();
        let setup_error = replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &fixture.block,
            fixture.claim,
            &wrong_setup,
            PanicReader,
            scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(
            setup_error,
            BlsDoryV3WinningNonceReplayError::ExecutionArtifact(
                BlsDoryExecutionAccumulatorArtifactError::WrongContext
            )
        ));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_false_output_and_malformed_banks_fail_closed_and_clean_up() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let challenge = fixture
            .transcript
            .challenge_context(&fixture.block, fixture.claim.nonce)
            .unwrap();
        let false_digest = [0xa5; 32];
        let false_claim = BlsDoryV3WinningNonceClaim {
            nonce: fixture.claim.nonce,
            final_activation_digest: false_digest,
            work_digest: challenge.work_digest(false_digest),
        };
        let false_error = replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &fixture.block,
            false_claim,
            &fixture.setup,
            Cursor::new(&fixture.bank.bytes),
            scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(
            false_error,
            BlsDoryV3WinningNonceReplayError::FinalActivationDigest
        ));
        assert_eq!(scratch.entry_count(), 0);

        let mut corrupt = fixture.bank.bytes.clone();
        corrupt[crate::MODEL_BANK_HEADER_BYTES] ^= 1;
        let mut truncated = fixture.bank.bytes.clone();
        truncated.pop();
        let mut trailing = fixture.bank.bytes.clone();
        trailing.push(0);
        for (bytes, expected) in [
            (corrupt, "root"),
            (truncated, "truncated"),
            (trailing, "trailing"),
        ] {
            let error = replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
                &fixture.authenticated,
                fixture.transcript,
                &fixture.block,
                fixture.claim,
                &fixture.setup,
                Cursor::new(bytes),
                scratch.path(),
                &AtomicBool::new(false),
            )
            .err()
            .unwrap();
            match expected {
                "root" => assert!(matches!(
                    error,
                    BlsDoryV3WinningNonceReplayError::ModelBank(ModelBankError::RawRootMismatch)
                )),
                "truncated" => assert!(matches!(
                    error,
                    BlsDoryV3WinningNonceReplayError::ModelBank(ModelBankError::Truncated)
                )),
                "trailing" => assert!(matches!(
                    error,
                    BlsDoryV3WinningNonceReplayError::ModelBank(ModelBankError::TrailingBytes)
                )),
                _ => unreachable!(),
            }
            assert_eq!(scratch.entry_count(), 0);
        }
    }

    #[test]
    fn dory_v3_reader_failure_removes_partial_artifact() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let reader = FailingReader {
            inner: Cursor::new(fixture.bank.bytes.clone()),
            fail_at: crate::MODEL_BANK_HEADER_BYTES as u64
                + fixture.bank.manifest.base_input_bytes
                + 2,
        };
        let error = replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &fixture.block,
            fixture.claim,
            &fixture.setup,
            reader,
            scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            BlsDoryV3WinningNonceReplayError::ModelBank(ModelBankError::Io(_))
        ));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_midstream_cancellation_removes_partial_artifact() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let cancel = AtomicBool::new(false);
        let reader = CancellingReader {
            inner: Cursor::new(fixture.bank.bytes.clone()),
            cancel: &cancel,
            cancel_after: (crate::MODEL_BANK_HEADER_BYTES as u64)
                + fixture.bank.manifest.base_input_bytes,
        };
        let error = replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &fixture.block,
            fixture.claim,
            &fixture.setup,
            reader,
            scratch.path(),
            &cancel,
        )
        .err()
        .unwrap();
        assert!(matches!(error, BlsDoryV3WinningNonceReplayError::Cancelled));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_cancellation_after_artifact_finalization_removes_the_file() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let challenge = fixture
            .transcript
            .challenge_context(&fixture.block, fixture.claim.nonce)
            .unwrap();
        let context = BlsDoryV3ExecutionAccumulatorArtifactContext::for_test(
            challenge,
            &fixture.authenticated,
            &fixture.setup,
        )
        .unwrap();
        let mut writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(scratch.path(), *context.raw())
                .unwrap();
        writer
            .write_column_chunk(BlsDoryExecutionAccumulatorColumn::Initialization, &[0; 4])
            .unwrap();
        for bank in 0..2 {
            for layer in 0..2 {
                writer
                    .write_column_chunk(
                        BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
                        &[0; 4],
                    )
                    .unwrap();
            }
        }
        let error = finish_verified_dory_v3_execution(
            writer,
            context,
            fixture.claim,
            fixture.claim.final_activation_digest,
            fixture.claim.work_digest,
            &AtomicBool::new(true),
        )
        .err()
        .unwrap();
        assert!(matches!(error, BlsDoryV3WinningNonceReplayError::Cancelled));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_replay_is_deterministic_across_thread_counts() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let one = ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap()
            .install(|| replay_dory_v3(&fixture, &scratch));
        let many = ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap()
            .install(|| replay_dory_v3(&fixture, &scratch));
        let (_, _, _, _, one_artifact) = one.into_parts();
        let (_, _, _, _, many_artifact) = many.into_parts();
        assert_eq!(one_artifact.root_digest(), many_artifact.root_digest());
        assert_eq!(one_artifact.digest(), many_artifact.digest());
        drop((one_artifact, many_artifact));
        assert_eq!(scratch.entry_count(), 0);
    }
}
