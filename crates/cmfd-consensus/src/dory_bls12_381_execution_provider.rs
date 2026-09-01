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
#[cfg(any(feature = "dory-v3-consensus-adapter", test))]
use std::time::Instant;

use rayon::prelude::*;
use thiserror::Error;

use crate::{
    BlockChallenge, ForgeMatrixV3CandidateProof,
    dory_bls12_381_aggregate::BlsDoryAggregateError,
    dory_bls12_381_blake3::prepare_production_dory_v3_native_blake3_opening_with_cancel,
    dory_bls12_381_candidate::{
        BlsDoryV3CandidateError, BlsDoryV3CandidatePayload,
        validate_dory_v3_layout_v5_record_setup_binding,
    },
    dory_bls12_381_execution_artifact::{
        BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS, BlsDoryExecutionAccumulatorArtifact,
        BlsDoryExecutionAccumulatorArtifactContext, BlsDoryExecutionAccumulatorArtifactError,
        BlsDoryExecutionAccumulatorArtifactWriter, BlsDoryExecutionAccumulatorColumn,
    },
    dory_bls12_381_layout::{
        BlsDoryPreparedFixedModelV5, BlsDorySharedLayoutError, BlsDorySharedLayoutV5Context,
        BlsDorySharedLayoutV5Proof, PreparedBlsDorySharedLayoutV5ProverState,
        ValidatedBlsDorySharedLayoutV5ExecutionPreparation,
        finish_prepared_bls_dory_shared_layout_v5_with_dory_v3_native_opening_and_cancel,
        preflight_bls_dory_shared_layout_v5_execution_preparation,
        preflight_prepared_bls_dory_shared_layout_v5_composition, signed_model_value,
    },
    dory_bls12_381_logup::{
        BLS_DORY_RANGE_LOGUP_TABLE_VALUES,
        prove_bls_dory_range_logup_deferred_with_precommitted_compact_transition_and_scratch_and_cancel,
    },
    dory_bls12_381_matrix::prove_bls_dory_matrix_deferred_with_precommitted_weight_from_dory_v3_execution_reader_and_scratch_and_cancel,
    dory_bls12_381_output_bridge::{BlsDoryOutputBridgeError, BlsDoryOutputBridgeStatement},
    dory_bls12_381_prototype::DeterministicBlsDorySetup,
    dory_bls12_381_transition::{
        BlsDoryTransitionError, derive_transition_regular_row_from_mask,
        prove_bls_dory_v3_small_range_logup_from_execution_reader_with_scratch_and_cancel,
        prove_bls_dory_v3_transition_deferred_from_execution_reader_with_scratch_and_cancel,
        regenerate_bls_dory_v3_transition_compact_source_from_execution_reader_with_scratch_and_cancel,
    },
    dory_bls12_381_wiring::prove_bls_dory_v3_wiring_deferred_from_execution_reader_with_scratch_and_cancel,
    dory_v3_model_record::BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    dory_v3_suite::{DORY_V3_ALGORITHM_VERSION, DORY_V3_PROOF_VERSION},
    dory_v3_transcript::{DoryV3ChallengeContext, DoryV3TranscriptContext, DoryV3TranscriptError},
    forgematrix_v2::{V2_MODEL_VALUE_CENTER, output_digest, work_digest_from_roots},
    model_bank::{
        ModelBankError, ModelBankFieldStreamError, ModelBankManifest, ModelFieldChunk,
        ModelPcsIdentity, ModelPcsRole, StagedModelFieldLayoutSink, StagedModelFieldSink,
        VerifiedModelBankLayoutReceipt, VerifiedModelBankReceipt,
        verify_model_bank_into_staged_field_layout_sink, verify_model_bank_into_staged_field_sink,
    },
    structured_proof::StructuredForgeMatrixResearchShape,
    structured_transition::{
        StructuredMaskPolynomial, StructuredTransitionError, StructuredTransitionStatement,
    },
};

#[cfg(any(feature = "dory-v3-consensus-adapter", test))]
use crate::{
    dory_bls12_381_candidate::verify_bls_dory_v3_layout_v5_candidate,
    dory_bls12_381_layout::prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch_and_cancel,
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
        // Keep bounded V3 fixtures genuinely streamed: one row per chunk
        // makes every multi-row layer cross an authentication boundary.
        let chunk_cells = columns;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlsDoryV3WinningNonceExpectation {
    Derive { nonce: u64 },
    Verify(BlsDoryV3WinningNonceClaim),
}

impl BlsDoryV3WinningNonceExpectation {
    const fn nonce(self) -> u64 {
        match self {
            Self::Derive { nonce } => nonce,
            Self::Verify(claim) => claim.nonce,
        }
    }

    fn resolve(
        self,
        final_activation_digest: [u8; 32],
        work_digest: [u8; 32],
    ) -> Result<BlsDoryV3WinningNonceClaim, BlsDoryV3WinningNonceReplayError> {
        let derived = BlsDoryV3WinningNonceClaim {
            nonce: self.nonce(),
            final_activation_digest,
            work_digest,
        };
        let Self::Verify(expected) = self else {
            return Ok(derived);
        };
        if derived.final_activation_digest != expected.final_activation_digest {
            return Err(BlsDoryV3WinningNonceReplayError::FinalActivationDigest);
        }
        if derived.work_digest != expected.work_digest {
            return Err(BlsDoryV3WinningNonceReplayError::WorkDigest);
        }
        Ok(derived)
    }
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
    const fn nonce(&self) -> u64 {
        self.nonce
    }

    const fn final_activation_digest(&self) -> [u8; 32] {
        self.final_activation_digest
    }

    const fn work_digest(&self) -> [u8; 32] {
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

/// Opaque authority for the canonical final activation of one verified V3
/// execution.
///
/// Only an authenticated execution-artifact reader can mint this capability.
/// The originating transcript context remains private and inseparable from the
/// canonical bytes and the two digests checked during reconstruction.
#[must_use]
#[allow(dead_code)]
pub(crate) struct VerifiedBlsDoryV3FinalActivation {
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    nonce: u64,
    activation: Box<[u8]>,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
}

#[allow(dead_code)]
impl VerifiedBlsDoryV3FinalActivation {
    const fn nonce(&self) -> u64 {
        self.nonce
    }

    fn as_bytes(&self) -> &[u8] {
        &self.activation
    }

    const fn final_activation_digest(&self) -> [u8; 32] {
        self.final_activation_digest
    }

    const fn work_digest(&self) -> [u8; 32] {
        self.work_digest
    }

    fn validate_native_composition_authority(
        &self,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDoryV3WinningNonceReplayError> {
        if self.context.raw().setup_identity() != setup.identity()
            || self.context.raw().challenge_identity() != self.context.challenge.digest()
        {
            return Err(BlsDoryV3WinningNonceReplayError::Context);
        }
        let final_activation_digest = self.context.output_digest(&self.activation)?;
        if final_activation_digest != self.final_activation_digest {
            return Err(BlsDoryV3WinningNonceReplayError::FinalActivationDigest);
        }
        if self.context.work_digest(final_activation_digest) != self.work_digest {
            return Err(BlsDoryV3WinningNonceReplayError::WorkDigest);
        }
        Ok(())
    }
}

/// Atomic output of one authenticated V3 replay and its matching Layout V5
/// preparation. The two capabilities cannot be split or substituted by a
/// caller; a future native-composition checkpoint will consume this value.
#[must_use]
#[allow(dead_code)]
pub(crate) struct PreparedBlsDoryV3LayoutV5Execution {
    prepared: PreparedBlsDorySharedLayoutV5ProverState,
    final_activation: VerifiedBlsDoryV3FinalActivation,
}

/// Opaque output of one atomic V3 execution, native BLAKE3 argument, and Layout
/// V5 aggregate. No raw proof pair or public-field getter is exposed.
#[must_use]
#[allow(dead_code)]
pub(crate) struct ComposedBlsDoryV3LayoutV5Execution {
    challenge: DoryV3ChallengeContext,
    nonce: u64,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
    proof: BlsDorySharedLayoutV5Proof,
    encoded_native_proof: Vec<u8>,
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
    const fn nonce(&self) -> u64 {
        self.nonce
    }

    const fn final_activation_digest(&self) -> [u8; 32] {
        self.final_activation_digest
    }

    const fn work_digest(&self) -> [u8; 32] {
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

    /// Reconstruct and authenticate the exact final activation retained by the
    /// final bank's final accumulator column.
    ///
    /// The bank, layer, transition statement, and V3 mask are all derived from
    /// the reader's private authority. A capability is returned only after
    /// every touched artifact chunk and both claimed digests authenticate.
    pub(crate) fn reconstruct_verified_final_activation(
        &mut self,
    ) -> Result<VerifiedBlsDoryV3FinalActivation, BlsDoryV3WinningNonceReplayError> {
        let final_bank = self
            .banks()
            .checked_sub(1)
            .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?;
        let final_layer = self
            .layers_per_bank()
            .checked_sub(1)
            .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?;
        let rows = self.canonical_rows();
        let cols = self.canonical_columns();
        let cells = rows
            .checked_mul(cols)
            .filter(|cells| *cells == self.cells_per_column())
            .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?;
        let statement = StructuredTransitionStatement {
            layers: self.layers_per_bank(),
            rows,
            cols,
            max_abs_accumulator: u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS),
            max_mask: MAX_TRANSITION_MASK,
        };
        statement.validate_verifier_shape()?;
        let mask = self.v3_bank_mask(final_bank)?;
        mask.validate(statement)?;

        let chunk_cells = self.authentication_chunk_cells();
        let mut accumulators = zeroed_dory_v3_vector(chunk_cells)?;
        let mut activation = reserved_dory_v3_vector(cells)?;
        let layer_offset = final_layer
            .checked_mul(cells)
            .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
        let mut start = 0usize;
        while start < cells {
            let take = cells.saturating_sub(start).min(chunk_cells);
            if take == 0 {
                return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
            }
            let read = self.read_bank_layer_segment(
                final_bank,
                final_layer,
                start,
                &mut accumulators[..take],
            )?;
            if read != take {
                return Err(BlsDoryV3WinningNonceReplayError::ExecutionArtifact(
                    BlsDoryExecutionAccumulatorArtifactError::InvalidShape,
                ));
            }
            for (offset, accumulator) in accumulators[..take].iter().copied().enumerate() {
                let index = layer_offset
                    .checked_add(start)
                    .and_then(|index| index.checked_add(offset))
                    .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
                let mask_value = mask.value_at_boolean_index_prevalidated(statement, index)?;
                let transition = derive_transition_regular_row_from_mask(
                    statement,
                    index,
                    i64::from(accumulator),
                    mask_value,
                )?;
                activation.push(encode_dory_v3_activation(transition.activation)?);
            }
            start = start
                .checked_add(take)
                .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
        }
        if activation.len() != cells {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        let (final_activation_digest, work_digest) =
            self.authenticate_final_activation(&activation)?;
        Ok(VerifiedBlsDoryV3FinalActivation {
            context: self.context,
            nonce: self.nonce,
            activation: activation.into_boxed_slice(),
            final_activation_digest,
            work_digest,
        })
    }

    fn authenticate_final_activation(
        &self,
        activation: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), BlsDoryV3WinningNonceReplayError> {
        if activation.len() != self.cells_per_column() {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        let final_activation_digest = self.context.output_digest(activation)?;
        if final_activation_digest != self.final_activation_digest {
            return Err(BlsDoryV3WinningNonceReplayError::FinalActivationDigest);
        }
        let work_digest = self.context.work_digest(final_activation_digest);
        if work_digest != self.work_digest {
            return Err(BlsDoryV3WinningNonceReplayError::WorkDigest);
        }
        Ok((final_activation_digest, work_digest))
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
pub enum BlsDoryV3WinningNonceReplayError {
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

#[derive(Debug, Error)]
#[allow(dead_code)]
pub(crate) enum BlsDoryV3LayoutV5PreparationError {
    #[error("verified Dory V3 execution failed authentication: {0}")]
    Replay(#[from] BlsDoryV3WinningNonceReplayError),
    #[error("Dory V3 Layout V5 preparation failed: {0}")]
    Layout(#[from] BlsDorySharedLayoutError),
}

#[derive(Debug, Error)]
#[allow(dead_code)]
pub(crate) enum BlsDoryV3LayoutV5CompositionError {
    #[error(
        "Dory V3 Layout V5 composition requires a nonzero row limit and existing absolute scratch directory"
    )]
    Configuration,
    #[error("Dory V3 Layout V5 retained execution authority failed: {0}")]
    ReplayAuthority(#[from] BlsDoryV3WinningNonceReplayError),
    #[error("Dory V3 Layout V5 output bridge failed: {0}")]
    OutputBridge(#[from] BlsDoryOutputBridgeError),
    #[error("Dory V3 native BLAKE3 proof failed: {0}")]
    Native(#[from] BlsDoryAggregateError),
    #[error("Dory V3 Layout V5 composition failed: {0}")]
    Layout(#[from] BlsDorySharedLayoutError),
}

fn validate_dory_v3_layout_v5_composition_configuration(
    scratch_directory: &Path,
    maximum_native_block_rows: usize,
) -> Result<(), BlsDoryV3LayoutV5CompositionError> {
    if maximum_native_block_rows == 0
        || !scratch_directory.is_absolute()
        || !scratch_directory.is_dir()
    {
        return Err(BlsDoryV3LayoutV5CompositionError::Configuration);
    }
    Ok(())
}

fn validated_dory_v3_layout_v5_output_bridge(
    execution: &PreparedBlsDoryV3LayoutV5Execution,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryOutputBridgeStatement, BlsDoryV3LayoutV5CompositionError> {
    execution
        .final_activation
        .validate_native_composition_authority(setup)?;
    let bridge = BlsDoryOutputBridgeStatement::from_pending_dory(
        execution.final_activation.context.challenge.digest(),
        execution.final_activation.final_activation_digest,
        execution.final_activation.activation.len(),
        execution.prepared.pending_final_output(),
    )?;
    bridge.validate_activation(&execution.final_activation.activation)?;
    Ok(bridge)
}

fn algebraic_binding_for_verified_dory_v3_execution(
    execution: &VerifiedBlsDoryV3WinningNonceExecution,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    block: &BlockChallenge,
    setup: &DeterministicBlsDorySetup,
) -> Result<[u8; 32], BlsDoryV3WinningNonceReplayError> {
    let transcript = BlsDoryV3ExecutionAccumulatorArtifactContext::validate_authority(
        execution.context.challenge,
        authenticated,
        setup,
    )?;
    let challenge = transcript.challenge_context(block, execution.nonce)?;
    if challenge != execution.context.challenge {
        return Err(BlsDoryV3WinningNonceReplayError::Context);
    }
    if execution
        .context
        .work_digest(execution.final_activation_digest)
        != execution.work_digest
    {
        return Err(BlsDoryV3WinningNonceReplayError::WorkDigest);
    }
    let public_fields = ForgeMatrixV3CandidateProof {
        algorithm_version: DORY_V3_ALGORITHM_VERSION,
        proof_version: DORY_V3_PROOF_VERSION,
        nonce: execution.nonce,
        model_manifest_digest: transcript.manifest_digest().into_bytes(),
        challenge_digest: challenge.digest(),
        final_activation_digest: execution.final_activation_digest,
        work_digest: execution.work_digest,
        structured_proof: Vec::new(),
    };
    Ok(transcript.algebraic_binding(block, &public_fields)?)
}

fn check_layout_preparation_cancel(
    cancel: &AtomicBool,
) -> Result<(), BlsDoryV3LayoutV5PreparationError> {
    if cancel.load(Ordering::Acquire) {
        return Err(BlsDoryV3WinningNonceReplayError::Cancelled.into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn prepare_bls_dory_shared_layout_v5_from_validated_execution_preparation_with_scratch(
    execution: VerifiedBlsDoryV3WinningNonceExecution,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    preparation: ValidatedBlsDorySharedLayoutV5ExecutionPreparation<'_>,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryV3LayoutV5Execution, BlsDoryV3LayoutV5PreparationError> {
    let cancel = AtomicBool::new(false);
    prepare_bls_dory_shared_layout_v5_from_validated_execution_preparation_with_scratch_and_cancel(
        execution,
        authenticated,
        preparation,
        setup,
        scratch_directory,
        &cancel,
    )
}

/// Report one layout-preparation component to standard error in the same
/// machine-readable shape as the proof stage lines, so operators can see
/// where layout wall time goes. Best effort by design: reporting must never
/// fail or reorder proving.
fn report_layout_component(component: &str, started: std::time::Instant) -> std::time::Instant {
    let elapsed = started.elapsed().as_micros();
    eprintln!(
        "CMFD_V3_PROOF_SUBSTAGE {{\"stage\":\"{component}\",\"scalars\":0,\"elapsed_micros\":{elapsed}}}"
    );
    std::time::Instant::now()
}

#[allow(clippy::too_many_arguments)]
fn prepare_bls_dory_shared_layout_v5_from_validated_execution_preparation_with_scratch_and_cancel(
    mut execution: VerifiedBlsDoryV3WinningNonceExecution,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    preparation: ValidatedBlsDorySharedLayoutV5ExecutionPreparation<'_>,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
    cancel: &AtomicBool,
) -> Result<PreparedBlsDoryV3LayoutV5Execution, BlsDoryV3LayoutV5PreparationError> {
    check_layout_preparation_cancel(cancel)?;
    if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
        return Err(BlsDoryV3WinningNonceReplayError::ScratchDirectory.into());
    }
    let component_binding = preparation.component_binding();
    let padded_variables = preparation.padded_variables();
    let (final_activation, matrices, transitions, wiring) = {
        let mut reader = execution.authenticated_artifact_reader(authenticated, setup)?;
        let expected_geometry = preparation.execution_geometry();
        let actual_geometry = (
            reader.canonical_rows(),
            reader.canonical_columns(),
            reader.banks(),
            reader.layers_per_bank(),
        );
        if actual_geometry != expected_geometry {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape.into());
        }

        // Authenticate the final-output bytes and both retained digests before
        // any matrix, transition, range, or wiring proof work begins.
        let mut component_started = std::time::Instant::now();
        let final_activation = reader.reconstruct_verified_final_activation()?;
        component_started = report_layout_component("layout_final_activation", component_started);
        check_layout_preparation_cancel(cancel)?;

        let mut matrices = Vec::with_capacity(preparation.matrix_count());
        for bank in 0..preparation.matrix_count() {
            let weight = preparation.matrix_weight(bank)?;
            let matrix =
            prove_bls_dory_matrix_deferred_with_precommitted_weight_from_dory_v3_execution_reader_and_scratch_and_cancel(
                component_binding.as_bytes(),
                weight,
                &mut reader,
                bank,
                padded_variables,
                setup,
                scratch_directory,
                cancel,
            )
            .map_err(BlsDorySharedLayoutError::from)?;
            if matrix.proof.weight_commitment != weight.commitment() {
                return Err(BlsDorySharedLayoutError::FixedModelCommitment.into());
            }
            matrices.push(matrix);
            component_started =
                report_layout_component(&format!("layout_matrix_bank_{bank}"), component_started);
        }

        let mut transitions = Vec::with_capacity(preparation.transition_count());
        let mut released_transition_sources = Vec::with_capacity(preparation.transition_count());
        for transition_index in 0..preparation.transition_count() {
            let statement = preparation.transition_statement(transition_index)?;
            let mut arithmetic =
                prove_bls_dory_v3_transition_deferred_from_execution_reader_with_scratch_and_cancel(
                    component_binding.as_bytes(),
                    &mut reader,
                    transition_index,
                    padded_variables,
                    setup,
                    scratch_directory,
                    cancel,
                )
                .map_err(BlsDorySharedLayoutError::from)?;
            let committed_transition = arithmetic
                .openings
                .polynomial(0)
                .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
            let transition_elements = statement
                .elements()
                .map_err(BlsDoryTransitionError::from)
                .map_err(BlsDorySharedLayoutError::from)?;
            let mut range = if transition_elements >= BLS_DORY_RANGE_LOGUP_TABLE_VALUES {
                prove_bls_dory_range_logup_deferred_with_precommitted_compact_transition_and_scratch_and_cancel(
                component_binding.as_bytes(),
                statement,
                committed_transition,
                padded_variables,
                setup,
                scratch_directory,
                cancel,
            )
            .map_err(BlsDorySharedLayoutError::from)?
            } else {
                prove_bls_dory_v3_small_range_logup_from_execution_reader_with_scratch_and_cancel(
                    component_binding.as_bytes(),
                    &mut reader,
                    transition_index,
                    committed_transition,
                    padded_variables,
                    setup,
                    scratch_directory,
                    cancel,
                )
                .map_err(BlsDorySharedLayoutError::from)?
            };
            if arithmetic.proof.oracle_commitment != range.proof.transition_commitment {
                return Err(BlsDorySharedLayoutError::TransitionRangeCommitment.into());
            }
            let arithmetic_source = arithmetic
                .openings
                .release_compact_source()
                .map_err(BlsDorySharedLayoutError::from)?
                .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
            let range_source = range
                .openings
                .release_compact_source()
                .map_err(BlsDorySharedLayoutError::from)?
                .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
            if arithmetic_source != range_source {
                return Err(BlsDorySharedLayoutError::OpeningClaims.into());
            }
            transitions.push((arithmetic, range));
            released_transition_sources.push(arithmetic_source);
            component_started = report_layout_component(
                &format!("layout_transition_{transition_index}"),
                component_started,
            );
        }

        let wiring =
            prove_bls_dory_v3_wiring_deferred_from_execution_reader_with_scratch_and_cancel(
                component_binding.as_bytes(),
                &mut reader,
                padded_variables,
                setup,
                scratch_directory,
                cancel,
            )
            .map_err(BlsDorySharedLayoutError::from)?;
        component_started = report_layout_component("layout_wiring", component_started);

        for (transition_index, ((arithmetic, range), expected_source)) in transitions
            .iter_mut()
            .zip(&released_transition_sources)
            .enumerate()
        {
            let restored =
            regenerate_bls_dory_v3_transition_compact_source_from_execution_reader_with_scratch_and_cancel(
                &mut reader,
                transition_index,
                padded_variables,
                expected_source,
                setup,
                scratch_directory,
                cancel,
            )
            .map_err(BlsDorySharedLayoutError::from)?;
            arithmetic
                .openings
                .restore_compact_source(&restored)
                .map_err(BlsDorySharedLayoutError::from)?;
            range
                .openings
                .restore_compact_source(&restored)
                .map_err(BlsDorySharedLayoutError::from)?;
            component_started = report_layout_component(
                &format!("layout_transition_source_restore_{transition_index}"),
                component_started,
            );
        }

        (final_activation, matrices, transitions, wiring)
    };
    drop(execution);
    check_layout_preparation_cancel(cancel)?;
    let assembly_started = std::time::Instant::now();
    let prepared = preparation.into_prepared(matrices, transitions, wiring, setup)?;
    let _ = report_layout_component("layout_shared_assembly", assembly_started);
    Ok(PreparedBlsDoryV3LayoutV5Execution {
        prepared,
        final_activation,
    })
}

/// Consume one verified V3 execution and prepare its exact bank-authenticated
/// Layout V5 state. The algebraic binding is derived internally from the
/// retained execution fields and block; callers cannot inject raw transcript
/// bytes, statements, masks, or artifact context.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_with_scratch(
    execution: VerifiedBlsDoryV3WinningNonceExecution,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    prepared_model: &BlsDoryPreparedFixedModelV5,
    block: &BlockChallenge,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryV3LayoutV5Execution, BlsDoryV3LayoutV5PreparationError> {
    let cancel = AtomicBool::new(false);
    prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_with_scratch_and_cancel(
        execution,
        authenticated,
        prepared_model,
        block,
        setup,
        scratch_directory,
        &cancel,
    )
}

#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_with_scratch_and_cancel(
    execution: VerifiedBlsDoryV3WinningNonceExecution,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    prepared_model: &BlsDoryPreparedFixedModelV5,
    block: &BlockChallenge,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
    cancel: &AtomicBool,
) -> Result<PreparedBlsDoryV3LayoutV5Execution, BlsDoryV3LayoutV5PreparationError> {
    check_layout_preparation_cancel(cancel)?;
    let binding =
        algebraic_binding_for_verified_dory_v3_execution(&execution, authenticated, block, setup)?;
    let context =
        BlsDorySharedLayoutV5Context::from_bank_authenticated_record(authenticated, setup)?;
    let component_binding = context.fixed_model_binding(&binding)?;
    let preparation = preflight_bls_dory_shared_layout_v5_execution_preparation(
        &binding,
        authenticated,
        prepared_model,
        context,
        component_binding,
        setup,
    )?;
    prepare_bls_dory_shared_layout_v5_from_validated_execution_preparation_with_scratch_and_cancel(
        execution,
        authenticated,
        preparation,
        setup,
        scratch_directory,
        cancel,
    )
}

/// Consume the only authenticated V3/Layout V5 preparation capability and
/// produce its Dory-V3-domain native proof plus one exact 134-claim aggregate.
/// Callers cannot supply or recover raw challenge, activation, digest, bridge,
/// native-opening, or proof-pair parts.
#[allow(dead_code)]
pub(crate) fn finish_prepared_bls_dory_v3_layout_v5_execution_with_composition(
    execution: PreparedBlsDoryV3LayoutV5Execution,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
    maximum_native_block_rows: usize,
) -> Result<ComposedBlsDoryV3LayoutV5Execution, BlsDoryV3LayoutV5CompositionError> {
    let cancel = AtomicBool::new(false);
    finish_prepared_bls_dory_v3_layout_v5_execution_with_composition_and_cancel(
        execution,
        setup,
        scratch_directory,
        maximum_native_block_rows,
        &cancel,
    )
}

#[allow(dead_code)]
pub(crate) fn finish_prepared_bls_dory_v3_layout_v5_execution_with_composition_and_cancel(
    execution: PreparedBlsDoryV3LayoutV5Execution,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
    maximum_native_block_rows: usize,
    cancel: &AtomicBool,
) -> Result<ComposedBlsDoryV3LayoutV5Execution, BlsDoryV3LayoutV5CompositionError> {
    if cancel.load(Ordering::Acquire) {
        return Err(BlsDoryV3LayoutV5CompositionError::Native(
            BlsDoryAggregateError::Cancelled,
        ));
    }
    validate_dory_v3_layout_v5_composition_configuration(
        scratch_directory,
        maximum_native_block_rows,
    )?;
    preflight_prepared_bls_dory_shared_layout_v5_composition(&execution.prepared, setup)?;
    let bridge = validated_dory_v3_layout_v5_output_bridge(&execution, setup)?;
    let native = prepare_production_dory_v3_native_blake3_opening_with_cancel(
        execution.final_activation.as_bytes(),
        &bridge,
        setup,
        scratch_directory,
        maximum_native_block_rows,
        cancel,
    )?;
    let PreparedBlsDoryV3LayoutV5Execution {
        prepared,
        final_activation,
    } = execution;
    let (proof, encoded_native_proof) =
        finish_prepared_bls_dory_shared_layout_v5_with_dory_v3_native_opening_and_cancel(
            prepared,
            native,
            setup,
            scratch_directory,
            cancel,
        )?;
    Ok(ComposedBlsDoryV3LayoutV5Execution {
        challenge: final_activation.context.challenge,
        nonce: final_activation.nonce,
        final_activation_digest: final_activation.final_activation_digest,
        work_digest: final_activation.work_digest,
        proof,
        encoded_native_proof,
    })
}

/// Consume one opaque composed V3/Layout V5 execution and seal its exact proof
/// pair into the existing CP02 candidate envelope. All public fields are
/// rederived from the same Record V2, block, and setup authority before the
/// private proof values are released as candidate bytes.
#[allow(dead_code)]
pub(crate) fn seal_composed_bls_dory_v3_layout_v5_candidate(
    execution: ComposedBlsDoryV3LayoutV5Execution,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    block: &BlockChallenge,
    setup: &DeterministicBlsDorySetup,
) -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError> {
    validate_dory_v3_layout_v5_record_setup_binding(authenticated, setup)?;
    authenticated.record().validate_production(setup)?;
    let transcript =
        DoryV3TranscriptContext::from_bank_authenticated_record(block.network_id, authenticated)?;
    let context =
        BlsDorySharedLayoutV5Context::from_bank_authenticated_record(authenticated, setup)?;
    seal_composed_bls_dory_v3_layout_v5_candidate_after_authority(
        execution, transcript, block, &context,
    )
}

/// Reauthenticate the fixed model and one accelerator-proposed winning nonce,
/// construct the complete Record-V2/Layout-V5 proof, and self-verify the exact
/// candidate before returning any proof bytes.
///
/// The two bank readers are deliberately independent. Fixed-model publication
/// and execution replay must each authenticate the complete bank against the
/// same non-serializable Record V2 authority. The scratch directory and native
/// row limit are explicit process resources, never consensus parameters.
/// Emits one machine-readable prover-stage line to standard error, matching
/// the ceremony progress convention, so operators can attribute Layout V5
/// proof wall time to its pipeline stages without a profiler. Best effort by
/// design: stage reporting must never fail or reorder proving.
#[cfg(any(feature = "dory-v3-consensus-adapter", test))]
fn report_prover_stage(stage: &str, started: Instant) -> Instant {
    let elapsed = started.elapsed().as_micros();
    eprintln!("CMFD_V3_PROOF_STAGE {{\"stage\":\"{stage}\",\"elapsed_micros\":{elapsed}}}");
    Instant::now()
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(feature = "dory-v3-consensus-adapter", test))]
pub(crate) fn prove_bls_dory_v3_layout_v5_candidate_from_winning_nonce_claim<
    FixedModelBank: Read,
    ReplayBank: Read,
>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    block: &BlockChallenge,
    claim: BlsDoryV3WinningNonceClaim,
    setup: &DeterministicBlsDorySetup,
    fixed_model_bank: FixedModelBank,
    replay_bank: ReplayBank,
    scratch_directory: &Path,
    maximum_native_block_rows: usize,
    cancel: &AtomicBool,
) -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError> {
    if maximum_native_block_rows == 0
        || !scratch_directory.is_absolute()
        || !scratch_directory.is_dir()
    {
        return Err(BlsDoryV3CandidateError::ProverConfiguration);
    }
    check_runtime_prover_cancel(cancel)?;

    let stage_started = Instant::now();
    let transcript =
        DoryV3TranscriptContext::from_bank_authenticated_record(block.network_id, authenticated)?;
    let _ = validate_dory_v3_replay_claim(authenticated, transcript, block, claim, cancel)?;
    let stage_started = report_prover_stage("claim_validation", stage_started);

    let prepared_model =
        prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch_and_cancel(
            fixed_model_bank,
            authenticated,
            setup,
            scratch_directory,
            cancel,
        )?;
    let _ = report_prover_stage("fixed_model_preparation", stage_started);
    check_runtime_prover_cancel(cancel)?;

    prove_bls_dory_v3_layout_v5_candidate_from_prepared_fixed_model(
        authenticated,
        block,
        claim,
        setup,
        &prepared_model,
        replay_bank,
        scratch_directory,
        maximum_native_block_rows,
        cancel,
    )
}

/// Replay and prove a winning nonce with fixed-model polynomials prepared once
/// for the process. The untrusted claim is fully transcript- and target-checked
/// before the replay reader is touched, and replay repeats the same validation
/// defensively before authenticating model bytes.
#[allow(clippy::too_many_arguments)]
#[cfg(any(feature = "dory-v3-consensus-adapter", test))]
pub(crate) fn prove_bls_dory_v3_layout_v5_candidate_from_prepared_fixed_model<ReplayBank: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    block: &BlockChallenge,
    claim: BlsDoryV3WinningNonceClaim,
    setup: &DeterministicBlsDorySetup,
    prepared_model: &BlsDoryPreparedFixedModelV5,
    replay_bank: ReplayBank,
    scratch_directory: &Path,
    maximum_native_block_rows: usize,
    cancel: &AtomicBool,
) -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError> {
    prove_bls_dory_v3_layout_v5_candidate_from_prepared_fixed_model_with_accelerated_replay(
        authenticated,
        block,
        claim,
        setup,
        prepared_model,
        replay_bank,
        scratch_directory,
        maximum_native_block_rows,
        None,
        cancel,
    )
}

/// The prepared-fixed-model prover with an optional accelerator-proposed
/// replay accumulator bundle. `None` executes the unchanged CPU replay;
/// `Some` still authenticates the complete bank on this path's own reader and
/// re-derives every published digest on the CPU, so accepting the bundle only
/// removes the redundant matrix re-execution, never any validation.
#[allow(clippy::too_many_arguments)]
#[cfg(any(feature = "dory-v3-consensus-adapter", test))]
pub(crate) fn prove_bls_dory_v3_layout_v5_candidate_from_prepared_fixed_model_with_accelerated_replay<
    ReplayBank: Read,
>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    block: &BlockChallenge,
    claim: BlsDoryV3WinningNonceClaim,
    setup: &DeterministicBlsDorySetup,
    prepared_model: &BlsDoryPreparedFixedModelV5,
    replay_bank: ReplayBank,
    scratch_directory: &Path,
    maximum_native_block_rows: usize,
    accelerated_replay: Option<BlsDoryV3AcceleratedReplayAccumulators>,
    cancel: &AtomicBool,
) -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError> {
    if maximum_native_block_rows == 0
        || !scratch_directory.is_absolute()
        || !scratch_directory.is_dir()
        || !prepared_model.is_bound_to_bank_authenticated_record(authenticated)
    {
        return Err(BlsDoryV3CandidateError::ProverConfiguration);
    }
    check_runtime_prover_cancel(cancel)?;

    let proof_started = Instant::now();
    let stage_started = proof_started;
    let transcript =
        DoryV3TranscriptContext::from_bank_authenticated_record(block.network_id, authenticated)?;
    let _ = validate_dory_v3_replay_claim(authenticated, transcript, block, claim, cancel)?;
    let execution = match accelerated_replay {
        Some(accelerated) => {
            replay_dory_v3_winning_nonce_from_bank_authenticated_record_accelerated(
                authenticated,
                transcript,
                block,
                claim,
                setup,
                replay_bank,
                scratch_directory,
                accelerated,
                cancel,
            )?
        }
        None => replay_dory_v3_winning_nonce_from_bank_authenticated_record(
            authenticated,
            transcript,
            block,
            claim,
            setup,
            replay_bank,
            scratch_directory,
            cancel,
        )?,
    };
    let stage_started = report_prover_stage("winning_nonce_replay", stage_started);
    check_runtime_prover_cancel(cancel)?;

    let prepared_result =
        prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_with_scratch_and_cancel(
            execution,
            authenticated,
            prepared_model,
            block,
            setup,
            scratch_directory,
            cancel,
        );
    let prepared = match prepared_result {
        Ok(prepared) => prepared,
        Err(_) if cancel.load(Ordering::Acquire) => {
            return Err(BlsDoryV3WinningNonceReplayError::Cancelled.into());
        }
        Err(error) => return Err(map_layout_v5_preparation_error(error)),
    };
    let stage_started = report_prover_stage("layout_preparation", stage_started);
    check_runtime_prover_cancel(cancel)?;

    let composed = finish_prepared_bls_dory_v3_layout_v5_execution_with_composition_and_cancel(
        prepared,
        setup,
        scratch_directory,
        maximum_native_block_rows,
        cancel,
    )
    .map_err(map_layout_v5_composition_error)?;
    let stage_started = report_prover_stage("native_composition", stage_started);
    check_runtime_prover_cancel(cancel)?;

    let candidate =
        seal_composed_bls_dory_v3_layout_v5_candidate(composed, authenticated, block, setup)?;
    let stage_started = report_prover_stage("candidate_seal", stage_started);
    let _verified = verify_bls_dory_v3_layout_v5_candidate(
        block.network_id,
        authenticated,
        block,
        &candidate,
        setup,
    )?;
    let _ = report_prover_stage("self_verification", stage_started);
    let _ = report_prover_stage("proof_total", proof_started);
    Ok(candidate)
}

#[cfg(any(feature = "dory-v3-consensus-adapter", test))]
fn check_runtime_prover_cancel(cancel: &AtomicBool) -> Result<(), BlsDoryV3CandidateError> {
    if cancel.load(Ordering::Acquire) {
        return Err(BlsDoryV3WinningNonceReplayError::Cancelled.into());
    }
    Ok(())
}

#[cfg(any(feature = "dory-v3-consensus-adapter", test))]
fn map_layout_v5_preparation_error(
    error: BlsDoryV3LayoutV5PreparationError,
) -> BlsDoryV3CandidateError {
    match error {
        BlsDoryV3LayoutV5PreparationError::Replay(error) => error.into(),
        BlsDoryV3LayoutV5PreparationError::Layout(error) => error.into(),
    }
}

#[cfg(any(feature = "dory-v3-consensus-adapter", test))]
fn map_layout_v5_composition_error(
    error: BlsDoryV3LayoutV5CompositionError,
) -> BlsDoryV3CandidateError {
    match error {
        BlsDoryV3LayoutV5CompositionError::Configuration => {
            BlsDoryV3CandidateError::ProverConfiguration
        }
        BlsDoryV3LayoutV5CompositionError::ReplayAuthority(error) => error.into(),
        BlsDoryV3LayoutV5CompositionError::OutputBridge(error) => error.into(),
        BlsDoryV3LayoutV5CompositionError::Native(error) => error.into(),
        BlsDoryV3LayoutV5CompositionError::Layout(error) => error.into(),
    }
}

fn seal_composed_bls_dory_v3_layout_v5_candidate_after_authority(
    execution: ComposedBlsDoryV3LayoutV5Execution,
    transcript: DoryV3TranscriptContext,
    block: &BlockChallenge,
    expected_context: &BlsDorySharedLayoutV5Context,
) -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError> {
    execution.proof.validate_context(expected_context)?;
    let expected_challenge = transcript.challenge_context(block, execution.nonce)?;
    if execution.challenge != expected_challenge {
        return Err(BlsDoryV3CandidateError::ChallengeDigest);
    }
    if execution.work_digest != expected_challenge.work_digest(execution.final_activation_digest) {
        return Err(BlsDoryV3CandidateError::WorkDigest);
    }
    if execution.work_digest > block.target {
        return Err(BlsDoryV3CandidateError::HighHash);
    }
    let shape = StructuredForgeMatrixResearchShape::production_candidate();
    let transition_statements = [
        shape.initialization_statement,
        shape.transition_statements[0],
        shape.transition_statements[1],
        shape.transition_statements[2],
    ];
    let dory_proof = execution.proof.encode(
        &shape.matrix_statements,
        &transition_statements,
        shape.wiring_statement,
    )?;
    Ok(ForgeMatrixV3CandidateProof {
        algorithm_version: DORY_V3_ALGORITHM_VERSION,
        proof_version: DORY_V3_PROOF_VERSION,
        nonce: execution.nonce,
        model_manifest_digest: transcript.manifest_digest().into_bytes(),
        challenge_digest: expected_challenge.digest(),
        final_activation_digest: execution.final_activation_digest,
        work_digest: execution.work_digest,
        structured_proof: BlsDoryV3CandidatePayload {
            dory_proof,
            native_blake3_proof: execution.encoded_native_proof,
        }
        .encode()?,
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_for_test_with_scratch(
    execution: VerifiedBlsDoryV3WinningNonceExecution,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    prepared_model: &BlsDoryPreparedFixedModelV5,
    block: &BlockChallenge,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryV3LayoutV5Execution, BlsDoryV3LayoutV5PreparationError> {
    use crate::dory_bls12_381_layout::preflight_bls_dory_shared_layout_v5_execution_preparation_for_test;

    let binding =
        algebraic_binding_for_verified_dory_v3_execution(&execution, authenticated, block, setup)?;
    let context = BlsDorySharedLayoutV5Context::from_bank_authenticated_record_for_test(
        authenticated,
        setup,
    )?;
    let component_binding = context.fixed_model_binding(&binding)?;
    let preparation = preflight_bls_dory_shared_layout_v5_execution_preparation_for_test(
        &binding,
        authenticated,
        prepared_model,
        context,
        component_binding,
        setup,
    )?;
    prepare_bls_dory_shared_layout_v5_from_validated_execution_preparation_with_scratch(
        execution,
        authenticated,
        preparation,
        setup,
        scratch_directory,
    )
}

/// Derive one Dory V3 claim by executing one caller-selected nonce against the
/// authenticated production bank.
///
/// This is a one-nonce evaluator, not a mining loop. The exact replay sink
/// derives both digests, the target is checked only after that complete
/// execution, and the provisional execution artifact is dropped before the
/// claim is returned.
#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) fn derive_dory_v3_winning_nonce_claim_from_bank_authenticated_record<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    transcript: DoryV3TranscriptContext,
    block: &BlockChallenge,
    nonce: u64,
    setup: &DeterministicBlsDorySetup,
    model_bank: R,
    scratch_directory: &Path,
    cancel: &AtomicBool,
) -> Result<BlsDoryV3WinningNonceClaim, BlsDoryV3WinningNonceReplayError> {
    let challenge =
        validate_dory_v3_derivation_context(authenticated, transcript, block, nonce, cancel)?;
    let context = BlsDoryV3ExecutionAccumulatorArtifactContext::from_challenge(
        challenge,
        authenticated,
        setup,
    )?;
    derive_dory_v3_winning_nonce_claim_with_context(
        authenticated,
        context,
        block,
        nonce,
        model_bank,
        scratch_directory,
        cancel,
    )
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
    execute_dory_v3_with_context(
        authenticated,
        context,
        BlsDoryV3WinningNonceExpectation::Verify(claim),
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
    execute_dory_v3_with_context(
        authenticated,
        context,
        BlsDoryV3WinningNonceExpectation::Verify(claim),
        model_bank,
        scratch_directory,
        cancel,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn derive_dory_v3_winning_nonce_claim_from_bank_authenticated_record_for_test<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    transcript: DoryV3TranscriptContext,
    block: &BlockChallenge,
    nonce: u64,
    setup: &DeterministicBlsDorySetup,
    model_bank: R,
    scratch_directory: &Path,
    cancel: &AtomicBool,
) -> Result<BlsDoryV3WinningNonceClaim, BlsDoryV3WinningNonceReplayError> {
    let challenge =
        validate_dory_v3_derivation_context(authenticated, transcript, block, nonce, cancel)?;
    let context =
        BlsDoryV3ExecutionAccumulatorArtifactContext::for_test(challenge, authenticated, setup)?;
    derive_dory_v3_winning_nonce_claim_with_context(
        authenticated,
        context,
        block,
        nonce,
        model_bank,
        scratch_directory,
        cancel,
    )
}

fn validate_dory_v3_derivation_context(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    transcript: DoryV3TranscriptContext,
    block: &BlockChallenge,
    nonce: u64,
    cancel: &AtomicBool,
) -> Result<DoryV3ChallengeContext, BlsDoryV3WinningNonceReplayError> {
    let challenge = transcript.challenge_context(block, nonce)?;
    let expected_transcript =
        DoryV3TranscriptContext::from_bank_authenticated_record(block.network_id, authenticated)?;
    if transcript != expected_transcript {
        return Err(BlsDoryV3WinningNonceReplayError::Context);
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
    }
    Ok(challenge)
}

pub(crate) fn validate_dory_v3_replay_claim(
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

fn derive_dory_v3_winning_nonce_claim_with_context<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    block: &BlockChallenge,
    nonce: u64,
    model_bank: R,
    scratch_directory: &Path,
    cancel: &AtomicBool,
) -> Result<BlsDoryV3WinningNonceClaim, BlsDoryV3WinningNonceReplayError> {
    let execution = execute_dory_v3_with_context(
        authenticated,
        context,
        BlsDoryV3WinningNonceExpectation::Derive { nonce },
        model_bank,
        scratch_directory,
        cancel,
    )?;
    let claim = BlsDoryV3WinningNonceClaim {
        nonce: execution.nonce(),
        final_activation_digest: execution.final_activation_digest(),
        work_digest: execution.work_digest(),
    };
    drop(execution);
    if claim.work_digest > block.target {
        return Err(BlsDoryV3WinningNonceReplayError::HighHash);
    }
    Ok(claim)
}

fn execute_dory_v3_with_context<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    expectation: BlsDoryV3WinningNonceExpectation,
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
        expectation,
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
    expectation: BlsDoryV3WinningNonceExpectation,
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
        expectation: BlsDoryV3WinningNonceExpectation,
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
            expectation,
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
            final_activation.push(encode_dory_v3_activation(i64::from(*activation))?);
        }
        let final_activation_digest = self.context.output_digest(&final_activation)?;
        let work_digest = self.context.work_digest(final_activation_digest);
        let claim = self
            .expectation
            .resolve(final_activation_digest, work_digest)?;

        let writer = self
            .writer
            .take()
            .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?;
        finish_verified_dory_v3_execution(
            writer,
            self.context,
            claim,
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

fn encode_dory_v3_activation(activation: i64) -> Result<u8, BlsDoryV3WinningNonceReplayError> {
    let activation =
        i8::try_from(activation).map_err(|_| BlsDoryV3WinningNonceReplayError::ModelShape)?;
    i16::from(activation)
        .checked_add(V2_MODEL_VALUE_CENTER)
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| *value <= 250)
        .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)
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

/// Accelerator-computed replay accumulator columns for one winning nonce, in
/// canonical bank-major layer order (`banks * layers_per_bank` columns of
/// `rows * columns` raw int32 accumulators each).
///
/// Accepting this bundle never extends trust to the accelerator: the replay
/// that consumes it still authenticates the complete model bank on its own
/// reader, validates the initialization transition per cell, bound-checks
/// every surfaced accumulator, re-derives the final activation and both
/// digests on the CPU from the last column, and writes the canonical
/// execution artifact. Downstream, the matrix sumcheck proves every column
/// against the CPU-committed fixed-model weights and the finished candidate
/// is self-verified, so a wrong accelerator value costs the candidate and
/// can never produce a valid proof.
pub struct BlsDoryV3AcceleratedReplayAccumulators {
    layer_accumulators: Vec<i32>,
}

impl BlsDoryV3AcceleratedReplayAccumulators {
    pub fn new(layer_accumulators: Vec<i32>) -> Self {
        Self { layer_accumulators }
    }

    fn layer_column(&self, global_layer: usize, cells: usize) -> Option<&[i32]> {
        let start = global_layer.checked_mul(cells)?;
        let end = start.checked_add(cells)?;
        self.layer_accumulators.get(start..end)
    }
}

/// Replay one winning nonce using accelerator-proposed accumulator columns in
/// place of the CPU matrix executions. The claimed work and target are checked
/// before the model-bank reader is touched, the complete bank authenticates on
/// this path's own reader exactly as in the CPU replay, and the artifact
/// remains provisional until everything has authenticated.
#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_dory_v3_winning_nonce_from_bank_authenticated_record_accelerated<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    transcript: DoryV3TranscriptContext,
    block: &BlockChallenge,
    claim: BlsDoryV3WinningNonceClaim,
    setup: &DeterministicBlsDorySetup,
    model_bank: R,
    scratch_directory: &Path,
    accelerated: BlsDoryV3AcceleratedReplayAccumulators,
    cancel: &AtomicBool,
) -> Result<VerifiedBlsDoryV3WinningNonceExecution, BlsDoryV3WinningNonceReplayError> {
    let challenge = validate_dory_v3_replay_claim(authenticated, transcript, block, claim, cancel)?;
    let context = BlsDoryV3ExecutionAccumulatorArtifactContext::from_challenge(
        challenge,
        authenticated,
        setup,
    )?;
    execute_dory_v3_accelerated_with_context(
        authenticated,
        context,
        BlsDoryV3WinningNonceExpectation::Verify(claim),
        model_bank,
        scratch_directory,
        accelerated,
        cancel,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn replay_dory_v3_winning_nonce_from_bank_authenticated_record_accelerated_for_test<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    transcript: DoryV3TranscriptContext,
    block: &BlockChallenge,
    claim: BlsDoryV3WinningNonceClaim,
    setup: &DeterministicBlsDorySetup,
    model_bank: R,
    scratch_directory: &Path,
    accelerated: BlsDoryV3AcceleratedReplayAccumulators,
    cancel: &AtomicBool,
) -> Result<VerifiedBlsDoryV3WinningNonceExecution, BlsDoryV3WinningNonceReplayError> {
    let challenge = validate_dory_v3_replay_claim(authenticated, transcript, block, claim, cancel)?;
    let context =
        BlsDoryV3ExecutionAccumulatorArtifactContext::for_test(challenge, authenticated, setup)?;
    execute_dory_v3_accelerated_with_context(
        authenticated,
        context,
        BlsDoryV3WinningNonceExpectation::Verify(claim),
        model_bank,
        scratch_directory,
        accelerated,
        cancel,
    )
}

fn execute_dory_v3_accelerated_with_context<R: Read>(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    expectation: BlsDoryV3WinningNonceExpectation,
    model_bank: R,
    scratch_directory: &Path,
    accelerated: BlsDoryV3AcceleratedReplayAccumulators,
    cancel: &AtomicBool,
) -> Result<VerifiedBlsDoryV3WinningNonceExecution, BlsDoryV3WinningNonceReplayError> {
    let record = authenticated.record();
    let identity = record.model_identity();
    let bank_count = identity
        .weight_bank_count()
        .map_err(|_| BlsDoryV3WinningNonceReplayError::ModelShape)?;
    validate_dory_v3_replay_geometry(context, authenticated, bank_count)?;
    preflight_dory_v3_execution_artifact(context, scratch_directory)?;
    let sink = DoryV3AcceleratedWinningNonceReplaySink::new(
        context,
        *record.manifest(),
        expectation,
        scratch_directory,
        accelerated,
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

/// Replay sink that authenticates the model stream exactly like
/// `DoryV3WinningNonceReplaySink` but consumes accelerator-proposed
/// accumulator columns instead of executing the matrix layers, so the weight
/// bytes only advance authentication bookkeeping. Validation posture is
/// unchanged where it feeds the artifact or the claim: the initialization
/// transition is still derived and range-checked per cell, every accumulator
/// is bound-checked before it is written, and the final activation is derived
/// on the CPU from the last accepted column.
struct DoryV3AcceleratedWinningNonceReplaySink<'a> {
    context: BlsDoryV3ExecutionAccumulatorArtifactContext,
    expected_manifest: ModelBankManifest,
    expectation: BlsDoryV3WinningNonceExpectation,
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
    accelerated: BlsDoryV3AcceleratedReplayAccumulators,
    final_activations: Vec<i8>,
    pending_initial_accumulators: Vec<i32>,
}

impl<'a> DoryV3AcceleratedWinningNonceReplaySink<'a> {
    fn new(
        context: BlsDoryV3ExecutionAccumulatorArtifactContext,
        expected_manifest: ModelBankManifest,
        expectation: BlsDoryV3WinningNonceExpectation,
        scratch_directory: &Path,
        accelerated: BlsDoryV3AcceleratedReplayAccumulators,
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
        let total_layers = raw
            .banks()
            .checked_mul(raw.layers_per_bank())
            .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
        if total_layers
            .checked_mul(cells)
            .is_none_or(|expected| accelerated.layer_accumulators.len() != expected)
        {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
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
            expectation,
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
            accelerated,
            final_activations: zeroed_dory_v3_vector(cells)?,
            pending_initial_accumulators: reserved_dory_v3_vector(
                raw.authentication_chunk_cells(),
            )?,
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
            let _ = i8::try_from(transition.activation)
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
        if self.cancel.load(Ordering::Relaxed) {
            return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
        }

        let mut consumed = 0usize;
        while consumed < chunk.elements.len() {
            let layer_offset = self.bank_offset % self.layer_cells;
            let take = (self.layer_cells - layer_offset).min(chunk.elements.len() - consumed);
            self.bank_offset = self
                .bank_offset
                .checked_add(take)
                .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
            consumed += take;

            if self.bank_offset.is_multiple_of(self.layer_cells) {
                let layer = self
                    .bank_offset
                    .checked_div(self.layer_cells)
                    .and_then(|completed| completed.checked_sub(1))
                    .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?;
                self.accept_accelerated_layer(self.current_bank, layer)?;
            }
        }

        if self.bank_offset as u64 == self.bank_elements {
            self.current_bank += 1;
            self.bank_offset = 0;
        }
        Ok(())
    }

    /// Bound-check and write one accelerator column once the corresponding
    /// authenticated weight layer has fully streamed; derive the final
    /// activations on the CPU when the last layer's column is accepted.
    fn accept_accelerated_layer(
        &mut self,
        bank: usize,
        layer: usize,
    ) -> Result<(), BlsDoryV3WinningNonceReplayError> {
        if bank >= self.context.raw().banks() || layer >= self.context.raw().layers_per_bank() {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }
        let global_layer = bank
            .checked_mul(self.context.raw().layers_per_bank())
            .and_then(|base| base.checked_add(layer))
            .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
        let total_layers = self
            .context
            .raw()
            .banks()
            .checked_mul(self.context.raw().layers_per_bank())
            .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
        let is_final_layer = global_layer + 1 == total_layers;
        let cells = self.cells;
        let chunk_cells = self.context.raw().authentication_chunk_cells();
        let column = self
            .accelerated
            .layer_column(global_layer, cells)
            .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?
            .to_vec();
        let mask = &self.transition_masks[bank];

        for start in (0..cells).step_by(chunk_cells) {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(BlsDoryV3WinningNonceReplayError::Cancelled);
            }
            let len = chunk_cells.min(cells - start);
            let encoded = &column[start..start + len];
            encoded.par_iter().try_for_each(|accumulator| {
                validate_dory_v3_accumulator_bound(std::slice::from_ref(&i64::from(*accumulator)))
            })?;
            if is_final_layer {
                let transition_statement = self.transition_statement;
                self.final_activations[start..start + len]
                    .par_iter_mut()
                    .zip(encoded.par_iter())
                    .enumerate()
                    .try_for_each(|(offset, (activation, accumulator))| {
                        let index = layer
                            .checked_mul(cells)
                            .and_then(|base| base.checked_add(start + offset))
                            .ok_or(BlsDoryV3WinningNonceReplayError::Resource)?;
                        let mask_value =
                            mask.value_at_boolean_index_prevalidated(transition_statement, index)?;
                        let transition = derive_transition_regular_row_from_mask(
                            transition_statement,
                            index,
                            i64::from(*accumulator),
                            mask_value,
                        )?;
                        *activation = i8::try_from(transition.activation)
                            .map_err(|_| BlsDoryV3WinningNonceReplayError::ModelShape)?;
                        Ok::<(), BlsDoryV3WinningNonceReplayError>(())
                    })?;
            }
            self.writer
                .as_mut()
                .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?
                .write_column_chunk(
                    BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
                    encoded,
                )?;
        }
        Ok(())
    }
}

impl StagedModelFieldLayoutSink for DoryV3AcceleratedWinningNonceReplaySink<'_> {
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
            || !self.pending_initial_accumulators.is_empty()
        {
            return Err(BlsDoryV3WinningNonceReplayError::ModelShape);
        }

        let mut final_activation = reserved_dory_v3_vector(self.cells)?;
        for activation in &self.final_activations {
            final_activation.push(encode_dory_v3_activation(i64::from(*activation))?);
        }
        let final_activation_digest = self.context.output_digest(&final_activation)?;
        let work_digest = self.context.work_digest(final_activation_digest);
        let claim = self
            .expectation
            .resolve(final_activation_digest, work_digest)?;

        let writer = self
            .writer
            .take()
            .ok_or(BlsDoryV3WinningNonceReplayError::ModelShape)?;
        finish_verified_dory_v3_execution(
            writer,
            self.context,
            claim,
            final_activation_digest,
            work_digest,
            self.cancel,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{self, Cursor, Read, Seek, SeekFrom, Write},
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
    };

    use dory_pcs::primitives::arithmetic::Field;
    use rayon::ThreadPoolBuilder;
    use serde_json::json;

    use super::*;
    use crate::{
        BlockChallenge, BlockProof, ForgeMatrixV2Descriptor, ForgeMatrixV2Reference,
        ForgeMatrixV2ReferenceProof, SmallModelBankFixture,
        dory_bls12_381_aggregate::commit_bls_dory_polynomial,
        dory_bls12_381_execution_artifact::BlsDoryExecutionAccumulatorColumn,
        dory_bls12_381_prototype::{BlsDoryFr, BlsDoryGt, deterministic_bls_dory_setup},
        dory_v3_model::{CanonicalBlsDoryGtHex, DoryV3ModelIdentityV1},
        dory_v3_model_record::{
            BankAuthenticatedDoryV3ModelCommitmentRecordV2, DoryV3ModelCommitmentRecordError,
            derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test,
        },
        dory_v3_suite::{DORY_V3_MODEL_IDENTITY_VERSION, DORY_V3_PRODUCTION_SUITE_DIGEST},
        model_bank::{BuiltModelBankFixture, build_small_model_bank},
    };

    #[cfg(feature = "whir-prototype")]
    use crate::{
        StructuredMatrixStatement, StructuredSumcheckError, StructuredTransitionWitness,
        StructuredWiringStatement,
        dory_bls12_381_aggregate::commit_bls_dory_padded_prefix_with_optional_scratch,
        dory_bls12_381_candidate::{
            decode_dory_v3_layout_v5_candidate_payload, layout_v5_relation_dispatches_for_test,
            reset_layout_v5_relation_dispatches_for_test,
            validate_dory_v3_layout_v5_candidate_statement_for_test,
            verify_bls_dory_v3_layout_v5_candidate_relation_for_test,
        },
        dory_bls12_381_layout::{
            bls_dory_shared_layout_v5_candidate_codec_fixture_for_test,
            prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_for_test_with_scratch,
        },
        dory_bls12_381_logup::{
            BlsDoryRangeLogUpError,
            prove_bls_dory_range_logup_deferred_with_precommitted_transition_and_scratch,
        },
        dory_bls12_381_matrix::{
            BlsDoryMatrixError,
            prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch,
            prove_bls_dory_matrix_deferred_with_precommitted_weight_from_dory_v3_execution_reader_and_scratch,
        },
        dory_bls12_381_transition::{
            prove_bls_dory_transition_deferred_at_variables_with_scratch,
            prove_bls_dory_v3_small_range_logup_from_execution_reader_with_scratch,
            prove_bls_dory_v3_transition_deferred_from_execution_reader_with_scratch,
            regenerate_bls_dory_v3_transition_compact_source_from_execution_reader_with_scratch,
        },
        dory_bls12_381_wiring::{
            BlsDoryWiringError,
            prove_bls_dory_v3_wiring_deferred_from_execution_reader_with_scratch,
            prove_bls_dory_wiring_deferred_at_variables_with_scratch,
        },
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

    fn corrupt_final_accumulator_column(
        scratch: &ScratchDirectory,
        reader: &BlsDoryV3ExecutionArtifactReader<'_>,
    ) {
        let mut entries = fs::read_dir(scratch.path()).unwrap();
        let path = entries.next().unwrap().unwrap().path();
        assert!(entries.next().is_none());

        let cells = reader.cells_per_column();
        let chunk_cells = reader.authentication_chunk_cells();
        let columns = reader
            .banks()
            .checked_mul(reader.layers_per_bank())
            .and_then(|columns| columns.checked_add(1))
            .unwrap();
        let chunks_per_column = cells.div_ceil(chunk_cells);
        let data_bytes = columns
            .checked_mul(cells)
            .and_then(|values| values.checked_mul(std::mem::size_of::<i32>()))
            .unwrap();
        let trailing_bytes = columns
            .checked_mul(chunks_per_column)
            .and_then(|digests| digests.checked_add(2))
            .and_then(|digests| digests.checked_mul(std::mem::size_of::<[u8; 32]>()))
            .unwrap();
        let file_bytes = usize::try_from(fs::metadata(&path).unwrap().len()).unwrap();
        let header_bytes = file_bytes
            .checked_sub(data_bytes)
            .and_then(|bytes| bytes.checked_sub(trailing_bytes))
            .unwrap();
        let final_column = columns.checked_sub(1).unwrap();
        let byte_offset = final_column
            .checked_mul(cells)
            .and_then(|values| values.checked_mul(std::mem::size_of::<i32>()))
            .and_then(|bytes| bytes.checked_add(header_bytes))
            .unwrap();
        assert!(byte_offset < header_bytes + data_bytes);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(u64::try_from(byte_offset).unwrap()))
            .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(u64::try_from(byte_offset).unwrap()))
            .unwrap();
        file.write_all(&byte).unwrap();
        file.sync_data().unwrap();
    }

    fn read_artifact_column_in_authenticated_chunks(
        artifact: &mut BlsDoryExecutionAccumulatorArtifact,
        column: BlsDoryExecutionAccumulatorColumn,
        output: &mut [i32],
    ) {
        let chunk_cells = artifact.context().authentication_chunk_cells();
        let mut start = 0usize;
        while start < output.len() {
            let end = start.saturating_add(chunk_cells).min(output.len());
            assert_eq!(
                artifact
                    .read_column_segment(column, start, &mut output[start..end])
                    .unwrap(),
                end - start
            );
            start = end;
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

    struct CountingReader<R> {
        inner: R,
        bytes_read: Arc<AtomicUsize>,
    }

    impl<R: Read> Read for CountingReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(buffer)?;
            self.bytes_read.fetch_add(read, Ordering::Relaxed);
            Ok(read)
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
    #[cfg(feature = "whir-prototype")]
    const DORY_V3_TRANSITION_TEST_VARIABLES: usize = 10;
    #[cfg(feature = "whir-prototype")]
    const DORY_V3_WIRING_TEST_VARIABLES: usize = 6;
    #[cfg(feature = "whir-prototype")]
    const DORY_V3_LAYOUT_V5_TEST_VARIABLES: usize = 10;
    const DORY_V3_TEST_BASE: [u8; 4] = [125, 126, 124, 127];
    const DORY_V3_TEST_LAYERS: [[u8; 4]; 4] = [
        [126, 125, 124, 127],
        [124, 126, 125, 123],
        [127, 124, 126, 125],
        [125, 123, 127, 124],
    ];
    #[cfg(feature = "whir-prototype")]
    const DORY_V3_LAYOUT_V5_TEST_LAYERS: [[u8; 4]; 6] = [
        [126, 125, 124, 127],
        [124, 126, 125, 123],
        [127, 124, 126, 125],
        [125, 123, 127, 124],
        [123, 127, 125, 126],
        [126, 124, 123, 127],
    ];
    #[cfg(feature = "whir-prototype")]
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

    fn commit_dory_v3_test_bytes_at_variables(
        bytes: &[u8],
        setup: &DeterministicBlsDorySetup,
        padded_variables: usize,
    ) -> BlsDoryGt {
        let mut coefficients = bytes
            .iter()
            .map(|value| BlsDoryFr::from_i64(i64::from(*value) - 125))
            .collect::<Vec<_>>();
        coefficients.resize(1 << padded_variables, BlsDoryFr::from_i64(0));
        commit_bls_dory_polynomial(
            coefficients,
            padded_variables / 2,
            padded_variables - padded_variables / 2,
            setup,
        )
        .unwrap()
        .commitment()
    }

    fn dory_v3_test_identity_at_variables(
        manifest: &ModelBankManifest,
        setup: &DeterministicBlsDorySetup,
        base: &[u8],
        layers: &[Vec<u8>],
        padded_variables: usize,
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
                encoded(commit_dory_v3_test_bytes_at_variables(
                    &bytes,
                    setup,
                    padded_variables,
                ))
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
            "padded_variables": padded_variables,
            "base_input_commitment": encoded(commit_dory_v3_test_bytes_at_variables(
                base,
                setup,
                padded_variables,
            )),
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
        dory_v3_replay_fixture_at_variables(tweak, DORY_V3_TEST_VARIABLES)
    }

    fn dory_v3_replay_fixture_at_variables(
        tweak: u8,
        padded_variables: usize,
    ) -> DoryV3ReplayFixture {
        dory_v3_replay_fixture_with_layers_at_variables(
            tweak,
            padded_variables,
            &DORY_V3_TEST_LAYERS,
        )
    }

    #[cfg(feature = "whir-prototype")]
    fn dory_v3_layout_v5_replay_fixture(tweak: u8) -> DoryV3ReplayFixture {
        dory_v3_replay_fixture_with_layers_at_variables(
            tweak,
            DORY_V3_LAYOUT_V5_TEST_VARIABLES,
            &DORY_V3_LAYOUT_V5_TEST_LAYERS,
        )
    }

    fn dory_v3_replay_fixture_with_layers_at_variables(
        tweak: u8,
        padded_variables: usize,
        layer_bytes: &[[u8; 4]],
    ) -> DoryV3ReplayFixture {
        let mut base = DORY_V3_TEST_BASE.to_vec();
        base[3] += tweak;
        let layers = layer_bytes
            .iter()
            .copied()
            .map(Vec::from)
            .collect::<Vec<_>>();
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
        let setup = deterministic_bls_dory_setup(padded_variables).unwrap();
        let identity = dory_v3_test_identity_at_variables(
            &provisional.manifest,
            &setup,
            &base,
            &layers,
            padded_variables,
        );
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

    #[cfg(feature = "whir-prototype")]
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

    #[cfg(feature = "whir-prototype")]
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

    #[cfg(feature = "whir-prototype")]
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

    #[cfg(feature = "whir-prototype")]
    fn materialized_dory_v3_transition(
        fixture: &DoryV3ReplayFixture,
        transition_index: usize,
    ) -> (
        StructuredTransitionStatement,
        StructuredMaskPolynomial,
        StructuredTransitionWitness,
    ) {
        let challenge = fixture
            .transcript
            .challenge_context(&fixture.block, fixture.claim.nonce)
            .unwrap();
        let (statement, mask, accumulators) = if transition_index == 0 {
            (
                StructuredTransitionStatement {
                    layers: 1,
                    rows: 2,
                    cols: 2,
                    max_abs_accumulator: 125,
                    max_mask: MAX_TRANSITION_MASK,
                },
                StructuredMaskPolynomial::from_dory_v3_virtual_challenge(&challenge.digest(), 2, 2)
                    .unwrap(),
                fixture
                    .base
                    .iter()
                    .map(|value| i64::from(*value) - 125)
                    .collect::<Vec<_>>(),
            )
        } else {
            let bank = transition_index - 1;
            (
                StructuredTransitionStatement {
                    layers: 2,
                    rows: 2,
                    cols: 2,
                    max_abs_accumulator: u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS),
                    max_mask: MAX_TRANSITION_MASK,
                },
                StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
                    &challenge.digest(),
                    u32::try_from(bank * 2).unwrap(),
                    2,
                    2,
                    2,
                )
                .unwrap(),
                fixture.expected_accumulators[bank * 2..bank * 2 + 2]
                    .iter()
                    .flatten()
                    .copied()
                    .map(i64::from)
                    .collect::<Vec<_>>(),
            )
        };
        let mut witness = StructuredTransitionWitness {
            accumulators: Vec::new(),
            masks: Vec::new(),
            encoded: Vec::new(),
            square_quotients: Vec::new(),
            square_remainders: Vec::new(),
            cube_quotients: Vec::new(),
            cube_remainders: Vec::new(),
            output_quotients: Vec::new(),
            output_remainders: Vec::new(),
            negative: Vec::new(),
            activations: Vec::new(),
        };
        for (index, accumulator) in accumulators.into_iter().enumerate() {
            let mask_value = mask
                .value_at_boolean_index_prevalidated(statement, index)
                .unwrap();
            let row =
                derive_transition_regular_row_from_mask(statement, index, accumulator, mask_value)
                    .unwrap();
            witness.accumulators.push(row.accumulator);
            witness.masks.push(row.mask);
            witness.encoded.push(row.encoded);
            witness.square_quotients.push(row.square_quotient);
            witness.square_remainders.push(row.square_remainder);
            witness.cube_quotients.push(row.cube_quotient);
            witness.cube_remainders.push(row.cube_remainder);
            witness.output_quotients.push(row.output_quotient);
            witness.output_remainders.push(row.output_remainder);
            witness.negative.push(row.negative);
            witness.activations.push(row.activation);
        }
        (statement, mask, witness)
    }

    #[cfg(feature = "whir-prototype")]
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

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn dory_v3_streamed_transitions_match_materialized_proofs_and_regeneration() {
        let fixture = dory_v3_replay_fixture_at_variables(0, DORY_V3_TRANSITION_TEST_VARIABLES);
        let replay_scratch = ScratchDirectory::create();
        let materialized_scratch = ScratchDirectory::create();
        let streamed_scratch = ScratchDirectory::create();
        let materialized_logup_scratch = ScratchDirectory::create();
        let streamed_logup_scratch = ScratchDirectory::create();
        let preflight_scratch = ScratchDirectory::create();
        let mismatch_scratch = ScratchDirectory::create();
        let unavailable_scratch = preflight_scratch.path().join("not-created");
        let mut execution = replay_dory_v3(&fixture, &replay_scratch);
        let mut materialized_transitions = Vec::new();

        for transition_index in 0..=2 {
            let (statement, mask, witness) =
                materialized_dory_v3_transition(&fixture, transition_index);
            let binding = format!("dory-v3-streamed-transition-{transition_index}");
            let materialized = prove_bls_dory_transition_deferred_at_variables_with_scratch(
                binding.as_bytes(),
                statement,
                &mask,
                &witness,
                DORY_V3_TRANSITION_TEST_VARIABLES,
                &fixture.setup,
                materialized_scratch.path(),
            )
            .unwrap();
            let mut streamed = {
                let mut reader = execution
                    .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                    .unwrap();
                prove_bls_dory_v3_transition_deferred_from_execution_reader_with_scratch(
                    binding.as_bytes(),
                    &mut reader,
                    transition_index,
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &fixture.setup,
                    streamed_scratch.path(),
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
                streamed.proof.oracle_commitment,
                materialized.proof.oracle_commitment
            );
            assert_eq!(streamed.openings.claims(), materialized.openings.claims());
            assert_eq!(
                streamed.openings.polynomial(0).unwrap().row_commitments(),
                materialized
                    .openings
                    .polynomial(0)
                    .unwrap()
                    .row_commitments()
            );
            let streamed_path = streamed
                .openings
                .polynomial(0)
                .unwrap()
                .coefficient_artifact_path()
                .unwrap()
                .to_path_buf();
            let materialized_path = materialized
                .openings
                .polynomial(0)
                .unwrap()
                .coefficient_artifact_path()
                .unwrap()
                .to_path_buf();
            let streamed_bytes = fs::read(&streamed_path).unwrap();
            assert_eq!(streamed_bytes, fs::read(&materialized_path).unwrap());

            let materialized_range =
                prove_bls_dory_range_logup_deferred_with_precommitted_transition_and_scratch(
                    binding.as_bytes(),
                    statement,
                    &witness,
                    materialized.openings.polynomial(0).unwrap(),
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &fixture.setup,
                    materialized_logup_scratch.path(),
                )
                .unwrap();
            let streamed_range = {
                let mut reader = execution
                    .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                    .unwrap();
                prove_bls_dory_v3_small_range_logup_from_execution_reader_with_scratch(
                    binding.as_bytes(),
                    &mut reader,
                    transition_index,
                    streamed.openings.polynomial(0).unwrap(),
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &fixture.setup,
                    streamed_logup_scratch.path(),
                )
                .unwrap()
            };
            assert_eq!(streamed_range.proof, materialized_range.proof);
            assert_eq!(
                streamed_range.proof.encode_deferred(statement).unwrap(),
                materialized_range.proof.encode_deferred(statement).unwrap()
            );
            assert_eq!(
                streamed_range.proof.transcript_digest,
                materialized_range.proof.transcript_digest
            );
            assert_eq!(
                streamed_range.proof.transition_commitment,
                materialized_range.proof.transition_commitment
            );
            assert_eq!(
                streamed_range.openings.claims(),
                materialized_range.openings.claims()
            );
            drop((streamed_range, materialized_range));

            let released = streamed.openings.release_compact_source().unwrap().unwrap();
            assert!(!streamed_path.exists());
            let regenerated = {
                let mut reader = execution
                    .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                    .unwrap();
                regenerate_bls_dory_v3_transition_compact_source_from_execution_reader_with_scratch(
                    &mut reader,
                    transition_index,
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &released,
                    &fixture.setup,
                    streamed_scratch.path(),
                )
                .unwrap()
            };
            assert_eq!(fs::read(regenerated.path()).unwrap(), streamed_bytes);
            streamed
                .openings
                .restore_compact_source(&regenerated)
                .unwrap();
            drop((regenerated, streamed));
            materialized_transitions.push(materialized);
        }

        let substituted_setup =
            deterministic_bls_dory_setup(DORY_V3_TRANSITION_TEST_VARIABLES + 1).unwrap();
        {
            let mut reader = execution
                .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                .unwrap();
            assert!(matches!(
                prove_bls_dory_v3_transition_deferred_from_execution_reader_with_scratch(
                    b"wrong-index",
                    &mut reader,
                    3,
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &fixture.setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryTransitionError::ExecutionArtifact)
            ));
            assert!(matches!(
                prove_bls_dory_v3_transition_deferred_from_execution_reader_with_scratch(
                    b"wrong-setup",
                    &mut reader,
                    0,
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &substituted_setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryTransitionError::ExecutionArtifact)
            ));
            assert!(matches!(
                prove_bls_dory_v3_transition_deferred_from_execution_reader_with_scratch(
                    &[0; 4_097],
                    &mut reader,
                    0,
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &fixture.setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryTransitionError::PublicBindingTooLarge)
            ));
            assert!(matches!(
                prove_bls_dory_v3_transition_deferred_from_execution_reader_with_scratch(
                    b"packed-too-small",
                    &mut reader,
                    1,
                    DORY_V3_TRANSITION_TEST_VARIABLES - 1,
                    &fixture.setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryTransitionError::InvalidDimensions)
            ));
            assert!(matches!(
                prove_bls_dory_v3_small_range_logup_from_execution_reader_with_scratch(
                    &[0; 4_097],
                    &mut reader,
                    0,
                    materialized_transitions[0].openings.polynomial(0).unwrap(),
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &fixture.setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryRangeLogUpError::PublicBindingTooLarge)
            ));
            assert!(matches!(
                prove_bls_dory_v3_small_range_logup_from_execution_reader_with_scratch(
                    b"wrong-precommitted-transition",
                    &mut reader,
                    1,
                    materialized_transitions[0].openings.polynomial(0).unwrap(),
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &fixture.setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryRangeLogUpError::InvalidDimensions)
            ));
        }
        assert_eq!(preflight_scratch.entry_count(), 0);

        let released_initialization = materialized_transitions[0]
            .openings
            .release_compact_source()
            .unwrap()
            .unwrap();
        {
            let mut reader = execution
                .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                .unwrap();
            assert!(
                regenerate_bls_dory_v3_transition_compact_source_from_execution_reader_with_scratch(
                    &mut reader,
                    1,
                    DORY_V3_TRANSITION_TEST_VARIABLES,
                    &released_initialization,
                    &fixture.setup,
                    mismatch_scratch.path(),
                )
                .is_err()
            );
        }
        assert_eq!(mismatch_scratch.entry_count(), 0);

        drop((released_initialization, materialized_transitions));
        drop(execution);
        assert_eq!(replay_scratch.entry_count(), 0);
        assert_eq!(materialized_scratch.entry_count(), 0);
        assert_eq!(streamed_scratch.entry_count(), 0);
        assert_eq!(materialized_logup_scratch.entry_count(), 0);
        assert_eq!(streamed_logup_scratch.entry_count(), 0);
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn dory_v3_streamed_wiring_matches_materialized_all_links_and_preflights() {
        let fixture = dory_v3_replay_fixture_at_variables(0, DORY_V3_WIRING_TEST_VARIABLES);
        let replay_scratch = ScratchDirectory::create();
        let materialized_scratch = ScratchDirectory::create();
        let streamed_scratch = ScratchDirectory::create();
        let preflight_scratch = ScratchDirectory::create();
        let unavailable_scratch = preflight_scratch.path().join("not-created");
        let statement = StructuredWiringStatement {
            banks: 2,
            layers_per_bank: 2,
            rows: 2,
            cols: 2,
            max_abs_activation: 125,
        };
        let cells = statement.rows * statement.cols;
        let bank_elements = statement.layers_per_bank * cells;
        let (_, _, initialization) = materialized_dory_v3_transition(&fixture, 0);
        let (_, _, first_bank) = materialized_dory_v3_transition(&fixture, 1);
        let (_, _, second_bank) = materialized_dory_v3_transition(&fixture, 2);
        let initial = initialization.activations;
        let mut outputs = first_bank.activations;
        outputs.extend_from_slice(&second_bank.activations);
        let mut inputs = Vec::with_capacity(outputs.len());
        let mut predecessor = initial.clone();
        for output in outputs.chunks_exact(cells) {
            inputs.extend_from_slice(&predecessor);
            predecessor.clear();
            predecessor.extend_from_slice(output);
        }
        assert_eq!(&inputs[..cells], initial.as_slice());
        assert_eq!(
            &inputs[bank_elements..bank_elements + cells],
            &outputs[bank_elements - cells..bank_elements]
        );

        let binding = b"dory-v3-streamed-wiring";
        let materialized = prove_bls_dory_wiring_deferred_at_variables_with_scratch(
            binding,
            statement,
            &initial,
            &inputs,
            &outputs,
            DORY_V3_WIRING_TEST_VARIABLES,
            &fixture.setup,
            materialized_scratch.path(),
        )
        .unwrap();
        let mut execution = replay_dory_v3(&fixture, &replay_scratch);
        let streamed = {
            let challenge = fixture
                .transcript
                .challenge_context(&fixture.block, fixture.claim.nonce)
                .unwrap();
            let mut reader = execution
                .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                .unwrap();
            assert_ne!(
                reader.v3_initialization_mask().unwrap(),
                StructuredMaskPolynomial::from_virtual_challenge(&challenge.digest(), 2, 2)
                    .unwrap()
            );
            for (bank, first_layer) in [0, 2].into_iter().enumerate() {
                assert_ne!(
                    reader.v3_bank_mask(bank).unwrap(),
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
            prove_bls_dory_v3_wiring_deferred_from_execution_reader_with_scratch(
                binding,
                &mut reader,
                DORY_V3_WIRING_TEST_VARIABLES,
                &fixture.setup,
                streamed_scratch.path(),
            )
            .unwrap()
        };

        assert_eq!(streamed.proof, materialized.proof);
        assert_eq!(streamed.openings.claims(), materialized.openings.claims());
        assert_eq!(
            streamed.proof.encode_deferred(statement).unwrap(),
            materialized.proof.encode_deferred(statement).unwrap()
        );
        assert_eq!(
            streamed.openings.polynomial(0).unwrap().row_commitments(),
            materialized
                .openings
                .polynomial(0)
                .unwrap()
                .row_commitments()
        );
        let streamed_compact = streamed
            .openings
            .polynomial(0)
            .unwrap()
            .compact_coefficient_artifact()
            .unwrap();
        let materialized_compact = materialized
            .openings
            .polynomial(0)
            .unwrap()
            .compact_coefficient_artifact()
            .unwrap();
        assert_eq!(streamed_compact.spec().word_scalar_count, 8);
        assert_eq!(streamed_compact.spec().explicit_scalar_count, 40);
        assert_eq!(streamed_compact.dictionary().len(), 251);
        assert_eq!(streamed_compact.spec(), materialized_compact.spec());
        assert_eq!(
            streamed_compact.dictionary(),
            materialized_compact.dictionary()
        );
        let streamed_path = streamed
            .openings
            .polynomial(0)
            .unwrap()
            .coefficient_artifact_path()
            .unwrap();
        let materialized_path = materialized
            .openings
            .polynomial(0)
            .unwrap()
            .coefficient_artifact_path()
            .unwrap();
        assert_eq!(
            fs::read(streamed_path).unwrap(),
            fs::read(materialized_path).unwrap()
        );

        let substituted_setup =
            deterministic_bls_dory_setup(DORY_V3_WIRING_TEST_VARIABLES + 1).unwrap();
        {
            let mut reader = execution
                .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                .unwrap();
            assert!(matches!(
                prove_bls_dory_v3_wiring_deferred_from_execution_reader_with_scratch(
                    b"wrong-setup",
                    &mut reader,
                    DORY_V3_WIRING_TEST_VARIABLES,
                    &substituted_setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryWiringError::ExecutionArtifact)
            ));
            assert!(matches!(
                prove_bls_dory_v3_wiring_deferred_from_execution_reader_with_scratch(
                    &[0; 4_097],
                    &mut reader,
                    DORY_V3_WIRING_TEST_VARIABLES,
                    &fixture.setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryWiringError::PublicBindingTooLarge)
            ));
            assert!(matches!(
                prove_bls_dory_v3_wiring_deferred_from_execution_reader_with_scratch(
                    b"packed-too-small",
                    &mut reader,
                    5,
                    &fixture.setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryWiringError::InvalidDimensions)
            ));
            assert!(matches!(
                prove_bls_dory_v3_wiring_deferred_from_execution_reader_with_scratch(
                    b"packed-too-large",
                    &mut reader,
                    DORY_V3_WIRING_TEST_VARIABLES + 1,
                    &fixture.setup,
                    &unavailable_scratch,
                ),
                Err(BlsDoryWiringError::InvalidDimensions)
            ));
        }
        assert_eq!(preflight_scratch.entry_count(), 0);

        drop((streamed, materialized));
        drop(execution);
        assert_eq!(replay_scratch.entry_count(), 0);
        assert_eq!(materialized_scratch.entry_count(), 0);
        assert_eq!(streamed_scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_activation_encoding_matches_execution_output_boundaries() {
        assert_eq!(encode_dory_v3_activation(-125).unwrap(), 0);
        assert_eq!(encode_dory_v3_activation(0).unwrap(), 125);
        assert_eq!(encode_dory_v3_activation(125).unwrap(), 250);
        assert!(matches!(
            encode_dory_v3_activation(-126),
            Err(BlsDoryV3WinningNonceReplayError::ModelShape)
        ));
        assert!(matches!(
            encode_dory_v3_activation(126),
            Err(BlsDoryV3WinningNonceReplayError::ModelShape)
        ));
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
        read_artifact_column_in_authenticated_chunks(
            &mut artifact,
            BlsDoryExecutionAccumulatorColumn::Initialization,
            &mut actual,
        );
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
                read_artifact_column_in_authenticated_chunks(
                    &mut artifact,
                    BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
                    &mut actual,
                );
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
        assert_eq!(reader.authentication_chunk_cells(), 2);
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
        let verified = reader.reconstruct_verified_final_activation().unwrap();
        assert_eq!(verified.nonce(), fixture.claim.nonce);
        assert_eq!(verified.as_bytes(), fixture.final_activation.as_slice());
        assert_eq!(
            verified.final_activation_digest(),
            fixture.claim.final_activation_digest
        );
        assert_eq!(verified.work_digest(), fixture.claim.work_digest);

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
        reader.final_activation_digest[0] ^= 1;
        assert!(matches!(
            reader.reconstruct_verified_final_activation(),
            Err(BlsDoryV3WinningNonceReplayError::FinalActivationDigest)
        ));
        reader.final_activation_digest = fixture.claim.final_activation_digest;
        reader.work_digest[0] ^= 1;
        assert!(matches!(
            reader.reconstruct_verified_final_activation(),
            Err(BlsDoryV3WinningNonceReplayError::WorkDigest)
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
    fn dory_v3_final_activation_reconstruction_rejects_live_artifact_corruption() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let mut execution = replay_dory_v3(&fixture, &scratch);
        {
            let mut reader = execution
                .authenticated_artifact_reader(&fixture.authenticated, &fixture.setup)
                .unwrap();

            corrupt_final_accumulator_column(&scratch, &reader);
            assert!(matches!(
                reader.reconstruct_verified_final_activation(),
                Err(BlsDoryV3WinningNonceReplayError::ExecutionArtifact(
                    BlsDoryExecutionAccumulatorArtifactError::Authentication
                ))
            ));
            assert!(matches!(
                reader.reconstruct_verified_final_activation(),
                Err(BlsDoryV3WinningNonceReplayError::ExecutionArtifact(
                    BlsDoryExecutionAccumulatorArtifactError::NotAuthenticated
                ))
            ));
        }

        drop(execution);
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_layout_v5_preparation_is_atomic_and_exact_for_bounded_execution() {
        let fixture = dory_v3_layout_v5_replay_fixture(0);
        let fixed_scratch = ScratchDirectory::create();
        let prepared_model =
            prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_for_test_with_scratch(
                Cursor::new(&fixture.bank.bytes),
                &fixture.authenticated,
                &fixture.setup,
                fixed_scratch.path(),
            )
            .unwrap();
        assert_eq!(fixed_scratch.entry_count(), 4);

        let execution_scratch = ScratchDirectory::create();
        let proof_scratch = ScratchDirectory::create();
        let execution = replay_dory_v3(&fixture, &execution_scratch);
        let atomic =
            prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_for_test_with_scratch(
                execution,
                &fixture.authenticated,
                &prepared_model,
                &fixture.block,
                &fixture.setup,
                proof_scratch.path(),
            )
            .unwrap();
        assert_eq!(execution_scratch.entry_count(), 0);

        assert_eq!(atomic.final_activation.nonce(), fixture.claim.nonce);
        assert_eq!(
            atomic.final_activation.as_bytes(),
            fixture.final_activation.as_slice()
        );
        assert_eq!(
            atomic.final_activation.final_activation_digest(),
            fixture.claim.final_activation_digest
        );
        assert_eq!(
            atomic.final_activation.work_digest(),
            fixture.claim.work_digest
        );
        let proof = atomic.prepared.proof_for_test();
        assert_eq!(proof.protocol_version, 5);
        assert_eq!(
            usize::from(proof.padded_variables),
            DORY_V3_LAYOUT_V5_TEST_VARIABLES
        );
        assert_eq!(proof.matrices.len(), 3);
        assert_eq!(proof.transitions.len(), 4);
        assert!(proof.opening_proof.is_empty());
        assert_eq!(atomic.prepared.expected_claim_count_for_test(), 110);
        assert_eq!(
            atomic.prepared.shared_opening_binding().into_bytes(),
            [
                0xeb, 0x33, 0x89, 0x7d, 0xbe, 0xe1, 0x45, 0x83, 0x2c, 0xba, 0xaf, 0x2e, 0x3c, 0x4c,
                0x75, 0xac, 0xb5, 0x39, 0xa7, 0xbc, 0xac, 0x18, 0xc1, 0x75, 0x50, 0xa6, 0xce, 0xa6,
                0xc3, 0xbe, 0x01, 0x09,
            ]
        );
        assert!(proof_scratch.entry_count() > 0);

        drop(prepared_model);
        assert!(fixed_scratch.entry_count() > 0);
        drop(atomic);
        assert_eq!(fixed_scratch.entry_count(), 0);
        assert_eq!(execution_scratch.entry_count(), 0);
        assert_eq!(proof_scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_layout_v5_preparation_rejects_cross_execution_substitution_before_proving() {
        let fixture = dory_v3_layout_v5_replay_fixture(0);
        let other = dory_v3_layout_v5_replay_fixture(1);
        let fixed_scratch = ScratchDirectory::create();
        let prepared_model =
            prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_for_test_with_scratch(
                Cursor::new(&other.bank.bytes),
                &other.authenticated,
                &other.setup,
                fixed_scratch.path(),
            )
            .unwrap();
        let execution_scratch = ScratchDirectory::create();
        let proof_scratch = ScratchDirectory::create();
        let execution = replay_dory_v3(&fixture, &execution_scratch);

        assert!(matches!(
            prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_for_test_with_scratch(
                execution,
                &other.authenticated,
                &prepared_model,
                &other.block,
                &other.setup,
                proof_scratch.path(),
            ),
            Err(BlsDoryV3LayoutV5PreparationError::Replay(
                BlsDoryV3WinningNonceReplayError::ExecutionArtifact(
                    BlsDoryExecutionAccumulatorArtifactError::WrongContext
                )
            ))
        ));
        assert_eq!(execution_scratch.entry_count(), 0);
        assert_eq!(proof_scratch.entry_count(), 0);
        assert_eq!(fixed_scratch.entry_count(), 4);

        let execution = replay_dory_v3(&fixture, &execution_scratch);
        assert!(matches!(
            prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_for_test_with_scratch(
                execution,
                &fixture.authenticated,
                &prepared_model,
                &fixture.block,
                &fixture.setup,
                proof_scratch.path(),
            ),
            Err(BlsDoryV3LayoutV5PreparationError::Layout(
                BlsDorySharedLayoutError::V3Context
            ))
        ));
        assert_eq!(execution_scratch.entry_count(), 0);
        assert_eq!(proof_scratch.entry_count(), 0);
        drop(prepared_model);
        assert_eq!(fixed_scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_layout_v5_preparation_rejects_invalid_proof_scratch_before_reading_execution() {
        let fixture = dory_v3_layout_v5_replay_fixture(0);
        let fixed_scratch = ScratchDirectory::create();
        let prepared_model =
            prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_for_test_with_scratch(
                Cursor::new(&fixture.bank.bytes),
                &fixture.authenticated,
                &fixture.setup,
                fixed_scratch.path(),
            )
            .unwrap();
        let execution_scratch = ScratchDirectory::create();
        let execution = replay_dory_v3(&fixture, &execution_scratch);

        assert!(matches!(
            prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_for_test_with_scratch(
                execution,
                &fixture.authenticated,
                &prepared_model,
                &fixture.block,
                &fixture.setup,
                Path::new("relative-proof-scratch"),
            ),
            Err(BlsDoryV3LayoutV5PreparationError::Replay(
                BlsDoryV3WinningNonceReplayError::ScratchDirectory
            ))
        ));
        assert_eq!(execution_scratch.entry_count(), 0);
        assert_eq!(fixed_scratch.entry_count(), 4);

        drop(prepared_model);
        assert_eq!(fixed_scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_layout_v5_preparation_rejects_block_substitution_before_proving() {
        let fixture = dory_v3_layout_v5_replay_fixture(0);
        let fixed_scratch = ScratchDirectory::create();
        let prepared_model =
            prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_for_test_with_scratch(
                Cursor::new(&fixture.bank.bytes),
                &fixture.authenticated,
                &fixture.setup,
                fixed_scratch.path(),
            )
            .unwrap();
        let execution_scratch = ScratchDirectory::create();
        let proof_scratch = ScratchDirectory::create();
        let execution = replay_dory_v3(&fixture, &execution_scratch);
        let mut substituted_block = fixture.block;
        substituted_block.timestamp += 1;

        assert!(matches!(
            prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_for_test_with_scratch(
                execution,
                &fixture.authenticated,
                &prepared_model,
                &substituted_block,
                &fixture.setup,
                proof_scratch.path(),
            ),
            Err(BlsDoryV3LayoutV5PreparationError::Replay(
                BlsDoryV3WinningNonceReplayError::Context
            ))
        ));
        assert_eq!(execution_scratch.entry_count(), 0);
        assert_eq!(proof_scratch.entry_count(), 0);

        drop(prepared_model);
        assert_eq!(fixed_scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_layout_v5_candidate_public_authority_rejects_every_substitution() {
        let fixture = dory_v3_replay_fixture(0);
        let challenge = fixture
            .transcript
            .challenge_context(&fixture.block, fixture.claim.nonce)
            .unwrap();
        let (v5_context, v5_proof) =
            bls_dory_shared_layout_v5_candidate_codec_fixture_for_test(0x71);
        let composed = |challenge, work_digest, proof: BlsDorySharedLayoutV5Proof| {
            ComposedBlsDoryV3LayoutV5Execution {
                challenge,
                nonce: fixture.claim.nonce,
                final_activation_digest: fixture.claim.final_activation_digest,
                work_digest,
                proof,
                encoded_native_proof: vec![0xa6, 0xa7, 0xa8],
            }
        };
        let proof = seal_composed_bls_dory_v3_layout_v5_candidate_after_authority(
            composed(challenge, fixture.claim.work_digest, v5_proof.clone()),
            fixture.transcript,
            &fixture.block,
            &v5_context,
        )
        .unwrap();
        assert_eq!(proof.algorithm_version, DORY_V3_ALGORITHM_VERSION);
        assert_eq!(proof.proof_version, DORY_V3_PROOF_VERSION);
        assert_eq!(
            proof.model_manifest_digest,
            fixture.transcript.manifest_digest().into_bytes()
        );
        assert_eq!(proof.challenge_digest, challenge.digest());
        let (decoded_v5_proof, decoded_payload) =
            decode_dory_v3_layout_v5_candidate_payload(&proof.structured_proof, &v5_context)
                .unwrap();
        assert_eq!(decoded_v5_proof, v5_proof);
        assert_eq!(decoded_payload.native_blake3_proof, vec![0xa6, 0xa7, 0xa8]);
        assert_eq!(decoded_payload.encode().unwrap(), proof.structured_proof);
        validate_dory_v3_layout_v5_candidate_statement_for_test(
            fixture.block.network_id,
            &fixture.authenticated,
            &fixture.block,
            &proof,
            &fixture.setup,
        )
        .unwrap();

        // This test-only authority bypasses only the 25 GiB production-bank
        // geometry check. It runs the same post-authority statement validator
        // used by ProductionV3. Rebuild every target-bound public digest so
        // HighHash, rather than an earlier binding check, is the rejection.
        let mut above = fixture.block;
        above.target = [0; 32];
        let above_challenge = fixture
            .transcript
            .challenge_context(&above, proof.nonce)
            .unwrap();
        let above_final_activation_digest = [0x5a; 32];
        let above_proof = ForgeMatrixV3CandidateProof {
            algorithm_version: DORY_V3_ALGORITHM_VERSION,
            proof_version: DORY_V3_PROOF_VERSION,
            nonce: proof.nonce,
            model_manifest_digest: fixture.transcript.manifest_digest().into_bytes(),
            challenge_digest: above_challenge.digest(),
            final_activation_digest: above_final_activation_digest,
            work_digest: fixture
                .transcript
                .work_digest(above_challenge.digest(), above_final_activation_digest),
            structured_proof: vec![1],
        };
        assert!(above_proof.work_digest > above.target);
        let above_block_proof = BlockProof::V3Candidate(Box::new(above_proof));
        let BlockProof::V3Candidate(above_proof) = &above_block_proof else {
            unreachable!();
        };
        reset_layout_v5_relation_dispatches_for_test();
        assert!(matches!(
            verify_bls_dory_v3_layout_v5_candidate_relation_for_test(
                fixture.block.network_id,
                &fixture.authenticated,
                &above,
                above_proof,
                &fixture.setup,
            ),
            Err(BlsDoryV3CandidateError::HighHash)
        ));
        assert_eq!(layout_v5_relation_dispatches_for_test(), 0);

        // This is an authenticated, correctly bound V3 block-proof envelope.
        // The small fixture cannot satisfy the production n=33 relation, but
        // it must cross the exact production relation-dispatch point once;
        // unlike the old statement-identity stub, the real context/decoder
        // path owns the resulting fail-closed error.
        let mut relation_envelope = proof.clone();
        relation_envelope.structured_proof = vec![1];
        let block_proof = BlockProof::V3Candidate(Box::new(relation_envelope));
        let BlockProof::V3Candidate(relation_proof) = &block_proof else {
            unreachable!();
        };
        assert!(relation_proof.work_digest <= fixture.block.target);
        reset_layout_v5_relation_dispatches_for_test();
        let relation_result = verify_bls_dory_v3_layout_v5_candidate_relation_for_test(
            fixture.block.network_id,
            &fixture.authenticated,
            &fixture.block,
            relation_proof,
            &fixture.setup,
        );
        let relation_error = match relation_result {
            Err(error) => error,
            Ok(_) => panic!("small fixture must fail closed"),
        };
        assert!(
            matches!(relation_error, BlsDoryV3CandidateError::Dory(_)),
            "unexpected relation error: {relation_error:?}"
        );
        assert_eq!(layout_v5_relation_dispatches_for_test(), 1);

        let mut wrong_network = fixture.block;
        wrong_network.network_id[0] ^= 1;
        assert!(matches!(
            validate_dory_v3_layout_v5_candidate_statement_for_test(
                fixture.block.network_id,
                &fixture.authenticated,
                &wrong_network,
                &proof,
                &fixture.setup,
            ),
            Err(BlsDoryV3CandidateError::WrongNetwork)
        ));
        let mut substituted_block = fixture.block;
        substituted_block.timestamp += 1;
        assert!(matches!(
            validate_dory_v3_layout_v5_candidate_statement_for_test(
                fixture.block.network_id,
                &fixture.authenticated,
                &substituted_block,
                &proof,
                &fixture.setup,
            ),
            Err(BlsDoryV3CandidateError::ChallengeDigest)
        ));
        let mutations: [fn(&mut ForgeMatrixV3CandidateProof); 8] = [
            |candidate: &mut ForgeMatrixV3CandidateProof| candidate.algorithm_version ^= 1,
            |candidate: &mut ForgeMatrixV3CandidateProof| candidate.proof_version ^= 1,
            |candidate: &mut ForgeMatrixV3CandidateProof| candidate.nonce ^= 1,
            |candidate: &mut ForgeMatrixV3CandidateProof| candidate.model_manifest_digest[0] ^= 1,
            |candidate: &mut ForgeMatrixV3CandidateProof| candidate.challenge_digest[0] ^= 1,
            |candidate: &mut ForgeMatrixV3CandidateProof| candidate.final_activation_digest[0] ^= 1,
            |candidate: &mut ForgeMatrixV3CandidateProof| candidate.work_digest[0] ^= 1,
            |candidate: &mut ForgeMatrixV3CandidateProof| candidate.structured_proof.clear(),
        ];
        for mutate in mutations {
            let mut substituted = proof.clone();
            mutate(&mut substituted);
            assert!(
                validate_dory_v3_layout_v5_candidate_statement_for_test(
                    fixture.block.network_id,
                    &fixture.authenticated,
                    &fixture.block,
                    &substituted,
                    &fixture.setup,
                )
                .is_err()
            );
        }

        let substituted_record = dory_v3_replay_fixture(1);
        assert!(
            validate_dory_v3_layout_v5_candidate_statement_for_test(
                fixture.block.network_id,
                &substituted_record.authenticated,
                &fixture.block,
                &proof,
                &fixture.setup,
            )
            .is_err()
        );

        let substituted_setup = deterministic_bls_dory_setup(DORY_V3_TEST_VARIABLES + 1).unwrap();
        assert!(matches!(
            validate_dory_v3_layout_v5_candidate_statement_for_test(
                fixture.block.network_id,
                &fixture.authenticated,
                &fixture.block,
                &proof,
                &substituted_setup,
            ),
            Err(BlsDoryV3CandidateError::DoryV3Record(
                DoryV3ModelCommitmentRecordError::SetupIdentityMismatch
            ))
        ));

        let substituted_challenge = fixture
            .transcript
            .challenge_context(&fixture.block, fixture.claim.nonce + 1)
            .unwrap();
        assert!(matches!(
            seal_composed_bls_dory_v3_layout_v5_candidate_after_authority(
                composed(
                    substituted_challenge,
                    fixture.claim.work_digest,
                    v5_proof.clone()
                ),
                fixture.transcript,
                &fixture.block,
                &v5_context,
            ),
            Err(BlsDoryV3CandidateError::ChallengeDigest)
        ));
        let mut substituted_work = fixture.claim.work_digest;
        substituted_work[0] ^= 1;
        assert!(matches!(
            seal_composed_bls_dory_v3_layout_v5_candidate_after_authority(
                composed(challenge, substituted_work, v5_proof.clone()),
                fixture.transcript,
                &fixture.block,
                &v5_context,
            ),
            Err(BlsDoryV3CandidateError::WorkDigest)
        ));
        assert!(matches!(
            seal_composed_bls_dory_v3_layout_v5_candidate_after_authority(
                composed(challenge, fixture.claim.work_digest, v5_proof.clone()),
                fixture.transcript,
                &substituted_block,
                &v5_context,
            ),
            Err(BlsDoryV3CandidateError::ChallengeDigest)
        ));

        let (substituted_context, _) =
            bls_dory_shared_layout_v5_candidate_codec_fixture_for_test(0x72);
        assert!(matches!(
            seal_composed_bls_dory_v3_layout_v5_candidate_after_authority(
                composed(challenge, fixture.claim.work_digest, v5_proof.clone()),
                fixture.transcript,
                &fixture.block,
                &substituted_context,
            ),
            Err(BlsDoryV3CandidateError::Dory(
                BlsDorySharedLayoutError::V3Context
            ))
        ));

        assert!(matches!(
            seal_composed_bls_dory_v3_layout_v5_candidate(
                composed(challenge, fixture.claim.work_digest, v5_proof.clone()),
                &fixture.authenticated,
                &fixture.block,
                &fixture.setup,
            ),
            Err(BlsDoryV3CandidateError::DoryV3Record(_))
        ));
        assert!(matches!(
            seal_composed_bls_dory_v3_layout_v5_candidate(
                composed(challenge, fixture.claim.work_digest, v5_proof.clone()),
                &fixture.authenticated,
                &fixture.block,
                &substituted_setup,
            ),
            Err(BlsDoryV3CandidateError::DoryV3Record(
                DoryV3ModelCommitmentRecordError::SetupIdentityMismatch
            ))
        ));

        let mut low_target_block = fixture.block;
        low_target_block.target = [0; 32];
        let low_target_challenge = fixture
            .transcript
            .challenge_context(&low_target_block, fixture.claim.nonce)
            .unwrap();
        let low_target_work =
            low_target_challenge.work_digest(fixture.claim.final_activation_digest);
        assert_ne!(low_target_work, [0; 32]);
        assert!(matches!(
            seal_composed_bls_dory_v3_layout_v5_candidate_after_authority(
                composed(low_target_challenge, low_target_work, v5_proof),
                fixture.transcript,
                &low_target_block,
                &v5_context,
            ),
            Err(BlsDoryV3CandidateError::HighHash)
        ));

        let mut trailing = proof.clone();
        trailing.structured_proof.push(0);
        assert!(matches!(
            decode_dory_v3_layout_v5_candidate_payload(&trailing.structured_proof, &v5_context),
            Err(BlsDoryV3CandidateError::Payload)
        ));

        type SealEntry = fn(
            ComposedBlsDoryV3LayoutV5Execution,
            &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
            &BlockChallenge,
            &DeterministicBlsDorySetup,
        )
            -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError>;
        let seal: SealEntry = seal_composed_bls_dory_v3_layout_v5_candidate;
        let _ = seal;
    }

    #[test]
    fn dory_v3_layout_v5_composition_derives_and_reauthenticates_the_private_bridge() {
        let fixture = dory_v3_layout_v5_replay_fixture(0);
        let fixed_scratch = ScratchDirectory::create();
        let prepared_model =
            prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_for_test_with_scratch(
                Cursor::new(&fixture.bank.bytes),
                &fixture.authenticated,
                &fixture.setup,
                fixed_scratch.path(),
            )
            .unwrap();
        let execution_scratch = ScratchDirectory::create();
        let proof_scratch = ScratchDirectory::create();
        let execution = replay_dory_v3(&fixture, &execution_scratch);
        let mut atomic =
            prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_for_test_with_scratch(
                execution,
                &fixture.authenticated,
                &prepared_model,
                &fixture.block,
                &fixture.setup,
                proof_scratch.path(),
            )
            .unwrap();
        assert_eq!(execution_scratch.entry_count(), 0);

        let bridge = validated_dory_v3_layout_v5_output_bridge(&atomic, &fixture.setup).unwrap();
        assert_eq!(
            bridge.challenge_digest(),
            atomic.final_activation.context.challenge.digest()
        );
        assert_eq!(
            bridge.final_activation_digest(),
            fixture.claim.final_activation_digest
        );
        assert_eq!(
            bridge.final_activation_len(),
            fixture.final_activation.len()
        );
        bridge
            .validate_activation(atomic.final_activation.as_bytes())
            .unwrap();

        atomic.final_activation.activation[0] ^= 1;
        assert!(matches!(
            validated_dory_v3_layout_v5_output_bridge(&atomic, &fixture.setup),
            Err(BlsDoryV3LayoutV5CompositionError::ReplayAuthority(
                BlsDoryV3WinningNonceReplayError::FinalActivationDigest
            ))
        ));
        atomic.final_activation.activation[0] ^= 1;

        atomic.final_activation.final_activation_digest[0] ^= 1;
        assert!(matches!(
            validated_dory_v3_layout_v5_output_bridge(&atomic, &fixture.setup),
            Err(BlsDoryV3LayoutV5CompositionError::ReplayAuthority(
                BlsDoryV3WinningNonceReplayError::FinalActivationDigest
            ))
        ));
        atomic.final_activation.final_activation_digest[0] ^= 1;

        atomic.final_activation.work_digest[0] ^= 1;
        assert!(matches!(
            validated_dory_v3_layout_v5_output_bridge(&atomic, &fixture.setup),
            Err(BlsDoryV3LayoutV5CompositionError::ReplayAuthority(
                BlsDoryV3WinningNonceReplayError::WorkDigest
            ))
        ));
        atomic.final_activation.work_digest[0] ^= 1;

        let substituted_setup =
            deterministic_bls_dory_setup(DORY_V3_LAYOUT_V5_TEST_VARIABLES + 1).unwrap();
        assert!(matches!(
            validated_dory_v3_layout_v5_output_bridge(&atomic, &substituted_setup),
            Err(BlsDoryV3LayoutV5CompositionError::ReplayAuthority(
                BlsDoryV3WinningNonceReplayError::Context
            ))
        ));
        assert!(matches!(
            preflight_prepared_bls_dory_shared_layout_v5_composition(
                &atomic.prepared,
                &fixture.setup
            ),
            Err(BlsDorySharedLayoutError::V3Context)
        ));
        assert!(matches!(
            validate_dory_v3_layout_v5_composition_configuration(Path::new("relative"), 1),
            Err(BlsDoryV3LayoutV5CompositionError::Configuration)
        ));
        assert!(matches!(
            validate_dory_v3_layout_v5_composition_configuration(proof_scratch.path(), 0),
            Err(BlsDoryV3LayoutV5CompositionError::Configuration)
        ));
        assert!(matches!(
            finish_prepared_bls_dory_v3_layout_v5_execution_with_composition(
                atomic,
                &fixture.setup,
                proof_scratch.path(),
                1,
            ),
            Err(BlsDoryV3LayoutV5CompositionError::Layout(
                BlsDorySharedLayoutError::V3Context
            ))
        ));
        assert_eq!(execution_scratch.entry_count(), 0);
        assert_eq!(proof_scratch.entry_count(), 0);
        assert_eq!(fixed_scratch.entry_count(), 4);
        drop(prepared_model);
        assert_eq!(fixed_scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_derived_claim_matches_reference_and_replay_and_cleans_artifact() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let claim = derive_dory_v3_winning_nonce_claim_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &fixture.block,
            fixture.claim.nonce,
            &fixture.setup,
            Cursor::new(&fixture.bank.bytes),
            scratch.path(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(claim, fixture.claim);
        assert_eq!(scratch.entry_count(), 0);

        let execution = replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &fixture.block,
            claim,
            &fixture.setup,
            Cursor::new(&fixture.bank.bytes),
            scratch.path(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(execution.nonce(), claim.nonce);
        assert_eq!(
            execution.final_activation_digest(),
            claim.final_activation_digest
        );
        assert_eq!(execution.work_digest(), claim.work_digest);
        drop(execution);
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_accelerated_replay_matches_the_cpu_replay() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let cancel = AtomicBool::new(false);
        let cpu = replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &fixture.block,
            fixture.claim,
            &fixture.setup,
            Cursor::new(&fixture.bank.bytes),
            scratch.path(),
            &cancel,
        )
        .unwrap();

        let layers = DORY_V3_TEST_LAYERS
            .into_iter()
            .map(Vec::from)
            .collect::<Vec<_>>();
        let (_, _, layer_accumulators) = evaluate_dory_v3_test_reference(
            &fixture.base,
            &layers,
            fixture.transcript,
            &fixture.block,
            fixture.claim.nonce,
        );
        let flat = layer_accumulators
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        let accelerated =
            replay_dory_v3_winning_nonce_from_bank_authenticated_record_accelerated_for_test(
                &fixture.authenticated,
                fixture.transcript,
                &fixture.block,
                fixture.claim,
                &fixture.setup,
                Cursor::new(&fixture.bank.bytes),
                scratch.path(),
                BlsDoryV3AcceleratedReplayAccumulators::new(flat),
                &cancel,
            )
            .unwrap();
        assert_eq!(accelerated.nonce(), cpu.nonce());
        assert_eq!(
            accelerated.final_activation_digest(),
            cpu.final_activation_digest()
        );
        assert_eq!(accelerated.work_digest(), cpu.work_digest());
        drop(cpu);
        drop(accelerated);
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_accelerated_replay_rejects_wrong_or_misshapen_accumulators() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let cancel = AtomicBool::new(false);
        let layers = DORY_V3_TEST_LAYERS
            .into_iter()
            .map(Vec::from)
            .collect::<Vec<_>>();
        let (_, _, layer_accumulators) = evaluate_dory_v3_test_reference(
            &fixture.base,
            &layers,
            fixture.transcript,
            &fixture.block,
            fixture.claim.nonce,
        );
        let flat = layer_accumulators
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        // A wrong final-layer accumulator changes the derived activation, so
        // the CPU-recomputed digest refuses the claim.
        let mut tampered_final = flat.clone();
        let last = tampered_final.len() - 1;
        tampered_final[last] += 1;
        assert!(
            replay_dory_v3_winning_nonce_from_bank_authenticated_record_accelerated_for_test(
                &fixture.authenticated,
                fixture.transcript,
                &fixture.block,
                fixture.claim,
                &fixture.setup,
                Cursor::new(&fixture.bank.bytes),
                scratch.path(),
                BlsDoryV3AcceleratedReplayAccumulators::new(tampered_final),
                &cancel,
            )
            .is_err()
        );
        assert_eq!(scratch.entry_count(), 0);

        // An out-of-bound accumulator is refused before it reaches the
        // artifact.
        let mut out_of_bound = flat.clone();
        out_of_bound[0] = i32::MAX;
        assert!(
            replay_dory_v3_winning_nonce_from_bank_authenticated_record_accelerated_for_test(
                &fixture.authenticated,
                fixture.transcript,
                &fixture.block,
                fixture.claim,
                &fixture.setup,
                Cursor::new(&fixture.bank.bytes),
                scratch.path(),
                BlsDoryV3AcceleratedReplayAccumulators::new(out_of_bound),
                &cancel,
            )
            .is_err()
        );
        assert_eq!(scratch.entry_count(), 0);

        // A wrong column count is refused before the bank is read.
        let mut truncated = flat;
        truncated.pop();
        let shape_error =
            replay_dory_v3_winning_nonce_from_bank_authenticated_record_accelerated_for_test(
                &fixture.authenticated,
                fixture.transcript,
                &fixture.block,
                fixture.claim,
                &fixture.setup,
                Cursor::new(&fixture.bank.bytes),
                scratch.path(),
                BlsDoryV3AcceleratedReplayAccumulators::new(truncated),
                &cancel,
            )
            .err();
        assert!(matches!(
            shape_error,
            Some(BlsDoryV3WinningNonceReplayError::ModelShape)
        ));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_derivation_checks_target_after_exact_execution_and_cleans_artifact() {
        let fixture = dory_v3_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let mut high_block = fixture.block;
        high_block.target = [0; 32];
        let layers = DORY_V3_TEST_LAYERS
            .into_iter()
            .map(Vec::from)
            .collect::<Vec<_>>();
        let (expected, _, _) = evaluate_dory_v3_test_reference(
            &fixture.base,
            &layers,
            fixture.transcript,
            &high_block,
            fixture.claim.nonce,
        );
        assert_ne!(expected.work_digest, high_block.target);

        let error = derive_dory_v3_winning_nonce_claim_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &high_block,
            fixture.claim.nonce,
            &fixture.setup,
            Cursor::new(&fixture.bank.bytes),
            scratch.path(),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(matches!(error, BlsDoryV3WinningNonceReplayError::HighHash));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_derivation_context_and_cancellation_precede_model_reads() {
        let fixture = dory_v3_replay_fixture(0);
        let other = dory_v3_replay_fixture(1);
        let scratch = ScratchDirectory::create();

        let context_error =
            derive_dory_v3_winning_nonce_claim_from_bank_authenticated_record_for_test(
                &other.authenticated,
                fixture.transcript,
                &fixture.block,
                fixture.claim.nonce,
                &other.setup,
                PanicReader,
                scratch.path(),
                &AtomicBool::new(false),
            )
            .unwrap_err();
        assert!(matches!(
            context_error,
            BlsDoryV3WinningNonceReplayError::Context
        ));

        let cancelled = derive_dory_v3_winning_nonce_claim_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &fixture.block,
            fixture.claim.nonce,
            &fixture.setup,
            PanicReader,
            scratch.path(),
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert!(matches!(
            cancelled,
            BlsDoryV3WinningNonceReplayError::Cancelled
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
            BlsDoryV3WinningNonceExpectation::Verify(fixture.claim),
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
    fn dory_v3_candidate_prevalidation_precedes_both_bank_reads() {
        let fixture = dory_v3_layout_v5_replay_fixture(0);
        let scratch = ScratchDirectory::create();
        let prove = |block: &BlockChallenge, claim: BlsDoryV3WinningNonceClaim| {
            prove_bls_dory_v3_layout_v5_candidate_from_winning_nonce_claim(
                &fixture.authenticated,
                block,
                claim,
                &fixture.setup,
                PanicReader,
                PanicReader,
                scratch.path(),
                1,
                &AtomicBool::new(false),
            )
            .unwrap_err()
        };

        let mut wrong_claim = fixture.claim;
        wrong_claim.work_digest[0] ^= 1;
        assert!(matches!(
            prove(&fixture.block, wrong_claim),
            BlsDoryV3CandidateError::WinningNonceReplay(
                BlsDoryV3WinningNonceReplayError::WorkDigest
            )
        ));

        let mut stale_block = fixture.block;
        stale_block.timestamp += 1;
        assert!(matches!(
            prove(&stale_block, fixture.claim),
            BlsDoryV3CandidateError::WinningNonceReplay(
                BlsDoryV3WinningNonceReplayError::WorkDigest
            )
        ));

        let mut changed_target = fixture.block;
        changed_target.target = [0; 32];
        let changed_target_challenge = fixture
            .transcript
            .challenge_context(&changed_target, fixture.claim.nonce)
            .unwrap();
        let changed_target_claim = BlsDoryV3WinningNonceClaim {
            nonce: fixture.claim.nonce,
            final_activation_digest: fixture.claim.final_activation_digest,
            work_digest: changed_target_challenge
                .work_digest(fixture.claim.final_activation_digest),
        };
        assert_ne!(changed_target_claim.work_digest, changed_target.target);
        assert!(matches!(
            prove(&changed_target, changed_target_claim),
            BlsDoryV3CandidateError::WinningNonceReplay(BlsDoryV3WinningNonceReplayError::HighHash)
        ));
        assert_eq!(scratch.entry_count(), 0);
    }

    #[test]
    fn dory_v3_prepared_model_streams_once_and_revalidates_each_job_before_replay_reads() {
        let fixture = dory_v3_layout_v5_replay_fixture(0);
        let fixed_scratch = ScratchDirectory::create();
        let fixed_bytes_read = Arc::new(AtomicUsize::new(0));
        let prepared_model =
            prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_for_test_with_scratch(
                CountingReader {
                    inner: Cursor::new(&fixture.bank.bytes),
                    bytes_read: Arc::clone(&fixed_bytes_read),
                },
                &fixture.authenticated,
                &fixture.setup,
                fixed_scratch.path(),
            )
            .unwrap();
        assert_eq!(
            fixed_bytes_read.load(Ordering::Relaxed),
            fixture.bank.bytes.len()
        );
        let fixed_stream_bytes = fixed_bytes_read.load(Ordering::Relaxed);
        let proof_scratch = ScratchDirectory::create();
        let prove = |block: &BlockChallenge, claim: BlsDoryV3WinningNonceClaim| {
            prove_bls_dory_v3_layout_v5_candidate_from_prepared_fixed_model(
                &fixture.authenticated,
                block,
                claim,
                &fixture.setup,
                &prepared_model,
                PanicReader,
                proof_scratch.path(),
                1,
                &AtomicBool::new(false),
            )
            .unwrap_err()
        };

        let mut stale_block = fixture.block;
        stale_block.previous_block[0] ^= 1;
        assert!(matches!(
            prove(&stale_block, fixture.claim),
            BlsDoryV3CandidateError::WinningNonceReplay(
                BlsDoryV3WinningNonceReplayError::WorkDigest
            )
        ));

        let mut changed_target = fixture.block;
        changed_target.target = [0; 32];
        let changed_target_challenge = fixture
            .transcript
            .challenge_context(&changed_target, fixture.claim.nonce)
            .unwrap();
        let changed_target_claim = BlsDoryV3WinningNonceClaim {
            nonce: fixture.claim.nonce,
            final_activation_digest: fixture.claim.final_activation_digest,
            work_digest: changed_target_challenge
                .work_digest(fixture.claim.final_activation_digest),
        };
        assert_ne!(changed_target_claim.work_digest, changed_target.target);
        assert!(matches!(
            prove(&changed_target, changed_target_claim),
            BlsDoryV3CandidateError::WinningNonceReplay(BlsDoryV3WinningNonceReplayError::HighHash)
        ));

        let mut wrong_claim = fixture.claim;
        wrong_claim.work_digest[0] ^= 1;
        assert!(matches!(
            prove(&fixture.block, wrong_claim),
            BlsDoryV3CandidateError::WinningNonceReplay(
                BlsDoryV3WinningNonceReplayError::WorkDigest
            )
        ));

        let execution_scratch = ScratchDirectory::create();
        let replay_error = replay_dory_v3_winning_nonce_from_bank_authenticated_record_for_test(
            &fixture.authenticated,
            fixture.transcript,
            &stale_block,
            fixture.claim,
            &fixture.setup,
            PanicReader,
            execution_scratch.path(),
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(matches!(
            replay_error,
            BlsDoryV3WinningNonceReplayError::WorkDigest
        ));
        assert_eq!(proof_scratch.entry_count(), 0);
        assert_eq!(execution_scratch.entry_count(), 0);
        assert_eq!(fixed_scratch.entry_count(), 4);
        assert_eq!(fixed_bytes_read.load(Ordering::Relaxed), fixed_stream_bytes);
        drop(prepared_model);
        assert_eq!(fixed_scratch.entry_count(), 0);
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
        let raw_context = *context.raw_for_test();
        let mut writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(scratch.path(), raw_context)
                .unwrap();
        let zero_chunk = vec![0; raw_context.authentication_chunk_cells()];
        let chunks_per_column =
            raw_context.cells_per_column() / raw_context.authentication_chunk_cells();
        for _ in 0..chunks_per_column {
            writer
                .write_column_chunk(
                    BlsDoryExecutionAccumulatorColumn::Initialization,
                    &zero_chunk,
                )
                .unwrap();
        }
        for bank in 0..raw_context.banks() {
            for layer in 0..raw_context.layers_per_bank() {
                for _ in 0..chunks_per_column {
                    writer
                        .write_column_chunk(
                            BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
                            &zero_chunk,
                        )
                        .unwrap();
                }
            }
        }
        assert_eq!(scratch.entry_count(), 1);
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
