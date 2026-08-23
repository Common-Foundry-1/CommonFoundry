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
    dory_bls12_381_execution_artifact::{
        BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS, BlsDoryExecutionAccumulatorArtifact,
        BlsDoryExecutionAccumulatorArtifactContext, BlsDoryExecutionAccumulatorArtifactError,
        BlsDoryExecutionAccumulatorArtifactWriter, BlsDoryExecutionAccumulatorColumn,
    },
    dory_bls12_381_layout::signed_model_value,
    dory_bls12_381_transition::{BlsDoryTransitionError, derive_transition_regular_row_from_mask},
    forgematrix_v2::{V2_MODEL_VALUE_CENTER, output_digest, work_digest_from_roots},
    model_bank::{
        ModelBankError, ModelBankFieldStreamError, ModelBankManifest, ModelFieldChunk,
        ModelPcsIdentity, ModelPcsRole, StagedModelFieldSink, VerifiedModelBankReceipt,
        verify_model_bank_into_staged_field_sink,
    },
    structured_transition::{
        StructuredMaskPolynomial, StructuredTransitionError, StructuredTransitionStatement,
    },
};

const MAX_TRANSITION_MASK: u64 = 5_000;

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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{self, Cursor, Read},
        path::{Path, PathBuf},
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    };

    use rayon::ThreadPoolBuilder;

    use super::*;
    use crate::{
        BlockChallenge, ForgeMatrixV2Descriptor, ForgeMatrixV2Reference,
        ForgeMatrixV2ReferenceProof, SmallModelBankFixture,
        dory_bls12_381_execution_artifact::BlsDoryExecutionAccumulatorColumn,
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
}
