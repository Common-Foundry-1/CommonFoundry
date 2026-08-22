//! Canonical shared-layout boundary for the BLS12-381 proof components.
//!
//! Matrix, transition, and wiring commitments must use one variable count before
//! their openings can be reduced by a single Dory aggregate. This module pins
//! the production n=33 geometry, composes transition arithmetic with the range
//! checkpoint against one commitment, and binds every component opening into a
//! single aggregate.

use std::io::{Cursor, Read};

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use thiserror::Error;

use crate::{
    ModelBankFieldStreamError, ModelBankManifest, ModelFieldChunk, ModelPcsIdentity, ModelPcsRole,
    STRUCTURED_TRANSITION_ACTIVATION_ORACLE, STRUCTURED_TRANSITION_INPUT_ORACLE,
    STRUCTURED_TRANSITION_ORACLES, StagedModelFieldSink, StructuredMaskPolynomial,
    StructuredMatrixStatement, StructuredTransitionStatement, StructuredTransitionWitness,
    StructuredWiringStatement, VerifiedModelBankReceipt,
    dory_bls12_381_aggregate::{
        BlsDoryAggregateError, BlsDoryCommittedPolynomial, BlsDoryDeferredOpeningSet,
        BlsDoryOpeningClaim, MAX_BLS_DORY_AGGREGATE_BYTES, commit_bls_dory_polynomial,
        projected_bls_dory_aggregate_bytes, prove_bls_dory_deferred_opening_sets,
        verify_bls_dory_openings,
    },
    dory_bls12_381_logup::{
        BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS, BlsDoryRangeLogUpError, BlsDoryRangeLogUpProof,
        PreparedBlsDoryRangeLogUpProof, projected_production_range_logup_opening_bytes,
        projected_production_range_logup_proof_bytes, prove_bls_dory_range_logup,
        prove_bls_dory_range_logup_at_variables, prove_bls_dory_range_logup_deferred_at_variables,
        verify_bls_dory_range_logup, verify_bls_dory_range_logup_at_variables,
        verify_bls_dory_range_logup_deferred_at_variables,
    },
    dory_bls12_381_matrix::{
        BlsDoryMatrixError, BlsDoryMatrixProof, PreparedBlsDoryMatrixProof,
        projected_production_matrix_opening_bytes, projected_production_matrix_proof_bytes,
        prove_bls_dory_matrix_deferred_at_variables, verify_bls_dory_matrix_deferred_at_variables,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryG1, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    dory_bls12_381_transition::{
        BLS_DORY_TRANSITION_OPENING_CLAIMS, BlsDoryTransitionError, BlsDoryTransitionProof,
        PreparedBlsDoryTransitionProof, projected_production_transition_opening_bytes,
        projected_production_transition_proof_bytes, prove_bls_dory_transition,
        prove_bls_dory_transition_at_variables, prove_bls_dory_transition_deferred_at_variables,
        verify_bls_dory_transition, verify_bls_dory_transition_at_variables,
        verify_bls_dory_transition_deferred_at_variables,
    },
    dory_bls12_381_wiring::{
        BlsDoryWiringError, BlsDoryWiringProof, PreparedBlsDoryWiringProof,
        projected_production_wiring_opening_bytes, projected_production_wiring_proof_bytes,
        prove_bls_dory_wiring_deferred_at_variables, verify_bls_dory_wiring_deferred_at_variables,
    },
    sumcheck::GOLDILOCKS_MODULUS,
    verify_model_bank_into_staged_field_sink,
};

pub const BLS_DORY_SHARED_LAYOUT_VERSION: u16 = 3;
pub const BLS_DORY_FIXED_MODEL_IDENTITY_VERSION: u16 = 1;
const MAX_SHARED_LAYOUT_BINDING_BYTES: usize = 4_096;
const SHARED_PROOF_MAGIC: [u8; 8] = *b"CFBLSS01";
const SHARED_PROOF_HEADER_BYTES: usize = 16;
pub const MAX_BLS_DORY_SHARED_MATRIX_PROOFS: usize = 3;
pub const MAX_BLS_DORY_SHARED_TRANSITION_PROOFS: usize = 4;
pub const MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES: usize = 262_128;
pub const BLS_DORY_SHARED_INITIALIZATION_LINKS: usize = 2;
pub const BLS_DORY_SHARED_LINKS_PER_BANK: usize = 3;

/// Maximum variable count across production matrix, transition, and wiring tables.
pub const BLS_DORY_SHARED_PRODUCTION_VARIABLES: usize = 33;
/// Three matrix banks each expose activation, weight, and accumulator openings.
pub const BLS_DORY_SHARED_PRODUCTION_MATRIX_CLAIMS: usize = 9;
/// The initialization transition and three matrix-bank transitions expose 110 claims each.
pub const BLS_DORY_SHARED_PRODUCTION_TRANSITION_CLAIMS: usize = 4 * STRUCTURED_TRANSITION_ORACLES;
/// Production wiring uses one initialization opening and ten openings per bank.
pub const BLS_DORY_SHARED_PRODUCTION_WIRING_CLAIMS: usize = 31;
/// Current direct terminal set before packed LogUp compression.
pub const BLS_DORY_SHARED_PRODUCTION_DIRECT_CLAIMS: usize = BLS_DORY_SHARED_PRODUCTION_MATRIX_CLAIMS
    + BLS_DORY_SHARED_PRODUCTION_TRANSITION_CLAIMS
    + BLS_DORY_SHARED_PRODUCTION_WIRING_CLAIMS;
/// Four scalar range checkpoints need four openings each.
pub const BLS_DORY_SHARED_LOGUP_RANGE_TRANSITION_CLAIMS: usize =
    4 * BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS;
/// Four arithmetic transition checkpoints retain twelve regular openings each.
pub const BLS_DORY_SHARED_ARITHMETIC_TRANSITION_CLAIMS: usize =
    4 * BLS_DORY_TRANSITION_OPENING_CLAIMS;
/// Arithmetic plus compressed range claims across all four transitions.
pub const BLS_DORY_SHARED_COMPRESSED_TRANSITION_CLAIMS: usize =
    BLS_DORY_SHARED_ARITHMETIC_TRANSITION_CLAIMS + BLS_DORY_SHARED_LOGUP_RANGE_TRANSITION_CLAIMS;
/// Complete claim count after packed range compression.
pub const BLS_DORY_SHARED_COMPRESSED_CHECKPOINT_CLAIMS: usize =
    BLS_DORY_SHARED_PRODUCTION_MATRIX_CLAIMS
        + BLS_DORY_SHARED_COMPRESSED_TRANSITION_CLAIMS
        + BLS_DORY_SHARED_PRODUCTION_WIRING_CLAIMS;
/// One initialization equality plus three matrix/transition/wiring equalities per bank.
pub const BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS: usize = BLS_DORY_SHARED_INITIALIZATION_LINKS
    + MAX_BLS_DORY_SHARED_MATRIX_PROOFS * BLS_DORY_SHARED_LINKS_PER_BANK;
/// Each equality opens both independently committed representations at one point.
pub const BLS_DORY_SHARED_PRODUCTION_EQUALITY_CLAIMS: usize =
    2 * BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS;
/// Complete production claim count after range compression and equality links.
pub const BLS_DORY_SHARED_PRODUCTION_CLAIMS: usize =
    BLS_DORY_SHARED_COMPRESSED_CHECKPOINT_CLAIMS + BLS_DORY_SHARED_PRODUCTION_EQUALITY_CLAIMS;
/// Shared transport is not yet accepted by consensus.
pub const BLS_DORY_SHARED_LAYOUT_PRODUCTION_READY: bool = false;
/// Remaining gates on the shared scalar layout.
pub const BLS_DORY_SHARED_LAYOUT_PRODUCTION_BLOCKERS: [&str; 2] = [
    "the final production model bank has not been streamed through the n=33 setup to publish pinned BLS commitments, and the common n=33 coefficient tables are not streamed by the prover",
    "the complete shared transcript, soundness accounting, and implementation have not received independent audit",
];

/// Network-pinned BLS commitments for the authenticated fixed model.
///
/// The descriptor is supplied by the trusted consensus configuration, never by
/// the block proof. Its model digest binds the existing byte/WHIR identity while
/// the Dory commitments bind the scalar tables used by this proof backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryFixedModelIdentity {
    pub protocol_version: u16,
    pub model_pcs_identity_digest: [u8; 32],
    pub setup_identity: [u8; 32],
    pub base_input_commitment: BlsDoryGt,
    pub weight_bank_commitments: Vec<BlsDoryGt>,
}

impl BlsDoryFixedModelIdentity {
    pub fn validate(
        &self,
        trusted_model: &ModelPcsIdentity,
        expected_banks: usize,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDorySharedLayoutError> {
        setup
            .validate()
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
        let model_digest = trusted_model
            .digest()
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
        if self.protocol_version != BLS_DORY_FIXED_MODEL_IDENTITY_VERSION
            || self.model_pcs_identity_digest != model_digest
            || self.setup_identity != setup.identity()
            || self.weight_bank_commitments.len() != expected_banks
            || self.weight_bank_commitments.len() != trusted_model.weight_bank_commitments.len()
            || self.base_input_commitment == BlsDoryGt::identity()
            || self
                .weight_bank_commitments
                .iter()
                .any(|commitment| *commitment == BlsDoryGt::identity())
        {
            return Err(BlsDorySharedLayoutError::FixedModelIdentity);
        }
        for (index, commitment) in self.weight_bank_commitments.iter().enumerate() {
            if *commitment == self.base_input_commitment
                || self.weight_bank_commitments[..index].contains(commitment)
            {
                return Err(BlsDorySharedLayoutError::FixedModelIdentity);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], BlsDorySharedLayoutError> {
        let bank_count = u16::try_from(self.weight_bank_commitments.len())
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
        let mut encoded = Vec::new();
        append_serialized(&mut encoded, &self.base_input_commitment)?;
        for commitment in &self.weight_bank_commitments {
            append_serialized(&mut encoded, commitment)?;
        }
        let mut hasher = blake3::Hasher::new_derive_key(
            "CommonFoundry/ForgeMatrix/BlsDoryFixedModelIdentity/v1",
        );
        hasher.update(&self.protocol_version.to_le_bytes());
        hasher.update(&bank_count.to_le_bytes());
        hasher.update(&self.model_pcs_identity_digest);
        hasher.update(&self.setup_identity);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Derive the network-pinned Dory commitments from already authenticated model
/// values. Production must call this through the streamed model-bank boundary;
/// this bounded reference helper exists for fixtures and activation tooling.
pub fn derive_bls_dory_fixed_model_identity(
    trusted_model: &ModelPcsIdentity,
    base_input: &[i64],
    weight_banks: &[&[i64]],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryFixedModelIdentity, BlsDorySharedLayoutError> {
    trusted_model
        .validate()
        .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
    setup
        .validate()
        .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
    if weight_banks.len() != trusted_model.weight_bank_commitments.len()
        || padded_variables > setup.max_log_n()
    {
        return Err(BlsDorySharedLayoutError::FixedModelIdentity);
    }
    let base_elements = usize::try_from(
        u64::from(trusted_model.batch)
            .checked_mul(u64::from(trusted_model.dimension))
            .ok_or(BlsDorySharedLayoutError::FixedModelIdentity)?,
    )
    .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
    let weight_elements = usize::try_from(
        u64::from(trusted_model.layers_per_bank)
            .checked_mul(u64::from(trusted_model.dimension))
            .and_then(|value| value.checked_mul(u64::from(trusted_model.dimension)))
            .ok_or(BlsDorySharedLayoutError::FixedModelIdentity)?,
    )
    .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
    if base_input.len() != base_elements
        || weight_banks
            .iter()
            .any(|weights| weights.len() != weight_elements)
    {
        return Err(BlsDorySharedLayoutError::FixedModelIdentity);
    }
    let base_input_commitment =
        commit_fixed_table(base_input, padded_variables, setup)?.commitment();
    let weight_bank_commitments = weight_banks
        .iter()
        .map(|weights| {
            commit_fixed_table(weights, padded_variables, setup)
                .map(|committed| committed.commitment())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let identity = BlsDoryFixedModelIdentity {
        protocol_version: BLS_DORY_FIXED_MODEL_IDENTITY_VERSION,
        model_pcs_identity_digest: trusted_model
            .digest()
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?,
        setup_identity: setup.identity(),
        base_input_commitment,
        weight_bank_commitments,
    };
    identity.validate(trusted_model, weight_banks.len(), setup)?;
    Ok(identity)
}

/// Authenticate one canonical model bank and derive its BLS commitments without
/// materializing any fixed polynomial.
///
/// Chunks remain provisional until the model-bank verifier checks the trusted
/// roots, exact payload length, and EOF. The returned identity is therefore the
/// only publication point for the incrementally accumulated commitments.
pub fn derive_bls_dory_fixed_model_identity_from_verified_bank<R: Read>(
    reader: R,
    expected_manifest: &ModelBankManifest,
    trusted_model: &ModelPcsIdentity,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryFixedModelIdentity, ModelBankFieldStreamError<BlsDoryFixedModelStreamError>> {
    let sink = BlsDoryFixedModelSink::new(trusted_model, padded_variables, setup)
        .map_err(ModelBankFieldStreamError::Sink)?;
    verify_model_bank_into_staged_field_sink(reader, expected_manifest, trusted_model, sink)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDoryFixedModelStreamError {
    #[error("the streamed fixed-model setup or padded geometry is invalid")]
    InvalidGeometry,
    #[error("the streamed fixed-model chunk order, offset, or length is invalid")]
    InvalidChunk,
    #[error("the streamed fixed-model field value is not a centered model byte")]
    InvalidFieldValue,
    #[error("the verified model-bank receipt does not match the requested identity")]
    ReceiptMismatch,
    #[error("the authenticated fixed-model commitments do not form a valid identity")]
    InvalidIdentity,
}

struct StreamedDoryRole {
    role: ModelPcsRole,
    expected_elements: u64,
    next_offset: u64,
    row_index: usize,
    column_offset: usize,
    row_commitment: BlsDoryG1,
    commitment: BlsDoryGt,
}

impl StreamedDoryRole {
    fn new(role: ModelPcsRole, expected_elements: u64) -> Self {
        Self {
            role,
            expected_elements,
            next_offset: 0,
            row_index: 0,
            column_offset: 0,
            row_commitment: BlsDoryG1::identity(),
            commitment: BlsDoryGt::identity(),
        }
    }

    fn write(
        &mut self,
        elements: &[u64],
        columns: usize,
        rows: usize,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDoryFixedModelStreamError> {
        let mut remaining = elements;
        while !remaining.is_empty() {
            if self.row_index >= rows {
                return Err(BlsDoryFixedModelStreamError::InvalidChunk);
            }
            let take = remaining.len().min(columns - self.column_offset);
            let scalars = remaining[..take]
                .iter()
                .copied()
                .map(bls_scalar_from_model_field)
                .collect::<Result<Vec<_>, _>>()?;
            let partial = setup
                .commit_row_segment(self.column_offset, &scalars)
                .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
            self.row_commitment = self.row_commitment + partial;
            self.column_offset += take;
            remaining = &remaining[take..];

            if self.column_offset == columns {
                self.commitment = self.commitment
                    + setup
                        .pair_committed_row(self.row_index, &self.row_commitment)
                        .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
                self.row_index += 1;
                self.column_offset = 0;
                self.row_commitment = BlsDoryG1::identity();
            }
        }
        Ok(())
    }

    fn finish(
        mut self,
        rows: usize,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<BlsDoryGt, BlsDoryFixedModelStreamError> {
        if self.next_offset != self.expected_elements || self.row_index > rows {
            return Err(BlsDoryFixedModelStreamError::InvalidChunk);
        }
        if self.column_offset != 0 {
            if self.row_index >= rows {
                return Err(BlsDoryFixedModelStreamError::InvalidChunk);
            }
            self.commitment = self.commitment
                + setup
                    .pair_committed_row(self.row_index, &self.row_commitment)
                    .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
        }
        Ok(self.commitment)
    }
}

struct BlsDoryFixedModelSink<'a> {
    expected_model: ModelPcsIdentity,
    setup: &'a DeterministicBlsDorySetup,
    columns: usize,
    rows: usize,
    roles: Vec<StreamedDoryRole>,
    next_role: usize,
}

impl<'a> BlsDoryFixedModelSink<'a> {
    fn new(
        trusted_model: &ModelPcsIdentity,
        padded_variables: usize,
        setup: &'a DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryFixedModelStreamError> {
        trusted_model
            .validate()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        setup
            .validate()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if padded_variables == 0 || padded_variables > setup.max_log_n() {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }
        let padded_elements = 1_u64
            .checked_shl(padded_variables as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let nu = padded_variables / 2;
        let sigma = padded_variables - nu;
        let rows = 1_usize
            .checked_shl(nu as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let columns = 1_usize
            .checked_shl(sigma as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let base_elements = u64::from(trusted_model.batch)
            .checked_mul(u64::from(trusted_model.dimension))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let weight_elements = u64::from(trusted_model.layers_per_bank)
            .checked_mul(u64::from(trusted_model.dimension))
            .and_then(|value| value.checked_mul(u64::from(trusted_model.dimension)))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if !base_elements.is_power_of_two()
            || !weight_elements.is_power_of_two()
            || base_elements > padded_elements
            || weight_elements > padded_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }

        let mut roles = Vec::with_capacity(1 + trusted_model.weight_bank_commitments.len());
        roles.push(StreamedDoryRole::new(
            ModelPcsRole::BaseInput,
            base_elements,
        ));
        roles.extend(
            trusted_model
                .weight_bank_commitments
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    let index = u32::try_from(index)
                        .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
                    Ok(StreamedDoryRole::new(
                        ModelPcsRole::WeightBank { index },
                        weight_elements,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        Ok(Self {
            expected_model: trusted_model.clone(),
            setup,
            columns,
            rows,
            roles,
            next_role: 0,
        })
    }
}

impl StagedModelFieldSink for BlsDoryFixedModelSink<'_> {
    type Error = BlsDoryFixedModelStreamError;
    type Output = BlsDoryFixedModelIdentity;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
        let role = self
            .roles
            .get_mut(self.next_role)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_len = u64::try_from(chunk.elements.len())
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_end = chunk
            .role_offset
            .checked_add(chunk_len)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        if chunk.elements.is_empty()
            || chunk.role != role.role
            || chunk.role_elements != role.expected_elements
            || chunk.role_offset != role.next_offset
            || chunk_end > role.expected_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidChunk);
        }
        role.write(chunk.elements, self.columns, self.rows, self.setup)?;
        role.next_offset = chunk_end;
        if chunk_end == role.expected_elements {
            self.next_role += 1;
        }
        Ok(())
    }

    fn finish_verified(
        self,
        receipt: VerifiedModelBankReceipt,
    ) -> Result<Self::Output, Self::Error> {
        if self.next_role != self.roles.len()
            || receipt.identity() != &self.expected_model
            || usize::try_from(receipt.layout().weight_bank_count()).ok()
                != Some(self.expected_model.weight_bank_commitments.len())
            || receipt.layout().layers_per_bank() != self.expected_model.layers_per_bank
        {
            return Err(BlsDoryFixedModelStreamError::ReceiptMismatch);
        }
        let mut commitments = self
            .roles
            .into_iter()
            .map(|role| role.finish(self.rows, self.setup));
        let base_input_commitment = commitments
            .next()
            .ok_or(BlsDoryFixedModelStreamError::InvalidIdentity)??;
        let weight_bank_commitments = commitments.collect::<Result<Vec<_>, _>>()?;
        let identity = BlsDoryFixedModelIdentity {
            protocol_version: BLS_DORY_FIXED_MODEL_IDENTITY_VERSION,
            model_pcs_identity_digest: self
                .expected_model
                .digest()
                .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?,
            setup_identity: self.setup.identity(),
            base_input_commitment,
            weight_bank_commitments,
        };
        identity
            .validate(
                &self.expected_model,
                self.expected_model.weight_bank_commitments.len(),
                self.setup,
            )
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        Ok(identity)
    }
}

fn bls_scalar_from_model_field(value: u64) -> Result<BlsDoryFr, BlsDoryFixedModelStreamError> {
    if value <= 125 {
        return Ok(BlsDoryFr::from_u64(value));
    }
    let negative_floor = GOLDILOCKS_MODULUS - 125;
    if value < negative_floor || value >= GOLDILOCKS_MODULUS {
        return Err(BlsDoryFixedModelStreamError::InvalidFieldValue);
    }
    Ok(-BlsDoryFr::from_u64(GOLDILOCKS_MODULUS - value))
}

fn commit_fixed_table(
    values: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryCommittedPolynomial, BlsDorySharedLayoutError> {
    let padded_len = 1usize
        .checked_shl(padded_variables as u32)
        .ok_or(BlsDorySharedLayoutError::FixedModelIdentity)?;
    if values.is_empty() || values.len() > padded_len || !values.len().is_power_of_two() {
        return Err(BlsDorySharedLayoutError::FixedModelIdentity);
    }
    let mut coefficients = values
        .iter()
        .copied()
        .map(BlsDoryFr::from_i64)
        .collect::<Vec<_>>();
    coefficients.resize(padded_len, BlsDoryFr::zero());
    let nu = padded_variables / 2;
    commit_bls_dory_polynomial(coefficients, nu, padded_variables - nu, setup).map_err(Into::into)
}

/// Arithmetic and range proofs that share the exact packed transition commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryTransitionRangeProof {
    pub arithmetic: BlsDoryTransitionProof,
    pub range: BlsDoryRangeLogUpProof,
}

/// One or more matrix and transition checkpoints plus wiring, authenticated by
/// one shared Dory opening payload. The production shape uses three matrix
/// proofs and four transition/range proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDorySharedLayoutProof {
    pub protocol_version: u16,
    pub padded_variables: u16,
    pub matrices: Vec<BlsDoryMatrixProof>,
    pub transitions: Vec<BlsDoryTransitionRangeProof>,
    pub wiring: BlsDoryWiringProof,
    pub link_evaluations: Vec<BlsDoryFr>,
    pub opening_proof: Vec<u8>,
}

impl BlsDorySharedLayoutProof {
    /// Encode the component algebraic messages and their single shared opening
    /// payload with exact length-delimited canonical framing.
    pub fn encode(
        &self,
        matrix_statements: &[StructuredMatrixStatement],
        transition_statements: &[StructuredTransitionStatement],
        wiring_statement: StructuredWiringStatement,
    ) -> Result<Vec<u8>, BlsDorySharedLayoutError> {
        validate_shared_component_shape(self, usize::from(self.padded_variables))?;
        if self.matrices.len() != matrix_statements.len()
            || self.transitions.len() != transition_statements.len()
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        validate_shared_link_topology(matrix_statements, transition_statements, wiring_statement)?;
        let matrices = self
            .matrices
            .iter()
            .zip(matrix_statements)
            .map(|(proof, statement)| proof.encode_deferred(*statement))
            .collect::<Result<Vec<_>, _>>()?;
        let transitions = self
            .transitions
            .iter()
            .zip(transition_statements)
            .map(|(proof, statement)| {
                Ok((
                    proof.arithmetic.encode_deferred(*statement)?,
                    proof.range.encode_deferred(*statement)?,
                ))
            })
            .collect::<Result<Vec<_>, BlsDorySharedLayoutError>>()?;
        let wiring = self.wiring.encode_deferred(wiring_statement)?;
        let mut link_evaluations =
            Vec::with_capacity(self.link_evaluations.len() * BlsDoryFr::zero().compressed_size());
        for evaluation in &self.link_evaluations {
            append_serialized(&mut link_evaluations, evaluation)?;
        }
        let mut total = SHARED_PROOF_HEADER_BYTES;
        for matrix in &matrices {
            total = framed_size(total, matrix.len())?;
        }
        for (arithmetic, range) in &transitions {
            total = framed_size(total, arithmetic.len())?;
            total = framed_size(total, range.len())?;
        }
        total = framed_size(total, wiring.len())?;
        total = framed_size(total, link_evaluations.len())?;
        total = framed_size(total, self.opening_proof.len())?;
        if total > MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES {
            return Err(BlsDorySharedLayoutError::ProofTooLarge);
        }
        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(&SHARED_PROOF_MAGIC);
        encoded.extend_from_slice(&self.protocol_version.to_le_bytes());
        encoded.extend_from_slice(&self.padded_variables.to_le_bytes());
        encoded.extend_from_slice(&(matrices.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&(transitions.len() as u16).to_le_bytes());
        for matrix in &matrices {
            append_framed(&mut encoded, matrix)?;
        }
        for (arithmetic, range) in &transitions {
            append_framed(&mut encoded, arithmetic)?;
            append_framed(&mut encoded, range)?;
        }
        append_framed(&mut encoded, &wiring)?;
        append_framed(&mut encoded, &link_evaluations)?;
        append_framed(&mut encoded, &self.opening_proof)?;
        if encoded.len() != total {
            return Err(BlsDorySharedLayoutError::ProofTooLarge);
        }
        Ok(encoded)
    }

    /// Decode the exact component shapes implied by the trusted statements and
    /// shared variable count.
    pub fn decode_with_variables(
        encoded: &[u8],
        matrix_statements: &[StructuredMatrixStatement],
        transition_statements: &[StructuredTransitionStatement],
        wiring_statement: StructuredWiringStatement,
        padded_variables: usize,
    ) -> Result<Self, BlsDorySharedLayoutError> {
        if encoded.len() < SHARED_PROOF_HEADER_BYTES
            || encoded.len() > MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES
            || encoded[..8] != SHARED_PROOF_MAGIC
        {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }
        let protocol_version = read_u16(encoded, 8)?;
        let encoded_variables = read_u16(encoded, 10)?;
        let matrix_count = read_u16(encoded, 12)? as usize;
        let transition_count = read_u16(encoded, 14)? as usize;
        if protocol_version != BLS_DORY_SHARED_LAYOUT_VERSION
            || usize::from(encoded_variables) != padded_variables
            || matrix_count != matrix_statements.len()
            || transition_count != transition_statements.len()
            || !(1..=MAX_BLS_DORY_SHARED_MATRIX_PROOFS).contains(&matrix_count)
            || !(1..=MAX_BLS_DORY_SHARED_TRANSITION_PROOFS).contains(&transition_count)
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        validate_shared_link_topology(matrix_statements, transition_statements, wiring_statement)?;
        let mut offset = SHARED_PROOF_HEADER_BYTES;
        let mut matrices = Vec::with_capacity(matrix_count);
        for statement in matrix_statements {
            matrices.push(BlsDoryMatrixProof::decode_deferred_with_variables(
                take_framed(encoded, &mut offset)?,
                *statement,
                padded_variables,
            )?);
        }
        let mut transitions = Vec::with_capacity(transition_count);
        for statement in transition_statements {
            let arithmetic = BlsDoryTransitionProof::decode_deferred_with_variables(
                take_framed(encoded, &mut offset)?,
                *statement,
                padded_variables,
            )?;
            let range = BlsDoryRangeLogUpProof::decode_deferred_with_variables(
                take_framed(encoded, &mut offset)?,
                *statement,
                padded_variables,
            )?;
            transitions.push(BlsDoryTransitionRangeProof { arithmetic, range });
        }
        let wiring = BlsDoryWiringProof::decode_deferred_with_variables(
            take_framed(encoded, &mut offset)?,
            wiring_statement,
            padded_variables,
        )?;
        let link_bytes = take_framed(encoded, &mut offset)?;
        let link_count = shared_link_count(matrix_count)?;
        if link_bytes.len()
            != link_count
                .checked_mul(BlsDoryFr::zero().compressed_size())
                .ok_or(BlsDorySharedLayoutError::ProofTooLarge)?
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let mut link_reader = Cursor::new(link_bytes);
        let link_evaluations = (0..link_count)
            .map(|_| read_serialized(&mut link_reader))
            .collect::<Result<Vec<_>, _>>()?;
        if link_reader.position() as usize != link_bytes.len() {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }
        let opening_proof = take_framed(encoded, &mut offset)?.to_vec();
        if opening_proof.is_empty()
            || opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
            || offset != encoded.len()
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let proof = Self {
            protocol_version,
            padded_variables: encoded_variables,
            matrices,
            transitions,
            wiring,
            link_evaluations,
            opening_proof,
        };
        validate_shared_component_shape(&proof, padded_variables)?;
        if proof.encode(matrix_statements, transition_statements, wiring_statement)? != encoded {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }
        Ok(proof)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDorySharedLayoutError {
    #[error("shared Dory layout projection failed: {0}")]
    Aggregate(#[from] BlsDoryAggregateError),
    #[error("transition arithmetic checkpoint failed: {0}")]
    Transition(#[from] BlsDoryTransitionError),
    #[error("transition range checkpoint failed: {0}")]
    Range(#[from] BlsDoryRangeLogUpError),
    #[error("matrix checkpoint failed: {0}")]
    Matrix(#[from] BlsDoryMatrixError),
    #[error("wiring checkpoint failed: {0}")]
    Wiring(#[from] BlsDoryWiringError),
    #[error("transition arithmetic and range proofs do not share one commitment")]
    TransitionRangeCommitment,
    #[error("shared layout proof has the wrong fixed shape")]
    InvalidProofShape,
    #[error("shared layout proof is too large")]
    ProofTooLarge,
    #[error("shared layout proof encoding is non-canonical or malformed")]
    InvalidEncoding,
    #[error("shared aggregate claims do not match the component transcripts")]
    OpeningClaims,
    #[error("matrix, transition, and wiring statements do not form one canonical topology")]
    LinkTopology,
    #[error("cross-component equality opening evaluations do not match")]
    LinkEvaluation,
    #[error("the pinned BLS fixed-model identity is invalid or mismatched")]
    FixedModelIdentity,
    #[error("the proof does not use the pinned BLS fixed-model commitments")]
    FixedModelCommitment,
    #[error("the shared BLS12-381 layout is not production ready")]
    NotProductionReady,
}

pub struct BlsDoryMatrixProverInput<'a> {
    pub statement: StructuredMatrixStatement,
    pub activations: &'a [i64],
    pub weights: &'a [i64],
    pub accumulators: &'a [i64],
}

pub struct BlsDoryTransitionProverInput<'a> {
    pub statement: StructuredTransitionStatement,
    pub mask_polynomial: &'a StructuredMaskPolynomial,
    pub witness: &'a StructuredTransitionWitness,
}

/// Prove all scalar checkpoints with a single opening aggregate. The bounded
/// vectors cover both small fixtures and the exact three-matrix/four-transition
/// production topology.
#[allow(clippy::too_many_arguments)]
pub fn prove_bls_dory_shared_layout_at_variables(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_inputs: &[BlsDoryMatrixProverInput<'_>],
    transition_inputs: &[BlsDoryTransitionProverInput<'_>],
    wiring_statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDorySharedLayoutProof, BlsDorySharedLayoutError> {
    if binding.len() > MAX_SHARED_LAYOUT_BINDING_BYTES
        || !(1..=MAX_BLS_DORY_SHARED_MATRIX_PROOFS).contains(&matrix_inputs.len())
        || !(1..=MAX_BLS_DORY_SHARED_TRANSITION_PROOFS).contains(&transition_inputs.len())
        || transition_inputs.len() != matrix_inputs.len() + 1
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    let matrix_statements = matrix_inputs
        .iter()
        .map(|input| input.statement)
        .collect::<Vec<_>>();
    let transition_statements = transition_inputs
        .iter()
        .map(|input| input.statement)
        .collect::<Vec<_>>();
    validate_shared_link_topology(&matrix_statements, &transition_statements, wiring_statement)?;
    validate_fixed_model_topology(
        trusted_model,
        fixed_model,
        &matrix_statements,
        &transition_statements,
        wiring_statement,
        setup,
    )?;
    let component_binding = fixed_model_binding(binding, trusted_model, fixed_model, setup)?;
    let fixed_base = commit_fixed_table(
        &transition_inputs[0].witness.accumulators,
        padded_variables,
        setup,
    )?;
    if fixed_base.commitment() != fixed_model.base_input_commitment {
        return Err(BlsDorySharedLayoutError::FixedModelCommitment);
    }
    let mut matrices = Vec::with_capacity(matrix_inputs.len());
    for (input, expected_weight) in matrix_inputs
        .iter()
        .zip(&fixed_model.weight_bank_commitments)
    {
        let matrix = prove_bls_dory_matrix_deferred_at_variables(
            &component_binding,
            input.statement,
            input.activations,
            input.weights,
            input.accumulators,
            padded_variables,
            setup,
        )?;
        if matrix.proof.weight_commitment != *expected_weight {
            return Err(BlsDorySharedLayoutError::FixedModelCommitment);
        }
        matrices.push(matrix);
    }
    let mut transitions = Vec::with_capacity(transition_inputs.len());
    for input in transition_inputs {
        let arithmetic = prove_bls_dory_transition_deferred_at_variables(
            &component_binding,
            input.statement,
            input.mask_polynomial,
            input.witness,
            padded_variables,
            setup,
        )?;
        let range = prove_bls_dory_range_logup_deferred_at_variables(
            &component_binding,
            input.statement,
            input.witness,
            padded_variables,
            setup,
        )?;
        if arithmetic.proof.oracle_commitment != range.proof.transition_commitment {
            return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
        }
        transitions.push((arithmetic, range));
    }
    let wiring = prove_bls_dory_wiring_deferred_at_variables(
        &component_binding,
        wiring_statement,
        initial,
        inputs,
        outputs,
        padded_variables,
        setup,
    )?;
    prove_prepared_shared_layout(
        &component_binding,
        matrices,
        transitions,
        wiring,
        fixed_base,
        fixed_model,
        &matrix_statements,
        &transition_statements,
        wiring_statement,
        padded_variables,
        setup,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_prepared_shared_layout(
    binding: &[u8],
    mut matrices: Vec<PreparedBlsDoryMatrixProof>,
    mut transitions: Vec<(
        PreparedBlsDoryTransitionProof,
        PreparedBlsDoryRangeLogUpProof,
    )>,
    mut wiring: PreparedBlsDoryWiringProof,
    fixed_base: BlsDoryCommittedPolynomial,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    wiring_statement: StructuredWiringStatement,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDorySharedLayoutProof, BlsDorySharedLayoutError> {
    let matrix_proofs = matrices
        .iter()
        .map(|prepared| &prepared.proof)
        .collect::<Vec<_>>();
    let transition_proofs = transitions
        .iter()
        .map(|(arithmetic, range)| (&arithmetic.proof, &range.proof))
        .collect::<Vec<_>>();
    let opening_binding = shared_opening_binding(
        binding,
        padded_variables,
        setup,
        &matrix_proofs,
        &transition_proofs,
        &wiring.proof,
        fixed_model,
    )?;
    let links = derive_shared_link_points(
        &opening_binding,
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    let mut fixed_base = BlsDoryDeferredOpeningSet::unopened(vec![fixed_base])?;
    let link_evaluations = attach_prover_links(
        &links,
        &mut matrices,
        &mut transitions,
        &mut wiring,
        &mut fixed_base,
    )?;
    let mut opening_sets = Vec::new();
    let mut expected_claims = Vec::new();
    for matrix in &matrices {
        opening_sets.push(&matrix.openings);
        expected_claims.extend_from_slice(matrix.openings.claims());
    }
    for (arithmetic, range) in &transitions {
        opening_sets.push(&arithmetic.openings);
        expected_claims.extend_from_slice(arithmetic.openings.claims());
        opening_sets.push(&range.openings);
        expected_claims.extend_from_slice(range.openings.claims());
    }
    opening_sets.push(&wiring.openings);
    expected_claims.extend_from_slice(wiring.openings.claims());
    opening_sets.push(&fixed_base);
    expected_claims.extend_from_slice(fixed_base.claims());
    let (claims, opening_proof) =
        prove_bls_dory_deferred_opening_sets(&opening_binding, &opening_sets, setup)?;
    if claims != expected_claims {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    Ok(BlsDorySharedLayoutProof {
        protocol_version: BLS_DORY_SHARED_LAYOUT_VERSION,
        padded_variables: u16::try_from(padded_variables)
            .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
        matrices: matrices
            .into_iter()
            .map(|prepared| prepared.proof)
            .collect(),
        transitions: transitions
            .into_iter()
            .map(|(arithmetic, range)| BlsDoryTransitionRangeProof {
                arithmetic: arithmetic.proof,
                range: range.proof,
            })
            .collect(),
        wiring: wiring.proof,
        link_evaluations,
        opening_proof,
    })
}

/// Verify every component transcript, then authenticate their ordered opening
/// claims with exactly one Dory payload.
#[allow(clippy::too_many_arguments)]
pub fn verify_bls_dory_shared_layout_at_variables(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    mask_polynomials: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    validate_shared_proof_shape(binding, proof, padded_variables)?;
    if proof.matrices.len() != matrix_statements.len()
        || proof.transitions.len() != transition_statements.len()
        || proof.transitions.len() != mask_polynomials.len()
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    validate_shared_link_topology(matrix_statements, transition_statements, wiring_statement)?;
    validate_fixed_model_topology(
        trusted_model,
        fixed_model,
        matrix_statements,
        transition_statements,
        wiring_statement,
        setup,
    )?;
    if proof
        .matrices
        .iter()
        .zip(&fixed_model.weight_bank_commitments)
        .any(|(matrix, commitment)| matrix.weight_commitment != *commitment)
    {
        return Err(BlsDorySharedLayoutError::FixedModelCommitment);
    }
    let component_binding = fixed_model_binding(binding, trusted_model, fixed_model, setup)?;
    let mut matrix_claims = Vec::with_capacity(proof.matrices.len());
    for (statement, matrix) in matrix_statements.iter().zip(&proof.matrices) {
        matrix_claims.push(verify_bls_dory_matrix_deferred_at_variables(
            &component_binding,
            *statement,
            matrix,
            padded_variables,
            setup,
        )?);
    }
    let mut transition_claims = Vec::with_capacity(proof.transitions.len());
    for ((statement, mask), transition) in transition_statements
        .iter()
        .zip(mask_polynomials)
        .zip(&proof.transitions)
    {
        if transition.arithmetic.oracle_commitment != transition.range.transition_commitment {
            return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
        }
        let arithmetic = verify_bls_dory_transition_deferred_at_variables(
            &component_binding,
            *statement,
            mask,
            &transition.arithmetic,
            padded_variables,
            setup,
        )?;
        let range = verify_bls_dory_range_logup_deferred_at_variables(
            &component_binding,
            *statement,
            transition.arithmetic.oracle_commitment,
            &transition.range,
            padded_variables,
            setup,
        )?;
        transition_claims.push((arithmetic, range));
    }
    let mut wiring_claims = verify_bls_dory_wiring_deferred_at_variables(
        &component_binding,
        wiring_statement,
        &proof.wiring,
        padded_variables,
        setup,
    )?;
    let matrix_proofs = proof.matrices.iter().collect::<Vec<_>>();
    let transition_proofs = proof
        .transitions
        .iter()
        .map(|proof| (&proof.arithmetic, &proof.range))
        .collect::<Vec<_>>();
    let opening_binding = shared_opening_binding(
        &component_binding,
        padded_variables,
        setup,
        &matrix_proofs,
        &transition_proofs,
        &proof.wiring,
        fixed_model,
    )?;
    let links = derive_shared_link_points(
        &opening_binding,
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    let mut fixed_base_claims = Vec::with_capacity(1);
    attach_verifier_links(
        &links,
        &proof.link_evaluations,
        proof,
        fixed_model,
        &mut matrix_claims,
        &mut transition_claims,
        &mut wiring_claims,
        &mut fixed_base_claims,
    )?;
    let mut claims = Vec::new();
    for component in matrix_claims {
        claims.extend(component);
    }
    for (arithmetic, range) in transition_claims {
        claims.extend(arithmetic);
        claims.extend(range);
    }
    claims.extend(wiring_claims);
    claims.extend(fixed_base_claims);
    verify_bls_dory_openings(&opening_binding, &claims, &proof.opening_proof, setup)?;
    Ok(())
}

fn validate_shared_proof_shape(
    binding: &[u8],
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
) -> Result<(), BlsDorySharedLayoutError> {
    if binding.len() > MAX_SHARED_LAYOUT_BINDING_BYTES {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    validate_shared_component_shape(proof, padded_variables)
}

fn validate_shared_component_shape(
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
) -> Result<(), BlsDorySharedLayoutError> {
    if proof.protocol_version != BLS_DORY_SHARED_LAYOUT_VERSION
        || usize::from(proof.padded_variables) != padded_variables
        || proof.opening_proof.is_empty()
        || proof.opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
        || !(1..=MAX_BLS_DORY_SHARED_MATRIX_PROOFS).contains(&proof.matrices.len())
        || !(1..=MAX_BLS_DORY_SHARED_TRANSITION_PROOFS).contains(&proof.transitions.len())
        || proof.transitions.len() != proof.matrices.len() + 1
        || proof.link_evaluations.len() != shared_link_count(proof.matrices.len())?
        || proof
            .matrices
            .iter()
            .any(|matrix| !matrix.opening_proof.is_empty())
        || proof.transitions.iter().any(|transition| {
            !transition.arithmetic.opening_proof.is_empty()
                || !transition.range.opening_proof.is_empty()
        })
        || !proof.wiring.opening_proof.is_empty()
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    Ok(())
}

fn append_serialized<T: DorySerialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDorySharedLayoutError> {
    value
        .serialize_compressed(output)
        .map_err(|_| BlsDorySharedLayoutError::InvalidEncoding)
}

fn read_serialized<T: DoryDeserialize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<T, BlsDorySharedLayoutError> {
    T::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDorySharedLayoutError::InvalidEncoding)
}

fn read_u16(encoded: &[u8], offset: usize) -> Result<u16, BlsDorySharedLayoutError> {
    let bytes = encoded
        .get(offset..offset + 2)
        .ok_or(BlsDorySharedLayoutError::InvalidEncoding)?;
    Ok(u16::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| BlsDorySharedLayoutError::InvalidEncoding)?,
    ))
}

fn read_u32(encoded: &[u8], offset: usize) -> Result<u32, BlsDorySharedLayoutError> {
    let bytes = encoded
        .get(offset..offset + 4)
        .ok_or(BlsDorySharedLayoutError::InvalidEncoding)?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| BlsDorySharedLayoutError::InvalidEncoding)?,
    ))
}

fn framed_size(total: usize, payload: usize) -> Result<usize, BlsDorySharedLayoutError> {
    total
        .checked_add(4)
        .and_then(|total| total.checked_add(payload))
        .ok_or(BlsDorySharedLayoutError::ProofTooLarge)
}

fn append_framed(encoded: &mut Vec<u8>, payload: &[u8]) -> Result<(), BlsDorySharedLayoutError> {
    let length =
        u32::try_from(payload.len()).map_err(|_| BlsDorySharedLayoutError::ProofTooLarge)?;
    encoded.extend_from_slice(&length.to_le_bytes());
    encoded.extend_from_slice(payload);
    Ok(())
}

fn take_framed<'a>(
    encoded: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], BlsDorySharedLayoutError> {
    let length = read_u32(encoded, *offset)? as usize;
    if length == 0 {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    *offset = offset
        .checked_add(4)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let end = offset
        .checked_add(length)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let payload = encoded
        .get(*offset..end)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    *offset = end;
    Ok(payload)
}

fn validate_fixed_model_topology(
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrices: &[StructuredMatrixStatement],
    transitions: &[StructuredTransitionStatement],
    wiring: StructuredWiringStatement,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    fixed_model.validate(trusted_model, matrices.len(), setup)?;
    if usize::try_from(trusted_model.batch).ok() != Some(wiring.rows)
        || usize::try_from(trusted_model.dimension).ok() != Some(wiring.cols)
        || usize::try_from(trusted_model.layers_per_bank).ok() != Some(wiring.layers_per_bank)
        || matrices.len() != trusted_model.weight_bank_commitments.len()
        || transitions.first().map(|statement| statement.layers) != Some(1)
    {
        return Err(BlsDorySharedLayoutError::FixedModelIdentity);
    }
    Ok(())
}

fn fixed_model_binding(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    setup: &DeterministicBlsDorySetup,
) -> Result<[u8; 32], BlsDorySharedLayoutError> {
    if binding.len() > MAX_SHARED_LAYOUT_BINDING_BYTES {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    fixed_model.validate(
        trusted_model,
        fixed_model.weight_bank_commitments.len(),
        setup,
    )?;
    let binding_len =
        u32::try_from(binding.len()).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    let mut hasher =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/BlsDoryFixedModelBinding/v1");
    hasher.update(&binding_len.to_le_bytes());
    hasher.update(binding);
    hasher.update(
        &trusted_model
            .digest()
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?,
    );
    hasher.update(&fixed_model.digest()?);
    Ok(*hasher.finalize().as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn shared_opening_binding(
    binding: &[u8],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    matrices: &[&BlsDoryMatrixProof],
    transitions: &[(&BlsDoryTransitionProof, &BlsDoryRangeLogUpProof)],
    wiring: &BlsDoryWiringProof,
    fixed_model: &BlsDoryFixedModelIdentity,
) -> Result<[u8; 32], BlsDorySharedLayoutError> {
    let variables =
        u16::try_from(padded_variables).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    let binding_len =
        u32::try_from(binding.len()).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CommonFoundry/BlsDorySharedLayout/openings/v1");
    hasher.update(&BLS_DORY_SHARED_LAYOUT_VERSION.to_le_bytes());
    hasher.update(&variables.to_le_bytes());
    hasher.update(&setup.identity());
    hasher.update(&binding_len.to_le_bytes());
    hasher.update(binding);
    hasher.update(&fixed_model.digest()?);
    hasher.update(&(matrices.len() as u16).to_le_bytes());
    for matrix in matrices {
        hasher.update(&matrix.transcript_digest);
    }
    hasher.update(&(transitions.len() as u16).to_le_bytes());
    for (arithmetic, range) in transitions {
        hasher.update(&arithmetic.transcript_digest);
        hasher.update(&range.transcript_digest);
    }
    hasher.update(&wiring.transcript_digest);
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Clone, Copy)]
enum SharedLinkRole {
    FixedBaseInput,
    MatrixActivation(usize),
    MatrixAccumulator(usize),
    TransitionInput(usize),
    TransitionActivation(usize),
    WiringInitial,
    WiringInput,
    WiringOutput,
}

struct SharedEqualityLink {
    left: SharedLinkRole,
    left_point: Vec<BlsDoryFr>,
    right: SharedLinkRole,
    right_point: Vec<BlsDoryFr>,
}

fn shared_link_count(banks: usize) -> Result<usize, BlsDorySharedLayoutError> {
    BLS_DORY_SHARED_LINKS_PER_BANK
        .checked_mul(banks)
        .and_then(|count| count.checked_add(BLS_DORY_SHARED_INITIALIZATION_LINKS))
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)
}

fn validate_shared_link_topology(
    matrices: &[StructuredMatrixStatement],
    transitions: &[StructuredTransitionStatement],
    wiring: StructuredWiringStatement,
) -> Result<(), BlsDorySharedLayoutError> {
    if matrices.len() != wiring.banks
        || transitions.len() != matrices.len() + 1
        || transitions[0].layers != 1
        || transitions[0].rows != wiring.rows
        || transitions[0].cols != wiring.cols
    {
        return Err(BlsDorySharedLayoutError::LinkTopology);
    }
    for (matrix, transition) in matrices.iter().zip(&transitions[1..]) {
        if matrix.layers != wiring.layers_per_bank
            || matrix.rows != wiring.rows
            || matrix.inner != wiring.cols
            || matrix.cols != wiring.cols
            || transition.layers != matrix.layers
            || transition.rows != matrix.rows
            || transition.cols != matrix.cols
        {
            return Err(BlsDorySharedLayoutError::LinkTopology);
        }
    }
    Ok(())
}

fn derive_shared_link_points(
    opening_binding: &[u8; 32],
    matrices: &[StructuredMatrixStatement],
    transitions: &[StructuredTransitionStatement],
    wiring: StructuredWiringStatement,
    padded_variables: usize,
) -> Result<Vec<SharedEqualityLink>, BlsDorySharedLayoutError> {
    validate_shared_link_topology(matrices, transitions, wiring)?;
    let mut transcript = BlsDoryTranscript::new(b"shared-equality-links");
    transcript.append_bytes(
        b"protocol-version",
        &BLS_DORY_SHARED_LAYOUT_VERSION.to_le_bytes(),
    );
    transcript.append_bytes(b"opening-binding", opening_binding);
    transcript.append_bytes(b"matrix-count", &(matrices.len() as u64).to_le_bytes());
    transcript.append_bytes(
        b"transition-count",
        &(transitions.len() as u64).to_le_bytes(),
    );

    let initialization_variables = transitions[0]
        .elements()
        .map_err(BlsDoryTransitionError::from)?
        .ilog2() as usize;
    let base_point = link_challenge_point(&mut transcript, 0, initialization_variables);
    let mut links = Vec::with_capacity(shared_link_count(matrices.len())?);
    links.push(SharedEqualityLink {
        left: SharedLinkRole::TransitionInput(0),
        left_point: packed_link_point(
            &base_point,
            STRUCTURED_TRANSITION_INPUT_ORACLE,
            7,
            padded_variables,
        )?,
        right: SharedLinkRole::FixedBaseInput,
        right_point: pad_link_point(&base_point, padded_variables)?,
    });

    let initial_point = link_challenge_point(&mut transcript, 1, initialization_variables);
    let mut wiring_initial_point = initial_point.clone();
    wiring_initial_point.resize(
        initialization_variables + wiring.layers_per_bank.ilog2() as usize,
        BlsDoryFr::zero(),
    );
    links.push(SharedEqualityLink {
        left: SharedLinkRole::TransitionActivation(0),
        left_point: packed_link_point(
            &initial_point,
            STRUCTURED_TRANSITION_ACTIVATION_ORACLE,
            7,
            padded_variables,
        )?,
        right: SharedLinkRole::WiringInitial,
        right_point: packed_link_point(&wiring_initial_point, 0, 3, padded_variables)?,
    });

    for (bank, transition) in transitions[1..].iter().enumerate() {
        let table_variables = transition
            .elements()
            .map_err(BlsDoryTransitionError::from)?
            .ilog2() as usize;
        for relation in 0..BLS_DORY_SHARED_LINKS_PER_BANK {
            let link_index = BLS_DORY_SHARED_INITIALIZATION_LINKS
                + bank * BLS_DORY_SHARED_LINKS_PER_BANK
                + relation;
            let point = link_challenge_point(&mut transcript, link_index, table_variables);
            let direct_point = pad_link_point(&point, padded_variables)?;
            let transition_index = bank + 1;
            let link = match relation {
                0 => SharedEqualityLink {
                    left: SharedLinkRole::MatrixActivation(bank),
                    left_point: direct_point,
                    right: SharedLinkRole::WiringInput,
                    right_point: packed_link_point(&point, 1 + bank * 2, 3, padded_variables)?,
                },
                1 => SharedEqualityLink {
                    left: SharedLinkRole::MatrixAccumulator(bank),
                    left_point: direct_point,
                    right: SharedLinkRole::TransitionInput(transition_index),
                    right_point: packed_link_point(
                        &point,
                        STRUCTURED_TRANSITION_INPUT_ORACLE,
                        7,
                        padded_variables,
                    )?,
                },
                2 => SharedEqualityLink {
                    left: SharedLinkRole::TransitionActivation(transition_index),
                    left_point: packed_link_point(
                        &point,
                        STRUCTURED_TRANSITION_ACTIVATION_ORACLE,
                        7,
                        padded_variables,
                    )?,
                    right: SharedLinkRole::WiringOutput,
                    right_point: packed_link_point(&point, 2 + bank * 2, 3, padded_variables)?,
                },
                _ => return Err(BlsDorySharedLayoutError::InvalidProofShape),
            };
            links.push(link);
        }
    }
    Ok(links)
}

fn link_challenge_point(
    transcript: &mut BlsDoryTranscript,
    link_index: usize,
    variables: usize,
) -> Vec<BlsDoryFr> {
    transcript.append_bytes(b"link-index", &(link_index as u64).to_le_bytes());
    transcript.append_bytes(b"link-variables", &(variables as u64).to_le_bytes());
    (0..variables)
        .map(|coordinate| {
            transcript.append_bytes(b"coordinate", &(coordinate as u64).to_le_bytes());
            transcript.challenge_scalar(b"link-point")
        })
        .collect()
}

fn packed_link_point(
    table_point: &[BlsDoryFr],
    slot: usize,
    selector_variables: usize,
    padded_variables: usize,
) -> Result<Vec<BlsDoryFr>, BlsDorySharedLayoutError> {
    let mut point = Vec::with_capacity(padded_variables);
    point.extend_from_slice(table_point);
    for bit in 0..selector_variables {
        point.push(if (slot >> bit) & 1 == 0 {
            BlsDoryFr::zero()
        } else {
            BlsDoryFr::one()
        });
    }
    pad_link_point(&point, padded_variables)
}

fn pad_link_point(
    point: &[BlsDoryFr],
    padded_variables: usize,
) -> Result<Vec<BlsDoryFr>, BlsDorySharedLayoutError> {
    if point.len() > padded_variables {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    let mut padded = Vec::with_capacity(padded_variables);
    padded.extend_from_slice(point);
    padded.resize(padded_variables, BlsDoryFr::zero());
    Ok(padded)
}

fn attach_prover_links(
    links: &[SharedEqualityLink],
    matrices: &mut [PreparedBlsDoryMatrixProof],
    transitions: &mut [(
        PreparedBlsDoryTransitionProof,
        PreparedBlsDoryRangeLogUpProof,
    )],
    wiring: &mut PreparedBlsDoryWiringProof,
    fixed_base: &mut BlsDoryDeferredOpeningSet,
) -> Result<Vec<BlsDoryFr>, BlsDorySharedLayoutError> {
    let mut evaluations = Vec::with_capacity(links.len());
    for link in links {
        let left = push_prover_role_opening(
            link.left,
            link.left_point.clone(),
            matrices,
            transitions,
            wiring,
            fixed_base,
        )?;
        let right = push_prover_role_opening(
            link.right,
            link.right_point.clone(),
            matrices,
            transitions,
            wiring,
            fixed_base,
        )?;
        if left.evaluation != right.evaluation {
            return Err(BlsDorySharedLayoutError::LinkEvaluation);
        }
        evaluations.push(left.evaluation);
    }
    Ok(evaluations)
}

fn push_prover_role_opening(
    role: SharedLinkRole,
    point: Vec<BlsDoryFr>,
    matrices: &mut [PreparedBlsDoryMatrixProof],
    transitions: &mut [(
        PreparedBlsDoryTransitionProof,
        PreparedBlsDoryRangeLogUpProof,
    )],
    wiring: &mut PreparedBlsDoryWiringProof,
    fixed_base: &mut BlsDoryDeferredOpeningSet,
) -> Result<BlsDoryOpeningClaim, BlsDorySharedLayoutError> {
    Ok(match role {
        SharedLinkRole::FixedBaseInput => fixed_base.push_opening(0, point)?,
        SharedLinkRole::MatrixActivation(bank) => matrices
            .get_mut(bank)
            .ok_or(BlsDorySharedLayoutError::LinkTopology)?
            .openings
            .push_opening(0, point)?,
        SharedLinkRole::MatrixAccumulator(bank) => matrices
            .get_mut(bank)
            .ok_or(BlsDorySharedLayoutError::LinkTopology)?
            .openings
            .push_opening(2, point)?,
        SharedLinkRole::TransitionInput(index) | SharedLinkRole::TransitionActivation(index) => {
            transitions
                .get_mut(index)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .0
                .openings
                .push_opening(0, point)?
        }
        SharedLinkRole::WiringInitial
        | SharedLinkRole::WiringInput
        | SharedLinkRole::WiringOutput => wiring.openings.push_opening(0, point)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn attach_verifier_links(
    links: &[SharedEqualityLink],
    evaluations: &[BlsDoryFr],
    proof: &BlsDorySharedLayoutProof,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrices: &mut [Vec<BlsDoryOpeningClaim>],
    transitions: &mut [(Vec<BlsDoryOpeningClaim>, Vec<BlsDoryOpeningClaim>)],
    wiring: &mut Vec<BlsDoryOpeningClaim>,
    fixed_base: &mut Vec<BlsDoryOpeningClaim>,
) -> Result<(), BlsDorySharedLayoutError> {
    if links.len() != evaluations.len() {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    for (link, evaluation) in links.iter().zip(evaluations) {
        push_verifier_role_claim(
            link.left,
            link.left_point.clone(),
            *evaluation,
            proof,
            fixed_model,
            matrices,
            transitions,
            wiring,
            fixed_base,
        )?;
        push_verifier_role_claim(
            link.right,
            link.right_point.clone(),
            *evaluation,
            proof,
            fixed_model,
            matrices,
            transitions,
            wiring,
            fixed_base,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_verifier_role_claim(
    role: SharedLinkRole,
    point: Vec<BlsDoryFr>,
    evaluation: BlsDoryFr,
    proof: &BlsDorySharedLayoutProof,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrices: &mut [Vec<BlsDoryOpeningClaim>],
    transitions: &mut [(Vec<BlsDoryOpeningClaim>, Vec<BlsDoryOpeningClaim>)],
    wiring: &mut Vec<BlsDoryOpeningClaim>,
    fixed_base: &mut Vec<BlsDoryOpeningClaim>,
) -> Result<(), BlsDorySharedLayoutError> {
    let commitment = role_commitment(role, proof, fixed_model)?;
    let claim = BlsDoryOpeningClaim {
        commitment,
        point,
        evaluation,
    };
    match role {
        SharedLinkRole::FixedBaseInput => fixed_base.push(claim),
        SharedLinkRole::MatrixActivation(bank) | SharedLinkRole::MatrixAccumulator(bank) => {
            matrices
                .get_mut(bank)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .push(claim)
        }
        SharedLinkRole::TransitionInput(index) | SharedLinkRole::TransitionActivation(index) => {
            transitions
                .get_mut(index)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .0
                .push(claim)
        }
        SharedLinkRole::WiringInitial
        | SharedLinkRole::WiringInput
        | SharedLinkRole::WiringOutput => wiring.push(claim),
    }
    Ok(())
}

fn role_commitment(
    role: SharedLinkRole,
    proof: &BlsDorySharedLayoutProof,
    fixed_model: &BlsDoryFixedModelIdentity,
) -> Result<BlsDoryGt, BlsDorySharedLayoutError> {
    Ok(match role {
        SharedLinkRole::FixedBaseInput => fixed_model.base_input_commitment,
        SharedLinkRole::MatrixActivation(bank) => {
            proof
                .matrices
                .get(bank)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .activation_commitment
        }
        SharedLinkRole::MatrixAccumulator(bank) => {
            proof
                .matrices
                .get(bank)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .accumulator_commitment
        }
        SharedLinkRole::TransitionInput(index) | SharedLinkRole::TransitionActivation(index) => {
            proof
                .transitions
                .get(index)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .arithmetic
                .oracle_commitment
        }
        SharedLinkRole::WiringInitial
        | SharedLinkRole::WiringInput
        | SharedLinkRole::WiringOutput => proof.wiring.oracle_commitment,
    })
}

/// Prove transition arithmetic and range constraints against one commitment.
pub fn prove_bls_dory_transition_range(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryTransitionRangeProof, BlsDorySharedLayoutError> {
    let arithmetic =
        prove_bls_dory_transition(binding, statement, mask_polynomial, witness, setup)?;
    let range = prove_bls_dory_range_logup(binding, statement, witness, setup)?;
    transition_range_proof(arithmetic, range)
}

/// Prove the combined transition checkpoint at an exact shared geometry.
pub fn prove_bls_dory_transition_range_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryTransitionRangeProof, BlsDorySharedLayoutError> {
    let arithmetic = prove_bls_dory_transition_at_variables(
        binding,
        statement,
        mask_polynomial,
        witness,
        packed_variables,
        setup,
    )?;
    let range = prove_bls_dory_range_logup_at_variables(
        binding,
        statement,
        witness,
        packed_variables,
        setup,
    )?;
    transition_range_proof(arithmetic, range)
}

fn transition_range_proof(
    arithmetic: BlsDoryTransitionProof,
    range: BlsDoryRangeLogUpProof,
) -> Result<BlsDoryTransitionRangeProof, BlsDorySharedLayoutError> {
    if arithmetic.oracle_commitment != range.transition_commitment {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    Ok(BlsDoryTransitionRangeProof { arithmetic, range })
}

/// Verify both halves of the transition relation against one commitment.
pub fn verify_bls_dory_transition_range(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &BlsDoryTransitionRangeProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    if proof.arithmetic.oracle_commitment != proof.range.transition_commitment {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    verify_bls_dory_transition(
        binding,
        statement,
        mask_polynomial,
        &proof.arithmetic,
        setup,
    )?;
    verify_bls_dory_range_logup(
        binding,
        statement,
        proof.arithmetic.oracle_commitment,
        &proof.range,
        setup,
    )?;
    Ok(())
}

/// Verify the combined transition checkpoint at an exact shared geometry.
pub fn verify_bls_dory_transition_range_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &BlsDoryTransitionRangeProof,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    if proof.arithmetic.oracle_commitment != proof.range.transition_commitment {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    verify_bls_dory_transition_at_variables(
        binding,
        statement,
        mask_polynomial,
        &proof.arithmetic,
        packed_variables,
        setup,
    )?;
    verify_bls_dory_range_logup_at_variables(
        binding,
        statement,
        proof.arithmetic.oracle_commitment,
        &proof.range,
        packed_variables,
        setup,
    )?;
    Ok(())
}

/// Project one Dory opening aggregate at the canonical production geometry.
pub fn projected_shared_production_opening_bytes() -> Result<usize, BlsDorySharedLayoutError> {
    Ok(projected_bls_dory_aggregate_bytes(
        BLS_DORY_SHARED_PRODUCTION_VARIABLES,
    )?)
}

/// Project the exact three-matrix/four-transition production frame after the
/// component-specific opening payloads have been replaced by one shared payload.
pub fn projected_shared_production_proof_bytes() -> Result<usize, BlsDorySharedLayoutError> {
    let matrix = projected_production_matrix_proof_bytes()?
        .checked_sub(projected_production_matrix_opening_bytes()?)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let arithmetic = projected_production_transition_proof_bytes()?
        .checked_sub(projected_production_transition_opening_bytes()?)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let range = projected_production_range_logup_proof_bytes()?
        .checked_sub(projected_production_range_logup_opening_bytes()?)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let wiring = projected_production_wiring_proof_bytes()?
        .checked_sub(projected_production_wiring_opening_bytes()?)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let mut total = SHARED_PROOF_HEADER_BYTES;
    for _ in 0..MAX_BLS_DORY_SHARED_MATRIX_PROOFS {
        total = framed_size(total, matrix)?;
    }
    for _ in 0..MAX_BLS_DORY_SHARED_TRANSITION_PROOFS {
        total = framed_size(total, arithmetic)?;
        total = framed_size(total, range)?;
    }
    total = framed_size(total, wiring)?;
    total = framed_size(
        total,
        shared_link_count(MAX_BLS_DORY_SHARED_MATRIX_PROOFS)?
            .checked_mul(BlsDoryFr::zero().compressed_size())
            .ok_or(BlsDorySharedLayoutError::ProofTooLarge)?,
    )?;
    total = framed_size(total, projected_shared_production_opening_bytes()?)?;
    if total > MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES {
        return Err(BlsDorySharedLayoutError::ProofTooLarge);
    }
    Ok(total)
}

/// Fail closed until every shared-layout blocker is resolved.
pub fn require_bls_dory_shared_layout_production_ready() -> Result<(), BlsDorySharedLayoutError> {
    Err(BlsDorySharedLayoutError::NotProductionReady)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BuiltModelBankFixture, SmallModelBankFixture, StructuredMaskPolynomial,
        StructuredMatrixStatement, StructuredTransitionStatement, StructuredTransitionWitness,
        StructuredWiringStatement, V2_TRANSITION_MODULUS, build_small_model_bank,
        dory_bls12_381_aggregate::MAX_BLS_DORY_AGGREGATE_CLAIMS,
        dory_bls12_381_matrix::{
            BlsDoryMatrixProof, prove_bls_dory_matrix_at_variables,
            verify_bls_dory_matrix_at_variables,
        },
        dory_bls12_381_prototype::{MAX_BLS_DORY_SETUP_VARIABLES, deterministic_bls_dory_setup},
        dory_bls12_381_wiring::{
            BlsDoryWiringProof, prove_bls_dory_wiring_at_variables,
            verify_bls_dory_wiring_at_variables,
        },
        model_bank::{MODEL_BANK_HEADER_BYTES, ModelBankError},
    };

    const FIXTURE_VARIABLES: usize = 10;
    const OUTPUT_MODULUS: u64 = 251;
    const OUTPUT_CENTER: i64 = 125;

    fn authenticated_fixed_model_fixture() -> (
        BuiltModelBankFixture,
        ModelPcsIdentity,
        Vec<i64>,
        Vec<Vec<i64>>,
    ) {
        let base = [0, 125, 250, 126];
        let layers = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ];
        let layer_slices = layers
            .iter()
            .map(|layer| layer.as_slice())
            .collect::<Vec<_>>();
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
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        let base_values = base
            .iter()
            .map(|value| i64::from(*value) - 125)
            .collect::<Vec<_>>();
        let weight_banks = layers
            .chunks_exact(2)
            .map(|bank| {
                bank.iter()
                    .flat_map(|layer| layer.iter())
                    .map(|value| i64::from(*value) - 125)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        (built, identity, base_values, weight_banks)
    }

    #[test]
    fn authenticated_model_stream_matches_in_memory_fixed_commitments() {
        const PADDED_VARIABLES: usize = 5;
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let (built, model, base, weight_banks) = authenticated_fixed_model_fixture();
        let weight_slices = weight_banks.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let expected = derive_bls_dory_fixed_model_identity(
            &model,
            &base,
            &weight_slices,
            PADDED_VARIABLES,
            &setup,
        )
        .unwrap();
        let streamed = derive_bls_dory_fixed_model_identity_from_verified_bank(
            Cursor::new(&built.bytes),
            &built.manifest,
            &model,
            PADDED_VARIABLES,
            &setup,
        )
        .unwrap();

        assert_eq!(streamed, expected);
        assert_eq!(streamed.digest().unwrap(), expected.digest().unwrap());
        assert_eq!(MAX_BLS_DORY_SETUP_VARIABLES, 33);
        assert_eq!(
            BLS_DORY_SHARED_PRODUCTION_VARIABLES,
            MAX_BLS_DORY_SETUP_VARIABLES
        );
    }

    #[test]
    fn authenticated_model_stream_never_publishes_failed_or_reordered_input() {
        const PADDED_VARIABLES: usize = 5;
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let (built, model, _, _) = authenticated_fixed_model_fixture();

        let mut corrupted = built.bytes.clone();
        corrupted[MODEL_BANK_HEADER_BYTES] ^= 1;
        assert!(matches!(
            derive_bls_dory_fixed_model_identity_from_verified_bank(
                Cursor::new(corrupted),
                &built.manifest,
                &model,
                PADDED_VARIABLES,
                &setup,
            ),
            Err(ModelBankFieldStreamError::ModelBank(
                ModelBankError::RawRootMismatch
            ))
        ));

        let mut trailing = built.bytes.clone();
        trailing.push(0);
        assert!(matches!(
            derive_bls_dory_fixed_model_identity_from_verified_bank(
                Cursor::new(trailing),
                &built.manifest,
                &model,
                PADDED_VARIABLES,
                &setup,
            ),
            Err(ModelBankFieldStreamError::ModelBank(
                ModelBankError::TrailingBytes
            ))
        ));

        let mut sink = BlsDoryFixedModelSink::new(&model, PADDED_VARIABLES, &setup).unwrap();
        assert_eq!(
            sink.write_chunk(ModelFieldChunk {
                role: ModelPcsRole::WeightBank { index: 0 },
                role_offset: 0,
                role_elements: 8,
                elements: &[GOLDILOCKS_MODULUS - 124],
            }),
            Err(BlsDoryFixedModelStreamError::InvalidChunk)
        );
        assert_eq!(
            bls_scalar_from_model_field(126),
            Err(BlsDoryFixedModelStreamError::InvalidFieldValue)
        );
        assert_eq!(
            bls_scalar_from_model_field(GOLDILOCKS_MODULUS),
            Err(BlsDoryFixedModelStreamError::InvalidFieldValue)
        );
    }

    fn matrix_fixture() -> (StructuredMatrixStatement, Vec<i64>, Vec<i64>, Vec<i64>) {
        let statement = StructuredMatrixStatement {
            layers: 2,
            rows: 2,
            inner: 2,
            cols: 2,
            max_abs_activation: 10,
            max_abs_weight: 10,
            max_abs_accumulator: 100,
        };
        (
            statement,
            vec![1, 2, 3, 4, -1, 2, 5, -2],
            vec![2, 1, -1, 3, 4, -2, 1, 5],
            vec![0, 7, 2, 15, -2, 12, 18, -20],
        )
    }

    fn transition_fixture() -> (
        StructuredTransitionStatement,
        StructuredMaskPolynomial,
        StructuredTransitionWitness,
    ) {
        let statement = StructuredTransitionStatement {
            layers: 2,
            rows: 2,
            cols: 2,
            max_abs_accumulator: 65_536,
            max_mask: 5_000,
        };
        let mask = StructuredMaskPolynomial::from_challenge(&[0x5a; 32], 2, 2, 2).unwrap();
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
        let modulus = u64::from(V2_TRANSITION_MODULUS);
        for index in 0..statement.layers * statement.rows * statement.cols {
            let accumulator = index as i64 * 113 - 390;
            let mask_value = mask.value_at_boolean_index(statement, index).unwrap();
            let combined = i128::from(accumulator) + i128::from(mask_value);
            let negative = u64::from(combined < 0);
            let encoded = u64::try_from(if combined < 0 {
                i128::from(modulus) + combined
            } else {
                combined
            })
            .unwrap();
            let square = encoded * encoded;
            let square_quotient = square / modulus;
            let square_remainder = square % modulus;
            let cube = square_remainder * encoded;
            let cube_quotient = cube / modulus;
            let cube_remainder = cube % modulus;
            let output_quotient = cube_remainder / OUTPUT_MODULUS;
            let output_remainder = cube_remainder % OUTPUT_MODULUS;

            witness.accumulators.push(accumulator);
            witness.masks.push(mask_value);
            witness.encoded.push(encoded);
            witness.square_quotients.push(square_quotient);
            witness.square_remainders.push(square_remainder);
            witness.cube_quotients.push(cube_quotient);
            witness.cube_remainders.push(cube_remainder);
            witness.output_quotients.push(output_quotient);
            witness.output_remainders.push(output_remainder);
            witness.negative.push(negative);
            witness
                .activations
                .push(i64::try_from(output_remainder).unwrap() - OUTPUT_CENTER);
        }
        (statement, mask, witness)
    }

    fn wiring_fixture() -> (StructuredWiringStatement, Vec<i64>, Vec<i64>, Vec<i64>) {
        (
            StructuredWiringStatement {
                banks: 2,
                layers_per_bank: 2,
                rows: 2,
                cols: 2,
                max_abs_activation: 100,
            },
            vec![1, 2, 3, 4],
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        )
    }

    struct LinkedMatrixWitness {
        activations: Vec<i64>,
        weights: Vec<i64>,
        accumulators: Vec<i64>,
    }

    struct LinkedTransitionWitness {
        statement: StructuredTransitionStatement,
        mask: StructuredMaskPolynomial,
        witness: StructuredTransitionWitness,
    }

    struct LinkedFixture {
        matrix_statement: StructuredMatrixStatement,
        matrices: Vec<LinkedMatrixWitness>,
        transitions: Vec<LinkedTransitionWitness>,
        wiring_statement: StructuredWiringStatement,
        initial: Vec<i64>,
        inputs: Vec<i64>,
        outputs: Vec<i64>,
    }

    fn linked_fixture(banks: usize) -> LinkedFixture {
        let rows = 2;
        let cols = 2;
        let layers = 2;
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows,
            cols,
            max_abs_accumulator: 65_536,
            max_mask: 5_000,
        };
        let initialization_mask =
            StructuredMaskPolynomial::from_challenge(&[0x31; 32], 1, rows, cols).unwrap();
        let initialization_witness = transition_witness_from_accumulators(
            initialization_statement,
            &initialization_mask,
            &[-7, 11, 23, -19],
        );
        let initial = initialization_witness.activations.clone();
        let mut transitions = vec![LinkedTransitionWitness {
            statement: initialization_statement,
            mask: initialization_mask,
            witness: initialization_witness,
        }];
        let matrix_statement = StructuredMatrixStatement {
            layers,
            rows,
            inner: cols,
            cols,
            max_abs_activation: 125,
            max_abs_weight: 10,
            max_abs_accumulator: 65_536,
        };
        let transition_statement = StructuredTransitionStatement {
            layers,
            rows,
            cols,
            max_abs_accumulator: 65_536,
            max_mask: 5_000,
        };
        let mut matrices = Vec::with_capacity(banks);
        let mut wiring_inputs = Vec::new();
        let mut wiring_outputs = Vec::new();
        let mut current = initial.clone();
        for bank in 0..banks {
            let mask = StructuredMaskPolynomial::from_challenge(
                &[0x40 + bank as u8; 32],
                layers,
                rows,
                cols,
            )
            .unwrap();
            let weights = (0..layers * cols * cols)
                .map(|index| ((index + bank) % 5) as i64 - 2)
                .collect::<Vec<_>>();
            let mut activations = Vec::with_capacity(layers * rows * cols);
            let mut accumulators = Vec::with_capacity(layers * rows * cols);
            let mut outputs = Vec::with_capacity(layers * rows * cols);
            for layer in 0..layers {
                activations.extend_from_slice(&current);
                let mut layer_accumulators = Vec::with_capacity(rows * cols);
                for row in 0..rows {
                    for col in 0..cols {
                        let mut accumulator = 0_i64;
                        for common in 0..cols {
                            accumulator += current[row * cols + common]
                                * weights[(layer * cols + common) * cols + col];
                        }
                        layer_accumulators.push(accumulator);
                    }
                }
                let layer_offset = layer * rows * cols;
                let layer_witness = transition_witness_from_accumulators_at_offset(
                    transition_statement,
                    &mask,
                    &layer_accumulators,
                    layer_offset,
                );
                accumulators.extend_from_slice(&layer_accumulators);
                outputs.extend_from_slice(&layer_witness.activations);
                current = layer_witness.activations;
            }
            let witness =
                transition_witness_from_accumulators(transition_statement, &mask, &accumulators);
            assert_eq!(witness.activations, outputs);
            wiring_inputs.extend_from_slice(&activations);
            wiring_outputs.extend_from_slice(&outputs);
            matrices.push(LinkedMatrixWitness {
                activations,
                weights,
                accumulators,
            });
            transitions.push(LinkedTransitionWitness {
                statement: transition_statement,
                mask,
                witness,
            });
        }
        LinkedFixture {
            matrix_statement,
            matrices,
            transitions,
            wiring_statement: StructuredWiringStatement {
                banks,
                layers_per_bank: layers,
                rows,
                cols,
                max_abs_activation: 125,
            },
            initial,
            inputs: wiring_inputs,
            outputs: wiring_outputs,
        }
    }

    fn fixed_model_fixture(
        fixture: &LinkedFixture,
        setup: &DeterministicBlsDorySetup,
    ) -> (ModelPcsIdentity, BlsDoryFixedModelIdentity) {
        let model = ModelPcsIdentity {
            model_version: 1,
            batch: fixture.wiring_statement.rows as u32,
            dimension: fixture.wiring_statement.cols as u32,
            layers_per_bank: fixture.wiring_statement.layers_per_bank as u32,
            model_byte_root: [0x11; 32],
            pcs_suite_parameter_digest: [0x22; 32],
            base_input_commitment: [0x33; 32],
            weight_bank_commitments: (0..fixture.matrices.len())
                .map(|bank| [0x40 + bank as u8; 32])
                .collect(),
        };
        let weights = fixture
            .matrices
            .iter()
            .map(|matrix| matrix.weights.as_slice())
            .collect::<Vec<_>>();
        let fixed = derive_bls_dory_fixed_model_identity(
            &model,
            &fixture.transitions[0].witness.accumulators,
            &weights,
            FIXTURE_VARIABLES,
            setup,
        )
        .unwrap();
        (model, fixed)
    }

    fn transition_witness_from_accumulators(
        statement: StructuredTransitionStatement,
        mask: &StructuredMaskPolynomial,
        accumulators: &[i64],
    ) -> StructuredTransitionWitness {
        transition_witness_from_accumulators_at_offset(statement, mask, accumulators, 0)
    }

    fn transition_witness_from_accumulators_at_offset(
        statement: StructuredTransitionStatement,
        mask: &StructuredMaskPolynomial,
        accumulators: &[i64],
        offset: usize,
    ) -> StructuredTransitionWitness {
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
        let modulus = u64::from(V2_TRANSITION_MODULUS);
        for (local_index, accumulator) in accumulators.iter().copied().enumerate() {
            let index = offset + local_index;
            let mask_value = mask.value_at_boolean_index(statement, index).unwrap();
            let combined = i128::from(accumulator) + i128::from(mask_value);
            let negative = u64::from(combined < 0);
            let encoded = u64::try_from(if combined < 0 {
                i128::from(modulus) + combined
            } else {
                combined
            })
            .unwrap();
            let square = encoded * encoded;
            let square_quotient = square / modulus;
            let square_remainder = square % modulus;
            let cube = square_remainder * encoded;
            let cube_quotient = cube / modulus;
            let cube_remainder = cube % modulus;
            let output_quotient = cube_remainder / OUTPUT_MODULUS;
            let output_remainder = cube_remainder % OUTPUT_MODULUS;
            witness.accumulators.push(accumulator);
            witness.masks.push(mask_value);
            witness.encoded.push(encoded);
            witness.square_quotients.push(square_quotient);
            witness.square_remainders.push(square_remainder);
            witness.cube_quotients.push(cube_quotient);
            witness.cube_remainders.push(cube_remainder);
            witness.output_quotients.push(output_quotient);
            witness.output_remainders.push(output_remainder);
            witness.negative.push(negative);
            witness
                .activations
                .push(i64::try_from(output_remainder).unwrap() - OUTPUT_CENTER);
        }
        witness
    }

    #[test]
    fn all_scalar_components_accept_one_exact_shared_layout() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let (matrix_statement, activations, weights, accumulators) = matrix_fixture();
        let matrix = prove_bls_dory_matrix_at_variables(
            b"shared-layout",
            matrix_statement,
            &activations,
            &weights,
            &accumulators,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_matrix_at_variables(
            b"shared-layout",
            matrix_statement,
            &matrix,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        let (transition_statement, mask, witness) = transition_fixture();
        let transition = prove_bls_dory_transition_range_at_variables(
            b"shared-layout",
            transition_statement,
            &mask,
            &witness,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_transition_range_at_variables(
            b"shared-layout",
            transition_statement,
            &mask,
            &transition,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        let (wiring_statement, initial, inputs, outputs) = wiring_fixture();
        let wiring = prove_bls_dory_wiring_at_variables(
            b"shared-layout",
            wiring_statement,
            &initial,
            &inputs,
            &outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_wiring_at_variables(
            b"shared-layout",
            wiring_statement,
            &wiring,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        assert_eq!(usize::from(matrix.padded_variables), FIXTURE_VARIABLES);
        assert_eq!(
            usize::from(transition.arithmetic.packed_variables),
            FIXTURE_VARIABLES
        );
        assert_eq!(
            usize::from(transition.range.packed_variables),
            FIXTURE_VARIABLES
        );
        assert_eq!(usize::from(wiring.packed_variables), FIXTURE_VARIABLES);
        assert_eq!(matrix.opening_proof.len(), 21_775);
        assert_eq!(transition.arithmetic.opening_proof.len(), 21_775);
        assert_eq!(transition.range.opening_proof.len(), 21_775);
        assert_eq!(wiring.opening_proof.len(), 21_775);
        let fixture_claims =
            3 + BLS_DORY_TRANSITION_OPENING_CLAIMS + BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS + 9;
        assert_eq!(fixture_claims, 28);
        assert!(fixture_claims <= MAX_BLS_DORY_AGGREGATE_CLAIMS);

        let matrix_encoded = matrix.encode(matrix_statement).unwrap();
        assert_eq!(
            BlsDoryMatrixProof::decode_with_variables(
                &matrix_encoded,
                matrix_statement,
                FIXTURE_VARIABLES,
            )
            .unwrap(),
            matrix
        );
        let transition_encoded = transition.arithmetic.encode(transition_statement).unwrap();
        assert_eq!(
            BlsDoryTransitionProof::decode_with_variables(
                &transition_encoded,
                transition_statement,
                FIXTURE_VARIABLES,
            )
            .unwrap(),
            transition.arithmetic
        );
        let wiring_encoded = wiring.encode(wiring_statement).unwrap();
        assert_eq!(
            BlsDoryWiringProof::decode_with_variables(
                &wiring_encoded,
                wiring_statement,
                FIXTURE_VARIABLES,
            )
            .unwrap(),
            wiring
        );
    }

    #[test]
    fn scalar_components_share_one_opening_payload() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let fixture = linked_fixture(1);
        let (model, fixed_model) = fixed_model_fixture(&fixture, &setup);
        let matrix_statements = vec![fixture.matrix_statement; fixture.matrices.len()];
        let transition_statements = fixture
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let masks = fixture
            .transitions
            .iter()
            .map(|transition| &transition.mask)
            .collect::<Vec<_>>();
        let matrix_inputs = fixture
            .matrices
            .iter()
            .map(|matrix| BlsDoryMatrixProverInput {
                statement: fixture.matrix_statement,
                activations: &matrix.activations,
                weights: &matrix.weights,
                accumulators: &matrix.accumulators,
            })
            .collect::<Vec<_>>();
        let transition_inputs = fixture
            .transitions
            .iter()
            .map(|transition| BlsDoryTransitionProverInput {
                statement: transition.statement,
                mask_polynomial: &transition.mask,
                witness: &transition.witness,
            })
            .collect::<Vec<_>>();
        let proof = prove_bls_dory_shared_layout_at_variables(
            b"shared-opening",
            &model,
            &fixed_model,
            &matrix_inputs,
            &transition_inputs,
            fixture.wiring_statement,
            &fixture.initial,
            &fixture.inputs,
            &fixture.outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_shared_layout_at_variables(
            b"shared-opening",
            &model,
            &fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &proof,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        let encoded = proof
            .encode(
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        assert_eq!(encoded.len(), 35_953);
        let decoded = BlsDorySharedLayoutProof::decode_with_variables(
            &encoded,
            &matrix_statements,
            &transition_statements,
            fixture.wiring_statement,
            FIXTURE_VARIABLES,
        )
        .unwrap();
        assert_eq!(decoded, proof);
        verify_bls_dory_shared_layout_at_variables(
            b"shared-opening",
            &model,
            &fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &decoded,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        assert!(proof.matrices[0].opening_proof.is_empty());
        assert!(proof.transitions[0].arithmetic.opening_proof.is_empty());
        assert!(proof.transitions[0].range.opening_proof.is_empty());
        assert!(proof.transitions[1].arithmetic.opening_proof.is_empty());
        assert!(proof.transitions[1].range.opening_proof.is_empty());
        assert!(proof.wiring.opening_proof.is_empty());
        assert_eq!(proof.link_evaluations.len(), 5);
        assert_eq!(proof.opening_proof.len(), 21_775);

        let mut malformed = encoded.clone();
        malformed[0] ^= 1;
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );
        let mut malformed = encoded.clone();
        malformed[16..20].copy_from_slice(&0_u32.to_le_bytes());
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );
        let mut link_frame_offset = SHARED_PROOF_HEADER_BYTES;
        for _ in 0..matrix_statements.len() + 2 * transition_statements.len() + 1 {
            let frame_bytes = read_u32(&encoded, link_frame_offset).unwrap() as usize;
            link_frame_offset += 4 + frame_bytes;
        }
        let mut malformed = encoded.clone();
        malformed[link_frame_offset..link_frame_offset + 4].copy_from_slice(&0_u32.to_le_bytes());
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );
        let mut malformed = encoded.clone();
        malformed.push(0);
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.link_evaluations[0] = changed.link_evaluations[0] + BlsDoryFr::one();
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut wrong_model = model.clone();
        wrong_model.model_byte_root[0] ^= 1;
        assert_eq!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &wrong_model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &proof,
                FIXTURE_VARIABLES,
                &setup,
            ),
            Err(BlsDorySharedLayoutError::FixedModelIdentity)
        );

        let mut wrong_weight = fixed_model.clone();
        wrong_weight.weight_bank_commitments[0] =
            wrong_weight.weight_bank_commitments[0].scale(&BlsDoryFr::from_u64(2));
        assert_eq!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &wrong_weight,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &proof,
                FIXTURE_VARIABLES,
                &setup,
            ),
            Err(BlsDorySharedLayoutError::FixedModelCommitment)
        );

        let mut wrong_base = fixed_model.clone();
        wrong_base.base_input_commitment = wrong_base
            .base_input_commitment
            .scale(&BlsDoryFr::from_u64(2));
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &wrong_base,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &proof,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        let middle = changed.opening_proof.len() / 2;
        changed.opening_proof[middle] ^= 1;
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.matrices[0].transcript_digest[0] ^= 1;
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.transitions[0].range.transition_commitment =
            changed.transitions[0].range.multiplicity_commitment;
        assert_eq!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            ),
            Err(BlsDorySharedLayoutError::TransitionRangeCommitment)
        );

        let mut changed = proof.clone();
        changed.wiring.opening_proof.push(0);
        assert_eq!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            ),
            Err(BlsDorySharedLayoutError::InvalidProofShape)
        );
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"other-binding",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &proof,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );
    }

    #[test]
    fn transition_range_composition_requires_both_proofs_and_one_commitment() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let (statement, mask, witness) = transition_fixture();
        let proof =
            prove_bls_dory_transition_range(b"composed", statement, &mask, &witness, &setup)
                .unwrap();
        verify_bls_dory_transition_range(b"composed", statement, &mask, &proof, &setup).unwrap();

        let mut mismatched = proof.clone();
        mismatched.range.transition_commitment = mismatched.range.multiplicity_commitment;
        assert_eq!(
            verify_bls_dory_transition_range(b"composed", statement, &mask, &mismatched, &setup,),
            Err(BlsDorySharedLayoutError::TransitionRangeCommitment)
        );

        let mut missing_range = proof;
        missing_range.range.opening_proof[0] ^= 1;
        assert!(
            verify_bls_dory_transition_range(
                b"composed",
                statement,
                &mask,
                &missing_range,
                &setup,
            )
            .is_err()
        );
    }

    #[test]
    fn production_component_counts_share_one_payload() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let fixture = linked_fixture(3);
        let (model, fixed_model) = fixed_model_fixture(&fixture, &setup);
        let matrix_statements = vec![fixture.matrix_statement; fixture.matrices.len()];
        let transition_statements = fixture
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let masks = fixture
            .transitions
            .iter()
            .map(|transition| &transition.mask)
            .collect::<Vec<_>>();
        let matrix_inputs = fixture
            .matrices
            .iter()
            .map(|matrix| BlsDoryMatrixProverInput {
                statement: fixture.matrix_statement,
                activations: &matrix.activations,
                weights: &matrix.weights,
                accumulators: &matrix.accumulators,
            })
            .collect::<Vec<_>>();
        let transition_inputs = fixture
            .transitions
            .iter()
            .map(|transition| BlsDoryTransitionProverInput {
                statement: transition.statement,
                mask_polynomial: &transition.mask,
                witness: &transition.witness,
            })
            .collect::<Vec<_>>();
        let proof = prove_bls_dory_shared_layout_at_variables(
            b"production-topology",
            &model,
            &fixed_model,
            &matrix_inputs,
            &transition_inputs,
            fixture.wiring_statement,
            &fixture.initial,
            &fixture.inputs,
            &fixture.outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_shared_layout_at_variables(
            b"production-topology",
            &model,
            &fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &proof,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert_eq!(proof.matrices.len(), 3);
        assert_eq!(proof.transitions.len(), 4);
        assert_eq!(proof.link_evaluations.len(), 11);
        assert_eq!(proof.opening_proof.len(), 21_775);
        assert_eq!(3 * 3 + 4 * (12 + 4) + 13 + 22, 108);

        let encoded = proof
            .encode(
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        let decoded = BlsDorySharedLayoutProof::decode_with_variables(
            &encoded,
            &matrix_statements,
            &transition_statements,
            fixture.wiring_statement,
            FIXTURE_VARIABLES,
        )
        .unwrap();
        assert_eq!(decoded, proof);

        let mut reordered = proof.clone();
        reordered.matrices.swap(0, 1);
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"production-topology",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &reordered,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut omitted = proof;
        omitted.matrices.pop();
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"production-topology",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &omitted,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );
    }

    #[test]
    fn shared_layout_mismatches_fail_before_opening_verification() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let mismatched_variables = FIXTURE_VARIABLES - 1;

        let (matrix_statement, activations, weights, accumulators) = matrix_fixture();
        let matrix = prove_bls_dory_matrix_at_variables(
            b"mismatch",
            matrix_statement,
            &activations,
            &weights,
            &accumulators,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            verify_bls_dory_matrix_at_variables(
                b"mismatch",
                matrix_statement,
                &matrix,
                mismatched_variables,
                &setup,
            )
            .is_err()
        );
        let matrix_encoded = matrix.encode(matrix_statement).unwrap();
        assert!(
            BlsDoryMatrixProof::decode_with_variables(
                &matrix_encoded,
                matrix_statement,
                mismatched_variables,
            )
            .is_err()
        );

        let (transition_statement, mask, witness) = transition_fixture();
        let transition = prove_bls_dory_transition_at_variables(
            b"mismatch",
            transition_statement,
            &mask,
            &witness,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            verify_bls_dory_transition_at_variables(
                b"mismatch",
                transition_statement,
                &mask,
                &transition,
                mismatched_variables,
                &setup,
            )
            .is_err()
        );
        let transition_encoded = transition.encode(transition_statement).unwrap();
        assert!(
            BlsDoryTransitionProof::decode_with_variables(
                &transition_encoded,
                transition_statement,
                mismatched_variables,
            )
            .is_err()
        );

        let (wiring_statement, initial, inputs, outputs) = wiring_fixture();
        let wiring = prove_bls_dory_wiring_at_variables(
            b"mismatch",
            wiring_statement,
            &initial,
            &inputs,
            &outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            verify_bls_dory_wiring_at_variables(
                b"mismatch",
                wiring_statement,
                &wiring,
                mismatched_variables,
                &setup,
            )
            .is_err()
        );
        let wiring_encoded = wiring.encode(wiring_statement).unwrap();
        assert!(
            BlsDoryWiringProof::decode_with_variables(
                &wiring_encoded,
                wiring_statement,
                mismatched_variables,
            )
            .is_err()
        );
    }

    #[test]
    fn production_claim_accounting_and_shared_projection_are_explicit() {
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_VARIABLES, 33);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_DIRECT_CLAIMS, 480);
        assert_eq!(BLS_DORY_SHARED_ARITHMETIC_TRANSITION_CLAIMS, 48);
        assert_eq!(BLS_DORY_SHARED_LOGUP_RANGE_TRANSITION_CLAIMS, 16);
        assert_eq!(BLS_DORY_SHARED_COMPRESSED_TRANSITION_CLAIMS, 64);
        assert_eq!(BLS_DORY_SHARED_COMPRESSED_CHECKPOINT_CLAIMS, 104);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS, 11);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_EQUALITY_CLAIMS, 22);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_CLAIMS, 126);
        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
        assert_eq!(projected_shared_production_opening_bytes().unwrap(), 70_639);
        assert_eq!(projected_shared_production_proof_bytes().unwrap(), 133_373);
        assert!(
            projected_shared_production_proof_bytes().unwrap()
                < MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES
        );
        assert_eq!(BLS_DORY_SHARED_LAYOUT_PRODUCTION_BLOCKERS.len(), 2);
        assert_eq!(
            require_bls_dory_shared_layout_production_ready(),
            Err(BlsDorySharedLayoutError::NotProductionReady)
        );
    }
}
