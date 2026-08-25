//! BLS12-381 scalar-field transition sumcheck authenticated by Dory.
//!
//! The 110 canonical transition oracles are packed into 128 selector slots
//! under one Dory commitment. The arithmetic sumcheck proves the seven regular
//! transition constraints and authenticates their twelve terminal roles. The
//! range LogUp checkpoint proves membership and reconstruction against the same
//! commitment. The executable prover remains capped below the production n=33
//! table.

use std::io::Cursor;
use std::path::Path;
#[cfg(any(test, feature = "whir-prototype"))]
use std::sync::{Arc, Mutex};

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use thiserror::Error;

use crate::{
    STRUCTURED_TRANSITION_ACTIVATION_ORACLE, STRUCTURED_TRANSITION_INPUT_ORACLE,
    STRUCTURED_TRANSITION_ORACLES, STRUCTURED_TRANSITION_REGULAR_ORACLES, StructuredMaskPolynomial,
    StructuredTransitionError, StructuredTransitionStatement, StructuredTransitionWitness,
    V2_TRANSITION_MODULUS,
    dory_bls12_381_aggregate::{
        BlsDoryAggregateError, BlsDoryAggregateLayout, BlsDoryCommittedPolynomial,
        BlsDoryCompactRowSource, BlsDoryDeferredOpeningSet, BlsDoryOpeningClaim,
        MAX_BLS_DORY_AGGREGATE_BYTES, commit_bls_dory_compact_row_source_with_scratch,
        commit_bls_dory_padded_prefix_with_optional_scratch, projected_bls_dory_aggregate_bytes,
        prove_bls_dory_deferred_opening_sets, verify_bls_dory_openings,
    },
    dory_bls12_381_compact_artifact::BlsDoryCompactArtifactSpec,
    dory_bls12_381_fold_artifact::{
        BlsDoryFoldArtifact, BlsDoryFoldArtifactError, BlsDoryFoldArtifactSpec,
        BlsDoryFoldArtifactWriter,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    dory_bls12_381_streaming::BlsDoryRowSource,
    structured_transition::{
        structured_transition_range_specs, validate_streaming_witness, validate_witness,
    },
};

#[cfg(any(test, feature = "whir-prototype"))]
use crate::{
    dory_bls12_381_aggregate::{
        BlsDoryReleasedCompactSource, commit_bls_dory_existing_compact_artifact,
        source_artifact_spec,
    },
    dory_bls12_381_compact_artifact::{
        BlsDoryCompactArtifact, BlsDoryGroupedCompactArtifactWriter,
    },
    dory_bls12_381_execution_artifact::{
        BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS, BlsDoryExecutionAccumulatorArtifact,
        BlsDoryExecutionAccumulatorArtifactContext, BlsDoryExecutionAccumulatorColumn,
    },
};

#[cfg(feature = "whir-prototype")]
use crate::{
    dory_bls12_381_execution_provider::BlsDoryV3ExecutionArtifactReader,
    dory_bls12_381_logup::{
        BLS_DORY_RANGE_LOGUP_TABLE_VALUES, BlsDoryRangeLogUpError, PreparedBlsDoryRangeLogUpProof,
        prove_bls_dory_range_logup_deferred_with_precommitted_row_source_and_scratch,
    },
};

/// Version of the arithmetic-only scalar-field transition transcript.
pub const BLS_DORY_TRANSITION_VERSION: u16 = 2;
/// Seven bits address 128 slots, covering all 110 transition oracles.
pub const BLS_DORY_TRANSITION_SELECTOR_VARIABLES: usize = 7;
/// Seven regular constraints define the non-range transition arithmetic.
pub const BLS_DORY_TRANSITION_ARITHMETIC_CONSTRAINTS: usize = 7;
/// The arithmetic proof opens the twelve regular transition roles.
pub const BLS_DORY_TRANSITION_OPENING_CLAIMS: usize = STRUCTURED_TRANSITION_REGULAR_ORACLES;
/// Equality weighting raises the quadratic arithmetic relation to degree three.
pub const BLS_DORY_TRANSITION_SUMCHECK_DEGREE: usize = 3;
/// Production transition banks contain 2^26 cells and therefore pack to n=33.
pub const PRODUCTION_BLS_DORY_TRANSITION_VARIABLES: usize = 33;
/// This checkpoint is not accepted by consensus.
pub const BLS_DORY_TRANSITION_PRODUCTION_READY: bool = false;
/// Remaining gates on this transition path.
pub const BLS_DORY_TRANSITION_PRODUCTION_BLOCKERS: [&str; 3] = [
    "the authenticated out-of-core transition sumcheck preserves exact proofs, but n=33 latency, peak disk, and peak memory have not been measured",
    "the executable algebraic union bound exists, but Dory knowledge soundness has not been independently reviewed",
    "the scalar transition transcript and packed opening path have not received an external audit",
];

const ORACLE_SLOTS: usize = 1 << BLS_DORY_TRANSITION_SELECTOR_VARIABLES;
pub(crate) const PROOF_MAGIC: [u8; 8] = *b"CFBLST01";
const PROOF_HEADER_BYTES: usize = 20;
const MAX_TRANSITION_PROOF_BYTES: usize = 262_128;
const MAX_TRANSITION_BINDING_BYTES: usize = 4_096;
const OUTPUT_MODULUS: u64 = 251;
const OUTPUT_CENTER: u64 = 125;
const ACCUMULATOR: usize = STRUCTURED_TRANSITION_INPUT_ORACLE;
const MASK: usize = 1;
const ENCODED: usize = 2;
const SQUARE_QUOTIENT: usize = 3;
const SQUARE_REMAINDER: usize = 4;
const CUBE_QUOTIENT: usize = 5;
const CUBE_REMAINDER: usize = 6;
const OUTPUT_QUOTIENT: usize = 7;
const OUTPUT_REMAINDER: usize = 8;
const NEGATIVE: usize = 9;
const ACTIVATION: usize = STRUCTURED_TRANSITION_ACTIVATION_ORACLE;
const SHIFTED_ACCUMULATOR: usize = 11;
const TRANSITION_FOLD_SLOTS: usize = 16;
#[cfg(any(test, feature = "whir-prototype"))]
const TRANSITION_GROUPED_COMPACT_CHUNK_CELLS: usize = 1 << 17;
pub(crate) const TRANSITION_SIGNED_WORD_SELECTORS: u64 =
    (1u64 << ACCUMULATOR) | (1u64 << ACTIVATION);
const TRANSITION_FIXED_WORD_WIDTH_CODES: u64 = (3u64 << (OUTPUT_QUOTIENT * 2))
    | (1u64 << (OUTPUT_REMAINDER * 2))
    | (1u64 << (NEGATIVE * 2))
    | (1u64 << (ACTIVATION * 2));
pub(crate) const PRODUCTION_TRANSITION_WORD_WIDTH_CODES: u64 =
    TRANSITION_FIXED_WORD_WIDTH_CODES | (2u64 << (MASK * 2));

fn transition_word_width_codes(max_mask: u64) -> u64 {
    TRANSITION_FIXED_WORD_WIDTH_CODES
        | if max_mask <= u64::from(u16::MAX) {
            2u64 << (MASK * 2)
        } else {
            0
        }
}

/// In-memory transition proof plus its canonical Dory opening payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryTransitionProof {
    pub protocol_version: u16,
    pub packed_variables: u16,
    pub oracle_commitment: BlsDoryGt,
    pub rounds: Vec<Vec<BlsDoryFr>>,
    pub terminal_evaluations: Vec<BlsDoryFr>,
    pub transcript_digest: [u8; 32],
    pub opening_proof: Vec<u8>,
}

pub(crate) struct PreparedBlsDoryTransitionProof {
    pub(crate) proof: BlsDoryTransitionProof,
    pub(crate) openings: BlsDoryDeferredOpeningSet,
}

impl BlsDoryTransitionProof {
    /// Encode the exact statement-bound proof shape canonically.
    pub fn encode(
        &self,
        statement: StructuredTransitionStatement,
    ) -> Result<Vec<u8>, BlsDoryTransitionError> {
        self.encode_with_opening(statement, true)
    }

    pub(crate) fn encode_deferred(
        &self,
        statement: StructuredTransitionStatement,
    ) -> Result<Vec<u8>, BlsDoryTransitionError> {
        self.encode_with_opening(statement, false)
    }

    fn encode_with_opening(
        &self,
        statement: StructuredTransitionStatement,
        require_opening: bool,
    ) -> Result<Vec<u8>, BlsDoryTransitionError> {
        validate_proof_shape_with_opening(
            statement,
            self,
            usize::from(self.packed_variables),
            require_opening,
        )?;
        if !require_opening && !self.opening_proof.is_empty() {
            return Err(BlsDoryTransitionError::InvalidProofShape);
        }
        let opening_len = u32::try_from(self.opening_proof.len())
            .map_err(|_| BlsDoryTransitionError::ProofTooLarge)?;
        let expected = transition_wire_bytes(self.rounds.len(), self.opening_proof.len())?;
        let mut encoded = Vec::with_capacity(expected);
        encoded.extend_from_slice(&PROOF_MAGIC);
        encoded.extend_from_slice(&self.protocol_version.to_le_bytes());
        encoded.extend_from_slice(&self.packed_variables.to_le_bytes());
        encoded.extend_from_slice(&(self.rounds.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&(self.terminal_evaluations.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&opening_len.to_le_bytes());
        append_serialized(&mut encoded, &self.oracle_commitment)?;
        for round in &self.rounds {
            for evaluation in round {
                append_serialized(&mut encoded, evaluation)?;
            }
        }
        for evaluation in &self.terminal_evaluations {
            append_serialized(&mut encoded, evaluation)?;
        }
        encoded.extend_from_slice(&self.transcript_digest);
        encoded.extend_from_slice(&self.opening_proof);
        if encoded.len() != expected || encoded.len() > MAX_TRANSITION_PROOF_BYTES {
            return Err(BlsDoryTransitionError::ProofTooLarge);
        }
        Ok(encoded)
    }

    /// Decode only the exact bounded shape implied by the trusted statement.
    pub fn decode(
        encoded: &[u8],
        statement: StructuredTransitionStatement,
    ) -> Result<Self, BlsDoryTransitionError> {
        let expected_variables = minimum_packed_variables(statement)?;
        Self::decode_with_variables(encoded, statement, expected_variables)
    }

    /// Decode using the exact shared aggregate geometry selected by consensus.
    pub fn decode_with_variables(
        encoded: &[u8],
        statement: StructuredTransitionStatement,
        expected_variables: usize,
    ) -> Result<Self, BlsDoryTransitionError> {
        Self::decode_with_variables_and_opening(encoded, statement, expected_variables, true)
    }

    pub(crate) fn decode_deferred_with_variables(
        encoded: &[u8],
        statement: StructuredTransitionStatement,
        expected_variables: usize,
    ) -> Result<Self, BlsDoryTransitionError> {
        Self::decode_with_variables_and_opening(encoded, statement, expected_variables, false)
    }

    fn decode_with_variables_and_opening(
        encoded: &[u8],
        statement: StructuredTransitionStatement,
        expected_variables: usize,
        require_opening: bool,
    ) -> Result<Self, BlsDoryTransitionError> {
        statement.validate_verifier_shape()?;
        validate_target_variables(minimum_packed_variables(statement)?, expected_variables)?;
        if encoded.len() < PROOF_HEADER_BYTES || encoded.len() > MAX_TRANSITION_PROOF_BYTES {
            return Err(BlsDoryTransitionError::ProofTooLarge);
        }
        if encoded[..8] != PROOF_MAGIC {
            return Err(BlsDoryTransitionError::InvalidEncoding);
        }
        let protocol_version = read_u16(encoded, 8)?;
        let packed_variables = read_u16(encoded, 10)?;
        let round_count = read_u16(encoded, 12)? as usize;
        let terminal_count = read_u16(encoded, 14)? as usize;
        let opening_len = read_u32(encoded, 16)? as usize;
        let expected_rounds = statement.elements()?.ilog2() as usize;
        if protocol_version != BLS_DORY_TRANSITION_VERSION
            || usize::from(packed_variables) != expected_variables
            || round_count != expected_rounds
            || terminal_count != BLS_DORY_TRANSITION_OPENING_CLAIMS
            || (require_opening && opening_len == 0)
            || (!require_opening && opening_len != 0)
            || opening_len > MAX_BLS_DORY_AGGREGATE_BYTES
            || encoded.len() != transition_wire_bytes(round_count, opening_len)?
        {
            return Err(BlsDoryTransitionError::InvalidProofShape);
        }

        let mut reader = Cursor::new(&encoded[PROOF_HEADER_BYTES..]);
        let oracle_commitment = read_serialized(&mut reader)?;
        let mut rounds = Vec::with_capacity(round_count);
        for _ in 0..round_count {
            let mut round = Vec::with_capacity(BLS_DORY_TRANSITION_SUMCHECK_DEGREE + 1);
            for _ in 0..=BLS_DORY_TRANSITION_SUMCHECK_DEGREE {
                round.push(read_serialized(&mut reader)?);
            }
            rounds.push(round);
        }
        let mut terminal_evaluations = Vec::with_capacity(terminal_count);
        for _ in 0..terminal_count {
            terminal_evaluations.push(read_serialized(&mut reader)?);
        }
        let payload_offset = PROOF_HEADER_BYTES + reader.position() as usize;
        let digest_end = payload_offset
            .checked_add(32)
            .ok_or(BlsDoryTransitionError::InvalidProofShape)?;
        let transcript_digest = encoded
            .get(payload_offset..digest_end)
            .ok_or(BlsDoryTransitionError::InvalidProofShape)?
            .try_into()
            .map_err(|_| BlsDoryTransitionError::InvalidProofShape)?;
        let opening_proof = encoded
            .get(digest_end..)
            .ok_or(BlsDoryTransitionError::InvalidProofShape)?
            .to_vec();
        if opening_proof.len() != opening_len {
            return Err(BlsDoryTransitionError::InvalidProofShape);
        }
        let proof = Self {
            protocol_version,
            packed_variables,
            oracle_commitment,
            rounds,
            terminal_evaluations,
            transcript_digest,
            opening_proof,
        };
        if proof.encode_with_opening(statement, require_opening)? != encoded {
            return Err(BlsDoryTransitionError::InvalidEncoding);
        }
        Ok(proof)
    }
}

/// Errors from the scalar transition checkpoint.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDoryTransitionError {
    #[error("structured transition input is invalid: {0}")]
    Structured(#[from] StructuredTransitionError),
    #[error("Dory opening authentication failed: {0}")]
    Aggregate(#[from] BlsDoryAggregateError),
    #[error("packed transition dimensions overflow or exceed this checkpoint")]
    InvalidDimensions,
    #[error("scalar transition proof has the wrong fixed shape")]
    InvalidProofShape,
    #[error("transition round does not preserve the current claim")]
    RoundClaim,
    #[error("transition terminal relation is invalid")]
    TerminalClaim,
    #[error("transition mask opening does not equal the challenge-derived polynomial")]
    MaskPolynomial,
    #[error("transition transcript digest mismatch")]
    Transcript,
    #[error("Dory claims do not match the transition terminal evaluations")]
    Opening,
    #[error("transition public binding exceeds the bounded transcript limit")]
    PublicBindingTooLarge,
    #[error("transition proof exceeds the network payload cap")]
    ProofTooLarge,
    #[error("transition proof encoding is malformed or non-canonical")]
    InvalidEncoding,
    #[error("authenticated execution-accumulator artifact failed")]
    ExecutionArtifact,
    #[error("the BLS12-381 transition checkpoint is not production ready")]
    NotProductionReady,
}

/// Fail closed while any production blocker remains.
pub fn require_bls_dory_transition_production_ready() -> Result<(), BlsDoryTransitionError> {
    Err(BlsDoryTransitionError::NotProductionReady)
}

/// Project only the canonical Dory opening payload for a transition bank.
pub fn projected_production_transition_opening_bytes() -> Result<usize, BlsDoryTransitionError> {
    projected_bls_dory_aggregate_bytes(PRODUCTION_BLS_DORY_TRANSITION_VARIABLES)
        .map_err(BlsDoryTransitionError::Aggregate)
}

/// Project the complete canonical transition proof at production geometry.
pub fn projected_production_transition_proof_bytes() -> Result<usize, BlsDoryTransitionError> {
    let opening = projected_production_transition_opening_bytes()?;
    transition_wire_bytes(26, opening)
}

/// Exact retained coefficient bytes for the production transition source.
pub fn projected_production_transition_source_artifact_bytes() -> Result<u64, BlsDoryTransitionError>
{
    let cells = 1u64
        .checked_shl(
            u32::try_from(
                PRODUCTION_BLS_DORY_TRANSITION_VARIABLES - BLS_DORY_TRANSITION_SELECTOR_VARIABLES,
            )
            .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
        )
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let scalar_count = 1u64
        .checked_shl(
            u32::try_from(PRODUCTION_BLS_DORY_TRANSITION_VARIABLES)
                .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
        )
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let explicit_scalar_count = cells
        .checked_mul(STRUCTURED_TRANSITION_ORACLES as u64)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let literal_scalar_count = cells
        .checked_mul(STRUCTURED_TRANSITION_REGULAR_ORACLES as u64)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    BlsDoryCompactArtifactSpec {
        context_digest: [1; 32],
        scalar_count,
        explicit_scalar_count,
        word_scalar_count: literal_scalar_count,
        word_bytes: 4,
        code_bits: 4,
        word_width_codes: PRODUCTION_TRANSITION_WORD_WIDTH_CODES,
        word_group_len: cells,
        signed_word_selectors: TRANSITION_SIGNED_WORD_SELECTORS,
    }
    .encoded_bytes(16)
    .map_err(|_| BlsDoryTransitionError::InvalidDimensions)
}

/// Prove the seven regular transition constraints and authenticate twelve terminals.
pub fn prove_bls_dory_transition(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryTransitionProof, BlsDoryTransitionError> {
    let packed_variables = minimum_packed_variables(statement)?;
    prove_bls_dory_transition_at_variables(
        binding,
        statement,
        mask_polynomial,
        witness,
        packed_variables,
        setup,
    )
}

/// Prove regular transition arithmetic at an exact shared aggregate geometry.
pub fn prove_bls_dory_transition_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryTransitionProof, BlsDoryTransitionError> {
    let mut prepared = prove_bls_dory_transition_deferred_at_variables(
        binding,
        statement,
        mask_polynomial,
        witness,
        packed_variables,
        setup,
    )?;
    let opening_binding = opening_binding(binding, &prepared.proof.transcript_digest);
    let aggregate_layout = BlsDoryAggregateLayout::new(
        packed_variables / 2,
        packed_variables - packed_variables / 2,
    )?;
    let (claims, opening_proof) = prove_bls_dory_deferred_opening_sets(
        &opening_binding,
        aggregate_layout,
        &[&prepared.openings],
        setup,
    )?;
    if claims != prepared.openings.claims() {
        return Err(BlsDoryTransitionError::Opening);
    }
    prepared.proof.opening_proof = opening_proof;
    verify_bls_dory_transition_at_variables(
        binding,
        statement,
        mask_polynomial,
        &prepared.proof,
        packed_variables,
        setup,
    )?;
    Ok(prepared.proof)
}

pub(crate) fn prove_bls_dory_transition_deferred_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDoryTransitionProof, BlsDoryTransitionError> {
    prove_bls_dory_transition_deferred_at_variables_with_optional_scratch(
        binding,
        statement,
        mask_polynomial,
        witness,
        packed_variables,
        setup,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_transition_deferred_at_variables_with_scratch(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryTransitionProof, BlsDoryTransitionError> {
    let packed_nu = packed_variables / 2;
    let packed_sigma = packed_variables - packed_nu;
    let packed_rows = 1usize
        .checked_shl(packed_nu as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let packed_columns = 1usize
        .checked_shl(packed_sigma as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let source =
        BlsDoryTransitionWitnessRowSource::new(statement, witness, packed_rows, packed_columns)?;
    prove_bls_dory_transition_deferred_from_row_source_with_scratch(
        binding,
        statement,
        mask_polynomial,
        source,
        packed_variables,
        setup,
        scratch_directory,
    )
}

#[cfg(any(test, feature = "whir-prototype"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_transition_deferred_from_execution_artifact_with_scratch(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    artifact: &mut BlsDoryExecutionAccumulatorArtifact,
    expected_context: BlsDoryExecutionAccumulatorArtifactContext,
    transition: BlsDoryExecutionAccumulatorTransition,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryTransitionProof, BlsDoryTransitionError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    if expected_context.setup_identity() != setup.identity() {
        return Err(BlsDoryTransitionError::ExecutionArtifact);
    }
    if binding.len() > MAX_TRANSITION_BINDING_BYTES {
        return Err(BlsDoryTransitionError::PublicBindingTooLarge);
    }
    mask_polynomial.validate(statement)?;
    let cell_variables = statement.elements()?.ilog2() as usize;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    let packed_nu = packed_variables / 2;
    let packed_sigma = packed_variables - packed_nu;
    let packed_rows = 1usize
        .checked_shl(packed_nu as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let packed_columns = 1usize
        .checked_shl(packed_sigma as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let mut source = BlsDoryTransitionWitnessRowSource::new_from_execution_artifact(
        statement,
        mask_polynomial,
        artifact,
        expected_context,
        transition,
        packed_rows,
        packed_columns,
    )?;
    let grouped = build_grouped_transition_compact_artifact_with_scratch(
        &mut source,
        packed_nu,
        packed_sigma,
        setup,
        scratch_directory,
    )?;
    if grouped.derived_cells != statement.elements()? {
        return Err(transition_storage_error());
    }
    let committed = commit_bls_dory_existing_compact_artifact(
        grouped.artifact,
        packed_nu,
        packed_sigma,
        setup,
    )?;
    prove_bls_dory_transition_deferred_from_committed_row_source_with_scratch(
        binding,
        statement,
        mask_polynomial,
        source,
        packed_variables,
        cell_variables,
        committed,
        setup,
        scratch_directory,
    )
}

#[cfg(any(test, feature = "whir-prototype"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn regenerate_bls_dory_transition_compact_source_from_execution_artifact_with_scratch(
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    artifact: &mut BlsDoryExecutionAccumulatorArtifact,
    expected_context: BlsDoryExecutionAccumulatorArtifactContext,
    transition: BlsDoryExecutionAccumulatorTransition,
    packed_variables: usize,
    expected: &BlsDoryReleasedCompactSource,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<Arc<BlsDoryCompactArtifact>, BlsDoryTransitionError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    if expected_context.setup_identity() != setup.identity() {
        return Err(BlsDoryTransitionError::ExecutionArtifact);
    }
    mask_polynomial.validate(statement)?;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    let packed_nu = packed_variables / 2;
    let packed_sigma = packed_variables - packed_nu;
    let packed_rows = 1usize
        .checked_shl(packed_nu as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let packed_columns = 1usize
        .checked_shl(packed_sigma as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let mut source = BlsDoryTransitionWitnessRowSource::new_from_execution_artifact(
        statement,
        mask_polynomial,
        artifact,
        expected_context,
        transition,
        packed_rows,
        packed_columns,
    )?;
    let grouped = build_grouped_transition_compact_artifact_with_scratch(
        &mut source,
        packed_nu,
        packed_sigma,
        setup,
        scratch_directory,
    )?;
    if grouped.derived_cells != statement.elements()? {
        return Err(transition_storage_error());
    }
    drop(source);
    expected.validate_artifact(grouped.artifact.as_ref())?;
    Ok(grouped.artifact)
}

#[cfg(feature = "whir-prototype")]
struct DoryV3ExecutionTransitionDescriptor {
    statement: StructuredTransitionStatement,
    mask_polynomial: StructuredMaskPolynomial,
    transition: BlsDoryExecutionAccumulatorTransition,
}

#[cfg(feature = "whir-prototype")]
fn dory_v3_execution_transition_descriptor(
    reader: &BlsDoryV3ExecutionArtifactReader<'_>,
    transition_index: usize,
) -> Result<DoryV3ExecutionTransitionDescriptor, BlsDoryTransitionError> {
    let rows = reader.canonical_rows();
    let cols = reader.canonical_columns();
    rows.checked_mul(cols)
        .filter(|cells| *cells == reader.cells_per_column())
        .ok_or(BlsDoryTransitionError::ExecutionArtifact)?;
    let (statement, mask_polynomial, transition) = if transition_index == 0 {
        (
            StructuredTransitionStatement {
                layers: 1,
                rows,
                cols,
                max_abs_accumulator: 125,
                max_mask: 5_000,
            },
            reader
                .v3_initialization_mask()
                .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?,
            BlsDoryExecutionAccumulatorTransition::Initialization,
        )
    } else {
        let bank = transition_index
            .checked_sub(1)
            .filter(|bank| *bank < reader.banks())
            .ok_or(BlsDoryTransitionError::ExecutionArtifact)?;
        (
            StructuredTransitionStatement {
                layers: reader.layers_per_bank(),
                rows,
                cols,
                max_abs_accumulator: u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS),
                max_mask: 5_000,
            },
            reader
                .v3_bank_mask(bank)
                .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?,
            BlsDoryExecutionAccumulatorTransition::Bank(bank),
        )
    };
    statement.validate_verifier_shape()?;
    mask_polynomial.validate(statement)?;
    Ok(DoryV3ExecutionTransitionDescriptor {
        statement,
        mask_polynomial,
        transition,
    })
}

#[cfg(feature = "whir-prototype")]
fn preflight_dory_v3_transition_dimensions(
    statement: StructuredTransitionStatement,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(usize, usize, usize, usize), BlsDoryTransitionError> {
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    let packed_nu = packed_variables / 2;
    let packed_sigma = packed_variables - packed_nu;
    let packed_rows = 1usize
        .checked_shl(packed_nu as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let packed_columns = 1usize
        .checked_shl(packed_sigma as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    Ok((packed_nu, packed_sigma, packed_rows, packed_columns))
}

/// Prove one V3 transition directly from the authority-checked execution reader.
///
/// Index zero selects initialization and indices `1..=banks` select the exact
/// authenticated bank. Statements, V3 masks, and artifact roles are derived
/// internally; no raw context, artifact, challenge, or caller mask enters.
#[cfg(feature = "whir-prototype")]
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_v3_transition_deferred_from_execution_reader_with_scratch(
    binding: &[u8],
    reader: &mut BlsDoryV3ExecutionArtifactReader<'_>,
    transition_index: usize,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryTransitionProof, BlsDoryTransitionError> {
    reader
        .validate_setup(setup)
        .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
    if binding.len() > MAX_TRANSITION_BINDING_BYTES {
        return Err(BlsDoryTransitionError::PublicBindingTooLarge);
    }
    let descriptor = dory_v3_execution_transition_descriptor(reader, transition_index)?;
    let (packed_nu, packed_sigma, packed_rows, packed_columns) =
        preflight_dory_v3_transition_dimensions(descriptor.statement, packed_variables, setup)?;
    let cell_variables = descriptor.statement.elements()?.ilog2() as usize;
    let mask_polynomial = descriptor.mask_polynomial.clone();
    let mut source = BlsDoryTransitionWitnessRowSource::new_from_dory_v3_execution_reader(
        descriptor,
        reader,
        packed_rows,
        packed_columns,
    )?;
    let grouped = build_grouped_transition_compact_artifact_with_scratch(
        &mut source,
        packed_nu,
        packed_sigma,
        setup,
        scratch_directory,
    )?;
    if grouped.derived_cells != source.statement.elements()? {
        return Err(transition_storage_error());
    }
    let statement = source.statement;
    let committed = commit_bls_dory_existing_compact_artifact(
        grouped.artifact,
        packed_nu,
        packed_sigma,
        setup,
    )?;
    prove_bls_dory_transition_deferred_from_committed_row_source_with_scratch(
        binding,
        statement,
        &mask_polynomial,
        source,
        packed_variables,
        cell_variables,
        committed,
        setup,
        scratch_directory,
    )
}

/// Rebuild a released V3 transition source from the same opaque execution
/// capability. The expected source is authenticated only after the reader has
/// been dropped, preserving the compact-artifact lifecycle.
#[cfg(feature = "whir-prototype")]
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn regenerate_bls_dory_v3_transition_compact_source_from_execution_reader_with_scratch(
    reader: &mut BlsDoryV3ExecutionArtifactReader<'_>,
    transition_index: usize,
    packed_variables: usize,
    expected: &BlsDoryReleasedCompactSource,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<Arc<BlsDoryCompactArtifact>, BlsDoryTransitionError> {
    reader
        .validate_setup(setup)
        .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
    let descriptor = dory_v3_execution_transition_descriptor(reader, transition_index)?;
    let (packed_nu, packed_sigma, packed_rows, packed_columns) =
        preflight_dory_v3_transition_dimensions(descriptor.statement, packed_variables, setup)?;
    let mut source = BlsDoryTransitionWitnessRowSource::new_from_dory_v3_execution_reader(
        descriptor,
        reader,
        packed_rows,
        packed_columns,
    )?;
    let grouped = build_grouped_transition_compact_artifact_with_scratch(
        &mut source,
        packed_nu,
        packed_sigma,
        setup,
        scratch_directory,
    )?;
    if grouped.derived_cells != source.statement.elements()? {
        return Err(transition_storage_error());
    }
    drop(source);
    expected.validate_artifact(grouped.artifact.as_ref())?;
    Ok(grouped.artifact)
}

/// Bounded small-table LogUp path for a V3 transition reader.
///
/// Production-sized transitions use their already committed compact source.
/// This entry exists only for tables below the compact LogUp threshold and
/// never crosses through the legacy V2 artifact row-source constructor.
#[cfg(feature = "whir-prototype")]
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_v3_small_range_logup_from_execution_reader_with_scratch(
    binding: &[u8],
    reader: &mut BlsDoryV3ExecutionArtifactReader<'_>,
    transition_index: usize,
    transition: &BlsDoryCommittedPolynomial,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    reader
        .validate_setup(setup)
        .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
    if binding.len() > MAX_TRANSITION_BINDING_BYTES {
        return Err(BlsDoryRangeLogUpError::PublicBindingTooLarge);
    }
    let descriptor = dory_v3_execution_transition_descriptor(reader, transition_index)?;
    let (_, _, packed_rows, packed_columns) =
        preflight_dory_v3_transition_dimensions(descriptor.statement, packed_variables, setup)?;
    let elements = descriptor.statement.elements()?;
    if elements >= BLS_DORY_RANGE_LOGUP_TABLE_VALUES {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let aggregate_layout = BlsDoryAggregateLayout::new(
        packed_variables / 2,
        packed_variables - packed_variables / 2,
    )?;
    let explicit_scalars = elements
        .checked_mul(STRUCTURED_TRANSITION_ORACLES)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    if !transition.matches_layout(aggregate_layout, setup)
        || transition.explicit_coefficient_count() != explicit_scalars
    {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let statement = descriptor.statement;
    let source = BlsDoryTransitionWitnessRowSource::new_from_dory_v3_execution_reader(
        descriptor,
        reader,
        packed_rows,
        packed_columns,
    )?;
    prove_bls_dory_range_logup_deferred_with_precommitted_row_source_and_scratch(
        binding,
        statement,
        &source,
        transition,
        packed_variables,
        setup,
        scratch_directory,
    )
}

#[cfg(any(test, feature = "whir-prototype"))]
struct BuiltGroupedTransitionArtifact {
    artifact: Arc<BlsDoryCompactArtifact>,
    derived_cells: usize,
}

#[cfg(any(test, feature = "whir-prototype"))]
fn build_grouped_transition_compact_artifact_with_scratch(
    source: &mut BlsDoryTransitionWitnessRowSource<'_>,
    packed_nu: usize,
    packed_sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BuiltGroupedTransitionArtifact, BlsDoryTransitionError> {
    build_grouped_transition_compact_artifact_with_chunk_cells(
        source,
        packed_nu,
        packed_sigma,
        setup,
        scratch_directory,
        TRANSITION_GROUPED_COMPACT_CHUNK_CELLS,
    )
}

#[cfg(any(test, feature = "whir-prototype"))]
fn build_grouped_transition_compact_artifact_with_chunk_cells(
    source: &mut BlsDoryTransitionWitnessRowSource<'_>,
    packed_nu: usize,
    packed_sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
    maximum_chunk_cells: usize,
) -> Result<BuiltGroupedTransitionArtifact, BlsDoryTransitionError> {
    let packed_rows = 1usize
        .checked_shl(packed_nu as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let packed_columns = 1usize
        .checked_shl(packed_sigma as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let coefficient_count = packed_rows
        .checked_mul(packed_columns)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let elements = source.elements;
    let regular_scalar_count = elements
        .checked_mul(STRUCTURED_TRANSITION_REGULAR_ORACLES)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let word_scalar_count = source.literal_scalar_count();
    let explicit_scalar_count = elements
        .checked_mul(STRUCTURED_TRANSITION_ORACLES)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let word_selectors = word_scalar_count
        .checked_div(elements)
        .filter(|selectors| selectors.checked_mul(elements) == Some(word_scalar_count))
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let word_range_selectors = word_selectors
        .checked_sub(STRUCTURED_TRANSITION_REGULAR_ORACLES)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let code_selectors = STRUCTURED_TRANSITION_ORACLES
        .checked_sub(word_selectors)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    if source.rows != packed_rows
        || source.columns != packed_columns
        || source.explicit_scalars != explicit_scalar_count
        || word_scalar_count < regular_scalar_count
        || source.range_oracles.len()
            != STRUCTURED_TRANSITION_ORACLES - STRUCTURED_TRANSITION_REGULAR_ORACLES
        || word_range_selectors > source.range_oracles.len()
        || source.range_dictionary.len() != 16
        || explicit_scalar_count > coefficient_count
        || !source.is_execution_artifact_backed()
    {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }

    let source_spec = source_artifact_spec(
        setup.identity(),
        packed_nu,
        packed_sigma,
        coefficient_count,
        explicit_scalar_count,
    )?;
    let compact_spec = BlsDoryCompactArtifactSpec {
        context_digest: source_spec.context_digest,
        scalar_count: source_spec.scalar_count,
        explicit_scalar_count: source_spec.explicit_scalar_count,
        word_scalar_count: u64::try_from(word_scalar_count)
            .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
        word_bytes: 4,
        code_bits: 4,
        word_width_codes: transition_word_width_codes(source.statement.max_mask),
        word_group_len: u64::try_from(elements)
            .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
        signed_word_selectors: TRANSITION_SIGNED_WORD_SELECTORS,
    };
    let mut writer = BlsDoryGroupedCompactArtifactWriter::create(
        scratch_directory,
        compact_spec,
        source.range_dictionary.clone(),
    )
    .map_err(|_| transition_storage_error())?;
    let chunk_cells = maximum_chunk_cells.min(elements);
    if chunk_cells == 0 {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    let maximum_word_scalars = chunk_cells
        .checked_mul(word_selectors)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let maximum_codes = chunk_cells
        .checked_mul(code_selectors)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let mut selector_words = Vec::new();
    selector_words
        .try_reserve_exact(maximum_word_scalars)
        .map_err(|_| transition_storage_error())?;
    let mut selector_codes = Vec::new();
    selector_codes
        .try_reserve_exact(maximum_codes)
        .map_err(|_| transition_storage_error())?;
    let range_oracles = source.range_oracles.clone();
    let mut derived_cells = 0usize;
    for cell_start in (0..elements).step_by(chunk_cells) {
        let cell_count = (elements - cell_start).min(chunk_cells);
        selector_words.resize(
            cell_count
                .checked_mul(word_selectors)
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?,
            0,
        );
        selector_codes.resize(
            cell_count
                .checked_mul(code_selectors)
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?,
            0,
        );
        for local_cell in 0..cell_count {
            let index = cell_start
                .checked_add(local_cell)
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
            let derived = source.execution_derived_regular_row(index)?;
            let mut regular_words = [0u64; STRUCTURED_TRANSITION_REGULAR_ORACLES];
            for (oracle, word) in regular_words.iter_mut().enumerate() {
                *word = derived.word(oracle)?;
                selector_words[oracle * cell_count + local_cell] = *word;
            }
            for (selector, descriptor) in range_oracles.iter().copied().enumerate() {
                let value = *regular_words
                    .get(descriptor.source_oracle)
                    .ok_or(BlsDoryTransitionError::InvalidProofShape)?;
                let bounded = if descriptor.slack {
                    descriptor
                        .maximum
                        .checked_sub(value)
                        .ok_or(BlsDoryTransitionError::InvalidDimensions)?
                } else {
                    value
                };
                let digit = u8::try_from((bounded >> (descriptor.digit * 4)) & 0xf)
                    .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?;
                if selector < word_range_selectors {
                    selector_words[(STRUCTURED_TRANSITION_REGULAR_ORACLES + selector)
                        * cell_count
                        + local_cell] = u64::from(digit);
                } else {
                    selector_codes[(selector - word_range_selectors) * cell_count + local_cell] =
                        digit;
                }
            }
            derived_cells = derived_cells
                .checked_add(1)
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        }
        writer
            .write_cell_chunk(
                u64::try_from(cell_start).map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
                cell_count,
                &selector_words,
                &selector_codes,
            )
            .map_err(|_| transition_storage_error())?;
    }
    if derived_cells != elements {
        return Err(transition_storage_error());
    }
    let artifact = writer.finish().map_err(|_| transition_storage_error())?;
    if artifact.spec() != compact_spec {
        return Err(transition_storage_error());
    }
    Ok(BuiltGroupedTransitionArtifact {
        artifact: Arc::new(artifact),
        derived_cells,
    })
}

#[allow(clippy::too_many_arguments)]
fn prove_bls_dory_transition_deferred_from_row_source_with_scratch(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    mut source: BlsDoryTransitionWitnessRowSource<'_>,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryTransitionProof, BlsDoryTransitionError> {
    if binding.len() > MAX_TRANSITION_BINDING_BYTES {
        return Err(BlsDoryTransitionError::PublicBindingTooLarge);
    }
    mask_polynomial.validate(statement)?;
    let cell_variables = statement.elements()?.ilog2() as usize;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    let packed_nu = packed_variables / 2;
    let packed_sigma = packed_variables - packed_nu;
    let committed = commit_bls_dory_compact_row_source_with_scratch(
        &mut source,
        packed_nu,
        packed_sigma,
        setup,
        scratch_directory,
    )?;
    prove_bls_dory_transition_deferred_from_committed_row_source_with_scratch(
        binding,
        statement,
        mask_polynomial,
        source,
        packed_variables,
        cell_variables,
        committed,
        setup,
        scratch_directory,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_bls_dory_transition_deferred_from_committed_row_source_with_scratch(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    source: BlsDoryTransitionWitnessRowSource<'_>,
    packed_variables: usize,
    cell_variables: usize,
    committed: BlsDoryCommittedPolynomial,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryTransitionProof, BlsDoryTransitionError> {
    let oracle_commitment = committed.commitment();

    let mut transcript = transition_transcript(
        binding,
        statement,
        mask_polynomial.digest(),
        &oracle_commitment,
    );
    let mixing = transcript.challenge_scalar(b"constraint-mixing");
    let mixing_powers = powers(mixing, BLS_DORY_TRANSITION_ARITHMETIC_CONSTRAINTS);
    let cell_point = challenge_vector(&mut transcript, b"cell-point", cell_variables);
    let output = prove_transition_sumcheck_with_scratch(
        statement,
        &source,
        &cell_point,
        &mixing_powers,
        &mut transcript,
        scratch_directory,
    )?;
    let terminal_evaluations = output.terminal_evaluations;
    if terminal_evaluations[MASK] != evaluate_mask(mask_polynomial, statement, &output.point)? {
        return Err(BlsDoryTransitionError::MaskPolynomial);
    }
    let expected = output.selector_terminal
        * arithmetic_constraint(statement, &terminal_evaluations, &mixing_powers)?;
    if output.final_claim != expected {
        return Err(BlsDoryTransitionError::TerminalClaim);
    }
    absorb_fields(
        &mut transcript,
        b"terminal-evaluation",
        &terminal_evaluations,
    );
    let transcript_digest = transcript.digest();
    let opening_points = packed_opening_points(&output.point, packed_variables)?;
    let expected_claims = transition_opening_claims(
        oracle_commitment,
        &output.point,
        &terminal_evaluations,
        packed_variables,
    )?;
    let openings = BlsDoryDeferredOpeningSet::new(
        vec![committed],
        vec![0; opening_points.len()],
        opening_points,
    )?;
    if openings.claims() != expected_claims {
        return Err(BlsDoryTransitionError::Opening);
    }
    let proof = BlsDoryTransitionProof {
        protocol_version: BLS_DORY_TRANSITION_VERSION,
        packed_variables: u16::try_from(packed_variables)
            .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
        oracle_commitment,
        rounds: output.rounds,
        terminal_evaluations,
        transcript_digest,
        opening_proof: Vec::new(),
    };
    verify_bls_dory_transition_deferred_at_variables(
        binding,
        statement,
        mask_polynomial,
        &proof,
        packed_variables,
        setup,
    )?;
    Ok(PreparedBlsDoryTransitionProof { proof, openings })
}

#[allow(clippy::too_many_arguments)]
fn prove_bls_dory_transition_deferred_at_variables_with_optional_scratch(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<PreparedBlsDoryTransitionProof, BlsDoryTransitionError> {
    if binding.len() > MAX_TRANSITION_BINDING_BYTES {
        return Err(BlsDoryTransitionError::PublicBindingTooLarge);
    }
    mask_polynomial.validate(statement)?;
    let mut oracles = if scratch_directory.is_none() {
        Some(build_scalar_oracles(statement, witness)?)
    } else {
        None
    };
    let cell_variables = statement.elements()?.ilog2() as usize;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    let packed_nu = packed_variables / 2;
    let packed_sigma = packed_variables - packed_nu;
    let packed_rows = 1usize
        .checked_shl(packed_nu as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let packed_columns = 1usize
        .checked_shl(packed_sigma as u32)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let mut witness_source = if scratch_directory.is_some() {
        Some(BlsDoryTransitionWitnessRowSource::new(
            statement,
            witness,
            packed_rows,
            packed_columns,
        )?)
    } else {
        None
    };
    let committed = if let Some(scratch_directory) = scratch_directory {
        commit_bls_dory_compact_row_source_with_scratch(
            witness_source
                .as_mut()
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?,
            packed_nu,
            packed_sigma,
            setup,
            scratch_directory,
        )?
    } else {
        let packed_coefficients = pack_oracles(
            oracles
                .as_ref()
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?,
        )?;
        commit_bls_dory_padded_prefix_with_optional_scratch(
            &packed_coefficients,
            packed_nu,
            packed_sigma,
            setup,
            None,
        )?
    };
    let oracle_commitment = committed.commitment();

    let mut transcript = transition_transcript(
        binding,
        statement,
        mask_polynomial.digest(),
        &oracle_commitment,
    );
    let mixing = transcript.challenge_scalar(b"constraint-mixing");
    let mixing_powers = powers(mixing, BLS_DORY_TRANSITION_ARITHMETIC_CONSTRAINTS);
    let cell_point = challenge_vector(&mut transcript, b"cell-point", cell_variables);
    let (rounds, sumcheck_point, terminal_evaluations, selector_terminal, claim) =
        if let Some(scratch_directory) = scratch_directory {
            let output = prove_transition_sumcheck_with_scratch(
                statement,
                witness_source
                    .as_ref()
                    .ok_or(BlsDoryTransitionError::InvalidDimensions)?,
                &cell_point,
                &mixing_powers,
                &mut transcript,
                scratch_directory,
            )?;
            (
                output.rounds,
                output.point,
                output.terminal_evaluations,
                output.selector_terminal,
                output.final_claim,
            )
        } else {
            let oracles = oracles
                .as_mut()
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
            oracles.truncate(STRUCTURED_TRANSITION_REGULAR_ORACLES);
            let mut selector = equality_table(&cell_point);
            let mut claim = BlsDoryFr::zero();
            let mut rounds = Vec::with_capacity(cell_variables);
            let mut sumcheck_point = Vec::with_capacity(cell_variables);
            for round_index in 0..cell_variables {
                let evaluations = transition_round(statement, &selector, oracles, &mixing_powers)?;
                if evaluations[0] + evaluations[1] != claim {
                    return Err(BlsDoryTransitionError::RoundClaim);
                }
                absorb_round(&mut transcript, round_index, &evaluations);
                let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
                claim = evaluate_samples(&evaluations, challenge)?;
                sumcheck_point.push(challenge);
                selector = fold_table(&selector, challenge);
                for oracle in oracles.iter_mut() {
                    *oracle = fold_table(oracle, challenge);
                }
                rounds.push(evaluations);
            }
            (
                rounds,
                sumcheck_point,
                oracles.iter().map(|oracle| oracle[0]).collect::<Vec<_>>(),
                selector[0],
                claim,
            )
        };
    if terminal_evaluations[MASK] != evaluate_mask(mask_polynomial, statement, &sumcheck_point)? {
        return Err(BlsDoryTransitionError::MaskPolynomial);
    }
    let expected = selector_terminal
        * arithmetic_constraint(statement, &terminal_evaluations, &mixing_powers)?;
    if claim != expected {
        return Err(BlsDoryTransitionError::TerminalClaim);
    }
    absorb_fields(
        &mut transcript,
        b"terminal-evaluation",
        &terminal_evaluations,
    );
    let transcript_digest = transcript.digest();

    let opening_points = packed_opening_points(&sumcheck_point, packed_variables)?;
    let expected_claims = transition_opening_claims(
        oracle_commitment,
        &sumcheck_point,
        &terminal_evaluations,
        packed_variables,
    )?;
    let openings = BlsDoryDeferredOpeningSet::new(
        vec![committed],
        vec![0; opening_points.len()],
        opening_points,
    )?;
    if openings.claims() != expected_claims {
        return Err(BlsDoryTransitionError::Opening);
    }

    let proof = BlsDoryTransitionProof {
        protocol_version: BLS_DORY_TRANSITION_VERSION,
        packed_variables: u16::try_from(packed_variables)
            .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
        oracle_commitment,
        rounds,
        terminal_evaluations,
        transcript_digest,
        opening_proof: Vec::new(),
    };
    verify_bls_dory_transition_deferred_at_variables(
        binding,
        statement,
        mask_polynomial,
        &proof,
        packed_variables,
        setup,
    )?;
    Ok(PreparedBlsDoryTransitionProof { proof, openings })
}

/// Verify regular transition arithmetic and its packed Dory openings without the witness.
pub fn verify_bls_dory_transition(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &BlsDoryTransitionProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryTransitionError> {
    let packed_variables = minimum_packed_variables(statement)?;
    verify_bls_dory_transition_at_variables(
        binding,
        statement,
        mask_polynomial,
        proof,
        packed_variables,
        setup,
    )
}

/// Verify regular transition arithmetic at the exact shared aggregate geometry.
pub fn verify_bls_dory_transition_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &BlsDoryTransitionProof,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryTransitionError> {
    let claims = verify_bls_dory_transition_deferred_at_variables(
        binding,
        statement,
        mask_polynomial,
        proof,
        packed_variables,
        setup,
    )?;
    let opening_binding = opening_binding(binding, &proof.transcript_digest);
    let aggregate_layout = BlsDoryAggregateLayout::new(
        packed_variables / 2,
        packed_variables - packed_variables / 2,
    )?;
    verify_bls_dory_openings(
        &opening_binding,
        aggregate_layout,
        &claims,
        &proof.opening_proof,
        setup,
    )?;
    Ok(())
}

pub(crate) fn verify_bls_dory_transition_deferred_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &BlsDoryTransitionProof,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<Vec<BlsDoryOpeningClaim>, BlsDoryTransitionError> {
    if binding.len() > MAX_TRANSITION_BINDING_BYTES {
        return Err(BlsDoryTransitionError::PublicBindingTooLarge);
    }
    statement.validate_verifier_shape()?;
    mask_polynomial.validate(statement)?;
    let cell_variables = statement.elements()?.ilog2() as usize;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    validate_deferred_proof_shape(statement, proof, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryTransitionError::InvalidProofShape);
    }

    let mut transcript = transition_transcript(
        binding,
        statement,
        mask_polynomial.digest(),
        &proof.oracle_commitment,
    );
    let mixing = transcript.challenge_scalar(b"constraint-mixing");
    let mixing_powers = powers(mixing, BLS_DORY_TRANSITION_ARITHMETIC_CONSTRAINTS);
    let cell_point = challenge_vector(&mut transcript, b"cell-point", cell_variables);
    let mut claim = BlsDoryFr::zero();
    let mut sumcheck_point = Vec::with_capacity(cell_variables);
    for (round_index, evaluations) in proof.rounds.iter().enumerate() {
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryTransitionError::RoundClaim);
        }
        absorb_round(&mut transcript, round_index, evaluations);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = evaluate_samples(evaluations, challenge)?;
        sumcheck_point.push(challenge);
    }
    if proof.terminal_evaluations[MASK]
        != evaluate_mask(mask_polynomial, statement, &sumcheck_point)?
    {
        return Err(BlsDoryTransitionError::MaskPolynomial);
    }
    let selector = equality_evaluation(&cell_point, &sumcheck_point);
    if claim
        != selector * arithmetic_constraint(statement, &proof.terminal_evaluations, &mixing_powers)?
    {
        return Err(BlsDoryTransitionError::TerminalClaim);
    }
    absorb_fields(
        &mut transcript,
        b"terminal-evaluation",
        &proof.terminal_evaluations,
    );
    if transcript.digest() != proof.transcript_digest {
        return Err(BlsDoryTransitionError::Transcript);
    }

    let claims = transition_opening_claims(
        proof.oracle_commitment,
        &sumcheck_point,
        &proof.terminal_evaluations,
        packed_variables,
    )?;
    Ok(claims)
}

fn validate_deferred_proof_shape(
    statement: StructuredTransitionStatement,
    proof: &BlsDoryTransitionProof,
    expected_variables: usize,
) -> Result<(), BlsDoryTransitionError> {
    validate_proof_shape_with_opening(statement, proof, expected_variables, false)
}

fn validate_proof_shape_with_opening(
    statement: StructuredTransitionStatement,
    proof: &BlsDoryTransitionProof,
    expected_variables: usize,
    require_opening: bool,
) -> Result<(), BlsDoryTransitionError> {
    statement.validate_verifier_shape()?;
    let cell_variables = statement.elements()?.ilog2() as usize;
    validate_target_variables(minimum_packed_variables(statement)?, expected_variables)?;
    if proof.protocol_version != BLS_DORY_TRANSITION_VERSION
        || usize::from(proof.packed_variables) != expected_variables
        || proof.rounds.len() != cell_variables
        || proof
            .rounds
            .iter()
            .any(|round| round.len() != BLS_DORY_TRANSITION_SUMCHECK_DEGREE + 1)
        || proof.terminal_evaluations.len() != BLS_DORY_TRANSITION_OPENING_CLAIMS
        || (require_opening && proof.opening_proof.is_empty())
        || proof.opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
    {
        return Err(BlsDoryTransitionError::InvalidProofShape);
    }
    Ok(())
}

fn minimum_packed_variables(
    statement: StructuredTransitionStatement,
) -> Result<usize, BlsDoryTransitionError> {
    statement.validate_verifier_shape()?;
    (statement.elements()?.ilog2() as usize)
        .checked_add(BLS_DORY_TRANSITION_SELECTOR_VARIABLES)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)
}

fn validate_target_variables(
    minimum_variables: usize,
    target_variables: usize,
) -> Result<(), BlsDoryTransitionError> {
    if target_variables < minimum_variables || target_variables > 64 {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    Ok(())
}

fn transition_wire_bytes(
    rounds: usize,
    opening_bytes: usize,
) -> Result<usize, BlsDoryTransitionError> {
    PROOF_HEADER_BYTES
        .checked_add(BlsDoryGt::identity().compressed_size())
        .and_then(|size| {
            size.checked_add(
                rounds
                    .checked_mul(BLS_DORY_TRANSITION_SUMCHECK_DEGREE + 1)?
                    .checked_mul(BlsDoryFr::zero().compressed_size())?,
            )
        })
        .and_then(|size| {
            size.checked_add(
                BLS_DORY_TRANSITION_OPENING_CLAIMS
                    .checked_mul(BlsDoryFr::zero().compressed_size())?,
            )
        })
        .and_then(|size| size.checked_add(32))
        .and_then(|size| size.checked_add(opening_bytes))
        .filter(|size| *size <= MAX_TRANSITION_PROOF_BYTES)
        .ok_or(BlsDoryTransitionError::ProofTooLarge)
}

fn append_serialized<T: DorySerialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDoryTransitionError> {
    value
        .serialize_compressed(output)
        .map_err(|_| BlsDoryTransitionError::InvalidEncoding)
}

fn read_serialized<T: DoryDeserialize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<T, BlsDoryTransitionError> {
    T::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryTransitionError::InvalidEncoding)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BlsDoryTransitionError> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(BlsDoryTransitionError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryTransitionError::InvalidProofShape)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BlsDoryTransitionError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(BlsDoryTransitionError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryTransitionError::InvalidProofShape)?;
    Ok(u32::from_le_bytes(value))
}

fn transition_transcript(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_digest: [u8; 32],
    commitment: &BlsDoryGt,
) -> BlsDoryTranscript {
    let mut transcript = BlsDoryTranscript::new(b"transition-sumcheck");
    transcript.append_bytes(
        b"protocol-version",
        &BLS_DORY_TRANSITION_VERSION.to_le_bytes(),
    );
    transcript.append_bytes(b"public-binding", binding);
    for value in [
        statement.layers as u64,
        statement.rows as u64,
        statement.cols as u64,
        statement.max_abs_accumulator,
        statement.max_mask,
    ] {
        transcript.append_bytes(b"statement-field", &value.to_le_bytes());
    }
    transcript.append_bytes(b"mask-polynomial", &mask_digest);
    transcript.append_group(b"packed-oracle-commitment", commitment);
    transcript
}

fn challenge_vector(
    transcript: &mut BlsDoryTranscript,
    label: &[u8],
    count: usize,
) -> Vec<BlsDoryFr> {
    (0..count)
        .map(|index| {
            transcript.append_bytes(b"point-index", &(index as u64).to_le_bytes());
            transcript.challenge_scalar(label)
        })
        .collect()
}

fn absorb_round(transcript: &mut BlsDoryTranscript, index: usize, values: &[BlsDoryFr]) {
    transcript.append_bytes(b"round-index", &(index as u64).to_le_bytes());
    transcript.append_bytes(b"round-count", &(values.len() as u64).to_le_bytes());
    for value in values {
        transcript.append_field(b"round-evaluation", value);
    }
}

fn absorb_fields(transcript: &mut BlsDoryTranscript, label: &[u8], values: &[BlsDoryFr]) {
    transcript.append_bytes(b"field-count", &(values.len() as u64).to_le_bytes());
    for value in values {
        transcript.append_field(label, value);
    }
}

fn opening_binding(binding: &[u8], transcript_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("CMFD/FORGEMATRIX/BLS-DORY-TRANSITION-OPENING-BINDING/V2");
    hasher.update(&(binding.len() as u64).to_le_bytes());
    hasher.update(binding);
    hasher.update(transcript_digest);
    *hasher.finalize().as_bytes()
}

pub(crate) fn build_scalar_oracles(
    statement: StructuredTransitionStatement,
    witness: &StructuredTransitionWitness,
) -> Result<Vec<Vec<BlsDoryFr>>, BlsDoryTransitionError> {
    validate_witness(statement, witness)?;
    let shifted_accumulators = witness
        .accumulators
        .iter()
        .map(|value| {
            u64::try_from(i128::from(*value) + i128::from(statement.max_abs_accumulator))
                .map_err(|_| BlsDoryTransitionError::InvalidDimensions)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut oracles = vec![
        signed_values(&witness.accumulators),
        unsigned_values(&witness.masks),
        unsigned_values(&witness.encoded),
        unsigned_values(&witness.square_quotients),
        unsigned_values(&witness.square_remainders),
        unsigned_values(&witness.cube_quotients),
        unsigned_values(&witness.cube_remainders),
        unsigned_values(&witness.output_quotients),
        unsigned_values(&witness.output_remainders),
        unsigned_values(&witness.negative),
        signed_values(&witness.activations),
        unsigned_values(&shifted_accumulators),
    ];
    for spec in structured_transition_range_specs(statement)? {
        let values = if spec.oracle == SHIFTED_ACCUMULATOR {
            shifted_accumulators.as_slice()
        } else {
            witness_unsigned_values(witness, spec.oracle)?
        };
        for digit in 0..spec.digits {
            oracles.push(unsigned_values(
                &values
                    .iter()
                    .map(|value| (value >> (digit * 4)) & 0xf)
                    .collect::<Vec<_>>(),
            ));
            oracles.push(unsigned_values(
                &values
                    .iter()
                    .map(|value| ((spec.maximum - value) >> (digit * 4)) & 0xf)
                    .collect::<Vec<_>>(),
            ));
        }
    }
    if oracles.len() != STRUCTURED_TRANSITION_ORACLES {
        return Err(BlsDoryTransitionError::InvalidProofShape);
    }
    Ok(oracles)
}

#[derive(Clone, Copy)]
struct RangeOracleDescriptor {
    source_oracle: usize,
    digit: usize,
    maximum: u64,
    slack: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DerivedTransitionRegularRow {
    pub(crate) accumulator: i64,
    pub(crate) mask: u64,
    pub(crate) encoded: u64,
    pub(crate) square_quotient: u64,
    pub(crate) square_remainder: u64,
    pub(crate) cube_quotient: u64,
    pub(crate) cube_remainder: u64,
    pub(crate) output_quotient: u64,
    pub(crate) output_remainder: u64,
    pub(crate) negative: u64,
    pub(crate) activation: i64,
    pub(crate) shifted_accumulator: u64,
}

impl DerivedTransitionRegularRow {
    pub(crate) fn word(self, oracle: usize) -> Result<u64, BlsDoryTransitionError> {
        Ok(match oracle {
            ACCUMULATOR => u64::from_le_bytes(self.accumulator.to_le_bytes()),
            MASK => self.mask,
            ENCODED => self.encoded,
            SQUARE_QUOTIENT => self.square_quotient,
            SQUARE_REMAINDER => self.square_remainder,
            CUBE_QUOTIENT => self.cube_quotient,
            CUBE_REMAINDER => self.cube_remainder,
            OUTPUT_QUOTIENT => self.output_quotient,
            OUTPUT_REMAINDER => self.output_remainder,
            NEGATIVE => self.negative,
            ACTIVATION => u64::from_le_bytes(self.activation.to_le_bytes()),
            SHIFTED_ACCUMULATOR => self.shifted_accumulator,
            _ => return Err(BlsDoryTransitionError::InvalidProofShape),
        })
    }
}

/// Derive the twelve canonical regular transition-oracle values for one cell.
///
/// `index` uses the transition table's canonical column-first, then row, then
/// layer order. The challenge-derived mask is authoritative; callers supply
/// only the signed accumulator retained by the execution trace.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn derive_transition_regular_row(
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    index: usize,
    accumulator: i64,
) -> Result<DerivedTransitionRegularRow, BlsDoryTransitionError> {
    let mask = mask_polynomial.value_at_boolean_index(statement, index)?;
    derive_transition_regular_row_from_mask(statement, index, accumulator, mask)
}

pub(crate) fn derive_transition_regular_row_from_mask(
    statement: StructuredTransitionStatement,
    index: usize,
    accumulator: i64,
    mask: u64,
) -> Result<DerivedTransitionRegularRow, BlsDoryTransitionError> {
    if index >= statement.elements()? {
        return Err(StructuredTransitionError::InvalidDimensions.into());
    }
    if accumulator.unsigned_abs() > statement.max_abs_accumulator {
        return Err(StructuredTransitionError::ValueOutOfRange.into());
    }

    if mask > statement.max_mask {
        return Err(StructuredTransitionError::ValueOutOfRange.into());
    }

    let arithmetic_overflow = || StructuredTransitionError::ArithmeticOverflow;
    let transition_modulus = u64::from(V2_TRANSITION_MODULUS);
    let signed_reduction = i128::from(accumulator)
        .checked_add(i128::from(mask))
        .ok_or_else(arithmetic_overflow)?;
    let negative = u64::from(signed_reduction < 0);
    let encoded = if signed_reduction < 0 {
        i128::from(transition_modulus)
            .checked_add(signed_reduction)
            .ok_or_else(arithmetic_overflow)?
    } else {
        signed_reduction
    };
    let encoded = u64::try_from(encoded).map_err(|_| arithmetic_overflow())?;
    if encoded >= transition_modulus {
        return Err(StructuredTransitionError::ValueOutOfRange.into());
    }

    let square = encoded
        .checked_mul(encoded)
        .ok_or_else(arithmetic_overflow)?;
    let square_quotient = square / transition_modulus;
    let square_remainder = square % transition_modulus;
    let cube = square_remainder
        .checked_mul(encoded)
        .ok_or_else(arithmetic_overflow)?;
    let cube_quotient = cube / transition_modulus;
    let cube_remainder = cube % transition_modulus;
    let output_quotient = cube_remainder / OUTPUT_MODULUS;
    let output_remainder = cube_remainder % OUTPUT_MODULUS;
    let activation = i64::try_from(output_remainder)
        .map_err(|_| arithmetic_overflow())?
        .checked_sub(i64::try_from(OUTPUT_CENTER).map_err(|_| arithmetic_overflow())?)
        .ok_or_else(arithmetic_overflow)?;
    let shifted_accumulator = i128::from(accumulator)
        .checked_add(i128::from(statement.max_abs_accumulator))
        .ok_or_else(arithmetic_overflow)?;
    let shifted_accumulator =
        u64::try_from(shifted_accumulator).map_err(|_| arithmetic_overflow())?;
    let maximum_shifted = statement
        .max_abs_accumulator
        .checked_mul(2)
        .ok_or_else(arithmetic_overflow)?;
    if shifted_accumulator > maximum_shifted {
        return Err(StructuredTransitionError::ValueOutOfRange.into());
    }

    Ok(DerivedTransitionRegularRow {
        accumulator,
        mask,
        encoded,
        square_quotient,
        square_remainder,
        cube_quotient,
        cube_remainder,
        output_quotient,
        output_remainder,
        negative,
        activation,
        shifted_accumulator,
    })
}

#[cfg(any(test, feature = "whir-prototype"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlsDoryExecutionAccumulatorTransition {
    Initialization,
    Bank(usize),
}

#[cfg(any(test, feature = "whir-prototype"))]
struct BlsDoryExecutionAccumulatorReader<'a> {
    artifact: &'a mut BlsDoryExecutionAccumulatorArtifact,
    context: BlsDoryExecutionAccumulatorArtifactContext,
    transition: BlsDoryExecutionAccumulatorTransition,
    cells_per_layer: usize,
    elements: usize,
    cached_column: Option<BlsDoryExecutionAccumulatorColumn>,
    cached_start: usize,
    cached_len: usize,
    cache: Vec<i32>,
}

#[cfg(any(test, feature = "whir-prototype"))]
impl<'a> BlsDoryExecutionAccumulatorReader<'a> {
    fn new(
        statement: StructuredTransitionStatement,
        artifact: &'a mut BlsDoryExecutionAccumulatorArtifact,
        expected_context: BlsDoryExecutionAccumulatorArtifactContext,
        transition: BlsDoryExecutionAccumulatorTransition,
    ) -> Result<Self, BlsDoryTransitionError> {
        statement.validate_verifier_shape()?;
        if artifact.context() != expected_context
            || statement.max_abs_accumulator > u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS)
        {
            return Err(BlsDoryTransitionError::ExecutionArtifact);
        }
        let cells_per_layer = statement
            .rows
            .checked_mul(statement.cols)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        if statement.rows != expected_context.canonical_rows()
            || statement.cols != expected_context.canonical_columns()
            || cells_per_layer != expected_context.cells_per_column()
        {
            return Err(BlsDoryTransitionError::ExecutionArtifact);
        }
        match transition {
            BlsDoryExecutionAccumulatorTransition::Initialization if statement.layers == 1 => {}
            BlsDoryExecutionAccumulatorTransition::Bank(bank)
                if bank < expected_context.banks()
                    && statement.layers == expected_context.layers_per_bank() => {}
            BlsDoryExecutionAccumulatorTransition::Initialization
            | BlsDoryExecutionAccumulatorTransition::Bank(_) => {
                return Err(BlsDoryTransitionError::ExecutionArtifact);
            }
        }
        let mut cache = Vec::new();
        cache
            .try_reserve_exact(expected_context.authentication_chunk_cells())
            .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
        cache.resize(expected_context.authentication_chunk_cells(), 0);
        Ok(Self {
            artifact,
            context: expected_context,
            transition,
            cells_per_layer,
            elements: statement.elements()?,
            cached_column: None,
            cached_start: 0,
            cached_len: 0,
            cache,
        })
    }

    fn accumulator(&mut self, index: usize) -> Result<i64, BlsDoryTransitionError> {
        if index >= self.elements {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        let layer = index / self.cells_per_layer;
        let cell = index % self.cells_per_layer;
        let column = match self.transition {
            BlsDoryExecutionAccumulatorTransition::Initialization => {
                BlsDoryExecutionAccumulatorColumn::Initialization
            }
            BlsDoryExecutionAccumulatorTransition::Bank(bank) => {
                BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer }
            }
        };
        let chunk_cells = self.context.authentication_chunk_cells();
        let chunk_start = cell / chunk_cells * chunk_cells;
        let chunk_len = self
            .cells_per_layer
            .checked_sub(chunk_start)
            .map(|remaining| remaining.min(chunk_cells))
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        if self.cached_column != Some(column)
            || self.cached_start != chunk_start
            || self.cached_len != chunk_len
        {
            self.cached_column = None;
            self.cached_start = 0;
            self.cached_len = 0;
            self.artifact
                .read_column_segment(column, chunk_start, &mut self.cache[..chunk_len])
                .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
            self.cached_column = Some(column);
            self.cached_start = chunk_start;
            self.cached_len = chunk_len;
        }
        self.cache
            .get(cell - chunk_start)
            .copied()
            .map(i64::from)
            .ok_or(BlsDoryTransitionError::ExecutionArtifact)
    }
}

#[cfg(feature = "whir-prototype")]
trait DoryV3TransitionAccumulatorReader: Send {
    fn accumulator(&mut self, index: usize) -> Result<i64, BlsDoryTransitionError>;
}

#[cfg(feature = "whir-prototype")]
struct BlsDoryV3ExecutionAccumulatorReader<'a, 'r> {
    reader: &'a mut BlsDoryV3ExecutionArtifactReader<'r>,
    transition: BlsDoryExecutionAccumulatorTransition,
    cells_per_layer: usize,
    elements: usize,
    cached_column: Option<BlsDoryExecutionAccumulatorColumn>,
    cached_start: usize,
    cached_len: usize,
    cache: Vec<i32>,
}

#[cfg(feature = "whir-prototype")]
impl<'a, 'r> BlsDoryV3ExecutionAccumulatorReader<'a, 'r> {
    fn new(
        statement: StructuredTransitionStatement,
        reader: &'a mut BlsDoryV3ExecutionArtifactReader<'r>,
        transition: BlsDoryExecutionAccumulatorTransition,
    ) -> Result<Self, BlsDoryTransitionError> {
        statement.validate_verifier_shape()?;
        let cells_per_layer = statement
            .rows
            .checked_mul(statement.cols)
            .filter(|cells| *cells == reader.cells_per_column())
            .ok_or(BlsDoryTransitionError::ExecutionArtifact)?;
        if statement.rows != reader.canonical_rows()
            || statement.cols != reader.canonical_columns()
            || statement.max_abs_accumulator > u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS)
        {
            return Err(BlsDoryTransitionError::ExecutionArtifact);
        }
        match transition {
            BlsDoryExecutionAccumulatorTransition::Initialization if statement.layers == 1 => {}
            BlsDoryExecutionAccumulatorTransition::Bank(bank)
                if bank < reader.banks() && statement.layers == reader.layers_per_bank() => {}
            BlsDoryExecutionAccumulatorTransition::Initialization
            | BlsDoryExecutionAccumulatorTransition::Bank(_) => {
                return Err(BlsDoryTransitionError::ExecutionArtifact);
            }
        }
        let mut cache = Vec::new();
        cache
            .try_reserve_exact(reader.authentication_chunk_cells())
            .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
        cache.resize(reader.authentication_chunk_cells(), 0);
        Ok(Self {
            reader,
            transition,
            cells_per_layer,
            elements: statement.elements()?,
            cached_column: None,
            cached_start: 0,
            cached_len: 0,
            cache,
        })
    }
}

#[cfg(feature = "whir-prototype")]
impl DoryV3TransitionAccumulatorReader for BlsDoryV3ExecutionAccumulatorReader<'_, '_> {
    fn accumulator(&mut self, index: usize) -> Result<i64, BlsDoryTransitionError> {
        if index >= self.elements {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        let layer = index / self.cells_per_layer;
        let cell = index % self.cells_per_layer;
        let column = match self.transition {
            BlsDoryExecutionAccumulatorTransition::Initialization => {
                BlsDoryExecutionAccumulatorColumn::Initialization
            }
            BlsDoryExecutionAccumulatorTransition::Bank(bank) => {
                BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer }
            }
        };
        let chunk_cells = self.reader.authentication_chunk_cells();
        let chunk_start = cell / chunk_cells * chunk_cells;
        let chunk_len = self
            .cells_per_layer
            .checked_sub(chunk_start)
            .map(|remaining| remaining.min(chunk_cells))
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        if self.cached_column != Some(column)
            || self.cached_start != chunk_start
            || self.cached_len != chunk_len
        {
            self.cached_column = None;
            self.cached_start = 0;
            self.cached_len = 0;
            let read = match column {
                BlsDoryExecutionAccumulatorColumn::Initialization => self
                    .reader
                    .read_initialization_segment(chunk_start, &mut self.cache[..chunk_len]),
                BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer } => {
                    self.reader.read_bank_layer_segment(
                        bank,
                        layer,
                        chunk_start,
                        &mut self.cache[..chunk_len],
                    )
                }
            }
            .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
            if read != chunk_len {
                return Err(BlsDoryTransitionError::ExecutionArtifact);
            }
            self.cached_column = Some(column);
            self.cached_start = chunk_start;
            self.cached_len = chunk_len;
        }
        self.cache
            .get(cell - chunk_start)
            .copied()
            .map(i64::from)
            .ok_or(BlsDoryTransitionError::ExecutionArtifact)
    }
}

enum TransitionWitnessBacking<'a> {
    Materialized(&'a StructuredTransitionWitness),
    Derived {
        mask_polynomial: &'a StructuredMaskPolynomial,
        accumulators: &'a [i64],
    },
    #[cfg(any(test, feature = "whir-prototype"))]
    ExecutionArtifact {
        mask_polynomial: &'a StructuredMaskPolynomial,
        reader: Box<Mutex<BlsDoryExecutionAccumulatorReader<'a>>>,
    },
    #[cfg(feature = "whir-prototype")]
    DoryV3ExecutionArtifact {
        mask_polynomial: StructuredMaskPolynomial,
        reader: Box<Mutex<dyn DoryV3TransitionAccumulatorReader + 'a>>,
    },
}

pub(crate) struct BlsDoryTransitionWitnessRowSource<'a> {
    statement: StructuredTransitionStatement,
    backing: TransitionWitnessBacking<'a>,
    range_oracles: Vec<RangeOracleDescriptor>,
    elements: usize,
    rows: usize,
    columns: usize,
    explicit_scalars: usize,
    range_dictionary: Vec<BlsDoryFr>,
}

impl<'a> BlsDoryTransitionWitnessRowSource<'a> {
    pub(crate) fn new(
        statement: StructuredTransitionStatement,
        witness: &'a StructuredTransitionWitness,
        rows: usize,
        columns: usize,
    ) -> Result<Self, BlsDoryTransitionError> {
        validate_streaming_witness(statement, witness)?;
        Self::from_backing(
            statement,
            TransitionWitnessBacking::Materialized(witness),
            rows,
            columns,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn new_from_accumulators(
        statement: StructuredTransitionStatement,
        mask_polynomial: &'a StructuredMaskPolynomial,
        accumulators: &'a [i64],
        rows: usize,
        columns: usize,
    ) -> Result<Self, BlsDoryTransitionError> {
        statement.validate_verifier_shape()?;
        mask_polynomial.validate(statement)?;
        if accumulators.len() != statement.elements()? {
            return Err(StructuredTransitionError::InvalidLength.into());
        }
        Self::from_backing(
            statement,
            TransitionWitnessBacking::Derived {
                mask_polynomial,
                accumulators,
            },
            rows,
            columns,
        )
    }

    #[cfg(any(test, feature = "whir-prototype"))]
    pub(crate) fn new_from_execution_artifact(
        statement: StructuredTransitionStatement,
        mask_polynomial: &'a StructuredMaskPolynomial,
        artifact: &'a mut BlsDoryExecutionAccumulatorArtifact,
        expected_context: BlsDoryExecutionAccumulatorArtifactContext,
        transition: BlsDoryExecutionAccumulatorTransition,
        rows: usize,
        columns: usize,
    ) -> Result<Self, BlsDoryTransitionError> {
        statement.validate_verifier_shape()?;
        mask_polynomial.validate(statement)?;
        let challenge = expected_context.challenge_identity();
        let expected_mask = match transition {
            BlsDoryExecutionAccumulatorTransition::Initialization => {
                StructuredMaskPolynomial::from_virtual_challenge(
                    &challenge,
                    expected_context.canonical_rows(),
                    expected_context.canonical_columns(),
                )
            }
            BlsDoryExecutionAccumulatorTransition::Bank(bank) => {
                let first_layer = bank
                    .checked_mul(expected_context.layers_per_bank())
                    .and_then(|layer| u32::try_from(layer).ok())
                    .ok_or(BlsDoryTransitionError::ExecutionArtifact)?;
                StructuredMaskPolynomial::from_challenge_at_layer_offset(
                    &challenge,
                    first_layer,
                    expected_context.layers_per_bank(),
                    expected_context.canonical_rows(),
                    expected_context.canonical_columns(),
                )
            }
        }
        .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
        if mask_polynomial != &expected_mask {
            return Err(BlsDoryTransitionError::ExecutionArtifact);
        }
        let reader = BlsDoryExecutionAccumulatorReader::new(
            statement,
            artifact,
            expected_context,
            transition,
        )?;
        Self::from_backing(
            statement,
            TransitionWitnessBacking::ExecutionArtifact {
                mask_polynomial,
                reader: Box::new(Mutex::new(reader)),
            },
            rows,
            columns,
        )
    }

    #[cfg(feature = "whir-prototype")]
    fn new_from_dory_v3_execution_reader<'r>(
        descriptor: DoryV3ExecutionTransitionDescriptor,
        reader: &'a mut BlsDoryV3ExecutionArtifactReader<'r>,
        rows: usize,
        columns: usize,
    ) -> Result<Self, BlsDoryTransitionError>
    where
        'r: 'a,
    {
        descriptor.statement.validate_verifier_shape()?;
        descriptor.mask_polynomial.validate(descriptor.statement)?;
        let reader = BlsDoryV3ExecutionAccumulatorReader::new(
            descriptor.statement,
            reader,
            descriptor.transition,
        )?;
        Self::from_backing(
            descriptor.statement,
            TransitionWitnessBacking::DoryV3ExecutionArtifact {
                mask_polynomial: descriptor.mask_polynomial,
                reader: Box::new(Mutex::new(reader)),
            },
            rows,
            columns,
        )
    }

    fn from_backing(
        statement: StructuredTransitionStatement,
        backing: TransitionWitnessBacking<'a>,
        rows: usize,
        columns: usize,
    ) -> Result<Self, BlsDoryTransitionError> {
        let elements = statement.elements()?;
        let mut range_oracles = Vec::with_capacity(
            STRUCTURED_TRANSITION_ORACLES - STRUCTURED_TRANSITION_REGULAR_ORACLES,
        );
        for spec in structured_transition_range_specs(statement)? {
            for digit in 0..spec.digits {
                range_oracles.push(RangeOracleDescriptor {
                    source_oracle: spec.oracle,
                    digit,
                    maximum: spec.maximum,
                    slack: false,
                });
                range_oracles.push(RangeOracleDescriptor {
                    source_oracle: spec.oracle,
                    digit,
                    maximum: spec.maximum,
                    slack: true,
                });
            }
        }
        let explicit_scalars = elements
            .checked_mul(STRUCTURED_TRANSITION_ORACLES)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        let logical_scalars = rows
            .checked_mul(columns)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        if range_oracles.len()
            != STRUCTURED_TRANSITION_ORACLES - STRUCTURED_TRANSITION_REGULAR_ORACLES
            || explicit_scalars > logical_scalars
        {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        Ok(Self {
            statement,
            backing,
            range_oracles,
            elements,
            rows,
            columns,
            explicit_scalars,
            range_dictionary: (0..16).map(BlsDoryFr::from_u64).collect(),
        })
    }

    pub(crate) const fn explicit_scalar_count(&self) -> usize {
        self.explicit_scalars
    }

    #[cfg(any(test, feature = "whir-prototype"))]
    fn is_execution_artifact_backed(&self) -> bool {
        match &self.backing {
            TransitionWitnessBacking::ExecutionArtifact { .. } => true,
            #[cfg(feature = "whir-prototype")]
            TransitionWitnessBacking::DoryV3ExecutionArtifact { .. } => true,
            TransitionWitnessBacking::Materialized(_)
            | TransitionWitnessBacking::Derived { .. } => false,
        }
    }

    #[cfg(any(test, feature = "whir-prototype"))]
    fn execution_derived_regular_row(
        &mut self,
        index: usize,
    ) -> Result<DerivedTransitionRegularRow, BlsDoryTransitionError> {
        if index >= self.elements {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        let (accumulator, mask) = match &mut self.backing {
            TransitionWitnessBacking::ExecutionArtifact {
                mask_polynomial,
                reader,
            } => {
                let accumulator = reader
                    .get_mut()
                    .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?
                    .accumulator(index)?;
                let mask =
                    mask_polynomial.value_at_boolean_index_prevalidated(self.statement, index)?;
                (accumulator, mask)
            }
            #[cfg(feature = "whir-prototype")]
            TransitionWitnessBacking::DoryV3ExecutionArtifact {
                mask_polynomial,
                reader,
            } => {
                let accumulator = reader
                    .get_mut()
                    .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?
                    .accumulator(index)?;
                let mask =
                    mask_polynomial.value_at_boolean_index_prevalidated(self.statement, index)?;
                (accumulator, mask)
            }
            TransitionWitnessBacking::Materialized(_)
            | TransitionWitnessBacking::Derived { .. } => {
                return Err(BlsDoryTransitionError::InvalidProofShape);
            }
        };
        derive_transition_regular_row_from_mask(self.statement, index, accumulator, mask)
    }

    fn literal_scalar_count(&self) -> usize {
        ((self.elements * STRUCTURED_TRANSITION_REGULAR_ORACLES).div_ceil(self.columns)
            * self.columns)
            .min(self.explicit_scalars)
    }

    fn regular_word(&self, oracle: usize, index: usize) -> Result<u64, BlsDoryTransitionError> {
        match &self.backing {
            TransitionWitnessBacking::Materialized(witness) => {
                let unsigned = |values: &[u64]| {
                    values
                        .get(index)
                        .copied()
                        .ok_or(BlsDoryTransitionError::InvalidDimensions)
                };
                let signed = |values: &[i64]| {
                    values
                        .get(index)
                        .copied()
                        .map(|value| u64::from_le_bytes(value.to_le_bytes()))
                        .ok_or(BlsDoryTransitionError::InvalidDimensions)
                };
                match oracle {
                    ACCUMULATOR => signed(&witness.accumulators),
                    MASK => unsigned(&witness.masks),
                    ENCODED => unsigned(&witness.encoded),
                    SQUARE_QUOTIENT => unsigned(&witness.square_quotients),
                    SQUARE_REMAINDER => unsigned(&witness.square_remainders),
                    CUBE_QUOTIENT => unsigned(&witness.cube_quotients),
                    CUBE_REMAINDER => unsigned(&witness.cube_remainders),
                    OUTPUT_QUOTIENT => unsigned(&witness.output_quotients),
                    OUTPUT_REMAINDER => unsigned(&witness.output_remainders),
                    NEGATIVE => unsigned(&witness.negative),
                    ACTIVATION => signed(&witness.activations),
                    SHIFTED_ACCUMULATOR => {
                        let accumulator = witness
                            .accumulators
                            .get(index)
                            .copied()
                            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
                        let shifted = u64::try_from(
                            i128::from(accumulator)
                                + i128::from(self.statement.max_abs_accumulator),
                        )
                        .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?;
                        Ok(shifted)
                    }
                    _ => Err(BlsDoryTransitionError::InvalidProofShape),
                }
            }
            TransitionWitnessBacking::Derived {
                mask_polynomial,
                accumulators,
            } => {
                let accumulator = accumulators
                    .get(index)
                    .copied()
                    .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
                let mask =
                    mask_polynomial.value_at_boolean_index_prevalidated(self.statement, index)?;
                derive_transition_regular_row_from_mask(self.statement, index, accumulator, mask)?
                    .word(oracle)
            }
            #[cfg(any(test, feature = "whir-prototype"))]
            TransitionWitnessBacking::ExecutionArtifact {
                mask_polynomial,
                reader,
            } => {
                let accumulator = reader
                    .lock()
                    .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?
                    .accumulator(index)?;
                let mask =
                    mask_polynomial.value_at_boolean_index_prevalidated(self.statement, index)?;
                derive_transition_regular_row_from_mask(self.statement, index, accumulator, mask)?
                    .word(oracle)
            }
            #[cfg(feature = "whir-prototype")]
            TransitionWitnessBacking::DoryV3ExecutionArtifact {
                mask_polynomial,
                reader,
            } => {
                let accumulator = reader
                    .lock()
                    .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?
                    .accumulator(index)?;
                let mask =
                    mask_polynomial.value_at_boolean_index_prevalidated(self.statement, index)?;
                derive_transition_regular_row_from_mask(self.statement, index, accumulator, mask)?
                    .word(oracle)
            }
        }
    }

    fn regular_value(
        &self,
        oracle: usize,
        index: usize,
    ) -> Result<BlsDoryFr, BlsDoryTransitionError> {
        let word = self.regular_word(oracle, index)?;
        if TRANSITION_SIGNED_WORD_SELECTORS & (1u64 << oracle) != 0 {
            Ok(BlsDoryFr::from_i64(i64::from_le_bytes(word.to_le_bytes())))
        } else {
            Ok(BlsDoryFr::from_u64(word))
        }
    }

    fn regular_row_values(
        &self,
        index: usize,
    ) -> Result<TransitionRegularRow, BlsDoryTransitionError> {
        if index >= self.elements {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        let derived = match &self.backing {
            TransitionWitnessBacking::Materialized(_) => None,
            TransitionWitnessBacking::Derived {
                mask_polynomial,
                accumulators,
            } => {
                let accumulator = accumulators
                    .get(index)
                    .copied()
                    .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
                let mask =
                    mask_polynomial.value_at_boolean_index_prevalidated(self.statement, index)?;
                Some(derive_transition_regular_row_from_mask(
                    self.statement,
                    index,
                    accumulator,
                    mask,
                )?)
            }
            #[cfg(any(test, feature = "whir-prototype"))]
            TransitionWitnessBacking::ExecutionArtifact {
                mask_polynomial,
                reader,
            } => {
                let accumulator = reader
                    .lock()
                    .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?
                    .accumulator(index)?;
                let mask =
                    mask_polynomial.value_at_boolean_index_prevalidated(self.statement, index)?;
                Some(derive_transition_regular_row_from_mask(
                    self.statement,
                    index,
                    accumulator,
                    mask,
                )?)
            }
            #[cfg(feature = "whir-prototype")]
            TransitionWitnessBacking::DoryV3ExecutionArtifact {
                mask_polynomial,
                reader,
            } => {
                let accumulator = reader
                    .lock()
                    .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?
                    .accumulator(index)?;
                let mask =
                    mask_polynomial.value_at_boolean_index_prevalidated(self.statement, index)?;
                Some(derive_transition_regular_row_from_mask(
                    self.statement,
                    index,
                    accumulator,
                    mask,
                )?)
            }
        };
        let mut values = [BlsDoryFr::zero(); STRUCTURED_TRANSITION_REGULAR_ORACLES];
        for (oracle, value) in values.iter_mut().enumerate() {
            if let Some(derived) = derived {
                let word = derived.word(oracle)?;
                *value = if TRANSITION_SIGNED_WORD_SELECTORS & (1u64 << oracle) != 0 {
                    BlsDoryFr::from_i64(i64::from_le_bytes(word.to_le_bytes()))
                } else {
                    BlsDoryFr::from_u64(word)
                };
            } else {
                *value = self.regular_value(oracle, index)?;
            }
        }
        Ok(values)
    }

    fn range_digit_for_descriptor(
        &self,
        descriptor: RangeOracleDescriptor,
        index: usize,
    ) -> Result<u8, BlsDoryTransitionError> {
        let value = self.regular_word(descriptor.source_oracle, index)?;
        let bounded = if descriptor.slack {
            descriptor
                .maximum
                .checked_sub(value)
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?
        } else {
            value
        };
        u8::try_from((bounded >> (descriptor.digit * 4)) & 0xf)
            .map_err(|_| BlsDoryTransitionError::InvalidDimensions)
    }

    pub(crate) fn range_digit(
        &self,
        oracle: usize,
        index: usize,
    ) -> Result<u8, BlsDoryTransitionError> {
        if index >= self.elements || oracle < STRUCTURED_TRANSITION_REGULAR_ORACLES {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        let descriptor = self
            .range_oracles
            .get(oracle - STRUCTURED_TRANSITION_REGULAR_ORACLES)
            .copied()
            .ok_or(BlsDoryTransitionError::InvalidProofShape)?;
        self.range_digit_for_descriptor(descriptor, index)
    }

    pub(crate) fn scalar(
        &self,
        oracle: usize,
        index: usize,
    ) -> Result<BlsDoryFr, BlsDoryTransitionError> {
        if index >= self.elements {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        if oracle < STRUCTURED_TRANSITION_REGULAR_ORACLES {
            return self.regular_value(oracle, index);
        }
        let descriptor = self
            .range_oracles
            .get(oracle - STRUCTURED_TRANSITION_REGULAR_ORACLES)
            .copied()
            .ok_or(BlsDoryTransitionError::InvalidProofShape)?;
        self.range_digit_for_descriptor(descriptor, index)
            .map(|digit| BlsDoryFr::from_u64(u64::from(digit)))
    }
}

impl BlsDoryRowSource for BlsDoryTransitionWitnessRowSource<'_> {
    type Error = BlsDoryTransitionError;

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.explicit_scalar_count()
    }

    fn read_row(
        &mut self,
        row_index: usize,
        output: &mut [BlsDoryFr],
    ) -> Result<usize, Self::Error> {
        let start = row_index
            .checked_mul(self.columns)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        for (column, scalar) in output.iter_mut().enumerate() {
            let packed_index = start + column;
            let oracle = packed_index / self.elements;
            let index = packed_index % self.elements;
            *scalar = if oracle < STRUCTURED_TRANSITION_ORACLES {
                self.scalar(oracle, index)?
            } else {
                BlsDoryFr::zero()
            };
        }
        Ok(output.len())
    }
}

#[cfg(test)]
impl crate::dory_bls12_381_aggregate::BlsDoryIndexedRowSource
    for BlsDoryTransitionWitnessRowSource<'_>
{
    type Error = BlsDoryTransitionError;

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.explicit_scalar_count()
    }

    fn literal_scalar_count(&self) -> usize {
        self.literal_scalar_count()
    }

    fn dictionary(&self) -> &[BlsDoryFr] {
        &self.range_dictionary
    }

    fn read_literal_row(
        &mut self,
        row_index: usize,
        output: &mut [BlsDoryFr],
    ) -> Result<usize, Self::Error> {
        let start = row_index
            .checked_mul(self.columns)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        let end = start
            .checked_add(output.len())
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        if output.len() != self.columns || end > self.literal_scalar_count() {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        for (column, scalar) in output.iter_mut().enumerate() {
            let packed_index = start + column;
            let oracle = packed_index / self.elements;
            let index = packed_index % self.elements;
            *scalar = self.scalar(oracle, index)?;
        }
        Ok(output.len())
    }

    fn read_code_row(&mut self, row_index: usize, output: &mut [u8]) -> Result<usize, Self::Error> {
        let start = row_index
            .checked_mul(self.columns)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        if output.len() != self.columns || start < self.literal_scalar_count() {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        for (column, code) in output.iter_mut().enumerate() {
            let packed_index = start + column;
            if packed_index >= self.explicit_scalars {
                *code = 0;
                continue;
            }
            let oracle = packed_index / self.elements;
            let index = packed_index % self.elements;
            *code = self.range_digit(oracle, index)?;
        }
        Ok(output.len())
    }
}

impl BlsDoryCompactRowSource for BlsDoryTransitionWitnessRowSource<'_> {
    type Error = BlsDoryTransitionError;

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.explicit_scalar_count()
    }

    fn word_scalar_count(&self) -> usize {
        self.literal_scalar_count()
    }

    fn word_bytes(&self) -> u8 {
        4
    }

    fn code_bits(&self) -> u8 {
        4
    }

    fn word_width_codes(&self) -> u64 {
        transition_word_width_codes(self.statement.max_mask)
    }

    fn word_group_len(&self) -> usize {
        self.elements
    }

    fn signed_word_selectors(&self) -> u64 {
        TRANSITION_SIGNED_WORD_SELECTORS
    }

    fn dictionary(&self) -> &[BlsDoryFr] {
        &self.range_dictionary
    }

    fn read_word_row(
        &mut self,
        row_index: usize,
        output: &mut [u64],
    ) -> Result<usize, Self::Error> {
        let start = row_index
            .checked_mul(self.columns)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        let end = start
            .checked_add(output.len())
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        if output.len() != self.columns || end > self.literal_scalar_count() {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        #[cfg(any(test, feature = "whir-prototype"))]
        if let TransitionWitnessBacking::ExecutionArtifact {
            mask_polynomial,
            reader,
        } = &mut self.backing
        {
            let statement = self.statement;
            let elements = self.elements;
            let reader = reader
                .get_mut()
                .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
            for (column, word) in output.iter_mut().enumerate() {
                let packed_index = start + column;
                let oracle = packed_index / elements;
                let index = packed_index % elements;
                if oracle >= STRUCTURED_TRANSITION_REGULAR_ORACLES {
                    return Err(BlsDoryTransitionError::InvalidProofShape);
                }
                let accumulator = reader.accumulator(index)?;
                let mask = mask_polynomial.value_at_boolean_index_prevalidated(statement, index)?;
                *word =
                    derive_transition_regular_row_from_mask(statement, index, accumulator, mask)?
                        .word(oracle)?;
            }
            return Ok(output.len());
        }
        #[cfg(feature = "whir-prototype")]
        if let TransitionWitnessBacking::DoryV3ExecutionArtifact {
            mask_polynomial,
            reader,
        } = &mut self.backing
        {
            let statement = self.statement;
            let elements = self.elements;
            let reader = reader
                .get_mut()
                .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
            for (column, word) in output.iter_mut().enumerate() {
                let packed_index = start + column;
                let oracle = packed_index / elements;
                let index = packed_index % elements;
                if oracle >= STRUCTURED_TRANSITION_REGULAR_ORACLES {
                    return Err(BlsDoryTransitionError::InvalidProofShape);
                }
                let accumulator = reader.accumulator(index)?;
                let mask = mask_polynomial.value_at_boolean_index_prevalidated(statement, index)?;
                *word =
                    derive_transition_regular_row_from_mask(statement, index, accumulator, mask)?
                        .word(oracle)?;
            }
            return Ok(output.len());
        }
        for (column, word) in output.iter_mut().enumerate() {
            let packed_index = start + column;
            let oracle = packed_index / self.elements;
            let index = packed_index % self.elements;
            *word = if oracle < STRUCTURED_TRANSITION_REGULAR_ORACLES {
                self.regular_word(oracle, index)?
            } else {
                u64::from(self.range_digit(oracle, index)?)
            };
        }
        Ok(output.len())
    }

    fn read_code_row(&mut self, row_index: usize, output: &mut [u8]) -> Result<usize, Self::Error> {
        let start = row_index
            .checked_mul(self.columns)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        if output.len() != self.columns || start < self.literal_scalar_count() {
            return Err(BlsDoryTransitionError::InvalidDimensions);
        }
        #[cfg(any(test, feature = "whir-prototype"))]
        if let TransitionWitnessBacking::ExecutionArtifact {
            mask_polynomial,
            reader,
        } = &mut self.backing
        {
            let statement = self.statement;
            let elements = self.elements;
            let range_oracles = &self.range_oracles;
            let reader = reader
                .get_mut()
                .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
            for (column, code) in output.iter_mut().enumerate() {
                let packed_index = start + column;
                if packed_index >= self.explicit_scalars {
                    *code = 0;
                    continue;
                }
                let oracle = packed_index / elements;
                let index = packed_index % elements;
                let descriptor = range_oracles
                    .get(
                        oracle
                            .checked_sub(STRUCTURED_TRANSITION_REGULAR_ORACLES)
                            .ok_or(BlsDoryTransitionError::InvalidProofShape)?,
                    )
                    .copied()
                    .ok_or(BlsDoryTransitionError::InvalidProofShape)?;
                let accumulator = reader.accumulator(index)?;
                let mask = mask_polynomial.value_at_boolean_index_prevalidated(statement, index)?;
                let value =
                    derive_transition_regular_row_from_mask(statement, index, accumulator, mask)?
                        .word(descriptor.source_oracle)?;
                let bounded = if descriptor.slack {
                    descriptor
                        .maximum
                        .checked_sub(value)
                        .ok_or(BlsDoryTransitionError::InvalidDimensions)?
                } else {
                    value
                };
                *code = u8::try_from((bounded >> (descriptor.digit * 4)) & 0xf)
                    .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?;
            }
            return Ok(output.len());
        }
        #[cfg(feature = "whir-prototype")]
        if let TransitionWitnessBacking::DoryV3ExecutionArtifact {
            mask_polynomial,
            reader,
        } = &mut self.backing
        {
            let statement = self.statement;
            let elements = self.elements;
            let range_oracles = &self.range_oracles;
            let reader = reader
                .get_mut()
                .map_err(|_| BlsDoryTransitionError::ExecutionArtifact)?;
            for (column, code) in output.iter_mut().enumerate() {
                let packed_index = start + column;
                if packed_index >= self.explicit_scalars {
                    *code = 0;
                    continue;
                }
                let oracle = packed_index / elements;
                let index = packed_index % elements;
                let descriptor = range_oracles
                    .get(
                        oracle
                            .checked_sub(STRUCTURED_TRANSITION_REGULAR_ORACLES)
                            .ok_or(BlsDoryTransitionError::InvalidProofShape)?,
                    )
                    .copied()
                    .ok_or(BlsDoryTransitionError::InvalidProofShape)?;
                let accumulator = reader.accumulator(index)?;
                let mask = mask_polynomial.value_at_boolean_index_prevalidated(statement, index)?;
                let value =
                    derive_transition_regular_row_from_mask(statement, index, accumulator, mask)?
                        .word(descriptor.source_oracle)?;
                let bounded = if descriptor.slack {
                    descriptor
                        .maximum
                        .checked_sub(value)
                        .ok_or(BlsDoryTransitionError::InvalidDimensions)?
                } else {
                    value
                };
                *code = u8::try_from((bounded >> (descriptor.digit * 4)) & 0xf)
                    .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?;
            }
            return Ok(output.len());
        }
        for (column, code) in output.iter_mut().enumerate() {
            let packed_index = start + column;
            if packed_index >= self.explicit_scalars {
                *code = 0;
                continue;
            }
            let oracle = packed_index / self.elements;
            let index = packed_index % self.elements;
            *code = self.range_digit(oracle, index)?;
        }
        Ok(output.len())
    }
}

fn witness_unsigned_values(
    witness: &StructuredTransitionWitness,
    oracle: usize,
) -> Result<&[u64], BlsDoryTransitionError> {
    Ok(match oracle {
        ENCODED => &witness.encoded,
        SQUARE_QUOTIENT => &witness.square_quotients,
        SQUARE_REMAINDER => &witness.square_remainders,
        CUBE_QUOTIENT => &witness.cube_quotients,
        CUBE_REMAINDER => &witness.cube_remainders,
        OUTPUT_QUOTIENT => &witness.output_quotients,
        OUTPUT_REMAINDER => &witness.output_remainders,
        _ => return Err(BlsDoryTransitionError::InvalidProofShape),
    })
}

fn signed_values(values: &[i64]) -> Vec<BlsDoryFr> {
    values.iter().copied().map(BlsDoryFr::from_i64).collect()
}

fn unsigned_values(values: &[u64]) -> Vec<BlsDoryFr> {
    values.iter().copied().map(BlsDoryFr::from_u64).collect()
}

pub(crate) fn pack_oracles(
    oracles: &[Vec<BlsDoryFr>],
) -> Result<Vec<BlsDoryFr>, BlsDoryTransitionError> {
    let elements = oracles
        .first()
        .ok_or(BlsDoryTransitionError::InvalidProofShape)?
        .len();
    if oracles.len() != STRUCTURED_TRANSITION_ORACLES
        || elements == 0
        || !elements.is_power_of_two()
        || oracles.iter().any(|oracle| oracle.len() != elements)
    {
        return Err(BlsDoryTransitionError::InvalidProofShape);
    }
    let total = elements
        .checked_mul(ORACLE_SLOTS)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let mut packed = Vec::with_capacity(total);
    for slot in 0..ORACLE_SLOTS {
        if let Some(oracle) = oracles.get(slot) {
            packed.extend_from_slice(oracle);
        } else {
            packed.resize(packed.len() + elements, BlsDoryFr::zero());
        }
    }
    Ok(packed)
}

fn packed_opening_points(
    cell_point: &[BlsDoryFr],
    packed_variables: usize,
) -> Result<Vec<Vec<BlsDoryFr>>, BlsDoryTransitionError> {
    let minimum = cell_point
        .len()
        .checked_add(BLS_DORY_TRANSITION_SELECTOR_VARIABLES)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    validate_target_variables(minimum, packed_variables)?;
    Ok((0..BLS_DORY_TRANSITION_OPENING_CLAIMS)
        .map(|oracle| {
            let mut point = Vec::with_capacity(packed_variables);
            point.extend_from_slice(cell_point);
            for bit in 0..BLS_DORY_TRANSITION_SELECTOR_VARIABLES {
                point.push(if (oracle >> bit) & 1 == 1 {
                    BlsDoryFr::one()
                } else {
                    BlsDoryFr::zero()
                });
            }
            point.resize(packed_variables, BlsDoryFr::zero());
            point
        })
        .collect())
}

fn transition_opening_claims(
    commitment: BlsDoryGt,
    cell_point: &[BlsDoryFr],
    evaluations: &[BlsDoryFr],
    packed_variables: usize,
) -> Result<Vec<BlsDoryOpeningClaim>, BlsDoryTransitionError> {
    Ok(packed_opening_points(cell_point, packed_variables)?
        .into_iter()
        .zip(evaluations)
        .map(|(point, evaluation)| BlsDoryOpeningClaim {
            commitment,
            point,
            evaluation: *evaluation,
        })
        .collect())
}

type TransitionRegularRow = [BlsDoryFr; STRUCTURED_TRANSITION_REGULAR_ORACLES];

struct TransitionScratchSumcheck {
    rounds: Vec<Vec<BlsDoryFr>>,
    point: Vec<BlsDoryFr>,
    terminal_evaluations: Vec<BlsDoryFr>,
    selector_terminal: BlsDoryFr,
    final_claim: BlsDoryFr,
}

struct TransitionEqualityWeightIterator<'a> {
    point: &'a [BlsDoryFr],
    stack: Vec<(usize, BlsDoryFr)>,
}

impl<'a> TransitionEqualityWeightIterator<'a> {
    fn new(point: &'a [BlsDoryFr]) -> Self {
        Self {
            point,
            stack: vec![(point.len(), BlsDoryFr::one())],
        }
    }
}

impl Iterator for TransitionEqualityWeightIterator<'_> {
    type Item = BlsDoryFr;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((remaining, prefix)) = self.stack.pop() {
            if remaining == 0 {
                return Some(prefix);
            }
            let coordinate = self.point[remaining - 1];
            self.stack.push((remaining - 1, prefix * coordinate));
            self.stack
                .push((remaining - 1, prefix * (BlsDoryFr::one() - coordinate)));
        }
        None
    }
}

fn transition_storage_error() -> BlsDoryTransitionError {
    BlsDoryAggregateError::ProverStorage.into()
}

fn regular_row(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    index: usize,
) -> Result<TransitionRegularRow, BlsDoryTransitionError> {
    source.regular_row_values(index)
}

fn accumulate_transition_pair(
    statement: StructuredTransitionStatement,
    lower: TransitionRegularRow,
    upper: TransitionRegularRow,
    selector_lower: BlsDoryFr,
    selector_upper: BlsDoryFr,
    mixing_powers: &[BlsDoryFr],
    evaluations: &mut [BlsDoryFr],
) -> Result<(), BlsDoryTransitionError> {
    for (sample, evaluation) in evaluations.iter_mut().enumerate() {
        let point = BlsDoryFr::from_u64(sample as u64);
        let mut values = [BlsDoryFr::zero(); STRUCTURED_TRANSITION_REGULAR_ORACLES];
        for oracle in 0..STRUCTURED_TRANSITION_REGULAR_ORACLES {
            values[oracle] = lower[oracle] + point * (upper[oracle] - lower[oracle]);
        }
        let selector = selector_lower + point * (selector_upper - selector_lower);
        *evaluation =
            *evaluation + selector * arithmetic_constraint(statement, &values, mixing_powers)?;
    }
    Ok(())
}

fn transition_raw_round(
    statement: StructuredTransitionStatement,
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    current_rows: usize,
    round_index: usize,
    cell_point: &[BlsDoryFr],
    selector_prefix: BlsDoryFr,
    mixing_powers: &[BlsDoryFr],
) -> Result<Vec<BlsDoryFr>, BlsDoryTransitionError> {
    if current_rows < 2 || !current_rows.is_power_of_two() || round_index >= cell_point.len() {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    let coordinate = cell_point[round_index];
    let mut suffix_weights = TransitionEqualityWeightIterator::new(&cell_point[round_index + 1..]);
    let mut evaluations = vec![BlsDoryFr::zero(); BLS_DORY_TRANSITION_SUMCHECK_DEGREE + 1];
    for pair_index in 0..current_rows / 2 {
        let suffix = suffix_weights
            .next()
            .ok_or(BlsDoryTransitionError::InvalidProofShape)?;
        let equality_scale = selector_prefix * suffix;
        accumulate_transition_pair(
            statement,
            regular_row(source, pair_index * 2)?,
            regular_row(source, pair_index * 2 + 1)?,
            equality_scale * (BlsDoryFr::one() - coordinate),
            equality_scale * coordinate,
            mixing_powers,
            &mut evaluations,
        )?;
    }
    if suffix_weights.next().is_some() {
        return Err(BlsDoryTransitionError::InvalidProofShape);
    }
    Ok(evaluations)
}

fn for_each_transition_artifact_pair(
    artifact: &BlsDoryFoldArtifact,
    mut visitor: impl FnMut(
        TransitionRegularRow,
        TransitionRegularRow,
    ) -> Result<(), BlsDoryTransitionError>,
) -> Result<(), BlsDoryTransitionError> {
    let scalar_count = usize::try_from(artifact.spec().scalar_count)
        .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?;
    if scalar_count < TRANSITION_FOLD_SLOTS * 2
        || !scalar_count.is_multiple_of(TRANSITION_FOLD_SLOTS * 2)
        || artifact.spec().explicit_scalar_count != artifact.spec().scalar_count
    {
        return Err(transition_storage_error());
    }
    let expected_rows = scalar_count / TRANSITION_FOLD_SLOTS;
    let mut row = [BlsDoryFr::zero(); STRUCTURED_TRANSITION_REGULAR_ORACLES];
    let mut slot = 0usize;
    let mut pending = None;
    let mut visited_rows = 0usize;
    let mut visitor_error = None;
    let artifact_result = artifact.for_each_scalar(|scalar| {
        if slot < STRUCTURED_TRANSITION_REGULAR_ORACLES {
            row[slot] = scalar;
        } else if !scalar.is_zero() {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        slot += 1;
        if slot == TRANSITION_FOLD_SLOTS {
            visited_rows += 1;
            if let Some(lower) = pending.take() {
                if let Err(error) = visitor(lower, row) {
                    visitor_error = Some(error);
                    return Err(BlsDoryFoldArtifactError::InvalidArtifact);
                }
            } else {
                pending = Some(row);
            }
            row.fill(BlsDoryFr::zero());
            slot = 0;
        }
        Ok(())
    });
    if let Some(error) = visitor_error {
        return Err(error);
    }
    artifact_result.map_err(|_| transition_storage_error())?;
    if slot != 0 || pending.is_some() || visited_rows != expected_rows {
        return Err(transition_storage_error());
    }
    Ok(())
}

fn transition_artifact_round(
    statement: StructuredTransitionStatement,
    artifact: &BlsDoryFoldArtifact,
    round_index: usize,
    cell_point: &[BlsDoryFr],
    selector_prefix: BlsDoryFr,
    mixing_powers: &[BlsDoryFr],
) -> Result<Vec<BlsDoryFr>, BlsDoryTransitionError> {
    let coordinate = *cell_point
        .get(round_index)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let mut suffix_weights = TransitionEqualityWeightIterator::new(&cell_point[round_index + 1..]);
    let mut evaluations = vec![BlsDoryFr::zero(); BLS_DORY_TRANSITION_SUMCHECK_DEGREE + 1];
    let mut visited = 0usize;
    for_each_transition_artifact_pair(artifact, |lower, upper| {
        let suffix = suffix_weights
            .next()
            .ok_or(BlsDoryTransitionError::InvalidProofShape)?;
        let equality_scale = selector_prefix * suffix;
        accumulate_transition_pair(
            statement,
            lower,
            upper,
            equality_scale * (BlsDoryFr::one() - coordinate),
            equality_scale * coordinate,
            mixing_powers,
            &mut evaluations,
        )?;
        visited += 1;
        Ok(())
    })?;
    let expected_pairs = usize::try_from(artifact.spec().scalar_count)
        .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?
        / TRANSITION_FOLD_SLOTS
        / 2;
    if suffix_weights.next().is_some() || visited != expected_pairs {
        return Err(BlsDoryTransitionError::InvalidProofShape);
    }
    Ok(evaluations)
}

fn transition_fold_spec(
    context_digest: [u8; 32],
    generation: usize,
    rows: usize,
    parent_digest: [u8; 32],
) -> Result<BlsDoryFoldArtifactSpec, BlsDoryTransitionError> {
    let scalar_count = rows
        .checked_mul(TRANSITION_FOLD_SLOTS)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    Ok(BlsDoryFoldArtifactSpec {
        context_digest,
        table_index: 0,
        generation: u32::try_from(generation)
            .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
        scalar_count: u64::try_from(scalar_count)
            .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
        explicit_scalar_count: u64::try_from(scalar_count)
            .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?,
        parent_digest,
    })
}

fn write_transition_fold_row(
    writer: &mut BlsDoryFoldArtifactWriter,
    lower: TransitionRegularRow,
    upper: TransitionRegularRow,
    challenge: BlsDoryFr,
) -> Result<(), BlsDoryTransitionError> {
    for oracle in 0..STRUCTURED_TRANSITION_REGULAR_ORACLES {
        writer
            .write_scalar(&(lower[oracle] + challenge * (upper[oracle] - lower[oracle])))
            .map_err(|_| transition_storage_error())?;
    }
    for _ in STRUCTURED_TRANSITION_REGULAR_ORACLES..TRANSITION_FOLD_SLOTS {
        writer
            .write_scalar(&BlsDoryFr::zero())
            .map_err(|_| transition_storage_error())?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn fold_raw_transition_rows(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    current_rows: usize,
    challenge: BlsDoryFr,
    context_digest: [u8; 32],
    generation: usize,
    parent_digest: [u8; 32],
    scratch_directory: &Path,
) -> Result<BlsDoryFoldArtifact, BlsDoryTransitionError> {
    let child_rows = current_rows
        .checked_div(2)
        .filter(|rows| *rows > 0)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let spec = transition_fold_spec(context_digest, generation, child_rows, parent_digest)?;
    let mut writer = BlsDoryFoldArtifactWriter::create(scratch_directory, spec)
        .map_err(|_| transition_storage_error())?;
    for pair_index in 0..child_rows {
        write_transition_fold_row(
            &mut writer,
            regular_row(source, pair_index * 2)?,
            regular_row(source, pair_index * 2 + 1)?,
            challenge,
        )?;
    }
    writer.finish().map_err(|_| transition_storage_error())
}

#[allow(clippy::too_many_arguments)]
fn fold_transition_artifact(
    artifact: &BlsDoryFoldArtifact,
    challenge: BlsDoryFr,
    context_digest: [u8; 32],
    generation: usize,
    parent_digest: [u8; 32],
    scratch_directory: &Path,
) -> Result<BlsDoryFoldArtifact, BlsDoryTransitionError> {
    let current_rows = usize::try_from(artifact.spec().scalar_count)
        .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?
        / TRANSITION_FOLD_SLOTS;
    let child_rows = current_rows
        .checked_div(2)
        .filter(|rows| *rows > 0)
        .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
    let spec = transition_fold_spec(context_digest, generation, child_rows, parent_digest)?;
    let mut writer = BlsDoryFoldArtifactWriter::create(scratch_directory, spec)
        .map_err(|_| transition_storage_error())?;
    for_each_transition_artifact_pair(artifact, |lower, upper| {
        write_transition_fold_row(&mut writer, lower, upper, challenge)
    })?;
    writer.finish().map_err(|_| transition_storage_error())
}

fn transition_terminal_row(
    artifact: &BlsDoryFoldArtifact,
) -> Result<TransitionRegularRow, BlsDoryTransitionError> {
    if artifact.spec().scalar_count != TRANSITION_FOLD_SLOTS as u64
        || artifact.spec().explicit_scalar_count != TRANSITION_FOLD_SLOTS as u64
    {
        return Err(transition_storage_error());
    }
    let mut row = [BlsDoryFr::zero(); STRUCTURED_TRANSITION_REGULAR_ORACLES];
    let mut slot = 0usize;
    artifact
        .for_each_scalar(|scalar| {
            if slot < STRUCTURED_TRANSITION_REGULAR_ORACLES {
                row[slot] = scalar;
            } else if !scalar.is_zero() {
                return Err(BlsDoryFoldArtifactError::InvalidArtifact);
            }
            slot += 1;
            Ok(())
        })
        .map_err(|_| transition_storage_error())?;
    if slot != TRANSITION_FOLD_SLOTS {
        return Err(transition_storage_error());
    }
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
fn prove_transition_sumcheck_with_scratch(
    statement: StructuredTransitionStatement,
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    cell_point: &[BlsDoryFr],
    mixing_powers: &[BlsDoryFr],
    transcript: &mut BlsDoryTranscript,
    scratch_directory: &Path,
) -> Result<TransitionScratchSumcheck, BlsDoryTransitionError> {
    let mut claim = BlsDoryFr::zero();
    let mut rounds = Vec::with_capacity(cell_point.len());
    let mut point = Vec::with_capacity(cell_point.len());
    let mut selector_prefix = BlsDoryFr::one();
    if cell_point.is_empty() {
        let terminal = regular_row(source, 0)?.to_vec();
        return Ok(TransitionScratchSumcheck {
            rounds,
            point,
            terminal_evaluations: terminal,
            selector_terminal: selector_prefix,
            final_claim: claim,
        });
    }

    let context_digest = transcript.digest();
    if context_digest == [0; 32] {
        return Err(transition_storage_error());
    }
    let mut parent =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/BlsDoryTransitionFoldParent/v1");
    parent.update(&context_digest);
    let mut parent_digest = *parent.finalize().as_bytes();
    let mut artifact = None;
    let mut current_rows = source.elements;
    for round_index in 0..cell_point.len() {
        let evaluations = if let Some(current) = artifact.as_ref() {
            transition_artifact_round(
                statement,
                current,
                round_index,
                cell_point,
                selector_prefix,
                mixing_powers,
            )?
        } else {
            transition_raw_round(
                statement,
                source,
                current_rows,
                round_index,
                cell_point,
                selector_prefix,
                mixing_powers,
            )?
        };
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryTransitionError::RoundClaim);
        }
        absorb_round(transcript, round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        point.push(challenge);
        let generation = round_index + 1;
        let child = if let Some(current) = artifact.as_ref() {
            fold_transition_artifact(
                current,
                challenge,
                context_digest,
                generation,
                parent_digest,
                scratch_directory,
            )?
        } else {
            fold_raw_transition_rows(
                source,
                current_rows,
                challenge,
                context_digest,
                generation,
                parent_digest,
                scratch_directory,
            )?
        };
        parent_digest = child.digest();
        artifact = Some(child);
        current_rows /= 2;
        let coordinate = cell_point[round_index];
        selector_prefix = selector_prefix
            * ((BlsDoryFr::one() - challenge) * (BlsDoryFr::one() - coordinate)
                + challenge * coordinate);
        rounds.push(evaluations);
    }
    let terminal_evaluations = transition_terminal_row(
        artifact
            .as_ref()
            .ok_or(BlsDoryTransitionError::InvalidProofShape)?,
    )?
    .to_vec();
    Ok(TransitionScratchSumcheck {
        rounds,
        point,
        terminal_evaluations,
        selector_terminal: selector_prefix,
        final_claim: claim,
    })
}

fn transition_round(
    statement: StructuredTransitionStatement,
    selector: &[BlsDoryFr],
    oracles: &[Vec<BlsDoryFr>],
    mixing_powers: &[BlsDoryFr],
) -> Result<Vec<BlsDoryFr>, BlsDoryTransitionError> {
    let mut evaluations = Vec::with_capacity(BLS_DORY_TRANSITION_SUMCHECK_DEGREE + 1);
    for sample in 0..=BLS_DORY_TRANSITION_SUMCHECK_DEGREE {
        let point = BlsDoryFr::from_u64(sample as u64);
        let mut sum = BlsDoryFr::zero();
        for pair_index in 0..selector.len() / 2 {
            let offset = pair_index * 2;
            let values = oracles
                .iter()
                .map(|oracle| interpolate_pair(&oracle[offset..offset + 2], point))
                .collect::<Vec<_>>();
            sum = sum
                + interpolate_pair(&selector[offset..offset + 2], point)
                    * arithmetic_constraint(statement, &values, mixing_powers)?;
        }
        evaluations.push(sum);
    }
    Ok(evaluations)
}

fn arithmetic_constraint(
    statement: StructuredTransitionStatement,
    values: &[BlsDoryFr],
    powers: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryTransitionError> {
    let modulus = BlsDoryFr::from_u64(u64::from(V2_TRANSITION_MODULUS));
    let output_modulus = BlsDoryFr::from_u64(OUTPUT_MODULUS);
    let center = BlsDoryFr::from_u64(OUTPUT_CENTER);
    if values.len() != STRUCTURED_TRANSITION_REGULAR_ORACLES
        || powers.len() != BLS_DORY_TRANSITION_ARITHMETIC_CONSTRAINTS
    {
        return Err(BlsDoryTransitionError::InvalidProofShape);
    }
    let mut constraints = Vec::with_capacity(BLS_DORY_TRANSITION_ARITHMETIC_CONSTRAINTS);
    constraints
        .push(values[ENCODED] - values[ACCUMULATOR] - values[MASK] - values[NEGATIVE] * modulus);
    constraints.push(
        values[ENCODED] * values[ENCODED]
            - values[SQUARE_QUOTIENT] * modulus
            - values[SQUARE_REMAINDER],
    );
    constraints.push(
        values[SQUARE_REMAINDER] * values[ENCODED]
            - values[CUBE_QUOTIENT] * modulus
            - values[CUBE_REMAINDER],
    );
    constraints.push(
        values[CUBE_REMAINDER]
            - values[OUTPUT_QUOTIENT] * output_modulus
            - values[OUTPUT_REMAINDER],
    );
    constraints.push(values[ACTIVATION] - values[OUTPUT_REMAINDER] + center);
    constraints.push(values[NEGATIVE] * (values[NEGATIVE] - BlsDoryFr::one()));
    constraints.push(
        values[SHIFTED_ACCUMULATOR]
            - values[ACCUMULATOR]
            - BlsDoryFr::from_u64(statement.max_abs_accumulator),
    );

    debug_assert_eq!(
        constraints.len(),
        BLS_DORY_TRANSITION_ARITHMETIC_CONSTRAINTS
    );
    Ok(constraints
        .into_iter()
        .zip(powers)
        .fold(BlsDoryFr::zero(), |sum, (constraint, coefficient)| {
            sum + constraint * coefficient
        }))
}

fn evaluate_mask(
    mask: &StructuredMaskPolynomial,
    statement: StructuredTransitionStatement,
    point: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryTransitionError> {
    let coefficients = mask.affine_coefficients(statement)?;
    let col_bits = statement.cols.ilog2() as usize;
    let row_bits = statement.rows.ilog2() as usize;
    let row_end = col_bits + row_bits;
    if point.len() != row_end + statement.layers.ilog2() as usize {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    let layer_weights = equality_table(&point[row_end..]);
    let coefficient_count = 1 + row_bits + col_bits;
    Ok(layer_weights
        .into_iter()
        .enumerate()
        .fold(BlsDoryFr::zero(), |sum, (layer, weight)| {
            let layer_coefficients =
                &coefficients[layer * coefficient_count..(layer + 1) * coefficient_count];
            let mut value = BlsDoryFr::from_u64(u64::from(layer_coefficients[0]));
            for (bit, challenge) in point[col_bits..row_end].iter().enumerate() {
                value =
                    value + BlsDoryFr::from_u64(u64::from(layer_coefficients[1 + bit])) * challenge;
            }
            for (bit, challenge) in point[..col_bits].iter().enumerate() {
                value = value
                    + BlsDoryFr::from_u64(u64::from(layer_coefficients[1 + row_bits + bit]))
                        * challenge;
            }
            sum + weight * value
        }))
}

fn equality_table(point: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
    let mut table = vec![BlsDoryFr::one(); 1usize << point.len()];
    let mut active = 1usize;
    for coordinate in point {
        for index in (0..active).rev() {
            let value = table[index];
            table[index] = value * (BlsDoryFr::one() - *coordinate);
            table[index + active] = value * coordinate;
        }
        active *= 2;
    }
    table
}

fn equality_evaluation(left: &[BlsDoryFr], right: &[BlsDoryFr]) -> BlsDoryFr {
    left.iter()
        .zip(right)
        .fold(BlsDoryFr::one(), |product, (left, right)| {
            product * ((BlsDoryFr::one() - *left) * (BlsDoryFr::one() - *right) + *left * right)
        })
}

fn interpolate_pair(pair: &[BlsDoryFr], point: BlsDoryFr) -> BlsDoryFr {
    pair[0] + point * (pair[1] - pair[0])
}

fn fold_table(table: &[BlsDoryFr], point: BlsDoryFr) -> Vec<BlsDoryFr> {
    table
        .chunks_exact(2)
        .map(|pair| interpolate_pair(pair, point))
        .collect()
}

fn powers(base: BlsDoryFr, count: usize) -> Vec<BlsDoryFr> {
    let mut result = Vec::with_capacity(count);
    let mut value = BlsDoryFr::one();
    for _ in 0..count {
        result.push(value);
        value = value * base;
    }
    result
}

fn evaluate_samples(
    values: &[BlsDoryFr],
    point: BlsDoryFr,
) -> Result<BlsDoryFr, BlsDoryTransitionError> {
    if values.len() != BLS_DORY_TRANSITION_SUMCHECK_DEGREE + 1 {
        return Err(BlsDoryTransitionError::InvalidProofShape);
    }
    let mut result = BlsDoryFr::zero();
    for (index, value) in values.iter().copied().enumerate() {
        let mut numerator = BlsDoryFr::one();
        let mut denominator = BlsDoryFr::one();
        for other in 0..values.len() {
            if other == index {
                continue;
            }
            numerator = numerator * (point - BlsDoryFr::from_u64(other as u64));
            denominator = denominator * BlsDoryFr::from_i64(index as i64 - other as i64);
        }
        let inverse = denominator
            .inv()
            .ok_or(BlsDoryTransitionError::InvalidProofShape)?;
        result = result + value * numerator * inverse;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dory_bls12_381_prototype::deterministic_bls_dory_setup;

    static SCRATCH_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    struct ScratchDirectory(std::path::PathBuf);

    impl ScratchDirectory {
        fn create() -> Self {
            let nonce = SCRATCH_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-transition-scratch-test-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> (
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
            let z = i128::from(accumulator) + i128::from(mask_value);
            let negative = u64::from(z < 0);
            let encoded = u64::try_from(if z < 0 { i128::from(modulus) + z } else { z }).unwrap();
            let square = encoded * encoded;
            let square_quotient = square / modulus;
            let square_remainder = square % modulus;
            let cube = square_remainder * encoded;
            let cube_quotient = cube / modulus;
            let cube_remainder = cube % modulus;
            let output_quotient = cube_remainder / OUTPUT_MODULUS;
            let output_remainder = cube_remainder % OUTPUT_MODULUS;
            let activation = i64::try_from(output_remainder).unwrap() - OUTPUT_CENTER as i64;

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
            witness.activations.push(activation);
        }
        (statement, mask, witness)
    }

    fn execution_artifact_for_fixture(
        statement: StructuredTransitionStatement,
        witness: &StructuredTransitionWitness,
        directory: &Path,
        setup_identity: [u8; 32],
    ) -> (
        BlsDoryExecutionAccumulatorArtifactContext,
        BlsDoryExecutionAccumulatorArtifact,
    ) {
        use crate::dory_bls12_381_execution_artifact::BlsDoryExecutionAccumulatorArtifactWriter;

        let context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [[0x11; 32], [0x22; 32], setup_identity, [0x5a; 32]],
            statement.rows,
            statement.cols,
            1,
            statement.layers,
            2,
        )
        .unwrap();
        let mut writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(directory, context).unwrap();
        for values in [[0, 0], [0, 0]] {
            writer
                .write_column_chunk(BlsDoryExecutionAccumulatorColumn::Initialization, &values)
                .unwrap();
        }
        let cells = statement.rows * statement.cols;
        for layer in 0..statement.layers {
            let column = BlsDoryExecutionAccumulatorColumn::BankLayer { bank: 0, layer };
            let layer_values = &witness.accumulators[layer * cells..(layer + 1) * cells];
            for chunk in layer_values.chunks_exact(context.authentication_chunk_cells()) {
                let values = chunk
                    .iter()
                    .copied()
                    .map(i32::try_from)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                writer.write_column_chunk(column, &values).unwrap();
            }
        }
        (context, writer.finish().unwrap())
    }

    #[test]
    fn witness_row_source_matches_every_materialized_transition_oracle() {
        let (statement, mask, witness) = fixture();
        let variables = minimum_packed_variables(statement).unwrap();
        let nu = variables / 2;
        let sigma = variables - nu;
        let rows = 1usize << nu;
        let columns = 1usize << sigma;
        let oracles = build_scalar_oracles(statement, &witness).unwrap();
        let packed = pack_oracles(&oracles).unwrap();
        let mut source =
            BlsDoryTransitionWitnessRowSource::new(statement, &witness, rows, columns).unwrap();
        let explicit = source.explicit_scalar_count();
        let mut streamed = Vec::new();
        let mut row = vec![BlsDoryFr::zero(); columns];
        for row_index in 0..explicit.div_ceil(columns) {
            source.read_row(row_index, &mut row).unwrap();
            streamed.extend_from_slice(&row);
        }
        streamed.truncate(explicit);
        assert_eq!(streamed, packed[..explicit]);

        let mut derived = BlsDoryTransitionWitnessRowSource::new_from_accumulators(
            statement,
            &mask,
            &witness.accumulators,
            rows,
            columns,
        )
        .unwrap();
        let mut derived_scalars = Vec::new();
        for row_index in 0..explicit.div_ceil(columns) {
            derived.read_row(row_index, &mut row).unwrap();
            derived_scalars.extend_from_slice(&row);
        }
        derived_scalars.truncate(explicit);
        assert_eq!(derived_scalars, packed[..explicit]);
        assert_eq!(derived_scalars, streamed);

        let literal_rows = source.literal_scalar_count() / columns;
        let explicit_rows = explicit.div_ceil(columns);
        let mut materialized_words = vec![0; columns];
        let mut derived_words = vec![0; columns];
        for row_index in 0..literal_rows {
            BlsDoryCompactRowSource::read_word_row(&mut source, row_index, &mut materialized_words)
                .unwrap();
            BlsDoryCompactRowSource::read_word_row(&mut derived, row_index, &mut derived_words)
                .unwrap();
            assert_eq!(derived_words, materialized_words);
        }
        let mut materialized_codes = vec![0; columns];
        let mut derived_codes = vec![0; columns];
        for row_index in literal_rows..explicit_rows {
            BlsDoryCompactRowSource::read_code_row(&mut source, row_index, &mut materialized_codes)
                .unwrap();
            BlsDoryCompactRowSource::read_code_row(&mut derived, row_index, &mut derived_codes)
                .unwrap();
            assert_eq!(derived_codes, materialized_codes);
        }
    }

    #[test]
    fn derived_transition_regular_rows_match_every_materialized_value() {
        let (statement, mask, witness) = fixture();
        for index in 0..statement.elements().unwrap() {
            let derived =
                derive_transition_regular_row(statement, &mask, index, witness.accumulators[index])
                    .unwrap();
            let expected = [
                u64::from_le_bytes(witness.accumulators[index].to_le_bytes()),
                witness.masks[index],
                witness.encoded[index],
                witness.square_quotients[index],
                witness.square_remainders[index],
                witness.cube_quotients[index],
                witness.cube_remainders[index],
                witness.output_quotients[index],
                witness.output_remainders[index],
                witness.negative[index],
                u64::from_le_bytes(witness.activations[index].to_le_bytes()),
                u64::try_from(
                    i128::from(witness.accumulators[index])
                        + i128::from(statement.max_abs_accumulator),
                )
                .unwrap(),
            ];
            for (oracle, expected) in expected.into_iter().enumerate() {
                assert_eq!(derived.word(oracle).unwrap(), expected, "oracle {oracle}");
            }
        }
    }

    #[test]
    fn artifact_backed_transition_source_matches_materialized_oracles() {
        let (statement, mask, witness) = fixture();
        let scratch = ScratchDirectory::create();
        let (context, mut artifact) =
            execution_artifact_for_fixture(statement, &witness, &scratch.0, [0x33; 32]);
        let variables = minimum_packed_variables(statement).unwrap();
        let nu = variables / 2;
        let sigma = variables - nu;
        let rows = 1usize << nu;
        let columns = 1usize << sigma;
        let mut materialized =
            BlsDoryTransitionWitnessRowSource::new(statement, &witness, rows, columns).unwrap();
        let mut streamed = BlsDoryTransitionWitnessRowSource::new_from_execution_artifact(
            statement,
            &mask,
            &mut artifact,
            context,
            BlsDoryExecutionAccumulatorTransition::Bank(0),
            rows,
            columns,
        )
        .unwrap();
        let mut expected = vec![BlsDoryFr::zero(); columns];
        let mut actual = vec![BlsDoryFr::zero(); columns];
        for row_index in 0..rows {
            materialized.read_row(row_index, &mut expected).unwrap();
            streamed.read_row(row_index, &mut actual).unwrap();
            assert_eq!(actual, expected, "packed row {row_index}");
        }
        drop(streamed);

        let wrong_mask = StructuredMaskPolynomial::from_challenge(&[0x5b; 32], 2, 2, 2).unwrap();
        assert_eq!(
            BlsDoryTransitionWitnessRowSource::new_from_execution_artifact(
                statement,
                &wrong_mask,
                &mut artifact,
                context,
                BlsDoryExecutionAccumulatorTransition::Bank(0),
                rows,
                columns,
            )
            .err(),
            Some(BlsDoryTransitionError::ExecutionArtifact)
        );

        let wrong_context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [[0x11; 32], [0x22; 32], [0x33; 32], [0x45; 32]],
            statement.rows,
            statement.cols,
            1,
            statement.layers,
            2,
        )
        .unwrap();
        assert_eq!(
            BlsDoryTransitionWitnessRowSource::new_from_execution_artifact(
                statement,
                &mask,
                &mut artifact,
                wrong_context,
                BlsDoryExecutionAccumulatorTransition::Bank(0),
                rows,
                columns,
            )
            .err(),
            Some(BlsDoryTransitionError::ExecutionArtifact)
        );

        let aliased_statement = StructuredTransitionStatement {
            rows: 1,
            cols: statement.rows * statement.cols,
            ..statement
        };
        assert_eq!(
            BlsDoryExecutionAccumulatorReader::new(
                aliased_statement,
                &mut artifact,
                context,
                BlsDoryExecutionAccumulatorTransition::Bank(0),
            )
            .err(),
            Some(BlsDoryTransitionError::ExecutionArtifact)
        );
    }

    #[test]
    fn grouped_execution_artifact_matches_legacy_bytes_and_commitment() {
        let (statement, mask, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let execution_scratch = ScratchDirectory::create();
        let grouped_scratch = ScratchDirectory::create();
        let legacy_scratch = ScratchDirectory::create();
        let (context, mut execution_artifact) = execution_artifact_for_fixture(
            statement,
            &witness,
            &execution_scratch.0,
            setup.identity(),
        );
        let variables = minimum_packed_variables(statement).unwrap();
        let nu = variables / 2;
        let sigma = variables - nu;
        let rows = 1usize << nu;
        let columns = 1usize << sigma;

        let mut grouped_source = BlsDoryTransitionWitnessRowSource::new_from_execution_artifact(
            statement,
            &mask,
            &mut execution_artifact,
            context,
            BlsDoryExecutionAccumulatorTransition::Bank(0),
            rows,
            columns,
        )
        .unwrap();
        let grouped = build_grouped_transition_compact_artifact_with_chunk_cells(
            &mut grouped_source,
            nu,
            sigma,
            &setup,
            &grouped_scratch.0,
            2,
        )
        .unwrap();
        assert_eq!(grouped.derived_cells, statement.elements().unwrap());
        let grouped_path = grouped.artifact.path().to_path_buf();
        let grouped_digest = grouped.artifact.digest();
        let grouped_bytes = std::fs::read(&grouped_path).unwrap();
        drop(grouped_source);

        let mut legacy_source = BlsDoryTransitionWitnessRowSource::new_from_execution_artifact(
            statement,
            &mask,
            &mut execution_artifact,
            context,
            BlsDoryExecutionAccumulatorTransition::Bank(0),
            rows,
            columns,
        )
        .unwrap();
        let legacy = commit_bls_dory_compact_row_source_with_scratch(
            &mut legacy_source,
            nu,
            sigma,
            &setup,
            &legacy_scratch.0,
        )
        .unwrap();
        drop(legacy_source);
        let legacy_path = legacy.coefficient_artifact_path().unwrap().to_path_buf();
        let legacy_bytes = std::fs::read(&legacy_path).unwrap();
        assert_eq!(grouped_bytes, legacy_bytes);
        assert_eq!(grouped_digest, legacy_bytes[legacy_bytes.len() - 32..]);

        let grouped_committed = commit_bls_dory_existing_compact_artifact(
            Arc::clone(&grouped.artifact),
            nu,
            sigma,
            &setup,
        )
        .unwrap();
        assert_eq!(grouped_committed.commitment(), legacy.commitment());
        assert_eq!(
            grouped_committed.row_commitments(),
            legacy.row_commitments()
        );
        assert_eq!(
            grouped_committed.coefficient_artifact_path(),
            Some(grouped_path.as_path())
        );
        assert_eq!(std::fs::read(&grouped_path).unwrap(), grouped_bytes);
        assert_eq!(std::fs::read_dir(&grouped_scratch.0).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&legacy_scratch.0).unwrap().count(), 1);

        drop(grouped_committed);
        drop(grouped);
        drop(legacy);
        drop(execution_artifact);
        assert_eq!(std::fs::read_dir(&grouped_scratch.0).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&legacy_scratch.0).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&execution_scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn grouped_execution_artifact_fails_closed_and_cleans_partial_file() {
        use std::io::{Read, Seek, SeekFrom, Write};

        let (statement, mask, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let execution_scratch = ScratchDirectory::create();
        let grouped_scratch = ScratchDirectory::create();
        let (context, mut execution_artifact) = execution_artifact_for_fixture(
            statement,
            &witness,
            &execution_scratch.0,
            setup.identity(),
        );
        let execution_path = std::fs::read_dir(&execution_scratch.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let artifact_bytes = std::fs::metadata(&execution_path).unwrap().len();
        let value_bytes = std::mem::size_of::<i32>() as u64;
        let data_bytes = (context.columns() * context.cells_per_column()) as u64 * value_bytes;
        let chunks_per_column = context
            .cells_per_column()
            .div_ceil(context.authentication_chunk_cells());
        let digest_bytes = (context.columns() * chunks_per_column * 32) as u64;
        let data_start = artifact_bytes - data_bytes - digest_bytes - 64;
        let second_bank_chunk_cell =
            context.cells_per_column() + context.authentication_chunk_cells();
        let corrupt_offset = data_start + second_bank_chunk_cell as u64 * value_bytes;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&execution_path)
            .unwrap();
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        let mut byte = [0; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        file.write_all(&[byte[0] ^ 0x80]).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();
        drop(file);

        let variables = minimum_packed_variables(statement).unwrap();
        let nu = variables / 2;
        let sigma = variables - nu;
        let rows = 1usize << nu;
        let columns = 1usize << sigma;
        let mut source = BlsDoryTransitionWitnessRowSource::new_from_execution_artifact(
            statement,
            &mask,
            &mut execution_artifact,
            context,
            BlsDoryExecutionAccumulatorTransition::Bank(0),
            rows,
            columns,
        )
        .unwrap();
        assert!(matches!(
            build_grouped_transition_compact_artifact_with_chunk_cells(
                &mut source,
                nu,
                sigma,
                &setup,
                &grouped_scratch.0,
                2,
            ),
            Err(BlsDoryTransitionError::ExecutionArtifact)
        ));
        assert_eq!(std::fs::read_dir(&grouped_scratch.0).unwrap().count(), 0);
        drop(source);
        drop(execution_artifact);
        assert_eq!(std::fs::read_dir(&execution_scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn artifact_reader_does_not_reuse_cached_chunk_after_authentication_failure() {
        use std::io::{Read, Seek, SeekFrom, Write};

        let (statement, _mask, witness) = fixture();
        let scratch = ScratchDirectory::create();
        let (context, mut artifact) =
            execution_artifact_for_fixture(statement, &witness, &scratch.0, [0x33; 32]);
        let artifact_path = std::fs::read_dir(&scratch.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let artifact_bytes = std::fs::metadata(&artifact_path).unwrap().len();
        let value_bytes = std::mem::size_of::<i32>() as u64;
        let data_bytes = (context.columns() * context.cells_per_column()) as u64 * value_bytes;
        let chunks_per_column = context
            .cells_per_column()
            .div_ceil(context.authentication_chunk_cells());
        let digest_bytes = (context.columns() * chunks_per_column * 32) as u64;
        let data_start = artifact_bytes - data_bytes - digest_bytes - 64;
        let chunk_b_cell = context.cells_per_column() + context.authentication_chunk_cells();
        let chunk_b_offset = data_start + chunk_b_cell as u64 * value_bytes;
        let mut reader = BlsDoryExecutionAccumulatorReader::new(
            statement,
            &mut artifact,
            context,
            BlsDoryExecutionAccumulatorTransition::Bank(0),
        )
        .unwrap();

        assert_eq!(reader.accumulator(0).unwrap(), witness.accumulators[0]);

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&artifact_path)
            .unwrap();
        file.seek(SeekFrom::Start(chunk_b_offset)).unwrap();
        let mut byte = [0; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(chunk_b_offset)).unwrap();
        file.write_all(&[byte[0] ^ 0x80]).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        assert_eq!(
            reader.accumulator(context.authentication_chunk_cells()),
            Err(BlsDoryTransitionError::ExecutionArtifact)
        );
        assert_eq!(reader.cached_column, None);
        assert_eq!(reader.cached_len, 0);
        assert_eq!(
            reader.accumulator(0),
            Err(BlsDoryTransitionError::ExecutionArtifact)
        );
    }

    #[test]
    fn artifact_backed_transition_proof_matches_materialized_proof_bytes() {
        let (statement, mask, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let materialized_scratch = ScratchDirectory::create();
        let artifact_scratch = ScratchDirectory::create();
        let streamed_scratch = ScratchDirectory::create();
        let wrong_setup_scratch = ScratchDirectory::create();
        let binding = b"artifact-transition-proof";

        let (wrong_context, mut wrong_artifact) =
            execution_artifact_for_fixture(statement, &witness, &wrong_setup_scratch.0, [0x55; 32]);
        assert!(matches!(
            prove_bls_dory_transition_deferred_from_execution_artifact_with_scratch(
                binding,
                statement,
                &mask,
                &mut wrong_artifact,
                wrong_context,
                BlsDoryExecutionAccumulatorTransition::Bank(0),
                10,
                &setup,
                &wrong_setup_scratch.0,
            ),
            Err(BlsDoryTransitionError::ExecutionArtifact)
        ));
        drop(wrong_artifact);
        assert_eq!(
            std::fs::read_dir(&wrong_setup_scratch.0).unwrap().count(),
            0
        );

        let materialized = prove_bls_dory_transition_deferred_at_variables_with_scratch(
            binding,
            statement,
            &mask,
            &witness,
            10,
            &setup,
            &materialized_scratch.0,
        )
        .unwrap();
        let (context, mut artifact) = execution_artifact_for_fixture(
            statement,
            &witness,
            &artifact_scratch.0,
            setup.identity(),
        );
        let mut streamed = prove_bls_dory_transition_deferred_from_execution_artifact_with_scratch(
            binding,
            statement,
            &mask,
            &mut artifact,
            context,
            BlsDoryExecutionAccumulatorTransition::Bank(0),
            10,
            &setup,
            &streamed_scratch.0,
        )
        .unwrap();

        assert_eq!(
            streamed.proof.encode_deferred(statement).unwrap(),
            materialized.proof.encode_deferred(statement).unwrap()
        );
        assert_eq!(
            streamed.proof.oracle_commitment,
            materialized.proof.oracle_commitment
        );
        assert_eq!(streamed.proof.rounds, materialized.proof.rounds);
        assert_eq!(
            streamed.proof.terminal_evaluations,
            materialized.proof.terminal_evaluations
        );
        assert_eq!(
            streamed.proof.transcript_digest,
            materialized.proof.transcript_digest
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
        let materialized_path = materialized
            .openings
            .polynomial(0)
            .unwrap()
            .coefficient_artifact_path()
            .unwrap()
            .to_path_buf();
        let streamed_path = streamed
            .openings
            .polynomial(0)
            .unwrap()
            .coefficient_artifact_path()
            .unwrap()
            .to_path_buf();
        let streamed_bytes = std::fs::read(&streamed_path).unwrap();
        assert_eq!(std::fs::read(&materialized_path).unwrap(), streamed_bytes);
        assert_eq!(std::fs::read_dir(&streamed_scratch.0).unwrap().count(), 1);
        assert_eq!(
            std::fs::read_dir(&materialized_scratch.0).unwrap().count(),
            1
        );

        let released = streamed.openings.release_compact_source().unwrap().unwrap();
        assert!(!streamed_path.exists());
        assert_eq!(std::fs::read_dir(&streamed_scratch.0).unwrap().count(), 0);
        let regenerated =
            regenerate_bls_dory_transition_compact_source_from_execution_artifact_with_scratch(
                statement,
                &mask,
                &mut artifact,
                context,
                BlsDoryExecutionAccumulatorTransition::Bank(0),
                10,
                &released,
                &setup,
                &streamed_scratch.0,
            )
            .unwrap();
        assert_eq!(std::fs::read(regenerated.path()).unwrap(), streamed_bytes);
        streamed
            .openings
            .restore_compact_source(&regenerated)
            .unwrap();
        assert_eq!(streamed.openings.claims(), materialized.openings.claims());
        drop(regenerated);
        assert_eq!(std::fs::read_dir(&streamed_scratch.0).unwrap().count(), 1);

        drop(streamed);
        drop(materialized);
        drop(artifact);
        assert_eq!(std::fs::read_dir(&streamed_scratch.0).unwrap().count(), 0);
        assert_eq!(
            std::fs::read_dir(&materialized_scratch.0).unwrap().count(),
            0
        );
        assert_eq!(std::fs::read_dir(&artifact_scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn derived_transition_regular_row_rejects_invalid_boundaries() {
        let (statement, mask, witness) = fixture();
        let negative_boundary = derive_transition_regular_row(
            statement,
            &mask,
            0,
            -(statement.max_abs_accumulator as i64),
        )
        .unwrap();
        assert_eq!(negative_boundary.shifted_accumulator, 0);
        let positive_boundary = derive_transition_regular_row(
            statement,
            &mask,
            0,
            statement.max_abs_accumulator as i64,
        )
        .unwrap();
        assert_eq!(
            positive_boundary.shifted_accumulator,
            statement.max_abs_accumulator * 2
        );

        assert_eq!(
            derive_transition_regular_row(
                statement,
                &mask,
                statement.elements().unwrap(),
                witness.accumulators[0],
            ),
            Err(BlsDoryTransitionError::Structured(
                StructuredTransitionError::InvalidDimensions
            ))
        );
        assert_eq!(
            derive_transition_regular_row(
                statement,
                &mask,
                0,
                statement.max_abs_accumulator as i64 + 1,
            ),
            Err(BlsDoryTransitionError::Structured(
                StructuredTransitionError::ValueOutOfRange
            ))
        );
        assert_eq!(
            derive_transition_regular_row(
                statement,
                &mask,
                0,
                -(statement.max_abs_accumulator as i64) - 1,
            ),
            Err(BlsDoryTransitionError::Structured(
                StructuredTransitionError::ValueOutOfRange
            ))
        );

        let wrong_mask = StructuredMaskPolynomial::from_challenge(&[0x5a; 32], 1, 2, 2).unwrap();
        assert_eq!(
            derive_transition_regular_row(statement, &wrong_mask, 0, witness.accumulators[0]),
            Err(BlsDoryTransitionError::Structured(
                StructuredTransitionError::MaskPolynomial
            ))
        );

        assert_eq!(
            BlsDoryTransitionWitnessRowSource::new_from_accumulators(
                statement,
                &mask,
                &witness.accumulators[..witness.accumulators.len() - 1],
                32,
                32,
            )
            .err(),
            Some(BlsDoryTransitionError::Structured(
                StructuredTransitionError::InvalidLength
            ))
        );
    }

    #[test]
    fn scratch_transition_sumcheck_preserves_transcript_and_cleans_artifacts() {
        let (statement, mask, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let ordinary = prove_bls_dory_transition_deferred_at_variables(
            b"scratch-transition",
            statement,
            &mask,
            &witness,
            10,
            &setup,
        )
        .unwrap();
        let scratch_directory = ScratchDirectory::create();
        let scratch = prove_bls_dory_transition_deferred_at_variables_with_scratch(
            b"scratch-transition",
            statement,
            &mask,
            &witness,
            10,
            &setup,
            &scratch_directory.0,
        )
        .unwrap();
        assert_eq!(scratch.proof, ordinary.proof);
        assert_eq!(scratch.openings.claims(), ordinary.openings.claims());
        let ordinary_polynomial = ordinary.openings.polynomial(0).unwrap();
        let scratch_polynomial = scratch.openings.polynomial(0).unwrap();
        assert_eq!(
            scratch_polynomial.row_commitments(),
            ordinary_polynomial.row_commitments()
        );
        let packed = pack_oracles(&build_scalar_oracles(statement, &witness).unwrap()).unwrap();
        let mut decoded = Vec::new();
        scratch_polynomial
            .for_each_explicit_coefficient(|_index, coefficient| decoded.push(coefficient))
            .unwrap();
        assert_eq!(decoded, packed[..decoded.len()]);
        let artifact_bytes =
            std::fs::metadata(scratch_polynomial.coefficient_artifact_path().unwrap())
                .unwrap()
                .len();
        let elements = u64::try_from(statement.elements().unwrap()).unwrap();
        let word_bytes = elements * 36;
        let code_scalars = elements
            * (STRUCTURED_TRANSITION_ORACLES - STRUCTURED_TRANSITION_REGULAR_ORACLES) as u64;
        assert_eq!(
            artifact_bytes,
            96 + 16 * 32 + word_bytes + code_scalars.div_ceil(2) + 32
        );
        let former_scalar_bytes = 100 + elements * STRUCTURED_TRANSITION_ORACLES as u64 * 32 + 32;
        assert!(artifact_bytes * 10 < former_scalar_bytes);
        drop(scratch);
        assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 0);
    }

    #[test]
    fn exact_transition_arithmetic_is_authenticated_by_one_packed_commitment() {
        let (statement, mask, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let proof = prove_bls_dory_transition(b"block-binding", statement, &mask, &witness, &setup)
            .unwrap();
        verify_bls_dory_transition(b"block-binding", statement, &mask, &proof, &setup).unwrap();
        assert_eq!(proof.rounds.len(), 3);
        assert!(
            proof
                .rounds
                .iter()
                .all(|round| round.len() == BLS_DORY_TRANSITION_SUMCHECK_DEGREE + 1)
        );
        assert_eq!(
            proof.terminal_evaluations.len(),
            BLS_DORY_TRANSITION_OPENING_CLAIMS
        );
        assert_eq!(proof.packed_variables, 10);
        assert_eq!(proof.opening_proof.len(), 21_775);
        let encoded = proof.encode(statement).unwrap();
        assert_eq!(encoded.len(), 23_171);
        let decoded = BlsDoryTransitionProof::decode(&encoded, statement).unwrap();
        assert_eq!(decoded, proof);
        verify_bls_dory_transition(b"block-binding", statement, &mask, &decoded, &setup).unwrap();
    }

    #[test]
    fn transition_statement_round_terminal_commitment_and_opening_are_bound() {
        let (statement, mask, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let proof =
            prove_bls_dory_transition(b"binding-a", statement, &mask, &witness, &setup).unwrap();
        assert!(
            verify_bls_dory_transition(b"binding-b", statement, &mask, &proof, &setup).is_err()
        );

        let mut changed = proof.clone();
        changed.rounds[0][0] = changed.rounds[0][0] + BlsDoryFr::one();
        assert!(
            verify_bls_dory_transition(b"binding-a", statement, &mask, &changed, &setup).is_err()
        );

        let mut changed = proof.clone();
        changed.terminal_evaluations[ENCODED] =
            changed.terminal_evaluations[ENCODED] + BlsDoryFr::one();
        assert!(
            verify_bls_dory_transition(b"binding-a", statement, &mask, &changed, &setup).is_err()
        );

        let mut changed = proof.clone();
        changed.oracle_commitment = changed.oracle_commitment.scale(&BlsDoryFr::from_u64(2));
        assert!(
            verify_bls_dory_transition(b"binding-a", statement, &mask, &changed, &setup).is_err()
        );

        let mut changed = proof.clone();
        changed.opening_proof[0] ^= 1;
        assert!(
            verify_bls_dory_transition(b"binding-a", statement, &mask, &changed, &setup).is_err()
        );

        let other_mask = StructuredMaskPolynomial::from_challenge(&[0xa5; 32], 2, 2, 2).unwrap();
        assert!(
            verify_bls_dory_transition(b"binding-a", statement, &other_mask, &proof, &setup)
                .is_err()
        );

        let mut invalid_witness = witness;
        invalid_witness.square_remainders[0] += 1;
        assert!(
            prove_bls_dory_transition(b"binding-a", statement, &mask, &invalid_witness, &setup,)
                .is_err()
        );
    }

    #[test]
    fn production_geometry_and_gate_remain_explicit() {
        assert_eq!(
            transition_word_width_codes(u64::from(u16::MAX)),
            PRODUCTION_TRANSITION_WORD_WIDTH_CODES
        );
        assert_eq!(
            transition_word_width_codes(u64::from(u16::MAX) + 1),
            TRANSITION_FIXED_WORD_WIDTH_CODES
        );
        assert_eq!(PRODUCTION_BLS_DORY_TRANSITION_VARIABLES, 26 + 7);
        assert_eq!(
            projected_production_transition_opening_bytes().unwrap(),
            70_639
        );
        assert_eq!(
            projected_production_transition_proof_bytes().unwrap(),
            74_979
        );
        assert_eq!(
            projected_production_transition_source_artifact_bytes().unwrap(),
            5_704_254_080
        );
        assert!(projected_production_transition_opening_bytes().unwrap() < 262_128);
        assert_eq!(BLS_DORY_TRANSITION_PRODUCTION_BLOCKERS.len(), 3);
        assert_eq!(
            require_bls_dory_transition_production_ready(),
            Err(BlsDoryTransitionError::NotProductionReady)
        );
    }

    #[test]
    fn outer_parser_rejects_shape_mutations_before_curve_decoding() {
        let (statement, mask, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let proof =
            prove_bls_dory_transition(b"parser", statement, &mask, &witness, &setup).unwrap();
        let encoded = proof.encode(statement).unwrap();

        let mut wrong_rounds = encoded.clone();
        wrong_rounds[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            BlsDoryTransitionProof::decode(&wrong_rounds, statement),
            Err(BlsDoryTransitionError::InvalidProofShape)
        );

        let mut wrong_opening = encoded.clone();
        wrong_opening[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            BlsDoryTransitionProof::decode(&wrong_opening, statement),
            Err(BlsDoryTransitionError::InvalidProofShape)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            BlsDoryTransitionProof::decode(&trailing, statement),
            Err(BlsDoryTransitionError::InvalidProofShape)
        );

        assert_eq!(
            verify_bls_dory_transition(
                &vec![0; MAX_TRANSITION_BINDING_BYTES + 1],
                statement,
                &mask,
                &proof,
                &setup,
            ),
            Err(BlsDoryTransitionError::PublicBindingTooLarge)
        );
    }
}
