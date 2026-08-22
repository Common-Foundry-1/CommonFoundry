//! BLS12-381 LogUp checkpoint for packed transition range digits.
//!
//! The 98 value/slack digit lanes already occupy selector slots in the packed
//! transition commitment. This argument commits their `0..15` table
//! multiplicities before sampling the lookup challenge, proves the logarithmic
//! derivative identity with one inverse polynomial. One randomly combined
//! selector sumcheck binds the packed value/slack reconstruction to the regular
//! source roles under the same transition commitment. The complete range
//! checkpoint uses four Dory openings.

use std::io::Cursor;
use std::path::Path;

#[cfg(test)]
use ark_ff::batch_inversion;
use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use rayon::prelude::*;
use thiserror::Error;

use crate::{
    STRUCTURED_TRANSITION_ORACLES, STRUCTURED_TRANSITION_REGULAR_ORACLES,
    StructuredTransitionError, StructuredTransitionStatement, StructuredTransitionWitness,
    dory_bls12_381_aggregate::{
        BlsDoryAggregateError, BlsDoryCommittedPolynomial, BlsDoryDeferredOpeningSet,
        BlsDoryOpeningClaim, MAX_BLS_DORY_AGGREGATE_BYTES,
        commit_bls_dory_compact_row_source_with_scratch, commit_bls_dory_mapped_compact_polynomial,
        commit_bls_dory_padded_prefix_with_optional_scratch, projected_bls_dory_aggregate_bytes,
        prove_bls_dory_deferred_opening_sets, verify_bls_dory_openings,
    },
    dory_bls12_381_fold_artifact::{
        BlsDoryFoldArtifact, BlsDoryFoldArtifactError, BlsDoryFoldArtifactSpec,
        BlsDoryFoldArtifactWriter,
    },
    dory_bls12_381_logup_artifact::{
        BlsDoryLogUpArtifact, BlsDoryLogUpArtifactError, BlsDoryLogUpArtifactSpec,
        BlsDoryLogUpArtifactValue, BlsDoryLogUpArtifactWriter,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    dory_bls12_381_transition::{
        BlsDoryTransitionError, BlsDoryTransitionWitnessRowSource, build_scalar_oracles,
        pack_oracles, projected_production_transition_source_artifact_bytes,
    },
    structured_transition::structured_transition_range_specs,
};

#[cfg(test)]
use crate::{
    dory_bls12_381_aggregate::{
        BlsDoryIndexedRowSource, commit_bls_dory_indexed_row_source_with_scratch,
        commit_bls_dory_row_source_with_scratch,
    },
    dory_bls12_381_streaming::BlsDoryRowSource,
};

/// Version of the scalar LogUp transcript and reconstruction wire grammar.
pub const BLS_DORY_RANGE_LOGUP_VERSION: u16 = 3;
/// Seven bits select the 110 used transition roles inside 128 slots.
pub const BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES: usize = 7;
/// Degree of the packed LogUp relation after equality weighting.
pub const BLS_DORY_RANGE_LOGUP_SUMCHECK_DEGREE: usize = 4;
/// Degree of the selector reconstruction sumcheck.
pub const BLS_DORY_RANGE_LOGUP_SELECTOR_SUMCHECK_DEGREE: usize = 2;
/// Cardinality of the fixed radix-16 lookup table.
pub const BLS_DORY_RANGE_LOGUP_TABLE_VALUES: usize = 16;
/// Production transition cells have 26 variables and seven selector variables.
pub const PRODUCTION_BLS_DORY_RANGE_LOGUP_VARIABLES: usize = 33;
/// Membership opens transition, multiplicity, and inverse commitments.
pub const BLS_DORY_RANGE_LOGUP_MEMBERSHIP_CLAIMS: usize = 3;
/// One random linear combination binds both source and digit reconstruction.
pub const BLS_DORY_RANGE_LOGUP_RECONSTRUCTION_CLAIMS: usize = 1;
/// Complete range checkpoint claim count.
pub const BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS: usize =
    BLS_DORY_RANGE_LOGUP_MEMBERSHIP_CLAIMS + BLS_DORY_RANGE_LOGUP_RECONSTRUCTION_CLAIMS;
/// This checkpoint is not accepted by consensus.
pub const BLS_DORY_RANGE_LOGUP_PRODUCTION_READY: bool = false;
/// Remaining gates before this can replace the direct range terminals.
pub const BLS_DORY_RANGE_LOGUP_PRODUCTION_BLOCKERS: [&str; 3] = [
    "bounded parallel work, compact transition sources, mapped inverse views, four challenge-bound compressed LogUp generations, and consuming openings preserve exact proofs and leave zero scratch after standalone completion, but n=19 still takes 9.431 seconds proving plus 7.064 seconds opening; CPU n=33 projects to roughly 1.79 plus 1.34 days and the fourth range pair still projects near 72.62 GiB peak scratch, so GPU or distributed folds, pre-fold aggregation or regeneration, and a complete measurement remain required",
    "the executable lookup bound exists, but its transcript and algebra have not received independent review",
    "the scalar range checkpoint has not received independent implementation or cryptographic review",
];

const PROOF_MAGIC: [u8; 8] = *b"CFBLSL01";
const PROOF_HEADER_BYTES: usize = 18;
const MAX_LOGUP_PROOF_BYTES: usize = 262_128;
const MAX_LOGUP_BINDING_BYTES: usize = 4_096;
const LOGUP_ROUND_DEGREE: usize = BLS_DORY_RANGE_LOGUP_SUMCHECK_DEGREE;
const LOGUP_ROUND_VALUES: usize = LOGUP_ROUND_DEGREE + 1;
const LOGUP_TERMINALS: usize = 3;
const SELECTOR_ROUNDS: usize = BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES;
const SELECTOR_ROUND_VALUES: usize = 3;
const RECONSTRUCTION_WIRE_FIELDS: usize = 1 + SELECTOR_ROUNDS * SELECTOR_ROUND_VALUES + 1;
const TABLE_VALUES: usize = BLS_DORY_RANGE_LOGUP_TABLE_VALUES;
const SELECTOR_SLOTS: usize = 1 << BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES;
const LOGUP_FOLD_SLOTS: usize = 2;
const LOGUP_PARALLEL_FOLD_CHUNK_VALUES: usize = 1 << 16;
const LOGUP_COMPRESSED_GENERATIONS: usize = 4;

/// Witness-free scalar range-membership proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryRangeLogUpProof {
    pub protocol_version: u16,
    pub packed_variables: u16,
    pub transition_commitment: BlsDoryGt,
    pub multiplicity_commitment: BlsDoryGt,
    pub inverse_commitment: BlsDoryGt,
    pub rounds: Vec<[BlsDoryFr; LOGUP_ROUND_VALUES]>,
    pub terminal_evaluations: [BlsDoryFr; LOGUP_TERMINALS],
    pub source_claim: BlsDoryFr,
    pub reconstruction_rounds: Vec<[BlsDoryFr; SELECTOR_ROUND_VALUES]>,
    pub reconstruction_evaluation: BlsDoryFr,
    pub transcript_digest: [u8; 32],
    pub opening_proof: Vec<u8>,
}

pub(crate) struct PreparedBlsDoryRangeLogUpProof {
    pub(crate) proof: BlsDoryRangeLogUpProof,
    pub(crate) openings: BlsDoryDeferredOpeningSet,
}

impl BlsDoryRangeLogUpProof {
    /// Encode the statement-derived proof shape canonically.
    pub fn encode(
        &self,
        statement: StructuredTransitionStatement,
    ) -> Result<Vec<u8>, BlsDoryRangeLogUpError> {
        self.encode_with_opening(statement, true)
    }

    pub(crate) fn encode_deferred(
        &self,
        statement: StructuredTransitionStatement,
    ) -> Result<Vec<u8>, BlsDoryRangeLogUpError> {
        self.encode_with_opening(statement, false)
    }

    fn encode_with_opening(
        &self,
        statement: StructuredTransitionStatement,
        require_opening: bool,
    ) -> Result<Vec<u8>, BlsDoryRangeLogUpError> {
        validate_proof_shape_with_opening(
            statement,
            self,
            usize::from(self.packed_variables),
            require_opening,
        )?;
        if !require_opening && !self.opening_proof.is_empty() {
            return Err(BlsDoryRangeLogUpError::InvalidProofShape);
        }
        let opening_len = u32::try_from(self.opening_proof.len())
            .map_err(|_| BlsDoryRangeLogUpError::ProofTooLarge)?;
        let expected = logup_wire_bytes(self.rounds.len(), self.opening_proof.len())?;
        let mut encoded = Vec::with_capacity(expected);
        encoded.extend_from_slice(&PROOF_MAGIC);
        encoded.extend_from_slice(&self.protocol_version.to_le_bytes());
        encoded.extend_from_slice(&self.packed_variables.to_le_bytes());
        encoded.extend_from_slice(&(self.rounds.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&opening_len.to_le_bytes());
        for commitment in [
            &self.transition_commitment,
            &self.multiplicity_commitment,
            &self.inverse_commitment,
        ] {
            append_serialized(&mut encoded, commitment)?;
        }
        for round in &self.rounds {
            for evaluation in round {
                append_serialized(&mut encoded, evaluation)?;
            }
        }
        for evaluation in &self.terminal_evaluations {
            append_serialized(&mut encoded, evaluation)?;
        }
        append_serialized(&mut encoded, &self.source_claim)?;
        for round in &self.reconstruction_rounds {
            for evaluation in round {
                append_serialized(&mut encoded, evaluation)?;
            }
        }
        append_serialized(&mut encoded, &self.reconstruction_evaluation)?;
        encoded.extend_from_slice(&self.transcript_digest);
        encoded.extend_from_slice(&self.opening_proof);
        if encoded.len() != expected || encoded.len() > MAX_LOGUP_PROOF_BYTES {
            return Err(BlsDoryRangeLogUpError::ProofTooLarge);
        }
        Ok(encoded)
    }

    /// Decode only the minimum bounded geometry implied by the statement.
    pub fn decode(
        encoded: &[u8],
        statement: StructuredTransitionStatement,
    ) -> Result<Self, BlsDoryRangeLogUpError> {
        let expected_variables = minimum_packed_variables(statement)?;
        Self::decode_with_variables(encoded, statement, expected_variables)
    }

    /// Decode using the exact shared aggregate geometry selected by consensus.
    pub fn decode_with_variables(
        encoded: &[u8],
        statement: StructuredTransitionStatement,
        expected_variables: usize,
    ) -> Result<Self, BlsDoryRangeLogUpError> {
        Self::decode_with_variables_and_opening(encoded, statement, expected_variables, true)
    }

    pub(crate) fn decode_deferred_with_variables(
        encoded: &[u8],
        statement: StructuredTransitionStatement,
        expected_variables: usize,
    ) -> Result<Self, BlsDoryRangeLogUpError> {
        Self::decode_with_variables_and_opening(encoded, statement, expected_variables, false)
    }

    fn decode_with_variables_and_opening(
        encoded: &[u8],
        statement: StructuredTransitionStatement,
        expected_variables: usize,
        require_opening: bool,
    ) -> Result<Self, BlsDoryRangeLogUpError> {
        statement.validate_verifier_shape()?;
        validate_target_variables(minimum_packed_variables(statement)?, expected_variables)?;
        if encoded.len() < PROOF_HEADER_BYTES || encoded.len() > MAX_LOGUP_PROOF_BYTES {
            return Err(BlsDoryRangeLogUpError::ProofTooLarge);
        }
        if encoded[..8] != PROOF_MAGIC {
            return Err(BlsDoryRangeLogUpError::InvalidEncoding);
        }
        let protocol_version = read_u16(encoded, 8)?;
        let packed_variables = read_u16(encoded, 10)?;
        let round_count = read_u16(encoded, 12)? as usize;
        let opening_len = read_u32(encoded, 14)? as usize;
        if protocol_version != BLS_DORY_RANGE_LOGUP_VERSION
            || usize::from(packed_variables) != expected_variables
            || round_count != expected_variables
            || (require_opening && opening_len == 0)
            || (!require_opening && opening_len != 0)
            || opening_len > MAX_BLS_DORY_AGGREGATE_BYTES
            || encoded.len() != logup_wire_bytes(round_count, opening_len)?
        {
            return Err(BlsDoryRangeLogUpError::InvalidProofShape);
        }

        let mut reader = Cursor::new(&encoded[PROOF_HEADER_BYTES..]);
        let transition_commitment = read_serialized(&mut reader)?;
        let multiplicity_commitment = read_serialized(&mut reader)?;
        let inverse_commitment = read_serialized(&mut reader)?;
        let mut rounds = Vec::with_capacity(round_count);
        for _ in 0..round_count {
            rounds.push(read_field_array(&mut reader)?);
        }
        let terminal_evaluations = read_field_array(&mut reader)?;
        let source_claim = read_serialized(&mut reader)?;
        let mut reconstruction_rounds = Vec::with_capacity(SELECTOR_ROUNDS);
        for _ in 0..SELECTOR_ROUNDS {
            reconstruction_rounds.push(read_field_array(&mut reader)?);
        }
        let reconstruction_evaluation = read_serialized(&mut reader)?;
        let payload_offset = PROOF_HEADER_BYTES + reader.position() as usize;
        let digest_end = payload_offset
            .checked_add(32)
            .ok_or(BlsDoryRangeLogUpError::InvalidProofShape)?;
        let transcript_digest = encoded
            .get(payload_offset..digest_end)
            .ok_or(BlsDoryRangeLogUpError::InvalidProofShape)?
            .try_into()
            .map_err(|_| BlsDoryRangeLogUpError::InvalidProofShape)?;
        let opening_proof = encoded
            .get(digest_end..)
            .ok_or(BlsDoryRangeLogUpError::InvalidProofShape)?
            .to_vec();
        if opening_proof.len() != opening_len {
            return Err(BlsDoryRangeLogUpError::InvalidProofShape);
        }
        let proof = Self {
            protocol_version,
            packed_variables,
            transition_commitment,
            multiplicity_commitment,
            inverse_commitment,
            rounds,
            terminal_evaluations,
            source_claim,
            reconstruction_rounds,
            reconstruction_evaluation,
            transcript_digest,
            opening_proof,
        };
        if proof.encode_with_opening(statement, require_opening)? != encoded {
            return Err(BlsDoryRangeLogUpError::InvalidEncoding);
        }
        Ok(proof)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDoryRangeLogUpError {
    #[error("structured transition input is invalid: {0}")]
    Structured(#[from] StructuredTransitionError),
    #[error("scalar transition witness conversion failed: {0}")]
    Transition(#[from] BlsDoryTransitionError),
    #[error("Dory opening authentication failed: {0}")]
    Aggregate(#[from] BlsDoryAggregateError),
    #[error("packed range dimensions overflow or exceed this checkpoint")]
    InvalidDimensions,
    #[error("range LogUp proof has the wrong fixed shape")]
    InvalidProofShape,
    #[error("a Fiat-Shamir lookup denominator is zero")]
    ChallengeCollision,
    #[error("range LogUp sumcheck does not preserve its claim")]
    RoundClaim,
    #[error("range LogUp terminal relation is invalid")]
    TerminalClaim,
    #[error("range LogUp transcript digest mismatch")]
    Transcript,
    #[error("Dory claims do not match the range LogUp evaluations")]
    Opening,
    #[error("range LogUp public binding exceeds the bounded transcript limit")]
    PublicBindingTooLarge,
    #[error("range LogUp proof exceeds the network payload cap")]
    ProofTooLarge,
    #[error("range LogUp proof encoding is malformed or non-canonical")]
    InvalidEncoding,
    #[error("the BLS12-381 range LogUp checkpoint is not production ready")]
    NotProductionReady,
}

/// Fail closed while the range checkpoint is not integrated and audited.
pub fn require_bls_dory_range_logup_production_ready() -> Result<(), BlsDoryRangeLogUpError> {
    Err(BlsDoryRangeLogUpError::NotProductionReady)
}

/// Project the one shared Dory opening payload at production geometry.
pub fn projected_production_range_logup_opening_bytes() -> Result<usize, BlsDoryRangeLogUpError> {
    projected_bls_dory_aggregate_bytes(PRODUCTION_BLS_DORY_RANGE_LOGUP_VARIABLES)
        .map_err(BlsDoryRangeLogUpError::Aggregate)
}

/// Project the complete scalar range-checkpoint proof at production geometry.
pub fn projected_production_range_logup_proof_bytes() -> Result<usize, BlsDoryRangeLogUpError> {
    logup_wire_bytes(
        PRODUCTION_BLS_DORY_RANGE_LOGUP_VARIABLES,
        projected_production_range_logup_opening_bytes()?,
    )
}

/// Extra retained coefficient-file bytes for the mapped production inverse.
/// The inverse reuses the authenticated transition artifact and adds no file.
pub fn projected_production_range_logup_inverse_artifact_bytes()
-> Result<u64, BlsDoryRangeLogUpError> {
    Ok(0)
}

/// Exact retained transition plus inverse bytes for one production pair.
pub fn projected_production_transition_range_source_bytes() -> Result<u64, BlsDoryRangeLogUpError> {
    projected_production_transition_source_artifact_bytes()?
        .checked_add(projected_production_range_logup_inverse_artifact_bytes()?)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)
}

/// Exact encoded bytes for the four compressed production LogUp lineages.
pub fn projected_production_range_logup_compressed_lineage_bytes()
-> Result<[u64; LOGUP_COMPRESSED_GENERATIONS], BlsDoryRangeLogUpError> {
    let cell_variables = PRODUCTION_BLS_DORY_RANGE_LOGUP_VARIABLES
        .checked_sub(BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let selector_rows = 1u64
        .checked_shl(BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut output = [0u64; LOGUP_COMPRESSED_GENERATIONS];
    for generation in 1..=LOGUP_COMPRESSED_GENERATIONS {
        let current_cells = 1u64
            .checked_shl(
                u32::try_from(cell_variables - generation)
                    .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
            )
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        output[generation - 1] = BlsDoryLogUpArtifactSpec {
            context_digest: [1; 32],
            parent_digest: [2; 32],
            reconstruction_digest: [3; 32],
            generation: u32::try_from(generation)
                .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
            selector_rows,
            current_cells,
            regular_selectors: STRUCTURED_TRANSITION_REGULAR_ORACLES as u32,
            range_selectors: (STRUCTURED_TRANSITION_ORACLES - STRUCTURED_TRANSITION_REGULAR_ORACLES)
                as u32,
        }
        .encoded_bytes()
        .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?;
    }
    Ok(output)
}

/// Peak overlap across compressed lineages and the first scalar fold.
pub fn projected_production_range_logup_early_lineage_peak_bytes()
-> Result<u64, BlsDoryRangeLogUpError> {
    let compressed = projected_production_range_logup_compressed_lineage_bytes()?;
    let selector_rows = 1usize
        .checked_shl(BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let cell_variables = PRODUCTION_BLS_DORY_RANGE_LOGUP_VARIABLES
        .checked_sub(BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let generation = LOGUP_COMPRESSED_GENERATIONS + 1;
    let current_cells = 1usize
        .checked_shl(
            u32::try_from(cell_variables - generation)
                .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        )
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let scalar_generation =
        logup_fold_spec([1; 32], generation, selector_rows, current_cells, [2; 32])?
            .encoded_bytes()
            .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut peak = 0u64;
    for pair in compressed.windows(2) {
        peak = peak.max(
            pair[0]
                .checked_add(pair[1])
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
        );
    }
    Ok(peak.max(
        compressed[LOGUP_COMPRESSED_GENERATIONS - 1]
            .checked_add(scalar_generation)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
    ))
}

/// Four retained transition/inverse pairs plus the fourth pair's lineage peak.
pub fn projected_production_range_logup_four_pair_peak_bytes() -> Result<u64, BlsDoryRangeLogUpError>
{
    let sources = projected_production_transition_range_source_bytes()?
        .checked_mul(4)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    sources
        .checked_add(projected_production_range_logup_early_lineage_peak_bytes()?)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)
}

pub fn prove_bls_dory_range_logup(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    witness: &StructuredTransitionWitness,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    let packed_variables = minimum_packed_variables(statement)?;
    prove_bls_dory_range_logup_at_variables(binding, statement, witness, packed_variables, setup)
}

pub fn prove_bls_dory_range_logup_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    let oracles = build_scalar_oracles(statement, witness)?;
    prove_from_oracles(binding, statement, &oracles, packed_variables, setup)
}

pub(crate) fn prove_bls_dory_range_logup_deferred_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    let oracles = build_scalar_oracles(statement, witness)?;
    prove_from_source_deferred(
        binding,
        statement,
        LogUpProverSource::Materialized(&oracles),
        packed_variables,
        setup,
        None,
        None,
    )
}

#[cfg(test)]
pub(crate) fn prove_bls_dory_range_logup_deferred_at_variables_with_scratch(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    prove_from_source_deferred(
        binding,
        statement,
        LogUpProverSource::Witness(witness),
        packed_variables,
        setup,
        Some(scratch_directory),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_range_logup_deferred_with_precommitted_transition_and_scratch(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    witness: &StructuredTransitionWitness,
    transition: &BlsDoryCommittedPolynomial,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    prove_from_source_deferred(
        binding,
        statement,
        LogUpProverSource::Witness(witness),
        packed_variables,
        setup,
        Some(scratch_directory),
        Some(transition),
    )
}

fn prove_from_oracles(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    oracles: &[Vec<BlsDoryFr>],
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    let mut prepared =
        prove_from_oracles_deferred(binding, statement, oracles, packed_variables, setup)?;
    let opening_binding = opening_binding(binding, &prepared.proof.transcript_digest);
    let (claims, opening_proof) =
        prove_bls_dory_deferred_opening_sets(&opening_binding, &[&prepared.openings], setup)?;
    if claims != prepared.openings.claims() {
        return Err(BlsDoryRangeLogUpError::Opening);
    }
    prepared.proof.opening_proof = opening_proof;
    verify_bls_dory_range_logup_at_variables(
        binding,
        statement,
        prepared.proof.transition_commitment,
        &prepared.proof,
        packed_variables,
        setup,
    )?;
    Ok(prepared.proof)
}

fn prove_from_oracles_deferred(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    oracles: &[Vec<BlsDoryFr>],
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    prove_from_source_deferred(
        binding,
        statement,
        LogUpProverSource::Materialized(oracles),
        packed_variables,
        setup,
        None,
        None,
    )
}

#[derive(Clone, Copy)]
enum LogUpProverSource<'a> {
    Materialized(&'a [Vec<BlsDoryFr>]),
    Witness(&'a StructuredTransitionWitness),
}

fn prove_from_source_deferred(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    source: LogUpProverSource<'_>,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
    precommitted_transition: Option<&BlsDoryCommittedPolynomial>,
) -> Result<PreparedBlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    if binding.len() > MAX_LOGUP_BINDING_BYTES {
        return Err(BlsDoryRangeLogUpError::PublicBindingTooLarge);
    }
    statement.validate_verifier_shape()?;
    let elements = statement.elements()?;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    if matches!(source, LogUpProverSource::Witness(_)) != scratch_directory.is_some()
        || (precommitted_transition.is_some()
            && (!matches!(source, LogUpProverSource::Witness(_)) || scratch_directory.is_none()))
    {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let padded_len = 1usize
        .checked_shl(packed_variables as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let (nu, sigma) = dory_layout(packed_variables);
    let rows = 1usize
        .checked_shl(nu as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let columns = 1usize
        .checked_shl(sigma as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut witness_source = match source {
        LogUpProverSource::Materialized(_) => None,
        LogUpProverSource::Witness(witness) => Some(BlsDoryTransitionWitnessRowSource::new(
            statement, witness, rows, columns,
        )?),
    };
    let mut transition_coefficients = match source {
        LogUpProverSource::Materialized(oracles) => Some(pack_oracles(oracles)?),
        LogUpProverSource::Witness(_) => None,
    };
    let transition = if let Some(transition) = precommitted_transition {
        let explicit_scalars = elements
            .checked_mul(STRUCTURED_TRANSITION_ORACLES)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        if !transition.matches_layout(packed_variables, setup)
            || transition.explicit_coefficient_count() != explicit_scalars
        {
            return Err(BlsDoryRangeLogUpError::InvalidDimensions);
        }
        transition.clone()
    } else if let Some(scratch_directory) = scratch_directory {
        commit_bls_dory_compact_row_source_with_scratch(
            witness_source
                .as_mut()
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
            nu,
            sigma,
            setup,
            scratch_directory,
        )?
    } else {
        commit_bls_dory_padded_prefix_with_optional_scratch(
            transition_coefficients
                .as_ref()
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
            nu,
            sigma,
            setup,
            None,
        )?
    };
    if let Some(coefficients) = transition_coefficients.as_mut() {
        coefficients.resize(padded_len, BlsDoryFr::zero());
    }

    let mut counts = [0_u64; TABLE_VALUES];
    match source {
        LogUpProverSource::Materialized(oracles) => {
            for oracle in &oracles[STRUCTURED_TRANSITION_REGULAR_ORACLES..] {
                for value in oracle {
                    if let Some(digit) =
                        (0..TABLE_VALUES).find(|digit| *value == BlsDoryFr::from_u64(*digit as u64))
                    {
                        counts[digit] = counts[digit]
                            .checked_add(1)
                            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
                    }
                }
            }
        }
        LogUpProverSource::Witness(_) => {
            let witness_source = witness_source
                .as_ref()
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
            for oracle in STRUCTURED_TRANSITION_REGULAR_ORACLES..STRUCTURED_TRANSITION_ORACLES {
                for index in 0..elements {
                    let digit = usize::from(witness_source.range_digit(oracle, index)?);
                    counts[digit] = counts[digit]
                        .checked_add(1)
                        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
                }
            }
        }
    }
    let mut multiplicity_coefficients = counts
        .into_iter()
        .map(BlsDoryFr::from_u64)
        .collect::<Vec<_>>();
    let multiplicity = commit_bls_dory_padded_prefix_with_optional_scratch(
        &multiplicity_coefficients,
        nu,
        sigma,
        setup,
        scratch_directory,
    )?;
    if matches!(source, LogUpProverSource::Materialized(_)) {
        multiplicity_coefficients.resize(padded_len, BlsDoryFr::zero());
    }

    let mut transcript = logup_transcript(
        binding,
        statement,
        packed_variables,
        &setup.identity(),
        &transition.commitment(),
        &multiplicity.commitment(),
    );
    let alpha = transcript.challenge_scalar(b"lookup-alpha");
    let (active, table, table_inverse, inverse_coefficients) =
        if let Some(transition_coefficients) = transition_coefficients.as_ref() {
            let active = query_active_table(elements, padded_len)?;
            let table = table_active_table(padded_len)?;
            let table_inverse = table_inverse_table(alpha, padded_len)?;
            let mut inverse_coefficients = vec![BlsDoryFr::zero(); padded_len];
            for index in 0..padded_len {
                if active[index] == BlsDoryFr::one() {
                    inverse_coefficients[index] = (alpha - transition_coefficients[index])
                        .inv()
                        .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)?;
                }
            }
            (
                Some(active),
                Some(table),
                Some(table_inverse),
                Some(inverse_coefficients),
            )
        } else {
            (None, None, None, None)
        };
    let inverse = if scratch_directory.is_some() {
        let mapped_dictionary = (0..TABLE_VALUES)
            .map(|digit| {
                (alpha - BlsDoryFr::from_u64(digit as u64))
                    .inv()
                    .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let zero_prefix_count = elements
            .checked_mul(STRUCTURED_TRANSITION_REGULAR_ORACLES)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        commit_bls_dory_mapped_compact_polynomial(
            &transition,
            zero_prefix_count,
            mapped_dictionary,
            setup,
        )?
    } else {
        let transition_explicit_len = elements
            .checked_mul(STRUCTURED_TRANSITION_ORACLES)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        commit_bls_dory_padded_prefix_with_optional_scratch(
            &inverse_coefficients
                .as_ref()
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?[..transition_explicit_len],
            nu,
            sigma,
            setup,
            None,
        )?
    };
    transcript.append_group(b"inverse-commitment", &inverse.commitment());
    let local_mixing = challenge_vector(&mut transcript, b"local-mixing", 3);
    let rational_mixing = transcript.challenge_scalar(b"rational-mixing");
    let count_mixing = transcript.challenge_scalar(b"count-mixing");
    let equality_point = challenge_vector(&mut transcript, b"equality-point", packed_variables);
    let (rounds, sumcheck_point, terminal_evaluations, terminal, claim) = match source {
        LogUpProverSource::Witness(_) => {
            let witness_source = witness_source
                .as_ref()
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
            let output = if elements >= TABLE_VALUES {
                prove_logup_sumcheck_with_artifacts(
                    witness_source,
                    &counts,
                    alpha,
                    elements,
                    packed_variables,
                    &equality_point,
                    &local_mixing,
                    rational_mixing,
                    count_mixing,
                    &mut transcript,
                    scratch_directory.ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                )?
            } else {
                prove_logup_sumcheck_with_recomputation(
                    witness_source,
                    &counts,
                    alpha,
                    elements,
                    packed_variables,
                    &equality_point,
                    &local_mixing,
                    rational_mixing,
                    count_mixing,
                    &mut transcript,
                )?
            };
            (
                output.rounds,
                output.point,
                output.terminal_evaluations,
                output.terminal,
                output.final_claim,
            )
        }
        LogUpProverSource::Materialized(_) => {
            let mut tables = LogUpTables {
                transition: transition_coefficients
                    .take()
                    .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                multiplicity: multiplicity_coefficients,
                inverse: inverse_coefficients.ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                active: active.ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                table: table.ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                table_inverse: table_inverse.ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                equality: equality_table(&equality_point),
            };
            let mut claim = BlsDoryFr::zero();
            let mut rounds = Vec::with_capacity(packed_variables);
            let mut sumcheck_point = Vec::with_capacity(packed_variables);
            for round_index in 0..packed_variables {
                let evaluations =
                    logup_round(&tables, alpha, &local_mixing, rational_mixing, count_mixing)?;
                if evaluations[0] + evaluations[1] != claim {
                    return Err(BlsDoryRangeLogUpError::RoundClaim);
                }
                absorb_round(&mut transcript, round_index, &evaluations);
                let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
                claim = evaluate_samples(&evaluations, challenge)?;
                sumcheck_point.push(challenge);
                tables.fold(challenge)?;
                rounds.push(evaluations);
            }
            let terminal_evaluations = [
                tables.transition[0],
                tables.multiplicity[0],
                tables.inverse[0],
            ];
            (
                rounds,
                sumcheck_point,
                terminal_evaluations,
                TerminalValues {
                    transition: terminal_evaluations[0],
                    multiplicity: terminal_evaluations[1],
                    inverse: terminal_evaluations[2],
                    active: tables.active[0],
                    table: tables.table[0],
                    table_inverse: tables.table_inverse[0],
                    equality: tables.equality[0],
                },
                claim,
            )
        }
    };
    let expected = logup_constraint(
        terminal,
        alpha,
        &local_mixing,
        rational_mixing,
        count_mixing,
    );
    if claim != expected {
        return Err(BlsDoryRangeLogUpError::TerminalClaim);
    }
    absorb_fields(
        &mut transcript,
        b"terminal-evaluation",
        &terminal_evaluations,
    );

    let cell_variables = elements.ilog2() as usize;
    let cell_point = challenge_vector(
        &mut transcript,
        b"reconstruction-cell-point",
        cell_variables,
    );
    let spec_point = challenge_vector(&mut transcript, b"reconstruction-spec-point", 3);
    let slack_mixing = transcript.challenge_scalar(b"reconstruction-slack-mixing");
    let reconstruction = match source {
        LogUpProverSource::Materialized(oracles) => {
            reconstruction_tables(statement, oracles, &cell_point, &spec_point, slack_mixing)?
        }
        LogUpProverSource::Witness(_) => reconstruction_tables_from_witness(
            statement,
            witness_source
                .as_ref()
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
            &cell_point,
            &spec_point,
            slack_mixing,
        )?,
    };
    let source_claim = inner_product(&reconstruction.source_weights, &reconstruction.role_values)?;
    transcript.append_field(b"source-claim", &source_claim);
    let digit_claim = (BlsDoryFr::one() - slack_mixing) * source_claim
        + slack_mixing * reconstruction.maximum_evaluation;
    transcript.append_field(b"digit-claim", &digit_claim);
    let reconstruction_mixing = transcript.challenge_scalar(b"reconstruction-mixing");
    let combined_claim = source_claim + reconstruction_mixing * digit_claim;
    let combined_weights = combine_weights(
        &reconstruction.source_weights,
        &reconstruction.digit_weights,
        reconstruction_mixing,
    )?;
    let reconstruction = prove_selector_sumcheck(
        combined_claim,
        combined_weights,
        reconstruction.role_values,
        &mut transcript,
        b"reconstruction",
    )?;
    transcript.append_field(b"reconstruction-evaluation", &reconstruction.evaluation);

    let transcript_digest = transcript.digest();
    let reconstruction_point =
        reconstruction_opening_point(&cell_point, &reconstruction.point, packed_variables)?;
    let points = vec![
        sumcheck_point.clone(),
        sumcheck_point.clone(),
        sumcheck_point,
        reconstruction_point,
    ];
    let expected_commitments = [
        transition.commitment(),
        multiplicity.commitment(),
        inverse.commitment(),
        transition.commitment(),
    ];
    let openings = BlsDoryDeferredOpeningSet::new(
        vec![transition, multiplicity, inverse],
        vec![0, 1, 2, 0],
        points,
    )?;
    let commitments = openings
        .claims()
        .iter()
        .map(|claim| claim.commitment)
        .collect::<Vec<_>>();
    if commitments.as_slice() != expected_commitments
        || openings
            .claims()
            .iter()
            .zip([
                terminal_evaluations[0],
                terminal_evaluations[1],
                terminal_evaluations[2],
                reconstruction.evaluation,
            ])
            .any(|(claim, evaluation)| claim.evaluation != evaluation)
    {
        return Err(BlsDoryRangeLogUpError::Opening);
    }

    let proof = BlsDoryRangeLogUpProof {
        protocol_version: BLS_DORY_RANGE_LOGUP_VERSION,
        packed_variables: u16::try_from(packed_variables)
            .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        transition_commitment: expected_commitments[0],
        multiplicity_commitment: expected_commitments[1],
        inverse_commitment: expected_commitments[2],
        rounds,
        terminal_evaluations,
        source_claim,
        reconstruction_rounds: reconstruction.rounds,
        reconstruction_evaluation: reconstruction.evaluation,
        transcript_digest,
        opening_proof: Vec::new(),
    };
    verify_bls_dory_range_logup_deferred_at_variables(
        binding,
        statement,
        proof.transition_commitment,
        &proof,
        packed_variables,
        setup,
    )?;
    Ok(PreparedBlsDoryRangeLogUpProof { proof, openings })
}

pub fn verify_bls_dory_range_logup(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    expected_transition_commitment: BlsDoryGt,
    proof: &BlsDoryRangeLogUpProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryRangeLogUpError> {
    let packed_variables = minimum_packed_variables(statement)?;
    verify_bls_dory_range_logup_at_variables(
        binding,
        statement,
        expected_transition_commitment,
        proof,
        packed_variables,
        setup,
    )
}

pub fn verify_bls_dory_range_logup_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    expected_transition_commitment: BlsDoryGt,
    proof: &BlsDoryRangeLogUpProof,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryRangeLogUpError> {
    let claims = verify_bls_dory_range_logup_deferred_at_variables(
        binding,
        statement,
        expected_transition_commitment,
        proof,
        packed_variables,
        setup,
    )?;
    let opening_binding = opening_binding(binding, &proof.transcript_digest);
    verify_bls_dory_openings(&opening_binding, &claims, &proof.opening_proof, setup)?;
    Ok(())
}

pub(crate) fn verify_bls_dory_range_logup_deferred_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    expected_transition_commitment: BlsDoryGt,
    proof: &BlsDoryRangeLogUpProof,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<Vec<BlsDoryOpeningClaim>, BlsDoryRangeLogUpError> {
    if binding.len() > MAX_LOGUP_BINDING_BYTES {
        return Err(BlsDoryRangeLogUpError::PublicBindingTooLarge);
    }
    statement.validate_verifier_shape()?;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    validate_deferred_proof_shape(statement, proof, packed_variables)?;
    if packed_variables > setup.max_log_n()
        || proof.transition_commitment != expected_transition_commitment
    {
        return Err(BlsDoryRangeLogUpError::InvalidProofShape);
    }
    let mut transcript = logup_transcript(
        binding,
        statement,
        packed_variables,
        &setup.identity(),
        &proof.transition_commitment,
        &proof.multiplicity_commitment,
    );
    let alpha = transcript.challenge_scalar(b"lookup-alpha");
    transcript.append_group(b"inverse-commitment", &proof.inverse_commitment);
    let local_mixing = challenge_vector(&mut transcript, b"local-mixing", 3);
    let rational_mixing = transcript.challenge_scalar(b"rational-mixing");
    let count_mixing = transcript.challenge_scalar(b"count-mixing");
    let equality_point = challenge_vector(&mut transcript, b"equality-point", packed_variables);

    let mut claim = BlsDoryFr::zero();
    let mut sumcheck_point = Vec::with_capacity(packed_variables);
    for (round_index, evaluations) in proof.rounds.iter().enumerate() {
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryRangeLogUpError::RoundClaim);
        }
        absorb_round(&mut transcript, round_index, evaluations);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = evaluate_samples(evaluations, challenge)?;
        sumcheck_point.push(challenge);
    }
    let elements = statement.elements()?;
    let active = query_active_evaluation(elements, &sumcheck_point)?;
    let table = table_active_evaluation(&sumcheck_point)?;
    let table_inverse = table_inverse_evaluation(alpha, &sumcheck_point)?;
    let expected = logup_constraint(
        TerminalValues {
            transition: proof.terminal_evaluations[0],
            multiplicity: proof.terminal_evaluations[1],
            inverse: proof.terminal_evaluations[2],
            active,
            table,
            table_inverse,
            equality: equality_evaluation(&equality_point, &sumcheck_point)?,
        },
        alpha,
        &local_mixing,
        rational_mixing,
        count_mixing,
    );
    if claim != expected {
        return Err(BlsDoryRangeLogUpError::TerminalClaim);
    }
    absorb_fields(
        &mut transcript,
        b"terminal-evaluation",
        &proof.terminal_evaluations,
    );

    let cell_variables = elements.ilog2() as usize;
    let cell_point = challenge_vector(
        &mut transcript,
        b"reconstruction-cell-point",
        cell_variables,
    );
    let spec_point = challenge_vector(&mut transcript, b"reconstruction-spec-point", 3);
    let slack_mixing = transcript.challenge_scalar(b"reconstruction-slack-mixing");
    let weights = reconstruction_weights(statement, &spec_point, slack_mixing)?;
    transcript.append_field(b"source-claim", &proof.source_claim);
    let digit_claim = (BlsDoryFr::one() - slack_mixing) * proof.source_claim
        + slack_mixing * weights.maximum_evaluation;
    transcript.append_field(b"digit-claim", &digit_claim);
    let reconstruction_mixing = transcript.challenge_scalar(b"reconstruction-mixing");
    let combined_claim = proof.source_claim + reconstruction_mixing * digit_claim;
    let combined_weights = combine_weights(
        &weights.source_weights,
        &weights.digit_weights,
        reconstruction_mixing,
    )?;
    let reconstruction_point = verify_selector_sumcheck(
        combined_claim,
        &combined_weights,
        &proof.reconstruction_rounds,
        proof.reconstruction_evaluation,
        &mut transcript,
        b"reconstruction",
    )?;
    transcript.append_field(
        b"reconstruction-evaluation",
        &proof.reconstruction_evaluation,
    );

    if transcript.digest() != proof.transcript_digest {
        return Err(BlsDoryRangeLogUpError::Transcript);
    }
    let reconstruction_opening =
        reconstruction_opening_point(&cell_point, &reconstruction_point, packed_variables)?;
    let claims = vec![
        BlsDoryOpeningClaim {
            commitment: proof.transition_commitment,
            point: sumcheck_point.clone(),
            evaluation: proof.terminal_evaluations[0],
        },
        BlsDoryOpeningClaim {
            commitment: proof.multiplicity_commitment,
            point: sumcheck_point.clone(),
            evaluation: proof.terminal_evaluations[1],
        },
        BlsDoryOpeningClaim {
            commitment: proof.inverse_commitment,
            point: sumcheck_point,
            evaluation: proof.terminal_evaluations[2],
        },
        BlsDoryOpeningClaim {
            commitment: proof.transition_commitment,
            point: reconstruction_opening,
            evaluation: proof.reconstruction_evaluation,
        },
    ];
    Ok(claims)
}

fn validate_deferred_proof_shape(
    statement: StructuredTransitionStatement,
    proof: &BlsDoryRangeLogUpProof,
    expected_variables: usize,
) -> Result<(), BlsDoryRangeLogUpError> {
    validate_proof_shape_with_opening(statement, proof, expected_variables, false)
}

fn validate_proof_shape_with_opening(
    statement: StructuredTransitionStatement,
    proof: &BlsDoryRangeLogUpProof,
    expected_variables: usize,
    require_opening: bool,
) -> Result<(), BlsDoryRangeLogUpError> {
    statement.validate_verifier_shape()?;
    validate_target_variables(minimum_packed_variables(statement)?, expected_variables)?;
    if proof.protocol_version != BLS_DORY_RANGE_LOGUP_VERSION
        || usize::from(proof.packed_variables) != expected_variables
        || proof.rounds.len() != expected_variables
        || proof.reconstruction_rounds.len() != SELECTOR_ROUNDS
        || (require_opening && proof.opening_proof.is_empty())
        || proof.opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
    {
        return Err(BlsDoryRangeLogUpError::InvalidProofShape);
    }
    Ok(())
}

fn minimum_packed_variables(
    statement: StructuredTransitionStatement,
) -> Result<usize, BlsDoryRangeLogUpError> {
    statement.validate_verifier_shape()?;
    (statement.elements()?.ilog2() as usize)
        .checked_add(BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)
}

fn validate_target_variables(minimum: usize, target: usize) -> Result<(), BlsDoryRangeLogUpError> {
    if target < minimum || !(4..=64).contains(&target) {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(())
}

fn dory_layout(variables: usize) -> (usize, usize) {
    let nu = variables / 2;
    (nu, variables - nu)
}

#[cfg(test)]
struct LogUpInverseRowSource<'a, 'w> {
    transition: &'a BlsDoryTransitionWitnessRowSource<'w>,
    alpha: BlsDoryFr,
    elements: usize,
    rows: usize,
    columns: usize,
    explicit_scalars: usize,
    active_columns: Vec<usize>,
    denominators: Vec<BlsDoryFr>,
}

#[cfg(test)]
struct LogUpInverseCodeRowSource<'a, 'w> {
    transition: &'a BlsDoryTransitionWitnessRowSource<'w>,
    elements: usize,
    rows: usize,
    columns: usize,
    explicit_scalars: usize,
    dictionary: Vec<BlsDoryFr>,
}

#[cfg(test)]
impl<'a, 'w> LogUpInverseCodeRowSource<'a, 'w> {
    fn new(
        transition: &'a BlsDoryTransitionWitnessRowSource<'w>,
        alpha: BlsDoryFr,
        elements: usize,
        rows: usize,
        columns: usize,
    ) -> Result<Self, BlsDoryRangeLogUpError> {
        let mut dictionary = Vec::with_capacity(TABLE_VALUES + 1);
        dictionary.push(BlsDoryFr::zero());
        for digit in 0..TABLE_VALUES {
            dictionary.push(
                (alpha - BlsDoryFr::from_u64(digit as u64))
                    .inv()
                    .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)?,
            );
        }
        let explicit_scalars = elements
            .checked_mul(STRUCTURED_TRANSITION_ORACLES)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        if explicit_scalars
            > rows
                .checked_mul(columns)
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?
        {
            return Err(BlsDoryRangeLogUpError::InvalidDimensions);
        }
        Ok(Self {
            transition,
            elements,
            rows,
            columns,
            explicit_scalars,
            dictionary,
        })
    }
}

#[cfg(test)]
impl BlsDoryIndexedRowSource for LogUpInverseCodeRowSource<'_, '_> {
    type Error = BlsDoryRangeLogUpError;

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.explicit_scalars
    }

    fn literal_scalar_count(&self) -> usize {
        0
    }

    fn dictionary(&self) -> &[BlsDoryFr] {
        &self.dictionary
    }

    fn read_literal_row(
        &mut self,
        _row_index: usize,
        _output: &mut [BlsDoryFr],
    ) -> Result<usize, Self::Error> {
        Err(BlsDoryRangeLogUpError::InvalidDimensions)
    }

    fn read_code_row(&mut self, row_index: usize, output: &mut [u8]) -> Result<usize, Self::Error> {
        let start = row_index
            .checked_mul(self.columns)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        for (column, code) in output.iter_mut().enumerate() {
            let packed_index = start + column;
            let oracle = packed_index / self.elements;
            let index = packed_index % self.elements;
            *code = if (STRUCTURED_TRANSITION_REGULAR_ORACLES..STRUCTURED_TRANSITION_ORACLES)
                .contains(&oracle)
            {
                self.transition
                    .range_digit(oracle, index)?
                    .checked_add(1)
                    .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?
            } else {
                0
            };
        }
        Ok(output.len())
    }
}

#[cfg(test)]
impl<'a, 'w> LogUpInverseRowSource<'a, 'w> {
    fn new(
        transition: &'a BlsDoryTransitionWitnessRowSource<'w>,
        alpha: BlsDoryFr,
        elements: usize,
        rows: usize,
        columns: usize,
    ) -> Result<Self, BlsDoryRangeLogUpError> {
        if (0..TABLE_VALUES)
            .any(|digit| (alpha - BlsDoryFr::from_u64(digit as u64)).inv().is_none())
        {
            return Err(BlsDoryRangeLogUpError::ChallengeCollision);
        }
        let explicit_scalars = elements
            .checked_mul(STRUCTURED_TRANSITION_ORACLES)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        if explicit_scalars
            > rows
                .checked_mul(columns)
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?
        {
            return Err(BlsDoryRangeLogUpError::InvalidDimensions);
        }
        Ok(Self {
            transition,
            alpha,
            elements,
            rows,
            columns,
            explicit_scalars,
            active_columns: Vec::with_capacity(columns),
            denominators: Vec::with_capacity(columns),
        })
    }
}

#[cfg(test)]
impl BlsDoryRowSource for LogUpInverseRowSource<'_, '_> {
    type Error = BlsDoryRangeLogUpError;

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.explicit_scalars
    }

    fn read_row(
        &mut self,
        row_index: usize,
        output: &mut [BlsDoryFr],
    ) -> Result<usize, Self::Error> {
        let start = row_index
            .checked_mul(self.columns)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        self.active_columns.clear();
        self.denominators.clear();
        for (column, scalar) in output.iter_mut().enumerate() {
            let packed_index = start + column;
            let oracle = packed_index / self.elements;
            let index = packed_index % self.elements;
            *scalar = if (STRUCTURED_TRANSITION_REGULAR_ORACLES..STRUCTURED_TRANSITION_ORACLES)
                .contains(&oracle)
            {
                self.active_columns.push(column);
                self.denominators
                    .push(self.alpha - self.transition.scalar(oracle, index)?);
                BlsDoryFr::zero()
            } else {
                BlsDoryFr::zero()
            };
        }
        batch_invert_logup_denominators(&mut self.denominators)?;
        for (column, inverse) in self.active_columns.iter().copied().zip(&self.denominators) {
            output[column] = *inverse;
        }
        Ok(output.len())
    }
}

#[derive(Clone, Copy)]
struct LogUpFoldValues {
    transition: BlsDoryFr,
    inverse: BlsDoryFr,
}

enum LogUpLineageArtifact {
    Compressed(BlsDoryLogUpArtifact),
    Scalar(BlsDoryFoldArtifact),
}

impl LogUpLineageArtifact {
    const fn digest(&self) -> [u8; 32] {
        match self {
            Self::Compressed(artifact) => artifact.digest(),
            Self::Scalar(artifact) => artifact.digest(),
        }
    }
}

fn interpolate_logup_fold_values(
    lower: LogUpFoldValues,
    upper: LogUpFoldValues,
    challenge: BlsDoryFr,
) -> LogUpFoldValues {
    LogUpFoldValues {
        transition: lower.transition + challenge * (upper.transition - lower.transition),
        inverse: lower.inverse + challenge * (upper.inverse - lower.inverse),
    }
}

fn logup_reconstruction_digest(
    alpha: BlsDoryFr,
    challenges: &[BlsDoryFr],
) -> Result<[u8; 32], BlsDoryRangeLogUpError> {
    let challenge_count =
        u32::try_from(challenges.len()).map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut encoded = Vec::with_capacity((challenges.len() + 1) * 32);
    append_serialized(&mut encoded, &alpha)?;
    for challenge in challenges {
        append_serialized(&mut encoded, challenge)?;
    }
    let mut hasher =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/BlsDoryLogUpReconstruction/v1");
    hasher.update(&challenge_count.to_le_bytes());
    hasher.update(&encoded);
    let digest = *hasher.finalize().as_bytes();
    if digest == [0; 32] {
        return Err(logup_storage_error());
    }
    Ok(digest)
}

fn compressed_logup_spec(
    context_digest: [u8; 32],
    generation: usize,
    selector_rows: usize,
    current_cells: usize,
    parent_digest: [u8; 32],
    alpha: BlsDoryFr,
    challenges: &[BlsDoryFr],
) -> Result<BlsDoryLogUpArtifactSpec, BlsDoryRangeLogUpError> {
    if generation == 0
        || generation > LOGUP_COMPRESSED_GENERATIONS
        || challenges.len() != generation
    {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(BlsDoryLogUpArtifactSpec {
        context_digest,
        parent_digest,
        reconstruction_digest: logup_reconstruction_digest(alpha, challenges)?,
        generation: u32::try_from(generation)
            .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        selector_rows: u64::try_from(selector_rows)
            .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        current_cells: u64::try_from(current_cells)
            .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        regular_selectors: u32::try_from(STRUCTURED_TRANSITION_REGULAR_ORACLES)
            .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        range_selectors: u32::try_from(
            STRUCTURED_TRANSITION_ORACLES - STRUCTURED_TRANSITION_REGULAR_ORACLES,
        )
        .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
    })
}

fn logup_range_digit_values(
    alpha: BlsDoryFr,
) -> Result<[LogUpFoldValues; TABLE_VALUES], BlsDoryRangeLogUpError> {
    let mut digits = [LogUpFoldValues {
        transition: BlsDoryFr::zero(),
        inverse: BlsDoryFr::zero(),
    }; TABLE_VALUES];
    for (digit, values) in digits.iter_mut().enumerate() {
        let transition = BlsDoryFr::from_u64(digit as u64);
        *values = LogUpFoldValues {
            transition,
            inverse: (alpha - transition)
                .inv()
                .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)?,
        };
    }
    Ok(digits)
}

fn decode_logup_range_fold_code(
    generation: usize,
    code: u64,
    challenges: &[BlsDoryFr],
    digits: &[LogUpFoldValues; TABLE_VALUES],
) -> Result<LogUpFoldValues, BlsDoryRangeLogUpError> {
    if generation == 0
        || generation > LOGUP_COMPRESSED_GENERATIONS
        || challenges.len() != generation
    {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let leaf_count = 1usize
        .checked_shl(generation as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let code_bits = leaf_count
        .checked_mul(4)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    if code_bits > u64::BITS as usize
        || (code_bits < u64::BITS as usize && code >= (1u64 << code_bits))
    {
        return Err(logup_storage_error());
    }
    let zero = LogUpFoldValues {
        transition: BlsDoryFr::zero(),
        inverse: BlsDoryFr::zero(),
    };
    let mut level = [zero; 1usize << LOGUP_COMPRESSED_GENERATIONS];
    for (index, target) in level.iter_mut().take(leaf_count).enumerate() {
        *target = digits[((code >> (index * 4)) & 0xf) as usize];
    }
    let mut width = leaf_count;
    for challenge in challenges {
        for index in 0..width / 2 {
            level[index] =
                interpolate_logup_fold_values(level[index * 2], level[index * 2 + 1], *challenge);
        }
        width /= 2;
    }
    if width != 1 {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(level[0])
}

fn logup_range_fold_dictionary(
    generation: usize,
    challenges: &[BlsDoryFr],
    digits: &[LogUpFoldValues; TABLE_VALUES],
) -> Result<Option<Vec<LogUpFoldValues>>, BlsDoryRangeLogUpError> {
    if generation > 2 {
        return Ok(None);
    }
    let leaf_count = 1usize
        .checked_shl(generation as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let code_bits = leaf_count
        .checked_mul(4)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let dictionary_len = 1usize
        .checked_shl(code_bits as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    (0..dictionary_len)
        .map(|code| decode_logup_range_fold_code(generation, code as u64, challenges, digits))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

#[cfg(test)]
fn batch_invert_logup_denominators(
    denominators: &mut [BlsDoryFr],
) -> Result<(), BlsDoryRangeLogUpError> {
    if denominators
        .iter()
        .any(|denominator| *denominator == BlsDoryFr::zero())
    {
        return Err(BlsDoryRangeLogUpError::ChallengeCollision);
    }
    let mut inner = denominators
        .iter()
        .map(|denominator| denominator.0)
        .collect::<Vec<_>>();
    batch_inversion(&mut inner);
    for (denominator, inverse) in denominators.iter_mut().zip(inner) {
        *denominator = BlsDoryFr(inverse);
    }
    Ok(())
}

struct LogUpSparseTables {
    multiplicity: Vec<BlsDoryFr>,
    table: Vec<BlsDoryFr>,
    table_inverse: Vec<BlsDoryFr>,
}

impl LogUpSparseTables {
    fn new(counts: &[u64; TABLE_VALUES], alpha: BlsDoryFr) -> Result<Self, BlsDoryRangeLogUpError> {
        Ok(Self {
            multiplicity: counts.iter().copied().map(BlsDoryFr::from_u64).collect(),
            table: vec![BlsDoryFr::one(); TABLE_VALUES],
            table_inverse: (0..TABLE_VALUES)
                .map(|digit| {
                    (alpha - BlsDoryFr::from_u64(digit as u64))
                        .inv()
                        .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    fn values(&self, selector: usize, cell: usize) -> (BlsDoryFr, BlsDoryFr, BlsDoryFr) {
        if selector != 0 {
            return (BlsDoryFr::zero(), BlsDoryFr::zero(), BlsDoryFr::zero());
        }
        (
            self.multiplicity
                .get(cell)
                .copied()
                .unwrap_or_else(BlsDoryFr::zero),
            self.table
                .get(cell)
                .copied()
                .unwrap_or_else(BlsDoryFr::zero),
            self.table_inverse
                .get(cell)
                .copied()
                .unwrap_or_else(BlsDoryFr::zero),
        )
    }

    fn fold(&mut self, challenge: BlsDoryFr) {
        for table in [
            &mut self.multiplicity,
            &mut self.table,
            &mut self.table_inverse,
        ] {
            if table.len() == 1 {
                table[0] = table[0] * (BlsDoryFr::one() - challenge);
                continue;
            }
            let folded_len = table.len() / 2;
            for index in 0..folded_len {
                table[index] =
                    table[index * 2] + challenge * (table[index * 2 + 1] - table[index * 2]);
            }
            table.truncate(folded_len);
        }
    }
}

fn logup_storage_error() -> BlsDoryRangeLogUpError {
    BlsDoryAggregateError::ProverStorage.into()
}

fn raw_logup_fold_values(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    alpha: BlsDoryFr,
    selector: usize,
    cell: usize,
) -> Result<LogUpFoldValues, BlsDoryRangeLogUpError> {
    let transition = if selector < STRUCTURED_TRANSITION_ORACLES {
        source.scalar(selector, cell)?
    } else {
        BlsDoryFr::zero()
    };
    let inverse = if (STRUCTURED_TRANSITION_REGULAR_ORACLES..STRUCTURED_TRANSITION_ORACLES)
        .contains(&selector)
    {
        (alpha - transition)
            .inv()
            .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)?
    } else {
        BlsDoryFr::zero()
    };
    Ok(LogUpFoldValues {
        transition,
        inverse,
    })
}

fn logup_core_from_fold(
    values: LogUpFoldValues,
    selector: usize,
    cell: usize,
    sparse: &LogUpSparseTables,
) -> LogUpCoreValues {
    let (multiplicity, table, table_inverse) = sparse.values(selector, cell);
    LogUpCoreValues {
        transition: values.transition,
        multiplicity,
        inverse: values.inverse,
        active: if (STRUCTURED_TRANSITION_REGULAR_ORACLES..STRUCTURED_TRANSITION_ORACLES)
            .contains(&selector)
        {
            BlsDoryFr::one()
        } else {
            BlsDoryFr::zero()
        },
        table,
        table_inverse,
    }
}

fn logup_fold_spec(
    context_digest: [u8; 32],
    generation: usize,
    selector_rows: usize,
    current_cells: usize,
    parent_digest: [u8; 32],
) -> Result<BlsDoryFoldArtifactSpec, BlsDoryRangeLogUpError> {
    let logical_values = selector_rows
        .checked_mul(current_cells)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let explicit_values = STRUCTURED_TRANSITION_ORACLES
        .checked_mul(current_cells)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    Ok(BlsDoryFoldArtifactSpec {
        context_digest,
        table_index: 0,
        generation: u32::try_from(generation)
            .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        scalar_count: u64::try_from(
            logical_values
                .checked_mul(LOGUP_FOLD_SLOTS)
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
        )
        .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        explicit_scalar_count: u64::try_from(
            explicit_values
                .checked_mul(LOGUP_FOLD_SLOTS)
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
        )
        .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        parent_digest,
    })
}

fn write_logup_fold_values(
    writer: &mut BlsDoryFoldArtifactWriter,
    values: LogUpFoldValues,
) -> Result<(), BlsDoryRangeLogUpError> {
    writer
        .write_scalars(&[values.transition, values.inverse])
        .map_err(|_| logup_storage_error())
}

#[allow(clippy::too_many_arguments)]
fn fold_raw_logup_values_compressed(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    alpha: BlsDoryFr,
    challenges: &[BlsDoryFr],
    selector_rows: usize,
    current_cells: usize,
    context_digest: [u8; 32],
    parent_digest: [u8; 32],
    scratch_directory: &Path,
) -> Result<BlsDoryLogUpArtifact, BlsDoryRangeLogUpError> {
    if challenges.len() != 1 {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let challenge = challenges[0];
    let child_cells = current_cells
        .checked_div(2)
        .filter(|cells| *cells > 0)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let spec = compressed_logup_spec(
        context_digest,
        1,
        selector_rows,
        child_cells,
        parent_digest,
        alpha,
        challenges,
    )?;
    let _ = logup_range_digit_values(alpha)?;
    let mut writer = BlsDoryLogUpArtifactWriter::create(scratch_directory, spec)
        .map_err(|_| logup_storage_error())?;

    let regular_child_values = STRUCTURED_TRANSITION_REGULAR_ORACLES
        .checked_mul(child_cells)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    for chunk_start in (0..regular_child_values).step_by(LOGUP_PARALLEL_FOLD_CHUNK_VALUES) {
        let chunk_end = chunk_start
            .saturating_add(LOGUP_PARALLEL_FOLD_CHUNK_VALUES)
            .min(regular_child_values);
        let folded = (chunk_start..chunk_end)
            .into_par_iter()
            .map(|packed_child| {
                let selector = packed_child / child_cells;
                let child_cell = packed_child % child_cells;
                let lower = source.scalar(selector, child_cell * 2)?;
                let upper = source.scalar(selector, child_cell * 2 + 1)?;
                Ok(lower + challenge * (upper - lower))
            })
            .collect::<Result<Vec<_>, BlsDoryRangeLogUpError>>()?;
        writer
            .write_regular_scalars(&folded)
            .map_err(|_| logup_storage_error())?;
    }

    let range_child_values = (STRUCTURED_TRANSITION_ORACLES
        - STRUCTURED_TRANSITION_REGULAR_ORACLES)
        .checked_mul(child_cells)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    for chunk_start in (0..range_child_values).step_by(LOGUP_PARALLEL_FOLD_CHUNK_VALUES) {
        let chunk_end = chunk_start
            .saturating_add(LOGUP_PARALLEL_FOLD_CHUNK_VALUES)
            .min(range_child_values);
        let codes = (chunk_start..chunk_end)
            .into_par_iter()
            .map(|packed_child| {
                let selector = STRUCTURED_TRANSITION_REGULAR_ORACLES + packed_child / child_cells;
                let child_cell = packed_child % child_cells;
                let lower = u64::from(source.range_digit(selector, child_cell * 2)?);
                let upper = u64::from(source.range_digit(selector, child_cell * 2 + 1)?);
                Ok(lower | (upper << 4))
            })
            .collect::<Result<Vec<_>, BlsDoryRangeLogUpError>>()?;
        writer
            .write_range_codes(&codes)
            .map_err(|_| logup_storage_error())?;
    }
    writer.finish().map_err(|_| logup_storage_error())
}

#[allow(clippy::too_many_arguments)]
fn fold_compressed_logup_artifact(
    artifact: &BlsDoryLogUpArtifact,
    alpha: BlsDoryFr,
    challenges: &[BlsDoryFr],
    selector_rows: usize,
    current_cells: usize,
    context_digest: [u8; 32],
    parent_digest: [u8; 32],
    scratch_directory: &Path,
) -> Result<BlsDoryLogUpArtifact, BlsDoryRangeLogUpError> {
    let generation = challenges.len();
    if !(2..=LOGUP_COMPRESSED_GENERATIONS).contains(&generation)
        || current_cells < 2
        || !current_cells.is_power_of_two()
    {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let parent_generation = generation - 1;
    let expected_spec = compressed_logup_spec(
        context_digest,
        parent_generation,
        selector_rows,
        current_cells,
        parent_digest,
        alpha,
        &challenges[..parent_generation],
    )?;
    if artifact.spec() != expected_spec {
        return Err(logup_storage_error());
    }
    let child_cells = current_cells / 2;
    let child_spec = compressed_logup_spec(
        context_digest,
        generation,
        selector_rows,
        child_cells,
        artifact.digest(),
        alpha,
        challenges,
    )?;
    let mut writer = BlsDoryLogUpArtifactWriter::create(scratch_directory, child_spec)
        .map_err(|_| logup_storage_error())?;
    let challenge = challenges[parent_generation];
    let code_shift = artifact
        .spec()
        .code_bytes()
        .map_err(|_| logup_storage_error())?
        .checked_mul(8)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut pending_regular = None;
    let mut pending_range = None;
    let mut regular_chunk = Vec::with_capacity(LOGUP_PARALLEL_FOLD_CHUNK_VALUES);
    let mut range_chunk = Vec::with_capacity(LOGUP_PARALLEL_FOLD_CHUNK_VALUES);
    let mut fold_error = None;
    let read_result = artifact.for_each_value(|value| {
        let result = match value {
            BlsDoryLogUpArtifactValue::Regular(value) => {
                if pending_range.is_some() || !range_chunk.is_empty() {
                    Err(logup_storage_error())
                } else if let Some(lower) = pending_regular.take() {
                    regular_chunk.push(lower + challenge * (value - lower));
                    if regular_chunk.len() == LOGUP_PARALLEL_FOLD_CHUNK_VALUES {
                        if writer.write_regular_scalars(&regular_chunk).is_err() {
                            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
                        }
                        regular_chunk.clear();
                    }
                    Ok(())
                } else {
                    pending_regular = Some(value);
                    Ok(())
                }
            }
            BlsDoryLogUpArtifactValue::Range(code) => {
                if pending_regular.is_some() {
                    Err(logup_storage_error())
                } else {
                    if !regular_chunk.is_empty() {
                        if writer.write_regular_scalars(&regular_chunk).is_err() {
                            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
                        }
                        regular_chunk.clear();
                    }
                    if let Some(lower) = pending_range.take() {
                        range_chunk.push(lower | (code << code_shift));
                        if range_chunk.len() == LOGUP_PARALLEL_FOLD_CHUNK_VALUES {
                            if writer.write_range_codes(&range_chunk).is_err() {
                                return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
                            }
                            range_chunk.clear();
                        }
                    } else {
                        pending_range = Some(code);
                    }
                    Ok(())
                }
            }
        };
        if let Err(error) = result {
            fold_error = Some(error);
            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
        }
        Ok(())
    });
    if let Some(error) = fold_error {
        return Err(error);
    }
    read_result.map_err(|_| logup_storage_error())?;
    if pending_regular.is_some() || pending_range.is_some() {
        return Err(logup_storage_error());
    }
    if !regular_chunk.is_empty() {
        writer
            .write_regular_scalars(&regular_chunk)
            .map_err(|_| logup_storage_error())?;
    }
    if !range_chunk.is_empty() {
        writer
            .write_range_codes(&range_chunk)
            .map_err(|_| logup_storage_error())?;
    }
    writer.finish().map_err(|_| logup_storage_error())
}

#[derive(Clone, Copy)]
struct LogUpLineageReadSpec<'a> {
    context_digest: [u8; 32],
    generation: usize,
    selector_rows: usize,
    current_cells: usize,
    parent_digest: [u8; 32],
    alpha: BlsDoryFr,
    challenges: &'a [BlsDoryFr],
}

fn for_each_logup_lineage_value(
    artifact: &LogUpLineageArtifact,
    expected: LogUpLineageReadSpec<'_>,
    mut visitor: impl FnMut(usize, LogUpFoldValues) -> Result<(), BlsDoryRangeLogUpError>,
) -> Result<(), BlsDoryRangeLogUpError> {
    if expected.challenges.len() != expected.generation {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let expected_values = STRUCTURED_TRANSITION_ORACLES
        .checked_mul(expected.current_cells)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    match artifact {
        LogUpLineageArtifact::Compressed(artifact)
            if expected.generation <= LOGUP_COMPRESSED_GENERATIONS =>
        {
            let expected_spec = compressed_logup_spec(
                expected.context_digest,
                expected.generation,
                expected.selector_rows,
                expected.current_cells,
                expected.parent_digest,
                expected.alpha,
                expected.challenges,
            )?;
            if artifact.spec() != expected_spec {
                return Err(logup_storage_error());
            }
            let range_digits = logup_range_digit_values(expected.alpha)?;
            let range_dictionary = logup_range_fold_dictionary(
                expected.generation,
                expected.challenges,
                &range_digits,
            )?;
            let regular_values = STRUCTURED_TRANSITION_REGULAR_ORACLES
                .checked_mul(expected.current_cells)
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
            let mut value_index = 0usize;
            let mut visitor_error = None;
            let artifact_result = artifact.for_each_value(|encoded| {
                let values = match encoded {
                    BlsDoryLogUpArtifactValue::Regular(transition)
                        if value_index < regular_values =>
                    {
                        LogUpFoldValues {
                            transition,
                            inverse: BlsDoryFr::zero(),
                        }
                    }
                    BlsDoryLogUpArtifactValue::Range(code) if value_index >= regular_values => {
                        let decoded = if let Some(dictionary) = &range_dictionary {
                            usize::try_from(code)
                                .ok()
                                .and_then(|index| dictionary.get(index).copied())
                                .ok_or_else(logup_storage_error)
                        } else {
                            decode_logup_range_fold_code(
                                expected.generation,
                                code,
                                expected.challenges,
                                &range_digits,
                            )
                        };
                        match decoded {
                            Ok(values) => values,
                            Err(_) => return Err(BlsDoryLogUpArtifactError::InvalidArtifact),
                        }
                    }
                    _ => return Err(BlsDoryLogUpArtifactError::InvalidArtifact),
                };
                if let Err(error) = visitor(value_index, values) {
                    visitor_error = Some(error);
                    return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
                }
                value_index += 1;
                Ok(())
            });
            if let Some(error) = visitor_error {
                return Err(error);
            }
            artifact_result.map_err(|_| logup_storage_error())?;
            if value_index != expected_values {
                return Err(logup_storage_error());
            }
        }
        LogUpLineageArtifact::Scalar(artifact)
            if expected.generation > LOGUP_COMPRESSED_GENERATIONS =>
        {
            let expected_spec = logup_fold_spec(
                expected.context_digest,
                expected.generation,
                expected.selector_rows,
                expected.current_cells,
                expected.parent_digest,
            )?;
            if artifact.spec() != expected_spec {
                return Err(logup_storage_error());
            }
            let mut values = LogUpFoldValues {
                transition: BlsDoryFr::zero(),
                inverse: BlsDoryFr::zero(),
            };
            let mut scalar_slot = 0usize;
            let mut value_index = 0usize;
            let mut visitor_error = None;
            let artifact_result = artifact.for_each_scalar(|scalar| {
                match scalar_slot {
                    0 => values.transition = scalar,
                    1 => values.inverse = scalar,
                    _ => return Err(BlsDoryFoldArtifactError::InvalidArtifact),
                }
                scalar_slot += 1;
                if scalar_slot == LOGUP_FOLD_SLOTS {
                    if let Err(error) = visitor(value_index, values) {
                        visitor_error = Some(error);
                        return Err(BlsDoryFoldArtifactError::InvalidArtifact);
                    }
                    value_index += 1;
                    scalar_slot = 0;
                    values = LogUpFoldValues {
                        transition: BlsDoryFr::zero(),
                        inverse: BlsDoryFr::zero(),
                    };
                }
                Ok(())
            });
            if let Some(error) = visitor_error {
                return Err(error);
            }
            artifact_result.map_err(|_| logup_storage_error())?;
            if scalar_slot != 0 || value_index != expected_values {
                return Err(logup_storage_error());
            }
        }
        _ => return Err(logup_storage_error()),
    }
    Ok(())
}

fn for_each_logup_lineage_pair(
    artifact: &LogUpLineageArtifact,
    expected: LogUpLineageReadSpec<'_>,
    mut visitor: impl FnMut(
        usize,
        LogUpFoldValues,
        LogUpFoldValues,
    ) -> Result<(), BlsDoryRangeLogUpError>,
) -> Result<(), BlsDoryRangeLogUpError> {
    if expected.current_cells < 2 || !expected.current_cells.is_power_of_two() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let expected_pairs = STRUCTURED_TRANSITION_ORACLES
        .checked_mul(expected.current_cells / 2)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut pending = None;
    let mut pair_index = 0usize;
    for_each_logup_lineage_value(artifact, expected, |_value_index, values| {
        if let Some(lower) = pending.take() {
            visitor(pair_index, lower, values)?;
            pair_index += 1;
        } else {
            pending = Some(values);
        }
        Ok(())
    })?;
    if pending.is_some() || pair_index != expected_pairs {
        return Err(logup_storage_error());
    }
    Ok(())
}

fn fold_logup_lineage_artifact(
    artifact: &LogUpLineageArtifact,
    expected: LogUpLineageReadSpec<'_>,
    challenge: BlsDoryFr,
    scratch_directory: &Path,
) -> Result<BlsDoryFoldArtifact, BlsDoryRangeLogUpError> {
    let child_cells = expected
        .current_cells
        .checked_div(2)
        .filter(|cells| *cells > 0)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let generation = expected
        .generation
        .checked_add(1)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    if generation <= LOGUP_COMPRESSED_GENERATIONS {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let spec = logup_fold_spec(
        expected.context_digest,
        generation,
        expected.selector_rows,
        child_cells,
        artifact.digest(),
    )?;
    let mut writer = BlsDoryFoldArtifactWriter::create(scratch_directory, spec)
        .map_err(|_| logup_storage_error())?;
    for_each_logup_lineage_pair(artifact, expected, |_pair_index, lower, upper| {
        write_logup_fold_values(
            &mut writer,
            interpolate_logup_fold_values(lower, upper, challenge),
        )
    })?;
    writer.finish().map_err(|_| logup_storage_error())
}

#[derive(Clone, Copy)]
struct LogUpCoreValues {
    transition: BlsDoryFr,
    multiplicity: BlsDoryFr,
    inverse: BlsDoryFr,
    active: BlsDoryFr,
    table: BlsDoryFr,
    table_inverse: BlsDoryFr,
}

impl LogUpCoreValues {
    fn zero() -> Self {
        Self {
            transition: BlsDoryFr::zero(),
            multiplicity: BlsDoryFr::zero(),
            inverse: BlsDoryFr::zero(),
            active: BlsDoryFr::zero(),
            table: BlsDoryFr::zero(),
            table_inverse: BlsDoryFr::zero(),
        }
    }

    fn add_scaled(&mut self, other: Self, scale: BlsDoryFr) {
        self.transition = self.transition + other.transition * scale;
        self.multiplicity = self.multiplicity + other.multiplicity * scale;
        self.inverse = self.inverse + other.inverse * scale;
        self.active = self.active + other.active * scale;
        self.table = self.table + other.table * scale;
        self.table_inverse = self.table_inverse + other.table_inverse * scale;
    }

    fn interpolate(lower: Self, upper: Self, point: BlsDoryFr) -> Self {
        let mut value = lower;
        value.transition = lower.transition + point * (upper.transition - lower.transition);
        value.multiplicity = lower.multiplicity + point * (upper.multiplicity - lower.multiplicity);
        value.inverse = lower.inverse + point * (upper.inverse - lower.inverse);
        value.active = lower.active + point * (upper.active - lower.active);
        value.table = lower.table + point * (upper.table - lower.table);
        value.table_inverse =
            lower.table_inverse + point * (upper.table_inverse - lower.table_inverse);
        value
    }

    fn terminal(self, equality: BlsDoryFr) -> TerminalValues {
        TerminalValues {
            transition: self.transition,
            multiplicity: self.multiplicity,
            inverse: self.inverse,
            active: self.active,
            table: self.table,
            table_inverse: self.table_inverse,
            equality,
        }
    }
}

struct LogUpEqualityWeightIterator<'a> {
    point: &'a [BlsDoryFr],
    stack: Vec<(usize, BlsDoryFr)>,
}

impl<'a> LogUpEqualityWeightIterator<'a> {
    fn new(point: &'a [BlsDoryFr]) -> Self {
        Self {
            point,
            stack: vec![(point.len(), BlsDoryFr::one())],
        }
    }
}

impl Iterator for LogUpEqualityWeightIterator<'_> {
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

fn logup_equality_weight_at(
    point: &[BlsDoryFr],
    index: usize,
) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
    let variables =
        u32::try_from(point.len()).map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?;
    let domain = 1usize
        .checked_shl(variables)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    if index >= domain {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(point
        .iter()
        .enumerate()
        .fold(BlsDoryFr::one(), |weight, (bit, coordinate)| {
            weight
                * if (index >> bit) & 1 == 1 {
                    *coordinate
                } else {
                    BlsDoryFr::one() - *coordinate
                }
        }))
}

struct LogUpScratchSumcheck {
    rounds: Vec<[BlsDoryFr; LOGUP_ROUND_VALUES]>,
    point: Vec<BlsDoryFr>,
    terminal: TerminalValues,
    terminal_evaluations: [BlsDoryFr; 3],
    final_claim: BlsDoryFr,
}

fn raw_logup_values(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    counts: &[u64; TABLE_VALUES],
    alpha: BlsDoryFr,
    elements: usize,
    packed_index: usize,
) -> Result<LogUpCoreValues, BlsDoryRangeLogUpError> {
    let oracle = packed_index / elements;
    let index = packed_index % elements;
    let transition = if oracle < STRUCTURED_TRANSITION_ORACLES {
        source.scalar(oracle, index)?
    } else {
        BlsDoryFr::zero()
    };
    let active =
        (STRUCTURED_TRANSITION_REGULAR_ORACLES..STRUCTURED_TRANSITION_ORACLES).contains(&oracle);
    let table = packed_index < TABLE_VALUES;
    let inverse = if active {
        (alpha - transition)
            .inv()
            .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)?
    } else {
        BlsDoryFr::zero()
    };
    let table_inverse = if table {
        (alpha - BlsDoryFr::from_u64(packed_index as u64))
            .inv()
            .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)?
    } else {
        BlsDoryFr::zero()
    };
    Ok(LogUpCoreValues {
        transition,
        multiplicity: counts
            .get(packed_index)
            .copied()
            .map_or_else(BlsDoryFr::zero, BlsDoryFr::from_u64),
        inverse,
        active: if active {
            BlsDoryFr::one()
        } else {
            BlsDoryFr::zero()
        },
        table: if table {
            BlsDoryFr::one()
        } else {
            BlsDoryFr::zero()
        },
        table_inverse,
    })
}

fn folded_raw_logup_values(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    counts: &[u64; TABLE_VALUES],
    alpha: BlsDoryFr,
    elements: usize,
    current_index: usize,
    prefix_point: &[BlsDoryFr],
) -> Result<LogUpCoreValues, BlsDoryRangeLogUpError> {
    let block = 1usize
        .checked_shl(prefix_point.len() as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let start = current_index
        .checked_mul(block)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut weights = LogUpEqualityWeightIterator::new(prefix_point);
    let mut folded = LogUpCoreValues::zero();
    for offset in 0..block {
        let weight = weights
            .next()
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        folded.add_scaled(
            raw_logup_values(source, counts, alpha, elements, start + offset)?,
            weight,
        );
    }
    if weights.next().is_some() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(folded)
}

#[allow(clippy::too_many_arguments)]
fn accumulate_logup_pair(
    lower: LogUpCoreValues,
    upper: LogUpCoreValues,
    equality_lower: BlsDoryFr,
    equality_upper: BlsDoryFr,
    alpha: BlsDoryFr,
    local_mixing: &[BlsDoryFr],
    rational_mixing: BlsDoryFr,
    count_mixing: BlsDoryFr,
    evaluations: &mut [BlsDoryFr; LOGUP_ROUND_VALUES],
) {
    for (sample, evaluation) in evaluations.iter_mut().enumerate() {
        let point = BlsDoryFr::from_u64(sample as u64);
        let values = LogUpCoreValues::interpolate(lower, upper, point);
        let equality = equality_lower + point * (equality_upper - equality_lower);
        *evaluation = *evaluation
            + logup_constraint(
                values.terminal(equality),
                alpha,
                local_mixing,
                rational_mixing,
                count_mixing,
            );
    }
}

fn validate_logup_suffix_pairs(
    equality_point: &[BlsDoryFr],
    round_index: usize,
    expected_pairs: usize,
) -> Result<(), BlsDoryRangeLogUpError> {
    let suffix_variables = equality_point
        .len()
        .checked_sub(round_index + 1)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let suffix_pairs = 1usize
        .checked_shl(suffix_variables as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    if suffix_pairs != expected_pairs {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn raw_logup_artifact_round(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    sparse: &LogUpSparseTables,
    alpha: BlsDoryFr,
    selector_rows: usize,
    current_cells: usize,
    round_index: usize,
    equality_point: &[BlsDoryFr],
    equality_prefix: BlsDoryFr,
    local_mixing: &[BlsDoryFr],
    rational_mixing: BlsDoryFr,
    count_mixing: BlsDoryFr,
) -> Result<[BlsDoryFr; LOGUP_ROUND_VALUES], BlsDoryRangeLogUpError> {
    if current_cells < 2 || !current_cells.is_power_of_two() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let total_pairs = selector_rows
        .checked_mul(current_cells / 2)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    validate_logup_suffix_pairs(equality_point, round_index, total_pairs)?;
    let coordinate = equality_point[round_index];
    let selector_start = round_index
        .checked_add(current_cells.ilog2() as usize)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let cell_suffix_point = equality_point
        .get(round_index + 1..selector_start)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let selector_point = equality_point
        .get(selector_start..)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let child_cells = current_cells / 2;
    if 1usize
        .checked_shl(
            u32::try_from(cell_suffix_point.len())
                .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        )
        .filter(|cells| *cells == child_cells)
        .is_none()
        || STRUCTURED_TRANSITION_ORACLES > selector_rows
    {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let partials = (0..STRUCTURED_TRANSITION_ORACLES)
        .into_par_iter()
        .map(|selector| {
            let selector_weight = logup_equality_weight_at(selector_point, selector)?;
            let mut cell_weights = LogUpEqualityWeightIterator::new(cell_suffix_point);
            let mut evaluations = [BlsDoryFr::zero(); LOGUP_ROUND_VALUES];
            for pair_cell in 0..child_cells {
                let suffix = cell_weights
                    .next()
                    .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?
                    * selector_weight;
                let equality_scale = equality_prefix * suffix;
                let lower_cell = pair_cell * 2;
                accumulate_logup_pair(
                    logup_core_from_fold(
                        raw_logup_fold_values(source, alpha, selector, lower_cell)?,
                        selector,
                        lower_cell,
                        sparse,
                    ),
                    logup_core_from_fold(
                        raw_logup_fold_values(source, alpha, selector, lower_cell + 1)?,
                        selector,
                        lower_cell + 1,
                        sparse,
                    ),
                    equality_scale * (BlsDoryFr::one() - coordinate),
                    equality_scale * coordinate,
                    alpha,
                    local_mixing,
                    rational_mixing,
                    count_mixing,
                    &mut evaluations,
                );
            }
            if cell_weights.next().is_some() {
                return Err(BlsDoryRangeLogUpError::InvalidDimensions);
            }
            Ok(evaluations)
        })
        .collect::<Result<Vec<_>, BlsDoryRangeLogUpError>>()?;
    let mut evaluations = [BlsDoryFr::zero(); LOGUP_ROUND_VALUES];
    for partial in partials {
        for (evaluation, value) in evaluations.iter_mut().zip(partial) {
            *evaluation = *evaluation + value;
        }
    }
    Ok(evaluations)
}

#[allow(clippy::too_many_arguments)]
fn logup_artifact_round(
    artifact: &LogUpLineageArtifact,
    expected: LogUpLineageReadSpec<'_>,
    sparse: &LogUpSparseTables,
    round_index: usize,
    equality_point: &[BlsDoryFr],
    equality_prefix: BlsDoryFr,
    local_mixing: &[BlsDoryFr],
    rational_mixing: BlsDoryFr,
    count_mixing: BlsDoryFr,
) -> Result<[BlsDoryFr; LOGUP_ROUND_VALUES], BlsDoryRangeLogUpError> {
    let total_pairs = expected
        .selector_rows
        .checked_mul(expected.current_cells / 2)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    validate_logup_suffix_pairs(equality_point, round_index, total_pairs)?;
    let coordinate = equality_point[round_index];
    let mut suffix_weights = LogUpEqualityWeightIterator::new(&equality_point[round_index + 1..]);
    let mut evaluations = [BlsDoryFr::zero(); LOGUP_ROUND_VALUES];
    let mut visited = 0usize;
    for_each_logup_lineage_pair(artifact, expected, |pair_index, lower, upper| {
        let suffix = suffix_weights
            .next()
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        let equality_scale = equality_prefix * suffix;
        let lower_index = pair_index
            .checked_mul(2)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        let selector = lower_index / expected.current_cells;
        let lower_cell = lower_index % expected.current_cells;
        accumulate_logup_pair(
            logup_core_from_fold(lower, selector, lower_cell, sparse),
            logup_core_from_fold(upper, selector, lower_cell + 1, sparse),
            equality_scale * (BlsDoryFr::one() - coordinate),
            equality_scale * coordinate,
            expected.alpha,
            local_mixing,
            rational_mixing,
            count_mixing,
            &mut evaluations,
        );
        visited += 1;
        Ok(())
    })?;
    if visited > total_pairs {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(evaluations)
}

fn logup_selector_values_from_artifact(
    artifact: &LogUpLineageArtifact,
    expected: LogUpLineageReadSpec<'_>,
    sparse: &LogUpSparseTables,
) -> Result<Vec<LogUpCoreValues>, BlsDoryRangeLogUpError> {
    if expected.current_cells != 1 {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let mut selectors = vec![LogUpCoreValues::zero(); expected.selector_rows];
    let mut selector = 0usize;
    for_each_logup_lineage_value(artifact, expected, |_value_index, values| {
        let target = selectors
            .get_mut(selector)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        *target = logup_core_from_fold(values, selector, 0, sparse);
        selector += 1;
        Ok(())
    })?;
    if selector != STRUCTURED_TRANSITION_ORACLES {
        return Err(logup_storage_error());
    }
    Ok(selectors)
}

#[allow(clippy::too_many_arguments)]
fn recomputed_logup_round(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    counts: &[u64; TABLE_VALUES],
    alpha: BlsDoryFr,
    elements: usize,
    current_rows: usize,
    prefix_point: &[BlsDoryFr],
    equality_point: &[BlsDoryFr],
    equality_prefix: BlsDoryFr,
    local_mixing: &[BlsDoryFr],
    rational_mixing: BlsDoryFr,
    count_mixing: BlsDoryFr,
) -> Result<[BlsDoryFr; LOGUP_ROUND_VALUES], BlsDoryRangeLogUpError> {
    let round_index = prefix_point.len();
    let coordinate = *equality_point
        .get(round_index)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut suffix_weights = LogUpEqualityWeightIterator::new(&equality_point[round_index + 1..]);
    let mut evaluations = [BlsDoryFr::zero(); LOGUP_ROUND_VALUES];
    for pair_index in 0..current_rows / 2 {
        let suffix = suffix_weights
            .next()
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        let equality_scale = equality_prefix * suffix;
        accumulate_logup_pair(
            folded_raw_logup_values(
                source,
                counts,
                alpha,
                elements,
                pair_index * 2,
                prefix_point,
            )?,
            folded_raw_logup_values(
                source,
                counts,
                alpha,
                elements,
                pair_index * 2 + 1,
                prefix_point,
            )?,
            equality_scale * (BlsDoryFr::one() - coordinate),
            equality_scale * coordinate,
            alpha,
            local_mixing,
            rational_mixing,
            count_mixing,
            &mut evaluations,
        );
    }
    if suffix_weights.next().is_some() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(evaluations)
}

#[allow(clippy::too_many_arguments)]
fn materialized_core_logup_round(
    values: &[LogUpCoreValues],
    round_index: usize,
    equality_point: &[BlsDoryFr],
    equality_prefix: BlsDoryFr,
    alpha: BlsDoryFr,
    local_mixing: &[BlsDoryFr],
    rational_mixing: BlsDoryFr,
    count_mixing: BlsDoryFr,
) -> Result<[BlsDoryFr; LOGUP_ROUND_VALUES], BlsDoryRangeLogUpError> {
    if values.len() < 2 || !values.len().is_multiple_of(2) {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let coordinate = *equality_point
        .get(round_index)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut suffix_weights = LogUpEqualityWeightIterator::new(&equality_point[round_index + 1..]);
    let mut evaluations = [BlsDoryFr::zero(); LOGUP_ROUND_VALUES];
    for pair in values.chunks_exact(2) {
        let suffix = suffix_weights
            .next()
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
        let equality_scale = equality_prefix * suffix;
        accumulate_logup_pair(
            pair[0],
            pair[1],
            equality_scale * (BlsDoryFr::one() - coordinate),
            equality_scale * coordinate,
            alpha,
            local_mixing,
            rational_mixing,
            count_mixing,
            &mut evaluations,
        );
    }
    if suffix_weights.next().is_some() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(evaluations)
}

fn fold_logup_core_values(values: &mut Vec<LogUpCoreValues>, challenge: BlsDoryFr) {
    let folded_len = values.len() / 2;
    for index in 0..folded_len {
        values[index] =
            LogUpCoreValues::interpolate(values[index * 2], values[index * 2 + 1], challenge);
    }
    values.truncate(folded_len);
}

#[allow(clippy::too_many_arguments)]
fn prove_logup_sumcheck_with_recomputation(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    counts: &[u64; TABLE_VALUES],
    alpha: BlsDoryFr,
    elements: usize,
    packed_variables: usize,
    equality_point: &[BlsDoryFr],
    local_mixing: &[BlsDoryFr],
    rational_mixing: BlsDoryFr,
    count_mixing: BlsDoryFr,
    transcript: &mut BlsDoryTranscript,
) -> Result<LogUpScratchSumcheck, BlsDoryRangeLogUpError> {
    let cell_variables = elements.ilog2() as usize;
    let padded_len = 1usize
        .checked_shl(packed_variables as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let selector_rows = padded_len >> cell_variables;
    if selector_rows < SELECTOR_SLOTS {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let mut claim = BlsDoryFr::zero();
    let mut rounds = Vec::with_capacity(packed_variables);
    let mut point = Vec::with_capacity(packed_variables);
    let mut equality_prefix = BlsDoryFr::one();
    let mut selector_values = if cell_variables == 0 {
        Some(
            (0..selector_rows)
                .map(|index| folded_raw_logup_values(source, counts, alpha, elements, index, &[]))
                .collect::<Result<Vec<_>, _>>()?,
        )
    } else {
        None
    };
    for round_index in 0..packed_variables {
        let current_rows = padded_len >> round_index;
        let evaluations = if round_index < cell_variables {
            recomputed_logup_round(
                source,
                counts,
                alpha,
                elements,
                current_rows,
                &point,
                equality_point,
                equality_prefix,
                local_mixing,
                rational_mixing,
                count_mixing,
            )?
        } else {
            materialized_core_logup_round(
                selector_values
                    .as_ref()
                    .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                round_index,
                equality_point,
                equality_prefix,
                alpha,
                local_mixing,
                rational_mixing,
                count_mixing,
            )?
        };
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryRangeLogUpError::RoundClaim);
        }
        absorb_round(transcript, round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        point.push(challenge);
        let coordinate = equality_point[round_index];
        equality_prefix = equality_prefix
            * ((BlsDoryFr::one() - challenge) * (BlsDoryFr::one() - coordinate)
                + challenge * coordinate);
        if round_index + 1 == cell_variables {
            selector_values = Some(
                (0..selector_rows)
                    .map(|index| {
                        folded_raw_logup_values(source, counts, alpha, elements, index, &point)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
        } else if round_index >= cell_variables {
            fold_logup_core_values(
                selector_values
                    .as_mut()
                    .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                challenge,
            );
        }
        rounds.push(evaluations);
    }
    let core = *selector_values
        .as_ref()
        .and_then(|values| values.first())
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let terminal = core.terminal(equality_prefix);
    Ok(LogUpScratchSumcheck {
        rounds,
        point,
        terminal,
        terminal_evaluations: [core.transition, core.multiplicity, core.inverse],
        final_claim: claim,
    })
}

#[allow(clippy::too_many_arguments)]
fn prove_logup_sumcheck_with_artifacts(
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    counts: &[u64; TABLE_VALUES],
    alpha: BlsDoryFr,
    elements: usize,
    packed_variables: usize,
    equality_point: &[BlsDoryFr],
    local_mixing: &[BlsDoryFr],
    rational_mixing: BlsDoryFr,
    count_mixing: BlsDoryFr,
    transcript: &mut BlsDoryTranscript,
    scratch_directory: &Path,
) -> Result<LogUpScratchSumcheck, BlsDoryRangeLogUpError> {
    if elements < TABLE_VALUES || !elements.is_power_of_two() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let cell_variables = elements.ilog2() as usize;
    let padded_len = 1usize
        .checked_shl(packed_variables as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let selector_rows = padded_len >> cell_variables;
    if selector_rows < SELECTOR_SLOTS || equality_point.len() != packed_variables {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }

    let context_digest = transcript.digest();
    if context_digest == [0; 32] {
        return Err(logup_storage_error());
    }
    let mut root_parent =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/BlsDoryLogUpFoldParent/v1");
    root_parent.update(&context_digest);
    let root_parent_digest = *root_parent.finalize().as_bytes();
    if root_parent_digest == [0; 32] {
        return Err(logup_storage_error());
    }

    let mut claim = BlsDoryFr::zero();
    let mut rounds = Vec::with_capacity(packed_variables);
    let mut point = Vec::with_capacity(packed_variables);
    let mut equality_prefix = BlsDoryFr::one();
    let mut sparse = LogUpSparseTables::new(counts, alpha)?;
    let mut artifact: Option<LogUpLineageArtifact> = None;
    let mut artifact_parent_digest = root_parent_digest;
    let mut current_cells = elements;

    for round_index in 0..cell_variables {
        let round_expected = artifact.as_ref().map(|_| LogUpLineageReadSpec {
            context_digest,
            generation: round_index,
            selector_rows,
            current_cells,
            parent_digest: artifact_parent_digest,
            alpha,
            challenges: &point,
        });
        let evaluations = if let Some(current) = artifact.as_ref() {
            logup_artifact_round(
                current,
                round_expected.ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                &sparse,
                round_index,
                equality_point,
                equality_prefix,
                local_mixing,
                rational_mixing,
                count_mixing,
            )?
        } else {
            raw_logup_artifact_round(
                source,
                &sparse,
                alpha,
                selector_rows,
                current_cells,
                round_index,
                equality_point,
                equality_prefix,
                local_mixing,
                rational_mixing,
                count_mixing,
            )?
        };
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryRangeLogUpError::RoundClaim);
        }
        absorb_round(transcript, round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        point.push(challenge);

        let current_expected = artifact.as_ref().map(|_| LogUpLineageReadSpec {
            context_digest,
            generation: round_index,
            selector_rows,
            current_cells,
            parent_digest: artifact_parent_digest,
            alpha,
            challenges: &point[..round_index],
        });

        let child_parent_digest = artifact
            .as_ref()
            .map_or(root_parent_digest, LogUpLineageArtifact::digest);
        let generation = round_index + 1;
        let child = match artifact.as_ref() {
            None => LogUpLineageArtifact::Compressed(fold_raw_logup_values_compressed(
                source,
                alpha,
                &point,
                selector_rows,
                current_cells,
                context_digest,
                child_parent_digest,
                scratch_directory,
            )?),
            Some(LogUpLineageArtifact::Compressed(current))
                if generation <= LOGUP_COMPRESSED_GENERATIONS =>
            {
                LogUpLineageArtifact::Compressed(fold_compressed_logup_artifact(
                    current,
                    alpha,
                    &point,
                    selector_rows,
                    current_cells,
                    context_digest,
                    artifact_parent_digest,
                    scratch_directory,
                )?)
            }
            Some(current) => LogUpLineageArtifact::Scalar(fold_logup_lineage_artifact(
                current,
                current_expected.ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                challenge,
                scratch_directory,
            )?),
        };
        artifact_parent_digest = child_parent_digest;
        artifact = Some(child);
        current_cells /= 2;
        sparse.fold(challenge);
        let coordinate = equality_point[round_index];
        equality_prefix = equality_prefix
            * ((BlsDoryFr::one() - challenge) * (BlsDoryFr::one() - coordinate)
                + challenge * coordinate);
        rounds.push(evaluations);
    }

    let expected_spec = LogUpLineageReadSpec {
        context_digest,
        generation: cell_variables,
        selector_rows,
        current_cells: 1,
        parent_digest: artifact_parent_digest,
        alpha,
        challenges: &point,
    };
    let mut selector_values = logup_selector_values_from_artifact(
        artifact
            .as_ref()
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
        expected_spec,
        &sparse,
    )?;
    drop(artifact);

    for round_index in cell_variables..packed_variables {
        let evaluations = materialized_core_logup_round(
            &selector_values,
            round_index,
            equality_point,
            equality_prefix,
            alpha,
            local_mixing,
            rational_mixing,
            count_mixing,
        )?;
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryRangeLogUpError::RoundClaim);
        }
        absorb_round(transcript, round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        point.push(challenge);
        fold_logup_core_values(&mut selector_values, challenge);
        let coordinate = equality_point[round_index];
        equality_prefix = equality_prefix
            * ((BlsDoryFr::one() - challenge) * (BlsDoryFr::one() - coordinate)
                + challenge * coordinate);
        rounds.push(evaluations);
    }

    let core = *selector_values
        .first()
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    Ok(LogUpScratchSumcheck {
        rounds,
        point,
        terminal: core.terminal(equality_prefix),
        terminal_evaluations: [core.transition, core.multiplicity, core.inverse],
        final_claim: claim,
    })
}

struct LogUpTables {
    transition: Vec<BlsDoryFr>,
    multiplicity: Vec<BlsDoryFr>,
    inverse: Vec<BlsDoryFr>,
    active: Vec<BlsDoryFr>,
    table: Vec<BlsDoryFr>,
    table_inverse: Vec<BlsDoryFr>,
    equality: Vec<BlsDoryFr>,
}

impl LogUpTables {
    fn fold(&mut self, challenge: BlsDoryFr) -> Result<(), BlsDoryRangeLogUpError> {
        for table in [
            &mut self.transition,
            &mut self.multiplicity,
            &mut self.inverse,
            &mut self.active,
            &mut self.table,
            &mut self.table_inverse,
            &mut self.equality,
        ] {
            *table = fold_table(table, challenge)?;
        }
        Ok(())
    }
}

struct ReconstructionWeights {
    source_weights: Vec<BlsDoryFr>,
    digit_weights: Vec<BlsDoryFr>,
    maximum_evaluation: BlsDoryFr,
}

struct ReconstructionTables {
    source_weights: Vec<BlsDoryFr>,
    digit_weights: Vec<BlsDoryFr>,
    role_values: Vec<BlsDoryFr>,
    maximum_evaluation: BlsDoryFr,
}

struct SelectorProverOutput {
    rounds: Vec<[BlsDoryFr; SELECTOR_ROUND_VALUES]>,
    point: Vec<BlsDoryFr>,
    evaluation: BlsDoryFr,
}

fn reconstruction_weights(
    statement: StructuredTransitionStatement,
    spec_point: &[BlsDoryFr],
    slack_mixing: BlsDoryFr,
) -> Result<ReconstructionWeights, BlsDoryRangeLogUpError> {
    if spec_point.len() != 3 {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let specs = structured_transition_range_specs(statement)?;
    let spec_weights = equality_table(spec_point);
    if specs.len() != spec_weights.len() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let mut source_weights = vec![BlsDoryFr::zero(); SELECTOR_SLOTS];
    let mut digit_weights = vec![BlsDoryFr::zero(); SELECTOR_SLOTS];
    let mut maximum_evaluation = BlsDoryFr::zero();
    let mut digit_slot = STRUCTURED_TRANSITION_REGULAR_ORACLES;
    for (spec, spec_weight) in specs.into_iter().zip(spec_weights) {
        source_weights[spec.oracle] = source_weights[spec.oracle] + spec_weight;
        maximum_evaluation = maximum_evaluation + spec_weight * BlsDoryFr::from_u64(spec.maximum);
        let mut radix = BlsDoryFr::one();
        for _ in 0..spec.digits {
            digit_weights[digit_slot] = digit_weights[digit_slot] + spec_weight * radix;
            digit_weights[digit_slot + 1] =
                digit_weights[digit_slot + 1] + spec_weight * slack_mixing * radix;
            digit_slot += 2;
            radix = radix * BlsDoryFr::from_u64(16);
        }
    }
    if digit_slot != STRUCTURED_TRANSITION_ORACLES {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(ReconstructionWeights {
        source_weights,
        digit_weights,
        maximum_evaluation,
    })
}

fn reconstruction_tables(
    statement: StructuredTransitionStatement,
    oracles: &[Vec<BlsDoryFr>],
    cell_point: &[BlsDoryFr],
    spec_point: &[BlsDoryFr],
    slack_mixing: BlsDoryFr,
) -> Result<ReconstructionTables, BlsDoryRangeLogUpError> {
    if oracles.len() != STRUCTURED_TRANSITION_ORACLES {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let weights = reconstruction_weights(statement, spec_point, slack_mixing)?;
    let mut role_values = vec![BlsDoryFr::zero(); SELECTOR_SLOTS];
    for (target, oracle) in role_values.iter_mut().zip(oracles) {
        *target = evaluate_mle(oracle, cell_point)?;
    }
    Ok(ReconstructionTables {
        source_weights: weights.source_weights,
        digit_weights: weights.digit_weights,
        role_values,
        maximum_evaluation: weights.maximum_evaluation,
    })
}

fn reconstruction_tables_from_witness(
    statement: StructuredTransitionStatement,
    source: &BlsDoryTransitionWitnessRowSource<'_>,
    cell_point: &[BlsDoryFr],
    spec_point: &[BlsDoryFr],
    slack_mixing: BlsDoryFr,
) -> Result<ReconstructionTables, BlsDoryRangeLogUpError> {
    let elements = statement.elements()?;
    if elements
        != 1usize
            .checked_shl(cell_point.len() as u32)
            .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?
    {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let weights = reconstruction_weights(statement, spec_point, slack_mixing)?;
    let mut role_values = vec![BlsDoryFr::zero(); SELECTOR_SLOTS];
    for (oracle, target) in role_values
        .iter_mut()
        .enumerate()
        .take(STRUCTURED_TRANSITION_ORACLES)
    {
        let mut equality_weights = LogUpEqualityWeightIterator::new(cell_point);
        for index in 0..elements {
            let equality_weight = equality_weights
                .next()
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
            *target = *target + source.scalar(oracle, index)? * equality_weight;
        }
        if equality_weights.next().is_some() {
            return Err(BlsDoryRangeLogUpError::InvalidDimensions);
        }
    }
    Ok(ReconstructionTables {
        source_weights: weights.source_weights,
        digit_weights: weights.digit_weights,
        role_values,
        maximum_evaluation: weights.maximum_evaluation,
    })
}

fn inner_product(
    left: &[BlsDoryFr],
    right: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
    if left.len() != right.len() || left.is_empty() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(BlsDoryFr::zero(), |sum, (left, right)| sum + *left * *right))
}

fn combine_weights(
    source: &[BlsDoryFr],
    digit: &[BlsDoryFr],
    mixing: BlsDoryFr,
) -> Result<Vec<BlsDoryFr>, BlsDoryRangeLogUpError> {
    if source.len() != digit.len() || source.is_empty() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(source
        .iter()
        .zip(digit)
        .map(|(source, digit)| *source + mixing * *digit)
        .collect())
}

fn prove_selector_sumcheck(
    initial_claim: BlsDoryFr,
    mut weights: Vec<BlsDoryFr>,
    mut values: Vec<BlsDoryFr>,
    transcript: &mut BlsDoryTranscript,
    kind: &'static [u8],
) -> Result<SelectorProverOutput, BlsDoryRangeLogUpError> {
    if weights.len() != SELECTOR_SLOTS || values.len() != SELECTOR_SLOTS {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    transcript.append_bytes(b"selector-kind", kind);
    let mut claim = initial_claim;
    let mut rounds = Vec::with_capacity(SELECTOR_ROUNDS);
    let mut point = Vec::with_capacity(SELECTOR_ROUNDS);
    for round_index in 0..SELECTOR_ROUNDS {
        let evaluations = selector_round(&weights, &values)?;
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryRangeLogUpError::RoundClaim);
        }
        absorb_selector_round(transcript, round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"selector-sumcheck-challenge");
        claim = evaluate_selector_samples(&evaluations, challenge)?;
        point.push(challenge);
        weights = fold_table(&weights, challenge)?;
        values = fold_table(&values, challenge)?;
        rounds.push(evaluations);
    }
    if claim != weights[0] * values[0] {
        return Err(BlsDoryRangeLogUpError::TerminalClaim);
    }
    Ok(SelectorProverOutput {
        rounds,
        point,
        evaluation: values[0],
    })
}

fn verify_selector_sumcheck(
    initial_claim: BlsDoryFr,
    weights: &[BlsDoryFr],
    rounds: &[[BlsDoryFr; SELECTOR_ROUND_VALUES]],
    evaluation: BlsDoryFr,
    transcript: &mut BlsDoryTranscript,
    kind: &'static [u8],
) -> Result<Vec<BlsDoryFr>, BlsDoryRangeLogUpError> {
    if weights.len() != SELECTOR_SLOTS || rounds.len() != SELECTOR_ROUNDS {
        return Err(BlsDoryRangeLogUpError::InvalidProofShape);
    }
    transcript.append_bytes(b"selector-kind", kind);
    let mut claim = initial_claim;
    let mut point = Vec::with_capacity(SELECTOR_ROUNDS);
    for (round_index, evaluations) in rounds.iter().enumerate() {
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryRangeLogUpError::RoundClaim);
        }
        absorb_selector_round(transcript, round_index, evaluations);
        let challenge = transcript.challenge_scalar(b"selector-sumcheck-challenge");
        claim = evaluate_selector_samples(evaluations, challenge)?;
        point.push(challenge);
    }
    if claim != evaluate_mle(weights, &point)? * evaluation {
        return Err(BlsDoryRangeLogUpError::TerminalClaim);
    }
    Ok(point)
}

fn selector_round(
    weights: &[BlsDoryFr],
    values: &[BlsDoryFr],
) -> Result<[BlsDoryFr; SELECTOR_ROUND_VALUES], BlsDoryRangeLogUpError> {
    if weights.len() != values.len() || weights.len() < 2 || !weights.len().is_multiple_of(2) {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(std::array::from_fn(|sample| {
        let point = BlsDoryFr::from_u64(sample as u64);
        weights.chunks_exact(2).zip(values.chunks_exact(2)).fold(
            BlsDoryFr::zero(),
            |sum, (weights, values)| {
                sum + interpolate_pair(weights, point) * interpolate_pair(values, point)
            },
        )
    }))
}

fn evaluate_selector_samples(
    values: &[BlsDoryFr; SELECTOR_ROUND_VALUES],
    point: BlsDoryFr,
) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
    interpolate_samples(values, point)
}

fn reconstruction_opening_point(
    cell_point: &[BlsDoryFr],
    selector_point: &[BlsDoryFr],
    packed_variables: usize,
) -> Result<Vec<BlsDoryFr>, BlsDoryRangeLogUpError> {
    if selector_point.len() != SELECTOR_ROUNDS
        || cell_point.len() + selector_point.len() > packed_variables
    {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let mut point = Vec::with_capacity(packed_variables);
    point.extend_from_slice(cell_point);
    point.extend_from_slice(selector_point);
    point.resize(packed_variables, BlsDoryFr::zero());
    Ok(point)
}

#[derive(Clone, Copy)]
struct TerminalValues {
    transition: BlsDoryFr,
    multiplicity: BlsDoryFr,
    inverse: BlsDoryFr,
    active: BlsDoryFr,
    table: BlsDoryFr,
    table_inverse: BlsDoryFr,
    equality: BlsDoryFr,
}

fn logup_constraint(
    values: TerminalValues,
    alpha: BlsDoryFr,
    local_mixing: &[BlsDoryFr],
    rational_mixing: BlsDoryFr,
    count_mixing: BlsDoryFr,
) -> BlsDoryFr {
    let one = BlsDoryFr::one();
    let local =
        local_mixing[0] * values.active * (values.inverse * (alpha - values.transition) - one)
            + local_mixing[1] * (one - values.active) * values.inverse
            + local_mixing[2] * (one - values.table) * values.multiplicity;
    let rational =
        values.active * values.inverse - values.table * values.multiplicity * values.table_inverse;
    let count = values.table * values.multiplicity - values.active;
    values.equality * local + rational_mixing * rational + count_mixing * count
}

fn logup_round(
    tables: &LogUpTables,
    alpha: BlsDoryFr,
    local_mixing: &[BlsDoryFr],
    rational_mixing: BlsDoryFr,
    count_mixing: BlsDoryFr,
) -> Result<[BlsDoryFr; LOGUP_ROUND_VALUES], BlsDoryRangeLogUpError> {
    if tables.transition.len() < 2
        || !tables.transition.len().is_multiple_of(2)
        || [
            tables.multiplicity.len(),
            tables.inverse.len(),
            tables.active.len(),
            tables.table.len(),
            tables.table_inverse.len(),
            tables.equality.len(),
        ]
        .into_iter()
        .any(|len| len != tables.transition.len())
    {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(std::array::from_fn(|sample| {
        let point = BlsDoryFr::from_u64(sample as u64);
        (0..tables.transition.len() / 2).fold(BlsDoryFr::zero(), |sum, pair| {
            let offset = pair * 2;
            sum + logup_constraint(
                TerminalValues {
                    transition: interpolate_pair(&tables.transition[offset..offset + 2], point),
                    multiplicity: interpolate_pair(&tables.multiplicity[offset..offset + 2], point),
                    inverse: interpolate_pair(&tables.inverse[offset..offset + 2], point),
                    active: interpolate_pair(&tables.active[offset..offset + 2], point),
                    table: interpolate_pair(&tables.table[offset..offset + 2], point),
                    table_inverse: interpolate_pair(
                        &tables.table_inverse[offset..offset + 2],
                        point,
                    ),
                    equality: interpolate_pair(&tables.equality[offset..offset + 2], point),
                },
                alpha,
                local_mixing,
                rational_mixing,
                count_mixing,
            )
        })
    }))
}

fn query_active_table(
    elements: usize,
    padded_len: usize,
) -> Result<Vec<BlsDoryFr>, BlsDoryRangeLogUpError> {
    let minimum_len = elements
        .checked_mul(SELECTOR_SLOTS)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    if padded_len < minimum_len {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok((0..padded_len)
        .map(|index| {
            let active = index < minimum_len
                && index / elements >= STRUCTURED_TRANSITION_REGULAR_ORACLES
                && index / elements < STRUCTURED_TRANSITION_ORACLES;
            if active {
                BlsDoryFr::one()
            } else {
                BlsDoryFr::zero()
            }
        })
        .collect())
}

fn table_active_table(padded_len: usize) -> Result<Vec<BlsDoryFr>, BlsDoryRangeLogUpError> {
    if padded_len < TABLE_VALUES {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let mut table = vec![BlsDoryFr::zero(); padded_len];
    table[..TABLE_VALUES].fill(BlsDoryFr::one());
    Ok(table)
}

fn table_inverse_table(
    alpha: BlsDoryFr,
    padded_len: usize,
) -> Result<Vec<BlsDoryFr>, BlsDoryRangeLogUpError> {
    if padded_len < TABLE_VALUES {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let mut table = vec![BlsDoryFr::zero(); padded_len];
    for (value, target) in table[..TABLE_VALUES].iter_mut().enumerate() {
        *target = (alpha - BlsDoryFr::from_u64(value as u64))
            .inv()
            .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)?;
    }
    Ok(table)
}

fn query_active_evaluation(
    elements: usize,
    point: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
    let cell_variables = elements.ilog2() as usize;
    let minimum = cell_variables + BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES;
    if point.len() < minimum {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let selector = (0..SELECTOR_SLOTS)
        .map(|slot| {
            if (STRUCTURED_TRANSITION_REGULAR_ORACLES..STRUCTURED_TRANSITION_ORACLES)
                .contains(&slot)
            {
                BlsDoryFr::one()
            } else {
                BlsDoryFr::zero()
            }
        })
        .collect::<Vec<_>>();
    let mut value = evaluate_mle(
        &selector,
        &point[cell_variables..cell_variables + BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES],
    )?;
    for coordinate in &point[minimum..] {
        value = value * (BlsDoryFr::one() - *coordinate);
    }
    Ok(value)
}

fn table_active_evaluation(point: &[BlsDoryFr]) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
    if point.len() < 4 {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(point[4..]
        .iter()
        .fold(BlsDoryFr::one(), |value, coordinate| {
            value * (BlsDoryFr::one() - *coordinate)
        }))
}

fn table_inverse_evaluation(
    alpha: BlsDoryFr,
    point: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
    if point.len() < 4 {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let values = (0..TABLE_VALUES)
        .map(|value| {
            (alpha - BlsDoryFr::from_u64(value as u64))
                .inv()
                .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut evaluation = evaluate_mle(&values, &point[..4])?;
    for coordinate in &point[4..] {
        evaluation = evaluation * (BlsDoryFr::one() - *coordinate);
    }
    Ok(evaluation)
}

fn logup_transcript(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    variables: usize,
    setup_identity: &[u8; 32],
    transition_commitment: &BlsDoryGt,
    multiplicity_commitment: &BlsDoryGt,
) -> BlsDoryTranscript {
    let mut transcript = BlsDoryTranscript::new(b"transition-range-logup");
    transcript.append_bytes(
        b"protocol-version",
        &BLS_DORY_RANGE_LOGUP_VERSION.to_le_bytes(),
    );
    transcript.append_bytes(b"public-binding", binding);
    transcript.append_bytes(b"layers", &(statement.layers as u64).to_le_bytes());
    transcript.append_bytes(b"rows", &(statement.rows as u64).to_le_bytes());
    transcript.append_bytes(b"cols", &(statement.cols as u64).to_le_bytes());
    transcript.append_bytes(
        b"max-abs-accumulator",
        &statement.max_abs_accumulator.to_le_bytes(),
    );
    transcript.append_bytes(b"max-mask", &statement.max_mask.to_le_bytes());
    transcript.append_bytes(b"variables", &(variables as u64).to_le_bytes());
    transcript.append_bytes(b"setup-identity", setup_identity);
    transcript.append_group(b"transition-commitment", transition_commitment);
    transcript.append_group(b"multiplicity-commitment", multiplicity_commitment);
    transcript
}

fn challenge_vector(
    transcript: &mut BlsDoryTranscript,
    label: &'static [u8],
    count: usize,
) -> Vec<BlsDoryFr> {
    (0..count)
        .map(|index| {
            transcript.append_bytes(b"challenge-index", &(index as u64).to_le_bytes());
            transcript.challenge_scalar(label)
        })
        .collect()
}

fn absorb_round(
    transcript: &mut BlsDoryTranscript,
    index: usize,
    evaluations: &[BlsDoryFr; LOGUP_ROUND_VALUES],
) {
    transcript.append_bytes(b"round-index", &(index as u64).to_le_bytes());
    for evaluation in evaluations {
        transcript.append_field(b"round-evaluation", evaluation);
    }
}

fn absorb_selector_round(
    transcript: &mut BlsDoryTranscript,
    index: usize,
    evaluations: &[BlsDoryFr; SELECTOR_ROUND_VALUES],
) {
    transcript.append_bytes(b"selector-round-index", &(index as u64).to_le_bytes());
    for evaluation in evaluations {
        transcript.append_field(b"selector-round-evaluation", evaluation);
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
        blake3::Hasher::new_derive_key("CMFD/FORGEMATRIX/BLS-DORY-RANGE-LOGUP-OPENING/V1");
    hasher.update(&(binding.len() as u64).to_le_bytes());
    hasher.update(binding);
    hasher.update(transcript_digest);
    *hasher.finalize().as_bytes()
}

fn equality_table(point: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
    let mut table = vec![BlsDoryFr::one()];
    for coordinate in point {
        let previous = table;
        table = Vec::with_capacity(previous.len() * 2);
        table.extend(
            previous
                .iter()
                .map(|value| *value * (BlsDoryFr::one() - *coordinate)),
        );
        table.extend(previous.iter().map(|value| *value * *coordinate));
    }
    table
}

fn equality_evaluation(
    left: &[BlsDoryFr],
    right: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
    if left.len() != right.len() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(BlsDoryFr::one(), |product, (left, right)| {
            product * (*left * *right + (BlsDoryFr::one() - *left) * (BlsDoryFr::one() - *right))
        }))
}

fn evaluate_mle(
    values: &[BlsDoryFr],
    point: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
    if values.len() != 1usize << point.len() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let mut folded = values.to_vec();
    for coordinate in point {
        folded = fold_table(&folded, *coordinate)?;
    }
    Ok(folded[0])
}

fn interpolate_pair(pair: &[BlsDoryFr], point: BlsDoryFr) -> BlsDoryFr {
    pair[0] + point * (pair[1] - pair[0])
}

fn fold_table(
    table: &[BlsDoryFr],
    point: BlsDoryFr,
) -> Result<Vec<BlsDoryFr>, BlsDoryRangeLogUpError> {
    if table.is_empty() || !table.len().is_multiple_of(2) {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    Ok(table
        .chunks_exact(2)
        .map(|pair| interpolate_pair(pair, point))
        .collect())
}

fn evaluate_samples(
    values: &[BlsDoryFr; LOGUP_ROUND_VALUES],
    point: BlsDoryFr,
) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
    interpolate_samples(values, point)
}

fn interpolate_samples<const N: usize>(
    values: &[BlsDoryFr; N],
    point: BlsDoryFr,
) -> Result<BlsDoryFr, BlsDoryRangeLogUpError> {
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
        result = result
            + value
                * numerator
                * denominator
                    .inv()
                    .ok_or(BlsDoryRangeLogUpError::InvalidProofShape)?;
    }
    Ok(result)
}

fn logup_wire_bytes(rounds: usize, opening_bytes: usize) -> Result<usize, BlsDoryRangeLogUpError> {
    let group_bytes = BlsDoryGt::identity().compressed_size();
    let field_bytes = BlsDoryFr::zero().compressed_size();
    PROOF_HEADER_BYTES
        .checked_add(
            3usize
                .checked_mul(group_bytes)
                .ok_or(BlsDoryRangeLogUpError::ProofTooLarge)?,
        )
        .and_then(|value| {
            value.checked_add(
                rounds
                    .checked_mul(LOGUP_ROUND_VALUES)?
                    .checked_mul(field_bytes)?,
            )
        })
        .and_then(|value| value.checked_add(LOGUP_TERMINALS.checked_mul(field_bytes)?))
        .and_then(|value| value.checked_add(RECONSTRUCTION_WIRE_FIELDS.checked_mul(field_bytes)?))
        .and_then(|value| value.checked_add(32))
        .and_then(|value| value.checked_add(opening_bytes))
        .filter(|bytes| *bytes <= MAX_LOGUP_PROOF_BYTES)
        .ok_or(BlsDoryRangeLogUpError::ProofTooLarge)
}

fn append_serialized<T: DorySerialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDoryRangeLogUpError> {
    value
        .serialize_with_mode(output, Compress::Yes)
        .map_err(|_| BlsDoryRangeLogUpError::InvalidEncoding)
}

fn read_serialized<T: DoryDeserialize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<T, BlsDoryRangeLogUpError> {
    T::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryRangeLogUpError::InvalidEncoding)
}

fn read_field_array<const N: usize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<[BlsDoryFr; N], BlsDoryRangeLogUpError> {
    (0..N)
        .map(|_| read_serialized(reader))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| BlsDoryRangeLogUpError::InvalidProofShape)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, BlsDoryRangeLogUpError> {
    Ok(u16::from_le_bytes(
        input
            .get(offset..offset + 2)
            .ok_or(BlsDoryRangeLogUpError::InvalidEncoding)?
            .try_into()
            .map_err(|_| BlsDoryRangeLogUpError::InvalidEncoding)?,
    ))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, BlsDoryRangeLogUpError> {
    Ok(u32::from_le_bytes(
        input
            .get(offset..offset + 4)
            .ok_or(BlsDoryRangeLogUpError::InvalidEncoding)?
            .try_into()
            .map_err(|_| BlsDoryRangeLogUpError::InvalidEncoding)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        StructuredMaskPolynomial, V2_TRANSITION_MODULUS,
        dory_bls12_381_prototype::deterministic_bls_dory_setup,
        dory_bls12_381_transition::prove_bls_dory_transition,
    };

    static SCRATCH_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    struct ScratchDirectory(std::path::PathBuf);

    impl ScratchDirectory {
        fn create() -> Self {
            let nonce = SCRATCH_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-logup-scratch-test-{}-{nonce}",
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

    const OUTPUT_MODULUS: u64 = 251;
    const OUTPUT_CENTER: i64 = 125;

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

    fn scaled_fixture(
        cell_variables: usize,
    ) -> (StructuredTransitionStatement, StructuredTransitionWitness) {
        assert!((3..=26).contains(&cell_variables));
        let (_, _, base) = fixture();
        let columns_variables = cell_variables.min(12);
        let remaining = cell_variables - columns_variables;
        let rows_variables = remaining.min(7);
        let layers_variables = remaining - rows_variables;
        assert!(layers_variables <= 7);
        let elements = 1usize << cell_variables;
        let repeat = |values: &[u64]| values.iter().copied().cycle().take(elements).collect();
        let repeat_signed =
            |values: &[i64]| values.iter().copied().cycle().take(elements).collect();
        let statement = StructuredTransitionStatement {
            layers: 1usize << layers_variables,
            rows: 1usize << rows_variables,
            cols: 1usize << columns_variables,
            max_abs_accumulator: 65_536,
            max_mask: 5_000,
        };
        let witness = StructuredTransitionWitness {
            accumulators: repeat_signed(&base.accumulators),
            masks: repeat(&base.masks),
            encoded: repeat(&base.encoded),
            square_quotients: repeat(&base.square_quotients),
            square_remainders: repeat(&base.square_remainders),
            cube_quotients: repeat(&base.cube_quotients),
            cube_remainders: repeat(&base.cube_remainders),
            output_quotients: repeat(&base.output_quotients),
            output_remainders: repeat(&base.output_remainders),
            negative: repeat(&base.negative),
            activations: repeat_signed(&base.activations),
        };
        (statement, witness)
    }

    fn directory_bytes(path: &Path) -> u64 {
        std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum()
    }

    #[test]
    fn inverse_row_source_matches_materialized_inverse_prefix() {
        let (statement, _, witness) = fixture();
        let variables = minimum_packed_variables(statement).unwrap();
        let (nu, sigma) = dory_layout(variables);
        let rows = 1usize << nu;
        let columns = 1usize << sigma;
        let padded_len = 1usize << variables;
        let elements = statement.elements().unwrap();
        let alpha = BlsDoryFr::from_u64(19);
        let oracles = build_scalar_oracles(statement, &witness).unwrap();
        let mut transition = pack_oracles(&oracles).unwrap();
        transition.resize(padded_len, BlsDoryFr::zero());
        let active = query_active_table(elements, padded_len).unwrap();
        let mut expected = vec![BlsDoryFr::zero(); padded_len];
        for index in 0..padded_len {
            if active[index] == BlsDoryFr::one() {
                expected[index] = (alpha - transition[index]).inv().unwrap();
            }
        }

        let source =
            BlsDoryTransitionWitnessRowSource::new(statement, &witness, rows, columns).unwrap();
        let mut inverse =
            LogUpInverseRowSource::new(&source, alpha, elements, rows, columns).unwrap();
        let explicit = inverse.explicit_scalar_count();
        let mut streamed = Vec::new();
        let mut row = vec![BlsDoryFr::zero(); columns];
        for row_index in 0..explicit.div_ceil(columns) {
            inverse.read_row(row_index, &mut row).unwrap();
            streamed.extend_from_slice(&row);
        }
        streamed.truncate(explicit);
        assert_eq!(streamed, expected[..explicit]);

        let mut indexed =
            LogUpInverseCodeRowSource::new(&source, alpha, elements, rows, columns).unwrap();
        let indexed_explicit = indexed.explicit_scalar_count();
        let dictionary = indexed.dictionary().to_vec();
        let mut decoded = Vec::new();
        let mut codes = vec![0u8; columns];
        for row_index in 0..indexed_explicit.div_ceil(columns) {
            indexed.read_code_row(row_index, &mut codes).unwrap();
            decoded.extend(codes.iter().map(|code| dictionary[usize::from(*code)]));
        }
        decoded.truncate(indexed_explicit);
        assert_eq!(decoded, expected[..indexed_explicit]);
        assert_eq!(decoded, streamed);
    }

    #[test]
    fn mapped_inverse_matches_scalar_without_a_second_coefficient_file() {
        let (statement, _, witness) = fixture();
        let variables = minimum_packed_variables(statement).unwrap();
        let (nu, sigma) = dory_layout(variables);
        let rows = 1usize << nu;
        let columns = 1usize << sigma;
        let elements = statement.elements().unwrap();
        let alpha = BlsDoryFr::from_u64(19);
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let source =
            BlsDoryTransitionWitnessRowSource::new(statement, &witness, rows, columns).unwrap();
        let scalar_scratch = ScratchDirectory::create();
        let indexed_scratch = ScratchDirectory::create();
        let transition_scratch = ScratchDirectory::create();

        let mut scalar_source =
            LogUpInverseRowSource::new(&source, alpha, elements, rows, columns).unwrap();
        let scalar = commit_bls_dory_row_source_with_scratch(
            &mut scalar_source,
            nu,
            sigma,
            &setup,
            &scalar_scratch.0,
        )
        .unwrap();
        let mut indexed_source =
            LogUpInverseCodeRowSource::new(&source, alpha, elements, rows, columns).unwrap();
        let indexed = commit_bls_dory_indexed_row_source_with_scratch(
            &mut indexed_source,
            nu,
            sigma,
            &setup,
            &indexed_scratch.0,
        )
        .unwrap();
        let mut compact_source =
            BlsDoryTransitionWitnessRowSource::new(statement, &witness, rows, columns).unwrap();
        let transition = commit_bls_dory_compact_row_source_with_scratch(
            &mut compact_source,
            nu,
            sigma,
            &setup,
            &transition_scratch.0,
        )
        .unwrap();
        let mapped_dictionary = (0..TABLE_VALUES)
            .map(|digit| (alpha - BlsDoryFr::from_u64(digit as u64)).inv().unwrap())
            .collect::<Vec<_>>();
        let mapped = commit_bls_dory_mapped_compact_polynomial(
            &transition,
            elements * STRUCTURED_TRANSITION_REGULAR_ORACLES,
            mapped_dictionary,
            &setup,
        )
        .unwrap();

        assert_eq!(indexed.commitment(), scalar.commitment());
        assert_eq!(indexed.row_commitments(), scalar.row_commitments());
        assert_eq!(mapped.commitment(), scalar.commitment());
        assert_eq!(mapped.row_commitments(), scalar.row_commitments());
        let mut mapped_coefficients = Vec::new();
        mapped
            .for_each_explicit_coefficient(|_index, coefficient| {
                mapped_coefficients.push(coefficient)
            })
            .unwrap();
        let mut scalar_coefficients = Vec::new();
        scalar
            .for_each_explicit_coefficient(|_index, coefficient| {
                scalar_coefficients.push(coefficient)
            })
            .unwrap();
        assert_eq!(mapped_coefficients, scalar_coefficients);
        let scalar_bytes = std::fs::metadata(scalar.coefficient_artifact_path().unwrap())
            .unwrap()
            .len();
        let indexed_bytes = std::fs::metadata(indexed.coefficient_artifact_path().unwrap())
            .unwrap()
            .len();
        let explicit = u64::try_from(elements * STRUCTURED_TRANSITION_ORACLES).unwrap();
        assert_eq!(indexed_bytes, explicit + 72 + 17 * 32 + 32);
        assert!(indexed_bytes * 10 < scalar_bytes);
        let transition_path = transition
            .coefficient_artifact_path()
            .unwrap()
            .to_path_buf();
        assert_eq!(
            mapped.coefficient_artifact_path(),
            Some(transition_path.as_path())
        );
        assert_eq!(std::fs::read_dir(&transition_scratch.0).unwrap().count(), 1);

        drop(scalar);
        drop(indexed);
        drop(transition);
        assert!(transition_path.exists());
        drop(mapped);
        assert!(!transition_path.exists());
        assert_eq!(std::fs::read_dir(&scalar_scratch.0).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&indexed_scratch.0).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&transition_scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn witness_reconstruction_matches_materialized_tables() {
        let (statement, _, witness) = fixture();
        let variables = minimum_packed_variables(statement).unwrap();
        let (nu, sigma) = dory_layout(variables);
        let source = BlsDoryTransitionWitnessRowSource::new(
            statement,
            &witness,
            1usize << nu,
            1usize << sigma,
        )
        .unwrap();
        let oracles = build_scalar_oracles(statement, &witness).unwrap();
        let cell_point = [
            BlsDoryFr::from_u64(3),
            BlsDoryFr::from_u64(5),
            BlsDoryFr::from_u64(7),
        ];
        let spec_point = [
            BlsDoryFr::from_u64(11),
            BlsDoryFr::from_u64(13),
            BlsDoryFr::from_u64(17),
        ];
        let slack_mixing = BlsDoryFr::from_u64(23);
        let materialized =
            reconstruction_tables(statement, &oracles, &cell_point, &spec_point, slack_mixing)
                .unwrap();
        let streamed = reconstruction_tables_from_witness(
            statement,
            &source,
            &cell_point,
            &spec_point,
            slack_mixing,
        )
        .unwrap();
        assert_eq!(streamed.source_weights, materialized.source_weights);
        assert_eq!(streamed.digit_weights, materialized.digit_weights);
        assert_eq!(streamed.role_values, materialized.role_values);
        assert_eq!(streamed.maximum_evaluation, materialized.maximum_evaluation);
    }

    #[test]
    fn indexed_equality_weights_match_canonical_iterator_order() {
        let point = (0..7)
            .map(|index| BlsDoryFr::from_u64(index * 13 + 3))
            .collect::<Vec<_>>();
        let iterated = LogUpEqualityWeightIterator::new(&point).collect::<Vec<_>>();
        let indexed = (0..1usize << point.len())
            .map(|index| logup_equality_weight_at(&point, index).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(indexed, iterated);
        assert!(matches!(
            logup_equality_weight_at(&point, indexed.len()),
            Err(BlsDoryRangeLogUpError::InvalidDimensions)
        ));
    }

    #[test]
    fn batched_logup_inversion_matches_individual_inverses_and_rejects_zero() {
        let original = (1..=257)
            .map(|value| BlsDoryFr::from_u64(value * 17))
            .collect::<Vec<_>>();
        let expected = original
            .iter()
            .map(|value| value.inv().unwrap())
            .collect::<Vec<_>>();
        let mut batched = original;
        batch_invert_logup_denominators(&mut batched).unwrap();
        assert_eq!(batched, expected);

        let mut with_zero = vec![BlsDoryFr::one(), BlsDoryFr::zero()];
        assert!(matches!(
            batch_invert_logup_denominators(&mut with_zero),
            Err(BlsDoryRangeLogUpError::ChallengeCollision)
        ));
    }

    #[test]
    fn parallel_raw_fold_preserves_serial_order_and_cleans_on_error() {
        let (statement, witness) = scaled_fixture(4);
        let packed_variables = 11;
        let (nu, sigma) = dory_layout(packed_variables);
        let source = BlsDoryTransitionWitnessRowSource::new(
            statement,
            &witness,
            1usize << nu,
            1usize << sigma,
        )
        .unwrap();
        let elements = statement.elements().unwrap();
        let selector_rows = 1usize << (packed_variables - elements.ilog2() as usize);
        let alpha = BlsDoryFr::from_u64(19);
        let challenge = BlsDoryFr::from_u64(23);
        let scratch_directory = ScratchDirectory::create();
        let challenges = [challenge];
        let artifact = LogUpLineageArtifact::Compressed(
            fold_raw_logup_values_compressed(
                &source,
                alpha,
                &challenges,
                selector_rows,
                elements,
                [3; 32],
                [9; 32],
                &scratch_directory.0,
            )
            .unwrap(),
        );
        let mut parallel = Vec::new();
        for_each_logup_lineage_value(
            &artifact,
            LogUpLineageReadSpec {
                context_digest: [3; 32],
                generation: 1,
                selector_rows,
                current_cells: elements / 2,
                parent_digest: [9; 32],
                alpha,
                challenges: &challenges,
            },
            |_value_index, values| {
                parallel.push(values.transition);
                parallel.push(values.inverse);
                Ok(())
            },
        )
        .unwrap();
        let mut serial = Vec::new();
        for selector in 0..STRUCTURED_TRANSITION_ORACLES {
            for child_cell in 0..elements / 2 {
                let lower =
                    raw_logup_fold_values(&source, alpha, selector, child_cell * 2).unwrap();
                let upper =
                    raw_logup_fold_values(&source, alpha, selector, child_cell * 2 + 1).unwrap();
                serial.push(lower.transition + challenge * (upper.transition - lower.transition));
                serial.push(lower.inverse + challenge * (upper.inverse - lower.inverse));
            }
        }
        assert_eq!(parallel, serial);
        drop(artifact);
        assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 0);

        let collision_alpha = source
            .scalar(STRUCTURED_TRANSITION_REGULAR_ORACLES, 0)
            .unwrap();
        assert!(matches!(
            fold_raw_logup_values_compressed(
                &source,
                collision_alpha,
                &challenges,
                selector_rows,
                elements,
                [3; 32],
                [9; 32],
                &scratch_directory.0,
            ),
            Err(BlsDoryRangeLogUpError::ChallengeCollision)
        ));
        assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 0);
    }

    #[test]
    fn second_compressed_fold_matches_scalar_order_and_binds_challenges() {
        let (statement, witness) = scaled_fixture(4);
        let packed_variables = 11;
        let (nu, sigma) = dory_layout(packed_variables);
        let source = BlsDoryTransitionWitnessRowSource::new(
            statement,
            &witness,
            1usize << nu,
            1usize << sigma,
        )
        .unwrap();
        let elements = statement.elements().unwrap();
        let selector_rows = 1usize << (packed_variables - elements.ilog2() as usize);
        let alpha = BlsDoryFr::from_u64(19);
        let challenges = [BlsDoryFr::from_u64(23), BlsDoryFr::from_u64(29)];
        let scratch_directory = ScratchDirectory::create();
        let first = fold_raw_logup_values_compressed(
            &source,
            alpha,
            &challenges[..1],
            selector_rows,
            elements,
            [3; 32],
            [9; 32],
            &scratch_directory.0,
        )
        .unwrap();
        let first_digest = first.digest();
        let second = fold_compressed_logup_artifact(
            &first,
            alpha,
            &challenges,
            selector_rows,
            elements / 2,
            [3; 32],
            [9; 32],
            &scratch_directory.0,
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(second.path()).unwrap().len(),
            compressed_logup_spec(
                [3; 32],
                2,
                selector_rows,
                elements / 4,
                first_digest,
                alpha,
                &challenges,
            )
            .unwrap()
            .encoded_bytes()
            .unwrap()
        );

        let lineage = LogUpLineageArtifact::Compressed(second);
        let expected = LogUpLineageReadSpec {
            context_digest: [3; 32],
            generation: 2,
            selector_rows,
            current_cells: elements / 4,
            parent_digest: first_digest,
            alpha,
            challenges: &challenges,
        };
        let mut compressed = Vec::new();
        for_each_logup_lineage_value(&lineage, expected, |_index, values| {
            compressed.push((values.transition, values.inverse));
            Ok(())
        })
        .unwrap();

        let mut scalar = Vec::new();
        for selector in 0..STRUCTURED_TRANSITION_ORACLES {
            for child_cell in 0..elements / 4 {
                let mut level = [LogUpFoldValues {
                    transition: BlsDoryFr::zero(),
                    inverse: BlsDoryFr::zero(),
                }; 4];
                for (offset, values) in level.iter_mut().enumerate() {
                    *values =
                        raw_logup_fold_values(&source, alpha, selector, child_cell * 4 + offset)
                            .unwrap();
                }
                let lower = interpolate_logup_fold_values(level[0], level[1], challenges[0]);
                let upper = interpolate_logup_fold_values(level[2], level[3], challenges[0]);
                let values = interpolate_logup_fold_values(lower, upper, challenges[1]);
                scalar.push((values.transition, values.inverse));
            }
        }
        assert_eq!(compressed, scalar);

        let wrong_challenges = [challenges[0], challenges[1] + BlsDoryFr::one()];
        assert!(
            for_each_logup_lineage_value(
                &lineage,
                LogUpLineageReadSpec {
                    challenges: &wrong_challenges,
                    ..expected
                },
                |_index, _values| Ok(()),
            )
            .is_err()
        );
        drop(lineage);
        drop(first);
        assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 0);
    }

    #[test]
    fn fourth_compressed_fold_matches_scalar_order_and_bounds_live_artifacts() {
        let (statement, witness) = scaled_fixture(4);
        let packed_variables = 11;
        let (nu, sigma) = dory_layout(packed_variables);
        let source = BlsDoryTransitionWitnessRowSource::new(
            statement,
            &witness,
            1usize << nu,
            1usize << sigma,
        )
        .unwrap();
        let elements = statement.elements().unwrap();
        let selector_rows = 1usize << (packed_variables - elements.ilog2() as usize);
        let alpha = BlsDoryFr::from_u64(19);
        let challenges = [
            BlsDoryFr::from_u64(23),
            BlsDoryFr::from_u64(29),
            BlsDoryFr::from_u64(31),
            BlsDoryFr::from_u64(37),
        ];
        let scratch_directory = ScratchDirectory::create();
        let root_parent = [9; 32];
        let first = fold_raw_logup_values_compressed(
            &source,
            alpha,
            &challenges[..1],
            selector_rows,
            elements,
            [3; 32],
            root_parent,
            &scratch_directory.0,
        )
        .unwrap();
        let first_digest = first.digest();
        let second = fold_compressed_logup_artifact(
            &first,
            alpha,
            &challenges[..2],
            selector_rows,
            elements / 2,
            [3; 32],
            root_parent,
            &scratch_directory.0,
        )
        .unwrap();
        drop(first);
        assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 1);
        let second_digest = second.digest();
        let third = fold_compressed_logup_artifact(
            &second,
            alpha,
            &challenges[..3],
            selector_rows,
            elements / 4,
            [3; 32],
            first_digest,
            &scratch_directory.0,
        )
        .unwrap();
        drop(second);
        assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 1);
        let third_digest = third.digest();
        let fourth = fold_compressed_logup_artifact(
            &third,
            alpha,
            &challenges,
            selector_rows,
            elements / 8,
            [3; 32],
            second_digest,
            &scratch_directory.0,
        )
        .unwrap();
        drop(third);
        assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 1);
        assert_eq!(
            std::fs::metadata(fourth.path()).unwrap().len(),
            compressed_logup_spec(
                [3; 32],
                4,
                selector_rows,
                elements / 16,
                third_digest,
                alpha,
                &challenges,
            )
            .unwrap()
            .encoded_bytes()
            .unwrap()
        );

        let lineage = LogUpLineageArtifact::Compressed(fourth);
        let expected = LogUpLineageReadSpec {
            context_digest: [3; 32],
            generation: 4,
            selector_rows,
            current_cells: elements / 16,
            parent_digest: third_digest,
            alpha,
            challenges: &challenges,
        };
        let mut compressed = Vec::new();
        for_each_logup_lineage_value(&lineage, expected, |_index, values| {
            compressed.push((values.transition, values.inverse));
            Ok(())
        })
        .unwrap();

        let mut scalar = Vec::new();
        for selector in 0..STRUCTURED_TRANSITION_ORACLES {
            for child_cell in 0..elements / 16 {
                let mut level = (0..16)
                    .map(|offset| {
                        raw_logup_fold_values(&source, alpha, selector, child_cell * 16 + offset)
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                for challenge in challenges {
                    for index in 0..level.len() / 2 {
                        level[index] = interpolate_logup_fold_values(
                            level[index * 2],
                            level[index * 2 + 1],
                            challenge,
                        );
                    }
                    level.truncate(level.len() / 2);
                }
                scalar.push((level[0].transition, level[0].inverse));
            }
        }
        assert_eq!(compressed, scalar);

        let mut wrong_challenges = challenges;
        wrong_challenges[3] = wrong_challenges[3] + BlsDoryFr::one();
        assert!(
            for_each_logup_lineage_value(
                &lineage,
                LogUpLineageReadSpec {
                    challenges: &wrong_challenges,
                    ..expected
                },
                |_index, _values| Ok(()),
            )
            .is_err()
        );
        drop(lineage);
        assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 0);
    }

    #[test]
    fn scratch_logup_matches_dense_proof_and_cleans_artifacts() {
        let (statement, _, witness) = fixture();
        let setup = deterministic_bls_dory_setup(11).unwrap();
        let scratch_directory = ScratchDirectory::create();
        for packed_variables in [10, 11] {
            let ordinary = prove_bls_dory_range_logup_deferred_at_variables(
                b"scratch-logup",
                statement,
                &witness,
                packed_variables,
                &setup,
            )
            .unwrap();
            let scratch = prove_bls_dory_range_logup_deferred_at_variables_with_scratch(
                b"scratch-logup",
                statement,
                &witness,
                packed_variables,
                &setup,
                &scratch_directory.0,
            )
            .unwrap();
            assert_eq!(scratch.proof, ordinary.proof);
            assert_eq!(scratch.openings.claims(), ordinary.openings.claims());
            drop(scratch);
            assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 0);
        }
    }

    #[test]
    fn scratch_logup_linear_artifacts_match_dense_proof_and_clean_up() {
        let (statement, witness) = scaled_fixture(4);
        let setup = deterministic_bls_dory_setup(12).unwrap();
        let scratch_directory = ScratchDirectory::create();
        for packed_variables in [11, 12] {
            let ordinary = prove_bls_dory_range_logup_deferred_at_variables(
                b"scratch-logup-linear",
                statement,
                &witness,
                packed_variables,
                &setup,
            )
            .unwrap();
            let scratch = prove_bls_dory_range_logup_deferred_at_variables_with_scratch(
                b"scratch-logup-linear",
                statement,
                &witness,
                packed_variables,
                &setup,
                &scratch_directory.0,
            )
            .unwrap();
            assert_eq!(scratch.proof, ordinary.proof);
            assert_eq!(scratch.openings.claims(), ordinary.openings.claims());
            drop(scratch);
            assert_eq!(std::fs::read_dir(&scratch_directory.0).unwrap().count(), 0);
        }
    }

    #[test]
    #[ignore = "release-only scaling benchmark selected through CMFD_BLS_LOGUP_BENCH_* variables"]
    fn scratch_logup_release_scaling_benchmark() {
        let cell_variables = std::env::var("CMFD_BLS_LOGUP_BENCH_CELL_LOG")
            .expect("CMFD_BLS_LOGUP_BENCH_CELL_LOG is required")
            .parse::<usize>()
            .expect("cell log must be an integer");
        let scratch_directory = std::path::PathBuf::from(
            std::env::var("CMFD_BLS_LOGUP_BENCH_SCRATCH")
                .expect("CMFD_BLS_LOGUP_BENCH_SCRATCH is required"),
        );
        assert!(scratch_directory.is_absolute());
        assert!(scratch_directory.is_dir());
        assert_eq!(std::fs::read_dir(&scratch_directory).unwrap().count(), 0);

        let witness_start = std::time::Instant::now();
        let (statement, witness) = scaled_fixture(cell_variables);
        let witness_millis = witness_start.elapsed().as_millis();
        let packed_variables = cell_variables + BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES;

        let setup_start = std::time::Instant::now();
        let setup = deterministic_bls_dory_setup(packed_variables).unwrap();
        let setup_millis = setup_start.elapsed().as_millis();

        let prover_start = std::time::Instant::now();
        let prepared = prove_bls_dory_range_logup_deferred_at_variables_with_scratch(
            b"logup-scaling-benchmark",
            statement,
            &witness,
            packed_variables,
            &setup,
            &scratch_directory,
        )
        .unwrap();
        let prover_millis = prover_start.elapsed().as_millis();
        let prepared_scratch_bytes = directory_bytes(&scratch_directory);

        let opening_start = std::time::Instant::now();
        let opening_binding = opening_binding(
            b"logup-scaling-benchmark",
            &prepared.proof.transcript_digest,
        );
        let expected_claims = prepared.openings.claims().to_vec();
        let mut proof = prepared.proof;
        let (claims, opening_proof) =
            crate::dory_bls12_381_aggregate::prove_bls_dory_deferred_opening_sets_consuming_with_scratch(
                &opening_binding,
                vec![prepared.openings],
                &setup,
                &scratch_directory,
            )
            .unwrap();
        assert_eq!(claims, expected_claims);
        proof.opening_proof = opening_proof;
        let opening_millis = opening_start.elapsed().as_millis();

        let verification_start = std::time::Instant::now();
        verify_bls_dory_range_logup_at_variables(
            b"logup-scaling-benchmark",
            statement,
            proof.transition_commitment,
            &proof,
            packed_variables,
            &setup,
        )
        .unwrap();
        let verification_millis = verification_start.elapsed().as_millis();
        let proof_bytes = proof.encode(statement).unwrap().len();
        let retained_scratch_bytes = directory_bytes(&scratch_directory);

        println!(
            "CMFD_BLS_LOGUP_BENCHMARK {{\"cell_variables\":{cell_variables},\"cells\":{},\"packed_variables\":{packed_variables},\"witness_millis\":{witness_millis},\"setup_millis\":{setup_millis},\"prover_millis\":{prover_millis},\"prepared_scratch_bytes\":{prepared_scratch_bytes},\"opening_millis\":{opening_millis},\"verification_millis\":{verification_millis},\"proof_bytes\":{proof_bytes},\"retained_scratch_bytes\":{retained_scratch_bytes}}}",
            statement.elements().unwrap()
        );

        assert_eq!(std::fs::read_dir(&scratch_directory).unwrap().count(), 0);
    }

    #[test]
    fn packed_ranges_reduce_to_four_authenticated_openings() {
        let (statement, mask, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let transition =
            prove_bls_dory_transition(b"same-transition", statement, &mask, &witness, &setup)
                .unwrap();
        let proof =
            prove_bls_dory_range_logup(b"same-transition", statement, &witness, &setup).unwrap();
        assert_eq!(proof.transition_commitment, transition.oracle_commitment);
        verify_bls_dory_range_logup(
            b"same-transition",
            statement,
            transition.oracle_commitment,
            &proof,
            &setup,
        )
        .unwrap();
        assert_eq!(proof.rounds.len(), 10);
        assert_eq!(proof.opening_proof.len(), 21_775);
        let encoded = proof.encode(statement).unwrap();
        assert_eq!(encoded.len(), 25_985);
        let decoded = BlsDoryRangeLogUpProof::decode(&encoded, statement).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn out_of_table_digit_cannot_satisfy_the_zero_claim() {
        let (statement, _, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let mut oracles = build_scalar_oracles(statement, &witness).unwrap();
        oracles[STRUCTURED_TRANSITION_REGULAR_ORACLES][0] = BlsDoryFr::from_u64(16);
        assert_eq!(
            prove_from_oracles(b"invalid-digit", statement, &oracles, 10, &setup),
            Err(BlsDoryRangeLogUpError::RoundClaim)
        );
    }

    #[test]
    fn in_range_digit_tampering_cannot_satisfy_reconstruction() {
        let (statement, _, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let mut oracles = build_scalar_oracles(statement, &witness).unwrap();
        let digit = &mut oracles[STRUCTURED_TRANSITION_REGULAR_ORACLES][0];
        *digit = if *digit == BlsDoryFr::zero() {
            BlsDoryFr::one()
        } else {
            BlsDoryFr::zero()
        };
        assert_eq!(
            prove_from_oracles(b"invalid-reconstruction", statement, &oracles, 10, &setup),
            Err(BlsDoryRangeLogUpError::RoundClaim)
        );
    }

    #[test]
    fn transcript_commitments_terminals_and_opening_are_bound() {
        let (statement, _, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let proof = prove_bls_dory_range_logup(b"binding-a", statement, &witness, &setup).unwrap();
        assert!(
            verify_bls_dory_range_logup(
                b"binding-b",
                statement,
                proof.transition_commitment,
                &proof,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.rounds[0][0] = changed.rounds[0][0] + BlsDoryFr::one();
        assert!(
            verify_bls_dory_range_logup(
                b"binding-a",
                statement,
                proof.transition_commitment,
                &changed,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.terminal_evaluations[0] = changed.terminal_evaluations[0] + BlsDoryFr::one();
        assert!(
            verify_bls_dory_range_logup(
                b"binding-a",
                statement,
                proof.transition_commitment,
                &changed,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.source_claim = changed.source_claim + BlsDoryFr::one();
        assert!(
            verify_bls_dory_range_logup(
                b"binding-a",
                statement,
                proof.transition_commitment,
                &changed,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.reconstruction_rounds[0][0] =
            changed.reconstruction_rounds[0][0] + BlsDoryFr::one();
        assert!(
            verify_bls_dory_range_logup(
                b"binding-a",
                statement,
                proof.transition_commitment,
                &changed,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.reconstruction_evaluation = changed.reconstruction_evaluation + BlsDoryFr::one();
        assert!(
            verify_bls_dory_range_logup(
                b"binding-a",
                statement,
                proof.transition_commitment,
                &changed,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.multiplicity_commitment = changed
            .multiplicity_commitment
            .scale(&BlsDoryFr::from_u64(2));
        assert!(
            verify_bls_dory_range_logup(
                b"binding-a",
                statement,
                proof.transition_commitment,
                &changed,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.inverse_commitment = changed.inverse_commitment.scale(&BlsDoryFr::from_u64(2));
        assert!(
            verify_bls_dory_range_logup(
                b"binding-a",
                statement,
                proof.transition_commitment,
                &changed,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.opening_proof[0] ^= 1;
        assert!(
            verify_bls_dory_range_logup(
                b"binding-a",
                statement,
                proof.transition_commitment,
                &changed,
                &setup,
            )
            .is_err()
        );
    }

    #[test]
    fn parser_and_production_gate_remain_fail_closed() {
        let (statement, _, witness) = fixture();
        let setup = deterministic_bls_dory_setup(10).unwrap();
        let proof = prove_bls_dory_range_logup(b"parser", statement, &witness, &setup).unwrap();
        let encoded = proof.encode(statement).unwrap();
        assert!(BlsDoryRangeLogUpProof::decode_with_variables(&encoded, statement, 11).is_err());

        let mut wrong_rounds = encoded.clone();
        wrong_rounds[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            BlsDoryRangeLogUpProof::decode(&wrong_rounds, statement),
            Err(BlsDoryRangeLogUpError::InvalidProofShape)
        );
        let mut wrong_opening = encoded.clone();
        wrong_opening[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            BlsDoryRangeLogUpProof::decode(&wrong_opening, statement),
            Err(BlsDoryRangeLogUpError::InvalidProofShape)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            BlsDoryRangeLogUpProof::decode(&trailing, statement),
            Err(BlsDoryRangeLogUpError::InvalidProofShape)
        );

        assert_eq!(BLS_DORY_RANGE_LOGUP_MEMBERSHIP_CLAIMS, 3);
        assert_eq!(BLS_DORY_RANGE_LOGUP_RECONSTRUCTION_CLAIMS, 1);
        assert_eq!(BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS, 4);
        assert_eq!(PRODUCTION_BLS_DORY_RANGE_LOGUP_VARIABLES, 33);
        assert_eq!(
            projected_production_range_logup_opening_bytes().unwrap(),
            70_639
        );
        assert_eq!(
            projected_production_range_logup_proof_bytes().unwrap(),
            78_529
        );
        assert_eq!(
            projected_production_range_logup_inverse_artifact_bytes().unwrap(),
            0
        );
        assert_eq!(
            projected_production_transition_range_source_bytes().unwrap(),
            13_019_120_248
        );
        assert_eq!(
            projected_production_range_logup_compressed_lineage_bytes().unwrap(),
            [16_173_236_396, 9_730_785_452, 6_509_559_980, 4_898_947_244,]
        );
        assert_eq!(
            projected_production_range_logup_early_lineage_peak_bytes().unwrap(),
            25_904_021_848
        );
        assert_eq!(
            projected_production_range_logup_four_pair_peak_bytes().unwrap(),
            77_980_502_840
        );
        assert_eq!(BLS_DORY_RANGE_LOGUP_PRODUCTION_BLOCKERS.len(), 3);
        assert_eq!(
            require_bls_dory_range_logup_production_ready(),
            Err(BlsDoryRangeLogUpError::NotProductionReady)
        );
    }
}
