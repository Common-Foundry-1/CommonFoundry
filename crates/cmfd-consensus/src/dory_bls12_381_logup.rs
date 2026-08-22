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

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use thiserror::Error;

use crate::{
    STRUCTURED_TRANSITION_ORACLES, STRUCTURED_TRANSITION_REGULAR_ORACLES,
    StructuredTransitionError, StructuredTransitionStatement, StructuredTransitionWitness,
    dory_bls12_381_aggregate::{
        BlsDoryAggregateError, BlsDoryDeferredOpeningSet, BlsDoryOpeningClaim,
        MAX_BLS_DORY_AGGREGATE_BYTES, commit_bls_dory_padded_prefix_with_optional_scratch,
        commit_bls_dory_row_source_with_scratch, projected_bls_dory_aggregate_bytes,
        prove_bls_dory_deferred_opening_sets, verify_bls_dory_openings,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    dory_bls12_381_streaming::BlsDoryRowSource,
    dory_bls12_381_transition::{
        BlsDoryTransitionError, BlsDoryTransitionWitnessRowSource, build_scalar_oracles,
        pack_oracles,
    },
    structured_transition::structured_transition_range_specs,
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
    "the scratch LogUp prover streams commitments and recomputes cell-variable rounds with bounded memory, but complete n=33 proving latency, peak memory and scratch use, proof size, and verification latency remain unmeasured",
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
    )
}

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
    if matches!(source, LogUpProverSource::Witness(_)) != scratch_directory.is_some() {
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
    let transition = if let Some(scratch_directory) = scratch_directory {
        commit_bls_dory_row_source_with_scratch(
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
                    let value = witness_source.scalar(oracle, index)?;
                    let digit = (0..TABLE_VALUES)
                        .find(|digit| value == BlsDoryFr::from_u64(*digit as u64))
                        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
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
    let inverse = if let Some(scratch_directory) = scratch_directory {
        let mut inverse_source = LogUpInverseRowSource::new(
            witness_source
                .as_ref()
                .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
            alpha,
            elements,
            rows,
            columns,
        )?;
        commit_bls_dory_row_source_with_scratch(
            &mut inverse_source,
            nu,
            sigma,
            setup,
            scratch_directory,
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
            let output = prove_logup_sumcheck_with_recomputation(
                witness_source
                    .as_ref()
                    .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?,
                &counts,
                alpha,
                elements,
                packed_variables,
                &equality_point,
                &local_mixing,
                rational_mixing,
                count_mixing,
                &mut transcript,
            )?;
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

struct LogUpInverseRowSource<'a, 'w> {
    transition: &'a BlsDoryTransitionWitnessRowSource<'w>,
    alpha: BlsDoryFr,
    elements: usize,
    rows: usize,
    columns: usize,
    explicit_scalars: usize,
}

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
        })
    }
}

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
        for (column, scalar) in output.iter_mut().enumerate() {
            let packed_index = start + column;
            let oracle = packed_index / self.elements;
            let index = packed_index % self.elements;
            *scalar = if (STRUCTURED_TRANSITION_REGULAR_ORACLES..STRUCTURED_TRANSITION_ORACLES)
                .contains(&oracle)
            {
                (self.alpha - self.transition.scalar(oracle, index)?)
                    .inv()
                    .ok_or(BlsDoryRangeLogUpError::ChallengeCollision)?
            } else {
                BlsDoryFr::zero()
            };
        }
        Ok(output.len())
    }
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
        assert_eq!(BLS_DORY_RANGE_LOGUP_PRODUCTION_BLOCKERS.len(), 3);
        assert_eq!(
            require_bls_dory_range_logup_production_ready(),
            Err(BlsDoryRangeLogUpError::NotProductionReady)
        );
    }
}
