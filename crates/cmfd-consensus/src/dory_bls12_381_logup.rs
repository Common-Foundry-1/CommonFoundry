//! BLS12-381 LogUp checkpoint for packed transition range digits.
//!
//! The 98 value/slack digit lanes already occupy selector slots in the packed
//! transition commitment. This argument commits their `0..15` table
//! multiplicities before sampling the lookup challenge, proves the logarithmic
//! derivative identity with one inverse polynomial, and reduces membership to
//! three Dory openings. Source/slack reconstruction remains a separate gate.

use std::io::Cursor;

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
        BlsDoryAggregateError, BlsDoryOpeningClaim, MAX_BLS_DORY_AGGREGATE_BYTES,
        commit_bls_dory_polynomial, projected_bls_dory_aggregate_bytes, prove_bls_dory_openings,
        verify_bls_dory_openings,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    dory_bls12_381_transition::{BlsDoryTransitionError, build_scalar_oracles, pack_oracles},
};

/// Version of the scalar LogUp transcript.
pub const BLS_DORY_RANGE_LOGUP_VERSION: u16 = 1;
/// Seven bits select the 110 used transition roles inside 128 slots.
pub const BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES: usize = 7;
/// Production transition cells have 26 variables and seven selector variables.
pub const PRODUCTION_BLS_DORY_RANGE_LOGUP_VARIABLES: usize = 33;
/// Membership reduces to the transition, multiplicity, and inverse commitments.
pub const BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS: usize = 3;
/// This checkpoint is not accepted by consensus.
pub const BLS_DORY_RANGE_LOGUP_PRODUCTION_READY: bool = false;
/// Remaining gates before this can replace the direct range terminals.
pub const BLS_DORY_RANGE_LOGUP_PRODUCTION_BLOCKERS: [&str; 5] = [
    "digit and slack reconstruction is not yet linked to the regular transition source roles",
    "the direct transition argument still opens all 110 terminal roles",
    "the three LogUp openings are not yet folded into the block-wide shared Dory aggregate",
    "the n=33 transition, multiplicity, and inverse polynomials are not streamed",
    "the lookup soundness accounting, transcript, and implementation have not received independent audit",
];

const PROOF_MAGIC: [u8; 8] = *b"CFBLSL01";
const PROOF_HEADER_BYTES: usize = 18;
const MAX_LOGUP_PROOF_BYTES: usize = 262_128;
const MAX_LOGUP_BINDING_BYTES: usize = 4_096;
const LOGUP_ROUND_DEGREE: usize = 4;
const LOGUP_ROUND_VALUES: usize = LOGUP_ROUND_DEGREE + 1;
const LOGUP_TERMINALS: usize = 3;
const TABLE_VALUES: usize = 16;
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
    pub transcript_digest: [u8; 32],
    pub opening_proof: Vec<u8>,
}

impl BlsDoryRangeLogUpProof {
    /// Encode the statement-derived proof shape canonically.
    pub fn encode(
        &self,
        statement: StructuredTransitionStatement,
    ) -> Result<Vec<u8>, BlsDoryRangeLogUpError> {
        validate_proof_shape(statement, self, usize::from(self.packed_variables))?;
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
            || opening_len == 0
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
            transcript_digest,
            opening_proof,
        };
        if proof.encode(statement)? != encoded {
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

/// Fail closed while the membership checkpoint is not the complete range argument.
pub fn require_bls_dory_range_logup_production_ready() -> Result<(), BlsDoryRangeLogUpError> {
    Err(BlsDoryRangeLogUpError::NotProductionReady)
}

/// Project the one shared Dory opening payload at production geometry.
pub fn projected_production_range_logup_opening_bytes() -> Result<usize, BlsDoryRangeLogUpError> {
    projected_bls_dory_aggregate_bytes(PRODUCTION_BLS_DORY_RANGE_LOGUP_VARIABLES)
        .map_err(BlsDoryRangeLogUpError::Aggregate)
}

/// Project the complete membership-only outer proof at production geometry.
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

fn prove_from_oracles(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    oracles: &[Vec<BlsDoryFr>],
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryRangeLogUpProof, BlsDoryRangeLogUpError> {
    if binding.len() > MAX_LOGUP_BINDING_BYTES {
        return Err(BlsDoryRangeLogUpError::PublicBindingTooLarge);
    }
    statement.validate_verifier_shape()?;
    let elements = statement.elements()?;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryRangeLogUpError::InvalidDimensions);
    }
    let padded_len = 1usize
        .checked_shl(packed_variables as u32)
        .ok_or(BlsDoryRangeLogUpError::InvalidDimensions)?;
    let mut transition_coefficients = pack_oracles(oracles)?;
    transition_coefficients.resize(padded_len, BlsDoryFr::zero());
    let (nu, sigma) = dory_layout(packed_variables);
    let transition = commit_bls_dory_polynomial(transition_coefficients.clone(), nu, sigma, setup)?;

    let mut counts = [0_u64; TABLE_VALUES];
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
    let mut multiplicity_coefficients = vec![BlsDoryFr::zero(); padded_len];
    for (index, count) in counts.into_iter().enumerate() {
        multiplicity_coefficients[index] = BlsDoryFr::from_u64(count);
    }
    let multiplicity =
        commit_bls_dory_polynomial(multiplicity_coefficients.clone(), nu, sigma, setup)?;

    let mut transcript = logup_transcript(
        binding,
        statement,
        packed_variables,
        &setup.identity(),
        &transition.commitment(),
        &multiplicity.commitment(),
    );
    let alpha = transcript.challenge_scalar(b"lookup-alpha");
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
    let inverse = commit_bls_dory_polynomial(inverse_coefficients.clone(), nu, sigma, setup)?;
    transcript.append_group(b"inverse-commitment", &inverse.commitment());
    let local_mixing = challenge_vector(&mut transcript, b"local-mixing", 3);
    let rational_mixing = transcript.challenge_scalar(b"rational-mixing");
    let count_mixing = transcript.challenge_scalar(b"count-mixing");
    let equality_point = challenge_vector(&mut transcript, b"equality-point", packed_variables);
    let equality = equality_table(&equality_point);

    let mut tables = LogUpTables {
        transition: transition_coefficients,
        multiplicity: multiplicity_coefficients,
        inverse: inverse_coefficients,
        active,
        table,
        table_inverse,
        equality,
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
    let expected = logup_constraint(
        TerminalValues {
            transition: terminal_evaluations[0],
            multiplicity: terminal_evaluations[1],
            inverse: terminal_evaluations[2],
            active: tables.active[0],
            table: tables.table[0],
            table_inverse: tables.table_inverse[0],
            equality: tables.equality[0],
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
        &terminal_evaluations,
    );
    let transcript_digest = transcript.digest();
    let opening_binding = opening_binding(binding, &transcript_digest);
    let points = vec![sumcheck_point; BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS];
    let expected_commitments = [
        transition.commitment(),
        multiplicity.commitment(),
        inverse.commitment(),
    ];
    let (claims, opening_proof) = prove_bls_dory_openings(
        &opening_binding,
        &[transition, multiplicity, inverse],
        &points,
        setup,
    )?;
    let commitments = claims
        .iter()
        .map(|claim| claim.commitment)
        .collect::<Vec<_>>();
    if commitments.as_slice() != expected_commitments
        || claims
            .iter()
            .zip(terminal_evaluations)
            .any(|(claim, evaluation)| claim.evaluation != evaluation)
    {
        return Err(BlsDoryRangeLogUpError::Opening);
    }

    Ok(BlsDoryRangeLogUpProof {
        protocol_version: BLS_DORY_RANGE_LOGUP_VERSION,
        packed_variables: u16::try_from(packed_variables)
            .map_err(|_| BlsDoryRangeLogUpError::InvalidDimensions)?,
        transition_commitment: expected_commitments[0],
        multiplicity_commitment: expected_commitments[1],
        inverse_commitment: expected_commitments[2],
        rounds,
        terminal_evaluations,
        transcript_digest,
        opening_proof,
    })
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
    if binding.len() > MAX_LOGUP_BINDING_BYTES {
        return Err(BlsDoryRangeLogUpError::PublicBindingTooLarge);
    }
    statement.validate_verifier_shape()?;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    validate_proof_shape(statement, proof, packed_variables)?;
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
    if transcript.digest() != proof.transcript_digest {
        return Err(BlsDoryRangeLogUpError::Transcript);
    }
    let claims = [
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
    ];
    let opening_binding = opening_binding(binding, &proof.transcript_digest);
    verify_bls_dory_openings(&opening_binding, &claims, &proof.opening_proof, setup)?;
    Ok(())
}

fn validate_proof_shape(
    statement: StructuredTransitionStatement,
    proof: &BlsDoryRangeLogUpProof,
    expected_variables: usize,
) -> Result<(), BlsDoryRangeLogUpError> {
    statement.validate_verifier_shape()?;
    validate_target_variables(minimum_packed_variables(statement)?, expected_variables)?;
    if proof.protocol_version != BLS_DORY_RANGE_LOGUP_VERSION
        || usize::from(proof.packed_variables) != expected_variables
        || proof.rounds.len() != expected_variables
        || proof.opening_proof.is_empty()
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
    fn packed_digits_reduce_to_three_authenticated_openings() {
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
        assert_eq!(encoded.len(), 25_249);
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

        assert_eq!(BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS, 3);
        assert_eq!(PRODUCTION_BLS_DORY_RANGE_LOGUP_VARIABLES, 33);
        assert_eq!(
            projected_production_range_logup_opening_bytes().unwrap(),
            70_639
        );
        assert_eq!(
            projected_production_range_logup_proof_bytes().unwrap(),
            77_793
        );
        assert_eq!(BLS_DORY_RANGE_LOGUP_PRODUCTION_BLOCKERS.len(), 5);
        assert_eq!(
            require_bls_dory_range_logup_production_ready(),
            Err(BlsDoryRangeLogUpError::NotProductionReady)
        );
    }
}
