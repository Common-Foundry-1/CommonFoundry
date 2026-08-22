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
        BlsDoryAggregateError, BlsDoryDeferredOpeningSet, BlsDoryOpeningClaim,
        MAX_BLS_DORY_AGGREGATE_BYTES, commit_bls_dory_padded_prefix_with_optional_scratch,
        commit_bls_dory_row_source_with_scratch, projected_bls_dory_aggregate_bytes,
        prove_bls_dory_deferred_opening_sets, verify_bls_dory_openings,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    dory_bls12_381_streaming::BlsDoryRowSource,
    structured_transition::{structured_transition_range_specs, validate_witness},
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
    "the scratch commitment derives all 110 lanes directly from the witness, but the n=33 transition sumcheck still materializes and folds its oracle tables",
    "the executable algebraic union bound exists, but Dory knowledge soundness has not been independently reviewed",
    "the scalar transition transcript and packed opening path have not received an external audit",
];

const ORACLE_SLOTS: usize = 1 << BLS_DORY_TRANSITION_SELECTOR_VARIABLES;
const PROOF_MAGIC: [u8; 8] = *b"CFBLST01";
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
    let (claims, opening_proof) =
        prove_bls_dory_deferred_opening_sets(&opening_binding, &[&prepared.openings], setup)?;
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
    prove_bls_dory_transition_deferred_at_variables_with_optional_scratch(
        binding,
        statement,
        mask_polynomial,
        witness,
        packed_variables,
        setup,
        Some(scratch_directory),
    )
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
    let mut oracles = build_scalar_oracles(statement, witness)?;
    let cell_variables = statement.elements()?.ilog2() as usize;
    validate_target_variables(minimum_packed_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryTransitionError::InvalidDimensions);
    }
    let packed_nu = packed_variables / 2;
    let packed_sigma = packed_variables - packed_nu;
    let committed = if let Some(scratch_directory) = scratch_directory {
        let rows = 1usize
            .checked_shl(packed_nu as u32)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        let columns = 1usize
            .checked_shl(packed_sigma as u32)
            .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
        let mut source = BlsDoryTransitionWitnessRowSource::new(statement, witness, rows, columns)?;
        commit_bls_dory_row_source_with_scratch(
            &mut source,
            packed_nu,
            packed_sigma,
            setup,
            scratch_directory,
        )?
    } else {
        let packed_coefficients = pack_oracles(&oracles)?;
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
    let mut selector = equality_table(&cell_point);
    let mut claim = BlsDoryFr::zero();
    let mut rounds = Vec::with_capacity(cell_variables);
    let mut sumcheck_point = Vec::with_capacity(cell_variables);

    oracles.truncate(STRUCTURED_TRANSITION_REGULAR_ORACLES);
    for round_index in 0..cell_variables {
        let evaluations = transition_round(statement, &selector, &oracles, &mixing_powers)?;
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryTransitionError::RoundClaim);
        }
        absorb_round(&mut transcript, round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        sumcheck_point.push(challenge);
        selector = fold_table(&selector, challenge);
        for oracle in &mut oracles {
            *oracle = fold_table(oracle, challenge);
        }
        rounds.push(evaluations);
    }

    let terminal_evaluations = oracles.iter().map(|oracle| oracle[0]).collect::<Vec<_>>();
    if terminal_evaluations[MASK] != evaluate_mask(mask_polynomial, statement, &sumcheck_point)? {
        return Err(BlsDoryTransitionError::MaskPolynomial);
    }
    let expected =
        selector[0] * arithmetic_constraint(statement, &terminal_evaluations, &mixing_powers)?;
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
    verify_bls_dory_openings(&opening_binding, &claims, &proof.opening_proof, setup)?;
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

pub(crate) struct BlsDoryTransitionWitnessRowSource<'a> {
    statement: StructuredTransitionStatement,
    witness: &'a StructuredTransitionWitness,
    range_oracles: Vec<RangeOracleDescriptor>,
    elements: usize,
    rows: usize,
    columns: usize,
    explicit_scalars: usize,
}

impl<'a> BlsDoryTransitionWitnessRowSource<'a> {
    pub(crate) fn new(
        statement: StructuredTransitionStatement,
        witness: &'a StructuredTransitionWitness,
        rows: usize,
        columns: usize,
    ) -> Result<Self, BlsDoryTransitionError> {
        validate_witness(statement, witness)?;
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
            witness,
            range_oracles,
            elements,
            rows,
            columns,
            explicit_scalars,
        })
    }

    fn regular_value(
        &self,
        oracle: usize,
        index: usize,
    ) -> Result<BlsDoryFr, BlsDoryTransitionError> {
        let unsigned = |values: &[u64]| {
            values
                .get(index)
                .copied()
                .map(BlsDoryFr::from_u64)
                .ok_or(BlsDoryTransitionError::InvalidDimensions)
        };
        let signed = |values: &[i64]| {
            values
                .get(index)
                .copied()
                .map(BlsDoryFr::from_i64)
                .ok_or(BlsDoryTransitionError::InvalidDimensions)
        };
        match oracle {
            ACCUMULATOR => signed(&self.witness.accumulators),
            MASK => unsigned(&self.witness.masks),
            ENCODED => unsigned(&self.witness.encoded),
            SQUARE_QUOTIENT => unsigned(&self.witness.square_quotients),
            SQUARE_REMAINDER => unsigned(&self.witness.square_remainders),
            CUBE_QUOTIENT => unsigned(&self.witness.cube_quotients),
            CUBE_REMAINDER => unsigned(&self.witness.cube_remainders),
            OUTPUT_QUOTIENT => unsigned(&self.witness.output_quotients),
            OUTPUT_REMAINDER => unsigned(&self.witness.output_remainders),
            NEGATIVE => unsigned(&self.witness.negative),
            ACTIVATION => signed(&self.witness.activations),
            SHIFTED_ACCUMULATOR => {
                let accumulator = self
                    .witness
                    .accumulators
                    .get(index)
                    .copied()
                    .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
                let shifted = u64::try_from(
                    i128::from(accumulator) + i128::from(self.statement.max_abs_accumulator),
                )
                .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?;
                Ok(BlsDoryFr::from_u64(shifted))
            }
            _ => Err(BlsDoryTransitionError::InvalidProofShape),
        }
    }

    fn range_value(
        &self,
        descriptor: RangeOracleDescriptor,
        index: usize,
    ) -> Result<BlsDoryFr, BlsDoryTransitionError> {
        let value = if descriptor.source_oracle == SHIFTED_ACCUMULATOR {
            let accumulator = self
                .witness
                .accumulators
                .get(index)
                .copied()
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?;
            u64::try_from(i128::from(accumulator) + i128::from(self.statement.max_abs_accumulator))
                .map_err(|_| BlsDoryTransitionError::InvalidDimensions)?
        } else {
            *witness_unsigned_values(self.witness, descriptor.source_oracle)?
                .get(index)
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?
        };
        let bounded = if descriptor.slack {
            descriptor
                .maximum
                .checked_sub(value)
                .ok_or(BlsDoryTransitionError::InvalidDimensions)?
        } else {
            value
        };
        Ok(BlsDoryFr::from_u64(
            (bounded >> (descriptor.digit * 4)) & 0xf,
        ))
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
        self.range_value(descriptor, index)
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
        self.explicit_scalars
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

    #[test]
    fn witness_row_source_matches_every_materialized_transition_oracle() {
        let (statement, _, witness) = fixture();
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
        assert_eq!(PRODUCTION_BLS_DORY_TRANSITION_VARIABLES, 26 + 7);
        assert_eq!(
            projected_production_transition_opening_bytes().unwrap(),
            70_639
        );
        assert_eq!(
            projected_production_transition_proof_bytes().unwrap(),
            74_979
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
