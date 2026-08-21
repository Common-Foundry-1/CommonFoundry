//! Structured transition and range sumcheck for ForgeMatrix v2 research.
//!
//! The argument batches every local reduction, cubic transition, output, and
//! range constraint in one power-of-two layer bank.  The current opening
//! adapter still receives the complete witness tables.  A production proof
//! must authenticate the same terminal openings with the transparent PCS.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    V2_TRANSITION_MODULUS,
    forgematrix_v2::mask_coefficients,
    structured_sumcheck::{
        ExtensionElement, ExtensionField, GOLDILOCKS_MODULUS, StructuredSumcheckError,
        absorb_length_prefixed, equality_evaluation, equality_weights, evaluate_mle, fold,
        interpolate_pair, table_commitment,
    },
};

pub const STRUCTURED_TRANSITION_VERSION: u32 = 1;
pub const STRUCTURED_TRANSITION_CONSTRAINTS: usize = 121;
pub const STRUCTURED_TRANSITION_ORACLES: usize = 110;
pub const STRUCTURED_TRANSITION_INPUT_ORACLE: usize = 0;
pub const STRUCTURED_TRANSITION_ACTIVATION_ORACLE: usize = 10;
pub const STRUCTURED_TRANSITION_MAX_DEGREE: usize = 17;
pub const STRUCTURED_TRANSITION_REGULAR_ORACLES: usize = 12;
pub const STRUCTURED_TRANSITION_RANGE_SPEC_COUNT: usize = 8;
pub const STRUCTURED_TRANSITION_RANGE_DIGITS_PER_CELL: usize = 49;
pub const STRUCTURED_TRANSITION_RANGE_ORACLES: [usize; STRUCTURED_TRANSITION_RANGE_SPEC_COUNT] = [
    ENCODED,
    SQUARE_QUOTIENT,
    SQUARE_REMAINDER,
    CUBE_QUOTIENT,
    CUBE_REMAINDER,
    OUTPUT_QUOTIENT,
    OUTPUT_REMAINDER,
    SHIFTED_ACCUMULATOR,
];
pub const STRUCTURED_TRANSITION_RANGE_DIGITS: [usize; STRUCTURED_TRANSITION_RANGE_SPEC_COUNT] =
    [7, 7, 7, 7, 7, 5, 2, 7];
pub const MAX_STRUCTURED_TRANSITION_ELEMENTS: usize = 1 << 20;
pub const MAX_STRUCTURED_TRANSITION_PROOF_BYTES: usize = 256 * 1024;

pub(crate) const MAX_STRUCTURED_TRANSITION_LAYERS: usize = 128;
pub(crate) const MAX_STRUCTURED_TRANSITION_ROWS: usize = 128;
pub(crate) const MAX_STRUCTURED_TRANSITION_COLS: usize = 4096;
const MAX_STRUCTURED_TRANSITION_VERIFIER_ELEMENTS: usize = 1 << 26;

const PROOF_MAGIC: &[u8; 8] = b"CMFDST01";
const TRANSCRIPT_DOMAIN: &str = "CMFD/FORGEMATRIX/STRUCTURED-TRANSITION/V1";
const OUTPUT_MODULUS: u64 = 251;
const MAX_OUTPUT_QUOTIENT: u64 = 534_731;
const OUTPUT_CENTER: i64 = 125;
const MAX_SUMCHECK_ROUNDS: usize = 64;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredTransitionStatement {
    pub layers: usize,
    pub rows: usize,
    pub cols: usize,
    pub max_abs_accumulator: u64,
    pub max_mask: u64,
}

/// Challenge-derived affine mask polynomial for one real-layer bank.
///
/// Coefficients are derived through the authoritative ForgeMatrix v2 mask
/// expander.  The verifier evaluates this compact polynomial at the random
/// transition opening point instead of trusting a miner-chosen mask table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMaskPolynomial {
    layers: usize,
    row_bits: u32,
    col_bits: u32,
    coefficients: Vec<u8>,
}

impl StructuredMaskPolynomial {
    pub fn from_challenge(
        challenge: &[u8; 32],
        layers: usize,
        rows: usize,
        cols: usize,
    ) -> Result<Self, StructuredTransitionError> {
        if layers == 0
            || rows == 0
            || cols == 0
            || !layers.is_power_of_two()
            || !rows.is_power_of_two()
            || !cols.is_power_of_two()
            || layers > u32::MAX as usize
        {
            return Err(StructuredTransitionError::InvalidDimensions);
        }
        if layers > MAX_STRUCTURED_TRANSITION_LAYERS
            || rows > MAX_STRUCTURED_TRANSITION_ROWS
            || cols > MAX_STRUCTURED_TRANSITION_COLS
        {
            return Err(StructuredTransitionError::ResearchCap);
        }
        let row_bits = rows.ilog2();
        let col_bits = cols.ilog2();
        let coefficient_count = 1 + row_bits as usize + col_bits as usize;
        let mut coefficients = Vec::with_capacity(
            layers
                .checked_mul(coefficient_count)
                .ok_or(StructuredTransitionError::ArithmeticOverflow)?,
        );
        for layer in 0..layers {
            coefficients.extend(mask_coefficients(challenge, layer as u32, rows, cols));
        }
        Ok(Self {
            layers,
            row_bits,
            col_bits,
            coefficients,
        })
    }

    /// Builds the mask polynomial for the virtual input layer.
    ///
    /// ForgeMatrix reserves `u32::MAX` for this layer so it cannot be confused
    /// with real layer zero under the challenge-derived mask expander.
    pub fn from_virtual_challenge(
        challenge: &[u8; 32],
        rows: usize,
        cols: usize,
    ) -> Result<Self, StructuredTransitionError> {
        if rows == 0 || cols == 0 || !rows.is_power_of_two() || !cols.is_power_of_two() {
            return Err(StructuredTransitionError::InvalidDimensions);
        }
        if rows > MAX_STRUCTURED_TRANSITION_ROWS || cols > MAX_STRUCTURED_TRANSITION_COLS {
            return Err(StructuredTransitionError::ResearchCap);
        }
        let row_bits = rows.ilog2();
        let col_bits = cols.ilog2();
        Ok(Self {
            layers: 1,
            row_bits,
            col_bits,
            coefficients: mask_coefficients(challenge, u32::MAX, rows, cols),
        })
    }

    fn validate(
        &self,
        statement: StructuredTransitionStatement,
    ) -> Result<(), StructuredTransitionError> {
        statement.validate_verifier_shape()?;
        let coefficient_count = 1 + self.row_bits as usize + self.col_bits as usize;
        let expected = self
            .layers
            .checked_mul(coefficient_count)
            .ok_or(StructuredTransitionError::ArithmeticOverflow)?;
        if self.layers != statement.layers
            || self.row_bits != statement.rows.ilog2()
            || self.col_bits != statement.cols.ilog2()
            || self.coefficients.len() != expected
            || self.coefficients.iter().any(|value| *value > 250)
            || self
                .coefficients
                .chunks_exact(coefficient_count)
                .any(|layer| {
                    layer.iter().map(|value| u64::from(*value)).sum::<u64>() > statement.max_mask
                })
        {
            return Err(StructuredTransitionError::MaskPolynomial);
        }
        Ok(())
    }

    fn digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key("CMFD/FORGEMATRIX/STRUCTURED-MASK/V1");
        hasher.update(&(self.layers as u64).to_le_bytes());
        hasher.update(&self.row_bits.to_le_bytes());
        hasher.update(&self.col_bits.to_le_bytes());
        hasher.update(&(self.coefficients.len() as u64).to_le_bytes());
        hasher.update(&self.coefficients);
        *hasher.finalize().as_bytes()
    }

    fn evaluate(&self, point: &[ExtensionField]) -> ExtensionField {
        let col_end = self.col_bits as usize;
        let row_end = col_end + self.row_bits as usize;
        let layer_point = &point[row_end..];
        let layer_weights = equality_weights(layer_point);
        let coefficient_count = 1 + self.row_bits as usize + self.col_bits as usize;
        layer_weights.into_iter().enumerate().fold(
            ExtensionField::ZERO,
            |sum, (layer, layer_weight)| {
                let coefficients =
                    &self.coefficients[layer * coefficient_count..(layer + 1) * coefficient_count];
                let mut value = ExtensionField::from_u64(u64::from(coefficients[0]));
                for (bit, challenge) in point[col_end..row_end].iter().enumerate() {
                    value = value.add(
                        ExtensionField::from_u64(u64::from(coefficients[1 + bit])).mul(*challenge),
                    );
                }
                for (bit, challenge) in point[..col_end].iter().enumerate() {
                    value = value.add(
                        ExtensionField::from_u64(u64::from(
                            coefficients[1 + self.row_bits as usize + bit],
                        ))
                        .mul(*challenge),
                    );
                }
                sum.add(layer_weight.mul(value))
            },
        )
    }

    /// Evaluate the challenge-derived mask at one canonical Boolean cell.
    ///
    /// Cells are ordered column-first, then row, then layer, matching the
    /// multilinear table order used by the transition witness. This is the
    /// verifier-side source for a fixed preprocessed mask column; a prover must
    /// never supply a replacement table.
    pub fn value_at_boolean_index(
        &self,
        statement: StructuredTransitionStatement,
        index: usize,
    ) -> Result<u64, StructuredTransitionError> {
        self.validate(statement)?;
        let cells_per_layer = statement
            .rows
            .checked_mul(statement.cols)
            .ok_or(StructuredTransitionError::ArithmeticOverflow)?;
        let elements = statement
            .layers
            .checked_mul(cells_per_layer)
            .ok_or(StructuredTransitionError::ArithmeticOverflow)?;
        if index >= elements {
            return Err(StructuredTransitionError::InvalidDimensions);
        }

        let layer = index / cells_per_layer;
        let within_layer = index % cells_per_layer;
        let row = within_layer / statement.cols;
        let col = within_layer % statement.cols;
        let coefficient_count = 1 + self.row_bits as usize + self.col_bits as usize;
        let coefficients =
            &self.coefficients[layer * coefficient_count..(layer + 1) * coefficient_count];
        let mut value = u64::from(coefficients[0]);
        for bit in 0..self.row_bits as usize {
            if (row >> bit) & 1 == 1 {
                value = value
                    .checked_add(u64::from(coefficients[1 + bit]))
                    .ok_or(StructuredTransitionError::ArithmeticOverflow)?;
            }
        }
        for bit in 0..self.col_bits as usize {
            if (col >> bit) & 1 == 1 {
                value = value
                    .checked_add(u64::from(coefficients[1 + self.row_bits as usize + bit]))
                    .ok_or(StructuredTransitionError::ArithmeticOverflow)?;
            }
        }
        Ok(value)
    }
}

impl StructuredTransitionStatement {
    pub fn sumcheck_error_numerator(&self) -> Result<u32, StructuredTransitionError> {
        self.validate_verifier_shape()?;
        let variables = self
            .layers
            .checked_mul(self.rows)
            .and_then(|value| value.checked_mul(self.cols))
            .ok_or(StructuredTransitionError::ArithmeticOverflow)?
            .ilog2();
        Ok((STRUCTURED_TRANSITION_MAX_DEGREE as u32) * variables)
    }

    pub(crate) fn validate_verifier_shape(&self) -> Result<(), StructuredTransitionError> {
        if self.layers == 0
            || self.rows == 0
            || self.cols == 0
            || !self.layers.is_power_of_two()
            || !self.rows.is_power_of_two()
            || !self.cols.is_power_of_two()
        {
            return Err(StructuredTransitionError::InvalidDimensions);
        }
        let elements = self
            .layers
            .checked_mul(self.rows)
            .and_then(|value| value.checked_mul(self.cols))
            .ok_or(StructuredTransitionError::ArithmeticOverflow)?;
        if self.layers > MAX_STRUCTURED_TRANSITION_LAYERS
            || self.rows > MAX_STRUCTURED_TRANSITION_ROWS
            || self.cols > MAX_STRUCTURED_TRANSITION_COLS
            || elements > MAX_STRUCTURED_TRANSITION_VERIFIER_ELEMENTS
        {
            return Err(StructuredTransitionError::ResearchCap);
        }
        if self.max_abs_accumulator == 0
            || self.max_abs_accumulator >= u64::from(V2_TRANSITION_MODULUS)
            || self
                .max_abs_accumulator
                .checked_mul(2)
                .is_none_or(|bound| bound >= u64::from(V2_TRANSITION_MODULUS))
            || self.max_mask >= u64::from(V2_TRANSITION_MODULUS)
            || self
                .max_abs_accumulator
                .checked_add(self.max_mask)
                .is_none_or(|bound| bound >= u64::from(V2_TRANSITION_MODULUS))
        {
            return Err(StructuredTransitionError::UnsafeIntegerBounds);
        }
        Ok(())
    }

    pub(crate) fn validate_materialized_shape(&self) -> Result<(), StructuredTransitionError> {
        self.validate_verifier_shape()?;
        if self.elements()? > MAX_STRUCTURED_TRANSITION_ELEMENTS {
            return Err(StructuredTransitionError::ResearchCap);
        }
        Ok(())
    }

    fn elements(&self) -> Result<usize, StructuredTransitionError> {
        self.layers
            .checked_mul(self.rows)
            .and_then(|value| value.checked_mul(self.cols))
            .ok_or(StructuredTransitionError::ArithmeticOverflow)
    }
}

/// Complete local witness for every real-layer transition in one bank.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredTransitionWitness {
    pub accumulators: Vec<i64>,
    pub masks: Vec<u64>,
    pub encoded: Vec<u64>,
    pub square_quotients: Vec<u64>,
    pub square_remainders: Vec<u64>,
    pub cube_quotients: Vec<u64>,
    pub cube_remainders: Vec<u64>,
    pub output_quotients: Vec<u64>,
    pub output_remainders: Vec<u64>,
    pub negative: Vec<u64>,
    pub activations: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredTransitionRound {
    pub evaluations: Vec<ExtensionElement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredTransitionProof {
    pub protocol_version: u32,
    pub oracle_commitments: Vec<[u8; 32]>,
    pub rounds: Vec<StructuredTransitionRound>,
    pub terminal_evaluations: Vec<ExtensionElement>,
    pub transcript_digest: [u8; 32],
}

/// PCS claims produced after checking the transition sumcheck transcript.
///
/// This is not a complete proof result.  Every returned opening must be
/// authenticated by the selected PCS before the transition is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredTransitionOpeningClaims {
    pub oracle_commitments: Vec<[u8; 32]>,
    pub point: Vec<ExtensionElement>,
    pub evaluations: Vec<ExtensionElement>,
}

impl StructuredTransitionProof {
    pub fn encode(&self) -> Result<Vec<u8>, StructuredTransitionError> {
        self.validate_shape()?;
        let mut output = Vec::with_capacity(self.canonical_size());
        output.extend_from_slice(PROOF_MAGIC);
        output.extend_from_slice(&self.protocol_version.to_le_bytes());
        output.extend_from_slice(&(self.oracle_commitments.len() as u32).to_le_bytes());
        for commitment in &self.oracle_commitments {
            output.extend_from_slice(commitment);
        }
        output.extend_from_slice(&(self.rounds.len() as u32).to_le_bytes());
        for round in &self.rounds {
            output.push(round.evaluations.len() as u8);
            for value in &round.evaluations {
                value.to_field()?;
                value.encode(&mut output);
            }
        }
        output.extend_from_slice(&(self.terminal_evaluations.len() as u32).to_le_bytes());
        for value in &self.terminal_evaluations {
            value.to_field()?;
            value.encode(&mut output);
        }
        output.extend_from_slice(&self.transcript_digest);
        if output.len() > MAX_STRUCTURED_TRANSITION_PROOF_BYTES {
            return Err(StructuredTransitionError::ProofTooLarge);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StructuredTransitionError> {
        if bytes.len() > MAX_STRUCTURED_TRANSITION_PROOF_BYTES {
            return Err(StructuredTransitionError::ProofTooLarge);
        }
        let mut reader = ProofReader::new(bytes);
        if reader.take(8)? != PROOF_MAGIC {
            return Err(StructuredTransitionError::Decode);
        }
        let protocol_version = reader.u32()?;
        let commitment_count = reader.u32()? as usize;
        if commitment_count != STRUCTURED_TRANSITION_ORACLES {
            return Err(StructuredTransitionError::OracleCount);
        }
        let mut oracle_commitments = Vec::with_capacity(commitment_count);
        for _ in 0..commitment_count {
            oracle_commitments.push(reader.array()?);
        }
        let round_count = reader.u32()? as usize;
        if round_count > MAX_SUMCHECK_ROUNDS {
            return Err(StructuredTransitionError::RoundCount);
        }
        let mut rounds = Vec::with_capacity(round_count);
        for _ in 0..round_count {
            let count = usize::from(reader.u8()?);
            if count != STRUCTURED_TRANSITION_MAX_DEGREE + 1 {
                return Err(StructuredTransitionError::RoundDegree);
            }
            let mut evaluations = Vec::with_capacity(count);
            for _ in 0..count {
                evaluations.push(reader.extension()?);
            }
            rounds.push(StructuredTransitionRound { evaluations });
        }
        let terminal_count = reader.u32()? as usize;
        if terminal_count != STRUCTURED_TRANSITION_ORACLES {
            return Err(StructuredTransitionError::OracleCount);
        }
        let mut terminal_evaluations = Vec::with_capacity(terminal_count);
        for _ in 0..terminal_count {
            terminal_evaluations.push(reader.extension()?);
        }
        let transcript_digest = reader.array()?;
        if !reader.is_empty() {
            return Err(StructuredTransitionError::Decode);
        }
        let proof = Self {
            protocol_version,
            oracle_commitments,
            rounds,
            terminal_evaluations,
            transcript_digest,
        };
        proof.validate_shape()?;
        Ok(proof)
    }

    pub fn canonical_size(&self) -> usize {
        8 + 4
            + 4
            + self.oracle_commitments.len() * 32
            + 4
            + self
                .rounds
                .iter()
                .map(|round| 1 + round.evaluations.len() * 24)
                .sum::<usize>()
            + 4
            + self.terminal_evaluations.len() * 24
            + 32
    }

    fn validate_shape(&self) -> Result<(), StructuredTransitionError> {
        if self.oracle_commitments.len() != STRUCTURED_TRANSITION_ORACLES
            || self.terminal_evaluations.len() != STRUCTURED_TRANSITION_ORACLES
        {
            return Err(StructuredTransitionError::OracleCount);
        }
        if self.rounds.len() > MAX_SUMCHECK_ROUNDS {
            return Err(StructuredTransitionError::RoundCount);
        }
        if self
            .rounds
            .iter()
            .any(|round| round.evaluations.len() != STRUCTURED_TRANSITION_MAX_DEGREE + 1)
        {
            return Err(StructuredTransitionError::RoundDegree);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StructuredTransitionError {
    #[error("transition dimensions must be nonzero powers of two")]
    InvalidDimensions,
    #[error("transition witness length does not match the statement")]
    InvalidLength,
    #[error("structured transition tables exceed their research element cap")]
    ResearchCap,
    #[error("transition bounds do not enforce one canonical prime-field encoding")]
    UnsafeIntegerBounds,
    #[error("transition witness value is outside its declared canonical range")]
    ValueOutOfRange,
    #[error("integer arithmetic overflowed while validating the transition statement")]
    ArithmeticOverflow,
    #[error("structured transition protocol version mismatch")]
    ProtocolVersion,
    #[error("structured transition proof has the wrong oracle count")]
    OracleCount,
    #[error("structured transition oracle commitment mismatch")]
    Commitment,
    #[error("transition mask does not match the challenge-derived affine polynomial")]
    MaskPolynomial,
    #[error("structured transition proof has the wrong number of rounds")]
    RoundCount,
    #[error("structured transition round has the wrong polynomial degree")]
    RoundDegree,
    #[error("structured transition round does not preserve the current claim")]
    RoundClaim,
    #[error("structured transition terminal constraint claim is invalid")]
    TerminalClaim,
    #[error("structured transition terminal opening does not match its table")]
    Opening,
    #[error("structured transition transcript digest mismatch")]
    Transcript,
    #[error("structured transition proof is larger than its research cap")]
    ProofTooLarge,
    #[error("structured transition proof is truncated, malformed, or has trailing bytes")]
    Decode,
    #[error("structured transition field operation failed: {0}")]
    Field(#[from] StructuredSumcheckError),
}

pub fn prove_structured_transition(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
) -> Result<StructuredTransitionProof, StructuredTransitionError> {
    mask_polynomial.validate(statement)?;
    let oracles = build_oracles(statement, witness)?;
    let oracle_commitments = oracle_commitments(statement, &oracles);
    prove_structured_transition_oracles(
        binding,
        statement,
        mask_polynomial,
        oracles,
        oracle_commitments,
    )
}

/// Builds the transition transcript using commitments supplied by an
/// aggregate PCS. The PCS must later authenticate every oracle opening.
#[cfg(feature = "whir-prototype")]
pub fn prove_structured_transition_with_commitments(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    oracle_commitments: Vec<[u8; 32]>,
) -> Result<StructuredTransitionProof, StructuredTransitionError> {
    mask_polynomial.validate(statement)?;
    if oracle_commitments.len() != STRUCTURED_TRANSITION_ORACLES {
        return Err(StructuredTransitionError::Commitment);
    }
    prove_structured_transition_oracles(
        binding,
        statement,
        mask_polynomial,
        build_oracles(statement, witness)?,
        oracle_commitments,
    )
}

fn prove_structured_transition_oracles(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    mut oracles: Vec<Vec<ExtensionField>>,
    oracle_commitments: Vec<[u8; 32]>,
) -> Result<StructuredTransitionProof, StructuredTransitionError> {
    let mut transcript = TransitionTranscript::new(
        binding,
        statement,
        mask_polynomial.digest(),
        &oracle_commitments,
    );
    let mixing = transcript.challenge(b"constraint-mixing");
    let mixing_powers = powers(mixing, STRUCTURED_TRANSITION_CONSTRAINTS);
    let variables = statement.elements()?.ilog2();
    let cell_point = transcript.challenge_vector(b"cell-point", variables);
    let mut selector = equality_weights(&cell_point);
    let mut claim = ExtensionField::ZERO;
    let mut rounds = Vec::with_capacity(variables as usize);
    let mut sumcheck_point = Vec::with_capacity(variables as usize);

    for round_index in 0..variables {
        let evaluations = transition_round(statement, &selector, &oracles, &mixing_powers);
        if evaluations[0].add(evaluations[1]) != claim {
            return Err(StructuredTransitionError::RoundClaim);
        }
        transcript.absorb_round(round_index, &evaluations);
        let challenge = transcript.challenge(b"sumcheck-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        sumcheck_point.push(challenge);
        selector = fold(&selector, challenge);
        for oracle in &mut oracles {
            *oracle = fold(oracle, challenge);
        }
        rounds.push(StructuredTransitionRound {
            evaluations: evaluations
                .into_iter()
                .map(ExtensionElement::from_field)
                .collect(),
        });
    }

    let terminal = oracles.iter().map(|oracle| oracle[0]).collect::<Vec<_>>();
    if terminal[MASK] != mask_polynomial.evaluate(&sumcheck_point) {
        return Err(StructuredTransitionError::MaskPolynomial);
    }
    let expected = selector[0].mul(mixed_constraint(statement, &terminal, &mixing_powers));
    if claim != expected {
        return Err(StructuredTransitionError::TerminalClaim);
    }
    transcript.absorb_fields(b"terminal-evaluation", &terminal);
    Ok(StructuredTransitionProof {
        protocol_version: STRUCTURED_TRANSITION_VERSION,
        oracle_commitments,
        rounds,
        terminal_evaluations: terminal
            .into_iter()
            .map(ExtensionElement::from_field)
            .collect(),
        transcript_digest: transcript.digest(),
    })
}

/// Returns all transition and range-check oracle tables in transcript order.
#[cfg(feature = "whir-prototype")]
pub fn structured_transition_whir_tables(
    statement: StructuredTransitionStatement,
    witness: &StructuredTransitionWitness,
) -> Result<Vec<Vec<u64>>, StructuredTransitionError> {
    Ok(build_oracles(statement, witness)?
        .iter()
        .map(|oracle| crate::structured_sumcheck::base_table_values(oracle))
        .collect())
}

pub fn verify_structured_transition(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    proof: &StructuredTransitionProof,
) -> Result<(), StructuredTransitionError> {
    let oracles = build_oracles(statement, witness)?;
    let commitments = oracle_commitments(statement, &oracles);
    let claims = verify_structured_transition_sumcheck(binding, statement, mask_polynomial, proof)?;
    if claims.oracle_commitments != commitments {
        return Err(StructuredTransitionError::Commitment);
    }
    let point = claims
        .point
        .iter()
        .copied()
        .map(ExtensionElement::to_field)
        .collect::<Result<Vec<_>, _>>()?;
    let evaluations = claims
        .evaluations
        .iter()
        .copied()
        .map(ExtensionElement::to_field)
        .collect::<Result<Vec<_>, _>>()?;
    for (oracle, claimed) in oracles.iter().zip(evaluations) {
        if evaluate_mle(oracle, &point) != claimed {
            return Err(StructuredTransitionError::Opening);
        }
    }
    Ok(())
}

/// Checks the Fiat--Shamir transition sumcheck and derives its PCS claims.
///
/// This function deliberately does not authenticate an opening.  Production
/// consensus must call a hardened PCS verifier for every returned claim.
pub fn verify_structured_transition_sumcheck(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &StructuredTransitionProof,
) -> Result<StructuredTransitionOpeningClaims, StructuredTransitionError> {
    statement.validate_verifier_shape()?;
    mask_polynomial.validate(statement)?;
    proof.validate_shape()?;
    if proof.protocol_version != STRUCTURED_TRANSITION_VERSION {
        return Err(StructuredTransitionError::ProtocolVersion);
    }
    let variables = statement.elements()?.ilog2() as usize;
    if proof.rounds.len() != variables {
        return Err(StructuredTransitionError::RoundCount);
    }
    let mut transcript = TransitionTranscript::new(
        binding,
        statement,
        mask_polynomial.digest(),
        &proof.oracle_commitments,
    );
    let mixing = transcript.challenge(b"constraint-mixing");
    let mixing_powers = powers(mixing, STRUCTURED_TRANSITION_CONSTRAINTS);
    let cell_point = transcript.challenge_vector(b"cell-point", variables as u32);
    let mut claim = ExtensionField::ZERO;
    let mut sumcheck_point = Vec::with_capacity(variables);
    for (round_index, round) in proof.rounds.iter().enumerate() {
        let evaluations = round
            .evaluations
            .iter()
            .copied()
            .map(ExtensionElement::to_field)
            .collect::<Result<Vec<_>, _>>()?;
        if evaluations[0].add(evaluations[1]) != claim {
            return Err(StructuredTransitionError::RoundClaim);
        }
        transcript.absorb_round(round_index as u32, &evaluations);
        let challenge = transcript.challenge(b"sumcheck-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        sumcheck_point.push(challenge);
    }
    let terminal = proof
        .terminal_evaluations
        .iter()
        .copied()
        .map(ExtensionElement::to_field)
        .collect::<Result<Vec<_>, _>>()?;
    if terminal[MASK] != mask_polynomial.evaluate(&sumcheck_point) {
        return Err(StructuredTransitionError::MaskPolynomial);
    }
    let selector = equality_evaluation(&cell_point, &sumcheck_point);
    if claim != selector.mul(mixed_constraint(statement, &terminal, &mixing_powers)) {
        return Err(StructuredTransitionError::TerminalClaim);
    }
    transcript.absorb_fields(b"terminal-evaluation", &terminal);
    if proof.transcript_digest != transcript.digest() {
        return Err(StructuredTransitionError::Transcript);
    }
    Ok(StructuredTransitionOpeningClaims {
        oracle_commitments: proof.oracle_commitments.clone(),
        point: sumcheck_point
            .into_iter()
            .map(ExtensionElement::from_field)
            .collect(),
        evaluations: proof.terminal_evaluations.clone(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredTransitionRangeSpec {
    pub oracle: usize,
    pub maximum: u64,
    pub digits: usize,
}

pub fn structured_transition_range_specs(
    statement: StructuredTransitionStatement,
) -> Result<
    [StructuredTransitionRangeSpec; STRUCTURED_TRANSITION_RANGE_SPEC_COUNT],
    StructuredTransitionError,
> {
    statement.validate_verifier_shape()?;
    Ok(range_specs(statement))
}

fn range_specs(
    statement: StructuredTransitionStatement,
) -> [StructuredTransitionRangeSpec; STRUCTURED_TRANSITION_RANGE_SPEC_COUNT] {
    let maxima = [
        V2_TRANSITION_MODULUS as u64 - 1,
        V2_TRANSITION_MODULUS as u64 - 1,
        V2_TRANSITION_MODULUS as u64 - 1,
        V2_TRANSITION_MODULUS as u64 - 1,
        V2_TRANSITION_MODULUS as u64 - 1,
        MAX_OUTPUT_QUOTIENT,
        250,
        statement.max_abs_accumulator * 2,
    ];
    std::array::from_fn(|index| StructuredTransitionRangeSpec {
        oracle: STRUCTURED_TRANSITION_RANGE_ORACLES[index],
        maximum: maxima[index],
        digits: STRUCTURED_TRANSITION_RANGE_DIGITS[index],
    })
}

fn build_oracles(
    statement: StructuredTransitionStatement,
    witness: &StructuredTransitionWitness,
) -> Result<Vec<Vec<ExtensionField>>, StructuredTransitionError> {
    validate_witness(statement, witness)?;
    let shifted_accumulators = witness
        .accumulators
        .iter()
        .map(|value| {
            u64::try_from(i128::from(*value) + i128::from(statement.max_abs_accumulator))
                .expect("validated signed accumulator shift is nonnegative")
        })
        .collect::<Vec<_>>();
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
    for spec in range_specs(statement) {
        let values = if spec.oracle == SHIFTED_ACCUMULATOR {
            shifted_accumulators.as_slice()
        } else {
            witness_values(witness, spec.oracle)
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
    debug_assert_eq!(oracles.len(), STRUCTURED_TRANSITION_ORACLES);
    Ok(oracles)
}

fn validate_witness(
    statement: StructuredTransitionStatement,
    witness: &StructuredTransitionWitness,
) -> Result<(), StructuredTransitionError> {
    statement.validate_materialized_shape()?;
    let elements = statement.elements()?;
    let lengths = [
        witness.accumulators.len(),
        witness.masks.len(),
        witness.encoded.len(),
        witness.square_quotients.len(),
        witness.square_remainders.len(),
        witness.cube_quotients.len(),
        witness.cube_remainders.len(),
        witness.output_quotients.len(),
        witness.output_remainders.len(),
        witness.negative.len(),
        witness.activations.len(),
    ];
    if lengths.into_iter().any(|length| length != elements) {
        return Err(StructuredTransitionError::InvalidLength);
    }
    if witness
        .accumulators
        .iter()
        .any(|value| value.unsigned_abs() > statement.max_abs_accumulator)
        || witness
            .masks
            .iter()
            .any(|value| *value > statement.max_mask)
        || witness.negative.iter().any(|value| *value > 1)
        || witness
            .activations
            .iter()
            .any(|value| !(-125..=125).contains(value))
    {
        return Err(StructuredTransitionError::ValueOutOfRange);
    }
    let shifted_accumulators = witness
        .accumulators
        .iter()
        .map(|value| {
            u64::try_from(i128::from(*value) + i128::from(statement.max_abs_accumulator))
                .expect("validated signed accumulator shift is nonnegative")
        })
        .collect::<Vec<_>>();
    for spec in range_specs(statement) {
        let values = if spec.oracle == SHIFTED_ACCUMULATOR {
            shifted_accumulators.as_slice()
        } else {
            witness_values(witness, spec.oracle)
        };
        if values.iter().any(|value| *value > spec.maximum) {
            return Err(StructuredTransitionError::ValueOutOfRange);
        }
    }
    Ok(())
}

fn witness_values(witness: &StructuredTransitionWitness, oracle: usize) -> &[u64] {
    match oracle {
        ENCODED => &witness.encoded,
        SQUARE_QUOTIENT => &witness.square_quotients,
        SQUARE_REMAINDER => &witness.square_remainders,
        CUBE_QUOTIENT => &witness.cube_quotients,
        CUBE_REMAINDER => &witness.cube_remainders,
        OUTPUT_QUOTIENT => &witness.output_quotients,
        OUTPUT_REMAINDER => &witness.output_remainders,
        _ => unreachable!("only range-constrained unsigned oracles are selected"),
    }
}

fn signed_values(values: &[i64]) -> Vec<ExtensionField> {
    values
        .iter()
        .copied()
        .map(ExtensionField::from_signed)
        .collect()
}

fn unsigned_values(values: &[u64]) -> Vec<ExtensionField> {
    values
        .iter()
        .copied()
        .map(ExtensionField::from_u64)
        .collect()
}

fn oracle_commitments(
    _statement: StructuredTransitionStatement,
    oracles: &[Vec<ExtensionField>],
) -> Vec<[u8; 32]> {
    oracles
        .iter()
        .map(|oracle| table_commitment(oracle))
        .collect()
}

fn transition_round(
    statement: StructuredTransitionStatement,
    selector: &[ExtensionField],
    oracles: &[Vec<ExtensionField>],
    mixing_powers: &[ExtensionField],
) -> Vec<ExtensionField> {
    (0..=STRUCTURED_TRANSITION_MAX_DEGREE)
        .map(|sample| {
            let point = ExtensionField::from_u64(sample as u64);
            (0..selector.len() / 2).fold(ExtensionField::ZERO, |sum, pair_index| {
                let offset = pair_index * 2;
                let values = oracles
                    .iter()
                    .map(|oracle| interpolate_pair(&oracle[offset..offset + 2], point))
                    .collect::<Vec<_>>();
                sum.add(
                    interpolate_pair(&selector[offset..offset + 2], point).mul(mixed_constraint(
                        statement,
                        &values,
                        mixing_powers,
                    )),
                )
            })
        })
        .collect()
}

fn mixed_constraint(
    statement: StructuredTransitionStatement,
    values: &[ExtensionField],
    powers: &[ExtensionField],
) -> ExtensionField {
    debug_assert_eq!(values.len(), STRUCTURED_TRANSITION_ORACLES);
    debug_assert_eq!(powers.len(), STRUCTURED_TRANSITION_CONSTRAINTS);
    let modulus = ExtensionField::from_u64(u64::from(V2_TRANSITION_MODULUS));
    let output_modulus = ExtensionField::from_u64(OUTPUT_MODULUS);
    let center = ExtensionField::from_u64(OUTPUT_CENTER as u64);
    let one = ExtensionField::ONE;
    let mut constraints = Vec::with_capacity(STRUCTURED_TRANSITION_CONSTRAINTS);
    constraints.push(
        values[ENCODED]
            .sub(values[ACCUMULATOR])
            .sub(values[MASK])
            .sub(values[NEGATIVE].mul(modulus)),
    );
    constraints.push(
        values[ENCODED]
            .mul(values[ENCODED])
            .sub(values[SQUARE_QUOTIENT].mul(modulus))
            .sub(values[SQUARE_REMAINDER]),
    );
    constraints.push(
        values[SQUARE_REMAINDER]
            .mul(values[ENCODED])
            .sub(values[CUBE_QUOTIENT].mul(modulus))
            .sub(values[CUBE_REMAINDER]),
    );
    constraints.push(
        values[CUBE_REMAINDER]
            .sub(values[OUTPUT_QUOTIENT].mul(output_modulus))
            .sub(values[OUTPUT_REMAINDER]),
    );
    constraints.push(values[ACTIVATION].sub(values[OUTPUT_REMAINDER]).add(center));
    constraints.push(values[NEGATIVE].mul(values[NEGATIVE].sub(one)));
    constraints.push(
        values[SHIFTED_ACCUMULATOR]
            .sub(values[ACCUMULATOR])
            .sub(ExtensionField::from_u64(statement.max_abs_accumulator)),
    );

    let mut digit_cursor = STRUCTURED_TRANSITION_REGULAR_ORACLES;
    for spec in range_specs(statement) {
        let mut reconstructed = ExtensionField::ZERO;
        let mut reconstructed_slack = ExtensionField::ZERO;
        let mut radix = ExtensionField::ONE;
        for _ in 0..spec.digits {
            reconstructed = reconstructed.add(values[digit_cursor].mul(radix));
            reconstructed_slack = reconstructed_slack.add(values[digit_cursor + 1].mul(radix));
            digit_cursor += 2;
            radix = radix.mul(ExtensionField::from_u64(16));
        }
        constraints.push(reconstructed.sub(values[spec.oracle]));
        constraints.push(
            reconstructed_slack
                .add(values[spec.oracle])
                .sub(ExtensionField::from_u64(spec.maximum)),
        );
    }
    for digit in &values[STRUCTURED_TRANSITION_REGULAR_ORACLES..] {
        let membership = (0..16).fold(ExtensionField::ONE, |product, allowed| {
            product.mul(digit.sub(ExtensionField::from_u64(allowed)))
        });
        constraints.push(membership);
    }
    debug_assert_eq!(constraints.len(), STRUCTURED_TRANSITION_CONSTRAINTS);
    constraints
        .into_iter()
        .zip(powers)
        .fold(ExtensionField::ZERO, |sum, (constraint, coefficient)| {
            sum.add(constraint.mul(*coefficient))
        })
}

fn powers(base: ExtensionField, count: usize) -> Vec<ExtensionField> {
    let mut result = Vec::with_capacity(count);
    let mut value = ExtensionField::ONE;
    for _ in 0..count {
        result.push(value);
        value = value.mul(base);
    }
    result
}

fn evaluate_samples(
    values: &[ExtensionField],
    point: ExtensionField,
) -> Result<ExtensionField, StructuredTransitionError> {
    if values.len() != STRUCTURED_TRANSITION_MAX_DEGREE + 1 {
        return Err(StructuredTransitionError::RoundDegree);
    }
    let mut result = ExtensionField::ZERO;
    for (index, value) in values.iter().copied().enumerate() {
        let mut numerator = ExtensionField::ONE;
        let mut denominator = ExtensionField::ONE;
        for other in 0..values.len() {
            if other == index {
                continue;
            }
            numerator = numerator.mul(point.sub(ExtensionField::from_u64(other as u64)));
            denominator = denominator.mul(ExtensionField::from_signed(index as i64 - other as i64));
        }
        result = result.add(value.mul(numerator).mul(denominator.inverse()?));
    }
    Ok(result)
}

struct TransitionTranscript {
    hasher: Hasher,
    challenge_counter: u64,
}

impl TransitionTranscript {
    fn new(
        binding: &[u8],
        statement: StructuredTransitionStatement,
        mask_digest: [u8; 32],
        commitments: &[[u8; 32]],
    ) -> Self {
        let mut transcript = Self {
            hasher: Hasher::new_derive_key(TRANSCRIPT_DOMAIN),
            challenge_counter: 0,
        };
        transcript.absorb(
            b"protocol-version",
            &STRUCTURED_TRANSITION_VERSION.to_le_bytes(),
        );
        transcript.absorb(b"public-binding", binding);
        let mut statement_hasher = Hasher::new();
        absorb_statement(&mut statement_hasher, statement);
        transcript.absorb(b"statement", statement_hasher.finalize().as_bytes());
        transcript.absorb(b"mask-polynomial", &mask_digest);
        transcript.absorb(b"oracle-count", &(commitments.len() as u32).to_le_bytes());
        for (index, commitment) in commitments.iter().enumerate() {
            transcript.absorb(b"oracle-index", &(index as u32).to_le_bytes());
            transcript.absorb(b"oracle-commitment", commitment);
        }
        transcript
    }

    fn absorb(&mut self, label: &[u8], value: &[u8]) {
        absorb_length_prefixed(&mut self.hasher, label);
        absorb_length_prefixed(&mut self.hasher, value);
    }

    fn absorb_field(&mut self, label: &[u8], value: ExtensionField) {
        self.absorb(label, &value.encode());
    }

    fn absorb_fields(&mut self, label: &[u8], values: &[ExtensionField]) {
        self.absorb(b"field-count", &(values.len() as u32).to_le_bytes());
        for value in values {
            self.absorb_field(label, *value);
        }
    }

    fn absorb_round(&mut self, index: u32, values: &[ExtensionField]) {
        self.absorb(b"round-index", &index.to_le_bytes());
        self.absorb(b"round-count", &(values.len() as u32).to_le_bytes());
        for value in values {
            self.absorb_field(b"round-evaluation", *value);
        }
    }

    fn challenge_vector(&mut self, label: &[u8], count: u32) -> Vec<ExtensionField> {
        (0..count)
            .map(|index| {
                self.absorb(b"point-index", &index.to_le_bytes());
                self.challenge(label)
            })
            .collect()
    }

    fn challenge(&mut self, label: &[u8]) -> ExtensionField {
        let mut limbs = [0_u64; 3];
        for (limb_index, limb) in limbs.iter_mut().enumerate() {
            let mut attempt = 0_u64;
            loop {
                let mut candidate_hasher = self.hasher.clone();
                absorb_length_prefixed(&mut candidate_hasher, label);
                candidate_hasher.update(&self.challenge_counter.to_le_bytes());
                candidate_hasher.update(&(limb_index as u64).to_le_bytes());
                candidate_hasher.update(&attempt.to_le_bytes());
                let digest = candidate_hasher.finalize();
                let candidate = u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap());
                if candidate < GOLDILOCKS_MODULUS {
                    *limb = candidate;
                    break;
                }
                attempt = attempt.wrapping_add(1);
            }
        }
        self.challenge_counter = self.challenge_counter.wrapping_add(1);
        let challenge = ExtensionElement { limbs }
            .to_field()
            .expect("rejection-sampled limbs are canonical");
        self.absorb_field(b"derived-challenge", challenge);
        challenge
    }

    fn digest(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

fn absorb_statement(hasher: &mut Hasher, statement: StructuredTransitionStatement) {
    for value in [
        statement.layers as u64,
        statement.rows as u64,
        statement.cols as u64,
        statement.max_abs_accumulator,
        statement.max_mask,
    ] {
        hasher.update(&value.to_le_bytes());
    }
}

struct ProofReader<'a> {
    remaining: &'a [u8],
}

impl<'a> ProofReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], StructuredTransitionError> {
        if self.remaining.len() < count {
            return Err(StructuredTransitionError::Decode);
        }
        let (head, tail) = self.remaining.split_at(count);
        self.remaining = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, StructuredTransitionError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, StructuredTransitionError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four checked bytes"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StructuredTransitionError> {
        Ok(self.take(N)?.try_into().expect("checked array length"))
    }

    fn extension(&mut self) -> Result<ExtensionElement, StructuredTransitionError> {
        let mut limbs = [0_u64; 3];
        for limb in &mut limbs {
            *limb = u64::from_le_bytes(self.take(8)?.try_into().expect("eight checked bytes"));
        }
        let value = ExtensionElement { limbs };
        value.to_field()?;
        Ok(value)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockChallenge, StructuredMatrixStatement, prove_structured_matrix_product,
        v2_test_reference,
    };

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

    fn empty_witness() -> StructuredTransitionWitness {
        StructuredTransitionWitness {
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
        }
    }

    fn production_statement() -> StructuredTransitionStatement {
        StructuredTransitionStatement {
            layers: MAX_STRUCTURED_TRANSITION_LAYERS,
            rows: MAX_STRUCTURED_TRANSITION_ROWS,
            cols: MAX_STRUCTURED_TRANSITION_COLS,
            max_abs_accumulator: 64_000_000,
            max_mask: 5_000,
        }
    }

    fn zero_envelope(statement: StructuredTransitionStatement) -> StructuredTransitionProof {
        let zero = ExtensionElement { limbs: [0; 3] };
        StructuredTransitionProof {
            protocol_version: STRUCTURED_TRANSITION_VERSION,
            oracle_commitments: vec![[0; 32]; STRUCTURED_TRANSITION_ORACLES],
            rounds: (0..statement.elements().unwrap().ilog2())
                .map(|_| StructuredTransitionRound {
                    evaluations: vec![zero; STRUCTURED_TRANSITION_MAX_DEGREE + 1],
                })
                .collect(),
            terminal_evaluations: vec![zero; STRUCTURED_TRANSITION_ORACLES],
            transcript_digest: [0; 32],
        }
    }

    fn fixture() -> (
        StructuredTransitionStatement,
        StructuredMaskPolynomial,
        StructuredTransitionWitness,
    ) {
        let reference = v2_test_reference().unwrap();
        let proof = reference.prove_reference(&block(), 7).unwrap();
        let mut witness = empty_witness();
        for layer in &proof.layers {
            for ((accumulator, reduction), activation) in layer
                .accumulators
                .iter()
                .zip(&layer.reductions)
                .zip(&layer.output)
            {
                witness.accumulators.push(i64::from(*accumulator));
                witness
                    .masks
                    .push(u64::try_from(reduction.z - accumulator).unwrap());
                witness.encoded.push(u64::from(reduction.encoded_z));
                witness
                    .square_quotients
                    .push(u64::from(reduction.square_quotient));
                witness
                    .square_remainders
                    .push(u64::from(reduction.square_remainder));
                witness
                    .cube_quotients
                    .push(u64::from(reduction.cube_quotient));
                witness
                    .cube_remainders
                    .push(u64::from(reduction.cube_remainder));
                witness
                    .output_quotients
                    .push(u64::from(reduction.output_quotient));
                witness
                    .output_remainders
                    .push(u64::from(reduction.output_remainder));
                witness.negative.push(u64::from(reduction.z < 0));
                witness.activations.push(i64::from(*activation));
            }
        }
        let statement = StructuredTransitionStatement {
            layers: proof.layers.len(),
            rows: 2,
            cols: 4,
            max_abs_accumulator: 64_000_000,
            max_mask: 5_000,
        };
        let mask = StructuredMaskPolynomial::from_challenge(
            &proof.challenge_digest,
            statement.layers,
            statement.rows,
            statement.cols,
        )
        .unwrap();
        (statement, mask, witness)
    }

    #[test]
    fn production_shape_is_verifier_safe_but_not_materializable() {
        let statement = production_statement();
        let mask = StructuredMaskPolynomial::from_challenge(
            &[0x42; 32],
            statement.layers,
            statement.rows,
            statement.cols,
        )
        .unwrap();
        let witness = empty_witness();
        let proof = zero_envelope(statement);

        statement.validate_verifier_shape().unwrap();
        assert_eq!(statement.elements().unwrap(), 1 << 26);
        assert_eq!(statement.sumcheck_error_numerator().unwrap(), 442);
        assert!(matches!(
            verify_structured_transition_sumcheck(b"binding", statement, &mask, &proof),
            Err(StructuredTransitionError::MaskPolynomial)
        ));

        assert!(matches!(
            statement.validate_materialized_shape(),
            Err(StructuredTransitionError::ResearchCap)
        ));
        assert!(matches!(
            prove_structured_transition(b"binding", statement, &mask, &witness),
            Err(StructuredTransitionError::ResearchCap)
        ));
        assert!(matches!(
            verify_structured_transition(b"binding", statement, &mask, &witness, &proof),
            Err(StructuredTransitionError::ResearchCap)
        ));
        #[cfg(feature = "whir-prototype")]
        assert!(matches!(
            structured_transition_whir_tables(statement, &witness),
            Err(StructuredTransitionError::ResearchCap)
        ));
    }

    #[test]
    fn verifier_shape_rejects_invalid_over_max_and_overflowing_dimensions() {
        for invalid in [0, 3] {
            for (layers, rows, cols) in [(invalid, 1, 1), (1, invalid, 1), (1, 1, invalid)] {
                let statement = StructuredTransitionStatement {
                    layers,
                    rows,
                    cols,
                    ..production_statement()
                };
                assert!(matches!(
                    statement.validate_verifier_shape(),
                    Err(StructuredTransitionError::InvalidDimensions)
                ));
            }
        }

        for (layers, rows, cols) in [
            (MAX_STRUCTURED_TRANSITION_LAYERS * 2, 1, 1),
            (1, MAX_STRUCTURED_TRANSITION_ROWS * 2, 1),
            (1, 1, MAX_STRUCTURED_TRANSITION_COLS * 2),
        ] {
            let statement = StructuredTransitionStatement {
                layers,
                rows,
                cols,
                ..production_statement()
            };
            assert!(matches!(
                statement.validate_verifier_shape(),
                Err(StructuredTransitionError::ResearchCap)
            ));
        }
        assert_eq!(
            StructuredMaskPolynomial::from_challenge(
                &[0; 32],
                MAX_STRUCTURED_TRANSITION_LAYERS * 2,
                1,
                1,
            ),
            Err(StructuredTransitionError::ResearchCap)
        );
        assert_eq!(
            StructuredMaskPolynomial::from_virtual_challenge(
                &[0; 32],
                MAX_STRUCTURED_TRANSITION_ROWS * 2,
                1,
            ),
            Err(StructuredTransitionError::ResearchCap)
        );

        let high_bit = 1_usize << (usize::BITS - 1);
        for (layers, rows, cols) in [(high_bit, 2, 1), (1, high_bit, 2), (1, 2, high_bit)] {
            let statement = StructuredTransitionStatement {
                layers,
                rows,
                cols,
                ..production_statement()
            };
            assert!(matches!(
                statement.validate_verifier_shape(),
                Err(StructuredTransitionError::ArithmeticOverflow)
            ));
        }

        let unsafe_bounds = StructuredTransitionStatement {
            max_abs_accumulator: u64::from(V2_TRANSITION_MODULUS),
            ..production_statement()
        };
        assert!(matches!(
            unsafe_bounds.validate_verifier_shape(),
            Err(StructuredTransitionError::UnsafeIntegerBounds)
        ));
    }

    #[test]
    fn proves_every_devnet_transition_and_range_constraint() {
        let (statement, mask, witness) = fixture();
        let proof =
            prove_structured_transition(b"block-42/nonce-7", statement, &mask, &witness).unwrap();
        verify_structured_transition(b"block-42/nonce-7", statement, &mask, &witness, &proof)
            .unwrap();
        let claims =
            verify_structured_transition_sumcheck(b"block-42/nonce-7", statement, &mask, &proof)
                .unwrap();
        assert_eq!(claims.point.len(), 5);
        assert_eq!(claims.evaluations.len(), STRUCTURED_TRANSITION_ORACLES);
        assert_eq!(proof.rounds.len(), 5);
        assert_eq!(
            proof.oracle_commitments.len(),
            STRUCTURED_TRANSITION_ORACLES
        );
        assert_eq!(
            proof.terminal_evaluations.len(),
            STRUCTURED_TRANSITION_ORACLES
        );
        assert_eq!(proof.encode().unwrap().len(), 8_381);
    }

    #[test]
    fn invalid_local_relation_cannot_construct_a_proof() {
        let (statement, mask, mut witness) = fixture();
        witness.square_quotients[3] += 1;
        assert_eq!(
            prove_structured_transition(b"binding", statement, &mask, &witness),
            Err(StructuredTransitionError::RoundClaim)
        );

        let (statement, mask, mut witness) = fixture();
        witness.negative[4] ^= 1;
        assert_eq!(
            prove_structured_transition(b"binding", statement, &mask, &witness),
            Err(StructuredTransitionError::RoundClaim)
        );
    }

    #[test]
    fn proof_is_bound_and_mutations_are_rejected() {
        let (statement, mask, witness) = fixture();
        let proof = prove_structured_transition(b"binding", statement, &mask, &witness).unwrap();
        assert_eq!(
            verify_structured_transition(b"other", statement, &mask, &witness, &proof),
            Err(StructuredTransitionError::RoundClaim)
        );

        let mut changed_round = proof.clone();
        changed_round.rounds[0].evaluations[2].limbs[0] ^= 1;
        assert!(
            verify_structured_transition(b"binding", statement, &mask, &witness, &changed_round,)
                .is_err()
        );

        let mut changed_terminal = proof.clone();
        changed_terminal.terminal_evaluations[ENCODED].limbs[0] ^= 1;
        assert!(
            verify_structured_transition(
                b"binding",
                statement,
                &mask,
                &witness,
                &changed_terminal,
            )
            .is_err()
        );

        let other_mask = StructuredMaskPolynomial::from_challenge(
            &[0x99; 32],
            statement.layers,
            statement.rows,
            statement.cols,
        )
        .unwrap();
        assert!(
            verify_structured_transition(b"binding", statement, &other_mask, &witness, &proof,)
                .is_err()
        );
    }

    #[test]
    fn canonical_parser_rejects_malformed_proofs() {
        let (statement, mask, witness) = fixture();
        let proof = prove_structured_transition(b"binding", statement, &mask, &witness).unwrap();
        let encoded = proof.encode().unwrap();
        assert_eq!(StructuredTransitionProof::decode(&encoded).unwrap(), proof);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            StructuredTransitionProof::decode(&trailing),
            Err(StructuredTransitionError::Decode)
        );
        assert_eq!(
            StructuredTransitionProof::decode(&encoded[..encoded.len() - 1]),
            Err(StructuredTransitionError::Decode)
        );

        let terminal_start = encoded.len() - 32 - STRUCTURED_TRANSITION_ORACLES * 24;
        let mut noncanonical = encoded;
        noncanonical[terminal_start..terminal_start + 8]
            .copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert!(matches!(
            StructuredTransitionProof::decode(&noncanonical),
            Err(StructuredTransitionError::Field(
                StructuredSumcheckError::NonCanonicalField
            ))
        ));
    }

    #[test]
    fn protocol_shape_and_soundness_accounting_are_fixed() {
        let (statement, mask, witness) = fixture();
        let oracles = build_oracles(statement, &witness).unwrap();
        assert_eq!(oracles.len(), STRUCTURED_TRANSITION_ORACLES);
        assert_eq!(STRUCTURED_TRANSITION_REGULAR_ORACLES, 12);
        assert_eq!(STRUCTURED_TRANSITION_RANGE_SPEC_COUNT, 8);
        assert_eq!(STRUCTURED_TRANSITION_RANGE_DIGITS_PER_CELL, 49);
        assert_eq!(
            STRUCTURED_TRANSITION_RANGE_ORACLES,
            [2, 3, 4, 5, 6, 7, 8, 11]
        );
        assert_eq!(STRUCTURED_TRANSITION_RANGE_DIGITS, [7, 7, 7, 7, 7, 5, 2, 7]);
        assert_eq!(
            structured_transition_range_specs(statement)
                .unwrap()
                .map(|spec| spec.digits),
            STRUCTURED_TRANSITION_RANGE_DIGITS
        );
        assert_eq!(STRUCTURED_TRANSITION_CONSTRAINTS, 121);
        assert_eq!(statement.sumcheck_error_numerator().unwrap(), 85);
        for (index, expected) in witness.masks.iter().copied().enumerate() {
            let point = (0..statement.elements().unwrap().ilog2())
                .map(|bit| ExtensionField::from_u64(((index >> bit) & 1) as u64))
                .collect::<Vec<_>>();
            assert_eq!(mask.evaluate(&point), ExtensionField::from_u64(expected));
            assert_eq!(
                mask.value_at_boolean_index(statement, index).unwrap(),
                expected
            );
        }
        assert_eq!(
            mask.value_at_boolean_index(statement, statement.elements().unwrap()),
            Err(StructuredTransitionError::InvalidDimensions)
        );
    }

    #[test]
    fn virtual_input_mask_uses_the_reserved_layer_tag() {
        let challenge = [0x42; 32];
        let virtual_mask =
            StructuredMaskPolynomial::from_virtual_challenge(&challenge, 2, 4).unwrap();
        let layer_zero = StructuredMaskPolynomial::from_challenge(&challenge, 1, 2, 4).unwrap();
        assert_eq!(virtual_mask.layers, 1);
        assert_eq!(
            virtual_mask.coefficients,
            mask_coefficients(&challenge, u32::MAX, 2, 4)
        );
        assert_eq!(
            layer_zero.coefficients,
            mask_coefficients(&challenge, 0, 2, 4)
        );
        assert_ne!(virtual_mask.digest(), layer_zero.digest());
    }

    #[test]
    fn matrix_and_transition_arguments_share_the_accumulator_commitment() {
        let reference = v2_test_reference().unwrap();
        let trace = reference.prove_reference(&block(), 7).unwrap();
        let model = reference.accelerator_model();
        let matrix_statement = StructuredMatrixStatement {
            layers: model.layers() as usize,
            rows: model.rows() as usize,
            inner: model.width() as usize,
            cols: model.width() as usize,
            max_abs_activation: 125,
            max_abs_weight: 125,
            max_abs_accumulator: 64_000_000,
        };
        let mut activations = trace
            .initial_activation
            .iter()
            .map(|value| i64::from(*value))
            .collect::<Vec<_>>();
        for layer in trace.layers.iter().take(trace.layers.len() - 1) {
            activations.extend(layer.output.iter().map(|value| i64::from(*value)));
        }
        let weights = model
            .weights()
            .iter()
            .map(|value| i64::from(*value) - 125)
            .collect::<Vec<_>>();
        let accumulators = trace
            .layers
            .iter()
            .flat_map(|layer| layer.accumulators.iter().map(|value| i64::from(*value)))
            .collect::<Vec<_>>();
        let matrix = prove_structured_matrix_product(
            &trace.challenge_digest,
            matrix_statement,
            &activations,
            &weights,
            &accumulators,
        )
        .unwrap();
        let (transition_statement, mask, transition_witness) = fixture();
        let transition = prove_structured_transition(
            &trace.challenge_digest,
            transition_statement,
            &mask,
            &transition_witness,
        )
        .unwrap();
        assert_eq!(
            matrix.accumulator_commitment,
            transition.oracle_commitments[ACCUMULATOR]
        );
    }
}
