//! Structured, bank-batched matrix sumcheck for ForgeMatrix v2 research.
//!
//! This module is the first component of the custom production-proof path. It
//! batches every matrix relation in one power-of-two layer bank and reduces it
//! to two multilinear openings. Challenges live in a cubic extension of the
//! Goldilocks field, giving roughly 192 bits of challenge space.
//!
//! The current verifier still receives the complete matrices to check the two
//! terminal openings. That full-table opening adapter is intentionally not a
//! production PCS. Consensus activation requires replacing it with a pinned,
//! transparent, independently audited multilinear polynomial commitment.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const STRUCTURED_SUMCHECK_VERSION: u32 = 1;
pub const MAX_STRUCTURED_MATRIX_ELEMENTS: usize = 1 << 20;
pub const MAX_STRUCTURED_SUMCHECK_PROOF_BYTES: usize = 64 * 1024;
pub const STRUCTURED_SUMCHECK_CHALLENGE_BITS: u32 = 191;

pub(crate) const MAX_STRUCTURED_MATRIX_LAYERS: usize = 128;
pub(crate) const MAX_STRUCTURED_MATRIX_ROWS: usize = 128;
pub(crate) const MAX_STRUCTURED_MATRIX_INNER: usize = 4096;
pub(crate) const MAX_STRUCTURED_MATRIX_COLS: usize = 4096;

pub(crate) const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
const PROOF_MAGIC: &[u8; 8] = b"CMFDSM01";
const TRANSCRIPT_DOMAIN: &str = "CMFD/FORGEMATRIX/STRUCTURED-MATRIX/V1";
const COMMITMENT_DOMAIN: &str = "CMFD/FORGEMATRIX/STRUCTURED-TABLE/V1";
const MAX_SUMCHECK_ROUNDS: usize = 64;

/// Exact public shape and integer bounds for one layer bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMatrixStatement {
    pub layers: usize,
    pub rows: usize,
    pub inner: usize,
    pub cols: usize,
    pub max_abs_activation: u64,
    pub max_abs_weight: u64,
    pub max_abs_accumulator: u64,
}

impl StructuredMatrixStatement {
    pub fn sumcheck_error_numerator(&self) -> Result<u32, StructuredSumcheckError> {
        self.validate_verifier_shape()?;
        Ok(2 * self.inner.ilog2() + 3 * self.layers.ilog2())
    }

    pub(crate) fn validate_verifier_shape(&self) -> Result<(), StructuredSumcheckError> {
        if self.layers == 0
            || self.rows == 0
            || self.inner == 0
            || self.cols == 0
            || !self.layers.is_power_of_two()
            || !self.rows.is_power_of_two()
            || !self.inner.is_power_of_two()
            || !self.cols.is_power_of_two()
        {
            return Err(StructuredSumcheckError::InvalidDimensions);
        }
        self.table_lengths()?;
        if self.layers > MAX_STRUCTURED_MATRIX_LAYERS
            || self.rows > MAX_STRUCTURED_MATRIX_ROWS
            || self.inner > MAX_STRUCTURED_MATRIX_INNER
            || self.cols > MAX_STRUCTURED_MATRIX_COLS
        {
            return Err(StructuredSumcheckError::ResearchCap);
        }
        if self.max_abs_activation == 0
            || self.max_abs_weight == 0
            || self.max_abs_accumulator == 0
            || self.max_abs_activation >= GOLDILOCKS_MODULUS
            || self.max_abs_weight >= GOLDILOCKS_MODULUS
            || self.max_abs_accumulator >= GOLDILOCKS_MODULUS
        {
            return Err(StructuredSumcheckError::UnsafeIntegerBounds);
        }
        let maximum_dot_product = (self.inner as u128)
            .checked_mul(u128::from(self.max_abs_activation))
            .and_then(|value| value.checked_mul(u128::from(self.max_abs_weight)))
            .ok_or(StructuredSumcheckError::ArithmeticOverflow)?;
        let maximum_difference = maximum_dot_product
            .checked_add(u128::from(self.max_abs_accumulator))
            .ok_or(StructuredSumcheckError::ArithmeticOverflow)?;
        if maximum_difference >= u128::from(GOLDILOCKS_MODULUS) {
            return Err(StructuredSumcheckError::UnsafeIntegerBounds);
        }
        Ok(())
    }

    pub(crate) fn validate_materialized_shape(&self) -> Result<(), StructuredSumcheckError> {
        self.validate_verifier_shape()?;
        let [activation_len, weight_len, accumulator_len] = self.table_lengths()?;
        if activation_len > MAX_STRUCTURED_MATRIX_ELEMENTS
            || weight_len > MAX_STRUCTURED_MATRIX_ELEMENTS
            || accumulator_len > MAX_STRUCTURED_MATRIX_ELEMENTS
        {
            return Err(StructuredSumcheckError::ResearchCap);
        }
        Ok(())
    }

    fn table_lengths(&self) -> Result<[usize; 3], StructuredSumcheckError> {
        Ok([
            checked_product(&[self.layers, self.rows, self.inner])?,
            checked_product(&[self.layers, self.inner, self.cols])?,
            checked_product(&[self.layers, self.rows, self.cols])?,
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionElement {
    pub limbs: [u64; 3],
}

impl ExtensionElement {
    pub(crate) fn from_field(value: ExtensionField) -> Self {
        Self {
            limbs: [value.0[0].0, value.0[1].0, value.0[2].0],
        }
    }

    pub(crate) fn to_field(self) -> Result<ExtensionField, StructuredSumcheckError> {
        Ok(ExtensionField([
            BaseField::canonical(self.limbs[0])?,
            BaseField::canonical(self.limbs[1])?,
            BaseField::canonical(self.limbs[2])?,
        ]))
    }

    pub(crate) fn encode(self, output: &mut Vec<u8>) {
        for limb in self.limbs {
            output.extend_from_slice(&limb.to_le_bytes());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMatrixRound {
    pub evaluations: Vec<ExtensionElement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMatrixProof {
    pub protocol_version: u32,
    pub activation_commitment: [u8; 32],
    pub weight_commitment: [u8; 32],
    pub accumulator_commitment: [u8; 32],
    pub accumulator_evaluation: ExtensionElement,
    pub rounds: Vec<StructuredMatrixRound>,
    pub activation_evaluation: ExtensionElement,
    pub weight_evaluation: ExtensionElement,
    pub transcript_digest: [u8; 32],
}

/// PCS claims produced after checking the matrix sumcheck transcript.
///
/// This is not a complete proof result.  A caller must authenticate every
/// returned commitment/point/evaluation tuple with the selected PCS before
/// accepting the matrix relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredMatrixOpeningClaims {
    pub activation_commitment: [u8; 32],
    pub weight_commitment: [u8; 32],
    pub accumulator_commitment: [u8; 32],
    pub activation_point: Vec<ExtensionElement>,
    pub weight_point: Vec<ExtensionElement>,
    pub accumulator_point: Vec<ExtensionElement>,
    pub activation_evaluation: ExtensionElement,
    pub weight_evaluation: ExtensionElement,
    pub accumulator_evaluation: ExtensionElement,
}

impl StructuredMatrixProof {
    pub fn encode(&self) -> Result<Vec<u8>, StructuredSumcheckError> {
        if self.rounds.len() > MAX_SUMCHECK_ROUNDS
            || self
                .rounds
                .iter()
                .any(|round| !matches!(round.evaluations.len(), 3 | 4))
        {
            return Err(StructuredSumcheckError::RoundCount);
        }
        self.accumulator_evaluation.to_field()?;
        self.activation_evaluation.to_field()?;
        self.weight_evaluation.to_field()?;
        for round in &self.rounds {
            for evaluation in &round.evaluations {
                evaluation.to_field()?;
            }
        }
        let mut output = Vec::with_capacity(self.canonical_size());
        output.extend_from_slice(PROOF_MAGIC);
        output.extend_from_slice(&self.protocol_version.to_le_bytes());
        output.extend_from_slice(&self.activation_commitment);
        output.extend_from_slice(&self.weight_commitment);
        output.extend_from_slice(&self.accumulator_commitment);
        self.accumulator_evaluation.encode(&mut output);
        output.extend_from_slice(&(self.rounds.len() as u32).to_le_bytes());
        for round in &self.rounds {
            output.push(round.evaluations.len() as u8);
            for evaluation in &round.evaluations {
                evaluation.encode(&mut output);
            }
        }
        self.activation_evaluation.encode(&mut output);
        self.weight_evaluation.encode(&mut output);
        output.extend_from_slice(&self.transcript_digest);
        if output.len() > MAX_STRUCTURED_SUMCHECK_PROOF_BYTES {
            return Err(StructuredSumcheckError::ProofTooLarge);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StructuredSumcheckError> {
        if bytes.len() > MAX_STRUCTURED_SUMCHECK_PROOF_BYTES {
            return Err(StructuredSumcheckError::ProofTooLarge);
        }
        let mut reader = ProofReader::new(bytes);
        if reader.take(8)? != PROOF_MAGIC {
            return Err(StructuredSumcheckError::Decode);
        }
        let protocol_version = reader.u32()?;
        let activation_commitment = reader.array()?;
        let weight_commitment = reader.array()?;
        let accumulator_commitment = reader.array()?;
        let accumulator_evaluation = reader.extension()?;
        let round_count = reader.u32()? as usize;
        if round_count > MAX_SUMCHECK_ROUNDS {
            return Err(StructuredSumcheckError::RoundCount);
        }
        let mut rounds = Vec::with_capacity(round_count);
        for _ in 0..round_count {
            let count = usize::from(reader.u8()?);
            if !matches!(count, 3 | 4) {
                return Err(StructuredSumcheckError::RoundDegree);
            }
            let mut evaluations = Vec::with_capacity(count);
            for _ in 0..count {
                evaluations.push(reader.extension()?);
            }
            rounds.push(StructuredMatrixRound { evaluations });
        }
        let activation_evaluation = reader.extension()?;
        let weight_evaluation = reader.extension()?;
        let transcript_digest = reader.array()?;
        if !reader.is_empty() {
            return Err(StructuredSumcheckError::Decode);
        }
        Ok(Self {
            protocol_version,
            activation_commitment,
            weight_commitment,
            accumulator_commitment,
            accumulator_evaluation,
            rounds,
            activation_evaluation,
            weight_evaluation,
            transcript_digest,
        })
    }

    pub fn canonical_size(&self) -> usize {
        8 + 4
            + 3 * 32
            + 24
            + 4
            + self
                .rounds
                .iter()
                .map(|round| 1 + 24 * round.evaluations.len())
                .sum::<usize>()
            + 2 * 24
            + 32
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StructuredSumcheckError {
    #[error("matrix dimensions must be nonzero powers of two")]
    InvalidDimensions,
    #[error("matrix input length does not match the statement")]
    InvalidLength,
    #[error("structured proof research tables exceed their element cap")]
    ResearchCap,
    #[error("integer bounds do not exclude Goldilocks field wraparound")]
    UnsafeIntegerBounds,
    #[error("matrix value exceeds its declared exact-integer bound")]
    ValueOutOfRange,
    #[error("integer arithmetic overflowed while validating the statement")]
    ArithmeticOverflow,
    #[error("structured proof protocol version mismatch")]
    ProtocolVersion,
    #[error("matrix table commitment mismatch")]
    Commitment,
    #[error("proof contains a noncanonical extension-field element")]
    NonCanonicalField,
    #[error("structured proof has the wrong number of rounds")]
    RoundCount,
    #[error("structured proof round has the wrong polynomial degree")]
    RoundDegree,
    #[error("sumcheck round does not preserve the current claim")]
    RoundClaim,
    #[error("sumcheck terminal product claim is invalid")]
    TerminalClaim,
    #[error("claimed terminal opening does not match its table")]
    Opening,
    #[error("structured proof transcript digest mismatch")]
    Transcript,
    #[error("structured proof is larger than its research cap")]
    ProofTooLarge,
    #[error("structured proof encoding is truncated, malformed, or has trailing bytes")]
    Decode,
}

#[allow(clippy::too_many_arguments)]
pub fn prove_structured_matrix_product(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weights: &[i64],
    accumulators: &[i64],
) -> Result<StructuredMatrixProof, StructuredSumcheckError> {
    validate_tables(statement, activations, weights, accumulators)?;
    let activation_values = field_values(activations);
    let weight_values = field_values(weights);
    let accumulator_values = field_values(accumulators);
    let activation_commitment = table_commitment(&activation_values);
    let weight_commitment = table_commitment(&weight_values);
    let accumulator_commitment = table_commitment(&accumulator_values);
    prove_structured_matrix_product_fields(
        binding,
        statement,
        activation_values,
        weight_values,
        accumulator_values,
        [
            activation_commitment,
            weight_commitment,
            accumulator_commitment,
        ],
    )
}

/// Builds the matrix transcript using commitments supplied by an aggregate
/// PCS. The PCS must later authenticate all returned terminal openings.
#[cfg(feature = "whir-prototype")]
#[allow(clippy::too_many_arguments)]
pub fn prove_structured_matrix_product_with_commitments(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weights: &[i64],
    accumulators: &[i64],
    commitments: [[u8; 32]; 3],
) -> Result<StructuredMatrixProof, StructuredSumcheckError> {
    validate_tables(statement, activations, weights, accumulators)?;
    prove_structured_matrix_product_fields(
        binding,
        statement,
        field_values(activations),
        field_values(weights),
        field_values(accumulators),
        commitments,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_structured_matrix_product_fields(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activation_values: Vec<ExtensionField>,
    weight_values: Vec<ExtensionField>,
    accumulator_values: Vec<ExtensionField>,
    commitments: [[u8; 32]; 3],
) -> Result<StructuredMatrixProof, StructuredSumcheckError> {
    let [
        activation_commitment,
        weight_commitment,
        accumulator_commitment,
    ] = commitments;
    let mut transcript = MatrixTranscript::new(
        binding,
        statement,
        activation_commitment,
        weight_commitment,
        accumulator_commitment,
    );
    let layer_point = transcript.challenge_vector(b"layer-point", statement.layers.ilog2());
    let row_point = transcript.challenge_vector(b"row-point", statement.rows.ilog2());
    let col_point = transcript.challenge_vector(b"column-point", statement.cols.ilog2());

    let mut accumulator_point = col_point.clone();
    accumulator_point.extend_from_slice(&row_point);
    accumulator_point.extend_from_slice(&layer_point);
    let accumulator_evaluation = evaluate_mle(&accumulator_values, &accumulator_point);
    transcript.absorb_field(b"accumulator-evaluation", accumulator_evaluation);

    let layer_weights = equality_weights(&layer_point);
    let row_weights = equality_weights(&row_point);
    let col_weights = equality_weights(&col_point);
    let table_len = statement.layers * statement.inner;
    let mut layer_selector = Vec::with_capacity(table_len);
    let mut activation_partial = Vec::with_capacity(table_len);
    let mut weight_partial = Vec::with_capacity(table_len);
    for (layer, layer_weight) in layer_weights.iter().copied().enumerate() {
        for common in 0..statement.inner {
            layer_selector.push(layer_weight);
            let mut activation = ExtensionField::ZERO;
            for (row, row_weight) in row_weights.iter().copied().enumerate() {
                let index = (layer * statement.rows + row) * statement.inner + common;
                activation = activation.add(activation_values[index].mul(row_weight));
            }
            activation_partial.push(activation);

            let mut weight = ExtensionField::ZERO;
            for (col, col_weight) in col_weights.iter().copied().enumerate() {
                let index = (layer * statement.inner + common) * statement.cols + col;
                weight = weight.add(weight_values[index].mul(col_weight));
            }
            weight_partial.push(weight);
        }
    }

    let mut claim = accumulator_evaluation;
    let mut rounds = Vec::with_capacity((statement.inner * statement.layers).ilog2() as usize);
    for round_index in 0..statement.inner.ilog2() {
        let evaluations = product_round(&layer_selector, &activation_partial, &weight_partial, 2);
        if evaluations[0].add(evaluations[1]) != claim {
            return Err(StructuredSumcheckError::RoundClaim);
        }
        transcript.absorb_round(b"common-round", round_index, &evaluations);
        let challenge = transcript.challenge(b"common-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        layer_selector = fold(&layer_selector, challenge);
        activation_partial = fold(&activation_partial, challenge);
        weight_partial = fold(&weight_partial, challenge);
        rounds.push(StructuredMatrixRound {
            evaluations: evaluations
                .into_iter()
                .map(ExtensionElement::from_field)
                .collect(),
        });
    }
    for round_index in 0..statement.layers.ilog2() {
        let evaluations = product_round(&layer_selector, &activation_partial, &weight_partial, 3);
        if evaluations[0].add(evaluations[1]) != claim {
            return Err(StructuredSumcheckError::RoundClaim);
        }
        transcript.absorb_round(b"layer-round", round_index, &evaluations);
        let challenge = transcript.challenge(b"layer-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        layer_selector = fold(&layer_selector, challenge);
        activation_partial = fold(&activation_partial, challenge);
        weight_partial = fold(&weight_partial, challenge);
        rounds.push(StructuredMatrixRound {
            evaluations: evaluations
                .into_iter()
                .map(ExtensionElement::from_field)
                .collect(),
        });
    }
    debug_assert_eq!(layer_selector.len(), 1);
    debug_assert_eq!(activation_partial.len(), 1);
    debug_assert_eq!(weight_partial.len(), 1);
    if claim
        != layer_selector[0]
            .mul(activation_partial[0])
            .mul(weight_partial[0])
    {
        return Err(StructuredSumcheckError::TerminalClaim);
    }
    transcript.absorb_field(b"activation-evaluation", activation_partial[0]);
    transcript.absorb_field(b"weight-evaluation", weight_partial[0]);
    let transcript_digest = transcript.digest();

    Ok(StructuredMatrixProof {
        protocol_version: STRUCTURED_SUMCHECK_VERSION,
        activation_commitment,
        weight_commitment,
        accumulator_commitment,
        accumulator_evaluation: ExtensionElement::from_field(accumulator_evaluation),
        rounds,
        activation_evaluation: ExtensionElement::from_field(activation_partial[0]),
        weight_evaluation: ExtensionElement::from_field(weight_partial[0]),
        transcript_digest,
    })
}

/// Returns the canonical base-field tables committed by the experimental
/// aggregate WHIR backend, in activation/weight/accumulator order.
#[cfg(feature = "whir-prototype")]
pub fn structured_matrix_whir_tables(
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weights: &[i64],
    accumulators: &[i64],
) -> Result<Vec<Vec<u64>>, StructuredSumcheckError> {
    validate_tables(statement, activations, weights, accumulators)?;
    Ok(vec![
        base_table_values(&field_values(activations)),
        base_table_values(&field_values(weights)),
        base_table_values(&field_values(accumulators)),
    ])
}

#[allow(clippy::too_many_arguments)]
pub fn verify_structured_matrix_product(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weights: &[i64],
    accumulators: &[i64],
    proof: &StructuredMatrixProof,
) -> Result<(), StructuredSumcheckError> {
    validate_tables(statement, activations, weights, accumulators)?;
    let activation_values = field_values(activations);
    let weight_values = field_values(weights);
    let accumulator_values = field_values(accumulators);
    let activation_commitment = table_commitment(&activation_values);
    let weight_commitment = table_commitment(&weight_values);
    let accumulator_commitment = table_commitment(&accumulator_values);
    let claims = verify_structured_matrix_sumcheck(binding, statement, proof)?;
    if claims.activation_commitment != activation_commitment
        || claims.weight_commitment != weight_commitment
        || claims.accumulator_commitment != accumulator_commitment
    {
        return Err(StructuredSumcheckError::Commitment);
    }
    let activation_point = claims
        .activation_point
        .iter()
        .copied()
        .map(ExtensionElement::to_field)
        .collect::<Result<Vec<_>, _>>()?;
    let weight_point = claims
        .weight_point
        .iter()
        .copied()
        .map(ExtensionElement::to_field)
        .collect::<Result<Vec<_>, _>>()?;
    let accumulator_point = claims
        .accumulator_point
        .iter()
        .copied()
        .map(ExtensionElement::to_field)
        .collect::<Result<Vec<_>, _>>()?;
    if claims.activation_evaluation.to_field()?
        != evaluate_mle(&activation_values, &activation_point)
        || claims.weight_evaluation.to_field()? != evaluate_mle(&weight_values, &weight_point)
        || claims.accumulator_evaluation.to_field()?
            != evaluate_mle(&accumulator_values, &accumulator_point)
    {
        return Err(StructuredSumcheckError::Opening);
    }
    Ok(())
}

/// Checks the Fiat--Shamir matrix sumcheck and derives its PCS opening claims.
///
/// This function deliberately does not authenticate an opening.  Production
/// consensus must call a hardened PCS verifier for every returned claim.
pub fn verify_structured_matrix_sumcheck(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    proof: &StructuredMatrixProof,
) -> Result<StructuredMatrixOpeningClaims, StructuredSumcheckError> {
    statement.validate_verifier_shape()?;
    if proof.protocol_version != STRUCTURED_SUMCHECK_VERSION {
        return Err(StructuredSumcheckError::ProtocolVersion);
    }
    let common_rounds = statement.inner.ilog2() as usize;
    let layer_rounds = statement.layers.ilog2() as usize;
    if proof.rounds.len() != common_rounds + layer_rounds {
        return Err(StructuredSumcheckError::RoundCount);
    }
    let mut transcript = MatrixTranscript::new(
        binding,
        statement,
        proof.activation_commitment,
        proof.weight_commitment,
        proof.accumulator_commitment,
    );
    let layer_point = transcript.challenge_vector(b"layer-point", statement.layers.ilog2());
    let row_point = transcript.challenge_vector(b"row-point", statement.rows.ilog2());
    let col_point = transcript.challenge_vector(b"column-point", statement.cols.ilog2());
    let accumulator_evaluation = proof.accumulator_evaluation.to_field()?;
    let mut accumulator_point = col_point.clone();
    accumulator_point.extend_from_slice(&row_point);
    accumulator_point.extend_from_slice(&layer_point);
    transcript.absorb_field(b"accumulator-evaluation", accumulator_evaluation);

    let mut claim = accumulator_evaluation;
    let mut common_point = Vec::with_capacity(common_rounds);
    let mut layer_sumcheck_point = Vec::with_capacity(layer_rounds);
    for (index, round) in proof.rounds.iter().enumerate() {
        let degree = if index < common_rounds { 2 } else { 3 };
        if round.evaluations.len() != degree + 1 {
            return Err(StructuredSumcheckError::RoundDegree);
        }
        let evaluations = round
            .evaluations
            .iter()
            .copied()
            .map(ExtensionElement::to_field)
            .collect::<Result<Vec<_>, _>>()?;
        if evaluations[0].add(evaluations[1]) != claim {
            return Err(StructuredSumcheckError::RoundClaim);
        }
        let phase_index = if index < common_rounds {
            index as u32
        } else {
            (index - common_rounds) as u32
        };
        let (phase, challenge_label) = if index < common_rounds {
            (b"common-round".as_slice(), b"common-challenge".as_slice())
        } else {
            (b"layer-round".as_slice(), b"layer-challenge".as_slice())
        };
        transcript.absorb_round(phase, phase_index, &evaluations);
        let challenge = transcript.challenge(challenge_label);
        claim = evaluate_samples(&evaluations, challenge)?;
        if index < common_rounds {
            common_point.push(challenge);
        } else {
            layer_sumcheck_point.push(challenge);
        }
    }

    let activation_evaluation = proof.activation_evaluation.to_field()?;
    let weight_evaluation = proof.weight_evaluation.to_field()?;
    let selector_evaluation = equality_evaluation(&layer_point, &layer_sumcheck_point);
    if claim
        != selector_evaluation
            .mul(activation_evaluation)
            .mul(weight_evaluation)
    {
        return Err(StructuredSumcheckError::TerminalClaim);
    }
    let mut activation_point = common_point.clone();
    activation_point.extend_from_slice(&row_point);
    activation_point.extend_from_slice(&layer_sumcheck_point);
    let mut weight_point = col_point.clone();
    weight_point.extend_from_slice(&common_point);
    weight_point.extend_from_slice(&layer_sumcheck_point);
    transcript.absorb_field(b"activation-evaluation", activation_evaluation);
    transcript.absorb_field(b"weight-evaluation", weight_evaluation);
    if proof.transcript_digest != transcript.digest() {
        return Err(StructuredSumcheckError::Transcript);
    }
    Ok(StructuredMatrixOpeningClaims {
        activation_commitment: proof.activation_commitment,
        weight_commitment: proof.weight_commitment,
        accumulator_commitment: proof.accumulator_commitment,
        activation_point: activation_point
            .into_iter()
            .map(ExtensionElement::from_field)
            .collect(),
        weight_point: weight_point
            .into_iter()
            .map(ExtensionElement::from_field)
            .collect(),
        accumulator_point: accumulator_point
            .into_iter()
            .map(ExtensionElement::from_field)
            .collect(),
        activation_evaluation: proof.activation_evaluation,
        weight_evaluation: proof.weight_evaluation,
        accumulator_evaluation: proof.accumulator_evaluation,
    })
}

fn validate_tables(
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weights: &[i64],
    accumulators: &[i64],
) -> Result<(), StructuredSumcheckError> {
    statement.validate_materialized_shape()?;
    let [activation_len, weight_len, accumulator_len] = statement.table_lengths()?;
    if activations.len() != activation_len
        || weights.len() != weight_len
        || accumulators.len() != accumulator_len
    {
        return Err(StructuredSumcheckError::InvalidLength);
    }
    validate_values(activations, statement.max_abs_activation)?;
    validate_values(weights, statement.max_abs_weight)?;
    validate_values(accumulators, statement.max_abs_accumulator)?;
    Ok(())
}

fn validate_values(values: &[i64], maximum: u64) -> Result<(), StructuredSumcheckError> {
    if values.iter().any(|value| value.unsigned_abs() > maximum) {
        return Err(StructuredSumcheckError::ValueOutOfRange);
    }
    Ok(())
}

fn checked_product(values: &[usize]) -> Result<usize, StructuredSumcheckError> {
    values.iter().try_fold(1_usize, |product, value| {
        product
            .checked_mul(*value)
            .ok_or(StructuredSumcheckError::ArithmeticOverflow)
    })
}

fn field_values(values: &[i64]) -> Vec<ExtensionField> {
    values
        .iter()
        .copied()
        .map(ExtensionField::from_signed)
        .collect()
}

#[cfg(feature = "whir-prototype")]
pub(crate) fn base_table_values(values: &[ExtensionField]) -> Vec<u64> {
    values
        .iter()
        .map(|value| {
            debug_assert_eq!(value.0[1].0, 0);
            debug_assert_eq!(value.0[2].0, 0);
            value.0[0].0
        })
        .collect()
}

pub(crate) fn table_commitment(values: &[ExtensionField]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(COMMITMENT_DOMAIN);
    hasher.update(&(values.len() as u64).to_le_bytes());
    for value in values {
        hasher.update(&value.encode());
    }
    *hasher.finalize().as_bytes()
}

fn product_round(
    selector: &[ExtensionField],
    left: &[ExtensionField],
    right: &[ExtensionField],
    degree: usize,
) -> Vec<ExtensionField> {
    debug_assert_eq!(selector.len(), left.len());
    debug_assert_eq!(left.len(), right.len());
    debug_assert_eq!(selector.len() % 2, 0);
    (0..=degree)
        .map(|sample| {
            let point = ExtensionField::from_u64(sample as u64);
            selector
                .chunks_exact(2)
                .zip(left.chunks_exact(2))
                .zip(right.chunks_exact(2))
                .fold(ExtensionField::ZERO, |sum, ((s, l), r)| {
                    sum.add(
                        interpolate_pair(s, point)
                            .mul(interpolate_pair(l, point))
                            .mul(interpolate_pair(r, point)),
                    )
                })
        })
        .collect()
}

pub(crate) fn interpolate_pair(pair: &[ExtensionField], point: ExtensionField) -> ExtensionField {
    pair[0].add(pair[1].sub(pair[0]).mul(point))
}

fn evaluate_samples(
    values: &[ExtensionField],
    point: ExtensionField,
) -> Result<ExtensionField, StructuredSumcheckError> {
    match values.len() {
        3 => {
            let first = values[1].sub(values[0]);
            let second = values[2]
                .sub(values[1].mul(ExtensionField::from_u64(2)))
                .add(values[0]);
            Ok(values[0].add(first.mul(point)).add(
                second
                    .mul(point)
                    .mul(point.sub(ExtensionField::ONE))
                    .mul(ExtensionField::from_u64(2).inverse()?),
            ))
        }
        4 => {
            let first = values[1].sub(values[0]);
            let second = values[2]
                .sub(values[1].mul(ExtensionField::from_u64(2)))
                .add(values[0]);
            let third = values[3]
                .sub(values[2].mul(ExtensionField::from_u64(3)))
                .add(values[1].mul(ExtensionField::from_u64(3)))
                .sub(values[0]);
            Ok(values[0]
                .add(first.mul(point))
                .add(
                    second
                        .mul(point)
                        .mul(point.sub(ExtensionField::ONE))
                        .mul(ExtensionField::from_u64(2).inverse()?),
                )
                .add(
                    third
                        .mul(point)
                        .mul(point.sub(ExtensionField::ONE))
                        .mul(point.sub(ExtensionField::from_u64(2)))
                        .mul(ExtensionField::from_u64(6).inverse()?),
                ))
        }
        _ => Err(StructuredSumcheckError::RoundDegree),
    }
}

pub(crate) fn equality_weights(point: &[ExtensionField]) -> Vec<ExtensionField> {
    let mut weights = vec![ExtensionField::ONE];
    for challenge in point {
        let previous = weights;
        let half = previous.len();
        weights = vec![ExtensionField::ZERO; half * 2];
        for (index, value) in previous.into_iter().enumerate() {
            weights[index] = value.mul(ExtensionField::ONE.sub(*challenge));
            weights[index + half] = value.mul(*challenge);
        }
    }
    weights
}

pub(crate) fn equality_evaluation(
    left: &[ExtensionField],
    right: &[ExtensionField],
) -> ExtensionField {
    debug_assert_eq!(left.len(), right.len());
    left.iter()
        .zip(right)
        .fold(ExtensionField::ONE, |product, (left, right)| {
            product.mul(
                left.mul(*right).add(
                    ExtensionField::ONE
                        .sub(*left)
                        .mul(ExtensionField::ONE.sub(*right)),
                ),
            )
        })
}

pub(crate) fn evaluate_mle(
    evaluations: &[ExtensionField],
    point: &[ExtensionField],
) -> ExtensionField {
    debug_assert_eq!(evaluations.len(), 1_usize << point.len());
    let mut table = evaluations.to_vec();
    for challenge in point {
        table = fold(&table, *challenge);
    }
    table[0]
}

pub(crate) fn fold(table: &[ExtensionField], challenge: ExtensionField) -> Vec<ExtensionField> {
    debug_assert_eq!(table.len() % 2, 0);
    table
        .chunks_exact(2)
        .map(|pair| interpolate_pair(pair, challenge))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaseField(u64);

impl BaseField {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    fn canonical(value: u64) -> Result<Self, StructuredSumcheckError> {
        if value < GOLDILOCKS_MODULUS {
            Ok(Self(value))
        } else {
            Err(StructuredSumcheckError::NonCanonicalField)
        }
    }

    fn from_u64(value: u64) -> Self {
        Self(value % GOLDILOCKS_MODULUS)
    }

    fn from_signed(value: i64) -> Self {
        if value >= 0 {
            Self::from_u64(value as u64)
        } else {
            let magnitude = value.unsigned_abs() % GOLDILOCKS_MODULUS;
            if magnitude == 0 {
                Self::ZERO
            } else {
                Self(GOLDILOCKS_MODULUS - magnitude)
            }
        }
    }

    fn add(self, rhs: Self) -> Self {
        Self(((u128::from(self.0) + u128::from(rhs.0)) % u128::from(GOLDILOCKS_MODULUS)) as u64)
    }

    fn sub(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            Self(self.0 - rhs.0)
        } else {
            Self(GOLDILOCKS_MODULUS - (rhs.0 - self.0))
        }
    }

    fn mul(self, rhs: Self) -> Self {
        Self(((u128::from(self.0) * u128::from(rhs.0)) % u128::from(GOLDILOCKS_MODULUS)) as u64)
    }

    fn inverse(self) -> Result<Self, StructuredSumcheckError> {
        if self == Self::ZERO {
            return Err(StructuredSumcheckError::ArithmeticOverflow);
        }
        let mut base = self;
        let mut exponent = GOLDILOCKS_MODULUS - 2;
        let mut result = Self::ONE;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exponent >>= 1;
        }
        Ok(result)
    }
}

/// Goldilocks cubic extension with `u^3 = u + 1`, matching Plonky3's
/// `CubicTrinomialExtensionField<Goldilocks>` selected for the transparent-PCS
/// adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExtensionField([BaseField; 3]);

impl ExtensionField {
    pub(crate) const ZERO: Self = Self([BaseField::ZERO; 3]);
    pub(crate) const ONE: Self = Self([BaseField::ONE, BaseField::ZERO, BaseField::ZERO]);

    pub(crate) fn from_u64(value: u64) -> Self {
        Self([BaseField::from_u64(value), BaseField::ZERO, BaseField::ZERO])
    }

    pub(crate) fn from_signed(value: i64) -> Self {
        Self([
            BaseField::from_signed(value),
            BaseField::ZERO,
            BaseField::ZERO,
        ])
    }

    pub(crate) fn from_canonical_limbs(limbs: [u64; 3]) -> Result<Self, StructuredSumcheckError> {
        Ok(Self([
            BaseField::canonical(limbs[0])?,
            BaseField::canonical(limbs[1])?,
            BaseField::canonical(limbs[2])?,
        ]))
    }

    pub(crate) fn add(self, rhs: Self) -> Self {
        Self([
            self.0[0].add(rhs.0[0]),
            self.0[1].add(rhs.0[1]),
            self.0[2].add(rhs.0[2]),
        ])
    }

    pub(crate) fn sub(self, rhs: Self) -> Self {
        Self([
            self.0[0].sub(rhs.0[0]),
            self.0[1].sub(rhs.0[1]),
            self.0[2].sub(rhs.0[2]),
        ])
    }

    pub(crate) fn mul(self, rhs: Self) -> Self {
        let cross_three = self.0[1].mul(rhs.0[2]).add(self.0[2].mul(rhs.0[1]));
        let degree_four = self.0[2].mul(rhs.0[2]);
        Self([
            self.0[0].mul(rhs.0[0]).add(cross_three),
            self.0[0]
                .mul(rhs.0[1])
                .add(self.0[1].mul(rhs.0[0]))
                .add(cross_three)
                .add(degree_four),
            self.0[0]
                .mul(rhs.0[2])
                .add(self.0[1].mul(rhs.0[1]))
                .add(self.0[2].mul(rhs.0[0]))
                .add(degree_four),
        ])
    }

    pub(crate) fn inverse(self) -> Result<Self, StructuredSumcheckError> {
        if self == Self::ZERO {
            return Err(StructuredSumcheckError::ArithmeticOverflow);
        }
        // Inversion is only used for the base-field constants 2 and 6.
        if self.0[1] != BaseField::ZERO || self.0[2] != BaseField::ZERO {
            return Err(StructuredSumcheckError::ArithmeticOverflow);
        }
        Ok(Self([
            self.0[0].inverse()?,
            BaseField::ZERO,
            BaseField::ZERO,
        ]))
    }

    pub(crate) fn encode(self) -> [u8; 24] {
        let mut encoded = [0_u8; 24];
        for (index, limb) in self.0.iter().enumerate() {
            encoded[index * 8..(index + 1) * 8].copy_from_slice(&limb.0.to_le_bytes());
        }
        encoded
    }
}

struct MatrixTranscript {
    hasher: Hasher,
    challenge_counter: u64,
}

impl MatrixTranscript {
    fn new(
        binding: &[u8],
        statement: StructuredMatrixStatement,
        activation_commitment: [u8; 32],
        weight_commitment: [u8; 32],
        accumulator_commitment: [u8; 32],
    ) -> Self {
        let mut transcript = Self {
            hasher: Hasher::new_derive_key(TRANSCRIPT_DOMAIN),
            challenge_counter: 0,
        };
        transcript.absorb(
            b"protocol-version",
            &STRUCTURED_SUMCHECK_VERSION.to_le_bytes(),
        );
        transcript.absorb(b"public-binding", binding);
        let mut encoded_statement = Hasher::new();
        absorb_statement(&mut encoded_statement, statement);
        transcript.absorb(b"statement", encoded_statement.finalize().as_bytes());
        transcript.absorb(b"activation-commitment", &activation_commitment);
        transcript.absorb(b"weight-commitment", &weight_commitment);
        transcript.absorb(b"accumulator-commitment", &accumulator_commitment);
        transcript
    }

    fn absorb(&mut self, label: &[u8], value: &[u8]) {
        absorb_length_prefixed(&mut self.hasher, label);
        absorb_length_prefixed(&mut self.hasher, value);
    }

    fn absorb_field(&mut self, label: &[u8], value: ExtensionField) {
        self.absorb(label, &value.encode());
    }

    fn absorb_round(&mut self, phase: &[u8], index: u32, values: &[ExtensionField]) {
        self.absorb(b"round-phase", phase);
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
        let mut limbs = [BaseField::ZERO; 3];
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
                    *limb = BaseField(candidate);
                    break;
                }
                attempt = attempt.wrapping_add(1);
            }
        }
        self.challenge_counter = self.challenge_counter.wrapping_add(1);
        let challenge = ExtensionField(limbs);
        self.absorb_field(b"derived-challenge", challenge);
        challenge
    }

    fn digest(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

fn absorb_statement(hasher: &mut Hasher, statement: StructuredMatrixStatement) {
    for value in [
        statement.layers as u64,
        statement.rows as u64,
        statement.inner as u64,
        statement.cols as u64,
        statement.max_abs_activation,
        statement.max_abs_weight,
        statement.max_abs_accumulator,
    ] {
        hasher.update(&value.to_le_bytes());
    }
}

pub(crate) fn absorb_length_prefixed(hasher: &mut Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

struct ProofReader<'a> {
    remaining: &'a [u8],
}

impl<'a> ProofReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], StructuredSumcheckError> {
        if self.remaining.len() < count {
            return Err(StructuredSumcheckError::Decode);
        }
        let (head, tail) = self.remaining.split_at(count);
        self.remaining = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, StructuredSumcheckError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, StructuredSumcheckError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four checked bytes"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StructuredSumcheckError> {
        Ok(self.take(N)?.try_into().expect("checked array length"))
    }

    fn extension(&mut self) -> Result<ExtensionElement, StructuredSumcheckError> {
        let mut limbs = [0_u64; 3];
        for limb in &mut limbs {
            *limb = u64::from_le_bytes(self.take(8)?.try_into().expect("eight checked bytes"));
            BaseField::canonical(*limb)?;
        }
        Ok(ExtensionElement { limbs })
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockChallenge, v2_test_reference};

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

    fn fixture() -> (StructuredMatrixStatement, Vec<i64>, Vec<i64>, Vec<i64>) {
        let statement = StructuredMatrixStatement {
            layers: 4,
            rows: 2,
            inner: 4,
            cols: 4,
            max_abs_activation: 125,
            max_abs_weight: 125,
            max_abs_accumulator: 64_000_000,
        };
        let activations = (0..statement.layers * statement.rows * statement.inner)
            .map(|index| index as i64 % 17 - 8)
            .collect::<Vec<_>>();
        let weights = (0..statement.layers * statement.inner * statement.cols)
            .map(|index| (index * 7) as i64 % 23 - 11)
            .collect::<Vec<_>>();
        let mut accumulators = Vec::new();
        for layer in 0..statement.layers {
            for row in 0..statement.rows {
                for col in 0..statement.cols {
                    let mut value = 0_i64;
                    for common in 0..statement.inner {
                        value += activations
                            [(layer * statement.rows + row) * statement.inner + common]
                            * weights[(layer * statement.inner + common) * statement.cols + col];
                    }
                    accumulators.push(value);
                }
            }
        }
        (statement, activations, weights, accumulators)
    }

    fn production_statement() -> StructuredMatrixStatement {
        StructuredMatrixStatement {
            layers: MAX_STRUCTURED_MATRIX_LAYERS,
            rows: MAX_STRUCTURED_MATRIX_ROWS,
            inner: MAX_STRUCTURED_MATRIX_INNER,
            cols: MAX_STRUCTURED_MATRIX_COLS,
            max_abs_activation: 125,
            max_abs_weight: 125,
            max_abs_accumulator: 64_000_000,
        }
    }

    fn zero_envelope(statement: StructuredMatrixStatement) -> StructuredMatrixProof {
        let zero = ExtensionElement { limbs: [0; 3] };
        let common_rounds = (0..statement.inner.ilog2()).map(|_| StructuredMatrixRound {
            evaluations: vec![zero; 3],
        });
        let layer_rounds = (0..statement.layers.ilog2()).map(|_| StructuredMatrixRound {
            evaluations: vec![zero; 4],
        });
        StructuredMatrixProof {
            protocol_version: STRUCTURED_SUMCHECK_VERSION,
            activation_commitment: [0; 32],
            weight_commitment: [0; 32],
            accumulator_commitment: [0; 32],
            accumulator_evaluation: zero,
            rounds: common_rounds.chain(layer_rounds).collect(),
            activation_evaluation: zero,
            weight_evaluation: zero,
            transcript_digest: [0; 32],
        }
    }

    #[test]
    fn production_shape_is_verifier_safe_but_not_materializable() {
        let statement = production_statement();
        statement.validate_verifier_shape().unwrap();
        assert_eq!(statement.sumcheck_error_numerator().unwrap(), 45);
        assert!(matches!(
            verify_structured_matrix_sumcheck(b"binding", statement, &zero_envelope(statement)),
            Err(StructuredSumcheckError::Transcript)
        ));

        assert!(matches!(
            statement.validate_materialized_shape(),
            Err(StructuredSumcheckError::ResearchCap)
        ));
        assert!(matches!(
            prove_structured_matrix_product(b"binding", statement, &[], &[], &[]),
            Err(StructuredSumcheckError::ResearchCap)
        ));
        assert!(matches!(
            verify_structured_matrix_product(
                b"binding",
                statement,
                &[],
                &[],
                &[],
                &zero_envelope(statement),
            ),
            Err(StructuredSumcheckError::ResearchCap)
        ));
        #[cfg(feature = "whir-prototype")]
        assert!(matches!(
            structured_matrix_whir_tables(statement, &[], &[], &[]),
            Err(StructuredSumcheckError::ResearchCap)
        ));
    }

    #[test]
    fn verifier_shape_rejects_invalid_over_max_and_overflowing_dimensions() {
        for invalid in [0, 3] {
            for (layers, rows, inner, cols) in [
                (invalid, 1, 1, 1),
                (1, invalid, 1, 1),
                (1, 1, invalid, 1),
                (1, 1, 1, invalid),
            ] {
                let statement = StructuredMatrixStatement {
                    layers,
                    rows,
                    inner,
                    cols,
                    ..production_statement()
                };
                assert!(matches!(
                    statement.validate_verifier_shape(),
                    Err(StructuredSumcheckError::InvalidDimensions)
                ));
            }
        }

        for (layers, rows, inner, cols) in [
            (MAX_STRUCTURED_MATRIX_LAYERS * 2, 1, 1, 1),
            (1, MAX_STRUCTURED_MATRIX_ROWS * 2, 1, 1),
            (1, 1, MAX_STRUCTURED_MATRIX_INNER * 2, 1),
            (1, 1, 1, MAX_STRUCTURED_MATRIX_COLS * 2),
        ] {
            let statement = StructuredMatrixStatement {
                layers,
                rows,
                inner,
                cols,
                ..production_statement()
            };
            assert!(matches!(
                statement.validate_verifier_shape(),
                Err(StructuredSumcheckError::ResearchCap)
            ));
        }

        let high_bit = 1_usize << (usize::BITS - 1);
        for (layers, rows, inner, cols) in [
            (high_bit, 2, 1, 1),
            (1, 1, 2, high_bit),
            (1, 2, 1, high_bit),
        ] {
            let statement = StructuredMatrixStatement {
                layers,
                rows,
                inner,
                cols,
                ..production_statement()
            };
            assert!(matches!(
                statement.validate_verifier_shape(),
                Err(StructuredSumcheckError::ArithmeticOverflow)
            ));
        }
    }

    #[test]
    fn cubic_extension_uses_plonky3_goldilocks_polynomial() {
        let u = ExtensionField([BaseField::ZERO, BaseField::ONE, BaseField::ZERO]);
        assert_eq!(u.mul(u).mul(u), u.add(ExtensionField::ONE));
    }

    #[test]
    fn batched_matrix_sumcheck_round_trips_and_is_canonical() {
        let (statement, activations, weights, accumulators) = fixture();
        let proof = prove_structured_matrix_product(
            b"block-model-nonce-binding",
            statement,
            &activations,
            &weights,
            &accumulators,
        )
        .unwrap();
        verify_structured_matrix_product(
            b"block-model-nonce-binding",
            statement,
            &activations,
            &weights,
            &accumulators,
            &proof,
        )
        .unwrap();
        let claims =
            verify_structured_matrix_sumcheck(b"block-model-nonce-binding", statement, &proof)
                .unwrap();
        assert_eq!(claims.activation_point.len(), 5);
        assert_eq!(claims.weight_point.len(), 6);
        assert_eq!(claims.accumulator_point.len(), 5);
        assert_eq!(proof.rounds.len(), 4);
        assert_eq!(proof.rounds[0].evaluations.len(), 3);
        assert_eq!(proof.rounds[2].evaluations.len(), 4);
        let encoded = proof.encode().unwrap();
        assert_eq!(encoded.len(), proof.canonical_size());
        assert_eq!(encoded.len(), 556);
        assert_eq!(StructuredMatrixProof::decode(&encoded).unwrap(), proof);
        assert_eq!(statement.sumcheck_error_numerator().unwrap(), 10);
    }

    #[test]
    fn every_statement_table_and_round_is_bound() {
        let (statement, activations, weights, accumulators) = fixture();
        let mut proof = prove_structured_matrix_product(
            b"statement-a",
            statement,
            &activations,
            &weights,
            &accumulators,
        )
        .unwrap();
        assert!(
            verify_structured_matrix_product(
                b"statement-b",
                statement,
                &activations,
                &weights,
                &accumulators,
                &proof,
            )
            .is_err()
        );

        let mut changed_accumulators = accumulators.clone();
        changed_accumulators[17] += 1;
        assert!(matches!(
            verify_structured_matrix_product(
                b"statement-a",
                statement,
                &activations,
                &weights,
                &changed_accumulators,
                &proof,
            ),
            Err(StructuredSumcheckError::Commitment)
        ));

        assert!(matches!(
            prove_structured_matrix_product(
                b"statement-a",
                statement,
                &activations,
                &weights,
                &changed_accumulators,
            ),
            Err(StructuredSumcheckError::RoundClaim)
        ));

        proof.rounds[0].evaluations[0].limbs[0] ^= 1;
        assert!(matches!(
            verify_structured_matrix_product(
                b"statement-a",
                statement,
                &activations,
                &weights,
                &accumulators,
                &proof,
            ),
            Err(StructuredSumcheckError::RoundClaim) | Err(StructuredSumcheckError::TerminalClaim)
        ));
    }

    #[test]
    fn unsafe_bounds_noncanonical_fields_and_malformed_encodings_are_rejected() {
        let (mut statement, activations, weights, accumulators) = fixture();
        statement.max_abs_accumulator = GOLDILOCKS_MODULUS - 1;
        assert!(matches!(
            prove_structured_matrix_product(
                b"binding",
                statement,
                &activations,
                &weights,
                &accumulators,
            ),
            Err(StructuredSumcheckError::UnsafeIntegerBounds)
        ));

        let (statement, activations, weights, accumulators) = fixture();
        let proof = prove_structured_matrix_product(
            b"binding",
            statement,
            &activations,
            &weights,
            &accumulators,
        )
        .unwrap();
        let mut encoded = proof.encode().unwrap();
        let field_offset = 8 + 4 + 3 * 32;
        encoded[field_offset..field_offset + 8].copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert!(matches!(
            StructuredMatrixProof::decode(&encoded),
            Err(StructuredSumcheckError::NonCanonicalField)
        ));

        let mut trailing = proof.encode().unwrap();
        trailing.push(0);
        assert!(matches!(
            StructuredMatrixProof::decode(&trailing),
            Err(StructuredSumcheckError::Decode)
        ));
        let canonical = proof.encode().unwrap();
        for length in 0..canonical.len() {
            assert!(StructuredMatrixProof::decode(&canonical[..length]).is_err());
        }
    }

    #[test]
    fn actual_forgematrix_trace_satisfies_the_batched_matrix_statement() {
        let reference = v2_test_reference().unwrap();
        let trace = reference.prove_reference(&block(), 7).unwrap();
        let model = reference.accelerator_model();
        let statement = StructuredMatrixStatement {
            layers: model.layers() as usize,
            rows: model.rows() as usize,
            inner: model.width() as usize,
            cols: model.width() as usize,
            max_abs_activation: 125,
            max_abs_weight: 125,
            max_abs_accumulator: 64_000_000,
        };
        let mut activations = Vec::new();
        activations.extend(
            trace
                .initial_activation
                .iter()
                .map(|value| i64::from(*value)),
        );
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
        let proof = prove_structured_matrix_product(
            &trace.challenge_digest,
            statement,
            &activations,
            &weights,
            &accumulators,
        )
        .unwrap();
        verify_structured_matrix_product(
            &trace.challenge_digest,
            statement,
            &activations,
            &weights,
            &accumulators,
            &proof,
        )
        .unwrap();
        assert_eq!(proof.encode().unwrap().len(), 556);
    }
}
