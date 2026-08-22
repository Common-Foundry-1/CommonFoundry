//! Successor-wiring argument for ForgeMatrix v2 research.
//!
//! The argument proves that every transition output is the next matrix input.
//! Within each power-of-two layer bank, a random multilinear identity reduces
//! all successor edges to logarithmically many openings.  Fixed-layer openings
//! check initialization and every cross-bank boundary.  The current full-table
//! adapter verifies those openings directly; production consensus must
//! authenticate the same claims with the selected transparent PCS.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::structured_sumcheck::{
    ExtensionElement, ExtensionField, GOLDILOCKS_MODULUS, StructuredMatrixProof,
    StructuredSumcheckError, absorb_length_prefixed, evaluate_mle, table_commitment,
};
use crate::structured_transition::{
    STRUCTURED_TRANSITION_ACTIVATION_ORACLE, STRUCTURED_TRANSITION_INPUT_ORACLE,
    StructuredTransitionProof,
};

pub const STRUCTURED_WIRING_VERSION: u32 = 1;
pub const MAX_STRUCTURED_WIRING_BANKS: usize = 3;
pub const MAX_STRUCTURED_WIRING_ELEMENTS: usize = 1 << 20;
pub const MAX_STRUCTURED_WIRING_PROOF_BYTES: usize = 64 * 1024;

pub(crate) const MAX_STRUCTURED_WIRING_LAYERS_PER_BANK: usize = 128;
pub(crate) const MAX_STRUCTURED_WIRING_ROWS: usize = 128;
pub(crate) const MAX_STRUCTURED_WIRING_COLS: usize = 4096;
const MAX_STRUCTURED_WIRING_VERIFIER_ELEMENTS: usize = 3 * (1 << 26);

const PROOF_MAGIC: &[u8; 8] = b"CMFDSW01";
const TRANSCRIPT_DOMAIN: &str = "CMFD/FORGEMATRIX/STRUCTURED-WIRING/V1";
const MAX_LAYER_BITS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredWiringStatement {
    pub banks: usize,
    pub layers_per_bank: usize,
    pub rows: usize,
    pub cols: usize,
    pub max_abs_activation: u64,
}

impl StructuredWiringStatement {
    pub fn soundness_error_numerator(&self) -> Result<u32, StructuredWiringError> {
        self.validate_verifier_shape()?;
        let cell_variables = self.cell_variables();
        let all_variables = cell_variables
            .checked_add(self.layers_per_bank.ilog2())
            .ok_or(StructuredWiringError::ArithmeticOverflow)?;
        let within = u32::try_from(self.banks)
            .ok()
            .and_then(|banks| banks.checked_mul(all_variables))
            .ok_or(StructuredWiringError::ArithmeticOverflow)?;
        let fixed_identities = u32::try_from(self.banks)
            .ok()
            .and_then(|banks| banks.checked_mul(cell_variables))
            .ok_or(StructuredWiringError::ArithmeticOverflow)?;
        within
            .checked_add(fixed_identities)
            .ok_or(StructuredWiringError::ArithmeticOverflow)
    }

    pub(crate) fn validate_verifier_shape(&self) -> Result<(), StructuredWiringError> {
        if self.banks == 0
            || self.layers_per_bank < 2
            || self.rows == 0
            || self.cols == 0
            || !self.layers_per_bank.is_power_of_two()
            || !self.rows.is_power_of_two()
            || !self.cols.is_power_of_two()
        {
            return Err(StructuredWiringError::InvalidDimensions);
        }
        let elements = self.elements()?;
        if self.banks > MAX_STRUCTURED_WIRING_BANKS
            || self.layers_per_bank > MAX_STRUCTURED_WIRING_LAYERS_PER_BANK
            || self.rows > MAX_STRUCTURED_WIRING_ROWS
            || self.cols > MAX_STRUCTURED_WIRING_COLS
            || elements > MAX_STRUCTURED_WIRING_VERIFIER_ELEMENTS
        {
            return Err(StructuredWiringError::ResearchCap);
        }
        if self.max_abs_activation == 0 || self.max_abs_activation >= GOLDILOCKS_MODULUS {
            return Err(StructuredWiringError::UnsafeIntegerBounds);
        }
        Ok(())
    }

    pub(crate) fn validate_materialized_shape(&self) -> Result<(), StructuredWiringError> {
        self.validate_verifier_shape()?;
        if self.elements()? > MAX_STRUCTURED_WIRING_ELEMENTS {
            return Err(StructuredWiringError::ResearchCap);
        }
        Ok(())
    }

    pub(crate) fn elements(&self) -> Result<usize, StructuredWiringError> {
        checked_product(&[self.banks, self.layers_per_bank, self.rows, self.cols])
    }

    pub(crate) fn bank_elements(&self) -> Result<usize, StructuredWiringError> {
        checked_product(&[self.layers_per_bank, self.rows, self.cols])
    }

    pub(crate) fn cell_variables(&self) -> u32 {
        self.cols.ilog2() + self.rows.ilog2()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredWiringProof {
    pub protocol_version: u32,
    pub initial_commitment: [u8; 32],
    pub input_commitments: Vec<[u8; 32]>,
    pub output_commitments: Vec<[u8; 32]>,
    pub initial_evaluation: ExtensionElement,
    pub input_shift_evaluations: Vec<ExtensionElement>,
    pub input_first_evaluations: Vec<ExtensionElement>,
    pub output_random_evaluations: Vec<ExtensionElement>,
    pub output_last_evaluations: Vec<ExtensionElement>,
    pub transcript_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredWiringOpeningClaim {
    pub commitment: [u8; 32],
    pub point: Vec<ExtensionElement>,
    pub evaluation: ExtensionElement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredWiringOpeningClaims {
    pub openings: Vec<StructuredWiringOpeningClaim>,
    /// Authenticated opening of the last layer in the last output bank.
    pub final_output: StructuredWiringOpeningClaim,
}

impl StructuredWiringProof {
    pub fn encode(&self) -> Result<Vec<u8>, StructuredWiringError> {
        self.validate_shape()?;
        let mut output = Vec::with_capacity(self.canonical_size());
        output.extend_from_slice(PROOF_MAGIC);
        output.extend_from_slice(&self.protocol_version.to_le_bytes());
        output.extend_from_slice(&self.initial_commitment);
        encode_commitments(&mut output, &self.input_commitments);
        encode_commitments(&mut output, &self.output_commitments);
        self.initial_evaluation.encode(&mut output);
        encode_evaluations(&mut output, &self.input_shift_evaluations)?;
        encode_evaluations(&mut output, &self.input_first_evaluations)?;
        encode_evaluations(&mut output, &self.output_random_evaluations)?;
        encode_evaluations(&mut output, &self.output_last_evaluations)?;
        output.extend_from_slice(&self.transcript_digest);
        if output.len() > MAX_STRUCTURED_WIRING_PROOF_BYTES {
            return Err(StructuredWiringError::ProofTooLarge);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StructuredWiringError> {
        if bytes.len() > MAX_STRUCTURED_WIRING_PROOF_BYTES {
            return Err(StructuredWiringError::ProofTooLarge);
        }
        let mut reader = ProofReader::new(bytes);
        if reader.take(PROOF_MAGIC.len())? != PROOF_MAGIC {
            return Err(StructuredWiringError::Decode);
        }
        let proof = Self {
            protocol_version: reader.u32()?,
            initial_commitment: reader.array()?,
            input_commitments: reader.commitments()?,
            output_commitments: reader.commitments()?,
            initial_evaluation: reader.extension()?,
            input_shift_evaluations: reader.evaluations()?,
            input_first_evaluations: reader.evaluations()?,
            output_random_evaluations: reader.evaluations()?,
            output_last_evaluations: reader.evaluations()?,
            transcript_digest: reader.array()?,
        };
        if !reader.is_empty() {
            return Err(StructuredWiringError::Decode);
        }
        proof.validate_shape()?;
        Ok(proof)
    }

    pub fn canonical_size(&self) -> usize {
        8 + 4
            + 32
            + 4
            + self.input_commitments.len() * 32
            + 4
            + self.output_commitments.len() * 32
            + 24
            + 4
            + self.input_shift_evaluations.len() * 24
            + 4
            + self.input_first_evaluations.len() * 24
            + 4
            + self.output_random_evaluations.len() * 24
            + 4
            + self.output_last_evaluations.len() * 24
            + 32
    }

    fn validate_shape(&self) -> Result<(), StructuredWiringError> {
        let banks = self.input_commitments.len();
        if banks == 0
            || banks > MAX_STRUCTURED_WIRING_BANKS
            || self.output_commitments.len() != banks
            || self.input_shift_evaluations.len() > banks * MAX_LAYER_BITS
            || self.input_first_evaluations.len() > banks
            || self.output_random_evaluations.len() > banks
            || self.output_last_evaluations.len() > banks
        {
            return Err(StructuredWiringError::EvaluationCount);
        }
        self.initial_evaluation.to_field()?;
        for evaluation in self
            .input_shift_evaluations
            .iter()
            .chain(&self.input_first_evaluations)
            .chain(&self.output_random_evaluations)
            .chain(&self.output_last_evaluations)
        {
            evaluation.to_field()?;
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StructuredWiringError {
    #[error("wiring dimensions must use bounded power-of-two layer and cell axes")]
    InvalidDimensions,
    #[error("wiring activation table length does not match the statement")]
    InvalidLength,
    #[error("structured wiring tables exceed their research element cap")]
    ResearchCap,
    #[error("wiring activation bounds do not enforce canonical field values")]
    UnsafeIntegerBounds,
    #[error("wiring activation is outside its declared range")]
    ValueOutOfRange,
    #[error("integer arithmetic overflowed while validating wiring")]
    ArithmeticOverflow,
    #[error("structured wiring protocol version mismatch")]
    ProtocolVersion,
    #[error("structured wiring proof has the wrong bank count")]
    BankCount,
    #[error("matrix, transition, and wiring component counts do not match")]
    ComponentCount,
    #[error("structured wiring proof has the wrong evaluation count")]
    EvaluationCount,
    #[error("structured wiring commitment does not match its activation table")]
    Commitment,
    #[error("a ForgeMatrix initialization, successor, or bank-boundary identity failed")]
    WiringIdentity,
    #[error("structured wiring opening does not match its activation table")]
    Opening,
    #[error("structured wiring transcript digest mismatch")]
    Transcript,
    #[error("structured wiring proof is larger than its research cap")]
    ProofTooLarge,
    #[error("structured wiring proof is truncated, malformed, or has trailing bytes")]
    Decode,
    #[error("structured wiring field operation failed: {0}")]
    Field(#[from] StructuredSumcheckError),
}

pub fn prove_structured_wiring(
    binding: &[u8],
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
) -> Result<StructuredWiringProof, StructuredWiringError> {
    validate_tables(statement, initial, inputs, outputs)?;
    validate_successors(statement, initial, inputs, outputs)?;
    let initial_values = initial
        .iter()
        .copied()
        .map(ExtensionField::from_signed)
        .collect::<Vec<_>>();
    let input_banks = bank_field_values(statement, inputs)?;
    let output_banks = bank_field_values(statement, outputs)?;
    let initial_commitment = table_commitment(&initial_values);
    let input_commitments = input_banks
        .iter()
        .map(|bank| table_commitment(bank))
        .collect::<Vec<_>>();
    let output_commitments = output_banks
        .iter()
        .map(|bank| table_commitment(bank))
        .collect::<Vec<_>>();
    prove_structured_wiring_fields(
        binding,
        statement,
        initial_values,
        input_banks,
        output_banks,
        initial_commitment,
        input_commitments,
        output_commitments,
    )
}

/// Builds the wiring transcript using commitments supplied by an aggregate
/// PCS. The PCS must later authenticate all returned activation openings.
#[cfg(feature = "whir-prototype")]
#[allow(clippy::too_many_arguments)]
pub fn prove_structured_wiring_with_commitments(
    binding: &[u8],
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    initial_commitment: [u8; 32],
    input_commitments: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
) -> Result<StructuredWiringProof, StructuredWiringError> {
    validate_tables(statement, initial, inputs, outputs)?;
    validate_successors(statement, initial, inputs, outputs)?;
    if input_commitments.len() != statement.banks || output_commitments.len() != statement.banks {
        return Err(StructuredWiringError::ComponentCount);
    }
    prove_structured_wiring_fields(
        binding,
        statement,
        initial
            .iter()
            .copied()
            .map(ExtensionField::from_signed)
            .collect(),
        bank_field_values(statement, inputs)?,
        bank_field_values(statement, outputs)?,
        initial_commitment,
        input_commitments,
        output_commitments,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_structured_wiring_fields(
    binding: &[u8],
    statement: StructuredWiringStatement,
    initial_values: Vec<ExtensionField>,
    input_banks: Vec<Vec<ExtensionField>>,
    output_banks: Vec<Vec<ExtensionField>>,
    initial_commitment: [u8; 32],
    input_commitments: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
) -> Result<StructuredWiringProof, StructuredWiringError> {
    let mut transcript = WiringTranscript::new(
        binding,
        statement,
        initial_commitment,
        &input_commitments,
        &output_commitments,
    );
    let points = WiringPoints::derive(statement, &mut transcript);
    let evaluations = compute_evaluations(
        statement,
        &points,
        &initial_values,
        &input_banks,
        &output_banks,
    );
    transcript.absorb_evaluations(&evaluations);
    let proof = StructuredWiringProof {
        protocol_version: STRUCTURED_WIRING_VERSION,
        initial_commitment,
        input_commitments,
        output_commitments,
        initial_evaluation: ExtensionElement::from_field(evaluations.initial),
        input_shift_evaluations: encode_fields(&evaluations.input_shift),
        input_first_evaluations: encode_fields(&evaluations.input_first),
        output_random_evaluations: encode_fields(&evaluations.output_random),
        output_last_evaluations: encode_fields(&evaluations.output_last),
        transcript_digest: transcript.digest(),
    };
    verify_structured_wiring_openings(binding, statement, &proof)?;
    Ok(proof)
}

/// Returns initial, input-bank, and output-bank tables in wiring transcript
/// order for the experimental aggregate WHIR backend.
#[cfg(feature = "whir-prototype")]
pub fn structured_wiring_whir_tables(
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
) -> Result<Vec<Vec<u64>>, StructuredWiringError> {
    validate_tables(statement, initial, inputs, outputs)?;
    validate_successors(statement, initial, inputs, outputs)?;
    let initial_values = initial
        .iter()
        .copied()
        .map(ExtensionField::from_signed)
        .collect::<Vec<_>>();
    let input_banks = bank_field_values(statement, inputs)?;
    let output_banks = bank_field_values(statement, outputs)?;
    Ok(
        std::iter::once(crate::structured_sumcheck::base_table_values(
            &initial_values,
        ))
        .chain(
            input_banks
                .iter()
                .map(|bank| crate::structured_sumcheck::base_table_values(bank)),
        )
        .chain(
            output_banks
                .iter()
                .map(|bank| crate::structured_sumcheck::base_table_values(bank)),
        )
        .collect(),
    )
}

pub fn verify_structured_wiring(
    binding: &[u8],
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    proof: &StructuredWiringProof,
) -> Result<(), StructuredWiringError> {
    validate_tables(statement, initial, inputs, outputs)?;
    validate_successors(statement, initial, inputs, outputs)?;
    let initial_values = initial
        .iter()
        .copied()
        .map(ExtensionField::from_signed)
        .collect::<Vec<_>>();
    let input_banks = bank_field_values(statement, inputs)?;
    let output_banks = bank_field_values(statement, outputs)?;
    let initial_commitment = table_commitment(&initial_values);
    let input_commitments = input_banks
        .iter()
        .map(|bank| table_commitment(bank))
        .collect::<Vec<_>>();
    let output_commitments = output_banks
        .iter()
        .map(|bank| table_commitment(bank))
        .collect::<Vec<_>>();
    if proof.initial_commitment != initial_commitment
        || proof.input_commitments != input_commitments
        || proof.output_commitments != output_commitments
    {
        return Err(StructuredWiringError::Commitment);
    }
    verify_structured_wiring_openings(binding, statement, proof)?;

    let mut transcript = WiringTranscript::new(
        binding,
        statement,
        initial_commitment,
        &input_commitments,
        &output_commitments,
    );
    let points = WiringPoints::derive(statement, &mut transcript);
    let expected = compute_evaluations(
        statement,
        &points,
        &initial_values,
        &input_banks,
        &output_banks,
    );
    if decode_evaluations(proof)? != expected {
        return Err(StructuredWiringError::Opening);
    }
    Ok(())
}

/// Binds each wiring input/output oracle to the corresponding matrix and
/// transition component commitment. Each component verifier must still check
/// its own transcript with the same public binding.
pub fn verify_structured_wiring_component_commitments(
    statement: StructuredWiringStatement,
    base_input_commitment: [u8; 32],
    initialization_proof: &StructuredTransitionProof,
    matrix_proofs: &[StructuredMatrixProof],
    transition_proofs: &[StructuredTransitionProof],
    wiring_proof: &StructuredWiringProof,
) -> Result<(), StructuredWiringError> {
    statement.validate_verifier_shape()?;
    if matrix_proofs.len() != statement.banks
        || transition_proofs.len() != statement.banks
        || wiring_proof.input_commitments.len() != statement.banks
        || wiring_proof.output_commitments.len() != statement.banks
    {
        return Err(StructuredWiringError::ComponentCount);
    }
    let initialization_input = initialization_proof
        .oracle_commitments
        .get(STRUCTURED_TRANSITION_INPUT_ORACLE)
        .ok_or(StructuredWiringError::ComponentCount)?;
    let initialization_output = initialization_proof
        .oracle_commitments
        .get(STRUCTURED_TRANSITION_ACTIVATION_ORACLE)
        .ok_or(StructuredWiringError::ComponentCount)?;
    if *initialization_input != base_input_commitment
        || *initialization_output != wiring_proof.initial_commitment
    {
        return Err(StructuredWiringError::Commitment);
    }
    for bank in 0..statement.banks {
        let transition_input = transition_proofs[bank]
            .oracle_commitments
            .get(STRUCTURED_TRANSITION_INPUT_ORACLE)
            .ok_or(StructuredWiringError::ComponentCount)?;
        let transition_output = transition_proofs[bank]
            .oracle_commitments
            .get(STRUCTURED_TRANSITION_ACTIVATION_ORACLE)
            .ok_or(StructuredWiringError::ComponentCount)?;
        if matrix_proofs[bank].activation_commitment != wiring_proof.input_commitments[bank]
            || matrix_proofs[bank].accumulator_commitment != *transition_input
            || *transition_output != wiring_proof.output_commitments[bank]
        {
            return Err(StructuredWiringError::Commitment);
        }
    }
    Ok(())
}

/// Checks the successor identities and returns all PCS opening claims.
///
/// This does not authenticate an opening. Production consensus must verify
/// every returned claim with the pinned transparent PCS.
pub fn verify_structured_wiring_openings(
    binding: &[u8],
    statement: StructuredWiringStatement,
    proof: &StructuredWiringProof,
) -> Result<StructuredWiringOpeningClaims, StructuredWiringError> {
    statement.validate_verifier_shape()?;
    proof.validate_shape()?;
    if proof.protocol_version != STRUCTURED_WIRING_VERSION {
        return Err(StructuredWiringError::ProtocolVersion);
    }
    let layer_bits = statement.layers_per_bank.ilog2() as usize;
    if proof.input_commitments.len() != statement.banks
        || proof.output_commitments.len() != statement.banks
    {
        return Err(StructuredWiringError::BankCount);
    }
    if proof.input_shift_evaluations.len() != statement.banks * layer_bits
        || proof.input_first_evaluations.len() != statement.banks
        || proof.output_random_evaluations.len() != statement.banks
        || proof.output_last_evaluations.len() != statement.banks
    {
        return Err(StructuredWiringError::EvaluationCount);
    }

    let mut transcript = WiringTranscript::new(
        binding,
        statement,
        proof.initial_commitment,
        &proof.input_commitments,
        &proof.output_commitments,
    );
    let points = WiringPoints::derive(statement, &mut transcript);
    let evaluations = decode_evaluations(proof)?;
    verify_identities(statement, &points, &evaluations)?;
    transcript.absorb_evaluations(&evaluations);
    if proof.transcript_digest != transcript.digest() {
        return Err(StructuredWiringError::Transcript);
    }
    Ok(opening_claims(statement, proof, &points, &evaluations))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WiringEvaluations {
    initial: ExtensionField,
    input_shift: Vec<ExtensionField>,
    input_first: Vec<ExtensionField>,
    output_random: Vec<ExtensionField>,
    output_last: Vec<ExtensionField>,
}

struct WiringPoints {
    cell: Vec<ExtensionField>,
    layer: Vec<ExtensionField>,
}

impl WiringPoints {
    fn derive(statement: StructuredWiringStatement, transcript: &mut WiringTranscript) -> Self {
        Self {
            cell: transcript.challenge_vector(b"cell-point", statement.cell_variables()),
            layer: transcript.challenge_vector(b"layer-point", statement.layers_per_bank.ilog2()),
        }
    }

    fn output_random(&self) -> Vec<ExtensionField> {
        point_with_layer(&self.cell, &self.layer)
    }

    fn output_last(&self) -> Vec<ExtensionField> {
        point_with_layer(&self.cell, &vec![ExtensionField::ONE; self.layer.len()])
    }

    fn input_first(&self) -> Vec<ExtensionField> {
        point_with_layer(&self.cell, &vec![ExtensionField::ZERO; self.layer.len()])
    }

    fn input_shift(&self, trailing_ones: usize) -> Vec<ExtensionField> {
        let mut layer = self.layer.clone();
        for value in layer.iter_mut().take(trailing_ones) {
            *value = ExtensionField::ZERO;
        }
        layer[trailing_ones] = ExtensionField::ONE;
        point_with_layer(&self.cell, &layer)
    }
}

fn compute_evaluations(
    statement: StructuredWiringStatement,
    points: &WiringPoints,
    initial: &[ExtensionField],
    inputs: &[Vec<ExtensionField>],
    outputs: &[Vec<ExtensionField>],
) -> WiringEvaluations {
    let random_point = points.output_random();
    let last_point = points.output_last();
    let first_point = points.input_first();
    let mut input_shift = Vec::with_capacity(statement.banks * points.layer.len());
    let mut input_first = Vec::with_capacity(statement.banks);
    let mut output_random = Vec::with_capacity(statement.banks);
    let mut output_last = Vec::with_capacity(statement.banks);
    for bank in 0..statement.banks {
        for trailing_ones in 0..points.layer.len() {
            input_shift.push(evaluate_mle(
                &inputs[bank],
                &points.input_shift(trailing_ones),
            ));
        }
        output_random.push(evaluate_mle(&outputs[bank], &random_point));
        output_last.push(evaluate_mle(&outputs[bank], &last_point));
        input_first.push(evaluate_mle(&inputs[bank], &first_point));
    }
    WiringEvaluations {
        initial: evaluate_mle(initial, &points.cell),
        input_shift,
        input_first,
        output_random,
        output_last,
    }
}

fn verify_identities(
    statement: StructuredWiringStatement,
    points: &WiringPoints,
    evaluations: &WiringEvaluations,
) -> Result<(), StructuredWiringError> {
    let layer_bits = points.layer.len();
    let last_selector = points
        .layer
        .iter()
        .fold(ExtensionField::ONE, |product, value| product.mul(*value));
    for bank in 0..statement.banks {
        let masked_output =
            evaluations.output_random[bank].sub(last_selector.mul(evaluations.output_last[bank]));
        let mut shifted_input = ExtensionField::ZERO;
        let mut trailing_selector = ExtensionField::ONE;
        for trailing_ones in 0..layer_bits {
            let coefficient =
                trailing_selector.mul(ExtensionField::ONE.sub(points.layer[trailing_ones]));
            shifted_input = shifted_input
                .add(coefficient.mul(evaluations.input_shift[bank * layer_bits + trailing_ones]));
            trailing_selector = trailing_selector.mul(points.layer[trailing_ones]);
        }
        if masked_output != shifted_input {
            return Err(StructuredWiringError::WiringIdentity);
        }
    }
    if evaluations.initial != evaluations.input_first[0] {
        return Err(StructuredWiringError::WiringIdentity);
    }
    for boundary in 0..statement.banks - 1 {
        if evaluations.output_last[boundary] != evaluations.input_first[boundary + 1] {
            return Err(StructuredWiringError::WiringIdentity);
        }
    }
    Ok(())
}

fn opening_claims(
    statement: StructuredWiringStatement,
    proof: &StructuredWiringProof,
    points: &WiringPoints,
    evaluations: &WiringEvaluations,
) -> StructuredWiringOpeningClaims {
    let mut openings = Vec::with_capacity(statement.banks * (points.layer.len() + 3) + 1);
    openings.push(StructuredWiringOpeningClaim {
        commitment: proof.initial_commitment,
        point: encode_fields(&points.cell),
        evaluation: ExtensionElement::from_field(evaluations.initial),
    });
    for bank in 0..statement.banks {
        openings.push(StructuredWiringOpeningClaim {
            commitment: proof.output_commitments[bank],
            point: encode_fields(&points.output_random()),
            evaluation: ExtensionElement::from_field(evaluations.output_random[bank]),
        });
        openings.push(StructuredWiringOpeningClaim {
            commitment: proof.output_commitments[bank],
            point: encode_fields(&points.output_last()),
            evaluation: ExtensionElement::from_field(evaluations.output_last[bank]),
        });
        for trailing_ones in 0..points.layer.len() {
            openings.push(StructuredWiringOpeningClaim {
                commitment: proof.input_commitments[bank],
                point: encode_fields(&points.input_shift(trailing_ones)),
                evaluation: ExtensionElement::from_field(
                    evaluations.input_shift[bank * points.layer.len() + trailing_ones],
                ),
            });
        }
        openings.push(StructuredWiringOpeningClaim {
            commitment: proof.input_commitments[bank],
            point: encode_fields(&points.input_first()),
            evaluation: ExtensionElement::from_field(evaluations.input_first[bank]),
        });
    }
    let final_output = StructuredWiringOpeningClaim {
        commitment: proof.output_commitments[statement.banks - 1],
        point: encode_fields(&points.output_last()),
        evaluation: ExtensionElement::from_field(evaluations.output_last[statement.banks - 1]),
    };
    StructuredWiringOpeningClaims {
        openings,
        final_output,
    }
}

pub(crate) fn validate_tables(
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
) -> Result<(), StructuredWiringError> {
    statement.validate_materialized_shape()?;
    validate_tables_after_shape(statement, initial, inputs, outputs)
}

#[cfg(any(test, feature = "dory-bls12-381-prototype"))]
pub(crate) fn validate_streaming_tables(
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
) -> Result<(), StructuredWiringError> {
    statement.validate_verifier_shape()?;
    validate_tables_after_shape(statement, initial, inputs, outputs)
}

fn validate_tables_after_shape(
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
) -> Result<(), StructuredWiringError> {
    let elements = statement.elements()?;
    let cells = checked_product(&[statement.rows, statement.cols])?;
    if initial.len() != cells || inputs.len() != elements || outputs.len() != elements {
        return Err(StructuredWiringError::InvalidLength);
    }
    if initial
        .iter()
        .chain(inputs)
        .chain(outputs)
        .any(|value| value.unsigned_abs() > statement.max_abs_activation)
    {
        return Err(StructuredWiringError::ValueOutOfRange);
    }
    Ok(())
}

pub(crate) fn validate_successors(
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
) -> Result<(), StructuredWiringError> {
    let cells = checked_product(&[statement.rows, statement.cols])?;
    let total_layers = statement
        .banks
        .checked_mul(statement.layers_per_bank)
        .ok_or(StructuredWiringError::ArithmeticOverflow)?;
    if initial != &inputs[..cells] {
        return Err(StructuredWiringError::WiringIdentity);
    }
    for layer in 0..total_layers - 1 {
        let output_start = layer
            .checked_mul(cells)
            .ok_or(StructuredWiringError::ArithmeticOverflow)?;
        let input_start = (layer + 1)
            .checked_mul(cells)
            .ok_or(StructuredWiringError::ArithmeticOverflow)?;
        if outputs[output_start..output_start + cells] != inputs[input_start..input_start + cells] {
            return Err(StructuredWiringError::WiringIdentity);
        }
    }
    Ok(())
}

fn bank_field_values(
    statement: StructuredWiringStatement,
    values: &[i64],
) -> Result<Vec<Vec<ExtensionField>>, StructuredWiringError> {
    let bank_elements = statement.bank_elements()?;
    Ok(values
        .chunks_exact(bank_elements)
        .map(|bank| {
            bank.iter()
                .copied()
                .map(ExtensionField::from_signed)
                .collect()
        })
        .collect())
}

fn decode_evaluations(
    proof: &StructuredWiringProof,
) -> Result<WiringEvaluations, StructuredWiringError> {
    Ok(WiringEvaluations {
        initial: proof.initial_evaluation.to_field()?,
        input_shift: decode_fields(&proof.input_shift_evaluations)?,
        input_first: decode_fields(&proof.input_first_evaluations)?,
        output_random: decode_fields(&proof.output_random_evaluations)?,
        output_last: decode_fields(&proof.output_last_evaluations)?,
    })
}

fn point_with_layer(cell: &[ExtensionField], layer: &[ExtensionField]) -> Vec<ExtensionField> {
    let mut point = Vec::with_capacity(cell.len() + layer.len());
    point.extend_from_slice(cell);
    point.extend_from_slice(layer);
    point
}

fn encode_fields(values: &[ExtensionField]) -> Vec<ExtensionElement> {
    values
        .iter()
        .copied()
        .map(ExtensionElement::from_field)
        .collect()
}

fn decode_fields(
    values: &[ExtensionElement],
) -> Result<Vec<ExtensionField>, StructuredWiringError> {
    values
        .iter()
        .copied()
        .map(ExtensionElement::to_field)
        .collect::<Result<Vec<_>, _>>()
        .map_err(StructuredWiringError::Field)
}

fn checked_product(values: &[usize]) -> Result<usize, StructuredWiringError> {
    values.iter().try_fold(1_usize, |product, value| {
        product
            .checked_mul(*value)
            .ok_or(StructuredWiringError::ArithmeticOverflow)
    })
}

fn encode_commitments(output: &mut Vec<u8>, commitments: &[[u8; 32]]) {
    output.extend_from_slice(&(commitments.len() as u32).to_le_bytes());
    for commitment in commitments {
        output.extend_from_slice(commitment);
    }
}

fn encode_evaluations(
    output: &mut Vec<u8>,
    evaluations: &[ExtensionElement],
) -> Result<(), StructuredWiringError> {
    output.extend_from_slice(&(evaluations.len() as u32).to_le_bytes());
    for evaluation in evaluations {
        evaluation.to_field()?;
        evaluation.encode(output);
    }
    Ok(())
}

struct WiringTranscript {
    hasher: Hasher,
    challenge_counter: u64,
}

impl WiringTranscript {
    fn new(
        binding: &[u8],
        statement: StructuredWiringStatement,
        initial_commitment: [u8; 32],
        input_commitments: &[[u8; 32]],
        output_commitments: &[[u8; 32]],
    ) -> Self {
        let mut transcript = Self {
            hasher: Hasher::new_derive_key(TRANSCRIPT_DOMAIN),
            challenge_counter: 0,
        };
        transcript.absorb(
            b"protocol-version",
            &STRUCTURED_WIRING_VERSION.to_le_bytes(),
        );
        transcript.absorb(b"public-binding", binding);
        let mut encoded_statement = Vec::with_capacity(40);
        for value in [
            statement.banks as u64,
            statement.layers_per_bank as u64,
            statement.rows as u64,
            statement.cols as u64,
            statement.max_abs_activation,
        ] {
            encoded_statement.extend_from_slice(&value.to_le_bytes());
        }
        transcript.absorb(b"statement", &encoded_statement);
        transcript.absorb(b"initial-commitment", &initial_commitment);
        for (bank, (input, output)) in input_commitments.iter().zip(output_commitments).enumerate()
        {
            transcript.absorb(b"bank-index", &(bank as u32).to_le_bytes());
            transcript.absorb(b"input-commitment", input);
            transcript.absorb(b"output-commitment", output);
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
        let challenge = ExtensionField::from_canonical_limbs(limbs).unwrap();
        self.absorb_field(b"derived-challenge", challenge);
        challenge
    }

    fn absorb_evaluations(&mut self, evaluations: &WiringEvaluations) {
        self.absorb_field(b"initial-evaluation", evaluations.initial);
        for (label, values) in [
            (b"input-shift".as_slice(), &evaluations.input_shift),
            (b"input-first".as_slice(), &evaluations.input_first),
            (b"output-random".as_slice(), &evaluations.output_random),
            (b"output-last".as_slice(), &evaluations.output_last),
        ] {
            self.absorb(b"evaluation-role", label);
            self.absorb(b"evaluation-count", &(values.len() as u32).to_le_bytes());
            for value in values {
                self.absorb_field(b"evaluation", *value);
            }
        }
    }

    fn digest(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

struct ProofReader<'a> {
    remaining: &'a [u8],
}

impl<'a> ProofReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], StructuredWiringError> {
        if self.remaining.len() < count {
            return Err(StructuredWiringError::Decode);
        }
        let (value, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, StructuredWiringError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| StructuredWiringError::Decode)?,
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StructuredWiringError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StructuredWiringError::Decode)
    }

    fn commitments(&mut self) -> Result<Vec<[u8; 32]>, StructuredWiringError> {
        let count = self.u32()? as usize;
        if count == 0 || count > MAX_STRUCTURED_WIRING_BANKS {
            return Err(StructuredWiringError::BankCount);
        }
        (0..count).map(|_| self.array()).collect()
    }

    fn evaluations(&mut self) -> Result<Vec<ExtensionElement>, StructuredWiringError> {
        let count = self.u32()? as usize;
        if count > MAX_STRUCTURED_WIRING_BANKS * MAX_LAYER_BITS {
            return Err(StructuredWiringError::EvaluationCount);
        }
        (0..count)
            .map(|_| {
                let limbs = [
                    u64::from_le_bytes(self.array()?),
                    u64::from_le_bytes(self.array()?),
                    u64::from_le_bytes(self.array()?),
                ];
                let value = ExtensionElement { limbs };
                value.to_field()?;
                Ok(value)
            })
            .collect()
    }

    fn extension(&mut self) -> Result<ExtensionElement, StructuredWiringError> {
        let value = ExtensionElement {
            limbs: [
                u64::from_le_bytes(self.array()?),
                u64::from_le_bytes(self.array()?),
                u64::from_le_bytes(self.array()?),
            ],
        };
        value.to_field()?;
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockChallenge, StructuredMaskPolynomial, StructuredMatrixStatement,
        StructuredTransitionStatement, StructuredTransitionWitness,
        prove_structured_matrix_product, prove_structured_transition, v2_test_reference,
    };

    fn statement(banks: usize) -> StructuredWiringStatement {
        StructuredWiringStatement {
            banks,
            layers_per_bank: 4,
            rows: 2,
            cols: 4,
            max_abs_activation: 125,
        }
    }

    fn production_statement() -> StructuredWiringStatement {
        StructuredWiringStatement {
            banks: MAX_STRUCTURED_WIRING_BANKS,
            layers_per_bank: MAX_STRUCTURED_WIRING_LAYERS_PER_BANK,
            rows: MAX_STRUCTURED_WIRING_ROWS,
            cols: MAX_STRUCTURED_WIRING_COLS,
            max_abs_activation: 125,
        }
    }

    fn empty_proof(statement: StructuredWiringStatement) -> StructuredWiringProof {
        let layer_bits = statement.layers_per_bank.ilog2() as usize;
        StructuredWiringProof {
            protocol_version: STRUCTURED_WIRING_VERSION,
            initial_commitment: [0; 32],
            input_commitments: vec![[0; 32]; statement.banks],
            output_commitments: vec![[0; 32]; statement.banks],
            initial_evaluation: ExtensionElement { limbs: [0; 3] },
            input_shift_evaluations: vec![
                ExtensionElement { limbs: [0; 3] };
                statement.banks * layer_bits
            ],
            input_first_evaluations: vec![ExtensionElement { limbs: [0; 3] }; statement.banks],
            output_random_evaluations: vec![ExtensionElement { limbs: [0; 3] }; statement.banks],
            output_last_evaluations: vec![ExtensionElement { limbs: [0; 3] }; statement.banks],
            transcript_digest: [0; 32],
        }
    }

    fn synthetic_fixture(banks: usize) -> (Vec<i64>, Vec<i64>) {
        let statement = statement(banks);
        let cells = statement.rows * statement.cols;
        let total_layers = banks * statement.layers_per_bank;
        let states = (0..=total_layers)
            .map(|layer| {
                (0..cells)
                    .map(|cell| ((layer * 17 + cell * 3) % 251) as i64 - 125)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let inputs = states[..total_layers].concat();
        let outputs = states[1..].concat();
        (inputs, outputs)
    }

    #[test]
    fn production_shape_is_verifier_safe_but_not_materializable() {
        let statement = production_statement();
        let proof = empty_proof(statement);

        statement.validate_verifier_shape().unwrap();
        assert_eq!(statement.elements().unwrap(), 3 * (1 << 26));
        assert_eq!(statement.soundness_error_numerator().unwrap(), 135);
        assert!(matches!(
            verify_structured_wiring_openings(b"binding", statement, &proof),
            Err(StructuredWiringError::Transcript)
        ));

        assert!(matches!(
            statement.validate_materialized_shape(),
            Err(StructuredWiringError::ResearchCap)
        ));
        assert!(matches!(
            validate_streaming_tables(statement, &[], &[], &[]),
            Err(StructuredWiringError::InvalidLength)
        ));
        assert!(matches!(
            prove_structured_wiring(b"binding", statement, &[], &[], &[]),
            Err(StructuredWiringError::ResearchCap)
        ));
        assert!(matches!(
            verify_structured_wiring(b"binding", statement, &[], &[], &[], &proof),
            Err(StructuredWiringError::ResearchCap)
        ));
        #[cfg(feature = "whir-prototype")]
        assert!(matches!(
            structured_wiring_whir_tables(statement, &[], &[], &[]),
            Err(StructuredWiringError::ResearchCap)
        ));
    }

    #[test]
    fn verifier_shape_rejects_invalid_over_max_and_overflowing_dimensions() {
        for (banks, layers_per_bank, rows, cols) in [(0, 2, 1, 1), (1, 0, 1, 1), (1, 3, 1, 1)] {
            let statement = StructuredWiringStatement {
                banks,
                layers_per_bank,
                rows,
                cols,
                ..production_statement()
            };
            assert!(matches!(
                statement.validate_verifier_shape(),
                Err(StructuredWiringError::InvalidDimensions)
            ));
        }

        for (banks, layers_per_bank, rows, cols) in [
            (MAX_STRUCTURED_WIRING_BANKS + 1, 2, 1, 1),
            (1, MAX_STRUCTURED_WIRING_LAYERS_PER_BANK * 2, 1, 1),
            (1, 2, MAX_STRUCTURED_WIRING_ROWS * 2, 1),
            (1, 2, 1, MAX_STRUCTURED_WIRING_COLS * 2),
        ] {
            let statement = StructuredWiringStatement {
                banks,
                layers_per_bank,
                rows,
                cols,
                ..production_statement()
            };
            assert!(matches!(
                statement.validate_verifier_shape(),
                Err(StructuredWiringError::ResearchCap)
            ));
        }

        let high_bit = 1_usize << (usize::BITS - 1);
        for (banks, layers_per_bank, rows, cols) in [
            (high_bit, 2, 1, 1),
            (1, high_bit, 2, 1),
            (1, 2, 2, high_bit),
        ] {
            let statement = StructuredWiringStatement {
                banks,
                layers_per_bank,
                rows,
                cols,
                ..production_statement()
            };
            assert!(matches!(
                statement.validate_verifier_shape(),
                Err(StructuredWiringError::ArithmeticOverflow)
            ));
        }

        let unsafe_bounds = StructuredWiringStatement {
            max_abs_activation: GOLDILOCKS_MODULUS,
            ..production_statement()
        };
        assert!(matches!(
            unsafe_bounds.validate_verifier_shape(),
            Err(StructuredWiringError::UnsafeIntegerBounds)
        ));
    }

    #[test]
    fn proves_all_internal_and_cross_bank_successors() {
        let statement = statement(3);
        let (inputs, outputs) = synthetic_fixture(3);
        let initial = &inputs[..statement.rows * statement.cols];
        let proof =
            prove_structured_wiring(b"block/model/nonce", statement, initial, &inputs, &outputs)
                .unwrap();
        verify_structured_wiring(
            b"block/model/nonce",
            statement,
            initial,
            &inputs,
            &outputs,
            &proof,
        )
        .unwrap();
        let claims =
            verify_structured_wiring_openings(b"block/model/nonce", statement, &proof).unwrap();
        assert_eq!(claims.openings.len(), 1 + 3 * (2 + 3));
        assert_eq!(statement.soundness_error_numerator().unwrap(), 24);
        assert_eq!(proof.encode().unwrap().len(), 676);
        assert_eq!(
            StructuredWiringProof::decode(&proof.encode().unwrap()).unwrap(),
            proof
        );
    }

    #[test]
    fn rejects_skipped_reordered_and_cross_bank_layers() {
        let statement = statement(3);
        let (inputs, outputs) = synthetic_fixture(3);
        let initial = &inputs[..statement.rows * statement.cols];

        let mut bad_initial = initial.to_vec();
        bad_initial[0] += 1;
        assert_eq!(
            prove_structured_wiring(b"binding", statement, &bad_initial, &inputs, &outputs),
            Err(StructuredWiringError::WiringIdentity)
        );

        let mut skipped = outputs.clone();
        skipped[..8].copy_from_slice(&outputs[8..16]);
        assert_eq!(
            prove_structured_wiring(b"binding", statement, initial, &inputs, &skipped),
            Err(StructuredWiringError::WiringIdentity)
        );

        let mut reordered = outputs.clone();
        let first = reordered[..8].to_vec();
        let second = reordered[8..16].to_vec();
        reordered[..8].copy_from_slice(&second);
        reordered[8..16].copy_from_slice(&first);
        assert_eq!(
            prove_structured_wiring(b"binding", statement, initial, &inputs, &reordered),
            Err(StructuredWiringError::WiringIdentity)
        );

        let mut bad_boundary = inputs.clone();
        bad_boundary[4 * 8] += 1;
        assert_eq!(
            prove_structured_wiring(b"binding", statement, initial, &bad_boundary, &outputs),
            Err(StructuredWiringError::WiringIdentity)
        );
    }

    #[test]
    fn transcript_and_opening_mutations_are_rejected() {
        let statement = statement(1);
        let (inputs, outputs) = synthetic_fixture(1);
        let initial = &inputs[..statement.rows * statement.cols];
        let proof =
            prove_structured_wiring(b"binding", statement, initial, &inputs, &outputs).unwrap();
        assert!(verify_structured_wiring_openings(b"other", statement, &proof).is_err());

        let mut evaluation = proof.clone();
        evaluation.output_random_evaluations[0].limbs[0] ^= 1;
        assert!(verify_structured_wiring_openings(b"binding", statement, &evaluation).is_err());

        let mut commitment = proof.clone();
        commitment.input_commitments[0][0] ^= 1;
        assert!(verify_structured_wiring_openings(b"binding", statement, &commitment).is_err());

        let mut trailing = proof.encode().unwrap();
        trailing.push(0);
        assert_eq!(
            StructuredWiringProof::decode(&trailing),
            Err(StructuredWiringError::Decode)
        );
        let canonical = proof.encode().unwrap();
        for length in 0..canonical.len() {
            assert!(StructuredWiringProof::decode(&canonical[..length]).is_err());
        }
    }

    #[test]
    fn actual_trace_shares_matrix_and_transition_commitments() {
        let block = BlockChallenge {
            network_id: [0x63; 32],
            previous_block: [0x11; 32],
            transaction_root: [0x22; 32],
            height: 42,
            timestamp: 1_777_777_777,
            target: [0xff; 32],
        };
        let reference = v2_test_reference().unwrap();
        let trace = reference.prove_reference(&block, 7).unwrap();
        let model = reference.accelerator_model();
        let initial = trace
            .initial_activation
            .iter()
            .map(|value| i64::from(*value))
            .collect::<Vec<_>>();
        let mut inputs = initial.clone();
        for layer in trace.layers.iter().take(trace.layers.len() - 1) {
            inputs.extend(layer.output.iter().map(|value| i64::from(*value)));
        }
        let outputs = trace
            .layers
            .iter()
            .flat_map(|layer| layer.output.iter().map(|value| i64::from(*value)))
            .collect::<Vec<_>>();
        let wiring_statement = StructuredWiringStatement {
            banks: 1,
            layers_per_bank: model.layers() as usize,
            rows: model.rows() as usize,
            cols: model.width() as usize,
            max_abs_activation: 125,
        };
        let wiring = prove_structured_wiring(
            &trace.challenge_digest,
            wiring_statement,
            &initial,
            &inputs,
            &outputs,
        )
        .unwrap();
        assert_eq!(wiring.encode().unwrap().len(), 308);

        let matrix_statement = StructuredMatrixStatement {
            layers: model.layers() as usize,
            rows: model.rows() as usize,
            inner: model.width() as usize,
            cols: model.width() as usize,
            max_abs_activation: 125,
            max_abs_weight: 125,
            max_abs_accumulator: 64_000_000,
        };
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
            &inputs,
            &weights,
            &accumulators,
        )
        .unwrap();

        let base_input = model
            .base_input()
            .iter()
            .map(|value| i64::from(*value) - 125)
            .collect::<Vec<_>>();
        let mut initialization_witness = StructuredTransitionWitness {
            accumulators: base_input.clone(),
            masks: Vec::new(),
            encoded: Vec::new(),
            square_quotients: Vec::new(),
            square_remainders: Vec::new(),
            cube_quotients: Vec::new(),
            cube_remainders: Vec::new(),
            output_quotients: Vec::new(),
            output_remainders: Vec::new(),
            negative: Vec::new(),
            activations: initial.clone(),
        };
        for (base, reduction) in base_input.iter().zip(&trace.initial_reductions) {
            initialization_witness
                .masks
                .push(u64::try_from(i64::from(reduction.z) - *base).unwrap());
            initialization_witness
                .encoded
                .push(u64::from(reduction.encoded_z));
            initialization_witness
                .square_quotients
                .push(u64::from(reduction.square_quotient));
            initialization_witness
                .square_remainders
                .push(u64::from(reduction.square_remainder));
            initialization_witness
                .cube_quotients
                .push(u64::from(reduction.cube_quotient));
            initialization_witness
                .cube_remainders
                .push(u64::from(reduction.cube_remainder));
            initialization_witness
                .output_quotients
                .push(u64::from(reduction.output_quotient));
            initialization_witness
                .output_remainders
                .push(u64::from(reduction.output_remainder));
            initialization_witness
                .negative
                .push(u64::from(reduction.z < 0));
        }
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows: model.rows() as usize,
            cols: model.width() as usize,
            max_abs_accumulator: 125,
            max_mask: 5_000,
        };
        let initialization_mask = StructuredMaskPolynomial::from_virtual_challenge(
            &trace.challenge_digest,
            initialization_statement.rows,
            initialization_statement.cols,
        )
        .unwrap();
        let initialization = prove_structured_transition(
            &trace.challenge_digest,
            initialization_statement,
            &initialization_mask,
            &initialization_witness,
        )
        .unwrap();
        let base_input_commitment = table_commitment(
            &base_input
                .iter()
                .copied()
                .map(ExtensionField::from_signed)
                .collect::<Vec<_>>(),
        );

        let mut transition_witness = StructuredTransitionWitness {
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
        for layer in &trace.layers {
            for ((accumulator, reduction), activation) in layer
                .accumulators
                .iter()
                .zip(&layer.reductions)
                .zip(&layer.output)
            {
                transition_witness
                    .accumulators
                    .push(i64::from(*accumulator));
                transition_witness
                    .masks
                    .push(u64::try_from(reduction.z - accumulator).unwrap());
                transition_witness
                    .encoded
                    .push(u64::from(reduction.encoded_z));
                transition_witness
                    .square_quotients
                    .push(u64::from(reduction.square_quotient));
                transition_witness
                    .square_remainders
                    .push(u64::from(reduction.square_remainder));
                transition_witness
                    .cube_quotients
                    .push(u64::from(reduction.cube_quotient));
                transition_witness
                    .cube_remainders
                    .push(u64::from(reduction.cube_remainder));
                transition_witness
                    .output_quotients
                    .push(u64::from(reduction.output_quotient));
                transition_witness
                    .output_remainders
                    .push(u64::from(reduction.output_remainder));
                transition_witness.negative.push(u64::from(reduction.z < 0));
                transition_witness.activations.push(i64::from(*activation));
            }
        }
        let transition_statement = StructuredTransitionStatement {
            layers: trace.layers.len(),
            rows: model.rows() as usize,
            cols: model.width() as usize,
            max_abs_accumulator: 64_000_000,
            max_mask: 5_000,
        };
        let mask = StructuredMaskPolynomial::from_challenge(
            &trace.challenge_digest,
            transition_statement.layers,
            transition_statement.rows,
            transition_statement.cols,
        )
        .unwrap();
        let transition = prove_structured_transition(
            &trace.challenge_digest,
            transition_statement,
            &mask,
            &transition_witness,
        )
        .unwrap();

        verify_structured_wiring_component_commitments(
            wiring_statement,
            base_input_commitment,
            &initialization,
            std::slice::from_ref(&matrix),
            std::slice::from_ref(&transition),
            &wiring,
        )
        .unwrap();
        let mut wrong_matrix = matrix.clone();
        wrong_matrix.activation_commitment[0] ^= 1;
        assert_eq!(
            verify_structured_wiring_component_commitments(
                wiring_statement,
                base_input_commitment,
                &initialization,
                &[wrong_matrix],
                std::slice::from_ref(&transition),
                &wiring,
            ),
            Err(StructuredWiringError::Commitment)
        );
        let mut wrong_initialization = initialization.clone();
        wrong_initialization.oracle_commitments[STRUCTURED_TRANSITION_ACTIVATION_ORACLE][0] ^= 1;
        assert_eq!(
            verify_structured_wiring_component_commitments(
                wiring_statement,
                base_input_commitment,
                &wrong_initialization,
                std::slice::from_ref(&matrix),
                std::slice::from_ref(&transition),
                &wiring,
            ),
            Err(StructuredWiringError::Commitment)
        );
        let mut wrong_accumulator = matrix.clone();
        wrong_accumulator.accumulator_commitment[0] ^= 1;
        assert_eq!(
            verify_structured_wiring_component_commitments(
                wiring_statement,
                base_input_commitment,
                &initialization,
                &[wrong_accumulator],
                std::slice::from_ref(&transition),
                &wiring,
            ),
            Err(StructuredWiringError::Commitment)
        );
        let mut wrong_base_input_commitment = base_input_commitment;
        wrong_base_input_commitment[0] ^= 1;
        assert_eq!(
            verify_structured_wiring_component_commitments(
                wiring_statement,
                wrong_base_input_commitment,
                &initialization,
                std::slice::from_ref(&matrix),
                std::slice::from_ref(&transition),
                &wiring,
            ),
            Err(StructuredWiringError::Commitment)
        );
        verify_structured_wiring(
            &trace.challenge_digest,
            wiring_statement,
            &initial,
            &inputs,
            &outputs,
            &wiring,
        )
        .unwrap();
    }
}
