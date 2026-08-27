//! CPU-owned relation checks and PCS point routing for ProductionV4.

use std::ops::Range;

use slop_algebra::AbstractField;
use slop_challenger::{CanObserve, FieldChallenger};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{PartialSumcheckProof, partially_verify_sumcheck_proof};
use thiserror::Error;

use crate::{
    FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE, FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
    FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE, FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
    FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK, FORGEMATRIX_V4_RELATION_OPENING_CLAIMS_PER_BANK,
    FORGEMATRIX_V4_RELATION_REPETITIONS, FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
    FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES, ForgeMatrixV4DynamicTraceKind,
    forgematrix_v2::PRODUCTION_V2_BANKS,
    forgematrix_v4_basefold::{
        ForgeMatrixV4Challenger, ForgeMatrixV4Extension, ForgeMatrixV4OpeningClaim,
        ForgeMatrixV4OpeningCommitment,
    },
};

const LAYER_VARIABLES: usize = 7;
const BATCH_VARIABLES: usize = 7;
const DIMENSION_VARIABLES: usize = 12;
const FIXED_COLUMN_VARIABLES: usize = 8;
const DYNAMIC_COLUMN_VARIABLES: usize = 4;
const COMMITMENTS_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/Commitments/v1";
const MATRIX_POINT_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/MatrixPoint/v1";
const MATRIX_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/MatrixProof/v1";
const SHIFT_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/ShiftProof/v1";
const CUBIC_POINT_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/CubicPoint/v1";
const CUBIC_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/CubicProof/v1";
const FINAL_POINT_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/FinalPoint/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeMatrixV4MatrixPoint {
    pub layer: Point<ForgeMatrixV4Extension>,
    pub batch: Point<ForgeMatrixV4Extension>,
    pub output: Point<ForgeMatrixV4Extension>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeMatrixV4CubicPoint {
    pub layer: Point<ForgeMatrixV4Extension>,
    pub batch: Point<ForgeMatrixV4Extension>,
    pub output: Point<ForgeMatrixV4Extension>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeMatrixV4BoundaryPoint {
    pub batch: Point<ForgeMatrixV4Extension>,
    pub output: Point<ForgeMatrixV4Extension>,
}

#[derive(Clone)]
pub struct ForgeMatrixV4MatrixRelationProof {
    pub sumcheck: PartialSumcheckProof<ForgeMatrixV4Extension>,
    pub preactivation_evaluation: ForgeMatrixV4Extension,
    pub weight_evaluation: ForgeMatrixV4Extension,
    pub input_evaluation: ForgeMatrixV4Extension,
}

#[derive(Clone)]
pub struct ForgeMatrixV4ShiftRelationProof {
    pub sumcheck: PartialSumcheckProof<ForgeMatrixV4Extension>,
    pub boundary_evaluation: ForgeMatrixV4Extension,
    pub next_activation_evaluation: ForgeMatrixV4Extension,
}

#[derive(Clone)]
pub struct ForgeMatrixV4CubicRelationProof {
    pub sumcheck: PartialSumcheckProof<ForgeMatrixV4Extension>,
    pub preactivation_evaluation: ForgeMatrixV4Extension,
    pub next_activation_evaluation: ForgeMatrixV4Extension,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeMatrixV4PcsPoint {
    pub column: Point<ForgeMatrixV4Extension>,
    pub row: Point<ForgeMatrixV4Extension>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ForgeMatrixV4RelationError {
    #[error("V4 relation index is outside the pinned bank or repetition count")]
    Index,
    #[error("V4 relation point or proof has the wrong shape")]
    Shape,
    #[error("V4 relation claim does not match its public reduction")]
    Claim,
    #[error("V4 relation sumcheck failed")]
    Sumcheck,
    #[error("V4 relation terminal identity failed")]
    Terminal,
}

pub fn bind_forgematrix_v4_commitments(
    challenger: &mut ForgeMatrixV4Challenger,
    fixed_commitments: &[crate::forgematrix_v4_basefold::ForgeMatrixV4Digest; 3],
    dynamic_commitments: &[crate::forgematrix_v4_basefold::ForgeMatrixV4Digest; 3],
) {
    observe_bytes(challenger, COMMITMENTS_DOMAIN);
    for bank in 0..PRODUCTION_V2_BANKS as usize {
        challenger.observe(fixed_commitments[bank]);
        challenger.observe(dynamic_commitments[bank]);
    }
}

pub fn sample_forgematrix_v4_matrix_point(
    challenger: &mut ForgeMatrixV4Challenger,
    bank: usize,
    repetition: usize,
) -> Result<ForgeMatrixV4MatrixPoint, ForgeMatrixV4RelationError> {
    observe_relation_index(challenger, MATRIX_POINT_DOMAIN, bank, repetition)?;
    Ok(ForgeMatrixV4MatrixPoint {
        layer: sample_point(challenger, LAYER_VARIABLES),
        batch: sample_point(challenger, BATCH_VARIABLES),
        output: sample_point(challenger, DIMENSION_VARIABLES),
    })
}

pub fn sample_forgematrix_v4_cubic_point(
    challenger: &mut ForgeMatrixV4Challenger,
    bank: usize,
    repetition: usize,
) -> Result<ForgeMatrixV4CubicPoint, ForgeMatrixV4RelationError> {
    observe_relation_index(challenger, CUBIC_POINT_DOMAIN, bank, repetition)?;
    Ok(ForgeMatrixV4CubicPoint {
        layer: sample_point(challenger, LAYER_VARIABLES),
        batch: sample_point(challenger, BATCH_VARIABLES),
        output: sample_point(challenger, DIMENSION_VARIABLES),
    })
}

pub fn sample_forgematrix_v4_final_point(
    challenger: &mut ForgeMatrixV4Challenger,
    repetition: usize,
) -> Result<ForgeMatrixV4BoundaryPoint, ForgeMatrixV4RelationError> {
    observe_relation_index(
        challenger,
        FINAL_POINT_DOMAIN,
        PRODUCTION_V2_BANKS as usize - 1,
        repetition,
    )?;
    Ok(ForgeMatrixV4BoundaryPoint {
        batch: sample_point(challenger, BATCH_VARIABLES),
        output: sample_point(challenger, DIMENSION_VARIABLES),
    })
}

pub fn verify_forgematrix_v4_matrix_relation(
    claim_point: &ForgeMatrixV4MatrixPoint,
    mask_evaluation: ForgeMatrixV4Extension,
    proof: &ForgeMatrixV4MatrixRelationProof,
    challenger: &mut ForgeMatrixV4Challenger,
) -> Result<(), ForgeMatrixV4RelationError> {
    validate_matrix_point(claim_point)?;
    validate_sumcheck_shape(
        &proof.sumcheck,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
    )?;
    observe_bytes(challenger, MATRIX_PROOF_DOMAIN);
    challenger.observe_ext_element(proof.preactivation_evaluation);
    challenger.observe_ext_element(mask_evaluation);
    if proof.sumcheck.claimed_sum != proof.preactivation_evaluation - mask_evaluation {
        return Err(ForgeMatrixV4RelationError::Claim);
    }
    partially_verify_sumcheck_proof(
        &proof.sumcheck,
        challenger,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
    )
    .map_err(|_| ForgeMatrixV4RelationError::Sumcheck)?;

    let terminal_layer = point_range(&proof.sumcheck.point_and_eval.0, 0..LAYER_VARIABLES)?;
    let equality = equality_evaluation(&claim_point.layer, &terminal_layer)?;
    if proof.sumcheck.point_and_eval.1
        != proof.weight_evaluation * proof.input_evaluation * equality
    {
        return Err(ForgeMatrixV4RelationError::Terminal);
    }
    challenger.observe_ext_element(proof.weight_evaluation);
    challenger.observe_ext_element(proof.input_evaluation);
    Ok(())
}

pub fn verify_forgematrix_v4_shift_relation(
    source_layer_point: &Point<ForgeMatrixV4Extension>,
    input_evaluation: ForgeMatrixV4Extension,
    proof: &ForgeMatrixV4ShiftRelationProof,
    challenger: &mut ForgeMatrixV4Challenger,
) -> Result<(), ForgeMatrixV4RelationError> {
    if source_layer_point.dimension() != LAYER_VARIABLES {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    validate_sumcheck_shape(
        &proof.sumcheck,
        FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
    )?;
    observe_bytes(challenger, SHIFT_PROOF_DOMAIN);
    challenger.observe_ext_element(input_evaluation);
    challenger.observe_ext_element(proof.boundary_evaluation);
    let boundary_coefficient = equality_at_boolean(source_layer_point, 0)?;
    if proof.sumcheck.claimed_sum
        != input_evaluation - boundary_coefficient * proof.boundary_evaluation
    {
        return Err(ForgeMatrixV4RelationError::Claim);
    }
    partially_verify_sumcheck_proof(
        &proof.sumcheck,
        challenger,
        FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
    )
    .map_err(|_| ForgeMatrixV4RelationError::Sumcheck)?;
    let shift_coefficient =
        shifted_layer_coefficient_evaluation(source_layer_point, &proof.sumcheck.point_and_eval.0)?;
    if proof.sumcheck.point_and_eval.1 != proof.next_activation_evaluation * shift_coefficient {
        return Err(ForgeMatrixV4RelationError::Terminal);
    }
    challenger.observe_ext_element(proof.next_activation_evaluation);
    Ok(())
}

pub fn verify_forgematrix_v4_cubic_relation(
    claim_point: &ForgeMatrixV4CubicPoint,
    proof: &ForgeMatrixV4CubicRelationProof,
    challenger: &mut ForgeMatrixV4Challenger,
) -> Result<(), ForgeMatrixV4RelationError> {
    validate_cubic_point(claim_point)?;
    validate_sumcheck_shape(
        &proof.sumcheck,
        FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE,
    )?;
    observe_bytes(challenger, CUBIC_PROOF_DOMAIN);
    if proof.sumcheck.claimed_sum != ForgeMatrixV4Extension::zero() {
        return Err(ForgeMatrixV4RelationError::Claim);
    }
    partially_verify_sumcheck_proof(
        &proof.sumcheck,
        challenger,
        FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE,
    )
    .map_err(|_| ForgeMatrixV4RelationError::Sumcheck)?;
    let external_point =
        concatenate_points(&[&claim_point.layer, &claim_point.batch, &claim_point.output]);
    let equality = equality_evaluation(&external_point, &proof.sumcheck.point_and_eval.0)?;
    let expected = equality
        * (proof.next_activation_evaluation
            - proof.preactivation_evaluation
                * proof.preactivation_evaluation
                * proof.preactivation_evaluation);
    if proof.sumcheck.point_and_eval.1 != expected {
        return Err(ForgeMatrixV4RelationError::Terminal);
    }
    challenger.observe_ext_element(proof.preactivation_evaluation);
    challenger.observe_ext_element(proof.next_activation_evaluation);
    Ok(())
}

pub fn forgematrix_v4_weight_pcs_point(
    layer: &Point<ForgeMatrixV4Extension>,
    common: &Point<ForgeMatrixV4Extension>,
    output: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4PcsPoint, ForgeMatrixV4RelationError> {
    if layer.dimension() != LAYER_VARIABLES
        || common.dimension() != DIMENSION_VARIABLES
        || output.dimension() != DIMENSION_VARIABLES
    {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    split_pcs_point(
        concatenate_points(&[layer, common, output]),
        FIXED_COLUMN_VARIABLES,
    )
}

pub fn forgematrix_v4_dynamic_pcs_point(
    kind: ForgeMatrixV4DynamicTraceKind,
    layer: &Point<ForgeMatrixV4Extension>,
    batch: &Point<ForgeMatrixV4Extension>,
    output: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4PcsPoint, ForgeMatrixV4RelationError> {
    if layer.dimension() != LAYER_VARIABLES
        || batch.dimension() != BATCH_VARIABLES
        || output.dimension() != DIMENSION_VARIABLES
    {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    let kind = Point::from(vec![match kind {
        ForgeMatrixV4DynamicTraceKind::Preactivation => ForgeMatrixV4Extension::zero(),
        ForgeMatrixV4DynamicTraceKind::NextActivation => ForgeMatrixV4Extension::one(),
    }]);
    split_pcs_point(
        concatenate_points(&[&kind, layer, batch, output]),
        DYNAMIC_COLUMN_VARIABLES,
    )
}

pub fn forgematrix_v4_matrix_opening_claims(
    claim_point: &ForgeMatrixV4MatrixPoint,
    proof: &ForgeMatrixV4MatrixRelationProof,
) -> Result<[ForgeMatrixV4OpeningClaim; 2], ForgeMatrixV4RelationError> {
    validate_matrix_point(claim_point)?;
    validate_sumcheck_shape(
        &proof.sumcheck,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
    )?;
    let terminal_layer = point_range(&proof.sumcheck.point_and_eval.0, 0..LAYER_VARIABLES)?;
    let terminal_common = point_range(
        &proof.sumcheck.point_and_eval.0,
        LAYER_VARIABLES..FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
    )?;
    let weight =
        forgematrix_v4_weight_pcs_point(&terminal_layer, &terminal_common, &claim_point.output)?;
    let preactivation = forgematrix_v4_dynamic_pcs_point(
        ForgeMatrixV4DynamicTraceKind::Preactivation,
        &claim_point.layer,
        &claim_point.batch,
        &claim_point.output,
    )?;
    Ok([
        ForgeMatrixV4OpeningClaim {
            commitment: ForgeMatrixV4OpeningCommitment::Fixed,
            column_point: weight.column,
            row_point: weight.row,
            value: proof.weight_evaluation,
        },
        ForgeMatrixV4OpeningClaim {
            commitment: ForgeMatrixV4OpeningCommitment::Dynamic,
            column_point: preactivation.column,
            row_point: preactivation.row,
            value: proof.preactivation_evaluation,
        },
    ])
}

pub fn forgematrix_v4_matrix_terminal_layer(
    proof: &ForgeMatrixV4MatrixRelationProof,
) -> Result<Point<ForgeMatrixV4Extension>, ForgeMatrixV4RelationError> {
    validate_sumcheck_shape(
        &proof.sumcheck,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
    )?;
    point_range(&proof.sumcheck.point_and_eval.0, 0..LAYER_VARIABLES)
}

pub fn forgematrix_v4_shift_opening_claim(
    matrix_point: &ForgeMatrixV4MatrixPoint,
    matrix_proof: &ForgeMatrixV4MatrixRelationProof,
    shift_proof: &ForgeMatrixV4ShiftRelationProof,
) -> Result<ForgeMatrixV4OpeningClaim, ForgeMatrixV4RelationError> {
    validate_matrix_point(matrix_point)?;
    validate_sumcheck_shape(
        &matrix_proof.sumcheck,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
    )?;
    validate_sumcheck_shape(
        &shift_proof.sumcheck,
        FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
    )?;
    let common = point_range(
        &matrix_proof.sumcheck.point_and_eval.0,
        LAYER_VARIABLES..FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
    )?;
    let point = forgematrix_v4_dynamic_pcs_point(
        ForgeMatrixV4DynamicTraceKind::NextActivation,
        &shift_proof.sumcheck.point_and_eval.0,
        &matrix_point.batch,
        &common,
    )?;
    Ok(ForgeMatrixV4OpeningClaim {
        commitment: ForgeMatrixV4OpeningCommitment::Dynamic,
        column_point: point.column,
        row_point: point.row,
        value: shift_proof.next_activation_evaluation,
    })
}

pub fn forgematrix_v4_cubic_opening_claims(
    proof: &ForgeMatrixV4CubicRelationProof,
) -> Result<[ForgeMatrixV4OpeningClaim; 2], ForgeMatrixV4RelationError> {
    validate_sumcheck_shape(
        &proof.sumcheck,
        FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE,
    )?;
    let terminal = &proof.sumcheck.point_and_eval.0;
    let layer = point_range(terminal, 0..LAYER_VARIABLES)?;
    let batch = point_range(terminal, LAYER_VARIABLES..LAYER_VARIABLES + BATCH_VARIABLES)?;
    let output = point_range(
        terminal,
        LAYER_VARIABLES + BATCH_VARIABLES..FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
    )?;
    let preactivation = forgematrix_v4_dynamic_pcs_point(
        ForgeMatrixV4DynamicTraceKind::Preactivation,
        &layer,
        &batch,
        &output,
    )?;
    let next_activation = forgematrix_v4_dynamic_pcs_point(
        ForgeMatrixV4DynamicTraceKind::NextActivation,
        &layer,
        &batch,
        &output,
    )?;
    Ok([
        ForgeMatrixV4OpeningClaim {
            commitment: ForgeMatrixV4OpeningCommitment::Dynamic,
            column_point: preactivation.column,
            row_point: preactivation.row,
            value: proof.preactivation_evaluation,
        },
        ForgeMatrixV4OpeningClaim {
            commitment: ForgeMatrixV4OpeningCommitment::Dynamic,
            column_point: next_activation.column,
            row_point: next_activation.row,
            value: proof.next_activation_evaluation,
        },
    ])
}

pub fn forgematrix_v4_shift_boundary_point(
    matrix_point: &ForgeMatrixV4MatrixPoint,
    matrix_proof: &ForgeMatrixV4MatrixRelationProof,
) -> Result<ForgeMatrixV4BoundaryPoint, ForgeMatrixV4RelationError> {
    validate_matrix_point(matrix_point)?;
    validate_sumcheck_shape(
        &matrix_proof.sumcheck,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
    )?;
    Ok(ForgeMatrixV4BoundaryPoint {
        batch: matrix_point.batch.clone(),
        output: point_range(
            &matrix_proof.sumcheck.point_and_eval.0,
            LAYER_VARIABLES..FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
        )?,
    })
}

pub fn forgematrix_v4_shift_boundary_opening_claim(
    matrix_point: &ForgeMatrixV4MatrixPoint,
    matrix_proof: &ForgeMatrixV4MatrixRelationProof,
    shift_proof: &ForgeMatrixV4ShiftRelationProof,
) -> Result<ForgeMatrixV4OpeningClaim, ForgeMatrixV4RelationError> {
    validate_sumcheck_shape(
        &shift_proof.sumcheck,
        FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
        FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
    )?;
    let point = forgematrix_v4_shift_boundary_point(matrix_point, matrix_proof)?;
    forgematrix_v4_last_activation_opening_claim(&point, shift_proof.boundary_evaluation)
}

pub fn forgematrix_v4_final_opening_claim(
    point: &ForgeMatrixV4BoundaryPoint,
    value: ForgeMatrixV4Extension,
) -> Result<ForgeMatrixV4OpeningClaim, ForgeMatrixV4RelationError> {
    forgematrix_v4_last_activation_opening_claim(point, value)
}

fn forgematrix_v4_last_activation_opening_claim(
    point: &ForgeMatrixV4BoundaryPoint,
    value: ForgeMatrixV4Extension,
) -> Result<ForgeMatrixV4OpeningClaim, ForgeMatrixV4RelationError> {
    if point.batch.dimension() != BATCH_VARIABLES || point.output.dimension() != DIMENSION_VARIABLES
    {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    let last_layer = Point::from(vec![ForgeMatrixV4Extension::one(); LAYER_VARIABLES]);
    let pcs = forgematrix_v4_dynamic_pcs_point(
        ForgeMatrixV4DynamicTraceKind::NextActivation,
        &last_layer,
        &point.batch,
        &point.output,
    )?;
    Ok(ForgeMatrixV4OpeningClaim {
        commitment: ForgeMatrixV4OpeningCommitment::Dynamic,
        column_point: pcs.column,
        row_point: pcs.row,
        value,
    })
}

pub fn finalize_forgematrix_v4_bank_opening_claims(
    claims: &mut Vec<ForgeMatrixV4OpeningClaim>,
) -> Result<(), ForgeMatrixV4RelationError> {
    if claims.len() != FORGEMATRIX_V4_RELATION_OPENING_CLAIMS_PER_BANK {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    let padding = claims
        .last()
        .cloned()
        .ok_or(ForgeMatrixV4RelationError::Shape)?;
    claims.resize(FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK, padding);
    Ok(())
}

fn validate_matrix_point(
    point: &ForgeMatrixV4MatrixPoint,
) -> Result<(), ForgeMatrixV4RelationError> {
    if point.layer.dimension() != LAYER_VARIABLES
        || point.batch.dimension() != BATCH_VARIABLES
        || point.output.dimension() != DIMENSION_VARIABLES
    {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    Ok(())
}

fn validate_cubic_point(point: &ForgeMatrixV4CubicPoint) -> Result<(), ForgeMatrixV4RelationError> {
    if point.layer.dimension() != LAYER_VARIABLES
        || point.batch.dimension() != BATCH_VARIABLES
        || point.output.dimension() != DIMENSION_VARIABLES
    {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    Ok(())
}

fn validate_sumcheck_shape(
    proof: &PartialSumcheckProof<ForgeMatrixV4Extension>,
    variables: usize,
    degree: usize,
) -> Result<(), ForgeMatrixV4RelationError> {
    if proof.univariate_polys.len() != variables
        || proof
            .univariate_polys
            .iter()
            .any(|polynomial| polynomial.coefficients.len() != degree + 1)
        || proof.point_and_eval.0.dimension() != variables
    {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    Ok(())
}

fn observe_relation_index(
    challenger: &mut ForgeMatrixV4Challenger,
    domain: &[u8],
    bank: usize,
    repetition: usize,
) -> Result<(), ForgeMatrixV4RelationError> {
    if bank >= PRODUCTION_V2_BANKS as usize
        || repetition >= FORGEMATRIX_V4_RELATION_REPETITIONS as usize
    {
        return Err(ForgeMatrixV4RelationError::Index);
    }
    observe_bytes(challenger, domain);
    challenger
        .observe(crate::forgematrix_v4_basefold::ForgeMatrixV4Field::from_canonical_usize(bank));
    challenger.observe(
        crate::forgematrix_v4_basefold::ForgeMatrixV4Field::from_canonical_usize(repetition),
    );
    Ok(())
}

fn observe_bytes(challenger: &mut ForgeMatrixV4Challenger, bytes: &[u8]) {
    challenger.observe(
        crate::forgematrix_v4_basefold::ForgeMatrixV4Field::from_canonical_usize(bytes.len()),
    );
    for &byte in bytes {
        challenger
            .observe(crate::forgematrix_v4_basefold::ForgeMatrixV4Field::from_canonical_u8(byte));
    }
}

fn sample_point(
    challenger: &mut ForgeMatrixV4Challenger,
    variables: usize,
) -> Point<ForgeMatrixV4Extension> {
    Point::from(
        (0..variables)
            .map(|_| challenger.sample_ext_element())
            .collect::<Vec<_>>(),
    )
}

fn equality_evaluation(
    left: &Point<ForgeMatrixV4Extension>,
    right: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4RelationError> {
    if left.dimension() != right.dimension() {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    Ok(left.iter().zip(right.iter()).fold(
        ForgeMatrixV4Extension::one(),
        |accumulator, (&left, &right)| {
            accumulator
                * ((ForgeMatrixV4Extension::one() - left) * (ForgeMatrixV4Extension::one() - right)
                    + left * right)
        },
    ))
}

fn equality_at_boolean(
    point: &Point<ForgeMatrixV4Extension>,
    index: usize,
) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4RelationError> {
    if index >= (1_usize << point.dimension()) {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    Ok(point.iter().enumerate().fold(
        ForgeMatrixV4Extension::one(),
        |accumulator, (coordinate, &value)| {
            let shift = point.dimension() - coordinate - 1;
            if ((index >> shift) & 1) == 1 {
                accumulator * value
            } else {
                accumulator * (ForgeMatrixV4Extension::one() - value)
            }
        },
    ))
}

fn shifted_layer_coefficient_evaluation(
    source_point: &Point<ForgeMatrixV4Extension>,
    terminal_point: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4RelationError> {
    if source_point.dimension() != LAYER_VARIABLES || terminal_point.dimension() != LAYER_VARIABLES
    {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    let terminal_lagrange = Mle::<ForgeMatrixV4Extension>::partial_lagrange(terminal_point);
    let mut result = ForgeMatrixV4Extension::zero();
    for source_index in 0..(1_usize << LAYER_VARIABLES) - 1 {
        result += equality_at_boolean(source_point, source_index + 1)?
            * terminal_lagrange.guts().as_slice()[source_index];
    }
    Ok(result)
}

fn concatenate_points(points: &[&Point<ForgeMatrixV4Extension>]) -> Point<ForgeMatrixV4Extension> {
    Point::from(
        points
            .iter()
            .flat_map(|point| point.iter().copied())
            .collect::<Vec<_>>(),
    )
}

fn point_range(
    point: &Point<ForgeMatrixV4Extension>,
    range: Range<usize>,
) -> Result<Point<ForgeMatrixV4Extension>, ForgeMatrixV4RelationError> {
    if range.start > range.end || range.end > point.dimension() {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    Ok(Point::from(
        point
            .iter()
            .skip(range.start)
            .take(range.end - range.start)
            .copied()
            .collect::<Vec<_>>(),
    ))
}

fn split_pcs_point(
    point: Point<ForgeMatrixV4Extension>,
    column_variables: usize,
) -> Result<ForgeMatrixV4PcsPoint, ForgeMatrixV4RelationError> {
    if point.dimension() < column_variables {
        return Err(ForgeMatrixV4RelationError::Shape);
    }
    Ok(ForgeMatrixV4PcsPoint {
        column: point_range(&point, 0..column_variables)?,
        row: point_range(&point, column_variables..point.dimension())?,
    })
}

#[cfg(test)]
mod tests {
    use slop_algebra::{AbstractExtensionField, UnivariatePolynomial};

    use super::*;
    use crate::{
        BlockChallenge, FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_PROOF_VERSION,
        PRODUCTION_V4_TESTNET_NETWORK_ID,
        forgematrix_v4_basefold::{ForgeMatrixV4TranscriptStatement, forgematrix_v4_transcript},
        forgematrix_v4_proof_system_digest,
    };

    fn statement() -> ForgeMatrixV4TranscriptStatement {
        ForgeMatrixV4TranscriptStatement {
            block: BlockChallenge {
                network_id: PRODUCTION_V4_TESTNET_NETWORK_ID,
                previous_block: [1; 32],
                transaction_root: [2; 32],
                height: 3,
                timestamp: 4,
                target: [5; 32],
            },
            algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V4_PROOF_VERSION,
            nonce: 6,
            proof_system_digest: forgematrix_v4_proof_system_digest(),
            model_manifest_digest: [7; 32],
            challenge_digest: [8; 32],
            final_activation_digest: [9; 32],
            work_digest: [10; 32],
        }
    }

    fn zero_sumcheck(
        challenger: &mut ForgeMatrixV4Challenger,
        variables: usize,
        degree: usize,
    ) -> PartialSumcheckProof<ForgeMatrixV4Extension> {
        let mut univariate_polys = Vec::with_capacity(variables);
        let mut point = Vec::with_capacity(variables);
        for _ in 0..variables {
            let polynomial =
                UnivariatePolynomial::new(vec![ForgeMatrixV4Extension::zero(); degree + 1]);
            let coefficients = polynomial
                .coefficients
                .iter()
                .flat_map(|value| {
                    <ForgeMatrixV4Extension as AbstractExtensionField<
                        crate::forgematrix_v4_basefold::ForgeMatrixV4Field,
                    >>::as_base_slice(value)
                })
                .copied()
                .collect::<Vec<crate::forgematrix_v4_basefold::ForgeMatrixV4Field>>();
            challenger.observe_slice(&coefficients);
            point.insert(0, challenger.sample_ext_element());
            univariate_polys.push(polynomial);
        }
        PartialSumcheckProof {
            univariate_polys,
            claimed_sum: ForgeMatrixV4Extension::zero(),
            point_and_eval: (Point::from(point), ForgeMatrixV4Extension::zero()),
        }
    }

    fn boolean_point(index: usize, variables: usize) -> Point<ForgeMatrixV4Extension> {
        Point::from(
            (0..variables)
                .map(|coordinate| {
                    ForgeMatrixV4Extension::from_canonical_usize(
                        (index >> (variables - coordinate - 1)) & 1,
                    )
                })
                .collect::<Vec<_>>(),
        )
    }

    fn boolean_index(point: &Point<ForgeMatrixV4Extension>) -> usize {
        point.iter().fold(0, |index, value| {
            (index << 1) | usize::from(*value == ForgeMatrixV4Extension::one())
        })
    }

    #[test]
    fn pcs_point_routing_matches_the_integer_layout() {
        let weight = forgematrix_v4_weight_pcs_point(
            &boolean_point(127, 7),
            &boolean_point(4095, 12),
            &boolean_point(4095, 12),
        )
        .unwrap();
        assert_eq!(boolean_index(&weight.column), 255);
        assert_eq!(boolean_index(&weight.row), (1 << 23) - 1);

        let common_boundary = forgematrix_v4_weight_pcs_point(
            &boolean_point(0, 7),
            &boolean_point(2048, 12),
            &boolean_point(0, 12),
        )
        .unwrap();
        assert_eq!(boolean_index(&common_boundary.column), 1);
        assert_eq!(boolean_index(&common_boundary.row), 0);

        let dynamic = forgematrix_v4_dynamic_pcs_point(
            ForgeMatrixV4DynamicTraceKind::NextActivation,
            &boolean_point(127, 7),
            &boolean_point(127, 7),
            &boolean_point(4095, 12),
        )
        .unwrap();
        assert_eq!(boolean_index(&dynamic.column), 15);
        assert_eq!(boolean_index(&dynamic.row), (1 << 23) - 1);

        let layer_boundary = forgematrix_v4_dynamic_pcs_point(
            ForgeMatrixV4DynamicTraceKind::Preactivation,
            &boolean_point(16, 7),
            &boolean_point(0, 7),
            &boolean_point(0, 12),
        )
        .unwrap();
        assert_eq!(boolean_index(&layer_boundary.column), 1);
        assert_eq!(boolean_index(&layer_boundary.row), 0);
        let kind_boundary = forgematrix_v4_dynamic_pcs_point(
            ForgeMatrixV4DynamicTraceKind::NextActivation,
            &boolean_point(0, 7),
            &boolean_point(0, 7),
            &boolean_point(0, 12),
        )
        .unwrap();
        assert_eq!(boolean_index(&kind_boundary.column), 8);
        assert_eq!(boolean_index(&kind_boundary.row), 0);
    }

    #[test]
    fn shift_coefficients_are_exact_at_boundary_and_every_carry_class() {
        for source in [0, 1, 64, 127] {
            let source_point = boolean_point(source, LAYER_VARIABLES);
            assert_eq!(
                equality_at_boolean(&source_point, 0).unwrap(),
                ForgeMatrixV4Extension::from_canonical_usize(usize::from(source == 0))
            );
            for terminal in [0, 1, 63, 126, 127] {
                assert_eq!(
                    shifted_layer_coefficient_evaluation(
                        &source_point,
                        &boolean_point(terminal, LAYER_VARIABLES),
                    )
                    .unwrap(),
                    ForgeMatrixV4Extension::from_canonical_usize(usize::from(
                        source == terminal + 1
                    ))
                );
            }
        }
    }

    #[test]
    fn zero_relations_replay_one_shared_transcript_and_reject_mutations() {
        let commitments = [[crate::forgematrix_v4_basefold::ForgeMatrixV4Field::zero(); 8]; 3];
        let mut prover_challenger = forgematrix_v4_transcript(statement());
        bind_forgematrix_v4_commitments(&mut prover_challenger, &commitments, &commitments);
        let matrix_point =
            sample_forgematrix_v4_matrix_point(&mut prover_challenger, 0, 0).unwrap();
        observe_bytes(&mut prover_challenger, MATRIX_PROOF_DOMAIN);
        prover_challenger.observe_ext_element(ForgeMatrixV4Extension::zero());
        prover_challenger.observe_ext_element(ForgeMatrixV4Extension::zero());
        let matrix = ForgeMatrixV4MatrixRelationProof {
            sumcheck: zero_sumcheck(
                &mut prover_challenger,
                FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
            ),
            preactivation_evaluation: ForgeMatrixV4Extension::zero(),
            weight_evaluation: ForgeMatrixV4Extension::zero(),
            input_evaluation: ForgeMatrixV4Extension::zero(),
        };
        prover_challenger.observe_ext_element(matrix.weight_evaluation);
        prover_challenger.observe_ext_element(matrix.input_evaluation);

        let source_layer =
            point_range(&matrix.sumcheck.point_and_eval.0, 0..LAYER_VARIABLES).unwrap();
        observe_bytes(&mut prover_challenger, SHIFT_PROOF_DOMAIN);
        prover_challenger.observe_ext_element(matrix.input_evaluation);
        prover_challenger.observe_ext_element(ForgeMatrixV4Extension::zero());
        let shift = ForgeMatrixV4ShiftRelationProof {
            sumcheck: zero_sumcheck(
                &mut prover_challenger,
                FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
            ),
            boundary_evaluation: ForgeMatrixV4Extension::zero(),
            next_activation_evaluation: ForgeMatrixV4Extension::zero(),
        };
        prover_challenger.observe_ext_element(shift.next_activation_evaluation);

        let cubic_point = sample_forgematrix_v4_cubic_point(&mut prover_challenger, 0, 0).unwrap();
        observe_bytes(&mut prover_challenger, CUBIC_PROOF_DOMAIN);
        let cubic = ForgeMatrixV4CubicRelationProof {
            sumcheck: zero_sumcheck(
                &mut prover_challenger,
                FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE,
            ),
            preactivation_evaluation: ForgeMatrixV4Extension::zero(),
            next_activation_evaluation: ForgeMatrixV4Extension::zero(),
        };
        prover_challenger.observe_ext_element(cubic.preactivation_evaluation);
        prover_challenger.observe_ext_element(cubic.next_activation_evaluation);
        let final_point = sample_forgematrix_v4_final_point(&mut prover_challenger, 0).unwrap();

        let mut verifier_challenger = forgematrix_v4_transcript(statement());
        bind_forgematrix_v4_commitments(&mut verifier_challenger, &commitments, &commitments);
        assert_eq!(
            sample_forgematrix_v4_matrix_point(&mut verifier_challenger, 0, 0).unwrap(),
            matrix_point
        );
        verify_forgematrix_v4_matrix_relation(
            &matrix_point,
            ForgeMatrixV4Extension::zero(),
            &matrix,
            &mut verifier_challenger,
        )
        .unwrap();
        verify_forgematrix_v4_shift_relation(
            &source_layer,
            matrix.input_evaluation,
            &shift,
            &mut verifier_challenger,
        )
        .unwrap();
        assert_eq!(
            sample_forgematrix_v4_cubic_point(&mut verifier_challenger, 0, 0).unwrap(),
            cubic_point
        );
        verify_forgematrix_v4_cubic_relation(&cubic_point, &cubic, &mut verifier_challenger)
            .unwrap();
        assert_eq!(
            sample_forgematrix_v4_final_point(&mut verifier_challenger, 0).unwrap(),
            final_point
        );

        let mut bad_matrix = matrix.clone();
        bad_matrix.preactivation_evaluation = ForgeMatrixV4Extension::one();
        let mut challenger = forgematrix_v4_transcript(statement());
        bind_forgematrix_v4_commitments(&mut challenger, &commitments, &commitments);
        let point = sample_forgematrix_v4_matrix_point(&mut challenger, 0, 0).unwrap();
        assert_eq!(
            verify_forgematrix_v4_matrix_relation(
                &point,
                ForgeMatrixV4Extension::zero(),
                &bad_matrix,
                &mut challenger,
            ),
            Err(ForgeMatrixV4RelationError::Claim)
        );
    }

    #[test]
    fn claim_routing_produces_twelve_relations_then_four_deterministic_padding_claims() {
        let mut claims = Vec::new();
        for _ in 0..FORGEMATRIX_V4_RELATION_REPETITIONS {
            for value in 0..6 {
                claims.push(ForgeMatrixV4OpeningClaim {
                    commitment: ForgeMatrixV4OpeningCommitment::Dynamic,
                    column_point: Point::from(vec![ForgeMatrixV4Extension::zero(); 4]),
                    row_point: Point::from(vec![ForgeMatrixV4Extension::zero(); 23]),
                    value: ForgeMatrixV4Extension::from_canonical_usize(value as usize),
                });
            }
        }
        let padding = claims.last().unwrap().value;
        finalize_forgematrix_v4_bank_opening_claims(&mut claims).unwrap();
        assert_eq!(claims.len(), FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK);
        assert!(
            claims[FORGEMATRIX_V4_RELATION_OPENING_CLAIMS_PER_BANK..]
                .iter()
                .all(|claim| claim.value == padding)
        );
    }

    #[test]
    fn shift_boundary_is_the_previous_bank_tail_at_the_matrix_input_coordinates() {
        let mut challenger = forgematrix_v4_transcript(statement());
        let matrix_point = sample_forgematrix_v4_matrix_point(&mut challenger, 1, 0).unwrap();
        observe_bytes(&mut challenger, MATRIX_PROOF_DOMAIN);
        challenger.observe_ext_element(ForgeMatrixV4Extension::zero());
        challenger.observe_ext_element(ForgeMatrixV4Extension::zero());
        let matrix = ForgeMatrixV4MatrixRelationProof {
            sumcheck: zero_sumcheck(
                &mut challenger,
                FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
            ),
            preactivation_evaluation: ForgeMatrixV4Extension::zero(),
            weight_evaluation: ForgeMatrixV4Extension::zero(),
            input_evaluation: ForgeMatrixV4Extension::zero(),
        };
        challenger.observe_ext_element(matrix.weight_evaluation);
        challenger.observe_ext_element(matrix.input_evaluation);
        observe_bytes(&mut challenger, SHIFT_PROOF_DOMAIN);
        challenger.observe_ext_element(matrix.input_evaluation);
        challenger.observe_ext_element(ForgeMatrixV4Extension::from_canonical_usize(17));
        let shift = ForgeMatrixV4ShiftRelationProof {
            sumcheck: zero_sumcheck(
                &mut challenger,
                FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
            ),
            boundary_evaluation: ForgeMatrixV4Extension::from_canonical_usize(17),
            next_activation_evaluation: ForgeMatrixV4Extension::zero(),
        };
        let boundary = forgematrix_v4_shift_boundary_point(&matrix_point, &matrix).unwrap();
        assert_eq!(boundary.batch, matrix_point.batch);
        assert_eq!(
            boundary.output,
            point_range(
                &matrix.sumcheck.point_and_eval.0,
                LAYER_VARIABLES..FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
            )
            .unwrap()
        );
        let claim =
            forgematrix_v4_shift_boundary_opening_claim(&matrix_point, &matrix, &shift).unwrap();
        assert_eq!(claim.commitment, ForgeMatrixV4OpeningCommitment::Dynamic);
        assert_eq!(claim.value, shift.boundary_evaluation);
        let expected = forgematrix_v4_dynamic_pcs_point(
            ForgeMatrixV4DynamicTraceKind::NextActivation,
            &Point::from(vec![ForgeMatrixV4Extension::one(); LAYER_VARIABLES]),
            &boundary.batch,
            &boundary.output,
        )
        .unwrap();
        assert_eq!(claim.column_point, expected.column);
        assert_eq!(claim.row_point, expected.row);
    }
}
