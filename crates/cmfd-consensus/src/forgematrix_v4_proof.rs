//! Complete CPU verification order for the isolated ProductionV4 proof.

use blake3::Hasher;
use slop_algebra::{AbstractField, PrimeField32};
use slop_multilinear::{Mle, Point};
use thiserror::Error;

use crate::{
    FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_FIELD_MODULUS,
    FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN, FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK,
    FORGEMATRIX_V4_PROOF_VERSION, FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES,
    FORGEMATRIX_V4_RELATION_REPETITIONS,
    forgematrix_v2::{
        PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION,
        PRODUCTION_V2_LAYERS_PER_BANK, V2_MODEL_VALUE_CENTER, mask_coefficients,
    },
    forgematrix_v4_basefold::{
        ForgeMatrixV4Digest, ForgeMatrixV4Extension, ForgeMatrixV4Field, ForgeMatrixV4OpeningClaim,
        ForgeMatrixV4OpeningReductionProof, ForgeMatrixV4TranscriptStatement,
        ForgeMatrixV4VerifierError, forgematrix_v4_transcript,
        verify_forgematrix_v4_opening_reduction,
    },
    forgematrix_v4_proof_system_digest,
    forgematrix_v4_relations::{
        ForgeMatrixV4CubicRelationProof, ForgeMatrixV4MatrixRelationProof,
        ForgeMatrixV4RelationError, ForgeMatrixV4ShiftRelationProof,
        bind_forgematrix_v4_commitments, finalize_forgematrix_v4_bank_opening_claims,
        forgematrix_v4_cubic_opening_claims, forgematrix_v4_final_opening_claim,
        forgematrix_v4_matrix_opening_claims, forgematrix_v4_matrix_terminal_layer,
        forgematrix_v4_shift_boundary_opening_claim, forgematrix_v4_shift_boundary_point,
        forgematrix_v4_shift_opening_claim, sample_forgematrix_v4_cubic_point,
        sample_forgematrix_v4_final_point, sample_forgematrix_v4_matrix_point,
        verify_forgematrix_v4_cubic_relation, verify_forgematrix_v4_matrix_relation,
        verify_forgematrix_v4_shift_relation,
    },
};

#[derive(Clone)]
pub struct ForgeMatrixV4RelationRepetitionProof {
    pub matrix: ForgeMatrixV4MatrixRelationProof,
    pub shift: ForgeMatrixV4ShiftRelationProof,
    pub cubic: ForgeMatrixV4CubicRelationProof,
}

#[derive(Clone)]
pub struct ForgeMatrixV4BankProof {
    pub dynamic_commitment: ForgeMatrixV4Digest,
    pub relations:
        [ForgeMatrixV4RelationRepetitionProof; FORGEMATRIX_V4_RELATION_REPETITIONS as usize],
    pub opening: ForgeMatrixV4OpeningReductionProof,
}

#[derive(Clone)]
pub struct ForgeMatrixV4TransparentProof {
    pub final_activation: Vec<ForgeMatrixV4Field>,
    pub banks: [ForgeMatrixV4BankProof; PRODUCTION_V2_BANKS as usize],
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ForgeMatrixV4ProofError {
    #[error("V4 proof statement does not match the pinned network and proof system")]
    Statement,
    #[error("V4 proof or model input has the wrong production shape")]
    Shape,
    #[error("V4 proof contains an invalid model or field value")]
    Value,
    #[error("V4 final activation digest does not match its canonical field vector")]
    FinalActivationDigest,
    #[error("V4 relation verification failed: {0}")]
    Relation(#[from] ForgeMatrixV4RelationError),
    #[error("V4 opening verification failed: {0}")]
    Opening(#[from] ForgeMatrixV4VerifierError),
}

pub fn forgematrix_v4_final_activation_digest(
    challenge_digest: [u8; 32],
    final_activation: &[ForgeMatrixV4Field],
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN);
    hasher.update(&challenge_digest);
    hasher.update(&(final_activation.len() as u64).to_le_bytes());
    for value in final_activation {
        hasher.update(&value.as_canonical_u32().to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Returns the exact coordinate-mask coefficients consumed by a V4 replay.
/// `global_layer == u32::MAX` selects the public initial-activation mask.
pub fn forgematrix_v4_mask_coefficients(challenge_digest: [u8; 32], global_layer: u32) -> [u8; 20] {
    mask_coefficients(
        &challenge_digest,
        global_layer,
        PRODUCTION_V2_BATCH as usize,
        PRODUCTION_V2_DIMENSION as usize,
    )
    .try_into()
    .expect("the production V4 mask has exactly 20 coefficients")
}

pub fn verify_forgematrix_v4_transparent_proof(
    statement: ForgeMatrixV4TranscriptStatement,
    fixed_commitments: [ForgeMatrixV4Digest; PRODUCTION_V2_BANKS as usize],
    base_input: &[u8],
    proof: &ForgeMatrixV4TransparentProof,
) -> Result<(), ForgeMatrixV4ProofError> {
    validate_statement(statement)?;
    let cells = production_cells()?;
    if base_input.len() != cells
        || proof.final_activation.len() != cells
        || cells.checked_mul(std::mem::size_of::<u32>())
            != Some(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES)
    {
        return Err(ForgeMatrixV4ProofError::Shape);
    }
    if base_input.iter().any(|value| *value > 250) {
        return Err(ForgeMatrixV4ProofError::Value);
    }
    if forgematrix_v4_final_activation_digest(statement.challenge_digest, &proof.final_activation)
        != statement.final_activation_digest
    {
        return Err(ForgeMatrixV4ProofError::FinalActivationDigest);
    }

    let dynamic_commitments = std::array::from_fn(|bank| proof.banks[bank].dynamic_commitment);
    let mut challenger = forgematrix_v4_transcript(statement);
    bind_forgematrix_v4_commitments(&mut challenger, &fixed_commitments, &dynamic_commitments);
    let mut claims: [Vec<ForgeMatrixV4OpeningClaim>; PRODUCTION_V2_BANKS as usize] =
        std::array::from_fn(|_| Vec::with_capacity(FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK));

    for bank in 0..PRODUCTION_V2_BANKS as usize {
        for repetition in 0..FORGEMATRIX_V4_RELATION_REPETITIONS as usize {
            let relation = &proof.banks[bank].relations[repetition];
            let matrix_point =
                sample_forgematrix_v4_matrix_point(&mut challenger, bank, repetition)?;
            let mask_evaluation = forgematrix_v4_mask_evaluation(
                statement.challenge_digest,
                bank,
                &matrix_point.layer,
                &matrix_point.batch,
                &matrix_point.output,
            )?;
            verify_forgematrix_v4_matrix_relation(
                &matrix_point,
                mask_evaluation,
                &relation.matrix,
                &mut challenger,
            )?;
            let terminal_layer = forgematrix_v4_matrix_terminal_layer(&relation.matrix)?;
            verify_forgematrix_v4_shift_relation(
                &terminal_layer,
                relation.matrix.input_evaluation,
                &relation.shift,
                &mut challenger,
            )?;

            claims[bank].extend(forgematrix_v4_matrix_opening_claims(
                &matrix_point,
                &relation.matrix,
            )?);
            claims[bank].push(forgematrix_v4_shift_opening_claim(
                &matrix_point,
                &relation.matrix,
                &relation.shift,
            )?);

            let boundary_point =
                forgematrix_v4_shift_boundary_point(&matrix_point, &relation.matrix)?;
            if bank == 0 {
                let expected = forgematrix_v4_initial_activation_evaluation(
                    statement.challenge_digest,
                    base_input,
                    &boundary_point.batch,
                    &boundary_point.output,
                )?;
                if relation.shift.boundary_evaluation != expected {
                    return Err(ForgeMatrixV4ProofError::Value);
                }
            } else {
                claims[bank - 1].push(forgematrix_v4_shift_boundary_opening_claim(
                    &matrix_point,
                    &relation.matrix,
                    &relation.shift,
                )?);
            }

            let cubic_point = sample_forgematrix_v4_cubic_point(&mut challenger, bank, repetition)?;
            verify_forgematrix_v4_cubic_relation(&cubic_point, &relation.cubic, &mut challenger)?;
            claims[bank].extend(forgematrix_v4_cubic_opening_claims(&relation.cubic)?);
        }
        if bank > 0 {
            let completed_bank = bank - 1;
            finalize_forgematrix_v4_bank_opening_claims(&mut claims[completed_bank])?;
            verify_forgematrix_v4_opening_reduction(
                [
                    fixed_commitments[completed_bank],
                    dynamic_commitments[completed_bank],
                ],
                &claims[completed_bank],
                &proof.banks[completed_bank].opening,
                &mut challenger,
            )?;
        }
    }

    let last_bank = PRODUCTION_V2_BANKS as usize - 1;
    for repetition in 0..FORGEMATRIX_V4_RELATION_REPETITIONS as usize {
        let point = sample_forgematrix_v4_final_point(&mut challenger, repetition)?;
        let value = forgematrix_v4_activation_evaluation(
            &proof.final_activation,
            &point.batch,
            &point.output,
        )?;
        claims[last_bank].push(forgematrix_v4_final_opening_claim(&point, value)?);
    }

    finalize_forgematrix_v4_bank_opening_claims(&mut claims[last_bank])?;
    verify_forgematrix_v4_opening_reduction(
        [fixed_commitments[last_bank], dynamic_commitments[last_bank]],
        &claims[last_bank],
        &proof.banks[last_bank].opening,
        &mut challenger,
    )?;
    Ok(())
}

pub fn forgematrix_v4_mask_evaluation(
    challenge_digest: [u8; 32],
    bank: usize,
    layer: &Point<ForgeMatrixV4Extension>,
    batch: &Point<ForgeMatrixV4Extension>,
    output: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4ProofError> {
    if bank >= PRODUCTION_V2_BANKS as usize
        || layer.dimension() != PRODUCTION_V2_LAYERS_PER_BANK.ilog2() as usize
        || batch.dimension() != PRODUCTION_V2_BATCH.ilog2() as usize
        || output.dimension() != PRODUCTION_V2_DIMENSION.ilog2() as usize
    {
        return Err(ForgeMatrixV4ProofError::Shape);
    }
    let layer_weights = Mle::<ForgeMatrixV4Extension>::partial_lagrange(layer);
    let mut result = ForgeMatrixV4Extension::zero();
    for local_layer in 0..PRODUCTION_V2_LAYERS_PER_BANK as usize {
        let global_layer = bank
            .checked_mul(PRODUCTION_V2_LAYERS_PER_BANK as usize)
            .and_then(|offset| offset.checked_add(local_layer))
            .and_then(|index| u32::try_from(index).ok())
            .ok_or(ForgeMatrixV4ProofError::Shape)?;
        let coefficients = forgematrix_v4_mask_coefficients(challenge_digest, global_layer);
        let value = affine_mask_evaluation(&coefficients, batch, output)?;
        result += layer_weights.guts().as_slice()[local_layer] * value;
    }
    Ok(result)
}

pub fn forgematrix_v4_initial_activation_evaluation(
    challenge_digest: [u8; 32],
    base_input: &[u8],
    batch: &Point<ForgeMatrixV4Extension>,
    output: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4ProofError> {
    let cells = production_cells()?;
    if base_input.len() != cells
        || batch.dimension() != PRODUCTION_V2_BATCH.ilog2() as usize
        || output.dimension() != PRODUCTION_V2_DIMENSION.ilog2() as usize
    {
        return Err(ForgeMatrixV4ProofError::Shape);
    }
    if base_input.iter().any(|value| *value > 250) {
        return Err(ForgeMatrixV4ProofError::Value);
    }
    let coefficients = forgematrix_v4_mask_coefficients(challenge_digest, u32::MAX);
    let point = concatenate_points(batch, output);
    let weights = Mle::<ForgeMatrixV4Extension>::partial_lagrange(&point);
    let mut result = ForgeMatrixV4Extension::zero();
    for (index, (&encoded, &weight)) in base_input.iter().zip(weights.guts().as_slice()).enumerate()
    {
        let row = index / PRODUCTION_V2_DIMENSION as usize;
        let column = index % PRODUCTION_V2_DIMENSION as usize;
        let mask = mask_value(&coefficients, row, column)?;
        let centered = i32::from(encoded) - i32::from(V2_MODEL_VALUE_CENTER);
        let value = canonical_signed(centered + i32::from(mask));
        result += weight * value * value * value;
    }
    Ok(result)
}

pub fn forgematrix_v4_activation_evaluation(
    activation: &[ForgeMatrixV4Field],
    batch: &Point<ForgeMatrixV4Extension>,
    output: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4ProofError> {
    if activation.len() != production_cells()?
        || batch.dimension() != PRODUCTION_V2_BATCH.ilog2() as usize
        || output.dimension() != PRODUCTION_V2_DIMENSION.ilog2() as usize
    {
        return Err(ForgeMatrixV4ProofError::Shape);
    }
    let weights =
        Mle::<ForgeMatrixV4Extension>::partial_lagrange(&concatenate_points(batch, output));
    Ok(activation
        .iter()
        .zip(weights.guts().as_slice())
        .map(|(&value, &weight)| weight * value)
        .sum())
}

fn validate_statement(
    statement: ForgeMatrixV4TranscriptStatement,
) -> Result<(), ForgeMatrixV4ProofError> {
    if statement.block.network_id == [0; 32]
        || statement.algorithm_version != FORGEMATRIX_V4_ALGORITHM_VERSION
        || statement.proof_version != FORGEMATRIX_V4_PROOF_VERSION
        || statement.proof_system_digest != forgematrix_v4_proof_system_digest()
        || statement.model_manifest_digest == [0; 32]
        || statement.challenge_digest == [0; 32]
        || statement.final_activation_digest == [0; 32]
        || statement.work_digest == [0; 32]
    {
        return Err(ForgeMatrixV4ProofError::Statement);
    }
    Ok(())
}

fn affine_mask_evaluation(
    coefficients: &[u8],
    batch: &Point<ForgeMatrixV4Extension>,
    output: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4ProofError> {
    if coefficients.len() != 1 + batch.dimension() + output.dimension() {
        return Err(ForgeMatrixV4ProofError::Shape);
    }
    let mut value = ForgeMatrixV4Extension::from_canonical_u8(coefficients[0]);
    for (bit, &coordinate) in batch.iter().rev().enumerate() {
        value += coordinate * ForgeMatrixV4Extension::from_canonical_u8(coefficients[1 + bit]);
    }
    for (bit, &coordinate) in output.iter().rev().enumerate() {
        value += coordinate
            * ForgeMatrixV4Extension::from_canonical_u8(coefficients[1 + batch.dimension() + bit]);
    }
    Ok(value)
}

fn mask_value(
    coefficients: &[u8],
    row: usize,
    column: usize,
) -> Result<u16, ForgeMatrixV4ProofError> {
    let row_bits = PRODUCTION_V2_BATCH.ilog2() as usize;
    let column_bits = PRODUCTION_V2_DIMENSION.ilog2() as usize;
    if coefficients.len() != 1 + row_bits + column_bits
        || row >= PRODUCTION_V2_BATCH as usize
        || column >= PRODUCTION_V2_DIMENSION as usize
    {
        return Err(ForgeMatrixV4ProofError::Shape);
    }
    let mut value = u16::from(coefficients[0]);
    for bit in 0..row_bits {
        if ((row >> bit) & 1) == 1 {
            value += u16::from(coefficients[1 + bit]);
        }
    }
    for bit in 0..column_bits {
        if ((column >> bit) & 1) == 1 {
            value += u16::from(coefficients[1 + row_bits + bit]);
        }
    }
    Ok(value)
}

fn canonical_signed(value: i32) -> ForgeMatrixV4Extension {
    let modulus = i64::from(FORGEMATRIX_V4_FIELD_MODULUS);
    let canonical = i64::from(value).rem_euclid(modulus) as u32;
    ForgeMatrixV4Extension::from_canonical_u32(canonical)
}

fn concatenate_points(
    left: &Point<ForgeMatrixV4Extension>,
    right: &Point<ForgeMatrixV4Extension>,
) -> Point<ForgeMatrixV4Extension> {
    Point::from(left.iter().chain(right.iter()).copied().collect::<Vec<_>>())
}

fn production_cells() -> Result<usize, ForgeMatrixV4ProofError> {
    (PRODUCTION_V2_BATCH as usize)
        .checked_mul(PRODUCTION_V2_DIMENSION as usize)
        .ok_or(ForgeMatrixV4ProofError::Shape)
}

#[cfg(test)]
mod tests {
    use slop_algebra::AbstractField;

    use super::*;
    use crate::BlockChallenge;

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

    #[test]
    fn mask_evaluation_matches_every_boolean_coordinate_in_selected_layers() {
        let challenge = [0x71; 32];
        for (bank, layer, row, column) in [
            (0, 0, 0, 0),
            (0, 127, 127, 4095),
            (1, 31, 64, 2048),
            (2, 126, 3, 17),
        ] {
            let global = bank * PRODUCTION_V2_LAYERS_PER_BANK as usize + layer;
            let coefficients = mask_coefficients(
                &challenge,
                global as u32,
                PRODUCTION_V2_BATCH as usize,
                PRODUCTION_V2_DIMENSION as usize,
            );
            assert_eq!(
                forgematrix_v4_mask_coefficients(challenge, global as u32).as_slice(),
                coefficients
            );
            assert_eq!(
                forgematrix_v4_mask_evaluation(
                    challenge,
                    bank,
                    &boolean_point(layer, 7),
                    &boolean_point(row, 7),
                    &boolean_point(column, 12),
                )
                .unwrap(),
                ForgeMatrixV4Extension::from_canonical_u16(
                    mask_value(&coefficients, row, column).unwrap()
                )
            );
        }
    }

    #[test]
    fn public_activation_evaluation_uses_exact_row_major_boolean_order() {
        let mut activation = vec![ForgeMatrixV4Field::zero(); production_cells().unwrap()];
        let row = 73;
        let column = 2027;
        activation[row * PRODUCTION_V2_DIMENSION as usize + column] =
            ForgeMatrixV4Field::from_canonical_u32(123_456);
        assert_eq!(
            forgematrix_v4_activation_evaluation(
                &activation,
                &boolean_point(row, 7),
                &boolean_point(column, 12),
            )
            .unwrap(),
            ForgeMatrixV4Extension::from_canonical_u32(123_456)
        );
        assert_eq!(
            forgematrix_v4_activation_evaluation(
                &activation,
                &boolean_point(row, 7),
                &boolean_point(column + 1, 12),
            )
            .unwrap(),
            ForgeMatrixV4Extension::zero()
        );
    }

    #[test]
    fn final_activation_digest_binds_challenge_length_order_and_values() {
        let mut values = vec![ForgeMatrixV4Field::zero(); production_cells().unwrap()];
        values[7] = ForgeMatrixV4Field::one();
        let baseline = forgematrix_v4_final_activation_digest([1; 32], &values);
        values.swap(7, 8);
        assert_ne!(
            forgematrix_v4_final_activation_digest([1; 32], &values),
            baseline
        );
        assert_ne!(
            forgematrix_v4_final_activation_digest([2; 32], &values),
            baseline
        );
        assert_ne!(
            forgematrix_v4_final_activation_digest([1; 32], &values[..values.len() - 1]),
            baseline
        );
    }

    #[test]
    fn initial_activation_rejects_nonproduction_and_forbidden_base_inputs() {
        let point_batch = boolean_point(0, 7);
        let point_output = boolean_point(0, 12);
        assert_eq!(
            forgematrix_v4_initial_activation_evaluation(
                [1; 32],
                &[0; 8],
                &point_batch,
                &point_output,
            ),
            Err(ForgeMatrixV4ProofError::Shape)
        );
        let mut input = vec![125; production_cells().unwrap()];
        input[0] = 251;
        assert_eq!(
            forgematrix_v4_initial_activation_evaluation(
                [1; 32],
                &input,
                &point_batch,
                &point_output,
            ),
            Err(ForgeMatrixV4ProofError::Value)
        );
    }

    #[test]
    fn transparent_verifier_rejects_bad_statement_before_proof_access() {
        let mut statement = ForgeMatrixV4TranscriptStatement {
            block: BlockChallenge {
                network_id: [0; 32],
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
        };
        assert_eq!(
            validate_statement(statement),
            Err(ForgeMatrixV4ProofError::Statement)
        );
        statement.block.network_id = [0xa5; 32];
        assert_eq!(validate_statement(statement), Ok(()));
    }
}
