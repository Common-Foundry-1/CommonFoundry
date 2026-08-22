//! Canonical shared-layout boundary for the BLS12-381 proof components.
//!
//! Matrix, transition, and wiring commitments must use one variable count before
//! their openings can be reduced by a single Dory aggregate. This module pins
//! the production n=33 geometry, composes transition arithmetic with the range
//! checkpoint against one commitment, and keeps the remaining shared-aggregate
//! deficit explicit.

use thiserror::Error;

use crate::{
    STRUCTURED_TRANSITION_ORACLES, StructuredMaskPolynomial, StructuredTransitionStatement,
    StructuredTransitionWitness,
    dory_bls12_381_aggregate::{BlsDoryAggregateError, projected_bls_dory_aggregate_bytes},
    dory_bls12_381_logup::{
        BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS, BlsDoryRangeLogUpError, BlsDoryRangeLogUpProof,
        prove_bls_dory_range_logup, prove_bls_dory_range_logup_at_variables,
        verify_bls_dory_range_logup, verify_bls_dory_range_logup_at_variables,
    },
    dory_bls12_381_prototype::DeterministicBlsDorySetup,
    dory_bls12_381_transition::{
        BLS_DORY_TRANSITION_OPENING_CLAIMS, BlsDoryTransitionError, BlsDoryTransitionProof,
        prove_bls_dory_transition, prove_bls_dory_transition_at_variables,
        verify_bls_dory_transition, verify_bls_dory_transition_at_variables,
    },
};

/// Maximum variable count across production matrix, transition, and wiring tables.
pub const BLS_DORY_SHARED_PRODUCTION_VARIABLES: usize = 33;
/// Three matrix banks each expose activation, weight, and accumulator openings.
pub const BLS_DORY_SHARED_PRODUCTION_MATRIX_CLAIMS: usize = 9;
/// The initialization transition and three matrix-bank transitions expose 110 claims each.
pub const BLS_DORY_SHARED_PRODUCTION_TRANSITION_CLAIMS: usize = 4 * STRUCTURED_TRANSITION_ORACLES;
/// Production wiring uses one initialization opening and ten openings per bank.
pub const BLS_DORY_SHARED_PRODUCTION_WIRING_CLAIMS: usize = 31;
/// Current direct terminal set before packed LogUp compression.
pub const BLS_DORY_SHARED_PRODUCTION_DIRECT_CLAIMS: usize = BLS_DORY_SHARED_PRODUCTION_MATRIX_CLAIMS
    + BLS_DORY_SHARED_PRODUCTION_TRANSITION_CLAIMS
    + BLS_DORY_SHARED_PRODUCTION_WIRING_CLAIMS;
/// Four scalar range checkpoints need five openings each.
pub const BLS_DORY_SHARED_LOGUP_RANGE_TRANSITION_CLAIMS: usize =
    4 * BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS;
/// Four arithmetic transition checkpoints retain twelve regular openings each.
pub const BLS_DORY_SHARED_ARITHMETIC_TRANSITION_CLAIMS: usize =
    4 * BLS_DORY_TRANSITION_OPENING_CLAIMS;
/// Arithmetic plus compressed range claims across all four transitions.
pub const BLS_DORY_SHARED_COMPRESSED_TRANSITION_CLAIMS: usize =
    BLS_DORY_SHARED_ARITHMETIC_TRANSITION_CLAIMS + BLS_DORY_SHARED_LOGUP_RANGE_TRANSITION_CLAIMS;
/// Complete claim count after packed range compression.
pub const BLS_DORY_SHARED_COMPRESSED_CHECKPOINT_CLAIMS: usize =
    BLS_DORY_SHARED_PRODUCTION_MATRIX_CLAIMS
        + BLS_DORY_SHARED_COMPRESSED_TRANSITION_CLAIMS
        + BLS_DORY_SHARED_PRODUCTION_WIRING_CLAIMS;
/// Shared transport is not yet accepted by consensus.
pub const BLS_DORY_SHARED_LAYOUT_PRODUCTION_READY: bool = false;
/// Remaining gates on the shared scalar layout.
pub const BLS_DORY_SHARED_LAYOUT_PRODUCTION_BLOCKERS: [&str; 4] = [
    "the 108 matrix, arithmetic, range, and wiring claims still emit separate opening proofs instead of one shared Dory aggregate",
    "matrix, transition, and wiring commitments are not yet linked by equality openings",
    "the common n=33 coefficient tables are not streamed by the in-memory prover",
    "the complete shared transcript, soundness accounting, and implementation have not received independent audit",
];

/// Arithmetic and range proofs that share the exact packed transition commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryTransitionRangeProof {
    pub arithmetic: BlsDoryTransitionProof,
    pub range: BlsDoryRangeLogUpProof,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDorySharedLayoutError {
    #[error("shared Dory layout projection failed: {0}")]
    Aggregate(#[from] BlsDoryAggregateError),
    #[error("transition arithmetic checkpoint failed: {0}")]
    Transition(#[from] BlsDoryTransitionError),
    #[error("transition range checkpoint failed: {0}")]
    Range(#[from] BlsDoryRangeLogUpError),
    #[error("transition arithmetic and range proofs do not share one commitment")]
    TransitionRangeCommitment,
    #[error("the shared BLS12-381 layout is not production ready")]
    NotProductionReady,
}

/// Prove transition arithmetic and range constraints against one commitment.
pub fn prove_bls_dory_transition_range(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryTransitionRangeProof, BlsDorySharedLayoutError> {
    let arithmetic =
        prove_bls_dory_transition(binding, statement, mask_polynomial, witness, setup)?;
    let range = prove_bls_dory_range_logup(binding, statement, witness, setup)?;
    transition_range_proof(arithmetic, range)
}

/// Prove the combined transition checkpoint at an exact shared geometry.
pub fn prove_bls_dory_transition_range_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryTransitionRangeProof, BlsDorySharedLayoutError> {
    let arithmetic = prove_bls_dory_transition_at_variables(
        binding,
        statement,
        mask_polynomial,
        witness,
        packed_variables,
        setup,
    )?;
    let range = prove_bls_dory_range_logup_at_variables(
        binding,
        statement,
        witness,
        packed_variables,
        setup,
    )?;
    transition_range_proof(arithmetic, range)
}

fn transition_range_proof(
    arithmetic: BlsDoryTransitionProof,
    range: BlsDoryRangeLogUpProof,
) -> Result<BlsDoryTransitionRangeProof, BlsDorySharedLayoutError> {
    if arithmetic.oracle_commitment != range.transition_commitment {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    Ok(BlsDoryTransitionRangeProof { arithmetic, range })
}

/// Verify both halves of the transition relation against one commitment.
pub fn verify_bls_dory_transition_range(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &BlsDoryTransitionRangeProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    if proof.arithmetic.oracle_commitment != proof.range.transition_commitment {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    verify_bls_dory_transition(
        binding,
        statement,
        mask_polynomial,
        &proof.arithmetic,
        setup,
    )?;
    verify_bls_dory_range_logup(
        binding,
        statement,
        proof.arithmetic.oracle_commitment,
        &proof.range,
        setup,
    )?;
    Ok(())
}

/// Verify the combined transition checkpoint at an exact shared geometry.
pub fn verify_bls_dory_transition_range_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &BlsDoryTransitionRangeProof,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    if proof.arithmetic.oracle_commitment != proof.range.transition_commitment {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    verify_bls_dory_transition_at_variables(
        binding,
        statement,
        mask_polynomial,
        &proof.arithmetic,
        packed_variables,
        setup,
    )?;
    verify_bls_dory_range_logup_at_variables(
        binding,
        statement,
        proof.arithmetic.oracle_commitment,
        &proof.range,
        packed_variables,
        setup,
    )?;
    Ok(())
}

/// Project one Dory opening aggregate at the canonical production geometry.
pub fn projected_shared_production_opening_bytes() -> Result<usize, BlsDorySharedLayoutError> {
    Ok(projected_bls_dory_aggregate_bytes(
        BLS_DORY_SHARED_PRODUCTION_VARIABLES,
    )?)
}

/// Fail closed until every shared-layout blocker is resolved.
pub fn require_bls_dory_shared_layout_production_ready() -> Result<(), BlsDorySharedLayoutError> {
    Err(BlsDorySharedLayoutError::NotProductionReady)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        StructuredMaskPolynomial, StructuredMatrixStatement, StructuredTransitionStatement,
        StructuredTransitionWitness, StructuredWiringStatement, V2_TRANSITION_MODULUS,
        dory_bls12_381_aggregate::MAX_BLS_DORY_AGGREGATE_CLAIMS,
        dory_bls12_381_matrix::{
            BlsDoryMatrixProof, prove_bls_dory_matrix_at_variables,
            verify_bls_dory_matrix_at_variables,
        },
        dory_bls12_381_prototype::deterministic_bls_dory_setup,
        dory_bls12_381_wiring::{
            BlsDoryWiringProof, prove_bls_dory_wiring_at_variables,
            verify_bls_dory_wiring_at_variables,
        },
    };

    const FIXTURE_VARIABLES: usize = 10;
    const OUTPUT_MODULUS: u64 = 251;
    const OUTPUT_CENTER: i64 = 125;

    fn matrix_fixture() -> (StructuredMatrixStatement, Vec<i64>, Vec<i64>, Vec<i64>) {
        let statement = StructuredMatrixStatement {
            layers: 2,
            rows: 2,
            inner: 2,
            cols: 2,
            max_abs_activation: 10,
            max_abs_weight: 10,
            max_abs_accumulator: 100,
        };
        (
            statement,
            vec![1, 2, 3, 4, -1, 2, 5, -2],
            vec![2, 1, -1, 3, 4, -2, 1, 5],
            vec![0, 7, 2, 15, -2, 12, 18, -20],
        )
    }

    fn transition_fixture() -> (
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

    fn wiring_fixture() -> (StructuredWiringStatement, Vec<i64>, Vec<i64>, Vec<i64>) {
        (
            StructuredWiringStatement {
                banks: 2,
                layers_per_bank: 2,
                rows: 2,
                cols: 2,
                max_abs_activation: 100,
            },
            vec![1, 2, 3, 4],
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        )
    }

    #[test]
    fn all_scalar_components_accept_one_exact_shared_layout() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let (matrix_statement, activations, weights, accumulators) = matrix_fixture();
        let matrix = prove_bls_dory_matrix_at_variables(
            b"shared-layout",
            matrix_statement,
            &activations,
            &weights,
            &accumulators,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_matrix_at_variables(
            b"shared-layout",
            matrix_statement,
            &matrix,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        let (transition_statement, mask, witness) = transition_fixture();
        let transition = prove_bls_dory_transition_range_at_variables(
            b"shared-layout",
            transition_statement,
            &mask,
            &witness,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_transition_range_at_variables(
            b"shared-layout",
            transition_statement,
            &mask,
            &transition,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        let (wiring_statement, initial, inputs, outputs) = wiring_fixture();
        let wiring = prove_bls_dory_wiring_at_variables(
            b"shared-layout",
            wiring_statement,
            &initial,
            &inputs,
            &outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_wiring_at_variables(
            b"shared-layout",
            wiring_statement,
            &wiring,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        assert_eq!(usize::from(matrix.padded_variables), FIXTURE_VARIABLES);
        assert_eq!(
            usize::from(transition.arithmetic.packed_variables),
            FIXTURE_VARIABLES
        );
        assert_eq!(
            usize::from(transition.range.packed_variables),
            FIXTURE_VARIABLES
        );
        assert_eq!(usize::from(wiring.packed_variables), FIXTURE_VARIABLES);
        assert_eq!(matrix.opening_proof.len(), 21_775);
        assert_eq!(transition.arithmetic.opening_proof.len(), 21_775);
        assert_eq!(transition.range.opening_proof.len(), 21_775);
        assert_eq!(wiring.opening_proof.len(), 21_775);
        let fixture_claims =
            3 + BLS_DORY_TRANSITION_OPENING_CLAIMS + BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS + 9;
        assert_eq!(fixture_claims, 29);
        assert!(fixture_claims <= MAX_BLS_DORY_AGGREGATE_CLAIMS);

        let matrix_encoded = matrix.encode(matrix_statement).unwrap();
        assert_eq!(
            BlsDoryMatrixProof::decode_with_variables(
                &matrix_encoded,
                matrix_statement,
                FIXTURE_VARIABLES,
            )
            .unwrap(),
            matrix
        );
        let transition_encoded = transition.arithmetic.encode(transition_statement).unwrap();
        assert_eq!(
            BlsDoryTransitionProof::decode_with_variables(
                &transition_encoded,
                transition_statement,
                FIXTURE_VARIABLES,
            )
            .unwrap(),
            transition.arithmetic
        );
        let wiring_encoded = wiring.encode(wiring_statement).unwrap();
        assert_eq!(
            BlsDoryWiringProof::decode_with_variables(
                &wiring_encoded,
                wiring_statement,
                FIXTURE_VARIABLES,
            )
            .unwrap(),
            wiring
        );
    }

    #[test]
    fn transition_range_composition_requires_both_proofs_and_one_commitment() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let (statement, mask, witness) = transition_fixture();
        let proof =
            prove_bls_dory_transition_range(b"composed", statement, &mask, &witness, &setup)
                .unwrap();
        verify_bls_dory_transition_range(b"composed", statement, &mask, &proof, &setup).unwrap();

        let mut mismatched = proof.clone();
        mismatched.range.transition_commitment = mismatched.range.multiplicity_commitment;
        assert_eq!(
            verify_bls_dory_transition_range(b"composed", statement, &mask, &mismatched, &setup,),
            Err(BlsDorySharedLayoutError::TransitionRangeCommitment)
        );

        let mut missing_range = proof;
        missing_range.range.opening_proof[0] ^= 1;
        assert!(
            verify_bls_dory_transition_range(
                b"composed",
                statement,
                &mask,
                &missing_range,
                &setup,
            )
            .is_err()
        );
    }

    #[test]
    fn shared_layout_mismatches_fail_before_opening_verification() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let mismatched_variables = FIXTURE_VARIABLES - 1;

        let (matrix_statement, activations, weights, accumulators) = matrix_fixture();
        let matrix = prove_bls_dory_matrix_at_variables(
            b"mismatch",
            matrix_statement,
            &activations,
            &weights,
            &accumulators,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            verify_bls_dory_matrix_at_variables(
                b"mismatch",
                matrix_statement,
                &matrix,
                mismatched_variables,
                &setup,
            )
            .is_err()
        );
        let matrix_encoded = matrix.encode(matrix_statement).unwrap();
        assert!(
            BlsDoryMatrixProof::decode_with_variables(
                &matrix_encoded,
                matrix_statement,
                mismatched_variables,
            )
            .is_err()
        );

        let (transition_statement, mask, witness) = transition_fixture();
        let transition = prove_bls_dory_transition_at_variables(
            b"mismatch",
            transition_statement,
            &mask,
            &witness,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            verify_bls_dory_transition_at_variables(
                b"mismatch",
                transition_statement,
                &mask,
                &transition,
                mismatched_variables,
                &setup,
            )
            .is_err()
        );
        let transition_encoded = transition.encode(transition_statement).unwrap();
        assert!(
            BlsDoryTransitionProof::decode_with_variables(
                &transition_encoded,
                transition_statement,
                mismatched_variables,
            )
            .is_err()
        );

        let (wiring_statement, initial, inputs, outputs) = wiring_fixture();
        let wiring = prove_bls_dory_wiring_at_variables(
            b"mismatch",
            wiring_statement,
            &initial,
            &inputs,
            &outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            verify_bls_dory_wiring_at_variables(
                b"mismatch",
                wiring_statement,
                &wiring,
                mismatched_variables,
                &setup,
            )
            .is_err()
        );
        let wiring_encoded = wiring.encode(wiring_statement).unwrap();
        assert!(
            BlsDoryWiringProof::decode_with_variables(
                &wiring_encoded,
                wiring_statement,
                mismatched_variables,
            )
            .is_err()
        );
    }

    #[test]
    fn production_claim_deficit_and_opening_projection_are_explicit() {
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_VARIABLES, 33);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_DIRECT_CLAIMS, 480);
        assert_eq!(BLS_DORY_SHARED_ARITHMETIC_TRANSITION_CLAIMS, 48);
        assert_eq!(BLS_DORY_SHARED_LOGUP_RANGE_TRANSITION_CLAIMS, 20);
        assert_eq!(BLS_DORY_SHARED_COMPRESSED_TRANSITION_CLAIMS, 68);
        assert_eq!(BLS_DORY_SHARED_COMPRESSED_CHECKPOINT_CLAIMS, 108);
        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
        assert_eq!(projected_shared_production_opening_bytes().unwrap(), 70_639);
        assert_eq!(BLS_DORY_SHARED_LAYOUT_PRODUCTION_BLOCKERS.len(), 4);
        assert_eq!(
            require_bls_dory_shared_layout_production_ready(),
            Err(BlsDorySharedLayoutError::NotProductionReady)
        );
    }
}
