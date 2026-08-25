//! Fallible row-stream boundary for BLS12-381 Dory opening proofs.
//!
//! Upstream Dory needs the coefficient matrix only to compute `L^T M` after
//! tier-one row commitments already exist. This module computes that vector
//! sequentially with one reusable row buffer, then runs the unchanged
//! transparent Dory reduction from the precomputed vector. Production sources
//! can therefore read or generate rows without materializing `2^n` scalars.

use dory_pcs::{
    DoryProof, DoryProverState, Transparent,
    messages::VMVMessage,
    primitives::{
        arithmetic::{DoryRoutines, Field, Group, PairingCurve},
        poly::compute_left_right_vectors,
        transcript::Transcript,
    },
};
use thiserror::Error;

use crate::dory_bls12_381_prototype::{
    BlsDoryCurve, BlsDoryFr, BlsDoryG1, BlsDoryG1Routines, BlsDoryG2, BlsDoryG2Routines, BlsDoryGt,
    BlsDoryTranscript, DeterministicBlsDorySetup,
};

pub type BlsDoryOpeningProof = DoryProof<BlsDoryG1, BlsDoryG2, BlsDoryGt>;

/// Sequential coefficient source with verifier-selected matrix geometry.
pub trait BlsDoryRowSource {
    type Error;

    fn rows(&self) -> usize;
    fn columns(&self) -> usize;

    /// Number of row-major scalars that are explicit before a canonical zero
    /// suffix. Dense sources use the full logical geometry.
    fn explicit_scalar_count(&self) -> usize {
        self.rows().saturating_mul(self.columns())
    }

    /// Fill `output` with the exact canonical row and return the number written.
    fn read_row(
        &mut self,
        row_index: usize,
        output: &mut [BlsDoryFr],
    ) -> Result<usize, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlsDoryRowReductionError<E> {
    InvalidGeometry,
    Source(E),
}

/// Compute `L^T M` with exactly one reusable source row plus the output vector.
pub fn stream_bls_dory_vector_matrix_product<S: BlsDoryRowSource>(
    source: &mut S,
    left: &[BlsDoryFr],
) -> Result<Vec<BlsDoryFr>, BlsDoryRowReductionError<S::Error>> {
    let rows = source.rows();
    let columns = source.columns();
    if rows == 0
        || columns == 0
        || !rows.is_power_of_two()
        || !columns.is_power_of_two()
        || left.len() != rows
    {
        return Err(BlsDoryRowReductionError::InvalidGeometry);
    }

    let mut output = vec![BlsDoryFr::zero(); columns];
    let mut row = vec![BlsDoryFr::zero(); columns];
    for (row_index, weight) in left.iter().copied().enumerate() {
        row.fill(BlsDoryFr::zero());
        let written = source
            .read_row(row_index, &mut row)
            .map_err(BlsDoryRowReductionError::Source)?;
        if written != columns {
            return Err(BlsDoryRowReductionError::InvalidGeometry);
        }
        for (result, coefficient) in output.iter_mut().zip(&row) {
            *result = *result + weight * *coefficient;
        }
    }
    Ok(output)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDoryStreamingProofError {
    #[error("precomputed Dory opening geometry is invalid")]
    InvalidGeometry,
}

/// Create the transparent Dory proof from a fallibly precomputed `L^T M`.
///
/// This is deliberately equivalent to `dory_pcs::prove` after its polynomial
/// has computed `vector_matrix_product`. It changes prover data access only;
/// the proof grammar, transcript, and verifier are unchanged.
#[allow(clippy::too_many_arguments)]
pub fn prove_bls_dory_opening_from_vector_product(
    point: &[BlsDoryFr],
    row_commitments: Vec<BlsDoryG1>,
    vector_matrix_product: Vec<BlsDoryFr>,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
    transcript: &mut BlsDoryTranscript,
) -> Result<BlsDoryOpeningProof, BlsDoryStreamingProofError> {
    let rows = 1usize
        .checked_shl(u32::try_from(nu).map_err(|_| BlsDoryStreamingProofError::InvalidGeometry)?)
        .ok_or(BlsDoryStreamingProofError::InvalidGeometry)?;
    let columns = 1usize
        .checked_shl(u32::try_from(sigma).map_err(|_| BlsDoryStreamingProofError::InvalidGeometry)?)
        .ok_or(BlsDoryStreamingProofError::InvalidGeometry)?;
    if nu == 0
        || nu > sigma
        || nu
            .checked_add(sigma)
            .is_none_or(|variables| variables > setup.max_log_n())
        || point.len() != nu + sigma
        || row_commitments.len() != rows
        || vector_matrix_product.len() != columns
    {
        return Err(BlsDoryStreamingProofError::InvalidGeometry);
    }

    let prover = setup.prover();
    let (mut left, mut right) = compute_left_right_vectors(point, nu, sigma);
    let mut padded_row_commitments = row_commitments.clone();
    if nu < sigma {
        padded_row_commitments.resize(columns, BlsDoryG1::identity());
        left.resize(columns, BlsDoryFr::zero());
        right.resize(columns, BlsDoryFr::zero());
    }

    let g2_final = &prover.g2_vec[0];
    let committed_columns = BlsDoryG1Routines::msm(&padded_row_commitments, &vector_matrix_product);
    let c = BlsDoryCurve::pair(&committed_columns, g2_final);
    let d2 = BlsDoryCurve::pair(
        &BlsDoryG1Routines::msm(&prover.g1_vec[..columns], &vector_matrix_product),
        g2_final,
    );
    let e1 = BlsDoryG1Routines::msm(&row_commitments, &left[..rows]);
    let vmv_message = VMVMessage { c, d2, e1 };

    transcript.append_serde(b"vmv_c", &vmv_message.c);
    transcript.append_serde(b"vmv_d2", &vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &vmv_message.e1);

    let v2 = BlsDoryG2Routines::fixed_base_vector_scalar_mul(g2_final, &vector_matrix_product);
    let mut state: DoryProverState<'_, BlsDoryCurve, Transparent> = DoryProverState::new(
        padded_row_commitments,
        v2,
        Some(vector_matrix_product),
        right,
        left,
        prover,
    );
    state.set_initial_blinds(
        BlsDoryFr::zero(),
        BlsDoryFr::zero(),
        BlsDoryFr::zero(),
        BlsDoryFr::zero(),
        BlsDoryFr::zero(),
    );

    let rounds = nu.max(sigma);
    let mut first_messages = Vec::with_capacity(rounds);
    let mut second_messages = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let first = state.compute_first_message::<BlsDoryG1Routines, BlsDoryG2Routines>();
        transcript.append_serde(b"d1_left", &first.d1_left);
        transcript.append_serde(b"d1_right", &first.d1_right);
        transcript.append_serde(b"d2_left", &first.d2_left);
        transcript.append_serde(b"d2_right", &first.d2_right);
        transcript.append_serde(b"e1_beta", &first.e1_beta);
        transcript.append_serde(b"e2_beta", &first.e2_beta);
        let beta = transcript.challenge_scalar(b"beta");
        state.apply_first_challenge::<BlsDoryG1Routines, BlsDoryG2Routines>(&beta);
        first_messages.push(first);

        let second = state.compute_second_message::<BlsDoryG1Routines, BlsDoryG2Routines>();
        transcript.append_serde(b"c_plus", &second.c_plus);
        transcript.append_serde(b"c_minus", &second.c_minus);
        transcript.append_serde(b"e1_plus", &second.e1_plus);
        transcript.append_serde(b"e1_minus", &second.e1_minus);
        transcript.append_serde(b"e2_plus", &second.e2_plus);
        transcript.append_serde(b"e2_minus", &second.e2_minus);
        let alpha = transcript.challenge_scalar(b"alpha");
        state.apply_second_challenge::<BlsDoryG1Routines, BlsDoryG2Routines>(&alpha);
        second_messages.push(second);
    }

    let gamma = transcript.challenge_scalar(b"gamma");
    state.apply_fold_scalars(&gamma);
    let final_message = state.compute_final_message();
    transcript.append_serde(b"final_e1", &final_message.e1);
    transcript.append_serde(b"final_e2", &final_message.e2);
    let _ = transcript.challenge_scalar(b"d");

    Ok(BlsDoryOpeningProof {
        vmv_message,
        first_messages,
        second_messages,
        final_message: Some(final_message),
        nu,
        sigma,
    })
}

#[cfg(test)]
mod tests {
    use dory_pcs::{MultilinearLagrange, Polynomial, prove, verify};

    use super::*;
    use crate::dory_bls12_381_prototype::{BlsDoryPolynomial, deterministic_bls_dory_setup};

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum SourceError {
        Injected,
    }

    struct FixtureRows {
        rows: usize,
        columns: usize,
        coefficients: Vec<BlsDoryFr>,
        fail_at: Option<usize>,
        short_at: Option<usize>,
        reads: usize,
        maximum_buffer: usize,
    }

    impl BlsDoryRowSource for FixtureRows {
        type Error = SourceError;

        fn rows(&self) -> usize {
            self.rows
        }

        fn columns(&self) -> usize {
            self.columns
        }

        fn read_row(
            &mut self,
            row_index: usize,
            output: &mut [BlsDoryFr],
        ) -> Result<usize, Self::Error> {
            if self.fail_at == Some(row_index) {
                return Err(SourceError::Injected);
            }
            self.reads += 1;
            self.maximum_buffer = self.maximum_buffer.max(output.len());
            let start = row_index * self.columns;
            let written = if self.short_at == Some(row_index) {
                self.columns - 1
            } else {
                self.columns
            };
            output[..written].copy_from_slice(&self.coefficients[start..start + written]);
            Ok(written)
        }
    }

    fn fixture_rows(rows: usize, columns: usize, coefficients: Vec<BlsDoryFr>) -> FixtureRows {
        FixtureRows {
            rows,
            columns,
            coefficients,
            fail_at: None,
            short_at: None,
            reads: 0,
            maximum_buffer: 0,
        }
    }

    #[test]
    fn streamed_vector_product_matches_materialized_polynomial_with_one_row_buffer() {
        let nu = 3;
        let sigma = 4;
        let rows = 1 << nu;
        let columns = 1 << sigma;
        let coefficients = (0..rows * columns)
            .map(|index| BlsDoryFr::from_u64((index * 17 + 3) as u64))
            .collect::<Vec<_>>();
        let polynomial = BlsDoryPolynomial::new(coefficients.clone()).unwrap();
        let point = (0..nu + sigma)
            .map(|index| BlsDoryFr::from_u64((index + 2) as u64))
            .collect::<Vec<_>>();
        let (left, _) = compute_left_right_vectors(&point, nu, sigma);
        let expected = polynomial.vector_matrix_product(&left, nu, sigma);
        let mut source = fixture_rows(rows, columns, coefficients);

        let actual = stream_bls_dory_vector_matrix_product(&mut source, &left).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(source.reads, rows);
        assert_eq!(source.maximum_buffer, columns);
    }

    #[test]
    fn streamed_vector_product_propagates_source_failure_and_short_rows() {
        let coefficients = (0..32)
            .map(|index| BlsDoryFr::from_u64(index as u64))
            .collect::<Vec<_>>();
        let left = vec![BlsDoryFr::one(); 4];
        let mut failed = fixture_rows(4, 8, coefficients.clone());
        failed.fail_at = Some(2);
        assert_eq!(
            stream_bls_dory_vector_matrix_product(&mut failed, &left),
            Err(BlsDoryRowReductionError::Source(SourceError::Injected))
        );

        let mut short = fixture_rows(4, 8, coefficients);
        short.short_at = Some(1);
        assert_eq!(
            stream_bls_dory_vector_matrix_product(&mut short, &left),
            Err(BlsDoryRowReductionError::InvalidGeometry)
        );
    }

    #[test]
    fn precomputed_vector_product_preserves_exact_dory_proof_and_transcript() {
        let nu = 3;
        let sigma = 4;
        let rows = 1 << nu;
        let columns = 1 << sigma;
        let coefficients = (0..rows * columns)
            .map(|index| BlsDoryFr::from_u64((index * 29 + 11) as u64))
            .collect::<Vec<_>>();
        let polynomial = BlsDoryPolynomial::new(coefficients.clone()).unwrap();
        let setup = deterministic_bls_dory_setup(nu + sigma).unwrap();
        let point = (0..nu + sigma)
            .map(|index| BlsDoryFr::from_u64((index * 7 + 5) as u64))
            .collect::<Vec<_>>();
        let (commitment, row_commitments, blind) = polynomial
            .commit::<BlsDoryCurve, Transparent, BlsDoryG1Routines>(nu, sigma, setup.prover())
            .unwrap();
        assert_eq!(blind, BlsDoryFr::zero());

        let (left, _) = compute_left_right_vectors(&point, nu, sigma);
        let mut source = fixture_rows(rows, columns, coefficients);
        let product = stream_bls_dory_vector_matrix_product(&mut source, &left).unwrap();
        let evaluation = polynomial.evaluate(&point);
        let mut ordinary_transcript = BlsDoryTranscript::new(b"stream-equivalence");
        let mut streamed_transcript = ordinary_transcript.clone();
        let (ordinary, hidden) =
            prove::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _, _, Transparent>(
                &polynomial,
                &point,
                row_commitments.clone(),
                blind,
                nu,
                sigma,
                setup.prover(),
                &mut ordinary_transcript,
            )
            .unwrap();
        assert!(hidden.is_none());
        let streamed = prove_bls_dory_opening_from_vector_product(
            &point,
            row_commitments,
            product,
            nu,
            sigma,
            &setup,
            &mut streamed_transcript,
        )
        .unwrap();

        assert_eq!(streamed, ordinary);
        assert_eq!(streamed_transcript.digest(), ordinary_transcript.digest());
        verify::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _>(
            commitment,
            evaluation,
            &point,
            &streamed,
            setup.verifier().clone(),
            &mut BlsDoryTranscript::new(b"stream-equivalence"),
        )
        .unwrap();
    }
}
