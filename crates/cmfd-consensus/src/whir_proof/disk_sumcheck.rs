//! Bounded preparation of WHIR's initial suffix sumcheck from an authenticated source.
//!
//! The initial fold is fixed at two variables. This module scans canonical
//! source evaluations in bounded chunks, retains only four suffix partials per
//! opening claim, and materialises the ordinary extension-field product
//! polynomial only after both initial challenges have been sampled.

use cmfd_proof_accel::whir_initial::{
    AuthenticatedWhirInitialSource, WHIR_INITIAL_MAX_SOURCE_READ_LIMBS, WhirInitialSourceIdentity,
};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::SumcheckData;
use p3_sumcheck::lagrange::extrapolate_01inf;
use p3_sumcheck::product_polynomial::ProductPolynomial;
use p3_sumcheck::strategy::{SumcheckProver, VariableOrder, sumcheck_coefficients_suffix};

use super::{EF, ExplicitWhirError, F};
use crate::GOLDILOCKS_MODULUS;

const INITIAL_FOLDING: usize = 2;
const SUFFIX_WIDTH: usize = 1 << INITIAL_FOLDING;

#[derive(Clone, Debug)]
pub(super) struct StreamedInitialClaim {
    point: Point<EF>,
    evaluation: EF,
    suffix_partials: [EF; SUFFIX_WIDTH],
}

impl StreamedInitialClaim {
    pub(super) const fn evaluation(&self) -> EF {
        self.evaluation
    }
}

#[derive(Debug)]
pub(super) struct StreamedInitialSumcheck {
    pub(super) prover: SumcheckProver<F, EF>,
    pub(super) randomness: Point<EF>,
}

/// Evaluate several claims in one bounded source scan and retain only the four
/// fold-two suffix partials needed by the initial sumcheck.
pub(super) fn evaluate_claims(
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    points: &[Point<EF>],
) -> Result<Vec<StreamedInitialClaim>, ExplicitWhirError> {
    let (num_variables, source_len) = validate_source(expected_source, source)?;
    if points
        .iter()
        .any(|point| point.num_variables() != num_variables)
    {
        return Err(ExplicitWhirError::PointDimensionMismatch);
    }

    let prefix_variables = num_variables - INITIAL_FOLDING;
    let mut partials = vec![[EF::ZERO; SUFFIX_WIDTH]; points.len()];
    scan_source(expected_source, source, source_len, |start, values| {
        for (local_group, group) in values.chunks_exact(SUFFIX_WIDTH).enumerate() {
            let prefix_index = (start / SUFFIX_WIDTH) + local_group;
            for (claim_partials, point) in partials.iter_mut().zip(points) {
                let prefix_weight =
                    eq_at_index(&point.as_slice()[..prefix_variables], prefix_index);
                for (slot, &value) in group.iter().enumerate() {
                    claim_partials[slot] += EF::from(F::new(value)) * prefix_weight;
                }
            }
        }
        Ok(())
    })?;

    Ok(points
        .iter()
        .cloned()
        .zip(partials)
        .map(|(point, suffix_partials)| {
            let suffix = &point.as_slice()[prefix_variables..];
            let evaluation =
                fold_suffix_pair(fold_suffix_quad(suffix_partials, suffix[1]), suffix[0]);
            StreamedInitialClaim {
                point,
                evaluation,
                suffix_partials,
            }
        })
        .collect())
}

/// Emit the exact two initial sumcheck messages and build the ordinary
/// residual prover over `2^(n-2)` extension-field evaluations and weights.
pub(super) fn prepare_sumcheck<Ch>(
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    claims: Vec<StreamedInitialClaim>,
    sumcheck_data: &mut SumcheckData<F, EF>,
    pow_bits: usize,
    challenger: &mut Ch,
) -> Result<StreamedInitialSumcheck, ExplicitWhirError>
where
    Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    if claims.is_empty() {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    let (num_variables, source_len) = validate_source(expected_source, source)?;
    if claims
        .iter()
        .any(|claim| claim.point.num_variables() != num_variables)
    {
        return Err(ExplicitWhirError::PointDimensionMismatch);
    }

    let alpha: EF = challenger.sample_algebra_element();
    let mut alpha_power = EF::ONE;
    let mut claimed_sum = EF::ZERO;
    let mut weighted_suffixes = Vec::with_capacity(claims.len());
    for claim in &claims {
        claimed_sum += claim.evaluation * alpha_power;
        let mut suffix = eq_suffix_values(&claim.point);
        for value in &mut suffix {
            *value *= alpha_power;
        }
        weighted_suffixes.push(suffix);
        alpha_power *= alpha;
    }

    let (c0, c_inf) = claims
        .iter()
        .zip(&weighted_suffixes)
        .map(|(claim, weights)| {
            sumcheck_coefficients_suffix::<EF, EF>(&claim.suffix_partials, weights)
        })
        .fold((EF::ZERO, EF::ZERO), |(a0, a_inf), (b0, b_inf)| {
            (a0 + b0, a_inf + b_inf)
        });
    let r0 = sumcheck_data.observe_and_sample(challenger, c0, c_inf, pow_bits);
    claimed_sum = extrapolate_01inf(c0, claimed_sum - c0, c_inf, r0);

    let folded_claims = claims
        .iter()
        .map(|claim| fold_suffix_quad(claim.suffix_partials, r0))
        .collect::<Vec<_>>();
    let folded_weights = weighted_suffixes
        .iter()
        .copied()
        .map(|weights| fold_suffix_quad(weights, r0))
        .collect::<Vec<_>>();
    let (c0, c_inf) = folded_claims
        .iter()
        .zip(&folded_weights)
        .map(|(evals, weights)| sumcheck_coefficients_suffix::<EF, EF>(evals, weights))
        .fold((EF::ZERO, EF::ZERO), |(a0, a_inf), (b0, b_inf)| {
            (a0 + b0, a_inf + b_inf)
        });
    let r1 = sumcheck_data.observe_and_sample(challenger, c0, c_inf, pow_bits);
    claimed_sum = extrapolate_01inf(c0, claimed_sum - c0, c_inf, r1);

    let suffix_scales = folded_weights
        .into_iter()
        .map(|weights| fold_suffix_pair(weights, r1))
        .collect::<Vec<_>>();
    let prefix_variables = num_variables - INITIAL_FOLDING;
    let residual_len = source_len / SUFFIX_WIDTH;
    let mut residual_evals = Vec::with_capacity(residual_len);
    let mut residual_weights = Vec::with_capacity(residual_len);
    scan_source(expected_source, source, source_len, |start, values| {
        for (local_group, group) in values.chunks_exact(SUFFIX_WIDTH).enumerate() {
            let prefix_index = (start / SUFFIX_WIDTH) + local_group;
            let evals = [
                EF::from(F::new(group[0])),
                EF::from(F::new(group[1])),
                EF::from(F::new(group[2])),
                EF::from(F::new(group[3])),
            ];
            residual_evals.push(fold_suffix_pair(fold_suffix_quad(evals, r0), r1));

            let mut weight = EF::ZERO;
            for (claim, &suffix_scale) in claims.iter().zip(&suffix_scales) {
                weight += suffix_scale
                    * eq_at_index(&claim.point.as_slice()[..prefix_variables], prefix_index);
            }
            residual_weights.push(weight);
        }
        Ok(())
    })?;
    if residual_evals.len() != residual_len || residual_weights.len() != residual_len {
        return Err(ExplicitWhirError::ProverStorage);
    }

    let product = ProductPolynomial::new_unpacked(
        VariableOrder::Suffix,
        Poly::new(residual_evals),
        Poly::new(residual_weights),
    );
    Ok(StreamedInitialSumcheck {
        prover: SumcheckProver::new(product, claimed_sum),
        randomness: Point::new(vec![r0, r1]),
    })
}

fn validate_source(
    expected: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
) -> Result<(usize, usize), ExplicitWhirError> {
    if source.identity() != expected {
        return Err(ExplicitWhirError::ProverStorage);
    }
    let num_variables =
        usize::try_from(expected.num_variables).map_err(|_| ExplicitWhirError::ProverStorage)?;
    if num_variables < INITIAL_FOLDING {
        return Err(ExplicitWhirError::ProverStorage);
    }
    let expected_len = 1_usize
        .checked_shl(expected.num_variables)
        .ok_or(ExplicitWhirError::ProverStorage)?;
    if source.len() != expected_len {
        return Err(ExplicitWhirError::ProverStorage);
    }
    Ok((num_variables, expected_len))
}

fn scan_source(
    expected: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    source_len: usize,
    mut consume: impl FnMut(usize, &[u64]) -> Result<(), ExplicitWhirError>,
) -> Result<(), ExplicitWhirError> {
    let chunk_len = WHIR_INITIAL_MAX_SOURCE_READ_LIMBS;
    debug_assert!(chunk_len.is_multiple_of(SUFFIX_WIDTH));
    let mut start = 0;
    while start < source_len {
        let count = (source_len - start).min(chunk_len);
        if !count.is_multiple_of(SUFFIX_WIDTH) {
            return Err(ExplicitWhirError::ProverStorage);
        }
        let values = source
            .read_elements(start, count)
            .map_err(|_| ExplicitWhirError::ProverStorage)?;
        if source.identity() != expected
            || source.len() != source_len
            || values.len() != count
            || values.iter().any(|&value| value >= GOLDILOCKS_MODULUS)
        {
            return Err(ExplicitWhirError::ProverStorage);
        }
        consume(start, &values)?;
        start += count;
    }
    if source.identity() != expected || source.len() != source_len {
        return Err(ExplicitWhirError::ProverStorage);
    }
    Ok(())
}

fn eq_at_index(point: &[EF], index: usize) -> EF {
    point
        .iter()
        .enumerate()
        .fold(EF::ONE, |weight, (coordinate, &value)| {
            let bit = point.len() - 1 - coordinate;
            if (index >> bit) & 1 == 0 {
                weight * (EF::ONE - value)
            } else {
                weight * value
            }
        })
}

fn eq_suffix_values(point: &Point<EF>) -> [EF; SUFFIX_WIDTH] {
    let suffix = &point.as_slice()[point.num_variables() - INITIAL_FOLDING..];
    core::array::from_fn(|index| eq_at_index(suffix, index))
}

fn fold_suffix_quad(values: [EF; SUFFIX_WIDTH], challenge: EF) -> [EF; 2] {
    [
        values[0] + challenge * (values[1] - values[0]),
        values[2] + challenge * (values[3] - values[2]),
    ]
}

fn fold_suffix_pair(values: [EF; 2], challenge: EF) -> EF {
    values[0] + challenge * (values[1] - values[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_weights_match_point_equality_polynomial() {
        let point = Point::new(vec![
            EF::from(F::new(3)),
            EF::from(F::new(5)),
            EF::from(F::new(7)),
        ]);
        let expected = Poly::new_from_point(point.as_slice(), EF::ONE);
        for (index, &expected) in expected.as_slice().iter().enumerate() {
            assert_eq!(eq_at_index(point.as_slice(), index), expected);
        }
    }
}
