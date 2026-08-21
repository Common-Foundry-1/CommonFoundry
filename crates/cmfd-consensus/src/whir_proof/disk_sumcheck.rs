//! Bounded preparation of WHIR's initial suffix sumcheck from an authenticated source.
//!
//! The initial fold is fixed at two variables. This module scans canonical
//! source evaluations in bounded chunks, retains only four suffix partials per
//! opening claim, and materialises the ordinary extension-field product
//! polynomial only after both initial challenges have been sampled.

use std::path::Path;

use blake3::Hasher;
use cmfd_proof_accel::whir_initial::{
    AuthenticatedWhirInitialSource, WHIR_INITIAL_MAX_SOURCE_READ_LIMBS, WhirInitialSourceIdentity,
};
use cmfd_proof_accel::whir_residual::{
    AuthenticatedWhirResidualArtifact, WHIR_RESIDUAL_LIMBS_PER_ROW, WHIR_RESIDUAL_MAX_IO_ROWS,
    WhirResidualArtifactSpec, WhirResidualArtifactWriter,
};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
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
const RESIDUAL_CONTEXT_DOMAIN: &str = "Common Foundry WHIR initial residual context v1";

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

#[derive(Debug)]
pub(super) struct PreparedArtifactSumcheck {
    pub(super) artifact: AuthenticatedWhirResidualArtifact,
    pub(super) claimed_sum: EF,
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
    let prepared = prepare_sumcheck_prefix(
        expected_source,
        source,
        claims,
        sumcheck_data,
        pow_bits,
        challenger,
    )?;
    materialize_dense_sumcheck(expected_source, source, &prepared)
}

/// Prepare and retain an authenticated residual artifact for a fallible WHIR
/// prover state. The artifact is not read back into dense vectors and remains
/// owned by the returned capability.
///
/// Artifact metadata is never observed by the challenger. Any storage failure
/// aborts this locally owned proof attempt without a dense fallback.
pub(super) fn prepare_artifact_sumcheck<Ch>(
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    claims: Vec<StreamedInitialClaim>,
    sumcheck_data: &mut SumcheckData<F, EF>,
    pow_bits: usize,
    challenger: &mut Ch,
    artifact: ResidualArtifactConfig<'_>,
) -> Result<PreparedArtifactSumcheck, ExplicitWhirError>
where
    Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    let prepared = prepare_sumcheck_prefix(
        expected_source,
        source,
        claims,
        sumcheck_data,
        pow_bits,
        challenger,
    )?;
    let spec = WhirResidualArtifactSpec {
        source_digest: artifact.exact_source_binding,
        context_digest: residual_context_digest(ResidualContext {
            expected_source,
            invocation_digest: artifact.invocation_digest,
            residual_len: prepared.residual_len,
            claims: &prepared.claims,
            alpha: prepared.alpha,
            sumcheck_data,
            pow_bits,
            r0: prepared.r0,
            r1: prepared.r1,
            claimed_sum: prepared.claimed_sum,
        }),
        num_variables: u32::try_from(prepared.prefix_variables)
            .map_err(|_| ExplicitWhirError::ProverStorage)?,
        generation: 0,
    };
    let mut writer = WhirResidualArtifactWriter::create(artifact.scratch_directory, spec)
        .map_err(|_| ExplicitWhirError::ProverStorage)?;
    let chunk_capacity = prepared.residual_len.min(WHIR_RESIDUAL_MAX_IO_ROWS);
    let mut residual_rows = Vec::new();
    residual_rows
        .try_reserve_exact(chunk_capacity)
        .map_err(|_| ExplicitWhirError::ProverStorage)?;
    emit_residual_product(expected_source, source, &prepared, |eval, weight| {
        residual_rows.push(encode_residual_row(eval, weight));
        if residual_rows.len() == chunk_capacity {
            writer
                .write_rows(writer.rows_written(), &residual_rows)
                .map_err(|_| ExplicitWhirError::ProverStorage)?;
            residual_rows.clear();
        }
        Ok(())
    })?;
    if !residual_rows.is_empty() {
        writer
            .write_rows(writer.rows_written(), &residual_rows)
            .map_err(|_| ExplicitWhirError::ProverStorage)?;
    }
    let artifact = writer
        .finish()
        .map_err(|_| ExplicitWhirError::ProverStorage)?;
    Ok(PreparedArtifactSumcheck {
        artifact,
        claimed_sum: prepared.claimed_sum,
        randomness: Point::new(vec![prepared.r0, prepared.r1]),
    })
}

#[derive(Clone, Copy)]
pub(super) struct ResidualArtifactConfig<'a> {
    pub(super) exact_source_binding: [u8; 32],
    pub(super) invocation_digest: [u8; 32],
    pub(super) scratch_directory: &'a Path,
}

struct PreparedInitialFold {
    source_len: usize,
    prefix_variables: usize,
    residual_len: usize,
    claims: Vec<StreamedInitialClaim>,
    suffix_scales: Vec<EF>,
    alpha: EF,
    r0: EF,
    r1: EF,
    claimed_sum: EF,
}

#[allow(clippy::too_many_arguments)]
fn prepare_sumcheck_prefix<Ch>(
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    claims: Vec<StreamedInitialClaim>,
    sumcheck_data: &mut SumcheckData<F, EF>,
    pow_bits: usize,
    challenger: &mut Ch,
) -> Result<PreparedInitialFold, ExplicitWhirError>
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
    Ok(PreparedInitialFold {
        source_len,
        prefix_variables,
        residual_len,
        claims,
        suffix_scales,
        alpha,
        r0,
        r1,
        claimed_sum,
    })
}

fn materialize_dense_sumcheck(
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    prepared: &PreparedInitialFold,
) -> Result<StreamedInitialSumcheck, ExplicitWhirError> {
    let mut residual_evals = Vec::new();
    let mut residual_weights = Vec::new();
    residual_evals
        .try_reserve_exact(prepared.residual_len)
        .map_err(|_| ExplicitWhirError::ProverStorage)?;
    residual_weights
        .try_reserve_exact(prepared.residual_len)
        .map_err(|_| ExplicitWhirError::ProverStorage)?;
    emit_residual_product(expected_source, source, prepared, |eval, weight| {
        residual_evals.push(eval);
        residual_weights.push(weight);
        Ok(())
    })?;
    if residual_evals.len() != prepared.residual_len
        || residual_weights.len() != prepared.residual_len
    {
        return Err(ExplicitWhirError::ProverStorage);
    }

    let product = ProductPolynomial::new_unpacked(
        VariableOrder::Suffix,
        Poly::new(residual_evals),
        Poly::new(residual_weights),
    );
    Ok(StreamedInitialSumcheck {
        prover: SumcheckProver::new(product, prepared.claimed_sum),
        randomness: Point::new(vec![prepared.r0, prepared.r1]),
    })
}

fn emit_residual_product(
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    prepared: &PreparedInitialFold,
    mut emit: impl FnMut(EF, EF) -> Result<(), ExplicitWhirError>,
) -> Result<(), ExplicitWhirError> {
    let mut actual_sum = EF::ZERO;
    let mut emitted = 0_usize;
    scan_source(
        expected_source,
        source,
        prepared.source_len,
        |start, values| {
            for (local_group, group) in values.chunks_exact(SUFFIX_WIDTH).enumerate() {
                let prefix_index = (start / SUFFIX_WIDTH) + local_group;
                let evals = [
                    EF::from(F::new(group[0])),
                    EF::from(F::new(group[1])),
                    EF::from(F::new(group[2])),
                    EF::from(F::new(group[3])),
                ];
                let residual_eval =
                    fold_suffix_pair(fold_suffix_quad(evals, prepared.r0), prepared.r1);

                let mut weight = EF::ZERO;
                for (claim, &suffix_scale) in prepared.claims.iter().zip(&prepared.suffix_scales) {
                    weight += suffix_scale
                        * eq_at_index(
                            &claim.point.as_slice()[..prepared.prefix_variables],
                            prefix_index,
                        );
                }
                actual_sum += residual_eval * weight;
                emitted = emitted
                    .checked_add(1)
                    .ok_or(ExplicitWhirError::ProverStorage)?;
                emit(residual_eval, weight)?;
            }
            Ok(())
        },
    )?;
    // This equality is a prover-integrity boundary: never publish or return a
    // residual whose encoded product disagrees with the live transcript claim.
    if emitted != prepared.residual_len || actual_sum != prepared.claimed_sum {
        return Err(ExplicitWhirError::ProverStorage);
    }
    Ok(())
}

struct ResidualContext<'a> {
    expected_source: &'a WhirInitialSourceIdentity,
    invocation_digest: [u8; 32],
    residual_len: usize,
    claims: &'a [StreamedInitialClaim],
    alpha: EF,
    sumcheck_data: &'a SumcheckData<F, EF>,
    pow_bits: usize,
    r0: EF,
    r1: EF,
    claimed_sum: EF,
}

fn residual_context_digest(context: ResidualContext<'_>) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(RESIDUAL_CONTEXT_DOMAIN);
    hasher.update(&context.invocation_digest);
    hasher.update(&context.expected_source.source_id);
    hasher.update(&context.expected_source.num_variables.to_le_bytes());
    hasher.update(&(INITIAL_FOLDING as u32).to_le_bytes());
    hasher.update(&[1]); // Natural suffix-variable order.
    hasher.update(&(context.residual_len as u64).to_le_bytes());
    hasher.update(&(context.claims.len() as u64).to_le_bytes());
    hash_extension(&mut hasher, context.alpha);
    for claim in context.claims {
        hasher.update(&(claim.point.num_variables() as u32).to_le_bytes());
        for &coordinate in claim.point.as_slice() {
            hash_extension(&mut hasher, coordinate);
        }
        hash_extension(&mut hasher, claim.evaluation);
        for &partial in &claim.suffix_partials {
            hash_extension(&mut hasher, partial);
        }
    }
    hasher.update(&(context.sumcheck_data.polynomial_evaluations.len() as u32).to_le_bytes());
    for coefficients in &context.sumcheck_data.polynomial_evaluations {
        hash_extension(&mut hasher, coefficients[0]);
        hash_extension(&mut hasher, coefficients[1]);
    }
    hasher.update(&(context.pow_bits as u32).to_le_bytes());
    hasher.update(&(context.sumcheck_data.pow_witnesses.len() as u32).to_le_bytes());
    for &witness in &context.sumcheck_data.pow_witnesses {
        hasher.update(&witness.as_canonical_u64().to_le_bytes());
    }
    hash_extension(&mut hasher, context.r0);
    hash_extension(&mut hasher, context.r1);
    hash_extension(&mut hasher, context.claimed_sum);
    *hasher.finalize().as_bytes()
}

fn encode_residual_row(eval: EF, weight: EF) -> [u64; WHIR_RESIDUAL_LIMBS_PER_ROW] {
    let eval: &[F] = eval.as_basis_coefficients_slice();
    let weight: &[F] = weight.as_basis_coefficients_slice();
    [
        eval[0].as_canonical_u64(),
        eval[1].as_canonical_u64(),
        eval[2].as_canonical_u64(),
        weight[0].as_canonical_u64(),
        weight[1].as_canonical_u64(),
        weight[2].as_canonical_u64(),
    ]
}

#[cfg(test)]
fn decode_residual_row(row: [u64; WHIR_RESIDUAL_LIMBS_PER_ROW]) -> (EF, EF) {
    (
        EF::new([F::new(row[0]), F::new(row[1]), F::new(row[2])]),
        EF::new([F::new(row[3]), F::new(row[4]), F::new(row[5])]),
    )
}

fn hash_extension(hasher: &mut Hasher, value: EF) {
    let limbs: &[F] = value.as_basis_coefficients_slice();
    for limb in limbs {
        hasher.update(&limb.as_canonical_u64().to_le_bytes());
    }
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
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use cmfd_proof_accel::whir_initial::WhirInitialSourceError;

    use super::*;

    static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone)]
    struct TestSource {
        identity: WhirInitialSourceIdentity,
        values: Vec<u64>,
        reads: Arc<AtomicUsize>,
    }

    impl TestSource {
        fn new(identity: WhirInitialSourceIdentity, values: Vec<u64>) -> Self {
            Self {
                identity,
                values,
                reads: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl AuthenticatedWhirInitialSource for TestSource {
        fn identity(&self) -> &WhirInitialSourceIdentity {
            &self.identity
        }

        fn len(&self) -> usize {
            self.values.len()
        }

        fn read_elements(
            &self,
            start: usize,
            count: usize,
        ) -> Result<Vec<u64>, WhirInitialSourceError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let end = start
                .checked_add(count)
                .ok_or_else(|| WhirInitialSourceError::new("test source range overflow"))?;
            self.values
                .get(start..end)
                .map(<[u64]>::to_vec)
                .ok_or_else(|| WhirInitialSourceError::new("test source range is out of bounds"))
        }
    }

    fn test_scratch(label: &str) -> PathBuf {
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-disk-sumcheck-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn test_points(num_variables: usize) -> Vec<Point<EF>> {
        (0..2)
            .map(|point_index| {
                Point::new(
                    (0..num_variables)
                        .map(|index| {
                            EF::new([
                                F::new((index * 3 + point_index + 2) as u64),
                                F::new((index * 5 + point_index + 3) as u64),
                                F::new((index * 7 + point_index + 5) as u64),
                            ])
                        })
                        .collect(),
                )
            })
            .collect()
    }

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

    #[test]
    fn live_artifact_matches_dense_sumcheck_and_cleans_on_drop() {
        let num_variables = 5;
        let identity = WhirInitialSourceIdentity {
            source_id: [0x51; 32],
            num_variables: num_variables as u32,
        };
        let source = TestSource::new(
            identity,
            (0..1_usize << num_variables)
                .map(|index| (index * index + 7 * index + 19) as u64)
                .collect(),
        );
        let points = test_points(num_variables);
        let claims = evaluate_claims(source.identity(), &source, &points).unwrap();
        let (pcs, mut dense_challenger) =
            super::super::build_pcs(num_variables, b"live-residual-parity").unwrap();
        let (_, mut artifact_challenger) =
            super::super::build_pcs(num_variables, b"live-residual-parity").unwrap();
        for (point, claim) in points.iter().zip(&claims) {
            dense_challenger.observe_algebra_slice(point.as_slice());
            dense_challenger.observe_algebra_element(claim.evaluation());
            artifact_challenger.observe_algebra_slice(point.as_slice());
            artifact_challenger.observe_algebra_element(claim.evaluation());
        }

        let mut dense_data = SumcheckData::default();
        let dense = prepare_sumcheck(
            source.identity(),
            &source,
            claims.clone(),
            &mut dense_data,
            pcs.starting_folding_pow_bits,
            &mut dense_challenger,
        )
        .unwrap();
        let reads_before_artifact = source.reads.load(Ordering::Relaxed);
        let scratch = test_scratch("live-parity");
        let mut artifact_data = SumcheckData::default();
        let artifact = prepare_artifact_sumcheck(
            source.identity(),
            &source,
            claims,
            &mut artifact_data,
            pcs.starting_folding_pow_bits,
            &mut artifact_challenger,
            ResidualArtifactConfig {
                exact_source_binding: [0x62; 32],
                invocation_digest: [0x73; 32],
                scratch_directory: &scratch,
            },
        )
        .unwrap();

        assert_eq!(
            source.reads.load(Ordering::Relaxed),
            reads_before_artifact + 1,
            "artifact preparation must scan the source exactly once"
        );
        assert_eq!(
            artifact_data.polynomial_evaluations,
            dense_data.polynomial_evaluations
        );
        assert_eq!(artifact_data.pow_witnesses, dense_data.pow_witnesses);
        assert_eq!(artifact.randomness, dense.randomness);
        assert_eq!(artifact.claimed_sum, dense.prover.claimed_sum());
        assert_eq!(artifact.artifact.identity().spec.source_digest, [0x62; 32]);
        assert_eq!(
            artifact.artifact.identity().spec.num_variables,
            (num_variables - INITIAL_FOLDING) as u32
        );
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);

        let rows = artifact
            .artifact
            .read_rows(
                0,
                usize::try_from(artifact.artifact.geometry().row_count).unwrap(),
            )
            .unwrap();
        let (evals, weights): (Vec<_>, Vec<_>) = rows.into_iter().map(decode_residual_row).unzip();
        assert_eq!(evals.as_slice(), dense.prover.evals().as_slice());
        assert_eq!(weights.as_slice(), dense.prover.weights().as_slice());
        assert_eq!(
            evals
                .iter()
                .zip(&weights)
                .fold(EF::ZERO, |sum, (&eval, &weight)| sum + eval * weight),
            artifact.claimed_sum
        );
        let dense_next: EF = dense_challenger.sample_algebra_element();
        let artifact_next: EF = artifact_challenger.sample_algebra_element();
        assert_eq!(artifact_next, dense_next);

        drop(artifact);
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        std::fs::remove_dir(scratch).unwrap();
    }

    #[test]
    fn residual_sum_mismatch_aborts_before_publication_and_cleans_partial() {
        let num_variables = 4;
        let identity = WhirInitialSourceIdentity {
            source_id: [0x84; 32],
            num_variables: num_variables as u32,
        };
        let claimed_source = TestSource::new(
            identity.clone(),
            (0..1_usize << num_variables)
                .map(|index| (index * index + 11) as u64)
                .collect(),
        );
        let changed_source = TestSource::new(
            identity,
            (0..1_usize << num_variables)
                .map(|index| (index * index + 3 * index + 101) as u64)
                .collect(),
        );
        let points = test_points(num_variables);
        let claims = evaluate_claims(claimed_source.identity(), &claimed_source, &points).unwrap();
        let (pcs, mut challenger) =
            super::super::build_pcs(num_variables, b"residual-sum-mismatch").unwrap();
        for (point, claim) in points.iter().zip(&claims) {
            challenger.observe_algebra_slice(point.as_slice());
            challenger.observe_algebra_element(claim.evaluation());
        }
        let scratch = test_scratch("sum-mismatch");
        let mut sumcheck_data = SumcheckData::default();

        let result = prepare_artifact_sumcheck(
            changed_source.identity(),
            &changed_source,
            claims,
            &mut sumcheck_data,
            pcs.starting_folding_pow_bits,
            &mut challenger,
            ResidualArtifactConfig {
                exact_source_binding: [0x95; 32],
                invocation_digest: [0xa6; 32],
                scratch_directory: &scratch,
            },
        );

        assert_eq!(result.unwrap_err(), ExplicitWhirError::ProverStorage);
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        std::fs::remove_dir(scratch).unwrap();
    }
}
