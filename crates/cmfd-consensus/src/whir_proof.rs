//! Research-only WHIR polynomial-opening prototype.
//!
//! This module is deliberately feature-gated and bounded. It authenticates
//! evaluations at caller-supplied multilinear points; it is not wired into
//! block validation and does not activate the production ForgeMatrix profile.

use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_blake3::Blake3;
use p3_challenger::{
    CanObserve, FieldChallenger, GrindingChallenger, HashChallenger, SerializingChallenger64,
};
use p3_commit::Mmcs;
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::extension::CubicTrinomialExtensionField;
use p3_field::integers::QuotientMap;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::DenseMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::SumcheckData;
use p3_sumcheck::constraints::Constraint;
use p3_sumcheck::constraints::statement::EqStatement;
use p3_sumcheck::layout::{Layout, LayoutStrategy, Table, Witness};
use p3_sumcheck::product_polynomial::ProductPolynomial;
use p3_sumcheck::strategy::{SumcheckProver, VariableOrder};
use p3_symmetric::{CompressionFunctionFromHasher, MerkleCap, SerializingHasher};
use p3_whir::fiat_shamir::domain_separator::DomainSeparator;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir::pcs::proof::{WhirProof, WhirRoundProof};
use p3_whir::pcs::prover::WhirProver;
use p3_whir::pcs::verifier::WhirVerifier;
use thiserror::Error;

use crate::{ExtensionElement, GOLDILOCKS_MODULUS};

pub const EXPLICIT_WHIR_VERSION: u32 = 1;
pub const EXPLICIT_WHIR_SECURITY_BITS: usize = 128;
pub const MAX_EXPLICIT_WHIR_VARIABLES: usize = 16;
pub const MAX_EXPLICIT_WHIR_OPENINGS: usize = 64;
pub const MAX_EXPLICIT_WHIR_PROOF_BYTES: usize = 1_048_576;
pub const MAX_EXPLICIT_WHIR_BINDING_BYTES: usize = 4_096;

const EXPLICIT_WHIR_MAGIC: &[u8; 8] = b"CMFDWHR1";
const EXPLICIT_WHIR_MIN_VARIABLES: usize = 2;
const EXPLICIT_WHIR_FOLDING: usize = 2;
const EXPLICIT_WHIR_STARTING_LOG_INV_RATE: usize = 1;
const EXPLICIT_WHIR_POW_BITS: usize = 0;
const EXPLICIT_WHIR_HEADER_BYTES: usize = 20;

type F = Goldilocks;
type EF = CubicTrinomialExtensionField<F>;
type FieldHash = SerializingHasher<Blake3>;
type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
type WhirMmcs = MerkleTreeMmcs<F, u8, FieldHash, Compress, 2, 32>;
type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3, 32>>;
type Dft = Radix2DFTSmallBatch<F>;
type Pcs = WhirProver<EF, F, Dft, WhirMmcs, Challenger, ExplicitPointLayout>;
type NativeProof = WhirProof<F, EF, WhirMmcs>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplicitWhirCommitment(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitWhirOpening {
    pub point: Vec<ExtensionElement>,
    pub evaluation: ExtensionElement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitWhirProof {
    pub protocol_version: u32,
    pub num_variables: u32,
    pub proof_bytes: Vec<u8>,
}

impl ExplicitWhirProof {
    pub fn encode(&self) -> Result<Vec<u8>, ExplicitWhirError> {
        validate_num_variables(self.num_variables as usize)?;
        if self.protocol_version != EXPLICIT_WHIR_VERSION {
            return Err(ExplicitWhirError::UnsupportedVersion);
        }
        if self.proof_bytes.len() > MAX_EXPLICIT_WHIR_PROOF_BYTES {
            return Err(ExplicitWhirError::ProofTooLarge);
        }
        let proof_len =
            u32::try_from(self.proof_bytes.len()).map_err(|_| ExplicitWhirError::ProofTooLarge)?;
        let mut encoded = Vec::with_capacity(EXPLICIT_WHIR_HEADER_BYTES + self.proof_bytes.len());
        encoded.extend_from_slice(EXPLICIT_WHIR_MAGIC);
        encoded.extend_from_slice(&self.protocol_version.to_le_bytes());
        encoded.extend_from_slice(&self.num_variables.to_le_bytes());
        encoded.extend_from_slice(&proof_len.to_le_bytes());
        encoded.extend_from_slice(&self.proof_bytes);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ExplicitWhirError> {
        if encoded.len() < EXPLICIT_WHIR_HEADER_BYTES
            || encoded.len() > EXPLICIT_WHIR_HEADER_BYTES + MAX_EXPLICIT_WHIR_PROOF_BYTES
        {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        if &encoded[..8] != EXPLICIT_WHIR_MAGIC {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        let protocol_version = read_u32(encoded, 8)?;
        if protocol_version != EXPLICIT_WHIR_VERSION {
            return Err(ExplicitWhirError::UnsupportedVersion);
        }
        let num_variables = read_u32(encoded, 12)?;
        validate_num_variables(num_variables as usize)?;
        let proof_len = read_u32(encoded, 16)? as usize;
        if proof_len > MAX_EXPLICIT_WHIR_PROOF_BYTES
            || encoded.len() != EXPLICIT_WHIR_HEADER_BYTES + proof_len
        {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        Ok(Self {
            protocol_version,
            num_variables,
            proof_bytes: encoded[EXPLICIT_WHIR_HEADER_BYTES..].to_vec(),
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExplicitWhirError {
    #[error("WHIR prototype supports 2..={MAX_EXPLICIT_WHIR_VARIABLES} variables")]
    InvalidVariableCount,
    #[error("WHIR prototype table length must be an exact power of two")]
    InvalidTableLength,
    #[error("WHIR prototype requires 1..={MAX_EXPLICIT_WHIR_OPENINGS} openings")]
    InvalidOpeningCount,
    #[error("WHIR transcript binding exceeds the research byte cap")]
    BindingTooLarge,
    #[error("WHIR opening point dimension does not match the committed table")]
    PointDimensionMismatch,
    #[error("non-canonical Goldilocks field element")]
    NonCanonicalFieldElement,
    #[error("WHIR proof exceeds the research byte cap")]
    ProofTooLarge,
    #[error("unsupported WHIR prototype version")]
    UnsupportedVersion,
    #[error("malformed WHIR proof encoding")]
    InvalidEncoding,
    #[error("WHIR configuration failed: {0}")]
    Configuration(String),
    #[error("WHIR proof serialization failed")]
    Serialization,
    #[error("WHIR proof verification failed")]
    Verification,
    #[error("WHIR backend panicked while handling untrusted proof data")]
    BackendPanic,
}

#[derive(Debug, Clone)]
struct ExplicitPointLayout {
    poly: Poly<F>,
    extension_poly: Poly<EF>,
    folding: usize,
    statement: EqStatement<EF>,
}

impl ExplicitPointLayout {
    fn record_explicit_claim<Ch>(&mut self, point: Point<EF>, evaluation: EF, challenger: &mut Ch)
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        assert_eq!(point.num_variables(), self.poly.num_variables());
        challenger.observe_algebra_slice(point.as_slice());
        challenger.observe_algebra_element(evaluation);
        self.statement.add_evaluated_constraint(point, evaluation);
    }
}

impl Layout<F, EF> for ExplicitPointLayout {
    fn from_witness(witness: Witness<F>) -> Self {
        let poly = witness.poly().clone();
        let extension_poly = extend_poly(&poly);
        let num_variables = poly.num_variables();
        Self {
            poly,
            extension_poly,
            folding: 0,
            statement: EqStatement::initialize(num_variables),
        }
    }

    fn new_witness(tables: Vec<Table<F>>, folding: usize) -> Witness<F> {
        Witness::new(tables, folding)
    }

    fn commit<D, MT, Ch>(
        dft: &D,
        mmcs: &MT,
        challenger: &mut Ch,
        witness: Witness<F>,
        folding: usize,
        starting_log_inv_rate: usize,
    ) -> (Self, MT::Commitment, MT::ProverData<DenseMatrix<F>>)
    where
        D: TwoAdicSubgroupDft<F>,
        MT: Mmcs<F>,
        Ch: CanObserve<MT::Commitment>,
    {
        let poly = witness.poly().clone();
        let extension_poly = extend_poly(&poly);
        let (commitment, prover_data) = p3_sumcheck::commit::commit_base(
            VariableOrder::Suffix,
            dft,
            mmcs,
            challenger,
            &poly,
            folding,
            starting_log_inv_rate,
        );
        let num_variables = poly.num_variables();
        (
            Self {
                poly,
                extension_poly,
                folding,
                statement: EqStatement::initialize(num_variables),
            },
            commitment,
            prover_data,
        )
    }

    fn num_claims(&self) -> usize {
        self.statement.len()
    }

    fn strategy() -> LayoutStrategy {
        LayoutStrategy::new(false, VariableOrder::Suffix)
    }

    fn folding(&self) -> usize {
        self.folding
    }

    fn num_variables(&self) -> usize {
        self.poly.num_variables()
    }

    fn num_variables_table(&self, id: usize) -> usize {
        assert_eq!(id, 0);
        self.poly.num_variables()
    }

    fn eval<Ch>(&mut self, table_idx: usize, polys: &[usize], challenger: &mut Ch) -> Vec<EF>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        assert_eq!(table_idx, 0);
        assert_eq!(polys, [0]);
        let point: Point<EF> = Point::expand_from_univariate(
            challenger.sample_algebra_element(),
            self.poly.num_variables(),
        );
        let evaluation = self.extension_poly.eval_ext::<F>(&point);
        challenger.observe_algebra_element(evaluation);
        self.statement.add_evaluated_constraint(point, evaluation);
        vec![evaluation]
    }

    fn add_virtual_eval<Ch>(&mut self, challenger: &mut Ch) -> EF
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let point: Point<EF> = Point::expand_from_univariate(
            challenger.sample_algebra_element(),
            self.poly.num_variables(),
        );
        let evaluation = self.extension_poly.eval_ext::<F>(&point);
        challenger.observe_algebra_element(evaluation);
        self.statement.add_evaluated_constraint(point, evaluation);
        evaluation
    }

    fn into_sumcheck<Ch>(
        self,
        sumcheck_data: &mut SumcheckData<F, EF>,
        pow_bits: usize,
        challenger: &mut Ch,
    ) -> (SumcheckProver<F, EF>, Point<EF>)
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        assert!(!self.statement.is_empty());
        let alpha = challenger.sample_algebra_element();
        let mut weights = Poly::<EF>::zero(self.poly.num_variables());
        let mut sum = EF::ZERO;
        self.statement
            .combine_hypercube::<F, false>(&mut weights, &mut sum, alpha);
        let product =
            ProductPolynomial::new_unpacked(VariableOrder::Suffix, self.extension_poly, weights);
        let mut prover = SumcheckProver::new(product, sum);
        let randomness = prover.compute_sumcheck_polynomials(
            sumcheck_data,
            challenger,
            self.folding,
            pow_bits,
            None,
        );
        (prover, randomness)
    }
}

pub fn prove_explicit_whir_openings(
    transcript_binding: &[u8],
    table: &[u64],
    points: &[Vec<ExtensionElement>],
) -> Result<
    (
        ExplicitWhirCommitment,
        Vec<ExplicitWhirOpening>,
        ExplicitWhirProof,
    ),
    ExplicitWhirError,
> {
    let num_variables = validate_table(table)?;
    validate_points(points, num_variables)?;
    let native_table = table
        .iter()
        .copied()
        .map(canonical_base)
        .collect::<Result<Vec<_>, _>>()?;
    let native_points = convert_points(points)?;
    let poly = Poly::<F>::new(native_table);
    let extension_poly = extend_poly(&poly);
    let evaluations = native_points
        .iter()
        .map(|point| extension_poly.eval_ext::<F>(point))
        .collect::<Vec<_>>();
    let (pcs, mut challenger) = build_pcs(num_variables, transcript_binding)?;
    let witness =
        ExplicitPointLayout::new_witness(vec![Table::new(vec![poly])], pcs.round_folding_factor(0));
    let (mut layout, commitment, prover_data) = ExplicitPointLayout::commit(
        &pcs.dft,
        &pcs.mmcs,
        &mut challenger,
        witness,
        pcs.round_folding_factor(0),
        pcs.starting_log_inv_rate,
    );

    let mut native_proof = empty_proof(&pcs.config);
    native_proof.initial_ood_answers = (0..pcs.commitment_ood_samples)
        .map(|_| layout.add_virtual_eval(&mut challenger))
        .collect();
    for (point, &evaluation) in native_points.into_iter().zip(&evaluations) {
        layout.record_explicit_claim(point, evaluation, &mut challenger);
    }
    pcs.prove(&mut native_proof, &mut challenger, layout, prover_data);

    let proof_bytes =
        serde_json::to_vec(&native_proof).map_err(|_| ExplicitWhirError::Serialization)?;
    if proof_bytes.len() > MAX_EXPLICIT_WHIR_PROOF_BYTES {
        return Err(ExplicitWhirError::ProofTooLarge);
    }
    let openings = points
        .iter()
        .cloned()
        .zip(evaluations.into_iter().map(external_extension))
        .map(|(point, evaluation)| ExplicitWhirOpening { point, evaluation })
        .collect();
    if commitment.num_roots() != 1 {
        return Err(ExplicitWhirError::Configuration(
            "WHIR commitment cap must contain exactly one root".to_owned(),
        ));
    }
    Ok((
        ExplicitWhirCommitment(commitment.roots()[0]),
        openings,
        ExplicitWhirProof {
            protocol_version: EXPLICIT_WHIR_VERSION,
            num_variables: num_variables as u32,
            proof_bytes,
        },
    ))
}

pub fn verify_explicit_whir_openings(
    transcript_binding: &[u8],
    commitment: ExplicitWhirCommitment,
    openings: &[ExplicitWhirOpening],
    proof: &ExplicitWhirProof,
) -> Result<(), ExplicitWhirError> {
    if proof.protocol_version != EXPLICIT_WHIR_VERSION {
        return Err(ExplicitWhirError::UnsupportedVersion);
    }
    let num_variables = proof.num_variables as usize;
    validate_num_variables(num_variables)?;
    if transcript_binding.len() > MAX_EXPLICIT_WHIR_BINDING_BYTES {
        return Err(ExplicitWhirError::BindingTooLarge);
    }
    if proof.proof_bytes.len() > MAX_EXPLICIT_WHIR_PROOF_BYTES {
        return Err(ExplicitWhirError::ProofTooLarge);
    }
    if openings.is_empty() || openings.len() > MAX_EXPLICIT_WHIR_OPENINGS {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    let native_points = openings
        .iter()
        .map(|opening| {
            if opening.point.len() != num_variables {
                return Err(ExplicitWhirError::PointDimensionMismatch);
            }
            convert_point(&opening.point)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let native_evaluations = openings
        .iter()
        .map(|opening| convert_extension(opening.evaluation))
        .collect::<Result<Vec<_>, _>>()?;

    let native_proof: NativeProof = serde_json::from_slice(&proof.proof_bytes)
        .map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    let canonical_proof_bytes =
        serde_json::to_vec(&native_proof).map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    if canonical_proof_bytes != proof.proof_bytes {
        return Err(ExplicitWhirError::InvalidEncoding);
    }
    catch_unwind(AssertUnwindSafe(|| {
        verify_native(
            transcript_binding,
            commitment.0,
            &native_points,
            &native_evaluations,
            num_variables,
            &native_proof,
        )
    }))
    .map_err(|_| ExplicitWhirError::BackendPanic)?
}

fn verify_native(
    transcript_binding: &[u8],
    commitment: [u8; 32],
    points: &[Point<EF>],
    evaluations: &[EF],
    num_variables: usize,
    proof: &NativeProof,
) -> Result<(), ExplicitWhirError> {
    let (pcs, mut challenger) = build_pcs(num_variables, transcript_binding)?;
    let commitment = MerkleCap::<F, [u8; 32]>::new(vec![commitment]);
    challenger.observe(commitment.clone());
    if proof.initial_ood_answers.len() != pcs.commitment_ood_samples {
        return Err(ExplicitWhirError::Verification);
    }
    let mut statement = EqStatement::initialize(num_variables);
    for &evaluation in &proof.initial_ood_answers {
        let point =
            Point::expand_from_univariate(challenger.sample_algebra_element(), num_variables);
        challenger.observe_algebra_element(evaluation);
        statement.add_evaluated_constraint(point, evaluation);
    }
    for (point, &evaluation) in points.iter().zip(evaluations) {
        challenger.observe_algebra_slice(point.as_slice());
        challenger.observe_algebra_element(evaluation);
        statement.add_evaluated_constraint(point.clone(), evaluation);
    }
    let alpha = challenger.sample_algebra_element();
    let constraint = Constraint::new_eq_only(alpha, statement);
    let mut claimed_evaluation = EF::ZERO;
    constraint.combine_evals(&mut claimed_evaluation);
    WhirVerifier::new(&pcs.config, &pcs.mmcs, VariableOrder::Suffix)
        .verify(
            proof,
            &mut challenger,
            &commitment,
            constraint,
            claimed_evaluation,
        )
        .map_err(|_| ExplicitWhirError::Verification)?;
    Ok(())
}

fn build_pcs(
    num_variables: usize,
    transcript_binding: &[u8],
) -> Result<(Pcs, Challenger), ExplicitWhirError> {
    validate_num_variables(num_variables)?;
    if transcript_binding.len() > MAX_EXPLICIT_WHIR_BINDING_BYTES {
        return Err(ExplicitWhirError::BindingTooLarge);
    }
    let folding_factor = FoldingFactor::Constant(EXPLICIT_WHIR_FOLDING);
    let (num_rounds, _) = folding_factor
        .compute_number_of_rounds(num_variables)
        .map_err(|error| ExplicitWhirError::Configuration(error.to_string()))?;
    let mut round_log_inv_rates = Vec::with_capacity(num_rounds);
    let mut rate = EXPLICIT_WHIR_STARTING_LOG_INV_RATE;
    for round in 0..num_rounds {
        rate += folding_factor.at_round(round) - 1;
        round_log_inv_rates.push(rate);
    }
    let parameters = ProtocolParameters {
        starting_log_inv_rate: EXPLICIT_WHIR_STARTING_LOG_INV_RATE,
        round_log_inv_rates,
        folding_factor,
        soundness_type: SecurityAssumption::UniqueDecoding,
        security_level: EXPLICIT_WHIR_SECURITY_BITS,
        pow_bits: EXPLICIT_WHIR_POW_BITS,
    };
    let config = WhirConfig::<EF, F, Challenger>::new(num_variables, parameters)
        .map_err(|error| ExplicitWhirError::Configuration(error.to_string()))?;
    if !config.check_pow_bits() {
        return Err(ExplicitWhirError::Configuration(
            "derived WHIR grinding exceeds the configured maximum".to_owned(),
        ));
    }
    let field_hash = FieldHash::new(Blake3 {});
    let compress = Compress::new(Blake3 {});
    let mmcs = WhirMmcs::new(field_hash, compress, 0);
    let dft = Dft::new(1 << config.max_fft_size());
    let pcs = Pcs::new(config, dft, mmcs);
    let mut initial_state = b"CMFD/FORGEMATRIX/EXPLICIT-WHIR/V1".to_vec();
    initial_state.extend_from_slice(&(transcript_binding.len() as u64).to_le_bytes());
    initial_state.extend_from_slice(transcript_binding);
    let mut challenger = Challenger::new(HashChallenger::new(initial_state, Blake3 {}));
    let mut domain_separator = DomainSeparator::new(vec![]);
    pcs.add_domain_separator::<32>(&mut domain_separator);
    domain_separator.observe_domain_separator(&mut challenger);
    Ok((pcs, challenger))
}

fn empty_proof(config: &WhirConfig<EF, F, Challenger>) -> NativeProof {
    NativeProof {
        initial_ood_answers: Vec::new(),
        initial_sumcheck: SumcheckData::default(),
        rounds: (0..config.n_rounds())
            .map(|_| WhirRoundProof::default())
            .collect(),
        final_poly: None,
        final_pow_witness: F::ZERO,
        final_queries: Vec::with_capacity(config.final_queries),
        final_sumcheck: None,
    }
}

fn validate_table(table: &[u64]) -> Result<usize, ExplicitWhirError> {
    if !table.len().is_power_of_two() {
        return Err(ExplicitWhirError::InvalidTableLength);
    }
    let num_variables = table.len().ilog2() as usize;
    validate_num_variables(num_variables)?;
    Ok(num_variables)
}

fn validate_num_variables(num_variables: usize) -> Result<(), ExplicitWhirError> {
    if !(EXPLICIT_WHIR_MIN_VARIABLES..=MAX_EXPLICIT_WHIR_VARIABLES).contains(&num_variables) {
        return Err(ExplicitWhirError::InvalidVariableCount);
    }
    Ok(())
}

fn validate_points(
    points: &[Vec<ExtensionElement>],
    num_variables: usize,
) -> Result<(), ExplicitWhirError> {
    if points.is_empty() || points.len() > MAX_EXPLICIT_WHIR_OPENINGS {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    if points.iter().any(|point| point.len() != num_variables) {
        return Err(ExplicitWhirError::PointDimensionMismatch);
    }
    Ok(())
}

fn canonical_base(value: u64) -> Result<F, ExplicitWhirError> {
    if value >= GOLDILOCKS_MODULUS {
        return Err(ExplicitWhirError::NonCanonicalFieldElement);
    }
    F::from_canonical_checked(value).ok_or(ExplicitWhirError::NonCanonicalFieldElement)
}

fn convert_extension(value: ExtensionElement) -> Result<EF, ExplicitWhirError> {
    Ok(EF::new([
        canonical_base(value.limbs[0])?,
        canonical_base(value.limbs[1])?,
        canonical_base(value.limbs[2])?,
    ]))
}

fn external_extension(value: EF) -> ExtensionElement {
    let limbs: &[F] = value.as_basis_coefficients_slice();
    ExtensionElement {
        limbs: [
            limbs[0].as_canonical_u64(),
            limbs[1].as_canonical_u64(),
            limbs[2].as_canonical_u64(),
        ],
    }
}

fn convert_point(point: &[ExtensionElement]) -> Result<Point<EF>, ExplicitWhirError> {
    Ok(Point::new(
        point
            .iter()
            .copied()
            .map(convert_extension)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

fn convert_points(points: &[Vec<ExtensionElement>]) -> Result<Vec<Point<EF>>, ExplicitWhirError> {
    points.iter().map(|point| convert_point(point)).collect()
}

fn extend_poly(poly: &Poly<F>) -> Poly<EF> {
    Poly::new(poly.as_slice().iter().copied().map(EF::from).collect())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ExplicitWhirError> {
    let encoded = bytes
        .get(offset..offset + 4)
        .ok_or(ExplicitWhirError::InvalidEncoding)?;
    Ok(u32::from_le_bytes(
        encoded
            .try_into()
            .map_err(|_| ExplicitWhirError::InvalidEncoding)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Vec<u64> {
        (0..256).map(|index| (index * index + 17) as u64).collect()
    }

    fn points() -> Vec<Vec<ExtensionElement>> {
        vec![
            (0..8)
                .map(|index| ExtensionElement {
                    limbs: [
                        (index * 7 + 3) as u64,
                        (index * 11 + 5) as u64,
                        (index * 13 + 9) as u64,
                    ],
                })
                .collect(),
            (0..8)
                .map(|index| ExtensionElement {
                    limbs: [
                        (index * 17 + 2) as u64,
                        (index * 19 + 4) as u64,
                        (index * 23 + 6) as u64,
                    ],
                })
                .collect(),
        ]
    }

    fn fixture() -> (
        Vec<u8>,
        ExplicitWhirCommitment,
        Vec<ExplicitWhirOpening>,
        ExplicitWhirProof,
    ) {
        let binding = b"forge-matrix-test-binding".to_vec();
        let (commitment, openings, proof) =
            prove_explicit_whir_openings(&binding, &table(), &points()).unwrap();
        (binding, commitment, openings, proof)
    }

    #[test]
    fn explicit_arbitrary_points_round_trip() {
        let (binding, commitment, openings, proof) = fixture();
        verify_explicit_whir_openings(&binding, commitment, &openings, &proof).unwrap();
        assert_eq!(proof.num_variables, 8);
        assert!(proof.proof_bytes.len() <= MAX_EXPLICIT_WHIR_PROOF_BYTES);
    }

    #[test]
    fn envelope_round_trip_and_rejects_trailing_bytes() {
        let (binding, commitment, openings, proof) = fixture();
        let encoded = proof.encode().unwrap();
        assert_eq!(ExplicitWhirProof::decode(&encoded).unwrap(), proof);

        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            ExplicitWhirProof::decode(&wrong_magic),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut wrong_version = encoded.clone();
        wrong_version[8..12].copy_from_slice(&(EXPLICIT_WHIR_VERSION + 1).to_le_bytes());
        assert_eq!(
            ExplicitWhirProof::decode(&wrong_version),
            Err(ExplicitWhirError::UnsupportedVersion)
        );

        let mut wrong_length = encoded.clone();
        let claimed_length = u32::from_le_bytes(wrong_length[16..20].try_into().unwrap());
        wrong_length[16..20].copy_from_slice(&(claimed_length + 1).to_le_bytes());
        assert_eq!(
            ExplicitWhirProof::decode(&wrong_length),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            ExplicitWhirProof::decode(&trailing),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut noncanonical_payload = proof.clone();
        noncanonical_payload.proof_bytes.push(b' ');
        assert_eq!(
            verify_explicit_whir_openings(&binding, commitment, &openings, &noncanonical_payload,),
            Err(ExplicitWhirError::InvalidEncoding)
        );
    }

    #[test]
    fn mutations_fail_closed() {
        let (binding, commitment, openings, proof) = fixture();

        let mut wrong_binding = binding.clone();
        wrong_binding[0] ^= 1;
        assert!(
            verify_explicit_whir_openings(&wrong_binding, commitment, &openings, &proof).is_err()
        );

        let mut wrong_commitment = commitment;
        wrong_commitment.0[0] ^= 1;
        assert!(
            verify_explicit_whir_openings(&binding, wrong_commitment, &openings, &proof).is_err()
        );

        let mut wrong_point = openings.clone();
        wrong_point[0].point[0].limbs[0] += 1;
        assert!(verify_explicit_whir_openings(&binding, commitment, &wrong_point, &proof).is_err());

        let mut wrong_evaluation = openings.clone();
        wrong_evaluation[0].evaluation.limbs[0] += 1;
        assert!(
            verify_explicit_whir_openings(&binding, commitment, &wrong_evaluation, &proof).is_err()
        );

        let mut wrong_proof = proof.clone();
        let index = wrong_proof.proof_bytes.len() / 2;
        wrong_proof.proof_bytes[index] ^= 1;
        assert!(
            verify_explicit_whir_openings(&binding, commitment, &openings, &wrong_proof).is_err()
        );
    }

    #[test]
    fn rejects_noncanonical_public_fields_and_wrong_dimensions() {
        let (_, commitment, mut openings, proof) = fixture();
        openings[0].point[0].limbs[0] = GOLDILOCKS_MODULUS;
        assert_eq!(
            verify_explicit_whir_openings(
                b"forge-matrix-test-binding",
                commitment,
                &openings,
                &proof
            ),
            Err(ExplicitWhirError::NonCanonicalFieldElement)
        );

        let mut bad_points = points();
        bad_points[0].pop();
        assert_eq!(
            prove_explicit_whir_openings(b"binding", &table(), &bad_points),
            Err(ExplicitWhirError::PointDimensionMismatch)
        );

        assert_eq!(
            prove_explicit_whir_openings(
                &vec![0; MAX_EXPLICIT_WHIR_BINDING_BYTES + 1],
                &table(),
                &points(),
            ),
            Err(ExplicitWhirError::BindingTooLarge)
        );
    }

    #[test]
    fn minimum_table_round_trip_and_limits_fail_closed() {
        let point = vec![
            ExtensionElement { limbs: [3, 5, 7] },
            ExtensionElement {
                limbs: [11, 13, 17],
            },
        ];
        let (commitment, openings, proof) =
            prove_explicit_whir_openings(b"minimum", &[1, 2, 3, 4], &[point]).unwrap();
        verify_explicit_whir_openings(b"minimum", commitment, &openings, &proof).unwrap();

        assert_eq!(
            prove_explicit_whir_openings(b"bad-length", &[1, 2, 3], &points()),
            Err(ExplicitWhirError::InvalidTableLength)
        );
        assert_eq!(
            prove_explicit_whir_openings(
                b"too-small",
                &[1, 2],
                &[vec![ExtensionElement { limbs: [0; 3] }]],
            ),
            Err(ExplicitWhirError::InvalidVariableCount)
        );
        assert_eq!(
            prove_explicit_whir_openings(
                b"noncanonical",
                &[GOLDILOCKS_MODULUS, 2, 3, 4],
                &[vec![ExtensionElement { limbs: [0; 3] }; 2]],
            ),
            Err(ExplicitWhirError::NonCanonicalFieldElement)
        );
        assert_eq!(
            verify_explicit_whir_openings(b"minimum", commitment, &[], &proof),
            Err(ExplicitWhirError::InvalidOpeningCount)
        );
        assert_eq!(
            verify_explicit_whir_openings(
                &vec![0; MAX_EXPLICIT_WHIR_BINDING_BYTES + 1],
                commitment,
                &openings,
                &proof,
            ),
            Err(ExplicitWhirError::BindingTooLarge)
        );
    }
}
