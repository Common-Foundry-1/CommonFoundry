//! Research-only WHIR polynomial-opening prototype.
//!
//! This module is deliberately feature-gated and bounded. It authenticates
//! evaluations at caller-supplied multilinear points and can batch every
//! structured ForgeMatrix oracle under one Merkle root. It is not wired into
//! block validation and does not activate the production ForgeMatrix profile.

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
};

use blake3::Hasher as Blake3Hasher;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
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

use crate::{
    ExtensionElement, GOLDILOCKS_MODULUS, StructuredPcsOpeningClaim, StructuredPcsVerifier,
};

pub const EXPLICIT_WHIR_VERSION: u32 = 1;
pub const EXPLICIT_WHIR_SECURITY_BITS: usize = 128;
pub const MAX_EXPLICIT_WHIR_VARIABLES: usize = 16;
pub const MAX_EXPLICIT_WHIR_OPENINGS: usize = 64;
pub const MAX_EXPLICIT_WHIR_PROOF_BYTES: usize = 1_048_576;
pub const MAX_EXPLICIT_WHIR_BINDING_BYTES: usize = 4_096;
pub const MAX_STRUCTURED_WHIR_TABLES: usize = 256;
pub const MAX_STRUCTURED_WHIR_ELEMENTS: usize = 1 << 20;
const MAX_STRUCTURED_WHIR_STACKED_VARIABLES: usize = 20;

const EXPLICIT_WHIR_MAGIC: &[u8; 8] = b"CMFDWHR1";
const STRUCTURED_WHIR_MAGIC: &[u8; 8] = b"CMFDWAG1";
const STRUCTURED_WHIR_ALIAS_DOMAIN: &str = "CMFD/FORGEMATRIX/WHIR-ORACLE/V1";
const MAX_STRUCTURED_WHIR_NATIVE_JSON_BYTES: usize = 4 * 1024 * 1024;
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

/// Canonical deduplicated oracle tables and their one-root WHIR commitment.
///
/// Per-table aliases bind a component transcript to a table position under
/// the root; they are not independent commitments.
#[derive(Debug, Clone)]
pub struct StructuredWhirCommitmentSet {
    tables: Vec<Vec<u64>>,
    table_variables: Vec<usize>,
    root: [u8; 32],
    aliases: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StructuredWhirAggregateProof {
    root: [u8; 32],
    table_variables: Vec<u32>,
    proof_bytes: Vec<u8>,
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

impl StructuredWhirCommitmentSet {
    pub fn new(mut tables: Vec<Vec<u64>>) -> Result<Self, ExplicitWhirError> {
        if tables.is_empty() || tables.len() > MAX_STRUCTURED_WHIR_TABLES {
            return Err(ExplicitWhirError::InvalidTableCount);
        }
        tables.sort();
        tables.dedup();
        if tables.len() > MAX_STRUCTURED_WHIR_TABLES {
            return Err(ExplicitWhirError::InvalidTableCount);
        }
        let table_variables = tables
            .iter()
            .map(|table| validate_table(table))
            .collect::<Result<Vec<_>, _>>()?;
        let stacked_variables = validate_stacked_shape(&table_variables)?;
        let native_tables = tables
            .iter()
            .map(|table| {
                table
                    .iter()
                    .copied()
                    .map(canonical_base)
                    .collect::<Result<Vec<_>, _>>()
                    .map(Poly::<F>::new)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (pcs, mut challenger) = build_pcs(stacked_variables, b"")?;
        let witness = ExplicitPointLayout::new_witness(
            native_tables
                .into_iter()
                .map(|poly| Table::new(vec![poly]))
                .collect(),
            pcs.round_folding_factor(0),
        );
        let (_, commitment, _) = ExplicitPointLayout::commit(
            &pcs.dft,
            &pcs.mmcs,
            &mut challenger,
            witness,
            pcs.round_folding_factor(0),
            pcs.starting_log_inv_rate,
        );
        if commitment.num_roots() != 1 {
            return Err(ExplicitWhirError::Configuration(
                "WHIR commitment cap must contain exactly one root".to_owned(),
            ));
        }
        let root = commitment.roots()[0];
        let aliases = structured_aliases(root, &table_variables)?;
        Ok(Self {
            tables,
            table_variables,
            root,
            aliases,
        })
    }

    /// Returns the transcript alias for an exact canonical table.
    pub fn commitment_for(&self, table: &[u64]) -> Result<[u8; 32], ExplicitWhirError> {
        let index = self
            .tables
            .binary_search_by(|candidate| candidate.as_slice().cmp(table))
            .map_err(|_| ExplicitWhirError::UnknownCommitment)?;
        Ok(self.aliases[index])
    }

    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn len(&self) -> usize {
        self.tables.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }
}

impl StructuredWhirAggregateProof {
    fn encode(&self) -> Result<Vec<u8>, ExplicitWhirError> {
        if self.table_variables.is_empty()
            || self.table_variables.len() > MAX_STRUCTURED_WHIR_TABLES
            || self.proof_bytes.is_empty()
            || self.proof_bytes.len() > crate::MAX_STRUCTURED_PCS_PROOF_BYTES
        {
            return Err(ExplicitWhirError::AggregateProofTooLarge);
        }
        let count = u32::try_from(self.table_variables.len())
            .map_err(|_| ExplicitWhirError::InvalidTableCount)?;
        let proof_len = u32::try_from(self.proof_bytes.len())
            .map_err(|_| ExplicitWhirError::AggregateProofTooLarge)?;
        let mut encoded =
            Vec::with_capacity(52 + self.table_variables.len() * 4 + self.proof_bytes.len());
        encoded.extend_from_slice(STRUCTURED_WHIR_MAGIC);
        encoded.extend_from_slice(&EXPLICIT_WHIR_VERSION.to_le_bytes());
        encoded.extend_from_slice(&self.root);
        encoded.extend_from_slice(&count.to_le_bytes());
        for variables in &self.table_variables {
            encoded.extend_from_slice(&variables.to_le_bytes());
        }
        encoded.extend_from_slice(&proof_len.to_le_bytes());
        encoded.extend_from_slice(&self.proof_bytes);
        if encoded.len() > crate::MAX_STRUCTURED_PCS_PROOF_BYTES {
            return Err(ExplicitWhirError::AggregateProofTooLarge);
        }
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, ExplicitWhirError> {
        if encoded.len() < 52 || encoded.len() > crate::MAX_STRUCTURED_PCS_PROOF_BYTES {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        if encoded.get(..8) != Some(STRUCTURED_WHIR_MAGIC.as_slice()) {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        if read_u32(encoded, 8)? != EXPLICIT_WHIR_VERSION {
            return Err(ExplicitWhirError::UnsupportedVersion);
        }
        let root: [u8; 32] = encoded
            .get(12..44)
            .ok_or(ExplicitWhirError::InvalidEncoding)?
            .try_into()
            .map_err(|_| ExplicitWhirError::InvalidEncoding)?;
        let count = read_u32(encoded, 44)? as usize;
        if count == 0 || count > MAX_STRUCTURED_WHIR_TABLES {
            return Err(ExplicitWhirError::InvalidTableCount);
        }
        let variables_end = 48usize
            .checked_add(
                count
                    .checked_mul(4)
                    .ok_or(ExplicitWhirError::InvalidEncoding)?,
            )
            .ok_or(ExplicitWhirError::InvalidEncoding)?;
        let mut table_variables = Vec::with_capacity(count);
        for index in 0..count {
            let variables = read_u32(encoded, 48 + index * 4)?;
            validate_num_variables(variables as usize)?;
            table_variables.push(variables);
        }
        validate_stacked_shape(
            &table_variables
                .iter()
                .map(|value| *value as usize)
                .collect::<Vec<_>>(),
        )?;
        let proof_len = read_u32(encoded, variables_end)? as usize;
        let proof_start = variables_end + 4;
        if proof_len == 0
            || proof_len > crate::MAX_STRUCTURED_PCS_PROOF_BYTES
            || proof_start.checked_add(proof_len) != Some(encoded.len())
        {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        Ok(Self {
            root,
            table_variables,
            proof_bytes: encoded[proof_start..].to_vec(),
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StructuredWhirPcsVerifier;

impl StructuredPcsVerifier for StructuredWhirPcsVerifier {
    fn verify_openings(
        &self,
        public_binding: &[u8; 32],
        claims: &[StructuredPcsOpeningClaim],
        proof: &[u8],
    ) -> bool {
        verify_structured_whir_openings(public_binding, claims, proof).is_ok()
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
    #[error("structured WHIR requires 1..={MAX_STRUCTURED_WHIR_TABLES} unique tables")]
    InvalidTableCount,
    #[error("structured WHIR tables exceed the aggregate research element cap")]
    AggregateTableSize,
    #[error("structured WHIR opening references an unknown oracle commitment")]
    UnknownCommitment,
    #[error("structured WHIR oracle commitment does not match its committed table")]
    CommitmentMismatch,
    #[error("structured WHIR claimed evaluation does not match the supplied table")]
    ClaimMismatch,
    #[error("structured WHIR proof exceeds the aggregate PCS byte cap")]
    AggregateProofTooLarge,
}

#[derive(Debug, Clone)]
struct ExplicitPointLayout {
    poly: Poly<F>,
    extension_poly: Poly<EF>,
    folding: usize,
    statement: EqStatement<EF>,
    table_variables: Vec<usize>,
    selectors: Vec<Point<F>>,
}

impl ExplicitPointLayout {
    fn from_poly_and_shapes(poly: Poly<F>, folding: usize, table_variables: Vec<usize>) -> Self {
        let num_variables = poly.num_variables();
        let selectors = plan_selectors(&table_variables, num_variables);
        let extension_poly = extend_poly(&poly);
        Self {
            poly,
            extension_poly,
            folding,
            statement: EqStatement::initialize(num_variables),
            table_variables,
            selectors,
        }
    }

    fn lift_point(&self, table_index: usize, point: &Point<EF>) -> Point<EF> {
        let mut lifted = self.selectors[table_index]
            .as_slice()
            .iter()
            .copied()
            .map(EF::from)
            .collect::<Vec<_>>();
        lifted.extend_from_slice(point.as_slice());
        Point::new(lifted)
    }

    fn record_explicit_claim<Ch>(
        &mut self,
        table_index: usize,
        point: Point<EF>,
        evaluation: EF,
        challenger: &mut Ch,
    ) where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        assert_eq!(point.num_variables(), self.table_variables[table_index]);
        let point = self.lift_point(table_index, &point);
        challenger.observe_algebra_slice(point.as_slice());
        challenger.observe_algebra_element(evaluation);
        self.statement.add_evaluated_constraint(point, evaluation);
    }
}

impl Layout<F, EF> for ExplicitPointLayout {
    fn from_witness(witness: Witness<F>) -> Self {
        let poly = witness.poly().clone();
        let table_variables = witness
            .table_shapes()
            .into_iter()
            .map(|shape| shape.num_variables())
            .collect();
        Self::from_poly_and_shapes(poly, 0, table_variables)
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
        let table_variables = witness
            .table_shapes()
            .into_iter()
            .map(|shape| shape.num_variables())
            .collect();
        let (commitment, prover_data) = p3_sumcheck::commit::commit_base(
            VariableOrder::Suffix,
            dft,
            mmcs,
            challenger,
            &poly,
            folding,
            starting_log_inv_rate,
        );
        (
            Self::from_poly_and_shapes(poly, folding, table_variables),
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
        self.table_variables[id]
    }

    fn eval<Ch>(&mut self, table_idx: usize, polys: &[usize], challenger: &mut Ch) -> Vec<EF>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        assert_eq!(polys, [0]);
        let point: Point<EF> = Point::expand_from_univariate(
            challenger.sample_algebra_element(),
            self.table_variables[table_idx],
        );
        let lifted = self.lift_point(table_idx, &point);
        let evaluation = self.extension_poly.eval_ext::<F>(&lifted);
        challenger.observe_algebra_element(evaluation);
        self.statement.add_evaluated_constraint(lifted, evaluation);
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
        layout.record_explicit_claim(0, point, evaluation, &mut challenger);
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

pub fn prove_structured_whir_openings(
    public_binding: &[u8; 32],
    commitment_set: &StructuredWhirCommitmentSet,
    claims: &[StructuredPcsOpeningClaim],
) -> Result<Vec<u8>, ExplicitWhirError> {
    let claims = crate::structured_proof::canonical_openings(claims.to_vec())
        .map_err(|_| ExplicitWhirError::ClaimMismatch)?;
    if claims.is_empty() || claims.len() > crate::MAX_STRUCTURED_OPENING_CLAIMS {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    let alias_map = commitment_set
        .aliases
        .iter()
        .copied()
        .enumerate()
        .map(|(index, alias)| (alias, index))
        .collect::<BTreeMap<_, _>>();
    if alias_map.len() != commitment_set.aliases.len() {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }
    let mut used_tables = vec![false; commitment_set.tables.len()];
    let stacked_variables = validate_stacked_shape(&commitment_set.table_variables)?;
    let native_tables = commitment_set
        .tables
        .iter()
        .map(|table| {
            table
                .iter()
                .copied()
                .map(canonical_base)
                .collect::<Result<Vec<_>, _>>()
                .map(Poly::<F>::new)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let extension_tables = native_tables.iter().map(extend_poly).collect::<Vec<_>>();
    let (pcs, mut challenger) = build_pcs(stacked_variables, public_binding)?;
    let witness = ExplicitPointLayout::new_witness(
        native_tables
            .into_iter()
            .map(|poly| Table::new(vec![poly]))
            .collect(),
        pcs.round_folding_factor(0),
    );
    let (mut layout, commitment, prover_data) = ExplicitPointLayout::commit(
        &pcs.dft,
        &pcs.mmcs,
        &mut challenger,
        witness,
        pcs.round_folding_factor(0),
        pcs.starting_log_inv_rate,
    );
    if commitment.num_roots() != 1 || commitment.roots()[0] != commitment_set.root {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }

    let mut native_proof = empty_proof(&pcs.config);
    native_proof.initial_ood_answers = (0..pcs.commitment_ood_samples)
        .map(|_| layout.add_virtual_eval(&mut challenger))
        .collect();
    for claim in &claims {
        let table_index = *alias_map
            .get(&claim.commitment)
            .ok_or(ExplicitWhirError::UnknownCommitment)?;
        used_tables[table_index] = true;
        if claim.point.len() != commitment_set.table_variables[table_index] {
            return Err(ExplicitWhirError::PointDimensionMismatch);
        }
        let point = convert_structured_point(&claim.point)?;
        let evaluation = convert_extension(claim.evaluation)?;
        if extension_tables[table_index].eval_ext::<F>(&point) != evaluation {
            return Err(ExplicitWhirError::ClaimMismatch);
        }
        layout.record_explicit_claim(table_index, point, evaluation, &mut challenger);
    }
    if used_tables.iter().any(|used| !used) {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }
    pcs.prove(&mut native_proof, &mut challenger, layout, prover_data);
    let proof_bytes = encode_aggregate_native_proof(&native_proof)?;
    StructuredWhirAggregateProof {
        root: commitment_set.root,
        table_variables: commitment_set
            .table_variables
            .iter()
            .map(|variables| *variables as u32)
            .collect(),
        proof_bytes,
    }
    .encode()
}

pub fn verify_structured_whir_openings(
    public_binding: &[u8; 32],
    claims: &[StructuredPcsOpeningClaim],
    encoded_proof: &[u8],
) -> Result<(), ExplicitWhirError> {
    let aggregate = StructuredWhirAggregateProof::decode(encoded_proof)?;
    let table_variables = aggregate
        .table_variables
        .iter()
        .map(|variables| *variables as usize)
        .collect::<Vec<_>>();
    let aliases = structured_aliases(aggregate.root, &table_variables)?;
    let alias_map = aliases
        .into_iter()
        .enumerate()
        .map(|(index, alias)| (alias, index))
        .collect::<BTreeMap<_, _>>();
    if alias_map.len() != table_variables.len() {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }
    let claims = crate::structured_proof::canonical_openings(claims.to_vec())
        .map_err(|_| ExplicitWhirError::ClaimMismatch)?;
    if claims.is_empty() || claims.len() > crate::MAX_STRUCTURED_OPENING_CLAIMS {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    let mut table_indices = Vec::with_capacity(claims.len());
    let mut used_tables = vec![false; table_variables.len()];
    let mut points = Vec::with_capacity(claims.len());
    let mut evaluations = Vec::with_capacity(claims.len());
    for claim in &claims {
        let table_index = *alias_map
            .get(&claim.commitment)
            .ok_or(ExplicitWhirError::UnknownCommitment)?;
        used_tables[table_index] = true;
        if claim.point.len() != table_variables[table_index] {
            return Err(ExplicitWhirError::PointDimensionMismatch);
        }
        table_indices.push(table_index);
        points.push(convert_structured_point(&claim.point)?);
        evaluations.push(convert_extension(claim.evaluation)?);
    }
    if used_tables.iter().any(|used| !used) {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }
    let native_proof = decode_aggregate_native_proof(&aggregate.proof_bytes)?;
    let canonical = encode_aggregate_native_proof(&native_proof)
        .map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    if canonical != aggregate.proof_bytes {
        return Err(ExplicitWhirError::InvalidEncoding);
    }
    catch_unwind(AssertUnwindSafe(|| {
        verify_native_multi(
            public_binding,
            aggregate.root,
            &table_variables,
            &table_indices,
            &points,
            &evaluations,
            &native_proof,
        )
    }))
    .map_err(|_| ExplicitWhirError::BackendPanic)?
}

fn verify_native_multi(
    transcript_binding: &[u8],
    commitment: [u8; 32],
    table_variables: &[usize],
    table_indices: &[usize],
    points: &[Point<EF>],
    evaluations: &[EF],
    proof: &NativeProof,
) -> Result<(), ExplicitWhirError> {
    let stacked_variables = validate_stacked_shape(table_variables)?;
    let selectors = plan_selectors(table_variables, stacked_variables);
    let (pcs, mut challenger) = build_pcs(stacked_variables, transcript_binding)?;
    let commitment = MerkleCap::<F, [u8; 32]>::new(vec![commitment]);
    challenger.observe(commitment.clone());
    if proof.initial_ood_answers.len() != pcs.commitment_ood_samples {
        return Err(ExplicitWhirError::Verification);
    }
    let mut statement = EqStatement::initialize(stacked_variables);
    for &evaluation in &proof.initial_ood_answers {
        let point =
            Point::expand_from_univariate(challenger.sample_algebra_element(), stacked_variables);
        challenger.observe_algebra_element(evaluation);
        statement.add_evaluated_constraint(point, evaluation);
    }
    for ((&table_index, point), &evaluation) in table_indices.iter().zip(points).zip(evaluations) {
        let mut lifted = selectors[table_index]
            .as_slice()
            .iter()
            .copied()
            .map(EF::from)
            .collect::<Vec<_>>();
        lifted.extend_from_slice(point.as_slice());
        let lifted = Point::new(lifted);
        challenger.observe_algebra_slice(lifted.as_slice());
        challenger.observe_algebra_element(evaluation);
        statement.add_evaluated_constraint(lifted, evaluation);
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
        .map(|_| ())
        .map_err(|_| ExplicitWhirError::Verification)
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
    if !(EXPLICIT_WHIR_MIN_VARIABLES..=MAX_STRUCTURED_WHIR_STACKED_VARIABLES)
        .contains(&num_variables)
    {
        return Err(ExplicitWhirError::InvalidVariableCount);
    }
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

fn encode_aggregate_native_proof(proof: &NativeProof) -> Result<Vec<u8>, ExplicitWhirError> {
    let canonical_json = serde_json::to_vec(proof).map_err(|_| ExplicitWhirError::Serialization)?;
    if canonical_json.len() > MAX_STRUCTURED_WHIR_NATIVE_JSON_BYTES {
        return Err(ExplicitWhirError::AggregateProofTooLarge);
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(&canonical_json)
        .map_err(|_| ExplicitWhirError::Serialization)?;
    encoder
        .finish()
        .map_err(|_| ExplicitWhirError::Serialization)
}

fn decode_aggregate_native_proof(encoded: &[u8]) -> Result<NativeProof, ExplicitWhirError> {
    let decoder = ZlibDecoder::new(encoded);
    let mut limited = decoder.take((MAX_STRUCTURED_WHIR_NATIVE_JSON_BYTES + 1) as u64);
    let mut canonical_json = Vec::new();
    limited
        .read_to_end(&mut canonical_json)
        .map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    let decoder = limited.into_inner();
    if canonical_json.len() > MAX_STRUCTURED_WHIR_NATIVE_JSON_BYTES
        || decoder.total_in() != encoded.len() as u64
    {
        return Err(ExplicitWhirError::InvalidEncoding);
    }
    let proof =
        serde_json::from_slice(&canonical_json).map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    let reencoded = serde_json::to_vec(&proof).map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    if reencoded != canonical_json {
        return Err(ExplicitWhirError::InvalidEncoding);
    }
    Ok(proof)
}

fn validate_table(table: &[u64]) -> Result<usize, ExplicitWhirError> {
    if !table.len().is_power_of_two() {
        return Err(ExplicitWhirError::InvalidTableLength);
    }
    let num_variables = table.len().ilog2() as usize;
    validate_num_variables(num_variables)?;
    Ok(num_variables)
}

fn validate_stacked_shape(table_variables: &[usize]) -> Result<usize, ExplicitWhirError> {
    if table_variables.is_empty() || table_variables.len() > MAX_STRUCTURED_WHIR_TABLES {
        return Err(ExplicitWhirError::InvalidTableCount);
    }
    let mut elements = 0usize;
    for &variables in table_variables {
        validate_num_variables(variables)?;
        elements = elements
            .checked_add(
                1usize
                    .checked_shl(variables as u32)
                    .ok_or(ExplicitWhirError::AggregateTableSize)?,
            )
            .ok_or(ExplicitWhirError::AggregateTableSize)?;
    }
    if elements > MAX_STRUCTURED_WHIR_ELEMENTS {
        return Err(ExplicitWhirError::AggregateTableSize);
    }
    let padded = elements
        .checked_next_power_of_two()
        .ok_or(ExplicitWhirError::AggregateTableSize)?;
    let variables = padded.ilog2() as usize;
    if variables > MAX_STRUCTURED_WHIR_STACKED_VARIABLES {
        return Err(ExplicitWhirError::AggregateTableSize);
    }
    Ok(variables)
}

fn plan_selectors(table_variables: &[usize], stacked_variables: usize) -> Vec<Point<F>> {
    let mut order = (0..table_variables.len()).collect::<Vec<_>>();
    order.sort_by_key(|&index| table_variables[index]);
    let mut offset = 0usize;
    let mut selectors = vec![Point::new(Vec::new()); table_variables.len()];
    for table_index in order.into_iter().rev() {
        let variables = table_variables[table_index];
        let selector_variables = stacked_variables - variables;
        selectors[table_index] = Point::hypercube(offset >> variables, selector_variables);
        offset += 1usize << variables;
    }
    selectors
}

fn structured_aliases(
    root: [u8; 32],
    table_variables: &[usize],
) -> Result<Vec<[u8; 32]>, ExplicitWhirError> {
    validate_stacked_shape(table_variables)?;
    let mut layout_hasher = Blake3Hasher::new_derive_key(STRUCTURED_WHIR_ALIAS_DOMAIN);
    layout_hasher.update(b"layout");
    layout_hasher.update(&root);
    layout_hasher.update(&(table_variables.len() as u32).to_le_bytes());
    for &variables in table_variables {
        layout_hasher.update(&(variables as u32).to_le_bytes());
    }
    let layout_digest = *layout_hasher.finalize().as_bytes();
    Ok(table_variables
        .iter()
        .enumerate()
        .map(|(index, variables)| {
            let mut hasher = Blake3Hasher::new_derive_key(STRUCTURED_WHIR_ALIAS_DOMAIN);
            hasher.update(b"oracle");
            hasher.update(&root);
            hasher.update(&layout_digest);
            hasher.update(&(index as u32).to_le_bytes());
            hasher.update(&(*variables as u32).to_le_bytes());
            *hasher.finalize().as_bytes()
        })
        .collect())
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

fn convert_structured_point(point: &[ExtensionElement]) -> Result<Point<EF>, ExplicitWhirError> {
    let mut point = convert_point(point)?.as_slice().to_vec();
    point.reverse();
    Ok(Point::new(point))
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

    #[test]
    fn structured_multi_table_opening_is_batched_and_every_table_is_required() {
        let first = vec![3, 5, 7, 11];
        let second = vec![13, 17, 19, 23, 29, 31, 37, 41];
        let set =
            StructuredWhirCommitmentSet::new(vec![second.clone(), first.clone(), first.clone()])
                .unwrap();
        assert_eq!(set.len(), 2);
        let claims = vec![
            StructuredPcsOpeningClaim {
                commitment: set.commitment_for(&first).unwrap(),
                point: vec![ExtensionElement { limbs: [0; 3] }; 2],
                evaluation: ExtensionElement {
                    limbs: [first[0], 0, 0],
                },
            },
            StructuredPcsOpeningClaim {
                commitment: set.commitment_for(&second).unwrap(),
                point: vec![ExtensionElement { limbs: [0; 3] }; 3],
                evaluation: ExtensionElement {
                    limbs: [second[0], 0, 0],
                },
            },
        ];
        let binding = [0x42; 32];
        let proof = prove_structured_whir_openings(&binding, &set, &claims).unwrap();
        verify_structured_whir_openings(&binding, &claims, &proof).unwrap();

        let mut wrong_binding = binding;
        wrong_binding[0] ^= 1;
        assert!(verify_structured_whir_openings(&wrong_binding, &claims, &proof).is_err());

        let mut wrong_root = proof.clone();
        wrong_root[12] ^= 1;
        assert_eq!(
            verify_structured_whir_openings(&binding, &claims, &wrong_root),
            Err(ExplicitWhirError::UnknownCommitment)
        );

        let mut trailing_stream = StructuredWhirAggregateProof::decode(&proof).unwrap();
        trailing_stream.proof_bytes.push(0);
        let trailing_stream = trailing_stream.encode().unwrap();
        assert_eq!(
            verify_structured_whir_openings(&binding, &claims, &trailing_stream),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let unused =
            StructuredWhirCommitmentSet::new(vec![first, second, vec![43, 47, 53, 59]]).unwrap();
        let partial_claims = vec![StructuredPcsOpeningClaim {
            commitment: unused.commitment_for(&[3, 5, 7, 11]).unwrap(),
            point: vec![ExtensionElement { limbs: [0; 3] }; 2],
            evaluation: ExtensionElement { limbs: [3, 0, 0] },
        }];
        assert_eq!(
            prove_structured_whir_openings(&binding, &unused, &partial_claims),
            Err(ExplicitWhirError::CommitmentMismatch)
        );
    }
}
