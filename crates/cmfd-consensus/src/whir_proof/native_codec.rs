//! Canonical fixed-width encoding for the native WHIR proof.
//!
//! The grammar is deliberately not self-describing. Every vector length,
//! query variant, and optional field is derived from the trusted
//! [`WhirConfig`]. The only variable-size portions are the authenticated path
//! node dictionary and its fixed-width `u16` references. Dictionary order is
//! pinned to first use so one native proof has exactly one binary encoding.

use std::collections::{BTreeMap, BTreeSet};

use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::SumcheckData;
use p3_symmetric::MerkleCap;
use p3_whir::{
    parameters::WhirConfig,
    pcs::proof::{QueryOpening, WhirProof, WhirRoundProof},
};
use thiserror::Error;

use super::{
    Challenger, EF, EXPLICIT_WHIR_VERSION, F, MAX_EXPLICIT_WHIR_PROOF_BYTES,
    MAX_STRUCTURED_WHIR_STACKED_VARIABLES, NativeProof,
};
use crate::GOLDILOCKS_MODULUS;

pub(super) const NATIVE_PROOF_CODEC_MAGIC: &[u8; 8] = b"CMFDWHB2";
pub(super) const NATIVE_PROOF_CODEC_VERSION: u32 = 2;
pub(super) const NATIVE_PROOF_CODEC_HEADER_BYTES: usize = 40;

pub(super) const NATIVE_PROOF_CODEC_FLAGS: u32 = 0;
const BASE_BYTES: usize = 8;
const EXTENSION_LIMBS: usize = 3;
const EXTENSION_BYTES: usize = BASE_BYTES * EXTENSION_LIMBS;
const DIGEST_BYTES: usize = 32;
pub(super) const NATIVE_PROOF_CODEC_REFERENCE_BYTES: usize = 2;
pub(super) const NATIVE_PROOF_CODEC_MAX_DICTIONARY_NODES: usize = u16::MAX as usize + 1;
const REFERENCE_BYTES: usize = NATIVE_PROOF_CODEC_REFERENCE_BYTES;
const MAX_DICTIONARY_NODES: usize = NATIVE_PROOF_CODEC_MAX_DICTIONARY_NODES;

type NativeQuery = QueryOpening<F, EF, Vec<[u8; DIGEST_BYTES]>>;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeProofCodecError {
    #[error("native WHIR proof configuration is not encodable")]
    Configuration,
    #[error("native WHIR proof does not have the configured canonical shape")]
    Shape,
    #[error("native WHIR proof encoding exceeds its fixed bound")]
    TooLarge,
    #[error("native WHIR proof header or byte layout is invalid")]
    InvalidEncoding,
    #[error("native WHIR proof codec or protocol version is unsupported")]
    UnsupportedVersion,
    #[error("native WHIR proof contains a non-canonical field element")]
    NonCanonicalField,
    #[error("native WHIR proof dictionary is non-canonical")]
    NonCanonicalDictionary,
    #[error("native WHIR proof dictionary reference is invalid")]
    InvalidDictionaryReference,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryField {
    Base,
    Extension,
}

#[derive(Clone, Copy, Debug)]
struct QueryShape {
    field: QueryField,
    count: usize,
    width: usize,
    path_len: usize,
}

#[derive(Clone, Copy, Debug)]
struct SumcheckShape {
    rounds: usize,
    has_pow: bool,
}

#[derive(Clone, Debug)]
struct RoundShape {
    ood_answers: usize,
    has_pow: bool,
    queries: QueryShape,
    sumcheck: SumcheckShape,
}

#[derive(Clone, Debug)]
struct ProofShape {
    initial_ood_answers: usize,
    initial_sumcheck: SumcheckShape,
    rounds: Vec<RoundShape>,
    final_poly_len: usize,
    final_has_pow: bool,
    final_queries: QueryShape,
    final_sumcheck: Option<SumcheckShape>,
    body_len: usize,
    reference_count: usize,
}

impl ProofShape {
    fn derive(config: &WhirConfig<EF, F, Challenger>) -> Result<Self, NativeProofCodecError> {
        if config.num_variables == 0
            || config.num_variables > MAX_STRUCTURED_WHIR_STACKED_VARIABLES
            || config.n_rounds() > config.num_variables
        {
            return Err(NativeProofCodecError::Configuration);
        }

        let initial_sumcheck = SumcheckShape {
            rounds: config.round_folding_factor(0),
            has_pow: config.starting_folding_pow_bits > 0,
        };
        let mut rounds = Vec::new();
        rounds
            .try_reserve_exact(config.n_rounds())
            .map_err(|_| NativeProofCodecError::Configuration)?;
        for (round_index, params) in config.round_parameters.iter().enumerate() {
            rounds.push(RoundShape {
                ood_answers: params.ood_samples,
                has_pow: params.pow_bits > 0,
                queries: derive_query_shape(
                    if round_index == 0 {
                        QueryField::Base
                    } else {
                        QueryField::Extension
                    },
                    params.domain_size,
                    params.folding_factor,
                    params.num_queries,
                )?,
                sumcheck: SumcheckShape {
                    rounds: config.round_folding_factor(round_index + 1),
                    has_pow: params.folding_pow_bits > 0,
                },
            });
        }

        let final_config = config.final_round_config();
        let final_poly_len = checked_pow2(final_config.num_variables)?;
        let final_queries = derive_query_shape(
            if config.n_rounds() == 0 {
                QueryField::Base
            } else {
                QueryField::Extension
            },
            final_config.domain_size,
            final_config.folding_factor,
            config.final_queries,
        )?;
        let final_sumcheck = (config.final_sumcheck_rounds > 0).then_some(SumcheckShape {
            rounds: config.final_sumcheck_rounds,
            has_pow: config.final_folding_pow_bits > 0,
        });

        let mut shape = Self {
            initial_ood_answers: config.commitment_ood_samples,
            initial_sumcheck,
            rounds,
            final_poly_len,
            final_has_pow: config.final_pow_bits > 0,
            final_queries,
            final_sumcheck,
            body_len: 0,
            reference_count: 0,
        };
        shape.body_len = shape.compute_body_len()?;
        shape.reference_count = shape.compute_reference_count()?;
        let minimum_encoded_len = NATIVE_PROOF_CODEC_HEADER_BYTES
            .checked_add(shape.body_len)
            .and_then(|value| {
                shape
                    .reference_count
                    .checked_mul(REFERENCE_BYTES)
                    .and_then(|references| value.checked_add(references))
            })
            .ok_or(NativeProofCodecError::Configuration)?;
        if shape.body_len > MAX_EXPLICIT_WHIR_PROOF_BYTES
            || shape.reference_count > u32::MAX as usize
            || minimum_encoded_len > MAX_EXPLICIT_WHIR_PROOF_BYTES
        {
            return Err(NativeProofCodecError::Configuration);
        }
        Ok(shape)
    }

    fn compute_body_len(&self) -> Result<usize, NativeProofCodecError> {
        let mut bytes = 0usize;
        add_items(&mut bytes, self.initial_ood_answers, EXTENSION_BYTES)?;
        add_sumcheck_bytes(&mut bytes, self.initial_sumcheck)?;
        for round in &self.rounds {
            add_items(&mut bytes, 1, DIGEST_BYTES)?;
            add_items(&mut bytes, round.ood_answers, EXTENSION_BYTES)?;
            add_items(&mut bytes, usize::from(round.has_pow), BASE_BYTES)?;
            add_query_value_bytes(&mut bytes, round.queries)?;
            add_sumcheck_bytes(&mut bytes, round.sumcheck)?;
        }
        add_items(&mut bytes, self.final_poly_len, EXTENSION_BYTES)?;
        add_items(&mut bytes, usize::from(self.final_has_pow), BASE_BYTES)?;
        add_query_value_bytes(&mut bytes, self.final_queries)?;
        if let Some(final_sumcheck) = self.final_sumcheck {
            add_sumcheck_bytes(&mut bytes, final_sumcheck)?;
        }
        Ok(bytes)
    }

    fn compute_reference_count(&self) -> Result<usize, NativeProofCodecError> {
        let mut references = 0usize;
        for query in self
            .rounds
            .iter()
            .map(|round| round.queries)
            .chain(std::iter::once(self.final_queries))
        {
            let round_references = query
                .count
                .checked_mul(query.path_len)
                .ok_or(NativeProofCodecError::Configuration)?;
            references = references
                .checked_add(round_references)
                .ok_or(NativeProofCodecError::Configuration)?;
        }
        Ok(references)
    }

    fn maximum_dictionary_nodes(&self) -> Result<usize, NativeProofCodecError> {
        let maximum = self
            .rounds
            .iter()
            .map(|round| round.queries)
            .chain(std::iter::once(self.final_queries))
            .try_fold(0usize, |total, query| {
                let mut nodes_at_level = checked_pow2(query.path_len)?;
                let mut phase_nodes = 0usize;
                for _ in 0..query.path_len {
                    phase_nodes = phase_nodes
                        .checked_add(query.count.min(nodes_at_level))
                        .ok_or(NativeProofCodecError::Configuration)?;
                    nodes_at_level /= 2;
                }
                total
                    .checked_add(phase_nodes)
                    .ok_or(NativeProofCodecError::Configuration)
            })?;
        Ok(maximum.min(MAX_DICTIONARY_NODES))
    }

    #[cfg(test)]
    fn encoded_bytes_upper_bound(&self) -> Result<usize, NativeProofCodecError> {
        let dictionary_bytes = self
            .maximum_dictionary_nodes()?
            .checked_mul(DIGEST_BYTES)
            .ok_or(NativeProofCodecError::Configuration)?;
        let reference_bytes = self
            .reference_count
            .checked_mul(REFERENCE_BYTES)
            .ok_or(NativeProofCodecError::Configuration)?;
        NATIVE_PROOF_CODEC_HEADER_BYTES
            .checked_add(self.body_len)
            .and_then(|value| value.checked_add(dictionary_bytes))
            .and_then(|value| value.checked_add(reference_bytes))
            .map(|value| value.min(MAX_EXPLICIT_WHIR_PROOF_BYTES))
            .ok_or(NativeProofCodecError::Configuration)
    }
}

#[cfg(test)]
pub(super) fn encoded_proof_upper_bound(
    config: &WhirConfig<EF, F, Challenger>,
) -> Result<usize, NativeProofCodecError> {
    ProofShape::derive(config)?.encoded_bytes_upper_bound()
}

fn derive_query_shape(
    field: QueryField,
    domain_size: usize,
    folding_factor: usize,
    requested_queries: usize,
) -> Result<QueryShape, NativeProofCodecError> {
    if domain_size == 0 || !domain_size.is_power_of_two() {
        return Err(NativeProofCodecError::Configuration);
    }
    let width = checked_pow2(folding_factor)?;
    let folded_domain = domain_size
        .checked_div(width)
        .filter(|value| *value > 0 && value.is_power_of_two())
        .ok_or(NativeProofCodecError::Configuration)?;
    Ok(QueryShape {
        field,
        count: requested_queries.min(folded_domain),
        width,
        path_len: folded_domain.ilog2() as usize,
    })
}

fn checked_pow2(exponent: usize) -> Result<usize, NativeProofCodecError> {
    let shift = u32::try_from(exponent).map_err(|_| NativeProofCodecError::Configuration)?;
    1usize
        .checked_shl(shift)
        .ok_or(NativeProofCodecError::Configuration)
}

fn add_items(
    total: &mut usize,
    count: usize,
    item_bytes: usize,
) -> Result<(), NativeProofCodecError> {
    let bytes = count
        .checked_mul(item_bytes)
        .ok_or(NativeProofCodecError::Configuration)?;
    *total = total
        .checked_add(bytes)
        .ok_or(NativeProofCodecError::Configuration)?;
    Ok(())
}

fn add_sumcheck_bytes(
    total: &mut usize,
    shape: SumcheckShape,
) -> Result<(), NativeProofCodecError> {
    add_items(total, shape.rounds, 2 * EXTENSION_BYTES)?;
    if shape.has_pow {
        add_items(total, shape.rounds, BASE_BYTES)?;
    }
    Ok(())
}

fn add_query_value_bytes(
    total: &mut usize,
    shape: QueryShape,
) -> Result<(), NativeProofCodecError> {
    let element_bytes = match shape.field {
        QueryField::Base => BASE_BYTES,
        QueryField::Extension => EXTENSION_BYTES,
    };
    let elements = shape
        .count
        .checked_mul(shape.width)
        .ok_or(NativeProofCodecError::Configuration)?;
    add_items(total, elements, element_bytes)
}

/// Encode one native proof under the exact trusted WHIR configuration.
pub(super) fn encode_native_proof<MT>(
    proof: &WhirProof<F, EF, MT>,
    config: &WhirConfig<EF, F, Challenger>,
) -> Result<Vec<u8>, NativeProofCodecError>
where
    MT: Mmcs<F, Commitment = MerkleCap<F, [u8; DIGEST_BYTES]>, Proof = Vec<[u8; DIGEST_BYTES]>>,
{
    let shape = ProofShape::derive(config)?;
    validate_proof_shape(proof, &shape)?;

    let mut body = Vec::new();
    body.try_reserve_exact(shape.body_len)
        .map_err(|_| NativeProofCodecError::TooLarge)?;
    let mut paths = PathEncoder::new(shape.reference_count, shape.maximum_dictionary_nodes()?)?;

    write_extensions(&mut body, &proof.initial_ood_answers);
    write_sumcheck(&mut body, &proof.initial_sumcheck, shape.initial_sumcheck);
    for (round, round_shape) in proof.rounds.iter().zip(&shape.rounds) {
        let commitment = round
            .commitment
            .as_ref()
            .ok_or(NativeProofCodecError::Shape)?;
        body.extend_from_slice(&commitment.roots()[0]);
        write_extensions(&mut body, &round.ood_answers);
        if round_shape.has_pow {
            write_base(&mut body, round.pow_witness);
        }
        write_queries(&mut body, &mut paths, &round.queries, round_shape.queries)?;
        write_sumcheck(&mut body, &round.sumcheck, round_shape.sumcheck);
    }

    let final_poly = proof
        .final_poly
        .as_ref()
        .ok_or(NativeProofCodecError::Shape)?;
    write_extensions(&mut body, final_poly.as_slice());
    if shape.final_has_pow {
        write_base(&mut body, proof.final_pow_witness);
    }
    write_queries(
        &mut body,
        &mut paths,
        &proof.final_queries,
        shape.final_queries,
    )?;
    if let (Some(data), Some(sumcheck_shape)) = (&proof.final_sumcheck, shape.final_sumcheck) {
        write_sumcheck(&mut body, data, sumcheck_shape);
    }

    if body.len() != shape.body_len || paths.references.len() != shape.reference_count {
        return Err(NativeProofCodecError::Shape);
    }
    paths.finish(&body, config.num_variables)
}

/// Decode one native proof without trusting any encoded vector length.
pub(super) fn decode_native_proof(
    encoded: &[u8],
    config: &WhirConfig<EF, F, Challenger>,
) -> Result<NativeProof, NativeProofCodecError> {
    let shape = ProofShape::derive(config)?;
    if encoded.len() < NATIVE_PROOF_CODEC_HEADER_BYTES
        || encoded.len() > MAX_EXPLICIT_WHIR_PROOF_BYTES
    {
        return Err(NativeProofCodecError::InvalidEncoding);
    }
    if &encoded[..8] != NATIVE_PROOF_CODEC_MAGIC {
        return Err(NativeProofCodecError::InvalidEncoding);
    }
    let codec_version = header_u32(encoded, 8)?;
    let header_bytes = header_u32(encoded, 12)?;
    let protocol_version = header_u32(encoded, 16)?;
    let num_variables = header_u32(encoded, 20)?;
    let body_len = header_u32(encoded, 24)? as usize;
    let dictionary_count = header_u32(encoded, 28)? as usize;
    let reference_count = header_u32(encoded, 32)? as usize;
    let flags = header_u32(encoded, 36)?;
    if codec_version != NATIVE_PROOF_CODEC_VERSION || protocol_version != EXPLICIT_WHIR_VERSION {
        return Err(NativeProofCodecError::UnsupportedVersion);
    }
    if header_bytes as usize != NATIVE_PROOF_CODEC_HEADER_BYTES
        || usize::try_from(num_variables).ok() != Some(config.num_variables)
        || body_len != shape.body_len
        || reference_count != shape.reference_count
        || flags != NATIVE_PROOF_CODEC_FLAGS
        || dictionary_count > reference_count
        || dictionary_count > shape.maximum_dictionary_nodes()?
    {
        return Err(NativeProofCodecError::InvalidEncoding);
    }

    let dictionary_bytes = dictionary_count
        .checked_mul(DIGEST_BYTES)
        .ok_or(NativeProofCodecError::InvalidEncoding)?;
    let reference_bytes = reference_count
        .checked_mul(REFERENCE_BYTES)
        .ok_or(NativeProofCodecError::InvalidEncoding)?;
    let expected_len = NATIVE_PROOF_CODEC_HEADER_BYTES
        .checked_add(body_len)
        .and_then(|value| value.checked_add(dictionary_bytes))
        .and_then(|value| value.checked_add(reference_bytes))
        .ok_or(NativeProofCodecError::InvalidEncoding)?;
    if expected_len != encoded.len() || expected_len > MAX_EXPLICIT_WHIR_PROOF_BYTES {
        return Err(NativeProofCodecError::InvalidEncoding);
    }

    let body_start = NATIVE_PROOF_CODEC_HEADER_BYTES;
    let dictionary_start = body_start + body_len;
    let references_start = dictionary_start + dictionary_bytes;
    let dictionary = decode_dictionary(
        &encoded[dictionary_start..references_start],
        dictionary_count,
    )?;
    let mut paths = PathDecoder::new(&dictionary, &encoded[references_start..]);
    let mut body = Reader::new(&encoded[body_start..dictionary_start]);

    let initial_ood_answers = body.read_extensions(shape.initial_ood_answers)?;
    let initial_sumcheck = body.read_sumcheck(shape.initial_sumcheck)?;
    let mut rounds = Vec::new();
    rounds
        .try_reserve_exact(shape.rounds.len())
        .map_err(|_| NativeProofCodecError::InvalidEncoding)?;
    for round_shape in &shape.rounds {
        let root = body.read_digest()?;
        let ood_answers = body.read_extensions(round_shape.ood_answers)?;
        let pow_witness = if round_shape.has_pow {
            body.read_base()?
        } else {
            F::ZERO
        };
        let queries = read_queries(&mut body, &mut paths, round_shape.queries)?;
        let sumcheck = body.read_sumcheck(round_shape.sumcheck)?;
        rounds.push(WhirRoundProof {
            commitment: Some(MerkleCap::new(vec![root])),
            ood_answers,
            pow_witness,
            queries,
            sumcheck,
        });
    }

    let final_poly = Poly::new(body.read_extensions(shape.final_poly_len)?);
    let final_pow_witness = if shape.final_has_pow {
        body.read_base()?
    } else {
        F::ZERO
    };
    let final_queries = read_queries(&mut body, &mut paths, shape.final_queries)?;
    let final_sumcheck = shape
        .final_sumcheck
        .map(|sumcheck_shape| body.read_sumcheck(sumcheck_shape))
        .transpose()?;

    body.finish()?;
    paths.finish()?;
    Ok(WhirProof {
        initial_ood_answers,
        initial_sumcheck,
        rounds,
        final_poly: Some(final_poly),
        final_pow_witness,
        final_queries,
        final_sumcheck,
    })
}

fn validate_proof_shape<MT>(
    proof: &WhirProof<F, EF, MT>,
    shape: &ProofShape,
) -> Result<(), NativeProofCodecError>
where
    MT: Mmcs<F, Commitment = MerkleCap<F, [u8; DIGEST_BYTES]>, Proof = Vec<[u8; DIGEST_BYTES]>>,
{
    if proof.initial_ood_answers.len() != shape.initial_ood_answers
        || proof.rounds.len() != shape.rounds.len()
    {
        return Err(NativeProofCodecError::Shape);
    }
    validate_sumcheck(&proof.initial_sumcheck, shape.initial_sumcheck)?;
    for (round, round_shape) in proof.rounds.iter().zip(&shape.rounds) {
        let commitment = round
            .commitment
            .as_ref()
            .ok_or(NativeProofCodecError::Shape)?;
        if commitment.num_roots() != 1
            || round.ood_answers.len() != round_shape.ood_answers
            || (!round_shape.has_pow && round.pow_witness != F::ZERO)
        {
            return Err(NativeProofCodecError::Shape);
        }
        validate_queries(&round.queries, round_shape.queries)?;
        validate_sumcheck(&round.sumcheck, round_shape.sumcheck)?;
    }

    let final_poly = proof
        .final_poly
        .as_ref()
        .ok_or(NativeProofCodecError::Shape)?;
    if final_poly.num_evals() != shape.final_poly_len
        || (!shape.final_has_pow && proof.final_pow_witness != F::ZERO)
    {
        return Err(NativeProofCodecError::Shape);
    }
    validate_queries(&proof.final_queries, shape.final_queries)?;
    match (&proof.final_sumcheck, shape.final_sumcheck) {
        (Some(data), Some(sumcheck_shape)) => validate_sumcheck(data, sumcheck_shape),
        (None, None) => Ok(()),
        _ => Err(NativeProofCodecError::Shape),
    }
}

fn validate_sumcheck(
    sumcheck: &SumcheckData<F, EF>,
    shape: SumcheckShape,
) -> Result<(), NativeProofCodecError> {
    let expected_pow = if shape.has_pow { shape.rounds } else { 0 };
    if sumcheck.polynomial_evaluations.len() != shape.rounds
        || sumcheck.pow_witnesses.len() != expected_pow
    {
        return Err(NativeProofCodecError::Shape);
    }
    Ok(())
}

fn validate_queries(
    queries: &[NativeQuery],
    shape: QueryShape,
) -> Result<(), NativeProofCodecError> {
    if queries.len() != shape.count {
        return Err(NativeProofCodecError::Shape);
    }
    for query in queries {
        let valid = match (shape.field, query) {
            (QueryField::Base, QueryOpening::Base { values, proof }) => {
                values.len() == shape.width && proof.len() == shape.path_len
            }
            (QueryField::Extension, QueryOpening::Extension { values, proof }) => {
                values.len() == shape.width && proof.len() == shape.path_len
            }
            _ => false,
        };
        if !valid {
            return Err(NativeProofCodecError::Shape);
        }
    }
    Ok(())
}

fn write_base(output: &mut Vec<u8>, value: F) {
    output.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
}

fn write_extension(output: &mut Vec<u8>, value: EF) {
    let limbs: &[F] = value.as_basis_coefficients_slice();
    debug_assert_eq!(limbs.len(), EXTENSION_LIMBS);
    write_base(output, limbs[0]);
    write_base(output, limbs[1]);
    write_base(output, limbs[2]);
}

fn write_extensions(output: &mut Vec<u8>, values: &[EF]) {
    for &value in values {
        write_extension(output, value);
    }
}

fn write_sumcheck(output: &mut Vec<u8>, sumcheck: &SumcheckData<F, EF>, shape: SumcheckShape) {
    for &[at_zero, at_infinity] in &sumcheck.polynomial_evaluations {
        write_extension(output, at_zero);
        write_extension(output, at_infinity);
    }
    if shape.has_pow {
        for &witness in &sumcheck.pow_witnesses {
            write_base(output, witness);
        }
    }
}

fn write_queries(
    body: &mut Vec<u8>,
    paths: &mut PathEncoder,
    queries: &[NativeQuery],
    shape: QueryShape,
) -> Result<(), NativeProofCodecError> {
    for query in queries {
        match (shape.field, query) {
            (QueryField::Base, QueryOpening::Base { values, proof }) => {
                for &value in values {
                    write_base(body, value);
                }
                paths.push_path(proof)?;
            }
            (QueryField::Extension, QueryOpening::Extension { values, proof }) => {
                write_extensions(body, values);
                paths.push_path(proof)?;
            }
            _ => return Err(NativeProofCodecError::Shape),
        }
    }
    Ok(())
}

fn read_queries(
    body: &mut Reader<'_>,
    paths: &mut PathDecoder<'_>,
    shape: QueryShape,
) -> Result<Vec<NativeQuery>, NativeProofCodecError> {
    let mut queries = Vec::new();
    queries
        .try_reserve_exact(shape.count)
        .map_err(|_| NativeProofCodecError::InvalidEncoding)?;
    for _ in 0..shape.count {
        let proof = paths.read_path(shape.path_len)?;
        let query = match shape.field {
            QueryField::Base => QueryOpening::Base {
                values: body.read_bases(shape.width)?,
                proof,
            },
            QueryField::Extension => QueryOpening::Extension {
                values: body.read_extensions(shape.width)?,
                proof,
            },
        };
        queries.push(query);
    }
    Ok(queries)
}

struct PathEncoder {
    indices: BTreeMap<[u8; DIGEST_BYTES], u16>,
    dictionary: Vec<[u8; DIGEST_BYTES]>,
    references: Vec<u16>,
    maximum_dictionary_nodes: usize,
}

impl PathEncoder {
    fn new(
        reference_count: usize,
        maximum_dictionary_nodes: usize,
    ) -> Result<Self, NativeProofCodecError> {
        let mut references = Vec::new();
        references
            .try_reserve_exact(reference_count)
            .map_err(|_| NativeProofCodecError::TooLarge)?;
        Ok(Self {
            indices: BTreeMap::new(),
            dictionary: Vec::new(),
            references,
            maximum_dictionary_nodes,
        })
    }

    fn push_path(&mut self, path: &[[u8; DIGEST_BYTES]]) -> Result<(), NativeProofCodecError> {
        for &node in path {
            let index = if let Some(&index) = self.indices.get(&node) {
                index
            } else {
                if self.dictionary.len() >= self.maximum_dictionary_nodes {
                    return Err(NativeProofCodecError::TooLarge);
                }
                let index = u16::try_from(self.dictionary.len())
                    .map_err(|_| NativeProofCodecError::TooLarge)?;
                self.dictionary.push(node);
                self.indices.insert(node, index);
                index
            };
            self.references.push(index);
        }
        Ok(())
    }

    fn finish(self, body: &[u8], num_variables: usize) -> Result<Vec<u8>, NativeProofCodecError> {
        let dictionary_bytes = self
            .dictionary
            .len()
            .checked_mul(DIGEST_BYTES)
            .ok_or(NativeProofCodecError::TooLarge)?;
        let reference_bytes = self
            .references
            .len()
            .checked_mul(REFERENCE_BYTES)
            .ok_or(NativeProofCodecError::TooLarge)?;
        let encoded_len = NATIVE_PROOF_CODEC_HEADER_BYTES
            .checked_add(body.len())
            .and_then(|value| value.checked_add(dictionary_bytes))
            .and_then(|value| value.checked_add(reference_bytes))
            .ok_or(NativeProofCodecError::TooLarge)?;
        if encoded_len > MAX_EXPLICIT_WHIR_PROOF_BYTES {
            return Err(NativeProofCodecError::TooLarge);
        }

        let body_len = u32::try_from(body.len()).map_err(|_| NativeProofCodecError::TooLarge)?;
        let dictionary_count =
            u32::try_from(self.dictionary.len()).map_err(|_| NativeProofCodecError::TooLarge)?;
        let reference_count =
            u32::try_from(self.references.len()).map_err(|_| NativeProofCodecError::TooLarge)?;
        let num_variables =
            u32::try_from(num_variables).map_err(|_| NativeProofCodecError::Configuration)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(encoded_len)
            .map_err(|_| NativeProofCodecError::TooLarge)?;
        encoded.extend_from_slice(NATIVE_PROOF_CODEC_MAGIC);
        encoded.extend_from_slice(&NATIVE_PROOF_CODEC_VERSION.to_le_bytes());
        encoded.extend_from_slice(&(NATIVE_PROOF_CODEC_HEADER_BYTES as u32).to_le_bytes());
        encoded.extend_from_slice(&EXPLICIT_WHIR_VERSION.to_le_bytes());
        encoded.extend_from_slice(&num_variables.to_le_bytes());
        encoded.extend_from_slice(&body_len.to_le_bytes());
        encoded.extend_from_slice(&dictionary_count.to_le_bytes());
        encoded.extend_from_slice(&reference_count.to_le_bytes());
        encoded.extend_from_slice(&NATIVE_PROOF_CODEC_FLAGS.to_le_bytes());
        encoded.extend_from_slice(body);
        for node in self.dictionary {
            encoded.extend_from_slice(&node);
        }
        for index in self.references {
            encoded.extend_from_slice(&index.to_le_bytes());
        }
        debug_assert_eq!(encoded.len(), encoded_len);
        Ok(encoded)
    }
}

fn decode_dictionary(
    encoded: &[u8],
    count: usize,
) -> Result<Vec<[u8; DIGEST_BYTES]>, NativeProofCodecError> {
    if encoded.len() != count.saturating_mul(DIGEST_BYTES) {
        return Err(NativeProofCodecError::InvalidEncoding);
    }
    let mut dictionary = Vec::new();
    dictionary
        .try_reserve_exact(count)
        .map_err(|_| NativeProofCodecError::InvalidEncoding)?;
    let mut unique = BTreeSet::new();
    for bytes in encoded.chunks_exact(DIGEST_BYTES) {
        let node: [u8; DIGEST_BYTES] = bytes
            .try_into()
            .map_err(|_| NativeProofCodecError::InvalidEncoding)?;
        if !unique.insert(node) {
            return Err(NativeProofCodecError::NonCanonicalDictionary);
        }
        dictionary.push(node);
    }
    Ok(dictionary)
}

struct PathDecoder<'a> {
    dictionary: &'a [[u8; DIGEST_BYTES]],
    references: &'a [u8],
    reference_offset: usize,
    next_new: usize,
}

impl<'a> PathDecoder<'a> {
    const fn new(dictionary: &'a [[u8; DIGEST_BYTES]], references: &'a [u8]) -> Self {
        Self {
            dictionary,
            references,
            reference_offset: 0,
            next_new: 0,
        }
    }

    fn read_path(
        &mut self,
        path_len: usize,
    ) -> Result<Vec<[u8; DIGEST_BYTES]>, NativeProofCodecError> {
        let mut path = Vec::new();
        path.try_reserve_exact(path_len)
            .map_err(|_| NativeProofCodecError::InvalidEncoding)?;
        for _ in 0..path_len {
            let end = self
                .reference_offset
                .checked_add(REFERENCE_BYTES)
                .ok_or(NativeProofCodecError::InvalidDictionaryReference)?;
            let bytes = self
                .references
                .get(self.reference_offset..end)
                .ok_or(NativeProofCodecError::InvalidDictionaryReference)?;
            self.reference_offset = end;
            let index = u16::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| NativeProofCodecError::InvalidDictionaryReference)?,
            ) as usize;
            if index > self.next_new || index >= self.dictionary.len() {
                return Err(NativeProofCodecError::InvalidDictionaryReference);
            }
            if index == self.next_new {
                self.next_new += 1;
            }
            path.push(self.dictionary[index]);
        }
        Ok(path)
    }

    fn finish(self) -> Result<(), NativeProofCodecError> {
        if self.reference_offset != self.references.len() {
            return Err(NativeProofCodecError::InvalidDictionaryReference);
        }
        if self.next_new != self.dictionary.len() {
            return Err(NativeProofCodecError::NonCanonicalDictionary);
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_base(&mut self) -> Result<F, NativeProofCodecError> {
        let encoded = self.take::<BASE_BYTES>()?;
        let canonical = u64::from_le_bytes(encoded);
        if canonical >= GOLDILOCKS_MODULUS {
            return Err(NativeProofCodecError::NonCanonicalField);
        }
        Ok(F::new(canonical))
    }

    fn read_bases(&mut self, count: usize) -> Result<Vec<F>, NativeProofCodecError> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| NativeProofCodecError::InvalidEncoding)?;
        for _ in 0..count {
            values.push(self.read_base()?);
        }
        Ok(values)
    }

    fn read_extension(&mut self) -> Result<EF, NativeProofCodecError> {
        Ok(EF::new([
            self.read_base()?,
            self.read_base()?,
            self.read_base()?,
        ]))
    }

    fn read_extensions(&mut self, count: usize) -> Result<Vec<EF>, NativeProofCodecError> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| NativeProofCodecError::InvalidEncoding)?;
        for _ in 0..count {
            values.push(self.read_extension()?);
        }
        Ok(values)
    }

    fn read_digest(&mut self) -> Result<[u8; DIGEST_BYTES], NativeProofCodecError> {
        self.take::<DIGEST_BYTES>()
    }

    fn read_sumcheck(
        &mut self,
        shape: SumcheckShape,
    ) -> Result<SumcheckData<F, EF>, NativeProofCodecError> {
        let mut polynomial_evaluations = Vec::new();
        polynomial_evaluations
            .try_reserve_exact(shape.rounds)
            .map_err(|_| NativeProofCodecError::InvalidEncoding)?;
        for _ in 0..shape.rounds {
            polynomial_evaluations.push([self.read_extension()?, self.read_extension()?]);
        }
        let pow_witnesses = if shape.has_pow {
            self.read_bases(shape.rounds)?
        } else {
            Vec::new()
        };
        Ok(SumcheckData {
            polynomial_evaluations,
            pow_witnesses,
        })
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], NativeProofCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(NativeProofCodecError::InvalidEncoding)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(NativeProofCodecError::InvalidEncoding)?;
        self.offset = end;
        bytes
            .try_into()
            .map_err(|_| NativeProofCodecError::InvalidEncoding)
    }

    fn finish(self) -> Result<(), NativeProofCodecError> {
        if self.offset != self.bytes.len() {
            return Err(NativeProofCodecError::InvalidEncoding);
        }
        Ok(())
    }
}

fn header_u32(encoded: &[u8], offset: usize) -> Result<u32, NativeProofCodecError> {
    let end = offset
        .checked_add(4)
        .ok_or(NativeProofCodecError::InvalidEncoding)?;
    let bytes = encoded
        .get(offset..end)
        .ok_or(NativeProofCodecError::InvalidEncoding)?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| NativeProofCodecError::InvalidEncoding)?,
    ))
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;
    use crate::whir_proof::build_pcs;

    fn config(num_variables: usize) -> WhirConfig<EF, F, Challenger> {
        build_pcs(num_variables, b"native-codec-test")
            .expect("test WHIR configuration")
            .0
            .config
    }

    fn next_base(counter: &mut u64) -> F {
        *counter += 1;
        F::new(*counter)
    }

    fn next_extension(counter: &mut u64) -> EF {
        EF::new([next_base(counter), next_base(counter), next_base(counter)])
    }

    fn sample_sumcheck(shape: SumcheckShape, counter: &mut u64) -> SumcheckData<F, EF> {
        SumcheckData {
            polynomial_evaluations: (0..shape.rounds)
                .map(|_| [next_extension(counter), next_extension(counter)])
                .collect(),
            pow_witnesses: if shape.has_pow {
                (0..shape.rounds).map(|_| next_base(counter)).collect()
            } else {
                Vec::new()
            },
        }
    }

    fn sample_node(phase: usize, query: usize, depth: usize) -> [u8; DIGEST_BYTES] {
        let mut node = [0xa5; DIGEST_BYTES];
        node[..8].copy_from_slice(&(phase as u64).to_le_bytes());
        node[8..16].copy_from_slice(&(depth as u64).to_le_bytes());
        // Higher path levels deliberately share nodes across nearby queries.
        node[16..24].copy_from_slice(
            &((query >> depth.min(usize::BITS as usize - 1)) as u64).to_le_bytes(),
        );
        node[24..].copy_from_slice(&0x434d_4644_5748_4952u64.to_le_bytes());
        node
    }

    fn sample_queries(shape: QueryShape, phase: usize, counter: &mut u64) -> Vec<NativeQuery> {
        (0..shape.count)
            .map(|query| {
                let proof = (0..shape.path_len)
                    .map(|depth| sample_node(phase, query, depth))
                    .collect();
                match shape.field {
                    QueryField::Base => QueryOpening::Base {
                        values: (0..shape.width).map(|_| next_base(counter)).collect(),
                        proof,
                    },
                    QueryField::Extension => QueryOpening::Extension {
                        values: (0..shape.width).map(|_| next_extension(counter)).collect(),
                        proof,
                    },
                }
            })
            .collect()
    }

    fn sample_proof(config: &WhirConfig<EF, F, Challenger>) -> NativeProof {
        let shape = ProofShape::derive(config).expect("test proof shape");
        let mut counter = 0u64;
        let initial_ood_answers = (0..shape.initial_ood_answers)
            .map(|_| next_extension(&mut counter))
            .collect();
        let initial_sumcheck = sample_sumcheck(shape.initial_sumcheck, &mut counter);
        let rounds = shape
            .rounds
            .iter()
            .enumerate()
            .map(|(round_index, round_shape)| WhirRoundProof {
                commitment: Some(MerkleCap::new(vec![sample_node(
                    10_000 + round_index,
                    0,
                    0,
                )])),
                ood_answers: (0..round_shape.ood_answers)
                    .map(|_| next_extension(&mut counter))
                    .collect(),
                pow_witness: if round_shape.has_pow {
                    next_base(&mut counter)
                } else {
                    F::ZERO
                },
                queries: sample_queries(round_shape.queries, round_index, &mut counter),
                sumcheck: sample_sumcheck(round_shape.sumcheck, &mut counter),
            })
            .collect();
        let final_poly = Some(Poly::new(
            (0..shape.final_poly_len)
                .map(|_| next_extension(&mut counter))
                .collect(),
        ));
        let final_pow_witness = if shape.final_has_pow {
            next_base(&mut counter)
        } else {
            F::ZERO
        };
        let final_queries = sample_queries(shape.final_queries, shape.rounds.len(), &mut counter);
        let final_sumcheck = shape
            .final_sumcheck
            .map(|sumcheck_shape| sample_sumcheck(sumcheck_shape, &mut counter));
        WhirProof {
            initial_ood_answers,
            initial_sumcheck,
            rounds,
            final_poly,
            final_pow_witness,
            final_queries,
            final_sumcheck,
        }
    }

    fn header_layout(encoded: &[u8]) -> (usize, usize, usize, usize) {
        let body_len = header_u32(encoded, 24).unwrap() as usize;
        let dictionary_count = header_u32(encoded, 28).unwrap() as usize;
        let reference_count = header_u32(encoded, 32).unwrap() as usize;
        let dictionary_start = NATIVE_PROOF_CODEC_HEADER_BYTES + body_len;
        let references_start = dictionary_start + dictionary_count * DIGEST_BYTES;
        (
            dictionary_start,
            references_start,
            dictionary_count,
            reference_count,
        )
    }

    #[test]
    fn production_candidate_shapes_are_exact() {
        for (variables, phases, body_len, references, final_poly_len, final_sumcheck_rounds) in [
            (2, vec![(QueryField::Base, 2, 1)], 184, 2, 1, None),
            (8, vec![(QueryField::Base, 128, 7)], 6_016, 896, 64, Some(6)),
            (
                9,
                vec![(QueryField::Base, 256, 8), (QueryField::Extension, 128, 7)],
                21_712,
                2_944,
                32,
                Some(5),
            ),
        ] {
            let shape = ProofShape::derive(&config(variables)).unwrap();
            let actual_phases = shape
                .rounds
                .iter()
                .map(|round| round.queries)
                .chain(std::iter::once(shape.final_queries))
                .map(|query| (query.field, query.count, query.path_len))
                .collect::<Vec<_>>();
            assert_eq!(actual_phases, phases);
            assert_eq!(shape.body_len, body_len);
            assert_eq!(shape.reference_count, references);
            assert_eq!(shape.final_poly_len, final_poly_len);
            assert_eq!(
                shape.final_sumcheck.map(|sumcheck| sumcheck.rounds),
                final_sumcheck_rounds
            );
        }

        let shape = ProofShape::derive(&config(13)).unwrap();
        let phases = shape
            .rounds
            .iter()
            .map(|round| round.queries)
            .chain(std::iter::once(shape.final_queries))
            .map(|query| (query.field, query.count, query.path_len))
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                (QueryField::Base, 309, 12),
                (QueryField::Extension, 189, 11),
                (QueryField::Extension, 155, 10),
                (QueryField::Extension, 141, 9),
            ]
        );
        assert_eq!(shape.body_len, 57_936);
        assert_eq!(shape.reference_count, 8_606);
        assert_eq!(shape.final_poly_len, 32);
        assert_eq!(shape.final_sumcheck.unwrap().rounds, 5);

        let shape = ProofShape::derive(&config(16)).unwrap();
        let path_depths = shape
            .rounds
            .iter()
            .map(|round| round.queries.path_len)
            .chain(std::iter::once(shape.final_queries.path_len))
            .collect::<Vec<_>>();
        assert_eq!(path_depths, vec![15, 14, 13, 12, 11]);
        assert_eq!(shape.body_len, 71_744);
        assert_eq!(shape.final_queries.count, 134);
        assert_eq!(shape.final_poly_len, 64);
        assert_eq!(shape.final_sumcheck.unwrap().rounds, 6);
    }

    #[test]
    fn valid_n13_merkle_paths_have_a_deterministic_wire_bound() {
        let shape = ProofShape::derive(&config(13)).unwrap();
        // At every tree level, verifier-valid paths can contain no more unique
        // siblings than either the query count or the number of nodes there.
        let maximum_dictionary_nodes = shape.maximum_dictionary_nodes().unwrap();
        assert_eq!(maximum_dictionary_nodes, 4_011);
        let maximum_native_bytes = NATIVE_PROOF_CODEC_HEADER_BYTES
            + shape.body_len
            + maximum_dictionary_nodes * DIGEST_BYTES
            + shape.reference_count * REFERENCE_BYTES;
        assert_eq!(maximum_native_bytes, 203_540);
        assert_eq!(
            crate::wire::WIRE_HEADER_BYTES
                + crate::whir_proof::EXPLICIT_WHIR_HEADER_BYTES
                + maximum_native_bytes,
            203_576
        );
        assert!(
            crate::wire::WIRE_HEADER_BYTES
                + crate::whir_proof::EXPLICIT_WHIR_HEADER_BYTES
                + maximum_native_bytes
                <= crate::wire::MAX_PROOF_BYTES
        );
    }

    #[test]
    fn tiny_split_shapes_have_exact_enforced_dictionary_and_byte_bounds() {
        for (variables, phases, body_len, references, dictionary_nodes, encoded_bytes) in [
            (3, vec![(4, 2)], 320, 8, 6, 568),
            (6, vec![(32, 5)], 1_696, 160, 62, 4_040),
            (
                12,
                vec![(309, 11), (189, 10), (155, 9)],
                45_088,
                6_684,
                2_822,
                148_800,
            ),
        ] {
            let config = config(variables);
            let shape = ProofShape::derive(&config).unwrap();
            let actual_phases = shape
                .rounds
                .iter()
                .map(|round| round.queries)
                .chain(std::iter::once(shape.final_queries))
                .map(|query| (query.count, query.path_len))
                .collect::<Vec<_>>();
            assert_eq!(actual_phases, phases);
            assert_eq!(shape.body_len, body_len);
            assert_eq!(shape.reference_count, references);
            assert_eq!(shape.maximum_dictionary_nodes().unwrap(), dictionary_nodes);
            assert_eq!(shape.encoded_bytes_upper_bound().unwrap(), encoded_bytes);
            assert_eq!(encoded_proof_upper_bound(&config).unwrap(), encoded_bytes);
        }
    }

    #[test]
    fn dictionary_above_the_shape_bound_is_rejected_before_path_decoding() {
        let config = config(3);
        let proof = sample_proof(&config);
        let encoded = encode_native_proof(&proof, &config).unwrap();
        let (dictionary_start, references_start, dictionary_count, _) = header_layout(&encoded);
        assert_eq!(dictionary_count, 6);
        assert_eq!(
            dictionary_count,
            ProofShape::derive(&config)
                .unwrap()
                .maximum_dictionary_nodes()
                .unwrap()
        );

        let mut malformed = encoded[..references_start].to_vec();
        malformed.extend_from_slice(&[0xa7; DIGEST_BYTES]);
        malformed.extend_from_slice(&encoded[references_start..]);
        malformed[28..32].copy_from_slice(&7_u32.to_le_bytes());
        assert_eq!(
            dictionary_start + dictionary_count * DIGEST_BYTES,
            references_start
        );
        assert!(matches!(
            decode_native_proof(&malformed, &config),
            Err(NativeProofCodecError::InvalidEncoding)
        ));
    }

    #[test]
    fn round_trip_is_byte_canonical() {
        let config = config(13);
        let proof = sample_proof(&config);
        let encoded = encode_native_proof(&proof, &config).unwrap();
        assert!(encoded.len() < 256 * 1024, "{} bytes", encoded.len());
        assert_eq!(&encoded[..8], NATIVE_PROOF_CODEC_MAGIC);
        assert_eq!(header_u32(&encoded, 8).unwrap(), NATIVE_PROOF_CODEC_VERSION);
        assert_eq!(header_u32(&encoded, 20).unwrap(), 13);
        assert_eq!(
            header_u32(&encoded, 32).unwrap() as usize,
            ProofShape::derive(&config).unwrap().reference_count
        );

        let decoded = decode_native_proof(&encoded, &config).unwrap();
        let reencoded = encode_native_proof(&decoded, &config).unwrap();
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn every_supported_round_topology_round_trips() {
        for variables in [2, 8, 9, 13, 16, 17, 18, 19, 20] {
            let config = config(variables);
            let proof = sample_proof(&config);
            let encoded = encode_native_proof(&proof, &config).unwrap();
            let decoded = decode_native_proof(&encoded, &config).unwrap();
            assert_eq!(encode_native_proof(&decoded, &config).unwrap(), encoded);
        }
    }

    #[test]
    fn malformed_headers_lengths_and_trailing_bytes_are_rejected() {
        let config = config(9);
        let proof = sample_proof(&config);
        let encoded = encode_native_proof(&proof, &config).unwrap();

        for (offset, replacement) in [
            (8, NATIVE_PROOF_CODEC_VERSION + 1),
            (12, (NATIVE_PROOF_CODEC_HEADER_BYTES as u32) + 4),
            (16, EXPLICIT_WHIR_VERSION + 1),
            (20, 8),
            (24, header_u32(&encoded, 24).unwrap() + 1),
            (28, u32::MAX),
            (32, header_u32(&encoded, 32).unwrap() + 1),
            (36, 1),
        ] {
            let mut malformed = encoded.clone();
            malformed[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
            assert!(decode_native_proof(&malformed, &config).is_err());
        }

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 0x80;
        assert!(matches!(
            decode_native_proof(&bad_magic, &config),
            Err(NativeProofCodecError::InvalidEncoding)
        ));
        let mut legacy_magic = encoded.clone();
        legacy_magic[..8].copy_from_slice(b"CMFDWHB1");
        assert!(matches!(
            decode_native_proof(&legacy_magic, &config),
            Err(NativeProofCodecError::InvalidEncoding)
        ));
        let mut legacy_version = encoded.clone();
        legacy_version[8..12].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            decode_native_proof(&legacy_version, &config),
            Err(NativeProofCodecError::UnsupportedVersion)
        ));
        assert!(decode_native_proof(&encoded[..encoded.len() - 1], &config).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_native_proof(&trailing, &config).is_err());
    }

    #[test]
    fn noncanonical_field_limb_is_rejected() {
        let config = config(9);
        let proof = sample_proof(&config);
        let mut encoded = encode_native_proof(&proof, &config).unwrap();
        encoded[NATIVE_PROOF_CODEC_HEADER_BYTES..NATIVE_PROOF_CODEC_HEADER_BYTES + BASE_BYTES]
            .copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert!(matches!(
            decode_native_proof(&encoded, &config),
            Err(NativeProofCodecError::NonCanonicalField)
        ));
    }

    #[test]
    fn duplicate_forward_out_of_range_and_unused_dictionary_entries_are_rejected() {
        let config = config(9);
        let proof = sample_proof(&config);
        let encoded = encode_native_proof(&proof, &config).unwrap();
        let (dictionary_start, references_start, dictionary_count, reference_count) =
            header_layout(&encoded);
        assert!(dictionary_count > 2);
        assert!(reference_count > 2);

        let mut duplicate = encoded.clone();
        let first = duplicate[dictionary_start..dictionary_start + DIGEST_BYTES].to_vec();
        duplicate[dictionary_start + DIGEST_BYTES..dictionary_start + 2 * DIGEST_BYTES]
            .copy_from_slice(&first);
        assert!(matches!(
            decode_native_proof(&duplicate, &config),
            Err(NativeProofCodecError::NonCanonicalDictionary)
        ));

        let mut forward = encoded.clone();
        forward[references_start..references_start + REFERENCE_BYTES]
            .copy_from_slice(&1u16.to_le_bytes());
        assert!(matches!(
            decode_native_proof(&forward, &config),
            Err(NativeProofCodecError::InvalidDictionaryReference)
        ));

        let mut out_of_range = encoded.clone();
        out_of_range[references_start..references_start + REFERENCE_BYTES]
            .copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            decode_native_proof(&out_of_range, &config),
            Err(NativeProofCodecError::InvalidDictionaryReference)
        ));

        let mut unused = encoded.clone();
        let last = u16::try_from(dictionary_count - 1).unwrap();
        for reference in unused[references_start..].chunks_exact_mut(REFERENCE_BYTES) {
            if u16::from_le_bytes(reference.try_into().unwrap()) == last {
                reference.copy_from_slice(&0u16.to_le_bytes());
            }
        }
        assert!(matches!(
            decode_native_proof(&unused, &config),
            Err(NativeProofCodecError::NonCanonicalDictionary)
        ));
    }

    #[test]
    fn encoder_rejects_every_structural_mismatch() {
        let config = config(9);
        let proof = sample_proof(&config);

        let mut missing_round = proof.clone();
        missing_round.rounds.pop();
        assert_eq!(
            encode_native_proof(&missing_round, &config),
            Err(NativeProofCodecError::Shape)
        );

        let mut missing_commitment = proof.clone();
        missing_commitment.rounds[0].commitment = None;
        assert_eq!(
            encode_native_proof(&missing_commitment, &config),
            Err(NativeProofCodecError::Shape)
        );

        let mut short_path = proof.clone();
        match &mut short_path.rounds[0].queries[0] {
            QueryOpening::Base { proof, .. } | QueryOpening::Extension { proof, .. } => {
                proof.pop();
            }
        }
        assert_eq!(
            encode_native_proof(&short_path, &config),
            Err(NativeProofCodecError::Shape)
        );

        let mut wrong_query_variant = proof.clone();
        let path = match &wrong_query_variant.rounds[0].queries[0] {
            QueryOpening::Base { proof, .. } => proof.clone(),
            QueryOpening::Extension { .. } => unreachable!("first query must be base field"),
        };
        wrong_query_variant.rounds[0].queries[0] = QueryOpening::Extension {
            values: vec![EF::ZERO; 4],
            proof: path,
        };
        assert_eq!(
            encode_native_proof(&wrong_query_variant, &config),
            Err(NativeProofCodecError::Shape)
        );

        let mut short_values = proof.clone();
        match &mut short_values.rounds[0].queries[0] {
            QueryOpening::Base { values, .. } => {
                values.pop();
            }
            QueryOpening::Extension { .. } => unreachable!("first query must be base field"),
        }
        assert_eq!(
            encode_native_proof(&short_values, &config),
            Err(NativeProofCodecError::Shape)
        );

        let mut multi_root = proof.clone();
        let root = multi_root.rounds[0].commitment.as_ref().unwrap().roots()[0];
        multi_root.rounds[0].commitment = Some(MerkleCap::new(vec![root, [0x5a; 32]]));
        assert_eq!(
            encode_native_proof(&multi_root, &config),
            Err(NativeProofCodecError::Shape)
        );

        let mut ignored_sumcheck_pow = proof.clone();
        ignored_sumcheck_pow
            .initial_sumcheck
            .pow_witnesses
            .push(F::new(1));
        assert_eq!(
            encode_native_proof(&ignored_sumcheck_pow, &config),
            Err(NativeProofCodecError::Shape)
        );

        let mut wrong_final_poly = proof.clone();
        wrong_final_poly.final_poly = Some(Poly::new(vec![EF::ZERO; 16]));
        assert_eq!(
            encode_native_proof(&wrong_final_poly, &config),
            Err(NativeProofCodecError::Shape)
        );

        let mut wrong_final_sumcheck = proof.clone();
        wrong_final_sumcheck.final_sumcheck = None;
        assert_eq!(
            encode_native_proof(&wrong_final_sumcheck, &config),
            Err(NativeProofCodecError::Shape)
        );

        let mut ignored_pow_malleability = proof;
        ignored_pow_malleability.final_pow_witness = F::new(1);
        assert_eq!(
            encode_native_proof(&ignored_pow_malleability, &config),
            Err(NativeProofCodecError::Shape)
        );
    }

    #[test]
    fn arbitrary_bounded_inputs_never_panic() {
        let large_config = config(9);
        for len in 0..=512 {
            let bytes = (0..len)
                .map(|index| (index as u8).wrapping_mul(73).wrapping_add(len as u8))
                .collect::<Vec<_>>();
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = decode_native_proof(&bytes, &large_config);
            }));
            assert!(result.is_ok(), "decoder panicked for {len} bytes");
        }

        let small_config = config(2);
        let encoded = encode_native_proof(&sample_proof(&small_config), &small_config).unwrap();
        for length in 0..encoded.len() {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = decode_native_proof(&encoded[..length], &small_config);
            }));
            assert!(result.is_ok(), "decoder panicked at truncation {length}");
        }
        for index in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[index] ^= 0xa5;
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = decode_native_proof(&mutated, &small_config);
            }));
            assert!(result.is_ok(), "decoder panicked at mutation {index}");
        }
    }
}
