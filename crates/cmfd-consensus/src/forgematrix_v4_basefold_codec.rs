//! Exact, allocation-bounded wire codec for a ProductionV4 bank opening.
//!
//! No collection length or tensor dimension is accepted from the wire. The
//! decoder reconstructs the one pinned topology after checking the exact byte
//! length, so untrusted proofs cannot request attacker-controlled allocations.

use slop_algebra::{AbstractExtensionField, AbstractField, PrimeField32, UnivariatePolynomial};
use slop_basefold::BasefoldProof;
use slop_merkle_tree::{MerkleTreeOpeningAndProof, MerkleTreeTcsProof};
use slop_multilinear::Point;
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::{Dimensions, Tensor};
use thiserror::Error;

use crate::{
    FORGEMATRIX_V4_BASEFOLD_QUERIES, FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES,
    FORGEMATRIX_V4_DYNAMIC_COLUMNS, FORGEMATRIX_V4_EXTENSION_DEGREE, FORGEMATRIX_V4_FIELD_MODULUS,
    FORGEMATRIX_V4_FIXED_COLUMNS, FORGEMATRIX_V4_MAX_OPENING_CLAIMS,
    forgematrix_v4_basefold::{
        ForgeMatrixV4Digest, ForgeMatrixV4Extension, ForgeMatrixV4Field, ForgeMatrixV4IopContext,
        ForgeMatrixV4OpeningReductionProof,
    },
};

const CODEC_MAGIC: [u8; 8] = *b"CMV4BF01";
const CODEC_VERSION: u32 = 1;
const CODEC_HEADER_BYTES: usize = 16;
const EXTENSION_BYTES: usize = FORGEMATRIX_V4_EXTENSION_DEGREE as usize * 4;
const DIGEST_FIELDS: usize = 8;
const DIGEST_BYTES: usize = DIGEST_FIELDS * 4;
const SUMCHECK_DEGREE: usize = 2;
const COMPONENT_LOG_HEIGHT: usize = FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize + 1;
const QUERY_WIDTH: usize = 8;

/// Exact bytes for one opening reduction with one claim.
pub const FORGEMATRIX_V4_OPENING_REDUCTION_MIN_BYTES: usize = 3_300_008;
/// Exact maximum bytes for one opening reduction with sixteen claims.
pub const FORGEMATRIX_V4_OPENING_REDUCTION_MAX_BYTES: usize = 3_300_264;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ForgeMatrixV4ProofCodecError {
    #[error("V4 opening proof has an invalid codec header")]
    Header,
    #[error("V4 opening proof uses an unsupported codec version")]
    Version,
    #[error("V4 opening proof has an invalid claim count")]
    ClaimCount,
    #[error("V4 opening proof has the wrong exact byte length")]
    Length,
    #[error("V4 opening proof contains a noncanonical field element")]
    Field,
    #[error("V4 opening proof does not have the pinned topology")]
    Shape,
}

pub fn forgematrix_v4_opening_reduction_encoded_len(
    claim_count: usize,
) -> Result<usize, ForgeMatrixV4ProofCodecError> {
    validate_claim_count(claim_count)?;
    let selector_variables = claim_count.ilog2() as usize;
    Ok(FORGEMATRIX_V4_OPENING_REDUCTION_MIN_BYTES + selector_variables * 64)
}

pub fn encode_forgematrix_v4_opening_reduction(
    proof: &ForgeMatrixV4OpeningReductionProof,
    claim_count: usize,
) -> Result<Vec<u8>, ForgeMatrixV4ProofCodecError> {
    validate_shape(proof, claim_count)?;
    let expected_len = forgematrix_v4_opening_reduction_encoded_len(claim_count)?;
    let mut bytes = Vec::with_capacity(expected_len);
    bytes.extend_from_slice(&CODEC_MAGIC);
    bytes.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(claim_count as u32).to_le_bytes());

    for polynomial in &proof.sumcheck.univariate_polys {
        for value in &polynomial.coefficients {
            write_extension(&mut bytes, value);
        }
    }
    write_extension(&mut bytes, &proof.sumcheck.claimed_sum);
    for value in proof.sumcheck.point_and_eval.0.iter() {
        write_extension(&mut bytes, value);
    }
    write_extension(&mut bytes, &proof.sumcheck.point_and_eval.1);

    write_extensions(&mut bytes, &proof.fixed_column_evaluations);
    write_extensions(&mut bytes, &proof.dynamic_column_evaluations);
    for values in &proof.basefold.univariate_messages {
        write_extension(&mut bytes, &values[0]);
        write_extension(&mut bytes, &values[1]);
    }
    for digest in &proof.basefold.fri_commitments {
        write_digest(&mut bytes, digest);
    }
    for opening in &proof
        .basefold
        .component_polynomials_query_openings_and_proofs
    {
        write_field_tensor(&mut bytes, &opening.values);
        write_digest(&mut bytes, &opening.proof.merkle_root);
        write_digest_tensor(&mut bytes, &opening.proof.paths);
    }
    for opening in &proof.basefold.query_phase_openings_and_proofs {
        write_field_tensor(&mut bytes, &opening.values);
        write_digest(&mut bytes, &opening.proof.merkle_root);
        write_digest_tensor(&mut bytes, &opening.proof.paths);
    }
    write_extension(&mut bytes, &proof.basefold.final_poly);
    write_field(&mut bytes, proof.basefold.pow_witness);
    write_field(&mut bytes, proof.basefold.batch_grinding_witness);

    if bytes.len() != expected_len {
        return Err(ForgeMatrixV4ProofCodecError::Shape);
    }
    Ok(bytes)
}

pub fn decode_forgematrix_v4_opening_reduction(
    bytes: &[u8],
    expected_claim_count: usize,
) -> Result<ForgeMatrixV4OpeningReductionProof, ForgeMatrixV4ProofCodecError> {
    validate_claim_count(expected_claim_count)?;
    if bytes.len() < CODEC_HEADER_BYTES {
        return Err(ForgeMatrixV4ProofCodecError::Length);
    }
    if bytes[..8] != CODEC_MAGIC {
        return Err(ForgeMatrixV4ProofCodecError::Header);
    }
    if u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ForgeMatrixV4ProofCodecError::Length)?,
    ) != CODEC_VERSION
    {
        return Err(ForgeMatrixV4ProofCodecError::Version);
    }
    let encoded_claim_count = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| ForgeMatrixV4ProofCodecError::Length)?,
    ) as usize;
    if encoded_claim_count != expected_claim_count {
        return Err(ForgeMatrixV4ProofCodecError::ClaimCount);
    }
    let expected_len = forgematrix_v4_opening_reduction_encoded_len(expected_claim_count)?;
    if bytes.len() != expected_len {
        return Err(ForgeMatrixV4ProofCodecError::Length);
    }

    let sumcheck_rounds = sumcheck_rounds(expected_claim_count);
    let mut reader = Reader::new(&bytes[CODEC_HEADER_BYTES..]);
    let mut univariate_polys = Vec::with_capacity(sumcheck_rounds);
    for _ in 0..sumcheck_rounds {
        let mut coefficients = Vec::with_capacity(SUMCHECK_DEGREE + 1);
        for _ in 0..=SUMCHECK_DEGREE {
            coefficients.push(reader.extension()?);
        }
        univariate_polys.push(UnivariatePolynomial::new(coefficients));
    }
    let claimed_sum = reader.extension()?;
    let point = Point::from(reader.extensions(sumcheck_rounds)?);
    let evaluation = reader.extension()?;
    let fixed_column_evaluations = reader.extensions(FORGEMATRIX_V4_FIXED_COLUMNS)?;
    let dynamic_column_evaluations = reader.extensions(FORGEMATRIX_V4_DYNAMIC_COLUMNS)?;

    let mut univariate_messages =
        Vec::with_capacity(FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize);
    for _ in 0..FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES {
        univariate_messages.push([reader.extension()?, reader.extension()?]);
    }
    let mut fri_commitments = Vec::with_capacity(FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize);
    for _ in 0..FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES {
        fri_commitments.push(reader.digest()?);
    }

    let component_polynomials_query_openings_and_proofs = vec![
        reader.opening(FORGEMATRIX_V4_FIXED_COLUMNS, COMPONENT_LOG_HEIGHT)?,
        reader.opening(FORGEMATRIX_V4_DYNAMIC_COLUMNS, COMPONENT_LOG_HEIGHT)?,
    ];
    let mut query_phase_openings_and_proofs =
        Vec::with_capacity(FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize);
    for index in 0..FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize {
        query_phase_openings_and_proofs.push(reader.opening(
            QUERY_WIDTH,
            FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize - index,
        )?);
    }
    let basefold = BasefoldProof::<ForgeMatrixV4IopContext> {
        univariate_messages,
        fri_commitments,
        component_polynomials_query_openings_and_proofs,
        query_phase_openings_and_proofs,
        final_poly: reader.extension()?,
        pow_witness: reader.field()?,
        batch_grinding_witness: reader.field()?,
    };
    if !reader.is_empty() {
        return Err(ForgeMatrixV4ProofCodecError::Length);
    }

    let proof = ForgeMatrixV4OpeningReductionProof {
        sumcheck: PartialSumcheckProof {
            univariate_polys,
            claimed_sum,
            point_and_eval: (point, evaluation),
        },
        fixed_column_evaluations,
        dynamic_column_evaluations,
        basefold,
    };
    validate_shape(&proof, expected_claim_count)?;
    Ok(proof)
}

fn validate_claim_count(claim_count: usize) -> Result<(), ForgeMatrixV4ProofCodecError> {
    if claim_count == 0
        || !claim_count.is_power_of_two()
        || claim_count > FORGEMATRIX_V4_MAX_OPENING_CLAIMS
    {
        return Err(ForgeMatrixV4ProofCodecError::ClaimCount);
    }
    Ok(())
}

fn sumcheck_rounds(claim_count: usize) -> usize {
    FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize + claim_count.ilog2() as usize
}

fn validate_shape(
    proof: &ForgeMatrixV4OpeningReductionProof,
    claim_count: usize,
) -> Result<(), ForgeMatrixV4ProofCodecError> {
    validate_claim_count(claim_count)?;
    let rounds = sumcheck_rounds(claim_count);
    if proof.sumcheck.univariate_polys.len() != rounds
        || proof
            .sumcheck
            .univariate_polys
            .iter()
            .any(|polynomial| polynomial.coefficients.len() != SUMCHECK_DEGREE + 1)
        || proof.sumcheck.point_and_eval.0.dimension() != rounds
        || proof.fixed_column_evaluations.len() != FORGEMATRIX_V4_FIXED_COLUMNS
        || proof.dynamic_column_evaluations.len() != FORGEMATRIX_V4_DYNAMIC_COLUMNS
        || proof.basefold.univariate_messages.len()
            != FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize
        || proof.basefold.fri_commitments.len() != FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize
        || proof
            .basefold
            .component_polynomials_query_openings_and_proofs
            .len()
            != 2
        || proof.basefold.query_phase_openings_and_proofs.len()
            != FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize
    {
        return Err(ForgeMatrixV4ProofCodecError::Shape);
    }

    validate_opening(
        &proof
            .basefold
            .component_polynomials_query_openings_and_proofs[0],
        FORGEMATRIX_V4_FIXED_COLUMNS,
        COMPONENT_LOG_HEIGHT,
    )?;
    validate_opening(
        &proof
            .basefold
            .component_polynomials_query_openings_and_proofs[1],
        FORGEMATRIX_V4_DYNAMIC_COLUMNS,
        COMPONENT_LOG_HEIGHT,
    )?;
    for (index, opening) in proof
        .basefold
        .query_phase_openings_and_proofs
        .iter()
        .enumerate()
    {
        validate_opening(
            opening,
            QUERY_WIDTH,
            FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize - index,
        )?;
    }
    Ok(())
}

fn validate_opening(
    opening: &MerkleTreeOpeningAndProof<ForgeMatrixV4IopContext>,
    width: usize,
    log_height: usize,
) -> Result<(), ForgeMatrixV4ProofCodecError> {
    let queries = FORGEMATRIX_V4_BASEFOLD_QUERIES as usize;
    if opening.values.dimensions.sizes() != [queries, width]
        || opening.proof.log_tensor_height != log_height
        || opening.proof.width != width
        || opening.proof.paths.dimensions.sizes() != [queries, log_height]
    {
        return Err(ForgeMatrixV4ProofCodecError::Shape);
    }
    Ok(())
}

fn write_field(bytes: &mut Vec<u8>, value: ForgeMatrixV4Field) {
    bytes.extend_from_slice(&value.as_canonical_u32().to_le_bytes());
}

fn write_extension(bytes: &mut Vec<u8>, value: &ForgeMatrixV4Extension) {
    for &coefficient in value.as_base_slice() {
        write_field(bytes, coefficient);
    }
}

fn write_extensions(bytes: &mut Vec<u8>, values: &[ForgeMatrixV4Extension]) {
    for value in values {
        write_extension(bytes, value);
    }
}

fn write_digest(bytes: &mut Vec<u8>, digest: &ForgeMatrixV4Digest) {
    for &value in digest {
        write_field(bytes, value);
    }
}

fn write_field_tensor(bytes: &mut Vec<u8>, tensor: &Tensor<ForgeMatrixV4Field>) {
    for &value in tensor.storage.iter() {
        write_field(bytes, value);
    }
}

fn write_digest_tensor(bytes: &mut Vec<u8>, tensor: &Tensor<ForgeMatrixV4Digest>) {
    for digest in tensor.storage.iter() {
        write_digest(bytes, digest);
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn field(&mut self) -> Result<ForgeMatrixV4Field, ForgeMatrixV4ProofCodecError> {
        let end = self
            .position
            .checked_add(4)
            .ok_or(ForgeMatrixV4ProofCodecError::Length)?;
        let encoded = self
            .bytes
            .get(self.position..end)
            .ok_or(ForgeMatrixV4ProofCodecError::Length)?;
        self.position = end;
        let value = u32::from_le_bytes(
            encoded
                .try_into()
                .map_err(|_| ForgeMatrixV4ProofCodecError::Length)?,
        );
        if value >= FORGEMATRIX_V4_FIELD_MODULUS {
            return Err(ForgeMatrixV4ProofCodecError::Field);
        }
        Ok(ForgeMatrixV4Field::from_canonical_u32(value))
    }

    fn extension(&mut self) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4ProofCodecError> {
        Ok(ForgeMatrixV4Extension::from_base_slice(&[
            self.field()?,
            self.field()?,
            self.field()?,
            self.field()?,
        ]))
    }

    fn extensions(
        &mut self,
        count: usize,
    ) -> Result<Vec<ForgeMatrixV4Extension>, ForgeMatrixV4ProofCodecError> {
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.extension()?);
        }
        Ok(values)
    }

    fn digest(&mut self) -> Result<ForgeMatrixV4Digest, ForgeMatrixV4ProofCodecError> {
        let mut digest = [ForgeMatrixV4Field::zero(); DIGEST_FIELDS];
        for value in &mut digest {
            *value = self.field()?;
        }
        Ok(digest)
    }

    fn field_tensor(
        &mut self,
        rows: usize,
        columns: usize,
    ) -> Result<Tensor<ForgeMatrixV4Field>, ForgeMatrixV4ProofCodecError> {
        let count = rows
            .checked_mul(columns)
            .ok_or(ForgeMatrixV4ProofCodecError::Shape)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.field()?);
        }
        Ok(Tensor {
            storage: values.into(),
            dimensions: Dimensions::try_from([rows, columns])
                .map_err(|_| ForgeMatrixV4ProofCodecError::Shape)?,
        })
    }

    fn digest_tensor(
        &mut self,
        rows: usize,
        columns: usize,
    ) -> Result<Tensor<ForgeMatrixV4Digest>, ForgeMatrixV4ProofCodecError> {
        let count = rows
            .checked_mul(columns)
            .ok_or(ForgeMatrixV4ProofCodecError::Shape)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.digest()?);
        }
        Ok(Tensor {
            storage: values.into(),
            dimensions: Dimensions::try_from([rows, columns])
                .map_err(|_| ForgeMatrixV4ProofCodecError::Shape)?,
        })
    }

    fn opening(
        &mut self,
        width: usize,
        log_height: usize,
    ) -> Result<MerkleTreeOpeningAndProof<ForgeMatrixV4IopContext>, ForgeMatrixV4ProofCodecError>
    {
        let queries = FORGEMATRIX_V4_BASEFOLD_QUERIES as usize;
        Ok(MerkleTreeOpeningAndProof {
            values: self.field_tensor(queries, width)?,
            proof: MerkleTreeTcsProof {
                merkle_root: self.digest()?,
                log_tensor_height: log_height,
                width,
                paths: self.digest_tensor(queries, log_height)?,
            },
        })
    }
}

const _: () = assert!(EXTENSION_BYTES == 16);
const _: () = assert!(DIGEST_BYTES == 32);

#[cfg(test)]
mod tests {
    use slop_algebra::AbstractField;

    use super::*;

    fn zero_tensor<T: Clone>(value: T, rows: usize, columns: usize) -> Tensor<T> {
        Tensor {
            storage: vec![value; rows * columns].into(),
            dimensions: Dimensions::try_from([rows, columns]).unwrap(),
        }
    }

    fn zero_opening(
        width: usize,
        log_height: usize,
    ) -> MerkleTreeOpeningAndProof<ForgeMatrixV4IopContext> {
        let queries = FORGEMATRIX_V4_BASEFOLD_QUERIES as usize;
        MerkleTreeOpeningAndProof {
            values: zero_tensor(ForgeMatrixV4Field::zero(), queries, width),
            proof: MerkleTreeTcsProof {
                merkle_root: [ForgeMatrixV4Field::zero(); DIGEST_FIELDS],
                log_tensor_height: log_height,
                width,
                paths: zero_tensor(
                    [ForgeMatrixV4Field::zero(); DIGEST_FIELDS],
                    queries,
                    log_height,
                ),
            },
        }
    }

    fn structural_proof(claim_count: usize) -> ForgeMatrixV4OpeningReductionProof {
        let rounds = sumcheck_rounds(claim_count);
        let mut query_openings = Vec::with_capacity(FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize);
        for index in 0..FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize {
            query_openings.push(zero_opening(
                QUERY_WIDTH,
                FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize - index,
            ));
        }
        ForgeMatrixV4OpeningReductionProof {
            sumcheck: PartialSumcheckProof {
                univariate_polys: (0..rounds)
                    .map(|_| {
                        UnivariatePolynomial::new(vec![
                            ForgeMatrixV4Extension::zero();
                            SUMCHECK_DEGREE + 1
                        ])
                    })
                    .collect(),
                claimed_sum: ForgeMatrixV4Extension::zero(),
                point_and_eval: (
                    Point::from(vec![ForgeMatrixV4Extension::zero(); rounds]),
                    ForgeMatrixV4Extension::zero(),
                ),
            },
            fixed_column_evaluations: vec![
                ForgeMatrixV4Extension::zero();
                FORGEMATRIX_V4_FIXED_COLUMNS
            ],
            dynamic_column_evaluations: vec![
                ForgeMatrixV4Extension::zero();
                FORGEMATRIX_V4_DYNAMIC_COLUMNS
            ],
            basefold: BasefoldProof {
                univariate_messages: vec![
                    [ForgeMatrixV4Extension::zero(); 2];
                    FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize
                ],
                fri_commitments: vec![
                    [ForgeMatrixV4Field::zero(); DIGEST_FIELDS];
                    FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize
                ],
                component_polynomials_query_openings_and_proofs: vec![
                    zero_opening(FORGEMATRIX_V4_FIXED_COLUMNS, COMPONENT_LOG_HEIGHT),
                    zero_opening(FORGEMATRIX_V4_DYNAMIC_COLUMNS, COMPONENT_LOG_HEIGHT),
                ],
                query_phase_openings_and_proofs: query_openings,
                final_poly: ForgeMatrixV4Extension::zero(),
                pow_witness: ForgeMatrixV4Field::zero(),
                batch_grinding_witness: ForgeMatrixV4Field::zero(),
            },
        }
    }

    #[test]
    fn exact_topology_round_trips_canonically_at_both_claim_bounds() {
        for claim_count in [1, FORGEMATRIX_V4_MAX_OPENING_CLAIMS] {
            let proof = structural_proof(claim_count);
            let encoded = encode_forgematrix_v4_opening_reduction(&proof, claim_count).unwrap();
            assert_eq!(
                encoded.len(),
                forgematrix_v4_opening_reduction_encoded_len(claim_count).unwrap()
            );
            let decoded = decode_forgematrix_v4_opening_reduction(&encoded, claim_count).unwrap();
            assert_eq!(
                encode_forgematrix_v4_opening_reduction(&decoded, claim_count).unwrap(),
                encoded
            );
        }
    }

    #[test]
    fn malformed_lengths_headers_counts_and_fields_fail_closed() {
        let proof = structural_proof(1);
        let encoded = encode_forgematrix_v4_opening_reduction(&proof, 1).unwrap();

        assert!(matches!(
            decode_forgematrix_v4_opening_reduction(&encoded[..encoded.len() - 1], 1),
            Err(ForgeMatrixV4ProofCodecError::Length)
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_forgematrix_v4_opening_reduction(&trailing, 1),
            Err(ForgeMatrixV4ProofCodecError::Length)
        ));
        assert!(matches!(
            decode_forgematrix_v4_opening_reduction(&encoded, 2),
            Err(ForgeMatrixV4ProofCodecError::ClaimCount)
        ));

        let mut bad_header = encoded.clone();
        bad_header[0] ^= 1;
        assert!(matches!(
            decode_forgematrix_v4_opening_reduction(&bad_header, 1),
            Err(ForgeMatrixV4ProofCodecError::Header)
        ));
        let mut bad_version = encoded.clone();
        bad_version[8] ^= 1;
        assert!(matches!(
            decode_forgematrix_v4_opening_reduction(&bad_version, 1),
            Err(ForgeMatrixV4ProofCodecError::Version)
        ));
        let mut bad_field = encoded;
        bad_field[CODEC_HEADER_BYTES..CODEC_HEADER_BYTES + 4]
            .copy_from_slice(&FORGEMATRIX_V4_FIELD_MODULUS.to_le_bytes());
        assert!(matches!(
            decode_forgematrix_v4_opening_reduction(&bad_field, 1),
            Err(ForgeMatrixV4ProofCodecError::Field)
        ));
    }

    #[test]
    fn encoder_rejects_nonpinned_shapes_and_claim_counts() {
        let mut proof = structural_proof(1);
        proof.basefold.query_phase_openings_and_proofs.pop();
        assert_eq!(
            encode_forgematrix_v4_opening_reduction(&proof, 1),
            Err(ForgeMatrixV4ProofCodecError::Shape)
        );
        assert_eq!(
            forgematrix_v4_opening_reduction_encoded_len(3),
            Err(ForgeMatrixV4ProofCodecError::ClaimCount)
        );
    }
}
