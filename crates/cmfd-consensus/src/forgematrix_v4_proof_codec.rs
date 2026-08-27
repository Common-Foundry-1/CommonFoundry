//! Exact, allocation-bounded codec for one complete ProductionV4 proof.

use slop_algebra::{AbstractExtensionField, AbstractField, PrimeField32, UnivariatePolynomial};
use slop_multilinear::Point;
use slop_sumcheck::PartialSumcheckProof;
use thiserror::Error;

use crate::{
    FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE, FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
    FORGEMATRIX_V4_EXTENSION_DEGREE, FORGEMATRIX_V4_FIELD_MODULUS,
    FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE, FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
    FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK, FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES,
    FORGEMATRIX_V4_RELATION_REPETITIONS, FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
    FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
    forgematrix_v2::PRODUCTION_V2_BANKS,
    forgematrix_v4_basefold::{ForgeMatrixV4Digest, ForgeMatrixV4Extension, ForgeMatrixV4Field},
    forgematrix_v4_basefold_codec::{
        FORGEMATRIX_V4_OPENING_REDUCTION_MAX_BYTES, ForgeMatrixV4ProofCodecError,
        decode_forgematrix_v4_opening_reduction, encode_forgematrix_v4_opening_reduction,
    },
    forgematrix_v4_proof::{
        ForgeMatrixV4BankProof, ForgeMatrixV4RelationRepetitionProof, ForgeMatrixV4TransparentProof,
    },
    forgematrix_v4_relations::{
        ForgeMatrixV4CubicRelationProof, ForgeMatrixV4MatrixRelationProof,
        ForgeMatrixV4ShiftRelationProof,
    },
};

const CODEC_MAGIC: [u8; 8] = *b"CMV4PF01";
const CODEC_VERSION: u32 = 1;
const CODEC_HEADER_BYTES: usize = 16;
const DIGEST_FIELDS: usize = 8;
const DIGEST_BYTES: usize = DIGEST_FIELDS * 4;
const EXTENSION_BYTES: usize = FORGEMATRIX_V4_EXTENSION_DEGREE as usize * 4;
const MATRIX_PROOF_BYTES: usize = sumcheck_bytes(
    FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
    FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
) + 3 * EXTENSION_BYTES;
const SHIFT_PROOF_BYTES: usize = sumcheck_bytes(
    FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
    FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
) + 2 * EXTENSION_BYTES;
const CUBIC_PROOF_BYTES: usize = sumcheck_bytes(
    FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
    FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE,
) + 2 * EXTENSION_BYTES;
const RELATION_REPETITION_BYTES: usize = MATRIX_PROOF_BYTES + SHIFT_PROOF_BYTES + CUBIC_PROOF_BYTES;
const BANK_RELATIONS_BYTES: usize =
    FORGEMATRIX_V4_RELATION_REPETITIONS as usize * RELATION_REPETITION_BYTES;

pub const FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES: usize = CODEC_HEADER_BYTES
    + FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES
    + PRODUCTION_V2_BANKS as usize
        * (DIGEST_BYTES + BANK_RELATIONS_BYTES + FORGEMATRIX_V4_OPENING_REDUCTION_MAX_BYTES);

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ForgeMatrixV4TransparentCodecError {
    #[error("V4 transparent proof has an invalid codec header")]
    Header,
    #[error("V4 transparent proof uses an unsupported codec version")]
    Version,
    #[error("V4 transparent proof has the wrong exact byte length")]
    Length,
    #[error("V4 transparent proof contains a noncanonical field element")]
    Field,
    #[error("V4 transparent proof does not have the pinned topology")]
    Shape,
    #[error("V4 transparent proof contains an invalid bank opening: {0}")]
    Opening(ForgeMatrixV4ProofCodecError),
}

pub fn encode_forgematrix_v4_transparent_proof(
    proof: &ForgeMatrixV4TransparentProof,
) -> Result<Vec<u8>, ForgeMatrixV4TransparentCodecError> {
    validate_shape(proof)?;
    let mut bytes = Vec::with_capacity(FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES);
    bytes.extend_from_slice(&CODEC_MAGIC);
    bytes.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    bytes.extend_from_slice(&PRODUCTION_V2_BANKS.to_le_bytes());
    for &value in &proof.final_activation {
        write_field(&mut bytes, value);
    }
    for bank in &proof.banks {
        write_digest(&mut bytes, &bank.dynamic_commitment);
        for relation in &bank.relations {
            write_relation(&mut bytes, relation);
        }
        bytes.extend_from_slice(
            &encode_forgematrix_v4_opening_reduction(
                &bank.opening,
                FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK,
            )
            .map_err(ForgeMatrixV4TransparentCodecError::Opening)?,
        );
    }
    if bytes.len() != FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES {
        return Err(ForgeMatrixV4TransparentCodecError::Shape);
    }
    Ok(bytes)
}

pub fn decode_forgematrix_v4_transparent_proof(
    bytes: &[u8],
) -> Result<ForgeMatrixV4TransparentProof, ForgeMatrixV4TransparentCodecError> {
    if bytes.len() != FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES {
        return Err(ForgeMatrixV4TransparentCodecError::Length);
    }
    if bytes[..8] != CODEC_MAGIC {
        return Err(ForgeMatrixV4TransparentCodecError::Header);
    }
    if u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ForgeMatrixV4TransparentCodecError::Length)?,
    ) != CODEC_VERSION
    {
        return Err(ForgeMatrixV4TransparentCodecError::Version);
    }
    if u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| ForgeMatrixV4TransparentCodecError::Length)?,
    ) != PRODUCTION_V2_BANKS
    {
        return Err(ForgeMatrixV4TransparentCodecError::Shape);
    }

    let mut reader = Reader::new(&bytes[CODEC_HEADER_BYTES..]);
    let final_fields = FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES
        .checked_div(std::mem::size_of::<u32>())
        .ok_or(ForgeMatrixV4TransparentCodecError::Shape)?;
    let final_activation = reader.fields(final_fields)?;
    let mut banks = Vec::with_capacity(PRODUCTION_V2_BANKS as usize);
    for _ in 0..PRODUCTION_V2_BANKS {
        let dynamic_commitment = reader.digest()?;
        let mut relations = Vec::with_capacity(FORGEMATRIX_V4_RELATION_REPETITIONS as usize);
        for _ in 0..FORGEMATRIX_V4_RELATION_REPETITIONS {
            relations.push(reader.relation()?);
        }
        let opening_bytes = reader.take(FORGEMATRIX_V4_OPENING_REDUCTION_MAX_BYTES)?;
        let opening = decode_forgematrix_v4_opening_reduction(
            opening_bytes,
            FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK,
        )
        .map_err(ForgeMatrixV4TransparentCodecError::Opening)?;
        banks.push(ForgeMatrixV4BankProof {
            dynamic_commitment,
            relations: relations
                .try_into()
                .map_err(|_| ForgeMatrixV4TransparentCodecError::Shape)?,
            opening,
        });
    }
    if !reader.is_empty() {
        return Err(ForgeMatrixV4TransparentCodecError::Length);
    }
    let proof = ForgeMatrixV4TransparentProof {
        final_activation,
        banks: banks
            .try_into()
            .map_err(|_| ForgeMatrixV4TransparentCodecError::Shape)?,
    };
    validate_shape(&proof)?;
    Ok(proof)
}

fn write_relation(bytes: &mut Vec<u8>, relation: &ForgeMatrixV4RelationRepetitionProof) {
    write_sumcheck(bytes, &relation.matrix.sumcheck);
    write_extension(bytes, &relation.matrix.preactivation_evaluation);
    write_extension(bytes, &relation.matrix.weight_evaluation);
    write_extension(bytes, &relation.matrix.input_evaluation);
    write_sumcheck(bytes, &relation.shift.sumcheck);
    write_extension(bytes, &relation.shift.boundary_evaluation);
    write_extension(bytes, &relation.shift.next_activation_evaluation);
    write_sumcheck(bytes, &relation.cubic.sumcheck);
    write_extension(bytes, &relation.cubic.preactivation_evaluation);
    write_extension(bytes, &relation.cubic.next_activation_evaluation);
}

fn validate_shape(
    proof: &ForgeMatrixV4TransparentProof,
) -> Result<(), ForgeMatrixV4TransparentCodecError> {
    if proof
        .final_activation
        .len()
        .checked_mul(std::mem::size_of::<u32>())
        != Some(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES)
    {
        return Err(ForgeMatrixV4TransparentCodecError::Shape);
    }
    for bank in &proof.banks {
        for relation in &bank.relations {
            validate_sumcheck(
                &relation.matrix.sumcheck,
                FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
            )?;
            validate_sumcheck(
                &relation.shift.sumcheck,
                FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
            )?;
            validate_sumcheck(
                &relation.cubic.sumcheck,
                FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE,
            )?;
        }
        encode_forgematrix_v4_opening_reduction(
            &bank.opening,
            FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK,
        )
        .map_err(ForgeMatrixV4TransparentCodecError::Opening)?;
    }
    Ok(())
}

fn validate_sumcheck(
    proof: &PartialSumcheckProof<ForgeMatrixV4Extension>,
    variables: usize,
    degree: usize,
) -> Result<(), ForgeMatrixV4TransparentCodecError> {
    if proof.univariate_polys.len() != variables
        || proof
            .univariate_polys
            .iter()
            .any(|polynomial| polynomial.coefficients.len() != degree + 1)
        || proof.point_and_eval.0.dimension() != variables
    {
        return Err(ForgeMatrixV4TransparentCodecError::Shape);
    }
    Ok(())
}

fn write_sumcheck(bytes: &mut Vec<u8>, proof: &PartialSumcheckProof<ForgeMatrixV4Extension>) {
    for polynomial in &proof.univariate_polys {
        for value in &polynomial.coefficients {
            write_extension(bytes, value);
        }
    }
    write_extension(bytes, &proof.claimed_sum);
    for value in proof.point_and_eval.0.iter() {
        write_extension(bytes, value);
    }
    write_extension(bytes, &proof.point_and_eval.1);
}

fn write_field(bytes: &mut Vec<u8>, value: ForgeMatrixV4Field) {
    bytes.extend_from_slice(&value.as_canonical_u32().to_le_bytes());
}

fn write_extension(bytes: &mut Vec<u8>, value: &ForgeMatrixV4Extension) {
    for &coefficient in value.as_base_slice() {
        write_field(bytes, coefficient);
    }
}

fn write_digest(bytes: &mut Vec<u8>, digest: &ForgeMatrixV4Digest) {
    for &value in digest {
        write_field(bytes, value);
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

    fn take(&mut self, count: usize) -> Result<&'a [u8], ForgeMatrixV4TransparentCodecError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(ForgeMatrixV4TransparentCodecError::Length)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ForgeMatrixV4TransparentCodecError::Length)?;
        self.position = end;
        Ok(value)
    }

    fn field(&mut self) -> Result<ForgeMatrixV4Field, ForgeMatrixV4TransparentCodecError> {
        let value = u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ForgeMatrixV4TransparentCodecError::Length)?,
        );
        if value >= FORGEMATRIX_V4_FIELD_MODULUS {
            return Err(ForgeMatrixV4TransparentCodecError::Field);
        }
        Ok(ForgeMatrixV4Field::from_canonical_u32(value))
    }

    fn fields(
        &mut self,
        count: usize,
    ) -> Result<Vec<ForgeMatrixV4Field>, ForgeMatrixV4TransparentCodecError> {
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.field()?);
        }
        Ok(values)
    }

    fn extension(&mut self) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4TransparentCodecError> {
        Ok(ForgeMatrixV4Extension::from_base_slice(&[
            self.field()?,
            self.field()?,
            self.field()?,
            self.field()?,
        ]))
    }

    fn digest(&mut self) -> Result<ForgeMatrixV4Digest, ForgeMatrixV4TransparentCodecError> {
        let mut digest = [ForgeMatrixV4Field::zero(); DIGEST_FIELDS];
        for value in &mut digest {
            *value = self.field()?;
        }
        Ok(digest)
    }

    fn sumcheck(
        &mut self,
        variables: usize,
        degree: usize,
    ) -> Result<PartialSumcheckProof<ForgeMatrixV4Extension>, ForgeMatrixV4TransparentCodecError>
    {
        let mut univariate_polys = Vec::with_capacity(variables);
        for _ in 0..variables {
            let mut coefficients = Vec::with_capacity(degree + 1);
            for _ in 0..=degree {
                coefficients.push(self.extension()?);
            }
            univariate_polys.push(UnivariatePolynomial::new(coefficients));
        }
        Ok(PartialSumcheckProof {
            univariate_polys,
            claimed_sum: self.extension()?,
            point_and_eval: (
                Point::from(
                    (0..variables)
                        .map(|_| self.extension())
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                self.extension()?,
            ),
        })
    }

    fn relation(
        &mut self,
    ) -> Result<ForgeMatrixV4RelationRepetitionProof, ForgeMatrixV4TransparentCodecError> {
        let matrix = ForgeMatrixV4MatrixRelationProof {
            sumcheck: self.sumcheck(
                FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
            )?,
            preactivation_evaluation: self.extension()?,
            weight_evaluation: self.extension()?,
            input_evaluation: self.extension()?,
        };
        let shift = ForgeMatrixV4ShiftRelationProof {
            sumcheck: self.sumcheck(
                FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
            )?,
            boundary_evaluation: self.extension()?,
            next_activation_evaluation: self.extension()?,
        };
        let cubic = ForgeMatrixV4CubicRelationProof {
            sumcheck: self.sumcheck(
                FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE,
            )?,
            preactivation_evaluation: self.extension()?,
            next_activation_evaluation: self.extension()?,
        };
        Ok(ForgeMatrixV4RelationRepetitionProof {
            matrix,
            shift,
            cubic,
        })
    }
}

const fn sumcheck_bytes(variables: usize, degree: usize) -> usize {
    (variables * (degree + 1) + variables + 2) * EXTENSION_BYTES
}

const _: () = assert!(EXTENSION_BYTES == 16);
const _: () = assert!(DIGEST_BYTES == 32);
const _: () = assert!(MATRIX_PROOF_BYTES == 1_600);
const _: () = assert!(SHIFT_PROOF_BYTES == 512);
const _: () = assert!(CUBIC_PROOF_BYTES == 2_560);
const _: () = assert!(RELATION_REPETITION_BYTES == 4_672);
const _: () = assert!(FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES == 12_025_320);

#[cfg(test)]
mod tests {
    use slop_basefold::BasefoldProof;
    use slop_merkle_tree::{MerkleTreeOpeningAndProof, MerkleTreeTcsProof};
    use slop_tensor::{Dimensions, Tensor};

    use super::*;
    use crate::{
        FORGEMATRIX_V4_BASEFOLD_QUERIES, FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES,
        FORGEMATRIX_V4_DYNAMIC_COLUMNS, FORGEMATRIX_V4_FIXED_COLUMNS,
        MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
        forgematrix_v4_basefold::{ForgeMatrixV4IopContext, ForgeMatrixV4OpeningReductionProof},
    };

    const COMPONENT_LOG_HEIGHT: usize = FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize + 1;
    const QUERY_WIDTH: usize = 8;

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

    fn zero_sumcheck(
        variables: usize,
        degree: usize,
    ) -> PartialSumcheckProof<ForgeMatrixV4Extension> {
        PartialSumcheckProof {
            univariate_polys: (0..variables)
                .map(|_| {
                    UnivariatePolynomial::new(vec![ForgeMatrixV4Extension::zero(); degree + 1])
                })
                .collect(),
            claimed_sum: ForgeMatrixV4Extension::zero(),
            point_and_eval: (
                Point::from(vec![ForgeMatrixV4Extension::zero(); variables]),
                ForgeMatrixV4Extension::zero(),
            ),
        }
    }

    fn structural_opening() -> ForgeMatrixV4OpeningReductionProof {
        let variables = FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize;
        let mut query_openings = Vec::with_capacity(FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize);
        for index in 0..FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize {
            query_openings.push(zero_opening(
                QUERY_WIDTH,
                FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize - index,
            ));
        }
        ForgeMatrixV4OpeningReductionProof {
            sumcheck: zero_sumcheck(variables, 2),
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

    fn structural_relation() -> ForgeMatrixV4RelationRepetitionProof {
        ForgeMatrixV4RelationRepetitionProof {
            matrix: ForgeMatrixV4MatrixRelationProof {
                sumcheck: zero_sumcheck(
                    FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
                    FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
                ),
                preactivation_evaluation: ForgeMatrixV4Extension::zero(),
                weight_evaluation: ForgeMatrixV4Extension::zero(),
                input_evaluation: ForgeMatrixV4Extension::zero(),
            },
            shift: ForgeMatrixV4ShiftRelationProof {
                sumcheck: zero_sumcheck(
                    FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
                    FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
                ),
                boundary_evaluation: ForgeMatrixV4Extension::zero(),
                next_activation_evaluation: ForgeMatrixV4Extension::zero(),
            },
            cubic: ForgeMatrixV4CubicRelationProof {
                sumcheck: zero_sumcheck(
                    FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
                    FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE,
                ),
                preactivation_evaluation: ForgeMatrixV4Extension::zero(),
                next_activation_evaluation: ForgeMatrixV4Extension::zero(),
            },
        }
    }

    fn structural_proof() -> ForgeMatrixV4TransparentProof {
        ForgeMatrixV4TransparentProof {
            final_activation: vec![
                ForgeMatrixV4Field::zero();
                FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES / 4
            ],
            banks: std::array::from_fn(|_| ForgeMatrixV4BankProof {
                dynamic_commitment: [ForgeMatrixV4Field::zero(); DIGEST_FIELDS],
                relations: std::array::from_fn(|_| structural_relation()),
                opening: structural_opening(),
            }),
        }
    }

    #[test]
    fn complete_proof_round_trips_with_one_exact_bounded_topology() {
        let proof = structural_proof();
        let encoded = encode_forgematrix_v4_transparent_proof(&proof).unwrap();
        assert_eq!(encoded.len(), FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES);
        assert!(encoded.len() <= MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES);
        let decoded = decode_forgematrix_v4_transparent_proof(&encoded).unwrap();
        assert_eq!(
            encode_forgematrix_v4_transparent_proof(&decoded).unwrap(),
            encoded
        );
    }

    #[test]
    fn complete_proof_rejects_framing_fields_and_noncanonical_values() {
        let encoded = encode_forgematrix_v4_transparent_proof(&structural_proof()).unwrap();
        assert!(matches!(
            decode_forgematrix_v4_transparent_proof(&encoded[..encoded.len() - 1]),
            Err(ForgeMatrixV4TransparentCodecError::Length)
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_forgematrix_v4_transparent_proof(&trailing),
            Err(ForgeMatrixV4TransparentCodecError::Length)
        ));
        for (offset, expected) in [
            (0, ForgeMatrixV4TransparentCodecError::Header),
            (8, ForgeMatrixV4TransparentCodecError::Version),
            (12, ForgeMatrixV4TransparentCodecError::Shape),
        ] {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 1;
            assert!(matches!(
                decode_forgematrix_v4_transparent_proof(&mutated),
                Err(actual) if actual == expected
            ));
        }
        let mut noncanonical = encoded;
        noncanonical[CODEC_HEADER_BYTES..CODEC_HEADER_BYTES + 4]
            .copy_from_slice(&FORGEMATRIX_V4_FIELD_MODULUS.to_le_bytes());
        assert!(matches!(
            decode_forgematrix_v4_transparent_proof(&noncanonical),
            Err(ForgeMatrixV4TransparentCodecError::Field)
        ));
    }

    #[test]
    fn encoder_rejects_relation_and_opening_shape_mutations() {
        let mut relation = structural_proof();
        relation.banks[0].relations[0]
            .matrix
            .sumcheck
            .univariate_polys
            .pop();
        assert_eq!(
            encode_forgematrix_v4_transparent_proof(&relation),
            Err(ForgeMatrixV4TransparentCodecError::Shape)
        );

        let mut opening = structural_proof();
        opening.banks[2]
            .opening
            .basefold
            .query_phase_openings_and_proofs
            .pop();
        assert!(matches!(
            encode_forgematrix_v4_transparent_proof(&opening),
            Err(ForgeMatrixV4TransparentCodecError::Opening(
                ForgeMatrixV4ProofCodecError::Shape
            ))
        ));
    }
}
