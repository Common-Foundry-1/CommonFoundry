//! CPU-only BaseFold types and verifier primitives for ProductionV4.
//!
//! This module deliberately contains no CUDA dependency. The GPU prover must
//! produce exactly the transcript accepted by these CPU-owned routines.

use slop_algebra::{AbstractField, extension::BinomialExtensionField};
use slop_basefold::{BasefoldProof, BasefoldVerifier, FriConfig};
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
use slop_multilinear::{Mle, MleEval, Point};
use slop_sumcheck::{PartialSumcheckProof, partially_verify_sumcheck_proof};
use thiserror::Error;

use crate::{
    BlockChallenge, FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP,
    FORGEMATRIX_V4_BASEFOLD_POW_BITS, FORGEMATRIX_V4_BASEFOLD_QUERIES,
    FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES, FORGEMATRIX_V4_DYNAMIC_COLUMNS,
    FORGEMATRIX_V4_FIXED_COLUMNS, FORGEMATRIX_V4_MAX_OPENING_CLAIMS, FORGEMATRIX_V4_PROOF_VERSION,
    ForgeMatrixV4CandidateProof, PRODUCTION_V4_TESTNET_NETWORK_ID,
    forgematrix_v4_proof_system_digest,
};

const TRANSCRIPT_STATEMENT_DOMAIN: &str = "CommonFoundry/ForgeMatrix/V4/TranscriptStatement/v1";
const OPENING_REDUCTION_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/OpeningReduction/v2";

pub type ForgeMatrixV4Field = KoalaBear;
pub type ForgeMatrixV4Extension = BinomialExtensionField<ForgeMatrixV4Field, 4>;
pub type ForgeMatrixV4IopContext = KoalaBearDegree4Duplex;
pub type ForgeMatrixV4Digest = <ForgeMatrixV4IopContext as IopCtx>::Digest;
pub type ForgeMatrixV4Challenger = <ForgeMatrixV4IopContext as IopCtx>::Challenger;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgeMatrixV4TranscriptStatement {
    pub block: BlockChallenge,
    pub algorithm_version: u32,
    pub proof_version: u32,
    pub nonce: u64,
    pub proof_system_digest: [u8; 32],
    pub model_manifest_digest: [u8; 32],
    pub challenge_digest: [u8; 32],
    pub final_activation_digest: [u8; 32],
    pub work_digest: [u8; 32],
}

impl ForgeMatrixV4TranscriptStatement {
    pub fn from_candidate(
        block: &BlockChallenge,
        proof: &ForgeMatrixV4CandidateProof,
    ) -> Result<Self, ForgeMatrixV4VerifierError> {
        if block.network_id != PRODUCTION_V4_TESTNET_NETWORK_ID
            || proof.algorithm_version != FORGEMATRIX_V4_ALGORITHM_VERSION
            || proof.proof_version != FORGEMATRIX_V4_PROOF_VERSION
            || proof.proof_system_digest != forgematrix_v4_proof_system_digest()
        {
            return Err(ForgeMatrixV4VerifierError::Statement);
        }
        Ok(Self {
            block: *block,
            algorithm_version: proof.algorithm_version,
            proof_version: proof.proof_version,
            nonce: proof.nonce,
            proof_system_digest: proof.proof_system_digest,
            model_manifest_digest: proof.model_manifest_digest,
            challenge_digest: proof.challenge_digest,
            final_activation_digest: proof.final_activation_digest,
            work_digest: proof.work_digest,
        })
    }

    pub fn digest(self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(TRANSCRIPT_STATEMENT_DOMAIN);
        hasher.update(&1_u32.to_le_bytes());
        hasher.update(&self.block.network_id);
        hasher.update(&self.block.previous_block);
        hasher.update(&self.block.transaction_root);
        hasher.update(&self.block.height.to_le_bytes());
        hasher.update(&self.block.timestamp.to_le_bytes());
        hasher.update(&self.block.target);
        hasher.update(&self.algorithm_version.to_le_bytes());
        hasher.update(&self.proof_version.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.proof_system_digest);
        hasher.update(&self.model_manifest_digest);
        hasher.update(&self.challenge_digest);
        hasher.update(&self.final_activation_digest);
        hasher.update(&self.work_digest);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ForgeMatrixV4OpeningCommitment {
    Fixed = 0,
    Dynamic = 1,
}

#[derive(Clone, Debug)]
pub struct ForgeMatrixV4OpeningClaim {
    pub commitment: ForgeMatrixV4OpeningCommitment,
    pub column_point: Point<ForgeMatrixV4Extension>,
    pub row_point: Point<ForgeMatrixV4Extension>,
    pub value: ForgeMatrixV4Extension,
}

#[derive(Clone)]
pub struct ForgeMatrixV4OpeningReductionProof {
    pub sumcheck: PartialSumcheckProof<ForgeMatrixV4Extension>,
    pub fixed_column_evaluations: Vec<ForgeMatrixV4Extension>,
    pub dynamic_column_evaluations: Vec<ForgeMatrixV4Extension>,
    pub basefold: BasefoldProof<ForgeMatrixV4IopContext>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ForgeMatrixV4VerifierError {
    #[error("V4 public statement does not match the pinned proof system")]
    Statement,
    #[error("V4 opening reduction has an invalid shape")]
    OpeningShape,
    #[error("V4 opening reduction does not match the claimed value")]
    OpeningClaim,
    #[error("V4 opening reduction sumcheck failed")]
    OpeningSumcheck,
    #[error("V4 opening reduction terminal relation failed")]
    OpeningTerminal,
    #[error("V4 BaseFold opening failed")]
    Basefold,
}

pub fn forgematrix_v4_basefold_verifier() -> BasefoldVerifier<ForgeMatrixV4IopContext> {
    BasefoldVerifier::new(
        FriConfig::<ForgeMatrixV4Field>::new(
            FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP as usize,
            FORGEMATRIX_V4_BASEFOLD_QUERIES as usize,
            FORGEMATRIX_V4_BASEFOLD_POW_BITS as usize,
        ),
        2,
    )
}

pub fn forgematrix_v4_transcript(
    statement: ForgeMatrixV4TranscriptStatement,
) -> ForgeMatrixV4Challenger {
    let mut challenger = ForgeMatrixV4IopContext::default_challenger();
    observe_bytes(&mut challenger, &statement.digest());
    challenger
}

pub fn verify_forgematrix_v4_opening_reduction(
    commitments: [ForgeMatrixV4Digest; 2],
    claims: &[ForgeMatrixV4OpeningClaim],
    proof: &ForgeMatrixV4OpeningReductionProof,
    challenger: &mut ForgeMatrixV4Challenger,
) -> Result<(), ForgeMatrixV4VerifierError> {
    if claims.is_empty()
        || !claims.len().is_power_of_two()
        || claims.len() > FORGEMATRIX_V4_MAX_OPENING_CLAIMS
        || proof.fixed_column_evaluations.len() != FORGEMATRIX_V4_FIXED_COLUMNS
        || proof.dynamic_column_evaluations.len() != FORGEMATRIX_V4_DYNAMIC_COLUMNS
    {
        return Err(ForgeMatrixV4VerifierError::OpeningShape);
    }

    let fixed_column_variables = FORGEMATRIX_V4_FIXED_COLUMNS.ilog2() as usize;
    let dynamic_column_variables = FORGEMATRIX_V4_DYNAMIC_COLUMNS.ilog2() as usize;
    if claims.iter().any(|claim| {
        claim.row_point.dimension() != FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize
            || claim.column_point.dimension()
                != match claim.commitment {
                    ForgeMatrixV4OpeningCommitment::Fixed => fixed_column_variables,
                    ForgeMatrixV4OpeningCommitment::Dynamic => dynamic_column_variables,
                }
    }) {
        return Err(ForgeMatrixV4VerifierError::OpeningShape);
    }

    observe_bytes(challenger, OPENING_REDUCTION_DOMAIN);
    challenger.observe(commitments[0]);
    challenger.observe(commitments[1]);
    challenger.observe(ForgeMatrixV4Field::from_canonical_usize(claims.len()));
    for claim in claims {
        challenger.observe(ForgeMatrixV4Field::from_canonical_u8(
            claim.commitment as u8,
        ));
        for &coordinate in claim.column_point.iter() {
            challenger.observe_ext_element(coordinate);
        }
        for &coordinate in claim.row_point.iter() {
            challenger.observe_ext_element(coordinate);
        }
        challenger.observe_ext_element(claim.value);
    }

    let powers = rlc_powers(challenger.sample_ext_element(), claims.len());
    let expected_claim = claims
        .iter()
        .zip(&powers)
        .map(|(claim, &power)| claim.value * power)
        .sum::<ForgeMatrixV4Extension>();
    if proof.sumcheck.claimed_sum != expected_claim {
        return Err(ForgeMatrixV4VerifierError::OpeningClaim);
    }

    partially_verify_sumcheck_proof(
        &proof.sumcheck,
        challenger,
        FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize,
        2,
    )
    .map_err(|_| ForgeMatrixV4VerifierError::OpeningSumcheck)?;

    let opening_point = &proof.sumcheck.point_and_eval.0;
    let expected_terminal = opening_terminal_evaluation(
        claims,
        &powers,
        &proof.fixed_column_evaluations,
        &proof.dynamic_column_evaluations,
        opening_point,
    )?;
    if proof.sumcheck.point_and_eval.1 != expected_terminal {
        return Err(ForgeMatrixV4VerifierError::OpeningTerminal);
    }

    forgematrix_v4_basefold_verifier()
        .verify_mle_evaluations(
            &commitments,
            opening_point.clone(),
            &[
                MleEval::from(proof.fixed_column_evaluations.clone()),
                MleEval::from(proof.dynamic_column_evaluations.clone()),
            ],
            &proof.basefold,
            challenger,
        )
        .map_err(|_| ForgeMatrixV4VerifierError::Basefold)
}

fn observe_bytes(challenger: &mut ForgeMatrixV4Challenger, bytes: &[u8]) {
    challenger.observe(ForgeMatrixV4Field::from_canonical_usize(bytes.len()));
    for &byte in bytes {
        challenger.observe(ForgeMatrixV4Field::from_canonical_u8(byte));
    }
}

fn rlc_powers(lambda: ForgeMatrixV4Extension, count: usize) -> Vec<ForgeMatrixV4Extension> {
    let mut powers = vec![ForgeMatrixV4Extension::one(); count];
    for index in (0..count - 1).rev() {
        powers[index] = powers[index + 1] * lambda;
    }
    powers
}

fn evaluate_columns(
    evaluations: &[ForgeMatrixV4Extension],
    point: &Point<ForgeMatrixV4Extension>,
) -> ForgeMatrixV4Extension {
    let equality = Mle::<ForgeMatrixV4Extension>::partial_lagrange(point);
    evaluations
        .iter()
        .zip(equality.guts().as_slice())
        .map(|(&value, &coefficient)| value * coefficient)
        .sum()
}

fn equality_evaluation(
    left: &Point<ForgeMatrixV4Extension>,
    right: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4VerifierError> {
    if left.dimension() != right.dimension() {
        return Err(ForgeMatrixV4VerifierError::OpeningShape);
    }
    Ok(left.iter().zip(right.iter()).fold(
        ForgeMatrixV4Extension::one(),
        |accumulator, (&left, &right)| {
            accumulator
                * ((ForgeMatrixV4Extension::one() - left) * (ForgeMatrixV4Extension::one() - right)
                    + left * right)
        },
    ))
}

fn opening_terminal_evaluation(
    claims: &[ForgeMatrixV4OpeningClaim],
    powers: &[ForgeMatrixV4Extension],
    fixed_evaluations: &[ForgeMatrixV4Extension],
    dynamic_evaluations: &[ForgeMatrixV4Extension],
    opening_point: &Point<ForgeMatrixV4Extension>,
) -> Result<ForgeMatrixV4Extension, ForgeMatrixV4VerifierError> {
    if claims.len() != powers.len() {
        return Err(ForgeMatrixV4VerifierError::OpeningShape);
    }
    claims
        .iter()
        .zip(powers)
        .map(|(claim, &power)| {
            let evaluations = match claim.commitment {
                ForgeMatrixV4OpeningCommitment::Fixed => fixed_evaluations,
                ForgeMatrixV4OpeningCommitment::Dynamic => dynamic_evaluations,
            };
            Ok(power
                * evaluate_columns(evaluations, &claim.column_point)
                * equality_evaluation(&claim.row_point, opening_point)?)
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use slop_algebra::PrimeField32;
    use slop_challenger::IopCtx;

    use super::*;
    use crate::{FORGEMATRIX_V4_EXTENSION_DEGREE, FORGEMATRIX_V4_FIELD_MODULUS};

    #[test]
    fn cpu_verifier_types_match_the_pinned_v4_field() {
        assert_eq!(ForgeMatrixV4Field::ORDER_U32, FORGEMATRIX_V4_FIELD_MODULUS);
        assert_eq!(
            std::mem::size_of::<ForgeMatrixV4Extension>(),
            FORGEMATRIX_V4_EXTENSION_DEGREE as usize * std::mem::size_of::<ForgeMatrixV4Field>()
        );
        let _challenger = ForgeMatrixV4IopContext::default_challenger();
        let _verifier = forgematrix_v4_basefold_verifier();
    }

    fn statement() -> ForgeMatrixV4TranscriptStatement {
        ForgeMatrixV4TranscriptStatement {
            block: BlockChallenge {
                network_id: PRODUCTION_V4_TESTNET_NETWORK_ID,
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
        }
    }

    #[test]
    fn transcript_statement_digest_is_pinned_and_binds_every_field() {
        let baseline = statement();
        let expected = baseline.digest();
        assert_eq!(
            hex::encode(expected),
            "002250105d30d659aac43c74d10bc12f8b8105fcb7ff4de4bfc2bed634b15939"
        );

        let mutations: [fn(&mut ForgeMatrixV4TranscriptStatement); 14] = [
            |value| value.block.network_id[0] ^= 1,
            |value| value.block.previous_block[0] ^= 1,
            |value| value.block.transaction_root[0] ^= 1,
            |value| value.block.height ^= 1,
            |value| value.block.timestamp ^= 1,
            |value| value.block.target[0] ^= 1,
            |value| value.algorithm_version ^= 1,
            |value| value.proof_version ^= 1,
            |value| value.nonce ^= 1,
            |value| value.proof_system_digest[0] ^= 1,
            |value| value.model_manifest_digest[0] ^= 1,
            |value| value.challenge_digest[0] ^= 1,
            |value| value.final_activation_digest[0] ^= 1,
            |value| value.work_digest[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = baseline;
            mutate(&mut changed);
            assert_ne!(changed.digest(), expected);
        }
    }

    #[test]
    fn candidate_transcript_requires_the_isolated_pinned_statement() {
        let statement = statement();
        let mut proof = ForgeMatrixV4CandidateProof {
            algorithm_version: statement.algorithm_version,
            proof_version: statement.proof_version,
            nonce: statement.nonce,
            proof_system_digest: statement.proof_system_digest,
            model_manifest_digest: statement.model_manifest_digest,
            challenge_digest: statement.challenge_digest,
            final_activation_digest: statement.final_activation_digest,
            work_digest: statement.work_digest,
            transparent_proof: vec![1],
        };
        assert_eq!(
            ForgeMatrixV4TranscriptStatement::from_candidate(&statement.block, &proof).unwrap(),
            statement
        );
        proof.proof_system_digest[0] ^= 1;
        assert_eq!(
            ForgeMatrixV4TranscriptStatement::from_candidate(&statement.block, &proof),
            Err(ForgeMatrixV4VerifierError::Statement)
        );
    }

    fn dummy_reduction_proof() -> ForgeMatrixV4OpeningReductionProof {
        ForgeMatrixV4OpeningReductionProof {
            sumcheck: PartialSumcheckProof::dummy(),
            fixed_column_evaluations: vec![
                ForgeMatrixV4Extension::zero();
                FORGEMATRIX_V4_FIXED_COLUMNS
            ],
            dynamic_column_evaluations: vec![
                ForgeMatrixV4Extension::zero();
                FORGEMATRIX_V4_DYNAMIC_COLUMNS
            ],
            basefold: BasefoldProof {
                univariate_messages: Vec::new(),
                fri_commitments: Vec::new(),
                component_polynomials_query_openings_and_proofs: Vec::new(),
                query_phase_openings_and_proofs: Vec::new(),
                final_poly: ForgeMatrixV4Extension::zero(),
                pow_witness: ForgeMatrixV4Field::zero(),
                batch_grinding_witness: ForgeMatrixV4Field::zero(),
            },
        }
    }

    fn opening_claim() -> ForgeMatrixV4OpeningClaim {
        ForgeMatrixV4OpeningClaim {
            commitment: ForgeMatrixV4OpeningCommitment::Fixed,
            column_point: Point::from(vec![
                ForgeMatrixV4Extension::zero();
                FORGEMATRIX_V4_FIXED_COLUMNS.ilog2() as usize
            ]),
            row_point: Point::from(vec![
                ForgeMatrixV4Extension::zero();
                FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize
            ]),
            value: ForgeMatrixV4Extension::zero(),
        }
    }

    #[test]
    fn opening_reduction_rejects_untrusted_shapes_before_basefold() {
        let commitments = [[ForgeMatrixV4Field::zero(); 8]; 2];
        let proof = dummy_reduction_proof();
        let mut challenger = forgematrix_v4_transcript(statement());
        assert_eq!(
            verify_forgematrix_v4_opening_reduction(commitments, &[], &proof, &mut challenger,),
            Err(ForgeMatrixV4VerifierError::OpeningShape)
        );

        let mut claims = vec![opening_claim(); 3];
        let mut challenger = forgematrix_v4_transcript(statement());
        assert_eq!(
            verify_forgematrix_v4_opening_reduction(commitments, &claims, &proof, &mut challenger,),
            Err(ForgeMatrixV4VerifierError::OpeningShape)
        );

        claims = vec![opening_claim(); FORGEMATRIX_V4_MAX_OPENING_CLAIMS * 2];
        let mut challenger = forgematrix_v4_transcript(statement());
        assert_eq!(
            verify_forgematrix_v4_opening_reduction(commitments, &claims, &proof, &mut challenger,),
            Err(ForgeMatrixV4VerifierError::OpeningShape)
        );

        let mut bad_claim = opening_claim();
        bad_claim.column_point = Point::from(vec![ForgeMatrixV4Extension::zero(); 7]);
        let mut challenger = forgematrix_v4_transcript(statement());
        assert_eq!(
            verify_forgematrix_v4_opening_reduction(
                commitments,
                &[bad_claim],
                &proof,
                &mut challenger,
            ),
            Err(ForgeMatrixV4VerifierError::OpeningShape)
        );

        let mut bad_proof = dummy_reduction_proof();
        bad_proof.fixed_column_evaluations.pop();
        let mut challenger = forgematrix_v4_transcript(statement());
        assert_eq!(
            verify_forgematrix_v4_opening_reduction(
                commitments,
                &[opening_claim()],
                &bad_proof,
                &mut challenger,
            ),
            Err(ForgeMatrixV4VerifierError::OpeningShape)
        );
    }

    #[test]
    fn direct_row_rlc_terminal_sums_each_claim_without_selector_variables() {
        let row_zero = Point::from(vec![
            ForgeMatrixV4Extension::zero();
            FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize
        ]);
        let row_one = Point::from(vec![
            ForgeMatrixV4Extension::one();
            FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES as usize
        ]);
        let claims = [
            ForgeMatrixV4OpeningClaim {
                commitment: ForgeMatrixV4OpeningCommitment::Fixed,
                column_point: Point::from(vec![
                    ForgeMatrixV4Extension::zero();
                    FORGEMATRIX_V4_FIXED_COLUMNS.ilog2() as usize
                ]),
                row_point: row_zero.clone(),
                value: ForgeMatrixV4Extension::zero(),
            },
            ForgeMatrixV4OpeningClaim {
                commitment: ForgeMatrixV4OpeningCommitment::Dynamic,
                column_point: Point::from(vec![
                    ForgeMatrixV4Extension::zero();
                    FORGEMATRIX_V4_DYNAMIC_COLUMNS.ilog2() as usize
                ]),
                row_point: row_one,
                value: ForgeMatrixV4Extension::zero(),
            },
        ];
        let fixed =
            vec![ForgeMatrixV4Extension::from_canonical_u8(2); FORGEMATRIX_V4_FIXED_COLUMNS];
        let dynamic =
            vec![ForgeMatrixV4Extension::from_canonical_u8(3); FORGEMATRIX_V4_DYNAMIC_COLUMNS];
        let powers = [
            ForgeMatrixV4Extension::from_canonical_u8(5),
            ForgeMatrixV4Extension::from_canonical_u8(7),
        ];
        assert_eq!(
            opening_terminal_evaluation(&claims, &powers, &fixed, &dynamic, &row_zero).unwrap(),
            ForgeMatrixV4Extension::from_canonical_u8(10)
        );
    }
}
