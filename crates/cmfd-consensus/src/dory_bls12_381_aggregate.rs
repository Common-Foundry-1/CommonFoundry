//! Bounded distinct-point opening aggregation over the BLS12-381 Dory backend.
//!
//! This module connects the deterministic BLS12-381 backend to the degree-two
//! sumcheck used by the earlier BN254 transport experiment. It remains
//! deliberately feature-gated and fail-closed for production activation.

use std::io::Cursor;

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    poly::Polynomial,
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use dory_pcs::proof::DoryProof;
use dory_pcs::{
    FirstReduceMessage, ScalarProductMessage, SecondReduceMessage, Transparent, VMVMessage, prove,
    verify,
};
use thiserror::Error;

use crate::dory_bls12_381_prototype::{
    BlsDoryCurve, BlsDoryFr, BlsDoryG1, BlsDoryG1Routines, BlsDoryG2, BlsDoryG2Routines, BlsDoryGt,
    BlsDoryPolynomial, BlsDoryTranscript, DeterministicBlsDorySetup,
    MAX_BLS_DORY_PROTOTYPE_VARIABLES,
};

/// Version of the bounded BLS12-381 aggregate wire grammar.
pub const BLS_DORY_AGGREGATE_VERSION: u16 = 1;
/// Maximum number of claims admitted by the research verifier.
pub const MAX_BLS_DORY_AGGREGATE_CLAIMS: usize = 128;
/// Same proof-payload ceiling enforced by the production candidate frame.
pub const MAX_BLS_DORY_AGGREGATE_BYTES: usize = 262_128;
/// This aggregate remains unavailable to consensus activation.
pub const BLS_DORY_AGGREGATE_PRODUCTION_READY: bool = false;
/// Remaining activation blockers after replacing BN254 and random setup.
pub const BLS_DORY_AGGREGATE_PRODUCTION_BLOCKERS: [&str; 4] = [
    "the matrix, successor-wiring, and packed LogUp arguments are not yet connected over the pairing scalar field",
    "the production n=31 polynomial is not streamed by this in-memory implementation",
    "the aggregate soundness bound has not been independently reviewed",
    "the replacement PCS and wire grammar have not received an external audit",
];

const WIRE_MAGIC: [u8; 8] = *b"CFDBLS01";
const WIRE_HEADER_BYTES: usize = 18;
const MAX_PUBLIC_BINDING_BYTES: usize = 4_096;

/// One public multilinear evaluation claim against a BLS12-381 Dory commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryOpeningClaim {
    pub commitment: BlsDoryGt,
    pub point: Vec<BlsDoryFr>,
    pub evaluation: BlsDoryFr,
}

/// A committed evaluation table retained only by the aggregate prover.
#[derive(Clone, Debug)]
pub struct BlsDoryCommittedPolynomial {
    coefficients: Vec<BlsDoryFr>,
    polynomial: BlsDoryPolynomial,
    commitment: BlsDoryGt,
    row_commitments: Vec<BlsDoryG1>,
    setup_identity: [u8; 32],
    nu: usize,
    sigma: usize,
}

impl BlsDoryCommittedPolynomial {
    /// Public tier-two commitment used by the opening statement.
    #[must_use]
    pub fn commitment(&self) -> BlsDoryGt {
        self.commitment
    }

    /// Number of variables in this evaluation table.
    #[must_use]
    pub fn variables(&self) -> usize {
        self.nu + self.sigma
    }
}

/// Errors returned by the non-production BLS aggregate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDoryAggregateError {
    #[error("the BLS12-381 Dory aggregate is not production ready")]
    NotProductionReady,
    #[error("public binding exceeds the aggregate limit")]
    PublicBindingTooLarge,
    #[error("claim count is outside the aggregate limit")]
    InvalidClaimCount,
    #[error("polynomial or point dimension is outside the aggregate limit")]
    InvalidDimension,
    #[error("polynomial coefficient count does not match its dimensions")]
    InvalidCoefficientCount,
    #[error("all aggregate inputs must use one setup identity and matrix layout")]
    MixedStatement,
    #[error("deterministic setup identity or verifier precomputation is inconsistent")]
    InvalidSetup,
    #[error("proof header or fixed shape is invalid")]
    InvalidProofShape,
    #[error("proof encoding is non-canonical or malformed")]
    InvalidEncoding,
    #[error("sumcheck relation failed")]
    SumcheckFailed,
    #[error("Dory operation failed: {0}")]
    Dory(String),
}

/// Fail closed until every documented production blocker is resolved.
pub fn require_bls_dory_aggregate_production_ready() -> Result<(), BlsDoryAggregateError> {
    Err(BlsDoryAggregateError::NotProductionReady)
}

/// Project the fixed aggregate grammar using compressed BLS12-381 elements.
///
/// This is wire accounting only; the in-memory prover remains capped at 16
/// variables and cannot yet execute the production n=31 shape.
pub fn projected_bls_dory_aggregate_bytes(
    variables: usize,
) -> Result<usize, BlsDoryAggregateError> {
    if variables == 0 || variables > 64 {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    Ok(aggregate_wire_bytes(variables, variables.div_ceil(2)))
}

/// Commit one bounded evaluation-form polynomial under the deterministic setup.
pub fn commit_bls_dory_polynomial(
    coefficients: Vec<BlsDoryFr>,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_layout(nu, sigma)?;
    let variables = nu + sigma;
    let expected = 1usize
        .checked_shl(variables as u32)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if coefficients.len() != expected {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    if setup.max_log_n() < variables
        || setup.prover().g1_vec.len() < (1usize << sigma)
        || setup.prover().g2_vec.len() < (1usize << nu)
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let polynomial = BlsDoryPolynomial::new(coefficients.clone())
        .map_err(|error| BlsDoryAggregateError::Dory(error.to_string()))?;
    let (commitment, row_commitments, blind) = polynomial
        .commit::<BlsDoryCurve, Transparent, BlsDoryG1Routines>(nu, sigma, setup.prover())
        .map_err(dory_error)?;
    if !blind.is_zero() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }

    Ok(BlsDoryCommittedPolynomial {
        coefficients,
        polynomial,
        commitment,
        row_commitments,
        setup_identity: setup.identity(),
        nu,
        sigma,
    })
}

/// Reduce distinct-point claims to one random point and prove one combined opening.
pub fn prove_bls_dory_openings(
    public_binding: &[u8],
    polynomials: &[BlsDoryCommittedPolynomial],
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    let polynomial_refs = polynomials.iter().collect::<Vec<_>>();
    prove_bls_dory_opening_refs(public_binding, &polynomial_refs, points, setup)
}

/// Prove many points of one commitment without cloning its coefficient table.
pub fn prove_bls_dory_same_commitment_openings(
    public_binding: &[u8],
    polynomial: &BlsDoryCommittedPolynomial,
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    let polynomial_refs = vec![polynomial; points.len()];
    prove_bls_dory_opening_refs(public_binding, &polynomial_refs, points, setup)
}

fn prove_bls_dory_opening_refs(
    public_binding: &[u8],
    polynomials: &[&BlsDoryCommittedPolynomial],
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_public_inputs(public_binding, polynomials.len())?;
    if polynomials.len() != points.len() {
        return Err(BlsDoryAggregateError::InvalidClaimCount);
    }
    let first = polynomials
        .first()
        .ok_or(BlsDoryAggregateError::InvalidClaimCount)?;
    let (nu, sigma) = (first.nu, first.sigma);
    validate_layout(nu, sigma)?;
    if setup.max_log_n() < nu + sigma
        || polynomials.iter().any(|polynomial| {
            polynomial.nu != nu
                || polynomial.sigma != sigma
                || polynomial.setup_identity != setup.identity()
        })
    {
        return Err(BlsDoryAggregateError::MixedStatement);
    }
    let variables = nu + sigma;
    if points.iter().any(|point| point.len() != variables) {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let claims = polynomials
        .iter()
        .zip(points)
        .map(|(polynomial, point)| BlsDoryOpeningClaim {
            commitment: polynomial.commitment,
            point: point.clone(),
            evaluation: polynomial.polynomial.evaluate(point),
        })
        .collect::<Vec<_>>();
    let mut transcript =
        statement_transcript(public_binding, &setup.identity(), &claims, nu, sigma)?;
    let batching = batching_challenges(&mut transcript, claims.len());
    let sumcheck = prove_distinct_point_sumcheck(polynomials, &claims, &batching, &mut transcript)?;

    let lambdas = batching
        .iter()
        .zip(&sumcheck.terminal.equality_values)
        .map(|(rho, equality)| *rho * equality)
        .collect::<Vec<_>>();
    let (combined_polynomial, combined_rows, combined_commitment) =
        combine_polynomials(polynomials, &lambdas, nu)?;

    append_combined_opening(
        &mut transcript,
        &combined_commitment,
        &sumcheck.terminal.random_point,
        &sumcheck.terminal.final_claim,
    );
    let (dory_proof, hidden_evaluation) =
        prove::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _, _, Transparent>(
            &combined_polynomial,
            &sumcheck.terminal.random_point,
            combined_rows,
            BlsDoryFr::zero(),
            nu,
            sigma,
            setup.prover(),
            &mut transcript,
        )
        .map_err(dory_error)?;
    if hidden_evaluation.is_some() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }

    let encoded = encode_aggregate_proof(
        claims.len(),
        variables,
        nu,
        sigma,
        &sumcheck.rounds,
        &dory_proof,
    )?;
    Ok((claims, encoded))
}

/// Verify the bounded aggregate after absorbing every public claim.
pub fn verify_bls_dory_openings(
    public_binding: &[u8],
    claims: &[BlsDoryOpeningClaim],
    proof: &[u8],
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_public_inputs(public_binding, claims.len())?;
    let parsed = decode_aggregate_proof(proof, claims.len())?;
    if setup.max_log_n() < parsed.variables
        || claims
            .iter()
            .any(|claim| claim.point.len() != parsed.variables)
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let mut transcript = statement_transcript(
        public_binding,
        &setup.identity(),
        claims,
        parsed.nu,
        parsed.sigma,
    )?;
    let batching = batching_challenges(&mut transcript, claims.len());
    let terminal = verify_distinct_point_sumcheck(
        claims,
        &batching,
        &parsed.sumcheck_rounds,
        &mut transcript,
    )?;
    let combined_commitment = claims
        .iter()
        .zip(batching.iter().zip(&terminal.equality_values))
        .fold(
            BlsDoryGt::identity(),
            |combined, (claim, (rho, equality))| {
                combined + claim.commitment.scale(&(*rho * equality))
            },
        );
    append_combined_opening(
        &mut transcript,
        &combined_commitment,
        &terminal.random_point,
        &terminal.final_claim,
    );

    verify::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _>(
        combined_commitment,
        terminal.final_claim,
        &terminal.random_point,
        &parsed.dory_proof,
        setup.verifier().clone(),
        &mut transcript,
    )
    .map_err(dory_error)
}

fn validate_layout(nu: usize, sigma: usize) -> Result<(), BlsDoryAggregateError> {
    let variables = nu
        .checked_add(sigma)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if variables == 0 || variables > MAX_BLS_DORY_PROTOTYPE_VARIABLES || nu > sigma {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    Ok(())
}

fn validate_public_inputs(
    public_binding: &[u8],
    claims: usize,
) -> Result<(), BlsDoryAggregateError> {
    if public_binding.len() > MAX_PUBLIC_BINDING_BYTES {
        return Err(BlsDoryAggregateError::PublicBindingTooLarge);
    }
    if claims == 0 || claims > MAX_BLS_DORY_AGGREGATE_CLAIMS {
        return Err(BlsDoryAggregateError::InvalidClaimCount);
    }
    Ok(())
}

fn dory_error(error: impl std::fmt::Display) -> BlsDoryAggregateError {
    BlsDoryAggregateError::Dory(error.to_string())
}

fn statement_transcript(
    public_binding: &[u8],
    setup_identity: &[u8; 32],
    claims: &[BlsDoryOpeningClaim],
    nu: usize,
    sigma: usize,
) -> Result<BlsDoryTranscript, BlsDoryAggregateError> {
    validate_layout(nu, sigma)?;
    let variables = nu + sigma;
    if claims.iter().any(|claim| claim.point.len() != variables) {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let mut transcript = BlsDoryTranscript::new(b"distinct-opening-aggregate");
    transcript.append_bytes(b"suite-version", &BLS_DORY_AGGREGATE_VERSION.to_le_bytes());
    transcript.append_bytes(b"public-binding", public_binding);
    transcript.append_bytes(b"setup-identity", setup_identity);
    transcript.append_bytes(b"claim-count", &(claims.len() as u64).to_le_bytes());
    transcript.append_bytes(b"variables", &(variables as u64).to_le_bytes());
    transcript.append_bytes(b"nu", &(nu as u64).to_le_bytes());
    transcript.append_bytes(b"sigma", &(sigma as u64).to_le_bytes());
    for claim in claims {
        transcript.append_group(b"commitment", &claim.commitment);
        for coordinate in &claim.point {
            transcript.append_field(b"point-coordinate", coordinate);
        }
        transcript.append_field(b"claimed-evaluation", &claim.evaluation);
    }
    Ok(transcript)
}

fn batching_challenges(transcript: &mut BlsDoryTranscript, count: usize) -> Vec<BlsDoryFr> {
    (0..count)
        .map(|_| transcript.challenge_scalar(b"claim-batching-challenge"))
        .collect()
}

fn append_sumcheck_round(transcript: &mut BlsDoryTranscript, round: &[BlsDoryFr; 3]) {
    transcript.append_field(b"sumcheck-at-zero", &round[0]);
    transcript.append_field(b"sumcheck-at-one", &round[1]);
    transcript.append_field(b"sumcheck-at-two", &round[2]);
}

fn append_combined_opening(
    transcript: &mut BlsDoryTranscript,
    commitment: &BlsDoryGt,
    point: &[BlsDoryFr],
    evaluation: &BlsDoryFr,
) {
    transcript.append_group(b"combined-commitment", commitment);
    for coordinate in point {
        transcript.append_field(b"combined-point", coordinate);
    }
    transcript.append_field(b"combined-evaluation", evaluation);
}

struct SumcheckTerminal {
    random_point: Vec<BlsDoryFr>,
    final_claim: BlsDoryFr,
    equality_values: Vec<BlsDoryFr>,
}

struct SumcheckProverOutput {
    rounds: Vec<[BlsDoryFr; 3]>,
    terminal: SumcheckTerminal,
}

fn prove_distinct_point_sumcheck(
    polynomials: &[&BlsDoryCommittedPolynomial],
    claims: &[BlsDoryOpeningClaim],
    batching: &[BlsDoryFr],
    transcript: &mut BlsDoryTranscript,
) -> Result<SumcheckProverOutput, BlsDoryAggregateError> {
    let variables = claims[0].point.len();
    let mut polynomial_tables = polynomials
        .iter()
        .map(|polynomial| polynomial.coefficients.clone())
        .collect::<Vec<_>>();
    let mut equality_tables = claims
        .iter()
        .map(|claim| equality_table(&claim.point))
        .collect::<Vec<_>>();
    let mut current_claim = claims
        .iter()
        .zip(batching)
        .fold(BlsDoryFr::zero(), |sum, (claim, rho)| {
            sum + *rho * claim.evaluation
        });
    let mut rounds = Vec::with_capacity(variables);
    let mut random_point = Vec::with_capacity(variables);

    for _ in 0..variables {
        let mut message = [BlsDoryFr::zero(); 3];
        for ((polynomial, equality), rho) in
            polynomial_tables.iter().zip(&equality_tables).zip(batching)
        {
            if polynomial.len() != equality.len() || polynomial.len() % 2 != 0 {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
            for (values, equality_values) in
                polynomial.chunks_exact(2).zip(equality.chunks_exact(2))
            {
                let value_two = values[1] + values[1] - values[0];
                let equality_two = equality_values[1] + equality_values[1] - equality_values[0];
                message[0] = message[0] + *rho * values[0] * equality_values[0];
                message[1] = message[1] + *rho * values[1] * equality_values[1];
                message[2] = message[2] + *rho * value_two * equality_two;
            }
        }
        if message[0] + message[1] != current_claim {
            return Err(BlsDoryAggregateError::SumcheckFailed);
        }
        append_sumcheck_round(transcript, &message);
        let challenge = transcript.challenge_scalar(b"sumcheck-round-challenge");
        current_claim = interpolate_quadratic(message, challenge)?;
        random_point.push(challenge);
        for table in &mut polynomial_tables {
            *table = fold_table(table, challenge);
        }
        for table in &mut equality_tables {
            *table = fold_table(table, challenge);
        }
        rounds.push(message);
    }

    let equality_values = equality_tables
        .iter()
        .map(|table| table[0])
        .collect::<Vec<_>>();
    let terminal = polynomial_tables
        .iter()
        .zip(equality_values.iter().zip(batching))
        .fold(BlsDoryFr::zero(), |sum, (polynomial, (equality, rho))| {
            sum + polynomial[0] * equality * rho
        });
    if terminal != current_claim {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    Ok(SumcheckProverOutput {
        rounds,
        terminal: SumcheckTerminal {
            random_point,
            final_claim: current_claim,
            equality_values,
        },
    })
}

fn verify_distinct_point_sumcheck(
    claims: &[BlsDoryOpeningClaim],
    batching: &[BlsDoryFr],
    rounds: &[[BlsDoryFr; 3]],
    transcript: &mut BlsDoryTranscript,
) -> Result<SumcheckTerminal, BlsDoryAggregateError> {
    let variables = claims[0].point.len();
    if rounds.len() != variables {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let mut current_claim = claims
        .iter()
        .zip(batching)
        .fold(BlsDoryFr::zero(), |sum, (claim, rho)| {
            sum + *rho * claim.evaluation
        });
    let mut random_point = Vec::with_capacity(variables);
    for message in rounds {
        if message[0] + message[1] != current_claim {
            return Err(BlsDoryAggregateError::SumcheckFailed);
        }
        append_sumcheck_round(transcript, message);
        let challenge = transcript.challenge_scalar(b"sumcheck-round-challenge");
        current_claim = interpolate_quadratic(*message, challenge)?;
        random_point.push(challenge);
    }
    let equality_values = claims
        .iter()
        .map(|claim| equality_evaluation(&claim.point, &random_point))
        .collect();
    Ok(SumcheckTerminal {
        random_point,
        final_claim: current_claim,
        equality_values,
    })
}

fn equality_table(point: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
    let mut table = vec![BlsDoryFr::one(); 1usize << point.len()];
    let mut active = 1usize;
    for coordinate in point {
        for index in (0..active).rev() {
            let value = table[index];
            table[index] = value * (BlsDoryFr::one() - *coordinate);
            table[index + active] = value * coordinate;
        }
        active *= 2;
    }
    table
}

fn equality_evaluation(point: &[BlsDoryFr], evaluation_point: &[BlsDoryFr]) -> BlsDoryFr {
    point
        .iter()
        .zip(evaluation_point)
        .fold(BlsDoryFr::one(), |product, (left, right)| {
            product * ((BlsDoryFr::one() - *left) * (BlsDoryFr::one() - *right) + *left * right)
        })
}

fn fold_table(table: &[BlsDoryFr], challenge: BlsDoryFr) -> Vec<BlsDoryFr> {
    table
        .chunks_exact(2)
        .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
        .collect()
}

fn interpolate_quadratic(
    evaluations: [BlsDoryFr; 3],
    point: BlsDoryFr,
) -> Result<BlsDoryFr, BlsDoryAggregateError> {
    let two_inverse = BlsDoryFr::from_u64(2)
        .inv()
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
    let second_difference = evaluations[2] - evaluations[1] - evaluations[1] + evaluations[0];
    Ok(evaluations[0]
        + point * (evaluations[1] - evaluations[0])
        + point * (point - BlsDoryFr::one()) * two_inverse * second_difference)
}

fn combine_polynomials(
    polynomials: &[&BlsDoryCommittedPolynomial],
    lambdas: &[BlsDoryFr],
    nu: usize,
) -> Result<(BlsDoryPolynomial, Vec<BlsDoryG1>, BlsDoryGt), BlsDoryAggregateError> {
    let coefficient_count = polynomials[0].coefficients.len();
    let mut coefficients = vec![BlsDoryFr::zero(); coefficient_count];
    let mut rows = vec![BlsDoryG1::identity(); 1usize << nu];
    let mut commitment = BlsDoryGt::identity();
    for (polynomial, lambda) in polynomials.iter().zip(lambdas) {
        if polynomial.coefficients.len() != coefficient_count
            || polynomial.row_commitments.len() != rows.len()
        {
            return Err(BlsDoryAggregateError::MixedStatement);
        }
        for (combined, value) in coefficients.iter_mut().zip(&polynomial.coefficients) {
            *combined = *combined + *lambda * value;
        }
        for (combined, row) in rows.iter_mut().zip(&polynomial.row_commitments) {
            *combined = *combined + row.scale(lambda);
        }
        commitment = commitment + polynomial.commitment.scale(lambda);
    }
    let polynomial = BlsDoryPolynomial::new(coefficients)
        .map_err(|error| BlsDoryAggregateError::Dory(error.to_string()))?;
    Ok((polynomial, rows, commitment))
}

type BlsDoryProof = DoryProof<BlsDoryG1, BlsDoryG2, BlsDoryGt>;

struct ParsedAggregateProof {
    variables: usize,
    nu: usize,
    sigma: usize,
    sumcheck_rounds: Vec<[BlsDoryFr; 3]>,
    dory_proof: BlsDoryProof,
}

fn encode_aggregate_proof(
    claims: usize,
    variables: usize,
    nu: usize,
    sigma: usize,
    sumcheck_rounds: &[[BlsDoryFr; 3]],
    dory_proof: &BlsDoryProof,
) -> Result<Vec<u8>, BlsDoryAggregateError> {
    if sumcheck_rounds.len() != variables || !valid_dory_shape(dory_proof, nu, sigma) {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let claims = u16::try_from(claims).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let variables =
        u16::try_from(variables).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let nu = u16::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let sigma = u16::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let mut encoded = Vec::with_capacity(aggregate_wire_bytes(variables as usize, sigma as usize));
    encoded.extend_from_slice(&WIRE_MAGIC);
    encoded.extend_from_slice(&BLS_DORY_AGGREGATE_VERSION.to_le_bytes());
    encoded.extend_from_slice(&claims.to_le_bytes());
    encoded.extend_from_slice(&variables.to_le_bytes());
    encoded.extend_from_slice(&nu.to_le_bytes());
    encoded.extend_from_slice(&sigma.to_le_bytes());
    for round in sumcheck_rounds {
        for evaluation in round {
            append_serialized(&mut encoded, evaluation)?;
        }
    }
    encode_dory_proof(&mut encoded, dory_proof)?;
    if encoded.len() != aggregate_wire_bytes(variables as usize, sigma as usize)
        || encoded.len() > MAX_BLS_DORY_AGGREGATE_BYTES
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(encoded)
}

fn decode_aggregate_proof(
    encoded: &[u8],
    expected_claims: usize,
) -> Result<ParsedAggregateProof, BlsDoryAggregateError> {
    if encoded.len() < WIRE_HEADER_BYTES || encoded.len() > MAX_BLS_DORY_AGGREGATE_BYTES {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    if encoded[..8] != WIRE_MAGIC {
        return Err(BlsDoryAggregateError::InvalidEncoding);
    }
    let version = read_u16(encoded, 8)?;
    let claims = read_u16(encoded, 10)? as usize;
    let variables = read_u16(encoded, 12)? as usize;
    let nu = read_u16(encoded, 14)? as usize;
    let sigma = read_u16(encoded, 16)? as usize;
    if version != BLS_DORY_AGGREGATE_VERSION || claims != expected_claims {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    validate_layout(nu, sigma)?;
    if variables != nu + sigma || encoded.len() != aggregate_wire_bytes(variables, sigma) {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }

    let mut reader = Cursor::new(&encoded[WIRE_HEADER_BYTES..]);
    let mut sumcheck_rounds = Vec::with_capacity(variables);
    for _ in 0..variables {
        let mut round = [BlsDoryFr::zero(); 3];
        for evaluation in &mut round {
            *evaluation = read_serialized(&mut reader)?;
        }
        sumcheck_rounds.push(round);
    }
    let dory_start = WIRE_HEADER_BYTES + reader.position() as usize;
    let dory_bytes = &encoded[dory_start..];
    preflight_dory_encoding(dory_bytes, nu, sigma)?;
    let dory_proof = decode_dory_proof(dory_bytes, nu, sigma)?;

    let canonical =
        encode_aggregate_proof(claims, variables, nu, sigma, &sumcheck_rounds, &dory_proof)?;
    if canonical != encoded {
        return Err(BlsDoryAggregateError::InvalidEncoding);
    }
    Ok(ParsedAggregateProof {
        variables,
        nu,
        sigma,
        sumcheck_rounds,
        dory_proof,
    })
}

fn valid_dory_shape(proof: &BlsDoryProof, nu: usize, sigma: usize) -> bool {
    proof.nu == nu
        && proof.sigma == sigma
        && proof.first_messages.len() == sigma
        && proof.second_messages.len() == sigma
        && proof.final_message.is_some()
}

fn encode_dory_proof(
    output: &mut Vec<u8>,
    proof: &BlsDoryProof,
) -> Result<(), BlsDoryAggregateError> {
    append_serialized(output, &proof.vmv_message.c)?;
    append_serialized(output, &proof.vmv_message.d2)?;
    append_serialized(output, &proof.vmv_message.e1)?;
    output.extend_from_slice(&(proof.first_messages.len() as u32).to_le_bytes());
    for message in &proof.first_messages {
        append_serialized(output, &message.d1_left)?;
        append_serialized(output, &message.d1_right)?;
        append_serialized(output, &message.d2_left)?;
        append_serialized(output, &message.d2_right)?;
        append_serialized(output, &message.e1_beta)?;
        append_serialized(output, &message.e2_beta)?;
    }
    for message in &proof.second_messages {
        append_serialized(output, &message.c_plus)?;
        append_serialized(output, &message.c_minus)?;
        append_serialized(output, &message.e1_plus)?;
        append_serialized(output, &message.e1_minus)?;
        append_serialized(output, &message.e2_plus)?;
        append_serialized(output, &message.e2_minus)?;
    }
    output.push(1);
    let final_message = proof
        .final_message
        .as_ref()
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    append_serialized(output, &final_message.e1)?;
    append_serialized(output, &final_message.e2)?;
    output.extend_from_slice(&(proof.nu as u32).to_le_bytes());
    output.extend_from_slice(&(proof.sigma as u32).to_le_bytes());
    Ok(())
}

fn decode_dory_proof(
    encoded: &[u8],
    nu: usize,
    sigma: usize,
) -> Result<BlsDoryProof, BlsDoryAggregateError> {
    let mut reader = Cursor::new(encoded);
    let vmv_message = VMVMessage {
        c: read_serialized(&mut reader)?,
        d2: read_serialized(&mut reader)?,
        e1: read_serialized(&mut reader)?,
    };
    if read_cursor_u32(&mut reader)? as usize != sigma {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let mut first_messages = Vec::with_capacity(sigma);
    for _ in 0..sigma {
        first_messages.push(FirstReduceMessage {
            d1_left: read_serialized(&mut reader)?,
            d1_right: read_serialized(&mut reader)?,
            d2_left: read_serialized(&mut reader)?,
            d2_right: read_serialized(&mut reader)?,
            e1_beta: read_serialized(&mut reader)?,
            e2_beta: read_serialized(&mut reader)?,
        });
    }
    let mut second_messages = Vec::with_capacity(sigma);
    for _ in 0..sigma {
        second_messages.push(SecondReduceMessage {
            c_plus: read_serialized(&mut reader)?,
            c_minus: read_serialized(&mut reader)?,
            e1_plus: read_serialized(&mut reader)?,
            e1_minus: read_serialized(&mut reader)?,
            e2_plus: read_serialized(&mut reader)?,
            e2_minus: read_serialized(&mut reader)?,
        });
    }
    if read_cursor_u8(&mut reader)? != 1 {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let final_message = Some(ScalarProductMessage {
        e1: read_serialized(&mut reader)?,
        e2: read_serialized(&mut reader)?,
    });
    let decoded_nu = read_cursor_u32(&mut reader)? as usize;
    let decoded_sigma = read_cursor_u32(&mut reader)? as usize;
    if decoded_nu != nu || decoded_sigma != sigma || reader.position() as usize != encoded.len() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(DoryProof {
        vmv_message,
        first_messages,
        second_messages,
        final_message,
        nu,
        sigma,
    })
}

fn preflight_dory_encoding(
    encoded: &[u8],
    nu: usize,
    sigma: usize,
) -> Result<(), BlsDoryAggregateError> {
    if encoded.len() != dory_wire_bytes(sigma) {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let vmv = 2 * gt_bytes() + g1_bytes();
    if read_u32(encoded, vmv)? as usize != sigma {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let first_round = 4 * gt_bytes() + g1_bytes() + g2_bytes();
    let second_round = 2 * gt_bytes() + 2 * g1_bytes() + 2 * g2_bytes();
    let final_flag = vmv + size_of::<u32>() + sigma * (first_round + second_round);
    if encoded.get(final_flag).copied() != Some(1) {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let shape = final_flag + 1 + g1_bytes() + g2_bytes();
    if read_u32(encoded, shape)? as usize != nu
        || read_u32(encoded, shape + size_of::<u32>())? as usize != sigma
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(())
}

fn aggregate_wire_bytes(variables: usize, rounds: usize) -> usize {
    WIRE_HEADER_BYTES + variables * 3 * scalar_bytes() + dory_wire_bytes(rounds)
}

fn dory_wire_bytes(rounds: usize) -> usize {
    2 * gt_bytes()
        + g1_bytes()
        + size_of::<u32>()
        + rounds * (6 * gt_bytes() + 3 * g1_bytes() + 3 * g2_bytes())
        + 1
        + g1_bytes()
        + g2_bytes()
        + 2 * size_of::<u32>()
}

fn scalar_bytes() -> usize {
    BlsDoryFr::zero().compressed_size()
}

fn g1_bytes() -> usize {
    BlsDoryG1::identity().compressed_size()
}

fn g2_bytes() -> usize {
    BlsDoryG2::identity().compressed_size()
}

fn gt_bytes() -> usize {
    BlsDoryGt::identity().compressed_size()
}

fn append_serialized<T: DorySerialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDoryAggregateError> {
    value
        .serialize_compressed(output)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)
}

fn read_serialized<T: DoryDeserialize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<T, BlsDoryAggregateError> {
    T::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)
}

fn read_cursor_u8(reader: &mut Cursor<&[u8]>) -> Result<u8, BlsDoryAggregateError> {
    let mut value = [0u8; 1];
    std::io::Read::read_exact(reader, &mut value)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)?;
    Ok(value[0])
}

fn read_cursor_u32(reader: &mut Cursor<&[u8]>) -> Result<u32, BlsDoryAggregateError> {
    let mut value = [0u8; 4];
    std::io::Read::read_exact(reader, &mut value)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)?;
    Ok(u32::from_le_bytes(value))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BlsDoryAggregateError> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BlsDoryAggregateError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    Ok(u32::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dory_bls12_381_prototype::deterministic_bls_dory_setup;

    struct Fixture {
        setup: DeterministicBlsDorySetup,
        polynomials: Vec<BlsDoryCommittedPolynomial>,
        points: Vec<Vec<BlsDoryFr>>,
    }

    fn fixture(variables: usize, claims: usize) -> Fixture {
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let nu = variables / 2;
        let sigma = variables - nu;
        let coefficient_count = 1usize << variables;
        let polynomials = (0..claims)
            .map(|claim| {
                let coefficients = (0..coefficient_count)
                    .map(|index| {
                        BlsDoryFr::from_u64(((index as u64 + 3) * (claim as u64 + 5) + 11) % 1_009)
                    })
                    .collect();
                commit_bls_dory_polynomial(coefficients, nu, sigma, &setup).unwrap()
            })
            .collect();
        let points = (0..claims)
            .map(|claim| {
                (0..variables)
                    .map(|coordinate| {
                        BlsDoryFr::from_u64((claim as u64 + 2) * (coordinate as u64 + 7))
                    })
                    .collect()
            })
            .collect();
        Fixture {
            setup,
            polynomials,
            points,
        }
    }

    #[test]
    fn distinct_points_reduce_to_one_real_bls_opening() {
        let Fixture {
            setup,
            polynomials,
            points,
        } = fixture(8, 3);
        let (claims, proof) =
            prove_bls_dory_openings(b"block-binding", &polynomials, &points, &setup).unwrap();
        verify_bls_dory_openings(b"block-binding", &claims, &proof, &setup).unwrap();
        assert_eq!(proof.len(), aggregate_wire_bytes(8, 4));
        assert_eq!(proof.len(), 17_695);
        assert!(proof.len() < MAX_BLS_DORY_AGGREGATE_BYTES);
    }

    #[test]
    fn statement_order_setup_and_proof_mutations_are_rejected() {
        let Fixture {
            setup,
            polynomials,
            points,
        } = fixture(6, 3);
        let (claims, proof) =
            prove_bls_dory_openings(b"binding-a", &polynomials, &points, &setup).unwrap();

        assert!(verify_bls_dory_openings(b"binding-b", &claims, &proof, &setup).is_err());

        let mut changed = claims.clone();
        changed[0].evaluation = changed[0].evaluation + BlsDoryFr::one();
        assert!(verify_bls_dory_openings(b"binding-a", &changed, &proof, &setup).is_err());

        let mut changed = claims.clone();
        changed[1].point[0] = changed[1].point[0] + BlsDoryFr::one();
        assert!(verify_bls_dory_openings(b"binding-a", &changed, &proof, &setup).is_err());

        let mut changed = claims.clone();
        changed[2].commitment = changed[2].commitment.scale(&BlsDoryFr::from_u64(2));
        assert!(verify_bls_dory_openings(b"binding-a", &changed, &proof, &setup).is_err());

        let mut reordered = claims.clone();
        reordered.swap(0, 1);
        assert!(verify_bls_dory_openings(b"binding-a", &reordered, &proof, &setup).is_err());

        let other_setup = deterministic_bls_dory_setup(8).unwrap();
        assert!(verify_bls_dory_openings(b"binding-a", &claims, &proof, &other_setup).is_err());

        let foreign =
            commit_bls_dory_polynomial(polynomials[0].coefficients.clone(), 3, 3, &other_setup)
                .unwrap();
        let mut mixed = polynomials.clone();
        mixed[0] = foreign;
        assert_eq!(
            prove_bls_dory_openings(b"binding-a", &mixed, &points, &setup),
            Err(BlsDoryAggregateError::MixedStatement)
        );

        let mut changed_sumcheck = proof.clone();
        changed_sumcheck[WIRE_HEADER_BYTES] ^= 1;
        assert!(
            verify_bls_dory_openings(b"binding-a", &claims, &changed_sumcheck, &setup).is_err()
        );

        let mut changed_dory = proof.clone();
        let dory_offset = WIRE_HEADER_BYTES + 6 * 3 * scalar_bytes();
        changed_dory[dory_offset] ^= 1;
        assert!(verify_bls_dory_openings(b"binding-a", &claims, &changed_dory, &setup).is_err());
    }

    #[test]
    fn parser_preflights_shape_and_rejects_trailing_bytes() {
        let Fixture {
            setup,
            polynomials,
            points,
        } = fixture(6, 2);
        let (claims, proof) =
            prove_bls_dory_openings(b"parser", &polynomials, &points, &setup).unwrap();
        let dory_offset = WIRE_HEADER_BYTES + 6 * 3 * scalar_bytes();
        let vmv = 2 * gt_bytes() + g1_bytes();

        let mut changed_round_count = proof.clone();
        changed_round_count[dory_offset + vmv..dory_offset + vmv + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            verify_bls_dory_openings(b"parser", &claims, &changed_round_count, &setup),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );

        let mut trailing = proof.clone();
        trailing.push(0);
        assert_eq!(
            verify_bls_dory_openings(b"parser", &claims, &trailing, &setup),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
    }

    #[test]
    fn production_gate_stays_closed_with_only_real_blockers() {
        assert_eq!(
            require_bls_dory_aggregate_production_ready(),
            Err(BlsDoryAggregateError::NotProductionReady)
        );
        assert_eq!(BLS_DORY_AGGREGATE_PRODUCTION_BLOCKERS.len(), 4);
        let projected = projected_bls_dory_aggregate_bytes(31).unwrap();
        assert_eq!(projected, 66_559);
        assert!(projected < MAX_BLS_DORY_AGGREGATE_BYTES);
    }
}
