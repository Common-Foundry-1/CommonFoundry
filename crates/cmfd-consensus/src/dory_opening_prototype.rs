//! Test-only Dory opening aggregation checkpoint.
//!
//! This module proves that opening claims at different multilinear points can
//! be reduced by a degree-two sumcheck and discharged with one homomorphic
//! Dory opening. It is deliberately isolated behind the
//! `dory-opening-prototype` feature. The available upstream backend uses
//! BN254 and randomly generated setup vectors, so this code is not an
//! activatable consensus suite.

use std::io::Cursor;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use dory_pcs::backends::arkworks::{
    ArkDoryProof, ArkFr, ArkG1, ArkGT, ArkworksPolynomial, BN254, Blake2bTranscript, G1Routines,
    G2Routines,
};
use dory_pcs::primitives::DorySerialize;
use dory_pcs::primitives::arithmetic::{Field, Group};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::primitives::serialization::Compress as DoryCompress;
use dory_pcs::primitives::transcript::Transcript;
use dory_pcs::setup::{ProverSetup, VerifierSetup};
use dory_pcs::{Transparent, prove, verify};
use thiserror::Error;

/// Version of the bounded prototype wire grammar.
pub const DORY_OPENING_PROTOTYPE_VERSION: u16 = 1;
/// The prototype accepts only small claim batches while its reduction is audited.
pub const MAX_DORY_PROTOTYPE_CLAIMS: usize = 8;
/// The in-memory prototype is intentionally capped well below production n=31.
pub const MAX_DORY_PROTOTYPE_VARIABLES: usize = 16;
/// Same payload ceiling used by the native production proof frame.
pub const MAX_DORY_PROTOTYPE_PROOF_BYTES: usize = 262_128;
/// The only backend supplied by dory-pcs 0.4.2.
pub const DORY_PROTOTYPE_BACKEND: &str = "BN254 test backend";
/// Explicit blockers that keep this prototype out of consensus activation.
pub const DORY_PROTOTYPE_PRODUCTION_BLOCKERS: [&str; 6] = [
    "BN254 is not the accepted 128-bit production curve",
    "setup generators are random rather than domain-separated hash-to-curve outputs",
    "the cubic Goldilocks AIR is not yet bridged to the pairing scalar field",
    "the production n=31 polynomial is not streamed by this in-memory prototype",
    "the aggregate soundness bound has not been independently reviewed",
    "the replacement PCS and wire grammar have not received an external audit",
];

const WIRE_MAGIC: [u8; 8] = *b"CFDORY01";
const WIRE_HEADER_BYTES: usize = 18;
const TRANSCRIPT_DOMAIN: &[u8] = b"common-foundry/dory-distinct-openings/v1";
const MAX_PUBLIC_BINDING_BYTES: usize = 4_096;

/// A public multilinear opening claim against a Dory tier-two commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoryPrototypeOpeningClaim {
    pub commitment: ArkGT,
    pub point: Vec<ArkFr>,
    pub evaluation: ArkFr,
}

/// A committed evaluation table retained by the prototype prover.
#[derive(Clone, Debug)]
pub struct DoryPrototypeCommittedPolynomial {
    coefficients: Vec<ArkFr>,
    polynomial: ArkworksPolynomial,
    commitment: ArkGT,
    row_commitments: Vec<ArkG1>,
    nu: usize,
    sigma: usize,
}

impl DoryPrototypeCommittedPolynomial {
    /// Public tier-two commitment used in opening statements.
    #[must_use]
    pub fn commitment(&self) -> ArkGT {
        self.commitment
    }

    /// Number of variables in this polynomial.
    #[must_use]
    pub fn variables(&self) -> usize {
        self.nu + self.sigma
    }
}

/// Errors returned by the non-production aggregation checkpoint.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DoryPrototypeError {
    #[error("the Dory opening prototype is not production ready")]
    NotProductionReady,
    #[error("public binding exceeds the prototype limit")]
    PublicBindingTooLarge,
    #[error("claim count is outside the prototype limit")]
    InvalidClaimCount,
    #[error("polynomial or point dimension is outside the prototype limit")]
    InvalidDimension,
    #[error("polynomial coefficient count does not match its dimensions")]
    InvalidCoefficientCount,
    #[error("all opening claims must use one matrix layout")]
    MixedLayouts,
    #[error("proof header or fixed shape is invalid")]
    InvalidProofShape,
    #[error("proof encoding is non-canonical or malformed")]
    InvalidEncoding,
    #[error("sumcheck relation failed")]
    SumcheckFailed,
    #[error("Dory operation failed: {0}")]
    Dory(String),
}

/// This always fails closed. Consensus code must not activate the BN254 prototype.
pub fn require_dory_prototype_production_ready() -> Result<(), DoryPrototypeError> {
    Err(DoryPrototypeError::NotProductionReady)
}

/// Hash the complete verifier setup into the outer Fiat-Shamir statement.
pub fn dory_prototype_setup_identity(
    setup: &VerifierSetup<BN254>,
) -> Result<[u8; 32], DoryPrototypeError> {
    let mut encoded = Vec::new();
    DorySerialize::serialize_with_mode(setup, &mut encoded, DoryCompress::Yes)
        .map_err(|_| DoryPrototypeError::InvalidEncoding)?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

/// Commit a small evaluation-form multilinear polynomial for prototype tests.
pub fn commit_dory_prototype_polynomial(
    coefficients: Vec<ArkFr>,
    nu: usize,
    sigma: usize,
    setup: &ProverSetup<BN254>,
) -> Result<DoryPrototypeCommittedPolynomial, DoryPrototypeError> {
    validate_layout(nu, sigma)?;
    let variables = nu + sigma;
    let expected = 1usize
        .checked_shl(variables as u32)
        .ok_or(DoryPrototypeError::InvalidDimension)?;
    if coefficients.len() != expected {
        return Err(DoryPrototypeError::InvalidCoefficientCount);
    }
    if setup.g1_vec.len() < (1usize << sigma) || setup.g2_vec.len() < (1usize << nu) {
        return Err(DoryPrototypeError::InvalidDimension);
    }

    let polynomial = ArkworksPolynomial::new(coefficients.clone());
    let (commitment, row_commitments, blind) = polynomial
        .commit::<BN254, Transparent, G1Routines>(nu, sigma, setup)
        .map_err(dory_error)?;
    if !blind.is_zero() {
        return Err(DoryPrototypeError::InvalidProofShape);
    }

    Ok(DoryPrototypeCommittedPolynomial {
        coefficients,
        polynomial,
        commitment,
        row_commitments,
        nu,
        sigma,
    })
}

/// Prove several distinct-point evaluations with one degree-two sumcheck and
/// one homomorphically combined Dory opening.
pub fn prove_dory_prototype_openings(
    public_binding: &[u8],
    polynomials: &[DoryPrototypeCommittedPolynomial],
    points: &[Vec<ArkFr>],
    prover_setup: &ProverSetup<BN254>,
    verifier_setup: &VerifierSetup<BN254>,
) -> Result<(Vec<DoryPrototypeOpeningClaim>, Vec<u8>), DoryPrototypeError> {
    validate_public_inputs(public_binding, polynomials.len())?;
    if polynomials.len() != points.len() {
        return Err(DoryPrototypeError::InvalidClaimCount);
    }
    let first = polynomials
        .first()
        .ok_or(DoryPrototypeError::InvalidClaimCount)?;
    let (nu, sigma) = (first.nu, first.sigma);
    validate_layout(nu, sigma)?;
    if polynomials
        .iter()
        .any(|polynomial| polynomial.nu != nu || polynomial.sigma != sigma)
    {
        return Err(DoryPrototypeError::MixedLayouts);
    }
    let variables = nu + sigma;
    if points.iter().any(|point| point.len() != variables) {
        return Err(DoryPrototypeError::InvalidDimension);
    }

    let claims: Vec<_> = polynomials
        .iter()
        .zip(points)
        .map(|(polynomial, point)| DoryPrototypeOpeningClaim {
            commitment: polynomial.commitment,
            point: point.clone(),
            evaluation: polynomial.polynomial.evaluate(point),
        })
        .collect();

    let setup_identity = dory_prototype_setup_identity(verifier_setup)?;
    let mut transcript = statement_transcript(public_binding, &setup_identity, &claims, nu, sigma)?;
    let batching = batching_challenges(&mut transcript, claims.len());
    let sumcheck = prove_distinct_point_sumcheck(polynomials, &claims, &batching, &mut transcript)?;

    let lambdas: Vec<_> = batching
        .iter()
        .zip(&sumcheck.terminal.equality_values)
        .map(|(rho, equality)| *rho * equality)
        .collect();
    let (combined_polynomial, combined_rows, combined_commitment) =
        combine_polynomials(polynomials, &lambdas, nu)?;

    append_combined_opening(
        &mut transcript,
        &combined_commitment,
        &sumcheck.terminal.random_point,
        &sumcheck.terminal.final_claim,
    );
    let (dory_proof, hidden_evaluation) =
        prove::<_, BN254, G1Routines, G2Routines, _, _, Transparent>(
            &combined_polynomial,
            &sumcheck.terminal.random_point,
            combined_rows,
            ArkFr::zero(),
            nu,
            sigma,
            prover_setup,
            &mut transcript,
        )
        .map_err(dory_error)?;
    if hidden_evaluation.is_some() {
        return Err(DoryPrototypeError::InvalidProofShape);
    }

    let encoded = encode_prototype_proof(
        claims.len(),
        variables,
        nu,
        sigma,
        &sumcheck.rounds,
        &dory_proof,
    )?;
    Ok((claims, encoded))
}

/// Verify the bounded aggregate proof. Every public claim is absorbed before
/// any batching challenge is sampled.
pub fn verify_dory_prototype_openings(
    public_binding: &[u8],
    claims: &[DoryPrototypeOpeningClaim],
    proof: &[u8],
    verifier_setup: &VerifierSetup<BN254>,
) -> Result<(), DoryPrototypeError> {
    validate_public_inputs(public_binding, claims.len())?;
    let parsed = decode_prototype_proof(proof, claims.len())?;
    if claims
        .iter()
        .any(|claim| claim.point.len() != parsed.variables)
    {
        return Err(DoryPrototypeError::InvalidDimension);
    }

    let setup_identity = dory_prototype_setup_identity(verifier_setup)?;
    let mut transcript = statement_transcript(
        public_binding,
        &setup_identity,
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
        .fold(ArkGT::identity(), |combined, (claim, (rho, equality))| {
            combined + claim.commitment.scale(&(*rho * equality))
        });
    append_combined_opening(
        &mut transcript,
        &combined_commitment,
        &terminal.random_point,
        &terminal.final_claim,
    );

    verify::<_, BN254, G1Routines, G2Routines, _>(
        combined_commitment,
        terminal.final_claim,
        &terminal.random_point,
        &parsed.dory_proof,
        verifier_setup.clone(),
        &mut transcript,
    )
    .map_err(dory_error)
}

/// Project the fixed opening-aggregate grammar onto compressed BLS12-381
/// element sizes. This is accounting, not a BLS12-381 implementation.
pub fn projected_bls12_381_opening_bytes(variables: usize) -> Result<usize, DoryPrototypeError> {
    if variables == 0 || variables > 64 {
        return Err(DoryPrototypeError::InvalidDimension);
    }
    let rounds = variables.div_ceil(2);
    let g1 = 48usize;
    let g2 = 96usize;
    let gt = 576usize;
    let scalar = 32usize;
    let vmv = 2 * gt + g1;
    let first_round = 4 * gt + g1 + g2;
    let second_round = 2 * gt + 2 * g1 + 2 * g2;
    let transparent_final_and_shape = 1 + g1 + g2 + 2 * size_of::<u32>();
    let dory = vmv
        + size_of::<u32>()
        + rounds * (first_round + second_round)
        + transparent_final_and_shape;
    Ok(WIRE_HEADER_BYTES + variables * 3 * scalar + dory)
}

fn validate_layout(nu: usize, sigma: usize) -> Result<(), DoryPrototypeError> {
    let variables = nu
        .checked_add(sigma)
        .ok_or(DoryPrototypeError::InvalidDimension)?;
    if variables == 0 || variables > MAX_DORY_PROTOTYPE_VARIABLES || nu > sigma {
        return Err(DoryPrototypeError::InvalidDimension);
    }
    Ok(())
}

fn validate_public_inputs(public_binding: &[u8], claims: usize) -> Result<(), DoryPrototypeError> {
    if public_binding.len() > MAX_PUBLIC_BINDING_BYTES {
        return Err(DoryPrototypeError::PublicBindingTooLarge);
    }
    if claims == 0 || claims > MAX_DORY_PROTOTYPE_CLAIMS {
        return Err(DoryPrototypeError::InvalidClaimCount);
    }
    Ok(())
}

fn dory_error(error: impl std::fmt::Display) -> DoryPrototypeError {
    DoryPrototypeError::Dory(error.to_string())
}

fn statement_transcript(
    public_binding: &[u8],
    setup_identity: &[u8; 32],
    claims: &[DoryPrototypeOpeningClaim],
    nu: usize,
    sigma: usize,
) -> Result<Blake2bTranscript<BN254>, DoryPrototypeError> {
    validate_layout(nu, sigma)?;
    let variables = nu + sigma;
    if claims.iter().any(|claim| claim.point.len() != variables) {
        return Err(DoryPrototypeError::InvalidDimension);
    }

    let mut transcript = Blake2bTranscript::<BN254>::new(TRANSCRIPT_DOMAIN);
    transcript.append_bytes(
        b"suite-version",
        &DORY_OPENING_PROTOTYPE_VERSION.to_le_bytes(),
    );
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

fn batching_challenges(transcript: &mut Blake2bTranscript<BN254>, count: usize) -> Vec<ArkFr> {
    (0..count)
        .map(|_| transcript.challenge_scalar(b"claim-batching-challenge"))
        .collect()
}

fn append_sumcheck_round(transcript: &mut Blake2bTranscript<BN254>, round: &[ArkFr; 3]) {
    transcript.append_field(b"sumcheck-at-zero", &round[0]);
    transcript.append_field(b"sumcheck-at-one", &round[1]);
    transcript.append_field(b"sumcheck-at-two", &round[2]);
}

fn append_combined_opening(
    transcript: &mut Blake2bTranscript<BN254>,
    commitment: &ArkGT,
    point: &[ArkFr],
    evaluation: &ArkFr,
) {
    transcript.append_group(b"combined-commitment", commitment);
    for coordinate in point {
        transcript.append_field(b"combined-point", coordinate);
    }
    transcript.append_field(b"combined-evaluation", evaluation);
}

struct SumcheckTerminal {
    random_point: Vec<ArkFr>,
    final_claim: ArkFr,
    equality_values: Vec<ArkFr>,
}

struct SumcheckProverOutput {
    rounds: Vec<[ArkFr; 3]>,
    terminal: SumcheckTerminal,
}

fn prove_distinct_point_sumcheck(
    polynomials: &[DoryPrototypeCommittedPolynomial],
    claims: &[DoryPrototypeOpeningClaim],
    batching: &[ArkFr],
    transcript: &mut Blake2bTranscript<BN254>,
) -> Result<SumcheckProverOutput, DoryPrototypeError> {
    let variables = claims[0].point.len();
    let mut polynomial_tables: Vec<_> = polynomials
        .iter()
        .map(|polynomial| polynomial.coefficients.clone())
        .collect();
    let mut equality_tables: Vec<_> = claims
        .iter()
        .map(|claim| equality_table(&claim.point))
        .collect();
    let mut current_claim = claims
        .iter()
        .zip(batching)
        .fold(ArkFr::zero(), |sum, (claim, rho)| {
            sum + *rho * claim.evaluation
        });
    let mut rounds = Vec::with_capacity(variables);
    let mut random_point = Vec::with_capacity(variables);

    for _ in 0..variables {
        let mut message = [ArkFr::zero(); 3];
        for ((polynomial, equality), rho) in
            polynomial_tables.iter().zip(&equality_tables).zip(batching)
        {
            if polynomial.len() != equality.len() || polynomial.len() % 2 != 0 {
                return Err(DoryPrototypeError::InvalidProofShape);
            }
            for (f, eq) in polynomial.chunks_exact(2).zip(equality.chunks_exact(2)) {
                let f_two = f[1] + f[1] - f[0];
                let eq_two = eq[1] + eq[1] - eq[0];
                message[0] = message[0] + *rho * f[0] * eq[0];
                message[1] = message[1] + *rho * f[1] * eq[1];
                message[2] = message[2] + *rho * f_two * eq_two;
            }
        }
        if message[0] + message[1] != current_claim {
            return Err(DoryPrototypeError::SumcheckFailed);
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

    let equality_values: Vec<_> = equality_tables.iter().map(|table| table[0]).collect();
    let terminal = polynomial_tables
        .iter()
        .zip(equality_values.iter().zip(batching))
        .fold(ArkFr::zero(), |sum, (polynomial, (equality, rho))| {
            sum + polynomial[0] * equality * rho
        });
    if terminal != current_claim {
        return Err(DoryPrototypeError::SumcheckFailed);
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
    claims: &[DoryPrototypeOpeningClaim],
    batching: &[ArkFr],
    rounds: &[[ArkFr; 3]],
    transcript: &mut Blake2bTranscript<BN254>,
) -> Result<SumcheckTerminal, DoryPrototypeError> {
    let variables = claims[0].point.len();
    if rounds.len() != variables {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    let mut current_claim = claims
        .iter()
        .zip(batching)
        .fold(ArkFr::zero(), |sum, (claim, rho)| {
            sum + *rho * claim.evaluation
        });
    let mut random_point = Vec::with_capacity(variables);
    for message in rounds {
        if message[0] + message[1] != current_claim {
            return Err(DoryPrototypeError::SumcheckFailed);
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

fn equality_table(point: &[ArkFr]) -> Vec<ArkFr> {
    let mut table = vec![ArkFr::one(); 1usize << point.len()];
    let mut active = 1usize;
    for coordinate in point {
        for index in (0..active).rev() {
            let value = table[index];
            table[index] = value * (ArkFr::one() - *coordinate);
            table[index + active] = value * coordinate;
        }
        active *= 2;
    }
    table
}

fn equality_evaluation(point: &[ArkFr], evaluation_point: &[ArkFr]) -> ArkFr {
    point
        .iter()
        .zip(evaluation_point)
        .fold(ArkFr::one(), |product, (left, right)| {
            product * ((ArkFr::one() - *left) * (ArkFr::one() - *right) + *left * right)
        })
}

fn fold_table(table: &[ArkFr], challenge: ArkFr) -> Vec<ArkFr> {
    table
        .chunks_exact(2)
        .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
        .collect()
}

fn interpolate_quadratic(
    evaluations: [ArkFr; 3],
    point: ArkFr,
) -> Result<ArkFr, DoryPrototypeError> {
    let two_inverse = ArkFr::from_u64(2)
        .inv()
        .ok_or(DoryPrototypeError::SumcheckFailed)?;
    let second_difference = evaluations[2] - evaluations[1] - evaluations[1] + evaluations[0];
    Ok(evaluations[0]
        + point * (evaluations[1] - evaluations[0])
        + point * (point - ArkFr::one()) * two_inverse * second_difference)
}

fn combine_polynomials(
    polynomials: &[DoryPrototypeCommittedPolynomial],
    lambdas: &[ArkFr],
    nu: usize,
) -> Result<(ArkworksPolynomial, Vec<ArkG1>, ArkGT), DoryPrototypeError> {
    let coefficient_count = polynomials[0].coefficients.len();
    let mut coefficients = vec![ArkFr::zero(); coefficient_count];
    let mut rows = vec![ArkG1::identity(); 1usize << nu];
    let mut commitment = ArkGT::identity();
    for (polynomial, lambda) in polynomials.iter().zip(lambdas) {
        if polynomial.coefficients.len() != coefficient_count
            || polynomial.row_commitments.len() != rows.len()
        {
            return Err(DoryPrototypeError::MixedLayouts);
        }
        for (combined, value) in coefficients.iter_mut().zip(&polynomial.coefficients) {
            *combined = *combined + *lambda * value;
        }
        for (combined, row) in rows.iter_mut().zip(&polynomial.row_commitments) {
            *combined = *combined + row.scale(lambda);
        }
        commitment = commitment + polynomial.commitment.scale(lambda);
    }
    Ok((ArkworksPolynomial::new(coefficients), rows, commitment))
}

struct ParsedPrototypeProof {
    variables: usize,
    nu: usize,
    sigma: usize,
    sumcheck_rounds: Vec<[ArkFr; 3]>,
    dory_proof: ArkDoryProof,
}

fn encode_prototype_proof(
    claims: usize,
    variables: usize,
    nu: usize,
    sigma: usize,
    sumcheck_rounds: &[[ArkFr; 3]],
    dory_proof: &ArkDoryProof,
) -> Result<Vec<u8>, DoryPrototypeError> {
    if sumcheck_rounds.len() != variables
        || dory_proof.nu != nu
        || dory_proof.sigma != sigma
        || dory_proof.first_messages.len() != sigma
        || dory_proof.second_messages.len() != sigma
        || dory_proof.final_message.is_none()
    {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    let claims = u16::try_from(claims).map_err(|_| DoryPrototypeError::InvalidProofShape)?;
    let variables = u16::try_from(variables).map_err(|_| DoryPrototypeError::InvalidProofShape)?;
    let nu = u16::try_from(nu).map_err(|_| DoryPrototypeError::InvalidProofShape)?;
    let sigma = u16::try_from(sigma).map_err(|_| DoryPrototypeError::InvalidProofShape)?;

    let mut encoded = Vec::with_capacity(prototype_wire_bytes(variables as usize, sigma as usize));
    encoded.extend_from_slice(&WIRE_MAGIC);
    encoded.extend_from_slice(&DORY_OPENING_PROTOTYPE_VERSION.to_le_bytes());
    encoded.extend_from_slice(&claims.to_le_bytes());
    encoded.extend_from_slice(&variables.to_le_bytes());
    encoded.extend_from_slice(&nu.to_le_bytes());
    encoded.extend_from_slice(&sigma.to_le_bytes());
    for round in sumcheck_rounds {
        for evaluation in round {
            CanonicalSerialize::serialize_with_mode(evaluation, &mut encoded, Compress::Yes)
                .map_err(|_| DoryPrototypeError::InvalidEncoding)?;
        }
    }
    dory_proof
        .serialize_with_mode(&mut encoded, Compress::Yes)
        .map_err(|_| DoryPrototypeError::InvalidEncoding)?;
    if encoded.len() != prototype_wire_bytes(variables as usize, sigma as usize)
        || encoded.len() > MAX_DORY_PROTOTYPE_PROOF_BYTES
    {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    Ok(encoded)
}

fn decode_prototype_proof(
    encoded: &[u8],
    expected_claims: usize,
) -> Result<ParsedPrototypeProof, DoryPrototypeError> {
    if encoded.len() < WIRE_HEADER_BYTES || encoded.len() > MAX_DORY_PROTOTYPE_PROOF_BYTES {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    if encoded[..8] != WIRE_MAGIC {
        return Err(DoryPrototypeError::InvalidEncoding);
    }
    let version = read_u16(encoded, 8)?;
    let claims = read_u16(encoded, 10)? as usize;
    let variables = read_u16(encoded, 12)? as usize;
    let nu = read_u16(encoded, 14)? as usize;
    let sigma = read_u16(encoded, 16)? as usize;
    if version != DORY_OPENING_PROTOTYPE_VERSION || claims != expected_claims {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    validate_layout(nu, sigma)?;
    if variables != nu + sigma || encoded.len() != prototype_wire_bytes(variables, sigma) {
        return Err(DoryPrototypeError::InvalidProofShape);
    }

    let field_bytes = canonical_size(&ArkFr::zero());
    let mut cursor = WIRE_HEADER_BYTES;
    let mut sumcheck_rounds = Vec::with_capacity(variables);
    for _ in 0..variables {
        let mut round = [ArkFr::zero(); 3];
        for evaluation in &mut round {
            let end = cursor
                .checked_add(field_bytes)
                .ok_or(DoryPrototypeError::InvalidProofShape)?;
            let mut reader = Cursor::new(
                encoded
                    .get(cursor..end)
                    .ok_or(DoryPrototypeError::InvalidProofShape)?,
            );
            *evaluation = ArkFr::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes)
                .map_err(|_| DoryPrototypeError::InvalidEncoding)?;
            if reader.position() as usize != field_bytes {
                return Err(DoryPrototypeError::InvalidEncoding);
            }
            cursor = end;
        }
        sumcheck_rounds.push(round);
    }

    let dory_bytes = &encoded[cursor..];
    preflight_dory_encoding(dory_bytes, nu, sigma)?;
    let mut reader = Cursor::new(dory_bytes);
    let dory_proof = ArkDoryProof::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes)
        .map_err(|_| DoryPrototypeError::InvalidEncoding)?;
    if reader.position() as usize != dory_bytes.len()
        || dory_proof.nu != nu
        || dory_proof.sigma != sigma
        || dory_proof.first_messages.len() != sigma
        || dory_proof.second_messages.len() != sigma
        || dory_proof.final_message.is_none()
    {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    let mut canonical = Vec::with_capacity(dory_bytes.len());
    dory_proof
        .serialize_with_mode(&mut canonical, Compress::Yes)
        .map_err(|_| DoryPrototypeError::InvalidEncoding)?;
    if canonical != dory_bytes {
        return Err(DoryPrototypeError::InvalidEncoding);
    }

    Ok(ParsedPrototypeProof {
        variables,
        nu,
        sigma,
        sumcheck_rounds,
        dory_proof,
    })
}

fn preflight_dory_encoding(
    encoded: &[u8],
    nu: usize,
    sigma: usize,
) -> Result<(), DoryPrototypeError> {
    let g1 = canonical_size(&ArkG1::identity());
    let g2 = canonical_size(&dory_pcs::backends::arkworks::ArkG2::identity());
    let gt = canonical_size(&ArkGT::identity());
    let vmv = 2 * gt + g1;
    let first_round = 4 * gt + g1 + g2;
    let second_round = 2 * gt + 2 * g1 + 2 * g2;
    let expected = dory_wire_bytes(sigma);
    if encoded.len() != expected {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    let round_count = read_u32(encoded, vmv)? as usize;
    if round_count != sigma {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    let final_flag = vmv + size_of::<u32>() + sigma * (first_round + second_round);
    if encoded.get(final_flag).copied() != Some(1) {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    let shape = final_flag + 1 + g1 + g2;
    if read_u32(encoded, shape)? as usize != nu
        || read_u32(encoded, shape + size_of::<u32>())? as usize != sigma
    {
        return Err(DoryPrototypeError::InvalidProofShape);
    }
    Ok(())
}

fn prototype_wire_bytes(variables: usize, rounds: usize) -> usize {
    WIRE_HEADER_BYTES + variables * 3 * canonical_size(&ArkFr::zero()) + dory_wire_bytes(rounds)
}

fn dory_wire_bytes(rounds: usize) -> usize {
    let g1 = canonical_size(&ArkG1::identity());
    let g2 = canonical_size(&dory_pcs::backends::arkworks::ArkG2::identity());
    let gt = canonical_size(&ArkGT::identity());
    2 * gt
        + g1
        + size_of::<u32>()
        + rounds * (6 * gt + 3 * g1 + 3 * g2)
        + 1
        + g1
        + g2
        + 2 * size_of::<u32>()
}

fn canonical_size<T: CanonicalSerialize>(value: &T) -> usize {
    value.serialized_size(Compress::Yes)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DoryPrototypeError> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(DoryPrototypeError::InvalidProofShape)?
        .try_into()
        .map_err(|_| DoryPrototypeError::InvalidProofShape)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DoryPrototypeError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(DoryPrototypeError::InvalidProofShape)?
        .try_into()
        .map_err(|_| DoryPrototypeError::InvalidProofShape)?;
    Ok(u32::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(
        variables: usize,
        claims: usize,
    ) -> (
        ProverSetup<BN254>,
        VerifierSetup<BN254>,
        Vec<DoryPrototypeCommittedPolynomial>,
        Vec<Vec<ArkFr>>,
    ) {
        let (prover_setup, verifier_setup) = dory_pcs::setup::<BN254>(variables);
        let nu = variables / 2;
        let sigma = variables - nu;
        let coefficient_count = 1usize << variables;
        let polynomials = (0..claims)
            .map(|claim| {
                let coefficients = (0..coefficient_count)
                    .map(|index| {
                        ArkFr::from_u64(((index as u64 + 3) * (claim as u64 + 5) + 11) % 1_009)
                    })
                    .collect();
                commit_dory_prototype_polynomial(coefficients, nu, sigma, &prover_setup).unwrap()
            })
            .collect();
        let points = (0..claims)
            .map(|claim| {
                (0..variables)
                    .map(|coordinate| ArkFr::from_u64((claim as u64 + 2) * (coordinate as u64 + 7)))
                    .collect()
            })
            .collect();
        (prover_setup, verifier_setup, polynomials, points)
    }

    #[test]
    fn distinct_points_reduce_to_one_dory_opening() {
        let (prover_setup, verifier_setup, polynomials, points) = fixture(8, 3);
        let (claims, proof) = prove_dory_prototype_openings(
            b"block-binding",
            &polynomials,
            &points,
            &prover_setup,
            &verifier_setup,
        )
        .unwrap();
        verify_dory_prototype_openings(b"block-binding", &claims, &proof, &verifier_setup).unwrap();
        assert_eq!(proof.len(), prototype_wire_bytes(8, 4));
        assert_eq!(proof.len(), 12_063);
        assert!(proof.len() < 16 * 1_024);
    }

    #[test]
    fn statement_and_transcript_mutations_are_rejected() {
        let (prover_setup, verifier_setup, polynomials, points) = fixture(6, 3);
        let (claims, proof) = prove_dory_prototype_openings(
            b"binding-a",
            &polynomials,
            &points,
            &prover_setup,
            &verifier_setup,
        )
        .unwrap();

        assert!(
            verify_dory_prototype_openings(b"binding-b", &claims, &proof, &verifier_setup).is_err()
        );

        let mut changed = claims.clone();
        changed[0].evaluation = changed[0].evaluation + ArkFr::one();
        assert!(
            verify_dory_prototype_openings(b"binding-a", &changed, &proof, &verifier_setup)
                .is_err()
        );

        let mut changed = claims.clone();
        changed[1].point[0] = changed[1].point[0] + ArkFr::one();
        assert!(
            verify_dory_prototype_openings(b"binding-a", &changed, &proof, &verifier_setup)
                .is_err()
        );

        let mut changed = claims.clone();
        changed[2].commitment = changed[2].commitment.scale(&ArkFr::from_u64(2));
        assert!(
            verify_dory_prototype_openings(b"binding-a", &changed, &proof, &verifier_setup)
                .is_err()
        );

        let mut reordered = claims.clone();
        reordered.swap(0, 1);
        assert!(
            verify_dory_prototype_openings(b"binding-a", &reordered, &proof, &verifier_setup)
                .is_err()
        );

        let (_, other_verifier_setup) = dory_pcs::setup::<BN254>(6);
        assert!(
            verify_dory_prototype_openings(b"binding-a", &claims, &proof, &other_verifier_setup,)
                .is_err()
        );
    }

    #[test]
    fn sumcheck_and_dory_bytes_are_rejected_when_mutated() {
        let (prover_setup, verifier_setup, polynomials, points) = fixture(6, 2);
        let (claims, proof) = prove_dory_prototype_openings(
            b"mutation-fixture",
            &polynomials,
            &points,
            &prover_setup,
            &verifier_setup,
        )
        .unwrap();

        let mut changed_sumcheck = proof.clone();
        changed_sumcheck[WIRE_HEADER_BYTES] ^= 1;
        assert!(
            verify_dory_prototype_openings(
                b"mutation-fixture",
                &claims,
                &changed_sumcheck,
                &verifier_setup,
            )
            .is_err()
        );

        let mut changed_dory = proof.clone();
        let dory_offset = WIRE_HEADER_BYTES + 6 * 3 * canonical_size(&ArkFr::zero());
        changed_dory[dory_offset] ^= 1;
        assert!(
            verify_dory_prototype_openings(
                b"mutation-fixture",
                &claims,
                &changed_dory,
                &verifier_setup,
            )
            .is_err()
        );
    }

    #[test]
    fn parser_rejects_attacker_controlled_shape_before_dory_allocation() {
        let (prover_setup, verifier_setup, polynomials, points) = fixture(6, 2);
        let (claims, proof) = prove_dory_prototype_openings(
            b"parser-fixture",
            &polynomials,
            &points,
            &prover_setup,
            &verifier_setup,
        )
        .unwrap();
        let dory_offset = WIRE_HEADER_BYTES + 6 * 3 * canonical_size(&ArkFr::zero());
        let vmv = 2 * canonical_size(&ArkGT::identity()) + canonical_size(&ArkG1::identity());

        let mut changed_round_count = proof.clone();
        changed_round_count[dory_offset + vmv..dory_offset + vmv + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            verify_dory_prototype_openings(
                b"parser-fixture",
                &claims,
                &changed_round_count,
                &verifier_setup,
            ),
            Err(DoryPrototypeError::InvalidProofShape)
        );

        let mut trailing = proof.clone();
        trailing.push(0);
        assert_eq!(
            verify_dory_prototype_openings(b"parser-fixture", &claims, &trailing, &verifier_setup,),
            Err(DoryPrototypeError::InvalidProofShape)
        );
    }

    #[test]
    fn production_gate_stays_closed_and_projection_fits_native_cap() {
        assert_eq!(
            require_dory_prototype_production_ready(),
            Err(DoryPrototypeError::NotProductionReady)
        );
        assert_eq!(DORY_PROTOTYPE_PRODUCTION_BLOCKERS.len(), 6);
        let projected = projected_bls12_381_opening_bytes(31).unwrap();
        assert_eq!(projected, 66_559);
        assert!(projected < MAX_DORY_PROTOTYPE_PROOF_BYTES);
    }
}
