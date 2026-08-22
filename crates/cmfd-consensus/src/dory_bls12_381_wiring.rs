//! BLS12-381 successor-wiring argument authenticated by Dory.
//!
//! The initial activation table and up to three input/output bank pairs are
//! packed into eight selector slots under one commitment. Random multilinear
//! identities prove every within-bank successor, initialization edge, and
//! cross-bank boundary. One distinct-point Dory aggregate authenticates all
//! evaluations used by those identities.

use std::io::Cursor;

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use thiserror::Error;

use crate::{
    StructuredWiringError, StructuredWiringStatement,
    dory_bls12_381_aggregate::{
        BlsDoryAggregateError, BlsDoryDeferredOpeningSet, BlsDoryOpeningClaim,
        MAX_BLS_DORY_AGGREGATE_BYTES, commit_bls_dory_polynomial,
        projected_bls_dory_aggregate_bytes, prove_bls_dory_deferred_opening_sets,
        verify_bls_dory_openings,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    structured_wiring::{validate_successors, validate_tables},
};

/// Version of the scalar-field wiring transcript.
pub const BLS_DORY_WIRING_VERSION: u16 = 1;
/// Three bits address the initial table and up to three input/output bank pairs.
pub const BLS_DORY_WIRING_SELECTOR_VARIABLES: usize = 3;
/// Production banks have 26 table variables and add three selector variables.
pub const PRODUCTION_BLS_DORY_WIRING_VARIABLES: usize = 29;
/// This checkpoint is not accepted by consensus.
pub const BLS_DORY_WIRING_PRODUCTION_READY: bool = false;
/// Remaining gates on the scalar wiring path.
pub const BLS_DORY_WIRING_PRODUCTION_BLOCKERS: [&str; 3] = [
    "the n=29 packed wiring polynomial is not streamed by the in-memory prover",
    "the executable algebraic union bound exists, but Dory knowledge soundness has not been independently reviewed",
    "the scalar wiring transcript and packed opening path have not received an external audit",
];

const WIRING_SLOTS: usize = 1 << BLS_DORY_WIRING_SELECTOR_VARIABLES;
const INITIAL_SLOT: usize = 0;
const PROOF_MAGIC: [u8; 8] = *b"CFBLSW01";
const PROOF_HEADER_BYTES: usize = 18;
const MAX_WIRING_PROOF_BYTES: usize = 262_128;
const MAX_WIRING_BINDING_BYTES: usize = 4_096;

/// Witness-free scalar wiring proof plus its canonical Dory opening payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryWiringProof {
    pub protocol_version: u16,
    pub packed_variables: u16,
    pub oracle_commitment: BlsDoryGt,
    pub evaluations: Vec<BlsDoryFr>,
    pub transcript_digest: [u8; 32],
    pub opening_proof: Vec<u8>,
}

pub(crate) struct PreparedBlsDoryWiringProof {
    pub(crate) proof: BlsDoryWiringProof,
    pub(crate) openings: BlsDoryDeferredOpeningSet,
}

impl BlsDoryWiringProof {
    /// Encode the exact statement-derived proof shape canonically.
    pub fn encode(
        &self,
        statement: StructuredWiringStatement,
    ) -> Result<Vec<u8>, BlsDoryWiringError> {
        self.encode_with_opening(statement, true)
    }

    pub(crate) fn encode_deferred(
        &self,
        statement: StructuredWiringStatement,
    ) -> Result<Vec<u8>, BlsDoryWiringError> {
        self.encode_with_opening(statement, false)
    }

    fn encode_with_opening(
        &self,
        statement: StructuredWiringStatement,
        require_opening: bool,
    ) -> Result<Vec<u8>, BlsDoryWiringError> {
        validate_proof_shape_with_opening(
            statement,
            self,
            usize::from(self.packed_variables),
            require_opening,
        )?;
        if !require_opening && !self.opening_proof.is_empty() {
            return Err(BlsDoryWiringError::InvalidProofShape);
        }
        let opening_len = u32::try_from(self.opening_proof.len())
            .map_err(|_| BlsDoryWiringError::ProofTooLarge)?;
        let expected = wiring_wire_bytes(self.evaluations.len(), self.opening_proof.len())?;
        let mut encoded = Vec::with_capacity(expected);
        encoded.extend_from_slice(&PROOF_MAGIC);
        encoded.extend_from_slice(&self.protocol_version.to_le_bytes());
        encoded.extend_from_slice(&self.packed_variables.to_le_bytes());
        encoded.extend_from_slice(&(self.evaluations.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&opening_len.to_le_bytes());
        append_serialized(&mut encoded, &self.oracle_commitment)?;
        for evaluation in &self.evaluations {
            append_serialized(&mut encoded, evaluation)?;
        }
        encoded.extend_from_slice(&self.transcript_digest);
        encoded.extend_from_slice(&self.opening_proof);
        if encoded.len() != expected || encoded.len() > MAX_WIRING_PROOF_BYTES {
            return Err(BlsDoryWiringError::ProofTooLarge);
        }
        Ok(encoded)
    }

    /// Decode only the bounded shape implied by the trusted statement.
    pub fn decode(
        encoded: &[u8],
        statement: StructuredWiringStatement,
    ) -> Result<Self, BlsDoryWiringError> {
        let expected_variables = packed_wiring_variables(statement)?;
        Self::decode_with_variables(encoded, statement, expected_variables)
    }

    /// Decode using the exact shared aggregate geometry selected by consensus.
    pub fn decode_with_variables(
        encoded: &[u8],
        statement: StructuredWiringStatement,
        expected_variables: usize,
    ) -> Result<Self, BlsDoryWiringError> {
        Self::decode_with_variables_and_opening(encoded, statement, expected_variables, true)
    }

    pub(crate) fn decode_deferred_with_variables(
        encoded: &[u8],
        statement: StructuredWiringStatement,
        expected_variables: usize,
    ) -> Result<Self, BlsDoryWiringError> {
        Self::decode_with_variables_and_opening(encoded, statement, expected_variables, false)
    }

    fn decode_with_variables_and_opening(
        encoded: &[u8],
        statement: StructuredWiringStatement,
        expected_variables: usize,
        require_opening: bool,
    ) -> Result<Self, BlsDoryWiringError> {
        statement.validate_verifier_shape()?;
        validate_target_variables(packed_wiring_variables(statement)?, expected_variables)?;
        if encoded.len() < PROOF_HEADER_BYTES || encoded.len() > MAX_WIRING_PROOF_BYTES {
            return Err(BlsDoryWiringError::ProofTooLarge);
        }
        if encoded[..8] != PROOF_MAGIC {
            return Err(BlsDoryWiringError::InvalidEncoding);
        }
        let protocol_version = read_u16(encoded, 8)?;
        let packed_variables = read_u16(encoded, 10)?;
        let evaluation_count = read_u16(encoded, 12)? as usize;
        let opening_len = read_u32(encoded, 14)? as usize;
        let expected_evaluations = wiring_evaluation_count(statement)?;
        if protocol_version != BLS_DORY_WIRING_VERSION
            || usize::from(packed_variables) != expected_variables
            || evaluation_count != expected_evaluations
            || (require_opening && opening_len == 0)
            || (!require_opening && opening_len != 0)
            || opening_len > MAX_BLS_DORY_AGGREGATE_BYTES
            || encoded.len() != wiring_wire_bytes(evaluation_count, opening_len)?
        {
            return Err(BlsDoryWiringError::InvalidProofShape);
        }

        let mut reader = Cursor::new(&encoded[PROOF_HEADER_BYTES..]);
        let oracle_commitment = read_serialized(&mut reader)?;
        let mut evaluations = Vec::with_capacity(evaluation_count);
        for _ in 0..evaluation_count {
            evaluations.push(read_serialized(&mut reader)?);
        }
        let payload_offset = PROOF_HEADER_BYTES + reader.position() as usize;
        let digest_end = payload_offset
            .checked_add(32)
            .ok_or(BlsDoryWiringError::InvalidProofShape)?;
        let transcript_digest = encoded
            .get(payload_offset..digest_end)
            .ok_or(BlsDoryWiringError::InvalidProofShape)?
            .try_into()
            .map_err(|_| BlsDoryWiringError::InvalidProofShape)?;
        let opening_proof = encoded
            .get(digest_end..)
            .ok_or(BlsDoryWiringError::InvalidProofShape)?
            .to_vec();
        if opening_proof.len() != opening_len {
            return Err(BlsDoryWiringError::InvalidProofShape);
        }
        let proof = Self {
            protocol_version,
            packed_variables,
            oracle_commitment,
            evaluations,
            transcript_digest,
            opening_proof,
        };
        if proof.encode_with_opening(statement, require_opening)? != encoded {
            return Err(BlsDoryWiringError::InvalidEncoding);
        }
        Ok(proof)
    }
}

/// Errors from the scalar successor-wiring checkpoint.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDoryWiringError {
    #[error("structured wiring input is invalid: {0}")]
    Structured(#[from] StructuredWiringError),
    #[error("Dory opening authentication failed: {0}")]
    Aggregate(#[from] BlsDoryAggregateError),
    #[error("packed wiring dimensions overflow or exceed this checkpoint")]
    InvalidDimensions,
    #[error("scalar wiring proof has the wrong fixed shape")]
    InvalidProofShape,
    #[error("a scalar initialization, successor, or bank-boundary identity failed")]
    WiringIdentity,
    #[error("wiring transcript digest mismatch")]
    Transcript,
    #[error("Dory claims do not match the wiring evaluations")]
    Opening,
    #[error("wiring public binding exceeds the bounded transcript limit")]
    PublicBindingTooLarge,
    #[error("wiring proof exceeds the network payload cap")]
    ProofTooLarge,
    #[error("wiring proof encoding is malformed or non-canonical")]
    InvalidEncoding,
    #[error("the BLS12-381 wiring checkpoint is not production ready")]
    NotProductionReady,
}

/// Fail closed while any production blocker remains.
pub fn require_bls_dory_wiring_production_ready() -> Result<(), BlsDoryWiringError> {
    Err(BlsDoryWiringError::NotProductionReady)
}

/// Project the canonical Dory opening payload for production wiring.
pub fn projected_production_wiring_opening_bytes() -> Result<usize, BlsDoryWiringError> {
    projected_bls_dory_aggregate_bytes(PRODUCTION_BLS_DORY_WIRING_VARIABLES)
        .map_err(BlsDoryWiringError::Aggregate)
}

/// Project the complete canonical production wiring proof.
pub fn projected_production_wiring_proof_bytes() -> Result<usize, BlsDoryWiringError> {
    let statement = production_wiring_statement();
    wiring_wire_bytes(
        wiring_evaluation_count(statement)?,
        projected_production_wiring_opening_bytes()?,
    )
}

/// Prove every wiring edge and authenticate every evaluation under one commitment.
pub fn prove_bls_dory_wiring(
    binding: &[u8],
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryWiringProof, BlsDoryWiringError> {
    let packed_variables = packed_wiring_variables(statement)?;
    prove_bls_dory_wiring_at_variables(
        binding,
        statement,
        initial,
        inputs,
        outputs,
        packed_variables,
        setup,
    )
}

/// Prove every wiring edge at an exact shared aggregate geometry.
pub fn prove_bls_dory_wiring_at_variables(
    binding: &[u8],
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryWiringProof, BlsDoryWiringError> {
    let mut prepared = prove_bls_dory_wiring_deferred_at_variables(
        binding,
        statement,
        initial,
        inputs,
        outputs,
        packed_variables,
        setup,
    )?;
    let opening_binding = opening_binding(binding, &prepared.proof.transcript_digest);
    let (claims, opening_proof) =
        prove_bls_dory_deferred_opening_sets(&opening_binding, &[&prepared.openings], setup)?;
    if claims != prepared.openings.claims() {
        return Err(BlsDoryWiringError::Opening);
    }
    prepared.proof.opening_proof = opening_proof;
    verify_bls_dory_wiring_at_variables(
        binding,
        statement,
        &prepared.proof,
        packed_variables,
        setup,
    )?;
    Ok(prepared.proof)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_wiring_deferred_at_variables(
    binding: &[u8],
    statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDoryWiringProof, BlsDoryWiringError> {
    if binding.len() > MAX_WIRING_BINDING_BYTES {
        return Err(BlsDoryWiringError::PublicBindingTooLarge);
    }
    validate_tables(statement, initial, inputs, outputs)?;
    validate_successors(statement, initial, inputs, outputs)?;
    validate_target_variables(packed_wiring_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryWiringError::InvalidDimensions);
    }
    let initial_values = signed_values(initial);
    let input_banks = bank_field_values(statement, inputs)?;
    let output_banks = bank_field_values(statement, outputs)?;
    let mut packed_coefficients =
        pack_wiring_tables(statement, &initial_values, &input_banks, &output_banks)?;
    let padded_len = 1usize
        .checked_shl(packed_variables as u32)
        .ok_or(BlsDoryWiringError::InvalidDimensions)?;
    packed_coefficients.resize(padded_len, BlsDoryFr::zero());
    let nu = packed_variables / 2;
    let sigma = packed_variables - nu;
    let committed = commit_bls_dory_polynomial(packed_coefficients, nu, sigma, setup)?;
    let oracle_commitment = committed.commitment();

    let mut transcript = wiring_transcript(binding, statement, &oracle_commitment);
    let points = WiringPoints::derive(statement, &mut transcript);
    let evaluations = compute_evaluations(
        statement,
        &points,
        &initial_values,
        &input_banks,
        &output_banks,
    )?;
    verify_identities(statement, &points, &evaluations)?;
    let flattened = evaluations.flatten(statement)?;
    absorb_evaluations(&mut transcript, &flattened);
    let transcript_digest = transcript.digest();
    let opening_points = opening_points(statement, &points, packed_variables)?;
    let expected_claims = opening_claims(oracle_commitment, &opening_points, &flattened)?;
    let openings = BlsDoryDeferredOpeningSet::new(
        vec![committed],
        vec![0; opening_points.len()],
        opening_points,
    )?;
    if openings.claims() != expected_claims {
        return Err(BlsDoryWiringError::Opening);
    }

    let proof = BlsDoryWiringProof {
        protocol_version: BLS_DORY_WIRING_VERSION,
        packed_variables: u16::try_from(packed_variables)
            .map_err(|_| BlsDoryWiringError::InvalidDimensions)?,
        oracle_commitment,
        evaluations: flattened,
        transcript_digest,
        opening_proof: Vec::new(),
    };
    verify_bls_dory_wiring_deferred_at_variables(
        binding,
        statement,
        &proof,
        packed_variables,
        setup,
    )?;
    Ok(PreparedBlsDoryWiringProof { proof, openings })
}

/// Verify wiring identities and their Dory-authenticated evaluations without a witness.
pub fn verify_bls_dory_wiring(
    binding: &[u8],
    statement: StructuredWiringStatement,
    proof: &BlsDoryWiringProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryWiringError> {
    let packed_variables = packed_wiring_variables(statement)?;
    verify_bls_dory_wiring_at_variables(binding, statement, proof, packed_variables, setup)
}

/// Verify wiring against the exact shared aggregate geometry.
pub fn verify_bls_dory_wiring_at_variables(
    binding: &[u8],
    statement: StructuredWiringStatement,
    proof: &BlsDoryWiringProof,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryWiringError> {
    let claims = verify_bls_dory_wiring_deferred_at_variables(
        binding,
        statement,
        proof,
        packed_variables,
        setup,
    )?;
    let binding = opening_binding(binding, &proof.transcript_digest);
    verify_bls_dory_openings(&binding, &claims, &proof.opening_proof, setup)?;
    Ok(())
}

pub(crate) fn verify_bls_dory_wiring_deferred_at_variables(
    binding: &[u8],
    statement: StructuredWiringStatement,
    proof: &BlsDoryWiringProof,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<Vec<BlsDoryOpeningClaim>, BlsDoryWiringError> {
    if binding.len() > MAX_WIRING_BINDING_BYTES {
        return Err(BlsDoryWiringError::PublicBindingTooLarge);
    }
    statement.validate_verifier_shape()?;
    validate_target_variables(packed_wiring_variables(statement)?, packed_variables)?;
    if packed_variables > setup.max_log_n() {
        return Err(BlsDoryWiringError::InvalidDimensions);
    }
    validate_deferred_proof_shape(statement, proof, packed_variables)?;
    let mut transcript = wiring_transcript(binding, statement, &proof.oracle_commitment);
    let points = WiringPoints::derive(statement, &mut transcript);
    let evaluations = WiringEvaluations::from_flat(statement, &proof.evaluations)?;
    verify_identities(statement, &points, &evaluations)?;
    absorb_evaluations(&mut transcript, &proof.evaluations);
    if transcript.digest() != proof.transcript_digest {
        return Err(BlsDoryWiringError::Transcript);
    }
    let points = opening_points(statement, &points, packed_variables)?;
    let claims = opening_claims(proof.oracle_commitment, &points, &proof.evaluations)?;
    Ok(claims)
}

fn production_wiring_statement() -> StructuredWiringStatement {
    StructuredWiringStatement {
        banks: 3,
        layers_per_bank: 128,
        rows: 128,
        cols: 4096,
        max_abs_activation: 125,
    }
}

fn validate_deferred_proof_shape(
    statement: StructuredWiringStatement,
    proof: &BlsDoryWiringProof,
    expected_variables: usize,
) -> Result<(), BlsDoryWiringError> {
    validate_proof_shape_with_opening(statement, proof, expected_variables, false)
}

fn validate_proof_shape_with_opening(
    statement: StructuredWiringStatement,
    proof: &BlsDoryWiringProof,
    expected_variables: usize,
    require_opening: bool,
) -> Result<(), BlsDoryWiringError> {
    statement.validate_verifier_shape()?;
    validate_target_variables(packed_wiring_variables(statement)?, expected_variables)?;
    if proof.protocol_version != BLS_DORY_WIRING_VERSION
        || usize::from(proof.packed_variables) != expected_variables
        || proof.evaluations.len() != wiring_evaluation_count(statement)?
        || (require_opening && proof.opening_proof.is_empty())
        || proof.opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
    {
        return Err(BlsDoryWiringError::InvalidProofShape);
    }
    Ok(())
}

fn validate_target_variables(
    minimum_variables: usize,
    target_variables: usize,
) -> Result<(), BlsDoryWiringError> {
    if target_variables < minimum_variables || target_variables > 64 {
        return Err(BlsDoryWiringError::InvalidDimensions);
    }
    Ok(())
}

fn wiring_wire_bytes(
    evaluations: usize,
    opening_bytes: usize,
) -> Result<usize, BlsDoryWiringError> {
    PROOF_HEADER_BYTES
        .checked_add(BlsDoryGt::identity().compressed_size())
        .and_then(|size| {
            size.checked_add(evaluations.checked_mul(BlsDoryFr::zero().compressed_size())?)
        })
        .and_then(|size| size.checked_add(32))
        .and_then(|size| size.checked_add(opening_bytes))
        .filter(|size| *size <= MAX_WIRING_PROOF_BYTES)
        .ok_or(BlsDoryWiringError::ProofTooLarge)
}

fn append_serialized<T: DorySerialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDoryWiringError> {
    value
        .serialize_compressed(output)
        .map_err(|_| BlsDoryWiringError::InvalidEncoding)
}

fn read_serialized<T: DoryDeserialize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<T, BlsDoryWiringError> {
    T::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryWiringError::InvalidEncoding)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BlsDoryWiringError> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(BlsDoryWiringError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryWiringError::InvalidProofShape)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BlsDoryWiringError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(BlsDoryWiringError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryWiringError::InvalidProofShape)?;
    Ok(u32::from_le_bytes(value))
}

fn packed_wiring_variables(
    statement: StructuredWiringStatement,
) -> Result<usize, BlsDoryWiringError> {
    statement.validate_verifier_shape()?;
    let bank_elements = statement.bank_elements()?;
    let table_variables = usize::try_from(bank_elements.ilog2())
        .map_err(|_| BlsDoryWiringError::InvalidDimensions)?;
    table_variables
        .checked_add(BLS_DORY_WIRING_SELECTOR_VARIABLES)
        .ok_or(BlsDoryWiringError::InvalidDimensions)
}

fn wiring_evaluation_count(
    statement: StructuredWiringStatement,
) -> Result<usize, BlsDoryWiringError> {
    let layer_variables = statement.layers_per_bank.ilog2() as usize;
    statement
        .banks
        .checked_mul(layer_variables + 3)
        .and_then(|count| count.checked_add(1))
        .ok_or(BlsDoryWiringError::InvalidDimensions)
}

fn wiring_transcript(
    binding: &[u8],
    statement: StructuredWiringStatement,
    commitment: &BlsDoryGt,
) -> BlsDoryTranscript {
    let mut transcript = BlsDoryTranscript::new(b"successor-wiring");
    transcript.append_bytes(b"protocol-version", &BLS_DORY_WIRING_VERSION.to_le_bytes());
    transcript.append_bytes(b"public-binding", binding);
    for value in [
        statement.banks as u64,
        statement.layers_per_bank as u64,
        statement.rows as u64,
        statement.cols as u64,
        statement.max_abs_activation,
    ] {
        transcript.append_bytes(b"statement-field", &value.to_le_bytes());
    }
    transcript.append_group(b"packed-wiring-commitment", commitment);
    transcript
}

fn challenge_vector(
    transcript: &mut BlsDoryTranscript,
    label: &[u8],
    count: usize,
) -> Vec<BlsDoryFr> {
    (0..count)
        .map(|index| {
            transcript.append_bytes(b"point-index", &(index as u64).to_le_bytes());
            transcript.challenge_scalar(label)
        })
        .collect()
}

fn absorb_evaluations(transcript: &mut BlsDoryTranscript, evaluations: &[BlsDoryFr]) {
    transcript.append_bytes(
        b"evaluation-count",
        &(evaluations.len() as u64).to_le_bytes(),
    );
    for evaluation in evaluations {
        transcript.append_field(b"wiring-evaluation", evaluation);
    }
}

fn opening_binding(binding: &[u8], transcript_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("CMFD/FORGEMATRIX/BLS-DORY-WIRING-OPENING-BINDING/V1");
    hasher.update(&(binding.len() as u64).to_le_bytes());
    hasher.update(binding);
    hasher.update(transcript_digest);
    *hasher.finalize().as_bytes()
}

fn signed_values(values: &[i64]) -> Vec<BlsDoryFr> {
    values.iter().copied().map(BlsDoryFr::from_i64).collect()
}

fn bank_field_values(
    statement: StructuredWiringStatement,
    values: &[i64],
) -> Result<Vec<Vec<BlsDoryFr>>, BlsDoryWiringError> {
    let bank_elements = statement.bank_elements()?;
    Ok(values
        .chunks_exact(bank_elements)
        .map(signed_values)
        .collect())
}

fn pack_wiring_tables(
    statement: StructuredWiringStatement,
    initial: &[BlsDoryFr],
    inputs: &[Vec<BlsDoryFr>],
    outputs: &[Vec<BlsDoryFr>],
) -> Result<Vec<BlsDoryFr>, BlsDoryWiringError> {
    let bank_elements = statement.bank_elements()?;
    let cells = statement
        .rows
        .checked_mul(statement.cols)
        .ok_or(BlsDoryWiringError::InvalidDimensions)?;
    if initial.len() != cells
        || inputs.len() != statement.banks
        || outputs.len() != statement.banks
        || inputs.iter().any(|bank| bank.len() != bank_elements)
        || outputs.iter().any(|bank| bank.len() != bank_elements)
    {
        return Err(BlsDoryWiringError::InvalidDimensions);
    }
    let total = bank_elements
        .checked_mul(WIRING_SLOTS)
        .ok_or(BlsDoryWiringError::InvalidDimensions)?;
    let mut packed = Vec::with_capacity(total);
    packed.extend_from_slice(initial);
    packed.resize(bank_elements, BlsDoryFr::zero());
    for bank in 0..statement.banks {
        packed.extend_from_slice(&inputs[bank]);
        packed.extend_from_slice(&outputs[bank]);
    }
    packed.resize(total, BlsDoryFr::zero());
    Ok(packed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WiringEvaluations {
    initial: BlsDoryFr,
    output_random: Vec<BlsDoryFr>,
    output_last: Vec<BlsDoryFr>,
    input_shift: Vec<BlsDoryFr>,
    input_first: Vec<BlsDoryFr>,
}

impl WiringEvaluations {
    fn flatten(
        &self,
        statement: StructuredWiringStatement,
    ) -> Result<Vec<BlsDoryFr>, BlsDoryWiringError> {
        let layer_variables = statement.layers_per_bank.ilog2() as usize;
        if self.output_random.len() != statement.banks
            || self.output_last.len() != statement.banks
            || self.input_shift.len() != statement.banks * layer_variables
            || self.input_first.len() != statement.banks
        {
            return Err(BlsDoryWiringError::InvalidProofShape);
        }
        let mut flattened = Vec::with_capacity(wiring_evaluation_count(statement)?);
        flattened.push(self.initial);
        for bank in 0..statement.banks {
            flattened.push(self.output_random[bank]);
            flattened.push(self.output_last[bank]);
            let start = bank * layer_variables;
            flattened.extend_from_slice(&self.input_shift[start..start + layer_variables]);
            flattened.push(self.input_first[bank]);
        }
        Ok(flattened)
    }

    fn from_flat(
        statement: StructuredWiringStatement,
        flattened: &[BlsDoryFr],
    ) -> Result<Self, BlsDoryWiringError> {
        if flattened.len() != wiring_evaluation_count(statement)? {
            return Err(BlsDoryWiringError::InvalidProofShape);
        }
        let layer_variables = statement.layers_per_bank.ilog2() as usize;
        let mut cursor = 1;
        let mut output_random = Vec::with_capacity(statement.banks);
        let mut output_last = Vec::with_capacity(statement.banks);
        let mut input_shift = Vec::with_capacity(statement.banks * layer_variables);
        let mut input_first = Vec::with_capacity(statement.banks);
        for _ in 0..statement.banks {
            output_random.push(flattened[cursor]);
            output_last.push(flattened[cursor + 1]);
            cursor += 2;
            input_shift.extend_from_slice(&flattened[cursor..cursor + layer_variables]);
            cursor += layer_variables;
            input_first.push(flattened[cursor]);
            cursor += 1;
        }
        Ok(Self {
            initial: flattened[0],
            output_random,
            output_last,
            input_shift,
            input_first,
        })
    }
}

struct WiringPoints {
    cell: Vec<BlsDoryFr>,
    layer: Vec<BlsDoryFr>,
}

impl WiringPoints {
    fn derive(statement: StructuredWiringStatement, transcript: &mut BlsDoryTranscript) -> Self {
        Self {
            cell: challenge_vector(
                transcript,
                b"cell-point",
                statement.cell_variables() as usize,
            ),
            layer: challenge_vector(
                transcript,
                b"layer-point",
                statement.layers_per_bank.ilog2() as usize,
            ),
        }
    }

    fn random_table(&self) -> Vec<BlsDoryFr> {
        point_with_layer(&self.cell, &self.layer)
    }

    fn last_table(&self) -> Vec<BlsDoryFr> {
        point_with_layer(&self.cell, &vec![BlsDoryFr::one(); self.layer.len()])
    }

    fn first_table(&self) -> Vec<BlsDoryFr> {
        point_with_layer(&self.cell, &vec![BlsDoryFr::zero(); self.layer.len()])
    }

    fn input_shift(&self, trailing_ones: usize) -> Vec<BlsDoryFr> {
        let mut layer = self.layer.clone();
        for value in layer.iter_mut().take(trailing_ones) {
            *value = BlsDoryFr::zero();
        }
        layer[trailing_ones] = BlsDoryFr::one();
        point_with_layer(&self.cell, &layer)
    }
}

fn compute_evaluations(
    statement: StructuredWiringStatement,
    points: &WiringPoints,
    initial: &[BlsDoryFr],
    inputs: &[Vec<BlsDoryFr>],
    outputs: &[Vec<BlsDoryFr>],
) -> Result<WiringEvaluations, BlsDoryWiringError> {
    let random_point = points.random_table();
    let last_point = points.last_table();
    let first_point = points.first_table();
    let layer_variables = points.layer.len();
    let mut output_random = Vec::with_capacity(statement.banks);
    let mut output_last = Vec::with_capacity(statement.banks);
    let mut input_shift = Vec::with_capacity(statement.banks * layer_variables);
    let mut input_first = Vec::with_capacity(statement.banks);
    for bank in 0..statement.banks {
        output_random.push(evaluate_mle(&outputs[bank], &random_point)?);
        output_last.push(evaluate_mle(&outputs[bank], &last_point)?);
        for trailing_ones in 0..layer_variables {
            input_shift.push(evaluate_mle(
                &inputs[bank],
                &points.input_shift(trailing_ones),
            )?);
        }
        input_first.push(evaluate_mle(&inputs[bank], &first_point)?);
    }
    Ok(WiringEvaluations {
        initial: evaluate_mle(initial, &points.cell)?,
        output_random,
        output_last,
        input_shift,
        input_first,
    })
}

fn verify_identities(
    statement: StructuredWiringStatement,
    points: &WiringPoints,
    evaluations: &WiringEvaluations,
) -> Result<(), BlsDoryWiringError> {
    let layer_variables = points.layer.len();
    let last_selector = points
        .layer
        .iter()
        .fold(BlsDoryFr::one(), |product, value| product * value);
    for bank in 0..statement.banks {
        let masked_output =
            evaluations.output_random[bank] - last_selector * evaluations.output_last[bank];
        let mut shifted_input = BlsDoryFr::zero();
        let mut trailing_selector = BlsDoryFr::one();
        for trailing_ones in 0..layer_variables {
            let coefficient = trailing_selector * (BlsDoryFr::one() - points.layer[trailing_ones]);
            shifted_input = shifted_input
                + coefficient * evaluations.input_shift[bank * layer_variables + trailing_ones];
            trailing_selector = trailing_selector * points.layer[trailing_ones];
        }
        if masked_output != shifted_input {
            return Err(BlsDoryWiringError::WiringIdentity);
        }
    }
    if evaluations.initial != evaluations.input_first[0] {
        return Err(BlsDoryWiringError::WiringIdentity);
    }
    for boundary in 0..statement.banks - 1 {
        if evaluations.output_last[boundary] != evaluations.input_first[boundary + 1] {
            return Err(BlsDoryWiringError::WiringIdentity);
        }
    }
    Ok(())
}

fn opening_points(
    statement: StructuredWiringStatement,
    points: &WiringPoints,
    packed_variables: usize,
) -> Result<Vec<Vec<BlsDoryFr>>, BlsDoryWiringError> {
    validate_target_variables(packed_wiring_variables(statement)?, packed_variables)?;
    let mut openings = Vec::with_capacity(1 + statement.banks * (points.layer.len() + 3));
    openings.push(pad_point(
        &packed_point(&points.first_table(), INITIAL_SLOT),
        packed_variables,
    )?);
    for bank in 0..statement.banks {
        openings.push(pad_point(
            &packed_point(&points.random_table(), output_slot(bank)),
            packed_variables,
        )?);
        openings.push(pad_point(
            &packed_point(&points.last_table(), output_slot(bank)),
            packed_variables,
        )?);
        for trailing_ones in 0..points.layer.len() {
            openings.push(pad_point(
                &packed_point(&points.input_shift(trailing_ones), input_slot(bank)),
                packed_variables,
            )?);
        }
        openings.push(pad_point(
            &packed_point(&points.first_table(), input_slot(bank)),
            packed_variables,
        )?);
    }
    Ok(openings)
}

fn opening_claims(
    commitment: BlsDoryGt,
    points: &[Vec<BlsDoryFr>],
    evaluations: &[BlsDoryFr],
) -> Result<Vec<BlsDoryOpeningClaim>, BlsDoryWiringError> {
    if points.len() != evaluations.len() {
        return Err(BlsDoryWiringError::InvalidProofShape);
    }
    Ok(points
        .iter()
        .zip(evaluations)
        .map(|(point, evaluation)| BlsDoryOpeningClaim {
            commitment,
            point: point.clone(),
            evaluation: *evaluation,
        })
        .collect())
}

fn input_slot(bank: usize) -> usize {
    1 + bank * 2
}

fn output_slot(bank: usize) -> usize {
    2 + bank * 2
}

fn packed_point(table_point: &[BlsDoryFr], slot: usize) -> Vec<BlsDoryFr> {
    let mut point = Vec::with_capacity(table_point.len() + BLS_DORY_WIRING_SELECTOR_VARIABLES);
    point.extend_from_slice(table_point);
    for bit in 0..BLS_DORY_WIRING_SELECTOR_VARIABLES {
        point.push(if (slot >> bit) & 1 == 0 {
            BlsDoryFr::zero()
        } else {
            BlsDoryFr::one()
        });
    }
    point
}

fn pad_point(point: &[BlsDoryFr], variables: usize) -> Result<Vec<BlsDoryFr>, BlsDoryWiringError> {
    if point.len() > variables {
        return Err(BlsDoryWiringError::InvalidDimensions);
    }
    let mut padded = Vec::with_capacity(variables);
    padded.extend_from_slice(point);
    padded.resize(variables, BlsDoryFr::zero());
    Ok(padded)
}

fn point_with_layer(cell: &[BlsDoryFr], layer: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
    let mut point = Vec::with_capacity(cell.len() + layer.len());
    point.extend_from_slice(cell);
    point.extend_from_slice(layer);
    point
}

fn evaluate_mle(
    values: &[BlsDoryFr],
    point: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryWiringError> {
    let expected = 1usize
        .checked_shl(point.len() as u32)
        .ok_or(BlsDoryWiringError::InvalidDimensions)?;
    if values.len() != expected {
        return Err(BlsDoryWiringError::InvalidDimensions);
    }
    let mut folded = values.to_vec();
    for coordinate in point {
        folded = folded
            .chunks_exact(2)
            .map(|pair| pair[0] + *coordinate * (pair[1] - pair[0]))
            .collect();
    }
    folded
        .first()
        .copied()
        .ok_or(BlsDoryWiringError::InvalidDimensions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dory_bls12_381_prototype::deterministic_bls_dory_setup;

    fn fixture() -> (StructuredWiringStatement, Vec<i64>, Vec<i64>, Vec<i64>) {
        let statement = StructuredWiringStatement {
            banks: 2,
            layers_per_bank: 2,
            rows: 2,
            cols: 2,
            max_abs_activation: 100,
        };
        let initial = vec![1, 2, 3, 4];
        let inputs = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let outputs = vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
        (statement, initial, inputs, outputs)
    }

    #[test]
    fn exact_successor_wiring_is_authenticated_by_one_packed_commitment() {
        let (statement, initial, inputs, outputs) = fixture();
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let proof = prove_bls_dory_wiring(
            b"block-binding",
            statement,
            &initial,
            &inputs,
            &outputs,
            &setup,
        )
        .unwrap();
        verify_bls_dory_wiring(b"block-binding", statement, &proof, &setup).unwrap();
        assert_eq!(proof.packed_variables, 6);
        assert_eq!(proof.evaluations.len(), 9);
        assert_eq!(proof.opening_proof.len(), 13_615);

        let encoded = proof.encode(statement).unwrap();
        assert_eq!(encoded.len(), 14_529);
        let decoded = BlsDoryWiringProof::decode(&encoded, statement).unwrap();
        assert_eq!(decoded, proof);
        verify_bls_dory_wiring(b"block-binding", statement, &decoded, &setup).unwrap();
    }

    #[test]
    fn binding_statement_commitment_evaluations_and_opening_are_bound() {
        let (statement, initial, inputs, outputs) = fixture();
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let proof =
            prove_bls_dory_wiring(b"binding", statement, &initial, &inputs, &outputs, &setup)
                .unwrap();
        assert!(verify_bls_dory_wiring(b"other", statement, &proof, &setup).is_err());

        let mut changed_statement = statement;
        changed_statement.max_abs_activation += 1;
        assert!(verify_bls_dory_wiring(b"binding", changed_statement, &proof, &setup).is_err());

        let mut commitment = proof.clone();
        commitment.oracle_commitment = BlsDoryGt::identity();
        assert!(verify_bls_dory_wiring(b"binding", statement, &commitment, &setup).is_err());

        for index in 0..proof.evaluations.len() {
            let mut evaluation = proof.clone();
            evaluation.evaluations[index] = evaluation.evaluations[index] + BlsDoryFr::one();
            assert!(
                verify_bls_dory_wiring(b"binding", statement, &evaluation, &setup).is_err(),
                "evaluation {index} was not bound"
            );
        }

        let mut digest = proof.clone();
        digest.transcript_digest[0] ^= 1;
        assert!(verify_bls_dory_wiring(b"binding", statement, &digest, &setup).is_err());

        let mut opening = proof.clone();
        let opening_middle = opening.opening_proof.len() / 2;
        opening.opening_proof[opening_middle] ^= 1;
        assert!(verify_bls_dory_wiring(b"binding", statement, &opening, &setup).is_err());

        let mut invalid_outputs = outputs;
        invalid_outputs[0] += 1;
        assert_eq!(
            prove_bls_dory_wiring(
                b"binding",
                statement,
                &initial,
                &inputs,
                &invalid_outputs,
                &setup,
            ),
            Err(BlsDoryWiringError::Structured(
                StructuredWiringError::WiringIdentity
            ))
        );
    }

    #[test]
    fn production_geometry_and_gate_remain_explicit() {
        let statement = production_wiring_statement();
        assert_eq!(PRODUCTION_BLS_DORY_WIRING_VARIABLES, 26 + 3);
        assert_eq!(wiring_evaluation_count(statement).unwrap(), 31);
        assert_eq!(statement.soundness_error_numerator().unwrap(), 135);
        assert_eq!(projected_production_wiring_opening_bytes().unwrap(), 62_479);
        assert_eq!(projected_production_wiring_proof_bytes().unwrap(), 64_097);
        assert!(projected_production_wiring_proof_bytes().unwrap() < 262_128);
        assert_eq!(
            require_bls_dory_wiring_production_ready(),
            Err(BlsDoryWiringError::NotProductionReady)
        );
        assert_eq!(BLS_DORY_WIRING_PRODUCTION_BLOCKERS.len(), 3);
    }

    #[test]
    fn outer_parser_rejects_shape_mutations_before_curve_decoding() {
        let (statement, initial, inputs, outputs) = fixture();
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let proof =
            prove_bls_dory_wiring(b"parser", statement, &initial, &inputs, &outputs, &setup)
                .unwrap();
        let encoded = proof.encode(statement).unwrap();

        let mut variables = encoded.clone();
        variables[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            BlsDoryWiringProof::decode(&variables, statement),
            Err(BlsDoryWiringError::InvalidProofShape)
        );

        let mut evaluations = encoded.clone();
        evaluations[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            BlsDoryWiringProof::decode(&evaluations, statement),
            Err(BlsDoryWiringError::InvalidProofShape)
        );

        let mut opening = encoded.clone();
        opening[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            BlsDoryWiringProof::decode(&opening, statement),
            Err(BlsDoryWiringError::InvalidProofShape)
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            BlsDoryWiringProof::decode(&trailing, statement),
            Err(BlsDoryWiringError::InvalidProofShape)
        );
        assert!(BlsDoryWiringProof::decode(&encoded[..encoded.len() - 1], statement).is_err());
        assert_eq!(
            verify_bls_dory_wiring(
                &vec![0; MAX_WIRING_BINDING_BYTES + 1],
                statement,
                &proof,
                &setup
            ),
            Err(BlsDoryWiringError::PublicBindingTooLarge)
        );
    }
}
