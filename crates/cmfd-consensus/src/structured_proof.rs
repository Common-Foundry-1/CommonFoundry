//! Fail-closed aggregate verifier boundary for the ForgeMatrix proof research.
//!
//! The matrix, transition, and successor-wiring arguments reduce the complete
//! computation to multilinear opening claims. This module binds those
//! components together, pins the fixed model commitments, parses one bounded
//! canonical envelope, and refuses to accept the result unless a caller-owned
//! PCS verifier authenticates every resulting opening.
//!
//! No production PCS is selected here. Implementing [`StructuredPcsVerifier`]
//! with a test stub does not make this a consensus-ready succinct proof.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    structured_sumcheck::{
        ExtensionElement, StructuredMatrixProof, StructuredMatrixStatement,
        StructuredSumcheckError, verify_structured_matrix_sumcheck,
    },
    structured_transition::{
        StructuredMaskPolynomial, StructuredTransitionError, StructuredTransitionProof,
        StructuredTransitionStatement, verify_structured_transition_sumcheck,
    },
    structured_wiring::{
        MAX_STRUCTURED_WIRING_BANKS, StructuredWiringError, StructuredWiringProof,
        StructuredWiringStatement, verify_structured_wiring_component_commitments,
        verify_structured_wiring_openings,
    },
};

pub const STRUCTURED_AGGREGATE_VERSION: u32 = 1;
pub const MAX_STRUCTURED_AGGREGATE_PROOF_BYTES: usize = 1024 * 1024;
pub const MAX_STRUCTURED_PCS_PROOF_BYTES: usize = 512 * 1024;
pub const MAX_STRUCTURED_OPENING_CLAIMS: usize = 4096;
pub const MAX_STRUCTURED_OPENING_VARIABLES: usize = 64;

const PROOF_MAGIC: &[u8; 8] = b"CMFDSA01";

/// Public data that fixes every component interpretation and fixed model
/// commitment in one ForgeMatrix execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredForgeMatrixStatement {
    pub public_binding: [u8; 32],
    pub base_input_commitment: [u8; 32],
    pub weight_commitments: Vec<[u8; 32]>,
    pub final_bank_output_commitment: [u8; 32],
    pub initialization_statement: StructuredTransitionStatement,
    pub initialization_mask: StructuredMaskPolynomial,
    pub matrix_statements: Vec<StructuredMatrixStatement>,
    pub transition_statements: Vec<StructuredTransitionStatement>,
    pub transition_masks: Vec<StructuredMaskPolynomial>,
    pub wiring_statement: StructuredWiringStatement,
}

/// Canonical aggregate research envelope. The opaque `pcs_proof` is accepted
/// only through the verifier supplied to [`verify_structured_forgematrix_proof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredForgeMatrixProof {
    pub protocol_version: u32,
    pub initialization_proof: StructuredTransitionProof,
    pub matrix_proofs: Vec<StructuredMatrixProof>,
    pub transition_proofs: Vec<StructuredTransitionProof>,
    pub wiring_proof: StructuredWiringProof,
    pub pcs_proof: Vec<u8>,
}

/// One explicit multilinear opening which the selected PCS must authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredPcsOpeningClaim {
    pub commitment: [u8; 32],
    pub point: Vec<ExtensionElement>,
    pub evaluation: ExtensionElement,
}

/// Consensus-owned PCS verifier boundary.
///
/// Implementations must bind `public_binding`, every claim, and `proof` in one
/// pinned transcript. They must be deterministic, panic-free for untrusted
/// bytes, and reject noncanonical encodings before this interface is eligible
/// for consensus use.
pub trait StructuredPcsVerifier: Send + Sync {
    fn verify_openings(
        &self,
        public_binding: &[u8; 32],
        claims: &[StructuredPcsOpeningClaim],
        proof: &[u8],
    ) -> bool;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StructuredProofError {
    #[error("aggregate proof protocol version mismatch")]
    ProtocolVersion,
    #[error("aggregate statement component counts do not match")]
    ComponentCount,
    #[error("aggregate statement component dimensions or bounds do not match")]
    ComponentShape,
    #[error("matrix proof does not use the pinned model weight commitment")]
    WeightCommitment,
    #[error("wiring proof does not bind the declared final-bank output commitment")]
    FinalBankOutputCommitment,
    #[error("aggregate proof is missing its authenticated PCS opening proof")]
    MissingPcsProof,
    #[error("aggregate proof contains too many PCS opening claims")]
    OpeningCount,
    #[error("aggregate proof opening point exceeds the variable cap")]
    OpeningVariables,
    #[error("the same PCS commitment and point claim conflicting evaluations")]
    ConflictingOpening,
    #[error("the selected PCS rejected one or more aggregate opening claims")]
    PcsRejected,
    #[error("aggregate proof exceeds its research byte cap")]
    ProofTooLarge,
    #[error("aggregate proof is truncated, malformed, or has trailing bytes")]
    Decode,
    #[error("matrix component failed: {0}")]
    Matrix(#[from] StructuredSumcheckError),
    #[error("transition component failed: {0}")]
    Transition(#[from] StructuredTransitionError),
    #[error("wiring component failed: {0}")]
    Wiring(#[from] StructuredWiringError),
}

impl StructuredForgeMatrixProof {
    pub fn encode(&self) -> Result<Vec<u8>, StructuredProofError> {
        if self.matrix_proofs.len() > MAX_STRUCTURED_WIRING_BANKS
            || self.transition_proofs.len() > MAX_STRUCTURED_WIRING_BANKS
        {
            return Err(StructuredProofError::ComponentCount);
        }
        if self.pcs_proof.is_empty() {
            return Err(StructuredProofError::MissingPcsProof);
        }
        if self.pcs_proof.len() > MAX_STRUCTURED_PCS_PROOF_BYTES {
            return Err(StructuredProofError::ProofTooLarge);
        }

        let initialization = self.initialization_proof.encode()?;
        let matrices = self
            .matrix_proofs
            .iter()
            .map(StructuredMatrixProof::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let transitions = self
            .transition_proofs
            .iter()
            .map(StructuredTransitionProof::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let wiring = self.wiring_proof.encode()?;

        let mut output = Vec::new();
        output.extend_from_slice(PROOF_MAGIC);
        output.extend_from_slice(&self.protocol_version.to_le_bytes());
        encode_blob(&mut output, &initialization)?;
        encode_blobs(&mut output, &matrices)?;
        encode_blobs(&mut output, &transitions)?;
        encode_blob(&mut output, &wiring)?;
        encode_blob(&mut output, &self.pcs_proof)?;
        if output.len() > MAX_STRUCTURED_AGGREGATE_PROOF_BYTES {
            return Err(StructuredProofError::ProofTooLarge);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StructuredProofError> {
        if bytes.len() > MAX_STRUCTURED_AGGREGATE_PROOF_BYTES {
            return Err(StructuredProofError::ProofTooLarge);
        }
        let mut reader = ProofReader::new(bytes);
        if reader.take(PROOF_MAGIC.len())? != PROOF_MAGIC {
            return Err(StructuredProofError::Decode);
        }
        let protocol_version = reader.u32()?;
        let initialization_proof = StructuredTransitionProof::decode(
            reader.blob(crate::MAX_STRUCTURED_TRANSITION_PROOF_BYTES)?,
        )?;
        let matrix_count = reader.count(MAX_STRUCTURED_WIRING_BANKS)?;
        let mut matrix_proofs = Vec::with_capacity(matrix_count);
        for _ in 0..matrix_count {
            matrix_proofs.push(StructuredMatrixProof::decode(
                reader.blob(crate::MAX_STRUCTURED_SUMCHECK_PROOF_BYTES)?,
            )?);
        }
        let transition_count = reader.count(MAX_STRUCTURED_WIRING_BANKS)?;
        let mut transition_proofs = Vec::with_capacity(transition_count);
        for _ in 0..transition_count {
            transition_proofs.push(StructuredTransitionProof::decode(
                reader.blob(crate::MAX_STRUCTURED_TRANSITION_PROOF_BYTES)?,
            )?);
        }
        let wiring_proof =
            StructuredWiringProof::decode(reader.blob(crate::MAX_STRUCTURED_WIRING_PROOF_BYTES)?)?;
        let pcs_proof = reader.blob(MAX_STRUCTURED_PCS_PROOF_BYTES)?.to_vec();
        if pcs_proof.is_empty() {
            return Err(StructuredProofError::MissingPcsProof);
        }
        if !reader.is_empty() {
            return Err(StructuredProofError::Decode);
        }
        Ok(Self {
            protocol_version,
            initialization_proof,
            matrix_proofs,
            transition_proofs,
            wiring_proof,
            pcs_proof,
        })
    }
}

/// Verifies all algebraic component transcripts and commitment identities,
/// then requires the selected PCS to authenticate every terminal opening.
pub fn verify_structured_forgematrix_proof(
    statement: &StructuredForgeMatrixStatement,
    proof: &StructuredForgeMatrixProof,
    pcs: &dyn StructuredPcsVerifier,
) -> Result<(), StructuredProofError> {
    if proof.pcs_proof.is_empty() {
        return Err(StructuredProofError::MissingPcsProof);
    }
    // Enforce all in-memory resource and canonical-field checks as well as the
    // byte parser does for an untrusted wire proof.
    proof.encode()?;
    let openings = collect_structured_forgematrix_openings(statement, proof)?;
    if !pcs.verify_openings(&statement.public_binding, &openings, &proof.pcs_proof) {
        return Err(StructuredProofError::PcsRejected);
    }
    Ok(())
}

/// Checks every algebraic component and commitment link, returning the exact
/// terminal claims that an aggregate PCS must authenticate.
///
/// This is the prover/verifier seam used by experimental PCS backends. It does
/// not accept a ForgeMatrix proof by itself.
pub fn collect_structured_forgematrix_openings(
    statement: &StructuredForgeMatrixStatement,
    proof: &StructuredForgeMatrixProof,
) -> Result<Vec<StructuredPcsOpeningClaim>, StructuredProofError> {
    validate_component_shapes(statement, proof)?;
    if proof.protocol_version != STRUCTURED_AGGREGATE_VERSION {
        return Err(StructuredProofError::ProtocolVersion);
    }

    verify_structured_wiring_component_commitments(
        statement.wiring_statement,
        statement.base_input_commitment,
        &proof.initialization_proof,
        &proof.matrix_proofs,
        &proof.transition_proofs,
        &proof.wiring_proof,
    )?;
    for (matrix, expected_weight) in proof
        .matrix_proofs
        .iter()
        .zip(&statement.weight_commitments)
    {
        if matrix.weight_commitment != *expected_weight {
            return Err(StructuredProofError::WeightCommitment);
        }
    }
    if proof.wiring_proof.output_commitments.last() != Some(&statement.final_bank_output_commitment)
    {
        return Err(StructuredProofError::FinalBankOutputCommitment);
    }

    let binding = &statement.public_binding;
    let initialization = verify_structured_transition_sumcheck(
        binding,
        statement.initialization_statement,
        &statement.initialization_mask,
        &proof.initialization_proof,
    )?;
    let mut openings = Vec::new();
    append_transition_openings(&mut openings, initialization)?;
    for ((matrix_statement, transition_statement), (transition_mask, (matrix, transition))) in
        statement
            .matrix_statements
            .iter()
            .zip(&statement.transition_statements)
            .zip(
                statement
                    .transition_masks
                    .iter()
                    .zip(proof.matrix_proofs.iter().zip(&proof.transition_proofs)),
            )
    {
        let matrix_claims = verify_structured_matrix_sumcheck(binding, *matrix_statement, matrix)?;
        openings.push(StructuredPcsOpeningClaim {
            commitment: matrix_claims.activation_commitment,
            point: matrix_claims.activation_point,
            evaluation: matrix_claims.activation_evaluation,
        });
        openings.push(StructuredPcsOpeningClaim {
            commitment: matrix_claims.weight_commitment,
            point: matrix_claims.weight_point,
            evaluation: matrix_claims.weight_evaluation,
        });
        openings.push(StructuredPcsOpeningClaim {
            commitment: matrix_claims.accumulator_commitment,
            point: matrix_claims.accumulator_point,
            evaluation: matrix_claims.accumulator_evaluation,
        });
        let transition_claims = verify_structured_transition_sumcheck(
            binding,
            *transition_statement,
            transition_mask,
            transition,
        )?;
        append_transition_openings(&mut openings, transition_claims)?;
    }
    let wiring = verify_structured_wiring_openings(
        binding,
        statement.wiring_statement,
        &proof.wiring_proof,
    )?;
    openings.extend(
        wiring
            .openings
            .into_iter()
            .map(|claim| StructuredPcsOpeningClaim {
                commitment: claim.commitment,
                point: claim.point,
                evaluation: claim.evaluation,
            }),
    );

    canonical_openings(openings)
}

fn validate_component_shapes(
    statement: &StructuredForgeMatrixStatement,
    proof: &StructuredForgeMatrixProof,
) -> Result<(), StructuredProofError> {
    let banks = statement.wiring_statement.banks;
    if banks == 0
        || banks > MAX_STRUCTURED_WIRING_BANKS
        || statement.weight_commitments.len() != banks
        || statement.matrix_statements.len() != banks
        || statement.transition_statements.len() != banks
        || statement.transition_masks.len() != banks
        || proof.matrix_proofs.len() != banks
        || proof.transition_proofs.len() != banks
    {
        return Err(StructuredProofError::ComponentCount);
    }
    let wiring = statement.wiring_statement;
    let initialization = statement.initialization_statement;
    if initialization.layers != 1
        || initialization.rows != wiring.rows
        || initialization.cols != wiring.cols
        || initialization.max_abs_accumulator != wiring.max_abs_activation
    {
        return Err(StructuredProofError::ComponentShape);
    }
    for (matrix, transition) in statement
        .matrix_statements
        .iter()
        .zip(&statement.transition_statements)
    {
        if matrix.layers != wiring.layers_per_bank
            || matrix.rows != wiring.rows
            || matrix.inner != wiring.cols
            || matrix.cols != wiring.cols
            || matrix.max_abs_activation != wiring.max_abs_activation
            || transition.layers != wiring.layers_per_bank
            || transition.rows != wiring.rows
            || transition.cols != wiring.cols
            || transition.max_abs_accumulator != matrix.max_abs_accumulator
        {
            return Err(StructuredProofError::ComponentShape);
        }
    }
    Ok(())
}

fn append_transition_openings(
    output: &mut Vec<StructuredPcsOpeningClaim>,
    claims: crate::StructuredTransitionOpeningClaims,
) -> Result<(), StructuredProofError> {
    if claims.oracle_commitments.len() != claims.evaluations.len() {
        return Err(StructuredProofError::ComponentCount);
    }
    output.extend(
        claims
            .oracle_commitments
            .into_iter()
            .zip(claims.evaluations)
            .map(|(commitment, evaluation)| StructuredPcsOpeningClaim {
                commitment,
                point: claims.point.clone(),
                evaluation,
            }),
    );
    Ok(())
}

pub(crate) fn canonical_openings(
    openings: Vec<StructuredPcsOpeningClaim>,
) -> Result<Vec<StructuredPcsOpeningClaim>, StructuredProofError> {
    if openings.len() > MAX_STRUCTURED_OPENING_CLAIMS {
        return Err(StructuredProofError::OpeningCount);
    }
    let mut seen = BTreeMap::<Vec<u8>, ExtensionElement>::new();
    let mut unique = Vec::with_capacity(openings.len());
    for opening in openings {
        if opening.point.len() > MAX_STRUCTURED_OPENING_VARIABLES {
            return Err(StructuredProofError::OpeningVariables);
        }
        opening.evaluation.to_field()?;
        let mut key = Vec::with_capacity(36 + opening.point.len() * 24);
        key.extend_from_slice(&opening.commitment);
        key.extend_from_slice(&(opening.point.len() as u32).to_le_bytes());
        for coordinate in &opening.point {
            coordinate.to_field()?;
            coordinate.encode(&mut key);
        }
        match seen.get(&key) {
            Some(evaluation) if *evaluation != opening.evaluation => {
                return Err(StructuredProofError::ConflictingOpening);
            }
            Some(_) => {}
            None => {
                seen.insert(key, opening.evaluation);
                unique.push(opening);
            }
        }
    }
    Ok(unique)
}

fn encode_blobs(output: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<(), StructuredProofError> {
    let count = u32::try_from(values.len()).map_err(|_| StructuredProofError::ProofTooLarge)?;
    output.extend_from_slice(&count.to_le_bytes());
    for value in values {
        encode_blob(output, value)?;
    }
    Ok(())
}

fn encode_blob(output: &mut Vec<u8>, value: &[u8]) -> Result<(), StructuredProofError> {
    let length = u32::try_from(value.len()).map_err(|_| StructuredProofError::ProofTooLarge)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct ProofReader<'a> {
    remaining: &'a [u8],
}

impl<'a> ProofReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StructuredProofError> {
        if self.remaining.len() < length {
            return Err(StructuredProofError::Decode);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, StructuredProofError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().map_err(|_| StructuredProofError::Decode)?,
        ))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, StructuredProofError> {
        let count = self.u32()? as usize;
        if count > maximum {
            return Err(StructuredProofError::ComponentCount);
        }
        Ok(count)
    }

    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], StructuredProofError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(StructuredProofError::ProofTooLarge);
        }
        self.take(length)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockChallenge, ReductionWitness, StructuredTransitionWitness,
        prove_structured_matrix_product, prove_structured_transition, prove_structured_wiring,
        structured_sumcheck::ExtensionField, structured_sumcheck::table_commitment,
        v2_test_reference,
    };
    #[cfg(feature = "whir-prototype")]
    use crate::{
        StructuredWhirCommitmentSet, StructuredWhirPcsVerifier,
        prove_structured_matrix_product_with_commitments,
        prove_structured_transition_with_commitments, prove_structured_whir_openings,
        prove_structured_wiring_with_commitments, structured_matrix_whir_tables,
        structured_transition_whir_tables, structured_wiring_whir_tables,
        verify_structured_whir_openings,
    };

    struct TestPcs {
        accept: bool,
    }

    impl StructuredPcsVerifier for TestPcs {
        fn verify_openings(
            &self,
            _public_binding: &[u8; 32],
            claims: &[StructuredPcsOpeningClaim],
            proof: &[u8],
        ) -> bool {
            self.accept && !claims.is_empty() && proof == b"authenticated-openings"
        }
    }

    fn append_reduction(
        witness: &mut StructuredTransitionWitness,
        accumulator: i64,
        reduction: &ReductionWitness,
        activation: i64,
    ) {
        witness.accumulators.push(accumulator);
        witness
            .masks
            .push(u64::try_from(i64::from(reduction.z) - accumulator).unwrap());
        witness.encoded.push(u64::from(reduction.encoded_z));
        witness
            .square_quotients
            .push(u64::from(reduction.square_quotient));
        witness
            .square_remainders
            .push(u64::from(reduction.square_remainder));
        witness
            .cube_quotients
            .push(u64::from(reduction.cube_quotient));
        witness
            .cube_remainders
            .push(u64::from(reduction.cube_remainder));
        witness
            .output_quotients
            .push(u64::from(reduction.output_quotient));
        witness
            .output_remainders
            .push(u64::from(reduction.output_remainder));
        witness.negative.push(u64::from(reduction.z < 0));
        witness.activations.push(activation);
    }

    fn empty_witness() -> StructuredTransitionWitness {
        StructuredTransitionWitness {
            accumulators: Vec::new(),
            masks: Vec::new(),
            encoded: Vec::new(),
            square_quotients: Vec::new(),
            square_remainders: Vec::new(),
            cube_quotients: Vec::new(),
            cube_remainders: Vec::new(),
            output_quotients: Vec::new(),
            output_remainders: Vec::new(),
            negative: Vec::new(),
            activations: Vec::new(),
        }
    }

    struct FixtureData {
        binding: [u8; 32],
        initial: Vec<i64>,
        inputs: Vec<i64>,
        outputs: Vec<i64>,
        weights: Vec<i64>,
        accumulators: Vec<i64>,
        base_input: Vec<i64>,
        initialization_witness: StructuredTransitionWitness,
        transition_witness: StructuredTransitionWitness,
        initialization_statement: StructuredTransitionStatement,
        initialization_mask: StructuredMaskPolynomial,
        matrix_statement: StructuredMatrixStatement,
        transition_statement: StructuredTransitionStatement,
        transition_mask: StructuredMaskPolynomial,
        wiring_statement: StructuredWiringStatement,
    }

    fn fixture_data() -> FixtureData {
        let block = BlockChallenge {
            network_id: [0x63; 32],
            previous_block: [0x11; 32],
            transaction_root: [0x22; 32],
            height: 42,
            timestamp: 1_777_777_777,
            target: [0xff; 32],
        };
        let reference = v2_test_reference().unwrap();
        let trace = reference.prove_reference(&block, 7).unwrap();
        let model = reference.accelerator_model();
        let rows = model.rows() as usize;
        let cols = model.width() as usize;
        let layers = model.layers() as usize;

        let initial = trace
            .initial_activation
            .iter()
            .map(|value| i64::from(*value))
            .collect::<Vec<_>>();
        let mut inputs = initial.clone();
        for layer in trace.layers.iter().take(layers - 1) {
            inputs.extend(layer.output.iter().map(|value| i64::from(*value)));
        }
        let outputs = trace
            .layers
            .iter()
            .flat_map(|layer| layer.output.iter().map(|value| i64::from(*value)))
            .collect::<Vec<_>>();
        let weights = model
            .weights()
            .iter()
            .map(|value| i64::from(*value) - 125)
            .collect::<Vec<_>>();
        let accumulators = trace
            .layers
            .iter()
            .flat_map(|layer| layer.accumulators.iter().map(|value| i64::from(*value)))
            .collect::<Vec<_>>();

        let matrix_statement = StructuredMatrixStatement {
            layers,
            rows,
            inner: cols,
            cols,
            max_abs_activation: 125,
            max_abs_weight: 125,
            max_abs_accumulator: 64_000_000,
        };
        let base_input = model
            .base_input()
            .iter()
            .map(|value| i64::from(*value) - 125)
            .collect::<Vec<_>>();
        let mut initialization_witness = empty_witness();
        for ((base, reduction), activation) in base_input
            .iter()
            .zip(&trace.initial_reductions)
            .zip(&initial)
        {
            append_reduction(&mut initialization_witness, *base, reduction, *activation);
        }
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows,
            cols,
            max_abs_accumulator: 125,
            max_mask: 5_000,
        };
        let initialization_mask =
            StructuredMaskPolynomial::from_virtual_challenge(&trace.challenge_digest, rows, cols)
                .unwrap();
        let mut transition_witness = empty_witness();
        for layer in &trace.layers {
            for ((accumulator, reduction), activation) in layer
                .accumulators
                .iter()
                .zip(&layer.reductions)
                .zip(&layer.output)
            {
                append_reduction(
                    &mut transition_witness,
                    i64::from(*accumulator),
                    reduction,
                    i64::from(*activation),
                );
            }
        }
        let transition_statement = StructuredTransitionStatement {
            layers,
            rows,
            cols,
            max_abs_accumulator: 64_000_000,
            max_mask: 5_000,
        };
        let transition_mask =
            StructuredMaskPolynomial::from_challenge(&trace.challenge_digest, layers, rows, cols)
                .unwrap();
        let wiring_statement = StructuredWiringStatement {
            banks: 1,
            layers_per_bank: layers,
            rows,
            cols,
            max_abs_activation: 125,
        };
        FixtureData {
            binding: trace.challenge_digest,
            initial,
            inputs,
            outputs,
            weights,
            accumulators,
            base_input,
            initialization_witness,
            transition_witness,
            initialization_statement,
            initialization_mask,
            matrix_statement,
            transition_statement,
            transition_mask,
            wiring_statement,
        }
    }

    fn fixture() -> (StructuredForgeMatrixStatement, StructuredForgeMatrixProof) {
        let data = fixture_data();
        let matrix_proof = prove_structured_matrix_product(
            &data.binding,
            data.matrix_statement,
            &data.inputs,
            &data.weights,
            &data.accumulators,
        )
        .unwrap();
        let initialization_proof = prove_structured_transition(
            &data.binding,
            data.initialization_statement,
            &data.initialization_mask,
            &data.initialization_witness,
        )
        .unwrap();
        let transition_proof = prove_structured_transition(
            &data.binding,
            data.transition_statement,
            &data.transition_mask,
            &data.transition_witness,
        )
        .unwrap();
        let wiring_proof = prove_structured_wiring(
            &data.binding,
            data.wiring_statement,
            &data.initial,
            &data.inputs,
            &data.outputs,
        )
        .unwrap();
        let base_input_commitment = table_commitment(
            &data
                .base_input
                .iter()
                .copied()
                .map(ExtensionField::from_signed)
                .collect::<Vec<_>>(),
        );
        let statement = StructuredForgeMatrixStatement {
            public_binding: data.binding,
            base_input_commitment,
            weight_commitments: vec![matrix_proof.weight_commitment],
            final_bank_output_commitment: *wiring_proof.output_commitments.last().unwrap(),
            initialization_statement: data.initialization_statement,
            initialization_mask: data.initialization_mask,
            matrix_statements: vec![data.matrix_statement],
            transition_statements: vec![data.transition_statement],
            transition_masks: vec![data.transition_mask],
            wiring_statement: data.wiring_statement,
        };
        let proof = StructuredForgeMatrixProof {
            protocol_version: STRUCTURED_AGGREGATE_VERSION,
            initialization_proof,
            matrix_proofs: vec![matrix_proof],
            transition_proofs: vec![transition_proof],
            wiring_proof,
            pcs_proof: b"authenticated-openings".to_vec(),
        };
        (statement, proof)
    }

    #[cfg(feature = "whir-prototype")]
    fn whir_fixture() -> (StructuredForgeMatrixStatement, StructuredForgeMatrixProof) {
        let data = fixture_data();
        let matrix_tables = structured_matrix_whir_tables(
            data.matrix_statement,
            &data.inputs,
            &data.weights,
            &data.accumulators,
        )
        .unwrap();
        let initialization_tables = structured_transition_whir_tables(
            data.initialization_statement,
            &data.initialization_witness,
        )
        .unwrap();
        let transition_tables =
            structured_transition_whir_tables(data.transition_statement, &data.transition_witness)
                .unwrap();
        let wiring_tables = structured_wiring_whir_tables(
            data.wiring_statement,
            &data.initial,
            &data.inputs,
            &data.outputs,
        )
        .unwrap();
        let commitment_set = StructuredWhirCommitmentSet::new(
            matrix_tables
                .iter()
                .chain(&initialization_tables)
                .chain(&transition_tables)
                .chain(&wiring_tables)
                .cloned()
                .collect(),
        )
        .unwrap();
        let aliases = |tables: &[Vec<u64>]| {
            tables
                .iter()
                .map(|table| commitment_set.commitment_for(table).unwrap())
                .collect::<Vec<_>>()
        };
        let matrix_aliases: [[u8; 32]; 3] = aliases(&matrix_tables).try_into().unwrap();
        let initialization_aliases = aliases(&initialization_tables);
        let transition_aliases = aliases(&transition_tables);
        let wiring_aliases = aliases(&wiring_tables);

        let matrix_proof = prove_structured_matrix_product_with_commitments(
            &data.binding,
            data.matrix_statement,
            &data.inputs,
            &data.weights,
            &data.accumulators,
            matrix_aliases,
        )
        .unwrap();
        let initialization_proof = prove_structured_transition_with_commitments(
            &data.binding,
            data.initialization_statement,
            &data.initialization_mask,
            &data.initialization_witness,
            initialization_aliases.clone(),
        )
        .unwrap();
        let transition_proof = prove_structured_transition_with_commitments(
            &data.binding,
            data.transition_statement,
            &data.transition_mask,
            &data.transition_witness,
            transition_aliases,
        )
        .unwrap();
        let wiring_proof = prove_structured_wiring_with_commitments(
            &data.binding,
            data.wiring_statement,
            &data.initial,
            &data.inputs,
            &data.outputs,
            wiring_aliases[0],
            vec![wiring_aliases[1]],
            vec![wiring_aliases[2]],
        )
        .unwrap();
        let statement = StructuredForgeMatrixStatement {
            public_binding: data.binding,
            base_input_commitment: initialization_aliases[0],
            weight_commitments: vec![matrix_aliases[1]],
            final_bank_output_commitment: wiring_aliases[2],
            initialization_statement: data.initialization_statement,
            initialization_mask: data.initialization_mask,
            matrix_statements: vec![data.matrix_statement],
            transition_statements: vec![data.transition_statement],
            transition_masks: vec![data.transition_mask],
            wiring_statement: data.wiring_statement,
        };
        let mut proof = StructuredForgeMatrixProof {
            protocol_version: STRUCTURED_AGGREGATE_VERSION,
            initialization_proof,
            matrix_proofs: vec![matrix_proof],
            transition_proofs: vec![transition_proof],
            wiring_proof,
            pcs_proof: Vec::new(),
        };
        let openings = collect_structured_forgematrix_openings(&statement, &proof).unwrap();
        proof.pcs_proof =
            prove_structured_whir_openings(&data.binding, &commitment_set, &openings).unwrap();
        (statement, proof)
    }

    #[test]
    fn aggregate_requires_every_component_and_authenticated_openings() {
        let (statement, proof) = fixture();
        let encoded = proof.encode().unwrap();
        let decoded = StructuredForgeMatrixProof::decode(&encoded).unwrap();
        assert_eq!(decoded, proof);
        verify_structured_forgematrix_proof(&statement, &decoded, &TestPcs { accept: true })
            .unwrap();
        assert_eq!(
            verify_structured_forgematrix_proof(&statement, &proof, &TestPcs { accept: false }),
            Err(StructuredProofError::PcsRejected)
        );

        let mut wrong_weight = statement.clone();
        wrong_weight.weight_commitments[0][0] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(&wrong_weight, &proof, &TestPcs { accept: true }),
            Err(StructuredProofError::WeightCommitment)
        );

        let mut wrong_accumulator = proof.clone();
        wrong_accumulator.matrix_proofs[0].accumulator_commitment[0] ^= 1;
        assert!(matches!(
            verify_structured_forgematrix_proof(
                &statement,
                &wrong_accumulator,
                &TestPcs { accept: true }
            ),
            Err(StructuredProofError::Wiring(
                StructuredWiringError::Commitment
            ))
        ));

        let mut wrong_final_output = statement.clone();
        wrong_final_output.final_bank_output_commitment[0] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(
                &wrong_final_output,
                &proof,
                &TestPcs { accept: true }
            ),
            Err(StructuredProofError::FinalBankOutputCommitment)
        );

        let mut wrong_binding = statement.clone();
        wrong_binding.public_binding[0] ^= 1;
        assert!(
            verify_structured_forgematrix_proof(&wrong_binding, &proof, &TestPcs { accept: true })
                .is_err()
        );
    }

    #[test]
    fn aggregate_parser_is_bounded_and_exact() {
        let (_, proof) = fixture();
        let canonical = proof.encode().unwrap();
        for length in [0, 1, 8, 12, canonical.len() - 1] {
            assert!(StructuredForgeMatrixProof::decode(&canonical[..length]).is_err());
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            StructuredForgeMatrixProof::decode(&trailing),
            Err(StructuredProofError::Decode)
        );
        let mut missing_pcs = proof.clone();
        missing_pcs.pcs_proof.clear();
        assert_eq!(
            missing_pcs.encode(),
            Err(StructuredProofError::MissingPcsProof)
        );
        assert_eq!(
            StructuredForgeMatrixProof::decode(&vec![0; MAX_STRUCTURED_AGGREGATE_PROOF_BYTES + 1]),
            Err(StructuredProofError::ProofTooLarge)
        );

        let stride = (canonical.len() / 257).max(1);
        for index in (0..canonical.len()).step_by(stride) {
            let mut mutated = canonical.clone();
            mutated[index] ^= 0x80;
            let decoded = std::panic::catch_unwind(|| StructuredForgeMatrixProof::decode(&mutated));
            assert!(decoded.is_ok(), "parser panicked for mutation at {index}");
            if let Ok(Ok(decoded)) = decoded {
                assert_eq!(decoded.encode().unwrap(), mutated);
            }
        }
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn aggregate_whir_openings_round_trip_and_fail_closed() {
        let (statement, proof) = whir_fixture();
        let encoded = proof.encode().unwrap();
        let decoded = StructuredForgeMatrixProof::decode(&encoded).unwrap();
        let openings = collect_structured_forgematrix_openings(&statement, &decoded).unwrap();
        verify_structured_whir_openings(&statement.public_binding, &openings, &decoded.pcs_proof)
            .unwrap();
        verify_structured_forgematrix_proof(&statement, &decoded, &StructuredWhirPcsVerifier)
            .unwrap();

        let mut wrong_root = proof.clone();
        wrong_root.pcs_proof[12] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &wrong_root,
                &StructuredWhirPcsVerifier,
            ),
            Err(StructuredProofError::PcsRejected)
        );

        let mut wrong_opening = proof.clone();
        wrong_opening.matrix_proofs[0].activation_evaluation.limbs[0] ^= 1;
        assert!(
            verify_structured_forgematrix_proof(
                &statement,
                &wrong_opening,
                &StructuredWhirPcsVerifier,
            )
            .is_err()
        );

        let mut truncated = proof.clone();
        truncated.pcs_proof.pop();
        assert_eq!(
            verify_structured_forgematrix_proof(&statement, &truncated, &StructuredWhirPcsVerifier,),
            Err(StructuredProofError::PcsRejected)
        );
    }

    #[test]
    fn duplicate_openings_are_deduplicated_but_conflicts_fail() {
        let first = StructuredPcsOpeningClaim {
            commitment: [7; 32],
            point: vec![ExtensionElement { limbs: [1, 0, 0] }],
            evaluation: ExtensionElement { limbs: [2, 0, 0] },
        };
        assert_eq!(
            canonical_openings(vec![first.clone(), first.clone()])
                .unwrap()
                .len(),
            1
        );
        let mut conflicting = first.clone();
        conflicting.evaluation.limbs[0] = 3;
        assert_eq!(
            canonical_openings(vec![first, conflicting]),
            Err(StructuredProofError::ConflictingOpening)
        );
    }
}
