//! Optional ForgeMatrix v2 GKR/Ligero research backend.
//!
//! This module proves the complete tiny `2 x 4 x 4` ForgeMatrix v2 relation.
//! It is intentionally feature-gated and is not a production consensus proof:
//! Remainder CE is unaudited, its verifier can panic on malformed transcripts,
//! and this prototype exposes the tiny fixed model as verifier-known public
//! input instead of linking a production model-bank PCS commitment.

use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::OnceLock,
};

use bincode::Options;
use blake3::Hasher;
use frontend::{
    abstract_expr::AbstractExpression,
    layouter::builder::{Circuit, CircuitBuilder, InputLayerNodeRef, LayerVisibility, NodeRef},
};
use remainder::{
    mle::evals::MultilinearExtension, provable_circuit::ProvableCircuit,
    verifiable_circuit::VerifiableCircuit,
};
use serde::{Deserialize, Serialize};
use shared_types::{
    Fr,
    circuit_hash::CircuitHashType,
    config::{GKRCircuitProverConfig, GKRCircuitVerifierConfig, ProofConfig},
    transcript::{Transcript, TranscriptReader, TranscriptWriter, poseidon_sponge::PoseidonSponge},
};
use thiserror::Error;

use crate::{
    BlockChallenge, ForgeMatrixV2Error, ForgeMatrixV2Reference, ForgeMatrixV2ReferenceProof,
    ReductionWitness, V2_TEST_BATCH, V2_TEST_DIMENSION, V2_TEST_LAYERS, V2_TRANSITION_MODULUS,
};

pub const REMAINDER_PROTOTYPE_VERSION: u32 = 1;
pub const REMAINDER_BACKEND_REVISION: &str = "5687fe7f3a077c75c374422ef79f22e3860de9c1";
pub const MAX_REMAINDER_PROTOTYPE_PROOF_BYTES: usize = 384 * 1024 * 1024;

// The pinned backend converts label bytes directly into BN254 field elements
// and panics for longer labels whose 32-byte chunks exceed the modulus.
const TRANSCRIPT_LABEL: &str = "GKR Prover Transcript";
const STATEMENT_DOMAIN: &str = "CMFD/FORGEMATRIX/REMAINDER-STATEMENT/V1";
const OUTPUT_CENTER: i32 = 125;
const OUTPUT_MODULUS: u64 = 251;
const MAX_OUTPUT_QUOTIENT: u64 = 534_731;
const ACTIVATION_LEN: usize = (V2_TEST_BATCH * V2_TEST_DIMENSION) as usize;
const WEIGHT_LEN: usize = (V2_TEST_DIMENSION * V2_TEST_DIMENSION) as usize;
const ACTIVATION_NUM_VARS: usize = 3;
const WEIGHT_NUM_VARS: usize = 4;
const RANGE_DIGITS_USED: usize = 420;
const RANGE_DIGITS_PADDED: usize = 512;
const RANGE_DIGIT_VALUES: usize = RANGE_DIGITS_PADDED * ACTIVATION_LEN;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeMatrixV2RemainderProof {
    pub prototype_version: u32,
    pub backend_revision: String,
    pub nonce: u64,
    pub model_manifest_digest: [u8; 32],
    pub challenge_digest: [u8; 32],
    pub final_activation: Vec<u8>,
    pub final_activation_digest: [u8; 32],
    pub work_digest: [u8; 32],
    pub statement_digest: [u8; 32],
    pub transcript: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum RemainderPrototypeError {
    #[error("the Remainder prototype supports only the fixed 2x4x4 ForgeMatrix v2 profile")]
    UnsupportedProfile,
    #[error("ForgeMatrix v2 statement is invalid: {0}")]
    Relation(#[from] ForgeMatrixV2Error),
    #[error("prototype proof version or pinned backend revision mismatch")]
    Version,
    #[error("prototype proof model manifest mismatch")]
    Model,
    #[error("prototype proof challenge mismatch")]
    Challenge,
    #[error("prototype final activation is malformed")]
    FinalActivation,
    #[error("prototype final activation digest mismatch")]
    OutputDigest,
    #[error("prototype work digest mismatch")]
    WorkDigest,
    #[error("prototype work digest does not meet the block target")]
    HighHash,
    #[error("prototype statement digest mismatch")]
    StatementDigest,
    #[error("prototype transcript is {actual} bytes, exceeding its research-only {max}-byte cap")]
    ProofTooLarge { actual: usize, max: usize },
    #[error("prototype transcript is malformed or has trailing bytes")]
    Decode,
    #[error("prototype transcript does not have its unique canonical encoding")]
    NonCanonicalEncoding,
    #[error("Remainder circuit construction failed: {0}")]
    Circuit(String),
    #[error("Remainder proof generation failed: {0}")]
    Proving(String),
    #[error("Remainder proof verification failed: {0}")]
    Verification(String),
    #[error("the research verifier rejected a malformed proof by panicking")]
    BackendPanic,
}

type Assignments = HashMap<String, Vec<Fr>>;

struct PrototypeStatement {
    model_manifest_digest: [u8; 32],
    challenge_digest: [u8; 32],
    final_activation: Vec<u8>,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
    statement_digest: [u8; 32],
    base: Vec<i32>,
    weights: Vec<Vec<i32>>,
    masks: Vec<Vec<u32>>,
}

static PROTOTYPE_CIRCUIT: OnceLock<Result<Circuit<Fr>, String>> = OnceLock::new();

/// Generates an actual GKR proof for every matrix and transition in the fixed
/// tiny v2 profile. It does not alter the active Devnet or production verifier.
pub fn prove_remainder_prototype(
    reference: &ForgeMatrixV2Reference,
    block: &BlockChallenge,
    nonce: u64,
) -> Result<ForgeMatrixV2RemainderProof, RemainderPrototypeError> {
    ensure_supported_profile(reference)?;
    let relation = reference.prove_reference(block, nonce)?;
    let final_activation = relation
        .layers
        .last()
        .ok_or(RemainderPrototypeError::UnsupportedProfile)?
        .output
        .iter()
        .map(|value| {
            u8::try_from(i32::from(*value) + OUTPUT_CENTER)
                .ok()
                .filter(|byte| *byte <= 250)
                .ok_or(RemainderPrototypeError::FinalActivation)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let statement = build_statement(reference, block, nonce, final_activation)?;
    if relation.challenge_digest != statement.challenge_digest
        || relation.final_activation_digest != statement.final_activation_digest
        || relation.work_digest != statement.work_digest
    {
        return Err(RemainderPrototypeError::StatementDigest);
    }

    let mut circuit = prototype_circuit()?;
    let public = public_assignments(&statement);
    let committed = committed_assignments(&relation, &statement)?;
    set_assignments(&mut circuit, public);
    set_assignments(&mut circuit, committed);
    let provable = circuit
        .gen_provable_circuit()
        .map_err(|error| RemainderPrototypeError::Circuit(error.to_string()))?;

    let prover_config = GKRCircuitProverConfig::runtime_optimized_default();
    let (proof_config, transcript) = shared_types::perform_function_under_prover_config!(
        prove_with_config,
        &prover_config,
        &provable
    )?;
    let expected_config = ProofConfig::new_from_prover_config(&prover_config);
    if !same_proof_config(&proof_config, &expected_config) {
        return Err(RemainderPrototypeError::Proving(
            "backend selected an unpinned proof configuration".into(),
        ));
    }
    let transcript = proof_encode_codec()
        .serialize(&transcript)
        .map_err(|error| RemainderPrototypeError::Proving(error.to_string()))?;
    enforce_proof_size(transcript.len())?;

    Ok(ForgeMatrixV2RemainderProof {
        prototype_version: REMAINDER_PROTOTYPE_VERSION,
        backend_revision: REMAINDER_BACKEND_REVISION.into(),
        nonce,
        model_manifest_digest: statement.model_manifest_digest,
        challenge_digest: statement.challenge_digest,
        final_activation: statement.final_activation,
        final_activation_digest: statement.final_activation_digest,
        work_digest: statement.work_digest,
        statement_digest: statement.statement_digest,
        transcript,
    })
}

/// Verifies the research proof without replaying the matrix relation. The
/// panic boundary is necessary because the pinned research backend still uses
/// assertions internally; production activation requires replacing those
/// assertions with bounded `Result` paths in an independently reviewed fork.
pub fn verify_remainder_prototype(
    reference: &ForgeMatrixV2Reference,
    block: &BlockChallenge,
    proof: &ForgeMatrixV2RemainderProof,
) -> Result<(), RemainderPrototypeError> {
    ensure_supported_profile(reference)?;
    if proof.prototype_version != REMAINDER_PROTOTYPE_VERSION
        || proof.backend_revision != REMAINDER_BACKEND_REVISION
    {
        return Err(RemainderPrototypeError::Version);
    }
    enforce_proof_size(proof.transcript.len())?;

    let statement = build_statement(
        reference,
        block,
        proof.nonce,
        proof.final_activation.clone(),
    )?;
    if proof.model_manifest_digest != statement.model_manifest_digest {
        return Err(RemainderPrototypeError::Model);
    }
    if proof.challenge_digest != statement.challenge_digest {
        return Err(RemainderPrototypeError::Challenge);
    }
    if proof.final_activation_digest != statement.final_activation_digest {
        return Err(RemainderPrototypeError::OutputDigest);
    }
    if proof.work_digest != statement.work_digest {
        return Err(RemainderPrototypeError::WorkDigest);
    }
    if proof.work_digest > block.target {
        return Err(RemainderPrototypeError::HighHash);
    }
    if proof.statement_digest != statement.statement_digest {
        return Err(RemainderPrototypeError::StatementDigest);
    }

    let transcript: Transcript<Fr> = proof_codec()
        .deserialize(&proof.transcript)
        .map_err(|_| RemainderPrototypeError::Decode)?;
    let canonical = proof_codec()
        .serialize(&transcript)
        .map_err(|_| RemainderPrototypeError::Decode)?;
    if canonical != proof.transcript {
        return Err(RemainderPrototypeError::NonCanonicalEncoding);
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut circuit = prototype_circuit()?;
        set_assignments(&mut circuit, public_assignments(&statement));
        let verifiable = circuit
            .gen_verifiable_circuit()
            .map_err(|error| RemainderPrototypeError::Circuit(error.to_string()))?;
        let prover_config = GKRCircuitProverConfig::runtime_optimized_default();
        let verifier_config =
            GKRCircuitVerifierConfig::new_from_prover_config(&prover_config, false);
        let proof_config = ProofConfig::new_from_prover_config(&prover_config);
        shared_types::perform_function_under_verifier_config!(
            verify_with_config,
            &verifier_config,
            &verifiable,
            &proof_config,
            transcript
        )
    }));
    result.map_err(|_| RemainderPrototypeError::BackendPanic)??;
    Ok(())
}

fn prove_with_config(
    circuit: &ProvableCircuit<Fr>,
) -> Result<(ProofConfig, Transcript<Fr>), RemainderPrototypeError> {
    let mut writer = TranscriptWriter::<Fr, PoseidonSponge<Fr>>::new(TRANSCRIPT_LABEL);
    let config = circuit
        .prove(CircuitHashType::Sha3_256, &mut writer)
        .map_err(|error| RemainderPrototypeError::Proving(error.to_string()))?;
    Ok((config, writer.get_transcript()))
}

fn verify_with_config(
    circuit: &VerifiableCircuit<Fr>,
    proof_config: &ProofConfig,
    transcript: Transcript<Fr>,
) -> Result<(), RemainderPrototypeError> {
    let mut reader = TranscriptReader::<Fr, PoseidonSponge<Fr>>::new(transcript);
    circuit
        .verify(CircuitHashType::Sha3_256, &mut reader, proof_config)
        .map_err(|error| RemainderPrototypeError::Verification(error.to_string()))
}

fn same_proof_config(left: &ProofConfig, right: &ProofConfig) -> bool {
    left.get_circuit_description_hash_type() == right.get_circuit_description_hash_type()
        && left.get_claim_agg_strategy() == right.get_claim_agg_strategy()
        && left.get_claim_agg_constant_column_optimization()
            == right.get_claim_agg_constant_column_optimization()
}

fn proof_codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_REMAINDER_PROTOTYPE_PROOF_BYTES as u64)
}

fn proof_encode_codec() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding()
}

fn enforce_proof_size(actual: usize) -> Result<(), RemainderPrototypeError> {
    if actual > MAX_REMAINDER_PROTOTYPE_PROOF_BYTES {
        return Err(RemainderPrototypeError::ProofTooLarge {
            actual,
            max: MAX_REMAINDER_PROTOTYPE_PROOF_BYTES,
        });
    }
    Ok(())
}

fn ensure_supported_profile(
    reference: &ForgeMatrixV2Reference,
) -> Result<(), RemainderPrototypeError> {
    let model = reference.accelerator_model();
    if model.rows() != V2_TEST_BATCH
        || model.width() != V2_TEST_DIMENSION
        || model.layers() != V2_TEST_LAYERS
        || model.activation_len() != ACTIVATION_LEN
        || model.base_input().len() != ACTIVATION_LEN
        || model.weights().len() != WEIGHT_LEN * V2_TEST_LAYERS as usize
    {
        return Err(RemainderPrototypeError::UnsupportedProfile);
    }
    Ok(())
}

fn build_statement(
    reference: &ForgeMatrixV2Reference,
    block: &BlockChallenge,
    nonce: u64,
    final_activation: Vec<u8>,
) -> Result<PrototypeStatement, RemainderPrototypeError> {
    if final_activation.len() != ACTIVATION_LEN || final_activation.iter().any(|value| *value > 250)
    {
        return Err(RemainderPrototypeError::FinalActivation);
    }
    let descriptor = reference.descriptor();
    let model = reference.accelerator_model();
    let batch = reference.prepare_accelerator_batch(block, nonce, 1)?;
    let challenge_digest = batch
        .challenge_at(0)
        .ok_or(RemainderPrototypeError::Challenge)?;
    let final_activation_digest = batch.candidate_output_digest(0, &final_activation)?;
    let work_digest = batch.candidate_work_digest(0, &final_activation)?;
    let model_manifest_digest = descriptor
        .model
        .digest()
        .map_err(ForgeMatrixV2Error::from)?;

    let base = model
        .base_input()
        .iter()
        .map(|value| i32::from(*value) - OUTPUT_CENTER)
        .collect();
    let weights = model
        .weights()
        .chunks_exact(WEIGHT_LEN)
        .map(|layer| {
            layer
                .iter()
                .map(|value| i32::from(*value) - OUTPUT_CENTER)
                .collect()
        })
        .collect();
    let masks = materialize_masks(&batch)?;
    let statement_digest = statement_digest(
        &descriptor,
        block,
        nonce,
        challenge_digest,
        &final_activation,
        final_activation_digest,
        work_digest,
    )?;

    Ok(PrototypeStatement {
        model_manifest_digest,
        challenge_digest,
        final_activation,
        final_activation_digest,
        work_digest,
        statement_digest,
        base,
        weights,
        masks,
    })
}

fn materialize_masks(
    batch: &crate::ForgeMatrixV2AcceleratorBatch,
) -> Result<Vec<Vec<u32>>, RemainderPrototypeError> {
    let coefficient_count = batch.coefficient_count();
    let expected = (V2_TEST_LAYERS as usize + 1) * coefficient_count;
    if batch.coefficients().len() != expected {
        return Err(RemainderPrototypeError::UnsupportedProfile);
    }
    Ok(batch
        .coefficients()
        .chunks_exact(coefficient_count)
        .map(|coefficients| {
            (0..V2_TEST_BATCH as usize)
                .flat_map(|row| {
                    (0..V2_TEST_DIMENSION as usize).map(move |col| {
                        let mut value = u32::from(coefficients[0]);
                        if row & 1 == 1 {
                            value += u32::from(coefficients[1]);
                        }
                        if col & 1 == 1 {
                            value += u32::from(coefficients[2]);
                        }
                        if col & 2 == 2 {
                            value += u32::from(coefficients[3]);
                        }
                        value
                    })
                })
                .collect()
        })
        .collect::<Vec<_>>())
}

#[allow(clippy::too_many_arguments)]
fn statement_digest(
    descriptor: &crate::ForgeMatrixV2Descriptor,
    block: &BlockChallenge,
    nonce: u64,
    challenge_digest: [u8; 32],
    final_activation: &[u8],
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
) -> Result<[u8; 32], RemainderPrototypeError> {
    let mut hasher = Hasher::new_derive_key(STATEMENT_DOMAIN);
    hasher.update(REMAINDER_BACKEND_REVISION.as_bytes());
    hasher.update(
        &descriptor
            .model
            .digest()
            .map_err(ForgeMatrixV2Error::from)?,
    );
    hasher.update(&block.network_id);
    hasher.update(&block.previous_block);
    hasher.update(&block.transaction_root);
    hasher.update(&block.height.to_le_bytes());
    hasher.update(&block.timestamp.to_le_bytes());
    hasher.update(&block.target);
    hasher.update(&nonce.to_le_bytes());
    hasher.update(&challenge_digest);
    hasher.update(&(final_activation.len() as u64).to_le_bytes());
    hasher.update(final_activation);
    hasher.update(&final_activation_digest);
    hasher.update(&work_digest);
    Ok(*hasher.finalize().as_bytes())
}

fn public_assignments(statement: &PrototypeStatement) -> Assignments {
    let mut values = Assignments::new();
    insert_u64(&mut values, "range-table", &(0_u64..16).collect::<Vec<_>>());
    insert_i32(&mut values, "base", &statement.base);
    for (index, layer) in statement.weights.iter().enumerate() {
        insert_i32(&mut values, &format!("weight-{index}"), layer);
    }
    for (index, mask) in statement.masks.iter().enumerate() {
        insert_u64(
            &mut values,
            &format!("mask-{index}"),
            &mask
                .iter()
                .map(|value| u64::from(*value))
                .collect::<Vec<_>>(),
        );
    }
    insert_i32(
        &mut values,
        "final-activation",
        &statement
            .final_activation
            .iter()
            .map(|value| i32::from(*value) - OUTPUT_CENTER)
            .collect::<Vec<_>>(),
    );
    insert_u64(
        &mut values,
        "statement-digest",
        &statement_digest_words(statement.statement_digest),
    );
    values
}

fn committed_assignments(
    proof: &ForgeMatrixV2ReferenceProof,
    statement: &PrototypeStatement,
) -> Result<Assignments, RemainderPrototypeError> {
    if proof.initial_reductions.len() != ACTIVATION_LEN
        || proof.initial_activation.len() != ACTIVATION_LEN
        || proof.layers.len() != V2_TEST_LAYERS as usize
        || proof.layers.iter().any(|layer| {
            layer.reductions.len() != ACTIVATION_LEN || layer.output.len() != ACTIVATION_LEN
        })
    {
        return Err(RemainderPrototypeError::UnsupportedProfile);
    }
    let mut values = Assignments::new();
    insert_u64(
        &mut values,
        "statement-digest-witness",
        &statement_digest_words(statement.statement_digest),
    );
    let mut range_digits = Vec::with_capacity(RANGE_DIGIT_VALUES);
    insert_reduction_assignments(
        &mut values,
        &mut range_digits,
        "init",
        &proof.initial_reductions,
    );
    insert_i32(
        &mut values,
        "activation-0",
        &proof
            .initial_activation
            .iter()
            .map(|value| i32::from(*value))
            .collect::<Vec<_>>(),
    );
    for (index, layer) in proof.layers.iter().enumerate() {
        insert_reduction_assignments(
            &mut values,
            &mut range_digits,
            &format!("layer-{index}"),
            &layer.reductions,
        );
        insert_i32(
            &mut values,
            &format!("activation-{}", index + 1),
            &layer
                .output
                .iter()
                .map(|value| i32::from(*value))
                .collect::<Vec<_>>(),
        );
    }
    debug_assert_eq!(range_digits.len(), RANGE_DIGITS_USED * ACTIVATION_LEN);
    range_digits.resize(RANGE_DIGIT_VALUES, 0);
    let mut multiplicities = vec![0_u64; 16];
    for digit in &range_digits {
        multiplicities[*digit as usize] += 1;
    }
    insert_u64(&mut values, "range-digits", &range_digits);
    insert_u64(&mut values, "range-multiplicities", &multiplicities);
    Ok(values)
}

fn statement_digest_words(digest: [u8; 32]) -> Vec<u64> {
    let mut words = digest
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk")))
        .collect::<Vec<_>>();
    words.resize(ACTIVATION_LEN, 0);
    words
}

fn insert_reduction_assignments(
    assignments: &mut Assignments,
    range_digits: &mut Vec<u64>,
    prefix: &str,
    reductions: &[ReductionWitness],
) {
    insert_i32(
        assignments,
        &format!("{prefix}-z"),
        &reductions
            .iter()
            .map(|witness| witness.z)
            .collect::<Vec<_>>(),
    );
    let fields = [
        (
            "encoded",
            reductions
                .iter()
                .map(|witness| u64::from(witness.encoded_z))
                .collect::<Vec<_>>(),
            u64::from(V2_TRANSITION_MODULUS - 1),
        ),
        (
            "square-q",
            reductions
                .iter()
                .map(|witness| u64::from(witness.square_quotient))
                .collect::<Vec<_>>(),
            u64::from(V2_TRANSITION_MODULUS - 1),
        ),
        (
            "square-r",
            reductions
                .iter()
                .map(|witness| u64::from(witness.square_remainder))
                .collect::<Vec<_>>(),
            u64::from(V2_TRANSITION_MODULUS - 1),
        ),
        (
            "cube-q",
            reductions
                .iter()
                .map(|witness| u64::from(witness.cube_quotient))
                .collect::<Vec<_>>(),
            u64::from(V2_TRANSITION_MODULUS - 1),
        ),
        (
            "cube-r",
            reductions
                .iter()
                .map(|witness| u64::from(witness.cube_remainder))
                .collect::<Vec<_>>(),
            u64::from(V2_TRANSITION_MODULUS - 1),
        ),
        (
            "output-q",
            reductions
                .iter()
                .map(|witness| u64::from(witness.output_quotient))
                .collect::<Vec<_>>(),
            MAX_OUTPUT_QUOTIENT,
        ),
        (
            "output-r",
            reductions
                .iter()
                .map(|witness| u64::from(witness.output_remainder))
                .collect::<Vec<_>>(),
            250,
        ),
    ];
    for (field, values, max) in fields {
        let label = format!("{prefix}-{field}");
        insert_u64(assignments, &label, &values);
        append_range_digits(range_digits, &values, max);
    }
    insert_u64(
        assignments,
        &format!("{prefix}-negative"),
        &reductions
            .iter()
            .map(|witness| u64::from(witness.z < 0))
            .collect::<Vec<_>>(),
    );
}

fn append_range_digits(range_digits: &mut Vec<u64>, values: &[u64], max: u64) {
    let bits = (u64::BITS - max.leading_zeros()) as usize;
    let digits = bits.div_ceil(4);
    for digit in 0..digits {
        range_digits.extend(values.iter().map(|value| (value >> (digit * 4)) & 0xf));
        range_digits.extend(
            values
                .iter()
                .map(|value| ((max - value) >> (digit * 4)) & 0xf),
        );
    }
}

fn insert_i32(assignments: &mut Assignments, label: &str, values: &[i32]) {
    assignments.insert(
        label.into(),
        values
            .iter()
            .map(|value| signed_field(i64::from(*value)))
            .collect(),
    );
}

fn insert_u64(assignments: &mut Assignments, label: &str, values: &[u64]) {
    assignments.insert(label.into(), values.iter().copied().map(Fr::from).collect());
}

fn signed_field(value: i64) -> Fr {
    if value >= 0 {
        Fr::from(value as u64)
    } else {
        -Fr::from(value.unsigned_abs())
    }
}

fn set_assignments(circuit: &mut Circuit<Fr>, assignments: Assignments) {
    for (label, values) in assignments {
        circuit.set_input(&label, MultilinearExtension::new(values));
    }
}

fn prototype_circuit() -> Result<Circuit<Fr>, RemainderPrototypeError> {
    PROTOTYPE_CIRCUIT
        .get_or_init(|| build_circuit().map_err(|error| error.to_string()))
        .clone()
        .map_err(RemainderPrototypeError::Circuit)
}

fn build_circuit() -> Result<Circuit<Fr>, RemainderPrototypeError> {
    let mut builder = CircuitBuilder::<Fr>::new();
    let mut constraints = Vec::new();
    let public = builder.add_input_layer("Statement", LayerVisibility::Public);
    let committed = builder.add_input_layer("Witness", LayerVisibility::Committed);

    let range_table = builder.add_input_shred("range-table", 4, &public);
    let range_digits = builder.add_input_shred("range-digits", 12, &committed);
    let range_multiplicities = builder.add_input_shred("range-multiplicities", 4, &committed);
    let mut split_range_digits = builder.add_split_node(&range_digits, 9).into_iter();
    let base = builder.add_input_shred("base", ACTIVATION_NUM_VARS, &public);
    let weights = (0..V2_TEST_LAYERS as usize)
        .map(|index| builder.add_input_shred(&format!("weight-{index}"), WEIGHT_NUM_VARS, &public))
        .collect::<Vec<_>>();
    let masks = (0..=V2_TEST_LAYERS as usize)
        .map(|index| {
            builder.add_input_shred(&format!("mask-{index}"), ACTIVATION_NUM_VARS, &public)
        })
        .collect::<Vec<_>>();
    let final_activation =
        builder.add_input_shred("final-activation", ACTIVATION_NUM_VARS, &public);
    let statement_digest =
        builder.add_input_shred("statement-digest", ACTIVATION_NUM_VARS, &public);
    let statement_digest_witness =
        builder.add_input_shred("statement-digest-witness", ACTIVATION_NUM_VARS, &committed);
    constraints.push(statement_digest_witness - statement_digest);

    let mut activation = add_reduction(
        &mut builder,
        &committed,
        "init",
        base + masks[0].clone(),
        "activation-0",
        &mut split_range_digits,
        &mut constraints,
    );
    for index in 0..V2_TEST_LAYERS as usize {
        let accumulator = builder.add_matmult_node(&activation, (1, 2), &weights[index], (2, 2));
        activation = add_reduction(
            &mut builder,
            &committed,
            &format!("layer-{index}"),
            accumulator + masks[index + 1].clone(),
            &format!("activation-{}", index + 1),
            &mut split_range_digits,
            &mut constraints,
        );
    }
    constraints.push(activation - final_activation);
    debug_assert_eq!(
        split_range_digits.len(),
        RANGE_DIGITS_PADDED - RANGE_DIGITS_USED
    );
    let zero_at_same_shape = constraints[0].clone() * Fr::from(0);
    constraints.resize(constraints.len().next_power_of_two(), zero_at_same_shape);
    add_zero_constraint(
        &mut builder,
        AbstractExpression::binary_tree_selector(constraints),
    );

    let lookup_challenge = builder.add_fiat_shamir_challenge_node(1);
    let lookup_table = builder.add_lookup_table(&range_table, &lookup_challenge);
    builder.add_lookup_constraint(&lookup_table, &range_digits, &range_multiplicities);

    let circuit = builder
        .build_with_layer_combination()
        .map_err(|error| RemainderPrototypeError::Circuit(error.to_string()))?;
    Ok(circuit)
}

fn add_reduction(
    builder: &mut CircuitBuilder<Fr>,
    committed: &InputLayerNodeRef<Fr>,
    prefix: &str,
    expected_z: AbstractExpression<Fr>,
    activation_label: &str,
    range_digits: &mut impl ExactSizeIterator<Item = NodeRef<Fr>>,
    constraints: &mut Vec<AbstractExpression<Fr>>,
) -> NodeRef<Fr> {
    let z = builder.add_input_shred(&format!("{prefix}-z"), ACTIVATION_NUM_VARS, committed);
    let encoded =
        builder.add_input_shred(&format!("{prefix}-encoded"), ACTIVATION_NUM_VARS, committed);
    let square_q = builder.add_input_shred(
        &format!("{prefix}-square-q"),
        ACTIVATION_NUM_VARS,
        committed,
    );
    let square_r = builder.add_input_shred(
        &format!("{prefix}-square-r"),
        ACTIVATION_NUM_VARS,
        committed,
    );
    let cube_q =
        builder.add_input_shred(&format!("{prefix}-cube-q"), ACTIVATION_NUM_VARS, committed);
    let cube_r =
        builder.add_input_shred(&format!("{prefix}-cube-r"), ACTIVATION_NUM_VARS, committed);
    let output_q = builder.add_input_shred(
        &format!("{prefix}-output-q"),
        ACTIVATION_NUM_VARS,
        committed,
    );
    let output_r = builder.add_input_shred(
        &format!("{prefix}-output-r"),
        ACTIVATION_NUM_VARS,
        committed,
    );
    let negative = builder.add_input_shred(
        &format!("{prefix}-negative"),
        ACTIVATION_NUM_VARS,
        committed,
    );
    let activation = builder.add_input_shred(activation_label, ACTIVATION_NUM_VARS, committed);

    constraints.push(z.clone() - expected_z);
    constraints
        .push(encoded.clone() - z - negative.clone() * Fr::from(u64::from(V2_TRANSITION_MODULUS)));
    constraints.push(
        encoded.clone() * encoded.clone()
            - square_q.clone() * Fr::from(u64::from(V2_TRANSITION_MODULUS))
            - square_r.clone(),
    );
    constraints.push(
        square_r.clone() * encoded.clone()
            - cube_q.clone() * Fr::from(u64::from(V2_TRANSITION_MODULUS))
            - cube_r.clone(),
    );
    constraints
        .push(cube_r.clone() - output_q.clone() * Fr::from(OUTPUT_MODULUS) - output_r.clone());
    constraints.push(activation.clone() - output_r.clone() + Fr::from(OUTPUT_CENTER as u64));
    constraints.push(negative.clone() * (negative.clone() - Fr::from(1)));

    for node_and_max in [
        ("encoded", &encoded, u64::from(V2_TRANSITION_MODULUS - 1)),
        ("square-q", &square_q, u64::from(V2_TRANSITION_MODULUS - 1)),
        ("square-r", &square_r, u64::from(V2_TRANSITION_MODULUS - 1)),
        ("cube-q", &cube_q, u64::from(V2_TRANSITION_MODULUS - 1)),
        ("cube-r", &cube_r, u64::from(V2_TRANSITION_MODULUS - 1)),
        ("output-q", &output_q, MAX_OUTPUT_QUOTIENT),
        ("output-r", &output_r, 250),
    ] {
        let (_, node, max) = node_and_max;
        add_range_check(node, max, range_digits, constraints);
    }
    activation
}

fn add_range_check(
    value: &NodeRef<Fr>,
    max: u64,
    range_digits: &mut impl Iterator<Item = NodeRef<Fr>>,
    constraints: &mut Vec<AbstractExpression<Fr>>,
) {
    let bits = (u64::BITS - max.leading_zeros()) as usize;
    let digits = bits.div_ceil(4);
    let mut reconstruction: AbstractExpression<Fr> = value.into();
    let mut upper_bound: AbstractExpression<Fr> = value.into();
    for digit in 0..digits {
        let coefficient = Fr::from(1_u64 << (digit * 4));
        let value_digit = range_digits.next().expect("range digit count is fixed");
        let slack_digit = range_digits.next().expect("range digit count is fixed");
        reconstruction -= value_digit * coefficient;
        upper_bound += slack_digit * coefficient;
    }
    constraints.push(reconstruction);
    constraints.push(upper_bound - Fr::from(max));
}

fn add_zero_constraint(builder: &mut CircuitBuilder<Fr>, expression: AbstractExpression<Fr>) {
    let constraint = builder.add_sector(expression);
    builder.set_output(&constraint);
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::v2_test_reference;

    fn block() -> BlockChallenge {
        BlockChallenge {
            network_id: [0x63; 32],
            previous_block: [0x11; 32],
            transaction_root: [0x22; 32],
            height: 42,
            timestamp: 1_777_777_777,
            target: [0xff; 32],
        }
    }

    #[test]
    fn complete_tiny_relation_proves_and_verifies() {
        let reference = v2_test_reference().unwrap();
        let started = Instant::now();
        let mut proof = prove_remainder_prototype(&reference, &block(), 7).unwrap();
        let proving = started.elapsed();
        let started = Instant::now();
        verify_remainder_prototype(&reference, &block(), &proof).unwrap();
        let verifying = started.elapsed();
        eprintln!(
            "Remainder prototype: {} bytes, prove {:?}, verify {:?}",
            proof.transcript.len(),
            proving,
            verifying
        );
        assert!(!proof.transcript.is_empty());
        assert!(proof.transcript.len() <= MAX_REMAINDER_PROTOTYPE_PROOF_BYTES);

        proof.prototype_version ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::Version)
        ));
        proof.prototype_version ^= 1;

        proof.backend_revision.push('0');
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::Version)
        ));
        proof.backend_revision.pop();

        proof.nonce ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::Challenge)
        ));
        proof.nonce ^= 1;

        proof.model_manifest_digest[0] ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::Model)
        ));
        proof.model_manifest_digest[0] ^= 1;

        proof.challenge_digest[0] ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::Challenge)
        ));
        proof.challenge_digest[0] ^= 1;

        proof.final_activation[0] ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::OutputDigest)
        ));
        proof.final_activation[0] ^= 1;

        proof.final_activation_digest[0] ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::OutputDigest)
        ));
        proof.final_activation_digest[0] ^= 1;

        proof.work_digest[0] ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::WorkDigest)
        ));
        proof.work_digest[0] ^= 1;

        proof.statement_digest[0] ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::StatementDigest)
        ));
        proof.statement_digest[0] ^= 1;

        proof.transcript[0] ^= 1;
        assert!(verify_remainder_prototype(&reference, &block(), &proof).is_err());
        proof.transcript[0] ^= 1;

        let mut changed_block = block();
        changed_block.transaction_root[0] ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &changed_block, &proof),
            Err(RemainderPrototypeError::Challenge)
        ));

        let mut changed_target = block();
        changed_target.target[0] ^= 1;
        assert!(matches!(
            verify_remainder_prototype(&reference, &changed_target, &proof),
            Err(RemainderPrototypeError::Challenge)
        ));

        proof.transcript.push(0);
        assert!(matches!(
            verify_remainder_prototype(&reference, &block(), &proof),
            Err(RemainderPrototypeError::Decode)
        ));
        proof.transcript.pop();
        assert!(matches!(
            enforce_proof_size(MAX_REMAINDER_PROTOTYPE_PROOF_BYTES + 1),
            Err(RemainderPrototypeError::ProofTooLarge { .. })
        ));
    }
}
