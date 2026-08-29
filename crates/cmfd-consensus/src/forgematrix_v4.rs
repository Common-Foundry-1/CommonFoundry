//! Consensus geometry reserved for the isolated ProductionV4 proof system.
//!
//! This module defines only the field, BaseFold, and trace-index parameters.
//! It does not activate ProductionV4 or provide a verifier.

use crate::{
    BlockChallenge,
    forgematrix_v2::{
        PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
        PRODUCTION_V2_LAYERS_PER_BANK,
    },
};

pub const FORGEMATRIX_V4_PROOF_SYSTEM_DIGEST_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/V4/ProofSystemDigest/v1";
pub const FORGEMATRIX_V4_TRANSCRIPT_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/V4/KoalaBearBaseFoldTranscript/v1";
pub const FORGEMATRIX_V4_BASEFOLD_SOURCE_REVISION: &str =
    "92b8eabaea9ab7306da5826caa700adabf7445ba";
pub const FORGEMATRIX_V4_POSEIDON_SUITE: &str =
    "slop-koala-bear/KoalaBearDegree4Duplex/Poseidon2-width16-digest8";
pub const FORGEMATRIX_V4_PROOF_CODEC: &str = "cmfd-v4-transparent-v1/final-fields;three-banks(dynamic-commitment,two-relations,direct-row-rlc-basefold-opening);fixed-shape;canonical-u32;little-endian;reject-trailing";
pub const FORGEMATRIX_V4_TRACE_RELATIONS: &str =
    "preactivation=matrix-accumulator+challenge-coordinate-mask;next-activation=preactivation^3";
pub const FORGEMATRIX_V4_EXECUTION_SEMANTICS: &str = "model-byte x maps to x-125;initial-activation=(base-input+CMFD/FORGEMATRIX/MASKCOEFF/V2(challenge,u32::MAX))^3;layer-mask=CMFD/FORGEMATRIX/MASKCOEFF/V2(challenge,global-layer);all arithmetic canonical KoalaBear";
pub const FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/V4/FinalActivation/v1";
pub const FORGEMATRIX_V4_CHALLENGE_DIGEST_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/V4/Challenge/v1";
pub const FORGEMATRIX_V4_WORK_DIGEST_DOMAIN: &str = "CommonFoundry/ForgeMatrix/V4/Work/v1";
/// Authenticated fixed-bank record selected by ProductionV4 Testnet-1.
pub const PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST: [u8; 32] = [
    0x2e, 0xfd, 0x2c, 0x42, 0x44, 0xbb, 0xd7, 0x80, 0x85, 0x47, 0xb8, 0x52, 0x66, 0x98, 0x75, 0x44,
    0x23, 0x3f, 0xbe, 0x33, 0x9f, 0x44, 0x51, 0x35, 0xb0, 0x78, 0x43, 0xaa, 0x88, 0x93, 0xd4, 0x5e,
];
pub const PRODUCTION_V4_MODEL_MANIFEST_DIGEST: [u8; 32] = [
    0x68, 0xf6, 0xfe, 0x67, 0x4f, 0x75, 0xa3, 0x63, 0xc6, 0x2c, 0x27, 0x5e, 0xbb, 0x11, 0xfa, 0x74,
    0xaa, 0x08, 0x9e, 0x9b, 0xbd, 0xe5, 0xbc, 0xb9, 0x52, 0xec, 0x35, 0xb8, 0x89, 0x0b, 0x57, 0x5c,
];
pub const FORGEMATRIX_V4_RELATION_TRANSCRIPT: &str = "commitments-v1;bank0-relations;bank1-relations;bank0-opening;bank2-relations;bank1-opening;final-point-v1;bank2-opening";

pub const FORGEMATRIX_V4_ALGORITHM_VERSION: u32 = 4;
pub const FORGEMATRIX_V4_PROOF_VERSION: u32 = 1;
pub const FORGEMATRIX_V4_FIELD_MODULUS: u32 = 0x7f00_0001;
pub const FORGEMATRIX_V4_EXTENSION_DEGREE: u32 = 4;
pub const FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES: u32 = 23;
pub const FORGEMATRIX_V4_BASEFOLD_ROWS: usize = 1 << FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES;
pub const FORGEMATRIX_V4_FIXED_COLUMNS: usize = 256;
pub const FORGEMATRIX_V4_DYNAMIC_COLUMNS: usize = 16;
pub const FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP: u32 = 1;
pub const FORGEMATRIX_V4_BASEFOLD_QUERIES: u32 = 270;
pub const FORGEMATRIX_V4_BASEFOLD_POW_BITS: u32 = 16;
pub const FORGEMATRIX_V4_RELATION_REPETITIONS: u32 = 2;
pub const FORGEMATRIX_V4_MAX_OPENING_CLAIMS: usize = 16;
pub const FORGEMATRIX_V4_RELATION_OPENING_CLAIMS_PER_BANK: usize = 12;
pub const FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK: usize = 16;
pub const FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES: usize = 19;
pub const FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE: usize = 3;
pub const FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES: usize = 7;
pub const FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE: usize = 2;
pub const FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES: usize = 26;
pub const FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE: usize = 4;
pub const FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES: usize =
    PRODUCTION_V2_BATCH as usize * PRODUCTION_V2_DIMENSION as usize * std::mem::size_of::<u32>();

pub const FORGEMATRIX_V4_WEIGHT_AXIS_ORDER: &str =
    "[column,common,layer-within-bank] least-significant/fastest-changing first";
pub const FORGEMATRIX_V4_DYNAMIC_AXIS_ORDER: &str =
    "[column,batch-row,layer-within-bank,trace-kind] least-significant/fastest-changing first";

const ROW_MASK: usize = FORGEMATRIX_V4_BASEFOLD_ROWS - 1;

/// Commits every immutable field, trace, transcript, PCS, and codec choice
/// used by the isolated V4 proof system.
pub fn forgematrix_v4_proof_system_digest() -> [u8; 32] {
    fn update_text(hasher: &mut blake3::Hasher, value: &str) {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }

    let mut hasher = blake3::Hasher::new_derive_key(FORGEMATRIX_V4_PROOF_SYSTEM_DIGEST_DOMAIN);
    hasher.update(&1_u32.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_ALGORITHM_VERSION.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_PROOF_VERSION.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_FIELD_MODULUS.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_EXTENSION_DEGREE.to_le_bytes());
    hasher.update(&PRODUCTION_V2_BATCH.to_le_bytes());
    hasher.update(&PRODUCTION_V2_DIMENSION.to_le_bytes());
    hasher.update(&PRODUCTION_V2_LAYERS.to_le_bytes());
    hasher.update(&PRODUCTION_V2_BANKS.to_le_bytes());
    hasher.update(&PRODUCTION_V2_LAYERS_PER_BANK.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES.to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_FIXED_COLUMNS as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_DYNAMIC_COLUMNS as u64).to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_BASEFOLD_QUERIES.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_BASEFOLD_POW_BITS.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_RELATION_REPETITIONS.to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_MAX_OPENING_CLAIMS as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_RELATION_OPENING_CLAIMS_PER_BANK as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE as u64).to_le_bytes());
    hasher.update(&(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES as u64).to_le_bytes());
    update_text(&mut hasher, FORGEMATRIX_V4_WEIGHT_AXIS_ORDER);
    update_text(&mut hasher, FORGEMATRIX_V4_DYNAMIC_AXIS_ORDER);
    update_text(&mut hasher, FORGEMATRIX_V4_TRACE_RELATIONS);
    update_text(&mut hasher, FORGEMATRIX_V4_EXECUTION_SEMANTICS);
    update_text(&mut hasher, FORGEMATRIX_V4_FINAL_ACTIVATION_DIGEST_DOMAIN);
    update_text(&mut hasher, FORGEMATRIX_V4_CHALLENGE_DIGEST_DOMAIN);
    update_text(&mut hasher, FORGEMATRIX_V4_WORK_DIGEST_DOMAIN);
    update_text(&mut hasher, FORGEMATRIX_V4_RELATION_TRANSCRIPT);
    update_text(&mut hasher, FORGEMATRIX_V4_TRANSCRIPT_DOMAIN);
    update_text(&mut hasher, FORGEMATRIX_V4_POSEIDON_SUITE);
    update_text(&mut hasher, FORGEMATRIX_V4_PROOF_CODEC);
    update_text(&mut hasher, FORGEMATRIX_V4_BASEFOLD_SOURCE_REVISION);
    *hasher.finalize().as_bytes()
}

pub fn forgematrix_v4_challenge_digest(
    block: &BlockChallenge,
    nonce: u64,
    model_manifest_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(FORGEMATRIX_V4_CHALLENGE_DIGEST_DOMAIN);
    hasher.update(&1_u32.to_le_bytes());
    hasher.update(&block.network_id);
    hasher.update(&block.previous_block);
    hasher.update(&block.transaction_root);
    hasher.update(&block.height.to_le_bytes());
    hasher.update(&block.timestamp.to_le_bytes());
    hasher.update(&block.target);
    hasher.update(&FORGEMATRIX_V4_ALGORITHM_VERSION.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_PROOF_VERSION.to_le_bytes());
    hasher.update(&forgematrix_v4_proof_system_digest());
    hasher.update(&model_manifest_digest);
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub fn forgematrix_v4_work_digest(
    model_manifest_digest: [u8; 32],
    challenge_digest: [u8; 32],
    final_activation_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(FORGEMATRIX_V4_WORK_DIGEST_DOMAIN);
    hasher.update(&1_u32.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_ALGORITHM_VERSION.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_PROOF_VERSION.to_le_bytes());
    hasher.update(&forgematrix_v4_proof_system_digest());
    hasher.update(&model_manifest_digest);
    hasher.update(&challenge_digest);
    hasher.update(&final_activation_digest);
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum ForgeMatrixV4DynamicTraceKind {
    /// Matrix accumulator plus the challenge-derived coordinate mask.
    Preactivation = 0,
    NextActivation = 1,
}

/// Returns the unchanged model-bank byte index and its stacked BaseFold
/// `(column, row)` location for one weight in the selected 128-layer bank.
pub fn forgematrix_v4_weight_index(
    layer: usize,
    common: usize,
    column: usize,
) -> Option<(usize, usize, usize)> {
    let layers = PRODUCTION_V2_LAYERS_PER_BANK as usize;
    let dimension = PRODUCTION_V2_DIMENSION as usize;
    if layer >= layers || common >= dimension || column >= dimension {
        return None;
    }
    let linear = ((layer * dimension) + common) * dimension + column;
    let (basefold_column, basefold_row) = split_basefold_index(linear)?;
    (basefold_column < FORGEMATRIX_V4_FIXED_COLUMNS).then_some((
        linear,
        basefold_column,
        basefold_row,
    ))
}

/// Returns the logical dynamic-trace index and its stacked BaseFold
/// `(column, row)` location.
pub fn forgematrix_v4_dynamic_index(
    kind: ForgeMatrixV4DynamicTraceKind,
    layer: usize,
    batch_row: usize,
    column: usize,
) -> Option<(usize, usize, usize)> {
    let layers = PRODUCTION_V2_LAYERS_PER_BANK as usize;
    let batch = PRODUCTION_V2_BATCH as usize;
    let dimension = PRODUCTION_V2_DIMENSION as usize;
    if layer >= layers || batch_row >= batch || column >= dimension {
        return None;
    }
    let linear = ((((kind as usize) * layers + layer) * batch) + batch_row) * dimension + column;
    let (basefold_column, basefold_row) = split_basefold_index(linear)?;
    (basefold_column < FORGEMATRIX_V4_DYNAMIC_COLUMNS).then_some((
        linear,
        basefold_column,
        basefold_row,
    ))
}

fn split_basefold_index(linear: usize) -> Option<(usize, usize)> {
    Some((
        linear.checked_shr(FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES)?,
        linear & ROW_MASK,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_layout_exactly_covers_one_production_bank() {
        let layers = PRODUCTION_V2_LAYERS_PER_BANK as usize;
        let dimension = PRODUCTION_V2_DIMENSION as usize;
        assert_eq!(
            layers * dimension * dimension,
            FORGEMATRIX_V4_FIXED_COLUMNS * FORGEMATRIX_V4_BASEFOLD_ROWS
        );

        assert_eq!(forgematrix_v4_weight_index(0, 0, 0), Some((0, 0, 0)));
        assert_eq!(
            forgematrix_v4_weight_index(0, 2047, 4095),
            Some((
                FORGEMATRIX_V4_BASEFOLD_ROWS - 1,
                0,
                FORGEMATRIX_V4_BASEFOLD_ROWS - 1
            ))
        );
        assert_eq!(
            forgematrix_v4_weight_index(0, 2048, 0),
            Some((FORGEMATRIX_V4_BASEFOLD_ROWS, 1, 0))
        );
        assert_eq!(
            forgematrix_v4_weight_index(127, 4095, 4095),
            Some((
                FORGEMATRIX_V4_FIXED_COLUMNS * FORGEMATRIX_V4_BASEFOLD_ROWS - 1,
                FORGEMATRIX_V4_FIXED_COLUMNS - 1,
                FORGEMATRIX_V4_BASEFOLD_ROWS - 1,
            ))
        );
        assert_eq!(forgematrix_v4_weight_index(128, 0, 0), None);
    }

    #[test]
    fn dynamic_layout_exactly_covers_both_production_traces() {
        let layers = PRODUCTION_V2_LAYERS_PER_BANK as usize;
        let batch = PRODUCTION_V2_BATCH as usize;
        let dimension = PRODUCTION_V2_DIMENSION as usize;
        assert_eq!(
            2 * layers * batch * dimension,
            FORGEMATRIX_V4_DYNAMIC_COLUMNS * FORGEMATRIX_V4_BASEFOLD_ROWS
        );
        assert_eq!(
            FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES,
            2 * 1024 * 1024
        );

        assert_eq!(
            forgematrix_v4_dynamic_index(
                ForgeMatrixV4DynamicTraceKind::Preactivation,
                15,
                127,
                4095,
            ),
            Some((
                FORGEMATRIX_V4_BASEFOLD_ROWS - 1,
                0,
                FORGEMATRIX_V4_BASEFOLD_ROWS - 1
            ))
        );
        assert_eq!(
            forgematrix_v4_dynamic_index(ForgeMatrixV4DynamicTraceKind::Preactivation, 16, 0, 0,),
            Some((FORGEMATRIX_V4_BASEFOLD_ROWS, 1, 0))
        );
        assert_eq!(
            forgematrix_v4_dynamic_index(ForgeMatrixV4DynamicTraceKind::NextActivation, 0, 0, 0,),
            Some((8 * FORGEMATRIX_V4_BASEFOLD_ROWS, 8, 0))
        );
        assert_eq!(
            forgematrix_v4_dynamic_index(
                ForgeMatrixV4DynamicTraceKind::NextActivation,
                127,
                127,
                4095,
            ),
            Some((
                FORGEMATRIX_V4_DYNAMIC_COLUMNS * FORGEMATRIX_V4_BASEFOLD_ROWS - 1,
                FORGEMATRIX_V4_DYNAMIC_COLUMNS - 1,
                FORGEMATRIX_V4_BASEFOLD_ROWS - 1,
            ))
        );
        assert_eq!(
            forgematrix_v4_dynamic_index(ForgeMatrixV4DynamicTraceKind::Preactivation, 0, 128, 0,),
            None
        );
    }

    #[test]
    fn proof_system_digest_has_a_pinned_known_answer() {
        let digest = forgematrix_v4_proof_system_digest();
        assert_ne!(digest, [0; 32]);
        assert_eq!(
            hex::encode(digest),
            "e849e3bfc83f8f8dd0f1fc1100879417718ba2bffb92af5cd649b61c720675a3"
        );
    }

    #[cfg(feature = "forgematrix-v4-verifier")]
    #[test]
    fn production_v4_message_order_manifest_matches_consensus() {
        use crate::{
            forgematrix_v4_basefold::{OPENING_REDUCTION_DOMAIN, TRANSCRIPT_STATEMENT_DOMAIN},
            forgematrix_v4_basefold_codec::FORGEMATRIX_V4_OPENING_REDUCTION_MAX_BYTES,
            forgematrix_v4_proof_codec::FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
            forgematrix_v4_relations::{
                COMMITMENTS_DOMAIN, CUBIC_POINT_DOMAIN, CUBIC_PROOF_DOMAIN, FINAL_POINT_DOMAIN,
                MATRIX_POINT_DOMAIN, MATRIX_PROOF_DOMAIN, SHIFT_PROOF_DOMAIN,
            },
        };

        fn text(bytes: &[u8]) -> &str {
            std::str::from_utf8(bytes).expect("consensus domain is UTF-8")
        }

        fn strings(value: &serde_json::Value) -> Vec<&str> {
            value
                .as_array()
                .expect("manifest value is an array")
                .iter()
                .map(|value| value.as_str().expect("manifest array contains strings"))
                .collect()
        }

        fn sumcheck_bytes(variables: usize, degree: usize) -> usize {
            const EXTENSION_BYTES: usize = FORGEMATRIX_V4_EXTENSION_DEGREE as usize * 4;
            variables * (degree + 1) * EXTENSION_BYTES
                + EXTENSION_BYTES
                + variables * EXTENSION_BYTES
                + EXTENSION_BYTES
        }

        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/consensus/production-v4-message-order-v1.json"
        ))
        .unwrap();
        assert_eq!(
            manifest["schema"],
            "CommonFoundry/ForgeMatrix/V4/MessageOrder/v1"
        );
        assert_eq!(manifest["consensus_change"], false);
        assert_eq!(manifest["field"]["modulus"], FORGEMATRIX_V4_FIELD_MODULUS);
        assert_eq!(
            manifest["field"]["extension_degree"],
            FORGEMATRIX_V4_EXTENSION_DEGREE
        );
        assert_eq!(manifest["field"]["extension_polynomial"], "X^4 - 3");
        assert_eq!(
            strings(&manifest["field"]["extension_coefficient_order"]),
            ["1", "X", "X^2", "X^3"]
        );
        assert_eq!(
            manifest["challenger"]["suite"],
            FORGEMATRIX_V4_POSEIDON_SUITE
        );
        assert_eq!(
            manifest["challenger"]["statement_domain"],
            TRANSCRIPT_STATEMENT_DOMAIN
        );

        let domains = &manifest["domains"];
        assert_eq!(domains["commitments"], text(COMMITMENTS_DOMAIN));
        assert_eq!(domains["matrix_point"], text(MATRIX_POINT_DOMAIN));
        assert_eq!(domains["matrix_proof"], text(MATRIX_PROOF_DOMAIN));
        assert_eq!(domains["shift_proof"], text(SHIFT_PROOF_DOMAIN));
        assert_eq!(domains["cubic_point"], text(CUBIC_POINT_DOMAIN));
        assert_eq!(domains["cubic_proof"], text(CUBIC_PROOF_DOMAIN));
        assert_eq!(domains["final_point"], text(FINAL_POINT_DOMAIN));
        assert_eq!(domains["opening_reduction"], text(OPENING_REDUCTION_DOMAIN));

        assert_eq!(
            strings(&manifest["top_level_sequence"]),
            [
                "transcript-statement-digest",
                "commitments",
                "bank-0/repetition-0/relations",
                "bank-0/repetition-1/relations",
                "bank-1/repetition-0/relations",
                "bank-1/repetition-1/relations",
                "bank-0/opening",
                "bank-2/repetition-0/relations",
                "bank-2/repetition-1/relations",
                "bank-1/opening",
                "final-point/repetition-0",
                "final-point/repetition-1",
                "bank-2/opening",
            ]
        );
        assert_eq!(
            FORGEMATRIX_V4_RELATION_TRANSCRIPT,
            "commitments-v1;bank0-relations;bank1-relations;bank0-opening;bank2-relations;bank1-opening;final-point-v1;bank2-opening"
        );
        assert_eq!(
            strings(&manifest["relation_repetition_sequence"]),
            [
                "matrix-point: observe domain, bank, repetition; sample layer-7, batch-7, output-12",
                "matrix-proof: observe preactivation, mask; verify 19-variable degree-3 sumcheck; observe weight, input",
                "shift-proof: observe input, boundary; verify 7-variable degree-2 sumcheck; observe next-activation",
                "route matrix, shift, and preceding-bank boundary opening claims",
                "cubic-point: observe domain, bank, repetition; sample layer-7, batch-7, output-12",
                "cubic-proof: verify zero-claim 26-variable degree-4 sumcheck; observe preactivation, next-activation",
            ]
        );
        assert_eq!(
            strings(&manifest["sumcheck_sequence"]),
            [
                "observe first polynomial coefficients",
                "for each later polynomial: sample extension challenge, then observe coefficients",
                "sample final extension challenge",
                "check encoded terminal point and terminal evaluation",
            ]
        );

        let opening = &manifest["opening_reduction"];
        assert_eq!(
            opening["claims_before_padding"],
            FORGEMATRIX_V4_RELATION_OPENING_CLAIMS_PER_BANK
        );
        assert_eq!(
            opening["claims_after_padding"],
            FORGEMATRIX_V4_OPENING_CLAIMS_PER_BANK
        );
        assert_eq!(
            opening["row_variables"],
            FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES
        );
        assert_eq!(opening["sumcheck_degree"], 2);
        assert_eq!(
            strings(&opening["sequence"]),
            [
                "observe domain",
                "observe fixed commitment",
                "observe dynamic commitment",
                "observe claim count",
                "observe each claim tag, column point, row point, value",
                "sample reverse-power RLC lambda",
                "verify opening sumcheck",
                "verify BaseFold evaluation claims",
            ]
        );

        let basefold = &manifest["basefold"];
        assert_eq!(
            basefold["source_revision"],
            FORGEMATRIX_V4_BASEFOLD_SOURCE_REVISION
        );
        assert_eq!(basefold["fixed_columns"], FORGEMATRIX_V4_FIXED_COLUMNS);
        assert_eq!(basefold["dynamic_columns"], FORGEMATRIX_V4_DYNAMIC_COLUMNS);
        assert_eq!(basefold["batching_variables"], 9);
        assert_eq!(
            basefold["fri_rounds"],
            FORGEMATRIX_V4_BASEFOLD_ROW_VARIABLES
        );
        assert_eq!(basefold["log_blowup"], FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP);
        assert_eq!(basefold["queries"], FORGEMATRIX_V4_BASEFOLD_QUERIES);
        assert_eq!(basefold["pow_bits"], FORGEMATRIX_V4_BASEFOLD_POW_BITS);
        assert_eq!(basefold["batch_grinding_bits"], 5);
        assert_eq!(
            strings(&basefold["sequence"]),
            [
                "observe batch-grinding witness and sample 5 zero bits",
                "sample 9-element polynomial-batching point",
                "reverse 23-element evaluation point",
                "observe FRI round count 23",
                "for each round: observe two-element univariate message, observe FRI commitment, sample beta",
                "observe final polynomial",
                "observe proof-of-work witness and sample 16 zero bits",
                "sample 270 query indices of 24 bits",
                "verify component Merkle openings, FRI query openings, folds, and final consistency",
            ]
        );

        let extension_bytes = FORGEMATRIX_V4_EXTENSION_DEGREE as usize * 4;
        let relation_bytes = sumcheck_bytes(
            FORGEMATRIX_V4_MATRIX_SUMCHECK_VARIABLES,
            FORGEMATRIX_V4_MATRIX_SUMCHECK_DEGREE,
        ) + 3 * extension_bytes
            + sumcheck_bytes(
                FORGEMATRIX_V4_SHIFT_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_SHIFT_SUMCHECK_DEGREE,
            )
            + 2 * extension_bytes
            + sumcheck_bytes(
                FORGEMATRIX_V4_CUBIC_SUMCHECK_VARIABLES,
                FORGEMATRIX_V4_CUBIC_SUMCHECK_DEGREE,
            )
            + 2 * extension_bytes;
        let bank_bytes = 32
            + FORGEMATRIX_V4_RELATION_REPETITIONS as usize * relation_bytes
            + FORGEMATRIX_V4_OPENING_REDUCTION_MAX_BYTES;
        let first_bank = 16 + FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES;
        let wire = &manifest["wire"];
        assert_eq!(wire["outer_magic"], "CMV4PF01");
        assert_eq!(wire["outer_version"], 1);
        assert_eq!(wire["banks"], PRODUCTION_V2_BANKS);
        assert_eq!(wire["opening_magic"], "CMV4BF01");
        assert_eq!(wire["opening_version"], 1);
        assert_eq!(
            wire["transparent_proof_bytes"],
            FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES
        );
        assert_eq!(
            wire["final_activation_bytes"],
            FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES
        );
        assert_eq!(wire["relation_repetition_bytes"], relation_bytes);
        assert_eq!(wire["bank_bytes"], bank_bytes);
        assert_eq!(
            wire["opening_bytes"],
            FORGEMATRIX_V4_OPENING_REDUCTION_MAX_BYTES
        );
        assert_eq!(
            wire["bank_offsets"],
            serde_json::json!([
                first_bank,
                first_bank + bank_bytes,
                first_bank + 2 * bank_bytes
            ])
        );
        assert_eq!(
            wire["opening_offsets"],
            serde_json::json!([
                first_bank + 32 + 2 * relation_bytes,
                first_bank + bank_bytes + 32 + 2 * relation_bytes,
                first_bank + 2 * bank_bytes + 32 + 2 * relation_bytes,
            ])
        );
    }

    #[cfg(feature = "forgematrix-v4-verifier")]
    #[test]
    fn production_v4_core_vector_is_canonical() {
        use slop_algebra::AbstractField;

        use crate::{
            MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES, PRODUCTION_V4_MAX_BLOCK_BYTES,
            PRODUCTION_V4_MAX_PROOF_BYTES, PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            PRODUCTION_V4_TESTNET_NETWORK_ID,
            forgematrix_v4_basefold::{ForgeMatrixV4Field, ForgeMatrixV4TranscriptStatement},
            forgematrix_v4_proof::forgematrix_v4_final_activation_digest,
            forgematrix_v4_proof_codec::FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
        };

        fn hex32(value: &serde_json::Value) -> [u8; 32] {
            hex::decode(value.as_str().expect("vector field is a string"))
                .expect("vector field is valid hex")
                .try_into()
                .expect("vector digest has 32 bytes")
        }

        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/consensus/production-v4-core-vector-v1.json"
        ))
        .unwrap();
        assert_eq!(
            vector["schema"],
            "CommonFoundry/ForgeMatrix/V4/CoreCanonicalVector/v1"
        );
        assert_eq!(
            vector["algorithm_version"],
            FORGEMATRIX_V4_ALGORITHM_VERSION
        );
        assert_eq!(vector["proof_version"], FORGEMATRIX_V4_PROOF_VERSION);
        let proof_system_digest = forgematrix_v4_proof_system_digest();
        assert_eq!(hex32(&vector["proof_system_digest"]), proof_system_digest);
        assert_eq!(
            hex32(&vector["model_manifest_digest"]),
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST
        );
        assert_eq!(
            hex32(&vector["fixed_artifact_record_digest"]),
            PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST
        );

        let block_vector = &vector["block"];
        let block = BlockChallenge {
            network_id: hex32(&block_vector["network_id"]),
            previous_block: hex32(&block_vector["previous_block"]),
            transaction_root: hex32(&block_vector["transaction_root"]),
            height: block_vector["height"].as_u64().unwrap(),
            timestamp: block_vector["timestamp"].as_u64().unwrap(),
            target: hex32(&block_vector["target"]),
        };
        assert_eq!(block.network_id, PRODUCTION_V4_TESTNET_NETWORK_ID);
        let nonce = vector["nonce"].as_u64().unwrap();
        let challenge_digest =
            forgematrix_v4_challenge_digest(&block, nonce, PRODUCTION_V4_MODEL_MANIFEST_DIGEST);
        let expected = &vector["expected"];
        assert_eq!(challenge_digest, hex32(&expected["challenge_digest"]));
        let activation_vector = &vector["final_activation"];
        let field_count = activation_vector["field_count"].as_u64().unwrap() as usize;
        assert_eq!(
            field_count,
            FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES / 4
        );
        assert_eq!(
            activation_vector["encoding"],
            "524288 canonical KoalaBear u32 little-endian values, all zero"
        );
        assert_eq!(activation_vector["fill_value"], 0);
        let final_activation = vec![ForgeMatrixV4Field::zero(); field_count];
        let final_activation_digest =
            forgematrix_v4_final_activation_digest(challenge_digest, &final_activation);
        assert_eq!(
            final_activation_digest,
            hex32(&expected["final_activation_digest"])
        );
        let work_digest = forgematrix_v4_work_digest(
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            challenge_digest,
            final_activation_digest,
        );
        assert_eq!(work_digest, hex32(&expected["work_digest"]));
        let transcript_statement_digest = ForgeMatrixV4TranscriptStatement {
            block,
            algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V4_PROOF_VERSION,
            nonce,
            proof_system_digest,
            model_manifest_digest: PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            challenge_digest,
            final_activation_digest,
            work_digest,
        }
        .digest();
        assert_eq!(
            transcript_statement_digest,
            hex32(&expected["transcript_statement_digest"])
        );

        let wire = &vector["wire"];
        assert_eq!(
            wire["transparent_proof_exact_bytes"],
            FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES
        );
        assert_eq!(
            wire["transparent_proof_max_bytes"],
            MAX_FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES
        );
        assert_eq!(wire["proof_frame_max_bytes"], PRODUCTION_V4_MAX_PROOF_BYTES);
        assert_eq!(wire["block_frame_max_bytes"], PRODUCTION_V4_MAX_BLOCK_BYTES);

        let rejections = vector["rejections"].as_array().unwrap();
        assert_eq!(rejections.len(), 5);
        assert_eq!(rejections[0][2], FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES - 1);
        assert_eq!(rejections[1][2], FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES + 1);
        assert_eq!(rejections[2][2], FORGEMATRIX_V4_FIELD_MODULUS);
        assert_eq!(rejections[3][2], PRODUCTION_V4_MAX_PROOF_BYTES + 1);
        assert_eq!(rejections[4][2], PRODUCTION_V4_MAX_BLOCK_BYTES + 1);
    }

    #[test]
    fn challenge_and_work_bind_every_public_input() {
        let block = BlockChallenge {
            network_id: [1; 32],
            previous_block: [2; 32],
            transaction_root: [3; 32],
            height: 4,
            timestamp: 5,
            target: [6; 32],
        };
        let challenge = forgematrix_v4_challenge_digest(&block, 7, [8; 32]);
        let work = forgematrix_v4_work_digest([8; 32], challenge, [9; 32]);

        let mut changed = block;
        changed.target[0] ^= 1;
        assert_ne!(
            forgematrix_v4_challenge_digest(&changed, 7, [8; 32]),
            challenge
        );
        assert_ne!(
            forgematrix_v4_challenge_digest(&block, 8, [8; 32]),
            challenge
        );
        assert_ne!(
            forgematrix_v4_challenge_digest(&block, 7, [9; 32]),
            challenge
        );
        assert_ne!(
            forgematrix_v4_work_digest([8; 32], challenge, [10; 32]),
            work
        );
    }
}
