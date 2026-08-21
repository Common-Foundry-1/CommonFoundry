//! Additive production-geometry WHIR candidate.
//!
//! This module defines and measures the exact n19/n31 role geometry and a
//! versioned n33 batched-model proposal without widening the legacy V2 adapter.
//! It also derives production work from verifier-visible commitments so the
//! final table need not be re-hashed inside a separate BLAKE3 STARK. It is
//! deliberately not a block-proof type: even the batched model's
//! dictionary-free floor exceeds the whole-frame shared argument budget and
//! therefore fails closed before activation.

use blake3::Hasher as Blake3Hasher;
use p3_field::PrimeCharacteristicRing;
use thiserror::Error;

use super::{
    Challenger, EF, EXPLICIT_WHIR_FOLDING, EXPLICIT_WHIR_POW_BITS, EXPLICIT_WHIR_SECURITY_BITS,
    EXPLICIT_WHIR_STARTING_LOG_INV_RATE, F, build_whir_config_bounded, convert_extension,
    external_extension,
    native_codec::{self, NativeProofCodecError, NativeProofCodecProfile, NativeProofGeometry},
    structured_whir_suite_parameter_digest,
};
use crate::{
    BlockChallenge, ForgeMatrixV2Descriptor, MAX_MODEL_PCS_WEIGHT_BANKS, ModelPcsIdentity,
    ModelPcsRole, PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION,
    PRODUCTION_V2_LAYERS, PRODUCTION_V2_LAYERS_PER_BANK,
};

pub const PRODUCTION_WHIR_CANDIDATE_VERSION: u32 = 1;
pub const PRODUCTION_PROOF_BINDING_VERSION: u32 = 1;
pub const PRODUCTION_WHIR_BASE_VARIABLES: usize = 19;
pub const PRODUCTION_WHIR_WEIGHT_VARIABLES: usize = 31;
pub const PRODUCTION_BATCHED_MODEL_VARIABLES: usize = 33;
pub const PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES: usize = PRODUCTION_WHIR_WEIGHT_VARIABLES;
pub const PRODUCTION_BATCHED_MODEL_SLOTS: usize = 1 + PRODUCTION_V2_BANKS as usize;
pub const PRODUCTION_FINAL_ACTIVATION_ELEMENTS: usize =
    PRODUCTION_V2_BATCH as usize * PRODUCTION_V2_DIMENSION as usize;
pub const PRODUCTION_TRACE_INITIALIZATION_VARIABLES: usize = 19;
pub const PRODUCTION_TRACE_BANK_VARIABLES: usize = 26;
pub const PRODUCTION_TRACE_INITIALIZATION_COLUMNS: usize = crate::STRUCTURED_TRANSITION_ORACLES - 1;
pub const PRODUCTION_TRACE_BANK_COLUMNS: usize = crate::STRUCTURED_TRANSITION_ORACLES;
pub const PRODUCTION_TRACE_BANK_SECTION_COLUMNS: usize = 32;
pub const PRODUCTION_TRACE_SECTIONS_PER_BANK: usize = 4;
pub const PRODUCTION_TRACE_SECTION_COUNT: usize =
    1 + PRODUCTION_V2_BANKS as usize * PRODUCTION_TRACE_SECTIONS_PER_BANK;
pub const PRODUCTION_TRACE_SEMANTIC_COLUMNS: usize = PRODUCTION_TRACE_INITIALIZATION_COLUMNS
    + PRODUCTION_V2_BANKS as usize * PRODUCTION_TRACE_BANK_COLUMNS;
pub const PRODUCTION_TRACE_BATCH_LOCAL_VARIABLES: usize = PRODUCTION_TRACE_BANK_VARIABLES;
pub const PRODUCTION_TRACE_BATCH_SELECTOR_VARIABLES: usize = 9;
pub const PRODUCTION_TRACE_BATCH_PADDED_COLUMNS: usize =
    1 << PRODUCTION_TRACE_BATCH_SELECTOR_VARIABLES;
pub const PRODUCTION_TRACE_BATCH_PADDING_COLUMNS: usize =
    PRODUCTION_TRACE_BATCH_PADDED_COLUMNS - PRODUCTION_TRACE_SEMANTIC_COLUMNS;
pub const PRODUCTION_TRACE_TERMINAL_SECTION: usize =
    1 + (PRODUCTION_V2_BANKS as usize - 1) * PRODUCTION_TRACE_SECTIONS_PER_BANK;
pub const PRODUCTION_TRACE_TERMINAL_COLUMN: usize = crate::STRUCTURED_TRANSITION_ACTIVATION_ORACLE;
pub const PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES: usize =
    match crate::wire::MAX_PROOF_BYTES.checked_sub(crate::wire::WIRE_HEADER_BYTES) {
        Some(bytes) => bytes,
        None => panic!("proof frame is smaller than its wire header"),
    };
pub const PRODUCTION_BATCHED_WHIR_MODEL_BYTES: usize =
    crate::structured_proof::STRUCTURED_BATCHED_PRODUCTION_MODEL_NATIVE_BYTES;

pub(super) const PRODUCTION_WHIR_NATIVE_MAGIC: &[u8; 8] = b"CMFDPWB1";
pub(super) const PRODUCTION_WHIR_NATIVE_CODEC_VERSION: u32 = 1;
pub(super) const PRODUCTION_WHIR_NATIVE_PROTOCOL_VERSION: u32 = 1;
pub(super) const PRODUCTION_BATCHED_WHIR_NATIVE_MAGIC: &[u8; 8] = b"CMFDPBJ1";
pub(super) const PRODUCTION_BATCHED_WHIR_NATIVE_CODEC_VERSION: u32 = 1;
pub(super) const PRODUCTION_BATCHED_WHIR_NATIVE_PROTOCOL_VERSION: u32 = 1;

const PRODUCTION_MODEL_VERSION: u32 = 2;
const CANDIDATE_SUITE_DOMAIN: &str = "CMFD/FORGEMATRIX/WHIR-PRODUCTION-CANDIDATE/V1";
const PROOF_BINDING_SUITE_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-PROOF-SUITE/V1";
const BATCHED_MODEL_IDENTITY_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-BATCHED-MODEL/V1";
const PROOF_COMMITMENT_ROOT_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-PROOF-COMMITMENT/V1";
const TRACE_LAYOUT_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-TRACE-LAYOUT/V1";
const TRACE_PADDING_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-TRACE-PADDING/V1";
const TRACE_COLUMN_ALIAS_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-TRACE-COLUMN/V1";
const TRACE_COMMITMENT_ROOT_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-TRACE-ROOT/V1";
const COMMITMENT_WORK_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-COMMITMENT-WORK/V1";
const COMMITMENT_PUBLIC_BINDING_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-COMMITMENT-PUBLIC/V1";
const NATIVE_CODEC_DESCRIPTION: &[u8] =
    b"fixed-width-le-config-derived-shape-first-reference-merkle-dictionary-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionWhirRoleV1 {
    BaseInput,
    WeightBank { index: u8 },
}

impl ProductionWhirRoleV1 {
    const fn num_variables(self) -> usize {
        match self {
            Self::BaseInput => PRODUCTION_WHIR_BASE_VARIABLES,
            Self::WeightBank { .. } => PRODUCTION_WHIR_WEIGHT_VARIABLES,
        }
    }

    #[cfg(feature = "gpu-proof-prover")]
    const fn as_model_role(self) -> ModelPcsRole {
        match self {
            Self::BaseInput => ModelPcsRole::BaseInput,
            Self::WeightBank { index } => ModelPcsRole::WeightBank {
                index: index as u32,
            },
        }
    }
}

pub struct ProductionWhirConfigV1 {
    role: ProductionWhirRoleV1,
    model_digest: [u8; 32],
    expected_commitment: [u8; 32],
    suite_digest: [u8; 32],
    inner: p3_whir::parameters::WhirConfig<EF, F, Challenger>,
}

pub struct ProductionBatchedModelWhirConfigV1 {
    trusted_model_digest: [u8; 32],
    expected_commitment: [u8; 32],
    suite_digest: [u8; 32],
    inner: p3_whir::parameters::WhirConfig<EF, F, Challenger>,
}

impl std::fmt::Debug for ProductionBatchedModelWhirConfigV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionBatchedModelWhirConfigV1")
            .field("trusted_model_digest", &self.trusted_model_digest)
            .field("expected_commitment", &self.expected_commitment)
            .field("suite_digest", &self.suite_digest)
            .field("num_variables", &self.inner.num_variables)
            .finish()
    }
}

impl std::fmt::Debug for ProductionWhirConfigV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionWhirConfigV1")
            .field("role", &self.role)
            .field("model_digest", &self.model_digest)
            .field("expected_commitment", &self.expected_commitment)
            .field("suite_digest", &self.suite_digest)
            .field("num_variables", &self.inner.num_variables)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionWhirWireShapeV1 {
    pub intermediate_rounds: usize,
    pub path_depths: Vec<usize>,
    pub body_bytes: usize,
    pub reference_count: usize,
    pub maximum_dictionary_nodes: usize,
    pub dictionary_free_floor_bytes: usize,
    pub maximum_native_bytes: usize,
    pub available_native_bytes: usize,
    pub conservative_payload_fit: bool,
}

/// Exact byte floors for the two straightforward production-trace PCS layouts.
///
/// Neither layout is an activation candidate. Independent section proofs pay
/// thirteen complete WHIR transports. A single 512-slot selector polynomial
/// stays algebraically sound, but selector-first opening exposes every slot;
/// the ordinary local-first schedule exposes four values per slot. This budget
/// pins both failures before a prover allocates production-sized buffers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionTraceBatchWireBudgetV1 {
    pub selector_variables: usize,
    pub semantic_columns: usize,
    pub padded_columns: usize,
    pub canonical_zero_columns: usize,
    pub local_variables: usize,
    pub stacked_variables: usize,
    pub first_round_queries: usize,
    pub local_fold_width: usize,
    pub selector_first_semantic_values_per_query: usize,
    pub selector_first_padded_values_per_query: usize,
    pub selector_first_semantic_value_bytes: usize,
    pub selector_first_padded_value_bytes: usize,
    pub local_first_semantic_values_per_query: usize,
    pub local_first_padded_values_per_query: usize,
    pub local_first_semantic_value_bytes: usize,
    pub local_first_padded_value_bytes: usize,
    pub independent_section_floor_bytes: usize,
    pub available_native_bytes: usize,
}

impl ProductionTraceBatchWireBudgetV1 {
    /// A direct wide-row opening fails even if canonical padding is omitted
    /// and all Merkle paths, roots, headers, and sumcheck messages are free.
    pub const fn direct_wide_row_cannot_fit(&self) -> bool {
        self.selector_first_semantic_value_bytes > self.available_native_bytes
    }

    /// Thirteen ordinary child proofs fail before their Merkle dictionaries
    /// or aggregate framing are added.
    pub const fn independent_sections_cannot_fit(&self) -> bool {
        self.independent_section_floor_bytes > self.available_native_bytes
    }
}

/// Trusted identity for one batched commitment to the ordered base-input and
/// three weight-bank polynomials.
///
/// The joint commitment must come from the model ceremony, not from a block or
/// miner. This descriptor binds it to the existing byte-authenticated model,
/// ordered role commitments, exact production geometry, and proof suite. It
/// does not itself prove that the ceremony formed the joint polynomial
/// correctly; that ceremony receipt remains a production activation gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionBatchedModelIdentityV1 {
    model_identity_digest: [u8; 32],
    model_byte_root: [u8; 32],
    source_pcs_suite_digest: [u8; 32],
    ordered_role_commitment_root: [u8; 32],
    joint_fixed_model_commitment: [u8; 32],
    proof_suite_digest: [u8; 32],
}

/// One exact physical PCS section in the production trace layout.
///
/// Columns remain semantically ordered even when two columns contain equal
/// values. Each section is independently padded with Goldilocks zeroes to the
/// stated stacked arity; data-dependent sorting or deduplication is forbidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionTraceSectionV1 {
    pub section_index: u32,
    pub semantic_column_start: u32,
    pub column_count: u32,
    pub column_variables: u32,
    pub stacked_variables: u32,
}

/// Canonical address of one semantic transition oracle in the physical trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionTraceColumnV1 {
    pub semantic_column: u32,
    pub section_index: u32,
    pub section_column: u32,
    pub column_variables: u32,
}

const fn production_trace_section_v1(index: usize) -> ProductionTraceSectionV1 {
    if index == 0 {
        return ProductionTraceSectionV1 {
            section_index: 0,
            semantic_column_start: 0,
            column_count: PRODUCTION_TRACE_INITIALIZATION_COLUMNS as u32,
            column_variables: PRODUCTION_TRACE_INITIALIZATION_VARIABLES as u32,
            stacked_variables: 26,
        };
    }
    let bank_section = index - 1;
    let bank = bank_section / PRODUCTION_TRACE_SECTIONS_PER_BANK;
    let chunk = bank_section % PRODUCTION_TRACE_SECTIONS_PER_BANK;
    let bank_column_start = chunk * PRODUCTION_TRACE_BANK_SECTION_COLUMNS;
    let remaining = PRODUCTION_TRACE_BANK_COLUMNS - bank_column_start;
    let column_count = if remaining < PRODUCTION_TRACE_BANK_SECTION_COLUMNS {
        remaining
    } else {
        PRODUCTION_TRACE_BANK_SECTION_COLUMNS
    };
    ProductionTraceSectionV1 {
        section_index: index as u32,
        semantic_column_start: (PRODUCTION_TRACE_INITIALIZATION_COLUMNS
            + bank * PRODUCTION_TRACE_BANK_COLUMNS
            + bank_column_start) as u32,
        column_count: column_count as u32,
        column_variables: PRODUCTION_TRACE_BANK_VARIABLES as u32,
        stacked_variables: if column_count == PRODUCTION_TRACE_BANK_SECTION_COLUMNS {
            31
        } else {
            30
        },
    }
}

pub const fn production_trace_sections_v1()
-> [ProductionTraceSectionV1; PRODUCTION_TRACE_SECTION_COUNT] {
    let mut sections = [production_trace_section_v1(0); PRODUCTION_TRACE_SECTION_COUNT];
    let mut index = 1;
    while index < PRODUCTION_TRACE_SECTION_COUNT {
        sections[index] = production_trace_section_v1(index);
        index += 1;
    }
    sections
}

pub fn production_trace_batch_wire_budget_v1()
-> Result<ProductionTraceBatchWireBudgetV1, ProductionWhirCandidateError> {
    let mut independent_section_floor_bytes = 0_usize;
    for section in production_trace_sections_v1() {
        let variables = section.stacked_variables as usize;
        let config = build_whir_config_bounded(variables, PRODUCTION_WHIR_WEIGHT_VARIABLES)
            .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        let geometry =
            native_codec::proof_geometry_with_profile(&config, candidate_codec_profile(usize::MAX))
                .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        independent_section_floor_bytes = independent_section_floor_bytes
            .checked_add(geometry.structural_floor_bytes)
            .ok_or(ProductionWhirCandidateError::Configuration)?;
    }

    let local_config = build_whir_config_bounded(
        PRODUCTION_TRACE_BATCH_LOCAL_VARIABLES,
        PRODUCTION_WHIR_WEIGHT_VARIABLES,
    )
    .map_err(|_| ProductionWhirCandidateError::Configuration)?;
    let first_round_queries = local_config
        .round_parameters
        .first()
        .ok_or(ProductionWhirCandidateError::Configuration)?
        .num_queries;
    let local_fold_width = 1_usize
        .checked_shl(EXPLICIT_WHIR_FOLDING as u32)
        .ok_or(ProductionWhirCandidateError::Configuration)?;
    let selector_first_semantic_values_per_query = PRODUCTION_TRACE_SEMANTIC_COLUMNS;
    let selector_first_padded_values_per_query = PRODUCTION_TRACE_BATCH_PADDED_COLUMNS;
    let selector_first_semantic_value_bytes = selector_first_semantic_values_per_query
        .checked_mul(first_round_queries)
        .and_then(|elements| elements.checked_mul(std::mem::size_of::<u64>()))
        .ok_or(ProductionWhirCandidateError::Configuration)?;
    let selector_first_padded_value_bytes = selector_first_padded_values_per_query
        .checked_mul(first_round_queries)
        .and_then(|elements| elements.checked_mul(std::mem::size_of::<u64>()))
        .ok_or(ProductionWhirCandidateError::Configuration)?;
    let local_first_semantic_values_per_query = PRODUCTION_TRACE_SEMANTIC_COLUMNS
        .checked_mul(local_fold_width)
        .ok_or(ProductionWhirCandidateError::Configuration)?;
    let local_first_padded_values_per_query = PRODUCTION_TRACE_BATCH_PADDED_COLUMNS
        .checked_mul(local_fold_width)
        .ok_or(ProductionWhirCandidateError::Configuration)?;
    let local_first_semantic_value_bytes = local_first_semantic_values_per_query
        .checked_mul(first_round_queries)
        .and_then(|elements| elements.checked_mul(std::mem::size_of::<u64>()))
        .ok_or(ProductionWhirCandidateError::Configuration)?;
    let local_first_padded_value_bytes = local_first_padded_values_per_query
        .checked_mul(first_round_queries)
        .and_then(|elements| elements.checked_mul(std::mem::size_of::<u64>()))
        .ok_or(ProductionWhirCandidateError::Configuration)?;

    Ok(ProductionTraceBatchWireBudgetV1 {
        selector_variables: PRODUCTION_TRACE_BATCH_SELECTOR_VARIABLES,
        semantic_columns: PRODUCTION_TRACE_SEMANTIC_COLUMNS,
        padded_columns: PRODUCTION_TRACE_BATCH_PADDED_COLUMNS,
        canonical_zero_columns: PRODUCTION_TRACE_BATCH_PADDING_COLUMNS,
        local_variables: PRODUCTION_TRACE_BATCH_LOCAL_VARIABLES,
        stacked_variables: PRODUCTION_TRACE_BATCH_LOCAL_VARIABLES
            + PRODUCTION_TRACE_BATCH_SELECTOR_VARIABLES,
        first_round_queries,
        local_fold_width,
        selector_first_semantic_values_per_query,
        selector_first_padded_values_per_query,
        selector_first_semantic_value_bytes,
        selector_first_padded_value_bytes,
        local_first_semantic_values_per_query,
        local_first_padded_values_per_query,
        local_first_semantic_value_bytes,
        local_first_padded_value_bytes,
        independent_section_floor_bytes,
        available_native_bytes: PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES,
    })
}

/// Fold one unified production-trace row at a selector point.
///
/// Semantic columns occupy slots `0..439`; slots `439..512` are canonical
/// zeroes. Initialization columns are also zero above their `2^19` local
/// domain. The prefix-order fold is the exact multilinear evaluation of that
/// 512-slot row and is shared by the future prover and verifier bridge.
pub fn production_trace_fold_row_v1(
    local_row: u64,
    semantic_values: &[crate::ExtensionElement],
    selector_point: &[crate::ExtensionElement],
) -> Result<crate::ExtensionElement, ProductionWhirCandidateError> {
    if local_row >= (1_u64 << PRODUCTION_TRACE_BATCH_LOCAL_VARIABLES)
        || semantic_values.len() != PRODUCTION_TRACE_SEMANTIC_COLUMNS
    {
        return Err(ProductionWhirCandidateError::InvalidTraceRow);
    }
    if selector_point.len() != PRODUCTION_TRACE_BATCH_SELECTOR_VARIABLES {
        return Err(ProductionWhirCandidateError::InvalidOpeningPoint);
    }
    if local_row >= (1_u64 << PRODUCTION_TRACE_INITIALIZATION_VARIABLES)
        && semantic_values[..PRODUCTION_TRACE_INITIALIZATION_COLUMNS]
            .iter()
            .any(|value| value.limbs != [0; 3])
    {
        return Err(ProductionWhirCandidateError::InvalidTraceRow);
    }

    let mut active = semantic_values
        .iter()
        .copied()
        .map(|value| {
            convert_extension(value).map_err(|_| ProductionWhirCandidateError::InvalidEncoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    active.resize(PRODUCTION_TRACE_BATCH_PADDED_COLUMNS, EF::ZERO);
    for challenge in selector_point.iter().copied() {
        let challenge = convert_extension(challenge)
            .map_err(|_| ProductionWhirCandidateError::InvalidEncoding)?;
        let half = active.len() / 2;
        {
            let (zero, one) = active.split_at_mut(half);
            for (zero, &one) in zero.iter_mut().zip(one.iter()) {
                *zero += (one - *zero) * challenge;
            }
        }
        active.truncate(half);
    }
    debug_assert_eq!(active.len(), 1);
    Ok(external_extension(active[0]))
}

pub fn production_trace_initialization_column_v1(
    oracle: usize,
) -> Result<ProductionTraceColumnV1, ProductionWhirCandidateError> {
    if oracle == crate::STRUCTURED_TRANSITION_INPUT_ORACLE
        || oracle >= crate::STRUCTURED_TRANSITION_ORACLES
    {
        return Err(ProductionWhirCandidateError::InvalidTraceColumn);
    }
    Ok(ProductionTraceColumnV1 {
        semantic_column: (oracle - 1) as u32,
        section_index: 0,
        section_column: (oracle - 1) as u32,
        column_variables: PRODUCTION_TRACE_INITIALIZATION_VARIABLES as u32,
    })
}

pub fn production_trace_bank_column_v1(
    bank: usize,
    oracle: usize,
) -> Result<ProductionTraceColumnV1, ProductionWhirCandidateError> {
    if bank >= PRODUCTION_V2_BANKS as usize || oracle >= PRODUCTION_TRACE_BANK_COLUMNS {
        return Err(ProductionWhirCandidateError::InvalidTraceColumn);
    }
    let chunk = oracle / PRODUCTION_TRACE_BANK_SECTION_COLUMNS;
    let section_index = 1 + bank * PRODUCTION_TRACE_SECTIONS_PER_BANK + chunk;
    Ok(ProductionTraceColumnV1 {
        semantic_column: (PRODUCTION_TRACE_INITIALIZATION_COLUMNS
            + bank * PRODUCTION_TRACE_BANK_COLUMNS
            + oracle) as u32,
        section_index: section_index as u32,
        section_column: (oracle % PRODUCTION_TRACE_BANK_SECTION_COLUMNS) as u32,
        column_variables: PRODUCTION_TRACE_BANK_VARIABLES as u32,
    })
}

pub fn production_trace_terminal_column_v1() -> ProductionTraceColumnV1 {
    production_trace_bank_column_v1(
        PRODUCTION_V2_BANKS as usize - 1,
        crate::STRUCTURED_TRANSITION_ACTIVATION_ORACLE,
    )
    .expect("the pinned production terminal oracle is in range")
}

pub fn production_trace_layout_digest_v1() -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(TRACE_LAYOUT_DOMAIN);
    hasher.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
    hasher.update(&(PRODUCTION_TRACE_SEMANTIC_COLUMNS as u32).to_le_bytes());
    hasher.update(&(PRODUCTION_TRACE_SECTION_COUNT as u32).to_le_bytes());
    hasher.update(&(crate::STRUCTURED_TRANSITION_ORACLES as u32).to_le_bytes());
    hasher.update(&(crate::STRUCTURED_TRANSITION_INPUT_ORACLE as u32).to_le_bytes());
    hasher.update(&(crate::STRUCTURED_TRANSITION_ACTIVATION_ORACLE as u32).to_le_bytes());
    for section in production_trace_sections_v1() {
        hasher.update(&section.section_index.to_le_bytes());
        hasher.update(&section.semantic_column_start.to_le_bytes());
        hasher.update(&section.column_count.to_le_bytes());
        hasher.update(&section.column_variables.to_le_bytes());
        hasher.update(&section.stacked_variables.to_le_bytes());
    }
    let terminal = production_trace_terminal_column_v1();
    hasher.update(&terminal.semantic_column.to_le_bytes());
    hasher.update(&terminal.section_index.to_le_bytes());
    hasher.update(&terminal.section_column.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub fn production_trace_padding_digest_v1() -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(TRACE_PADDING_DOMAIN);
    hasher.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
    hasher.update(&production_trace_layout_digest_v1());
    for section in production_trace_sections_v1() {
        let column_elements = 1_u64 << section.column_variables;
        let populated = u64::from(section.column_count) * column_elements;
        let committed = 1_u64 << section.stacked_variables;
        hasher.update(&section.section_index.to_le_bytes());
        hasher.update(&populated.to_le_bytes());
        hasher.update(&committed.to_le_bytes());
        hasher.update(&(committed - populated).to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub fn production_trace_column_alias_v1(
    section_root: [u8; 32],
    column: ProductionTraceColumnV1,
) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(TRACE_COLUMN_ALIAS_DOMAIN);
    hasher.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
    hasher.update(&production_trace_layout_digest_v1());
    hasher.update(&section_root);
    hasher.update(&column.semantic_column.to_le_bytes());
    hasher.update(&column.section_index.to_le_bytes());
    hasher.update(&column.section_column.to_le_bytes());
    hasher.update(&column.column_variables.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub fn production_trace_commitment_root_v1(
    section_roots: &[[u8; 32]; PRODUCTION_TRACE_SECTION_COUNT],
) -> Result<[u8; 32], ProductionWhirCandidateError> {
    if section_roots.contains(&[0; 32]) {
        return Err(ProductionWhirCandidateError::UncommittedTrace);
    }
    let mut hasher = Blake3Hasher::new_derive_key(TRACE_COMMITMENT_ROOT_DOMAIN);
    hasher.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
    hasher.update(&production_trace_layout_digest_v1());
    hasher.update(&production_trace_padding_digest_v1());
    hasher.update(&(PRODUCTION_TRACE_SECTION_COUNT as u32).to_le_bytes());
    for (index, root) in section_roots.iter().enumerate() {
        hasher.update(&(index as u32).to_le_bytes());
        hasher.update(root);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub fn production_trace_column_commitments_v1(
    section_roots: &[[u8; 32]; PRODUCTION_TRACE_SECTION_COUNT],
) -> Result<Vec<[u8; 32]>, ProductionWhirCandidateError> {
    production_trace_commitment_root_v1(section_roots)?;
    let mut commitments = Vec::with_capacity(PRODUCTION_TRACE_SEMANTIC_COLUMNS);
    for oracle in 1..crate::STRUCTURED_TRANSITION_ORACLES {
        let column = production_trace_initialization_column_v1(oracle)?;
        commitments.push(production_trace_column_alias_v1(
            section_roots[column.section_index as usize],
            column,
        ));
    }
    for bank in 0..PRODUCTION_V2_BANKS as usize {
        for oracle in 0..crate::STRUCTURED_TRANSITION_ORACLES {
            let column = production_trace_bank_column_v1(bank, oracle)?;
            commitments.push(production_trace_column_alias_v1(
                section_roots[column.section_index as usize],
                column,
            ));
        }
    }
    debug_assert_eq!(commitments.len(), PRODUCTION_TRACE_SEMANTIC_COLUMNS);
    Ok(commitments)
}

impl ProductionBatchedModelIdentityV1 {
    /// Research-only constructor. Activation must replace this with a verified
    /// model-ceremony receipt that proves the joint source layout.
    #[allow(dead_code)]
    pub(crate) fn from_unverified_ceremony_root(
        model: &ModelPcsIdentity,
        joint_fixed_model_commitment: [u8; 32],
    ) -> Result<Self, ProductionWhirCandidateError> {
        validate_production_model(model)?;
        if joint_fixed_model_commitment == [0; 32] {
            return Err(ProductionWhirCandidateError::UncommittedBatchedModel);
        }
        Ok(Self {
            model_identity_digest: model
                .digest()
                .map_err(|_| ProductionWhirCandidateError::InvalidModel)?,
            model_byte_root: model.model_byte_root,
            source_pcs_suite_digest: model.pcs_suite_parameter_digest,
            ordered_role_commitment_root: model
                .commitment_root()
                .map_err(|_| ProductionWhirCandidateError::InvalidModel)?,
            joint_fixed_model_commitment,
            proof_suite_digest: production_proof_binding_suite_digest_v1(),
        })
    }

    pub const fn joint_fixed_model_commitment(&self) -> [u8; 32] {
        self.joint_fixed_model_commitment
    }

    pub const fn proof_suite_digest(&self) -> [u8; 32] {
        self.proof_suite_digest
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Blake3Hasher::new_derive_key(BATCHED_MODEL_IDENTITY_DOMAIN);
        hasher.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
        hasher.update(&self.proof_suite_digest);
        hasher.update(&self.model_identity_digest);
        hasher.update(&self.model_byte_root);
        hasher.update(&self.source_pcs_suite_digest);
        hasher.update(&self.ordered_role_commitment_root);
        hasher.update(&self.joint_fixed_model_commitment);
        *hasher.finalize().as_bytes()
    }
}

/// Opaque evidence that the production algebraic and PCS verifier accepted one
/// exact semantic trace layout and its terminal output alias.
///
/// There is intentionally no callable production constructor yet. The future
/// integrated verifier must validate the fixed table order, variables,
/// canonical padding, terminal-table identity, and every opening before it can
/// mint this capability. This keeps raw miner-supplied roots out of the work
/// binding API while that verifier bridge remains an activation gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedProductionTraceV1 {
    trusted_model_digest: [u8; 32],
    challenge_digest: [u8; 32],
    trace_commitment_root: [u8; 32],
    trace_layout_digest: [u8; 32],
    canonical_padding_digest: [u8; 32],
    trace_section_count: u32,
    terminal_section_index: u32,
    terminal_column_index: u32,
    final_output_commitment: [u8; 32],
}

impl VerifiedProductionTraceV1 {
    #[allow(dead_code)]
    pub(super) fn from_verified_sections(
        trusted_model_digest: [u8; 32],
        challenge_digest: [u8; 32],
        section_roots: [[u8; 32]; PRODUCTION_TRACE_SECTION_COUNT],
        semantic_commitments: &[[u8; 32]],
    ) -> Result<Self, ProductionWhirCandidateError> {
        let trace_commitment_root = production_trace_commitment_root_v1(&section_roots)?;
        if production_trace_column_commitments_v1(&section_roots)? != semantic_commitments {
            return Err(ProductionWhirCandidateError::TraceCommitmentMismatch);
        }
        let trace_layout_digest = production_trace_layout_digest_v1();
        let canonical_padding_digest = production_trace_padding_digest_v1();
        let terminal = production_trace_terminal_column_v1();
        let final_output_commitment = production_trace_column_alias_v1(
            section_roots[terminal.section_index as usize],
            terminal,
        );
        Ok(Self {
            trusted_model_digest,
            challenge_digest,
            trace_commitment_root,
            trace_layout_digest,
            canonical_padding_digest,
            trace_section_count: PRODUCTION_TRACE_SECTION_COUNT as u32,
            terminal_section_index: terminal.section_index,
            terminal_column_index: terminal.section_column,
            final_output_commitment,
        })
    }
}

/// Verifier-derived commitment to every proof-specific polynomial root needed
/// by the production candidate. This value is never trusted from the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionProofCommitmentRootV1([u8; 32]);

impl ProductionProofCommitmentRootV1 {
    #[allow(dead_code)]
    pub(crate) fn derive(
        trusted_model: &ProductionBatchedModelIdentityV1,
        verified_trace: &VerifiedProductionTraceV1,
    ) -> Result<Self, ProductionWhirCandidateError> {
        if verified_trace.trusted_model_digest != trusted_model.digest() {
            return Err(ProductionWhirCandidateError::VerifiedTraceContextMismatch);
        }
        let mut hasher = Blake3Hasher::new_derive_key(PROOF_COMMITMENT_ROOT_DOMAIN);
        hasher.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
        hasher.update(&trusted_model.proof_suite_digest());
        hasher.update(&trusted_model.digest());
        hasher.update(&verified_trace.challenge_digest);
        hasher.update(&verified_trace.trace_layout_digest);
        hasher.update(&verified_trace.trace_section_count.to_le_bytes());
        hasher.update(&verified_trace.terminal_section_index.to_le_bytes());
        hasher.update(&verified_trace.terminal_column_index.to_le_bytes());
        hasher.update(&verified_trace.canonical_padding_digest);
        hasher.update(&verified_trace.trace_commitment_root);
        hasher.update(&verified_trace.final_output_commitment);
        hasher.update(&(PRODUCTION_FINAL_ACTIVATION_ELEMENTS as u64).to_le_bytes());
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Untrusted commitment-derived claims carried by a future production proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionCommitmentClaimsV1 {
    pub proof_commitment_root: [u8; 32],
    pub work_digest: [u8; 32],
    pub public_binding: [u8; 32],
}

/// Canonical nonce challenge and target recomputed from caller-owned block
/// data instead of accepted as two independent proof fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionCommitmentChallengeV1 {
    challenge_digest: [u8; 32],
    work_target: [u8; 32],
}

impl ProductionCommitmentChallengeV1 {
    #[allow(dead_code)]
    pub(crate) fn from_block(
        descriptor: &ForgeMatrixV2Descriptor,
        trusted_model: &ProductionBatchedModelIdentityV1,
        block: &BlockChallenge,
        nonce: u64,
    ) -> Result<Self, ProductionWhirCandidateError> {
        let production_descriptor_matches = descriptor.network_id != [0; 32]
            && descriptor.algorithm_version == crate::FORGEMATRIX_V2_ALGORITHM_VERSION
            && descriptor.proof_version == crate::FORGEMATRIX_V2_PROOF_VERSION
            && descriptor.banks == PRODUCTION_V2_BANKS
            && descriptor.layers_per_bank == PRODUCTION_V2_LAYERS_PER_BANK
            && descriptor.model.model_version == PRODUCTION_MODEL_VERSION
            && descriptor.model.batch == PRODUCTION_V2_BATCH
            && descriptor.model.dimension == PRODUCTION_V2_DIMENSION
            && descriptor.model.layers == PRODUCTION_V2_LAYERS
            && descriptor.model.raw_blake3_root == trusted_model.model_byte_root
            && descriptor.model.pcs_parameter_digest == trusted_model.source_pcs_suite_digest
            && descriptor.model.pcs_commitment_root == trusted_model.ordered_role_commitment_root
            && descriptor.model.digest().is_ok();
        if !production_descriptor_matches {
            return Err(ProductionWhirCandidateError::InvalidProductionDescriptor);
        }
        Ok(Self {
            challenge_digest: crate::forgematrix_v2::challenge_digest(descriptor, block, nonce)
                .map_err(|_| ProductionWhirCandidateError::InvalidChallenge)?,
            work_target: block.target,
        })
    }

    #[cfg(test)]
    const fn from_test_parts(challenge_digest: [u8; 32], work_target: [u8; 32]) -> Self {
        Self {
            challenge_digest,
            work_target,
        }
    }

    pub const fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    pub const fn work_target(&self) -> [u8; 32] {
        self.work_target
    }
}

/// Work and Fiat-Shamir bindings derived from authenticated commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionCommitmentWorkBindingV1 {
    proof_commitment_root: ProductionProofCommitmentRootV1,
    work_digest: [u8; 32],
    public_binding: [u8; 32],
}

impl ProductionCommitmentWorkBindingV1 {
    #[allow(dead_code)]
    pub(crate) fn derive(
        challenge: ProductionCommitmentChallengeV1,
        trusted_model: &ProductionBatchedModelIdentityV1,
        verified_trace: &VerifiedProductionTraceV1,
    ) -> Result<Self, ProductionWhirCandidateError> {
        if verified_trace.challenge_digest != challenge.challenge_digest() {
            return Err(ProductionWhirCandidateError::VerifiedTraceContextMismatch);
        }
        let proof_commitment_root =
            ProductionProofCommitmentRootV1::derive(trusted_model, verified_trace)?;
        let mut work = Blake3Hasher::new_derive_key(COMMITMENT_WORK_DOMAIN);
        work.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
        work.update(&challenge.challenge_digest());
        work.update(proof_commitment_root.as_bytes());
        let work_digest = *work.finalize().as_bytes();

        let mut binding = Blake3Hasher::new_derive_key(COMMITMENT_PUBLIC_BINDING_DOMAIN);
        binding.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
        binding.update(&trusted_model.proof_suite_digest());
        binding.update(&challenge.challenge_digest());
        binding.update(proof_commitment_root.as_bytes());
        binding.update(&work_digest);
        binding.update(&challenge.work_target());
        let public_binding = *binding.finalize().as_bytes();
        Ok(Self {
            proof_commitment_root,
            work_digest,
            public_binding,
        })
    }

    pub const fn proof_commitment_root(&self) -> ProductionProofCommitmentRootV1 {
        self.proof_commitment_root
    }

    pub const fn work_digest(&self) -> [u8; 32] {
        self.work_digest
    }

    pub const fn public_binding(&self) -> [u8; 32] {
        self.public_binding
    }

    pub const fn claims(&self) -> ProductionCommitmentClaimsV1 {
        ProductionCommitmentClaimsV1 {
            proof_commitment_root: *self.proof_commitment_root.as_bytes(),
            work_digest: self.work_digest,
            public_binding: self.public_binding,
        }
    }
}

/// Re-derives every commitment claim from verifier-authenticated inputs.
///
/// The opaque trace capability can only be minted by the future integrated PCS
/// and algebraic verifier after it accepts the exact semantic layout and
/// terminal alias. Callers must never accept these claims independently of
/// that proof result.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn verify_production_commitment_claims_v1(
    challenge: ProductionCommitmentChallengeV1,
    trusted_model: &ProductionBatchedModelIdentityV1,
    verified_trace: &VerifiedProductionTraceV1,
    claimed: &ProductionCommitmentClaimsV1,
) -> Result<(), ProductionWhirCandidateError> {
    let expected =
        ProductionCommitmentWorkBindingV1::derive(challenge, trusted_model, verified_trace)?;
    if claimed.proof_commitment_root != *expected.proof_commitment_root().as_bytes() {
        return Err(ProductionWhirCandidateError::ProofCommitmentMismatch);
    }
    if claimed.work_digest != expected.work_digest() {
        return Err(ProductionWhirCandidateError::WorkDigestMismatch);
    }
    if claimed.public_binding != expected.public_binding() {
        return Err(ProductionWhirCandidateError::PublicBindingMismatch);
    }
    if claimed.work_digest > challenge.work_target() {
        return Err(ProductionWhirCandidateError::HighHash);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductionWhirCandidateError {
    #[error("model identity is not the exact ForgeMatrix-v2 production geometry")]
    InvalidModel,
    #[error("model role is not one of the exact production base/weight roles")]
    InvalidRole,
    #[error("model role offset is outside its exact production table")]
    InvalidRoleOffset,
    #[error("model role opening point has the wrong variable count")]
    InvalidOpeningPoint,
    #[error("production-candidate WHIR configuration derivation failed")]
    Configuration,
    #[error(
        "native proof dictionary-free floor {minimum} exceeds the {available}-byte proof-payload budget"
    )]
    NetworkBudgetExceeded { minimum: usize, available: usize },
    #[error("native proof exceeds the bounded candidate parser budget")]
    NativeProofTooLarge,
    #[error("native proof is not a canonical production-candidate encoding")]
    InvalidEncoding,
    #[error("batched fixed-model identity has no trusted joint commitment")]
    UncommittedBatchedModel,
    #[error("production proof has no authenticated trace commitment")]
    UncommittedTrace,
    #[error("production trace bank, oracle, section, or column is outside the canonical layout")]
    InvalidTraceColumn,
    #[error("production trace row or its canonical zero padding is invalid")]
    InvalidTraceRow,
    #[error("production component commitments do not match the canonical trace section aliases")]
    TraceCommitmentMismatch,
    #[error("verified production trace belongs to a different model or block challenge")]
    VerifiedTraceContextMismatch,
    #[error("production proof commitment root mismatch")]
    ProofCommitmentMismatch,
    #[error("production commitment-derived work digest mismatch")]
    WorkDigestMismatch,
    #[error("production commitment-derived public binding mismatch")]
    PublicBindingMismatch,
    #[error("production commitment-derived work digest does not meet the target")]
    HighHash,
    #[error("production challenge could not be recomputed from the block and nonce")]
    InvalidChallenge,
    #[error("block descriptor does not match the trusted production model and geometry")]
    InvalidProductionDescriptor,
    #[error("prepared model role does not match the production-candidate configuration")]
    PreparedRoleMismatch,
    #[error("prepared model role context or artifact geometry is invalid")]
    PreparedContextMismatch,
}

impl ProductionWhirConfigV1 {
    pub fn for_model_role(
        model: &ModelPcsIdentity,
        role: ModelPcsRole,
    ) -> Result<Self, ProductionWhirCandidateError> {
        validate_production_model(model)?;
        let (role, expected_commitment) = production_role(model, role)?;
        let inner =
            build_whir_config_bounded(role.num_variables(), PRODUCTION_WHIR_WEIGHT_VARIABLES)
                .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        Ok(Self {
            role,
            model_digest: model
                .digest()
                .map_err(|_| ProductionWhirCandidateError::InvalidModel)?,
            expected_commitment,
            suite_digest: production_whir_suite_parameter_digest_v1(),
            inner,
        })
    }

    pub const fn role(&self) -> ProductionWhirRoleV1 {
        self.role
    }

    pub const fn num_variables(&self) -> usize {
        self.role.num_variables()
    }

    pub const fn model_digest(&self) -> [u8; 32] {
        self.model_digest
    }

    pub const fn expected_commitment(&self) -> [u8; 32] {
        self.expected_commitment
    }

    pub const fn suite_digest(&self) -> [u8; 32] {
        self.suite_digest
    }

    pub fn wire_shape(&self) -> Result<ProductionWhirWireShapeV1, ProductionWhirCandidateError> {
        let geometry = native_codec::proof_geometry_with_profile(
            &self.inner,
            candidate_codec_profile(usize::MAX),
        )
        .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        Ok(wire_shape(geometry, PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES))
    }

    /// Parse and canonicalize one candidate native proof without verifying its
    /// polynomial-opening statement. The n31 role fails before proof decoding
    /// or proof-sized allocation because even its dictionary-free floor exceeds
    /// the proof-payload budget.
    pub fn validate_native_proof_encoding(
        &self,
        encoded: &[u8],
    ) -> Result<(), ProductionWhirCandidateError> {
        let shape = self.wire_shape()?;
        if shape.dictionary_free_floor_bytes > PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES {
            return Err(ProductionWhirCandidateError::NetworkBudgetExceeded {
                minimum: shape.dictionary_free_floor_bytes,
                available: PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES,
            });
        }
        if encoded.len() > PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES {
            return Err(ProductionWhirCandidateError::NativeProofTooLarge);
        }
        let profile = candidate_codec_profile(PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES);
        let proof = native_codec::decode_native_proof_with_profile(encoded, &self.inner, profile)
            .map_err(map_codec_decode_error)?;
        let canonical =
            native_codec::encode_native_proof_with_profile(&proof, &self.inner, profile)
                .map_err(map_codec_encode_error)?;
        if canonical != encoded {
            return Err(ProductionWhirCandidateError::InvalidEncoding);
        }
        Ok(())
    }
}

impl ProductionBatchedModelWhirConfigV1 {
    pub fn for_trusted_model(
        trusted_model: &ProductionBatchedModelIdentityV1,
    ) -> Result<Self, ProductionWhirCandidateError> {
        let inner = build_whir_config_bounded(
            PRODUCTION_BATCHED_MODEL_VARIABLES,
            PRODUCTION_BATCHED_MODEL_VARIABLES,
        )
        .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        Ok(Self {
            trusted_model_digest: trusted_model.digest(),
            expected_commitment: trusted_model.joint_fixed_model_commitment(),
            suite_digest: production_proof_binding_suite_digest_v1(),
            inner,
        })
    }

    pub const fn num_variables(&self) -> usize {
        PRODUCTION_BATCHED_MODEL_VARIABLES
    }

    pub const fn trusted_model_digest(&self) -> [u8; 32] {
        self.trusted_model_digest
    }

    pub const fn expected_commitment(&self) -> [u8; 32] {
        self.expected_commitment
    }

    pub const fn suite_digest(&self) -> [u8; 32] {
        self.suite_digest
    }

    pub fn wire_shape(&self) -> Result<ProductionWhirWireShapeV1, ProductionWhirCandidateError> {
        let geometry = native_codec::proof_geometry_with_profile(
            &self.inner,
            batched_candidate_codec_profile(usize::MAX),
        )
        .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        Ok(wire_shape(geometry, PRODUCTION_BATCHED_WHIR_MODEL_BYTES))
    }

    pub fn validate_native_proof_encoding(
        &self,
        encoded: &[u8],
    ) -> Result<(), ProductionWhirCandidateError> {
        let shape = self.wire_shape()?;
        if shape.dictionary_free_floor_bytes > PRODUCTION_BATCHED_WHIR_MODEL_BYTES {
            return Err(ProductionWhirCandidateError::NetworkBudgetExceeded {
                minimum: shape.dictionary_free_floor_bytes,
                available: PRODUCTION_BATCHED_WHIR_MODEL_BYTES,
            });
        }
        if encoded.len() > PRODUCTION_BATCHED_WHIR_MODEL_BYTES {
            return Err(ProductionWhirCandidateError::NativeProofTooLarge);
        }
        let profile = batched_candidate_codec_profile(PRODUCTION_BATCHED_WHIR_MODEL_BYTES);
        let proof = native_codec::decode_native_proof_with_profile(encoded, &self.inner, profile)
            .map_err(map_codec_decode_error)?;
        let canonical =
            native_codec::encode_native_proof_with_profile(&proof, &self.inner, profile)
                .map_err(map_codec_encode_error)?;
        if canonical != encoded {
            return Err(ProductionWhirCandidateError::InvalidEncoding);
        }
        Ok(())
    }
}

pub fn production_whir_suite_parameter_digest_v1() -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(CANDIDATE_SUITE_DOMAIN);
    update_descriptor(
        &mut hasher,
        b"source-artifact-suite",
        &structured_whir_suite_parameter_digest(),
    );
    update_u64(
        &mut hasher,
        b"candidate-version",
        PRODUCTION_WHIR_CANDIDATE_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"production-model-version",
        PRODUCTION_MODEL_VERSION as u64,
    );
    update_u64(&mut hasher, b"production-batch", PRODUCTION_V2_BATCH as u64);
    update_u64(
        &mut hasher,
        b"production-dimension",
        PRODUCTION_V2_DIMENSION as u64,
    );
    update_u64(
        &mut hasher,
        b"production-layers-per-bank",
        PRODUCTION_V2_LAYERS_PER_BANK as u64,
    );
    update_u64(
        &mut hasher,
        b"production-total-layers",
        PRODUCTION_V2_LAYERS as u64,
    );
    update_u64(
        &mut hasher,
        b"base-variables",
        PRODUCTION_WHIR_BASE_VARIABLES as u64,
    );
    update_u64(
        &mut hasher,
        b"weight-variables",
        PRODUCTION_WHIR_WEIGHT_VARIABLES as u64,
    );
    update_u64(&mut hasher, b"weight-banks", PRODUCTION_V2_BANKS as u64);
    update_descriptor(&mut hasher, b"variable-order", b"suffix");
    update_descriptor(&mut hasher, b"security-assumption", b"unique-decoding");
    update_u64(
        &mut hasher,
        b"security-bits",
        EXPLICIT_WHIR_SECURITY_BITS as u64,
    );
    update_u64(&mut hasher, b"folding-factor", EXPLICIT_WHIR_FOLDING as u64);
    update_u64(
        &mut hasher,
        b"starting-log-inverse-rate",
        EXPLICIT_WHIR_STARTING_LOG_INV_RATE as u64,
    );
    update_u64(&mut hasher, b"pow-bits", EXPLICIT_WHIR_POW_BITS as u64);
    update_descriptor(&mut hasher, b"base-field", b"goldilocks");
    update_descriptor(&mut hasher, b"extension-field", b"cubic:u^3=u+1");
    update_descriptor(
        &mut hasher,
        b"field-element-encoding",
        b"canonical-u64-coefficients-extension-basis-1-u-u2",
    );
    update_descriptor(&mut hasher, b"native-codec", NATIVE_CODEC_DESCRIPTION);
    update_descriptor(
        &mut hasher,
        b"native-codec-magic",
        PRODUCTION_WHIR_NATIVE_MAGIC,
    );
    update_u64(
        &mut hasher,
        b"native-codec-version",
        PRODUCTION_WHIR_NATIVE_CODEC_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"native-protocol-version",
        PRODUCTION_WHIR_NATIVE_PROTOCOL_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"native-codec-flags",
        native_codec::NATIVE_PROOF_CODEC_FLAGS as u64,
    );
    update_u64(
        &mut hasher,
        b"native-header-bytes",
        native_codec::NATIVE_PROOF_CODEC_HEADER_BYTES as u64,
    );
    update_u64(
        &mut hasher,
        b"dictionary-reference-bytes",
        native_codec::NATIVE_PROOF_CODEC_REFERENCE_BYTES as u64,
    );
    update_u64(
        &mut hasher,
        b"maximum-dictionary-nodes",
        native_codec::NATIVE_PROOF_CODEC_MAX_DICTIONARY_NODES as u64,
    );
    update_u64(
        &mut hasher,
        b"complete-frame-bytes",
        crate::wire::MAX_PROOF_BYTES as u64,
    );
    update_u64(
        &mut hasher,
        b"wire-header-bytes",
        crate::wire::WIRE_HEADER_BYTES as u64,
    );
    update_u64(
        &mut hasher,
        b"absolute-native-bytes",
        PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES as u64,
    );
    *hasher.finalize().as_bytes()
}

/// Digest of the complete commitment-derived production binding proposal.
///
/// This is separate from the per-role WHIR suite so adding the batched proof
/// architecture cannot silently reinterpret already-generated artifacts.
pub fn production_proof_binding_suite_digest_v1() -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(PROOF_BINDING_SUITE_DOMAIN);
    update_u64(
        &mut hasher,
        b"binding-version",
        PRODUCTION_PROOF_BINDING_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"forgematrix-algorithm-version",
        crate::FORGEMATRIX_V2_ALGORITHM_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"forgematrix-proof-version",
        crate::FORGEMATRIX_V2_PROOF_VERSION as u64,
    );
    update_descriptor(
        &mut hasher,
        b"whir-candidate-suite",
        &production_whir_suite_parameter_digest_v1(),
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-layout",
        b"four-equal-n31-slots-concatenated-into-one-n33-polynomial",
    );
    update_u64(
        &mut hasher,
        b"fixed-model-joint-variables",
        PRODUCTION_BATCHED_MODEL_VARIABLES as u64,
    );
    update_u64(
        &mut hasher,
        b"fixed-model-slot-variables",
        PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES as u64,
    );
    update_u64(
        &mut hasher,
        b"fixed-model-slot-count",
        PRODUCTION_BATCHED_MODEL_SLOTS as u64,
    );
    update_u64(
        &mut hasher,
        b"maximum-batched-model-native-bytes",
        PRODUCTION_BATCHED_WHIR_MODEL_BYTES as u64,
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-slot-order",
        b"base-input,weight-bank-0,weight-bank-1,weight-bank-2",
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-linear-index",
        b"slot-index-times-2^31-plus-role-local-index",
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-base-padding",
        b"goldilocks-zero-for-local-indices-2^19-through-exclusive-2^31",
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-variable-order",
        b"suffix-low-31-role-local-bits-high-2-slot-selector-bits",
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-opening-lift",
        b"base=[selector-be2(0),zero^12,r19];weight-i=[selector-be2(i+1),r31]",
    );
    update_descriptor(
        &mut hasher,
        b"batched-native-codec",
        NATIVE_CODEC_DESCRIPTION,
    );
    update_descriptor(
        &mut hasher,
        b"batched-native-magic",
        PRODUCTION_BATCHED_WHIR_NATIVE_MAGIC,
    );
    update_u64(
        &mut hasher,
        b"batched-native-codec-version",
        PRODUCTION_BATCHED_WHIR_NATIVE_CODEC_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"batched-native-protocol-version",
        PRODUCTION_BATCHED_WHIR_NATIVE_PROTOCOL_VERSION as u64,
    );
    update_descriptor(
        &mut hasher,
        b"trace-layout",
        b"ordered-init-oracles-1-through-109-then-bank-major-oracles-0-through-109-no-sort-no-dedup",
    );
    update_u64(
        &mut hasher,
        b"trace-semantic-columns",
        PRODUCTION_TRACE_SEMANTIC_COLUMNS as u64,
    );
    update_u64(
        &mut hasher,
        b"trace-section-count",
        PRODUCTION_TRACE_SECTION_COUNT as u64,
    );
    update_descriptor(
        &mut hasher,
        b"trace-physical-sections",
        b"init:109xn19-to-n26;each-bank:32,32,32,14-columns-of-n26-to-n31,n31,n31,n30;zero-tail-padding",
    );
    update_descriptor(
        &mut hasher,
        b"trace-section-field-limit",
        b"goldilocks-two-adicity-32-with-rate-one-no-committed-section-exceeds-n31",
    );
    update_descriptor(
        &mut hasher,
        b"terminal-column",
        b"bank-2-transition-activation-oracle-10-at-section-9-column-10",
    );
    update_descriptor(
        &mut hasher,
        b"trace-root",
        b"blake3(layout-digest,padding-digest,ordered-thirteen-section-roots)",
    );
    update_descriptor(
        &mut hasher,
        b"trace-column-alias",
        b"blake3(layout-digest,section-root,semantic-column,section-index,section-column,column-variables)",
    );
    update_descriptor(
        &mut hasher,
        b"verified-trace-capability",
        b"sealed-after-all-thirteen-ordered-section-openings-layout-padding-and-terminal-column-alias-checks;binds-trusted-model-digest-and-block-challenge-digest",
    );
    update_descriptor(
        &mut hasher,
        b"commitment-randomness",
        b"none-deterministic-non-hiding-canonical-padding",
    );
    update_u64(
        &mut hasher,
        b"final-output-elements",
        PRODUCTION_FINAL_ACTIVATION_ELEMENTS as u64,
    );
    update_descriptor(
        &mut hasher,
        b"final-output-binding",
        b"sealed-terminal-table-alias-equals-terminal-wiring-commitment",
    );
    update_descriptor(
        &mut hasher,
        b"final-output-hash-argument",
        b"absent-work-binds-authenticated-canonical-final-trace-commitment",
    );
    update_descriptor(
        &mut hasher,
        b"work-relation",
        b"blake3(challenge-digest,verifier-derived-proof-commitment-root)",
    );
    update_descriptor(
        &mut hasher,
        b"work-target-order",
        b"unsigned-big-endian-256-bit-work-digest-less-than-or-equal-target",
    );
    update_descriptor(
        &mut hasher,
        b"batched-model-domain",
        BATCHED_MODEL_IDENTITY_DOMAIN.as_bytes(),
    );
    update_descriptor(
        &mut hasher,
        b"proof-commitment-domain",
        PROOF_COMMITMENT_ROOT_DOMAIN.as_bytes(),
    );
    update_descriptor(
        &mut hasher,
        b"work-domain",
        COMMITMENT_WORK_DOMAIN.as_bytes(),
    );
    update_descriptor(
        &mut hasher,
        b"public-binding-domain",
        COMMITMENT_PUBLIC_BINDING_DOMAIN.as_bytes(),
    );
    *hasher.finalize().as_bytes()
}

/// Maps an existing fixed-model role element into the exact n33 batched source.
/// The unused tail of slot zero is canonically Goldilocks zero.
pub fn production_batched_model_source_index_v1(
    role: ProductionWhirRoleV1,
    role_offset: u64,
) -> Result<u64, ProductionWhirCandidateError> {
    let (slot, role_elements) = match role {
        ProductionWhirRoleV1::BaseInput => (0_u64, 1_u64 << PRODUCTION_WHIR_BASE_VARIABLES),
        ProductionWhirRoleV1::WeightBank { index } if index < PRODUCTION_V2_BANKS as u8 => (
            u64::from(index) + 1,
            1_u64 << PRODUCTION_WHIR_WEIGHT_VARIABLES,
        ),
        ProductionWhirRoleV1::WeightBank { .. } => {
            return Err(ProductionWhirCandidateError::InvalidRole);
        }
    };
    if role_offset >= role_elements {
        return Err(ProductionWhirCandidateError::InvalidRoleOffset);
    }
    slot.checked_shl(PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES as u32)
        .and_then(|start| start.checked_add(role_offset))
        .ok_or(ProductionWhirCandidateError::Configuration)
}

/// Lifts a role-local multilinear opening into the exact n33 joint model.
pub fn production_batched_model_lift_point_v1(
    role: ProductionWhirRoleV1,
    role_point: &[crate::ExtensionElement],
) -> Result<Vec<crate::ExtensionElement>, ProductionWhirCandidateError> {
    if role_point.len() != role.num_variables() {
        return Err(ProductionWhirCandidateError::InvalidOpeningPoint);
    }
    let slot = match role {
        ProductionWhirRoleV1::BaseInput => 0_u8,
        ProductionWhirRoleV1::WeightBank { index } if index < PRODUCTION_V2_BANKS as u8 => {
            index + 1
        }
        ProductionWhirRoleV1::WeightBank { .. } => {
            return Err(ProductionWhirCandidateError::InvalidRole);
        }
    };
    let zero = crate::ExtensionElement { limbs: [0; 3] };
    let one = crate::ExtensionElement { limbs: [1, 0, 0] };
    let mut lifted = Vec::with_capacity(PRODUCTION_BATCHED_MODEL_VARIABLES);
    lifted.push(if slot & 0b10 == 0 { zero } else { one });
    lifted.push(if slot & 0b01 == 0 { zero } else { one });
    if role == ProductionWhirRoleV1::BaseInput {
        lifted.extend(std::iter::repeat_n(
            zero,
            PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES - PRODUCTION_WHIR_BASE_VARIABLES,
        ));
    }
    lifted.extend_from_slice(role_point);
    debug_assert_eq!(lifted.len(), PRODUCTION_BATCHED_MODEL_VARIABLES);
    Ok(lifted)
}

pub(super) const fn candidate_codec_profile(max_encoded_bytes: usize) -> NativeProofCodecProfile {
    NativeProofCodecProfile::new(
        PRODUCTION_WHIR_NATIVE_MAGIC,
        PRODUCTION_WHIR_NATIVE_CODEC_VERSION,
        PRODUCTION_WHIR_NATIVE_PROTOCOL_VERSION,
        PRODUCTION_WHIR_WEIGHT_VARIABLES,
        max_encoded_bytes,
    )
}

pub(super) const fn batched_candidate_codec_profile(
    max_encoded_bytes: usize,
) -> NativeProofCodecProfile {
    NativeProofCodecProfile::new(
        PRODUCTION_BATCHED_WHIR_NATIVE_MAGIC,
        PRODUCTION_BATCHED_WHIR_NATIVE_CODEC_VERSION,
        PRODUCTION_BATCHED_WHIR_NATIVE_PROTOCOL_VERSION,
        PRODUCTION_BATCHED_MODEL_VARIABLES,
        max_encoded_bytes,
    )
}

fn wire_shape(geometry: NativeProofGeometry, available_bytes: usize) -> ProductionWhirWireShapeV1 {
    ProductionWhirWireShapeV1 {
        intermediate_rounds: geometry.intermediate_rounds,
        path_depths: geometry.path_depths,
        body_bytes: geometry.body_bytes,
        reference_count: geometry.reference_count,
        maximum_dictionary_nodes: geometry.maximum_dictionary_nodes,
        dictionary_free_floor_bytes: geometry.structural_floor_bytes,
        maximum_native_bytes: geometry.conservative_upper_bound_bytes,
        available_native_bytes: available_bytes,
        conservative_payload_fit: geometry.conservative_upper_bound_bytes <= available_bytes,
    }
}

fn validate_production_model(model: &ModelPcsIdentity) -> Result<(), ProductionWhirCandidateError> {
    model
        .validate()
        .map_err(|_| ProductionWhirCandidateError::InvalidModel)?;
    if model.model_version != PRODUCTION_MODEL_VERSION
        || model.batch != PRODUCTION_V2_BATCH
        || model.dimension != PRODUCTION_V2_DIMENSION
        || model.layers_per_bank != PRODUCTION_V2_LAYERS_PER_BANK
        || model.weight_bank_commitments.len() != PRODUCTION_V2_BANKS as usize
        || model.weight_bank_commitments.len() != MAX_MODEL_PCS_WEIGHT_BANKS
        || model.layers_per_bank.checked_mul(PRODUCTION_V2_BANKS) != Some(PRODUCTION_V2_LAYERS)
        || model.pcs_suite_parameter_digest != structured_whir_suite_parameter_digest()
    {
        return Err(ProductionWhirCandidateError::InvalidModel);
    }
    Ok(())
}

fn production_role(
    model: &ModelPcsIdentity,
    role: ModelPcsRole,
) -> Result<(ProductionWhirRoleV1, [u8; 32]), ProductionWhirCandidateError> {
    match role {
        ModelPcsRole::BaseInput => {
            Ok((ProductionWhirRoleV1::BaseInput, model.base_input_commitment))
        }
        ModelPcsRole::WeightBank { index } => {
            let index_u8 =
                u8::try_from(index).map_err(|_| ProductionWhirCandidateError::InvalidRole)?;
            let commitment = model
                .weight_bank_commitments
                .get(index as usize)
                .copied()
                .ok_or(ProductionWhirCandidateError::InvalidRole)?;
            Ok((
                ProductionWhirRoleV1::WeightBank { index: index_u8 },
                commitment,
            ))
        }
    }
}

fn map_codec_decode_error(error: NativeProofCodecError) -> ProductionWhirCandidateError {
    match error {
        NativeProofCodecError::TooLarge => ProductionWhirCandidateError::NativeProofTooLarge,
        NativeProofCodecError::Configuration => ProductionWhirCandidateError::Configuration,
        _ => ProductionWhirCandidateError::InvalidEncoding,
    }
}

fn map_codec_encode_error(error: NativeProofCodecError) -> ProductionWhirCandidateError {
    match error {
        NativeProofCodecError::TooLarge => ProductionWhirCandidateError::NativeProofTooLarge,
        NativeProofCodecError::Configuration => ProductionWhirCandidateError::Configuration,
        _ => ProductionWhirCandidateError::InvalidEncoding,
    }
}

fn update_descriptor(hasher: &mut Blake3Hasher, label: &[u8], value: &[u8]) {
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn update_u64(hasher: &mut Blake3Hasher, label: &[u8], value: u64) {
    update_descriptor(hasher, label, &value.to_le_bytes());
}

#[cfg(feature = "gpu-proof-prover")]
pub struct BoundProductionWhirRoleV1 {
    model_digest: [u8; 32],
    production_suite_digest: [u8; 32],
    role: ProductionWhirRoleV1,
    prepared: crate::PreparedModelWhirRoleV2,
}

#[cfg(feature = "gpu-proof-prover")]
impl std::fmt::Debug for BoundProductionWhirRoleV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundProductionWhirRoleV1")
            .field("model_digest", &self.model_digest)
            .field("production_suite_digest", &self.production_suite_digest)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl BoundProductionWhirRoleV1 {
    pub const fn model_digest(&self) -> [u8; 32] {
        self.model_digest
    }

    pub const fn production_suite_digest(&self) -> [u8; 32] {
        self.production_suite_digest
    }

    pub const fn role(&self) -> ProductionWhirRoleV1 {
        self.role
    }

    pub const fn prepared(&self) -> &crate::PreparedModelWhirRoleV2 {
        &self.prepared
    }
}

/// A failed candidate bind together with the original prepared role.
///
/// Preparing an n19/n31 role can be expensive, so a rejected bind must not
/// silently destroy the caller's capability.
#[cfg(feature = "gpu-proof-prover")]
#[derive(Debug)]
pub struct ProductionWhirBindFailure {
    error: ProductionWhirCandidateError,
    prepared: Box<crate::PreparedModelWhirRoleV2>,
}

#[cfg(feature = "gpu-proof-prover")]
impl ProductionWhirBindFailure {
    pub const fn error(&self) -> &ProductionWhirCandidateError {
        &self.error
    }

    pub fn prepared(&self) -> &crate::PreparedModelWhirRoleV2 {
        self.prepared.as_ref()
    }

    pub fn into_prepared(self) -> crate::PreparedModelWhirRoleV2 {
        *self.prepared
    }

    pub fn into_parts(self) -> (ProductionWhirCandidateError, crate::PreparedModelWhirRoleV2) {
        (self.error, *self.prepared)
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl std::fmt::Display for ProductionWhirBindFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl std::error::Error for ProductionWhirBindFailure {}

/// Join the authenticated source/oracle capability to the candidate type
/// boundary without changing the existing WHIR transcript.
///
/// This wrapper is prover-local type state only. A future candidate proof must
/// cryptographically bind the production suite digest, model digest, exact
/// role/index, expected commitment, and opening statement into its public
/// statement and Fiat-Shamir transcript before this path can be consensus.
#[cfg(feature = "gpu-proof-prover")]
pub fn bind_prepared_production_whir_role_v1(
    config: &ProductionWhirConfigV1,
    model: &ModelPcsIdentity,
    prepared: crate::PreparedModelWhirRoleV2,
) -> Result<BoundProductionWhirRoleV1, ProductionWhirBindFailure> {
    if let Err(error) = validate_prepared_production_whir_role_v1(config, model, &prepared) {
        return Err(ProductionWhirBindFailure {
            error,
            prepared: Box::new(prepared),
        });
    }

    Ok(BoundProductionWhirRoleV1 {
        model_digest: config.model_digest,
        production_suite_digest: config.suite_digest,
        role: config.role,
        prepared,
    })
}

#[cfg(feature = "gpu-proof-prover")]
fn validate_prepared_production_whir_role_v1(
    config: &ProductionWhirConfigV1,
    model: &ModelPcsIdentity,
    prepared: &crate::PreparedModelWhirRoleV2,
) -> Result<(), ProductionWhirCandidateError> {
    let prover_identity = prepared.prover_identity();
    let source = prover_identity.source_artifact_identity();
    let oracle = prover_identity.oracle_identity();
    let binding = PreparedProductionWhirBindingV1 {
        role: prepared.role(),
        expected_commitment: prepared.expected_commitment(),
        source_num_variables: source.source.num_variables,
        source_element_count: source.element_count,
        context_digest: prepared.context_digest(),
        oracle_context_digest: oracle.context_digest(),
        oracle_source_matches: oracle.codeword_identity().source == source.source,
    };
    validate_prepared_production_whir_binding_v1(config, model, &binding)
}

#[cfg(feature = "gpu-proof-prover")]
struct PreparedProductionWhirBindingV1 {
    role: ModelPcsRole,
    expected_commitment: [u8; 32],
    source_num_variables: u32,
    source_element_count: u64,
    context_digest: [u8; 32],
    oracle_context_digest: [u8; 32],
    oracle_source_matches: bool,
}

#[cfg(feature = "gpu-proof-prover")]
fn validate_prepared_production_whir_binding_v1(
    config: &ProductionWhirConfigV1,
    model: &ModelPcsIdentity,
    binding: &PreparedProductionWhirBindingV1,
) -> Result<(), ProductionWhirCandidateError> {
    let derived = ProductionWhirConfigV1::for_model_role(model, binding.role)?;
    if derived.role != config.role
        || derived.model_digest != config.model_digest
        || derived.expected_commitment != config.expected_commitment
        || derived.suite_digest != config.suite_digest
        || binding.role != config.role.as_model_role()
        || binding.expected_commitment != config.expected_commitment
    {
        return Err(ProductionWhirCandidateError::PreparedRoleMismatch);
    }

    let expected_elements = 1_u64
        .checked_shl(config.num_variables() as u32)
        .ok_or(ProductionWhirCandidateError::PreparedContextMismatch)?;
    let expected_context = crate::model_whir_role_context_digest(model, binding.role)
        .map_err(|_| ProductionWhirCandidateError::PreparedContextMismatch)?;
    if binding.source_num_variables as usize != config.num_variables()
        || binding.source_element_count != expected_elements
        || binding.context_digest != expected_context
        || binding.oracle_context_digest != expected_context
        || !binding.oracle_source_matches
    {
        return Err(ProductionWhirCandidateError::PreparedContextMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{Dft, WhirMmcs, build_pcs, empty_proof_for};
    use super::*;
    use crate::ExtensionElement;
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_multilinear_util::{point::Point, poly::Poly};
    use p3_sumcheck::commit::commit_base;
    use p3_sumcheck::constraints::{Constraint, statement::EqStatement};
    use p3_sumcheck::layout::PrefixProver;
    use p3_sumcheck::product_polynomial::ProductPolynomial;
    use p3_sumcheck::strategy::{SumcheckProver, VariableOrder};
    use p3_whir::pcs::prover::WhirProver;
    use p3_whir::pcs::verifier::WhirVerifier;

    fn production_model() -> ModelPcsIdentity {
        ModelPcsIdentity {
            model_version: PRODUCTION_MODEL_VERSION,
            batch: PRODUCTION_V2_BATCH,
            dimension: PRODUCTION_V2_DIMENSION,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            model_byte_root: [0x31; 32],
            pcs_suite_parameter_digest: structured_whir_suite_parameter_digest(),
            base_input_commitment: [0x41; 32],
            weight_bank_commitments: vec![[0x51; 32], [0x52; 32], [0x53; 32]],
        }
    }

    fn production_descriptor(model: &ModelPcsIdentity) -> ForgeMatrixV2Descriptor {
        let dimension = u64::from(PRODUCTION_V2_DIMENSION);
        let base_input_bytes = u64::from(PRODUCTION_V2_BATCH) * dimension;
        let bytes_per_layer = dimension * dimension;
        ForgeMatrixV2Descriptor {
            network_id: [0x63; 32],
            algorithm_version: crate::FORGEMATRIX_V2_ALGORITHM_VERSION,
            proof_version: crate::FORGEMATRIX_V2_PROOF_VERSION,
            banks: PRODUCTION_V2_BANKS,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            model: crate::ModelBankManifest {
                model_version: PRODUCTION_MODEL_VERSION,
                dimension: PRODUCTION_V2_DIMENSION,
                batch: PRODUCTION_V2_BATCH,
                layers: PRODUCTION_V2_LAYERS,
                base_input_bytes,
                bytes_per_layer,
                payload_bytes: u64::from(PRODUCTION_V2_LAYERS) * bytes_per_layer + base_input_bytes,
                raw_blake3_root: model.model_byte_root,
                layer_roots_aggregate: [0x32; 32],
                pcs_parameter_digest: model.pcs_suite_parameter_digest,
                pcs_commitment_root: model.commitment_root().unwrap(),
            },
        }
    }

    fn trace_section_roots(
        trace_seed: [u8; 32],
        terminal_seed: [u8; 32],
    ) -> [[u8; 32]; PRODUCTION_TRACE_SECTION_COUNT] {
        let mut section_roots = std::array::from_fn(|index| {
            let mut root = trace_seed;
            root[31] ^= index as u8;
            root
        });
        section_roots[PRODUCTION_TRACE_TERMINAL_SECTION] = terminal_seed;
        section_roots
    }

    fn verified_trace(
        trusted_model: &ProductionBatchedModelIdentityV1,
        challenge: ProductionCommitmentChallengeV1,
        trace_seed: [u8; 32],
        terminal_seed: [u8; 32],
    ) -> VerifiedProductionTraceV1 {
        let section_roots = trace_section_roots(trace_seed, terminal_seed);
        let commitments = production_trace_column_commitments_v1(&section_roots).unwrap();
        VerifiedProductionTraceV1::from_verified_sections(
            trusted_model.digest(),
            challenge.challenge_digest(),
            section_roots,
            &commitments,
        )
        .unwrap()
    }

    #[test]
    fn exact_production_roles_have_pinned_n19_and_n31_geometry() {
        let model = production_model();
        let base = ProductionWhirConfigV1::for_model_role(&model, ModelPcsRole::BaseInput).unwrap();
        let base_shape = base.wire_shape().unwrap();
        assert_eq!(base.role(), ProductionWhirRoleV1::BaseInput);
        assert_eq!(base.num_variables(), 19);
        assert_eq!(base_shape.intermediate_rounds, 6);
        assert_eq!(base_shape.path_depths, (12..=18).rev().collect::<Vec<_>>());
        assert_eq!(base_shape.body_bytes, 96_240);
        assert_eq!(base_shape.reference_count, 18_509);
        assert_eq!(base_shape.maximum_dictionary_nodes, 11_911);
        assert_eq!(base_shape.dictionary_free_floor_bytes, 133_298);
        assert_eq!(base_shape.maximum_native_bytes, 514_450);
        assert_eq!(
            base_shape.available_native_bytes,
            PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES
        );
        assert!(!base_shape.conservative_payload_fit);

        for index in 0..PRODUCTION_V2_BANKS {
            let config =
                ProductionWhirConfigV1::for_model_role(&model, ModelPcsRole::WeightBank { index })
                    .unwrap();
            let shape = config.wire_shape().unwrap();
            assert_eq!(
                config.role(),
                ProductionWhirRoleV1::WeightBank { index: index as u8 }
            );
            assert_eq!(config.num_variables(), 31);
            assert_eq!(shape.intermediate_rounds, 12);
            assert_eq!(shape.path_depths, (18..=30).rev().collect::<Vec<_>>());
            assert_eq!(shape.body_bytes, 171_312);
            assert_eq!(shape.reference_count, 48_644);
            assert_eq!(shape.maximum_dictionary_nodes, 38_152);
            assert_eq!(shape.dictionary_free_floor_bytes, 268_640);
            assert_eq!(shape.maximum_native_bytes, 1_489_504);
            assert_eq!(
                shape.available_native_bytes,
                PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES
            );
            assert!(!shape.conservative_payload_fit);
            assert_eq!(
                config.validate_native_proof_encoding(&[]),
                Err(ProductionWhirCandidateError::NetworkBudgetExceeded {
                    minimum: 268_640,
                    available: 262_128,
                })
            );
        }
    }

    #[test]
    fn only_the_exact_source_suite_model_shape_and_roles_are_admitted() {
        let model = production_model();
        assert!(
            ProductionWhirConfigV1::for_model_role(&model, ModelPcsRole::WeightBank { index: 3 })
                .is_err()
        );

        for mutate in [
            |identity: &mut ModelPcsIdentity| identity.model_version = 3,
            |identity: &mut ModelPcsIdentity| identity.batch /= 2,
            |identity: &mut ModelPcsIdentity| identity.dimension /= 2,
            |identity: &mut ModelPcsIdentity| identity.layers_per_bank /= 2,
            |identity: &mut ModelPcsIdentity| identity.pcs_suite_parameter_digest[0] ^= 1,
            |identity: &mut ModelPcsIdentity| {
                identity.weight_bank_commitments.pop();
            },
        ] {
            let mut malformed = model.clone();
            mutate(&mut malformed);
            assert_eq!(
                ProductionWhirConfigV1::for_model_role(&malformed, ModelPcsRole::BaseInput)
                    .unwrap_err(),
                ProductionWhirCandidateError::InvalidModel
            );
        }
    }

    #[test]
    fn candidate_suite_is_separate_from_the_v2_source_artifact_suite() {
        let candidate = production_whir_suite_parameter_digest_v1();
        assert_ne!(candidate, structured_whir_suite_parameter_digest());
        assert_eq!(
            hex::encode(candidate),
            "ac65cb999e987299d87ea6e6c1b2934784b2130d915eb4f1e284bb034b7ab696"
        );
    }

    #[test]
    fn commitment_challenge_is_recomputed_with_the_header_target() {
        let model = production_model();
        let trusted =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x61; 32])
                .unwrap();
        let descriptor = production_descriptor(&model);
        let block = BlockChallenge {
            network_id: descriptor.network_id,
            previous_block: [0x11; 32],
            transaction_root: [0x22; 32],
            height: 42,
            timestamp: 1_777_777_777,
            target: [0x7f; 32],
        };
        let challenge =
            ProductionCommitmentChallengeV1::from_block(&descriptor, &trusted, &block, 9).unwrap();
        assert_eq!(challenge.work_target(), block.target);
        assert_eq!(
            challenge.challenge_digest(),
            crate::forgematrix_v2::challenge_digest(&descriptor, &block, 9).unwrap()
        );

        let mut different_target = block;
        different_target.target[0] ^= 1;
        let different = ProductionCommitmentChallengeV1::from_block(
            &descriptor,
            &trusted,
            &different_target,
            9,
        )
        .unwrap();
        assert_ne!(challenge.challenge_digest(), different.challenge_digest());
        assert_ne!(challenge.work_target(), different.work_target());

        let mut wrong_network = block;
        wrong_network.network_id[0] ^= 1;
        assert_eq!(
            ProductionCommitmentChallengeV1::from_block(&descriptor, &trusted, &wrong_network, 9,),
            Err(ProductionWhirCandidateError::InvalidChallenge)
        );

        let tiny = crate::v2_test_reference().unwrap().descriptor();
        assert_eq!(
            ProductionCommitmentChallengeV1::from_block(&tiny, &trusted, &block, 9),
            Err(ProductionWhirCandidateError::InvalidProductionDescriptor)
        );
        let mut wrong_model = descriptor;
        wrong_model.model.pcs_commitment_root[0] ^= 1;
        assert_eq!(
            ProductionCommitmentChallengeV1::from_block(&wrong_model, &trusted, &block, 9),
            Err(ProductionWhirCandidateError::InvalidProductionDescriptor)
        );
    }

    #[test]
    fn batched_model_layout_has_four_exact_n31_slots() {
        assert_eq!(PRODUCTION_BATCHED_MODEL_VARIABLES, 33);
        assert_eq!(PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES, 31);
        assert_eq!(PRODUCTION_BATCHED_MODEL_SLOTS, 4);
        assert_eq!(
            production_batched_model_source_index_v1(ProductionWhirRoleV1::BaseInput, 0),
            Ok(0)
        );
        assert_eq!(
            production_batched_model_source_index_v1(
                ProductionWhirRoleV1::BaseInput,
                (1_u64 << 19) - 1,
            ),
            Ok((1_u64 << 19) - 1)
        );
        assert_eq!(
            production_batched_model_source_index_v1(ProductionWhirRoleV1::BaseInput, 1_u64 << 19,),
            Err(ProductionWhirCandidateError::InvalidRoleOffset)
        );
        for index in 0..PRODUCTION_V2_BANKS as u8 {
            let slot_start = (u64::from(index) + 1) << 31;
            assert_eq!(
                production_batched_model_source_index_v1(
                    ProductionWhirRoleV1::WeightBank { index },
                    0,
                ),
                Ok(slot_start)
            );
            assert_eq!(
                production_batched_model_source_index_v1(
                    ProductionWhirRoleV1::WeightBank { index },
                    (1_u64 << 31) - 1,
                ),
                Ok(slot_start + (1_u64 << 31) - 1)
            );
            assert_eq!(
                production_batched_model_source_index_v1(
                    ProductionWhirRoleV1::WeightBank { index },
                    1_u64 << 31,
                ),
                Err(ProductionWhirCandidateError::InvalidRoleOffset)
            );
        }
        assert_eq!(
            production_batched_model_source_index_v1(
                ProductionWhirRoleV1::WeightBank { index: 3 },
                0,
            ),
            Err(ProductionWhirCandidateError::InvalidRole)
        );
    }

    #[test]
    fn batched_model_opening_lift_matches_the_linear_index_layout() {
        let boolean_point = |index: u64, variables: usize| {
            (0..variables)
                .map(|coordinate| ExtensionElement {
                    limbs: [(index >> (variables - coordinate - 1)) & 1, 0, 0],
                })
                .collect::<Vec<_>>()
        };
        let boolean_index = |point: &[ExtensionElement]| {
            point.iter().fold(0_u64, |index, coordinate| {
                assert_eq!(coordinate.limbs[1..], [0, 0]);
                assert!(coordinate.limbs[0] <= 1);
                (index << 1) | coordinate.limbs[0]
            })
        };

        for offset in [0, 1, (1_u64 << 19) - 1] {
            let role = ProductionWhirRoleV1::BaseInput;
            let point = boolean_point(offset, PRODUCTION_WHIR_BASE_VARIABLES);
            let lifted = production_batched_model_lift_point_v1(role, &point).unwrap();
            assert_eq!(lifted.len(), PRODUCTION_BATCHED_MODEL_VARIABLES);
            assert!(
                lifted[..14]
                    .iter()
                    .all(|coordinate| coordinate.limbs == [0; 3])
            );
            assert_eq!(
                boolean_index(&lifted),
                production_batched_model_source_index_v1(role, offset).unwrap()
            );
        }
        for index in 0..PRODUCTION_V2_BANKS as u8 {
            let role = ProductionWhirRoleV1::WeightBank { index };
            for offset in [0, 1, (1_u64 << 31) - 1] {
                let point = boolean_point(offset, PRODUCTION_WHIR_WEIGHT_VARIABLES);
                let lifted = production_batched_model_lift_point_v1(role, &point).unwrap();
                assert_eq!(lifted.len(), PRODUCTION_BATCHED_MODEL_VARIABLES);
                assert_eq!(
                    boolean_index(&lifted),
                    production_batched_model_source_index_v1(role, offset).unwrap()
                );
            }
        }
        assert_eq!(
            production_batched_model_lift_point_v1(
                ProductionWhirRoleV1::BaseInput,
                &boolean_point(0, PRODUCTION_WHIR_BASE_VARIABLES - 1),
            ),
            Err(ProductionWhirCandidateError::InvalidOpeningPoint)
        );
        assert_eq!(
            production_batched_model_lift_point_v1(
                ProductionWhirRoleV1::WeightBank { index: 3 },
                &boolean_point(0, PRODUCTION_WHIR_WEIGHT_VARIABLES),
            ),
            Err(ProductionWhirCandidateError::InvalidRole)
        );
    }

    #[test]
    fn batched_model_whir_geometry_is_measured_before_activation() {
        let model = production_model();
        let trusted =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x61; 32])
                .unwrap();
        let config = ProductionBatchedModelWhirConfigV1::for_trusted_model(&trusted).unwrap();
        assert_eq!(config.num_variables(), 33);
        assert_eq!(config.trusted_model_digest(), trusted.digest());
        assert_eq!(config.expected_commitment(), [0x61; 32]);
        assert_eq!(config.suite_digest(), trusted.proof_suite_digest());
        let shape = config.wire_shape().unwrap();
        assert_eq!(shape.intermediate_rounds, 13);
        assert_eq!(shape.path_depths, (19..=32).rev().collect::<Vec<_>>());
        assert_eq!(shape.body_bytes, 183_824);
        assert_eq!(shape.reference_count, 55_021);
        assert_eq!(shape.maximum_dictionary_nodes, 43_880);
        assert_eq!(shape.dictionary_free_floor_bytes, 293_906);
        assert_eq!(shape.maximum_native_bytes, 1_698_066);
        assert_eq!(
            shape.available_native_bytes,
            PRODUCTION_BATCHED_WHIR_MODEL_BYTES
        );
        assert!(!shape.conservative_payload_fit);
        assert_eq!(
            config.validate_native_proof_encoding(&[]),
            Err(ProductionWhirCandidateError::NetworkBudgetExceeded {
                minimum: shape.dictionary_free_floor_bytes,
                available: PRODUCTION_BATCHED_WHIR_MODEL_BYTES,
            })
        );
    }

    #[test]
    fn production_trace_layout_is_exact_ordered_and_within_field_two_adicity() {
        assert_eq!(PRODUCTION_TRACE_INITIALIZATION_COLUMNS, 109);
        assert_eq!(PRODUCTION_TRACE_BANK_COLUMNS, 110);
        assert_eq!(PRODUCTION_TRACE_BANK_SECTION_COLUMNS, 32);
        assert_eq!(PRODUCTION_TRACE_SEMANTIC_COLUMNS, 439);
        assert_eq!(PRODUCTION_TRACE_SECTION_COUNT, 13);

        let sections = production_trace_sections_v1();
        assert_eq!(
            sections.map(|section| section.semantic_column_start),
            [
                0, 109, 141, 173, 205, 219, 251, 283, 315, 329, 361, 393, 425
            ]
        );
        assert_eq!(
            sections.map(|section| section.column_count),
            [109, 32, 32, 32, 14, 32, 32, 32, 14, 32, 32, 32, 14]
        );
        assert_eq!(
            sections.map(|section| section.stacked_variables),
            [26, 31, 31, 31, 30, 31, 31, 31, 30, 31, 31, 31, 30]
        );
        for (index, section) in sections.into_iter().enumerate() {
            assert_eq!(section.section_index, index as u32);
            assert_eq!(section.column_variables, if index == 0 { 19 } else { 26 });
            let populated = u64::from(section.column_count) << section.column_variables;
            assert!(populated <= 1_u64 << section.stacked_variables);
            assert!(section.stacked_variables <= 31);
        }

        assert_eq!(
            production_trace_initialization_column_v1(0),
            Err(ProductionWhirCandidateError::InvalidTraceColumn)
        );
        assert_eq!(
            production_trace_initialization_column_v1(110),
            Err(ProductionWhirCandidateError::InvalidTraceColumn)
        );
        assert_eq!(
            production_trace_initialization_column_v1(1).unwrap(),
            ProductionTraceColumnV1 {
                semantic_column: 0,
                section_index: 0,
                section_column: 0,
                column_variables: 19,
            }
        );
        assert_eq!(
            production_trace_initialization_column_v1(109).unwrap(),
            ProductionTraceColumnV1 {
                semantic_column: 108,
                section_index: 0,
                section_column: 108,
                column_variables: 19,
            }
        );
        assert_eq!(
            production_trace_bank_column_v1(0, 31).unwrap(),
            ProductionTraceColumnV1 {
                semantic_column: 140,
                section_index: 1,
                section_column: 31,
                column_variables: 26,
            }
        );
        assert_eq!(
            production_trace_bank_column_v1(0, 32).unwrap(),
            ProductionTraceColumnV1 {
                semantic_column: 141,
                section_index: 2,
                section_column: 0,
                column_variables: 26,
            }
        );
        assert_eq!(
            production_trace_bank_column_v1(3, 0),
            Err(ProductionWhirCandidateError::InvalidTraceColumn)
        );
        assert_eq!(
            production_trace_bank_column_v1(0, 110),
            Err(ProductionWhirCandidateError::InvalidTraceColumn)
        );
        assert_eq!(
            production_trace_terminal_column_v1(),
            ProductionTraceColumnV1 {
                semantic_column: 339,
                section_index: 9,
                section_column: 10,
                column_variables: 26,
            }
        );
        assert_ne!(production_trace_layout_digest_v1(), [0; 32]);
        assert_ne!(production_trace_padding_digest_v1(), [0; 32]);
        assert_ne!(
            production_trace_layout_digest_v1(),
            production_trace_padding_digest_v1()
        );

        let section_roots = std::array::from_fn(|index| [index as u8 + 1; 32]);
        let trace_root = production_trace_commitment_root_v1(&section_roots).unwrap();
        let mut reordered = section_roots;
        reordered.swap(1, 2);
        assert_ne!(
            trace_root,
            production_trace_commitment_root_v1(&reordered).unwrap()
        );
        let terminal = production_trace_terminal_column_v1();
        assert_ne!(
            production_trace_column_alias_v1(
                section_roots[terminal.section_index as usize],
                terminal,
            ),
            production_trace_column_alias_v1(
                section_roots[terminal.section_index as usize],
                production_trace_bank_column_v1(2, 11).unwrap(),
            )
        );
    }

    #[test]
    fn production_trace_batch_budget_rejects_both_direct_layouts() {
        let budget = production_trace_batch_wire_budget_v1().unwrap();
        assert_eq!(budget.selector_variables, 9);
        assert_eq!(budget.semantic_columns, 439);
        assert_eq!(budget.padded_columns, 512);
        assert_eq!(budget.canonical_zero_columns, 73);
        assert_eq!(budget.local_variables, 26);
        assert_eq!(budget.stacked_variables, 35);
        assert_eq!(budget.first_round_queries, 309);
        assert_eq!(budget.local_fold_width, 4);
        assert_eq!(budget.selector_first_semantic_values_per_query, 439);
        assert_eq!(budget.selector_first_padded_values_per_query, 512);
        assert_eq!(budget.selector_first_semantic_value_bytes, 1_085_208);
        assert_eq!(budget.selector_first_padded_value_bytes, 1_265_664);
        assert_eq!(budget.local_first_semantic_values_per_query, 1_756);
        assert_eq!(budget.local_first_padded_values_per_query, 2_048);
        assert_eq!(budget.local_first_semantic_value_bytes, 4_340_832);
        assert_eq!(budget.local_first_padded_value_bytes, 5_062_656);
        assert_eq!(budget.independent_section_floor_bytes, 3_365_110);
        assert_eq!(budget.available_native_bytes, 262_128);
        assert!(budget.direct_wide_row_cannot_fit());
        assert!(budget.independent_sections_cannot_fit());
    }

    #[test]
    fn production_trace_selector_fold_matches_multilinear_evaluation() {
        let selector_point = (0..PRODUCTION_TRACE_BATCH_SELECTOR_VARIABLES)
            .map(|index| ExtensionElement {
                limbs: [
                    (index + 2) as u64,
                    (2 * index + 3) as u64,
                    (3 * index + 5) as u64,
                ],
            })
            .collect::<Vec<_>>();
        let semantic_values = (0..PRODUCTION_TRACE_SEMANTIC_COLUMNS)
            .map(|index| ExtensionElement {
                limbs: [
                    (index + 11) as u64,
                    (2 * index + 13) as u64,
                    (3 * index + 17) as u64,
                ],
            })
            .collect::<Vec<_>>();
        let folded = production_trace_fold_row_v1(17, &semantic_values, &selector_point).unwrap();

        let mut padded = semantic_values
            .iter()
            .copied()
            .map(convert_extension)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        padded.resize(PRODUCTION_TRACE_BATCH_PADDED_COLUMNS, EF::ZERO);
        let point = Point::new(
            selector_point
                .iter()
                .copied()
                .map(convert_extension)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
        );
        let expected = Poly::<EF>::new(padded).eval_ext::<F>(&point);
        assert_eq!(convert_extension(folded).unwrap(), expected);

        let mut noncanonical = semantic_values.clone();
        noncanonical[0].limbs[0] = crate::GOLDILOCKS_MODULUS;
        assert_eq!(
            production_trace_fold_row_v1(17, &noncanonical, &selector_point),
            Err(ProductionWhirCandidateError::InvalidEncoding)
        );
        assert_eq!(
            production_trace_fold_row_v1(17, &semantic_values[..438], &selector_point),
            Err(ProductionWhirCandidateError::InvalidTraceRow)
        );
        assert_eq!(
            production_trace_fold_row_v1(17, &semantic_values, &selector_point[..8]),
            Err(ProductionWhirCandidateError::InvalidOpeningPoint)
        );

        let high_row = 1_u64 << PRODUCTION_TRACE_INITIALIZATION_VARIABLES;
        assert_eq!(
            production_trace_fold_row_v1(high_row, &semantic_values, &selector_point),
            Err(ProductionWhirCandidateError::InvalidTraceRow)
        );
        let mut padded_initialization = semantic_values;
        padded_initialization[..PRODUCTION_TRACE_INITIALIZATION_COLUMNS]
            .fill(ExtensionElement { limbs: [0; 3] });
        assert!(
            production_trace_fold_row_v1(high_row, &padded_initialization, &selector_point).is_ok()
        );
    }

    #[test]
    fn selector_sumcheck_continues_into_one_verified_whir_proof() {
        const LOCAL_VARIABLES: usize = 3;
        const SELECTOR_VARIABLES: usize = 2;
        const STACKED_VARIABLES: usize = LOCAL_VARIABLES + SELECTOR_VARIABLES;
        const COLUMNS: usize = 1 << SELECTOR_VARIABLES;
        const BINDING: &[u8] = b"production-selector-batch-reference-v1";

        type SelectorPcs = WhirProver<EF, F, Dft, WhirMmcs, Challenger, PrefixProver<F, EF>>;

        let columns = (0..COLUMNS)
            .map(|column| {
                Poly::<F>::new(
                    (0..1_usize << LOCAL_VARIABLES)
                        .map(|row| F::from_u64((column * 101 + row * row + 7 * row + 19) as u64))
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let stacked = Poly::<F>::new(
            columns
                .iter()
                .flat_map(|column| column.as_slice().iter().copied())
                .collect(),
        );

        let (ordinary, mut prover_challenger) = build_pcs(STACKED_VARIABLES, BINDING).unwrap();
        assert_eq!(ordinary.round_folding_factor(0), SELECTOR_VARIABLES);
        let pcs = SelectorPcs::new(ordinary.config, ordinary.dft, ordinary.mmcs);
        let (commitment, prover_data) = commit_base(
            VariableOrder::Prefix,
            &pcs.dft,
            &pcs.mmcs,
            &mut prover_challenger,
            &stacked,
            SELECTOR_VARIABLES,
            pcs.starting_log_inv_rate,
        );

        let mut statement = EqStatement::initialize(STACKED_VARIABLES);
        let mut evaluations = Vec::with_capacity(COLUMNS);
        for (column, poly) in columns.iter().enumerate() {
            let local_point = Point::expand_from_univariate(
                prover_challenger.sample_algebra_element(),
                LOCAL_VARIABLES,
            );
            let evaluation = poly.eval_base(&local_point);
            let mut lifted = Point::<F>::hypercube(column, SELECTOR_VARIABLES)
                .as_slice()
                .iter()
                .copied()
                .map(EF::from)
                .collect::<Vec<_>>();
            lifted.extend_from_slice(local_point.as_slice());
            let lifted = Point::new(lifted);
            prover_challenger.observe_algebra_slice(lifted.as_slice());
            prover_challenger.observe_algebra_element(evaluation);
            statement.add_evaluated_constraint(lifted, evaluation);
            evaluations.push(evaluation);
        }

        let alpha = prover_challenger.sample_algebra_element();
        let mut weights = Poly::<EF>::zero(STACKED_VARIABLES);
        let mut claimed_sum = EF::ZERO;
        statement.combine_hypercube::<F, false>(&mut weights, &mut claimed_sum, alpha);
        let extension_stacked = Poly::<EF>::new(stacked.iter().copied().map(EF::from).collect());
        let product =
            ProductPolynomial::new_unpacked(VariableOrder::Prefix, extension_stacked, weights);
        let mut sumcheck_prover = SumcheckProver::new(product, claimed_sum);
        let mut proof = empty_proof_for(&pcs.config);
        let selector_randomness = sumcheck_prover.compute_sumcheck_polynomials(
            &mut proof.initial_sumcheck,
            &mut prover_challenger,
            SELECTOR_VARIABLES,
            pcs.starting_folding_pow_bits,
            None,
        );
        assert_eq!(sumcheck_prover.num_variables(), LOCAL_VARIABLES);

        let expected_residual = (0..1_usize << LOCAL_VARIABLES)
            .map(|row| {
                Poly::<F>::new(
                    columns
                        .iter()
                        .map(|column| column.as_slice()[row])
                        .collect(),
                )
                .eval_base(&selector_randomness)
            })
            .collect::<Vec<_>>();
        assert_eq!(sumcheck_prover.evals().as_slice(), expected_residual);

        pcs.prove_from_sumcheck(
            &mut proof,
            &mut prover_challenger,
            sumcheck_prover,
            selector_randomness,
            prover_data,
        );

        let verify = |binding: &[u8], columns: &[usize], evaluations: &[EF]| {
            let (verifier_pcs, mut challenger) = build_pcs(STACKED_VARIABLES, binding).unwrap();
            challenger.observe(commitment.clone());
            let mut statement = EqStatement::initialize(STACKED_VARIABLES);
            for (&column, &evaluation) in columns.iter().zip(evaluations) {
                let local_point = Point::expand_from_univariate(
                    challenger.sample_algebra_element(),
                    LOCAL_VARIABLES,
                );
                let mut lifted = Point::<F>::hypercube(column, SELECTOR_VARIABLES)
                    .as_slice()
                    .iter()
                    .copied()
                    .map(EF::from)
                    .collect::<Vec<_>>();
                lifted.extend_from_slice(local_point.as_slice());
                let lifted = Point::new(lifted);
                challenger.observe_algebra_slice(lifted.as_slice());
                challenger.observe_algebra_element(evaluation);
                statement.add_evaluated_constraint(lifted, evaluation);
            }
            let alpha = challenger.sample_algebra_element();
            let constraint = Constraint::new_eq_only(alpha, statement);
            let mut claimed_sum = EF::ZERO;
            constraint.combine_evals(&mut claimed_sum);
            WhirVerifier::new(
                &verifier_pcs.config,
                &verifier_pcs.mmcs,
                VariableOrder::Prefix,
            )
            .verify(
                &proof,
                &mut challenger,
                &commitment,
                constraint,
                claimed_sum,
            )
            .is_ok()
        };

        let canonical_columns = [0, 1, 2, 3];
        assert!(verify(BINDING, &canonical_columns, &evaluations));

        let mut substituted = evaluations.clone();
        substituted[2] += EF::ONE;
        assert!(!verify(BINDING, &canonical_columns, &substituted));
        assert!(!verify(BINDING, &[1, 0, 2, 3], &evaluations));
        assert!(!verify(BINDING, &canonical_columns[..3], &evaluations[..3]));
        assert!(!verify(
            b"production-selector-batch-reference-replay",
            &canonical_columns,
            &evaluations,
        ));
    }

    #[test]
    fn commitment_derived_work_binding_binds_the_sealed_candidate_identity() {
        let model = production_model();
        assert_eq!(
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0; 32]),
            Err(ProductionWhirCandidateError::UncommittedBatchedModel)
        );
        let trusted =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x61; 32])
                .unwrap();
        assert_ne!(
            trusted.proof_suite_digest(),
            production_whir_suite_parameter_digest_v1()
        );
        let challenge = ProductionCommitmentChallengeV1::from_test_parts([0x11; 32], [0x7f; 32]);
        assert_eq!(
            VerifiedProductionTraceV1::from_verified_sections(
                trusted.digest(),
                challenge.challenge_digest(),
                [[0; 32]; PRODUCTION_TRACE_SECTION_COUNT],
                &[],
            ),
            Err(ProductionWhirCandidateError::UncommittedTrace)
        );
        let mut incomplete_sections = [[0x62; 32]; PRODUCTION_TRACE_SECTION_COUNT];
        incomplete_sections[3] = [0; 32];
        assert_eq!(
            VerifiedProductionTraceV1::from_verified_sections(
                trusted.digest(),
                challenge.challenge_digest(),
                incomplete_sections,
                &[],
            ),
            Err(ProductionWhirCandidateError::UncommittedTrace)
        );

        let exact_sections = trace_section_roots([0x62; 32], [0x71; 32]);
        let exact_commitments = production_trace_column_commitments_v1(&exact_sections).unwrap();
        assert_eq!(exact_commitments.len(), PRODUCTION_TRACE_SEMANTIC_COLUMNS);
        let mut reordered_commitments = exact_commitments.clone();
        reordered_commitments.swap(0, 1);
        assert_eq!(
            VerifiedProductionTraceV1::from_verified_sections(
                trusted.digest(),
                challenge.challenge_digest(),
                exact_sections,
                &reordered_commitments,
            ),
            Err(ProductionWhirCandidateError::TraceCommitmentMismatch)
        );
        let mut substituted_terminal = exact_commitments.clone();
        substituted_terminal[production_trace_terminal_column_v1().semantic_column as usize][0] ^=
            1;
        assert_eq!(
            VerifiedProductionTraceV1::from_verified_sections(
                trusted.digest(),
                challenge.challenge_digest(),
                exact_sections,
                &substituted_terminal,
            ),
            Err(ProductionWhirCandidateError::TraceCommitmentMismatch)
        );
        assert_eq!(
            VerifiedProductionTraceV1::from_verified_sections(
                trusted.digest(),
                challenge.challenge_digest(),
                exact_sections,
                &exact_commitments[..exact_commitments.len() - 1],
            ),
            Err(ProductionWhirCandidateError::TraceCommitmentMismatch)
        );

        let trace = verified_trace(&trusted, challenge, [0x62; 32], [0x71; 32]);
        assert_eq!(
            trace.trace_layout_digest,
            production_trace_layout_digest_v1()
        );
        assert_eq!(
            trace.canonical_padding_digest,
            production_trace_padding_digest_v1()
        );
        assert_eq!(
            trace.trace_section_count,
            PRODUCTION_TRACE_SECTION_COUNT as u32
        );
        assert_eq!(
            trace.terminal_section_index,
            PRODUCTION_TRACE_TERMINAL_SECTION as u32
        );
        assert_eq!(
            trace.terminal_column_index,
            PRODUCTION_TRACE_TERMINAL_COLUMN as u32
        );
        let binding =
            ProductionCommitmentWorkBindingV1::derive(challenge, &trusted, &trace).unwrap();
        let different_challenge =
            ProductionCommitmentChallengeV1::from_test_parts([0x12; 32], [0x7f; 32]);
        assert_eq!(
            ProductionCommitmentWorkBindingV1::derive(different_challenge, &trusted, &trace),
            Err(ProductionWhirCandidateError::VerifiedTraceContextMismatch)
        );
        let different_challenge_trace =
            verified_trace(&trusted, different_challenge, [0x62; 32], [0x71; 32]);
        let different_challenge_binding = ProductionCommitmentWorkBindingV1::derive(
            different_challenge,
            &trusted,
            &different_challenge_trace,
        )
        .unwrap();
        assert_ne!(
            binding.proof_commitment_root,
            different_challenge_binding.proof_commitment_root
        );
        assert_ne!(binding.work_digest, different_challenge_binding.work_digest);
        assert_ne!(
            binding.public_binding,
            different_challenge_binding.public_binding
        );

        let different_target = ProductionCommitmentWorkBindingV1::derive(
            ProductionCommitmentChallengeV1::from_test_parts([0x11; 32], [0x7e; 32]),
            &trusted,
            &trace,
        )
        .unwrap();
        assert_eq!(binding.work_digest, different_target.work_digest);
        assert_ne!(binding.public_binding, different_target.public_binding);

        let different_trace = ProductionCommitmentWorkBindingV1::derive(
            challenge,
            &trusted,
            &verified_trace(&trusted, challenge, [0x65; 32], [0x71; 32]),
        )
        .unwrap();
        assert_ne!(
            binding.proof_commitment_root,
            different_trace.proof_commitment_root
        );
        assert_ne!(binding.work_digest, different_trace.work_digest);

        let mut wrong_layout = trace;
        wrong_layout.trace_layout_digest[0] ^= 1;
        let mut wrong_padding = trace;
        wrong_padding.canonical_padding_digest[0] ^= 1;
        let mut wrong_section_count = trace;
        wrong_section_count.trace_section_count += 1;
        let mut wrong_terminal = trace;
        wrong_terminal.terminal_column_index += 1;
        for different_identity in [
            wrong_layout,
            wrong_padding,
            wrong_section_count,
            wrong_terminal,
        ] {
            let different =
                ProductionCommitmentWorkBindingV1::derive(challenge, &trusted, &different_identity)
                    .unwrap();
            assert_ne!(
                binding.proof_commitment_root,
                different.proof_commitment_root
            );
            assert_ne!(binding.work_digest, different.work_digest);
        }

        let different_output = ProductionCommitmentWorkBindingV1::derive(
            challenge,
            &trusted,
            &verified_trace(&trusted, challenge, [0x62; 32], [0x72; 32]),
        )
        .unwrap();
        assert_ne!(
            binding.proof_commitment_root,
            different_output.proof_commitment_root
        );
        assert_ne!(binding.work_digest, different_output.work_digest);

        let different_model =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x64; 32])
                .unwrap();
        assert_eq!(
            ProductionCommitmentWorkBindingV1::derive(challenge, &different_model, &trace),
            Err(ProductionWhirCandidateError::VerifiedTraceContextMismatch)
        );
        let different_model_trace =
            verified_trace(&different_model, challenge, [0x62; 32], [0x71; 32]);
        let different_model_binding = ProductionCommitmentWorkBindingV1::derive(
            challenge,
            &different_model,
            &different_model_trace,
        )
        .unwrap();
        assert_ne!(
            binding.proof_commitment_root,
            different_model_binding.proof_commitment_root
        );
        assert_ne!(binding.work_digest, different_model_binding.work_digest);

        assert_eq!(
            hex::encode(production_proof_binding_suite_digest_v1()),
            "3901c9569e563768fe3246126aff67ab67aeeab7f45f265677bb534b05c91141"
        );
        assert_eq!(
            hex::encode(trusted.digest()),
            "b75271070a010414ba70d5935e883dd29be3ccbb506a9d4a4a848535f2d20d9f"
        );
        assert_eq!(
            hex::encode(binding.proof_commitment_root.as_bytes()),
            "27af7650a99357aeea43b2169d33606caf1735ce9faf2d5ca4389c5e954ca0b7"
        );
        assert_eq!(
            hex::encode(binding.work_digest),
            "96bcd8b3c377b4e8ca1d9f163eaa2de59d53c47e1850a86161395e41c31c88cf"
        );
        assert_eq!(
            hex::encode(binding.public_binding),
            "97c84266d09f14583c9d84f274033be8b03fd978c97e97773943d95704fa6e69"
        );
    }

    #[test]
    fn commitment_claim_verifier_rederives_roots_work_and_target() {
        let model = production_model();
        let trusted =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x61; 32])
                .unwrap();
        let challenge_digest = [0x11; 32];
        let target = [0xff; 32];
        let challenge = ProductionCommitmentChallengeV1::from_test_parts(challenge_digest, target);
        let trace = verified_trace(&trusted, challenge, [0x62; 32], [0x71; 32]);
        let expected =
            ProductionCommitmentWorkBindingV1::derive(challenge, &trusted, &trace).unwrap();
        let claims = expected.claims();
        verify_production_commitment_claims_v1(challenge, &trusted, &trace, &claims).unwrap();

        let mut wrong_root = claims;
        wrong_root.proof_commitment_root[0] ^= 1;
        assert_eq!(
            verify_production_commitment_claims_v1(challenge, &trusted, &trace, &wrong_root),
            Err(ProductionWhirCandidateError::ProofCommitmentMismatch)
        );

        let mut wrong_work = claims;
        wrong_work.work_digest[0] ^= 1;
        assert_eq!(
            verify_production_commitment_claims_v1(challenge, &trusted, &trace, &wrong_work),
            Err(ProductionWhirCandidateError::WorkDigestMismatch)
        );

        let mut wrong_binding = claims;
        wrong_binding.public_binding[0] ^= 1;
        assert_eq!(
            verify_production_commitment_claims_v1(challenge, &trusted, &trace, &wrong_binding,),
            Err(ProductionWhirCandidateError::PublicBindingMismatch)
        );
        let different_trace = verified_trace(&trusted, challenge, [0x65; 32], [0x71; 32]);
        assert_eq!(
            verify_production_commitment_claims_v1(challenge, &trusted, &different_trace, &claims,),
            Err(ProductionWhirCandidateError::ProofCommitmentMismatch)
        );

        let hard_target = [0; 32];
        let hard_challenge =
            ProductionCommitmentChallengeV1::from_test_parts(challenge_digest, hard_target);
        let high_hash = ProductionCommitmentWorkBindingV1::derive(hard_challenge, &trusted, &trace)
            .unwrap()
            .claims();
        assert_eq!(
            verify_production_commitment_claims_v1(hard_challenge, &trusted, &trace, &high_hash,),
            Err(ProductionWhirCandidateError::HighHash)
        );
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    fn prepared_role_binding_rejects_role_and_context_substitution() {
        let model = production_model();
        let config =
            ProductionWhirConfigV1::for_model_role(&model, ModelPcsRole::BaseInput).unwrap();
        let context_digest =
            crate::model_whir_role_context_digest(&model, ModelPcsRole::BaseInput).unwrap();
        let mut binding = PreparedProductionWhirBindingV1 {
            role: ModelPcsRole::BaseInput,
            expected_commitment: model.base_input_commitment,
            source_num_variables: PRODUCTION_WHIR_BASE_VARIABLES as u32,
            source_element_count: 1_u64 << PRODUCTION_WHIR_BASE_VARIABLES,
            context_digest,
            oracle_context_digest: context_digest,
            oracle_source_matches: true,
        };
        assert!(validate_prepared_production_whir_binding_v1(&config, &model, &binding).is_ok());

        binding.role = ModelPcsRole::WeightBank { index: 0 };
        binding.expected_commitment = model.weight_bank_commitments[0];
        assert_eq!(
            validate_prepared_production_whir_binding_v1(&config, &model, &binding),
            Err(ProductionWhirCandidateError::PreparedRoleMismatch)
        );

        binding.role = ModelPcsRole::BaseInput;
        binding.expected_commitment = model.base_input_commitment;
        binding.context_digest[0] ^= 1;
        assert_eq!(
            validate_prepared_production_whir_binding_v1(&config, &model, &binding),
            Err(ProductionWhirCandidateError::PreparedContextMismatch)
        );
    }
}
