pub mod chain;
pub mod difficulty;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_aggregate;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_blake3;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_candidate;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_compact_artifact;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_execution_artifact;
#[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
mod dory_bls12_381_execution_provider;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_fold_artifact;
#[cfg(all(feature = "dory-bls12-381-prototype", test))]
pub mod dory_bls12_381_index_artifact;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_layout;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_logup;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_logup_artifact;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_matrix;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_model_commitment;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_output_bridge;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_prototype;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_soundness;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_streaming;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_transition;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_transpose;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_bls12_381_wiring;
#[cfg(all(test, feature = "dory-opening-prototype"))]
mod dory_field_portability;
#[cfg(feature = "dory-opening-prototype")]
pub mod dory_opening_prototype;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_v3_model;
#[cfg(feature = "dory-bls12-381-prototype")]
pub mod dory_v3_suite;
pub mod economics;
pub mod forgematrix;
pub mod forgematrix_v2;
pub mod model_bank;
#[cfg(feature = "gpu-proof-prover")]
pub mod model_whir_sources;
pub mod network;
pub mod pow;
#[cfg(all(test, feature = "production-whir-candidate"))]
mod production_range_lookup_prototype;
#[cfg(feature = "remainder-prototype")]
pub mod remainder_proof;
#[cfg(feature = "whir-prototype")]
pub mod structured_blake3;
mod structured_blake3_identity;
#[cfg(feature = "whir-prototype")]
mod structured_blake3_narrow;
#[cfg(feature = "whir-prototype")]
mod structured_blake3_tree;
#[cfg(all(test, feature = "whir-prototype"))]
mod structured_lookup_prototype;
pub mod structured_proof;
pub mod structured_sumcheck;
pub mod structured_transition;
pub mod structured_wiring;
pub mod sumcheck;
#[cfg(feature = "whir-prototype")]
pub mod whir_proof;
pub mod wire;

pub use chain::{
    BLOCK_VERSION, Block, COINBASE_MATURITY, ChainError, ChainState, Coinbase, InputWitness,
    OutPoint, OutputLock, TRANSACTION_VERSION, Transaction, TransactionSetValidation, TxInput,
    TxOutput, UtxoSet, merkle_root, validate_block_resources,
};
pub use difficulty::{
    DGW_WINDOW, DifficultyError, HeaderWork, TARGET_SPACING_SECONDS, add_chain_work, block_work,
    chain_work_bytes, next_work_target,
};
#[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
pub use dory_bls12_381_execution_provider::{
    BlsDoryWinningNonceClaim, BlsDoryWinningNonceReplayError, VerifiedBlsDoryWinningNonceExecution,
};
pub use economics::{
    Allocation, BLOCKS_PER_365_DAY_YEAR, COIN, CoinbaseClaim, DEFAULT_MONETARY_POLICY,
    EconomicsError, INITIAL_EMISSION_BLOCKS, INITIAL_EMISSION_YEARS, MonetaryPolicy,
};
pub use forgematrix::{
    BlockChallenge, ForgeMatrixError, ForgeMatrixProfile, ForgeMatrixProof, ForgeMatrixVerifier,
    ProfileMetrics, TEST_PROFILE,
};
pub use forgematrix_v2::{
    FORGEMATRIX_V2_ALGORITHM_VERSION, FORGEMATRIX_V2_PROOF_VERSION, ForgeMatrixV2AcceleratorBatch,
    ForgeMatrixV2AcceleratorModel, ForgeMatrixV2CompactProof, ForgeMatrixV2Descriptor,
    ForgeMatrixV2Error, ForgeMatrixV2Reference, ForgeMatrixV2ReferenceProof, LayerWitness,
    PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
    PRODUCTION_V2_LAYERS_PER_BANK, ReductionWitness, V2_ACCELERATOR_MAX_BATCH,
    V2_REFERENCE_MAX_BATCH, V2_REFERENCE_MAX_DIMENSION, V2_REFERENCE_MAX_LAYERS, V2_TEST_BATCH,
    V2_TEST_DIMENSION, V2_TEST_LAYERS, V2_TRANSITION_MODULUS, v2_test_reference,
};
pub use model_bank::{
    BuiltModelBankFixture, MAX_MODEL_BYTE, MAX_MODEL_PCS_WEIGHT_BANKS,
    MAX_SMALL_FIXTURE_PAYLOAD_BYTES, MODEL_BANK_FORMAT_VERSION, MODEL_BANK_HEADER_BYTES,
    MODEL_BANK_MAGIC, MODEL_FIELD_CHUNK_ELEMENTS, MODEL_PCS_BASE_INPUT_AXIS_ORDER,
    MODEL_PCS_IDENTITY_VERSION, MODEL_PCS_VALUE_ENCODING, MODEL_PCS_WEIGHT_BANK_AXIS_ORDER,
    ModelBankError, ModelBankFieldStreamError, ModelBankManifest, ModelFieldChunk,
    ModelPcsIdentity, ModelPcsRole, ModelPcsRoleLayout, SmallModelBankFixture,
    StagedModelFieldSink, VerifiedModelBankReceipt, build_small_model_bank, verify_model_bank,
    verify_model_bank_into_staged_field_sink,
};
#[cfg(feature = "gpu-proof-prover")]
pub use model_whir_sources::{
    MODEL_WHIR_SOURCE_BUNDLE_IDENTITY_BYTES, ModelWhirSourceBundleIdentity, ModelWhirSourceError,
    PreparedModelWhirRoleV2, PublishedModelWhirSourceBundle, PublishedModelWhirSourceRole,
    adopt_published_model_whir_role_v2, build_verified_model_whir_sources,
    model_whir_role_context_digest, open_published_model_whir_sources,
};
pub use network::{
    BlockValidationContext, CONSENSUS_SIGNATURE_BYTES, FixedRewardDestinations,
    MAX_BLOCK_AGGREGATE_INPUTS, MAX_BLOCK_AGGREGATE_OUTPUTS, MAX_BLOCK_SIGNATURE_CHECKS,
    MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS, MAX_FUTURE_OFFSET_SECS, MAX_TRANSACTION_INPUTS,
    MAX_TRANSACTION_OUTPUTS, MEDIAN_TIME_WINDOW, NETWORK_PROTOCOL_VERSION, NetworkError,
    NetworkParams,
};
pub use pow::{
    BlockProof, ConsensusPowVerifier, ExternalPreverificationBinding, ForgeMatrixV3CandidateProof,
    POW_TYPE_V1_LEGACY, POW_TYPE_V2_REFERENCE, POW_TYPE_V3_CANDIDATE, PowError, PowParameters,
    PreverifiedBlockProof,
};
#[cfg(feature = "remainder-prototype")]
pub use remainder_proof::{
    ForgeMatrixV2RemainderProof, MAX_REMAINDER_PROTOTYPE_PROOF_BYTES, REMAINDER_BACKEND_REVISION,
    REMAINDER_PROTOTYPE_VERSION, RemainderPrototypeError, prove_remainder_prototype,
    verify_remainder_prototype,
};
#[cfg(feature = "whir-prototype")]
pub use structured_blake3::{
    STRUCTURED_BLAKE3_VERSION, StructuredBlake3Error, StructuredBlake3StarkVerifier,
    prove_structured_blake3, verify_structured_blake3,
};
#[cfg(feature = "gpu-proof-prover")]
pub use structured_blake3::{
    prove_structured_blake3_with_cuda, prove_structured_blake3_with_cuda_in_spill_dir,
};
pub use structured_proof::{
    MAX_STRUCTURED_AGGREGATE_PROOF_BYTES, MAX_STRUCTURED_BLAKE3_PROOF_BYTES,
    MAX_STRUCTURED_FINAL_ACTIVATION_BYTES, MAX_STRUCTURED_OPENING_CLAIMS,
    MAX_STRUCTURED_OPENING_VARIABLES, MAX_STRUCTURED_PCS_PROOF_BYTES, STRUCTURED_AGGREGATE_VERSION,
    STRUCTURED_BATCHED_PRODUCTION_COMPONENT_FLOOR_BYTES,
    STRUCTURED_BATCHED_PRODUCTION_MODEL_NATIVE_BYTES, STRUCTURED_BATCHED_PRODUCTION_PCS_BYTES,
    STRUCTURED_BATCHED_PRODUCTION_SPLIT_PCS_FIXED_BYTES,
    STRUCTURED_PRODUCTION_AGGREGATE_LENGTH_BYTES, STRUCTURED_PRODUCTION_COMPONENT_FLOOR_BYTES,
    STRUCTURED_PRODUCTION_FRAME_BYTES, STRUCTURED_PRODUCTION_SHARED_ARGUMENT_BYTES,
    STRUCTURED_PRODUCTION_SPLIT_PCS_FIXED_BYTES, STRUCTURED_PRODUCTION_SPLIT_PCS_TRACE_TABLE_BYTES,
    STRUCTURED_PRODUCTION_SPLIT_V3_MAX_TRACE_TABLES, STRUCTURED_PRODUCTION_V2_WRAPPER_BYTES,
    StructuredBatchedProductionBudget, StructuredBlake3Statement, StructuredBlake3Verifier,
    StructuredForgeMatrixProof, StructuredForgeMatrixStatement, StructuredPcsOpeningClaim,
    StructuredPcsOpeningSet, StructuredPcsVerifier, StructuredProductionBudgetError,
    StructuredProductionProofUsage, StructuredProofError, StructuredSplitV3ProductionBudget,
    collect_structured_forgematrix_openings, structured_forgematrix_public_binding,
    verify_structured_forgematrix_proof,
};
pub use structured_sumcheck::{
    ExtensionElement, MAX_STRUCTURED_MATRIX_ELEMENTS, MAX_STRUCTURED_SUMCHECK_PROOF_BYTES,
    STRUCTURED_SUMCHECK_CHALLENGE_BITS, STRUCTURED_SUMCHECK_VERSION, StructuredMatrixOpeningClaims,
    StructuredMatrixProof, StructuredMatrixRound, StructuredMatrixStatement,
    StructuredSumcheckError, prove_structured_matrix_product, verify_structured_matrix_product,
    verify_structured_matrix_sumcheck,
};
#[cfg(feature = "whir-prototype")]
pub use structured_sumcheck::{
    prove_structured_matrix_product_with_commitments, structured_matrix_whir_tables,
};
pub use structured_transition::{
    MAX_STRUCTURED_TRANSITION_ELEMENTS, MAX_STRUCTURED_TRANSITION_PROOF_BYTES,
    STRUCTURED_TRANSITION_ACTIVATION_ORACLE, STRUCTURED_TRANSITION_CONSTRAINTS,
    STRUCTURED_TRANSITION_INPUT_ORACLE, STRUCTURED_TRANSITION_MAX_DEGREE,
    STRUCTURED_TRANSITION_ORACLES, STRUCTURED_TRANSITION_RANGE_DIGITS,
    STRUCTURED_TRANSITION_RANGE_DIGITS_PER_CELL, STRUCTURED_TRANSITION_RANGE_ORACLES,
    STRUCTURED_TRANSITION_RANGE_SPEC_COUNT, STRUCTURED_TRANSITION_REGULAR_ORACLES,
    STRUCTURED_TRANSITION_VERSION, StructuredMaskPolynomial, StructuredTransitionError,
    StructuredTransitionOpeningClaims, StructuredTransitionProof, StructuredTransitionRangeSpec,
    StructuredTransitionRound, StructuredTransitionStatement, StructuredTransitionWitness,
    prove_structured_transition, structured_transition_range_specs, verify_structured_transition,
    verify_structured_transition_sumcheck,
};
#[cfg(feature = "whir-prototype")]
pub use structured_transition::{
    prove_structured_transition_with_commitments, structured_transition_whir_tables,
};
pub use structured_wiring::{
    MAX_STRUCTURED_WIRING_BANKS, MAX_STRUCTURED_WIRING_ELEMENTS, MAX_STRUCTURED_WIRING_PROOF_BYTES,
    STRUCTURED_WIRING_VERSION, StructuredWiringError, StructuredWiringOpeningClaim,
    StructuredWiringOpeningClaims, StructuredWiringProof, StructuredWiringStatement,
    prove_structured_wiring, verify_structured_wiring,
    verify_structured_wiring_component_commitments, verify_structured_wiring_openings,
};
#[cfg(feature = "whir-prototype")]
pub use structured_wiring::{
    prove_structured_wiring_with_commitments, structured_wiring_whir_tables,
};
pub use sumcheck::{
    GOLDILOCKS_MODULUS, MAX_TOY_MATRIX_ELEMENTS, MatrixProductSumcheckProof, SumcheckError,
    TOY_SUMCHECK_RAW_CHALLENGE_BITS, prove_toy_matrix_product, reference_matrix_product,
    verify_toy_matrix_product,
};
#[cfg(all(feature = "production-whir-candidate", feature = "gpu-proof-prover"))]
pub use whir_proof::{
    BoundProductionWhirRoleV1, ProductionWhirBindFailure, bind_prepared_production_whir_role_v1,
};
#[cfg(feature = "whir-prototype")]
pub use whir_proof::{
    EXPLICIT_WHIR_SECURITY_BITS, EXPLICIT_WHIR_VERSION, ExplicitWhirCommitment, ExplicitWhirError,
    ExplicitWhirOpening, ExplicitWhirProof, MAX_EXPLICIT_WHIR_BINDING_BYTES,
    MAX_EXPLICIT_WHIR_OPENINGS, MAX_EXPLICIT_WHIR_PROOF_BYTES, MAX_EXPLICIT_WHIR_VARIABLES,
    MAX_STRUCTURED_WHIR_ELEMENTS, MAX_STRUCTURED_WHIR_TABLES, STRUCTURED_WHIR_SPLIT_VERSION,
    StructuredWhirCommitmentSet, StructuredWhirModelCommitmentSet, StructuredWhirModelMetadata,
    StructuredWhirPcsVerifier, VerifiedModelBankWhirError, prove_explicit_whir_openings,
    prove_structured_whir_openings, structured_whir_suite_parameter_digest,
    verify_explicit_whir_openings, verify_structured_whir_openings,
};
#[cfg(feature = "production-whir-candidate")]
pub use whir_proof::{
    PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES, PRODUCTION_BATCHED_MODEL_SLOTS,
    PRODUCTION_BATCHED_MODEL_VARIABLES, PRODUCTION_BATCHED_WHIR_MODEL_BYTES,
    PRODUCTION_FINAL_ACTIVATION_ELEMENTS, PRODUCTION_PROOF_BINDING_VERSION,
    PRODUCTION_TRACE_BANK_COLUMNS, PRODUCTION_TRACE_BANK_RANGE_VARIABLES,
    PRODUCTION_TRACE_BANK_SECTION_COLUMNS, PRODUCTION_TRACE_BANK_VARIABLES,
    PRODUCTION_TRACE_BATCH_LOCAL_VARIABLES, PRODUCTION_TRACE_BATCH_PADDED_COLUMNS,
    PRODUCTION_TRACE_BATCH_PADDING_COLUMNS, PRODUCTION_TRACE_BATCH_SELECTOR_VARIABLES,
    PRODUCTION_TRACE_COMPACT_LAYOUT_VERSION, PRODUCTION_TRACE_CORE_BANK_COLUMNS,
    PRODUCTION_TRACE_CORE_INITIALIZATION_COLUMNS, PRODUCTION_TRACE_CORE_PADDED_COLUMNS,
    PRODUCTION_TRACE_CORE_SELECTOR_VARIABLES, PRODUCTION_TRACE_CORE_SEMANTIC_COLUMNS,
    PRODUCTION_TRACE_INITIALIZATION_COLUMNS, PRODUCTION_TRACE_INITIALIZATION_RANGE_VARIABLES,
    PRODUCTION_TRACE_INITIALIZATION_VARIABLES, PRODUCTION_TRACE_JOHNSON_REFERENCE_GRINDING_BITS,
    PRODUCTION_TRACE_PACKED_BANK_LDE_VARIABLES, PRODUCTION_TRACE_PACKED_BANK_MAIN_COLUMNS,
    PRODUCTION_TRACE_PACKED_BANK_VARIABLES, PRODUCTION_TRACE_PACKED_COLUMN_BITS,
    PRODUCTION_TRACE_PACKED_COORDINATE_COLUMNS, PRODUCTION_TRACE_PACKED_DIGIT_COLUMNS,
    PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS, PRODUCTION_TRACE_PACKED_DIGITS_PER_LOOKUP,
    PRODUCTION_TRACE_PACKED_FRI_LOG_BLOWUP, PRODUCTION_TRACE_PACKED_FRI_LOG_FINAL_POLY_LEN,
    PRODUCTION_TRACE_PACKED_FRI_MAX_LOG_ARITY, PRODUCTION_TRACE_PACKED_FRI_QUERIES,
    PRODUCTION_TRACE_PACKED_INITIALIZATION_MAIN_COLUMNS,
    PRODUCTION_TRACE_PACKED_INITIALIZATION_VARIABLES, PRODUCTION_TRACE_PACKED_LAYER_BITS,
    PRODUCTION_TRACE_PACKED_LAYOUT_VERSION, PRODUCTION_TRACE_PACKED_MAIN_COLUMNS,
    PRODUCTION_TRACE_PACKED_PREPROCESSED_VERSION, PRODUCTION_TRACE_PACKED_PREPROCESSED_WIDTH,
    PRODUCTION_TRACE_PACKED_ROW_BITS, PRODUCTION_TRACE_PACKED_ROW_VARIABLES,
    PRODUCTION_TRACE_PACKED_ROWS_PER_CELL, PRODUCTION_TRACE_PACKED_SPEC_ROWS,
    PRODUCTION_TRACE_PACKED_TABLE_MULTIPLICITY_COLUMNS,
    PRODUCTION_TRACE_PRACTICAL_MAX_GRINDING_BITS, PRODUCTION_TRACE_RANGE_ACTIVE_ROWS_PER_CELL,
    PRODUCTION_TRACE_RANGE_AUXILIARY_COLUMNS, PRODUCTION_TRACE_RANGE_ROW_VARIABLES,
    PRODUCTION_TRACE_RANGE_ROWS_PER_CELL, PRODUCTION_TRACE_SECTION_COUNT,
    PRODUCTION_TRACE_SECTIONS_PER_BANK, PRODUCTION_TRACE_SEMANTIC_COLUMNS,
    PRODUCTION_TRACE_TERMINAL_COLUMN, PRODUCTION_TRACE_TERMINAL_SECTION,
    PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES, PRODUCTION_WHIR_BASE_VARIABLES,
    PRODUCTION_WHIR_CANDIDATE_VERSION, PRODUCTION_WHIR_WEIGHT_VARIABLES,
    ProductionBatchedModelIdentityV1, ProductionBatchedModelWhirConfigV1,
    ProductionCommitmentChallengeV1, ProductionCommitmentClaimsV1,
    ProductionCommitmentWorkBindingV1, ProductionProofCommitmentRootV1,
    ProductionTraceBatchWireBudgetV1, ProductionTraceColumnV1, ProductionTraceCompactLayoutV1,
    ProductionTracePackedComponentV2, ProductionTracePackedDigitSlotV2,
    ProductionTracePackedFriWireBudgetV2, ProductionTracePackedLayoutV2,
    ProductionTracePackedPreprocessedPlanV2, ProductionTracePackedPreprocessedRowV2,
    ProductionTracePackedRowV2, ProductionTraceRangeRowV1, ProductionTraceSectionV1,
    ProductionTraceWhirAssumptionBudgetV1, ProductionWhirCandidateError, ProductionWhirConfigV1,
    ProductionWhirRoleV1, ProductionWhirWireShapeV1, production_batched_model_lift_point_v1,
    production_batched_model_source_index_v1, production_proof_binding_suite_digest_v1,
    production_trace_bank_column_v1, production_trace_batch_wire_budget_v1,
    production_trace_column_alias_v1, production_trace_column_commitments_v1,
    production_trace_commitment_root_v1, production_trace_compact_layout_digest_v1,
    production_trace_compact_layout_v1, production_trace_core_columns_v1,
    production_trace_fold_row_v1, production_trace_initialization_column_v1,
    production_trace_layout_digest_v1, production_trace_packed_digit_slot_v2,
    production_trace_packed_fri_wire_budget_v2, production_trace_packed_layout_digest_v2,
    production_trace_packed_layout_v2, production_trace_packed_preprocessed_plan_digest_v2,
    production_trace_packed_preprocessed_plan_v2, production_trace_packed_preprocessed_row_v2,
    production_trace_packed_row_v2, production_trace_padding_digest_v1,
    production_trace_range_row_v1, production_trace_sections_v1,
    production_trace_terminal_column_v1, production_trace_whir_assumption_budget_v1,
    production_whir_suite_parameter_digest_v1,
};
#[cfg(feature = "gpu-proof-prover")]
pub use whir_proof::{
    prove_explicit_whir_openings_with_initial_oracle,
    prove_explicit_whir_openings_with_initial_source,
    prove_explicit_whir_openings_with_prover_oracle,
    prove_explicit_whir_openings_with_prover_oracle_in_spill_dir,
    prove_explicit_whir_openings_with_prover_oracle_v2,
    prove_explicit_whir_openings_with_prover_oracle_v2_in_spill_dir,
};
pub use wire::{
    BLOCK_KIND, FORGEMATRIX_PROOF_KIND, FORGEMATRIX_V1_PROOF_TAG, FORGEMATRIX_V2_PROOF_TAG,
    FORGEMATRIX_V3_CANDIDATE_PROOF_TAG, MAX_BLOCK_BYTES, MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
    MAX_PROOF_BYTES, MAX_TRANSACTION_BYTES, TRANSACTION_KIND, WIRE_HEADER_BYTES, WIRE_VERSION,
    WireError, decode_block, decode_forgematrix_proof, decode_transaction, encode_block,
    encode_forgematrix_proof, encode_transaction, network_magic,
};
