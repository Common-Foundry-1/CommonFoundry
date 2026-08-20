pub mod chain;
pub mod difficulty;
pub mod economics;
pub mod forgematrix;
pub mod forgematrix_v2;
pub mod model_bank;
pub mod network;
pub mod pow;
#[cfg(feature = "remainder-prototype")]
pub mod remainder_proof;
#[cfg(feature = "whir-prototype")]
pub mod structured_blake3;
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
    BuiltModelBankFixture, MAX_MODEL_BYTE, MAX_SMALL_FIXTURE_PAYLOAD_BYTES,
    MODEL_BANK_FORMAT_VERSION, MODEL_BANK_HEADER_BYTES, MODEL_BANK_MAGIC, ModelBankError,
    ModelBankManifest, SmallModelBankFixture, build_small_model_bank, verify_model_bank,
};
pub use network::{
    BlockValidationContext, CONSENSUS_SIGNATURE_BYTES, FixedRewardDestinations,
    MAX_BLOCK_AGGREGATE_INPUTS, MAX_BLOCK_AGGREGATE_OUTPUTS, MAX_BLOCK_SIGNATURE_CHECKS,
    MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS, MAX_FUTURE_OFFSET_SECS, MAX_TRANSACTION_INPUTS,
    MAX_TRANSACTION_OUTPUTS, MEDIAN_TIME_WINDOW, NETWORK_PROTOCOL_VERSION, NetworkError,
    NetworkParams,
};
pub use pow::{
    BlockProof, ConsensusPowVerifier, POW_TYPE_V1_LEGACY, POW_TYPE_V2_REFERENCE, PowError,
    PowParameters,
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
pub use structured_proof::{
    MAX_STRUCTURED_AGGREGATE_PROOF_BYTES, MAX_STRUCTURED_BLAKE3_PROOF_BYTES,
    MAX_STRUCTURED_FINAL_ACTIVATION_BYTES, MAX_STRUCTURED_OPENING_CLAIMS,
    MAX_STRUCTURED_OPENING_VARIABLES, MAX_STRUCTURED_PCS_PROOF_BYTES, STRUCTURED_AGGREGATE_VERSION,
    StructuredBlake3Statement, StructuredBlake3Verifier, StructuredForgeMatrixProof,
    StructuredForgeMatrixStatement, StructuredPcsOpeningClaim, StructuredPcsVerifier,
    StructuredProofError, collect_structured_forgematrix_openings,
    structured_forgematrix_public_binding, verify_structured_forgematrix_proof,
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
    STRUCTURED_TRANSITION_ORACLES, STRUCTURED_TRANSITION_VERSION, StructuredMaskPolynomial,
    StructuredTransitionError, StructuredTransitionOpeningClaims, StructuredTransitionProof,
    StructuredTransitionRound, StructuredTransitionStatement, StructuredTransitionWitness,
    prove_structured_transition, verify_structured_transition,
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
#[cfg(feature = "whir-prototype")]
pub use whir_proof::{
    EXPLICIT_WHIR_SECURITY_BITS, EXPLICIT_WHIR_VERSION, ExplicitWhirCommitment, ExplicitWhirError,
    ExplicitWhirOpening, ExplicitWhirProof, MAX_EXPLICIT_WHIR_BINDING_BYTES,
    MAX_EXPLICIT_WHIR_OPENINGS, MAX_EXPLICIT_WHIR_PROOF_BYTES, MAX_EXPLICIT_WHIR_VARIABLES,
    MAX_STRUCTURED_WHIR_ELEMENTS, MAX_STRUCTURED_WHIR_TABLES, StructuredWhirCommitmentSet,
    StructuredWhirPcsVerifier, prove_explicit_whir_openings, prove_structured_whir_openings,
    verify_explicit_whir_openings, verify_structured_whir_openings,
};
pub use wire::{
    BLOCK_KIND, FORGEMATRIX_PROOF_KIND, FORGEMATRIX_V1_PROOF_TAG, FORGEMATRIX_V2_PROOF_TAG,
    MAX_BLOCK_BYTES, MAX_PROOF_BYTES, MAX_TRANSACTION_BYTES, TRANSACTION_KIND, WIRE_HEADER_BYTES,
    WIRE_VERSION, WireError, decode_block, decode_forgematrix_proof, decode_transaction,
    encode_block, encode_forgematrix_proof, encode_transaction, network_magic,
};
