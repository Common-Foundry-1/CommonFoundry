//! Research-only WHIR polynomial-opening prototype.
//!
//! This module is deliberately feature-gated and bounded. It authenticates
//! evaluations at caller-supplied multilinear points under independent fixed
//! model-role commitments and a separate execution-trace commitment. It is not
//! wired into block validation and does not activate the production ForgeMatrix
//! profile.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
};

use blake3::Hasher as Blake3Hasher;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use p3_blake3::Blake3;
use p3_challenger::{
    CanObserve, FieldChallenger, GrindingChallenger, HashChallenger, SerializingChallenger64,
};
use p3_commit::Mmcs;
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::extension::CubicTrinomialExtensionField;
use p3_field::integers::QuotientMap;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::DenseMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::SumcheckData;
use p3_sumcheck::constraints::Constraint;
use p3_sumcheck::constraints::statement::EqStatement;
use p3_sumcheck::layout::{Layout, LayoutStrategy, Table, Witness};
use p3_sumcheck::product_polynomial::ProductPolynomial;
use p3_sumcheck::strategy::{SumcheckProver, VariableOrder};
use p3_symmetric::{CompressionFunctionFromHasher, MerkleCap, SerializingHasher};
use p3_whir::fiat_shamir::domain_separator::DomainSeparator;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir::pcs::proof::{WhirProof, WhirRoundProof};
use p3_whir::pcs::prover::WhirProver;
use p3_whir::pcs::verifier::WhirVerifier;
use thiserror::Error;

use crate::{
    ExtensionElement, GOLDILOCKS_MODULUS, StructuredPcsOpeningClaim, StructuredPcsOpeningSet,
    StructuredPcsVerifier,
    model_bank::{
        MAX_MODEL_PCS_WEIGHT_BANKS, MAX_SMALL_FIXTURE_PAYLOAD_BYTES, MODEL_BANK_HEADER_BYTES,
        ModelBankError, ModelBankManifest, ModelPcsIdentity, centered_model_field_element,
        verify_model_bank,
    },
};

pub const EXPLICIT_WHIR_VERSION: u32 = 1;
pub const STRUCTURED_WHIR_SPLIT_VERSION: u32 = 2;
pub const EXPLICIT_WHIR_SECURITY_BITS: usize = 128;
pub const MAX_EXPLICIT_WHIR_VARIABLES: usize = 16;
pub const MAX_EXPLICIT_WHIR_OPENINGS: usize = 64;
pub const MAX_EXPLICIT_WHIR_PROOF_BYTES: usize = 1_048_576;
pub const MAX_EXPLICIT_WHIR_BINDING_BYTES: usize = 4_096;
pub const MAX_STRUCTURED_WHIR_TABLES: usize = 256;
pub const MAX_STRUCTURED_WHIR_ELEMENTS: usize = 1 << 20;
const MAX_STRUCTURED_WHIR_STACKED_VARIABLES: usize = 20;

const EXPLICIT_WHIR_MAGIC: &[u8; 8] = b"CMFDWHR1";
const STRUCTURED_WHIR_MAGIC: &[u8; 8] = b"CMFDWAG1";
const STRUCTURED_WHIR_SPLIT_MAGIC: &[u8; 8] = b"CMFDWSP2";
const STRUCTURED_WHIR_ALIAS_DOMAIN: &str = "CMFD/FORGEMATRIX/WHIR-ORACLE/V1";
const STRUCTURED_WHIR_SUITE_DOMAIN: &str = "CMFD/FORGEMATRIX/WHIR-SUITE/V1";
const STRUCTURED_WHIR_SPLIT_DOMAIN: &str = "CMFD/FORGEMATRIX/WHIR-SPLIT/V2";
const EXPLICIT_WHIR_TRANSCRIPT_DOMAIN: &[u8] = b"CMFD/FORGEMATRIX/EXPLICIT-WHIR/V1";
const STRUCTURED_WHIR_ALIAS_LAYOUT_LABEL: &[u8] = b"layout";
const STRUCTURED_WHIR_ALIAS_ORACLE_LABEL: &[u8] = b"oracle";
const STRUCTURED_WHIR_SPLIT_COMMON_LABEL: &[u8] = b"common";
const STRUCTURED_WHIR_SPLIT_CHILD_LABEL: &[u8] = b"child";
const STRUCTURED_WHIR_FIXED_MODEL_SCOPE: &[u8] = b"fixed-model";
const STRUCTURED_WHIR_EXECUTION_TRACE_SCOPE: &[u8] = b"execution-trace";
const MAX_STRUCTURED_WHIR_NATIVE_JSON_BYTES: usize = 4 * 1024 * 1024;
const EXPLICIT_WHIR_MIN_VARIABLES: usize = 2;
const EXPLICIT_WHIR_FOLDING: usize = 2;
const EXPLICIT_WHIR_STARTING_LOG_INV_RATE: usize = 1;
const EXPLICIT_WHIR_POW_BITS: usize = 0;
const EXPLICIT_WHIR_HEADER_BYTES: usize = 20;

type F = Goldilocks;
type EF = CubicTrinomialExtensionField<F>;
type FieldHash = SerializingHasher<Blake3>;
type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
type WhirMmcs = MerkleTreeMmcs<F, u8, FieldHash, Compress, 2, 32>;
type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3, 32>>;
type Dft = Radix2DFTSmallBatch<F>;
type Pcs = WhirProver<EF, F, Dft, WhirMmcs, Challenger, ExplicitPointLayout>;
type NativeProof = WhirProof<F, EF, WhirMmcs>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplicitWhirCommitment(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitWhirOpening {
    pub point: Vec<ExtensionElement>,
    pub evaluation: ExtensionElement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitWhirProof {
    pub protocol_version: u32,
    pub num_variables: u32,
    pub proof_bytes: Vec<u8>,
}

/// Canonical deduplicated oracle tables and their one-root WHIR commitment.
///
/// Per-table aliases bind a component transcript to a table position under
/// the root; they are not independent commitments.
#[derive(Debug, Clone)]
pub struct StructuredWhirCommitmentSet {
    tables: Vec<Vec<u64>>,
    table_variables: Vec<usize>,
    root: [u8; 32],
    aliases: Vec<[u8; 32]>,
}

/// Model metadata needed to derive the stable PCS identity for one artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredWhirModelMetadata {
    pub model_version: u32,
    pub batch: u32,
    pub dimension: u32,
    pub layers_per_bank: u32,
    pub model_byte_root: [u8; 32],
}

/// Independently committed model roles: one base input followed by one to
/// three ordered weight banks. Unlike the execution trace commitment, these
/// sets are stable across blocks and are intended to be pinned at activation.
#[derive(Debug, Clone)]
pub struct StructuredWhirModelCommitmentSet {
    sections: Vec<StructuredWhirCommitmentSet>,
    identity: ModelPcsIdentity,
}

/// Failure while deriving bounded research WHIR commitments from one verified
/// canonical model bank.
#[derive(Debug, Error)]
pub enum VerifiedModelBankWhirError {
    #[error("model-bank verification failed: {0}")]
    ModelBank(#[from] ModelBankError),
    #[error("structured WHIR commitment derivation failed: {0}")]
    Whir(#[from] ExplicitWhirError),
    #[error("model bank exceeds the bounded research WHIR limits")]
    ResearchLimit,
    #[error("trusted model identity selects a different WHIR suite")]
    SuiteMismatch,
    #[error("byte-derived model PCS identity does not match the trusted identity")]
    IdentityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StructuredWhirAggregateProof {
    root: [u8; 32],
    table_variables: Vec<u32>,
    proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StructuredWhirSplitProof {
    fixed_model: Vec<StructuredWhirAggregateProof>,
    trace: StructuredWhirAggregateProof,
}

impl ExplicitWhirProof {
    pub fn encode(&self) -> Result<Vec<u8>, ExplicitWhirError> {
        validate_num_variables(self.num_variables as usize)?;
        if self.protocol_version != EXPLICIT_WHIR_VERSION {
            return Err(ExplicitWhirError::UnsupportedVersion);
        }
        if self.proof_bytes.len() > MAX_EXPLICIT_WHIR_PROOF_BYTES {
            return Err(ExplicitWhirError::ProofTooLarge);
        }
        let proof_len =
            u32::try_from(self.proof_bytes.len()).map_err(|_| ExplicitWhirError::ProofTooLarge)?;
        let mut encoded = Vec::with_capacity(EXPLICIT_WHIR_HEADER_BYTES + self.proof_bytes.len());
        encoded.extend_from_slice(EXPLICIT_WHIR_MAGIC);
        encoded.extend_from_slice(&self.protocol_version.to_le_bytes());
        encoded.extend_from_slice(&self.num_variables.to_le_bytes());
        encoded.extend_from_slice(&proof_len.to_le_bytes());
        encoded.extend_from_slice(&self.proof_bytes);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ExplicitWhirError> {
        if encoded.len() < EXPLICIT_WHIR_HEADER_BYTES
            || encoded.len() > EXPLICIT_WHIR_HEADER_BYTES + MAX_EXPLICIT_WHIR_PROOF_BYTES
        {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        if &encoded[..8] != EXPLICIT_WHIR_MAGIC {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        let protocol_version = read_u32(encoded, 8)?;
        if protocol_version != EXPLICIT_WHIR_VERSION {
            return Err(ExplicitWhirError::UnsupportedVersion);
        }
        let num_variables = read_u32(encoded, 12)?;
        validate_num_variables(num_variables as usize)?;
        let proof_len = read_u32(encoded, 16)? as usize;
        if proof_len > MAX_EXPLICIT_WHIR_PROOF_BYTES
            || encoded.len() != EXPLICIT_WHIR_HEADER_BYTES + proof_len
        {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        Ok(Self {
            protocol_version,
            num_variables,
            proof_bytes: encoded[EXPLICIT_WHIR_HEADER_BYTES..].to_vec(),
        })
    }
}

impl StructuredWhirCommitmentSet {
    pub fn new(mut tables: Vec<Vec<u64>>) -> Result<Self, ExplicitWhirError> {
        if tables.is_empty() || tables.len() > MAX_STRUCTURED_WHIR_TABLES {
            return Err(ExplicitWhirError::InvalidTableCount);
        }
        tables.sort();
        tables.dedup();
        if tables.len() > MAX_STRUCTURED_WHIR_TABLES {
            return Err(ExplicitWhirError::InvalidTableCount);
        }
        let table_variables = tables
            .iter()
            .map(|table| validate_table(table))
            .collect::<Result<Vec<_>, _>>()?;
        let stacked_variables = validate_stacked_shape(&table_variables)?;
        let native_tables = tables
            .iter()
            .map(|table| {
                table
                    .iter()
                    .copied()
                    .map(canonical_base)
                    .collect::<Result<Vec<_>, _>>()
                    .map(Poly::<F>::new)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (pcs, mut challenger) = build_pcs(stacked_variables, b"")?;
        let witness = ExplicitPointLayout::new_witness(
            native_tables
                .into_iter()
                .map(|poly| Table::new(vec![poly]))
                .collect(),
            pcs.round_folding_factor(0),
        );
        let (_, commitment, _) = ExplicitPointLayout::commit(
            &pcs.dft,
            &pcs.mmcs,
            &mut challenger,
            witness,
            pcs.round_folding_factor(0),
            pcs.starting_log_inv_rate,
        );
        if commitment.num_roots() != 1 {
            return Err(ExplicitWhirError::Configuration(
                "WHIR commitment cap must contain exactly one root".to_owned(),
            ));
        }
        let root = commitment.roots()[0];
        let aliases = structured_aliases(root, &table_variables)?;
        Ok(Self {
            tables,
            table_variables,
            root,
            aliases,
        })
    }

    /// Returns the transcript alias for an exact canonical table.
    pub fn commitment_for(&self, table: &[u64]) -> Result<[u8; 32], ExplicitWhirError> {
        let index = self
            .tables
            .binary_search_by(|candidate| candidate.as_slice().cmp(table))
            .map_err(|_| ExplicitWhirError::UnknownCommitment)?;
        Ok(self.aliases[index])
    }

    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn len(&self) -> usize {
        self.tables.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }
}

impl StructuredWhirModelCommitmentSet {
    pub fn new(
        metadata: StructuredWhirModelMetadata,
        base_input: Vec<u64>,
        weight_banks: Vec<Vec<u64>>,
    ) -> Result<Self, ExplicitWhirError> {
        if weight_banks.is_empty() || weight_banks.len() > MAX_MODEL_PCS_WEIGHT_BANKS {
            return Err(ExplicitWhirError::ModelIdentity);
        }
        let expected_base = usize::try_from(metadata.batch)
            .ok()
            .and_then(|batch| {
                usize::try_from(metadata.dimension)
                    .ok()
                    .and_then(|dimension| batch.checked_mul(dimension))
            })
            .ok_or(ExplicitWhirError::ModelIdentity)?;
        let expected_weight = usize::try_from(metadata.layers_per_bank)
            .ok()
            .and_then(|layers| {
                usize::try_from(metadata.dimension)
                    .ok()
                    .and_then(|dimension| {
                        layers
                            .checked_mul(dimension)
                            .and_then(|elements| elements.checked_mul(dimension))
                    })
            })
            .ok_or(ExplicitWhirError::ModelIdentity)?;
        if base_input.len() != expected_base
            || weight_banks
                .iter()
                .any(|bank| bank.len() != expected_weight)
        {
            return Err(ExplicitWhirError::ModelIdentity);
        }
        let mut sections = Vec::with_capacity(1 + weight_banks.len());
        sections.push(StructuredWhirCommitmentSet::new(vec![base_input])?);
        for bank in weight_banks {
            sections.push(StructuredWhirCommitmentSet::new(vec![bank])?);
        }
        let identity = ModelPcsIdentity {
            model_version: metadata.model_version,
            batch: metadata.batch,
            dimension: metadata.dimension,
            layers_per_bank: metadata.layers_per_bank,
            model_byte_root: metadata.model_byte_root,
            pcs_suite_parameter_digest: structured_whir_suite_parameter_digest(),
            base_input_commitment: sections[0].aliases[0],
            weight_bank_commitments: sections[1..]
                .iter()
                .map(|section| section.aliases[0])
                .collect(),
        };
        identity
            .validate()
            .map_err(|_| ExplicitWhirError::ModelIdentity)?;
        Ok(Self { sections, identity })
    }

    pub const fn identity(&self) -> &ModelPcsIdentity {
        &self.identity
    }

    /// Verifies one bounded canonical model bank and derives every fixed-model
    /// commitment from the exact verified bytes. This remains research-only
    /// and cannot admit production-sized ForgeMatrix tables.
    pub fn from_verified_model_bank<R: Read>(
        reader: R,
        trusted_manifest: &ModelBankManifest,
        trusted_identity: &ModelPcsIdentity,
    ) -> Result<Self, VerifiedModelBankWhirError> {
        trusted_identity.validate()?;
        if trusted_identity.pcs_suite_parameter_digest != structured_whir_suite_parameter_digest() {
            return Err(VerifiedModelBankWhirError::SuiteMismatch);
        }
        trusted_manifest.verify_pcs_identity(trusted_identity)?;

        if trusted_manifest.payload_bytes > MAX_SMALL_FIXTURE_PAYLOAD_BYTES {
            return Err(VerifiedModelBankWhirError::ResearchLimit);
        }
        let dimension = u64::from(trusted_manifest.dimension);
        let base_elements = u64::from(trusted_manifest.batch)
            .checked_mul(dimension)
            .ok_or(VerifiedModelBankWhirError::ResearchLimit)?;
        let bank_elements = u64::from(trusted_identity.layers_per_bank)
            .checked_mul(dimension)
            .and_then(|elements| elements.checked_mul(dimension))
            .ok_or(VerifiedModelBankWhirError::ResearchLimit)?;
        let base_len = bounded_model_table_len(base_elements)?;
        let bank_len = bounded_model_table_len(bank_elements)?;
        let bank_count = trusted_identity.weight_bank_commitments.len();
        let payload_len = base_len
            .checked_add(
                bank_len
                    .checked_mul(bank_count)
                    .ok_or(VerifiedModelBankWhirError::ResearchLimit)?,
            )
            .ok_or(VerifiedModelBankWhirError::ResearchLimit)?;
        if u64::try_from(payload_len).ok() != Some(trusted_manifest.payload_bytes) {
            return Err(VerifiedModelBankWhirError::IdentityMismatch);
        }
        let exact_len = MODEL_BANK_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(VerifiedModelBankWhirError::ResearchLimit)?;
        let read_limit = exact_len
            .checked_add(1)
            .ok_or(VerifiedModelBankWhirError::ResearchLimit)?;

        let mut encoded = Vec::with_capacity(read_limit);
        reader
            .take(read_limit as u64)
            .read_to_end(&mut encoded)
            .map_err(ModelBankError::Io)?;
        verify_model_bank(Cursor::new(encoded.as_slice()), trusted_manifest)?;

        let payload = encoded
            .get(MODEL_BANK_HEADER_BYTES..)
            .ok_or(VerifiedModelBankWhirError::IdentityMismatch)?;
        if payload.len() != payload_len {
            return Err(VerifiedModelBankWhirError::IdentityMismatch);
        }
        let base_input = payload
            .get(..base_len)
            .ok_or(VerifiedModelBankWhirError::IdentityMismatch)?
            .iter()
            .copied()
            .map(centered_model_field_element)
            .collect();
        let mut weight_banks = Vec::with_capacity(bank_count);
        for bank_index in 0..bank_count {
            let start = base_len
                .checked_add(
                    bank_index
                        .checked_mul(bank_len)
                        .ok_or(VerifiedModelBankWhirError::ResearchLimit)?,
                )
                .ok_or(VerifiedModelBankWhirError::ResearchLimit)?;
            let end = start
                .checked_add(bank_len)
                .ok_or(VerifiedModelBankWhirError::ResearchLimit)?;
            weight_banks.push(
                payload
                    .get(start..end)
                    .ok_or(VerifiedModelBankWhirError::IdentityMismatch)?
                    .iter()
                    .copied()
                    .map(centered_model_field_element)
                    .collect(),
            );
        }

        let derived = Self::new(
            StructuredWhirModelMetadata {
                model_version: trusted_manifest.model_version,
                batch: trusted_manifest.batch,
                dimension: trusted_manifest.dimension,
                layers_per_bank: trusted_identity.layers_per_bank,
                model_byte_root: trusted_manifest.raw_blake3_root,
            },
            base_input,
            weight_banks,
        )?;
        if derived.identity() != trusted_identity {
            return Err(VerifiedModelBankWhirError::IdentityMismatch);
        }
        Ok(derived)
    }
}

fn bounded_model_table_len(elements: u64) -> Result<usize, VerifiedModelBankWhirError> {
    let elements =
        usize::try_from(elements).map_err(|_| VerifiedModelBankWhirError::ResearchLimit)?;
    if !elements.is_power_of_two() {
        return Err(VerifiedModelBankWhirError::ResearchLimit);
    }
    let variables = elements.ilog2() as usize;
    if !(EXPLICIT_WHIR_MIN_VARIABLES..=MAX_EXPLICIT_WHIR_VARIABLES).contains(&variables) {
        return Err(VerifiedModelBankWhirError::ResearchLimit);
    }
    Ok(elements)
}

/// Digest of every cryptographic and canonical-encoding choice made by the
/// current research WHIR adapter. A production suite must replace this
/// prototype identifier only through an explicit protocol version change.
pub fn structured_whir_suite_parameter_digest() -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(STRUCTURED_WHIR_SUITE_DOMAIN);
    update_suite_descriptor(
        &mut hasher,
        b"descriptor-format",
        b"ordered-label-u64le-length-value-u64le-length-v1",
    );
    update_suite_descriptor(
        &mut hasher,
        b"suite-domain",
        STRUCTURED_WHIR_SUITE_DOMAIN.as_bytes(),
    );
    update_suite_descriptor(
        &mut hasher,
        b"alias-domain",
        STRUCTURED_WHIR_ALIAS_DOMAIN.as_bytes(),
    );
    update_suite_descriptor(
        &mut hasher,
        b"split-domain",
        STRUCTURED_WHIR_SPLIT_DOMAIN.as_bytes(),
    );
    update_suite_descriptor(
        &mut hasher,
        b"explicit-transcript-domain",
        EXPLICIT_WHIR_TRANSCRIPT_DOMAIN,
    );
    update_suite_descriptor(
        &mut hasher,
        b"alias-layout-label",
        STRUCTURED_WHIR_ALIAS_LAYOUT_LABEL,
    );
    update_suite_descriptor(
        &mut hasher,
        b"alias-oracle-label",
        STRUCTURED_WHIR_ALIAS_ORACLE_LABEL,
    );
    update_suite_descriptor(
        &mut hasher,
        b"split-common-label",
        STRUCTURED_WHIR_SPLIT_COMMON_LABEL,
    );
    update_suite_descriptor(
        &mut hasher,
        b"split-child-label",
        STRUCTURED_WHIR_SPLIT_CHILD_LABEL,
    );
    update_suite_descriptor(
        &mut hasher,
        b"fixed-model-scope",
        STRUCTURED_WHIR_FIXED_MODEL_SCOPE,
    );
    update_suite_descriptor(
        &mut hasher,
        b"execution-trace-scope",
        STRUCTURED_WHIR_EXECUTION_TRACE_SCOPE,
    );
    update_suite_descriptor(&mut hasher, b"explicit-magic", EXPLICIT_WHIR_MAGIC);
    update_suite_descriptor(&mut hasher, b"aggregate-magic", STRUCTURED_WHIR_MAGIC);
    update_suite_descriptor(&mut hasher, b"split-magic", STRUCTURED_WHIR_SPLIT_MAGIC);
    update_suite_u64(
        &mut hasher,
        b"explicit-version",
        EXPLICIT_WHIR_VERSION as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"split-version",
        STRUCTURED_WHIR_SPLIT_VERSION as u64,
    );
    update_suite_descriptor(&mut hasher, b"p3-suite", b"0.6.3");
    update_suite_descriptor(
        &mut hasher,
        b"p3-util-source",
        b"0.6.3+cmfd-rust-1.88-assume-init-ref-backport-v1",
    );
    update_suite_descriptor(
        &mut hasher,
        b"p3-merkle-tree-source",
        b"0.6.3+cmfd-checked-prover-first-digest-layer-hook-v1",
    );
    update_suite_descriptor(
        &mut hasher,
        b"p3-fri-source",
        b"0.6.3+cmfd-generic-prover-data-matrix-v1",
    );
    update_suite_descriptor(&mut hasher, b"blake3-crate", b"1.8.6");
    update_suite_descriptor(&mut hasher, b"flate2-crate", b"1.1.9");
    update_suite_descriptor(&mut hasher, b"crc32fast-crate", b"1.5.0");
    update_suite_descriptor(&mut hasher, b"cfg-if-crate", b"1.0.4");
    update_suite_descriptor(&mut hasher, b"miniz-oxide-crate", b"0.8.9");
    update_suite_descriptor(&mut hasher, b"adler2-crate", b"2.0.1");
    update_suite_descriptor(&mut hasher, b"simd-adler32-crate", b"0.3.10");
    update_suite_descriptor(&mut hasher, b"serde-crate", b"1.0.229");
    update_suite_descriptor(&mut hasher, b"serde-json-crate", b"1.0.151");
    update_suite_descriptor(&mut hasher, b"base-field", b"goldilocks");
    update_suite_u64(&mut hasher, b"base-field-modulus", GOLDILOCKS_MODULUS);
    update_suite_descriptor(&mut hasher, b"extension-field", b"cubic:u^3=u+1");
    update_suite_descriptor(&mut hasher, b"variable-order", b"suffix");
    update_suite_descriptor(
        &mut hasher,
        b"structured-point-order",
        b"reverse-fastest-first",
    );
    update_suite_descriptor(
        &mut hasher,
        b"field-element-encoding",
        b"canonical-u64-coefficients-extension-basis-1-u-u2",
    );
    update_suite_descriptor(&mut hasher, b"dft", b"radix2-small-batch");
    update_suite_descriptor(
        &mut hasher,
        b"challenger",
        b"serializing64-hash-challenger-blake3-32",
    );
    update_suite_descriptor(
        &mut hasher,
        b"mmcs",
        b"merkle-tree-field-u8-serializing-blake3-binary-digest32-min-height0-cap1",
    );
    update_suite_descriptor(
        &mut hasher,
        b"table-canonicalization",
        b"lexicographic-u64-sort-dedup",
    );
    update_suite_descriptor(
        &mut hasher,
        b"stack-layout",
        b"descending-variable-count-reverse-stable-index-ties-zero-pad-power-of-two",
    );
    update_suite_descriptor(
        &mut hasher,
        b"alias-encoding",
        b"root32-layout-count-u32le-vars-u32le-oracle-index-u32le",
    );
    update_suite_descriptor(
        &mut hasher,
        b"fixed-role-layout",
        b"base-input-then-ordered-weight-banks-one-table-per-role",
    );
    update_suite_descriptor(
        &mut hasher,
        b"split-common-transcript",
        b"label-version-u32le-public32-identity32-fixed-count-u32le-indexed-roots-trace-root",
    );
    update_suite_descriptor(
        &mut hasher,
        b"split-child-transcript",
        b"label-common32-scope-length-u32le-scope-index-u32le",
    );
    update_suite_descriptor(
        &mut hasher,
        b"pcs-transcript-initial-state",
        b"domain-binding-length-u64le-binding-pcs-domain-separator32",
    );
    update_suite_descriptor(&mut hasher, b"security-assumption", b"unique-decoding");
    update_suite_u64(
        &mut hasher,
        b"security-bits",
        EXPLICIT_WHIR_SECURITY_BITS as u64,
    );
    update_suite_u64(&mut hasher, b"folding-factor", EXPLICIT_WHIR_FOLDING as u64);
    update_suite_u64(
        &mut hasher,
        b"starting-log-inverse-rate",
        EXPLICIT_WHIR_STARTING_LOG_INV_RATE as u64,
    );
    update_suite_u64(&mut hasher, b"pow-bits", EXPLICIT_WHIR_POW_BITS as u64);
    update_suite_descriptor(
        &mut hasher,
        b"native-proof-codec",
        b"serde-json-exact-reencode-zlib-rfc1950-best-level9-exact-stream-exhaustion",
    );
    update_suite_descriptor(
        &mut hasher,
        b"split-envelope-codec",
        b"little-endian-u32-count-and-length-exact-exhaustion",
    );
    update_suite_u64(
        &mut hasher,
        b"minimum-variables",
        EXPLICIT_WHIR_MIN_VARIABLES as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-explicit-variables",
        MAX_EXPLICIT_WHIR_VARIABLES as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-stacked-variables",
        MAX_STRUCTURED_WHIR_STACKED_VARIABLES as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-explicit-openings",
        MAX_EXPLICIT_WHIR_OPENINGS as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-structured-openings",
        crate::MAX_STRUCTURED_OPENING_CLAIMS as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-opening-variables",
        crate::MAX_STRUCTURED_OPENING_VARIABLES as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-structured-tables",
        MAX_STRUCTURED_WHIR_TABLES as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-structured-elements",
        MAX_STRUCTURED_WHIR_ELEMENTS as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-native-json-bytes",
        MAX_STRUCTURED_WHIR_NATIVE_JSON_BYTES as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-explicit-proof-bytes",
        MAX_EXPLICIT_WHIR_PROOF_BYTES as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-pcs-proof-bytes",
        crate::MAX_STRUCTURED_PCS_PROOF_BYTES as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-binding-bytes",
        MAX_EXPLICIT_WHIR_BINDING_BYTES as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"maximum-fixed-weight-banks",
        MAX_MODEL_PCS_WEIGHT_BANKS as u64,
    );
    update_suite_u64(
        &mut hasher,
        b"explicit-header-bytes",
        EXPLICIT_WHIR_HEADER_BYTES as u64,
    );
    *hasher.finalize().as_bytes()
}

fn update_suite_descriptor(hasher: &mut Blake3Hasher, label: &[u8], value: &[u8]) {
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn update_suite_u64(hasher: &mut Blake3Hasher, label: &[u8], value: u64) {
    update_suite_descriptor(hasher, label, &value.to_le_bytes());
}

impl StructuredWhirAggregateProof {
    fn encode(&self) -> Result<Vec<u8>, ExplicitWhirError> {
        if self.table_variables.is_empty()
            || self.table_variables.len() > MAX_STRUCTURED_WHIR_TABLES
            || self.proof_bytes.is_empty()
            || self.proof_bytes.len() > crate::MAX_STRUCTURED_PCS_PROOF_BYTES
        {
            return Err(ExplicitWhirError::AggregateProofTooLarge);
        }
        let count = u32::try_from(self.table_variables.len())
            .map_err(|_| ExplicitWhirError::InvalidTableCount)?;
        let proof_len = u32::try_from(self.proof_bytes.len())
            .map_err(|_| ExplicitWhirError::AggregateProofTooLarge)?;
        let mut encoded =
            Vec::with_capacity(52 + self.table_variables.len() * 4 + self.proof_bytes.len());
        encoded.extend_from_slice(STRUCTURED_WHIR_MAGIC);
        encoded.extend_from_slice(&EXPLICIT_WHIR_VERSION.to_le_bytes());
        encoded.extend_from_slice(&self.root);
        encoded.extend_from_slice(&count.to_le_bytes());
        for variables in &self.table_variables {
            encoded.extend_from_slice(&variables.to_le_bytes());
        }
        encoded.extend_from_slice(&proof_len.to_le_bytes());
        encoded.extend_from_slice(&self.proof_bytes);
        if encoded.len() > crate::MAX_STRUCTURED_PCS_PROOF_BYTES {
            return Err(ExplicitWhirError::AggregateProofTooLarge);
        }
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, ExplicitWhirError> {
        if encoded.len() < 52 || encoded.len() > crate::MAX_STRUCTURED_PCS_PROOF_BYTES {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        if encoded.get(..8) != Some(STRUCTURED_WHIR_MAGIC.as_slice()) {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        if read_u32(encoded, 8)? != EXPLICIT_WHIR_VERSION {
            return Err(ExplicitWhirError::UnsupportedVersion);
        }
        let root: [u8; 32] = encoded
            .get(12..44)
            .ok_or(ExplicitWhirError::InvalidEncoding)?
            .try_into()
            .map_err(|_| ExplicitWhirError::InvalidEncoding)?;
        let count = read_u32(encoded, 44)? as usize;
        if count == 0 || count > MAX_STRUCTURED_WHIR_TABLES {
            return Err(ExplicitWhirError::InvalidTableCount);
        }
        let variables_end = 48usize
            .checked_add(
                count
                    .checked_mul(4)
                    .ok_or(ExplicitWhirError::InvalidEncoding)?,
            )
            .ok_or(ExplicitWhirError::InvalidEncoding)?;
        let mut table_variables = Vec::with_capacity(count);
        for index in 0..count {
            let variables = read_u32(encoded, 48 + index * 4)?;
            validate_num_variables(variables as usize)?;
            table_variables.push(variables);
        }
        validate_stacked_shape(
            &table_variables
                .iter()
                .map(|value| *value as usize)
                .collect::<Vec<_>>(),
        )?;
        let proof_len = read_u32(encoded, variables_end)? as usize;
        let proof_start = variables_end + 4;
        if proof_len == 0
            || proof_len > crate::MAX_STRUCTURED_PCS_PROOF_BYTES
            || proof_start.checked_add(proof_len) != Some(encoded.len())
        {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        Ok(Self {
            root,
            table_variables,
            proof_bytes: encoded[proof_start..].to_vec(),
        })
    }
}

impl StructuredWhirSplitProof {
    fn encode(&self) -> Result<Vec<u8>, ExplicitWhirError> {
        if self.fixed_model.is_empty() || self.fixed_model.len() > 1 + MAX_MODEL_PCS_WEIGHT_BANKS {
            return Err(ExplicitWhirError::ModelIdentity);
        }
        let fixed = self
            .fixed_model
            .iter()
            .map(StructuredWhirAggregateProof::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let trace = self.trace.encode()?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(STRUCTURED_WHIR_SPLIT_MAGIC);
        encoded.extend_from_slice(&STRUCTURED_WHIR_SPLIT_VERSION.to_le_bytes());
        encoded.extend_from_slice(&(fixed.len() as u32).to_le_bytes());
        for section in fixed {
            encode_split_blob(&mut encoded, &section)?;
        }
        encode_split_blob(&mut encoded, &trace)?;
        if encoded.len() > crate::MAX_STRUCTURED_PCS_PROOF_BYTES {
            return Err(ExplicitWhirError::AggregateProofTooLarge);
        }
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, ExplicitWhirError> {
        if encoded.len() > crate::MAX_STRUCTURED_PCS_PROOF_BYTES
            || encoded.get(..8) != Some(STRUCTURED_WHIR_SPLIT_MAGIC.as_slice())
            || read_u32(encoded, 8)? != STRUCTURED_WHIR_SPLIT_VERSION
        {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        let count = read_u32(encoded, 12)? as usize;
        if count == 0 || count > 1 + MAX_MODEL_PCS_WEIGHT_BANKS {
            return Err(ExplicitWhirError::ModelIdentity);
        }
        let mut offset = 16;
        let mut fixed_model = Vec::with_capacity(count);
        for _ in 0..count {
            fixed_model.push(StructuredWhirAggregateProof::decode(take_split_blob(
                encoded,
                &mut offset,
            )?)?);
        }
        let trace = StructuredWhirAggregateProof::decode(take_split_blob(encoded, &mut offset)?)?;
        if offset != encoded.len() {
            return Err(ExplicitWhirError::InvalidEncoding);
        }
        Ok(Self { fixed_model, trace })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StructuredWhirPcsVerifier;

impl StructuredPcsVerifier for StructuredWhirPcsVerifier {
    fn verify_openings(
        &self,
        public_binding: &[u8; 32],
        expected_model: &ModelPcsIdentity,
        openings: &StructuredPcsOpeningSet,
        proof: &[u8],
    ) -> bool {
        verify_structured_whir_openings(public_binding, expected_model, openings, proof).is_ok()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExplicitWhirError {
    #[error("WHIR prototype supports 2..={MAX_EXPLICIT_WHIR_VARIABLES} variables")]
    InvalidVariableCount,
    #[error("WHIR prototype table length must be an exact power of two")]
    InvalidTableLength,
    #[error("WHIR prototype requires 1..={MAX_EXPLICIT_WHIR_OPENINGS} openings")]
    InvalidOpeningCount,
    #[error("WHIR transcript binding exceeds the research byte cap")]
    BindingTooLarge,
    #[error("WHIR opening point dimension does not match the committed table")]
    PointDimensionMismatch,
    #[error("non-canonical Goldilocks field element")]
    NonCanonicalFieldElement,
    #[error("WHIR proof exceeds the research byte cap")]
    ProofTooLarge,
    #[error("unsupported WHIR prototype version")]
    UnsupportedVersion,
    #[error("malformed WHIR proof encoding")]
    InvalidEncoding,
    #[error("WHIR configuration failed: {0}")]
    Configuration(String),
    #[error("WHIR proof serialization failed")]
    Serialization,
    #[error("WHIR proof verification failed")]
    Verification,
    #[error("WHIR backend panicked while handling untrusted proof data")]
    BackendPanic,
    #[error("structured WHIR requires 1..={MAX_STRUCTURED_WHIR_TABLES} unique tables")]
    InvalidTableCount,
    #[error("structured WHIR tables exceed the aggregate research element cap")]
    AggregateTableSize,
    #[error("structured WHIR opening references an unknown oracle commitment")]
    UnknownCommitment,
    #[error("structured WHIR oracle commitment does not match its committed table")]
    CommitmentMismatch,
    #[error("structured WHIR claimed evaluation does not match the supplied table")]
    ClaimMismatch,
    #[error("structured WHIR proof exceeds the aggregate PCS byte cap")]
    AggregateProofTooLarge,
    #[error("structured WHIR fixed-model PCS identity is invalid or mismatched")]
    ModelIdentity,
    #[error("structured WHIR opening claims cross the fixed-model and trace scopes")]
    OpeningScope,
}

#[derive(Debug, Clone)]
struct ExplicitPointLayout {
    poly: Poly<F>,
    extension_poly: Poly<EF>,
    folding: usize,
    statement: EqStatement<EF>,
    table_variables: Vec<usize>,
    selectors: Vec<Point<F>>,
}

impl ExplicitPointLayout {
    fn from_poly_and_shapes(poly: Poly<F>, folding: usize, table_variables: Vec<usize>) -> Self {
        let num_variables = poly.num_variables();
        let selectors = plan_selectors(&table_variables, num_variables);
        let extension_poly = extend_poly(&poly);
        Self {
            poly,
            extension_poly,
            folding,
            statement: EqStatement::initialize(num_variables),
            table_variables,
            selectors,
        }
    }

    fn lift_point(&self, table_index: usize, point: &Point<EF>) -> Point<EF> {
        let mut lifted = self.selectors[table_index]
            .as_slice()
            .iter()
            .copied()
            .map(EF::from)
            .collect::<Vec<_>>();
        lifted.extend_from_slice(point.as_slice());
        Point::new(lifted)
    }

    fn record_explicit_claim<Ch>(
        &mut self,
        table_index: usize,
        point: Point<EF>,
        evaluation: EF,
        challenger: &mut Ch,
    ) where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        assert_eq!(point.num_variables(), self.table_variables[table_index]);
        let point = self.lift_point(table_index, &point);
        challenger.observe_algebra_slice(point.as_slice());
        challenger.observe_algebra_element(evaluation);
        self.statement.add_evaluated_constraint(point, evaluation);
    }
}

impl Layout<F, EF> for ExplicitPointLayout {
    fn from_witness(witness: Witness<F>) -> Self {
        let poly = witness.poly().clone();
        let table_variables = witness
            .table_shapes()
            .into_iter()
            .map(|shape| shape.num_variables())
            .collect();
        Self::from_poly_and_shapes(poly, 0, table_variables)
    }

    fn new_witness(tables: Vec<Table<F>>, folding: usize) -> Witness<F> {
        Witness::new(tables, folding)
    }

    fn commit<D, MT, Ch>(
        dft: &D,
        mmcs: &MT,
        challenger: &mut Ch,
        witness: Witness<F>,
        folding: usize,
        starting_log_inv_rate: usize,
    ) -> (Self, MT::Commitment, MT::ProverData<DenseMatrix<F>>)
    where
        D: TwoAdicSubgroupDft<F>,
        MT: Mmcs<F>,
        Ch: CanObserve<MT::Commitment>,
    {
        let poly = witness.poly().clone();
        let table_variables = witness
            .table_shapes()
            .into_iter()
            .map(|shape| shape.num_variables())
            .collect();
        let (commitment, prover_data) = p3_sumcheck::commit::commit_base(
            VariableOrder::Suffix,
            dft,
            mmcs,
            challenger,
            &poly,
            folding,
            starting_log_inv_rate,
        );
        (
            Self::from_poly_and_shapes(poly, folding, table_variables),
            commitment,
            prover_data,
        )
    }

    fn num_claims(&self) -> usize {
        self.statement.len()
    }

    fn strategy() -> LayoutStrategy {
        LayoutStrategy::new(false, VariableOrder::Suffix)
    }

    fn folding(&self) -> usize {
        self.folding
    }

    fn num_variables(&self) -> usize {
        self.poly.num_variables()
    }

    fn num_variables_table(&self, id: usize) -> usize {
        self.table_variables[id]
    }

    fn eval<Ch>(&mut self, table_idx: usize, polys: &[usize], challenger: &mut Ch) -> Vec<EF>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        assert_eq!(polys, [0]);
        let point: Point<EF> = Point::expand_from_univariate(
            challenger.sample_algebra_element(),
            self.table_variables[table_idx],
        );
        let lifted = self.lift_point(table_idx, &point);
        let evaluation = self.extension_poly.eval_ext::<F>(&lifted);
        challenger.observe_algebra_element(evaluation);
        self.statement.add_evaluated_constraint(lifted, evaluation);
        vec![evaluation]
    }

    fn add_virtual_eval<Ch>(&mut self, challenger: &mut Ch) -> EF
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let point: Point<EF> = Point::expand_from_univariate(
            challenger.sample_algebra_element(),
            self.poly.num_variables(),
        );
        let evaluation = self.extension_poly.eval_ext::<F>(&point);
        challenger.observe_algebra_element(evaluation);
        self.statement.add_evaluated_constraint(point, evaluation);
        evaluation
    }

    fn into_sumcheck<Ch>(
        self,
        sumcheck_data: &mut SumcheckData<F, EF>,
        pow_bits: usize,
        challenger: &mut Ch,
    ) -> (SumcheckProver<F, EF>, Point<EF>)
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        assert!(!self.statement.is_empty());
        let alpha = challenger.sample_algebra_element();
        let mut weights = Poly::<EF>::zero(self.poly.num_variables());
        let mut sum = EF::ZERO;
        self.statement
            .combine_hypercube::<F, false>(&mut weights, &mut sum, alpha);
        let product =
            ProductPolynomial::new_unpacked(VariableOrder::Suffix, self.extension_poly, weights);
        let mut prover = SumcheckProver::new(product, sum);
        let randomness = prover.compute_sumcheck_polynomials(
            sumcheck_data,
            challenger,
            self.folding,
            pow_bits,
            None,
        );
        (prover, randomness)
    }
}

pub fn prove_explicit_whir_openings(
    transcript_binding: &[u8],
    table: &[u64],
    points: &[Vec<ExtensionElement>],
) -> Result<
    (
        ExplicitWhirCommitment,
        Vec<ExplicitWhirOpening>,
        ExplicitWhirProof,
    ),
    ExplicitWhirError,
> {
    let num_variables = validate_table(table)?;
    validate_points(points, num_variables)?;
    let native_table = table
        .iter()
        .copied()
        .map(canonical_base)
        .collect::<Result<Vec<_>, _>>()?;
    let native_points = convert_points(points)?;
    let poly = Poly::<F>::new(native_table);
    let extension_poly = extend_poly(&poly);
    let evaluations = native_points
        .iter()
        .map(|point| extension_poly.eval_ext::<F>(point))
        .collect::<Vec<_>>();
    let (pcs, mut challenger) = build_pcs(num_variables, transcript_binding)?;
    let witness =
        ExplicitPointLayout::new_witness(vec![Table::new(vec![poly])], pcs.round_folding_factor(0));
    let (mut layout, commitment, prover_data) = ExplicitPointLayout::commit(
        &pcs.dft,
        &pcs.mmcs,
        &mut challenger,
        witness,
        pcs.round_folding_factor(0),
        pcs.starting_log_inv_rate,
    );

    let mut native_proof = empty_proof(&pcs.config);
    native_proof.initial_ood_answers = (0..pcs.commitment_ood_samples)
        .map(|_| layout.add_virtual_eval(&mut challenger))
        .collect();
    for (point, &evaluation) in native_points.into_iter().zip(&evaluations) {
        layout.record_explicit_claim(0, point, evaluation, &mut challenger);
    }
    pcs.prove(&mut native_proof, &mut challenger, layout, prover_data);

    let proof_bytes =
        serde_json::to_vec(&native_proof).map_err(|_| ExplicitWhirError::Serialization)?;
    if proof_bytes.len() > MAX_EXPLICIT_WHIR_PROOF_BYTES {
        return Err(ExplicitWhirError::ProofTooLarge);
    }
    let openings = points
        .iter()
        .cloned()
        .zip(evaluations.into_iter().map(external_extension))
        .map(|(point, evaluation)| ExplicitWhirOpening { point, evaluation })
        .collect();
    if commitment.num_roots() != 1 {
        return Err(ExplicitWhirError::Configuration(
            "WHIR commitment cap must contain exactly one root".to_owned(),
        ));
    }
    Ok((
        ExplicitWhirCommitment(commitment.roots()[0]),
        openings,
        ExplicitWhirProof {
            protocol_version: EXPLICIT_WHIR_VERSION,
            num_variables: num_variables as u32,
            proof_bytes,
        },
    ))
}

pub fn verify_explicit_whir_openings(
    transcript_binding: &[u8],
    commitment: ExplicitWhirCommitment,
    openings: &[ExplicitWhirOpening],
    proof: &ExplicitWhirProof,
) -> Result<(), ExplicitWhirError> {
    if proof.protocol_version != EXPLICIT_WHIR_VERSION {
        return Err(ExplicitWhirError::UnsupportedVersion);
    }
    let num_variables = proof.num_variables as usize;
    validate_num_variables(num_variables)?;
    if transcript_binding.len() > MAX_EXPLICIT_WHIR_BINDING_BYTES {
        return Err(ExplicitWhirError::BindingTooLarge);
    }
    if proof.proof_bytes.len() > MAX_EXPLICIT_WHIR_PROOF_BYTES {
        return Err(ExplicitWhirError::ProofTooLarge);
    }
    if openings.is_empty() || openings.len() > MAX_EXPLICIT_WHIR_OPENINGS {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    let native_points = openings
        .iter()
        .map(|opening| {
            if opening.point.len() != num_variables {
                return Err(ExplicitWhirError::PointDimensionMismatch);
            }
            convert_point(&opening.point)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let native_evaluations = openings
        .iter()
        .map(|opening| convert_extension(opening.evaluation))
        .collect::<Result<Vec<_>, _>>()?;

    let native_proof: NativeProof = serde_json::from_slice(&proof.proof_bytes)
        .map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    let canonical_proof_bytes =
        serde_json::to_vec(&native_proof).map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    if canonical_proof_bytes != proof.proof_bytes {
        return Err(ExplicitWhirError::InvalidEncoding);
    }
    catch_unwind(AssertUnwindSafe(|| {
        verify_native(
            transcript_binding,
            commitment.0,
            &native_points,
            &native_evaluations,
            num_variables,
            &native_proof,
        )
    }))
    .map_err(|_| ExplicitWhirError::BackendPanic)?
}

pub fn prove_structured_whir_openings(
    public_binding: &[u8; 32],
    expected_model: &ModelPcsIdentity,
    model_commitments: &StructuredWhirModelCommitmentSet,
    trace_commitments: &StructuredWhirCommitmentSet,
    openings: &StructuredPcsOpeningSet,
) -> Result<Vec<u8>, ExplicitWhirError> {
    validate_model_identity(expected_model)?;
    if model_commitments.identity() != expected_model {
        return Err(ExplicitWhirError::ModelIdentity);
    }
    let (fixed_claims, trace_claims) = partition_openings(expected_model, openings)?;
    let fixed_roots = model_commitments
        .sections
        .iter()
        .map(StructuredWhirCommitmentSet::root)
        .collect::<Vec<_>>();
    let common_binding = split_binding(
        public_binding,
        expected_model,
        &fixed_roots,
        trace_commitments.root(),
    )?;
    let fixed_model = model_commitments
        .sections
        .iter()
        .zip(fixed_claims)
        .enumerate()
        .map(|(index, (commitments, claims))| {
            prove_structured_whir_section(
                &child_binding(
                    common_binding,
                    STRUCTURED_WHIR_FIXED_MODEL_SCOPE,
                    index as u32,
                ),
                commitments,
                &claims,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trace = prove_structured_whir_section(
        &child_binding(common_binding, STRUCTURED_WHIR_EXECUTION_TRACE_SCOPE, 0),
        trace_commitments,
        &trace_claims,
    )?;
    StructuredWhirSplitProof { fixed_model, trace }.encode()
}

fn prove_structured_whir_section(
    transcript_binding: &[u8; 32],
    commitment_set: &StructuredWhirCommitmentSet,
    claims: &[StructuredPcsOpeningClaim],
) -> Result<StructuredWhirAggregateProof, ExplicitWhirError> {
    let claims = crate::structured_proof::canonical_openings(claims.to_vec())
        .map_err(|_| ExplicitWhirError::ClaimMismatch)?;
    if claims.is_empty() || claims.len() > crate::MAX_STRUCTURED_OPENING_CLAIMS {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    let alias_map = commitment_set
        .aliases
        .iter()
        .copied()
        .enumerate()
        .map(|(index, alias)| (alias, index))
        .collect::<BTreeMap<_, _>>();
    if alias_map.len() != commitment_set.aliases.len() {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }
    let mut used_tables = vec![false; commitment_set.tables.len()];
    let stacked_variables = validate_stacked_shape(&commitment_set.table_variables)?;
    let native_tables = commitment_set
        .tables
        .iter()
        .map(|table| {
            table
                .iter()
                .copied()
                .map(canonical_base)
                .collect::<Result<Vec<_>, _>>()
                .map(Poly::<F>::new)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let extension_tables = native_tables.iter().map(extend_poly).collect::<Vec<_>>();
    let (pcs, mut challenger) = build_pcs(stacked_variables, transcript_binding)?;
    let witness = ExplicitPointLayout::new_witness(
        native_tables
            .into_iter()
            .map(|poly| Table::new(vec![poly]))
            .collect(),
        pcs.round_folding_factor(0),
    );
    let (mut layout, commitment, prover_data) = ExplicitPointLayout::commit(
        &pcs.dft,
        &pcs.mmcs,
        &mut challenger,
        witness,
        pcs.round_folding_factor(0),
        pcs.starting_log_inv_rate,
    );
    if commitment.num_roots() != 1 || commitment.roots()[0] != commitment_set.root {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }

    let mut native_proof = empty_proof(&pcs.config);
    native_proof.initial_ood_answers = (0..pcs.commitment_ood_samples)
        .map(|_| layout.add_virtual_eval(&mut challenger))
        .collect();
    for claim in &claims {
        let table_index = *alias_map
            .get(&claim.commitment)
            .ok_or(ExplicitWhirError::UnknownCommitment)?;
        used_tables[table_index] = true;
        if claim.point.len() != commitment_set.table_variables[table_index] {
            return Err(ExplicitWhirError::PointDimensionMismatch);
        }
        let point = convert_structured_point(&claim.point)?;
        let evaluation = convert_extension(claim.evaluation)?;
        if extension_tables[table_index].eval_ext::<F>(&point) != evaluation {
            return Err(ExplicitWhirError::ClaimMismatch);
        }
        layout.record_explicit_claim(table_index, point, evaluation, &mut challenger);
    }
    if used_tables.iter().any(|used| !used) {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }
    pcs.prove(&mut native_proof, &mut challenger, layout, prover_data);
    let proof_bytes = encode_aggregate_native_proof(&native_proof)?;
    Ok(StructuredWhirAggregateProof {
        root: commitment_set.root,
        table_variables: commitment_set
            .table_variables
            .iter()
            .map(|variables| *variables as u32)
            .collect(),
        proof_bytes,
    })
}

pub fn verify_structured_whir_openings(
    public_binding: &[u8; 32],
    expected_model: &ModelPcsIdentity,
    openings: &StructuredPcsOpeningSet,
    encoded_proof: &[u8],
) -> Result<(), ExplicitWhirError> {
    validate_model_identity(expected_model)?;
    let expected_table_variables = model_table_variables(expected_model)?;
    let aggregate = StructuredWhirSplitProof::decode(encoded_proof)?;
    let expected_commitments = model_commitment_encodings(expected_model);
    if aggregate.fixed_model.len() != expected_commitments.len()
        || expected_table_variables.len() != expected_commitments.len()
    {
        return Err(ExplicitWhirError::ModelIdentity);
    }
    for ((section, expected), expected_variables) in aggregate
        .fixed_model
        .iter()
        .zip(&expected_commitments)
        .zip(expected_table_variables)
    {
        let table_variables = section
            .table_variables
            .iter()
            .map(|variables| *variables as usize)
            .collect::<Vec<_>>();
        if section.table_variables.len() != 1
            || section.table_variables[0] != expected_variables
            || structured_aliases(section.root, &table_variables)? != [*expected]
        {
            return Err(ExplicitWhirError::ModelIdentity);
        }
    }
    let (fixed_claims, trace_claims) = partition_openings(expected_model, openings)?;
    let fixed_roots = aggregate
        .fixed_model
        .iter()
        .map(|section| section.root)
        .collect::<Vec<_>>();
    let common_binding = split_binding(
        public_binding,
        expected_model,
        &fixed_roots,
        aggregate.trace.root,
    )?;
    for (index, (section, claims)) in aggregate.fixed_model.iter().zip(fixed_claims).enumerate() {
        verify_structured_whir_section(
            &child_binding(
                common_binding,
                STRUCTURED_WHIR_FIXED_MODEL_SCOPE,
                index as u32,
            ),
            &claims,
            section,
        )?;
    }
    verify_structured_whir_section(
        &child_binding(common_binding, STRUCTURED_WHIR_EXECUTION_TRACE_SCOPE, 0),
        &trace_claims,
        &aggregate.trace,
    )
}

fn verify_structured_whir_section(
    transcript_binding: &[u8; 32],
    claims: &[StructuredPcsOpeningClaim],
    aggregate: &StructuredWhirAggregateProof,
) -> Result<(), ExplicitWhirError> {
    let table_variables = aggregate
        .table_variables
        .iter()
        .map(|variables| *variables as usize)
        .collect::<Vec<_>>();
    let aliases = structured_aliases(aggregate.root, &table_variables)?;
    let alias_map = aliases
        .into_iter()
        .enumerate()
        .map(|(index, alias)| (alias, index))
        .collect::<BTreeMap<_, _>>();
    if alias_map.len() != table_variables.len() {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }
    let claims = crate::structured_proof::canonical_openings(claims.to_vec())
        .map_err(|_| ExplicitWhirError::ClaimMismatch)?;
    if claims.is_empty() || claims.len() > crate::MAX_STRUCTURED_OPENING_CLAIMS {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    let mut table_indices = Vec::with_capacity(claims.len());
    let mut used_tables = vec![false; table_variables.len()];
    let mut points = Vec::with_capacity(claims.len());
    let mut evaluations = Vec::with_capacity(claims.len());
    for claim in &claims {
        let table_index = *alias_map
            .get(&claim.commitment)
            .ok_or(ExplicitWhirError::UnknownCommitment)?;
        used_tables[table_index] = true;
        if claim.point.len() != table_variables[table_index] {
            return Err(ExplicitWhirError::PointDimensionMismatch);
        }
        table_indices.push(table_index);
        points.push(convert_structured_point(&claim.point)?);
        evaluations.push(convert_extension(claim.evaluation)?);
    }
    if used_tables.iter().any(|used| !used) {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }
    let native_proof = decode_aggregate_native_proof(&aggregate.proof_bytes)?;
    let canonical = encode_aggregate_native_proof(&native_proof)
        .map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    if canonical != aggregate.proof_bytes {
        return Err(ExplicitWhirError::InvalidEncoding);
    }
    catch_unwind(AssertUnwindSafe(|| {
        verify_native_multi(
            transcript_binding,
            aggregate.root,
            &table_variables,
            &table_indices,
            &points,
            &evaluations,
            &native_proof,
        )
    }))
    .map_err(|_| ExplicitWhirError::BackendPanic)?
}

fn validate_model_identity(identity: &ModelPcsIdentity) -> Result<(), ExplicitWhirError> {
    identity
        .validate()
        .map_err(|_| ExplicitWhirError::ModelIdentity)?;
    if identity.pcs_suite_parameter_digest != structured_whir_suite_parameter_digest() {
        return Err(ExplicitWhirError::ModelIdentity);
    }
    Ok(())
}

fn model_commitment_encodings(identity: &ModelPcsIdentity) -> Vec<[u8; 32]> {
    std::iter::once(identity.base_input_commitment)
        .chain(identity.weight_bank_commitments.iter().copied())
        .collect()
}

fn model_table_variables(identity: &ModelPcsIdentity) -> Result<Vec<u32>, ExplicitWhirError> {
    let batch = u128::from(identity.batch);
    let dimension = u128::from(identity.dimension);
    let layers = u128::from(identity.layers_per_bank);
    let base_elements = batch
        .checked_mul(dimension)
        .ok_or(ExplicitWhirError::ModelIdentity)?;
    let weight_elements = layers
        .checked_mul(dimension)
        .and_then(|elements| elements.checked_mul(dimension))
        .ok_or(ExplicitWhirError::ModelIdentity)?;
    if !base_elements.is_power_of_two() || !weight_elements.is_power_of_two() {
        return Err(ExplicitWhirError::ModelIdentity);
    }
    Ok(std::iter::once(base_elements.ilog2())
        .chain(std::iter::repeat_n(
            weight_elements.ilog2(),
            identity.weight_bank_commitments.len(),
        ))
        .collect())
}

fn partition_openings(
    identity: &ModelPcsIdentity,
    openings: &StructuredPcsOpeningSet,
) -> Result<
    (
        Vec<Vec<StructuredPcsOpeningClaim>>,
        Vec<StructuredPcsOpeningClaim>,
    ),
    ExplicitWhirError,
> {
    let fixed = crate::structured_proof::canonical_openings(openings.fixed_model.clone())
        .map_err(|_| ExplicitWhirError::ClaimMismatch)?;
    let trace = crate::structured_proof::canonical_openings(openings.trace.clone())
        .map_err(|_| ExplicitWhirError::ClaimMismatch)?;
    if fixed
        .len()
        .checked_add(trace.len())
        .is_none_or(|count| count == 0 || count > crate::MAX_STRUCTURED_OPENING_CLAIMS)
    {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    let fixed_commitments = fixed
        .iter()
        .map(|claim| claim.commitment)
        .collect::<BTreeSet<_>>();
    if trace
        .iter()
        .any(|claim| fixed_commitments.contains(&claim.commitment))
    {
        return Err(ExplicitWhirError::OpeningScope);
    }
    let expected = model_commitment_encodings(identity);
    let mut grouped = vec![Vec::new(); expected.len()];
    for claim in fixed {
        let index = expected
            .iter()
            .position(|commitment| *commitment == claim.commitment)
            .ok_or(ExplicitWhirError::OpeningScope)?;
        grouped[index].push(claim);
    }
    if grouped.iter().any(Vec::is_empty) {
        return Err(ExplicitWhirError::CommitmentMismatch);
    }
    Ok((grouped, trace))
}

fn split_binding(
    public_binding: &[u8; 32],
    identity: &ModelPcsIdentity,
    fixed_roots: &[[u8; 32]],
    trace_root: [u8; 32],
) -> Result<[u8; 32], ExplicitWhirError> {
    if fixed_roots.len() != 1 + identity.weight_bank_commitments.len() {
        return Err(ExplicitWhirError::ModelIdentity);
    }
    let mut hasher = Blake3Hasher::new_derive_key(STRUCTURED_WHIR_SPLIT_DOMAIN);
    hasher.update(STRUCTURED_WHIR_SPLIT_COMMON_LABEL);
    hasher.update(&STRUCTURED_WHIR_SPLIT_VERSION.to_le_bytes());
    hasher.update(public_binding);
    hasher.update(
        &identity
            .digest()
            .map_err(|_| ExplicitWhirError::ModelIdentity)?,
    );
    hasher.update(&(fixed_roots.len() as u32).to_le_bytes());
    for (index, root) in fixed_roots.iter().enumerate() {
        hasher.update(&(index as u32).to_le_bytes());
        hasher.update(root);
    }
    hasher.update(&trace_root);
    Ok(*hasher.finalize().as_bytes())
}

fn child_binding(common: [u8; 32], scope: &[u8], index: u32) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(STRUCTURED_WHIR_SPLIT_DOMAIN);
    hasher.update(STRUCTURED_WHIR_SPLIT_CHILD_LABEL);
    hasher.update(&common);
    hasher.update(&(scope.len() as u32).to_le_bytes());
    hasher.update(scope);
    hasher.update(&index.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn verify_native_multi(
    transcript_binding: &[u8],
    commitment: [u8; 32],
    table_variables: &[usize],
    table_indices: &[usize],
    points: &[Point<EF>],
    evaluations: &[EF],
    proof: &NativeProof,
) -> Result<(), ExplicitWhirError> {
    let stacked_variables = validate_stacked_shape(table_variables)?;
    let selectors = plan_selectors(table_variables, stacked_variables);
    let (pcs, mut challenger) = build_pcs(stacked_variables, transcript_binding)?;
    let commitment = MerkleCap::<F, [u8; 32]>::new(vec![commitment]);
    challenger.observe(commitment.clone());
    if proof.initial_ood_answers.len() != pcs.commitment_ood_samples {
        return Err(ExplicitWhirError::Verification);
    }
    let mut statement = EqStatement::initialize(stacked_variables);
    for &evaluation in &proof.initial_ood_answers {
        let point =
            Point::expand_from_univariate(challenger.sample_algebra_element(), stacked_variables);
        challenger.observe_algebra_element(evaluation);
        statement.add_evaluated_constraint(point, evaluation);
    }
    for ((&table_index, point), &evaluation) in table_indices.iter().zip(points).zip(evaluations) {
        let mut lifted = selectors[table_index]
            .as_slice()
            .iter()
            .copied()
            .map(EF::from)
            .collect::<Vec<_>>();
        lifted.extend_from_slice(point.as_slice());
        let lifted = Point::new(lifted);
        challenger.observe_algebra_slice(lifted.as_slice());
        challenger.observe_algebra_element(evaluation);
        statement.add_evaluated_constraint(lifted, evaluation);
    }
    let alpha = challenger.sample_algebra_element();
    let constraint = Constraint::new_eq_only(alpha, statement);
    let mut claimed_evaluation = EF::ZERO;
    constraint.combine_evals(&mut claimed_evaluation);
    WhirVerifier::new(&pcs.config, &pcs.mmcs, VariableOrder::Suffix)
        .verify(
            proof,
            &mut challenger,
            &commitment,
            constraint,
            claimed_evaluation,
        )
        .map(|_| ())
        .map_err(|_| ExplicitWhirError::Verification)
}

fn verify_native(
    transcript_binding: &[u8],
    commitment: [u8; 32],
    points: &[Point<EF>],
    evaluations: &[EF],
    num_variables: usize,
    proof: &NativeProof,
) -> Result<(), ExplicitWhirError> {
    let (pcs, mut challenger) = build_pcs(num_variables, transcript_binding)?;
    let commitment = MerkleCap::<F, [u8; 32]>::new(vec![commitment]);
    challenger.observe(commitment.clone());
    if proof.initial_ood_answers.len() != pcs.commitment_ood_samples {
        return Err(ExplicitWhirError::Verification);
    }
    let mut statement = EqStatement::initialize(num_variables);
    for &evaluation in &proof.initial_ood_answers {
        let point =
            Point::expand_from_univariate(challenger.sample_algebra_element(), num_variables);
        challenger.observe_algebra_element(evaluation);
        statement.add_evaluated_constraint(point, evaluation);
    }
    for (point, &evaluation) in points.iter().zip(evaluations) {
        challenger.observe_algebra_slice(point.as_slice());
        challenger.observe_algebra_element(evaluation);
        statement.add_evaluated_constraint(point.clone(), evaluation);
    }
    let alpha = challenger.sample_algebra_element();
    let constraint = Constraint::new_eq_only(alpha, statement);
    let mut claimed_evaluation = EF::ZERO;
    constraint.combine_evals(&mut claimed_evaluation);
    WhirVerifier::new(&pcs.config, &pcs.mmcs, VariableOrder::Suffix)
        .verify(
            proof,
            &mut challenger,
            &commitment,
            constraint,
            claimed_evaluation,
        )
        .map_err(|_| ExplicitWhirError::Verification)?;
    Ok(())
}

fn build_pcs(
    num_variables: usize,
    transcript_binding: &[u8],
) -> Result<(Pcs, Challenger), ExplicitWhirError> {
    if !(EXPLICIT_WHIR_MIN_VARIABLES..=MAX_STRUCTURED_WHIR_STACKED_VARIABLES)
        .contains(&num_variables)
    {
        return Err(ExplicitWhirError::InvalidVariableCount);
    }
    if transcript_binding.len() > MAX_EXPLICIT_WHIR_BINDING_BYTES {
        return Err(ExplicitWhirError::BindingTooLarge);
    }
    let folding_factor = FoldingFactor::Constant(EXPLICIT_WHIR_FOLDING);
    let (num_rounds, _) = folding_factor
        .compute_number_of_rounds(num_variables)
        .map_err(|error| ExplicitWhirError::Configuration(error.to_string()))?;
    let mut round_log_inv_rates = Vec::with_capacity(num_rounds);
    let mut rate = EXPLICIT_WHIR_STARTING_LOG_INV_RATE;
    for round in 0..num_rounds {
        rate += folding_factor.at_round(round) - 1;
        round_log_inv_rates.push(rate);
    }
    let parameters = ProtocolParameters {
        starting_log_inv_rate: EXPLICIT_WHIR_STARTING_LOG_INV_RATE,
        round_log_inv_rates,
        folding_factor,
        soundness_type: SecurityAssumption::UniqueDecoding,
        security_level: EXPLICIT_WHIR_SECURITY_BITS,
        pow_bits: EXPLICIT_WHIR_POW_BITS,
    };
    let config = WhirConfig::<EF, F, Challenger>::new(num_variables, parameters)
        .map_err(|error| ExplicitWhirError::Configuration(error.to_string()))?;
    if !config.check_pow_bits() {
        return Err(ExplicitWhirError::Configuration(
            "derived WHIR grinding exceeds the configured maximum".to_owned(),
        ));
    }
    let field_hash = FieldHash::new(Blake3 {});
    let compress = Compress::new(Blake3 {});
    let mmcs = WhirMmcs::new(field_hash, compress, 0);
    let dft = Dft::new(1 << config.max_fft_size());
    let pcs = Pcs::new(config, dft, mmcs);
    let mut initial_state = EXPLICIT_WHIR_TRANSCRIPT_DOMAIN.to_vec();
    initial_state.extend_from_slice(&(transcript_binding.len() as u64).to_le_bytes());
    initial_state.extend_from_slice(transcript_binding);
    let mut challenger = Challenger::new(HashChallenger::new(initial_state, Blake3 {}));
    let mut domain_separator = DomainSeparator::new(vec![]);
    pcs.add_domain_separator::<32>(&mut domain_separator);
    domain_separator.observe_domain_separator(&mut challenger);
    Ok((pcs, challenger))
}

fn empty_proof(config: &WhirConfig<EF, F, Challenger>) -> NativeProof {
    NativeProof {
        initial_ood_answers: Vec::new(),
        initial_sumcheck: SumcheckData::default(),
        rounds: (0..config.n_rounds())
            .map(|_| WhirRoundProof::default())
            .collect(),
        final_poly: None,
        final_pow_witness: F::ZERO,
        final_queries: Vec::with_capacity(config.final_queries),
        final_sumcheck: None,
    }
}

fn encode_aggregate_native_proof(proof: &NativeProof) -> Result<Vec<u8>, ExplicitWhirError> {
    let canonical_json = serde_json::to_vec(proof).map_err(|_| ExplicitWhirError::Serialization)?;
    if canonical_json.len() > MAX_STRUCTURED_WHIR_NATIVE_JSON_BYTES {
        return Err(ExplicitWhirError::AggregateProofTooLarge);
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(&canonical_json)
        .map_err(|_| ExplicitWhirError::Serialization)?;
    encoder
        .finish()
        .map_err(|_| ExplicitWhirError::Serialization)
}

fn decode_aggregate_native_proof(encoded: &[u8]) -> Result<NativeProof, ExplicitWhirError> {
    let decoder = ZlibDecoder::new(encoded);
    let mut limited = decoder.take((MAX_STRUCTURED_WHIR_NATIVE_JSON_BYTES + 1) as u64);
    let mut canonical_json = Vec::new();
    limited
        .read_to_end(&mut canonical_json)
        .map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    let decoder = limited.into_inner();
    if canonical_json.len() > MAX_STRUCTURED_WHIR_NATIVE_JSON_BYTES
        || decoder.total_in() != encoded.len() as u64
    {
        return Err(ExplicitWhirError::InvalidEncoding);
    }
    let proof =
        serde_json::from_slice(&canonical_json).map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    let reencoded = serde_json::to_vec(&proof).map_err(|_| ExplicitWhirError::InvalidEncoding)?;
    if reencoded != canonical_json {
        return Err(ExplicitWhirError::InvalidEncoding);
    }
    Ok(proof)
}

fn validate_table(table: &[u64]) -> Result<usize, ExplicitWhirError> {
    if !table.len().is_power_of_two() {
        return Err(ExplicitWhirError::InvalidTableLength);
    }
    let num_variables = table.len().ilog2() as usize;
    validate_num_variables(num_variables)?;
    Ok(num_variables)
}

fn validate_stacked_shape(table_variables: &[usize]) -> Result<usize, ExplicitWhirError> {
    if table_variables.is_empty() || table_variables.len() > MAX_STRUCTURED_WHIR_TABLES {
        return Err(ExplicitWhirError::InvalidTableCount);
    }
    let mut elements = 0usize;
    for &variables in table_variables {
        validate_num_variables(variables)?;
        elements = elements
            .checked_add(
                1usize
                    .checked_shl(variables as u32)
                    .ok_or(ExplicitWhirError::AggregateTableSize)?,
            )
            .ok_or(ExplicitWhirError::AggregateTableSize)?;
    }
    if elements > MAX_STRUCTURED_WHIR_ELEMENTS {
        return Err(ExplicitWhirError::AggregateTableSize);
    }
    let padded = elements
        .checked_next_power_of_two()
        .ok_or(ExplicitWhirError::AggregateTableSize)?;
    let variables = padded.ilog2() as usize;
    if variables > MAX_STRUCTURED_WHIR_STACKED_VARIABLES {
        return Err(ExplicitWhirError::AggregateTableSize);
    }
    Ok(variables)
}

fn plan_selectors(table_variables: &[usize], stacked_variables: usize) -> Vec<Point<F>> {
    let mut order = (0..table_variables.len()).collect::<Vec<_>>();
    order.sort_by_key(|&index| table_variables[index]);
    let mut offset = 0usize;
    let mut selectors = vec![Point::new(Vec::new()); table_variables.len()];
    for table_index in order.into_iter().rev() {
        let variables = table_variables[table_index];
        let selector_variables = stacked_variables - variables;
        selectors[table_index] = Point::hypercube(offset >> variables, selector_variables);
        offset += 1usize << variables;
    }
    selectors
}

fn structured_aliases(
    root: [u8; 32],
    table_variables: &[usize],
) -> Result<Vec<[u8; 32]>, ExplicitWhirError> {
    validate_stacked_shape(table_variables)?;
    let mut layout_hasher = Blake3Hasher::new_derive_key(STRUCTURED_WHIR_ALIAS_DOMAIN);
    layout_hasher.update(STRUCTURED_WHIR_ALIAS_LAYOUT_LABEL);
    layout_hasher.update(&root);
    layout_hasher.update(&(table_variables.len() as u32).to_le_bytes());
    for &variables in table_variables {
        layout_hasher.update(&(variables as u32).to_le_bytes());
    }
    let layout_digest = *layout_hasher.finalize().as_bytes();
    Ok(table_variables
        .iter()
        .enumerate()
        .map(|(index, variables)| {
            let mut hasher = Blake3Hasher::new_derive_key(STRUCTURED_WHIR_ALIAS_DOMAIN);
            hasher.update(STRUCTURED_WHIR_ALIAS_ORACLE_LABEL);
            hasher.update(&root);
            hasher.update(&layout_digest);
            hasher.update(&(index as u32).to_le_bytes());
            hasher.update(&(*variables as u32).to_le_bytes());
            *hasher.finalize().as_bytes()
        })
        .collect())
}

fn validate_num_variables(num_variables: usize) -> Result<(), ExplicitWhirError> {
    if !(EXPLICIT_WHIR_MIN_VARIABLES..=MAX_EXPLICIT_WHIR_VARIABLES).contains(&num_variables) {
        return Err(ExplicitWhirError::InvalidVariableCount);
    }
    Ok(())
}

fn validate_points(
    points: &[Vec<ExtensionElement>],
    num_variables: usize,
) -> Result<(), ExplicitWhirError> {
    if points.is_empty() || points.len() > MAX_EXPLICIT_WHIR_OPENINGS {
        return Err(ExplicitWhirError::InvalidOpeningCount);
    }
    if points.iter().any(|point| point.len() != num_variables) {
        return Err(ExplicitWhirError::PointDimensionMismatch);
    }
    Ok(())
}

fn canonical_base(value: u64) -> Result<F, ExplicitWhirError> {
    if value >= GOLDILOCKS_MODULUS {
        return Err(ExplicitWhirError::NonCanonicalFieldElement);
    }
    F::from_canonical_checked(value).ok_or(ExplicitWhirError::NonCanonicalFieldElement)
}

fn convert_extension(value: ExtensionElement) -> Result<EF, ExplicitWhirError> {
    Ok(EF::new([
        canonical_base(value.limbs[0])?,
        canonical_base(value.limbs[1])?,
        canonical_base(value.limbs[2])?,
    ]))
}

fn external_extension(value: EF) -> ExtensionElement {
    let limbs: &[F] = value.as_basis_coefficients_slice();
    ExtensionElement {
        limbs: [
            limbs[0].as_canonical_u64(),
            limbs[1].as_canonical_u64(),
            limbs[2].as_canonical_u64(),
        ],
    }
}

fn convert_point(point: &[ExtensionElement]) -> Result<Point<EF>, ExplicitWhirError> {
    Ok(Point::new(
        point
            .iter()
            .copied()
            .map(convert_extension)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

fn convert_structured_point(point: &[ExtensionElement]) -> Result<Point<EF>, ExplicitWhirError> {
    let mut point = convert_point(point)?.as_slice().to_vec();
    point.reverse();
    Ok(Point::new(point))
}

fn convert_points(points: &[Vec<ExtensionElement>]) -> Result<Vec<Point<EF>>, ExplicitWhirError> {
    points.iter().map(|point| convert_point(point)).collect()
}

fn extend_poly(poly: &Poly<F>) -> Poly<EF> {
    Poly::new(poly.as_slice().iter().copied().map(EF::from).collect())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ExplicitWhirError> {
    let encoded = bytes
        .get(offset..offset + 4)
        .ok_or(ExplicitWhirError::InvalidEncoding)?;
    Ok(u32::from_le_bytes(
        encoded
            .try_into()
            .map_err(|_| ExplicitWhirError::InvalidEncoding)?,
    ))
}

fn encode_split_blob(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ExplicitWhirError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| ExplicitWhirError::AggregateProofTooLarge)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn take_split_blob<'a>(
    encoded: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], ExplicitWhirError> {
    let length = read_u32(encoded, *offset)? as usize;
    *offset = offset
        .checked_add(4)
        .ok_or(ExplicitWhirError::InvalidEncoding)?;
    let end = offset
        .checked_add(length)
        .ok_or(ExplicitWhirError::InvalidEncoding)?;
    let bytes = encoded
        .get(*offset..end)
        .ok_or(ExplicitWhirError::InvalidEncoding)?;
    *offset = end;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_bank::{BuiltModelBankFixture, SmallModelBankFixture, build_small_model_bank};

    const VERIFIED_BASE_BYTES: [u8; 4] = [0, 125, 250, 1];
    const VERIFIED_LAYER_BYTES: [[u8; 4]; 6] = [
        [2, 3, 4, 5],
        [6, 7, 8, 9],
        [10, 11, 12, 13],
        [14, 15, 16, 17],
        [18, 19, 20, 21],
        [22, 23, 24, 25],
    ];

    struct VerifiedBankFixture {
        bytes: Vec<u8>,
        manifest: ModelBankManifest,
        identity: ModelPcsIdentity,
        base_table: Vec<u64>,
        weight_banks: Vec<Vec<u64>>,
    }

    fn manual_centered_table(bytes: impl IntoIterator<Item = u8>) -> Vec<u64> {
        bytes
            .into_iter()
            .map(centered_model_field_element)
            .collect()
    }

    fn decode_hex_32(value: &str) -> [u8; 32] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn manual_weight_banks(layers: &[[u8; 4]], layers_per_bank: usize) -> Vec<Vec<u64>> {
        layers
            .chunks_exact(layers_per_bank)
            .map(|bank| manual_centered_table(bank.iter().flatten().copied()))
            .collect()
    }

    fn build_bank_with_root(
        layers: &[[u8; 4]],
        pcs_commitment_root: [u8; 32],
    ) -> BuiltModelBankFixture {
        let layer_slices = layers
            .iter()
            .map(|layer| layer.as_slice())
            .collect::<Vec<_>>();
        build_small_model_bank(SmallModelBankFixture {
            model_version: 1,
            dimension: 2,
            batch: 2,
            base_input: &VERIFIED_BASE_BYTES,
            layers: &layer_slices,
            pcs_parameter_digest: structured_whir_suite_parameter_digest(),
            pcs_commitment_root,
        })
        .unwrap()
    }

    fn verified_bank_fixture() -> VerifiedBankFixture {
        let base_table = manual_centered_table(VERIFIED_BASE_BYTES);
        let weight_banks = manual_weight_banks(&VERIFIED_LAYER_BYTES, 2);
        let provisional = StructuredWhirModelCommitmentSet::new(
            StructuredWhirModelMetadata {
                model_version: 1,
                batch: 2,
                dimension: 2,
                layers_per_bank: 2,
                model_byte_root: [0x51; 32],
            },
            base_table.clone(),
            weight_banks.clone(),
        )
        .unwrap();
        let commitment_root = provisional.identity().commitment_root().unwrap();
        let built = build_bank_with_root(&VERIFIED_LAYER_BYTES, commitment_root);
        let mut identity = provisional.identity().clone();
        identity.model_byte_root = built.manifest.raw_blake3_root;
        built.manifest.verify_pcs_identity(&identity).unwrap();
        VerifiedBankFixture {
            bytes: built.bytes,
            manifest: built.manifest,
            identity,
            base_table,
            weight_banks,
        }
    }

    fn split_fixture(
        weight_banks: Vec<Vec<u64>>,
    ) -> (ModelPcsIdentity, StructuredPcsOpeningSet, Vec<u8>) {
        let base = vec![3, 5, 7, 11];
        let trace = vec![79, 83, 89, 97];
        let model = StructuredWhirModelCommitmentSet::new(
            StructuredWhirModelMetadata {
                model_version: 1,
                batch: 2,
                dimension: 2,
                layers_per_bank: 2,
                model_byte_root: [0x51; 32],
            },
            base.clone(),
            weight_banks.clone(),
        )
        .unwrap();
        let identity = model.identity().clone();
        let trace_set = StructuredWhirCommitmentSet::new(vec![trace.clone()]).unwrap();
        let mut fixed_model = vec![StructuredPcsOpeningClaim {
            commitment: identity.base_input_commitment,
            point: vec![ExtensionElement { limbs: [0; 3] }; 2],
            evaluation: ExtensionElement {
                limbs: [base[0], 0, 0],
            },
        }];
        fixed_model.extend(weight_banks.iter().enumerate().map(|(index, weights)| {
            StructuredPcsOpeningClaim {
                commitment: identity.weight_bank_commitments[index],
                point: vec![ExtensionElement { limbs: [0; 3] }; 3],
                evaluation: ExtensionElement {
                    limbs: [weights[0], 0, 0],
                },
            }
        }));
        let openings = StructuredPcsOpeningSet {
            fixed_model,
            trace: vec![StructuredPcsOpeningClaim {
                commitment: trace_set.commitment_for(&trace).unwrap(),
                point: vec![ExtensionElement { limbs: [0; 3] }; 2],
                evaluation: ExtensionElement {
                    limbs: [trace[0], 0, 0],
                },
            }],
        };
        let proof =
            prove_structured_whir_openings(&[0x42; 32], &identity, &model, &trace_set, &openings)
                .unwrap();
        (identity, openings, proof)
    }

    fn table() -> Vec<u64> {
        (0..256).map(|index| (index * index + 17) as u64).collect()
    }

    fn points() -> Vec<Vec<ExtensionElement>> {
        vec![
            (0..8)
                .map(|index| ExtensionElement {
                    limbs: [
                        (index * 7 + 3) as u64,
                        (index * 11 + 5) as u64,
                        (index * 13 + 9) as u64,
                    ],
                })
                .collect(),
            (0..8)
                .map(|index| ExtensionElement {
                    limbs: [
                        (index * 17 + 2) as u64,
                        (index * 19 + 4) as u64,
                        (index * 23 + 6) as u64,
                    ],
                })
                .collect(),
        ]
    }

    fn fixture() -> (
        Vec<u8>,
        ExplicitWhirCommitment,
        Vec<ExplicitWhirOpening>,
        ExplicitWhirProof,
    ) {
        let binding = b"forge-matrix-test-binding".to_vec();
        let (commitment, openings, proof) =
            prove_explicit_whir_openings(&binding, &table(), &points()).unwrap();
        (binding, commitment, openings, proof)
    }

    #[test]
    fn literal_model_bank_vector_derives_the_canonical_tables_and_identity() {
        let artifact = hex::decode(concat!(
            "434d4644424e4b3202000000b800000001000000020000000200000006000000",
            "040000000000000004000000000000001c00000000000000921f746e64fb0502",
            "2fe53c5ddcf048c74d79604680d5716a7299929750744c539a37a20d1bc3e472",
            "41e63ac491185f80f717049e4982c922715b96f44943690ec4d6d139c79d8cd3",
            "27e0b9001c9952dc786ff4a12277067c715fdb1895d2abf5993745b234219cb7",
            "bd26be1e800e1cf8c12a0dcb47677ef001da4d8168a4f8ff007dfa0102030405",
            "060708090a0b0c0d0e0f10111213141516171819"
        ))
        .unwrap();
        let manifest = ModelBankManifest {
            model_version: 1,
            dimension: 2,
            batch: 2,
            layers: 6,
            base_input_bytes: 4,
            bytes_per_layer: 4,
            payload_bytes: 28,
            raw_blake3_root: decode_hex_32(
                "921f746e64fb05022fe53c5ddcf048c74d79604680d5716a7299929750744c53",
            ),
            layer_roots_aggregate: decode_hex_32(
                "9a37a20d1bc3e47241e63ac491185f80f717049e4982c922715b96f44943690e",
            ),
            pcs_parameter_digest: decode_hex_32(
                "c4d6d139c79d8cd327e0b9001c9952dc786ff4a12277067c715fdb1895d2abf5",
            ),
            pcs_commitment_root: decode_hex_32(
                "993745b234219cb7bd26be1e800e1cf8c12a0dcb47677ef001da4d8168a4f8ff",
            ),
        };
        let identity = ModelPcsIdentity {
            model_version: 1,
            batch: 2,
            dimension: 2,
            layers_per_bank: 2,
            model_byte_root: manifest.raw_blake3_root,
            pcs_suite_parameter_digest: manifest.pcs_parameter_digest,
            base_input_commitment: decode_hex_32(
                "0625c5c07d31a47a86c1c3f0c98d4f9ea0b3ce02f5240912bc360b44356834ac",
            ),
            weight_bank_commitments: vec![
                decode_hex_32("3640739c43b725b1a772d0dfd35917fcdee4a8355ba5e7f207c801488120a935"),
                decode_hex_32("d3153726aefb3019c12d663e9aefa0acee76858b1ae286a36dbacbb3a523043b"),
                decode_hex_32("96f2d3afdcd1e81dd8d7baebce4f8d4f5ecd3930eb71e03e27f42d2056768e1a"),
            ],
        };
        let derived = StructuredWhirModelCommitmentSet::from_verified_model_bank(
            Cursor::new(artifact),
            &manifest,
            &identity,
        )
        .unwrap();

        assert_eq!(derived.identity(), &identity);
        assert_eq!(
            derived.sections[0].tables[0],
            vec![GOLDILOCKS_MODULUS - 125, 0, 125, GOLDILOCKS_MODULUS - 124]
        );
        let expected_weight_banks = [
            vec![
                GOLDILOCKS_MODULUS - 123,
                GOLDILOCKS_MODULUS - 122,
                GOLDILOCKS_MODULUS - 121,
                GOLDILOCKS_MODULUS - 120,
                GOLDILOCKS_MODULUS - 119,
                GOLDILOCKS_MODULUS - 118,
                GOLDILOCKS_MODULUS - 117,
                GOLDILOCKS_MODULUS - 116,
            ],
            vec![
                GOLDILOCKS_MODULUS - 115,
                GOLDILOCKS_MODULUS - 114,
                GOLDILOCKS_MODULUS - 113,
                GOLDILOCKS_MODULUS - 112,
                GOLDILOCKS_MODULUS - 111,
                GOLDILOCKS_MODULUS - 110,
                GOLDILOCKS_MODULUS - 109,
                GOLDILOCKS_MODULUS - 108,
            ],
            vec![
                GOLDILOCKS_MODULUS - 107,
                GOLDILOCKS_MODULUS - 106,
                GOLDILOCKS_MODULUS - 105,
                GOLDILOCKS_MODULUS - 104,
                GOLDILOCKS_MODULUS - 103,
                GOLDILOCKS_MODULUS - 102,
                GOLDILOCKS_MODULUS - 101,
                GOLDILOCKS_MODULUS - 100,
            ],
        ];
        for (section, expected) in derived.sections[1..].iter().zip(expected_weight_banks) {
            assert_eq!(section.tables[0], expected);
        }
    }

    #[test]
    fn verified_model_bank_exact_three_bank_derivation_is_deterministic() {
        let fixture = verified_bank_fixture();
        assert_eq!(
            hex::encode(fixture.manifest.raw_blake3_root),
            "921f746e64fb05022fe53c5ddcf048c74d79604680d5716a7299929750744c53"
        );
        assert_eq!(
            hex::encode(fixture.identity.base_input_commitment),
            "0625c5c07d31a47a86c1c3f0c98d4f9ea0b3ce02f5240912bc360b44356834ac"
        );
        assert_eq!(
            fixture
                .identity
                .weight_bank_commitments
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            [
                "3640739c43b725b1a772d0dfd35917fcdee4a8355ba5e7f207c801488120a935",
                "d3153726aefb3019c12d663e9aefa0acee76858b1ae286a36dbacbb3a523043b",
                "96f2d3afdcd1e81dd8d7baebce4f8d4f5ecd3930eb71e03e27f42d2056768e1a",
            ]
        );
        assert_eq!(
            hex::encode(fixture.identity.commitment_root().unwrap()),
            "993745b234219cb7bd26be1e800e1cf8c12a0dcb47677ef001da4d8168a4f8ff"
        );
        assert_eq!(
            hex::encode(fixture.identity.digest().unwrap()),
            "4704cca7add661c12051a445126c9b90bcbeb3ef7069f1d0fb283e3d1f46e12c"
        );
        let derived = StructuredWhirModelCommitmentSet::from_verified_model_bank(
            Cursor::new(&fixture.bytes),
            &fixture.manifest,
            &fixture.identity,
        )
        .unwrap();
        let repeated = StructuredWhirModelCommitmentSet::from_verified_model_bank(
            Cursor::new(&fixture.bytes),
            &fixture.manifest,
            &fixture.identity,
        )
        .unwrap();

        assert_eq!(derived.identity(), &fixture.identity);
        assert_eq!(repeated.identity(), derived.identity());
        assert_eq!(derived.sections.len(), 1 + MAX_MODEL_PCS_WEIGHT_BANKS);
        assert_eq!(derived.sections[0].tables[0], fixture.base_table);
        for (section, expected) in derived.sections[1..].iter().zip(&fixture.weight_banks) {
            assert_eq!(&section.tables[0], expected);
        }
    }

    #[test]
    fn verified_model_bank_centered_byte_boundaries_are_canonical() {
        assert_eq!(centered_model_field_element(0), GOLDILOCKS_MODULUS - 125);
        assert_eq!(centered_model_field_element(124), GOLDILOCKS_MODULUS - 1);
        assert_eq!(centered_model_field_element(125), 0);
        assert_eq!(centered_model_field_element(126), 1);
        assert_eq!(centered_model_field_element(250), 125);
    }

    #[test]
    fn verified_model_bank_rejects_payload_mutations_and_wrong_lengths() {
        let fixture = verified_bank_fixture();

        let mut mutated = fixture.bytes.clone();
        mutated[MODEL_BANK_HEADER_BYTES] ^= 1;
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                Cursor::new(mutated),
                &fixture.manifest,
                &fixture.identity,
            ),
            Err(VerifiedModelBankWhirError::ModelBank(
                ModelBankError::RawRootMismatch
            ))
        ));

        let mut forbidden = fixture.bytes.clone();
        forbidden[MODEL_BANK_HEADER_BYTES] = 251;
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                Cursor::new(forbidden),
                &fixture.manifest,
                &fixture.identity,
            ),
            Err(VerifiedModelBankWhirError::ModelBank(
                ModelBankError::OutOfRange {
                    offset: 0,
                    value: 251
                }
            ))
        ));

        let mut truncated = fixture.bytes.clone();
        truncated.pop();
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                Cursor::new(truncated),
                &fixture.manifest,
                &fixture.identity,
            ),
            Err(VerifiedModelBankWhirError::ModelBank(
                ModelBankError::Truncated
            ))
        ));

        let mut trailing = fixture.bytes.clone();
        trailing.push(0);
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                Cursor::new(trailing),
                &fixture.manifest,
                &fixture.identity,
            ),
            Err(VerifiedModelBankWhirError::ModelBank(
                ModelBankError::TrailingBytes
            ))
        ));
    }

    #[test]
    fn verified_model_bank_rejects_wrong_suite_and_commitment_identity() {
        let fixture = verified_bank_fixture();
        let mut wrong_suite = fixture.identity.clone();
        wrong_suite.pcs_suite_parameter_digest[0] ^= 1;
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                Cursor::new(&fixture.bytes),
                &fixture.manifest,
                &wrong_suite,
            ),
            Err(VerifiedModelBankWhirError::SuiteMismatch)
        ));

        let mut wrong_commitment = fixture.identity.clone();
        wrong_commitment.weight_bank_commitments[0][0] ^= 1;
        let wrong_root = wrong_commitment.commitment_root().unwrap();
        let rebuilt = build_bank_with_root(&VERIFIED_LAYER_BYTES, wrong_root);
        wrong_commitment.model_byte_root = rebuilt.manifest.raw_blake3_root;
        rebuilt
            .manifest
            .verify_pcs_identity(&wrong_commitment)
            .unwrap();
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                Cursor::new(rebuilt.bytes),
                &rebuilt.manifest,
                &wrong_commitment,
            ),
            Err(VerifiedModelBankWhirError::IdentityMismatch)
        ));
    }

    #[test]
    fn verified_model_bank_rejects_partition_and_order_replay() {
        let fixture = verified_bank_fixture();
        let reordered_layers = [
            VERIFIED_LAYER_BYTES[2],
            VERIFIED_LAYER_BYTES[3],
            VERIFIED_LAYER_BYTES[0],
            VERIFIED_LAYER_BYTES[1],
            VERIFIED_LAYER_BYTES[4],
            VERIFIED_LAYER_BYTES[5],
        ];
        let original_root = fixture.identity.commitment_root().unwrap();
        let reordered = build_bank_with_root(&reordered_layers, original_root);
        let mut reordered_identity = fixture.identity.clone();
        reordered_identity.model_byte_root = reordered.manifest.raw_blake3_root;
        reordered
            .manifest
            .verify_pcs_identity(&reordered_identity)
            .unwrap();
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                Cursor::new(reordered.bytes),
                &reordered.manifest,
                &reordered_identity,
            ),
            Err(VerifiedModelBankWhirError::IdentityMismatch)
        ));

        let partition_layers = [
            [31, 32, 33, 34],
            [35, 36, 37, 38],
            [39, 40, 41, 42],
            [43, 44, 45, 46],
            [47, 48, 49, 50],
            [51, 52, 53, 54],
            [55, 56, 57, 58],
            [59, 60, 61, 62],
        ];
        let base_table = manual_centered_table(VERIFIED_BASE_BYTES);
        let first_partition =
            manual_centered_table(partition_layers[..4].iter().flatten().copied());
        let partial = StructuredWhirModelCommitmentSet::new(
            StructuredWhirModelMetadata {
                model_version: 1,
                batch: 2,
                dimension: 2,
                layers_per_bank: 4,
                model_byte_root: [0x61; 32],
            },
            base_table,
            vec![first_partition],
        )
        .unwrap();
        let mut partition_identity = ModelPcsIdentity {
            model_version: 1,
            batch: 2,
            dimension: 2,
            layers_per_bank: 8,
            model_byte_root: [0x61; 32],
            pcs_suite_parameter_digest: structured_whir_suite_parameter_digest(),
            base_input_commitment: partial.identity().base_input_commitment,
            weight_bank_commitments: partial.identity().weight_bank_commitments.clone(),
        };
        let partition_root = partition_identity.commitment_root().unwrap();
        let partitioned = build_bank_with_root(&partition_layers, partition_root);
        partition_identity.model_byte_root = partitioned.manifest.raw_blake3_root;
        partitioned
            .manifest
            .verify_pcs_identity(&partition_identity)
            .unwrap();
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                Cursor::new(partitioned.bytes),
                &partitioned.manifest,
                &partition_identity,
            ),
            Err(VerifiedModelBankWhirError::IdentityMismatch)
        ));
    }

    #[test]
    fn verified_model_bank_rejects_production_shape_without_reading() {
        struct PanicReader;

        impl Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                panic!("bounded preflight must reject before touching the reader")
            }
        }

        let identity = ModelPcsIdentity {
            model_version: 1,
            batch: 128,
            dimension: 4_096,
            layers_per_bank: 128,
            model_byte_root: [0x71; 32],
            pcs_suite_parameter_digest: structured_whir_suite_parameter_digest(),
            base_input_commitment: [0x72; 32],
            weight_bank_commitments: vec![[0x73; 32], [0x74; 32], [0x75; 32]],
        };
        let dimension = u64::from(identity.dimension);
        let base_input_bytes = u64::from(identity.batch) * dimension;
        let bytes_per_layer = dimension * dimension;
        let layers = identity.layers_per_bank * 3;
        let payload_bytes = base_input_bytes + u64::from(layers) * bytes_per_layer;
        let manifest = ModelBankManifest {
            model_version: identity.model_version,
            dimension: identity.dimension,
            batch: identity.batch,
            layers,
            base_input_bytes,
            bytes_per_layer,
            payload_bytes,
            raw_blake3_root: identity.model_byte_root,
            layer_roots_aggregate: [0x76; 32],
            pcs_parameter_digest: identity.pcs_suite_parameter_digest,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        };
        manifest.verify_pcs_identity(&identity).unwrap();

        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                PanicReader,
                &manifest,
                &identity,
            ),
            Err(VerifiedModelBankWhirError::ResearchLimit)
        ));
    }

    #[test]
    fn verified_model_bank_variable_caps_reject_without_reading() {
        struct PanicReader;

        impl Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                panic!("variable-cap preflight must reject before touching the reader")
            }
        }

        fn manifest_for(identity: &ModelPcsIdentity) -> ModelBankManifest {
            let dimension = u64::from(identity.dimension);
            let base_input_bytes = u64::from(identity.batch) * dimension;
            let bytes_per_layer = dimension * dimension;
            let layers = identity.layers_per_bank
                * u32::try_from(identity.weight_bank_commitments.len()).unwrap();
            ModelBankManifest {
                model_version: identity.model_version,
                dimension: identity.dimension,
                batch: identity.batch,
                layers,
                base_input_bytes,
                bytes_per_layer,
                payload_bytes: base_input_bytes + u64::from(layers) * bytes_per_layer,
                raw_blake3_root: identity.model_byte_root,
                layer_roots_aggregate: [0x86; 32],
                pcs_parameter_digest: identity.pcs_suite_parameter_digest,
                pcs_commitment_root: identity.commitment_root().unwrap(),
            }
        }

        let oversized_bank = ModelPcsIdentity {
            model_version: 1,
            batch: 1,
            dimension: 256,
            layers_per_bank: 2,
            model_byte_root: [0x81; 32],
            pcs_suite_parameter_digest: structured_whir_suite_parameter_digest(),
            base_input_commitment: [0x82; 32],
            weight_bank_commitments: vec![[0x83; 32]],
        };
        let oversized_bank_manifest = manifest_for(&oversized_bank);
        assert!(oversized_bank_manifest.payload_bytes < MAX_SMALL_FIXTURE_PAYLOAD_BYTES);
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                PanicReader,
                &oversized_bank_manifest,
                &oversized_bank,
            ),
            Err(VerifiedModelBankWhirError::ResearchLimit)
        ));

        let undersized_base = ModelPcsIdentity {
            model_version: 1,
            batch: 1,
            dimension: 2,
            layers_per_bank: 1,
            model_byte_root: [0x91; 32],
            pcs_suite_parameter_digest: structured_whir_suite_parameter_digest(),
            base_input_commitment: [0x92; 32],
            weight_bank_commitments: vec![[0x93; 32]],
        };
        let undersized_base_manifest = manifest_for(&undersized_base);
        assert!(matches!(
            StructuredWhirModelCommitmentSet::from_verified_model_bank(
                PanicReader,
                &undersized_base_manifest,
                &undersized_base,
            ),
            Err(VerifiedModelBankWhirError::ResearchLimit)
        ));
    }

    #[test]
    fn explicit_arbitrary_points_round_trip() {
        let (binding, commitment, openings, proof) = fixture();
        verify_explicit_whir_openings(&binding, commitment, &openings, &proof).unwrap();
        assert_eq!(proof.num_variables, 8);
        assert!(proof.proof_bytes.len() <= MAX_EXPLICIT_WHIR_PROOF_BYTES);
    }

    #[test]
    fn envelope_round_trip_and_rejects_trailing_bytes() {
        let (binding, commitment, openings, proof) = fixture();
        let encoded = proof.encode().unwrap();
        assert_eq!(ExplicitWhirProof::decode(&encoded).unwrap(), proof);

        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            ExplicitWhirProof::decode(&wrong_magic),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut wrong_version = encoded.clone();
        wrong_version[8..12].copy_from_slice(&(EXPLICIT_WHIR_VERSION + 1).to_le_bytes());
        assert_eq!(
            ExplicitWhirProof::decode(&wrong_version),
            Err(ExplicitWhirError::UnsupportedVersion)
        );

        let mut wrong_length = encoded.clone();
        let claimed_length = u32::from_le_bytes(wrong_length[16..20].try_into().unwrap());
        wrong_length[16..20].copy_from_slice(&(claimed_length + 1).to_le_bytes());
        assert_eq!(
            ExplicitWhirProof::decode(&wrong_length),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            ExplicitWhirProof::decode(&trailing),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut noncanonical_payload = proof.clone();
        noncanonical_payload.proof_bytes.push(b' ');
        assert_eq!(
            verify_explicit_whir_openings(&binding, commitment, &openings, &noncanonical_payload,),
            Err(ExplicitWhirError::InvalidEncoding)
        );
    }

    #[test]
    fn mutations_fail_closed() {
        let (binding, commitment, openings, proof) = fixture();

        let mut wrong_binding = binding.clone();
        wrong_binding[0] ^= 1;
        assert!(
            verify_explicit_whir_openings(&wrong_binding, commitment, &openings, &proof).is_err()
        );

        let mut wrong_commitment = commitment;
        wrong_commitment.0[0] ^= 1;
        assert!(
            verify_explicit_whir_openings(&binding, wrong_commitment, &openings, &proof).is_err()
        );

        let mut wrong_point = openings.clone();
        wrong_point[0].point[0].limbs[0] += 1;
        assert!(verify_explicit_whir_openings(&binding, commitment, &wrong_point, &proof).is_err());

        let mut wrong_evaluation = openings.clone();
        wrong_evaluation[0].evaluation.limbs[0] += 1;
        assert!(
            verify_explicit_whir_openings(&binding, commitment, &wrong_evaluation, &proof).is_err()
        );

        let mut wrong_proof = proof.clone();
        let index = wrong_proof.proof_bytes.len() / 2;
        wrong_proof.proof_bytes[index] ^= 1;
        assert!(
            verify_explicit_whir_openings(&binding, commitment, &openings, &wrong_proof).is_err()
        );
    }

    #[test]
    fn rejects_noncanonical_public_fields_and_wrong_dimensions() {
        let (_, commitment, mut openings, proof) = fixture();
        openings[0].point[0].limbs[0] = GOLDILOCKS_MODULUS;
        assert_eq!(
            verify_explicit_whir_openings(
                b"forge-matrix-test-binding",
                commitment,
                &openings,
                &proof
            ),
            Err(ExplicitWhirError::NonCanonicalFieldElement)
        );

        let mut bad_points = points();
        bad_points[0].pop();
        assert_eq!(
            prove_explicit_whir_openings(b"binding", &table(), &bad_points),
            Err(ExplicitWhirError::PointDimensionMismatch)
        );

        assert_eq!(
            prove_explicit_whir_openings(
                &vec![0; MAX_EXPLICIT_WHIR_BINDING_BYTES + 1],
                &table(),
                &points(),
            ),
            Err(ExplicitWhirError::BindingTooLarge)
        );
    }

    #[test]
    fn minimum_table_round_trip_and_limits_fail_closed() {
        let point = vec![
            ExtensionElement { limbs: [3, 5, 7] },
            ExtensionElement {
                limbs: [11, 13, 17],
            },
        ];
        let (commitment, openings, proof) =
            prove_explicit_whir_openings(b"minimum", &[1, 2, 3, 4], &[point]).unwrap();
        verify_explicit_whir_openings(b"minimum", commitment, &openings, &proof).unwrap();

        assert_eq!(
            prove_explicit_whir_openings(b"bad-length", &[1, 2, 3], &points()),
            Err(ExplicitWhirError::InvalidTableLength)
        );
        assert_eq!(
            prove_explicit_whir_openings(
                b"too-small",
                &[1, 2],
                &[vec![ExtensionElement { limbs: [0; 3] }]],
            ),
            Err(ExplicitWhirError::InvalidVariableCount)
        );
        assert_eq!(
            prove_explicit_whir_openings(
                b"noncanonical",
                &[GOLDILOCKS_MODULUS, 2, 3, 4],
                &[vec![ExtensionElement { limbs: [0; 3] }; 2]],
            ),
            Err(ExplicitWhirError::NonCanonicalFieldElement)
        );
        assert_eq!(
            verify_explicit_whir_openings(b"minimum", commitment, &[], &proof),
            Err(ExplicitWhirError::InvalidOpeningCount)
        );
        assert_eq!(
            verify_explicit_whir_openings(
                &vec![0; MAX_EXPLICIT_WHIR_BINDING_BYTES + 1],
                commitment,
                &openings,
                &proof,
            ),
            Err(ExplicitWhirError::BindingTooLarge)
        );
    }

    #[test]
    fn structured_split_envelope_and_fixed_layout_fail_closed() {
        let weight = vec![13, 17, 19, 23, 29, 31, 37, 41];
        let (identity, openings, proof) = split_fixture(vec![weight]);
        verify_structured_whir_openings(&[0x42; 32], &identity, &openings, &proof).unwrap();

        let mut trailing = proof.clone();
        trailing.push(0);
        assert_eq!(
            verify_structured_whir_openings(&[0x42; 32], &identity, &openings, &trailing),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut truncated = proof.clone();
        truncated.pop();
        assert_eq!(
            verify_structured_whir_openings(&[0x42; 32], &identity, &openings, &truncated),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut zero_sections = proof.clone();
        zero_sections[12..16].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            verify_structured_whir_openings(&[0x42; 32], &identity, &openings, &zero_sections,),
            Err(ExplicitWhirError::ModelIdentity)
        );

        let mut excess_sections = proof.clone();
        excess_sections[12..16]
            .copy_from_slice(&((2 + MAX_MODEL_PCS_WEIGHT_BANKS) as u32).to_le_bytes());
        assert_eq!(
            verify_structured_whir_openings(&[0x42; 32], &identity, &openings, &excess_sections,),
            Err(ExplicitWhirError::ModelIdentity)
        );

        let mut oversized_section = proof.clone();
        oversized_section[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            verify_structured_whir_openings(&[0x42; 32], &identity, &openings, &oversized_section,),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        assert_eq!(
            verify_structured_whir_openings(
                &[0x42; 32],
                &identity,
                &openings,
                &vec![0; crate::MAX_STRUCTURED_PCS_PROOF_BYTES + 1],
            ),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut wrong_layout = StructuredWhirSplitProof::decode(&proof).unwrap();
        let root = wrong_layout.fixed_model[0].root;
        wrong_layout.fixed_model[0].table_variables[0] = 3;
        let mut wrong_identity = identity.clone();
        wrong_identity.base_input_commitment = structured_aliases(root, &[3]).unwrap()[0];
        assert_eq!(
            verify_structured_whir_openings(
                &[0x42; 32],
                &wrong_identity,
                &openings,
                &wrong_layout.encode().unwrap(),
            ),
            Err(ExplicitWhirError::ModelIdentity)
        );
    }

    #[test]
    fn exact_three_bank_split_round_trip_and_order_replay_fails() {
        let weight_0 = vec![13, 17, 19, 23, 29, 31, 37, 41];
        let weight_1 = vec![43, 47, 53, 59, 61, 67, 71, 73];
        let weight_2 = vec![83, 89, 97, 101, 103, 107, 109, 113];
        let (identity, openings, proof) = split_fixture(vec![weight_0, weight_1, weight_2]);
        assert_eq!(
            identity.weight_bank_commitments.len(),
            MAX_MODEL_PCS_WEIGHT_BANKS
        );
        verify_structured_whir_openings(&[0x42; 32], &identity, &openings, &proof).unwrap();

        let mut reordered_identity = identity.clone();
        reordered_identity.weight_bank_commitments.swap(0, 1);
        assert_eq!(
            verify_structured_whir_openings(&[0x42; 32], &reordered_identity, &openings, &proof,),
            Err(ExplicitWhirError::ModelIdentity)
        );

        let mut reordered_proof = StructuredWhirSplitProof::decode(&proof).unwrap();
        reordered_proof.fixed_model.swap(1, 2);
        assert_eq!(
            verify_structured_whir_openings(
                &[0x42; 32],
                &identity,
                &openings,
                &reordered_proof.encode().unwrap(),
            ),
            Err(ExplicitWhirError::ModelIdentity)
        );
    }

    #[test]
    fn equal_fixed_polynomials_are_rejected_as_ambiguous_roles() {
        let weight = vec![13, 17, 19, 23, 29, 31, 37, 41];
        assert!(matches!(
            StructuredWhirModelCommitmentSet::new(
                StructuredWhirModelMetadata {
                    model_version: 1,
                    batch: 2,
                    dimension: 2,
                    layers_per_bank: 2,
                    model_byte_root: [0x51; 32],
                },
                vec![3, 5, 7, 11],
                vec![weight.clone(), weight],
            ),
            Err(ExplicitWhirError::ModelIdentity)
        ));
    }

    #[test]
    fn structured_model_and_trace_openings_are_separate_and_bound() {
        assert_eq!(
            hex::encode(structured_whir_suite_parameter_digest()),
            "c4d6d139c79d8cd327e0b9001c9952dc786ff4a12277067c715fdb1895d2abf5"
        );
        let base = vec![3, 5, 7, 11];
        let weight_0 = vec![13, 17, 19, 23, 29, 31, 37, 41];
        let weight_1 = vec![43, 47, 53, 59, 61, 67, 71, 73];
        let trace = vec![79, 83, 89, 97];
        let metadata = StructuredWhirModelMetadata {
            model_version: 1,
            batch: 2,
            dimension: 2,
            layers_per_bank: 2,
            model_byte_root: [0x21; 32],
        };
        let model = StructuredWhirModelCommitmentSet::new(
            metadata,
            base.clone(),
            vec![weight_0.clone(), weight_1.clone()],
        )
        .unwrap();
        assert!(matches!(
            StructuredWhirModelCommitmentSet::new(
                metadata,
                base[..2].to_vec(),
                vec![weight_0.clone(), weight_1.clone()],
            ),
            Err(ExplicitWhirError::ModelIdentity)
        ));
        assert!(matches!(
            StructuredWhirModelCommitmentSet::new(
                metadata,
                base.clone(),
                vec![weight_0[..4].to_vec(), weight_1.clone()],
            ),
            Err(ExplicitWhirError::ModelIdentity)
        ));
        let trace_set = StructuredWhirCommitmentSet::new(vec![trace.clone()]).unwrap();
        let identity = model.identity().clone();
        let openings = StructuredPcsOpeningSet {
            fixed_model: vec![
                StructuredPcsOpeningClaim {
                    commitment: identity.base_input_commitment,
                    point: vec![ExtensionElement { limbs: [0; 3] }; 2],
                    evaluation: ExtensionElement {
                        limbs: [base[0], 0, 0],
                    },
                },
                StructuredPcsOpeningClaim {
                    commitment: identity.weight_bank_commitments[0],
                    point: vec![ExtensionElement { limbs: [0; 3] }; 3],
                    evaluation: ExtensionElement {
                        limbs: [weight_0[0], 0, 0],
                    },
                },
                StructuredPcsOpeningClaim {
                    commitment: identity.weight_bank_commitments[1],
                    point: vec![ExtensionElement { limbs: [0; 3] }; 3],
                    evaluation: ExtensionElement {
                        limbs: [weight_1[0], 0, 0],
                    },
                },
            ],
            trace: vec![StructuredPcsOpeningClaim {
                commitment: trace_set.commitment_for(&trace).unwrap(),
                point: vec![ExtensionElement { limbs: [0; 3] }; 2],
                evaluation: ExtensionElement {
                    limbs: [trace[0], 0, 0],
                },
            }],
        };
        let binding = [0x42; 32];
        let proof =
            prove_structured_whir_openings(&binding, &identity, &model, &trace_set, &openings)
                .unwrap();
        verify_structured_whir_openings(&binding, &identity, &openings, &proof).unwrap();

        let mut wrong_binding = binding;
        wrong_binding[0] ^= 1;
        assert!(
            verify_structured_whir_openings(&wrong_binding, &identity, &openings, &proof).is_err()
        );

        let mut wrong_suite = identity.clone();
        wrong_suite.pcs_suite_parameter_digest[0] ^= 1;
        assert_eq!(
            verify_structured_whir_openings(&binding, &wrong_suite, &openings, &proof),
            Err(ExplicitWhirError::ModelIdentity)
        );

        let mut swapped = StructuredWhirSplitProof::decode(&proof).unwrap();
        swapped.fixed_model.swap(0, 1);
        assert_eq!(
            verify_structured_whir_openings(
                &binding,
                &identity,
                &openings,
                &swapped.encode().unwrap(),
            ),
            Err(ExplicitWhirError::ModelIdentity)
        );

        let mut wrong_root = StructuredWhirSplitProof::decode(&proof).unwrap();
        wrong_root.fixed_model[0].root[0] ^= 1;
        assert_eq!(
            verify_structured_whir_openings(
                &binding,
                &identity,
                &openings,
                &wrong_root.encode().unwrap(),
            ),
            Err(ExplicitWhirError::ModelIdentity)
        );

        let mut wrong_trace_root = StructuredWhirSplitProof::decode(&proof).unwrap();
        wrong_trace_root.trace.root[0] ^= 1;
        assert!(
            verify_structured_whir_openings(
                &binding,
                &identity,
                &openings,
                &wrong_trace_root.encode().unwrap(),
            )
            .is_err()
        );

        let mut missing_model = StructuredWhirSplitProof::decode(&proof).unwrap();
        missing_model.fixed_model.pop();
        assert_eq!(
            verify_structured_whir_openings(
                &binding,
                &identity,
                &openings,
                &missing_model.encode().unwrap(),
            ),
            Err(ExplicitWhirError::ModelIdentity)
        );

        let mut trailing_stream = StructuredWhirSplitProof::decode(&proof).unwrap();
        trailing_stream.trace.proof_bytes.push(0);
        assert_eq!(
            verify_structured_whir_openings(
                &binding,
                &identity,
                &openings,
                &trailing_stream.encode().unwrap(),
            ),
            Err(ExplicitWhirError::InvalidEncoding)
        );

        let mut crossed_scope = openings.clone();
        crossed_scope
            .fixed_model
            .push(crossed_scope.trace[0].clone());
        assert_eq!(
            verify_structured_whir_openings(&binding, &identity, &crossed_scope, &proof),
            Err(ExplicitWhirError::OpeningScope)
        );

        let other_trace = vec![101, 103, 107, 109];
        let other_trace_set = StructuredWhirCommitmentSet::new(vec![other_trace.clone()]).unwrap();
        assert_eq!(model.identity(), &identity);
        assert_ne!(trace_set.root(), other_trace_set.root());
        let mut other_openings = openings.clone();
        other_openings.trace[0] = StructuredPcsOpeningClaim {
            commitment: other_trace_set.commitment_for(&other_trace).unwrap(),
            point: vec![ExtensionElement { limbs: [0; 3] }; 2],
            evaluation: ExtensionElement {
                limbs: [other_trace[0], 0, 0],
            },
        };
        let other_proof = prove_structured_whir_openings(
            &binding,
            &identity,
            &model,
            &other_trace_set,
            &other_openings,
        )
        .unwrap();
        verify_structured_whir_openings(&binding, &identity, &other_openings, &other_proof)
            .unwrap();
        assert_ne!(proof, other_proof);
    }
}
