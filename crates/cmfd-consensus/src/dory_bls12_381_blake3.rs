//! Fail-closed production projection for proving BLAKE3 inside the BLS/Dory aggregate.
//!
//! This module implements production-owned sources and verifier transcript
//! replay, but does not activate a complete proof. It pins the conservative wire
//! and opening-claim budget for replacing the separate Goldilocks FRI bridge
//! with two BLS12-381 scalar-field arguments:
//!
//! 1. an execution sumcheck over the complete narrow BLAKE3 trace; and
//! 2. a row-indexed LogUp permutation that binds every committed `next` row to
//!    the following committed `local` row.
//!
//! The adjacency argument is required. Merely placing local and next values in
//! one prover-supplied table would not prove that adjacent rows are related.

#[cfg(feature = "whir-prototype")]
use std::io::Cursor;

use dory_pcs::primitives::arithmetic::Field as DoryField;
#[cfg(feature = "whir-prototype")]
use dory_pcs::primitives::arithmetic::Group as DoryGroup;
#[cfg(feature = "whir-prototype")]
use dory_pcs::primitives::transcript::Transcript;
#[cfg(feature = "whir-prototype")]
use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    serialization::{Compress, Validate},
};
#[cfg(feature = "whir-prototype")]
use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression, get_symbolic_constraints,
};
#[cfg(feature = "whir-prototype")]
use p3_field::PrimeField64;
#[cfg(feature = "whir-prototype")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "whir-prototype")]
use crate::dory_bls12_381_compact_artifact::BlsDoryCompactArtifactError;
#[cfg(feature = "whir-prototype")]
use crate::dory_bls12_381_prototype::BlsDoryTranscript;
use crate::dory_bls12_381_prototype::{BlsDoryFr, BlsDoryGt};
#[cfg(feature = "whir-prototype")]
use crate::{ExtensionElement, structured_blake3_narrow::NarrowBlake3Error};
#[cfg(feature = "whir-prototype")]
use crate::{
    GOLDILOCKS_MODULUS, StructuredBlake3Statement,
    dory_bls12_381_aggregate::{
        BlsDoryAggregateLayout, BlsDoryCommittedPolynomial, BlsDoryCommittedPolynomialWriter,
        BlsDoryCompactRowSource, BlsDoryDeferredOpeningSet,
        commit_bls_dory_compact_row_source_with_scratch, source_artifact_spec,
    },
    dory_bls12_381_output_bridge::BlsDoryOutputBridgeStatement,
    dory_bls12_381_prototype::{
        BlsDoryPrototypeError, DeterministicBlsDorySetup, deterministic_bls_dory_setup,
    },
    dory_bls12_381_transpose::{
        BlsDoryTransposeError, BlsDoryWordTransposeArtifact, BlsDoryWordTransposeWriter,
    },
    structured_blake3_identity::{pinned_preprocessed_key, pinned_preprocessed_registry_digest},
    structured_blake3_narrow::{
        F as Goldilocks, NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START, NARROW_BLAKE3_MAIN_WIDTH,
        NARROW_BLAKE3_ORIGINAL_NIBBLES_START, NARROW_BLAKE3_PREPROCESSED_WIDTH,
        NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS, NARROW_BLAKE3_STACK_START, NarrowBlake3Air,
        for_each_canonical_preprocessed_trace_row, for_each_main_trace_row, public_values,
    },
};
use crate::{
    dory_bls12_381_aggregate::{BlsDoryAggregateError, BlsDoryOpeningClaim},
    dory_bls12_381_compact_artifact::BlsDoryCompactArtifactSpec,
    dory_bls12_381_fold_artifact::{
        BlsDoryFoldArtifact, BlsDoryFoldArtifactError, BlsDoryFoldArtifactSpec,
        BlsDoryFoldArtifactWriter,
    },
    dory_bls12_381_layout::{
        BLS_DORY_SHARED_PRODUCTION_CLAIMS, BLS_DORY_SHARED_PRODUCTION_VARIABLES,
        BlsDoryAdditionalFoldSourceProjection, projected_shared_production_scratch_bytes,
        projected_shared_production_scratch_with_additional_sources,
    },
    dory_bls12_381_soundness::{
        BlsDorySoundnessError, BlsDorySoundnessTerm, production_bls_dory_soundness_report,
    },
    dory_bls12_381_transpose::{
        BLS_DORY_TRANSPOSE_AUTHENTICATION_BLOCK_ROWS, projected_bls_dory_transpose_artifact_bytes,
    },
    wire::MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
};

/// Version of this projection only; no wire proof uses it.
pub const BLS_DORY_BLAKE3_PROJECTION_VERSION: u16 = 2;
/// The production final activation contains 128 * 4096 bytes.
pub const BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES: usize = 1 << 19;
/// The narrow tree schedule pads the production computation to 2^20 rows.
pub const BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS: usize = 1 << 20;
/// Twenty Boolean variables address the production trace rows.
pub const BLS_DORY_BLAKE3_TRACE_VARIABLES: usize = 20;
/// BLS-native evaluation uses one accumulator instead of three Goldilocks limbs.
pub const BLS_DORY_BLAKE3_MAIN_WIDTH: usize = 289;
/// The deterministic BLAKE3 schedule retains the existing fixed preprocessing width.
pub const BLS_DORY_BLAKE3_PREPROCESSED_WIDTH: usize = 84;
/// Eleven selector variables separate main and preprocessing tables into 1,024-slot halves.
pub const BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES: usize = 11;
/// Adjacency fixes the source half selector and randomizes the remaining ten variables.
pub const BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES: usize = 10;
/// Twenty trace variables plus eleven source selectors define the shared commitment.
pub const BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES: usize = 31;
/// Dory rows address the eleven high-order selector variables.
pub const BLS_DORY_BLAKE3_SOURCE_DORY_NU: usize = BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES;
/// Dory columns address the twenty low-order trace-row variables.
pub const BLS_DORY_BLAKE3_SOURCE_DORY_SIGMA: usize = BLS_DORY_BLAKE3_TRACE_VARIABLES;
/// Shared production aggregate rows address sixteen variables.
pub const BLS_DORY_BLAKE3_SHARED_DORY_NU: usize = 16;
/// Shared production aggregate columns address seventeen variables.
pub const BLS_DORY_BLAKE3_SHARED_DORY_SIGMA: usize = 17;
/// Ordinary main columns, excluding the native full-field accumulator, for local and next rows.
pub const BLS_DORY_BLAKE3_SIGNED_WORD_TABLES: usize = 2 * (BLS_DORY_BLAKE3_MAIN_WIDTH - 1);
/// Local and next native accumulators require canonical full-field scalars.
pub const BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES: usize = 2;
/// Counter low/high, block length, and flags for local and next preprocessing rows.
pub const BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES: usize = 8;
/// Remaining local and next preprocessing tables are Boolean dictionary codes.
pub const BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES: usize =
    2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH - BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES;
/// Two post-challenge LogUp inverse tables require canonical full-field scalars.
pub const BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES: usize = 2;
#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_OUTPUT_CONTEXT: &str = "CMFD/FORGEMATRIX/OUTPUT/V2";

#[cfg(feature = "whir-prototype")]
const _: () = {
    assert!(NARROW_BLAKE3_STACK_START > NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START);
    assert!(
        BLS_DORY_BLAKE3_MAIN_WIDTH
            == NARROW_BLAKE3_MAIN_WIDTH
                - (NARROW_BLAKE3_STACK_START - NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START)
                + 1
    );
    assert!(BLS_DORY_BLAKE3_PREPROCESSED_WIDTH == NARROW_BLAKE3_PREPROCESSED_WIDTH);
    assert!(
        NARROW_BLAKE3_ORIGINAL_NIBBLES_START + 16 <= NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START
    );
    assert!(
        BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
            == 2 * NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.len()
    );
};

const BLS_DORY_SCALAR_BYTES: u64 = 32;
const BLS_DORY_SIGNED_WORD_BYTES: u64 = 8;
const BLS_DORY_BOOLEAN_CODE_BITS: u64 = 4;
const BLS_DORY_BLAKE3_TRACE_ROWS_U64: u64 = BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS as u64;
/// Literal payload for all execution and inverse tables before authenticated framing.
pub const BLS_DORY_BLAKE3_LITERAL_SOURCE_PAYLOAD_BYTES: u64 =
    (2 * (BLS_DORY_BLAKE3_MAIN_WIDTH + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
        + BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES) as u64
        * BLS_DORY_BLAKE3_TRACE_ROWS_U64
        * BLS_DORY_SCALAR_BYTES;
/// Fixed-width payload for ordinary main local/next tables.
pub const BLS_DORY_BLAKE3_SIGNED_WORD_PAYLOAD_BYTES: u64 = BLS_DORY_BLAKE3_SIGNED_WORD_TABLES
    as u64
    * BLS_DORY_BLAKE3_TRACE_ROWS_U64
    * BLS_DORY_SIGNED_WORD_BYTES;
/// Full-field payload for local/next accumulators and the two inverse tables.
pub const BLS_DORY_BLAKE3_FULL_FIELD_PAYLOAD_BYTES: u64 =
    (BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES + BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES) as u64
        * BLS_DORY_BLAKE3_TRACE_ROWS_U64
        * BLS_DORY_SCALAR_BYTES;
/// Fixed-width payload for the eight non-Boolean preprocessing tables.
pub const BLS_DORY_BLAKE3_PREPROCESSED_WORD_PAYLOAD_BYTES: u64 =
    BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES as u64
        * BLS_DORY_BLAKE3_TRACE_ROWS_U64
        * BLS_DORY_SIGNED_WORD_BYTES;
/// Packed nibble payload for Boolean preprocessing tables.
pub const BLS_DORY_BLAKE3_PREPROCESSED_CODE_PAYLOAD_BYTES: u64 =
    BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES as u64
        * BLS_DORY_BLAKE3_TRACE_ROWS_U64
        * BLS_DORY_BOOLEAN_CODE_BITS
        / 8;
/// Projected authenticated source payload, excluding small framing and later polynomial-fold scratch.
pub const BLS_DORY_BLAKE3_COMPACT_SOURCE_PAYLOAD_BYTES: u64 =
    BLS_DORY_BLAKE3_SIGNED_WORD_PAYLOAD_BYTES
        + BLS_DORY_BLAKE3_FULL_FIELD_PAYLOAD_BYTES
        + BLS_DORY_BLAKE3_PREPROCESSED_WORD_PAYLOAD_BYTES
        + BLS_DORY_BLAKE3_PREPROCESSED_CODE_PAYLOAD_BYTES;
/// The translated execution constraints have degree at most sixteen.
pub const BLS_DORY_BLAKE3_EXECUTION_CONSTRAINT_DEGREE: usize = 16;
/// The native relation keeps 1,296 BLAKE3 constraints and replaces nine
/// three-limb evaluation constraints with three scalar constraints.
pub const BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS: usize = 1_299;
/// Multiplying by the row-equality polynomial raises sumcheck degree by one.
pub const BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE: usize =
    BLS_DORY_BLAKE3_EXECUTION_CONSTRAINT_DEGREE + 1;
/// The row-indexed LogUp adjacency relation has degree at most three after equality weighting.
pub const BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE: usize = 3;
/// Local and next terminal evaluations exposed by the execution sumcheck.
pub const BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS: usize =
    2 * (BLS_DORY_BLAKE3_MAIN_WIDTH + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH);
/// Main words, the native accumulator, and preprocessing use three physical
/// sources and therefore require three execution openings.
pub const BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS: usize = 3;
/// Local/next and inverse terminal evaluations exposed by the adjacency sumcheck.
pub const BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS: usize =
    2 * BLS_DORY_BLAKE3_MAIN_WIDTH + 2;

const BLS_DORY_BLAKE3_EXECUTION_ROUND_ROW_STRIDE: u64 = 1_024;
const BLS_DORY_BLAKE3_EXECUTION_ROUND_TABLE_INDEX: u32 = 0;
const BLS_DORY_BLAKE3_ADJACENCY_ROUND_ROW_STRIDE: u64 = 1_024;
const BLS_DORY_BLAKE3_ADJACENCY_ROUND_TABLE_INDEX: u32 = 1;
/// Equality, first/last/transition selectors, and eight byte-coefficient tables.
const BLS_DORY_BLAKE3_EXECUTION_AUXILIARY_TABLES: usize = 1 + 3 + 8;
const BLS_DORY_BLAKE3_ADJACENCY_AUXILIARY_TABLES: usize = 3;
const BLS_DORY_BLAKE3_EXECUTION_ROUND_CONTEXT_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/BlsDoryBlake3ExecutionRoundContext/v1";
const BLS_DORY_BLAKE3_EXECUTION_ROUND_ROOT_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/BlsDoryBlake3ExecutionRoundRoot/v1";
const BLS_DORY_BLAKE3_ADJACENCY_ROUND_ROOT_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/BlsDoryBlake3AdjacencyRoundRoot/v1";

const _: () = {
    assert!(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS == 746);
    assert!(
        (BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS as u64)
            < BLS_DORY_BLAKE3_EXECUTION_ROUND_ROW_STRIDE
    );
};

type BlsDoryBlake3ExecutionRoundRow = [BlsDoryFr; BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS];

/// Private lineage selector for an out-of-core execution sumcheck round.
#[cfg_attr(not(test), allow(dead_code))]
enum BlsDoryBlake3ExecutionRoundParent<'a> {
    /// The first stored generation is the result of folding the streamed root
    /// rows once, so it binds directly to the root row-stream lineage.
    Root([u8; 32]),
    /// Later generations bind to the authenticated digest of the immediately
    /// preceding round artifact.
    Previous(&'a BlsDoryBlake3ExecutionRoundArtifact),
}

/// RAII writer for a packed row-major execution-round artifact.
///
/// Each physical row stores exactly 746 explicit scalars. The 1,024-scalar
/// logical stride exists only in the authenticated specification; the unused
/// tail is implicit and is never written.
#[cfg_attr(not(test), allow(dead_code))]
struct BlsDoryBlake3ExecutionRoundArtifactWriter {
    inner: BlsDoryFoldArtifactWriter,
    root_lineage: [u8; 32],
    parent_digest: [u8; 32],
    round_index: usize,
    active_rows: u64,
    written_rows: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl BlsDoryBlake3ExecutionRoundArtifactWriter {
    fn create(
        scratch_directory: &std::path::Path,
        active_rows: u64,
        round_index: usize,
        parent: BlsDoryBlake3ExecutionRoundParent<'_>,
    ) -> Result<Self, BlsDoryFoldArtifactError> {
        if active_rows == 0 || !active_rows.is_power_of_two() {
            return Err(BlsDoryFoldArtifactError::InvalidSpec);
        }
        let generation = u32::try_from(round_index)
            .ok()
            .and_then(|round| round.checked_add(1))
            .ok_or(BlsDoryFoldArtifactError::InvalidSpec)?;
        let (root_lineage, parent_digest) = match parent {
            BlsDoryBlake3ExecutionRoundParent::Root(root_lineage) => {
                if round_index != 0 || root_lineage == [0; 32] {
                    return Err(BlsDoryFoldArtifactError::InvalidSpec);
                }
                (root_lineage, root_lineage)
            }
            BlsDoryBlake3ExecutionRoundParent::Previous(previous) => {
                previous.validate_shape()?;
                let expected_round = previous
                    .round_index
                    .checked_add(1)
                    .ok_or(BlsDoryFoldArtifactError::InvalidSpec)?;
                let expected_parent_rows = active_rows
                    .checked_mul(2)
                    .ok_or(BlsDoryFoldArtifactError::InvalidSpec)?;
                if round_index == 0
                    || round_index != expected_round
                    || previous.active_rows != expected_parent_rows
                {
                    return Err(BlsDoryFoldArtifactError::InvalidSpec);
                }
                (previous.root_lineage, previous.digest())
            }
        };
        let context_digest = bls_dory_blake3_execution_round_context(root_lineage);
        if context_digest == [0; 32] || parent_digest == [0; 32] {
            return Err(BlsDoryFoldArtifactError::InvalidSpec);
        }
        let explicit_scalar_count = active_rows
            .checked_mul(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS as u64)
            .ok_or(BlsDoryFoldArtifactError::InvalidSpec)?;
        let scalar_count = active_rows
            .checked_mul(BLS_DORY_BLAKE3_EXECUTION_ROUND_ROW_STRIDE)
            .ok_or(BlsDoryFoldArtifactError::InvalidSpec)?;
        let spec = BlsDoryFoldArtifactSpec {
            context_digest,
            table_index: BLS_DORY_BLAKE3_EXECUTION_ROUND_TABLE_INDEX,
            generation,
            scalar_count,
            explicit_scalar_count,
            parent_digest,
        };
        Ok(Self {
            inner: BlsDoryFoldArtifactWriter::create(scratch_directory, spec)?,
            root_lineage,
            parent_digest,
            round_index,
            active_rows,
            written_rows: 0,
        })
    }

    fn write_row(&mut self, row: &[BlsDoryFr]) -> Result<(), BlsDoryFoldArtifactError> {
        if row.len() != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
            || self.written_rows >= self.active_rows
        {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        self.inner.write_scalars(row)?;
        self.written_rows += 1;
        Ok(())
    }

    fn finish(self) -> Result<BlsDoryBlake3ExecutionRoundArtifact, BlsDoryFoldArtifactError> {
        if self.written_rows != self.active_rows {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        Ok(BlsDoryBlake3ExecutionRoundArtifact {
            inner: self.inner.finish()?,
            root_lineage: self.root_lineage,
            parent_digest: self.parent_digest,
            round_index: self.round_index,
            active_rows: self.active_rows,
        })
    }
}

/// Authenticated packed row-major state for one completed execution fold.
#[cfg_attr(not(test), allow(dead_code))]
struct BlsDoryBlake3ExecutionRoundArtifact {
    inner: BlsDoryFoldArtifact,
    root_lineage: [u8; 32],
    parent_digest: [u8; 32],
    round_index: usize,
    active_rows: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl BlsDoryBlake3ExecutionRoundArtifact {
    fn digest(&self) -> [u8; 32] {
        self.inner.digest()
    }

    fn validate_shape(&self) -> Result<(), BlsDoryFoldArtifactError> {
        if self.root_lineage == [0; 32]
            || self.active_rows == 0
            || !self.active_rows.is_power_of_two()
        {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        let generation = u32::try_from(self.round_index)
            .ok()
            .and_then(|round| round.checked_add(1))
            .ok_or(BlsDoryFoldArtifactError::InvalidArtifact)?;
        let spec = self.inner.spec();
        let context_digest = bls_dory_blake3_execution_round_context(self.root_lineage);
        let explicit_scalar_count = self
            .active_rows
            .checked_mul(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS as u64)
            .ok_or(BlsDoryFoldArtifactError::InvalidArtifact)?;
        let scalar_count = self
            .active_rows
            .checked_mul(BLS_DORY_BLAKE3_EXECUTION_ROUND_ROW_STRIDE)
            .ok_or(BlsDoryFoldArtifactError::InvalidArtifact)?;
        if context_digest == [0; 32]
            || self.parent_digest == [0; 32]
            || (self.round_index == 0 && self.parent_digest != self.root_lineage)
            || spec.context_digest != context_digest
            || spec.table_index != BLS_DORY_BLAKE3_EXECUTION_ROUND_TABLE_INDEX
            || spec.generation != generation
            || spec.scalar_count != scalar_count
            || spec.explicit_scalar_count != explicit_scalar_count
            || spec.parent_digest != self.parent_digest
        {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        Ok(())
    }

    /// Visit adjacent rows in canonical order while retaining only two rows.
    ///
    /// Visitor effects are provisional. A corrupt body or footer can be found
    /// after earlier callbacks, so callers must discard all accumulated state
    /// unless this method returns `Ok(())`.
    fn for_each_row_pair(
        &self,
        mut visitor: impl FnMut(
            &BlsDoryBlake3ExecutionRoundRow,
            &BlsDoryBlake3ExecutionRoundRow,
        ) -> Result<(), BlsDoryFoldArtifactError>,
    ) -> Result<(), BlsDoryFoldArtifactError> {
        self.validate_shape()?;
        if self.active_rows < 2 {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        let mut rows = [
            [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS],
            [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS],
        ];
        let mut row_index = 0u64;
        let mut column = 0usize;
        self.inner.for_each_scalar(|scalar| {
            let pair_row = usize::try_from(row_index & 1)
                .map_err(|_| BlsDoryFoldArtifactError::InvalidArtifact)?;
            rows[pair_row][column] = scalar;
            column += 1;
            if column == BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS {
                row_index += 1;
                column = 0;
                if pair_row == 1 {
                    visitor(&rows[0], &rows[1])?;
                }
            }
            Ok(())
        })?;
        if column != 0 || row_index != self.active_rows {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        Ok(())
    }

    /// Return the sole terminal row only after the entire artifact authenticates.
    fn terminal_row(&self) -> Result<BlsDoryBlake3ExecutionRoundRow, BlsDoryFoldArtifactError> {
        self.validate_shape()?;
        if self.active_rows != 1 {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        let mut row = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS];
        let mut column = 0usize;
        self.inner.for_each_scalar(|scalar| {
            if column >= row.len() {
                return Err(BlsDoryFoldArtifactError::InvalidArtifact);
            }
            row[column] = scalar;
            column += 1;
            Ok(())
        })?;
        if column != row.len() {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        Ok(row)
    }

    #[cfg(test)]
    fn spec(&self) -> BlsDoryFoldArtifactSpec {
        self.inner.spec()
    }

    #[cfg(test)]
    fn path(&self) -> &std::path::Path {
        self.inner.path()
    }
}

fn bls_dory_blake3_execution_round_context(root_lineage: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(BLS_DORY_BLAKE3_EXECUTION_ROUND_CONTEXT_DOMAIN);
    hasher.update(&root_lineage);
    hasher.update(&BLS_DORY_BLAKE3_EXECUTION_ROUND_TABLE_INDEX.to_le_bytes());
    hasher.update(&(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS as u64).to_le_bytes());
    hasher.update(&BLS_DORY_BLAKE3_EXECUTION_ROUND_ROW_STRIDE.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
#[path = "dory_bls12_381_blake3_execution_round_tests.rs"]
mod execution_round_artifact_tests;

#[cfg(feature = "whir-prototype")]
#[path = "dory_bls12_381_blake3_adjacency_round.rs"]
mod adjacency_round_artifact;
#[cfg(feature = "whir-prototype")]
use adjacency_round_artifact::{
    BlsDoryBlake3AdjacencyRoundArtifact, BlsDoryBlake3AdjacencyRoundArtifactWriter,
    BlsDoryBlake3AdjacencyRoundParent, BlsDoryBlake3AdjacencyRoundRow,
    fold_native_blake3_adjacency_artifact,
};

/// Main words, the native accumulator, and post-challenge inverses require
/// three adjacency openings. Preprocessing is not part of adjacency.
pub const BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS: usize = 3;
#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_EXECUTION_SOURCE_TERMINALS: [usize; 3] = [
    BLS_DORY_BLAKE3_SIGNED_WORD_TABLES,
    BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES,
    BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES,
];
#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_ADJACENCY_SOURCE_TERMINALS: [usize; 3] = [
    BLS_DORY_BLAKE3_SIGNED_WORD_TABLES,
    BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES,
    BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES,
];
#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_SOURCE_TERMINALS: [usize; 4] = [
    BLS_DORY_BLAKE3_SIGNED_WORD_TABLES,
    BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES,
    BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES,
    BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES,
];
/// Physical source commitments in canonical order: main words, accumulator,
/// preprocessing, and post-challenge adjacency inverses.
pub const BLS_DORY_BLAKE3_SOURCE_COMMITMENTS: usize = 4;
/// Semantic identity of each physical BLAKE3 coefficient source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum BlsDoryBlake3SourceRole {
    Main = 0,
    Accumulator = 1,
    Preprocessing = 2,
    Inverse = 3,
}

impl BlsDoryBlake3SourceRole {
    const fn index(self) -> usize {
        self as usize
    }
}

/// Canonical physical-source order used only at the aggregate boundary.
pub const BLS_DORY_BLAKE3_SOURCE_ROLES: [BlsDoryBlake3SourceRole; 4] = [
    BlsDoryBlake3SourceRole::Main,
    BlsDoryBlake3SourceRole::Accumulator,
    BlsDoryBlake3SourceRole::Preprocessing,
    BlsDoryBlake3SourceRole::Inverse,
];
/// Canonical source role selected by each execution then adjacency claim.
pub const BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES: [BlsDoryBlake3SourceRole; 6] = [
    BlsDoryBlake3SourceRole::Main,
    BlsDoryBlake3SourceRole::Accumulator,
    BlsDoryBlake3SourceRole::Preprocessing,
    BlsDoryBlake3SourceRole::Main,
    BlsDoryBlake3SourceRole::Accumulator,
    BlsDoryBlake3SourceRole::Inverse,
];
pub const BLS_DORY_BLAKE3_SOURCE_ORDER: &str =
    "main_words,accumulator,preprocessing,adjacency_inverses";
pub const BLS_DORY_BLAKE3_OPENING_SOURCE_ORDER: &str =
    "execution:main,accumulator,preprocessing; adjacency:main,accumulator,inverses";
/// Canonical source selected by each execution then adjacency opening claim.
pub const BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES: [usize; 6] = [
    BlsDoryBlake3SourceRole::Main.index(),
    BlsDoryBlake3SourceRole::Accumulator.index(),
    BlsDoryBlake3SourceRole::Preprocessing.index(),
    BlsDoryBlake3SourceRole::Main.index(),
    BlsDoryBlake3SourceRole::Accumulator.index(),
    BlsDoryBlake3SourceRole::Inverse.index(),
];
/// Complete Dory opening-claim count after composition with the shared proof.
pub const BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS: usize = BLS_DORY_SHARED_PRODUCTION_CLAIMS
    + BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS
    + BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS;
/// Proposed future parser bound. The active aggregate parser remains at 128 claims.
pub const BLS_DORY_BLAKE3_PROPOSED_MAX_OPENING_CLAIMS: usize = 256;

/// Named commitments for the four physical BLAKE3 coefficient sources.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct BlsDoryBlake3SourceCommitments {
    main: BlsDoryGt,
    accumulator: BlsDoryGt,
    preprocessing: BlsDoryGt,
    inverse: BlsDoryGt,
}

impl BlsDoryBlake3SourceCommitments {
    fn commitment(&self, role: BlsDoryBlake3SourceRole) -> &BlsDoryGt {
        match role {
            BlsDoryBlake3SourceRole::Main => &self.main,
            BlsDoryBlake3SourceRole::Accumulator => &self.accumulator,
            BlsDoryBlake3SourceRole::Preprocessing => &self.preprocessing,
            BlsDoryBlake3SourceRole::Inverse => &self.inverse,
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn adjacency_sources(&self) -> BlsDoryBlake3AdjacencySourceCommitments {
        BlsDoryBlake3AdjacencySourceCommitments {
            main: self.main,
            accumulator: self.accumulator,
            preprocessing: self.preprocessing,
        }
    }
}

/// Named commitments absorbed before deriving the adjacency challenges.
#[cfg(feature = "whir-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlsDoryBlake3AdjacencySourceCommitments {
    main: BlsDoryGt,
    accumulator: BlsDoryGt,
    preprocessing: BlsDoryGt,
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryBlake3AdjacencySourceCommitments {
    fn ordered(&self) -> [BlsDoryGt; BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS] {
        [self.main, self.accumulator, self.preprocessing]
    }
}

#[cfg(feature = "whir-prototype")]
fn append_native_blake3_source_descriptor(
    transcript: &mut BlsDoryTranscript,
    role: BlsDoryBlake3SourceRole,
    terminal_count: usize,
    commitment: &BlsDoryGt,
) {
    transcript.append_bytes(b"source-role", &[role as u8]);
    transcript.append_bytes(
        b"source-terminal-count",
        &(terminal_count as u64).to_le_bytes(),
    );
    transcript.append_group(b"source-commitment", commitment);
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_adjacency_transcript(
    bridge: &BlsDoryOutputBridgeStatement,
    trace_rows: usize,
    commitments: &BlsDoryBlake3AdjacencySourceCommitments,
) -> Result<BlsDoryTranscript, BlsDoryAggregateError> {
    if !trace_rows.is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let ordered = commitments.ordered();
    let mut transcript = BlsDoryTranscript::new(b"blake3-native-row-adjacency-sumcheck-v2");
    transcript.append_bytes(b"protocol-version", &2_u16.to_le_bytes());
    transcript.append_bytes(b"challenge-digest", &bridge.challenge_digest());
    transcript.append_bytes(
        b"activation-length",
        &(bridge.final_activation_len() as u64).to_le_bytes(),
    );
    transcript.append_bytes(b"activation-digest", &bridge.final_activation_digest());
    transcript.append_bytes(b"dory-binding", &bridge.transcript_binding());
    transcript.append_bytes(b"trace-rows", &(trace_rows as u64).to_le_bytes());
    transcript.append_bytes(
        b"main-width",
        &(BLS_DORY_BLAKE3_MAIN_WIDTH as u64).to_le_bytes(),
    );
    transcript.append_bytes(
        b"source-count",
        &(BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS as u64).to_le_bytes(),
    );
    for ((role, terminal_count), commitment) in [
        BlsDoryBlake3SourceRole::Main,
        BlsDoryBlake3SourceRole::Accumulator,
        BlsDoryBlake3SourceRole::Preprocessing,
    ]
    .into_iter()
    .zip(BLS_DORY_BLAKE3_EXECUTION_SOURCE_TERMINALS)
    .zip(&ordered)
    {
        append_native_blake3_source_descriptor(&mut transcript, role, terminal_count, commitment);
    }
    Ok(transcript)
}

#[cfg(feature = "whir-prototype")]
fn derive_native_blake3_adjacency_challenges(
    bridge: &BlsDoryOutputBridgeStatement,
    trace_rows: usize,
    commitments: BlsDoryBlake3AdjacencySourceCommitments,
) -> Result<(BlsDoryFr, BlsDoryFr), BlsDoryAggregateError> {
    let mut transcript = native_blake3_adjacency_transcript(bridge, trace_rows, &commitments)?;
    Ok((
        transcript.challenge_scalar(b"row-compression"),
        transcript.challenge_scalar(b"lookup-alpha"),
    ))
}

/// Prover-owned BLAKE3 sources kept in semantic rather than positional form.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
struct BlsDoryBlake3CommittedSources {
    main: BlsDoryCommittedPolynomial,
    accumulator: BlsDoryCommittedPolynomial,
    preprocessing: BlsDoryCommittedPolynomial,
    inverse: BlsDoryCommittedPolynomial,
}

/// Construction-time source bundle retained for the future out-of-core native
/// sumchecks. The transposes remain private and RAII-owned: callers can only
/// validate the complete bundle or consume it into the existing four committed
/// sources.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
struct PreparedBlsDoryBlake3Sources {
    sources: BlsDoryBlake3CommittedSources,
    main_transpose: BlsDoryWordTransposeArtifact,
    preprocessing_transpose: BlsDoryWordTransposeArtifact,
    binding: PreparedBlsDoryBlake3SourceBinding,
}

/// Four authenticated sources after both native sumchecks have been produced.
/// The source artifacts remain owned until verifier replay fixes all six
/// opening points and consumes them into one deferred opening set.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
struct ProvenBlsDoryNativeBlake3Sources {
    sources: BlsDoryBlake3CommittedSources,
    proof: BlsDoryNativeBlake3Proof,
    geometry: BlsDoryBlake3ReplayGeometry,
}

/// Native proof bytes plus the exact verifier-derived six-opening witness used
/// by the shared 128+6 aggregate composer.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct PreparedBlsDoryNativeBlake3Opening {
    pub(crate) opening_statement: BlsDoryBlake3OpeningStatement,
    pub(crate) opening_set: BlsDoryDeferredOpeningSet,
    pub(crate) encoded_native_proof: Vec<u8>,
}

#[cfg(feature = "whir-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedBlsDoryBlake3SourceBinding {
    trace_rows: usize,
    layout: BlsDoryAggregateLayout,
    setup_identity: [u8; 32],
    main_transpose_digest: [u8; 32],
    preprocessing_transpose_digest: [u8; 32],
    source_commitments: BlsDoryBlake3SourceCommitments,
}

#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
impl BlsDoryBlake3CommittedSources {
    fn source(&self, role: BlsDoryBlake3SourceRole) -> &BlsDoryCommittedPolynomial {
        match role {
            BlsDoryBlake3SourceRole::Main => &self.main,
            BlsDoryBlake3SourceRole::Accumulator => &self.accumulator,
            BlsDoryBlake3SourceRole::Preprocessing => &self.preprocessing,
            BlsDoryBlake3SourceRole::Inverse => &self.inverse,
        }
    }

    fn commitments(&self) -> BlsDoryBlake3SourceCommitments {
        BlsDoryBlake3SourceCommitments {
            main: self.main.commitment(),
            accumulator: self.accumulator.commitment(),
            preprocessing: self.preprocessing.commitment(),
            inverse: self.inverse.commitment(),
        }
    }

    fn validate_layout(
        &self,
        trace_rows: usize,
        layout: BlsDoryAggregateLayout,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDoryAggregateError> {
        let expected = [
            trace_rows
                .checked_mul(BLS_DORY_BLAKE3_SIGNED_WORD_TABLES)
                .ok_or(BlsDoryAggregateError::InvalidDimension)?,
            trace_rows
                .checked_mul(BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES)
                .ok_or(BlsDoryAggregateError::InvalidDimension)?,
            trace_rows
                .checked_mul(
                    BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
                        + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES,
                )
                .ok_or(BlsDoryAggregateError::InvalidDimension)?,
            trace_rows
                .checked_mul(BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES)
                .ok_or(BlsDoryAggregateError::InvalidDimension)?,
        ];
        if !trace_rows.is_power_of_two()
            || BLS_DORY_BLAKE3_SOURCE_ROLES
                .into_iter()
                .zip(expected)
                .any(|(role, expected)| {
                    let source = self.source(role);
                    !source.matches_layout(layout, setup)
                        || source.explicit_coefficient_count() != expected
                })
        {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        Ok(())
    }

    #[cfg_attr(test, allow(dead_code))]
    fn into_canonical_deferred_openings(
        self,
        points: [Vec<BlsDoryFr>; BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()],
    ) -> Result<BlsDoryDeferredOpeningSet, BlsDoryAggregateError> {
        Self::validate_lifted_points(
            &points,
            BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES,
            BLS_DORY_SHARED_PRODUCTION_VARIABLES,
        )?;
        self.into_deferred_openings(points)
    }

    #[cfg(test)]
    fn into_canonical_deferred_openings_at_variables(
        self,
        points: [Vec<BlsDoryFr>; BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()],
        source_variables: usize,
        shared_variables: usize,
    ) -> Result<BlsDoryDeferredOpeningSet, BlsDoryAggregateError> {
        Self::validate_lifted_points(&points, source_variables, shared_variables)?;
        self.into_deferred_openings(points)
    }

    fn validate_lifted_points(
        points: &[Vec<BlsDoryFr>; BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()],
        source_variables: usize,
        shared_variables: usize,
    ) -> Result<(), BlsDoryAggregateError> {
        if source_variables > shared_variables
            || points.iter().any(|point| {
                point.len() != shared_variables
                    || point[source_variables..]
                        .iter()
                        .any(|coordinate| *coordinate != BlsDoryFr::zero())
            })
        {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        Ok(())
    }

    fn into_deferred_openings(
        self,
        points: [Vec<BlsDoryFr>; BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()],
    ) -> Result<BlsDoryDeferredOpeningSet, BlsDoryAggregateError> {
        BlsDoryDeferredOpeningSet::new(
            vec![
                self.main,
                self.accumulator,
                self.preprocessing,
                self.inverse,
            ],
            BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.to_vec(),
            points.into_iter().collect(),
        )
    }
}

#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
impl PreparedBlsDoryBlake3Sources {
    fn new(
        sources: BlsDoryBlake3CommittedSources,
        main_transpose: BlsDoryWordTransposeArtifact,
        preprocessing_transpose: BlsDoryWordTransposeArtifact,
        trace_rows: usize,
        layout: BlsDoryAggregateLayout,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryAggregateError> {
        let binding = PreparedBlsDoryBlake3SourceBinding {
            trace_rows,
            layout,
            setup_identity: setup.identity(),
            main_transpose_digest: main_transpose.digest(),
            preprocessing_transpose_digest: preprocessing_transpose.digest(),
            source_commitments: sources.commitments(),
        };
        let mut prepared = Self {
            sources,
            main_transpose,
            preprocessing_transpose,
            binding,
        };
        prepared.validate(trace_rows, layout, setup)?;
        Ok(prepared)
    }

    fn commitments(&self) -> BlsDoryBlake3SourceCommitments {
        self.sources.commitments()
    }

    fn validate(
        &mut self,
        trace_rows: usize,
        layout: BlsDoryAggregateLayout,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDoryAggregateError> {
        validate_native_blake3_source_layout(trace_rows, layout, setup)?;
        self.sources.validate_layout(trace_rows, layout, setup)?;
        if self.binding.trace_rows != trace_rows
            || self.binding.layout != layout
            || self.binding.setup_identity != setup.identity()
            || self.binding.main_transpose_digest != self.main_transpose.digest()
            || self.binding.preprocessing_transpose_digest != self.preprocessing_transpose.digest()
            || self.binding.source_commitments != self.sources.commitments()
            || self.main_transpose.rows() != trace_rows
            || self.main_transpose.columns() != BLS_DORY_BLAKE3_MAIN_WIDTH - 1
            || self.preprocessing_transpose.rows() != trace_rows
            || self.preprocessing_transpose.columns() != BLS_DORY_BLAKE3_PREPROCESSED_WIDTH
        {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        self.main_transpose
            .authenticate()
            .map_err(blake3_transpose_error)?;
        self.preprocessing_transpose
            .authenticate()
            .map_err(blake3_transpose_error)?;
        Ok(())
    }

    /// Stream the 746 execution terminals for every trace row in canonical
    /// dense-table order without materializing the complete 746-column field
    /// matrix.
    ///
    /// Both retained transposes are completely authenticated before the first
    /// row callback. Each bounded batch then retains one local row segment plus
    /// its cyclic successor for all 372 word columns. `maximum_block_rows` may
    /// lower the artifact's preferred authentication-block batch size, but
    /// cannot raise it. Both complete accumulator tables are snapshotted before
    /// callbacks so their authenticated storage is scanned only once per table.
    /// Corruption present on entry therefore yields zero callbacks. Callbacks
    /// remain provisional until this method returns `Ok`: a concurrent mutation
    /// of a later slab can still fail after earlier authenticated rows were
    /// delivered, because an incremental callback cannot be rolled back.
    #[cfg_attr(not(test), allow(dead_code))]
    fn for_each_authenticated_execution_row(
        &mut self,
        maximum_block_rows: usize,
        mut emit: impl FnMut(
            usize,
            &[BlsDoryFr; BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS],
        ) -> Result<(), BlsDoryAggregateError>,
    ) -> Result<(), BlsDoryAggregateError> {
        let trace_rows = self.binding.trace_rows;
        if maximum_block_rows == 0
            || !trace_rows.is_power_of_two()
            || self.binding.main_transpose_digest != self.main_transpose.digest()
            || self.binding.preprocessing_transpose_digest != self.preprocessing_transpose.digest()
            || self.binding.source_commitments != self.sources.commitments()
            || self.main_transpose.rows() != trace_rows
            || self.main_transpose.columns() != BLS_DORY_BLAKE3_MAIN_WIDTH - 1
            || self.preprocessing_transpose.rows() != trace_rows
            || self.preprocessing_transpose.columns() != BLS_DORY_BLAKE3_PREPROCESSED_WIDTH
            || self.sources.accumulator.explicit_coefficient_count()
                != trace_rows
                    .checked_mul(BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES)
                    .ok_or(BlsDoryAggregateError::InvalidDimension)?
        {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }

        // Authentication is deliberately a preflight operation. Corruption
        // present on entry cannot produce a partial row stream.
        self.main_transpose
            .authenticate()
            .map_err(blake3_transpose_error)?;
        self.preprocessing_transpose
            .authenticate()
            .map_err(blake3_transpose_error)?;

        let block_rows = maximum_block_rows
            .min(self.main_transpose.preferred_authenticated_segment_rows())
            .min(
                self.preprocessing_transpose
                    .preferred_authenticated_segment_rows(),
            );
        if block_rows == 0 {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        let stride = block_rows;
        let main_word_count = (BLS_DORY_BLAKE3_MAIN_WIDTH - 1)
            .checked_mul(stride)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let preprocessing_word_count = BLS_DORY_BLAKE3_PREPROCESSED_WIDTH
            .checked_mul(stride)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;

        let mut accumulator_local = Vec::new();
        accumulator_local
            .try_reserve_exact(trace_rows)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        accumulator_local.resize(trace_rows, BlsDoryFr::zero());
        let mut accumulator_next = Vec::new();
        accumulator_next
            .try_reserve_exact(trace_rows)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        accumulator_next.resize(trace_rows, BlsDoryFr::zero());

        // Snapshot both complete accumulator tables before external callbacks.
        // The range reader authenticates the complete backing artifact before
        // exposing either retained range, so released or corrupt storage fails
        // transactionally here.
        self.sources
            .accumulator
            .for_each_authenticated_coefficient_range(0, trace_rows, |index, coefficient| {
                accumulator_local[index] = coefficient;
                Ok(())
            })?;
        self.sources
            .accumulator
            .for_each_authenticated_coefficient_range(
                trace_rows,
                trace_rows,
                |index, coefficient| {
                    accumulator_next[index - trace_rows] = coefficient;
                    Ok(())
                },
            )?;

        // Allocate the large transpose slabs only after both accumulator
        // snapshots have authenticated, keeping the range reader's temporary
        // authentication buffer out of the slab peak.
        let mut main_words = Vec::new();
        main_words
            .try_reserve_exact(main_word_count)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        main_words.resize(main_word_count, 0u64);
        let mut preprocessing_words = Vec::new();
        preprocessing_words
            .try_reserve_exact(preprocessing_word_count)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        preprocessing_words.resize(preprocessing_word_count, 0u64);

        let mut main_local = vec![0u64; BLS_DORY_BLAKE3_MAIN_WIDTH - 1];
        let mut main_next = vec![0u64; BLS_DORY_BLAKE3_MAIN_WIDTH - 1];
        let mut pending_main = vec![0u64; BLS_DORY_BLAKE3_MAIN_WIDTH - 1];
        let mut first_main = vec![0u64; BLS_DORY_BLAKE3_MAIN_WIDTH - 1];
        let mut preprocessing_local = vec![0u64; BLS_DORY_BLAKE3_PREPROCESSED_WIDTH];
        let mut preprocessing_next = vec![0u64; BLS_DORY_BLAKE3_PREPROCESSED_WIDTH];
        let mut pending_preprocessing = vec![0u64; BLS_DORY_BLAKE3_PREPROCESSED_WIDTH];
        let mut first_preprocessing = vec![0u64; BLS_DORY_BLAKE3_PREPROCESSED_WIDTH];
        let mut pending_row = None;
        let mut terminal = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS];

        for block_start in (0..trace_rows).step_by(block_rows) {
            let rows = block_rows.min(trace_rows - block_start);
            for column in 0..BLS_DORY_BLAKE3_MAIN_WIDTH - 1 {
                let start = column * stride;
                self.main_transpose
                    .read_column_segment(column, block_start, &mut main_words[start..start + rows])
                    .map_err(blake3_transpose_error)?;
            }
            for column in 0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
                let start = column * stride;
                self.preprocessing_transpose
                    .read_column_segment(
                        column,
                        block_start,
                        &mut preprocessing_words[start..start + rows],
                    )
                    .map_err(blake3_transpose_error)?;
            }

            copy_transposed_execution_row(&main_words, stride, 0, &mut main_local)?;
            copy_transposed_execution_row(
                &preprocessing_words,
                stride,
                0,
                &mut preprocessing_local,
            )?;
            if block_start == 0 {
                first_main.copy_from_slice(&main_local);
                first_preprocessing.copy_from_slice(&preprocessing_local);
            }
            if let Some(row) = pending_row {
                fill_bls_dory_execution_terminal(
                    &pending_main,
                    &main_local,
                    accumulator_local[row],
                    accumulator_next[row],
                    &pending_preprocessing,
                    &preprocessing_local,
                    &mut terminal,
                )?;
                emit(row, &terminal)?;
            }

            for row_offset in 0..rows.saturating_sub(1) {
                copy_transposed_execution_row(&main_words, stride, row_offset, &mut main_local)?;
                copy_transposed_execution_row(&main_words, stride, row_offset + 1, &mut main_next)?;
                copy_transposed_execution_row(
                    &preprocessing_words,
                    stride,
                    row_offset,
                    &mut preprocessing_local,
                )?;
                copy_transposed_execution_row(
                    &preprocessing_words,
                    stride,
                    row_offset + 1,
                    &mut preprocessing_next,
                )?;
                let row = block_start + row_offset;
                fill_bls_dory_execution_terminal(
                    &main_local,
                    &main_next,
                    accumulator_local[row],
                    accumulator_next[row],
                    &preprocessing_local,
                    &preprocessing_next,
                    &mut terminal,
                )?;
                emit(row, &terminal)?;
            }

            copy_transposed_execution_row(&main_words, stride, rows - 1, &mut pending_main)?;
            copy_transposed_execution_row(
                &preprocessing_words,
                stride,
                rows - 1,
                &mut pending_preprocessing,
            )?;
            pending_row = Some(block_start + rows - 1);
        }

        let final_row = pending_row.ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
        fill_bls_dory_execution_terminal(
            &pending_main,
            &first_main,
            accumulator_local[final_row],
            accumulator_next[final_row],
            &pending_preprocessing,
            &first_preprocessing,
            &mut terminal,
        )?;
        emit(final_row, &terminal)?;
        Ok(())
    }

    /// Stream the 580 adjacency terminals in canonical dense-table order:
    /// main local, main next, inverse local, then inverse next.
    ///
    /// Both inverse tables authenticate and snapshot before the execution-row
    /// stream can invoke the first external callback. Callback effects remain
    /// provisional until the complete execution stream returns `Ok(())`.
    #[cfg_attr(not(test), allow(dead_code))]
    fn for_each_authenticated_adjacency_row(
        &mut self,
        maximum_block_rows: usize,
        mut emit: impl FnMut(
            usize,
            &[BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS],
        ) -> Result<(), BlsDoryAggregateError>,
    ) -> Result<(), BlsDoryAggregateError> {
        let trace_rows = self.binding.trace_rows;
        let inverse_scalars = trace_rows
            .checked_mul(BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        if maximum_block_rows == 0
            || !trace_rows.is_power_of_two()
            || self.sources.inverse.explicit_coefficient_count() != inverse_scalars
        {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }

        let mut inverse_local = Vec::new();
        inverse_local
            .try_reserve_exact(trace_rows)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        inverse_local.resize(trace_rows, BlsDoryFr::zero());
        let mut inverse_next = Vec::new();
        inverse_next
            .try_reserve_exact(trace_rows)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        inverse_next.resize(trace_rows, BlsDoryFr::zero());
        self.sources
            .inverse
            .for_each_explicit_coefficient(|index, coefficient| {
                if index < trace_rows {
                    inverse_local[index] = coefficient;
                } else {
                    inverse_next[index - trace_rows] = coefficient;
                }
            })?;

        let mut terminal = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS];
        self.for_each_authenticated_execution_row(maximum_block_rows, |row, execution| {
            terminal[..2 * BLS_DORY_BLAKE3_MAIN_WIDTH]
                .copy_from_slice(&execution[..2 * BLS_DORY_BLAKE3_MAIN_WIDTH]);
            terminal[2 * BLS_DORY_BLAKE3_MAIN_WIDTH] = inverse_local[row];
            terminal[2 * BLS_DORY_BLAKE3_MAIN_WIDTH + 1] = inverse_next[row];
            emit(row, &terminal)
        })
    }

    fn into_committed_sources(
        self,
    ) -> Result<BlsDoryBlake3CommittedSources, BlsDoryAggregateError> {
        let Self {
            sources,
            main_transpose,
            preprocessing_transpose,
            binding: _,
        } = self;
        drop((main_transpose, preprocessing_transpose));
        Ok(sources)
    }
}

#[cfg(feature = "whir-prototype")]
fn copy_transposed_execution_row(
    columns: &[u64],
    stride: usize,
    row: usize,
    output: &mut [u64],
) -> Result<(), BlsDoryAggregateError> {
    if stride == 0
        || row >= stride
        || columns.len()
            != output
                .len()
                .checked_mul(stride)
                .ok_or(BlsDoryAggregateError::InvalidDimension)?
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    for (column, value) in output.iter_mut().enumerate() {
        *value = columns[column * stride + row];
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn fill_bls_dory_execution_terminal(
    main_local: &[u64],
    main_next: &[u64],
    accumulator_local: BlsDoryFr,
    accumulator_next: BlsDoryFr,
    preprocessing_local: &[u64],
    preprocessing_next: &[u64],
    terminal: &mut [BlsDoryFr; BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS],
) -> Result<(), BlsDoryAggregateError> {
    if main_local.len() != BLS_DORY_BLAKE3_MAIN_WIDTH - 1
        || main_next.len() != BLS_DORY_BLAKE3_MAIN_WIDTH - 1
        || preprocessing_local.len() != BLS_DORY_BLAKE3_PREPROCESSED_WIDTH
        || preprocessing_next.len() != BLS_DORY_BLAKE3_PREPROCESSED_WIDTH
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let mut artifact_column = 0usize;
    for logical_column in 0..BLS_DORY_BLAKE3_MAIN_WIDTH {
        let local_terminal = logical_column;
        let next_terminal = BLS_DORY_BLAKE3_MAIN_WIDTH + logical_column;
        if logical_column == NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START {
            terminal[local_terminal] = accumulator_local;
            terminal[next_terminal] = accumulator_next;
        } else {
            terminal[local_terminal] = BlsDoryFr::from_i64(i64::from_le_bytes(
                main_local[artifact_column].to_le_bytes(),
            ));
            terminal[next_terminal] =
                BlsDoryFr::from_i64(i64::from_le_bytes(main_next[artifact_column].to_le_bytes()));
            artifact_column += 1;
        }
    }
    if artifact_column != BLS_DORY_BLAKE3_MAIN_WIDTH - 1 {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }

    let preprocessing_local_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
    let preprocessing_next_start = preprocessing_local_start + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH;
    for column in 0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
        terminal[preprocessing_local_start + column] =
            bls_dory_centered_goldilocks_word(preprocessing_local[column])?;
        terminal[preprocessing_next_start + column] =
            bls_dory_centered_goldilocks_word(preprocessing_next[column])?;
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn bls_dory_centered_goldilocks_word(canonical: u64) -> Result<BlsDoryFr, BlsDoryAggregateError> {
    if canonical >= GOLDILOCKS_MODULUS {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let centered = if canonical <= GOLDILOCKS_MODULUS / 2 {
        i64::try_from(canonical).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?
    } else {
        -i64::try_from(GOLDILOCKS_MODULUS - canonical)
            .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?
    };
    Ok(BlsDoryFr::from_i64(centered))
}

/// Six points and evaluations emitted by successful verifier transcript replay.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct BlsDoryBlake3OpeningReplay {
    execution_points: [Vec<BlsDoryFr>; BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS],
    execution_evaluations: [BlsDoryFr; BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS],
    adjacency_points: [Vec<BlsDoryFr>; BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS],
    adjacency_evaluations: [BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS],
    opening_binding: [u8; 32],
}

/// Internal binding of replayed claims to named source commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct BlsDoryBlake3OpeningStatement {
    source_commitments: BlsDoryBlake3SourceCommitments,
    points: [Vec<BlsDoryFr>; BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()],
    evaluations: [BlsDoryFr; BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()],
    opening_binding: [u8; 32],
}

#[cfg_attr(not(test), allow(dead_code))]
impl BlsDoryBlake3OpeningStatement {
    pub(crate) fn from_verified_replay(
        source_commitments: BlsDoryBlake3SourceCommitments,
        replay: BlsDoryBlake3OpeningReplay,
    ) -> Result<Self, BlsDoryAggregateError> {
        Self::from_verified_replay_with_geometry(
            source_commitments,
            replay,
            BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY,
        )
    }

    #[cfg(all(test, feature = "whir-prototype"))]
    fn from_verified_replay_at_geometry(
        source_commitments: BlsDoryBlake3SourceCommitments,
        replay: BlsDoryBlake3OpeningReplay,
        geometry: BlsDoryBlake3ReplayGeometry,
    ) -> Result<Self, BlsDoryAggregateError> {
        Self::from_verified_replay_with_geometry(source_commitments, replay, geometry)
    }

    fn from_verified_replay_with_geometry(
        source_commitments: BlsDoryBlake3SourceCommitments,
        replay: BlsDoryBlake3OpeningReplay,
        geometry: BlsDoryBlake3ReplayGeometry,
    ) -> Result<Self, BlsDoryAggregateError> {
        let (points, evaluations, opening_binding) = Self::replay_parts(replay);
        Self::validate_replay_shape(&points, geometry)?;
        Ok(Self {
            source_commitments,
            points,
            evaluations,
            opening_binding,
        })
    }

    fn validate_replay_shape(
        points: &[Vec<BlsDoryFr>; BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()],
        geometry: BlsDoryBlake3ReplayGeometry,
    ) -> Result<(), BlsDoryAggregateError> {
        if geometry.trace_variables >= geometry.source_variables
            || geometry.source_variables > geometry.shared_variables
            || points.iter().any(|point| {
                point.len() != geometry.shared_variables
                    || point[geometry.source_variables..]
                        .iter()
                        .any(|coordinate| *coordinate != BlsDoryFr::zero())
            })
        {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        let adjacency_fixed_selector = geometry.source_variables - 1;
        if points[1][..geometry.trace_variables] != points[0][..geometry.trace_variables]
            || points[2][..geometry.trace_variables] != points[0][..geometry.trace_variables]
            || points[4][..geometry.trace_variables] != points[3][..geometry.trace_variables]
            || points[5][..geometry.trace_variables] != points[3][..geometry.trace_variables]
            || points[3..]
                .iter()
                .any(|point| point[adjacency_fixed_selector] != BlsDoryFr::zero())
        {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        Ok(())
    }

    fn replay_parts(
        replay: BlsDoryBlake3OpeningReplay,
    ) -> (
        [Vec<BlsDoryFr>; BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()],
        [BlsDoryFr; BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()],
        [u8; 32],
    ) {
        let opening_binding = replay.opening_binding;
        let [execution_point_0, execution_point_1, execution_point_2] = replay.execution_points;
        let [adjacency_point_0, adjacency_point_1, adjacency_point_2] = replay.adjacency_points;
        let points = [
            execution_point_0,
            execution_point_1,
            execution_point_2,
            adjacency_point_0,
            adjacency_point_1,
            adjacency_point_2,
        ];
        let [
            execution_evaluation_0,
            execution_evaluation_1,
            execution_evaluation_2,
        ] = replay.execution_evaluations;
        let [
            adjacency_evaluation_0,
            adjacency_evaluation_1,
            adjacency_evaluation_2,
        ] = replay.adjacency_evaluations;
        (
            points,
            [
                execution_evaluation_0,
                execution_evaluation_1,
                execution_evaluation_2,
                adjacency_evaluation_0,
                adjacency_evaluation_1,
                adjacency_evaluation_2,
            ],
            opening_binding,
        )
    }

    /// Canonical verifier-owned binding for the six replayed opening claims.
    pub(crate) fn opening_binding(&self) -> [u8; 32] {
        self.opening_binding
    }

    /// Reconstruct the exact ordered suffix accepted by the composed verifier.
    /// Callers cannot choose a commitment, point, evaluation, or source role.
    pub(crate) fn claims(&self) -> Vec<BlsDoryOpeningClaim> {
        BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES
            .into_iter()
            .zip(&self.points)
            .zip(&self.evaluations)
            .map(|((role, point), evaluation)| BlsDoryOpeningClaim {
                commitment: *self.source_commitments.commitment(role),
                point: point.clone(),
                evaluation: *evaluation,
            })
            .collect()
    }

    /// Bind each claim to its semantic source role, exact lifted point, and
    /// transcript-replayed terminal evaluation.
    pub(crate) fn validate_claims(
        &self,
        claims: &[BlsDoryOpeningClaim],
    ) -> Result<(), BlsDoryAggregateError> {
        if claims.len() != BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES.len()
            || claims
                .iter()
                .zip(BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES)
                .zip(&self.points)
                .zip(&self.evaluations)
                .any(|(((claim, role), point), evaluation)| {
                    claim.commitment != *self.source_commitments.commitment(role)
                        || claim.point != *point
                        || claim.evaluation != *evaluation
                })
        {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        Ok(())
    }
}

#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn read_transposed_shifted_segment(
    artifact: &mut BlsDoryWordTransposeArtifact,
    column: usize,
    direction: usize,
    start_row: usize,
    output: &mut [u64],
) -> Result<usize, BlsDoryTransposeError> {
    if output.is_empty() || start_row >= artifact.rows() || direction > 1 {
        return Err(BlsDoryTransposeError::InvalidShape);
    }
    if direction == 0 {
        return artifact.read_column_segment(column, start_row, output);
    }
    let shifted_start = (start_row + 1) % artifact.rows();
    let first_len = output.len().min(artifact.rows() - shifted_start);
    artifact.read_column_segment(column, shifted_start, &mut output[..first_len])?;
    if first_len < output.len() {
        artifact.read_column_segment(column, 0, &mut output[first_len..])?;
    }
    Ok(output.len())
}

#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn read_lifted_transposed_row(
    artifact: &mut BlsDoryWordTransposeArtifact,
    physical_rows: usize,
    physical_columns: usize,
    logical_tables: usize,
    row_index: usize,
    output: &mut [u64],
    mut logical_role: impl FnMut(usize) -> Option<(usize, usize)>,
) -> Result<usize, BlsDoryTransposeError> {
    if row_index >= physical_rows
        || output.len() != physical_columns
        || logical_tables == 0
        || physical_columns == 0
    {
        return Err(BlsDoryTransposeError::InvalidShape);
    }
    let logical_values = logical_tables
        .checked_mul(artifact.rows())
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    let flat_start = row_index
        .checked_mul(physical_columns)
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    if flat_start >= logical_values {
        return Err(BlsDoryTransposeError::InvalidShape);
    }
    let flat_end = flat_start
        .checked_add(physical_columns)
        .ok_or(BlsDoryTransposeError::InvalidShape)?
        .min(logical_values);
    output.fill(0);
    let mut flat = flat_start;
    let mut written = 0usize;
    while flat < flat_end {
        let logical_table = flat / artifact.rows();
        let table_offset = flat % artifact.rows();
        let take = (artifact.rows() - table_offset).min(flat_end - flat);
        let (direction, column) =
            logical_role(logical_table).ok_or(BlsDoryTransposeError::InvalidShape)?;
        read_transposed_shifted_segment(
            artifact,
            column,
            direction,
            table_offset,
            &mut output[written..written + take],
        )?;
        flat += take;
        written += take;
    }
    Ok(output.len())
}

/// Compact Dory source for local and cyclic-next signed BLAKE3 main columns.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
struct TransposedLocalNextSignedWordRowSource<'a> {
    artifact: &'a mut BlsDoryWordTransposeArtifact,
    physical_rows: usize,
    physical_columns: usize,
    dictionary: [BlsDoryFr; 1],
}

#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
impl<'a> TransposedLocalNextSignedWordRowSource<'a> {
    #[cfg(test)]
    fn new(artifact: &'a mut BlsDoryWordTransposeArtifact, selector_slots: usize) -> Self {
        let trace_rows = artifact.rows();
        Self::new_with_geometry(artifact, selector_slots, trace_rows).expect("valid source shape")
    }

    fn new_for_layout(
        artifact: &'a mut BlsDoryWordTransposeArtifact,
        layout: BlsDoryAggregateLayout,
    ) -> Result<Self, BlsDoryTransposeError> {
        let physical_rows = 1usize
            .checked_shl(layout.nu() as u32)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        let physical_columns = 1usize
            .checked_shl(layout.sigma() as u32)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        Self::new_with_geometry(artifact, physical_rows, physical_columns)
    }

    fn new_with_geometry(
        artifact: &'a mut BlsDoryWordTransposeArtifact,
        physical_rows: usize,
        physical_columns: usize,
    ) -> Result<Self, BlsDoryTransposeError> {
        let explicit = artifact
            .columns()
            .checked_mul(2)
            .and_then(|tables| tables.checked_mul(artifact.rows()))
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        let capacity = physical_rows
            .checked_mul(physical_columns)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        if !physical_rows.is_power_of_two()
            || !physical_columns.is_power_of_two()
            || explicit == 0
            || explicit > capacity
            || !explicit.is_multiple_of(physical_columns)
        {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        Ok(Self {
            artifact,
            physical_rows,
            physical_columns,
            dictionary: [BlsDoryFr::zero()],
        })
    }
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryCompactRowSource for TransposedLocalNextSignedWordRowSource<'_> {
    type Error = BlsDoryTransposeError;

    fn rows(&self) -> usize {
        self.physical_rows
    }

    fn columns(&self) -> usize {
        self.physical_columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.artifact
            .columns()
            .saturating_mul(2)
            .saturating_mul(self.artifact.rows())
    }

    fn word_scalar_count(&self) -> usize {
        self.explicit_scalar_count()
    }

    fn word_group_len(&self) -> usize {
        self.artifact.rows()
    }

    fn signed_word_selectors(&self) -> u64 {
        let word_selectors = self.word_scalar_count() / self.word_group_len();
        if word_selectors >= u64::BITS as usize {
            u64::MAX
        } else {
            (1u64 << word_selectors) - 1
        }
    }

    fn dictionary(&self) -> &[BlsDoryFr] {
        &self.dictionary
    }

    fn read_word_row(
        &mut self,
        row_index: usize,
        output: &mut [u64],
    ) -> Result<usize, Self::Error> {
        let local_columns = self.artifact.columns();
        read_lifted_transposed_row(
            self.artifact,
            self.physical_rows,
            self.physical_columns,
            2 * local_columns,
            row_index,
            output,
            |logical_table| {
                (logical_table < 2 * local_columns).then_some((
                    usize::from(logical_table >= local_columns),
                    logical_table % local_columns,
                ))
            },
        )
    }

    fn read_code_row(
        &mut self,
        _row_index: usize,
        _output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        Err(BlsDoryTransposeError::InvalidShape)
    }
}

#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn preprocessed_physical_role(physical_slot: usize) -> Option<(usize, usize)> {
    let word_columns = NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.len();
    let boolean_columns = BLS_DORY_BLAKE3_PREPROCESSED_WIDTH.checked_sub(word_columns)?;
    if physical_slot < word_columns {
        return Some((0, NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS[physical_slot]));
    }
    if physical_slot < 2 * word_columns {
        return Some((
            1,
            NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS[physical_slot - word_columns],
        ));
    }
    let code_slot = physical_slot.checked_sub(2 * word_columns)?;
    if code_slot >= 2 * boolean_columns {
        return None;
    }
    let direction = code_slot / boolean_columns;
    let boolean_index = code_slot % boolean_columns;
    let column = (0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
        .filter(|column| !NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.contains(column))
        .nth(boolean_index)?;
    Some((direction, column))
}

#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn preprocessed_physical_terminal_index(physical_slot: usize) -> Option<usize> {
    let (direction, column) = preprocessed_physical_role(physical_slot)?;
    direction
        .checked_mul(BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)?
        .checked_add(column)
}

/// Compact Dory source for reordered BLAKE3 preprocessing words and Boolean codes.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
struct TransposedPreprocessedRowSource<'a> {
    artifact: &'a mut BlsDoryWordTransposeArtifact,
    physical_rows: usize,
    physical_columns: usize,
    code_scratch: Vec<u64>,
    dictionary: [BlsDoryFr; 2],
}

#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
impl<'a> TransposedPreprocessedRowSource<'a> {
    #[cfg(test)]
    fn new(artifact: &'a mut BlsDoryWordTransposeArtifact, selector_slots: usize) -> Self {
        let trace_rows = artifact.rows();
        Self::new_with_geometry(artifact, selector_slots, trace_rows).expect("valid source shape")
    }

    fn new_for_layout(
        artifact: &'a mut BlsDoryWordTransposeArtifact,
        layout: BlsDoryAggregateLayout,
    ) -> Result<Self, BlsDoryTransposeError> {
        let physical_rows = 1usize
            .checked_shl(layout.nu() as u32)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        let physical_columns = 1usize
            .checked_shl(layout.sigma() as u32)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        Self::new_with_geometry(artifact, physical_rows, physical_columns)
    }

    fn new_with_geometry(
        artifact: &'a mut BlsDoryWordTransposeArtifact,
        physical_rows: usize,
        physical_columns: usize,
    ) -> Result<Self, BlsDoryTransposeError> {
        let expected_code_tables = 2usize
            .checked_mul(
                BLS_DORY_BLAKE3_PREPROCESSED_WIDTH
                    .checked_sub(NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.len())
                    .ok_or(BlsDoryTransposeError::InvalidShape)?,
            )
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        if artifact.columns() != BLS_DORY_BLAKE3_PREPROCESSED_WIDTH
            || expected_code_tables != BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES
        {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        let explicit = (BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
            + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES)
            .checked_mul(artifact.rows())
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        let word_scalars = BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
            .checked_mul(artifact.rows())
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        let capacity = physical_rows
            .checked_mul(physical_columns)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        if !physical_rows.is_power_of_two()
            || !physical_columns.is_power_of_two()
            || explicit > capacity
            || !word_scalars.is_multiple_of(physical_columns)
        {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        Ok(Self {
            code_scratch: vec![0; physical_columns],
            artifact,
            physical_rows,
            physical_columns,
            dictionary: [BlsDoryFr::zero(), BlsDoryFr::from_u64(1)],
        })
    }
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryCompactRowSource for TransposedPreprocessedRowSource<'_> {
    type Error = BlsDoryTransposeError;

    fn rows(&self) -> usize {
        self.physical_rows
    }

    fn columns(&self) -> usize {
        self.physical_columns
    }

    fn explicit_scalar_count(&self) -> usize {
        (BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES)
            .saturating_mul(self.artifact.rows())
    }

    fn word_scalar_count(&self) -> usize {
        BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES.saturating_mul(self.artifact.rows())
    }

    fn code_bits(&self) -> u8 {
        4
    }

    fn word_group_len(&self) -> usize {
        self.artifact.rows()
    }

    fn signed_word_selectors(&self) -> u64 {
        0
    }

    fn dictionary(&self) -> &[BlsDoryFr] {
        &self.dictionary
    }

    fn read_word_row(
        &mut self,
        row_index: usize,
        output: &mut [u64],
    ) -> Result<usize, Self::Error> {
        if row_index
            .checked_mul(self.physical_columns)
            .is_none_or(|start| start >= self.word_scalar_count())
        {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        read_lifted_transposed_row(
            self.artifact,
            self.physical_rows,
            self.physical_columns,
            2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
            row_index,
            output,
            preprocessed_physical_role,
        )
    }

    fn read_code_row(&mut self, row_index: usize, output: &mut [u8]) -> Result<usize, Self::Error> {
        let row_start = row_index
            .checked_mul(self.physical_columns)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        if row_start < self.word_scalar_count()
            || row_start >= self.explicit_scalar_count()
            || output.len() != self.physical_columns
        {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        let read = read_lifted_transposed_row(
            self.artifact,
            self.physical_rows,
            self.physical_columns,
            2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
            row_index,
            &mut self.code_scratch,
            preprocessed_physical_role,
        )?;
        for (code, value) in output.iter_mut().zip(&self.code_scratch) {
            *code = u8::try_from(*value)
                .ok()
                .filter(|code| *code <= 1)
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
        }
        Ok(read)
    }
}

const SCALAR_BYTES: usize = 32;
pub(crate) const GT_BYTES: usize = 576;
pub(crate) const COMPONENT_HEADER_BYTES: usize = 20;
const TRANSCRIPT_DIGEST_BYTES: usize = 32;
const CANDIDATE_PAYLOAD_HEADER_BYTES: usize = 18;
const CURRENT_SHARED_PRODUCTION_BYTES: usize = 133_409;
pub(crate) const BLS_DORY_BLAKE3_EXECUTION_PROOF_MAGIC: [u8; 8] = *b"CFB3EX01";
pub(crate) const BLS_DORY_BLAKE3_ADJACENCY_PROOF_MAGIC: [u8; 8] = *b"CFB3AD01";
#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_COMPONENT_RESERVED: u16 = 0;

/// Version of the canonical native BLAKE3 component wire grammar.
pub const BLS_DORY_BLAKE3_NATIVE_PROOF_VERSION: u16 = 1;

/// Conservative execution-component wire projection.
pub const BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES: usize = COMPONENT_HEADER_BYTES
    + BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS * GT_BYTES
    + BLS_DORY_BLAKE3_TRACE_VARIABLES
        * (BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1)
        * SCALAR_BYTES
    + BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS * SCALAR_BYTES
    + TRANSCRIPT_DIGEST_BYTES;
/// Conservative adjacency-component wire projection.
pub const BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES: usize = COMPONENT_HEADER_BYTES
    + GT_BYTES
    + BLS_DORY_BLAKE3_TRACE_VARIABLES
        * (BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1)
        * SCALAR_BYTES
    + BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS * SCALAR_BYTES
    + TRANSCRIPT_DIGEST_BYTES;
/// Projected V3 payload after replacing, rather than composing with, the FRI bridge.
pub const BLS_DORY_BLAKE3_PROJECTED_V3_BYTES: usize = CURRENT_SHARED_PRODUCTION_BYTES
    + CANDIDATE_PAYLOAD_HEADER_BYTES
    + BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES
    + BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES;
/// Remaining room under the existing V3 structured-proof allowance.
pub const BLS_DORY_BLAKE3_PROJECTED_HEADROOM_BYTES: usize =
    MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES - BLS_DORY_BLAKE3_PROJECTED_V3_BYTES;

const _: () = {
    assert!(BLS_DORY_BLAKE3_PROJECTED_V3_BYTES < MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES);
    assert!(BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS <= BLS_DORY_BLAKE3_PROPOSED_MAX_OPENING_CLAIMS);
    assert!(
        BLS_DORY_BLAKE3_SOURCE_DORY_NU + BLS_DORY_BLAKE3_SOURCE_DORY_SIGMA
            == BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES
    );
    assert!(
        BLS_DORY_BLAKE3_SHARED_DORY_NU + BLS_DORY_BLAKE3_SHARED_DORY_SIGMA
            == BLS_DORY_SHARED_PRODUCTION_VARIABLES
    );
    assert!(
        BLS_DORY_BLAKE3_SIGNED_WORD_TABLES
            + BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES
            + BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
            + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES
            == BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
    );
    assert!(
        BLS_DORY_BLAKE3_COMPACT_SOURCE_PAYLOAD_BYTES < BLS_DORY_BLAKE3_LITERAL_SOURCE_PAYLOAD_BYTES
    );
    assert!(
        BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len()
            == BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS + BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS
    );
    assert!(!BLS_DORY_BLAKE3_PRODUCTION_READY);
};

/// This is a bounded design projection, not an implemented production proof.
pub const BLS_DORY_BLAKE3_PRODUCTION_READY: bool = false;
/// Gates that must remain closed before this design can replace the FRI bridge.
pub const BLS_DORY_BLAKE3_PRODUCTION_BLOCKERS: [&str; 4] = [
    "production-owned main and preprocessing row-source primitives now transpose every ordinary column, derive cyclic next rows without duplicate scratch, reject malformed shapes and non-Boolean codes, and are pinned to the narrow-trace schema by compile-time assertions; a production-owned named bundle constructs main, accumulator, preprocessing, and bounded-batch adjacency-inverse sources, derives LogUp challenges from the bridge and the three named pre-inverse commitments, preserves exact dense commitment/opening bytes, and rejects mismatched statements, terminal evaluations, zero denominators, corrupt sources, setup mismatches, and source-role swaps; verifier-owned v2 execution and adjacency replay verifies the complete terminal relations, derives the fixed named six points and evaluations, fixes the adjacency half selector and lift coordinates to zero, binds the exact Dory layout and setup identity, and loads an opaque preprocessing pin from the byte-identical two-run ceremony record; native source construction and replay derive one normalized statement solely from the bridge, fixing the unused legacy Goldilocks point and evaluation to zero so callers cannot supply a parallel opening; a bounded canonical native wire now carries only the four named commitments and two fixed-shape sumchecks, and the layout composer accepts only the opaque replay statement before authenticating the exact 128-plus-6 partition; the version-2 top-level candidate envelope routes its shared frame and native frame through that atomic composer and rejects the legacy separate bridge; a bounded release-only 21-variable regression composes the authentic topology in one consuming 134-claim aggregate, verifies canonical envelope routing and tamper rejection, and leaves zero retained scratch; the authenticated out-of-core execution and adjacency sumchecks match their dense v2 proofs byte for byte, reject corrupt sources, and clean every round artifact; a fail-closed materialized production candidate constructor derives every public field, rejects losing work before proving, composes the exact shared and native openings, and self-verifies the canonical envelope, but the authenticated streaming execution-witness provider, final pinned model artifact, and unchanged exact n=33 run are still not implemented or measured",
    "the executable union bound covers execution, row compression, lookup, sumchecks, and selector batching at a 219-bit algebraic floor, but it is not independently reviewed and does not replace Dory knowledge-soundness or Fiat-Shamir analysis",
    "the public shared aggregate parser intentionally remains capped at 128; only the version-2 top-level candidate route reaches the specialized exact-134 verifier after deriving the native six-claim suffix from opaque replay, so unrelated callers cannot widen the aggregate boundary",
    "a nonallocating fail-closed budget checker accounts for 5,117,051,496 bytes of framed BLAKE3 sources and 3,120,562,320 bytes of source-construction transposes; authenticated execution rounds require an 18,773,704,968-byte maximum parent/child overlap and a 27,011,318,784-byte complete stage, while adjacency rounds require 14,596,178,184 bytes of parent/child overlap and a 22,833,792,000-byte complete stage; known execution and adjacency root-stream vector payloads are 859,844,224 and 624,963,200 bytes respectively, excluding allocator, stack, authentication, setup, Rayon, and I/O overhead; the canonical four-source fold lifecycle projects a 35,304,177,312-byte aggregate-stage peak, or 38,424,739,632 bytes if both transposes remain live, and the checker rejects caller-supplied measurements below provisional 50 GiB scratch and 4 GiB memory floors; it is not yet wired to a production run, and the complete n=33 proof size, proving time, verification time, peak memory, and peak scratch have not been measured or audited",
];

/// Version of the reproducible native-BLAKE3 preprocessing commitment record.
#[cfg(feature = "whir-prototype")]
pub const BLS_DORY_BLAKE3_PREPROCESSING_RECORD_VERSION: u16 = 1;
#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_PREPROCESSING_RECORD_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/BlsDoryBlake3PreprocessingRecord/v1";
#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD: &[u8] =
    include_bytes!("../data/bls_dory_blake3_preprocessing_record_v1.json");
#[cfg(feature = "whir-prototype")]
pub(crate) const BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD_DIGEST: [u8; 32] = [
    0x98, 0x7a, 0xcd, 0x2e, 0xca, 0x3e, 0x41, 0xbb, 0xc2, 0xab, 0xbd, 0xf6, 0xf9, 0x1a, 0x5f, 0x7b,
    0xa9, 0x07, 0x55, 0x52, 0x33, 0x35, 0x3e, 0xda, 0x10, 0x9c, 0x28, 0x11, 0x4b, 0xb4, 0xb8, 0xb1,
];

/// Auditable output of the deterministic production preprocessing-only job.
///
/// This record is a reproducibility artifact. Producing or validating a new
/// record does not replace the twice-reproduced embedded registry
/// entry used by the production verifier pin.
#[cfg(feature = "whir-prototype")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlsDoryBlake3PreprocessingRecord {
    pub record_version: u16,
    pub projection_version: u16,
    pub native_proof_version: u16,
    pub activation_len: u64,
    pub cell_point_variables: u32,
    pub trace_rows: u64,
    pub preprocessed_width: u32,
    pub preprocessed_word_tables: u32,
    pub preprocessed_code_tables: u32,
    pub preprocessing_terminal_count: u32,
    pub trace_variables: u32,
    pub source_variables: u32,
    pub shared_variables: u32,
    pub dory_nu: u32,
    pub dory_sigma: u32,
    pub setup_max_log_n: u32,
    pub setup_identity: String,
    pub preprocessing_bls_commitment: String,
    pub transpose_digest: String,
    pub transpose_bytes: u64,
    pub compact_artifact_context_digest: String,
    pub compact_artifact_digest: String,
    pub compact_artifact_bytes: u64,
    pub compact_scalar_count: u64,
    pub compact_explicit_scalar_count: u64,
    pub compact_word_scalar_count: u64,
    pub compact_word_bytes: u8,
    pub compact_code_bits: u8,
    pub compact_word_width_codes: u64,
    pub compact_word_group_len: u64,
    pub compact_signed_word_selectors: u64,
    pub fri_preprocessed_registry_digest: String,
    pub fri_preprocessed_root: [String; 4],
    pub record_digest: String,
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryBlake3PreprocessingRecord {
    /// Validate canonical encodings and every production geometry constant.
    ///
    /// This is a self-consistency check. Trusting the resulting record still
    /// requires a byte-identical reproduction and reviewed registry-digest
    /// update before it can replace the embedded production record.
    pub fn validate(&self) -> Result<(), BlsDoryBlake3PreprocessingRecordError> {
        let expected_terminal_count =
            BLS_DORY_BLAKE3_SOURCE_TERMINALS[BlsDoryBlake3SourceRole::Preprocessing.index()];
        let expected_explicit_scalars = expected_terminal_count
            .checked_mul(BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS)
            .ok_or(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "compact explicit scalar count",
            ))?;
        let expected_word_scalars = BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
            .checked_mul(BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS)
            .ok_or(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "compact word scalar count",
            ))?;
        let expected_scalar_count = 1_u64
            .checked_shl(BLS_DORY_SHARED_PRODUCTION_VARIABLES as u32)
            .ok_or(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "compact scalar count",
            ))?;
        if self.record_version != BLS_DORY_BLAKE3_PREPROCESSING_RECORD_VERSION
            || self.projection_version != BLS_DORY_BLAKE3_PROJECTION_VERSION
            || self.native_proof_version != BLS_DORY_BLAKE3_NATIVE_PROOF_VERSION
            || self.activation_len != BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES as u64
            || self.cell_point_variables != BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES.ilog2()
            || self.trace_rows != BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS as u64
            || self.preprocessed_width != BLS_DORY_BLAKE3_PREPROCESSED_WIDTH as u32
            || self.preprocessed_word_tables != BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES as u32
            || self.preprocessed_code_tables != BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES as u32
            || self.preprocessing_terminal_count != expected_terminal_count as u32
            || self.trace_variables != BLS_DORY_BLAKE3_TRACE_VARIABLES as u32
            || self.source_variables != BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES as u32
            || self.shared_variables != BLS_DORY_SHARED_PRODUCTION_VARIABLES as u32
            || self.dory_nu != BLS_DORY_BLAKE3_SHARED_DORY_NU as u32
            || self.dory_sigma != BLS_DORY_BLAKE3_SHARED_DORY_SIGMA as u32
            || self.setup_max_log_n != BLS_DORY_SHARED_PRODUCTION_VARIABLES as u32
            || self.compact_scalar_count != expected_scalar_count
            || self.compact_explicit_scalar_count != expected_explicit_scalars as u64
            || self.compact_word_scalar_count != expected_word_scalars as u64
            || self.compact_word_bytes != 8
            || self.compact_code_bits != 4
            || self.compact_word_width_codes != 0
            || self.compact_word_group_len != BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS as u64
            || self.compact_signed_word_selectors != 0
        {
            return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "production geometry",
            ));
        }

        let setup_identity = decode_blake3_record_hex_32("setup identity", &self.setup_identity)?;
        if setup_identity == [0; 32] {
            return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "setup identity",
            ));
        }
        let preprocessing_commitment =
            decode_blake3_record_commitment(&self.preprocessing_bls_commitment)?;
        if preprocessing_commitment == BlsDoryGt::identity() {
            return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "preprocessing BLS commitment",
            ));
        }
        let _ = decode_blake3_record_hex_32("transpose digest", &self.transpose_digest)?;
        let compact_spec = self.compact_artifact_spec()?;
        let expected_source_spec = source_artifact_spec(
            setup_identity,
            BLS_DORY_BLAKE3_SHARED_DORY_NU,
            BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
            usize::try_from(expected_scalar_count).map_err(|_| {
                BlsDoryBlake3PreprocessingRecordError::InvalidMetadata("compact scalar count")
            })?,
            expected_explicit_scalars,
        )?;
        if compact_spec.context_digest != expected_source_spec.context_digest {
            return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "compact artifact context",
            ));
        }
        let _ =
            decode_blake3_record_hex_32("compact artifact digest", &self.compact_artifact_digest)?;
        let expected_transpose_bytes = projected_bls_dory_transpose_artifact_bytes(
            BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
            BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
        )?;
        if self.transpose_bytes != expected_transpose_bytes
            || self.compact_artifact_bytes != compact_spec.encoded_bytes(2)?
        {
            return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "artifact bytes",
            ));
        }

        let fri_key = pinned_preprocessed_key(
            BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES,
            BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
        )
        .ok_or(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
            "FRI preprocessing key",
        ))?;
        require_blake3_record_digest(
            "FRI registry",
            pinned_preprocessed_registry_digest(),
            &self.fri_preprocessed_registry_digest,
        )?;
        if self.decoded_fri_preprocessed_root()? != fri_key.root {
            return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "FRI preprocessing root",
            ));
        }
        require_blake3_record_digest("record", self.canonical_digest()?, &self.record_digest)
    }

    /// Validate the record against the exact deterministic setup used to derive it.
    pub fn validate_for_setup(
        &self,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDoryBlake3PreprocessingRecordError> {
        self.validate()?;
        setup.validate()?;
        if setup.max_log_n() != BLS_DORY_SHARED_PRODUCTION_VARIABLES
            || decode_blake3_record_hex_32("setup identity", &self.setup_identity)?
                != setup.identity()
        {
            return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "deterministic setup",
            ));
        }
        Ok(())
    }

    /// Canonical digest independent of JSON map ordering and whitespace.
    pub fn canonical_digest(&self) -> Result<[u8; 32], BlsDoryBlake3PreprocessingRecordError> {
        let setup_identity = decode_blake3_record_hex_32("setup identity", &self.setup_identity)?;
        let commitment = decode_blake3_record_commitment_bytes(
            "preprocessing BLS commitment",
            &self.preprocessing_bls_commitment,
        )?;
        let transpose_digest =
            decode_blake3_record_hex_32("transpose digest", &self.transpose_digest)?;
        let compact_context = decode_blake3_record_hex_32(
            "compact artifact context",
            &self.compact_artifact_context_digest,
        )?;
        let compact_digest =
            decode_blake3_record_hex_32("compact artifact digest", &self.compact_artifact_digest)?;
        let fri_registry =
            decode_blake3_record_hex_32("FRI registry", &self.fri_preprocessed_registry_digest)?;

        let mut hasher =
            blake3::Hasher::new_derive_key(BLS_DORY_BLAKE3_PREPROCESSING_RECORD_DOMAIN);
        hasher.update(&self.record_version.to_le_bytes());
        hasher.update(&self.projection_version.to_le_bytes());
        hasher.update(&self.native_proof_version.to_le_bytes());
        hasher.update(&self.activation_len.to_le_bytes());
        hasher.update(&self.cell_point_variables.to_le_bytes());
        hasher.update(&self.trace_rows.to_le_bytes());
        hasher.update(&self.preprocessed_width.to_le_bytes());
        hasher.update(&self.preprocessed_word_tables.to_le_bytes());
        hasher.update(&self.preprocessed_code_tables.to_le_bytes());
        hasher.update(&self.preprocessing_terminal_count.to_le_bytes());
        hasher.update(&self.trace_variables.to_le_bytes());
        hasher.update(&self.source_variables.to_le_bytes());
        hasher.update(&self.shared_variables.to_le_bytes());
        hasher.update(&self.dory_nu.to_le_bytes());
        hasher.update(&self.dory_sigma.to_le_bytes());
        hasher.update(&self.setup_max_log_n.to_le_bytes());
        hasher.update(&setup_identity);
        absorb_blake3_record_bytes(&mut hasher, &commitment)?;
        hasher.update(&transpose_digest);
        hasher.update(&self.transpose_bytes.to_le_bytes());
        hasher.update(&compact_context);
        hasher.update(&compact_digest);
        hasher.update(&self.compact_artifact_bytes.to_le_bytes());
        hasher.update(&self.compact_scalar_count.to_le_bytes());
        hasher.update(&self.compact_explicit_scalar_count.to_le_bytes());
        hasher.update(&self.compact_word_scalar_count.to_le_bytes());
        hasher.update(&[self.compact_word_bytes]);
        hasher.update(&[self.compact_code_bits]);
        hasher.update(&self.compact_word_width_codes.to_le_bytes());
        hasher.update(&self.compact_word_group_len.to_le_bytes());
        hasher.update(&self.compact_signed_word_selectors.to_le_bytes());
        hasher.update(&fri_registry);
        for word in self.decoded_fri_preprocessed_root()? {
            hasher.update(&word.to_le_bytes());
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn decoded_fri_preprocessed_root(
        &self,
    ) -> Result<[u64; 4], BlsDoryBlake3PreprocessingRecordError> {
        let mut decoded = [0_u64; 4];
        for (target, encoded) in decoded.iter_mut().zip(&self.fri_preprocessed_root) {
            if encoded.len() != 16 {
                return Err(BlsDoryBlake3PreprocessingRecordError::InvalidHex(
                    "FRI preprocessing root",
                ));
            }
            let value = u64::from_str_radix(encoded, 16).map_err(|_| {
                BlsDoryBlake3PreprocessingRecordError::InvalidHex("FRI preprocessing root")
            })?;
            if format!("{value:016x}") != *encoded {
                return Err(BlsDoryBlake3PreprocessingRecordError::InvalidHex(
                    "FRI preprocessing root",
                ));
            }
            *target = value;
        }
        Ok(decoded)
    }

    fn compact_artifact_spec(
        &self,
    ) -> Result<BlsDoryCompactArtifactSpec, BlsDoryBlake3PreprocessingRecordError> {
        Ok(BlsDoryCompactArtifactSpec {
            context_digest: decode_blake3_record_hex_32(
                "compact artifact context",
                &self.compact_artifact_context_digest,
            )?,
            scalar_count: self.compact_scalar_count,
            explicit_scalar_count: self.compact_explicit_scalar_count,
            word_scalar_count: self.compact_word_scalar_count,
            word_bytes: self.compact_word_bytes,
            code_bits: self.compact_code_bits,
            word_width_codes: self.compact_word_width_codes,
            word_group_len: self.compact_word_group_len,
            signed_word_selectors: self.compact_signed_word_selectors,
        })
    }
}

#[cfg(feature = "whir-prototype")]
#[derive(Debug, Error)]
pub enum BlsDoryBlake3PreprocessingRecordError {
    #[error("native BLAKE3 preprocessing record metadata is invalid: {0}")]
    InvalidMetadata(&'static str),
    #[error("native BLAKE3 preprocessing record hex is noncanonical: {0}")]
    InvalidHex(&'static str),
    #[error("native BLAKE3 preprocessing record digest mismatch: {0}")]
    DigestMismatch(&'static str),
    #[error("native BLAKE3 preprocessing commitment serialization failed: {0}")]
    CommitmentSerialization(String),
    #[error("deterministic BLS setup derivation failed: {0}")]
    Setup(#[from] BlsDoryPrototypeError),
    #[error("native BLAKE3 preprocessing aggregate failed: {0}")]
    Aggregate(#[from] BlsDoryAggregateError),
    #[error("native BLAKE3 preprocessing transpose failed: {0}")]
    Transpose(#[from] BlsDoryTransposeError),
    #[error("native BLAKE3 compact artifact validation failed: {0}")]
    CompactArtifact(#[from] BlsDoryCompactArtifactError),
    #[error("native BLAKE3 AIR construction failed: {0}")]
    Air(String),
}

#[cfg(feature = "whir-prototype")]
fn require_blake3_record_digest(
    label: &'static str,
    expected: [u8; 32],
    encoded: &str,
) -> Result<(), BlsDoryBlake3PreprocessingRecordError> {
    if decode_blake3_record_hex_32(label, encoded)? != expected {
        return Err(BlsDoryBlake3PreprocessingRecordError::DigestMismatch(label));
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn decode_blake3_record_hex_32(
    label: &'static str,
    encoded: &str,
) -> Result<[u8; 32], BlsDoryBlake3PreprocessingRecordError> {
    let bytes = decode_blake3_record_hex(label, encoded)?;
    bytes
        .try_into()
        .map_err(|_| BlsDoryBlake3PreprocessingRecordError::InvalidHex(label))
}

#[cfg(feature = "whir-prototype")]
fn decode_blake3_record_hex(
    label: &'static str,
    encoded: &str,
) -> Result<Vec<u8>, BlsDoryBlake3PreprocessingRecordError> {
    let bytes = hex::decode(encoded)
        .map_err(|_| BlsDoryBlake3PreprocessingRecordError::InvalidHex(label))?;
    if hex::encode(&bytes) != encoded {
        return Err(BlsDoryBlake3PreprocessingRecordError::InvalidHex(label));
    }
    Ok(bytes)
}

#[cfg(feature = "whir-prototype")]
fn encode_blake3_record_commitment(
    commitment: &BlsDoryGt,
) -> Result<String, BlsDoryBlake3PreprocessingRecordError> {
    let mut encoded = Vec::new();
    commitment
        .serialize_compressed(&mut encoded)
        .map_err(|error| {
            BlsDoryBlake3PreprocessingRecordError::CommitmentSerialization(error.to_string())
        })?;
    Ok(hex::encode(encoded))
}

#[cfg(feature = "whir-prototype")]
fn decode_blake3_record_commitment_bytes(
    label: &'static str,
    encoded: &str,
) -> Result<Vec<u8>, BlsDoryBlake3PreprocessingRecordError> {
    if encoded.len() != GT_BYTES * 2 {
        return Err(BlsDoryBlake3PreprocessingRecordError::InvalidHex(label));
    }
    decode_blake3_record_hex(label, encoded)
}

#[cfg(feature = "whir-prototype")]
fn decode_blake3_record_commitment(
    encoded: &str,
) -> Result<BlsDoryGt, BlsDoryBlake3PreprocessingRecordError> {
    let bytes = decode_blake3_record_commitment_bytes("preprocessing BLS commitment", encoded)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let commitment = BlsDoryGt::deserialize_compressed(&mut cursor).map_err(|error| {
        BlsDoryBlake3PreprocessingRecordError::CommitmentSerialization(error.to_string())
    })?;
    if cursor.position() != bytes.len() as u64
        || encode_blake3_record_commitment(&commitment)? != encoded
    {
        return Err(BlsDoryBlake3PreprocessingRecordError::InvalidHex(
            "preprocessing BLS commitment",
        ));
    }
    Ok(commitment)
}

#[cfg(feature = "whir-prototype")]
fn absorb_blake3_record_bytes(
    hasher: &mut blake3::Hasher,
    bytes: &[u8],
) -> Result<(), BlsDoryBlake3PreprocessingRecordError> {
    let len = u64::try_from(bytes.len()).map_err(|_| {
        BlsDoryBlake3PreprocessingRecordError::InvalidMetadata("encoded byte length")
    })?;
    hasher.update(&len.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

/// Executable algebraic union bound for the shared proof plus BLAKE3 replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryBlake3SoundnessReport {
    pub shared_algebraic_numerator_upper_bound: u64,
    pub blake3_terms: Vec<BlsDorySoundnessTerm>,
    pub blake3_algebraic_numerator_upper_bound: u64,
    pub composed_algebraic_numerator_upper_bound: u64,
    pub nonzero_challenge_space_lower_bound_bits: u32,
    pub algebraic_soundness_bits: u32,
    pub required_algebraic_soundness_bits: u32,
    pub grinding_headroom_bits: u32,
    pub composed_opening_claims: usize,
    pub proposed_maximum_opening_claims: usize,
    pub independently_reviewed: bool,
}

/// Conservative algebraic terms for the exact projected BLAKE3 topology.
pub fn projected_bls_dory_blake3_soundness_report()
-> Result<BlsDoryBlake3SoundnessReport, BlsDorySoundnessError> {
    const NONZERO_CHALLENGE_BITS: u32 = 254;
    const REQUIRED_BITS: u32 = 128;
    let rows = u64::try_from(BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS)
        .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?;
    let trace_variables = u64::try_from(BLS_DORY_BLAKE3_TRACE_VARIABLES)
        .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?;
    let terms = vec![
        blake3_soundness_term(
            "BLAKE3 execution constraint mixing",
            u64::try_from(BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS - 1)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term("BLAKE3 execution local equality point", trace_variables),
        blake3_soundness_term(
            "BLAKE3 execution sumcheck",
            u64::try_from(BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?
                .checked_mul(trace_variables)
                .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 execution source selector batching",
            u64::try_from(BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 adjacency row compression",
            rows.checked_mul(
                u64::try_from(BLS_DORY_BLAKE3_MAIN_WIDTH)
                    .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
            )
            .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 adjacency lookup-alpha rational identity",
            rows.checked_mul(2)
                .and_then(|value| value.checked_sub(1))
                .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term("BLAKE3 adjacency local relation mixing", 1),
        blake3_soundness_term("BLAKE3 adjacency global relation mixing", 1),
        blake3_soundness_term("BLAKE3 adjacency local equality point", trace_variables),
        blake3_soundness_term(
            "BLAKE3 adjacency sumcheck",
            u64::try_from(BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?
                .checked_mul(trace_variables)
                .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 adjacency source selector batching",
            u64::try_from(BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 adjacency inverse selector batching",
            u64::try_from(BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
    ];
    let blake3_algebraic_numerator_upper_bound = terms.iter().try_fold(0_u64, |total, term| {
        total
            .checked_add(term.total_numerator_upper_bound()?)
            .ok_or(BlsDorySoundnessError::ArithmeticOverflow)
    })?;
    let shared = production_bls_dory_soundness_report()?;
    let composed_algebraic_numerator_upper_bound = shared
        .total_algebraic_numerator_upper_bound
        .checked_add(blake3_algebraic_numerator_upper_bound)
        .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?;
    let algebraic_soundness_bits = NONZERO_CHALLENGE_BITS
        .checked_sub(blake3_ceil_log2(composed_algebraic_numerator_upper_bound))
        .ok_or(BlsDorySoundnessError::InvalidProductionGeometry)?;
    let grinding_headroom_bits = algebraic_soundness_bits
        .checked_sub(REQUIRED_BITS)
        .ok_or(BlsDorySoundnessError::InvalidProductionGeometry)?;
    Ok(BlsDoryBlake3SoundnessReport {
        shared_algebraic_numerator_upper_bound: shared.total_algebraic_numerator_upper_bound,
        blake3_terms: terms,
        blake3_algebraic_numerator_upper_bound,
        composed_algebraic_numerator_upper_bound,
        nonzero_challenge_space_lower_bound_bits: NONZERO_CHALLENGE_BITS,
        algebraic_soundness_bits,
        required_algebraic_soundness_bits: REQUIRED_BITS,
        grinding_headroom_bits,
        composed_opening_claims: BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS,
        proposed_maximum_opening_claims: BLS_DORY_BLAKE3_PROPOSED_MAX_OPENING_CLAIMS,
        independently_reviewed: false,
    })
}

fn blake3_soundness_term(label: &'static str, numerator: u64) -> BlsDorySoundnessTerm {
    BlsDorySoundnessTerm {
        label,
        instances: 1,
        numerator_upper_bound_per_instance: numerator,
    }
}

const fn blake3_ceil_log2(value: u64) -> u32 {
    if value <= 1 {
        0
    } else {
        u64::BITS - (value - 1).leading_zeros()
    }
}

/// Field-independent variable reference emitted by the existing BLAKE3 AIR.
#[cfg(feature = "whir-prototype")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlsDoryBlake3Variable {
    Main { offset: u8, index: u16 },
    Preprocessed { offset: u8, index: u16 },
    Public { index: u16 },
    Periodic { index: u16 },
}

/// Canonical integer expression translated from one Goldilocks AIR constraint.
#[cfg(feature = "whir-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BlsDoryBlake3ConstraintExpr {
    Variable(BlsDoryBlake3Variable),
    FirstRow,
    LastRow,
    Transition,
    Constant(i64),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Neg(Box<Self>),
    Mul(Box<Self>, Box<Self>),
}

#[cfg(feature = "whir-prototype")]
pub(crate) struct BlsDoryBlake3Evaluation<'a> {
    pub main_local: &'a [BlsDoryFr],
    pub main_next: &'a [BlsDoryFr],
    pub preprocessed_local: &'a [BlsDoryFr],
    pub preprocessed_next: &'a [BlsDoryFr],
    pub public: &'a [BlsDoryFr],
    pub periodic: &'a [BlsDoryFr],
    pub first_row: BlsDoryFr,
    pub last_row: BlsDoryFr,
    pub transition: BlsDoryFr,
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryBlake3ConstraintExpr {
    pub(crate) fn evaluate(&self, values: &BlsDoryBlake3Evaluation<'_>) -> BlsDoryFr {
        match self {
            Self::Variable(variable) => match *variable {
                BlsDoryBlake3Variable::Main { offset: 0, index } => {
                    values.main_local[usize::from(index)]
                }
                BlsDoryBlake3Variable::Main { offset: 1, index } => {
                    values.main_next[usize::from(index)]
                }
                BlsDoryBlake3Variable::Preprocessed { offset: 0, index } => {
                    values.preprocessed_local[usize::from(index)]
                }
                BlsDoryBlake3Variable::Preprocessed { offset: 1, index } => {
                    values.preprocessed_next[usize::from(index)]
                }
                BlsDoryBlake3Variable::Public { index } => values.public[usize::from(index)],
                BlsDoryBlake3Variable::Periodic { index } => values.periodic[usize::from(index)],
                BlsDoryBlake3Variable::Main { offset, .. }
                | BlsDoryBlake3Variable::Preprocessed { offset, .. } => {
                    panic!("BLAKE3 constraint IR contains unsupported row offset {offset}")
                }
            },
            Self::FirstRow => values.first_row,
            Self::LastRow => values.last_row,
            Self::Transition => values.transition,
            Self::Constant(value) => BlsDoryFr::from_i64(*value),
            Self::Add(left, right) => left.evaluate(values) + right.evaluate(values),
            Self::Sub(left, right) => left.evaluate(values) - right.evaluate(values),
            Self::Neg(value) => -value.evaluate(values),
            Self::Mul(left, right) => left.evaluate(values) * right.evaluate(values),
        }
    }
}

/// Generate the exact existing narrow-BLAKE3 equations as a field-independent IR.
#[cfg(feature = "whir-prototype")]
pub(crate) fn bls_dory_blake3_constraint_ir(
    activation_len: usize,
) -> Result<Vec<BlsDoryBlake3ConstraintExpr>, NarrowBlake3Error> {
    if activation_len < 32 || !activation_len.is_power_of_two() {
        return Err(NarrowBlake3Error::UnsupportedShape);
    }
    let point_variables = activation_len.ilog2() as usize;
    let statement = StructuredBlake3Statement {
        challenge_digest: [0; 32],
        final_activation_len: activation_len,
        final_activation_digest: [0; 32],
        final_activation_point: vec![ExtensionElement { limbs: [0; 3] }; point_variables],
        final_activation_evaluation: ExtensionElement { limbs: [0; 3] },
    };
    let air = NarrowBlake3Air::new(&statement)?;
    let layout = AirLayout::from_air(&air);
    get_symbolic_constraints::<Goldilocks, _>(&air, layout)
        .iter()
        .map(translate_constraint)
        .collect()
}

#[cfg(feature = "whir-prototype")]
fn translate_constraint(
    expression: &SymbolicExpression<Goldilocks>,
) -> Result<BlsDoryBlake3ConstraintExpr, NarrowBlake3Error> {
    Ok(match expression {
        SymbolicExpr::Leaf(BaseLeaf::Variable(variable)) => {
            BlsDoryBlake3ConstraintExpr::Variable(match variable.entry {
                BaseEntry::Main { offset } => BlsDoryBlake3Variable::Main {
                    offset: u8::try_from(offset).map_err(|_| NarrowBlake3Error::Encoding)?,
                    index: u16::try_from(variable.index)
                        .map_err(|_| NarrowBlake3Error::Encoding)?,
                },
                BaseEntry::Preprocessed { offset } => BlsDoryBlake3Variable::Preprocessed {
                    offset: u8::try_from(offset).map_err(|_| NarrowBlake3Error::Encoding)?,
                    index: u16::try_from(variable.index)
                        .map_err(|_| NarrowBlake3Error::Encoding)?,
                },
                BaseEntry::Public => BlsDoryBlake3Variable::Public {
                    index: u16::try_from(variable.index)
                        .map_err(|_| NarrowBlake3Error::Encoding)?,
                },
                BaseEntry::Periodic => BlsDoryBlake3Variable::Periodic {
                    index: u16::try_from(variable.index)
                        .map_err(|_| NarrowBlake3Error::Encoding)?,
                },
            })
        }
        SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => BlsDoryBlake3ConstraintExpr::FirstRow,
        SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => BlsDoryBlake3ConstraintExpr::LastRow,
        SymbolicExpr::Leaf(BaseLeaf::IsTransition) => BlsDoryBlake3ConstraintExpr::Transition,
        SymbolicExpr::Leaf(BaseLeaf::Constant(value)) => {
            BlsDoryBlake3ConstraintExpr::Constant(centered_goldilocks(*value))
        }
        SymbolicExpr::Add { x, y, .. } => BlsDoryBlake3ConstraintExpr::Add(
            Box::new(translate_constraint(x)?),
            Box::new(translate_constraint(y)?),
        ),
        SymbolicExpr::Sub { x, y, .. } => BlsDoryBlake3ConstraintExpr::Sub(
            Box::new(translate_constraint(x)?),
            Box::new(translate_constraint(y)?),
        ),
        SymbolicExpr::Neg { x, .. } => {
            BlsDoryBlake3ConstraintExpr::Neg(Box::new(translate_constraint(x)?))
        }
        SymbolicExpr::Mul { x, y, .. } => BlsDoryBlake3ConstraintExpr::Mul(
            Box::new(translate_constraint(x)?),
            Box::new(translate_constraint(y)?),
        ),
    })
}

#[cfg(feature = "whir-prototype")]
fn centered_goldilocks(value: Goldilocks) -> i64 {
    let canonical = value.as_canonical_u64();
    if canonical <= GOLDILOCKS_MODULUS / 2 {
        canonical as i64
    } else {
        -i64::try_from(GOLDILOCKS_MODULUS - canonical)
            .expect("centered Goldilocks constant fits i64")
    }
}

#[cfg(feature = "whir-prototype")]
fn uses_old_evaluation_constraint(expression: &BlsDoryBlake3ConstraintExpr) -> bool {
    match expression {
        BlsDoryBlake3ConstraintExpr::Variable(BlsDoryBlake3Variable::Main { index, .. }) => {
            (NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START..NARROW_BLAKE3_STACK_START)
                .contains(&usize::from(*index))
        }
        BlsDoryBlake3ConstraintExpr::Add(left, right)
        | BlsDoryBlake3ConstraintExpr::Sub(left, right)
        | BlsDoryBlake3ConstraintExpr::Mul(left, right) => {
            uses_old_evaluation_constraint(left) || uses_old_evaluation_constraint(right)
        }
        BlsDoryBlake3ConstraintExpr::Neg(value) => uses_old_evaluation_constraint(value),
        BlsDoryBlake3ConstraintExpr::Variable(_)
        | BlsDoryBlake3ConstraintExpr::FirstRow
        | BlsDoryBlake3ConstraintExpr::LastRow
        | BlsDoryBlake3ConstraintExpr::Transition
        | BlsDoryBlake3ConstraintExpr::Constant(_) => false,
    }
}

#[cfg(feature = "whir-prototype")]
fn remap_native_main_constraint(
    expression: &BlsDoryBlake3ConstraintExpr,
) -> Result<BlsDoryBlake3ConstraintExpr, NarrowBlake3Error> {
    Ok(match expression {
        BlsDoryBlake3ConstraintExpr::Variable(variable) => {
            let variable = match *variable {
                BlsDoryBlake3Variable::Main { offset, index } => {
                    let index = usize::from(index);
                    if (NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START..NARROW_BLAKE3_STACK_START)
                        .contains(&index)
                    {
                        return Err(NarrowBlake3Error::Encoding);
                    }
                    let native_index = if index >= NARROW_BLAKE3_STACK_START {
                        index
                            - (NARROW_BLAKE3_STACK_START
                                - NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START
                                - 1)
                    } else {
                        index
                    };
                    BlsDoryBlake3Variable::Main {
                        offset,
                        index: u16::try_from(native_index)
                            .map_err(|_| NarrowBlake3Error::Encoding)?,
                    }
                }
                other => other,
            };
            BlsDoryBlake3ConstraintExpr::Variable(variable)
        }
        BlsDoryBlake3ConstraintExpr::FirstRow => BlsDoryBlake3ConstraintExpr::FirstRow,
        BlsDoryBlake3ConstraintExpr::LastRow => BlsDoryBlake3ConstraintExpr::LastRow,
        BlsDoryBlake3ConstraintExpr::Transition => BlsDoryBlake3ConstraintExpr::Transition,
        BlsDoryBlake3ConstraintExpr::Constant(value) => {
            BlsDoryBlake3ConstraintExpr::Constant(*value)
        }
        BlsDoryBlake3ConstraintExpr::Add(left, right) => BlsDoryBlake3ConstraintExpr::Add(
            Box::new(remap_native_main_constraint(left)?),
            Box::new(remap_native_main_constraint(right)?),
        ),
        BlsDoryBlake3ConstraintExpr::Sub(left, right) => BlsDoryBlake3ConstraintExpr::Sub(
            Box::new(remap_native_main_constraint(left)?),
            Box::new(remap_native_main_constraint(right)?),
        ),
        BlsDoryBlake3ConstraintExpr::Neg(value) => {
            BlsDoryBlake3ConstraintExpr::Neg(Box::new(remap_native_main_constraint(value)?))
        }
        BlsDoryBlake3ConstraintExpr::Mul(left, right) => BlsDoryBlake3ConstraintExpr::Mul(
            Box::new(remap_native_main_constraint(left)?),
            Box::new(remap_native_main_constraint(right)?),
        ),
    })
}

#[cfg(all(test, feature = "whir-prototype"))]
fn uses_removed_native_input(expression: &BlsDoryBlake3ConstraintExpr) -> bool {
    match expression {
        BlsDoryBlake3ConstraintExpr::Variable(BlsDoryBlake3Variable::Public { index }) => {
            usize::from(*index) >= 72
        }
        BlsDoryBlake3ConstraintExpr::Variable(BlsDoryBlake3Variable::Periodic { .. }) => true,
        BlsDoryBlake3ConstraintExpr::Add(left, right)
        | BlsDoryBlake3ConstraintExpr::Sub(left, right)
        | BlsDoryBlake3ConstraintExpr::Mul(left, right) => {
            uses_removed_native_input(left) || uses_removed_native_input(right)
        }
        BlsDoryBlake3ConstraintExpr::Neg(value) => uses_removed_native_input(value),
        BlsDoryBlake3ConstraintExpr::Variable(_)
        | BlsDoryBlake3ConstraintExpr::FirstRow
        | BlsDoryBlake3ConstraintExpr::LastRow
        | BlsDoryBlake3ConstraintExpr::Transition
        | BlsDoryBlake3ConstraintExpr::Constant(_) => false,
    }
}

#[cfg(feature = "whir-prototype")]
fn bls_dory_native_blake3_constraint_ir(
    activation_len: usize,
) -> Result<Vec<BlsDoryBlake3ConstraintExpr>, NarrowBlake3Error> {
    bls_dory_blake3_constraint_ir(activation_len)?
        .iter()
        .filter(|constraint| !uses_old_evaluation_constraint(constraint))
        .map(remap_native_main_constraint)
        .collect()
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_main_row(old_row: &[BlsDoryFr], accumulator: BlsDoryFr) -> Vec<BlsDoryFr> {
    assert_eq!(old_row.len(), NARROW_BLAKE3_MAIN_WIDTH);
    let mut row = Vec::with_capacity(BLS_DORY_BLAKE3_MAIN_WIDTH);
    row.extend_from_slice(&old_row[..NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START]);
    row.push(accumulator);
    row.extend_from_slice(&old_row[NARROW_BLAKE3_STACK_START..]);
    assert_eq!(row.len(), BLS_DORY_BLAKE3_MAIN_WIDTH);
    row
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_activation_contribution(
    main_local: &[BlsDoryFr],
    activation_group: Option<usize>,
    point: &[BlsDoryFr],
) -> BlsDoryFr {
    let coefficients = native_byte_coefficients(activation_group, point);
    native_activation_contribution_from_coefficients(main_local, &coefficients)
}

#[cfg(feature = "whir-prototype")]
fn native_byte_coefficients(
    activation_group: Option<usize>,
    point: &[BlsDoryFr],
) -> [BlsDoryFr; 8] {
    let Some(group) = activation_group else {
        return [BlsDoryFr::zero(); 8];
    };
    std::array::from_fn(|byte| {
        let index = group + byte;
        point
            .iter()
            .enumerate()
            .fold(BlsDoryFr::from_u64(1), |weight, (variable, coordinate)| {
                if (index >> variable) & 1 == 1 {
                    weight * *coordinate
                } else {
                    weight * (BlsDoryFr::from_u64(1) - *coordinate)
                }
            })
    })
}

#[cfg(feature = "whir-prototype")]
fn native_activation_contribution_from_coefficients(
    main_local: &[BlsDoryFr],
    coefficients: &[BlsDoryFr; 8],
) -> BlsDoryFr {
    (0..8).fold(BlsDoryFr::zero(), |sum, byte| {
        let low = main_local[NARROW_BLAKE3_ORIGINAL_NIBBLES_START + 2 * byte];
        let high = main_local[NARROW_BLAKE3_ORIGINAL_NIBBLES_START + 2 * byte + 1];
        let value = low + BlsDoryFr::from_u64(16) * high;
        sum + value * coefficients[byte]
    })
}

#[cfg(feature = "whir-prototype")]
struct BlsDoryNativeEvaluationRow<'a> {
    main_local: &'a [BlsDoryFr],
    main_next: &'a [BlsDoryFr],
    first_row: BlsDoryFr,
    last_row: BlsDoryFr,
    transition: BlsDoryFr,
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_evaluation_residuals(
    row: &BlsDoryNativeEvaluationRow<'_>,
    activation_group: Option<usize>,
    point: &[BlsDoryFr],
    raw_evaluation: BlsDoryFr,
) -> [BlsDoryFr; 3] {
    let coefficients = native_byte_coefficients(activation_group, point);
    native_evaluation_residuals_from_coefficients(row, &coefficients, raw_evaluation)
}

#[cfg(feature = "whir-prototype")]
fn native_evaluation_residuals_from_coefficients(
    row: &BlsDoryNativeEvaluationRow<'_>,
    coefficients: &[BlsDoryFr; 8],
    raw_evaluation: BlsDoryFr,
) -> [BlsDoryFr; 3] {
    let current = row.main_local[NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START];
    let next = row.main_next[NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START];
    let contribution =
        native_activation_contribution_from_coefficients(row.main_local, coefficients);
    [
        row.first_row * current,
        row.transition * (next - current - contribution),
        row.last_row * (current - raw_evaluation),
    ]
}

#[cfg(feature = "whir-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlsDoryBlake3ExecutionSumcheckProof {
    rounds: Vec<Vec<BlsDoryFr>>,
    terminal_evaluations: Vec<BlsDoryFr>,
    transcript_digest: [u8; 32],
}

#[cfg(feature = "whir-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlsDoryBlake3AdjacencySumcheckProof {
    rounds: Vec<Vec<BlsDoryFr>>,
    terminal_evaluations: Vec<BlsDoryFr>,
    transcript_digest: [u8; 32],
}

/// Canonical native BLAKE3 proof material. The four source commitments are
/// named internally, and the verifier derives every opening point and
/// evaluation by replaying the two sumchecks.
#[cfg(feature = "whir-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlsDoryNativeBlake3Proof {
    source_commitments: BlsDoryBlake3SourceCommitments,
    execution: BlsDoryBlake3ExecutionSumcheckProof,
    adjacency: BlsDoryBlake3AdjacencySumcheckProof,
}

#[cfg(feature = "whir-prototype")]
struct DecodedBlsDoryBlake3Component {
    commitments: Vec<BlsDoryGt>,
    rounds: Vec<Vec<BlsDoryFr>>,
    terminal_evaluations: Vec<BlsDoryFr>,
    transcript_digest: [u8; 32],
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryNativeBlake3Proof {
    /// Encode the immutable production geometry.
    #[allow(dead_code)]
    pub(crate) fn encode(&self) -> Result<Vec<u8>, BlsDoryAggregateError> {
        self.encode_at_trace_variables(BLS_DORY_BLAKE3_TRACE_VARIABLES)
    }

    /// Decode only the immutable production geometry.
    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, BlsDoryAggregateError> {
        Self::decode_at_trace_variables(encoded, BLS_DORY_BLAKE3_TRACE_VARIABLES)
    }

    fn encode_at_trace_variables(
        &self,
        trace_variables: usize,
    ) -> Result<Vec<u8>, BlsDoryAggregateError> {
        let execution_commitments = [
            self.source_commitments.main,
            self.source_commitments.accumulator,
            self.source_commitments.preprocessing,
        ];
        let execution = encode_native_blake3_component(
            BLS_DORY_BLAKE3_EXECUTION_PROOF_MAGIC,
            &execution_commitments,
            &self.execution.rounds,
            BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1,
            &self.execution.terminal_evaluations,
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS,
            self.execution.transcript_digest,
            trace_variables,
        )?;
        let adjacency_commitments = [self.source_commitments.inverse];
        let adjacency = encode_native_blake3_component(
            BLS_DORY_BLAKE3_ADJACENCY_PROOF_MAGIC,
            &adjacency_commitments,
            &self.adjacency.rounds,
            BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1,
            &self.adjacency.terminal_evaluations,
            BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS,
            self.adjacency.transcript_digest,
            trace_variables,
        )?;
        let total = execution
            .len()
            .checked_add(adjacency.len())
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(&execution);
        encoded.extend_from_slice(&adjacency);
        Ok(encoded)
    }

    fn decode_at_trace_variables(
        encoded: &[u8],
        trace_variables: usize,
    ) -> Result<Self, BlsDoryAggregateError> {
        let execution_bytes = native_blake3_component_wire_bytes(
            3,
            trace_variables,
            BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1,
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS,
        )
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let adjacency_bytes = native_blake3_component_wire_bytes(
            1,
            trace_variables,
            BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1,
            BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS,
        )
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        if encoded.len()
            != execution_bytes
                .checked_add(adjacency_bytes)
                .ok_or(BlsDoryAggregateError::InvalidProofShape)?
        {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        let execution = decode_native_blake3_component(
            &encoded[..execution_bytes],
            BLS_DORY_BLAKE3_EXECUTION_PROOF_MAGIC,
            3,
            trace_variables,
            BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1,
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS,
        )?;
        let adjacency = decode_native_blake3_component(
            &encoded[execution_bytes..],
            BLS_DORY_BLAKE3_ADJACENCY_PROOF_MAGIC,
            1,
            trace_variables,
            BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1,
            BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS,
        )?;
        let [main, accumulator, preprocessing]: [BlsDoryGt; 3] =
            execution
                .commitments
                .try_into()
                .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        let [inverse]: [BlsDoryGt; 1] = adjacency
            .commitments
            .try_into()
            .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        let proof = Self {
            source_commitments: BlsDoryBlake3SourceCommitments {
                main,
                accumulator,
                preprocessing,
                inverse,
            },
            execution: BlsDoryBlake3ExecutionSumcheckProof {
                rounds: execution.rounds,
                terminal_evaluations: execution.terminal_evaluations,
                transcript_digest: execution.transcript_digest,
            },
            adjacency: BlsDoryBlake3AdjacencySumcheckProof {
                rounds: adjacency.rounds,
                terminal_evaluations: adjacency.terminal_evaluations,
                transcript_digest: adjacency.transcript_digest,
            },
        };
        if proof.encode_at_trace_variables(trace_variables)? != encoded {
            return Err(BlsDoryAggregateError::InvalidEncoding);
        }
        Ok(proof)
    }
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_component_wire_bytes(
    commitments: usize,
    rounds: usize,
    round_width: usize,
    terminal_evaluations: usize,
) -> Option<usize> {
    COMPONENT_HEADER_BYTES
        .checked_add(commitments.checked_mul(GT_BYTES)?)?
        .checked_add(rounds.checked_mul(round_width)?.checked_mul(SCALAR_BYTES)?)?
        .checked_add(terminal_evaluations.checked_mul(SCALAR_BYTES)?)?
        .checked_add(TRANSCRIPT_DIGEST_BYTES)
}

#[cfg(feature = "whir-prototype")]
#[allow(clippy::too_many_arguments)]
fn encode_native_blake3_component(
    magic: [u8; 8],
    commitments: &[BlsDoryGt],
    rounds: &[Vec<BlsDoryFr>],
    round_width: usize,
    terminal_evaluations: &[BlsDoryFr],
    expected_terminal_evaluations: usize,
    transcript_digest: [u8; 32],
    expected_rounds: usize,
) -> Result<Vec<u8>, BlsDoryAggregateError> {
    if rounds.len() != expected_rounds
        || terminal_evaluations.len() != expected_terminal_evaluations
        || rounds.iter().any(|round| round.len() != round_width)
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let commitment_count =
        u16::try_from(commitments.len()).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let round_count =
        u16::try_from(rounds.len()).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let round_width =
        u16::try_from(round_width).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let terminal_count = u16::try_from(terminal_evaluations.len())
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let expected_bytes = native_blake3_component_wire_bytes(
        commitments.len(),
        rounds.len(),
        usize::from(round_width),
        terminal_evaluations.len(),
    )
    .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    let mut encoded = Vec::with_capacity(expected_bytes);
    encoded.extend_from_slice(&magic);
    encoded.extend_from_slice(&BLS_DORY_BLAKE3_NATIVE_PROOF_VERSION.to_le_bytes());
    encoded.extend_from_slice(&commitment_count.to_le_bytes());
    encoded.extend_from_slice(&round_count.to_le_bytes());
    encoded.extend_from_slice(&round_width.to_le_bytes());
    encoded.extend_from_slice(&terminal_count.to_le_bytes());
    encoded.extend_from_slice(&BLS_DORY_BLAKE3_COMPONENT_RESERVED.to_le_bytes());
    for commitment in commitments {
        append_native_blake3_wire_value(&mut encoded, commitment)?;
    }
    for round in rounds {
        for evaluation in round {
            append_native_blake3_wire_value(&mut encoded, evaluation)?;
        }
    }
    for evaluation in terminal_evaluations {
        append_native_blake3_wire_value(&mut encoded, evaluation)?;
    }
    encoded.extend_from_slice(&transcript_digest);
    if encoded.len() != expected_bytes {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(encoded)
}

#[cfg(feature = "whir-prototype")]
#[allow(clippy::too_many_arguments)]
fn decode_native_blake3_component(
    encoded: &[u8],
    expected_magic: [u8; 8],
    expected_commitments: usize,
    expected_rounds: usize,
    expected_round_width: usize,
    expected_terminal_evaluations: usize,
) -> Result<DecodedBlsDoryBlake3Component, BlsDoryAggregateError> {
    let expected_bytes = native_blake3_component_wire_bytes(
        expected_commitments,
        expected_rounds,
        expected_round_width,
        expected_terminal_evaluations,
    )
    .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    if encoded.len() != expected_bytes || encoded[..8] != expected_magic {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let version = read_native_blake3_wire_u16(encoded, 8)?;
    let commitments = read_native_blake3_wire_u16(encoded, 10)? as usize;
    let rounds = read_native_blake3_wire_u16(encoded, 12)? as usize;
    let round_width = read_native_blake3_wire_u16(encoded, 14)? as usize;
    let terminal_evaluations = read_native_blake3_wire_u16(encoded, 16)? as usize;
    let reserved = read_native_blake3_wire_u16(encoded, 18)?;
    if version != BLS_DORY_BLAKE3_NATIVE_PROOF_VERSION
        || commitments != expected_commitments
        || rounds != expected_rounds
        || round_width != expected_round_width
        || terminal_evaluations != expected_terminal_evaluations
        || reserved != BLS_DORY_BLAKE3_COMPONENT_RESERVED
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let mut reader = Cursor::new(&encoded[COMPONENT_HEADER_BYTES..]);
    let commitments = (0..commitments)
        .map(|_| read_native_blake3_wire_value(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let rounds = (0..rounds)
        .map(|_| {
            (0..round_width)
                .map(|_| read_native_blake3_wire_value(&mut reader))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let terminal_evaluations = (0..terminal_evaluations)
        .map(|_| read_native_blake3_wire_value(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let digest_offset = COMPONENT_HEADER_BYTES
        .checked_add(reader.position() as usize)
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    let transcript_digest: [u8; 32] = encoded
        .get(digest_offset..)
        .and_then(|digest| digest.try_into().ok())
        .ok_or(BlsDoryAggregateError::InvalidEncoding)?;
    Ok(DecodedBlsDoryBlake3Component {
        commitments,
        rounds,
        terminal_evaluations,
        transcript_digest,
    })
}

#[cfg(feature = "whir-prototype")]
fn append_native_blake3_wire_value<T: DorySerialize>(
    encoded: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDoryAggregateError> {
    value
        .serialize_compressed(encoded)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)
}

#[cfg(feature = "whir-prototype")]
fn read_native_blake3_wire_value<T: DoryDeserialize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<T, BlsDoryAggregateError> {
    T::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)
}

#[cfg(feature = "whir-prototype")]
fn read_native_blake3_wire_u16(
    encoded: &[u8],
    offset: usize,
) -> Result<u16, BlsDoryAggregateError> {
    encoded
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(BlsDoryAggregateError::InvalidEncoding)
}

#[cfg(feature = "whir-prototype")]
struct VerifiedBlsDoryBlake3Sumcheck {
    point: Vec<BlsDoryFr>,
    transcript_digest: [u8; 32],
}

#[cfg(feature = "whir-prototype")]
#[derive(Clone, Copy)]
struct BlsDoryBlake3OpeningTranscriptDigests {
    execution_sumcheck: [u8; 32],
    adjacency_sumcheck: [u8; 32],
    execution_selectors: [u8; 32],
    adjacency_selectors: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlsDoryBlake3ReplayGeometry {
    trace_variables: usize,
    source_variables: usize,
    shared_variables: usize,
}

const BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY: BlsDoryBlake3ReplayGeometry =
    BlsDoryBlake3ReplayGeometry {
        trace_variables: BLS_DORY_BLAKE3_TRACE_VARIABLES,
        source_variables: BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES,
        shared_variables: BLS_DORY_SHARED_PRODUCTION_VARIABLES,
    };

/// Validated Dory verifier identity used by the BLAKE3 replay boundary.
#[cfg(feature = "whir-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlsDoryBlake3VerifierContext {
    layout: BlsDoryAggregateLayout,
    setup_identity: [u8; 32],
    setup_max_log_n: usize,
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryBlake3VerifierContext {
    fn new(
        layout: BlsDoryAggregateLayout,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryAggregateError> {
        setup
            .validate()
            .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        if layout.variables() > setup.max_log_n() {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        Ok(Self {
            layout,
            setup_identity: setup.identity(),
            setup_max_log_n: setup.max_log_n(),
        })
    }

    #[cfg(test)]
    fn for_test_metadata(
        layout: BlsDoryAggregateLayout,
        setup_identity: [u8; 32],
        setup_max_log_n: usize,
    ) -> Result<Self, BlsDoryAggregateError> {
        if setup_identity == [0u8; 32]
            || setup_max_log_n == 0
            || layout.variables() > setup_max_log_n
        {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        Ok(Self {
            layout,
            setup_identity,
            setup_max_log_n,
        })
    }

    fn validate_geometry(
        &self,
        geometry: BlsDoryBlake3ReplayGeometry,
    ) -> Result<(), BlsDoryAggregateError> {
        if self.layout.variables() != geometry.shared_variables
            || self.layout.variables() > self.setup_max_log_n
        {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        Ok(())
    }
}

/// Opaque verifier authority for the deterministic preprocessing polynomial.
/// Production construction is restricted to the two-run-reproduced embedded registry
/// record and an already-validated verifier context.
#[cfg(feature = "whir-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlsDoryBlake3TrustedPreprocessingPin {
    projection_version: u16,
    activation_len: usize,
    cell_point_variables: usize,
    trace_rows: usize,
    geometry: BlsDoryBlake3ReplayGeometry,
    verifier_context: BlsDoryBlake3VerifierContext,
    source_role: BlsDoryBlake3SourceRole,
    terminal_count: usize,
    commitment: BlsDoryGt,
}

#[cfg(feature = "whir-prototype")]
#[derive(Clone, Copy)]
struct BlsDoryBlake3ReplayVerifier<'a> {
    context: &'a BlsDoryBlake3VerifierContext,
    preprocessing_pin: &'a BlsDoryBlake3TrustedPreprocessingPin,
    geometry: BlsDoryBlake3ReplayGeometry,
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryBlake3TrustedPreprocessingPin {
    #[cfg(test)]
    fn for_test_sources(
        bridge: &BlsDoryOutputBridgeStatement,
        trace_rows: usize,
        geometry: BlsDoryBlake3ReplayGeometry,
        verifier_context: &BlsDoryBlake3VerifierContext,
        commitments: &BlsDoryBlake3SourceCommitments,
    ) -> Self {
        Self {
            projection_version: BLS_DORY_BLAKE3_PROJECTION_VERSION,
            activation_len: bridge.final_activation_len(),
            cell_point_variables: bridge.cell_point().len(),
            trace_rows,
            geometry,
            verifier_context: verifier_context.clone(),
            source_role: BlsDoryBlake3SourceRole::Preprocessing,
            terminal_count: BLS_DORY_BLAKE3_SOURCE_TERMINALS
                [BlsDoryBlake3SourceRole::Preprocessing.index()],
            commitment: *commitments.commitment(BlsDoryBlake3SourceRole::Preprocessing),
        }
    }

    fn validate(
        &self,
        bridge: &BlsDoryOutputBridgeStatement,
        trace_rows: usize,
        geometry: BlsDoryBlake3ReplayGeometry,
        verifier_context: &BlsDoryBlake3VerifierContext,
        commitments: &BlsDoryBlake3SourceCommitments,
    ) -> Result<(), BlsDoryAggregateError> {
        if self.projection_version != BLS_DORY_BLAKE3_PROJECTION_VERSION
            || self.activation_len != bridge.final_activation_len()
            || self.cell_point_variables != bridge.cell_point().len()
            || self.trace_rows != trace_rows
            || self.geometry != geometry
            || self.verifier_context != *verifier_context
            || self.source_role != BlsDoryBlake3SourceRole::Preprocessing
            || self.terminal_count
                != BLS_DORY_BLAKE3_SOURCE_TERMINALS[BlsDoryBlake3SourceRole::Preprocessing.index()]
            || self.commitment != *commitments.commitment(BlsDoryBlake3SourceRole::Preprocessing)
        {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        Ok(())
    }
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_production_preprocessing_pin_from_record(
    encoded_record: &[u8],
    verifier_context: &BlsDoryBlake3VerifierContext,
) -> Result<BlsDoryBlake3TrustedPreprocessingPin, BlsDoryBlake3PreprocessingRecordError> {
    let record: BlsDoryBlake3PreprocessingRecord =
        serde_json::from_slice(encoded_record).map_err(|_| {
            BlsDoryBlake3PreprocessingRecordError::InvalidMetadata("embedded record JSON")
        })?;
    record.validate()?;
    require_blake3_record_digest(
        "pinned production record",
        BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD_DIGEST,
        &record.record_digest,
    )?;

    let expected_layout = BlsDoryAggregateLayout::new(
        BLS_DORY_BLAKE3_SHARED_DORY_NU,
        BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
    )?;
    verifier_context.validate_geometry(BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY)?;
    if verifier_context.layout != expected_layout
        || verifier_context.setup_identity
            != decode_blake3_record_hex_32("setup identity", &record.setup_identity)?
        || verifier_context.setup_max_log_n != record.setup_max_log_n as usize
    {
        return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
            "verifier context",
        ));
    }

    Ok(BlsDoryBlake3TrustedPreprocessingPin {
        projection_version: record.projection_version,
        activation_len: BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES,
        cell_point_variables: BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES.ilog2() as usize,
        trace_rows: BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
        geometry: BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY,
        verifier_context: verifier_context.clone(),
        source_role: BlsDoryBlake3SourceRole::Preprocessing,
        terminal_count: BLS_DORY_BLAKE3_SOURCE_TERMINALS
            [BlsDoryBlake3SourceRole::Preprocessing.index()],
        commitment: decode_blake3_record_commitment(&record.preprocessing_bls_commitment)?,
    })
}

/// Load the two-run-reproduced production pin. Any parse, digest, metadata, setup, or
/// commitment mismatch keeps the production wrapper fail-closed.
#[cfg(feature = "whir-prototype")]
fn native_blake3_production_preprocessing_pin(
    verifier_context: &BlsDoryBlake3VerifierContext,
) -> Result<BlsDoryBlake3TrustedPreprocessingPin, BlsDoryBlake3PreprocessingRecordError> {
    native_blake3_production_preprocessing_pin_from_record(
        BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD,
        verifier_context,
    )
}

#[cfg(feature = "whir-prototype")]
struct BlsDoryBlake3ExecutionRelation<'a> {
    public: &'a [BlsDoryFr],
    constraints: &'a [BlsDoryBlake3ConstraintExpr],
    mixing_powers: &'a [BlsDoryFr],
    raw_evaluation: BlsDoryFr,
}

#[cfg(feature = "whir-prototype")]
#[derive(Clone, Copy)]
struct BlsDoryBlake3AdjacencyRelation {
    trace_rows: BlsDoryFr,
    compression: BlsDoryFr,
    alpha: BlsDoryFr,
    local_mixing: [BlsDoryFr; 2],
    rational_mixing: BlsDoryFr,
}

#[cfg(feature = "whir-prototype")]
// This is only a shape adapter for the legacy narrow AIR. The zero Goldilocks
// point and evaluation are intentional placeholders: the authenticated BLS
// point and evaluation remain exclusively in the bridge/native accumulator.
fn native_blake3_statement_from_bridge(
    bridge: &BlsDoryOutputBridgeStatement,
) -> StructuredBlake3Statement {
    StructuredBlake3Statement {
        challenge_digest: bridge.challenge_digest(),
        final_activation_len: bridge.final_activation_len(),
        final_activation_digest: bridge.final_activation_digest(),
        final_activation_point: vec![ExtensionElement { limbs: [0; 3] }; bridge.cell_point().len()],
        final_activation_evaluation: ExtensionElement { limbs: [0; 3] },
    }
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_public_values(
    bridge: &BlsDoryOutputBridgeStatement,
) -> Result<Vec<BlsDoryFr>, BlsDoryAggregateError> {
    public_values(&native_blake3_statement_from_bridge(bridge))
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)
        .map(|values| {
            values
                .into_iter()
                .map(|value| BlsDoryFr::from_i64(centered_goldilocks(value)))
                .collect()
        })
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_execution_transcript(
    bridge: &BlsDoryOutputBridgeStatement,
    commitments: &BlsDoryBlake3SourceCommitments,
) -> BlsDoryTranscript {
    let mut transcript = BlsDoryTranscript::new(b"blake3-native-execution-sumcheck-v2");
    transcript.append_bytes(b"protocol-version", &2_u16.to_le_bytes());
    transcript.append_bytes(b"challenge-digest", &bridge.challenge_digest());
    transcript.append_bytes(
        b"activation-length",
        &(bridge.final_activation_len() as u64).to_le_bytes(),
    );
    transcript.append_bytes(b"activation-digest", &bridge.final_activation_digest());
    transcript.append_bytes(b"dory-binding", &bridge.transcript_binding());
    transcript.append_bytes(
        b"point-count",
        &(bridge.cell_point().len() as u64).to_le_bytes(),
    );
    for coordinate in bridge.cell_point() {
        transcript.append_field(b"dory-point", coordinate);
    }
    transcript.append_field(b"raw-evaluation", &bridge.raw_byte_evaluation());
    transcript.append_bytes(
        b"source-count",
        &(BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS as u64).to_le_bytes(),
    );
    for (role, terminal_count) in [
        BlsDoryBlake3SourceRole::Main,
        BlsDoryBlake3SourceRole::Accumulator,
        BlsDoryBlake3SourceRole::Preprocessing,
    ]
    .into_iter()
    .zip(BLS_DORY_BLAKE3_EXECUTION_SOURCE_TERMINALS)
    {
        append_native_blake3_source_descriptor(
            &mut transcript,
            role,
            terminal_count,
            commitments.commitment(role),
        );
    }
    transcript
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_constraint_powers(transcript: &mut BlsDoryTranscript) -> Vec<BlsDoryFr> {
    let mixing = transcript.challenge_scalar(b"constraint-mixing");
    let mut powers = Vec::with_capacity(BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS);
    let mut power = BlsDoryFr::from_u64(1);
    for _ in 0..BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS {
        powers.push(power);
        power = power * mixing;
    }
    powers
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_cell_point(
    transcript: &mut BlsDoryTranscript,
    variables: usize,
) -> Vec<BlsDoryFr> {
    (0..variables)
        .map(|index| {
            transcript.append_bytes(b"cell-index", &(index as u64).to_le_bytes());
            transcript.challenge_scalar(b"cell-point")
        })
        .collect()
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_absorb_sumcheck_round(
    transcript: &mut BlsDoryTranscript,
    round_index: usize,
    evaluations: &[BlsDoryFr],
) {
    transcript.append_bytes(b"round-index", &(round_index as u64).to_le_bytes());
    transcript.append_bytes(b"round-count", &(evaluations.len() as u64).to_le_bytes());
    for evaluation in evaluations {
        transcript.append_field(b"round-evaluation", evaluation);
    }
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_absorb_terminal(transcript: &mut BlsDoryTranscript, terminal: &[BlsDoryFr]) {
    transcript.append_bytes(b"terminal-count", &(terminal.len() as u64).to_le_bytes());
    for evaluation in terminal {
        transcript.append_field(b"terminal-evaluation", evaluation);
    }
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_evaluate_samples(
    values: &[BlsDoryFr],
    expected_samples: usize,
    point: BlsDoryFr,
) -> Option<BlsDoryFr> {
    if values.len() != expected_samples {
        return None;
    }
    values
        .iter()
        .copied()
        .enumerate()
        .try_fold(BlsDoryFr::zero(), |result, (index, value)| {
            let mut numerator = BlsDoryFr::from_u64(1);
            let mut denominator = BlsDoryFr::from_u64(1);
            for other in 0..values.len() {
                if other != index {
                    numerator = numerator * (point - BlsDoryFr::from_u64(other as u64));
                    denominator = denominator * BlsDoryFr::from_i64(index as i64 - other as i64);
                }
            }
            Some(result + value * numerator * denominator.inv()?)
        })
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_boolean_equality(index: usize, point: &[BlsDoryFr]) -> BlsDoryFr {
    point
        .iter()
        .enumerate()
        .fold(BlsDoryFr::from_u64(1), |weight, (variable, coordinate)| {
            if (index >> variable) & 1 == 1 {
                weight * *coordinate
            } else {
                weight * (BlsDoryFr::from_u64(1) - *coordinate)
            }
        })
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_equality_evaluation(left: &[BlsDoryFr], right: &[BlsDoryFr]) -> Option<BlsDoryFr> {
    if left.len() != right.len() {
        return None;
    }
    Some(
        left.iter()
            .zip(right)
            .fold(BlsDoryFr::from_u64(1), |product, (left, right)| {
                product
                    * ((BlsDoryFr::from_u64(1) - *left) * (BlsDoryFr::from_u64(1) - *right)
                        + *left * *right)
            }),
    )
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_coefficient_terminal(
    air: &NarrowBlake3Air,
    dory_point: &[BlsDoryFr],
    sumcheck_point: &[BlsDoryFr],
) -> [BlsDoryFr; 8] {
    let mut terminal = [BlsDoryFr::zero(); 8];
    for row in 0..air.trace_rows() {
        let equality = native_blake3_boolean_equality(row, sumcheck_point);
        let coefficients =
            native_byte_coefficients(air.activation_group_index_at_row(row), dory_point);
        for byte in 0..8 {
            terminal[byte] = terminal[byte] + equality * coefficients[byte];
        }
    }
    terminal
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_execution_relation_value(
    terminal: &[BlsDoryFr],
    selectors: [BlsDoryFr; 3],
    coefficients: &[BlsDoryFr; 8],
    relation: &BlsDoryBlake3ExecutionRelation<'_>,
) -> Result<BlsDoryFr, BlsDoryAggregateError> {
    if terminal.len() != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
        || relation.constraints.len() + 3 != BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS
        || relation.mixing_powers.len() != BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let main_next_start = BLS_DORY_BLAKE3_MAIN_WIDTH;
    let preprocessed_local_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
    let preprocessed_next_start = preprocessed_local_start + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH;
    let values = BlsDoryBlake3Evaluation {
        main_local: &terminal[..main_next_start],
        main_next: &terminal[main_next_start..preprocessed_local_start],
        preprocessed_local: &terminal[preprocessed_local_start..preprocessed_next_start],
        preprocessed_next: &terminal[preprocessed_next_start..],
        public: relation.public,
        periodic: &[],
        first_row: selectors[0],
        last_row: selectors[1],
        transition: selectors[2],
    };
    let mut mixed = relation
        .constraints
        .iter()
        .zip(relation.mixing_powers)
        .fold(BlsDoryFr::zero(), |sum, (constraint, coefficient)| {
            sum + constraint.evaluate(&values) * *coefficient
        });
    let native = native_evaluation_residuals_from_coefficients(
        &BlsDoryNativeEvaluationRow {
            main_local: values.main_local,
            main_next: values.main_next,
            first_row: values.first_row,
            last_row: values.last_row,
            transition: values.transition,
        },
        coefficients,
        relation.raw_evaluation,
    );
    for (residual, coefficient) in native
        .into_iter()
        .zip(&relation.mixing_powers[relation.constraints.len()..])
    {
        mixed = mixed + residual * *coefficient;
    }
    Ok(mixed)
}

#[cfg(feature = "whir-prototype")]
struct BlsDoryBlake3ExecutionAuxiliaryTables {
    equality: Vec<BlsDoryFr>,
    first: Vec<BlsDoryFr>,
    last: Vec<BlsDoryFr>,
    transition: Vec<BlsDoryFr>,
    byte_coefficients: [Vec<BlsDoryFr>; 8],
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryBlake3ExecutionAuxiliaryTables {
    fn new(
        air: &NarrowBlake3Air,
        equality_point: &[BlsDoryFr],
        coefficient_point: &[BlsDoryFr],
    ) -> Result<Self, BlsDoryAggregateError> {
        let rows = air.trace_rows();
        if !rows.is_power_of_two() || equality_point.len() != rows.ilog2() as usize {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }

        let mut equality = allocate_native_blake3_auxiliary_table(rows, BlsDoryFr::zero())?;
        equality[0] = BlsDoryFr::from_u64(1);
        let mut active = 1usize;
        for coordinate in equality_point {
            for index in (0..active).rev() {
                let value = equality[index];
                equality[index] = value * (BlsDoryFr::from_u64(1) - *coordinate);
                equality[index + active] = value * *coordinate;
            }
            active = active
                .checked_mul(2)
                .ok_or(BlsDoryAggregateError::ProverStorage)?;
        }
        if active != rows {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }

        let mut first = allocate_native_blake3_auxiliary_table(rows, BlsDoryFr::zero())?;
        first[0] = BlsDoryFr::from_u64(1);
        let mut last = allocate_native_blake3_auxiliary_table(rows, BlsDoryFr::zero())?;
        last[rows - 1] = BlsDoryFr::from_u64(1);
        let mut transition = allocate_native_blake3_auxiliary_table(rows, BlsDoryFr::from_u64(1))?;
        transition[rows - 1] = BlsDoryFr::zero();

        let mut byte_coefficients: [Vec<BlsDoryFr>; 8] = std::array::from_fn(|_| Vec::new());
        for table in &mut byte_coefficients {
            table
                .try_reserve_exact(rows)
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
            table.resize(rows, BlsDoryFr::zero());
        }
        for row in 0..rows {
            let coefficients =
                native_byte_coefficients(air.activation_group_index_at_row(row), coefficient_point);
            for (table, coefficient) in byte_coefficients.iter_mut().zip(coefficients) {
                table[row] = coefficient;
            }
        }

        Ok(Self {
            equality,
            first,
            last,
            transition,
            byte_coefficients,
        })
    }

    fn active_rows(&self) -> Result<usize, BlsDoryAggregateError> {
        let rows = self.equality.len();
        if rows == 0
            || self.first.len() != rows
            || self.last.len() != rows
            || self.transition.len() != rows
            || self
                .byte_coefficients
                .iter()
                .any(|table| table.len() != rows)
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        Ok(rows)
    }

    fn fold(&mut self, challenge: BlsDoryFr) -> Result<(), BlsDoryAggregateError> {
        let rows = self.active_rows()?;
        if rows < 2 || rows & 1 != 0 {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        fold_native_blake3_auxiliary_table(&mut self.equality, challenge);
        fold_native_blake3_auxiliary_table(&mut self.first, challenge);
        fold_native_blake3_auxiliary_table(&mut self.last, challenge);
        fold_native_blake3_auxiliary_table(&mut self.transition, challenge);
        for table in &mut self.byte_coefficients {
            fold_native_blake3_auxiliary_table(table, challenge);
        }
        Ok(())
    }

    fn terminal(
        &self,
    ) -> Result<(BlsDoryFr, [BlsDoryFr; 3], [BlsDoryFr; 8]), BlsDoryAggregateError> {
        if self.active_rows()? != 1 {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        Ok((
            self.equality[0],
            [self.first[0], self.last[0], self.transition[0]],
            std::array::from_fn(|byte| self.byte_coefficients[byte][0]),
        ))
    }
}

#[cfg(feature = "whir-prototype")]
fn allocate_native_blake3_auxiliary_table(
    rows: usize,
    value: BlsDoryFr,
) -> Result<Vec<BlsDoryFr>, BlsDoryAggregateError> {
    let mut table = Vec::new();
    table
        .try_reserve_exact(rows)
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    table.resize(rows, value);
    Ok(table)
}

#[cfg(feature = "whir-prototype")]
fn fold_native_blake3_auxiliary_table(table: &mut Vec<BlsDoryFr>, challenge: BlsDoryFr) {
    let folded = table.len() / 2;
    for pair in 0..folded {
        let lower = table[2 * pair];
        let upper = table[2 * pair + 1];
        table[pair] = lower + challenge * (upper - lower);
    }
    table.truncate(folded);
}

#[cfg(feature = "whir-prototype")]
fn for_each_authenticated_execution_root_pair(
    prepared: &mut PreparedBlsDoryBlake3Sources,
    maximum_block_rows: usize,
    mut visitor: impl FnMut(
        usize,
        &BlsDoryBlake3ExecutionRoundRow,
        &BlsDoryBlake3ExecutionRoundRow,
    ) -> Result<(), BlsDoryAggregateError>,
) -> Result<(), BlsDoryAggregateError> {
    let trace_rows = prepared.binding.trace_rows;
    if trace_rows < 2 || !trace_rows.is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let mut lower = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS];
    let mut visited = 0usize;
    let mut pair_index = 0usize;
    prepared.for_each_authenticated_execution_row(maximum_block_rows, |row, terminal| {
        if row != visited {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        if row & 1 == 0 {
            lower.copy_from_slice(terminal);
        } else {
            visitor(pair_index, &lower, terminal)?;
            pair_index += 1;
        }
        visited += 1;
        Ok(())
    })?;
    if visited != trace_rows || pair_index != trace_rows / 2 {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn for_each_authenticated_execution_round_pair(
    artifact: &BlsDoryBlake3ExecutionRoundArtifact,
    mut visitor: impl FnMut(
        usize,
        &BlsDoryBlake3ExecutionRoundRow,
        &BlsDoryBlake3ExecutionRoundRow,
    ) -> Result<(), BlsDoryAggregateError>,
) -> Result<(), BlsDoryAggregateError> {
    let mut pair_index = 0usize;
    let mut visitor_error = None;
    let traversal = artifact.for_each_row_pair(|lower, upper| {
        match visitor(pair_index, lower, upper) {
            Ok(()) => pair_index += 1,
            Err(error) => {
                visitor_error = Some(error);
                return Err(BlsDoryFoldArtifactError::InvalidArtifact);
            }
        }
        Ok(())
    });
    if let Some(error) = visitor_error {
        return Err(error);
    }
    traversal.map_err(native_blake3_fold_artifact_error)?;
    let expected_pairs = usize::try_from(artifact.active_rows / 2)
        .map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    if pair_index != expected_pairs {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_accumulate_execution_pair(
    pair_index: usize,
    lower: &BlsDoryBlake3ExecutionRoundRow,
    upper: &BlsDoryBlake3ExecutionRoundRow,
    auxiliary: &BlsDoryBlake3ExecutionAuxiliaryTables,
    relation: &BlsDoryBlake3ExecutionRelation<'_>,
    evaluations: &mut [BlsDoryFr; BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1],
) -> Result<(), BlsDoryAggregateError> {
    let offset = pair_index
        .checked_mul(2)
        .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
    let rows = auxiliary.active_rows()?;
    if offset + 1 >= rows {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }

    let mut terminal = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS];
    for (sample_index, evaluation) in evaluations.iter_mut().enumerate() {
        let sample = BlsDoryFr::from_u64(sample_index as u64);
        for column in 0..BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS {
            terminal[column] = lower[column] + sample * (upper[column] - lower[column]);
        }
        let interpolate =
            |table: &[BlsDoryFr]| table[offset] + sample * (table[offset + 1] - table[offset]);
        let selectors = [
            interpolate(&auxiliary.first),
            interpolate(&auxiliary.last),
            interpolate(&auxiliary.transition),
        ];
        let coefficients =
            std::array::from_fn(|byte| interpolate(&auxiliary.byte_coefficients[byte]));
        let equality = interpolate(&auxiliary.equality);
        *evaluation = *evaluation
            + equality
                * native_blake3_execution_relation_value(
                    &terminal,
                    selectors,
                    &coefficients,
                    relation,
                )?;
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn evaluate_native_blake3_execution_root_round(
    prepared: &mut PreparedBlsDoryBlake3Sources,
    maximum_block_rows: usize,
    auxiliary: &BlsDoryBlake3ExecutionAuxiliaryTables,
    relation: &BlsDoryBlake3ExecutionRelation<'_>,
) -> Result<[BlsDoryFr; BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1], BlsDoryAggregateError> {
    let mut evaluations = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1];
    for_each_authenticated_execution_root_pair(
        prepared,
        maximum_block_rows,
        |pair_index, lower, upper| {
            native_blake3_accumulate_execution_pair(
                pair_index,
                lower,
                upper,
                auxiliary,
                relation,
                &mut evaluations,
            )
        },
    )?;
    Ok(evaluations)
}

#[cfg(feature = "whir-prototype")]
fn evaluate_native_blake3_execution_artifact_round(
    artifact: &BlsDoryBlake3ExecutionRoundArtifact,
    auxiliary: &BlsDoryBlake3ExecutionAuxiliaryTables,
    relation: &BlsDoryBlake3ExecutionRelation<'_>,
) -> Result<[BlsDoryFr; BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1], BlsDoryAggregateError> {
    let artifact_rows = usize::try_from(artifact.active_rows)
        .map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    if artifact_rows != auxiliary.active_rows()? {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    let mut evaluations = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1];
    for_each_authenticated_execution_round_pair(artifact, |pair_index, lower, upper| {
        native_blake3_accumulate_execution_pair(
            pair_index,
            lower,
            upper,
            auxiliary,
            relation,
            &mut evaluations,
        )
    })?;
    Ok(evaluations)
}

#[cfg(feature = "whir-prototype")]
fn fold_native_blake3_execution_root(
    prepared: &mut PreparedBlsDoryBlake3Sources,
    maximum_block_rows: usize,
    scratch_directory: &std::path::Path,
    root_lineage: [u8; 32],
    challenge: BlsDoryFr,
) -> Result<BlsDoryBlake3ExecutionRoundArtifact, BlsDoryAggregateError> {
    let active_rows = prepared.binding.trace_rows / 2;
    let active_rows =
        u64::try_from(active_rows).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let mut writer = BlsDoryBlake3ExecutionRoundArtifactWriter::create(
        scratch_directory,
        active_rows,
        0,
        BlsDoryBlake3ExecutionRoundParent::Root(root_lineage),
    )
    .map_err(native_blake3_fold_artifact_error)?;
    let mut folded = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS];
    for_each_authenticated_execution_root_pair(
        prepared,
        maximum_block_rows,
        |_pair_index, lower, upper| {
            for column in 0..BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS {
                folded[column] = lower[column] + challenge * (upper[column] - lower[column]);
            }
            writer
                .write_row(&folded)
                .map_err(native_blake3_fold_artifact_error)
        },
    )?;
    writer.finish().map_err(native_blake3_fold_artifact_error)
}

#[cfg(feature = "whir-prototype")]
fn fold_native_blake3_execution_artifact(
    parent: &BlsDoryBlake3ExecutionRoundArtifact,
    scratch_directory: &std::path::Path,
    challenge: BlsDoryFr,
) -> Result<BlsDoryBlake3ExecutionRoundArtifact, BlsDoryAggregateError> {
    if parent.active_rows < 2 {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    let round_index = parent
        .round_index
        .checked_add(1)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let mut writer = BlsDoryBlake3ExecutionRoundArtifactWriter::create(
        scratch_directory,
        parent.active_rows / 2,
        round_index,
        BlsDoryBlake3ExecutionRoundParent::Previous(parent),
    )
    .map_err(native_blake3_fold_artifact_error)?;
    let mut folded = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS];

    // The writer remains locally owned until the complete parent traversal,
    // including footer authentication, succeeds. Any read or callback error
    // therefore drops and deletes the unfinished child before returning.
    parent
        .for_each_row_pair(|lower, upper| {
            for column in 0..BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS {
                folded[column] = lower[column] + challenge * (upper[column] - lower[column]);
            }
            writer.write_row(&folded)
        })
        .map_err(native_blake3_fold_artifact_error)?;
    writer.finish().map_err(native_blake3_fold_artifact_error)
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_execution_round_root_lineage(
    transcript_digest: [u8; 32],
    trace_rows: usize,
) -> Result<[u8; 32], BlsDoryAggregateError> {
    if transcript_digest == [0; 32] || !trace_rows.is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let mut hasher = blake3::Hasher::new_derive_key(BLS_DORY_BLAKE3_EXECUTION_ROUND_ROOT_DOMAIN);
    hasher.update(&transcript_digest);
    let trace_rows =
        u64::try_from(trace_rows).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    hasher.update(&trace_rows.to_le_bytes());
    hasher.update(&(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS as u64).to_le_bytes());
    let digest = *hasher.finalize().as_bytes();
    if digest == [0; 32] {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(digest)
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_fold_artifact_error(error: BlsDoryFoldArtifactError) -> BlsDoryAggregateError {
    match error {
        BlsDoryFoldArtifactError::InvalidSpec => BlsDoryAggregateError::InvalidProofShape,
        BlsDoryFoldArtifactError::InvalidArtifact
        | BlsDoryFoldArtifactError::InvalidScalar
        | BlsDoryFoldArtifactError::Authentication
        | BlsDoryFoldArtifactError::Io(_) => BlsDoryAggregateError::ProverStorage,
    }
}

/// Produce the native execution sumcheck without materializing the 746-column
/// terminal matrix. The streamed root is read twice; each later authenticated
/// round artifact is also read twice, first for the round polynomial and then
/// transactionally for the challenge fold.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn prove_native_blake3_execution_sumcheck_out_of_core(
    prepared: &mut PreparedBlsDoryBlake3Sources,
    bridge: &BlsDoryOutputBridgeStatement,
    scratch_directory: &std::path::Path,
    maximum_block_rows: usize,
) -> Result<BlsDoryBlake3ExecutionSumcheckProof, BlsDoryAggregateError> {
    if maximum_block_rows == 0 || !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let native_statement = native_blake3_statement_from_bridge(bridge);
    let air = NarrowBlake3Air::new(&native_statement)
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let trace_rows = air.trace_rows();
    if trace_rows != prepared.binding.trace_rows || !trace_rows.is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let variables = trace_rows.ilog2() as usize;
    let public = native_blake3_public_values(bridge)?;
    let constraints = bls_dory_native_blake3_constraint_ir(bridge.final_activation_len())
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    if constraints.len() + 3 != BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }

    let commitments = prepared.commitments();
    let mut transcript = native_blake3_execution_transcript(bridge, &commitments);
    let mixing_powers = native_blake3_constraint_powers(&mut transcript);
    let cell_point = native_blake3_cell_point(&mut transcript, variables);
    let root_lineage = native_blake3_execution_round_root_lineage(transcript.digest(), trace_rows)?;
    let relation = BlsDoryBlake3ExecutionRelation {
        public: &public,
        constraints: &constraints,
        mixing_powers: &mixing_powers,
        raw_evaluation: bridge.raw_byte_evaluation(),
    };
    let mut auxiliary =
        BlsDoryBlake3ExecutionAuxiliaryTables::new(&air, &cell_point, bridge.cell_point())?;
    let mut rounds = Vec::new();
    rounds
        .try_reserve_exact(variables)
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    let mut claim = BlsDoryFr::zero();
    let mut current_artifact = None;

    for round_index in 0..variables {
        let evaluations = if let Some(parent) = current_artifact.as_ref() {
            evaluate_native_blake3_execution_artifact_round(parent, &auxiliary, &relation)?
        } else {
            evaluate_native_blake3_execution_root_round(
                prepared,
                maximum_block_rows,
                &auxiliary,
                &relation,
            )?
        };
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryAggregateError::SumcheckFailed);
        }
        native_blake3_absorb_sumcheck_round(&mut transcript, round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = native_blake3_evaluate_samples(
            &evaluations,
            BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1,
            challenge,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;

        let child = if let Some(parent) = current_artifact.as_ref() {
            fold_native_blake3_execution_artifact(parent, scratch_directory, challenge)?
        } else {
            fold_native_blake3_execution_root(
                prepared,
                maximum_block_rows,
                scratch_directory,
                root_lineage,
                challenge,
            )?
        };
        auxiliary.fold(challenge)?;
        current_artifact = Some(child);
        rounds.push(evaluations.to_vec());
    }

    let terminal = current_artifact
        .as_ref()
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?
        .terminal_row()
        .map_err(native_blake3_fold_artifact_error)?;
    let (equality, selectors, coefficients) = auxiliary.terminal()?;
    let expected = equality
        * native_blake3_execution_relation_value(&terminal, selectors, &coefficients, &relation)?;
    if claim != expected {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    native_blake3_absorb_terminal(&mut transcript, &terminal);
    let proof = BlsDoryBlake3ExecutionSumcheckProof {
        rounds,
        terminal_evaluations: terminal.to_vec(),
        transcript_digest: transcript.digest(),
    };
    let verified = verify_native_blake3_execution_sumcheck(
        &proof,
        &air,
        &public,
        &constraints,
        bridge,
        &commitments,
    )?;
    if verified.point.len() != variables || verified.transcript_digest != proof.transcript_digest {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    Ok(proof)
}

#[cfg(feature = "whir-prototype")]
fn verify_native_blake3_execution_sumcheck(
    proof: &BlsDoryBlake3ExecutionSumcheckProof,
    air: &NarrowBlake3Air,
    public: &[BlsDoryFr],
    constraints: &[BlsDoryBlake3ConstraintExpr],
    bridge: &BlsDoryOutputBridgeStatement,
    commitments: &BlsDoryBlake3SourceCommitments,
) -> Result<VerifiedBlsDoryBlake3Sumcheck, BlsDoryAggregateError> {
    let trace_rows = air.trace_rows();
    if !trace_rows.is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let variables = trace_rows.ilog2() as usize;
    if proof.rounds.len() != variables
        || proof.terminal_evaluations.len() != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
        || proof
            .rounds
            .iter()
            .any(|round| round.len() != BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1)
        || constraints.len() + 3 != BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let mut transcript = native_blake3_execution_transcript(bridge, commitments);
    let mixing_powers = native_blake3_constraint_powers(&mut transcript);
    let cell_point = native_blake3_cell_point(&mut transcript, variables);
    let relation = BlsDoryBlake3ExecutionRelation {
        public,
        constraints,
        mixing_powers: &mixing_powers,
        raw_evaluation: bridge.raw_byte_evaluation(),
    };
    let mut claim = BlsDoryFr::zero();
    let mut point = Vec::with_capacity(variables);
    for (round_index, round) in proof.rounds.iter().enumerate() {
        if round[0] + round[1] != claim {
            return Err(BlsDoryAggregateError::SumcheckFailed);
        }
        native_blake3_absorb_sumcheck_round(&mut transcript, round_index, round);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = native_blake3_evaluate_samples(
            round,
            BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1,
            challenge,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        point.push(challenge);
    }
    let first = point
        .iter()
        .fold(BlsDoryFr::from_u64(1), |value, coordinate| {
            value * (BlsDoryFr::from_u64(1) - *coordinate)
        });
    let last = point
        .iter()
        .fold(BlsDoryFr::from_u64(1), |value, coordinate| {
            value * *coordinate
        });
    let selectors = [first, last, BlsDoryFr::from_u64(1) - last];
    let coefficients = native_blake3_coefficient_terminal(air, bridge.cell_point(), &point);
    let expected = native_blake3_equality_evaluation(&cell_point, &point)
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?
        * native_blake3_execution_relation_value(
            &proof.terminal_evaluations,
            selectors,
            &coefficients,
            &relation,
        )?;
    if claim != expected {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    native_blake3_absorb_terminal(&mut transcript, &proof.terminal_evaluations);
    let transcript_digest = transcript.digest();
    if transcript_digest != proof.transcript_digest {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    Ok(VerifiedBlsDoryBlake3Sumcheck {
        point,
        transcript_digest,
    })
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_adjacency_key(
    values: impl IntoIterator<Item = BlsDoryFr>,
    row_label: BlsDoryFr,
    compression: BlsDoryFr,
) -> BlsDoryFr {
    values
        .into_iter()
        .fold(row_label, |key, value| key * compression + value)
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_adjacency_relation_value(
    terminal: &[BlsDoryFr],
    row_index: BlsDoryFr,
    first_row: BlsDoryFr,
    equality: BlsDoryFr,
    relation: BlsDoryBlake3AdjacencyRelation,
) -> Option<BlsDoryFr> {
    if terminal.len() != BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS {
        return None;
    }
    let next_start = BLS_DORY_BLAKE3_MAIN_WIDTH;
    let inverse_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
    let local_key = native_blake3_adjacency_key(
        terminal[..next_start].iter().copied(),
        row_index - BlsDoryFr::from_u64(1) + relation.trace_rows * first_row,
        relation.compression,
    );
    let next_key = native_blake3_adjacency_key(
        terminal[next_start..inverse_start].iter().copied(),
        row_index,
        relation.compression,
    );
    let local_inverse = terminal[inverse_start];
    let next_inverse = terminal[inverse_start + 1];
    let local_constraint = local_inverse * (relation.alpha - local_key) - BlsDoryFr::from_u64(1);
    let next_constraint = next_inverse * (relation.alpha - next_key) - BlsDoryFr::from_u64(1);
    Some(
        equality
            * (relation.local_mixing[0] * local_constraint
                + relation.local_mixing[1] * next_constraint)
            + relation.rational_mixing * (next_inverse - local_inverse),
    )
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_row_index_evaluation(point: &[BlsDoryFr]) -> Option<BlsDoryFr> {
    if point.len() >= u64::BITS as usize {
        return None;
    }
    Some(
        point
            .iter()
            .enumerate()
            .fold(BlsDoryFr::zero(), |value, (variable, coordinate)| {
                value + BlsDoryFr::from_u64(1_u64 << variable) * *coordinate
            }),
    )
}

#[cfg(feature = "whir-prototype")]
struct BlsDoryBlake3AdjacencyAuxiliaryTables {
    equality: Vec<BlsDoryFr>,
    row_index: Vec<BlsDoryFr>,
    first: Vec<BlsDoryFr>,
}

#[cfg(feature = "whir-prototype")]
impl BlsDoryBlake3AdjacencyAuxiliaryTables {
    fn new(trace_rows: usize, equality_point: &[BlsDoryFr]) -> Result<Self, BlsDoryAggregateError> {
        if !trace_rows.is_power_of_two() || equality_point.len() != trace_rows.ilog2() as usize {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        let mut equality = allocate_native_blake3_auxiliary_table(trace_rows, BlsDoryFr::zero())?;
        equality[0] = BlsDoryFr::from_u64(1);
        let mut active = 1usize;
        for coordinate in equality_point {
            for index in (0..active).rev() {
                let value = equality[index];
                equality[index] = value * (BlsDoryFr::from_u64(1) - *coordinate);
                equality[index + active] = value * *coordinate;
            }
            active = active
                .checked_mul(2)
                .ok_or(BlsDoryAggregateError::ProverStorage)?;
        }
        if active != trace_rows {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }

        let mut row_index = allocate_native_blake3_auxiliary_table(trace_rows, BlsDoryFr::zero())?;
        for (row, value) in row_index.iter_mut().enumerate() {
            let row = u64::try_from(row).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
            *value = BlsDoryFr::from_u64(row);
        }
        let mut first = allocate_native_blake3_auxiliary_table(trace_rows, BlsDoryFr::zero())?;
        first[0] = BlsDoryFr::from_u64(1);
        Ok(Self {
            equality,
            row_index,
            first,
        })
    }

    fn active_rows(&self) -> Result<usize, BlsDoryAggregateError> {
        let rows = self.equality.len();
        if rows == 0 || self.row_index.len() != rows || self.first.len() != rows {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        Ok(rows)
    }

    fn fold(&mut self, challenge: BlsDoryFr) -> Result<(), BlsDoryAggregateError> {
        let rows = self.active_rows()?;
        if rows < 2 || rows & 1 != 0 {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        fold_native_blake3_auxiliary_table(&mut self.equality, challenge);
        fold_native_blake3_auxiliary_table(&mut self.row_index, challenge);
        fold_native_blake3_auxiliary_table(&mut self.first, challenge);
        Ok(())
    }

    fn terminal(&self) -> Result<(BlsDoryFr, BlsDoryFr, BlsDoryFr), BlsDoryAggregateError> {
        if self.active_rows()? != 1 {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        Ok((self.equality[0], self.row_index[0], self.first[0]))
    }
}

#[cfg(feature = "whir-prototype")]
fn for_each_authenticated_adjacency_root_pair(
    prepared: &mut PreparedBlsDoryBlake3Sources,
    maximum_block_rows: usize,
    mut visitor: impl FnMut(
        usize,
        &[BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS],
        &[BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS],
    ) -> Result<(), BlsDoryAggregateError>,
) -> Result<(), BlsDoryAggregateError> {
    let trace_rows = prepared.binding.trace_rows;
    if trace_rows < 2 || !trace_rows.is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let mut lower = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS];
    let mut visited = 0usize;
    let mut pair_index = 0usize;
    prepared.for_each_authenticated_adjacency_row(maximum_block_rows, |row, terminal| {
        if row != visited {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        if row & 1 == 0 {
            lower.copy_from_slice(terminal);
        } else {
            visitor(pair_index, &lower, terminal)?;
            pair_index += 1;
        }
        visited += 1;
        Ok(())
    })?;
    if visited != trace_rows || pair_index != trace_rows / 2 {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_accumulate_adjacency_pair(
    pair_index: usize,
    lower: &[BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS],
    upper: &[BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS],
    auxiliary: &BlsDoryBlake3AdjacencyAuxiliaryTables,
    relation: BlsDoryBlake3AdjacencyRelation,
    evaluations: &mut [BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1],
) -> Result<(), BlsDoryAggregateError> {
    let offset = pair_index
        .checked_mul(2)
        .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
    let rows = auxiliary.active_rows()?;
    if offset + 1 >= rows {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    let mut terminal = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS];
    for (sample_index, evaluation) in evaluations.iter_mut().enumerate() {
        let sample = BlsDoryFr::from_u64(sample_index as u64);
        for column in 0..BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS {
            terminal[column] = lower[column] + sample * (upper[column] - lower[column]);
        }
        let interpolate =
            |table: &[BlsDoryFr]| table[offset] + sample * (table[offset + 1] - table[offset]);
        *evaluation = *evaluation
            + native_blake3_adjacency_relation_value(
                &terminal,
                interpolate(&auxiliary.row_index),
                interpolate(&auxiliary.first),
                interpolate(&auxiliary.equality),
                relation,
            )
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn evaluate_native_blake3_adjacency_root_round(
    prepared: &mut PreparedBlsDoryBlake3Sources,
    maximum_block_rows: usize,
    auxiliary: &BlsDoryBlake3AdjacencyAuxiliaryTables,
    relation: BlsDoryBlake3AdjacencyRelation,
) -> Result<[BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1], BlsDoryAggregateError> {
    let mut evaluations = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1];
    for_each_authenticated_adjacency_root_pair(
        prepared,
        maximum_block_rows,
        |pair_index, lower, upper| {
            native_blake3_accumulate_adjacency_pair(
                pair_index,
                lower,
                upper,
                auxiliary,
                relation,
                &mut evaluations,
            )
        },
    )?;
    Ok(evaluations)
}

#[cfg(feature = "whir-prototype")]
fn for_each_authenticated_adjacency_round_pair(
    artifact: &BlsDoryBlake3AdjacencyRoundArtifact,
    mut visitor: impl FnMut(
        usize,
        &BlsDoryBlake3AdjacencyRoundRow,
        &BlsDoryBlake3AdjacencyRoundRow,
    ) -> Result<(), BlsDoryAggregateError>,
) -> Result<(), BlsDoryAggregateError> {
    let mut pair_index = 0usize;
    let mut visitor_error = None;
    let traversal = artifact.for_each_row_pair(|lower, upper| {
        match visitor(pair_index, lower, upper) {
            Ok(()) => pair_index += 1,
            Err(error) => {
                visitor_error = Some(error);
                return Err(BlsDoryFoldArtifactError::InvalidArtifact);
            }
        }
        Ok(())
    });
    if let Some(error) = visitor_error {
        return Err(error);
    }
    traversal.map_err(native_blake3_fold_artifact_error)?;
    let expected_pairs = usize::try_from(artifact.active_rows() / 2)
        .map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    if pair_index != expected_pairs {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn evaluate_native_blake3_adjacency_artifact_round(
    artifact: &BlsDoryBlake3AdjacencyRoundArtifact,
    auxiliary: &BlsDoryBlake3AdjacencyAuxiliaryTables,
    relation: BlsDoryBlake3AdjacencyRelation,
) -> Result<[BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1], BlsDoryAggregateError> {
    let artifact_rows = usize::try_from(artifact.active_rows())
        .map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    if artifact_rows != auxiliary.active_rows()? {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    let mut evaluations = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1];
    for_each_authenticated_adjacency_round_pair(artifact, |pair_index, lower, upper| {
        native_blake3_accumulate_adjacency_pair(
            pair_index,
            lower,
            upper,
            auxiliary,
            relation,
            &mut evaluations,
        )
    })?;
    Ok(evaluations)
}

#[cfg(feature = "whir-prototype")]
fn fold_native_blake3_adjacency_root(
    prepared: &mut PreparedBlsDoryBlake3Sources,
    maximum_block_rows: usize,
    scratch_directory: &std::path::Path,
    root_lineage: [u8; 32],
    challenge: BlsDoryFr,
) -> Result<BlsDoryBlake3AdjacencyRoundArtifact, BlsDoryAggregateError> {
    let active_rows = prepared.binding.trace_rows / 2;
    let active_rows =
        u64::try_from(active_rows).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let mut writer = BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
        scratch_directory,
        active_rows,
        0,
        BlsDoryBlake3AdjacencyRoundParent::Root(root_lineage),
    )
    .map_err(native_blake3_fold_artifact_error)?;
    let mut folded = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS];
    for_each_authenticated_adjacency_root_pair(
        prepared,
        maximum_block_rows,
        |_pair_index, lower, upper| {
            for column in 0..BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS {
                folded[column] = lower[column] + challenge * (upper[column] - lower[column]);
            }
            writer
                .write_row(&folded)
                .map_err(native_blake3_fold_artifact_error)
        },
    )?;
    writer.finish().map_err(native_blake3_fold_artifact_error)
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_adjacency_round_root_lineage(
    transcript_digest: [u8; 32],
    trace_rows: usize,
) -> Result<[u8; 32], BlsDoryAggregateError> {
    if transcript_digest == [0; 32] || !trace_rows.is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let trace_rows =
        u64::try_from(trace_rows).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let mut hasher = blake3::Hasher::new_derive_key(BLS_DORY_BLAKE3_ADJACENCY_ROUND_ROOT_DOMAIN);
    hasher.update(&transcript_digest);
    hasher.update(&trace_rows.to_le_bytes());
    hasher.update(&(BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS as u64).to_le_bytes());
    let digest = *hasher.finalize().as_bytes();
    if digest == [0; 32] {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(digest)
}

/// Produce the native row-adjacency sumcheck without materializing its
/// 580-column terminal matrix. The authenticated streamed root and every
/// subsequent round artifact are each read twice: once to evaluate the round
/// polynomial and once to transactionally write the challenge-folded child.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn prove_native_blake3_adjacency_sumcheck_out_of_core(
    prepared: &mut PreparedBlsDoryBlake3Sources,
    bridge: &BlsDoryOutputBridgeStatement,
    scratch_directory: &std::path::Path,
    maximum_block_rows: usize,
) -> Result<BlsDoryBlake3AdjacencySumcheckProof, BlsDoryAggregateError> {
    if maximum_block_rows == 0 || !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let air = NarrowBlake3Air::new(&native_blake3_statement_from_bridge(bridge))
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let trace_rows = air.trace_rows();
    if trace_rows != prepared.binding.trace_rows || !trace_rows.is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let variables = trace_rows.ilog2() as usize;
    let trace_rows_field = BlsDoryFr::from_u64(
        u64::try_from(trace_rows).map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
    );
    let commitments = prepared.commitments();
    let adjacency_sources = commitments.adjacency_sources();
    let mut transcript =
        native_blake3_adjacency_transcript(bridge, trace_rows, &adjacency_sources)?;
    let compression = transcript.challenge_scalar(b"row-compression");
    let alpha = transcript.challenge_scalar(b"lookup-alpha");
    transcript.append_bytes(b"inverse-source-count", &1_u64.to_le_bytes());
    append_native_blake3_source_descriptor(
        &mut transcript,
        BlsDoryBlake3SourceRole::Inverse,
        BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES,
        commitments.commitment(BlsDoryBlake3SourceRole::Inverse),
    );
    let local_mixing = [
        transcript.challenge_scalar(b"local-mixing"),
        transcript.challenge_scalar(b"local-mixing"),
    ];
    let rational_mixing = transcript.challenge_scalar(b"rational-mixing");
    let equality_point = native_blake3_cell_point(&mut transcript, variables);
    let root_lineage = native_blake3_adjacency_round_root_lineage(transcript.digest(), trace_rows)?;
    let relation = BlsDoryBlake3AdjacencyRelation {
        trace_rows: trace_rows_field,
        compression,
        alpha,
        local_mixing,
        rational_mixing,
    };
    let mut auxiliary = BlsDoryBlake3AdjacencyAuxiliaryTables::new(trace_rows, &equality_point)?;
    let mut rounds = Vec::new();
    rounds
        .try_reserve_exact(variables)
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    let mut claim = BlsDoryFr::zero();
    let mut current_artifact = None;

    for round_index in 0..variables {
        let evaluations = if let Some(parent) = current_artifact.as_ref() {
            evaluate_native_blake3_adjacency_artifact_round(parent, &auxiliary, relation)?
        } else {
            evaluate_native_blake3_adjacency_root_round(
                prepared,
                maximum_block_rows,
                &auxiliary,
                relation,
            )?
        };
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryAggregateError::SumcheckFailed);
        }
        native_blake3_absorb_sumcheck_round(&mut transcript, round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = native_blake3_evaluate_samples(
            &evaluations,
            BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1,
            challenge,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;

        let child = if let Some(parent) = current_artifact.as_ref() {
            fold_native_blake3_adjacency_artifact(parent, scratch_directory, challenge)
                .map_err(native_blake3_fold_artifact_error)?
        } else {
            fold_native_blake3_adjacency_root(
                prepared,
                maximum_block_rows,
                scratch_directory,
                root_lineage,
                challenge,
            )?
        };
        auxiliary.fold(challenge)?;
        current_artifact = Some(child);
        rounds.push(evaluations.to_vec());
    }

    let terminal = current_artifact
        .as_ref()
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?
        .terminal_row()
        .map_err(native_blake3_fold_artifact_error)?;
    let (equality, row_index, first) = auxiliary.terminal()?;
    let expected =
        native_blake3_adjacency_relation_value(&terminal, row_index, first, equality, relation)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    if claim != expected {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    native_blake3_absorb_terminal(&mut transcript, &terminal);
    let proof = BlsDoryBlake3AdjacencySumcheckProof {
        rounds,
        terminal_evaluations: terminal.to_vec(),
        transcript_digest: transcript.digest(),
    };
    let verified =
        verify_native_blake3_adjacency_sumcheck(&proof, trace_rows, bridge, &commitments)?;
    if verified.point.len() != variables || verified.transcript_digest != proof.transcript_digest {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    Ok(proof)
}

#[cfg(feature = "whir-prototype")]
fn verify_native_blake3_adjacency_sumcheck(
    proof: &BlsDoryBlake3AdjacencySumcheckProof,
    trace_rows: usize,
    bridge: &BlsDoryOutputBridgeStatement,
    commitments: &BlsDoryBlake3SourceCommitments,
) -> Result<VerifiedBlsDoryBlake3Sumcheck, BlsDoryAggregateError> {
    if !trace_rows.is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let variables = trace_rows.ilog2() as usize;
    if proof.rounds.len() != variables
        || proof.terminal_evaluations.len() != BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS
        || proof
            .rounds
            .iter()
            .any(|round| round.len() != BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1)
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let adjacency_sources = commitments.adjacency_sources();
    let mut transcript =
        native_blake3_adjacency_transcript(bridge, trace_rows, &adjacency_sources)?;
    let compression = transcript.challenge_scalar(b"row-compression");
    let alpha = transcript.challenge_scalar(b"lookup-alpha");
    transcript.append_bytes(b"inverse-source-count", &1_u64.to_le_bytes());
    append_native_blake3_source_descriptor(
        &mut transcript,
        BlsDoryBlake3SourceRole::Inverse,
        BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES,
        commitments.commitment(BlsDoryBlake3SourceRole::Inverse),
    );
    let local_mixing = [
        transcript.challenge_scalar(b"local-mixing"),
        transcript.challenge_scalar(b"local-mixing"),
    ];
    let rational_mixing = transcript.challenge_scalar(b"rational-mixing");
    let equality_point = native_blake3_cell_point(&mut transcript, variables);
    let relation = BlsDoryBlake3AdjacencyRelation {
        trace_rows: BlsDoryFr::from_u64(trace_rows as u64),
        compression,
        alpha,
        local_mixing,
        rational_mixing,
    };
    let mut claim = BlsDoryFr::zero();
    let mut point = Vec::with_capacity(variables);
    for (round_index, round) in proof.rounds.iter().enumerate() {
        if round[0] + round[1] != claim {
            return Err(BlsDoryAggregateError::SumcheckFailed);
        }
        native_blake3_absorb_sumcheck_round(&mut transcript, round_index, round);
        let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
        claim = native_blake3_evaluate_samples(
            round,
            BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1,
            challenge,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        point.push(challenge);
    }
    let first = point
        .iter()
        .fold(BlsDoryFr::from_u64(1), |value, coordinate| {
            value * (BlsDoryFr::from_u64(1) - *coordinate)
        });
    let expected = native_blake3_adjacency_relation_value(
        &proof.terminal_evaluations,
        native_blake3_row_index_evaluation(&point)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?,
        first,
        native_blake3_equality_evaluation(&equality_point, &point)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?,
        relation,
    )
    .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    if claim != expected {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    native_blake3_absorb_terminal(&mut transcript, &proof.terminal_evaluations);
    let transcript_digest = transcript.digest();
    if transcript_digest != proof.transcript_digest {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    Ok(VerifiedBlsDoryBlake3Sumcheck {
        point,
        transcript_digest,
    })
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_execution_selector_points(
    sumcheck_digest: [u8; 32],
    commitments: &BlsDoryBlake3SourceCommitments,
) -> (
    [Vec<BlsDoryFr>; BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS],
    [u8; 32],
) {
    let roles = [
        BlsDoryBlake3SourceRole::Main,
        BlsDoryBlake3SourceRole::Accumulator,
        BlsDoryBlake3SourceRole::Preprocessing,
    ];
    let mut transcript = BlsDoryTranscript::new(b"blake3-native-execution-opening-selectors-v2");
    transcript.append_bytes(b"protocol-version", &2_u16.to_le_bytes());
    transcript.append_bytes(b"sumcheck-digest", &sumcheck_digest);
    transcript.append_bytes(
        b"source-count",
        &(BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS as u64).to_le_bytes(),
    );
    let points = std::array::from_fn(|source| {
        transcript.append_bytes(b"source-index", &(source as u64).to_le_bytes());
        append_native_blake3_source_descriptor(
            &mut transcript,
            roles[source],
            BLS_DORY_BLAKE3_EXECUTION_SOURCE_TERMINALS[source],
            commitments.commitment(roles[source]),
        );
        (0..BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES)
            .map(|selector| {
                transcript.append_bytes(b"selector-index", &(selector as u64).to_le_bytes());
                transcript.challenge_scalar(b"opening-selector")
            })
            .collect()
    });
    (points, transcript.digest())
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_adjacency_selector_points(
    sumcheck_digest: [u8; 32],
    commitments: &BlsDoryBlake3SourceCommitments,
) -> (
    [Vec<BlsDoryFr>; BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS],
    [u8; 32],
) {
    let roles = [
        BlsDoryBlake3SourceRole::Main,
        BlsDoryBlake3SourceRole::Accumulator,
        BlsDoryBlake3SourceRole::Inverse,
    ];
    let mut transcript = BlsDoryTranscript::new(b"blake3-native-adjacency-opening-selectors-v2");
    transcript.append_bytes(b"protocol-version", &2_u16.to_le_bytes());
    transcript.append_bytes(b"sumcheck-digest", &sumcheck_digest);
    transcript.append_bytes(
        b"source-count",
        &(BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS as u64).to_le_bytes(),
    );
    let points = std::array::from_fn(|source| {
        transcript.append_bytes(b"source-index", &(source as u64).to_le_bytes());
        append_native_blake3_source_descriptor(
            &mut transcript,
            roles[source],
            BLS_DORY_BLAKE3_ADJACENCY_SOURCE_TERMINALS[source],
            commitments.commitment(roles[source]),
        );
        (0..BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES)
            .map(|selector| {
                transcript.append_bytes(b"selector-index", &(selector as u64).to_le_bytes());
                transcript.challenge_scalar(b"opening-selector")
            })
            .collect()
    });
    (points, transcript.digest())
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_opening_binding(
    bridge: &BlsDoryOutputBridgeStatement,
    digests: BlsDoryBlake3OpeningTranscriptDigests,
    geometry: BlsDoryBlake3ReplayGeometry,
    verifier_context: &BlsDoryBlake3VerifierContext,
    commitments: &BlsDoryBlake3SourceCommitments,
) -> [u8; 32] {
    let mut transcript = BlsDoryTranscript::new(b"blake3-native-six-opening-binding-v2");
    transcript.append_bytes(b"protocol-version", &2_u16.to_le_bytes());
    transcript.append_bytes(
        b"projection-version",
        &BLS_DORY_BLAKE3_PROJECTION_VERSION.to_le_bytes(),
    );
    transcript.append_bytes(b"challenge-digest", &bridge.challenge_digest());
    transcript.append_bytes(
        b"activation-length",
        &(bridge.final_activation_len() as u64).to_le_bytes(),
    );
    transcript.append_bytes(b"activation-digest", &bridge.final_activation_digest());
    transcript.append_bytes(b"dory-binding", &bridge.transcript_binding());
    transcript.append_bytes(
        b"point-count",
        &(bridge.cell_point().len() as u64).to_le_bytes(),
    );
    for coordinate in bridge.cell_point() {
        transcript.append_field(b"dory-point", coordinate);
    }
    transcript.append_field(b"raw-evaluation", &bridge.raw_byte_evaluation());
    transcript.append_bytes(b"execution-sumcheck-digest", &digests.execution_sumcheck);
    transcript.append_bytes(b"adjacency-sumcheck-digest", &digests.adjacency_sumcheck);
    transcript.append_bytes(b"execution-selector-digest", &digests.execution_selectors);
    transcript.append_bytes(b"adjacency-selector-digest", &digests.adjacency_selectors);
    transcript.append_bytes(
        b"trace-variables",
        &(geometry.trace_variables as u64).to_le_bytes(),
    );
    transcript.append_bytes(
        b"source-variables",
        &(geometry.source_variables as u64).to_le_bytes(),
    );
    transcript.append_bytes(
        b"shared-variables",
        &(geometry.shared_variables as u64).to_le_bytes(),
    );
    transcript.append_bytes(
        b"dory-nu",
        &(verifier_context.layout.nu() as u64).to_le_bytes(),
    );
    transcript.append_bytes(
        b"dory-sigma",
        &(verifier_context.layout.sigma() as u64).to_le_bytes(),
    );
    transcript.append_bytes(b"setup-identity", &verifier_context.setup_identity);
    transcript.append_bytes(
        b"setup-max-log-n",
        &(verifier_context.setup_max_log_n as u64).to_le_bytes(),
    );
    transcript.append_bytes(
        b"source-count",
        &(BLS_DORY_BLAKE3_SOURCE_ROLES.len() as u64).to_le_bytes(),
    );
    for (role, terminal_count) in BLS_DORY_BLAKE3_SOURCE_ROLES
        .into_iter()
        .zip(BLS_DORY_BLAKE3_SOURCE_TERMINALS)
    {
        append_native_blake3_source_descriptor(
            &mut transcript,
            role,
            terminal_count,
            commitments.commitment(role),
        );
    }
    transcript.digest()
}

#[cfg(feature = "whir-prototype")]
fn native_main_physical_terminal_index(physical_slot: usize) -> Option<usize> {
    let ordinary_width = BLS_DORY_BLAKE3_MAIN_WIDTH.checked_sub(1)?;
    if physical_slot >= 2 * ordinary_width
        || NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START >= BLS_DORY_BLAKE3_MAIN_WIDTH
    {
        return None;
    }
    let direction = physical_slot / ordinary_width;
    let ordinary_column = physical_slot % ordinary_width;
    let logical_column = ordinary_column
        + usize::from(ordinary_column >= NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START);
    direction
        .checked_mul(BLS_DORY_BLAKE3_MAIN_WIDTH)?
        .checked_add(logical_column)
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_terminal_selector_evaluation(
    terminal: &[BlsDoryFr],
    selector_point: &[BlsDoryFr],
) -> Option<BlsDoryFr> {
    let capacity = 1usize.checked_shl(selector_point.len() as u32)?;
    if terminal.is_empty() || terminal.len() > capacity {
        return None;
    }
    let mut layer = terminal.to_vec();
    layer.resize(capacity, BlsDoryFr::zero());
    for coordinate in selector_point {
        for index in 0..layer.len() / 2 {
            let low = layer[2 * index];
            let high = layer[2 * index + 1];
            layer[index] = low + *coordinate * (high - low);
        }
        layer.truncate(layer.len() / 2);
    }
    (layer.len() == 1).then_some(layer[0])
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_main_terminal_values(terminal: &[BlsDoryFr]) -> Option<Vec<BlsDoryFr>> {
    if terminal.len() < 2 * BLS_DORY_BLAKE3_MAIN_WIDTH {
        return None;
    }
    (0..BLS_DORY_BLAKE3_SIGNED_WORD_TABLES)
        .map(|physical_slot| {
            native_main_physical_terminal_index(physical_slot)
                .and_then(|logical| terminal.get(logical).copied())
        })
        .collect()
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_accumulator_terminal_values(terminal: &[BlsDoryFr]) -> Option<Vec<BlsDoryFr>> {
    let accumulator = NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START;
    Some(vec![
        *terminal.get(accumulator)?,
        *terminal.get(BLS_DORY_BLAKE3_MAIN_WIDTH + accumulator)?,
    ])
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_execution_evaluations(
    terminal: &[BlsDoryFr],
    selectors: &[Vec<BlsDoryFr>; BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS],
) -> Option<[BlsDoryFr; BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS]> {
    if terminal.len() != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
        || selectors
            .iter()
            .any(|selector| selector.len() != BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES)
    {
        return None;
    }
    let main = native_blake3_main_terminal_values(terminal)?;
    let accumulator = native_blake3_accumulator_terminal_values(terminal)?;
    let preprocessed_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
    let preprocessing = (0..BLS_DORY_BLAKE3_EXECUTION_SOURCE_TERMINALS[2])
        .map(|physical_slot| {
            preprocessed_physical_terminal_index(physical_slot)
                .and_then(|logical| terminal.get(preprocessed_start + logical).copied())
        })
        .collect::<Option<Vec<_>>>()?;
    Some([
        native_blake3_terminal_selector_evaluation(&main, &selectors[0])?,
        native_blake3_terminal_selector_evaluation(&accumulator, &selectors[1])?,
        native_blake3_terminal_selector_evaluation(&preprocessing, &selectors[2])?,
    ])
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_adjacency_evaluations(
    terminal: &[BlsDoryFr],
    selectors: &[Vec<BlsDoryFr>; BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS],
) -> Option<[BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS]> {
    if terminal.len() != BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS
        || selectors
            .iter()
            .any(|selector| selector.len() != BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES)
    {
        return None;
    }
    let main = native_blake3_main_terminal_values(terminal)?;
    let accumulator = native_blake3_accumulator_terminal_values(terminal)?;
    let inverse_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
    let inverse = terminal.get(inverse_start..inverse_start + 2)?;
    Some([
        native_blake3_terminal_selector_evaluation(&main, &selectors[0])?,
        native_blake3_terminal_selector_evaluation(&accumulator, &selectors[1])?,
        native_blake3_terminal_selector_evaluation(inverse, &selectors[2])?,
    ])
}

#[cfg(feature = "whir-prototype")]
fn native_blake3_lifted_opening_point(
    sumcheck_point: &[BlsDoryFr],
    selector_point: &[BlsDoryFr],
    source_variables: usize,
    shared_variables: usize,
) -> Option<Vec<BlsDoryFr>> {
    if sumcheck_point.len() + selector_point.len() != source_variables
        || source_variables > shared_variables
    {
        return None;
    }
    let mut point = Vec::with_capacity(shared_variables);
    point.extend_from_slice(sumcheck_point);
    point.extend_from_slice(selector_point);
    point.resize(shared_variables, BlsDoryFr::zero());
    Some(point)
}

#[cfg(feature = "whir-prototype")]
fn verify_native_blake3_opening_replay_at_geometry(
    bridge: &BlsDoryOutputBridgeStatement,
    commitments: &BlsDoryBlake3SourceCommitments,
    verifier: BlsDoryBlake3ReplayVerifier<'_>,
    execution: &BlsDoryBlake3ExecutionSumcheckProof,
    adjacency: &BlsDoryBlake3AdjacencySumcheckProof,
) -> Result<BlsDoryBlake3OpeningReplay, BlsDoryAggregateError> {
    let geometry = verifier.geometry;
    if !bridge.final_activation_len().is_power_of_two()
        || bridge.cell_point().len() != bridge.final_activation_len().ilog2() as usize
        || geometry.source_variables
            != geometry.trace_variables + BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES
        || geometry.shared_variables != geometry.source_variables + 2
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let native_statement = native_blake3_statement_from_bridge(bridge);
    let air = NarrowBlake3Air::new(&native_statement)
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    if !air.trace_rows().is_power_of_two()
        || air.trace_rows().ilog2() as usize != geometry.trace_variables
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    verifier.context.validate_geometry(geometry)?;
    verifier.preprocessing_pin.validate(
        bridge,
        air.trace_rows(),
        geometry,
        verifier.context,
        commitments,
    )?;
    let public = native_blake3_public_values(bridge)?;
    let constraints = bls_dory_native_blake3_constraint_ir(bridge.final_activation_len())
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let execution_replay = verify_native_blake3_execution_sumcheck(
        execution,
        &air,
        &public,
        &constraints,
        bridge,
        commitments,
    )?;
    let adjacency_replay =
        verify_native_blake3_adjacency_sumcheck(adjacency, air.trace_rows(), bridge, commitments)?;
    let (execution_selectors, execution_selector_digest) =
        native_blake3_execution_selector_points(execution_replay.transcript_digest, commitments);
    let (adjacency_selectors, adjacency_selector_digest) =
        native_blake3_adjacency_selector_points(adjacency_replay.transcript_digest, commitments);
    let execution_evaluations =
        native_blake3_execution_evaluations(&execution.terminal_evaluations, &execution_selectors)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    let adjacency_evaluations =
        native_blake3_adjacency_evaluations(&adjacency.terminal_evaluations, &adjacency_selectors)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;

    let execution_points = execution_selectors
        .iter()
        .map(|selector| {
            native_blake3_lifted_opening_point(
                &execution_replay.point,
                selector,
                geometry.source_variables,
                geometry.shared_variables,
            )
            .ok_or(BlsDoryAggregateError::InvalidProofShape)
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let adjacency_points = adjacency_selectors
        .iter()
        .map(|selector| {
            let mut full_selector = selector.clone();
            full_selector.push(BlsDoryFr::zero());
            native_blake3_lifted_opening_point(
                &adjacency_replay.point,
                &full_selector,
                geometry.source_variables,
                geometry.shared_variables,
            )
            .ok_or(BlsDoryAggregateError::InvalidProofShape)
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let opening_binding = native_blake3_opening_binding(
        bridge,
        BlsDoryBlake3OpeningTranscriptDigests {
            execution_sumcheck: execution_replay.transcript_digest,
            adjacency_sumcheck: adjacency_replay.transcript_digest,
            execution_selectors: execution_selector_digest,
            adjacency_selectors: adjacency_selector_digest,
        },
        geometry,
        verifier.context,
        commitments,
    );

    Ok(BlsDoryBlake3OpeningReplay {
        execution_points,
        execution_evaluations,
        adjacency_points,
        adjacency_evaluations,
        opening_binding,
    })
}

/// Verify both native BLAKE3 sumchecks and bind their six verifier-derived
/// openings at the immutable production geometry.
#[cfg(feature = "whir-prototype")]
#[allow(dead_code)]
pub(crate) fn verify_native_blake3_opening_statement(
    bridge: &BlsDoryOutputBridgeStatement,
    proof: &BlsDoryNativeBlake3Proof,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryBlake3OpeningStatement, BlsDoryAggregateError> {
    if bridge.final_activation_len() != BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let verifier_context = BlsDoryBlake3VerifierContext::new(
        BlsDoryAggregateLayout::new(
            BLS_DORY_BLAKE3_SHARED_DORY_NU,
            BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
        )?,
        setup,
    )?;
    let preprocessing_pin = native_blake3_production_preprocessing_pin(&verifier_context)
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let replay = verify_native_blake3_opening_replay_at_geometry(
        bridge,
        &proof.source_commitments,
        BlsDoryBlake3ReplayVerifier {
            context: &verifier_context,
            preprocessing_pin: &preprocessing_pin,
            geometry: BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY,
        },
        &proof.execution,
        &proof.adjacency,
    )?;
    BlsDoryBlake3OpeningStatement::from_verified_replay(proof.source_commitments.clone(), replay)
}

/// Decode the canonical production native proof before verifier-owned replay.
#[cfg(feature = "whir-prototype")]
#[allow(dead_code)]
pub(crate) fn verify_encoded_native_blake3_opening_statement(
    bridge: &BlsDoryOutputBridgeStatement,
    encoded: &[u8],
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryBlake3OpeningStatement, BlsDoryAggregateError> {
    let proof = BlsDoryNativeBlake3Proof::decode(encoded)?;
    verify_native_blake3_opening_statement(bridge, &proof, setup)
}

/// Exercise the same opaque wire-to-replay boundary at a bounded test
/// geometry while supplying preprocessing authority out of band.
#[cfg(all(test, feature = "whir-prototype"))]
pub(crate) fn verify_encoded_native_blake3_test_opening_statement_at_layout(
    bridge: &BlsDoryOutputBridgeStatement,
    encoded: &[u8],
    trusted_preprocessing_commitment: BlsDoryGt,
    layout: BlsDoryAggregateLayout,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryBlake3OpeningStatement, BlsDoryAggregateError> {
    let native_statement = native_blake3_statement_from_bridge(bridge);
    let air = NarrowBlake3Air::new(&native_statement)
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    if !air.trace_rows().is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let trace_variables = air.trace_rows().ilog2() as usize;
    let geometry = BlsDoryBlake3ReplayGeometry {
        trace_variables,
        source_variables: trace_variables + BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES,
        shared_variables: layout.variables(),
    };
    let proof = BlsDoryNativeBlake3Proof::decode_at_trace_variables(encoded, trace_variables)?;
    let verifier_context = BlsDoryBlake3VerifierContext::new(layout, setup)?;
    let mut trusted_commitments = proof.source_commitments.clone();
    trusted_commitments.preprocessing = trusted_preprocessing_commitment;
    let preprocessing_pin = BlsDoryBlake3TrustedPreprocessingPin::for_test_sources(
        bridge,
        air.trace_rows(),
        geometry,
        &verifier_context,
        &trusted_commitments,
    );
    let replay = verify_native_blake3_opening_replay_at_geometry(
        bridge,
        &proof.source_commitments,
        BlsDoryBlake3ReplayVerifier {
            context: &verifier_context,
            preprocessing_pin: &preprocessing_pin,
            geometry,
        },
        &proof.execution,
        &proof.adjacency,
    )?;
    BlsDoryBlake3OpeningStatement::from_verified_replay_at_geometry(
        proof.source_commitments,
        replay,
        geometry,
    )
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_accumulator_trace(
    air: &NarrowBlake3Air,
    old_main_rows: &[Vec<BlsDoryFr>],
    statement: &BlsDoryOutputBridgeStatement,
) -> Vec<BlsDoryFr> {
    let mut accumulator = BlsDoryFr::zero();
    old_main_rows
        .iter()
        .enumerate()
        .map(|(row, main_local)| {
            let current = accumulator;
            accumulator = accumulator
                + native_activation_contribution(
                    main_local,
                    air.activation_group_index_at_row(row),
                    statement.cell_point(),
                );
            current
        })
        .collect()
}

#[cfg(feature = "whir-prototype")]
fn for_each_native_accumulator_pair<E>(
    air: &NarrowBlake3Air,
    statement: &StructuredBlake3Statement,
    witness: &crate::structured_blake3_tree::Blake3TreeWitness,
    bridge: &BlsDoryOutputBridgeStatement,
    mut emit: impl FnMut(usize, BlsDoryFr, BlsDoryFr) -> Result<(), E>,
) -> Result<(), E> {
    let mut accumulator = BlsDoryFr::zero();
    crate::structured_blake3_narrow::for_each_main_trace_row(
        air,
        statement,
        witness,
        |row_index, row| {
            let current = accumulator;
            let coefficients = native_byte_coefficients(
                air.activation_group_index_at_row(row_index),
                bridge.cell_point(),
            );
            let contribution = (0..8).fold(BlsDoryFr::zero(), |sum, byte| {
                let low = BlsDoryFr::from_i64(centered_goldilocks(
                    row[NARROW_BLAKE3_ORIGINAL_NIBBLES_START + 2 * byte],
                ));
                let high = BlsDoryFr::from_i64(centered_goldilocks(
                    row[NARROW_BLAKE3_ORIGINAL_NIBBLES_START + 2 * byte + 1],
                ));
                sum + (low + BlsDoryFr::from_u64(16) * high) * coefficients[byte]
            });
            let after = current + contribution;
            let next = if row_index + 1 == air.trace_rows() {
                BlsDoryFr::zero()
            } else {
                after
            };
            emit(row_index, current, next)?;
            accumulator = after;
            Ok(())
        },
    )
}

#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_ACCUMULATOR_WRITE_CHUNK_SCALARS: usize = 1 << 15;

#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn write_native_accumulator_pass(
    writer: &mut BlsDoryCommittedPolynomialWriter<'_>,
    air: &NarrowBlake3Air,
    statement: &StructuredBlake3Statement,
    witness: &crate::structured_blake3_tree::Blake3TreeWitness,
    bridge: &BlsDoryOutputBridgeStatement,
    write_next: bool,
) -> Result<(), BlsDoryAggregateError> {
    let mut scalars = Vec::with_capacity(BLS_DORY_BLAKE3_ACCUMULATOR_WRITE_CHUNK_SCALARS);
    let mut emitted = 0usize;
    let mut last = None;
    for_each_native_accumulator_pair(air, statement, witness, bridge, |row_index, local, next| {
        if row_index != emitted {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        scalars.push(if write_next { next } else { local });
        if scalars.len() == BLS_DORY_BLAKE3_ACCUMULATOR_WRITE_CHUNK_SCALARS {
            writer.write_scalars(&scalars)?;
            scalars.clear();
        }
        emitted += 1;
        last = Some((local, next));
        Ok(())
    })?;
    if !scalars.is_empty() {
        writer.write_scalars(&scalars)?;
    }
    if emitted != air.trace_rows()
        || last != Some((bridge.raw_byte_evaluation(), BlsDoryFr::zero()))
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(())
}

/// Commit the local and cyclic-next native evaluation accumulators without
/// retaining either full scalar table in memory. The canonical main trace is
/// regenerated once per table so the artifact remains in table-major order.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn commit_native_accumulator_source(
    witness: &crate::structured_blake3_tree::Blake3TreeWitness,
    bridge: &BlsDoryOutputBridgeStatement,
    layout: BlsDoryAggregateLayout,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &std::path::Path,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    if witness.digest != bridge.final_activation_digest() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let native_statement = native_blake3_statement_from_bridge(bridge);
    let air = NarrowBlake3Air::new(&native_statement)
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    if !air.trace_rows().is_power_of_two() {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let explicit_scalars = air
        .trace_rows()
        .checked_mul(BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let mut writer = BlsDoryCommittedPolynomialWriter::create(
        scratch_directory,
        explicit_scalars,
        layout.nu(),
        layout.sigma(),
        setup,
    )?;
    write_native_accumulator_pass(&mut writer, &air, &native_statement, witness, bridge, false)?;
    write_native_accumulator_pass(&mut writer, &air, &native_statement, witness, bridge, true)?;
    writer.finish()
}

#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_INVERSE_BATCH_SCALARS: usize = 1 << 15;

#[cfg(feature = "whir-prototype")]
fn batch_invert_nonzero(values: &mut [BlsDoryFr]) -> Option<()> {
    for batch in values.chunks_mut(BLS_DORY_BLAKE3_INVERSE_BATCH_SCALARS) {
        let mut prefixes = Vec::with_capacity(batch.len());
        let mut product = BlsDoryFr::from_u64(1);
        for value in batch.iter().copied() {
            prefixes.push(product);
            product = product * value;
        }
        let mut suffix = product.inv()?;
        for index in (0..batch.len()).rev() {
            let value = batch[index];
            batch[index] = suffix * prefixes[index];
            suffix = suffix * value;
        }
    }
    Some(())
}

/// Commit the two LogUp inverse tables from authenticated ordinary-main and
/// accumulator sources. A denominator collision fails before any inverse
/// artifact is created.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn commit_native_adjacency_inverse_source(
    ordinary_main: &mut BlsDoryWordTransposeArtifact,
    accumulator: &BlsDoryCommittedPolynomial,
    compression: BlsDoryFr,
    alpha: BlsDoryFr,
    layout: BlsDoryAggregateLayout,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &std::path::Path,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    let trace_rows = ordinary_main.rows();
    let explicit_scalars = trace_rows
        .checked_mul(BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let physical_rows = 1usize
        .checked_shl(layout.nu() as u32)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let physical_columns = 1usize
        .checked_shl(layout.sigma() as u32)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let capacity = physical_rows
        .checked_mul(physical_columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if ordinary_main.columns() != BLS_DORY_BLAKE3_MAIN_WIDTH - 1
        || !trace_rows.is_power_of_two()
        || explicit_scalars > capacity
        || accumulator.explicit_coefficient_count() != explicit_scalars
        || !accumulator.matches_layout(layout, setup)
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let trace_rows_u64 =
        u64::try_from(trace_rows).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let mut keys = Vec::with_capacity(explicit_scalars);
    keys.extend((0..trace_rows).map(|row| {
        BlsDoryFr::from_u64(if row == 0 {
            trace_rows_u64 - 1
        } else {
            row as u64 - 1
        })
    }));
    keys.extend((0..trace_rows).map(|row| BlsDoryFr::from_u64(row as u64)));

    let mut words = vec![0u64; trace_rows];
    let mut artifact_column = 0usize;
    for native_column in 0..BLS_DORY_BLAKE3_MAIN_WIDTH {
        if native_column == NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START {
            accumulator.for_each_explicit_coefficient(|index, value| {
                keys[index] = keys[index] * compression + value;
            })?;
            continue;
        }
        ordinary_main
            .read_column(artifact_column, &mut words)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        for row in 0..trace_rows {
            let local = BlsDoryFr::from_i64(i64::from_le_bytes(words[row].to_le_bytes()));
            let next_word = words[(row + 1) % trace_rows];
            let next = BlsDoryFr::from_i64(i64::from_le_bytes(next_word.to_le_bytes()));
            keys[row] = keys[row] * compression + local;
            keys[trace_rows + row] = keys[trace_rows + row] * compression + next;
        }
        artifact_column += 1;
    }
    if artifact_column != ordinary_main.columns() {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }

    for key in &mut keys {
        *key = alpha - *key;
    }
    batch_invert_nonzero(&mut keys).ok_or(BlsDoryAggregateError::InvalidProofShape)?;

    let row_bytes = physical_columns
        .checked_mul(std::mem::size_of::<BlsDoryFr>())
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let mut writer = BlsDoryCommittedPolynomialWriter::create_with_chunk_bytes(
        scratch_directory,
        explicit_scalars,
        layout.nu(),
        layout.sigma(),
        setup,
        row_bytes,
    )?;
    writer.write_scalars(&keys)?;
    writer.finish()
}

#[cfg(feature = "whir-prototype")]
const BLS_DORY_BLAKE3_TRANSPOSE_CHUNK_ROWS: usize = 1 << 14;

#[cfg(feature = "whir-prototype")]
fn blake3_transpose_error(error: BlsDoryTransposeError) -> BlsDoryAggregateError {
    match error {
        BlsDoryTransposeError::InvalidShape | BlsDoryTransposeError::Incomplete => {
            BlsDoryAggregateError::InvalidProofShape
        }
        BlsDoryTransposeError::Authentication | BlsDoryTransposeError::Io(_) => {
            BlsDoryAggregateError::ProverStorage
        }
    }
}

#[cfg(feature = "whir-prototype")]
fn validate_native_blake3_source_layout(
    trace_rows: usize,
    layout: BlsDoryAggregateLayout,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryAggregateError> {
    let physical_rows = 1usize
        .checked_shl(layout.nu() as u32)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let physical_columns = 1usize
        .checked_shl(layout.sigma() as u32)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let capacity = physical_rows
        .checked_mul(physical_columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let main_scalars = trace_rows
        .checked_mul(BLS_DORY_BLAKE3_SIGNED_WORD_TABLES)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let accumulator_scalars = trace_rows
        .checked_mul(BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let preprocessed_word_scalars = trace_rows
        .checked_mul(BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let preprocessed_scalars = trace_rows
        .checked_mul(
            BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES,
        )
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let inverse_scalars = trace_rows
        .checked_mul(BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    if !trace_rows.is_power_of_two()
        || setup.max_log_n() < layout.variables()
        || setup.prover().g1_vec.len() < physical_columns
        || setup.prover().g2_vec.len() < physical_rows
        || [
            main_scalars,
            accumulator_scalars,
            preprocessed_scalars,
            inverse_scalars,
        ]
        .into_iter()
        .any(|scalars| scalars > capacity)
        || !main_scalars.is_multiple_of(physical_columns)
        || !preprocessed_word_scalars.is_multiple_of(physical_columns)
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn create_native_main_transpose(
    air: &NarrowBlake3Air,
    statement: &StructuredBlake3Statement,
    witness: &crate::structured_blake3_tree::Blake3TreeWitness,
    scratch_directory: &std::path::Path,
) -> Result<BlsDoryWordTransposeArtifact, BlsDoryAggregateError> {
    let mut writer = BlsDoryWordTransposeWriter::create(
        scratch_directory,
        air.trace_rows(),
        BLS_DORY_BLAKE3_MAIN_WIDTH - 1,
        BLS_DORY_BLAKE3_TRANSPOSE_CHUNK_ROWS.min(air.trace_rows()),
    )
    .map_err(blake3_transpose_error)?;
    let mut emitted = 0usize;
    let mut words = Vec::with_capacity(BLS_DORY_BLAKE3_MAIN_WIDTH - 1);
    for_each_main_trace_row(air, statement, witness, |row_index, row| {
        if row_index != emitted || row.len() != NARROW_BLAKE3_MAIN_WIDTH {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        words.clear();
        words.extend(
            row.iter()
                .enumerate()
                .filter(|(column, _)| {
                    !(NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START..NARROW_BLAKE3_STACK_START)
                        .contains(column)
                })
                .map(|(_, value)| u64::from_le_bytes(centered_goldilocks(*value).to_le_bytes())),
        );
        if words.len() != BLS_DORY_BLAKE3_MAIN_WIDTH - 1 {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        writer.write_row(&words)?;
        emitted += 1;
        Ok(())
    })
    .map_err(blake3_transpose_error)?;
    if emitted != air.trace_rows() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    writer.finish().map_err(blake3_transpose_error)
}

#[cfg(feature = "whir-prototype")]
fn create_native_preprocessed_transpose(
    air: &NarrowBlake3Air,
    scratch_directory: &std::path::Path,
) -> Result<BlsDoryWordTransposeArtifact, BlsDoryAggregateError> {
    let mut writer = BlsDoryWordTransposeWriter::create(
        scratch_directory,
        air.trace_rows(),
        BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
        BLS_DORY_BLAKE3_TRANSPOSE_CHUNK_ROWS.min(air.trace_rows()),
    )
    .map_err(blake3_transpose_error)?;
    let mut emitted = 0usize;
    let mut words = Vec::with_capacity(BLS_DORY_BLAKE3_PREPROCESSED_WIDTH);
    for_each_canonical_preprocessed_trace_row(air, |row_index, row| {
        if row_index != emitted || row.len() != BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        words.clear();
        words.extend(row.iter().map(|value| value.as_canonical_u64()));
        writer.write_row(&words)?;
        emitted += 1;
        Ok(())
    })
    .map_err(blake3_transpose_error)?;
    if emitted != air.trace_rows() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    writer.finish().map_err(blake3_transpose_error)
}

/// Derive the deterministic production preprocessing commitment without
/// constructing any witness-dependent native BLAKE3 source.
///
/// The returned record is deliberately not installed as a verifier pin. Every
/// scratch artifact created by this job remains owned by its RAII wrapper and
/// is removed on success or error.
#[cfg(feature = "whir-prototype")]
pub fn derive_bls_dory_blake3_preprocessing_record(
    scratch_directory: &std::path::Path,
) -> Result<BlsDoryBlake3PreprocessingRecord, BlsDoryBlake3PreprocessingRecordError> {
    if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
        return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
            "scratch directory",
        ));
    }

    let setup = deterministic_bls_dory_setup(BLS_DORY_SHARED_PRODUCTION_VARIABLES)?;
    let layout = BlsDoryAggregateLayout::new(
        BLS_DORY_BLAKE3_SHARED_DORY_NU,
        BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
    )?;
    let zero = ExtensionElement { limbs: [0; 3] };
    let statement = StructuredBlake3Statement {
        challenge_digest: [0; 32],
        final_activation_len: BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES,
        final_activation_digest: [0; 32],
        final_activation_point: vec![
            zero;
            BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES.ilog2() as usize
        ],
        final_activation_evaluation: zero,
    };
    let air = NarrowBlake3Air::new(&statement)
        .map_err(|error| BlsDoryBlake3PreprocessingRecordError::Air(error.to_string()))?;
    if air.trace_rows() != BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS {
        return Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
            "AIR trace rows",
        ));
    }
    validate_native_blake3_source_layout(air.trace_rows(), layout, &setup)?;

    let mut transpose = create_native_preprocessed_transpose(&air, scratch_directory)?;
    let transpose_digest = transpose.digest();
    let transpose_bytes = transpose.file_bytes()?;
    let preprocessing = {
        let mut source = TransposedPreprocessedRowSource::new_for_layout(&mut transpose, layout)?;
        commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            layout.nu(),
            layout.sigma(),
            &setup,
            scratch_directory,
        )?
    };
    let (compact_spec, compact_artifact_digest, compact_artifact_bytes) =
        preprocessing.compact_artifact_audit_metadata()?;
    let fri_key = pinned_preprocessed_key(
        BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES,
        BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
    )
    .ok_or(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
        "FRI preprocessing key",
    ))?;

    let mut record = BlsDoryBlake3PreprocessingRecord {
        record_version: BLS_DORY_BLAKE3_PREPROCESSING_RECORD_VERSION,
        projection_version: BLS_DORY_BLAKE3_PROJECTION_VERSION,
        native_proof_version: BLS_DORY_BLAKE3_NATIVE_PROOF_VERSION,
        activation_len: BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES as u64,
        cell_point_variables: BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES.ilog2(),
        trace_rows: BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS as u64,
        preprocessed_width: BLS_DORY_BLAKE3_PREPROCESSED_WIDTH as u32,
        preprocessed_word_tables: BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES as u32,
        preprocessed_code_tables: BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES as u32,
        preprocessing_terminal_count: BLS_DORY_BLAKE3_SOURCE_TERMINALS
            [BlsDoryBlake3SourceRole::Preprocessing.index()]
            as u32,
        trace_variables: BLS_DORY_BLAKE3_TRACE_VARIABLES as u32,
        source_variables: BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES as u32,
        shared_variables: BLS_DORY_SHARED_PRODUCTION_VARIABLES as u32,
        dory_nu: layout.nu() as u32,
        dory_sigma: layout.sigma() as u32,
        setup_max_log_n: setup.max_log_n() as u32,
        setup_identity: hex::encode(setup.identity()),
        preprocessing_bls_commitment: encode_blake3_record_commitment(&preprocessing.commitment())?,
        transpose_digest: hex::encode(transpose_digest),
        transpose_bytes,
        compact_artifact_context_digest: hex::encode(compact_spec.context_digest),
        compact_artifact_digest: hex::encode(compact_artifact_digest),
        compact_artifact_bytes,
        compact_scalar_count: compact_spec.scalar_count,
        compact_explicit_scalar_count: compact_spec.explicit_scalar_count,
        compact_word_scalar_count: compact_spec.word_scalar_count,
        compact_word_bytes: compact_spec.word_bytes,
        compact_code_bits: compact_spec.code_bits,
        compact_word_width_codes: compact_spec.word_width_codes,
        compact_word_group_len: compact_spec.word_group_len,
        compact_signed_word_selectors: compact_spec.signed_word_selectors,
        fri_preprocessed_registry_digest: hex::encode(pinned_preprocessed_registry_digest()),
        fri_preprocessed_root: fri_key.root.map(|word| format!("{word:016x}")),
        record_digest: String::new(),
    };
    record.record_digest = hex::encode(record.canonical_digest()?);
    record.validate_for_setup(&setup)?;
    Ok(record)
}

#[cfg(feature = "whir-prototype")]
fn prepare_native_blake3_sources_at_layout(
    witness: &crate::structured_blake3_tree::Blake3TreeWitness,
    bridge: &BlsDoryOutputBridgeStatement,
    layout: BlsDoryAggregateLayout,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &std::path::Path,
) -> Result<PreparedBlsDoryBlake3Sources, BlsDoryAggregateError> {
    if witness.digest != bridge.final_activation_digest() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let native_statement = native_blake3_statement_from_bridge(bridge);
    let air = NarrowBlake3Air::new(&native_statement)
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    validate_native_blake3_source_layout(air.trace_rows(), layout, setup)?;

    let mut preprocessed_transpose = create_native_preprocessed_transpose(&air, scratch_directory)?;
    let preprocessing = {
        let mut source =
            TransposedPreprocessedRowSource::new_for_layout(&mut preprocessed_transpose, layout)
                .map_err(blake3_transpose_error)?;
        commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            layout.nu(),
            layout.sigma(),
            setup,
            scratch_directory,
        )?
    };

    let mut main_transpose =
        create_native_main_transpose(&air, &native_statement, witness, scratch_directory)?;
    let main = {
        let mut source =
            TransposedLocalNextSignedWordRowSource::new_for_layout(&mut main_transpose, layout)
                .map_err(blake3_transpose_error)?;
        commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            layout.nu(),
            layout.sigma(),
            setup,
            scratch_directory,
        )?
    };
    let accumulator =
        commit_native_accumulator_source(witness, bridge, layout, setup, scratch_directory)?;
    let (compression, alpha) = derive_native_blake3_adjacency_challenges(
        bridge,
        air.trace_rows(),
        BlsDoryBlake3AdjacencySourceCommitments {
            main: main.commitment(),
            accumulator: accumulator.commitment(),
            preprocessing: preprocessing.commitment(),
        },
    )?;
    let inverse = commit_native_adjacency_inverse_source(
        &mut main_transpose,
        &accumulator,
        compression,
        alpha,
        layout,
        setup,
        scratch_directory,
    )?;

    let sources = BlsDoryBlake3CommittedSources {
        main,
        accumulator,
        preprocessing,
        inverse,
    };
    PreparedBlsDoryBlake3Sources::new(
        sources,
        main_transpose,
        preprocessed_transpose,
        air.trace_rows(),
        layout,
        setup,
    )
}

/// Produce both native arguments while the authenticated source transposes are
/// still retained, then release those transposes before the deferred Dory
/// opening stage begins.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn prove_prepared_native_blake3_sources(
    mut prepared: PreparedBlsDoryBlake3Sources,
    bridge: &BlsDoryOutputBridgeStatement,
    scratch_directory: &std::path::Path,
    maximum_block_rows: usize,
) -> Result<ProvenBlsDoryNativeBlake3Sources, BlsDoryAggregateError> {
    let trace_rows = prepared.binding.trace_rows;
    if maximum_block_rows == 0
        || !scratch_directory.is_absolute()
        || !scratch_directory.is_dir()
        || !trace_rows.is_power_of_two()
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let geometry = BlsDoryBlake3ReplayGeometry {
        trace_variables: trace_rows.ilog2() as usize,
        source_variables: (trace_rows.ilog2() as usize)
            .checked_add(BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?,
        shared_variables: prepared.binding.layout.variables(),
    };
    if geometry.shared_variables != geometry.source_variables + 2 {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let source_commitments = prepared.commitments();
    let execution = prove_native_blake3_execution_sumcheck_out_of_core(
        &mut prepared,
        bridge,
        scratch_directory,
        maximum_block_rows,
    )?;
    let adjacency = prove_native_blake3_adjacency_sumcheck_out_of_core(
        &mut prepared,
        bridge,
        scratch_directory,
        maximum_block_rows,
    )?;
    let sources = prepared.into_committed_sources()?;
    if sources.commitments() != source_commitments {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(ProvenBlsDoryNativeBlake3Sources {
        sources,
        proof: BlsDoryNativeBlake3Proof {
            source_commitments,
            execution,
            adjacency,
        },
        geometry,
    })
}

/// Replay the two native arguments, derive the six canonical opening points,
/// and consume the four authenticated sources into one deferred opening set.
#[cfg(feature = "whir-prototype")]
#[cfg_attr(not(test), allow(dead_code))]
fn finalize_native_blake3_opening(
    proven: ProvenBlsDoryNativeBlake3Sources,
    bridge: &BlsDoryOutputBridgeStatement,
    verifier: BlsDoryBlake3ReplayVerifier<'_>,
) -> Result<PreparedBlsDoryNativeBlake3Opening, BlsDoryAggregateError> {
    let ProvenBlsDoryNativeBlake3Sources {
        sources,
        proof,
        geometry,
    } = proven;
    if verifier.geometry != geometry || sources.commitments() != proof.source_commitments {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }

    let replay = verify_native_blake3_opening_replay_at_geometry(
        bridge,
        &proof.source_commitments,
        verifier,
        &proof.execution,
        &proof.adjacency,
    )?;
    let points = [
        replay.execution_points[0].clone(),
        replay.execution_points[1].clone(),
        replay.execution_points[2].clone(),
        replay.adjacency_points[0].clone(),
        replay.adjacency_points[1].clone(),
        replay.adjacency_points[2].clone(),
    ];
    let opening_statement = BlsDoryBlake3OpeningStatement::from_verified_replay_with_geometry(
        proof.source_commitments.clone(),
        replay,
        geometry,
    )?;
    let encoded_native_proof = proof.encode_at_trace_variables(geometry.trace_variables)?;
    if BlsDoryNativeBlake3Proof::decode_at_trace_variables(
        &encoded_native_proof,
        geometry.trace_variables,
    )? != proof
    {
        return Err(BlsDoryAggregateError::InvalidEncoding);
    }
    BlsDoryBlake3CommittedSources::validate_lifted_points(
        &points,
        geometry.source_variables,
        geometry.shared_variables,
    )?;
    let opening_set = sources.into_deferred_openings(points)?;
    opening_statement.validate_claims(opening_set.claims())?;

    Ok(PreparedBlsDoryNativeBlake3Opening {
        opening_statement,
        opening_set,
        encoded_native_proof,
    })
}

/// Build the exact production-geometry native opening witness for the
/// non-consensus V3 research candidate. This does not change either production
/// readiness flag or create a chain-admission capability.
#[cfg(feature = "whir-prototype")]
pub(crate) fn prepare_production_native_blake3_opening(
    final_activation: &[u8],
    bridge: &BlsDoryOutputBridgeStatement,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &std::path::Path,
    maximum_block_rows: usize,
) -> Result<PreparedBlsDoryNativeBlake3Opening, BlsDoryAggregateError> {
    if final_activation.len() != BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES
        || bridge.final_activation_len() != final_activation.len()
        || setup.max_log_n() != BLS_DORY_SHARED_PRODUCTION_VARIABLES
        || maximum_block_rows == 0
        || !scratch_directory.is_absolute()
        || !scratch_directory.is_dir()
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    bridge
        .validate_activation(final_activation)
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let witness = crate::structured_blake3_tree::build_tree_witness(
        BLS_DORY_BLAKE3_OUTPUT_CONTEXT,
        bridge.challenge_digest(),
        final_activation,
    )
    .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let layout = BlsDoryAggregateLayout::new(
        BLS_DORY_BLAKE3_SHARED_DORY_NU,
        BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
    )?;
    let verifier_context = BlsDoryBlake3VerifierContext::new(layout, setup)?;
    let preprocessing_pin = native_blake3_production_preprocessing_pin(&verifier_context)
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let prepared = prepare_native_blake3_sources_at_layout(
        &witness,
        bridge,
        layout,
        setup,
        scratch_directory,
    )?;
    let proven = prove_prepared_native_blake3_sources(
        prepared,
        bridge,
        scratch_directory,
        maximum_block_rows,
    )?;
    if proven.geometry != BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    finalize_native_blake3_opening(
        proven,
        bridge,
        BlsDoryBlake3ReplayVerifier {
            context: &verifier_context,
            preprocessing_pin: &preprocessing_pin,
            geometry: BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY,
        },
    )
}

#[cfg(feature = "whir-prototype")]
fn commit_native_blake3_sources_at_layout(
    witness: &crate::structured_blake3_tree::Blake3TreeWitness,
    bridge: &BlsDoryOutputBridgeStatement,
    layout: BlsDoryAggregateLayout,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &std::path::Path,
) -> Result<BlsDoryBlake3CommittedSources, BlsDoryAggregateError> {
    prepare_native_blake3_sources_at_layout(witness, bridge, layout, setup, scratch_directory)?
        .into_committed_sources()
}

/// Build the four production sources at the immutable shared 33-variable
/// layout. This remains private until the six-claim verifier replay is wired.
#[cfg(feature = "whir-prototype")]
#[allow(dead_code)]
fn commit_native_blake3_sources(
    witness: &crate::structured_blake3_tree::Blake3TreeWitness,
    bridge: &BlsDoryOutputBridgeStatement,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &std::path::Path,
) -> Result<BlsDoryBlake3CommittedSources, BlsDoryAggregateError> {
    if bridge.final_activation_len() != BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES
        || setup.max_log_n() != BLS_DORY_SHARED_PRODUCTION_VARIABLES
        || !scratch_directory.is_absolute()
        || !scratch_directory.is_dir()
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    if NarrowBlake3Air::new(&native_blake3_statement_from_bridge(bridge))
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?
        .trace_rows()
        != BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let layout = BlsDoryAggregateLayout::new(
        BLS_DORY_BLAKE3_SHARED_DORY_NU,
        BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
    )?;
    commit_native_blake3_sources_at_layout(witness, bridge, layout, setup, scratch_directory)
}

/// Exact projection values exposed to tests and activation tooling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryBlake3Projection {
    pub execution_terminal_evaluations: usize,
    pub adjacency_terminal_evaluations: usize,
    pub composed_opening_claims: usize,
    pub execution_proof_bytes: usize,
    pub adjacency_proof_bytes: usize,
    pub projected_v3_bytes: usize,
    pub projected_headroom_bytes: usize,
}

pub const fn projected_bls_dory_blake3_v3() -> BlsDoryBlake3Projection {
    BlsDoryBlake3Projection {
        execution_terminal_evaluations: BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS,
        adjacency_terminal_evaluations: BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS,
        composed_opening_claims: BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS,
        execution_proof_bytes: BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES,
        adjacency_proof_bytes: BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES,
        projected_v3_bytes: BLS_DORY_BLAKE3_PROJECTED_V3_BYTES,
        projected_headroom_bytes: BLS_DORY_BLAKE3_PROJECTED_HEADROOM_BYTES,
    }
}

/// Source-payload accounting only. Artifact framing and later Dory fold scratch
/// remain outside this projection and must be measured in a complete run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryBlake3SourceStorageProjection {
    pub literal_payload_bytes: u64,
    pub signed_word_payload_bytes: u64,
    pub full_field_payload_bytes: u64,
    pub preprocessed_word_payload_bytes: u64,
    pub preprocessed_code_payload_bytes: u64,
    pub compact_payload_bytes: u64,
}

pub const fn projected_bls_dory_blake3_source_storage() -> BlsDoryBlake3SourceStorageProjection {
    BlsDoryBlake3SourceStorageProjection {
        literal_payload_bytes: BLS_DORY_BLAKE3_LITERAL_SOURCE_PAYLOAD_BYTES,
        signed_word_payload_bytes: BLS_DORY_BLAKE3_SIGNED_WORD_PAYLOAD_BYTES,
        full_field_payload_bytes: BLS_DORY_BLAKE3_FULL_FIELD_PAYLOAD_BYTES,
        preprocessed_word_payload_bytes: BLS_DORY_BLAKE3_PREPROCESSED_WORD_PAYLOAD_BYTES,
        preprocessed_code_payload_bytes: BLS_DORY_BLAKE3_PREPROCESSED_CODE_PAYLOAD_BYTES,
        compact_payload_bytes: BLS_DORY_BLAKE3_COMPACT_SOURCE_PAYLOAD_BYTES,
    }
}

/// Operational scratch floor used while the exact composed fold lifecycle is
/// still being modeled. Passing this floor never authorizes a production run.
pub const BLS_DORY_BLAKE3_PROVISIONAL_SCRATCH_GATE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
/// Provisional free-memory floor. The complete prover's peak resident memory
/// remains unmeasured, so passing this floor never authorizes a production run.
pub const BLS_DORY_BLAKE3_PROVISIONAL_AVAILABLE_MEMORY_GATE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Nonallocating resource accounting for the proposed shared plus BLAKE3 proof.
///
/// `aggregate_stage_lower_bound_bytes` retains the earlier source-only floor.
/// `aggregate_stage_projected_peak_bytes` additionally follows every scalar
/// fold parent/child overlap in canonical source order. Transpose artifacts
/// remain live through both streamed roots. Each sumcheck-stage scratch peak
/// conservatively retains both transposes, all four framed sources, and that
/// argument's largest authenticated round parent/child overlap. Root-stream
/// resident fields count initialized vector payloads but exclude allocator,
/// stack, authentication, setup, Rayon, and I/O overhead. Coexistence fields
/// are deterministic projections, not peak-RSS measurements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryBlake3ProductionResourceProjection {
    pub shared_aggregate_peak_bytes: u64,
    pub compact_source_payload_bytes: u64,
    pub framed_source_artifact_bytes: u64,
    pub transpose_artifact_bytes: u64,
    pub source_construction_coexistence_bytes: u64,
    pub first_execution_round_artifact_bytes: u64,
    pub second_execution_round_artifact_bytes: u64,
    pub execution_round_peak_scratch_bytes: u64,
    pub execution_stage_projected_peak_scratch_bytes: u64,
    /// Initialized scalar-vector payload only; excludes allocator overhead,
    /// setup, Rayon, and I/O buffers.
    pub execution_auxiliary_resident_bytes: u64,
    /// Both complete accumulator vectors retained by the execution root pass.
    pub execution_root_snapshot_resident_bytes: u64,
    /// Maximum authenticated main plus preprocessing word slabs.
    pub root_streaming_slab_resident_bytes: u64,
    /// Eight small row vectors retained beside the word slabs.
    pub root_streaming_row_resident_bytes: u64,
    /// Known vector payload at the execution root; excludes allocator, stack,
    /// transpose authentication, setup, Rayon, and I/O buffers.
    pub execution_root_stream_resident_payload_bytes: u64,
    pub first_adjacency_round_artifact_bytes: u64,
    pub second_adjacency_round_artifact_bytes: u64,
    pub adjacency_round_peak_scratch_bytes: u64,
    pub adjacency_stage_projected_peak_scratch_bytes: u64,
    /// Equality, row-index, and first-row scalar vectors.
    pub adjacency_auxiliary_resident_bytes: u64,
    /// Both complete inverse vectors retained outside the nested execution
    /// root stream.
    pub adjacency_inverse_snapshot_resident_bytes: u64,
    /// Known vector payload at the adjacency root; excludes allocator, stack,
    /// transpose authentication, setup, Rayon, and I/O buffers.
    pub adjacency_root_stream_resident_payload_bytes: u64,
    pub aggregate_stage_lower_bound_bytes: u64,
    pub first_generation_fold_bytes: u64,
    pub second_generation_fold_bytes: u64,
    pub eighth_generation_fold_bytes: u64,
    pub source_materialization_fold_bytes: u64,
    pub final_generation_fold_bytes: u64,
    pub aggregate_retained_source_bytes: u64,
    pub aggregate_fold_peak_bytes: u64,
    pub aggregate_stage_projected_peak_bytes: u64,
    pub aggregate_with_transpose_coexistence_bytes: u64,
    pub provisional_scratch_gate_bytes: u64,
    pub provisional_available_memory_gate_bytes: u64,
    pub fold_scratch_model_complete: bool,
    pub fold_scratch_measurement_complete: bool,
    pub peak_memory_projection_complete: bool,
    pub composed_prover_implemented: bool,
}

impl BlsDoryBlake3ProductionResourceProjection {
    /// A run remains blocked until every independently testable gate closes.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.fold_scratch_model_complete
            && self.fold_scratch_measurement_complete
            && self.peak_memory_projection_complete
            && self.composed_prover_implemented
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BlsDoryBlake3ProductionPreflightError {
    #[error("the BLAKE3 production resource projection is invalid")]
    InvalidProjection,
    #[error(
        "insufficient scratch space for the provisional BLAKE3 production gate: need {required} bytes, have {available} bytes"
    )]
    InsufficientScratch { required: u64, available: u64 },
    #[error(
        "insufficient available memory for the provisional BLAKE3 production gate: need {required} bytes, have {available} bytes"
    )]
    InsufficientMemory { required: u64, available: u64 },
    #[error(
        "the production run remains blocked until every resource projection and the composed prover are complete"
    )]
    IncompleteProjection,
}

/// Project every currently known framed artifact without allocating production
/// setup, trace, source, or fold storage.
pub fn projected_bls_dory_blake3_production_resources()
-> Result<BlsDoryBlake3ProductionResourceProjection, BlsDoryBlake3ProductionPreflightError> {
    let logical_scalars = 1u64
        .checked_shl(BLS_DORY_SHARED_PRODUCTION_VARIABLES as u32)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let trace_rows = BLS_DORY_BLAKE3_TRACE_ROWS_U64;
    if trace_rows < 4 || !trace_rows.is_power_of_two() {
        return Err(BlsDoryBlake3ProductionPreflightError::InvalidProjection);
    }
    let execution_terminals = u64::try_from(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS)
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let execution_round_artifact_bytes = |active_rows: u64, generation: u32| {
        let explicit_scalar_count = active_rows
            .checked_mul(execution_terminals)
            .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
        let scalar_count = active_rows
            .checked_mul(BLS_DORY_BLAKE3_EXECUTION_ROUND_ROW_STRIDE)
            .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
        BlsDoryFoldArtifactSpec {
            context_digest: [1; 32],
            table_index: BLS_DORY_BLAKE3_EXECUTION_ROUND_TABLE_INDEX,
            generation,
            scalar_count,
            explicit_scalar_count,
            parent_digest: [2; 32],
        }
        .encoded_bytes()
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)
    };
    let first_execution_round_rows = trace_rows
        .checked_div(2)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let second_execution_round_rows = trace_rows
        .checked_div(4)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let first_execution_round_artifact_bytes =
        execution_round_artifact_bytes(first_execution_round_rows, 1)?;
    let second_execution_round_artifact_bytes =
        execution_round_artifact_bytes(second_execution_round_rows, 2)?;
    let execution_round_peak_scratch_bytes = first_execution_round_artifact_bytes
        .checked_add(second_execution_round_artifact_bytes)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let adjacency_terminals = u64::try_from(BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS)
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let adjacency_round_artifact_bytes = |active_rows: u64, generation: u32| {
        let explicit_scalar_count = active_rows
            .checked_mul(adjacency_terminals)
            .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
        let scalar_count = active_rows
            .checked_mul(BLS_DORY_BLAKE3_ADJACENCY_ROUND_ROW_STRIDE)
            .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
        BlsDoryFoldArtifactSpec {
            context_digest: [1; 32],
            table_index: BLS_DORY_BLAKE3_ADJACENCY_ROUND_TABLE_INDEX,
            generation,
            scalar_count,
            explicit_scalar_count,
            parent_digest: [2; 32],
        }
        .encoded_bytes()
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)
    };
    let first_adjacency_round_artifact_bytes =
        adjacency_round_artifact_bytes(first_execution_round_rows, 1)?;
    let second_adjacency_round_artifact_bytes =
        adjacency_round_artifact_bytes(second_execution_round_rows, 2)?;
    let adjacency_round_peak_scratch_bytes = first_adjacency_round_artifact_bytes
        .checked_add(second_adjacency_round_artifact_bytes)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let resident_scalar_bytes = u64::try_from(std::mem::size_of::<BlsDoryFr>())
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let execution_auxiliary_tables = u64::try_from(BLS_DORY_BLAKE3_EXECUTION_AUXILIARY_TABLES)
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let execution_auxiliary_resident_bytes = trace_rows
        .checked_mul(execution_auxiliary_tables)
        .and_then(|scalars| scalars.checked_mul(resident_scalar_bytes))
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let execution_root_snapshot_resident_bytes = trace_rows
        .checked_mul(BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES as u64)
        .and_then(|scalars| scalars.checked_mul(resident_scalar_bytes))
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let resident_word_bytes = u64::try_from(std::mem::size_of::<u64>())
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let root_streaming_word_columns =
        u64::try_from(BLS_DORY_BLAKE3_MAIN_WIDTH - 1 + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
            .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let root_streaming_block_rows = u64::try_from(BLS_DORY_TRANSPOSE_AUTHENTICATION_BLOCK_ROWS)
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let root_streaming_slab_resident_bytes = root_streaming_word_columns
        .checked_mul(root_streaming_block_rows)
        .and_then(|words| words.checked_mul(resident_word_bytes))
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let root_streaming_row_resident_bytes = root_streaming_word_columns
        .checked_mul(4)
        .and_then(|words| words.checked_mul(resident_word_bytes))
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let execution_root_stream_resident_payload_bytes = execution_auxiliary_resident_bytes
        .checked_add(execution_root_snapshot_resident_bytes)
        .and_then(|bytes| bytes.checked_add(root_streaming_slab_resident_bytes))
        .and_then(|bytes| bytes.checked_add(root_streaming_row_resident_bytes))
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let adjacency_auxiliary_tables = u64::try_from(BLS_DORY_BLAKE3_ADJACENCY_AUXILIARY_TABLES)
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let adjacency_auxiliary_resident_bytes = trace_rows
        .checked_mul(adjacency_auxiliary_tables)
        .and_then(|scalars| scalars.checked_mul(resident_scalar_bytes))
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let adjacency_inverse_snapshot_resident_bytes = trace_rows
        .checked_mul(BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES as u64)
        .and_then(|scalars| scalars.checked_mul(resident_scalar_bytes))
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let adjacency_root_stream_resident_payload_bytes = adjacency_auxiliary_resident_bytes
        .checked_add(adjacency_inverse_snapshot_resident_bytes)
        .and_then(|bytes| bytes.checked_add(execution_root_snapshot_resident_bytes))
        .and_then(|bytes| bytes.checked_add(root_streaming_slab_resident_bytes))
        .and_then(|bytes| bytes.checked_add(root_streaming_row_resident_bytes))
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let main_explicit_scalars = (BLS_DORY_BLAKE3_SIGNED_WORD_TABLES as u64)
        .checked_mul(trace_rows)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let preprocessed_word_scalars = (BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES as u64)
        .checked_mul(trace_rows)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let preprocessed_explicit_scalars = ((BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
        + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES)
        as u64)
        .checked_mul(trace_rows)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let accumulator_explicit_scalars = (BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES as u64)
        .checked_mul(trace_rows)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let inverse_explicit_scalars = (BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES as u64)
        .checked_mul(trace_rows)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;

    let main_bytes = BlsDoryCompactArtifactSpec {
        context_digest: [1; 32],
        scalar_count: logical_scalars,
        explicit_scalar_count: main_explicit_scalars,
        word_scalar_count: main_explicit_scalars,
        word_bytes: 8,
        code_bits: 8,
        word_width_codes: 0,
        word_group_len: trace_rows,
        signed_word_selectors: u64::MAX,
    }
    .encoded_bytes(1)
    .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let preprocessed_bytes = BlsDoryCompactArtifactSpec {
        context_digest: [1; 32],
        scalar_count: logical_scalars,
        explicit_scalar_count: preprocessed_explicit_scalars,
        word_scalar_count: preprocessed_word_scalars,
        word_bytes: 8,
        code_bits: 4,
        word_width_codes: 0,
        word_group_len: trace_rows,
        signed_word_selectors: 0,
    }
    .encoded_bytes(2)
    .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let scalar_source_bytes = |table_index, explicit_scalar_count| {
        BlsDoryFoldArtifactSpec {
            context_digest: [1; 32],
            table_index,
            generation: 1,
            scalar_count: logical_scalars,
            explicit_scalar_count,
            parent_digest: [2; 32],
        }
        .encoded_bytes()
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)
    };
    let accumulator_bytes = scalar_source_bytes(0, accumulator_explicit_scalars)?;
    let inverse_bytes = scalar_source_bytes(1, inverse_explicit_scalars)?;
    let framed_source_artifact_bytes = main_bytes
        .checked_add(preprocessed_bytes)
        .and_then(|bytes| bytes.checked_add(accumulator_bytes))
        .and_then(|bytes| bytes.checked_add(inverse_bytes))
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let composed_scratch = projected_shared_production_scratch_with_additional_sources(
        framed_source_artifact_bytes,
        &[
            BlsDoryAdditionalFoldSourceProjection {
                explicit_scalars: main_explicit_scalars,
                compress_first_eight_generations: true,
            },
            BlsDoryAdditionalFoldSourceProjection {
                explicit_scalars: accumulator_explicit_scalars,
                compress_first_eight_generations: false,
            },
            BlsDoryAdditionalFoldSourceProjection {
                explicit_scalars: preprocessed_explicit_scalars,
                compress_first_eight_generations: false,
            },
            BlsDoryAdditionalFoldSourceProjection {
                explicit_scalars: inverse_explicit_scalars,
                compress_first_eight_generations: false,
            },
        ],
    )
    .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let transpose_artifact_bytes = projected_bls_dory_transpose_artifact_bytes(
        BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
        BLS_DORY_BLAKE3_MAIN_WIDTH - 1,
    )
    .and_then(|main| {
        projected_bls_dory_transpose_artifact_bytes(
            BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
            BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
        )
        .and_then(|preprocessed| {
            main.checked_add(preprocessed)
                .ok_or(crate::dory_bls12_381_transpose::BlsDoryTransposeError::InvalidShape)
        })
    })
    .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let shared_aggregate_peak_bytes = projected_shared_production_scratch_bytes()
        .map_err(|_| BlsDoryBlake3ProductionPreflightError::InvalidProjection)?
        .aggregate_peak_bytes;
    let source_construction_coexistence_bytes = framed_source_artifact_bytes
        .checked_add(transpose_artifact_bytes)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let execution_stage_projected_peak_scratch_bytes = source_construction_coexistence_bytes
        .checked_add(execution_round_peak_scratch_bytes)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let adjacency_stage_projected_peak_scratch_bytes = source_construction_coexistence_bytes
        .checked_add(adjacency_round_peak_scratch_bytes)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let aggregate_stage_lower_bound_bytes = shared_aggregate_peak_bytes
        .checked_add(framed_source_artifact_bytes)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;
    let aggregate_with_transpose_coexistence_bytes = composed_scratch
        .aggregate_peak_bytes
        .checked_add(transpose_artifact_bytes)
        .ok_or(BlsDoryBlake3ProductionPreflightError::InvalidProjection)?;

    let provisional_scratch_gate_bytes = BLS_DORY_BLAKE3_PROVISIONAL_SCRATCH_GATE_BYTES
        .max(source_construction_coexistence_bytes)
        .max(execution_stage_projected_peak_scratch_bytes)
        .max(adjacency_stage_projected_peak_scratch_bytes)
        .max(aggregate_with_transpose_coexistence_bytes);
    let provisional_available_memory_gate_bytes =
        BLS_DORY_BLAKE3_PROVISIONAL_AVAILABLE_MEMORY_GATE_BYTES
            .max(execution_root_stream_resident_payload_bytes)
            .max(adjacency_root_stream_resident_payload_bytes);

    Ok(BlsDoryBlake3ProductionResourceProjection {
        shared_aggregate_peak_bytes,
        compact_source_payload_bytes: BLS_DORY_BLAKE3_COMPACT_SOURCE_PAYLOAD_BYTES,
        framed_source_artifact_bytes,
        transpose_artifact_bytes,
        source_construction_coexistence_bytes,
        first_execution_round_artifact_bytes,
        second_execution_round_artifact_bytes,
        execution_round_peak_scratch_bytes,
        execution_stage_projected_peak_scratch_bytes,
        execution_auxiliary_resident_bytes,
        execution_root_snapshot_resident_bytes,
        root_streaming_slab_resident_bytes,
        root_streaming_row_resident_bytes,
        execution_root_stream_resident_payload_bytes,
        first_adjacency_round_artifact_bytes,
        second_adjacency_round_artifact_bytes,
        adjacency_round_peak_scratch_bytes,
        adjacency_stage_projected_peak_scratch_bytes,
        adjacency_auxiliary_resident_bytes,
        adjacency_inverse_snapshot_resident_bytes,
        adjacency_root_stream_resident_payload_bytes,
        aggregate_stage_lower_bound_bytes,
        first_generation_fold_bytes: composed_scratch.first_generation_fold_bytes,
        second_generation_fold_bytes: composed_scratch.second_generation_fold_bytes,
        eighth_generation_fold_bytes: composed_scratch.eighth_generation_fold_bytes,
        source_materialization_fold_bytes: composed_scratch.source_materialization_fold_bytes,
        final_generation_fold_bytes: composed_scratch.final_generation_fold_bytes,
        aggregate_retained_source_bytes: composed_scratch.retained_source_bytes,
        aggregate_fold_peak_bytes: composed_scratch.aggregate_fold_peak_bytes,
        aggregate_stage_projected_peak_bytes: composed_scratch.aggregate_peak_bytes,
        aggregate_with_transpose_coexistence_bytes,
        provisional_scratch_gate_bytes,
        provisional_available_memory_gate_bytes,
        fold_scratch_model_complete: true,
        fold_scratch_measurement_complete: false,
        peak_memory_projection_complete: false,
        composed_prover_implemented: false,
    })
}

/// Fail closed before any production allocation or file creation. The caller
/// supplies already measured free resources; this function does no I/O.
pub fn preflight_bls_dory_blake3_production_resources(
    available_scratch_bytes: u64,
    available_memory_bytes: u64,
) -> Result<BlsDoryBlake3ProductionResourceProjection, BlsDoryBlake3ProductionPreflightError> {
    let projection = projected_bls_dory_blake3_production_resources()?;
    if available_scratch_bytes < projection.provisional_scratch_gate_bytes {
        return Err(BlsDoryBlake3ProductionPreflightError::InsufficientScratch {
            required: projection.provisional_scratch_gate_bytes,
            available: available_scratch_bytes,
        });
    }
    if available_memory_bytes < projection.provisional_available_memory_gate_bytes {
        return Err(BlsDoryBlake3ProductionPreflightError::InsufficientMemory {
            required: projection.provisional_available_memory_gate_bytes,
            available: available_memory_bytes,
        });
    }
    if !projection.is_complete() {
        return Err(BlsDoryBlake3ProductionPreflightError::IncompleteProjection);
    }
    Ok(projection)
}

/// Timings and retained scratch recorded while preparing the bounded native
/// BLAKE3 opening set used by cross-module composition tests.
#[cfg(all(test, feature = "whir-prototype"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlsDoryNativeBlake3TestTelemetry {
    pub(crate) fixture_millis: u128,
    pub(crate) source_millis: u128,
    pub(crate) sumcheck_millis: u128,
    pub(crate) finalize_millis: u128,
    pub(crate) total_millis: u128,
    pub(crate) retained_scratch_entries: usize,
    pub(crate) retained_scratch_bytes: u64,
}

/// Real four-source, six-opening preparation owned by the BLAKE3 test module.
/// Public fields are the minimum boundary needed by the shared-layout E2E.
#[cfg(all(test, feature = "whir-prototype"))]
pub(crate) struct PreparedBlsDoryNativeBlake3TestOpening {
    pub(crate) opening_statement: BlsDoryBlake3OpeningStatement,
    pub(crate) opening_set: BlsDoryDeferredOpeningSet,
    pub(crate) encoded_native_proof: Vec<u8>,
    pub(crate) trusted_preprocessing_commitment: BlsDoryGt,
    pub(crate) telemetry: BlsDoryNativeBlake3TestTelemetry,
    commitments: BlsDoryBlake3SourceCommitments,
    execution: BlsDoryBlake3ExecutionSumcheckProof,
    adjacency: BlsDoryBlake3AdjacencySumcheckProof,
    geometry: BlsDoryBlake3ReplayGeometry,
    verifier_context: BlsDoryBlake3VerifierContext,
}

/// Prepare authentic native BLAKE3 sources and verifier-replayed openings for
/// a bounded shared-layout composition test. This helper is absent from every
/// non-test build and does not provide the missing production preprocessing
/// registry.
#[cfg(all(test, feature = "whir-prototype"))]
pub(crate) fn prepare_native_blake3_test_opening_at_layout(
    activation: &[u8],
    bridge: &BlsDoryOutputBridgeStatement,
    layout: BlsDoryAggregateLayout,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &std::path::Path,
) -> Result<PreparedBlsDoryNativeBlake3TestOpening, BlsDoryAggregateError> {
    if activation.len() != 32
        || bridge.final_activation_len() != activation.len()
        || layout.variables() != 21
        || setup.max_log_n() < layout.variables()
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    tests::prepare_native_blake3_test_opening_at_layout_impl(
        activation,
        bridge,
        layout,
        setup,
        scratch_directory,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dory_bls12_381_aggregate::MAX_BLS_DORY_AGGREGATE_CLAIMS;
    #[cfg(feature = "whir-prototype")]
    use crate::dory_bls12_381_aggregate::{
        BlsDoryAggregateLayout, BlsDoryCommittedPolynomial, BlsDoryCommittedPolynomialWriter,
        BlsDoryCompactRowSource, BlsDoryDeferredOpeningSet,
        commit_bls_dory_compact_row_source_with_scratch, commit_bls_dory_polynomial,
        commit_bls_dory_row_source_with_scratch, prove_bls_dory_deferred_opening_sets,
        prove_bls_dory_deferred_opening_sets_consuming_with_scratch,
        prove_bls_dory_same_commitment_openings, verify_bls_dory_openings,
    };
    #[cfg(feature = "whir-prototype")]
    use crate::dory_bls12_381_prototype::DeterministicBlsDorySetup;
    #[cfg(feature = "whir-prototype")]
    use crate::dory_bls12_381_streaming::BlsDoryRowSource;
    #[cfg(feature = "whir-prototype")]
    use crate::dory_bls12_381_transpose::{BlsDoryTransposeError, BlsDoryWordTransposeWriter};
    #[cfg(feature = "whir-prototype")]
    use crate::structured_blake3_narrow::{
        for_each_main_trace_row, for_each_preprocessed_trace_row, generate_main_trace,
        public_values,
    };
    #[cfg(feature = "whir-prototype")]
    use crate::structured_blake3_tree::build_tree_witness;
    use dory_pcs::primitives::arithmetic::Group as DoryGroup;
    #[cfg(feature = "whir-prototype")]
    use p3_air::BaseAir;
    #[cfg(feature = "whir-prototype")]
    use p3_matrix::Matrix;
    #[cfg(feature = "whir-prototype")]
    use std::{
        io::{Read, Seek, SeekFrom, Write},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(feature = "whir-prototype")]
    fn dense_aggregate_layout() -> BlsDoryAggregateLayout {
        BlsDoryAggregateLayout::new(8, 8).unwrap()
    }

    #[cfg(feature = "whir-prototype")]
    const OUTPUT_CONTEXT: &str = "CMFD/FORGEMATRIX/OUTPUT/V2";

    #[cfg(feature = "whir-prototype")]
    static BLAKE3_SCRATCH_NONCE: AtomicU64 = AtomicU64::new(1);

    #[cfg(feature = "whir-prototype")]
    fn bounded_preprocessing_record_fixture() -> BlsDoryBlake3PreprocessingRecord {
        let terminal_count =
            BLS_DORY_BLAKE3_SOURCE_TERMINALS[BlsDoryBlake3SourceRole::Preprocessing.index()];
        let setup_identity = [0xab; 32];
        let scalar_count = 1usize << BLS_DORY_SHARED_PRODUCTION_VARIABLES;
        let explicit_scalar_count = terminal_count * BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS;
        let source_spec = source_artifact_spec(
            setup_identity,
            BLS_DORY_BLAKE3_SHARED_DORY_NU,
            BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
            scalar_count,
            explicit_scalar_count,
        )
        .unwrap();
        let compact_spec = BlsDoryCompactArtifactSpec {
            context_digest: source_spec.context_digest,
            scalar_count: scalar_count as u64,
            explicit_scalar_count: explicit_scalar_count as u64,
            word_scalar_count: (BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
                * BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS) as u64,
            word_bytes: 8,
            code_bits: 4,
            word_width_codes: 0,
            word_group_len: BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS as u64,
            signed_word_selectors: 0,
        };
        let fri_key = pinned_preprocessed_key(
            BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES,
            BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
        )
        .unwrap();
        let mut record = BlsDoryBlake3PreprocessingRecord {
            record_version: BLS_DORY_BLAKE3_PREPROCESSING_RECORD_VERSION,
            projection_version: BLS_DORY_BLAKE3_PROJECTION_VERSION,
            native_proof_version: BLS_DORY_BLAKE3_NATIVE_PROOF_VERSION,
            activation_len: BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES as u64,
            cell_point_variables: BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES.ilog2(),
            trace_rows: BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS as u64,
            preprocessed_width: BLS_DORY_BLAKE3_PREPROCESSED_WIDTH as u32,
            preprocessed_word_tables: BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES as u32,
            preprocessed_code_tables: BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES as u32,
            preprocessing_terminal_count: terminal_count as u32,
            trace_variables: BLS_DORY_BLAKE3_TRACE_VARIABLES as u32,
            source_variables: BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES as u32,
            shared_variables: BLS_DORY_SHARED_PRODUCTION_VARIABLES as u32,
            dory_nu: BLS_DORY_BLAKE3_SHARED_DORY_NU as u32,
            dory_sigma: BLS_DORY_BLAKE3_SHARED_DORY_SIGMA as u32,
            setup_max_log_n: BLS_DORY_SHARED_PRODUCTION_VARIABLES as u32,
            setup_identity: hex::encode(setup_identity),
            preprocessing_bls_commitment: encode_blake3_record_commitment(&loop {
                let commitment = BlsDoryGt::random();
                if commitment != BlsDoryGt::identity() {
                    break commitment;
                }
            })
            .unwrap(),
            transpose_digest: hex::encode([0x11; 32]),
            transpose_bytes: projected_bls_dory_transpose_artifact_bytes(
                BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
                BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
            )
            .unwrap(),
            compact_artifact_context_digest: hex::encode(compact_spec.context_digest),
            compact_artifact_digest: hex::encode([0x22; 32]),
            compact_artifact_bytes: compact_spec.encoded_bytes(2).unwrap(),
            compact_scalar_count: compact_spec.scalar_count,
            compact_explicit_scalar_count: compact_spec.explicit_scalar_count,
            compact_word_scalar_count: compact_spec.word_scalar_count,
            compact_word_bytes: compact_spec.word_bytes,
            compact_code_bits: compact_spec.code_bits,
            compact_word_width_codes: compact_spec.word_width_codes,
            compact_word_group_len: compact_spec.word_group_len,
            compact_signed_word_selectors: compact_spec.signed_word_selectors,
            fri_preprocessed_registry_digest: hex::encode(pinned_preprocessed_registry_digest()),
            fri_preprocessed_root: fri_key.root.map(|word| format!("{word:016x}")),
            record_digest: String::new(),
        };
        record.record_digest = hex::encode(record.canonical_digest().unwrap());
        record
    }

    #[cfg(feature = "whir-prototype")]
    fn pinned_production_preprocessing_context() -> BlsDoryBlake3VerifierContext {
        let record: BlsDoryBlake3PreprocessingRecord =
            serde_json::from_slice(BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD).unwrap();
        BlsDoryBlake3VerifierContext::for_test_metadata(
            BlsDoryAggregateLayout::new(
                BLS_DORY_BLAKE3_SHARED_DORY_NU,
                BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
            )
            .unwrap(),
            decode_blake3_record_hex_32("setup identity", &record.setup_identity).unwrap(),
            record.setup_max_log_n as usize,
        )
        .unwrap()
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn production_preprocessing_pin_loads_exact_pinned_record() {
        let record: BlsDoryBlake3PreprocessingRecord =
            serde_json::from_slice(BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD).unwrap();
        let context = pinned_production_preprocessing_context();
        let pin = native_blake3_production_preprocessing_pin(&context).unwrap();
        let mut canonical_json = serde_json::to_vec_pretty(&record).unwrap();
        canonical_json.push(b'\n');

        assert_eq!(
            canonical_json,
            BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD
        );
        assert_eq!(
            record.canonical_digest().unwrap(),
            BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD_DIGEST
        );
        assert_eq!(
            decode_blake3_record_hex_32("record", &record.record_digest).unwrap(),
            BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD_DIGEST
        );
        assert_eq!(
            encode_blake3_record_commitment(&pin.commitment).unwrap(),
            record.preprocessing_bls_commitment
        );
        assert_ne!(pin.commitment, BlsDoryGt::identity());
        assert_eq!(pin.verifier_context, context);
        assert_eq!(pin.geometry, BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY);
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn production_preprocessing_pin_rejects_mutated_embedded_records() {
        let mut record: BlsDoryBlake3PreprocessingRecord =
            serde_json::from_slice(BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD).unwrap();
        record.compact_artifact_digest = hex::encode([0x42; 32]);
        record.record_digest = hex::encode(record.canonical_digest().unwrap());
        record.validate().unwrap();
        let mutated = serde_json::to_vec_pretty(&record).unwrap();
        assert!(matches!(
            native_blake3_production_preprocessing_pin_from_record(
                &mutated,
                &pinned_production_preprocessing_context(),
            ),
            Err(BlsDoryBlake3PreprocessingRecordError::DigestMismatch(
                "pinned production record"
            ))
        ));

        let mut unknown_field: serde_json::Value =
            serde_json::from_slice(BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD).unwrap();
        unknown_field
            .as_object_mut()
            .unwrap()
            .insert("unreviewed".to_owned(), serde_json::Value::Bool(true));
        assert!(matches!(
            native_blake3_production_preprocessing_pin_from_record(
                &serde_json::to_vec(&unknown_field).unwrap(),
                &pinned_production_preprocessing_context(),
            ),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "embedded record JSON"
            ))
        ));

        let truncated = &BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD
            [..BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD.len() - 2];
        assert!(matches!(
            native_blake3_production_preprocessing_pin_from_record(
                truncated,
                &pinned_production_preprocessing_context(),
            ),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "embedded record JSON"
            ))
        ));

        let mut duplicate_field = br#"{"record_version":1,"#.to_vec();
        duplicate_field.extend_from_slice(&BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD[1..]);
        assert!(matches!(
            native_blake3_production_preprocessing_pin_from_record(
                &duplicate_field,
                &pinned_production_preprocessing_context(),
            ),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "embedded record JSON"
            ))
        ));
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn production_preprocessing_pin_rejects_wrong_context_and_commitment() {
        let context = pinned_production_preprocessing_context();
        let mut wrong_context = context.clone();
        wrong_context.setup_identity[0] ^= 1;
        assert!(matches!(
            native_blake3_production_preprocessing_pin(&wrong_context),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "verifier context"
            ))
        ));
        let mut wrong_max_log_n = context.clone();
        wrong_max_log_n.setup_max_log_n += 1;
        assert!(matches!(
            native_blake3_production_preprocessing_pin(&wrong_max_log_n),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "verifier context"
            ))
        ));
        let wrong_layout = BlsDoryBlake3VerifierContext::for_test_metadata(
            BlsDoryAggregateLayout::new(15, 18).unwrap(),
            context.setup_identity,
            context.setup_max_log_n,
        )
        .unwrap();
        assert!(matches!(
            native_blake3_production_preprocessing_pin(&wrong_layout),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "verifier context"
            ))
        ));

        let pin = native_blake3_production_preprocessing_pin(&context).unwrap();
        let activation = vec![0_u8; BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES];
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            [0x11; 32],
            [0x22; 32],
            &activation,
            [0x33; 32],
            vec![BlsDoryFr::zero(); BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES.ilog2() as usize],
        )
        .unwrap();
        let commitments = BlsDoryBlake3SourceCommitments {
            main: pin.commitment,
            accumulator: pin.commitment,
            preprocessing: pin.commitment,
            inverse: pin.commitment,
        };
        pin.validate(
            &bridge,
            BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
            BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY,
            &context,
            &commitments,
        )
        .unwrap();

        let wrong_commitments = BlsDoryBlake3SourceCommitments {
            preprocessing: BlsDoryGt::identity(),
            ..commitments
        };
        assert_eq!(
            pin.validate(
                &bridge,
                BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS,
                BLS_DORY_BLAKE3_PRODUCTION_REPLAY_GEOMETRY,
                &context,
                &wrong_commitments,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn preprocessing_record_is_canonical_and_json_round_trips() {
        let record = bounded_preprocessing_record_fixture();
        record.validate().unwrap();
        let encoded = serde_json::to_vec_pretty(&record).unwrap();
        let decoded: BlsDoryBlake3PreprocessingRecord = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, record);
        decoded.validate().unwrap();
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn preprocessing_record_rejects_mutated_or_noncanonical_fields() {
        let record = bounded_preprocessing_record_fixture();

        let mut wrong_geometry = record.clone();
        wrong_geometry.trace_rows += 1;
        assert!(matches!(
            wrong_geometry.validate(),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(_))
        ));

        let mut wrong_fri_root = record.clone();
        wrong_fri_root.fri_preprocessed_root[0] = "0000000000000000".to_owned();
        wrong_fri_root.record_digest = hex::encode(wrong_fri_root.canonical_digest().unwrap());
        assert!(matches!(
            wrong_fri_root.validate(),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "FRI preprocessing root"
            ))
        ));

        let mut wrong_context = record.clone();
        wrong_context.compact_artifact_context_digest = hex::encode([0x66; 32]);
        wrong_context.record_digest = hex::encode(wrong_context.canonical_digest().unwrap());
        assert!(matches!(
            wrong_context.validate(),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "compact artifact context"
            ))
        ));

        let mut identity_commitment = record.clone();
        identity_commitment.preprocessing_bls_commitment =
            encode_blake3_record_commitment(&BlsDoryGt::identity()).unwrap();
        identity_commitment.record_digest =
            hex::encode(identity_commitment.canonical_digest().unwrap());
        assert!(matches!(
            identity_commitment.validate(),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidMetadata(
                "preprocessing BLS commitment"
            ))
        ));

        let mut uppercase_hex = record.clone();
        uppercase_hex.setup_identity.make_ascii_uppercase();
        assert!(matches!(
            uppercase_hex.validate(),
            Err(BlsDoryBlake3PreprocessingRecordError::InvalidHex(
                "setup identity"
            ))
        ));

        let mut wrong_digest = record;
        wrong_digest.record_digest = hex::encode([0x55; 32]);
        assert!(matches!(
            wrong_digest.validate(),
            Err(BlsDoryBlake3PreprocessingRecordError::DigestMismatch(
                "record"
            ))
        ));
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn preprocessing_record_digest_binds_every_record_field() {
        let record = bounded_preprocessing_record_fixture();
        let expected = record.canonical_digest().unwrap();

        macro_rules! assert_numeric_field_bound {
            ($field:ident) => {{
                let mut mutated = record.clone();
                mutated.$field = mutated.$field.wrapping_add(1);
                assert_ne!(
                    mutated.canonical_digest().unwrap(),
                    expected,
                    "{} is not bound",
                    stringify!($field)
                );
            }};
        }
        macro_rules! assert_hex_field_bound {
            ($field:ident) => {{
                let mut mutated = record.clone();
                let replacement = if mutated.$field.starts_with('0') {
                    "1"
                } else {
                    "0"
                };
                mutated.$field.replace_range(..1, replacement);
                assert_ne!(
                    mutated.canonical_digest().unwrap(),
                    expected,
                    "{} is not bound",
                    stringify!($field)
                );
            }};
        }

        assert_numeric_field_bound!(record_version);
        assert_numeric_field_bound!(projection_version);
        assert_numeric_field_bound!(native_proof_version);
        assert_numeric_field_bound!(activation_len);
        assert_numeric_field_bound!(cell_point_variables);
        assert_numeric_field_bound!(trace_rows);
        assert_numeric_field_bound!(preprocessed_width);
        assert_numeric_field_bound!(preprocessed_word_tables);
        assert_numeric_field_bound!(preprocessed_code_tables);
        assert_numeric_field_bound!(preprocessing_terminal_count);
        assert_numeric_field_bound!(trace_variables);
        assert_numeric_field_bound!(source_variables);
        assert_numeric_field_bound!(shared_variables);
        assert_numeric_field_bound!(dory_nu);
        assert_numeric_field_bound!(dory_sigma);
        assert_numeric_field_bound!(setup_max_log_n);
        assert_numeric_field_bound!(transpose_bytes);
        assert_numeric_field_bound!(compact_artifact_bytes);
        assert_numeric_field_bound!(compact_scalar_count);
        assert_numeric_field_bound!(compact_explicit_scalar_count);
        assert_numeric_field_bound!(compact_word_scalar_count);
        assert_numeric_field_bound!(compact_word_bytes);
        assert_numeric_field_bound!(compact_code_bits);
        assert_numeric_field_bound!(compact_word_width_codes);
        assert_numeric_field_bound!(compact_word_group_len);
        assert_numeric_field_bound!(compact_signed_word_selectors);

        assert_hex_field_bound!(setup_identity);
        assert_hex_field_bound!(transpose_digest);
        assert_hex_field_bound!(compact_artifact_context_digest);
        assert_hex_field_bound!(compact_artifact_digest);
        assert_hex_field_bound!(fri_preprocessed_registry_digest);

        let mut mutated_commitment = record.clone();
        mutated_commitment.preprocessing_bls_commitment = encode_blake3_record_commitment(&loop {
            let commitment = BlsDoryGt::random();
            let encoded = encode_blake3_record_commitment(&commitment).unwrap();
            if commitment != BlsDoryGt::identity() && encoded != record.preprocessing_bls_commitment
            {
                break commitment;
            }
        })
        .unwrap();
        assert_ne!(mutated_commitment.canonical_digest().unwrap(), expected);

        for root_index in 0..record.fri_preprocessed_root.len() {
            let mut mutated = record.clone();
            let word = u64::from_str_radix(&mutated.fri_preprocessed_root[root_index], 16).unwrap();
            mutated.fri_preprocessed_root[root_index] = format!("{:016x}", word.wrapping_add(1));
            assert_ne!(
                mutated.canonical_digest().unwrap(),
                expected,
                "FRI root word {root_index} is not bound"
            );
        }
    }

    #[test]
    fn canonical_opening_binding_rejects_semantic_mismatches() {
        let main = BlsDoryGt::random();
        let preprocessing = loop {
            let candidate = BlsDoryGt::random();
            if candidate != main {
                break candidate;
            }
        };
        let source_commitments = BlsDoryBlake3SourceCommitments {
            main,
            accumulator: BlsDoryGt::random(),
            preprocessing,
            inverse: BlsDoryGt::random(),
        };

        let execution_trace = (0..BLS_DORY_BLAKE3_TRACE_VARIABLES)
            .map(|coordinate| BlsDoryFr::from_u64(coordinate as u64 + 101))
            .collect::<Vec<_>>();
        let adjacency_trace = (0..BLS_DORY_BLAKE3_TRACE_VARIABLES)
            .map(|coordinate| BlsDoryFr::from_u64(coordinate as u64 + 211))
            .collect::<Vec<_>>();
        let points = (0..BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES.len())
            .map(|claim| {
                let mut point = vec![BlsDoryFr::zero(); BLS_DORY_SHARED_PRODUCTION_VARIABLES];
                let trace = if claim < BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS {
                    &execution_trace
                } else {
                    &adjacency_trace
                };
                point[..BLS_DORY_BLAKE3_TRACE_VARIABLES].copy_from_slice(trace);
                for selector in 0..BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES {
                    point[BLS_DORY_BLAKE3_TRACE_VARIABLES + selector] =
                        BlsDoryFr::from_u64((claim as u64 + 1) * 31 + selector as u64 + 1);
                }
                if claim >= BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS {
                    point[BLS_DORY_BLAKE3_TRACE_VARIABLES
                        + BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES] = BlsDoryFr::zero();
                }
                point
            })
            .collect::<Vec<_>>();
        let evaluations = (0..BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES.len())
            .map(|claim| BlsDoryFr::from_u64(claim as u64 + 11))
            .collect::<Vec<_>>();
        let statement = BlsDoryBlake3OpeningStatement::from_verified_replay(
            source_commitments.clone(),
            blake3_opening_replay(&points, &evaluations),
        )
        .unwrap();
        let claims = BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES
            .iter()
            .enumerate()
            .map(|(index, role)| BlsDoryOpeningClaim {
                commitment: *source_commitments.commitment(*role),
                point: points[index].clone(),
                evaluation: evaluations[index],
            })
            .collect::<Vec<_>>();
        assert_eq!(statement.claims(), claims);
        statement.validate_claims(&claims).unwrap();

        let mut wrong_count = claims.clone();
        wrong_count.pop();
        assert_eq!(
            statement.validate_claims(&wrong_count),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let mut wrong_role = claims.clone();
        wrong_role[0].commitment = source_commitments.preprocessing;
        assert_eq!(
            statement.validate_claims(&wrong_role),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let mut wrong_point = claims.clone();
        wrong_point[0].point[0] = wrong_point[0].point[0] + BlsDoryFr::from_u64(1);
        assert_eq!(
            statement.validate_claims(&wrong_point),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let mut wrong_evaluation = claims;
        wrong_evaluation[0].evaluation = wrong_evaluation[0].evaluation + BlsDoryFr::from_u64(1);
        assert_eq!(
            statement.validate_claims(&wrong_evaluation),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );

        let mut noncanonical_points = points.clone();
        noncanonical_points[0][BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES] =
            BlsDoryFr::from_u64(1);
        assert_eq!(
            BlsDoryBlake3OpeningStatement::from_verified_replay(
                source_commitments.clone(),
                blake3_opening_replay(&noncanonical_points, &evaluations),
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let mut mismatched_execution_prefix = points.clone();
        mismatched_execution_prefix[1][0] =
            mismatched_execution_prefix[1][0] + BlsDoryFr::from_u64(1);
        assert_eq!(
            BlsDoryBlake3OpeningStatement::from_verified_replay(
                source_commitments.clone(),
                blake3_opening_replay(&mismatched_execution_prefix, &evaluations),
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let mut nonzero_adjacency_half = points.clone();
        nonzero_adjacency_half[3]
            [BLS_DORY_BLAKE3_TRACE_VARIABLES + BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES] =
            BlsDoryFr::from_u64(1);
        assert_eq!(
            BlsDoryBlake3OpeningStatement::from_verified_replay(
                source_commitments.clone(),
                blake3_opening_replay(&nonzero_adjacency_half, &evaluations),
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let mut short_points = points;
        short_points[0].pop();
        assert_eq!(
            BlsDoryBlake3OpeningStatement::from_verified_replay(
                source_commitments,
                blake3_opening_replay(&short_points, &evaluations),
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn native_blake3_proof_wire_is_exact_canonical_and_bounded() {
        let execution_rounds = (0..BLS_DORY_BLAKE3_TRACE_VARIABLES)
            .map(|round| {
                (0..=BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE)
                    .map(|sample| BlsDoryFr::from_u64((round * 101 + sample + 1) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let adjacency_rounds = (0..BLS_DORY_BLAKE3_TRACE_VARIABLES)
            .map(|round| {
                (0..=BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE)
                    .map(|sample| BlsDoryFr::from_u64((round * 17 + sample + 10_001) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let proof = BlsDoryNativeBlake3Proof {
            source_commitments: BlsDoryBlake3SourceCommitments {
                main: BlsDoryGt::random(),
                accumulator: BlsDoryGt::random(),
                preprocessing: BlsDoryGt::random(),
                inverse: BlsDoryGt::random(),
            },
            execution: BlsDoryBlake3ExecutionSumcheckProof {
                rounds: execution_rounds,
                terminal_evaluations: (0..BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS)
                    .map(|index| BlsDoryFr::from_u64(index as u64 + 20_001))
                    .collect(),
                transcript_digest: [0x31; 32],
            },
            adjacency: BlsDoryBlake3AdjacencySumcheckProof {
                rounds: adjacency_rounds,
                terminal_evaluations: (0..BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS)
                    .map(|index| BlsDoryFr::from_u64(index as u64 + 30_001))
                    .collect(),
                transcript_digest: [0x42; 32],
            },
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(
            encoded.len(),
            BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES + BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES
        );
        assert_eq!(BlsDoryNativeBlake3Proof::decode(&encoded).unwrap(), proof);

        let mut malformed = encoded.clone();
        malformed[8] ^= 1;
        assert!(BlsDoryNativeBlake3Proof::decode(&malformed).is_err());
        let mut malformed = encoded.clone();
        malformed[10..12].copy_from_slice(&2_u16.to_le_bytes());
        assert!(BlsDoryNativeBlake3Proof::decode(&malformed).is_err());
        let mut malformed = encoded.clone();
        malformed[18..20].copy_from_slice(&1_u16.to_le_bytes());
        assert!(BlsDoryNativeBlake3Proof::decode(&malformed).is_err());
        assert!(BlsDoryNativeBlake3Proof::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut overlong = encoded;
        overlong.push(0);
        assert!(BlsDoryNativeBlake3Proof::decode(&overlong).is_err());
    }

    #[cfg(feature = "whir-prototype")]
    struct Blake3ScratchDirectory(std::path::PathBuf);

    #[cfg(feature = "whir-prototype")]
    impl Blake3ScratchDirectory {
        fn create() -> Self {
            let nonce = BLAKE3_SCRATCH_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-blake3-test-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    #[cfg(feature = "whir-prototype")]
    impl Drop for Blake3ScratchDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(feature = "whir-prototype")]
    struct BoundedPreparedSourceFixture {
        prepared: PreparedBlsDoryBlake3Sources,
        main_rows: Vec<Vec<u64>>,
        preprocessing_rows: Vec<Vec<u64>>,
        layout: BlsDoryAggregateLayout,
        setup: DeterministicBlsDorySetup,
    }

    #[cfg(feature = "whir-prototype")]
    fn bounded_prepared_source_bundle(
        scratch_directory: &std::path::Path,
        corrupt_main_before_binding: bool,
    ) -> Result<BoundedPreparedSourceFixture, BlsDoryAggregateError> {
        const TRACE_ROWS: usize = 16;
        let layout = BlsDoryAggregateLayout::new(7, 7)?;
        let setup =
            deterministic_bls_dory_setup(14).map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
        let main_rows = (0..TRACE_ROWS)
            .map(|row| {
                (0..BLS_DORY_BLAKE3_MAIN_WIDTH - 1)
                    .map(|column| {
                        let value = column as i64 * 13 + row as i64 - 1_337;
                        u64::from_le_bytes(value.to_le_bytes())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let preprocessing_rows = (0..TRACE_ROWS)
            .map(|row| {
                (0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
                    .map(|column| {
                        if NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.contains(&column) {
                            (column * 101 + row * 17) as u64
                        } else {
                            ((column + row) & 1) as u64
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut main_writer = BlsDoryWordTransposeWriter::create(
            scratch_directory,
            TRACE_ROWS,
            BLS_DORY_BLAKE3_MAIN_WIDTH - 1,
            TRACE_ROWS,
        )
        .map_err(blake3_transpose_error)?;
        for row in &main_rows {
            main_writer.write_row(row).map_err(blake3_transpose_error)?;
        }
        let mut main_transpose = main_writer.finish().map_err(blake3_transpose_error)?;
        let main = {
            let mut source =
                TransposedLocalNextSignedWordRowSource::new_for_layout(&mut main_transpose, layout)
                    .map_err(blake3_transpose_error)?;
            commit_bls_dory_compact_row_source_with_scratch(
                &mut source,
                layout.nu(),
                layout.sigma(),
                &setup,
                scratch_directory,
            )?
        };

        let mut preprocessing_writer = BlsDoryWordTransposeWriter::create(
            scratch_directory,
            TRACE_ROWS,
            BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
            TRACE_ROWS,
        )
        .map_err(blake3_transpose_error)?;
        for row in &preprocessing_rows {
            preprocessing_writer
                .write_row(row)
                .map_err(blake3_transpose_error)?;
        }
        let mut preprocessing_transpose = preprocessing_writer
            .finish()
            .map_err(blake3_transpose_error)?;
        let preprocessing = {
            let mut source = TransposedPreprocessedRowSource::new_for_layout(
                &mut preprocessing_transpose,
                layout,
            )
            .map_err(blake3_transpose_error)?;
            commit_bls_dory_compact_row_source_with_scratch(
                &mut source,
                layout.nu(),
                layout.sigma(),
                &setup,
                scratch_directory,
            )?
        };

        let commit_scalar_source = |seed: u64, scalar_tables: usize| {
            let mut writer = BlsDoryCommittedPolynomialWriter::create(
                scratch_directory,
                TRACE_ROWS * scalar_tables,
                layout.nu(),
                layout.sigma(),
                &setup,
            )?;
            writer.write_scalars(
                &(0..TRACE_ROWS * scalar_tables)
                    .map(|index| BlsDoryFr::from_u64(seed + index as u64 * 19))
                    .collect::<Vec<_>>(),
            )?;
            writer.finish()
        };
        let mut accumulator_writer = BlsDoryCommittedPolynomialWriter::create_signed_byte(
            scratch_directory,
            TRACE_ROWS * BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES,
            layout.nu(),
            layout.sigma(),
            127,
            &setup,
        )?;
        accumulator_writer.write_signed_values(
            &(0..TRACE_ROWS * BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES)
                .map(|index| index as i64 - TRACE_ROWS as i64)
                .collect::<Vec<_>>(),
        )?;
        let accumulator = accumulator_writer.finish()?;
        let inverse = commit_scalar_source(20_003, BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES)?;
        let sources = BlsDoryBlake3CommittedSources {
            main,
            accumulator,
            preprocessing,
            inverse,
        };
        if corrupt_main_before_binding {
            flip_file_byte(main_transpose.path(), 100)
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        }
        let prepared = PreparedBlsDoryBlake3Sources::new(
            sources,
            main_transpose,
            preprocessing_transpose,
            TRACE_ROWS,
            layout,
            &setup,
        )?;
        Ok(BoundedPreparedSourceFixture {
            prepared,
            main_rows,
            preprocessing_rows,
            layout,
            setup,
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn bls_values(values: impl IntoIterator<Item = Goldilocks>) -> Vec<BlsDoryFr> {
        values
            .into_iter()
            .map(|value| BlsDoryFr::from_i64(centered_goldilocks(value)))
            .collect()
    }

    #[cfg(feature = "whir-prototype")]
    fn maximum_abs_constant(expression: &BlsDoryBlake3ConstraintExpr) -> u64 {
        match expression {
            BlsDoryBlake3ConstraintExpr::Constant(value) => value.unsigned_abs(),
            BlsDoryBlake3ConstraintExpr::Add(left, right)
            | BlsDoryBlake3ConstraintExpr::Sub(left, right)
            | BlsDoryBlake3ConstraintExpr::Mul(left, right) => {
                maximum_abs_constant(left).max(maximum_abs_constant(right))
            }
            BlsDoryBlake3ConstraintExpr::Neg(value) => maximum_abs_constant(value),
            BlsDoryBlake3ConstraintExpr::Variable(_)
            | BlsDoryBlake3ConstraintExpr::FirstRow
            | BlsDoryBlake3ConstraintExpr::LastRow
            | BlsDoryBlake3ConstraintExpr::Transition => 0,
        }
    }

    #[cfg(feature = "whir-prototype")]
    const DENSE_EXECUTION_SUMCHECK_DEGREE: usize = BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE;
    #[cfg(feature = "whir-prototype")]
    const DENSE_ADJACENCY_SUMCHECK_DEGREE: usize = BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE;
    #[cfg(feature = "whir-prototype")]
    const DENSE_EXECUTION_BATCH_TERMINAL_COUNTS: [usize; 4] = [256, 256, 66, 168];

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseExecutionSumcheckProof {
        rounds: Vec<Vec<BlsDoryFr>>,
        terminal_evaluations: Vec<BlsDoryFr>,
        transcript_digest: [u8; 32],
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAdjacencySumcheckProof {
        rounds: Vec<Vec<BlsDoryFr>>,
        terminal_evaluations: Vec<BlsDoryFr>,
        transcript_digest: [u8; 32],
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseExecutionOpeningBatch {
        commitment: BlsDoryGt,
        terminal_count: usize,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAuthenticatedExecutionProof {
        sumcheck: DenseExecutionSumcheckProof,
        opening_batches: Vec<DenseExecutionOpeningBatch>,
        opening_proof: Vec<u8>,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAdjacencyOpeningBatch {
        commitment: BlsDoryGt,
        terminal_start: usize,
        terminal_count: usize,
        selector_variables: usize,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAuthenticatedAdjacencyProof {
        sumcheck: DenseAdjacencySumcheckProof,
        opening_batches: Vec<DenseAdjacencyOpeningBatch>,
        opening_proof: Vec<u8>,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAuthenticatedBlake3Proof {
        execution_sumcheck: DenseExecutionSumcheckProof,
        adjacency_sumcheck: DenseAdjacencySumcheckProof,
        execution_batches: Vec<DenseExecutionOpeningBatch>,
        inverse_commitment: BlsDoryGt,
        opening_proof: Vec<u8>,
    }

    #[cfg(feature = "whir-prototype")]
    struct DenseBlake3Fixture {
        activation: Vec<u8>,
        air: NarrowBlake3Air,
        tables: Vec<Vec<BlsDoryFr>>,
        statement: StructuredBlake3Statement,
        witness: crate::structured_blake3_tree::Blake3TreeWitness,
        public: Vec<BlsDoryFr>,
        constraints: Vec<BlsDoryBlake3ConstraintExpr>,
        bridge: BlsDoryOutputBridgeStatement,
    }

    #[cfg(feature = "whir-prototype")]
    struct DenseExecutionRelation<'a> {
        public: &'a [BlsDoryFr],
        constraints: &'a [BlsDoryBlake3ConstraintExpr],
        mixing_powers: &'a [BlsDoryFr],
        raw_evaluation: BlsDoryFr,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone, Copy)]
    struct DenseAdjacencyRelation {
        trace_rows: BlsDoryFr,
        compression: BlsDoryFr,
        alpha: BlsDoryFr,
        local_mixing: [BlsDoryFr; 2],
        rational_mixing: BlsDoryFr,
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_execution_tables(
        main_rows: &[Vec<BlsDoryFr>],
        preprocessed_rows: &[Vec<BlsDoryFr>],
    ) -> Vec<Vec<BlsDoryFr>> {
        assert_eq!(main_rows.len(), preprocessed_rows.len());
        assert!(main_rows.len().is_power_of_two());
        assert!(
            main_rows
                .iter()
                .all(|row| row.len() == BLS_DORY_BLAKE3_MAIN_WIDTH)
        );
        assert!(
            preprocessed_rows
                .iter()
                .all(|row| row.len() == BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
        );
        let mut tables = Vec::with_capacity(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS);
        for column in 0..BLS_DORY_BLAKE3_MAIN_WIDTH {
            tables.push(main_rows.iter().map(|row| row[column]).collect());
        }
        for column in 0..BLS_DORY_BLAKE3_MAIN_WIDTH {
            tables.push(
                main_rows[1..]
                    .iter()
                    .chain(&main_rows[..1])
                    .map(|row| row[column])
                    .collect(),
            );
        }
        for column in 0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
            tables.push(preprocessed_rows.iter().map(|row| row[column]).collect());
        }
        for column in 0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
            tables.push(
                preprocessed_rows[1..]
                    .iter()
                    .chain(&preprocessed_rows[..1])
                    .map(|row| row[column])
                    .collect(),
            );
        }
        assert_eq!(tables.len(), BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS);
        tables
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_relation_value(
        terminal: &[BlsDoryFr],
        selectors: [BlsDoryFr; 3],
        coefficients: &[BlsDoryFr; 8],
        relation: &DenseExecutionRelation<'_>,
    ) -> BlsDoryFr {
        let main_next_start = BLS_DORY_BLAKE3_MAIN_WIDTH;
        let preprocessed_local_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
        let preprocessed_next_start = preprocessed_local_start + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH;
        let values = BlsDoryBlake3Evaluation {
            main_local: &terminal[..main_next_start],
            main_next: &terminal[main_next_start..preprocessed_local_start],
            preprocessed_local: &terminal[preprocessed_local_start..preprocessed_next_start],
            preprocessed_next: &terminal[preprocessed_next_start..],
            public: relation.public,
            periodic: &[],
            first_row: selectors[0],
            last_row: selectors[1],
            transition: selectors[2],
        };
        let mut mixed = relation
            .constraints
            .iter()
            .zip(relation.mixing_powers)
            .fold(BlsDoryFr::zero(), |sum, (constraint, coefficient)| {
                sum + constraint.evaluate(&values) * *coefficient
            });
        let native = native_evaluation_residuals_from_coefficients(
            &BlsDoryNativeEvaluationRow {
                main_local: values.main_local,
                main_next: values.main_next,
                first_row: values.first_row,
                last_row: values.last_row,
                transition: values.transition,
            },
            coefficients,
            relation.raw_evaluation,
        );
        for (residual, coefficient) in native
            .into_iter()
            .zip(&relation.mixing_powers[relation.constraints.len()..])
        {
            mixed = mixed + residual * *coefficient;
        }
        mixed
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_execution_transcript(
        bridge: &BlsDoryOutputBridgeStatement,
        commitments: &[BlsDoryGt],
    ) -> BlsDoryTranscript {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-execution-sumcheck");
        transcript.append_bytes(b"protocol-version", &1_u16.to_le_bytes());
        transcript.append_bytes(b"challenge-digest", &bridge.challenge_digest());
        transcript.append_bytes(
            b"activation-length",
            &(bridge.final_activation_len() as u64).to_le_bytes(),
        );
        transcript.append_bytes(b"activation-digest", &bridge.final_activation_digest());
        transcript.append_bytes(b"dory-binding", &bridge.transcript_binding());
        transcript.append_bytes(
            b"point-count",
            &(bridge.cell_point().len() as u64).to_le_bytes(),
        );
        for coordinate in bridge.cell_point() {
            transcript.append_field(b"dory-point", coordinate);
        }
        transcript.append_field(b"raw-evaluation", &bridge.raw_byte_evaluation());
        transcript.append_bytes(
            b"commitment-count",
            &(commitments.len() as u64).to_le_bytes(),
        );
        for commitment in commitments {
            transcript.append_group(b"packed-execution-commitment", commitment);
        }
        transcript
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_constraint_powers(transcript: &mut BlsDoryTranscript) -> Vec<BlsDoryFr> {
        let mixing = transcript.challenge_scalar(b"constraint-mixing");
        let mut powers = Vec::with_capacity(BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS);
        let mut power = BlsDoryFr::from_u64(1);
        for _ in 0..BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS {
            powers.push(power);
            power = power * mixing;
        }
        powers
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_cell_point(transcript: &mut BlsDoryTranscript, variables: usize) -> Vec<BlsDoryFr> {
        (0..variables)
            .map(|index| {
                transcript.append_bytes(b"cell-index", &(index as u64).to_le_bytes());
                transcript.challenge_scalar(b"cell-point")
            })
            .collect()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_absorb_round(
        transcript: &mut BlsDoryTranscript,
        round_index: usize,
        evaluations: &[BlsDoryFr],
    ) {
        transcript.append_bytes(b"round-index", &(round_index as u64).to_le_bytes());
        transcript.append_bytes(b"round-count", &(evaluations.len() as u64).to_le_bytes());
        for evaluation in evaluations {
            transcript.append_field(b"round-evaluation", evaluation);
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_absorb_terminal(transcript: &mut BlsDoryTranscript, terminal: &[BlsDoryFr]) {
        transcript.append_bytes(b"terminal-count", &(terminal.len() as u64).to_le_bytes());
        for evaluation in terminal {
            transcript.append_field(b"terminal-evaluation", evaluation);
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_interpolate(pair: &[BlsDoryFr], point: BlsDoryFr) -> BlsDoryFr {
        pair[0] + point * (pair[1] - pair[0])
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_fold(table: &[BlsDoryFr], point: BlsDoryFr) -> Vec<BlsDoryFr> {
        table
            .chunks_exact(2)
            .map(|pair| dense_interpolate(pair, point))
            .collect()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_equality_table(point: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
        let mut table = vec![BlsDoryFr::from_u64(1); 1usize << point.len()];
        let mut active = 1usize;
        for coordinate in point {
            for index in (0..active).rev() {
                let value = table[index];
                table[index] = value * (BlsDoryFr::from_u64(1) - *coordinate);
                table[index + active] = value * *coordinate;
            }
            active *= 2;
        }
        table
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_equality_evaluation(left: &[BlsDoryFr], right: &[BlsDoryFr]) -> BlsDoryFr {
        left.iter()
            .zip(right)
            .fold(BlsDoryFr::from_u64(1), |product, (left, right)| {
                product
                    * ((BlsDoryFr::from_u64(1) - *left) * (BlsDoryFr::from_u64(1) - *right)
                        + *left * *right)
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_evaluate_samples(values: &[BlsDoryFr], point: BlsDoryFr) -> BlsDoryFr {
        assert_eq!(values.len(), DENSE_EXECUTION_SUMCHECK_DEGREE + 1);
        values
            .iter()
            .copied()
            .enumerate()
            .fold(BlsDoryFr::zero(), |result, (index, value)| {
                let mut numerator = BlsDoryFr::from_u64(1);
                let mut denominator = BlsDoryFr::from_u64(1);
                for other in 0..values.len() {
                    if other != index {
                        numerator = numerator * (point - BlsDoryFr::from_u64(other as u64));
                        denominator =
                            denominator * BlsDoryFr::from_i64(index as i64 - other as i64);
                    }
                }
                result + value * numerator * denominator.inv().unwrap()
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_boolean_equality(index: usize, point: &[BlsDoryFr]) -> BlsDoryFr {
        point
            .iter()
            .enumerate()
            .fold(BlsDoryFr::from_u64(1), |weight, (variable, coordinate)| {
                if (index >> variable) & 1 == 1 {
                    weight * *coordinate
                } else {
                    weight * (BlsDoryFr::from_u64(1) - *coordinate)
                }
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_coefficient_terminal(
        air: &NarrowBlake3Air,
        dory_point: &[BlsDoryFr],
        sumcheck_point: &[BlsDoryFr],
    ) -> [BlsDoryFr; 8] {
        let mut terminal = [BlsDoryFr::zero(); 8];
        for row in 0..air.trace_rows() {
            let equality = dense_boolean_equality(row, sumcheck_point);
            let coefficients =
                native_byte_coefficients(air.activation_group_index_at_row(row), dory_point);
            for byte in 0..8 {
                terminal[byte] = terminal[byte] + equality * coefficients[byte];
            }
        }
        terminal
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_execution_sumcheck(
        tables: Vec<Vec<BlsDoryFr>>,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        commitments: &[BlsDoryGt],
    ) -> DenseExecutionSumcheckProof {
        let transcript = dense_execution_transcript(bridge, commitments);
        prove_dense_execution_sumcheck_with_transcript(
            tables,
            air,
            public,
            constraints,
            bridge,
            transcript,
        )
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_execution_sumcheck_with_transcript(
        mut tables: Vec<Vec<BlsDoryFr>>,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        mut transcript: BlsDoryTranscript,
    ) -> DenseExecutionSumcheckProof {
        assert_eq!(tables.len(), BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS);
        let rows = tables[0].len();
        assert!(rows.is_power_of_two());
        assert!(tables.iter().all(|table| table.len() == rows));
        assert_eq!(constraints.len() + 3, BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS);
        let variables = rows.ilog2() as usize;
        let mixing_powers = dense_constraint_powers(&mut transcript);
        let cell_point = dense_cell_point(&mut transcript, variables);
        let relation = DenseExecutionRelation {
            public,
            constraints,
            mixing_powers: &mixing_powers,
            raw_evaluation: bridge.raw_byte_evaluation(),
        };
        let mut equality = dense_equality_table(&cell_point);
        let mut first = vec![BlsDoryFr::zero(); rows];
        first[0] = BlsDoryFr::from_u64(1);
        let mut last = vec![BlsDoryFr::zero(); rows];
        last[rows - 1] = BlsDoryFr::from_u64(1);
        let mut transition = vec![BlsDoryFr::from_u64(1); rows];
        transition[rows - 1] = BlsDoryFr::zero();
        let mut byte_coefficients: [Vec<BlsDoryFr>; 8] = std::array::from_fn(|byte| {
            (0..rows)
                .map(|row| {
                    native_byte_coefficients(
                        air.activation_group_index_at_row(row),
                        bridge.cell_point(),
                    )[byte]
                })
                .collect()
        });
        let mut claim = BlsDoryFr::zero();
        let mut rounds = Vec::with_capacity(variables);
        for round_index in 0..variables {
            let pair_count = equality.len() / 2;
            let evaluations = (0..=DENSE_EXECUTION_SUMCHECK_DEGREE)
                .map(|sample| {
                    let sample = BlsDoryFr::from_u64(sample as u64);
                    (0..pair_count).fold(BlsDoryFr::zero(), |sum, pair| {
                        let offset = 2 * pair;
                        let terminal = tables
                            .iter()
                            .map(|table| dense_interpolate(&table[offset..offset + 2], sample))
                            .collect::<Vec<_>>();
                        let selectors = [
                            dense_interpolate(&first[offset..offset + 2], sample),
                            dense_interpolate(&last[offset..offset + 2], sample),
                            dense_interpolate(&transition[offset..offset + 2], sample),
                        ];
                        let coefficients = std::array::from_fn(|byte| {
                            dense_interpolate(&byte_coefficients[byte][offset..offset + 2], sample)
                        });
                        sum + dense_interpolate(&equality[offset..offset + 2], sample)
                            * dense_relation_value(&terminal, selectors, &coefficients, &relation)
                    })
                })
                .collect::<Vec<_>>();
            assert_eq!(evaluations[0] + evaluations[1], claim);
            dense_absorb_round(&mut transcript, round_index, &evaluations);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_samples(&evaluations, challenge);
            for table in &mut tables {
                *table = dense_fold(table, challenge);
            }
            equality = dense_fold(&equality, challenge);
            first = dense_fold(&first, challenge);
            last = dense_fold(&last, challenge);
            transition = dense_fold(&transition, challenge);
            for coefficients in &mut byte_coefficients {
                *coefficients = dense_fold(coefficients, challenge);
            }
            rounds.push(evaluations);
        }
        let terminal_evaluations = tables.iter().map(|table| table[0]).collect::<Vec<_>>();
        let selectors = [first[0], last[0], transition[0]];
        let coefficients = std::array::from_fn(|byte| byte_coefficients[byte][0]);
        assert_eq!(
            claim,
            equality[0]
                * dense_relation_value(&terminal_evaluations, selectors, &coefficients, &relation,)
        );
        dense_absorb_terminal(&mut transcript, &terminal_evaluations);
        DenseExecutionSumcheckProof {
            rounds,
            terminal_evaluations,
            transcript_digest: transcript.digest(),
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_execution_sumcheck(
        proof: &DenseExecutionSumcheckProof,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        commitments: &[BlsDoryGt],
    ) -> bool {
        let variables = air.trace_rows().ilog2() as usize;
        if proof.rounds.len() != variables
            || proof.terminal_evaluations.len() != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
            || proof
                .rounds
                .iter()
                .any(|round| round.len() != DENSE_EXECUTION_SUMCHECK_DEGREE + 1)
        {
            return false;
        }
        let mut transcript = dense_execution_transcript(bridge, commitments);
        let mixing_powers = dense_constraint_powers(&mut transcript);
        let cell_point = dense_cell_point(&mut transcript, variables);
        let relation = DenseExecutionRelation {
            public,
            constraints,
            mixing_powers: &mixing_powers,
            raw_evaluation: bridge.raw_byte_evaluation(),
        };
        let mut claim = BlsDoryFr::zero();
        let mut sumcheck_point = Vec::with_capacity(variables);
        for (round_index, round) in proof.rounds.iter().enumerate() {
            if round[0] + round[1] != claim {
                return false;
            }
            dense_absorb_round(&mut transcript, round_index, round);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_samples(round, challenge);
            sumcheck_point.push(challenge);
        }
        let first = sumcheck_point
            .iter()
            .fold(BlsDoryFr::from_u64(1), |value, coordinate| {
                value * (BlsDoryFr::from_u64(1) - *coordinate)
            });
        let last = sumcheck_point
            .iter()
            .fold(BlsDoryFr::from_u64(1), |value, coordinate| {
                value * *coordinate
            });
        let selectors = [first, last, BlsDoryFr::from_u64(1) - last];
        let coefficients = dense_coefficient_terminal(air, bridge.cell_point(), &sumcheck_point);
        if claim
            != dense_equality_evaluation(&cell_point, &sumcheck_point)
                * dense_relation_value(
                    &proof.terminal_evaluations,
                    selectors,
                    &coefficients,
                    &relation,
                )
        {
            return false;
        }
        dense_absorb_terminal(&mut transcript, &proof.terminal_evaluations);
        transcript.digest() == proof.transcript_digest
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_source_tables(execution_tables: &[Vec<BlsDoryFr>]) -> Vec<Vec<BlsDoryFr>> {
        assert_eq!(
            execution_tables.len(),
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
        );
        execution_tables[..2 * BLS_DORY_BLAKE3_MAIN_WIDTH].to_vec()
    }

    #[cfg(feature = "whir-prototype")]
    fn synthetic_dense_adjacency_tables(rows: usize) -> Vec<Vec<BlsDoryFr>> {
        assert!(rows.is_power_of_two());
        let local = (0..BLS_DORY_BLAKE3_MAIN_WIDTH)
            .map(|column| {
                (0..rows)
                    .map(|row| {
                        BlsDoryFr::from_u64(
                            1 + row as u64 * BLS_DORY_BLAKE3_MAIN_WIDTH as u64 + column as u64,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut tables = Vec::with_capacity(2 * BLS_DORY_BLAKE3_MAIN_WIDTH);
        tables.extend(local.iter().cloned());
        tables.extend(
            local
                .iter()
                .map(|table| table[1..].iter().chain(&table[..1]).copied().collect()),
        );
        tables
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_transcript(
        bridge: &BlsDoryOutputBridgeStatement,
        trace_rows: usize,
        source_commitments: &[BlsDoryGt],
    ) -> BlsDoryTranscript {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-row-adjacency-sumcheck");
        transcript.append_bytes(b"protocol-version", &1_u16.to_le_bytes());
        transcript.append_bytes(b"challenge-digest", &bridge.challenge_digest());
        transcript.append_bytes(
            b"activation-length",
            &(bridge.final_activation_len() as u64).to_le_bytes(),
        );
        transcript.append_bytes(b"activation-digest", &bridge.final_activation_digest());
        transcript.append_bytes(b"dory-binding", &bridge.transcript_binding());
        transcript.append_bytes(b"trace-rows", &(trace_rows as u64).to_le_bytes());
        transcript.append_bytes(
            b"main-width",
            &(BLS_DORY_BLAKE3_MAIN_WIDTH as u64).to_le_bytes(),
        );
        transcript.append_bytes(
            b"source-commitment-count",
            &(source_commitments.len() as u64).to_le_bytes(),
        );
        for commitment in source_commitments {
            transcript.append_group(b"packed-adjacency-source-commitment", commitment);
        }
        transcript
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_key(
        values: impl IntoIterator<Item = BlsDoryFr>,
        row_label: BlsDoryFr,
        compression: BlsDoryFr,
    ) -> BlsDoryFr {
        values
            .into_iter()
            .fold(row_label, |key, value| key * compression + value)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_relation(
        terminal: &[BlsDoryFr],
        row_index: BlsDoryFr,
        first_row: BlsDoryFr,
        equality: BlsDoryFr,
        relation: DenseAdjacencyRelation,
    ) -> BlsDoryFr {
        let next_start = BLS_DORY_BLAKE3_MAIN_WIDTH;
        let inverse_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
        assert_eq!(terminal.len(), inverse_start + 2);
        let local_key = dense_adjacency_key(
            terminal[..next_start].iter().copied(),
            row_index - BlsDoryFr::from_u64(1) + relation.trace_rows * first_row,
            relation.compression,
        );
        let next_key = dense_adjacency_key(
            terminal[next_start..inverse_start].iter().copied(),
            row_index,
            relation.compression,
        );
        let local_inverse = terminal[inverse_start];
        let next_inverse = terminal[inverse_start + 1];
        let local_constraint =
            local_inverse * (relation.alpha - local_key) - BlsDoryFr::from_u64(1);
        let next_constraint = next_inverse * (relation.alpha - next_key) - BlsDoryFr::from_u64(1);
        equality
            * (relation.local_mixing[0] * local_constraint
                + relation.local_mixing[1] * next_constraint)
            + relation.rational_mixing * (next_inverse - local_inverse)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_inverse_tables(
        source_tables: &[Vec<BlsDoryFr>],
        compression: BlsDoryFr,
        alpha: BlsDoryFr,
    ) -> Option<[Vec<BlsDoryFr>; 2]> {
        if source_tables.len() != 2 * BLS_DORY_BLAKE3_MAIN_WIDTH || source_tables.is_empty() {
            return None;
        }
        let rows = source_tables[0].len();
        if !rows.is_power_of_two() || source_tables.iter().any(|table| table.len() != rows) {
            return None;
        }
        let mut local_inverse = Vec::with_capacity(rows);
        let mut next_inverse = Vec::with_capacity(rows);
        for row in 0..rows {
            let first = u64::from(row == 0);
            let local_label = row as u64 - u64::from(row != 0) + (rows as u64 - 1) * first;
            let local_key = dense_adjacency_key(
                source_tables[..BLS_DORY_BLAKE3_MAIN_WIDTH]
                    .iter()
                    .map(|table| table[row]),
                BlsDoryFr::from_u64(local_label),
                compression,
            );
            let next_key = dense_adjacency_key(
                source_tables[BLS_DORY_BLAKE3_MAIN_WIDTH..]
                    .iter()
                    .map(|table| table[row]),
                BlsDoryFr::from_u64(row as u64),
                compression,
            );
            local_inverse.push((alpha - local_key).inv()?);
            next_inverse.push((alpha - next_key).inv()?);
        }
        Some([local_inverse, next_inverse])
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_evaluate_adjacency_samples(values: &[BlsDoryFr], point: BlsDoryFr) -> BlsDoryFr {
        assert_eq!(values.len(), DENSE_ADJACENCY_SUMCHECK_DEGREE + 1);
        values
            .iter()
            .copied()
            .enumerate()
            .fold(BlsDoryFr::zero(), |result, (index, value)| {
                let mut numerator = BlsDoryFr::from_u64(1);
                let mut denominator = BlsDoryFr::from_u64(1);
                for other in 0..values.len() {
                    if other != index {
                        numerator = numerator * (point - BlsDoryFr::from_u64(other as u64));
                        denominator =
                            denominator * BlsDoryFr::from_i64(index as i64 - other as i64);
                    }
                }
                result + value * numerator * denominator.inv().unwrap()
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_row_index_evaluation(point: &[BlsDoryFr]) -> BlsDoryFr {
        point
            .iter()
            .enumerate()
            .fold(BlsDoryFr::zero(), |value, (variable, coordinate)| {
                value + BlsDoryFr::from_u64(1_u64 << variable) * *coordinate
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_adjacency_sumcheck(
        source_tables: Vec<Vec<BlsDoryFr>>,
        bridge: &BlsDoryOutputBridgeStatement,
        source_commitments: &[BlsDoryGt],
        inverse_commitments: &[BlsDoryGt],
    ) -> Option<DenseAdjacencySumcheckProof> {
        let rows = source_tables.first()?.len();
        let transcript = dense_adjacency_transcript(bridge, rows, source_commitments);
        prove_dense_adjacency_sumcheck_with_transcript(
            source_tables,
            inverse_commitments,
            transcript,
            false,
        )
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_adjacency_sumcheck_with_transcript(
        mut source_tables: Vec<Vec<BlsDoryFr>>,
        inverse_commitments: &[BlsDoryGt],
        mut transcript: BlsDoryTranscript,
        named_inverse: bool,
    ) -> Option<DenseAdjacencySumcheckProof> {
        let rows = source_tables.first()?.len();
        if source_tables.len() != 2 * BLS_DORY_BLAKE3_MAIN_WIDTH
            || !rows.is_power_of_two()
            || source_tables.iter().any(|table| table.len() != rows)
        {
            return None;
        }
        let variables = rows.ilog2() as usize;
        let compression = transcript.challenge_scalar(b"row-compression");
        let alpha = transcript.challenge_scalar(b"lookup-alpha");
        let inverses = dense_adjacency_inverse_tables(&source_tables, compression, alpha)?;
        source_tables.extend(inverses);
        if named_inverse {
            let [inverse_commitment] = inverse_commitments else {
                return None;
            };
            transcript.append_bytes(b"inverse-source-count", &1_u64.to_le_bytes());
            append_native_blake3_source_descriptor(
                &mut transcript,
                BlsDoryBlake3SourceRole::Inverse,
                BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES,
                inverse_commitment,
            );
        } else {
            transcript.append_bytes(
                b"inverse-commitment-count",
                &(inverse_commitments.len() as u64).to_le_bytes(),
            );
            for commitment in inverse_commitments {
                transcript.append_group(b"packed-adjacency-inverse-commitment", commitment);
            }
        }
        let local_mixing = [
            transcript.challenge_scalar(b"local-mixing"),
            transcript.challenge_scalar(b"local-mixing"),
        ];
        let rational_mixing = transcript.challenge_scalar(b"rational-mixing");
        let equality_point = dense_cell_point(&mut transcript, variables);
        let relation = DenseAdjacencyRelation {
            trace_rows: BlsDoryFr::from_u64(rows as u64),
            compression,
            alpha,
            local_mixing,
            rational_mixing,
        };
        let mut equality = dense_equality_table(&equality_point);
        let mut row_index = (0..rows)
            .map(|row| BlsDoryFr::from_u64(row as u64))
            .collect::<Vec<_>>();
        let mut first = vec![BlsDoryFr::zero(); rows];
        first[0] = BlsDoryFr::from_u64(1);
        let mut claim = BlsDoryFr::zero();
        let mut rounds = Vec::with_capacity(variables);
        for round_index in 0..variables {
            let pair_count = equality.len() / 2;
            let evaluations = (0..=DENSE_ADJACENCY_SUMCHECK_DEGREE)
                .map(|sample| {
                    let sample = BlsDoryFr::from_u64(sample as u64);
                    (0..pair_count).fold(BlsDoryFr::zero(), |sum, pair| {
                        let offset = 2 * pair;
                        let terminal = source_tables
                            .iter()
                            .map(|table| dense_interpolate(&table[offset..offset + 2], sample))
                            .collect::<Vec<_>>();
                        sum + dense_adjacency_relation(
                            &terminal,
                            dense_interpolate(&row_index[offset..offset + 2], sample),
                            dense_interpolate(&first[offset..offset + 2], sample),
                            dense_interpolate(&equality[offset..offset + 2], sample),
                            relation,
                        )
                    })
                })
                .collect::<Vec<_>>();
            if evaluations[0] + evaluations[1] != claim {
                return None;
            }
            dense_absorb_round(&mut transcript, round_index, &evaluations);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_adjacency_samples(&evaluations, challenge);
            for table in &mut source_tables {
                *table = dense_fold(table, challenge);
            }
            equality = dense_fold(&equality, challenge);
            row_index = dense_fold(&row_index, challenge);
            first = dense_fold(&first, challenge);
            rounds.push(evaluations);
        }
        let terminal_evaluations = source_tables
            .iter()
            .map(|table| table[0])
            .collect::<Vec<_>>();
        if claim
            != dense_adjacency_relation(
                &terminal_evaluations,
                row_index[0],
                first[0],
                equality[0],
                relation,
            )
        {
            return None;
        }
        dense_absorb_terminal(&mut transcript, &terminal_evaluations);
        Some(DenseAdjacencySumcheckProof {
            rounds,
            terminal_evaluations,
            transcript_digest: transcript.digest(),
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_adjacency_sumcheck(
        proof: &DenseAdjacencySumcheckProof,
        trace_rows: usize,
        bridge: &BlsDoryOutputBridgeStatement,
        source_commitments: &[BlsDoryGt],
        inverse_commitments: &[BlsDoryGt],
    ) -> bool {
        if !trace_rows.is_power_of_two()
            || proof.rounds.len() != trace_rows.ilog2() as usize
            || proof.terminal_evaluations.len() != BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS
            || proof
                .rounds
                .iter()
                .any(|round| round.len() != DENSE_ADJACENCY_SUMCHECK_DEGREE + 1)
        {
            return false;
        }
        let variables = trace_rows.ilog2() as usize;
        let mut transcript = dense_adjacency_transcript(bridge, trace_rows, source_commitments);
        let compression = transcript.challenge_scalar(b"row-compression");
        let alpha = transcript.challenge_scalar(b"lookup-alpha");
        transcript.append_bytes(
            b"inverse-commitment-count",
            &(inverse_commitments.len() as u64).to_le_bytes(),
        );
        for commitment in inverse_commitments {
            transcript.append_group(b"packed-adjacency-inverse-commitment", commitment);
        }
        let local_mixing = [
            transcript.challenge_scalar(b"local-mixing"),
            transcript.challenge_scalar(b"local-mixing"),
        ];
        let rational_mixing = transcript.challenge_scalar(b"rational-mixing");
        let equality_point = dense_cell_point(&mut transcript, variables);
        let relation = DenseAdjacencyRelation {
            trace_rows: BlsDoryFr::from_u64(trace_rows as u64),
            compression,
            alpha,
            local_mixing,
            rational_mixing,
        };
        let mut claim = BlsDoryFr::zero();
        let mut sumcheck_point = Vec::with_capacity(variables);
        for (round_index, evaluations) in proof.rounds.iter().enumerate() {
            if evaluations[0] + evaluations[1] != claim {
                return false;
            }
            dense_absorb_round(&mut transcript, round_index, evaluations);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_adjacency_samples(evaluations, challenge);
            sumcheck_point.push(challenge);
        }
        let first = sumcheck_point
            .iter()
            .fold(BlsDoryFr::from_u64(1), |value, coordinate| {
                value * (BlsDoryFr::from_u64(1) - *coordinate)
            });
        let expected = dense_adjacency_relation(
            &proof.terminal_evaluations,
            dense_adjacency_row_index_evaluation(&sumcheck_point),
            first,
            dense_equality_evaluation(&equality_point, &sumcheck_point),
            relation,
        );
        if claim != expected {
            return false;
        }
        dense_absorb_terminal(&mut transcript, &proof.terminal_evaluations);
        transcript.digest() == proof.transcript_digest
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_replay_adjacency_point(
        proof: &DenseAdjacencySumcheckProof,
        trace_rows: usize,
        bridge: &BlsDoryOutputBridgeStatement,
        source_commitments: &[BlsDoryGt],
        inverse_commitments: &[BlsDoryGt],
    ) -> Option<Vec<BlsDoryFr>> {
        if !trace_rows.is_power_of_two()
            || proof.rounds.len() != trace_rows.ilog2() as usize
            || proof
                .rounds
                .iter()
                .any(|round| round.len() != DENSE_ADJACENCY_SUMCHECK_DEGREE + 1)
        {
            return None;
        }
        let mut transcript = dense_adjacency_transcript(bridge, trace_rows, source_commitments);
        transcript.challenge_scalar(b"row-compression");
        transcript.challenge_scalar(b"lookup-alpha");
        transcript.append_bytes(
            b"inverse-commitment-count",
            &(inverse_commitments.len() as u64).to_le_bytes(),
        );
        for commitment in inverse_commitments {
            transcript.append_group(b"packed-adjacency-inverse-commitment", commitment);
        }
        transcript.challenge_scalar(b"local-mixing");
        transcript.challenge_scalar(b"local-mixing");
        transcript.challenge_scalar(b"rational-mixing");
        dense_cell_point(&mut transcript, proof.rounds.len());
        let mut claim = BlsDoryFr::zero();
        let mut point = Vec::with_capacity(proof.rounds.len());
        for (round_index, round) in proof.rounds.iter().enumerate() {
            if round[0] + round[1] != claim {
                return None;
            }
            dense_absorb_round(&mut transcript, round_index, round);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_adjacency_samples(round, challenge);
            point.push(challenge);
        }
        Some(point)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_pack_adjacency_tables(
        tables: &[Vec<BlsDoryFr>],
        rows: usize,
        slots: usize,
    ) -> Option<Vec<BlsDoryFr>> {
        if tables.is_empty()
            || tables.len() > slots
            || tables.iter().any(|table| table.len() != rows)
        {
            return None;
        }
        let mut packed = Vec::with_capacity(rows.checked_mul(slots)?);
        for slot in 0..slots {
            if let Some(table) = tables.get(slot) {
                packed.extend_from_slice(table);
            } else {
                packed.resize(packed.len().checked_add(rows)?, BlsDoryFr::zero());
            }
        }
        Some(packed)
    }

    #[cfg(feature = "whir-prototype")]
    struct DensePackedTableRowSource<'a> {
        tables: &'a [Vec<BlsDoryFr>],
        trace_rows: usize,
        selector_slots: usize,
        reads: usize,
        fail_at: Option<usize>,
        short_at: Option<usize>,
    }

    #[cfg(feature = "whir-prototype")]
    impl<'a> DensePackedTableRowSource<'a> {
        fn new(tables: &'a [Vec<BlsDoryFr>], trace_rows: usize, selector_slots: usize) -> Self {
            Self {
                tables,
                trace_rows,
                selector_slots,
                reads: 0,
                fail_at: None,
                short_at: None,
            }
        }
    }

    #[cfg(feature = "whir-prototype")]
    impl BlsDoryRowSource for DensePackedTableRowSource<'_> {
        type Error = ();

        fn rows(&self) -> usize {
            self.selector_slots
        }

        fn columns(&self) -> usize {
            self.trace_rows
        }

        fn explicit_scalar_count(&self) -> usize {
            self.tables.len().saturating_mul(self.trace_rows)
        }

        fn read_row(
            &mut self,
            row_index: usize,
            output: &mut [BlsDoryFr],
        ) -> Result<usize, Self::Error> {
            if self.fail_at == Some(row_index) {
                return Err(());
            }
            let table = self.tables.get(row_index).ok_or(())?;
            if output.len() != self.trace_rows || table.len() != self.trace_rows {
                return Err(());
            }
            output.copy_from_slice(table);
            self.reads += 1;
            Ok(if self.short_at == Some(row_index) {
                output.len() - 1
            } else {
                output.len()
            })
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn flip_file_byte(path: &std::path::Path, offset: u64) -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let mut byte = [0u8; 1];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut byte)?;
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&byte)?;
        file.flush()
    }

    fn blake3_opening_replay(
        points: &[Vec<BlsDoryFr>],
        evaluations: &[BlsDoryFr],
    ) -> BlsDoryBlake3OpeningReplay {
        assert_eq!(points.len(), BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES.len());
        assert_eq!(
            evaluations.len(),
            BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES.len()
        );
        BlsDoryBlake3OpeningReplay {
            execution_points: [points[0].clone(), points[1].clone(), points[2].clone()],
            execution_evaluations: [evaluations[0], evaluations[1], evaluations[2]],
            adjacency_points: [points[3].clone(), points[4].clone(), points[5].clone()],
            adjacency_evaluations: [evaluations[3], evaluations[4], evaluations[5]],
            opening_binding: [0u8; 32],
        }
    }

    #[cfg(feature = "whir-prototype")]
    struct DensePackedCodeRowSource<'a> {
        tables: &'a [Vec<u8>],
        trace_rows: usize,
        selector_slots: usize,
        dictionary: Vec<BlsDoryFr>,
    }

    #[cfg(feature = "whir-prototype")]
    impl BlsDoryCompactRowSource for DensePackedCodeRowSource<'_> {
        type Error = ();

        fn rows(&self) -> usize {
            self.selector_slots
        }

        fn columns(&self) -> usize {
            self.trace_rows
        }

        fn explicit_scalar_count(&self) -> usize {
            self.tables.len().saturating_mul(self.trace_rows)
        }

        fn word_scalar_count(&self) -> usize {
            0
        }

        fn code_bits(&self) -> u8 {
            4
        }

        fn word_group_len(&self) -> usize {
            self.trace_rows
        }

        fn signed_word_selectors(&self) -> u64 {
            0
        }

        fn dictionary(&self) -> &[BlsDoryFr] {
            &self.dictionary
        }

        fn read_word_row(
            &mut self,
            _row_index: usize,
            _output: &mut [u64],
        ) -> Result<usize, Self::Error> {
            Err(())
        }

        fn read_code_row(
            &mut self,
            row_index: usize,
            output: &mut [u8],
        ) -> Result<usize, Self::Error> {
            let table = self.tables.get(row_index).ok_or(())?;
            if output.len() != self.trace_rows || table.len() != self.trace_rows {
                return Err(());
            }
            output.copy_from_slice(table);
            Ok(output.len())
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_opening_selector_points(
        sumcheck_digest: [u8; 32],
        batches: &[DenseAdjacencyOpeningBatch],
    ) -> (Vec<Vec<BlsDoryFr>>, [u8; 32]) {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-adjacency-opening-selectors");
        transcript.append_bytes(b"sumcheck-digest", &sumcheck_digest);
        transcript.append_bytes(b"batch-count", &(batches.len() as u64).to_le_bytes());
        let points = batches
            .iter()
            .enumerate()
            .map(|(batch_index, batch)| {
                transcript.append_bytes(b"batch-index", &(batch_index as u64).to_le_bytes());
                transcript.append_bytes(
                    b"terminal-start",
                    &(batch.terminal_start as u64).to_le_bytes(),
                );
                transcript.append_bytes(
                    b"terminal-count",
                    &(batch.terminal_count as u64).to_le_bytes(),
                );
                transcript.append_bytes(
                    b"selector-variables",
                    &(batch.selector_variables as u64).to_le_bytes(),
                );
                transcript.append_group(b"packed-adjacency-commitment", &batch.commitment);
                (0..batch.selector_variables)
                    .map(|selector| {
                        transcript
                            .append_bytes(b"selector-index", &(selector as u64).to_le_bytes());
                        transcript.challenge_scalar(b"opening-selector")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        (points, transcript.digest())
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_authenticated_adjacency(
        source_tables: Vec<Vec<BlsDoryFr>>,
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<DenseAuthenticatedAdjacencyProof, BlsDoryAggregateError> {
        const ROWS: usize = 1 << 4;
        const SELECTOR_VARIABLES: usize = 12;
        const SLOTS: usize = 1 << SELECTOR_VARIABLES;
        if source_tables.len() != 2 * BLS_DORY_BLAKE3_MAIN_WIDTH
            || source_tables.iter().any(|table| table.len() != ROWS)
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let source = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&source_tables, ROWS, SLOTS)
                .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?,
            8,
            8,
            setup,
        )?;
        let source_commitments = [source.commitment()];
        let mut challenge_transcript =
            dense_adjacency_transcript(bridge, ROWS, &source_commitments);
        let compression = challenge_transcript.challenge_scalar(b"row-compression");
        let alpha = challenge_transcript.challenge_scalar(b"lookup-alpha");
        let inverse_tables = dense_adjacency_inverse_tables(&source_tables, compression, alpha)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let inverse = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&inverse_tables, ROWS, SLOTS)
                .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?,
            8,
            8,
            setup,
        )?;
        let inverse_commitments = [inverse.commitment()];
        let sumcheck = prove_dense_adjacency_sumcheck(
            source_tables,
            bridge,
            &source_commitments,
            &inverse_commitments,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let sumcheck_point = dense_replay_adjacency_point(
            &sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let opening_batches = vec![
            DenseAdjacencyOpeningBatch {
                commitment: source_commitments[0],
                terminal_start: 0,
                terminal_count: 2 * BLS_DORY_BLAKE3_MAIN_WIDTH,
                selector_variables: SELECTOR_VARIABLES,
            },
            DenseAdjacencyOpeningBatch {
                commitment: inverse_commitments[0],
                terminal_start: 2 * BLS_DORY_BLAKE3_MAIN_WIDTH,
                terminal_count: 2,
                selector_variables: SELECTOR_VARIABLES,
            },
        ];
        let (selector_points, opening_binding) =
            dense_adjacency_opening_selector_points(sumcheck.transcript_digest, &opening_batches);
        let points = selector_points
            .iter()
            .map(|selector| dense_opening_point(&sumcheck_point, selector))
            .collect::<Vec<_>>();
        let openings = BlsDoryDeferredOpeningSet::new(vec![source, inverse], vec![0, 1], points)?;
        for ((claim, selector), batch) in openings
            .claims()
            .iter()
            .zip(&selector_points)
            .zip(&opening_batches)
        {
            let terminal_end = batch.terminal_start + batch.terminal_count;
            let expected = dense_terminal_selector_evaluation(
                &sumcheck.terminal_evaluations[batch.terminal_start..terminal_end],
                selector,
            );
            if claim.evaluation != expected {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
        }
        let (_, opening_proof) = prove_bls_dory_deferred_opening_sets(
            &opening_binding,
            dense_aggregate_layout(),
            &[&openings],
            setup,
        )?;
        Ok(DenseAuthenticatedAdjacencyProof {
            sumcheck,
            opening_batches,
            opening_proof,
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_authenticated_adjacency(
        proof: &DenseAuthenticatedAdjacencyProof,
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> bool {
        const ROWS: usize = 1 << 4;
        const SELECTOR_VARIABLES: usize = 12;
        let expected = [
            (0, 2 * BLS_DORY_BLAKE3_MAIN_WIDTH),
            (2 * BLS_DORY_BLAKE3_MAIN_WIDTH, 2),
        ];
        if proof.opening_batches.len() != expected.len()
            || proof.opening_proof.is_empty()
            || proof
                .opening_batches
                .iter()
                .zip(expected)
                .any(|(batch, (start, count))| {
                    batch.terminal_start != start
                        || batch.terminal_count != count
                        || batch.selector_variables != SELECTOR_VARIABLES
                })
        {
            return false;
        }
        let source_commitments = [proof.opening_batches[0].commitment];
        let inverse_commitments = [proof.opening_batches[1].commitment];
        if !verify_dense_adjacency_sumcheck(
            &proof.sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        ) {
            return false;
        }
        let Some(sumcheck_point) = dense_replay_adjacency_point(
            &proof.sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        ) else {
            return false;
        };
        let (selector_points, opening_binding) = dense_adjacency_opening_selector_points(
            proof.sumcheck.transcript_digest,
            &proof.opening_batches,
        );
        let claims = proof
            .opening_batches
            .iter()
            .zip(&selector_points)
            .map(|(batch, selector)| {
                let terminal_end = batch.terminal_start + batch.terminal_count;
                BlsDoryOpeningClaim {
                    commitment: batch.commitment,
                    point: dense_opening_point(&sumcheck_point, selector),
                    evaluation: dense_terminal_selector_evaluation(
                        &proof.sumcheck.terminal_evaluations[batch.terminal_start..terminal_end],
                        selector,
                    ),
                }
            })
            .collect::<Vec<_>>();
        verify_bls_dory_openings(
            &opening_binding,
            dense_aggregate_layout(),
            &claims,
            &proof.opening_proof,
            setup,
        )
        .is_ok()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_replay_sumcheck_point(
        proof: &DenseExecutionSumcheckProof,
        bridge: &BlsDoryOutputBridgeStatement,
        commitments: &[BlsDoryGt],
    ) -> Option<Vec<BlsDoryFr>> {
        let variables = proof.rounds.len();
        if variables == 0
            || proof
                .rounds
                .iter()
                .any(|round| round.len() != DENSE_EXECUTION_SUMCHECK_DEGREE + 1)
        {
            return None;
        }
        let mut transcript = dense_execution_transcript(bridge, commitments);
        dense_constraint_powers(&mut transcript);
        dense_cell_point(&mut transcript, variables);
        let mut claim = BlsDoryFr::zero();
        let mut point = Vec::with_capacity(variables);
        for (round_index, round) in proof.rounds.iter().enumerate() {
            if round[0] + round[1] != claim {
                return None;
            }
            dense_absorb_round(&mut transcript, round_index, round);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_samples(round, challenge);
            point.push(challenge);
        }
        Some(point)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_opening_point(
        sumcheck_point: &[BlsDoryFr],
        selector_point: &[BlsDoryFr],
    ) -> Vec<BlsDoryFr> {
        let mut point = Vec::with_capacity(16);
        point.extend_from_slice(sumcheck_point);
        point.extend_from_slice(selector_point);
        assert_eq!(point.len(), 16);
        point
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_terminal_selector_evaluation(
        terminal: &[BlsDoryFr],
        selector_point: &[BlsDoryFr],
    ) -> BlsDoryFr {
        assert!(terminal.len() <= 1usize << selector_point.len());
        let mut table = terminal.to_vec();
        table.resize(1usize << selector_point.len(), BlsDoryFr::zero());
        for coordinate in selector_point {
            table = dense_fold(&table, *coordinate);
        }
        assert_eq!(table.len(), 1);
        table[0]
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_execution_batch_selector_evaluation(
        terminal: &[BlsDoryFr],
        batch_index: usize,
        selector_point: &[BlsDoryFr],
    ) -> Option<BlsDoryFr> {
        if terminal.len() != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
            || selector_point.len() != 8
        {
            return None;
        }
        match batch_index {
            0 => Some(dense_terminal_selector_evaluation(
                &terminal[..256],
                selector_point,
            )),
            1 => Some(dense_terminal_selector_evaluation(
                &terminal[256..512],
                selector_point,
            )),
            2 => Some(dense_terminal_selector_evaluation(
                &terminal[512..2 * BLS_DORY_BLAKE3_MAIN_WIDTH],
                selector_point,
            )),
            3 => {
                let preprocessed_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
                let mut physical = Vec::with_capacity(2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH);
                for physical_slot in 0..2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
                    let logical = preprocessed_physical_terminal_index(physical_slot)?;
                    physical.push(terminal[preprocessed_start + logical]);
                }
                Some(dense_terminal_selector_evaluation(
                    &physical,
                    selector_point,
                ))
            }
            _ => None,
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_opening_selector_points(
        sumcheck_digest: [u8; 32],
        batches: &[DenseExecutionOpeningBatch],
    ) -> (Vec<Vec<BlsDoryFr>>, [u8; 32]) {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-execution-opening-selectors");
        transcript.append_bytes(b"sumcheck-digest", &sumcheck_digest);
        transcript.append_bytes(b"batch-count", &(batches.len() as u64).to_le_bytes());
        let points = batches
            .iter()
            .enumerate()
            .map(|(batch_index, batch)| {
                transcript.append_bytes(b"batch-index", &(batch_index as u64).to_le_bytes());
                transcript.append_bytes(
                    b"terminal-count",
                    &(batch.terminal_count as u64).to_le_bytes(),
                );
                transcript.append_group(b"packed-execution-commitment", &batch.commitment);
                (0..8)
                    .map(|selector| {
                        transcript
                            .append_bytes(b"selector-index", &(selector as u64).to_le_bytes());
                        transcript.challenge_scalar(b"opening-selector")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        (points, transcript.digest())
    }

    #[cfg(feature = "whir-prototype")]
    fn commit_dense_execution_batches(
        tables: &[Vec<BlsDoryFr>],
        setup: &DeterministicBlsDorySetup,
    ) -> Result<
        (
            Vec<BlsDoryCommittedPolynomial>,
            Vec<DenseExecutionOpeningBatch>,
        ),
        BlsDoryAggregateError,
    > {
        const ROWS: usize = 1 << 8;
        const PACKED_SLOTS: usize = 1 << 8;
        if tables.len() != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
            || tables.iter().any(|table| table.len() != ROWS)
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let mut committed_batches = Vec::new();
        let mut opening_batches = Vec::new();
        let main_terminals = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
        for batch in tables[..main_terminals].chunks(PACKED_SLOTS) {
            let packed = dense_pack_adjacency_tables(batch, ROWS, PACKED_SLOTS)
                .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
            let committed = commit_bls_dory_polynomial(packed, 8, 8, setup)?;
            opening_batches.push(DenseExecutionOpeningBatch {
                commitment: committed.commitment(),
                terminal_count: batch.len(),
            });
            committed_batches.push(committed);
        }
        let mut packed_preprocessed = Vec::with_capacity(ROWS * PACKED_SLOTS);
        for physical_slot in 0..PACKED_SLOTS {
            if physical_slot < 2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
                let logical = preprocessed_physical_terminal_index(physical_slot)
                    .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
                packed_preprocessed.extend_from_slice(&tables[main_terminals + logical]);
            } else {
                packed_preprocessed.resize(packed_preprocessed.len() + ROWS, BlsDoryFr::zero());
            }
        }
        let committed = commit_bls_dory_polynomial(packed_preprocessed, 8, 8, setup)?;
        opening_batches.push(DenseExecutionOpeningBatch {
            commitment: committed.commitment(),
            terminal_count: 2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
        });
        committed_batches.push(committed);
        debug_assert_eq!(
            opening_batches
                .iter()
                .map(|batch| batch.terminal_count)
                .collect::<Vec<_>>(),
            DENSE_EXECUTION_BATCH_TERMINAL_COUNTS
        );
        Ok((committed_batches, opening_batches))
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_authenticated_execution(
        tables: Vec<Vec<BlsDoryFr>>,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<DenseAuthenticatedExecutionProof, BlsDoryAggregateError> {
        let (committed_batches, opening_batches) = commit_dense_execution_batches(&tables, setup)?;
        let commitments = opening_batches
            .iter()
            .map(|batch| batch.commitment)
            .collect::<Vec<_>>();
        let sumcheck =
            prove_dense_execution_sumcheck(tables, air, public, constraints, bridge, &commitments);
        let sumcheck_point = dense_replay_sumcheck_point(&sumcheck, bridge, &commitments)
            .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let (selector_points, opening_binding) =
            dense_opening_selector_points(sumcheck.transcript_digest, &opening_batches);
        let points = selector_points
            .iter()
            .map(|selector| dense_opening_point(&sumcheck_point, selector))
            .collect::<Vec<_>>();
        let openings = BlsDoryDeferredOpeningSet::new(
            committed_batches,
            (0..opening_batches.len()).collect(),
            points,
        )?;
        for (batch_index, ((claim, selector), batch)) in openings
            .claims()
            .iter()
            .zip(&selector_points)
            .zip(&opening_batches)
            .enumerate()
        {
            if batch.terminal_count != DENSE_EXECUTION_BATCH_TERMINAL_COUNTS[batch_index] {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
            let expected = dense_execution_batch_selector_evaluation(
                &sumcheck.terminal_evaluations,
                batch_index,
                selector,
            )
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
            if claim.evaluation != expected {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
        }
        let (_, opening_proof) = prove_bls_dory_deferred_opening_sets(
            &opening_binding,
            dense_aggregate_layout(),
            &[&openings],
            setup,
        )?;
        Ok(DenseAuthenticatedExecutionProof {
            sumcheck,
            opening_batches,
            opening_proof,
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_authenticated_execution(
        proof: &DenseAuthenticatedExecutionProof,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        expected_preprocessed_commitment: BlsDoryGt,
        setup: &DeterministicBlsDorySetup,
    ) -> bool {
        if proof.opening_batches.len() != DENSE_EXECUTION_BATCH_TERMINAL_COUNTS.len()
            || proof.opening_proof.is_empty()
            || proof.opening_batches[3].commitment != expected_preprocessed_commitment
        {
            return false;
        }
        let commitments = proof
            .opening_batches
            .iter()
            .map(|batch| batch.commitment)
            .collect::<Vec<_>>();
        if !verify_dense_execution_sumcheck(
            &proof.sumcheck,
            air,
            public,
            constraints,
            bridge,
            &commitments,
        ) {
            return false;
        }
        let Some(sumcheck_point) =
            dense_replay_sumcheck_point(&proof.sumcheck, bridge, &commitments)
        else {
            return false;
        };
        let (selector_points, opening_binding) =
            dense_opening_selector_points(proof.sumcheck.transcript_digest, &proof.opening_batches);
        let mut claims = Vec::with_capacity(DENSE_EXECUTION_BATCH_TERMINAL_COUNTS.len());
        for (batch_index, ((batch, selector), expected_count)) in proof
            .opening_batches
            .iter()
            .zip(&selector_points)
            .zip(DENSE_EXECUTION_BATCH_TERMINAL_COUNTS)
            .enumerate()
        {
            if batch.terminal_count != expected_count {
                return false;
            }
            let Some(evaluation) = dense_execution_batch_selector_evaluation(
                &proof.sumcheck.terminal_evaluations,
                batch_index,
                selector,
            ) else {
                return false;
            };
            claims.push(BlsDoryOpeningClaim {
                commitment: batch.commitment,
                point: dense_opening_point(&sumcheck_point, selector),
                evaluation,
            });
        }
        verify_bls_dory_openings(
            &opening_binding,
            dense_aggregate_layout(),
            &claims,
            &proof.opening_proof,
            setup,
        )
        .is_ok()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_composed_adjacency_batches(
        execution_batches: &[DenseExecutionOpeningBatch],
        inverse_commitment: BlsDoryGt,
    ) -> Option<Vec<DenseAdjacencyOpeningBatch>> {
        let source_counts = [256, 256, 66];
        if execution_batches.len() != DENSE_EXECUTION_BATCH_TERMINAL_COUNTS.len()
            || execution_batches
                .iter()
                .zip(DENSE_EXECUTION_BATCH_TERMINAL_COUNTS)
                .any(|(batch, count)| batch.terminal_count != count)
        {
            return None;
        }
        let mut terminal_start = 0usize;
        let mut batches = execution_batches[..3]
            .iter()
            .zip(source_counts)
            .map(|(batch, count)| {
                let opening = DenseAdjacencyOpeningBatch {
                    commitment: batch.commitment,
                    terminal_start,
                    terminal_count: count,
                    selector_variables: 8,
                };
                terminal_start += count;
                opening
            })
            .collect::<Vec<_>>();
        batches.push(DenseAdjacencyOpeningBatch {
            commitment: inverse_commitment,
            terminal_start,
            terminal_count: 2,
            selector_variables: 8,
        });
        Some(batches)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_composed_opening_binding(
        bridge: &BlsDoryOutputBridgeStatement,
        execution_digest: [u8; 32],
        adjacency_digest: [u8; 32],
        execution_selector_binding: [u8; 32],
        adjacency_selector_binding: [u8; 32],
        execution_batches: &[DenseExecutionOpeningBatch],
        inverse_commitment: BlsDoryGt,
    ) -> [u8; 32] {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-composed-dory-opening");
        transcript.append_bytes(b"dory-binding", &bridge.transcript_binding());
        transcript.append_bytes(b"execution-sumcheck", &execution_digest);
        transcript.append_bytes(b"adjacency-sumcheck", &adjacency_digest);
        transcript.append_bytes(b"execution-selectors", &execution_selector_binding);
        transcript.append_bytes(b"adjacency-selectors", &adjacency_selector_binding);
        transcript.append_bytes(
            b"execution-batch-count",
            &(execution_batches.len() as u64).to_le_bytes(),
        );
        for batch in execution_batches {
            transcript.append_bytes(
                b"execution-terminal-count",
                &(batch.terminal_count as u64).to_le_bytes(),
            );
            transcript.append_group(b"execution-commitment", &batch.commitment);
        }
        transcript.append_group(b"adjacency-inverse-commitment", &inverse_commitment);
        transcript.digest()
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_authenticated_blake3(
        tables: Vec<Vec<BlsDoryFr>>,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<DenseAuthenticatedBlake3Proof, BlsDoryAggregateError> {
        const ROWS: usize = 1 << 8;
        const SLOTS: usize = 1 << 8;
        let adjacency_tables = dense_adjacency_source_tables(&tables);
        let (mut committed_batches, execution_batches) =
            commit_dense_execution_batches(&tables, setup)?;
        let execution_commitments = execution_batches
            .iter()
            .map(|batch| batch.commitment)
            .collect::<Vec<_>>();
        let execution_sumcheck = prove_dense_execution_sumcheck(
            tables,
            air,
            public,
            constraints,
            bridge,
            &execution_commitments,
        );

        let source_commitments = execution_commitments[..3].to_vec();
        let mut challenge_transcript =
            dense_adjacency_transcript(bridge, ROWS, &source_commitments);
        let compression = challenge_transcript.challenge_scalar(b"row-compression");
        let alpha = challenge_transcript.challenge_scalar(b"lookup-alpha");
        let inverse_tables = dense_adjacency_inverse_tables(&adjacency_tables, compression, alpha)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let inverse = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&inverse_tables, ROWS, SLOTS)
                .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?,
            8,
            8,
            setup,
        )?;
        let inverse_commitment = inverse.commitment();
        let inverse_commitments = [inverse_commitment];
        let adjacency_sumcheck = prove_dense_adjacency_sumcheck(
            adjacency_tables,
            bridge,
            &source_commitments,
            &inverse_commitments,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;

        let execution_point =
            dense_replay_sumcheck_point(&execution_sumcheck, bridge, &execution_commitments)
                .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let adjacency_point = dense_replay_adjacency_point(
            &adjacency_sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let adjacency_batches =
            dense_composed_adjacency_batches(&execution_batches, inverse_commitment)
                .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let (execution_selectors, execution_selector_binding) =
            dense_opening_selector_points(execution_sumcheck.transcript_digest, &execution_batches);
        let (adjacency_selectors, adjacency_selector_binding) =
            dense_adjacency_opening_selector_points(
                adjacency_sumcheck.transcript_digest,
                &adjacency_batches,
            );
        let mut points = execution_selectors
            .iter()
            .map(|selector| dense_opening_point(&execution_point, selector))
            .collect::<Vec<_>>();
        points.extend(
            adjacency_selectors
                .iter()
                .map(|selector| dense_opening_point(&adjacency_point, selector)),
        );
        committed_batches.push(inverse);
        let mut polynomial_indices = (0..execution_batches.len()).collect::<Vec<_>>();
        polynomial_indices.extend([0, 1, 2, 4]);
        let openings =
            BlsDoryDeferredOpeningSet::new(committed_batches, polynomial_indices, points)?;
        let mut opening_index = 0usize;
        for (batch_index, (batch, selector)) in execution_batches
            .iter()
            .zip(&execution_selectors)
            .enumerate()
        {
            if batch.terminal_count != DENSE_EXECUTION_BATCH_TERMINAL_COUNTS[batch_index] {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
            let expected = dense_execution_batch_selector_evaluation(
                &execution_sumcheck.terminal_evaluations,
                batch_index,
                selector,
            )
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
            if openings.claims()[opening_index].evaluation != expected {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
            opening_index += 1;
        }
        for (batch, selector) in adjacency_batches.iter().zip(&adjacency_selectors) {
            let terminal_end = batch.terminal_start + batch.terminal_count;
            let expected = dense_terminal_selector_evaluation(
                &adjacency_sumcheck.terminal_evaluations[batch.terminal_start..terminal_end],
                selector,
            );
            if openings.claims()[opening_index].evaluation != expected {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
            opening_index += 1;
        }
        let opening_binding = dense_composed_opening_binding(
            bridge,
            execution_sumcheck.transcript_digest,
            adjacency_sumcheck.transcript_digest,
            execution_selector_binding,
            adjacency_selector_binding,
            &execution_batches,
            inverse_commitment,
        );
        let (_, opening_proof) = prove_bls_dory_deferred_opening_sets(
            &opening_binding,
            dense_aggregate_layout(),
            &[&openings],
            setup,
        )?;
        Ok(DenseAuthenticatedBlake3Proof {
            execution_sumcheck,
            adjacency_sumcheck,
            execution_batches,
            inverse_commitment,
            opening_proof,
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_authenticated_blake3(
        proof: &DenseAuthenticatedBlake3Proof,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        expected_preprocessed_commitment: BlsDoryGt,
        setup: &DeterministicBlsDorySetup,
    ) -> bool {
        const ROWS: usize = 1 << 8;
        if proof.opening_proof.is_empty()
            || proof.execution_batches.len() != DENSE_EXECUTION_BATCH_TERMINAL_COUNTS.len()
            || proof
                .execution_batches
                .iter()
                .zip(DENSE_EXECUTION_BATCH_TERMINAL_COUNTS)
                .any(|(batch, count)| batch.terminal_count != count)
            || proof.execution_batches[3].commitment != expected_preprocessed_commitment
        {
            return false;
        }
        let execution_commitments = proof
            .execution_batches
            .iter()
            .map(|batch| batch.commitment)
            .collect::<Vec<_>>();
        let source_commitments = execution_commitments[..3].to_vec();
        let inverse_commitments = [proof.inverse_commitment];
        if !verify_dense_execution_sumcheck(
            &proof.execution_sumcheck,
            air,
            public,
            constraints,
            bridge,
            &execution_commitments,
        ) || !verify_dense_adjacency_sumcheck(
            &proof.adjacency_sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        ) {
            return false;
        }
        let Some(execution_point) =
            dense_replay_sumcheck_point(&proof.execution_sumcheck, bridge, &execution_commitments)
        else {
            return false;
        };
        let Some(adjacency_point) = dense_replay_adjacency_point(
            &proof.adjacency_sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        ) else {
            return false;
        };
        let Some(adjacency_batches) =
            dense_composed_adjacency_batches(&proof.execution_batches, proof.inverse_commitment)
        else {
            return false;
        };
        let (execution_selectors, execution_selector_binding) = dense_opening_selector_points(
            proof.execution_sumcheck.transcript_digest,
            &proof.execution_batches,
        );
        let (adjacency_selectors, adjacency_selector_binding) =
            dense_adjacency_opening_selector_points(
                proof.adjacency_sumcheck.transcript_digest,
                &adjacency_batches,
            );
        let mut claims = Vec::with_capacity(8);
        for (batch_index, (batch, selector)) in proof
            .execution_batches
            .iter()
            .zip(&execution_selectors)
            .enumerate()
        {
            let Some(evaluation) = dense_execution_batch_selector_evaluation(
                &proof.execution_sumcheck.terminal_evaluations,
                batch_index,
                selector,
            ) else {
                return false;
            };
            claims.push(BlsDoryOpeningClaim {
                commitment: batch.commitment,
                point: dense_opening_point(&execution_point, selector),
                evaluation,
            });
        }
        for (batch, selector) in adjacency_batches.iter().zip(&adjacency_selectors) {
            let terminal_end = batch.terminal_start + batch.terminal_count;
            claims.push(BlsDoryOpeningClaim {
                commitment: batch.commitment,
                point: dense_opening_point(&adjacency_point, selector),
                evaluation: dense_terminal_selector_evaluation(
                    &proof.adjacency_sumcheck.terminal_evaluations
                        [batch.terminal_start..terminal_end],
                    selector,
                ),
            });
        }
        let opening_binding = dense_composed_opening_binding(
            bridge,
            proof.execution_sumcheck.transcript_digest,
            proof.adjacency_sumcheck.transcript_digest,
            execution_selector_binding,
            adjacency_selector_binding,
            &proof.execution_batches,
            proof.inverse_commitment,
        );
        verify_bls_dory_openings(
            &opening_binding,
            dense_aggregate_layout(),
            &claims,
            &proof.opening_proof,
            setup,
        )
        .is_ok()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_blake3_fixture() -> DenseBlake3Fixture {
        let activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        let challenge_digest = [0x42; 32];
        let witness = build_tree_witness(OUTPUT_CONTEXT, challenge_digest, &activation).unwrap();
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            challenge_digest,
            witness.digest,
            &activation,
            [0x51; 32],
            [2_u64, 3, 5, 7, 11]
                .into_iter()
                .map(BlsDoryFr::from_u64)
                .collect(),
        )
        .unwrap();
        dense_blake3_fixture_for_activation_and_bridge(&activation, bridge).unwrap()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_blake3_fixture_for_activation_and_bridge(
        activation: &[u8],
        bridge: BlsDoryOutputBridgeStatement,
    ) -> Result<DenseBlake3Fixture, BlsDoryAggregateError> {
        bridge
            .validate_activation(activation)
            .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        let witness = build_tree_witness(OUTPUT_CONTEXT, bridge.challenge_digest(), activation)
            .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        if bridge.final_activation_len() != activation.len()
            || bridge.final_activation_digest() != witness.digest
        {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        let point = (0..activation.len().ilog2())
            .map(|index| ExtensionElement {
                limbs: [
                    u64::from(index) + 2,
                    u64::from(index) + 3,
                    u64::from(index) + 4,
                ],
            })
            .collect::<Vec<_>>();
        let native_point = point
            .iter()
            .copied()
            .map(ExtensionElement::to_field)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        let signed_activation = activation
            .iter()
            .map(|value| {
                crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*value) - 125)
            })
            .collect::<Vec<_>>();
        let statement = StructuredBlake3Statement {
            challenge_digest: bridge.challenge_digest(),
            final_activation_len: activation.len(),
            final_activation_digest: witness.digest,
            final_activation_point: point,
            final_activation_evaluation: ExtensionElement::from_field(
                crate::structured_sumcheck::evaluate_mle(&signed_activation, &native_point),
            ),
        };
        let air = NarrowBlake3Air::new(&statement)
            .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        let main = generate_main_trace(&air, &statement, &witness);
        let old_main_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { main.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let accumulators = native_accumulator_trace(&air, &old_main_rows, &bridge);
        let native_rows = old_main_rows
            .iter()
            .zip(&accumulators)
            .map(|(row, accumulator)| native_main_row(row, *accumulator))
            .collect::<Vec<_>>();
        let preprocessed = air
            .preprocessed_trace()
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let preprocessed_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { preprocessed.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let public = bls_values(
            public_values(&statement).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?,
        );
        Ok(DenseBlake3Fixture {
            activation: activation.to_vec(),
            tables: dense_execution_tables(&native_rows, &preprocessed_rows),
            statement,
            witness,
            public,
            constraints: bls_dory_native_blake3_constraint_ir(activation.len())
                .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?,
            bridge,
            air,
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn named_replay_sumcheck_proofs(
        fixture: &DenseBlake3Fixture,
        commitments: &BlsDoryBlake3SourceCommitments,
    ) -> (
        BlsDoryBlake3ExecutionSumcheckProof,
        BlsDoryBlake3AdjacencySumcheckProof,
    ) {
        try_named_replay_sumcheck_proofs(fixture, commitments).unwrap()
    }

    #[cfg(feature = "whir-prototype")]
    fn try_named_replay_sumcheck_proofs(
        fixture: &DenseBlake3Fixture,
        commitments: &BlsDoryBlake3SourceCommitments,
    ) -> Result<
        (
            BlsDoryBlake3ExecutionSumcheckProof,
            BlsDoryBlake3AdjacencySumcheckProof,
        ),
        BlsDoryAggregateError,
    > {
        let native_statement = native_blake3_statement_from_bridge(&fixture.bridge);
        let native_air = NarrowBlake3Air::new(&native_statement)
            .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        let native_public = native_blake3_public_values(&fixture.bridge)?;
        let native_constraints =
            bls_dory_native_blake3_constraint_ir(fixture.bridge.final_activation_len())
                .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        let execution = prove_dense_execution_sumcheck_with_transcript(
            fixture.tables.clone(),
            &native_air,
            &native_public,
            &native_constraints,
            &fixture.bridge,
            native_blake3_execution_transcript(&fixture.bridge, commitments),
        );
        let adjacency_sources = commitments.adjacency_sources();
        let adjacency = prove_dense_adjacency_sumcheck_with_transcript(
            dense_adjacency_source_tables(&fixture.tables),
            &[*commitments.commitment(BlsDoryBlake3SourceRole::Inverse)],
            native_blake3_adjacency_transcript(
                &fixture.bridge,
                native_air.trace_rows(),
                &adjacency_sources,
            )?,
            true,
        )
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        Ok((
            BlsDoryBlake3ExecutionSumcheckProof {
                rounds: execution.rounds,
                terminal_evaluations: execution.terminal_evaluations,
                transcript_digest: execution.transcript_digest,
            },
            BlsDoryBlake3AdjacencySumcheckProof {
                rounds: adjacency.rounds,
                terminal_evaluations: adjacency.terminal_evaluations,
                transcript_digest: adjacency.transcript_digest,
            },
        ))
    }

    #[cfg(feature = "whir-prototype")]
    pub(super) fn prepare_native_blake3_test_opening_at_layout_impl(
        activation: &[u8],
        bridge: &BlsDoryOutputBridgeStatement,
        layout: BlsDoryAggregateLayout,
        setup: &DeterministicBlsDorySetup,
        scratch_directory: &std::path::Path,
    ) -> Result<PreparedBlsDoryNativeBlake3TestOpening, BlsDoryAggregateError> {
        let total_started = std::time::Instant::now();
        let fixture_started = std::time::Instant::now();
        let fixture = dense_blake3_fixture_for_activation_and_bridge(activation, bridge.clone())?;
        let fixture_millis = fixture_started.elapsed().as_millis();
        prepare_native_blake3_test_opening_from_fixture(
            &fixture,
            layout,
            setup,
            scratch_directory,
            fixture_millis,
            total_started,
        )
    }

    #[cfg(feature = "whir-prototype")]
    fn prepare_native_blake3_test_opening_from_fixture(
        fixture: &DenseBlake3Fixture,
        layout: BlsDoryAggregateLayout,
        setup: &DeterministicBlsDorySetup,
        scratch_directory: &std::path::Path,
        fixture_millis: u128,
        total_started: std::time::Instant,
    ) -> Result<PreparedBlsDoryNativeBlake3TestOpening, BlsDoryAggregateError> {
        if fixture.activation.len() != 32
            || fixture.bridge.final_activation_len() != fixture.activation.len()
            || fixture.air.trace_rows() != 1 << 8
            || layout.variables() != 21
        {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        fixture
            .bridge
            .validate_activation(&fixture.activation)
            .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
        let geometry = BlsDoryBlake3ReplayGeometry {
            trace_variables: 8,
            source_variables: 19,
            shared_variables: 21,
        };
        let verifier_context = BlsDoryBlake3VerifierContext::new(layout, setup)?;

        let source_started = std::time::Instant::now();
        let prepared = prepare_native_blake3_sources_at_layout(
            &fixture.witness,
            &fixture.bridge,
            layout,
            setup,
            scratch_directory,
        )?;
        let source_millis = source_started.elapsed().as_millis();
        let commitments = prepared.commitments();
        let preprocessing_pin = BlsDoryBlake3TrustedPreprocessingPin::for_test_sources(
            &fixture.bridge,
            fixture.air.trace_rows(),
            geometry,
            &verifier_context,
            &commitments,
        );

        let sumcheck_started = std::time::Instant::now();
        let proven =
            prove_prepared_native_blake3_sources(prepared, &fixture.bridge, scratch_directory, 31)?;
        let sumcheck_millis = sumcheck_started.elapsed().as_millis();
        if proven.proof.source_commitments != commitments {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        let execution = proven.proof.execution.clone();
        let adjacency = proven.proof.adjacency.clone();

        let finalize_started = std::time::Instant::now();
        let PreparedBlsDoryNativeBlake3Opening {
            opening_statement,
            opening_set,
            encoded_native_proof,
        } = finalize_native_blake3_opening(
            proven,
            &fixture.bridge,
            BlsDoryBlake3ReplayVerifier {
                context: &verifier_context,
                preprocessing_pin: &preprocessing_pin,
                geometry,
            },
        )?;
        let finalize_millis = finalize_started.elapsed().as_millis();

        let (retained_scratch_entries, retained_scratch_bytes) =
            std::fs::read_dir(scratch_directory)
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?
                .try_fold((0usize, 0u64), |(entries, bytes), entry| {
                    let len = entry
                        .map_err(|_| BlsDoryAggregateError::ProverStorage)?
                        .metadata()
                        .map_err(|_| BlsDoryAggregateError::ProverStorage)?
                        .len();
                    Ok::<_, BlsDoryAggregateError>((entries + 1, bytes + len))
                })?;
        Ok(PreparedBlsDoryNativeBlake3TestOpening {
            opening_statement,
            opening_set,
            encoded_native_proof,
            trusted_preprocessing_commitment: commitments.preprocessing,
            telemetry: BlsDoryNativeBlake3TestTelemetry {
                fixture_millis,
                source_millis,
                sumcheck_millis,
                finalize_millis,
                total_millis: total_started.elapsed().as_millis(),
                retained_scratch_entries,
                retained_scratch_bytes,
            },
            commitments,
            execution,
            adjacency,
            geometry,
            verifier_context,
        })
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn verifier_context_validates_and_captures_small_real_setup() {
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(6).unwrap();
        let layout = BlsDoryAggregateLayout::new(3, 3).unwrap();
        let context = BlsDoryBlake3VerifierContext::new(layout, &setup).unwrap();
        assert_eq!(context.layout, layout);
        assert_eq!(context.setup_identity, setup.identity());
        assert_eq!(context.setup_max_log_n, setup.max_log_n());
        assert_eq!(
            BlsDoryBlake3VerifierContext::new(BlsDoryAggregateLayout::new(3, 4).unwrap(), &setup,),
            Err(BlsDoryAggregateError::InvalidDimension)
        );
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn dense_fixture_accepts_caller_activation_and_bridge() {
        let activation = (0_u8..32).map(|index| 32 + index).collect::<Vec<_>>();
        let challenge_digest = [0x77; 32];
        let witness = build_tree_witness(OUTPUT_CONTEXT, challenge_digest, &activation).unwrap();
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            challenge_digest,
            witness.digest,
            &activation,
            [0x78; 32],
            [13_u64, 17, 19, 23, 29]
                .into_iter()
                .map(BlsDoryFr::from_u64)
                .collect(),
        )
        .unwrap();
        let fixture =
            dense_blake3_fixture_for_activation_and_bridge(&activation, bridge.clone()).unwrap();

        assert_eq!(fixture.activation, activation);
        assert_eq!(fixture.bridge, bridge);
        assert_eq!(fixture.witness.digest, witness.digest);
        assert_eq!(fixture.air.trace_rows(), 1 << 8);
        assert_eq!(
            fixture.tables.len(),
            2 * (BLS_DORY_BLAKE3_MAIN_WIDTH + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
        );

        let mut changed_activation = activation;
        changed_activation[0] ^= 1;
        assert!(matches!(
            dense_blake3_fixture_for_activation_and_bridge(&changed_activation, bridge),
            Err(BlsDoryAggregateError::InvalidProofShape)
        ));
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn native_bridge_normalization_excludes_legacy_point_and_evaluation() {
        let mut fixture = dense_blake3_fixture();
        let canonical = native_blake3_statement_from_bridge(&fixture.bridge);
        assert_eq!(
            canonical.challenge_digest,
            fixture.bridge.challenge_digest()
        );
        assert_eq!(
            canonical.final_activation_digest,
            fixture.bridge.final_activation_digest()
        );
        assert_eq!(
            canonical.final_activation_len,
            fixture.bridge.final_activation_len()
        );
        assert_eq!(
            canonical.final_activation_point.len(),
            fixture.bridge.cell_point().len()
        );
        assert!(
            canonical
                .final_activation_point
                .iter()
                .all(|coordinate| coordinate.limbs == [0; 3])
        );
        assert_eq!(canonical.final_activation_evaluation.limbs, [0; 3]);

        fixture.statement.final_activation_point[0] = ExtensionElement { limbs: [1, 0, 0] };
        fixture.statement.final_activation_evaluation = ExtensionElement { limbs: [7, 0, 0] };
        fixture.public = bls_values(public_values(&fixture.statement).unwrap());
        assert_ne!(
            fixture.statement.final_activation_point,
            canonical.final_activation_point
        );
        assert_ne!(
            fixture.statement.final_activation_evaluation,
            canonical.final_activation_evaluation
        );
        assert_eq!(
            native_blake3_statement_from_bridge(&fixture.bridge),
            canonical
        );
        assert_ne!(
            fixture.public,
            native_blake3_public_values(&fixture.bridge).unwrap()
        );

        let commitments = BlsDoryBlake3SourceCommitments {
            main: BlsDoryGt::random(),
            accumulator: BlsDoryGt::random(),
            preprocessing: BlsDoryGt::random(),
            inverse: BlsDoryGt::random(),
        };
        let (execution, adjacency) = named_replay_sumcheck_proofs(&fixture, &commitments);
        let geometry = BlsDoryBlake3ReplayGeometry {
            trace_variables: fixture.air.trace_rows().ilog2() as usize,
            source_variables: fixture.air.trace_rows().ilog2() as usize
                + BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES,
            shared_variables: fixture.air.trace_rows().ilog2() as usize
                + BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES
                + 2,
        };
        let verifier_context = BlsDoryBlake3VerifierContext::for_test_metadata(
            BlsDoryAggregateLayout::new(10, 11).unwrap(),
            [0x71; 32],
            21,
        )
        .unwrap();
        let preprocessing_pin = BlsDoryBlake3TrustedPreprocessingPin::for_test_sources(
            &fixture.bridge,
            fixture.air.trace_rows(),
            geometry,
            &verifier_context,
            &commitments,
        );
        verify_native_blake3_opening_replay_at_geometry(
            &fixture.bridge,
            &commitments,
            BlsDoryBlake3ReplayVerifier {
                context: &verifier_context,
                preprocessing_pin: &preprocessing_pin,
                geometry,
            },
            &execution,
            &adjacency,
        )
        .unwrap();

        let activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        let mut wrong_digest = fixture.bridge.final_activation_digest();
        wrong_digest[0] ^= 1;
        let wrong_bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            fixture.bridge.challenge_digest(),
            wrong_digest,
            &activation,
            fixture.bridge.transcript_binding(),
            fixture.bridge.cell_point().to_vec(),
        )
        .unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(6).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        assert!(matches!(
            commit_native_blake3_sources_at_layout(
                &fixture.witness,
                &wrong_bridge,
                BlsDoryAggregateLayout::new(3, 3).unwrap(),
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn verifier_owned_replay_derives_six_fixed_named_claims() {
        let fixture = dense_blake3_fixture();
        let commitments = BlsDoryBlake3SourceCommitments {
            main: BlsDoryGt::random(),
            accumulator: BlsDoryGt::random(),
            preprocessing: BlsDoryGt::random(),
            inverse: BlsDoryGt::random(),
        };
        let (execution, adjacency) = named_replay_sumcheck_proofs(&fixture, &commitments);
        let trace_variables = fixture.air.trace_rows().ilog2() as usize;
        let source_variables = trace_variables + BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES;
        let shared_variables = source_variables + 2;
        let geometry = BlsDoryBlake3ReplayGeometry {
            trace_variables,
            source_variables,
            shared_variables,
        };
        let verifier_context = BlsDoryBlake3VerifierContext::for_test_metadata(
            BlsDoryAggregateLayout::new(10, 11).unwrap(),
            [0x61; 32],
            21,
        )
        .unwrap();
        let preprocessing_pin = BlsDoryBlake3TrustedPreprocessingPin::for_test_sources(
            &fixture.bridge,
            fixture.air.trace_rows(),
            geometry,
            &verifier_context,
            &commitments,
        );
        let replay_verifier = BlsDoryBlake3ReplayVerifier {
            context: &verifier_context,
            preprocessing_pin: &preprocessing_pin,
            geometry,
        };
        let replay = verify_native_blake3_opening_replay_at_geometry(
            &fixture.bridge,
            &commitments,
            replay_verifier,
            &execution,
            &adjacency,
        )
        .unwrap();

        assert!(
            replay
                .execution_points
                .iter()
                .chain(&replay.adjacency_points)
                .all(|point| {
                    point.len() == shared_variables
                        && point[source_variables..]
                            .iter()
                            .all(|coordinate| *coordinate == BlsDoryFr::zero())
                })
        );
        assert!(
            replay
                .execution_points
                .iter()
                .all(|point| point[..trace_variables]
                    == replay.execution_points[0][..trace_variables])
        );
        assert!(
            replay
                .adjacency_points
                .iter()
                .all(|point| point[..trace_variables]
                    == replay.adjacency_points[0][..trace_variables]
                    && point[trace_variables + BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES]
                        == BlsDoryFr::zero())
        );
        assert_ne!(replay.execution_points[0], replay.adjacency_points[0]);

        let statement = BlsDoryBlake3OpeningStatement::from_verified_replay_at_geometry(
            commitments.clone(),
            replay.clone(),
            geometry,
        )
        .unwrap();
        assert_eq!(statement.opening_binding(), replay.opening_binding);
        let points = [
            replay.execution_points[0].clone(),
            replay.execution_points[1].clone(),
            replay.execution_points[2].clone(),
            replay.adjacency_points[0].clone(),
            replay.adjacency_points[1].clone(),
            replay.adjacency_points[2].clone(),
        ];
        let evaluations = [
            replay.execution_evaluations[0],
            replay.execution_evaluations[1],
            replay.execution_evaluations[2],
            replay.adjacency_evaluations[0],
            replay.adjacency_evaluations[1],
            replay.adjacency_evaluations[2],
        ];
        let claims = BLS_DORY_BLAKE3_OPENING_SOURCE_ROLES
            .iter()
            .enumerate()
            .map(|(index, role)| BlsDoryOpeningClaim {
                commitment: *commitments.commitment(*role),
                point: points[index].clone(),
                evaluation: evaluations[index],
            })
            .collect::<Vec<_>>();
        statement.validate_claims(&claims).unwrap();

        let mut wrong_execution_round = execution.clone();
        wrong_execution_round.rounds[0][0] =
            wrong_execution_round.rounds[0][0] + BlsDoryFr::from_u64(1);
        assert_eq!(
            verify_native_blake3_opening_replay_at_geometry(
                &fixture.bridge,
                &commitments,
                replay_verifier,
                &wrong_execution_round,
                &adjacency,
            ),
            Err(BlsDoryAggregateError::SumcheckFailed)
        );

        let mut wrong_execution_terminal = execution.clone();
        wrong_execution_terminal.terminal_evaluations[0] =
            wrong_execution_terminal.terminal_evaluations[0] + BlsDoryFr::from_u64(1);
        assert!(
            verify_native_blake3_opening_replay_at_geometry(
                &fixture.bridge,
                &commitments,
                replay_verifier,
                &wrong_execution_terminal,
                &adjacency,
            )
            .is_err()
        );

        let mut wrong_adjacency_digest = adjacency.clone();
        wrong_adjacency_digest.transcript_digest[0] ^= 1;
        assert_eq!(
            verify_native_blake3_opening_replay_at_geometry(
                &fixture.bridge,
                &commitments,
                replay_verifier,
                &execution,
                &wrong_adjacency_digest,
            ),
            Err(BlsDoryAggregateError::SumcheckFailed)
        );

        let swapped = BlsDoryBlake3SourceCommitments {
            main: commitments.accumulator,
            accumulator: commitments.main,
            preprocessing: commitments.preprocessing,
            inverse: commitments.inverse,
        };
        assert!(
            verify_native_blake3_opening_replay_at_geometry(
                &fixture.bridge,
                &swapped,
                replay_verifier,
                &execution,
                &adjacency,
            )
            .is_err()
        );

        let wrong_preprocessing = loop {
            let candidate = BlsDoryGt::random();
            if candidate != commitments.preprocessing {
                break candidate;
            }
        };
        let wrong_pin_sources = BlsDoryBlake3SourceCommitments {
            preprocessing: wrong_preprocessing,
            ..commitments.clone()
        };
        let wrong_commitment_pin = BlsDoryBlake3TrustedPreprocessingPin::for_test_sources(
            &fixture.bridge,
            fixture.air.trace_rows(),
            geometry,
            &verifier_context,
            &wrong_pin_sources,
        );
        assert_eq!(
            verify_native_blake3_opening_replay_at_geometry(
                &fixture.bridge,
                &commitments,
                BlsDoryBlake3ReplayVerifier {
                    context: &verifier_context,
                    preprocessing_pin: &wrong_commitment_pin,
                    geometry,
                },
                &execution,
                &adjacency,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let wrong_pin_geometry = BlsDoryBlake3ReplayGeometry {
            shared_variables: geometry.shared_variables + 1,
            ..geometry
        };
        let wrong_shape_pin = BlsDoryBlake3TrustedPreprocessingPin::for_test_sources(
            &fixture.bridge,
            fixture.air.trace_rows(),
            wrong_pin_geometry,
            &verifier_context,
            &commitments,
        );
        assert_eq!(
            verify_native_blake3_opening_replay_at_geometry(
                &fixture.bridge,
                &commitments,
                BlsDoryBlake3ReplayVerifier {
                    context: &verifier_context,
                    preprocessing_pin: &wrong_shape_pin,
                    geometry,
                },
                &execution,
                &adjacency,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let wrong_layout_context = BlsDoryBlake3VerifierContext::for_test_metadata(
            BlsDoryAggregateLayout::new(9, 12).unwrap(),
            verifier_context.setup_identity,
            verifier_context.setup_max_log_n,
        )
        .unwrap();
        let wrong_layout_pin = BlsDoryBlake3TrustedPreprocessingPin::for_test_sources(
            &fixture.bridge,
            fixture.air.trace_rows(),
            geometry,
            &wrong_layout_context,
            &commitments,
        );
        assert_eq!(
            verify_native_blake3_opening_replay_at_geometry(
                &fixture.bridge,
                &commitments,
                BlsDoryBlake3ReplayVerifier {
                    context: &verifier_context,
                    preprocessing_pin: &wrong_layout_pin,
                    geometry,
                },
                &execution,
                &adjacency,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let mut wrong_setup_context = verifier_context.clone();
        wrong_setup_context.setup_identity[0] ^= 1;
        let wrong_setup_pin = BlsDoryBlake3TrustedPreprocessingPin::for_test_sources(
            &fixture.bridge,
            fixture.air.trace_rows(),
            geometry,
            &wrong_setup_context,
            &commitments,
        );
        assert_eq!(
            verify_native_blake3_opening_replay_at_geometry(
                &fixture.bridge,
                &commitments,
                BlsDoryBlake3ReplayVerifier {
                    context: &verifier_context,
                    preprocessing_pin: &wrong_setup_pin,
                    geometry,
                },
                &execution,
                &adjacency,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );

        let mut nonzero_fixed_selector = replay.clone();
        nonzero_fixed_selector.adjacency_points[0]
            [trace_variables + BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES] =
            BlsDoryFr::from_u64(1);
        assert_eq!(
            BlsDoryBlake3OpeningStatement::from_verified_replay_at_geometry(
                commitments.clone(),
                nonzero_fixed_selector,
                geometry,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );

        let (execution_selectors, execution_selector_digest) =
            native_blake3_execution_selector_points(execution.transcript_digest, &commitments);
        let (_, adjacency_selector_digest) =
            native_blake3_adjacency_selector_points(adjacency.transcript_digest, &commitments);
        assert_eq!(
            replay.opening_binding,
            native_blake3_opening_binding(
                &fixture.bridge,
                BlsDoryBlake3OpeningTranscriptDigests {
                    execution_sumcheck: execution.transcript_digest,
                    adjacency_sumcheck: adjacency.transcript_digest,
                    execution_selectors: execution_selector_digest,
                    adjacency_selectors: adjacency_selector_digest,
                },
                geometry,
                &verifier_context,
                &commitments,
            )
        );
        let mut changed_sumcheck_digest = execution.transcript_digest;
        changed_sumcheck_digest[0] ^= 1;
        let (changed_selectors, changed_selector_digest) =
            native_blake3_execution_selector_points(changed_sumcheck_digest, &commitments);
        assert_ne!(changed_selectors, execution_selectors);
        assert_ne!(changed_selector_digest, execution_selector_digest);
        assert_ne!(
            native_blake3_opening_binding(
                &fixture.bridge,
                BlsDoryBlake3OpeningTranscriptDigests {
                    execution_sumcheck: changed_sumcheck_digest,
                    adjacency_sumcheck: adjacency.transcript_digest,
                    execution_selectors: changed_selector_digest,
                    adjacency_selectors: adjacency_selector_digest,
                },
                geometry,
                &verifier_context,
                &commitments,
            ),
            replay.opening_binding
        );
        let changed_commitments = BlsDoryBlake3SourceCommitments {
            main: BlsDoryGt::random(),
            ..commitments.clone()
        };
        let (_, changed_execution_selector_digest) = native_blake3_execution_selector_points(
            execution.transcript_digest,
            &changed_commitments,
        );
        let (_, changed_adjacency_selector_digest) = native_blake3_adjacency_selector_points(
            adjacency.transcript_digest,
            &changed_commitments,
        );
        assert_ne!(
            native_blake3_opening_binding(
                &fixture.bridge,
                BlsDoryBlake3OpeningTranscriptDigests {
                    execution_sumcheck: execution.transcript_digest,
                    adjacency_sumcheck: adjacency.transcript_digest,
                    execution_selectors: changed_execution_selector_digest,
                    adjacency_selectors: changed_adjacency_selector_digest,
                },
                geometry,
                &verifier_context,
                &changed_commitments,
            ),
            replay.opening_binding
        );
    }

    #[test]
    fn native_blake3_projection_is_bounded_but_fail_closed() {
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES, 524_288);
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS, 1_048_576);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS, 746);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS, 3);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS, 1_299);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES, 11);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES, 10);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES, 31);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_DORY_NU, 11);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_DORY_SIGMA, 20);
        assert_eq!(BLS_DORY_BLAKE3_SIGNED_WORD_TABLES, 576);
        assert_eq!(BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES, 2);
        assert_eq!(BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES, 8);
        assert_eq!(BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES, 160);
        assert_eq!(BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES, 2);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS, 580);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS, 3);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_COMMITMENTS, 4);
        assert_eq!(BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES, [0, 1, 2, 0, 1, 3]);
        assert_eq!(BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS, 134);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES, 37_172);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES, 21_748);
        assert_eq!(
            crate::dory_bls12_381_layout::projected_shared_production_proof_bytes().unwrap(),
            133_409
        );
        assert_eq!(BLS_DORY_BLAKE3_PROJECTED_V3_BYTES, 192_347);
        assert_eq!(MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES, 261_947);
        assert_eq!(BLS_DORY_BLAKE3_PROJECTED_HEADROOM_BYTES, 69_600);
        assert_eq!(
            projected_bls_dory_blake3_source_storage(),
            BlsDoryBlake3SourceStorageProjection {
                literal_payload_bytes: 25_098_715_136,
                signed_word_payload_bytes: 4_831_838_208,
                full_field_payload_bytes: 134_217_728,
                preprocessed_word_payload_bytes: 67_108_864,
                preprocessed_code_payload_bytes: 83_886_080,
                compact_payload_bytes: 5_117_050_880,
            }
        );
        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_BLOCKERS.len(), 4);
    }

    #[test]
    fn production_resource_preflight_accounts_known_artifacts_and_stays_closed() {
        let projection = projected_bls_dory_blake3_production_resources().unwrap();
        assert_eq!(projection.shared_aggregate_peak_bytes, 29_202_416_244);
        assert_eq!(projection.compact_source_payload_bytes, 5_117_050_880);
        assert_eq!(projection.framed_source_artifact_bytes, 5_117_051_496);
        assert_eq!(projection.transpose_artifact_bytes, 3_120_562_320);
        assert_eq!(
            projection.source_construction_coexistence_bytes,
            8_237_613_816
        );
        assert_eq!(
            projection.first_execution_round_artifact_bytes,
            12_515_803_268
        );
        assert_eq!(
            projection.second_execution_round_artifact_bytes,
            6_257_901_700
        );
        assert_eq!(
            projection.execution_round_peak_scratch_bytes,
            18_773_704_968
        );
        assert_eq!(
            projection.execution_stage_projected_peak_scratch_bytes,
            27_011_318_784
        );
        assert_eq!(projection.execution_auxiliary_resident_bytes, 402_653_184);
        assert_eq!(
            projection.execution_root_snapshot_resident_bytes,
            67_108_864
        );
        assert_eq!(projection.root_streaming_slab_resident_bytes, 390_070_272);
        assert_eq!(projection.root_streaming_row_resident_bytes, 11_904);
        assert_eq!(
            projection.execution_root_stream_resident_payload_bytes,
            859_844_224
        );
        assert_eq!(
            projection.first_adjacency_round_artifact_bytes,
            9_730_785_412
        );
        assert_eq!(
            projection.second_adjacency_round_artifact_bytes,
            4_865_392_772
        );
        assert_eq!(
            projection.adjacency_round_peak_scratch_bytes,
            14_596_178_184
        );
        assert_eq!(
            projection.adjacency_stage_projected_peak_scratch_bytes,
            22_833_792_000
        );
        assert_eq!(projection.adjacency_auxiliary_resident_bytes, 100_663_296);
        assert_eq!(
            projection.adjacency_inverse_snapshot_resident_bytes,
            67_108_864
        );
        assert_eq!(
            projection.adjacency_root_stream_resident_payload_bytes,
            624_963_200
        );
        assert_eq!(projection.aggregate_stage_lower_bound_bytes, 34_319_467_740);
        assert_eq!(projection.first_generation_fold_bytes, 2_894_071_840);
        assert_eq!(projection.second_generation_fold_bytes, 1_447_036_448);
        assert_eq!(projection.eighth_generation_fold_bytes, 22_611_104);
        assert_eq!(projection.source_materialization_fold_bytes, 3_281_686_124);
        assert_eq!(projection.final_generation_fold_bytes, 4_428);
        assert_eq!(projection.aggregate_retained_source_bytes, 31_021_791_228);
        assert_eq!(projection.aggregate_fold_peak_bytes, 4_282_386_084);
        assert_eq!(
            projection.aggregate_stage_projected_peak_bytes,
            35_304_177_312
        );
        assert_eq!(
            projection.aggregate_with_transpose_coexistence_bytes,
            38_424_739_632
        );
        assert_eq!(projection.provisional_scratch_gate_bytes, 53_687_091_200);
        assert!(
            projection.provisional_scratch_gate_bytes
                >= projection.source_construction_coexistence_bytes
        );
        assert!(
            projection.provisional_scratch_gate_bytes
                >= projection.execution_stage_projected_peak_scratch_bytes
        );
        assert!(
            projection.provisional_scratch_gate_bytes
                >= projection.adjacency_stage_projected_peak_scratch_bytes
        );
        assert!(
            projection.provisional_scratch_gate_bytes
                >= projection.aggregate_with_transpose_coexistence_bytes
        );
        assert_eq!(
            projection.provisional_available_memory_gate_bytes,
            4_294_967_296
        );
        assert!(
            projection.provisional_available_memory_gate_bytes
                >= projection.execution_root_stream_resident_payload_bytes
        );
        assert!(
            projection.provisional_available_memory_gate_bytes
                >= projection.adjacency_root_stream_resident_payload_bytes
        );
        assert!(projection.fold_scratch_model_complete);
        assert!(!projection.fold_scratch_measurement_complete);
        assert!(!projection.peak_memory_projection_complete);
        assert!(!projection.composed_prover_implemented);
        assert!(!projection.is_complete());

        assert_eq!(
            preflight_bls_dory_blake3_production_resources(
                projection.provisional_scratch_gate_bytes - 1,
                projection.provisional_available_memory_gate_bytes,
            ),
            Err(BlsDoryBlake3ProductionPreflightError::InsufficientScratch {
                required: projection.provisional_scratch_gate_bytes,
                available: projection.provisional_scratch_gate_bytes - 1,
            })
        );
        assert_eq!(
            preflight_bls_dory_blake3_production_resources(
                projection.provisional_scratch_gate_bytes,
                projection.provisional_available_memory_gate_bytes - 1,
            ),
            Err(BlsDoryBlake3ProductionPreflightError::InsufficientMemory {
                required: projection.provisional_available_memory_gate_bytes,
                available: projection.provisional_available_memory_gate_bytes - 1,
            })
        );
        assert_eq!(
            preflight_bls_dory_blake3_production_resources(u64::MAX, u64::MAX,),
            Err(BlsDoryBlake3ProductionPreflightError::IncompleteProjection)
        );
    }

    #[test]
    fn native_blake3_sources_fit_the_shared_production_geometry() {
        let shared_nu = BLS_DORY_SHARED_PRODUCTION_VARIABLES / 2;
        let shared_sigma = BLS_DORY_SHARED_PRODUCTION_VARIABLES - shared_nu;
        let shared_rows = 1u64 << shared_nu;
        let shared_columns = 1u64 << shared_sigma;
        let shared_capacity = shared_rows * shared_columns;
        let source_prefix = 1u64 << BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES;
        let trace_rows = BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS as u64;
        let segments_per_table = trace_rows / shared_columns;
        let source_tables = [
            BLS_DORY_BLAKE3_SIGNED_WORD_TABLES,
            BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES,
            BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES,
            BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES,
        ];
        let physical_rows = source_tables.map(|tables| tables as u64 * segments_per_table);

        assert_eq!((shared_nu, shared_sigma), (16, 17));
        assert_eq!(shared_capacity, 1u64 << 33);
        assert_eq!(source_prefix, 1u64 << 31);
        assert!(source_prefix < shared_capacity);
        assert_eq!(segments_per_table, 8);
        assert_eq!(physical_rows, [4_608, 16, 1_344, 16]);
        for tables in source_tables {
            let explicit_scalars = tables as u64 * trace_rows;
            assert!(explicit_scalars <= source_prefix);
            assert!(explicit_scalars.is_multiple_of(shared_columns));
        }

        let mut uses = [0usize; BLS_DORY_BLAKE3_SOURCE_COMMITMENTS];
        for source in BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES {
            uses[source] += 1;
        }
        assert_eq!(uses, [2, 2, 1, 1]);
        assert!(BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len() <= MAX_BLS_DORY_AGGREGATE_CLAIMS);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn preprocessing_storage_split_leaves_only_boolean_code_tables() {
        let fixture = dense_blake3_fixture();
        let local_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
        let next_start = local_start + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH;
        let zero = BlsDoryFr::zero();
        let one = BlsDoryFr::from_u64(1);
        for column in 0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
            if NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.contains(&column) {
                continue;
            }
            for table in [
                &fixture.tables[local_start + column],
                &fixture.tables[next_start + column],
            ] {
                assert!(table.iter().all(|value| *value == zero || *value == one));
            }
        }
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn preprocessing_physical_mapping_is_bijective_and_complete() {
        let word_columns = NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.len();
        let boolean_columns = BLS_DORY_BLAKE3_PREPROCESSED_WIDTH - word_columns;
        let physical_tables = 2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH;
        let mut logical_indices = Vec::with_capacity(physical_tables);

        for physical_slot in 0..physical_tables {
            let (direction, column) = preprocessed_physical_role(physical_slot).unwrap();
            assert!(direction <= 1);
            if physical_slot < word_columns {
                assert_eq!(direction, 0);
                assert!(NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.contains(&column));
            } else if physical_slot < 2 * word_columns {
                assert_eq!(direction, 1);
                assert!(NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.contains(&column));
            } else if physical_slot < 2 * word_columns + boolean_columns {
                assert_eq!(direction, 0);
                assert!(!NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.contains(&column));
            } else {
                assert_eq!(direction, 1);
                assert!(!NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.contains(&column));
            }

            let logical = preprocessed_physical_terminal_index(physical_slot).unwrap();
            assert_eq!(
                logical,
                direction * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH + column
            );
            assert_eq!(
                (0..physical_tables)
                    .find(|candidate| {
                        preprocessed_physical_terminal_index(*candidate) == Some(logical)
                    })
                    .unwrap(),
                physical_slot
            );
            logical_indices.push(logical);
        }

        logical_indices.sort_unstable();
        assert_eq!(logical_indices, (0..physical_tables).collect::<Vec<_>>());
        assert_eq!(preprocessed_physical_role(physical_tables), None);
        assert_eq!(preprocessed_physical_terminal_index(physical_tables), None);
    }

    #[test]
    fn composed_blake3_soundness_report_pins_every_algebraic_term() {
        let report = projected_bls_dory_blake3_soundness_report().unwrap();
        let expected = [
            ("BLAKE3 execution constraint mixing", 1_298),
            ("BLAKE3 execution local equality point", 20),
            ("BLAKE3 execution sumcheck", 340),
            ("BLAKE3 execution source selector batching", 11),
            ("BLAKE3 adjacency row compression", 303_038_464),
            ("BLAKE3 adjacency lookup-alpha rational identity", 2_097_151),
            ("BLAKE3 adjacency local relation mixing", 1),
            ("BLAKE3 adjacency global relation mixing", 1),
            ("BLAKE3 adjacency local equality point", 20),
            ("BLAKE3 adjacency sumcheck", 60),
            ("BLAKE3 adjacency source selector batching", 10),
            ("BLAKE3 adjacency inverse selector batching", 10),
        ];
        assert_eq!(report.blake3_terms.len(), expected.len());
        for (term, (label, numerator)) in report.blake3_terms.iter().zip(expected) {
            assert_eq!(term.label, label);
            assert_eq!(term.instances, 1);
            assert_eq!(term.numerator_upper_bound_per_instance, numerator);
        }
        assert_eq!(
            report.shared_algebraic_numerator_upper_bound,
            19_781_388_263
        );
        assert_eq!(report.blake3_algebraic_numerator_upper_bound, 305_137_386);
        assert_eq!(
            report.composed_algebraic_numerator_upper_bound,
            20_086_525_649
        );
        assert_eq!(report.nonzero_challenge_space_lower_bound_bits, 254);
        assert_eq!(
            blake3_ceil_log2(report.composed_algebraic_numerator_upper_bound),
            35
        );
        assert_eq!(report.algebraic_soundness_bits, 219);
        assert_eq!(report.required_algebraic_soundness_bits, 128);
        assert_eq!(report.grinding_headroom_bits, 91);
        assert_eq!(report.composed_opening_claims, 134);
        assert_eq!(report.proposed_maximum_opening_claims, 256);
        assert!(!report.independently_reviewed);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn production_air_translates_to_bounded_integer_constraints() {
        let constraints =
            bls_dory_blake3_constraint_ir(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES).unwrap();
        assert_eq!(constraints.len(), 1_305);
        let maximum = constraints.iter().map(maximum_abs_constant).max().unwrap();
        assert_eq!(maximum, 1_u64 << 33);
        let native =
            bls_dory_native_blake3_constraint_ir(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES)
                .unwrap();
        assert_eq!(native.len() + 3, BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS);
        assert!(
            native
                .iter()
                .all(|constraint| !uses_removed_native_input(constraint))
        );
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn honest_narrow_blake3_trace_satisfies_translated_bls_constraints() {
        let activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        let challenge_digest = [0x42; 32];
        let witness = build_tree_witness(OUTPUT_CONTEXT, challenge_digest, &activation).unwrap();
        let point = (0..activation.len().ilog2())
            .map(|index| ExtensionElement {
                limbs: [
                    u64::from(index) + 2,
                    u64::from(index) + 3,
                    u64::from(index) + 4,
                ],
            })
            .collect::<Vec<_>>();
        let native_point = point
            .iter()
            .copied()
            .map(ExtensionElement::to_field)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let table = activation
            .iter()
            .map(|value| {
                crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*value) - 125)
            })
            .collect::<Vec<_>>();
        let statement = StructuredBlake3Statement {
            challenge_digest,
            final_activation_len: activation.len(),
            final_activation_digest: witness.digest,
            final_activation_point: point,
            final_activation_evaluation: ExtensionElement::from_field(
                crate::structured_sumcheck::evaluate_mle(&table, &native_point),
            ),
        };
        let air = NarrowBlake3Air::new(&statement).unwrap();
        let main = generate_main_trace(&air, &statement, &witness);
        let preprocessed = air.preprocessed_trace().unwrap();
        let public = bls_values(public_values(&statement).unwrap());
        let constraints = bls_dory_blake3_constraint_ir(activation.len()).unwrap();
        assert_eq!(constraints.len(), 1_305);

        for row in 0..air.trace_rows() {
            let next_row = (row + 1) % air.trace_rows();
            let main_local = bls_values(unsafe { main.row_unchecked(row) });
            let main_next = bls_values(unsafe { main.row_unchecked(next_row) });
            let preprocessed_local = bls_values(unsafe { preprocessed.row_unchecked(row) });
            let preprocessed_next = bls_values(unsafe { preprocessed.row_unchecked(next_row) });
            let periodic = bls_values(air.periodic_values(row));
            let values = BlsDoryBlake3Evaluation {
                main_local: &main_local,
                main_next: &main_next,
                preprocessed_local: &preprocessed_local,
                preprocessed_next: &preprocessed_next,
                public: &public,
                periodic: &periodic,
                first_row: BlsDoryFr::from_u64(u64::from(row == 0)),
                last_row: BlsDoryFr::from_u64(u64::from(row + 1 == air.trace_rows())),
                transition: BlsDoryFr::from_u64(u64::from(row + 1 != air.trace_rows())),
            };
            for (constraint_index, constraint) in constraints.iter().enumerate() {
                assert_eq!(
                    constraint.evaluate(&values),
                    BlsDoryFr::zero(),
                    "translated constraint {constraint_index} failed at row {row}"
                );
            }
        }

        let main_next = bls_values(unsafe { main.row_unchecked(1) });
        let mut changed_main = bls_values(unsafe { main.row_unchecked(0) });
        changed_main[0] = changed_main[0] + BlsDoryFr::from_u64(1);
        let preprocessed_local = bls_values(unsafe { preprocessed.row_unchecked(0) });
        let preprocessed_next = bls_values(unsafe { preprocessed.row_unchecked(1) });
        let periodic = bls_values(air.periodic_values(0));
        let changed = BlsDoryBlake3Evaluation {
            main_local: &changed_main,
            main_next: &main_next,
            preprocessed_local: &preprocessed_local,
            preprocessed_next: &preprocessed_next,
            public: &public,
            periodic: &periodic,
            first_row: BlsDoryFr::from_u64(1),
            last_row: BlsDoryFr::zero(),
            transition: BlsDoryFr::from_u64(1),
        };
        assert!(
            constraints
                .iter()
                .any(|constraint| constraint.evaluate(&changed) != BlsDoryFr::zero())
        );

        let mut changed_public = public.clone();
        changed_public[72] = changed_public[72] + BlsDoryFr::from_u64(1);
        let point_mutation_rejected = (0..air.trace_rows()).any(|row| {
            let next_row = (row + 1) % air.trace_rows();
            let main_local = bls_values(unsafe { main.row_unchecked(row) });
            let main_next = bls_values(unsafe { main.row_unchecked(next_row) });
            let preprocessed_local = bls_values(unsafe { preprocessed.row_unchecked(row) });
            let preprocessed_next = bls_values(unsafe { preprocessed.row_unchecked(next_row) });
            let periodic = bls_values(air.periodic_values(row));
            let changed = BlsDoryBlake3Evaluation {
                main_local: &main_local,
                main_next: &main_next,
                preprocessed_local: &preprocessed_local,
                preprocessed_next: &preprocessed_next,
                public: &changed_public,
                periodic: &periodic,
                first_row: BlsDoryFr::from_u64(u64::from(row == 0)),
                last_row: BlsDoryFr::from_u64(u64::from(row + 1 == air.trace_rows())),
                transition: BlsDoryFr::from_u64(u64::from(row + 1 != air.trace_rows())),
            };
            constraints
                .iter()
                .any(|constraint| constraint.evaluate(&changed) != BlsDoryFr::zero())
        });
        assert!(point_mutation_rejected);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn native_bls_accumulator_replaces_three_goldilocks_limbs() {
        let activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        let challenge_digest = [0x42; 32];
        let witness = build_tree_witness(OUTPUT_CONTEXT, challenge_digest, &activation).unwrap();
        let goldilocks_point = (0..activation.len().ilog2())
            .map(|index| ExtensionElement {
                limbs: [
                    u64::from(index) + 2,
                    u64::from(index) + 3,
                    u64::from(index) + 4,
                ],
            })
            .collect::<Vec<_>>();
        let native_point = goldilocks_point
            .iter()
            .copied()
            .map(ExtensionElement::to_field)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let signed_activation = activation
            .iter()
            .map(|value| {
                crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*value) - 125)
            })
            .collect::<Vec<_>>();
        let statement = StructuredBlake3Statement {
            challenge_digest,
            final_activation_len: activation.len(),
            final_activation_digest: witness.digest,
            final_activation_point: goldilocks_point,
            final_activation_evaluation: ExtensionElement::from_field(
                crate::structured_sumcheck::evaluate_mle(&signed_activation, &native_point),
            ),
        };
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            challenge_digest,
            witness.digest,
            &activation,
            [0x51; 32],
            [2_u64, 3, 5, 7, 11]
                .into_iter()
                .map(BlsDoryFr::from_u64)
                .collect(),
        )
        .unwrap();
        bridge.validate_activation(&activation).unwrap();

        let air = NarrowBlake3Air::new(&statement).unwrap();
        let main = generate_main_trace(&air, &statement, &witness);
        let preprocessed = air.preprocessed_trace().unwrap();
        let public = bls_values(public_values(&statement).unwrap());
        let old_main_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { main.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let accumulators = native_accumulator_trace(&air, &old_main_rows, &bridge);
        assert_eq!(NARROW_BLAKE3_MAIN_WIDTH, 291);
        assert_eq!(BLS_DORY_BLAKE3_MAIN_WIDTH, 289);
        assert_eq!(accumulators.last(), Some(&bridge.raw_byte_evaluation()));

        let original_constraints = bls_dory_blake3_constraint_ir(activation.len()).unwrap();
        assert_eq!(
            original_constraints
                .iter()
                .filter(|constraint| uses_old_evaluation_constraint(constraint))
                .count(),
            9
        );
        let constraints = bls_dory_native_blake3_constraint_ir(activation.len()).unwrap();
        assert_eq!(constraints.len(), 1_296);
        assert!(
            constraints
                .iter()
                .all(|constraint| !uses_removed_native_input(constraint))
        );

        let native_rows = old_main_rows
            .iter()
            .zip(&accumulators)
            .map(|(row, accumulator)| native_main_row(row, *accumulator))
            .collect::<Vec<_>>();
        for row in 0..air.trace_rows() {
            let next_row = (row + 1) % air.trace_rows();
            let preprocessed_local = bls_values(unsafe { preprocessed.row_unchecked(row) });
            let preprocessed_next = bls_values(unsafe { preprocessed.row_unchecked(next_row) });
            let first_row = BlsDoryFr::from_u64(u64::from(row == 0));
            let last_row = BlsDoryFr::from_u64(u64::from(row + 1 == air.trace_rows()));
            let transition = BlsDoryFr::from_u64(u64::from(row + 1 != air.trace_rows()));
            let values = BlsDoryBlake3Evaluation {
                main_local: &native_rows[row],
                main_next: &native_rows[next_row],
                preprocessed_local: &preprocessed_local,
                preprocessed_next: &preprocessed_next,
                public: &public,
                periodic: &[],
                first_row,
                last_row,
                transition,
            };
            for (constraint_index, constraint) in constraints.iter().enumerate() {
                assert_eq!(
                    constraint.evaluate(&values),
                    BlsDoryFr::zero(),
                    "native constraint {constraint_index} failed at row {row}"
                );
            }
            assert_eq!(
                native_evaluation_residuals(
                    &BlsDoryNativeEvaluationRow {
                        main_local: &native_rows[row],
                        main_next: &native_rows[next_row],
                        first_row,
                        last_row,
                        transition,
                    },
                    air.activation_group_index_at_row(row),
                    bridge.cell_point(),
                    bridge.raw_byte_evaluation(),
                ),
                [BlsDoryFr::zero(); 3],
                "native evaluation relation failed at row {row}"
            );
        }

        let mut changed_first = native_rows[0].clone();
        changed_first[NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START] = BlsDoryFr::from_u64(1);
        assert_ne!(
            native_evaluation_residuals(
                &BlsDoryNativeEvaluationRow {
                    main_local: &changed_first,
                    main_next: &native_rows[1],
                    first_row: BlsDoryFr::from_u64(1),
                    last_row: BlsDoryFr::zero(),
                    transition: BlsDoryFr::from_u64(1),
                },
                air.activation_group_index_at_row(0),
                bridge.cell_point(),
                bridge.raw_byte_evaluation(),
            ),
            [BlsDoryFr::zero(); 3]
        );

        let activation_row = (0..air.trace_rows())
            .find(|row| air.activation_group_index_at_row(*row).is_some())
            .unwrap();
        let mut changed_byte = native_rows[activation_row].clone();
        changed_byte[NARROW_BLAKE3_ORIGINAL_NIBBLES_START] =
            changed_byte[NARROW_BLAKE3_ORIGINAL_NIBBLES_START] + BlsDoryFr::from_u64(1);
        assert_ne!(
            native_evaluation_residuals(
                &BlsDoryNativeEvaluationRow {
                    main_local: &changed_byte,
                    main_next: &native_rows[activation_row + 1],
                    first_row: BlsDoryFr::zero(),
                    last_row: BlsDoryFr::zero(),
                    transition: BlsDoryFr::from_u64(1),
                },
                air.activation_group_index_at_row(activation_row),
                bridge.cell_point(),
                bridge.raw_byte_evaluation(),
            ),
            [BlsDoryFr::zero(); 3]
        );

        let mut changed_point = bridge.cell_point().to_vec();
        changed_point[0] = changed_point[0] + BlsDoryFr::from_u64(1);
        let point_mutation_rejected = (0..air.trace_rows()).any(|row| {
            let next_row = (row + 1) % air.trace_rows();
            native_evaluation_residuals(
                &BlsDoryNativeEvaluationRow {
                    main_local: &native_rows[row],
                    main_next: &native_rows[next_row],
                    first_row: BlsDoryFr::from_u64(u64::from(row == 0)),
                    last_row: BlsDoryFr::from_u64(u64::from(row + 1 == air.trace_rows())),
                    transition: BlsDoryFr::from_u64(u64::from(row + 1 != air.trace_rows())),
                },
                air.activation_group_index_at_row(row),
                &changed_point,
                bridge.raw_byte_evaluation(),
            ) != [BlsDoryFr::zero(); 3]
        });
        assert!(point_mutation_rejected);

        let last_row = air.trace_rows() - 1;
        assert_ne!(
            native_evaluation_residuals(
                &BlsDoryNativeEvaluationRow {
                    main_local: &native_rows[last_row],
                    main_next: &native_rows[0],
                    first_row: BlsDoryFr::zero(),
                    last_row: BlsDoryFr::from_u64(1),
                    transition: BlsDoryFr::zero(),
                },
                air.activation_group_index_at_row(last_row),
                bridge.cell_point(),
                bridge.raw_byte_evaluation() + BlsDoryFr::from_u64(1),
            ),
            [BlsDoryFr::zero(); 3]
        );

        let preprocessed_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { preprocessed.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let tables = dense_execution_tables(&native_rows, &preprocessed_rows);
        let proof = prove_dense_execution_sumcheck(
            tables.clone(),
            &air,
            &public,
            &constraints,
            &bridge,
            &[],
        );
        assert_eq!(proof.rounds.len(), 8);
        assert!(
            proof
                .rounds
                .iter()
                .all(|round| round.len() == DENSE_EXECUTION_SUMCHECK_DEGREE + 1)
        );
        assert_eq!(
            proof.terminal_evaluations.len(),
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
        );
        assert!(verify_dense_execution_sumcheck(
            &proof,
            &air,
            &public,
            &constraints,
            &bridge,
            &[],
        ));

        let mut changed_round = proof.clone();
        changed_round.rounds[0][0] = changed_round.rounds[0][0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_execution_sumcheck(
            &changed_round,
            &air,
            &public,
            &constraints,
            &bridge,
            &[],
        ));

        let mut changed_terminal = proof.clone();
        changed_terminal.terminal_evaluations[0] =
            changed_terminal.terminal_evaluations[0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_execution_sumcheck(
            &changed_terminal,
            &air,
            &public,
            &constraints,
            &bridge,
            &[],
        ));

        let adjacency_tables = dense_adjacency_source_tables(&tables);
        let adjacency =
            prove_dense_adjacency_sumcheck(adjacency_tables.clone(), &bridge, &[], &[]).unwrap();
        assert_eq!(adjacency.rounds.len(), 8);
        assert!(
            adjacency
                .rounds
                .iter()
                .all(|round| round.len() == DENSE_ADJACENCY_SUMCHECK_DEGREE + 1)
        );
        assert_eq!(
            adjacency.terminal_evaluations.len(),
            BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS
        );
        assert!(verify_dense_adjacency_sumcheck(
            &adjacency,
            air.trace_rows(),
            &bridge,
            &[],
            &[],
        ));

        let mut changed_adjacency_round = adjacency.clone();
        changed_adjacency_round.rounds[0][0] =
            changed_adjacency_round.rounds[0][0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_adjacency_sumcheck(
            &changed_adjacency_round,
            air.trace_rows(),
            &bridge,
            &[],
            &[],
        ));

        let mut changed_adjacency_terminal = adjacency.clone();
        changed_adjacency_terminal.terminal_evaluations[0] =
            changed_adjacency_terminal.terminal_evaluations[0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_adjacency_sumcheck(
            &changed_adjacency_terminal,
            air.trace_rows(),
            &bridge,
            &[],
            &[],
        ));

        let next_start = BLS_DORY_BLAKE3_MAIN_WIDTH;
        let mut substituted_next = adjacency_tables.clone();
        substituted_next[next_start][7] = substituted_next[next_start][7] + BlsDoryFr::from_u64(1);
        assert!(prove_dense_adjacency_sumcheck(substituted_next, &bridge, &[], &[]).is_none());

        let mut reordered_next = adjacency_tables.clone();
        for table in &mut reordered_next[next_start..] {
            table.swap(4, 5);
        }
        assert!(prove_dense_adjacency_sumcheck(reordered_next, &bridge, &[], &[]).is_none());

        let mut duplicated_next = adjacency_tables.clone();
        for table in &mut duplicated_next[next_start..] {
            table[9] = table[8];
        }
        assert!(prove_dense_adjacency_sumcheck(duplicated_next, &bridge, &[], &[]).is_none());

        let mut changed_boundary = adjacency_tables;
        let final_row = air.trace_rows() - 1;
        changed_boundary[next_start][final_row] =
            changed_boundary[next_start][final_row] + BlsDoryFr::from_u64(1);
        assert!(prove_dense_adjacency_sumcheck(changed_boundary, &bridge, &[], &[]).is_none());
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn blake3_streamed_source_rejects_failed_short_and_malformed_rows() {
        const TRACE_ROWS: usize = 1 << 3;
        const SELECTOR_SLOTS: usize = 1 << 3;
        let tables = (0..5)
            .map(|selector| {
                (0..TRACE_ROWS)
                    .map(|row| BlsDoryFr::from_u64((selector * TRACE_ROWS + row + 1) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(6).unwrap();
        let scratch = Blake3ScratchDirectory::create();

        let mut failed = DensePackedTableRowSource::new(&tables, TRACE_ROWS, SELECTOR_SLOTS);
        failed.fail_at = Some(1);
        assert!(matches!(
            commit_bls_dory_row_source_with_scratch(&mut failed, 3, 3, &setup, &scratch.0,),
            Err(BlsDoryAggregateError::CoefficientSource)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut short = DensePackedTableRowSource::new(&tables, TRACE_ROWS, SELECTOR_SLOTS);
        short.short_at = Some(0);
        assert!(matches!(
            commit_bls_dory_row_source_with_scratch(&mut short, 3, 3, &setup, &scratch.0,),
            Err(BlsDoryAggregateError::InvalidCoefficientCount)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut malformed_tables = tables;
        malformed_tables[0].pop();
        let mut malformed =
            DensePackedTableRowSource::new(&malformed_tables, TRACE_ROWS, SELECTOR_SLOTS);
        assert!(matches!(
            commit_bls_dory_row_source_with_scratch(&mut malformed, 3, 3, &setup, &scratch.0,),
            Err(BlsDoryAggregateError::CoefficientSource)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "the exact 16-variable Dory commitment and opening comparison is intentionally expensive"]
    fn blake3_streamed_source_preserves_commitment_and_exact_opening_bytes() {
        const TRACE_VARIABLES: usize = 8;
        const SELECTOR_VARIABLES: usize = 8;
        const TRACE_ROWS: usize = 1 << TRACE_VARIABLES;
        const SELECTOR_SLOTS: usize = 1 << SELECTOR_VARIABLES;
        let tables = (0..137)
            .map(|selector| {
                (0..TRACE_ROWS)
                    .map(|row| {
                        BlsDoryFr::from_u64(
                            ((selector as u64 + 3) * 65_537 + (row as u64 + 5) * 257) % 65_521,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let materialized = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&tables, TRACE_ROWS, SELECTOR_SLOTS).unwrap(),
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
        )
        .unwrap();
        let mut source = DensePackedTableRowSource::new(&tables, TRACE_ROWS, SELECTOR_SLOTS);
        let streamed = commit_bls_dory_row_source_with_scratch(
            &mut source,
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(source.reads, tables.len());
        assert_eq!(streamed.commitment(), materialized.commitment());

        let points = vec![
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 2) * 7))
                .collect::<Vec<_>>(),
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 3) * 11))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"blake3-row-source-equivalence",
            dense_aggregate_layout(),
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_backed = prove_bls_dory_same_commitment_openings(
            b"blake3-row-source-equivalence",
            dense_aggregate_layout(),
            &streamed,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(artifact_backed, ordinary);
        verify_bls_dory_openings(
            b"blake3-row-source-equivalence",
            dense_aggregate_layout(),
            &artifact_backed.0,
            &artifact_backed.1,
            &setup,
        )
        .unwrap();

        let artifact_path = std::fs::read_dir(&scratch.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut artifact = std::fs::OpenOptions::new()
            .write(true)
            .open(artifact_path)
            .unwrap();
        artifact.seek(SeekFrom::Start(100)).unwrap();
        artifact.write_all(&[0xff]).unwrap();
        artifact.flush().unwrap();
        drop(artifact);
        assert_eq!(
            prove_bls_dory_same_commitment_openings(
                b"blake3-row-source-corruption",
                dense_aggregate_layout(),
                &streamed,
                &points,
                &setup,
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        drop(streamed);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "the exact 16-variable compact Dory comparison is intentionally expensive"]
    fn blake3_signed_word_source_preserves_commitment_and_opening_bytes() {
        const TRACE_VARIABLES: usize = 8;
        const SELECTOR_VARIABLES: usize = 8;
        const TRACE_ROWS: usize = 1 << TRACE_VARIABLES;
        const SELECTOR_SLOTS: usize = 1 << SELECTOR_VARIABLES;
        const TABLES_PER_DIRECTION: usize = BLS_DORY_BLAKE3_MAIN_WIDTH - 1;
        const MAX_BATCH_TABLES: usize = SELECTOR_SLOTS / 2;
        let fixture = dense_blake3_fixture();
        let native_statement = native_blake3_statement_from_bridge(&fixture.bridge);
        let native_air = NarrowBlake3Air::new(&native_statement).unwrap();
        assert_eq!(native_air.trace_rows(), TRACE_ROWS);
        let ordinary_native_columns = (0..BLS_DORY_BLAKE3_MAIN_WIDTH)
            .filter(|column| *column != NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START)
            .collect::<Vec<_>>();
        assert_eq!(ordinary_native_columns.len(), TABLES_PER_DIRECTION);
        let next_start = BLS_DORY_BLAKE3_MAIN_WIDTH;
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(
            TRACE_VARIABLES + SELECTOR_VARIABLES,
        )
        .unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let points = vec![
            (0..(TRACE_VARIABLES + SELECTOR_VARIABLES))
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 5) * 13))
                .collect::<Vec<_>>(),
            (0..(TRACE_VARIABLES + SELECTOR_VARIABLES))
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 7) * 17))
                .collect::<Vec<_>>(),
        ];
        let mut covered_tables = 0;
        for batch_start in (0..TABLES_PER_DIRECTION).step_by(MAX_BATCH_TABLES) {
            let batch_end = batch_start
                .saturating_add(MAX_BATCH_TABLES)
                .min(TABLES_PER_DIRECTION);
            let batch_columns = &ordinary_native_columns[batch_start..batch_end];
            let field_tables = batch_columns
                .iter()
                .map(|column| fixture.tables[*column].clone())
                .chain(
                    batch_columns
                        .iter()
                        .map(|column| fixture.tables[next_start + *column].clone()),
                )
                .collect::<Vec<_>>();
            let materialized = commit_bls_dory_polynomial(
                dense_pack_adjacency_tables(&field_tables, TRACE_ROWS, SELECTOR_SLOTS).unwrap(),
                SELECTOR_VARIABLES,
                TRACE_VARIABLES,
                &setup,
            )
            .unwrap();
            let mut transpose_writer =
                BlsDoryWordTransposeWriter::create(&scratch.0, TRACE_ROWS, batch_columns.len(), 17)
                    .unwrap();
            for_each_main_trace_row(
                &native_air,
                &native_statement,
                &fixture.witness,
                |row_index, row| {
                    let centered = row
                        .iter()
                        .enumerate()
                        .filter(|(column, _)| {
                            !(NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START..NARROW_BLAKE3_STACK_START)
                                .contains(column)
                        })
                        .map(|(_, value)| centered_goldilocks(*value))
                        .collect::<Vec<_>>();
                    assert_eq!(centered.len(), TABLES_PER_DIRECTION);
                    let batch = &centered[batch_start..batch_end];
                    for (column, value) in batch.iter().copied().enumerate() {
                        assert_eq!(field_tables[column][row_index], BlsDoryFr::from_i64(value));
                    }
                    let values = batch
                        .iter()
                        .map(|value| u64::from_le_bytes(value.to_le_bytes()))
                        .collect::<Vec<_>>();
                    transpose_writer.write_row(&values)
                },
            )
            .unwrap();
            let mut transpose = transpose_writer.finish().unwrap();
            transpose.authenticate().unwrap();
            let compact = {
                let mut source =
                    TransposedLocalNextSignedWordRowSource::new(&mut transpose, SELECTOR_SLOTS);
                commit_bls_dory_compact_row_source_with_scratch(
                    &mut source,
                    SELECTOR_VARIABLES,
                    TRACE_VARIABLES,
                    &setup,
                    &scratch.0,
                )
                .unwrap()
            };
            drop(transpose);
            assert_eq!(compact.commitment(), materialized.commitment());
            let artifact_path = std::fs::read_dir(&scratch.0)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let compact_bytes = std::fs::metadata(artifact_path).unwrap().len();
            let literal_bytes = (field_tables.len() * TRACE_ROWS * 32) as u64;
            assert!(compact_bytes * 3 < literal_bytes);

            let mut binding = b"blake3-compact-source-equivalence".to_vec();
            binding.extend_from_slice(&(batch_start as u64).to_le_bytes());
            let ordinary = prove_bls_dory_same_commitment_openings(
                &binding,
                dense_aggregate_layout(),
                &materialized,
                &points,
                &setup,
            )
            .unwrap();
            let artifact_backed = prove_bls_dory_same_commitment_openings(
                &binding,
                dense_aggregate_layout(),
                &compact,
                &points,
                &setup,
            )
            .unwrap();
            assert_eq!(artifact_backed, ordinary);
            verify_bls_dory_openings(
                &binding,
                dense_aggregate_layout(),
                &artifact_backed.0,
                &artifact_backed.1,
                &setup,
            )
            .unwrap();
            covered_tables += batch_columns.len();
            drop(compact);
            assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        }
        assert_eq!(covered_tables, TABLES_PER_DIRECTION);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn lifted_transposed_source_reblocks_flat_prefix_and_wraps_next_rows() {
        const TRACE_ROWS: usize = 1 << 3;
        const SOURCE_COLUMNS: usize = 2;
        let shared_layout = BlsDoryAggregateLayout::new(1, 4).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let mut writer =
            BlsDoryWordTransposeWriter::create(&scratch.0, TRACE_ROWS, SOURCE_COLUMNS, 4).unwrap();
        for row in 0..TRACE_ROWS {
            writer
                .write_row(&[100 + row as u64, 200 + row as u64])
                .unwrap();
        }
        let mut artifact = writer.finish().unwrap();
        artifact.authenticate().unwrap();

        {
            let mut source = TransposedLocalNextSignedWordRowSource::new_for_layout(
                &mut artifact,
                shared_layout,
            )
            .unwrap();
            assert_eq!(source.rows(), 2);
            assert_eq!(source.columns(), 16);
            assert_eq!(source.explicit_scalar_count(), 32);
            assert_eq!(source.word_group_len(), TRACE_ROWS);
            assert_eq!(source.signed_word_selectors(), 0b1111);

            let mut row = vec![0; source.columns()];
            source.read_word_row(0, &mut row).unwrap();
            assert_eq!(row, (100..108).chain(200..208).collect::<Vec<_>>());
            source.read_word_row(1, &mut row).unwrap();
            assert_eq!(
                row,
                [101, 102, 103, 104, 105, 106, 107, 100]
                    .into_iter()
                    .chain([201, 202, 203, 204, 205, 206, 207, 200])
                    .collect::<Vec<_>>()
            );
            assert!(source.read_word_row(2, &mut row).is_err());
            assert!(source.read_word_row(0, &mut row[..15]).is_err());
        }
        drop(artifact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "cryptographic equivalence regression; run explicitly in --release"]
    fn signed_word_source_lifts_exactly_into_shared_layout_geometry() {
        const TRACE_ROWS: usize = 1 << 8;
        const SOURCE_COLUMNS: usize = 2;
        let source_layout = BlsDoryAggregateLayout::new(2, 8).unwrap();
        let shared_layout = BlsDoryAggregateLayout::new(5, 7).unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let mut local_tables = (0..SOURCE_COLUMNS)
            .map(|_| Vec::with_capacity(TRACE_ROWS))
            .collect::<Vec<_>>();
        let mut transpose_writer =
            BlsDoryWordTransposeWriter::create(&scratch.0, TRACE_ROWS, SOURCE_COLUMNS, 17).unwrap();
        for row in 0..TRACE_ROWS {
            let signed = (0..SOURCE_COLUMNS)
                .map(|column| ((row * 19 + column * 37) % 201) as i64 - 100)
                .collect::<Vec<_>>();
            for (table, value) in local_tables.iter_mut().zip(signed.iter().copied()) {
                table.push(BlsDoryFr::from_i64(value));
            }
            transpose_writer
                .write_row(
                    &signed
                        .iter()
                        .map(|value| u64::from_le_bytes(value.to_le_bytes()))
                        .collect::<Vec<_>>(),
                )
                .unwrap();
        }
        let logical_tables = local_tables
            .iter()
            .cloned()
            .chain(local_tables.iter().map(|table| {
                table[1..]
                    .iter()
                    .chain(&table[..1])
                    .copied()
                    .collect::<Vec<_>>()
            }))
            .collect::<Vec<_>>();
        let source_coefficients = logical_tables.iter().flatten().copied().collect::<Vec<_>>();
        let original = commit_bls_dory_polynomial(
            source_coefficients.clone(),
            source_layout.nu(),
            source_layout.sigma(),
            &setup,
        )
        .unwrap();
        let mut padded_coefficients = source_coefficients;
        padded_coefficients.resize(1 << shared_layout.variables(), BlsDoryFr::zero());
        let materialized = commit_bls_dory_polynomial(
            padded_coefficients,
            shared_layout.nu(),
            shared_layout.sigma(),
            &setup,
        )
        .unwrap();

        let mut transpose = transpose_writer.finish().unwrap();
        transpose.authenticate().unwrap();
        let compact = {
            let mut source = TransposedLocalNextSignedWordRowSource::new_for_layout(
                &mut transpose,
                shared_layout,
            )
            .unwrap();
            commit_bls_dory_compact_row_source_with_scratch(
                &mut source,
                shared_layout.nu(),
                shared_layout.sigma(),
                &setup,
                &scratch.0,
            )
            .unwrap()
        };
        drop(transpose);
        assert_eq!(compact.commitment(), materialized.commitment());

        let source_points = vec![
            (0..source_layout.variables())
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 13) * 17))
                .collect::<Vec<_>>(),
            (0..source_layout.variables())
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 19) * 23))
                .collect::<Vec<_>>(),
        ];
        let shared_points = source_points
            .iter()
            .map(|point| {
                let mut lifted = point.clone();
                lifted.resize(shared_layout.variables(), BlsDoryFr::zero());
                lifted
            })
            .collect::<Vec<_>>();
        let original_opening = prove_bls_dory_same_commitment_openings(
            b"blake3-signed-source-original-geometry",
            source_layout,
            &original,
            &source_points,
            &setup,
        )
        .unwrap();
        let materialized_opening = prove_bls_dory_same_commitment_openings(
            b"blake3-signed-source-shared-lift",
            shared_layout,
            &materialized,
            &shared_points,
            &setup,
        )
        .unwrap();
        let compact_opening = prove_bls_dory_same_commitment_openings(
            b"blake3-signed-source-shared-lift",
            shared_layout,
            &compact,
            &shared_points,
            &setup,
        )
        .unwrap();
        assert_eq!(compact_opening, materialized_opening);
        assert_eq!(
            original_opening
                .0
                .iter()
                .map(|claim| claim.evaluation)
                .collect::<Vec<_>>(),
            compact_opening
                .0
                .iter()
                .map(|claim| claim.evaluation)
                .collect::<Vec<_>>()
        );
        verify_bls_dory_openings(
            b"blake3-signed-source-shared-lift",
            shared_layout,
            &compact_opening.0,
            &compact_opening.1,
            &setup,
        )
        .unwrap();
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "cryptographic equivalence regression; run explicitly in --release"]
    fn preprocessed_source_lifts_exactly_into_shared_layout_geometry() {
        const TRACE_ROWS: usize = 1 << 4;
        let shared_layout = BlsDoryAggregateLayout::new(6, 6).unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(12).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let mut local_tables = (0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
            .map(|_| Vec::with_capacity(TRACE_ROWS))
            .collect::<Vec<_>>();
        let mut transpose_writer = BlsDoryWordTransposeWriter::create(
            &scratch.0,
            TRACE_ROWS,
            BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
            8,
        )
        .unwrap();
        for row in 0..TRACE_ROWS {
            let values = (0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
                .map(|column| {
                    if NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.contains(&column) {
                        (row * 1_009 + column * 97 + 11) as u64
                    } else {
                        ((row + column) & 1) as u64
                    }
                })
                .collect::<Vec<_>>();
            for (table, value) in local_tables.iter_mut().zip(values.iter().copied()) {
                table.push(BlsDoryFr::from_u64(value));
            }
            transpose_writer.write_row(&values).unwrap();
        }

        let mut coefficients = Vec::with_capacity(1 << shared_layout.variables());
        for physical_slot in 0..2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
            let (direction, column) = preprocessed_physical_role(physical_slot).unwrap();
            if direction == 0 {
                coefficients.extend_from_slice(&local_tables[column]);
            } else {
                coefficients.extend_from_slice(&local_tables[column][1..]);
                coefficients.push(local_tables[column][0]);
            }
        }
        coefficients.resize(1 << shared_layout.variables(), BlsDoryFr::zero());
        let materialized = commit_bls_dory_polynomial(
            coefficients,
            shared_layout.nu(),
            shared_layout.sigma(),
            &setup,
        )
        .unwrap();

        let mut transpose = transpose_writer.finish().unwrap();
        transpose.authenticate().unwrap();
        let compact = {
            let mut source =
                TransposedPreprocessedRowSource::new_for_layout(&mut transpose, shared_layout)
                    .unwrap();
            commit_bls_dory_compact_row_source_with_scratch(
                &mut source,
                shared_layout.nu(),
                shared_layout.sigma(),
                &setup,
                &scratch.0,
            )
            .unwrap()
        };
        drop(transpose);
        assert_eq!(compact.commitment(), materialized.commitment());

        let points = vec![
            (0..shared_layout.variables())
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 31) * 37))
                .collect::<Vec<_>>(),
            (0..shared_layout.variables())
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 41) * 43))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"blake3-preprocessed-source-shared-lift",
            shared_layout,
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_backed = prove_bls_dory_same_commitment_openings(
            b"blake3-preprocessed-source-shared-lift",
            shared_layout,
            &compact,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(artifact_backed, ordinary);
        verify_bls_dory_openings(
            b"blake3-preprocessed-source-shared-lift",
            shared_layout,
            &artifact_backed.0,
            &artifact_backed.1,
            &setup,
        )
        .unwrap();
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn native_accumulator_stream_matches_materialized_local_and_next() {
        let fixture = dense_blake3_fixture();
        let native_statement = native_blake3_statement_from_bridge(&fixture.bridge);
        let native_air = NarrowBlake3Air::new(&native_statement).unwrap();
        let local_table = NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START;
        let next_table = BLS_DORY_BLAKE3_MAIN_WIDTH + local_table;
        let mut visited = 0usize;
        for_each_native_accumulator_pair(
            &native_air,
            &native_statement,
            &fixture.witness,
            &fixture.bridge,
            |row_index, local, next| {
                assert_eq!(local, fixture.tables[local_table][row_index]);
                assert_eq!(next, fixture.tables[next_table][row_index]);
                visited += 1;
                Ok::<_, std::convert::Infallible>(())
            },
        )
        .unwrap();
        assert_eq!(visited, fixture.air.trace_rows());
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn native_accumulator_source_builder_preserves_commitment_and_opening_bytes() {
        const TRACE_ROWS: usize = 1 << 8;
        let fixture = dense_blake3_fixture();
        assert_eq!(fixture.air.trace_rows(), TRACE_ROWS);
        let local_table = NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START;
        let next_table = BLS_DORY_BLAKE3_MAIN_WIDTH + local_table;
        let field_tables = vec![
            fixture.tables[local_table].clone(),
            fixture.tables[next_table].clone(),
        ];
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(9).unwrap();
        let layout = BlsDoryAggregateLayout::new(4, 5).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let materialized = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&field_tables, TRACE_ROWS, 2).unwrap(),
            layout.nu(),
            layout.sigma(),
            &setup,
        )
        .unwrap();
        let mut wrong_activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        wrong_activation[0] ^= 1;
        let wrong_bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            fixture.bridge.challenge_digest(),
            fixture.bridge.final_activation_digest(),
            &wrong_activation,
            fixture.bridge.transcript_binding(),
            fixture.bridge.cell_point().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            commit_native_accumulator_source(
                &fixture.witness,
                &wrong_bridge,
                layout,
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let streamed = commit_native_accumulator_source(
            &fixture.witness,
            &fixture.bridge,
            layout,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(streamed.commitment(), materialized.commitment());

        let points = vec![
            (0..layout.variables())
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 23) * 37))
                .collect::<Vec<_>>(),
            (0..layout.variables())
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 29) * 41))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"blake3-native-accumulator-source-equivalence",
            layout,
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_backed = prove_bls_dory_same_commitment_openings(
            b"blake3-native-accumulator-source-equivalence",
            layout,
            &streamed,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(artifact_backed, ordinary);
        verify_bls_dory_openings(
            b"blake3-native-accumulator-source-equivalence",
            layout,
            &artifact_backed.0,
            &artifact_backed.1,
            &setup,
        )
        .unwrap();
        drop(streamed);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn bounded_batch_inversion_crosses_chunks_and_rejects_late_zero() {
        let values = (1..=BLS_DORY_BLAKE3_INVERSE_BATCH_SCALARS + 3)
            .map(|value| BlsDoryFr::from_u64(value as u64))
            .collect::<Vec<_>>();
        let mut inverses = values.clone();
        batch_invert_nonzero(&mut inverses).unwrap();
        assert!(
            values
                .iter()
                .zip(&inverses)
                .all(|(value, inverse)| *value * *inverse == BlsDoryFr::from_u64(1))
        );

        let mut with_late_zero = values;
        with_late_zero[BLS_DORY_BLAKE3_INVERSE_BATCH_SCALARS + 1] = BlsDoryFr::zero();
        assert_eq!(batch_invert_nonzero(&mut with_late_zero), None);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn named_adjacency_challenges_match_the_canonical_transcript_order() {
        let fixture = dense_blake3_fixture();
        let layout = BlsDoryAggregateLayout::new(1, 1).unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(2).unwrap();
        let commitments: [BlsDoryGt; BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS] =
            std::array::from_fn(|source| {
                commit_bls_dory_polynomial(
                    (0..4)
                        .map(|index| {
                            BlsDoryFr::from_u64((source as u64 + 3) * 101 + index as u64 * 7)
                        })
                        .collect(),
                    layout.nu(),
                    layout.sigma(),
                    &setup,
                )
                .unwrap()
                .commitment()
            });
        let named = BlsDoryBlake3AdjacencySourceCommitments {
            main: commitments[0],
            accumulator: commitments[1],
            preprocessing: commitments[2],
        };
        let derived = derive_native_blake3_adjacency_challenges(
            &fixture.bridge,
            fixture.air.trace_rows(),
            named.clone(),
        )
        .unwrap();
        let mut reference = BlsDoryTranscript::new(b"blake3-native-row-adjacency-sumcheck-v2");
        reference.append_bytes(b"protocol-version", &2_u16.to_le_bytes());
        reference.append_bytes(b"challenge-digest", &fixture.bridge.challenge_digest());
        reference.append_bytes(
            b"activation-length",
            &(fixture.bridge.final_activation_len() as u64).to_le_bytes(),
        );
        reference.append_bytes(
            b"activation-digest",
            &fixture.bridge.final_activation_digest(),
        );
        reference.append_bytes(b"dory-binding", &fixture.bridge.transcript_binding());
        reference.append_bytes(
            b"trace-rows",
            &(fixture.air.trace_rows() as u64).to_le_bytes(),
        );
        reference.append_bytes(
            b"main-width",
            &(BLS_DORY_BLAKE3_MAIN_WIDTH as u64).to_le_bytes(),
        );
        reference.append_bytes(
            b"source-count",
            &(BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS as u64).to_le_bytes(),
        );
        for ((role, terminal_count), commitment) in [
            BlsDoryBlake3SourceRole::Main,
            BlsDoryBlake3SourceRole::Accumulator,
            BlsDoryBlake3SourceRole::Preprocessing,
        ]
        .into_iter()
        .zip(BLS_DORY_BLAKE3_EXECUTION_SOURCE_TERMINALS)
        .zip(&commitments)
        {
            append_native_blake3_source_descriptor(
                &mut reference,
                role,
                terminal_count,
                commitment,
            );
        }
        assert_eq!(
            derived,
            (
                reference.challenge_scalar(b"row-compression"),
                reference.challenge_scalar(b"lookup-alpha"),
            )
        );

        let swapped = derive_native_blake3_adjacency_challenges(
            &fixture.bridge,
            fixture.air.trace_rows(),
            BlsDoryBlake3AdjacencySourceCommitments {
                main: named.accumulator,
                accumulator: named.main,
                preprocessing: named.preprocessing,
            },
        )
        .unwrap();
        assert_ne!(swapped, derived);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "full four-source construction; run explicitly in --release"]
    fn native_blake3_source_bundle_constructs_named_authenticated_sources() {
        let fixture = dense_blake3_fixture();
        let layout = BlsDoryAggregateLayout::new(9, 9).unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(18).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        assert!(matches!(
            commit_native_blake3_sources(&fixture.witness, &fixture.bridge, &setup, &scratch.0,),
            Err(BlsDoryAggregateError::InvalidProofShape)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let undersized_setup =
            crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(2).unwrap();
        assert!(matches!(
            commit_native_blake3_sources_at_layout(
                &fixture.witness,
                &fixture.bridge,
                layout,
                &undersized_setup,
                &scratch.0,
            ),
            Err(BlsDoryAggregateError::InvalidDimension)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let sources = commit_native_blake3_sources_at_layout(
            &fixture.witness,
            &fixture.bridge,
            layout,
            &setup,
            &scratch.0,
        )
        .unwrap();
        sources
            .validate_layout(fixture.air.trace_rows(), layout, &setup)
            .unwrap();
        let expected = [
            fixture.air.trace_rows() * BLS_DORY_BLAKE3_SIGNED_WORD_TABLES,
            fixture.air.trace_rows() * BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES,
            fixture.air.trace_rows()
                * (BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
                    + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES),
            fixture.air.trace_rows() * BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES,
        ];
        let commitments = BLS_DORY_BLAKE3_SOURCE_ROLES.map(|role| {
            let source = sources.source(role);
            assert_eq!(source.explicit_coefficient_count(), expected[role.index()]);
            assert!(source.matches_layout(layout, &setup));
            source.commitment()
        });
        for (index, commitment) in commitments.iter().enumerate() {
            assert!(
                commitments
                    .iter()
                    .skip(index + 1)
                    .all(|other| other != commitment)
            );
        }
        drop(sources);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn prepared_native_sources_retain_authenticated_transposes_without_changing_commitments() {
        let scratch = Blake3ScratchDirectory::create();
        let BoundedPreparedSourceFixture {
            mut prepared,
            main_rows,
            preprocessing_rows,
            layout,
            setup,
        } = bounded_prepared_source_bundle(&scratch.0, false).unwrap();
        prepared.validate(16, layout, &setup).unwrap();
        let main_path = prepared.main_transpose.path().to_path_buf();
        let preprocessing_path = prepared.preprocessing_transpose.path().to_path_buf();
        assert!(main_path.is_file());
        assert!(preprocessing_path.is_file());

        {
            let mut main_source = TransposedLocalNextSignedWordRowSource::new_for_layout(
                &mut prepared.main_transpose,
                layout,
            )
            .unwrap();
            let mut actual = vec![0; main_source.columns()];
            main_source.read_word_row(0, &mut actual).unwrap();
            let mut expected_local = Vec::new();
            for column in 0..8 {
                expected_local.extend(main_rows.iter().map(|row| row[column]));
            }
            assert_eq!(actual, expected_local);
            main_source.read_word_row(36, &mut actual).unwrap();
            let mut expected_next = Vec::new();
            for column in 0..8 {
                expected_next.extend(
                    main_rows
                        .iter()
                        .cycle()
                        .skip(1)
                        .take(16)
                        .map(|row| row[column]),
                );
            }
            assert_eq!(actual, expected_next);
        }

        {
            let mut preprocessing_source = TransposedPreprocessedRowSource::new_for_layout(
                &mut prepared.preprocessing_transpose,
                layout,
            )
            .unwrap();
            let mut actual_words = vec![0; preprocessing_source.columns()];
            preprocessing_source
                .read_word_row(0, &mut actual_words)
                .unwrap();
            let mut expected_words = Vec::new();
            for slot in 0..BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES {
                let (direction, column) = preprocessed_physical_role(slot).unwrap();
                for row in 0..16 {
                    expected_words.push(preprocessing_rows[(row + direction) % 16][column]);
                }
            }
            assert_eq!(actual_words, expected_words);
            let mut actual_codes = vec![0; preprocessing_source.columns()];
            preprocessing_source
                .read_code_row(1, &mut actual_codes)
                .unwrap();
            let mut expected_codes = Vec::new();
            for slot in BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES
                ..BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES + 8
            {
                let (direction, column) = preprocessed_physical_role(slot).unwrap();
                for row in 0..16 {
                    expected_codes.push(preprocessing_rows[(row + direction) % 16][column] as u8);
                }
            }
            assert_eq!(actual_codes, expected_codes);
        }

        let commitments_before = prepared.commitments();
        let sources = prepared.into_committed_sources().unwrap();
        assert_eq!(sources.commitments(), commitments_before);
        assert!(!main_path.exists());
        assert!(!preprocessing_path.exists());
        assert!(std::fs::read_dir(&scratch.0).unwrap().count() > 0);
        drop(sources);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn prepared_native_source_binding_and_drop_are_fail_closed() {
        let scratch = Blake3ScratchDirectory::create();
        let BoundedPreparedSourceFixture {
            mut prepared,
            layout,
            setup,
            ..
        } = bounded_prepared_source_bundle(&scratch.0, false).unwrap();
        let wrong_setup = deterministic_bls_dory_setup(layout.variables() + 1).unwrap();
        assert!(matches!(
            prepared.validate(16, layout, &wrong_setup),
            Err(BlsDoryAggregateError::InvalidDimension)
        ));
        let original_main = prepared.binding.source_commitments.main;
        prepared.binding.source_commitments.main = prepared.binding.source_commitments.accumulator;
        assert!(matches!(
            prepared.validate(16, layout, &setup),
            Err(BlsDoryAggregateError::InvalidDimension)
        ));
        prepared.binding.source_commitments.main = original_main;
        prepared.validate(16, layout, &setup).unwrap();
        drop(prepared);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn prepared_native_source_construction_cleans_every_artifact_on_authentication_failure() {
        let scratch = Blake3ScratchDirectory::create();
        assert!(matches!(
            bounded_prepared_source_bundle(&scratch.0, true),
            Err(BlsDoryAggregateError::ProverStorage)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn prepared_execution_rows_stream_exact_dense_order_across_blocks_and_wrap() {
        const BLOCK_ROWS: usize = 31;
        let fixture = dense_blake3_fixture();
        assert_eq!(fixture.air.trace_rows(), 1 << 8);
        let layout = BlsDoryAggregateLayout::new(9, 10).unwrap();
        let setup = deterministic_bls_dory_setup(layout.variables()).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let mut prepared = prepare_native_blake3_sources_at_layout(
            &fixture.witness,
            &fixture.bridge,
            layout,
            &setup,
            &scratch.0,
        )
        .unwrap();

        let mut seen = Vec::new();
        prepared
            .for_each_authenticated_execution_row(BLOCK_ROWS, |row, terminal| {
                assert_eq!(
                    terminal.len(),
                    BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
                );
                for (table, value) in fixture.tables.iter().zip(terminal) {
                    assert_eq!(*value, table[row], "terminal mismatch at row {row}");
                }
                if row + 1 == fixture.air.trace_rows() {
                    for column in 0..BLS_DORY_BLAKE3_MAIN_WIDTH {
                        assert_eq!(
                            terminal[BLS_DORY_BLAKE3_MAIN_WIDTH + column],
                            fixture.tables[column][0]
                        );
                    }
                    let preprocessing_local_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
                    let preprocessing_next_start =
                        preprocessing_local_start + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH;
                    for column in 0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
                        assert_eq!(
                            terminal[preprocessing_next_start + column],
                            fixture.tables[preprocessing_local_start + column][0]
                        );
                    }
                }
                seen.push(row);
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, (0..fixture.air.trace_rows()).collect::<Vec<_>>());
        for boundary in [
            BLOCK_ROWS - 1,
            BLOCK_ROWS,
            2 * BLOCK_ROWS - 1,
            2 * BLOCK_ROWS,
        ] {
            assert_eq!(seen[boundary], boundary);
        }

        drop(prepared);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn out_of_core_execution_sumcheck_matches_dense_v2_at_256_rows() {
        let fixture = dense_blake3_fixture();
        assert_eq!(fixture.air.trace_rows(), 1 << 8);
        let layout = BlsDoryAggregateLayout::new(9, 10).unwrap();
        let setup = deterministic_bls_dory_setup(layout.variables()).unwrap();
        let source_scratch = Blake3ScratchDirectory::create();
        let round_scratch = Blake3ScratchDirectory::create();
        let mut prepared = prepare_native_blake3_sources_at_layout(
            &fixture.witness,
            &fixture.bridge,
            layout,
            &setup,
            &source_scratch.0,
        )
        .unwrap();
        let commitments = prepared.commitments();
        let native_statement = native_blake3_statement_from_bridge(&fixture.bridge);
        let native_air = NarrowBlake3Air::new(&native_statement).unwrap();
        let native_public = native_blake3_public_values(&fixture.bridge).unwrap();
        let native_constraints =
            bls_dory_native_blake3_constraint_ir(fixture.bridge.final_activation_len()).unwrap();
        let dense = prove_dense_execution_sumcheck_with_transcript(
            fixture.tables.clone(),
            &native_air,
            &native_public,
            &native_constraints,
            &fixture.bridge,
            native_blake3_execution_transcript(&fixture.bridge, &commitments),
        );
        let expected = BlsDoryBlake3ExecutionSumcheckProof {
            rounds: dense.rounds,
            terminal_evaluations: dense.terminal_evaluations,
            transcript_digest: dense.transcript_digest,
        };

        let first = prove_native_blake3_execution_sumcheck_out_of_core(
            &mut prepared,
            &fixture.bridge,
            &round_scratch.0,
            31,
        )
        .unwrap();
        assert_eq!(first, expected);
        assert_eq!(std::fs::read_dir(&round_scratch.0).unwrap().count(), 0);
        let second = prove_native_blake3_execution_sumcheck_out_of_core(
            &mut prepared,
            &fixture.bridge,
            &round_scratch.0,
            17,
        )
        .unwrap();
        assert_eq!(second, first);
        assert_eq!(std::fs::read_dir(&round_scratch.0).unwrap().count(), 0);

        let execution_commitments = [
            *commitments.commitment(BlsDoryBlake3SourceRole::Main),
            *commitments.commitment(BlsDoryBlake3SourceRole::Accumulator),
            *commitments.commitment(BlsDoryBlake3SourceRole::Preprocessing),
        ];
        let encode = |proof: &BlsDoryBlake3ExecutionSumcheckProof| {
            encode_native_blake3_component(
                BLS_DORY_BLAKE3_EXECUTION_PROOF_MAGIC,
                &execution_commitments,
                &proof.rounds,
                BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1,
                &proof.terminal_evaluations,
                BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS,
                proof.transcript_digest,
                native_air.trace_rows().ilog2() as usize,
            )
            .unwrap()
        };
        let first_encoded = encode(&first);
        assert_eq!(first_encoded, encode(&expected));
        assert_eq!(first_encoded, encode(&second));
        let decoded = decode_native_blake3_component(
            &first_encoded,
            BLS_DORY_BLAKE3_EXECUTION_PROOF_MAGIC,
            BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS,
            native_air.trace_rows().ilog2() as usize,
            BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1,
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS,
        )
        .unwrap();
        assert_eq!(decoded.commitments, execution_commitments);
        assert_eq!(decoded.rounds, first.rounds);
        assert_eq!(decoded.terminal_evaluations, first.terminal_evaluations);
        assert_eq!(decoded.transcript_digest, first.transcript_digest);
        let verified = verify_native_blake3_execution_sumcheck(
            &first,
            &native_air,
            &native_public,
            &native_constraints,
            &fixture.bridge,
            &commitments,
        )
        .unwrap();
        assert_eq!(verified.point.len(), 8);
        assert_eq!(verified.transcript_digest, first.transcript_digest);

        drop(prepared);
        assert_eq!(std::fs::read_dir(&source_scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn out_of_core_execution_sumcheck_rejects_corrupt_source_without_scratch_leaks() {
        let fixture = dense_blake3_fixture();
        let layout = BlsDoryAggregateLayout::new(9, 10).unwrap();
        let setup = deterministic_bls_dory_setup(layout.variables()).unwrap();
        let source_scratch = Blake3ScratchDirectory::create();
        let round_scratch = Blake3ScratchDirectory::create();
        let mut prepared = prepare_native_blake3_sources_at_layout(
            &fixture.witness,
            &fixture.bridge,
            layout,
            &setup,
            &source_scratch.0,
        )
        .unwrap();
        flip_file_byte(prepared.main_transpose.path(), 100).unwrap();
        assert!(matches!(
            prove_native_blake3_execution_sumcheck_out_of_core(
                &mut prepared,
                &fixture.bridge,
                &round_scratch.0,
                31,
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        ));
        assert_eq!(std::fs::read_dir(&round_scratch.0).unwrap().count(), 0);
        drop(prepared);
        assert_eq!(std::fs::read_dir(&source_scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn prepared_adjacency_rows_match_dense_order_across_blocks_and_wrap() {
        let fixture = dense_blake3_fixture();
        assert_eq!(fixture.air.trace_rows(), 1 << 8);
        let layout = BlsDoryAggregateLayout::new(9, 10).unwrap();
        let setup = deterministic_bls_dory_setup(layout.variables()).unwrap();
        let source_scratch = Blake3ScratchDirectory::create();
        let mut prepared = prepare_native_blake3_sources_at_layout(
            &fixture.witness,
            &fixture.bridge,
            layout,
            &setup,
            &source_scratch.0,
        )
        .unwrap();
        let commitments = prepared.commitments();
        let source_tables = dense_adjacency_source_tables(&fixture.tables);
        let mut transcript = native_blake3_adjacency_transcript(
            &fixture.bridge,
            fixture.air.trace_rows(),
            &commitments.adjacency_sources(),
        )
        .unwrap();
        let compression = transcript.challenge_scalar(b"row-compression");
        let alpha = transcript.challenge_scalar(b"lookup-alpha");
        let inverse_tables =
            dense_adjacency_inverse_tables(&source_tables, compression, alpha).unwrap();
        let mut seen = Vec::new();

        prepared
            .for_each_authenticated_adjacency_row(31, |row, terminal| {
                for column in 0..2 * BLS_DORY_BLAKE3_MAIN_WIDTH {
                    assert_eq!(terminal[column], source_tables[column][row]);
                }
                assert_eq!(
                    terminal[2 * BLS_DORY_BLAKE3_MAIN_WIDTH],
                    inverse_tables[0][row]
                );
                assert_eq!(
                    terminal[2 * BLS_DORY_BLAKE3_MAIN_WIDTH + 1],
                    inverse_tables[1][row]
                );
                seen.push(row);
                Ok(())
            })
            .unwrap();

        assert_eq!(seen, (0..fixture.air.trace_rows()).collect::<Vec<_>>());
        for boundary in [30, 31, 61, 62, fixture.air.trace_rows() - 1] {
            assert_eq!(seen[boundary], boundary);
        }
        let final_row = fixture.air.trace_rows() - 1;
        for column in 0..BLS_DORY_BLAKE3_MAIN_WIDTH {
            assert_eq!(
                source_tables[BLS_DORY_BLAKE3_MAIN_WIDTH + column][final_row],
                source_tables[column][0]
            );
        }

        drop(prepared);
        assert_eq!(std::fs::read_dir(&source_scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn out_of_core_adjacency_sumcheck_matches_dense_v2_at_256_rows() {
        let fixture = dense_blake3_fixture();
        assert_eq!(fixture.air.trace_rows(), 1 << 8);
        let layout = BlsDoryAggregateLayout::new(9, 10).unwrap();
        let setup = deterministic_bls_dory_setup(layout.variables()).unwrap();
        let source_scratch = Blake3ScratchDirectory::create();
        let round_scratch = Blake3ScratchDirectory::create();
        let mut prepared = prepare_native_blake3_sources_at_layout(
            &fixture.witness,
            &fixture.bridge,
            layout,
            &setup,
            &source_scratch.0,
        )
        .unwrap();
        let commitments = prepared.commitments();
        let inverse_commitments = [*commitments.commitment(BlsDoryBlake3SourceRole::Inverse)];
        let dense = prove_dense_adjacency_sumcheck_with_transcript(
            dense_adjacency_source_tables(&fixture.tables),
            &inverse_commitments,
            native_blake3_adjacency_transcript(
                &fixture.bridge,
                fixture.air.trace_rows(),
                &commitments.adjacency_sources(),
            )
            .unwrap(),
            true,
        )
        .unwrap();
        let expected = BlsDoryBlake3AdjacencySumcheckProof {
            rounds: dense.rounds,
            terminal_evaluations: dense.terminal_evaluations,
            transcript_digest: dense.transcript_digest,
        };

        let first = prove_native_blake3_adjacency_sumcheck_out_of_core(
            &mut prepared,
            &fixture.bridge,
            &round_scratch.0,
            31,
        )
        .unwrap();
        assert_eq!(first, expected);
        assert_eq!(std::fs::read_dir(&round_scratch.0).unwrap().count(), 0);
        let second = prove_native_blake3_adjacency_sumcheck_out_of_core(
            &mut prepared,
            &fixture.bridge,
            &round_scratch.0,
            17,
        )
        .unwrap();
        assert_eq!(second, first);
        assert_eq!(std::fs::read_dir(&round_scratch.0).unwrap().count(), 0);

        let encode = |proof: &BlsDoryBlake3AdjacencySumcheckProof| {
            encode_native_blake3_component(
                BLS_DORY_BLAKE3_ADJACENCY_PROOF_MAGIC,
                &inverse_commitments,
                &proof.rounds,
                BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1,
                &proof.terminal_evaluations,
                BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS,
                proof.transcript_digest,
                fixture.air.trace_rows().ilog2() as usize,
            )
            .unwrap()
        };
        let first_encoded = encode(&first);
        assert_eq!(first_encoded, encode(&expected));
        assert_eq!(first_encoded, encode(&second));
        let decoded = decode_native_blake3_component(
            &first_encoded,
            BLS_DORY_BLAKE3_ADJACENCY_PROOF_MAGIC,
            inverse_commitments.len(),
            fixture.air.trace_rows().ilog2() as usize,
            BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1,
            BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS,
        )
        .unwrap();
        assert_eq!(decoded.commitments, inverse_commitments);
        assert_eq!(decoded.rounds, first.rounds);
        assert_eq!(decoded.terminal_evaluations, first.terminal_evaluations);
        assert_eq!(decoded.transcript_digest, first.transcript_digest);
        let verified = verify_native_blake3_adjacency_sumcheck(
            &first,
            fixture.air.trace_rows(),
            &fixture.bridge,
            &commitments,
        )
        .unwrap();
        assert_eq!(verified.point.len(), 8);
        assert_eq!(verified.transcript_digest, first.transcript_digest);

        drop(prepared);
        assert_eq!(std::fs::read_dir(&source_scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn out_of_core_adjacency_sumcheck_rejects_corrupt_sources_without_scratch_leaks() {
        for corrupt_inverse in [false, true] {
            let fixture = dense_blake3_fixture();
            let layout = BlsDoryAggregateLayout::new(9, 10).unwrap();
            let setup = deterministic_bls_dory_setup(layout.variables()).unwrap();
            let source_scratch = Blake3ScratchDirectory::create();
            let round_scratch = Blake3ScratchDirectory::create();
            let mut prepared = prepare_native_blake3_sources_at_layout(
                &fixture.witness,
                &fixture.bridge,
                layout,
                &setup,
                &source_scratch.0,
            )
            .unwrap();
            let path = if corrupt_inverse {
                prepared
                    .sources
                    .inverse
                    .coefficient_artifact_path()
                    .unwrap()
                    .to_path_buf()
            } else {
                prepared.main_transpose.path().to_path_buf()
            };
            flip_file_byte(&path, 100).unwrap();
            assert!(matches!(
                prove_native_blake3_adjacency_sumcheck_out_of_core(
                    &mut prepared,
                    &fixture.bridge,
                    &round_scratch.0,
                    31,
                ),
                Err(BlsDoryAggregateError::ProverStorage)
            ));
            assert_eq!(std::fs::read_dir(&round_scratch.0).unwrap().count(), 0);
            drop(prepared);
            assert_eq!(std::fs::read_dir(&source_scratch.0).unwrap().count(), 0);
        }
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn prepared_execution_row_stream_fails_before_callbacks_for_corrupt_transposes() {
        for corrupt_main in [true, false] {
            let scratch = Blake3ScratchDirectory::create();
            let BoundedPreparedSourceFixture { mut prepared, .. } =
                bounded_prepared_source_bundle(&scratch.0, false).unwrap();
            let path = if corrupt_main {
                prepared.main_transpose.path()
            } else {
                prepared.preprocessing_transpose.path()
            };
            flip_file_byte(path, 100).unwrap();
            let mut callbacks = 0usize;
            assert!(matches!(
                prepared.for_each_authenticated_execution_row(3, |_row, _terminal| {
                    callbacks += 1;
                    Ok(())
                }),
                Err(BlsDoryAggregateError::ProverStorage)
            ));
            assert_eq!(callbacks, 0);
            drop(prepared);
            assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        }
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn prepared_execution_row_stream_fails_before_callbacks_for_released_accumulator() {
        let scratch = Blake3ScratchDirectory::create();
        let BoundedPreparedSourceFixture { mut prepared, .. } =
            bounded_prepared_source_bundle(&scratch.0, false).unwrap();
        prepared
            .sources
            .accumulator
            .release_compact_source_for_test();
        assert!(
            prepared
                .sources
                .accumulator
                .coefficient_artifact_path()
                .is_none()
        );
        let mut callbacks = 0usize;
        assert!(matches!(
            prepared.for_each_authenticated_execution_row(3, |_row, _terminal| {
                callbacks += 1;
                Ok(())
            }),
            Err(BlsDoryAggregateError::ProverStorage)
        ));
        assert_eq!(callbacks, 0);
        drop(prepared);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "real 21-variable four-source replay and Dory opening; run explicitly in --release"]
    fn native_six_claim_replay_authenticates_named_sources_end_to_end() {
        let total_started = std::time::Instant::now();
        let fixture = dense_blake3_fixture();
        assert_eq!(fixture.air.trace_rows(), 1 << 8);
        let layout = BlsDoryAggregateLayout::new(10, 11).unwrap();

        let setup_started = std::time::Instant::now();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(21).unwrap();
        let setup_elapsed = setup_started.elapsed();

        let scratch = Blake3ScratchDirectory::create();
        let PreparedBlsDoryNativeBlake3TestOpening {
            opening_statement,
            opening_set,
            encoded_native_proof,
            trusted_preprocessing_commitment,
            telemetry,
            commitments,
            execution,
            adjacency,
            geometry,
            verifier_context,
        } = prepare_native_blake3_test_opening_at_layout(
            &fixture.activation,
            &fixture.bridge,
            layout,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(encoded_native_proof.len(), 50_472);
        let decoded_native_proof = BlsDoryNativeBlake3Proof::decode_at_trace_variables(
            &encoded_native_proof,
            geometry.trace_variables,
        )
        .unwrap();
        assert_eq!(
            decoded_native_proof
                .encode_at_trace_variables(geometry.trace_variables)
                .unwrap(),
            encoded_native_proof
        );
        assert_eq!(trusted_preprocessing_commitment, commitments.preprocessing);
        assert_ne!(commitments.main, commitments.preprocessing);
        let wrong_pin_commitments = BlsDoryBlake3SourceCommitments {
            preprocessing: commitments.main,
            ..commitments.clone()
        };
        let wrong_preprocessing_pin = BlsDoryBlake3TrustedPreprocessingPin::for_test_sources(
            &fixture.bridge,
            fixture.air.trace_rows(),
            geometry,
            &verifier_context,
            &wrong_pin_commitments,
        );
        assert_eq!(
            verify_native_blake3_opening_replay_at_geometry(
                &fixture.bridge,
                &commitments,
                BlsDoryBlake3ReplayVerifier {
                    context: &verifier_context,
                    preprocessing_pin: &wrong_preprocessing_pin,
                    geometry,
                },
                &execution,
                &adjacency,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let expected_claims = opening_set.claims().to_vec();
        opening_statement.validate_claims(&expected_claims).unwrap();
        let opening_binding = opening_statement.opening_binding();

        let opening_started = std::time::Instant::now();
        let (claims, proof) = prove_bls_dory_deferred_opening_sets_consuming_with_scratch(
            &opening_binding,
            layout,
            vec![opening_set],
            &setup,
            &scratch.0,
        )
        .unwrap();
        let opening_elapsed = opening_started.elapsed();
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        assert_eq!(claims, expected_claims);
        opening_statement.validate_claims(&claims).unwrap();
        verify_bls_dory_openings(&opening_binding, layout, &claims, &proof, &setup).unwrap();

        let mut changed_binding = opening_binding;
        changed_binding[0] ^= 1;
        assert!(
            verify_bls_dory_openings(&changed_binding, layout, &claims, &proof, &setup).is_err()
        );
        let mut wrong_route = claims.clone();
        wrong_route[0].commitment = commitments.inverse;
        assert_eq!(
            opening_statement.validate_claims(&wrong_route),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        assert!(
            verify_bls_dory_openings(&opening_binding, layout, &wrong_route, &proof, &setup)
                .is_err()
        );
        let mut wrong_point = claims.clone();
        wrong_point[0].point[0] = wrong_point[0].point[0] + BlsDoryFr::from_u64(1);
        assert_eq!(
            opening_statement.validate_claims(&wrong_point),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        assert!(
            verify_bls_dory_openings(&opening_binding, layout, &wrong_point, &proof, &setup)
                .is_err()
        );
        let mut wrong_evaluation = claims.clone();
        wrong_evaluation[0].evaluation = wrong_evaluation[0].evaluation + BlsDoryFr::from_u64(1);
        assert_eq!(
            opening_statement.validate_claims(&wrong_evaluation),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        assert!(
            verify_bls_dory_openings(&opening_binding, layout, &wrong_evaluation, &proof, &setup)
                .is_err()
        );
        let mut changed_proof = proof.clone();
        let changed_proof_index = changed_proof.len() / 2;
        changed_proof[changed_proof_index] ^= 1;
        assert!(
            verify_bls_dory_openings(&opening_binding, layout, &claims, &changed_proof, &setup,)
                .is_err()
        );
        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
        eprintln!(
            "native six-claim E2E: setup={setup_elapsed:?}, fixture_millis={}, sources_millis={}, sumcheck_millis={}, finalize_millis={}, opening={opening_elapsed:?}, total={:?}, retained_scratch_entries={}, retained_scratch_bytes={}, proof_bytes={}",
            telemetry.fixture_millis,
            telemetry.source_millis,
            telemetry.sumcheck_millis,
            telemetry.finalize_millis,
            total_started.elapsed(),
            telemetry.retained_scratch_entries,
            telemetry.retained_scratch_bytes,
            proof.len(),
        );
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "bounded four-source Dory aggregate; run explicitly in --release"]
    fn four_source_six_claim_aggregate_uses_canonical_blake3_routing() {
        const SOURCE_VARIABLES: usize = 10;
        const TRACE_VARIABLES: usize = 4;
        let layout = BlsDoryAggregateLayout::new(5, 7).unwrap();
        let replay_geometry = BlsDoryBlake3ReplayGeometry {
            trace_variables: TRACE_VARIABLES,
            source_variables: SOURCE_VARIABLES,
            shared_variables: layout.variables(),
        };
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(14).unwrap();
        let [main, accumulator, preprocessing, inverse] = std::array::from_fn(|source| {
            let mut coefficients = (0..1 << SOURCE_VARIABLES)
                .map(|index| {
                    BlsDoryFr::from_u64((source as u64 + 1) * 1_000_003 + (index as u64 + 17) * 97)
                })
                .collect::<Vec<_>>();
            coefficients.resize(1 << layout.variables(), BlsDoryFr::zero());
            commit_bls_dory_polynomial(coefficients, layout.nu(), layout.sigma(), &setup).unwrap()
        });
        let committed_sources = BlsDoryBlake3CommittedSources {
            main,
            accumulator,
            preprocessing,
            inverse,
        };
        let source_commitments = committed_sources.commitments();
        let commitments =
            BLS_DORY_BLAKE3_SOURCE_ROLES.map(|role| committed_sources.source(role).commitment());
        for (index, commitment) in commitments.iter().enumerate() {
            assert!(
                commitments
                    .iter()
                    .skip(index + 1)
                    .all(|other| other != commitment)
            );
        }

        let execution_trace = (0..TRACE_VARIABLES)
            .map(|coordinate| BlsDoryFr::from_u64(coordinate as u64 + 71))
            .collect::<Vec<_>>();
        let adjacency_trace = (0..TRACE_VARIABLES)
            .map(|coordinate| BlsDoryFr::from_u64(coordinate as u64 + 173))
            .collect::<Vec<_>>();
        let points = (0..BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.len())
            .map(|claim| {
                let mut point = vec![BlsDoryFr::zero(); SOURCE_VARIABLES];
                let trace = if claim < BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS {
                    &execution_trace
                } else {
                    &adjacency_trace
                };
                point[..TRACE_VARIABLES].copy_from_slice(trace);
                for (coordinate, value) in point
                    .iter_mut()
                    .enumerate()
                    .take(SOURCE_VARIABLES)
                    .skip(TRACE_VARIABLES)
                {
                    *value = BlsDoryFr::from_u64(
                        (claim as u64 + 3) * 101 + (coordinate as u64 + 5) * 103,
                    );
                }
                if claim >= BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS {
                    point[SOURCE_VARIABLES - 1] = BlsDoryFr::zero();
                }
                point.resize(layout.variables(), BlsDoryFr::zero());
                point
            })
            .collect::<Vec<_>>();
        let expected_points = points.clone();
        let opening_set = committed_sources
            .into_canonical_deferred_openings_at_variables(
                points.try_into().unwrap(),
                SOURCE_VARIABLES,
                layout.variables(),
            )
            .unwrap();
        assert!(opening_set.claims().iter().all(|claim| {
            claim.point[SOURCE_VARIABLES..]
                .iter()
                .all(|coordinate| *coordinate == BlsDoryFr::zero())
        }));
        assert_ne!(opening_set.claims()[0].point, opening_set.claims()[3].point);
        assert_ne!(opening_set.claims()[1].point, opening_set.claims()[4].point);
        for (claim, source) in opening_set
            .claims()
            .iter()
            .zip(BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES)
        {
            assert_eq!(claim.commitment, commitments[source]);
        }
        assert_eq!(
            opening_set.claims()[0].commitment,
            opening_set.claims()[3].commitment
        );
        assert_eq!(
            opening_set.claims()[1].commitment,
            opening_set.claims()[4].commitment
        );
        assert_ne!(
            opening_set.claims()[2].commitment,
            opening_set.claims()[5].commitment
        );

        let public_binding = b"blake3-four-source-six-claim-aggregate-v1";
        let (claims, proof) =
            prove_bls_dory_deferred_opening_sets(public_binding, layout, &[&opening_set], &setup)
                .unwrap();
        let expected_evaluations = opening_set
            .claims()
            .iter()
            .map(|claim| claim.evaluation)
            .collect::<Vec<_>>();
        let opening_replay = blake3_opening_replay(&expected_points, &expected_evaluations);
        let opening_statement = BlsDoryBlake3OpeningStatement::from_verified_replay_at_geometry(
            source_commitments.clone(),
            opening_replay,
            replay_geometry,
        )
        .unwrap();
        assert_eq!(claims, opening_set.claims());
        opening_statement.validate_claims(&claims).unwrap();
        verify_bls_dory_openings(public_binding, layout, &claims, &proof, &setup).unwrap();

        let wrong_routing_set = BlsDoryDeferredOpeningSet::new(
            (0..BLS_DORY_BLAKE3_SOURCE_COMMITMENTS)
                .map(|source| opening_set.polynomial(source).unwrap().clone())
                .collect(),
            [0, 1, 2, 2, 1, 3].to_vec(),
            opening_set
                .claims()
                .iter()
                .map(|claim| claim.point.clone())
                .collect(),
        )
        .unwrap();
        let (wrong_routing_claims, wrong_routing_proof) = prove_bls_dory_deferred_opening_sets(
            public_binding,
            layout,
            &[&wrong_routing_set],
            &setup,
        )
        .unwrap();
        verify_bls_dory_openings(
            public_binding,
            layout,
            &wrong_routing_claims,
            &wrong_routing_proof,
            &setup,
        )
        .unwrap();
        assert_eq!(
            opening_statement.validate_claims(&wrong_routing_claims),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );

        let mut noncanonical_lift_points = expected_points.clone();
        noncanonical_lift_points[0][SOURCE_VARIABLES] = BlsDoryFr::from_u64(1);
        let noncanonical_lift_replay =
            blake3_opening_replay(&noncanonical_lift_points, &expected_evaluations);
        assert_eq!(
            BlsDoryBlake3OpeningStatement::from_verified_replay_at_geometry(
                source_commitments,
                noncanonical_lift_replay,
                replay_geometry,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let noncanonical_lift_set = BlsDoryDeferredOpeningSet::new(
            (0..BLS_DORY_BLAKE3_SOURCE_COMMITMENTS)
                .map(|source| opening_set.polynomial(source).unwrap().clone())
                .collect(),
            BLS_DORY_BLAKE3_OPENING_SOURCE_INDICES.to_vec(),
            noncanonical_lift_points,
        )
        .unwrap();
        let (noncanonical_lift_claims, noncanonical_lift_proof) =
            prove_bls_dory_deferred_opening_sets(
                public_binding,
                layout,
                &[&noncanonical_lift_set],
                &setup,
            )
            .unwrap();
        verify_bls_dory_openings(
            public_binding,
            layout,
            &noncanonical_lift_claims,
            &noncanonical_lift_proof,
            &setup,
        )
        .unwrap();
        assert_eq!(
            opening_statement.validate_claims(&noncanonical_lift_claims),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );

        assert!(
            verify_bls_dory_openings(b"wrong-binding", layout, &claims, &proof, &setup).is_err()
        );
        let mut wrong_point = claims.clone();
        wrong_point[0].point[SOURCE_VARIABLES] = BlsDoryFr::from_u64(1);
        assert!(
            verify_bls_dory_openings(public_binding, layout, &wrong_point, &proof, &setup).is_err()
        );
        let mut wrong_evaluation = claims.clone();
        wrong_evaluation[1].evaluation = wrong_evaluation[1].evaluation + BlsDoryFr::from_u64(1);
        assert!(
            verify_bls_dory_openings(public_binding, layout, &wrong_evaluation, &proof, &setup,)
                .is_err()
        );
        let mut wrong_commitment = claims.clone();
        wrong_commitment[2].commitment = commitments[3];
        assert!(
            verify_bls_dory_openings(public_binding, layout, &wrong_commitment, &proof, &setup,)
                .is_err()
        );
        let mut reordered = claims.clone();
        reordered.swap(0, 1);
        assert!(
            verify_bls_dory_openings(public_binding, layout, &reordered, &proof, &setup).is_err()
        );
        let wrong_layout = BlsDoryAggregateLayout::new(6, 6).unwrap();
        assert!(
            verify_bls_dory_openings(public_binding, wrong_layout, &claims, &proof, &setup)
                .is_err()
        );
        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn native_adjacency_inverse_stream_matches_dense_reference_and_rejects_bad_inputs() {
        const TRACE_ROWS: usize = 1 << 4;
        let layout = BlsDoryAggregateLayout::new(3, 3).unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(6).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let ordinary_columns = (0..BLS_DORY_BLAKE3_MAIN_WIDTH)
            .filter(|column| *column != NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START)
            .collect::<Vec<_>>();
        assert_eq!(ordinary_columns.len(), BLS_DORY_BLAKE3_MAIN_WIDTH - 1);

        let mut local_tables = (0..BLS_DORY_BLAKE3_MAIN_WIDTH)
            .map(|_| Vec::with_capacity(TRACE_ROWS))
            .collect::<Vec<_>>();
        let mut transpose_writer =
            BlsDoryWordTransposeWriter::create(&scratch.0, TRACE_ROWS, ordinary_columns.len(), 8)
                .unwrap();
        for row in 0..TRACE_ROWS {
            let mut words = Vec::with_capacity(ordinary_columns.len());
            for (native_column, table) in local_tables.iter_mut().enumerate() {
                if native_column == NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START {
                    table.push(BlsDoryFr::from_u64((row as u64 + 3) * (row as u64 + 11)));
                } else {
                    let value = ((row * 19 + native_column * 37) % 201) as i64 - 100;
                    table.push(BlsDoryFr::from_i64(value));
                    words.push(u64::from_le_bytes(value.to_le_bytes()));
                }
            }
            transpose_writer.write_row(&words).unwrap();
        }
        let next_tables = local_tables
            .iter()
            .map(|table| {
                table[1..]
                    .iter()
                    .chain(&table[..1])
                    .copied()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let source_tables = local_tables
            .iter()
            .cloned()
            .chain(next_tables.iter().cloned())
            .collect::<Vec<_>>();

        let mut accumulator_writer = BlsDoryCommittedPolynomialWriter::create(
            &scratch.0,
            2 * TRACE_ROWS,
            layout.nu(),
            layout.sigma(),
            &setup,
        )
        .unwrap();
        accumulator_writer
            .write_scalars(&local_tables[NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START])
            .unwrap();
        accumulator_writer
            .write_scalars(&next_tables[NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START])
            .unwrap();
        let accumulator = accumulator_writer.finish().unwrap();

        let mut ordinary_main = transpose_writer.finish().unwrap();
        ordinary_main.authenticate().unwrap();
        let compression = BlsDoryFr::from_u64(7);
        let mut alpha = BlsDoryFr::from_u64(1_000_003);
        let inverse_tables = loop {
            if let Some(inverses) =
                dense_adjacency_inverse_tables(&source_tables, compression, alpha)
            {
                break inverses;
            }
            alpha = alpha + BlsDoryFr::from_u64(1);
        };
        let mut materialized_coefficients =
            inverse_tables.iter().flatten().copied().collect::<Vec<_>>();
        materialized_coefficients.resize(1 << layout.variables(), BlsDoryFr::zero());
        let materialized = commit_bls_dory_polynomial(
            materialized_coefficients,
            layout.nu(),
            layout.sigma(),
            &setup,
        )
        .unwrap();
        let streamed = commit_native_adjacency_inverse_source(
            &mut ordinary_main,
            &accumulator,
            compression,
            alpha,
            layout,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(streamed.commitment(), materialized.commitment());
        assert_eq!(streamed.row_commitments(), materialized.row_commitments());

        let points = vec![
            (0..layout.variables())
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 47) * 53))
                .collect::<Vec<_>>(),
            (0..layout.variables())
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 59) * 61))
                .collect::<Vec<_>>(),
        ];
        let ordinary_opening = prove_bls_dory_same_commitment_openings(
            b"blake3-native-adjacency-inverse-source-equivalence",
            layout,
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let streamed_opening = prove_bls_dory_same_commitment_openings(
            b"blake3-native-adjacency-inverse-source-equivalence",
            layout,
            &streamed,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(streamed_opening, ordinary_opening);
        verify_bls_dory_openings(
            b"blake3-native-adjacency-inverse-source-equivalence",
            layout,
            &streamed_opening.0,
            &streamed_opening.1,
            &setup,
        )
        .unwrap();

        let wrong_setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(7).unwrap();
        assert!(matches!(
            commit_native_adjacency_inverse_source(
                &mut ordinary_main,
                &accumulator,
                compression,
                alpha,
                layout,
                &wrong_setup,
                &scratch.0,
            ),
            Err(BlsDoryAggregateError::InvalidDimension)
        ));

        let colliding_alpha = dense_adjacency_key(
            source_tables[..BLS_DORY_BLAKE3_MAIN_WIDTH]
                .iter()
                .map(|table| table[0]),
            BlsDoryFr::from_u64((TRACE_ROWS - 1) as u64),
            compression,
        );
        assert!(matches!(
            commit_native_adjacency_inverse_source(
                &mut ordinary_main,
                &accumulator,
                compression,
                colliding_alpha,
                layout,
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        ));

        let accumulator_path = accumulator
            .coefficient_artifact_path()
            .unwrap()
            .to_path_buf();
        flip_file_byte(&accumulator_path, 100).unwrap();
        assert!(matches!(
            commit_native_adjacency_inverse_source(
                &mut ordinary_main,
                &accumulator,
                compression,
                alpha,
                layout,
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        ));

        let transpose_path = ordinary_main.path().to_path_buf();
        flip_file_byte(&transpose_path, 100).unwrap();
        assert!(matches!(
            commit_native_adjacency_inverse_source(
                &mut ordinary_main,
                &accumulator,
                compression,
                alpha,
                layout,
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        ));

        drop(streamed);
        drop(accumulator);
        drop(ordinary_main);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn blake3_preprocessed_source_rejects_non_boolean_and_corrupt_transpose() {
        const TRACE_ROWS: usize = 1 << 3;
        const SELECTOR_SLOTS: usize = 1 << 8;
        let scratch = Blake3ScratchDirectory::create();
        let boolean_column = (0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
            .find(|column| !NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS.contains(column))
            .unwrap();

        let mut wrong_width_writer = BlsDoryWordTransposeWriter::create(
            &scratch.0,
            TRACE_ROWS,
            BLS_DORY_BLAKE3_PREPROCESSED_WIDTH - 1,
            3,
        )
        .unwrap();
        let wrong_width_row = vec![0; BLS_DORY_BLAKE3_PREPROCESSED_WIDTH - 1];
        for _ in 0..TRACE_ROWS {
            wrong_width_writer.write_row(&wrong_width_row).unwrap();
        }
        let mut wrong_width_artifact = wrong_width_writer.finish().unwrap();
        assert!(matches!(
            TransposedPreprocessedRowSource::new_with_geometry(
                &mut wrong_width_artifact,
                SELECTOR_SLOTS,
                TRACE_ROWS,
            ),
            Err(BlsDoryTransposeError::InvalidShape)
        ));
        drop(wrong_width_artifact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut writer = BlsDoryWordTransposeWriter::create(
            &scratch.0,
            TRACE_ROWS,
            BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
            3,
        )
        .unwrap();
        for row_index in 0..TRACE_ROWS {
            let mut row = vec![0; BLS_DORY_BLAKE3_PREPROCESSED_WIDTH];
            if row_index == 3 {
                row[boolean_column] = 2;
            }
            writer.write_row(&row).unwrap();
        }
        let mut artifact = writer.finish().unwrap();
        artifact.authenticate().unwrap();
        {
            let mut source = TransposedPreprocessedRowSource::new(&mut artifact, SELECTOR_SLOTS);
            let mut output = vec![0; TRACE_ROWS];
            assert!(matches!(
                source.read_code_row(BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES, &mut output),
                Err(BlsDoryTransposeError::InvalidShape)
            ));
        }
        drop(artifact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut writer = BlsDoryWordTransposeWriter::create(
            &scratch.0,
            TRACE_ROWS,
            BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
            3,
        )
        .unwrap();
        let row = vec![0; BLS_DORY_BLAKE3_PREPROCESSED_WIDTH];
        for _ in 0..TRACE_ROWS {
            writer.write_row(&row).unwrap();
        }
        let mut artifact = writer.finish().unwrap();
        artifact.authenticate().unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(artifact.path())
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.flush().unwrap();
        assert!(matches!(
            artifact.authenticate(),
            Err(BlsDoryTransposeError::Authentication)
        ));
        drop(file);
        drop(artifact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "the exact 16-variable compact Dory comparison is intentionally expensive"]
    fn blake3_preprocessed_source_preserves_commitment_and_opening_bytes() {
        const TRACE_VARIABLES: usize = 8;
        const SELECTOR_VARIABLES: usize = 8;
        const TRACE_ROWS: usize = 1 << TRACE_VARIABLES;
        const SELECTOR_SLOTS: usize = 1 << SELECTOR_VARIABLES;
        let fixture = dense_blake3_fixture();
        assert_eq!(fixture.air.trace_rows(), TRACE_ROWS);
        let local_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
        let mut field_tables = Vec::with_capacity(
            BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES,
        );
        for physical_slot in 0..2 * BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
            let logical = preprocessed_physical_terminal_index(physical_slot).unwrap();
            field_tables.push(fixture.tables[local_start + logical].clone());
        }
        assert_eq!(
            field_tables.len(),
            BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES + BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES
        );

        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(
            TRACE_VARIABLES + SELECTOR_VARIABLES,
        )
        .unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let materialized = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&field_tables, TRACE_ROWS, SELECTOR_SLOTS).unwrap(),
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
        )
        .unwrap();
        let mut transpose_writer = BlsDoryWordTransposeWriter::create(
            &scratch.0,
            TRACE_ROWS,
            BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
            17,
        )
        .unwrap();
        for_each_preprocessed_trace_row(&fixture.air, &fixture.witness, |row_index, row| {
            assert_eq!(row.len(), BLS_DORY_BLAKE3_PREPROCESSED_WIDTH);
            let values = row
                .iter()
                .map(|value| value.as_canonical_u64())
                .collect::<Vec<_>>();
            for (column, value) in values.iter().copied().enumerate() {
                assert_eq!(
                    fixture.tables[local_start + column][row_index],
                    BlsDoryFr::from_u64(value)
                );
            }
            transpose_writer.write_row(&values)
        })
        .unwrap();
        let mut transpose = transpose_writer.finish().unwrap();
        transpose.authenticate().unwrap();
        let compact = {
            let mut source = TransposedPreprocessedRowSource::new(&mut transpose, SELECTOR_SLOTS);
            commit_bls_dory_compact_row_source_with_scratch(
                &mut source,
                SELECTOR_VARIABLES,
                TRACE_VARIABLES,
                &setup,
                &scratch.0,
            )
            .unwrap()
        };
        drop(transpose);
        assert_eq!(compact.commitment(), materialized.commitment());

        let points = vec![
            (0..(TRACE_VARIABLES + SELECTOR_VARIABLES))
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 17) * 29))
                .collect::<Vec<_>>(),
            (0..(TRACE_VARIABLES + SELECTOR_VARIABLES))
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 19) * 31))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"blake3-preprocessed-source-equivalence",
            dense_aggregate_layout(),
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_backed = prove_bls_dory_same_commitment_openings(
            b"blake3-preprocessed-source-equivalence",
            dense_aggregate_layout(),
            &compact,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(artifact_backed, ordinary);
        verify_bls_dory_openings(
            b"blake3-preprocessed-source-equivalence",
            dense_aggregate_layout(),
            &artifact_backed.0,
            &artifact_backed.1,
            &setup,
        )
        .unwrap();
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "the exact 16-variable code-only Dory comparison is intentionally expensive"]
    fn blake3_code_only_source_preserves_commitment_and_opening_bytes() {
        const TRACE_VARIABLES: usize = 8;
        const SELECTOR_VARIABLES: usize = 8;
        const TRACE_ROWS: usize = 1 << TRACE_VARIABLES;
        const SELECTOR_SLOTS: usize = 1 << SELECTOR_VARIABLES;
        let dictionary = std::iter::once(BlsDoryFr::zero())
            .chain((-7..=-1).chain(1..=8).map(BlsDoryFr::from_i64))
            .collect::<Vec<_>>();
        let code_tables = (0..137)
            .map(|selector| {
                (0..TRACE_ROWS)
                    .map(|row| ((selector * 7 + row * 11) % dictionary.len()) as u8)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let field_tables = code_tables
            .iter()
            .map(|table| {
                table
                    .iter()
                    .map(|code| dictionary[usize::from(*code)])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let materialized = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&field_tables, TRACE_ROWS, SELECTOR_SLOTS).unwrap(),
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
        )
        .unwrap();
        let mut source = DensePackedCodeRowSource {
            tables: &code_tables,
            trace_rows: TRACE_ROWS,
            selector_slots: SELECTOR_SLOTS,
            dictionary,
        };
        let compact = commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(compact.commitment(), materialized.commitment());
        let artifact_path = std::fs::read_dir(&scratch.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let compact_bytes = std::fs::metadata(artifact_path).unwrap().len();
        let literal_bytes = (code_tables.len() * TRACE_ROWS * 32) as u64;
        assert!(compact_bytes * 32 < literal_bytes);

        let points = vec![
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 11) * 19))
                .collect::<Vec<_>>(),
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 13) * 23))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"blake3-code-source-equivalence",
            dense_aggregate_layout(),
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_backed = prove_bls_dory_same_commitment_openings(
            b"blake3-code-source-equivalence",
            dense_aggregate_layout(),
            &compact,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(artifact_backed, ordinary);
        verify_bls_dory_openings(
            b"blake3-code-source-equivalence",
            dense_aggregate_layout(),
            &artifact_backed.0,
            &artifact_backed.1,
            &setup,
        )
        .unwrap();
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "three packed Dory commitments are intentionally expensive in debug builds"]
    fn native_execution_sumcheck_terminal_values_are_dory_authenticated() {
        let activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        let challenge_digest = [0x42; 32];
        let witness = build_tree_witness(OUTPUT_CONTEXT, challenge_digest, &activation).unwrap();
        let point = (0..activation.len().ilog2())
            .map(|index| ExtensionElement {
                limbs: [
                    u64::from(index) + 2,
                    u64::from(index) + 3,
                    u64::from(index) + 4,
                ],
            })
            .collect::<Vec<_>>();
        let native_point = point
            .iter()
            .copied()
            .map(ExtensionElement::to_field)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let signed_activation = activation
            .iter()
            .map(|value| {
                crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*value) - 125)
            })
            .collect::<Vec<_>>();
        let statement = StructuredBlake3Statement {
            challenge_digest,
            final_activation_len: activation.len(),
            final_activation_digest: witness.digest,
            final_activation_point: point,
            final_activation_evaluation: ExtensionElement::from_field(
                crate::structured_sumcheck::evaluate_mle(&signed_activation, &native_point),
            ),
        };
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            challenge_digest,
            witness.digest,
            &activation,
            [0x51; 32],
            [2_u64, 3, 5, 7, 11]
                .into_iter()
                .map(BlsDoryFr::from_u64)
                .collect(),
        )
        .unwrap();
        let air = NarrowBlake3Air::new(&statement).unwrap();
        let main = generate_main_trace(&air, &statement, &witness);
        let old_main_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { main.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let accumulators = native_accumulator_trace(&air, &old_main_rows, &bridge);
        let native_rows = old_main_rows
            .iter()
            .zip(&accumulators)
            .map(|(row, accumulator)| native_main_row(row, *accumulator))
            .collect::<Vec<_>>();
        let preprocessed = air.preprocessed_trace().unwrap();
        let preprocessed_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { preprocessed.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let tables = dense_execution_tables(&native_rows, &preprocessed_rows);
        let public = bls_values(public_values(&statement).unwrap());
        let constraints = bls_dory_native_blake3_constraint_ir(activation.len()).unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let authenticated = prove_dense_authenticated_execution(
            tables.clone(),
            &air,
            &public,
            &constraints,
            &bridge,
            &setup,
        )
        .unwrap();
        assert_eq!(authenticated.opening_batches.len(), 4);
        assert_eq!(
            authenticated
                .opening_batches
                .iter()
                .map(|batch| batch.terminal_count)
                .sum::<usize>(),
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
        );
        let expected_preprocessed_commitment = authenticated.opening_batches[3].commitment;
        assert!(verify_dense_authenticated_execution(
            &authenticated,
            &air,
            &public,
            &constraints,
            &bridge,
            expected_preprocessed_commitment,
            &setup,
        ));

        let mut changed_opening = authenticated.clone();
        changed_opening.opening_proof[0] ^= 1;
        assert!(!verify_dense_authenticated_execution(
            &changed_opening,
            &air,
            &public,
            &constraints,
            &bridge,
            expected_preprocessed_commitment,
            &setup,
        ));

        let mut altered_tables = tables;
        let local_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
        let next_start = local_start + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH;
        let counter_low = NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS[0];
        let delta = BlsDoryFr::from_u64(1);
        altered_tables[local_start + counter_low][1] =
            altered_tables[local_start + counter_low][1] + delta;
        altered_tables[next_start + counter_low][0] =
            altered_tables[next_start + counter_low][0] + delta;
        let altered = prove_dense_authenticated_execution(
            altered_tables,
            &air,
            &public,
            &constraints,
            &bridge,
            &setup,
        )
        .unwrap();
        let altered_preprocessed_commitment = altered.opening_batches[3].commitment;
        assert_ne!(
            altered_preprocessed_commitment,
            expected_preprocessed_commitment
        );
        assert!(verify_dense_authenticated_execution(
            &altered,
            &air,
            &public,
            &constraints,
            &bridge,
            altered_preprocessed_commitment,
            &setup,
        ));
        assert!(!verify_dense_authenticated_execution(
            &altered,
            &air,
            &public,
            &constraints,
            &bridge,
            expected_preprocessed_commitment,
            &setup,
        ));
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "five shared Dory commitments are intentionally expensive in debug builds"]
    fn native_execution_and_adjacency_share_authenticated_source_commitments() {
        let fixture = dense_blake3_fixture();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let proving_started = std::time::Instant::now();
        let authenticated = prove_dense_authenticated_blake3(
            fixture.tables,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            &setup,
        )
        .unwrap();
        let proving_elapsed = proving_started.elapsed();
        assert_eq!(authenticated.execution_batches.len(), 4);
        assert_eq!(authenticated.execution_sumcheck.rounds.len(), 8);
        assert_eq!(authenticated.adjacency_sumcheck.rounds.len(), 8);
        let expected_preprocessed_commitment = authenticated.execution_batches[3].commitment;
        let verification_started = std::time::Instant::now();
        let verified = verify_dense_authenticated_blake3(
            &authenticated,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            expected_preprocessed_commitment,
            &setup,
        );
        let verification_elapsed = verification_started.elapsed();
        eprintln!(
            "composed BLAKE3 fixture: prove_ms={} verify_ms={} opening_bytes={}",
            proving_elapsed.as_millis(),
            verification_elapsed.as_millis(),
            authenticated.opening_proof.len(),
        );
        assert!(verified);
        assert!(!verify_dense_authenticated_blake3(
            &authenticated,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            authenticated.execution_batches[0].commitment,
            &setup,
        ));

        let mut changed_shared_source = authenticated.clone();
        changed_shared_source.execution_batches[0].commitment =
            changed_shared_source.execution_batches[1].commitment;
        assert!(!verify_dense_authenticated_blake3(
            &changed_shared_source,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            expected_preprocessed_commitment,
            &setup,
        ));

        let mut changed_adjacency_terminal = authenticated.clone();
        changed_adjacency_terminal
            .adjacency_sumcheck
            .terminal_evaluations[0] = changed_adjacency_terminal
            .adjacency_sumcheck
            .terminal_evaluations[0]
            + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_authenticated_blake3(
            &changed_adjacency_terminal,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            expected_preprocessed_commitment,
            &setup,
        ));

        let mut changed_inverse = authenticated.clone();
        changed_inverse.inverse_commitment = changed_inverse.execution_batches[0].commitment;
        assert!(!verify_dense_authenticated_blake3(
            &changed_inverse,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            expected_preprocessed_commitment,
            &setup,
        ));

        let mut changed_opening = authenticated;
        changed_opening.opening_proof[0] ^= 1;
        assert!(!verify_dense_authenticated_blake3(
            &changed_opening,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            expected_preprocessed_commitment,
            &setup,
        ));
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "two packed Dory commitments are intentionally expensive in debug builds"]
    fn native_adjacency_sumcheck_sources_and_terminals_are_dory_authenticated() {
        let activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            [0x42; 32],
            [0x43; 32],
            &activation,
            [0x51; 32],
            [2_u64, 3, 5, 7, 11]
                .into_iter()
                .map(BlsDoryFr::from_u64)
                .collect(),
        )
        .unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let authenticated = prove_dense_authenticated_adjacency(
            synthetic_dense_adjacency_tables(16),
            &bridge,
            &setup,
        )
        .unwrap();
        assert_eq!(authenticated.sumcheck.rounds.len(), 4);
        assert_eq!(
            authenticated.sumcheck.terminal_evaluations.len(),
            BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS
        );
        assert_eq!(authenticated.opening_batches.len(), 2);
        assert!(verify_dense_authenticated_adjacency(
            &authenticated,
            &bridge,
            &setup,
        ));

        let mut changed_source_commitment = authenticated.clone();
        changed_source_commitment.opening_batches[0].commitment =
            changed_source_commitment.opening_batches[1].commitment;
        assert!(!verify_dense_authenticated_adjacency(
            &changed_source_commitment,
            &bridge,
            &setup,
        ));

        let mut changed_terminal = authenticated.clone();
        changed_terminal.sumcheck.terminal_evaluations[0] =
            changed_terminal.sumcheck.terminal_evaluations[0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_authenticated_adjacency(
            &changed_terminal,
            &bridge,
            &setup,
        ));

        let mut changed_opening = authenticated;
        changed_opening.opening_proof[0] ^= 1;
        assert!(!verify_dense_authenticated_adjacency(
            &changed_opening,
            &bridge,
            &setup,
        ));
    }
}
