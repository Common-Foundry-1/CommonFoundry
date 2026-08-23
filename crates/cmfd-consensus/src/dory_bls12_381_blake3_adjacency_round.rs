//! Authenticated out-of-core round state for the native BLAKE3 adjacency sumcheck.
//!
//! Each artifact stores the 580 explicit terminal values for every active row
//! in canonical row-major order. The authenticated specification retains the
//! shared 1,024-scalar logical stride, whose unused tail remains implicit.

use super::*;
use dory_pcs::primitives::arithmetic::Field;

const BLS_DORY_BLAKE3_ADJACENCY_ROUND_ROW_STRIDE: u64 = 1_024;
const BLS_DORY_BLAKE3_ADJACENCY_ROUND_TABLE_INDEX: u32 = 1;
const BLS_DORY_BLAKE3_ADJACENCY_ROUND_CONTEXT_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/BlsDoryBlake3AdjacencyRoundContext/v1";

const _: () = {
    assert!(BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS == 580);
    assert!(
        (BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS as u64)
            < BLS_DORY_BLAKE3_ADJACENCY_ROUND_ROW_STRIDE
    );
};

pub(super) type BlsDoryBlake3AdjacencyRoundRow =
    [BlsDoryFr; BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS];

/// Lineage selector for an out-of-core adjacency sumcheck round.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum BlsDoryBlake3AdjacencyRoundParent<'a> {
    /// The first stored generation is the result of folding the streamed root
    /// once and therefore binds directly to the root stream's lineage.
    Root([u8; 32]),
    /// A later generation binds to the authenticated digest of the immediately
    /// preceding round artifact.
    Previous(&'a BlsDoryBlake3AdjacencyRoundArtifact),
}

/// RAII writer for a packed row-major adjacency-round artifact.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct BlsDoryBlake3AdjacencyRoundArtifactWriter {
    inner: BlsDoryFoldArtifactWriter,
    root_lineage: [u8; 32],
    parent_digest: [u8; 32],
    round_index: usize,
    active_rows: u64,
    written_rows: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl BlsDoryBlake3AdjacencyRoundArtifactWriter {
    pub(super) fn create(
        scratch_directory: &std::path::Path,
        active_rows: u64,
        round_index: usize,
        parent: BlsDoryBlake3AdjacencyRoundParent<'_>,
    ) -> Result<Self, BlsDoryFoldArtifactError> {
        if active_rows == 0 || !active_rows.is_power_of_two() {
            return Err(BlsDoryFoldArtifactError::InvalidSpec);
        }
        let generation = u32::try_from(round_index)
            .ok()
            .and_then(|round| round.checked_add(1))
            .ok_or(BlsDoryFoldArtifactError::InvalidSpec)?;
        let (root_lineage, parent_digest) = match parent {
            BlsDoryBlake3AdjacencyRoundParent::Root(root_lineage) => {
                if round_index != 0 || root_lineage == [0; 32] {
                    return Err(BlsDoryFoldArtifactError::InvalidSpec);
                }
                (root_lineage, root_lineage)
            }
            BlsDoryBlake3AdjacencyRoundParent::Previous(previous) => {
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
        let context_digest = bls_dory_blake3_adjacency_round_context(root_lineage);
        if context_digest == [0; 32] || parent_digest == [0; 32] {
            return Err(BlsDoryFoldArtifactError::InvalidSpec);
        }
        let explicit_scalar_count = active_rows
            .checked_mul(BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS as u64)
            .ok_or(BlsDoryFoldArtifactError::InvalidSpec)?;
        let scalar_count = active_rows
            .checked_mul(BLS_DORY_BLAKE3_ADJACENCY_ROUND_ROW_STRIDE)
            .ok_or(BlsDoryFoldArtifactError::InvalidSpec)?;
        let spec = BlsDoryFoldArtifactSpec {
            context_digest,
            table_index: BLS_DORY_BLAKE3_ADJACENCY_ROUND_TABLE_INDEX,
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

    pub(super) fn write_row(&mut self, row: &[BlsDoryFr]) -> Result<(), BlsDoryFoldArtifactError> {
        if row.len() != BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS
            || self.written_rows >= self.active_rows
        {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        self.inner.write_scalars(row)?;
        self.written_rows += 1;
        Ok(())
    }

    pub(super) fn finish(
        self,
    ) -> Result<BlsDoryBlake3AdjacencyRoundArtifact, BlsDoryFoldArtifactError> {
        if self.written_rows != self.active_rows {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        Ok(BlsDoryBlake3AdjacencyRoundArtifact {
            inner: self.inner.finish()?,
            root_lineage: self.root_lineage,
            parent_digest: self.parent_digest,
            round_index: self.round_index,
            active_rows: self.active_rows,
        })
    }
}

/// Authenticated packed row-major state for one completed adjacency fold.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct BlsDoryBlake3AdjacencyRoundArtifact {
    inner: BlsDoryFoldArtifact,
    root_lineage: [u8; 32],
    parent_digest: [u8; 32],
    round_index: usize,
    active_rows: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl BlsDoryBlake3AdjacencyRoundArtifact {
    pub(super) fn digest(&self) -> [u8; 32] {
        self.inner.digest()
    }

    pub(super) fn active_rows(&self) -> u64 {
        self.active_rows
    }

    pub(super) fn round_index(&self) -> usize {
        self.round_index
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
        let context_digest = bls_dory_blake3_adjacency_round_context(self.root_lineage);
        let explicit_scalar_count = self
            .active_rows
            .checked_mul(BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS as u64)
            .ok_or(BlsDoryFoldArtifactError::InvalidArtifact)?;
        let scalar_count = self
            .active_rows
            .checked_mul(BLS_DORY_BLAKE3_ADJACENCY_ROUND_ROW_STRIDE)
            .ok_or(BlsDoryFoldArtifactError::InvalidArtifact)?;
        if context_digest == [0; 32]
            || self.parent_digest == [0; 32]
            || (self.round_index == 0 && self.parent_digest != self.root_lineage)
            || spec.context_digest != context_digest
            || spec.table_index != BLS_DORY_BLAKE3_ADJACENCY_ROUND_TABLE_INDEX
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
    /// Visitor effects are provisional: a corrupt body or footer can be found
    /// after earlier callbacks. Callers must discard accumulated state unless
    /// the complete traversal returns `Ok(())`.
    pub(super) fn for_each_row_pair(
        &self,
        mut visitor: impl FnMut(
            &BlsDoryBlake3AdjacencyRoundRow,
            &BlsDoryBlake3AdjacencyRoundRow,
        ) -> Result<(), BlsDoryFoldArtifactError>,
    ) -> Result<(), BlsDoryFoldArtifactError> {
        self.validate_shape()?;
        if self.active_rows < 2 {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        let mut rows = [
            [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS],
            [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS],
        ];
        let mut row_index = 0u64;
        let mut column = 0usize;
        self.inner.for_each_scalar(|scalar| {
            let pair_row = usize::try_from(row_index & 1)
                .map_err(|_| BlsDoryFoldArtifactError::InvalidArtifact)?;
            rows[pair_row][column] = scalar;
            column += 1;
            if column == BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS {
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

    /// Return the sole terminal row only after authenticating the whole file.
    pub(super) fn terminal_row(
        &self,
    ) -> Result<BlsDoryBlake3AdjacencyRoundRow, BlsDoryFoldArtifactError> {
        self.validate_shape()?;
        if self.active_rows != 1 {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        let mut row = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS];
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

/// Transactionally fold an authenticated parent into its next generation.
///
/// The child writer remains locally owned until the parent body and footer
/// authenticate. Any traversal or write error drops and deletes the unfinished
/// child artifact.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn fold_native_blake3_adjacency_artifact(
    parent: &BlsDoryBlake3AdjacencyRoundArtifact,
    scratch_directory: &std::path::Path,
    challenge: BlsDoryFr,
) -> Result<BlsDoryBlake3AdjacencyRoundArtifact, BlsDoryFoldArtifactError> {
    if parent.active_rows < 2 {
        return Err(BlsDoryFoldArtifactError::InvalidArtifact);
    }
    let round_index = parent
        .round_index
        .checked_add(1)
        .ok_or(BlsDoryFoldArtifactError::InvalidSpec)?;
    let mut writer = BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
        scratch_directory,
        parent.active_rows / 2,
        round_index,
        BlsDoryBlake3AdjacencyRoundParent::Previous(parent),
    )?;
    let mut folded = [BlsDoryFr::zero(); BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS];
    parent.for_each_row_pair(|lower, upper| {
        for column in 0..BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS {
            folded[column] = lower[column] + challenge * (upper[column] - lower[column]);
        }
        writer.write_row(&folded)
    })?;
    writer.finish()
}

fn bls_dory_blake3_adjacency_round_context(root_lineage: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(BLS_DORY_BLAKE3_ADJACENCY_ROUND_CONTEXT_DOMAIN);
    hasher.update(&root_lineage);
    hasher.update(&BLS_DORY_BLAKE3_ADJACENCY_ROUND_TABLE_INDEX.to_le_bytes());
    hasher.update(&(BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS as u64).to_le_bytes());
    hasher.update(&BLS_DORY_BLAKE3_ADJACENCY_ROUND_ROW_STRIDE.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
#[path = "dory_bls12_381_blake3_adjacency_round_tests.rs"]
mod tests;
