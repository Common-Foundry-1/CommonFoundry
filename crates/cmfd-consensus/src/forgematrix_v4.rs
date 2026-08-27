//! Consensus geometry reserved for the isolated ProductionV4 proof system.
//!
//! This module defines only the field, BaseFold, and trace-index parameters.
//! It does not activate ProductionV4 or provide a verifier.

use crate::forgematrix_v2::{
    PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS_PER_BANK,
};

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

pub const FORGEMATRIX_V4_WEIGHT_AXIS_ORDER: &str =
    "[column,common,layer-within-bank] least-significant/fastest-changing first";
pub const FORGEMATRIX_V4_DYNAMIC_AXIS_ORDER: &str =
    "[column,batch-row,layer-within-bank,trace-kind] least-significant/fastest-changing first";

const ROW_MASK: usize = FORGEMATRIX_V4_BASEFOLD_ROWS - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum ForgeMatrixV4DynamicTraceKind {
    Accumulator = 0,
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
            forgematrix_v4_dynamic_index(ForgeMatrixV4DynamicTraceKind::Accumulator, 15, 127, 4095,),
            Some((
                FORGEMATRIX_V4_BASEFOLD_ROWS - 1,
                0,
                FORGEMATRIX_V4_BASEFOLD_ROWS - 1
            ))
        );
        assert_eq!(
            forgematrix_v4_dynamic_index(ForgeMatrixV4DynamicTraceKind::Accumulator, 16, 0, 0,),
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
            forgematrix_v4_dynamic_index(ForgeMatrixV4DynamicTraceKind::Accumulator, 0, 128, 0,),
            None
        );
    }
}
