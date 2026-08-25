#![no_main]

use cmfd_consensus::dory_bls12_381_layout::BlsDorySharedLayoutProof;
use cmfd_consensus::{
    StructuredMatrixStatement, StructuredTransitionStatement, StructuredWiringStatement,
};
use libfuzzer_sys::fuzz_target;

const PADDED_VARIABLES: usize = 10;
const MATRIX_STATEMENTS: [StructuredMatrixStatement; 1] = [StructuredMatrixStatement {
    layers: 2,
    rows: 2,
    inner: 2,
    cols: 2,
    max_abs_activation: 125,
    max_abs_weight: 10,
    max_abs_accumulator: 65_536,
}];
const TRANSITION_STATEMENTS: [StructuredTransitionStatement; 2] = [
    StructuredTransitionStatement {
        layers: 1,
        rows: 2,
        cols: 2,
        max_abs_accumulator: 65_536,
        max_mask: 5_000,
    },
    StructuredTransitionStatement {
        layers: 2,
        rows: 2,
        cols: 2,
        max_abs_accumulator: 65_536,
        max_mask: 5_000,
    },
];
const WIRING_STATEMENT: StructuredWiringStatement = StructuredWiringStatement {
    banks: 1,
    layers_per_bank: 2,
    rows: 2,
    cols: 2,
    max_abs_activation: 125,
};

fuzz_target!(|bytes: &[u8]| {
    let _ = BlsDorySharedLayoutProof::decode_with_variables(
        bytes,
        &MATRIX_STATEMENTS,
        &TRANSITION_STATEMENTS,
        WIRING_STATEMENT,
        PADDED_VARIABLES,
    );
});
