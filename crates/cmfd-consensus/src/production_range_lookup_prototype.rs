//! Batch-STARK/LogUp prototype for the compact production range layout.
//!
//! This test-only argument proves the transition core together with the two
//! relations required by the four-row packed range witness:
//!
//! - the mask equals the challenge-derived, verifier-fixed mask column;
//! - all seven ForgeMatrix transition equations hold on each core row;
//! - each core source value and its fixed slack equal the final auxiliary
//!   accumulators carrying the same verifier-fixed lookup ID;
//! - each value and slack digit belongs to the verifier-fixed `0..15` table.
//!
//! The prototype uses 128 transition cells so the pinned FRI configuration has
//! a valid minimum domain while adversarial tests remain bounded.
//! Its 26 fixed coordinate-bit columns match the production preprocessing
//! plan. The AIR selects the challenge-derived affine coefficients itself, so
//! preprocessing remains reusable across blocks and contains no mask table.
//! It is not a production proof type and does not activate the compact layout.

use std::panic::{AssertUnwindSafe, catch_unwind};

use bincode::Options;
use flate2::{Compression, write::ZlibEncoder};

use p3_air::symbolic::AirLayout;
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks, get_max_constraint_degree,
};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_field::integers::QuotientMap;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::FriParameters;
use p3_lookup::{Count, InteractionBuilder, LogUpGadget};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};
use primitive_types::U256;

use crate::structured_blake3_narrow::{
    Config, EF, F, FRI_COMMIT_POW_BITS, FRI_LOG_FINAL_POLY_LEN, FRI_MAX_LOG_ARITY,
    FRI_QUERY_POW_BITS, build_config_with_fri,
};
use crate::{
    PRODUCTION_TRACE_PACKED_COLUMN_BITS, PRODUCTION_TRACE_PACKED_DIGIT_COLUMNS,
    PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS, PRODUCTION_TRACE_PACKED_DIGITS_PER_LOOKUP,
    PRODUCTION_TRACE_PACKED_LAYER_BITS, PRODUCTION_TRACE_PACKED_PREPROCESSED_WIDTH,
    PRODUCTION_TRACE_PACKED_ROW_BITS, PRODUCTION_TRACE_PACKED_ROWS_PER_CELL,
    PRODUCTION_TRACE_PACKED_SPEC_ROWS, STRUCTURED_TRANSITION_RANGE_SPEC_COUNT,
    STRUCTURED_TRANSITION_REGULAR_ORACLES, StructuredMaskPolynomial, StructuredTransitionStatement,
    V2_TRANSITION_MODULUS, production_trace_packed_digit_slot_v2, production_trace_packed_row_v2,
    structured_transition_range_specs,
};

const CELLS: usize = 128;
const TRACE_ROWS: usize = CELLS * PRODUCTION_TRACE_PACKED_ROWS_PER_CELL;

const CORE_START: usize = 0;
const CORE_ACCUMULATOR: usize = CORE_START;
const CORE_MASK: usize = CORE_START + 1;
const CORE_ENCODED: usize = CORE_START + 2;
const CORE_SQUARE_QUOTIENT: usize = CORE_START + 3;
const CORE_SQUARE_REMAINDER: usize = CORE_START + 4;
const CORE_CUBE_QUOTIENT: usize = CORE_START + 5;
const CORE_CUBE_REMAINDER: usize = CORE_START + 6;
const CORE_OUTPUT_QUOTIENT: usize = CORE_START + 7;
const CORE_OUTPUT_REMAINDER: usize = CORE_START + 8;
const CORE_NEGATIVE: usize = CORE_START + 9;
const CORE_ACTIVATION: usize = CORE_START + 10;
const CORE_SHIFTED_ACCUMULATOR: usize = CORE_START + 11;
const DIGIT_START: usize = CORE_START + STRUCTURED_TRANSITION_REGULAR_ORACLES;
const TABLE_MULTIPLICITY_START: usize = DIGIT_START + PRODUCTION_TRACE_PACKED_DIGIT_COLUMNS;
const MAIN_WIDTH: usize = TABLE_MULTIPLICITY_START + PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS;

const CORE_ACTIVE: usize = 0;
const CELL_LOOKUP_ID_START: usize = 1;
const TABLE_ACTIVE: usize = 2;
const TABLE_VALUE: usize = 3;
const SOURCE_ACTIVE_START: usize = 4;
const DIGIT_ACTIVE_START: usize = SOURCE_ACTIVE_START + STRUCTURED_TRANSITION_RANGE_SPEC_COUNT;
const LAYER_BITS_START: usize = DIGIT_ACTIVE_START + PRODUCTION_TRACE_PACKED_DIGIT_COLUMNS;
const ROW_BITS_START: usize = LAYER_BITS_START + PRODUCTION_TRACE_PACKED_LAYER_BITS;
const COLUMN_BITS_START: usize = ROW_BITS_START + PRODUCTION_TRACE_PACKED_ROW_BITS;
const PREPROCESSED_WIDTH: usize = COLUMN_BITS_START + PRODUCTION_TRACE_PACKED_COLUMN_BITS;

const LOOKUP_COUNT: usize =
    STRUCTURED_TRANSITION_RANGE_SPEC_COUNT + PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS;
const LOOKUP_MAX_COMBO: usize = PRODUCTION_TRACE_PACKED_DIGITS_PER_LOOKUP + 1;
const LOOKUP_AUX_EXTENSION_WIDTH: usize = LOOKUP_COUNT + 1;
const LOOKUP_AUX_BASE_WIDTH: usize = LOOKUP_AUX_EXTENSION_WIDTH * 3;
const PACKED_FRI_LOG_BLOWUP: usize = 4;
const PACKED_FRI_QUERIES: usize = 57;

fn build_packed_config() -> Config {
    build_config_with_fri(PACKED_FRI_LOG_BLOWUP, PACKED_FRI_QUERIES)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationShapeError {
    DegreeBits,
}

#[derive(Clone, Debug)]
struct ProductionRangeLookupAir {
    statement: StructuredTransitionStatement,
    mask: StructuredMaskPolynomial,
    preprocessed_deltas: Vec<(usize, usize, u64)>,
}

impl ProductionRangeLookupAir {
    fn canonical() -> Self {
        let statement = fixture_statement();
        Self {
            statement,
            mask: StructuredMaskPolynomial::from_challenge(
                &[0x42; 32],
                statement.layers,
                statement.rows,
                statement.cols,
            )
            .unwrap(),
            preprocessed_deltas: Vec::new(),
        }
    }

    fn with_preprocessed_delta(&self, row: usize, column: usize, delta: u64) -> Self {
        assert!(row < TRACE_ROWS);
        assert!(column < PREPROCESSED_WIDTH);
        assert_ne!(delta, 0);
        let mut changed = self.clone();
        changed.preprocessed_deltas.push((row, column, delta));
        changed
    }

    fn core_values(&self) -> [[u64; STRUCTURED_TRANSITION_REGULAR_ORACLES]; CELLS] {
        std::array::from_fn(|cell| {
            let mask = self
                .mask
                .value_at_boolean_index(self.statement, cell)
                .unwrap();
            let z = if cell % 2 == 0 {
                -((cell as i64) + 1)
            } else {
                mask as i64 + (cell as i64) * 3
            };
            let accumulator = z - mask as i64;
            transition_core_values(self.statement, accumulator, mask)
        })
    }

    fn valid_trace(&self) -> RowMajorMatrix<F> {
        let core_values = self.core_values();
        let mut values = F::zero_vec(TRACE_ROWS * MAIN_WIDTH);
        let mut multiplicities = [[0_u64; 16]; PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS];

        for row in 0..TRACE_ROWS {
            let cell = row / PRODUCTION_TRACE_PACKED_ROWS_PER_CELL;
            let local = &mut values[row * MAIN_WIDTH..(row + 1) * MAIN_WIDTH];
            if row % PRODUCTION_TRACE_PACKED_ROWS_PER_CELL == 0 {
                for (target, value) in local
                    [CORE_START..CORE_START + STRUCTURED_TRANSITION_REGULAR_ORACLES]
                    .iter_mut()
                    .zip(core_values[cell])
                {
                    *target = F::from_u64(value);
                }
            }

            let packed =
                production_trace_packed_row_v2(self.statement, &core_values[cell], row as u64)
                    .unwrap();
            for (column, digit) in packed.digits.into_iter().enumerate() {
                local[DIGIT_START + column] = F::from_u8(digit);
                let slot =
                    production_trace_packed_digit_slot_v2(usize::from(packed.row_in_cell), column)
                        .unwrap();
                if slot.active {
                    multiplicities[column / PRODUCTION_TRACE_PACKED_DIGITS_PER_LOOKUP]
                        [usize::from(digit)] += 1;
                }
            }
        }
        for row in 0..16 {
            for group in 0..PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS {
                values[row * MAIN_WIDTH + TABLE_MULTIPLICITY_START + group] =
                    F::from_u64(multiplicities[group][row]);
            }
        }

        RowMajorMatrix::new(values, MAIN_WIDTH)
    }

    fn canonical_preprocessed(&self) -> RowMajorMatrix<F> {
        let mut values = F::zero_vec(TRACE_ROWS * PREPROCESSED_WIDTH);

        for row in 0..TRACE_ROWS {
            let cell = row / PRODUCTION_TRACE_PACKED_ROWS_PER_CELL;
            let row_in_cell = row % PRODUCTION_TRACE_PACKED_ROWS_PER_CELL;
            let local = &mut values[row * PREPROCESSED_WIDTH..(row + 1) * PREPROCESSED_WIDTH];

            local[CELL_LOOKUP_ID_START] =
                F::from_u64((cell * STRUCTURED_TRANSITION_RANGE_SPEC_COUNT + 1) as u64);
            if row_in_cell == 0 {
                local[CORE_ACTIVE] = F::ONE;
            }
            let cells_per_layer = self.statement.rows * self.statement.cols;
            let layer = cell / cells_per_layer;
            let within_layer = cell % cells_per_layer;
            let matrix_row = within_layer / self.statement.cols;
            let column = within_layer % self.statement.cols;
            for bit in 0..PRODUCTION_TRACE_PACKED_LAYER_BITS {
                local[LAYER_BITS_START + bit] = F::from_bool((layer >> bit) & 1 == 1);
            }
            for bit in 0..PRODUCTION_TRACE_PACKED_ROW_BITS {
                local[ROW_BITS_START + bit] = F::from_bool((matrix_row >> bit) & 1 == 1);
            }
            for bit in 0..PRODUCTION_TRACE_PACKED_COLUMN_BITS {
                local[COLUMN_BITS_START + bit] = F::from_bool((column >> bit) & 1 == 1);
            }
            if row < 16 {
                local[TABLE_ACTIVE] = F::ONE;
                local[TABLE_VALUE] = F::from_u64(row as u64);
            }
            for (spec_index, spec_row) in PRODUCTION_TRACE_PACKED_SPEC_ROWS.into_iter().enumerate()
            {
                if spec_row == row_in_cell {
                    local[SOURCE_ACTIVE_START + spec_index] = F::ONE;
                }
            }
            for column in 0..PRODUCTION_TRACE_PACKED_DIGIT_COLUMNS {
                if production_trace_packed_digit_slot_v2(row_in_cell, column)
                    .unwrap()
                    .active
                {
                    local[DIGIT_ACTIVE_START + column] = F::ONE;
                }
            }
        }

        for &(row, column, delta) in &self.preprocessed_deltas {
            values[row * PREPROCESSED_WIDTH + column] += F::from_u64(delta);
        }
        RowMajorMatrix::new(values, PREPROCESSED_WIDTH)
    }
}

impl BaseAir<F> for ProductionRangeLookupAir {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(self.canonical_preprocessed())
    }

    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_WIDTH
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(9)
    }
}

fn select_mask_coefficient<AB: AirBuilder<F = F>>(
    coefficients: &[u8],
    statement: StructuredTransitionStatement,
    padded_coefficient: usize,
    layer_bits: &[AB::Var],
) -> AB::Expr {
    let actual_row_bits = statement.rows.ilog2() as usize;
    let actual_column_bits = statement.cols.ilog2() as usize;
    let actual_coefficient_count = 1 + actual_row_bits + actual_column_bits;
    let actual_coefficient = if padded_coefficient == 0 {
        Some(0)
    } else if padded_coefficient <= PRODUCTION_TRACE_PACKED_ROW_BITS {
        let bit = padded_coefficient - 1;
        (bit < actual_row_bits).then_some(1 + bit)
    } else {
        let bit = padded_coefficient - 1 - PRODUCTION_TRACE_PACKED_ROW_BITS;
        (bit < actual_column_bits).then_some(1 + actual_row_bits + bit)
    };
    let mut values = (0..(1 << PRODUCTION_TRACE_PACKED_LAYER_BITS))
        .map(|layer| {
            let value = if layer < statement.layers {
                actual_coefficient
                    .map(|index| coefficients[layer * actual_coefficient_count + index])
                    .unwrap_or(0)
            } else {
                0
            };
            AB::Expr::from_u8(value)
        })
        .collect::<Vec<_>>();
    for bit in layer_bits {
        values = values
            .chunks_exact(2)
            .map(|pair| {
                pair[0].clone() + AB::Expr::from(*bit) * (pair[1].clone() - pair[0].clone())
            })
            .collect();
    }
    values.pop().expect("seven layer folds leave one value")
}

impl<AB> Air<AB> for ProductionRangeLookupAir
where
    AB: PermutationAirBuilder<F = F> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let (local, prep) = {
            let main = builder.main();
            (
                main.current_slice().to_vec(),
                builder.preprocessed().current_slice().to_vec(),
            )
        };

        let core_active: AB::Expr = prep[CORE_ACTIVE].into();
        let table_active: AB::Expr = prep[TABLE_ACTIVE].into();

        builder.assert_bool(prep[CORE_ACTIVE]);
        builder.assert_bool(prep[TABLE_ACTIVE]);
        for selector in
            &prep[SOURCE_ACTIVE_START..SOURCE_ACTIVE_START + STRUCTURED_TRANSITION_RANGE_SPEC_COUNT]
        {
            builder.assert_bool(*selector);
        }
        for bit in &prep[LAYER_BITS_START..PREPROCESSED_WIDTH] {
            builder.assert_bool(*bit);
        }
        for column in 0..PRODUCTION_TRACE_PACKED_DIGIT_COLUMNS {
            let active: AB::Expr = prep[DIGIT_ACTIVE_START + column].into();
            builder.assert_bool(prep[DIGIT_ACTIVE_START + column]);
            builder
                .when(AB::Expr::ONE - active)
                .assert_zero(local[DIGIT_START + column]);
        }
        let core_inactive = AB::Expr::ONE - core_active.clone();
        for value in &local[CORE_START..CORE_START + STRUCTURED_TRANSITION_REGULAR_ORACLES] {
            builder.when(core_inactive.clone()).assert_zero(*value);
        }
        let modulus = AB::Expr::from_u64(u64::from(V2_TRANSITION_MODULUS));
        let encoded: AB::Expr = local[CORE_ENCODED].into();
        let square_remainder: AB::Expr = local[CORE_SQUARE_REMAINDER].into();
        let cube_remainder: AB::Expr = local[CORE_CUBE_REMAINDER].into();
        let coefficients = self.mask.affine_coefficients(self.statement).unwrap();
        let layer_bits = &prep[LAYER_BITS_START..ROW_BITS_START];
        let mut expected_mask =
            select_mask_coefficient::<AB>(coefficients, self.statement, 0, layer_bits);
        for bit in 0..PRODUCTION_TRACE_PACKED_ROW_BITS {
            expected_mask += AB::Expr::from(prep[ROW_BITS_START + bit])
                * select_mask_coefficient::<AB>(coefficients, self.statement, 1 + bit, layer_bits);
        }
        for bit in 0..PRODUCTION_TRACE_PACKED_COLUMN_BITS {
            expected_mask += AB::Expr::from(prep[COLUMN_BITS_START + bit])
                * select_mask_coefficient::<AB>(
                    coefficients,
                    self.statement,
                    1 + PRODUCTION_TRACE_PACKED_ROW_BITS + bit,
                    layer_bits,
                );
        }
        builder
            .when(core_active.clone())
            .assert_eq(local[CORE_MASK], expected_mask);
        builder.when(core_active.clone()).assert_eq(
            local[CORE_ENCODED],
            AB::Expr::from(local[CORE_ACCUMULATOR])
                + local[CORE_MASK]
                + AB::Expr::from(local[CORE_NEGATIVE]) * modulus.clone(),
        );
        builder.when(core_active.clone()).assert_eq(
            encoded.clone() * encoded.clone(),
            AB::Expr::from(local[CORE_SQUARE_QUOTIENT]) * modulus.clone()
                + square_remainder.clone(),
        );
        builder.when(core_active.clone()).assert_eq(
            square_remainder * encoded,
            AB::Expr::from(local[CORE_CUBE_QUOTIENT]) * modulus + cube_remainder.clone(),
        );
        builder.when(core_active.clone()).assert_eq(
            cube_remainder,
            AB::Expr::from(local[CORE_OUTPUT_QUOTIENT]) * F::from_u64(251)
                + local[CORE_OUTPUT_REMAINDER],
        );
        builder.when(core_active.clone()).assert_eq(
            local[CORE_ACTIVATION],
            AB::Expr::from(local[CORE_OUTPUT_REMAINDER]) - F::from_u64(125),
        );
        builder
            .when(core_active.clone())
            .assert_bool(local[CORE_NEGATIVE]);
        builder.when(core_active.clone()).assert_eq(
            local[CORE_SHIFTED_ACCUMULATOR],
            AB::Expr::from(local[CORE_ACCUMULATOR])
                + AB::Expr::from_u64(self.statement.max_abs_accumulator),
        );
        let table_inactive = AB::Expr::ONE - table_active;
        for group in 0..PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS {
            builder
                .when(table_inactive.clone())
                .assert_zero(local[TABLE_MULTIPLICITY_START + group]);
        }

        let specs = structured_transition_range_specs(self.statement).unwrap();
        for (spec_index, spec) in specs.into_iter().enumerate() {
            let source: AB::Expr = local[CORE_START + spec.oracle].into();
            let source_active: AB::Expr = prep[SOURCE_ACTIVE_START + spec_index].into();
            let mut reconstructed = AB::Expr::ZERO;
            let mut reconstructed_slack = AB::Expr::ZERO;
            for column in 0..PRODUCTION_TRACE_PACKED_DIGIT_COLUMNS {
                let slot = production_trace_packed_digit_slot_v2(
                    PRODUCTION_TRACE_PACKED_SPEC_ROWS[spec_index],
                    column,
                )
                .unwrap();
                if slot.active && usize::from(slot.spec_index) == spec_index {
                    let term =
                        AB::Expr::from(local[DIGIT_START + column]) * F::from_u64(slot.radix);
                    if slot.slack {
                        reconstructed_slack += term;
                    } else {
                        reconstructed += term;
                    }
                }
            }
            builder.when(source_active.clone()).assert_eq(
                reconstructed.clone() + reconstructed_slack.clone(),
                AB::Expr::from_u64(spec.maximum),
            );
            builder.push_local_interaction([
                (
                    vec![
                        AB::Expr::from(prep[CELL_LOOKUP_ID_START])
                            + AB::Expr::from_u64(spec_index as u64),
                        source.clone(),
                        AB::Expr::from_u64(spec.maximum) - source,
                    ],
                    Count::bounded(core_active.clone(), 1),
                ),
                (
                    vec![
                        AB::Expr::from(prep[CELL_LOOKUP_ID_START])
                            + AB::Expr::from_u64(spec_index as u64),
                        reconstructed,
                        reconstructed_slack,
                    ],
                    Count::provided(-source_active),
                ),
            ]);
        }

        for group in 0..PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS {
            let start = group * PRODUCTION_TRACE_PACKED_DIGITS_PER_LOOKUP;
            let mut terms = Vec::with_capacity(PRODUCTION_TRACE_PACKED_DIGITS_PER_LOOKUP + 1);
            for column in start..start + PRODUCTION_TRACE_PACKED_DIGITS_PER_LOOKUP {
                terms.push((
                    vec![local[DIGIT_START + column].into()],
                    Count::bounded(prep[DIGIT_ACTIVE_START + column].into(), 1),
                ));
            }
            terms.push((
                vec![prep[TABLE_VALUE].into()],
                Count::provided(-AB::Expr::from(local[TABLE_MULTIPLICITY_START + group])),
            ));
            builder.push_local_interaction(terms);
        }
    }
}

fn transition_core_values(
    statement: StructuredTransitionStatement,
    accumulator: i64,
    mask: u64,
) -> [u64; STRUCTURED_TRANSITION_REGULAR_ORACLES] {
    let z = accumulator + mask as i64;
    let modulus = u64::from(V2_TRANSITION_MODULUS);
    assert!(z.unsigned_abs() < modulus);
    assert!(accumulator.unsigned_abs() <= statement.max_abs_accumulator);
    assert!(mask <= statement.max_mask);

    let encoded = if z >= 0 {
        z as u64
    } else {
        modulus - z.unsigned_abs()
    };
    let square = encoded * encoded;
    let square_quotient = square / modulus;
    let square_remainder = square % modulus;
    let cube_product = square_remainder * encoded;
    let cube_quotient = cube_product / modulus;
    let cube_remainder = cube_product % modulus;
    let output_quotient = cube_remainder / 251;
    let output_remainder = cube_remainder % 251;
    let activation = output_remainder as i64 - 125;
    let shifted_accumulator = (accumulator + statement.max_abs_accumulator as i64) as u64;

    [
        F::from_int(accumulator).as_canonical_u64(),
        mask,
        encoded,
        square_quotient,
        square_remainder,
        cube_quotient,
        cube_remainder,
        output_quotient,
        output_remainder,
        u64::from(z < 0),
        F::from_int(activation).as_canonical_u64(),
        shifted_accumulator,
    ]
}

fn fixture_statement() -> StructuredTransitionStatement {
    StructuredTransitionStatement {
        layers: 4,
        rows: 4,
        cols: 8,
        max_abs_accumulator: 5_000,
        max_mask: 5_000,
    }
}

fn trusted_verifier_data(
    config: &Config,
    air: &ProductionRangeLookupAir,
    degree_bits: &[usize],
) -> Result<ProverData<Config>, VerificationShapeError> {
    if degree_bits != [TRACE_ROWS.ilog2() as usize] {
        return Err(VerificationShapeError::DegreeBits);
    }
    Ok(ProverData::from_airs_and_degrees(
        config,
        std::slice::from_ref(air),
        degree_bits,
    ))
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        String::new()
    }
}

fn invalid_trace_is_rejected(air: ProductionRangeLookupAir, trace: RowMajorMatrix<F>) -> bool {
    match catch_unwind(AssertUnwindSafe(|| {
        let config = build_packed_config();
        let instances = [StarkInstance {
            air: &air,
            trace: &trace,
            public_values: Vec::new(),
        }];
        let prover_data = ProverData::from_instances(&config, &instances);
        let proof = prove_batch(&config, &instances, &prover_data);
        let verifier_data = trusted_verifier_data(&config, &air, &proof.degree_bits)
            .expect("honest prover emits the pinned degree");
        verify_batch(
            &config,
            std::slice::from_ref(&air),
            &proof,
            &[Vec::new()],
            &verifier_data.common,
        )
        .is_err()
    })) {
        Ok(rejected) => rejected,
        Err(payload) => {
            let message = panic_message(payload);
            cfg!(debug_assertions)
                && (message.contains("Lookup mismatch")
                    || message.contains("constraints not satisfied"))
        }
    }
}

#[test]
fn compact_transition_batch_logup_proves_arithmetic_core_and_range_bindings() {
    let air = ProductionRangeLookupAir::canonical();
    let trace = air.valid_trace();
    let config = build_packed_config();
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: Vec::new(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);

    assert_eq!(proof.degree_bits, vec![TRACE_ROWS.ilog2() as usize]);
    assert_eq!(proof.lookup_terminals.len(), 1);
    assert!(proof.lookup_terminals[0].is_some());
    assert!(proof.commitments.permutation.is_some());
    assert_eq!(
        proof.opened_values.instances[0].permutation_local.len(),
        LOOKUP_AUX_BASE_WIDTH
    );
    assert_eq!(
        proof.opened_values.instances[0].permutation_next.len(),
        LOOKUP_AUX_BASE_WIDTH
    );
    let opened = &proof.opened_values.instances[0].base_opened_values;
    assert_eq!(opened.trace_local.len(), MAIN_WIDTH);
    assert_eq!(
        opened.preprocessed_local.as_ref().map(Vec::len),
        Some(PREPROCESSED_WIDTH)
    );
    assert_eq!(
        opened
            .quotient_chunks
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        vec![3; 8]
    );
    let verifier_data = trusted_verifier_data(&config, &air, &proof.degree_bits).unwrap();
    verify_batch(
        &config,
        std::slice::from_ref(&air),
        &proof,
        &[Vec::new()],
        &verifier_data.common,
    )
    .expect("honest compact range proof must verify");

    let native = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .serialize(&proof)
        .unwrap();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    std::io::Write::write_all(&mut encoder, &native).unwrap();
    let compressed = encoder.finish().unwrap();
    assert_eq!(native.len(), 222_960);
    assert!(compressed.len() < native.len());
    assert!(compressed.len() <= 165_000);

    let decoded: p3_batch_stark::BatchProof<Config> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .deserialize(&native)
        .unwrap();
    verify_batch(
        &config,
        &[air],
        &decoded,
        &[Vec::new()],
        &verifier_data.common,
    )
    .expect("the measured bincode baseline must still verify");
}

#[test]
fn compact_range_witness_mutations_are_rejected() {
    let air = ProductionRangeLookupAir::canonical();

    let mut mutations = (CORE_START..CORE_START + STRUCTURED_TRANSITION_REGULAR_ORACLES)
        .map(|column| (0, column))
        .collect::<Vec<_>>();
    mutations.extend([
        (0, DIGIT_START),
        (1, DIGIT_START + 7),
        (2, DIGIT_START + 24),
        (0, TABLE_MULTIPLICITY_START),
    ]);
    for (row, column) in mutations {
        let mut trace = air.valid_trace();
        trace.values[row * MAIN_WIDTH + column] += F::ONE;
        assert!(
            invalid_trace_is_rejected(air.clone(), trace),
            "mutation at row {row}, column {column} was accepted"
        );
    }
}

#[test]
fn verifier_rederives_compact_range_topology() {
    let air = ProductionRangeLookupAir::canonical();
    let trace = air.valid_trace();
    let config = build_packed_config();
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: Vec::new(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);

    for changed in [
        air.with_preprocessed_delta(0, CELL_LOOKUP_ID_START, 1),
        air.with_preprocessed_delta(1, SOURCE_ACTIVE_START, 1),
        air.with_preprocessed_delta(2, DIGIT_ACTIVE_START + 24, 1),
        air.with_preprocessed_delta(3, TABLE_VALUE, 1),
        air.with_preprocessed_delta(0, LAYER_BITS_START, 1),
        air.with_preprocessed_delta(0, ROW_BITS_START, 1),
        air.with_preprocessed_delta(0, COLUMN_BITS_START, 1),
    ] {
        let verifier_data = trusted_verifier_data(&config, &changed, &proof.degree_bits).unwrap();
        assert!(
            verify_batch(
                &config,
                &[changed],
                &proof,
                &[Vec::new()],
                &verifier_data.common,
            )
            .is_err()
        );
    }

    let different_mask = ProductionRangeLookupAir {
        statement: air.statement,
        mask: StructuredMaskPolynomial::from_challenge(
            &[0x43; 32],
            air.statement.layers,
            air.statement.rows,
            air.statement.cols,
        )
        .unwrap(),
        preprocessed_deltas: Vec::new(),
    };
    assert_eq!(
        air.canonical_preprocessed().values,
        different_mask.canonical_preprocessed().values
    );
    let verifier_data =
        trusted_verifier_data(&config, &different_mask, &proof.degree_bits).unwrap();
    assert!(
        verify_batch(
            &config,
            &[different_mask],
            &proof,
            &[Vec::new()],
            &verifier_data.common,
        )
        .is_err()
    );
}

#[test]
fn compact_range_verifier_rejects_untrusted_degree_bits() {
    let config = build_packed_config();
    let air = ProductionRangeLookupAir::canonical();
    assert!(matches!(
        trusted_verifier_data(&config, &air, &[]),
        Err(VerificationShapeError::DegreeBits)
    ));
    assert!(matches!(
        trusted_verifier_data(&config, &air, &[4]),
        Err(VerificationShapeError::DegreeBits)
    ));
    assert!(matches!(
        trusted_verifier_data(&config, &air, &[5, 5]),
        Err(VerificationShapeError::DegreeBits)
    ));
}

#[test]
fn compact_range_constraint_layout_is_pinned() {
    let air = ProductionRangeLookupAir::canonical();
    let trace = air.valid_trace();
    let config = build_packed_config();
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: Vec::new(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let lookups = &prover_data.common.lookups[0];
    let gadget = LogUpGadget::new();
    let base_layout = AirLayout::from_air::<F>(&air);
    let constraint_layout =
        get_constraint_layout::<F, EF, _, _>(&air, base_layout, lookups, &gadget);
    let max_degree = get_max_constraint_degree::<F, EF, _, _>(&air, base_layout, lookups, &gadget);
    let log_chunks =
        get_log_num_quotient_chunks::<F, EF, _, _>(&air, base_layout, lookups, 0, &gadget);

    assert_eq!(lookups.len(), LOOKUP_COUNT);
    assert_eq!(lookups.total_count_weight(), 36);
    assert_eq!(constraint_layout.base_indices.len(), 127);
    assert_eq!(constraint_layout.ext_indices.len(), 18);
    assert_eq!(constraint_layout.total_constraints(), 145);
    assert_eq!(LOOKUP_AUX_EXTENSION_WIDTH, 16);
    assert_eq!(LOOKUP_AUX_BASE_WIDTH, 48);
    assert_eq!(
        PREPROCESSED_WIDTH,
        PRODUCTION_TRACE_PACKED_PREPROCESSED_WIDTH
    );
    assert_eq!(max_degree, 9);
    assert_eq!(log_chunks, 3);

    let fri = FriParameters {
        log_blowup: PACKED_FRI_LOG_BLOWUP,
        log_final_poly_len: FRI_LOG_FINAL_POLY_LEN,
        max_log_arity: FRI_MAX_LOG_ARITY,
        num_queries: PACKED_FRI_QUERIES,
        commit_proof_of_work_bits: FRI_COMMIT_POW_BITS,
        query_proof_of_work_bits: FRI_QUERY_POW_BITS,
        mmcs: (),
    };
    let params = StarkSecurityParams::new(
        &fri,
        192,
        128,
        constraint_layout.total_constraints(),
        max_degree,
        LOOKUP_MAX_COMBO,
    );
    let security = ProvenSecurity::compute(&params, TRACE_ROWS);
    assert_eq!(security.unique_decoding_bits, 69);
    assert_eq!(security.list_decoding_bits, 128);
    assert_eq!(security.security_bits(), 128);

    let minimum_queries = (1..=256)
        .find(|queries| {
            let mut candidate = params.clone();
            candidate.fri_num_queries = *queries;
            ProvenSecurity::compute(&candidate, TRACE_ROWS).security_bits() >= 128
        })
        .expect("configured compact range proof must reach 128 proven bits");
    assert_eq!(minimum_queries, 56);
    assert_eq!(PACKED_FRI_QUERIES, minimum_queries + 1);

    let production_security = ProvenSecurity::compute(&params, 1 << 28);
    let production_minimum_queries = (1..=256)
        .find(|queries| {
            let mut candidate = params.clone();
            candidate.fri_num_queries = *queries;
            ProvenSecurity::compute(&candidate, 1 << 28).security_bits() >= 128
        })
        .unwrap();
    assert_eq!(production_security.unique_decoding_bits, 70);
    assert_eq!(production_security.list_decoding_bits, 128);
    assert_eq!(production_security.security_bits(), 128);
    assert_eq!(production_minimum_queries, 56);
}

#[test]
fn packed_transition_lookup_challenge_error_is_below_two_to_the_minus_163() {
    // All fifteen buses share one (alpha, beta) pair. The maximum payload width is
    // three, so different bus prefixes are separated at beta^3. Count roots
    // for collisions within each bus, across buses, a false rational sum, and
    // every denominator evaluated by the prover.
    let core_terms = (CELLS * 2) as u64;
    let mut nibble_terms = [0_u64; PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS];
    for row in 0..PRODUCTION_TRACE_PACKED_ROWS_PER_CELL {
        for column in 0..PRODUCTION_TRACE_PACKED_DIGIT_COLUMNS {
            if production_trace_packed_digit_slot_v2(row, column)
                .unwrap()
                .active
            {
                nibble_terms[column / PRODUCTION_TRACE_PACKED_DIGITS_PER_LOOKUP] += CELLS as u64;
            }
        }
    }
    for terms in &mut nibble_terms {
        *terms += 16;
    }
    assert_eq!(
        nibble_terms,
        [2_064, 2_064, 2_064, 2_064, 1_808, 1_552, 1_040]
    );
    let choose_two = |n: u64| n * (n - 1) / 2;

    let within_core_roots =
        STRUCTURED_TRANSITION_RANGE_SPEC_COUNT as u64 * 2 * choose_two(core_terms);
    let core_bus_pairs = choose_two(STRUCTURED_TRANSITION_RANGE_SPEC_COUNT as u64);
    let cross_core_roots = 3 * core_bus_pairs * core_terms * core_terms;
    let total_nibble_terms = nibble_terms.into_iter().sum::<u64>();
    let cross_core_nibble_roots =
        3 * STRUCTURED_TRANSITION_RANGE_SPEC_COUNT as u64 * core_terms * total_nibble_terms;
    let cross_nibble_roots = 3 * nibble_terms
        .iter()
        .enumerate()
        .flat_map(|(left, terms)| {
            nibble_terms[left + 1..]
                .iter()
                .map(move |other| terms * other)
        })
        .sum::<u64>();
    let beta_collision_roots =
        within_core_roots + cross_core_roots + cross_core_nibble_roots + cross_nibble_roots;
    let false_sum_roots =
        STRUCTURED_TRANSITION_RANGE_SPEC_COUNT as u64 * core_terms + total_nibble_terms - 1;
    let denominators_per_row = STRUCTURED_TRANSITION_RANGE_SPEC_COUNT * 2
        + PRODUCTION_TRACE_PACKED_DIGIT_LOOKUPS * (PRODUCTION_TRACE_PACKED_DIGITS_PER_LOOKUP + 1);
    let denominator_roots = (denominators_per_row * TRACE_ROWS) as u64;
    let lookup_error_roots = beta_collision_roots + false_sum_roots + denominator_roots;

    assert_eq!(within_core_roots, 522_240);
    assert_eq!(cross_core_roots, 5_505_024);
    assert_eq!(cross_core_nibble_roots, 77_758_464);
    assert_eq!(cross_nibble_roots, 204_562_176);
    assert_eq!(beta_collision_roots, 288_347_904);
    assert_eq!(false_sum_roots, 14_703);
    assert_eq!(denominator_roots, 26_112);
    assert_eq!(lookup_error_roots, 288_388_719);

    let field_order = U256::from(F::ORDER_U64);
    let extension_field_size = field_order * field_order * field_order;
    let numerator = U256::from(lookup_error_roots);
    assert!(numerator << 163usize <= extension_field_size);
    assert!(numerator << 164usize > extension_field_size);
}
