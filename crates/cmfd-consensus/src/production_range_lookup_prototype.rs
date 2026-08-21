//! Batch-STARK/LogUp prototype for the compact production range layout.
//!
//! This test-only argument proves the two relations required by the row-
//! transposed range witness:
//!
//! - each core source value and its fixed slack equal the final auxiliary
//!   accumulators carrying the same verifier-fixed lookup ID;
//! - each value and slack digit belongs to the verifier-fixed `0..15` table.
//!
//! The prototype uses eight transition cells so adversarial tests remain fast.
//! It is not a production proof type and does not activate the compact layout.

use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_air::symbolic::AirLayout;
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks, get_max_constraint_degree,
};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::FriParameters;
use p3_lookup::{Count, InteractionBuilder, LogUpGadget};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};
use primitive_types::U256;

use crate::structured_blake3_narrow::{
    Config, EF, F, FRI_COMMIT_POW_BITS, FRI_LOG_BLOWUP, FRI_LOG_FINAL_POLY_LEN, FRI_MAX_LOG_ARITY,
    FRI_QUERIES, FRI_QUERY_POW_BITS, build_config,
};
use crate::{
    PRODUCTION_TRACE_RANGE_ACTIVE_ROWS_PER_CELL, PRODUCTION_TRACE_RANGE_ROWS_PER_CELL,
    STRUCTURED_TRANSITION_RANGE_SPEC_COUNT, STRUCTURED_TRANSITION_REGULAR_ORACLES,
    StructuredTransitionStatement, production_trace_range_row_v1,
    structured_transition_range_specs,
};

const CELLS: usize = 8;
const TRACE_ROWS: usize = CELLS * PRODUCTION_TRACE_RANGE_ROWS_PER_CELL;

const CORE_START: usize = 0;
const DIGIT: usize = CORE_START + STRUCTURED_TRANSITION_REGULAR_ORACLES;
const SLACK_DIGIT: usize = DIGIT + 1;
const VALUE_ACCUMULATOR: usize = SLACK_DIGIT + 1;
const SLACK_ACCUMULATOR: usize = VALUE_ACCUMULATOR + 1;
const VALUE_TABLE_MULTIPLICITY: usize = SLACK_ACCUMULATOR + 1;
const SLACK_TABLE_MULTIPLICITY: usize = VALUE_TABLE_MULTIPLICITY + 1;
const MAIN_WIDTH: usize = SLACK_TABLE_MULTIPLICITY + 1;

const RANGE_ACTIVE: usize = 0;
const RANGE_FIRST: usize = 1;
const RANGE_LAST: usize = 2;
const RANGE_LOOKUP_ID: usize = 3;
const RANGE_MAXIMUM: usize = 4;
const RANGE_RADIX: usize = 5;
const CORE_ACTIVE: usize = 6;
const CORE_LOOKUP_ID_START: usize = 7;
const TABLE_ACTIVE: usize = 8;
const TABLE_VALUE: usize = 9;
const RANGE_LAST_SPEC_START: usize = 10;
const PREPROCESSED_WIDTH: usize = RANGE_LAST_SPEC_START + STRUCTURED_TRANSITION_RANGE_SPEC_COUNT;

const LOOKUP_COUNT: usize = STRUCTURED_TRANSITION_RANGE_SPEC_COUNT + 2;
const LOOKUP_MAX_COMBO: usize = 2;
const LOOKUP_AUX_EXTENSION_WIDTH: usize = LOOKUP_COUNT + 1;
const LOOKUP_AUX_BASE_WIDTH: usize = LOOKUP_AUX_EXTENSION_WIDTH * 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationShapeError {
    DegreeBits,
}

#[derive(Clone, Debug)]
struct ProductionRangeLookupAir {
    statement: StructuredTransitionStatement,
    preprocessed_deltas: Vec<(usize, usize, u64)>,
}

impl ProductionRangeLookupAir {
    fn canonical() -> Self {
        Self {
            statement: fixture_statement(),
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
        let specs = structured_transition_range_specs(self.statement).unwrap();
        std::array::from_fn(|cell| {
            let mut values = [0_u64; STRUCTURED_TRANSITION_REGULAR_ORACLES];
            values[0] = 7 + cell as u64;
            values[1] = 17 + cell as u64;
            values[9] = 27 + cell as u64;
            values[10] = 37 + cell as u64;
            for (spec_index, spec) in specs.into_iter().enumerate() {
                let seed = (cell as u64 + 1) * (spec_index as u64 + 3) * 0x1_2345;
                values[spec.oracle] = seed % (spec.maximum + 1);
            }
            values
        })
    }

    fn valid_trace(&self) -> RowMajorMatrix<F> {
        let core_values = self.core_values();
        let mut values = F::zero_vec(TRACE_ROWS * MAIN_WIDTH);
        let mut value_multiplicities = [0_u64; 16];
        let mut slack_multiplicities = [0_u64; 16];

        for row in 0..TRACE_ROWS {
            let cell = row / PRODUCTION_TRACE_RANGE_ROWS_PER_CELL;
            let local = &mut values[row * MAIN_WIDTH..(row + 1) * MAIN_WIDTH];
            if row % PRODUCTION_TRACE_RANGE_ROWS_PER_CELL == 0 {
                for (target, value) in local
                    [CORE_START..CORE_START + STRUCTURED_TRANSITION_REGULAR_ORACLES]
                    .iter_mut()
                    .zip(core_values[cell])
                {
                    *target = F::from_u64(value);
                }
            }

            let auxiliary =
                production_trace_range_row_v1(self.statement, &core_values[cell], row as u64)
                    .unwrap();
            if auxiliary.active {
                local[DIGIT] = F::from_u8(auxiliary.digit);
                local[SLACK_DIGIT] = F::from_u8(auxiliary.slack_digit);
                local[VALUE_ACCUMULATOR] = F::from_u64(auxiliary.value_accumulator);
                local[SLACK_ACCUMULATOR] = F::from_u64(auxiliary.slack_accumulator);
                value_multiplicities[usize::from(auxiliary.digit)] += 1;
                slack_multiplicities[usize::from(auxiliary.slack_digit)] += 1;
            }
        }
        for row in 0..16 {
            values[row * MAIN_WIDTH + VALUE_TABLE_MULTIPLICITY] =
                F::from_u64(value_multiplicities[row]);
            values[row * MAIN_WIDTH + SLACK_TABLE_MULTIPLICITY] =
                F::from_u64(slack_multiplicities[row]);
        }

        RowMajorMatrix::new(values, MAIN_WIDTH)
    }

    fn canonical_preprocessed(&self) -> RowMajorMatrix<F> {
        let specs = structured_transition_range_specs(self.statement).unwrap();
        let mut values = F::zero_vec(TRACE_ROWS * PREPROCESSED_WIDTH);

        for row in 0..TRACE_ROWS {
            let cell = row / PRODUCTION_TRACE_RANGE_ROWS_PER_CELL;
            let slot = row % PRODUCTION_TRACE_RANGE_ROWS_PER_CELL;
            let local = &mut values[row * PREPROCESSED_WIDTH..(row + 1) * PREPROCESSED_WIDTH];

            if slot == 0 {
                local[CORE_ACTIVE] = F::ONE;
                local[CORE_LOOKUP_ID_START] =
                    F::from_u64((cell * STRUCTURED_TRANSITION_RANGE_SPEC_COUNT + 1) as u64);
            }
            if row < 16 {
                local[TABLE_ACTIVE] = F::ONE;
                local[TABLE_VALUE] = F::from_u64(row as u64);
            }
            if slot >= PRODUCTION_TRACE_RANGE_ACTIVE_ROWS_PER_CELL {
                continue;
            }

            let mut offset = slot;
            for (spec_index, spec) in specs.into_iter().enumerate() {
                if offset < spec.digits {
                    local[RANGE_ACTIVE] = F::ONE;
                    local[RANGE_FIRST] = F::from_bool(offset == 0);
                    local[RANGE_LAST] = F::from_bool(offset + 1 == spec.digits);
                    local[RANGE_LOOKUP_ID] = F::from_u64(
                        (cell * STRUCTURED_TRANSITION_RANGE_SPEC_COUNT + spec_index + 1) as u64,
                    );
                    local[RANGE_MAXIMUM] = F::from_u64(spec.maximum);
                    local[RANGE_RADIX] = F::from_u64(1_u64 << (4 * offset));
                    if offset + 1 == spec.digits {
                        local[RANGE_LAST_SPEC_START + spec_index] = F::ONE;
                    }
                    break;
                }
                offset -= spec.digits;
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
        vec![DIGIT, SLACK_DIGIT, VALUE_ACCUMULATOR, SLACK_ACCUMULATOR]
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB> Air<AB> for ProductionRangeLookupAir
where
    AB: PermutationAirBuilder<F = F> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let (local, next, prep) = {
            let main = builder.main();
            (
                main.current_slice().to_vec(),
                main.next_slice().to_vec(),
                builder.preprocessed().current_slice().to_vec(),
            )
        };

        let active: AB::Expr = prep[RANGE_ACTIVE].into();
        let first: AB::Expr = prep[RANGE_FIRST].into();
        let last: AB::Expr = prep[RANGE_LAST].into();
        let core_active: AB::Expr = prep[CORE_ACTIVE].into();
        let table_active: AB::Expr = prep[TABLE_ACTIVE].into();

        builder.assert_bool(prep[RANGE_ACTIVE]);
        builder.assert_bool(prep[RANGE_FIRST]);
        builder.assert_bool(prep[RANGE_LAST]);
        builder.assert_bool(prep[CORE_ACTIVE]);
        builder.assert_bool(prep[TABLE_ACTIVE]);
        builder.assert_zero(first.clone() * (AB::Expr::ONE - active.clone()));
        builder.assert_zero(last.clone() * (AB::Expr::ONE - active.clone()));
        let mut last_spec_sum = AB::Expr::ZERO;
        for selector in &prep
            [RANGE_LAST_SPEC_START..RANGE_LAST_SPEC_START + STRUCTURED_TRANSITION_RANGE_SPEC_COUNT]
        {
            builder.assert_bool(*selector);
            last_spec_sum += *selector;
        }
        builder.assert_eq(last_spec_sum, last.clone());

        let range_inactive = AB::Expr::ONE - active.clone();
        for column in [DIGIT, SLACK_DIGIT, VALUE_ACCUMULATOR, SLACK_ACCUMULATOR] {
            builder
                .when(range_inactive.clone())
                .assert_zero(local[column]);
        }
        let core_inactive = AB::Expr::ONE - core_active.clone();
        for value in &local[CORE_START..CORE_START + STRUCTURED_TRANSITION_REGULAR_ORACLES] {
            builder.when(core_inactive.clone()).assert_zero(*value);
        }
        let table_inactive = AB::Expr::ONE - table_active;
        builder
            .when(table_inactive.clone())
            .assert_zero(local[VALUE_TABLE_MULTIPLICITY]);
        builder
            .when(table_inactive)
            .assert_zero(local[SLACK_TABLE_MULTIPLICITY]);

        builder
            .when(first.clone())
            .assert_eq(local[VALUE_ACCUMULATOR], local[DIGIT]);
        builder
            .when(first.clone())
            .assert_eq(local[SLACK_ACCUMULATOR], local[SLACK_DIGIT]);

        let continuation = active.clone() - last.clone();
        let next_radix = AB::Expr::from(prep[RANGE_RADIX]) * F::from_u64(16);
        builder
            .when_transition()
            .when(continuation.clone())
            .assert_eq(
                next[VALUE_ACCUMULATOR],
                AB::Expr::from(local[VALUE_ACCUMULATOR])
                    + AB::Expr::from(next[DIGIT]) * next_radix.clone(),
            );
        builder.when_transition().when(continuation).assert_eq(
            next[SLACK_ACCUMULATOR],
            AB::Expr::from(local[SLACK_ACCUMULATOR])
                + AB::Expr::from(next[SLACK_DIGIT]) * next_radix,
        );
        builder.when(last.clone()).assert_eq(
            AB::Expr::from(local[VALUE_ACCUMULATOR]) + local[SLACK_ACCUMULATOR],
            prep[RANGE_MAXIMUM],
        );

        let specs = structured_transition_range_specs(self.statement).unwrap();
        for (spec_index, spec) in specs.into_iter().enumerate() {
            let source: AB::Expr = local[CORE_START + spec.oracle].into();
            let last_for_spec: AB::Expr = prep[RANGE_LAST_SPEC_START + spec_index].into();
            builder.push_local_interaction([
                (
                    vec![
                        AB::Expr::from(prep[CORE_LOOKUP_ID_START])
                            + AB::Expr::from_u64(spec_index as u64),
                        source.clone(),
                        AB::Expr::from_u64(spec.maximum) - source,
                    ],
                    Count::bounded(core_active.clone(), 1),
                ),
                (
                    vec![
                        prep[RANGE_LOOKUP_ID].into(),
                        local[VALUE_ACCUMULATOR].into(),
                        local[SLACK_ACCUMULATOR].into(),
                    ],
                    Count::provided(-last_for_spec),
                ),
            ]);
        }

        builder.push_local_interaction([
            (vec![local[DIGIT].into()], Count::bounded(active.clone(), 1)),
            (
                vec![prep[TABLE_VALUE].into()],
                Count::provided(-AB::Expr::from(local[VALUE_TABLE_MULTIPLICITY])),
            ),
        ]);
        builder.push_local_interaction([
            (vec![local[SLACK_DIGIT].into()], Count::bounded(active, 1)),
            (
                vec![prep[TABLE_VALUE].into()],
                Count::provided(-AB::Expr::from(local[SLACK_TABLE_MULTIPLICITY])),
            ),
        ]);
    }
}

fn fixture_statement() -> StructuredTransitionStatement {
    StructuredTransitionStatement {
        layers: 1,
        rows: 2,
        cols: 4,
        max_abs_accumulator: 1_000,
        max_mask: 100,
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
        let config = build_config();
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
fn compact_range_batch_logup_proves_core_and_nibble_bindings() {
    let air = ProductionRangeLookupAir::canonical();
    let trace = air.valid_trace();
    let config = build_config();
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

    let verifier_data = trusted_verifier_data(&config, &air, &proof.degree_bits).unwrap();
    verify_batch(
        &config,
        &[air],
        &proof,
        &[Vec::new()],
        &verifier_data.common,
    )
    .expect("honest compact range proof must verify");
}

#[test]
fn compact_range_witness_mutations_are_rejected() {
    let air = ProductionRangeLookupAir::canonical();

    for (row, column) in [
        (0, DIGIT),
        (1, SLACK_DIGIT),
        (6, VALUE_ACCUMULATOR),
        (0, CORE_START + 2),
        (PRODUCTION_TRACE_RANGE_ACTIVE_ROWS_PER_CELL, DIGIT),
        (0, VALUE_TABLE_MULTIPLICITY),
    ] {
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
    let config = build_config();
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: Vec::new(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);

    for changed in [
        air.with_preprocessed_delta(6, RANGE_LOOKUP_ID, 1),
        air.with_preprocessed_delta(6, RANGE_MAXIMUM, 1),
        air.with_preprocessed_delta(1, RANGE_RADIX, 1),
        air.with_preprocessed_delta(49, RANGE_ACTIVE, 1),
        air.with_preprocessed_delta(3, TABLE_VALUE, 1),
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
}

#[test]
fn compact_range_verifier_rejects_untrusted_degree_bits() {
    let config = build_config();
    let air = ProductionRangeLookupAir::canonical();
    assert!(matches!(
        trusted_verifier_data(&config, &air, &[]),
        Err(VerificationShapeError::DegreeBits)
    ));
    assert!(matches!(
        trusted_verifier_data(&config, &air, &[8]),
        Err(VerificationShapeError::DegreeBits)
    ));
    assert!(matches!(
        trusted_verifier_data(&config, &air, &[9, 9]),
        Err(VerificationShapeError::DegreeBits)
    ));
}

#[test]
fn compact_range_constraint_layout_is_pinned() {
    let air = ProductionRangeLookupAir::canonical();
    let trace = air.valid_trace();
    let config = build_config();
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
    assert_eq!(lookups.total_count_weight(), 10);
    assert_eq!(constraint_layout.base_indices.len(), 39);
    assert_eq!(constraint_layout.ext_indices.len(), 13);
    assert_eq!(constraint_layout.total_constraints(), 52);
    assert_eq!(LOOKUP_AUX_EXTENSION_WIDTH, 11);
    assert_eq!(LOOKUP_AUX_BASE_WIDTH, 33);
    assert_eq!(max_degree, 3);
    assert_eq!(log_chunks, 1);

    let fri = FriParameters {
        log_blowup: FRI_LOG_BLOWUP,
        log_final_poly_len: FRI_LOG_FINAL_POLY_LEN,
        max_log_arity: FRI_MAX_LOG_ARITY,
        num_queries: FRI_QUERIES,
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
    assert_eq!(security.unique_decoding_bits, 50);
    assert_eq!(security.list_decoding_bits, 128);
    assert_eq!(security.security_bits(), 128);

    let minimum_queries = (1..=FRI_QUERIES)
        .find(|queries| {
            let mut candidate = params.clone();
            candidate.fri_num_queries = *queries;
            ProvenSecurity::compute(&candidate, TRACE_ROWS).security_bits() >= 128
        })
        .expect("configured compact range proof must reach 128 proven bits");
    assert_eq!(minimum_queries, 32);
    assert_eq!(FRI_QUERIES, minimum_queries + 1);
}

#[test]
fn compact_range_lookup_challenge_error_is_below_two_to_the_minus_172() {
    // All ten buses share one (alpha, beta) pair. The maximum payload width is
    // three, so different bus prefixes are separated at beta^3. Count roots
    // for collisions within each bus, across buses, a false rational sum, and
    // every denominator evaluated by the prover.
    let core_terms = (CELLS * 2) as u64;
    let nibble_terms = (CELLS * PRODUCTION_TRACE_RANGE_ACTIVE_ROWS_PER_CELL + 16) as u64;
    let choose_two = |n: u64| n * (n - 1) / 2;

    let within_core_roots =
        STRUCTURED_TRANSITION_RANGE_SPEC_COUNT as u64 * 2 * choose_two(core_terms);
    let core_bus_pairs = choose_two(STRUCTURED_TRANSITION_RANGE_SPEC_COUNT as u64);
    let cross_core_roots = 3 * core_bus_pairs * core_terms * core_terms;
    let cross_core_nibble_roots =
        3 * STRUCTURED_TRANSITION_RANGE_SPEC_COUNT as u64 * 2 * core_terms * nibble_terms;
    let cross_nibble_roots = 3 * nibble_terms * nibble_terms;
    let beta_collision_roots =
        within_core_roots + cross_core_roots + cross_core_nibble_roots + cross_nibble_roots;
    let false_sum_roots =
        STRUCTURED_TRANSITION_RANGE_SPEC_COUNT as u64 * core_terms + 2 * nibble_terms - 1;
    let denominator_roots = (LOOKUP_COUNT * 2 * TRACE_ROWS) as u64;
    let lookup_error_roots = beta_collision_roots + false_sum_roots + denominator_roots;

    assert_eq!(within_core_roots, 1_920);
    assert_eq!(cross_core_roots, 21_504);
    assert_eq!(cross_core_nibble_roots, 313_344);
    assert_eq!(cross_nibble_roots, 499_392);
    assert_eq!(beta_collision_roots, 836_160);
    assert_eq!(false_sum_roots, 943);
    assert_eq!(denominator_roots, 10_240);
    assert_eq!(lookup_error_roots, 847_343);

    let field_order = U256::from(F::ORDER_U64);
    let extension_field_size = field_order * field_order * field_order;
    let numerator = U256::from(lookup_error_roots);
    assert!(numerator << 172usize <= extension_field_size);
    assert!(numerator << 173usize > extension_field_size);
}
