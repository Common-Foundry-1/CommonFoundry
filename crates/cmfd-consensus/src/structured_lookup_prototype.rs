//! Isolated LogUp migration prototype for the narrow BLAKE3 AIR.
//!
//! The currently validated narrow proof remains on `p3-uni-stark`. This test-only
//! module proves the two relations that must replace its widest columns before
//! the production verifier can move to `p3-batch-stark`:
//!
//! - nibble XOR queries against a verifier-fixed 256-row truth table;
//! - tree-edge values against a verifier-fixed, unique, chronological schedule.
//!
//! Neither lookup is meaningful if its table or schedule is prover-chosen. Both
//! therefore live in the preprocessed commitment, while the verifier derives
//! fresh trusted `CommonData` from the AIR and proof degree instead of accepting
//! the prover's copy.
//!
//! This is a reduction prototype, not the production migration. It intentionally
//! recomputes its tiny preprocessed trace; the real verifier must construct
//! `CommonData` from the pinned preprocessed commitment without materializing the
//! production trace. Its two toy edges also occupy distinct consumer rows, while
//! the real tree lookup must support left and right children consumed on one row.

use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_air::symbolic::AirLayout;
use p3_air::{Air, BaseAir, PermutationAirBuilder, WindowAccess};
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

const TRACE_ROWS: usize = 256;
const XOR_QUERY_ROWS: usize = 32;
const EDGE_COUNT: usize = 2;
const EDGE_WORDS: usize = 8;

const XOR_X: usize = 0;
const XOR_Y: usize = 1;
const XOR_Z: usize = 2;
const XOR_TABLE_MULTIPLICITY: usize = 3;
const EDGE_PRODUCER_START: usize = 4;
const EDGE_CONSUMER_START: usize = EDGE_PRODUCER_START + EDGE_WORDS;
const MAIN_WIDTH: usize = EDGE_CONSUMER_START + EDGE_WORDS;

const TABLE_X: usize = 0;
const TABLE_Y: usize = 1;
const TABLE_Z: usize = 2;
const XOR_QUERY_SELECTOR: usize = 3;
const EDGE_PRODUCER_SELECTOR: usize = 4;
const EDGE_CONSUMER_SELECTOR: usize = 5;
const EDGE_ID: usize = 6;
const PREPROCESSED_WIDTH: usize = 7;

const LOOKUP_COUNT: usize = 2;
const LOOKUP_AUX_EXTENSION_WIDTH: usize = LOOKUP_COUNT + 1;
const LOOKUP_AUX_BASE_WIDTH: usize = LOOKUP_AUX_EXTENSION_WIDTH * 3;
const LOOKUP_MAX_COMBO: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScheduleError {
    RowOutOfRange,
    NonChronological,
    ReusedRow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationShapeError {
    DegreeBits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EdgeSchedule {
    /// `(producer_row, consumer_row)` for each stable edge identifier.
    edges: [(usize, usize); EDGE_COUNT],
}

impl EdgeSchedule {
    fn new(edges: [(usize, usize); EDGE_COUNT]) -> Result<Self, ScheduleError> {
        let mut occupied = [false; TRACE_ROWS];
        for &(producer, consumer) in &edges {
            if producer >= TRACE_ROWS || consumer >= TRACE_ROWS {
                return Err(ScheduleError::RowOutOfRange);
            }
            if producer >= consumer {
                return Err(ScheduleError::NonChronological);
            }
            if occupied[producer] || occupied[consumer] {
                return Err(ScheduleError::ReusedRow);
            }
            occupied[producer] = true;
            occupied[consumer] = true;
        }
        Ok(Self { edges })
    }

    fn canonical() -> Self {
        Self::new([(0, 4), (1, 5)]).expect("canonical schedule is valid")
    }
}

#[derive(Clone, Debug)]
struct LookupPrototypeAir {
    schedule: EdgeSchedule,
    table_corruption: Option<(usize, u8)>,
}

impl LookupPrototypeAir {
    fn new(schedule: EdgeSchedule) -> Self {
        Self {
            schedule,
            table_corruption: None,
        }
    }

    fn with_table_corruption(schedule: EdgeSchedule, row: usize, delta: u8) -> Self {
        assert!(row < TRACE_ROWS);
        assert_ne!(delta, 0);
        Self {
            schedule,
            table_corruption: Some((row, delta)),
        }
    }

    fn table_z(&self, row: usize, x: u8, y: u8) -> u8 {
        let delta = self
            .table_corruption
            .filter(|(corrupted_row, _)| *corrupted_row == row)
            .map_or(0, |(_, delta)| delta);
        (x ^ y) ^ delta
    }

    fn valid_trace(&self) -> RowMajorMatrix<F> {
        let mut values = F::zero_vec(TRACE_ROWS * MAIN_WIDTH);
        let mut multiplicities = [0_u64; TRACE_ROWS];

        for row in 0..XOR_QUERY_ROWS {
            let x = ((row * 5 + 1) & 0xf) as u8;
            let y = ((row * 11 + 3) & 0xf) as u8;
            let key = (usize::from(x) << 4) | usize::from(y);
            let local = &mut values[row * MAIN_WIDTH..(row + 1) * MAIN_WIDTH];
            local[XOR_X] = F::from_u8(x);
            local[XOR_Y] = F::from_u8(y);
            local[XOR_Z] = F::from_u8(self.table_z(key, x, y));
            multiplicities[key] += 1;
        }
        for (row, multiplicity) in multiplicities.into_iter().enumerate() {
            values[row * MAIN_WIDTH + XOR_TABLE_MULTIPLICITY] = F::from_u64(multiplicity);
        }

        for (edge, &(producer_row, consumer_row)) in self.schedule.edges.iter().enumerate() {
            for word in 0..EDGE_WORDS {
                let value = F::from_u64(1_000 + (edge * 100 + word) as u64);
                values[producer_row * MAIN_WIDTH + EDGE_PRODUCER_START + word] = value;
                values[consumer_row * MAIN_WIDTH + EDGE_CONSUMER_START + word] = value;
            }
        }

        RowMajorMatrix::new(values, MAIN_WIDTH)
    }
}

impl BaseAir<F> for LookupPrototypeAir {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut values = F::zero_vec(TRACE_ROWS * PREPROCESSED_WIDTH);
        for row in 0..TRACE_ROWS {
            let local = &mut values[row * PREPROCESSED_WIDTH..(row + 1) * PREPROCESSED_WIDTH];
            let x = (row >> 4) as u8;
            let y = (row & 0xf) as u8;
            local[TABLE_X] = F::from_u8(x);
            local[TABLE_Y] = F::from_u8(y);
            local[TABLE_Z] = F::from_u8(self.table_z(row, x, y));
            local[XOR_QUERY_SELECTOR] = F::from_bool(row < XOR_QUERY_ROWS);
        }
        for (edge, &(producer_row, consumer_row)) in self.schedule.edges.iter().enumerate() {
            let stable_id = F::from_u64((edge + 1) as u64);
            values[producer_row * PREPROCESSED_WIDTH + EDGE_PRODUCER_SELECTOR] = F::ONE;
            values[producer_row * PREPROCESSED_WIDTH + EDGE_ID] = stable_id;
            values[consumer_row * PREPROCESSED_WIDTH + EDGE_CONSUMER_SELECTOR] = F::ONE;
            values[consumer_row * PREPROCESSED_WIDTH + EDGE_ID] = stable_id;
        }
        Some(RowMajorMatrix::new(values, PREPROCESSED_WIDTH))
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
        Some(3)
    }
}

impl<AB> Air<AB> for LookupPrototypeAir
where
    AB: PermutationAirBuilder<F = F> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let (
            xor_query,
            xor_table,
            xor_query_selector_var,
            xor_table_multiplicity,
            edge_producer,
            edge_consumer,
            edge_producer_selector_var,
            edge_consumer_selector_var,
        ) = {
            let main = builder.main();
            let local = main.current_slice();
            let prep = builder.preprocessed().current_slice();

            let xor_query = vec![
                local[XOR_X].into(),
                local[XOR_Y].into(),
                local[XOR_Z].into(),
            ];
            let xor_table = vec![
                prep[TABLE_X].into(),
                prep[TABLE_Y].into(),
                prep[TABLE_Z].into(),
            ];
            let xor_table_multiplicity: AB::Expr = local[XOR_TABLE_MULTIPLICITY].into();

            let mut edge_producer = Vec::with_capacity(EDGE_WORDS + 1);
            edge_producer.push(prep[EDGE_ID].into());
            edge_producer.extend(
                local[EDGE_PRODUCER_START..EDGE_PRODUCER_START + EDGE_WORDS]
                    .iter()
                    .copied()
                    .map(Into::into),
            );
            let mut edge_consumer = Vec::with_capacity(EDGE_WORDS + 1);
            edge_consumer.push(prep[EDGE_ID].into());
            edge_consumer.extend(
                local[EDGE_CONSUMER_START..EDGE_CONSUMER_START + EDGE_WORDS]
                    .iter()
                    .copied()
                    .map(Into::into),
            );
            (
                xor_query,
                xor_table,
                prep[XOR_QUERY_SELECTOR],
                xor_table_multiplicity,
                edge_producer,
                edge_consumer,
                prep[EDGE_PRODUCER_SELECTOR],
                prep[EDGE_CONSUMER_SELECTOR],
            )
        };
        let xor_query_selector: AB::Expr = xor_query_selector_var.into();
        let edge_producer_selector: AB::Expr = edge_producer_selector_var.into();
        let edge_consumer_selector: AB::Expr = edge_consumer_selector_var.into();

        // Count::bounded only declares a bound. These constraints establish the
        // selectors are in fact in {0,1}; the fixed preprocessed commitment then
        // pins exactly which rows are active.
        builder.assert_bool(xor_query_selector_var);
        builder.assert_bool(edge_producer_selector_var);
        builder.assert_bool(edge_consumer_selector_var);
        builder.assert_zero(
            AB::Expr::from(edge_producer_selector_var) * AB::Expr::from(edge_consumer_selector_var),
        );

        builder.push_local_interaction([
            (xor_query, Count::bounded(xor_query_selector, 1)),
            (xor_table, Count::provided(-xor_table_multiplicity)),
        ]);
        builder.push_local_interaction([
            (edge_consumer, Count::bounded(edge_consumer_selector, 1)),
            (edge_producer, Count::provided(-edge_producer_selector)),
        ]);
    }
}

fn trusted_verifier_data(
    config: &Config,
    air: &LookupPrototypeAir,
    degree_bits: &[usize],
) -> Result<ProverData<Config>, VerificationShapeError> {
    let pinned = TRACE_ROWS.ilog2() as usize;
    if degree_bits != [pinned] {
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

fn invalid_trace_is_rejected(air: LookupPrototypeAir, trace: RowMajorMatrix<F>) -> bool {
    match catch_unwind(AssertUnwindSafe(|| {
        let config = build_config();
        let instances = [StarkInstance {
            air: &air,
            trace: &trace,
            public_values: Vec::new(),
        }];
        let prover_data = ProverData::from_instances(&config, &instances);
        let proof = prove_batch(&config, &instances, &prover_data);

        // CommonData is consensus input, not prover-authored proof data. Pin the
        // expected degree before deriving it from the trusted AIR.
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
        // Debug builds replay lookup multisets before proving. Accept only that
        // exact fail-fast path; an unrelated panic must never satisfy the test.
        Err(payload) => {
            cfg!(debug_assertions) && panic_message(payload).contains("Lookup mismatch")
        }
    }
}

#[test]
fn batch_logup_proves_xor_table_and_chronological_edges() {
    let air = LookupPrototypeAir::new(EdgeSchedule::canonical());
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
    assert_eq!(
        proof.opened_values.instances[0]
            .base_opened_values
            .quotient_chunks
            .len(),
        1 << 1
    );

    let verifier_data = trusted_verifier_data(&config, &air, &proof.degree_bits).unwrap();
    verify_batch(
        &config,
        &[air],
        &proof,
        &[Vec::new()],
        &verifier_data.common,
    )
    .expect("honest lookup proof must verify");
}

#[test]
fn invalid_xor_and_substituted_edge_values_are_rejected() {
    let air = LookupPrototypeAir::new(EdgeSchedule::canonical());

    let mut bad_xor = air.valid_trace();
    bad_xor.values[XOR_Z] += F::ONE;
    assert!(invalid_trace_is_rejected(air.clone(), bad_xor));

    let mut bad_edge = air.valid_trace();
    let consumer_row = air.schedule.edges[0].1;
    bad_edge.values[consumer_row * MAIN_WIDTH + EDGE_CONSUMER_START + 3] += F::ONE;
    assert!(invalid_trace_is_rejected(air.clone(), bad_edge));

    let mut bad_multiplicity = air.valid_trace();
    let first_key = (1 << 4) | 3;
    bad_multiplicity.values[first_key * MAIN_WIDTH + XOR_TABLE_MULTIPLICITY] += F::ONE;
    assert!(invalid_trace_is_rejected(air, bad_multiplicity));
}

#[test]
fn edge_schedule_requires_unique_chronological_slots() {
    assert_eq!(
        EdgeSchedule::new([(4, 0), (1, 5)]),
        Err(ScheduleError::NonChronological)
    );
    assert_eq!(
        EdgeSchedule::new([(0, 4), (0, 5)]),
        Err(ScheduleError::ReusedRow)
    );
    assert_eq!(
        EdgeSchedule::new([(0, TRACE_ROWS), (1, 5)]),
        Err(ScheduleError::RowOutOfRange)
    );
}

#[test]
fn verifier_binds_the_preprocessed_edge_topology() {
    let air = LookupPrototypeAir::new(EdgeSchedule::canonical());
    let trace = air.valid_trace();
    let config = build_config();
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: Vec::new(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);

    // Same widths and rows, but the two consumers are assigned to the opposite
    // stable IDs. The verifier-derived preprocessed commitment must differ.
    let substituted = LookupPrototypeAir::new(
        EdgeSchedule::new([(0, 5), (1, 4)]).expect("substituted schedule is well formed"),
    );
    let verifier_data = trusted_verifier_data(&config, &substituted, &proof.degree_bits).unwrap();
    assert!(
        verify_batch(
            &config,
            &[substituted],
            &proof,
            &[Vec::new()],
            &verifier_data.common,
        )
        .is_err()
    );
}

#[test]
fn verifier_rederives_the_canonical_xor_table() {
    let first_key = (1 << 4) | 3;
    let malicious =
        LookupPrototypeAir::with_table_corruption(EdgeSchedule::canonical(), first_key, 1);
    let trace = malicious.valid_trace();
    let config = build_config();
    let instances = [StarkInstance {
        air: &malicious,
        trace: &trace,
        public_values: Vec::new(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);

    let matching_data = trusted_verifier_data(&config, &malicious, &proof.degree_bits).unwrap();
    verify_batch(
        &config,
        std::slice::from_ref(&malicious),
        &proof,
        &[Vec::new()],
        &matching_data.common,
    )
    .expect("internally consistent malicious table demonstrates the trust boundary");

    let canonical = LookupPrototypeAir::new(EdgeSchedule::canonical());
    let canonical_data = trusted_verifier_data(&config, &canonical, &proof.degree_bits).unwrap();
    assert!(
        verify_batch(
            &config,
            &[canonical],
            &proof,
            &[Vec::new()],
            &canonical_data.common,
        )
        .is_err()
    );
}

#[test]
fn verifier_rejects_untrusted_degree_bits_before_key_derivation() {
    let config = build_config();
    let air = LookupPrototypeAir::new(EdgeSchedule::canonical());

    assert!(matches!(
        trusted_verifier_data(&config, &air, &[]),
        Err(VerificationShapeError::DegreeBits)
    ));
    assert!(matches!(
        trusted_verifier_data(&config, &air, &[TRACE_ROWS.ilog2() as usize - 1]),
        Err(VerificationShapeError::DegreeBits)
    ));
    assert!(matches!(
        trusted_verifier_data(
            &config,
            &air,
            &[TRACE_ROWS.ilog2() as usize, TRACE_ROWS.ilog2() as usize]
        ),
        Err(VerificationShapeError::DegreeBits)
    ));
}

#[test]
fn lookup_layout_and_security_budget_are_pinned() {
    let air = LookupPrototypeAir::new(EdgeSchedule::canonical());
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
    let log_quotient_chunks =
        get_log_num_quotient_chunks::<F, EF, _, _>(&air, base_layout, lookups, 0, &gadget);
    assert_eq!(lookups.len(), LOOKUP_COUNT);
    assert_eq!(lookups.total_count_weight(), 2);
    assert_eq!(constraint_layout.base_indices.len(), 4);
    assert_eq!(constraint_layout.ext_indices.len(), 5);
    assert_eq!(constraint_layout.total_constraints(), 9);
    assert_eq!(LOOKUP_AUX_EXTENSION_WIDTH, 3);
    assert_eq!(LOOKUP_AUX_BASE_WIDTH, 9);
    assert_eq!(max_degree, 3);
    assert_eq!(log_quotient_chunks, 1);
    assert_eq!(1 << log_quotient_chunks, 2);

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

    let minimum_queries = (1..=FRI_QUERIES)
        .find(|queries| {
            let mut candidate = params.clone();
            candidate.fri_num_queries = *queries;
            ProvenSecurity::compute(&candidate, TRACE_ROWS).security_bits() >= 128
        })
        .expect("configured lookup proof must reach 128 proven bits");
    assert_eq!(minimum_queries, 32);
    assert_eq!(FRI_QUERIES, minimum_queries + 1);
}

#[test]
fn lookup_challenge_error_is_below_two_to_the_minus_175() {
    // p3-batch-stark samples one (alpha, beta) pair for the whole batch and
    // separates the two buses by powers of beta. Count every possible root of
    // the resulting bad-challenge polynomials, including cross-bus collisions.
    let xor_active_terms = (XOR_QUERY_ROWS + TRACE_ROWS) as u64;
    let edge_active_terms = (EDGE_COUNT * 2) as u64;
    let choose_two = |n: u64| n * (n - 1) / 2;
    let beta_collision_roots = 2 * choose_two(xor_active_terms)
        + 8 * choose_two(edge_active_terms)
        + 9 * xor_active_terms * edge_active_terms;
    let false_sum_roots = xor_active_terms + edge_active_terms - 1;
    let denominator_roots = (LOOKUP_COUNT * 2 * TRACE_ROWS) as u64;
    let lookup_error_roots = beta_collision_roots + false_sum_roots + denominator_roots;

    assert_eq!(beta_collision_roots, 93_072);
    assert_eq!(false_sum_roots, 291);
    assert_eq!(denominator_roots, 1_024);
    assert_eq!(lookup_error_roots, 94_387);

    let field_order = U256::from(F::ORDER_U64);
    let extension_field_size = field_order * field_order * field_order;
    let numerator = U256::from(lookup_error_roots);
    assert!(numerator << 175usize <= extension_field_size);
    assert!(numerator << 176usize > extension_field_size);

    // This is the lookup-reduction component only. The STARK/PCS component is
    // pinned separately above; a production gate must report their union bound.
}
