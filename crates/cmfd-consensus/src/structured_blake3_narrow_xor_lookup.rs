//! Real-row XOR lookup migration prototype for the narrow BLAKE3 AIR.
//!
//! This module keeps the v4 runtime and wire path unchanged. It reuses the
//! existing tree schedule, public inputs, non-XOR constraints, and pinned
//! preprocessed commitment while replacing only the four 32-bit XOR witness
//! decompositions with nibble lookups and an explicit rotate-right-7 helper.

use std::borrow::{Borrow, BorrowMut};

use p3_air::symbolic::AirLayout;
use p3_air::{Air, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks, get_max_constraint_degree,
};
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder, LogUpGadget, Lookups};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};
use primitive_types::U256;

use super::*;
use crate::structured_blake3_identity::PINNED_PREPROCESSED_KEYS;

const XOR_NIBBLES: usize = 8;
const XOR_LOOKUPS: usize = 2;
const XOR_TABLE_ROWS: usize = 256;

const INPUT_B: usize = 0;
const INPUT_D: usize = 1;
const RAW_B: usize = 2;
const RAW_D: usize = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct LookupStateCols<T> {
    words: [T; 16],
    xor_nibbles: [[T; XOR_NIBBLES]; 4],
    range_nibbles: [[T; XOR_NIBBLES]; 2],
    rotate7_high_bits: [T; XOR_NIBBLES],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LookupMainCols<T> {
    state: LookupStateCols<T>,
    message: [T; MESSAGE_WORDS],
    original_nibbles: [[T; 2]; BYTES_PER_EVAL_ROW],
    chaining_value: [T; CV_WORDS],
    output_words: [T; CV_WORDS],
    evaluation_accumulator: [T; 3],
    stack: [[T; CV_WORDS]; MAX_STACK_DEPTH],
    xor_table: [T; 3],
    xor_table_multiplicity: [T; XOR_LOOKUPS],
}

const LOOKUP_MAIN_WIDTH: usize = size_of::<LookupMainCols<u8>>();

impl<T> Borrow<LookupMainCols<T>> for [T] {
    fn borrow(&self) -> &LookupMainCols<T> {
        assert_eq!(self.len(), LOOKUP_MAIN_WIDTH);
        unsafe { &*self.as_ptr().cast::<LookupMainCols<T>>() }
    }
}

impl<T> BorrowMut<LookupMainCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut LookupMainCols<T> {
        assert_eq!(self.len(), LOOKUP_MAIN_WIDTH);
        unsafe { &mut *self.as_mut_ptr().cast::<LookupMainCols<T>>() }
    }
}

#[derive(Clone, Debug)]
struct NarrowBlake3XorLookupAir {
    inner: NarrowBlake3Air,
}

impl NarrowBlake3XorLookupAir {
    fn new(statement: &StructuredBlake3Statement) -> Result<Self, NarrowBlake3Error> {
        Ok(Self {
            inner: NarrowBlake3Air::new(statement)?,
        })
    }
}

impl BaseAir<F> for NarrowBlake3XorLookupAir {
    fn width(&self) -> usize {
        LOOKUP_MAIN_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.inner.preprocessed_trace()
    }

    fn preprocessed_width(&self) -> usize {
        self.inner.preprocessed_width()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.inner.preprocessed_next_row_columns()
    }

    fn num_periodic_columns(&self) -> usize {
        ACTIVATION_HIGH_WEIGHT_WIDTH + 3
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let mut columns = self.inner.periodic_columns();
        columns.push(
            (0..XOR_TABLE_ROWS)
                .map(|row| F::from_usize(row >> 4))
                .collect(),
        );
        columns.push(
            (0..XOR_TABLE_ROWS)
                .map(|row| F::from_usize(row & 0xf))
                .collect(),
        );
        columns.push(
            (0..XOR_TABLE_ROWS)
                .map(|row| F::from_usize((row >> 4) ^ (row & 0xf)))
                .collect(),
        );
        columns
    }

    fn periodic_values(&self, row_index: usize) -> Vec<F> {
        let mut values = self.inner.periodic_values(row_index);
        let table_row = row_index % XOR_TABLE_ROWS;
        let x = table_row >> 4;
        let y = table_row & 0xf;
        values.extend([F::from_usize(x), F::from_usize(y), F::from_usize(x ^ y)]);
        values
    }

    fn num_public_values(&self) -> usize {
        self.inner.num_public_values()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(16)
    }
}

fn legacy_view<T: Copy>(row: &LookupMainCols<T>) -> MainCols<T> {
    let filler = row.state.words[0];
    MainCols {
        state: StateCols {
            words: row.state.words,
            xor_bits: [[filler; WORD_BITS]; 4],
            range_nibbles: row.state.range_nibbles,
        },
        message: row.message,
        original_nibbles: row.original_nibbles,
        chaining_value: row.chaining_value,
        output_words: row.output_words,
        evaluation_accumulator: row.evaluation_accumulator,
        stack: row.stack,
    }
}

fn pack_nibble_exprs<AB: p3_air::AirBuilder>(nibbles: &[AB::Expr; XOR_NIBBLES]) -> AB::Expr {
    let mut factor = AB::Expr::ONE;
    let mut result = AB::Expr::ZERO;
    for nibble in nibbles {
        result += nibble.clone() * factor.clone();
        factor *= AB::Expr::from_u8(16);
    }
    result
}

fn rotate_right_aligned<AB: p3_air::AirBuilder>(
    raw: &[AB::Var; XOR_NIBBLES],
    rotation: usize,
) -> AB::Expr {
    debug_assert_eq!(rotation % 4, 0);
    let shift = rotation / 4;
    let output = array::from_fn(|index| raw[(index + shift) % XOR_NIBBLES].into());
    pack_nibble_exprs::<AB>(&output)
}

fn rotate_right_seven<AB: p3_air::AirBuilder>(
    raw: &[AB::Var; XOR_NIBBLES],
    high_bits: &[AB::Var; XOR_NIBBLES],
) -> AB::Expr {
    let output = array::from_fn(|index| {
        let high: AB::Expr = high_bits[(index + 1) % XOR_NIBBLES].into();
        let next_raw: AB::Expr = raw[(index + 2) % XOR_NIBBLES].into();
        let next_high: AB::Expr = high_bits[(index + 2) % XOR_NIBBLES].into();
        high + AB::Expr::TWO * (next_raw - AB::Expr::from_u8(8) * next_high)
    });
    pack_nibble_exprs::<AB>(&output)
}

fn constrain_lookup_ranges<AB: p3_air::AirBuilder>(
    builder: &mut AB,
    local: &LookupMainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
) {
    for nibble in local
        .state
        .xor_nibbles
        .iter()
        .flatten()
        .chain(local.state.range_nibbles.iter().flatten())
        .chain(local.original_nibbles.iter().flatten())
    {
        let value: AB::Expr = (*nibble).into();
        let mut range = AB::Expr::ONE;
        for allowed in 0..16 {
            range *= value.clone() - AB::Expr::from_u8(allowed);
        }
        builder.assert_zero(range);
    }

    let r7_active =
        (AB::Expr::from(prep.phase[1]) + prep.phase[3]) * AB::Expr::from(prep.is_active_operation);
    builder.assert_bool(r7_active.clone());
    for index in 0..XOR_NIBBLES {
        let helper = local.state.rotate7_high_bits[index];
        builder.assert_zero((AB::Expr::ONE - r7_active.clone()) * helper);
        builder.when(r7_active.clone()).assert_bool(helper);

        let raw: AB::Expr = local.state.xor_nibbles[RAW_B][index].into();
        let low = raw - AB::Expr::from_u8(8) * AB::Expr::from(helper);
        let mut low_range = AB::Expr::ONE;
        for allowed in 0..8 {
            low_range *= low.clone() - AB::Expr::from_u8(allowed);
        }
        builder.when(r7_active.clone()).assert_zero(low_range);
    }
}

fn constrain_round_lookup<AB: p3_air::AirBuilder>(
    builder: &mut AB,
    local: &LookupMainCols<AB::Var>,
    next: &LookupMainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
) {
    let message = local.message.map(Into::into);
    for phase in 0..4 {
        for index in 0..4 {
            let active =
                AB::Expr::from(prep.phase[phase]) * prep.g_index[index] * prep.is_active_operation;
            constrain_half_g_lookup(builder, local, next, &message, active.clone(), index, phase);
            let diagonal = phase >= 2;
            let changed = [
                index,
                4 + if diagonal { (index + 1) % 4 } else { index },
                8 + if diagonal { (index + 2) % 4 } else { index },
                12 + if diagonal { (index + 3) % 4 } else { index },
            ];
            for word in 0..16 {
                if !changed.contains(&word) {
                    builder
                        .when_transition()
                        .when(active.clone())
                        .assert_eq(next.state.words[word], local.state.words[word]);
                }
            }
        }
    }

    let g_active = prep.phase.iter().fold(AB::Expr::ZERO, |sum, selector| {
        sum + AB::Expr::from(*selector)
    }) * prep.is_active_operation;
    let last_g = AB::Expr::from(prep.round[6]) * prep.permute_message * prep.is_active_operation;
    for word in 0..CV_WORDS {
        builder
            .when_transition()
            .when(g_active.clone() - last_g.clone())
            .assert_eq(next.output_words[word], local.output_words[word]);
    }

    constrain_finalization_lookup(builder, local, next, prep);
}

fn constrain_half_g_lookup<AB: p3_air::AirBuilder>(
    builder: &mut AB,
    local: &LookupMainCols<AB::Var>,
    next: &LookupMainCols<AB::Var>,
    message: &[AB::Expr; MESSAGE_WORDS],
    active: AB::Expr,
    index: usize,
    phase: usize,
) {
    let second = phase % 2 == 1;
    let diagonal = phase >= 2;
    let a = index;
    let b = 4 + if diagonal { (index + 1) % 4 } else { index };
    let c = 8 + if diagonal { (index + 2) % 4 } else { index };
    let d = 12 + if diagonal { (index + 3) % 4 } else { index };
    let message_index = if diagonal {
        8 + 2 * index + usize::from(second)
    } else {
        2 * index + usize::from(second)
    };

    let input_b = &local.state.xor_nibbles[INPUT_B];
    let input_d = &local.state.xor_nibbles[INPUT_D];
    let raw_b = &local.state.xor_nibbles[RAW_B];
    let raw_d = &local.state.xor_nibbles[RAW_D];
    let output_a = &local.state.range_nibbles[0];
    let output_c = &local.state.range_nibbles[1];

    let expected_a = pack_nibbles::<AB>(output_a);
    let expected_c = pack_nibbles::<AB>(output_c);
    builder
        .when(active.clone())
        .assert_eq(pack_nibbles::<AB>(input_b), local.state.words[b]);
    builder
        .when(active.clone())
        .assert_eq(pack_nibbles::<AB>(input_d), local.state.words[d]);
    builder
        .when(active.clone())
        .assert_eq(expected_a.clone(), next.state.words[a]);
    builder
        .when(active.clone())
        .assert_eq(expected_c.clone(), next.state.words[c]);

    constrain_add3(
        builder,
        active.clone(),
        expected_a.clone(),
        local.state.words[a].into(),
        local.state.words[b].into(),
        message[message_index].clone(),
    );
    constrain_add2(
        builder,
        active.clone(),
        expected_c,
        local.state.words[c].into(),
        next.state.words[d].into(),
    );

    let rotated_d = rotate_right_aligned::<AB>(raw_d, if second { 8 } else { 16 });
    let rotated_b = if second {
        rotate_right_seven::<AB>(raw_b, &local.state.rotate7_high_bits)
    } else {
        rotate_right_aligned::<AB>(raw_b, 12)
    };
    builder
        .when(active.clone())
        .assert_eq(next.state.words[d], rotated_d);
    builder
        .when(active)
        .assert_eq(next.state.words[b], rotated_b);
}

fn constrain_finalization_lookup<AB: p3_air::AirBuilder>(
    builder: &mut AB,
    local: &LookupMainCols<AB::Var>,
    next: &LookupMainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
) {
    for word in 0..CV_WORDS {
        let active = AB::Expr::from(prep.final_word[word]) * prep.is_active_operation;
        let left = &local.state.xor_nibbles[INPUT_B];
        let right = &local.state.range_nibbles[1];
        let output = &local.state.xor_nibbles[RAW_B];
        builder
            .when(active.clone())
            .assert_eq(pack_nibbles::<AB>(left), local.state.words[word]);
        builder.when(active.clone()).assert_eq(
            pack_nibbles::<AB>(right),
            local.state.words[word + CV_WORDS],
        );
        builder
            .when(active.clone())
            .assert_eq(local.output_words[word], pack_nibbles::<AB>(output));
        for later in word + 1..CV_WORDS {
            builder
                .when(active.clone())
                .assert_zero(local.output_words[later]);
        }
        if word + 1 < CV_WORDS {
            for state_word in 0..16 {
                builder
                    .when_transition()
                    .when(active.clone())
                    .assert_eq(next.state.words[state_word], local.state.words[state_word]);
            }
            for completed in 0..=word {
                builder
                    .when_transition()
                    .when(active.clone())
                    .assert_eq(next.output_words[completed], local.output_words[completed]);
            }
        }
    }
}

fn constrain_digest_lookup<AB: p3_air::AirBuilder>(
    builder: &mut AB,
    local: &LookupMainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
) {
    let public = builder.public_values().to_vec();
    let output = &local.state.xor_nibbles[RAW_B];
    for word in 0..CV_WORDS {
        let active = AB::Expr::from(prep.is_root) * prep.final_word[word];
        for byte in 0..4 {
            let byte_nibbles = [output[2 * byte], output[2 * byte + 1]];
            builder
                .when(active.clone())
                .assert_eq(byte_expr::<AB>(&byte_nibbles), public[40 + word * 4 + byte]);
        }
    }
}

fn constrain_evaluation_lookup<AB: p3_air::AirBuilder>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    point_variables: usize,
) {
    let public = builder.public_values().to_vec();
    let periodic = builder.periodic_values().to_vec();
    debug_assert_eq!(periodic.len(), ACTIVATION_HIGH_WEIGHT_WIDTH + 3);
    let high_weight = ExtExpr(array::from_fn(|limb| periodic[limb].into()));
    let mut contribution = ExtExpr::zero();
    for byte in 0..BYTES_PER_EVAL_ROW {
        let mut low_weight = ExtExpr::one();
        for variable in 0..LOW_EVALUATION_VARIABLES {
            let point = ExtExpr(array::from_fn(|limb| {
                public[72 + 3 * variable + limb].into()
            }));
            let bit = AB::Expr::from_bool((byte >> variable) & 1 == 1);
            let one = ExtExpr::one();
            let factor =
                one.clone() - point.clone() + (point.clone() + point - one) * ExtExpr::splat(bit);
            low_weight = low_weight * factor;
        }
        let selected = byte_expr::<AB>(&local.original_nibbles[byte]) - AB::Expr::from_u8(125);
        contribution = contribution + high_weight.clone() * low_weight * ExtExpr::splat(selected);
    }
    let current = ExtExpr(local.evaluation_accumulator.map(Into::into));
    let expected = current + contribution;
    for limb in 0..3 {
        builder
            .when_first_row()
            .assert_zero(local.evaluation_accumulator[limb]);
        builder
            .when_transition()
            .assert_eq(next.evaluation_accumulator[limb], expected.0[limb].clone());
        builder.when_last_row().assert_eq(
            local.evaluation_accumulator[limb],
            public[72 + 3 * point_variables + limb],
        );
    }
}

fn emit_xor_lookups<AB>(builder: &mut AB, local: &LookupMainCols<AB::Var>, prep: &PrepCols<AB::Var>)
where
    AB: PermutationAirBuilder<F = F> + InteractionBuilder,
{
    let table = local
        .xor_table
        .iter()
        .copied()
        .map(Into::into)
        .collect::<Vec<AB::Expr>>();

    let g_active = prep.phase.iter().fold(AB::Expr::ZERO, |sum, selector| {
        sum + AB::Expr::from(*selector)
    }) * prep.is_active_operation;
    let final_active = prep
        .final_word
        .iter()
        .fold(AB::Expr::ZERO, |sum, selector| {
            sum + AB::Expr::from(*selector)
        })
        * prep.is_active_operation;
    let b_or_final_active = g_active.clone() + final_active;

    // Count::bounded trusts this declared weight. Prove the selectors are in
    // {0,1}, including the disjoint union used by the B/final lookup.
    builder.assert_bool(g_active.clone());
    builder.assert_bool(b_or_final_active.clone());

    let mut b_or_final = Vec::with_capacity(XOR_NIBBLES + 1);
    let mut d = Vec::with_capacity(XOR_NIBBLES + 1);
    for nibble in 0..XOR_NIBBLES {
        b_or_final.push((
            vec![
                local.state.xor_nibbles[INPUT_B][nibble].into(),
                local.state.range_nibbles[1][nibble].into(),
                local.state.xor_nibbles[RAW_B][nibble].into(),
            ],
            Count::bounded(b_or_final_active.clone(), 1),
        ));
        d.push((
            vec![
                local.state.xor_nibbles[INPUT_D][nibble].into(),
                local.state.range_nibbles[0][nibble].into(),
                local.state.xor_nibbles[RAW_D][nibble].into(),
            ],
            Count::bounded(g_active.clone(), 1),
        ));
    }
    b_or_final.push((
        table.clone(),
        Count::provided(-AB::Expr::from(local.xor_table_multiplicity[0])),
    ));
    d.push((
        table,
        Count::provided(-AB::Expr::from(local.xor_table_multiplicity[1])),
    ));
    builder.push_local_interaction(b_or_final);
    builder.push_local_interaction(d);
}

fn constrain_lookup_table<AB: p3_air::AirBuilder>(
    builder: &mut AB,
    local: &LookupMainCols<AB::Var>,
) {
    let periodic = builder.periodic_values().to_vec();
    debug_assert_eq!(periodic.len(), ACTIVATION_HIGH_WEIGHT_WIDTH + 3);
    for (column, expected) in local
        .xor_table
        .iter()
        .zip(&periodic[ACTIVATION_HIGH_WEIGHT_WIDTH..])
    {
        builder.assert_eq(*column, *expected);
    }
}

impl<AB> Air<AB> for NarrowBlake3XorLookupAir
where
    AB: PermutationAirBuilder<F = F> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let (local, next, prep) = {
            let main = builder.main();
            let local =
                *<[AB::Var] as Borrow<LookupMainCols<AB::Var>>>::borrow(main.current_slice());
            let next = *<[AB::Var] as Borrow<LookupMainCols<AB::Var>>>::borrow(main.next_slice());
            let prep = *<[AB::Var] as Borrow<PrepCols<AB::Var>>>::borrow(
                builder.preprocessed().current_slice(),
            );
            (local, next, prep)
        };
        let legacy_local = legacy_view(&local);
        let legacy_next = legacy_view(&next);

        constrain_lookup_ranges(builder, &local, &prep);
        constrain_round_lookup(builder, &local, &next, &prep);
        constrain_initial_state(builder, &legacy_local, &prep);
        constrain_message(builder, &legacy_local, &legacy_next, &prep);
        constrain_digest_lookup(builder, &local, &prep);
        constrain_evaluation_lookup(
            builder,
            &legacy_local,
            &legacy_next,
            self.inner.point_variables,
        );
        constrain_links(builder, &legacy_local, &legacy_next, &prep);
        constrain_lookup_table(builder, &local);
        emit_xor_lookups(builder, &local, &prep);
    }
}

fn u32_nibbles(value: u32) -> [F; XOR_NIBBLES] {
    array::from_fn(|index| F::from_u8(((value >> (4 * index)) & 0xf) as u8))
}

fn legacy_bits_u32(bits: &[F; WORD_BITS]) -> u32 {
    bits.iter().enumerate().fold(0_u32, |value, (index, bit)| {
        let bit = bit.as_canonical_u64();
        assert!(bit <= 1, "legacy XOR bit is not boolean");
        value | ((bit as u32) << index)
    })
}

fn legacy_nibbles_u32(nibbles: &[F; XOR_NIBBLES]) -> u32 {
    nibbles
        .iter()
        .enumerate()
        .fold(0_u32, |value, (index, nibble)| {
            let nibble = nibble.as_canonical_u64();
            assert!(nibble < 16, "legacy range nibble is out of range");
            value | ((nibble as u32) << (4 * index))
        })
}

fn project_lookup_row(
    row_index: usize,
    active_operations: usize,
    legacy_values: &[F],
) -> [F; LOOKUP_MAIN_WIDTH] {
    let legacy: &MainCols<F> = legacy_values.borrow();
    let mut values = [F::ZERO; LOOKUP_MAIN_WIDTH];
    let row: &mut LookupMainCols<F> = values.as_mut_slice().borrow_mut();

    row.state.words = legacy.state.words;
    row.message = legacy.message;
    row.original_nibbles = legacy.original_nibbles;
    row.chaining_value = legacy.chaining_value;
    row.output_words = legacy.output_words;
    row.evaluation_accumulator = legacy.evaluation_accumulator;
    row.stack = legacy.stack;
    let table_key = row_index % XOR_TABLE_ROWS;
    let table_x = table_key >> 4;
    let table_y = table_key & 0xf;
    row.xor_table = [
        F::from_usize(table_x),
        F::from_usize(table_y),
        F::from_usize(table_x ^ table_y),
    ];

    let operation_index = row_index / ROWS_PER_COMPRESSION;
    if operation_index >= active_operations {
        return values;
    }

    let step = row_index % ROWS_PER_COMPRESSION;
    if step < G_STEPS_PER_COMPRESSION {
        let input_b = legacy_bits_u32(&legacy.state.xor_bits[INPUT_B]);
        let input_d = legacy_bits_u32(&legacy.state.xor_bits[INPUT_D]);
        let output_a = legacy_nibbles_u32(&legacy.state.range_nibbles[0]);
        let output_c = legacy_nibbles_u32(&legacy.state.range_nibbles[1]);
        let raw_b = input_b ^ output_c;
        let raw_d = input_d ^ output_a;

        row.state.xor_nibbles[INPUT_B] = u32_nibbles(input_b);
        row.state.xor_nibbles[INPUT_D] = u32_nibbles(input_d);
        row.state.xor_nibbles[RAW_B] = u32_nibbles(raw_b);
        row.state.xor_nibbles[RAW_D] = u32_nibbles(raw_d);
        row.state.range_nibbles = legacy.state.range_nibbles;

        let phase = (step % G_STEPS_PER_ROUND) / 4;
        if phase % 2 == 1 {
            row.state.rotate7_high_bits =
                array::from_fn(|index| F::from_bool(((raw_b >> (4 * index + 3)) & 1) == 1));
        }
    } else {
        let left = legacy_bits_u32(&legacy.state.xor_bits[INPUT_B]);
        let right = legacy_bits_u32(&legacy.state.xor_bits[INPUT_D]);
        let output = legacy_bits_u32(&legacy.state.xor_bits[RAW_B]);
        row.state.xor_nibbles[INPUT_B] = u32_nibbles(left);
        row.state.range_nibbles[1] = u32_nibbles(right);
        row.state.xor_nibbles[RAW_B] = u32_nibbles(output);
    }

    values
}

fn lookup_nibble(value: F) -> usize {
    let value = value.as_canonical_u64();
    assert!(value < 16, "XOR lookup nibble is out of range");
    value as usize
}

fn increment_lookup(histogram: &mut [u64; XOR_TABLE_ROWS], x: F, y: F, z: F) {
    let x = lookup_nibble(x);
    let y = lookup_nibble(y);
    let z = lookup_nibble(z);
    assert_eq!(z, x ^ y, "projected XOR tuple is inconsistent");
    let key = (x << 4) | y;
    histogram[key] = histogram[key]
        .checked_add(1)
        .expect("XOR multiplicity overflow");
}

fn accumulate_lookup_multiplicities(
    row_index: usize,
    active_operations: usize,
    row: &LookupMainCols<F>,
    multiplicities: &mut [[u64; XOR_TABLE_ROWS]; XOR_LOOKUPS],
) {
    if row_index / ROWS_PER_COMPRESSION >= active_operations {
        return;
    }
    let step = row_index % ROWS_PER_COMPRESSION;
    for nibble in 0..XOR_NIBBLES {
        increment_lookup(
            &mut multiplicities[0],
            row.state.xor_nibbles[INPUT_B][nibble],
            row.state.range_nibbles[1][nibble],
            row.state.xor_nibbles[RAW_B][nibble],
        );
        if step < G_STEPS_PER_COMPRESSION {
            increment_lookup(
                &mut multiplicities[1],
                row.state.xor_nibbles[INPUT_D][nibble],
                row.state.range_nibbles[0][nibble],
                row.state.xor_nibbles[RAW_D][nibble],
            );
        }
    }
}

fn xor_lookup_multiplicities(
    air: &NarrowBlake3XorLookupAir,
    statement: &StructuredBlake3Statement,
    witness: &Blake3TreeWitness,
) -> [[u64; XOR_TABLE_ROWS]; XOR_LOOKUPS] {
    let mut multiplicities = [[0_u64; XOR_TABLE_ROWS]; XOR_LOOKUPS];
    for_each_main_trace_row(&air.inner, statement, witness, |row_index, legacy| {
        let projected = project_lookup_row(row_index, witness.operations.len(), legacy);
        let row: &LookupMainCols<F> = projected.as_slice().borrow();
        accumulate_lookup_multiplicities(
            row_index,
            witness.operations.len(),
            row,
            &mut multiplicities,
        );
        Ok::<_, std::convert::Infallible>(())
    })
    .expect("infallible XOR multiplicity pass");
    multiplicities
}

fn for_each_xor_lookup_trace_row<E>(
    air: &NarrowBlake3XorLookupAir,
    statement: &StructuredBlake3Statement,
    witness: &Blake3TreeWitness,
    mut emit: impl FnMut(usize, &[F]) -> Result<(), E>,
) -> Result<(), E> {
    let multiplicities = xor_lookup_multiplicities(air, statement, witness);
    for_each_main_trace_row(&air.inner, statement, witness, |row_index, legacy| {
        let mut projected = project_lookup_row(row_index, witness.operations.len(), legacy);
        if row_index < XOR_TABLE_ROWS {
            let row: &mut LookupMainCols<F> = projected.as_mut_slice().borrow_mut();
            for (lookup, histogram) in multiplicities.iter().enumerate() {
                row.xor_table_multiplicity[lookup] = F::from_u64(histogram[row_index]);
            }
        }
        emit(row_index, &projected)
    })
}

fn generate_xor_lookup_trace(
    air: &NarrowBlake3XorLookupAir,
    statement: &StructuredBlake3Statement,
    witness: &Blake3TreeWitness,
) -> RowMajorMatrix<F> {
    let mut values = Vec::with_capacity(air.inner.trace_rows * LOOKUP_MAIN_WIDTH);
    for_each_xor_lookup_trace_row(air, statement, witness, |row_index, row| {
        debug_assert_eq!(values.len(), row_index * LOOKUP_MAIN_WIDTH);
        values.extend_from_slice(row);
        Ok::<_, std::convert::Infallible>(())
    })
    .expect("infallible in-memory XOR lookup trace sink");
    RowMajorMatrix::new(values, LOOKUP_MAIN_WIDTH)
}

fn fixture_statement(activation: &[u8]) -> StructuredBlake3Statement {
    let challenge = [0x42; 32];
    let point = (0..activation.len().ilog2())
        .map(|index| crate::ExtensionElement {
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
        .map(crate::ExtensionElement::to_field)
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture point is canonical");
    let table = activation
        .iter()
        .map(|value| {
            crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*value) - 125)
        })
        .collect::<Vec<_>>();
    StructuredBlake3Statement {
        challenge_digest: challenge,
        final_activation_len: activation.len(),
        final_activation_digest: crate::forgematrix_v2::output_digest(challenge, activation),
        final_activation_point: point,
        final_activation_evaluation: crate::ExtensionElement::from_field(
            crate::structured_sumcheck::evaluate_mle(&table, &native_point),
        ),
    }
}

struct PreprocessedTraceForbidGuard;

impl Drop for PreprocessedTraceForbidGuard {
    fn drop(&mut self) {
        PREPROCESSED_TRACE_FORBIDDEN.with(|forbidden| forbidden.set(false));
    }
}

fn with_preprocessed_trace_forbidden<T>(operation: impl FnOnce() -> T) -> T {
    PREPROCESSED_TRACE_FORBIDDEN.with(|forbidden| assert!(!forbidden.replace(true)));
    let _guard = PreprocessedTraceForbidGuard;
    operation()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LookupBatchError {
    DegreeBits,
    PinnedKey,
    LookupShape,
    Statement,
    Verification,
    BackendPanic,
}

fn pinned_lookup_common_data(
    air: &NarrowBlake3XorLookupAir,
    degree_bits: &[usize],
) -> Result<CommonData<Config>, LookupBatchError> {
    let expected_degree_bits = air.inner.trace_rows.ilog2() as usize;
    if degree_bits != [expected_degree_bits] {
        return Err(LookupBatchError::DegreeBits);
    }

    let pinned =
        pinned_preprocessed_verifier_key(&air.inner).map_err(|_| LookupBatchError::PinnedKey)?;
    if pinned.width != air.preprocessed_width()
        || pinned.degree_bits != expected_degree_bits
        || pinned.width != PINNED_PREPROCESSED_WIDTH
    {
        return Err(LookupBatchError::PinnedKey);
    }

    let lookups = Lookups::<F>::from_air::<EF, _>(air);
    if lookups.len() != XOR_LOOKUPS || lookups.total_count_weight() != 16 {
        return Err(LookupBatchError::LookupShape);
    }

    Ok(CommonData::new(
        Some(GlobalPreprocessed {
            commitment: pinned.commitment,
            instances: vec![Some(PreprocessedInstanceMeta {
                matrix_index: 0,
                width: pinned.width,
                degree_bits: pinned.degree_bits,
            })],
            matrix_to_instance: vec![0],
        }),
        vec![lookups],
    ))
}

fn lookup_batch_inputs(
    statement: &StructuredBlake3Statement,
    activation: &[u8],
) -> (NarrowBlake3XorLookupAir, RowMajorMatrix<F>, Vec<F>) {
    let air = NarrowBlake3XorLookupAir::new(statement).expect("fixture shape is supported");
    validate_opening(statement, activation).expect("fixture activation matches its statement");
    let witness = build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, activation)
        .expect("fixture tree witness builds");
    assert_eq!(witness.digest, statement.final_activation_digest);
    let trace = generate_xor_lookup_trace(&air, statement, &witness);
    let public = public_values(statement).expect("fixture public values are canonical");
    (air, trace, public)
}

fn prove_lookup_batch(
    statement: &StructuredBlake3Statement,
    activation: &[u8],
) -> BatchProof<Config> {
    let (air, trace, public) = lookup_batch_inputs(statement, activation);
    let config = build_config();
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: public,
    }];
    let prover_data = ProverData::from_instances(&config, &instances);

    let generated = prover_data
        .common
        .preprocessed
        .as_ref()
        .expect("lookup AIR has preprocessed columns");
    let generated_meta = generated.instances[0]
        .as_ref()
        .expect("lookup AIR has preprocessed metadata");
    let pinned = pinned_preprocessed_verifier_key(&air.inner).expect("fixture key is pinned");
    assert_eq!(generated.commitment, pinned.commitment);
    assert_eq!(generated.instances.len(), 1);
    assert_eq!(generated.matrix_to_instance, vec![0]);
    assert_eq!(generated_meta.matrix_index, 0);
    assert_eq!(generated_meta.width, pinned.width);
    assert_eq!(generated_meta.degree_bits, pinned.degree_bits);
    assert!(prover_data.prover_only.preprocessed_prover_data.is_some());
    assert_eq!(prover_data.common.lookups[0].len(), XOR_LOOKUPS);
    assert_eq!(prover_data.common.lookups[0].total_count_weight(), 16);

    prove_batch(&config, &instances, &prover_data)
}

fn verify_lookup_batch(
    statement: &StructuredBlake3Statement,
    proof: &BatchProof<Config>,
) -> Result<(), LookupBatchError> {
    let air = NarrowBlake3XorLookupAir::new(statement).map_err(|_| LookupBatchError::Statement)?;
    let public = public_values(statement).map_err(|_| LookupBatchError::Statement)?;

    with_preprocessed_trace_forbidden(|| {
        let common = pinned_lookup_common_data(&air, &proof.degree_bits)?;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_batch(
                &build_config(),
                std::slice::from_ref(&air),
                proof,
                &[public],
                &common,
            )
        }))
        .map_err(|_| LookupBatchError::BackendPanic)?
        .map_err(|_| LookupBatchError::Verification)
    })
}

#[test]
fn real_xor_lookup_air_round_trips_through_pinned_batch_verifier() {
    let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    let statement = fixture_statement(&activation);
    let mut proof = prove_lookup_batch(&statement, &activation);

    assert_eq!(LOOKUP_MAIN_WIDTH, 208);
    assert_eq!(PREP_WIDTH, 84);
    assert_eq!(proof.degree_bits, vec![8]);
    assert_eq!(proof.lookup_terminals.len(), 1);
    assert!(proof.lookup_terminals[0].is_some());
    assert!(proof.commitments.permutation.is_some());
    assert!(proof.commitments.random.is_none());

    let opened = &proof.opened_values.instances[0];
    assert_eq!(opened.permutation_local.len(), 9);
    assert_eq!(opened.permutation_next.len(), 9);
    assert_eq!(
        opened.base_opened_values.trace_local.len(),
        LOOKUP_MAIN_WIDTH
    );
    assert_eq!(
        opened.base_opened_values.trace_next.as_ref().map(Vec::len),
        Some(LOOKUP_MAIN_WIDTH)
    );
    assert_eq!(
        opened
            .base_opened_values
            .preprocessed_local
            .as_ref()
            .map(Vec::len),
        Some(PREP_WIDTH)
    );
    assert!(opened.base_opened_values.preprocessed_next.is_none());
    assert_eq!(opened.base_opened_values.quotient_chunks.len(), 16);

    verify_lookup_batch(&statement, &proof).expect("honest XOR lookup proof must verify");

    let mut wrong_digest = statement.clone();
    wrong_digest.final_activation_digest[0] ^= 1;
    assert_eq!(
        verify_lookup_batch(&wrong_digest, &proof),
        Err(LookupBatchError::Verification)
    );

    let mut wrong_challenge = statement.clone();
    wrong_challenge.challenge_digest[0] ^= 1;
    assert_eq!(
        verify_lookup_batch(&wrong_challenge, &proof),
        Err(LookupBatchError::Verification)
    );

    let mut wrong_point = statement.clone();
    wrong_point.final_activation_point[0].limbs[0] += 1;
    assert_eq!(
        verify_lookup_batch(&wrong_point, &proof),
        Err(LookupBatchError::Verification)
    );

    let mut wrong_evaluation = statement.clone();
    wrong_evaluation.final_activation_evaluation.limbs[0] += 1;
    assert_eq!(
        verify_lookup_batch(&wrong_evaluation, &proof),
        Err(LookupBatchError::Verification)
    );

    let smaller_activation = (0..32).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    let smaller_statement = fixture_statement(&smaller_activation);
    let original_air = NarrowBlake3XorLookupAir::new(&statement).unwrap();
    let smaller_air = NarrowBlake3XorLookupAir::new(&smaller_statement).unwrap();
    assert_eq!(original_air.inner.trace_rows, smaller_air.inner.trace_rows);
    assert_ne!(
        pinned_preprocessed_verifier_key(&original_air.inner)
            .unwrap()
            .commitment,
        pinned_preprocessed_verifier_key(&smaller_air.inner)
            .unwrap()
            .commitment
    );
    assert_eq!(
        verify_lookup_batch(&smaller_statement, &proof),
        Err(LookupBatchError::Verification)
    );

    let missing_instance = proof.opened_values.instances.pop().unwrap();
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.opened_values.instances.push(missing_instance);

    let missing_terminal = proof.lookup_terminals.pop().unwrap();
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.lookup_terminals.push(missing_terminal);

    let terminal = proof.lookup_terminals[0].as_mut().unwrap();
    let original_terminal = terminal.0;
    terminal.0 += EF::ONE;
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.lookup_terminals[0].as_mut().unwrap().0 = original_terminal;

    let missing_preprocessed = proof.opened_values.instances[0]
        .base_opened_values
        .preprocessed_local
        .as_mut()
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.opened_values.instances[0]
        .base_opened_values
        .preprocessed_local
        .as_mut()
        .unwrap()
        .push(missing_preprocessed);

    let missing_trace = proof.opened_values.instances[0]
        .base_opened_values
        .trace_local
        .pop()
        .unwrap();
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local
        .push(missing_trace);

    let missing_permutation_local = proof.opened_values.instances[0]
        .permutation_local
        .pop()
        .unwrap();
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.opened_values.instances[0]
        .permutation_local
        .push(missing_permutation_local);

    let missing_permutation_next = proof.opened_values.instances[0]
        .permutation_next
        .pop()
        .unwrap();
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.opened_values.instances[0]
        .permutation_next
        .push(missing_permutation_next);

    let original_permutation_opening = proof.opened_values.instances[0].permutation_local[0];
    proof.opened_values.instances[0].permutation_local[0] += F::ONE;
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.opened_values.instances[0].permutation_local[0] = original_permutation_opening;

    let missing_quotient = proof.opened_values.instances[0]
        .base_opened_values
        .quotient_chunks
        .pop()
        .unwrap();
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.opened_values.instances[0]
        .base_opened_values
        .quotient_chunks
        .push(missing_quotient);

    let permutation_commitment = proof.commitments.permutation.take().unwrap();
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::Verification)
    );
    proof.commitments.permutation = Some(permutation_commitment);

    proof.degree_bits[0] = usize::BITS as usize;
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::DegreeBits)
    );
    proof.degree_bits = vec![8, 8];
    assert_eq!(
        verify_lookup_batch(&statement, &proof),
        Err(LookupBatchError::DegreeBits)
    );
}

#[test]
fn xor_lookup_table_period_repeats_in_a_larger_real_proof() {
    let activation = (0..128)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let statement = fixture_statement(&activation);
    let air = NarrowBlake3XorLookupAir::new(&statement).unwrap();
    assert_eq!(air.inner.trace_rows, 512);
    let proof = prove_lookup_batch(&statement, &activation);
    assert_eq!(proof.degree_bits, vec![9]);
    verify_lookup_batch(&statement, &proof)
        .expect("the 256-row XOR table period must repeat on a larger trace");
}

fn packed_lookup_nibbles(nibbles: &[F; XOR_NIBBLES]) -> u32 {
    legacy_nibbles_u32(nibbles)
}

fn lookup_row(trace: &RowMajorMatrix<F>, row_index: usize) -> &LookupMainCols<F> {
    let start = row_index * LOOKUP_MAIN_WIDTH;
    trace.values[start..start + LOOKUP_MAIN_WIDTH].borrow()
}

fn lookup_row_mut(trace: &mut RowMajorMatrix<F>, row_index: usize) -> &mut LookupMainCols<F> {
    let start = row_index * LOOKUP_MAIN_WIDTH;
    trace.values[start..start + LOOKUP_MAIN_WIDTH].borrow_mut()
}

#[test]
fn projected_trace_matches_native_blake3_and_lookup_histograms() {
    for activation_len in [64, 2_048] {
        let activation = (0..activation_len)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let statement = fixture_statement(&activation);
        let air = NarrowBlake3XorLookupAir::new(&statement).unwrap();
        let witness =
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, &activation).unwrap();
        let trace = generate_xor_lookup_trace(&air, &statement, &witness);
        assert_eq!(trace.width(), LOOKUP_MAIN_WIDTH);
        assert_eq!(trace.height(), air.inner.trace_rows);

        for row_index in 0..trace.height() {
            let row = lookup_row(&trace, row_index);
            let table_key = row_index % XOR_TABLE_ROWS;
            assert_eq!(
                row.xor_table.map(|value| value.as_canonical_u64()),
                [
                    (table_key >> 4) as u64,
                    (table_key & 0xf) as u64,
                    ((table_key >> 4) ^ (table_key & 0xf)) as u64,
                ]
            );

            let operation_index = row_index / ROWS_PER_COMPRESSION;
            let step = row_index % ROWS_PER_COMPRESSION;
            if operation_index >= witness.operations.len() {
                assert!(
                    row.state
                        .xor_nibbles
                        .iter()
                        .flatten()
                        .all(|value| *value == F::ZERO)
                );
                assert!(
                    row.state
                        .range_nibbles
                        .iter()
                        .flatten()
                        .all(|value| *value == F::ZERO)
                );
                assert!(
                    row.state
                        .rotate7_high_bits
                        .iter()
                        .all(|value| *value == F::ZERO)
                );
                continue;
            }

            if step < G_STEPS_PER_COMPRESSION {
                let phase = (step % G_STEPS_PER_ROUND) / 4;
                let index = step % 4;
                let diagonal = phase >= 2;
                let second = phase % 2 == 1;
                let a = index;
                let b = 4 + if diagonal { (index + 1) % 4 } else { index };
                let c = 8 + if diagonal { (index + 2) % 4 } else { index };
                let d = 12 + if diagonal { (index + 3) % 4 } else { index };
                let next = lookup_row(&trace, row_index + 1);
                let input_b = packed_lookup_nibbles(&row.state.xor_nibbles[INPUT_B]);
                let input_d = packed_lookup_nibbles(&row.state.xor_nibbles[INPUT_D]);
                let output_a = packed_lookup_nibbles(&row.state.range_nibbles[0]);
                let output_c = packed_lookup_nibbles(&row.state.range_nibbles[1]);
                let raw_b = packed_lookup_nibbles(&row.state.xor_nibbles[RAW_B]);
                let raw_d = packed_lookup_nibbles(&row.state.xor_nibbles[RAW_D]);

                assert_eq!(input_b, row.state.words[b].as_canonical_u64() as u32);
                assert_eq!(input_d, row.state.words[d].as_canonical_u64() as u32);
                assert_eq!(output_a, next.state.words[a].as_canonical_u64() as u32);
                assert_eq!(output_c, next.state.words[c].as_canonical_u64() as u32);
                assert_eq!(raw_b, input_b ^ output_c);
                assert_eq!(raw_d, input_d ^ output_a);
                assert_eq!(
                    next.state.words[b].as_canonical_u64() as u32,
                    raw_b.rotate_right(if second { 7 } else { 12 })
                );
                assert_eq!(
                    next.state.words[d].as_canonical_u64() as u32,
                    raw_d.rotate_right(if second { 8 } else { 16 })
                );
                for nibble in 0..XOR_NIBBLES {
                    let expected = u64::from(second && ((raw_b >> (4 * nibble + 3)) & 1) == 1);
                    assert_eq!(
                        row.state.rotate7_high_bits[nibble].as_canonical_u64(),
                        expected
                    );
                }
            } else {
                let word = step - G_STEPS_PER_COMPRESSION;
                let left = packed_lookup_nibbles(&row.state.xor_nibbles[INPUT_B]);
                let right = packed_lookup_nibbles(&row.state.range_nibbles[1]);
                let output = packed_lookup_nibbles(&row.state.xor_nibbles[RAW_B]);
                assert_eq!(left, row.state.words[word].as_canonical_u64() as u32);
                assert_eq!(
                    right,
                    row.state.words[word + CV_WORDS].as_canonical_u64() as u32
                );
                assert_eq!(output, row.output_words[word].as_canonical_u64() as u32);
                assert_eq!(output, left ^ right);
                assert!(
                    row.state.xor_nibbles[INPUT_D]
                        .iter()
                        .all(|value| *value == F::ZERO)
                );
                assert!(
                    row.state.xor_nibbles[RAW_D]
                        .iter()
                        .all(|value| *value == F::ZERO)
                );
                assert!(
                    row.state.range_nibbles[0]
                        .iter()
                        .all(|value| *value == F::ZERO)
                );
                assert!(
                    row.state
                        .rotate7_high_bits
                        .iter()
                        .all(|value| *value == F::ZERO)
                );
            }
        }

        let multiplicities = xor_lookup_multiplicities(&air, &statement, &witness);
        assert_eq!(
            multiplicities[0].iter().sum::<u64>(),
            960 * witness.operations.len() as u64
        );
        assert_eq!(
            multiplicities[1].iter().sum::<u64>(),
            896 * witness.operations.len() as u64
        );
        for row_index in 0..trace.height() {
            let row = lookup_row(&trace, row_index);
            for (lookup, histogram) in multiplicities.iter().enumerate() {
                let expected = histogram.get(row_index).copied().unwrap_or(0);
                assert_eq!(
                    row.xor_table_multiplicity[lookup].as_canonical_u64(),
                    expected
                );
            }
        }
    }
}

#[test]
fn lookup_trace_stream_matches_collected_trace_and_stops_on_sink_error() {
    let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    let statement = fixture_statement(&activation);
    let air = NarrowBlake3XorLookupAir::new(&statement).unwrap();
    let witness =
        build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, &activation).unwrap();
    let collected = generate_xor_lookup_trace(&air, &statement, &witness);
    let mut streamed = Vec::new();
    for_each_xor_lookup_trace_row(&air, &statement, &witness, |row_index, row| {
        assert_eq!(streamed.len(), row_index * LOOKUP_MAIN_WIDTH);
        streamed.extend_from_slice(row);
        Ok::<_, std::convert::Infallible>(())
    })
    .unwrap();
    assert_eq!(streamed, collected.values);

    let mut emitted = 0;
    let stopped = for_each_xor_lookup_trace_row(&air, &statement, &witness, |_row_index, _row| {
        emitted += 1;
        if emitted == 17 { Err("stop") } else { Ok(()) }
    });
    assert_eq!(stopped, Err("stop"));
    assert_eq!(emitted, 17);
}

#[test]
fn canonical_periodic_xor_table_covers_every_nibble_pair() {
    let activation = vec![0_u8; 64];
    let statement = fixture_statement(&activation);
    let air = NarrowBlake3XorLookupAir::new(&statement).unwrap();
    let columns = air.periodic_columns();
    assert_eq!(columns.len(), ACTIVATION_HIGH_WEIGHT_WIDTH + 3);
    assert!(
        columns[..ACTIVATION_HIGH_WEIGHT_WIDTH]
            .iter()
            .all(|column| column.len() == air.inner.trace_rows)
    );
    assert!(
        columns[ACTIVATION_HIGH_WEIGHT_WIDTH..]
            .iter()
            .all(|column| column.len() == XOR_TABLE_ROWS)
    );
    for (key, ((table_x, table_y), table_z)) in columns[ACTIVATION_HIGH_WEIGHT_WIDTH]
        .iter()
        .zip(&columns[ACTIVATION_HIGH_WEIGHT_WIDTH + 1])
        .zip(&columns[ACTIVATION_HIGH_WEIGHT_WIDTH + 2])
        .enumerate()
    {
        let expected = [key >> 4, key & 0xf, (key >> 4) ^ (key & 0xf)];
        let periodic = air.periodic_values(key);
        let table_values = [*table_x, *table_y, *table_z];
        for index in 0..3 {
            assert_eq!(
                periodic[ACTIVATION_HIGH_WEIGHT_WIDTH + index],
                F::from_usize(expected[index])
            );
            assert_eq!(table_values[index], F::from_usize(expected[index]));
        }
    }
}

#[test]
fn rotate_right_seven_helper_is_exact_for_every_adjacent_nibble_pair() {
    for output_index in 0..XOR_NIBBLES {
        let high_index = (output_index + 1) % XOR_NIBBLES;
        let low_index = (output_index + 2) % XOR_NIBBLES;
        for high_source in 0_u32..16 {
            for low_source in 0_u32..16 {
                let raw = (high_source << (4 * high_index)) | (low_source << (4 * low_index));
                let expected = (raw.rotate_right(7) >> (4 * output_index)) & 0xf;
                let actual = (high_source >> 3) + 2 * (low_source & 7);
                assert_eq!(
                    actual, expected,
                    "output={output_index}, high_source={high_source}, low_source={low_source}"
                );
            }
        }
    }
}

#[test]
fn xor_lookup_batch_layout_and_security_budget_are_pinned() {
    let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    let statement = fixture_statement(&activation);
    let air = NarrowBlake3XorLookupAir::new(&statement).unwrap();
    let lookups = Lookups::<F>::from_air::<EF, _>(&air);
    let gadget = LogUpGadget::new();
    let layout = AirLayout::from_air::<F>(&air);
    let constraints = get_constraint_layout::<F, EF, _, _>(&air, layout, &lookups, &gadget);
    let max_degree = get_max_constraint_degree::<F, EF, _, _>(&air, layout, &lookups, &gadget);
    let log_quotient_chunks =
        get_log_num_quotient_chunks::<F, EF, _, _>(&air, layout, &lookups, 0, &gadget);

    assert_eq!(air.inner.trace_rows, 256);
    assert_eq!(air.width(), 208);
    assert_eq!(air.preprocessed_width(), 84);
    assert_eq!(air.num_periodic_columns(), 6);
    assert_eq!(air.num_public_values(), 93);
    assert_eq!(lookups.len(), 2);
    assert_eq!(lookups.total_count_weight(), 16);
    assert_eq!(constraints.base_indices.len(), 951);
    assert_eq!(constraints.ext_indices.len(), 5);
    assert_eq!(constraints.total_constraints(), 956);
    assert_eq!(max_degree, 16);
    assert_eq!(log_quotient_chunks, 4);
    assert_eq!(1 << log_quotient_chunks, 16);

    let perm = default_poseidon2();
    let val = ValMmcs::new(FieldHash::new(perm.clone()), Compress::new(perm), 0);
    let fri = fri_parameters_with(FRI_LOG_BLOWUP, FRI_QUERIES, ChallengeMmcs::new(val));
    let security_params = StarkSecurityParams::new(
        &fri,
        192,
        128,
        constraints.total_constraints(),
        max_degree,
        2,
    );
    let security = ProvenSecurity::compute(&security_params, air.inner.trace_rows);
    assert!(security.security_bits() >= 128, "{security:?}");
    let minimum_queries = (1..=FRI_QUERIES)
        .find(|queries| {
            let mut candidate = security_params.clone();
            candidate.fri_num_queries = *queries;
            ProvenSecurity::compute(&candidate, air.inner.trace_rows).security_bits() >= 128
        })
        .expect("lookup batch envelope must reach 128 proven bits");
    assert_eq!(minimum_queries, 32);
    assert_eq!(FRI_QUERIES, minimum_queries + 1);
}

#[test]
fn lookup_challenge_error_and_multiplicity_bound_cover_every_supported_shape() {
    let choose_two = |n: u128| n * (n - 1) / 2;
    let mut maximum_roots = 0_u128;
    for key in PINNED_PREPROCESSED_KEYS {
        let operations = operation_count(key.activation_len).unwrap() as u128;
        let trace_rows = key.trace_rows as u128;
        let b_or_final_terms = 960 * operations + XOR_TABLE_ROWS as u128;
        let d_terms = 896 * operations + XOR_TABLE_ROWS as u128;
        let roots = 2 * choose_two(b_or_final_terms)
            + 2 * choose_two(d_terms)
            + 3 * b_or_final_terms * d_terms
            + b_or_final_terms
            + d_terms
            - 1
            + 18 * trace_rows;
        maximum_roots = maximum_roots.max(roots);
        assert!(16_u128 * trace_rows < u128::from(F::ORDER_U64));
    }
    assert_eq!(maximum_roots, 326_232_911_310_847);

    let field_order = U256::from(F::ORDER_U64);
    let extension_field_size = field_order * field_order * field_order;
    let numerator = U256::from(maximum_roots);
    assert!(numerator << 143usize <= extension_field_size);
    assert!(numerator << 144usize > extension_field_size);

    // The lookup term is well below 2^-143. Combined naively with a component
    // capped at exactly 2^-128 collision security, the result is below 2^-127
    // but strictly above 2^-128. This pins the honest "128-bit class" boundary
    // without misrepresenting it as an audit-grade >=128-bit aggregate proof.
    assert!(numerator << 128usize <= extension_field_size);
}

fn pinned_shape_statement(activation_len: usize) -> StructuredBlake3Statement {
    let challenge_digest = [0x42; 32];
    let activation = vec![125; activation_len];
    StructuredBlake3Statement {
        challenge_digest,
        final_activation_len: activation_len,
        final_activation_digest: crate::forgematrix_v2::output_digest(
            challenge_digest,
            &activation,
        ),
        final_activation_point: vec![
            crate::ExtensionElement { limbs: [0; 3] };
            activation_len.ilog2() as usize
        ],
        final_activation_evaluation: crate::ExtensionElement { limbs: [0; 3] },
    }
}

#[test]
fn every_supported_shape_uses_pinned_preprocessing_without_materialization() {
    assert_eq!(PINNED_PREPROCESSED_KEYS.len(), 15);
    for key in PINNED_PREPROCESSED_KEYS {
        let statement = pinned_shape_statement(key.activation_len);
        let air = NarrowBlake3XorLookupAir::new(&statement).unwrap();
        let degree_bits = air.inner.trace_rows.ilog2() as usize;
        assert_eq!(air.inner.trace_rows, key.trace_rows);

        let common =
            with_preprocessed_trace_forbidden(|| pinned_lookup_common_data(&air, &[degree_bits]))
                .unwrap();
        let global = common.preprocessed.unwrap();
        let meta = global.instances[0].as_ref().unwrap();
        let pinned = pinned_preprocessed_verifier_key(&air.inner).unwrap();
        assert_eq!(global.commitment, pinned.commitment);
        assert_eq!(global.instances.len(), 1);
        assert_eq!(global.matrix_to_instance, vec![0]);
        assert_eq!(meta.matrix_index, 0);
        assert_eq!(meta.width, PINNED_PREPROCESSED_WIDTH);
        assert_eq!(meta.degree_bits, degree_bits);
        assert_eq!(common.lookups.len(), 1);
        assert_eq!(common.lookups[0].len(), XOR_LOOKUPS);
        assert_eq!(common.lookups[0].total_count_weight(), 16);

        for row_index in [0, 255, 256, air.inner.trace_rows - 1] {
            let periodic = air.periodic_values(row_index);
            let table_key = row_index % XOR_TABLE_ROWS;
            assert_eq!(
                periodic[ACTIVATION_HIGH_WEIGHT_WIDTH..],
                [
                    F::from_usize(table_key >> 4),
                    F::from_usize(table_key & 0xf),
                    F::from_usize((table_key >> 4) ^ (table_key & 0xf)),
                ]
            );
        }

        assert!(matches!(
            pinned_lookup_common_data(&air, &[degree_bits + 1]),
            Err(LookupBatchError::DegreeBits)
        ));
    }
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

fn invalid_lookup_trace_is_rejected(
    air: &NarrowBlake3XorLookupAir,
    trace: RowMajorMatrix<F>,
    public: &[F],
) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let config = build_config();
        let instances = [StarkInstance {
            air,
            trace: &trace,
            public_values: public.to_vec(),
        }];
        let prover_data = ProverData::from_instances(&config, &instances);
        let proof = prove_batch(&config, &instances, &prover_data);
        let common = pinned_lookup_common_data(air, &proof.degree_bits)
            .expect("invalid fixture still has the trusted proof shape");
        verify_batch(
            &config,
            std::slice::from_ref(air),
            &proof,
            &[public.to_vec()],
            &common,
        )
        .is_err()
    })) {
        Ok(rejected) => rejected,
        Err(payload) => {
            let message = panic_message(payload);
            cfg!(debug_assertions)
                && (message.contains("Lookup mismatch")
                    || message.contains("constraints not satisfied on row"))
        }
    }
}

#[test]
fn corrupted_xor_helpers_tables_and_multiplicities_are_rejected() {
    let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    let statement = fixture_statement(&activation);
    let (air, trace, public) = lookup_batch_inputs(&statement, &activation);

    let mut bad_xor = trace.clone();
    lookup_row_mut(&mut bad_xor, 0).state.xor_nibbles[RAW_B][0] += F::ONE;
    assert!(invalid_lookup_trace_is_rejected(&air, bad_xor, &public));

    let mut bad_table = trace.clone();
    lookup_row_mut(&mut bad_table, 0).xor_table[2] += F::ONE;
    assert!(invalid_lookup_trace_is_rejected(&air, bad_table, &public));

    let mut bad_multiplicity = trace.clone();
    let populated_key = (0..XOR_TABLE_ROWS)
        .find(|row| lookup_row(&bad_multiplicity, *row).xor_table_multiplicity[0] != F::ZERO)
        .unwrap();
    lookup_row_mut(&mut bad_multiplicity, populated_key).xor_table_multiplicity[0] += F::ONE;
    assert!(invalid_lookup_trace_is_rejected(
        &air,
        bad_multiplicity,
        &public
    ));

    let mut cross_bus_shift = trace.clone();
    let populated_d_key = (0..XOR_TABLE_ROWS)
        .find(|row| lookup_row(&cross_bus_shift, *row).xor_table_multiplicity[1] != F::ZERO)
        .unwrap();
    lookup_row_mut(&mut cross_bus_shift, populated_key).xor_table_multiplicity[0] += F::ONE;
    lookup_row_mut(&mut cross_bus_shift, populated_d_key).xor_table_multiplicity[1] -= F::ONE;
    assert!(invalid_lookup_trace_is_rejected(
        &air,
        cross_bus_shift,
        &public
    ));

    let mut non_boolean_helper = trace.clone();
    lookup_row_mut(&mut non_boolean_helper, 4)
        .state
        .rotate7_high_bits[0] = F::TWO;
    assert!(invalid_lookup_trace_is_rejected(
        &air,
        non_boolean_helper,
        &public
    ));

    for row_index in [0, G_STEPS_PER_COMPRESSION, 2 * ROWS_PER_COMPRESSION] {
        let mut helper_outside_r7 = trace.clone();
        lookup_row_mut(&mut helper_outside_r7, row_index)
            .state
            .rotate7_high_bits[0] = F::ONE;
        assert!(invalid_lookup_trace_is_rejected(
            &air,
            helper_outside_r7,
            &public
        ));
    }
}

#[test]
#[ignore = "run with --release; single-sample diagnostic"]
fn legacy_vs_xor_lookup_batch_release_benchmark() {
    use std::io::{Read, Write};
    use std::time::Instant;

    #[derive(Clone, Copy)]
    struct Result {
        width: usize,
        main_trace_bytes: usize,
        bincode_bytes: usize,
        zlib_bytes: usize,
        trace_ms: f64,
        setup_ms: f64,
        prove_ms: f64,
        bincode_encode_ms: f64,
        zlib_compress_ms: f64,
        zlib_decompress_ms: f64,
        bincode_decode_ms: f64,
        verify_ms: f64,
    }

    fn milliseconds(started: Instant) -> f64 {
        started.elapsed().as_secs_f64() * 1_000.0
    }

    let activation = (0..1_024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let statement = fixture_statement(&activation);
    let witness = build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, &activation)
        .expect("benchmark tree witness builds");
    let public = public_values(&statement).expect("benchmark public values are canonical");
    let config = build_config();
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let legacy_air = NarrowBlake3Air::new(&statement).expect("benchmark shape is supported");
    let lookup_air =
        NarrowBlake3XorLookupAir::new(&statement).expect("benchmark shape is supported");

    assert_eq!(legacy_air.trace_rows, 4_096);
    assert_eq!(lookup_air.inner.trace_rows, legacy_air.trace_rows);
    assert_eq!(legacy_air.width(), 291);
    assert_eq!(lookup_air.width(), 208);
    assert_eq!(legacy_air.preprocessed_width(), 84);
    assert_eq!(lookup_air.preprocessed_width(), 84);
    assert_eq!(legacy_air.num_periodic_columns(), 3);
    assert_eq!(lookup_air.num_periodic_columns(), 6);
    let legacy_pinned = pinned_preprocessed_verifier_key(&legacy_air).unwrap();
    let lookup_pinned = pinned_preprocessed_verifier_key(&lookup_air.inner).unwrap();
    assert_eq!(legacy_pinned.commitment, lookup_pinned.commitment);

    let legacy_trace_started = Instant::now();
    let legacy_trace = generate_main_trace(&legacy_air, &statement, &witness);
    let legacy_trace_ms = milliseconds(legacy_trace_started);
    let legacy_trace_bytes = legacy_trace.values.len() * size_of::<F>();
    let legacy_instances = [StarkInstance {
        air: &legacy_air,
        trace: &legacy_trace,
        public_values: public.clone(),
    }];
    let legacy_setup_started = Instant::now();
    let legacy_prover_data = ProverData::from_instances(&config, &legacy_instances);
    let legacy_setup_ms = milliseconds(legacy_setup_started);
    let legacy_generated = legacy_prover_data.common.preprocessed.as_ref().unwrap();
    assert_eq!(legacy_generated.commitment, legacy_pinned.commitment);
    assert!(legacy_prover_data.common.lookups[0].is_empty());
    let legacy_prove_started = Instant::now();
    let legacy_proof = prove_batch(&config, &legacy_instances, &legacy_prover_data);
    let legacy_prove_ms = milliseconds(legacy_prove_started);
    let legacy_encode_started = Instant::now();
    let legacy_bytes = bincode_options().serialize(&legacy_proof).unwrap();
    let legacy_bincode_encode_ms = milliseconds(legacy_encode_started);
    let legacy_compress_started = Instant::now();
    let mut legacy_encoder =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    legacy_encoder.write_all(&legacy_bytes).unwrap();
    let legacy_zlib = legacy_encoder.finish().unwrap();
    let legacy_zlib_compress_ms = milliseconds(legacy_compress_started);
    let legacy_decompress_started = Instant::now();
    let mut legacy_decoder = flate2::read::ZlibDecoder::new(legacy_zlib.as_slice());
    let mut legacy_decompressed = Vec::new();
    legacy_decoder
        .read_to_end(&mut legacy_decompressed)
        .unwrap();
    let legacy_zlib_decompress_ms = milliseconds(legacy_decompress_started);
    assert_eq!(legacy_decompressed, legacy_bytes);
    let legacy_decode_started = Instant::now();
    let legacy_decoded: BatchProof<Config> =
        bincode_options().deserialize(&legacy_decompressed).unwrap();
    let legacy_bincode_decode_ms = milliseconds(legacy_decode_started);
    let legacy_lookups = Lookups::<F>::from_air::<EF, _>(&legacy_air);
    assert!(legacy_lookups.is_empty());
    let legacy_common = CommonData::new(
        Some(GlobalPreprocessed {
            commitment: legacy_pinned.commitment.clone(),
            instances: vec![Some(PreprocessedInstanceMeta {
                matrix_index: 0,
                width: legacy_pinned.width,
                degree_bits: legacy_pinned.degree_bits,
            })],
            matrix_to_instance: vec![0],
        }),
        vec![legacy_lookups],
    );
    let legacy_public = [public.clone()];
    let legacy_verify_started = Instant::now();
    verify_batch(
        &config,
        std::slice::from_ref(&legacy_air),
        &legacy_decoded,
        &legacy_public,
        &legacy_common,
    )
    .expect("decoded legacy proof verifies");
    let legacy_verify_ms = milliseconds(legacy_verify_started);
    let legacy = Result {
        width: legacy_air.width(),
        main_trace_bytes: legacy_trace_bytes,
        bincode_bytes: legacy_bytes.len(),
        zlib_bytes: legacy_zlib.len(),
        trace_ms: legacy_trace_ms,
        setup_ms: legacy_setup_ms,
        prove_ms: legacy_prove_ms,
        bincode_encode_ms: legacy_bincode_encode_ms,
        zlib_compress_ms: legacy_zlib_compress_ms,
        zlib_decompress_ms: legacy_zlib_decompress_ms,
        bincode_decode_ms: legacy_bincode_decode_ms,
        verify_ms: legacy_verify_ms,
    };
    drop(legacy_prover_data);
    drop(legacy_instances);
    drop(legacy_decoded);
    drop(legacy_proof);
    drop(legacy_zlib);
    drop(legacy_decompressed);
    drop(legacy_bytes);
    drop(legacy_trace);

    let lookup_trace_started = Instant::now();
    let lookup_trace = generate_xor_lookup_trace(&lookup_air, &statement, &witness);
    let lookup_trace_ms = milliseconds(lookup_trace_started);
    let lookup_trace_bytes = lookup_trace.values.len() * size_of::<F>();
    let lookup_instances = [StarkInstance {
        air: &lookup_air,
        trace: &lookup_trace,
        public_values: public.clone(),
    }];
    let lookup_setup_started = Instant::now();
    let lookup_prover_data = ProverData::from_instances(&config, &lookup_instances);
    let lookup_setup_ms = milliseconds(lookup_setup_started);
    let lookup_generated = lookup_prover_data.common.preprocessed.as_ref().unwrap();
    assert_eq!(lookup_generated.commitment, lookup_pinned.commitment);
    assert_eq!(lookup_prover_data.common.lookups[0].len(), XOR_LOOKUPS);
    let lookup_prove_started = Instant::now();
    let lookup_proof = prove_batch(&config, &lookup_instances, &lookup_prover_data);
    let lookup_prove_ms = milliseconds(lookup_prove_started);
    let lookup_encode_started = Instant::now();
    let lookup_bytes = bincode_options().serialize(&lookup_proof).unwrap();
    let lookup_bincode_encode_ms = milliseconds(lookup_encode_started);
    let lookup_compress_started = Instant::now();
    let mut lookup_encoder =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    lookup_encoder.write_all(&lookup_bytes).unwrap();
    let lookup_zlib = lookup_encoder.finish().unwrap();
    let lookup_zlib_compress_ms = milliseconds(lookup_compress_started);
    let lookup_decompress_started = Instant::now();
    let mut lookup_decoder = flate2::read::ZlibDecoder::new(lookup_zlib.as_slice());
    let mut lookup_decompressed = Vec::new();
    lookup_decoder
        .read_to_end(&mut lookup_decompressed)
        .unwrap();
    let lookup_zlib_decompress_ms = milliseconds(lookup_decompress_started);
    assert_eq!(lookup_decompressed, lookup_bytes);
    let lookup_decode_started = Instant::now();
    let lookup_decoded: BatchProof<Config> =
        bincode_options().deserialize(&lookup_decompressed).unwrap();
    let lookup_bincode_decode_ms = milliseconds(lookup_decode_started);
    let lookup_common =
        pinned_lookup_common_data(&lookup_air, &lookup_decoded.degree_bits).unwrap();
    let lookup_public = [public];
    let lookup_verify_started = Instant::now();
    verify_batch(
        &config,
        std::slice::from_ref(&lookup_air),
        &lookup_decoded,
        &lookup_public,
        &lookup_common,
    )
    .expect("decoded lookup proof verifies");
    let lookup_verify_ms = milliseconds(lookup_verify_started);
    let lookup = Result {
        width: lookup_air.width(),
        main_trace_bytes: lookup_trace_bytes,
        bincode_bytes: lookup_bytes.len(),
        zlib_bytes: lookup_zlib.len(),
        trace_ms: lookup_trace_ms,
        setup_ms: lookup_setup_ms,
        prove_ms: lookup_prove_ms,
        bincode_encode_ms: lookup_bincode_encode_ms,
        zlib_compress_ms: lookup_zlib_compress_ms,
        zlib_decompress_ms: lookup_zlib_decompress_ms,
        bincode_decode_ms: lookup_bincode_decode_ms,
        verify_ms: lookup_verify_ms,
    };

    for (variant, periodic_width, lookup_buses, result) in [
        ("legacy", 3, 0, legacy),
        ("xor-lookup", 6, XOR_LOOKUPS, lookup),
    ] {
        eprintln!(
            "kind=batch-prototype backend=cpu profile={profile} sample_count=1 order=legacy-first timing=diagnostic variant={variant} activation_bytes={} rows={} main_width={} prep_width=84 periodic_width={periodic_width} lookup_buses={lookup_buses} main_trace_bytes={} bincode_bytes={} zlib_bytes={} trace_ms={:.3} setup_ms={:.3} prove_ms={:.3} bincode_encode_ms={:.3} zlib_compress_ms={:.3} zlib_decompress_ms={:.3} bincode_decode_ms={:.3} verify_ms={:.3}",
            activation.len(),
            legacy_air.trace_rows,
            result.width,
            result.main_trace_bytes,
            result.bincode_bytes,
            result.zlib_bytes,
            result.trace_ms,
            result.setup_ms,
            result.prove_ms,
            result.bincode_encode_ms,
            result.zlib_compress_ms,
            result.zlib_decompress_ms,
            result.bincode_decode_ms,
            result.verify_ms,
        );
    }
    eprintln!(
        "kind=batch-prototype-delta backend=cpu profile={profile} sample_count=1 order=legacy-first timing=diagnostic width_ratio={:.6} main_trace_ratio={:.6} bincode_ratio={:.6} zlib_ratio={:.6} diagnostic_prove_ratio={:.6} diagnostic_verify_ratio={:.6}",
        lookup.width as f64 / legacy.width as f64,
        lookup.main_trace_bytes as f64 / legacy.main_trace_bytes as f64,
        lookup.bincode_bytes as f64 / legacy.bincode_bytes as f64,
        lookup.zlib_bytes as f64 / legacy.zlib_bytes as f64,
        lookup.prove_ms / legacy.prove_ms,
        lookup.verify_ms / legacy.verify_ms,
    );

    assert_eq!(legacy.width - lookup.width, 83);
    assert_eq!(
        lookup.main_trace_bytes * legacy.width,
        legacy.main_trace_bytes * lookup.width
    );
    assert!(legacy.bincode_bytes > 0 && lookup.bincode_bytes > 0);
    assert!(legacy.zlib_bytes > 0 && lookup.zlib_bytes > 0);
}
