//! Narrow multi-row BLAKE3 tree STARK.
//!
//! Each compression uses 112 single-G half-round rows and eight finalization
//! rows. Only the four words involved in the active G operation are bit
//! decomposed, keeping the committed trace materially narrower than a full
//! 512-bit state decomposition on every row. The
//! deterministic preprocessed schedule fixes chunk counters, flags, tree
//! topology, stack accesses, and activation-byte positions. Exact adjacent
//! transitions and a deterministic 10-entry CV stack authenticate every tree
//! edge without a prover-known permutation challenge. A running sum binds the
//! message bytes to the final-table multilinear opening.

use std::{
    array,
    borrow::{Borrow, BorrowMut},
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
};

use bincode::Options;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::CubicTrinomialExtensionField;
use p3_field::integers::QuotientMap;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    Proof, StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed,
};
use thiserror::Error;

use crate::{
    GOLDILOCKS_MODULUS, StructuredBlake3Statement,
    structured_blake3_tree::{Blake3TreeError, CompressionKind, CompressionOp, build_tree_witness},
};

const OUTPUT_CONTEXT: &str = "CMFD/FORGEMATRIX/OUTPUT/V2";
const MAX_POINT_VARIABLES: usize = 19;
const MAX_STACK_DEPTH: usize = 10;
const G_STEPS_PER_ROUND: usize = 16;
const G_STEPS_PER_COMPRESSION: usize = 7 * G_STEPS_PER_ROUND;
const FINALIZATION_ROWS: usize = 8;
const ROWS_PER_COMPRESSION: usize = G_STEPS_PER_COMPRESSION + FINALIZATION_ROWS;
const BYTES_PER_EVAL_ROW: usize = 8;
const LOW_EVALUATION_VARIABLES: usize = 3;
const WORD_BITS: usize = 32;
const MESSAGE_WORDS: usize = 16;
const CV_WORDS: usize = 8;
const NARROW_PROOF_MAGIC: &[u8; 8] = b"CMFDB3N2";
const NARROW_PROOF_VERSION: u32 = 2;

const FRI_LOG_BLOWUP: usize = 7;
const FRI_QUERIES: usize = 33;
const FRI_QUERY_POW_BITS: usize = 18;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

pub(crate) type F = Goldilocks;
pub(crate) type EF = CubicTrinomialExtensionField<F>;
type Perm = Poseidon2Goldilocks<8>;
type FieldHash = PaddingFreeSponge<Perm, 8, 4, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 8>;
type ValMmcs =
    MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, FieldHash, Compress, 2, 4>;
type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm, 8, 4>;
type Pcs = TwoAdicFriPcs<F, Radix2DitParallel<F>, ValMmcs, ChallengeMmcs>;
pub(crate) type Config = StarkConfig<Pcs, EF, Challenger>;
pub(crate) type NativeProof = Proof<Config>;

#[derive(serde::Serialize, serde::Deserialize)]
struct MerklePathArchive {
    lengths: Vec<u16>,
    indices: Vec<u16>,
    digests: Vec<[F; 4]>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum NarrowBlake3Error {
    #[error("narrow BLAKE3 tree requires a 32-byte-or-larger power-of-two activation")]
    UnsupportedShape,
    #[error("narrow BLAKE3 tree statement contains a noncanonical field element")]
    NonCanonicalField,
    #[error("narrow BLAKE3 tree witness is invalid: {0}")]
    Tree(#[from] Blake3TreeError),
    #[error("narrow BLAKE3 tree activation opening is inconsistent")]
    Opening,
    #[error("narrow BLAKE3 tree proof encoding is malformed")]
    Encoding,
    #[error("narrow BLAKE3 tree verifier rejected the proof")]
    Verification,
    #[error("narrow BLAKE3 tree backend panicked")]
    BackendPanic,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StateCols<T> {
    words: [T; 16],
    xor_bits: [[T; WORD_BITS]; 4],
    range_nibbles: [[T; 8]; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MainCols<T> {
    state: StateCols<T>,
    message: [T; MESSAGE_WORDS],
    original_nibbles: [[T; 2]; BYTES_PER_EVAL_ROW],
    chaining_value: [T; CV_WORDS],
    output_words: [T; CV_WORDS],
    evaluation_accumulator: [T; 3],
    stack: [[T; CV_WORDS]; MAX_STACK_DEPTH],
}

const MAIN_WIDTH: usize = size_of::<MainCols<u8>>();

#[repr(C)]
#[derive(Clone, Copy)]
struct PrepCols<T> {
    round: [T; 7],
    phase: [T; 4],
    g_index: [T; 4],
    final_word: [T; FINALIZATION_ROWS],
    is_first_step: T,
    permute_message: T,
    is_finalization: T,
    is_last_finalization: T,
    byte_group: [T; BYTES_PER_EVAL_ROW],
    activation_active: T,
    activation_high_weight: [T; 3],
    padding_active: [T; BYTES_PER_EVAL_ROW],
    is_active_operation: T,
    is_root: T,
    uses_fixed_cv: T,
    is_first_message_block: T,
    is_last_message_block: T,
    counter_low: T,
    counter_high: T,
    block_len: T,
    flags: T,
    chains_to_next: T,
    stack_read_left: [T; MAX_STACK_DEPTH],
    stack_read_right: [T; MAX_STACK_DEPTH],
    stack_write: [T; MAX_STACK_DEPTH],
}

const PREP_WIDTH: usize = size_of::<PrepCols<u8>>();

impl<T> Borrow<MainCols<T>> for [T] {
    fn borrow(&self) -> &MainCols<T> {
        assert_eq!(self.len(), MAIN_WIDTH);
        unsafe { &*self.as_ptr().cast::<MainCols<T>>() }
    }
}

impl<T> BorrowMut<MainCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MainCols<T> {
        assert_eq!(self.len(), MAIN_WIDTH);
        unsafe { &mut *self.as_mut_ptr().cast::<MainCols<T>>() }
    }
}

impl<T> Borrow<PrepCols<T>> for [T] {
    fn borrow(&self) -> &PrepCols<T> {
        assert_eq!(self.len(), PREP_WIDTH);
        unsafe { &*self.as_ptr().cast::<PrepCols<T>>() }
    }
}

impl<T> BorrowMut<PrepCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut PrepCols<T> {
        assert_eq!(self.len(), PREP_WIDTH);
        unsafe { &mut *self.as_mut_ptr().cast::<PrepCols<T>>() }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NarrowBlake3Air {
    activation_len: usize,
    point_variables: usize,
    point: Vec<crate::structured_sumcheck::ExtensionField>,
    trace_rows: usize,
}

impl NarrowBlake3Air {
    pub(crate) fn new(statement: &StructuredBlake3Statement) -> Result<Self, NarrowBlake3Error> {
        Self::new_with_min_rows(statement, ROWS_PER_COMPRESSION)
    }

    pub(crate) fn new_with_min_rows(
        statement: &StructuredBlake3Statement,
        min_rows: usize,
    ) -> Result<Self, NarrowBlake3Error> {
        if statement.final_activation_len < 32
            || !statement.final_activation_len.is_power_of_two()
            || statement.final_activation_point.len()
                != statement.final_activation_len.ilog2() as usize
            || statement.final_activation_point.len() > MAX_POINT_VARIABLES
        {
            return Err(NarrowBlake3Error::UnsupportedShape);
        }
        validate_field_elements(statement)?;
        let operation_count = operation_count(statement.final_activation_len)?;
        let active_rows = operation_count
            .checked_mul(ROWS_PER_COMPRESSION)
            .ok_or(NarrowBlake3Error::UnsupportedShape)?;
        let mut trace_rows = active_rows
            .next_power_of_two()
            .max(min_rows.next_power_of_two())
            .max(ROWS_PER_COMPRESSION.next_power_of_two());
        if trace_rows == active_rows {
            trace_rows = trace_rows
                .checked_mul(2)
                .ok_or(NarrowBlake3Error::UnsupportedShape)?;
        }
        Ok(Self {
            activation_len: statement.final_activation_len,
            point_variables: statement.final_activation_point.len(),
            point: statement
                .final_activation_point
                .iter()
                .map(|value| value.to_field().expect("validated point"))
                .collect(),
            trace_rows,
        })
    }
}

impl BaseAir<F> for NarrowBlake3Air {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(generate_preprocessed(
            self.activation_len,
            self.trace_rows,
            &self.point,
        ))
    }

    fn preprocessed_width(&self) -> usize {
        PREP_WIDTH
    }

    fn num_public_values(&self) -> usize {
        72 + 3 * self.point_variables + 3
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(16)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for NarrowBlake3Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = *<[AB::Var] as Borrow<MainCols<AB::Var>>>::borrow(main.current_slice());
        let next = *<[AB::Var] as Borrow<MainCols<AB::Var>>>::borrow(main.next_slice());
        let prep = *<[AB::Var] as Borrow<PrepCols<AB::Var>>>::borrow(
            builder.preprocessed().current_slice(),
        );

        constrain_bits(builder, &local);
        constrain_round(builder, &local, &next, &prep);
        constrain_initial_state(builder, &local, &prep);
        constrain_message(builder, &local, &next, &prep);
        constrain_digest(builder, &local, &prep, self.point_variables);
        constrain_evaluation(builder, &local, &next, &prep, self.point_variables);
        constrain_links(builder, &local, &next, &prep);
    }
}

pub(crate) fn prove_narrow_blake3(
    statement: &StructuredBlake3Statement,
    activation: &[u8],
) -> Result<Vec<u8>, NarrowBlake3Error> {
    let air = NarrowBlake3Air::new(statement)?;
    if activation.len() != statement.final_activation_len || activation.iter().any(|v| *v > 250) {
        return Err(NarrowBlake3Error::UnsupportedShape);
    }
    validate_opening(statement, activation)?;
    let witness = build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, activation)?;
    if witness.digest != statement.final_activation_digest {
        return Err(NarrowBlake3Error::Tree(Blake3TreeError::DigestMismatch));
    }
    let trace = generate_main_trace(&air, statement, &witness);
    let public = public_values(statement)?;
    let config = build_config();
    let log_rows = air.trace_rows.ilog2() as usize;
    let (prep, _) = setup_preprocessed(&config, &air, log_rows)
        .expect("narrow BLAKE3 AIR has preprocessed columns");
    let proof = catch_unwind(AssertUnwindSafe(|| {
        prove_with_preprocessed(&config, &air, trace, &public, Some(&prep))
    }))
    .map_err(|_| NarrowBlake3Error::BackendPanic)?;
    encode_native_proof(proof)
}

pub(crate) fn verify_narrow_blake3(
    statement: &StructuredBlake3Statement,
    bytes: &[u8],
) -> Result<(), NarrowBlake3Error> {
    let air = NarrowBlake3Air::new(statement)?;
    let proof = decode_native_proof(bytes)?;
    let config = build_config();
    let log_rows = air.trace_rows.ilog2() as usize;
    let (_, verifier_key) = setup_preprocessed(&config, &air, log_rows)
        .expect("narrow BLAKE3 AIR has preprocessed columns");
    let public = public_values(statement)?;
    catch_unwind(AssertUnwindSafe(|| {
        verify_with_preprocessed(&config, &air, &proof, &public, Some(&verifier_key))
    }))
    .map_err(|_| NarrowBlake3Error::BackendPanic)?
    .map_err(|_| NarrowBlake3Error::Verification)
}

fn constrain_bits<AB: AirBuilder>(builder: &mut AB, local: &MainCols<AB::Var>) {
    for bit in local.state.xor_bits.iter().flatten() {
        builder.assert_bool(*bit);
    }
    for nibble in local
        .state
        .range_nibbles
        .iter()
        .flatten()
        .chain(local.original_nibbles.iter().flatten())
    {
        let value: AB::Expr = (*nibble).into();
        let mut range = AB::Expr::ONE;
        for allowed in 0..16 {
            range *= value.clone() - AB::Expr::from_u8(allowed);
        }
        builder.assert_zero(range);
    }
}

fn constrain_round<AB: AirBuilder>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
) {
    let msg = local.message.map(Into::into);
    for phase in 0..4 {
        for index in 0..4 {
            let active =
                AB::Expr::from(prep.phase[phase]) * prep.g_index[index] * prep.is_active_operation;
            constrain_half_g(builder, local, next, &msg, active.clone(), index, phase);
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

    constrain_finalization(builder, local, next, prep);
}

fn constrain_half_g<AB: AirBuilder>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    message: &[AB::Expr; 16],
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
    let msg_index = if diagonal {
        8 + 2 * index + usize::from(second)
    } else {
        2 * index + usize::from(second)
    };
    let input_b_bits = &local.state.xor_bits[0];
    let input_d_bits = &local.state.xor_bits[1];
    let output_b_bits = &local.state.xor_bits[2];
    let output_d_bits = &local.state.xor_bits[3];
    let output_a_nibbles = &local.state.range_nibbles[0];
    let output_c_nibbles = &local.state.range_nibbles[1];
    builder
        .when(active.clone())
        .assert_eq(pack_bits::<AB>(input_b_bits), local.state.words[b]);
    builder
        .when(active.clone())
        .assert_eq(pack_bits::<AB>(input_d_bits), local.state.words[d]);
    builder
        .when(active.clone())
        .assert_eq(pack_bits::<AB>(output_b_bits), next.state.words[b]);
    builder
        .when(active.clone())
        .assert_eq(pack_bits::<AB>(output_d_bits), next.state.words[d]);
    builder
        .when(active.clone())
        .assert_eq(pack_nibbles::<AB>(output_a_nibbles), next.state.words[a]);
    builder
        .when(active.clone())
        .assert_eq(pack_nibbles::<AB>(output_c_nibbles), next.state.words[c]);
    let expected_a = pack_nibbles::<AB>(output_a_nibbles);
    let expected_c = pack_nibbles::<AB>(output_c_nibbles);
    let a_expr: AB::Expr = local.state.words[a].into();
    let c_expr: AB::Expr = local.state.words[c].into();
    let input_b: AB::Expr = local.state.words[b].into();
    constrain_add3(
        builder,
        active.clone(),
        expected_a.clone(),
        a_expr,
        input_b,
        message[msg_index].clone(),
    );
    constrain_xor_rotate(
        builder,
        active.clone(),
        expected_a,
        input_d_bits,
        output_d_bits,
        if second { 8 } else { 16 },
    );
    let packed_d: AB::Expr = next.state.words[d].into();
    constrain_add2(
        builder,
        active.clone(),
        expected_c.clone(),
        c_expr,
        packed_d,
    );
    constrain_xor_rotate(
        builder,
        active,
        expected_c,
        input_b_bits,
        output_b_bits,
        if second { 7 } else { 12 },
    );
}

fn constrain_finalization<AB: AirBuilder>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
) {
    for word in 0..CV_WORDS {
        let active = AB::Expr::from(prep.final_word[word]) * prep.is_active_operation;
        let left_bits = &local.state.xor_bits[0];
        let right_bits = &local.state.xor_bits[1];
        let output_bits = &local.state.xor_bits[2];
        builder
            .when(active.clone())
            .assert_eq(pack_bits::<AB>(left_bits), local.state.words[word]);
        builder.when(active.clone()).assert_eq(
            pack_bits::<AB>(right_bits),
            local.state.words[word + CV_WORDS],
        );
        let expected_bits = array::from_fn::<_, WORD_BITS, _>(|bit| {
            let left: AB::Expr = left_bits[bit].into();
            let right: AB::Expr = right_bits[bit].into();
            left.clone() + right.clone() - AB::Expr::TWO * left * right
        });
        for bit in 0..WORD_BITS {
            builder
                .when(active.clone())
                .assert_eq(output_bits[bit], expected_bits[bit].clone());
        }
        builder
            .when(active.clone())
            .assert_eq(local.output_words[word], pack_bits::<AB>(output_bits));
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

fn constrain_add3<AB: AirBuilder>(
    builder: &mut AB,
    active: AB::Expr,
    result: AB::Expr,
    a: AB::Expr,
    b: AB::Expr,
    c: AB::Expr,
) {
    let modulus = AB::Expr::from_u64(1_u64 << 32);
    let diff = a + b + c - result;
    builder.assert_zero(
        active * diff.clone() * (diff.clone() - modulus.clone()) * (diff - modulus.double()),
    );
}

fn constrain_add2<AB: AirBuilder>(
    builder: &mut AB,
    active: AB::Expr,
    result: AB::Expr,
    a: AB::Expr,
    b: AB::Expr,
) {
    let modulus = AB::Expr::from_u64(1_u64 << 32);
    let diff = a + b - result;
    builder.assert_zero(active * diff.clone() * (diff - modulus));
}

fn constrain_xor_rotate<AB: AirBuilder>(
    builder: &mut AB,
    active: AB::Expr,
    packed: AB::Expr,
    left: &[AB::Var; 32],
    output: &[AB::Var; 32],
    rotation: usize,
) {
    let bits = array::from_fn::<_, 32, _>(|index| {
        let a: AB::Expr = left[index].into();
        let b: AB::Expr = output[(index + 32 - rotation) % 32].into();
        a.clone() + b.clone() - AB::Expr::TWO * a * b
    });
    builder.assert_zero(active * (packed - pack_expr_bits::<AB>(&bits)));
}

fn constrain_initial_state<AB: AirBuilder>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
) {
    let is_new = prep.is_first_step;
    let state = &local.state;
    for index in 0..8 {
        builder
            .when(is_new)
            .assert_eq(state.words[index], local.chaining_value[index]);
    }
    for (index, iv) in IV.iter().take(4).enumerate() {
        builder
            .when(is_new)
            .assert_eq(state.words[8 + index], AB::Expr::from_u64(*iv as u64));
    }
    let tweaks = [
        prep.counter_low,
        prep.counter_high,
        prep.block_len,
        prep.flags,
    ];
    for (word, expected) in state.words[12..].iter().zip(tweaks) {
        builder.when(is_new).assert_eq(*word, expected);
    }
    for word in local.output_words {
        builder.when(is_new).assert_zero(word);
    }
    let context_key = blake3::hazmat::hash_derive_key_context(OUTPUT_CONTEXT);
    for index in 0..8 {
        let word = u32::from_le_bytes(
            context_key[index * 4..(index + 1) * 4]
                .try_into()
                .expect("word"),
        );
        builder
            .when(prep.uses_fixed_cv)
            .assert_eq(local.chaining_value[index], AB::Expr::from_u64(word as u64));
    }
}

fn constrain_message<AB: AirBuilder>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
) {
    let g_active = prep.phase.iter().fold(AB::Expr::ZERO, |sum, selector| {
        sum + AB::Expr::from(*selector)
    }) * prep.is_active_operation;
    for (word, permuted_word) in MSG_PERMUTATION.iter().enumerate() {
        let permute: AB::Expr = prep.permute_message.into();
        let expected = permute.clone() * local.message[*permuted_word]
            + (g_active.clone() - permute) * local.message[word];
        builder
            .when_transition()
            .when(g_active.clone())
            .assert_eq(next.message[word], expected);
    }
    let public = builder.public_values().to_vec();
    for group in 0..8 {
        for pair_word in 0..2 {
            let original_word = 2 * group + pair_word;
            let packed =
                pack_bytes::<AB>(&local.original_nibbles[pair_word * 4..pair_word * 4 + 4]);
            builder
                .when(prep.byte_group[group])
                .assert_eq(local.message[original_word], packed);
        }
        for byte in 0..8 {
            let block_byte = group * 8 + byte;
            if block_byte < 40 {
                builder
                    .when(AB::Expr::from(prep.is_first_message_block) * prep.byte_group[group])
                    .assert_eq(
                        byte_expr::<AB>(&local.original_nibbles[byte]),
                        public[block_byte],
                    );
            }
        }
    }
    for byte in 0..8 {
        builder
            .when(prep.padding_active[byte])
            .assert_zero(byte_expr::<AB>(&local.original_nibbles[byte]));
    }
}

fn constrain_digest<AB: AirBuilder>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
    _point_variables: usize,
) {
    let digest_offset = 40;
    let public = builder.public_values().to_vec();
    for word in 0..CV_WORDS {
        let active = AB::Expr::from(prep.is_root) * prep.final_word[word];
        let output_bits = &local.state.xor_bits[2];
        for byte in 0..4 {
            let shift = byte * 8;
            let bits = &output_bits[shift..shift + 8];
            builder.when(active.clone()).assert_eq(
                pack_expr_bits::<AB>(&bits.iter().map(|bit| (*bit).into()).collect::<Vec<_>>()),
                public[digest_offset + word * 4 + byte],
            );
        }
    }
}

fn constrain_evaluation<AB: AirBuilder>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
    point_variables: usize,
) {
    let public = builder.public_values().to_vec();
    let high_weight = ExtExpr(prep.activation_high_weight.map(Into::into));
    let mut contribution = ExtExpr::zero();
    for byte in 0..8 {
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

fn constrain_links<AB: AirBuilder>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    prep: &PrepCols<AB::Var>,
) {
    let output = output_packed_expr::<AB>(local);
    for (word, output_word) in output.iter().enumerate() {
        builder
            .when_transition()
            .when(prep.chains_to_next)
            .assert_eq(next.chaining_value[word], output_word.clone());

        let left = (0..MAX_STACK_DEPTH).fold(AB::Expr::ZERO, |sum, slot| {
            sum + AB::Expr::from(prep.stack_read_left[slot]) * local.stack[slot][word]
        });
        let right = (0..MAX_STACK_DEPTH).fold(AB::Expr::ZERO, |sum, slot| {
            sum + AB::Expr::from(prep.stack_read_right[slot]) * local.stack[slot][word]
        });
        let reads_left = prep
            .stack_read_left
            .iter()
            .fold(AB::Expr::ZERO, |sum, selector| {
                sum + AB::Expr::from(*selector)
            });
        let reads_right = prep
            .stack_read_right
            .iter()
            .fold(AB::Expr::ZERO, |sum, selector| {
                sum + AB::Expr::from(*selector)
            });
        builder
            .when(reads_left)
            .assert_eq(local.message[word], left);
        builder
            .when(reads_right)
            .assert_eq(local.message[word + CV_WORDS], right);

        for slot in 0..MAX_STACK_DEPTH {
            builder
                .when_first_row()
                .assert_zero(local.stack[slot][word]);
            let write: AB::Expr = prep.stack_write[slot].into();
            let expected = write.clone() * output[word].clone()
                + (AB::Expr::ONE - write) * local.stack[slot][word];
            builder
                .when_transition()
                .assert_eq(next.stack[slot][word], expected);
        }
    }
}

fn generate_preprocessed(
    activation_len: usize,
    rows: usize,
    point: &[crate::structured_sumcheck::ExtensionField],
) -> RowMajorMatrix<F> {
    let dummy = vec![0_u8; activation_len];
    let witness =
        build_tree_witness(OUTPUT_CONTEXT, [0; 32], &dummy).expect("valid deterministic schedule");
    let mut values = F::zero_vec(rows * PREP_WIDTH);
    for row_index in 0..rows {
        let prep: &mut PrepCols<F> =
            values[row_index * PREP_WIDTH..(row_index + 1) * PREP_WIDTH].borrow_mut();
        let step = row_index % ROWS_PER_COMPRESSION;
        if step < G_STEPS_PER_COMPRESSION {
            let round = step / G_STEPS_PER_ROUND;
            let within_round = step % G_STEPS_PER_ROUND;
            let phase = within_round / 4;
            let index = within_round % 4;
            prep.round[round] = F::ONE;
            prep.phase[phase] = F::ONE;
            prep.g_index[index] = F::ONE;
            prep.is_first_step = F::from_bool(step == 0);
            prep.permute_message = F::from_bool(within_round + 1 == G_STEPS_PER_ROUND);
        } else {
            let word = step - G_STEPS_PER_COMPRESSION;
            prep.final_word[word] = F::ONE;
            prep.is_finalization = F::ONE;
            prep.is_last_finalization = F::from_bool(word + 1 == FINALIZATION_ROWS);
        }
        if step < BYTES_PER_EVAL_ROW {
            prep.byte_group[step] = F::ONE;
        }
        let operation_index = row_index / ROWS_PER_COMPRESSION;
        let Some(operation) = witness.operations.get(operation_index) else {
            continue;
        };
        prep.is_active_operation = F::ONE;
        prep.is_root = F::from_bool(
            operation.output_id.is_none()
                && operation_index + 1 == witness.operations.len()
                && step >= G_STEPS_PER_COMPRESSION,
        );
        prep.uses_fixed_cv = F::from_bool(
            step == 0
                && (operation.kind == CompressionKind::Parent || operation.consume_left.is_none()),
        );
        prep.is_first_message_block = F::from_bool(operation.message_offset == Some(0));
        prep.is_last_message_block =
            F::from_bool(operation.message_offset.is_some_and(|offset| {
                offset + operation.block_len as usize == witness.message_len
            }));
        prep.counter_low = F::from_u32(operation.counter as u32);
        prep.counter_high = F::from_u32((operation.counter >> 32) as u32);
        prep.block_len = F::from_u32(operation.block_len);
        prep.flags = F::from_u32(operation.flags);
        if prep.is_last_finalization == F::ONE {
            if let Some(next) = witness.operations.get(operation_index + 1) {
                prep.chains_to_next = F::from_bool(
                    operation.output_id.is_some()
                        && next.kind == CompressionKind::Chunk
                        && next.consume_left == operation.output_id,
                );
            }
            if let Some(slot) = operation.stack_write {
                prep.stack_write[slot] = F::ONE;
            }
        }
        if prep.is_first_step == F::ONE {
            if let Some(slot) = operation.stack_read_left {
                prep.stack_read_left[slot] = F::ONE;
            }
            if let Some(slot) = operation.stack_read_right {
                prep.stack_read_right[slot] = F::ONE;
            }
        }
        if operation.kind == CompressionKind::Chunk && step < BYTES_PER_EVAL_ROW {
            let message_offset = operation
                .message_offset
                .expect("chunk compression has a message offset")
                + step * 8;
            if (40..40 + activation_len).contains(&message_offset)
                && message_offset + 8 <= 40 + activation_len
            {
                let activation_index = message_offset - 40;
                prep.activation_active = F::ONE;
                let mut weight = crate::structured_sumcheck::ExtensionField::ONE;
                for (variable, coordinate) in
                    point.iter().enumerate().skip(LOW_EVALUATION_VARIABLES)
                {
                    weight = weight.mul(if (activation_index >> variable) & 1 == 1 {
                        *coordinate
                    } else {
                        crate::structured_sumcheck::ExtensionField::ONE.sub(*coordinate)
                    });
                }
                set_ext(&mut prep.activation_high_weight, weight);
            }
            if prep.is_last_message_block == F::ONE {
                for byte in 0..8 {
                    prep.padding_active[byte] =
                        F::from_bool(step * 8 + byte >= operation.block_len as usize);
                }
            }
        }
    }
    RowMajorMatrix::new(values, PREP_WIDTH)
}

pub(crate) fn generate_main_trace(
    air: &NarrowBlake3Air,
    statement: &StructuredBlake3Statement,
    witness: &crate::structured_blake3_tree::Blake3TreeWitness,
) -> RowMajorMatrix<F> {
    let mut values = Vec::with_capacity(air.trace_rows * MAIN_WIDTH);
    for_each_main_trace_row(air, statement, witness, |row_index, row| {
        debug_assert_eq!(values.len(), row_index * MAIN_WIDTH);
        values.extend_from_slice(row);
        Ok::<_, std::convert::Infallible>(())
    })
    .expect("infallible in-memory trace sink");
    RowMajorMatrix::new(values, MAIN_WIDTH)
}

/// Generates one canonical trace row at a time so a future PCS can consume or
/// spill the witness without retaining the full base trace in memory.
pub(crate) fn for_each_main_trace_row<E>(
    air: &NarrowBlake3Air,
    statement: &StructuredBlake3Statement,
    witness: &crate::structured_blake3_tree::Blake3TreeWitness,
    mut emit: impl FnMut(usize, &[F]) -> Result<(), E>,
) -> Result<(), E> {
    let point = statement
        .final_activation_point
        .iter()
        .map(|p| p.to_field().expect("validated point"))
        .collect::<Vec<_>>();
    let mut evaluation_acc = crate::structured_sumcheck::ExtensionField::ZERO;
    let mut stack = [[0_u32; CV_WORDS]; MAX_STACK_DEPTH];
    let mut row_values = F::zero_vec(MAIN_WIDTH);
    let dummy = dummy_operation();
    for operation_index in 0..air.trace_rows.div_ceil(ROWS_PER_COMPRESSION) {
        let operation = witness.operations.get(operation_index).unwrap_or(&dummy);
        let (states, messages) = operation_trace(operation);
        for (step, message) in messages.iter().enumerate().take(ROWS_PER_COMPRESSION) {
            let row_index = operation_index * ROWS_PER_COMPRESSION + step;
            if row_index == air.trace_rows {
                break;
            }
            row_values.fill(F::ZERO);
            let row: &mut MainCols<F> = row_values.as_mut_slice().borrow_mut();
            set_ext(&mut row.evaluation_accumulator, evaluation_acc);
            row.stack = stack.map(|entry| entry.map(F::from_u32));
            row.state = state_cols(step, &states, operation);
            row.message = (*message).map(F::from_u32);
            if step >= G_STEPS_PER_COMPRESSION {
                let final_word = step - G_STEPS_PER_COMPRESSION;
                for word in 0..=final_word {
                    row.output_words[word] = F::from_u32(operation.output[word]);
                }
            }
            row.original_nibbles = array::from_fn(|byte| {
                let value = if step < BYTES_PER_EVAL_ROW {
                    let block_byte = step * 8 + byte;
                    ((operation.block[block_byte / 4] >> (8 * (block_byte % 4))) & 0xff) as u8
                } else {
                    0
                };
                [F::from_u8(value & 0xf), F::from_u8(value >> 4)]
            });
            row.chaining_value = operation.chaining_value.map(F::from_u32);
            let message_offset = operation
                .message_offset
                .unwrap_or(usize::MAX)
                .saturating_add(step * 8);
            let active = operation.kind == CompressionKind::Chunk
                && step < BYTES_PER_EVAL_ROW
                && (40..40 + air.activation_len).contains(&message_offset)
                && message_offset + 8 <= 40 + air.activation_len;
            let mut high_weight =
                crate::structured_sumcheck::ExtensionField::from_u64(u64::from(active));
            if active {
                let base_index = message_offset - 40;
                for (variable, coordinate) in point
                    .iter()
                    .enumerate()
                    .take(air.point_variables)
                    .skip(LOW_EVALUATION_VARIABLES)
                {
                    let factor = if (base_index >> variable) & 1 == 1 {
                        *coordinate
                    } else {
                        crate::structured_sumcheck::ExtensionField::ONE.sub(*coordinate)
                    };
                    high_weight = high_weight.mul(factor);
                }
                for byte in 0..8 {
                    let mut low_weight = crate::structured_sumcheck::ExtensionField::ONE;
                    for (variable, coordinate) in
                        point.iter().enumerate().take(LOW_EVALUATION_VARIABLES)
                    {
                        let factor = if (byte >> variable) & 1 == 1 {
                            *coordinate
                        } else {
                            crate::structured_sumcheck::ExtensionField::ONE.sub(*coordinate)
                        };
                        low_weight = low_weight.mul(factor);
                    }
                    let selected = ((operation.block[(step * 8 + byte) / 4]
                        >> (8 * ((step * 8 + byte) % 4)))
                        & 0xff) as u8;
                    evaluation_acc = evaluation_acc.add(high_weight.mul(low_weight).mul(
                        crate::structured_sumcheck::ExtensionField::from_signed(
                            i64::from(selected) - 125,
                        ),
                    ));
                }
            }
            if step + 1 == ROWS_PER_COMPRESSION {
                let output_values = operation.output[..8]
                    .try_into()
                    .expect("eight output words");
                if let Some(slot) = operation.stack_write {
                    stack[slot] = output_values;
                }
            }
            emit(row_index, &row_values)?;
        }
    }
    Ok(())
}

fn operation_trace(
    operation: &CompressionOp,
) -> (
    [[u32; 16]; ROWS_PER_COMPRESSION],
    [[u32; 16]; ROWS_PER_COMPRESSION],
) {
    let mut states = [[0_u32; 16]; ROWS_PER_COMPRESSION];
    let mut messages = [[0_u32; 16]; ROWS_PER_COMPRESSION];
    let mut state = initial_state(operation);
    let mut message = operation.block;
    for step in 0..G_STEPS_PER_COMPRESSION {
        states[step] = state;
        messages[step] = message;
        let within_round = step % G_STEPS_PER_ROUND;
        let phase = within_round / 4;
        let index = within_round % 4;
        let diagonal = phase >= 2;
        let second = phase % 2 == 1;
        let a = index;
        let b = 4 + if diagonal { (index + 1) % 4 } else { index };
        let c = 8 + if diagonal { (index + 2) % 4 } else { index };
        let d = 12 + if diagonal { (index + 3) % 4 } else { index };
        let message_index = if diagonal {
            8 + 2 * index + usize::from(second)
        } else {
            2 * index + usize::from(second)
        };
        half_g_native(&mut state, a, b, c, d, message[message_index], second);
        if within_round + 1 == G_STEPS_PER_ROUND {
            message = array::from_fn(|word| message[MSG_PERMUTATION[word]]);
        }
    }
    for step in G_STEPS_PER_COMPRESSION..ROWS_PER_COMPRESSION {
        states[step] = state;
        messages[step] = message;
    }
    (states, messages)
}

fn initial_state(operation: &CompressionOp) -> [u32; 16] {
    [
        operation.chaining_value[0],
        operation.chaining_value[1],
        operation.chaining_value[2],
        operation.chaining_value[3],
        operation.chaining_value[4],
        operation.chaining_value[5],
        operation.chaining_value[6],
        operation.chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        operation.counter as u32,
        (operation.counter >> 32) as u32,
        operation.block_len,
        operation.flags,
    ]
}

fn half_g_native(
    state: &mut [u32; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    m: u32,
    second: bool,
) {
    let (r1, r2) = if second { (8, 7) } else { (16, 12) };
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(m);
    state[d] = (state[d] ^ state[a]).rotate_right(r1);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(r2);
}

fn state_cols(
    step: usize,
    states: &[[u32; 16]; ROWS_PER_COMPRESSION],
    operation: &CompressionOp,
) -> StateCols<F> {
    let words = states[step];
    let mut values = [0_u32; 6];
    if step < G_STEPS_PER_COMPRESSION {
        let within_round = step % G_STEPS_PER_ROUND;
        let phase = within_round / 4;
        let index = within_round % 4;
        let diagonal = phase >= 2;
        let a = index;
        let b = 4 + if diagonal { (index + 1) % 4 } else { index };
        let c = 8 + if diagonal { (index + 2) % 4 } else { index };
        let d = 12 + if diagonal { (index + 3) % 4 } else { index };
        let next = states[step + 1];
        values = [words[b], words[d], next[b], next[d], next[a], next[c]];
    } else {
        let word = step - G_STEPS_PER_COMPRESSION;
        values[0] = words[word];
        values[1] = words[word + CV_WORDS];
        values[2] = operation.output[word];
    }
    StateCols {
        words: words.map(F::from_u32),
        xor_bits: array::from_fn(|index| u32_bits(values[index]).map(F::from_bool)),
        range_nibbles: array::from_fn(|index| {
            array::from_fn(|nibble| F::from_u8(((values[4 + index] >> (4 * nibble)) & 0xf) as u8))
        }),
    }
}

fn dummy_operation() -> CompressionOp {
    CompressionOp {
        kind: CompressionKind::Chunk,
        block: [0; 16],
        chaining_value: [0; 8],
        counter: 0,
        block_len: 0,
        flags: 0,
        output: [0; 16],
        output_id: None,
        consume_left: None,
        consume_right: None,
        message_offset: None,
        stack_read_left: None,
        stack_read_right: None,
        stack_write: None,
    }
}

fn operation_count(len: usize) -> Result<usize, NarrowBlake3Error> {
    let message = len
        .checked_add(40)
        .ok_or(NarrowBlake3Error::UnsupportedShape)?;
    let chunks = message.div_ceil(1024);
    message
        .div_ceil(64)
        .checked_add(chunks.saturating_sub(1))
        .ok_or(NarrowBlake3Error::UnsupportedShape)
}

pub(crate) fn public_values(
    statement: &StructuredBlake3Statement,
) -> Result<Vec<F>, NarrowBlake3Error> {
    let mut values = Vec::with_capacity(75 + 3 * statement.final_activation_point.len());
    values.extend(statement.challenge_digest.into_iter().map(F::from_u8));
    values.extend(
        (statement.final_activation_len as u64)
            .to_le_bytes()
            .into_iter()
            .map(F::from_u8),
    );
    values.extend(
        statement
            .final_activation_digest
            .into_iter()
            .map(F::from_u8),
    );
    for point in &statement.final_activation_point {
        for limb in point.limbs {
            values.push(canonical(limb)?);
        }
    }
    for limb in statement.final_activation_evaluation.limbs {
        values.push(canonical(limb)?);
    }
    Ok(values)
}
fn canonical(value: u64) -> Result<F, NarrowBlake3Error> {
    F::from_canonical_checked(value).ok_or(NarrowBlake3Error::NonCanonicalField)
}
fn validate_field_elements(statement: &StructuredBlake3Statement) -> Result<(), NarrowBlake3Error> {
    if statement
        .final_activation_point
        .iter()
        .chain(std::iter::once(&statement.final_activation_evaluation))
        .any(|v| v.limbs.iter().any(|x| *x >= GOLDILOCKS_MODULUS))
    {
        Err(NarrowBlake3Error::NonCanonicalField)
    } else {
        Ok(())
    }
}
fn validate_opening(
    statement: &StructuredBlake3Statement,
    activation: &[u8],
) -> Result<(), NarrowBlake3Error> {
    let point = statement
        .final_activation_point
        .iter()
        .map(|p| p.to_field())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NarrowBlake3Error::NonCanonicalField)?;
    let table = activation
        .iter()
        .map(|v| crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*v) - 125))
        .collect::<Vec<_>>();
    let got = crate::structured_sumcheck::evaluate_mle(&table, &point);
    if crate::ExtensionElement::from_field(got) == statement.final_activation_evaluation {
        Ok(())
    } else {
        Err(NarrowBlake3Error::Opening)
    }
}

fn encode_native_proof(mut proof: NativeProof) -> Result<Vec<u8>, NarrowBlake3Error> {
    let archive = extract_merkle_paths(&mut proof)?;
    let proof_bytes = bincode_options()
        .serialize(&proof)
        .map_err(|_| NarrowBlake3Error::Encoding)?;
    let archive_bytes = bincode_options()
        .serialize(&archive)
        .map_err(|_| NarrowBlake3Error::Encoding)?;
    let proof_len = u32::try_from(proof_bytes.len()).map_err(|_| NarrowBlake3Error::Encoding)?;
    let archive_len =
        u32::try_from(archive_bytes.len()).map_err(|_| NarrowBlake3Error::Encoding)?;
    let mut encoded = Vec::with_capacity(20 + proof_bytes.len() + archive_bytes.len());
    encoded.extend_from_slice(NARROW_PROOF_MAGIC);
    encoded.extend_from_slice(&NARROW_PROOF_VERSION.to_le_bytes());
    encoded.extend_from_slice(&proof_len.to_le_bytes());
    encoded.extend_from_slice(&archive_len.to_le_bytes());
    encoded.extend_from_slice(&proof_bytes);
    encoded.extend_from_slice(&archive_bytes);
    Ok(encoded)
}

pub(crate) fn decode_native_proof(bytes: &[u8]) -> Result<NativeProof, NarrowBlake3Error> {
    if bytes.len() < 20 || bytes.get(..8) != Some(NARROW_PROOF_MAGIC.as_slice()) {
        return Err(NarrowBlake3Error::Encoding);
    }
    let version = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| NarrowBlake3Error::Encoding)?,
    );
    let proof_len = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| NarrowBlake3Error::Encoding)?,
    ) as usize;
    let archive_len = u32::from_le_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| NarrowBlake3Error::Encoding)?,
    ) as usize;
    let proof_end = 20usize
        .checked_add(proof_len)
        .ok_or(NarrowBlake3Error::Encoding)?;
    let archive_end = proof_end
        .checked_add(archive_len)
        .ok_or(NarrowBlake3Error::Encoding)?;
    if version != NARROW_PROOF_VERSION || archive_end != bytes.len() {
        return Err(NarrowBlake3Error::Encoding);
    }
    let proof_bytes = &bytes[20..proof_end];
    let archive_bytes = &bytes[proof_end..archive_end];
    let mut proof: NativeProof = bincode_options()
        .deserialize(proof_bytes)
        .map_err(|_| NarrowBlake3Error::Encoding)?;
    let archive: MerklePathArchive = bincode_options()
        .deserialize(archive_bytes)
        .map_err(|_| NarrowBlake3Error::Encoding)?;
    if bincode_options()
        .serialize(&proof)
        .map_err(|_| NarrowBlake3Error::Encoding)?
        != proof_bytes
        || bincode_options()
            .serialize(&archive)
            .map_err(|_| NarrowBlake3Error::Encoding)?
            != archive_bytes
    {
        return Err(NarrowBlake3Error::Encoding);
    }
    restore_merkle_paths(&mut proof, &archive)?;
    Ok(proof)
}

fn extract_merkle_paths(proof: &mut NativeProof) -> Result<MerklePathArchive, NarrowBlake3Error> {
    let mut archive = MerklePathArchive {
        lengths: Vec::new(),
        indices: Vec::new(),
        digests: Vec::new(),
    };
    let mut dictionary = BTreeMap::new();
    for query in &mut proof.opening_proof.query_proofs {
        for opening in &mut query.input_proof {
            archive_path(&mut opening.opening_proof, &mut archive, &mut dictionary)?;
        }
        for step in &mut query.commit_phase_openings {
            archive_path(&mut step.opening_proof, &mut archive, &mut dictionary)?;
        }
    }
    Ok(archive)
}

fn archive_path(
    path: &mut Vec<[F; 4]>,
    archive: &mut MerklePathArchive,
    dictionary: &mut BTreeMap<[u64; 4], u16>,
) -> Result<(), NarrowBlake3Error> {
    archive
        .lengths
        .push(u16::try_from(path.len()).map_err(|_| NarrowBlake3Error::Encoding)?);
    for digest in path.drain(..) {
        let key = digest.map(|value| value.as_canonical_u64());
        let index = if let Some(index) = dictionary.get(&key) {
            *index
        } else {
            let index =
                u16::try_from(archive.digests.len()).map_err(|_| NarrowBlake3Error::Encoding)?;
            dictionary.insert(key, index);
            archive.digests.push(digest);
            index
        };
        archive.indices.push(index);
    }
    Ok(())
}

fn restore_merkle_paths(
    proof: &mut NativeProof,
    archive: &MerklePathArchive,
) -> Result<(), NarrowBlake3Error> {
    let mut unique = BTreeMap::new();
    for (index, digest) in archive.digests.iter().enumerate() {
        let key = digest.map(|value| value.as_canonical_u64());
        if unique.insert(key, index).is_some() {
            return Err(NarrowBlake3Error::Encoding);
        }
    }
    let mut length_cursor = 0;
    let mut index_cursor = 0;
    let mut next_new_digest = 0_usize;
    for query in &mut proof.opening_proof.query_proofs {
        for opening in &mut query.input_proof {
            restore_path(
                &mut opening.opening_proof,
                archive,
                &mut length_cursor,
                &mut index_cursor,
                &mut next_new_digest,
            )?;
        }
        for step in &mut query.commit_phase_openings {
            restore_path(
                &mut step.opening_proof,
                archive,
                &mut length_cursor,
                &mut index_cursor,
                &mut next_new_digest,
            )?;
        }
    }
    if length_cursor != archive.lengths.len()
        || index_cursor != archive.indices.len()
        || next_new_digest != archive.digests.len()
    {
        return Err(NarrowBlake3Error::Encoding);
    }
    Ok(())
}

fn restore_path(
    path: &mut Vec<[F; 4]>,
    archive: &MerklePathArchive,
    length_cursor: &mut usize,
    index_cursor: &mut usize,
    next_new_digest: &mut usize,
) -> Result<(), NarrowBlake3Error> {
    if !path.is_empty() {
        return Err(NarrowBlake3Error::Encoding);
    }
    let length = usize::from(
        *archive
            .lengths
            .get(*length_cursor)
            .ok_or(NarrowBlake3Error::Encoding)?,
    );
    *length_cursor += 1;
    path.reserve(length);
    for _ in 0..length {
        let index = usize::from(
            *archive
                .indices
                .get(*index_cursor)
                .ok_or(NarrowBlake3Error::Encoding)?,
        );
        *index_cursor += 1;
        let digest = *archive
            .digests
            .get(index)
            .ok_or(NarrowBlake3Error::Encoding)?;
        if index == *next_new_digest {
            *next_new_digest += 1;
        } else if index > *next_new_digest {
            return Err(NarrowBlake3Error::Encoding);
        }
        path.push(digest);
    }
    Ok(())
}

pub(crate) fn build_config() -> Config {
    build_config_with_fri(FRI_LOG_BLOWUP, FRI_QUERIES)
}

pub(crate) fn build_config_with_fri(log_blowup: usize, num_queries: usize) -> Config {
    let perm = default_poseidon2();
    let val = ValMmcs::new(FieldHash::new(perm.clone()), Compress::new(perm.clone()), 0);
    let challenge = ChallengeMmcs::new(val.clone());
    let pcs = Pcs::new(
        Radix2DitParallel::default(),
        val,
        fri_parameters_with(log_blowup, num_queries, challenge),
    );
    Config::new(pcs, Challenger::new(perm))
}

fn default_poseidon2() -> Perm {
    default_goldilocks_poseidon2_8()
}
#[cfg(test)]
fn fri_parameters(mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
    fri_parameters_with(FRI_LOG_BLOWUP, FRI_QUERIES, mmcs)
}
fn fri_parameters_with(
    log_blowup: usize,
    num_queries: usize,
    mmcs: ChallengeMmcs,
) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 4,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: FRI_QUERY_POW_BITS,
        mmcs,
    }
}
fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES as u64)
}

fn pack_bits<AB: AirBuilder>(bits: &[AB::Var; 32]) -> AB::Expr {
    let mut factor = AB::Expr::ONE;
    let mut result = AB::Expr::ZERO;
    for bit in bits {
        result += AB::Expr::from(*bit) * factor.clone();
        factor = factor.double();
    }
    result
}
fn pack_nibbles<AB: AirBuilder>(nibbles: &[AB::Var; 8]) -> AB::Expr {
    let mut factor = AB::Expr::ONE;
    let mut result = AB::Expr::ZERO;
    for nibble in nibbles {
        result += AB::Expr::from(*nibble) * factor.clone();
        factor *= AB::Expr::from_u8(16);
    }
    result
}
fn pack_expr_bits<AB: AirBuilder>(bits: &[AB::Expr]) -> AB::Expr {
    let mut factor = AB::Expr::ONE;
    let mut result = AB::Expr::ZERO;
    for bit in bits {
        result += bit.clone() * factor.clone();
        factor = factor.double();
    }
    result
}
fn byte_expr<AB: AirBuilder>(nibbles: &[AB::Var; 2]) -> AB::Expr {
    AB::Expr::from(nibbles[0]) + AB::Expr::from(nibbles[1]) * AB::Expr::from_u8(16)
}
fn pack_bytes<AB: AirBuilder>(bytes: &[[AB::Var; 2]]) -> AB::Expr {
    let mut factor = AB::Expr::ONE;
    let mut result = AB::Expr::ZERO;
    for byte in bytes {
        result += byte_expr::<AB>(byte) * factor.clone();
        factor *= AB::Expr::from_u64(256);
    }
    result
}
fn output_packed_expr<AB: AirBuilder>(local: &MainCols<AB::Var>) -> [AB::Expr; 8] {
    local.output_words.map(Into::into)
}
fn u32_bits(value: u32) -> [bool; 32] {
    array::from_fn(|bit| (value >> bit) & 1 == 1)
}
fn set_ext(target: &mut [F; 3], value: crate::structured_sumcheck::ExtensionField) {
    let e = crate::ExtensionElement::from_field(value);
    for (target, limb) in target.iter_mut().zip(e.limbs) {
        *target = F::from_u64(limb);
    }
}

#[derive(Clone)]
struct ExtExpr<E>([E; 3]);
impl<E: Clone + std::ops::Add<Output = E>> std::ops::Add for ExtExpr<E> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(array::from_fn(|i| self.0[i].clone() + rhs.0[i].clone()))
    }
}
impl<E: Clone + std::ops::Sub<Output = E>> std::ops::Sub for ExtExpr<E> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(array::from_fn(|i| self.0[i].clone() - rhs.0[i].clone()))
    }
}
impl<E: Clone + std::ops::Add<Output = E> + std::ops::Mul<Output = E>> std::ops::Mul
    for ExtExpr<E>
{
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        let cross = a[1].clone() * b[2].clone() + a[2].clone() * b[1].clone();
        let d4 = a[2].clone() * b[2].clone();
        Self([
            a[0].clone() * b[0].clone() + cross.clone(),
            a[0].clone() * b[1].clone() + a[1].clone() * b[0].clone() + cross + d4.clone(),
            a[0].clone() * b[2].clone()
                + a[1].clone() * b[1].clone()
                + a[2].clone() * b[0].clone()
                + d4,
        ])
    }
}
impl<E: Clone + PrimeCharacteristicRing> ExtExpr<E> {
    fn zero() -> Self {
        Self([E::ZERO, E::ZERO, E::ZERO])
    }
    fn one() -> Self {
        Self([E::ONE, E::ZERO, E::ZERO])
    }
    fn splat(v: E) -> Self {
        Self([v, E::ZERO, E::ZERO])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::AirLayout;
    use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};

    fn statement(activation: &[u8]) -> StructuredBlake3Statement {
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
            .unwrap();
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

    #[test]
    fn narrow_tree_trace_satisfies_every_air_constraint() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let air = NarrowBlake3Air::new(&statement).unwrap();
        assert_eq!(air.trace_rows, 256);
        let witness =
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, &activation).unwrap();
        let trace = generate_main_trace(&air, &statement, &witness);
        p3_air::check_constraints(&air, &trace, &public_values(&statement).unwrap());
    }

    #[test]
    fn trace_rows_can_be_consumed_incrementally_and_stop_early() {
        let activation = (0..2_048)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let statement = statement(&activation);
        let air = NarrowBlake3Air::new(&statement).unwrap();
        let witness =
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, &activation).unwrap();
        let mut emitted = 0_usize;
        let stopped = for_each_main_trace_row(
            &air,
            &statement,
            &witness,
            |row_index, row| -> Result<(), &'static str> {
                assert_eq!(row_index, emitted);
                assert_eq!(row.len(), MAIN_WIDTH);
                emitted += 1;
                if emitted == 17 { Err("stop") } else { Ok(()) }
            },
        );
        assert_eq!(stopped, Err("stop"));
        assert_eq!(emitted, 17);
        assert!(air.trace_rows > emitted);
    }

    #[test]
    fn narrow_tree_stark_round_trips() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let proof = prove_narrow_blake3(&statement, &activation).unwrap();
        assert_eq!(proof.len(), 214_379);
        verify_narrow_blake3(&statement, &proof).unwrap();
        assert!(proof.len() <= crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES);

        let mut wrong_digest = statement.clone();
        wrong_digest.final_activation_digest[0] ^= 1;
        assert!(verify_narrow_blake3(&wrong_digest, &proof).is_err());

        for index in [0, 8, 12, 16, proof.len() / 2, proof.len() - 1] {
            let mut mutated = proof.clone();
            mutated[index] ^= 0x80;
            let result = catch_unwind(AssertUnwindSafe(|| {
                verify_narrow_blake3(&statement, &mutated)
            }));
            assert!(result.is_ok(), "verifier panicked for mutation at {index}");
            assert!(result.unwrap().is_err());
        }
        let mut trailing = proof.clone();
        trailing.push(0);
        assert_eq!(
            verify_narrow_blake3(&statement, &trailing),
            Err(NarrowBlake3Error::Encoding)
        );
        for length in [0, 8, 19, proof.len() - 1] {
            assert_eq!(
                verify_narrow_blake3(&statement, &proof[..length]),
                Err(NarrowBlake3Error::Encoding)
            );
        }
    }

    #[test]
    fn merkle_archive_rejects_noncanonical_or_out_of_range_dictionaries() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let proof = prove_narrow_blake3(&statement, &activation).unwrap();
        let proof_len = u32::from_le_bytes(proof[12..16].try_into().unwrap()) as usize;
        let archive_start = 20 + proof_len;
        let mut archive: MerklePathArchive = bincode_options()
            .deserialize(&proof[archive_start..])
            .unwrap();

        archive.digests.push(archive.digests[0]);
        let duplicate = rebuild_with_archive(&proof, proof_len, &archive);
        assert_eq!(
            decode_native_proof(&duplicate).err(),
            Some(NarrowBlake3Error::Encoding)
        );

        archive.digests.pop();
        archive.indices[0] = u16::MAX;
        let out_of_range = rebuild_with_archive(&proof, proof_len, &archive);
        assert_eq!(
            decode_native_proof(&out_of_range).err(),
            Some(NarrowBlake3Error::Encoding)
        );
    }

    fn rebuild_with_archive(
        original: &[u8],
        proof_len: usize,
        archive: &MerklePathArchive,
    ) -> Vec<u8> {
        let archive = bincode_options().serialize(archive).unwrap();
        let mut rebuilt = original[..20 + proof_len].to_vec();
        rebuilt[16..20].copy_from_slice(&(archive.len() as u32).to_le_bytes());
        rebuilt.extend_from_slice(&archive);
        rebuilt
    }

    #[test]
    fn multi_chunk_stack_trace_satisfies_every_air_constraint() {
        let activation = (0..2_048)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let statement = statement(&activation);
        let air = NarrowBlake3Air::new(&statement).unwrap();
        let witness =
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, &activation).unwrap();
        assert!(witness.operations.iter().any(|operation| {
            operation.stack_read_left.is_some() && operation.stack_read_right.is_some()
        }));
        let trace = generate_main_trace(&air, &statement, &witness);
        p3_air::check_constraints(&air, &trace, &public_values(&statement).unwrap());
    }

    #[test]
    fn production_shape_has_at_least_128_bits_of_proven_security() {
        let activation = vec![0_u8; 1 << 19];
        let statement = statement(&activation);
        let air = NarrowBlake3Air::new(&statement).unwrap();
        assert_eq!(air.trace_rows, 1 << 20);
        let perm = default_poseidon2();
        let val = ValMmcs::new(FieldHash::new(perm.clone()), Compress::new(perm), 0);
        let params = StarkSecurityParams::from_air::<F, EF, _, _>(
            &fri_parameters(ChallengeMmcs::new(val)),
            &air,
            AirLayout::from_air::<F>(&air),
            192,
            128,
            1,
        );
        let security = ProvenSecurity::compute(&params, air.trace_rows);
        assert!(security.security_bits() >= 128, "{security:?}");
    }

    #[test]
    #[ignore = "resource-sizing benchmark"]
    fn proof_size_at_32768_rows() {
        use std::io::Write;

        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let air = NarrowBlake3Air::new_with_min_rows(&statement, 32_768).unwrap();
        let witness =
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, &activation).unwrap();
        let trace = generate_main_trace(&air, &statement, &witness);
        let public = public_values(&statement).unwrap();
        let config = build_config();
        let (prep, _) = setup_preprocessed(&config, &air, 15).unwrap();
        let proof = prove_with_preprocessed(&config, &air, trace, &public, Some(&prep));
        let native = encode_native_proof(proof).unwrap();
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&native).unwrap();
        let compressed = encoder.finish().unwrap();
        eprintln!("native={} zlib={}", native.len(), compressed.len());
        assert!(17 + compressed.len() <= 256 * 1024);
    }
}
