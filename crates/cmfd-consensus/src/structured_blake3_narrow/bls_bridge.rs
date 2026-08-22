//! BLS12-381 final-output opening inside the narrow BLAKE3 AIR.
//!
//! The existing hash trace authenticates the exact activation bytes. This
//! companion AIR accumulates those same row bytes against the multilinear
//! basis weights selected by the Dory verifier. Eight 32-bit limbs, bounded
//! quotient digits, and signed carries enforce every modular-reduction limb as
//! an integer equality below the Goldilocks modulus. No field homomorphism
//! between Goldilocks and BLS12-381 is assumed.

use std::io::{Read, Write};

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use dory_pcs::primitives::arithmetic::Field as DoryField;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use primitive_types::U512;

use super::*;
use crate::{
    ExtensionElement,
    dory_bls12_381_output_bridge::{
        BLS_DORY_OUTPUT_BRIDGE_SCALAR_LIMBS, BlsDoryOutputBridgeStatement, bls_dory_scalar_limbs,
    },
    dory_bls12_381_prototype::BlsDoryFr,
};

const BRIDGE_PROOF_MAGIC: &[u8; 8] = b"CMFDB3B1";
const BRIDGE_PROOF_VERSION: u32 = 1;
const BRIDGE_CODEC_MAGIC: &[u8; 8] = b"CMFDB3Z1";
const BRIDGE_CODEC_HEADER_BYTES: usize = 12;
const LIMBS: usize = BLS_DORY_OUTPUT_BRIDGE_SCALAR_LIMBS;
const LIMB_NIBBLES: usize = 8;
const QUOTIENT_NIBBLES: usize = 3;
const CARRY_COUNT: usize = LIMBS + 1;
const CARRY_NIBBLES: usize = 3;
const CARRY_OFFSET: i64 = 2_048;
const LIMB_BASE: u64 = 1_u64 << 32;
const BRIDGE_PERIODIC_WIDTH: usize = BYTES_PER_EVAL_ROW * LIMBS;
const HASH_PUBLIC_VALUES: usize = 72;
const TRANSCRIPT_BINDING_PUBLIC_VALUES: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct BridgeCols<T> {
    base: MainCols<T>,
    accumulator_limbs: [T; LIMBS],
    accumulator_nibbles: [[T; LIMB_NIBBLES]; LIMBS],
    quotient_nibbles: [T; QUOTIENT_NIBBLES],
    carry_nibbles: [[T; CARRY_NIBBLES]; CARRY_COUNT],
}

const BRIDGE_WIDTH: usize = size_of::<BridgeCols<u8>>();

impl<T> Borrow<BridgeCols<T>> for [T] {
    fn borrow(&self) -> &BridgeCols<T> {
        assert_eq!(self.len(), BRIDGE_WIDTH);
        unsafe { &*self.as_ptr().cast::<BridgeCols<T>>() }
    }
}

impl<T> BorrowMut<BridgeCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut BridgeCols<T> {
        assert_eq!(self.len(), BRIDGE_WIDTH);
        unsafe { &mut *self.as_mut_ptr().cast::<BridgeCols<T>>() }
    }
}

#[derive(Debug, Clone)]
struct BlsDoryNarrowBlake3Air {
    base: NarrowBlake3Air,
    point: Vec<BlsDoryFr>,
}

impl BlsDoryNarrowBlake3Air {
    fn new(statement: &BlsDoryOutputBridgeStatement) -> Result<Self, NarrowBlake3Error> {
        if statement.final_activation_len() < 32
            || statement.cell_point().len() != statement.final_activation_len().ilog2() as usize
        {
            return Err(NarrowBlake3Error::UnsupportedShape);
        }
        let base_statement = base_statement(statement);
        Ok(Self {
            base: NarrowBlake3Air::new(&base_statement)?,
            point: statement.cell_point().to_vec(),
        })
    }

    fn weights_at_row(&self, row_index: usize) -> [[u32; LIMBS]; BYTES_PER_EVAL_ROW] {
        let operation_index = row_index / ROWS_PER_COMPRESSION;
        let step = row_index % ROWS_PER_COMPRESSION;
        let message_offset = self
            .base
            .schedule
            .operations
            .get(operation_index)
            .and_then(|operation| operation.message_offset);
        activation_basis_weights(self.base.activation_len, &self.point, message_offset, step)
            .unwrap_or([[0; LIMBS]; BYTES_PER_EVAL_ROW])
    }
}

impl BaseAir<F> for BlsDoryNarrowBlake3Air {
    fn width(&self) -> usize {
        BRIDGE_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.base.preprocessed_trace()
    }

    fn preprocessed_width(&self) -> usize {
        PREP_WIDTH
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn num_periodic_columns(&self) -> usize {
        BRIDGE_PERIODIC_WIDTH
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let mut columns: [Vec<F>; BRIDGE_PERIODIC_WIDTH] =
            array::from_fn(|_| F::zero_vec(self.base.trace_rows));
        for row_index in 0..self.base.trace_rows {
            let weights = self.weights_at_row(row_index);
            for (column, weight) in columns.iter_mut().zip(weights.into_iter().flatten()) {
                column[row_index] = F::from_u32(weight);
            }
        }
        columns.into_iter().collect()
    }

    fn periodic_values(&self, row_index: usize) -> Vec<F> {
        self.weights_at_row(row_index)
            .into_iter()
            .flatten()
            .map(F::from_u32)
            .collect()
    }

    fn num_public_values(&self) -> usize {
        HASH_PUBLIC_VALUES + TRANSCRIPT_BINDING_PUBLIC_VALUES + self.point.len() * LIMBS + LIMBS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(16)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for BlsDoryNarrowBlake3Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = *<[AB::Var] as Borrow<BridgeCols<AB::Var>>>::borrow(main.current_slice());
        let next = *<[AB::Var] as Borrow<BridgeCols<AB::Var>>>::borrow(main.next_slice());
        let prep = *<[AB::Var] as Borrow<PrepCols<AB::Var>>>::borrow(
            builder.preprocessed().current_slice(),
        );

        constrain_bits(builder, &local.base);
        constrain_round(builder, &local.base, &next.base, &prep);
        constrain_initial_state(builder, &local.base, &prep);
        constrain_message(builder, &local.base, &next.base, &prep);
        constrain_digest(builder, &local.base, &prep, 0);
        constrain_links(builder, &local.base, &next.base, &prep);
        constrain_bls_evaluation(builder, &local, &next, self.point.len());
    }
}

pub(crate) fn prove_bls_dory_narrow_blake3(
    statement: &BlsDoryOutputBridgeStatement,
    activation: &[u8],
) -> Result<Vec<u8>, NarrowBlake3Error> {
    let config = build_config_with_backends(NarrowDft::default(), NarrowCommitBackend::default());
    let native = prove_bls_dory_narrow_blake3_with_config(statement, activation, &config, true)?;
    compress_bridge_proof(&native)
}

fn prove_bls_dory_narrow_blake3_with_config(
    statement: &BlsDoryOutputBridgeStatement,
    activation: &[u8],
    config: &Config,
    require_pinned_key: bool,
) -> Result<Vec<u8>, NarrowBlake3Error> {
    if activation.len() != statement.final_activation_len()
        || activation.iter().any(|value| *value > 250)
    {
        return Err(NarrowBlake3Error::UnsupportedShape);
    }
    statement
        .validate_activation(activation)
        .map_err(|_| NarrowBlake3Error::Opening)?;
    let air = BlsDoryNarrowBlake3Air::new(statement)?;
    let pinned_key = pinned_preprocessed_verifier_key(&air.base)?;
    let witness = build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest(), activation)?;
    if witness.digest != statement.final_activation_digest() {
        return Err(NarrowBlake3Error::Tree(Blake3TreeError::DigestMismatch));
    }
    let trace = generate_bridge_trace(&air, statement, &witness)?;
    let public = bridge_public_values(statement);
    let log_rows = air.base.trace_rows.ilog2() as usize;
    let proof = catch_unwind(AssertUnwindSafe(
        || -> Result<NativeProof, NarrowBlake3Error> {
            let (prep, generated_key) = setup_preprocessed(config, &air, log_rows)
                .expect("BLS bridge AIR has preprocessed columns");
            if require_pinned_key {
                require_matching_preprocessed_key(&generated_key, &pinned_key)?;
            }
            Ok(prove_with_preprocessed(
                config,
                &air,
                trace,
                &public,
                Some(&prep),
            ))
        },
    ))
    .map_err(|_| NarrowBlake3Error::BackendPanic)??;
    encode_native_proof_with_identity(proof, BRIDGE_PROOF_MAGIC, BRIDGE_PROOF_VERSION)
}

pub(crate) fn verify_bls_dory_narrow_blake3(
    statement: &BlsDoryOutputBridgeStatement,
    bytes: &[u8],
) -> Result<(), NarrowBlake3Error> {
    let air = BlsDoryNarrowBlake3Air::new(statement)?;
    let native = decompress_bridge_proof(bytes)?;
    let proof =
        decode_native_proof_with_identity(&native, BRIDGE_PROOF_MAGIC, BRIDGE_PROOF_VERSION)?;
    let config = build_config();
    let verifier_key = pinned_preprocessed_verifier_key(&air.base)?;
    let public = bridge_public_values(statement);
    catch_unwind(AssertUnwindSafe(|| {
        verify_with_preprocessed(&config, &air, &proof, &public, Some(&verifier_key))
    }))
    .map_err(|_| NarrowBlake3Error::BackendPanic)?
    .map_err(|_| NarrowBlake3Error::Verification)
}

fn compress_bridge_proof(native: &[u8]) -> Result<Vec<u8>, NarrowBlake3Error> {
    if native.len() > crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES {
        return Err(NarrowBlake3Error::Encoding);
    }
    let native_len = u32::try_from(native.len()).map_err(|_| NarrowBlake3Error::Encoding)?;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(native)
        .map_err(|_| NarrowBlake3Error::Encoding)?;
    let compressed = encoder.finish().map_err(|_| NarrowBlake3Error::Encoding)?;
    let mut encoded = Vec::with_capacity(BRIDGE_CODEC_HEADER_BYTES + compressed.len());
    encoded.extend_from_slice(BRIDGE_CODEC_MAGIC);
    encoded.extend_from_slice(&native_len.to_le_bytes());
    encoded.extend_from_slice(&compressed);
    if encoded.len() > crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES {
        return Err(NarrowBlake3Error::Encoding);
    }
    Ok(encoded)
}

fn decompress_bridge_proof(encoded: &[u8]) -> Result<Vec<u8>, NarrowBlake3Error> {
    if encoded.len() < BRIDGE_CODEC_HEADER_BYTES
        || encoded.len() > crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES
        || encoded.get(..8) != Some(BRIDGE_CODEC_MAGIC.as_slice())
    {
        return Err(NarrowBlake3Error::Encoding);
    }
    let expected_len = u32::from_le_bytes(
        encoded[8..12]
            .try_into()
            .map_err(|_| NarrowBlake3Error::Encoding)?,
    ) as usize;
    if expected_len > crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES {
        return Err(NarrowBlake3Error::Encoding);
    }
    let decoder = ZlibDecoder::new(&encoded[BRIDGE_CODEC_HEADER_BYTES..]);
    let mut bounded = decoder.take((crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES + 1) as u64);
    let mut native = Vec::with_capacity(expected_len);
    bounded
        .read_to_end(&mut native)
        .map_err(|_| NarrowBlake3Error::Encoding)?;
    if native.len() != expected_len || compress_bridge_proof(&native)? != encoded {
        return Err(NarrowBlake3Error::Encoding);
    }
    Ok(native)
}

fn constrain_bls_evaluation<AB: AirBuilder>(
    builder: &mut AB,
    local: &BridgeCols<AB::Var>,
    next: &BridgeCols<AB::Var>,
    point_variables: usize,
) {
    for nibbles in &local.accumulator_nibbles {
        constrain_nibbles(builder, nibbles);
    }
    constrain_nibbles(builder, &local.quotient_nibbles);
    for nibbles in &local.carry_nibbles {
        constrain_nibbles(builder, nibbles);
    }
    for limb in 0..LIMBS {
        builder.assert_eq(
            local.accumulator_limbs[limb],
            pack_nibbles::<AB>(&local.accumulator_nibbles[limb]),
        );
        builder
            .when_first_row()
            .assert_zero(local.accumulator_limbs[limb]);
    }

    let quotient = pack_nibbles::<AB>(&local.quotient_nibbles);
    let carries: [AB::Expr; CARRY_COUNT] = array::from_fn(|index| {
        pack_nibbles::<AB>(&local.carry_nibbles[index]) - AB::Expr::from_u16(CARRY_OFFSET as u16)
    });
    builder.assert_zero(carries[0].clone());
    builder.assert_zero(carries[CARRY_COUNT - 1].clone());

    let periodic = builder.periodic_values().to_vec();
    debug_assert_eq!(periodic.len(), BRIDGE_PERIODIC_WIDTH);
    let modulus = modulus_limbs();
    for limb in 0..LIMBS {
        let mut equation = AB::Expr::from(local.accumulator_limbs[limb]) + carries[limb].clone()
            - AB::Expr::from(next.accumulator_limbs[limb])
            - quotient.clone() * AB::Expr::from_u64(u64::from(modulus[limb]))
            - carries[limb + 1].clone() * AB::Expr::from_u64(LIMB_BASE);
        for byte in 0..BYTES_PER_EVAL_ROW {
            let weight: AB::Expr = periodic[byte * LIMBS + limb].into();
            equation += byte_expr::<AB>(&local.base.original_nibbles[byte]) * weight;
        }
        builder.when_transition().assert_zero(equation);
    }

    let evaluation_offset =
        HASH_PUBLIC_VALUES + TRANSCRIPT_BINDING_PUBLIC_VALUES + point_variables * LIMBS;
    let public = builder.public_values().to_vec();
    for limb in 0..LIMBS {
        builder.when_last_row().assert_eq(
            local.accumulator_limbs[limb],
            public[evaluation_offset + limb],
        );
    }
}

fn constrain_nibbles<AB: AirBuilder>(builder: &mut AB, nibbles: &[AB::Var]) {
    for nibble in nibbles {
        let value: AB::Expr = (*nibble).into();
        let mut range = AB::Expr::ONE;
        for allowed in 0..16 {
            range *= value.clone() - AB::Expr::from_u8(allowed);
        }
        builder.assert_zero(range);
    }
}

fn pack_nibbles<AB: AirBuilder>(nibbles: &[AB::Var]) -> AB::Expr {
    nibbles
        .iter()
        .enumerate()
        .fold(AB::Expr::ZERO, |sum, (index, nibble)| {
            sum + AB::Expr::from(*nibble) * AB::Expr::from_u64(1_u64 << (4 * index))
        })
}

fn generate_bridge_trace(
    air: &BlsDoryNarrowBlake3Air,
    statement: &BlsDoryOutputBridgeStatement,
    witness: &Blake3TreeWitness,
) -> Result<RowMajorMatrix<F>, NarrowBlake3Error> {
    let base_statement = base_statement(statement);
    let mut values = Vec::with_capacity(air.base.trace_rows * BRIDGE_WIDTH);
    let mut accumulator = [0_u32; LIMBS];
    for_each_main_trace_row(
        &air.base,
        &base_statement,
        witness,
        |row_index, base_values| -> Result<(), NarrowBlake3Error> {
            let base: &MainCols<F> = base_values.borrow();
            let bytes = array::from_fn(|byte| {
                let low = base.original_nibbles[byte][0].as_canonical_u64() as u8;
                let high = base.original_nibbles[byte][1].as_canonical_u64() as u8;
                low | (high << 4)
            });
            let weights = air.weights_at_row(row_index);
            let step = bridge_step(accumulator, bytes, weights)?;
            let offset = values.len();
            values.resize(offset + BRIDGE_WIDTH, F::ZERO);
            let row: &mut BridgeCols<F> = values[offset..].borrow_mut();
            row.base = *base;
            row.accumulator_limbs = accumulator.map(F::from_u32);
            row.accumulator_nibbles = accumulator
                .map(nibbles_32)
                .map(|digits| digits.map(F::from_u8));
            row.quotient_nibbles = nibbles_12(step.quotient).map(F::from_u8);
            row.carry_nibbles = step.carries.map(|carry| {
                nibbles_12(
                    u16::try_from(i64::from(carry) + CARRY_OFFSET)
                        .map_err(|_| NarrowBlake3Error::Opening)
                        .expect("validated bridge carry"),
                )
                .map(F::from_u8)
            });
            accumulator = step.next;
            Ok(())
        },
    )?;
    Ok(RowMajorMatrix::new(values, BRIDGE_WIDTH))
}

#[derive(Clone, Copy)]
struct BridgeStep {
    next: [u32; LIMBS],
    quotient: u16,
    carries: [i16; CARRY_COUNT],
}

fn bridge_step(
    current: [u32; LIMBS],
    bytes: [u8; BYTES_PER_EVAL_ROW],
    weights: [[u32; LIMBS]; BYTES_PER_EVAL_ROW],
) -> Result<BridgeStep, NarrowBlake3Error> {
    let modulus_limbs = modulus_limbs();
    let modulus = limbs_to_u512(modulus_limbs);
    let mut total = limbs_to_u512(current);
    for byte in 0..BYTES_PER_EVAL_ROW {
        total = total
            .checked_add(
                limbs_to_u512(weights[byte])
                    .checked_mul(U512::from(bytes[byte]))
                    .ok_or(NarrowBlake3Error::Opening)?,
            )
            .ok_or(NarrowBlake3Error::Opening)?;
    }
    let quotient = total / modulus;
    if quotient > U512::from(0x0fff_u16) {
        return Err(NarrowBlake3Error::Opening);
    }
    let next = u512_to_limbs(total % modulus)?;
    let quotient = quotient.low_u32() as u16;
    let mut carries = [0_i16; CARRY_COUNT];
    let mut carry = 0_i128;
    for limb in 0..LIMBS {
        let weighted = (0..BYTES_PER_EVAL_ROW).fold(0_i128, |sum, byte| {
            sum + i128::from(bytes[byte]) * i128::from(weights[byte][limb])
        });
        let numerator = i128::from(current[limb]) + weighted + carry
            - i128::from(next[limb])
            - i128::from(quotient) * i128::from(modulus_limbs[limb]);
        if numerator % i128::from(LIMB_BASE) != 0 {
            return Err(NarrowBlake3Error::Opening);
        }
        carry = numerator / i128::from(LIMB_BASE);
        if !(-CARRY_OFFSET..CARRY_OFFSET).contains(&(carry as i64)) {
            return Err(NarrowBlake3Error::Opening);
        }
        carries[limb + 1] = i16::try_from(carry).map_err(|_| NarrowBlake3Error::Opening)?;
    }
    if carry != 0 {
        return Err(NarrowBlake3Error::Opening);
    }
    Ok(BridgeStep {
        next,
        quotient,
        carries,
    })
}

fn activation_basis_weights(
    activation_len: usize,
    point: &[BlsDoryFr],
    message_offset: Option<usize>,
    step: usize,
) -> Option<[[u32; LIMBS]; BYTES_PER_EVAL_ROW]> {
    let activation_start = 40_usize;
    let activation_end = activation_start.checked_add(activation_len)?;
    let group_offset = message_offset?.checked_add(step.checked_mul(BYTES_PER_EVAL_ROW)?)?;
    let group_end = group_offset.checked_add(BYTES_PER_EVAL_ROW)?;
    if group_offset < activation_start || group_end > activation_end {
        return None;
    }
    let first_index = group_offset - activation_start;
    Some(array::from_fn(|byte| {
        let index = first_index + byte;
        let weight =
            point
                .iter()
                .enumerate()
                .fold(BlsDoryFr::one(), |weight, (variable, coordinate)| {
                    weight
                        * if (index >> variable) & 1 == 1 {
                            *coordinate
                        } else {
                            BlsDoryFr::one() - *coordinate
                        }
                });
        bls_dory_scalar_limbs(weight)
    }))
}

fn base_statement(statement: &BlsDoryOutputBridgeStatement) -> StructuredBlake3Statement {
    StructuredBlake3Statement {
        challenge_digest: statement.challenge_digest(),
        final_activation_len: statement.final_activation_len(),
        final_activation_digest: statement.final_activation_digest(),
        final_activation_point: vec![
            ExtensionElement { limbs: [0; 3] };
            statement.cell_point().len()
        ],
        final_activation_evaluation: ExtensionElement { limbs: [0; 3] },
    }
}

fn bridge_public_values(statement: &BlsDoryOutputBridgeStatement) -> Vec<F> {
    let mut values = Vec::with_capacity(
        HASH_PUBLIC_VALUES
            + TRANSCRIPT_BINDING_PUBLIC_VALUES
            + statement.cell_point().len() * LIMBS
            + LIMBS,
    );
    values.extend(statement.challenge_digest().into_iter().map(F::from_u8));
    values.extend(
        (statement.final_activation_len() as u64)
            .to_le_bytes()
            .into_iter()
            .map(F::from_u8),
    );
    values.extend(
        statement
            .final_activation_digest()
            .into_iter()
            .map(F::from_u8),
    );
    values.extend(statement.transcript_binding().into_iter().map(F::from_u8));
    for limbs in statement.point_limbs() {
        values.extend(limbs.map(F::from_u32));
    }
    values.extend(statement.raw_byte_evaluation_limbs().map(F::from_u32));
    values
}

fn modulus_limbs() -> [u32; LIMBS] {
    let mut bytes = Fr::MODULUS.to_bytes_le();
    bytes.resize(32, 0);
    array::from_fn(|limb| {
        let offset = limb * 4;
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("BLS12-381 scalar modulus has eight limbs"),
        )
    })
}

fn limbs_to_u512(limbs: [u32; LIMBS]) -> U512 {
    let mut bytes = [0_u8; 64];
    for (limb, value) in limbs.into_iter().enumerate() {
        bytes[limb * 4..limb * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    U512::from_little_endian(&bytes)
}

fn u512_to_limbs(value: U512) -> Result<[u32; LIMBS], NarrowBlake3Error> {
    let bytes = value.to_little_endian();
    if bytes[32..].iter().any(|byte| *byte != 0) {
        return Err(NarrowBlake3Error::Opening);
    }
    Ok(array::from_fn(|limb| {
        let offset = limb * 4;
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("U512 has complete 32-bit limbs"),
        )
    }))
}

fn nibbles_32(value: u32) -> [u8; LIMB_NIBBLES] {
    array::from_fn(|index| ((value >> (4 * index)) & 0x0f) as u8)
}

fn nibbles_12(value: u16) -> [u8; 3] {
    array::from_fn(|index| ((value >> (4 * index)) & 0x0f) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forgematrix_v2::output_digest;
    use p3_air::AirLayout;
    use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};

    fn statement(activation: &[u8], point: Vec<BlsDoryFr>) -> BlsDoryOutputBridgeStatement {
        let challenge = [0x39; 32];
        BlsDoryOutputBridgeStatement::from_test_parts(
            challenge,
            output_digest(challenge, activation),
            activation,
            [0x71; 32],
            point,
        )
        .unwrap()
    }

    fn point(variables: usize) -> Vec<BlsDoryFr> {
        (0..variables)
            .map(|index| BlsDoryFr::from_u64(3 + 2 * index as u64))
            .collect()
    }

    #[test]
    fn exact_limb_reduction_matches_bls_field_accumulation() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation, point(6));
        let air = BlsDoryNarrowBlake3Air::new(&statement).unwrap();
        let witness =
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest(), &activation).unwrap();
        let trace = generate_bridge_trace(&air, &statement, &witness).unwrap();
        let final_row = trace.row_slice(trace.height() - 1).unwrap();
        let final_cols: &BridgeCols<F> = final_row.as_ref().borrow();
        assert_eq!(
            final_cols
                .accumulator_limbs
                .map(|limb| limb.as_canonical_u64() as u32),
            statement.raw_byte_evaluation_limbs()
        );
    }

    #[test]
    fn bridge_air_accepts_the_honest_trace() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation, point(6));
        let air = BlsDoryNarrowBlake3Air::new(&statement).unwrap();
        let witness =
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest(), &activation).unwrap();
        let trace = generate_bridge_trace(&air, &statement, &witness).unwrap();
        p3_air::check_constraints(&air, &trace, &bridge_public_values(&statement));
    }

    #[test]
    fn bridge_proof_rejects_changed_dory_statement_and_codec() {
        let activation = (0..32).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let bridge_statement = statement(&activation, point(5));
        let proof = prove_bls_dory_narrow_blake3(&bridge_statement, &activation).unwrap();
        assert_eq!(
            BlsDoryNarrowBlake3Air::new(&bridge_statement)
                .unwrap()
                .base
                .trace_rows,
            256
        );
        assert_eq!(BRIDGE_WIDTH, 393);
        assert!(
            proof.len() <= 157_000,
            "compressed bridge proof is {} bytes",
            proof.len()
        );
        let native = decompress_bridge_proof(&proof).unwrap();
        assert!(
            native.len() <= 222_500,
            "native bridge proof exceeded its measured regression ceiling"
        );
        verify_bls_dory_narrow_blake3(&bridge_statement, &proof).unwrap();

        let changed_point = statement(&activation, point(5).into_iter().rev().collect());
        assert!(verify_bls_dory_narrow_blake3(&changed_point, &proof).is_err());
        let changed_binding = BlsDoryOutputBridgeStatement::from_test_parts(
            bridge_statement.challenge_digest(),
            bridge_statement.final_activation_digest(),
            &activation,
            [0x72; 32],
            bridge_statement.cell_point().to_vec(),
        )
        .unwrap();
        assert!(verify_bls_dory_narrow_blake3(&changed_binding, &proof).is_err());
        assert!(
            verify_bls_dory_narrow_blake3(&bridge_statement, &proof[..proof.len() - 1]).is_err()
        );
        let mut wrong_magic = proof.clone();
        wrong_magic[0] ^= 1;
        assert!(verify_bls_dory_narrow_blake3(&bridge_statement, &wrong_magic).is_err());
        let mut wrong_length = proof.clone();
        wrong_length[8] ^= 1;
        assert!(verify_bls_dory_narrow_blake3(&bridge_statement, &wrong_length).is_err());
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(verify_bls_dory_narrow_blake3(&bridge_statement, &trailing).is_err());
        let mut noncanonical_encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        noncanonical_encoder.write_all(&native).unwrap();
        let mut noncanonical = Vec::new();
        noncanonical.extend_from_slice(BRIDGE_CODEC_MAGIC);
        noncanonical.extend_from_slice(&u32::try_from(native.len()).unwrap().to_le_bytes());
        noncanonical.extend_from_slice(&noncanonical_encoder.finish().unwrap());
        assert_ne!(noncanonical, proof);
        assert!(verify_bls_dory_narrow_blake3(&bridge_statement, &noncanonical).is_err());

        let mut bomb_encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        bomb_encoder
            .write_all(&vec![0; crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES + 1])
            .unwrap();
        let mut expansion_bomb = Vec::new();
        expansion_bomb.extend_from_slice(BRIDGE_CODEC_MAGIC);
        expansion_bomb.extend_from_slice(
            &u32::try_from(crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES)
                .unwrap()
                .to_le_bytes(),
        );
        expansion_bomb.extend_from_slice(&bomb_encoder.finish().unwrap());
        assert!(decompress_bridge_proof(&expansion_bomb).is_err());

        let mut changed_activation = activation;
        changed_activation[9] ^= 1;
        assert!(prove_bls_dory_narrow_blake3(&bridge_statement, &changed_activation).is_err());
    }

    #[test]
    #[ignore = "proof-size and soundness parameter measurement"]
    fn bridge_query_size_and_soundness_measurement() {
        use std::{io::Write, time::Instant};

        fn proven_security(
            air: &BlsDoryNarrowBlake3Air,
            log_blowup: usize,
            queries: usize,
            query_pow_bits: usize,
        ) -> ProvenSecurity {
            let perm = default_poseidon2();
            let val = ValMmcs::new(FieldHash::new(perm.clone()), Compress::new(perm), 0);
            let mut fri = fri_parameters_with(log_blowup, queries, ChallengeMmcs::new(val));
            fri.query_proof_of_work_bits = query_pow_bits;
            let params = StarkSecurityParams::from_air::<F, EF, _, _>(
                &fri,
                air,
                AirLayout::from_air::<F>(air),
                192,
                128,
                2,
            );
            ProvenSecurity::compute(&params, air.base.trace_rows)
        }

        let activation = (0..32).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let bridge_statement = statement(&activation, point(5));

        let production_activation = vec![0_u8; 1 << 19];
        let production_statement = statement(&production_activation, point(19));
        let production_air = BlsDoryNarrowBlake3Air::new(&production_statement).unwrap();
        assert_eq!(production_air.base.trace_rows, 1 << 20);

        let mut margin_candidates = Vec::new();
        for log_blowup in [7, 8, 9, 10] {
            let minimum_queries = (1..=FRI_QUERIES)
                .find(|queries| {
                    proven_security(&production_air, log_blowup, *queries, FRI_QUERY_POW_BITS)
                        .security_bits()
                        >= 128
                })
                .unwrap();
            eprintln!(
                "kind=bls-bridge-security log_blowup={log_blowup} query_pow_bits={} minimum_queries={minimum_queries}",
                FRI_QUERY_POW_BITS
            );
            margin_candidates.push((log_blowup, minimum_queries + 1));
        }

        for (log_blowup, queries) in margin_candidates {
            let required_pow_bits = (0..=64)
                .find(|query_pow_bits| {
                    proven_security(&production_air, log_blowup, queries, *query_pow_bits)
                        .security_bits()
                        >= 128
                })
                .unwrap();
            let security =
                proven_security(&production_air, log_blowup, queries, FRI_QUERY_POW_BITS);
            let config = build_config_with_dft_and_fri(NarrowDft::default(), log_blowup, queries);
            let started = Instant::now();
            let proof = prove_bls_dory_narrow_blake3_with_config(
                &bridge_statement,
                &activation,
                &config,
                false,
            )
            .unwrap();
            let prove_ms = started.elapsed().as_millis();
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
            encoder.write_all(&proof).unwrap();
            let compressed = encoder.finish().unwrap();
            eprintln!(
                "kind=bls-bridge-query-size log_blowup={log_blowup} queries={queries} configured_query_pow_bits={} minimum_query_pow_bits={required_pow_bits} proven_bits={} native_bytes={} zlib_bytes={} prove_ms={prove_ms}",
                FRI_QUERY_POW_BITS,
                security.security_bits(),
                proof.len(),
                compressed.len(),
            );
        }
    }
}
