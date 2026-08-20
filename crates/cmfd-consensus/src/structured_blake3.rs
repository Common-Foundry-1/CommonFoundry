//! BLAKE3 argument for the structured ForgeMatrix proof.
//!
//! This research component proves the exact derive-key BLAKE3 compression used
//! by `forgematrix_v2::output_digest` without carrying the final activation
//! bytes in the aggregate envelope. The private activation bytes are linked to
//! the authenticated last-layer table through its cubic-Goldilocks MLE value.
//!
//! Small messages use the upstream one-row Plonky3 AIR. Larger power-of-two
//! activation tables use the narrow multi-row tree AIR, which authenticates
//! every chunk compression, parent compression, final digest, and final-table
//! multilinear opening.

use std::{
    array,
    borrow::{Borrow, BorrowMut},
    io::{Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
};

use bincode::Options;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use p3_air::utils::{pack_bits_le, u32_to_bits_le};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_blake3::Blake3;
use p3_blake3_air::{Blake3Air, Blake3Cols, Blake3State, FullRound, NUM_BLAKE3_COLS};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::CubicTrinomialExtensionField;
use p3_field::integers::QuotientMap;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};
use thiserror::Error;

use crate::{
    GOLDILOCKS_MODULUS, StructuredBlake3Statement, StructuredBlake3Verifier,
    forgematrix_v2::output_digest,
    structured_blake3_narrow::{NarrowBlake3Error, prove_narrow_blake3, verify_narrow_blake3},
};

pub const STRUCTURED_BLAKE3_VERSION: u32 = 2;

const PROOF_MAGIC: &[u8; 8] = b"CMFDB3S2";
const BACKEND_ONE_BLOCK: u8 = 0;
const BACKEND_TREE: u8 = 1;
const MAX_COMPRESSED_TREE_PROOF_BYTES: usize = 256 * 1024;
const PROOF_TRANSCRIPT_DOMAIN: &str = "CMFD/FORGEMATRIX/BLAKE3-STARK/V1";
const OUTPUT_CONTEXT: &str = "CMFD/FORGEMATRIX/OUTPUT/V2";
const BLOCK_BYTES: usize = 64;
const PUBLIC_PREFIX_BYTES: usize = 40;
const MAX_ONE_BLOCK_ACTIVATION_BYTES: usize = BLOCK_BYTES - PUBLIC_PREFIX_BYTES;
const TRACE_ROWS: usize = 8;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const ROOT: u32 = 1 << 3;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;
const OUTPUT_FLAGS: u32 = CHUNK_START | CHUNK_END | ROOT | DERIVE_KEY_MATERIAL;

const CHALLENGE_OFFSET: usize = 32;
const LENGTH_OFFSET: usize = 64;
const DIGEST_OFFSET: usize = 72;
const POINT_OFFSET: usize = 104;

const FRI_LOG_BLOWUP: usize = 7;
const FRI_QUERIES: usize = 40;
const FRI_QUERY_POW_BITS: usize = 8;
#[cfg(test)]
const REQUIRED_PROVEN_SECURITY_BITS: usize = 128;

type F = Goldilocks;
type EF = CubicTrinomialExtensionField<F>;
type FieldHash = SerializingHasher<Blake3>;
type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
type ValMmcs = MerkleTreeMmcs<<F as Field>::Packing, u8, FieldHash, Compress, 2, 32>;
type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;
type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3, 32>>;
type Dft = Radix2DitParallel<F>;
type Pcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, EF, Challenger>;
type NativeProof = Proof<Config>;

#[derive(Debug, Default, Clone, Copy)]
pub struct StructuredBlake3StarkVerifier;

impl StructuredBlake3Verifier for StructuredBlake3StarkVerifier {
    fn verify_argument(&self, statement: &StructuredBlake3Statement, proof: &[u8]) -> bool {
        verify_structured_blake3(statement, proof).is_ok()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StructuredBlake3Error {
    #[error(
        "BLAKE3 argument requires a nonempty power-of-two activation table of at most 524288 bytes"
    )]
    UnsupportedShape,
    #[error("BLAKE3 argument activation is not canonically encoded in 0..=250")]
    ActivationEncoding,
    #[error("BLAKE3 argument statement contains a noncanonical Goldilocks element")]
    NonCanonicalField,
    #[error("BLAKE3 argument activation does not match the authenticated final-table opening")]
    ActivationOpening,
    #[error("BLAKE3 argument digest does not match the private activation")]
    Digest,
    #[error("BLAKE3 argument proof exceeds its byte cap")]
    ProofTooLarge,
    #[error("BLAKE3 argument encoding is malformed, noncanonical, or has trailing bytes")]
    InvalidEncoding,
    #[error("BLAKE3 STARK verifier rejected the proof")]
    Verification,
    #[error("BLAKE3 STARK backend panicked while handling proof data")]
    BackendPanic,
}

impl From<NarrowBlake3Error> for StructuredBlake3Error {
    fn from(error: NarrowBlake3Error) -> Self {
        match error {
            NarrowBlake3Error::UnsupportedShape => Self::UnsupportedShape,
            NarrowBlake3Error::NonCanonicalField => Self::NonCanonicalField,
            NarrowBlake3Error::Tree(_) => Self::Digest,
            NarrowBlake3Error::Opening => Self::ActivationOpening,
            NarrowBlake3Error::Encoding => Self::InvalidEncoding,
            NarrowBlake3Error::Verification => Self::Verification,
            NarrowBlake3Error::BackendPanic => Self::BackendPanic,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BoundBlake3Air {
    activation_len: usize,
    point_variables: usize,
}

impl BoundBlake3Air {
    fn new(statement: &StructuredBlake3Statement) -> Result<Self, StructuredBlake3Error> {
        validate_statement(statement)?;
        Ok(Self {
            activation_len: statement.final_activation_len,
            point_variables: statement.final_activation_point.len(),
        })
    }

    const fn evaluation_offset(self) -> usize {
        POINT_OFFSET + 3 * self.point_variables
    }
}

impl<T> BaseAir<T> for BoundBlake3Air {
    fn width(&self) -> usize {
        NUM_BLAKE3_COLS
    }

    fn num_public_values(&self) -> usize {
        self.evaluation_offset() + 3
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(self.point_variables + 2)
    }
}

impl<AB: AirBuilder> Air<AB> for BoundBlake3Air {
    fn eval(&self, builder: &mut AB) {
        Blake3Air {}.eval(builder);

        let main = builder.main();
        let local: &Blake3Cols<AB::Var> = main.current_slice().borrow();
        let public = builder.public_values().to_vec();
        let mut first = builder.when_first_row();

        for byte_index in 0..32 {
            first.assert_eq(
                input_byte::<AB>(local, byte_index),
                public[CHALLENGE_OFFSET + byte_index],
            );
        }
        for byte_index in 0..8 {
            first.assert_eq(
                input_byte::<AB>(local, 32 + byte_index),
                public[LENGTH_OFFSET + byte_index],
            );
        }
        for byte_index in PUBLIC_PREFIX_BYTES + self.activation_len..BLOCK_BYTES {
            first.assert_zero(input_byte::<AB>(local, byte_index));
        }

        let context_key = blake3::hazmat::hash_derive_key_context(OUTPUT_CONTEXT);
        for word_index in 0..8 {
            let word = u32::from_le_bytes(
                context_key[word_index * 4..(word_index + 1) * 4]
                    .try_into()
                    .expect("four-byte context-key word"),
            );
            let bits = &local.chaining_values[word_index / 4][word_index % 4];
            first.assert_eq(
                pack_bits_le(bits[..16].iter().copied()),
                AB::Expr::from_u16(word as u16),
            );
            first.assert_eq(
                pack_bits_le(bits[16..].iter().copied()),
                AB::Expr::from_u16((word >> 16) as u16),
            );
        }
        assert_word_constant::<AB>(&mut first, &local.counter_low, 0);
        assert_word_constant::<AB>(&mut first, &local.counter_hi, 0);
        assert_word_constant::<AB>(
            &mut first,
            &local.block_len,
            (PUBLIC_PREFIX_BYTES + self.activation_len) as u32,
        );
        assert_word_constant::<AB>(&mut first, &local.flags, OUTPUT_FLAGS);

        for byte_index in 0..32 {
            first.assert_eq(
                output_byte::<AB>(local, byte_index),
                public[DIGEST_OFFSET + byte_index],
            );
        }

        let point = (0..self.point_variables)
            .map(|index| {
                let offset = POINT_OFFSET + 3 * index;
                ExtExpr([
                    public[offset].into(),
                    public[offset + 1].into(),
                    public[offset + 2].into(),
                ])
            })
            .collect::<Vec<_>>();
        let mut table = (0..self.activation_len)
            .map(|index| {
                ExtExpr([
                    input_byte::<AB>(local, PUBLIC_PREFIX_BYTES + index) - AB::Expr::from_u8(125),
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                ])
            })
            .collect::<Vec<_>>();
        for coordinate in point {
            table = table
                .chunks_exact(2)
                .map(|pair| {
                    pair[0].clone() + (pair[1].clone() - pair[0].clone()) * coordinate.clone()
                })
                .collect();
        }
        let evaluation = &table[0].0;
        let evaluation_offset = self.evaluation_offset();
        for limb in 0..3 {
            first.assert_eq(evaluation[limb].clone(), public[evaluation_offset + limb]);
        }
    }
}

#[derive(Clone)]
struct ExtExpr<E>([E; 3]);

impl<E> std::ops::Add for ExtExpr<E>
where
    E: Clone + std::ops::Add<Output = E>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(array::from_fn(|index| {
            self.0[index].clone() + rhs.0[index].clone()
        }))
    }
}

impl<E> std::ops::Sub for ExtExpr<E>
where
    E: Clone + std::ops::Sub<Output = E>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(array::from_fn(|index| {
            self.0[index].clone() - rhs.0[index].clone()
        }))
    }
}

impl<E> std::ops::Mul for ExtExpr<E>
where
    E: Clone + std::ops::Add<Output = E> + std::ops::Mul<Output = E>,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let cross_three = a[1].clone() * b[2].clone() + a[2].clone() * b[1].clone();
        let degree_four = a[2].clone() * b[2].clone();
        Self([
            a[0].clone() * b[0].clone() + cross_three.clone(),
            a[0].clone() * b[1].clone()
                + a[1].clone() * b[0].clone()
                + cross_three
                + degree_four.clone(),
            a[0].clone() * b[2].clone()
                + a[1].clone() * b[1].clone()
                + a[2].clone() * b[0].clone()
                + degree_four,
        ])
    }
}

pub fn prove_structured_blake3(
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
) -> Result<Vec<u8>, StructuredBlake3Error> {
    if statement.final_activation_len > MAX_ONE_BLOCK_ACTIVATION_BYTES {
        let backend = BACKEND_TREE;
        let payload = prove_narrow_blake3(statement, final_activation)?;
        let compressed = compress_tree_proof(&payload)?;
        if 17 + compressed.len() > MAX_COMPRESSED_TREE_PROOF_BYTES {
            return Err(StructuredBlake3Error::ProofTooLarge);
        }
        return encode_proof(backend, &compressed);
    }
    let air = BoundBlake3Air::new(statement)?;
    validate_activation(statement, final_activation)?;
    if output_digest(statement.challenge_digest, final_activation)
        != statement.final_activation_digest
    {
        return Err(StructuredBlake3Error::Digest);
    }
    validate_opening(statement, final_activation)?;

    let trace = generate_trace(statement.challenge_digest, final_activation);
    let public_values = public_values(statement)?;
    let config = build_config();
    let proof = catch_unwind(AssertUnwindSafe(|| {
        prove(&config, &air, trace, &public_values)
    }))
    .map_err(|_| StructuredBlake3Error::BackendPanic)?;
    let native = bincode_options()
        .serialize(&proof)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
    encode_proof(BACKEND_ONE_BLOCK, &native)
}

pub fn verify_structured_blake3(
    statement: &StructuredBlake3Statement,
    encoded: &[u8],
) -> Result<(), StructuredBlake3Error> {
    let (backend, native) = decode_proof(encoded)?;
    if backend == BACKEND_TREE {
        if statement.final_activation_len <= MAX_ONE_BLOCK_ACTIVATION_BYTES {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
        if encoded.len() > MAX_COMPRESSED_TREE_PROOF_BYTES {
            return Err(StructuredBlake3Error::ProofTooLarge);
        }
        let decompressed = decompress_tree_proof(native)?;
        return verify_narrow_blake3(statement, &decompressed).map_err(Into::into);
    }
    if backend != BACKEND_ONE_BLOCK
        || statement.final_activation_len > MAX_ONE_BLOCK_ACTIVATION_BYTES
    {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    let air = BoundBlake3Air::new(statement)?;
    let proof: NativeProof = bincode_options()
        .deserialize(native)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
    let canonical = bincode_options()
        .serialize(&proof)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
    if canonical != native {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    let public_values = public_values(statement)?;
    let config = build_config();
    catch_unwind(AssertUnwindSafe(|| {
        verify(&config, &air, &proof, &public_values)
    }))
    .map_err(|_| StructuredBlake3Error::BackendPanic)?
    .map_err(|_| StructuredBlake3Error::Verification)
}

fn validate_statement(statement: &StructuredBlake3Statement) -> Result<(), StructuredBlake3Error> {
    let len = statement.final_activation_len;
    if len == 0
        || len > MAX_ONE_BLOCK_ACTIVATION_BYTES
        || !len.is_power_of_two()
        || statement.final_activation_point.len() != len.ilog2() as usize
    {
        return Err(StructuredBlake3Error::UnsupportedShape);
    }
    for value in statement
        .final_activation_point
        .iter()
        .chain(std::iter::once(&statement.final_activation_evaluation))
    {
        if value.limbs.iter().any(|limb| *limb >= GOLDILOCKS_MODULUS) {
            return Err(StructuredBlake3Error::NonCanonicalField);
        }
    }
    Ok(())
}

fn validate_activation(
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
) -> Result<(), StructuredBlake3Error> {
    if final_activation.len() != statement.final_activation_len {
        return Err(StructuredBlake3Error::UnsupportedShape);
    }
    if final_activation.iter().any(|value| *value > 250) {
        return Err(StructuredBlake3Error::ActivationEncoding);
    }
    Ok(())
}

fn validate_opening(
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
) -> Result<(), StructuredBlake3Error> {
    let point = statement
        .final_activation_point
        .iter()
        .copied()
        .map(crate::ExtensionElement::to_field)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StructuredBlake3Error::NonCanonicalField)?;
    let table = final_activation
        .iter()
        .map(|value| {
            crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*value) - 125)
        })
        .collect::<Vec<_>>();
    let evaluation = crate::structured_sumcheck::evaluate_mle(&table, &point);
    if crate::ExtensionElement::from_field(evaluation) != statement.final_activation_evaluation {
        return Err(StructuredBlake3Error::ActivationOpening);
    }
    Ok(())
}

fn public_values(statement: &StructuredBlake3Statement) -> Result<Vec<F>, StructuredBlake3Error> {
    validate_statement(statement)?;
    let mut values =
        Vec::with_capacity(POINT_OFFSET + 3 * statement.final_activation_point.len() + 3);
    values.extend(
        blake3::derive_key(PROOF_TRANSCRIPT_DOMAIN, b"")
            .into_iter()
            .map(F::from_u8),
    );
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
    for coordinate in &statement.final_activation_point {
        for limb in coordinate.limbs {
            values.push(canonical_field(limb)?);
        }
    }
    for limb in statement.final_activation_evaluation.limbs {
        values.push(canonical_field(limb)?);
    }
    Ok(values)
}

fn canonical_field(value: u64) -> Result<F, StructuredBlake3Error> {
    F::from_canonical_checked(value).ok_or(StructuredBlake3Error::NonCanonicalField)
}

fn build_config() -> Config {
    let byte_hash = Blake3 {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = fri_parameters(challenge_mmcs);
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::new(HashChallenger::new(Vec::new(), byte_hash));
    Config::new(pcs, challenger)
}

fn fri_parameters(mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup: FRI_LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: FRI_QUERIES,
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

fn encode_proof(backend: u8, native: &[u8]) -> Result<Vec<u8>, StructuredBlake3Error> {
    let length = u32::try_from(native.len()).map_err(|_| StructuredBlake3Error::ProofTooLarge)?;
    let mut encoded = Vec::with_capacity(17 + native.len());
    encoded.extend_from_slice(PROOF_MAGIC);
    encoded.extend_from_slice(&STRUCTURED_BLAKE3_VERSION.to_le_bytes());
    encoded.push(backend);
    encoded.extend_from_slice(&length.to_le_bytes());
    encoded.extend_from_slice(native);
    if encoded.len() > crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES {
        return Err(StructuredBlake3Error::ProofTooLarge);
    }
    Ok(encoded)
}

fn decode_proof(encoded: &[u8]) -> Result<(u8, &[u8]), StructuredBlake3Error> {
    if encoded.len() < 17 || encoded.len() > crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES {
        return Err(StructuredBlake3Error::ProofTooLarge);
    }
    if encoded.get(..8) != Some(PROOF_MAGIC.as_slice()) {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    let version = u32::from_le_bytes(
        encoded[8..12]
            .try_into()
            .map_err(|_| StructuredBlake3Error::InvalidEncoding)?,
    );
    if version != STRUCTURED_BLAKE3_VERSION {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    let length = u32::from_le_bytes(
        encoded[13..17]
            .try_into()
            .map_err(|_| StructuredBlake3Error::InvalidEncoding)?,
    ) as usize;
    if 17usize.checked_add(length) != Some(encoded.len()) {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    Ok((encoded[12], &encoded[17..]))
}

fn compress_tree_proof(native: &[u8]) -> Result<Vec<u8>, StructuredBlake3Error> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(native)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
    encoder
        .finish()
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)
}

fn decompress_tree_proof(encoded: &[u8]) -> Result<Vec<u8>, StructuredBlake3Error> {
    let decoder = ZlibDecoder::new(encoded);
    let mut bounded = decoder.take((crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES + 1) as u64);
    let mut native = Vec::new();
    bounded
        .read_to_end(&mut native)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
    if native.len() > crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES
        || compress_tree_proof(&native)? != encoded
    {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    Ok(native)
}

fn input_byte<AB: AirBuilder>(local: &Blake3Cols<AB::Var>, index: usize) -> AB::Expr {
    let word = index / 4;
    let bit = (index % 4) * 8;
    pack_bits_le(local.inputs[word][bit..bit + 8].iter().copied())
}

fn output_byte<AB: AirBuilder>(local: &Blake3Cols<AB::Var>, index: usize) -> AB::Expr {
    let word = index / 4;
    let bit = (index % 4) * 8;
    let state_row = word / 4;
    let state_col = word % 4;
    pack_bits_le(
        local.outputs[state_row][state_col][bit..bit + 8]
            .iter()
            .copied(),
    )
}

fn assert_word_constant<AB: AirBuilder>(
    builder: &mut impl AirBuilder<Expr = AB::Expr, Var = AB::Var, F = AB::F>,
    bits: &[AB::Var; 32],
    value: u32,
) {
    builder.assert_eq(
        pack_bits_le(bits[..16].iter().copied()),
        AB::Expr::from_u16(value as u16),
    );
    builder.assert_eq(
        pack_bits_le(bits[16..].iter().copied()),
        AB::Expr::from_u16((value >> 16) as u16),
    );
}

fn generate_trace(challenge: [u8; 32], final_activation: &[u8]) -> RowMajorMatrix<F> {
    let mut block = [0_u8; BLOCK_BYTES];
    block[..32].copy_from_slice(&challenge);
    block[32..40].copy_from_slice(&(final_activation.len() as u64).to_le_bytes());
    block[40..40 + final_activation.len()].copy_from_slice(final_activation);
    let block_words = array::from_fn(|index| {
        u32::from_le_bytes(block[index * 4..(index + 1) * 4].try_into().expect("word"))
    });
    let context_key = blake3::hazmat::hash_derive_key_context(OUTPUT_CONTEXT);
    let chaining_value = array::from_fn(|index| {
        u32::from_le_bytes(
            context_key[index * 4..(index + 1) * 4]
                .try_into()
                .expect("context word"),
        )
    });

    let mut values = F::zero_vec(TRACE_ROWS * NUM_BLAKE3_COLS);
    for row_values in values.chunks_exact_mut(NUM_BLAKE3_COLS) {
        let row: &mut Blake3Cols<F> = row_values.borrow_mut();
        generate_trace_row(
            row,
            block_words,
            chaining_value,
            (PUBLIC_PREFIX_BYTES + final_activation.len()) as u32,
            OUTPUT_FLAGS,
        );
    }
    RowMajorMatrix::new(values, NUM_BLAKE3_COLS)
}

// The compression trace population below is adapted from p3-blake3-air 0.6.3
// (Plonky3, MIT OR Apache-2.0). It is kept local because the upstream public
// generator fixes block metadata that does not match BLAKE3 derive-key output.
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

fn generate_trace_row<R: PrimeCharacteristicRing>(
    row: &mut Blake3Cols<R>,
    block_words: [u32; 16],
    chaining_value: [u32; 8],
    block_len: u32,
    flags: u32,
) {
    row.inputs = block_words.map(u32_to_bits_le);
    row.chaining_values = array::from_fn(|half| {
        array::from_fn(|word| u32_to_bits_le(chaining_value[half * 4 + word]))
    });
    row.counter_low = u32_to_bits_le(0);
    row.counter_hi = u32_to_bits_le(0);
    row.block_len = u32_to_bits_le(block_len);
    row.flags = u32_to_bits_le(flags);
    row.initial_row0 = array::from_fn(|index| {
        [
            R::from_u16(chaining_value[index] as u16),
            R::from_u16((chaining_value[index] >> 16) as u16),
        ]
    });
    row.initial_row2 = array::from_fn(|index| {
        [
            R::from_u16(IV[index] as u16),
            R::from_u16((IV[index] >> 16) as u16),
        ]
    });

    let mut message = block_words;
    let mut state = [
        [
            chaining_value[0],
            chaining_value[1],
            chaining_value[2],
            chaining_value[3],
        ],
        [
            chaining_value[4],
            chaining_value[5],
            chaining_value[6],
            chaining_value[7],
        ],
        [IV[0], IV[1], IV[2], IV[3]],
        [0, 0, block_len, flags],
    ];
    for round in &mut row.full_rounds {
        generate_round(round, &mut state, &message);
        message = array::from_fn(|index| message[MSG_PERMUTATION[index]]);
    }
    row.final_round_helpers = array::from_fn(|index| u32_to_bits_le(state[2][index]));
    row.outputs[0] = array::from_fn(|index| u32_to_bits_le(state[0][index] ^ state[2][index]));
    row.outputs[1] = array::from_fn(|index| u32_to_bits_le(state[1][index] ^ state[3][index]));
    row.outputs[2] =
        array::from_fn(|index| u32_to_bits_le(state[2][index] ^ chaining_value[index]));
    row.outputs[3] =
        array::from_fn(|index| u32_to_bits_le(state[3][index] ^ chaining_value[4 + index]));
}

fn generate_round<R: PrimeCharacteristicRing>(
    round: &mut FullRound<R>,
    state: &mut [[u32; 4]; 4],
    message: &[u32; 16],
) {
    for index in 0..4 {
        (
            state[0][index],
            state[1][index],
            state[2][index],
            state[3][index],
        ) = half_round(
            state[0][index],
            state[1][index],
            state[2][index],
            state[3][index],
            message[2 * index],
            false,
        );
    }
    save_state(&mut round.state_prime, state);
    for index in 0..4 {
        (
            state[0][index],
            state[1][index],
            state[2][index],
            state[3][index],
        ) = half_round(
            state[0][index],
            state[1][index],
            state[2][index],
            state[3][index],
            message[2 * index + 1],
            true,
        );
    }
    save_state(&mut round.state_middle, state);
    for index in 0..4 {
        (
            state[0][index],
            state[1][(index + 1) % 4],
            state[2][(index + 2) % 4],
            state[3][(index + 3) % 4],
        ) = half_round(
            state[0][index],
            state[1][(index + 1) % 4],
            state[2][(index + 2) % 4],
            state[3][(index + 3) % 4],
            message[8 + 2 * index],
            false,
        );
    }
    save_state(&mut round.state_middle_prime, state);
    for index in 0..4 {
        (
            state[0][index],
            state[1][(index + 1) % 4],
            state[2][(index + 2) % 4],
            state[3][(index + 3) % 4],
        ) = half_round(
            state[0][index],
            state[1][(index + 1) % 4],
            state[2][(index + 2) % 4],
            state[3][(index + 3) % 4],
            message[9 + 2 * index],
            true,
        );
    }
    save_state(&mut round.state_output, state);
}

fn half_round(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    message: u32,
    second: bool,
) -> (u32, u32, u32, u32) {
    let (first_rotation, second_rotation) = if second { (8, 7) } else { (16, 12) };
    a = a.wrapping_add(b).wrapping_add(message);
    d = (d ^ a).rotate_right(first_rotation);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(second_rotation);
    (a, b, c, d)
}

fn save_state<R: PrimeCharacteristicRing>(trace: &mut Blake3State<R>, state: &[[u32; 4]; 4]) {
    trace.row0 = array::from_fn(|index| {
        [
            R::from_u16(state[0][index] as u16),
            R::from_u16((state[0][index] >> 16) as u16),
        ]
    });
    trace.row1 = array::from_fn(|index| u32_to_bits_le(state[1][index]));
    trace.row2 = array::from_fn(|index| {
        [
            R::from_u16(state[2][index] as u16),
            R::from_u16((state[2][index] >> 16) as u16),
        ]
    });
    trace.row3 = array::from_fn(|index| u32_to_bits_le(state[3][index]));
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::AirLayout;
    use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};

    fn statement(final_activation: &[u8]) -> StructuredBlake3Statement {
        let challenge = [0x42; 32];
        let point = (0..final_activation.len().ilog2())
            .map(|index| crate::ExtensionElement {
                limbs: [
                    3 * u64::from(index) + 3,
                    3 * u64::from(index) + 4,
                    3 * u64::from(index) + 5,
                ],
            })
            .collect::<Vec<_>>();
        let native_point = point
            .iter()
            .copied()
            .map(crate::ExtensionElement::to_field)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let table = final_activation
            .iter()
            .map(|value| {
                crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*value) - 125)
            })
            .collect::<Vec<_>>();
        StructuredBlake3Statement {
            challenge_digest: challenge,
            final_activation_len: final_activation.len(),
            final_activation_digest: output_digest(challenge, final_activation),
            final_activation_point: point,
            final_activation_evaluation: crate::ExtensionElement::from_field(
                crate::structured_sumcheck::evaluate_mle(&table, &native_point),
            ),
        }
    }

    #[test]
    fn one_block_argument_round_trips_and_rejects_mutations() {
        let activation = [1, 2, 3, 4, 200, 210, 220, 230];
        let statement = statement(&activation);
        let proof = prove_structured_blake3(&statement, &activation).unwrap();
        assert_eq!(proof.len(), 3_223_046);
        verify_structured_blake3(&statement, &proof).unwrap();

        let mut wrong_digest = statement.clone();
        wrong_digest.final_activation_digest[0] ^= 1;
        assert!(verify_structured_blake3(&wrong_digest, &proof).is_err());

        let mut wrong_opening = statement.clone();
        wrong_opening.final_activation_evaluation.limbs[0] ^= 1;
        assert!(verify_structured_blake3(&wrong_opening, &proof).is_err());

        let mut tampered = proof.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(verify_structured_blake3(&statement, &tampered).is_err());

        for length in [0, 1, 8, 15, proof.len() - 1] {
            assert!(verify_structured_blake3(&statement, &proof[..length]).is_err());
        }
        let stride = (proof.len() / 16).max(1);
        for index in (0..proof.len()).step_by(stride) {
            let mut mutation = proof.clone();
            mutation[index] ^= 0x80;
            let result = catch_unwind(AssertUnwindSafe(|| {
                verify_structured_blake3(&statement, &mutation)
            }));
            assert!(result.is_ok(), "verifier panicked for mutation at {index}");
            assert!(result.unwrap().is_err());
        }
        assert_eq!(
            verify_structured_blake3(
                &statement,
                &vec![0; crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES + 1],
            ),
            Err(StructuredBlake3Error::ProofTooLarge)
        );
    }

    #[test]
    fn wrong_private_activation_and_tree_shapes_fail_closed() {
        let activation = [1, 2, 3, 4, 5, 6, 7, 8];
        let statement = statement(&activation);
        let mut wrong = activation;
        wrong[0] ^= 1;
        assert_eq!(
            prove_structured_blake3(&statement, &wrong),
            Err(StructuredBlake3Error::Digest)
        );
        let mut noncanonical = activation;
        noncanonical[0] = 251;
        assert_eq!(
            prove_structured_blake3(&statement, &noncanonical),
            Err(StructuredBlake3Error::ActivationEncoding)
        );

        let mut production = statement;
        production.final_activation_len = 1 << 19;
        production.final_activation_point = vec![crate::ExtensionElement { limbs: [1, 0, 0] }; 19];
        assert_eq!(
            verify_structured_blake3(&production, &[0; 16]),
            Err(StructuredBlake3Error::ProofTooLarge)
        );
    }

    #[test]
    fn multi_block_tree_argument_uses_the_canonical_envelope() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let proof = prove_structured_blake3(&statement, &activation).unwrap();
        assert!(proof.len() < MAX_COMPRESSED_TREE_PROOF_BYTES);
        assert_eq!(proof[12], BACKEND_TREE);
        verify_structured_blake3(&statement, &proof).unwrap();

        let mut wrong_digest = statement.clone();
        wrong_digest.final_activation_digest[0] ^= 1;
        assert!(verify_structured_blake3(&wrong_digest, &proof).is_err());

        for index in [0, 8, 12, 17, proof.len() / 2, proof.len() - 1] {
            let mut mutated = proof.clone();
            mutated[index] ^= 0x80;
            let result = catch_unwind(AssertUnwindSafe(|| {
                verify_structured_blake3(&statement, &mutated)
            }));
            assert!(
                result.is_ok(),
                "tree verifier panicked for mutation at {index}"
            );
            assert!(result.unwrap().is_err());
        }
        for length in [0, 16, proof.len() - 1] {
            assert!(verify_structured_blake3(&statement, &proof[..length]).is_err());
        }
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(verify_structured_blake3(&statement, &trailing).is_err());

        let (_, compressed) = decode_proof(&proof).unwrap();
        let native = decompress_tree_proof(compressed).unwrap();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&native).unwrap();
        let alternative = encoder.finish().unwrap();
        assert_ne!(alternative, compressed);
        let noncanonical = encode_proof(BACKEND_TREE, &alternative).unwrap();
        assert_eq!(
            verify_structured_blake3(&statement, &noncanonical),
            Err(StructuredBlake3Error::InvalidEncoding)
        );
    }

    #[test]
    fn multi_chunk_tree_argument_remains_below_the_component_cap() {
        let activation = (0..2_048)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let statement = statement(&activation);
        let proof = prove_structured_blake3(&statement, &activation).unwrap();
        assert!(proof.len() < MAX_COMPRESSED_TREE_PROOF_BYTES);
        verify_structured_blake3(&statement, &proof).unwrap();
    }

    #[test]
    fn configured_stark_security_is_measured() {
        let air = BoundBlake3Air {
            activation_len: 8,
            point_variables: 3,
        };
        let byte_hash = Blake3 {};
        let val_mmcs = ValMmcs::new(FieldHash::new(byte_hash), Compress::new(byte_hash), 0);
        let params = StarkSecurityParams::from_air::<F, EF, _, _>(
            &fri_parameters(ChallengeMmcs::new(val_mmcs)),
            &air,
            AirLayout::from_air::<F>(&air),
            192,
            128,
            1,
        );
        let security = ProvenSecurity::compute(&params, TRACE_ROWS);
        assert!(security.security_bits() >= REQUIRED_PROVEN_SECURITY_BITS);
    }
}
