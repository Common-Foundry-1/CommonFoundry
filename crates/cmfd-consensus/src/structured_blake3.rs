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
    collections::{BTreeMap, BTreeSet},
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
use p3_field::extension::CubicTrinomialExtensionField;
use p3_field::integers::QuotientMap;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};
use thiserror::Error;

#[cfg(feature = "gpu-proof-prover")]
use crate::structured_blake3_narrow::prove_narrow_blake3_with_cuda as prove_narrow_blake3_with_cuda_backends;
#[cfg(feature = "gpu-proof-prover")]
use crate::structured_blake3_narrow::prove_narrow_blake3_with_cuda_in_spill_dir as prove_narrow_blake3_with_cuda_in_spill_dir_backends;
use crate::{
    GOLDILOCKS_MODULUS, StructuredBlake3Statement, StructuredBlake3Verifier,
    forgematrix_v2::output_digest,
    structured_blake3_identity::STRUCTURED_BLAKE3_PROOF_MAGIC,
    structured_blake3_narrow::{
        NarrowBlake3Error, NarrowDft, prove_narrow_blake3_with_dft, verify_narrow_blake3,
    },
};

pub use crate::structured_blake3_identity::STRUCTURED_BLAKE3_VERSION;

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
const ONE_BLOCK_CODEC_MAGIC: &[u8; 8] = b"CMFDB3O1";
const ONE_BLOCK_CODEC_VERSION: u32 = 1;
const ONE_BLOCK_CODEC_HEADER_BYTES: usize = 44;
const ONE_BLOCK_CODEC_FLAGS: u32 = 0;
const ONE_BLOCK_FRI_COMMIT_PHASES: usize = 3;
const ONE_BLOCK_INPUT_BATCHES: usize = 2;
const ONE_BLOCK_TRACE_WIDTH: usize = NUM_BLAKE3_COLS;
const ONE_BLOCK_QUOTIENT_WIDTH: usize = <EF as BasedVectorSpace<F>>::DIMENSION;
const ONE_BLOCK_PATHS_PER_QUERY: usize = ONE_BLOCK_INPUT_BATCHES + ONE_BLOCK_FRI_COMMIT_PHASES;
const ONE_BLOCK_PATH_COUNT: usize = FRI_QUERIES * ONE_BLOCK_PATHS_PER_QUERY;
const ONE_BLOCK_PATH_LENGTHS: [usize; ONE_BLOCK_PATHS_PER_QUERY] = [10, 10, 9, 8, 7];
const ONE_BLOCK_PATH_REFERENCES: usize = FRI_QUERIES * (10 + 10 + 9 + 8 + 7);
const ONE_BLOCK_MAX_QUOTIENT_CHUNKS: usize = 8;
const ONE_BLOCK_SKELETON_BASE_BYTES: usize = 7_477;
const ONE_BLOCK_SKELETON_BYTES_PER_QUOTIENT_CHUNK: usize = 8 * (FRI_QUERIES + 1);
const MAX_ONE_BLOCK_SKELETON_BYTES: usize = ONE_BLOCK_SKELETON_BASE_BYTES
    + ONE_BLOCK_MAX_QUOTIENT_CHUNKS * ONE_BLOCK_SKELETON_BYTES_PER_QUOTIENT_CHUNK;
// The canonical one-block prover commits constant codewords: generate_trace
// repeats one row and the quotient is zero, so each authentication-tree level
// contributes at most one distinct node irrespective of the sampled indices.
const MAX_ONE_BLOCK_PATH_DICTIONARY_NODES: usize = 10 + 10 + 9 + 8 + 7;
#[cfg(test)]
const MAX_ONE_BLOCK_ROW_REFERENCES: usize = (FRI_QUERIES + 1) * (1 + ONE_BLOCK_MAX_QUOTIENT_CHUNKS);
#[cfg(test)]
const MAX_ONE_BLOCK_ARCHIVED_PROOF_BYTES: usize = ONE_BLOCK_CODEC_HEADER_BYTES
    + MAX_ONE_BLOCK_SKELETON_BYTES
    + 2 * MAX_ONE_BLOCK_ROW_REFERENCES
    + 2 * ONE_BLOCK_PATH_REFERENCES
    + 8 * (ONE_BLOCK_TRACE_WIDTH + ONE_BLOCK_QUOTIENT_WIDTH)
    + 32 * MAX_ONE_BLOCK_PATH_DICTIONARY_NODES;
const _: () = assert!(MAX_ONE_BLOCK_PATH_DICTIONARY_NODES == 44);
#[cfg(test)]
const _: () = assert!(MAX_ONE_BLOCK_ARCHIVED_PROOF_BYTES == 89_179);
#[cfg(test)]
const REQUIRED_PROVEN_SECURITY_BITS: usize = 128;

type F = Goldilocks;
type EF = CubicTrinomialExtensionField<F>;
type FieldHash = SerializingHasher<Blake3>;
type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
type ValMmcs = MerkleTreeMmcs<<F as Field>::Packing, u8, FieldHash, Compress, 2, 32>;
type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;
type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3, 32>>;
type Dft = NarrowDft;
type Pcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, EF, Challenger>;
type NativeProof = Proof<Config>;

// The one-block payload is a fixed-width little-endian header followed by a
// canonical stripped NativeProof, u16 row references, u16 authentication-path
// references, canonical Goldilocks row dictionaries, and 32-byte path nodes.
// All section counts except the number of unique path nodes are derived from
// the trusted one-block suite rather than accepted from the prover.

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
    #[error("BLAKE3 STARK pinned preprocessed key is missing or malformed")]
    PinnedPreprocessedKeyInvalid,
    #[error("BLAKE3 STARK preprocessed commitment does not match the pinned key")]
    PinnedPreprocessedKeyMismatch,
    #[error("BLAKE3 STARK accelerator setup failed: {0}")]
    Accelerator(String),
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
            NarrowBlake3Error::PinnedPreprocessedKeyInvalid => Self::PinnedPreprocessedKeyInvalid,
            NarrowBlake3Error::PinnedPreprocessedKeyMismatch => Self::PinnedPreprocessedKeyMismatch,
            #[cfg(feature = "gpu-proof-prover")]
            NarrowBlake3Error::Accelerator(message) => Self::Accelerator(message),
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
        Some((self.point_variables + 2).max(3))
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
    prove_structured_blake3_with_dft(statement, final_activation, NarrowDft::default())
}

/// Generate a BLAKE3 argument with the exact caller-supplied CUDA proof
/// library and device. This never searches for a library, reads an accelerator
/// setting from the environment, or falls back to CPU after selection. The
/// fully encoded result must pass the unchanged CPU verifier before it is
/// returned to the caller.
#[cfg(feature = "gpu-proof-prover")]
pub fn prove_structured_blake3_with_cuda(
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
    library_path: impl AsRef<std::path::Path>,
    device_index: i32,
) -> Result<Vec<u8>, StructuredBlake3Error> {
    prove_structured_blake3_with_cuda_inner(
        statement,
        final_activation,
        library_path.as_ref(),
        device_index,
        None,
    )
}

/// Explicit spill-directory entry point for the crash-isolated proof worker.
///
/// The caller must own this existing absolute directory for the duration of
/// the call and remove it after the worker process exits.
#[cfg(feature = "gpu-proof-prover")]
#[doc(hidden)]
pub fn prove_structured_blake3_with_cuda_in_spill_dir(
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
    library_path: impl AsRef<std::path::Path>,
    device_index: i32,
    spill_dir: impl AsRef<std::path::Path>,
) -> Result<Vec<u8>, StructuredBlake3Error> {
    let spill_dir = spill_dir.as_ref();
    if !spill_dir.is_absolute() {
        return Err(StructuredBlake3Error::Accelerator(
            "proof spill directory must be absolute".to_owned(),
        ));
    }
    if !spill_dir.is_dir() {
        return Err(StructuredBlake3Error::Accelerator(
            "proof spill directory must already exist".to_owned(),
        ));
    }
    prove_structured_blake3_with_cuda_inner(
        statement,
        final_activation,
        library_path.as_ref(),
        device_index,
        Some(spill_dir),
    )
}

#[cfg(feature = "gpu-proof-prover")]
fn prove_structured_blake3_with_cuda_inner(
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
    library_path: &std::path::Path,
    device_index: i32,
    spill_dir: Option<&std::path::Path>,
) -> Result<Vec<u8>, StructuredBlake3Error> {
    let dft = NarrowDft::load_cuda(library_path, device_index)?;
    let proof = if statement.final_activation_len > MAX_ONE_BLOCK_ACTIVATION_BYTES {
        let backend = BACKEND_TREE;
        let payload = if let Some(spill_dir) = spill_dir {
            prove_narrow_blake3_with_cuda_in_spill_dir_backends(
                statement,
                final_activation,
                dft,
                library_path,
                device_index,
                spill_dir,
            )?
        } else {
            prove_narrow_blake3_with_cuda_backends(
                statement,
                final_activation,
                dft,
                library_path,
                device_index,
            )?
        };
        let compressed = compress_tree_proof(&payload)?;
        if 17 + compressed.len() > MAX_COMPRESSED_TREE_PROOF_BYTES {
            return Err(StructuredBlake3Error::ProofTooLarge);
        }
        encode_proof(backend, &compressed)
    } else {
        prove_structured_blake3_with_dft(statement, final_activation, dft)
    }?;
    require_cpu_verified_proof(statement, proof)
}

#[cfg(feature = "gpu-proof-prover")]
fn require_cpu_verified_proof(
    statement: &StructuredBlake3Statement,
    proof: Vec<u8>,
) -> Result<Vec<u8>, StructuredBlake3Error> {
    verify_structured_blake3(statement, &proof)?;
    Ok(proof)
}

fn prove_structured_blake3_with_dft(
    statement: &StructuredBlake3Statement,
    final_activation: &[u8],
    dft: NarrowDft,
) -> Result<Vec<u8>, StructuredBlake3Error> {
    if statement.final_activation_len > MAX_ONE_BLOCK_ACTIVATION_BYTES {
        let backend = BACKEND_TREE;
        let payload = prove_narrow_blake3_with_dft(statement, final_activation, dft)?;
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
    let config = build_config_with_dft(dft);
    let proof = catch_unwind(AssertUnwindSafe(|| {
        prove(&config, &air, trace, &public_values)
    }))
    .map_err(|_| StructuredBlake3Error::BackendPanic)?;
    let native = encode_one_block_native_proof(statement, proof)?;
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
    let proof = decode_one_block_native_proof(statement, native)?;
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
    build_config_with_dft(Dft::default())
}

fn build_config_with_dft(dft: Dft) -> Config {
    let byte_hash = Blake3 {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = fri_parameters(challenge_mmcs);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
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

#[derive(Debug, Clone, Copy)]
struct OneBlockProofShape {
    quotient_chunks: usize,
}

impl OneBlockProofShape {
    fn from_statement(
        statement: &StructuredBlake3Statement,
    ) -> Result<Self, StructuredBlake3Error> {
        validate_statement(statement)?;
        let point_variables = statement.final_activation_len.ilog2() as usize;
        let quotient_chunks = point_variables
            .checked_add(2)
            .map(|degree| degree.max(3) - 1)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?;
        Ok(Self { quotient_chunks })
    }

    fn row_reference_count(self) -> Result<usize, StructuredBlake3Error> {
        (FRI_QUERIES + 1)
            .checked_mul(
                1usize
                    .checked_add(self.quotient_chunks)
                    .ok_or(StructuredBlake3Error::InvalidEncoding)?,
            )
            .ok_or(StructuredBlake3Error::InvalidEncoding)
    }

    fn skeleton_bytes(self) -> Result<usize, StructuredBlake3Error> {
        ONE_BLOCK_SKELETON_BASE_BYTES
            .checked_add(
                self.quotient_chunks
                    .checked_mul(ONE_BLOCK_SKELETON_BYTES_PER_QUOTIENT_CHUNK)
                    .ok_or(StructuredBlake3Error::InvalidEncoding)?,
            )
            .ok_or(StructuredBlake3Error::InvalidEncoding)
    }

    fn encoded_bytes_bound(self) -> Result<usize, StructuredBlake3Error> {
        let row_reference_bytes = self
            .row_reference_count()?
            .checked_mul(2)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?;
        ONE_BLOCK_CODEC_HEADER_BYTES
            .checked_add(self.skeleton_bytes()?)
            .and_then(|value| value.checked_add(row_reference_bytes))
            .and_then(|value| value.checked_add(ONE_BLOCK_PATH_REFERENCES * 2))
            .and_then(|value| {
                value.checked_add(8 * (ONE_BLOCK_TRACE_WIDTH + ONE_BLOCK_QUOTIENT_WIDTH))
            })
            .and_then(|value| value.checked_add(32 * MAX_ONE_BLOCK_PATH_DICTIONARY_NODES))
            .ok_or(StructuredBlake3Error::InvalidEncoding)
    }

    fn row_width(self, reference: usize) -> Result<usize, StructuredBlake3Error> {
        let group_width = 1usize
            .checked_add(self.quotient_chunks)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?;
        if reference >= self.row_reference_count()? {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
        Ok(if reference.rem_euclid(group_width) == 0 {
            ONE_BLOCK_TRACE_WIDTH
        } else {
            ONE_BLOCK_QUOTIENT_WIDTH
        })
    }
}

#[cfg(test)]
pub(crate) fn one_block_encoded_proof_bound(final_activation_len: usize) -> Option<usize> {
    if final_activation_len == 0
        || final_activation_len > MAX_ONE_BLOCK_ACTIVATION_BYTES
        || !final_activation_len.is_power_of_two()
    {
        return None;
    }
    let point_variables = final_activation_len.ilog2() as usize;
    let quotient_chunks =
        (point_variables.checked_add(2)?.max(3) - 1).checked_next_power_of_two()?;
    OneBlockProofShape { quotient_chunks }
        .encoded_bytes_bound()
        .ok()?
        .checked_add(17)
}

#[derive(Default)]
struct OneBlockArchive {
    row_indices: BTreeMap<Vec<u64>, u16>,
    rows: Vec<Vec<F>>,
    row_references: Vec<u16>,
    path_indices: BTreeMap<[u8; 32], u16>,
    paths: Vec<[u8; 32]>,
    path_references: Vec<u16>,
}

fn encode_one_block_native_proof(
    statement: &StructuredBlake3Statement,
    mut proof: NativeProof,
) -> Result<Vec<u8>, StructuredBlake3Error> {
    let shape = OneBlockProofShape::from_statement(statement)?;
    let mut archive = OneBlockArchive::default();

    archive_extension_row(
        &mut proof.opened_values.trace_local,
        ONE_BLOCK_TRACE_WIDTH,
        &mut archive,
    )?;
    if proof.opened_values.trace_next.is_some()
        || proof.opened_values.preprocessed_local.is_some()
        || proof.opened_values.preprocessed_next.is_some()
        || proof.opened_values.random.is_some()
        || proof.opened_values.quotient_chunks.len() != shape.quotient_chunks
    {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    for row in &mut proof.opened_values.quotient_chunks {
        archive_extension_row(row, ONE_BLOCK_QUOTIENT_WIDTH, &mut archive)?;
    }
    if proof.degree_bits != TRACE_ROWS.ilog2() as usize
        || proof.commitments.random.is_some()
        || proof.opening_proof.commit_phase_commits.len() != ONE_BLOCK_FRI_COMMIT_PHASES
        || proof.opening_proof.commit_pow_witnesses.len() != ONE_BLOCK_FRI_COMMIT_PHASES
        || proof
            .opening_proof
            .commit_pow_witnesses
            .iter()
            .any(|witness| !witness.is_zero())
        || proof.opening_proof.query_proofs.len() != FRI_QUERIES
        || proof.opening_proof.final_poly.len() != 1
    {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    for query in &mut proof.opening_proof.query_proofs {
        if query.input_proof.len() != ONE_BLOCK_INPUT_BATCHES
            || query.input_proof[0].opened_values.len() != 1
            || query.input_proof[1].opened_values.len() != shape.quotient_chunks
            || query.commit_phase_openings.len() != ONE_BLOCK_FRI_COMMIT_PHASES
        {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
        archive_base_row(
            &mut query.input_proof[0].opened_values[0],
            ONE_BLOCK_TRACE_WIDTH,
            &mut archive,
        )?;
        for row in &mut query.input_proof[1].opened_values {
            archive_base_row(row, ONE_BLOCK_QUOTIENT_WIDTH, &mut archive)?;
        }
        for (batch, &path_len) in query
            .input_proof
            .iter_mut()
            .zip(&ONE_BLOCK_PATH_LENGTHS[..ONE_BLOCK_INPUT_BATCHES])
        {
            archive_path(&mut batch.opening_proof, path_len, &mut archive)?;
        }
        for (step, &path_len) in query
            .commit_phase_openings
            .iter_mut()
            .zip(&ONE_BLOCK_PATH_LENGTHS[ONE_BLOCK_INPUT_BATCHES..])
        {
            if step.log_arity != 1 || step.sibling_values.len() != 1 {
                return Err(StructuredBlake3Error::InvalidEncoding);
            }
            archive_path(&mut step.opening_proof, path_len, &mut archive)?;
        }
    }

    if archive.rows.len() != 2
        || archive.row_references.len() != shape.row_reference_count()?
        || archive.path_references.len() != ONE_BLOCK_PATH_REFERENCES
        || archive.paths.len() > MAX_ONE_BLOCK_PATH_DICTIONARY_NODES
    {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    validate_stripped_one_block_proof(&proof, shape)?;
    let skeleton = one_block_bincode_options()
        .serialize(&proof)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
    if skeleton.len() != shape.skeleton_bytes()? {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }

    let row_bytes = archive.rows.iter().try_fold(0usize, |total, row| {
        total
            .checked_add(
                row.len()
                    .checked_mul(std::mem::size_of::<u64>())
                    .ok_or(StructuredBlake3Error::ProofTooLarge)?,
            )
            .ok_or(StructuredBlake3Error::ProofTooLarge)
    })?;
    let encoded_len = ONE_BLOCK_CODEC_HEADER_BYTES
        .checked_add(skeleton.len())
        .and_then(|value| value.checked_add(archive.row_references.len() * 2))
        .and_then(|value| value.checked_add(archive.path_references.len() * 2))
        .and_then(|value| value.checked_add(row_bytes))
        .and_then(|value| value.checked_add(archive.paths.len() * 32))
        .ok_or(StructuredBlake3Error::ProofTooLarge)?;
    if encoded_len > shape.encoded_bytes_bound()? {
        return Err(StructuredBlake3Error::ProofTooLarge);
    }

    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| StructuredBlake3Error::ProofTooLarge)?;
    encoded.extend_from_slice(ONE_BLOCK_CODEC_MAGIC);
    encoded.extend_from_slice(&ONE_BLOCK_CODEC_VERSION.to_le_bytes());
    encoded.extend_from_slice(&(ONE_BLOCK_CODEC_HEADER_BYTES as u32).to_le_bytes());
    encoded.extend_from_slice(&ONE_BLOCK_CODEC_FLAGS.to_le_bytes());
    encode_one_block_count(&mut encoded, skeleton.len())?;
    encode_one_block_count(&mut encoded, archive.rows.len())?;
    encode_one_block_count(&mut encoded, archive.row_references.len())?;
    encode_one_block_count(&mut encoded, ONE_BLOCK_PATH_COUNT)?;
    encode_one_block_count(&mut encoded, archive.paths.len())?;
    encode_one_block_count(&mut encoded, archive.path_references.len())?;
    encoded.extend_from_slice(&skeleton);
    for reference in archive.row_references {
        encoded.extend_from_slice(&reference.to_le_bytes());
    }
    for reference in archive.path_references {
        encoded.extend_from_slice(&reference.to_le_bytes());
    }
    for row in archive.rows {
        for value in row {
            encoded.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
        }
    }
    for digest in archive.paths {
        encoded.extend_from_slice(&digest);
    }
    debug_assert_eq!(encoded.len(), encoded_len);
    Ok(encoded)
}

fn archive_extension_row(
    row: &mut Vec<EF>,
    expected_width: usize,
    archive: &mut OneBlockArchive,
) -> Result<(), StructuredBlake3Error> {
    if row.len() != expected_width {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    let base_row = std::mem::take(row)
        .into_iter()
        .map(|value| {
            let coefficients: &[F] = value.as_basis_coefficients_slice();
            if coefficients.len() != ONE_BLOCK_QUOTIENT_WIDTH
                || coefficients[1..]
                    .iter()
                    .any(|coefficient| !coefficient.is_zero())
            {
                return Err(StructuredBlake3Error::InvalidEncoding);
            }
            Ok(coefficients[0])
        })
        .collect::<Result<Vec<_>, _>>()?;
    archive_row(base_row, archive)
}

fn archive_base_row(
    row: &mut Vec<F>,
    expected_width: usize,
    archive: &mut OneBlockArchive,
) -> Result<(), StructuredBlake3Error> {
    if row.len() != expected_width {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    archive_row(std::mem::take(row), archive)
}

fn archive_row(row: Vec<F>, archive: &mut OneBlockArchive) -> Result<(), StructuredBlake3Error> {
    let key = row
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect::<Vec<_>>();
    let reference = if let Some(&reference) = archive.row_indices.get(&key) {
        reference
    } else {
        let reference =
            u16::try_from(archive.rows.len()).map_err(|_| StructuredBlake3Error::ProofTooLarge)?;
        archive.row_indices.insert(key, reference);
        archive.rows.push(row);
        reference
    };
    archive.row_references.push(reference);
    Ok(())
}

fn archive_path(
    path: &mut Vec<[u8; 32]>,
    expected_len: usize,
    archive: &mut OneBlockArchive,
) -> Result<(), StructuredBlake3Error> {
    if path.len() != expected_len {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    for digest in path.drain(..) {
        let reference = if let Some(&reference) = archive.path_indices.get(&digest) {
            reference
        } else {
            let reference = u16::try_from(archive.paths.len())
                .map_err(|_| StructuredBlake3Error::ProofTooLarge)?;
            archive.path_indices.insert(digest, reference);
            archive.paths.push(digest);
            reference
        };
        archive.path_references.push(reference);
    }
    Ok(())
}

fn validate_stripped_one_block_proof(
    proof: &NativeProof,
    shape: OneBlockProofShape,
) -> Result<(), StructuredBlake3Error> {
    if proof.degree_bits != TRACE_ROWS.ilog2() as usize
        || proof.commitments.random.is_some()
        || !proof.opened_values.trace_local.is_empty()
        || proof.opened_values.trace_next.is_some()
        || proof.opened_values.preprocessed_local.is_some()
        || proof.opened_values.preprocessed_next.is_some()
        || proof.opened_values.random.is_some()
        || proof.opened_values.quotient_chunks.len() != shape.quotient_chunks
        || proof
            .opened_values
            .quotient_chunks
            .iter()
            .any(|row| !row.is_empty())
        || proof.opening_proof.commit_phase_commits.len() != ONE_BLOCK_FRI_COMMIT_PHASES
        || proof.opening_proof.commit_pow_witnesses.len() != ONE_BLOCK_FRI_COMMIT_PHASES
        || proof
            .opening_proof
            .commit_pow_witnesses
            .iter()
            .any(|witness| !witness.is_zero())
        || proof.opening_proof.query_proofs.len() != FRI_QUERIES
        || proof.opening_proof.final_poly.len() != 1
    {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    for query in &proof.opening_proof.query_proofs {
        if query.input_proof.len() != ONE_BLOCK_INPUT_BATCHES
            || query.input_proof[0].opened_values.len() != 1
            || query.input_proof[1].opened_values.len() != shape.quotient_chunks
            || query
                .input_proof
                .iter()
                .flat_map(|batch| &batch.opened_values)
                .any(|row| !row.is_empty())
            || query
                .input_proof
                .iter()
                .any(|batch| !batch.opening_proof.is_empty())
            || query.commit_phase_openings.len() != ONE_BLOCK_FRI_COMMIT_PHASES
            || query.commit_phase_openings.iter().any(|step| {
                step.log_arity != 1
                    || step.sibling_values.len() != 1
                    || !step.opening_proof.is_empty()
            })
        {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
    }
    Ok(())
}

fn encode_one_block_count(
    encoded: &mut Vec<u8>,
    count: usize,
) -> Result<(), StructuredBlake3Error> {
    encoded.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| StructuredBlake3Error::ProofTooLarge)?
            .to_le_bytes(),
    );
    Ok(())
}

fn decode_one_block_native_proof(
    statement: &StructuredBlake3Statement,
    encoded: &[u8],
) -> Result<NativeProof, StructuredBlake3Error> {
    let shape = OneBlockProofShape::from_statement(statement)?;
    if encoded.len() < ONE_BLOCK_CODEC_HEADER_BYTES
        || encoded.len() > shape.encoded_bytes_bound()?
        || encoded.get(..8) != Some(ONE_BLOCK_CODEC_MAGIC.as_slice())
        || one_block_header_u32(encoded, 8)? != ONE_BLOCK_CODEC_VERSION
        || one_block_header_u32(encoded, 12)? != ONE_BLOCK_CODEC_HEADER_BYTES as u32
        || one_block_header_u32(encoded, 16)? != ONE_BLOCK_CODEC_FLAGS
    {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    let skeleton_len = one_block_header_usize(encoded, 20)?;
    let row_dictionary_count = one_block_header_usize(encoded, 24)?;
    let row_reference_count = one_block_header_usize(encoded, 28)?;
    let path_count = one_block_header_usize(encoded, 32)?;
    let path_dictionary_count = one_block_header_usize(encoded, 36)?;
    let path_reference_count = one_block_header_usize(encoded, 40)?;
    if skeleton_len != shape.skeleton_bytes()?
        || row_dictionary_count != 2
        || row_reference_count != shape.row_reference_count()?
        || path_count != ONE_BLOCK_PATH_COUNT
        || path_dictionary_count == 0
        || path_dictionary_count > MAX_ONE_BLOCK_PATH_DICTIONARY_NODES
        || path_reference_count != ONE_BLOCK_PATH_REFERENCES
    {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }

    let skeleton_start = ONE_BLOCK_CODEC_HEADER_BYTES;
    let skeleton_end = checked_one_block_end(skeleton_start, skeleton_len)?;
    let row_references_end = checked_one_block_end(skeleton_end, row_reference_count * 2)?;
    let path_references_end = checked_one_block_end(row_references_end, path_reference_count * 2)?;
    if path_references_end > encoded.len() {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    let skeleton = encoded
        .get(skeleton_start..skeleton_end)
        .ok_or(StructuredBlake3Error::InvalidEncoding)?;
    let mut proof: NativeProof = one_block_bincode_options()
        .deserialize(skeleton)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
    if one_block_bincode_options()
        .serialize(&proof)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?
        != skeleton
    {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    validate_stripped_one_block_proof(&proof, shape)?;

    let row_references = decode_one_block_references(
        encoded
            .get(skeleton_end..row_references_end)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?,
        row_reference_count,
    )?;
    let path_references = decode_one_block_references(
        encoded
            .get(row_references_end..path_references_end)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?,
        path_reference_count,
    )?;
    let row_widths =
        validate_one_block_row_references(&row_references, row_dictionary_count, shape)?;
    validate_one_block_reference_order(&path_references, path_dictionary_count)?;

    let row_dictionary_bytes = row_widths.iter().try_fold(0usize, |total, &width| {
        total
            .checked_add(
                width
                    .checked_mul(std::mem::size_of::<u64>())
                    .ok_or(StructuredBlake3Error::InvalidEncoding)?,
            )
            .ok_or(StructuredBlake3Error::InvalidEncoding)
    })?;
    let row_dictionary_end = checked_one_block_end(path_references_end, row_dictionary_bytes)?;
    let path_dictionary_end = checked_one_block_end(
        row_dictionary_end,
        path_dictionary_count
            .checked_mul(32)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?,
    )?;
    if path_dictionary_end != encoded.len() {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    let rows = decode_one_block_rows(
        encoded
            .get(path_references_end..row_dictionary_end)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?,
        &row_widths,
    )?;
    let paths = decode_one_block_paths(
        encoded
            .get(row_dictionary_end..path_dictionary_end)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?,
        path_dictionary_count,
    )?;

    let mut row_decoder = OneBlockRowDecoder {
        rows: &rows,
        references: &row_references,
        offset: 0,
    };
    proof.opened_values.trace_local = row_decoder.read_extension(ONE_BLOCK_TRACE_WIDTH)?;
    for row in &mut proof.opened_values.quotient_chunks {
        *row = row_decoder.read_extension(ONE_BLOCK_QUOTIENT_WIDTH)?;
    }
    let mut path_decoder = OneBlockPathDecoder {
        paths: &paths,
        references: &path_references,
        offset: 0,
    };
    for query in &mut proof.opening_proof.query_proofs {
        query.input_proof[0].opened_values[0] = row_decoder.read_base(ONE_BLOCK_TRACE_WIDTH)?;
        for row in &mut query.input_proof[1].opened_values {
            *row = row_decoder.read_base(ONE_BLOCK_QUOTIENT_WIDTH)?;
        }
        for (batch, &path_len) in query
            .input_proof
            .iter_mut()
            .zip(&ONE_BLOCK_PATH_LENGTHS[..ONE_BLOCK_INPUT_BATCHES])
        {
            batch.opening_proof = path_decoder.read_path(path_len)?;
        }
        for (step, &path_len) in query
            .commit_phase_openings
            .iter_mut()
            .zip(&ONE_BLOCK_PATH_LENGTHS[ONE_BLOCK_INPUT_BATCHES..])
        {
            step.opening_proof = path_decoder.read_path(path_len)?;
        }
    }
    row_decoder.finish()?;
    path_decoder.finish()?;
    Ok(proof)
}

fn one_block_header_u32(encoded: &[u8], offset: usize) -> Result<u32, StructuredBlake3Error> {
    let end = offset
        .checked_add(4)
        .ok_or(StructuredBlake3Error::InvalidEncoding)?;
    Ok(u32::from_le_bytes(
        encoded
            .get(offset..end)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?
            .try_into()
            .map_err(|_| StructuredBlake3Error::InvalidEncoding)?,
    ))
}

fn one_block_header_usize(encoded: &[u8], offset: usize) -> Result<usize, StructuredBlake3Error> {
    usize::try_from(one_block_header_u32(encoded, offset)?)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)
}

fn checked_one_block_end(start: usize, len: usize) -> Result<usize, StructuredBlake3Error> {
    start
        .checked_add(len)
        .ok_or(StructuredBlake3Error::InvalidEncoding)
}

fn decode_one_block_references(
    encoded: &[u8],
    count: usize,
) -> Result<Vec<u16>, StructuredBlake3Error> {
    if encoded.len() != count.saturating_mul(2) {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    encoded
        .chunks_exact(2)
        .map(|bytes| {
            Ok(u16::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| StructuredBlake3Error::InvalidEncoding)?,
            ))
        })
        .collect()
}

fn validate_one_block_row_references(
    references: &[u16],
    dictionary_count: usize,
    shape: OneBlockProofShape,
) -> Result<Vec<usize>, StructuredBlake3Error> {
    validate_one_block_reference_order(references, dictionary_count)?;
    let mut widths = vec![0usize; dictionary_count];
    for (position, &reference) in references.iter().enumerate() {
        let index = usize::from(reference);
        let width = shape.row_width(position)?;
        if widths[index] == 0 {
            widths[index] = width;
        } else if widths[index] != width {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
    }
    if widths.contains(&0) {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    Ok(widths)
}

fn validate_one_block_reference_order(
    references: &[u16],
    dictionary_count: usize,
) -> Result<(), StructuredBlake3Error> {
    let mut next_new = 0usize;
    for &reference in references {
        let index = usize::from(reference);
        if index > next_new || index >= dictionary_count {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
        if index == next_new {
            next_new += 1;
        }
    }
    if next_new != dictionary_count {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    Ok(())
}

fn decode_one_block_rows(
    encoded: &[u8],
    widths: &[usize],
) -> Result<Vec<Vec<F>>, StructuredBlake3Error> {
    let mut offset = 0usize;
    let mut rows = Vec::new();
    rows.try_reserve_exact(widths.len())
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
    let mut unique = BTreeSet::new();
    for &width in widths {
        let mut row = Vec::new();
        row.try_reserve_exact(width)
            .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
        let mut key = Vec::new();
        key.try_reserve_exact(width)
            .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
        for _ in 0..width {
            let end = checked_one_block_end(offset, 8)?;
            let canonical = u64::from_le_bytes(
                encoded
                    .get(offset..end)
                    .ok_or(StructuredBlake3Error::InvalidEncoding)?
                    .try_into()
                    .map_err(|_| StructuredBlake3Error::InvalidEncoding)?,
            );
            if canonical >= GOLDILOCKS_MODULUS {
                return Err(StructuredBlake3Error::NonCanonicalField);
            }
            offset = end;
            key.push(canonical);
            row.push(F::new(canonical));
        }
        if !unique.insert(key) {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
        rows.push(row);
    }
    if offset != encoded.len() {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    Ok(rows)
}

fn decode_one_block_paths(
    encoded: &[u8],
    count: usize,
) -> Result<Vec<[u8; 32]>, StructuredBlake3Error> {
    if encoded.len() != count.saturating_mul(32) {
        return Err(StructuredBlake3Error::InvalidEncoding);
    }
    let mut paths = Vec::new();
    paths
        .try_reserve_exact(count)
        .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
    let mut unique = BTreeSet::new();
    for bytes in encoded.chunks_exact(32) {
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| StructuredBlake3Error::InvalidEncoding)?;
        if !unique.insert(digest) {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
        paths.push(digest);
    }
    Ok(paths)
}

struct OneBlockRowDecoder<'a> {
    rows: &'a [Vec<F>],
    references: &'a [u16],
    offset: usize,
}

impl OneBlockRowDecoder<'_> {
    fn read_base(&mut self, width: usize) -> Result<Vec<F>, StructuredBlake3Error> {
        let reference = *self
            .references
            .get(self.offset)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?;
        self.offset += 1;
        let row = self
            .rows
            .get(usize::from(reference))
            .ok_or(StructuredBlake3Error::InvalidEncoding)?;
        if row.len() != width {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
        Ok(row.clone())
    }

    fn read_extension(&mut self, width: usize) -> Result<Vec<EF>, StructuredBlake3Error> {
        Ok(self
            .read_base(width)?
            .into_iter()
            .map(|value| EF::new([value, F::ZERO, F::ZERO]))
            .collect())
    }

    fn finish(self) -> Result<(), StructuredBlake3Error> {
        if self.offset != self.references.len() {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
        Ok(())
    }
}

struct OneBlockPathDecoder<'a> {
    paths: &'a [[u8; 32]],
    references: &'a [u16],
    offset: usize,
}

impl OneBlockPathDecoder<'_> {
    fn read_path(&mut self, len: usize) -> Result<Vec<[u8; 32]>, StructuredBlake3Error> {
        let end = checked_one_block_end(self.offset, len)?;
        let references = self
            .references
            .get(self.offset..end)
            .ok_or(StructuredBlake3Error::InvalidEncoding)?;
        self.offset = end;
        references
            .iter()
            .map(|reference| {
                self.paths
                    .get(usize::from(*reference))
                    .copied()
                    .ok_or(StructuredBlake3Error::InvalidEncoding)
            })
            .collect()
    }

    fn finish(self) -> Result<(), StructuredBlake3Error> {
        if self.offset != self.references.len() {
            return Err(StructuredBlake3Error::InvalidEncoding);
        }
        Ok(())
    }
}

fn one_block_bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_ONE_BLOCK_SKELETON_BYTES as u64)
}

#[cfg(test)]
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
    encoded.extend_from_slice(STRUCTURED_BLAKE3_PROOF_MAGIC);
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
    if encoded.get(..8) != Some(STRUCTURED_BLAKE3_PROOF_MAGIC.as_slice()) {
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
    fn legacy_outer_proof_envelope_is_rejected() {
        let proof = encode_proof(BACKEND_TREE, b"canonical-body").unwrap();
        assert_eq!(&proof[..8], STRUCTURED_BLAKE3_PROOF_MAGIC);
        assert_eq!(
            u32::from_le_bytes(proof[8..12].try_into().unwrap()),
            STRUCTURED_BLAKE3_VERSION
        );

        let mut legacy_magic = proof.clone();
        legacy_magic[..8].copy_from_slice(b"CMFDB3S3");
        assert_eq!(
            decode_proof(&legacy_magic).unwrap_err(),
            StructuredBlake3Error::InvalidEncoding
        );

        let mut legacy_version = proof;
        legacy_version[8..12].copy_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            decode_proof(&legacy_version).unwrap_err(),
            StructuredBlake3Error::InvalidEncoding
        );
    }

    #[test]
    fn pinned_preprocessed_key_failures_preserve_their_diagnosis() {
        assert_eq!(
            StructuredBlake3Error::from(NarrowBlake3Error::PinnedPreprocessedKeyInvalid),
            StructuredBlake3Error::PinnedPreprocessedKeyInvalid
        );
        assert_eq!(
            StructuredBlake3Error::from(NarrowBlake3Error::PinnedPreprocessedKeyMismatch),
            StructuredBlake3Error::PinnedPreprocessedKeyMismatch
        );
    }

    #[test]
    fn one_block_argument_round_trips_and_rejects_mutations() {
        let activation = [1, 2, 3, 4, 200, 210, 220, 230];
        let statement = statement(&activation);
        let proof = prove_structured_blake3(&statement, &activation).unwrap();
        assert!(proof.len() <= MAX_ONE_BLOCK_ARCHIVED_PROOF_BYTES + 17);
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
    fn one_block_archive_is_canonical_for_every_supported_shape() {
        for len in [1usize, 2, 4, 8, 16] {
            let activation = (0..len)
                .map(|index| ((17 * index + 3) % 251) as u8)
                .collect::<Vec<_>>();
            let statement = statement(&activation);
            let encoded = prove_structured_blake3(&statement, &activation).unwrap();
            assert_eq!(encoded[12], BACKEND_ONE_BLOCK);
            assert!(encoded.len() <= MAX_ONE_BLOCK_ARCHIVED_PROOF_BYTES + 17);
            verify_structured_blake3(&statement, &encoded).unwrap();

            let (_, native) = decode_proof(&encoded).unwrap();
            assert_eq!(&native[..8], ONE_BLOCK_CODEC_MAGIC);
            let decoded = decode_one_block_native_proof(&statement, native).unwrap();
            assert_eq!(
                encode_one_block_native_proof(&statement, decoded).unwrap(),
                native
            );
            let shape = OneBlockProofShape::from_statement(&statement).unwrap();
            assert_eq!(
                one_block_header_usize(native, 28).unwrap(),
                shape.row_reference_count().unwrap()
            );
            assert_eq!(
                one_block_header_usize(native, 32).unwrap(),
                ONE_BLOCK_PATH_COUNT
            );
            assert_eq!(
                one_block_header_usize(native, 40).unwrap(),
                ONE_BLOCK_PATH_REFERENCES
            );
        }
    }

    #[test]
    fn one_byte_archive_uses_corrected_degree_and_rejects_malformed_references() {
        let activation = [17_u8];
        let statement = statement(&activation);
        let shape = OneBlockProofShape::from_statement(&statement).unwrap();
        assert_eq!(shape.quotient_chunks, 2);
        let encoded = prove_structured_blake3(&statement, &activation).unwrap();
        verify_structured_blake3(&statement, &encoded).unwrap();
        let (_, native) = decode_proof(&encoded).unwrap();
        let mut malformed = native.to_vec();
        let row_reference_start =
            ONE_BLOCK_CODEC_HEADER_BYTES + one_block_header_usize(&malformed, 20).unwrap();
        malformed[row_reference_start..row_reference_start + 2]
            .copy_from_slice(&1_u16.to_le_bytes());
        let malformed = encode_proof(BACKEND_ONE_BLOCK, &malformed).unwrap();
        assert_eq!(
            verify_structured_blake3(&statement, &malformed),
            Err(StructuredBlake3Error::InvalidEncoding)
        );
    }

    #[test]
    fn one_block_archive_rejects_noncanonical_dictionaries_and_counts() {
        let activation = [1, 2, 3, 4, 200, 210, 220, 230];
        let statement = statement(&activation);
        let encoded = prove_structured_blake3(&statement, &activation).unwrap();
        let (_, native) = decode_proof(&encoded).unwrap();
        let native = native.to_vec();
        let skeleton_len = one_block_header_usize(&native, 20).unwrap();
        let row_reference_count = one_block_header_usize(&native, 28).unwrap();
        let path_dictionary_count = one_block_header_usize(&native, 36).unwrap();
        let path_reference_count = one_block_header_usize(&native, 40).unwrap();
        assert!(path_dictionary_count > 1);
        let row_reference_start = ONE_BLOCK_CODEC_HEADER_BYTES + skeleton_len;
        let path_reference_start = row_reference_start + 2 * row_reference_count;
        let row_dictionary_start = path_reference_start + 2 * path_reference_count;
        let row_dictionary_bytes = (ONE_BLOCK_TRACE_WIDTH + ONE_BLOCK_QUOTIENT_WIDTH) * 8;
        let path_dictionary_start = row_dictionary_start + row_dictionary_bytes;
        assert_eq!(
            native.len(),
            path_dictionary_start + 32 * path_dictionary_count
        );

        let rejects = |mutated_native: Vec<u8>| {
            let wrapped = encode_proof(BACKEND_ONE_BLOCK, &mutated_native).unwrap();
            let result = catch_unwind(AssertUnwindSafe(|| {
                verify_structured_blake3(&statement, &wrapped)
            }));
            assert!(result.is_ok());
            assert!(result.unwrap().is_err());
        };

        let mut mutation = native.clone();
        mutation[0] ^= 1;
        rejects(mutation);
        let mut mutation = native.clone();
        mutation[8..12].copy_from_slice(&0_u32.to_le_bytes());
        rejects(mutation);
        let mut mutation = native.clone();
        mutation[12..16].copy_from_slice(&0_u32.to_le_bytes());
        rejects(mutation);
        let mut mutation = native.clone();
        mutation[16..20].copy_from_slice(&1_u32.to_le_bytes());
        rejects(mutation);

        for (offset, value) in [(24, 3_u32), (28, 0), (32, 0), (36, 0), (40, 0)] {
            let mut mutation = native.clone();
            mutation[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            rejects(mutation);
        }

        let mut forward_row = native.clone();
        forward_row[row_reference_start..row_reference_start + 2]
            .copy_from_slice(&1_u16.to_le_bytes());
        rejects(forward_row);
        let mut wrong_width_row = native.clone();
        wrong_width_row[row_reference_start + 2..row_reference_start + 4]
            .copy_from_slice(&0_u16.to_le_bytes());
        rejects(wrong_width_row);
        let mut forward_path = native.clone();
        forward_path[path_reference_start..path_reference_start + 2]
            .copy_from_slice(&1_u16.to_le_bytes());
        rejects(forward_path);

        let mut noncanonical_field = native.clone();
        noncanonical_field[row_dictionary_start..row_dictionary_start + 8]
            .copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        rejects(noncanonical_field);
        let mut duplicate_digest = native.clone();
        let first_digest =
            duplicate_digest[path_dictionary_start..path_dictionary_start + 32].to_vec();
        duplicate_digest[path_dictionary_start + 32..path_dictionary_start + 64]
            .copy_from_slice(&first_digest);
        rejects(duplicate_digest);

        let mut unused_digest = native.clone();
        unused_digest[36..40].copy_from_slice(
            &u32::try_from(path_dictionary_count + 1)
                .unwrap()
                .to_le_bytes(),
        );
        unused_digest.extend_from_slice(&[0xA5; 32]);
        rejects(unused_digest);
        let mut trailing = native.clone();
        trailing.push(0);
        rejects(trailing);

        let skeleton_start = ONE_BLOCK_CODEC_HEADER_BYTES;
        let skeleton_end = skeleton_start + skeleton_len;
        let mut malformed_skeleton: NativeProof = bincode_options()
            .deserialize(&native[skeleton_start..skeleton_end])
            .unwrap();
        malformed_skeleton.opened_values.trace_next = Some(Vec::new());
        let malformed_skeleton = bincode_options().serialize(&malformed_skeleton).unwrap();
        let mut malformed_native = native[..ONE_BLOCK_CODEC_HEADER_BYTES].to_vec();
        malformed_native[20..24].copy_from_slice(
            &u32::try_from(malformed_skeleton.len())
                .unwrap()
                .to_le_bytes(),
        );
        malformed_native.extend_from_slice(&malformed_skeleton);
        malformed_native.extend_from_slice(&native[skeleton_end..]);
        rejects(malformed_native);

        let decoded = decode_one_block_native_proof(&statement, &native).unwrap();
        let legacy_native = bincode_options().serialize(&decoded).unwrap();
        assert_ne!(&legacy_native[..8], ONE_BLOCK_CODEC_MAGIC);
        rejects(legacy_native);
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

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    fn cuda_prover_requires_the_explicit_library_to_load() {
        let activation = [1, 2, 3, 4, 5, 6, 7, 8];
        let statement = statement(&activation);
        let missing = std::env::temp_dir().join(format!(
            "cmfd-proof-cuda-missing-{}-{}",
            std::process::id(),
            std::env::consts::DLL_EXTENSION
        ));
        let error = prove_structured_blake3_with_cuda(&statement, &activation, missing, 0)
            .expect_err("an explicitly missing CUDA library must fail closed");
        assert!(matches!(error, StructuredBlake3Error::Accelerator(_)));
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    fn cuda_worker_spill_directory_must_be_absolute_and_existing() {
        let activation = [1, 2, 3, 4, 5, 6, 7, 8];
        let statement = statement(&activation);
        let missing_library = std::env::temp_dir().join(format!(
            "cmfd-proof-cuda-missing-{}-{}",
            std::process::id(),
            std::env::consts::DLL_EXTENSION
        ));
        let relative = prove_structured_blake3_with_cuda_in_spill_dir(
            &statement,
            &activation,
            &missing_library,
            0,
            std::path::Path::new("relative-spill-directory"),
        );
        assert_eq!(
            relative,
            Err(StructuredBlake3Error::Accelerator(
                "proof spill directory must be absolute".to_owned()
            ))
        );

        let missing_spill = std::env::temp_dir().join(format!(
            "cmfd-proof-missing-spill-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let absent = prove_structured_blake3_with_cuda_in_spill_dir(
            &statement,
            &activation,
            missing_library,
            0,
            missing_spill,
        );
        assert_eq!(
            absent,
            Err(StructuredBlake3Error::Accelerator(
                "proof spill directory must already exist".to_owned()
            ))
        );
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    fn cuda_return_gate_rejects_a_corrupt_backend_proof() {
        let activation = [1, 2, 3, 4, 5, 6, 7, 8];
        let statement = statement(&activation);
        assert_eq!(
            require_cpu_verified_proof(&statement, vec![0; 17]),
            Err(StructuredBlake3Error::InvalidEncoding)
        );
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    #[ignore = "requires CMFD_TEST_PROOF_CUDA_LIBRARY and a CUDA device"]
    fn cuda_tree_proof_is_accepted_by_the_unchanged_cpu_verifier() {
        let library_path = std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
            .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the exact CUDA proof-library path");
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let proof = prove_structured_blake3_with_cuda(
            &statement,
            &activation,
            std::path::PathBuf::from(library_path),
            0,
        )
        .unwrap();
        let cpu_proof = prove_structured_blake3(&statement, &activation).unwrap();
        // Plonky3's parallel FRI proof-of-work search may find a different
        // valid nonce on each run. That changes query positions and Merkle
        // paths, so complete proof bytes are not deterministic. Compare the
        // algebraic commitments and transcript values fixed before that nonce.
        let (_, gpu_compressed) = decode_proof(&proof).unwrap();
        let gpu_native = crate::structured_blake3_narrow::decode_native_proof(
            &decompress_tree_proof(gpu_compressed).unwrap(),
        )
        .unwrap();
        let (_, cpu_compressed) = decode_proof(&cpu_proof).unwrap();
        let cpu_native = crate::structured_blake3_narrow::decode_native_proof(
            &decompress_tree_proof(cpu_compressed).unwrap(),
        )
        .unwrap();
        assert_eq!(gpu_native.degree_bits, cpu_native.degree_bits);
        assert_eq!(
            bincode_options()
                .serialize(&gpu_native.commitments)
                .unwrap(),
            bincode_options()
                .serialize(&cpu_native.commitments)
                .unwrap()
        );
        assert_eq!(
            bincode_options()
                .serialize(&gpu_native.opened_values)
                .unwrap(),
            bincode_options()
                .serialize(&cpu_native.opened_values)
                .unwrap()
        );
        assert_eq!(
            bincode_options()
                .serialize(&gpu_native.opening_proof.commit_phase_commits)
                .unwrap(),
            bincode_options()
                .serialize(&cpu_native.opening_proof.commit_phase_commits)
                .unwrap()
        );
        assert_eq!(
            bincode_options()
                .serialize(&gpu_native.opening_proof.final_poly)
                .unwrap(),
            bincode_options()
                .serialize(&cpu_native.opening_proof.final_poly)
                .unwrap()
        );
        verify_structured_blake3(&statement, &proof).unwrap();
        verify_structured_blake3(&statement, &cpu_proof).unwrap();
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
            activation_len: 16,
            point_variables: 4,
        };
        let security_at = |num_queries| {
            let byte_hash = Blake3 {};
            let val_mmcs = ValMmcs::new(FieldHash::new(byte_hash), Compress::new(byte_hash), 0);
            let mut fri = fri_parameters(ChallengeMmcs::new(val_mmcs));
            fri.num_queries = num_queries;
            let params = StarkSecurityParams::from_air::<F, EF, _, _>(
                &fri,
                &air,
                AirLayout::from_air::<F>(&air),
                192,
                128,
                1,
            );
            assert_eq!(params.max_combo, 1);
            ProvenSecurity::compute(&params, TRACE_ROWS)
        };
        let security = security_at(FRI_QUERIES);
        assert!(security.security_bits() >= REQUIRED_PROVEN_SECURITY_BITS);
        let minimum_queries = (1..=FRI_QUERIES)
            .find(|queries| security_at(*queries).security_bits() >= REQUIRED_PROVEN_SECURITY_BITS)
            .expect("configured query count must reach 128 proven bits");
        assert_eq!(minimum_queries, 36);
        assert_eq!(FRI_QUERIES, minimum_queries + 4);
    }
}
