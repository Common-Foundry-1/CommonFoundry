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

#[cfg(feature = "gpu-proof-prover")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    array,
    borrow::{Borrow, BorrowMut},
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

use bincode::Options;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::DuplexChallenger;
#[cfg(feature = "gpu-proof-prover")]
use p3_commit::{BatchOpening, BatchOpeningRef};
use p3_commit::{
    BuildPeriodicLdeTableFast, ExtensionMmcs, Mmcs, OpenedValues, Pcs as PcsTrait,
    PeriodicLdeTable, PolynomialSpace,
};
#[cfg(any(test, not(feature = "gpu-proof-prover")))]
use p3_dft::Radix2DitParallel;
use p3_dft::{Layout, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::CubicTrinomialExtensionField;
use p3_field::integers::QuotientMap;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
#[cfg(feature = "gpu-proof-prover")]
use p3_fri::FriLdeMatrix;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
#[cfg(feature = "gpu-proof-prover")]
use p3_matrix::bitrev::BitReversalPerm;
use p3_matrix::{
    Matrix,
    bitrev::{BitReversedMatrixView, BitReversibleMatrix},
    dense::{RowMajorMatrix, RowMajorMatrixViewMut},
};
use p3_merkle_tree::MerkleTreeMmcs;
#[cfg(feature = "gpu-proof-prover")]
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use p3_symmetric::{MerkleCap, PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    PreprocessedVerifierKey, Proof, StarkConfig, prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed,
};
use thiserror::Error;

use crate::{
    GOLDILOCKS_MODULUS, StructuredBlake3Statement,
    structured_blake3_identity::{
        NARROW_BLAKE3_PROOF_MAGIC, NARROW_BLAKE3_PROOF_VERSION, PINNED_PREPROCESSED_WIDTH,
        pinned_preprocessed_key,
    },
    structured_blake3_tree::{
        Blake3TreeError, Blake3TreeWitness, CompressionKind, CompressionOp, build_tree_witness,
    },
};

#[cfg(all(test, feature = "dory-bls12-381-prototype"))]
pub(crate) mod bls_bridge;

#[cfg(feature = "gpu-proof-prover")]
type NarrowDftBackend = cmfd_proof_accel::ProofDft;
#[cfg(not(feature = "gpu-proof-prover"))]
type NarrowDftBackend = Radix2DitParallel<F>;

const OUTPUT_CONTEXT: &str = "CMFD/FORGEMATRIX/OUTPUT/V2";
const MAX_POINT_VARIABLES: usize = 19;
const MAX_STACK_DEPTH: usize = 10;
const G_STEPS_PER_ROUND: usize = 16;
const G_STEPS_PER_COMPRESSION: usize = 7 * G_STEPS_PER_ROUND;
const FINALIZATION_ROWS: usize = 8;
const ROWS_PER_COMPRESSION: usize = G_STEPS_PER_COMPRESSION + FINALIZATION_ROWS;
const BYTES_PER_EVAL_ROW: usize = 8;
const LOW_EVALUATION_VARIABLES: usize = 3;
const ACTIVATION_HIGH_WEIGHT_WIDTH: usize = 3;
const WORD_BITS: usize = 32;
const MESSAGE_WORDS: usize = 16;
const CV_WORDS: usize = 8;
pub(crate) const FRI_LOG_BLOWUP: usize = 7;
// The smallest supported narrow trace has 2^8 rows. FRI requires the final
// polynomial degree to remain strictly below the trace degree, so seven is the
// largest single consensus value that is valid for every supported shape.
pub(crate) const FRI_LOG_FINAL_POLY_LEN: usize = 7;
pub(crate) const FRI_MAX_LOG_ARITY: usize = 4;
pub(crate) const FRI_QUERIES: usize = 33;
pub(crate) const FRI_COMMIT_POW_BITS: usize = 0;
pub(crate) const FRI_QUERY_POW_BITS: usize = 18;
#[cfg(feature = "gpu-proof-prover")]
const STREAM_CHUNK_ROWS: usize = 1 << 16;
#[cfg(feature = "gpu-proof-prover")]
static NEXT_STREAM_ARTIFACT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "gpu-proof-prover")]
static NEXT_MERKLE_ARTIFACT: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
std::thread_local! {
    static PREPROCESSED_TRACE_FORBIDDEN: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

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
#[cfg(not(feature = "gpu-proof-prover"))]
type InputMmcs = ValMmcs;
#[cfg(feature = "gpu-proof-prover")]
type InputMmcs = NarrowInputMmcs;
#[cfg(not(feature = "gpu-proof-prover"))]
type StoredLde = RowMajorMatrix<F>;
#[cfg(feature = "gpu-proof-prover")]
type StoredLde = NarrowStoredLde;
type InnerPcs = TwoAdicFriPcs<F, NarrowDft, InputMmcs, ChallengeMmcs, StoredLde>;
type Pcs = NarrowPcs;
pub(crate) type Config = StarkConfig<Pcs, EF, Challenger>;
pub(crate) type NativeProof = Proof<Config>;

#[cfg(feature = "gpu-proof-prover")]
#[derive(Clone, Debug)]
pub(crate) enum NarrowStoredLde {
    Memory(RowMajorMatrix<F>),
    Authenticated(cmfd_proof_accel::spill::AuthenticatedLdeMatrix),
}

#[cfg(feature = "gpu-proof-prover")]
impl NarrowStoredLde {
    fn as_memory(&self) -> Option<&RowMajorMatrix<F>> {
        match self {
            Self::Memory(matrix) => Some(matrix),
            Self::Authenticated(_) => None,
        }
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl Matrix<F> for NarrowStoredLde {
    fn width(&self) -> usize {
        match self {
            Self::Memory(matrix) => matrix.width(),
            Self::Authenticated(matrix) => matrix.width(),
        }
    }

    fn height(&self) -> usize {
        match self {
            Self::Memory(matrix) => matrix.height(),
            Self::Authenticated(matrix) => matrix.height(),
        }
    }

    unsafe fn row_subseq_unchecked(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> impl IntoIterator<Item = F, IntoIter = impl Iterator<Item = F> + Send + Sync> {
        match self {
            Self::Memory(matrix) => unsafe {
                matrix
                    .row_subseq_unchecked(row, start, end)
                    .into_iter()
                    .collect::<Vec<_>>()
            },
            Self::Authenticated(matrix) => unsafe {
                matrix
                    .row_subseq_unchecked(row, start, end)
                    .into_iter()
                    .collect::<Vec<_>>()
            },
        }
        .into_iter()
    }
}

#[cfg(feature = "gpu-proof-prover")]
pub(crate) struct NarrowStoredLdePrefix<'a> {
    matrix: &'a NarrowStoredLde,
    height: usize,
}

#[cfg(feature = "gpu-proof-prover")]
impl Matrix<F> for NarrowStoredLdePrefix<'_> {
    fn width(&self) -> usize {
        self.matrix.width()
    }

    fn height(&self) -> usize {
        self.height
    }

    unsafe fn row_subseq_unchecked(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> impl IntoIterator<Item = F, IntoIter = impl Iterator<Item = F> + Send + Sync> {
        unsafe {
            self.matrix
                .row_subseq_unchecked(row, start, end)
                .into_iter()
                .collect::<Vec<_>>()
                .into_iter()
        }
    }
}

#[cfg(feature = "gpu-proof-prover")]
pub(crate) enum NarrowStoredEvaluations<'a> {
    Borrowed(BitReversedMatrixView<NarrowStoredLdePrefix<'a>>),
    Owned(BitReversedMatrixView<RowMajorMatrix<F>>),
}

#[cfg(feature = "gpu-proof-prover")]
impl Matrix<F> for NarrowStoredEvaluations<'_> {
    fn width(&self) -> usize {
        match self {
            Self::Borrowed(matrix) => matrix.width(),
            Self::Owned(matrix) => matrix.width(),
        }
    }

    fn height(&self) -> usize {
        match self {
            Self::Borrowed(matrix) => matrix.height(),
            Self::Owned(matrix) => matrix.height(),
        }
    }

    unsafe fn row_subseq_unchecked(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> impl IntoIterator<Item = F, IntoIter = impl Iterator<Item = F> + Send + Sync> {
        match self {
            Self::Borrowed(matrix) => unsafe {
                matrix
                    .row_subseq_unchecked(row, start, end)
                    .into_iter()
                    .collect::<Vec<_>>()
            },
            Self::Owned(matrix) => unsafe {
                matrix
                    .row_subseq_unchecked(row, start, end)
                    .into_iter()
                    .collect::<Vec<_>>()
            },
        }
        .into_iter()
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl FriLdeMatrix<F> for NarrowStoredLde {
    type EvaluationsOnDomain<'a> = NarrowStoredEvaluations<'a>;

    fn from_bit_reversed_row_major(lde: RowMajorMatrix<F>) -> Self {
        Self::Memory(lde)
    }

    fn evaluations_from_prefix(&self, height: usize) -> Self::EvaluationsOnDomain<'_> {
        assert!(height <= self.height());
        NarrowStoredEvaluations::Borrowed(BitReversalPerm::new_view(NarrowStoredLdePrefix {
            matrix: self,
            height,
        }))
    }

    fn evaluations_from_owned<'a>(evaluations: RowMajorMatrix<F>) -> Self::EvaluationsOnDomain<'a> {
        NarrowStoredEvaluations::Owned(evaluations.bit_reverse_rows())
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl cmfd_proof_accel::merkle_store::MerkleRowSource for NarrowStoredLde {
    fn height(&self) -> usize {
        Matrix::height(self)
    }

    fn width(&self) -> usize {
        Matrix::width(self)
    }

    fn read_row(
        &self,
        row: usize,
    ) -> Result<Vec<u64>, cmfd_proof_accel::merkle_store::MerkleStoreError> {
        self.read_rows(row, 1)
    }

    fn read_rows(
        &self,
        row_start: usize,
        row_count: usize,
    ) -> Result<Vec<u64>, cmfd_proof_accel::merkle_store::MerkleStoreError> {
        match self {
            Self::Memory(matrix) => {
                let row_end = row_start.checked_add(row_count).ok_or(
                    cmfd_proof_accel::merkle_store::MerkleStoreError::Invalid(
                        "matrix row range overflow",
                    ),
                )?;
                if row_count == 0 || row_end > matrix.height() {
                    return Err(cmfd_proof_accel::merkle_store::MerkleStoreError::Invalid(
                        "matrix row range is out of bounds",
                    ));
                }
                Ok((row_start..row_end)
                    .flat_map(|row| unsafe { matrix.row_unchecked(row) })
                    .map(|value| value.as_canonical_u64())
                    .collect())
            }
            Self::Authenticated(matrix) => matrix
                .read_canonical_rows(row_start, row_count)
                .map_err(|error| {
                    cmfd_proof_accel::merkle_store::MerkleStoreError::Source(error.to_string())
                }),
        }
    }
}

#[cfg(feature = "gpu-proof-prover")]
#[derive(Clone)]
pub(crate) struct NarrowInputMmcs {
    cpu: ValMmcs,
    use_disk: bool,
    disk_hash: NarrowBinaryMerkleHash,
    spill_dir: Option<Arc<std::path::PathBuf>>,
}

#[cfg(feature = "gpu-proof-prover")]
impl NarrowInputMmcs {
    #[cfg(test)]
    fn new(cpu: ValMmcs, use_disk: bool) -> Self {
        Self::new_with_spill_dir(cpu, use_disk, None)
    }

    fn new_with_spill_dir(
        cpu: ValMmcs,
        use_disk: bool,
        spill_dir: Option<Arc<std::path::PathBuf>>,
    ) -> Self {
        Self {
            cpu,
            use_disk,
            disk_hash: NarrowBinaryMerkleHash::new(),
            spill_dir,
        }
    }

    fn commit_stored_with_first_digest_layer(
        &self,
        matrices: Vec<NarrowStoredLde>,
        first_digests: Option<&dyn cmfd_proof_accel::merkle_store::MerkleRowSource>,
    ) -> (
        <Self as Mmcs<F>>::Commitment,
        <Self as Mmcs<F>>::ProverData<NarrowStoredLde>,
    ) {
        if !self.use_disk {
            assert!(
                first_digests.is_none(),
                "prehashed Merkle leaves require authenticated disk prover data"
            );
            let (commitment, data) = self.cpu.commit(matrices);
            return (commitment, NarrowMmcsProverData::Memory(data));
        }
        let sequence = NEXT_MERKLE_ARTIFACT.fetch_add(1, Ordering::Relaxed);
        let mut identity = blake3::Hasher::new();
        identity.update(b"CMFD-NARROW-MERKLE-STORE-V1");
        identity.update(&sequence.to_le_bytes());
        identity.update(&(matrices.len() as u64).to_le_bytes());
        for matrix in &matrices {
            identity.update(&(matrix.height() as u64).to_le_bytes());
            identity.update(&(matrix.width() as u64).to_le_bytes());
            if let NarrowStoredLde::Authenticated(matrix) = matrix {
                identity.update(&matrix.artifact().digest());
                identity.update(&(matrix.column_start() as u64).to_le_bytes());
            }
        }
        if let Some(first_digests) = first_digests {
            identity.update(b"PREHASHED-FIRST-LAYER");
            identity.update(&(first_digests.height() as u64).to_le_bytes());
            identity.update(&(first_digests.width() as u64).to_le_bytes());
        }
        let store_id = *identity.finalize().as_bytes();
        let artifact_dir =
            proof_artifact_dir(self.spill_dir.as_deref().map(std::path::PathBuf::as_path));
        let store_path = artifact_dir.join(format!(
            "{}-{sequence}-{}.merkle",
            std::process::id(),
            hex::encode(store_id)
        ));
        let sources = matrices
            .iter()
            .map(|matrix| matrix as &dyn cmfd_proof_accel::merkle_store::MerkleRowSource)
            .collect::<Vec<_>>();
        let store = match first_digests {
            Some(first_digests) => {
                cmfd_proof_accel::merkle_store::build_authenticated_merkle_store_with_first_digest_layer(
                    &store_path,
                    store_id,
                    &sources,
                    first_digests,
                    0,
                    &self.disk_hash,
                )
            }
            None => cmfd_proof_accel::merkle_store::build_authenticated_merkle_store(
                &store_path,
                store_id,
                &sources,
                0,
                &self.disk_hash,
            ),
        }
        .unwrap_or_else(|error| panic!("building authenticated Merkle store failed: {error}"))
        .remove_on_drop();
        let commitment = MerkleCap::new(
            store
                .cap()
                .unwrap_or_else(|error| panic!("reading authenticated Merkle cap failed: {error}"))
                .into_iter()
                .map(digest_from_canonical_words)
                .collect(),
        );
        (
            commitment,
            NarrowMmcsProverData::Disk {
                matrices,
                store: Box::new(store),
            },
        )
    }
}

#[cfg(feature = "gpu-proof-prover")]
pub(crate) enum NarrowMmcsProverData<M> {
    Memory(<ValMmcs as Mmcs<F>>::ProverData<M>),
    Disk {
        matrices: Vec<M>,
        store: Box<cmfd_proof_accel::merkle_store::AuthenticatedMerkleStore>,
    },
}

#[cfg(feature = "gpu-proof-prover")]
impl Mmcs<F> for NarrowInputMmcs {
    type ProverData<M> = NarrowMmcsProverData<M>;
    type Commitment = <ValMmcs as Mmcs<F>>::Commitment;
    type Proof = <ValMmcs as Mmcs<F>>::Proof;
    type Error = <ValMmcs as Mmcs<F>>::Error;

    fn commit<M: Matrix<F>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        let (commitment, data) = self.cpu.commit(inputs);
        (commitment, NarrowMmcsProverData::Memory(data))
    }

    fn open_batch<M: Matrix<F>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<F, Self> {
        match prover_data {
            NarrowMmcsProverData::Memory(data) => {
                let (opened_values, opening_proof) = self.cpu.open_batch(index, data).unpack();
                BatchOpening::new(opened_values, opening_proof)
            }
            NarrowMmcsProverData::Disk { matrices, store } => {
                let row_indices = store.matrix_row_indices(index).unwrap_or_else(|error| {
                    panic!("reading authenticated Merkle row indices failed: {error}")
                });
                let opened_values = matrices
                    .iter()
                    .zip(row_indices)
                    .map(|(matrix, row)| {
                        matrix
                            .row(row)
                            .expect("authenticated Merkle row index is in bounds")
                            .into_iter()
                            .collect()
                    })
                    .collect();
                let opening_proof = store
                    .opening_path(index)
                    .unwrap_or_else(|error| {
                        panic!("reading authenticated Merkle opening failed: {error}")
                    })
                    .into_iter()
                    .map(digest_from_canonical_words)
                    .collect();
                BatchOpening::new(opened_values, opening_proof)
            }
        }
    }

    fn get_matrices<'a, M: Matrix<F>>(&self, prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        match prover_data {
            NarrowMmcsProverData::Memory(data) => self.cpu.get_matrices(data),
            NarrowMmcsProverData::Disk { matrices, .. } => matrices.iter().collect(),
        }
    }

    fn verify_batch(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[p3_matrix::Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, F, Self>,
    ) -> Result<(), Self::Error> {
        self.cpu.verify_batch(
            commitment,
            dimensions,
            index,
            BatchOpeningRef::new(opening.opened_values, opening.opening_proof),
        )
    }
}

#[cfg(feature = "gpu-proof-prover")]
#[derive(Clone)]
struct NarrowBinaryMerkleHash {
    hash: FieldHash,
    compress: Compress,
}

#[cfg(feature = "gpu-proof-prover")]
impl NarrowBinaryMerkleHash {
    fn new() -> Self {
        let permutation = default_poseidon2();
        Self {
            hash: FieldHash::new(permutation.clone()),
            compress: Compress::new(permutation),
        }
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl cmfd_proof_accel::merkle_store::BinaryMerkleHash for NarrowBinaryMerkleHash {
    fn hash_row(&self, values: &[u64]) -> [u64; 4] {
        digest_to_canonical_words(self.hash.hash_iter(values.iter().copied().map(F::new)))
    }

    fn compress(&self, children: [[u64; 4]; 2]) -> [u64; 4] {
        digest_to_canonical_words(
            self.compress
                .compress(children.map(digest_from_canonical_words)),
        )
    }
}

#[cfg(feature = "gpu-proof-prover")]
fn digest_to_canonical_words(digest: [F; 4]) -> [u64; 4] {
    digest.map(|word| word.as_canonical_u64())
}

#[cfg(feature = "gpu-proof-prover")]
fn digest_from_canonical_words(digest: [u64; 4]) -> [F; 4] {
    digest.map(F::new)
}

#[derive(Clone, Default)]
struct NarrowCommitBackend {
    #[cfg(feature = "gpu-proof-prover")]
    poseidon2: Option<cmfd_proof_accel::CudaProofPoseidon2>,
    #[cfg(feature = "gpu-proof-prover")]
    spill_dir: Option<Arc<std::path::PathBuf>>,
}

impl NarrowCommitBackend {
    #[cfg(feature = "gpu-proof-prover")]
    fn load_cuda(
        library_path: impl AsRef<std::path::Path>,
        device_index: i32,
    ) -> Result<Self, NarrowBlake3Error> {
        cmfd_proof_accel::CudaProofPoseidon2::load(library_path, device_index)
            .map(|poseidon2| Self {
                poseidon2: Some(poseidon2),
                spill_dir: None,
            })
            .map_err(|error| NarrowBlake3Error::Accelerator(error.to_string()))
    }

    #[cfg(feature = "gpu-proof-prover")]
    fn load_cuda_in_spill_dir(
        library_path: impl AsRef<std::path::Path>,
        device_index: i32,
        spill_dir: impl AsRef<std::path::Path>,
    ) -> Result<Self, NarrowBlake3Error> {
        let spill_dir = spill_dir.as_ref();
        if !spill_dir.is_absolute() {
            return Err(NarrowBlake3Error::Accelerator(
                "proof spill directory must be absolute".to_owned(),
            ));
        }
        if !spill_dir.is_dir() {
            return Err(NarrowBlake3Error::Accelerator(
                "proof spill directory must already exist".to_owned(),
            ));
        }
        cmfd_proof_accel::CudaProofPoseidon2::load(library_path, device_index)
            .map(|poseidon2| Self {
                poseidon2: Some(poseidon2),
                spill_dir: Some(Arc::new(spill_dir.to_path_buf())),
            })
            .map_err(|error| NarrowBlake3Error::Accelerator(error.to_string()))
    }
}

#[cfg(feature = "gpu-proof-prover")]
fn proof_artifact_dir(explicit: Option<&std::path::Path>) -> std::path::PathBuf {
    if let Some(explicit) = explicit {
        assert!(
            explicit.is_absolute(),
            "proof spill directory must be absolute"
        );
        assert!(
            explicit.is_dir(),
            "proof spill directory must already exist"
        );
        return explicit.to_path_buf();
    }

    let artifact_dir = std::env::temp_dir().join("commonfoundry-proof-spill");
    std::fs::create_dir_all(&artifact_dir)
        .unwrap_or_else(|error| panic!("creating proof spill directory failed: {error}"));
    artifact_dir
}

#[derive(Clone)]
pub(crate) struct NarrowPcs {
    inner: InnerPcs,
    dft: NarrowDft,
    input_mmcs: InputMmcs,
    log_blowup: usize,
    #[cfg(feature = "gpu-proof-prover")]
    commit_backend: NarrowCommitBackend,
}

/// Exact proof DFT seam. Its default is always the CPU reference; CUDA is
/// available only through the explicit accelerated-prover entry point.
#[derive(Clone, Default)]
pub(crate) struct NarrowDft {
    backend: NarrowDftBackend,
}

impl NarrowDft {
    #[cfg(feature = "gpu-proof-prover")]
    pub(crate) fn load_cuda(
        library_path: impl AsRef<std::path::Path>,
        device_index: i32,
    ) -> Result<Self, NarrowBlake3Error> {
        cmfd_proof_accel::ProofDft::load_cuda(library_path, device_index)
            .map(|backend| Self { backend })
            .map_err(|error| NarrowBlake3Error::Accelerator(error.to_string()))
    }

    #[cfg(all(test, feature = "gpu-proof-prover"))]
    fn is_cuda(&self) -> bool {
        self.backend.is_cuda()
    }
}

impl TwoAdicSubgroupDft<F> for NarrowDft {
    type Evaluations = BitReversedMatrixView<RowMajorMatrix<F>>;

    fn dft_batch(&self, mat: RowMajorMatrix<F>) -> Self::Evaluations {
        self.backend.dft_batch(mat)
    }

    fn coset_dft_batch(&self, mat: RowMajorMatrix<F>, shift: F) -> Self::Evaluations {
        self.backend.coset_dft_batch(mat, shift)
    }

    fn coset_idft_batch(&self, mat: RowMajorMatrix<F>, shift: F) -> RowMajorMatrix<F> {
        self.backend.coset_idft_batch(mat, shift)
    }

    fn coset_lde_batch_with_transform<T>(
        &self,
        mat: RowMajorMatrix<F>,
        added_bits: usize,
        shift: F,
        transform: T,
    ) -> Self::Evaluations
    where
        T: FnOnce(&mut RowMajorMatrixViewMut<'_, F>, Layout),
    {
        self.backend
            .coset_lde_batch_with_transform(mat, added_bits, shift, transform)
    }
}

impl NarrowPcs {
    fn new(
        dft: NarrowDft,
        input_mmcs: ValMmcs,
        fri: FriParameters<ChallengeMmcs>,
        commit_backend: NarrowCommitBackend,
    ) -> Self {
        #[cfg(not(feature = "gpu-proof-prover"))]
        let _ = commit_backend;
        #[cfg(feature = "gpu-proof-prover")]
        let input_mmcs = NarrowInputMmcs::new_with_spill_dir(
            input_mmcs,
            commit_backend.poseidon2.is_some(),
            commit_backend.spill_dir.clone(),
        );
        Self {
            inner: InnerPcs::new_with_lde(dft.clone(), input_mmcs.clone(), fri),
            dft,
            input_mmcs,
            log_blowup: FRI_LOG_BLOWUP,
            #[cfg(feature = "gpu-proof-prover")]
            commit_backend,
        }
    }

    fn with_log_blowup(mut self, log_blowup: usize) -> Self {
        self.log_blowup = log_blowup;
        self
    }

    fn commit_stored_ldes(
        &self,
        ldes: Vec<StoredLde>,
    ) -> (
        <Self as PcsTrait<EF, Challenger>>::Commitment,
        <Self as PcsTrait<EF, Challenger>>::ProverData,
    ) {
        #[cfg(feature = "gpu-proof-prover")]
        return self.commit_stored_ldes_with_first_digest_layer(ldes, None);
        #[cfg(not(feature = "gpu-proof-prover"))]
        self.commit_stored_ldes_inner(ldes)
    }

    #[cfg(not(feature = "gpu-proof-prover"))]
    fn commit_stored_ldes_inner(
        &self,
        ldes: Vec<StoredLde>,
    ) -> (
        <Self as PcsTrait<EF, Challenger>>::Commitment,
        <Self as PcsTrait<EF, Challenger>>::ProverData,
    ) {
        let min_height = 1 << self.log_blowup;
        for lde in &ldes {
            assert!(
                lde.height() >= min_height,
                "committed LDE height {} is smaller than the blowup factor {min_height}",
                lde.height()
            );
        }

        self.input_mmcs.commit(ldes)
    }

    #[cfg(feature = "gpu-proof-prover")]
    fn commit_stored_ldes_with_first_digest_layer(
        &self,
        ldes: Vec<StoredLde>,
        first_digests: Option<&dyn cmfd_proof_accel::merkle_store::MerkleRowSource>,
    ) -> (
        <Self as PcsTrait<EF, Challenger>>::Commitment,
        <Self as PcsTrait<EF, Challenger>>::ProverData,
    ) {
        let min_height = 1 << self.log_blowup;
        for lde in &ldes {
            assert!(
                lde.height() >= min_height,
                "committed LDE height {} is smaller than the blowup factor {min_height}",
                lde.height()
            );
        }

        if first_digests.is_none()
            && let Some(poseidon2) = &self.commit_backend.poseidon2
        {
            let memory_ldes = ldes
                .iter()
                .map(NarrowStoredLde::as_memory)
                .collect::<Option<Vec<_>>>();
            if let Some(memory_ldes) = memory_ldes {
                let max_height = ldes
                    .iter()
                    .map(Matrix::height)
                    .max()
                    .expect("all matrices have height 0");
                let tallest = memory_ldes
                    .iter()
                    .copied()
                    .filter(|matrix| matrix.height() == max_height)
                    .collect::<Vec<_>>();
                let digest_matrix = poseidon2
                    .try_first_digest_layer_refs(&tallest)
                    .unwrap_or_else(|error| {
                        panic!("explicit proof Poseidon2 backend failed: {error}")
                    });
                debug_assert_eq!(digest_matrix.height(), max_height);
                debug_assert_eq!(digest_matrix.width, 4);
                let first_digests = digest_matrix
                    .values
                    .chunks_exact(4)
                    .map(|digest| [digest[0], digest[1], digest[2], digest[3]])
                    .collect();
                let (commitment, data) = self
                    .input_mmcs
                    .cpu
                    .commit_with_first_digest_layer(ldes, first_digests);
                return (commitment, NarrowMmcsProverData::Memory(data));
            }
        }

        self.input_mmcs
            .commit_stored_with_first_digest_layer(ldes, first_digests)
    }

    fn commit_bit_reversed_ldes(
        &self,
        ldes: Vec<RowMajorMatrix<F>>,
    ) -> (
        <Self as PcsTrait<EF, Challenger>>::Commitment,
        <Self as PcsTrait<EF, Challenger>>::ProverData,
    ) {
        #[cfg(feature = "gpu-proof-prover")]
        let ldes = ldes.into_iter().map(NarrowStoredLde::Memory).collect();
        self.commit_stored_ldes(ldes)
    }

    #[cfg(feature = "gpu-proof-prover")]
    fn commit_streamed_evaluations(
        &self,
        evaluations: impl IntoIterator<Item = (TwoAdicMultiplicativeCoset<F>, RowMajorMatrix<F>)>,
    ) -> (
        <Self as PcsTrait<EF, Challenger>>::Commitment,
        <Self as PcsTrait<EF, Challenger>>::ProverData,
    ) {
        let backend = self
            .commit_backend
            .poseidon2
            .as_ref()
            .expect("streamed commitments require the explicit CUDA backend");
        let coefficients = evaluations
            .into_iter()
            .map(|(domain, evaluations)| {
                assert_eq!(domain.size(), evaluations.height());
                let shift = F::GENERATOR / domain.shift();
                let coefficients = self
                    .dft
                    .idft_batch(evaluations)
                    .bit_reverse_rows()
                    .to_row_major_matrix();
                (coefficients, shift)
            })
            .collect::<Vec<_>>();
        assert!(!coefficients.is_empty(), "No matrices given?");
        let descriptors = coefficients
            .iter()
            .map(|(matrix, shift)| cmfd_proof_accel::CudaProofStreamMatrix::new(matrix, *shift))
            .collect::<Vec<_>>();
        let mut stream = cmfd_proof_accel::CudaProofStream::load(
            backend.library_path(),
            backend.device_index(),
            &descriptors,
            self.log_blowup,
        )
        .unwrap_or_else(|error| panic!("explicit proof stream backend failed: {error}"));
        let components = stream.components().to_vec();
        let job_id = streamed_lde_job_id(&coefficients, self.log_blowup);
        let digest_job_id = streamed_digest_job_id(job_id);
        let source_height = stream.source_height();
        let expanded_rows = stream.expanded_rows();
        let added_bits =
            u8::try_from(stream.added_bits()).expect("validated proof stream blowup fits u8");
        let stream_manifest = cmfd_proof_accel::spill::cuda_proof_stream_manifest(&stream);
        let artifact_dir = proof_artifact_dir(
            self.commit_backend
                .spill_dir
                .as_deref()
                .map(std::path::PathBuf::as_path),
        );
        let sequence = NEXT_STREAM_ARTIFACT.fetch_add(1, Ordering::Relaxed);
        let artifact_path = artifact_dir.join(format!(
            "{}-{sequence}-{}.lde",
            std::process::id(),
            hex::encode(job_id)
        ));
        let digest_artifact_path = artifact_dir.join(format!(
            "{}-{sequence}-{}.first-digests",
            std::process::id(),
            hex::encode(digest_job_id)
        ));
        let writer = cmfd_proof_accel::spill::LdeArtifactWriter::create(
            &artifact_path,
            cmfd_proof_accel::spill::LdeArtifactSpec {
                job_id,
                source_height,
                height: expanded_rows,
                width: u32::try_from(stream.total_width())
                    .expect("validated proof stream width fits u32"),
                added_bits,
                stream_manifest,
            },
        )
        .unwrap_or_else(|error| panic!("creating authenticated proof spill failed: {error}"));
        let mut digest_writer = cmfd_proof_accel::spill::LdeArtifactWriter::create(
            &digest_artifact_path,
            cmfd_proof_accel::spill::LdeArtifactSpec {
                job_id: digest_job_id,
                source_height,
                height: expanded_rows,
                width: 4,
                added_bits,
                stream_manifest,
            },
        )
        .unwrap_or_else(|error| {
            panic!("creating authenticated first-digest spill failed: {error}")
        });
        let source_height = usize::try_from(source_height)
            .expect("validated proof stream source height fits usize");
        let artifact = cmfd_proof_accel::spill::drain_cuda_proof_stream(
            &mut stream,
            writer,
            source_height.min(STREAM_CHUNK_ROWS),
            |row_start, _row_count, digests| digest_writer.write_rows(row_start, digests),
        )
        .unwrap_or_else(|error| panic!("streaming authenticated proof LDE failed: {error}"))
        .remove_on_drop();
        let digest_artifact = digest_writer
            .seal()
            .unwrap_or_else(|error| {
                panic!("sealing authenticated first-digest spill failed: {error}")
            })
            .remove_on_drop();
        let first_digests =
            cmfd_proof_accel::spill::AuthenticatedLdeMatrix::new(Arc::new(digest_artifact))
                .unwrap_or_else(|error| {
                    panic!("opening authenticated first-digest spill failed: {error}")
                });
        let matrices = cmfd_proof_accel::spill::AuthenticatedLdeMatrix::from_stream_components(
            Arc::new(artifact),
            &components,
        )
        .unwrap_or_else(|error| panic!("opening authenticated proof LDE failed: {error}"))
        .into_iter()
        .map(NarrowStoredLde::Authenticated)
        .collect();
        self.commit_stored_ldes_with_first_digest_layer(matrices, Some(&first_digests))
    }
}

#[cfg(feature = "gpu-proof-prover")]
fn streamed_lde_job_id(coefficients: &[(RowMajorMatrix<F>, F)], added_bits: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CMFD-NARROW-STREAMED-LDE-JOB-V1");
    hasher.update(&(added_bits as u64).to_le_bytes());
    hasher.update(&(coefficients.len() as u64).to_le_bytes());
    for (matrix, shift) in coefficients {
        hasher.update(&(matrix.height() as u64).to_le_bytes());
        hasher.update(&(matrix.width as u64).to_le_bytes());
        hasher.update(&shift.as_canonical_u64().to_le_bytes());
        for value in &matrix.values {
            hasher.update(&value.as_canonical_u64().to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

#[cfg(feature = "gpu-proof-prover")]
fn streamed_digest_job_id(lde_job_id: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CMFD-NARROW-STREAMED-FIRST-DIGESTS-V1");
    hasher.update(&lde_job_id);
    *hasher.finalize().as_bytes()
}

impl BuildPeriodicLdeTableFast for NarrowPcs {
    type PeriodicDomain = TwoAdicMultiplicativeCoset<F>;

    fn maybe_build_periodic_lde_table_fast(
        &self,
        periodic_cols: &[Vec<F>],
        trace_domain: Self::PeriodicDomain,
        quotient_domain: Self::PeriodicDomain,
    ) -> Option<PeriodicLdeTable<F>>
    where
        F: Clone,
    {
        self.inner
            .maybe_build_periodic_lde_table_fast(periodic_cols, trace_domain, quotient_domain)
    }
}

impl PcsTrait<EF, Challenger> for NarrowPcs {
    type Domain = TwoAdicMultiplicativeCoset<F>;
    type Commitment = <InnerPcs as PcsTrait<EF, Challenger>>::Commitment;
    type ProverData = <InnerPcs as PcsTrait<EF, Challenger>>::ProverData;
    type EvaluationsOnDomain<'a> = <InnerPcs as PcsTrait<EF, Challenger>>::EvaluationsOnDomain<'a>;
    type Proof = <InnerPcs as PcsTrait<EF, Challenger>>::Proof;
    type Error = <InnerPcs as PcsTrait<EF, Challenger>>::Error;
    const ZK: bool = <InnerPcs as PcsTrait<EF, Challenger>>::ZK;

    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        <InnerPcs as PcsTrait<EF, Challenger>>::natural_domain_for_degree(&self.inner, degree)
    }

    fn log_max_lde_height(&self) -> usize {
        <InnerPcs as PcsTrait<EF, Challenger>>::log_max_lde_height(&self.inner)
    }

    fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<F>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        #[cfg(feature = "gpu-proof-prover")]
        if self.commit_backend.poseidon2.is_some() {
            return self.commit_streamed_evaluations(evaluations);
        }
        let ldes = evaluations
            .into_iter()
            .map(|(domain, evaluations)| {
                assert_eq!(domain.size(), evaluations.height());
                let shift = F::GENERATOR / domain.shift();
                self.dft
                    .coset_lde_batch(evaluations, self.log_blowup, shift)
                    .bit_reverse_rows()
                    .to_row_major_matrix()
            })
            .collect();
        self.commit_bit_reversed_ldes(ldes)
    }

    fn commit_quotient(
        &self,
        quotient_domain: Self::Domain,
        quotient_evaluations: RowMajorMatrix<F>,
        num_chunks: usize,
    ) -> (Self::Commitment, Self::ProverData) {
        let quotient_sub_evaluations =
            quotient_domain.split_evals(num_chunks, quotient_evaluations);
        let quotient_sub_domains = quotient_domain.split_domains(num_chunks);
        #[cfg(feature = "gpu-proof-prover")]
        if self.commit_backend.poseidon2.is_some() {
            return self.commit_streamed_evaluations(
                quotient_sub_domains
                    .into_iter()
                    .zip(quotient_sub_evaluations),
            );
        }
        let ldes = self.get_quotient_ldes(
            quotient_sub_domains
                .into_iter()
                .zip(quotient_sub_evaluations),
            num_chunks,
        );
        self.commit_ldes(ldes)
    }

    fn get_quotient_ldes(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<F>)>,
        num_chunks: usize,
    ) -> Vec<RowMajorMatrix<F>> {
        <InnerPcs as PcsTrait<EF, Challenger>>::get_quotient_ldes(
            &self.inner,
            evaluations,
            num_chunks,
        )
    }

    fn commit_ldes(&self, ldes: Vec<RowMajorMatrix<F>>) -> (Self::Commitment, Self::ProverData) {
        self.commit_bit_reversed_ldes(ldes)
    }

    fn get_evaluations_on_domain<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        index: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        <InnerPcs as PcsTrait<EF, Challenger>>::get_evaluations_on_domain(
            &self.inner,
            prover_data,
            index,
            domain,
        )
    }

    fn open(
        &self,
        commitment_data_with_opening_points: Vec<(&Self::ProverData, Vec<Vec<EF>>)>,
        challenger: &mut Challenger,
    ) -> (OpenedValues<EF>, Self::Proof) {
        self.inner
            .open(commitment_data_with_opening_points, challenger)
    }

    fn verify(
        &self,
        commitments_with_opening_points: Vec<(
            Self::Commitment,
            Vec<(Self::Domain, Vec<(EF, Vec<EF>)>)>,
        )>,
        proof: &Self::Proof,
        challenger: &mut Challenger,
    ) -> Result<(), Self::Error> {
        self.inner
            .verify(commitments_with_opening_points, proof, challenger)
    }
}

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
    #[error("narrow BLAKE3 tree pinned preprocessed key is missing or malformed")]
    PinnedPreprocessedKeyInvalid,
    #[error("narrow BLAKE3 tree preprocessed commitment does not match the pinned key")]
    PinnedPreprocessedKeyMismatch,
    #[cfg(feature = "gpu-proof-prover")]
    #[error("narrow BLAKE3 tree accelerator setup failed: {0}")]
    Accelerator(String),
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
#[cfg(feature = "dory-bls12-381-prototype")]
pub(crate) const NARROW_BLAKE3_MAIN_WIDTH: usize = MAIN_WIDTH;
#[cfg(feature = "dory-bls12-381-prototype")]
pub(crate) const NARROW_BLAKE3_ORIGINAL_NIBBLES_START: usize =
    std::mem::offset_of!(MainCols<u8>, original_nibbles);
#[cfg(feature = "dory-bls12-381-prototype")]
pub(crate) const NARROW_BLAKE3_EVALUATION_ACCUMULATOR_START: usize =
    std::mem::offset_of!(MainCols<u8>, evaluation_accumulator);
#[cfg(feature = "dory-bls12-381-prototype")]
pub(crate) const NARROW_BLAKE3_STACK_START: usize = std::mem::offset_of!(MainCols<u8>, stack);

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
#[cfg(feature = "dory-bls12-381-prototype")]
// Rust 1.88 does not count the combined-path anonymous const assertion as a use.
#[allow(dead_code)]
pub(crate) const NARROW_BLAKE3_PREPROCESSED_WIDTH: usize = PREP_WIDTH;
#[cfg(feature = "dory-bls12-381-prototype")]
pub(crate) const NARROW_BLAKE3_PREPROCESSED_WORD_COLUMNS: [usize; 4] = [
    std::mem::offset_of!(PrepCols<u8>, counter_low),
    std::mem::offset_of!(PrepCols<u8>, counter_high),
    std::mem::offset_of!(PrepCols<u8>, block_len),
    std::mem::offset_of!(PrepCols<u8>, flags),
];

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
    schedule: Arc<Blake3TreeWitness>,
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
        let dummy = vec![0_u8; statement.final_activation_len];
        let schedule = build_tree_witness(OUTPUT_CONTEXT, [0; 32], &dummy)?;
        let operation_count = operation_count(statement.final_activation_len)?;
        debug_assert_eq!(schedule.operations.len(), operation_count);
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
            schedule: Arc::new(schedule),
        })
    }

    #[cfg(feature = "dory-bls12-381-prototype")]
    pub(crate) const fn trace_rows(&self) -> usize {
        self.trace_rows
    }

    #[cfg(feature = "dory-bls12-381-prototype")]
    pub(crate) fn activation_group_index_at_row(&self, row_index: usize) -> Option<usize> {
        let operation_index = row_index / ROWS_PER_COMPRESSION;
        let step = row_index % ROWS_PER_COMPRESSION;
        let message_offset = self
            .schedule
            .operations
            .get(operation_index)
            .and_then(|operation| operation.message_offset);
        activation_group_index(self.activation_len, message_offset, step)
    }

    fn activation_high_weight_at_row(
        &self,
        row_index: usize,
    ) -> crate::structured_sumcheck::ExtensionField {
        let operation_index = row_index / ROWS_PER_COMPRESSION;
        let step = row_index % ROWS_PER_COMPRESSION;
        let message_offset = self
            .schedule
            .operations
            .get(operation_index)
            .and_then(|operation| operation.message_offset);
        activation_high_weight(self.activation_len, &self.point, message_offset, step)
            .unwrap_or(crate::structured_sumcheck::ExtensionField::ZERO)
    }
}

impl BaseAir<F> for NarrowBlake3Air {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        #[cfg(test)]
        PREPROCESSED_TRACE_FORBIDDEN.with(|forbidden| {
            assert!(
                !forbidden.get(),
                "verifier must not materialize the preprocessed trace"
            );
        });
        Some(generate_preprocessed(self))
    }

    fn preprocessed_width(&self) -> usize {
        PREP_WIDTH
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn num_periodic_columns(&self) -> usize {
        ACTIVATION_HIGH_WEIGHT_WIDTH
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let mut columns: [Vec<F>; ACTIVATION_HIGH_WEIGHT_WIDTH] =
            array::from_fn(|_| F::zero_vec(self.trace_rows));
        for (operation_index, operation) in self.schedule.operations.iter().enumerate() {
            for step in 0..BYTES_PER_EVAL_ROW {
                let row_index = operation_index * ROWS_PER_COMPRESSION + step;
                if row_index >= self.trace_rows {
                    break;
                }
                let Some(weight) = activation_high_weight(
                    self.activation_len,
                    &self.point,
                    operation.message_offset,
                    step,
                ) else {
                    continue;
                };
                let mut limbs = [F::ZERO; ACTIVATION_HIGH_WEIGHT_WIDTH];
                set_ext(&mut limbs, weight);
                for limb in 0..ACTIVATION_HIGH_WEIGHT_WIDTH {
                    columns[limb][row_index] = limbs[limb];
                }
            }
        }
        columns.into_iter().collect()
    }

    fn periodic_values(&self, row_index: usize) -> Vec<F> {
        let mut limbs = [F::ZERO; ACTIVATION_HIGH_WEIGHT_WIDTH];
        set_ext(&mut limbs, self.activation_high_weight_at_row(row_index));
        limbs.into()
    }

    fn num_public_values(&self) -> usize {
        72 + 3 * self.point_variables + 3
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(16)
    }
}

fn pinned_preprocessed_verifier_key(
    air: &NarrowBlake3Air,
) -> Result<PreprocessedVerifierKey<Config>, NarrowBlake3Error> {
    let entry = pinned_preprocessed_key(air.activation_len, air.trace_rows)
        .ok_or(NarrowBlake3Error::PinnedPreprocessedKeyInvalid)?;
    if entry.activation_len != air.activation_len
        || entry.trace_rows != air.trace_rows
        || PINNED_PREPROCESSED_WIDTH != PREP_WIDTH
    {
        return Err(NarrowBlake3Error::PinnedPreprocessedKeyInvalid);
    }

    let mut root = [F::ZERO; 4];
    for (field_word, canonical_word) in root.iter_mut().zip(entry.root) {
        *field_word = F::from_canonical_checked(canonical_word)
            .ok_or(NarrowBlake3Error::PinnedPreprocessedKeyInvalid)?;
    }
    let commitment: <Pcs as PcsTrait<EF, Challenger>>::Commitment = MerkleCap::new(vec![root]);

    Ok(PreprocessedVerifierKey {
        width: PINNED_PREPROCESSED_WIDTH,
        degree_bits: air.trace_rows.ilog2() as usize,
        commitment,
    })
}

fn require_matching_preprocessed_key(
    generated: &PreprocessedVerifierKey<Config>,
    pinned: &PreprocessedVerifierKey<Config>,
) -> Result<(), NarrowBlake3Error> {
    if generated.width == pinned.width
        && generated.degree_bits == pinned.degree_bits
        && generated.commitment == pinned.commitment
    {
        Ok(())
    } else {
        Err(NarrowBlake3Error::PinnedPreprocessedKeyMismatch)
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
        constrain_evaluation(builder, &local, &next, self.point_variables);
        constrain_links(builder, &local, &next, &prep);
    }
}

#[cfg(test)]
pub(crate) fn prove_narrow_blake3(
    statement: &StructuredBlake3Statement,
    activation: &[u8],
) -> Result<Vec<u8>, NarrowBlake3Error> {
    prove_narrow_blake3_with_dft(statement, activation, NarrowDft::default())
}

pub(crate) fn prove_narrow_blake3_with_dft(
    statement: &StructuredBlake3Statement,
    activation: &[u8],
    dft: NarrowDft,
) -> Result<Vec<u8>, NarrowBlake3Error> {
    prove_narrow_blake3_with_backends(statement, activation, dft, NarrowCommitBackend::default())
}

#[cfg(feature = "gpu-proof-prover")]
pub(crate) fn prove_narrow_blake3_with_cuda(
    statement: &StructuredBlake3Statement,
    activation: &[u8],
    dft: NarrowDft,
    library_path: impl AsRef<std::path::Path>,
    device_index: i32,
) -> Result<Vec<u8>, NarrowBlake3Error> {
    let commit_backend = NarrowCommitBackend::load_cuda(library_path, device_index)?;
    prove_narrow_blake3_with_backends(statement, activation, dft, commit_backend)
}

#[cfg(feature = "gpu-proof-prover")]
pub(crate) fn prove_narrow_blake3_with_cuda_in_spill_dir(
    statement: &StructuredBlake3Statement,
    activation: &[u8],
    dft: NarrowDft,
    library_path: impl AsRef<std::path::Path>,
    device_index: i32,
    spill_dir: impl AsRef<std::path::Path>,
) -> Result<Vec<u8>, NarrowBlake3Error> {
    let commit_backend =
        NarrowCommitBackend::load_cuda_in_spill_dir(library_path, device_index, spill_dir)?;
    prove_narrow_blake3_with_backends(statement, activation, dft, commit_backend)
}

fn prove_narrow_blake3_with_backends(
    statement: &StructuredBlake3Statement,
    activation: &[u8],
    dft: NarrowDft,
    commit_backend: NarrowCommitBackend,
) -> Result<Vec<u8>, NarrowBlake3Error> {
    let air = NarrowBlake3Air::new(statement)?;
    let pinned_key = pinned_preprocessed_verifier_key(&air)?;
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
    let config = build_config_with_backends(dft, commit_backend);
    let log_rows = air.trace_rows.ilog2() as usize;
    let proof = catch_unwind(AssertUnwindSafe(
        || -> Result<NativeProof, NarrowBlake3Error> {
            let (prep, generated_key) = setup_preprocessed(&config, &air, log_rows)
                .expect("narrow BLAKE3 AIR has preprocessed columns");
            require_matching_preprocessed_key(&generated_key, &pinned_key)?;
            Ok(prove_with_preprocessed(
                &config,
                &air,
                trace,
                &public,
                Some(&prep),
            ))
        },
    ))
    .map_err(|_| NarrowBlake3Error::BackendPanic)??;
    encode_native_proof(proof)
}

pub(crate) fn verify_narrow_blake3(
    statement: &StructuredBlake3Statement,
    bytes: &[u8],
) -> Result<(), NarrowBlake3Error> {
    let air = NarrowBlake3Air::new(statement)?;
    let proof = decode_native_proof(bytes)?;
    let config = build_config();
    let verifier_key = pinned_preprocessed_verifier_key(&air)?;
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
    point_variables: usize,
) {
    let public = builder.public_values().to_vec();
    let periodic = builder.periodic_values().to_vec();
    debug_assert_eq!(periodic.len(), ACTIVATION_HIGH_WEIGHT_WIDTH);
    let high_weight = ExtExpr(array::from_fn(|limb| periodic[limb].into()));
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

fn activation_high_weight(
    activation_len: usize,
    point: &[crate::structured_sumcheck::ExtensionField],
    message_offset: Option<usize>,
    step: usize,
) -> Option<crate::structured_sumcheck::ExtensionField> {
    let activation_index = activation_group_index(activation_len, message_offset, step)?;
    let mut weight = crate::structured_sumcheck::ExtensionField::ONE;
    for (variable, coordinate) in point.iter().enumerate().skip(LOW_EVALUATION_VARIABLES) {
        let factor = if (activation_index >> variable) & 1 == 1 {
            *coordinate
        } else {
            crate::structured_sumcheck::ExtensionField::ONE.sub(*coordinate)
        };
        weight = weight.mul(factor);
    }
    Some(weight)
}

fn activation_group_index(
    activation_len: usize,
    message_offset: Option<usize>,
    step: usize,
) -> Option<usize> {
    if step >= BYTES_PER_EVAL_ROW {
        return None;
    }
    let activation_start = 40_usize;
    let activation_end = activation_start.checked_add(activation_len)?;
    let evaluation_offset = message_offset?.checked_add(step.checked_mul(BYTES_PER_EVAL_ROW)?)?;
    let evaluation_end = evaluation_offset.checked_add(BYTES_PER_EVAL_ROW)?;
    if evaluation_offset < activation_start || evaluation_end > activation_end {
        return None;
    }
    Some(evaluation_offset - activation_start)
}

fn generate_preprocessed(air: &NarrowBlake3Air) -> RowMajorMatrix<F> {
    let mut values = Vec::with_capacity(air.trace_rows * PREP_WIDTH);
    for_each_canonical_preprocessed_trace_row(air, |row_index, row| {
        debug_assert_eq!(values.len(), row_index * PREP_WIDTH);
        values.extend_from_slice(row);
        Ok::<_, std::convert::Infallible>(())
    })
    .expect("infallible in-memory preprocessing sink");
    RowMajorMatrix::new(values, PREP_WIDTH)
}

/// Streams the canonical preprocessing profile owned by the AIR without
/// accepting any prover witness.
pub(crate) fn for_each_canonical_preprocessed_trace_row<E>(
    air: &NarrowBlake3Air,
    emit: impl FnMut(usize, &[F]) -> Result<(), E>,
) -> Result<(), E> {
    for_each_preprocessed_trace_row(air, &air.schedule, emit)
}

/// Generates one deterministic preprocessing row at a time without retaining
/// the full matrix.
pub(crate) fn for_each_preprocessed_trace_row<E>(
    air: &NarrowBlake3Air,
    witness: &Blake3TreeWitness,
    mut emit: impl FnMut(usize, &[F]) -> Result<(), E>,
) -> Result<(), E> {
    let mut row_values = F::zero_vec(PREP_WIDTH);
    for row_index in 0..air.trace_rows {
        row_values.fill(F::ZERO);
        let prep: &mut PrepCols<F> = row_values.as_mut_slice().borrow_mut();
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
            emit(row_index, &row_values)?;
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
            if (40..40 + air.activation_len).contains(&message_offset)
                && message_offset + 8 <= 40 + air.activation_len
            {
                let activation_index = message_offset - 40;
                prep.activation_active = F::ONE;
                debug_assert_eq!(activation_index % BYTES_PER_EVAL_ROW, 0);
            }
            if prep.is_last_message_block == F::ONE {
                for byte in 0..8 {
                    prep.padding_active[byte] =
                        F::from_bool(step * 8 + byte >= operation.block_len as usize);
                }
            }
        }
        emit(row_index, &row_values)?;
    }
    Ok(())
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
            if let Some(high_weight) =
                activation_high_weight(air.activation_len, &point, operation.message_offset, step)
            {
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

fn encode_native_proof(proof: NativeProof) -> Result<Vec<u8>, NarrowBlake3Error> {
    encode_native_proof_with_identity(
        proof,
        NARROW_BLAKE3_PROOF_MAGIC,
        NARROW_BLAKE3_PROOF_VERSION,
    )
}

fn encode_native_proof_with_identity(
    mut proof: NativeProof,
    magic: &[u8; 8],
    version: u32,
) -> Result<Vec<u8>, NarrowBlake3Error> {
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
    encoded.extend_from_slice(magic);
    encoded.extend_from_slice(&version.to_le_bytes());
    encoded.extend_from_slice(&proof_len.to_le_bytes());
    encoded.extend_from_slice(&archive_len.to_le_bytes());
    encoded.extend_from_slice(&proof_bytes);
    encoded.extend_from_slice(&archive_bytes);
    Ok(encoded)
}

pub(crate) fn decode_native_proof(bytes: &[u8]) -> Result<NativeProof, NarrowBlake3Error> {
    decode_native_proof_with_identity(
        bytes,
        NARROW_BLAKE3_PROOF_MAGIC,
        NARROW_BLAKE3_PROOF_VERSION,
    )
}

fn decode_native_proof_with_identity(
    bytes: &[u8],
    magic: &[u8; 8],
    expected_version: u32,
) -> Result<NativeProof, NarrowBlake3Error> {
    if bytes.len() < 20 || bytes.get(..8) != Some(magic.as_slice()) {
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
    if version != expected_version || archive_end != bytes.len() {
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
    build_config_with_dft_and_fri(NarrowDft::default(), log_blowup, num_queries)
}

fn build_config_with_backends(dft: NarrowDft, commit_backend: NarrowCommitBackend) -> Config {
    build_config_with_backends_and_fri(dft, commit_backend, FRI_LOG_BLOWUP, FRI_QUERIES)
}

fn build_config_with_dft_and_fri(dft: NarrowDft, log_blowup: usize, num_queries: usize) -> Config {
    build_config_with_backends_and_fri(dft, NarrowCommitBackend::default(), log_blowup, num_queries)
}

#[cfg(all(test, feature = "dory-bls12-381-prototype"))]
fn build_config_with_fri_geometry(
    dft: NarrowDft,
    log_blowup: usize,
    num_queries: usize,
    log_final_poly_len: usize,
    max_log_arity: usize,
) -> Config {
    let perm = default_poseidon2();
    let val = ValMmcs::new(FieldHash::new(perm.clone()), Compress::new(perm.clone()), 0);
    let challenge = ChallengeMmcs::new(val.clone());
    let pcs = NarrowPcs::new(
        dft,
        val,
        fri_parameters_with_geometry(
            log_blowup,
            num_queries,
            log_final_poly_len,
            max_log_arity,
            challenge,
        ),
        NarrowCommitBackend::default(),
    )
    .with_log_blowup(log_blowup);
    Config::new(pcs, Challenger::new(perm))
}

fn build_config_with_backends_and_fri(
    dft: NarrowDft,
    commit_backend: NarrowCommitBackend,
    log_blowup: usize,
    num_queries: usize,
) -> Config {
    let perm = default_poseidon2();
    let val = ValMmcs::new(FieldHash::new(perm.clone()), Compress::new(perm.clone()), 0);
    // The accelerator is held by `NarrowPcs`, not by `ValMmcs`, so the FRI
    // challenge MMCS remains the same plain CPU clone used by the verifier.
    let challenge = ChallengeMmcs::new(val.clone());
    let pcs = NarrowPcs::new(
        dft,
        val,
        fri_parameters_with(log_blowup, num_queries, challenge),
        commit_backend,
    )
    .with_log_blowup(log_blowup);
    Config::new(pcs, Challenger::new(perm))
}

fn default_poseidon2() -> Perm {
    default_goldilocks_poseidon2_8()
}
fn fri_parameters_with(
    log_blowup: usize,
    num_queries: usize,
    mmcs: ChallengeMmcs,
) -> FriParameters<ChallengeMmcs> {
    fri_parameters_with_geometry(
        log_blowup,
        num_queries,
        FRI_LOG_FINAL_POLY_LEN,
        FRI_MAX_LOG_ARITY,
        mmcs,
    )
}

fn fri_parameters_with_geometry(
    log_blowup: usize,
    num_queries: usize,
    log_final_poly_len: usize,
    max_log_arity: usize,
    mmcs: ChallengeMmcs,
) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup,
        log_final_poly_len,
        max_log_arity,
        num_queries,
        commit_proof_of_work_bits: FRI_COMMIT_POW_BITS,
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
#[path = "structured_blake3_narrow_xor_lookup.rs"]
mod xor_lookup_migration;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured_blake3_identity::{
        PINNED_PREPROCESSED_KEYS, PINNED_PREPROCESSED_LOG_BLOWUP,
        PINNED_PREPROCESSED_REGISTRY_VERSION,
    };
    use p3_air::AirLayout;
    use p3_batch_stark::{
        BatchProof, CommonData, ProverData, StarkInstance,
        common::{GlobalPreprocessed, PreprocessedInstanceMeta},
        prove_batch,
        symbolic::{
            get_constraint_layout as get_batch_constraint_layout,
            get_log_num_quotient_chunks as get_batch_log_num_quotient_chunks,
            get_max_constraint_degree as get_batch_max_constraint_degree,
        },
        verify_batch,
    };
    use p3_commit::PeriodicEvaluator;
    use p3_lookup::{LogUpGadget, Lookups};
    use p3_matrix::Matrix;
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

    fn preprocessed_air(activation_len: usize) -> NarrowBlake3Air {
        assert!(
            PINNED_PREPROCESSED_KEYS
                .iter()
                .any(|key| key.activation_len == activation_len)
        );
        let challenge_digest = [0x42; 32];
        let activation = vec![125; activation_len];
        let statement = StructuredBlake3Statement {
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
        };
        NarrowBlake3Air::new(&statement).unwrap()
    }

    fn preprocessed_root_and_drop(config: &Config, air: &NarrowBlake3Air) -> [u64; 4] {
        let degree_bits = air.trace_rows.ilog2() as usize;
        let (prover_key, verifier_key) = setup_preprocessed(config, air, degree_bits)
            .expect("narrow BLAKE3 AIR has preprocessed columns");

        assert_eq!(PREP_WIDTH, 84);
        assert_eq!(prover_key.width, PREP_WIDTH);
        assert_eq!(verifier_key.width, PREP_WIDTH);
        assert_eq!(prover_key.degree_bits, degree_bits);
        assert_eq!(verifier_key.degree_bits, degree_bits);
        assert_eq!(prover_key.commitment, verifier_key.commitment);
        assert_eq!(verifier_key.commitment.num_roots(), 1);
        let root = verifier_key.commitment.roots()[0].map(|word| word.as_canonical_u64());

        // GPU setup owns authenticated LDE and Merkle artifacts through this
        // value. Release them before the generator advances to the next shape.
        drop(prover_key);
        root
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
    enum BatchPrototypeError {
        DegreeBits,
        PinnedKey,
        UnexpectedLookups,
        Statement,
        Verification,
        BackendPanic,
    }

    fn pinned_batch_common_data(
        air: &NarrowBlake3Air,
        degree_bits: &[usize],
    ) -> Result<CommonData<Config>, BatchPrototypeError> {
        let expected_degree_bits = air.trace_rows.ilog2() as usize;
        if degree_bits != [expected_degree_bits] {
            return Err(BatchPrototypeError::DegreeBits);
        }

        let pinned =
            pinned_preprocessed_verifier_key(air).map_err(|_| BatchPrototypeError::PinnedKey)?;
        if pinned.width != air.preprocessed_width()
            || pinned.degree_bits != expected_degree_bits
            || pinned.width != PINNED_PREPROCESSED_WIDTH
        {
            return Err(BatchPrototypeError::PinnedKey);
        }

        // Derive the lookup metadata from the trusted AIR so a future lookup
        // addition cannot silently be verified with an empty reduction. This
        // is symbolic evaluation only and never materializes the fixed trace.
        let lookups = Lookups::<F>::from_air::<EF, _>(air);
        if !lookups.is_empty() {
            return Err(BatchPrototypeError::UnexpectedLookups);
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

    fn narrow_batch_inputs(
        statement: &StructuredBlake3Statement,
        activation: &[u8],
    ) -> (NarrowBlake3Air, RowMajorMatrix<F>, Vec<F>) {
        let air = NarrowBlake3Air::new(statement).unwrap();
        validate_opening(statement, activation).unwrap();
        let witness =
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, activation).unwrap();
        assert_eq!(witness.digest, statement.final_activation_digest);
        let trace = generate_main_trace(&air, statement, &witness);
        let public = public_values(statement).unwrap();
        (air, trace, public)
    }

    fn prove_narrow_blake3_batch_in_memory(
        statement: &StructuredBlake3Statement,
        activation: &[u8],
    ) -> BatchProof<Config> {
        let (air, trace, public) = narrow_batch_inputs(statement, activation);
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
            .expect("real narrow AIR has a preprocessed commitment");
        let generated_meta = generated.instances[0]
            .as_ref()
            .expect("real narrow AIR has preprocessed metadata");
        let pinned = pinned_preprocessed_verifier_key(&air).unwrap();
        assert_eq!(generated.commitment, pinned.commitment);
        assert_eq!(generated.instances.len(), 1);
        assert_eq!(generated.matrix_to_instance, vec![0]);
        assert_eq!(generated_meta.matrix_index, 0);
        assert_eq!(generated_meta.width, pinned.width);
        assert_eq!(generated_meta.degree_bits, pinned.degree_bits);
        assert!(prover_data.prover_only.preprocessed_prover_data.is_some());
        assert!(prover_data.common.lookups[0].is_empty());

        prove_batch(&config, &instances, &prover_data)
    }

    fn verify_narrow_blake3_batch_in_memory(
        statement: &StructuredBlake3Statement,
        proof: &BatchProof<Config>,
    ) -> Result<(), BatchPrototypeError> {
        let air = NarrowBlake3Air::new(statement).map_err(|_| BatchPrototypeError::Statement)?;
        let public = public_values(statement).map_err(|_| BatchPrototypeError::Statement)?;

        with_preprocessed_trace_forbidden(|| {
            let common = pinned_batch_common_data(&air, &proof.degree_bits)?;
            catch_unwind(AssertUnwindSafe(|| {
                verify_batch(
                    &build_config(),
                    std::slice::from_ref(&air),
                    proof,
                    &[public],
                    &common,
                )
            }))
            .map_err(|_| BatchPrototypeError::BackendPanic)?
            .map_err(|_| BatchPrototypeError::Verification)
        })
    }

    fn legacy_activation_high_weight(
        activation_len: usize,
        point: &[crate::structured_sumcheck::ExtensionField],
        operation: Option<&CompressionOp>,
        step: usize,
    ) -> crate::structured_sumcheck::ExtensionField {
        let Some(operation) = operation else {
            return crate::structured_sumcheck::ExtensionField::ZERO;
        };
        if operation.kind != CompressionKind::Chunk || step >= BYTES_PER_EVAL_ROW {
            return crate::structured_sumcheck::ExtensionField::ZERO;
        }
        let message_offset = operation.message_offset.unwrap_or(usize::MAX) + step * 8;
        if !(40..40 + activation_len).contains(&message_offset)
            || message_offset + 8 > 40 + activation_len
        {
            return crate::structured_sumcheck::ExtensionField::ZERO;
        }

        let activation_index = message_offset - 40;
        point
            .iter()
            .enumerate()
            .skip(LOW_EVALUATION_VARIABLES)
            .fold(
                crate::structured_sumcheck::ExtensionField::ONE,
                |weight, (variable, coordinate)| {
                    weight.mul(if (activation_index >> variable) & 1 == 1 {
                        *coordinate
                    } else {
                        crate::structured_sumcheck::ExtensionField::ONE.sub(*coordinate)
                    })
                },
            )
    }

    fn deterministic_extension_point(
        variables: usize,
    ) -> Vec<crate::structured_sumcheck::ExtensionField> {
        (0..variables)
            .map(|index| {
                let index = index as u64 + 1;
                crate::structured_sumcheck::ExtensionField::from_canonical_limbs([
                    0x1020_3040_5060_7080_u64.wrapping_mul(index) % GOLDILOCKS_MODULUS,
                    0x8877_6655_4433_2211_u64.wrapping_mul(index) % GOLDILOCKS_MODULUS,
                    0x0f1e_2d3c_4b5a_6978_u64.wrapping_mul(index) % GOLDILOCKS_MODULUS,
                ])
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn periodic_activation_weights_match_legacy_rows_for_zero_one_and_random_points() {
        assert_eq!(PREP_WIDTH, 84);
        for activation_len in [32, 64, 2_048] {
            let activation = vec![0_u8; activation_len];
            let base_statement = statement(&activation);
            let variables = activation_len.ilog2() as usize;
            let point_cases = [
                vec![crate::structured_sumcheck::ExtensionField::ZERO; variables],
                vec![crate::structured_sumcheck::ExtensionField::ONE; variables],
                deterministic_extension_point(variables),
            ];

            for point in point_cases {
                let mut air = NarrowBlake3Air::new(&base_statement).unwrap();
                air.point = point.clone();
                let columns = air.periodic_columns();
                assert_eq!(air.num_periodic_columns(), ACTIVATION_HIGH_WEIGHT_WIDTH);
                assert_eq!(columns.len(), ACTIVATION_HIGH_WEIGHT_WIDTH);
                assert!(columns.iter().all(|column| column.len() == air.trace_rows));

                for (row_index, ((limb_0, limb_1), limb_2)) in columns[0]
                    .iter()
                    .zip(&columns[1])
                    .zip(&columns[2])
                    .enumerate()
                {
                    let operation = air
                        .schedule
                        .operations
                        .get(row_index / ROWS_PER_COMPRESSION);
                    let expected = legacy_activation_high_weight(
                        activation_len,
                        &point,
                        operation,
                        row_index % ROWS_PER_COMPRESSION,
                    );
                    let mut expected_limbs = [F::ZERO; ACTIVATION_HIGH_WEIGHT_WIDTH];
                    set_ext(&mut expected_limbs, expected);
                    let actual_limbs = [*limb_0, *limb_1, *limb_2];
                    assert_eq!(
                        actual_limbs, expected_limbs,
                        "activation_len={activation_len}, row={row_index}"
                    );
                    assert_eq!(air.periodic_values(row_index), actual_limbs);
                }
            }
        }
    }

    #[test]
    fn periodic_activation_polynomials_equal_rows_on_the_trace_domain() {
        type Evaluator = p3_fri::TwoAdicPeriodicEvaluator<Radix2DitParallel<F>>;

        let activation = vec![0_u8; 64];
        let base_statement = statement(&activation);
        let mut air = NarrowBlake3Air::new(&base_statement).unwrap();
        air.point = deterministic_extension_point(activation.len().ilog2() as usize);
        let columns = air.periodic_columns();
        let mut domain = TwoAdicMultiplicativeCoset::new(F::ONE, air.trace_rows.ilog2() as usize)
            .expect("supported trace domain");

        for row_index in [0, 1, 4, 5, 8, 119, 120, 127, air.trace_rows - 1] {
            let point = domain.element(row_index);
            let evaluated = <Evaluator as PeriodicEvaluator<F, _>>::eval_at_point::<F>(
                &columns, &domain, point,
            );
            assert_eq!(evaluated, air.periodic_values(row_index));
        }
    }

    #[test]
    fn preprocessed_schedule_is_point_independent_after_weight_extraction() {
        let activation = vec![0_u8; 64];
        let base_statement = statement(&activation);
        let mut air = NarrowBlake3Air::new(&base_statement).unwrap();
        air.point = vec![
            crate::structured_sumcheck::ExtensionField::ZERO;
            activation.len().ilog2() as usize
        ];
        let zero_point_preprocessed = air.preprocessed_trace().unwrap();
        let zero_point_periodic = air.periodic_columns();

        air.point = deterministic_extension_point(activation.len().ilog2() as usize);
        let random_point_preprocessed = air.preprocessed_trace().unwrap();
        let random_point_periodic = air.periodic_columns();

        assert_eq!(zero_point_preprocessed, random_point_preprocessed);
        assert_ne!(zero_point_periodic, random_point_periodic);
    }

    #[test]
    fn pinned_preprocessed_registry_matches_every_supported_air_shape() {
        assert_eq!(NARROW_BLAKE3_PROOF_VERSION, 4);
        assert_eq!(NARROW_BLAKE3_PROOF_MAGIC, b"CMFDB3N4");
        assert_eq!(PINNED_PREPROCESSED_REGISTRY_VERSION, 1);
        assert_eq!(PINNED_PREPROCESSED_WIDTH, PREP_WIDTH);
        assert_eq!(PINNED_PREPROCESSED_LOG_BLOWUP, FRI_LOG_BLOWUP);
        assert_eq!(FRI_LOG_FINAL_POLY_LEN, 7);
        assert_eq!(PINNED_PREPROCESSED_KEYS.len(), 15);

        let mut roots = std::collections::BTreeSet::new();
        for key in &PINNED_PREPROCESSED_KEYS {
            let air = preprocessed_air(key.activation_len);
            assert_eq!(air.trace_rows, key.trace_rows);
            assert!(key.root.into_iter().all(|word| word < GOLDILOCKS_MODULUS));
            assert!(roots.insert(key.root));
            assert_eq!(
                pinned_preprocessed_key(key.activation_len, key.trace_rows),
                Some(key)
            );
        }
    }

    #[test]
    fn small_preprocessed_keys_match_the_pinned_roots() {
        let config = build_config();
        let roots = [32, 64].map(|activation_len| {
            let air = preprocessed_air(activation_len);
            let root = preprocessed_root_and_drop(&config, &air);
            let pinned = pinned_preprocessed_key(activation_len, air.trace_rows).unwrap();
            assert_eq!(root, pinned.root);
            root
        });

        assert_ne!(roots[0], roots[1]);
        assert!(
            roots
                .into_iter()
                .flatten()
                .all(|word| word < GOLDILOCKS_MODULUS)
        );
    }

    #[test]
    fn prover_rejects_a_mutated_pinned_preprocessed_key() {
        let config = build_config();
        let air = preprocessed_air(32);
        let degree_bits = air.trace_rows.ilog2() as usize;
        let (prover_key, generated_key) = setup_preprocessed(&config, &air, degree_bits).unwrap();
        let pinned_key = pinned_preprocessed_verifier_key(&air).unwrap();
        require_matching_preprocessed_key(&generated_key, &pinned_key).unwrap();

        let mut mutated_root = pinned_key.commitment.roots()[0];
        mutated_root[0] += F::ONE;
        let mutated_key = PreprocessedVerifierKey {
            width: pinned_key.width,
            degree_bits: pinned_key.degree_bits,
            commitment: MerkleCap::new(vec![mutated_root]),
        };
        assert_eq!(
            require_matching_preprocessed_key(&generated_key, &mutated_key),
            Err(NarrowBlake3Error::PinnedPreprocessedKeyMismatch)
        );
        drop(prover_key);
    }

    #[test]
    fn preprocessed_key_is_point_independent() {
        let config = build_config();
        let mut air = preprocessed_air(64);
        let zero_point_root = preprocessed_root_and_drop(&config, &air);

        air.point = deterministic_extension_point(air.point_variables);
        let nonzero_point_root = preprocessed_root_and_drop(&config, &air);

        assert_eq!(zero_point_root, nonzero_point_root);
        assert_ne!(air.periodic_columns()[0], vec![F::ZERO; air.trace_rows]);
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    #[ignore = "generates production preprocessed roots with an explicitly selected CUDA library and device"]
    fn generate_cuda_pinned_preprocessed_roots() {
        let library_path = std::path::PathBuf::from(
            std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
                .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the exact CUDA proof-library path"),
        );
        assert!(
            library_path.is_absolute() && library_path.is_file(),
            "CMFD_TEST_PROOF_CUDA_LIBRARY must name an existing absolute file"
        );
        let device_index = std::env::var("CMFD_TEST_PROOF_CUDA_DEVICE")
            .expect("set CMFD_TEST_PROOF_CUDA_DEVICE to the exact CUDA device index")
            .parse::<i32>()
            .expect("CMFD_TEST_PROOF_CUDA_DEVICE must be an i32");
        assert!(
            device_index >= 0,
            "CMFD_TEST_PROOF_CUDA_DEVICE must be nonnegative"
        );

        let selected_keys = match std::env::var("CMFD_PINNED_PREP_ACTIVATION_LEN") {
            Ok(value) => {
                let activation_len = value
                    .parse::<usize>()
                    .expect("CMFD_PINNED_PREP_ACTIVATION_LEN must be a decimal usize");
                vec![*PINNED_PREPROCESSED_KEYS
                    .iter()
                    .find(|key| key.activation_len == activation_len)
                    .expect("CMFD_PINNED_PREP_ACTIVATION_LEN must name a registry activation length")]
            }
            Err(std::env::VarError::NotPresent) => PINNED_PREPROCESSED_KEYS.to_vec(),
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("CMFD_PINNED_PREP_ACTIVATION_LEN must be valid Unicode")
            }
        };

        let spill_dir =
            std::env::var_os("CMFD_PINNED_PREP_SPILL_DIR").map(std::path::PathBuf::from);
        if let Some(spill_dir) = &spill_dir {
            assert!(
                spill_dir.is_absolute() && spill_dir.is_dir(),
                "CMFD_PINNED_PREP_SPILL_DIR must name an existing absolute directory"
            );
        }

        let dft = NarrowDft::load_cuda(&library_path, device_index).unwrap();
        let commit_backend = match spill_dir {
            Some(spill_dir) => {
                NarrowCommitBackend::load_cuda_in_spill_dir(&library_path, device_index, spill_dir)
                    .unwrap()
            }
            None => NarrowCommitBackend::load_cuda(&library_path, device_index).unwrap(),
        };
        let config = build_config_with_backends(dft, commit_backend);

        for key in selected_keys {
            let air = preprocessed_air(key.activation_len);
            assert_eq!(air.trace_rows, key.trace_rows);
            let degree_bits = air.trace_rows.ilog2() as usize;
            let root = preprocessed_root_and_drop(&config, &air);
            assert_eq!(
                root, key.root,
                "generated preprocessed root does not match the pinned registry entry"
            );
            println!(
                "activation_len={} degree_bits={degree_bits} prep_width={PREP_WIDTH} preprocessed_root_u64={root:?}",
                key.activation_len
            );
        }
    }

    fn dft_fixture(height: usize, width: usize, salt: u64) -> RowMajorMatrix<F> {
        let boundaries = [0, 1, 2, GOLDILOCKS_MODULUS - 2, GOLDILOCKS_MODULUS - 1];
        let values = (0..height * width)
            .map(|index| {
                let value = boundaries.get(index).copied().unwrap_or_else(|| {
                    ((index as u128 * 0x9e37_79b9_7f4a_7c15_u128 + u128::from(salt))
                        % u128::from(GOLDILOCKS_MODULUS)) as u64
                });
                F::from_u64(value)
            })
            .collect();
        RowMajorMatrix::new(values, width)
    }

    fn assert_bit_reversed_outputs_equal(
        label: &str,
        reference: BitReversedMatrixView<RowMajorMatrix<F>>,
        adapted: BitReversedMatrixView<RowMajorMatrix<F>>,
    ) {
        assert_eq!(
            reference.inner, adapted.inner,
            "{label} physical bit-reversed ordering differs"
        );
        assert_eq!(
            reference.to_row_major_matrix(),
            adapted.to_row_major_matrix(),
            "{label} logical ordering differs"
        );
    }

    fn transform_coefficients(matrix: &mut RowMajorMatrixViewMut<'_, F>, layout: Layout) {
        assert_eq!(layout, Layout::BitReversed);
        for (index, value) in matrix.values.iter_mut().enumerate() {
            *value += F::from_u64((index as u64 % 251) + 1);
        }
    }

    #[test]
    fn narrow_dft_matches_reference_for_every_delegated_operation() {
        let reference = Radix2DitParallel::<F>::default();
        let adapted = NarrowDft::default();
        let shifts = [F::ONE, F::from_u64(7), F::from_u64(0x1234_5678_9abc_def0)];

        for log_height in 1..=6 {
            let height = 1 << log_height;
            for width in [1, 2, 3, 7] {
                let input = dft_fixture(height, width, (height * width) as u64);
                assert_bit_reversed_outputs_equal(
                    "dft_batch",
                    reference.dft_batch(input.clone()),
                    adapted.dft_batch(input.clone()),
                );

                for shift in shifts {
                    assert_bit_reversed_outputs_equal(
                        "coset_dft_batch",
                        reference.coset_dft_batch(input.clone(), shift),
                        adapted.coset_dft_batch(input.clone(), shift),
                    );
                    assert_eq!(
                        reference.coset_idft_batch(input.clone(), shift),
                        adapted.coset_idft_batch(input.clone(), shift),
                        "coset_idft_batch differs for height={height}, width={width}"
                    );

                    for added_bits in 0..=3 {
                        assert_bit_reversed_outputs_equal(
                            "coset_lde_batch",
                            reference.coset_lde_batch(input.clone(), added_bits, shift),
                            adapted.coset_lde_batch(input.clone(), added_bits, shift),
                        );
                        assert_bit_reversed_outputs_equal(
                            "coset_lde_batch_with_transform",
                            reference.coset_lde_batch_with_transform(
                                input.clone(),
                                added_bits,
                                shift,
                                transform_coefficients,
                            ),
                            adapted.coset_lde_batch_with_transform(
                                input.clone(),
                                added_bits,
                                shift,
                                transform_coefficients,
                            ),
                        );
                    }
                }
            }
        }
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    fn narrow_dft_default_remains_cpu() {
        assert!(!NarrowDft::default().is_cuda());
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    #[ignore = "requires CMFD_TEST_PROOF_CUDA_LIBRARY and a CUDA device"]
    fn cuda_first_digest_layer_matches_cpu_merkle_commit_and_openings() {
        let library_path = std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
            .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the exact CUDA proof-library path");
        let poseidon2 = cmfd_proof_accel::CudaProofPoseidon2::load(library_path, 0).unwrap();
        let perm = default_poseidon2();
        let mmcs = ValMmcs::new(FieldHash::new(perm.clone()), Compress::new(perm), 0);
        let matrices = vec![
            dft_fixture(7, 1, 0x101),
            dft_fixture(4, 8, 0x202),
            dft_fixture(7, 291, 0x303),
        ];
        let (cpu_commitment, cpu_data) = mmcs.commit(matrices.clone());
        let tallest = [&matrices[0], &matrices[2]];
        let digest_matrix = poseidon2.try_first_digest_layer_refs(&tallest).unwrap();
        let first_digests = digest_matrix
            .values
            .chunks_exact(4)
            .map(|digest| [digest[0], digest[1], digest[2], digest[3]])
            .collect();
        let (cuda_commitment, cuda_data) =
            mmcs.commit_with_first_digest_layer(matrices, first_digests);

        assert_eq!(cuda_commitment, cpu_commitment);
        for index in 0..7 {
            let cpu_opening = mmcs.open_batch(index, &cpu_data);
            let cuda_opening = mmcs.open_batch(index, &cuda_data);
            assert_eq!(cuda_opening.opened_values, cpu_opening.opened_values);
            assert_eq!(cuda_opening.opening_proof, cpu_opening.opening_proof);
        }
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    fn authenticated_disk_mmcs_matches_cpu_commitment_and_every_opening() {
        let permutation = default_poseidon2();
        let cpu = ValMmcs::new(
            FieldHash::new(permutation.clone()),
            Compress::new(permutation),
            0,
        );
        let matrices = vec![
            dft_fixture(7, 1, 0x411),
            dft_fixture(4, 3, 0x422),
            dft_fixture(7, 2, 0x433),
        ];
        let (cpu_commitment, cpu_data) = cpu.commit(matrices.clone());
        let disk = NarrowInputMmcs::new(cpu.clone(), true);
        let (disk_commitment, disk_data) = disk.commit_stored_with_first_digest_layer(
            matrices.into_iter().map(NarrowStoredLde::Memory).collect(),
            None,
        );
        assert_eq!(disk_commitment, cpu_commitment);
        let store_path = match &disk_data {
            NarrowMmcsProverData::Disk { store, .. } => store.path().to_path_buf(),
            NarrowMmcsProverData::Memory(_) => panic!("disk MMCS returned memory prover data"),
        };
        assert!(store_path.exists());
        for index in 0..7 {
            let cpu_opening = cpu.open_batch(index, &cpu_data);
            let disk_opening = disk.open_batch(index, &disk_data);
            assert_eq!(disk_opening.opened_values, cpu_opening.opened_values);
            assert_eq!(disk_opening.opening_proof, cpu_opening.opening_proof);
        }
        drop(disk_data);
        assert!(!store_path.exists());
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
    fn canonical_preprocessing_rows_stream_exact_matrix_and_stop_early() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let air = NarrowBlake3Air::new(&statement).unwrap();
        let materialized = generate_preprocessed(&air);
        let mut streamed = Vec::with_capacity(materialized.values.len());
        for_each_canonical_preprocessed_trace_row(
            &air,
            |row_index, row| -> Result<(), std::convert::Infallible> {
                assert_eq!(streamed.len(), row_index * PREP_WIDTH);
                assert_eq!(row.len(), PREP_WIDTH);
                streamed.extend_from_slice(row);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(streamed, materialized.values);

        let mut emitted = 0_usize;
        let stopped = for_each_canonical_preprocessed_trace_row(
            &air,
            |row_index, _| -> Result<(), &'static str> {
                assert_eq!(row_index, emitted);
                emitted += 1;
                if emitted == 17 { Err("stop") } else { Ok(()) }
            },
        );
        assert_eq!(stopped, Err("stop"));
        assert_eq!(emitted, 17);
    }

    #[test]
    fn canonical_preprocessing_rows_match_witness_schedules_across_bounded_profiles() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let alternate_activation = (0..64)
            .map(|index| (250 - index % 251) as u8)
            .collect::<Vec<_>>();
        let statement = statement(&activation);
        let witnesses = [
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, &activation).unwrap(),
            build_tree_witness(OUTPUT_CONTEXT, [0xa5; 32], &alternate_activation).unwrap(),
        ];

        for min_rows in [ROWS_PER_COMPRESSION, 1 << 9] {
            let air = NarrowBlake3Air::new_with_min_rows(&statement, min_rows).unwrap();
            let mut canonical = Vec::with_capacity(air.trace_rows * PREP_WIDTH);
            for_each_canonical_preprocessed_trace_row(
                &air,
                |_, row| -> Result<(), std::convert::Infallible> {
                    canonical.extend_from_slice(row);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(canonical, generate_preprocessed(&air).values);

            for witness in &witnesses {
                let mut supplied = Vec::with_capacity(canonical.len());
                for_each_preprocessed_trace_row(
                    &air,
                    witness,
                    |_, row| -> Result<(), std::convert::Infallible> {
                        supplied.extend_from_slice(row);
                        Ok(())
                    },
                )
                .unwrap();
                assert_eq!(supplied, canonical);
            }
        }
    }

    #[test]
    fn real_narrow_air_round_trips_through_the_pinned_batch_envelope() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let mut proof = prove_narrow_blake3_batch_in_memory(&statement, &activation);

        assert_eq!(MAIN_WIDTH, 291);
        assert_eq!(PREP_WIDTH, 84);
        assert_eq!(ACTIVATION_HIGH_WEIGHT_WIDTH, 3);
        assert_eq!(proof.degree_bits, vec![8]);
        assert_eq!(proof.opened_values.instances.len(), 1);
        assert_eq!(proof.lookup_terminals.len(), 1);
        assert!(proof.lookup_terminals[0].is_none());
        assert!(proof.commitments.permutation.is_none());
        assert!(proof.commitments.random.is_none());

        let opened = &proof.opened_values.instances[0];
        assert!(opened.permutation_local.is_empty());
        assert!(opened.permutation_next.is_empty());
        assert_eq!(opened.base_opened_values.trace_local.len(), MAIN_WIDTH);
        assert_eq!(
            opened.base_opened_values.trace_next.as_ref().map(Vec::len),
            Some(MAIN_WIDTH)
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
        assert!(opened.base_opened_values.random.is_none());
        assert_eq!(opened.base_opened_values.quotient_chunks.len(), 16);
        assert!(
            opened
                .base_opened_values
                .quotient_chunks
                .iter()
                .all(|chunk| chunk.len() == 3)
        );

        verify_narrow_blake3_batch_in_memory(&statement, &proof).unwrap();

        let mut wrong_digest = statement.clone();
        wrong_digest.final_activation_digest[0] ^= 1;
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&wrong_digest, &proof),
            Err(BatchPrototypeError::Verification)
        );

        let mut wrong_challenge = statement.clone();
        wrong_challenge.challenge_digest[0] ^= 1;
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&wrong_challenge, &proof),
            Err(BatchPrototypeError::Verification)
        );

        let mut wrong_point = statement.clone();
        wrong_point.final_activation_point[0].limbs[0] += 1;
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&wrong_point, &proof),
            Err(BatchPrototypeError::Verification)
        );

        let mut wrong_evaluation = statement.clone();
        wrong_evaluation.final_activation_evaluation.limbs[0] += 1;
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&wrong_evaluation, &proof),
            Err(BatchPrototypeError::Verification)
        );

        // Thirty-two and sixty-four activation bytes both use a 256-row trace,
        // so degree checks alone cannot prevent cross-shape replay. The trusted
        // registry selects different preprocessed commitments for the two AIRs.
        let smaller_activation = (0..32).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let smaller_statement = self::statement(&smaller_activation);
        let original_air = NarrowBlake3Air::new(&statement).unwrap();
        let smaller_air = NarrowBlake3Air::new(&smaller_statement).unwrap();
        assert_eq!(original_air.trace_rows, smaller_air.trace_rows);
        assert_ne!(
            pinned_preprocessed_verifier_key(&original_air)
                .unwrap()
                .commitment,
            pinned_preprocessed_verifier_key(&smaller_air)
                .unwrap()
                .commitment
        );
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&smaller_statement, &proof),
            Err(BatchPrototypeError::Verification)
        );

        let missing_instance = proof.opened_values.instances.pop().unwrap();
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&statement, &proof),
            Err(BatchPrototypeError::Verification)
        );
        proof.opened_values.instances.push(missing_instance);

        let missing_terminal = proof.lookup_terminals.pop().unwrap();
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&statement, &proof),
            Err(BatchPrototypeError::Verification)
        );
        proof.lookup_terminals.push(missing_terminal);

        let missing_preprocessed_value = proof.opened_values.instances[0]
            .base_opened_values
            .preprocessed_local
            .as_mut()
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&statement, &proof),
            Err(BatchPrototypeError::Verification)
        );
        proof.opened_values.instances[0]
            .base_opened_values
            .preprocessed_local
            .as_mut()
            .unwrap()
            .push(missing_preprocessed_value);

        let missing_trace_value = proof.opened_values.instances[0]
            .base_opened_values
            .trace_local
            .pop()
            .unwrap();
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&statement, &proof),
            Err(BatchPrototypeError::Verification)
        );
        proof.opened_values.instances[0]
            .base_opened_values
            .trace_local
            .push(missing_trace_value);

        let missing_quotient_chunk = proof.opened_values.instances[0]
            .base_opened_values
            .quotient_chunks
            .pop()
            .unwrap();
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&statement, &proof),
            Err(BatchPrototypeError::Verification)
        );
        proof.opened_values.instances[0]
            .base_opened_values
            .quotient_chunks
            .push(missing_quotient_chunk);

        proof.commitments.permutation = Some(proof.commitments.main.clone());
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&statement, &proof),
            Err(BatchPrototypeError::Verification)
        );
        proof.commitments.permutation = None;

        proof.degree_bits[0] = usize::BITS as usize;
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&statement, &proof),
            Err(BatchPrototypeError::DegreeBits)
        );
        proof.degree_bits = vec![8, 8];
        assert_eq!(
            verify_narrow_blake3_batch_in_memory(&statement, &proof),
            Err(BatchPrototypeError::DegreeBits)
        );
    }

    #[test]
    fn real_narrow_batch_layout_is_pinned() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let air = NarrowBlake3Air::new(&statement).unwrap();
        let lookups = Lookups::<F>::from_air::<EF, _>(&air);
        let gadget = LogUpGadget::new();
        let layout = AirLayout::from_air::<F>(&air);
        let constraints =
            get_batch_constraint_layout::<F, EF, _, _>(&air, layout, &lookups, &gadget);
        let max_degree =
            get_batch_max_constraint_degree::<F, EF, _, _>(&air, layout, &lookups, &gadget);
        let log_quotient_chunks =
            get_batch_log_num_quotient_chunks::<F, EF, _, _>(&air, layout, &lookups, 0, &gadget);

        assert_eq!(air.trace_rows, 256);
        assert_eq!(air.width(), 291);
        assert_eq!(air.preprocessed_width(), 84);
        assert_eq!(air.num_periodic_columns(), 3);
        assert_eq!(air.num_public_values(), 93);
        assert!(lookups.is_empty());
        assert_eq!(constraints.base_indices.len(), 1_305);
        assert!(constraints.ext_indices.is_empty());
        assert_eq!(constraints.total_constraints(), 1_305);
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
        let security = ProvenSecurity::compute(&security_params, air.trace_rows);
        assert!(security.security_bits() >= 128, "{security:?}");
        let minimum_queries = (1..=FRI_QUERIES)
            .find(|queries| {
                let mut candidate = security_params.clone();
                candidate.fri_num_queries = *queries;
                ProvenSecurity::compute(&candidate, air.trace_rows).security_bits() >= 128
            })
            .expect("real batch envelope must reach 128 proven bits");
        assert_eq!(FRI_QUERIES, minimum_queries + 1);
    }

    #[test]
    fn batch_common_data_accepts_every_pinned_preprocessed_shape_without_materializing() {
        for key in PINNED_PREPROCESSED_KEYS {
            let air = preprocessed_air(key.activation_len);
            let degree_bits = air.trace_rows.ilog2() as usize;
            assert_eq!(air.trace_rows, key.trace_rows);

            let common = with_preprocessed_trace_forbidden(|| {
                pinned_batch_common_data(&air, &[degree_bits])
            })
            .unwrap();
            let global = common.preprocessed.unwrap();
            let meta = global.instances[0].as_ref().unwrap();
            let pinned = pinned_preprocessed_verifier_key(&air).unwrap();
            assert_eq!(global.commitment, pinned.commitment);
            assert_eq!(global.instances.len(), 1);
            assert_eq!(global.matrix_to_instance, vec![0]);
            assert_eq!(meta.matrix_index, 0);
            assert_eq!(meta.width, PINNED_PREPROCESSED_WIDTH);
            assert_eq!(meta.degree_bits, degree_bits);
            assert_eq!(common.lookups.len(), 1);
            assert!(common.lookups[0].is_empty());

            assert!(matches!(
                pinned_batch_common_data(&air, &[degree_bits + 1]),
                Err(BatchPrototypeError::DegreeBits)
            ));
        }
    }

    #[test]
    fn narrow_tree_stark_round_trips() {
        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let proof = prove_narrow_blake3(&statement, &activation).unwrap();
        assert_eq!(&proof[..8], NARROW_BLAKE3_PROOF_MAGIC);
        assert_eq!(
            u32::from_le_bytes(proof[8..12].try_into().unwrap()),
            NARROW_BLAKE3_PROOF_VERSION
        );
        let native = decode_native_proof(&proof).unwrap();
        assert!(native.opened_values.preprocessed_next.is_none());
        with_preprocessed_trace_forbidden(|| verify_narrow_blake3(&statement, &proof)).unwrap();
        assert!(proof.len() <= crate::MAX_STRUCTURED_BLAKE3_PROOF_BYTES);

        let mut legacy_v3 = proof.clone();
        legacy_v3[..8].copy_from_slice(b"CMFDB3N3");
        legacy_v3[8..12].copy_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            decode_native_proof(&legacy_v3).err(),
            Some(NarrowBlake3Error::Encoding)
        );

        let mut wrong_digest = statement.clone();
        wrong_digest.final_activation_digest[0] ^= 1;
        assert!(verify_narrow_blake3(&wrong_digest, &proof).is_err());

        let mut wrong_point = statement.clone();
        wrong_point.final_activation_point[3].limbs[0] += 1;
        assert!(verify_narrow_blake3(&wrong_point, &proof).is_err());

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
        let security_at = |num_queries| {
            let perm = default_poseidon2();
            let val = ValMmcs::new(FieldHash::new(perm.clone()), Compress::new(perm), 0);
            let params = StarkSecurityParams::from_air::<F, EF, _, _>(
                &fri_parameters_with(FRI_LOG_BLOWUP, num_queries, ChallengeMmcs::new(val)),
                &air,
                AirLayout::from_air::<F>(&air),
                192,
                128,
                2,
            );
            ProvenSecurity::compute(&params, air.trace_rows)
        };
        let security = security_at(FRI_QUERIES);
        assert!(security.security_bits() >= 128, "{security:?}");
        let minimum_queries = (1..=FRI_QUERIES)
            .find(|queries| security_at(*queries).security_bits() >= 128)
            .expect("configured query count must reach 128 proven bits");
        assert_eq!(
            FRI_QUERIES,
            minimum_queries + 1,
            "the production configuration must retain one full query above the calculated minimum"
        );
    }

    #[test]
    #[ignore = "resource-sizing benchmark"]
    fn proof_size_at_32768_rows() {
        proof_size_at_32768_rows_with_backends(
            "cpu",
            NarrowDft::default(),
            NarrowCommitBackend::default(),
        );
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    #[ignore = "requires CMFD_TEST_PROOF_CUDA_LIBRARY, a CUDA device, and about 14 GiB temporary disk"]
    fn gpu_proof_size_at_32768_rows() {
        let library_path = std::env::var_os("CMFD_TEST_PROOF_CUDA_LIBRARY")
            .expect("set CMFD_TEST_PROOF_CUDA_LIBRARY to the exact CUDA proof-library path");
        let library_path = std::path::PathBuf::from(library_path);
        let dft = NarrowDft::load_cuda(&library_path, 0).unwrap();
        let commit_backend = NarrowCommitBackend::load_cuda(&library_path, 0).unwrap();
        proof_size_at_32768_rows_with_backends("cuda", dft, commit_backend);
    }

    fn proof_size_at_32768_rows_with_backends(
        label: &str,
        dft: NarrowDft,
        commit_backend: NarrowCommitBackend,
    ) {
        use std::io::Write;
        use std::time::Instant;

        let activation = (0..64).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        let statement = statement(&activation);
        let air = NarrowBlake3Air::new_with_min_rows(&statement, 32_768).unwrap();
        let witness_started = Instant::now();
        let witness =
            build_tree_witness(OUTPUT_CONTEXT, statement.challenge_digest, &activation).unwrap();
        let witness_elapsed = witness_started.elapsed();
        let trace_started = Instant::now();
        let trace = generate_main_trace(&air, &statement, &witness);
        let trace_elapsed = trace_started.elapsed();
        let public = public_values(&statement).unwrap();
        let config = build_config_with_backends(dft, commit_backend);
        let setup_started = Instant::now();
        let (prep, _) = setup_preprocessed(&config, &air, 15).unwrap();
        let setup_elapsed = setup_started.elapsed();
        let prove_started = Instant::now();
        let proof = prove_with_preprocessed(&config, &air, trace, &public, Some(&prep));
        let prove_elapsed = prove_started.elapsed();
        let encode_started = Instant::now();
        let native = encode_native_proof(proof).unwrap();
        let encode_elapsed = encode_started.elapsed();
        let compress_started = Instant::now();
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&native).unwrap();
        let compressed = encoder.finish().unwrap();
        let compress_elapsed = compress_started.elapsed();
        eprintln!(
            "backend={label} rows={} native={} zlib={} witness={witness_elapsed:?} trace={trace_elapsed:?} setup={setup_elapsed:?} prove={prove_elapsed:?} encode={encode_elapsed:?} compress={compress_elapsed:?}",
            air.trace_rows,
            native.len(),
            compressed.len()
        );
        assert!(17 + compressed.len() <= 256 * 1024);
    }
}
