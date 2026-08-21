//! Prover-only adoption of authenticated disk-backed WHIR trees.
//!
//! Both the initial base-field oracle and later extension-field codewords can
//! be adopted without materialising their matrices in memory. Artifact
//! identities stay prover-local and are never added to the Fiat-Shamir
//! transcript.

use std::panic::panic_any;
use std::sync::Arc;

use cmfd_proof_accel::blake3_merkle_store::{
    AuthenticatedBlake3MerkleStore, Blake3MerkleStoreError, Blake3MerkleStoreIdentity,
};
use cmfd_proof_accel::initial_whir_oracle::{
    INITIAL_WHIR_TREE_PARTITION, InitialWhirOracle, InitialWhirOracleError,
};
use cmfd_proof_accel::merkle_store::MerkleRowSource;
use cmfd_proof_accel::whir_extension::{
    AuthenticatedWhirExtensionCodeword, WHIR_EXTENSION_FOLDING, WHIR_EXTENSION_LIMBS_PER_ELEMENT,
    WHIR_EXTENSION_LIMBS_PER_ROW, WHIR_EXTENSION_WIDTH, WhirExtensionCodewordIdentity,
    WhirExtensionEncodingError,
};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::BasedVectorSpace;
use p3_matrix::extension::FlatMatrixView;
use p3_matrix::{Dimensions, Matrix};
use p3_symmetric::MerkleCap;
use thiserror::Error;

use super::{EF, F, WhirMmcs};

/// Matrix view tied to the same authenticated capability used for openings.
pub(super) struct InitialWhirMatrix {
    oracle: Arc<InitialWhirOracle>,
}

impl Matrix<F> for InitialWhirMatrix {
    fn width(&self) -> usize {
        INITIAL_WHIR_TREE_PARTITION[0]
    }

    fn height(&self) -> usize {
        self.oracle.height()
    }

    unsafe fn row_subseq_unchecked(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> impl IntoIterator<Item = F, IntoIter = impl Iterator<Item = F> + Send + Sync> {
        debug_assert!(row < self.height());
        debug_assert!(start <= end && end <= self.width());
        let opening = self
            .oracle
            .opening(row)
            .map_err(DiskWhirStorageError::Initial)
            .unwrap_or_else(|error| panic_storage(error));
        opening.row()[start..end]
            .iter()
            .copied()
            .map(F::new)
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Extension-field view over one authenticated natural-row codeword.
///
/// Each on-disk row contains twelve canonical Goldilocks limbs. The view
/// groups them, in order, into four cubic extension-field elements so
/// [`FlatMatrixView`] recovers the exact original twelve-limb row.
pub(super) struct WhirExtensionMatrix {
    codeword: Arc<AuthenticatedWhirExtensionCodeword>,
}

impl WhirExtensionMatrix {
    fn try_row(&self, row: usize) -> Result<[EF; WHIR_EXTENSION_WIDTH], DiskWhirStorageError> {
        let limbs = self.codeword.read_canonical_rows(row, 1)?;
        let limbs: [u64; WHIR_EXTENSION_LIMBS_PER_ROW] = limbs.try_into().map_err(|_| {
            DiskWhirStorageError::Invalid("extension codeword row width changed after adoption")
        })?;
        Ok(core::array::from_fn(|element| {
            EF::from_basis_coefficients_fn(|limb| {
                F::new(limbs[element * WHIR_EXTENSION_LIMBS_PER_ELEMENT + limb])
            })
        }))
    }
}

impl Matrix<EF> for WhirExtensionMatrix {
    fn width(&self) -> usize {
        WHIR_EXTENSION_WIDTH
    }

    fn height(&self) -> usize {
        usize::try_from(self.codeword.geometry().height)
            .expect("bounded extension height fits usize")
    }

    unsafe fn row_subseq_unchecked(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> impl IntoIterator<Item = EF, IntoIter = impl Iterator<Item = EF> + Send + Sync> {
        debug_assert!(row < self.height());
        debug_assert!(start <= end && end <= self.width());
        let values = self
            .try_row(row)
            .unwrap_or_else(|error| panic_storage(error));
        values.into_iter().skip(start).take(end - start)
    }
}

/// Prover data is dense for ordinary commits and disk-backed only when an
/// already authenticated initial or extension capability is explicitly
/// adopted under caller-retained identities.
pub(super) enum DiskWhirProverData<M> {
    Dense(<WhirMmcs as Mmcs<F>>::ProverData<M>),
    Initial {
        matrix: M,
        oracle: Arc<InitialWhirOracle>,
    },
    Extension {
        matrix: M,
        codeword: Arc<AuthenticatedWhirExtensionCodeword>,
        tree: Arc<AuthenticatedBlake3MerkleStore>,
        codeword_identity: Box<WhirExtensionCodewordIdentity>,
        tree_identity: Box<Blake3MerkleStoreIdentity>,
    },
}

/// MMCS adapter with the same public commitment, proof, and verifier types as
/// the ordinary BLAKE3 Merkle MMCS.
#[derive(Clone)]
pub(super) struct DiskWhirMmcs {
    inner: WhirMmcs,
}

type AdoptedInitial = (
    <DiskWhirMmcs as Mmcs<F>>::Commitment,
    <DiskWhirMmcs as Mmcs<F>>::ProverData<InitialWhirMatrix>,
);

type AdoptedExtension = (
    <DiskWhirMmcs as Mmcs<F>>::Commitment,
    <DiskWhirMmcs as Mmcs<F>>::ProverData<FlatMatrixView<F, EF, WhirExtensionMatrix>>,
);

/// Fallible authenticated-storage boundary used by an external WHIR state.
#[derive(Debug, Error)]
pub(super) enum DiskWhirStorageError {
    #[error("initial WHIR storage failed: {0}")]
    Initial(#[from] InitialWhirOracleError),
    #[error("extension WHIR storage failed: {0}")]
    Extension(#[from] WhirExtensionEncodingError),
    #[error("WHIR Merkle storage failed: {0}")]
    Merkle(#[from] Blake3MerkleStoreError),
    #[error("invalid disk-backed WHIR storage: {0}")]
    Invalid(&'static str),
}

#[derive(Debug)]
pub(super) struct DiskWhirOpeningPanic {
    message: String,
}

impl DiskWhirOpeningPanic {
    pub(super) fn message(&self) -> &str {
        &self.message
    }
}

impl DiskWhirMmcs {
    pub(super) fn new(inner: WhirMmcs) -> Self {
        assert_eq!(
            inner.cap_height(),
            0,
            "disk WHIR adoption requires cap height zero"
        );
        Self { inner }
    }

    /// Adopt a capability only after its fallible construction or reopen has
    /// authenticated both artifacts and their exact external identity.
    pub(super) fn adopt_initial(
        &self,
        expected_num_variables: usize,
        oracle: Arc<InitialWhirOracle>,
    ) -> Result<AdoptedInitial, DiskWhirStorageError> {
        let actual_num_variables =
            usize::try_from(oracle.identity().codeword_identity().source.num_variables)
                .expect("bounded WHIR variable count fits usize");
        if actual_num_variables != expected_num_variables {
            return Err(DiskWhirStorageError::Invalid(
                "initial oracle variable count does not match the prover state",
            ));
        }
        let commitment = MerkleCap::<F, [u8; 32]>::new(vec![oracle.identity().pinned_root()]);
        let matrix = InitialWhirMatrix {
            oracle: Arc::clone(&oracle),
        };
        Ok((commitment, DiskWhirProverData::Initial { matrix, oracle }))
    }

    /// Adopt one exact authenticated extension codeword/tree pair.
    ///
    /// The caller must retain both identities outside the scratch artifacts.
    /// All checks happen before a commitment or prover-data capability is
    /// returned, so an intact self-consistent substitute is not accepted.
    pub(super) fn adopt_extension(
        &self,
        expected_codeword: &WhirExtensionCodewordIdentity,
        expected_tree: &Blake3MerkleStoreIdentity,
        codeword: Arc<AuthenticatedWhirExtensionCodeword>,
        tree: Arc<AuthenticatedBlake3MerkleStore>,
    ) -> Result<AdoptedExtension, DiskWhirStorageError> {
        validate_extension_capabilities(expected_codeword, expected_tree, &codeword, &tree)?;

        let root = tree.root()?;
        if root != expected_tree.tree_root {
            return Err(DiskWhirStorageError::Invalid(
                "extension Merkle root changed during adoption",
            ));
        }
        let commitment = MerkleCap::<F, [u8; 32]>::new(vec![root]);
        let matrix = FlatMatrixView::new(WhirExtensionMatrix {
            codeword: Arc::clone(&codeword),
        });
        Ok((
            commitment,
            DiskWhirProverData::Extension {
                matrix,
                codeword,
                tree,
                codeword_identity: Box::new(expected_codeword.clone()),
                tree_identity: Box::new(expected_tree.clone()),
            },
        ))
    }

    /// Open dense or authenticated disk-backed prover data without a storage
    /// panic. Callers must discard a partially advanced proof/challenger when
    /// this returns an error; there is deliberately no dense fallback.
    pub(super) fn try_open_batch<M: Matrix<F>>(
        &self,
        index: usize,
        prover_data: &DiskWhirProverData<M>,
    ) -> Result<BatchOpening<F, Self>, DiskWhirStorageError> {
        match prover_data {
            DiskWhirProverData::Dense(data) => {
                let max_height = self
                    .inner
                    .get_matrices(data)
                    .into_iter()
                    .map(Matrix::height)
                    .max()
                    .ok_or(DiskWhirStorageError::Invalid(
                        "dense MMCS prover data contains no matrices",
                    ))?;
                if index >= max_height {
                    return Err(DiskWhirStorageError::Invalid(
                        "dense MMCS opening index is out of bounds",
                    ));
                }
                let opening = self.inner.open_batch(index, data);
                Ok(BatchOpening::new(
                    opening.opened_values,
                    opening.opening_proof,
                ))
            }
            DiskWhirProverData::Initial { matrix, oracle } => {
                if index >= matrix.height() {
                    return Err(DiskWhirStorageError::Invalid(
                        "initial WHIR opening index is out of bounds",
                    ));
                }
                let opening = oracle.opening(index)?;
                Ok(BatchOpening::new(
                    vec![opening.row().iter().copied().map(F::new).collect()],
                    opening.authentication_path().to_vec(),
                ))
            }
            DiskWhirProverData::Extension {
                matrix,
                codeword,
                tree,
                codeword_identity,
                tree_identity,
            } => {
                validate_extension_capabilities(
                    codeword_identity.as_ref(),
                    tree_identity.as_ref(),
                    codeword,
                    tree,
                )?;
                if index >= matrix.height() {
                    return Err(DiskWhirStorageError::Invalid(
                        "extension WHIR opening index is out of bounds",
                    ));
                }
                let sources: [&dyn MerkleRowSource; 1] = [codeword.as_ref()];
                let opening = tree.authenticated_opening(index, &sources)?;
                if opening.opened_rows.len() != 1
                    || opening.opened_rows[0].len() != WHIR_EXTENSION_LIMBS_PER_ROW
                {
                    return Err(DiskWhirStorageError::Invalid(
                        "extension WHIR opening has the wrong matrix shape",
                    ));
                }
                Ok(BatchOpening::new(
                    opening
                        .opened_rows
                        .into_iter()
                        .map(|row| row.into_iter().map(F::new).collect())
                        .collect(),
                    opening.opening_path,
                ))
            }
        }
    }
}

impl Mmcs<F> for DiskWhirMmcs {
    type ProverData<M> = DiskWhirProverData<M>;
    type Commitment = <WhirMmcs as Mmcs<F>>::Commitment;
    type Proof = <WhirMmcs as Mmcs<F>>::Proof;
    type Error = <WhirMmcs as Mmcs<F>>::Error;

    fn commit<M: Matrix<F>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        let (commitment, data) = self.inner.commit(inputs);
        (commitment, DiskWhirProverData::Dense(data))
    }

    fn open_batch<M: Matrix<F>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<F, Self> {
        self.try_open_batch(index, prover_data)
            .unwrap_or_else(|error| panic_storage(error))
    }

    fn get_matrices<'a, M: Matrix<F>>(&self, prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        match prover_data {
            DiskWhirProverData::Dense(data) => self.inner.get_matrices(data),
            DiskWhirProverData::Initial { matrix, .. } => vec![matrix],
            DiskWhirProverData::Extension { matrix, .. } => vec![matrix],
        }
    }

    fn verify_batch(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, F, Self>,
    ) -> Result<(), Self::Error> {
        self.inner.verify_batch(
            commitment,
            dimensions,
            index,
            BatchOpeningRef::<F, WhirMmcs>::new(opening.opened_values, opening.opening_proof),
        )
    }
}

fn validate_extension_capabilities(
    expected_codeword: &WhirExtensionCodewordIdentity,
    expected_tree: &Blake3MerkleStoreIdentity,
    codeword: &AuthenticatedWhirExtensionCodeword,
    tree: &AuthenticatedBlake3MerkleStore,
) -> Result<(), DiskWhirStorageError> {
    if codeword.identity() != expected_codeword {
        return Err(DiskWhirStorageError::Invalid(
            "extension codeword identity does not match the retained identity",
        ));
    }
    if expected_codeword.folding != WHIR_EXTENSION_FOLDING as u8
        || expected_codeword.width != WHIR_EXTENSION_WIDTH as u32
    {
        return Err(DiskWhirStorageError::Invalid(
            "extension codeword has the wrong protocol shape",
        ));
    }
    let height = usize::try_from(expected_codeword.height).map_err(|_| {
        DiskWhirStorageError::Invalid("extension codeword height does not fit memory")
    })?;
    if codeword.geometry().height != expected_codeword.height {
        return Err(DiskWhirStorageError::Invalid(
            "extension codeword geometry does not match its retained identity",
        ));
    }
    if expected_tree.height != height
        || expected_tree.ordered_matrix_widths.as_slice() != [WHIR_EXTENSION_LIMBS_PER_ROW]
    {
        return Err(DiskWhirStorageError::Invalid(
            "extension Merkle store has the wrong height or matrix partition",
        ));
    }
    let actual_tree = tree.identity()?;
    if &actual_tree != expected_tree {
        return Err(DiskWhirStorageError::Invalid(
            "extension Merkle identity does not match the retained identity",
        ));
    }
    Ok(())
}

fn panic_storage(error: DiskWhirStorageError) -> ! {
    panic_any(DiskWhirOpeningPanic {
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use cmfd_proof_accel::blake3_merkle_store::build_authenticated_blake3_merkle_store;
    use cmfd_proof_accel::whir_extension::encode_whir_extension_codeword;
    use cmfd_proof_accel::whir_residual::{
        AuthenticatedWhirResidualArtifact, WHIR_RESIDUAL_LIMBS_PER_ROW, WhirResidualArtifactSpec,
        WhirResidualArtifactWriter,
    };
    use p3_blake3::Blake3;
    use p3_commit::{ExtensionMmcs, Mmcs};
    use p3_field::BasedVectorSpace;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::{Dimensions, Matrix};
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

    use super::*;

    const TREE_HEADER_BYTES: u64 = 128 + 8;
    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct ExtensionFixture {
        directory: PathBuf,
        residual: AuthenticatedWhirResidualArtifact,
        codeword: Arc<AuthenticatedWhirExtensionCodeword>,
        tree: Arc<AuthenticatedBlake3MerkleStore>,
        codeword_identity: WhirExtensionCodewordIdentity,
        tree_identity: Blake3MerkleStoreIdentity,
        values: Vec<EF>,
    }

    fn test_directory(label: &str) -> PathBuf {
        let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "cmfd-disk-mmcs-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        directory
    }

    fn residual_row(index: u64) -> [u64; WHIR_RESIDUAL_LIMBS_PER_ROW] {
        core::array::from_fn(|limb| {
            (index
                .wrapping_mul(0x9e37_79b9)
                .wrapping_add((limb as u64 + 1) * 0x1_0000_01b3)
                .wrapping_add(29))
                % super::super::GOLDILOCKS_MODULUS
        })
    }

    fn build_residual(directory: &Path) -> AuthenticatedWhirResidualArtifact {
        let spec = WhirResidualArtifactSpec {
            source_digest: [0x31; 32],
            context_digest: [0x72; 32],
            num_variables: 3,
            generation: 1,
        };
        let mut writer = WhirResidualArtifactWriter::create(directory, spec).unwrap();
        let rows = (0..8).map(residual_row).collect::<Vec<_>>();
        writer.write_rows(0, &rows).unwrap();
        writer.finish().unwrap()
    }

    fn ordinary_mmcs() -> WhirMmcs {
        WhirMmcs::new(
            SerializingHasher::new(Blake3),
            CompressionFunctionFromHasher::new(Blake3),
            0,
        )
    }

    fn build_fixture(label: &str) -> ExtensionFixture {
        let directory = test_directory(label);
        let residual = build_residual(&directory);
        let codeword = encode_whir_extension_codeword(
            &directory,
            [0x41; 32],
            residual.identity(),
            &residual,
            1,
        )
        .unwrap();
        let height = usize::try_from(codeword.geometry().height).unwrap();
        let canonical = codeword.read_canonical_rows(0, height).unwrap();
        let values = canonical
            .chunks_exact(WHIR_EXTENSION_LIMBS_PER_ELEMENT)
            .map(|limbs| EF::from_basis_coefficients_fn(|index| F::new(limbs[index])))
            .collect::<Vec<_>>();
        let codeword_identity = codeword.identity().clone();
        let tree = build_authenticated_blake3_merkle_store(
            directory.join("extension-tree"),
            [0x93; 32],
            &[&codeword],
        )
        .unwrap()
        .remove_on_drop();
        let tree_identity = tree.identity().unwrap();
        ExtensionFixture {
            directory,
            residual,
            codeword: Arc::new(codeword),
            tree: Arc::new(tree),
            codeword_identity,
            tree_identity,
            values,
        }
    }

    fn remove_fixture(fixture: ExtensionFixture) {
        let ExtensionFixture {
            directory,
            residual,
            codeword,
            tree,
            ..
        } = fixture;
        drop(tree);
        drop(codeword);
        drop(residual);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn extension_matrix_decodes_four_cubic_values_and_flattens_exactly() {
        let fixture = build_fixture("matrix");
        let matrix = WhirExtensionMatrix {
            codeword: Arc::clone(&fixture.codeword),
        };
        assert_eq!(matrix.width(), WHIR_EXTENSION_WIDTH);
        assert_eq!(matrix.height(), fixture.tree_identity.height);

        let row_index = 2;
        let row = matrix
            .row(row_index)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(
            row,
            fixture.values
                [row_index * WHIR_EXTENSION_WIDTH..(row_index + 1) * WHIR_EXTENSION_WIDTH]
        );
        let flat = FlatMatrixView::<F, EF, _>::new(matrix);
        let flat_row = flat.row(row_index).unwrap().into_iter().collect::<Vec<_>>();
        let expected = fixture
            .codeword
            .read_canonical_rows(row_index, 1)
            .unwrap()
            .into_iter()
            .map(F::new)
            .collect::<Vec<_>>();
        assert_eq!(flat_row, expected);

        drop(flat);
        remove_fixture(fixture);
    }

    #[test]
    fn adopted_extension_matches_ordinary_extension_mmcs_commitment_and_openings() {
        let fixture = build_fixture("parity");
        let disk = DiskWhirMmcs::new(ordinary_mmcs());
        let (commitment, prover_data) = disk
            .adopt_extension(
                &fixture.codeword_identity,
                &fixture.tree_identity,
                Arc::clone(&fixture.codeword),
                Arc::clone(&fixture.tree),
            )
            .unwrap();
        match &prover_data {
            DiskWhirProverData::Extension {
                codeword_identity,
                tree_identity,
                ..
            } => {
                assert_eq!(codeword_identity.as_ref(), &fixture.codeword_identity);
                assert_eq!(tree_identity.as_ref(), &fixture.tree_identity);
            }
            _ => panic!("adopted extension must retain extension prover data"),
        }

        let ordinary_extension = ExtensionMmcs::<F, EF, _>::new(ordinary_mmcs());
        let (ordinary_commitment, ordinary_data) =
            ordinary_extension.commit(vec![RowMajorMatrix::new(
                fixture.values.clone(),
                WHIR_EXTENSION_WIDTH,
            )]);
        assert_eq!(commitment, ordinary_commitment);

        let disk_extension = ExtensionMmcs::<F, EF, _>::new(disk.clone());
        let dimensions = [Dimensions {
            width: WHIR_EXTENSION_LIMBS_PER_ROW,
            height: fixture.tree_identity.height,
        }];
        for index in 0..fixture.tree_identity.height {
            let base_opening = disk.try_open_batch(index, &prover_data).unwrap();
            disk.verify_batch(&commitment, &dimensions, index, (&base_opening).into())
                .unwrap();

            let disk_opening = disk_extension.open_batch(index, &prover_data);
            let ordinary_opening = ordinary_extension.open_batch(index, &ordinary_data);
            assert_eq!(disk_opening.opened_values, ordinary_opening.opened_values);
            assert_eq!(disk_opening.opening_proof, ordinary_opening.opening_proof);
            assert_eq!(base_opening.opening_proof, ordinary_opening.opening_proof);
            let ordinary_base = ordinary_opening.opened_values[0]
                .iter()
                .flat_map(|value| value.as_basis_coefficients_slice().iter().copied())
                .collect::<Vec<_>>();
            assert_eq!(base_opening.opened_values, vec![ordinary_base]);
        }

        assert!(matches!(
            disk.try_open_batch(fixture.tree_identity.height, &prover_data),
            Err(DiskWhirStorageError::Invalid(
                "extension WHIR opening index is out of bounds"
            ))
        ));
        drop(prover_data);
        remove_fixture(fixture);
    }

    #[test]
    fn extension_adoption_rejects_every_untrusted_identity_change() {
        let fixture = build_fixture("identity");
        let disk = DiskWhirMmcs::new(ordinary_mmcs());

        let mut wrong_codeword = fixture.codeword_identity.clone();
        wrong_codeword.codeword_id[0] ^= 1;
        assert!(matches!(
            disk.adopt_extension(
                &wrong_codeword,
                &fixture.tree_identity,
                Arc::clone(&fixture.codeword),
                Arc::clone(&fixture.tree),
            ),
            Err(DiskWhirStorageError::Invalid(
                "extension codeword identity does not match the retained identity"
            ))
        ));

        let mut wrong_tree = fixture.tree_identity.clone();
        wrong_tree.store_id[0] ^= 1;
        assert!(matches!(
            disk.adopt_extension(
                &fixture.codeword_identity,
                &wrong_tree,
                Arc::clone(&fixture.codeword),
                Arc::clone(&fixture.tree),
            ),
            Err(DiskWhirStorageError::Invalid(
                "extension Merkle identity does not match the retained identity"
            ))
        ));

        let mut wrong_partition = fixture.tree_identity.clone();
        wrong_partition.ordered_matrix_widths = vec![WHIR_EXTENSION_WIDTH];
        assert!(matches!(
            disk.adopt_extension(
                &fixture.codeword_identity,
                &wrong_partition,
                Arc::clone(&fixture.codeword),
                Arc::clone(&fixture.tree),
            ),
            Err(DiskWhirStorageError::Invalid(
                "extension Merkle store has the wrong height or matrix partition"
            ))
        ));

        remove_fixture(fixture);
    }

    #[test]
    fn extension_tree_corruption_fails_closed_without_dense_fallback() {
        let fixture = build_fixture("corruption");
        let disk = DiskWhirMmcs::new(ordinary_mmcs());
        let (_, prover_data) = disk
            .adopt_extension(
                &fixture.codeword_identity,
                &fixture.tree_identity,
                Arc::clone(&fixture.codeword),
                Arc::clone(&fixture.tree),
            )
            .unwrap();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.tree.path())
            .unwrap();
        file.seek(SeekFrom::Start(TREE_HEADER_BYTES)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start(TREE_HEADER_BYTES)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();

        for _ in 0..2 {
            assert!(matches!(
                disk.try_open_batch(0, &prover_data),
                Err(DiskWhirStorageError::Merkle(
                    Blake3MerkleStoreError::ChecksumMismatch
                ))
            ));
        }

        drop(prover_data);
        drop(file);
        remove_fixture(fixture);
    }

    #[test]
    fn dense_out_of_bounds_opening_is_fallible() {
        let disk = DiskWhirMmcs::new(ordinary_mmcs());
        let (_, prover_data) = disk.commit(vec![RowMajorMatrix::new(vec![F::new(7); 8], 2)]);
        assert!(matches!(
            disk.try_open_batch(4, &prover_data),
            Err(DiskWhirStorageError::Invalid(
                "dense MMCS opening index is out of bounds"
            ))
        ));
    }
}
