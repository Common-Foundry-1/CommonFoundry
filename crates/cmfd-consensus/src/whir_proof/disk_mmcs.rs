//! Prover-only adoption of an authenticated disk-backed initial WHIR tree.
//!
//! The initial commitment is the only special case. Later extension-field
//! rounds still call the ordinary in-memory MMCS through [`DiskWhirMmcs::commit`].

use std::panic::panic_any;
use std::sync::Arc;

use cmfd_proof_accel::initial_whir_oracle::{
    INITIAL_WHIR_TREE_PARTITION, InitialWhirOpening, InitialWhirOracle,
};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_matrix::{Dimensions, Matrix};
use p3_symmetric::MerkleCap;

use super::{F, WhirMmcs};

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
        let opening = authenticated_opening(&self.oracle, row);
        opening.row()[start..end]
            .iter()
            .copied()
            .map(F::new)
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Prover data is dense for ordinary commits and disk-backed only when an
/// already validated initial oracle is explicitly adopted.
pub(super) enum DiskWhirProverData<M> {
    Dense(<WhirMmcs as Mmcs<F>>::ProverData<M>),
    Initial {
        matrix: M,
        oracle: Arc<InitialWhirOracle>,
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

#[derive(Debug, PartialEq, Eq)]
pub(super) struct DiskWhirAdoptionError {
    pub(super) expected_num_variables: usize,
    pub(super) actual_num_variables: usize,
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
    ) -> Result<AdoptedInitial, DiskWhirAdoptionError> {
        let actual_num_variables =
            usize::try_from(oracle.identity().codeword_identity().source.num_variables)
                .expect("bounded WHIR variable count fits usize");
        if actual_num_variables != expected_num_variables {
            return Err(DiskWhirAdoptionError {
                expected_num_variables,
                actual_num_variables,
            });
        }
        let commitment = MerkleCap::<F, [u8; 32]>::new(vec![oracle.identity().pinned_root()]);
        let matrix = InitialWhirMatrix {
            oracle: Arc::clone(&oracle),
        };
        Ok((commitment, DiskWhirProverData::Initial { matrix, oracle }))
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
        match prover_data {
            DiskWhirProverData::Dense(data) => {
                let opening = self.inner.open_batch(index, data);
                BatchOpening::new(opening.opened_values, opening.opening_proof)
            }
            DiskWhirProverData::Initial { matrix, oracle } => {
                assert!(
                    index < matrix.height(),
                    "initial WHIR opening index is out of bounds"
                );
                let opening = authenticated_opening(oracle, index);
                BatchOpening::new(
                    vec![opening.row().iter().copied().map(F::new).collect()],
                    opening.authentication_path().to_vec(),
                )
            }
        }
    }

    fn get_matrices<'a, M: Matrix<F>>(&self, prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        match prover_data {
            DiskWhirProverData::Dense(data) => self.inner.get_matrices(data),
            DiskWhirProverData::Initial { matrix, .. } => vec![matrix],
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

fn authenticated_opening(oracle: &InitialWhirOracle, row: usize) -> InitialWhirOpening {
    match oracle.opening(row) {
        Ok(opening) => opening,
        Err(error) => panic_any(DiskWhirOpeningPanic {
            message: error.to_string(),
        }),
    }
}
