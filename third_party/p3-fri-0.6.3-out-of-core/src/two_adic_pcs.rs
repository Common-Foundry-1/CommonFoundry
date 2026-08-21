//! The FRI PCS protocol over two-adic fields.
//!
//! The following implements a slight variant of the usual FRI protocol. As usual we start
//! with a polynomial `F(x)` of degree `n` given as evaluations over the coset `gH` with `|H| = 2^n`.
//!
//! Now consider the polynomial `G(x) = F(gx)`. Note that `G(x)` has the same degree as `F(x)` and
//! the evaluations of `F(x)` over `gH` are identical to the evaluations of `G(x)` over `H`.
//!
//! Hence we can reinterpret our vector of evaluations as evaluations of `G(x)` over `H` and apply
//! the standard FRI protocol to this evaluation vector. This makes it easier to apply FRI to a collection
//! of polynomials defined over different cosets as we don't need to keep track of the coset shifts. We
//! can just assume that every polynomial is defined over the subgroup of the relevant size.
//!
//! If we changed our domain construction (e.g., using multiple cosets), we would need to carefully reconsider these assumptions.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use itertools::{Itertools, izip};
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::{
    BatchOpening, BuildPeriodicLdeTableFast, Mmcs, OpenedValues, Pcs, PeriodicLdeTable,
};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{
    ExtensionField, PackedFieldExtension, TwoAdicField, batch_multiplicative_inverse, dot_product,
};
use p3_matrix::Matrix;
use p3_matrix::bitrev::{BitReversedMatrixView, BitReversibleMatrix};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixCow};
use p3_matrix::interpolation::{Interpolate, compute_adjusted_weights};
use p3_maybe_rayon::prelude::*;
use p3_util::linear_map::LinearMap;
use p3_util::{log2_strict_usize, reverse_bits_len, reverse_slice_index_bits};
use tracing::{debug_span, instrument};

use crate::periodic::build_periodic_lde_table_two_adic;
use crate::verifier::{self, FriError};
use crate::{FriFoldingStrategy, FriParameters, FriProof, prover};

/// A polynomial commitment scheme using FRI to generate opening proofs.
///
/// We commit to a polynomial `f` via its evaluation vectors over a coset
/// `gH` where `|H| >= 2 * deg(f)`. A value `f(z)` is opened by using a FRI
/// proof to show that the evaluations of `(f(x) - f(z))/(x - z)` over
/// `gH` are low degree.
#[derive(Clone, Debug)]
pub struct TwoAdicFriPcs<Val, Dft, InputMmcs, FriMmcs, Lde = RowMajorMatrix<Val>> {
    pub(crate) dft: Dft,
    pub(crate) mmcs: InputMmcs,
    pub(crate) fri: FriParameters<FriMmcs>,
    _phantom: PhantomData<fn() -> (Val, Lde)>,
}

impl<Val, Dft, InputMmcs, FriMmcs>
    TwoAdicFriPcs<Val, Dft, InputMmcs, FriMmcs, RowMajorMatrix<Val>>
{
    pub const fn new(dft: Dft, mmcs: InputMmcs, fri: FriParameters<FriMmcs>) -> Self {
        Self {
            dft,
            mmcs,
            fri,
            _phantom: PhantomData,
        }
    }
}

impl<Val, Dft, InputMmcs, FriMmcs, Lde> TwoAdicFriPcs<Val, Dft, InputMmcs, FriMmcs, Lde> {
    /// Construct a PCS whose input LDEs use a custom prover-side matrix type.
    pub const fn new_with_lde(dft: Dft, mmcs: InputMmcs, fri: FriParameters<FriMmcs>) -> Self {
        Self {
            dft,
            mmcs,
            fri,
            _phantom: PhantomData,
        }
    }
}

/// Prover-side storage for physical bit-reversed input LDE rows.
///
/// This changes only how the prover retains and reads the large input LDEs.
/// Commitments, openings, proof types, and verifier behavior are independent
/// of this type. Implementations must expose rows in exactly the same physical
/// bit-reversed order as [`RowMajorMatrix`] does in the default PCS.
pub trait FriLdeMatrix<Val>: Matrix<Val>
where
    Val: Send + Sync + Clone,
{
    /// Matrix view returned by [`Pcs::get_evaluations_on_domain`].
    type EvaluationsOnDomain<'a>: Matrix<Val> + 'a
    where
        Self: 'a,
        Val: 'a;

    /// Store a generated physical bit-reversed row-major LDE.
    fn from_bit_reversed_row_major(lde: RowMajorMatrix<Val>) -> Self;

    /// Reinterpret the first `height` physical bit-reversed rows as standard
    /// domain-order evaluations.
    fn evaluations_from_prefix(&self, height: usize) -> Self::EvaluationsOnDomain<'_>;

    /// Wrap owned standard-order DFT output in the PCS evaluation view.
    fn evaluations_from_owned<'a>(
        evaluations: RowMajorMatrix<Val>,
    ) -> Self::EvaluationsOnDomain<'a>
    where
        Self: 'a,
        Val: 'a;

    /// Materialize standard-order rows for the uncommon re-evaluation path.
    fn to_natural_order_row_major(&self) -> RowMajorMatrix<Val> {
        let log_height = log2_strict_usize(self.height());
        RowMajorMatrix::new(
            (0..self.height())
                .flat_map(|row| unsafe { self.row_unchecked(reverse_bits_len(row, log_height)) })
                .collect(),
            self.width(),
        )
    }
}

impl<Val> FriLdeMatrix<Val> for RowMajorMatrix<Val>
where
    Val: Send + Sync + Clone + Default,
{
    type EvaluationsOnDomain<'a>
        = BitReversedMatrixView<RowMajorMatrixCow<'a, Val>>
    where
        Val: 'a;

    fn from_bit_reversed_row_major(lde: Self) -> Self {
        lde
    }

    fn evaluations_from_prefix(&self, height: usize) -> Self::EvaluationsOnDomain<'_> {
        self.split_rows(height).0.as_cow().bit_reverse_rows()
    }

    fn evaluations_from_owned<'a>(evaluations: Self) -> Self::EvaluationsOnDomain<'a>
    where
        Val: 'a,
    {
        let width = evaluations.width();
        RowMajorMatrixCow::new(Cow::Owned(evaluations.values), width).bit_reverse_rows()
    }

    fn to_natural_order_row_major(&self) -> Self {
        self.as_view().bit_reverse_rows().to_row_major_matrix()
    }
}

struct RowsPrefix<'a, Val, M> {
    matrix: &'a M,
    height: usize,
    _phantom: PhantomData<Val>,
}

impl<'a, Val, M> RowsPrefix<'a, Val, M> {
    const fn new(matrix: &'a M, height: usize) -> Self {
        Self {
            matrix,
            height,
            _phantom: PhantomData,
        }
    }
}

impl<Val, M> Matrix<Val> for RowsPrefix<'_, Val, M>
where
    Val: Send + Sync + Clone,
    M: Matrix<Val>,
{
    fn width(&self) -> usize {
        self.matrix.width()
    }

    fn height(&self) -> usize {
        self.height
    }

    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = Val, IntoIter = impl Iterator<Item = Val> + Send + Sync> {
        unsafe { self.matrix.row_unchecked(row) }
    }
}

impl<Val, Dft, InputMmcs, FriMmcs, Lde> TwoAdicFriPcs<Val, Dft, InputMmcs, FriMmcs, Lde>
where
    Val: Send + Sync + Clone,
    InputMmcs: Mmcs<Val>,
    Lde: FriLdeMatrix<Val>,
{
    /// Commit already-generated physical bit-reversed LDE matrices without
    /// converting them through in-memory row-major storage.
    pub fn commit_bit_reversed_ldes(
        &self,
        ldes: Vec<Lde>,
    ) -> (InputMmcs::Commitment, InputMmcs::ProverData<Lde>) {
        // Opening recovers the underlying polynomial degree as
        // `height >> log_blowup`. Shorter matrices would silently yield a
        // zero-height degree and a malformed proof.
        let min_height = 1 << self.fri.log_blowup;
        for lde in &ldes {
            assert!(
                lde.height() >= min_height,
                "committed LDE height {} is smaller than the blowup factor {min_height}",
                lde.height()
            );
        }
        self.mmcs.commit(ldes)
    }
}

/// The Prover Data associated to a commitment to a collection of matrices
/// and a list of points to open each matrix at.
pub type ProverDataWithOpeningPoints<'a, EF, ProverData> = (
    // The matrices and auxiliary prover data
    &'a ProverData,
    // for each matrix,
    Vec<
        // points to open
        Vec<EF>,
    >,
);

/// A joint commitment to a collection of matrices and their opening at
/// a collection of points.
pub type CommitmentWithOpeningPoints<Challenge, Commitment, Domain> = (
    Commitment,
    // For each matrix in the commitment:
    Vec<(
        // The domain of the matrix
        Domain,
        // A vector of (point, claimed_evaluation) pairs.
        // The claimed evaluation count per point is also the matrix width used by verification.
        Vec<(Challenge, Vec<Challenge>)>,
    )>,
);

pub struct TwoAdicFriFolding<InputProof, InputError>(pub PhantomData<(InputProof, InputError)>);

pub type TwoAdicFriFoldingForMmcs<F, M> =
    TwoAdicFriFolding<Vec<BatchOpening<F, M>>, <M as Mmcs<F>>::Error>;

impl<F: TwoAdicField, InputProof: Sync, InputError: Debug + Sync, EF: ExtensionField<F>>
    FriFoldingStrategy<F, EF> for TwoAdicFriFolding<InputProof, InputError>
{
    type InputProof = InputProof;
    type InputError = InputError;

    fn extra_query_index_bits(&self) -> usize {
        0
    }

    fn fold_row(
        &self,
        index: usize,
        log_height: usize,
        log_arity: usize,
        beta: EF,
        evals: impl Iterator<Item = EF>,
    ) -> EF {
        let arity = 1 << log_arity;
        let evals: Vec<_> = evals.collect();
        assert_eq!(evals.len(), arity, "Expected {} evaluations", arity);

        // Compute the evaluation points in the subgroup
        let subgroup_start = F::two_adic_generator(log_height + log_arity)
            .exp_u64(reverse_bits_len(index, log_height) as u64);
        let mut xs: Vec<F> = F::two_adic_generator(log_arity)
            .shifted_powers(subgroup_start)
            .take(arity)
            .collect();
        reverse_slice_index_bits(&mut xs);

        // Lagrange interpolation at beta
        lagrange_interpolate_at(&xs, &evals, beta)
    }

    #[instrument(skip_all, level = "debug")]
    fn fold_matrix<M: Matrix<EF>>(&self, beta: EF, log_arity: usize, m: M) -> Vec<EF> {
        if log_arity == 1 {
            // Optimized path for arity 2
            // We use the fact that
            //     p_e(x^2) = (p(x) + p(-x)) / 2
            //     p_o(x^2) = (p(x) - p(-x)) / (2 x)
            // that is,
            //     p_e(g^(2i)) = (p(g^i) + p(g^(n/2 + i))) / 2
            //     p_o(g^(2i)) = (p(g^i) - p(g^(n/2 + i))) / (2 g^i)
            // so
            //     result(g^(2i)) = p_e(g^(2i)) + beta p_o(g^(2i))
            //
            // As p_e, p_o will be in the extension field we want to find ways to avoid extension multiplications.
            // We should only need a single one (namely multiplication by beta).
            let g_inv = F::two_adic_generator(log2_strict_usize(m.height()) + 1).inverse();

            // As beta is in the extension field, we want to avoid multiplying by it
            // for as long as possible. Here we precompute the powers  `g_inv^i / 2` in the base field.
            let mut halve_inv_powers = g_inv.shifted_powers(F::ONE.halve()).collect_n(m.height());
            reverse_slice_index_bits(&mut halve_inv_powers);

            m.par_rows()
                .zip(halve_inv_powers)
                .map(|(mut row, halve_inv_power)| {
                    let (lo, hi) = row.next_tuple().unwrap();
                    (lo + hi).halve() + (lo - hi) * beta * halve_inv_power
                })
                .collect()
        } else {
            // Decompose arity-2^k fold into k sequential arity-2 folds.
            // This way, an arity-2^k fold with a single challenge beta is equivalent to
            // k arity-2 folds with challenges beta, beta^2, beta^4, ..., beta^{2^{k-1}}.
            //
            // For arity 4 with evaluation points {s, -s, si, -si}:
            //   Step 1 (beta):   fold pairs → g(s^2), g(-s^2) where g = f_e + beta*f_o
            //   Step 2 (beta^2): fold pair  → g(beta^2) = f(beta)
            let arity = 1 << log_arity;
            assert_eq!(m.width(), arity, "fold matrix width must equal its arity");

            let height = m.height();
            let log_height = log2_strict_usize(height);
            let g_inv = F::two_adic_generator(log_height + log_arity).inverse();

            // The old whole-matrix implementation materialized one inverse power per first-step
            // pair. Factor each such power into a row term and a small within-row term instead.
            let mut row_halve_inv_powers = g_inv.shifted_powers(F::ONE.halve()).collect_n(height);
            reverse_slice_index_bits(&mut row_halve_inv_powers);

            let local_g_inv = g_inv.exp_power_of_2(log_height);
            let mut local_inv_powers = local_g_inv.shifted_powers(F::ONE).collect_n(arity >> 1);
            reverse_slice_index_bits(&mut local_inv_powers);

            // Each layer is arity-only metadata shared by every row. Squaring the even entries
            // reproduces the inverse powers used by the next sequential binary fold.
            let mut local_inv_power_layers = Vec::with_capacity(log_arity);
            for _ in 0..log_arity {
                let next = (0..(local_inv_powers.len() >> 1))
                    .map(|i| local_inv_powers[i << 1].square())
                    .collect();
                local_inv_power_layers.push(local_inv_powers);
                local_inv_powers = next;
            }

            let mut folded = EF::zero_vec(height);
            folded
                .par_iter_mut()
                .zip(m.par_rows())
                .zip(row_halve_inv_powers)
                .for_each(|((out, row), row_halve_inv_power)| {
                    if arity <= 16 {
                        let mut data = [EF::ZERO; 16];
                        for (slot, value) in data[..arity].iter_mut().zip(row) {
                            *slot = value;
                        }
                        *out = fold_binary_layers_in_place(
                            &mut data[..arity],
                            beta,
                            row_halve_inv_power,
                            &local_inv_power_layers,
                        );
                    } else {
                        // Preserve support for larger caller-selected arities while keeping the
                        // scratch allocation bounded to one row per worker thread.
                        let mut data = row.collect_vec();
                        *out = fold_binary_layers_in_place(
                            &mut data,
                            beta,
                            row_halve_inv_power,
                            &local_inv_power_layers,
                        );
                    }
                });
            folded
        }
    }
}

fn fold_binary_layers_in_place<F: TwoAdicField, EF: ExtensionField<F>>(
    data: &mut [EF],
    beta: EF,
    mut row_halve_inv_power: F,
    local_inv_power_layers: &[Vec<F>],
) -> EF {
    let two = F::ONE + F::ONE;
    let mut current_beta = beta;
    let mut current_len = data.len();

    for (step, local_inv_powers) in local_inv_power_layers.iter().enumerate() {
        let next_len = current_len >> 1;
        debug_assert_eq!(local_inv_powers.len(), next_len);

        // Writes only trail reads: index i is written after indices 2i and 2i + 1 are read.
        for i in 0..next_len {
            let lo = data[i << 1];
            let hi = data[(i << 1) + 1];
            let halve_inv_power = row_halve_inv_power * local_inv_powers[i];
            data[i] = (lo + hi).halve() + (lo - hi) * current_beta * halve_inv_power;
        }

        current_len = next_len;
        if step + 1 < local_inv_power_layers.len() {
            current_beta = current_beta.square();
            row_halve_inv_power = two * row_halve_inv_power.square();
        }
    }

    debug_assert_eq!(current_len, 1);
    data[0]
}

/// Lagrange interpolation: given points `(xs[i], ys[i])`, evaluate at z.
///
/// Uses the barycentric formula for efficiency when xs are roots of unity.
fn lagrange_interpolate_at<F: TwoAdicField, EF: ExtensionField<F>>(
    xs: &[F],
    ys: &[EF],
    z: EF,
) -> EF {
    debug_assert_eq!(xs.len(), ys.len());
    let n = xs.len();

    if n == 0 {
        return EF::ZERO;
    }

    // If z equals one of the interpolation points, return early.
    for i in 0..n {
        if (z - xs[i]).is_zero() {
            return ys[i];
        }
    }

    let log_n = log2_strict_usize(n);

    // All xs lie in a coset of the 2^log_n roots of unity.
    let coset_power = xs[0].exp_power_of_2(log_n);
    let weight_scale = (F::from_usize(n) * coset_power).inverse();

    // Compute (z - x_i)^{-1} as a batch inversion
    let diffs: Vec<_> = xs.iter().map(|&x| z - x).collect();
    let diff_invs = batch_multiplicative_inverse(&diffs);

    // Compute L(z) = prod_i (z - x_i)
    let l_z = diffs.iter().copied().product::<EF>();

    // Barycentric formula: sum_i (w_i * y_i / (z - x_i))
    // where w_i = 1 / prod_{j != i} (x_i - x_j) = x_i * weight_scale.
    let mut result = EF::ZERO;
    for ((&x, &y), &diff_inv) in xs.iter().zip(ys).zip(diff_invs.iter()) {
        let weight = x * weight_scale;
        result += y * weight * diff_inv;
    }
    result * l_z
}

impl<Val, Dft, InputMmcs, FriMmcs, Lde, Challenge, Challenger> Pcs<Challenge, Challenger>
    for TwoAdicFriPcs<Val, Dft, InputMmcs, FriMmcs, Lde>
where
    Val: TwoAdicField + 'static,
    Dft: TwoAdicSubgroupDft<Val>,
    InputMmcs: Mmcs<Val, Proof: Sync, Error: Sync>,
    FriMmcs: Mmcs<Challenge>,
    Lde: FriLdeMatrix<Val> + 'static,
    Challenge: ExtensionField<Val>,
    Challenger:
        FieldChallenger<Val> + CanObserve<FriMmcs::Commitment> + GrindingChallenger<Witness = Val>,
{
    type Domain = TwoAdicMultiplicativeCoset<Val>;
    type Commitment = InputMmcs::Commitment;
    type ProverData = InputMmcs::ProverData<Lde>;
    type EvaluationsOnDomain<'a> = Lde::EvaluationsOnDomain<'a>;
    type Proof = FriProof<Challenge, FriMmcs, Val, Vec<BatchOpening<Val, InputMmcs>>>;
    type Error = FriError<FriMmcs::Error, InputMmcs::Error>;
    const ZK: bool = false;

    /// Get the unique subgroup `H` of size `|H| = degree`.
    ///
    /// # Panics:
    /// This function will panic if `degree` is not a power of 2 or `degree > (1 << Val::TWO_ADICITY)`.
    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        TwoAdicMultiplicativeCoset::new(Val::ONE, log2_strict_usize(degree)).unwrap()
    }

    fn log_max_lde_height(&self) -> usize {
        Val::TWO_ADICITY
    }

    /// Commit to a collection of evaluation matrices.
    ///
    /// Each element of `evaluations` contains a coset `shift * H` and a matrix `mat` with `mat.height() = |H|`.
    /// Interpreting each column of `mat` as the evaluations of a polynomial `p_i(x)` over `shift * H`,
    /// this computes the evaluations of `p_i` over `gK` where `g` is the chosen generator of the multiplicative group
    /// of `Val` and `K` is the unique subgroup of order `|H| << self.fri.log_blowup`.
    ///
    /// This then outputs a Merkle commitment to these evaluations.
    fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        let ldes = evaluations
            .into_iter()
            .map(|(domain, evals)| {
                assert_eq!(domain.size(), evals.height());
                // coset_lde_batch converts from evaluations over `xH` to evaluations over `shift * x * K`.
                // Hence, letting `shift = g/x` the output will be evaluations over `gK` as desired.
                // When `x = g`, we could just use the standard LDE but currently this doesn't seem
                // to give a meaningful performance boost.
                let shift = Val::GENERATOR / domain.shift();
                // Compute the LDE with blowup factor fri.log_blowup.
                // We bit reverse as this is required by our implementation of the FRI protocol.
                let lde = self
                    .dft
                    .coset_lde_batch(evals, self.fri.log_blowup, shift)
                    .bit_reverse_rows()
                    .to_row_major_matrix();
                Lde::from_bit_reversed_row_major(lde)
            })
            .collect();

        // Commit to the bit-reversed LDEs.
        self.commit_bit_reversed_ldes(ldes)
    }

    fn get_quotient_ldes(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
        _num_chunks: usize,
    ) -> Vec<RowMajorMatrix<Val>> {
        evaluations
            .into_iter()
            .map(|(domain, evals)| {
                assert_eq!(domain.size(), evals.height());
                // coset_lde_batch converts from evaluations over `xH` to evaluations over `shift * x * K`.
                // Hence, letting `shift = g/x` the output will be evaluations over `gK` as desired.
                // When `x = g`, we could just use the standard LDE but currently this doesn't seem
                // to give a meaningful performance boost.
                let shift = Val::GENERATOR / domain.shift();
                // Compute the LDE with blowup factor fri.log_blowup.
                // We bit reverse as this is required by our implementation of the FRI protocol.
                self.dft
                    .coset_lde_batch(evals, self.fri.log_blowup, shift)
                    .bit_reverse_rows()
                    .to_row_major_matrix()
            })
            .collect()
    }

    fn commit_ldes(&self, ldes: Vec<RowMajorMatrix<Val>>) -> (Self::Commitment, Self::ProverData) {
        self.commit_bit_reversed_ldes(
            ldes.into_iter()
                .map(Lde::from_bit_reversed_row_major)
                .collect(),
        )
    }

    /// Given the evaluations on a domain `gH`, return the evaluations on a different domain `g'K`.
    ///
    /// Arguments:
    /// - `prover_data`: The prover data containing all committed evaluation matrices.
    /// - `idx`: The index of the matrix containing the evaluations we want. These evaluations
    ///   are assumed to be over the coset `gH` where `g = Val::GENERATOR`.
    /// - `domain`: The domain `g'K` on which to get evaluations on.
    ///
    /// When `g' = g` (i.e. `Val::GENERATOR`) and `K` is a subgroup of `H`, this is a simple
    /// truncation of the bit-reversed LDE. Otherwise, we recover the polynomial coefficients
    /// from the committed LDE and re-evaluate on the requested domain.
    fn get_evaluations_on_domain<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        let lde = self.mmcs.get_matrices(prover_data)[idx];
        if domain.shift() == Val::GENERATOR && lde.height() >= domain.size() {
            return lde.evaluations_from_prefix(domain.size());
        }

        // The committed LDE contains bit-reversed evaluations over `gH`.
        // Un-bit-reverse, coset iDFT to recover coefficients, truncate to
        // the original polynomial degree, then coset DFT onto the target domain.
        let poly_height = lde.height() >> self.fri.log_blowup;
        let lde_mat = lde.to_natural_order_row_major();
        let mut coeffs = self.dft.coset_idft_batch(lde_mat, Val::GENERATOR);
        let width = coeffs.width();
        coeffs.values.truncate(poly_height * width);
        coeffs.values.resize(domain.size() * width, Val::ZERO);
        let result = self
            .dft
            .coset_dft_batch(coeffs, domain.shift())
            .to_row_major_matrix();
        Lde::evaluations_from_owned(result)
    }

    /// Open a batch of matrices at a collection of points.
    ///
    /// Returns the opened values along with a proof.
    ///
    /// This function assumes that all matrices correspond to evaluations over the
    /// coset `gH` where `g = Val::GENERATOR` and `H` is a subgroup of appropriate size depending on the
    /// matrix.
    fn open(
        &self,
        // For each multi-matrix commitment,
        commitment_data_with_opening_points: Vec<(
            // The matrices and auxiliary prover data
            &Self::ProverData,
            // for each matrix,
            Vec<
                // points to open
                Vec<Challenge>,
            >,
        )>,
        challenger: &mut Challenger,
    ) -> (OpenedValues<Challenge>, Self::Proof) {
        /*

        A quick rundown of the optimizations in this function:
        We are trying to compute sum_i alpha^i * (p(X) - y)/(X - z),
        for each z an opening point, y = p(z). Each p(X) is given as evaluations in bit-reversed order
        in the columns of the matrices. y is computed by barycentric interpolation.
        X and p(X) are in the base field; alpha, y and z are in the extension.
        The primary goal is to minimize extension multiplications.

        - Instead of computing all alpha^i, we just compute alpha^i for i up to the largest width
        of a matrix, then multiply by an "alpha offset" when accumulating.
              a^0 x0 + a^1 x1 + a^2 x2 + a^3 x3 + ...
            = ( a^0 x0 + a^1 x1 ) + a^2 ( a^0 x2 + a^1 x3 ) + ...
            (see `alpha_pows`, `alpha_pow_offset`, `num_reduced`)

        - For each unique point z, we precompute 1/(X-z) for the largest subgroup opened at this point.
        Since we compute it in bit-reversed order, smaller subgroups can simply truncate the vector.
            (see `inv_denoms`)

        - Then, for each matrix (with columns p_i) and opening point z, we want:
            for each row (corresponding to subgroup element X):
                reduced[X] += alpha_offset * sum_i [ alpha^i * inv_denom[X] * (p_i[X] - y[i]) ]

            We can factor out inv_denom, and expand what's left:
                reduced[X] += alpha_offset * inv_denom[X] * sum_i [ alpha^i * p_i[X] - alpha^i * y[i] ]

            And separate the sum:
                reduced[X] += alpha_offset * inv_denom[X] * [ sum_i [ alpha^i * p_i[X] ] - sum_i [ alpha^i * y[i] ] ]

            And now the last sum doesn't depend on X, so we can precompute that for the matrix, too.
            So the hot loop (that depends on both X and i) is just:
                sum_i [ alpha^i * p_i[X] ]

            with alpha^i an extension, p_i[X] a base

        */

        // Contained in each `Self::ProverData` is a list of matrices which have been committed to.
        // We extract those matrices to be able to refer to them directly.
        let mats_and_points = commitment_data_with_opening_points
            .iter()
            .map(|(data, points)| {
                let mats = self.mmcs.get_matrices(data).into_iter().collect_vec();
                debug_assert_eq!(
                    mats.len(),
                    points.len(),
                    "each matrix should have a corresponding set of evaluation points"
                );
                (mats, points)
            })
            .collect_vec();

        // Find the maximum height and the maximum width of matrices in the batch.
        // These do not need to correspond to the same matrix.
        let (global_max_height, global_max_width) = mats_and_points
            .iter()
            .flat_map(|(mats, _)| mats.iter().map(|m| (m.height(), m.width())))
            .reduce(|(hmax, wmax), (h, w)| (hmax.max(h), wmax.max(w)))
            .expect("No Matrices Supplied?");
        let log_global_max_height = log2_strict_usize(global_max_height);

        // Get all values of the coset `gH` for the largest necessary subgroup `H`.
        // We also bit reverse which means that coset has the nice property that
        // `coset[..2^i]` contains the values of `gK` for `|K| = 2^i`.
        let coset = {
            let coset =
                TwoAdicMultiplicativeCoset::new(Val::GENERATOR, log_global_max_height).unwrap();
            let mut coset_points = coset.iter().collect();
            reverse_slice_index_bits(&mut coset_points);
            coset_points
        };

        // For each unique opening point z, we will find the largest degree bound
        // for that point, and precompute 1/(z - X) for the largest subgroup (in bitrev order).
        let inv_denoms = compute_inverse_denominators(&mats_and_points, &coset);

        // Precompute adjusted barycentric weights once per opening point.
        // adjusted[i] = 1/(z - x_i) - 1/z, reused across all matrices opened at z.
        let adjusted_weights = compute_interpolation_adjusted_weights(
            &mats_and_points,
            &inv_denoms,
            self.fri.log_blowup,
        );

        // Evaluate coset representations and write openings to the challenger
        let all_opened_values = mats_and_points
            .iter()
            .map(|(mats, points)| {
                // For each collection of matrices
                izip!(mats.iter(), points.iter())
                    .map(|(mat, points_for_mat)| {
                        // Every committed matrix is assumed to be an LDE at `self.fri.log_blowup`;
                        // `commit`/`commit_ldes` enforce `height >= 1 << log_blowup`. A larger actual
                        // blowup is still sound, just slightly slower.
                        // Ideally, polynomials would be passed in with their blow-up factors known.

                        // The point of this correction is that each column of the matrix corresponds to a low degree polynomial.
                        // Hence we can save time by restricting the height of the matrix to be the minimal height which
                        // uniquely identifies the polynomial.
                        let h = mat.height() >> self.fri.log_blowup;

                        // `subgroup` and `mat` are both in bit-reversed order, so we can truncate.
                        let low_coset = RowsPrefix::new(*mat, h);

                        points_for_mat
                            .iter()
                            .map(|&point| {
                                let _guard =
                                    debug_span!("evaluate matrix", dims = %mat.dimensions())
                                        .entered();

                                // Use Barycentric interpolation to evaluate each column of the matrix at the given point.
                                let ys = debug_span!(
                                    "compute opened values with Lagrange interpolation"
                                )
                                .in_scope(|| {
                                    // Slice the precomputed adjusted weights to match this matrix's height.
                                    // Zero-allocation hot path: straight to the SIMD dot product.
                                    let adj = &adjusted_weights.get(&point).unwrap()[..h];
                                    low_coset.interpolate_coset_with_precomputation(
                                        Val::GENERATOR,
                                        point,
                                        adj,
                                    )
                                });

                                challenger.observe_algebra_slice(&ys);
                                ys
                            })
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();

        // Batch combination challenge

        // Soundness Error:
        // See the discussion in the doc comment of [`prove_fri`]. Essentially, the soundness error
        // for this sample is tightly tied to the soundness error of the FRI protocol.
        // Roughly speaking, at a minimum is it k/|EF| where `k` is the sum of, for each function, the number of
        // points it needs to be opened at. This comes from the fact that we are taking a large linear combination
        // of `(f(zeta) - f(x))/(zeta - x)` for each function `f` and all of `f`'s opening points.
        // In our setup, k is two times the trace width plus the number of quotient polynomials.
        let alpha: Challenge = challenger.sample_algebra_element();

        // We precompute the packed powers of alpha as we need the same powers for each matrix.
        // The hot per-matrix reduction (`rowwise_packed_dot_product`) consumes these directly; the
        // per-opening combination below unpacks `alpha`'s powers lazily via `alpha.powers()`, so we
        // never materialize a full unpacked copy.
        let packed_alpha_powers =
            Challenge::ExtensionPacking::packed_ext_powers_capped(alpha, global_max_width)
                .collect_vec();

        // Now that we have sent the openings to the verifier, it remains to prove
        // that those openings are correct.

        // Given a low degree polynomial `f(x)` with claimed evaluation `f(zeta)`, we can check
        // that `f(zeta)` is correct by doing a low degree test on `(f(zeta) - f(x))/(zeta - x)`.
        // We will use `alpha` to batch together both different claimed openings `zeta` and
        // different polynomials `f` whose evaluation vectors have the same height.

        // TODO: If we allow different polynomials to have different blow_up factors
        // we may need to revisit this and to ensure it is safe to batch them together.

        // num_reduced records the number of (function, opening point) pairs for each `log_height`.
        // TODO: This should really be `[0; Val::TWO_ADICITY]` but that runs into issues with generics.
        let mut num_reduced = [0; 32];

        // For each `log_height` from 2^1 -> 2^32, reduced_openings will contain either `None`
        // if there are no matrices of that height, or `Some(vec)` where `vec` is equal to
        // a weighted sum of `(f(zeta) - f(x))/(zeta - x)` over all `f`'s of that height and
        // for each `f`, all opening points `zeta`. The sum is weighted by powers of the challenge alpha.
        let mut reduced_openings: [_; 32] = core::array::from_fn(|_| None);

        for ((mats, points), openings_for_round) in
            mats_and_points.iter().zip(all_opened_values.iter())
        {
            for (mat, points_for_mat, openings_for_mat) in
                izip!(mats.iter(), points.iter(), openings_for_round.iter())
            {
                let _guard =
                    debug_span!("reduce matrix quotient", dims = %mat.dimensions()).entered();

                let log_height = log2_strict_usize(mat.height());

                // If this is our first matrix at this height, initialise reduced_openings to zero.
                // Otherwise, get a mutable reference to it.
                let reduced_opening_for_log_height = reduced_openings[log_height]
                    .get_or_insert_with(|| Challenge::zero_vec(mat.height()));
                debug_assert_eq!(reduced_opening_for_log_height.len(), mat.height());

                // Treating our matrix M as the evaluations of functions f_0, f_1, ...
                // Compute the evaluations of `Mred(x) = f_0(x) + alpha*f_1(x) + ...`
                let mat_compressed = debug_span!("compress mat").in_scope(|| {
                    // This will be reused for all points z which M is opened at so we collect into a vector.
                    mat.rowwise_packed_dot_product::<Challenge>(&packed_alpha_powers)
                        .collect::<Vec<_>>()
                });

                for (&point, openings) in points_for_mat.iter().zip(openings_for_mat) {
                    // If we have multiple matrices at the same height, we need to scale alpha to combine them.
                    // This means that reduced_openings will contain:
                    // Mred_0(x) + alpha^{M_0.width()}Mred_1(x) + alpha^{M_0.width() + M_1.width()}Mred_2(x) + ...
                    // Where M_0, M_1, ... are the matrices of the same height.
                    let alpha_pow_offset = alpha.exp_u64(num_reduced[log_height] as u64);

                    // As we have all the openings `f_i(z)`, we can combine them using `alpha`
                    // in an identical way to before to compute `Mred(z)`.
                    let reduced_openings: Challenge =
                        dot_product(alpha.powers(), openings.iter().copied());

                    mat_compressed
                        .par_iter()
                        .zip(reduced_opening_for_log_height.par_iter_mut())
                        // inv_denoms contains `1/(z - x)` for `x` in a coset `gK`.
                        // If `|K| =/= mat.height()` we actually want a subset of this
                        // corresponding to the evaluations over `gH` for `|H| = mat.height()`.
                        // As inv_denoms is bit reversed, the evaluations over `gH` are exactly
                        // the evaluations over `gK` at the indices `0..mat.height()`.
                        // So zip will truncate to the desired smaller length.
                        .zip(inv_denoms.get(&point).unwrap().par_iter())
                        // Map the function `Mred(x) -> (Mred(z) - Mred(x))/(z - x)`
                        // across the evaluation vector of `Mred(x)`. Adjust by alpha_pow_offset
                        // as needed.
                        .for_each(|((&reduced_row, ro), &inv_denom)| {
                            *ro += alpha_pow_offset * (reduced_openings - reduced_row) * inv_denom;
                        });
                    num_reduced[log_height] += mat.width();
                }
            }
        }

        // These point-specific precomputations are not used by FRI. Release them before
        // constructing the FRI input so their large allocations cannot overlap that phase.
        drop(adjusted_weights);
        drop(inv_denoms);
        drop(coset);

        // It remains to prove that all evaluation vectors in reduced_openings correspond to
        // low degree functions.
        let fri_input = reduced_openings.into_iter().rev().flatten().collect_vec();

        let folding: TwoAdicFriFoldingForMmcs<Val, InputMmcs> = TwoAdicFriFolding(PhantomData);

        // Produce the FRI proof.
        let fri_proof = prover::prove_fri(
            &folding,
            &self.fri,
            fri_input,
            challenger,
            log_global_max_height,
            &commitment_data_with_opening_points,
            &self.mmcs,
        );

        (all_opened_values, fri_proof)
    }

    fn verify(
        &self,
        // For each commitment:
        commitments_with_opening_points: Vec<
            CommitmentWithOpeningPoints<Challenge, Self::Commitment, Self::Domain>,
        >,
        proof: &Self::Proof,
        challenger: &mut Challenger,
    ) -> Result<(), Self::Error> {
        // Write all evaluations to challenger.
        // Need to ensure to do this in the same order as the prover.
        for (_, round) in &commitments_with_opening_points {
            for (_, mat) in round {
                for (_, point) in mat {
                    challenger.observe_algebra_slice(point);
                }
            }
        }

        let folding: TwoAdicFriFoldingForMmcs<Val, InputMmcs> = TwoAdicFriFolding(PhantomData);

        verifier::verify_fri(
            &folding,
            &self.fri,
            proof,
            challenger,
            &commitments_with_opening_points,
            &self.mmcs,
        )?;

        Ok(())
    }
}

impl<Val, Dft, InputMmcs, FriMmcs, Lde> BuildPeriodicLdeTableFast
    for TwoAdicFriPcs<Val, Dft, InputMmcs, FriMmcs, Lde>
where
    Val: TwoAdicField,
    Dft: TwoAdicSubgroupDft<Val> + Default,
{
    type PeriodicDomain = TwoAdicMultiplicativeCoset<Val>;

    fn maybe_build_periodic_lde_table_fast(
        &self,
        periodic_cols: &[Vec<p3_commit::Val<Self::PeriodicDomain>>],
        trace_domain: Self::PeriodicDomain,
        quotient_domain: Self::PeriodicDomain,
    ) -> Option<PeriodicLdeTable<p3_commit::Val<Self::PeriodicDomain>>>
    where
        p3_commit::Val<Self::PeriodicDomain>: Clone,
    {
        let periodic_cols_val: &[Vec<Val>] = unsafe { core::mem::transmute(periodic_cols) };
        let table = build_periodic_lde_table_two_adic::<Val, Dft>(
            periodic_cols_val,
            &trace_domain,
            &quotient_domain,
        );
        Some(table)
    }
}

/// Compute vectors of inverse denominators for each unique opening point.
///
/// Arguments:
/// - `mats_and_points` is a list of matrices and for each matrix a list of points. We assume that
///    the total number of distinct points is very small as several methods contained herein are `O(n^2)`
///    in the number of points.
/// - `coset` is the set of points `gH` where `H` a two-adic subgroup such that `|H|` is greater
///     than or equal to the largest height of any matrix in `mats_and_points`. The values
///     in `coset` must be in bit-reversed order.
///
/// For each point `z`, let `M` be the matrix of largest height which opens at `z`.
/// let `H_z` be the unique subgroup of order `M.height()`. Compute the vector of
/// `1/(z - x)` for `x` in `gH_z`.
///
/// Return a LinearMap which allows us to recover the computed vectors for each `z`.
#[instrument(skip_all)]
fn compute_inverse_denominators<F: TwoAdicField, EF: ExtensionField<F>, M: Matrix<F>>(
    mats_and_points: &[(Vec<&M>, &Vec<Vec<EF>>)],
    coset: &[F],
) -> LinearMap<EF, Vec<EF>> {
    // For each `z`, find the maximal height of any matrix which we need to
    // open at `z`.
    let mut max_log_height_for_point: LinearMap<EF, usize> = LinearMap::new();
    for (mats, points) in mats_and_points {
        for (mat, points_for_mat) in izip!(mats, *points) {
            let log_height = log2_strict_usize(mat.height());
            for &z in points_for_mat {
                if let Some(lh) = max_log_height_for_point.get_mut(&z) {
                    *lh = core::cmp::max(*lh, log_height);
                } else {
                    max_log_height_for_point.insert(z, log_height);
                }
            }
        }
    }

    // Compute the inverse denominators for each point `z`.
    max_log_height_for_point
        .into_iter()
        .map(|(z, log_height)| {
            (
                z,
                batch_multiplicative_inverse(
                    // As coset is stored in bit-reversed order,
                    // we can just take the first `2^log_height` elements.
                    &coset[..(1 << log_height)]
                        .iter()
                        .map(|&x| z - x)
                        .collect_vec(),
                ),
            )
        })
        .collect()
}

/// Compute only the adjusted-weight prefixes consumed by polynomial interpolation.
///
/// Inverse denominators cover the full LDE because quotient reduction consumes every LDE row.
/// Interpolation truncates each LDE to its polynomial height, so retaining adjusted weights past
/// the largest such prefix for an opening point would only duplicate unused extension elements.
fn compute_interpolation_adjusted_weights<F: TwoAdicField, EF: ExtensionField<F>, M: Matrix<F>>(
    mats_and_points: &[(Vec<&M>, &Vec<Vec<EF>>)],
    inv_denoms: &LinearMap<EF, Vec<EF>>,
    log_blowup: usize,
) -> LinearMap<EF, Vec<EF>> {
    let mut max_height_for_point: LinearMap<EF, usize> = LinearMap::new();
    for (mats, points) in mats_and_points {
        for (mat, points_for_mat) in izip!(mats, *points) {
            let height = mat.height() >> log_blowup;
            debug_assert_ne!(height, 0);
            for &point in points_for_mat {
                if let Some(max_height) = max_height_for_point.get_mut(&point) {
                    *max_height = core::cmp::max(*max_height, height);
                } else {
                    max_height_for_point.insert(point, height);
                }
            }
        }
    }

    max_height_for_point
        .into_iter()
        .map(|(point, height)| {
            let denoms = inv_denoms
                .get(&point)
                .expect("inverse denominators must exist for every opening point");
            debug_assert!(height <= denoms.len());
            (point, compute_adjusted_weights(point, &denoms[..height]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::{CanObserve, DuplexChallenger};
    use p3_commit::{BatchOpening, ExtensionMmcs, Mmcs};
    use p3_field::Field;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    type Challenge = BinomialExtensionField<BabyBear, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type TestHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type TestCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type ValMmcs = MerkleTreeMmcs<
        <BabyBear as Field>::Packing,
        <BabyBear as Field>::Packing,
        TestHash,
        TestCompress,
        2,
        8,
    >;
    type ChallengeMmcs = ExtensionMmcs<BabyBear, Challenge, ValMmcs>;
    type TestChallenger = DuplexChallenger<BabyBear, Perm, 16, 8>;
    type ProductionFolding = TwoAdicFriFoldingForMmcs<BabyBear, ValMmcs>;

    struct ReferenceFolding;

    impl FriFoldingStrategy<BabyBear, Challenge> for ReferenceFolding {
        type InputProof = Vec<BatchOpening<BabyBear, ValMmcs>>;
        type InputError = ();

        fn extra_query_index_bits(&self) -> usize {
            0
        }

        fn fold_row(
            &self,
            index: usize,
            log_height: usize,
            log_arity: usize,
            beta: Challenge,
            evals: impl Iterator<Item = Challenge>,
        ) -> Challenge {
            let folding = TwoAdicFriFolding::<Self::InputProof, ()>(PhantomData);
            <TwoAdicFriFolding<Self::InputProof, ()> as FriFoldingStrategy<
                BabyBear,
                Challenge,
            >>::fold_row(
                &folding,
                index,
                log_height,
                log_arity,
                beta,
                evals,
            )
        }

        fn fold_matrix<M: Matrix<Challenge>>(
            &self,
            beta: Challenge,
            log_arity: usize,
            m: M,
        ) -> Vec<Challenge> {
            reference_fold_matrix::<BabyBear, _, _>(beta, log_arity, m)
        }
    }

    fn matrix(height: usize) -> RowMajorMatrix<BabyBear> {
        RowMajorMatrix::new(BabyBear::zero_vec(height), 1)
    }

    fn point(coefficients: [u64; 4]) -> Challenge {
        Challenge::new(coefficients.map(BabyBear::from_u64))
    }

    fn reference_fold_matrix<F, EF, M>(beta: EF, log_arity: usize, m: M) -> Vec<EF>
    where
        F: TwoAdicField,
        EF: ExtensionField<F>,
        M: Matrix<EF>,
    {
        let mut data = m.to_row_major_matrix().values;
        let initial_height = data.len() / 2;
        let g_inv = F::two_adic_generator(log2_strict_usize(initial_height) + 1).inverse();
        let mut halve_inv_powers = g_inv
            .shifted_powers(F::ONE.halve())
            .collect_n(initial_height);
        reverse_slice_index_bits(&mut halve_inv_powers);

        let two = F::ONE + F::ONE;
        let mut current_beta = beta;
        let mut next_data = EF::zero_vec(initial_height);

        for step in 0..log_arity {
            let height = data.len() / 2;
            if step > 0 {
                for j in 0..height {
                    halve_inv_powers[j] = two * halve_inv_powers[j << 1].square();
                }
            }
            for j in 0..height {
                let lo = data[j << 1];
                let hi = data[(j << 1) + 1];
                next_data[j] = (lo + hi).halve() + (lo - hi) * current_beta * halve_inv_powers[j];
            }
            current_beta = current_beta.square();
            data.truncate(height);
            data.copy_from_slice(&next_data[..height]);
        }

        data
    }

    fn assert_fold_matches_reference(values: Vec<Challenge>, height: usize, log_arity: usize) {
        let arity = 1 << log_arity;
        let beta = point([11, 7, 5, 3]);
        let matrix = RowMajorMatrix::new(values, arity);
        assert_eq!(matrix.height(), height);

        let folding = TwoAdicFriFolding::<(), ()>(PhantomData);
        let actual =
            <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<BabyBear, Challenge>>::fold_matrix(
                &folding,
                beta,
                log_arity,
                matrix.as_view(),
            );
        let expected = reference_fold_matrix::<BabyBear, _, _>(beta, log_arity, matrix.as_view());
        assert_eq!(actual, expected, "height={height}, log_arity={log_arity}");
    }

    #[test]
    fn direct_fold_matches_reference_for_edge_vectors_and_arities_one_through_four() {
        for log_arity in 1..=4 {
            let arity = 1 << log_arity;
            for height in [1, 2, 8] {
                let len = height * arity;
                assert_fold_matches_reference(vec![Challenge::ZERO; len], height, log_arity);
                assert_fold_matches_reference(vec![point([9, 1, 4, 2]); len], height, log_arity);
                assert_fold_matches_reference(
                    (0..len)
                        .map(|i| {
                            if i & 1 == 0 {
                                point([1, 0, 2, 0])
                            } else {
                                point([0, 3, 0, 4])
                            }
                        })
                        .collect(),
                    height,
                    log_arity,
                );
            }
        }
    }

    #[test]
    fn direct_fold_matches_reference_for_seeded_random_vectors() {
        let mut rng = SmallRng::seed_from_u64(0x434d_4644);
        for log_arity in 1..=4 {
            let arity = 1 << log_arity;
            for height in [1, 2, 4, 16] {
                let values = (0..height * arity).map(|_| rng.random()).collect();
                assert_fold_matches_reference(values, height, log_arity);
            }
        }
    }

    #[test]
    fn direct_fold_preserves_complete_deterministic_proof_bytes() {
        let mut rng = SmallRng::seed_from_u64(0x4652_495f_4259_5445);
        let perm = Perm::new_from_rng_128(&mut rng);
        let hash = TestHash::new(perm.clone());
        let compress = TestCompress::new(perm.clone());
        let input_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));
        let params = FriParameters {
            log_blowup: 1,
            log_final_poly_len: 0,
            max_log_arity: 4,
            num_queries: 3,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs: challenge_mmcs,
        };

        let input_matrix = RowMajorMatrix::new(
            (0..64)
                .map(|i| BabyBear::from_u64((i + 1) as u64))
                .collect(),
            1,
        );
        let (input_commitment, input_data) = input_mmcs.commit_matrix(input_matrix);
        let inputs = vec![(0..64).map(|_| rng.random()).collect::<Vec<Challenge>>()];
        let opening_point = rng.random();

        let mut challenger = TestChallenger::new(perm);
        challenger.observe(&input_commitment);
        let mut direct_challenger = challenger.clone();
        let mut reference_challenger = challenger;

        let direct_data = [(&input_data, vec![vec![opening_point]])];
        let direct = crate::prover::prove_fri::<
            ProductionFolding,
            BabyBear,
            Challenge,
            ValMmcs,
            ChallengeMmcs,
            TestChallenger,
            RowMajorMatrix<BabyBear>,
        >(
            &TwoAdicFriFolding(PhantomData),
            &params,
            inputs.clone(),
            &mut direct_challenger,
            6,
            &direct_data,
            &input_mmcs,
        );

        let reference_data = [(&input_data, vec![vec![opening_point]])];
        let reference = crate::prover::prove_fri::<
            ReferenceFolding,
            BabyBear,
            Challenge,
            ValMmcs,
            ChallengeMmcs,
            TestChallenger,
            RowMajorMatrix<BabyBear>,
        >(
            &ReferenceFolding,
            &params,
            inputs,
            &mut reference_challenger,
            6,
            &reference_data,
            &input_mmcs,
        );

        assert_eq!(
            direct.query_proofs[0].commit_phase_openings[0].log_arity, 4,
            "fixture must exercise the non-binary direct fold"
        );
        assert_eq!(
            serde_json::to_vec(&direct).unwrap(),
            serde_json::to_vec(&reference).unwrap(),
        );
    }

    #[test]
    fn adjusted_weights_match_legacy_prefixes_for_mixed_heights_and_repeated_points() {
        const LOG_BLOWUP: usize = 2;

        let short = matrix(8);
        let medium = matrix(16);
        let tall = matrix(32);

        // A non-base coefficient keeps every point outside the base-field coset.
        let repeated = point([2, 1, 0, 0]);
        let short_only = point([3, 0, 1, 0]);
        let medium_only = point([5, 0, 0, 1]);

        // Put the shortest occurrence of `repeated` first, then repeat it in another round at
        // the tallest height. This exercises both mixed heights and max-prefix accumulation.
        let first_round_points = vec![vec![repeated, short_only], vec![medium_only]];
        let second_round_points = vec![vec![repeated]];
        let mats_and_points = vec![
            (vec![&short, &medium], &first_round_points),
            (vec![&tall], &second_round_points),
        ];

        let mut coset = TwoAdicMultiplicativeCoset::new(BabyBear::GENERATOR, 5)
            .unwrap()
            .iter()
            .collect_vec();
        reverse_slice_index_bits(&mut coset);

        let inv_denoms = compute_inverse_denominators(&mats_and_points, &coset);
        let bounded =
            compute_interpolation_adjusted_weights(&mats_and_points, &inv_denoms, LOG_BLOWUP);

        for (point, expected_height) in [
            (repeated, tall.height() >> LOG_BLOWUP),
            (short_only, short.height() >> LOG_BLOWUP),
            (medium_only, medium.height() >> LOG_BLOWUP),
        ] {
            let full = compute_adjusted_weights(point, inv_denoms.get(&point).unwrap());
            let actual = bounded.get(&point).unwrap();
            assert_eq!(actual.len(), expected_height);
            assert_eq!(actual, &full[..expected_height]);
        }
    }
}
