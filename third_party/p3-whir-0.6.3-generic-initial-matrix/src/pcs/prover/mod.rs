use alloc::vec::Vec;
use core::convert::Infallible;
use core::marker::PhantomData;
use core::ops::Deref;

use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpening, ExtensionMmcs, Mmcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::Matrix;
use p3_matrix::dense::DenseMatrix;
use p3_matrix::extension::FlatMatrixView;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::constraints::Constraint;
use p3_sumcheck::constraints::statement::{EqStatement, SelectStatement};
use p3_sumcheck::layout::Layout;
use p3_sumcheck::strategy::{SumcheckProver, VariableOrder};
use tracing::instrument;

use crate::fiat_shamir::domain_separator::DomainSeparator;
use crate::parameters::WhirConfig;
use crate::pcs::committer::writer::commit_extension;
use crate::pcs::proof::{QueryOpening, SumcheckData, WhirProof};
use crate::pcs::utils::get_challenge_stir_queries;

/// Fallible state required by WHIR after the layout-specific initial sumcheck.
///
/// Implementations may keep the residual product polynomial in external
/// storage. Storage identities and errors are prover-local: this interface
/// does not add anything to the Fiat-Shamir transcript or the public proof.
/// An error may occur after the proof and challenger have been partially
/// advanced; callers must discard both values for that proving attempt.
/// The ordinary dense [`SumcheckProver`] implements this trait with
/// [`Infallible`] as its error type.
pub trait FallibleWhirProverState<EF, F, Dft, MT, Challenger>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    MT: Mmcs<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    /// Backend error surfaced without advancing through a fallback path.
    type Error;
    /// Extension-field matrix retained by the MMCS after a round commitment.
    type ExtensionMatrix: Matrix<EF>;

    /// Number of variables not yet folded from the residual polynomial.
    fn num_variables(&self) -> usize;

    /// Encode and commit the current evaluation polynomial.
    #[allow(clippy::type_complexity)]
    fn try_commit_extension(
        &self,
        order: VariableOrder,
        dft: &Dft,
        extension_mmcs: &ExtensionMmcs<F, EF, MT>,
        folding: usize,
        inv_rate: usize,
    ) -> Result<
        (
            MT::Commitment,
            MT::ProverData<FlatMatrixView<F, EF, Self::ExtensionMatrix>>,
        ),
        Self::Error,
    >;

    /// Evaluate the current multilinear polynomial at `point`.
    fn try_eval(&self, point: &Point<EF>) -> Result<EF, Self::Error>;

    /// Open an initial base-field commitment at `index`.
    fn try_open_base<M: Matrix<F>>(
        &self,
        index: usize,
        mmcs: &MT,
        prover_data: &MT::ProverData<M>,
    ) -> Result<BatchOpening<F, MT>, Self::Error>;

    /// Open a folded extension-field commitment at `index`.
    #[allow(clippy::type_complexity)]
    fn try_open_extension(
        &self,
        index: usize,
        extension_mmcs: &ExtensionMmcs<F, EF, MT>,
        prover_data: &MT::ProverData<FlatMatrixView<F, EF, Self::ExtensionMatrix>>,
    ) -> Result<BatchOpening<EF, ExtensionMmcs<F, EF, MT>>, Self::Error>;

    /// Apply an optional constraint and execute the requested sumcheck folds.
    fn try_compute_sumcheck_polynomials(
        &mut self,
        sumcheck_data: &mut SumcheckData<F, EF>,
        challenger: &mut Challenger,
        folding_factor: usize,
        pow_bits: usize,
        constraint: Option<Constraint<F, EF>>,
    ) -> Result<Point<EF>, Self::Error>;

    /// Materialize the final polynomial sent in the clear.
    fn try_final_poly(&self) -> Result<Poly<EF>, Self::Error>;
}

impl<EF, F, Dft, MT, Challenger> FallibleWhirProverState<EF, F, Dft, MT, Challenger>
    for SumcheckProver<F, EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    MT: Mmcs<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    type Error = Infallible;
    type ExtensionMatrix = DenseMatrix<EF>;

    fn num_variables(&self) -> usize {
        self.num_variables()
    }

    fn try_commit_extension(
        &self,
        order: VariableOrder,
        dft: &Dft,
        extension_mmcs: &ExtensionMmcs<F, EF, MT>,
        folding: usize,
        inv_rate: usize,
    ) -> Result<
        (
            MT::Commitment,
            MT::ProverData<FlatMatrixView<F, EF, Self::ExtensionMatrix>>,
        ),
        Self::Error,
    > {
        Ok(commit_extension(
            order,
            dft,
            extension_mmcs,
            self.evals_view(),
            folding,
            inv_rate,
        ))
    }

    fn try_eval(&self, point: &Point<EF>) -> Result<EF, Self::Error> {
        Ok(self.eval(point))
    }

    fn try_open_base<M: Matrix<F>>(
        &self,
        index: usize,
        mmcs: &MT,
        prover_data: &MT::ProverData<M>,
    ) -> Result<BatchOpening<F, MT>, Self::Error> {
        Ok(mmcs.open_batch(index, prover_data))
    }

    fn try_open_extension(
        &self,
        index: usize,
        extension_mmcs: &ExtensionMmcs<F, EF, MT>,
        prover_data: &MT::ProverData<FlatMatrixView<F, EF, Self::ExtensionMatrix>>,
    ) -> Result<BatchOpening<EF, ExtensionMmcs<F, EF, MT>>, Self::Error> {
        Ok(extension_mmcs.open_batch(index, prover_data))
    }

    fn try_compute_sumcheck_polynomials(
        &mut self,
        sumcheck_data: &mut SumcheckData<F, EF>,
        challenger: &mut Challenger,
        folding_factor: usize,
        pow_bits: usize,
        constraint: Option<Constraint<F, EF>>,
    ) -> Result<Point<EF>, Self::Error> {
        Ok(self.compute_sumcheck_polynomials(
            sumcheck_data,
            challenger,
            folding_factor,
            pow_bits,
            constraint,
        ))
    }

    fn try_final_poly(&self) -> Result<Poly<EF>, Self::Error> {
        Ok(self.evals())
    }
}

/// Active Merkle prover data for the polynomial currently being queried.
#[derive(Debug)]
enum RoundData<BaseData, ExtData> {
    /// Base-field commitment produced by the initial round.
    Base(BaseData),
    /// Extension-field commitment produced by every subsequent folded round.
    Ext(ExtData),
}

/// Per-round state during WHIR proof generation.
///
/// Tracks the sumcheck prover, folding randomness, and Merkle
/// commitments across base and extension field rounds.
#[derive(Debug)]
struct RoundState<State, EF, BaseData, ExtData> {
    /// Backend managing constraint batching and polynomial folding.
    prover_state: State,
    /// Folding challenges (alpha_1, ..., alpha_k) for the current round.
    folding_randomness: Point<EF>,
    /// Active Merkle prover data for the polynomial currently being queried.
    round_data: RoundData<BaseData, ExtData>,
}

/// Per-round prover state with the base and extension MMCS shapes fixed.
type WhirRoundState<State, EF, F, MT, M, ExtensionMatrix> = RoundState<
    State,
    EF,
    <MT as Mmcs<F>>::ProverData<M>,
    <MT as Mmcs<F>>::ProverData<FlatMatrixView<F, EF, ExtensionMatrix>>,
>;

/// WHIR prover bundling the protocol config with its FFT and commitment backends.
#[derive(Debug)]
pub struct WhirProver<EF, F, Dft, MT, Challenger, Layout>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Derived per-protocol parameters and per-round configuration.
    pub config: WhirConfig<EF, F, Challenger>,
    /// FFT engine used to encode polynomials before each commitment.
    pub dft: Dft,
    /// Base-field Merkle commitment scheme used in the initial round.
    pub mmcs: MT,
    /// Extension-field commitment scheme used in every folded round.
    pub extension_mmcs: ExtensionMmcs<F, EF, MT>,
    /// Marker tying the prover to a specific stacked-layout binding mode.
    _marker: PhantomData<Layout>,
}

impl<EF, F, Dft, MT, Challenger, Layout> Deref for WhirProver<EF, F, Dft, MT, Challenger, Layout>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Target = WhirConfig<EF, F, Challenger>;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<EF, F, Dft, MT, Challenger, L> WhirProver<EF, F, Dft, MT, Challenger, L>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F> + CanSampleUniformBits<F>,
    MT: Mmcs<F>,
    L: Layout<F, EF>,
{
    /// Builds a prover from a derived config, an FFT engine, and a base-field MMCS.
    ///
    /// The extension-field MMCS is constructed by wrapping the base-field one,
    /// so callers never have to thread it through manually.
    pub fn new(config: WhirConfig<EF, F, Challenger>, dft: Dft, mmcs: MT) -> Self {
        let extension_mmcs = ExtensionMmcs::new(mmcs.clone());
        Self {
            config,
            dft,
            mmcs,
            extension_mmcs,
            _marker: PhantomData,
        }
    }

    /// Build the Fiat-Shamir domain separator for this protocol instance.
    ///
    /// The domain separator encodes all public protocol parameters into
    /// the transcript so the verifier's challenges are bound to this
    /// specific configuration (see Construction 5.1, step 1).
    pub fn add_domain_separator<const DIGEST_ELEMS: usize>(&self, ds: &mut DomainSeparator<EF, F>)
    where
        EF: TwoAdicField,
    {
        // Encode the public parameters (num_variables, security, rate, etc.).
        ds.commit_statement::<Challenger, DIGEST_ELEMS>(&self.config);
        // Encode the full proof structure (round counts, query counts, etc.).
        ds.add_whir_proof::<Challenger, DIGEST_ELEMS>(&self.config);
    }

    /// Execute the full WHIR proving protocol.
    ///
    /// Performs multi-round sumcheck-based polynomial folding,
    /// producing Merkle authentication paths and constraint evaluations.
    #[instrument(skip_all)]
    pub fn prove<M: Matrix<F>>(
        &self,
        proof: &mut WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        layout: L,
        prover_data: MT::ProverData<M>,
    ) where
        Dft: TwoAdicSubgroupDft<F>,
        Challenger: CanObserve<MT::Commitment>,
    {
        assert_eq!(self.round_folding_factor(0), layout.folding());

        let (sumcheck_prover, folding_randomness) = layout.into_sumcheck(
            &mut proof.initial_sumcheck,
            self.starting_folding_pow_bits,
            challenger,
        );

        self.prove_from_sumcheck(
            proof,
            challenger,
            sumcheck_prover,
            folding_randomness,
            prover_data,
        );
    }

    /// Continue proving from an already completed initial sumcheck batch.
    ///
    /// This is the fallible-storage seam for layouts that prepare WHIR's
    /// initial fold without materialising the full extension-field product
    /// polynomial. The caller must have observed the initial commitment and
    /// every opening claim in the ordinary order, and must have written the
    /// exact initial sumcheck messages into `proof` before calling this method.
    /// No additional transcript element is observed here before the first
    /// ordinary WHIR round.
    pub fn prove_from_sumcheck<M: Matrix<F>>(
        &self,
        proof: &mut WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        sumcheck_prover: SumcheckProver<F, EF>,
        folding_randomness: Point<EF>,
        prover_data: MT::ProverData<M>,
    ) where
        Dft: TwoAdicSubgroupDft<F>,
        Challenger: CanObserve<MT::Commitment>,
    {
        match self.try_prove_from_state(
            proof,
            challenger,
            sumcheck_prover,
            folding_randomness,
            prover_data,
        ) {
            Ok(()) => {}
            Err(never) => match never {},
        }
    }

    /// Continue proving from a caller-provided fallible residual state.
    ///
    /// This is the prover-only external-storage seam. It produces the same
    /// proof and observes the same transcript elements as
    /// [`Self::prove_from_sumcheck`]. Backend metadata is never observed by
    /// the challenger. If a state operation fails, the error is returned
    /// immediately and this method does not retry with another backend.
    /// The proof and challenger may contain a valid transcript prefix on
    /// error; callers must discard both and start a new proving attempt.
    pub fn try_prove_from_state<M, State>(
        &self,
        proof: &mut WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        prover_state: State,
        folding_randomness: Point<EF>,
        prover_data: MT::ProverData<M>,
    ) -> Result<(), State::Error>
    where
        M: Matrix<F>,
        State: FallibleWhirProverState<EF, F, Dft, MT, Challenger>,
        Challenger: CanObserve<MT::Commitment>,
    {
        let initial_folding = self.round_folding_factor(0);
        assert_eq!(proof.initial_sumcheck.num_rounds(), initial_folding);
        assert_eq!(folding_randomness.num_variables(), initial_folding);
        assert_eq!(
            prover_state.num_variables(),
            self.num_variables - initial_folding
        );
        let variable_order = L::variable_order();

        let mut round_state = RoundState {
            prover_state,
            folding_randomness,
            round_data: RoundData::Base(prover_data),
        };

        // Run each WHIR folding round.
        for round in 0..=self.n_rounds() {
            self.try_round(round, proof, challenger, &mut round_state, variable_order)?;
        }

        Ok(())
    }

    #[instrument(skip_all, fields(round_number = round_index, log_size = self.num_variables - self.total_folded_through(round_index)))]
    #[allow(clippy::too_many_lines)]
    fn try_round<M, State>(
        &self,
        round_index: usize,
        proof: &mut WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        round_state: &mut WhirRoundState<State, EF, F, MT, M, State::ExtensionMatrix>,
        variable_order: VariableOrder,
    ) -> Result<(), State::Error>
    where
        M: Matrix<F>,
        State: FallibleWhirProverState<EF, F, Dft, MT, Challenger>,
        Challenger: CanObserve<MT::Commitment>,
    {
        let num_variables = self.num_variables - self.total_folded_through(round_index);
        assert_eq!(num_variables, round_state.prover_state.num_variables());

        // Final round: send polynomial in the clear.
        if round_index == self.n_rounds() {
            return self.try_final_round(round_index, proof, challenger, round_state);
        }

        let round_params = &self.round_parameters[round_index];
        let folding_factor_next = self.round_folding_factor(round_index + 1);
        let inv_rate = self.inv_rate(round_index);

        // Commit straight from the live sumcheck buffer; no scalar copy is materialized.
        let (root, prover_data) = round_state.prover_state.try_commit_extension(
            variable_order,
            &self.dft,
            &self.extension_mmcs,
            folding_factor_next,
            inv_rate,
        )?;

        // Observe the round commitment.
        challenger.observe(root.clone());
        proof.rounds[round_index].commitment = Some(root);

        // OOD sampling.
        let mut ood_statement = EqStatement::initialize(num_variables);
        let mut ood_answers = Vec::with_capacity(round_params.ood_samples);
        for _ in 0..round_params.ood_samples {
            let point =
                Point::expand_from_univariate(challenger.sample_algebra_element(), num_variables);
            let eval = round_state.prover_state.try_eval(&point)?;
            challenger.observe_algebra_element(eval);

            ood_answers.push(eval);
            ood_statement.add_evaluated_constraint(point, eval);
        }
        proof.rounds[round_index].ood_answers = ood_answers;

        // PoW grinding: prevents query manipulation by forcing work after committing.
        if round_params.pow_bits > 0 {
            proof.rounds[round_index].pow_witness = challenger.grind(round_params.pow_bits);
        }

        challenger.sample();

        // STIR query sampling.
        let stir_challenges_indexes = get_challenge_stir_queries::<Challenger, F>(
            round_params.domain_size,
            self.round_folding_factor(round_index),
            round_params.num_queries,
            challenger,
        );

        let mut stir_statement = SelectStatement::initialize(num_variables);
        let mut queries = Vec::with_capacity(stir_challenges_indexes.len());
        let query_randomness = match variable_order {
            VariableOrder::Prefix => round_state.folding_randomness.clone(),
            VariableOrder::Suffix => round_state.folding_randomness.reversed(),
        };

        // Open Merkle proofs and evaluate folded polynomials at each queried position.
        match &round_state.round_data {
            RoundData::Base(data) => {
                for &challenge in &stir_challenges_indexes {
                    let opening = round_state
                        .prover_state
                        .try_open_base(challenge, &self.mmcs, data)?;
                    // WHIR commits a single matrix per round, so take its one opened row.
                    let answer = opening
                        .opened_values
                        .into_iter()
                        .next()
                        .expect("a committed batch opens at least one matrix");

                    // Evaluate the fold by borrowing the row.
                    // Then hand the same allocation to the proof, with no per-query leaf copy.
                    let poly = Poly::new(answer);
                    let eval = poly.eval_base(&query_randomness);
                    let var = round_params.folded_domain_gen.exp_u64(challenge as u64);
                    stir_statement.add_constraint(var, eval);

                    queries.push(QueryOpening::Base {
                        values: poly.into_evals(),
                        proof: opening.opening_proof,
                    });
                }
            }
            RoundData::Ext(data) => {
                for &challenge in &stir_challenges_indexes {
                    let opening = round_state.prover_state.try_open_extension(
                        challenge,
                        &self.extension_mmcs,
                        data,
                    )?;
                    // WHIR commits a single matrix per round, so take its one opened row.
                    let answer = opening
                        .opened_values
                        .into_iter()
                        .next()
                        .expect("a committed batch opens at least one matrix");

                    // Evaluate the fold by borrowing the row.
                    // Then hand the same allocation to the proof, with no per-query leaf copy.
                    let poly = Poly::new(answer);
                    let eval = poly.eval_ext::<F>(&query_randomness);
                    let var = round_params.folded_domain_gen.exp_u64(challenge as u64);
                    stir_statement.add_constraint(var, eval);

                    queries.push(QueryOpening::Extension {
                        values: poly.into_evals(),
                        proof: opening.opening_proof,
                    });
                }
            }
        }

        proof.rounds[round_index].queries = queries;

        let constraint = Constraint::new(
            challenger.sample_algebra_element(),
            ood_statement,
            stir_statement,
        );

        // Run sumcheck and fold the polynomial.
        let mut sumcheck_data: SumcheckData<F, EF> = SumcheckData::default();
        let folding_randomness = round_state.prover_state.try_compute_sumcheck_polynomials(
            &mut sumcheck_data,
            challenger,
            folding_factor_next,
            round_params.folding_pow_bits,
            Some(constraint),
        )?;
        proof.set_sumcheck_data_at(sumcheck_data, round_index);

        // Update round state for next iteration.
        round_state.folding_randomness = folding_randomness;
        round_state.round_data = RoundData::Ext(prover_data);

        Ok(())
    }

    #[instrument(skip_all)]
    fn try_final_round<M, State>(
        &self,
        round_index: usize,
        proof: &mut WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        round_state: &mut WhirRoundState<State, EF, F, MT, M, State::ExtensionMatrix>,
    ) -> Result<(), State::Error>
    where
        M: Matrix<F>,
        State: FallibleWhirProverState<EF, F, Dft, MT, Challenger>,
    {
        // Send final polynomial coefficients in the clear.
        // Unpack once; the transcript and the proof share the same copy.
        let final_poly = round_state.prover_state.try_final_poly()?;
        challenger.observe_algebra_slice(final_poly.as_slice());
        proof.final_poly = Some(final_poly);

        // PoW grinding for the final round.
        if self.final_pow_bits > 0 {
            proof.final_pow_witness = challenger.grind(self.final_pow_bits);
        }

        // Final STIR queries.
        let final_challenge_indexes = get_challenge_stir_queries::<Challenger, F>(
            self.final_round_config().domain_size,
            self.round_folding_factor(round_index),
            self.final_queries,
            challenger,
        );

        // Open Merkle proofs at the queried positions.
        match &round_state.round_data {
            RoundData::Base(data) => {
                for challenge in final_challenge_indexes {
                    let commitment = round_state
                        .prover_state
                        .try_open_base(challenge, &self.mmcs, data)?;

                    proof.final_queries.push(QueryOpening::Base {
                        values: commitment.opened_values[0].clone(),
                        proof: commitment.opening_proof,
                    });
                }
            }

            RoundData::Ext(data) => {
                for challenge in final_challenge_indexes {
                    let commitment = round_state.prover_state.try_open_extension(
                        challenge,
                        &self.extension_mmcs,
                        data,
                    )?;
                    proof.final_queries.push(QueryOpening::Extension {
                        values: commitment.opened_values[0].clone(),
                        proof: commitment.opening_proof,
                    });
                }
            }
        }

        // Optional final sumcheck.
        if self.final_sumcheck_rounds > 0 {
            let mut sumcheck_data: SumcheckData<F, EF> = SumcheckData::default();
            round_state.prover_state.try_compute_sumcheck_polynomials(
                &mut sumcheck_data,
                challenger,
                self.final_sumcheck_rounds,
                self.final_folding_pow_bits,
                None,
            )?;
            proof.set_final_sumcheck_data(sumcheck_data);
        }

        Ok(())
    }
}
