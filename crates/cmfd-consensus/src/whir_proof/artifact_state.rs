//! Fallible, artifact-backed WHIR prover state after the initial suffix fold.
//!
//! This module is deliberately prover-local. Artifact identities authenticate
//! scratch capabilities and their lineage, but none of that metadata is added
//! to Fiat-Shamir. A storage error poisons the attempt: callers must discard
//! the partially advanced proof and challenger rather than retrying densely.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use blake3::Hasher;
use cmfd_proof_accel::blake3_merkle_store::{
    Blake3MerkleStoreError, Blake3MerkleStoreIdentity, blake3_merkle_store_geometry,
    build_authenticated_blake3_merkle_store_with_first_digest_layer,
};
use cmfd_proof_accel::merkle_store::MerkleRowSource;
use cmfd_proof_accel::whir_extension::{
    WHIR_EXTENSION_FOLDING, WHIR_EXTENSION_LIMBS_PER_ROW, WhirExtensionCodewordIdentity,
    WhirExtensionEncodingError, encode_whir_extension_codeword, whir_extension_geometry,
};
use cmfd_proof_accel::whir_residual::{
    AuthenticatedWhirResidualArtifact, WHIR_RESIDUAL_LIMBS_PER_ROW, WHIR_RESIDUAL_MAX_IO_ROWS,
    WHIR_RESIDUAL_MAX_VARIABLES, WhirResidualArtifactError, WhirResidualArtifactIdentity,
    WhirResidualArtifactSpec, WhirResidualArtifactWriter,
};
use p3_commit::{BatchOpening, ExtensionMmcs, Mmcs};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use p3_matrix::extension::FlatMatrixView;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::SumcheckData;
use p3_sumcheck::constraints::Constraint;
use p3_sumcheck::lagrange::extrapolate_01inf;
use p3_sumcheck::product_polynomial::ProductPolynomial;
use p3_sumcheck::strategy::{SumcheckProver, VariableOrder};
use p3_whir::pcs::prover::FallibleWhirProverState;
use thiserror::Error;

use super::disk_mmcs::{DiskWhirMmcs, DiskWhirStorageError, WhirExtensionMatrix};
use super::disk_sumcheck::PreparedArtifactSumcheck;
use super::{Challenger, Dft, EF, F};

const FINAL_TAIL_MAX_VARIABLES: usize = 6;
const CHILD_CONTEXT_DOMAIN: &str = "Common Foundry WHIR residual child context v1";
const CHILD_SOURCE_DOMAIN: &str = "Common Foundry WHIR residual child source v1";
const CODEWORD_ID_DOMAIN: &str = "Common Foundry WHIR extension codeword ID v1";
const TREE_ID_DOMAIN: &str = "Common Foundry WHIR extension Merkle store ID v1";
const TREE_FILE_PREFIX: &str = "cmfd-whir-extension-tree";

#[derive(Debug, Error)]
pub(super) enum ArtifactWhirStateError {
    #[error("invalid artifact-backed WHIR state: {0}")]
    Invalid(&'static str),
    #[error(
        "WHIR extension and tree need {required} scratch bytes but only {available} are available"
    )]
    InsufficientPeakSpace { required: u64, available: u64 },
    #[error("WHIR residual storage failed: {0}")]
    Residual(#[from] WhirResidualArtifactError),
    #[error("WHIR extension storage failed: {0}")]
    Extension(#[from] WhirExtensionEncodingError),
    #[error("WHIR Merkle storage failed: {0}")]
    Merkle(#[from] Blake3MerkleStoreError),
    #[error("WHIR MMCS storage failed: {0}")]
    Mmcs(#[from] DiskWhirStorageError),
    #[error("WHIR scratch free-space query failed: {0}")]
    FreeSpace(#[source] std::io::Error),
}

#[derive(Clone, Debug)]
struct PendingCommitment {
    codeword: WhirExtensionCodewordIdentity,
    tree: Blake3MerkleStoreIdentity,
}

type ArtifactExtensionCommitment = (
    <DiskWhirMmcs as Mmcs<F>>::Commitment,
    <DiskWhirMmcs as Mmcs<F>>::ProverData<FlatMatrixView<F, EF, WhirExtensionMatrix>>,
);

/// The first real external-storage state consumed by WHIR after its initial
/// two suffix-variable sumcheck rounds.
pub(super) struct ArtifactWhirProverState {
    scratch_directory: PathBuf,
    attempt_digest: [u8; 32],
    mmcs: DiskWhirMmcs,
    residual: Option<AuthenticatedWhirResidualArtifact>,
    claimed_sum: EF,
    pending: Mutex<Option<PendingCommitment>>,
    failed: AtomicBool,
}

impl ArtifactWhirProverState {
    pub(super) fn new(
        scratch_directory: impl AsRef<Path>,
        attempt_digest: [u8; 32],
        mmcs: DiskWhirMmcs,
        prepared: PreparedArtifactSumcheck,
    ) -> Result<Self, ArtifactWhirStateError> {
        let scratch_directory = scratch_directory.as_ref();
        if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
            return Err(ArtifactWhirStateError::Invalid(
                "scratch directory must be absolute and already exist",
            ));
        }
        if attempt_digest == [0; 32] {
            return Err(ArtifactWhirStateError::Invalid(
                "proof attempt digest must be nonzero",
            ));
        }
        validate_residual(&prepared.artifact)?;
        Ok(Self {
            scratch_directory: scratch_directory.to_path_buf(),
            attempt_digest,
            mmcs,
            residual: Some(prepared.artifact),
            claimed_sum: prepared.claimed_sum,
            pending: Mutex::new(None),
            failed: AtomicBool::new(false),
        })
    }

    fn ensure_live(&self) -> Result<(), ArtifactWhirStateError> {
        if self.failed.load(Ordering::Acquire) {
            Err(ArtifactWhirStateError::Invalid(
                "proof attempt was discarded after a prior storage failure",
            ))
        } else {
            Ok(())
        }
    }

    fn poison<T>(
        &self,
        result: Result<T, ArtifactWhirStateError>,
    ) -> Result<T, ArtifactWhirStateError> {
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    fn residual(&self) -> Result<&AuthenticatedWhirResidualArtifact, ArtifactWhirStateError> {
        self.residual
            .as_ref()
            .ok_or(ArtifactWhirStateError::Invalid(
                "proof attempt no longer owns a residual artifact",
            ))
    }

    fn commit_extension_inner(
        &self,
        order: VariableOrder,
        folding: usize,
        inv_rate: usize,
    ) -> Result<ArtifactExtensionCommitment, ArtifactWhirStateError> {
        self.ensure_live()?;
        if order != VariableOrder::Suffix {
            return Err(ArtifactWhirStateError::Invalid(
                "artifact state supports natural suffix order only",
            ));
        }
        if folding != WHIR_EXTENSION_FOLDING {
            return Err(ArtifactWhirStateError::Invalid(
                "artifact extension commitment requires folding two",
            ));
        }
        if inv_rate == 0 || !inv_rate.is_power_of_two() {
            return Err(ArtifactWhirStateError::Invalid(
                "linear inverse rate must be a nonzero power of two",
            ));
        }
        let log_inv_rate = u8::try_from(inv_rate.ilog2()).map_err(|_| {
            ArtifactWhirStateError::Invalid("inverse-rate exponent does not fit u8")
        })?;

        // Keep this guard across construction so even an accidental concurrent
        // caller cannot publish a second commitment for the same residual.
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| ArtifactWhirStateError::Invalid("pending commitment lock is poisoned"))?;
        if pending.is_some() {
            return Err(ArtifactWhirStateError::Invalid(
                "a residual already has an unconsumed extension commitment",
            ));
        }

        let residual = self.residual()?;
        validate_residual(residual)?;
        let residual_identity = residual.identity().clone();
        let codeword_id = derive_artifact_id(
            CODEWORD_ID_DOMAIN,
            self.attempt_digest,
            &residual_identity,
            order,
            folding,
            log_inv_rate,
        );
        let store_id = derive_artifact_id(
            TREE_ID_DOMAIN,
            self.attempt_digest,
            &residual_identity,
            order,
            folding,
            log_inv_rate,
        );

        // Both lower builders preflight independently. This additional check
        // covers their simultaneous peak while the codeword remains live.
        let available = fs2::available_space(&self.scratch_directory)
            .map_err(ArtifactWhirStateError::FreeSpace)?;
        preflight_extension_tree(&residual_identity, log_inv_rate, available)?;

        let codeword = encode_whir_extension_codeword(
            &self.scratch_directory,
            codeword_id,
            &residual_identity,
            residual,
            log_inv_rate,
        )?;
        let codeword_identity = codeword.identity().clone();
        let tree_path = self.scratch_directory.join(format!(
            "{TREE_FILE_PREFIX}-{}.artifact",
            hex::encode(store_id)
        ));
        let sources: [&dyn MerkleRowSource; 1] = [&codeword];
        let tree = build_authenticated_blake3_merkle_store_with_first_digest_layer(
            &tree_path, store_id, &sources, &codeword,
        )?
        .remove_on_drop();
        let tree_identity = tree.identity()?;

        let (commitment, prover_data) = self.mmcs.adopt_extension(
            &codeword_identity,
            &tree_identity,
            Arc::new(codeword),
            Arc::new(tree),
        )?;
        *pending = Some(PendingCommitment {
            codeword: codeword_identity,
            tree: tree_identity,
        });
        Ok((commitment, prover_data))
    }

    fn eval_inner(&self, point: &Point<EF>) -> Result<EF, ArtifactWhirStateError> {
        self.ensure_live()?;
        let residual = self.residual()?;
        validate_residual(residual)?;
        let variables = residual_variables(residual.identity())?;
        if point.num_variables() != variables {
            return Err(ArtifactWhirStateError::Invalid(
                "multilinear evaluation point has the wrong arity",
            ));
        }

        let mut result = EF::ZERO;
        scan_residual(residual, |start, rows| {
            let (prefix_weight, suffix_weights) =
                chunk_equality_weights(point.as_slice(), start, rows.len())?;
            for (offset, row) in rows.iter().enumerate() {
                let eval = decode_extension(&row[..3]);
                result += eval * prefix_weight * suffix_weights[offset];
            }
            Ok(())
        })?;
        Ok(result)
    }

    fn open_extension_inner(
        &self,
        index: usize,
        prover_data: &<DiskWhirMmcs as Mmcs<F>>::ProverData<
            FlatMatrixView<F, EF, WhirExtensionMatrix>,
        >,
    ) -> Result<BatchOpening<EF, ExtensionMmcs<F, EF, DiskWhirMmcs>>, ArtifactWhirStateError> {
        self.ensure_live()?;
        let opening = self.mmcs.try_open_batch(index, prover_data)?;
        let opened_values = opening
            .opened_values
            .into_iter()
            .map(|row| {
                if !row
                    .len()
                    .is_multiple_of(<EF as BasedVectorSpace<F>>::DIMENSION)
                {
                    return Err(ArtifactWhirStateError::Invalid(
                        "flattened extension opening has a partial field element",
                    ));
                }
                Ok(EF::reconstitute_from_base(row))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BatchOpening::new(opened_values, opening.opening_proof))
    }

    fn compute_inner(
        &mut self,
        sumcheck_data: &mut SumcheckData<F, EF>,
        challenger: &mut Challenger,
        folding_factor: usize,
        pow_bits: usize,
        constraint: Option<Constraint<F, EF>>,
    ) -> Result<Point<EF>, ArtifactWhirStateError> {
        self.ensure_live()?;
        match constraint {
            Some(constraint) => self.compute_constrained_round(
                sumcheck_data,
                challenger,
                folding_factor,
                pow_bits,
                constraint,
            ),
            None => self.compute_final_tail(sumcheck_data, challenger, folding_factor, pow_bits),
        }
    }

    fn compute_constrained_round(
        &mut self,
        sumcheck_data: &mut SumcheckData<F, EF>,
        challenger: &mut Challenger,
        folding_factor: usize,
        pow_bits: usize,
        constraint: Constraint<F, EF>,
    ) -> Result<Point<EF>, ArtifactWhirStateError> {
        if folding_factor != 2 {
            return Err(ArtifactWhirStateError::Invalid(
                "artifact intermediate sumcheck requires folding two",
            ));
        }
        let residual = self.residual()?;
        validate_residual(residual)?;
        let variables = residual_variables(residual.identity())?;
        if variables < folding_factor || constraint.num_variables() != variables {
            return Err(ArtifactWhirStateError::Invalid(
                "constraint arity does not match the residual",
            ));
        }
        let pending = self
            .pending
            .lock()
            .map_err(|_| ArtifactWhirStateError::Invalid("pending commitment lock is poisoned"))?
            .clone()
            .ok_or(ArtifactWhirStateError::Invalid(
                "intermediate sumcheck has no pending extension commitment",
            ))?;

        let pre_claim = self.claimed_sum;
        let mut post_constraint_claim = pre_claim;
        constraint.combine_evals(&mut post_constraint_claim);

        // Scan 1: authenticate the old invariant, add the exact constraint
        // weight at every Boolean row, and emit the first quadratic message.
        let mut old_dot = EF::ZERO;
        let mut new_dot = EF::ZERO;
        let mut c0 = EF::ZERO;
        let mut c_inf = EF::ZERO;
        scan_residual(residual, |start, rows| {
            if !start.is_multiple_of(2) || !rows.len().is_multiple_of(2) {
                return Err(ArtifactWhirStateError::Invalid(
                    "residual scan does not preserve suffix pairs",
                ));
            }
            let constraint_weights = constraint_weights_for_chunk(&constraint, start, rows.len())?;
            for (pair_offset, pair) in rows.chunks_exact(2).enumerate() {
                let local_index = pair_offset * 2;
                let (e0, w0_stored) = decode_residual_row(pair[0]);
                let (e1, w1_stored) = decode_residual_row(pair[1]);
                let w0 = w0_stored + constraint_weights[local_index];
                let w1 = w1_stored + constraint_weights[local_index + 1];
                old_dot += e0 * w0_stored + e1 * w1_stored;
                new_dot += e0 * w0 + e1 * w1;
                c0 += e0 * w0;
                c_inf += (e1 - e0) * (w1 - w0);
            }
            Ok(())
        })?;
        if old_dot != pre_claim || new_dot != post_constraint_claim {
            return Err(ArtifactWhirStateError::Invalid(
                "residual dot product disagrees with the transcript claim",
            ));
        }

        let r0 = sumcheck_data.observe_and_sample(challenger, c0, c_inf, pow_bits);
        let claim_after_r0 = extrapolate_01inf(c0, post_constraint_claim - c0, c_inf, r0);

        // Scan 2: fold each suffix pair once, check that intermediate dot
        // product unconditionally, and emit the second quadratic message.
        let residual = self.residual()?;
        let mut intermediate_dot = EF::ZERO;
        let mut c0_second = EF::ZERO;
        let mut c_inf_second = EF::ZERO;
        scan_residual(residual, |start, rows| {
            if !start.is_multiple_of(4) || !rows.len().is_multiple_of(4) {
                return Err(ArtifactWhirStateError::Invalid(
                    "residual scan does not preserve suffix groups of four",
                ));
            }
            let constraint_weights = constraint_weights_for_chunk(&constraint, start, rows.len())?;
            for (group_offset, group) in rows.chunks_exact(4).enumerate() {
                let local_index = group_offset * 4;
                let mut evals = [EF::ZERO; 4];
                let mut weights = [EF::ZERO; 4];
                for slot in 0..4 {
                    let (eval, stored_weight) = decode_residual_row(group[slot]);
                    evals[slot] = eval;
                    weights[slot] = stored_weight + constraint_weights[local_index + slot];
                }
                let e0 = fold_pair(evals[0], evals[1], r0);
                let e1 = fold_pair(evals[2], evals[3], r0);
                let w0 = fold_pair(weights[0], weights[1], r0);
                let w1 = fold_pair(weights[2], weights[3], r0);
                intermediate_dot += e0 * w0 + e1 * w1;
                c0_second += e0 * w0;
                c_inf_second += (e1 - e0) * (w1 - w0);
            }
            Ok(())
        })?;
        if intermediate_dot != claim_after_r0 {
            return Err(ArtifactWhirStateError::Invalid(
                "first folded residual disagrees with its claimed sum",
            ));
        }

        let r1 = sumcheck_data.observe_and_sample(challenger, c0_second, c_inf_second, pow_bits);
        let child_claim =
            extrapolate_01inf(c0_second, claim_after_r0 - c0_second, c_inf_second, r1);

        let parent_identity = self.residual()?.identity().clone();
        let child_context = child_context_digest(ChildContext {
            attempt_digest: self.attempt_digest,
            parent: &parent_identity,
            pending: &pending,
            constraint: &constraint,
            folding_factor,
            pow_bits,
            pre_claim,
            post_constraint_claim,
            sumcheck_data,
            r0,
            r1,
            child_claim,
        });
        let child_source = child_source_digest(self.attempt_digest, &parent_identity, &pending);
        let child_spec = WhirResidualArtifactSpec {
            source_digest: child_source,
            context_digest: child_context,
            num_variables: u32::try_from(variables - folding_factor).map_err(|_| {
                ArtifactWhirStateError::Invalid("child variable count does not fit u32")
            })?,
            generation: parent_identity.spec.generation.checked_add(1).ok_or(
                ArtifactWhirStateError::Invalid("residual generation overflowed"),
            )?,
        };
        let mut writer = WhirResidualArtifactWriter::create(&self.scratch_directory, child_spec)?;

        // Scan 3: fold each group by r0 then r1 and write the authenticated
        // child. The child is installed only after sealing and full reopen.
        let residual = self.residual()?;
        let mut child_dot = EF::ZERO;
        let mut emitted_child_rows = 0_u64;
        let child_buffer_capacity = child_row_buffer_capacity(writer.geometry().row_count);
        let mut child_rows = Vec::new();
        child_rows
            .try_reserve_exact(child_buffer_capacity)
            .map_err(|_| ArtifactWhirStateError::Invalid("child row buffer allocation failed"))?;
        scan_residual(residual, |start, rows| {
            if !start.is_multiple_of(4) || !rows.len().is_multiple_of(4) {
                return Err(ArtifactWhirStateError::Invalid(
                    "residual scan does not preserve suffix groups of four",
                ));
            }
            let constraint_weights = constraint_weights_for_chunk(&constraint, start, rows.len())?;
            for (group_offset, group) in rows.chunks_exact(4).enumerate() {
                let local_index = group_offset * 4;
                let mut evals = [EF::ZERO; 4];
                let mut weights = [EF::ZERO; 4];
                for slot in 0..4 {
                    let (eval, stored_weight) = decode_residual_row(group[slot]);
                    evals[slot] = eval;
                    weights[slot] = stored_weight + constraint_weights[local_index + slot];
                }
                let eval = fold_pair(
                    fold_pair(evals[0], evals[1], r0),
                    fold_pair(evals[2], evals[3], r0),
                    r1,
                );
                let weight = fold_pair(
                    fold_pair(weights[0], weights[1], r0),
                    fold_pair(weights[2], weights[3], r0),
                    r1,
                );
                child_dot += eval * weight;
                child_rows.push(encode_residual_row(eval, weight));
                emitted_child_rows =
                    emitted_child_rows
                        .checked_add(1)
                        .ok_or(ArtifactWhirStateError::Invalid(
                            "child residual row count overflowed",
                        ))?;
                if child_rows.len() == WHIR_RESIDUAL_MAX_IO_ROWS {
                    writer.write_rows(writer.rows_written(), &child_rows)?;
                    child_rows.clear();
                }
            }
            Ok(())
        })?;
        if !child_rows.is_empty() {
            writer.write_rows(writer.rows_written(), &child_rows)?;
            child_rows.clear();
        }
        if child_dot != child_claim
            || emitted_child_rows != writer.geometry().row_count
            || writer.rows_written() != writer.geometry().row_count
        {
            return Err(ArtifactWhirStateError::Invalid(
                "child residual disagrees with its claimed sum",
            ));
        }
        let child = writer.finish()?;
        validate_residual(&child)?;

        // Install the fully authenticated child first. Only then consume the
        // one pending commitment and explicitly remove its parent residual.
        let parent = self
            .residual
            .replace(child)
            .ok_or(ArtifactWhirStateError::Invalid(
                "parent residual disappeared before replacement",
            ))?;
        self.claimed_sum = child_claim;
        parent.remove()?;
        let consumed = self
            .pending
            .lock()
            .map_err(|_| ArtifactWhirStateError::Invalid("pending commitment lock is poisoned"))?
            .take();
        if consumed.as_ref().map(|item| (&item.codeword, &item.tree))
            != Some((&pending.codeword, &pending.tree))
        {
            return Err(ArtifactWhirStateError::Invalid(
                "pending commitment changed before child installation",
            ));
        }

        Ok(Point::new(vec![r0, r1]))
    }

    fn compute_final_tail(
        &mut self,
        sumcheck_data: &mut SumcheckData<F, EF>,
        challenger: &mut Challenger,
        folding_factor: usize,
        pow_bits: usize,
    ) -> Result<Point<EF>, ArtifactWhirStateError> {
        let variables = self.num_variables();
        if variables > FINAL_TAIL_MAX_VARIABLES || folding_factor > variables {
            return Err(ArtifactWhirStateError::Invalid(
                "unconstrained final tail exceeds six variables",
            ));
        }
        if self
            .pending
            .lock()
            .map_err(|_| ArtifactWhirStateError::Invalid("pending commitment lock is poisoned"))?
            .is_some()
        {
            return Err(ArtifactWhirStateError::Invalid(
                "unconstrained tail cannot consume a pending commitment",
            ));
        }
        let (evals, weights) = materialize_tail(self.residual()?)?;
        let product = ProductPolynomial::new_unpacked(
            VariableOrder::Suffix,
            Poly::new(evals),
            Poly::new(weights),
        );
        let mut prover = SumcheckProver::new(product, self.claimed_sum);
        let randomness = prover.compute_sumcheck_polynomials(
            sumcheck_data,
            challenger,
            folding_factor,
            pow_bits,
            None,
        );
        self.claimed_sum = prover.claimed_sum();
        Ok(randomness)
    }

    fn final_poly_inner(&self) -> Result<Poly<EF>, ArtifactWhirStateError> {
        self.ensure_live()?;
        if self.num_variables() > FINAL_TAIL_MAX_VARIABLES {
            return Err(ArtifactWhirStateError::Invalid(
                "final polynomial exceeds six variables",
            ));
        }
        let (evals, _) = materialize_tail(self.residual()?)?;
        Ok(Poly::new(evals))
    }
}

impl FallibleWhirProverState<EF, F, Dft, DiskWhirMmcs, Challenger> for ArtifactWhirProverState {
    type Error = ArtifactWhirStateError;
    type ExtensionMatrix = WhirExtensionMatrix;

    fn num_variables(&self) -> usize {
        self.residual
            .as_ref()
            .and_then(|residual| usize::try_from(residual.identity().spec.num_variables).ok())
            .unwrap_or(0)
    }

    fn try_commit_extension(
        &self,
        order: VariableOrder,
        _dft: &Dft,
        _extension_mmcs: &ExtensionMmcs<F, EF, DiskWhirMmcs>,
        folding: usize,
        inv_rate: usize,
    ) -> Result<
        (
            <DiskWhirMmcs as Mmcs<F>>::Commitment,
            <DiskWhirMmcs as Mmcs<F>>::ProverData<FlatMatrixView<F, EF, Self::ExtensionMatrix>>,
        ),
        Self::Error,
    > {
        self.poison(self.commit_extension_inner(order, folding, inv_rate))
    }

    fn try_eval(&self, point: &Point<EF>) -> Result<EF, Self::Error> {
        self.poison(self.eval_inner(point))
    }

    fn try_open_base<M: Matrix<F>>(
        &self,
        index: usize,
        mmcs: &DiskWhirMmcs,
        prover_data: &<DiskWhirMmcs as Mmcs<F>>::ProverData<M>,
    ) -> Result<BatchOpening<F, DiskWhirMmcs>, Self::Error> {
        let result = self
            .ensure_live()
            .and_then(|()| mmcs.try_open_batch(index, prover_data).map_err(Into::into));
        self.poison(result)
    }

    fn try_open_extension(
        &self,
        index: usize,
        _extension_mmcs: &ExtensionMmcs<F, EF, DiskWhirMmcs>,
        prover_data: &<DiskWhirMmcs as Mmcs<F>>::ProverData<
            FlatMatrixView<F, EF, Self::ExtensionMatrix>,
        >,
    ) -> Result<BatchOpening<EF, ExtensionMmcs<F, EF, DiskWhirMmcs>>, Self::Error> {
        self.poison(self.open_extension_inner(index, prover_data))
    }

    fn try_compute_sumcheck_polynomials(
        &mut self,
        sumcheck_data: &mut SumcheckData<F, EF>,
        challenger: &mut Challenger,
        folding_factor: usize,
        pow_bits: usize,
        constraint: Option<Constraint<F, EF>>,
    ) -> Result<Point<EF>, Self::Error> {
        let result = self.compute_inner(
            sumcheck_data,
            challenger,
            folding_factor,
            pow_bits,
            constraint,
        );
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    fn try_final_poly(&self) -> Result<Poly<EF>, Self::Error> {
        self.poison(self.final_poly_inner())
    }
}

fn validate_residual(
    residual: &AuthenticatedWhirResidualArtifact,
) -> Result<(), ArtifactWhirStateError> {
    let identity = residual.identity();
    let variables = residual_variables(identity)?;
    if variables > WHIR_RESIDUAL_MAX_VARIABLES {
        return Err(ArtifactWhirStateError::Invalid(
            "residual variable count exceeds the authenticated format",
        ));
    }
    let expected_rows =
        1_u64
            .checked_shl(identity.spec.num_variables)
            .ok_or(ArtifactWhirStateError::Invalid(
                "residual row geometry overflowed",
            ))?;
    if identity.row_count != expected_rows || residual.geometry().row_count != expected_rows {
        return Err(ArtifactWhirStateError::Invalid(
            "residual geometry is inconsistent with its authenticated identity",
        ));
    }
    Ok(())
}

fn residual_variables(
    identity: &WhirResidualArtifactIdentity,
) -> Result<usize, ArtifactWhirStateError> {
    usize::try_from(identity.spec.num_variables)
        .map_err(|_| ArtifactWhirStateError::Invalid("residual variable count does not fit usize"))
}

fn preflight_extension_tree(
    residual: &WhirResidualArtifactIdentity,
    log_inv_rate: u8,
    available: u64,
) -> Result<u64, ArtifactWhirStateError> {
    let extension_geometry = whir_extension_geometry(residual, log_inv_rate)?;
    let height = usize::try_from(extension_geometry.height)
        .map_err(|_| ArtifactWhirStateError::Invalid("extension height does not fit usize"))?;
    let tree_geometry = blake3_merkle_store_geometry(height, &[WHIR_EXTENSION_LIMBS_PER_ROW])?;
    let required = extension_geometry
        .artifact_bytes
        .checked_add(tree_geometry.artifact_bytes)
        .ok_or(ArtifactWhirStateError::Invalid(
            "combined extension/tree byte geometry overflowed",
        ))?;
    if available < required {
        return Err(ArtifactWhirStateError::InsufficientPeakSpace {
            required,
            available,
        });
    }
    Ok(required)
}

fn scan_residual(
    residual: &AuthenticatedWhirResidualArtifact,
    mut consume: impl FnMut(
        usize,
        &[[u64; WHIR_RESIDUAL_LIMBS_PER_ROW]],
    ) -> Result<(), ArtifactWhirStateError>,
) -> Result<(), ArtifactWhirStateError> {
    validate_residual(residual)?;
    let total = usize::try_from(residual.geometry().row_count)
        .map_err(|_| ArtifactWhirStateError::Invalid("residual row count does not fit usize"))?;
    let mut start = 0;
    while start < total {
        let count = (total - start).min(WHIR_RESIDUAL_MAX_IO_ROWS);
        let rows = residual.read_rows(start as u64, count)?;
        if rows.len() != count || residual.geometry().row_count != total as u64 {
            return Err(ArtifactWhirStateError::Invalid(
                "residual geometry changed during an authenticated scan",
            ));
        }
        consume(start, &rows)?;
        start += count;
    }
    Ok(())
}

fn materialize_tail(
    residual: &AuthenticatedWhirResidualArtifact,
) -> Result<(Vec<EF>, Vec<EF>), ArtifactWhirStateError> {
    let variables = residual_variables(residual.identity())?;
    if variables > FINAL_TAIL_MAX_VARIABLES {
        return Err(ArtifactWhirStateError::Invalid(
            "tail materialization exceeds 64 rows",
        ));
    }
    let row_count = 1_usize << variables;
    let rows = residual.read_rows(0, row_count)?;
    if rows.len() != row_count {
        return Err(ArtifactWhirStateError::Invalid(
            "tail row count changed while reading",
        ));
    }
    Ok(rows.into_iter().map(decode_residual_row).unzip())
}

fn decode_extension(limbs: &[u64]) -> EF {
    debug_assert_eq!(limbs.len(), <EF as BasedVectorSpace<F>>::DIMENSION);
    EF::from_basis_coefficients_fn(|index| F::new(limbs[index]))
}

fn decode_residual_row(row: [u64; WHIR_RESIDUAL_LIMBS_PER_ROW]) -> (EF, EF) {
    (decode_extension(&row[..3]), decode_extension(&row[3..]))
}

fn encode_residual_row(eval: EF, weight: EF) -> [u64; WHIR_RESIDUAL_LIMBS_PER_ROW] {
    let eval: &[F] = eval.as_basis_coefficients_slice();
    let weight: &[F] = weight.as_basis_coefficients_slice();
    [
        eval[0].as_canonical_u64(),
        eval[1].as_canonical_u64(),
        eval[2].as_canonical_u64(),
        weight[0].as_canonical_u64(),
        weight[1].as_canonical_u64(),
        weight[2].as_canonical_u64(),
    ]
}

fn fold_pair(lo: EF, hi: EF, challenge: EF) -> EF {
    lo + challenge * (hi - lo)
}

fn eq_at_index(point: &[EF], index: usize) -> EF {
    point
        .iter()
        .enumerate()
        .fold(EF::ONE, |weight, (coordinate, &value)| {
            let bit = point.len() - 1 - coordinate;
            if (index >> bit) & 1 == 0 {
                weight * (EF::ONE - value)
            } else {
                weight * value
            }
        })
}

fn bounded_eq_table(point: &[EF]) -> Result<Vec<EF>, ArtifactWhirStateError> {
    let table_len = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| {
            ArtifactWhirStateError::Invalid("equality-table arity does not fit u32")
        })?)
        .ok_or(ArtifactWhirStateError::Invalid(
            "equality-table geometry overflowed",
        ))?;
    if table_len > WHIR_RESIDUAL_MAX_IO_ROWS {
        return Err(ArtifactWhirStateError::Invalid(
            "equality-table chunk exceeds the bounded row count",
        ));
    }

    let mut table = Vec::new();
    table
        .try_reserve_exact(table_len)
        .map_err(|_| ArtifactWhirStateError::Invalid("equality-table allocation failed"))?;
    table.push(EF::ONE);
    for &coordinate in point {
        let old_len = table.len();
        table.resize(old_len * 2, EF::ZERO);
        for index in (0..old_len).rev() {
            let weight = table[index];
            table[2 * index] = weight * (EF::ONE - coordinate);
            table[2 * index + 1] = weight * coordinate;
        }
    }
    Ok(table)
}

fn chunk_equality_weights(
    point: &[EF],
    start: usize,
    count: usize,
) -> Result<(EF, Vec<EF>), ArtifactWhirStateError> {
    if count == 0
        || !count.is_power_of_two()
        || count > WHIR_RESIDUAL_MAX_IO_ROWS
        || !start.is_multiple_of(count)
    {
        return Err(ArtifactWhirStateError::Invalid(
            "residual chunk is not a bounded aligned power of two",
        ));
    }
    let suffix_variables = count.ilog2() as usize;
    if suffix_variables > point.len() {
        return Err(ArtifactWhirStateError::Invalid(
            "residual chunk exceeds the evaluation-point arity",
        ));
    }
    let total_rows = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| {
            ArtifactWhirStateError::Invalid("evaluation-point arity does not fit u32")
        })?)
        .ok_or(ArtifactWhirStateError::Invalid(
            "evaluation-point row geometry overflowed",
        ))?;
    if start.checked_add(count).is_none_or(|end| end > total_rows) {
        return Err(ArtifactWhirStateError::Invalid(
            "residual chunk exceeds the evaluation domain",
        ));
    }

    let prefix_variables = point.len() - suffix_variables;
    let prefix_index = start >> suffix_variables;
    let prefix_weight = eq_at_index(&point[..prefix_variables], prefix_index);
    let suffix_weights = bounded_eq_table(&point[prefix_variables..])?;
    if suffix_weights.len() != count {
        return Err(ArtifactWhirStateError::Invalid(
            "bounded equality table has the wrong row count",
        ));
    }
    Ok((prefix_weight, suffix_weights))
}

fn constraint_weights_for_chunk(
    constraint: &Constraint<F, EF>,
    start: usize,
    count: usize,
) -> Result<Vec<EF>, ArtifactWhirStateError> {
    let mut weights = Vec::new();
    weights
        .try_reserve_exact(count)
        .map_err(|_| ArtifactWhirStateError::Invalid("constraint-weight allocation failed"))?;
    weights.resize(count, EF::ZERO);

    for (point, coefficient) in constraint.iter_eqs() {
        let (prefix_weight, suffix_weights) =
            chunk_equality_weights(point.as_slice(), start, count)?;
        for (weight, suffix_weight) in weights.iter_mut().zip(suffix_weights) {
            *weight += coefficient * prefix_weight * suffix_weight;
        }
    }
    for (&variable, coefficient) in constraint.iter_sels() {
        let mut power = variable.exp_u64(start as u64);
        for weight in &mut weights {
            *weight += coefficient * power;
            power *= variable;
        }
    }
    Ok(weights)
}

fn child_row_buffer_capacity(row_count: u64) -> usize {
    usize::try_from(row_count)
        .unwrap_or(usize::MAX)
        .min(WHIR_RESIDUAL_MAX_IO_ROWS)
}

fn derive_artifact_id(
    domain: &str,
    attempt_digest: [u8; 32],
    residual: &WhirResidualArtifactIdentity,
    order: VariableOrder,
    folding: usize,
    log_inv_rate: u8,
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(domain);
    hasher.update(&attempt_digest);
    hash_residual_identity(&mut hasher, residual);
    hasher.update(&residual.spec.generation.to_le_bytes());
    hasher.update(&[match order {
        VariableOrder::Prefix => 0,
        VariableOrder::Suffix => 1,
    }]);
    hasher.update(&(folding as u32).to_le_bytes());
    hasher.update(&[log_inv_rate]);
    nonzero_digest(*hasher.finalize().as_bytes())
}

fn nonzero_digest(mut digest: [u8; 32]) -> [u8; 32] {
    if digest == [0; 32] {
        digest[31] = 1;
    }
    digest
}

fn hash_residual_identity(hasher: &mut Hasher, identity: &WhirResidualArtifactIdentity) {
    hasher.update(&identity.spec.source_digest);
    hasher.update(&identity.spec.context_digest);
    hasher.update(&identity.spec.num_variables.to_le_bytes());
    hasher.update(&identity.spec.generation.to_le_bytes());
    hasher.update(&identity.row_count.to_le_bytes());
    hasher.update(&identity.artifact_digest);
}

fn hash_codeword_identity(hasher: &mut Hasher, identity: &WhirExtensionCodewordIdentity) {
    hasher.update(&identity.codeword_id);
    hash_residual_identity(hasher, &identity.residual);
    hasher.update(&[identity.folding]);
    hasher.update(&[identity.log_inv_rate]);
    hasher.update(&identity.height.to_le_bytes());
    hasher.update(&identity.width.to_le_bytes());
    hasher.update(&identity.artifact_digest);
}

fn hash_tree_identity(hasher: &mut Hasher, identity: &Blake3MerkleStoreIdentity) {
    hasher.update(&identity.store_id);
    hasher.update(&(identity.height as u64).to_le_bytes());
    hasher.update(&(identity.ordered_matrix_widths.len() as u32).to_le_bytes());
    for &width in &identity.ordered_matrix_widths {
        hasher.update(&(width as u64).to_le_bytes());
    }
    hasher.update(&identity.tree_root);
    hasher.update(&identity.artifact_global_digest);
}

fn hash_extension(hasher: &mut Hasher, value: EF) {
    let limbs: &[F] = value.as_basis_coefficients_slice();
    for limb in limbs {
        hasher.update(&limb.as_canonical_u64().to_le_bytes());
    }
}

fn child_source_digest(
    attempt_digest: [u8; 32],
    parent: &WhirResidualArtifactIdentity,
    pending: &PendingCommitment,
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(CHILD_SOURCE_DOMAIN);
    hasher.update(&attempt_digest);
    hash_residual_identity(&mut hasher, parent);
    hash_codeword_identity(&mut hasher, &pending.codeword);
    hash_tree_identity(&mut hasher, &pending.tree);
    *hasher.finalize().as_bytes()
}

struct ChildContext<'a> {
    attempt_digest: [u8; 32],
    parent: &'a WhirResidualArtifactIdentity,
    pending: &'a PendingCommitment,
    constraint: &'a Constraint<F, EF>,
    folding_factor: usize,
    pow_bits: usize,
    pre_claim: EF,
    post_constraint_claim: EF,
    sumcheck_data: &'a SumcheckData<F, EF>,
    r0: EF,
    r1: EF,
    child_claim: EF,
}

fn child_context_digest(context: ChildContext<'_>) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(CHILD_CONTEXT_DOMAIN);
    hasher.update(&context.attempt_digest);
    hash_residual_identity(&mut hasher, context.parent);
    hash_codeword_identity(&mut hasher, &context.pending.codeword);
    hash_tree_identity(&mut hasher, &context.pending.tree);
    hasher.update(&[1]); // Natural suffix order.
    hasher.update(&(context.folding_factor as u64).to_le_bytes());
    hasher.update(&(context.pow_bits as u64).to_le_bytes());
    hash_extension(&mut hasher, context.pre_claim);
    hash_extension(&mut hasher, context.post_constraint_claim);
    hash_constraint(&mut hasher, context.constraint);
    hasher.update(&(context.sumcheck_data.polynomial_evaluations.len() as u32).to_le_bytes());
    for [c0, c_inf] in &context.sumcheck_data.polynomial_evaluations {
        hash_extension(&mut hasher, *c0);
        hash_extension(&mut hasher, *c_inf);
    }
    hasher.update(&(context.sumcheck_data.pow_witnesses.len() as u32).to_le_bytes());
    for witness in &context.sumcheck_data.pow_witnesses {
        hasher.update(&witness.as_canonical_u64().to_le_bytes());
    }
    hash_extension(&mut hasher, context.r0);
    hash_extension(&mut hasher, context.r1);
    hash_extension(&mut hasher, context.child_claim);
    *hasher.finalize().as_bytes()
}

fn hash_constraint(hasher: &mut Hasher, constraint: &Constraint<F, EF>) {
    hasher.update(&(constraint.num_variables() as u32).to_le_bytes());
    hash_extension(hasher, constraint.challenge);
    hasher.update(&(constraint.eq_statement.len() as u32).to_le_bytes());
    for (point, evaluation) in constraint
        .eq_statement
        .points
        .iter()
        .zip(&constraint.eq_statement.evaluations)
    {
        hasher.update(&(point.num_variables() as u32).to_le_bytes());
        for &coordinate in point.as_slice() {
            hash_extension(hasher, coordinate);
        }
        hash_extension(hasher, *evaluation);
    }
    hasher.update(&(constraint.sel_statement.len() as u32).to_le_bytes());
    for (&variable, &evaluation) in constraint.sel_statement.iter() {
        hasher.update(&variable.as_canonical_u64().to_le_bytes());
        hash_extension(hasher, evaluation);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicU64, Ordering};

    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_sumcheck::constraints::statement::{EqStatement, SelectStatement};

    use super::*;
    use crate::whir_proof::{DiskPcs, build_pcs};

    static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

    fn scratch_dir(label: &str) -> PathBuf {
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-artifact-whir-state-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        assert!(path.is_absolute());
        path
    }

    fn values(variables: usize, seed: u64) -> (Vec<EF>, Vec<EF>) {
        let count = 1_usize << variables;
        let evals = (0..count)
            .map(|index| {
                EF::new([
                    F::new(seed + index as u64 * 3 + 1),
                    F::new(seed + index as u64 * 5 + 2),
                    F::new(seed + index as u64 * 7 + 3),
                ])
            })
            .collect::<Vec<_>>();
        let weights = (0..count)
            .map(|index| {
                EF::new([
                    F::new(seed + index as u64 * 11 + 5),
                    F::new(seed + index as u64 * 13 + 7),
                    F::new(seed + index as u64 * 17 + 11),
                ])
            })
            .collect::<Vec<_>>();
        (evals, weights)
    }

    fn prepare(
        scratch: &Path,
        variables: usize,
        generation: u32,
        evals: &[EF],
        weights: &[EF],
    ) -> PreparedArtifactSumcheck {
        assert_eq!(evals.len(), 1 << variables);
        assert_eq!(weights.len(), evals.len());
        let spec = WhirResidualArtifactSpec {
            source_digest: [0x31; 32],
            context_digest: [0x52; 32],
            num_variables: variables as u32,
            generation,
        };
        let mut writer = WhirResidualArtifactWriter::create(scratch, spec).unwrap();
        let rows = evals
            .iter()
            .copied()
            .zip(weights.iter().copied())
            .map(|(eval, weight)| encode_residual_row(eval, weight))
            .collect::<Vec<_>>();
        for chunk in rows.chunks(WHIR_RESIDUAL_MAX_IO_ROWS) {
            writer.write_rows(writer.rows_written(), chunk).unwrap();
        }
        let artifact = writer.finish().unwrap();
        let claimed_sum = evals
            .iter()
            .zip(weights)
            .map(|(&eval, &weight)| eval * weight)
            .sum();
        PreparedArtifactSumcheck {
            artifact,
            claimed_sum,
            randomness: Point::new(vec![EF::new([F::new(2), F::ONE, F::ZERO]); 2]),
        }
    }

    fn disk_pcs(num_variables: usize, binding: &[u8]) -> (DiskPcs, Challenger, DiskWhirMmcs) {
        let (ordinary, challenger) = build_pcs(num_variables, binding).unwrap();
        let mmcs = DiskWhirMmcs::new(ordinary.mmcs);
        let pcs = DiskPcs::new(ordinary.config, ordinary.dft, mmcs.clone());
        (pcs, challenger, mmcs)
    }

    fn dense_prover(evals: Vec<EF>, weights: Vec<EF>) -> SumcheckProver<F, EF> {
        let claimed_sum = evals
            .iter()
            .zip(&weights)
            .map(|(&eval, &weight)| eval * weight)
            .sum();
        SumcheckProver::new(
            ProductPolynomial::new_unpacked(
                VariableOrder::Suffix,
                Poly::new(evals),
                Poly::new(weights),
            ),
            claimed_sum,
        )
    }

    #[test]
    fn streaming_eval_matches_dense_across_multiple_chunks_at_n16() {
        let variables = 14;
        let scratch = scratch_dir("eval");
        let (evals, weights) = values(variables, 19);
        let prepared = prepare(&scratch, variables, 0, &evals, &weights);
        let (_, _, mmcs) = disk_pcs(variables + 2, b"artifact-state-eval");
        let state = ArtifactWhirProverState::new(&scratch, [0x81; 32], mmcs, prepared).unwrap();
        let point = Point::new(
            (0..variables)
                .map(|index| {
                    EF::new([
                        F::new(index as u64 + 2),
                        F::new(index as u64 + 3),
                        F::new(index as u64 + 5),
                    ])
                })
                .collect(),
        );

        let expected = Poly::new(evals).eval_ext::<F>(&point);
        assert_eq!(state.try_eval(&point).unwrap(), expected);
        drop(state);
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        std::fs::remove_dir(scratch).unwrap();
    }

    #[test]
    fn final_tail_matches_dense_transcript_and_state() {
        let variables = 5;
        let scratch = scratch_dir("final-tail");
        let (evals, weights) = values(variables, 23);
        let prepared = prepare(&scratch, variables, 2, &evals, &weights);
        let (_, mut artifact_challenger, mmcs) =
            disk_pcs(variables + 2, b"artifact-state-final-tail");
        let mut dense_challenger = artifact_challenger.clone();
        let mut state = ArtifactWhirProverState::new(&scratch, [0x82; 32], mmcs, prepared).unwrap();
        let mut dense = dense_prover(evals.clone(), weights);

        assert_eq!(state.try_final_poly().unwrap(), Poly::new(evals));
        let mut artifact_data = SumcheckData::default();
        let artifact_randomness = state
            .try_compute_sumcheck_polynomials(
                &mut artifact_data,
                &mut artifact_challenger,
                2,
                0,
                None,
            )
            .unwrap();
        let mut dense_data = SumcheckData::default();
        let dense_randomness =
            dense.compute_sumcheck_polynomials(&mut dense_data, &mut dense_challenger, 2, 0, None);
        assert_eq!(
            artifact_data.polynomial_evaluations,
            dense_data.polynomial_evaluations
        );
        assert_eq!(artifact_data.pow_witnesses, dense_data.pow_witnesses);
        assert_eq!(artifact_randomness, dense_randomness);
        assert_eq!(state.claimed_sum, dense.claimed_sum());
        assert_eq!(
            artifact_challenger.sample_algebra_element::<EF>(),
            dense_challenger.sample_algebra_element::<EF>()
        );

        drop(state);
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        std::fs::remove_dir(scratch).unwrap();
    }

    #[test]
    fn extension_commitment_and_opening_match_dense_at_nine_thirteen_and_sixteen_variables() {
        for original_variables in [9_usize, 13, 16] {
            let variables = original_variables - 2;
            let scratch = scratch_dir(&format!("commit-{original_variables}"));
            let (evals, weights) = values(variables, original_variables as u64 + 29);
            let prepared = prepare(&scratch, variables, 0, &evals, &weights);
            let (pcs, mut artifact_challenger, mmcs) = disk_pcs(
                original_variables,
                format!("artifact-state-commit-{original_variables}").as_bytes(),
            );
            let mut dense_challenger = artifact_challenger.clone();
            let state = ArtifactWhirProverState::new(
                &scratch,
                [original_variables as u8; 32],
                mmcs,
                prepared,
            )
            .unwrap();
            let dense = dense_prover(evals, weights);

            let (artifact_commitment, artifact_data) = state
                .try_commit_extension(VariableOrder::Suffix, &pcs.dft, &pcs.extension_mmcs, 2, 2)
                .unwrap();
            let (dense_commitment, dense_data) =
                <SumcheckProver<F, EF> as FallibleWhirProverState<
                    EF,
                    F,
                    Dft,
                    DiskWhirMmcs,
                    Challenger,
                >>::try_commit_extension(
                    &dense,
                    VariableOrder::Suffix,
                    &pcs.dft,
                    &pcs.extension_mmcs,
                    2,
                    2,
                )
                .unwrap();
            assert_eq!(artifact_commitment, dense_commitment);
            artifact_challenger.observe(artifact_commitment.clone());
            dense_challenger.observe(dense_commitment.clone());
            assert_eq!(
                artifact_challenger.sample_algebra_element::<EF>(),
                dense_challenger.sample_algebra_element::<EF>()
            );

            let index = (1_usize << (variables - 1)).saturating_sub(1);
            let artifact_opening = state
                .try_open_extension(index, &pcs.extension_mmcs, &artifact_data)
                .unwrap();
            let dense_opening = <SumcheckProver<F, EF> as FallibleWhirProverState<
                EF,
                F,
                Dft,
                DiskWhirMmcs,
                Challenger,
            >>::try_open_extension(
                &dense, index, &pcs.extension_mmcs, &dense_data
            )
            .unwrap();
            assert_eq!(artifact_opening.opened_values, dense_opening.opened_values);
            assert_eq!(artifact_opening.opening_proof, dense_opening.opening_proof);

            drop(dense_data);
            drop(artifact_data);
            drop(state);
            assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
            std::fs::remove_dir(scratch).unwrap();
        }
    }

    #[test]
    fn child_row_buffer_is_bounded_independently_of_artifact_height() {
        assert_eq!(child_row_buffer_capacity(1), 1);
        assert_eq!(
            child_row_buffer_capacity(WHIR_RESIDUAL_MAX_IO_ROWS as u64),
            WHIR_RESIDUAL_MAX_IO_ROWS
        );
        assert_eq!(
            child_row_buffer_capacity((WHIR_RESIDUAL_MAX_IO_ROWS as u64) * 4),
            WHIR_RESIDUAL_MAX_IO_ROWS
        );
        assert_eq!(
            child_row_buffer_capacity(1_u64 << (WHIR_RESIDUAL_MAX_VARIABLES - 2)),
            WHIR_RESIDUAL_MAX_IO_ROWS
        );
    }

    #[test]
    fn constrained_fold_matches_dense_with_eq_and_selector() {
        let original_variables = 16;
        let variables = original_variables - 2;
        let scratch = scratch_dir("constrained");
        let (evals, weights) = values(variables, 37);
        let prepared = prepare(&scratch, variables, 4, &evals, &weights);
        let (pcs, mut artifact_challenger, mmcs) =
            disk_pcs(original_variables, b"artifact-state-constrained");
        let mut dense_challenger = artifact_challenger.clone();
        let mut state = ArtifactWhirProverState::new(&scratch, [0x83; 32], mmcs, prepared).unwrap();
        let mut dense = dense_prover(evals.clone(), weights);
        let (_, artifact_data) = state
            .try_commit_extension(VariableOrder::Suffix, &pcs.dft, &pcs.extension_mmcs, 2, 2)
            .unwrap();

        let eval_poly = Poly::new(evals);
        let eq_point = Point::new(
            (0..variables)
                .map(|index| EF::new([F::new(index as u64 + 3), F::ONE, F::new(2)]))
                .collect(),
        );
        let mut eq = EqStatement::initialize(variables);
        eq.add_evaluated_constraint(eq_point.clone(), eval_poly.eval_ext::<F>(&eq_point));
        let selector_var = F::new(7);
        let selector_eval = eval_poly
            .iter()
            .rev()
            .fold(EF::ZERO, |acc, &value| acc * selector_var + value);
        let mut select = SelectStatement::initialize(variables);
        select.add_constraint(selector_var, selector_eval);
        let constraint = Constraint::new(EF::new([F::new(11), F::new(13), F::new(17)]), eq, select);

        let mut artifact_sumcheck = SumcheckData::default();
        let artifact_randomness = state
            .try_compute_sumcheck_polynomials(
                &mut artifact_sumcheck,
                &mut artifact_challenger,
                2,
                0,
                Some(constraint.clone()),
            )
            .unwrap();
        let mut dense_sumcheck = SumcheckData::default();
        let dense_randomness = dense.compute_sumcheck_polynomials(
            &mut dense_sumcheck,
            &mut dense_challenger,
            2,
            0,
            Some(constraint),
        );

        assert_eq!(
            artifact_sumcheck.polynomial_evaluations,
            dense_sumcheck.polynomial_evaluations
        );
        assert_eq!(artifact_randomness, dense_randomness);
        assert_eq!(state.claimed_sum, dense.claimed_sum());
        assert_eq!(
            artifact_challenger.sample_algebra_element::<EF>(),
            dense_challenger.sample_algebra_element::<EF>()
        );
        assert!(state.pending.lock().unwrap().is_none());
        let child = state.residual().unwrap();
        assert_eq!(child.identity().spec.generation, 5);
        let rows = child
            .read_rows(0, child.geometry().row_count as usize)
            .unwrap();
        let (child_evals, child_weights): (Vec<_>, Vec<_>) =
            rows.into_iter().map(decode_residual_row).unzip();
        assert_eq!(Poly::new(child_evals), dense.evals());
        assert_eq!(Poly::new(child_weights), dense.weights());

        drop(artifact_data);
        drop(state);
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        std::fs::remove_dir(scratch).unwrap();
    }

    #[test]
    fn corruption_and_identity_fail_closed_without_generated_fallback_artifacts() {
        let variables = 3;
        let scratch = scratch_dir("corruption");
        let (evals, weights) = values(variables, 43);
        let prepared = prepare(&scratch, variables, 0, &evals, &weights);
        let (_, _, mmcs) = disk_pcs(variables + 2, b"artifact-state-corruption");
        let state = ArtifactWhirProverState::new(&scratch, [0x84; 32], mmcs, prepared).unwrap();
        let artifact_path = std::fs::read_dir(&scratch)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut file = OpenOptions::new().write(true).open(&artifact_path).unwrap();
        file.seek(SeekFrom::Start(160)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        let point = Point::new(vec![EF::ONE; variables]);
        let result = catch_unwind(AssertUnwindSafe(|| state.try_eval(&point)));
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
        drop(state);
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        std::fs::remove_dir(scratch).unwrap();

        let scratch = scratch_dir("identity");
        let prepared = prepare(&scratch, variables, 0, &evals, &weights);
        let (_, _, mmcs) = disk_pcs(variables + 2, b"artifact-state-identity");
        assert!(ArtifactWhirProverState::new(&scratch, [0; 32], mmcs, prepared).is_err());
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        std::fs::remove_dir(scratch).unwrap();
    }

    #[test]
    fn capacity_and_invalid_order_fail_before_extension_artifacts_are_created() {
        let variables = 7;
        let scratch = scratch_dir("preflight");
        let (evals, weights) = values(variables, 47);
        let prepared = prepare(&scratch, variables, 0, &evals, &weights);
        let required = preflight_extension_tree(prepared.artifact.identity(), 1, u64::MAX).unwrap();
        assert!(matches!(
            preflight_extension_tree(prepared.artifact.identity(), 1, required - 1),
            Err(ArtifactWhirStateError::InsufficientPeakSpace { .. })
        ));
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);
        let (pcs, _, mmcs) = disk_pcs(variables + 2, b"artifact-state-invalid-order");
        let state = ArtifactWhirProverState::new(&scratch, [0x85; 32], mmcs, prepared).unwrap();
        assert!(
            state
                .try_commit_extension(VariableOrder::Prefix, &pcs.dft, &pcs.extension_mmcs, 2, 2,)
                .is_err()
        );
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);
        drop(state);
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        std::fs::remove_dir(scratch).unwrap();
    }
}
