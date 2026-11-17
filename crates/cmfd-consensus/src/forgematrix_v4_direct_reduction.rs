//! Shared opening reduction for the dedicated direct-proof testnet.
//! A successful reduction returns an obligation, never an accepted proof.
use crate::forgematrix_v4_basefold::{
    ForgeMatrixV4Challenger as C, ForgeMatrixV4Digest as D, ForgeMatrixV4Extension as E,
    ForgeMatrixV4Field as F, ForgeMatrixV4IopContext as G,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_basefold::{BATCH_GRINDING_BITS, BasefoldProof, BasefoldVerifier, FriConfig};
use slop_challenger::{CanObserve, FieldChallenger, GrindingChallenger, IopCtx};
use slop_multilinear::{MleEval, Point};

#[derive(Clone)]
pub struct Shape {
    pub row_log: usize,
    pub columns: [usize; 6],
}
impl Shape {
    fn validate(&self) -> Result<()> {
        ensure!((1..=23).contains(&self.row_log), "trusted row geometry");
        ensure!(
            self.columns
                .iter()
                .all(|n| n.is_power_of_two() && *n <= 256),
            "trusted column geometry"
        );
        Ok(())
    }
    pub fn production() -> Self {
        Self {
            row_log: 23,
            columns: [256, 16, 256, 16, 256, 16],
        }
    }
}
#[derive(Clone)]
pub struct Statement {
    pub shape: Shape,
    pub job: [u8; 32],
    pub roots: [D; 6],
    pub bank_points: [Vec<E>; 3],
    pub original_evaluations: [Vec<E>; 6],
}
impl Statement {
    fn validate(&self) -> Result<()> {
        self.shape.validate()?;
        ensure!(
            self.bank_points
                .iter()
                .all(|p| p.len() == self.shape.row_log),
            "bank point geometry"
        );
        ensure!(
            self.original_evaluations
                .iter()
                .zip(self.shape.columns)
                .all(|(v, n)| v.len() == n),
            "original column evaluation geometry"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ReductionProof {
    pub batch_witness: <C as GrindingChallenger>::Witness,
    pub rounds: Vec<[E; 3]>,
    pub evaluations_at_shared_point: [Vec<E>; 6],
}
fn observe_ext(c: &mut C, value: E) {
    let fields: &[F] = value.as_base_slice();
    for x in fields {
        c.observe(*x)
    }
}
fn tag(c: &mut C, bytes: &[u8]) {
    c.observe(F::from_canonical_usize(bytes.len()));
    for byte in bytes {
        c.observe(F::from_canonical_u8(*byte));
    }
}
fn initial(s: &Statement) -> Result<C> {
    s.validate()?;
    let mut c = G::default_challenger();
    tag(&mut c, b"CommonFoundry/Research/DirectSixOpening/v1");
    c.observe(F::from_canonical_usize(s.shape.row_log));
    c.observe(F::from_canonical_usize(6));
    for n in s.shape.columns {
        c.observe(F::from_canonical_usize(n));
    }
    for b in s.job {
        c.observe(F::from_canonical_u8(b));
    }
    for root in s.roots {
        for word in root {
            c.observe(word);
        }
    }
    for point in &s.bank_points {
        for x in point {
            observe_ext(&mut c, *x)
        }
    }
    for values in &s.original_evaluations {
        for x in values {
            observe_ext(&mut c, *x)
        }
    }
    Ok(c)
}
pub fn equality_table(point: &[E]) -> Vec<E> {
    let mut values = vec![E::one()];
    for x in point {
        values = values
            .into_iter()
            .flat_map(|v| [v * (E::one() - *x), v * *x])
            .collect();
    }
    values
}
fn weights(c: &mut C, s: &Statement) -> Vec<E> {
    let n = s.shape.columns.iter().sum::<usize>().next_power_of_two();
    let point = (0..n.ilog2())
        .map(|_| c.sample_ext_element::<E>())
        .collect::<Vec<_>>();
    equality_table(&point)
}
fn claimed_sum(s: &Statement, coeff: &[E]) -> E {
    s.original_evaluations
        .iter()
        .flatten()
        .zip(coeff)
        .map(|(v, w)| *v * *w)
        .sum()
}
fn row_polynomial(coeff: [E; 3], at: E) -> E {
    coeff[0] + at * (coeff[1] + at * coeff[2])
}
fn observe_round(c: &mut C, coeff: [E; 3]) {
    for x in coeff {
        observe_ext(c, x)
    }
}
fn observe_shared_point(c: &mut C, point: &[E]) {
    tag(c, b"CommonFoundry/Research/DirectSixOpening/SharedPCS/v1");
    for x in point {
        observe_ext(c, *x);
    }
}
fn equal_at(left: &[E], right: &[E]) -> E {
    left.iter()
        .zip(right)
        .map(|(a, b)| *a * *b + (E::one() - *a) * (E::one() - *b))
        .product()
}
fn end_value(s: &Statement, coeff: &[E], point: &[E], values: &[Vec<E>; 6]) -> Result<E> {
    ensure!(
        values
            .iter()
            .zip(s.shape.columns)
            .all(|(v, n)| v.len() == n),
        "shared column evaluation geometry"
    );
    let mut at = 0;
    let mut sum = E::zero();
    for (i, column_values) in values.iter().enumerate() {
        let n = s.shape.columns[i];
        let value = column_values
            .iter()
            .zip(&coeff[at..at + n])
            .map(|(v, w)| *v * *w)
            .sum::<E>();
        at += n;
        sum += equal_at(&s.bank_points[i / 2], point) * value;
    }
    Ok(sum)
}

/// Values here remain untrusted until the ORIGINAL BaseFold verifier succeeds.
pub struct PcsObligation {
    shape: Shape,
    roots: [D; 6],
    point: Vec<E>,
    values: [Vec<E>; 6],
    challenger: C,
}
impl PcsObligation {
    pub fn point(&self) -> &[E] {
        &self.point
    }
    pub fn values(&self) -> &[Vec<E>; 6] {
        &self.values
    }
    pub fn challenger(&self) -> C {
        self.challenger.clone()
    }
    /// GPU builders use the trusted-evaluations proving interface, so bind
    /// every claimed value before that interface samples its batch challenge.
    /// The verifier independently uses `verify_untrusted_evaluations` instead.
    pub fn prover_challenger(&self) -> C {
        use slop_challenger::VariableLengthChallenger;
        let mut challenger = self.challenger.clone();
        for columns in &self.values {
            VariableLengthChallenger::<F, D>::observe_constant_length_extension_slice(
                &mut challenger,
                columns,
            );
        }
        challenger
    }
    pub fn verify_basefold(mut self, proof: &BasefoldProof<G>) -> Result<VerifiedOpening> {
        ensure!(
            proof.univariate_messages.len() == self.shape.row_log
                && proof.fri_commitments.len() == self.shape.row_log
                && proof.query_phase_openings_and_proofs.len() == self.shape.row_log
                && proof.component_polynomials_query_openings_and_proofs.len() == 6,
            "bounded BaseFold round/component counts"
        );
        let evaluations = self
            .values
            .into_iter()
            .map(MleEval::from)
            .collect::<Vec<_>>();
        BasefoldVerifier::<G>::new(FriConfig::new(1, 270, 16), 6)
            .verify_untrusted_evaluations(
                &self.roots,
                Point::from(self.point),
                &evaluations,
                proof,
                &mut self.challenger,
            )
            .map_err(|e| anyhow::anyhow!("six-commitment BaseFold rejected: {e:?}"))?;
        Ok(VerifiedOpening { _private: () })
    }
}
pub struct VerifiedOpening {
    _private: (),
}
pub type DirectBasefoldProof = BasefoldProof<G>;
pub fn decode_basefold(bytes: &[u8]) -> Result<DirectBasefoldProof> {
    Ok(bincode::deserialize(bytes)?)
}
/// Exact transcript state for the production GPU prover. These values are
/// prover inputs only; acceptance still requires both verifier stages below.
pub struct ProverStart {
    pub challenger: C,
    pub batch_witness: <C as GrindingChallenger>::Witness,
    pub column_weights: Vec<E>,
    pub claimed_sum: E,
}
pub fn begin_proving(s: &Statement) -> Result<ProverStart> {
    let mut challenger = initial(s)?;
    let batch_witness = challenger.grind(BATCH_GRINDING_BITS);
    let column_weights = weights(&mut challenger, s);
    let claimed_sum = claimed_sum(s, &column_weights);
    Ok(ProverStart {
        challenger,
        batch_witness,
        column_weights,
        claimed_sum,
    })
}
pub fn verify_reduction(s: &Statement, p: &ReductionProof) -> Result<PcsObligation> {
    let mut c = initial(s)?;
    ensure!(
        p.rounds.len() == s.shape.row_log,
        "exact secondary sumcheck round count"
    );
    ensure!(
        c.check_witness(BATCH_GRINDING_BITS, p.batch_witness),
        "secondary batching witness"
    );
    let coeff = weights(&mut c, s);
    let mut claim = claimed_sum(s, &coeff);
    let mut point = Vec::with_capacity(s.shape.row_log);
    for round in &p.rounds {
        ensure!(
            round[0] + round[0] + round[1] + round[2] == claim,
            "secondary sumcheck recurrence"
        );
        observe_round(&mut c, *round);
        let r = c.sample_ext_element::<E>();
        point.push(r);
        claim = row_polynomial(*round, r);
    }
    point.reverse();
    ensure!(
        end_value(s, &coeff, &point, &p.evaluations_at_shared_point)? == claim,
        "secondary terminal equation"
    );
    // The safe backend wrapper absorbs every evaluation before its batching
    // witness/challenge, matching the GPU's canonical explicit absorption.
    observe_shared_point(&mut c, &point);
    Ok(PcsObligation {
        shape: s.shape.clone(),
        roots: s.roots,
        point,
        values: p.evaluations_at_shared_point.clone(),
        challenger: c,
    })
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use slop_challenger::VariableLengthChallenger;
    use slop_multilinear::MultilinearPcsChallenger;

    fn observe_shared_claims(c: &mut C, point: &[E], values: &[Vec<E>; 6]) {
        observe_shared_point(c, point);
        for columns in values {
            VariableLengthChallenger::<F, D>::observe_constant_length_extension_slice(c, columns);
        }
    }

    #[test]
    fn safe_backend_absorption_matches_the_gpu_transcript() {
        let mut statement = statement();
        for (i, columns) in statement.original_evaluations.iter_mut().enumerate() {
            for (j, value) in columns.iter_mut().enumerate() {
                let limbs: [F; 4] =
                    std::array::from_fn(|k| F::from_canonical_usize(1 + i * 10000 + j * 4 + k));
                *value = E::from_base_slice(&limbs);
            }
        }
        let point = statement.bank_points[0].clone();
        let mut manual = G::default_challenger();
        observe_shared_point(&mut manual, &point);
        for columns in &statement.original_evaluations {
            for value in columns {
                observe_ext(&mut manual, *value);
            }
        }
        let mut safe = G::default_challenger();
        observe_shared_claims(&mut safe, &point, &statement.original_evaluations);
        for _ in 0..16 {
            assert_eq!(
                manual.sample_ext_element::<E>(),
                safe.sample_ext_element::<E>()
            );
        }
    }

    fn statement() -> Statement {
        let shape = Shape::production();
        Statement {
            original_evaluations: std::array::from_fn(|i| vec![E::zero(); shape.columns[i]]),
            shape,
            job: [7; 32],
            roots: std::array::from_fn(|i| {
                std::array::from_fn(|j| F::from_canonical_usize(i * 8 + j + 1))
            }),
            bank_points: std::array::from_fn(|i| {
                vec![E::from_base(F::from_canonical_usize(i + 2)); 23]
            }),
        }
    }

    #[test]
    fn every_original_and_shared_evaluation_changes_the_later_challenger() {
        let statement = statement();
        let mut original = initial(&statement).unwrap();
        let original_challenge = original.sample_ext_element::<E>();
        let point = vec![E::from_base(F::from_canonical_u32(13)); 23];
        let mut shared = G::default_challenger();
        observe_shared_claims(&mut shared, &point, &statement.original_evaluations);
        let shared_challenge = shared.sample_ext_element::<E>();
        for component in 0..6 {
            for column in 0..statement.shape.columns[component] {
                for limb in 0..4 {
                    let mut coefficients = [F::zero(); 4];
                    coefficients[limb] = F::one();
                    let delta = E::from_base_slice(&coefficients);
                    let mut changed = statement.clone();
                    changed.original_evaluations[component][column] += delta;
                    let mut challenger = initial(&changed).unwrap();
                    assert_ne!(
                        challenger.sample_ext_element::<E>(),
                        original_challenge,
                        "original evaluation {component}/{column}/{limb} was not bound"
                    );
                    let mut challenger = G::default_challenger();
                    observe_shared_claims(&mut challenger, &point, &changed.original_evaluations);
                    assert_ne!(
                        challenger.sample_ext_element::<E>(),
                        shared_challenge,
                        "shared evaluation {component}/{column}/{limb} was not bound"
                    );
                }
            }
        }
    }

    /// Reads an already public, honestly mined block. A rejected variant can be
    /// written only to an explicit private test path for node admission checks.
    /// Reproduces the missing-binding failure at the trusted backend boundary,
    /// then requires the actual compact verifier to reject the same changes.
    #[test]
    #[ignore = "requires CMFD_DIRECT_BLOCK_FIXTURE and CMFD_DIRECT_BASE_INPUT"]
    fn coordinated_evaluation_changes_are_rejected_by_the_complete_bound_verifier() {
        use crate::forgematrix_v4_basefold::ForgeMatrixV4TranscriptStatement;
        use crate::forgematrix_v4_direct as packet_codec;
        let wire =
            std::fs::read(std::env::var_os("CMFD_DIRECT_BLOCK_FIXTURE").expect("block fixture"))
                .unwrap();
        let base =
            std::fs::read(std::env::var_os("CMFD_DIRECT_BASE_INPUT").expect("base input")).unwrap();
        let block =
            crate::wire::decode_block(&wire, crate::FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID)
                .unwrap();
        let crate::BlockProof::V4Candidate(candidate) = &block.proof else {
            panic!("V4 fixture required")
        };
        let transcript = ForgeMatrixV4TranscriptStatement {
            block: block.challenge,
            algorithm_version: candidate.algorithm_version,
            proof_version: candidate.proof_version,
            nonce: candidate.nonce,
            proof_system_digest: candidate.proof_system_digest,
            model_manifest_digest: candidate.model_manifest_digest,
            challenge_digest: candidate.challenge_digest,
            final_activation_digest: candidate.final_activation_digest,
            work_digest: candidate.work_digest,
        };
        let record: crate::ForgeMatrixV4FixedArtifactRecordV1 = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"), "/../../packaging/production-v4-pool/shared/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"))).unwrap();
        record.validate().unwrap();
        let fixed = record.fixed_commitments();
        let packet = packet_codec::decode(&candidate.transparent_proof, transcript).unwrap();
        packet_codec::verify_direct(transcript, fixed, &base, &packet).unwrap();
        let statement = Statement {
            shape: Shape::production(),
            job: transcript.digest(),
            roots: std::array::from_fn(|i| {
                if i % 2 == 0 {
                    fixed[i / 2]
                } else {
                    packet.public.banks[i / 2].dynamic_commitment
                }
            }),
            bank_points: std::array::from_fn(|i| {
                packet.public.banks[i]
                    .opening
                    .sumcheck
                    .point_and_eval
                    .0
                    .iter()
                    .copied()
                    .collect()
            }),
            original_evaluations: std::array::from_fn(|i| {
                if i % 2 == 0 {
                    packet.public.banks[i / 2]
                        .opening
                        .fixed_column_evaluations
                        .clone()
                } else {
                    packet.public.banks[i / 2]
                        .opening
                        .dynamic_column_evaluations
                        .clone()
                }
            }),
        };
        let obligation = verify_reduction(&statement, &packet.reduction).unwrap();
        let mut c = initial(&statement).unwrap();
        assert!(c.check_witness(BATCH_GRINDING_BITS, packet.reduction.batch_witness));
        let column_weights = weights(&mut c, &statement);
        let mut bound_challenger = obligation.challenger.clone();
        for columns in &obligation.values {
            VariableLengthChallenger::<F, D>::observe_constant_length_extension_slice(
                &mut bound_challenger,
                columns,
            );
        }
        let mut batching = bound_challenger.clone();
        assert!(batching.check_witness(
            BATCH_GRINDING_BITS,
            packet.joint_basefold.batch_grinding_witness
        ));
        let batching_point = batching.sample_point::<E>(10);
        let pcs_weights = slop_multilinear::partial_lagrange_blocking(&batching_point);
        let mut checked = 0;
        let mut offset = 0;
        for component in 0..6 {
            let width = statement.shape.columns[component];
            for seed in 0..8 {
                let indices = [
                    seed % width,
                    (seed + width / 3 + 1) % width,
                    (seed + 2 * width / 3 + 2) % width,
                ];
                assert!(
                    indices[0] != indices[1]
                        && indices[0] != indices[2]
                        && indices[1] != indices[2]
                );
                let equality = equal_at(&statement.bank_points[component / 2], &obligation.point);
                let a = indices.map(|i| column_weights[offset + i] * equality);
                let b = indices.map(|i| pcs_weights.as_slice()[offset + i]);
                let delta = [
                    a[1] * b[2] - a[2] * b[1],
                    a[2] * b[0] - a[0] * b[2],
                    a[0] * b[1] - a[1] * b[0],
                ];
                assert!(delta.iter().any(|x| *x != E::zero()));
                let mut changed = packet.reduction.clone();
                for j in 0..3 {
                    changed.evaluations_at_shared_point[component][indices[j]] += delta[j];
                }
                // Both linear equations survive, so a terminal-only test is insufficient.
                let rebound = verify_reduction(&statement, &changed).unwrap();
                let changed_values = changed
                    .evaluations_at_shared_point
                    .iter()
                    .cloned()
                    .map(MleEval::from)
                    .collect::<Vec<_>>();
                BasefoldVerifier::<G>::new(FriConfig::new(1, 270, 16), 6)
                    .verify_mle_evaluations(
                        &obligation.roots,
                        Point::from(obligation.point.clone()),
                        &changed_values,
                        &packet.joint_basefold,
                        &mut bound_challenger.clone(),
                    )
                    .expect("counterfactual unbound backend reproduces the known failure");
                assert!(
                    rebound.verify_basefold(&packet.joint_basefold).is_err(),
                    "bound backend accepted coordinated changes"
                );
                let altered = packet_codec::encode(
                    &packet.public,
                    transcript,
                    &changed,
                    &packet.joint_basefold,
                )
                .unwrap();
                assert!(
                    packet_codec::verify_wire(transcript, fixed, &base, &altered).is_err(),
                    "complete verifier accepted coordinated changes"
                );
                if component == 0 && seed == 0 {
                    if let Some(path) = std::env::var_os("CMFD_REJECTED_BLOCK_FIXTURE") {
                        let mut rejected = block.clone();
                        let crate::BlockProof::V4Candidate(proof) = &mut rejected.proof else {
                            unreachable!("fixture is V4")
                        };
                        proof.transparent_proof = altered;
                        std::fs::write(path, crate::wire::encode_block(&rejected).unwrap())
                            .unwrap();
                    }
                }
                checked += 1;
            }
            offset += width;
        }
        assert_eq!(checked, 48);
        if let Some(path) = std::env::var_os("CMFD_SECURITY_REPORT") {
            std::fs::write(path, serde_json::to_vec_pretty(&serde_json::json!({
                "baseline_complete_proof_valid": true, "coordinated_cases": checked,
                "counterfactual_unbound_backend_accepts": checked, "bound_complete_verifier_rejects": checked,
                "forged_artifacts_written": false, "gpu_used": false,
            })).unwrap()).unwrap();
        }
    }
}
