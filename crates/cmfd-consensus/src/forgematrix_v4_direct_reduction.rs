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
    for i in 0..6 {
        let n = s.shape.columns[i];
        let value = values[i]
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
            .verify_mle_evaluations(
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
    // The backend calls this a TRUSTED-evaluations interface: bind all new claims
    // before its own batching grind/challenge, rather than relying on the backend.
    tag(
        &mut c,
        b"CommonFoundry/Research/DirectSixOpening/SharedPCS/v1",
    );
    for x in &point {
        observe_ext(&mut c, *x)
    }
    for values in &p.evaluations_at_shared_point {
        for x in values {
            observe_ext(&mut c, *x)
        }
    }
    Ok(PcsObligation {
        shape: s.shape.clone(),
        roots: s.roots,
        point,
        values: p.evaluations_at_shared_point.clone(),
        challenger: c,
    })
}
