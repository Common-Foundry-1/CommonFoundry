// AriaPool: CPU prover for the CommonFoundry compact proof (`forgematrix_v4_direct` packet).
// Original CPU compact prover by Stefan and AriaPool. Common Foundry contributed the subsequent optimizations.
// It recomputes the trace with the integer kernel `aria_v4_cpu`, then proves the matrix / shift / cubic relations
// of the 3 banks, the public bank openings, the opening reduction and the joint basefold. The relations, the
// openings and the reduction are checked by the consensus verifier while they are built. Set
// ARIA_PROVER_SELF_CHECK=1 to also run the full `verify_wire` on every proof.
#[cfg(not(all(target_arch = "x86_64", target_feature = "avx512f")))]
compile_error!("aria-cmfd-cpu-prover needs AVX-512: build it with RUSTFLAGS=\"-C target-cpu=native\" on an AVX-512 CPU");
use cmfd_consensus::compact_mainnet_fork::COMPACT_MAINNET_NETWORK_ID;
use cmfd_consensus::forgematrix_v4_basefold::{ForgeMatrixV4OpeningClaim as Claim, ForgeMatrixV4OpeningCommitment as Side, ForgeMatrixV4OpeningReductionProof as Opening, forgematrix_v4_transcript, ForgeMatrixV4Challenger as Ch, ForgeMatrixV4Extension as E, ForgeMatrixV4Field as F, ForgeMatrixV4TranscriptStatement};
use cmfd_consensus::forgematrix_v4_execution::aria_v4_cpu::AriaPackedBank;
use cmfd_consensus::forgematrix_v4_proof::{forgematrix_v4_mask_evaluation, ForgeMatrixV4RelationRepetitionProof};
use cmfd_consensus::forgematrix_v4_relations::*;
use cmfd_consensus::*;
use rayon::prelude::*;
use slop_algebra::{interpolate_univariate_polynomial, AbstractExtensionField, AbstractField, PrimeField32};
use slop_challenger::{CanObserve, FieldChallenger};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_basefold::{BasefoldProof, BATCH_GRINDING_BITS};
use slop_challenger::{CanSampleBits, GrindingChallenger};
use slop_koala_bear::KoalaBearDegree4Duplex as GC;
use slop_merkle_tree::{MerkleTreeOpeningAndProof, MerkleTreeTcsProof};
use slop_multilinear::{partial_lagrange_blocking, MultilinearPcsChallenger};
use slop_tensor::Tensor;
use std::{fs, io::BufReader, sync::Arc, time::Instant};
const LAYERS: usize = 128; const BATCH: usize = 128; const WIDTH: usize = 4096;
const CELLS: usize = BATCH * WIDTH; const BANK_VALUES: usize = LAYERS * CELLS; const BANK_BYTES: usize = LAYERS * WIDTH * WIDTH;
const P: u64 = 0x7f00_0001;
const MATRIX_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/MatrixProof/v1";
const SHIFT_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/ShiftProof/v1";
const CUBIC_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/CubicProof/v1";

fn observe_bytes(c: &mut Ch, bytes: &[u8]) { c.observe(F::from_canonical_usize(bytes.len())); for b in bytes { c.observe(F::from_canonical_u8(*b)); } }
fn eq_small(point: &[E]) -> Vec<E> { Mle::<E>::partial_lagrange(&Point::from(point.to_vec())).guts().as_slice().to_vec() }
/// Equality table (first coordinate = most significant bit). Large tables are the product of two small ones, in parallel.
fn eq(point: &[E]) -> Vec<E> {
    if point.len() <= 12 { return eq_small(point); }
    let lo = 12;
    let (hi, low) = (eq_small(&point[..point.len() - lo]), eq_small(&point[point.len() - lo..]));
    let mut out = vec![E::zero(); 1 << point.len()];
    out.par_chunks_mut(1 << lo).zip(hi.par_iter()).for_each(|(chunk, h)| { for (o, l) in chunk.iter_mut().zip(&low) { *o = *h * *l; } });
    out
}
fn dot(a: &[E], b: &[E]) -> E { a.iter().zip(b).map(|(x, y)| *x * *y).sum() }
fn eq_at_boolean(point: &[E], index: usize) -> E {
    point.iter().enumerate().fold(E::one(), |acc, (i, v)| acc * if (index >> (point.len() - i - 1)) & 1 == 1 { *v } else { E::one() - *v })
}
/// Generic sumcheck: sum over the hypercube of term(columns), least significant variable first.
/// `degree` = degree of the round polynomial. Same messages as the GPU kernels (coefficients observed, point inserted at the front).
fn sumcheck(mut cols: Vec<Vec<E>>, c: &mut Ch, claim: E, degree: usize, term: impl Fn(&[E]) -> E + Sync) -> (PartialSumcheckProof<E>, Vec<E>) {
    let k = cols.len();
    let xs: Vec<E> = (0..=degree).map(|t| E::from_canonical_usize(t)).collect();
    let (mut polys, mut point, mut claim_now) = (Vec::new(), Vec::new(), claim);
    loop {
        let half = cols[0].len() / 2;
        let cols_ref = &cols;
        // evaluations at 0, 2, 3, ..., degree. The value at 1 comes from the claimed sum.
        let sums: Vec<E> = (0..half).into_par_iter().fold(|| vec![E::zero(); degree + 1], |mut acc, i| {
            let mut lo = [E::zero(); 32]; let mut d = [E::zero(); 32]; let mut v = [E::zero(); 32];
            for j in 0..k { lo[j] = cols_ref[j][2 * i]; d[j] = cols_ref[j][2 * i + 1] - lo[j]; v[j] = lo[j]; }
            acc[0] += term(&v[..k]);
            for j in 0..k { v[j] += d[j]; }
            for t in 2..=degree { for j in 0..k { v[j] += d[j]; } acc[t] += term(&v[..k]); }
            acc
        }).reduce(|| vec![E::zero(); degree + 1], |mut a, b| { for t in 0..=degree { a[t] += b[t]; } a });
        let mut ys = sums.clone(); ys[1] = claim_now - sums[0];
        let poly = interpolate_univariate_polynomial(&xs, &ys);
        c.observe_slice(&poly.coefficients.iter().flat_map(|v| v.as_base_slice()).copied().collect::<Vec<F>>());
        let alpha: E = c.sample_ext_element();
        point.insert(0, alpha);
        claim_now = poly.eval_at_point(alpha);
        for col in cols.iter_mut() { *col = col.par_chunks_exact(2).map(|p| p[0] + alpha * (p[1] - p[0])).collect(); }
        polys.push(poly);
        if cols[0].len() == 1 {
            let ends = cols.iter().map(|col| col[0]).collect();
            return (PartialSumcheckProof { univariate_polys: polys, claimed_sum: claim, point_and_eval: (point.into(), claim_now) }, ends);
        }
    }
}
// ---------------------------------------------------------------------------------------------------------------
// Packed AVX-512 arithmetic: 16 extension elements per operation. Columns are stored limb by limb.
use p3_koala_bear::PackedKoalaBearAVX512 as PF;
type PE = slop_algebra::extension::BinomialExtensionField<PF, 4>;
struct Soa { l: [Vec<F>; 4] }
/// Buffer pool: a released column is reused without a new allocation (and without page faults).
static POOL: std::sync::Mutex<Vec<Vec<F>>> = std::sync::Mutex::new(Vec::new());
fn falloc(n: usize) -> Vec<F> {
    let reused = {
        let mut pool = POOL.lock().unwrap();
        let best = pool.iter().enumerate()
            .filter(|(_, column)| column.capacity() >= n)
            .min_by_key(|(_, column)| column.capacity())
            .map(|(index, _)| index);
        best.map(|index| pool.swap_remove(index))
    };
    let mut column = reused.unwrap_or_else(|| Vec::with_capacity(n));
    column.resize(n, F::zero());
    column
}

#[cfg(test)]
mod buffer_tests {
    use super::*;

    #[test]
    fn aria_falloc_initializes_fresh_and_reused_columns() {
        assert_eq!(falloc(8), vec![F::zero(); 8]);

        let mut column = vec![F::one(); 8];
        column.truncate(4);
        POOL.lock().unwrap().push(column);

        let grown = falloc(8);
        assert_eq!(&grown[..4], &[F::one(); 4]);
        assert_eq!(&grown[4..], &[F::zero(); 4]);
    }
}
impl Drop for Soa { fn drop(&mut self) { let mut pool = POOL.lock().unwrap(); for l in self.l.iter_mut() { let v = std::mem::take(l); if v.capacity() >= 1 << 16 { pool.push(v); } } } }
impl Soa {
    fn len(&self) -> usize { self.l[0].len() }
    fn with_len(n: usize) -> Self { Soa { l: std::array::from_fn(|_| falloc(n)) } }
    fn get(&self, i: usize) -> E { E::from_base_slice(&[self.l[0][i], self.l[1][i], self.l[2][i], self.l[3][i]]) }
    fn set(&mut self, i: usize, e: E) { let b: &[F] = e.as_base_slice(); for k in 0..4 { self.l[k][i] = b[k]; } }
    fn from_aos(v: &[E]) -> Self { let mut s = Soa::with_len(v.len()); for k in 0..4 { s.l[k].par_iter_mut().zip(v.par_iter()).for_each(|(o, e)| { let b: &[F] = e.as_base_slice(); *o = b[k]; }); } s }
    fn to_aos(&self) -> Vec<E> { (0..self.len()).map(|i| self.get(i)).collect() }
}
#[inline(always)] fn pf(x: &[F]) -> PF { let a: [F; 16] = x[..16].try_into().unwrap(); unsafe { std::mem::transmute::<[F; 16], PF>(a) } }
#[inline(always)] fn pe(l: [PF; 4]) -> PE { <PE as AbstractExtensionField<PF>>::from_base_slice(&l) }
#[inline(always)] fn pe_at(c: &Soa, i: usize) -> PE { pe(std::array::from_fn(|k| pf(&c.l[k][i..]))) }
#[inline(always)] fn pe_splat(e: E) -> PE { let b: &[F] = e.as_base_slice(); pe(std::array::from_fn(|k| PF::from(b[k]))) }
#[inline(always)] fn pe_sum(x: PE) -> E { let b: &[PF] = x.as_base_slice(); let s: [F; 4] = std::array::from_fn(|k| { let lanes: [F; 16] = unsafe { std::mem::transmute::<PF, [F; 16]>(b[k]) }; lanes.iter().copied().sum() }); E::from_base_slice(&s) }
/// 32 consecutive elements -> (the 16 at even indices, the 16 at odd indices)
#[inline(always)] fn split(x: &[F]) -> (PF, PF) {
    assert!(x.len() >= 32);
    unsafe {
        use std::arch::x86_64::*;
        let (v0, v1) = (_mm512_loadu_si512(x.as_ptr().cast()), _mm512_loadu_si512(x.as_ptr().add(16).cast()));
        let even = _mm512_setr_epi32(0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30);
        let odd = _mm512_setr_epi32(1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31);
        (std::mem::transmute::<__m512i, PF>(_mm512_permutex2var_epi32(v0, even, v1)), std::mem::transmute::<__m512i, PF>(_mm512_permutex2var_epi32(v0, odd, v1)))
    }
}
/// The pairs (2i, 2i+1) of the column for i = j .. j+16: (values at 0, values at 1), packed.
#[inline(always)] fn pairs_at(c: &Soa, j: usize) -> (PE, PE) {
    let s: [(PF, PF); 4] = std::array::from_fn(|k| split(&c.l[k][2 * j..]));
    (pe([s[0].0, s[1].0, s[2].0, s[3].0]), pe([s[0].1, s[1].1, s[2].1, s[3].1]))
}
/// Multiply by a fixed quartic challenge in the even/odd basis over y = x².
/// The three quadratic products use Karatsuba, with challenge sums prepared once per round.
struct QuarticChallenge {
    even: QuadraticChallenge,
    odd: QuadraticChallenge,
    sum: QuadraticChallenge,
    nonresidue: PF,
}

struct QuadraticChallenge {
    constant: PF,
    linear: PF,
    sum: PF,
}

impl QuadraticChallenge {
    fn new(constant: PF, linear: PF) -> Self {
        Self { constant, linear, sum: constant + linear }
    }

    #[inline(always)]
    fn multiply(&self, a: PF, b: PF, nonresidue: PF) -> [PF; 2] {
        let low = a * self.constant;
        let high = b * self.linear;
        [low + nonresidue * high, (a + b) * self.sum - low - high]
    }
}

impl QuarticChallenge {
    fn new(alpha: E) -> Self {
        use slop_algebra::extension::BinomiallyExtendable;
        let a: &[F] = alpha.as_base_slice();
        let [a0, a1, a2, a3] = std::array::from_fn(|i| PF::from(a[i]));
        Self {
            even: QuadraticChallenge::new(a0, a2),
            odd: QuadraticChallenge::new(a1, a3),
            sum: QuadraticChallenge::new(a0 + a1, a2 + a3),
            nonresidue: PF::from(<F as BinomiallyExtendable<4>>::w()),
        }
    }

    #[inline(always)]
    fn multiply(&self, [d0, d1, d2, d3]: [PF; 4]) -> [PF; 4] {
        let [e0, e1] = self.even.multiply(d0, d2, self.nonresidue);
        let [o0, o1] = self.odd.multiply(d1, d3, self.nonresidue);
        let [s0, s1] = self.sum.multiply(d0 + d1, d2 + d3, self.nonresidue);
        [
            e0 + self.nonresidue * o1,
            s0 - e0 - o0,
            e1 + o0,
            s1 - e1 - o1,
        ]
    }
}

#[inline(always)]
fn fold_cubic_lanes(alpha: &QuarticChallenge, pairs: [(PF, PF); 4]) -> [PF; 4] {
    let delta = std::array::from_fn(|limb| pairs[limb].1 - pairs[limb].0);
    let scaled = alpha.multiply(delta);
    std::array::from_fn(|limb| pairs[limb].0 + scaled[limb])
}

fn fold_cubic_tile(alpha: &QuarticChallenge, input: [&[F]; 4], mut output: [&mut [F]; 4]) {
    for start in (0..output[0].len()).step_by(16) {
        let pairs = std::array::from_fn(|limb| split(&input[limb][2 * start..]));
        let folded = fold_cubic_lanes(alpha, pairs);
        for (limb, value) in output.iter_mut().zip(folded) {
            st(&mut limb[start..], value);
        }
    }
}

/// Fold into the first half of the column, processing completed prefixes first.
/// After the initial pack, a wave reads [2*start, 4*start) and writes [start, 2*start).
fn soa_fold(column: &mut Soa, scalar: E) {
    const PACK: usize = 16;
    const TILE: usize = 4096;
    let len = column.len() / 2;
    if len < PACK {
        for i in 0..len {
            let low = column.get(2 * i);
            let high = column.get(2 * i + 1);
            column.set(i, low + scalar * (high - low));
        }
    } else {
        let alpha = QuarticChallenge::new(scalar);
        let pairs = std::array::from_fn(|limb| split(&column.l[limb]));
        for (limb, value) in column.l.iter_mut().zip(fold_cubic_lanes(&alpha, pairs)) {
            st(limb, value);
        }

        let mut start = PACK;
        while start < len {
            let [l0, l1, l2, l3] = &mut column.l;
            let (d0, s0) = l0.split_at_mut(2 * start);
            let (d1, s1) = l1.split_at_mut(2 * start);
            let (d2, s2) = l2.split_at_mut(2 * start);
            let (d3, s3) = l3.split_at_mut(2 * start);
            let source = [&s0[..2 * start], &s1[..2 * start], &s2[..2 * start], &s3[..2 * start]];
            let output = [&mut d0[start..], &mut d1[start..], &mut d2[start..], &mut d3[start..]];
            if start <= TILE {
                fold_cubic_tile(&alpha, source, output);
            } else {
                let [o0, o1, o2, o3] = output;
                (
                    o0.par_chunks_mut(TILE),
                    o1.par_chunks_mut(TILE),
                    o2.par_chunks_mut(TILE),
                    o3.par_chunks_mut(TILE),
                ).into_par_iter().enumerate().for_each(|(tile, (o0, o1, o2, o3))| {
                    let offset = 2 * tile * TILE;
                    fold_cubic_tile(&alpha, source.map(|limb| &limb[offset..]), [o0, o1, o2, o3]);
                });
            }
            start *= 2;
        }
    }
    for limb in &mut column.l {
        limb.truncate(len);
    }
}

// Split each canonical field weight into two signed i16 values. This
// preserves the value exactly, including low limbs that are negative.
fn split_fixed_weight(weight: u64) -> (i16, i16) {
    let low = weight as i16;
    let high = ((weight >> 16) + u64::from(low < 0)) as i16;
    (low, high)
}

#[cfg(all(target_feature = "avx512vnni", target_feature = "avx512bw"))]
fn fixed_row_linear_combination(
    bytes: &[u8], stride: usize, start: usize, weights: &[Vec<u64>; 4], out: &mut [[u64; 4096]],
) {
    use std::arch::x86_64::*;
    assert_eq!(out.len(), 4);
    assert!(start.checked_add(4096).is_some_and(|end| end <= stride));
    assert!(stride.checked_mul(256).is_some_and(|len| len <= bytes.len()));
    // 256 terms with a byte and signed 16-bit factor fit in an i32.
    const PACK: usize = 16;
    const COLUMNS: usize = 256;
    let coefficient_pairs: [[(i32, i32); COLUMNS / 2]; 4] = std::array::from_fn(|limb| {
        std::array::from_fn(|pair| {
            let a = split_fixed_weight(weights[limb][2 * pair]);
            let b = split_fixed_weight(weights[limb][2 * pair + 1]);
            let join = |x: i16, y: i16| i32::from(x as u16) | (i32::from(y) << 16);
            (join(a.0, b.0), join(a.1, b.1))
        })
    });
    for row in (0..4096).step_by(PACK) {
        // SAFETY: callers pass a full 4096-row tile from each column. Each
        // packed load consumes exactly 16 bytes and all integer lanes fit.
        unsafe {
            let mut low = [_mm512_setzero_si512(); 4];
            let mut high = [_mm512_setzero_si512(); 4];
            for pair in 0..COLUMNS / 2 {
                let column = 2 * pair * stride + start + row;
                let a = _mm512_cvtepu8_epi32(_mm_loadu_si128(bytes.as_ptr().add(column).cast()));
                let b = _mm512_cvtepu8_epi32(_mm_loadu_si128(bytes.as_ptr().add(column + stride).cast()));
                let input = _mm512_or_si512(a, _mm512_slli_epi32::<16>(b));
                for limb in 0..4 {
                    let (w0, w1) = coefficient_pairs[limb][pair];
                    low[limb] = _mm512_dpwssd_epi32(low[limb], input, _mm512_set1_epi32(w0));
                    high[limb] = _mm512_dpwssd_epi32(high[limb], input, _mm512_set1_epi32(w1));
                }
            }
            for limb in 0..4 {
                let lows: [i32; PACK] = std::mem::transmute(low[limb]);
                let highs: [i32; PACK] = std::mem::transmute(high[limb]);
                for lane in 0..PACK {
                    out[limb][row + lane] = ((i64::from(highs[lane]) << 16) + i64::from(lows[lane])) as u64;
                }
            }
        }
    }
}

#[cfg(not(all(target_feature = "avx512vnni", target_feature = "avx512bw")))]
fn fixed_row_linear_combination(
    bytes: &[u8], stride: usize, start: usize, weights: &[Vec<u64>; 4], out: &mut [[u64; 4096]],
) {
    for c in 0..256 {
        let col = &bytes[c * stride + start..][..4096];
        for (coefficients, output) in weights.iter().zip(out.iter_mut()) {
            for (value, byte) in output.iter_mut().zip(col) {
                *value += u64::from(*byte) * coefficients[c];
            }
        }
    }
}

#[cfg(all(target_feature = "avx512vnni", target_feature = "avx512bw"))]
fn packed_fixed_weights(values: &[u64]) -> (Vec<i16>, Vec<i16>) {
    values.iter().copied().map(split_fixed_weight).unzip()
}

#[cfg(all(target_feature = "avx512vnni", target_feature = "avx512bw"))]
fn fixed_dot_packed(bytes: &[u8], low: &[i16], high: &[i16]) -> u64 {
    use std::arch::x86_64::*;
    assert_eq!(bytes.len(), low.len());
    assert_eq!(bytes.len(), high.len());
    assert_eq!(bytes.len() % 32, 0);
    let mut total = 0i64;
    for start in (0..bytes.len()).step_by(4096) {
        // 4096 values at 16 lanes give at most 256 products per lane.
        // Pointer offsets remain within the three equally-sized slices.
        unsafe {
            let mut a = _mm512_setzero_si512();
            let mut b = _mm512_setzero_si512();
            for index in (start..(start + 4096).min(bytes.len())).step_by(32) {
                let values = _mm512_cvtepu8_epi16(_mm256_loadu_si256(bytes.as_ptr().add(index).cast()));
                let w0 = _mm512_loadu_si512(low.as_ptr().add(index).cast());
                let w1 = _mm512_loadu_si512(high.as_ptr().add(index).cast());
                a = _mm512_dpwssd_epi32(a, values, w0);
                b = _mm512_dpwssd_epi32(b, values, w1);
            }
            let a: [i32; 16] = std::mem::transmute(a);
            let b: [i32; 16] = std::mem::transmute(b);
            total += a.into_iter().map(i64::from).sum::<i64>() +
                     (b.into_iter().map(i64::from).sum::<i64>() << 16);
        }
    }
    total as u64
}

#[cfg(test)]
#[test]
fn fixed_integer_contractions_match_the_reference() {
    let stride = 4096;
    let bytes: Vec<u8> = (0..256 * stride).map(|i| ((i * 31 + i / 113) % 251) as u8).collect();
    let weights: [Vec<u64>; 4] = std::array::from_fn(|limb|
        (0..256).map(|col| ((limb as u64 + 2) * (col as u64 + 3) * 0x73f1_ffff) % P).collect());
    let mut rows = vec![[0u64; 4096]; 4];
    fixed_row_linear_combination(&bytes, stride, 0, &weights, &mut rows);
    for (limb, output) in rows.iter().enumerate() {
        for (row, &sum) in output.iter().enumerate() {
            assert_eq!(sum, (0..256).map(|c| u64::from(bytes[c * stride + row]) * weights[limb][c]).sum::<u64>());
        }
    }
    #[cfg(all(target_feature = "avx512vnni", target_feature = "avx512bw"))]
    {
        let w: Vec<u64> = (0u64..8192).map(|i| (i * 0x40fa_fffe) % P).collect();
        let (lo, hi) = packed_fixed_weights(&w);
        let data = &bytes[..w.len()];
        assert_eq!(fixed_dot_packed(data, &lo, &hi),
            data.iter().zip(&w).map(|(&a, &b)| u64::from(a) * b).sum::<u64>());
    }
}

/// Combined line of a group, written limb by limb: weighted sum of the fixed columns (centered bytes) and of the dynamic columns.
fn group_line(bytes: &[u8], p: &[u32], q: &[u32], fw: Option<&[E]>, dw: Option<&[E]>) -> Soa {
    let (fl, dl) = (fw.map(limbs_of), dw.map(limbs_of));
    let center: E = fw.map_or(E::zero(), |w| w.iter().copied().sum::<E>() * F::from_canonical_u32(125));
    let cl: [F; 4] = { let b: &[F] = center.as_base_slice(); [b[0], b[1], b[2], b[3]] };
    let mut out = Soa::with_len(ROWS);
    let [o0, o1, o2, o3] = &mut out.l;
    (o0.par_chunks_mut(4096), o1.par_chunks_mut(4096), o2.par_chunks_mut(4096), o3.par_chunks_mut(4096)).into_par_iter().enumerate().for_each(|(chunk, (x0, x1, x2, x3))| {
        let r0 = chunk * 4096;
        let af = fl.as_ref().map(|weights| {
            let mut rows = vec![[0u64; 4096]; 4];
            fixed_row_linear_combination(bytes, ROWS, r0, weights, &mut rows);
            rows
        });
        let ad = dl.as_ref().map(|dl| {
            let mut ad = vec![[0u64; 4096]; 8];
            for c in 0..16 {
            let col = if c < 8 { &p[c * ROWS + r0..][..4096] } else { &q[(c - 8) * ROWS + r0..][..4096] };
            for l in 0..4 {
                let (wl, wh) = (dl[l][c] & 0xffff, dl[l][c] >> 16);
                { let a = &mut ad[2 * l]; for i in 0..4096 { a[i] += col[i] as u64 * wl; } }
                { let a = &mut ad[2 * l + 1]; for i in 0..4096 { a[i] += col[i] as u64 * wh; } }
            }
            }
            ad
        });
        for (limb, dst) in [x0, x1, x2, x3].into_iter().enumerate() {
            match (&af, &ad) {
                (Some(af), Some(ad)) => {
                    for (i, value) in dst.iter_mut().enumerate() {
                        // Both sums and the reduced high half fit together in u64.
                        let n = af[limb][i] + ad[2 * limb][i] + ((ad[2 * limb + 1][i] % P) << 16);
                        *value = F::from_canonical_u32((n % P) as u32) - cl[limb];
                    }
                }
                (Some(af), None) => {
                    for (value, &fixed) in dst.iter_mut().zip(&af[limb]) {
                        *value = F::from_canonical_u32((fixed % P) as u32) - cl[limb];
                    }
                }
                (None, Some(ad)) => {
                    for (i, value) in dst.iter_mut().enumerate() {
                        let n = ad[2 * limb][i] + ((ad[2 * limb + 1][i] % P) << 16);
                        *value = F::from_canonical_u32((n % P) as u32);
                    }
                }
                (None, None) => dst.fill(F::zero()),
            }
        }
    });
    out
}
/// (sum of W[i] * v[2i], sum of W[i] * v[2i+1]) with W[i] = high[i >> low] * low[i & mask] over the `m` pair bits.
fn weighted_pair_sums(c: &Soa, point: &[E]) -> (E, E) {
    let m = c.len().ilog2() as usize - 1; let lo = 12.min(m);
    let (ta, tb) = (eq_or_one(&point[..m - lo]), eq_or_one(&point[m - lo..m]));
    if lo < 4 {
        let mut s = (E::zero(), E::zero());
        for i in 0..1usize << m { let w = ta[i >> lo] * tb[i & ((1 << lo) - 1)]; s.0 += w * c.get(2 * i); s.1 += w * c.get(2 * i + 1); }
        return s;
    }
    let tbs = Soa::from_aos(&tb);
    (0..1usize << (m - lo)).into_par_iter().map(|ih| {
        let (mut a0, mut a1) = (pe_splat(E::zero()), pe_splat(E::zero()));
        for k in 0..(1usize << lo) / 16 { let (x0, x1) = pairs_at(c, (ih << lo) + 16 * k); let w = pe_at(&tbs, 16 * k); a0 += w * x0; a1 += w * x1; }
        (ta[ih] * pe_sum(a0), ta[ih] * pe_sum(a1))
    }).reduce(|| (E::zero(), E::zero()), |x, y| (x.0 + y.0, x.1 + y.1))
}
const OPENING_WINDOW_BITS: usize = 4;

/// Sum each column over the high bits with the equality weights for those bits.
/// Each output lane keeps a distinct assignment of the low bits.
fn project_opening_window(column: &Soa, prefix: &[E], width: usize) -> Vec<E> {
    if prefix.is_empty() {
        return column.to_aos();
    }
    debug_assert_eq!(width, OPENING_WINDOW_BITS);
    let low_bits = prefix.len().min(8);
    let split = prefix.len() - low_bits;
    let high_weights = eq_or_one(&prefix[..split]);
    let low_weights: Vec<PE> = eq_or_one(&prefix[split..]).into_iter().map(pe_splat).collect();
    let result = high_weights.par_iter().enumerate().map(|(high, weight)| {
        let mut acc = pe_splat(E::zero());
        let first = (high * low_weights.len()) << width;
        for (low, w) in low_weights.iter().enumerate() {
            acc += *w * pe_at(column, first + (low << width));
        }
        pe_splat(*weight) * acc
    }).reduce(|| pe_splat(E::zero()), |a, b| a + b);
    let fields: &[PF] = result.as_base_slice();
    let mut lanes = [[F::zero(); 1 << OPENING_WINDOW_BITS]; 4];
    for (lane, field) in lanes.iter_mut().zip(fields) {
        st(lane, *field);
    }
    (0..1 << width)
        .map(|i| E::from_base_slice(&[lanes[0][i], lanes[1][i], lanes[2][i], lanes[3][i]]))
        .collect()
}

/// Apply all four sampled challenges to the full column in a single pass.
fn fold_opening_window(column: &Soa, weights: PE) -> Soa {
    let mut output = Soa::with_len(column.len() >> OPENING_WINDOW_BITS);
    let [a, b, c, d] = &mut output.l;
    const CHUNK: usize = 256;
    (a.par_chunks_mut(CHUNK), b.par_chunks_mut(CHUNK), c.par_chunks_mut(CHUNK), d.par_chunks_mut(CHUNK))
        .into_par_iter().enumerate().for_each(|(block, (a, b, c, d))| {
            for i in 0..a.len() {
                let from = (block * CHUNK + i) << OPENING_WINDOW_BITS;
                let sum = pe_sum(weights * pe_at(column, from));
                let f: &[F] = sum.as_base_slice();
                (a[i], b[i], c[i], d[i]) = (f[0], f[1], f[2], f[3]);
            }
        });
    output
}

/// Sumcheck for the weighted opening columns, consuming low variables first.
///
/// A window projects out the high variables once, then reads its round messages
/// from the small low-bit projections. The full columns are folded only after
/// all challenges for the window have been sampled.
fn multi_point_sumcheck(mut cols: Vec<Soa>, points: &[Vec<E>], c: &mut Ch, claim: E) -> PartialSumcheckProof<E> {
    let g = cols.len();
    let xs: Vec<E> = (0..3).map(E::from_canonical_usize).collect();
    let (mut polys, mut rpoint, mut now, mut scales) = (Vec::new(), Vec::<E>::new(), claim, vec![E::one(); g]);

    while cols[0].len() > 1 {
        let bits = cols[0].len().ilog2() as usize;
        let width = bits.min(OPENING_WINDOW_BITS);
        let prefix = bits - width;
        let mut projections: Vec<_> = cols.iter().zip(points)
            .map(|(column, point)| project_opening_window(column, &point[..prefix], width))
            .collect();
        let mut challenges = Vec::with_capacity(width);

        for m in (prefix..bits).rev() {
            let (mut y0, mut y2) = (E::zero(), E::zero());
            for i in 0..g {
                let low_weights = eq_or_one(&points[i][prefix..m]);
                let (mut s0, mut s1) = (E::zero(), E::zero());
                for (w, pair) in low_weights.iter().zip(projections[i].chunks_exact(2)) {
                    s0 += *w * pair[0];
                    s1 += *w * pair[1];
                }
                let r = points[i][m];
                y0 += scales[i] * (E::one() - r) * s0;
                y2 += scales[i] * (r + r + r - E::one()) * (s1 + s1 - s0);
            }
            let poly = interpolate_univariate_polynomial(&xs, &[y0, now - y0, y2]);
            c.observe_slice(&poly.coefficients.iter().flat_map(|v| v.as_base_slice()).copied().collect::<Vec<F>>());
            let alpha: E = c.sample_ext_element();
            challenges.push(alpha);
            rpoint.insert(0, alpha);
            now = poly.eval_at_point(alpha);
            for i in 0..g {
                let r = points[i][m];
                scales[i] *= (E::one() - r) * (E::one() - alpha) + r * alpha;
                let projection = &mut projections[i];
                let half = projection.len() / 2;
                for j in 0..half {
                    let x0 = projection[2 * j];
                    let x1 = projection[2 * j + 1];
                    projection[j] = x0 + alpha * (x1 - x0);
                }
                projection.truncate(half);
            }
            polys.push(poly);
        }

        if prefix == 0 {
            break;
        }
        // Equality table indexes coordinates from the most significant bit.
        challenges.reverse();
        let packed = pe_at(&Soa::from_aos(&eq_small(&challenges)), 0);
        for column in &mut cols {
            *column = fold_opening_window(column, packed);
        }
    }

    PartialSumcheckProof { univariate_polys: polys, claimed_sum: claim, point_and_eval: (rpoint.into(), now) }
}

#[cfg(test)]
mod opening_window_tests {
    use super::*;
    use cmfd_consensus::forgematrix_v4_basefold::ForgeMatrixV4IopContext;
    use slop_challenger::IopCtx;

    #[test]
    fn opening_windows_preserve_the_generic_sumcheck_transcript() {
        let mut seed = 0x42b6_7d31_u32;
        let mut field = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            F::from_canonical_u32(seed % P as u32)
        };
        let mut value = || E::from_base_slice(&[field(), field(), field(), field()]);
        for bits in [1, 3, 4, 5, 8, 9] {
            let mut points: Vec<Vec<E>> = (0..3).map(|_| (0..bits).map(|_| value()).collect()).collect();
            points[0][bits - 1] = E::zero();
            points[1][bits - 1] = E::one();
            let cols: Vec<Vec<E>> = (0..points.len()).map(|_| (0..1 << bits).map(|_| value()).collect()).collect();
            let eqs: Vec<Vec<E>> = points.iter().map(|p| eq(p)).collect();
            let claim: E = cols.iter().zip(&eqs).map(|(c, eq)| dot(c, eq)).sum();
            let packed = cols.iter().map(|c| Soa::from_aos(c)).collect();
            let generic_cols = cols.into_iter().zip(eqs).flat_map(|(c, eq)| [c, eq]).collect();
            let mut reference_ch = ForgeMatrixV4IopContext::default_challenger();
            let mut actual_ch = reference_ch.clone();
            let (reference, _) = sumcheck(generic_cols, &mut reference_ch, claim, 2, |x| {
                x.chunks_exact(2).map(|pair| pair[0] * pair[1]).sum()
            });
            let actual = multi_point_sumcheck(packed, &points, &mut actual_ch, claim);
            assert_eq!(actual.claimed_sum, reference.claimed_sum, "{bits} variables");
            assert_eq!(actual.univariate_polys.len(), reference.univariate_polys.len());
            for (a, b) in actual.univariate_polys.iter().zip(&reference.univariate_polys) {
                assert_eq!(a.coefficients, b.coefficients, "{bits} variables");
            }
            assert_eq!(actual.point_and_eval.0.iter().copied().collect::<Vec<_>>(),
                       reference.point_and_eval.0.iter().copied().collect::<Vec<_>>());
            assert_eq!(actual.point_and_eval.1, reference.point_and_eval.1, "{bits} variables");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Transform (Reed-Solomon code, blowup 1): one column of 2^23 coefficients -> 2^24 evaluations in
// bit-reversed order, like `Radix2DitParallel` + `bit_reverse_rows` in the library, but with decimation in frequency
// (no reordering copy), packed AVX-512 butterflies, and recursion to stay in cache.
use slop_algebra::TwoAdicField;
const LOG_CODE: usize = 24;
static TWIDDLES: std::sync::OnceLock<Vec<Vec<F>>> = std::sync::OnceLock::new();
/// tw[k][j] = (root of order 2^k)^j for j < 2^(k-1)
fn twiddles() -> &'static Vec<Vec<F>> {
    TWIDDLES.get_or_init(|| {
        let g = F::two_adic_generator(LOG_CODE);
        let half = 1usize << (LOG_CODE - 1);
        let mut top = vec![F::one(); half];
        top.par_chunks_mut(1 << 12).enumerate().for_each(|(c, chunk)| { let mut w = g.exp_u64((c << 12) as u64); for x in chunk.iter_mut() { *x = w; w *= g; } });
        let mut tw: Vec<Vec<F>> = (0..=LOG_CODE).map(|_| Vec::new()).collect();
        for k in 1..LOG_CODE { let step = 1usize << (LOG_CODE - k); tw[k] = (0..1usize << (k - 1)).into_par_iter().map(|j| top[j * step]).collect(); }
        tw[LOG_CODE] = top;
        tw
    })
}
#[inline(always)] fn st(dst: &mut [F], v: PF) { let lanes: [F; 16] = unsafe { std::mem::transmute::<PF, [F; 16]>(v) }; dst[..16].copy_from_slice(&lanes); }
static LEAF_TWIDDLES: std::sync::OnceLock<[PF; 4]> = std::sync::OnceLock::new();

#[inline(always)]
fn dif_leaf(x: &mut [F], tw: &[PF; 4]) {
    use std::arch::x86_64::*;
    let round = |a: PF, half: usize, mask: u16, weights: PF| -> PF {
        let indices: [i32; 16] = std::array::from_fn(|i| (i ^ half) as i32);
        // Each permutation stays in the 16 initialized lanes.
        unsafe {
            let indices = std::mem::transmute::<[i32; 16], __m512i>(indices);
            let a_bits = std::mem::transmute::<PF, __m512i>(a);
            let b = std::mem::transmute::<__m512i, PF>(_mm512_permutexvar_epi32(indices, a_bits));
            let sum = std::mem::transmute::<PF, __m512i>(a + b);
            let difference = std::mem::transmute::<PF, __m512i>((b - a) * weights);
            std::mem::transmute::<__m512i, PF>(_mm512_mask_blend_epi32(mask, sum, difference))
        }
    };
    let a = round(pf(x), 8, 0xff00, tw[3]);
    let b = round(a, 4, 0xf0f0, tw[2]);
    let c = round(b, 2, 0xcccc, tw[1]);
    st(x, round(c, 1, 0xaaaa, tw[0]));
}

fn leaf_twiddles(tw: &[Vec<F>]) -> &[PF; 4] {
    LEAF_TWIDDLES.get_or_init(|| std::array::from_fn(|k| {
        let table = &tw[k + 1];
        let lanes: [F; 16] = std::array::from_fn(|i| table[i % table.len()]);
        pf(&lanes)
    }))
}

/// Two levels of the same DIF butterfly per read/write pass.
fn dif(x: &mut [F], k: usize, tw: &[Vec<F>], leaf: &[PF; 4]) {
    if k == 4 {
        dif_leaf(x, leaf);
        return;
    }
    let half = x.len() / 2;
    let (lo, hi) = x.split_at_mut(half);
    if k == 5 {
        let (a, b) = (pf(lo), pf(hi));
        st(lo, a + b);
        st(hi, (a - b) * pf(&tw[k]));
        dif_leaf(lo, leaf);
        dif_leaf(hi, leaf);
        return;
    }
    let quarter = half / 2;
    let (a, b) = lo.split_at_mut(quarter);
    let (c, d) = hi.split_at_mut(quarter);
    let (tw_first, tw_second) = (&tw[k], &tw[k - 1]);
    for i in (0..quarter).step_by(16) {
        let (av, bv, cv, dv) = (pf(&a[i..]), pf(&b[i..]), pf(&c[i..]), pf(&d[i..]));
        let p = av + cv;
        let q = bv + dv;
        let r = (av - cv) * pf(&tw_first[i..]);
        let s = (bv - dv) * pf(&tw_first[i + quarter..]);
        let t = pf(&tw_second[i..]);
        st(&mut a[i..], p + q);
        st(&mut b[i..], (p - q) * t);
        st(&mut c[i..], r + s);
        st(&mut d[i..], (r - s) * t);
    }
    for column in [a, b, c, d] { dif(column, k - 2, tw, leaf); }
}

/// Upper half starts at zero before the first butterfly.
fn encode_column(col: &mut [F]) {
    let tw = twiddles();
    let leaf = leaf_twiddles(tw);
    let half = col.len() / 2;
    let (lo, hi) = col.split_at_mut(half);
    for i in (0..half).step_by(16) {
        st(&mut hi[i..], pf(&lo[i..]) * pf(&tw[LOG_CODE][i..]));
    }
    rayon::join(
        || dif(lo, LOG_CODE - 1, tw, leaf),
        || dif(hi, LOG_CODE - 1, tw, leaf),
    );
}

fn encode_trace_column(col: &mut [F], coefficients: &[u32], to_field: PF) {
    let tw = twiddles();
    let leaf = leaf_twiddles(tw);
    let (lo, hi) = col.split_at_mut(coefficients.len());
    // F has a transparent 32-bit representation. Conversion to Montgomery
    // form is done before either value enters a butterfly.
    let raw: &[F] = unsafe { std::slice::from_raw_parts(coefficients.as_ptr().cast(), coefficients.len()) };
    for i in (0..coefficients.len()).step_by(16) {
        let v = pf(&raw[i..]) * to_field;
        st(&mut lo[i..], v);
        st(&mut hi[i..], v * pf(&tw[LOG_CODE][i..]));
    }
    dif(lo, LOG_CODE - 1, tw, leaf);
    dif(hi, LOG_CODE - 1, tw, leaf);
}

#[cfg(test)]
#[test]
fn fused_dif_matches_scalar_transform() {
    let tw = twiddles();
    for k in [4usize, 5, 6, 7, 8] {
        let mut actual: Vec<F> = (0u64..1 << k)
            .map(|i| F::from_canonical_u32(((i * i + 37) * 0x3a6b_e9 % P) as u32)).collect();
        let mut expected = actual.clone();
        for level in (1..=k).rev() {
            let half = 1 << (level - 1);
            for block in expected.chunks_exact_mut(2 * half) {
                for i in 0..half {
                    let (lo, hi)=(block[i],block[i+half]);
                    block[i]=lo+hi;
                    block[i+half]=(lo-hi)*tw[level][i];
                }
            }
        }
        dif(&mut actual,k,tw,leaf_twiddles(tw));
        assert_eq!(actual,expected);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Poseidon2 hash tree (sponge without padding, rate 8, compression = truncated permutation) over columns:
// same digests as `commit_tensors` in the library, 16 leaves per packed permutation, no copied matrix.
use slop_koala_bear::my_kb_16_perm;
use slop_symmetric::Permutation;
/// levels[0] = leaf digests, ..., last = root. Each level is stored limb by limb (8 words).
type Tree = Vec<[Vec<F>; 8]>;
const MERKLE_TILE_LOG: usize = 8;
const MERKLE_TILE: usize = 1 << MERKLE_TILE_LOG;

/// Build just one leaf subtree. Commitments retain its root; openings recreate
/// the same lower levels for requested rows.
fn dynamic_merkle_tile(
    cols: &[Vec<F>], start: usize, query: Option<usize>,
) -> ([F; 8], Vec<[F; 8]>) {
    let perm = my_kb_16_perm();
    let zero = PF::from(F::zero());
    let mut nodes = [[F::zero(); MERKLE_TILE]; 8];
    for offset in (0..MERKLE_TILE).step_by(16) {
        let mut state = [zero; 16];
        let row = start + offset;
        for i in 0..8 { state[i] = pf(&cols[i][row..]); }
        perm.permute_mut(&mut state);
        if cols.len() == 16 {
            for i in 0..8 { state[i] = pf(&cols[8 + i][row..]); }
            perm.permute_mut(&mut state);
        }
        for i in 0..8 { st(&mut nodes[i][offset..], state[i]); }
    }
    let mut path = query.map_or_else(Vec::new, |_| Vec::with_capacity(MERKLE_TILE_LOG));
    for level in 0..MERKLE_TILE_LOG {
        if let Some(query) = query {
            let sibling = (query >> level) ^ 1;
            path.push(std::array::from_fn(|limb| nodes[limb][sibling]));
        }
        let parents = MERKLE_TILE >> (level + 1);
        // Below 16 parents only the leading lanes remain live. The full tile
        // stays allocated and the extra lanes cannot affect any live lane.
        for parent in (0..parents).step_by(16) {
            let mut state = [zero; 16];
            for i in 0..8 {
                let (left, right) = split(&nodes[i][2 * parent..]);
                state[i] = left;
                state[8 + i] = right;
            }
            perm.permute_mut(&mut state);
            for i in 0..8 { st(&mut nodes[i][parent..], state[i]); }
        }
    }
    (std::array::from_fn(|i| nodes[i][0]), path)
}

fn merkle_columns(cols: &[Vec<F>]) -> Tree {
    let rows = cols[0].len();
    assert!(cols.len() == 8 || cols.len() == 16);
    assert!(rows.is_power_of_two() && rows >= MERKLE_TILE);
    let mut tile_roots: [Vec<F>; 8] = std::array::from_fn(|_| falloc(rows / MERKLE_TILE));
    let [a, b, c, d, e, f, g, h] = &mut tile_roots;
    (a.par_iter_mut(), b, c, d, e, f, g, h).into_par_iter().enumerate()
        .for_each(|(i, (a, b, c, d, e, f, g, h))| {
            let (root, _) = dynamic_merkle_tile(cols, i * MERKLE_TILE, None);
            for (dst, val) in [a, b, c, d, e, f, g, h].into_iter().zip(root) { *dst = val; }
        });
    merkle_up(tile_roots)
}
fn merkle_up(leaf: [Vec<F>; 8]) -> Tree {
    let perm = my_kb_16_perm();
    let zero = PF::from(F::zero());
    let mut tree: Tree = vec![leaf];
    while tree.last().unwrap()[0].len() > 1 {
        let prev = tree.last().unwrap();
        let m = prev[0].len() / 2;
        let mut next: [Vec<F>; 8] = std::array::from_fn(|_| falloc(m));
        if m >= 16 {
            let [a, b, c, d, e, f, g, h] = &mut next;
            (a.par_chunks_mut(16), b.par_chunks_mut(16), c.par_chunks_mut(16), d.par_chunks_mut(16), e.par_chunks_mut(16), f.par_chunks_mut(16), g.par_chunks_mut(16), h.par_chunks_mut(16))
                .into_par_iter().enumerate().for_each(|(k, outs)| {
                    let mut state = [zero; 16];
                    for i in 0..8 { let (l, r) = split(&prev[i][32 * k..]); state[i] = l; state[8 + i] = r; }
                    perm.permute_mut(&mut state);
                    let outs = [outs.0, outs.1, outs.2, outs.3, outs.4, outs.5, outs.6, outs.7];
                    for (i, dst) in outs.into_iter().enumerate() { st(dst, state[i]); }
                });
        } else {
            for j in 0..m {
                let mut state = [F::zero(); 16];
                for i in 0..8 { state[i] = prev[i][2 * j]; state[8 + i] = prev[i][2 * j + 1]; }
                perm.permute_mut(&mut state);
                for i in 0..8 { next[i][j] = state[i]; }
            }
        }
        tree.push(next);
    }
    tree
}
/// Tree of one folding round: leaf r = elements 2r and 2r+1 of the codeword (8 words).
fn merkle_pairs(c: &Soa) -> Tree {
    let (perm, n) = (my_kb_16_perm(), c.len() / 2);
    let zero = PF::from(F::zero());
    let mut leaf: [Vec<F>; 8] = std::array::from_fn(|_| falloc(n));
    if n >= 16 {
        let [a, b, cc, d, e, f, g, h] = &mut leaf;
        (a.par_chunks_mut(16), b.par_chunks_mut(16), cc.par_chunks_mut(16), d.par_chunks_mut(16), e.par_chunks_mut(16), f.par_chunks_mut(16), g.par_chunks_mut(16), h.par_chunks_mut(16))
            .into_par_iter().enumerate().for_each(|(k, outs)| {
                let mut state = [zero; 16];
                for l in 0..4 { let (ev, od) = split(&c.l[l][32 * k..]); state[l] = ev; state[4 + l] = od; }
                perm.permute_mut(&mut state);
                let outs = [outs.0, outs.1, outs.2, outs.3, outs.4, outs.5, outs.6, outs.7];
                for (i, dst) in outs.into_iter().enumerate() { st(dst, state[i]); }
            });
    } else {
        for r in 0..n {
            let mut state = [F::zero(); 16];
            for l in 0..4 { state[l] = c.l[l][2 * r]; state[4 + l] = c.l[l][2 * r + 1]; }
            perm.permute_mut(&mut state);
            for i in 0..8 { leaf[i][r] = state[i]; }
        }
    }
    merkle_up(leaf)
}
fn open_pairs(c: &Soa, tree: &Tree, indices: &[usize]) -> MerkleTreeOpeningAndProof<GC> {
    let height = tree.len() - 1;
    let (mut values, mut paths) = (Vec::with_capacity(indices.len() * 8), Vec::with_capacity(indices.len() * height));
    for &q in indices {
        for l in 0..4 { values.push(c.l[l][2 * q]); }
        for l in 0..4 { values.push(c.l[l][2 * q + 1]); }
        for level in 0..height { let s = (q >> level) ^ 1; paths.push(std::array::from_fn::<F, 8, _>(|i| tree[level][i][s])); }
    }
    MerkleTreeOpeningAndProof::<GC> { values: Tensor::from(values).reshape([indices.len(), 8]),
        proof: MerkleTreeTcsProof { merkle_root: tree_root(tree), log_tensor_height: height, width: 8, paths: Tensor::from(paths).reshape([indices.len(), height]) } }
}
/// New column of half the length: f(block index, even values, odd values), 16 at a time.
fn soa_pairs_map(c: &Soa, f: impl Fn(usize, PE, PE) -> PE + Sync, fs: impl Fn(usize, E, E) -> E) -> Soa {
    let n = c.len() / 2;
    let mut out = Soa::with_len(n);
    if n < 16 { for i in 0..n { let v = fs(i, c.get(2 * i), c.get(2 * i + 1)); out.set(i, v); } return out; }
    {
        let [o0, o1, o2, o3] = &mut out.l;
        (o0.par_chunks_mut(16), o1.par_chunks_mut(16), o2.par_chunks_mut(16), o3.par_chunks_mut(16)).into_par_iter().enumerate().for_each(|(k, (a, b, c2, d))| {
            let (x0, x1) = pairs_at(c, 16 * k);
            let r = f(k, x0, x1);
            let limbs: &[PF] = r.as_base_slice();
            for (dst, src) in [a, b, c2, d].into_iter().zip(limbs) { st(dst, *src); }
        });
    }
    out
}
/// For a codeword of 2^k elements: table of (root of order 2^k)^(-bitrev(i)) for i < 2^(k-1).
static INV_TWIDDLES: std::sync::OnceLock<Vec<Vec<F>>> = std::sync::OnceLock::new();
fn inv_twiddles() -> &'static Vec<Vec<F>> {
    INV_TWIDDLES.get_or_init(|| {
        let tw = twiddles();
        (0..=LOG_CODE).map(|k| {
            if k == 0 { return Vec::new(); }
            let half = 1usize << (k - 1);
            (0..half).into_par_iter().map(|i| {
                let j = if k == 1 { 0 } else { i.reverse_bits() >> (usize::BITS as usize - (k - 1)) };
                if j == 0 { F::one() } else { -tw[k][half - j] }
            }).collect()
        }).collect()
    })
}
fn tree_root(tree: &Tree) -> [F; 8] { let top = tree.last().unwrap(); std::array::from_fn(|i| top[i][0]) }
/// The published commitment: compression of the root with the digest of (height in bits, width).
fn tree_commitment(tree: &Tree, height: usize, width: usize) -> [F; 8] {
    let perm = my_kb_16_perm();
    let mut h = [F::zero(); 16];
    h[0] = F::from_canonical_usize(height); h[1] = F::from_canonical_usize(width);
    perm.permute_mut(&mut h);
    let root = tree_root(tree);
    let mut state = [F::zero(); 16];
    for i in 0..8 { state[i] = root[i]; state[8 + i] = h[i]; }
    perm.permute_mut(&mut state);
    std::array::from_fn(|i| state[i])
}
/// Opening of the rows `indices`: column values and paths (siblings from bottom to top).
fn dynamic_merkle_path(cols: &[Vec<F>], tree: &Tree, query: usize) -> Vec<[F;8]> {
    let (tile, local) = (query / MERKLE_TILE, query % MERKLE_TILE);
    let (root, mut path) = dynamic_merkle_tile(cols, tile * MERKLE_TILE, Some(local));
    debug_assert_eq!(root, std::array::from_fn(|i| tree[0][i][tile]));
    let mut node = tile;
    for level in tree.iter().take(tree.len() - 1) {
        path.push(std::array::from_fn(|limb| level[limb][node ^ 1]));
        node >>= 1;
    }
    path
}

fn open_columns(cols: &[Vec<F>], tree: &Tree, indices: &[usize]) -> MerkleTreeOpeningAndProof<GC> {
    let width = cols.len();
    let height = MERKLE_TILE_LOG + tree.len() - 1;
    let values: Vec<F> = indices.iter().flat_map(|&q| cols.iter().map(move |col| col[q])).collect();
    let paths = indices.par_iter().map(|&q| dynamic_merkle_path(cols, tree, q)).collect::<Vec<_>>();
    let paths: Vec<[F; 8]> = paths.into_iter().flatten().collect();
    MerkleTreeOpeningAndProof::<GC> { values: Tensor::from(values).reshape([indices.len(), width]),
        proof: MerkleTreeTcsProof { merkle_root: tree_root(tree), log_tensor_height: height,
            width, paths: Tensor::from(paths).reshape([indices.len(), height]) } }
}

#[cfg(test)]
#[test]
fn tiled_dynamic_merkle_paths_match_full_tree() {
    for width in [8, 16] {
        let rows = MERKLE_TILE * 4;
        let cols: Vec<Vec<F>> = (0..width).map(|column| (0..rows).map(|row|
            F::from_canonical_u32(((row as u64 + 1) * (column as u64 + 43) * 17863 % P) as u32)
        ).collect()).collect();
        let perm = my_kb_16_perm();
        let mut leaves = std::array::from_fn(|_| Vec::with_capacity(rows));
        for row in 0..rows {
            let mut state = [F::zero(); 16];
            for i in 0..8 { state[i] = cols[i][row]; }
            perm.permute_mut(&mut state);
            if width == 16 {
                for i in 0..8 { state[i] = cols[8 + i][row]; }
                perm.permute_mut(&mut state);
            }
            for i in 0..8 { leaves[i].push(state[i]); }
        }
        let full = merkle_up(leaves);
        let tiled = merkle_columns(&cols);
        assert_eq!(tree_root(&full), tree_root(&tiled));
        assert_eq!(
            tree_commitment(&full, full.len() - 1, width),
            tree_commitment(&tiled, MERKLE_TILE_LOG + tiled.len() - 1, width)
        );
        for query in [0, 1, MERKLE_TILE-1, MERKLE_TILE, rows-2, rows-1] {
            let expected = full.iter().enumerate().take(full.len()-1).map(|(level, siblings)|
                std::array::from_fn(|limb| siblings[limb][(query >> level) ^ 1])
            ).collect::<Vec<[F;8]>>();
            assert_eq!(dynamic_merkle_path(&cols, &tiled, query), expected);
        }
    }
}

fn eq_or_one(point: &[E]) -> Vec<E> { if point.is_empty() { vec![E::one()] } else { eq(point) } }
#[cfg(test)]
mod cubic_fold_tests {
    use super::*;
    use cmfd_consensus::forgematrix_v4_basefold::ForgeMatrixV4IopContext;
    use slop_challenger::IopCtx;

    #[test]
    fn cubic_fold_preserves_extension_values() {
        let mut seed = 0x65aa_5d42_u32;
        let mut value = || {
            E::from_base_slice(&std::array::from_fn::<F, 4, _>(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                F::from_canonical_u32(seed % P as u32)
            }))
        };
        for size in [2, 16, 32, 64, 512, 32768, 65536] {
            let challenge = value();
            let input: Vec<E> = (0..size).map(|_| value()).collect();
            let mut column = Soa::from_aos(&input);
            let expected: Vec<E> = input.chunks_exact(2)
                .map(|pair| pair[0] + challenge * (pair[1] - pair[0])).collect();
            soa_fold(&mut column, challenge);
            assert_eq!(column.to_aos(), expected);
        }
    }

    #[test]
    fn cubic_fold_preserves_the_generic_sumcheck_transcript() {
        for bits in [5, 6, 8, 10] {
            let values: Vec<u32> = (0..1 << bits)
                .map(|i| ((u64::from(i as u32) * 0xa688_b925) % P) as u32)
                .collect();
            let base: Vec<F> = values.iter().copied().map(F::from_canonical_u32).collect();
            let cubes: Vec<F> = base.iter().map(|&x| x * x * x).collect();
            let next: Vec<u32> = cubes.iter().map(|x| x.as_canonical_u32()).collect();
            let point: Vec<E> = (0..bits)
                .map(|i| E::from_base_slice(&[2 * i + 3, 3 * i + 5, 5 * i + 7, 7 * i + 11]
                    .map(F::from_canonical_usize)))
                .collect();
            let cols = vec![
                base.into_iter().map(E::from_base).collect(),
                cubes.into_iter().map(E::from_base).collect(),
                eq(&point),
            ];
            let mut reference_ch = ForgeMatrixV4IopContext::default_challenger();
            let mut actual_ch = reference_ch.clone();
            let (reference, expected_ends) = sumcheck(cols, &mut reference_ch, E::zero(), 4, |x| {
                x[2] * (x[1] - x[0] * x[0] * x[0])
            });
            let (actual, ends) = cubic_sumcheck(&values, &next, &point, &mut actual_ch);
            assert_eq!(actual.claimed_sum, reference.claimed_sum);
            assert_eq!(actual.univariate_polys.len(), reference.univariate_polys.len());
            for (actual, expected) in actual.univariate_polys.iter().zip(&reference.univariate_polys) {
                assert_eq!(actual.coefficients, expected.coefficients, "{bits} variables");
            }
            assert_eq!(
                actual.point_and_eval.0.iter().copied().collect::<Vec<_>>(),
                reference.point_and_eval.0.iter().copied().collect::<Vec<_>>(),
            );
            assert_eq!(actual.point_and_eval.1, reference.point_and_eval.1);
            assert_eq!(ends, [expected_ends[0], expected_ends[1]]);
        }
    }
}


#[inline(always)]
fn load_cubic_quads(values: &[u32], index: usize, montgomery: PF) -> [PF; 4] {
    let slice = &values[4 * index..][..64];
    // Both types are transparent over a canonical 32-bit field word.
    let raw = unsafe { std::slice::from_raw_parts(slice.as_ptr().cast::<F>(), 64) };
    let (even_lo, odd_lo) = split(raw);
    let (even_hi, odd_hi) = split(&raw[32..]);
    let split_vectors = |lo: PF, hi: PF| {
        let words = unsafe { std::mem::transmute::<[PF; 2], [F; 32]>([lo, hi]) };
        split(&words)
    };
    let (v0, v2) = split_vectors(even_lo, even_hi);
    let (v1, v3) = split_vectors(odd_lo, odd_hi);
    [v0, v1, v2, v3].map(|v| v * montgomery)
}

/// Evaluate the second round from groups of four original values. After one
/// challenge, each interpolation is A + alpha*B for base-field A and B.
fn cubic_second_round(
    p: &[u32], q: &[u32], point: &[E], alpha: E, montgomery: PF,
) -> [E; 4] {
    let m = point.len() - 2;
    let lo = 12.min(m);
    let (high, low) = (eq_or_one(&point[..m-lo]), eq_or_one(&point[m-lo..m]));
    let low = Soa::from_aos(&low);
    let powers = [alpha, alpha * alpha, alpha * alpha * alpha].map(pe_splat);
    let expand = |a: PF, b: PF, c: PF, d: PF| -> PE {
        let a2 = a * a;
        let b2 = b * b;
        let a2b = a2 * b;
        let ab2 = a * b2;
        let base = pe([c - a2 * a, PF::zero(), PF::zero(), PF::zero()]);
        base + powers[0] * (d - (a2b + a2b + a2b))
             - powers[1] * (ab2 + ab2 + ab2) - powers[2] * (b2 * b)
    };
    (0..high.len()).into_par_iter().map(|block| {
        let mut acc = [pe_splat(E::zero()); 4];
        for pack in 0..(1 << lo) / 16 {
            let j = (block << lo) + 16 * pack;
            let [p0,p1,p2,p3] = load_cubic_quads(p, j, montgomery);
            let [q0,q1,q2,q3] = load_cubic_quads(q, j, montgomery);
            let weight = pe_at(&low, 16 * pack);
            let pd0 = p1-p0;
            let qd0 = q1-q0;
            let pd1 = p3-p2;
            let qd1 = q3-q2;
            let (pa, pb, qa, qb) = (p2-p0, pd1-pd0, q2-q0, qd1-qd0);
            acc[0] += weight * expand(p0, pd0, q0, qd0);
            let (mut a, mut b, mut c, mut d) = (p2, pd1, q2, qd1);
            for total in &mut acc[1..] {
                a += pa;
                b += pb;
                c += qa;
                d += qb;
                *total += weight * expand(a, b, c, d);
            }
        }
        acc.map(|s| high[block] * pe_sum(s))
    }).reduce(|| [E::zero(); 4], |x,y| std::array::from_fn(|i| x[i]+y[i]))
}

fn cubic_fold_quads(values: &[u32], alpha: E, beta: E, montgomery: PF) -> Soa {
    let weights = [
        (E::one()-alpha) * (E::one()-beta),
        alpha * (E::one()-beta),
        (E::one()-alpha) * beta,
        alpha * beta,
    ].map(pe_splat);
    let mut output = Soa::with_len(values.len()/4);
    let [o0,o1,o2,o3] = &mut output.l;
    (o0.par_chunks_mut(16), o1.par_chunks_mut(16), o2.par_chunks_mut(16), o3.par_chunks_mut(16))
        .into_par_iter().enumerate().for_each(|(pack,(a,b,c,d))| {
            let [v0,v1,v2,v3] = load_cubic_quads(values, pack*16, montgomery);
            let value = weights[0]*v0 + weights[1]*v1 + weights[2]*v2 + weights[3]*v3;
            let limbs: &[PF] = value.as_base_slice();
            for (dst, &limb) in [a,b,c,d].into_iter().zip(limbs) { st(dst,limb); }
        });
    output
}

/// Cubic relation: sum over the hypercube of eq(point, x) * (next(x) - value(x)^3) = 0, 26 variables.
/// Same messages as the generic sumcheck, but the first round runs in the base field (the sums at 0 and at 1 are zero),
/// the equality is split into two small tables (high bits, low bits) with a factor for the bound variables, and there is no 2^26 table.
fn cubic_sumcheck(p: &[u32], q: &[u32], point: &[E], c: &mut Ch) -> (PartialSumcheckProof<E>, [E; 2]) {
    let nv = point.len();
    let xs: Vec<E> = (0..=4).map(E::from_canonical_usize).collect();
    let lo_at = |r: E, t: E| (E::one() - r) * (E::one() - t) + r * t;
    let (mut polys, mut rpoint, mut claim, mut scale) = (Vec::new(), Vec::<E>::new(), E::zero(), E::one());
    let finish = |ys: [E; 5], r: E, c: &mut Ch, polys: &mut Vec<_>, rpoint: &mut Vec<E>, claim: &mut E, scale: &mut E| -> E {
        let poly = interpolate_univariate_polynomial(&xs, &ys);
        c.observe_slice(&poly.coefficients.iter().flat_map(|v| v.as_base_slice()).copied().collect::<Vec<F>>());
        let alpha: E = c.sample_ext_element();
        rpoint.insert(0, alpha);
        *claim = poly.eval_at_point(alpha);
        *scale *= lo_at(r, alpha);
        polys.push(poly);
        alpha
    };
    // round 1: pairs (2i, 2i+1) in the base field. h(0) = h(1) = 0 because next = value^3 on the hypercube.
    let m = nv - 1; let lo = 12.min(m);
    let (ta, tb) = (eq_or_one(&point[..m - lo]), eq_or_one(&point[m - lo..m]));
    // canonical u32 values -> field (Montgomery form): raw read, then one multiplication by R
    let to_field = PF::from(F::from_canonical_u32(((1u64 << 32) % P) as u32));
    let load = move |v: &[u32], j: usize| -> (PF, PF) { let raw: &[F] = unsafe { std::slice::from_raw_parts(v.as_ptr().add(2 * j).cast::<F>(), 32) }; let (e, o) = split(raw); (e * to_field, o * to_field) };
    let tbs = Soa::from_aos(&tb);
    let s = (0..1usize << (m - lo)).into_par_iter().map(|ih| {
        let z = PF::from(F::zero());
        let mut acc = [[z; 4]; 3];
        for k in 0..(1usize << lo) / 16 {
            let j = (ih << lo) + 16 * k;
            let ((a0, a1), (b0, b1)) = (load(p, j), load(q, j));
            let w: [PF; 4] = std::array::from_fn(|l| pf(&tbs.l[l][16 * k..]));
            let (da, db, mut a, mut b) = (a1 - a0, b1 - b0, a1, b1);
            for t in 0..3 { a += da; b += db; let h = b - a * a * a; for l in 0..4 { acc[t][l] += w[l] * h; } }
        }
        let wa = ta[ih];
        [wa * pe_sum(pe(acc[0])), wa * pe_sum(pe(acc[1])), wa * pe_sum(pe(acc[2]))]
    }).reduce(|| [E::zero(); 3], |x, y| [x[0] + y[0], x[1] + y[1], x[2] + y[2]]);
    let r = point[m];
    let ys = [E::zero(), E::zero(), lo_at(r, xs[2]) * s[0], lo_at(r, xs[3]) * s[1], lo_at(r, xs[4]) * s[2]];
    let alpha = finish(ys, r, c, &mut polys, &mut rpoint, &mut claim, &mut scale);
    let fold1 = |v: &[u32]| -> Soa {
        let n = v.len() / 2;
        let al: &[F] = alpha.as_base_slice();
        let pa: [PF; 4] = std::array::from_fn(|l| PF::from(al[l]));
        let mut out = Soa::with_len(n);
        let [o0, o1, o2, o3] = &mut out.l;
        (o0.par_chunks_mut(16), o1.par_chunks_mut(16), o2.par_chunks_mut(16), o3.par_chunks_mut(16)).into_par_iter().enumerate().for_each(|(k, (x0, x1, x2, x3))| {
            let (e, o) = load(v, 16 * k); let d = o - e;
            let res = [e + pa[0] * d, pa[1] * d, pa[2] * d, pa[3] * d];
            for (dst, src) in [x0, x1, x2, x3].into_iter().zip(res) { let lanes: [F; 16] = unsafe { std::mem::transmute::<PF, [F; 16]>(src) }; dst.copy_from_slice(&lanes); }
        });
        out
    };
    let (mut a, mut b) = if nv >= 6 {
        let s = cubic_second_round(p, q, point, alpha, to_field);
        let r = point[nv - 2];
        let g0 = scale * lo_at(r,xs[0]) * s[0];
        let ys = [g0, claim-g0, scale*lo_at(r,xs[2])*s[1],
                  scale*lo_at(r,xs[3])*s[2], scale*lo_at(r,xs[4])*s[3]];
        let beta = finish(ys, r, c, &mut polys, &mut rpoint, &mut claim, &mut scale);
        (cubic_fold_quads(p, alpha, beta, to_field), cubic_fold_quads(q, alpha, beta, to_field))
    } else {
        (fold1(p), fold1(q))
    };
    // following rounds in the extension field, 16 pairs per operation
    while a.len() > 1 {
        let m = a.len().ilog2() as usize - 1; let lo = 12.min(m);
        let (ta, tb) = (eq_or_one(&point[..m - lo]), eq_or_one(&point[m - lo..m]));
        let (ar, br) = (&a, &b);
        let s = if lo < 4 {
            let mut acc = [E::zero(); 4];
            for i in 0..1usize << m {
                let (a0, a1, b0, b1, w) = (ar.get(2 * i), ar.get(2 * i + 1), br.get(2 * i), br.get(2 * i + 1), ta[i >> lo] * tb[i & ((1 << lo) - 1)]);
                acc[0] += w * (b0 - a0 * a0 * a0);
                let (da, db, mut x, mut y) = (a1 - a0, b1 - b0, a1, b1);
                for t in 1..4 { x += da; y += db; acc[t] += w * (y - x * x * x); }
            }
            acc
        } else {
            let tbs = Soa::from_aos(&tb);
            (0..1usize << (m - lo)).into_par_iter().map(|ih| {
                let z = pe_splat(E::zero());
                let mut acc = [z, z, z, z];
                for k in 0..(1usize << lo) / 16 {
                    let j = (ih << lo) + 16 * k;
                    let ((a0, a1), (b0, b1), w) = (pairs_at(ar, j), pairs_at(br, j), pe_at(&tbs, 16 * k));
                    acc[0] += w * (b0 - a0 * a0 * a0);
                    let (da, db, mut x, mut y) = (a1 - a0, b1 - b0, a1, b1);
                    for t in 1..4 { x += da; y += db; acc[t] += w * (y - x * x * x); }
                }
                let wa = ta[ih];
                [wa * pe_sum(acc[0]), wa * pe_sum(acc[1]), wa * pe_sum(acc[2]), wa * pe_sum(acc[3])]
            }).reduce(|| [E::zero(); 4], |x, y| [x[0] + y[0], x[1] + y[1], x[2] + y[2], x[3] + y[3]])
        };
        let r = point[m];
        let g0 = scale * lo_at(r, xs[0]) * s[0];
        let ys = [g0, claim - g0, scale * lo_at(r, xs[2]) * s[1], scale * lo_at(r, xs[3]) * s[2], scale * lo_at(r, xs[4]) * s[3]];
        let alpha = finish(ys, r, c, &mut polys, &mut rpoint, &mut claim, &mut scale);
        soa_fold(&mut a, alpha); soa_fold(&mut b, alpha);
    }
    let (a, b) = (a.to_aos(), b.to_aos());
    (PartialSumcheckProof { univariate_polys: polys, claimed_sum: E::zero(), point_and_eval: (rpoint.into(), claim) }, [a[0], b[0]])
}
/// out[layer * WIDTH + column] = sum over the batch of coeff[batch] * values[layer][batch][column]
fn reduce_batches(values: &[u32], coeff: &[E], layers: usize) -> Vec<E> {
    let mut out = vec![E::zero(); layers * WIDTH];
    out.par_chunks_mut(WIDTH).enumerate().for_each(|(l, row)| {
        for b in 0..BATCH { let w = coeff[b]; let src = &values[(l * BATCH + b) * WIDTH..][..WIDTH]; for j in 0..WIDTH { row[j] += w * F::from_canonical_u32(src[j]); } }
    });
    out
}
/// out[layer * WIDTH + k] = sum over output j of coeff[j] * (byte[layer][k][j] - 125), exact sums per limb.
fn reduce_weights(bytes: &[u8], coeff: &[E]) -> Vec<E> {
    let limbs: [Vec<u64>; 4] = std::array::from_fn(|l| coeff.iter().map(|c| { let b: &[F] = c.as_base_slice(); b[l].as_canonical_u32() as u64 }).collect());
    let center: E = coeff.iter().copied().sum::<E>() * F::from_canonical_u32(125);
    #[cfg(all(target_feature = "avx512vnni", target_feature = "avx512bw"))]
    let weights = limbs.each_ref().map(|v| packed_fixed_weights(v));
    bytes.par_chunks_exact(WIDTH).map(|row| {
        let s: [F; 4] = std::array::from_fn(|l| {
            #[cfg(all(target_feature = "avx512vnni", target_feature = "avx512bw"))]
            let acc = fixed_dot_packed(row, &weights[l].0, &weights[l].1);
            #[cfg(not(all(target_feature = "avx512vnni", target_feature = "avx512bw")))]
            let acc: u64 = row.iter().zip(&limbs[l]).map(|(&b, &w)| u64::from(b) * w).sum();
            F::from_canonical_u32((acc % P) as u32)
        });
        E::from_base_slice(&s) - center
    }).collect()
}
const ROWS: usize = 1 << 23;
const OPENING_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/OpeningReduction/v2";
fn limbs_of(values: &[E]) -> [Vec<u64>; 4] { std::array::from_fn(|l| values.iter().map(|c| { let b: &[F] = c.as_base_slice(); b[l].as_canonical_u32() as u64 }).collect()) }
/// The 256 fixed columns and the 16 dynamic columns of a bank evaluated at one row point.
/// Evaluate a column against a low-coordinate equality table and combine the
/// block evaluations with the remaining coordinates. This avoids constructing
/// a full table of 2^23 extension values for every opening.
#[cfg(all(target_feature = "avx512vnni", target_feature = "avx512bw"))]
fn column_evaluations(bytes: &[u8], p: &[u32], q: &[u32], point: &[E]) -> (Vec<E>, Vec<E>) {
    use std::arch::x86_64::*;
    const BLOCK: usize = 4096;
    const COLS: usize = 8;
    assert_eq!(1usize << point.len(), ROWS);
    assert_eq!(bytes.len(), 256 * ROWS);
    assert_eq!(p.len(), 8 * ROWS);
    assert_eq!(q.len(), 8 * ROWS);
    let split = point.len() - 12;
    let high = eq(&point[..split]);
    let low = limbs_of(&eq(&point[split..]));
    let packed = low.each_ref().map(|v| packed_fixed_weights(v));
    let result = high.par_iter().enumerate().fold(
        || vec![E::zero(); 272],
        |mut result, (block, &scale)| {
            let row = block * BLOCK;
            for first in (0..256).step_by(COLS) {
                let mut words = [[F::zero(); 4]; COLS];
                for limb in 0..4 {
                    // The block and all eight columns lie in the validated bank.
                    // Each signed i32 lane receives at most 256 byte products.
                    unsafe {
                        let mut a = [_mm512_setzero_si512(); COLS];
                        let mut b = [_mm512_setzero_si512(); COLS];
                        for i in (0..BLOCK).step_by(32) {
                            let w0 = _mm512_loadu_si512(packed[limb].0.as_ptr().add(i).cast());
                            let w1 = _mm512_loadu_si512(packed[limb].1.as_ptr().add(i).cast());
                            for c in 0..COLS {
                                let ptr = bytes.as_ptr().add((first+c)*ROWS + row + i);
                                let x = _mm512_cvtepu8_epi16(_mm256_loadu_si256(ptr.cast()));
                                a[c] = _mm512_dpwssd_epi32(a[c], x, w0);
                                b[c] = _mm512_dpwssd_epi32(b[c], x, w1);
                            }
                        }
                        for c in 0..COLS {
                            let a: [i32;16] = std::mem::transmute(a[c]);
                            let b: [i32;16] = std::mem::transmute(b[c]);
                            let sum = a.into_iter().map(i64::from).sum::<i64>()
                                + (b.into_iter().map(i64::from).sum::<i64>() << 16);
                            words[c][limb] = F::from_canonical_u32((sum as u64 % P) as u32);
                        }
                    }
                }
                for c in 0..COLS { result[first+c] += E::from_base_slice(&words[c]) * scale; }
            }
            for c in 0..16 {
                let col = if c<8 { &p[c*ROWS+row..][..BLOCK] } else { &q[(c-8)*ROWS+row..][..BLOCK] };
                let words: [F;4] = std::array::from_fn(|limb| {
                    let mut lo = 0u64;
                    let mut hi = 0u64;
                    for (&x,&w) in col.iter().zip(&low[limb]) {
                        lo += u64::from(x) * (w & 0xffff);
                        hi += u64::from(x) * (w >> 16);
                    }
                    F::from_canonical_u32(((lo + ((hi % P) << 16)) % P) as u32)
                });
                result[256+c] += E::from_base_slice(&words) * scale;
            }
            result
        },
    ).reduce(|| vec![E::zero();272], |mut x,y| { for (dest,v) in x.iter_mut().zip(y) { *dest+=v; } x });
    let mut fixed = result;
    let dynamic = fixed.split_off(256);
    // The equality weights sum to one over the hypercube.
    for x in &mut fixed { *x -= E::from_canonical_u32(125); }
    (fixed,dynamic)
}

#[cfg(not(all(target_feature = "avx512vnni", target_feature = "avx512bw")))]

fn column_evaluations(bytes: &[u8], p: &[u32], q: &[u32], point: &[E]) -> (Vec<E>, Vec<E>) {
    let eqp = eq(point);
    let el = limbs_of(&eqp);
    let center: E = eqp.par_iter().copied().sum::<E>() * F::from_canonical_u32(125);
    // by blocks of rows, so that the weights of a block fit in cache. byte (8 bits) x weight (31 bits), exact sums in u64
    #[cfg(all(target_feature = "avx512vnni", target_feature = "avx512bw"))]
    let weights = el.par_iter().map(|v| packed_fixed_weights(v)).collect::<Vec<_>>();
    const BLK: usize = 32768;
    let sums = (0..ROWS / BLK).into_par_iter().fold(|| vec![[0u64; 4]; 256], |mut acc, blk| {
        let r0 = blk * BLK;
        for c in 0..256 {
            let col = &bytes[c * ROWS + r0..][..BLK];
            for l in 0..4 {
                #[cfg(all(target_feature = "avx512vnni", target_feature = "avx512bw"))]
                let t = fixed_dot_packed(col, &weights[l].0[r0..r0+BLK], &weights[l].1[r0..r0+BLK]);
                #[cfg(not(all(target_feature = "avx512vnni", target_feature = "avx512bw")))]
                let t: u64 = col.iter().zip(&el[l][r0..r0+BLK]).map(|(&b, &w)| u64::from(b) * w).sum();
                acc[c][l] = (acc[c][l] + t % P) % P;
            }
        }
        acc
    }).reduce(|| vec![[0u64; 4]; 256], |mut x, y| { for c in 0..256 { for l in 0..4 { x[c][l] = (x[c][l] + y[c][l]) % P; } } x });
    let fixed: Vec<E> = sums.iter().map(|t| { let s: [F; 4] = std::array::from_fn(|l| F::from_canonical_u32((t[l] % P) as u32)); E::from_base_slice(&s) - center }).collect();
    let dynamic: Vec<E> = (0..16).into_par_iter().map(|c| {
        let col = if c < 8 { &p[c * ROWS..][..ROWS] } else { &q[(c - 8) * ROWS..][..ROWS] };
        let mut total = [0u64; 4];
        for (rows, start) in col.chunks(4096).zip((0..ROWS).step_by(4096)) {
            for l in 0..4 {
                let w = &el[l][start..start + rows.len()];
                let (mut lo, mut hi) = (0u64, 0u64);
                for i in 0..rows.len() { lo += rows[i] as u64 * (w[i] & 0xffff); hi += rows[i] as u64 * (w[i] >> 16); }
                total[l] = (total[l] + lo % P + ((hi % P) << 16) % P) % P;
            }
        }
        let s: [F; 4] = std::array::from_fn(|l| F::from_canonical_u32(total[l] as u32));
        E::from_base_slice(&s)
    }).collect();
    (fixed, dynamic)
}
/// Public opening of a bank: reduces its 16 openings to one point, then evaluates the 256 + 16 columns at that point.
fn opening(bytes: &[u8], p: &[u32], q: &[u32], fixed: [F; 8], dynamic: [F; 8], claims: &[Claim], ch: &mut Ch) -> Opening {
    let mut pch = ch.clone();
    observe_bytes(&mut pch, OPENING_DOMAIN); pch.observe(fixed); pch.observe(dynamic); pch.observe(F::from_canonical_usize(claims.len()));
    for c in claims {
        pch.observe(F::from_canonical_u8(c.commitment as u8));
        for x in c.column_point.iter() { pch.observe_ext_element(*x); }
        for x in c.row_point.iter() { pch.observe_ext_element(*x); }
        pch.observe_ext_element(c.value);
    }
    let lambda: E = pch.sample_ext_element();
    let mut powers = vec![E::one(); claims.len()];
    for i in (0..claims.len() - 1).rev() { powers[i] = powers[i + 1] * lambda; }
    let claimed: E = claims.iter().zip(&powers).map(|(c, w)| c.value * *w).sum();
    // Openings with the same row point are merged: same round polynomial, fewer columns.
    let mut groups: Vec<(Vec<E>, Vec<E>, Vec<E>, bool, bool)> = Vec::new(); // point, fixed weights (256), dynamic weights (16)
    for (c, w) in claims.iter().zip(&powers) {
        let row: Vec<E> = c.row_point.iter().copied().collect();
        let coeff: Vec<E> = eq(&c.column_point.iter().copied().collect::<Vec<_>>()).iter().map(|x| *x * *w).collect();
        let g = match groups.iter().position(|g| g.0 == row) { Some(g) => g, None => { groups.push((row, vec![E::zero(); 256], vec![E::zero(); 16], false, false)); groups.len() - 1 } };
        match c.commitment {
            Side::Fixed => { for (a, b) in groups[g].1.iter_mut().zip(&coeff) { *a += *b; } groups[g].3 = true; }
            Side::Dynamic => { for (a, b) in groups[g].2.iter_mut().zip(&coeff) { *a += *b; } groups[g].4 = true; }
        }
    }
    let n = groups.len();
    let mut cols = Vec::with_capacity(2 * n);
    for g in &groups {
        cols.push(group_line(bytes, p, q, g.3.then_some(&g.1[..]), g.4.then_some(&g.2[..])));
    }
    let sumcheck_proof = multi_point_sumcheck(cols, &groups.iter().map(|g| g.0.clone()).collect::<Vec<_>>(), &mut pch, claimed);
    let point: Vec<E> = sumcheck_proof.point_and_eval.0.iter().copied().collect();
    let (fixed_evaluations, dynamic_evaluations) = column_evaluations(bytes, p, q, &point);
    fn put(bytes: &mut Vec<u8>, v: &E) { let f: &[F] = v.as_base_slice(); for x in f { bytes.extend_from_slice(&x.as_canonical_u32().to_le_bytes()); } }
    let mut wire = Vec::with_capacity(3_300_008);
    wire.extend_from_slice(b"CMV4BF01"); wire.extend_from_slice(&1_u32.to_le_bytes()); wire.extend_from_slice(&16_u32.to_le_bytes());
    for poly in &sumcheck_proof.univariate_polys { assert_eq!(poly.coefficients.len(), 3); for v in &poly.coefficients { put(&mut wire, v); } }
    put(&mut wire, &sumcheck_proof.claimed_sum);
    for v in sumcheck_proof.point_and_eval.0.iter() { put(&mut wire, v); }
    put(&mut wire, &sumcheck_proof.point_and_eval.1);
    for v in fixed_evaluations.iter().chain(dynamic_evaluations.iter()) { put(&mut wire, v); }
    assert_eq!(wire.len(), 5_872);
    wire.resize(3_300_008, 0);
    let proof = cmfd_consensus::forgematrix_v4_basefold_codec::decode_forgematrix_v4_opening_reduction(&wire, 16).expect("opening decodes");
    forgematrix_v4_direct::verify_public_opening([fixed, dynamic], claims, &proof, ch).expect("opening rejected by the verifier");
    proof
}
/// Everything that is loaded once: the model packed for the kernel, the bytes of the 3 banks, the fixed commitments, the trace buffers.
struct Ctx { source: ForgeMatrixV4FileLayerSource, packed: Option<AriaPackedBank>, banks: Vec<memmap2::Mmap>, fixed: [[F; 8]; 3], base_input: Vec<u8>, record_path: String, threads: usize, pre: Vec<u32>, act: Vec<u32>, commitment_columns: Vec<Vec<F>>, self_check: bool }
fn load(bank_path: &str, record_path: &str, threads: usize, capture_mode: bool) -> Ctx {
    let record: ForgeMatrixV4FixedArtifactRecordV1 = serde_json::from_slice(&fs::read(record_path).unwrap()).unwrap();
    let fixed: [[F; 8]; 3] = std::array::from_fn(|b| record.banks()[b].commitment_words().map(F::from_canonical_u32));
    let (_v, identity) = ConsensusPowVerifier::v4_candidate_for_network_with_layer_roots(COMPACT_MAINNET_NETWORK_ID, record, BufReader::with_capacity(64 << 20, fs::File::open(bank_path).unwrap())).unwrap();
    let source = ForgeMatrixV4FileLayerSource::new(fs::File::open(bank_path).unwrap(), &identity.manifest, Arc::clone(&identity.base_input), Arc::clone(&identity.layer_roots)).unwrap();
    let packed = (!capture_mode).then(|| AriaPackedBank::build(&source, 16).unwrap());
    // The bank bytes are read through a file mapping: no second copy in memory, and the page cache is shared with the node.
    let model = fs::File::open(bank_path).unwrap();
    let banks: Vec<memmap2::Mmap> = (0..3).map(|bank| unsafe { memmap2::MmapOptions::new().offset(184 + CELLS as u64 + (bank * BANK_BYTES) as u64).len(BANK_BYTES).map(&model).unwrap() }).collect();
    #[cfg(unix)]
    for b in &banks { let _ = b.advise(memmap2::Advice::WillNeed); }
    twiddles(); inv_twiddles();
    Ctx { source, packed, banks, fixed, base_input: identity.base_input.to_vec(), record_path: record_path.to_owned(), threads, pre: Vec::new(), act: Vec::new(), commitment_columns: Vec::new(), self_check: std::env::var("ARIA_PROVER_SELF_CHECK").as_deref() == Ok("1") }
}
/// The whole proof (`forgematrix_v4_direct` packet) for the block (`challenge`, `nonce`), and the time of each step.
fn prove(ctx: &mut Ctx, challenge: BlockChallenge, nonce: u64, capture: Option<(&[u32], &[u32], [u8;32])>) -> (Vec<u8>, [u8; 32], Vec<(&'static str, f64)>) {
    let mut steps: Vec<(&'static str, f64)> = Vec::new();
    let digest = forgematrix_v4_challenge_digest(&challenge, nonce, PRODUCTION_V4_MODEL_MANIFEST_DIGEST);
    let coefficients = forgematrix_v4_replay_coefficients(digest);
    let (banks, fixed, base_input, record_path) = (&ctx.banks, ctx.fixed, &ctx.base_input, &ctx.record_path);
    let t_step = Instant::now();
    let (pre, act, last, expected): (&[u32], &[u32], Vec<u32>, Option<[u8;32]>) = match capture {
        Some((pre,act,work)) => {
            assert_eq!(pre.len(),3*BANK_VALUES);
            assert_eq!(act.len(),3*BANK_VALUES);
            assert!(pre.par_iter().chain(act.par_iter()).all(|&x|u64::from(x)<P),"non-canonical replay trace");
            (pre,act,act[act.len()-CELLS..].to_vec(),Some(work))
        }
        None => {
            let packed=ctx.packed.get_or_insert_with(||AriaPackedBank::build(&ctx.source,16).unwrap());
            ctx.pre.resize(3*BANK_VALUES,0); ctx.act.resize(3*BANK_VALUES,0);
            let last=packed.execute_traced(&coefficients,ctx.threads,&mut ctx.pre,&mut ctx.act).unwrap();
            (&ctx.pre,&ctx.act,last,None)
        }
    };
    let initial = AriaPackedBank::initial_from_base(base_input,&coefficients).unwrap();
    let encoded: Vec<u8> = last.iter().flat_map(|x| x.to_le_bytes()).collect();
    let final_digest = forgematrix_v4_final_activation_digest_from_le_bytes(digest, &encoded).unwrap();
    let work = forgematrix_v4_work_digest(PRODUCTION_V4_MODEL_MANIFEST_DIGEST, digest, final_digest);
    if let Some(expected) = expected { assert_eq!(work,expected,"replay trace differs from checked work"); }
    steps.push((if capture.is_some() {"captured trace"} else {"trace"}, t_step.elapsed().as_secs_f64()));
    let parameters = ForgeMatrixV4CandidateParameters::for_network(COMPACT_MAINNET_NETWORK_ID).unwrap();
    let statement = ForgeMatrixV4TranscriptStatement { block: challenge, algorithm_version: parameters.algorithm_version(), proof_version: parameters.proof_version_at_height(challenge.height), nonce,
        proof_system_digest: parameters.proof_system_digest_at_height(challenge.height), model_manifest_digest: PRODUCTION_V4_MODEL_MANIFEST_DIGEST, challenge_digest: digest, final_activation_digest: final_digest, work_digest: work };
    let t_step = Instant::now();
    let to_field = PF::from(F::from_canonical_u32(((1u64 << 32) % P) as u32));
    let mut reusable_columns = std::mem::take(&mut ctx.commitment_columns);
    let workspace: Vec<Vec<Vec<F>>> = (0..3).map(|_| {
        (0..16).map(|_| reusable_columns.pop().unwrap_or_default()).collect()
    }).collect();
    // All three commitments depend only on the completed trace.
    let dynamic_data: Vec<_> = workspace.into_par_iter().enumerate().map(|(bank, inputs)| {
        let (p, q) = (&pre[bank * BANK_VALUES..][..BANK_VALUES], &act[bank * BANK_VALUES..][..BANK_VALUES]);
        let cols: Vec<Vec<F>> = inputs.into_par_iter().enumerate().map(|(c, mut col)| {
            let src = if c < 8 { &p[c * ROWS..][..ROWS] } else { &q[(c - 8) * ROWS..][..ROWS] };
            if col.len() != 2 * ROWS { col = falloc(2 * ROWS); }
            encode_trace_column(&mut col, src, to_field);
            col
        }).collect();
        let tree = merkle_columns(&cols);
        (cols, tree)
    }).collect();
    let dynamic: [[F; 8]; 3] = std::array::from_fn(|b| {
        let tree = &dynamic_data[b].1;
        tree_commitment(tree, MERKLE_TILE_LOG + tree.len() - 1, 16)
    });
    steps.push(("commitment", t_step.elapsed().as_secs_f64()));
    let t_step = Instant::now();
    let mut ch = forgematrix_v4_transcript(statement);
    bind_forgematrix_v4_commitments(&mut ch, &fixed, &dynamic);
    let mut claims: Vec<Vec<Claim>> = vec![Vec::new(); 3];
    let mut all_relations: Vec<Vec<ForgeMatrixV4RelationRepetitionProof>> = vec![Vec::new(), Vec::new(), Vec::new()];
    for bank in 0..3 {
        let bytes: &[u8] = &banks[bank];
        let (p, q) = (&pre[bank * BANK_VALUES..][..BANK_VALUES], &act[bank * BANK_VALUES..][..BANK_VALUES]);
        let boundary: &[u32] = if bank == 0 { &initial } else { &act[bank * BANK_VALUES - CELLS..bank * BANK_VALUES] };
        let mut boundary_claims = Vec::new();
        for repetition in 0..2 {
            let mp = sample_forgematrix_v4_matrix_point(&mut ch, bank, repetition).unwrap();
            let (pl, pb, po): (Vec<E>, Vec<E>, Vec<E>) = (mp.layer.iter().copied().collect(), mp.batch.iter().copied().collect(), mp.output.iter().copied().collect());
            let (el, eb, eo) = (eq(&pl), eq(&pb), eq(&po));
            let pre_reduced = reduce_batches(p, &eb, LAYERS);
            let next_reduced = reduce_batches(q, &eb, LAYERS);
            let pre_eval = dot(&pre_reduced.par_chunks_exact(WIDTH).map(|row| dot(row, &eo)).collect::<Vec<_>>(), &el);
            let mask = forgematrix_v4_mask_evaluation(statement.challenge_digest, bank, &mp.layer, &mp.batch, &mp.output).unwrap();
            let mut pch = ch.clone();
            observe_bytes(&mut pch, MATRIX_PROOF_DOMAIN); pch.observe_ext_element(pre_eval); pch.observe_ext_element(mask);
            let weights = reduce_weights(bytes, &eo);
            let boundary_reduced = reduce_batches(boundary, &eb, 1);
            let mut input = boundary_reduced.clone(); input.extend_from_slice(&next_reduced[..(LAYERS - 1) * WIDTH]);
            let equality: Vec<E> = el.iter().flat_map(|x| std::iter::repeat_n(*x, WIDTH)).collect();
            let (matrix_sumcheck, ends) = sumcheck(vec![weights, input, equality], &mut pch, pre_eval - mask, 3, |x| x[0] * x[1] * x[2]);
            let matrix = ForgeMatrixV4MatrixRelationProof { sumcheck: matrix_sumcheck.clone(), preactivation_evaluation: pre_eval, weight_evaluation: ends[0], input_evaluation: ends[1] };
            verify_forgematrix_v4_matrix_relation(&mp, mask, &matrix, &mut ch).expect("matrix relation rejected");
            claims[bank].extend(forgematrix_v4_matrix_opening_claims(&mp, &matrix).unwrap());
            let sp: Vec<E> = matrix_sumcheck.point_and_eval.0.iter().copied().collect();
            let (terminal_layer, terminal_common) = (&sp[..7], &sp[7..]);
            let ec = eq(terminal_common);
            let next_values: Vec<E> = next_reduced.par_chunks_exact(WIDTH).map(|row| dot(row, &ec)).collect();
            let boundary_evaluation = dot(&boundary_reduced, &ec);
            let mut pch = ch.clone();
            observe_bytes(&mut pch, SHIFT_PROOF_DOMAIN); pch.observe_ext_element(ends[1]); pch.observe_ext_element(boundary_evaluation);
            let shifted: Vec<E> = (0..LAYERS).map(|l| if l + 1 < LAYERS { eq_at_boolean(terminal_layer, l + 1) } else { E::zero() }).collect();
            let (shift_sumcheck, shift_ends) = sumcheck(vec![next_values, shifted], &mut pch, ends[1] - eq_at_boolean(terminal_layer, 0) * boundary_evaluation, 2, |x| x[0] * x[1]);
            let shift = ForgeMatrixV4ShiftRelationProof { sumcheck: shift_sumcheck, boundary_evaluation, next_activation_evaluation: shift_ends[0] };
            let cpu_terminal_layer = forgematrix_v4_matrix_terminal_layer(&matrix).unwrap();
            verify_forgematrix_v4_shift_relation(&cpu_terminal_layer, matrix.input_evaluation, &shift, &mut ch).expect("shift relation rejected");
            claims[bank].push(forgematrix_v4_shift_opening_claim(&mp, &matrix, &shift).unwrap());
            if bank > 0 { boundary_claims.push(forgematrix_v4_shift_boundary_opening_claim(&mp, &matrix, &shift).unwrap()); }
            let cp = sample_forgematrix_v4_cubic_point(&mut ch, bank, repetition).unwrap();
            let cpoint: Vec<E> = cp.layer.iter().chain(cp.batch.iter()).chain(cp.output.iter()).copied().collect();
            let mut pch = ch.clone();
            observe_bytes(&mut pch, CUBIC_PROOF_DOMAIN);
            let (cubic_sumcheck, cubic_ends) = cubic_sumcheck(p, q, &cpoint, &mut pch);
            let cubic = ForgeMatrixV4CubicRelationProof { sumcheck: cubic_sumcheck, preactivation_evaluation: cubic_ends[0], next_activation_evaluation: cubic_ends[1] };
            verify_forgematrix_v4_cubic_relation(&cp, &cubic, &mut ch).expect("cubic relation rejected");
            claims[bank].extend(forgematrix_v4_cubic_opening_claims(&cubic).unwrap());
            let mine = ForgeMatrixV4RelationRepetitionProof { matrix, shift, cubic };
            all_relations[bank].push(mine);
        }
        if bank > 0 { claims[bank - 1].extend(boundary_claims); }
    }
    steps.push(("relations", t_step.elapsed().as_secs_f64()));
    let t_step = Instant::now();
    let final_activation: Vec<F> = last.iter().map(|x| F::from_canonical_u32(*x)).collect();
    for repetition in 0..2 {
        let fp = sample_forgematrix_v4_final_point(&mut ch, repetition).unwrap();
        let value = cmfd_consensus::forgematrix_v4_proof::forgematrix_v4_activation_evaluation(&final_activation, &fp.batch, &fp.output).unwrap();
        claims[2].push(forgematrix_v4_final_opening_claim(&fp, value).unwrap());
    }
    for bank in 0..3 { finalize_forgematrix_v4_bank_opening_claims(&mut claims[bank]).unwrap(); }
    let mut openings = Vec::new();
    for bank in 0..3 {
        let bytes: &[u8] = &banks[bank];
        let (p, q) = (&pre[bank * BANK_VALUES..][..BANK_VALUES], &act[bank * BANK_VALUES..][..BANK_VALUES]);
        let mine = opening(bytes, p, q, fixed[bank], dynamic[bank], &claims[bank], &mut ch);
        openings.push(mine);
    }
    steps.push(("openings", t_step.elapsed().as_secs_f64()));
    let t_step = Instant::now();
    use cmfd_consensus::forgematrix_v4_direct::reduction as direct;
    let lab = direct::Statement {
        shape: direct::Shape::production(), job: statement.digest(),
        roots: std::array::from_fn(|i| if i % 2 == 0 { fixed[i / 2] } else { dynamic[i / 2] }),
        bank_points: std::array::from_fn(|b| openings[b].sumcheck.point_and_eval.0.iter().copied().collect()),
        original_evaluations: std::array::from_fn(|i| if i % 2 == 0 { openings[i / 2].fixed_column_evaluations.clone() } else { openings[i / 2].dynamic_column_evaluations.clone() }),
    };
    let start = direct::begin_proving(&lab).expect("reduction start");
    let (mut dch, weights) = (start.challenger, start.column_weights);
    let mut cols = Vec::new();
    let mut at = 0;
    for bank in 0..3 {
        let bytes: &[u8] = &banks[bank];
        let (p, q) = (&pre[bank * BANK_VALUES..][..BANK_VALUES], &act[bank * BANK_VALUES..][..BANK_VALUES]);
        cols.push(group_line(bytes, p, q, Some(&weights[at..at + 256]), Some(&weights[at + 256..at + 272]))); at += 272;
    }
    let red_sumcheck = multi_point_sumcheck(cols, &lab.bank_points, &mut dch, start.claimed_sum);
    let shared_point: Vec<E> = red_sumcheck.point_and_eval.0.iter().copied().collect();
    let mut shared: [Vec<E>; 6] = std::array::from_fn(|_| Vec::new());
    for bank in 0..3 {
        let bytes: &[u8] = &banks[bank];
        let (p, q) = (&pre[bank * BANK_VALUES..][..BANK_VALUES], &act[bank * BANK_VALUES..][..BANK_VALUES]);
        let (f, d) = column_evaluations(bytes, p, q, &shared_point);
        shared[2 * bank] = f; shared[2 * bank + 1] = d;
    }
    let reduction = direct::ReductionProof {
        batch_witness: start.batch_witness,
        rounds: red_sumcheck.univariate_polys.iter().map(|u| [u.coefficients[0], u.coefficients[1], u.coefficients[2]]).collect(),
        evaluations_at_shared_point: shared,
    };
    let obligation = direct::verify_reduction(&lab, &reduction).expect("reduction rejected by the verifier");
    steps.push(("reduction", t_step.elapsed().as_secs_f64()));
    let t_step = Instant::now();
    let mut c = obligation.prover_challenger();
    let batch_grinding_witness = c.grind(BATCH_GRINDING_BITS);
    let batching_point = c.sample_point::<E>(10);
    let coefficients = partial_lagrange_blocking(&batching_point);
    let coefficients = coefficients.as_slice();
    let mut lines = Vec::new();
    let mut at = 0;
    for bank in 0..3 {
        let bytes: &[u8] = &banks[bank];
        let (p, q) = (&pre[bank * BANK_VALUES..][..BANK_VALUES], &act[bank * BANK_VALUES..][..BANK_VALUES]);
        lines.push(group_line(bytes, p, q, Some(&coefficients[at..at + 256]), Some(&coefficients[at + 256..at + 272]))); at += 272;
    }
    let mut lines = lines.into_iter();
    let mut mle = lines.next().expect("three bank lines");
    let second = lines.next().expect("three bank lines");
    let third = lines.next().expect("three bank lines");
    for ((output, b), c) in mle.l.iter_mut().zip(&second.l).zip(&third.l) {
        (output.par_chunks_mut(4096), b.par_chunks(4096), c.par_chunks(4096))
            .into_par_iter().for_each(|(out, b, c)| {
                for i in (0..out.len()).step_by(16) {
                    let value = pf(&out[i..]) + pf(&b[i..]) + pf(&c[i..]);
                    st(&mut out[i..], value);
                }
            });
    }
    drop(second);
    drop(third);
    let mut claim: E = reduction.evaluations_at_shared_point.iter().flatten().zip(coefficients).map(|(v, w)| *v * *w).sum();
    let limb_cols: Vec<Vec<F>> = mle.l.par_iter().map(|limb| {
        let mut col = falloc(2 * ROWS);
        col[..ROWS].copy_from_slice(limb);
        encode_column(&mut col);
        col
    }).collect();
    let mut code = Soa { l: limb_cols.try_into().ok().expect("four limbs") };
    let itw = inv_twiddles();
    let half = { use slop_algebra::Field; F::two().inverse() };
    let ph = PF::from(half);
    let log_len = 23usize;
    let (mut univariate_messages, mut fri_commitments) = (Vec::new(), Vec::new());
    let mut rounds: Vec<(Soa, Tree)> = Vec::new();
    c.observe(F::from_canonical_usize(log_len));
    for round in 0..log_len {
        let m = log_len - 1 - round;
        let last_coord = shared_point[m];
        let zero_val = weighted_pair_sums(&mle, &shared_point).0;
        let one_val = (claim - zero_val) / last_coord + zero_val;
        univariate_messages.push([zero_val, one_val]);
        c.observe_ext_element(zero_val); c.observe_ext_element(one_val);
        let tree = merkle_pairs(&code);
        let commitment = tree_commitment(&tree, tree.len() - 1, 8);
        c.observe(commitment);
        fri_commitments.push(commitment);
        let beta: E = c.sample_ext_element();
        // folded codeword: (c0 + c1) / 2 + (beta / 2) * (c0 - c1) * root^(-bitrev(i))
        let (half_beta, table) = (beta * half, &itw[code.len().ilog2() as usize]);
        let phb = pe_splat(half_beta);
        let folded = soa_pairs_map(&code, |k, x0, x1| (x0 + x1) * ph + (x0 - x1) * phb * pf(&table[16 * k..]), |i, x0, x1| (x0 + x1) * half + (x0 - x1) * half_beta * table[i]);
        rounds.push((std::mem::replace(&mut code, folded), tree));
        // folded polynomial: a + beta * b
        let pb = pe_splat(beta);
        mle = soa_pairs_map(&mle, |_, x0, x1| x0 + pb * x1, |_, x0, x1| x0 + beta * x1);
        claim = zero_val + beta * one_val;
    }
    let final_poly = code.get(0);
    c.observe_ext_element(final_poly);
    let pow_witness = c.grind(16);
    let query_indices: Vec<usize> = (0..270).map(|_| c.sample_bits(log_len + 1)).collect();
    let fixed_dir = std::path::Path::new(record_path.as_str()).parent().unwrap();
    let raw = |b: &[u8], i: usize| -> F { let w = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()); assert!(w < 0x7f00_0001); unsafe { std::mem::transmute::<u32, F>(w) } };
    let mut components = Vec::new();
    let mut dynamic_data = dynamic_data.into_iter();
    for bank in 0..3 {
        let codeword = fs::File::open(fixed_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.row-major.codeword"))).unwrap();
        let tree = fs::File::open(fixed_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.tree"))).unwrap();
        // These release artifacts are immutable. Query pages are faulted in only as needed.
        let codeword = unsafe { memmap2::MmapOptions::new().map(&codeword).unwrap() };
        let tree = unsafe { memmap2::MmapOptions::new().map(&tree).unwrap() };
        let root = std::array::from_fn(|i| raw(&tree[..32], i));
        let opened: Vec<(Vec<F>, Vec<[F; 8]>)> = query_indices.par_iter().map(|&qi| {
            let row = &codeword[qi * 1024..][..1024];
            let values: Vec<F> = (0..256).map(|i| raw(row, i)).collect();
            let (mut path, mut node) = (Vec::with_capacity(24), (1usize << 24) - 1 + qi);
            for _ in 0..24 {
                let sibling = if node & 1 == 0 { node - 1 } else { node + 1 };
                let digest = &tree[sibling * 32..][..32];
                path.push(std::array::from_fn::<F, 8, _>(|i| raw(digest, i)));
                node = (node - 1) >> 1;
            }
            (values, path)
        }).collect();
        let (mut values, mut paths) = (Vec::new(), Vec::new());
        for (v, p) in opened { values.extend(v); paths.extend(p); }
        components.push(MerkleTreeOpeningAndProof::<GC> { values: Tensor::from(values).reshape([270, 256]),
            proof: MerkleTreeTcsProof { merkle_root: root, log_tensor_height: 24, width: 256, paths: Tensor::from(paths).reshape([270, 24]) } });
        let (cols, tree) = dynamic_data.next().unwrap();
        components.push(open_columns(&cols, &tree, &query_indices));
        // Each opening owns its values and paths; the next request overwrites
        // every codeword before using it.
        ctx.commitment_columns.extend(cols);
    }
    let mut query_phase = Vec::new();
    let mut indices = query_indices;
    for (code, tree) in rounds.iter() {
        for index in indices.iter_mut() { *index >>= 1; }
        query_phase.push(open_pairs(code, tree, &indices));
    }
    let basefold = BasefoldProof::<GC> { univariate_messages, fri_commitments, component_polynomials_query_openings_and_proofs: components, query_phase_openings_and_proofs: query_phase, final_poly, pow_witness, batch_grinding_witness };
    if ctx.self_check { obligation.verify_basefold(&basefold).expect("joint basefold rejected by the verifier"); }
    // --- whole proof
    let mut relations = all_relations.into_iter(); let mut openings = openings.into_iter();
    let banks: [cmfd_consensus::forgematrix_v4_proof::ForgeMatrixV4BankProof; 3] = std::array::from_fn(|b| cmfd_consensus::forgematrix_v4_proof::ForgeMatrixV4BankProof {
        dynamic_commitment: dynamic[b], relations: relations.next().unwrap().try_into().ok().expect("2 repetitions"), opening: openings.next().unwrap() });
    let public = cmfd_consensus::forgematrix_v4_proof::ForgeMatrixV4TransparentProof { final_activation, banks };
    let wire = forgematrix_v4_direct::encode(&public, statement, &reduction, &basefold).expect("proof encodes");
    steps.push(("final opening", t_step.elapsed().as_secs_f64()));
    if ctx.self_check {
        let t_step = Instant::now();
        forgematrix_v4_direct::verify_wire(statement, fixed, base_input, &wire).expect("whole proof rejected by the full verifier");
        steps.push(("self-check", t_step.elapsed().as_secs_f64()));
    }
    (wire, work, steps)
}
fn read_template(path: &str) -> (BlockChallenge, u64) {
    let v: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    (serde_json::from_value(v["challenge"].clone()).unwrap(), v["nonce"].as_u64().unwrap())
}
fn report(steps: &[(&'static str, f64)], total: f64, work: [u8; 32], bytes: usize) -> String {
    format!("proof of {bytes} bytes in {total:.2} s ({}) work {}", steps.iter().map(|(n, s)| format!("{n} {s:.2}")).collect::<Vec<_>>().join(", "), hex::encode(work))
}
/// Usage: `aria-cmfd-cpu-prover --server MODEL RECORD THREADS` (pool protocol: tab-separated lines on stdin,
/// `RUN template output` -> `CMFD_V4_PROOF_DONE`), or `aria-cmfd-cpu-prover MODEL RECORD THREADS TEMPLATE OUTPUT [RUNS]`.
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let server = a.get(1).map(String::as_str) == Some("--server");
    let o = if server { 2 } else { 1 };
    let t = Instant::now();
    #[cfg(any(windows, target_os = "linux"))]
    let maps: Vec<_> = match std::env::var("CMFD_CPU_TRACE_MAPS") {
        Ok(names) => {
            assert!(server && names.split(',').count()==2, "invalid pool trace configuration");
            names.split(',').map(|name| cmfd_consensus::forgematrix_v4_execution::aria_v4_cpu::trace_section::Reader::open(name).unwrap()).collect()
        }
        Err(std::env::VarError::NotPresent) => Vec::new(),
        Err(error) => panic!("invalid trace configuration: {error}"),
    };
    #[cfg(any(windows, target_os = "linux"))] let capture_mode=!maps.is_empty();
    #[cfg(not(any(windows, target_os = "linux")))] let capture_mode=false;
    let mut ctx = load(&a[o], &a[o + 1], a[o + 2].parse().unwrap(), capture_mode);
    eprintln!("aria-cmfd-cpu-prover: model loaded in {:.1} s, {} threads", t.elapsed().as_secs_f64(), ctx.threads);
    if !server {
        let (challenge, nonce) = read_template(&a[o + 3]);
        for run in 0..a.get(o + 5).map_or(1, |n| n.parse().unwrap()) {
            let t = Instant::now();
            let (wire, work, steps) = prove(&mut ctx, challenge, nonce, None);
            eprintln!("run {run}: {}", report(&steps, t.elapsed().as_secs_f64(), work, wire.len()));
            fs::write(&a[o + 4], &wire).unwrap();
        }
        return;
    }
    // warm-up: one dry proof fills the buffer pool and the page cache of the fixed files
    if std::env::var("ARIA_PROVER_NO_WARMUP").is_err() {
        let t = Instant::now();
        let warmup = BlockChallenge { height: 67_535, ..serde_json::from_str::<BlockChallenge>(&std::env::var("ARIA_PROVER_WARMUP_TEMPLATE").ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()).map(|v| v["challenge"].to_string()).unwrap_or_default()).unwrap_or_else(|_| panic!("warm-up template missing: set ARIA_PROVER_WARMUP_TEMPLATE")) };
        let (wire, work, steps) = prove(&mut ctx, warmup, 1, None);
        eprintln!("aria-cmfd-cpu-prover: warm-up: {}", report(&steps, t.elapsed().as_secs_f64(), work, wire.len()));
    }
    use std::io::{BufRead, Write};
    println!("{}", if capture_mode { "CMFD_V4_TRACE_PROOF_READY" } else { "CMFD_V4_PROOF_READY" });
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<&str> = line.trim_end().split('\t').collect();
        match fields.as_slice() {
            ["QUIT"] => break,
            ["RUN", template, output] | ["RUNTRACE", template, output, _, _] => {
                let t = Instant::now();
                let (challenge, nonce) = read_template(template);
                #[cfg(any(windows, target_os = "linux"))]
                let capture = if let ["RUNTRACE",_,_,index,work]=fields.as_slice() {
                    let i: usize = index.parse().expect("trace slot");
                    let expected: [u8;32] = hex::decode(work).unwrap().try_into().expect("work digest");
                    // The parent holds the slot until DONE or this process is reaped.
                    let (p,a)=unsafe {maps.get(i).expect("unconfigured trace slot").columns()};
                    Some((p,a,expected))
                } else { None };
                #[cfg(not(any(windows, target_os = "linux")))]
                let capture = { assert!(fields[0]=="RUN","unsupported trace transport"); None };
                let (wire, work, steps) = prove(&mut ctx, challenge, nonce, capture);
                let pending = format!("{output}.pending");
                fs::write(&pending, &wire).unwrap();
                fs::rename(&pending, output).unwrap();
                eprintln!("aria-cmfd-cpu-prover: height {}: {}", challenge.height, report(&steps, t.elapsed().as_secs_f64(), work, wire.len()));
                println!("CMFD_V4_PROOF_DONE");
                std::io::stdout().flush().unwrap();
            }
            _ => { eprintln!("aria-cmfd-cpu-prover: unknown command"); println!("CMFD_V4_PROOF_ERROR"); std::io::stdout().flush().unwrap(); }
        }
    }
}
