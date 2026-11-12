//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2023 Succinct Labs. See ../LICENSE-SP1-MIT.
//! Derived from the pinned SP1 GPU hadamard implementation. Upstream source
//! SHA-256: 8452aed19c93c512ce1bfd1bf990a61aed9d84c43fbe1adb0614aca486e57773.
//! The only algorithmic change streams the round-zero equality allocations;
//! all round messages and challenges are retained. The reserved-GPU differential
//! test checks complete proof bytes and transcript state against the SDK.
use itertools::Itertools;
use num_bigint::BigUint;
use slop_algebra::{interpolate_univariate_polynomial, AbstractField, Field};
use slop_algebra::{AbstractExtensionField, UnivariatePolynomial};
use slop_challenger::FieldChallenger;
use slop_multilinear::MleBaseBackend;
use slop_multilinear::{Mle, Point};
use sp1_gpu_cudart::sys::kernels::cubic_transition_fix_last_variable_and_sum_as_poly_ext_kernel;
use sp1_gpu_cudart::sys::kernels::cubic_transition_sum_as_poly_ext_kernel;
use sp1_gpu_cudart::sys::kernels::hadamard_fix_last_variable_and_sum_as_poly_base_ext_kernel;
use sp1_gpu_cudart::sys::kernels::hadamard_fix_last_variable_and_sum_as_poly_ext_ext_kernel;
use sp1_gpu_cudart::sys::kernels::hadamard_sum_as_poly_base_ext_kernel;
use sp1_gpu_cudart::sys::kernels::hadamard_sum_as_poly_ext_ext_kernel;
use sp1_gpu_cudart::sys::kernels::mle_fix_last_variable_koala_bear_ext_ext_zero_padding;
use sp1_gpu_cudart::sys::kernels::padded_hadamard_fix_and_sum;
use sp1_gpu_cudart::sys::kernels::triple_hadamard_fix_last_variable_and_sum_as_poly_ext_kernel;
use sp1_gpu_cudart::sys::kernels::triple_hadamard_sum_as_poly_ext_kernel;
use sp1_gpu_cudart::sys::runtime::Dim3;
use sp1_gpu_cudart::sys::runtime::KernelPtr;
use sp1_gpu_cudart::{args, dot_along_dim_view, DeviceTensor};
use sp1_gpu_cudart::{DevicePoint, TaskScope};
use sp1_gpu_utils::{Ext, Felt};

use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;

/// Generic helper for sum in last variable operations
fn sum_in_last_variable<F>(
    poly_base: &Mle<F, TaskScope>,
    poly_ext: &Mle<Ext, TaskScope>,
    claim: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> UnivariatePolynomial<Ext>
where
    F: Field,
{
    let num_variables = poly_base.num_variables();
    let num_polys = poly_base.num_polynomials();
    let scope = poly_base.backend();

    debug_assert!(num_variables >= 1);
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 1;

    let output_height = 1usize << (num_variables - 1);

    let grid_dim: Dim3 = (
        output_height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE).min(512),
        num_polys,
        1,
    )
        .into();

    let mut univariate_evals = Tensor::<Ext, TaskScope>::with_sizes_in(
        [2, grid_dim.y as usize, grid_dim.x as usize],
        scope.clone(),
    );
    let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();
    let num_variables_minus_one: usize = num_variables as usize - 1;
    unsafe {
        let args = args!(
            univariate_evals.as_mut_ptr(),
            poly_base.guts().as_ptr(),
            poly_ext.guts().as_ptr(),
            num_variables_minus_one,
            num_polys
        );
        univariate_evals.assume_init();
        scope
            .launch_kernel(kernel(), grid_dim, BLOCK_SIZE, &args, shared_mem)
            .unwrap();
    }
    let univariate_evals = DeviceTensor::from_raw(univariate_evals);
    let univariate_evals = univariate_evals.sum_dim(2).sum_dim(1);
    let host_evals = univariate_evals.to_host().unwrap();
    let [component_eval_zero, component_eval_half] = host_evals.as_slice().try_into().unwrap();
    let eval_zero = component_eval_zero;
    let eval_half = component_eval_half;

    let eval_one = claim - eval_zero;

    interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
        ],
        &[
            eval_zero,
            eval_one,
            eval_half * Felt::from_canonical_u16(4).inverse(),
        ],
    )
}

pub fn fix_last_variable<F>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    alpha: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (Mle<Ext, TaskScope>, Mle<Ext, TaskScope>)
where
    F: Field,
{
    let base = fix_last_variable_inner(&base, alpha, kernel);
    let ext = fix_last_variable_inner(
        &ext,
        alpha,
        mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
    );

    (base, ext)
}

fn fix_last_variable_inner<F>(
    mle: &Mle<F, TaskScope>,
    alpha: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> Mle<Ext, TaskScope>
where
    F: Field,
{
    let num_polynomials = 1;
    let input_height = mle.guts().sizes()[1];
    assert!(input_height > 0);
    let output_height = input_height.div_ceil(2);
    let mut output: Tensor<Ext, TaskScope> =
        mle.backend().uninit_mle(num_polynomials, output_height);

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 1;
    // This kernel already uses a grid-stride loop. Bounding resident threads
    // avoids a large per-launch local-memory reservation on long MLEs.
    let grid_size_x = output_height.div_ceil(BLOCK_SIZE * STRIDE).min(512);
    let grid_size_y = num_polynomials;
    let grid_size = (grid_size_x, grid_size_y, 1);

    let args = args!(
        mle.guts().as_ptr(),
        output.as_mut_ptr(),
        alpha,
        input_height,
        num_polynomials
    );

    unsafe {
        output.assume_init();
        mle.backend()
            .launch_kernel(kernel(), grid_size, BLOCK_SIZE, &args, 0)
            .unwrap();
    }

    mle.backend().synchronize_blocking().unwrap();
    Mle::new(output)
}

// returns (base_output, ext_output, next_univariate)
pub fn fix_last_variable_and_sum_as_poly<F>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    alpha: Ext,
    claim: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (
    Mle<Ext, TaskScope>,
    Mle<Ext, TaskScope>,
    UnivariatePolynomial<Ext>,
)
where
    F: Field,
{
    let input_height = base.guts().sizes()[1];
    let output_height = input_height.div_ceil(2);
    let backend = base.backend();
    let mut base_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);
    let mut ext_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 1;

    let grid_size_x = output_height.div_ceil(BLOCK_SIZE * STRIDE);

    let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    let mut univariate_evals =
        Tensor::<Ext, TaskScope>::with_sizes_in([2, grid_size_x], backend.clone());

    unsafe {
        let args = args!(
            base.guts().as_ptr(),
            ext.guts().as_ptr(),
            base_output.as_mut_ptr(),
            ext_output.as_mut_ptr(),
            alpha,
            univariate_evals.as_mut_ptr(),
            input_height
        );
        univariate_evals.assume_init();
        base_output.assume_init();
        ext_output.assume_init();
        backend
            .launch_kernel(kernel(), grid_size_x, BLOCK_SIZE, &args, shared_mem)
            .unwrap();
    }

    let uni_poly = interpolate_round_poly(univariate_evals, claim);

    (Mle::new(base_output), Mle::new(ext_output), uni_poly)
}

/// Sum the per-block `(eval_zero, eval_half)` partial evaluations produced by a
/// fix-and-sum kernel and interpolate the round's degree-2 univariate polynomial.
fn interpolate_round_poly(
    univariate_evals: Tensor<Ext, TaskScope>,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    let univariate_evals = DeviceTensor::from_raw(univariate_evals);
    let host_evals = univariate_evals.sum_dim(1).to_host().unwrap();

    let [eval_zero, eval_half] = host_evals.as_slice().try_into().unwrap();

    let eval_one = claim - eval_zero;

    interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
        ],
        &[
            eval_zero,
            eval_one,
            eval_half * Felt::from_canonical_u16(4).inverse(),
        ],
    )
}

/// A simpler hadamard sumcheck. Avoids using the complex slop traits, and prioritizes a simple, readable implementation.
pub fn hadamard_sumcheck<C, F>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    mut challenger: C,
    initial_claim: Ext,
    base_ext_sum_as_poly_kernel: unsafe extern "C" fn() -> KernelPtr,
    base_ext_fix_and_sum_kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
    F: Field,
{
    let mut uni_polys = vec![];
    let initial_univariate =
        sum_in_last_variable::<F>(&base, &ext, initial_claim, base_ext_sum_as_poly_kernel);
    let coefficients = initial_univariate
        .coefficients
        .iter()
        .flat_map(|x| x.as_base_slice())
        .copied()
        .collect_vec();
    challenger.observe_slice(&coefficients);

    uni_polys.push(initial_univariate);

    let num_variables = base.num_variables();

    let alpha = challenger.sample_ext_element();

    let mut point = vec![alpha];

    // For the first round, use base-ext kernels.
    let round_claim = uni_polys
        .last()
        .unwrap()
        .eval_at_point(*point.first().unwrap());
    let (mut base, mut ext, uni_poly) = fix_last_variable_and_sum_as_poly(
        base,
        ext,
        alpha,
        round_claim,
        base_ext_fix_and_sum_kernel,
    );

    let coefficients = uni_poly
        .coefficients
        .iter()
        .flat_map(|x| x.as_base_slice())
        .copied()
        .collect_vec();

    challenger.observe_slice(&coefficients);

    uni_polys.push(uni_poly);

    let alpha: Ext = challenger.sample_ext_element();
    point.insert(0, alpha);

    // The multi-variate polynomial used at the start of each sumcheck round.
    for _ in 2..num_variables as usize {
        // Get the round claims from the last round's univariate poly messages.
        let round_claim = uni_polys
            .last()
            .unwrap()
            .eval_at_point(*point.first().unwrap());

        let uni_poly;
        (base, ext, uni_poly) = fix_last_variable_and_sum_as_poly(
            base,
            ext,
            *point.first().unwrap(),
            round_claim,
            padded_hadamard_fix_and_sum,
        );

        let coefficients = uni_poly
            .coefficients
            .iter()
            .flat_map(|x| x.as_base_slice())
            .copied()
            .collect_vec();

        challenger.observe_slice(&coefficients);

        uni_polys.push(uni_poly);

        let alpha: Ext = challenger.sample_ext_element();
        point.insert(0, alpha);
    }

    // Perform the final fix last variable operation to get the final base and extension evaluations.
    let (base, ext) = fix_last_variable(
        base,
        ext,
        *point.first().unwrap(),
        mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
    );

    let proof = PartialSumcheckProof {
        univariate_polys: uni_polys.clone(),
        claimed_sum: initial_claim,
        point_and_eval: (
            point.clone().into(),
            uni_polys
                .last()
                .unwrap()
                .eval_at_point(*point.first().unwrap()),
        ),
    };
    let base_eval_tensor = DeviceTensor::copy_to_host(base.guts()).unwrap();
    let base_eval = Ext::from_base(base_eval_tensor.as_slice()[0]);
    let ext_eval_tensor = DeviceTensor::copy_to_host(ext.guts()).unwrap();
    let ext_eval = ext_eval_tensor.as_slice()[0];
    (proof, vec![base_eval, ext_eval])
}

pub fn simple_hadamard_sumcheck<C, F>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    challenger: C,
    claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
    F: Field,
{
    if F::order() > BigUint::from(0x7f000001u32) {
        hadamard_sumcheck(
            base,
            ext,
            challenger,
            claim,
            hadamard_sum_as_poly_ext_ext_kernel,
            hadamard_fix_last_variable_and_sum_as_poly_ext_ext_kernel,
        )
    } else {
        hadamard_sumcheck(
            base,
            ext,
            challenger,
            claim,
            hadamard_sum_as_poly_base_ext_kernel,
            hadamard_fix_last_variable_and_sum_as_poly_base_ext_kernel,
        )
    }
}

fn sum_round_polynomials(polynomials: &[UnivariatePolynomial<Ext>]) -> UnivariatePolynomial<Ext> {
    let mut coefficients = vec![Ext::zero(); 3];
    for polynomial in polynomials {
        assert_eq!(polynomial.coefficients.len(), coefficients.len());
        for (sum, &coefficient) in coefficients.iter_mut().zip(&polynomial.coefficients) {
            *sum += coefficient;
        }
    }
    UnivariatePolynomial::new(coefficients)
}

fn observe_round_polynomial<C>(challenger: &mut C, polynomial: &UnivariatePolynomial<Ext>)
where
    C: FieldChallenger<Felt>,
{
    challenger.observe_slice(
        &polynomial
            .coefficients
            .iter()
            .flat_map(|value| value.as_base_slice())
            .copied()
            .collect_vec(),
    );
}

/// Proves a random-linear combination of multilinear evaluations at distinct
/// points without materializing a selector-expanded equality table.
///
/// Each trace is already scaled by its random-linear-combination coefficient.
/// `component_claims[i]` is the claimed sum of `traces[i] * eq(points[i], Â·)`.
pub fn multi_hadamard_sumcheck_at_points<C>(
    mut traces: Vec<Mle<Ext, TaskScope>>,
    equality_points: &[Point<Ext>],
    mut component_claims: Vec<Ext>,
    mut challenger: C,
    initial_claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
{
    assert!(!traces.is_empty());
    assert_eq!(traces.len(), equality_points.len());
    assert_eq!(traces.len(), component_claims.len());
    assert_eq!(component_claims.iter().copied().sum::<Ext>(), initial_claim);
    let num_variables = traces[0].num_variables() as usize;
    assert!(num_variables > 0);
    assert!(traces
        .iter()
        .all(|trace| trace.num_variables() as usize == num_variables));
    assert!(equality_points
        .iter()
        .all(|point| point.dimension() == num_variables));

    let scope = traces[0].backend().clone();
    let mut equalities: Vec<Mle<Ext, TaskScope>> = Vec::new();
    let mut univariate_polys = Vec::with_capacity(num_variables);
    let mut point = Vec::with_capacity(num_variables);

    for round in 0..num_variables {
        let component_polynomials = if round == 0 {
            traces
                .iter()
                .zip(equality_points)
                .zip(&component_claims)
                .map(|((trace, equality_point), &claim)| {
                    let device_point = DevicePoint::from_host(equality_point, &scope).unwrap();
                    let equality: Mle<Ext, TaskScope> = device_point.partial_lagrange().into();
                    sum_in_last_variable(
                        trace,
                        &equality,
                        claim,
                        hadamard_sum_as_poly_ext_ext_kernel,
                    )
                })
                .collect::<Vec<_>>()
        } else {
            traces
                .iter()
                .zip(&equalities)
                .zip(&component_claims)
                .map(|((trace, equality), &claim)| {
                    sum_in_last_variable(
                        trace,
                        equality,
                        claim,
                        hadamard_sum_as_poly_ext_ext_kernel,
                    )
                })
                .collect::<Vec<_>>()
        };
        let polynomial = sum_round_polynomials(&component_polynomials);
        observe_round_polynomial(&mut challenger, &polynomial);
        let alpha = challenger.sample_ext_element();
        point.insert(0, alpha);
        component_claims = component_polynomials
            .iter()
            .map(|component| component.eval_at_point(alpha))
            .collect();
        univariate_polys.push(polynomial);

        // Materialize round-zero equalities one at a time. The individual
        // polynomials, summed round polynomial and sampled alpha are unchanged.
        let mut current_equalities = equalities.into_iter();
        let mut next_traces = Vec::with_capacity(traces.len());
        let mut next_equalities = Vec::with_capacity(traces.len());
        for (index, trace) in traces.into_iter().enumerate() {
            let equality = if round == 0 {
                Mle::from(
                    DevicePoint::from_host(&equality_points[index], &scope)
                        .unwrap()
                        .partial_lagrange(),
                )
            } else {
                current_equalities.next().expect("one equality per trace")
            };
            let (trace, equality) = fix_last_variable(
                trace,
                equality,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            next_traces.push(trace);
            next_equalities.push(equality);
        }
        traces = next_traces;
        equalities = next_equalities;
    }

    let trace_evaluations = traces
        .iter()
        .map(|trace| DeviceTensor::copy_to_host(trace.guts()).unwrap().as_slice()[0])
        .collect();
    let terminal = component_claims.iter().copied().sum();
    (
        PartialSumcheckProof {
            univariate_polys,
            claimed_sum: initial_claim,
            point_and_eval: (point.into(), terminal),
        },
        trace_evaluations,
    )
}

/// One subset of an otherwise unchanged sumcheck. Only summed round
/// polynomials and sampled challenges cross the process boundary.
pub struct ComponentSumcheck {
    traces: Vec<Mle<Ext, TaskScope>>,
    points: Vec<Point<Ext>>,
    equalities: Vec<Mle<Ext, TaskScope>>,
    claims: Vec<Ext>,
    polynomials: Vec<UnivariatePolynomial<Ext>>,
    round: usize,
    variables: usize,
}

unsafe extern "C" {
    fn cudaDeviceGetDefaultMemPool(pool: *mut *mut std::ffi::c_void, device: i32) -> i32;
    fn cudaMemPoolGetAttribute(
        pool: *mut std::ffi::c_void,
        attribute: i32,
        value: *mut std::ffi::c_void,
    ) -> i32;
    fn cudaMemPoolTrimTo(pool: *mut std::ffi::c_void, minimum: usize) -> i32;
}
pub(crate) fn release_component_reservations(scope: &TaskScope, label: &str) {
    if std::env::var_os("CMFD_TRIM_COMPONENT_POOL").is_none() {
        return;
    }
    scope.synchronize_blocking().unwrap();
    let mut pool = std::ptr::null_mut();
    let mut reserved = 0u64;
    let mut used = 0u64;
    unsafe {
        assert_eq!(cudaDeviceGetDefaultMemPool(&mut pool, 0), 0);
        assert_eq!(
            cudaMemPoolGetAttribute(pool, 5, (&mut reserved as *mut u64).cast()),
            0
        );
        assert_eq!(
            cudaMemPoolGetAttribute(pool, 7, (&mut used as *mut u64).cast()),
            0
        );
        // CUDA only releases unused pages; every live model/trace stays owned.
        assert_eq!(cudaMemPoolTrimTo(pool, 0), 0);
    }
    if std::env::var_os("CMFD_COMPONENT_MEMORY_TRACE").is_some() {
        let (free, total) = sp1_gpu_cudart::cuda_memory_info().unwrap();
        eprintln!("component_memory stage={label} total_used_bytes={} pool_reserved_before={reserved} pool_live_bytes={used}",total-free);
    }
}

pub fn bounded_equality(point: &Point<Ext>, scope: &TaskScope) -> Mle<Ext, TaskScope> {
    let device = DevicePoint::from_host(point, scope).unwrap();
    let rows = 1usize << point.dimension();
    let mut output = DeviceTensor::<Ext>::with_sizes_in([1, rows], scope.clone());
    unsafe {
        output.assume_init();
        let arguments = args!(output.as_mut_ptr(), device.as_ptr(), point.dimension());
        scope
            .launch_kernel(
                sp1_gpu_sys::mle::partial_lagrange_koala_bear_extension(),
                rows.div_ceil(256).min(512),
                256usize,
                &arguments,
                0,
            )
            .unwrap();
    }
    scope.synchronize_blocking().unwrap();
    Mle::new(output.into_inner())
}

impl ComponentSumcheck {
    pub fn new(
        traces: Vec<Mle<Ext, TaskScope>>,
        points: Vec<Point<Ext>>,
        claims: Vec<Ext>,
    ) -> Self {
        assert!(!traces.is_empty());
        let variables = traces[0].num_variables() as usize;
        assert_eq!(traces.len(), points.len());
        assert_eq!(traces.len(), claims.len());
        assert!(traces
            .iter()
            .all(|trace| trace.num_variables() as usize == variables));
        assert!(points.iter().all(|point| point.dimension() == variables));
        Self {
            traces,
            points,
            claims,
            equalities: Vec::new(),
            polynomials: Vec::new(),
            round: 0,
            variables,
        }
    }
    pub fn polynomial(&mut self) -> UnivariatePolynomial<Ext> {
        assert!(self.round < self.variables && self.polynomials.is_empty());
        let scope = self.traces[0].backend().clone();
        self.polynomials = self
            .traces
            .iter()
            .enumerate()
            .map(|(index, trace)| {
                if self.round == 0 {
                    let equality = bounded_equality(&self.points[index], &scope);
                    let polynomial = sum_in_last_variable(
                        trace,
                        &equality,
                        self.claims[index],
                        hadamard_sum_as_poly_ext_ext_kernel,
                    );
                    drop(equality);
                    release_component_reservations(&scope, "initial-polynomial-released");
                    polynomial
                } else {
                    sum_in_last_variable(
                        trace,
                        &self.equalities[index],
                        self.claims[index],
                        hadamard_sum_as_poly_ext_ext_kernel,
                    )
                }
            })
            .collect();
        sum_round_polynomials(&self.polynomials)
    }
    pub fn fold(&mut self, alpha: Ext) {
        assert_eq!(self.polynomials.len(), self.traces.len());
        self.claims = self
            .polynomials
            .iter()
            .map(|poly| poly.eval_at_point(alpha))
            .collect();
        self.polynomials.clear();
        let scope = self.traces[0].backend().clone();
        if self.round == 0 {
            release_component_reservations(&scope, "before-first-fold");
        }
        let mut equalities = std::mem::take(&mut self.equalities).into_iter();
        let mut next_traces = Vec::new();
        let mut next_equalities = Vec::new();
        for (index, trace) in std::mem::take(&mut self.traces).into_iter().enumerate() {
            let next_trace = fix_last_variable_inner(
                &trace,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            drop(trace);
            if self.round == 0 {
                release_component_reservations(&scope, "trace-fold-released");
            }
            let next_equality = if self.round == 0 {
                // eq_r(x,alpha) = eq_r_without_last(x) * eq_r_last(alpha).
                // Construct the half-sized table directly after releasing the
                // old trace, rather than allocating the full equality first.
                let mut remaining = self.points[index].iter().copied().collect::<Vec<_>>();
                let last = remaining.pop().expect("nonempty equality point");
                let scale = Ext::one() - last + alpha * (last + last - Ext::one());
                let half = bounded_equality(&Point::from(remaining), &scope);
                let coefficient =
                    DeviceTensor::from_host(&Tensor::from(vec![scale]), &scope).unwrap();
                let count = half.guts().sizes()[1];
                let scaled = dot_along_dim_view(half.guts().as_view(), coefficient.as_view(), 0);
                let folded = Mle::new(scaled.reshape([1, count]));
                scope.synchronize_blocking().unwrap();
                drop(half);
                drop(coefficient);
                release_component_reservations(&scope, "folded-equality-ready");
                folded
            } else {
                let equality = equalities.next().expect("one equality per component");
                fix_last_variable_inner(
                    &equality,
                    alpha,
                    mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
                )
            };
            next_traces.push(next_trace);
            next_equalities.push(next_equality);
        }
        self.traces = next_traces;
        self.equalities = next_equalities;
        self.round += 1;
    }
}

pub fn add_round_polynomials(
    a: &UnivariatePolynomial<Ext>,
    b: &UnivariatePolynomial<Ext>,
) -> UnivariatePolynomial<Ext> {
    sum_round_polynomials(&[a.clone(), b.clone()])
}

pub fn observe_sumcheck_round<C: FieldChallenger<Felt>>(
    challenger: &mut C,
    poly: &UnivariatePolynomial<Ext>,
) {
    observe_round_polynomial(challenger, poly);
}

fn triple_interpolate_round(
    univariate_evals: Tensor<Ext, TaskScope>,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    let host_evals = DeviceTensor::from_raw(univariate_evals)
        .sum_dim(1)
        .to_host()
        .unwrap();
    let [eval_zero, eval_two, eval_three] = host_evals.as_slice().try_into().unwrap();
    let eval_one = claim - eval_zero;
    interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2),
            Ext::from_canonical_u16(3),
        ],
        &[eval_zero, eval_one, eval_two, eval_three],
    )
}

fn triple_sum_as_poly(
    first: &Mle<Ext, TaskScope>,
    second: &Mle<Ext, TaskScope>,
    third: &Mle<Ext, TaskScope>,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    assert_eq!(first.guts().sizes(), second.guts().sizes());
    assert_eq!(first.guts().sizes(), third.guts().sizes());
    let num_variables = first.num_variables() as usize;
    let height = 1usize << (num_variables - 1);
    const BLOCK_SIZE: usize = 256;
    let grid_size = height.div_ceil(BLOCK_SIZE);
    let mut evaluations =
        Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_size], first.backend().clone());
    let shared_mem = BLOCK_SIZE.checked_div(32).unwrap_or(1) * std::mem::size_of::<Ext>();
    unsafe {
        let args = args!(
            evaluations.as_mut_ptr(),
            first.guts().as_ptr(),
            second.guts().as_ptr(),
            third.guts().as_ptr(),
            num_variables - 1
        );
        evaluations.assume_init();
        first
            .backend()
            .launch_kernel(
                triple_hadamard_sum_as_poly_ext_kernel(),
                grid_size,
                BLOCK_SIZE,
                &args,
                shared_mem,
            )
            .unwrap();
    }
    triple_interpolate_round(evaluations, claim)
}

fn triple_fix_and_sum_as_poly(
    first: Mle<Ext, TaskScope>,
    second: Mle<Ext, TaskScope>,
    third: Mle<Ext, TaskScope>,
    alpha: Ext,
    claim: Ext,
) -> (
    Mle<Ext, TaskScope>,
    Mle<Ext, TaskScope>,
    Mle<Ext, TaskScope>,
    UnivariatePolynomial<Ext>,
) {
    assert_eq!(first.guts().sizes(), second.guts().sizes());
    assert_eq!(first.guts().sizes(), third.guts().sizes());
    let input_height = first.guts().sizes()[1];
    let output_height = input_height >> 1;
    let backend = first.backend();
    let mut first_output = backend.uninit_mle(1, output_height);
    let mut second_output = backend.uninit_mle(1, output_height);
    let mut third_output = backend.uninit_mle(1, output_height);
    const BLOCK_SIZE: usize = 256;
    let grid_size = output_height.div_ceil(BLOCK_SIZE);
    let mut evaluations = Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_size], backend.clone());
    let shared_mem = BLOCK_SIZE.checked_div(32).unwrap_or(1) * std::mem::size_of::<Ext>();
    unsafe {
        let args = args!(
            first.guts().as_ptr(),
            second.guts().as_ptr(),
            third.guts().as_ptr(),
            first_output.as_mut_ptr(),
            second_output.as_mut_ptr(),
            third_output.as_mut_ptr(),
            alpha,
            evaluations.as_mut_ptr(),
            input_height
        );
        first_output.assume_init();
        second_output.assume_init();
        third_output.assume_init();
        evaluations.assume_init();
        backend
            .launch_kernel(
                triple_hadamard_fix_last_variable_and_sum_as_poly_ext_kernel(),
                grid_size,
                BLOCK_SIZE,
                &args,
                shared_mem,
            )
            .unwrap();
    }
    (
        Mle::new(first_output),
        Mle::new(second_output),
        Mle::new(third_output),
        triple_interpolate_round(evaluations, claim),
    )
}

/// Proves a sum of pointwise products of three extension-field multilinears.
pub fn triple_hadamard_sumcheck<C>(
    mut first: Mle<Ext, TaskScope>,
    mut second: Mle<Ext, TaskScope>,
    mut third: Mle<Ext, TaskScope>,
    mut challenger: C,
    initial_claim: Ext,
) -> (PartialSumcheckProof<Ext>, [Ext; 3])
where
    C: FieldChallenger<Felt>,
{
    assert_eq!(first.guts().sizes(), second.guts().sizes());
    assert_eq!(first.guts().sizes(), third.guts().sizes());
    let num_variables = first.num_variables() as usize;
    assert!(num_variables > 0);
    let mut univariate_polys = Vec::with_capacity(num_variables);
    univariate_polys.push(triple_sum_as_poly(&first, &second, &third, initial_claim));
    let mut point = Vec::with_capacity(num_variables);

    loop {
        let polynomial = univariate_polys.last().unwrap();
        challenger.observe_slice(
            &polynomial
                .coefficients
                .iter()
                .flat_map(|value| value.as_base_slice())
                .copied()
                .collect_vec(),
        );
        let alpha = challenger.sample_ext_element();
        point.insert(0, alpha);
        let next_claim = polynomial.eval_at_point(alpha);
        if univariate_polys.len() == num_variables {
            first = fix_last_variable_inner(
                &first,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            second = fix_last_variable_inner(
                &second,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            third = fix_last_variable_inner(
                &third,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            let endpoints = [
                DeviceTensor::copy_to_host(first.guts()).unwrap().as_slice()[0],
                DeviceTensor::copy_to_host(second.guts())
                    .unwrap()
                    .as_slice()[0],
                DeviceTensor::copy_to_host(third.guts()).unwrap().as_slice()[0],
            ];
            return (
                PartialSumcheckProof {
                    univariate_polys,
                    claimed_sum: initial_claim,
                    point_and_eval: (point.into(), next_claim),
                },
                endpoints,
            );
        }
        let (next_first, next_second, next_third, next_polynomial) =
            triple_fix_and_sum_as_poly(first, second, third, alpha, next_claim);
        first = next_first;
        second = next_second;
        third = next_third;
        univariate_polys.push(next_polynomial);
    }
}

fn cubic_transition_interpolate_round(
    univariate_evals: Tensor<Ext, TaskScope>,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    let host_evals = DeviceTensor::from_raw(univariate_evals)
        .sum_dim(1)
        .to_host()
        .unwrap();
    let [eval_zero, eval_two, eval_three, eval_four] = host_evals.as_slice().try_into().unwrap();
    let eval_one = claim - eval_zero;
    interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2),
            Ext::from_canonical_u16(3),
            Ext::from_canonical_u16(4),
        ],
        &[eval_zero, eval_one, eval_two, eval_three, eval_four],
    )
}

fn cubic_transition_sum_as_poly(
    preactivation: &Mle<Ext, TaskScope>,
    next_activation: &Mle<Ext, TaskScope>,
    equality: &Mle<Ext, TaskScope>,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    assert_eq!(preactivation.guts().sizes(), next_activation.guts().sizes());
    assert_eq!(preactivation.guts().sizes(), equality.guts().sizes());
    let num_variables = preactivation.num_variables() as usize;
    let height = 1usize << (num_variables - 1);
    const BLOCK_SIZE: usize = 256;
    let grid_size = height.div_ceil(BLOCK_SIZE);
    let mut evaluations =
        Tensor::<Ext, TaskScope>::with_sizes_in([4, grid_size], preactivation.backend().clone());
    let shared_mem = BLOCK_SIZE.checked_div(32).unwrap_or(1) * std::mem::size_of::<Ext>();
    unsafe {
        let args = args!(
            evaluations.as_mut_ptr(),
            preactivation.guts().as_ptr(),
            next_activation.guts().as_ptr(),
            equality.guts().as_ptr(),
            num_variables - 1
        );
        evaluations.assume_init();
        preactivation
            .backend()
            .launch_kernel(
                cubic_transition_sum_as_poly_ext_kernel(),
                grid_size,
                BLOCK_SIZE,
                &args,
                shared_mem,
            )
            .unwrap();
    }
    cubic_transition_interpolate_round(evaluations, claim)
}

fn cubic_transition_fix_and_sum_as_poly(
    preactivation: Mle<Ext, TaskScope>,
    next_activation: Mle<Ext, TaskScope>,
    equality: Mle<Ext, TaskScope>,
    alpha: Ext,
    claim: Ext,
) -> (
    Mle<Ext, TaskScope>,
    Mle<Ext, TaskScope>,
    Mle<Ext, TaskScope>,
    UnivariatePolynomial<Ext>,
) {
    assert_eq!(preactivation.guts().sizes(), next_activation.guts().sizes());
    assert_eq!(preactivation.guts().sizes(), equality.guts().sizes());
    let input_height = preactivation.guts().sizes()[1];
    let output_height = input_height >> 1;
    let backend = preactivation.backend();
    let mut preactivation_output = backend.uninit_mle(1, output_height);
    let mut next_activation_output = backend.uninit_mle(1, output_height);
    let mut equality_output = backend.uninit_mle(1, output_height);
    const BLOCK_SIZE: usize = 256;
    let grid_size = output_height.div_ceil(BLOCK_SIZE);
    let mut evaluations = Tensor::<Ext, TaskScope>::with_sizes_in([4, grid_size], backend.clone());
    let shared_mem = BLOCK_SIZE.checked_div(32).unwrap_or(1) * std::mem::size_of::<Ext>();
    unsafe {
        let args = args!(
            preactivation.guts().as_ptr(),
            next_activation.guts().as_ptr(),
            equality.guts().as_ptr(),
            preactivation_output.as_mut_ptr(),
            next_activation_output.as_mut_ptr(),
            equality_output.as_mut_ptr(),
            alpha,
            evaluations.as_mut_ptr(),
            input_height
        );
        preactivation_output.assume_init();
        next_activation_output.assume_init();
        equality_output.assume_init();
        evaluations.assume_init();
        backend
            .launch_kernel(
                cubic_transition_fix_last_variable_and_sum_as_poly_ext_kernel(),
                grid_size,
                BLOCK_SIZE,
                &args,
                shared_mem,
            )
            .unwrap();
    }
    (
        Mle::new(preactivation_output),
        Mle::new(next_activation_output),
        Mle::new(equality_output),
        cubic_transition_interpolate_round(evaluations, claim),
    )
}

/// Proves `sum equality * (next_activation - preactivation^3)`.
pub fn cubic_transition_sumcheck<C>(
    mut preactivation: Mle<Ext, TaskScope>,
    mut next_activation: Mle<Ext, TaskScope>,
    mut equality: Mle<Ext, TaskScope>,
    mut challenger: C,
    initial_claim: Ext,
) -> (PartialSumcheckProof<Ext>, [Ext; 3])
where
    C: FieldChallenger<Felt>,
{
    assert_eq!(preactivation.guts().sizes(), next_activation.guts().sizes());
    assert_eq!(preactivation.guts().sizes(), equality.guts().sizes());
    let num_variables = preactivation.num_variables() as usize;
    assert!(num_variables > 0);
    let mut univariate_polys = Vec::with_capacity(num_variables);
    univariate_polys.push(cubic_transition_sum_as_poly(
        &preactivation,
        &next_activation,
        &equality,
        initial_claim,
    ));
    let mut point = Vec::with_capacity(num_variables);

    loop {
        let polynomial = univariate_polys.last().unwrap();
        observe_round_polynomial(&mut challenger, polynomial);
        let alpha = challenger.sample_ext_element();
        point.insert(0, alpha);
        let next_claim = polynomial.eval_at_point(alpha);
        if univariate_polys.len() == num_variables {
            preactivation = fix_last_variable_inner(
                &preactivation,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            next_activation = fix_last_variable_inner(
                &next_activation,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            equality = fix_last_variable_inner(
                &equality,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            let endpoints = [
                DeviceTensor::copy_to_host(preactivation.guts())
                    .unwrap()
                    .as_slice()[0],
                DeviceTensor::copy_to_host(next_activation.guts())
                    .unwrap()
                    .as_slice()[0],
                DeviceTensor::copy_to_host(equality.guts())
                    .unwrap()
                    .as_slice()[0],
            ];
            return (
                PartialSumcheckProof {
                    univariate_polys,
                    claimed_sum: initial_claim,
                    point_and_eval: (point.into(), next_claim),
                },
                endpoints,
            );
        }
        if univariate_polys.len() == 1 {
            // Fold and release the large first-round inputs individually.
            // The next polynomial is identical to the fused kernel's result.
            let scope = preactivation.backend().clone();
            preactivation = fix_last_variable_inner(
                &preactivation,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            scope.synchronize_blocking().unwrap();
            next_activation = fix_last_variable_inner(
                &next_activation,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            scope.synchronize_blocking().unwrap();
            equality = fix_last_variable_inner(
                &equality,
                alpha,
                mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            scope.synchronize_blocking().unwrap();
            univariate_polys.push(cubic_transition_sum_as_poly(
                &preactivation,
                &next_activation,
                &equality,
                next_claim,
            ));
            continue;
        }
        let (next_preactivation, next_activation_value, next_equality, next_polynomial) =
            cubic_transition_fix_and_sum_as_poly(
                preactivation,
                next_activation,
                equality,
                alpha,
                next_claim,
            );
        preactivation = next_preactivation;
        next_activation = next_activation_value;
        equality = next_equality;
        univariate_polys.push(next_polynomial);
    }
}
