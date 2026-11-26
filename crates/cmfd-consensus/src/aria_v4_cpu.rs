//! ProductionV4 forward pass on the CPU using an integer AVX-512 VNNI kernel.
//! Original CPU verifier and replay kernel by Stefan and AriaPool. Common Foundry contributed the subsequent optimizations.
//!
//! Same computation as `forward` (identical result, everything is integer and exact), with a different arithmetic:
//! * each activation (< p < 2^31) is written as 4 signed base-256 digits (in [-128, 127]),
//! * the weights stay unsigned bytes and `vpdpbusd` does 64 byte x digit products per instruction,
//! * the model is packed once into tiles of 32 columns, 4 interleaved rows, so that it is read sequentially.
//! Sums: 4096 products of absolute value <= 250 x 128 per digit, so below 2^27: no i32 overflow.
//! Production shape only (128 x 4096, 384 layers). Without AVX-512 VNNI, `AriaPackedBank::supported()` is false
//! and the caller keeps the original engine.
use std::sync::{Barrier, OnceLock};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use super::{
    CENTER, ForgeMatrixV4ExecutionError, ForgeMatrixV4ExecutionShape, ForgeMatrixV4LayerSource,
    Mask, initial_activation,
};

const SHAPE: ForgeMatrixV4ExecutionShape = ForgeMatrixV4ExecutionShape::PRODUCTION;
const B: usize = 128;
const D: usize = 4096;
const TILE: usize = 32;
const TILES: usize = D / TILE;
const K4: usize = D / 4;
/// One tile: for each group of 4 rows k, 32 columns x 4 bytes.
const TILE_BYTES: usize = K4 * TILE * 4;
const LAYER_BYTES: usize = D * D;
/// Digits of one activation row: for each group of 4 columns k, 4 digits x 4 bytes.
const ROW_BYTES: usize = K4 * 16;

const _: () = assert!(SHAPE.batch == B && SHAPE.dimension == D);
const _: () = assert!(TILES * TILE_BYTES == LAYER_BYTES);

/// The model packed for the integer kernel, and its base input.
pub struct AriaPackedBank {
    base_input: Vec<u8>,
    layers: Vec<u8>,
    layer_count: usize,
}

impl std::fmt::Debug for AriaPackedBank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AriaPackedBank")
            .field("layers", &self.layer_count)
            .finish()
    }
}

struct Shared<T>(T);
// SAFETY: the shared pointers refer to buffers that live for the whole `thread::scope`. Each thread only
// writes the bytes of the tiles it claimed (disjoint ranges) and only reads the current buffer, which nobody
// writes during the layer. The barrier separates the layers.
unsafe impl<T> Sync for Shared<T> {}

impl AriaPackedBank {
    /// True if this CPU has the instructions the kernel needs.
    pub fn supported() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512bw")
                && std::arch::is_x86_feature_detected!("avx512vnni")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    /// Packs the model from `source` (production shape) for the integer kernel. It takes about the size of the model in memory.
    pub fn build(
        source: &dyn ForgeMatrixV4LayerSource,
        threads: usize,
    ) -> Result<Self, ForgeMatrixV4ExecutionError> {
        if !Self::supported() || source.shape() != SHAPE {
            return Err(ForgeMatrixV4ExecutionError::Shape);
        }
        let layer_count = SHAPE.layers;
        let mut layers = vec![0_u8; layer_count * LAYER_BYTES];
        let work = std::sync::Mutex::new(layers.chunks_exact_mut(LAYER_BYTES).enumerate());
        let failed = std::sync::Mutex::new(None);
        std::thread::scope(|scope| {
            for _ in 0..threads.clamp(1, 16) {
                scope.spawn(|| {
                    let mut raw = vec![0_u8; LAYER_BYTES];
                    loop {
                        let Some((layer, out)) = work
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .next()
                        else {
                            break;
                        };
                        if let Err(error) = source.read_layer(layer, &mut raw, true) {
                            *failed
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                            break;
                        }
                        // out[tile][k4][c][b] = weight[k4 * 4 + b][tile * 64 + c]
                        for (k, row) in raw.chunks_exact(D).enumerate() {
                            let (k4, b) = (k / 4, k % 4);
                            for (tile, columns) in row.chunks_exact(TILE).enumerate() {
                                let at = tile * TILE_BYTES + k4 * TILE * 4 + b;
                                for (c, &byte) in columns.iter().enumerate() {
                                    out[at + c * 4] = byte;
                                }
                            }
                        }
                    }
                });
            }
        });
        drop(work);
        if let Some(error) = failed
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return Err(error);
        }
        Ok(Self {
            base_input: source.base_input().to_vec(),
            layers,
            layer_count,
        })
    }

    /// The forward pass for one set of mask coefficients (like `forgematrix_v4_execute`):
    /// the final activation as canonical values, row by row.
    pub fn execute(
        &self,
        coefficients: &[u8],
        threads: usize,
    ) -> Result<Vec<u32>, ForgeMatrixV4ExecutionError> {
        self.run(coefficients, threads, None, None)
    }

    /// Run the share kernel with a placement hook on each newly spawned worker thread.
    pub fn execute_with_thread_setup(
        &self, coefficients: &[u8], threads: usize,
        setup: &(dyn Fn() -> std::io::Result<()> + Sync),
    ) -> Result<Vec<u32>, ForgeMatrixV4ExecutionError> {
        self.run(coefficients, threads, None, Some(setup))
    }

    /// The initial activation (before the first layer), as canonical values, row by row.
    pub fn initial(&self, coefficients: &[u8]) -> Result<Vec<u32>, ForgeMatrixV4ExecutionError> {
        if coefficients.len() != SHAPE.coefficient_bytes() {
            return Err(ForgeMatrixV4ExecutionError::InputLength);
        }
        Ok(initial_activation(SHAPE, &self.base_input, &coefficients[..SHAPE.mask_coefficients()]))
    }

    /// Like `execute`, and fills the full trace as canonical values: `pre[layer][row][column]`
    /// (value before the cube) and `act[layer][row][column]` (activation after the layer),
    /// each of `layers x 128 x 4096` values. This is the witness the prover needs.
    pub fn execute_traced(
        &self,
        coefficients: &[u8],
        threads: usize,
        pre: &mut [u32],
        act: &mut [u32],
    ) -> Result<Vec<u32>, ForgeMatrixV4ExecutionError> {
        let values = self.layer_count * SHAPE.cells();
        if pre.len() != values || act.len() != values {
            return Err(ForgeMatrixV4ExecutionError::InputLength);
        }
        self.run(coefficients, threads, Some((pre.as_mut_ptr(), act.as_mut_ptr())), None)
    }

    fn run(
        &self,
        coefficients: &[u8],
        threads: usize,
        trace: Option<(*mut u32, *mut u32)>,
        setup: Option<&(dyn Fn() -> std::io::Result<()> + Sync)>,
    ) -> Result<Vec<u32>, ForgeMatrixV4ExecutionError> {
        if coefficients.len() != SHAPE.coefficient_bytes() || self.base_input.len() != SHAPE.cells()
        {
            return Err(ForgeMatrixV4ExecutionError::InputLength);
        }
        if threads == 0 {
            return Err(ForgeMatrixV4ExecutionError::ThreadCount);
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(ForgeMatrixV4ExecutionError::Shape)
        }
        #[cfg(target_arch = "x86_64")]
        {
            let threads = threads.min(TILES);
            let terms = SHAPE.mask_coefficients();
            let (initial, layer_coefficients) = coefficients.split_at(terms);
            let start = initial_activation(SHAPE, &self.base_input, initial);
            let mut even = vec![0_u8; B * ROW_BYTES];
            let mut odd = vec![0_u8; B * ROW_BYTES];
            let row_sums = (0..(self.layer_count + 1) * B)
                .map(|_| AtomicI64::new(0))
                .collect::<Vec<_>>();
            for (row, values) in start.chunks_exact(D).enumerate() {
                let mut sum = 0_i64;
                for (column, &value) in values.iter().enumerate() {
                    sum += i64::from(value);
                    // SAFETY: the indices are inside `even` (row < B, column < D).
                    unsafe { write_digits(even.as_mut_ptr(), row, column, value) };
                }
                row_sums[row].store(sum, Ordering::Relaxed);
            }
            let next_tile = (0..self.layer_count)
                .map(|_| AtomicUsize::new(0))
                .collect::<Vec<_>>();
            // Set after the spawns: the barrier counts the threads that really started.
            let gate = OnceLock::<Barrier>::new();
            let buffers = Shared([even.as_mut_ptr(), odd.as_mut_ptr()]);
            let trace = Shared(trace);
            let masks: Vec<_> = layer_coefficients.chunks_exact(terms)
                .map(|coefficients| Mask::new(SHAPE, coefficients)).collect();
            let masks = &masks;
            let setup_error = std::sync::Mutex::new(None);
            let mut spawn_error = None;
            std::thread::scope(|scope| {
                let (buffers, row_sums, next_tile, gate, trace) =
                    (&buffers, &row_sums, &next_tile, &gate, &trace);
                let setup_error = &setup_error;
                let mut started = 0;
                for _ in 0..threads {
                    let spawned = std::thread::Builder::new().spawn_scoped(scope, move || {
                        let barrier = gate.wait();
                        if let Some(setup) = setup {
                            if let Err(error) = setup() {
                                *setup_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                            }
                            barrier.wait();
                            if setup_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_some() { return; }
                        }
                        for layer in 0..self.layer_count {
                            let mask = &masks[layer];
                            let mut row_offsets = [0_i64; B];
                            for (row, offset) in row_offsets.iter_mut().enumerate() {
                                *offset = mask.row[row]
                                    - CENTER * row_sums[layer * B + row].load(Ordering::Relaxed);
                            }
                            let mut partial = [0_i64; B];
                            let weights = &self.layers[layer * LAYER_BYTES..][..LAYER_BYTES];
                            let (current, next) = (buffers.0[layer % 2], buffers.0[(layer + 1) % 2]);
                            // SAFETY: the trace buffers hold layers x cells values (checked by the caller).
                            let layer_trace = trace.0.map(|(pre, act)| unsafe {
                                (pre.add(layer * SHAPE.cells()), act.add(layer * SHAPE.cells()))
                            });
                            loop {
                                let tile = next_tile[layer].fetch_add(1, Ordering::Relaxed);
                                if tile >= TILES {
                                    break;
                                }
                                // SAFETY: the instructions were checked by `supported()` in `build`. The tile is
                                // inside `weights`. `current` and `next` are B * ROW_BYTES bytes long. Only this
                                // task writes the columns of this tile in `next`.
                                unsafe {
                                    tile_kernel(
                                        weights.as_ptr().add(tile * TILE_BYTES),
                                        current,
                                        next,
                                        tile,
                                        &row_offsets,
                                        &mask.column[tile * TILE..(tile + 1) * TILE],
                                        &mut partial,
                                        layer_trace,
                                    );
                                }
                            }
                            for (row, sum) in partial.iter().enumerate() {
                                row_sums[(layer + 1) * B + row].fetch_add(*sum, Ordering::Relaxed);
                            }
                            barrier.wait();
                        }
                    });
                    match spawned {
                        Ok(_) => started += 1,
                        Err(error) => {
                            spawn_error = Some(error);
                            break;
                        }
                    }
                }
                // Tiles are claimed on demand: fewer threads than requested give the same result.
                let _ = gate.set(Barrier::new(started));
                if started > 0 {
                    spawn_error = None;
                }
            });
            if let Some(error) = setup_error.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner) {
                return Err(ForgeMatrixV4ExecutionError::ThreadSetup(error));
            }
            if let Some(error) = spawn_error {
                return Err(ForgeMatrixV4ExecutionError::ThreadSpawn(error));
            }
            let last = if self.layer_count % 2 == 0 { &even } else { &odd };
            let mut out = vec![0_u32; SHAPE.cells()];
            for (index, out) in out.iter_mut().enumerate() {
                let (row, column) = (index / D, index % D);
                let at = row * ROW_BYTES + (column / 4) * 16 + column % 4;
                let digit = |l: usize| i64::from(last[at + l * 4] as i8);
                *out = (digit(0) + (digit(1) << 8) + (digit(2) << 16) + (digit(3) << 24)) as u32;
            }
            Ok(out)
        }
    }
}

/// Writes the 4 signed base-256 digits of `value` (< p) for (`row`, `column`).
#[inline(always)]
unsafe fn write_digits(digits: *mut u8, row: usize, column: usize, value: u32) {
    let at = row * ROW_BYTES + (column / 4) * 16 + column % 4;
    let mut x = value as i32;
    for l in 0..3 {
        let digit = x as i8;
        // SAFETY: guaranteed by the caller.
        unsafe { *digits.add(at + l * 4) = digit as u8 };
        x = (x - i32::from(digit)) >> 8;
    }
    // x <= 127 because value <= 0x7f00_0000.
    unsafe { *digits.add(at + 12) = x as u8 };
}

/// Three activation rows share a pair of packed weight vectors in the inner loop.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw,avx512vnni")]
unsafe fn tile_kernel(
    weights: *const u8, current: *const u8, next: *mut u8, tile: usize,
    row_offsets: &[i64; B], column: &[i64], partial: &mut [i64; B],
    trace: Option<(*mut u32, *mut u32)>,
) {
    const FULL_ROWS: usize = B / 3 * 3;
    unsafe {
        for first in (0..FULL_ROWS).step_by(3) {
            row_kernel::<3>(weights, current, next, tile, first, row_offsets, column, partial, trace);
        }
        row_kernel::<2>(weights, current, next, tile, FULL_ROWS, row_offsets, column, partial, trace);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw,avx512vnni")]
unsafe fn row_kernel<const N: usize>(
    weights: *const u8, current: *const u8, next: *mut u8, tile: usize, first: usize,
    row_offsets: &[i64; B], column: &[i64], partial: &mut [i64; B],
    trace: Option<(*mut u32, *mut u32)>,
) {
    use std::arch::x86_64::*;
    const _: () = assert!(TILE == 32 && B % 3 == 2);
    unsafe {
        let zero = _mm512_setzero_si512();
        let mut accum = [[[zero; 2]; 4]; N];
        for k in 0..K4 {
            let w = weights.add(k * TILE * 4);
            let left = _mm512_loadu_si512(w.cast());
            let right = _mm512_loadu_si512(w.add(64).cast());
            macro_rules! add_row {
                ($r:expr) => {{
                    let digit_ptr = current.add((first+$r)*ROW_BYTES + 16*k).cast::<i32>();
                    for digit in 0..4 {
                        let value = _mm512_set1_epi32(digit_ptr.add(digit).read_unaligned());
                        accum[$r][digit][0] = _mm512_dpbusd_epi32(accum[$r][digit][0],left,value);
                        accum[$r][digit][1] = _mm512_dpbusd_epi32(accum[$r][digit][1],right,value);
                    }
                }}
            }
            add_row!(0);
            add_row!(1);
            if N == 3 { add_row!(2); }
        }
        let bias = _mm512_set1_epi32(0x0080_8080);
        let shuffle = _mm512_broadcast_i32x4(_mm_setr_epi8(0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15));
        for (r, vectors) in accum.into_iter().enumerate() {
            let row = first+r;
            let sums: [[i32; TILE]; 4] = std::mem::transmute(vectors);
            let mut pre = [0u32; TILE];
            let mut output = [0u32; TILE];
            let mut row_sum = 0i64;
            for i in 0..TILE {
                let product = i64::from(sums[0][i]) + (i64::from(sums[1][i]) << 8)
                    + (i64::from(sums[2][i]) << 16) + (i64::from(sums[3][i]) << 24);
                let x = (product + row_offsets[row] + column[i]).rem_euclid(super::MODULUS as i64) as u64;
                let y = ((x * x % super::MODULUS) * x % super::MODULUS) as u32;
                pre[i] = x as u32;
                output[i] = y;
                row_sum += i64::from(y);
            }
            partial[row] += row_sum;
            for i in (0..TILE).step_by(16) {
                let v = _mm512_loadu_si512(output.as_ptr().add(i).cast());
                // The bias propagates signed-digit carries before the four-by-four byte transpose.
                let digits = _mm512_xor_si512(_mm512_add_epi32(v, bias), bias);
                let dst = next.add(row * ROW_BYTES + (tile * TILE + i) * 4);
                _mm512_storeu_si512(dst.cast(), _mm512_shuffle_epi8(digits, shuffle));
            }
            if let Some((pre_ptr, act_ptr)) = trace {
                let offset = row * D + tile * TILE;
                std::ptr::copy_nonoverlapping(pre.as_ptr(), pre_ptr.add(offset), TILE);
                std::ptr::copy_nonoverlapping(output.as_ptr(), act_ptr.add(offset), TILE);
            }
        }
    }
}
