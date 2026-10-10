// Fused layer kernel: GEMM + limb-recombine + mask + cube + int8 pack in one
// launch, bit-exact with the official two-kernel path. dp4a implementation
// (portable SM70+). Mapping:
//   grid = (rows/16, width/64, batch_size), 256 threads per block
//   thread t: row t/16 (16 row owners), cols (t%16)*4 (4 cols)
//   16 rows x 64 cols output tile per block, per lane.
// Limb planes: [lane][plane][row][col], plane stride = cells (row-major within
// plane) — identical to the official initialize_activation_batch layout.
// Weights: column-major [layer][col][k] (the bank is transposed at load).
// Coefficients: official layout coefficients[(lane*stride + layer+1) * 20].
// The row_sums pointer may be null (official -width/2 fallback semantics).
#include "layer_fused.cuh"
#include <cuda_runtime.h>

namespace cmfd_v4_replay {

constexpr uint32_t K_TILE = 64;
constexpr uint32_t TILE_ROWS = 16;
constexpr uint32_t TILE_COLS = 64;
constexpr uint32_t THREADS = 256;

__device__ __forceinline__ uint32_t canon(int64_t v) {
    int64_t r = v % static_cast<int64_t>(FUSED_MODULUS);
    if (r < 0) r += static_cast<int64_t>(FUSED_MODULUS);
    return static_cast<uint32_t>(r);
}

__device__ __forceinline__ uint32_t fmul(uint32_t l, uint32_t r) {
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(l) * r) % FUSED_MODULUS);
}

__device__ __forceinline__ uint32_t fcube(uint32_t v) {
    return fmul(fmul(v, v), v);
}

__device__ __forceinline__ uint32_t fmask(const uint32_t* c, uint32_t row,
                                          uint32_t col, uint32_t row_bits,
                                          uint32_t col_bits) {
    uint64_t m = c[0];
    for (uint32_t b = 0; b < row_bits; ++b)
        if (((row >> b) & 1U) != 0) m += c[1 + b];
    for (uint32_t b = 0; b < col_bits; ++b)
        if (((col >> b) & 1U) != 0) m += c[1 + row_bits + b];
    return static_cast<uint32_t>(m % FUSED_MODULUS);
}

__global__ __launch_bounds__(THREADS) void layer_fused(
    const int8_t* __restrict__ limbs_in, const int8_t* __restrict__ weights,
    int8_t* __restrict__ limbs_out, uint32_t* __restrict__ preactivations,
    uint32_t* __restrict__ activations, const uint32_t* __restrict__ coefficients,
    const int32_t* __restrict__ weight_row_sums, uint32_t layer,
    uint32_t layer_stride, uint32_t rows, uint32_t width,
    uint32_t batch_size) {
    const uint32_t lane = blockIdx.z;
    const uint32_t row_tile = blockIdx.x;
    const uint32_t col_tile = blockIdx.y;
    const uint32_t cells = rows * width;
    const size_t lane_off = size_t(lane) * 4 * cells;

    const uint32_t row0 = row_tile * TILE_ROWS;
    const uint32_t col0 = col_tile * TILE_COLS;

    const uint32_t tid = threadIdx.x;
    const uint32_t trow = tid / 16;        // 16 row owners
    const uint32_t tcol = (tid % 16) * 4;  // 4 cols per thread

    const int8_t* lane_in = limbs_in + lane_off;
    int8_t* lane_out = limbs_out + lane_off;

    // 64x80 (rows padded to 16B so the int4 tile store stays aligned)
    __shared__ int8_t wt[TILE_COLS][K_TILE + 16];

    int32_t acc[4][4] = {};  // [col][plane]

    const uint32_t row_bits = __ffs(static_cast<int>(rows)) - 1;
    const uint32_t column_bits = __ffs(static_cast<int>(width)) - 1;
    const uint32_t* lane_coeffs =
        coefficients + (size_t(lane) * layer_stride + size_t(layer + 1)) * 20;

    for (uint32_t k0 = 0; k0 < width; k0 += K_TILE) {
        // Load W tile: 64 cols x 64 k = 4096 B = 256 int4 loads.
        {
            const int4* src = reinterpret_cast<const int4*>(
                weights + size_t(col0) * width + k0);
            const uint32_t idx = tid;        // 0..255
            const uint32_t col = idx / 4;    // 0..63
            const uint32_t kquad = idx % 4;  // int4 index: k = kquad*16
            const int4 value = src[size_t(col) * (width / 16) + kquad];
            reinterpret_cast<int4*>(&wt[col][0])[kquad] = value;
        }
        __syncthreads();

#pragma unroll
        for (uint32_t kk = 0; kk < K_TILE; kk += 4) {
            const uint32_t gr = row0 + trow;
            int32_t a[4];
#pragma unroll
            for (uint32_t plane = 0; plane < 4; ++plane) {
                a[plane] = *reinterpret_cast<const int32_t*>(
                    lane_in + size_t(plane) * cells + size_t(gr) * width +
                    k0 + kk);
            }
#pragma unroll
            for (uint32_t c = 0; c < 4; ++c) {
                const int32_t w4 =
                    *reinterpret_cast<const int32_t*>(&wt[tcol + c][kk]);
#pragma unroll
                for (uint32_t plane = 0; plane < 4; ++plane) {
                    acc[c][plane] = __dp4a(a[plane], w4, acc[c][plane]);
                }
            }
        }
        __syncthreads();
    }

    // Epilogue: exact recombine + center + mask + cube + pack.
    {
        const uint32_t gr = row0 + trow;
#pragma unroll
        for (uint32_t c = 0; c < 4; ++c) {
            const uint32_t gc = col0 + tcol + c;
            const int32_t* accv = acc[c];
            const int64_t dot =
                int64_t(accv[0]) + 256LL * int64_t(accv[1]) +
                65'536LL * int64_t(accv[2]) +
                16'777'216LL * int64_t(accv[3]) +
                FUSED_CENTER *
                    int64_t(weight_row_sums == nullptr
                                ? -int64_t(width / 2)
                                : weight_row_sums[gc]);
            const uint32_t accumulator = canon(dot);
            const uint32_t mask = fmask(lane_coeffs, gr, gc, row_bits,
                                        column_bits);
            uint32_t value = accumulator + mask;
            if (value >= FUSED_MODULUS) value -= FUSED_MODULUS;
            preactivations[size_t(lane) * cells + size_t(gr) * width + gc] =
                value;
            value = fcube(value);
            activations[size_t(lane) * cells + size_t(gr) * width + gc] = value;
            int8_t* out = lane_out + size_t(gr) * width + gc;
            out[0] = int8_t(int32_t(value & 0xffU) - 128);
            out[cells] = int8_t(int32_t((value >> 8) & 0xffU) - 128);
            out[2 * cells] = int8_t(int32_t((value >> 16) & 0xffU) - 128);
            out[3 * cells] = int8_t(int32_t((value >> 24) & 0xffU) - 128);
        }
    }
}

void launch_layer_fused(const int8_t* limbs_in, const int8_t* weights,
                        int8_t* limbs_out, uint32_t* preactivations,
                        uint32_t* activations, const uint32_t* coefficients,
                        const int32_t* weight_row_sums, uint32_t layer,
                        uint32_t layer_stride, uint32_t rows, uint32_t width,
                        uint32_t batch_size) {
    static_assert(TILE_ROWS == 16 && TILE_COLS == 64 && K_TILE == 64,
                  "mapping specialized for this tile shape");
    const dim3 blocks(rows / TILE_ROWS, width / TILE_COLS, batch_size);
    layer_fused<<<blocks, THREADS>>>(limbs_in, weights, limbs_out,
                                     preactivations, activations, coefficients,
                                     weight_row_sums, layer, layer_stride,
                                     rows, width, batch_size);
}

}  // namespace cmfd_v4_replay
