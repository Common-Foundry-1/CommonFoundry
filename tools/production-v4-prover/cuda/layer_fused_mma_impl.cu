// Fused layer kernel — mma.sync m16n8k32 (s8/s8/s32) implementation, SM75+.
// Same contract as the dp4a version in layer_fused_impl.cu (identical wire
// behavior, byte-identical output):
//   grid = (rows/16, width/TILE_COLS, batch_size), THREADS threads per block.
//   Limb planes: [lane][plane][row][col], plane stride = cells.
//   Weights: column-major [layer][col][k].
//   Coefficients: coefficients[(lane*stride + layer+1) * 20].
//   row_sums == nullptr → official -width/2 fallback.
//
// mma.sync.aligned.m16n8k32.row.col.satfinite.s32.s8.s8.s32:
//   A fragment: 4 x int32 = 16 rows x 32 k (per thread: rows {r, r+8},
//   k spans 4 bytes each) — A is the limb planes (4 planes = 4 A fragments).
//   B fragment: 2 x int32 = 8 cols x 32 k — B is the weight tile.
//   C fragment: 4 x int32 = 2 rows x 8 cols.
// Tile: 16 rows x 64 cols x 64 k per stage; each warp computes the full
// 16x64 output (8 mma ops per plane... 4 planes x 8 col-halves x 1 row-half).
// 128 threads = 4 warps; warp w handles cols 16*w..16*w+15 (2 n8 tiles).
#include "layer_fused.cuh"
#include <cuda_runtime.h>

namespace cmfd_v4_replay {
#if !defined(__CUDA_ARCH__) || __CUDA_ARCH__ >= 800


constexpr uint32_t K_TILE = 64;
constexpr uint32_t TILE_ROWS = 16;
constexpr uint32_t TILE_COLS = 64;
constexpr uint32_t THREADS = 128;  // 4 warps

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

__device__ __forceinline__ void mma_s8(int32_t* d, const int32_t* a,
                                       const int32_t* b, const int32_t* c) {
    asm volatile(
        "mma.sync.aligned.m16n8k32.row.col.s32.s8.s8.s32.satfinite "
        "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%10,%11,%12,%13};\n"
        : "=r"(d[0]), "=r"(d[1]), "=r"(d[2]), "=r"(d[3])
        : "r"(a[0]), "r"(a[1]), "r"(a[2]), "r"(a[3]), "r"(b[0]), "r"(b[1]),
          "r"(c[0]), "r"(c[1]), "r"(c[2]), "r"(c[3]));
}

__global__ __launch_bounds__(THREADS) void layer_fused_mma(
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
    const uint32_t warp = tid / 32;      // 4 warps
    const uint32_t wlane = tid % 32;     // lane within warp

    const int8_t* lane_in = limbs_in + lane_off;
    int8_t* lane_out = limbs_out + lane_off;

    // Weight tile smem: [64 cols][64 k] int8, 16B-padded rows.
    __shared__ int8_t wt[TILE_COLS][K_TILE + 16];

    // Fragment index math (PTX ISA m16n8k32 s8):
    //   groupID = wlane >> 2, tig = wlane & 3.
    //   A: 4 regs — {A[g, tig*4], A[g+8, tig*4], A[g, 16+tig*4], A[g+8, 16+tig*4]}
    //      (each reg = 4 consecutive k bytes, row-major).
    //   B: 2 regs — {W[k=tig*4, col=g], W[k=16+tig*4, col=g]}
    //      (each reg = 4 consecutive k bytes of ONE column, k-major).
    //   C: 4 regs — {D[g, tig*2], D[g, tig*2+1], D[g+8, tig*2], D[g+8, tig*2+1]}
    const uint32_t g = wlane >> 2;         // 0..7
    const uint32_t tig = wlane & 3U;       // 0..3
    const uint32_t arow0 = row0 + g;       // rows g and g+8
    const uint32_t acol0 = tig * 4;        // k offset 0..12 (and +16)

    // Warp w owns output cols 16*w .. 16*w+15 = two n8 tiles.
    const uint32_t warp_col0 = warp * 16;

    // acc[plane][tile][4] — C fragments per plane per n8 tile.
    int32_t acc[4][2][4];
#pragma unroll
    for (uint32_t p = 0; p < 4; ++p)
#pragma unroll
        for (uint32_t t = 0; t < 2; ++t)
#pragma unroll
            for (uint32_t i = 0; i < 4; ++i) acc[p][t][i] = 0;

    const uint32_t row_bits = __ffs(static_cast<int>(rows)) - 1;
    const uint32_t column_bits = __ffs(static_cast<int>(width)) - 1;
    const uint32_t* lane_coeffs =
        coefficients + (size_t(lane) * layer_stride + size_t(layer + 1)) * 20;

    for (uint32_t k0 = 0; k0 < width; k0 += K_TILE) {
        // Load W tile: 64 cols x 64 bytes = 4 KiB. 128 threads x 32 B.
        {
            const int4* src = reinterpret_cast<const int4*>(
                weights + size_t(col0) * width + k0);
            const uint32_t col = tid / 2;
            const uint32_t kq0 = (tid % 2) * 2;
            reinterpret_cast<int4*>(&wt[col][0])[kq0] =
                src[size_t(col) * (width / 16) + kq0];
            reinterpret_cast<int4*>(&wt[col][0])[kq0 + 1] =
                src[size_t(col) * (width / 16) + kq0 + 1];
        }
        __syncthreads();

        // B fragments from smem + TWO mma calls per 64-k tile: the mma
        // covers 32 k, so kh=0 (k 0..31) and kh=1 (k 32..63) each need
        // their own A fragment pair and B fragment.
#pragma unroll
        for (uint32_t kh = 0; kh < 2; ++kh) {
            const uint32_t koff = kh * 32;
            int32_t af[4][4];
#pragma unroll
            for (uint32_t p = 0; p < 4; ++p) {
                af[p][0] = *reinterpret_cast<const int32_t*>(
                    lane_in + size_t(p) * cells + size_t(arow0) * width +
                    k0 + koff + acol0);
                af[p][1] = *reinterpret_cast<const int32_t*>(
                    lane_in + size_t(p) * cells + size_t(arow0 + 8) * width +
                    k0 + koff + acol0);
                af[p][2] = *reinterpret_cast<const int32_t*>(
                    lane_in + size_t(p) * cells + size_t(arow0) * width +
                    k0 + koff + 16 + acol0);
                af[p][3] = *reinterpret_cast<const int32_t*>(
                    lane_in + size_t(p) * cells + size_t(arow0 + 8) * width +
                    k0 + koff + 16 + acol0);
            }
#pragma unroll
            for (uint32_t t = 0; t < 2; ++t) {
                const uint32_t cbase = warp_col0 + t * 8 + g;
                const int32_t b0 = *reinterpret_cast<const int32_t*>(
                    &wt[cbase][koff + tig * 4]);
                const int32_t b1 = *reinterpret_cast<const int32_t*>(
                    &wt[cbase][koff + 16 + tig * 4]);
                const int32_t bfrag[2] = {b0, b1};
#pragma unroll
                for (uint32_t p = 0; p < 4; ++p) {
                    mma_s8(acc[p][t], af[p], bfrag, acc[p][t]);
                }
            }
        }
        __syncthreads();
    }

    // Epilogue: exact recombine + center + mask + cube + pack.
    // C fragment: {D[g, tig*2], D[g, tig*2+1], D[g+8, tig*2], D[g+8, tig*2+1]}
#pragma unroll
    for (uint32_t t = 0; t < 2; ++t) {
        const uint32_t gc0 = col0 + warp_col0 + t * 8 + tig * 2;
#pragma unroll
        for (uint32_t half = 0; half < 2; ++half) {
            const uint32_t gr = row0 + g + half * 8;
#pragma unroll
            for (uint32_t cc = 0; cc < 2; ++cc) {
                const uint32_t gc = gc0 + cc;
                const int64_t dot =
                    int64_t(acc[0][t][half * 2 + cc]) +
                    256LL * int64_t(acc[1][t][half * 2 + cc]) +
                    65'536LL * int64_t(acc[2][t][half * 2 + cc]) +
                    16'777'216LL * int64_t(acc[3][t][half * 2 + cc]) +
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
                activations[size_t(lane) * cells + size_t(gr) * width + gc] =
                    value;
                int8_t* out = lane_out + size_t(gr) * width + gc;
                out[0] = int8_t(int32_t(value & 0xffU) - 128);
                out[cells] = int8_t(int32_t((value >> 8) & 0xffU) - 128);
                out[2 * cells] = int8_t(int32_t((value >> 16) & 0xffU) - 128);
                out[3 * cells] = int8_t(int32_t((value >> 24) & 0xffU) - 128);
            }
        }
    }
}

void launch_layer_fused_mma(const int8_t* limbs_in, const int8_t* weights,
                            int8_t* limbs_out, uint32_t* preactivations,
                            uint32_t* activations, const uint32_t* coefficients,
                            const int32_t* weight_row_sums, uint32_t layer,
                            uint32_t layer_stride, uint32_t rows, uint32_t width,
                            uint32_t batch_size) {
    static_assert(TILE_ROWS == 16 && TILE_COLS == 64 && K_TILE == 64,
                  "mapping specialized for this tile shape");
    const dim3 blocks(rows / TILE_ROWS, width / TILE_COLS, batch_size);
    layer_fused_mma<<<blocks, THREADS>>>(limbs_in, weights, limbs_out,
                                         preactivations, activations,
                                         coefficients, weight_row_sums, layer,
                                         layer_stride, rows, width, batch_size);
}


#endif  // __CUDA_ARCH__ >= 800 (mma.sync m16n8k32 requires sm_80+)
}  // namespace cmfd_v4_replay
