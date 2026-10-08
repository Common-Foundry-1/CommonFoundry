// From FreeForgeMiner (https://github.com/pepsykolya/freeforgeminer), MIT License,
// Copyright (c) 2026 FreeForgeMiner contributors. See THIRD_PARTY_NOTICES.md.
//
// FreeForgeMiner: one kernel per ForgeMatrix layer = int8 tensor-core GEMM + layer reduce.
//
// A = interleaved limb rows (row 4*cell + limb, K = 4096 contiguous), B = layer weights
// stored N-major (K contiguous), so the product is a TN GEMM that maps directly onto
// mma.sync.m16n8k32.s8 (sm_80 and every later architecture, incl. Ada and Blackwell
// sm_120). Each 16-row MMA tile holds exactly 4 cells x 4 limbs; the 4 limb partial sums
// of a cell sit in lanes {l, l^4, l^8, l^12}, so the reduction is a 2-step register
// reduce-scatter (4 shuffles per 16x8 tile) and every lane ends up owning one cell value.
// The int32 accumulators never leave registers; the kernel writes only next-layer limbs
// (double-buffered: other tiles of this layer still read the input limbs).
//
// Tile shape, pipeline depth and rasterization are template parameters, so new GPU
// generations get their own configuration instead of new code (see launch_fused_layer).
#pragma once

// Included inside namespace cmfd_v4_replay.
namespace fused {

constexpr uint32_t DIM = PRODUCTION_WIDTH;  // N = K = 4096
constexpr uint32_t LANE_CELLS = PRODUCTION_ROWS * PRODUCTION_WIDTH;
constexpr uint32_t ROW_BITS = 7;      // log2(PRODUCTION_ROWS)
constexpr uint32_t COLUMN_BITS = 12;  // log2(PRODUCTION_WIDTH)
static_assert((1U << ROW_BITS) == PRODUCTION_ROWS, "row bits");
static_assert((1U << COLUMN_BITS) == PRODUCTION_WIDTH, "column bits");
static_assert(1 + ROW_BITS + COLUMN_BITS == MASK_COEFFICIENTS, "mask layout");

struct LayerArgs {
    const int8_t* limbs_in = nullptr;      // [batch * 512][4096], limb-interleaved
    const int8_t* weights = nullptr;       // [4096 n][4096 k] for this layer
    int8_t* limbs_out = nullptr;           // next layer limbs (must differ from limbs_in)
    uint32_t* activations_out = nullptr;   // last layer only
    const int32_t* row_sums = nullptr;     // [4096] for this layer
    const uint32_t* coefficients = nullptr;  // [batch][LAYERS + 1][20]
    uint32_t layer = 0;
    uint32_t m_rows = 0;                   // batch * 512
};

__device__ __forceinline__ uint32_t smem_addr(const void* pointer) {
    return static_cast<uint32_t>(__cvta_generic_to_shared(pointer));
}

__device__ __forceinline__ void cp_async_16(uint32_t destination, const void* source) {
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 800
    asm volatile("cp.async.cg.shared.global [%0], [%1], 16;\n" ::"r"(destination),
                 "l"(source));
#endif
}

__device__ __forceinline__ void cp_async_commit() {
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 800
    asm volatile("cp.async.commit_group;\n" ::);
#endif
}

template <int Pending>
__device__ __forceinline__ void cp_async_wait() {
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 800
    asm volatile("cp.async.wait_group %0;\n" ::"n"(Pending));
#endif
}

__device__ __forceinline__ void ldmatrix_x4(uint32_t (&r)[4], uint32_t address) {
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 800
    asm volatile("ldmatrix.sync.aligned.m8n8.x4.shared.b16 {%0,%1,%2,%3}, [%4];\n"
                 : "=r"(r[0]), "=r"(r[1]), "=r"(r[2]), "=r"(r[3])
                 : "r"(address));
#endif
}

__device__ __forceinline__ void mma_s8(int32_t (&c)[4], const uint32_t (&a)[4],
                                       uint32_t b0, uint32_t b1) {
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 800
    asm volatile(
        "mma.sync.aligned.m16n8k32.row.col.s32.s8.s8.s32 "
        "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};\n"
        : "+r"(c[0]), "+r"(c[1]), "+r"(c[2]), "+r"(c[3])
        : "r"(a[0]), "r"(a[1]), "r"(a[2]), "r"(a[3]), "r"(b0), "r"(b1));
#endif
}

// Barrett reduction for p = 2^31 - 2^24 + 1: for x < 2^62 the quotient estimate is low by
// at most 1, so one conditional subtraction yields the canonical residue (same result as
// x % p, without the ~70-instruction 64-bit division).
__device__ __forceinline__ uint32_t reduce_u64(uint64_t x) {
    constexpr uint64_t barrett = ~uint64_t(0) / KOALA_BEAR_MODULUS;
    const uint64_t r = x - __umul64hi(x, barrett) * KOALA_BEAR_MODULUS;
    return static_cast<uint32_t>(r >= KOALA_BEAR_MODULUS ? r - KOALA_BEAR_MODULUS : r);
}

// |dot| < 2^52 (4 limbs * 2^26 * 2^24 plus CENTER_OFFSET * row_sum), so adding p * 2^23
// (> 2^53) makes it non-negative and keeps it below 2^62.
__device__ __forceinline__ uint32_t canonical_dot(int64_t dot) {
    constexpr int64_t bias = int64_t(KOALA_BEAR_MODULUS) << 23;
    return reduce_u64(static_cast<uint64_t>(dot + bias));
}

__device__ __forceinline__ uint32_t cube_fast(uint32_t v) {
    const uint32_t square = reduce_u64(uint64_t(v) * v);
    return reduce_u64(uint64_t(square) * v);
}

// 16-byte chunk swizzle: the 8 rows read by one ldmatrix phase hit 8 distinct
// bank groups, and cp.async writes stay 16-byte aligned.
template <int BK>
__device__ __forceinline__ int swizzle(int row, int chunk) {
    static_assert(BK == 64 || BK == 128, "BK must be 64 or 128 bytes");
    return BK == 128 ? (chunk ^ (row & 7)) : (chunk ^ ((row >> 1) & 3));
}

template <int BM, int BN, int BK, int WARPS_M, int WARPS_N, int STAGES, int GROUP_M>
struct Config {
    static constexpr int kThreads = WARPS_M * WARPS_N * 32;
    static constexpr int kWarpM = BM / WARPS_M;
    static constexpr int kWarpN = BN / WARPS_N;
    static constexpr int kMmaM = kWarpM / 16;
    static constexpr int kMmaN = kWarpN / 8;
    static constexpr int kChunksPerRow = BK / 16;
    static constexpr int kStageA = BM * BK;
    static constexpr int kStageB = BN * BK;
    static constexpr int kSmemBytes = STAGES * (kStageA + kStageB);
    static_assert(kWarpM % 16 == 0 && kWarpN % 16 == 0, "warp tile");
    static_assert((BM * kChunksPerRow) % kThreads == 0, "A loader");
    static_assert((BN * kChunksPerRow) % kThreads == 0, "B loader");
    static_assert(512 % BM == 0, "a block row tile must not straddle two nonces");
    static_assert(DIM % BN == 0 && DIM % BK == 0, "tile divides 4096");
    static_assert(STAGES >= 2, "pipeline");
    static_assert((BM * (BN / 16)) % kThreads == 0, "epilogue writer");
};

template <int BM, int BN, int BK, int WARPS_M, int WARPS_N, int STAGES, int GROUP_M>
__global__ void __launch_bounds__(WARPS_M * WARPS_N * 32)
fused_layer_kernel(const LayerArgs args) {
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 800
    using C = Config<BM, BN, BK, WARPS_M, WARPS_N, STAGES, GROUP_M>;
    extern __shared__ __align__(128) int8_t shared[];
    int8_t* shared_a = shared;
    int8_t* shared_b = shared + STAGES * C::kStageA;

    const int thread = threadIdx.x;
    const int lane = thread & 31;
    const int warp = thread >> 5;
    const int warp_m = warp / WARPS_N;
    const int warp_n = warp % WARPS_N;

    // Grouped rasterization: GROUP_M row tiles share each streamed weight panel in L2.
    const int tiles_m = static_cast<int>(args.m_rows) / BM;
    constexpr int tiles_n = DIM / BN;
    const int block = blockIdx.x;
    const int per_group = GROUP_M * tiles_n;
    const int first_m = (block / per_group) * GROUP_M;
    const int group_rows = min(tiles_m - first_m, GROUP_M);
    const int tile_m = first_m + (block % per_group) % group_rows;
    const int tile_n = (block % per_group) / group_rows;
    const int m0 = tile_m * BM;
    const int n0 = tile_n * BN;

    // Epilogue inputs (mask coefficients, weight row sums) go to shared memory now, so
    // their global-load latency hides behind the main loop.
    // A row tile never straddles two nonces (512 % BM == 0): one coefficient set per block.
    __shared__ uint32_t shared_coefficients[MASK_COEFFICIENTS];
    __shared__ int32_t shared_row_sums[BN];
    const uint32_t nonce = uint32_t(m0) / (4 * PRODUCTION_ROWS);
    if (thread < int(MASK_COEFFICIENTS))
        shared_coefficients[thread] =
            args.coefficients[(size_t(nonce) * (PRODUCTION_LAYERS + 1) + args.layer + 1) *
                                  MASK_COEFFICIENTS + thread];
    for (int i = thread; i < BN; i += C::kThreads) shared_row_sums[i] = args.row_sums[n0 + i];

    const int8_t* global_a = args.limbs_in + size_t(m0) * DIM;
    const int8_t* global_b = args.weights + size_t(n0) * DIM;

    auto load_stage = [&](int stage, int k_tile) {
        const int k0 = k_tile * BK;
        const uint32_t base_a = smem_addr(shared_a + stage * C::kStageA);
#pragma unroll
        for (int it = 0; it < BM * C::kChunksPerRow / C::kThreads; ++it) {
            const int index = thread + it * C::kThreads;
            const int row = index / C::kChunksPerRow;
            const int chunk = index % C::kChunksPerRow;
            cp_async_16(base_a + row * BK + swizzle<BK>(row, chunk) * 16,
                        global_a + size_t(row) * DIM + k0 + chunk * 16);
        }
        const uint32_t base_b = smem_addr(shared_b + stage * C::kStageB);
#pragma unroll
        for (int it = 0; it < BN * C::kChunksPerRow / C::kThreads; ++it) {
            const int index = thread + it * C::kThreads;
            const int row = index / C::kChunksPerRow;
            const int chunk = index % C::kChunksPerRow;
            cp_async_16(base_b + row * BK + swizzle<BK>(row, chunk) * 16,
                        global_b + size_t(row) * DIM + k0 + chunk * 16);
        }
    };

    int32_t acc[C::kMmaM][C::kMmaN][4];
#pragma unroll
    for (int i = 0; i < C::kMmaM; ++i)
#pragma unroll
        for (int j = 0; j < C::kMmaN; ++j)
#pragma unroll
            for (int k = 0; k < 4; ++k) acc[i][j][k] = 0;

    // Software pipeline (CUTLASS-style): STAGES-1 k-tiles in flight via cp.async, and the
    // fragments of the next k-step are read from shared memory while the current k-step's
    // MMAs issue, so ldmatrix latency hides behind tensor-core work.
    constexpr int k_tiles = DIM / BK;
    constexpr int k_steps = BK / 32;
#pragma unroll
    for (int stage = 0; stage < STAGES - 1; ++stage) {
        load_stage(stage, stage);
        cp_async_commit();
    }
    cp_async_wait<STAGES - 2>();
    __syncthreads();

    uint32_t frag_a[2][C::kMmaM][4];
    uint32_t frag_b[2][C::kMmaN / 2][4];
    auto load_fragments = [&](int buffer, int stage, int k_step) {
        const uint32_t base_a = smem_addr(shared_a + stage * C::kStageA);
        const uint32_t base_b = smem_addr(shared_b + stage * C::kStageB);
#pragma unroll
        for (int mi = 0; mi < C::kMmaM; ++mi) {
            const int row = warp_m * C::kWarpM + mi * 16 + (lane & 15);
            const int chunk = k_step * 2 + (lane >> 4);
            ldmatrix_x4(frag_a[buffer][mi], base_a + row * BK + swizzle<BK>(row, chunk) * 16);
        }
#pragma unroll
        for (int ni = 0; ni < C::kMmaN / 2; ++ni) {
            const int row = warp_n * C::kWarpN + ni * 16 + ((lane >> 4) << 3) + (lane & 7);
            const int chunk = k_step * 2 + ((lane >> 3) & 1);
            ldmatrix_x4(frag_b[buffer][ni], base_b + row * BK + swizzle<BK>(row, chunk) * 16);
        }
    };

    int read_stage = 0;
    int write_stage = STAGES - 1;
    load_fragments(0, read_stage, 0);
    for (int k_tile = 0; k_tile < k_tiles; ++k_tile) {
#pragma unroll
        for (int k_step = 0; k_step < k_steps; ++k_step) {
            if (k_step == k_steps - 1) {
                // the next k-tile must be resident before its first fragments are read;
                // this barrier also retires every read of the stage refilled below
                cp_async_wait<STAGES - 2>();
                __syncthreads();
                read_stage = read_stage + 1 == STAGES ? 0 : read_stage + 1;
            }
            load_fragments((k_step + 1) & 1, read_stage, (k_step + 1) % k_steps);
            if (k_step == 0) {
                const int prefetch = k_tile + STAGES - 1;
                if (prefetch < k_tiles) load_stage(write_stage, prefetch);
                cp_async_commit();
                write_stage = write_stage + 1 == STAGES ? 0 : write_stage + 1;
            }
            const int buffer = k_step & 1;
#pragma unroll
            for (int mi = 0; mi < C::kMmaM; ++mi)
#pragma unroll
                for (int ni = 0; ni < C::kMmaN; ++ni)
                    mma_s8(acc[mi][ni], frag_a[buffer][mi], frag_b[buffer][ni >> 1][(ni & 1) * 2],
                           frag_b[buffer][ni >> 1][(ni & 1) * 2 + 1]);
        }
    }
    cp_async_wait<0>();

    // ---- epilogue: limb recombination in registers, then mask, cube, next limbs ----
    // Accumulator element e of an m16n8 tile: rows g (e0,e1) and g+8 (e2,e3),
    // columns 2*tig + {0,1}. Row g = 4*cell + limb, limb j = g & 3.
    const int group = lane >> 2;
    const int limb = group & 3;
    const int tig = lane & 3;
    const int high = (lane >> 3) & 1;  // limb bit 1 -> partner lane ^ 8
    const int low = (lane >> 2) & 1;   // limb bit 0 -> partner lane ^ 4
    const int64_t own_scale = int64_t(1) << (8 * limb);
    const int64_t pair_scale = int64_t(1) << (8 * (limb ^ 2));
    constexpr uint32_t full = 0xffffffffU;

    const uint32_t* coefficients = shared_coefficients;  // published by the main-loop barriers
    // The coordinate mask is separable: c0 + row part + column part. Every lane owns
    // kMmaN columns for the whole tile, so the column part and the row sums are hoisted.
    uint32_t column_mask[C::kMmaN];
    int64_t column_offset[C::kMmaN];
#pragma unroll
    for (int ni = 0; ni < C::kMmaN; ++ni) {
        const uint32_t column = uint32_t(n0 + warp_n * C::kWarpN + ni * 8 + 2 * tig + low);
        uint32_t mask = 0;
#pragma unroll
        for (uint32_t bit = 0; bit < COLUMN_BITS; ++bit)
            if ((column >> bit) & 1U) mask += coefficients[1 + ROW_BITS + bit];
        column_mask[ni] = mask;
        column_offset[ni] = CENTER_OFFSET * int64_t(shared_row_sums[column - n0]);
    }

    // Output limbs are staged in shared memory (the pipeline buffers are free now) and
    // written back as full 16-byte rows instead of scattered single bytes.
    __syncthreads();
    int8_t* staged = shared;  // [BM limb rows][BN columns]
    static_assert(BM * BN <= STAGES * (C::kStageA + C::kStageB), "staging fits");

#pragma unroll
    for (int mi = 0; mi < C::kMmaM; ++mi) {
        // after the reduce-scatter this lane owns cell (high ? 2 : 0) + (lane >> 4)
        const int local_cell = (warp_m * C::kWarpM + mi * 16) / 4 + high * 2 + (lane >> 4);
        const uint32_t row = (uint32_t(m0) / 4 + uint32_t(local_cell)) % PRODUCTION_ROWS;
        uint32_t row_mask = coefficients[0];
#pragma unroll
        for (uint32_t bit = 0; bit < ROW_BITS; ++bit)
            if ((row >> bit) & 1U) row_mask += coefficients[1 + bit];

#pragma unroll
        for (int ni = 0; ni < C::kMmaN; ++ni) {
            const int32_t* e = acc[mi][ni];
            const int32_t keep0 = high ? e[2] : e[0];
            const int32_t keep1 = high ? e[3] : e[1];
            const int32_t give0 = high ? e[0] : e[2];
            const int32_t give1 = high ? e[1] : e[3];
            const int32_t got0 = __shfl_xor_sync(full, give0, 8);
            const int32_t got1 = __shfl_xor_sync(full, give1, 8);
            const int64_t pair0 = int64_t(keep0) * own_scale + int64_t(got0) * pair_scale;
            const int64_t pair1 = int64_t(keep1) * own_scale + int64_t(got1) * pair_scale;
            const int64_t keep = low ? pair1 : pair0;
            const int64_t give = low ? pair0 : pair1;
            const int64_t got = __shfl_xor_sync(full, give, 4);

            const uint32_t accumulator = canonical_dot(keep + got + column_offset[ni]);
            // coefficients are bytes, so the mask is far below p; % only as a guard
            uint32_t mask = row_mask + column_mask[ni];
            if (mask >= KOALA_BEAR_MODULUS) mask %= KOALA_BEAR_MODULUS;
            uint32_t value = accumulator + mask;
            if (value >= KOALA_BEAR_MODULUS) value -= KOALA_BEAR_MODULUS;
            value = cube_fast(value);
            const int local_column = warp_n * C::kWarpN + ni * 8 + 2 * tig + low;
            if (args.activations_out != nullptr)
                args.activations_out[size_t(nonce) * LANE_CELLS + size_t(row) * DIM +
                                     uint32_t(n0 + local_column)] = value;
            int8_t* out = staged + (4 * local_cell) * BN + local_column;
            out[0] = static_cast<int8_t>(static_cast<int32_t>(value & 0xffU) - 128);
            out[BN] = static_cast<int8_t>(static_cast<int32_t>((value >> 8) & 0xffU) - 128);
            out[2 * BN] = static_cast<int8_t>(static_cast<int32_t>((value >> 16) & 0xffU) - 128);
            out[3 * BN] = static_cast<int8_t>(static_cast<int32_t>((value >> 24) & 0xffU) - 128);
        }
    }
    __syncthreads();
    // limb row r of this tile is global row m0 + r of the (interleaved) next-layer limbs
    constexpr int chunks_per_row = BN / 16;
#pragma unroll
    for (int it = 0; it < BM * chunks_per_row / C::kThreads; ++it) {
        const int index = thread + it * C::kThreads;
        const int r = index / chunks_per_row;
        const int chunk = index % chunks_per_row;
        *reinterpret_cast<int4*>(args.limbs_out + size_t(m0 + r) * DIM + n0 + chunk * 16) =
            *reinterpret_cast<const int4*>(staged + r * BN + chunk * 16);
    }
#endif
}

template <int BM, int BN, int BK, int WARPS_M, int WARPS_N, int STAGES, int GROUP_M>
void launch_config(const LayerArgs& args) {
    using C = Config<BM, BN, BK, WARPS_M, WARPS_N, STAGES, GROUP_M>;
    auto kernel = fused_layer_kernel<BM, BN, BK, WARPS_M, WARPS_N, STAGES, GROUP_M>;
    static bool configured = false;
    if (!configured) {
        cuda_check(cudaFuncSetAttribute(kernel, cudaFuncAttributeMaxDynamicSharedMemorySize,
                                        C::kSmemBytes),
                   "configure fused layer shared memory");
        configured = true;
    }
    const int blocks = static_cast<int>(args.m_rows / BM) * static_cast<int>(DIM / BN);
    kernel<<<blocks, C::kThreads, C::kSmemBytes>>>(args);
}

// Tile configurations. New architectures add a line here and pick a default in
// default_config(); CMFD_FUSED=<n> selects one explicitly for tuning.
//                         BM   BN   BK  WM WN ST GROUP
#define FFM_FUSED_CONFIGS(X)                          X(0, 128, 128, 64, 2, 2, 3, 8)                    X(1, 128, 128, 64, 2, 4, 3, 8)                    X(2, 128, 128, 64, 2, 2, 2, 8)                    X(3, 128, 64, 64, 2, 2, 4, 8)                     X(4, 64, 128, 64, 2, 2, 4, 8)                     X(5, 128, 128, 64, 2, 2, 3, 16)                   X(6, 128, 128, 64, 2, 2, 3, 4)                    X(7, 64, 64, 64, 2, 2, 4, 8)

constexpr int CONFIG_COUNT = 8;

inline void launch_fused_layer(int config, const LayerArgs& args) {
    switch (config) {
#define FFM_FUSED_CASE(id, bm, bn, bk, wm, wn, st, gm) \
    case id: launch_config<bm, bn, bk, wm, wn, st, gm>(args); return;
        FFM_FUSED_CONFIGS(FFM_FUSED_CASE)
#undef FFM_FUSED_CASE
        default: throw std::runtime_error("unknown fused layer configuration");
    }
}

// Whether this binary carries an sm_80+ image of the fused kernel for the current GPU.
inline bool fused_available(const cudaDeviceProp& properties) {
    if (properties.major < 8) return false;
    cudaFuncAttributes attributes{};
    if (cudaFuncGetAttributes(&attributes, fused_layer_kernel<128, 128, 64, 2, 2, 3, 8>) !=
        cudaSuccess)
        return false;
    return attributes.ptxVersion >= 80;
}

inline int default_config(const cudaDeviceProp& properties) {
    // Tuned on RTX 4070 Ti (sm_89) and RTX 3070 (sm_86): 128x128x64, 3 stages, 2 blocks/SM.
    // Hopper/Blackwell run the same mma.sync path; add their tuned entries here.
    (void)properties;
    return 5;
}

}  // namespace fused
