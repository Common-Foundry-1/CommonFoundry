#include <cuda_runtime.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "cutlass/cutlass.h"
#include "cutlass/epilogue/thread/linear_combination_clamp.h"
#include "cutlass/gemm/device/gemm.h"
#include "cutlass/version.h"

static_assert(CUTLASS_MAJOR == 3 && CUTLASS_MINOR == 9 && CUTLASS_PATCH == 2,
              "benchmark requires the production-pinned CUTLASS v3.9.2");

namespace {

constexpr uint32_t KOALA_BEAR_MODULUS = 0x7f000001U;
constexpr uint32_t PRODUCTION_ROWS = 128;
constexpr uint32_t PRODUCTION_WIDTH = 4096;
constexpr uint32_t PRODUCTION_LAYERS = 384;
constexpr uint32_t MASK_COEFFICIENTS = 20;
constexpr uint32_t THREADS = 256;
constexpr size_t MODEL_HEADER_BYTES = 184;
constexpr size_t MODEL_BASE_BYTES = size_t(PRODUCTION_ROWS) * PRODUCTION_WIDTH;
constexpr int64_t CENTER_OFFSET = 128LL * (1LL + 256LL + 65'536LL + 16'777'216LL);

using TensorCoreGemm = cutlass::gemm::device::Gemm<
    int8_t, cutlass::layout::RowMajor, int8_t, cutlass::layout::ColumnMajor,
    int32_t, cutlass::layout::RowMajor, int32_t, cutlass::arch::OpClassTensorOp,
    cutlass::arch::Sm75, cutlass::gemm::GemmShape<128, 128, 64>,
    cutlass::gemm::GemmShape<64, 64, 64>, cutlass::gemm::GemmShape<8, 8, 16>,
    cutlass::epilogue::thread::LinearCombinationClamp<int32_t, 4, int32_t, int32_t>,
    cutlass::gemm::threadblock::GemmIdentityThreadblockSwizzle<>, 2>;

void cuda_check(cudaError_t result, const char* operation) {
    if (result != cudaSuccess) {
        throw std::runtime_error(std::string(operation) + ": " + cudaGetErrorString(result));
    }
}

void cutlass_check(cutlass::Status status, const char* operation) {
    if (status != cutlass::Status::kSuccess) {
        throw std::runtime_error(std::string(operation) + ": " +
                                 cutlass::cutlassGetStatusString(status));
    }
}

__host__ __device__ int8_t synthetic_weight(uint32_t layer, uint32_t common,
                                             uint32_t column) {
    return static_cast<int8_t>(static_cast<int32_t>(
                                   (common + 3U * column + 5U * layer) & 15U) -
                               8);
}

constexpr int8_t decode_model_byte(uint8_t value) {
    return static_cast<int8_t>(static_cast<int16_t>(value) - 125);
}

static_assert(decode_model_byte(0) == -125);
static_assert(decode_model_byte(125) == 0);
static_assert(decode_model_byte(250) == 125);

__host__ __device__ uint32_t canonicalize_signed(int64_t value) {
    int64_t remainder = value % static_cast<int64_t>(KOALA_BEAR_MODULUS);
    if (remainder < 0) remainder += KOALA_BEAR_MODULUS;
    return static_cast<uint32_t>(remainder);
}

__host__ __device__ uint32_t mul_field(uint32_t left, uint32_t right) {
    return static_cast<uint32_t>((static_cast<uint64_t>(left) * right) %
                                 KOALA_BEAR_MODULUS);
}

__host__ __device__ uint32_t cube_field(uint32_t value) {
    return mul_field(mul_field(value, value), value);
}

__host__ __device__ uint32_t coordinate_mask(const uint32_t* coefficients,
                                               uint32_t row, uint32_t column,
                                               uint32_t row_bits,
                                               uint32_t column_bits) {
    uint64_t mask = coefficients[0];
    for (uint32_t bit = 0; bit < row_bits; ++bit) {
        if (((row >> bit) & 1U) != 0) mask += coefficients[1 + bit];
    }
    for (uint32_t bit = 0; bit < column_bits; ++bit) {
        if (((column >> bit) & 1U) != 0) {
            mask += coefficients[1 + row_bits + bit];
        }
    }
    return static_cast<uint32_t>(mask % KOALA_BEAR_MODULUS);
}

__device__ void write_centered_limbs(uint32_t value, int8_t* limbs,
                                     size_t limb_stride, size_t index) {
    limbs[index] = static_cast<int8_t>(static_cast<int32_t>(value & 0xffU) - 128);
    limbs[limb_stride + index] =
        static_cast<int8_t>(static_cast<int32_t>((value >> 8) & 0xffU) - 128);
    limbs[2 * limb_stride + index] =
        static_cast<int8_t>(static_cast<int32_t>((value >> 16) & 0xffU) - 128);
    limbs[3 * limb_stride + index] =
        static_cast<int8_t>(static_cast<int32_t>((value >> 24) & 0xffU) - 128);
}

__global__ void initialize_weights(int8_t* weights, size_t count, uint32_t width) {
    const size_t layer_size = size_t(width) * width;
    for (size_t index = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += size_t(gridDim.x) * blockDim.x) {
        const uint32_t layer = static_cast<uint32_t>(index / layer_size);
        const size_t within_layer = index - size_t(layer) * layer_size;
        const uint32_t column = static_cast<uint32_t>(within_layer / width);
        const uint32_t common = static_cast<uint32_t>(within_layer % width);
        weights[index] = synthetic_weight(layer, common, column);
    }
}

__global__ void transpose_square_layer(const int8_t* input, int8_t* output,
                                       uint32_t width) {
    __shared__ int8_t tile[32][33];
    const uint32_t source_column = blockIdx.x * 32 + threadIdx.x;
    const uint32_t source_row = blockIdx.y * 32 + threadIdx.y;
    for (uint32_t offset = 0; offset < 32; offset += 8) {
        if (source_column < width && source_row + offset < width) {
            tile[threadIdx.y + offset][threadIdx.x] =
                input[size_t(source_row + offset) * width + source_column];
        }
    }
    __syncthreads();
    const uint32_t target_column = blockIdx.y * 32 + threadIdx.x;
    const uint32_t target_row = blockIdx.x * 32 + threadIdx.y;
    for (uint32_t offset = 0; offset < 32; offset += 8) {
        if (target_column < width && target_row + offset < width) {
            output[size_t(target_row + offset) * width + target_column] =
                tile[threadIdx.x][threadIdx.y + offset];
        }
    }
}

__global__ void calculate_weight_row_sums(const int8_t* transposed_weights,
                                          int32_t* sums, uint32_t layers,
                                          uint32_t width) {
    const size_t index = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t count = size_t(layers) * width;
    if (index >= count) return;
    const uint32_t layer = static_cast<uint32_t>(index / width);
    const uint32_t column = static_cast<uint32_t>(index % width);
    const int8_t* weights = transposed_weights +
                            size_t(layer) * width * width + size_t(column) * width;
    int32_t sum = 0;
    for (uint32_t common = 0; common < width; ++common) {
        sum += weights[common];
    }
    sums[index] = sum;
}

__global__ void initialize_activation(const int8_t* base_input, int8_t* limbs,
                                      uint32_t* activation_trace,
                                      const uint32_t* coefficients, uint32_t rows,
                                      uint32_t width) {
    const size_t index = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t count = size_t(rows) * width;
    if (index >= count) return;
    const uint32_t row = static_cast<uint32_t>(index / width);
    const uint32_t column = static_cast<uint32_t>(index % width);
    const uint32_t row_bits = __ffs(static_cast<int>(rows)) - 1;
    const uint32_t column_bits = __ffs(static_cast<int>(width)) - 1;
    const uint32_t base = base_input == nullptr
                              ? static_cast<uint32_t>(
                                    (uint64_t(row) * 131'071U +
                                     uint64_t(column) * 8'191U + 17U) %
                                    KOALA_BEAR_MODULUS)
                              : canonicalize_signed(base_input[index]);
    const uint32_t mask =
        coordinate_mask(coefficients, row, column, row_bits, column_bits);
    uint32_t value = base + mask;
    if (value >= KOALA_BEAR_MODULUS) value -= KOALA_BEAR_MODULUS;
    value = cube_field(value);
    activation_trace[index] = value;
    write_centered_limbs(value, limbs, count, index);
}

__global__ void reduce_layer(const int32_t* limb_accumulators, int8_t* limbs,
                             uint32_t* preactivation_trace,
                             uint32_t* activation_trace,
                             const uint32_t* coefficients,
                             const int32_t* weight_row_sums, uint32_t rows,
                             uint32_t width) {
    const size_t index = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t count = size_t(rows) * width;
    if (index >= count) return;
    const int64_t dot =
        int64_t(limb_accumulators[index]) +
        256LL * int64_t(limb_accumulators[count + index]) +
        65'536LL * int64_t(limb_accumulators[2 * count + index]) +
        16'777'216LL * int64_t(limb_accumulators[3 * count + index]) +
        CENTER_OFFSET *
            (weight_row_sums == nullptr ? -int64_t(width / 2)
                                        : int64_t(weight_row_sums[index % width]));
    const uint32_t accumulator = canonicalize_signed(dot);
    const uint32_t row = static_cast<uint32_t>(index / width);
    const uint32_t column = static_cast<uint32_t>(index % width);
    const uint32_t row_bits = __ffs(static_cast<int>(rows)) - 1;
    const uint32_t column_bits = __ffs(static_cast<int>(width)) - 1;
    const uint32_t mask =
        coordinate_mask(coefficients, row, column, row_bits, column_bits);
    uint32_t value = accumulator + mask;
    if (value >= KOALA_BEAR_MODULUS) value -= KOALA_BEAR_MODULUS;
    preactivation_trace[index] = value;
    value = cube_field(value);
    activation_trace[index] = value;
    write_centered_limbs(value, limbs, count, index);
}

void launch_gemm(const int8_t* activation, const int8_t* weights,
                 int32_t* accumulators, uint32_t rows, uint32_t width) {
    const cutlass::gemm::GemmCoord problem_size(static_cast<int>(rows),
                                                 static_cast<int>(width),
                                                 static_cast<int>(width));
    typename TensorCoreGemm::Arguments arguments{
        problem_size,
        {activation, static_cast<int>(width)},
        {weights, static_cast<int>(width)},
        {accumulators, static_cast<int>(width)},
        {accumulators, static_cast<int>(width)},
        {int32_t{1}, int32_t{0}},
        1};
    TensorCoreGemm operation;
    cutlass_check(operation.can_implement(arguments), "validate Tensor Core GEMM");
    cutlass_check(operation(arguments), "launch Tensor Core GEMM");
}

std::vector<uint32_t> make_coefficients(uint32_t layers) {
    std::vector<uint32_t> coefficients(size_t(layers + 1) * MASK_COEFFICIENTS);
    for (size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = static_cast<uint32_t>(
            (uint64_t(index + 1) * 1'000'003U + 97U) % KOALA_BEAR_MODULUS);
    }
    return coefficients;
}

std::vector<uint32_t> load_coefficients(const char* path, uint32_t layers) {
    if (path == nullptr) return make_coefficients(layers);
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("open V4 replay coefficients");
    const size_t expected = size_t(layers + 1) * MASK_COEFFICIENTS;
    const auto actual = input.tellg();
    if (actual < 0 || static_cast<uint64_t>(actual) != expected) {
        throw std::runtime_error("V4 replay coefficients have the wrong byte length");
    }
    input.seekg(0, std::ios::beg);
    std::vector<uint8_t> encoded(expected);
    input.read(reinterpret_cast<char*>(encoded.data()), encoded.size());
    if (!input) throw std::runtime_error("read V4 replay coefficients");
    std::vector<uint32_t> coefficients(expected);
    std::transform(encoded.begin(), encoded.end(), coefficients.begin(),
                   [](uint8_t value) { return static_cast<uint32_t>(value); });
    return coefficients;
}

void append_device_u32(std::ofstream& output, const uint32_t* device_values,
                       size_t count) {
    constexpr size_t CHUNK_VALUES = (size_t{16} << 20) / sizeof(uint32_t);
    std::vector<uint32_t> buffer(std::min(count, CHUNK_VALUES));
    for (size_t offset = 0; offset < count; offset += buffer.size()) {
        const size_t chunk = std::min(buffer.size(), count - offset);
        cuda_check(cudaMemcpy(buffer.data(), device_values + offset,
                              chunk * sizeof(uint32_t), cudaMemcpyDeviceToHost),
                   "copy V4 replay trace chunk");
        output.write(reinterpret_cast<const char*>(buffer.data()),
                     chunk * sizeof(uint32_t));
        if (!output) throw std::runtime_error("write V4 replay trace chunk");
    }
}

__global__ void canonical_to_montgomery(uint32_t* values, size_t count) {
    constexpr uint32_t MONTGOMERY_ONE = 33'554'430U;
    for (size_t index = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += size_t(gridDim.x) * blockDim.x) {
        values[index] = static_cast<uint32_t>(
            (static_cast<uint64_t>(values[index]) * MONTGOMERY_ONE) %
            KOALA_BEAR_MODULUS);
    }
}

void write_final_activation(const char* prefix, const uint32_t* final_activation,
                            size_t cells) {
    if (prefix == nullptr) return;
    const std::string final_path = std::string(prefix) + "-final-activation.bin";
    std::ofstream final_output(final_path, std::ios::binary | std::ios::trunc);
    if (!final_output) throw std::runtime_error("create V4 final activation");
    append_device_u32(final_output, final_activation, cells);
    final_output.close();
    std::printf("final_activation_path=%s bytes=%llu encoding=canonical_u32\n",
                final_path.c_str(),
                static_cast<unsigned long long>(cells * sizeof(uint32_t)));
}

void write_replay_outputs(const char* prefix, uint32_t* preactivation_trace,
                          uint32_t* activation_trace, size_t cells) {
    if (prefix == nullptr) return;
    write_final_activation(prefix,
                           activation_trace + size_t(PRODUCTION_LAYERS) * cells,
                           cells);

    const size_t transition_values = size_t(PRODUCTION_LAYERS) * cells;
    const uint32_t blocks = static_cast<uint32_t>(
        std::min<size_t>((transition_values + THREADS - 1) / THREADS, 65'535));
    canonical_to_montgomery<<<blocks, THREADS>>>(preactivation_trace,
                                                 transition_values);
    canonical_to_montgomery<<<blocks, THREADS>>>(activation_trace + cells,
                                                 transition_values);
    cuda_check(cudaDeviceSynchronize(), "convert V4 dynamic traces to Montgomery form");

    const size_t bank_values = size_t{128} * cells;
    for (uint32_t bank = 0; bank < 3; ++bank) {
        const std::string path = std::string(prefix) + "-bank" +
                                 std::to_string(bank) + "-dynamic.bin";
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("create V4 bank dynamic trace");
        append_device_u32(output,
                          preactivation_trace + size_t(bank) * bank_values,
                          bank_values);
        append_device_u32(output,
                          activation_trace + (size_t(bank) * 128 + 1) * cells,
                          bank_values);
        std::printf("dynamic_trace_path=%s bytes=%llu encoding=montgomery_u32\n",
                    path.c_str(),
                    static_cast<unsigned long long>(2 * bank_values * sizeof(uint32_t)));
    }
}

void run_small_differential() {
    constexpr uint32_t rows = 2;
    constexpr uint32_t width = 128;
    constexpr uint32_t layers = 3;
    const size_t cells = size_t(rows) * width;
    const size_t layer_cells = size_t(width) * width;
    const auto coefficients = make_coefficients(layers);

    int8_t* device_weights = nullptr;
    int8_t* device_limbs = nullptr;
    int32_t* device_accumulators = nullptr;
    uint32_t* device_preactivation_trace = nullptr;
    uint32_t* device_activation_trace = nullptr;
    uint32_t* device_coefficients = nullptr;
    cuda_check(cudaMalloc(&device_weights, size_t(layers) * layer_cells),
               "allocate differential weights");
    cuda_check(cudaMalloc(&device_limbs, 4 * cells), "allocate differential limbs");
    cuda_check(cudaMalloc(&device_accumulators, 4 * cells * sizeof(int32_t)),
               "allocate differential accumulators");
    cuda_check(cudaMalloc(&device_preactivation_trace, size_t(layers) * cells * sizeof(uint32_t)),
               "allocate differential preactivation trace");
    cuda_check(cudaMalloc(&device_activation_trace, size_t(layers + 1) * cells * sizeof(uint32_t)),
               "allocate differential activation trace");
    cuda_check(cudaMalloc(&device_coefficients, coefficients.size() * sizeof(uint32_t)),
               "allocate differential coefficients");
    cuda_check(cudaMemcpy(device_coefficients, coefficients.data(),
                          coefficients.size() * sizeof(uint32_t), cudaMemcpyHostToDevice),
               "copy differential coefficients");
    initialize_weights<<<64, THREADS>>>(device_weights, size_t(layers) * layer_cells, width);
    initialize_activation<<<1, THREADS>>>(nullptr, device_limbs,
                                          device_activation_trace,
                                          device_coefficients, rows, width);
    for (uint32_t layer = 0; layer < layers; ++layer) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            launch_gemm(device_limbs + size_t(limb) * cells,
                        device_weights + size_t(layer) * layer_cells,
                        device_accumulators + size_t(limb) * cells, rows, width);
        }
        reduce_layer<<<1, THREADS>>>(
            device_accumulators, device_limbs,
            device_preactivation_trace + size_t(layer) * cells,
            device_activation_trace + size_t(layer + 1) * cells,
            device_coefficients + size_t(layer + 1) * MASK_COEFFICIENTS,
            nullptr, rows, width);
    }
    cuda_check(cudaDeviceSynchronize(), "run differential replay");

    std::vector<uint32_t> actual_preactivations(size_t(layers) * cells);
    std::vector<uint32_t> actual_activations(size_t(layers + 1) * cells);
    cuda_check(cudaMemcpy(actual_preactivations.data(), device_preactivation_trace,
                          actual_preactivations.size() * sizeof(uint32_t), cudaMemcpyDeviceToHost),
               "copy differential preactivation trace");
    cuda_check(cudaMemcpy(actual_activations.data(), device_activation_trace,
                          actual_activations.size() * sizeof(uint32_t), cudaMemcpyDeviceToHost),
               "copy differential activation trace");

    std::vector<uint32_t> expected(cells);
    for (size_t index = 0; index < cells; ++index) {
        const uint32_t row = static_cast<uint32_t>(index / width);
        const uint32_t column = static_cast<uint32_t>(index % width);
        const uint32_t base = static_cast<uint32_t>(
            (uint64_t(row) * 131'071U + uint64_t(column) * 8'191U + 17U) %
            KOALA_BEAR_MODULUS);
        uint32_t value = base + coordinate_mask(coefficients.data(), row, column, 1, 7);
        if (value >= KOALA_BEAR_MODULUS) value -= KOALA_BEAR_MODULUS;
        expected[index] = cube_field(value);
        if (actual_activations[index] != expected[index]) {
            throw std::runtime_error("initial activation differential mismatch");
        }
    }
    for (uint32_t layer = 0; layer < layers; ++layer) {
        std::vector<uint32_t> next(cells);
        for (uint32_t row = 0; row < rows; ++row) {
            for (uint32_t column = 0; column < width; ++column) {
                int64_t dot = 0;
                for (uint32_t common = 0; common < width; ++common) {
                    dot += int64_t(expected[size_t(row) * width + common]) *
                           synthetic_weight(layer, common, column);
                }
                const size_t index = size_t(row) * width + column;
                const uint32_t accumulator = canonicalize_signed(dot);
                uint32_t value = accumulator + coordinate_mask(
                    coefficients.data() + size_t(layer + 1) * MASK_COEFFICIENTS,
                    row, column, 1, 7);
                if (value >= KOALA_BEAR_MODULUS) value -= KOALA_BEAR_MODULUS;
                if (actual_preactivations[size_t(layer) * cells + index] != value) {
                    throw std::runtime_error("matrix preactivation differential mismatch");
                }
                next[index] = cube_field(value);
                if (actual_activations[size_t(layer + 1) * cells + index] != next[index]) {
                    throw std::runtime_error("transition differential mismatch");
                }
            }
        }
        expected.swap(next);
    }
    cudaFree(device_coefficients);
    cudaFree(device_activation_trace);
    cudaFree(device_preactivation_trace);
    cudaFree(device_accumulators);
    cudaFree(device_limbs);
    cudaFree(device_weights);
    std::printf("small_differential=EXACT\n");
}

class ProductionModel {
   public:
    explicit ProductionModel(const char* model_path)
        : model_path_(model_path == nullptr ? "" : model_path) {
        size_t total_bytes = 0;
        cuda_check(cudaMemGetInfo(&baseline_free_, &total_bytes),
                   "read initial device memory");
        load();
    }

    ProductionModel(const ProductionModel&) = delete;
    ProductionModel& operator=(const ProductionModel&) = delete;

    ~ProductionModel() { evict(); }

    void ensure_loaded() {
        if (weights_ == nullptr) load();
    }

    void evict() {
        if (weights_ == nullptr) return;
        cudaDeviceSynchronize();
        cudaFree(device_weight_row_sums_);
        cudaFree(device_base_);
        cudaFree(weights_);
        device_weight_row_sums_ = nullptr;
        device_base_ = nullptr;
        weights_ = nullptr;
    }

    bool real_model() const { return !model_path_.empty(); }
    int8_t* weights() const { return weights_; }
    int8_t* base() const { return device_base_; }
    int32_t* row_sums() const { return device_weight_row_sums_; }
    const std::vector<int8_t>& host_base() const { return host_base_; }
    const std::vector<int8_t>& first_layer() const { return first_canonical_layer_; }
    size_t baseline_free() const { return baseline_free_; }

   private:
    void load() {
        const size_t layer_cells = size_t(PRODUCTION_WIDTH) * PRODUCTION_WIDTH;
        const size_t weight_bytes = size_t(PRODUCTION_LAYERS) * layer_cells;
        cuda_check(cudaMalloc(&weights_, weight_bytes), "allocate production weights");
        if (!real_model()) {
            initialize_weights<<<65'535, THREADS>>>(weights_, weight_bytes,
                                                    PRODUCTION_WIDTH);
            cuda_check(cudaDeviceSynchronize(), "initialize production weights");
            return;
        }

        std::ifstream model(model_path_, std::ios::binary | std::ios::ate);
        if (!model) throw std::runtime_error("open production model bank");
        const auto actual_bytes = model.tellg();
        const size_t expected_bytes = MODEL_HEADER_BYTES + MODEL_BASE_BYTES + weight_bytes;
        if (actual_bytes < 0 || static_cast<uint64_t>(actual_bytes) != expected_bytes) {
            throw std::runtime_error("production model bank has the wrong byte length");
        }
        model.seekg(MODEL_HEADER_BYTES, std::ios::beg);
        std::vector<uint8_t> encoded_base(MODEL_BASE_BYTES);
        model.read(reinterpret_cast<char*>(encoded_base.data()), encoded_base.size());
        if (!model) throw std::runtime_error("read production base input");
        host_base_.resize(MODEL_BASE_BYTES);
        std::transform(encoded_base.begin(), encoded_base.end(), host_base_.begin(),
                       decode_model_byte);
        cuda_check(cudaMalloc(&device_base_, MODEL_BASE_BYTES),
                   "allocate production base input");
        cuda_check(cudaMemcpy(device_base_, host_base_.data(), MODEL_BASE_BYTES,
                              cudaMemcpyHostToDevice),
                   "copy production base input");

        int8_t* device_canonical_layer = nullptr;
        cuda_check(cudaMalloc(&device_canonical_layer, layer_cells),
                   "allocate canonical weight layer");
        cuda_check(cudaMalloc(&device_weight_row_sums_,
                              size_t(PRODUCTION_LAYERS) * PRODUCTION_WIDTH *
                                  sizeof(int32_t)),
                   "allocate weight row sums");
        std::vector<uint8_t> encoded_layer(layer_cells);
        std::vector<int8_t> canonical_layer(layer_cells);
        first_canonical_layer_.resize(layer_cells);
        const dim3 transpose_threads(32, 8);
        const dim3 transpose_blocks(PRODUCTION_WIDTH / 32,
                                    PRODUCTION_WIDTH / 32);
        for (uint32_t layer = 0; layer < PRODUCTION_LAYERS; ++layer) {
            model.read(reinterpret_cast<char*>(encoded_layer.data()), encoded_layer.size());
            if (!model) throw std::runtime_error("read production weight layer");
            std::transform(encoded_layer.begin(), encoded_layer.end(), canonical_layer.begin(),
                           decode_model_byte);
            if (layer == 0) first_canonical_layer_ = canonical_layer;
            cuda_check(cudaMemcpy(device_canonical_layer, canonical_layer.data(),
                                  canonical_layer.size(), cudaMemcpyHostToDevice),
                       "copy canonical production weight layer");
            transpose_square_layer<<<transpose_blocks, transpose_threads>>>(
                device_canonical_layer, weights_ + size_t(layer) * layer_cells,
                PRODUCTION_WIDTH);
            cuda_check(cudaGetLastError(), "transpose production weight layer");
        }
        const size_t row_sum_count = size_t(PRODUCTION_LAYERS) * PRODUCTION_WIDTH;
        calculate_weight_row_sums<<<
            static_cast<uint32_t>((row_sum_count + THREADS - 1) / THREADS), THREADS>>>(
            weights_, device_weight_row_sums_, PRODUCTION_LAYERS, PRODUCTION_WIDTH);
        cuda_check(cudaDeviceSynchronize(), "prepare real production weights");
        cudaFree(device_canonical_layer);
    }

    std::string model_path_;
    int8_t* weights_ = nullptr;
    int8_t* device_base_ = nullptr;
    int32_t* device_weight_row_sums_ = nullptr;
    std::vector<int8_t> host_base_;
    std::vector<int8_t> first_canonical_layer_;
    size_t baseline_free_ = 0;
};

void run_production_replay(ProductionModel& model, const char* coefficient_path,
                           const char* output_prefix, bool full_trace) {
    if (output_prefix != nullptr && coefficient_path == nullptr) {
        throw std::runtime_error("V4 replay output requires exact coefficients");
    }
    model.ensure_loaded();
    const size_t cells = size_t(PRODUCTION_ROWS) * PRODUCTION_WIDTH;
    const size_t layer_cells = size_t(PRODUCTION_WIDTH) * PRODUCTION_WIDTH;
    const size_t weight_bytes = size_t(PRODUCTION_LAYERS) * layer_cells;
    const auto coefficients = load_coefficients(coefficient_path, PRODUCTION_LAYERS);

    int8_t* limbs = nullptr;
    int32_t* limb_accumulators = nullptr;
    uint32_t* preactivation_trace = nullptr;
    uint32_t* activation_trace = nullptr;
    uint32_t* device_coefficients = nullptr;
    cuda_check(cudaMalloc(&limbs, 4 * cells), "allocate production activation limbs");
    cuda_check(cudaMalloc(&limb_accumulators, 4 * cells * sizeof(int32_t)),
               "allocate production limb accumulators");
    cuda_check(cudaMalloc(&preactivation_trace,
                          (full_trace ? size_t(PRODUCTION_LAYERS) * cells : cells) *
                              sizeof(uint32_t)),
               "allocate production preactivation trace");
    cuda_check(cudaMalloc(&activation_trace,
                          (full_trace ? size_t(PRODUCTION_LAYERS + 1) * cells : cells) *
                              sizeof(uint32_t)),
               "allocate production activation trace");
    cuda_check(cudaMalloc(&device_coefficients, coefficients.size() * sizeof(uint32_t)),
               "allocate production coefficients");
    cuda_check(cudaMemcpy(device_coefficients, coefficients.data(),
                          coefficients.size() * sizeof(uint32_t), cudaMemcpyHostToDevice),
               "copy production coefficients");
    size_t free_after = 0;
    size_t total_bytes = 0;
    cuda_check(cudaMemGetInfo(&free_after, &total_bytes), "read allocated device memory");
    cudaEvent_t start{};
    cudaEvent_t stop{};
    cuda_check(cudaEventCreate(&start), "create start event");
    cuda_check(cudaEventCreate(&stop), "create stop event");
    cuda_check(cudaEventRecord(start), "record replay start");
    const uint32_t blocks = static_cast<uint32_t>((cells + THREADS - 1) / THREADS);
    initialize_activation<<<blocks, THREADS>>>(model.base(), limbs, activation_trace,
                                               device_coefficients, PRODUCTION_ROWS,
                                               PRODUCTION_WIDTH);
    for (uint32_t layer = 0; layer < PRODUCTION_LAYERS; ++layer) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            launch_gemm(limbs + size_t(limb) * cells,
                        model.weights() + size_t(layer) * layer_cells,
                        limb_accumulators + size_t(limb) * cells,
                        PRODUCTION_ROWS, PRODUCTION_WIDTH);
        }
        uint32_t* layer_preactivation = full_trace
                                            ? preactivation_trace + size_t(layer) * cells
                                            : preactivation_trace;
        uint32_t* layer_activation = full_trace
                                         ? activation_trace + size_t(layer + 1) * cells
                                         : activation_trace;
        reduce_layer<<<blocks, THREADS>>>(
            limb_accumulators, limbs, layer_preactivation, layer_activation,
            device_coefficients + size_t(layer + 1) * MASK_COEFFICIENTS,
            model.row_sums() == nullptr
                ? nullptr
                : model.row_sums() + size_t(layer) * PRODUCTION_WIDTH,
            PRODUCTION_ROWS, PRODUCTION_WIDTH);
    }
    cuda_check(cudaEventRecord(stop), "record replay stop");
    cuda_check(cudaEventSynchronize(stop), "finish production replay");
    float elapsed_ms = 0.0F;
    cuda_check(cudaEventElapsedTime(&elapsed_ms, start, stop), "measure production replay");

    std::vector<uint32_t> final_sample(16);
    const uint32_t* final_activation = full_trace
                                           ? activation_trace + size_t(PRODUCTION_LAYERS) * cells
                                           : activation_trace;
    cuda_check(cudaMemcpy(final_sample.data(), final_activation,
                          final_sample.size() * sizeof(uint32_t), cudaMemcpyDeviceToHost),
               "copy final activation sample");
    uint64_t sample_checksum = 0;
    for (uint32_t value : final_sample) {
        if (value >= KOALA_BEAR_MODULUS) {
            throw std::runtime_error("production replay emitted a noncanonical field value");
        }
        sample_checksum = sample_checksum * 1'000'003ULL + value;
    }

    if (full_trace && model.real_model()) {
        for (const auto [row, column] :
             {std::pair<uint32_t, uint32_t>{0, 0},
              std::pair<uint32_t, uint32_t>{PRODUCTION_ROWS - 1,
                                            PRODUCTION_WIDTH - 1}}) {
            int64_t dot = 0;
            for (uint32_t common = 0; common < PRODUCTION_WIDTH; ++common) {
                const size_t activation_index = size_t(row) * PRODUCTION_WIDTH + common;
                uint32_t input = canonicalize_signed(model.host_base()[activation_index]);
                const uint32_t mask = coordinate_mask(
                    coefficients.data(), row, common, 7, 12);
                input += mask;
                if (input >= KOALA_BEAR_MODULUS) input -= KOALA_BEAR_MODULUS;
                input = cube_field(input);
                dot += int64_t(input) *
                       model.first_layer()[size_t(common) * PRODUCTION_WIDTH + column];
            }
            uint32_t expected = canonicalize_signed(dot);
            expected += coordinate_mask(
                coefficients.data() + MASK_COEFFICIENTS, row, column, 7, 12);
            if (expected >= KOALA_BEAR_MODULUS) expected -= KOALA_BEAR_MODULUS;
            uint32_t actual = 0;
            cuda_check(cudaMemcpy(&actual,
                                  preactivation_trace + size_t(row) * PRODUCTION_WIDTH + column,
                                  sizeof(actual), cudaMemcpyDeviceToHost),
                       "copy real-bank differential preactivation");
            if (actual != expected) {
                throw std::runtime_error("real-bank first-layer preactivation mismatch");
            }
        }
        std::printf("real_bank_first_layer_samples=EXACT\n");
    }

    std::printf("production_shape rows=%u width=%u layers=%u\n", PRODUCTION_ROWS,
                PRODUCTION_WIDTH, PRODUCTION_LAYERS);
    std::printf("weight_gib=%.6f trace_gib=%.6f\n",
                double(weight_bytes) / double(size_t{1} << 30),
                double((size_t(2) * PRODUCTION_LAYERS + 1) * cells * sizeof(uint32_t)) /
                    double(size_t{1} << 30));
    std::printf("device_allocation_gib=%.6f\n",
                double(model.baseline_free() - free_after) / double(size_t{1} << 30));
    std::printf("replay_seconds=%.6f\n", double(elapsed_ms) / 1000.0);
    std::printf("replay_mode=%s\n", full_trace ? "full" : "search");
    std::printf("final_sample_checksum=%llu\n",
                static_cast<unsigned long long>(sample_checksum));
    if (full_trace) {
        write_replay_outputs(output_prefix, preactivation_trace, activation_trace, cells);
    } else {
        write_final_activation(output_prefix, final_activation, cells);
    }

    cudaEventDestroy(stop);
    cudaEventDestroy(start);
    cudaFree(device_coefficients);
    cudaFree(activation_trace);
    cudaFree(preactivation_trace);
    cudaFree(limb_accumulators);
    cudaFree(limbs);
}

void run_production_benchmark(const char* model_path, const char* coefficient_path,
                              const char* output_prefix) {
    if (output_prefix != nullptr && (model_path == nullptr || coefficient_path == nullptr)) {
        throw std::runtime_error(
            "writing V4 traces requires a real model and exact replay coefficients");
    }
    ProductionModel model(model_path);
    run_production_replay(model, coefficient_path, output_prefix, true);
}

std::vector<std::string> split_command(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream stream(line);
    std::string field;
    while (std::getline(stream, field, '\t')) fields.push_back(field);
    return fields;
}

void run_persistent_server(const char* model_path) {
    if (model_path == nullptr) throw std::runtime_error("server requires a model bank");
    ProductionModel model(model_path);
    std::printf("CMFD_V4_REPLAY_READY\n");
    std::fflush(stdout);
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto fields = split_command(line);
        if (fields.size() == 1 && fields[0] == "QUIT") break;
        if (fields.size() == 1 && fields[0] == "EVICT") {
            model.evict();
            std::printf("CMFD_V4_REPLAY_EVICTED\n");
            std::fflush(stdout);
            continue;
        }
        if (fields.size() != 4 || fields[0] != "RUN" ||
            (fields[1] != "search" && fields[1] != "full") || fields[2].empty() ||
            fields[3].empty()) {
            throw std::runtime_error("invalid persistent replay command");
        }
        run_production_replay(model, fields[2].c_str(), fields[3].c_str(),
                              fields[1] == "full");
        std::printf("CMFD_V4_REPLAY_DONE\n");
        std::fflush(stdout);
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        cudaDeviceProp properties{};
        cuda_check(cudaGetDeviceProperties(&properties, 0), "read CUDA device");
        std::printf("device=%s compute=%d.%d\n", properties.name, properties.major,
                    properties.minor);
        run_small_differential();
        if (argc > 1 && std::string(argv[1]) == "--server") {
            if (argc != 3) throw std::runtime_error("usage: --server MODEL");
            run_persistent_server(argv[2]);
        } else {
            run_production_benchmark(argc > 1 ? argv[1] : nullptr,
                                     argc > 2 ? argv[2] : nullptr,
                                     argc > 3 ? argv[3] : nullptr);
        }
        return 0;
    } catch (const std::exception& exception) {
        std::fprintf(stderr, "error: %s\n", exception.what());
        return 1;
    }
}
