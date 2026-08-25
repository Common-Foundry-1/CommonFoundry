#include <cuda_runtime.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef CMFD_CUTLASS_ENABLED
#define CMFD_CUTLASS_ENABLED 0
#endif

#if CMFD_CUTLASS_ENABLED
extern "C" int32_t cmfd_cutlass_int8_gemm(const int8_t* activation,
                                           const int8_t* transposed_weights,
                                           int32_t* accumulators, uint32_t rows,
                                           uint32_t width, char* error,
                                           size_t error_len);
#endif

#if defined(_WIN32)
#define CMFD_CUDA_EXPORT extern "C" __declspec(dllexport)
#else
#define CMFD_CUDA_EXPORT extern "C" __attribute__((visibility("default")))
#endif

namespace {

constexpr uint32_t API_VERSION = 1;
constexpr uint32_t MAX_WIDTH = 32;
constexpr uint32_t MAX_ROWS = 4;
constexpr uint32_t MAX_LAYERS = 4;
constexpr uint32_t MAX_ACTIVATION_VALUES = MAX_WIDTH * MAX_ROWS;
constexpr uint32_t MAX_BATCH = 65'536;
constexpr uint32_t THREADS = 128;
constexpr uint32_t PRODUCTION_ROWS = 128;
constexpr uint32_t PRODUCTION_WIDTH = 4096;
constexpr uint32_t PRODUCTION_LAYERS = 384;
constexpr uint32_t PRODUCTION_BANKS = 3;
constexpr uint32_t PRODUCTION_LAYERS_PER_BANK = 128;
constexpr uint32_t PRODUCTION_COEFFICIENTS = 20;
constexpr uint32_t PRODUCTION_STAGES = PRODUCTION_LAYERS + 1;
constexpr uint32_t PRODUCTION_MAX_NONCES = 64;
constexpr uint32_t PRODUCTION_RESIDENCY_AUTO = 0;
constexpr uint32_t PRODUCTION_RESIDENCY_FULL = 1;
constexpr uint32_t PRODUCTION_RESIDENCY_HOST = 2;
constexpr uint32_t PRODUCTION_ENGINE_AUTO = 0;
constexpr uint32_t PRODUCTION_ENGINE_DP4A = 1;
constexpr uint32_t PRODUCTION_ENGINE_TENSOR_CORE = 2;
constexpr size_t PRODUCTION_ACTIVATION_VALUES =
    size_t(PRODUCTION_ROWS) * PRODUCTION_WIDTH;
constexpr size_t PRODUCTION_LAYER_BYTES = size_t(PRODUCTION_WIDTH) * PRODUCTION_WIDTH;
constexpr size_t PRODUCTION_BANK_BYTES =
    size_t(PRODUCTION_LAYERS_PER_BANK) * PRODUCTION_LAYER_BYTES;
constexpr size_t PRODUCTION_WEIGHT_BYTES = size_t(PRODUCTION_LAYERS) * PRODUCTION_LAYER_BYTES;

static_assert(PRODUCTION_COEFFICIENTS == 1 + 7 + 12);
static_assert(PRODUCTION_WEIGHT_BYTES == size_t(6'442'450'944ULL));

struct Context {
    int device_index = 0;
    uint32_t rows = 0;
    uint32_t width = 0;
    uint32_t layers = 0;
    uint32_t coefficient_count = 0;
    uint32_t activation_len = 0;
    uint32_t capacity = 0;
    uint8_t* device_base = nullptr;
    int8_t* device_weights = nullptr;
    uint8_t* device_coefficients = nullptr;
    uint8_t* device_outputs = nullptr;

    ~Context() {
        if (device_index >= 0) cudaSetDevice(device_index);
        cudaFree(device_outputs);
        cudaFree(device_coefficients);
        cudaFree(device_weights);
        cudaFree(device_base);
    }
};

struct ProductionContext {
    int device_index = -1;
    uint32_t residency = PRODUCTION_RESIDENCY_AUTO;
    uint32_t engine = PRODUCTION_ENGINE_AUTO;
    bool finalized = false;
    size_t base_uploaded = 0;
    std::array<size_t, PRODUCTION_BANKS> bank_uploaded{};
    int8_t* device_base = nullptr;
    int8_t* device_weights = nullptr;
    std::unique_ptr<int8_t[]> host_weights;
    int8_t* device_stream_layer = nullptr;
    int8_t* device_activation_a = nullptr;
    int8_t* device_activation_b = nullptr;
    int8_t* device_transpose_layer = nullptr;
    int32_t* device_accumulators = nullptr;
    uint8_t* device_coefficients = nullptr;
    uint8_t* device_encoded_output = nullptr;
    size_t coefficient_capacity = 0;

    ~ProductionContext() {
        if (device_index >= 0) cudaSetDevice(device_index);
        cudaFree(device_encoded_output);
        cudaFree(device_coefficients);
        cudaFree(device_accumulators);
        cudaFree(device_transpose_layer);
        cudaFree(device_activation_b);
        cudaFree(device_activation_a);
        cudaFree(device_stream_layer);
        cudaFree(device_weights);
        cudaFree(device_base);
    }
};

void write_error(char* output, size_t output_len, const std::string& message) {
    if (output == nullptr || output_len == 0) return;
    const size_t copied = std::min(output_len - 1, message.size());
    std::memcpy(output, message.data(), copied);
    output[copied] = '\0';
}

void cuda_check(cudaError_t result, const char* operation) {
    if (result != cudaSuccess) {
        throw std::runtime_error(std::string(operation) + ": " + cudaGetErrorString(result));
    }
}

uint32_t exact_log2(uint32_t value) {
    if (value == 0 || (value & (value - 1)) != 0) {
        throw std::runtime_error("dimensions must be powers of two");
    }
    uint32_t bits = 0;
    while ((uint32_t{1} << bits) != value) ++bits;
    return bits;
}

void validate_canonical(const uint8_t* values, size_t length, const char* label) {
    if (values == nullptr) throw std::runtime_error(std::string(label) + " is null");
    for (size_t index = 0; index < length; ++index) {
        if (values[index] > 250) {
            throw std::runtime_error(std::string(label) + " contains a noncanonical byte");
        }
    }
}

__device__ int32_t coordinate_mask(const uint8_t* coefficients, uint32_t row, uint32_t col,
                                   uint32_t row_bits, uint32_t col_bits) {
    int32_t mask = coefficients[0];
    for (uint32_t bit = 0; bit < row_bits; ++bit) {
        if (((row >> bit) & 1U) != 0) mask += coefficients[1 + bit];
    }
    for (uint32_t bit = 0; bit < col_bits; ++bit) {
        if (((col >> bit) & 1U) != 0) mask += coefficients[1 + row_bits + bit];
    }
    return mask;
}

__device__ int8_t cubic_reduce(int32_t z) {
    constexpr uint32_t transition_modulus = 134217689;
    const uint32_t encoded =
        z >= 0 ? static_cast<uint32_t>(z)
               : static_cast<uint32_t>(int64_t(transition_modulus) + int64_t(z));
    const uint64_t square = uint64_t(encoded) * encoded;
    const uint32_t square_remainder = static_cast<uint32_t>(square % transition_modulus);
    const uint64_t cube_product = uint64_t(square_remainder) * encoded;
    const uint32_t cube_remainder = static_cast<uint32_t>(cube_product % transition_modulus);
    return static_cast<int8_t>(static_cast<int32_t>(cube_remainder % 251) - 125);
}

__device__ int32_t pack_int8x4(const int8_t* values) {
    const uint32_t packed = uint32_t(uint8_t(values[0])) |
                            (uint32_t(uint8_t(values[1])) << 8) |
                            (uint32_t(uint8_t(values[2])) << 16) |
                            (uint32_t(uint8_t(values[3])) << 24);
    return static_cast<int32_t>(packed);
}

__global__ void evaluate_batch(const uint8_t* base, const int8_t* transposed_weights,
                               const uint8_t* all_coefficients, uint8_t* outputs, uint32_t rows,
                               uint32_t width, uint32_t layers, uint32_t coefficient_count,
                               uint32_t batch_count) {
    const uint32_t nonce_index = blockIdx.x;
    if (nonce_index >= batch_count) return;

    __shared__ int8_t activation[2][MAX_ACTIVATION_VALUES];
    const uint32_t index = threadIdx.x;
    const uint32_t activation_len = rows * width;
    const uint32_t row_bits = __ffs(static_cast<int>(rows)) - 1;
    const uint32_t col_bits = __ffs(static_cast<int>(width)) - 1;
    const uint32_t stages = layers + 1;
    const uint8_t* nonce_coefficients =
        all_coefficients + size_t(nonce_index) * stages * coefficient_count;

    if (index < activation_len) {
        const uint32_t row = index / width;
        const uint32_t col = index % width;
        const int32_t z = int32_t(base[index]) - 125 +
                          coordinate_mask(nonce_coefficients, row, col, row_bits, col_bits);
        activation[0][index] = cubic_reduce(z);
    }
    __syncthreads();

    for (uint32_t layer = 0; layer < layers; ++layer) {
        const uint32_t input_bank = layer & 1U;
        const uint32_t output_bank = input_bank ^ 1U;
        if (index < activation_len) {
            const uint32_t row = index / width;
            const uint32_t col = index % width;
            const int8_t* input = &activation[input_bank][row * width];
            const int8_t* weights = transposed_weights +
                                    size_t(layer) * width * width + size_t(col) * width;
            int32_t accumulator = 0;
            uint32_t common = 0;
            for (; common + 4 <= width; common += 4) {
                accumulator = __dp4a(pack_int8x4(input + common),
                                     pack_int8x4(weights + common), accumulator);
            }
            for (; common < width; ++common) {
                accumulator += int32_t(input[common]) * int32_t(weights[common]);
            }
            const uint8_t* coefficients =
                nonce_coefficients + size_t(layer + 1) * coefficient_count;
            const int32_t z = accumulator +
                              coordinate_mask(coefficients, row, col, row_bits, col_bits);
            activation[output_bank][index] = cubic_reduce(z);
        }
        __syncthreads();
    }

    if (index < activation_len) {
        outputs[size_t(nonce_index) * activation_len + index] =
            static_cast<uint8_t>(int32_t(activation[layers & 1U][index]) + 125);
    }
}

__global__ void initialize_production_activation(const int8_t* base,
                                                 const uint8_t* coefficients,
                                                 int8_t* activation, uint32_t rows,
                                                 uint32_t width) {
    const size_t index = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t activation_len = size_t(rows) * width;
    if (index >= activation_len) return;
    const uint32_t row = static_cast<uint32_t>(index / width);
    const uint32_t col = static_cast<uint32_t>(index % width);
    const uint32_t row_bits = __ffs(static_cast<int>(rows)) - 1;
    const uint32_t col_bits = __ffs(static_cast<int>(width)) - 1;
    const int32_t z = int32_t(base[index]) +
                      coordinate_mask(coefficients, row, col, row_bits, col_bits);
    activation[index] = cubic_reduce(z);
}

__global__ void reduce_production_layer(const int32_t* accumulators,
                                        const uint8_t* coefficients, int8_t* activation,
                                        uint32_t rows, uint32_t width) {
    const size_t index = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t activation_len = size_t(rows) * width;
    if (index >= activation_len) return;
    const uint32_t row = static_cast<uint32_t>(index / width);
    const uint32_t col = static_cast<uint32_t>(index % width);
    const uint32_t row_bits = __ffs(static_cast<int>(rows)) - 1;
    const uint32_t col_bits = __ffs(static_cast<int>(width)) - 1;
    const int32_t z = accumulators[index] +
                      coordinate_mask(coefficients, row, col, row_bits, col_bits);
    activation[index] = cubic_reduce(z);
}

__global__ void encode_production_activation(const int8_t* activation, uint8_t* output,
                                              size_t length) {
    const size_t index = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index < length) output[index] = static_cast<uint8_t>(int32_t(activation[index]) + 125);
}

__global__ void transpose_square_layer(const int8_t* input, int8_t* output, uint32_t width) {
    __shared__ int8_t tile[32][33];
    const uint32_t source_col = blockIdx.x * 32 + threadIdx.x;
    const uint32_t source_row = blockIdx.y * 32 + threadIdx.y;
    for (uint32_t offset = 0; offset < 32; offset += 8) {
        if (source_col < width && source_row + offset < width) {
            tile[threadIdx.y + offset][threadIdx.x] =
                input[size_t(source_row + offset) * width + source_col];
        }
    }
    __syncthreads();
    const uint32_t target_col = blockIdx.y * 32 + threadIdx.x;
    const uint32_t target_row = blockIdx.x * 32 + threadIdx.y;
    for (uint32_t offset = 0; offset < 32; offset += 8) {
        if (target_col < width && target_row + offset < width) {
            output[size_t(target_row + offset) * width + target_col] =
                tile[threadIdx.x][threadIdx.y + offset];
        }
    }
}

__global__ void exact_int8_matrix_layer(const int8_t* activation,
                                        const int8_t* transposed_weights,
                                        int32_t* accumulators, uint32_t rows,
                                        uint32_t width) {
    extern __shared__ int8_t row_activation[];
    const uint32_t row = blockIdx.y;
    for (uint32_t common = threadIdx.x; common < width; common += blockDim.x) {
        row_activation[common] = activation[size_t(row) * width + common];
    }
    __syncthreads();
    const uint32_t col = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows || col >= width) return;
    const int8_t* weights = transposed_weights + size_t(col) * width;
    int32_t accumulator = 0;
    uint32_t common = 0;
    for (; common + 4 <= width; common += 4) {
        accumulator = __dp4a(pack_int8x4(row_activation + common),
                             pack_int8x4(weights + common), accumulator);
    }
    for (; common < width; ++common) {
        accumulator += int32_t(row_activation[common]) * int32_t(weights[common]);
    }
    accumulators[size_t(row) * width + col] = accumulator;
}

void transpose_layer(const int8_t* source, int8_t* destination, uint32_t width) {
    const dim3 threads(32, 8);
    const dim3 blocks((width + 31) / 32, (width + 31) / 32);
    transpose_square_layer<<<blocks, threads>>>(source, destination, width);
    cuda_check(cudaGetLastError(), "transpose canonical production weight layer");
}

void launch_exact_matrix_layer(const int8_t* activation, const int8_t* transposed_weights,
                               int32_t* accumulators, uint32_t rows, uint32_t width) {
    const dim3 blocks((width + THREADS - 1) / THREADS, rows);
    exact_int8_matrix_layer<<<blocks, THREADS, width>>>(activation, transposed_weights,
                                                       accumulators, rows, width);
    cuda_check(cudaGetLastError(), "evaluate exact INT8xINT8 matrix layer");
}

void launch_production_matrix_layer(uint32_t engine, const int8_t* activation,
                                    const int8_t* transposed_weights,
                                    int32_t* accumulators, uint32_t rows,
                                    uint32_t width) {
    if (engine == PRODUCTION_ENGINE_DP4A) {
        launch_exact_matrix_layer(activation, transposed_weights, accumulators, rows, width);
        return;
    }
    if (engine == PRODUCTION_ENGINE_TENSOR_CORE) {
#if CMFD_CUTLASS_ENABLED
        char error[256]{};
        if (cmfd_cutlass_int8_gemm(activation, transposed_weights, accumulators, rows,
                                   width, error, sizeof(error)) != 0) {
            throw std::runtime_error(std::string("CUTLASS tensor-core GEMM: ") + error);
        }
        return;
#else
        throw std::runtime_error("production tensor-core engine is not compiled into this library");
#endif
    }
    throw std::runtime_error("production matrix engine is invalid");
}

void ensure_production_coefficient_capacity(ProductionContext& context, size_t bytes) {
    if (context.coefficient_capacity >= bytes) return;
    cudaFree(context.device_coefficients);
    context.device_coefficients = nullptr;
    context.coefficient_capacity = 0;
    cuda_check(cudaMalloc(&context.device_coefficients, bytes),
               "allocate production mask coefficients");
    context.coefficient_capacity = bytes;
}

struct ProductionDeviceCapacity {
    size_t free_bytes;
    size_t total_bytes;
    int compute_major;
    int compute_minor;
};

ProductionDeviceCapacity validate_production_device(int device_index) {
    cuda_check(cudaSetDevice(device_index), "select CUDA device");
    cudaDeviceProp properties{};
    cuda_check(cudaGetDeviceProperties(&properties, device_index), "read CUDA device");
    if (properties.major < 7) {
        throw std::runtime_error("production CUDA backend requires compute capability 7.0+");
    }
    size_t free_bytes = 0;
    size_t total_bytes = 0;
    cuda_check(cudaMemGetInfo(&free_bytes, &total_bytes), "read CUDA memory capacity");
    return {free_bytes, total_bytes, properties.major, properties.minor};
}

uint32_t select_production_engine(uint32_t requested,
                                  const ProductionDeviceCapacity& capacity,
                                  uint32_t matrix_width) {
    if (requested != PRODUCTION_ENGINE_AUTO && requested != PRODUCTION_ENGINE_DP4A &&
        requested != PRODUCTION_ENGINE_TENSOR_CORE) {
        throw std::runtime_error("production matrix engine is invalid");
    }
    if (requested == PRODUCTION_ENGINE_TENSOR_CORE) {
#if CMFD_CUTLASS_ENABLED
        const bool tensor_capable =
            capacity.compute_major > 7 ||
            (capacity.compute_major == 7 && capacity.compute_minor >= 5);
        if (!tensor_capable) {
            throw std::runtime_error(
                "production tensor-core engine requires compute capability 7.5+");
        }
        if (matrix_width < 16 || matrix_width % 16 != 0) {
            throw std::runtime_error(
                "production tensor-core engine requires matrix width divisible by 16");
        }
        return PRODUCTION_ENGINE_TENSOR_CORE;
#else
        throw std::runtime_error("production tensor-core engine is not compiled into this library");
#endif
    }
    if (requested == PRODUCTION_ENGINE_DP4A) return PRODUCTION_ENGINE_DP4A;
#if CMFD_CUTLASS_ENABLED
    const bool tensor_capable =
        capacity.compute_major > 7 ||
        (capacity.compute_major == 7 && capacity.compute_minor >= 5);
    if (tensor_capable && matrix_width >= 16 && matrix_width % 16 == 0) {
        return PRODUCTION_ENGINE_TENSOR_CORE;
    }
#endif
    return PRODUCTION_ENGINE_DP4A;
}

size_t production_common_device_bytes(uint32_t residency) {
    size_t bytes = PRODUCTION_ACTIVATION_VALUES * 4 +
                   PRODUCTION_ACTIVATION_VALUES * sizeof(int32_t) +
                   PRODUCTION_LAYER_BYTES;
    if (residency == PRODUCTION_RESIDENCY_FULL) {
        return bytes + PRODUCTION_WEIGHT_BYTES;
    }
    if (residency == PRODUCTION_RESIDENCY_HOST) {
        return bytes + PRODUCTION_LAYER_BYTES;
    }
    throw std::runtime_error("production residency mode is invalid");
}

uint32_t select_production_residency(uint32_t requested,
                                     const ProductionDeviceCapacity& capacity) {
    if (requested != PRODUCTION_RESIDENCY_AUTO &&
        requested != PRODUCTION_RESIDENCY_FULL &&
        requested != PRODUCTION_RESIDENCY_HOST) {
        throw std::runtime_error("production residency mode is invalid");
    }
    const size_t full_required = production_common_device_bytes(PRODUCTION_RESIDENCY_FULL);
    const uint32_t selected =
        requested == PRODUCTION_RESIDENCY_AUTO
            ? (capacity.free_bytes >= full_required ? PRODUCTION_RESIDENCY_FULL
                                                    : PRODUCTION_RESIDENCY_HOST)
            : requested;
    const size_t required = production_common_device_bytes(selected);
    if (capacity.free_bytes < required) {
        throw std::runtime_error("production CUDA residency mode requires at least " +
                                 std::to_string(required) + " free device bytes; only " +
                                 std::to_string(capacity.free_bytes) + " are available");
    }
    return selected;
}

std::unique_ptr<ProductionContext> allocate_production_context(int device_index,
                                                               uint32_t requested_residency,
                                                               uint32_t requested_engine,
                                                               uint32_t* active_residency,
                                                               uint32_t* active_engine) {
    if (active_residency == nullptr || active_engine == nullptr) {
        throw std::runtime_error("active production option output is null");
    }
    *active_residency = PRODUCTION_RESIDENCY_AUTO;
    *active_engine = PRODUCTION_ENGINE_AUTO;
    const ProductionDeviceCapacity capacity = validate_production_device(device_index);
    const uint32_t residency = select_production_residency(requested_residency, capacity);
    const uint32_t engine =
        select_production_engine(requested_engine, capacity, PRODUCTION_WIDTH);

    auto context = std::make_unique<ProductionContext>();
    context->device_index = device_index;
    context->residency = residency;
    context->engine = engine;
    cuda_check(cudaMalloc(&context->device_base, PRODUCTION_ACTIVATION_VALUES),
               "allocate production base input");
    if (residency == PRODUCTION_RESIDENCY_FULL) {
        cuda_check(cudaMalloc(&context->device_weights, PRODUCTION_WEIGHT_BYTES),
                   "allocate resident production weights");
    } else {
        context->host_weights.reset(new (std::nothrow) int8_t[PRODUCTION_WEIGHT_BYTES]);
        if (!context->host_weights) {
            throw std::runtime_error("allocate host-backed production weights");
        }
        cuda_check(cudaMalloc(&context->device_stream_layer, PRODUCTION_LAYER_BYTES),
                   "allocate production streamed canonical layer");
    }
    cuda_check(cudaMalloc(&context->device_activation_a, PRODUCTION_ACTIVATION_VALUES),
               "allocate production activation A");
    cuda_check(cudaMalloc(&context->device_activation_b, PRODUCTION_ACTIVATION_VALUES),
               "allocate production activation B");
    cuda_check(cudaMalloc(&context->device_transpose_layer, PRODUCTION_LAYER_BYTES),
               "allocate production transpose staging layer");
    cuda_check(cudaMalloc(&context->device_accumulators,
                          PRODUCTION_ACTIVATION_VALUES * sizeof(int32_t)),
               "allocate production INT32 accumulators");
    cuda_check(cudaMalloc(&context->device_encoded_output, PRODUCTION_ACTIVATION_VALUES),
               "allocate production encoded output");
    *active_residency = residency;
    *active_engine = engine;
    return context;
}

void ensure_capacity(Context& context, uint32_t count) {
    if (context.capacity >= count) return;
    cudaFree(context.device_outputs);
    cudaFree(context.device_coefficients);
    context.device_outputs = nullptr;
    context.device_coefficients = nullptr;
    context.capacity = 0;

    const size_t coefficient_bytes = size_t(count) * (context.layers + 1) *
                                     context.coefficient_count;
    const size_t output_bytes = size_t(count) * context.activation_len;
    cuda_check(cudaMalloc(&context.device_coefficients, coefficient_bytes),
               "allocate batch coefficients");
    try {
        cuda_check(cudaMalloc(&context.device_outputs, output_bytes), "allocate batch outputs");
    } catch (...) {
        cudaFree(context.device_coefficients);
        context.device_coefficients = nullptr;
        throw;
    }
    context.capacity = count;
}

}  // namespace

struct CmfdCudaDeviceInfo {
    uint32_t api_version;
    int32_t device_index;
    uint32_t compute_major;
    uint32_t compute_minor;
    uint64_t total_memory_bytes;
    char name[128];
};

CMFD_CUDA_EXPORT uint32_t cmfd_cuda_api_version() { return API_VERSION; }

CMFD_CUDA_EXPORT int32_t cmfd_cuda_device_count(int32_t* count, char* error, size_t error_len) {
    try {
        if (count == nullptr) throw std::runtime_error("device count output is null");
        int value = 0;
        cuda_check(cudaGetDeviceCount(&value), "enumerate CUDA devices");
        *count = value;
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_device_info(int32_t device_index,
                                                CmfdCudaDeviceInfo* output, char* error,
                                                size_t error_len) {
    try {
        if (output == nullptr) throw std::runtime_error("device info output is null");
        cudaDeviceProp properties{};
        cuda_check(cudaGetDeviceProperties(&properties, device_index), "read CUDA device");
        std::memset(output, 0, sizeof(*output));
        output->api_version = API_VERSION;
        output->device_index = device_index;
        output->compute_major = static_cast<uint32_t>(properties.major);
        output->compute_minor = static_cast<uint32_t>(properties.minor);
        output->total_memory_bytes = static_cast<uint64_t>(properties.totalGlobalMem);
        std::strncpy(output->name, properties.name, sizeof(output->name) - 1);
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_create(
    int32_t device_index, uint32_t rows, uint32_t width, uint32_t layers,
    uint32_t coefficient_count, const uint8_t* base_input, size_t base_input_len,
    const uint8_t* weights, size_t weights_len, void** output_context, char* error,
    size_t error_len) {
    try {
        if (output_context == nullptr) throw std::runtime_error("context output is null");
        *output_context = nullptr;
        if (rows == 0 || rows > MAX_ROWS || width == 0 || width > MAX_WIDTH || layers == 0 ||
            layers > MAX_LAYERS) {
            throw std::runtime_error("CUDA backend accepts only the bounded v2 research profile");
        }
        const uint32_t row_bits = exact_log2(rows);
        const uint32_t col_bits = exact_log2(width);
        if (coefficient_count != 1 + row_bits + col_bits) {
            throw std::runtime_error("coefficient count mismatch");
        }
        const size_t activation_len = size_t(rows) * width;
        const size_t expected_weights = size_t(layers) * width * width;
        if (base_input_len != activation_len || weights_len != expected_weights) {
            throw std::runtime_error("model byte length mismatch");
        }
        validate_canonical(base_input, base_input_len, "base input");
        validate_canonical(weights, weights_len, "weights");

        cuda_check(cudaSetDevice(device_index), "select CUDA device");
        cudaDeviceProp properties{};
        cuda_check(cudaGetDeviceProperties(&properties, device_index), "read CUDA device");
        if (properties.major < 7) {
            throw std::runtime_error("CUDA device must support compute capability 7.0 or newer");
        }

        auto context = std::make_unique<Context>();
        context->device_index = device_index;
        context->rows = rows;
        context->width = width;
        context->layers = layers;
        context->coefficient_count = coefficient_count;
        context->activation_len = static_cast<uint32_t>(activation_len);

        std::vector<int8_t> transposed_weights(expected_weights);
        for (uint32_t layer = 0; layer < layers; ++layer) {
            for (uint32_t col = 0; col < width; ++col) {
                for (uint32_t common = 0; common < width; ++common) {
                    const size_t source = size_t(layer) * width * width + size_t(common) * width + col;
                    const size_t target = size_t(layer) * width * width + size_t(col) * width + common;
                    transposed_weights[target] = static_cast<int8_t>(int32_t(weights[source]) - 125);
                }
            }
        }

        cuda_check(cudaMalloc(&context->device_base, activation_len), "allocate base input");
        cuda_check(cudaMalloc(&context->device_weights, expected_weights), "allocate weights");
        cuda_check(cudaMemcpy(context->device_base, base_input, activation_len,
                              cudaMemcpyHostToDevice),
                   "copy base input");
        cuda_check(cudaMemcpy(context->device_weights, transposed_weights.data(), expected_weights,
                              cudaMemcpyHostToDevice),
                   "copy weights");
        *output_context = context.release();
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_evaluate(void* opaque_context,
                                             const uint8_t* coefficients,
                                             size_t coefficients_len, uint32_t count,
                                             uint8_t* outputs, size_t outputs_len, char* error,
                                             size_t error_len) {
    try {
        if (opaque_context == nullptr) throw std::runtime_error("CUDA context is null");
        if (count == 0 || count > MAX_BATCH) throw std::runtime_error("batch size is out of range");
        auto& context = *static_cast<Context*>(opaque_context);
        const size_t expected_coefficients =
            size_t(count) * (context.layers + 1) * context.coefficient_count;
        const size_t expected_outputs = size_t(count) * context.activation_len;
        if (coefficients == nullptr || coefficients_len != expected_coefficients ||
            outputs == nullptr || outputs_len != expected_outputs) {
            throw std::runtime_error("batch buffer length mismatch");
        }
        validate_canonical(coefficients, coefficients_len, "mask coefficients");
        cuda_check(cudaSetDevice(context.device_index), "select CUDA device");
        ensure_capacity(context, count);
        cuda_check(cudaMemcpy(context.device_coefficients, coefficients, coefficients_len,
                              cudaMemcpyHostToDevice),
                   "copy mask coefficients");
        evaluate_batch<<<count, THREADS>>>(
            context.device_base, context.device_weights, context.device_coefficients,
            context.device_outputs, context.rows, context.width, context.layers,
            context.coefficient_count, count);
        cuda_check(cudaGetLastError(), "launch ForgeMatrix v2 batch");
        cuda_check(cudaMemcpy(outputs, context.device_outputs, outputs_len, cudaMemcpyDeviceToHost),
                   "copy ForgeMatrix v2 outputs");
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT void cmfd_cuda_destroy(void* opaque_context) {
    delete static_cast<Context*>(opaque_context);
}

// The production ABI is deliberately separate from the bounded Devnet ABI.
// A caller must stream every centered model byte, in canonical role order,
// and finalize the context before evaluation is permitted. The Rust wrapper
// only exposes a finalized context after the same stream authenticates against
// the bank-authenticated Dory V3 Record V2 capability.
CMFD_CUDA_EXPORT int32_t cmfd_cuda_production_begin(int32_t device_index,
                                                    void** output_context, char* error,
                                                    size_t error_len) {
    try {
        if (output_context == nullptr) throw std::runtime_error("context output is null");
        *output_context = nullptr;
        uint32_t active_residency = PRODUCTION_RESIDENCY_AUTO;
        uint32_t active_engine = PRODUCTION_ENGINE_AUTO;
        auto context = allocate_production_context(device_index, PRODUCTION_RESIDENCY_AUTO,
                                                   PRODUCTION_ENGINE_AUTO, &active_residency,
                                                   &active_engine);
        *output_context = context.release();
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_production_begin_v2(
    int32_t device_index, uint32_t requested_residency, uint32_t* active_residency,
    void** output_context, char* error, size_t error_len) {
    try {
        if (output_context == nullptr) throw std::runtime_error("context output is null");
        *output_context = nullptr;
        uint32_t active_engine = PRODUCTION_ENGINE_AUTO;
        auto context = allocate_production_context(device_index, requested_residency,
                                                   PRODUCTION_ENGINE_AUTO, active_residency,
                                                   &active_engine);
        *output_context = context.release();
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_production_begin_v3(
    int32_t device_index, uint32_t requested_residency, uint32_t requested_engine,
    uint32_t* active_residency, uint32_t* active_engine, void** output_context,
    char* error, size_t error_len) {
    try {
        if (output_context == nullptr) throw std::runtime_error("context output is null");
        *output_context = nullptr;
        auto context = allocate_production_context(device_index, requested_residency,
                                                   requested_engine, active_residency,
                                                   active_engine);
        *output_context = context.release();
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_production_upload(
    void* opaque_context, uint32_t role, uint32_t bank_index, uint64_t role_offset,
    const int8_t* centered_values, size_t centered_values_len, char* error,
    size_t error_len) {
    try {
        if (opaque_context == nullptr) throw std::runtime_error("production context is null");
        if (centered_values == nullptr || centered_values_len == 0) {
            throw std::runtime_error("production upload is empty");
        }
        auto& context = *static_cast<ProductionContext*>(opaque_context);
        if (context.finalized) throw std::runtime_error("production context is already finalized");
        cuda_check(cudaSetDevice(context.device_index), "select CUDA device");

        int8_t* destination = nullptr;
        size_t* uploaded = nullptr;
        size_t capacity = 0;
        bool host_destination = false;
        if (role == 0) {
            if (bank_index != 0) throw std::runtime_error("base-input bank index must be zero");
            destination = context.device_base;
            uploaded = &context.base_uploaded;
            capacity = PRODUCTION_ACTIVATION_VALUES;
        } else if (role == 1) {
            if (bank_index >= PRODUCTION_BANKS) {
                throw std::runtime_error("production weight-bank index is out of range");
            }
            const size_t bank_offset = size_t(bank_index) * PRODUCTION_BANK_BYTES;
            if (context.residency == PRODUCTION_RESIDENCY_FULL) {
                destination = context.device_weights + bank_offset;
            } else if (context.residency == PRODUCTION_RESIDENCY_HOST) {
                if (!context.host_weights) {
                    throw std::runtime_error("host-backed production weights are unavailable");
                }
                destination = context.host_weights.get() + bank_offset;
                host_destination = true;
            } else {
                throw std::runtime_error("production residency mode is invalid");
            }
            uploaded = &context.bank_uploaded[bank_index];
            capacity = PRODUCTION_BANK_BYTES;
        } else {
            throw std::runtime_error("production model role is invalid");
        }
        if (*uploaded > capacity || role_offset != *uploaded ||
            centered_values_len > capacity - *uploaded) {
            throw std::runtime_error("production model chunks must be contiguous and exact");
        }
        if (host_destination) {
            std::memcpy(destination + *uploaded, centered_values, centered_values_len);
        } else {
            cuda_check(cudaMemcpy(destination + *uploaded, centered_values, centered_values_len,
                                  cudaMemcpyHostToDevice),
                       "upload authenticated production model chunk");
        }
        *uploaded += centered_values_len;
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_production_finalize(void* opaque_context, char* error,
                                                       size_t error_len) {
    try {
        if (opaque_context == nullptr) throw std::runtime_error("production context is null");
        auto& context = *static_cast<ProductionContext*>(opaque_context);
        if (context.finalized) throw std::runtime_error("production context is already finalized");
        if (context.base_uploaded != PRODUCTION_ACTIVATION_VALUES) {
            throw std::runtime_error("production base input is incomplete");
        }
        for (uint32_t bank = 0; bank < PRODUCTION_BANKS; ++bank) {
            if (context.bank_uploaded[bank] != PRODUCTION_BANK_BYTES) {
                throw std::runtime_error("production weight bank " + std::to_string(bank) +
                                         " is incomplete");
            }
        }
        cuda_check(cudaSetDevice(context.device_index), "select CUDA device");
        if (context.residency == PRODUCTION_RESIDENCY_FULL) {
            for (uint32_t layer = 0; layer < PRODUCTION_LAYERS; ++layer) {
                int8_t* weights =
                    context.device_weights + size_t(layer) * PRODUCTION_LAYER_BYTES;
                transpose_layer(weights, context.device_transpose_layer, PRODUCTION_WIDTH);
                cuda_check(cudaMemcpy(weights, context.device_transpose_layer,
                                      PRODUCTION_LAYER_BYTES, cudaMemcpyDeviceToDevice),
                           "store transposed production weight layer");
            }
        } else if (context.residency != PRODUCTION_RESIDENCY_HOST) {
            throw std::runtime_error("production residency mode is invalid");
        }
        context.finalized = true;
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_production_evaluate(
    void* opaque_context, const uint8_t* coefficients, size_t coefficients_len,
    uint32_t count, uint8_t* outputs, size_t outputs_len, char* error, size_t error_len) {
    try {
        if (opaque_context == nullptr) throw std::runtime_error("production context is null");
        if (count == 0 || count > PRODUCTION_MAX_NONCES) {
            throw std::runtime_error("production nonce batch must be between 1 and 64");
        }
        auto& context = *static_cast<ProductionContext*>(opaque_context);
        if (!context.finalized) throw std::runtime_error("production model is not authenticated");
        const size_t coefficients_per_nonce =
            size_t(PRODUCTION_STAGES) * PRODUCTION_COEFFICIENTS;
        const size_t expected_coefficients = size_t(count) * coefficients_per_nonce;
        const size_t expected_outputs = size_t(count) * PRODUCTION_ACTIVATION_VALUES;
        if (coefficients == nullptr || coefficients_len != expected_coefficients ||
            outputs == nullptr || outputs_len != expected_outputs) {
            throw std::runtime_error("production batch buffer length mismatch");
        }
        validate_canonical(coefficients, coefficients_len, "production mask coefficients");
        cuda_check(cudaSetDevice(context.device_index), "select CUDA device");
        ensure_production_coefficient_capacity(context, expected_coefficients);
        cuda_check(cudaMemcpy(context.device_coefficients, coefficients, coefficients_len,
                              cudaMemcpyHostToDevice),
                   "copy production mask coefficients");

        const uint32_t blocks = static_cast<uint32_t>(
            (PRODUCTION_ACTIVATION_VALUES + THREADS - 1) / THREADS);
        for (uint32_t nonce = 0; nonce < count; ++nonce) {
            const uint8_t* nonce_coefficients =
                context.device_coefficients + size_t(nonce) * coefficients_per_nonce;
            initialize_production_activation<<<blocks, THREADS>>>(
                context.device_base, nonce_coefficients, context.device_activation_a,
                PRODUCTION_ROWS, PRODUCTION_WIDTH);
            cuda_check(cudaGetLastError(), "launch production input transition");

            int8_t* current = context.device_activation_a;
            int8_t* next = context.device_activation_b;
            for (uint32_t layer = 0; layer < PRODUCTION_LAYERS; ++layer) {
                const int8_t* weights = nullptr;
                if (context.residency == PRODUCTION_RESIDENCY_FULL) {
                    weights =
                        context.device_weights + size_t(layer) * PRODUCTION_LAYER_BYTES;
                } else if (context.residency == PRODUCTION_RESIDENCY_HOST) {
                    const int8_t* host_layer =
                        context.host_weights.get() + size_t(layer) * PRODUCTION_LAYER_BYTES;
                    cuda_check(cudaMemcpy(context.device_stream_layer, host_layer,
                                          PRODUCTION_LAYER_BYTES, cudaMemcpyHostToDevice),
                               "stream authenticated production weight layer");
                    transpose_layer(context.device_stream_layer,
                                    context.device_transpose_layer, PRODUCTION_WIDTH);
                    weights = context.device_transpose_layer;
                } else {
                    throw std::runtime_error("production residency mode is invalid");
                }
                launch_production_matrix_layer(context.engine, current, weights,
                                               context.device_accumulators,
                                               PRODUCTION_ROWS, PRODUCTION_WIDTH);
                reduce_production_layer<<<blocks, THREADS>>>(
                    context.device_accumulators,
                    nonce_coefficients + size_t(layer + 1) * PRODUCTION_COEFFICIENTS, next,
                    PRODUCTION_ROWS, PRODUCTION_WIDTH);
                cuda_check(cudaGetLastError(), "launch production layer transition");
                std::swap(current, next);
            }
            encode_production_activation<<<blocks, THREADS>>>(
                current, context.device_encoded_output, PRODUCTION_ACTIVATION_VALUES);
            cuda_check(cudaGetLastError(), "launch production output encoding");
            cuda_check(cudaMemcpy(outputs + size_t(nonce) * PRODUCTION_ACTIVATION_VALUES,
                                  context.device_encoded_output, PRODUCTION_ACTIVATION_VALUES,
                                  cudaMemcpyDeviceToHost),
                       "copy production ForgeMatrix output");
        }
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT void cmfd_cuda_production_destroy(void* opaque_context) {
    delete static_cast<ProductionContext*>(opaque_context);
}

// Qualification seam: execute one exact matrix/transition layer at any valid
// power-of-two research or production shape. It shares the same DP4A and
// reduction routines as the production evaluator and is never called by the
// mining path.
int32_t differential_layer_impl(
    int32_t device_index, uint32_t requested_residency, uint32_t* active_residency,
    uint32_t requested_engine, uint32_t* active_engine, uint32_t rows, uint32_t width,
    const int8_t* activation, size_t activation_len, const int8_t* weights,
    size_t weights_len, const uint8_t* coefficients, size_t coefficients_len,
    uint8_t* output, size_t output_len, char* error, size_t error_len) {
    int8_t* device_activation = nullptr;
    int8_t* device_weights = nullptr;
    int8_t* device_transposed_weights = nullptr;
    int32_t* device_accumulators = nullptr;
    int8_t* device_output = nullptr;
    uint8_t* device_encoded = nullptr;
    uint8_t* device_coefficients = nullptr;
    try {
        if (active_residency == nullptr || active_engine == nullptr) {
            throw std::runtime_error("active differential option output is null");
        }
        *active_residency = PRODUCTION_RESIDENCY_AUTO;
        *active_engine = PRODUCTION_ENGINE_AUTO;
        if (rows == 0 || rows > PRODUCTION_ROWS || width == 0 || width > PRODUCTION_WIDTH) {
            throw std::runtime_error("differential dimensions exceed production geometry");
        }
        const uint32_t row_bits = exact_log2(rows);
        const uint32_t col_bits = exact_log2(width);
        const size_t expected_activation = size_t(rows) * width;
        const size_t expected_weights = size_t(width) * width;
        const size_t expected_coefficients = 1 + row_bits + col_bits;
        if (activation == nullptr || activation_len != expected_activation ||
            weights == nullptr || weights_len != expected_weights || coefficients == nullptr ||
            coefficients_len != expected_coefficients || output == nullptr ||
            output_len != expected_activation) {
            throw std::runtime_error("differential layer buffer length mismatch");
        }
        validate_canonical(coefficients, coefficients_len, "differential mask coefficients");
        const ProductionDeviceCapacity capacity = validate_production_device(device_index);
        const uint32_t residency =
            select_production_residency(requested_residency, capacity);
        const uint32_t engine = select_production_engine(requested_engine, capacity, width);
        std::unique_ptr<int8_t[]> host_weights;
        if (residency == PRODUCTION_RESIDENCY_HOST) {
            host_weights.reset(new (std::nothrow) int8_t[expected_weights]);
            if (!host_weights) throw std::runtime_error("allocate differential host weights");
            std::memcpy(host_weights.get(), weights, expected_weights);
        }
        cuda_check(cudaMalloc(&device_activation, expected_activation),
                   "allocate differential activation");
        cuda_check(cudaMalloc(&device_weights, expected_weights),
                   "allocate differential weights");
        cuda_check(cudaMalloc(&device_transposed_weights, expected_weights),
                   "allocate differential transposed weights");
        cuda_check(cudaMalloc(&device_accumulators, expected_activation * sizeof(int32_t)),
                   "allocate differential accumulators");
        cuda_check(cudaMalloc(&device_output, expected_activation),
                   "allocate differential output");
        cuda_check(cudaMalloc(&device_encoded, expected_activation),
                   "allocate differential encoding");
        cuda_check(cudaMalloc(&device_coefficients, expected_coefficients),
                   "allocate differential coefficients");
        cuda_check(cudaMemcpy(device_activation, activation, expected_activation,
                              cudaMemcpyHostToDevice),
                   "copy differential activation");
        const int8_t* weight_source =
            residency == PRODUCTION_RESIDENCY_HOST ? host_weights.get() : weights;
        cuda_check(
            cudaMemcpy(device_weights, weight_source, expected_weights, cudaMemcpyHostToDevice),
            residency == PRODUCTION_RESIDENCY_HOST ? "stream differential host weights"
                                                   : "copy differential resident weights");
        cuda_check(cudaMemcpy(device_coefficients, coefficients, expected_coefficients,
                              cudaMemcpyHostToDevice),
                   "copy differential coefficients");
        transpose_layer(device_weights, device_transposed_weights, width);
        launch_production_matrix_layer(engine, device_activation, device_transposed_weights,
                                       device_accumulators, rows, width);
        const uint32_t blocks =
            static_cast<uint32_t>((expected_activation + THREADS - 1) / THREADS);
        reduce_production_layer<<<blocks, THREADS>>>(device_accumulators, device_coefficients,
                                                    device_output, rows, width);
        cuda_check(cudaGetLastError(), "launch differential transition");
        encode_production_activation<<<blocks, THREADS>>>(device_output, device_encoded,
                                                         expected_activation);
        cuda_check(cudaGetLastError(), "launch differential output encoding");
        cuda_check(cudaMemcpy(output, device_encoded, expected_activation,
                              cudaMemcpyDeviceToHost),
                   "copy differential output");
        cudaFree(device_coefficients);
        cudaFree(device_encoded);
        cudaFree(device_output);
        cudaFree(device_accumulators);
        cudaFree(device_transposed_weights);
        cudaFree(device_weights);
        cudaFree(device_activation);
        *active_residency = residency;
        *active_engine = engine;
        return 0;
    } catch (const std::exception& exception) {
        cudaFree(device_coefficients);
        cudaFree(device_encoded);
        cudaFree(device_output);
        cudaFree(device_accumulators);
        cudaFree(device_transposed_weights);
        cudaFree(device_weights);
        cudaFree(device_activation);
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_differential_layer(
    int32_t device_index, uint32_t rows, uint32_t width, const int8_t* activation,
    size_t activation_len, const int8_t* weights, size_t weights_len,
    const uint8_t* coefficients, size_t coefficients_len, uint8_t* output,
    size_t output_len, char* error, size_t error_len) {
    uint32_t active_residency = PRODUCTION_RESIDENCY_AUTO;
    uint32_t active_engine = PRODUCTION_ENGINE_AUTO;
    return differential_layer_impl(
        device_index, PRODUCTION_RESIDENCY_AUTO, &active_residency, PRODUCTION_ENGINE_AUTO,
        &active_engine, rows, width, activation, activation_len, weights, weights_len,
        coefficients, coefficients_len, output, output_len, error, error_len);
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_differential_layer_v2(
    int32_t device_index, uint32_t requested_residency, uint32_t* active_residency,
    uint32_t rows, uint32_t width, const int8_t* activation, size_t activation_len,
    const int8_t* weights, size_t weights_len, const uint8_t* coefficients,
    size_t coefficients_len, uint8_t* output, size_t output_len, char* error,
    size_t error_len) {
    uint32_t active_engine = PRODUCTION_ENGINE_AUTO;
    return differential_layer_impl(
        device_index, requested_residency, active_residency, PRODUCTION_ENGINE_AUTO,
        &active_engine, rows, width, activation, activation_len, weights, weights_len,
        coefficients, coefficients_len, output, output_len, error, error_len);
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_differential_layer_v3(
    int32_t device_index, uint32_t requested_residency, uint32_t* active_residency,
    uint32_t requested_engine, uint32_t* active_engine, uint32_t rows, uint32_t width,
    const int8_t* activation, size_t activation_len, const int8_t* weights,
    size_t weights_len, const uint8_t* coefficients, size_t coefficients_len,
    uint8_t* output, size_t output_len, char* error, size_t error_len) {
    return differential_layer_impl(
        device_index, requested_residency, active_residency, requested_engine, active_engine,
        rows, width, activation, activation_len, weights, weights_len, coefficients,
        coefficients_len, output, output_len, error, error_len);
}
