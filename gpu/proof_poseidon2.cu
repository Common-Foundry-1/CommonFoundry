// Standalone, non-consensus CUDA canary for the first ValMmcs digest layer.
//
// Poseidon2 parameters, round constants, and PaddingFreeSponge semantics are
// derived from Plonky3 v0.6.3 (Copyright Plonky3 contributors), licensed under
// MIT OR Apache-2.0. The CUDA and host implementations below were written for
// Common Foundry and intentionally share only the pinned constants.

#include <cuda_runtime.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#if defined(CMFD_POSEIDON2_BACKEND_LIBRARY)
#if defined(_WIN32)
#define CMFD_POSEIDON2_EXPORT extern "C" __declspec(dllexport)
#else
#define CMFD_POSEIDON2_EXPORT \
  extern "C" __attribute__((visibility("default")))
#endif
#else
#define CMFD_POSEIDON2_EXPORT extern "C"
#endif

// C ABI v1 descriptor. Each view is a canonical Goldilocks row-major matrix.
// The first-digest input for physical row r is the ordered concatenation of
// matrices[0].row(r), matrices[1].row(r), ... . Buffer lengths count u64s.
struct CmfdProofPoseidon2MatrixViewV1 {
  const std::uint64_t* values;
  std::size_t values_len;
  std::uint32_t rows;
  std::uint32_t columns;
};

namespace {

using u32 = std::uint32_t;
using u64 = std::uint64_t;

constexpr u64 kGoldilocksPrime = UINT64_C(0xffffffff00000001);
constexpr u64 kEpsilon = UINT64_C(0x00000000ffffffff);
constexpr u64 kHalf = UINT64_C(0x7fffffff80000001);
constexpr std::size_t kDigestWidth = 4;
constexpr std::size_t kStateWidth = 8;
constexpr std::size_t kRate = 4;
constexpr std::size_t kMaxRows = std::size_t{1} << 24;
constexpr std::size_t kMaxRowWidth = 4096;
constexpr std::size_t kMaxInputElements = std::size_t{1} << 31;
constexpr std::size_t kRowsPerLaunch = std::size_t{1} << 16;
constexpr std::size_t kMaxMatrices = 64;
constexpr int kThreads = 256;
constexpr u32 kPoseidon2ApiVersion = 1;
constexpr u64 kPoseidon2ContextMagic = UINT64_C(0x434d4644504f5332);

struct Poseidon2Context {
  u64 magic = kPoseidon2ContextMagic;
  int device_index = -1;
  std::mutex operation_mutex;
};

// Plonky3 0.6.3 GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL.
constexpr std::array<u64, 32> kExternalInitial = {
    UINT64_C(0xdd5743e7f2a5a5d9), UINT64_C(0xcb3a864e58ada44b),
    UINT64_C(0xffa2449ed32f8cdc), UINT64_C(0x42025f65d6bd13ee),
    UINT64_C(0x7889175e25506323), UINT64_C(0x34b98bb03d24b737),
    UINT64_C(0xbdcc535ecc4faa2a), UINT64_C(0x5b20ad869fc0d033),
    UINT64_C(0xf1dda5b9259dfcb4), UINT64_C(0x27515210be112d59),
    UINT64_C(0x4227d1718c766c3f), UINT64_C(0x26d333161a5bd794),
    UINT64_C(0x49b938957bf4b026), UINT64_C(0x4a56b5938b213669),
    UINT64_C(0x1120426b48c8353d), UINT64_C(0x6b323c3f10a56cad),
    UINT64_C(0xce57d6245ddca6b2), UINT64_C(0xb1fc8d402bba1eb1),
    UINT64_C(0xb5c5096ca959bd04), UINT64_C(0x6db55cd306d31f7f),
    UINT64_C(0xc49d293a81cb9641), UINT64_C(0x1ce55a4fe979719f),
    UINT64_C(0xa92e60a9d178a4d1), UINT64_C(0x002cc64973bcfd8c),
    UINT64_C(0xcea721cce82fb11b), UINT64_C(0xe5b55eb8098ece81),
    UINT64_C(0x4e30525c6f1ddd66), UINT64_C(0x43c6702827070987),
    UINT64_C(0xaca68430a7b5762a), UINT64_C(0x3674238634df9c93),
    UINT64_C(0x88cee1c825e33433), UINT64_C(0xde99ae8d74b57176),
};

// Plonky3 0.6.3 GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL.
constexpr std::array<u64, 32> kExternalFinal = {
    UINT64_C(0x014ef1197d341346), UINT64_C(0x9725e20825d07394),
    UINT64_C(0xfdb25aef2c5bae3b), UINT64_C(0xbe5402dc598c971e),
    UINT64_C(0x93a5711f04cdca3d), UINT64_C(0xc45a9a5b2f8fb97b),
    UINT64_C(0xfe8946a924933545), UINT64_C(0x2af997a27369091c),
    UINT64_C(0xaa62c88e0b294011), UINT64_C(0x058eb9d810ce9f74),
    UINT64_C(0xb3cb23eced349ae4), UINT64_C(0xa3648177a77b4a84),
    UINT64_C(0x43153d905992d95d), UINT64_C(0xf4e2a97cda44aa4b),
    UINT64_C(0x5baa2702b908682f), UINT64_C(0x082923bdf4f750d1),
    UINT64_C(0x98ae09a325893803), UINT64_C(0xf8a6475077968838),
    UINT64_C(0xceb0735bf00b2c5f), UINT64_C(0x0a1a5d953888e072),
    UINT64_C(0x2fcb190489f94475), UINT64_C(0xb5be06270dec69fc),
    UINT64_C(0x739cb934b09acf8b), UINT64_C(0x537750b75ec7f25b),
    UINT64_C(0xe9dd318bae1f3961), UINT64_C(0xf7462137299efe1a),
    UINT64_C(0xb1f6b8eee9adb940), UINT64_C(0xbdebcc8a809dfe6b),
    UINT64_C(0x40fc1f791b178113), UINT64_C(0x3ac1c3362d014864),
    UINT64_C(0x9a016184bdb8aeba), UINT64_C(0x95f2394459fbc25e),
};

// Plonky3 0.6.3 GOLDILOCKS_POSEIDON2_RC_8_INTERNAL.
constexpr std::array<u64, 22> kInternal = {
    UINT64_C(0x488897d85ff51f56), UINT64_C(0x1140737ccb162218),
    UINT64_C(0xa7eeb9215866ed35), UINT64_C(0x9bd2976fee49fcc9),
    UINT64_C(0xc0c8f0de580a3fcc), UINT64_C(0x4fb2dae6ee8fc793),
    UINT64_C(0x343a89f35f37395b), UINT64_C(0x223b525a77ca72c8),
    UINT64_C(0x56ccb62574aaa918), UINT64_C(0xc4d507d8027af9ed),
    UINT64_C(0xa080673cf0b7e95c), UINT64_C(0xf0184884eb70dcf8),
    UINT64_C(0x044f10b0cb3d5c69), UINT64_C(0xe9e3f7993938f186),
    UINT64_C(0x1b761c80e772f459), UINT64_C(0x606cec607a1b5fac),
    UINT64_C(0x14a0c2e1d45f03cd), UINT64_C(0x4eace8855398574f),
    UINT64_C(0xf905ca7103eff3e6), UINT64_C(0xf8c8f8d20862c059),
    UINT64_C(0xb524fe8bdd678e5a), UINT64_C(0xfbb7865901a1ec41),
};

__device__ __constant__ u64 kDeviceExternalInitial[32];
__device__ __constant__ u64 kDeviceExternalFinal[32];
__device__ __constant__ u64 kDeviceInternal[22];

[[noreturn]] void fail(const std::string& message) {
  throw std::runtime_error(message);
}

void write_error(char* output, std::size_t output_len,
                 const char* message) noexcept {
  if (output == nullptr || output_len == 0) {
    return;
  }
  std::size_t copied = 0;
  while (copied + 1 < output_len && message[copied] != '\0') {
    output[copied] = message[copied];
    ++copied;
  }
  output[copied] = '\0';
}

template <typename Function>
std::int32_t abi_guard(char* error, std::size_t error_len,
                       Function&& function) noexcept {
  write_error(error, error_len, "");
  try {
    function();
    return 0;
  } catch (const std::exception& exception) {
    write_error(error, error_len, exception.what());
    return 1;
  } catch (...) {
    write_error(error, error_len, "unknown Poseidon2 CUDA backend failure");
    return 1;
  }
}

void cuda_check(cudaError_t status, const char* operation) {
  if (status != cudaSuccess) {
    const std::string message =
        std::string(operation) + ": " + cudaGetErrorString(status);
    (void)cudaGetLastError();
    fail(message);
  }
}

void cuda_cleanup_warn(cudaError_t status, const char* operation) noexcept {
  if (status != cudaSuccess) {
    std::fprintf(stderr, "WARN: %s during Poseidon2 CUDA cleanup: %s\n",
                 operation, cudaGetErrorString(status));
  }
}

#define CUDA_CHECK(operation) cuda_check((operation), #operation)

class DeviceBuffer {
 public:
  explicit DeviceBuffer(std::size_t bytes) {
    if (bytes == 0) {
      fail("zero-byte CUDA allocation rejected");
    }
    CUDA_CHECK(cudaMalloc(&pointer_, bytes));
  }

  DeviceBuffer(const DeviceBuffer&) = delete;
  DeviceBuffer& operator=(const DeviceBuffer&) = delete;

  ~DeviceBuffer() {
    if (pointer_ != nullptr) {
      cuda_cleanup_warn(cudaFree(pointer_), "cudaFree");
    }
  }

  u64* data() { return static_cast<u64*>(pointer_); }

 private:
  void* pointer_ = nullptr;
};

class CudaEvent {
 public:
  CudaEvent() { CUDA_CHECK(cudaEventCreate(&event_)); }
  CudaEvent(const CudaEvent&) = delete;
  CudaEvent& operator=(const CudaEvent&) = delete;
  ~CudaEvent() {
    if (event_ != nullptr) {
      cuda_cleanup_warn(cudaEventDestroy(event_), "cudaEventDestroy");
    }
  }
  cudaEvent_t get() const { return event_; }

 private:
  cudaEvent_t event_ = nullptr;
};

struct Shape {
  std::size_t rows;
  std::size_t width;
  std::size_t input_elements;
  std::size_t output_elements;
  std::size_t input_bytes;
  std::size_t output_bytes;
};

Shape checked_shape(std::size_t rows, std::size_t width,
                    std::size_t input_len, std::size_t output_len) {
  if (rows == 0) {
    fail("Poseidon2 row count must be nonzero");
  }
  if (width == 0) {
    fail("Poseidon2 row width must be nonzero");
  }
  if (rows > kMaxRows) {
    fail("Poseidon2 row count exceeds the canary limit");
  }
  if (width > kMaxRowWidth) {
    fail("Poseidon2 row width exceeds the canary limit");
  }
  if (rows > std::numeric_limits<std::size_t>::max() / width) {
    fail("Poseidon2 input element count overflow");
  }
  const std::size_t input_elements = rows * width;
  if (input_elements > kMaxInputElements) {
    fail("Poseidon2 input element count exceeds the canary limit");
  }
  if (rows > std::numeric_limits<std::size_t>::max() / kDigestWidth) {
    fail("Poseidon2 output element count overflow");
  }
  const std::size_t output_elements = rows * kDigestWidth;
  if (input_elements > std::numeric_limits<std::size_t>::max() / sizeof(u64) ||
      output_elements > std::numeric_limits<std::size_t>::max() / sizeof(u64)) {
    fail("Poseidon2 byte count overflow");
  }
  if (input_len != input_elements) {
    fail("Poseidon2 input length does not equal rows times width");
  }
  if (output_len != output_elements) {
    fail("Poseidon2 output length does not equal rows times four");
  }
  return {rows, width, input_elements, output_elements,
          input_elements * sizeof(u64), output_elements * sizeof(u64)};
}

Shape checked_matrix_views(const CmfdProofPoseidon2MatrixViewV1* matrices,
                           std::size_t matrix_count, std::size_t rows,
                           std::size_t output_len) {
  if (matrix_count == 0) {
    fail("Poseidon2 matrix count must be nonzero");
  }
  if (matrix_count > kMaxMatrices) {
    fail("Poseidon2 matrix count exceeds the ABI v1 limit");
  }
  if (matrices == nullptr) {
    fail("Poseidon2 matrix view array is null");
  }
  if (rows == 0) {
    fail("Poseidon2 row count must be nonzero");
  }
  if (rows > kMaxRows) {
    fail("Poseidon2 row count exceeds the ABI v1 limit");
  }

  std::size_t total_width = 0;
  for (std::size_t index = 0; index < matrix_count; ++index) {
    const auto& matrix = matrices[index];
    if (matrix.rows != rows) {
      fail("Poseidon2 matrix row count does not match the requested rows at view " +
           std::to_string(index));
    }
    if (matrix.columns == 0) {
      fail("Poseidon2 matrix column count must be nonzero at view " +
           std::to_string(index));
    }
    if (matrix.columns > kMaxRowWidth ||
        total_width > kMaxRowWidth - matrix.columns) {
      fail("Poseidon2 concatenated row width exceeds the ABI v1 limit");
    }
    const std::size_t expected_len = rows * matrix.columns;
    if (matrix.values_len != expected_len) {
      fail("Poseidon2 matrix length does not equal rows times columns at view " +
           std::to_string(index));
    }
    if (matrix.values == nullptr) {
      fail("Poseidon2 matrix values are null at view " +
           std::to_string(index));
    }
    total_width += matrix.columns;
  }

  const std::size_t input_len = rows * total_width;
  return checked_shape(rows, total_width, input_len, output_len);
}

void validate_canonical(const u64* values, std::size_t length,
                        const char* label) {
  if (values == nullptr) {
    fail(std::string(label) + " is null");
  }
  for (std::size_t index = 0; index < length; ++index) {
    if (values[index] >= kGoldilocksPrime) {
      fail(std::string(label) +
           " contains a noncanonical Goldilocks limb at index " +
           std::to_string(index));
    }
  }
}

u64 host_add(u64 lhs, u64 rhs) {
  const u64 gap = kGoldilocksPrime - rhs;
  return lhs >= gap ? lhs - gap : lhs + rhs;
}

// Independent multiplication oracle: repeated doubling deliberately avoids
// the CUDA __umul64hi reduction used by the kernel.
u64 host_mul(u64 lhs, u64 rhs) {
  u64 result = 0;
  while (rhs != 0) {
    if ((rhs & 1U) != 0) {
      result = host_add(result, lhs);
    }
    rhs >>= 1;
    if (rhs != 0) {
      lhs = host_add(lhs, lhs);
    }
  }
  return result;
}

u64 host_sbox(u64 value) {
  const u64 square = host_mul(value, value);
  const u64 fourth = host_mul(square, square);
  return host_mul(host_mul(fourth, square), value);
}

void host_external_linear(std::array<u64, kStateWidth>& state) {
  constexpr u32 matrix[4][4] = {
      {2, 3, 1, 1},
      {1, 2, 3, 1},
      {1, 1, 2, 3},
      {3, 1, 1, 2},
  };
  std::array<u64, kStateWidth> local{};
  for (std::size_t chunk = 0; chunk < 2; ++chunk) {
    for (std::size_t row = 0; row < 4; ++row) {
      u64 sum = 0;
      for (std::size_t column = 0; column < 4; ++column) {
        for (u32 copy = 0; copy < matrix[row][column]; ++copy) {
          sum = host_add(sum, state[chunk * 4 + column]);
        }
      }
      local[chunk * 4 + row] = sum;
    }
  }
  for (std::size_t column = 0; column < 4; ++column) {
    const u64 sum = host_add(local[column], local[column + 4]);
    state[column] = host_add(local[column], sum);
    state[column + 4] = host_add(local[column + 4], sum);
  }
}

void host_external_rounds(std::array<u64, kStateWidth>& state,
                          const std::array<u64, 32>& constants) {
  for (std::size_t round = 0; round < 4; ++round) {
    for (std::size_t lane = 0; lane < kStateWidth; ++lane) {
      state[lane] =
          host_sbox(host_add(state[lane], constants[round * 8 + lane]));
    }
    host_external_linear(state);
  }
}

void host_internal_linear(std::array<u64, kStateWidth>& state) {
  constexpr std::array<u64, 8> diagonal = {
      UINT64_C(0xfffffffeffffffff), UINT64_C(0x0000000000000001),
      UINT64_C(0x0000000000000002), UINT64_C(0x7fffffff80000001),
      UINT64_C(0x0000000000000003), UINT64_C(0x7fffffff80000000),
      UINT64_C(0xfffffffefffffffe), UINT64_C(0xfffffffefffffffd),
  };
  u64 sum = 0;
  for (u64 value : state) {
    sum = host_add(sum, value);
  }
  for (std::size_t lane = 0; lane < state.size(); ++lane) {
    state[lane] = host_add(sum, host_mul(state[lane], diagonal[lane]));
  }
}

void host_permute(std::array<u64, kStateWidth>& state) {
  host_external_linear(state);
  host_external_rounds(state, kExternalInitial);
  for (u64 round_constant : kInternal) {
    state[0] = host_sbox(host_add(state[0], round_constant));
    host_internal_linear(state);
  }
  host_external_rounds(state, kExternalFinal);
}

std::array<u64, kDigestWidth> host_hash_row(const u64* row,
                                            std::size_t width) {
  validate_canonical(row, width, "host Poseidon2 input");
  std::array<u64, kStateWidth> state{};
  for (std::size_t offset = 0; offset < width; offset += kRate) {
    const std::size_t absorbed = std::min(kRate, width - offset);
    for (std::size_t lane = 0; lane < absorbed; ++lane) {
      state[lane] = row[offset + lane];
    }
    host_permute(state);
  }
  return {state[0], state[1], state[2], state[3]};
}

std::vector<u64> host_hash_rows(const std::vector<u64>& input,
                                std::size_t rows, std::size_t width) {
  const std::size_t output_len =
      rows <= kMaxRows ? rows * kDigestWidth : 0;
  checked_shape(rows, width, input.size(), output_len);
  validate_canonical(input.data(), input.size(), "host Poseidon2 input");
  std::vector<u64> output(output_len);
  for (std::size_t row = 0; row < rows; ++row) {
    const auto digest = host_hash_row(input.data() + row * width, width);
    std::copy(digest.begin(), digest.end(),
              output.begin() + row * kDigestWidth);
  }
  return output;
}

__device__ __forceinline__ u64 device_add(u64 lhs, u64 rhs) {
  u64 result = lhs + rhs;
  if (result < lhs) {
    result += kEpsilon;
  } else if (result >= kGoldilocksPrime) {
    result -= kGoldilocksPrime;
  }
  return result;
}

__device__ __forceinline__ u64 device_sub(u64 lhs, u64 rhs) {
  return lhs >= rhs ? lhs - rhs : kGoldilocksPrime - (rhs - lhs);
}

__device__ __forceinline__ u64 device_mul(u64 lhs, u64 rhs) {
  const u64 low = lhs * rhs;
  const u64 high = __umul64hi(lhs, rhs);
  const u64 high_high = high >> 32;
  const u64 high_low = high & kEpsilon;

  u64 folded = low - high_high;
  if (low < high_high) {
    folded -= kEpsilon;
  }
  const u64 correction = high_low * kEpsilon;
  const u64 before = folded;
  folded += correction;
  if (folded < before) {
    folded += kEpsilon;
  }
  return folded >= kGoldilocksPrime ? folded - kGoldilocksPrime : folded;
}

__device__ __forceinline__ u64 device_sbox(u64 value) {
  const u64 square = device_mul(value, value);
  const u64 fourth = device_mul(square, square);
  return device_mul(device_mul(fourth, square), value);
}

__device__ __forceinline__ u64 device_half(u64 value) {
  return (value >> 1) + ((value & 1U) != 0 ? kHalf : 0);
}

__device__ __forceinline__ void device_mat4(u64* values) {
  const u64 x0 = values[0];
  const u64 x1 = values[1];
  const u64 x2 = values[2];
  const u64 x3 = values[3];
  const u64 t01 = device_add(x0, x1);
  const u64 t23 = device_add(x2, x3);
  const u64 t0123 = device_add(t01, t23);
  const u64 t01123 = device_add(t0123, x1);
  const u64 t01233 = device_add(t0123, x3);
  values[3] = device_add(t01233, device_add(x0, x0));
  values[1] = device_add(t01123, device_add(x2, x2));
  values[0] = device_add(t01123, t01);
  values[2] = device_add(t01233, t23);
}

__device__ __forceinline__ void device_external_linear(u64 state[8]) {
  device_mat4(state);
  device_mat4(state + 4);
#pragma unroll
  for (int lane = 0; lane < 4; ++lane) {
    const u64 sum = device_add(state[lane], state[lane + 4]);
    state[lane] = device_add(state[lane], sum);
    state[lane + 4] = device_add(state[lane + 4], sum);
  }
}

__device__ __forceinline__ void device_internal_linear(u64 state[8]) {
  u64 sum = 0;
#pragma unroll
  for (int lane = 0; lane < 8; ++lane) {
    sum = device_add(sum, state[lane]);
  }
  const u64 x0 = state[0];
  const u64 x1 = state[1];
  const u64 x2 = state[2];
  const u64 x3 = state[3];
  const u64 x4 = state[4];
  const u64 x5 = state[5];
  const u64 x6 = state[6];
  const u64 x7 = state[7];
  state[0] = device_sub(sum, device_add(x0, x0));
  state[1] = device_add(sum, x1);
  state[2] = device_add(sum, device_add(x2, x2));
  state[3] = device_add(sum, device_half(x3));
  state[4] = device_add(sum, device_add(device_add(x4, x4), x4));
  state[5] = device_sub(sum, device_half(x5));
  state[6] = device_sub(sum, device_add(device_add(x6, x6), x6));
  state[7] = device_sub(sum, device_add(device_add(x7, x7),
                                        device_add(x7, x7)));
}

__device__ __forceinline__ void device_external_rounds(
    u64 state[8], const u64* constants) {
#pragma unroll
  for (int round = 0; round < 4; ++round) {
#pragma unroll
    for (int lane = 0; lane < 8; ++lane) {
      state[lane] =
          device_sbox(device_add(state[lane], constants[round * 8 + lane]));
    }
    device_external_linear(state);
  }
}

__device__ __forceinline__ void device_permute(u64 state[8]) {
  device_external_linear(state);
  device_external_rounds(state, kDeviceExternalInitial);
#pragma unroll
  for (int round = 0; round < 22; ++round) {
    state[0] = device_sbox(device_add(state[0], kDeviceInternal[round]));
    device_internal_linear(state);
  }
  device_external_rounds(state, kDeviceExternalFinal);
}

__global__ void hash_rows_kernel(const u64* input, u64* output,
                                 std::size_t row_start,
                                 std::size_t row_count,
                                 std::size_t width) {
  const std::size_t local_row =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (local_row >= row_count) {
    return;
  }
  const std::size_t row = row_start + local_row;
  const u64* row_input = input + row * width;
  u64 state[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (std::size_t offset = 0; offset < width; offset += 4) {
    const std::size_t absorbed = width - offset < 4 ? width - offset : 4;
#pragma unroll
    for (int lane = 0; lane < 4; ++lane) {
      if (static_cast<std::size_t>(lane) < absorbed) {
        state[lane] = row_input[offset + lane];
      }
    }
    device_permute(state);
  }
  u64* digest = output + row * 4;
#pragma unroll
  for (int lane = 0; lane < 4; ++lane) {
    digest[lane] = state[lane];
  }
}

unsigned launch_blocks(std::size_t count) {
  const std::size_t blocks = (count + kThreads - 1) / kThreads;
  if (blocks == 0 ||
      blocks > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    fail("Poseidon2 CUDA launch grid is outside the supported range");
  }
  return static_cast<unsigned>(blocks);
}

void load_device_constants() {
  CUDA_CHECK(cudaMemcpyToSymbol(kDeviceExternalInitial, kExternalInitial.data(),
                                sizeof(kExternalInitial)));
  CUDA_CHECK(cudaMemcpyToSymbol(kDeviceExternalFinal, kExternalFinal.data(),
                                sizeof(kExternalFinal)));
  CUDA_CHECK(cudaMemcpyToSymbol(kDeviceInternal, kInternal.data(),
                                sizeof(kInternal)));
}

Poseidon2Context& checked_context(void* opaque_context) {
  if (opaque_context == nullptr) {
    fail("Poseidon2 CUDA context is null");
  }
  auto& context = *static_cast<Poseidon2Context*>(opaque_context);
  if (context.magic != kPoseidon2ContextMagic || context.device_index < 0) {
    fail("Poseidon2 CUDA context is invalid");
  }
  return context;
}

void execute_first_digest_layer(
    const CmfdProofPoseidon2MatrixViewV1* matrices,
    std::size_t matrix_count, std::size_t rows, u64* output,
    std::size_t output_len) {
  const Shape shape =
      checked_matrix_views(matrices, matrix_count, rows, output_len);
  if (output == nullptr) {
    fail("Poseidon2 first-digest output is null");
  }
  for (std::size_t index = 0; index < matrix_count; ++index) {
    validate_canonical(matrices[index].values, matrices[index].values_len,
                       "Poseidon2 matrix input");
  }

  load_device_constants();
  DeviceBuffer device_input(shape.input_bytes);
  DeviceBuffer device_output(shape.output_bytes);

  std::size_t column_offset = 0;
  for (std::size_t index = 0; index < matrix_count; ++index) {
    const auto& matrix = matrices[index];
    CUDA_CHECK(cudaMemcpy2DAsync(
        device_input.data() + column_offset, shape.width * sizeof(u64),
        matrix.values, static_cast<std::size_t>(matrix.columns) * sizeof(u64),
        static_cast<std::size_t>(matrix.columns) * sizeof(u64), rows,
        cudaMemcpyHostToDevice));
    column_offset += matrix.columns;
  }

  for (std::size_t row_start = 0; row_start < rows;
       row_start += kRowsPerLaunch) {
    const std::size_t row_count =
        std::min(kRowsPerLaunch, rows - row_start);
    hash_rows_kernel<<<launch_blocks(row_count), kThreads>>>(
        device_input.data(), device_output.data(), row_start, row_count,
        shape.width);
    CUDA_CHECK(cudaGetLastError());
  }
  CUDA_CHECK(cudaMemcpyAsync(output, device_output.data(), shape.output_bytes,
                             cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaStreamSynchronize(0));
  validate_canonical(output, output_len, "Poseidon2 first-digest output");
}

struct GpuHashResult {
  std::vector<u64> output;
  float h2d_ms = 0;
  float kernel_ms = 0;
  float d2h_ms = 0;
};

GpuHashResult gpu_hash_rows(const u64* input, std::size_t input_len,
                            std::size_t rows, std::size_t width) {
  const std::size_t output_len =
      rows <= kMaxRows ? rows * kDigestWidth : 0;
  const Shape shape = checked_shape(rows, width, input_len, output_len);
  validate_canonical(input, input_len, "GPU Poseidon2 input");
  load_device_constants();

  DeviceBuffer device_input(shape.input_bytes);
  DeviceBuffer device_output(shape.output_bytes);
  GpuHashResult result;
  result.output.resize(shape.output_elements);

  CudaEvent start;
  CudaEvent after_copy;
  CudaEvent after_kernel;
  CudaEvent finished;
  CUDA_CHECK(cudaEventRecord(start.get()));
  CUDA_CHECK(cudaMemcpyAsync(device_input.data(), input, shape.input_bytes,
                             cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaEventRecord(after_copy.get()));

  for (std::size_t row_start = 0; row_start < rows;
       row_start += kRowsPerLaunch) {
    const std::size_t row_count =
        std::min(kRowsPerLaunch, rows - row_start);
    hash_rows_kernel<<<launch_blocks(row_count), kThreads>>>(
        device_input.data(), device_output.data(), row_start, row_count, width);
    CUDA_CHECK(cudaGetLastError());
  }
  CUDA_CHECK(cudaEventRecord(after_kernel.get()));
  CUDA_CHECK(cudaMemcpyAsync(result.output.data(), device_output.data(),
                             shape.output_bytes, cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaEventRecord(finished.get()));
  CUDA_CHECK(cudaEventSynchronize(finished.get()));
  CUDA_CHECK(cudaEventElapsedTime(&result.h2d_ms, start.get(),
                                  after_copy.get()));
  CUDA_CHECK(cudaEventElapsedTime(&result.kernel_ms, after_copy.get(),
                                  after_kernel.get()));
  CUDA_CHECK(cudaEventElapsedTime(&result.d2h_ms, after_kernel.get(),
                                  finished.get()));
  validate_canonical(result.output.data(), result.output.size(),
                     "GPU Poseidon2 output");
  return result;
}

}  // namespace

// Poseidon2 CUDA ABI v1 is independent of the DFT ABI in the same shared
// artifact. Calls on one context serialize internally. Callers must not race
// destroy against an operation. This operation returns only the unpadded
// physical rows; the MerkleTree hook retains Plonky3's zero digest padding.
CMFD_POSEIDON2_EXPORT std::uint32_t
cmfd_proof_poseidon2_api_version() noexcept {
  return kPoseidon2ApiVersion;
}

CMFD_POSEIDON2_EXPORT std::int32_t cmfd_proof_poseidon2_create(
    std::int32_t device_index, void** output_context, char* error,
    std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    if (output_context == nullptr) {
      fail("Poseidon2 context output is null");
    }
    *output_context = nullptr;
    int device_count = 0;
    CUDA_CHECK(cudaGetDeviceCount(&device_count));
    if (device_index < 0 || device_index >= device_count) {
      fail("Poseidon2 CUDA device index is out of range");
    }
    CUDA_CHECK(cudaSetDevice(device_index));
    cudaDeviceProp properties{};
    CUDA_CHECK(cudaGetDeviceProperties(&properties, device_index));
    if (properties.major < 7) {
      fail("Poseidon2 CUDA backend requires compute capability 7.0 or newer");
    }
    auto context = std::make_unique<Poseidon2Context>();
    context->device_index = device_index;
    *output_context = context.release();
  });
}

CMFD_POSEIDON2_EXPORT std::int32_t
cmfd_proof_poseidon2_first_digest_layer(
    void* opaque_context,
    const CmfdProofPoseidon2MatrixViewV1* matrices,
    std::size_t matrix_count, std::uint32_t rows, std::uint64_t* output,
    std::size_t output_len, char* error, std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    Poseidon2Context& context = checked_context(opaque_context);
    std::lock_guard<std::mutex> lock(context.operation_mutex);
    CUDA_CHECK(cudaSetDevice(context.device_index));
    execute_first_digest_layer(matrices, matrix_count, rows, output,
                               output_len);
  });
}

CMFD_POSEIDON2_EXPORT void
cmfd_proof_poseidon2_destroy(void* opaque_context) noexcept {
  if (opaque_context == nullptr) {
    return;
  }
  auto* context = static_cast<Poseidon2Context*>(opaque_context);
  context->magic = 0;
  context->device_index = -1;
  delete context;
}

namespace {

void compare_exact(const std::vector<u64>& expected,
                   const std::vector<u64>& actual,
                   const std::string& label) {
  if (expected.size() != actual.size()) {
    fail(label + " output length mismatch");
  }
  for (std::size_t index = 0; index < expected.size(); ++index) {
    if (expected[index] != actual[index]) {
      fail(label + " mismatch at limb " + std::to_string(index) +
           ": expected " + std::to_string(expected[index]) + ", got " +
           std::to_string(actual[index]));
    }
  }
}

u64 fixture_value(std::size_t index, u64 salt) {
  u64 value = static_cast<u64>(index) + salt;
  value ^= value >> 12;
  value ^= value << 25;
  value ^= value >> 27;
  value *= UINT64_C(0x2545f4914f6cdd1d);
  return value >= kGoldilocksPrime ? value - kGoldilocksPrime : value;
}

void run_plonky3_fixtures() {
  struct Fixture {
    std::size_t width;
    std::array<u64, 4> digest;
  };
  constexpr u64 salt = UINT64_C(0x123456789abcdef0);
  constexpr std::array<Fixture, 5> fixtures = {{
      {1,
       {UINT64_C(7668073106091160635), UINT64_C(8186641118638216760),
        UINT64_C(6457284654664772022), UINT64_C(5770619367258960679)}},
      {4,
       {UINT64_C(11126648771938909578), UINT64_C(13035621986393488367),
        UINT64_C(4678693851439491810), UINT64_C(875937718037293451)}},
      {8,
       {UINT64_C(17634486255809933696), UINT64_C(15766679345631357503),
        UINT64_C(16584936375404369965), UINT64_C(18186598152891123503)}},
      {87,
       {UINT64_C(10725271548208625869), UINT64_C(17474902801359862501),
        UINT64_C(2635340078653449537), UINT64_C(7180112465085594324)}},
      {291,
       {UINT64_C(13843296229019507427), UINT64_C(1099202951096753247),
        UINT64_C(12685862824277584409), UINT64_C(2349131546407372023)}},
  }};

  for (const Fixture& fixture : fixtures) {
    std::vector<u64> input(fixture.width);
    for (std::size_t index = 0; index < fixture.width; ++index) {
      input[index] = fixture_value(index, salt);
    }
    const auto host = host_hash_rows(input, 1, fixture.width);
    const std::vector<u64> expected(fixture.digest.begin(),
                                    fixture.digest.end());
    compare_exact(expected, host,
                  "Plonky3 0.6.3 host width " +
                      std::to_string(fixture.width));
    const auto gpu = gpu_hash_rows(input.data(), input.size(), 1, fixture.width);
    compare_exact(expected, gpu.output,
                  "Plonky3 0.6.3 CUDA width " +
                      std::to_string(fixture.width));
  }
  std::printf("PASS Plonky3 0.6.3 fixed vectors (widths 1, 4, 8, 87, 291)\n");
}

void run_pattern_tests() {
  constexpr std::array<std::size_t, 5> widths = {1, 4, 8, 87, 291};
  constexpr std::size_t rows = 6;
  for (std::size_t width : widths) {
    std::vector<u64> input(rows * width, 0);
    for (std::size_t column = 0; column < width; ++column) {
      input[width + column] = 1;
      input[2 * width + column] = kGoldilocksPrime - 1;
      input[4 * width + column] =
          (column & 1U) == 0 ? 0 : kGoldilocksPrime - 1;
      input[5 * width + column] =
          fixture_value(column, UINT64_C(0xd1b54a32d192ed03) ^ width);
    }
    input[3 * width] = 1;
    input[4 * width - 1] = kGoldilocksPrime - 1;

    const auto expected = host_hash_rows(input, rows, width);
    const auto gpu = gpu_hash_rows(input.data(), input.size(), rows, width);
    compare_exact(expected, gpu.output,
                  "batched pattern width " + std::to_string(width));
  }
  std::printf("PASS exact batched zero/one/p-1/impulse/alternating/random rows\n");
}

void require_abi_success(std::int32_t status, const char* operation,
                         const char* error) {
  if (status != 0) {
    fail(std::string(operation) + " failed through C ABI: " + error);
  }
}

void require_abi_failure(std::int32_t status, const char* operation,
                         const char* error) {
  if (status == 0 || error == nullptr || error[0] == '\0') {
    fail(std::string(operation) +
         " did not fail with a bounded C ABI error");
  }
}

void run_c_abi_tests(int device) {
  if (cmfd_proof_poseidon2_api_version() != kPoseidon2ApiVersion) {
    fail("Poseidon2 CUDA C ABI reported the wrong API version");
  }
  char error[192] = {};
  void* context = nullptr;
  require_abi_failure(
      cmfd_proof_poseidon2_create(device, nullptr, error, sizeof(error)),
      "null Poseidon2 context output", error);
  void* invalid_device_context = reinterpret_cast<void*>(UINTPTR_MAX);
  require_abi_failure(cmfd_proof_poseidon2_create(
                          -1, &invalid_device_context, error, sizeof(error)),
                      "invalid Poseidon2 device", error);
  if (invalid_device_context != nullptr) {
    fail("Poseidon2 create did not clear context output on failure");
  }
  require_abi_success(cmfd_proof_poseidon2_create(
                          device, &context, error, sizeof(error)),
                      "Poseidon2 create", error);
  if (context == nullptr) {
    fail("Poseidon2 C ABI returned a null context");
  }

  try {
    constexpr std::size_t rows = 7;
    constexpr std::array<std::size_t, 3> widths = {1, 4, 3};
    std::array<std::vector<u64>, 3> inputs;
    for (std::size_t matrix = 0; matrix < inputs.size(); ++matrix) {
      inputs[matrix].resize(rows * widths[matrix]);
      for (std::size_t index = 0; index < inputs[matrix].size(); ++index) {
        inputs[matrix][index] = fixture_value(
            index, UINT64_C(0x6a09e667f3bcc909) ^
                       (static_cast<u64>(matrix) << 40));
      }
    }
    std::array<CmfdProofPoseidon2MatrixViewV1, 3> views{};
    for (std::size_t matrix = 0; matrix < views.size(); ++matrix) {
      views[matrix] = {inputs[matrix].data(), inputs[matrix].size(),
                       static_cast<u32>(rows),
                       static_cast<u32>(widths[matrix])};
    }

    std::vector<u64> expected(rows * kDigestWidth);
    std::vector<u64> logical_row;
    logical_row.reserve(8);
    for (std::size_t row = 0; row < rows; ++row) {
      logical_row.clear();
      for (std::size_t matrix = 0; matrix < inputs.size(); ++matrix) {
        const auto begin = inputs[matrix].begin() + row * widths[matrix];
        logical_row.insert(logical_row.end(), begin, begin + widths[matrix]);
      }
      const auto digest = host_hash_row(logical_row.data(), logical_row.size());
      std::copy(digest.begin(), digest.end(),
                expected.begin() + row * kDigestWidth);
    }
    std::vector<u64> output(expected.size());
    require_abi_success(cmfd_proof_poseidon2_first_digest_layer(
                            context, views.data(), views.size(), rows,
                            output.data(), output.size(), error, sizeof(error)),
                        "multi-matrix first digest", error);
    compare_exact(expected, output,
                  "C ABI multi-matrix physical-row first digest");

    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            nullptr, views.data(), views.size(), rows,
                            output.data(), output.size(), error, sizeof(error)),
                        "null Poseidon2 context", error);
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, nullptr, views.size(), rows, output.data(),
                            output.size(), error, sizeof(error)),
                        "null matrix views", error);
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, views.data(), 0, rows, output.data(),
                            output.size(), error, sizeof(error)),
                        "zero matrix views", error);
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, views.data(), kMaxMatrices + 1, rows,
                            output.data(), output.size(), error, sizeof(error)),
                        "excess matrix views", error);
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, views.data(), views.size(), 0,
                            output.data(), output.size(), error, sizeof(error)),
                        "zero first-digest rows", error);

    auto invalid_views = views;
    invalid_views[1].rows = static_cast<u32>(rows - 1);
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, invalid_views.data(), invalid_views.size(),
                            rows, output.data(), output.size(), error,
                            sizeof(error)),
                        "mismatched matrix rows", error);
    invalid_views = views;
    invalid_views[1].columns = 0;
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, invalid_views.data(), invalid_views.size(),
                            rows, output.data(), output.size(), error,
                            sizeof(error)),
                        "zero matrix columns", error);
    invalid_views = views;
    --invalid_views[1].values_len;
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, invalid_views.data(), invalid_views.size(),
                            rows, output.data(), output.size(), error,
                            sizeof(error)),
                        "short matrix input", error);
    invalid_views = views;
    invalid_views[1].values = nullptr;
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, invalid_views.data(), invalid_views.size(),
                            rows, output.data(), output.size(), error,
                            sizeof(error)),
                        "null matrix input", error);

    const u64 scalar = 0;
    CmfdProofPoseidon2MatrixViewV1 wide_view{
        &scalar, kMaxRowWidth + 1, 1,
        static_cast<u32>(kMaxRowWidth + 1)};
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, &wide_view, 1, 1, output.data(),
                            output.size(), error, sizeof(error)),
                        "first-digest width cap", error);
    CmfdProofPoseidon2MatrixViewV1 oversized_view{
        &scalar, kMaxRows * 291, static_cast<u32>(kMaxRows), 291};
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, &oversized_view, 1,
                            static_cast<u32>(kMaxRows), output.data(),
                            output.size(), error, sizeof(error)),
                        "first-digest element cap", error);
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, views.data(), views.size(), rows, nullptr,
                            output.size(), error, sizeof(error)),
                        "null first-digest output", error);
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, views.data(), views.size(), rows,
                            output.data(), output.size() - 1, error,
                            sizeof(error)),
                        "short first-digest output", error);

    auto noncanonical_input = inputs[0];
    noncanonical_input[2] = kGoldilocksPrime;
    invalid_views = views;
    invalid_views[0].values = noncanonical_input.data();
    require_abi_failure(cmfd_proof_poseidon2_first_digest_layer(
                            context, invalid_views.data(), invalid_views.size(),
                            rows, output.data(), output.size(), error,
                            sizeof(error)),
                        "noncanonical first-digest input", error);

    char bounded_error[8];
    std::fill(std::begin(bounded_error), std::end(bounded_error), 'X');
    if (cmfd_proof_poseidon2_first_digest_layer(
            context, nullptr, views.size(), rows, output.data(), output.size(),
            bounded_error, sizeof(bounded_error)) == 0 ||
        bounded_error[sizeof(bounded_error) - 1] != '\0') {
      fail("Poseidon2 C ABI did not bound and terminate its error string");
    }
  } catch (...) {
    cmfd_proof_poseidon2_destroy(context);
    throw;
  }
  cmfd_proof_poseidon2_destroy(context);
  cmfd_proof_poseidon2_destroy(nullptr);
  std::printf(
      "PASS Poseidon2 C ABI v1: lifecycle, ordered multi-matrix rows, nulls, "
      "caps, shapes, canonicality, bounded errors, and exact output\n");
}

template <typename Function>
void expect_rejection(const char* label, const char* expected,
                      Function&& function) {
  try {
    function();
  } catch (const std::exception& exception) {
    if (std::string(exception.what()).find(expected) == std::string::npos) {
      fail(std::string(label) + " returned the wrong error: " +
           exception.what());
    }
    return;
  }
  fail(std::string(label) + " was not rejected");
}

void run_rejection_tests() {
  expect_rejection("zero rows", "row count must be nonzero", [] {
    checked_shape(0, 1, 0, 0);
  });
  expect_rejection("zero width", "row width must be nonzero", [] {
    checked_shape(1, 0, 0, 4);
  });
  expect_rejection("excess rows", "row count exceeds", [] {
    checked_shape(kMaxRows + 1, 1, kMaxRows + 1,
                  (kMaxRows + 1) * kDigestWidth);
  });
  expect_rejection("excess width", "row width exceeds", [] {
    checked_shape(1, kMaxRowWidth + 1, kMaxRowWidth + 1, kDigestWidth);
  });
  expect_rejection("excess elements", "input element count exceeds", [] {
    checked_shape(kMaxRows, 291, kMaxRows * 291,
                  kMaxRows * kDigestWidth);
  });
  expect_rejection("wrong input length", "input length", [] {
    checked_shape(2, 4, 7, 8);
  });
  expect_rejection("wrong output length", "output length", [] {
    checked_shape(2, 4, 8, 7);
  });
  expect_rejection("null input", "is null", [] {
    validate_canonical(nullptr, 1, "test input");
  });
  expect_rejection("modulus limb", "noncanonical", [] {
    const u64 value = kGoldilocksPrime;
    validate_canonical(&value, 1, "test input");
  });
  expect_rejection("maximum limb", "noncanonical", [] {
    const u64 value = std::numeric_limits<u64>::max();
    validate_canonical(&value, 1, "test input");
  });
  expect_rejection("GPU path wrong input length", "input length", [] {
    const u64 value = 0;
    (void)gpu_hash_rows(&value, 1, 1, 2);
  });
  expect_rejection("GPU path null input", "is null", [] {
    (void)gpu_hash_rows(nullptr, 1, 1, 1);
  });
  expect_rejection("GPU path noncanonical limb", "noncanonical", [] {
    const u64 value = kGoldilocksPrime;
    (void)gpu_hash_rows(&value, 1, 1, 1);
  });
  std::printf("PASS null/noncanonical/bounds/shape rejection gates\n");
}

void verify_benchmark_samples(const std::vector<u64>& input,
                              const std::vector<u64>& output,
                              std::size_t rows, std::size_t width) {
  const std::array<std::size_t, 4> samples = {
      0, rows / 3, (rows * 2) / 3, rows - 1};
  for (std::size_t row : samples) {
    const auto expected = host_hash_row(input.data() + row * width, width);
    for (std::size_t lane = 0; lane < kDigestWidth; ++lane) {
      if (expected[lane] != output[row * kDigestWidth + lane]) {
        fail("large benchmark sample mismatch at row " +
             std::to_string(row) + ", lane " + std::to_string(lane));
      }
    }
  }
}

bool run_large_benchmark(std::size_t width) {
  constexpr std::size_t rows = std::size_t{1} << 22;
  const std::size_t input_elements = rows * width;
  const std::size_t output_elements = rows * kDigestWidth;
  const Shape shape = checked_shape(rows, width, input_elements,
                                    output_elements);
  std::size_t free_bytes = 0;
  std::size_t total_bytes = 0;
  CUDA_CHECK(cudaMemGetInfo(&free_bytes, &total_bytes));
  constexpr std::size_t reserve = std::size_t{256} << 20;
  if (shape.input_bytes > free_bytes ||
      shape.output_bytes > free_bytes -
                               std::min(free_bytes, shape.input_bytes) ||
      shape.input_bytes + shape.output_bytes + reserve > free_bytes) {
    std::printf(
        "SKIP 4,194,304x%zu: needs %.3f GiB plus reserve, %.3f GiB free\n",
        width,
        static_cast<double>(shape.input_bytes + shape.output_bytes) /
            static_cast<double>(UINT64_C(1) << 30),
        static_cast<double>(free_bytes) /
            static_cast<double>(UINT64_C(1) << 30));
    return false;
  }

  std::printf("Preparing 4,194,304x%zu input (%.3f GiB)...\n", width,
              static_cast<double>(shape.input_bytes) /
                  static_cast<double>(UINT64_C(1) << 30));
  const auto fill_start = std::chrono::steady_clock::now();
  std::vector<u64> input;
  try {
    input.resize(input_elements);
  } catch (const std::bad_alloc&) {
    std::printf("SKIP 4,194,304x%zu: host allocation failed\n", width);
    return false;
  }
  for (std::size_t index = 0; index < input.size(); ++index) {
    input[index] = static_cast<u64>(index + width);
  }
  const auto fill_end = std::chrono::steady_clock::now();
  const double fill_seconds =
      std::chrono::duration<double>(fill_end - fill_start).count();

  const GpuHashResult gpu =
      gpu_hash_rows(input.data(), input.size(), rows, width);
  verify_benchmark_samples(input, gpu.output, rows, width);
  const double permutations =
      static_cast<double>(rows) * static_cast<double>((width + 3) / 4);
  const double kernel_seconds = static_cast<double>(gpu.kernel_ms) / 1000.0;
  std::printf(
      "BENCH 4,194,304x%zu: fill %.3f s, H2D %.3f ms, kernel %.3f ms, "
      "D2H %.3f ms, %.3f M rows/s, %.3f M permutations/s, %.3f GiB/s\n",
      width, fill_seconds, gpu.h2d_ms, gpu.kernel_ms, gpu.d2h_ms,
      static_cast<double>(rows) / kernel_seconds / 1.0e6,
      permutations / kernel_seconds / 1.0e6,
      static_cast<double>(shape.input_bytes) / kernel_seconds /
          static_cast<double>(UINT64_C(1) << 30));
  return true;
}

int parse_device(const char* text) {
  if (text == nullptr || *text == '\0') {
    fail("--device requires a nonnegative integer");
  }
  char* end = nullptr;
  const long value = std::strtol(text, &end, 10);
  if (*end != '\0' || value < 0 || value > std::numeric_limits<int>::max()) {
    fail("--device requires a nonnegative integer");
  }
  return static_cast<int>(value);
}

void print_usage(const char* executable) {
  std::printf("Usage: %s [--device N] [--large-benchmark]\n", executable);
}

}  // namespace

#if !defined(CMFD_POSEIDON2_BACKEND_LIBRARY)
int main(int argc, char** argv) {
  try {
    int device = 0;
    bool large_benchmark = false;
    for (int index = 1; index < argc; ++index) {
      const std::string argument = argv[index];
      if (argument == "--device") {
        if (++index >= argc) {
          fail("--device requires a value");
        }
        device = parse_device(argv[index]);
      } else if (argument == "--large-benchmark") {
        large_benchmark = true;
      } else if (argument == "--help" || argument == "-h") {
        print_usage(argv[0]);
        return 0;
      } else {
        fail("unknown argument: " + argument);
      }
    }

    int device_count = 0;
    CUDA_CHECK(cudaGetDeviceCount(&device_count));
    if (device_count <= 0) {
      fail("no CUDA devices are available");
    }
    if (device >= device_count) {
      fail("requested CUDA device is not available");
    }
    CUDA_CHECK(cudaSetDevice(device));
    cudaDeviceProp properties{};
    CUDA_CHECK(cudaGetDeviceProperties(&properties, device));
    std::printf("Poseidon2 exact CUDA canary on device %d: %s (sm_%d%d)\n",
                device, properties.name, properties.major, properties.minor);

    run_rejection_tests();
    run_plonky3_fixtures();
    run_pattern_tests();
    run_c_abi_tests(device);
    if (large_benchmark) {
      run_large_benchmark(87);
      run_large_benchmark(291);
    }
    std::printf("PASS all Poseidon2 exact CUDA canary checks\n");
    return 0;
  } catch (const std::exception& exception) {
    std::fprintf(stderr, "FAIL Poseidon2 exact CUDA canary: %s\n",
                 exception.what());
    return 1;
  } catch (...) {
    std::fprintf(stderr, "FAIL Poseidon2 exact CUDA canary: unknown error\n");
    return 1;
  }
}
#endif
