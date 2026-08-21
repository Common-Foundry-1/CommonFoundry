// Optional, non-consensus CUDA backend and standalone canary for exact
// Goldilocks DFT acceleration.
//
// The shared library is independently versioned and is never loaded
// automatically by the node, wallet, miner, or verifier. The executable tests
// integer-only CUDA arithmetic against an independent host oracle and exits
// nonzero on every mismatch or CUDA failure.

#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#if defined(CMFD_PROOF_BACKEND_LIBRARY)
#if defined(_WIN32)
#define CMFD_PROOF_EXPORT extern "C" __declspec(dllexport)
#else
#define CMFD_PROOF_EXPORT extern "C" __attribute__((visibility("default")))
#endif
#else
#define CMFD_PROOF_EXPORT extern "C"
#endif

struct CmfdProofCudaDeviceInfo {
  std::uint32_t api_version;
  std::int32_t device_index;
  std::uint32_t compute_major;
  std::uint32_t compute_minor;
  std::uint64_t total_memory_bytes;
  char name[128];
};

namespace {

using u64 = std::uint64_t;

constexpr u64 kGoldilocksPrime = UINT64_C(0xffffffff00000001);
constexpr u64 kEpsilon = UINT64_C(0x00000000ffffffff);
constexpr u64 kGenerator = UINT64_C(7);
constexpr int kThreads = 256;
constexpr std::uint32_t kProofApiVersion = 2;
constexpr std::size_t kMaxHeight = std::size_t{1} << 24;
// Plonky3's supported one-block BLAKE3 AIR is 9,168 columns wide.
constexpr std::size_t kMaxWidth = std::size_t{1} << 14;
constexpr std::size_t kMaxElements = std::size_t{1} << 31;
constexpr u64 kProofContextMagic = UINT64_C(0x434d464450524f4f);

enum class RowOrder : std::uint32_t {
  kNatural = 0,
  kBitReversed = 1,
};

struct ProofContext {
  u64 magic = kProofContextMagic;
  int device_index = -1;
  std::mutex operation_mutex;
};

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
    write_error(error, error_len, "unknown CUDA proof backend failure");
    return 1;
  }
}

void cuda_check(cudaError_t status, const char* operation) {
  if (status != cudaSuccess) {
    fail(std::string(operation) + ": " + cudaGetErrorString(status));
  }
}

void cuda_cleanup_warn(cudaError_t status, const char* operation) noexcept {
  if (status != cudaSuccess) {
    std::fprintf(stderr, "WARN: %s during CUDA proof cleanup: %s\n", operation,
                 cudaGetErrorString(status));
  }
}

#define CUDA_CHECK(operation) cuda_check((operation), #operation)

class DeviceBuffer {
 public:
  explicit DeviceBuffer(std::size_t bytes) : bytes_(bytes) {
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

  void* raw() { return pointer_; }
  u64* data() { return static_cast<u64*>(pointer_); }
  std::size_t bytes() const { return bytes_; }

 private:
  void* pointer_ = nullptr;
  std::size_t bytes_ = 0;
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

bool is_power_of_two(std::size_t value) {
  return value != 0 && (value & (value - 1)) == 0;
}

unsigned strict_log2(std::size_t value) {
  if (!is_power_of_two(value)) {
    fail("DFT height must be a nonzero power of two");
  }
  unsigned result = 0;
  while (value > 1) {
    value >>= 1;
    ++result;
  }
  return result;
}

std::size_t checked_elements(std::size_t height, std::size_t width) {
  if (height == 0 || width == 0) {
    fail("DFT height and width must be nonzero");
  }
  if (height > std::numeric_limits<std::size_t>::max() / width) {
    fail("DFT element count overflow");
  }
  const std::size_t elements = height * width;
  if (elements > std::numeric_limits<std::size_t>::max() / sizeof(u64)) {
    fail("DFT byte count overflow");
  }
  return elements;
}

std::size_t checked_backend_elements(std::uint32_t height,
                                     std::uint32_t width) {
  if (height > kMaxHeight || width > kMaxWidth) {
    fail("proof transform dimensions exceed the ABI v2 limits");
  }
  const std::size_t elements = checked_elements(height, width);
  if (elements > kMaxElements) {
    fail("proof transform element count exceeds the ABI v2 limit");
  }
  const unsigned log_height = strict_log2(height);
  if (log_height > 24) {
    fail("proof transform height exceeds the ABI v2 two-adic limit");
  }
  return elements;
}

RowOrder parse_row_order(std::uint32_t value) {
  if (value == static_cast<std::uint32_t>(RowOrder::kNatural)) {
    return RowOrder::kNatural;
  }
  if (value == static_cast<std::uint32_t>(RowOrder::kBitReversed)) {
    return RowOrder::kBitReversed;
  }
  fail("row order must be 0 (natural) or 1 (physical bit-reversed)");
}

void validate_canonical(const u64* values, std::size_t length,
                        const char* label) {
  if (values == nullptr) {
    fail(std::string(label) + " is null");
  }
  for (std::size_t index = 0; index < length; ++index) {
    if (values[index] >= kGoldilocksPrime) {
      fail(std::string(label) + " contains a noncanonical Goldilocks limb at index " +
           std::to_string(index));
    }
  }
}

void validate_canonical(const std::vector<u64>& values) {
  validate_canonical(values.data(), values.size(), "Goldilocks input");
}

u64 host_add(u64 lhs, u64 rhs) {
  if (lhs >= kGoldilocksPrime || rhs >= kGoldilocksPrime) {
    fail("host_add received noncanonical input");
  }
  const u64 gap = kGoldilocksPrime - rhs;
  return lhs >= gap ? lhs - gap : lhs + rhs;
}

u64 host_sub(u64 lhs, u64 rhs) {
  if (lhs >= kGoldilocksPrime || rhs >= kGoldilocksPrime) {
    fail("host_sub received noncanonical input");
  }
  return lhs >= rhs ? lhs - rhs : kGoldilocksPrime - (rhs - lhs);
}

// Independent multiplication oracle: repeated doubling uses no 128-bit
// reduction and therefore does not share the CUDA multiplication algorithm.
u64 host_mul_oracle(u64 lhs, u64 rhs) {
  if (lhs >= kGoldilocksPrime || rhs >= kGoldilocksPrime) {
    fail("host_mul_oracle received noncanonical input");
  }
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

u64 host_reduce_product(u64 low, u64 high) {
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

u64 host_mul(u64 lhs, u64 rhs) {
#if defined(_MSC_VER) && defined(_M_X64)
  unsigned __int64 high = 0;
  const unsigned __int64 low = _umul128(lhs, rhs, &high);
  return host_reduce_product(low, high);
#else
  const unsigned __int128 product =
      static_cast<unsigned __int128>(lhs) * static_cast<unsigned __int128>(rhs);
  return static_cast<u64>(product % kGoldilocksPrime);
#endif
}

u64 host_pow(u64 base, u64 exponent) {
  if (base >= kGoldilocksPrime) {
    fail("host_pow received noncanonical input");
  }
  u64 result = 1;
  while (exponent != 0) {
    if ((exponent & 1U) != 0) {
      result = host_mul(result, base);
    }
    exponent >>= 1;
    if (exponent != 0) {
      base = host_mul(base, base);
    }
  }
  return result;
}

u64 two_adic_root(unsigned log_height) {
  if (log_height > 32) {
    fail("Goldilocks only supports two-adic heights through 2^32");
  }
  if (log_height == 0) {
    return 1;
  }
  const u64 order = UINT64_C(0xffffffff00000000);
  return host_pow(kGenerator, order >> log_height);
}

void validate_root(unsigned log_height) {
  const u64 root = two_adic_root(log_height);
  const u64 height = UINT64_C(1) << log_height;
  if (host_pow(root, height) != 1) {
    fail("two-adic root does not have the required order");
  }
  if (log_height != 0 &&
      host_pow(root, height >> 1) != kGoldilocksPrime - 1) {
    fail("two-adic root is not primitive");
  }
}

std::vector<u64> make_twiddles(std::size_t height, bool inverse) {
  const unsigned log_height = strict_log2(height);
  if (log_height > 32) {
    fail("DFT height exceeds the Goldilocks two-adicity");
  }
  if (height == 1) {
    return {1};
  }

  u64 root = two_adic_root(log_height);
  if (inverse) {
    root = host_pow(root, kGoldilocksPrime - 2);
  }

  std::vector<u64> twiddles(height - 1);
  for (std::size_t length = 2; length <= height; length <<= 1) {
    const std::size_t half = length >> 1;
    const std::size_t offset = half - 1;
    const u64 stage_root = host_pow(root, height / length);
    u64 power = 1;
    for (std::size_t index = 0; index < half; ++index) {
      twiddles[offset + index] = power;
      power = host_mul(power, stage_root);
    }
  }
  return twiddles;
}

std::size_t reverse_bits(std::size_t value, unsigned bits) {
  std::size_t result = 0;
  for (unsigned bit = 0; bit < bits; ++bit) {
    result = (result << 1) | ((value >> bit) & 1U);
  }
  return result;
}

void host_dft_in_place(std::vector<u64>& values, std::size_t height,
                       std::size_t width, bool inverse) {
  const std::size_t expected = checked_elements(height, width);
  if (values.size() != expected) {
    fail("host DFT input length does not match height times width");
  }
  validate_canonical(values);
  const unsigned log_height = strict_log2(height);
  if (log_height > 32) {
    fail("host DFT height exceeds the Goldilocks two-adicity");
  }

  for (std::size_t row = 0; row < height; ++row) {
    const std::size_t reversed = reverse_bits(row, log_height);
    if (row < reversed) {
      for (std::size_t column = 0; column < width; ++column) {
        std::swap(values[row * width + column],
                  values[reversed * width + column]);
      }
    }
  }

  const std::vector<u64> twiddles = make_twiddles(height, inverse);
  for (std::size_t length = 2; length <= height; length <<= 1) {
    const std::size_t half = length >> 1;
    const std::size_t offset = half - 1;
    for (std::size_t start = 0; start < height; start += length) {
      for (std::size_t index = 0; index < half; ++index) {
        const u64 twiddle = twiddles[offset + index];
        for (std::size_t column = 0; column < width; ++column) {
          const std::size_t low_index = (start + index) * width + column;
          const std::size_t high_index = low_index + half * width;
          const u64 low = values[low_index];
          const u64 high = host_mul(values[high_index], twiddle);
          values[low_index] = host_add(low, high);
          values[high_index] = host_sub(low, high);
        }
      }
    }
  }

  if (inverse) {
    const u64 inverse_height =
        host_pow(static_cast<u64>(height), kGoldilocksPrime - 2);
    for (u64& value : values) {
      value = host_mul(value, inverse_height);
    }
  }
}

std::vector<u64> host_dft(std::vector<u64> values, std::size_t height,
                          std::size_t width) {
  host_dft_in_place(values, height, width, false);
  return values;
}

std::vector<u64> host_coset_lde(std::vector<u64> evaluations,
                                std::size_t height, std::size_t width,
                                unsigned added_bits, u64 shift) {
  if (shift == 0 || shift >= kGoldilocksPrime) {
    fail("coset shift must be a canonical nonzero Goldilocks element");
  }
  const unsigned log_height = strict_log2(height);
  if (added_bits > 32 || log_height + added_bits > 32) {
    fail("coset LDE height exceeds the Goldilocks two-adicity");
  }
  host_dft_in_place(evaluations, height, width, true);

  const std::size_t expanded_height = height << added_bits;
  std::vector<u64> expanded(checked_elements(expanded_height, width), 0);
  u64 shift_power = 1;
  for (std::size_t row = 0; row < height; ++row) {
    for (std::size_t column = 0; column < width; ++column) {
      expanded[row * width + column] =
          host_mul(evaluations[row * width + column], shift_power);
    }
    shift_power = host_mul(shift_power, shift);
  }
  host_dft_in_place(expanded, expanded_height, width, false);
  return expanded;
}

std::vector<u64> host_coefficients_to_coset_lde(
    const std::vector<u64>& coefficients, std::size_t height,
    std::size_t width, unsigned added_bits, u64 shift) {
  if (coefficients.size() != checked_elements(height, width)) {
    fail("host coefficient LDE input length mismatch");
  }
  validate_canonical(coefficients);
  if (shift == 0 || shift >= kGoldilocksPrime) {
    fail("coefficient LDE shift must be canonical and nonzero");
  }
  const unsigned log_height = strict_log2(height);
  if (added_bits > 32 || log_height + added_bits > 32) {
    fail("host coefficient LDE height exceeds Goldilocks two-adicity");
  }

  const std::size_t expanded_height = height << added_bits;
  std::vector<u64> expanded(checked_elements(expanded_height, width), 0);
  u64 shift_power = 1;
  for (std::size_t row = 0; row < height; ++row) {
    for (std::size_t column = 0; column < width; ++column) {
      expanded[row * width + column] =
          host_mul(coefficients[row * width + column], shift_power);
    }
    shift_power = host_mul(shift_power, shift);
  }
  host_dft_in_place(expanded, expanded_height, width, false);
  return expanded;
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

__global__ void field_operations_kernel(const u64* lhs, const u64* rhs,
                                        u64* sums, u64* differences,
                                        u64* products, std::size_t count) {
  const std::size_t index =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (index < count) {
    sums[index] = device_add(lhs[index], rhs[index]);
    differences[index] = device_sub(lhs[index], rhs[index]);
    products[index] = device_mul(lhs[index], rhs[index]);
  }
}

__global__ void bit_reverse_rows_kernel(u64* values, std::size_t height,
                                        std::size_t width,
                                        unsigned log_height) {
  const std::size_t index =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  const std::size_t count = height * width;
  if (index >= count) {
    return;
  }
  const std::size_t row = index / width;
  const std::size_t column = index - row * width;
  const unsigned reversed = log_height == 0
                                ? static_cast<unsigned>(row)
                                : __brev(static_cast<unsigned>(row)) >>
                                      (32U - log_height);
  if (row < reversed) {
    const std::size_t other =
        static_cast<std::size_t>(reversed) * width + column;
    const u64 temporary = values[index];
    values[index] = values[other];
    values[other] = temporary;
  }
}

__global__ void butterfly_kernel(u64* values, const u64* twiddles,
                                 std::size_t height, std::size_t width,
                                 std::size_t half) {
  const std::size_t index =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  const std::size_t butterfly_count = (height >> 1) * width;
  if (index >= butterfly_count) {
    return;
  }

  const std::size_t butterfly = index / width;
  const std::size_t column = index - butterfly * width;
  const std::size_t group = butterfly / half;
  const std::size_t offset = butterfly - group * half;
  const std::size_t low_row = group * (half << 1) + offset;
  const std::size_t low_index = low_row * width + column;
  const std::size_t high_index = low_index + half * width;
  const u64 low = values[low_index];
  const u64 high = device_mul(values[high_index], twiddles[half - 1 + offset]);
  values[low_index] = device_add(low, high);
  values[high_index] = device_sub(low, high);
}

__global__ void scale_kernel(u64* values, std::size_t count, u64 scale) {
  const std::size_t index =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (index < count) {
    values[index] = device_mul(values[index], scale);
  }
}

__global__ void expand_coset_kernel(const u64* coefficients, u64* expanded,
                                    const u64* shift_powers,
                                    std::size_t height, std::size_t width) {
  const std::size_t index =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  const std::size_t count = height * width;
  if (index < count) {
    const std::size_t row = index / width;
    expanded[index] = device_mul(coefficients[index], shift_powers[row]);
  }
}

__global__ void canonical_output_kernel(const u64* values, std::size_t count,
                                        unsigned int* invalid) {
  const std::size_t index =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (index < count && values[index] >= kGoldilocksPrime) {
    atomicExch(invalid, 1U);
  }
}

unsigned launch_blocks(std::size_t count) {
  const std::size_t blocks = (count + kThreads - 1) / kThreads;
  if (blocks == 0 || blocks > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    fail("CUDA launch grid is outside the supported range");
  }
  return static_cast<unsigned>(blocks);
}

void validate_device_canonical(const u64* values, std::size_t count) {
  DeviceBuffer device_invalid(sizeof(unsigned int));
  CUDA_CHECK(cudaMemset(device_invalid.raw(), 0, sizeof(unsigned int)));
  canonical_output_kernel<<<launch_blocks(count), kThreads>>>(
      values, count, static_cast<unsigned int*>(device_invalid.raw()));
  CUDA_CHECK(cudaGetLastError());
  unsigned int invalid = 0;
  CUDA_CHECK(cudaMemcpy(&invalid, device_invalid.raw(), sizeof(invalid),
                        cudaMemcpyDeviceToHost));
  if (invalid != 0) {
    fail("CUDA proof backend produced a noncanonical Goldilocks limb");
  }
}

void launch_dft(u64* device_values, std::size_t height, std::size_t width,
                bool inverse, RowOrder input_order, RowOrder output_order) {
  const unsigned log_height = strict_log2(height);
  if (log_height > 32) {
    fail("CUDA DFT height exceeds the Goldilocks two-adicity");
  }
  const std::size_t elements = checked_elements(height, width);
  const std::vector<u64> twiddles = make_twiddles(height, inverse);
  DeviceBuffer device_twiddles(twiddles.size() * sizeof(u64));
  CUDA_CHECK(cudaMemcpy(device_twiddles.data(), twiddles.data(),
                        twiddles.size() * sizeof(u64), cudaMemcpyHostToDevice));

  if (input_order == RowOrder::kNatural) {
    bit_reverse_rows_kernel<<<launch_blocks(elements), kThreads>>>(
        device_values, height, width, log_height);
    CUDA_CHECK(cudaGetLastError());
  }

  for (std::size_t length = 2; length <= height; length <<= 1) {
    const std::size_t half = length >> 1;
    const std::size_t butterflies = (height >> 1) * width;
    butterfly_kernel<<<launch_blocks(butterflies), kThreads>>>(
        device_values, device_twiddles.data(), height, width, half);
    CUDA_CHECK(cudaGetLastError());
  }

  if (inverse) {
    const u64 inverse_height =
        host_pow(static_cast<u64>(height), kGoldilocksPrime - 2);
    scale_kernel<<<launch_blocks(elements), kThreads>>>(device_values, elements,
                                                        inverse_height);
    CUDA_CHECK(cudaGetLastError());
  }

  if (output_order == RowOrder::kBitReversed) {
    bit_reverse_rows_kernel<<<launch_blocks(elements), kThreads>>>(
        device_values, height, width, log_height);
    CUDA_CHECK(cudaGetLastError());
  }
}

struct GpuResult {
  std::vector<u64> values;
  float kernel_milliseconds = 0.0F;
  double end_to_end_milliseconds = 0.0;
};

GpuResult execute_dft(const u64* input, std::size_t input_len,
                      std::uint32_t height, std::uint32_t width, bool inverse,
                      RowOrder input_order, RowOrder output_order, u64* output,
                      std::size_t output_len, bool copy_output) {
  const auto wall_start = std::chrono::steady_clock::now();
  const std::size_t elements = checked_backend_elements(height, width);
  if (input_len != elements) {
    fail("CUDA DFT input length does not match height times width");
  }
  if (copy_output) {
    if (output == nullptr || output_len != elements) {
      fail("CUDA DFT output length does not match height times width");
    }
  } else if (output != nullptr || output_len != 0) {
    fail("CUDA DFT benchmark output must be null and empty");
  }
  validate_canonical(input, input_len, "DFT input");

  DeviceBuffer device_values(elements * sizeof(u64));
  CUDA_CHECK(cudaMemcpy(device_values.data(), input, device_values.bytes(),
                        cudaMemcpyHostToDevice));
  CudaEvent start;
  CudaEvent stop;
  CUDA_CHECK(cudaEventRecord(start.get()));
  launch_dft(device_values.data(), height, width, inverse, input_order,
             output_order);
  validate_device_canonical(device_values.data(), elements);
  CUDA_CHECK(cudaEventRecord(stop.get()));
  CUDA_CHECK(cudaEventSynchronize(stop.get()));

  GpuResult result;
  if (copy_output) {
    CUDA_CHECK(cudaMemcpy(output, device_values.data(),
                          device_values.bytes(), cudaMemcpyDeviceToHost));
  }
  CUDA_CHECK(cudaEventElapsedTime(&result.kernel_milliseconds, start.get(),
                                  stop.get()));
  result.end_to_end_milliseconds =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() -
                                                wall_start)
          .count();
  return result;
}

GpuResult gpu_dft(const std::vector<u64>& input, std::size_t height,
                  std::size_t width, bool copy_output = true,
                  bool inverse = false,
                  RowOrder input_order = RowOrder::kNatural,
                  RowOrder output_order = RowOrder::kNatural) {
  if (height > std::numeric_limits<std::uint32_t>::max() ||
      width > std::numeric_limits<std::uint32_t>::max()) {
    fail("CUDA DFT dimensions exceed u32");
  }
  GpuResult result;
  if (copy_output) {
    result.values.resize(checked_elements(height, width));
  }
  const GpuResult timing = execute_dft(
      input.data(), input.size(), static_cast<std::uint32_t>(height),
      static_cast<std::uint32_t>(width), inverse, input_order, output_order,
      copy_output ? result.values.data() : nullptr,
      copy_output ? result.values.size() : 0, copy_output);
  result.kernel_milliseconds = timing.kernel_milliseconds;
  result.end_to_end_milliseconds = timing.end_to_end_milliseconds;
  return result;
}

GpuResult execute_coset_lde(
    const u64* input, std::size_t input_len, std::uint32_t height,
    std::uint32_t width, unsigned added_bits, u64 shift,
    RowOrder input_order, RowOrder output_order, u64* output,
    std::size_t output_len, bool copy_output) {
  const auto wall_start = std::chrono::steady_clock::now();
  const std::size_t elements = checked_backend_elements(height, width);
  if (shift == 0 || shift >= kGoldilocksPrime) {
    fail("coset shift must be a canonical nonzero Goldilocks element");
  }
  const unsigned log_height = strict_log2(height);
  if (added_bits > 24 || log_height + added_bits > 24) {
    fail("CUDA coset LDE height exceeds the ABI v2 limit");
  }
  const std::uint32_t expanded_height = height << added_bits;
  const std::size_t expanded_elements =
      checked_backend_elements(expanded_height, width);
  if (input_len != elements) {
    fail("CUDA coset LDE input length does not match height times width");
  }
  if (copy_output) {
    if (output == nullptr || output_len != expanded_elements) {
      fail("CUDA coset LDE output length does not match expanded height times width");
    }
  } else if (output != nullptr || output_len != 0) {
    fail("CUDA coset LDE benchmark output must be null and empty");
  }
  validate_canonical(input, input_len, "coset LDE input");

  std::vector<u64> shift_powers(height);
  u64 shift_power = 1;
  for (std::size_t row = 0; row < height; ++row) {
    shift_powers[row] = shift_power;
    shift_power = host_mul(shift_power, shift);
  }

  DeviceBuffer device_values(elements * sizeof(u64));
  DeviceBuffer device_expanded(expanded_elements * sizeof(u64));
  DeviceBuffer device_shift_powers(height * sizeof(u64));
  CUDA_CHECK(cudaMemcpy(device_values.data(), input, device_values.bytes(),
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(device_shift_powers.data(), shift_powers.data(),
                        device_shift_powers.bytes(), cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemset(device_expanded.data(), 0, device_expanded.bytes()));

  CudaEvent start;
  CudaEvent stop;
  CUDA_CHECK(cudaEventRecord(start.get()));
  launch_dft(device_values.data(), height, width, true, input_order,
             RowOrder::kNatural);
  expand_coset_kernel<<<launch_blocks(elements), kThreads>>>(
      device_values.data(), device_expanded.data(), device_shift_powers.data(),
      height, width);
  CUDA_CHECK(cudaGetLastError());
  launch_dft(device_expanded.data(), expanded_height, width, false,
             RowOrder::kNatural, output_order);
  validate_device_canonical(device_expanded.data(), expanded_elements);
  CUDA_CHECK(cudaEventRecord(stop.get()));
  CUDA_CHECK(cudaEventSynchronize(stop.get()));

  GpuResult result;
  if (copy_output) {
    CUDA_CHECK(cudaMemcpy(output, device_expanded.data(),
                          device_expanded.bytes(), cudaMemcpyDeviceToHost));
  }
  CUDA_CHECK(cudaEventElapsedTime(&result.kernel_milliseconds, start.get(),
                                  stop.get()));
  result.end_to_end_milliseconds =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() -
                                                wall_start)
          .count();
  return result;
}

GpuResult gpu_coset_lde(const std::vector<u64>& input, std::size_t height,
                        std::size_t width, unsigned added_bits, u64 shift,
                        bool copy_output = true,
                        RowOrder input_order = RowOrder::kNatural,
                        RowOrder output_order = RowOrder::kNatural) {
  if (height > std::numeric_limits<std::uint32_t>::max() ||
      width > std::numeric_limits<std::uint32_t>::max()) {
    fail("CUDA coset LDE dimensions exceed u32");
  }
  const unsigned log_height = strict_log2(height);
  if (added_bits > 24 || log_height + added_bits > 24) {
    fail("CUDA coset LDE height exceeds the ABI v2 limit");
  }
  const std::size_t expanded_height = height << added_bits;
  GpuResult result;
  if (copy_output) {
    result.values.resize(checked_elements(expanded_height, width));
  }
  const GpuResult timing = execute_coset_lde(
      input.data(), input.size(), static_cast<std::uint32_t>(height),
      static_cast<std::uint32_t>(width), added_bits, shift, input_order,
      output_order, copy_output ? result.values.data() : nullptr,
      copy_output ? result.values.size() : 0, copy_output);
  result.kernel_milliseconds = timing.kernel_milliseconds;
  result.end_to_end_milliseconds = timing.end_to_end_milliseconds;
  return result;
}

GpuResult execute_coefficients_to_coset_lde(
    const u64* coefficients, std::size_t coefficients_len,
    std::uint32_t height, std::uint32_t width, unsigned added_bits, u64 shift,
    u64* output, std::size_t output_len, bool copy_output) {
  const auto wall_start = std::chrono::steady_clock::now();
  const std::size_t elements = checked_backend_elements(height, width);
  if (shift == 0 || shift >= kGoldilocksPrime) {
    fail("coefficient LDE shift must be canonical and nonzero");
  }
  const unsigned log_height = strict_log2(height);
  if (added_bits > 24 || log_height + added_bits > 24) {
    fail("CUDA coefficient LDE height exceeds the ABI v2 limit");
  }
  const std::uint32_t expanded_height = height << added_bits;
  const std::size_t expanded_elements =
      checked_backend_elements(expanded_height, width);
  if (coefficients_len != elements) {
    fail("CUDA coefficient LDE input length does not match height times width");
  }
  if (copy_output) {
    if (output == nullptr || output_len != expanded_elements) {
      fail("CUDA coefficient LDE output length does not match expanded height times width");
    }
  } else if (output != nullptr || output_len != 0) {
    fail("CUDA coefficient LDE benchmark output must be null and empty");
  }
  validate_canonical(coefficients, coefficients_len,
                     "physical bit-reversed coefficient input");

  std::vector<u64> shift_powers(height);
  u64 shift_power = 1;
  for (std::size_t row = 0; row < height; ++row) {
    shift_powers[row] = shift_power;
    shift_power = host_mul(shift_power, shift);
  }

  DeviceBuffer device_coefficients(elements * sizeof(u64));
  DeviceBuffer device_expanded(expanded_elements * sizeof(u64));
  DeviceBuffer device_shift_powers(height * sizeof(u64));
  CUDA_CHECK(cudaMemcpy(device_coefficients.data(), coefficients,
                        device_coefficients.bytes(), cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(device_shift_powers.data(), shift_powers.data(),
                        device_shift_powers.bytes(), cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemset(device_expanded.data(), 0, device_expanded.bytes()));

  CudaEvent start;
  CudaEvent stop;
  CUDA_CHECK(cudaEventRecord(start.get()));
  bit_reverse_rows_kernel<<<launch_blocks(elements), kThreads>>>(
      device_coefficients.data(), height, width, log_height);
  CUDA_CHECK(cudaGetLastError());
  expand_coset_kernel<<<launch_blocks(elements), kThreads>>>(
      device_coefficients.data(), device_expanded.data(),
      device_shift_powers.data(), height, width);
  CUDA_CHECK(cudaGetLastError());
  launch_dft(device_expanded.data(), expanded_height, width, false,
             RowOrder::kNatural, RowOrder::kBitReversed);
  validate_device_canonical(device_expanded.data(), expanded_elements);
  CUDA_CHECK(cudaEventRecord(stop.get()));
  CUDA_CHECK(cudaEventSynchronize(stop.get()));

  GpuResult result;
  if (copy_output) {
    CUDA_CHECK(cudaMemcpy(output, device_expanded.data(),
                          device_expanded.bytes(), cudaMemcpyDeviceToHost));
  }
  CUDA_CHECK(cudaEventElapsedTime(&result.kernel_milliseconds, start.get(),
                                  stop.get()));
  result.end_to_end_milliseconds =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() -
                                                wall_start)
          .count();
  return result;
}

GpuResult gpu_coefficients_to_coset_lde(
    const std::vector<u64>& physical_bit_reversed_coefficients,
    std::size_t height, std::size_t width, unsigned added_bits, u64 shift,
    bool copy_output = true) {
  if (height > std::numeric_limits<std::uint32_t>::max() ||
      width > std::numeric_limits<std::uint32_t>::max()) {
    fail("CUDA coefficient LDE dimensions exceed u32");
  }
  const unsigned log_height = strict_log2(height);
  if (added_bits > 24 || log_height + added_bits > 24) {
    fail("CUDA coefficient LDE height exceeds the ABI v2 limit");
  }
  const std::size_t expanded_height = height << added_bits;
  GpuResult result;
  if (copy_output) {
    result.values.resize(checked_elements(expanded_height, width));
  }
  const GpuResult timing = execute_coefficients_to_coset_lde(
      physical_bit_reversed_coefficients.data(),
      physical_bit_reversed_coefficients.size(),
      static_cast<std::uint32_t>(height), static_cast<std::uint32_t>(width),
      added_bits, shift, copy_output ? result.values.data() : nullptr,
      copy_output ? result.values.size() : 0, copy_output);
  result.kernel_milliseconds = timing.kernel_milliseconds;
  result.end_to_end_milliseconds = timing.end_to_end_milliseconds;
  return result;
}

ProofContext& checked_context(void* opaque_context) {
  if (opaque_context == nullptr) {
    fail("CUDA proof context is null");
  }
  auto& context = *static_cast<ProofContext*>(opaque_context);
  if (context.magic != kProofContextMagic || context.device_index < 0) {
    fail("CUDA proof context is invalid");
  }
  return context;
}

}  // namespace

// Proof CUDA ABI v2. Buffer lengths count u64 elements. Row order 0 is
// natural; row order 1 is the physical storage beneath Plonky3's
// BitReversedMatrixView. Calls on one handle serialize internally. The caller
// must not race destroy with an operation. The v2 coefficient-LDE call fixes
// both input and output to physical bit-reversed row order so the expanded
// matrix is never materialized or reordered on the host.
CMFD_PROOF_EXPORT std::uint32_t cmfd_proof_cuda_api_version() noexcept {
  return kProofApiVersion;
}

CMFD_PROOF_EXPORT std::int32_t cmfd_proof_cuda_device_count(
    std::int32_t* count, char* error, std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    if (count == nullptr) {
      fail("device count output is null");
    }
    *count = 0;
    int value = 0;
    CUDA_CHECK(cudaGetDeviceCount(&value));
    *count = value;
  });
}

CMFD_PROOF_EXPORT std::int32_t cmfd_proof_cuda_device_info(
    std::int32_t device_index, CmfdProofCudaDeviceInfo* output, char* error,
    std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    if (output == nullptr) {
      fail("device info output is null");
    }
    std::memset(output, 0, sizeof(*output));
    cudaDeviceProp properties{};
    CUDA_CHECK(cudaGetDeviceProperties(&properties, device_index));
    output->api_version = kProofApiVersion;
    output->device_index = device_index;
    output->compute_major = static_cast<std::uint32_t>(properties.major);
    output->compute_minor = static_cast<std::uint32_t>(properties.minor);
    output->total_memory_bytes =
        static_cast<std::uint64_t>(properties.totalGlobalMem);
    std::size_t name_len = 0;
    while (name_len + 1 < sizeof(output->name) &&
           properties.name[name_len] != '\0') {
      output->name[name_len] = properties.name[name_len];
      ++name_len;
    }
    output->name[name_len] = '\0';
  });
}

CMFD_PROOF_EXPORT std::int32_t cmfd_proof_cuda_create(
    std::int32_t device_index, void** output_context, char* error,
    std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    if (output_context == nullptr) {
      fail("context output is null");
    }
    *output_context = nullptr;
    CUDA_CHECK(cudaSetDevice(device_index));
    cudaDeviceProp properties{};
    CUDA_CHECK(cudaGetDeviceProperties(&properties, device_index));
    if (properties.major < 7) {
      fail("CUDA proof backend requires compute capability 7.0 or newer");
    }
    auto context = std::make_unique<ProofContext>();
    context->device_index = device_index;
    *output_context = context.release();
  });
}

CMFD_PROOF_EXPORT std::int32_t cmfd_proof_cuda_dft(
    void* opaque_context, const std::uint64_t* input, std::size_t input_len,
    std::uint32_t height, std::uint32_t width, std::uint32_t inverse,
    std::uint32_t input_order, std::uint32_t output_order,
    std::uint64_t* output, std::size_t output_len, char* error,
    std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    if (inverse > 1) {
      fail("inverse must be 0 or 1");
    }
    const RowOrder parsed_input_order = parse_row_order(input_order);
    const RowOrder parsed_output_order = parse_row_order(output_order);
    ProofContext& context = checked_context(opaque_context);
    std::lock_guard<std::mutex> lock(context.operation_mutex);
    CUDA_CHECK(cudaSetDevice(context.device_index));
    execute_dft(input, input_len, height, width, inverse == 1,
                parsed_input_order, parsed_output_order, output, output_len,
                true);
  });
}

CMFD_PROOF_EXPORT std::int32_t cmfd_proof_cuda_coset_lde(
    void* opaque_context, const std::uint64_t* input, std::size_t input_len,
    std::uint32_t height, std::uint32_t width, std::uint32_t added_bits,
    std::uint64_t shift, std::uint32_t input_order,
    std::uint32_t output_order, std::uint64_t* output,
    std::size_t output_len, char* error, std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    const RowOrder parsed_input_order = parse_row_order(input_order);
    const RowOrder parsed_output_order = parse_row_order(output_order);
    ProofContext& context = checked_context(opaque_context);
    std::lock_guard<std::mutex> lock(context.operation_mutex);
    CUDA_CHECK(cudaSetDevice(context.device_index));
    execute_coset_lde(input, input_len, height, width, added_bits, shift,
                      parsed_input_order, parsed_output_order, output,
                      output_len, true);
  });
}

CMFD_PROOF_EXPORT std::int32_t
cmfd_proof_cuda_coefficients_to_coset_lde(
    void* opaque_context, const std::uint64_t* coefficients,
    std::size_t coefficients_len, std::uint32_t height, std::uint32_t width,
    std::uint32_t added_bits, std::uint64_t shift, std::uint64_t* output,
    std::size_t output_len, char* error, std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    ProofContext& context = checked_context(opaque_context);
    std::lock_guard<std::mutex> lock(context.operation_mutex);
    CUDA_CHECK(cudaSetDevice(context.device_index));
    execute_coefficients_to_coset_lde(
        coefficients, coefficients_len, height, width, added_bits, shift,
        output, output_len, true);
  });
}

CMFD_PROOF_EXPORT void cmfd_proof_cuda_destroy(void* opaque_context) noexcept {
  if (opaque_context == nullptr) {
    return;
  }
  auto* context = static_cast<ProofContext*>(opaque_context);
  context->magic = 0;
  context->device_index = -1;
  delete context;
}

namespace {

u64 next_random(u64& state) {
  state ^= state >> 12;
  state ^= state << 25;
  state ^= state >> 27;
  return state * UINT64_C(0x2545f4914f6cdd1d);
}

enum class Pattern {
  kZeros,
  kOnes,
  kPrimeMinusOne,
  kImpulse,
  kAlternating,
  kDeterministicRandom,
};

const char* pattern_name(Pattern pattern) {
  switch (pattern) {
    case Pattern::kZeros:
      return "zeros";
    case Pattern::kOnes:
      return "ones";
    case Pattern::kPrimeMinusOne:
      return "p-1";
    case Pattern::kImpulse:
      return "impulse";
    case Pattern::kAlternating:
      return "alternating";
    case Pattern::kDeterministicRandom:
      return "deterministic-random";
  }
  return "unknown";
}

std::vector<u64> make_vector(std::size_t height, std::size_t width,
                             Pattern pattern) {
  std::vector<u64> values(checked_elements(height, width), 0);
  u64 random_state = UINT64_C(0x6a09e667f3bcc909) ^
                     static_cast<u64>(height * UINT64_C(0x9e3779b1)) ^
                     static_cast<u64>(width);
  for (std::size_t row = 0; row < height; ++row) {
    for (std::size_t column = 0; column < width; ++column) {
      u64 value = 0;
      switch (pattern) {
        case Pattern::kZeros:
          value = 0;
          break;
        case Pattern::kOnes:
          value = 1;
          break;
        case Pattern::kPrimeMinusOne:
          value = kGoldilocksPrime - 1;
          break;
        case Pattern::kImpulse:
          value = row == 0 ? static_cast<u64>(column + 1) : 0;
          break;
        case Pattern::kAlternating:
          value = ((row + column) & 1U) == 0 ? 1 : kGoldilocksPrime - 1;
          break;
        case Pattern::kDeterministicRandom:
          value = next_random(random_state);
          if (value >= kGoldilocksPrime) {
            value -= kGoldilocksPrime;
          }
          break;
      }
      values[row * width + column] = value;
    }
  }
  return values;
}

void compare_exact(const std::vector<u64>& expected,
                   const std::vector<u64>& actual, std::size_t width,
                   const std::string& context) {
  if (expected.size() != actual.size()) {
    fail(context + ": output lengths differ");
  }
  for (std::size_t index = 0; index < expected.size(); ++index) {
    if (expected[index] != actual[index]) {
      char message[320];
      const std::size_t row = index / width;
      const std::size_t column = index - row * width;
      std::snprintf(message, sizeof(message),
                    "%s mismatch at row %zu column %zu: expected "
                    "0x%016llx, got 0x%016llx",
                    context.c_str(), row, column,
                    static_cast<unsigned long long>(expected[index]),
                    static_cast<unsigned long long>(actual[index]));
      fail(message);
    }
  }
}

std::vector<u64> bit_reverse_physical(std::vector<u64> values,
                                      std::size_t height,
                                      std::size_t width) {
  if (values.size() != checked_elements(height, width)) {
    fail("bit-reversal fixture shape mismatch");
  }
  const unsigned log_height = strict_log2(height);
  for (std::size_t row = 0; row < height; ++row) {
    const std::size_t reversed = reverse_bits(row, log_height);
    if (row < reversed) {
      for (std::size_t column = 0; column < width; ++column) {
        std::swap(values[row * width + column],
                  values[reversed * width + column]);
      }
    }
  }
  return values;
}

void test_field_arithmetic() {
  constexpr std::size_t kCount = 32768;
  std::vector<u64> lhs(kCount);
  std::vector<u64> rhs(kCount);
  const u64 boundaries[] = {0,
                            1,
                            2,
                            kEpsilon - 1,
                            kEpsilon,
                            kEpsilon + 1,
                            kGoldilocksPrime / 2,
                            kGoldilocksPrime - 3,
                            kGoldilocksPrime - 2,
                            kGoldilocksPrime - 1};
  std::size_t cursor = 0;
  for (u64 left : boundaries) {
    for (u64 right : boundaries) {
      lhs[cursor] = left;
      rhs[cursor] = right;
      ++cursor;
    }
  }
  u64 state = UINT64_C(0xbb67ae8584caa73b);
  while (cursor < kCount) {
    lhs[cursor] = next_random(state);
    rhs[cursor] = next_random(state);
    if (lhs[cursor] >= kGoldilocksPrime) {
      lhs[cursor] -= kGoldilocksPrime;
    }
    if (rhs[cursor] >= kGoldilocksPrime) {
      rhs[cursor] -= kGoldilocksPrime;
    }
    ++cursor;
  }

  DeviceBuffer device_lhs(kCount * sizeof(u64));
  DeviceBuffer device_rhs(kCount * sizeof(u64));
  DeviceBuffer device_sums(kCount * sizeof(u64));
  DeviceBuffer device_differences(kCount * sizeof(u64));
  DeviceBuffer device_products(kCount * sizeof(u64));
  CUDA_CHECK(cudaMemcpy(device_lhs.data(), lhs.data(), device_lhs.bytes(),
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(device_rhs.data(), rhs.data(), device_rhs.bytes(),
                        cudaMemcpyHostToDevice));
  field_operations_kernel<<<launch_blocks(kCount), kThreads>>>(
      device_lhs.data(), device_rhs.data(), device_sums.data(),
      device_differences.data(), device_products.data(), kCount);
  CUDA_CHECK(cudaGetLastError());

  std::vector<u64> sums(kCount);
  std::vector<u64> differences(kCount);
  std::vector<u64> products(kCount);
  CUDA_CHECK(cudaMemcpy(sums.data(), device_sums.data(), device_sums.bytes(),
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaMemcpy(differences.data(), device_differences.data(),
                        device_differences.bytes(), cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaMemcpy(products.data(), device_products.data(),
                        device_products.bytes(), cudaMemcpyDeviceToHost));

  for (std::size_t index = 0; index < kCount; ++index) {
    if (sums[index] != host_add(lhs[index], rhs[index]) ||
        differences[index] != host_sub(lhs[index], rhs[index]) ||
        products[index] != host_mul_oracle(lhs[index], rhs[index])) {
      fail("Goldilocks CUDA arithmetic disagrees with the independent host oracle "
           "at pair " +
           std::to_string(index));
    }
    if (host_mul(lhs[index], rhs[index]) != products[index]) {
      fail("fast host multiplication disagrees with the independent host oracle at pair " +
           std::to_string(index));
    }
  }
  std::printf("PASS field arithmetic: %zu canonical boundary/random pairs\n", kCount);
}

void test_known_plonky3_vectors() {
  // Generated independently with p3-dft 0.6.3
  // Radix2DitParallel<Goldilocks>, then converted from its bit-reversed view to
  // the canonical logical row-major output. This height-8 fixture detects root
  // selection, root direction, row ordering, and column-layout drift.
  std::vector<u64> dft_input(16);
  for (std::size_t index = 0; index < dft_input.size(); ++index) {
    dft_input[index] = static_cast<u64>(index + 1);
  }
  const std::vector<u64> dft_expected = {
      UINT64_C(0x0000000000000040), UINT64_C(0x0000000000000048),
      UINT64_C(0xfff807ff07fff7f9), UINT64_C(0xfff807ff07fff7f9),
      UINT64_C(0xfff7fffefffffff9), UINT64_C(0xfff7fffefffffff9),
      UINT64_C(0x0008080007fff7f8), UINT64_C(0x0008080007fff7f8),
      UINT64_C(0xfffffffefffffff9), UINT64_C(0xfffffffefffffff9),
      UINT64_C(0xfff7f7fef80007f9), UINT64_C(0xfff7f7fef80007f9),
      UINT64_C(0x0007fffffffffff8), UINT64_C(0x0007fffffffffff8),
      UINT64_C(0x0007f7fff80007f8), UINT64_C(0x0007f7fff80007f8)};
  compare_exact(dft_expected, host_dft(dft_input, 8, 2), 2,
                "host Plonky3 0.6.3 DFT fixture");
  compare_exact(dft_expected, gpu_dft(dft_input, 8, 2).values, 2,
                "CUDA Plonky3 0.6.3 DFT fixture");

  // Generated by the same Plonky3 implementation with added_bits=2 and the
  // canonical Goldilocks multiplicative generator (shift=7).
  const std::vector<u64> lde_expected = {
      UINT64_C(0xf0d14cc2332016f8), UINT64_C(0xf0d14cc2332016f9),
      UINT64_C(0xcd6587e202e89bdb), UINT64_C(0xcd6587e202e89bdc),
      UINT64_C(0xee16d8354e60441b), UINT64_C(0xee16d8354e60441c),
      UINT64_C(0x1595a6f2884aa919), UINT64_C(0x1595a6f2884aa91a),
      UINT64_C(0x6e720c430c3f69b6), UINT64_C(0x6e720c430c3f69b7),
      UINT64_C(0x68a43cdbb62a785b), UINT64_C(0x68a43cdbb62a785c),
      UINT64_C(0x1ff108c0df210245), UINT64_C(0x1ff108c0df210246),
      UINT64_C(0x5bf1334a0670765b), UINT64_C(0x5bf1334a0670765c),
      UINT64_C(0x0fb20c5c0c42ee5f), UINT64_C(0x0fb20c5c0c42ee60),
      UINT64_C(0x9f443d2f55c2783e), UINT64_C(0x9f443d2f55c2783f),
      UINT64_C(0x0ab7b3ab9f974e0c), UINT64_C(0x0ab7b3ab9f974e0d),
      UINT64_C(0xcdf69b3b38eb0e6a), UINT64_C(0xcdf69b3b38eb0e6b),
      UINT64_C(0x786eb338ccc64125), UINT64_C(0x786eb338ccc64126),
      UINT64_C(0x332a39f4fc9ba8fe), UINT64_C(0x332a39f4fc9ba8ff),
      UINT64_C(0xc89ae112b24b3df6), UINT64_C(0xc89ae112b24b3df7),
      UINT64_C(0xea6a1b962a37f278), UINT64_C(0xea6a1b962a37f279),
      UINT64_C(0x786eb338ccdc3ed7), UINT64_C(0x786eb338ccdc3ed8),
      UINT64_C(0xe0b3ea55313d846a), UINT64_C(0xe0b3ea55313d846b),
      UINT64_C(0x02bde432ee08fbf6), UINT64_C(0x02bde432ee08fbf7),
      UINT64_C(0xc45cdb7ab734ee6a), UINT64_C(0xc45cdb7ab734ee6b),
      UINT64_C(0x284df3bff3bd1195), UINT64_C(0x284df3bff3bd1196),
      UINT64_C(0x450250f6f9ef67e9), UINT64_C(0x450250f6f9ef67ea),
      UINT64_C(0xf6687ed5a14779cc), UINT64_C(0xf6687ed5a14779cd),
      UINT64_C(0x7ddbd762c6506528), UINT64_C(0x7ddbd762c6506529),
      UINT64_C(0x870df3a6f3c09670), UINT64_C(0x870df3a6f3c09671),
      UINT64_C(0xb2a250bbfa1767a0), UINT64_C(0xb2a250bbfa1767a1),
      UINT64_C(0xdeef8fea23ff7205), UINT64_C(0xdeef8fea23ff7206),
      UINT64_C(0x583c6655876fd635), UINT64_C(0x583c6655876fd636),
      UINT64_C(0xf0d14cc2333d6936), UINT64_C(0xf0d14cc2333d6937),
      UINT64_C(0x1f2f3811cf4a76df), UINT64_C(0x1f2f3811cf4a76e0),
      UINT64_C(0x468f9754cd4c461b), UINT64_C(0x468f9754cd4c461c),
      UINT64_C(0x3ba355bb092cb627), UINT64_C(0x3ba355bb092cb628)};
  compare_exact(lde_expected,
                host_coset_lde(dft_input, 8, 2, 2, kGenerator),
                2, "host Plonky3 0.6.3 coset-LDE fixture");
  compare_exact(lde_expected,
                gpu_coset_lde(dft_input, 8, 2, 2, kGenerator).values, 2,
                "CUDA Plonky3 0.6.3 coset-LDE fixture");
  std::printf("PASS pinned Plonky3 0.6.3 DFT and coset-LDE fixtures\n");
}

void test_dfts() {
  const std::pair<std::size_t, std::size_t> shapes[] = {
      {1, 1},    {2, 3},      {8, 5},   {32, 87},
      {128, 291}, {1024, 17}, {8, 9168}};
  const Pattern patterns[] = {Pattern::kZeros,
                              Pattern::kOnes,
                              Pattern::kPrimeMinusOne,
                              Pattern::kImpulse,
                              Pattern::kAlternating,
                              Pattern::kDeterministicRandom};
  std::size_t cases = 0;
  for (const auto& shape : shapes) {
    for (Pattern pattern : patterns) {
      const std::vector<u64> input =
          make_vector(shape.first, shape.second, pattern);
      const std::vector<u64> expected =
          host_dft(input, shape.first, shape.second);
      const GpuResult actual = gpu_dft(input, shape.first, shape.second);
      compare_exact(expected, actual.values, shape.second,
                    std::string("DFT ") + pattern_name(pattern));
      ++cases;
    }
  }
  std::printf("PASS batched DFT: %zu exact GPU-vs-CPU cases\n", cases);
}

void test_coset_ldes() {
  struct Shape {
    std::size_t height;
    std::size_t width;
    unsigned added_bits;
  };
  const Shape shapes[] = {
      {2, 3, 1}, {8, 5, 2}, {32, 87, 1}, {64, 291, 1}, {32, 3, 7}};
  const Pattern patterns[] = {Pattern::kZeros,
                              Pattern::kOnes,
                              Pattern::kPrimeMinusOne,
                              Pattern::kImpulse,
                              Pattern::kAlternating,
                              Pattern::kDeterministicRandom};
  std::size_t cases = 0;
  for (const Shape& shape : shapes) {
    for (Pattern pattern : patterns) {
      const std::vector<u64> input =
          make_vector(shape.height, shape.width, pattern);
      const std::vector<u64> expected = host_coset_lde(
          input, shape.height, shape.width, shape.added_bits, kGenerator);
      const GpuResult actual = gpu_coset_lde(
          input, shape.height, shape.width, shape.added_bits, kGenerator);
      compare_exact(expected, actual.values, shape.width,
                    std::string("coset LDE ") + pattern_name(pattern));
      ++cases;
    }
  }
  std::printf("PASS coset LDE: %zu exact GPU-vs-CPU cases\n", cases);
}

void test_coefficient_coset_ldes() {
  struct Shape {
    std::size_t height;
    std::size_t width;
    unsigned added_bits;
  };
  const Shape shapes[] = {
      {1, 1, 0}, {2, 3, 1}, {8, 5, 2},
      {32, 87, 1}, {64, 291, 1}, {32, 3, 7}};
  const Pattern patterns[] = {Pattern::kZeros,
                              Pattern::kOnes,
                              Pattern::kPrimeMinusOne,
                              Pattern::kImpulse,
                              Pattern::kAlternating,
                              Pattern::kDeterministicRandom};
  std::size_t cases = 0;
  for (const Shape& shape : shapes) {
    for (Pattern pattern : patterns) {
      const std::vector<u64> natural_coefficients =
          make_vector(shape.height, shape.width, pattern);
      const std::vector<u64> physical_coefficients = bit_reverse_physical(
          natural_coefficients, shape.height, shape.width);
      const std::vector<u64> expected_natural =
          host_coefficients_to_coset_lde(
              natural_coefficients, shape.height, shape.width,
              shape.added_bits, kGenerator);
      const std::vector<u64> expected_physical = bit_reverse_physical(
          expected_natural, shape.height << shape.added_bits, shape.width);
      const GpuResult actual = gpu_coefficients_to_coset_lde(
          physical_coefficients, shape.height, shape.width, shape.added_bits,
          kGenerator);
      compare_exact(expected_physical, actual.values, shape.width,
                    std::string("coefficient coset LDE ") +
                        pattern_name(pattern));
      ++cases;
    }
  }
  std::printf(
      "PASS coefficient-to-coset LDE: %zu exact physical-layout "
      "GPU-vs-CPU cases\n",
      cases);
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

void test_c_abi() {
  if (cmfd_proof_cuda_api_version() != kProofApiVersion) {
    fail("CUDA proof C ABI reported the wrong API version");
  }

  char error[192] = {};
  std::int32_t device_count = 0;
  require_abi_failure(
      cmfd_proof_cuda_device_count(nullptr, error, sizeof(error)),
      "null device count output", error);
  require_abi_success(
      cmfd_proof_cuda_device_count(&device_count, error, sizeof(error)),
      "device count", error);
  if (device_count <= 0) {
    fail("CUDA proof C ABI found no devices");
  }
  CmfdProofCudaDeviceInfo device_info{};
  require_abi_failure(
      cmfd_proof_cuda_device_info(0, nullptr, error, sizeof(error)),
      "null device info output", error);
  require_abi_success(
      cmfd_proof_cuda_device_info(0, &device_info, error, sizeof(error)),
      "device info", error);
  if (device_info.api_version != kProofApiVersion ||
      device_info.device_index != 0 || device_info.compute_major < 7 ||
      device_info.name[0] == '\0') {
    fail("CUDA proof C ABI returned invalid device information");
  }

  void* context = nullptr;
  require_abi_failure(cmfd_proof_cuda_create(0, nullptr, error, sizeof(error)),
                      "null context output", error);
  require_abi_success(
      cmfd_proof_cuda_create(0, &context, error, sizeof(error)), "create",
      error);
  if (context == nullptr) {
    fail("CUDA proof C ABI returned a null context");
  }

  try {
    constexpr std::uint32_t kHeight = 32;
    constexpr std::uint32_t kWidth = 7;
    const std::vector<u64> input =
        make_vector(kHeight, kWidth, Pattern::kDeterministicRandom);
    const std::vector<u64> expected_natural =
        host_dft(input, kHeight, kWidth);
    const std::vector<u64> expected_bit_reversed =
        bit_reverse_physical(expected_natural, kHeight, kWidth);
    std::vector<u64> output(input.size());

    require_abi_failure(
        cmfd_proof_cuda_dft(nullptr, input.data(), input.size(), kHeight,
                            kWidth, 0, 0, 0, output.data(), output.size(), error,
                            sizeof(error)),
        "null DFT context", error);
    require_abi_failure(
        cmfd_proof_cuda_dft(context, nullptr, input.size(), kHeight, kWidth, 0,
                            0, 0, output.data(), output.size(), error,
                            sizeof(error)),
        "null DFT input", error);
    require_abi_failure(
        cmfd_proof_cuda_dft(context, input.data(), input.size() - 1, kHeight,
                            kWidth, 0, 0, 0, output.data(), output.size(), error,
                            sizeof(error)),
        "short DFT input", error);
    require_abi_failure(
        cmfd_proof_cuda_dft(context, input.data(), input.size(), kHeight,
                            kWidth, 0, 0, 0, nullptr, output.size(), error,
                            sizeof(error)),
        "null DFT output", error);
    require_abi_failure(
        cmfd_proof_cuda_dft(context, input.data(), input.size(), kHeight,
                            kWidth, 0, 0, 0, output.data(), output.size() - 1,
                            error, sizeof(error)),
        "short DFT output", error);
    require_abi_failure(
        cmfd_proof_cuda_dft(context, input.data(), input.size(), kHeight,
                            kWidth, 2, 0, 0, output.data(), output.size(), error,
                            sizeof(error)),
        "invalid inverse flag", error);
    require_abi_failure(
        cmfd_proof_cuda_dft(context, nullptr, 0, UINT32_C(1) << 25, 1, 0, 0,
                            0, nullptr, 0, error, sizeof(error)),
        "DFT log-height cap", error);
    require_abi_failure(
        cmfd_proof_cuda_dft(context, nullptr, 0, 1, UINT32_C(16385), 0, 0, 0,
                            nullptr, 0, error, sizeof(error)),
        "DFT width cap", error);
    require_abi_failure(
        cmfd_proof_cuda_dft(context, nullptr, 0, UINT32_C(1) << 20, 4096, 0,
                            0, 0, nullptr, 0, error, sizeof(error)),
        "DFT element cap", error);

    require_abi_success(
        cmfd_proof_cuda_dft(
            context, input.data(), input.size(), kHeight, kWidth, 0,
            static_cast<std::uint32_t>(RowOrder::kNatural),
            static_cast<std::uint32_t>(RowOrder::kBitReversed), output.data(),
            output.size(), error, sizeof(error)),
        "forward bit-reversed DFT", error);
    compare_exact(expected_bit_reversed, output, kWidth,
                  "C ABI physical bit-reversed DFT output");

    std::vector<u64> recovered(input.size());
    require_abi_success(
        cmfd_proof_cuda_dft(
            context, output.data(), output.size(), kHeight, kWidth, 1,
            static_cast<std::uint32_t>(RowOrder::kBitReversed),
            static_cast<std::uint32_t>(RowOrder::kNatural), recovered.data(),
            recovered.size(), error, sizeof(error)),
        "inverse bit-reversed DFT", error);
    compare_exact(input, recovered, kWidth,
                  "C ABI inverse bit-reversed DFT input");

    std::vector<u64> in_place = input;
    require_abi_success(
        cmfd_proof_cuda_dft(
            context, in_place.data(), in_place.size(), kHeight, kWidth, 0,
            static_cast<std::uint32_t>(RowOrder::kNatural),
            static_cast<std::uint32_t>(RowOrder::kNatural), in_place.data(),
            in_place.size(), error, sizeof(error)),
        "in-place DFT", error);
    compare_exact(expected_natural, in_place, kWidth, "C ABI in-place DFT");

    constexpr std::uint32_t kLdeHeight = 8;
    constexpr std::uint32_t kLdeWidth = 3;
    constexpr std::uint32_t kAddedBits = 2;
    const std::vector<u64> lde_input =
        make_vector(kLdeHeight, kLdeWidth, Pattern::kDeterministicRandom);
    const std::vector<u64> lde_input_bit_reversed =
        bit_reverse_physical(lde_input, kLdeHeight, kLdeWidth);
    const std::vector<u64> lde_expected_natural = host_coset_lde(
        lde_input, kLdeHeight, kLdeWidth, kAddedBits, kGenerator);
    const std::vector<u64> lde_expected_bit_reversed = bit_reverse_physical(
        lde_expected_natural, kLdeHeight << kAddedBits, kLdeWidth);
    std::vector<u64> lde_output(lde_expected_bit_reversed.size());
    require_abi_failure(
        cmfd_proof_cuda_coset_lde(
            context, lde_input.data(), lde_input.size(), kLdeHeight, kLdeWidth,
            kAddedBits, 0, 0, 0, lde_output.data(), lde_output.size(), error,
            sizeof(error)),
        "zero coset shift", error);
    require_abi_failure(
        cmfd_proof_cuda_coset_lde(
            context, lde_input.data(), lde_input.size(), kLdeHeight, kLdeWidth,
            kAddedBits, kGenerator, 0, 0, lde_output.data(),
            lde_output.size() - 1, error, sizeof(error)),
        "short coset LDE output", error);
    require_abi_failure(
        cmfd_proof_cuda_coset_lde(
            context, nullptr, 0, UINT32_C(1) << 24, 1, 1, kGenerator, 0, 0,
            nullptr, 0, error, sizeof(error)),
        "coset LDE expanded log-height cap", error);
    require_abi_success(
        cmfd_proof_cuda_coset_lde(
            context, lde_input_bit_reversed.data(),
            lde_input_bit_reversed.size(), kLdeHeight, kLdeWidth, kAddedBits,
            kGenerator,
            static_cast<std::uint32_t>(RowOrder::kBitReversed),
            static_cast<std::uint32_t>(RowOrder::kBitReversed),
            lde_output.data(), lde_output.size(), error, sizeof(error)),
        "bit-reversed coset LDE", error);
    compare_exact(lde_expected_bit_reversed, lde_output, kLdeWidth,
                  "C ABI physical bit-reversed coset LDE output");

    const std::vector<u64> coefficient_input =
        make_vector(kLdeHeight, kLdeWidth, Pattern::kAlternating);
    const std::vector<u64> physical_coefficient_input = bit_reverse_physical(
        coefficient_input, kLdeHeight, kLdeWidth);
    const std::vector<u64> coefficient_expected_natural =
        host_coefficients_to_coset_lde(coefficient_input, kLdeHeight,
                                       kLdeWidth, kAddedBits, kGenerator);
    const std::vector<u64> coefficient_expected_physical =
        bit_reverse_physical(coefficient_expected_natural,
                             kLdeHeight << kAddedBits, kLdeWidth);
    std::vector<u64> coefficient_output(coefficient_expected_physical.size());
    require_abi_success(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, physical_coefficient_input.data(),
            physical_coefficient_input.size(), kLdeHeight, kLdeWidth,
            kAddedBits, kGenerator, coefficient_output.data(),
            coefficient_output.size(), error, sizeof(error)),
        "physical coefficient-to-coset LDE", error);
    compare_exact(coefficient_expected_physical, coefficient_output,
                  kLdeWidth,
                  "C ABI physical coefficient-to-coset LDE output");

    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            nullptr, physical_coefficient_input.data(),
            physical_coefficient_input.size(), kLdeHeight, kLdeWidth,
            kAddedBits, kGenerator, coefficient_output.data(),
            coefficient_output.size(), error, sizeof(error)),
        "null coefficient LDE context", error);
    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, nullptr, physical_coefficient_input.size(), kLdeHeight,
            kLdeWidth, kAddedBits, kGenerator, coefficient_output.data(),
            coefficient_output.size(), error, sizeof(error)),
        "null coefficient LDE input", error);
    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, physical_coefficient_input.data(),
            physical_coefficient_input.size() - 1, kLdeHeight, kLdeWidth,
            kAddedBits, kGenerator, coefficient_output.data(),
            coefficient_output.size(), error, sizeof(error)),
        "short coefficient LDE input", error);
    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, physical_coefficient_input.data(),
            physical_coefficient_input.size(), kLdeHeight, kLdeWidth,
            kAddedBits, kGenerator, nullptr, coefficient_output.size(), error,
            sizeof(error)),
        "null coefficient LDE output", error);
    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, physical_coefficient_input.data(),
            physical_coefficient_input.size(), kLdeHeight, kLdeWidth,
            kAddedBits, kGenerator, coefficient_output.data(),
            coefficient_output.size() - 1, error, sizeof(error)),
        "short coefficient LDE output", error);
    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, physical_coefficient_input.data(),
            physical_coefficient_input.size(), kLdeHeight, kLdeWidth,
            kAddedBits, 0, coefficient_output.data(), coefficient_output.size(),
            error, sizeof(error)),
        "zero coefficient LDE shift", error);
    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, physical_coefficient_input.data(),
            physical_coefficient_input.size(), kLdeHeight, kLdeWidth,
            kAddedBits, kGoldilocksPrime, coefficient_output.data(),
            coefficient_output.size(), error, sizeof(error)),
        "noncanonical coefficient LDE shift", error);
    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, nullptr, 0, 3, 1, 1, kGenerator, nullptr, 0, error,
            sizeof(error)),
        "non-power-of-two coefficient LDE height", error);
    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, nullptr, 0, UINT32_C(1) << 24, 1, 1, kGenerator, nullptr,
            0, error, sizeof(error)),
        "coefficient LDE expanded log-height cap", error);

    std::vector<u64> noncanonical_coefficients = physical_coefficient_input;
    noncanonical_coefficients[2] = kGoldilocksPrime;
    require_abi_failure(
        cmfd_proof_cuda_coefficients_to_coset_lde(
            context, noncanonical_coefficients.data(),
            noncanonical_coefficients.size(), kLdeHeight, kLdeWidth,
            kAddedBits, kGenerator, coefficient_output.data(),
            coefficient_output.size(), error, sizeof(error)),
        "noncanonical coefficient LDE input", error);

    std::vector<u64> noncanonical = input;
    noncanonical[3] = kGoldilocksPrime;
    std::memset(error, 0, sizeof(error));
    if (cmfd_proof_cuda_dft(
            context, noncanonical.data(), noncanonical.size(), kHeight, kWidth,
            0, 0, 0, output.data(), output.size(), error, sizeof(error)) == 0 ||
        error[0] == '\0') {
      fail("CUDA proof C ABI accepted a noncanonical input");
    }

    char bounded_error[8];
    std::memset(bounded_error, 'X', sizeof(bounded_error));
    if (cmfd_proof_cuda_dft(context, input.data(), input.size(), kHeight,
                            kWidth, 0, 7, 0, output.data(), output.size(),
                            bounded_error, sizeof(bounded_error)) == 0 ||
        bounded_error[sizeof(bounded_error) - 1] != '\0') {
      fail("CUDA proof C ABI did not bound and terminate its error string");
    }
  } catch (...) {
    cmfd_proof_cuda_destroy(context);
    throw;
  }
  cmfd_proof_cuda_destroy(context);
  cmfd_proof_cuda_destroy(nullptr);
  std::printf(
      "PASS proof C ABI v2: lifecycle, forward/inverse, natural/bit-reversed, "
      "coset-LDE, coefficient-LDE, aliasing, nulls, bounds, canonicality, "
      "and errors\n");
}

template <typename Function>
void expect_rejection(const char* name, Function&& function) {
  bool rejected = false;
  try {
    function();
  } catch (const std::exception&) {
    rejected = true;
  }
  if (!rejected) {
    fail(std::string("invalid input was accepted: ") + name);
  }
}

void test_rejections() {
  expect_rejection("zero width", [] { gpu_dft({1}, 1, 0); });
  expect_rejection("non-power-of-two height",
                   [] { gpu_dft({1, 2, 3}, 3, 1); });
  expect_rejection("mismatched shape",
                   [] { gpu_dft({1, 2, 3}, 2, 2); });
  expect_rejection("noncanonical field limb", [] {
    gpu_dft({1, kGoldilocksPrime}, 2, 1);
  });
  expect_rejection("zero coset shift", [] {
    gpu_coset_lde({1, 2}, 2, 1, 1, 0);
  });
  expect_rejection("noncanonical coset shift", [] {
    gpu_coset_lde({1, 2}, 2, 1, 1, kGoldilocksPrime);
  });
  expect_rejection("two-adicity overflow", [] {
    gpu_coset_lde({1, 2}, 2, 1, 32, kGenerator);
  });
  std::printf("PASS validation: invalid shapes, limbs, shifts, and domains rejected\n");
}

void run_large_benchmarks() {
  constexpr std::size_t kHeight = 32768;
  constexpr std::size_t kWidth = 291;
  const std::vector<u64> input =
      make_vector(kHeight, kWidth, Pattern::kDeterministicRandom);
  const GpuResult result = gpu_dft(input, kHeight, kWidth, false);
  const double butterflies =
      static_cast<double>(kHeight / 2) * kWidth * strict_log2(kHeight);
  const double millions_per_second =
      butterflies / (static_cast<double>(result.kernel_milliseconds) * 1000.0);
  std::printf(
      "BENCH DFT %zux%zu: kernel %.3f ms, end-to-end %.3f ms, %.2f M "
      "butterflies/s\n",
      kHeight, kWidth, result.kernel_milliseconds,
      result.end_to_end_milliseconds, millions_per_second);

  constexpr unsigned kAddedBits = 7;
  const std::size_t expanded_height = kHeight << kAddedBits;
  const std::size_t expanded_elements = checked_elements(expanded_height, kWidth);
  const double output_gib = static_cast<double>(expanded_elements * sizeof(u64)) /
                            static_cast<double>(UINT64_C(1) << 30);
  const GpuResult coset_result = gpu_coset_lde(
      input, kHeight, kWidth, kAddedBits, kGenerator, false);
  std::printf(
      "BENCH coset LDE %zux%zu +%u bits -> %zux%zu (%.3f GiB): device "
      "pipeline %.3f ms, end-to-end %.3f ms\n",
      kHeight, kWidth, kAddedBits, expanded_height, kWidth, output_gib,
      coset_result.kernel_milliseconds, coset_result.end_to_end_milliseconds);

  const std::vector<u64> physical_coefficients =
      bit_reverse_physical(input, kHeight, kWidth);
  const GpuResult coefficient_result = gpu_coefficients_to_coset_lde(
      physical_coefficients, kHeight, kWidth, kAddedBits, kGenerator, false);
  std::printf(
      "BENCH coefficient LDE %zux%zu +%u bits -> %zux%zu (%.3f GiB): "
      "device pipeline %.3f ms, end-to-end %.3f ms, no host-expanded "
      "matrix\n",
      kHeight, kWidth, kAddedBits, expanded_height, kWidth, output_gib,
      coefficient_result.kernel_milliseconds,
      coefficient_result.end_to_end_milliseconds);
}

}  // namespace

#if !defined(CMFD_PROOF_BACKEND_LIBRARY)
int main(int argc, char** argv) {
  try {
    bool large_bench = false;
    for (int index = 1; index < argc; ++index) {
      const std::string argument = argv[index];
      if (argument == "--large-bench") {
        large_bench = true;
      } else if (argument == "--help") {
        std::printf("Usage: %s [--large-bench]\n", argv[0]);
        return EXIT_SUCCESS;
      } else {
        fail("unknown argument: " + argument);
      }
    }
    int device_count = 0;
    CUDA_CHECK(cudaGetDeviceCount(&device_count));
    if (device_count <= 0) {
      fail("no CUDA device is available");
    }
    CUDA_CHECK(cudaSetDevice(0));
    cudaDeviceProp properties{};
    CUDA_CHECK(cudaGetDeviceProperties(&properties, 0));
    std::printf("Common Foundry standalone Goldilocks CUDA canary\n");
    std::printf("Device 0: %s (sm_%d%d, %zu MiB)\n", properties.name,
                properties.major, properties.minor,
                properties.totalGlobalMem / (1024U * 1024U));

    for (unsigned log_height = 0; log_height <= 20; ++log_height) {
      validate_root(log_height);
    }
    std::printf("PASS two-adic roots: orders 2^0 through 2^20\n");
    test_field_arithmetic();
    test_known_plonky3_vectors();
    test_dfts();
    test_coset_ldes();
    test_coefficient_coset_ldes();
    test_c_abi();
    test_rejections();
    if (large_bench) {
      run_large_benchmarks();
    } else {
      std::printf("INFO large 32768x291 benchmarks skipped; pass --large-bench to run them\n");
    }
    CUDA_CHECK(cudaDeviceSynchronize());
    std::printf("PASS all exact CUDA proof-acceleration canary checks\n");
    return EXIT_SUCCESS;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "FAIL: %s\n", error.what());
    return EXIT_FAILURE;
  }
}
#endif
