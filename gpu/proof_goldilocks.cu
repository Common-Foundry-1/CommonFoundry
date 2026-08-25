// Optional, non-consensus CUDA backend and standalone canary for exact
// Goldilocks DFT acceleration.
//
// The shared library is independently versioned and is never loaded
// automatically by the node, wallet, miner, or verifier. The executable tests
// integer-only CUDA arithmetic against an independent host oracle and exits
// nonzero on every mismatch or CUDA failure.

#include <cuda_runtime.h>

#include <algorithm>
#include <array>
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

// Proof-stream ABI v1 descriptor. Coefficients use the physical storage order
// beneath Plonky3's BitReversedMatrixView. Buffer lengths count u64 elements.
struct CmfdProofStreamMatrixV1 {
  const std::uint64_t* physical_coefficients;
  std::size_t coefficients_len;
  std::uint32_t height;
  std::uint32_t width;
  std::uint64_t coset_shift;
};

static_assert(sizeof(void*) == 8,
              "the proof-stream ABI supports 64-bit hosts only");
static_assert(sizeof(CmfdProofStreamMatrixV1) == 32,
              "unexpected proof-stream descriptor layout");
static_assert(offsetof(CmfdProofStreamMatrixV1, physical_coefficients) == 0);
static_assert(offsetof(CmfdProofStreamMatrixV1, coefficients_len) == 8);
static_assert(offsetof(CmfdProofStreamMatrixV1, height) == 16);
static_assert(offsetof(CmfdProofStreamMatrixV1, width) == 20);
static_assert(offsetof(CmfdProofStreamMatrixV1, coset_shift) == 24);

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
constexpr std::uint32_t kProofStreamApiVersion = 1;
constexpr std::size_t kProofStreamMaxHeight = std::size_t{1} << 20;
constexpr unsigned kProofStreamMaxAddedBits = 7;
constexpr std::size_t kProofStreamMaxExpandedHeight = std::size_t{1} << 27;
constexpr std::size_t kProofStreamMaxMatrices = 64;
constexpr std::size_t kProofStreamMaxWidth = 4096;
constexpr std::size_t kProofStreamMaxInputElements = std::size_t{1} << 31;
constexpr std::size_t kProofStreamMaxRequestedRows = std::size_t{1} << 16;
constexpr std::size_t kProofStreamDigestWidth = 4;
constexpr std::size_t kProofStreamStateWidth = 8;
constexpr std::size_t kProofStreamRate = 4;
constexpr u64 kProofStreamHalf = UINT64_C(0x7fffffff80000001);
constexpr u64 kProofStreamContextMagic = UINT64_C(0x434d464453545231);

// Plonky3 0.6.3 Goldilocks Poseidon2 width-8 parameters and round constants
// (Copyright Plonky3 contributors, MIT OR Apache-2.0). They are intentionally
// pinned here so proof_stream remains one fused CUDA operation rather than
// copying each LDE chunk through the separate Poseidon2 ABI.
constexpr std::array<u64, 32> kStreamExternalInitial = {
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

constexpr std::array<u64, 32> kStreamExternalFinal = {
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

constexpr std::array<u64, 22> kStreamInternal = {
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

__device__ __constant__ u64 kStreamDeviceExternalInitial[32];
__device__ __constant__ u64 kStreamDeviceExternalFinal[32];
__device__ __constant__ u64 kStreamDeviceInternal[22];

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

struct ProofStreamContext {
  u64 magic = kProofStreamContextMagic;
  int device_index = -1;
  std::size_t height = 0;
  std::size_t total_width = 0;
  std::size_t expanded_height = 0;
  unsigned log_height = 0;
  unsigned added_bits = 0;
  std::size_t matrix_count = 0;
  std::vector<u64> shifts;
  std::unique_ptr<DeviceBuffer> device_coefficients;
  std::unique_ptr<DeviceBuffer> device_workspace;
  std::unique_ptr<DeviceBuffer> device_twiddles;
  std::unique_ptr<DeviceBuffer> device_matrix_for_column;
  std::unique_ptr<DeviceBuffer> device_shift_powers;
  std::unique_ptr<DeviceBuffer> device_bases;
  std::unique_ptr<DeviceBuffer> device_digests;
  std::uint64_t cursor = 0;
  std::uint64_t loaded_coset_block = std::numeric_limits<std::uint64_t>::max();
  std::mutex operation_mutex;
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

u64 stream_host_sbox(u64 value) {
  const u64 square = host_mul(value, value);
  const u64 fourth = host_mul(square, square);
  return host_mul(host_mul(fourth, square), value);
}

void stream_host_external_linear(
    std::array<u64, kProofStreamStateWidth>& state) {
  constexpr std::uint32_t matrix[4][4] = {
      {2, 3, 1, 1},
      {1, 2, 3, 1},
      {1, 1, 2, 3},
      {3, 1, 1, 2},
  };
  std::array<u64, kProofStreamStateWidth> local{};
  for (std::size_t chunk = 0; chunk < 2; ++chunk) {
    for (std::size_t row = 0; row < 4; ++row) {
      u64 sum = 0;
      for (std::size_t column = 0; column < 4; ++column) {
        for (std::uint32_t copy = 0; copy < matrix[row][column]; ++copy) {
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

void stream_host_external_rounds(
    std::array<u64, kProofStreamStateWidth>& state,
    const std::array<u64, 32>& constants) {
  for (std::size_t round = 0; round < 4; ++round) {
    for (std::size_t lane = 0; lane < kProofStreamStateWidth; ++lane) {
      state[lane] =
          stream_host_sbox(host_add(state[lane], constants[round * 8 + lane]));
    }
    stream_host_external_linear(state);
  }
}

void stream_host_internal_linear(
    std::array<u64, kProofStreamStateWidth>& state) {
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

void stream_host_permute(std::array<u64, kProofStreamStateWidth>& state) {
  stream_host_external_linear(state);
  stream_host_external_rounds(state, kStreamExternalInitial);
  for (u64 round_constant : kStreamInternal) {
    state[0] = stream_host_sbox(host_add(state[0], round_constant));
    stream_host_internal_linear(state);
  }
  stream_host_external_rounds(state, kStreamExternalFinal);
}

std::array<u64, kProofStreamDigestWidth> stream_host_hash_row(
    const u64* row, std::size_t width) {
  validate_canonical(row, width, "proof stream host Poseidon2 input");
  std::array<u64, kProofStreamStateWidth> state{};
  for (std::size_t offset = 0; offset < width;
       offset += kProofStreamRate) {
    const std::size_t absorbed =
        std::min(kProofStreamRate, width - offset);
    for (std::size_t lane = 0; lane < absorbed; ++lane) {
      state[lane] = row[offset + lane];
    }
    stream_host_permute(state);
  }
  return {state[0], state[1], state[2], state[3]};
}

std::vector<u64> stream_host_hash_rows(const std::vector<u64>& input,
                                       std::size_t rows,
                                       std::size_t width) {
  if (input.size() != checked_elements(rows, width)) {
    fail("proof stream host Poseidon2 fixture shape mismatch");
  }
  std::vector<u64> output(rows * kProofStreamDigestWidth);
  for (std::size_t row = 0; row < rows; ++row) {
    const auto digest =
        stream_host_hash_row(input.data() + row * width, width);
    std::copy(digest.begin(), digest.end(),
              output.begin() + row * kProofStreamDigestWidth);
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

__device__ __forceinline__ u64 stream_device_pow(u64 base,
                                                  std::size_t exponent) {
  u64 result = 1;
  while (exponent != 0) {
    if ((exponent & 1U) != 0) {
      result = device_mul(result, base);
    }
    exponent >>= 1;
    if (exponent != 0) {
      base = device_mul(base, base);
    }
  }
  return result;
}

__device__ __forceinline__ u64 stream_device_sbox(u64 value) {
  const u64 square = device_mul(value, value);
  const u64 fourth = device_mul(square, square);
  return device_mul(device_mul(fourth, square), value);
}

__device__ __forceinline__ u64 stream_device_half(u64 value) {
  return (value >> 1) + ((value & 1U) != 0 ? kProofStreamHalf : 0);
}

__device__ __forceinline__ void stream_device_mat4(u64* values) {
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

__device__ __forceinline__ void stream_device_external_linear(u64 state[8]) {
  stream_device_mat4(state);
  stream_device_mat4(state + 4);
#pragma unroll
  for (int lane = 0; lane < 4; ++lane) {
    const u64 sum = device_add(state[lane], state[lane + 4]);
    state[lane] = device_add(state[lane], sum);
    state[lane + 4] = device_add(state[lane + 4], sum);
  }
}

__device__ __forceinline__ void stream_device_internal_linear(u64 state[8]) {
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
  state[3] = device_add(sum, stream_device_half(x3));
  state[4] = device_add(sum, device_add(device_add(x4, x4), x4));
  state[5] = device_sub(sum, stream_device_half(x5));
  state[6] = device_sub(sum, device_add(device_add(x6, x6), x6));
  state[7] = device_sub(
      sum, device_add(device_add(x7, x7), device_add(x7, x7)));
}

__device__ __forceinline__ void stream_device_external_rounds(
    u64 state[8], const u64* constants) {
#pragma unroll
  for (int round = 0; round < 4; ++round) {
#pragma unroll
    for (int lane = 0; lane < 8; ++lane) {
      state[lane] = stream_device_sbox(
          device_add(state[lane], constants[round * 8 + lane]));
    }
    stream_device_external_linear(state);
  }
}

__device__ __forceinline__ void stream_device_permute(u64 state[8]) {
  stream_device_external_linear(state);
  stream_device_external_rounds(state, kStreamDeviceExternalInitial);
#pragma unroll
  for (int round = 0; round < 22; ++round) {
    state[0] = stream_device_sbox(
        device_add(state[0], kStreamDeviceInternal[round]));
    stream_device_internal_linear(state);
  }
  stream_device_external_rounds(state, kStreamDeviceExternalFinal);
}

__global__ void stream_shift_powers_kernel(const u64* bases, u64* powers,
                                            std::size_t height,
                                            std::size_t matrix_count) {
  const std::size_t index =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  const std::size_t count = height * matrix_count;
  if (index < count) {
    const std::size_t row = index / matrix_count;
    const std::size_t matrix = index - row * matrix_count;
    powers[index] = stream_device_pow(bases[matrix], row);
  }
}

__global__ void stream_scale_coefficients_kernel(
    const u64* coefficients, u64* workspace, const u64* shift_powers,
    const u64* matrix_for_column, std::size_t height,
    std::size_t total_width, std::size_t matrix_count) {
  const std::size_t index =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  const std::size_t count = height * total_width;
  if (index < count) {
    const std::size_t row = index / total_width;
    const std::size_t column = index - row * total_width;
    const std::size_t matrix = matrix_for_column[column];
    workspace[index] = device_mul(
        coefficients[index], shift_powers[row * matrix_count + matrix]);
  }
}

__global__ void stream_hash_rows_kernel(const u64* input, u64* output,
                                         std::size_t row_start,
                                         std::size_t row_count,
                                         std::size_t width) {
  const std::size_t local_row =
      static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (local_row >= row_count) {
    return;
  }
  const u64* row_input = input + (row_start + local_row) * width;
  u64 state[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (std::size_t offset = 0; offset < width; offset += kProofStreamRate) {
    const std::size_t absorbed =
        width - offset < kProofStreamRate ? width - offset : kProofStreamRate;
#pragma unroll
    for (int lane = 0; lane < 4; ++lane) {
      if (static_cast<std::size_t>(lane) < absorbed) {
        state[lane] = row_input[offset + lane];
      }
    }
    stream_device_permute(state);
  }
  u64* digest = output + local_row * kProofStreamDigestWidth;
#pragma unroll
  for (int lane = 0; lane < 4; ++lane) {
    digest[lane] = state[lane];
  }
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

struct CheckedProofStreamInput {
  std::size_t height;
  std::size_t total_width;
  std::size_t expanded_height;
  unsigned log_height;
  std::vector<u64> shifts;
  std::vector<u64> matrix_for_column;
};

CheckedProofStreamInput checked_proof_stream_input(
    const CmfdProofStreamMatrixV1* matrices, std::size_t matrix_count,
    unsigned added_bits) {
  if (matrix_count == 0) {
    fail("proof stream matrix count must be nonzero");
  }
  if (matrix_count > kProofStreamMaxMatrices) {
    fail("proof stream matrix count exceeds the ABI v1 limit");
  }
  if (matrices == nullptr) {
    fail("proof stream matrix descriptor array is null");
  }
  if (added_bits > kProofStreamMaxAddedBits) {
    fail("proof stream added bits exceed the ABI v1 limit");
  }

  const std::size_t height = matrices[0].height;
  if (height == 0 || !is_power_of_two(height)) {
    fail("proof stream height must be a nonzero power of two");
  }
  if (height > kProofStreamMaxHeight) {
    fail("proof stream source height exceeds the ABI v1 limit");
  }
  const unsigned log_height = strict_log2(height);
  if (log_height + added_bits > 27) {
    fail("proof stream expanded height exceeds the ABI v1 two-adic limit");
  }
  const std::size_t expanded_height = height << added_bits;
  if (expanded_height > kProofStreamMaxExpandedHeight) {
    fail("proof stream expanded height exceeds the ABI v1 limit");
  }

  std::size_t total_width = 0;
  std::size_t total_input_elements = 0;
  std::vector<u64> shifts;
  shifts.reserve(matrix_count);
  std::vector<u64> matrix_for_column;
  for (std::size_t index = 0; index < matrix_count; ++index) {
    const auto& matrix = matrices[index];
    if (matrix.height != height) {
      fail("proof stream matrices must have equal source heights");
    }
    if (matrix.width == 0) {
      fail("proof stream matrix width must be nonzero at descriptor " +
           std::to_string(index));
    }
    if (matrix.width > kProofStreamMaxWidth ||
        total_width > kProofStreamMaxWidth - matrix.width) {
      fail("proof stream concatenated row width exceeds the ABI v1 limit");
    }
    const std::size_t expected_len = checked_elements(height, matrix.width);
    if (matrix.coefficients_len != expected_len) {
      fail("proof stream coefficient length does not equal height times width at descriptor " +
           std::to_string(index));
    }
    validate_canonical(matrix.physical_coefficients, matrix.coefficients_len,
                       "proof stream physical coefficient input");
    if (matrix.coset_shift == 0 || matrix.coset_shift >= kGoldilocksPrime) {
      fail("proof stream coset shift must be canonical and nonzero at descriptor " +
           std::to_string(index));
    }
    if (expected_len > kProofStreamMaxInputElements ||
        total_input_elements >
            kProofStreamMaxInputElements - expected_len) {
      fail("proof stream coefficient count exceeds the ABI v1 limit");
    }
    total_input_elements += expected_len;
    total_width += matrix.width;
    shifts.push_back(matrix.coset_shift);
    matrix_for_column.insert(matrix_for_column.end(), matrix.width,
                             static_cast<u64>(index));
  }

  return {height, total_width, expanded_height, log_height,
          std::move(shifts), std::move(matrix_for_column)};
}

void load_proof_stream_poseidon_constants() {
  CUDA_CHECK(cudaMemcpyToSymbol(kStreamDeviceExternalInitial,
                                kStreamExternalInitial.data(),
                                sizeof(kStreamExternalInitial)));
  CUDA_CHECK(cudaMemcpyToSymbol(kStreamDeviceExternalFinal,
                                kStreamExternalFinal.data(),
                                sizeof(kStreamExternalFinal)));
  CUDA_CHECK(cudaMemcpyToSymbol(kStreamDeviceInternal, kStreamInternal.data(),
                                sizeof(kStreamInternal)));
}

void launch_proof_stream_dft(ProofStreamContext& context) {
  const std::size_t elements =
      checked_elements(context.height, context.total_width);
  bit_reverse_rows_kernel<<<launch_blocks(elements), kThreads>>>(
      context.device_workspace->data(), context.height, context.total_width,
      context.log_height);
  CUDA_CHECK(cudaGetLastError());

  for (std::size_t length = 2; length <= context.height; length <<= 1) {
    const std::size_t half = length >> 1;
    const std::size_t butterflies = (context.height >> 1) * context.total_width;
    butterfly_kernel<<<launch_blocks(butterflies), kThreads>>>(
        context.device_workspace->data(), context.device_twiddles->data(),
        context.height, context.total_width, half);
    CUDA_CHECK(cudaGetLastError());
  }

  bit_reverse_rows_kernel<<<launch_blocks(elements), kThreads>>>(
      context.device_workspace->data(), context.height, context.total_width,
      context.log_height);
  CUDA_CHECK(cudaGetLastError());
}

void prepare_proof_stream_coset_block(ProofStreamContext& context,
                                      std::uint64_t block) {
  if (context.loaded_coset_block == block) {
    return;
  }
  const std::size_t block_count = std::size_t{1} << context.added_bits;
  if (block >= block_count) {
    fail("proof stream coset block is outside the expanded domain");
  }
  const std::size_t natural_coset =
      reverse_bits(static_cast<std::size_t>(block), context.added_bits);
  const u64 expanded_root =
      two_adic_root(context.log_height + context.added_bits);
  const u64 coset_root = host_pow(expanded_root, natural_coset);
  std::vector<u64> bases(context.matrix_count);
  for (std::size_t index = 0; index < context.matrix_count; ++index) {
    bases[index] = host_mul(context.shifts[index], coset_root);
  }
  CUDA_CHECK(cudaMemcpy(context.device_bases->data(), bases.data(),
                        bases.size() * sizeof(u64), cudaMemcpyHostToDevice));

  const std::size_t power_count = context.height * context.matrix_count;
  stream_shift_powers_kernel<<<launch_blocks(power_count), kThreads>>>(
      context.device_bases->data(), context.device_shift_powers->data(),
      context.height, context.matrix_count);
  CUDA_CHECK(cudaGetLastError());
  const std::size_t coefficient_count =
      checked_elements(context.height, context.total_width);
  stream_scale_coefficients_kernel<<<launch_blocks(coefficient_count),
                                     kThreads>>>(
      context.device_coefficients->data(), context.device_workspace->data(),
      context.device_shift_powers->data(),
      context.device_matrix_for_column->data(), context.height,
      context.total_width, context.matrix_count);
  CUDA_CHECK(cudaGetLastError());
  launch_proof_stream_dft(context);
  CUDA_CHECK(cudaStreamSynchronize(0));
  context.loaded_coset_block = block;
}

ProofStreamContext& checked_proof_stream_context(void* opaque_context) {
  if (opaque_context == nullptr) {
    fail("proof stream context is null");
  }
  auto& context = *static_cast<ProofStreamContext*>(opaque_context);
  if (context.magic != kProofStreamContextMagic || context.device_index < 0) {
    fail("proof stream context is invalid");
  }
  return context;
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

// Proof-stream ABI v1. This interface is independently versioned from the DFT
// and Poseidon2 ABIs. create synchronously copies every coefficient matrix;
// callers may release those inputs after it returns. next emits monotonically
// ordered physical bit-reversed LDE rows and the corresponding unpadded P3
// Poseidon2 first-digest rows. A request may not cross a source-height coset
// block. Calls on one handle serialize internally; destroy must not race next.
CMFD_PROOF_EXPORT std::uint32_t cmfd_proof_stream_api_version() noexcept {
  return kProofStreamApiVersion;
}

CMFD_PROOF_EXPORT std::int32_t cmfd_proof_stream_create(
    std::int32_t device_index, const CmfdProofStreamMatrixV1* matrices,
    std::size_t matrix_count, std::uint32_t added_bits, void** output_context,
    char* error, std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    if (output_context == nullptr) {
      fail("proof stream context output is null");
    }
    *output_context = nullptr;
    CheckedProofStreamInput input =
        checked_proof_stream_input(matrices, matrix_count, added_bits);

    int device_count = 0;
    CUDA_CHECK(cudaGetDeviceCount(&device_count));
    if (device_index < 0 || device_index >= device_count) {
      fail("proof stream CUDA device index is out of range");
    }
    CUDA_CHECK(cudaSetDevice(device_index));
    cudaDeviceProp properties{};
    CUDA_CHECK(cudaGetDeviceProperties(&properties, device_index));
    if (properties.major < 7) {
      fail("proof stream requires compute capability 7.0 or newer");
    }

    auto context = std::make_unique<ProofStreamContext>();
    context->device_index = device_index;
    context->height = input.height;
    context->total_width = input.total_width;
    context->expanded_height = input.expanded_height;
    context->log_height = input.log_height;
    context->added_bits = added_bits;
    context->matrix_count = matrix_count;
    context->shifts = std::move(input.shifts);

    const std::size_t coefficient_count =
        checked_elements(context->height, context->total_width);
    context->device_coefficients =
        std::make_unique<DeviceBuffer>(coefficient_count * sizeof(u64));
    context->device_workspace =
        std::make_unique<DeviceBuffer>(coefficient_count * sizeof(u64));

    std::size_t column_offset = 0;
    for (std::size_t index = 0; index < matrix_count; ++index) {
      const auto& matrix = matrices[index];
      CUDA_CHECK(cudaMemcpy2D(
          context->device_coefficients->data() + column_offset,
          context->total_width * sizeof(u64), matrix.physical_coefficients,
          static_cast<std::size_t>(matrix.width) * sizeof(u64),
          static_cast<std::size_t>(matrix.width) * sizeof(u64),
          context->height, cudaMemcpyHostToDevice));
      column_offset += matrix.width;
    }
    bit_reverse_rows_kernel<<<launch_blocks(coefficient_count), kThreads>>>(
        context->device_coefficients->data(), context->height,
        context->total_width, context->log_height);
    CUDA_CHECK(cudaGetLastError());

    const std::vector<u64> twiddles = make_twiddles(context->height, false);
    context->device_twiddles =
        std::make_unique<DeviceBuffer>(twiddles.size() * sizeof(u64));
    CUDA_CHECK(cudaMemcpy(context->device_twiddles->data(), twiddles.data(),
                          twiddles.size() * sizeof(u64),
                          cudaMemcpyHostToDevice));
    context->device_matrix_for_column = std::make_unique<DeviceBuffer>(
        input.matrix_for_column.size() * sizeof(u64));
    CUDA_CHECK(cudaMemcpy(context->device_matrix_for_column->data(),
                          input.matrix_for_column.data(),
                          input.matrix_for_column.size() * sizeof(u64),
                          cudaMemcpyHostToDevice));
    context->device_shift_powers = std::make_unique<DeviceBuffer>(
        context->height * context->matrix_count * sizeof(u64));
    context->device_bases =
        std::make_unique<DeviceBuffer>(context->matrix_count * sizeof(u64));
    const std::size_t digest_rows =
        std::min(context->height, kProofStreamMaxRequestedRows);
    context->device_digests = std::make_unique<DeviceBuffer>(
        digest_rows * kProofStreamDigestWidth * sizeof(u64));
    load_proof_stream_poseidon_constants();
    CUDA_CHECK(cudaStreamSynchronize(0));
    *output_context = context.release();
  });
}

CMFD_PROOF_EXPORT std::int32_t cmfd_proof_stream_next(
    void* opaque_context, std::uint64_t expected_global_physical_row,
    std::uint32_t requested_rows, std::uint64_t* optional_lde_output,
    std::size_t lde_output_len, std::uint64_t* digest_output,
    std::size_t digest_output_len, char* error,
    std::size_t error_len) noexcept {
  return abi_guard(error, error_len, [&] {
    ProofStreamContext& context =
        checked_proof_stream_context(opaque_context);
    std::lock_guard<std::mutex> lock(context.operation_mutex);
    if (expected_global_physical_row != context.cursor) {
      fail("proof stream expected row does not match the monotonic cursor");
    }
    if (context.cursor >= context.expanded_height) {
      fail("proof stream is already complete");
    }
    if (requested_rows == 0 || !is_power_of_two(requested_rows)) {
      fail("proof stream requested rows must be a nonzero power of two");
    }
    if (requested_rows > kProofStreamMaxRequestedRows) {
      fail("proof stream requested rows exceed the ABI v1 limit");
    }
    const std::size_t rows = requested_rows;
    const std::size_t remaining =
        context.expanded_height - static_cast<std::size_t>(context.cursor);
    if (rows > remaining) {
      fail("proof stream request exceeds the remaining expanded rows");
    }
    const std::size_t local_row =
        static_cast<std::size_t>(context.cursor % context.height);
    if (rows > context.height - local_row) {
      fail("proof stream request crosses a source-height coset block");
    }

    const std::size_t expected_digest_len =
        rows * kProofStreamDigestWidth;
    if (digest_output == nullptr) {
      fail("proof stream digest output is null");
    }
    if (digest_output_len != expected_digest_len) {
      fail("proof stream digest length does not equal requested rows times four");
    }
    const std::size_t expected_lde_len = rows * context.total_width;
    if (optional_lde_output == nullptr) {
      if (lde_output_len != 0) {
        fail("proof stream omitted LDE output must have length zero");
      }
    } else if (lde_output_len != expected_lde_len) {
      fail("proof stream LDE length does not equal requested rows times total width");
    }

    CUDA_CHECK(cudaSetDevice(context.device_index));
    const std::uint64_t coset_block = context.cursor / context.height;
    prepare_proof_stream_coset_block(context, coset_block);
    stream_hash_rows_kernel<<<launch_blocks(rows), kThreads>>>(
        context.device_workspace->data(), context.device_digests->data(),
        local_row, rows, context.total_width);
    CUDA_CHECK(cudaGetLastError());
    if (optional_lde_output != nullptr) {
      CUDA_CHECK(cudaMemcpyAsync(
          optional_lde_output,
          context.device_workspace->data() + local_row * context.total_width,
          expected_lde_len * sizeof(u64), cudaMemcpyDeviceToHost));
    }
    CUDA_CHECK(cudaMemcpyAsync(digest_output, context.device_digests->data(),
                               expected_digest_len * sizeof(u64),
                               cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaStreamSynchronize(0));
    validate_canonical(digest_output, digest_output_len,
                       "proof stream digest output");
    context.cursor += rows;
  });
}

CMFD_PROOF_EXPORT void cmfd_proof_stream_destroy(
    void* opaque_context) noexcept {
  if (opaque_context == nullptr) {
    return;
  }
  auto* context = static_cast<ProofStreamContext*>(opaque_context);
  context->magic = 0;
  const int device_index = context->device_index;
  context->device_index = -1;
  if (device_index >= 0) {
    cuda_cleanup_warn(cudaSetDevice(device_index),
                      "cudaSetDevice for proof-stream destroy");
  }
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

struct ProofStreamTestMatrix {
  std::vector<u64> physical_coefficients;
  std::size_t height;
  std::size_t width;
  u64 shift;
};

struct ProofStreamTestOutput {
  std::vector<u64> lde;
  std::vector<u64> digests;
};

std::vector<CmfdProofStreamMatrixV1> proof_stream_descriptors(
    const std::vector<ProofStreamTestMatrix>& matrices) {
  std::vector<CmfdProofStreamMatrixV1> descriptors;
  descriptors.reserve(matrices.size());
  for (const auto& matrix : matrices) {
    descriptors.push_back(
        {matrix.physical_coefficients.data(),
         matrix.physical_coefficients.size(),
         static_cast<std::uint32_t>(matrix.height),
         static_cast<std::uint32_t>(matrix.width), matrix.shift});
  }
  return descriptors;
}

ProofStreamTestOutput proof_stream_host_expected(
    const std::vector<ProofStreamTestMatrix>& matrices,
    unsigned added_bits) {
  if (matrices.empty()) {
    fail("proof stream test fixture has no matrices");
  }
  const std::size_t height = matrices[0].height;
  const std::size_t expanded_height = height << added_bits;
  std::size_t total_width = 0;
  std::vector<std::vector<u64>> physical_ldes;
  physical_ldes.reserve(matrices.size());
  for (const auto& matrix : matrices) {
    if (matrix.height != height) {
      fail("proof stream test fixture heights differ");
    }
    std::vector<u64> natural_coefficients = bit_reverse_physical(
        matrix.physical_coefficients, matrix.height, matrix.width);
    std::vector<u64> natural_lde = host_coefficients_to_coset_lde(
        natural_coefficients, matrix.height, matrix.width, added_bits,
        matrix.shift);
    physical_ldes.push_back(bit_reverse_physical(
        std::move(natural_lde), expanded_height, matrix.width));
    total_width += matrix.width;
  }

  ProofStreamTestOutput output;
  output.lde.reserve(expanded_height * total_width);
  for (std::size_t row = 0; row < expanded_height; ++row) {
    for (std::size_t matrix = 0; matrix < matrices.size(); ++matrix) {
      const std::size_t width = matrices[matrix].width;
      const auto begin = physical_ldes[matrix].begin() + row * width;
      output.lde.insert(output.lde.end(), begin, begin + width);
    }
  }
  output.digests =
      stream_host_hash_rows(output.lde, expanded_height, total_width);
  return output;
}

ProofStreamTestOutput run_proof_stream_test(
    const std::vector<ProofStreamTestMatrix>& matrices, unsigned added_bits,
    const std::vector<std::size_t>& repeating_chunks, bool copy_lde = true) {
  if (matrices.empty() || repeating_chunks.empty()) {
    fail("proof stream test runner received an empty fixture");
  }
  const std::size_t expanded_height = matrices[0].height << added_bits;
  std::size_t total_width = 0;
  for (const auto& matrix : matrices) {
    total_width += matrix.width;
  }
  const auto descriptors = proof_stream_descriptors(matrices);
  char error[256] = {};
  void* context = nullptr;
  if (cmfd_proof_stream_create(0, descriptors.data(), descriptors.size(),
                               added_bits, &context, error,
                               sizeof(error)) != 0) {
    fail(std::string("proof stream test create failed: ") + error);
  }

  ProofStreamTestOutput output;
  if (copy_lde) {
    output.lde.reserve(expanded_height * total_width);
  }
  output.digests.reserve(expanded_height * kProofStreamDigestWidth);
  try {
    std::size_t cursor = 0;
    std::size_t chunk_index = 0;
    while (cursor < expanded_height) {
      const std::size_t rows =
          repeating_chunks[chunk_index++ % repeating_chunks.size()];
      if (rows > std::numeric_limits<std::uint32_t>::max()) {
        fail("proof stream test chunk exceeds u32");
      }
      std::vector<u64> lde_chunk(copy_lde ? rows * total_width : 0);
      std::vector<u64> digest_chunk(rows * kProofStreamDigestWidth);
      if (cmfd_proof_stream_next(
              context, cursor, static_cast<std::uint32_t>(rows),
              copy_lde ? lde_chunk.data() : nullptr, lde_chunk.size(),
              digest_chunk.data(), digest_chunk.size(), error,
              sizeof(error)) != 0) {
        fail(std::string("proof stream test next failed: ") + error);
      }
      output.lde.insert(output.lde.end(), lde_chunk.begin(), lde_chunk.end());
      output.digests.insert(output.digests.end(), digest_chunk.begin(),
                            digest_chunk.end());
      cursor += rows;
    }
  } catch (...) {
    cmfd_proof_stream_destroy(context);
    throw;
  }
  cmfd_proof_stream_destroy(context);
  return output;
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

void test_proof_stream_exactness() {
  if (cmfd_proof_stream_api_version() != kProofStreamApiVersion) {
    fail("proof stream C ABI reported the wrong API version");
  }

  // This one-row vector is pinned independently by p3-goldilocks 0.6.3's
  // PaddingFreeSponge<Poseidon2Goldilocks<8>, 8, 4, 4> fixture.
  constexpr u64 kSalt = UINT64_C(0x123456789abcdef0);
  u64 pinned_input = kSalt;
  pinned_input ^= pinned_input >> 12;
  pinned_input ^= pinned_input << 25;
  pinned_input ^= pinned_input >> 27;
  pinned_input *= UINT64_C(0x2545f4914f6cdd1d);
  if (pinned_input >= kGoldilocksPrime) {
    pinned_input -= kGoldilocksPrime;
  }
  const std::vector<ProofStreamTestMatrix> pinned_matrix = {
      {{pinned_input}, 1, 1, kGenerator}};
  const ProofStreamTestOutput pinned =
      run_proof_stream_test(pinned_matrix, 0, {1});
  compare_exact({pinned_input}, pinned.lde, 1,
                "proof stream pinned one-row LDE");
  const std::vector<u64> pinned_digest = {
      UINT64_C(7668073106091160635), UINT64_C(8186641118638216760),
      UINT64_C(6457284654664772022), UINT64_C(5770619367258960679)};
  compare_exact(pinned_digest, pinned.digests, kProofStreamDigestWidth,
                "proof stream pinned Plonky3 Poseidon2 digest");

  // Convert the already-pinned height-8 Plonky3 evaluation fixture to
  // coefficients. Streaming those coefficients must reproduce the same
  // physical bit-reversed coset LDE for every legal chunk partition.
  std::vector<u64> evaluations(16);
  for (std::size_t index = 0; index < evaluations.size(); ++index) {
    evaluations[index] = static_cast<u64>(index + 1);
  }
  std::vector<u64> coefficients = evaluations;
  host_dft_in_place(coefficients, 8, 2, true);
  const std::vector<ProofStreamTestMatrix> lde_matrix = {
      {bit_reverse_physical(coefficients, 8, 2), 8, 2, kGenerator}};
  const std::vector<u64> expected_natural =
      host_coset_lde(evaluations, 8, 2, 2, kGenerator);
  const std::vector<u64> expected_physical =
      bit_reverse_physical(expected_natural, 32, 2);
  const std::vector<u64> expected_digests =
      stream_host_hash_rows(expected_physical, 32, 2);
  for (const std::vector<std::size_t>& chunks :
       {std::vector<std::size_t>{8}, std::vector<std::size_t>{4},
        std::vector<std::size_t>{1},
        std::vector<std::size_t>{1, 1, 2, 4}}) {
    const ProofStreamTestOutput actual =
        run_proof_stream_test(lde_matrix, 2, chunks);
    compare_exact(expected_physical, actual.lde, 2,
                  "proof stream pinned chunked coset LDE");
    compare_exact(expected_digests, actual.digests,
                  kProofStreamDigestWidth,
                  "proof stream pinned chunked Poseidon2 digests");
  }
  const ProofStreamTestOutput digest_only =
      run_proof_stream_test(lde_matrix, 2, {8}, false);
  if (!digest_only.lde.empty()) {
    fail("proof stream digest-only test unexpectedly materialized LDE rows");
  }
  compare_exact(expected_digests, digest_only.digests,
                kProofStreamDigestWidth,
                "proof stream digest-only Poseidon2 digests");

  // Exercise the proof profile's two widest current matrices, distinct shifts,
  // and insertion-order-sensitive row concatenation.
  const std::vector<u64> first_natural =
      make_vector(8, 87, Pattern::kDeterministicRandom);
  const std::vector<u64> second_natural =
      make_vector(8, 291, Pattern::kAlternating);
  const std::vector<ProofStreamTestMatrix> matrices = {
      {bit_reverse_physical(first_natural, 8, 87), 8, 87, kGenerator},
      {bit_reverse_physical(second_natural, 8, 291), 8, 291, 11}};
  const ProofStreamTestOutput expected =
      proof_stream_host_expected(matrices, 1);
  const ProofStreamTestOutput actual =
      run_proof_stream_test(matrices, 1, {1, 1, 2, 4});
  compare_exact(expected.lde, actual.lde, 378,
                "proof stream ordered multi-matrix LDE");
  compare_exact(expected.digests, actual.digests,
                kProofStreamDigestWidth,
                "proof stream ordered multi-matrix digests");

  std::vector<ProofStreamTestMatrix> reversed = matrices;
  std::reverse(reversed.begin(), reversed.end());
  const ProofStreamTestOutput reversed_expected =
      proof_stream_host_expected(reversed, 1);
  const ProofStreamTestOutput reversed_actual =
      run_proof_stream_test(reversed, 1, {8});
  compare_exact(reversed_expected.lde, reversed_actual.lde, 378,
                "proof stream reversed multi-matrix LDE");
  compare_exact(reversed_expected.digests, reversed_actual.digests,
                kProofStreamDigestWidth,
                "proof stream reversed multi-matrix digests");
  if (reversed_actual.digests == actual.digests) {
    fail("proof stream matrix reordering did not change the digest layer");
  }

  std::printf(
      "PASS proof stream exactness: pinned P3 digest, CPU LDE/digest "
      "differentials, chunk partitions, digest-only mode, widths 87/291, "
      "and matrix order\n");
}

void test_proof_stream_abi_errors() {
  char error[256] = {};
  const std::vector<u64> natural =
      make_vector(8, 2, Pattern::kDeterministicRandom);
  std::vector<u64> physical = bit_reverse_physical(natural, 8, 2);
  CmfdProofStreamMatrixV1 descriptor = {
      physical.data(), physical.size(), 8, 2, kGenerator};
  void* context = reinterpret_cast<void*>(UINTPTR_MAX);
  require_abi_failure(
      cmfd_proof_stream_create(0, &descriptor, 1, 1, nullptr, error,
                               sizeof(error)),
      "proof stream null context output", error);
  require_abi_failure(
      cmfd_proof_stream_create(0, nullptr, 1, 1, &context, error,
                               sizeof(error)),
      "proof stream null descriptor array", error);
  if (context != nullptr) {
    fail("proof stream failed create did not clear its context output");
  }
  require_abi_failure(
      cmfd_proof_stream_create(0, &descriptor, 0, 1, &context, error,
                               sizeof(error)),
      "proof stream zero matrices", error);
  require_abi_failure(
      cmfd_proof_stream_create(-1, &descriptor, 1, 1, &context, error,
                               sizeof(error)),
      "proof stream invalid device", error);

  CmfdProofStreamMatrixV1 invalid = descriptor;
  invalid.coefficients_len -= 1;
  require_abi_failure(
      cmfd_proof_stream_create(0, &invalid, 1, 1, &context, error,
                               sizeof(error)),
      "proof stream short coefficient input", error);
  invalid = descriptor;
  invalid.physical_coefficients = nullptr;
  require_abi_failure(
      cmfd_proof_stream_create(0, &invalid, 1, 1, &context, error,
                               sizeof(error)),
      "proof stream null coefficient input", error);
  invalid = descriptor;
  invalid.height = 3;
  require_abi_failure(
      cmfd_proof_stream_create(0, &invalid, 1, 1, &context, error,
                               sizeof(error)),
      "proof stream non-power-of-two height", error);
  invalid = descriptor;
  invalid.coset_shift = 0;
  require_abi_failure(
      cmfd_proof_stream_create(0, &invalid, 1, 1, &context, error,
                               sizeof(error)),
      "proof stream zero shift", error);
  invalid.coset_shift = kGoldilocksPrime;
  require_abi_failure(
      cmfd_proof_stream_create(0, &invalid, 1, 1, &context, error,
                               sizeof(error)),
      "proof stream noncanonical shift", error);
  require_abi_failure(
      cmfd_proof_stream_create(0, &descriptor, 1, 8, &context, error,
                               sizeof(error)),
      "proof stream added-bits cap", error);

  std::vector<CmfdProofStreamMatrixV1> too_many(65, descriptor);
  require_abi_failure(
      cmfd_proof_stream_create(0, too_many.data(), too_many.size(), 1,
                               &context, error, sizeof(error)),
      "proof stream matrix-count cap", error);
  CmfdProofStreamMatrixV1 mismatched[2] = {descriptor, descriptor};
  mismatched[1].height = 4;
  mismatched[1].coefficients_len = 8;
  require_abi_failure(
      cmfd_proof_stream_create(0, mismatched, 2, 1, &context, error,
                               sizeof(error)),
      "proof stream mixed heights", error);

  std::vector<u64> noncanonical = physical;
  noncanonical[3] = kGoldilocksPrime;
  invalid = {noncanonical.data(), noncanonical.size(), 8, 2, kGenerator};
  require_abi_failure(
      cmfd_proof_stream_create(0, &invalid, 1, 1, &context, error,
                               sizeof(error)),
      "proof stream noncanonical coefficient", error);

  require_abi_success(
      cmfd_proof_stream_create(0, &descriptor, 1, 1, &context, error,
                               sizeof(error)),
      "proof stream create", error);
  std::vector<u64> lde(8 * 2);
  std::vector<u64> digests(8 * kProofStreamDigestWidth);
  try {
    require_abi_failure(
        cmfd_proof_stream_next(nullptr, 0, 4, lde.data(), 8,
                               digests.data(), 16, error, sizeof(error)),
        "proof stream null next context", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 1, 4, lde.data(), 8,
                               digests.data(), 16, error, sizeof(error)),
        "proof stream skipped cursor", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 0, 0, lde.data(), 0,
                               digests.data(), 0, error, sizeof(error)),
        "proof stream zero row request", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 0, 3, lde.data(), 6,
                               digests.data(), 12, error, sizeof(error)),
        "proof stream non-power-of-two row request", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 0, UINT32_C(1) << 17, nullptr, 0,
                               digests.data(), digests.size(), error,
                               sizeof(error)),
        "proof stream row-request cap", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 0, 4, lde.data(), 8, nullptr, 16,
                               error, sizeof(error)),
        "proof stream null digest output", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 0, 4, lde.data(), 8,
                               digests.data(), 15, error, sizeof(error)),
        "proof stream short digest output", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 0, 4, nullptr, 8, digests.data(),
                               16, error, sizeof(error)),
        "proof stream omitted LDE with nonzero length", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 0, 4, lde.data(), 7,
                               digests.data(), 16, error, sizeof(error)),
        "proof stream short LDE output", error);

    require_abi_success(
        cmfd_proof_stream_next(context, 0, 4, lde.data(), 8,
                               digests.data(), 16, error, sizeof(error)),
        "proof stream first chunk", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 0, 4, lde.data() + 8, 8,
                               digests.data() + 16, 16, error,
                               sizeof(error)),
        "proof stream replayed cursor", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 4, 8, lde.data() + 8, 16,
                               digests.data() + 16, 32, error,
                               sizeof(error)),
        "proof stream cross-block request", error);
    require_abi_success(
        cmfd_proof_stream_next(context, 4, 4, lde.data() + 8, 8,
                               digests.data() + 16, 16, error,
                               sizeof(error)),
        "proof stream end first block", error);

    std::vector<u64> second_lde(8 * 2);
    std::vector<u64> second_digests(8 * kProofStreamDigestWidth);
    require_abi_success(
        cmfd_proof_stream_next(context, 8, 8, second_lde.data(),
                               second_lde.size(), second_digests.data(),
                               second_digests.size(), error, sizeof(error)),
        "proof stream second block", error);
    require_abi_failure(
        cmfd_proof_stream_next(context, 16, 1, lde.data(), 2,
                               digests.data(), 4, error, sizeof(error)),
        "proof stream post-completion call", error);
  } catch (...) {
    cmfd_proof_stream_destroy(context);
    throw;
  }
  cmfd_proof_stream_destroy(context);
  cmfd_proof_stream_destroy(nullptr);
  std::printf(
      "PASS proof stream C ABI v1: descriptor/lifecycle limits, monotonic "
      "cursor, chunk boundary, exact lengths, canonicality, and errors\n");
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

void run_proof_stream_benchmark() {
  constexpr std::size_t kHeight = 32768;
  constexpr std::size_t kWidth = 291;
  constexpr unsigned kAddedBits = 7;
  constexpr std::size_t kExpandedHeight = kHeight << kAddedBits;
  std::vector<u64> physical_coefficients = bit_reverse_physical(
      make_vector(kHeight, kWidth, Pattern::kDeterministicRandom), kHeight,
      kWidth);
  CmfdProofStreamMatrixV1 descriptor = {
      physical_coefficients.data(), physical_coefficients.size(),
      static_cast<std::uint32_t>(kHeight),
      static_cast<std::uint32_t>(kWidth), kGenerator};
  char error[256] = {};
  void* context = nullptr;
  const auto create_start = std::chrono::steady_clock::now();
  require_abi_success(
      cmfd_proof_stream_create(0, &descriptor, 1, kAddedBits, &context, error,
                               sizeof(error)),
      "proof stream benchmark create", error);
  const auto create_finished = std::chrono::steady_clock::now();

  std::vector<u64> digests(kHeight * kProofStreamDigestWidth);
  u64 checksum = 0;
  const auto stream_start = std::chrono::steady_clock::now();
  try {
    for (std::size_t cursor = 0; cursor < kExpandedHeight;
         cursor += kHeight) {
      require_abi_success(
          cmfd_proof_stream_next(
              context, cursor, static_cast<std::uint32_t>(kHeight), nullptr, 0,
              digests.data(), digests.size(), error, sizeof(error)),
          "proof stream benchmark next", error);
      for (u64 value : digests) {
        checksum ^= value;
      }
    }
  } catch (...) {
    cmfd_proof_stream_destroy(context);
    throw;
  }
  const auto stream_finished = std::chrono::steady_clock::now();
  cmfd_proof_stream_destroy(context);

  const double create_ms =
      std::chrono::duration<double, std::milli>(create_finished - create_start)
          .count();
  const double stream_ms =
      std::chrono::duration<double, std::milli>(stream_finished - stream_start)
          .count();
  const double rows_per_second =
      static_cast<double>(kExpandedHeight) * 1000.0 / stream_ms;
  const double avoided_gib =
      static_cast<double>(kExpandedHeight) * kWidth * sizeof(u64) /
      static_cast<double>(UINT64_C(1) << 30);
  std::printf(
      "BENCH proof_stream %zux%zu +%u bits: create %.3f ms, streamed LDE + "
      "Poseidon2 %.3f ms, %.0f rows/s, %.3f GiB host LDE avoided, checksum "
      "0x%016llx\n",
      kHeight, kWidth, kAddedBits, create_ms, stream_ms, rows_per_second,
      avoided_gib, static_cast<unsigned long long>(checksum));
}

}  // namespace

#if !defined(CMFD_PROOF_BACKEND_LIBRARY)
int main(int argc, char** argv) {
  try {
    bool large_bench = false;
    bool stream_bench = false;
    for (int index = 1; index < argc; ++index) {
      const std::string argument = argv[index];
      if (argument == "--large-bench") {
        large_bench = true;
      } else if (argument == "--stream-bench") {
        stream_bench = true;
      } else if (argument == "--help") {
        std::printf("Usage: %s [--large-bench] [--stream-bench]\n", argv[0]);
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
    test_proof_stream_exactness();
    test_proof_stream_abi_errors();
    test_c_abi();
    test_rejections();
    if (large_bench) {
      run_large_benchmarks();
    } else {
      std::printf("INFO large 32768x291 benchmarks skipped; pass --large-bench to run them\n");
    }
    if (stream_bench) {
      run_proof_stream_benchmark();
    } else {
      std::printf(
          "INFO bounded 32768x291 proof-stream benchmark skipped; pass "
          "--stream-bench to run it\n");
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
