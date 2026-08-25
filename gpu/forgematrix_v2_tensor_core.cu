#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "cutlass/cutlass.h"
#include "cutlass/epilogue/thread/linear_combination_clamp.h"
#include "cutlass/gemm/device/gemm.h"
#include "cutlass/version.h"

static_assert(CUTLASS_MAJOR == 3 && CUTLASS_MINOR == 9 && CUTLASS_PATCH == 2,
              "the production tensor-core backend requires CUTLASS v3.9.2");

namespace {

using TensorCoreGemm = cutlass::gemm::device::Gemm<
    int8_t, cutlass::layout::RowMajor, int8_t, cutlass::layout::ColumnMajor,
    int32_t, cutlass::layout::RowMajor, int32_t, cutlass::arch::OpClassTensorOp,
    cutlass::arch::Sm75, cutlass::gemm::GemmShape<128, 128, 64>,
    cutlass::gemm::GemmShape<64, 64, 64>, cutlass::gemm::GemmShape<8, 8, 16>,
    cutlass::epilogue::thread::LinearCombinationClamp<int32_t, 4, int32_t, int32_t>,
    cutlass::gemm::threadblock::GemmIdentityThreadblockSwizzle<>, 2>;

void write_error(char* output, size_t output_len, const char* message) {
    if (output == nullptr || output_len == 0) return;
    const size_t message_len = std::strlen(message);
    const size_t copied = message_len < output_len - 1 ? message_len : output_len - 1;
    std::memcpy(output, message, copied);
    output[copied] = '\0';
}

}  // namespace

extern "C" int32_t cmfd_cutlass_int8_gemm(const int8_t* activation,
                                           const int8_t* transposed_weights,
                                           int32_t* accumulators, uint32_t rows,
                                           uint32_t width, char* error,
                                           size_t error_len) {
    if (activation == nullptr || transposed_weights == nullptr || accumulators == nullptr) {
        write_error(error, error_len, "CUTLASS GEMM received a null matrix pointer");
        return 1;
    }

    const cutlass::gemm::GemmCoord problem_size(static_cast<int>(rows),
                                                 static_cast<int>(width),
                                                 static_cast<int>(width));
    typename TensorCoreGemm::Arguments arguments{
        problem_size,
        {activation, static_cast<int>(width)},
        {transposed_weights, static_cast<int>(width)},
        {accumulators, static_cast<int>(width)},
        {accumulators, static_cast<int>(width)},
        {int32_t{1}, int32_t{0}},
        1};

    TensorCoreGemm operation;
    cutlass::Status status = operation.can_implement(arguments);
    if (status != cutlass::Status::kSuccess) {
        write_error(error, error_len, cutlass::cutlassGetStatusString(status));
        return 1;
    }
    status = operation(arguments);
    if (status != cutlass::Status::kSuccess) {
        write_error(error, error_len, cutlass::cutlassGetStatusString(status));
        return 1;
    }
    return 0;
}
