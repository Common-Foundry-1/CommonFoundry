// Fused layer kernel declarations — shared between the fused implementation
// and the patched replay worker.
#pragma once

#include <cstdint>

namespace cmfd_v4_replay {

// Matches koala_four_limb_replay.cu constants.
constexpr uint32_t FUSED_MODULUS = 0x7f000001U;
constexpr int64_t FUSED_CENTER =
    128LL * (1LL + 256LL + 65'536LL + 16'777'216LL);  // = 2155905152

void launch_layer_fused(const int8_t* limbs_in, const int8_t* weights,
                        int8_t* limbs_out, uint32_t* preactivations,
                        uint32_t* activations, const uint32_t* coefficients,
                        const int32_t* weight_row_sums, uint32_t layer,
                        uint32_t layer_stride, uint32_t rows, uint32_t width,
                        uint32_t batch_size);

bool fused_use_mma();

void launch_layer_fused_mma(const int8_t* limbs_in, const int8_t* weights,
                            int8_t* limbs_out, uint32_t* preactivations,
                            uint32_t* activations, const uint32_t* coefficients,
                            const int32_t* weight_row_sums, uint32_t layer,
                            uint32_t layer_stride, uint32_t rows, uint32_t width,
                            uint32_t batch_size);

}  // namespace cmfd_v4_replay
