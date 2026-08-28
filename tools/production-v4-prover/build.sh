#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SP1_DIR=/root/sp1-basefold-eval
CUTLASS_DIR=/root/cutlass-3.9.2
CUDA_DIR=/usr/local/cuda-12.8
SP1_PATCH=$SCRIPT_DIR/patches/sp1-gpu-production-v4.patch
ACTUAL_SP1_PATCH=$(mktemp)
trap 'rm -f "$ACTUAL_SP1_PATCH"' EXIT

test "$(git -C "$SP1_DIR" rev-parse HEAD)" = 92b8eabaea9ab7306da5826caa700adabf7445ba
test "$(git -C "$CUTLASS_DIR" rev-parse HEAD)" = ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e
git -C "$SP1_DIR" diff --check
test -z "$(git -C "$SP1_DIR" ls-files --others --exclude-standard)"
git -C "$SP1_DIR" diff > "$ACTUAL_SP1_PATCH"
if ! cmp -s "$ACTUAL_SP1_PATCH" "$SP1_PATCH"; then
    echo "SP1 worktree does not exactly match the pinned ProductionV4 patch" >&2
    exit 1
fi

export CUDA_HOME=$CUDA_DIR
export CUDA_PATH=$CUDA_DIR
export CUDAToolkit_ROOT=$CUDA_DIR
export CUDACXX=$CUDA_DIR/bin/nvcc
export CMAKE_CUDA_COMPILER=$CUDA_DIR/bin/nvcc
export CUDA_ARCHS=120
export PATH=$CUDA_DIR/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LD_LIBRARY_PATH=$CUDA_DIR/lib64

cargo build --release --locked --manifest-path "$SCRIPT_DIR/Cargo.toml" \
    --bin fixed_bank_artifact \
    --bin real_dynamic_commitments \
    --bin real_bank0_relations

mkdir -p "$SCRIPT_DIR/target/release"
"$CUDA_DIR/bin/nvcc" -O3 -std=c++17 -arch=sm_120 \
    -I"$CUTLASS_DIR/include" \
    "$SCRIPT_DIR/cuda/koala_four_limb_replay.cu" \
    -o "$SCRIPT_DIR/target/release/cmfd-v4-replay"
"$CUDA_DIR/bin/nvcc" -O3 -std=c++17 -arch=sm_120 \
    "$SCRIPT_DIR/cuda/fixed_row_cache.cu" \
    -o "$SCRIPT_DIR/target/release/cmfd-v4-fixed-row-cache"
