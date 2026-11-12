#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$root/../.." && pwd)
sdk=/root/sp1-basefold-eval
cutlass=/root/cutlass-3.9.2
cuda=${CMFD_CUDA_ROOT:-/root/cmfd-cuda-12.9.1-repro/toolkit}
test "$(git -C "$sdk" rev-parse HEAD)" = 92b8eabaea9ab7306da5826caa700adabf7445ba
test "$(git -C "$cutlass" rev-parse HEAD)" = ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e
git -C "$sdk" diff --check
git -C "$sdk" diff --cached --quiet
patch=$(mktemp)
trap 'rm -f "$patch"' EXIT
git -C "$sdk" diff > "$patch"
cmp "$patch" "$repo/tools/production-v4-prover/patches/sp1-gpu-production-v4.patch"
export PATH="/root/.cargo/bin:$cuda/bin:/usr/bin:/bin"
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} CMAKE_BUILD_PARALLEL_LEVEL=${CMAKE_BUILD_PARALLEL_LEVEL:-4}
export CARGO_INCREMENTAL=0 GOMAXPROCS=4 RAYON_NUM_THREADS=4
export CMAKE=/usr/bin/cmake CUDA_PATH="$cuda" CUDA_HOME="$cuda"
export SP1_CUDA_ENABLED=1 CUDA_ARCHS='86;89;120' CUDACXX="$cuda/bin/nvcc"
export CUDAToolkit_ROOT="$cuda" CMAKE_TOOLCHAIN_FILE="$root/cuda-toolchain.cmake"
export CARGO_TARGET_DIR=${CMFD_GPU_TARGET_DIR:-$root/target}
cargo +1.97.1 build --release --locked --offline --manifest-path "$root/Cargo.toml" \
  --bin cmfd-all-relations-first-foundation --features shared-resident-replay
printf 'Worker: %s\n' "$CARGO_TARGET_DIR/release/cmfd-all-relations-first-foundation"
