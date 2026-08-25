#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-linux-common.sh
source "$PROJECT_ROOT/scripts/release-linux-common.sh"

BUILD_DIRECTORY="${1:-$PROJECT_ROOT/target/gpu-opencl-build-linux}"
EXPECTED_COMMIT="$(cmfd_release_commit "${2:-}")"
RELEASE_INTEGRITY="$PROJECT_ROOT/scripts/release_integrity.py"

cmfd_require_linux_gnu_x86_64
for command_name in cargo cmake git ninja python3 sed; do
  cmfd_require_command "$command_name"
done
CXX="${CXX:-c++}"
cmfd_require_command "$CXX"
CXX="$(command -v "$CXX")"

cmake -S "$PROJECT_ROOT/gpu" -B "$BUILD_DIRECTORY" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMFD_ENABLE_CUDA=OFF \
  -DCMFD_ENABLE_OPENCL=ON
cmake --build "$BUILD_DIRECTORY" --target cmfd-forgematrix-v2-opencl

LIBRARY="$BUILD_DIRECTORY/cmfd-forgematrix-v2-opencl.so"
cmfd_require_elf_x86_64 "$LIBRARY" shared
if [[ "${CMFD_SKIP_DIFFERENTIAL_TEST:-0}" != "1" ]]; then
  CMFD_GPU_BACKEND=opencl \
    CMFD_OPENCL_MINER_LIBRARY="$LIBRARY" \
    cargo test \
    --manifest-path "$PROJECT_ROOT/Cargo.toml" \
    -p common-foundry-wallet \
    cuda::tests::available_cuda_backend_matches_authoritative_v2_digests -- --nocapture
fi

TOOLCHAIN="$("$CXX" --version | sed -n '1p'); $(cmake --version | sed -n '1p')"
RECEIPT="$LIBRARY.build-receipt"
python3 "$RELEASE_INTEGRITY" receipt-write \
  --repo "$PROJECT_ROOT" \
  --expected-commit "$EXPECTED_COMMIT" \
  --kind opencl \
  --library "$LIBRARY" \
  --build-script scripts/build-opencl-miner.sh \
  --toolchain "$TOOLCHAIN" \
  --target x86_64-unknown-linux-gnu \
  --architectures opencl_1_2 \
  --output "$RECEIPT"

printf 'Library: %s\nBuild receipt: %s\n' "$LIBRARY" "$RECEIPT"
