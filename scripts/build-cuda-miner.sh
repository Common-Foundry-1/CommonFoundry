#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-linux-common.sh
source "$PROJECT_ROOT/scripts/release-linux-common.sh"

BUILD_DIRECTORY="${1:-$PROJECT_ROOT/target/gpu-miner-build-volta-linux}"
EXPECTED_COMMIT="$(cmfd_release_commit "${2:-}")"
RELEASE_INTEGRITY="$PROJECT_ROOT/scripts/release_integrity.py"

cmfd_require_linux_gnu_x86_64
for command_name in cargo cmake git grep ninja python3 sed strip tr; do
  cmfd_require_command "$command_name"
done
STRIP="$(command -v strip)"
STRIP_VERSION="$("$STRIP" --version | sed -n '1p')"
if [[ "$STRIP_VERSION" != 'GNU strip '* ]]; then
  printf 'GNU strip is required; found: %s\n' "$STRIP_VERSION" >&2
  exit 1
fi

NVCC="${CUDACXX:-}"
if [[ -z "$NVCC" ]]; then
  NVCC="$(command -v nvcc || true)"
else
  NVCC="$(command -v "$NVCC" || true)"
fi
if [[ -z "$NVCC" || ! -x "$NVCC" ]]; then
  echo 'nvcc is required; use CUDA Toolkit 12.8 or 12.9 for Volta through Blackwell.' >&2
  exit 1
fi
CUOBJDUMP="$(dirname -- "$NVCC")/cuobjdump"
if [[ ! -x "$CUOBJDUMP" ]]; then
  echo 'cuobjdump is required beside nvcc.' >&2
  exit 1
fi

SUPPORTED="$("$NVCC" --list-gpu-code)"
for architecture in sm_70 sm_75 sm_86 sm_89 sm_120; do
  if ! grep -Fxq "$architecture" <<<"$SUPPORTED"; then
    printf 'The selected CUDA toolkit cannot emit %s.\n' "$architecture" >&2
    exit 1
  fi
done

cmake -S "$PROJECT_ROOT/gpu" -B "$BUILD_DIRECTORY" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CUDA_COMPILER="$NVCC"
cmake --build "$BUILD_DIRECTORY" --target cmfd-forgematrix-v2-miner

LIBRARY="$BUILD_DIRECTORY/cmfd-forgematrix-v2-miner.so"
"$STRIP" --strip-unneeded "$LIBRARY"
cmfd_require_elf_x86_64 "$LIBRARY" shared
NATIVE_IMAGES="$($CUOBJDUMP --list-elf "$LIBRARY")"
PTX_IMAGES="$($CUOBJDUMP --list-ptx "$LIBRARY")"
for architecture in sm_70 sm_75 sm_86 sm_89 sm_120; do
  if ! grep -Fq "$architecture" <<<"$NATIVE_IMAGES"; then
    printf 'The CUDA library is missing its native %s image.\n' "$architecture" >&2
    exit 1
  fi
done
if ! grep -Fq sm_70 <<<"$PTX_IMAGES"; then
  echo 'The CUDA library is missing its forward-compatible compute_70 PTX image.' >&2
  exit 1
fi

if [[ "${CMFD_SKIP_DIFFERENTIAL_TEST:-0}" != "1" ]]; then
  CMFD_CUDA_MINER_LIBRARY="$LIBRARY" cargo test \
    --manifest-path "$PROJECT_ROOT/Cargo.toml" \
    -p common-foundry-wallet \
    cuda::tests::available_cuda_backend_matches_authoritative_v2_digests -- --nocapture
fi

TOOLCHAIN="$("$NVCC" --version | tr '\n' ' '); $(cmake --version | sed -n '1p'); $STRIP_VERSION"
RECEIPT="$LIBRARY.build-receipt"
python3 "$RELEASE_INTEGRITY" receipt-write \
  --repo "$PROJECT_ROOT" \
  --expected-commit "$EXPECTED_COMMIT" \
  --kind cuda \
  --library "$LIBRARY" \
  --build-script scripts/build-cuda-miner.sh \
  --toolchain "$TOOLCHAIN" \
  --target x86_64-unknown-linux-gnu \
  --architectures 'sm_70;sm_75;sm_86;sm_89;sm_120;compute_70' \
  --output "$RECEIPT"

printf 'Library: %s\nBuild receipt: %s\n' "$LIBRARY" "$RECEIPT"
