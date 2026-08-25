#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-linux-common.sh
source "$PROJECT_ROOT/scripts/release-linux-common.sh"

BUILD_DIRECTORY="${1:-$PROJECT_ROOT/target/gpu-miner-build-volta-linux}"
EXPECTED_COMMIT="$(cmfd_release_commit "${2:-}")"
RELEASE_INTEGRITY="$PROJECT_ROOT/scripts/release_integrity.py"
CUTLASS_COMMIT='ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e'
CUTLASS_REPOSITORY='https://github.com/NVIDIA/cutlass.git'
CUTLASS_TAG='v3.9.2'
CUTLASS_ROOT="${CMFD_CUTLASS_ROOT:-$BUILD_DIRECTORY/_deps/cutlass-3.9.2}"

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

if [[ ! -d "$CUTLASS_ROOT" ]]; then
  mkdir -p "$(dirname -- "$CUTLASS_ROOT")"
  git clone --filter=blob:none --depth=1 --branch "$CUTLASS_TAG" \
    "$CUTLASS_REPOSITORY" "$CUTLASS_ROOT"
  git -C "$CUTLASS_ROOT" checkout --detach "$CUTLASS_COMMIT"
fi
ACTUAL_CUTLASS_COMMIT="$(git -C "$CUTLASS_ROOT" rev-parse HEAD)"
if [[ "$ACTUAL_CUTLASS_COMMIT" != "$CUTLASS_COMMIT" ]]; then
  printf 'CUTLASS must be the pinned commit %s; got %s.\n' \
    "$CUTLASS_COMMIT" "$ACTUAL_CUTLASS_COMMIT" >&2
  exit 1
fi
if [[ -n "$(git -C "$CUTLASS_ROOT" status --porcelain --untracked-files=all)" ]]; then
  echo 'The pinned CUTLASS checkout has local or untracked changes.' >&2
  exit 1
fi

cmake -S "$PROJECT_ROOT/gpu" -B "$BUILD_DIRECTORY" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CUDA_COMPILER="$NVCC" \
  -DCMFD_CUTLASS_ROOT="$CUTLASS_ROOT"
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
if ! grep -Fq sm_75 <<<"$PTX_IMAGES"; then
  echo 'The CUDA library is missing its signed-INT8 Tensor Core compute_75 PTX image.' >&2
  exit 1
fi
PTX_ASSEMBLY="$($CUOBJDUMP --dump-ptx "$LIBRARY")"
if ! grep -Fq \
  'mma.sync.aligned.m8n8k16.row.col.satfinite.s32.s8.s8.s32' \
  <<<"$PTX_ASSEMBLY"; then
  echo 'The compute_75 PTX lacks the required signed-INT8 Tensor Core MMA.' >&2
  exit 1
fi

if [[ "${CMFD_SKIP_DIFFERENTIAL_TEST:-0}" != "1" ]]; then
  CMFD_CUDA_MINER_LIBRARY="$LIBRARY" cargo test \
    --manifest-path "$PROJECT_ROOT/Cargo.toml" \
    -p common-foundry-wallet \
    cuda::tests::available_cuda_backend_matches_authoritative_v2_digests -- --nocapture
  CMFD_CUDA_MINER_LIBRARY="$LIBRARY" CMFD_REQUIRE_TENSOR_CORE=1 cargo run \
    --manifest-path "$PROJECT_ROOT/Cargo.toml" \
    --release -p cmfd-cuda --example production_differential
fi

TOOLCHAIN="$("$NVCC" --version | tr '\n' ' '); $(cmake --version | sed -n '1p'); $STRIP_VERSION; CUTLASS $ACTUAL_CUTLASS_COMMIT"
RECEIPT="$LIBRARY.build-receipt"
python3 "$RELEASE_INTEGRITY" receipt-write \
  --repo "$PROJECT_ROOT" \
  --expected-commit "$EXPECTED_COMMIT" \
  --kind cuda \
  --library "$LIBRARY" \
  --build-script scripts/build-cuda-miner.sh \
  --toolchain "$TOOLCHAIN" \
  --target x86_64-unknown-linux-gnu \
  --architectures 'sm_70;sm_75;sm_86;sm_89;sm_120;compute_70;compute_75-tensor-core' \
  --output "$RECEIPT"

printf 'Library: %s\nBuild receipt: %s\n' "$LIBRARY" "$RECEIPT"
