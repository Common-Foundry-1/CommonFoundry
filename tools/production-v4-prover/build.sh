#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SP1_DIR=/root/sp1-basefold-eval
CUTLASS_DIR=${CMFD_PROVER_CUTLASS_DIR:-/root/cutlass-3.9.2}
CUDA_DIR=/usr/local/cuda-12.8
SP1_PATCH=$SCRIPT_DIR/patches/sp1-gpu-production-v4.patch

usage() {
    echo "usage: build.sh [--dual-arch] [--print-build-plan]" >&2
}

dual_arch=false
print_build_plan=false
for argument in "$@"; do
    case "$argument" in
        --dual-arch)
            if "$dual_arch"; then usage; exit 2; fi
            dual_arch=true
            ;;
        --print-build-plan)
            if "$print_build_plan"; then usage; exit 2; fi
            print_build_plan=true
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

# The default is the already-qualified RC SM120 build. The opt-in mainnet
# candidate gives the full prover native SM89 and SM120 code images.
# The replay/search worker uses its own cross-generation builder in both modes.
# Keep its Cargo build directory separate: cached single-arch CUDA objects must
# never be mistaken for dual-arch worker bytes submitted for signing.
if "$dual_arch"; then
    CUDA_ARCHS='89;120'
    BUILD_ROOT=${CMFD_PROVER_DUAL_TARGET_DIR:-$SCRIPT_DIR/target/dual-sm89-sm120}
    if [[ $BUILD_ROOT != /* || $BUILD_ROOT == "$SCRIPT_DIR/target" ]]; then
        echo "CMFD_PROVER_DUAL_TARGET_DIR must be a separate absolute directory" >&2
        exit 2
    fi
    NVCC_ARCH_FLAGS=(
        '-gencode=arch=compute_89,code=sm_89'
        '-gencode=arch=compute_120,code=sm_120'
    )
else
    CUDA_ARCHS=120
    BUILD_ROOT=$SCRIPT_DIR/target
    NVCC_ARCH_FLAGS=('-arch=sm_120')
fi
RELEASE_DIR=$BUILD_ROOT/release

RUST_BUILD=(
    cargo build --release --locked --manifest-path "$SCRIPT_DIR/Cargo.toml"
    --bin fixed_bank_artifact
    --bin real_dynamic_commitments
    --bin real_bank0_relations
)
REPLAY_BUILD=(
    env "CUDACXX=$CUDA_DIR/bin/nvcc" "CMFD_CUTLASS_ROOT=$CUTLASS_DIR"
    bash "$SCRIPT_DIR/build-replay.sh" "$RELEASE_DIR"
)
CACHE_BUILD=(
    "$CUDA_DIR/bin/nvcc" -O3 -std=c++17 "${NVCC_ARCH_FLAGS[@]}"
    "$SCRIPT_DIR/cuda/fixed_row_cache.cu"
    -o "$RELEASE_DIR/cmfd-v4-fixed-row-cache"
)

# This output is generated from the exact arrays executed below. It needs no
# dependency checkout or GPU, so release reviewers can check argument drift.
if "$print_build_plan"; then
    printf 'SP1_COMMIT=%s\n' 92b8eabaea9ab7306da5826caa700adabf7445ba
    printf 'CUTLASS_COMMIT=%s\n' ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e
    printf 'CUTLASS_DIR=%s\nCUDA_DIR=%s\nCUDA_ARCHS=%s\nCMAKE_CUDA_ARCHITECTURES=%s\nCARGO_TARGET_DIR=%s\n' \
        "$CUTLASS_DIR" "$CUDA_DIR" "$CUDA_ARCHS" "$CUDA_ARCHS" "$BUILD_ROOT"
    for command_name in RUST_BUILD REPLAY_BUILD CACHE_BUILD; do
        declare -n command_args="$command_name"
        printf '%s=' "$command_name"
        printf '%q ' "${command_args[@]}"
        printf '\n'
    done
    "${REPLAY_BUILD[@]}" --print-build-plan
    exit 0
fi

ACTUAL_SP1_PATCH=$(mktemp)
trap 'rm -f "$ACTUAL_SP1_PATCH"' EXIT

test "$(git -C "$SP1_DIR" rev-parse HEAD)" = 92b8eabaea9ab7306da5826caa700adabf7445ba
test "$(git -C "$CUTLASS_DIR" rev-parse HEAD)" = ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e
git -C "$SP1_DIR" diff --check
git -C "$SP1_DIR" diff --cached --quiet
test -z "$(git -C "$SP1_DIR" ls-files --others --exclude-standard)"
git -C "$SP1_DIR" diff > "$ACTUAL_SP1_PATCH"
if ! cmp -s "$ACTUAL_SP1_PATCH" "$SP1_PATCH"; then
    echo "SP1 worktree does not exactly match the pinned ProductionV4 patch" >&2
    exit 1
fi
git -C "$CUTLASS_DIR" diff --quiet
git -C "$CUTLASS_DIR" diff --cached --quiet
test -z "$(git -C "$CUTLASS_DIR" ls-files --others --exclude-standard)"

export CUDA_HOME=$CUDA_DIR
export CUDA_PATH=$CUDA_DIR
export CUDAToolkit_ROOT=$CUDA_DIR
export CUDACXX=$CUDA_DIR/bin/nvcc
export CMAKE_CUDA_COMPILER=$CUDA_DIR/bin/nvcc
export CUDA_ARCHS
export CMAKE_CUDA_ARCHITECTURES=$CUDA_ARCHS
export CARGO_TARGET_DIR=$BUILD_ROOT
export PATH=$CUDA_DIR/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LD_LIBRARY_PATH=$CUDA_DIR/lib64

"${RUST_BUILD[@]}"

mkdir -p "$RELEASE_DIR"
"${REPLAY_BUILD[@]}"
"${CACHE_BUILD[@]}"

# Only real output bytes are eligible for a signed release identity. Printing
# these digests does not sign or qualify them on either GPU generation.
sha256sum \
    "$RELEASE_DIR/cmfd-v4-replay" \
    "$RELEASE_DIR/real_dynamic_commitments" \
    "$RELEASE_DIR/real_bank0_relations" \
    "$RELEASE_DIR/cmfd-v4-fixed-row-cache"
