#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BUILD_SCRIPT=$SCRIPT_DIR/build.sh
CUDA_DIR=/usr/local/cuda-12.8
CUTLASS_DIR=/root/cutlass-3.9.2

expected_command() {
    local name=$1
    shift
    printf '%s=' "$name"
    printf '%q ' "$@"
}

expect_line() {
    local plan=$1
    local line=$2
    if ! grep -Fqx -- "$line" <<< "$plan"; then
        printf 'missing exact build-plan line: %s\n' "$line" >&2
        exit 1
    fi
}

check_plan() {
    local mode=$1
    local plan=$2
    local archs=$3
    local build_root=$4
    shift 4
    local -a flags=("$@")
    local release_dir=$build_root/release

    expect_line "$plan" 'SP1_COMMIT=92b8eabaea9ab7306da5826caa700adabf7445ba'
    expect_line "$plan" 'CUTLASS_COMMIT=ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e'
    expect_line "$plan" "CUTLASS_DIR=$CUTLASS_DIR"
    expect_line "$plan" "CUDA_DIR=$CUDA_DIR"
    expect_line "$plan" "CUDA_ARCHS=$archs"
    expect_line "$plan" "CMAKE_CUDA_ARCHITECTURES=$archs"
    expect_line "$plan" "CARGO_TARGET_DIR=$build_root"
    expect_line "$plan" "$(expected_command RUST_BUILD \
        cargo build --release --locked --manifest-path "$SCRIPT_DIR/Cargo.toml" \
        --bin fixed_bank_artifact --bin real_dynamic_commitments \
        --bin real_bank0_relations)"
    expect_line "$plan" "$(expected_command REPLAY_BUILD \
        env "CUDACXX=$CUDA_DIR/bin/nvcc" "CMFD_CUTLASS_ROOT=$CUTLASS_DIR" \
        bash "$SCRIPT_DIR/build-replay.sh" "$release_dir")"
    expect_line "$plan" 'REPLAY_NATIVE_ARCHS=70 75 80 86 89 90 120'
    expect_line "$plan" 'REPLAY_PTX_ARCH=70'
    local -a replay_flags=()
    for architecture in 70 75 80 86 89 90 120; do
        replay_flags+=("--generate-code=arch=compute_$architecture,code=sm_$architecture")
    done
    replay_flags+=('--generate-code=arch=compute_70,code=compute_70')
    expect_line "$plan" "$(expected_command REPLAY_COMPILE \
        "$CUDA_DIR/bin/nvcc" -O3 -std=c++17 "${replay_flags[@]}" \
        -I"$CUTLASS_DIR/include" "$SCRIPT_DIR/cuda/koala_four_limb_replay.cu" \
        -o "$release_dir/cmfd-v4-replay")"
    expect_line "$plan" "$(expected_command CACHE_BUILD \
        "$CUDA_DIR/bin/nvcc" -O3 -std=c++17 "${flags[@]}" \
        "$SCRIPT_DIR/cuda/fixed_row_cache.cu" \
        -o "$release_dir/cmfd-v4-fixed-row-cache")"
    test "$(wc -l <<< "$plan")" -eq 13 || {
        echo "$mode plan has unexpected extra lines" >&2
        exit 1
    }
}

single_plan=$("$BUILD_SCRIPT" --print-build-plan)
check_plan single "$single_plan" 120 "$SCRIPT_DIR/target" '-arch=sm_120'

dual_plan=$("$BUILD_SCRIPT" --dual-arch --print-build-plan)
check_plan dual "$dual_plan" '89;120' "$SCRIPT_DIR/target/dual-sm89-sm120" \
    '-gencode=arch=compute_89,code=sm_89' \
    '-gencode=arch=compute_120,code=sm_120'

# Option order must not affect the build identity or its emitted commands.
test "$dual_plan" = "$("$BUILD_SCRIPT" --print-build-plan --dual-arch)"
test "$dual_plan" = "$(
    CUDA_ARCHS=120 CMAKE_CUDA_ARCHITECTURES=120 \
        CARGO_TARGET_DIR=/tmp/stale-single-arch \
        "$BUILD_SCRIPT" --dual-arch --print-build-plan
)"

override_plan=$(CMFD_PROVER_CUTLASS_DIR=/tmp/clean-cutlass "$BUILD_SCRIPT" --dual-arch --print-build-plan)
expect_line "$override_plan" 'CUTLASS_DIR=/tmp/clean-cutlass'
if grep -Fq -- "$CUTLASS_DIR/include" <<< "$override_plan"; then
    echo 'clean CUTLASS override leaked the default include path' >&2
    exit 1
fi

isolated_plan=$(CMFD_PROVER_DUAL_TARGET_DIR=/tmp/cmfd-dual-output "$BUILD_SCRIPT" --dual-arch --print-build-plan)
expect_line "$isolated_plan" 'CARGO_TARGET_DIR=/tmp/cmfd-dual-output'
if CMFD_PROVER_DUAL_TARGET_DIR=relative/output "$BUILD_SCRIPT" --dual-arch --print-build-plan >/dev/null 2>&1; then
    echo 'relative dual-architecture output directory was accepted' >&2
    exit 1
fi

for bad_args in '--dual-arch --dual-arch' '--print-build-plan --print-build-plan' '--arch=sm_89'; do
    # Split this static fixture into arguments without evaluating shell input.
    read -r -a arguments <<< "$bad_args"
    if "$BUILD_SCRIPT" "${arguments[@]}" >/dev/null 2>&1; then
        echo "unexpected success for build options: $bad_args" >&2
        exit 1
    else
        test "$?" -eq 2 || {
            echo "wrong rejection status for build options: $bad_args" >&2
            exit 1
        }
    fi
done

echo 'ProductionV4 build argument plans passed (no GPU build performed).'
