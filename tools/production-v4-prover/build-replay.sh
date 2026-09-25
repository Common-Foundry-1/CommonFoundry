#!/usr/bin/env bash
set -euo pipefail

# Replay/search compatibility is independent of the full proof worker's targets.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIRECTORY="$SCRIPT_DIR/target/replay-compatible"
CUTLASS_ROOT="${CMFD_CUTLASS_ROOT:-/root/cutlass-3.9.2}"
CUTLASS_COMMIT=ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e
NVCC="${CUDACXX:-/usr/local/cuda-12.8/bin/nvcc}"
CUOBJDUMP="${CMFD_CUOBJDUMP:-$(dirname -- "$NVCC")/cuobjdump}"
PRINT_PLAN=false
REPRODUCIBLE=false
OUTPUT_SET=false
for argument in "$@"; do
    case "$argument" in
        --print-build-plan)
            if "$PRINT_PLAN"; then echo 'duplicate --print-build-plan' >&2; exit 2; fi
            PRINT_PLAN=true ;;
        --reproducible)
            if "$REPRODUCIBLE"; then echo 'duplicate --reproducible' >&2; exit 2; fi
            REPRODUCIBLE=true ;;
        --*) echo 'usage: build-replay.sh [OUTPUT_DIRECTORY] [--reproducible] [--print-build-plan]' >&2; exit 2 ;;
        *)
            if "$OUTPUT_SET"; then echo 'only one output directory is accepted' >&2; exit 2; fi
            OUTPUT_DIRECTORY="$argument"
            OUTPUT_SET=true ;;
    esac
done

ARCHITECTURES=(70 75 80 86 89 90 120)
CODE_FLAGS=()
for architecture in "${ARCHITECTURES[@]}"; do
    CODE_FLAGS+=("--generate-code=arch=compute_$architecture,code=sm_$architecture")
done
# CUDA_FORCE_PTX_JIT qualification exercises the Volta-compatible exact DP4A path.
CODE_FLAGS+=("--generate-code=arch=compute_70,code=compute_70")
WORKER="$OUTPUT_DIRECTORY/cmfd-v4-replay"
INTERMEDIATES="$OUTPUT_DIRECTORY/cuda-intermediates"
REPRO_FLAGS=()
if "$REPRODUCIBLE"; then
    # One CUDA translation unit: this seed controls compiler symbol names only,
    # never runtime nonces or cryptographic randomness. Keeping intermediates
    # is also required by CUDA 12.9.1 to stabilize its module registration ID.
    REPRO_FLAGS=(--objdir-as-tempdir --keep --keep-dir "$INTERMEDIATES"
                 --frandom-seed=1129137732)
fi
BUILD=("$NVCC" -O3 -std=c++17 "${REPRO_FLAGS[@]}" "${CODE_FLAGS[@]}" -I"$CUTLASS_ROOT/include"
       "$SCRIPT_DIR/cuda/koala_four_limb_replay.cu" -o "$WORKER")
if "$PRINT_PLAN"; then
    printf 'REPLAY_NATIVE_ARCHS=%s\n' "${ARCHITECTURES[*]}"
    printf 'REPLAY_PTX_ARCH=70\nREPLAY_COMPILE='
    printf '%q ' "${BUILD[@]}"
    printf '\n'
    exit 0
fi

NVCC="$(command -v "$NVCC")"
CUOBJDUMP="$(command -v "$CUOBJDUMP")"
test -x "$NVCC"
test -x "$CUOBJDUMP"
if "$REPRODUCIBLE"; then
    COMPILER_HELP="$("$NVCC" --help)"
    if ! grep -Fq -- '--frandom-seed' <<< "$COMPILER_HELP"; then
        echo 'Reproducible replay builds require CUDA 12.9 with --frandom-seed support.' >&2
        exit 1
    fi
    if [[ -e "$INTERMEDIATES" || -L "$INTERMEDIATES" ]]; then
        echo 'Preserve existing CUDA intermediates; choose a new output directory.' >&2
        exit 1
    fi
fi
if [[ "$(git -C "$CUTLASS_ROOT" rev-parse HEAD)" != "$CUTLASS_COMMIT" ||
      -n "$(git -C "$CUTLASS_ROOT" status --porcelain --untracked-files=all)" ]]; then
    echo 'The replay worker requires the clean, pinned CUTLASS 3.9.2 checkout.' >&2
    exit 1
fi
SUPPORTED="$("$NVCC" --list-gpu-code)"
for architecture in "${ARCHITECTURES[@]}"; do
    if ! grep -Fxq "sm_$architecture" <<< "$SUPPORTED"; then
        echo "The selected toolkit cannot emit sm_$architecture; use CUDA 12.8 or 12.9." >&2
        exit 1
    fi
done
if [[ -e "$WORKER" || -L "$WORKER" ]]; then
    echo 'Preserve the existing replay artifact; choose a new output directory.' >&2
    exit 1
fi
mkdir -p -- "$OUTPUT_DIRECTORY"
if "$REPRODUCIBLE"; then mkdir -- "$INTERMEDIATES"; fi
# Re-resolve only the executable, preserving the exact emitted compiler arguments.
BUILD[0]="$NVCC"
"${BUILD[@]}"

NATIVE_IMAGES="$("$CUOBJDUMP" --list-elf "$WORKER")"
PTX_IMAGES="$("$CUOBJDUMP" --list-ptx "$WORKER")"
for architecture in "${ARCHITECTURES[@]}"; do
    if ! grep -Eq "sm_${architecture}([._[:space:]]|$)" <<< "$NATIVE_IMAGES"; then
        echo "The replay artifact is missing its native sm_$architecture image." >&2
        exit 1
    fi
done
if ! grep -Eq 'sm_70([._[:space:]]|$)' <<< "$PTX_IMAGES"; then
    echo 'The replay artifact is missing its compute_70 PTX fallback.' >&2
    exit 1
fi
printf '%s\n%s\n' "$NATIVE_IMAGES" "$PTX_IMAGES"
sha256sum -- "$WORKER"
echo 'Replay targets verified: Volta and RTX 20/30/40/50; physical-card qualification is separate.'
