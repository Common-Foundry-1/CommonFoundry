#!/usr/bin/env bash
set -euo pipefail

SP1_COMMIT=92b8eabaea9ab7306da5826caa700adabf7445ba
CUTLASS_COMMIT=ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e
SP1_DIR=/root/sp1-basefold-eval
CUTLASS_DIR=/root/cutlass-3.9.2
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ -e "$SP1_DIR" || -e "$CUTLASS_DIR" ]]; then
    echo "dependency destination already exists; refusing to replace it" >&2
    exit 1
fi

git clone --filter=blob:none https://github.com/succinctlabs/sp1.git "$SP1_DIR"
git -C "$SP1_DIR" checkout --detach "$SP1_COMMIT"
git -C "$SP1_DIR" apply --check "$SCRIPT_DIR/patches/sp1-gpu-production-v4.patch"
git -C "$SP1_DIR" apply "$SCRIPT_DIR/patches/sp1-gpu-production-v4.patch"

git clone --filter=blob:none https://github.com/NVIDIA/cutlass.git "$CUTLASS_DIR"
git -C "$CUTLASS_DIR" checkout --detach "$CUTLASS_COMMIT"

test "$(git -C "$SP1_DIR" rev-parse HEAD)" = "$SP1_COMMIT"
test "$(git -C "$CUTLASS_DIR" rev-parse HEAD)" = "$CUTLASS_COMMIT"
