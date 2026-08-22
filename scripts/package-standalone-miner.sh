#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIRECTORY="${1:-$PROJECT_ROOT/target/standalone-miner-package-linux}"
CUDA_BUILD_DIRECTORY="${2:-$PROJECT_ROOT/target/gpu-miner-build-volta-linux}"
OPENCL_BUILD_DIRECTORY="${3:-$PROJECT_ROOT/target/gpu-opencl-build-linux}"
CUDA_LIBRARY="$CUDA_BUILD_DIRECTORY/cmfd-forgematrix-v2-miner.so"
OPENCL_LIBRARY="$OPENCL_BUILD_DIRECTORY/cmfd-forgematrix-v2-opencl.so"

if [[ ! -f "$CUDA_LIBRARY" ]]; then
  echo "CUDA library is missing: $CUDA_LIBRARY" >&2
  exit 1
fi

TARGET_DIRECTORY="$OUTPUT_DIRECTORY/rust-target"
CARGO_TARGET_DIR="$TARGET_DIRECTORY" cargo build \
  --manifest-path "$PROJECT_ROOT/Cargo.toml" \
  --release --locked -p cmfd-miner

VERSION="$(
  cargo pkgid --manifest-path "$PROJECT_ROOT/Cargo.toml" -p cmfd-miner --locked |
    sed -E 's/.*#//'
)"
PACKAGE_NAME="commonfoundry-miner-v${VERSION}-linux-x86_64-gnu"
STAGE="$OUTPUT_DIRECTORY/$PACKAGE_NAME"
ARCHIVE="$OUTPUT_DIRECTORY/$PACKAGE_NAME.tar.gz"

if [[ -e "$STAGE" || -e "$ARCHIVE" ]]; then
  echo "Package staging path or archive already exists." >&2
  exit 1
fi

mkdir -p "$STAGE"
install -m 0755 "$TARGET_DIRECTORY/release/cmfd-miner" "$STAGE/cmfd-miner"
install -m 0755 "$CUDA_LIBRARY" "$STAGE/cmfd-forgematrix-v2-miner.so"
if [[ -f "$OPENCL_LIBRARY" ]]; then
  install -m 0755 "$OPENCL_LIBRARY" "$STAGE/cmfd-forgematrix-v2-opencl.so"
  install -m 0644 "$PROJECT_ROOT/docs/opencl-miner.md" "$STAGE/opencl-miner.md"
fi
install -m 0755 "$PROJECT_ROOT/packaging/standalone-miner/linux/start-miner.sh" "$STAGE/start-miner.sh"
install -m 0644 "$PROJECT_ROOT/packaging/standalone-miner/linux/README.txt" "$STAGE/README.txt"
install -m 0644 "$PROJECT_ROOT/docs/standalone-miner.md" "$STAGE/standalone-miner.md"
install -m 0644 "$PROJECT_ROOT/LICENSE" "$STAGE/LICENSE"

tar -C "$OUTPUT_DIRECTORY" -czf "$ARCHIVE" "$PACKAGE_NAME"
BYTES="$(stat -c '%s' "$ARCHIVE")"
SHA256="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"

printf 'Package: %s\nBytes: %s\nSHA256: %s\n' "$ARCHIVE" "$BYTES" "$SHA256"
printf 'Native architectures: sm_70, sm_75, sm_86, sm_89, sm_120\n'
printf 'PTX fallback: compute_70\n'
if [[ -f "$OPENCL_LIBRARY" ]]; then
  printf 'OpenCL backend: included\n'
fi
