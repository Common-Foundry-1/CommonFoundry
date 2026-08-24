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

# Stage the archive under the native Linux temporary filesystem. WSL-mounted
# Windows filesystems can otherwise collapse every staged mode to 0777 before
# tar records it.
PACKAGE_TEMP_ROOT="$(mktemp -d /tmp/cmfd-miner-package.XXXXXX)"
trap 'rm -rf -- "$PACKAGE_TEMP_ROOT"' EXIT
TEMP_STAGE="$PACKAGE_TEMP_ROOT/$PACKAGE_NAME"
TEMP_ARCHIVE="$PACKAGE_TEMP_ROOT/$PACKAGE_NAME.tar.gz"

mkdir -p "$TEMP_STAGE"
install -m 0755 "$TARGET_DIRECTORY/release/cmfd-miner" "$TEMP_STAGE/cmfd-miner"
install -m 0755 "$CUDA_LIBRARY" "$TEMP_STAGE/cmfd-forgematrix-v2-miner.so"
if [[ -f "$OPENCL_LIBRARY" ]]; then
  install -m 0755 "$OPENCL_LIBRARY" "$TEMP_STAGE/cmfd-forgematrix-v2-opencl.so"
  install -m 0644 "$PROJECT_ROOT/docs/opencl-miner.md" "$TEMP_STAGE/opencl-miner.md"
fi
install -m 0755 "$PROJECT_ROOT/packaging/standalone-miner/linux/start-miner.sh" "$TEMP_STAGE/start-miner.sh"
install -m 0644 "$PROJECT_ROOT/packaging/standalone-miner/linux/README.txt" "$TEMP_STAGE/README.txt"
install -m 0644 "$PROJECT_ROOT/docs/standalone-miner.md" "$TEMP_STAGE/standalone-miner.md"
install -m 0644 "$PROJECT_ROOT/LICENSE" "$TEMP_STAGE/LICENSE"

tar -C "$PACKAGE_TEMP_ROOT" -czf "$TEMP_ARCHIVE" "$PACKAGE_NAME"

VERIFY_ROOT="$PACKAGE_TEMP_ROOT/verify"
mkdir -p "$VERIFY_ROOT"
tar -C "$VERIFY_ROOT" -xzf "$TEMP_ARCHIVE"

require_mode() {
  local expected="$1"
  local path="$2"
  local actual
  actual="$(stat -c '%a' "$path")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Unexpected archive mode $actual for $path; expected $expected." >&2
    exit 1
  fi
}

VERIFY_STAGE="$VERIFY_ROOT/$PACKAGE_NAME"
require_mode 755 "$VERIFY_STAGE"
require_mode 755 "$VERIFY_STAGE/cmfd-miner"
require_mode 755 "$VERIFY_STAGE/cmfd-forgematrix-v2-miner.so"
require_mode 755 "$VERIFY_STAGE/start-miner.sh"
require_mode 644 "$VERIFY_STAGE/README.txt"
require_mode 644 "$VERIFY_STAGE/standalone-miner.md"
require_mode 644 "$VERIFY_STAGE/LICENSE"
if [[ -f "$OPENCL_LIBRARY" ]]; then
  require_mode 755 "$VERIFY_STAGE/cmfd-forgematrix-v2-opencl.so"
  require_mode 644 "$VERIFY_STAGE/opencl-miner.md"
fi

cp -a "$TEMP_STAGE" "$STAGE"
cp "$TEMP_ARCHIVE" "$ARCHIVE"
BYTES="$(stat -c '%s' "$ARCHIVE")"
SHA256="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"

printf 'Package: %s\nBytes: %s\nSHA256: %s\n' "$ARCHIVE" "$BYTES" "$SHA256"
printf 'Native architectures: sm_70, sm_75, sm_86, sm_89, sm_120\n'
printf 'PTX fallback: compute_70\n'
if [[ -f "$OPENCL_LIBRARY" ]]; then
  printf 'OpenCL backend: included\n'
fi
