#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-linux-common.sh
source "$PROJECT_ROOT/scripts/release-linux-common.sh"
RELEASE_INTEGRITY="$PROJECT_ROOT/scripts/release_integrity.py"
OUTPUT_DIRECTORY="${1:-$PROJECT_ROOT/target/standalone-miner-package-linux}"
CUDA_BUILD_DIRECTORY="${2:-$PROJECT_ROOT/target/gpu-miner-build-volta-linux}"
OPENCL_BUILD_DIRECTORY="${3:-$PROJECT_ROOT/target/gpu-opencl-build-linux}"
EXPECTED_COMMIT="$(cmfd_release_commit "${4:-}")"
CUDA_LIBRARY="$CUDA_BUILD_DIRECTORY/cmfd-forgematrix-v2-miner.so"
OPENCL_LIBRARY="$OPENCL_BUILD_DIRECTORY/cmfd-forgematrix-v2-opencl.so"
CUDA_RECEIPT="$CUDA_LIBRARY.build-receipt"
OPENCL_RECEIPT="$OPENCL_LIBRARY.build-receipt"

cmfd_require_linux_gnu_x86_64
for command_name in cargo cp cut git install mktemp python3 sed sha256sum stat; do
  cmfd_require_command "$command_name"
done
SOURCE_DATE_EPOCH_VALUE="${SOURCE_DATE_EPOCH:-$(git -C "$PROJECT_ROOT" show -s --format=%ct "$EXPECTED_COMMIT")}"
VERSION="$(
  cargo pkgid --manifest-path "$PROJECT_ROOT/Cargo.toml" -p cmfd-miner --locked |
    sed -E 's/.*#//'
)"

if [[ ! -f "$CUDA_LIBRARY" ]]; then
  echo "CUDA library is missing: $CUDA_LIBRARY" >&2
  exit 1
fi

cmfd_require_elf_x86_64 "$CUDA_LIBRARY" shared
python3 "$RELEASE_INTEGRITY" receipt-verify \
  --repo "$PROJECT_ROOT" \
  --expected-commit "$EXPECTED_COMMIT" \
  --kind cuda \
  --library "$CUDA_LIBRARY" \
  --receipt "$CUDA_RECEIPT" \
  --expected-build-script scripts/build-cuda-miner.sh \
  --expected-target x86_64-unknown-linux-gnu \
  --expected-architectures 'sm_70;sm_75;sm_86;sm_89;sm_120;compute_70' \
  --source-date-epoch "$SOURCE_DATE_EPOCH_VALUE"

if [[ -f "$OPENCL_LIBRARY" ]]; then
  cmfd_require_elf_x86_64 "$OPENCL_LIBRARY" shared
  python3 "$RELEASE_INTEGRITY" receipt-verify \
    --repo "$PROJECT_ROOT" \
    --expected-commit "$EXPECTED_COMMIT" \
    --kind opencl \
    --library "$OPENCL_LIBRARY" \
    --receipt "$OPENCL_RECEIPT" \
    --expected-build-script scripts/build-opencl-miner.sh \
    --expected-target x86_64-unknown-linux-gnu \
    --expected-architectures opencl_1_2 \
    --source-date-epoch "$SOURCE_DATE_EPOCH_VALUE"
fi

TARGET_DIRECTORY="$OUTPUT_DIRECTORY/rust-target"
CMFD_RELEASE_LABEL="$VERSION" CARGO_TARGET_DIR="$TARGET_DIRECTORY" cargo build \
  --manifest-path "$PROJECT_ROOT/Cargo.toml" \
  --release --locked -p cmfd-miner
cmfd_require_elf_x86_64 "$TARGET_DIRECTORY/release/cmfd-miner" executable

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
install -m 0644 "$CUDA_RECEIPT" "$TEMP_STAGE/cmfd-forgematrix-v2-miner.so.build-receipt"
if [[ -f "$OPENCL_LIBRARY" ]]; then
  install -m 0755 "$OPENCL_LIBRARY" "$TEMP_STAGE/cmfd-forgematrix-v2-opencl.so"
  install -m 0644 "$OPENCL_RECEIPT" "$TEMP_STAGE/cmfd-forgematrix-v2-opencl.so.build-receipt"
  install -m 0644 "$PROJECT_ROOT/docs/opencl-miner.md" "$TEMP_STAGE/opencl-miner.md"
fi
install -m 0755 "$PROJECT_ROOT/packaging/standalone-miner/linux/start-miner.sh" "$TEMP_STAGE/start-miner.sh"
install -m 0644 "$PROJECT_ROOT/packaging/standalone-miner/linux/README.txt" "$TEMP_STAGE/README.txt"
install -m 0644 "$PROJECT_ROOT/docs/standalone-miner.md" "$TEMP_STAGE/standalone-miner.md"
install -m 0644 "$PROJECT_ROOT/LICENSE" "$TEMP_STAGE/LICENSE"

python3 "$RELEASE_INTEGRITY" archive-tar-gz \
  --stage "$TEMP_STAGE" \
  --output "$TEMP_ARCHIVE" \
  --source-date-epoch "$SOURCE_DATE_EPOCH_VALUE"

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
