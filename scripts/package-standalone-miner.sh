#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-linux-common.sh
source "$PROJECT_ROOT/scripts/release-linux-common.sh"
RELEASE_INTEGRITY="$PROJECT_ROOT/scripts/release_integrity.py"
OUTPUT_DIRECTORY="${1:-$PROJECT_ROOT/target/standalone-miner-package-linux}"
REPLAY_WORKER="${2:-$PROJECT_ROOT/tools/production-v4-prover/target/release/cmfd-v4-replay}"
EXPECTED_COMMIT="$(cmfd_release_commit "${3:-}")"

cmfd_require_linux_gnu_x86_64
for command_name in cargo cp cut git install mktemp python3 sed sha256sum stat; do
  cmfd_require_command "$command_name"
done
if [[ ! -x "$REPLAY_WORKER" ]]; then
  echo "ProductionV4 replay worker is missing or not executable: $REPLAY_WORKER" >&2
  exit 1
fi
SOURCE_DATE_EPOCH_VALUE="${SOURCE_DATE_EPOCH:-$(git -C "$PROJECT_ROOT" show -s --format=%ct "$EXPECTED_COMMIT")}"
VERSION="$(cargo pkgid --manifest-path "$PROJECT_ROOT/Cargo.toml" -p cmfd-miner --locked | sed -E 's/.*#//')"
TARGET_DIRECTORY="$OUTPUT_DIRECTORY/rust-target"
MINER="${CMFD_MINER_BINARY:-$TARGET_DIRECTORY/release/cmfd-miner}"
if [[ -z "${CMFD_MINER_BINARY:-}" ]]; then
  CMFD_BUILD_SOURCE_COMMIT="$EXPECTED_COMMIT" CMFD_RELEASE_LABEL="$VERSION" \
    CARGO_TARGET_DIR="$TARGET_DIRECTORY" cargo build \
    --manifest-path "$PROJECT_ROOT/Cargo.toml" \
    --release --locked -p cmfd-miner --features production-rc
fi
cmfd_require_elf_x86_64 "$MINER" executable
cmfd_require_elf_x86_64 "$REPLAY_WORKER" executable
"$MINER" network-info | python3 -c '
import json, sys
identity = json.load(sys.stdin)
if (identity.get("build_source_commit") != sys.argv[1]
    or identity.get("proof_selection") != "ProductionV4"
    or identity.get("network_id") != "3e99d45959c19c0053d8e9fef34875b57b46a8a1ce330637daddab515bc7b92d"):
    raise SystemExit("Miner does not report the expected RC4 source and RCNet-1 identity.")
' "$EXPECTED_COMMIT"

PACKAGE_NAME="commonfoundry-miner-v${VERSION}-linux-x86_64-gnu"
STAGE="$OUTPUT_DIRECTORY/$PACKAGE_NAME"
ARCHIVE="$OUTPUT_DIRECTORY/$PACKAGE_NAME.tar.gz"
if [[ -e "$STAGE" || -e "$ARCHIVE" ]]; then
  echo "Package staging path or archive already exists." >&2
  exit 1
fi

PACKAGE_TEMP_ROOT="$(mktemp -d /tmp/cmfd-miner-package.XXXXXX)"
trap 'rm -rf -- "$PACKAGE_TEMP_ROOT"' EXIT
TEMP_STAGE="$PACKAGE_TEMP_ROOT/$PACKAGE_NAME"
TEMP_ARCHIVE="$PACKAGE_TEMP_ROOT/$PACKAGE_NAME.tar.gz"
SHARED="$PROJECT_ROOT/packaging/production-v4-pool/shared"
mkdir -p "$TEMP_STAGE"
install -m 0755 "$MINER" "$TEMP_STAGE/cmfd-miner"
install -m 0755 "$REPLAY_WORKER" "$TEMP_STAGE/cmfd-v4-replay"
install -m 0755 "$PROJECT_ROOT/packaging/production-rc/miner/linux/start-miner.sh" "$TEMP_STAGE/start-miner.sh"
install -m 0755 "$PROJECT_ROOT/packaging/production-v4-testnet/linux/PREPARE-V4-INPUTS.sh" "$TEMP_STAGE/PREPARE-V4-INPUTS.sh"
install -m 0755 "$PROJECT_ROOT/scripts/production-v4-inputs.py" "$TEMP_STAGE/production-v4-inputs.py"
install -m 0644 "$SHARED/V4-INPUT-CHUNKS.json" "$TEMP_STAGE/V4-INPUT-CHUNKS.json"
install -m 0644 "$SHARED/production-v4-rcnet-1-inputs.json" "$TEMP_STAGE/production-v4-rcnet-1-inputs.json"
install -m 0644 "$SHARED/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" "$TEMP_STAGE/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
install -m 0644 "$PROJECT_ROOT/docs/production-v4-pool-miner.md" "$TEMP_STAGE/README.md"
install -m 0644 "$PROJECT_ROOT/docs/release-notes/v${VERSION}.md" "$TEMP_STAGE/RELEASE_NOTES.md"
install -m 0644 "$PROJECT_ROOT/LICENSE" "$TEMP_STAGE/LICENSE"
install -m 0644 "$PROJECT_ROOT/THIRD_PARTY_NOTICES.md" "$TEMP_STAGE/THIRD_PARTY_NOTICES.md"

python3 "$RELEASE_INTEGRITY" archive-tar-gz \
  --stage "$TEMP_STAGE" \
  --output "$TEMP_ARCHIVE" \
  --source-date-epoch "$SOURCE_DATE_EPOCH_VALUE"
mkdir -p "$OUTPUT_DIRECTORY"
cp -a "$TEMP_STAGE" "$STAGE"
cp "$TEMP_ARCHIVE" "$ARCHIVE"
printf 'Package: %s\nBytes: %s\nSHA256: %s\n' \
  "$ARCHIVE" "$(stat -c '%s' "$ARCHIVE")" "$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
printf 'Runtime: ProductionV4 certificate-pinned pool miner\n'
