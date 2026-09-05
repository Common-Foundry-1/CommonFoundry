#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_COMMIT="${1:?usage: package-wallet-runtime-bootstrap.sh EXPECTED_COMMIT VERSION [OUTPUT_DIRECTORY]}"
VERSION="${2:?usage: package-wallet-runtime-bootstrap.sh EXPECTED_COMMIT VERSION [OUTPUT_DIRECTORY]}"
OUTPUT_DIRECTORY="${3:-$PROJECT_ROOT/target/runtime-bootstrap-linux}"
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo 'ERROR: expected commit must be 40 lowercase hex characters.' >&2; exit 2; }
[[ "$VERSION" =~ ^0\.1\.0-rc\.[0-9]+$ ]] || { echo 'ERROR: version must be an RC label.' >&2; exit 2; }
CURRENT_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
[[ "$CURRENT_COMMIT" == "$EXPECTED_COMMIT" ]] || { echo "ERROR: expected commit $EXPECTED_COMMIT, found $CURRENT_COMMIT" >&2; exit 1; }
NODE="$PROJECT_ROOT/target/release/cmfd-node"
WALLET="$PROJECT_ROOT/target/release/common-foundry-wallet"
[[ -x "$NODE" && -x "$WALLET" ]] || { echo 'ERROR: release node and wallet binaries are required.' >&2; exit 1; }
for command_name in cp git install mkdir python3 rm stat sha256sum; do command -v "$command_name" >/dev/null 2>&1 || { echo "ERROR: $command_name is required." >&2; exit 1; }; done

PACKAGE_NAME="commonfoundry-rc-runtime-bootstrap-linux-x86_64-v$VERSION"
STAGE="$OUTPUT_DIRECTORY/$PACKAGE_NAME"
ARCHIVE="$OUTPUT_DIRECTORY/$PACKAGE_NAME.tar.gz"
[[ ! -e "$STAGE" && ! -e "$ARCHIVE" ]] || { echo "ERROR: package output already exists: $OUTPUT_DIRECTORY" >&2; exit 1; }
TEMP_ROOT="$(mktemp -d /tmp/cmfd-runtime-bootstrap.XXXXXX)"
trap 'rm -rf -- "$TEMP_ROOT"' EXIT
TEMP_STAGE="$TEMP_ROOT/$PACKAGE_NAME"
TEMP_ARCHIVE="$TEMP_ROOT/$PACKAGE_NAME.tar.gz"
mkdir -p "$TEMP_STAGE"
SHARED="$PROJECT_ROOT/packaging/production-v4-pool/shared"
RUNTIME="$PROJECT_ROOT/packaging/production-rc/runtime"
install -m 0755 "$WALLET" "$TEMP_STAGE/common-foundry-wallet"
install -m 0755 "$NODE" "$TEMP_STAGE/cmfd-node"
install -m 0755 "$RUNTIME/linux/prepare-rcnet-runtime.sh" "$TEMP_STAGE/prepare-rcnet-runtime.sh"
install -m 0755 "$RUNTIME/linux/start-wallet.sh" "$TEMP_STAGE/start-wallet.sh"
install -m 0755 "$RUNTIME/linux/prepare-mining.sh" "$TEMP_STAGE/prepare-mining.sh"
install -m 0644 "$RUNTIME/MINING-WORKERS.json" "$TEMP_STAGE/MINING-WORKERS.json"
install -m 0644 "$PROJECT_ROOT/scripts/production-v4-inputs.py" "$TEMP_STAGE/production-v4-inputs.py"
install -m 0644 "$RUNTIME/README.md" "$TEMP_STAGE/README.md"
install -m 0644 "$SHARED/V4-INPUT-CHUNKS.json" "$TEMP_STAGE/V4-INPUT-CHUNKS.json"
install -m 0644 "$SHARED/production-v4-rcnet-1-inputs.json" "$TEMP_STAGE/production-v4-rcnet-1-inputs.json"
install -m 0644 "$SHARED/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" "$TEMP_STAGE/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
install -m 0644 "$PROJECT_ROOT/LICENSE" "$TEMP_STAGE/LICENSE"
install -m 0644 "$PROJECT_ROOT/THIRD_PARTY_NOTICES.md" "$TEMP_STAGE/THIRD_PARTY_NOTICES.md"
SOURCE_DATE_EPOCH_VALUE="${SOURCE_DATE_EPOCH:-$(git -C "$PROJECT_ROOT" show -s --format=%ct "$EXPECTED_COMMIT")}"
python3 "$PROJECT_ROOT/scripts/release_integrity.py" archive-tar-gz --stage "$TEMP_STAGE" --output "$TEMP_ARCHIVE" --source-date-epoch "$SOURCE_DATE_EPOCH_VALUE"
mkdir -p "$OUTPUT_DIRECTORY"
cp -a "$TEMP_STAGE" "$STAGE"
cp "$TEMP_ARCHIVE" "$ARCHIVE"
printf 'Package: %s\nBytes: %s\nSHA256: %s\n' "$ARCHIVE" "$(stat -c '%s' "$ARCHIVE")" "$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
