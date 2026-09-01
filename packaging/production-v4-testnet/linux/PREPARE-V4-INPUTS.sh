#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_BASE="${CMFD_RELEASE_BASE:-https://downloads.commonfoundry.ai/v0.1.0-rc.1}"
FALLBACK_RELEASE_BASE="${CMFD_FALLBACK_RELEASE_BASE:-https://github.com/Common-Foundry-1/CommonFoundry/releases/download/v0.1.0-rc.1}"

for command_name in curl python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: $command_name is required." >&2
    exit 1
  fi
done

exec python3 "$SCRIPT_DIR/production-v4-inputs.py" \
  --chunk-manifest "$SCRIPT_DIR/V4-INPUT-CHUNKS.json" \
  --input-manifest "$SCRIPT_DIR/production-v4-rcnet-1-inputs.json" \
  --fixed-record "$SCRIPT_DIR/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" \
  --destination "$SCRIPT_DIR/inputs" \
  --release-base "$RELEASE_BASE" \
  --fallback-release-base "$FALLBACK_RELEASE_BASE" "$@"
