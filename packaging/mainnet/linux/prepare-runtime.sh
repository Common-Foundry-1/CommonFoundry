#!/usr/bin/env bash
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DESTINATION="${1:-$SCRIPT_DIR/production-v4}"
ROLE="${2:-node}"
[[ "$ROLE" == node || "$ROLE" == miner ]] || { echo 'ERROR: role must be node or miner.' >&2; exit 2; }
"$SCRIPT_DIR/cmfd-node" mainnet-launch-info
# RC1 names identify immutable artifact provenance, not this package's network.
python3 "$SCRIPT_DIR/production-v4-inputs.py" \
  --chunk-manifest "$SCRIPT_DIR/V4-INPUT-CHUNKS.json" \
  --input-manifest "$SCRIPT_DIR/production-v4-rcnet-1-inputs.json" \
  --fixed-record "$SCRIPT_DIR/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" \
  --destination "$DESTINATION" --role "$ROLE" \
  --release-base 'https://downloads.commonfoundry.ai/v0.1.0-rc.1' \
  --fallback-release-base 'https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.16'
cp -- "$DESTINATION/fixed/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" "$DESTINATION/"
echo 'Mainnet model inputs are ready. This does not activate the network.'
