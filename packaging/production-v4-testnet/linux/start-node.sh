#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
"$SCRIPT_DIR/prepare-v4-node-inputs.sh"
exec "$SCRIPT_DIR/cmfd-node" \
  --data-dir "$SCRIPT_DIR/node-data" \
  --production-v4-bank "$SCRIPT_DIR/production-v4/MODEL-V2.bank" \
  --production-v4-fixed-record "$SCRIPT_DIR/production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" \
  run \
  --bind 127.0.0.1:22443 \
  --p2p-bind 0.0.0.0:22444 \
  --peer 107.214.187.2:22444 \
  --allow-public-peers
