#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
"$SCRIPT_DIR/prepare-v4-node-inputs.sh"
exec "$SCRIPT_DIR/common-foundry-wallet" \
  --peer 107.214.187.2:22444 \
  --allow-public-peers
