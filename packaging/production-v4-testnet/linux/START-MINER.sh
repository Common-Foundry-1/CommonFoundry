#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MINER_ADDRESS="${1:-}"
if [[ -z "$MINER_ADDRESS" ]]; then
  echo "Paste the 64-character receive address shown by your RCNet-1 wallet."
  read -r -p "Mining address: " MINER_ADDRESS
fi

"$SCRIPT_DIR/PREPARE-V4-INPUTS.sh"
exec "$SCRIPT_DIR/run-production-v4-miner.sh" --miner "$MINER_ADDRESS" --inputs-prepared
