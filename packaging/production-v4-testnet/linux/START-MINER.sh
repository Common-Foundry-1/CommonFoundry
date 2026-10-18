#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MINER_ADDRESS="${1:-}"
if [[ -z "$MINER_ADDRESS" ]]; then
  echo "Paste the receive address shown by your RCNet-1 wallet (tcmfd1... or 64 hex characters)."
  read -r -p "Mining address: " MINER_ADDRESS
fi

"$SCRIPT_DIR/PREPARE-V4-INPUTS.sh"
exec "$SCRIPT_DIR/run-production-v4-miner.sh" --miner "$MINER_ADDRESS" --inputs-prepared
