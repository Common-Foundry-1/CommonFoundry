#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

# ProductionV3 refuses to load its Record V2 from a directory other accounts can
# reach, and tar restores 0755. Make the sidecar directory private to you.
if [[ -d "$SCRIPT_DIR/production-v3" ]]; then
  chmod 700 "$SCRIPT_DIR/production-v3"
fi

exec "$SCRIPT_DIR/common-foundry-wallet" \
  --p2p-bind 0.0.0.0:21444 \
  --peer 107.214.187.2:21444 \
  --allow-public-peers \
  --proof-verifier-cpu-quota-us 400000 \
  --proof-verifier-cpu-period-us 100000 \
  --proof-verifier-pids-limit 64
