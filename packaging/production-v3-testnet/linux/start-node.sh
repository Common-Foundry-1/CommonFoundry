#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
exec "$SCRIPT_DIR/cmfd-node" \
  --data-dir "$SCRIPT_DIR/data" \
  --proof-verifier-cpu-quota-us 400000 \
  --proof-verifier-cpu-period-us 100000 \
  --proof-verifier-pids-limit 64 \
  -vv run \
  --bind 127.0.0.1:21443 \
  --p2p-bind 0.0.0.0:21444 \
  --peer 107.214.187.2:21444 \
  --allow-public-peers
