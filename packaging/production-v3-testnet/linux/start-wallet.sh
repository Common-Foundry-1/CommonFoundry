#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
exec "$SCRIPT_DIR/common-foundry-wallet" \
  --proof-verifier-cpu-quota-us 400000 \
  --proof-verifier-cpu-period-us 100000 \
  --proof-verifier-pids-limit 64
