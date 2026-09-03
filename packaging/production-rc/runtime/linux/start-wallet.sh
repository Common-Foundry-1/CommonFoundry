#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -x "$SCRIPT_DIR/common-foundry-wallet" ]] || { echo 'ERROR: common-foundry-wallet is missing or not executable.' >&2; exit 1; }
"$SCRIPT_DIR/prepare-rcnet-runtime.sh" "$SCRIPT_DIR/production-v4"
exec "$SCRIPT_DIR/common-foundry-wallet"
