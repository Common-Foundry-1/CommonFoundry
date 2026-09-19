#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$SCRIPT_DIR"
for file in cmfd-node cmfd-launch common-foundry-wallet prepare-runtime.sh; do
  [[ -x "$SCRIPT_DIR/$file" ]] || { echo "ERROR: $file is missing or not executable." >&2; exit 1; }
done
"$SCRIPT_DIR/cmfd-node" mainnet-launch-info
"$SCRIPT_DIR/prepare-runtime.sh" "$SCRIPT_DIR/production-v4"
# The GUI can prepare keys offline; its node independently enforces activation.
exec "$SCRIPT_DIR/common-foundry-wallet"
