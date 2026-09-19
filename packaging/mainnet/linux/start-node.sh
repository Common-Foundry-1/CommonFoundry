#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$SCRIPT_DIR"
for file in cmfd-node cmfd-launch prepare-runtime.sh; do
  [[ -x "$SCRIPT_DIR/$file" ]] || { echo "ERROR: $file is missing or not executable." >&2; exit 1; }
done
PASSPHRASE_FILE="${CMFD_WALLET_PASSPHRASE_FILE:-${1:-}}"
[[ -n "$PASSPHRASE_FILE" ]] || read -r -p 'Path to the existing wallet passphrase file: ' PASSPHRASE_FILE
[[ "$PASSPHRASE_FILE" == /* && -f "$PASSPHRASE_FILE" ]] || { echo 'ERROR: supply an absolute path to a passphrase file outside the node data directory.' >&2; exit 2; }
PASSPHRASE_FILE="$(realpath -- "$PASSPHRASE_FILE")"
case "$PASSPHRASE_FILE" in "$SCRIPT_DIR/data-mainnet/"*) echo 'ERROR: keep the passphrase outside the node data directory.' >&2; exit 2;; esac
"$SCRIPT_DIR/cmfd-node" mainnet-launch-info
"$SCRIPT_DIR/prepare-runtime.sh" "$SCRIPT_DIR/production-v4"
"$SCRIPT_DIR/cmfd-launch" fetch --runtime "$SCRIPT_DIR/cmfd-node" --wait
exec "$SCRIPT_DIR/cmfd-node" --data-dir "$SCRIPT_DIR/data-mainnet" --wallet-passphrase-file "$PASSPHRASE_FILE" run --p2p-bind 0.0.0.0:29444 --allow-public-peers
