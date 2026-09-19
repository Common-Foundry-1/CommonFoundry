#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$SCRIPT_DIR"
WALLET_ADDRESS="${CMFD_WALLET_ADDRESS:-${1:-}}"
POOL_URL="${CMFD_POOL_URL:-${2:-}}"
WORKER_NAME="${CMFD_WORKER_NAME:-$(hostname -s)}"
[[ -n "$WALLET_ADDRESS" ]] || read -r -p 'Mainnet wallet receive address (64 hex characters): ' WALLET_ADDRESS
[[ "$WALLET_ADDRESS" =~ ^[0-9a-fA-F]{64}$ ]] || { echo 'ERROR: wallet address must be 64 hex characters.' >&2; exit 2; }
[[ -n "$POOL_URL" ]] || read -r -p 'Mainnet pool URL (cmfd+tls://IP:PORT?pin=...): ' POOL_URL
[[ "$POOL_URL" =~ ^cmfd\+tls://([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}\?pin=[0-9a-fA-F]{64}$ ]] || { echo 'ERROR: use a complete certificate-pinned numeric IPv4 pool URL.' >&2; exit 2; }
[[ "$WORKER_NAME" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || { echo 'ERROR: worker name must be 1-32 letters, numbers, dots, underscores or hyphens.' >&2; exit 2; }
"$SCRIPT_DIR/cmfd-miner" mainnet-launch-info
CMFD_FALLBACK_RELEASE_BASE='https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-rc.1' \
  "$SCRIPT_DIR/PREPARE-V4-INPUTS.sh" --role pool-miner
"$SCRIPT_DIR/cmfd-launch" fetch --runtime "$SCRIPT_DIR/cmfd-miner" --wait
mkdir -p -- "$SCRIPT_DIR/work/pool-search"
exec "$SCRIPT_DIR/cmfd-miner" pool --pool "$POOL_URL" --miner "$WALLET_ADDRESS" --worker "$WORKER_NAME" \
  --production-v4-bank "$SCRIPT_DIR/inputs/MODEL-V2.bank" \
  --production-v4-replay-worker "$SCRIPT_DIR/cmfd-v4-replay" \
  --production-v4-scratch "$SCRIPT_DIR/work/pool-search" --stats-seconds 5
