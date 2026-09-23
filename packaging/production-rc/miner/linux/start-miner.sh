#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WALLET_ADDRESS="${CMFD_WALLET_ADDRESS:-${1:-}}"
POOL_URL="${CMFD_POOL_URL:-${2:-}}"
WORKER_NAME="${CMFD_WORKER_NAME:-$(hostname -s)}"
GPU_SELECTOR="${CMFD_GPU:-${3:-${CUDA_VISIBLE_DEVICES:-}}}"

if [[ -z "$WALLET_ADDRESS" ]]; then
  read -r -p "RCNet-1 wallet receive address (64 hex characters): " WALLET_ADDRESS
fi
if [[ ! "$WALLET_ADDRESS" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "ERROR: wallet address must be exactly 64 hexadecimal characters." >&2
  exit 2
fi
if [[ -z "$POOL_URL" ]]; then
  read -r -p "Certificate-pinned pool URL (cmfd+tls://IP:PORT?pin=...): " POOL_URL
fi
if [[ ! "$POOL_URL" =~ ^cmfd\+tls://([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}\?pin=[0-9a-fA-F]{64}$ ]]; then
  echo "ERROR: pool URL must use cmfd+tls://NUMERIC_IP:PORT?pin=64_HEX." >&2
  exit 2
fi
if [[ ! "$WORKER_NAME" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
  echo "ERROR: worker name must contain 1-32 letters, numbers, dots, underscores, or hyphens." >&2
  exit 2
fi
if [[ -n "$GPU_SELECTOR" && ! "$GPU_SELECTOR" =~ ^([0-9]+|GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$ ]]; then
  echo "ERROR: CMFD_GPU must be one NVIDIA GPU index or full GPU UUID." >&2
  exit 2
fi
gpu_args=()
scratch="$SCRIPT_DIR/work/pool-search"
log_key=default
if [[ -n "$GPU_SELECTOR" ]]; then
  gpu_args=(--gpu "$GPU_SELECTOR")
  scratch="$SCRIPT_DIR/work/pool-search-gpu-$GPU_SELECTOR"
  log_key="gpu-$GPU_SELECTOR"
fi
mkdir -p -- "$SCRIPT_DIR/work/logs"
exec > >(tee -a "$SCRIPT_DIR/work/logs/miner-$log_key.log") 2>&1

"$SCRIPT_DIR/PREPARE-V4-INPUTS.sh" --role pool-miner
mkdir -p -- "$scratch"
exec "$SCRIPT_DIR/cmfd-miner" pool \
  --pool "$POOL_URL" \
  --miner "$WALLET_ADDRESS" \
  --worker "$WORKER_NAME" \
  "${gpu_args[@]}" \
  --production-v4-bank "$SCRIPT_DIR/inputs/MODEL-V2.bank" \
  --production-v4-replay-worker "$SCRIPT_DIR/cmfd-v4-replay" \
  --production-v4-scratch "$scratch" \
  --stats-seconds 5
