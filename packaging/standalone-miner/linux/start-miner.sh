#!/usr/bin/env bash
set -euo pipefail

# These defaults work with a wallet on this computer or the community bootstrap.
# Leave GPU_INDEXES empty to use every supported GPU.
LOCAL_PEER="127.0.0.1:18444"
BOOTSTRAP_PEER="107.214.187.2:18444"
GPU_INDEXES=""
# PAYOUT_ADDRESS is your wallet's 64-character receive address.
PAYOUT_ADDRESS=""
BATCH_SIZE="8192"
# 0 automatically divides host CPU threads across the selected GPUs (maximum 16 each).
WORKERS_PER_GPU="0"
STATS_SECONDS="5"

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
if [[ -z "$PAYOUT_ADDRESS" ]]; then
  echo "ERROR: Set PAYOUT_ADDRESS to the 64-character receive address shown by your wallet." >&2
  exit 1
fi

ARGS=(mine --miner "$PAYOUT_ADDRESS" --batch-size "$BATCH_SIZE" --workers-per-gpu "$WORKERS_PER_GPU" --stats-seconds "$STATS_SECONDS")
if [[ -n "$LOCAL_PEER" ]]; then
  ARGS+=(--peer "$LOCAL_PEER")
fi
if [[ -n "$BOOTSTRAP_PEER" ]]; then
  ARGS+=(--peer "$BOOTSTRAP_PEER" --allow-public-peers)
fi
if [[ -n "$GPU_INDEXES" ]]; then
  IFS=',' read -ra DEVICES <<< "$GPU_INDEXES"
  for DEVICE in "${DEVICES[@]}"; do
    ARGS+=(--device "$DEVICE")
  done
fi
exec "$SCRIPT_DIR/cmfd-miner" "${ARGS[@]}"
