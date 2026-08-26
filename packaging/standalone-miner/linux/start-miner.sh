#!/usr/bin/env bash
set -euo pipefail

# These defaults work with a wallet on this computer or the community bootstrap.
# Leave GPU_INDEXES empty to use every supported GPU.
LOCAL_PEER="127.0.0.1:18444"
BOOTSTRAP_PEER="107.214.187.2:18444"
# Use auto for NVIDIA, or opencl for Intel Arc.
GPU_BACKEND="auto"
GPU_INDEXES=""
# PAYOUT_ADDRESS is your wallet's 64-character receive address.
PAYOUT_ADDRESS=""
BATCH_SIZE="8192"
# 0 automatically divides host CPU threads across the selected GPUs (maximum 16 each).
WORKERS_PER_GPU="0"
STATS_SECONDS="5"
PRODUCTION_V3_MAX_ROWS="131072"

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
if [[ -z "$PAYOUT_ADDRESS" ]]; then
  echo "ERROR: Set PAYOUT_ADDRESS to the 64-character receive address shown by your wallet." >&2
  exit 1
fi

PRODUCTION_V3_READY=0
if [[ -f "$SCRIPT_DIR/production-v3/MODEL-V2.bank" &&
      -f "$SCRIPT_DIR/production-v3/MODEL-V2.manifest.json" &&
      -f "$SCRIPT_DIR/production-v3/DORY-V3-MODEL-RECORD-V2.json" ]]; then
  if [[ "$LOCAL_PEER" == "127.0.0.1:18444" ]]; then
    LOCAL_PEER="127.0.0.1:21444"
  fi
  if [[ "$BOOTSTRAP_PEER" == "107.214.187.2:18444" ]]; then
    BOOTSTRAP_PEER="107.214.187.2:21444"
  fi
  PRODUCTION_V3_READY=1
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
if [[ "$PRODUCTION_V3_READY" == 1 ]]; then
  mkdir -p "$SCRIPT_DIR/production-v3/scratch"
  # ProductionV3 refuses to load model artifacts from a directory other accounts
  # can reach, and tar restores 0755. Make the sidecar directory private to you.
  chmod 700 "$SCRIPT_DIR/production-v3"
  ARGS+=(
    --production-v3-bank "$SCRIPT_DIR/production-v3/MODEL-V2.bank"
    --production-v3-manifest "$SCRIPT_DIR/production-v3/MODEL-V2.manifest.json"
    --production-v3-record-v2 "$SCRIPT_DIR/production-v3/DORY-V3-MODEL-RECORD-V2.json"
    --production-v3-scratch "$SCRIPT_DIR/production-v3/scratch"
    --production-v3-max-rows "$PRODUCTION_V3_MAX_ROWS"
  )
fi
export CMFD_GPU_BACKEND="$GPU_BACKEND"
exec "$SCRIPT_DIR/cmfd-miner" "${ARGS[@]}"
