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

# ---------------------------------------------------------------
# ProductionV3 model bank bootstrap. The 6.4 GB bank cannot ship as one
# download (GitHub caps release assets at 2 GiB), so on first run this
# launcher downloads its four published parts, verifies every SHA-256,
# assembles MODEL-V2.bank, and deletes the parts. Later runs skip this.
# Needs ~13 GB free during the first run.
# ---------------------------------------------------------------
BANK_BASE_URL="https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.15"
BANK_SHA="5f9b213c3bda51b74e4ebabb26607b67385d613aa8d99af915a48ab063e17d4e"
BANK_BYTES="6442975416"
declare -A PART_SHA=(
  [01]="3af0fd15bf0377bab42f2c59d8337f4f82e87e32c5f8c4f27ebfc21681450254"
  [02]="9d4f2547dc632c1c5f74ace84d26ca2ce38be50bea01ed93542fc5ab56aed6cf"
  [03]="a1bf1ac3230a54006039b3ce2add912e4c6f94065afad322bbaebee15b089602"
  [04]="5af1c6de16f5d48032aa9b37a5d48abd5d6c6e22b24935476faddb9af2cf7069"
)

hash_matches() {
  [[ "$(sha256sum "$1" | awk '{print $1}')" == "$2" ]]
}

if [[ ! -f "$SCRIPT_DIR/production-v3/MODEL-V2.bank" ]]; then
  echo "First run: fetching the 6.4 GB ProductionV3 model bank (four verified parts)..."
  mkdir -p "$SCRIPT_DIR/production-v3"
  for part in 01 02 03 04; do
    part_file="$SCRIPT_DIR/production-v3/RCNET1-MODEL-V2.bank.part$part"
    if [[ -f "$part_file" ]] && hash_matches "$part_file" "${PART_SHA[$part]}"; then
      echo "Part $part already present and verified."
      continue
    fi
    rm -f "$part_file"
    echo "Downloading part $part of 04 (about 1.6 GB)..."
    curl -L --fail --retry 3 --retry-delay 5 -o "$part_file.tmp"       "$BANK_BASE_URL/RCNET1-MODEL-V2.bank.part$part"
    mv "$part_file.tmp" "$part_file"
    echo "Verifying part $part..."
    if ! hash_matches "$part_file" "${PART_SHA[$part]}"; then
      echo "ERROR: part $part failed SHA-256 verification after download." >&2
      rm -f "$part_file"
      exit 1
    fi
  done
  echo "Assembling MODEL-V2.bank..."
  cat "$SCRIPT_DIR/production-v3/RCNET1-MODEL-V2.bank.part"{01,02,03,04}     > "$SCRIPT_DIR/production-v3/MODEL-V2.bank.tmp"
  actual_bytes="$(stat -c '%s' "$SCRIPT_DIR/production-v3/MODEL-V2.bank.tmp" 2>/dev/null || stat -f '%z' "$SCRIPT_DIR/production-v3/MODEL-V2.bank.tmp")"
  if [[ "$actual_bytes" != "$BANK_BYTES" ]]; then
    echo "ERROR: assembled bank size mismatch: expected $BANK_BYTES, got $actual_bytes." >&2
    rm -f "$SCRIPT_DIR/production-v3/MODEL-V2.bank.tmp"
    exit 1
  fi
  echo "Verifying the assembled bank's SHA-256 (a few minutes)..."
  if ! hash_matches "$SCRIPT_DIR/production-v3/MODEL-V2.bank.tmp" "$BANK_SHA"; then
    echo "ERROR: assembled bank failed SHA-256 verification. Delete the .part" >&2
    echo "files in production-v3 and run this launcher again to re-download." >&2
    rm -f "$SCRIPT_DIR/production-v3/MODEL-V2.bank.tmp"
    exit 1
  fi
  mv "$SCRIPT_DIR/production-v3/MODEL-V2.bank.tmp" "$SCRIPT_DIR/production-v3/MODEL-V2.bank"
  rm -f "$SCRIPT_DIR/production-v3/RCNET1-MODEL-V2.bank.part"{01,02,03,04}
  echo "Model bank ready and verified."
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
  # ProductionV3 accepts --batch-size 1-64 (per-worker nonce stride; proof
  # time dominates). Correct the reference-profile default automatically.
  if [[ "$BATCH_SIZE" == "8192" ]]; then
    BATCH_SIZE="64"
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
