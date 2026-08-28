#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PEER="107.214.187.2:22444"
MINER=""
BLOCKS=0
CUDA_DEVICE=0
NONCE=0
KEEP_ACCEPTED_WORK=0
VALIDATE_ONLY=0

usage() {
  echo "Usage: $0 --miner ADDRESS [--peer HOST:PORT] [--blocks N] [--cuda-device N]"
}

while (($#)); do
  case "$1" in
    --miner) MINER="${2:-}"; shift 2 ;;
    --peer) PEER="${2:-}"; shift 2 ;;
    --blocks) BLOCKS="${2:-}"; shift 2 ;;
    --cuda-device) CUDA_DEVICE="${2:-}"; shift 2 ;;
    --nonce) NONCE="${2:-}"; shift 2 ;;
    --keep-accepted-work) KEEP_ACCEPTED_WORK=1; shift ;;
    --validate-only) VALIDATE_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! "$MINER" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "ERROR: --miner must be the wallet's 64-character receive address." >&2
  exit 2
fi
if [[ ! "$BLOCKS" =~ ^[0-9]+$ || ! "$CUDA_DEVICE" =~ ^[0-9]+$ || ! "$NONCE" =~ ^[0-9]+$ ]]; then
  echo "ERROR: blocks, CUDA device, and nonce must be non-negative integers." >&2
  exit 2
fi

for command_name in nvidia-smi python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: $command_name is required." >&2
    exit 1
  fi
done

MODEL_BANK="$SCRIPT_DIR/inputs/MODEL-V2.bank"
FIXED_DIRECTORY="$SCRIPT_DIR/inputs/fixed"
INPUT_MANIFEST="$SCRIPT_DIR/production-v4-testnet-1-inputs.json"
FIXED_RECORD="$FIXED_DIRECTORY/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
CMFD_MINER="$SCRIPT_DIR/cmfd-miner"
REPLAY_BINARY="$SCRIPT_DIR/cmfd-v4-replay"
DYNAMIC_BINARY="$SCRIPT_DIR/cmfd-v4-dynamic-commitments"
PROOF_BINARY="$SCRIPT_DIR/cmfd-v4-prover"
WORK_DIRECTORY="$SCRIPT_DIR/work"

for path in "$CMFD_MINER" "$REPLAY_BINARY" "$DYNAMIC_BINARY" "$PROOF_BINARY"; do
  if [[ ! -x "$path" ]]; then
    echo "ERROR: required executable is missing: $path" >&2
    exit 1
  fi
done

python3 "$SCRIPT_DIR/production-v4-inputs.py" \
  --chunk-manifest "$SCRIPT_DIR/V4-INPUT-CHUNKS.json" \
  --input-manifest "$INPUT_MANIFEST" \
  --fixed-record "$SCRIPT_DIR/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" \
  --destination "$SCRIPT_DIR/inputs" \
  --release-base "https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.16" \
  --validate-only

gpu_line="$(nvidia-smi --id="$CUDA_DEVICE" --query-gpu=name,memory.total,compute_cap --format=csv,noheader,nounits)"
IFS=',' read -r gpu_name gpu_memory gpu_compute <<<"$gpu_line"
gpu_name="${gpu_name# }"; gpu_name="${gpu_name% }"
gpu_memory="${gpu_memory// /}"
gpu_compute="${gpu_compute// /}"
if [[ ! "$gpu_memory" =~ ^[0-9]+$ || "$gpu_memory" -lt 15000 ]]; then
  echo "ERROR: GPU $gpu_name has ${gpu_memory:-unknown} MiB; at least 15000 MiB is required." >&2
  exit 1
fi
if [[ "$gpu_compute" != "12.0" ]]; then
  echo "ERROR: GPU $gpu_name has compute capability $gpu_compute; this build requires 12.0." >&2
  exit 1
fi
echo "ProductionV4 GPU: $gpu_name, $gpu_memory MiB, compute $gpu_compute"

if ((VALIDATE_ONLY)); then
  echo "ProductionV4 Linux miner launcher validation passed."
  exit 0
fi

mkdir -p -- "$WORK_DIRECTORY"
export CUDA_VISIBLE_DEVICES="$CUDA_DEVICE"
export CUDA_HOME="${CUDA_HOME:-/usr/local/cuda-12.8}"
export CUDA_PATH="${CUDA_PATH:-$CUDA_HOME}"
export CUDAToolkit_ROOT="${CUDAToolkit_ROOT:-$CUDA_HOME}"
export LD_LIBRARY_PATH="$CUDA_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

accepted=0
while ((BLOCKS == 0 || accepted < BLOCKS)); do
  attempt_name="attempt-$(printf '%08d' "$((accepted + 1))")-$(date -u +%Y%m%dT%H%M%S%NZ)"
  attempt_directory="$WORK_DIRECTORY/$attempt_name"
  if [[ -e "$attempt_directory" ]]; then
    echo "ERROR: attempt directory already exists: $attempt_directory" >&2
    exit 1
  fi
  mkdir -- "$attempt_directory"

  template="$attempt_directory/template.json"
  coefficients="$attempt_directory/replay-coefficients.bin"
  trace_prefix="$attempt_directory/trace"
  dynamic_commitments="$attempt_directory/dynamic-commitments.json"
  final_activation="$trace_prefix-final-activation.bin"
  proof="$attempt_directory/transparent-proof.bin"

  "$CMFD_MINER" snapshot-v4-template \
    --peer "$PEER" --allow-public-peers --miner "$MINER" --nonce "$NONCE" \
    --fixed-record "$FIXED_RECORD" --coefficients-output "$coefficients" --output "$template"
  "$REPLAY_BINARY" "$MODEL_BANK" "$coefficients" "$trace_prefix"
  "$DYNAMIC_BINARY" "$trace_prefix" "$dynamic_commitments"
  "$PROOF_BINARY" "$MODEL_BANK" "$FIXED_DIRECTORY" "$template" "$trace_prefix" \
    "$dynamic_commitments" "$final_activation" "$proof"
  "$CMFD_MINER" submit-v4-template \
    --peer "$PEER" --allow-public-peers --template "$template" \
    --transparent-proof "$proof" --fixed-record "$FIXED_RECORD"

  accepted=$((accepted + 1))
  echo "Accepted ProductionV4 block $accepted for this launcher session."
  if ((KEEP_ACCEPTED_WORK == 0)); then
    resolved_attempt="$(realpath -- "$attempt_directory")"
    resolved_parent="$(dirname -- "$resolved_attempt")"
    if [[ "$resolved_parent" != "$(realpath -- "$WORK_DIRECTORY")" ]]; then
      echo "ERROR: refusing to remove an attempt outside the work directory." >&2
      exit 1
    fi
    rm -rf -- "$resolved_attempt"
  fi
done
