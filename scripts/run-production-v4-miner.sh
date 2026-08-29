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
INPUTS_PREPARED=0
sampler_pid=""

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
    --inputs-prepared) INPUTS_PREPARED=1; shift ;;
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

input_validation=(
  --chunk-manifest "$SCRIPT_DIR/V4-INPUT-CHUNKS.json"
  --input-manifest "$INPUT_MANIFEST"
  --fixed-record "$SCRIPT_DIR/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
  --destination "$SCRIPT_DIR/inputs"
  --release-base "https://downloads.commonfoundry.ai/v0.1.0-devnet.16"
  --fallback-release-base "https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.16"
  --validate-only
)
if ((INPUTS_PREPARED != 0)); then
  input_validation+=(--prepared-inputs)
fi
python3 "$SCRIPT_DIR/production-v4-inputs.py" "${input_validation[@]}"

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

start_gpu_sampler() {
  local output_path="$1"
  (
    while :; do
      nvidia-smi --id="$CUDA_DEVICE" \
        --query-gpu=power.draw,temperature.gpu \
        --format=csv,noheader,nounits >>"$output_path" 2>/dev/null || true
      sleep 2
    done
  ) &
  sampler_pid=$!
}

stop_gpu_sampler() {
  if [[ -n "$sampler_pid" ]]; then
    kill "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true
    sampler_pid=""
  fi
}

attempt_failure() {
  local message="$1"
  stop_gpu_sampler
  echo "MINER ERROR | $message | log $attempt_log" >&2
  tail -n 40 -- "$attempt_log" >&2 || true
  exit 1
}

run_logged() {
  local label="$1"
  shift
  printf '\n=== %s ===\n' "$label" >>"$attempt_log"
  if ! "$@" >>"$attempt_log" 2>&1; then
    attempt_failure "$label failed"
  fi
}

write_stats() {
  local average_power="$1"
  local maximum_temperature="$2"
  local elapsed_seconds="$3"
  local efficiency="N/A"
  if [[ "$session_energy_kwh" != "0" && "$session_energy_kwh" != "0.000000000" ]]; then
    efficiency="$(awk -v accepted="$accepted" -v energy="$session_energy_kwh" 'BEGIN { printf "%.2f", accepted / energy }')"
  fi
  printf 'MINER STATS | accepted %d | rejected %d | avg %s W | efficiency %s accepted/kWh | temp %s C | last %s s\n' \
    "$accepted" "$rejected" "$average_power" "$efficiency" "$maximum_temperature" "$elapsed_seconds"
}

trap stop_gpu_sampler EXIT
trap 'stop_gpu_sampler; exit 130' INT
trap 'stop_gpu_sampler; exit 143' TERM
accepted=0
rejected=0
attempts=0
session_energy_kwh="0"
log_directory="$WORK_DIRECTORY/logs"
mkdir -p -- "$log_directory"
write_stats "N/A" "N/A" "N/A"
while ((BLOCKS == 0 || accepted < BLOCKS)); do
  attempts=$((attempts + 1))
  attempt_name="attempt-$(printf '%08d' "$attempts")-$(date -u +%Y%m%dT%H%M%S%NZ)"
  attempt_directory="$WORK_DIRECTORY/$attempt_name"
  if [[ -e "$attempt_directory" ]]; then
    echo "ERROR: attempt directory already exists: $attempt_directory" >&2
    exit 1
  fi
  mkdir -- "$attempt_directory"
  attempt_log="$log_directory/$attempt_name.log"
  gpu_samples="$attempt_directory/gpu-samples.csv"
  : >"$attempt_log"
  : >"$gpu_samples"

  template="$attempt_directory/template.json"
  coefficients="$attempt_directory/replay-coefficients.bin"
  trace_prefix="$attempt_directory/trace"
  dynamic_commitments="$attempt_directory/dynamic-commitments.json"
  final_activation="$trace_prefix-final-activation.bin"
  proof="$attempt_directory/transparent-proof.bin"

  start_ns="$(date +%s%N)"
  start_gpu_sampler "$gpu_samples"

  run_logged "ProductionV4 template snapshot" "$CMFD_MINER" snapshot-v4-template \
    --peer "$PEER" --allow-public-peers --miner "$MINER" --nonce "$NONCE" \
    --fixed-record "$FIXED_RECORD" --coefficients-output "$coefficients" --output "$template"
  run_logged "ProductionV4 replay" "$REPLAY_BINARY" "$MODEL_BANK" "$coefficients" "$trace_prefix"
  run_logged "ProductionV4 dynamic commitments" "$DYNAMIC_BINARY" "$trace_prefix" "$dynamic_commitments"
  run_logged "ProductionV4 proof" "$PROOF_BINARY" "$MODEL_BANK" "$FIXED_DIRECTORY" "$template" "$trace_prefix" \
    "$dynamic_commitments" "$final_activation" "$proof"

  printf '\n=== ProductionV4 block submission ===\n' >>"$attempt_log"
  if "$CMFD_MINER" submit-v4-template \
      --peer "$PEER" --allow-public-peers --template "$template" \
      --transparent-proof "$proof" --fixed-record "$FIXED_RECORD" >>"$attempt_log" 2>&1; then
    accepted=$((accepted + 1))
    outcome="accepted"
  elif grep -Fq -e 'ProductionV4 block was rejected by the node' \
      -e 'frozen ProductionV4 template is stale' "$attempt_log"; then
    rejected=$((rejected + 1))
    outcome="rejected"
  else
    attempt_failure "ProductionV4 block submission failed"
  fi

  stop_gpu_sampler
  end_ns="$(date +%s%N)"
  elapsed_seconds="$(awk -v start="$start_ns" -v end="$end_ns" 'BEGIN { printf "%.1f", (end - start) / 1000000000 }')"
  read -r average_power maximum_temperature sample_count < <(
    awk -F, '
      {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
        if ($1 ~ /^[0-9]+([.][0-9]+)?$/ && $2 ~ /^[0-9]+([.][0-9]+)?$/) {
          power += $1
          if (count == 0 || $2 > maximum) maximum = $2
          count++
        }
      }
      END {
        if (count == 0) print "N/A N/A 0"
        else printf "%.1f %.0f %d\n", power / count, maximum, count
      }
    ' "$gpu_samples"
  )
  if ((sample_count > 0)); then
    session_energy_kwh="$(awk -v energy="$session_energy_kwh" -v power="$average_power" -v seconds="$elapsed_seconds" \
      'BEGIN { printf "%.9f", energy + power * seconds / 3600000 }')"
  fi
  write_stats "$average_power" "$maximum_temperature" "$elapsed_seconds"

  if [[ "$outcome" == "rejected" ]] || ((KEEP_ACCEPTED_WORK == 0)); then
    resolved_attempt="$(realpath -- "$attempt_directory")"
    resolved_parent="$(dirname -- "$resolved_attempt")"
    if [[ "$resolved_parent" != "$(realpath -- "$WORK_DIRECTORY")" ]]; then
      echo "ERROR: refusing to remove an attempt outside the work directory." >&2
      exit 1
    fi
    rm -rf -- "$resolved_attempt"
  fi
done
