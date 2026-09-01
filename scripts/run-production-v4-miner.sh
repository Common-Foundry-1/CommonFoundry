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
TEMPLATE_REFRESH_SECONDS=15
SEARCH_BATCH_SIZE=32
sampler_pid=""
proof_pid=""
replay_pid=""
proof_input_fd=""
proof_output_fd=""
replay_input_fd=""
replay_output_fd=""
worker_session_directory=""

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
    --template-refresh-seconds) TEMPLATE_REFRESH_SECONDS="${2:-}"; shift 2 ;;
    --search-batch-size) SEARCH_BATCH_SIZE="${2:-}"; shift 2 ;;
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
if [[ ! "$BLOCKS" =~ ^[0-9]+$ || ! "$CUDA_DEVICE" =~ ^[0-9]+$ || ! "$NONCE" =~ ^[0-9]+$ ||
      ! "$TEMPLATE_REFRESH_SECONDS" =~ ^[1-9][0-9]*$ ||
      ! "$SEARCH_BATCH_SIZE" =~ ^[1-9][0-9]*$ || "$SEARCH_BATCH_SIZE" -gt 64 ]]; then
  echo "ERROR: blocks, CUDA device, and nonce must be non-negative integers; template refresh and search batch size must be positive, with batch size at most 64." >&2
  exit 2
fi
if ((${#NONCE} > 19)) || ((${#NONCE} == 19)) && [[ "$NONCE" > "9223372036854775806" ]]; then
  echo "ERROR: --nonce must be at most 9223372036854775806 in the Linux launcher." >&2
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
NETWORK_ID="$(python3 - "$INPUT_MANIFEST" "$CMFD_MINER" <<'PY'
import json
import re
import subprocess
import sys


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


with open(sys.argv[1], "r", encoding="utf-8") as source:
    manifest = json.load(source, object_pairs_hook=unique_object)
network_id = manifest.get("network_id") if isinstance(manifest, dict) else None
if not isinstance(network_id, str) or re.fullmatch(r"[0-9a-f]{64}", network_id) is None:
    raise SystemExit(
        "input manifest network_id must contain exactly 64 lowercase hexadecimal characters"
    )

result = subprocess.run(
    [sys.argv[2], "network-info"],
    check=False,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
if result.returncode != 0:
    detail = result.stderr.decode("utf-8", errors="replace").strip()
    raise SystemExit(f"cmfd-miner network-info exited with code {result.returncode}: {detail}")
if result.stderr:
    raise SystemExit("cmfd-miner network-info wrote unexpected diagnostic output")
try:
    identity_text = result.stdout.decode("utf-8", errors="strict")
except UnicodeDecodeError as error:
    raise SystemExit("cmfd-miner network-info is not UTF-8") from error
if not identity_text.endswith("\n") or "\r" in identity_text or identity_text.count("\n") != 1:
    raise SystemExit("cmfd-miner network-info must contain exactly one canonical JSON line")
try:
    identity = json.loads(identity_text, object_pairs_hook=unique_object)
except ValueError as error:
    raise SystemExit(f"cmfd-miner network-info is not strict JSON: {error}") from error
expected_fields = [
    "format",
    "format_version",
    "network_id",
    "network_name",
    "network_profile",
    "proof_selection",
    "build_source_commit",
]
if not isinstance(identity, dict) or list(identity) != expected_fields:
    raise SystemExit("cmfd-miner network-info fields do not match the canonical schema")
if (
    identity["format"] != "commonfoundry-miner-network-info"
    or type(identity["format_version"]) is not int
    or identity["format_version"] != 1
):
    raise SystemExit("cmfd-miner network-info format is unsupported")
miner_network_id = identity["network_id"]
if not isinstance(miner_network_id, str) or re.fullmatch(r"[0-9a-f]{64}", miner_network_id) is None:
    raise SystemExit("cmfd-miner network-info network_id is not canonical lowercase hexadecimal")
if miner_network_id != network_id:
    raise SystemExit(
        f"cmfd-miner network {miner_network_id} does not match input manifest network {network_id}"
    )
for field in ("network_name", "network_profile"):
    value = identity[field]
    if not isinstance(value, str) or re.fullmatch(r"[\x20-\x7e]{1,128}", value) is None:
        raise SystemExit(f"cmfd-miner network-info {field} is not a canonical printable name")
if identity["proof_selection"] != "ProductionV4":
    raise SystemExit(
        f"cmfd-miner proof selection is {identity['proof_selection']}; ProductionV4 is required"
    )
source_commit = identity["build_source_commit"]
if source_commit is not None and (
    not isinstance(source_commit, str)
    or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_commit) is None
    or set(source_commit) == {"0"}
):
    raise SystemExit(
        "cmfd-miner build_source_commit is not canonical nonzero lowercase hexadecimal"
    )
canonical = json.dumps(identity, ensure_ascii=False, separators=(",", ":")) + "\n"
if identity_text != canonical:
    raise SystemExit("cmfd-miner network-info is not canonical JSON")
print(network_id)
PY
)"

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

read_worker_until() {
  local output_fd="$1"
  local marker="$2"
  local log_path="$3"
  local label="$4"
  local line
  while IFS= read -r -u "$output_fd" line; do
    printf '%s\n' "$line" >>"$log_path"
    if [[ "$line" == "$marker" ]]; then
      return 0
    fi
  done
  echo "ERROR: $label exited before $marker" >&2
  return 1
}

invoke_worker() {
  local input_fd="$1"
  local output_fd="$2"
  local marker="$3"
  local log_path="$4"
  local label="$5"
  shift 5
  local IFS=$'\t'
  printf '%s\n' "$*" >&"$input_fd"
  read_worker_until "$output_fd" "$marker" "$log_path" "$label"
}

stop_worker() {
  local pid="$1"
  local input_fd="$2"
  local output_fd="$3"
  if [[ -z "$pid" ]]; then
    return
  fi
  if [[ -n "$input_fd" ]] && kill -0 "$pid" 2>/dev/null; then
    printf 'QUIT\n' >&"$input_fd" 2>/dev/null || true
  fi
  if [[ -n "$input_fd" ]]; then
    exec {input_fd}>&- 2>/dev/null || true
  fi
  for _ in {1..20}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  if [[ -n "$output_fd" ]]; then
    exec {output_fd}<&- 2>/dev/null || true
  fi
}

stop_workers() {
  stop_worker "$replay_pid" "$replay_input_fd" "$replay_output_fd"
  replay_pid=""
  stop_worker "$proof_pid" "$proof_input_fd" "$proof_output_fd"
  proof_pid=""
}

cleanup() {
  stop_gpu_sampler
  stop_workers
  if [[ -n "$worker_session_directory" && -d "$worker_session_directory" ]]; then
    rm -f -- "$worker_session_directory/proof.in" "$worker_session_directory/proof.out" \
      "$worker_session_directory/replay.in" "$worker_session_directory/replay.out"
    rmdir -- "$worker_session_directory" 2>/dev/null || true
    worker_session_directory=""
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
  local hashrate="N/A"
  local compute="N/A"
  if [[ "$session_energy_kwh" != "0" && "$session_energy_kwh" != "0.000000000" ]]; then
    efficiency="$(awk -v accepted="$accepted" -v energy="$session_energy_kwh" 'BEGIN { printf "%.2f", accepted / energy }')"
  fi
  if ((session_forge_work_count > 0)) && [[ "$session_search_seconds" != "0" && "$session_search_seconds" != "0.000000000" ]]; then
    read -r hashrate compute < <(awk -v work="$session_forge_work_count" -v seconds="$session_search_seconds" \
      'BEGIN { rate = work / seconds; printf "%.2f %.2f\n", rate, rate * 0.824633720832 }')
  fi
  printf 'MINER STATS | Hashrate %s FW/s | Compute %s TMAC/s | accepted %d | rejected %d | avg %s W | efficiency %s accepted/kWh | temp %s C | last %s s\n' \
    "$hashrate" "$compute" "$accepted" "$rejected" "$average_power" "$efficiency" "$maximum_temperature" "$elapsed_seconds"
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
accepted=0
rejected=0
attempts=0
session_energy_kwh="0"
session_forge_work_count=0
session_search_seconds="0"
log_directory="$WORK_DIRECTORY/logs"
mkdir -p -- "$log_directory"
session_log="$log_directory/session-$(date -u +%Y%m%dT%H%M%S%NZ).log"
: >"$session_log"
worker_session_directory="$(mktemp -d -- "$WORK_DIRECTORY/.worker-session.XXXXXXXX")"
mkfifo -- "$worker_session_directory/proof.in" "$worker_session_directory/proof.out" \
  "$worker_session_directory/replay.in" "$worker_session_directory/replay.out"

"$PROOF_BINARY" --server "$NETWORK_ID" "$MODEL_BANK" "$FIXED_DIRECTORY" \
  <"$worker_session_directory/proof.in" >"$worker_session_directory/proof.out" 2>&1 &
proof_pid="$!"
exec {proof_input_fd}>"$worker_session_directory/proof.in"
exec {proof_output_fd}<"$worker_session_directory/proof.out"
read_worker_until "$proof_output_fd" 'CMFD_V4_PROOF_READY' "$session_log" 'ProductionV4 proof worker'

"$REPLAY_BINARY" --server "$MODEL_BANK" \
  <"$worker_session_directory/replay.in" >"$worker_session_directory/replay.out" 2>&1 &
replay_pid="$!"
exec {replay_input_fd}>"$worker_session_directory/replay.in"
exec {replay_output_fd}<"$worker_session_directory/replay.out"
read_worker_until "$replay_output_fd" 'CMFD_V4_REPLAY_READY' "$session_log" 'ProductionV4 replay worker'

keep_replay_resident=0
if ((gpu_memory >= 20000)); then
  keep_replay_resident=1
fi
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
  final_activation="$trace_prefix-final-activation.bin"
  search_final_activation="$attempt_directory/search-final-activation.bin"
  proof="$attempt_directory/transparent-proof.bin"

  start_ns="$(date +%s%N)"
  start_gpu_sampler "$gpu_samples"

  run_logged "ProductionV4 template snapshot" "$CMFD_MINER" snapshot-v4-template \
    --peer "$PEER" --allow-public-peers --miner "$MINER" --nonce "$NONCE" \
    --fixed-record "$FIXED_RECORD" --coefficients-output "$coefficients" --output "$template"
  candidate_nonce="$NONCE"
  attempt_forge_work_count=0
  search_start_ns="$(date +%s%N)"
  outcome=""
  while :; do
    remaining_nonces=$((9223372036854775806 - candidate_nonce))
    batch_count="$SEARCH_BATCH_SIZE"
    if ((remaining_nonces < batch_count - 1)); then
      batch_count=$((remaining_nonces + 1))
    fi
    batch_coefficients="$attempt_directory/search-batch-$candidate_nonce.bin"
    batch_trace_prefix="$attempt_directory/search-batch-$candidate_nonce"
    batch_final_activations="$batch_trace_prefix-final-activation.bin"
    run_logged "ProductionV4 search-batch preparation" "$CMFD_MINER" \
      prepare-v4-search-batch --template "$template" --start-nonce "$candidate_nonce" \
      --count "$batch_count" --fixed-record "$FIXED_RECORD" \
      --coefficients-output "$batch_coefficients"
    invoke_worker "$replay_input_fd" "$replay_output_fd" 'CMFD_V4_REPLAY_DONE' "$attempt_log" \
      'ProductionV4 replay worker' RUNBATCH "$batch_count" "$batch_coefficients" \
      "$batch_trace_prefix" \
      || attempt_failure "ProductionV4 search replay failed"
    if ! work_output="$("$CMFD_MINER" inspect-v4-search-batch \
        --template "$template" --start-nonce "$candidate_nonce" --count "$batch_count" \
        --final-activations "$batch_final_activations" --fixed-record "$FIXED_RECORD" \
        --winner-final-output "$search_final_activation" 2>&1)"; then
      printf '%s\n' "$work_output" >>"$attempt_log"
      attempt_failure "ProductionV4 work inspection failed"
    fi
    printf '%s\n' "$work_output" >>"$attempt_log"
    if [[ "$(grep -c '^CMFD_V4_SEARCH_BATCH ' <<<"$work_output")" -ne 1 ]]; then
      attempt_failure "ProductionV4 work inspection returned a noncanonical result"
    fi
    attempt_forge_work_count=$((attempt_forge_work_count + batch_count))
    if grep -q '^CMFD_V4_SEARCH_BATCH qualified=true ' <<<"$work_output"; then
      candidate_nonce="$(sed -nE 's/^CMFD_V4_SEARCH_BATCH .* nonce=([0-9]+) .*/\1/p' <<<"$work_output")"
      if [[ ! "$candidate_nonce" =~ ^[0-9]+$ ]]; then
        attempt_failure "ProductionV4 search-batch winner did not identify its nonce"
      fi
      candidate_template="$attempt_directory/template-$candidate_nonce.json"
      candidate_coefficients="$attempt_directory/replay-coefficients-$candidate_nonce.bin"
      run_logged "ProductionV4 winning nonce binding" "$CMFD_MINER" bind-v4-nonce \
        --template "$template" --nonce "$candidate_nonce" --fixed-record "$FIXED_RECORD" \
        --coefficients-output "$candidate_coefficients" --output "$candidate_template"
      break
    fi
    search_now_ns="$(date +%s%N)"
    if (( (search_now_ns - search_start_ns) / 1000000000 >= TEMPLATE_REFRESH_SECONDS )); then
      outcome="refresh"
      break
    fi
    if ((batch_count > 9223372036854775806 - candidate_nonce)); then
      attempt_failure "ProductionV4 nonce space exhausted"
    fi
    candidate_nonce=$((candidate_nonce + batch_count))
  done
  search_end_ns="$(date +%s%N)"
  search_elapsed_seconds="$(awk -v start="$search_start_ns" -v end="$search_end_ns" \
    'BEGIN { printf "%.9f", (end - start) / 1000000000 }')"
  session_forge_work_count=$((session_forge_work_count + attempt_forge_work_count))
  session_search_seconds="$(awk -v total="$session_search_seconds" -v elapsed="$search_elapsed_seconds" \
    'BEGIN { printf "%.9f", total + elapsed }')"
  printf 'CMFD_V4_MINER_PHASE phase=search elapsed_micros=%d\n' \
    "$(((search_end_ns - search_start_ns) / 1000))" >>"$attempt_log"

  if [[ "$outcome" != "refresh" ]]; then
    replay_start_ns="$(date +%s%N)"
    invoke_worker "$replay_input_fd" "$replay_output_fd" 'CMFD_V4_REPLAY_DONE' "$attempt_log" \
      'ProductionV4 replay worker' RUN full "$candidate_coefficients" "$trace_prefix" \
      || attempt_failure "ProductionV4 winning replay failed"
    if ! cmp -- "$search_final_activation" "$final_activation"; then
      attempt_failure "ProductionV4 search/full replay comparison failed"
    fi
    replay_end_ns="$(date +%s%N)"
    printf 'CMFD_V4_MINER_PHASE phase=winning_replay elapsed_micros=%d\n' \
      "$(((replay_end_ns - replay_start_ns) / 1000))" >>"$attempt_log"
    if ((keep_replay_resident == 0)); then
      invoke_worker "$replay_input_fd" "$replay_output_fd" 'CMFD_V4_REPLAY_EVICTED' "$attempt_log" \
        'ProductionV4 replay worker' EVICT || attempt_failure "ProductionV4 replay eviction failed"
    fi
    proof_start_ns="$(date +%s%N)"
    invoke_worker "$proof_input_fd" "$proof_output_fd" 'CMFD_V4_PROOF_DONE' "$attempt_log" \
      'ProductionV4 proof worker' RUN "$candidate_template" "$trace_prefix" "$final_activation" "$proof" \
      || attempt_failure "ProductionV4 proof failed"
    proof_end_ns="$(date +%s%N)"
    printf 'CMFD_V4_MINER_PHASE phase=proof elapsed_micros=%d\n' \
      "$(((proof_end_ns - proof_start_ns) / 1000))" >>"$attempt_log"

    printf '\n=== ProductionV4 block submission ===\n' >>"$attempt_log"
    if "$CMFD_MINER" submit-v4-template \
        --peer "$PEER" --allow-public-peers --template "$candidate_template" \
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

  if [[ "$outcome" != "accepted" ]] || ((KEEP_ACCEPTED_WORK == 0)); then
    resolved_attempt="$(realpath -- "$attempt_directory")"
    resolved_parent="$(dirname -- "$resolved_attempt")"
    if [[ "$resolved_parent" != "$(realpath -- "$WORK_DIRECTORY")" ]]; then
      echo "ERROR: refusing to remove an attempt outside the work directory." >&2
      exit 1
    fi
    rm -rf -- "$resolved_attempt"
  fi
done
