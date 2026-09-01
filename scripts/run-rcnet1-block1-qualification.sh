#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 MINER_EXE TEMPLATE MODEL_BANK FIXED_ARTIFACT_DIR REPLAY COMMITMENT_PROVER PROOF_PROVER WORK_DIR [MAX_NONCE]" >&2
  exit 2
}

[[ $# -eq 8 || $# -eq 9 ]] || usage

miner_exe=$1
source_template=$2
model_bank=$3
fixed_dir=$4
replay_binary=$5
commitment_binary=$6
proof_binary=$7
work_dir=$8
max_nonce=${9:-65535}
fixed_record="$fixed_dir/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
network_id=3e99d45959c19c0053d8e9fef34875b57b46a8a1ce330637daddab515bc7b92d
expected_proof_bytes=12025320

for path in "$miner_exe" "$source_template" "$model_bank" "$fixed_record" \
  "$replay_binary" "$commitment_binary" "$proof_binary"; do
  [[ "$path" = /* && -f "$path" ]] || {
    echo "required absolute file is absent: $path" >&2
    exit 1
  }
done
[[ "$fixed_dir" = /* && -d "$fixed_dir" ]] || {
  echo "fixed-artifact directory is absent: $fixed_dir" >&2
  exit 1
}
[[ "$work_dir" = /* && ! -e "$work_dir" ]] || {
  echo "work directory must be an absent absolute path: $work_dir" >&2
  exit 1
}
[[ "$max_nonce" =~ ^[0-9]+$ && "$max_nonce" -le 4294967295 ]] || {
  echo "MAX_NONCE must be an integer from 0 through 4294967295" >&2
  exit 1
}

for bank in 0 1 2; do
  for suffix in row-major.codeword tree; do
    artifact="$fixed_dir/FORGEMATRIX-V4-FIXED-BANK-$bank.$suffix"
    [[ -f "$artifact" ]] || {
      echo "required proving artifact is absent: $artifact" >&2
      exit 1
    }
  done
done

mkdir "$work_dir"
log="$work_dir/qualification.log"
gpu_samples="$work_dir/gpu-samples.csv"
input_hashes="$work_dir/INPUT-SHA256SUMS"
output_hashes="$work_dir/OUTPUT-SHA256SUMS"

printf 'timestamp_utc,index,name,uuid,driver_version,pstate,power_draw_w,power_limit_w,temperature_c,utilization_gpu_pct,memory_used_mib,memory_total_mib\n' >"$gpu_samples"
(
  while true; do
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
    sample=$(/usr/lib/wsl/lib/nvidia-smi --query-gpu=index,name,uuid,driver_version,pstate,power.draw,power.limit,temperature.gpu,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits 2>/dev/null || true)
    [[ -n "$sample" ]] && printf '%s,%s\n' "$timestamp" "$sample" >>"$gpu_samples"
    sleep 0.2
  done
) &
sampler_pid=$!
replay_pid=

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$replay_pid" ]] && kill -0 "$replay_pid" 2>/dev/null; then
    printf 'QUIT\n' >&7 2>/dev/null || true
    wait "$replay_pid" 2>/dev/null || true
  fi
  kill "$sampler_pid" 2>/dev/null || true
  wait "$sampler_pid" 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT INT TERM

exec > >(tee -a "$log") 2>&1
echo "RCNET1_QUALIFICATION_START $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
printf '%s\n' "$miner_exe" "$source_template" "$model_bank" "$fixed_record" \
  "$replay_binary" "$commitment_binary" "$proof_binary" |
  xargs -d '\n' sha256sum >"$input_hashes"
cat "$input_hashes"
"$miner_exe" network-info | tee "$work_dir/miner-network-info.json"

miner_template=$(wslpath -w "$source_template")
miner_fixed_record=$(wslpath -w "$fixed_record")

coproc REPLAY_WORKER { "$replay_binary" --server "$model_bank" 2>&1; }
replay_pid=$REPLAY_WORKER_PID
exec 7>&"${REPLAY_WORKER[1]}"
exec 8<&"${REPLAY_WORKER[0]}"

read_replay_until() {
  local expected=$1 line
  while IFS= read -r line <&8; do
    printf '%s\n' "$line"
    [[ "$line" == "$expected" ]] && return 0
  done
  echo "replay worker exited before $expected" >&2
  return 1
}

read_replay_until CMFD_V4_REPLAY_READY

winner_nonce=
winner_final=
start_nonce=0
while (( start_nonce <= max_nonce )); do
  remaining=$((max_nonce - start_nonce + 1))
  count=64
  (( remaining < count )) && count=$remaining
  batch_coefficients="$work_dir/search-$start_nonce-$count-coefficients.bin"
  batch_prefix="$work_dir/search-$start_nonce-$count"
  batch_final="$batch_prefix-final-activation.bin"
  selected_final="$work_dir/search-winner-$start_nonce-$count-final-activation.bin"
  miner_batch_coefficients=$(wslpath -w "$batch_coefficients")
  miner_batch_final=$(wslpath -w "$batch_final")
  miner_selected_final=$(wslpath -w "$selected_final")

  "$miner_exe" prepare-rcnet1-search-batch \
    --template "$miner_template" \
    --start-nonce "$start_nonce" \
    --count "$count" \
    --fixed-record "$miner_fixed_record" \
    --coefficients-output "$miner_batch_coefficients"
  printf 'RUNBATCH\t%s\t%s\t%s\n' "$count" "$batch_coefficients" "$batch_prefix" >&7
  read_replay_until CMFD_V4_REPLAY_DONE

  inspection=$("$miner_exe" inspect-rcnet1-search-batch \
    --template "$miner_template" \
    --start-nonce "$start_nonce" \
    --count "$count" \
    --final-activations "$miner_batch_final" \
    --fixed-record "$miner_fixed_record" \
    --winner-final-output "$miner_selected_final")
  printf '%s\n' "$inspection"
  if grep -Eq '^CMFD_V4_SEARCH_BATCH qualified=true .* nonce=[0-9]+ ' <<<"$inspection"; then
    winner_nonce=$(sed -nE 's/^CMFD_V4_SEARCH_BATCH qualified=true .* nonce=([0-9]+) .*/\1/p' <<<"$inspection")
    winner_final=$selected_final
    break
  fi
  start_nonce=$((start_nonce + count))
done

[[ -n "$winner_nonce" && -f "$winner_final" ]] || {
  echo "no qualifying nonce found through $max_nonce" >&2
  exit 1
}
echo "RCNET1_WINNER_NONCE $winner_nonce"

candidate_template="$work_dir/RCNET1-BLOCK1-CANDIDATE-$winner_nonce.json"
candidate_coefficients="$work_dir/RCNET1-BLOCK1-COEFFICIENTS-$winner_nonce.bin"
miner_candidate_template=$(wslpath -w "$candidate_template")
miner_candidate_coefficients=$(wslpath -w "$candidate_coefficients")
"$miner_exe" bind-rcnet1-nonce \
  --template "$miner_template" \
  --nonce "$winner_nonce" \
  --fixed-record "$miner_fixed_record" \
  --coefficients-output "$miner_candidate_coefficients" \
  --output "$miner_candidate_template"

trace_prefix="$work_dir/RCNET1-BLOCK1-TRACE-$winner_nonce"
final_activation="$trace_prefix-final-activation.bin"
printf 'RUN\tfull\t%s\t%s\n' "$candidate_coefficients" "$trace_prefix" >&7
read_replay_until CMFD_V4_REPLAY_DONE
cmp -- "$winner_final" "$final_activation"
echo 'RCNET1_SEARCH_FULL_REPLAY_MATCH EXACT'

miner_final_activation=$(wslpath -w "$final_activation")
"$miner_exe" inspect-rcnet1-work \
  --template "$miner_candidate_template" \
  --final-activation "$miner_final_activation" \
  --fixed-record "$miner_fixed_record" | tee "$work_dir/work-inspection.txt"
grep -Eq '^CMFD_V4_WORK qualified=true nonce=' "$work_dir/work-inspection.txt"

dynamic_record="$work_dir/RCNET1-BLOCK1-DYNAMIC-COMMITMENTS-$winner_nonce.json"
proof="$work_dir/RCNET1-BLOCK1-TRANSPARENT-PROOF-$winner_nonce.bin"
"$commitment_binary" "$trace_prefix" "$dynamic_record" 2>&1 |
  tee "$work_dir/dynamic-commitments.log"
"$proof_binary" --network-id "$network_id" "$model_bank" "$fixed_dir" \
  "$candidate_template" "$trace_prefix" "$dynamic_record" \
  "$final_activation" "$proof" 2>&1 | tee "$work_dir/proof.log"

[[ -f "$proof" && $(stat -c %s "$proof") -eq $expected_proof_bytes ]]
grep -Eq '^complete_cpu_verify_seconds=[0-9]+\.[0-9]+$' "$work_dir/proof.log"
grep -Fqx 'complete_mutations=REJECTED final,matrix,opening,truncation,byte' "$work_dir/proof.log"
grep -Eq '^real_complete_proof=VERIFIED bytes=12025320 ' "$work_dir/proof.log"

sha256sum "$candidate_template" "$candidate_coefficients" "$final_activation" \
  "$dynamic_record" "$proof" "$gpu_samples" "$log" >"$output_hashes"
cat "$output_hashes"
echo "RCNET1_QUALIFICATION_COMPLETE $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
