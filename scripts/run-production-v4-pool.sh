#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -gt 3 ]; then
  echo "Usage: $0 [PUBLIC_NUMERIC_IP] [PRIVATE_BIND_IP] [DATA_DIR]" >&2
  exit 2
fi

for command_name in awk curl ldd nvidia-smi python3 readlink sha256sum tee; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: $command_name is required." >&2
    exit 1
  fi
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle_dir="${CMFD_POOL_BUNDLE_DIR:-$script_dir}"
data_dir="$(readlink -m "${3:-$bundle_dir/pool-data}")"
control_dir="$data_dir/pool-control"
settings_file="$control_dir/pool-settings.json"
state_file="$control_dir/pool-state.json"
shutdown_request_file="$control_dir/shutdown.request"
log_dir="$data_dir/logs"
control_script="$bundle_dir/POOL-CONTROL.py"
mkdir -p "$data_dir" "$control_dir" "$log_dir"
chmod 700 "$data_dir" "$control_dir" "$log_dir"

if [ ! -f "$control_script" ]; then
  echo "Required file is missing: $control_script" >&2
  exit 1
fi
set +e
python3 "$control_script" status --data-dir "$data_dir" >/dev/null 2>&1
control_status=$?
set -e
case "$control_status" in
  0)
    echo "ERROR: a pool instance is already running for $data_dir." >&2
    exit 1
    ;;
  3) ;;
  *)
    echo "ERROR: pool control state could not be validated under $control_dir." >&2
    exit 1
    ;;
esac

saved=()
if [ -f "$settings_file" ] && [ "${CMFD_POOL_IGNORE_SAVED_SETTINGS:-0}" != "1" ]; then
  if ! python3 - "$settings_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    settings = json.load(source)
if settings.get("schema") != "CommonFoundry/ProductionV4/PoolSettings/v1":
    raise SystemExit("unsupported pool settings schema")
PY
  then
    echo "ERROR: saved pool settings could not be validated: $settings_file" >&2
    exit 1
  fi
  while IFS= read -r -d '' value; do
    saved+=("$value")
  done < <(python3 - "$settings_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    settings = json.load(source)
if settings.get("schema") != "CommonFoundry/ProductionV4/PoolSettings/v1":
    raise SystemExit("unsupported pool settings schema")
for name in (
    "public_numeric_address",
    "private_bind_address",
    "pool_port",
    "p2p_bind",
    "dashboard_bind",
    "share_leading_zero_bits",
    "minimum_payout_atoms",
    "payout_fee_atoms",
    "operator_fee_bps",
    "pplns_window_shares",
    "peer",
    "allow_public_peers",
):
    print(settings.get(name, ""), end="\0")
PY
  )
fi
public_host="${1:-${CMFD_POOL_PUBLIC_IP:-${saved[0]:-}}}"
private_bind_ip="${2:-${CMFD_POOL_PRIVATE_IP:-${saved[1]:-}}}"
if [ -z "$public_host" ]; then
  read -r -p "Public numeric IP address miners will use: " public_host
fi
if [ -z "$private_bind_ip" ]; then
  read -r -p "Private LAN IP address of this pool host: " private_bind_ip
fi
if ! python3 - "$public_host" "$private_bind_ip" <<'PY'
import ipaddress
import sys

for value in sys.argv[1:]:
    ipaddress.ip_address(value)
PY
then
  echo "ERROR: public and private addresses must be numeric IPv4 or IPv6 addresses." >&2
  exit 1
fi
public_url_host="$public_host"
private_bind_host="$private_bind_ip"
if [[ "$public_host" == *:* ]]; then
  public_url_host="[$public_host]"
fi
if [[ "$private_bind_ip" == *:* ]]; then
  private_bind_host="[$private_bind_ip]"
fi
scratch_dir="$(readlink -m "${CMFD_POOL_SCRATCH:-$bundle_dir/pool-scratch}")"
tls_dir="$(readlink -m "${CMFD_POOL_TLS_DIR:-$bundle_dir/pool-tls}")"
node="${CMFD_POOL_NODE:-$bundle_dir/cmfd-node}"
replay_worker="${CMFD_POOL_REPLAY_WORKER:-$bundle_dir/cmfd-v4-replay}"
proof_worker="${CMFD_POOL_PROOF_WORKER:-$bundle_dir/real_bank0_relations}"
dashboard_assets="${CMFD_POOL_DASHBOARD_ASSETS:-$bundle_dir/dashboard}"
pool_port="${CMFD_POOL_PORT:-${saved[2]:-19445}}"
p2p_bind="${CMFD_POOL_P2P_BIND:-${saved[3]:-0.0.0.0:19444}}"
dashboard_bind="${CMFD_POOL_DASHBOARD_BIND:-${saved[4]:-127.0.0.1:19446}}"
share_bits="${CMFD_POOL_SHARE_BITS:-${saved[5]:-7}}"
minimum_payout_atoms="${CMFD_POOL_MINIMUM_PAYOUT_ATOMS:-${saved[6]:-100}}"
payout_fee_atoms="${CMFD_POOL_PAYOUT_FEE_ATOMS:-${saved[7]:-10000000}}"
operator_fee_bps="${CMFD_POOL_OPERATOR_FEE_BPS:-${saved[8]:-300}}"
pplns_window_shares="${CMFD_POOL_PPLNS_WINDOW_SHARES:-${saved[9]:-0}}"
pool_peer="${CMFD_POOL_PEER:-${saved[10]:-}}"
allow_public_peers="${CMFD_POOL_ALLOW_PUBLIC_PEERS:-${saved[11]:-0}}"
certificate="$tls_dir/pool-cert.der"
private_key="$tls_dir/pool-key.der"
prepare_inputs="$bundle_dir/PREPARE-V4-INPUTS.sh"
model_bank="$bundle_dir/inputs/MODEL-V2.bank"
fixed_record="$bundle_dir/inputs/fixed/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"

if ! nvidia-smi -L >/dev/null 2>&1; then
  echo "ERROR: an NVIDIA GPU and working driver are required." >&2
  exit 1
fi
for cuda_root in "${CUDA_HOME:-}" /usr/local/cuda-12.8 /usr/local/cuda-12 /usr/local/cuda; do
  if [ -n "$cuda_root" ] && [ -f "$cuda_root/lib64/libcudart.so.12" ]; then
    export LD_LIBRARY_PATH="$cuda_root/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    break
  fi
done

for file in "$node" "$replay_worker" "$proof_worker" "$prepare_inputs"; do
  if [ ! -f "$file" ]; then
    echo "Required file is missing: $file" >&2
    exit 1
  fi
done
if ldd "$proof_worker" | grep -q 'not found'; then
  echo "ERROR: the CUDA 12 runtime required by $proof_worker is unavailable." >&2
  exit 1
fi
if [ ! -f "$dashboard_assets/index.html" ]; then
  echo "Built dashboard is missing: $dashboard_assets/index.html" >&2
  exit 1
fi
if [ "$private_bind_ip" = "0.0.0.0" ] || [ "$private_bind_ip" = "::" ]; then
  echo "PRIVATE_BIND_IP must be the host's private LAN address, not a wildcard." >&2
  exit 1
fi
if [[ ! "$operator_fee_bps" =~ ^[0-9]+$ ]] || (( operator_fee_bps > 10000 )); then
  echo "CMFD_POOL_OPERATOR_FEE_BPS must be an integer from 0 through 10000." >&2
  exit 1
fi
if [[ ! "$pplns_window_shares" =~ ^[0-9]+$ ]] || (( pplns_window_shares > 65536 )); then
  echo "CMFD_POOL_PPLNS_WINDOW_SHARES must be 0 (automatic) or an integer through 65536." >&2
  exit 1
fi
echo "Preparing authenticated ProductionV4 pool inputs. The first run downloads about 61 GB."
"$prepare_inputs"
for file in "$model_bank" "$fixed_record"; do
  if [ ! -f "$file" ]; then
    echo "Required input is missing after preparation: $file" >&2
    exit 1
  fi
done

mkdir -p "$data_dir" "$scratch_dir" "$tls_dir"
chmod 700 "$data_dir" "$scratch_dir" "$tls_dir"
if { [ -f "$certificate" ] && [ ! -f "$private_key" ]; } ||
  { [ ! -f "$certificate" ] && [ -f "$private_key" ]; }; then
  echo "ERROR: the pool TLS certificate and private key must both exist or both be absent." >&2
  exit 1
fi
if [ ! -f "$certificate" ]; then
  "$node" \
    --production-v4-bank "$model_bank" \
    --production-v4-fixed-record "$fixed_record" \
    pool-certificate \
    --certificate "$certificate" \
    --private-key "$private_key"
fi
chmod 600 "$private_key"

certificate_pin="$(sha256sum "$certificate" | awk '{print $1}')"
public_url="cmfd+tls://${public_url_host}:${pool_port}?pin=${certificate_pin}"
peer_args=()
if [ -n "$pool_peer" ]; then
  peer_args+=(--peer "$pool_peer")
fi
if [ "$allow_public_peers" = "1" ]; then
  peer_args+=(--allow-public-peers)
fi

python3 - "$settings_file" \
  "$public_host" "$private_bind_ip" "$pool_port" "$p2p_bind" "$dashboard_bind" \
  "$share_bits" "$minimum_payout_atoms" "$payout_fee_atoms" "$operator_fee_bps" \
  "$pplns_window_shares" "$pool_peer" "$allow_public_peers" <<'PY'
import json
import os
import sys

target = sys.argv[1]
values = sys.argv[2:]
names = (
    "public_numeric_address",
    "private_bind_address",
    "pool_port",
    "p2p_bind",
    "dashboard_bind",
    "share_leading_zero_bits",
    "minimum_payout_atoms",
    "payout_fee_atoms",
    "operator_fee_bps",
    "pplns_window_shares",
    "peer",
    "allow_public_peers",
)
settings = {"schema": "CommonFoundry/ProductionV4/PoolSettings/v1"}
settings.update(zip(names, values))
temporary = f"{target}.{os.getpid()}.tmp"
with open(temporary, "x", encoding="utf-8", newline="\n") as output:
    json.dump(settings, output, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, target)
PY

log_file="$log_dir/pool-$(date -u +%Y%m%d-%H%M%S).log"
python3 - "$state_file" "$$" "$dashboard_bind" "$log_file" <<'PY'
import json
import os
import sys

target, pid_text, dashboard_bind, log_file = sys.argv[1:]
pid = int(pid_text)
stat = open(f"/proc/{pid}/stat", encoding="ascii").read()
start_ticks = int(stat.rsplit(") ", 1)[1].split()[19])
state = {
    "schema": "CommonFoundry/ProductionV4/PoolProcess/v1",
    "pid": pid,
    "process_start_ticks": start_ticks,
    "dashboard_url": f"http://{dashboard_bind}/",
    "log_file": log_file,
}
temporary = f"{target}.{pid}.tmp"
with open(temporary, "x", encoding="utf-8", newline="\n") as output:
    json.dump(state, output, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, target)
PY

exec > >(tee -a "$log_file") 2>&1

echo "Pool URL: $public_url"
echo "Dashboard: http://$dashboard_bind/"
if [ "$pplns_window_shares" = "0" ]; then
  echo "PPLNS: ${operator_fee_bps} basis-point operator fee; automatic one-block share window"
else
  echo "PPLNS: ${operator_fee_bps} basis-point operator fee; ${pplns_window_shares}-share window"
fi
echo "Log: $log_file"
exec "$node" \
  --data-dir "$data_dir" \
  --production-v4-bank "$model_bank" \
  --production-v4-fixed-record "$fixed_record" \
  pool-serve \
  --bind "${private_bind_host}:${pool_port}" \
  --p2p-bind "$p2p_bind" \
  "${peer_args[@]}" \
  --certificate "$certificate" \
  --private-key "$private_key" \
  --share-leading-zero-bits "$share_bits" \
  --production-v4-pool-replay-worker "$replay_worker" \
  --production-v4-pool-proof-worker "$proof_worker" \
  --production-v4-pool-scratch "$scratch_dir" \
  --enable-testnet-payouts \
  --pool-minimum-payout-atoms "$minimum_payout_atoms" \
  --pool-payout-fee-atoms "$payout_fee_atoms" \
  --pool-operator-fee-bps "$operator_fee_bps" \
  --pool-pplns-window-shares "$pplns_window_shares" \
  --pool-dashboard-assets "$dashboard_assets" \
  --pool-public-url "$public_url" \
  --pool-dashboard-bind "$dashboard_bind" \
  --shutdown-request-file "$shutdown_request_file" \
  --allow-public-pool-clients \
  --allow-address-only-payouts
