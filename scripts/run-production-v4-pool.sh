#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -gt 3 ]; then
  echo "Usage: $0 [PUBLIC_NUMERIC_IP] [PRIVATE_BIND_IP] [DATA_DIR]" >&2
  exit 2
fi

for command_name in awk curl ldd nvidia-smi python3 readlink sha256sum; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: $command_name is required." >&2
    exit 1
  fi
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle_dir="${CMFD_POOL_BUNDLE_DIR:-$script_dir}"
public_host="${1:-${CMFD_POOL_PUBLIC_IP:-}}"
private_bind_ip="${2:-${CMFD_POOL_PRIVATE_IP:-}}"
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
data_dir="$(readlink -m "${3:-$bundle_dir/pool-data}")"
scratch_dir="$(readlink -m "${CMFD_POOL_SCRATCH:-$bundle_dir/pool-scratch}")"
tls_dir="$(readlink -m "${CMFD_POOL_TLS_DIR:-$bundle_dir/pool-tls}")"
node="${CMFD_POOL_NODE:-$bundle_dir/cmfd-node}"
replay_worker="${CMFD_POOL_REPLAY_WORKER:-$bundle_dir/cmfd-v4-replay}"
proof_worker="${CMFD_POOL_PROOF_WORKER:-$bundle_dir/real_bank0_relations}"
dashboard_assets="${CMFD_POOL_DASHBOARD_ASSETS:-$bundle_dir/dashboard}"
pool_port="${CMFD_POOL_PORT:-22445}"
p2p_bind="${CMFD_POOL_P2P_BIND:-0.0.0.0:22444}"
dashboard_bind="${CMFD_POOL_DASHBOARD_BIND:-127.0.0.1:22446}"
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
if [ -n "${CMFD_POOL_PEER:-}" ]; then
  peer_args+=(--peer "$CMFD_POOL_PEER")
fi
if [ "${CMFD_POOL_ALLOW_PUBLIC_PEERS:-0}" = "1" ]; then
  peer_args+=(--allow-public-peers)
fi

echo "Pool URL: $public_url"
echo "Dashboard: http://$dashboard_bind/"
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
  --share-leading-zero-bits "${CMFD_POOL_SHARE_BITS:-7}" \
  --production-v4-pool-replay-worker "$replay_worker" \
  --production-v4-pool-proof-worker "$proof_worker" \
  --production-v4-pool-scratch "$scratch_dir" \
  --enable-testnet-payouts \
  --pool-minimum-payout-atoms "${CMFD_POOL_MINIMUM_PAYOUT_ATOMS:-100}" \
  --pool-payout-fee-atoms "${CMFD_POOL_PAYOUT_FEE_ATOMS:-1}" \
  --pool-dashboard-assets "$dashboard_assets" \
  --pool-public-url "$public_url" \
  --pool-dashboard-bind "$dashboard_bind" \
  --allow-public-pool-clients
