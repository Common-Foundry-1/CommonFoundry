#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if (( $# < 2 )); then
  echo 'Usage: start-pool.sh ABSOLUTE_COPIED_DATA_DIR ABSOLUTE_PASSPHRASE_FILE [pool-serve options]' >&2
  echo 'Supply your existing certificate, private key, payout policy and dedicated GPU options.' >&2
  exit 2
fi
data=$1
passphrase=$2
shift 2
[[ "$data" == /* && -d "$data" && "$passphrase" == /* && -f "$passphrase" ]] || exit 2
export PATH="/usr/lib/wsl/lib:$PATH"
export LD_LIBRARY_PATH="$root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$root/cmfd-node" --data-dir "$data" --wallet-passphrase-file "$passphrase" \
  --production-v4-bank "${CMFD_MODEL_BANK:-$root/production-v4/MODEL-V2.bank}" \
  --production-v4-fixed-record "${CMFD_FIXED_RECORD:-$root/production-v4/fixed/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json}" \
  pool-serve --no-default-seeds --bind 127.0.0.1:39445 --p2p-bind 127.0.0.1:39454 \
  --production-v4-pool-replay-worker "$root/production-v4/cmfd-v4-replay" \
  --production-v4-pool-proof-worker "$root/production-v4/cmfd-mainnet-fork-prover" \
  --production-v4-pool-scratch "$data/fork-proof-scratch" \
  --pool-dashboard-assets "$root/dashboard" --pool-dashboard-bind 127.0.0.1:39446 "$@"
