#!/usr/bin/env bash
set -euo pipefail

api="https://wallet.commonfoundry.ai"
network_id="88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62"
destination="79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

curl_args=(--silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 20)
curl "${curl_args[@]}" --fail-with-body "$api/v1/explorer" -o "$scratch/explorer.json"
curl "${curl_args[@]}" --fail-with-body "$api/v1/explorer/address/$destination" -o "$scratch/address.json"

python3 - "$scratch/explorer.json" "$scratch/address.json" "$network_id" "$destination" <<'PY'
import json
import sys

explorer = json.load(open(sys.argv[1], encoding="utf-8"))
address = json.load(open(sys.argv[2], encoding="utf-8"))
assert explorer["network"] == "CommonFoundry Mainnet"
assert explorer["network_id"] == sys.argv[3]
assert len(explorer["tip"]) == 64
assert address["address"] == sys.argv[4]
for field in ("confirmed_atoms", "spendable_atoms", "immature_atoms"):
    assert address[field].isdigit()
print(f"mainnet ok: accepted={explorer['accepted_height']} validated={explorer.get('validated_height')}")
print(f"synthetic address ok: history={len(address.get('history', []))} utxos={address['utxo_count']}")
PY

status="$({ curl "${curl_args[@]}" -o "$scratch/utxos.json" -w '%{http_code}' \
  -H 'content-type: application/json' \
  --data "{\"address\":\"$destination\",\"cursor\":null}" \
  "$api/v1/wallet/utxos"; } || true)"
printf 'utxo endpoint HTTP %s: ' "$status"
python3 - "$scratch/utxos.json" <<'PY'
import json
import sys

try:
    body = json.load(open(sys.argv[1], encoding="utf-8"))
except (FileNotFoundError, json.JSONDecodeError):
    print("non-JSON response")
else:
    print(body.get("error", "ok"))
PY
