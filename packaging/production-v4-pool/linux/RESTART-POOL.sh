#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
data_dir="${1:-$script_dir/pool-data}"
python3 "$script_dir/POOL-CONTROL.py" stop --data-dir "$data_dir"
exec "$script_dir/START-POOL.sh" "" "" "$data_dir"
