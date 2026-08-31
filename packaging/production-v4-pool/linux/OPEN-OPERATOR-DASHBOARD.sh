#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/POOL-OPERATOR.py" --bundle-dir "$script_dir" --open-browser "$@"
