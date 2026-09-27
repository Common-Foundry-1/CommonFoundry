#!/usr/bin/env bash
# Hive sources this file; keep options and directory changes out of its caller.
_cmfd_hive_config() (
    set -euo pipefail
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    . "$script_dir/h-manifest.conf"
    CMFD_HIVE_TEMPLATE="${CUSTOM_TEMPLATE:-${CUSTOM_WALLET:-}}" \
    CMFD_HIVE_URL="${CUSTOM_URL:-}" \
    CMFD_HIVE_WORKER="${WORKER_NAME:-$(hostname -s)}" \
    CMFD_HIVE_OPTIONS="${CUSTOM_USER_CONFIG:-}" \
        python3 "$script_dir/hive-adapter.py" configure --root "$script_dir" \
        --config "$CUSTOM_CONFIG_FILENAME" --log-base "$CUSTOM_LOG_BASENAME"
)
_cmfd_hive_config "$@"
