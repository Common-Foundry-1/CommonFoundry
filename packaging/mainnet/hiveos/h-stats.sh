#!/usr/bin/env bash
# The agent sources this callback and consumes khs and stats.
_cmfd_hive_stats() (
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
    . "$script_dir/h-manifest.conf"
    python3 "$script_dir/hive-adapter.py" stats --root "$script_dir" \
        --config "$CUSTOM_CONFIG_FILENAME" --log-base "$CUSTOM_LOG_BASENAME"
)
_cmfd_hive_report="$(_cmfd_hive_stats 2>/dev/null)" || _cmfd_hive_report='{"khs":0,"stats":null}'
khs="$(printf '%s' "$_cmfd_hive_report" | jq -r '.khs // 0')"
stats="$(printf '%s' "$_cmfd_hive_report" | jq -c '.stats // null')"
unset _cmfd_hive_report
