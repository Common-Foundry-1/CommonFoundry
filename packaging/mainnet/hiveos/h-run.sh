#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
. "$SCRIPT_DIR/h-manifest.conf"
mkdir -p -- "$(dirname -- "$CUSTOM_LOG_BASENAME")"
exec > >(tee -a "$CUSTOM_LOG_BASENAME.log") 2>&1
exec python3 "$SCRIPT_DIR/hive-adapter.py" run --root "$SCRIPT_DIR" \
    --config "$CUSTOM_CONFIG_FILENAME" --log-base "$CUSTOM_LOG_BASENAME"
