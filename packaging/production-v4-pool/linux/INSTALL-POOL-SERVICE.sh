#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
data_dir="$(readlink -m "${1:-$script_dir/pool-data}")"
settings_file="$data_dir/pool-control/pool-settings.json"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit_file="$unit_dir/commonfoundry-production-v4-pool.service"

if ! command -v systemctl >/dev/null 2>&1; then
  echo "ERROR: systemd user services are unavailable." >&2
  exit 1
fi
if [ ! -f "$settings_file" ]; then
  echo "ERROR: run START-POOL.sh successfully once before installing the service." >&2
  exit 1
fi
mkdir -p "$unit_dir"
python3 - "$unit_file" "$script_dir" "$data_dir" <<'PY'
import json
import os
import sys

target, bundle, data = sys.argv[1:]

def quote(value: str) -> str:
    return json.dumps(value.replace("%", "%%"), ensure_ascii=True)

content = "\n".join(
    [
        "[Unit]",
        "Description=Common Foundry ProductionV4 Pool",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"WorkingDirectory={quote(bundle)}",
        f"ExecStart={quote(os.path.join(bundle, 'START-POOL.sh'))} \"\" \"\" {quote(data)}",
        f"ExecStop={quote(sys.executable)} {quote(os.path.join(bundle, 'POOL-CONTROL.py'))} stop --data-dir {quote(data)}",
        "Restart=on-failure",
        "RestartSec=10",
        "TimeoutStopSec=190",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ]
)
temporary = f"{target}.{os.getpid()}.tmp"
with open(temporary, "x", encoding="utf-8", newline="\n") as output:
    output.write(content)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, target)
PY
systemctl --user daemon-reload
systemctl --user enable --now commonfoundry-production-v4-pool.service
echo "Pool service installed and started for user $USER."
echo "For boot-before-login operation, an administrator may run: loginctl enable-linger $USER"
