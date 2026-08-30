#!/usr/bin/env bash
set -euo pipefail

unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit_file="$unit_dir/commonfoundry-production-v4-pool.service"
systemctl --user disable --now commonfoundry-production-v4-pool.service 2>/dev/null || true
rm -f -- "$unit_file"
systemctl --user daemon-reload
echo "Common Foundry pool user service removed. Pool data was preserved."
