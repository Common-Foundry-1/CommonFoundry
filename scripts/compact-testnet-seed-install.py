#!/usr/bin/env python3
"""Install only the CPU seed inside the dedicated compact-testnet guest."""
import hashlib
import json
from pathlib import Path
import pwd
import subprocess
import sys

bundle = Path(sys.argv[1]).resolve()
assert Path("/etc/hostname").read_text().strip() == "cmfd-compact-testnet"
manifest = json.loads((bundle / "SEED-MANIFEST.json").read_text())
for name, expected in manifest.items():
    path = bundle / name
    assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected, name

def run(*args):
    subprocess.run(args, check=True)

run("systemctl", "disable", "--now", "ssh.service", "ssh.socket")
try:
    pwd.getpwnam("cmfd-testnet")
except KeyError:
    run("useradd", "--system", "--home", "/var/lib/cmfd-compact-testnet", "--shell", "/usr/sbin/nologin", "cmfd-testnet")
data = Path("/var/lib/cmfd-compact-testnet")
data.mkdir(mode=0o700, exist_ok=True)
run("chown", "cmfd-testnet:cmfd-testnet", str(data))
inputs = data / "inputs"
run("runuser", "-u", "cmfd-testnet", "--", "python3", str(bundle / "production-v4-inputs.py"),
    "--chunk-manifest", str(bundle / "V4-INPUT-CHUNKS.json"),
    "--input-manifest", str(bundle / "production-v4-rcnet-1-inputs.json"),
    "--fixed-record", str(bundle / "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"),
    "--destination", str(inputs), "--role", "node", "--download-concurrency", "4",
    "--release-base", "https://downloads.commonfoundry.ai/v0.1.0-rc.1",
    "--fallback-release-base", "https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-rc.1")
unit = f"""[Unit]
Description=Common Foundry compact proof public testnet seed
After=network-online.target
Wants=network-online.target

[Service]
User=cmfd-testnet
Group=cmfd-testnet
ExecStart={bundle}/cmfd-node --data-dir {data}/chain --production-v4-bank {inputs}/MODEL-V2.bank --production-v4-fixed-record {inputs}/fixed/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json -vv run --bind 127.0.0.1:23443 --p2p-bind 0.0.0.0:23444 --no-default-seeds --allow-public-peers --work-bank resident --work-threads 2 --prune-keep-blocks 2880
Restart=on-failure
RestartSec=5
TimeoutStopSec=90
MemoryMax=10G
CPUQuota=200%
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={data}
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
Path("/etc/systemd/system/cmfd-compact-testnet-seed.service").write_text(unit)
run("systemctl", "daemon-reload")
run("systemctl", "enable", "--now", "cmfd-compact-testnet-seed.service")
print("Dedicated compact testnet seed started", flush=True)
