#!/usr/bin/env python3
"""Reference operator launcher for the compact-proof public testnet."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
USER_DATA = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "commonfoundry-compact-testnet1"
SEED = "209.145.48.36:23444"
NETWORK = "8a34c0d9eaa92c5eaec4af7fe146afdfa2ab6859918b7deb0c97e0a1f600d6d1"
RECORD = "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(root=ROOT, worker=False):
    manifest = json.loads((root / "PACKAGE-MANIFEST.json").read_text())
    if manifest["network_id"] != NETWORK:
        raise ValueError("package network identity differs from this launcher")
    for name, expected in manifest["files"].items():
        path = root / name
        if Path(name).is_absolute() or ".." in Path(name).parts or path.is_symlink():
            raise ValueError("unsafe package entry")
        if not path.is_file() or path.stat().st_size != expected["bytes"] or sha256(path) != expected["sha256"]:
            raise ValueError(f"package checksum mismatch: {name}")
    if worker:
        info = json.loads(subprocess.check_output([str(root / "cmfd-direct-prover"), "network-info"]))
        if info["network_id"] != NETWORK or info["proof_version"] != 2:
            raise ValueError("proof worker has the wrong network identity")
    print("Compact Proof Testnet-1 package verified.", file=sys.stderr, flush=True)
    return manifest


def prepare(inputs, role):
    download_role = {"pool": "miner", "miner": "pool-miner", "node": "node"}[role]
    command = [sys.executable, str(ROOT / "production-v4-inputs.py"),
        "--chunk-manifest", str(ROOT / "V4-INPUT-CHUNKS.json"),
        "--input-manifest", str(ROOT / "production-v4-rcnet-1-inputs.json"),
        "--fixed-record", str(ROOT / RECORD), "--destination", str(inputs),
        "--role", download_role, "--download-concurrency", "4",
        "--release-base", "https://downloads.commonfoundry.ai/v0.1.0-rc.1",
        "--fallback-release-base", "https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-rc.1"]
    subprocess.run(command, check=True)


def common(inputs, data):
    return [str(ROOT / "cmfd-node"), "--data-dir", str(data),
        "--production-v4-bank", str(inputs / "MODEL-V2.bank"),
        "--production-v4-fixed-record", str(inputs / "fixed" / RECORD), "-vv"]


def peers(values):
    result = ["--no-default-seeds", "--allow-public-peers"]
    for peer in values or [SEED]:
        result += ["--peer", peer]
    return result


def build_command(args, inputs, data):
    if args.action == "node":
        return common(inputs, data) + ["run", "--bind", args.rpc_bind,
            "--p2p-bind", args.p2p_bind, "--work-bank", args.work_bank] + peers(args.peer)
    if args.action == "miner":
        command = [str(ROOT / "cmfd-miner"), "pool", "--pool", args.pool,
            "--miner", args.address, "--worker", args.worker,
            "--production-v4-bank", str(inputs / "MODEL-V2.bank"),
            "--production-v4-replay-worker", str(ROOT / "cmfd-v4-replay"),
            "--production-v4-scratch", str(data / "miner-scratch")]
        if args.gpu is not None:
            command += ["--gpu", args.gpu]
        return command
    public = ipaddress.ip_address(args.public_ip)
    bind = ipaddress.ip_address(args.bind_ip)
    host = f"[{public}]" if public.version == 6 else str(public)
    local = f"[{bind}]" if bind.version == 6 else str(bind)
    tls = data / "tls"
    cert, key = tls / "pool-cert.der", tls / "pool-key.der"
    if cert.exists() != key.exists():
        raise ValueError("pool certificate and private key must both exist")
    if not cert.exists() and not args.check:
        tls.mkdir(parents=True, mode=0o700, exist_ok=True)
        subprocess.run(common(inputs, data) + ["pool-certificate", "--certificate", str(cert), "--private-key", str(key)], check=True)
        key.chmod(0o600)
    pin = sha256(cert) if cert.exists() else "CERTIFICATE_CREATED_ON_START"
    url = f"cmfd+tls://{host}:{args.pool_port}?pin={pin}"
    print(f"Miner URL: {url}", flush=True)
    command = common(inputs, data) + ["pool-serve", "--bind", f"{local}:{args.pool_port}",
        "--p2p-bind", args.p2p_bind, "--certificate", str(cert), "--private-key", str(key),
        "--share-leading-zero-bits", str(args.share_bits),
        "--production-v4-pool-replay-worker", str(ROOT / "cmfd-v4-replay"),
        "--production-v4-pool-proof-worker", str(ROOT / "cmfd-direct-prover"),
        "--production-v4-pool-scratch", str(data / "pool-scratch"),
        "--pool-operator-fee-bps", "0", "--work-bank", args.work_bank,
        "--allow-public-pool-clients", "--allow-address-only-payouts"] + peers(args.peer)
    if args.replay_gpu is not None:
        command += ["--production-v4-pool-replay-gpu", args.replay_gpu]
    if args.proof_gpu is not None:
        command += ["--production-v4-pool-proof-gpu", args.proof_gpu]
    if args.enable_payouts:
        command += ["--enable-testnet-payouts"]
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("verify")
    address = sub.add_parser("new-address")
    address.add_argument("--key", type=Path, required=True)
    diag = sub.add_parser("diagnostics")
    diag.add_argument("--rpc", default="http://127.0.0.1:23443")
    diag.add_argument("--output", type=Path, default=Path("testnet-diagnostics.json"))
    prep = sub.add_parser("prepare")
    prep.add_argument("--role", choices=("pool", "miner", "node"), default="pool")
    prep.add_argument("--inputs", type=Path, default=USER_DATA / "inputs")
    for role in ("node", "pool", "miner"):
        p = sub.add_parser(role)
        p.add_argument("--inputs", type=Path, default=USER_DATA / "inputs")
        p.add_argument("--data-dir", type=Path, default=USER_DATA / role)
        p.add_argument("--check", action="store_true", help="verify package and print the launch command")
        if role != "miner":
            p.add_argument("--peer", action="append")
            p.add_argument("--p2p-bind", default="0.0.0.0:23444")
            p.add_argument("--work-bank", choices=("resident", "streamed", "auto"), default="auto")
        if role == "node":
            p.add_argument("--rpc-bind", default="127.0.0.1:23443")
        elif role == "pool":
            p.add_argument("--public-ip", required=True)
            p.add_argument("--bind-ip", default="0.0.0.0")
            p.add_argument("--pool-port", type=int, default=23445)
            p.add_argument("--share-bits", type=int, choices=range(7), default=4)
            p.add_argument("--replay-gpu")
            p.add_argument("--proof-gpu")
            p.add_argument("--enable-payouts", action="store_true")
        else:
            p.add_argument("--pool", required=True)
            p.add_argument("--address", required=True)
            p.add_argument("--worker", default="testnet")
            p.add_argument("--gpu")
    args = parser.parse_args()
    os.environ["LD_LIBRARY_PATH"] = str(ROOT / "lib") + (
        ":" + os.environ["LD_LIBRARY_PATH"] if os.environ.get("LD_LIBRARY_PATH") else "")
    for cuda in (os.environ.get("CUDA_HOME", ""), "/usr/local/cuda-12.9", "/usr/local/cuda-12.8", "/usr/local/cuda-12", "/usr/local/cuda"):
        if cuda and (Path(cuda) / "lib64/libcudart.so.12").is_file():
            os.environ["LD_LIBRARY_PATH"] += ":" + str(Path(cuda) / "lib64")
            break
    verify(worker=args.action in ("pool", "miner"))
    if args.action == "verify":
        return
    if args.action == "new-address":
        subprocess.run([str(ROOT / "cmfd-node"), "exchange-key-new", "--output", str(args.key.resolve())], check=True)
        return
    if args.action == "diagnostics":
        data = {"schema": "CMFD_COMPACT_TESTNET_DIAGNOSTICS_V1", "network_id": NETWORK,
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "build": json.loads((ROOT / "BUILD-INFO.json").read_text())}
        try:
            with urllib.request.urlopen(args.rpc.rstrip("/") + "/v1/status", timeout=10) as response:
                data["status"] = json.load(response)
        except OSError as error:
            data["status_error"] = str(error)
        try:
            data["gpu"] = subprocess.check_output(["nvidia-smi", "--query-gpu=name,uuid,memory.total,memory.used,utilization.gpu", "--format=csv,noheader"], text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass
        with args.output.open("x") as output:
            json.dump(data, output, indent=2)
        print(f"Diagnostics saved to {args.output}")
        return
    inputs = args.inputs.expanduser().resolve()
    if args.action == "prepare":
        prepare(inputs, args.role)
        return
    data = args.data_dir.expanduser().resolve()
    if not args.check:
        data.mkdir(parents=True, mode=0o700, exist_ok=True)
        prepare(inputs, args.action)
    command = build_command(args, inputs, data)
    if args.check:
        print(json.dumps(command, indent=2))
        return
    for name in ("pool-scratch", "miner-scratch"):
        (data / name).mkdir(mode=0o700, exist_ok=True)
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(ROOT / "lib") + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    os.execve(command[0], command, env)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
