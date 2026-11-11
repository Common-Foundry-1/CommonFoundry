#!/usr/bin/env python3
"""Package an unsigned pool-miner test overlay, never a stable mainnet release."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

import release_integrity as integrity

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/compact-proof-testnet/MINER-COMPATIBILITY.md"
MANIFEST = ROOT / "docs/compact-proof-testnet/MAINNET-FORK-IDENTITY-65535.json"


def output(command: list[str], *, cwd: Path | None = None) -> bytes:
    result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=60, check=False)
    if result.returncode or result.stderr:
        raise ValueError(f"command failed: {command[0]}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def validate_reports(network: dict, compatibility: dict, commit: str, fork: dict) -> None:
    if (network.get("format") != "commonfoundry-miner-network-info"
            or network.get("format_version") != 1
            or network.get("network_id") != fork["network_id"]
            or network.get("proof_selection") != "ProductionV4"
            or network.get("build_source_commit") != commit):
        raise ValueError("miner does not report the frozen mainnet source identity")
    if (compatibility.get("format") != "commonfoundry-pool-miner-compatibility"
            or compatibility.get("format_version") != 1
            or compatibility.get("build_source_commit") != commit
            or compatibility.get("network_id") != fork["network_id"]
            or compatibility.get("accepted_consensus_fingerprints") != [
                fork["predecessor_fingerprint"], fork["consensus_fingerprint"]]
            or compatibility.get("pool_protocol_version") != 2
            or compatibility.get("compact_mainnet_activation_height") != fork["activation_height"]
            or compatibility.get("compact_mainnet_proof_system_digest") != fork["at_and_after_activation"]["proof_system_digest"]
            or compatibility.get("compact_mainnet_block_proof_generation") is not False
            or compatibility.get("activates_mainnet_fork") is not False
            or compatibility.get("scope") != "pool-nonce-search"):
        raise ValueError("miner does not report the exact pool-only compact compatibility policy")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--miner", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--platform", required=True, choices=("windows-x86_64", "linux-x86_64"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--wsl-distribution", default="Ubuntu-22.04")
    args = parser.parse_args()
    commit = args.expected_commit
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or commit == "0" * 40:
        raise ValueError("expected commit must be an exact nonzero Git SHA-1")
    if output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip() != commit:
        raise ValueError("checkout does not match the frozen source commit")
    if output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT).strip():
        raise ValueError("freeze a clean checkout before packaging")
    version = tomllib.loads((ROOT / "crates/cmfd-miner/Cargo.toml").read_text())["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-compact\.[0-9]+)?", version):
        raise ValueError("invalid pool miner version")
    miner = args.miner.resolve(strict=True)
    if not miner.is_file() or args.miner.is_symlink():
        raise ValueError("miner must be a regular file")
    windows = args.platform == "windows-x86_64"
    with miner.open("rb") as handle:
        header = handle.read(64)
        if windows:
            if header[:2] != b"MZ":
                raise ValueError("Windows candidate must be a PE executable")
            handle.seek(int.from_bytes(header[60:64], "little"))
            if handle.read(6) != b"PE\0\0\x64\x86":
                raise ValueError("Windows candidate must be x86-64")
        elif header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
            raise ValueError("Linux candidate must be a little-endian ELF x86-64 executable")
    if os.name == "nt" and not windows:
        linux_path = output(["wsl.exe", "-d", args.wsl_distribution, "--exec", "wslpath", "-u", miner.as_posix()]).decode().strip()
        executable = ["wsl.exe", "-d", args.wsl_distribution, "--exec", linux_path]
    else:
        executable = [str(miner)]
    if output([*executable, "--version"]).decode().strip() != f"cmfd-miner {version}":
        raise ValueError("binary version does not match the candidate source")
    network_bytes = output([*executable, "network-info"])
    compatibility_bytes = output([*executable, "pool-compatibility-info"])
    fork = json.loads(MANIFEST.read_bytes())
    validate_reports(json.loads(network_bytes), json.loads(compatibility_bytes), commit, fork)
    epoch = int(output(["git", "show", "-s", "--format=%ct", commit], cwd=ROOT))
    args.output.mkdir(parents=True, exist_ok=True)
    name = f"commonfoundry-compact-miner-candidate-v{version}-{args.platform}"
    stage = args.output / name
    archive = args.output / (name + (".zip" if windows else ".tar.gz"))
    if stage.exists() or archive.exists():
        raise ValueError("candidate output already exists")
    stage.mkdir()
    shutil.copyfile(miner, stage / ("cmfd-miner.exe" if windows else "cmfd-miner"))
    shutil.copyfile(GUIDE, stage / "README.md")
    shutil.copyfile(MANIFEST, stage / MANIFEST.name)
    for filename in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        shutil.copyfile(ROOT / filename, stage / filename)
    (stage / "MINER-NETWORK-INFO.json").write_bytes(network_bytes)
    (stage / "POOL-COMPATIBILITY.json").write_bytes(compatibility_bytes)
    receipt = {
        "schema": "commonfoundry-compact-miner-candidate/v1",
        "status": "unsigned-test-candidate",
        "version": version,
        "platform": args.platform,
        "source_commit": commit,
        "scope": "pool-nonce-search",
        "node_pool_fork_qualification": "pending",
        "fresh_gpu_mining_qualification": "not-run",
        "files": {
            path.name: {"bytes": path.stat().st_size, "sha256": sha256(path)}
            for path in sorted(stage.iterdir())
        },
    }
    (stage / "CANDIDATE.json").write_bytes(canonical(receipt))
    create = integrity.create_deterministic_zip if windows else integrity.create_deterministic_tar_gz
    create(stage, archive, epoch)
    with archive.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    checksum = args.output / (name + ".sha256")
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="utf-8", newline="\n")
    print(json.dumps({"archive": str(archive), "sha256": digest, "source_commit": commit, "status": receipt["status"]}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, integrity.IntegrityError) as error:
        sys.exit(str(error))
