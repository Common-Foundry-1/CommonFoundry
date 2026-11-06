#!/usr/bin/env python3
"""Assemble the compact-proof Linux public canary kit from qualified binaries."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

ROOT = Path(__file__).resolve().parents[1]
NETWORK = "8a34c0d9eaa92c5eaec4af7fe146afdfa2ab6859918b7deb0c97e0a1f600d6d1"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for part in iter(lambda: source.read(8 * 1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--source-commit", required=True)
    p.add_argument("--source-dirty", action="store_true")
    p.add_argument("--kit-version", default="0.2.0")
    args = p.parse_args()
    output = args.output.resolve()
    name = f"commonfoundry-compact-testnet-v{args.kit_version}-linux-x86_64"
    stage = output / name
    stage.mkdir(parents=True, exist_ok=False)
    for name in ("cmfd-node", "cmfd-miner", "cmfd-v4-replay", "cmfd-direct-prover"):
        shutil.copy2(args.artifacts / name, stage / name)
        (stage / name).chmod(0o755)
    shutil.copy2(ROOT / "packaging/compact-proof-testnet/launch.py", stage / "launch.py")
    shutil.copy2(ROOT / "scripts/production-v4-inputs.py", stage / "production-v4-inputs.py")
    for path in (ROOT / "packaging/production-v4-pool/shared").iterdir():
        if path.name in ("V4-INPUT-CHUNKS.json", "production-v4-rcnet-1-inputs.json", "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"):
            shutil.copy2(path, stage / path.name)
    for source, target in (("LICENSE", "LICENSE"), ("THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md"),
            ("packaging/compact-proof-testnet/README.md", "README.md"),
            ("docs/compact-proof-testnet/POOL-PROPOSAL.md", "POOL-INVITATION.md")):
        shutil.copy2(ROOT / source, stage / target)
    for filename, action in (("START-POOL.sh", "pool"), ("START-MINER.sh", "miner"),
            ("START-NODE.sh", "node"), ("PREPARE-INPUTS.sh", "prepare"),
            ("VERIFY-PACKAGE.sh", "verify"), ("COLLECT-DIAGNOSTICS.sh", "diagnostics"),
            ("NEW-ADDRESS.sh", "new-address")):
        path = stage / filename
        path.write_text('#!/usr/bin/env bash\nset -euo pipefail\ncd "$(dirname "$0")"\nexec python3 ./launch.py ' + action + ' "$@"\n', newline="\n")
        path.chmod(0o755)
    commit = args.source_commit
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("source commit must be a full lowercase Git SHA")
    build = {"schema": "CMFD_COMPACT_TESTNET_PACKAGE_V1", "version": args.kit_version, "network_id": NETWORK,
        "source_commit": commit, "source_commit_scope": "node, miner, launcher, downloader and packaging",
        "prover_identity": "exact GPU binary SHA-256 in PACKAGE-MANIFEST.json; pinned direct-proof research build",
        "source_dirty": args.source_dirty, "seed": "209.145.48.36:23444",
        "seed_backend": "dedicated Proxmox testnet guest", "proof_version": 2,
        "work_validation_policy": "complete compact proof; optional separate work-replay audit node",
        "initial_target": "01" + "ff" * 31,
        "roles": ["reference pool", "GPU pool miner", "CPU full node"],
        "gpu_architectures": ["sm_86", "sm_89", "sm_120"],
        "platform": "Linux x86_64, glibc 2.35+, CUDA 12 runtime for GPU roles",
        "proof_bytes_local_pilot": [5667661, 5662826, 5665867],
        "local_pilot_full_acceptance_seconds": 16.75}
    (stage / "BUILD-INFO.json").write_text(json.dumps(build, indent=2) + "\n")
    files = {str(path.relative_to(stage)).replace("\\", "/"): {"bytes": path.stat().st_size, "sha256": digest(path)}
        for path in sorted(stage.rglob("*")) if path.is_file()}
    (stage / "PACKAGE-MANIFEST.json").write_text(json.dumps({"network_id": NETWORK, "files": files}, indent=2) + "\n")
    sums = "".join(f'{digest(path)}  {path.name}\n' for path in sorted(stage.iterdir()) if path.is_file())
    (stage / "PACKAGE-SHA256SUMS.txt").write_text(sums)
    archive = output / (name + ".tar.gz")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(stage, arcname=name)
    (output / "SHA256SUMS.txt").write_text(f"{digest(archive)}  {archive.name}\n")
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size, "sha256": digest(archive)}))


if __name__ == "__main__":
    main()
