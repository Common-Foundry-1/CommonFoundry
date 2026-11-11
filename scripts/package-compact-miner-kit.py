#!/usr/bin/env python3
"""Build complete pre-activation pool-miner kits from an authenticated baseline."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

import release_integrity as integrity

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("candidate", ROOT / "scripts/package-compact-miner-candidate.py")
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


def read_archive(archive: Path) -> dict[str, bytes]:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as handle:
            rows = [(m.filename, m.file_size, lambda m=m: handle.read(m)) for m in handle.infolist() if not m.is_dir()]
            return archive_files(rows)
    with tarfile.open(archive, "r:gz") as handle:
        rows = []
        for member in handle.getmembers():
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("baseline contains a link or special file")
            rows.append((member.name, member.size, lambda m=member: handle.extractfile(m).read()))
        return archive_files(rows)


def archive_files(rows) -> dict[str, bytes]:
    if not 1 <= len(rows) <= 256 or sum(size for _, size, _ in rows) > 512 * 1024**2:
        raise ValueError("baseline inventory exceeds bounds")
    files = {}
    roots = set()
    for name, size, read in rows:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or len(path.parts) < 2:
            raise ValueError("unsafe baseline member")
        roots.add(path.parts[0])
        relative = str(PurePosixPath(*path.parts[1:]))
        if relative in files:
            raise ValueError("duplicate baseline member")
        files[relative] = read()
        if len(files[relative]) != size:
            raise ValueError("baseline member size mismatch")
    if len(roots) != 1:
        raise ValueError("baseline must have one package root")
    return files


def verify_baseline(archive: Path, checksums: Path, signature: Path, verifier: str) -> dict[str, bytes]:
    payload = checksums.read_bytes()
    checked = subprocess.run([verifier, "-Y", "verify", "-f", str(ROOT / "packaging/mainnet/MAINNET-RELEASE.allowed_signers"),
                              "-I", "commonfoundry-mainnet-owner", "-n", "commonfoundry-release", "-s", str(signature)],
                             input=payload, capture_output=True, timeout=30)
    if checked.returncode:
        raise ValueError("baseline checksum signature did not verify")
    expected = {}
    for line in payload.decode().splitlines():
        digest, name = line.split("  ", 1)
        if name in expected or Path(name).name != name or not re.fullmatch("[0-9a-f]{64}", digest):
            raise ValueError("invalid signed baseline checksums")
        expected[name] = digest
    if expected.get(archive.name) != candidate.sha256(archive):
        raise ValueError("baseline archive does not match the signed release")
    files = read_archive(archive)
    receipt = json.loads(files["MAINNET-PACKAGE.json"])
    if receipt["package_version"] != "1.0.20" or set(receipt["files"]) != set(files) - {"MAINNET-PACKAGE.json"}:
        raise ValueError("baseline package inventory is incomplete")
    for name, expected in receipt["files"].items():
        if expected != {"bytes": len(files[name]), "sha256": hashlib.sha256(files[name]).hexdigest()}:
            raise ValueError("baseline package file differs from its receipt")
    return files


def validate_signed_copy(original: bytes, signed: bytes) -> None:
    """Code signing may change only the PE checksum/security directory and append a certificate."""
    pe = struct.unpack_from("<I", original, 60)[0]
    if original[pe:pe + 6] != b"PE\0\0\x64\x86" or signed[pe:pe + 6] != original[pe:pe + 6]:
        raise ValueError("expected an x86-64 PE signing input")
    optional = pe + 24
    if original[optional:optional + 2] != b"\x0b\x02":
        raise ValueError("expected PE32+")
    security = optional + 112 + 4 * 8
    certificate, length = struct.unpack_from("<II", signed, security)
    if certificate < len(original) or certificate > len(original) + 7 or certificate + length != len(signed) or length < 8:
        raise ValueError("signed executable has unexpected appended content")
    if any(signed[len(original):certificate]):
        raise ValueError("signed executable has nonzero certificate alignment padding")
    before, after = bytearray(original), bytearray(signed[:len(original)])
    for offset, size in [(optional + 64, 4), (security, 8)]:
        before[offset:offset + size] = b"\0" * size
        after[offset:offset + size] = b"\0" * size
    if before != after:
        raise ValueError("code or data changed while signing")


def require_authenticode(path: Path) -> None:
    if os.name != "nt":
        raise ValueError("check Windows signing on native Windows")
    script = "$ErrorActionPreference='Stop';$s=Get-AuthenticodeSignature -LiteralPath $env:CMFD_SIGNED_EXE;" \
             "if($s.Status -ne 'Valid' -or $null -eq $s.TimeStamperCertificate){throw 'Valid timestamped Authenticode required'};" \
             "if(-not ($s.SignerCertificate.EnhancedKeyUsageList | Where-Object Value -eq '1.3.6.1.5.5.7.3.3')){throw 'Code Signing EKU required'}"
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], check=True, timeout=30,
                   env=dict(os.environ, CMFD_SIGNED_EXE=str(path),
                            PSModulePath=str(Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/Modules")))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "baseline-checksums", "baseline-signature", "miner", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--platform", required=True, choices=("linux-x86_64", "windows-x86_64", "windows-wsl2-x86_64"))
    parser.add_argument("--kind", default="miner", choices=("miner", "hiveos"))
    parser.add_argument("--unsigned-miner", type=Path)
    parser.add_argument("--signed-launch", type=Path)
    parser.add_argument("--ssh-keygen", default="ssh-keygen")
    args = parser.parse_args()
    commit = args.expected_commit
    if candidate.output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip() != commit:
        raise ValueError("wrong frozen source commit")
    if candidate.output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("source must be clean")
    version = tomllib.loads((ROOT / "crates/cmfd-miner/Cargo.toml").read_text())["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("complete miner kits require a numeric version")
    windows = args.platform == "windows-x86_64"
    wsl = args.platform == "windows-wsl2-x86_64"
    if (windows or wsl) and args.kind == "hiveos":
        raise ValueError("HiveOS requires Linux")
    baseline_platform = "linux-x86_64" if wsl else args.platform
    expected_baseline = f"commonfoundry-mainnet-miner-{baseline_platform}-v1.0.20" + (".zip" if windows else ".tar.gz")
    if args.kind == "hiveos":
        expected_baseline = "commonfoundry-mainnet-hiveos-1.0.20.tar.gz"
    if args.baseline.name != expected_baseline:
        raise ValueError("wrong baseline platform or role")
    files = verify_baseline(args.baseline, args.baseline_checksums, args.baseline_signature, args.ssh_keygen)
    baseline_receipt = files.pop("MAINNET-PACKAGE.json")
    extension = ".exe" if windows else ""
    miner_name = "cmfd-miner" + extension
    files[miner_name] = args.miner.read_bytes()
    if windows:
        if not args.unsigned_miner or not args.signed_launch:
            raise ValueError("supply the unsigned miner build and timestamped signed launcher/miner")
        validate_signed_copy(args.unsigned_miner.read_bytes(), files[miner_name])
        validate_signed_copy(files["cmfd-launch.exe"], args.signed_launch.read_bytes())
        require_authenticode(args.miner)
        require_authenticode(args.signed_launch)
        files["cmfd-launch.exe"] = args.signed_launch.read_bytes()
    name = f"commonfoundry-mainnet-miner-{args.platform}-v{version}"
    archive_name = name + (".zip" if windows or wsl else ".tar.gz")
    if args.kind == "hiveos":
        name = "commonfoundry-mainnet-hiveos"
        archive_name = name + f"-{version}.tar.gz"
        files["h-manifest.conf"] = (ROOT / "packaging/mainnet/hiveos/h-manifest.conf").read_bytes().replace(b"\r\n", b"\n")
    files["BASELINE-PACKAGE.json"] = baseline_receipt
    files["MINER-COMPATIBILITY.md"] = candidate.GUIDE.read_bytes()
    files["MAINNET-FORK-IDENTITY-65535.json"] = candidate.MANIFEST.read_bytes()
    if wsl:
        # WSL exposes NVIDIA's utility here without consistently adding it to
        # the non-interactive PATH inherited by `wsl --exec bash`.
        files["start-miner.sh"] = files["start-miner.sh"].replace(
            b"set -euo pipefail\n",
            b"set -euo pipefail\nexport PATH=\"/usr/lib/wsl/lib:$PATH\"\n", 1)
        files["START-HERE.txt"] = b"""Common Foundry pool miner - Windows WSL2 edition

Requires Ubuntu-22.04 in WSL2 with working NVIDIA GPU support.
Extract this ZIP into a new directory. Open Windows Terminal in that directory
(right-click the directory background and choose Open in Terminal), then run:

wsl -d Ubuntu-22.04 --exec bash ./start-miner.sh

Enter your existing CMFD receive address and complete pinned pool URL when
asked. Ctrl+C stops the miner. You can reuse the inputs directory from your
previous miner to avoid another model download. Keep the previous kit intact.

This edition runs the miner and GPU worker inside WSL. It contains Linux
executables and uses Windows' installed Microsoft-signed wsl.exe launcher.
It does not include a new native Windows EXE or require a code-signing account.
See README.md and MINER-COMPATIBILITY.md for verification and compatibility.
"""
        if any(Path(n).suffix.lower() in (".exe", ".dll", ".cmd", ".bat", ".ps1") for n in files):
            raise ValueError("WSL edition must not contain native Windows executables or scripts")
    launch_instruction = ("For Windows WSL2, follow START-HERE.txt: open a terminal in this directory\n"
                          "and run `wsl -d Ubuntu-22.04 --exec bash ./start-miner.sh`." if wsl else
                          "For native Linux, run `./start-miner.sh`. For a signed native Windows kit,\n"
                          "run `START-MINER.bat` with working Ubuntu-22.04 WSL2 GPU support.")
    guide = f"""# Common Foundry pool miner {version}

This complete NVIDIA miner kit supports today's mainnet pool and the exact
planned compact-mainnet identity. This pre-activation compatibility prerelease
does not activate the fork. Full node/pool cross-height qualification is pending.

{launch_instruction} Supply your existing CMFD receive
address and full certificate-pinned pool URL. Keep your worker/GPU settings.
Model downloads are resumable and verified. Reuse your existing verified model
bank by copying the inputs directory into this new installation. Keep the old
installation for rollback. No wallet keys or existing config are overwritten.

For HiveOS, install the complete commonfoundry-mainnet-hiveos-{version}.tar.gz
asset from this release as the custom miner. Wallet: %WAL%; algorithm:
forgematrix_v4; pool: the complete cmfd+tls URL including its certificate pin.
Existing external model/state directories are preserved by the HiveOS adapter.

Read MINER-COMPATIBILITY.md for the exact fingerprints and developer procedure.
Verify the downloaded archive with the signed release SHA256SUMS.txt and the
Common Foundry release signer. BASELINE-PACKAGE.json describes inherited 1.0.20
files; MINER-KIT.json is the inventory for this kit and records both provenances.
"""
    files["README.md"] = guide.encode()
    for filename in files:
        if filename.endswith((".sh", ".py", ".conf")):
            files[filename] = files[filename].replace(b"\r\n", b"\n")
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / archive_name
    if archive.exists():
        raise ValueError("output archive already exists")
    with tempfile.TemporaryDirectory(prefix="cmfd-miner-kit-") as temporary:
        stage = Path(temporary) / name
        stage.mkdir()
        for filename, data in files.items():
            path = stage / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        binary = stage / miner_name
        binary.chmod(0o755)
        executable = [str(binary)]
        if os.name == "nt" and not windows:
            linux_path = candidate.output(["wsl.exe", "-d", "Ubuntu-22.04", "--exec", "wslpath", "-u", binary.as_posix()]).decode().strip()
            executable = ["wsl.exe", "-d", "Ubuntu-22.04", "--exec", linux_path]
        network = json.loads(candidate.output([*executable, "network-info"]))
        compatibility = json.loads(candidate.output([*executable, "pool-compatibility-info"]))
        candidate.validate_reports(network, compatibility, commit, json.loads(candidate.MANIFEST.read_bytes()))
        if candidate.output([*executable, "--version"]).decode().strip() != f"cmfd-miner {version}":
            raise ValueError("miner version mismatch")
        # Also authenticate the preserved launch plan with the new executable.
        launch_info = json.loads(candidate.output([*executable, "mainnet-launch-info"]))
        if launch_info["source_commit"] != commit or launch_info["launch_plan"]["network_id"] != compatibility["network_id"]:
            raise ValueError("packaged launch identity mismatch")
        files["POOL-COMPATIBILITY.json"] = candidate.canonical(compatibility)
        (stage / "POOL-COMPATIBILITY.json").write_bytes(files["POOL-COMPATIBILITY.json"])
        receipt = {"schema": "CMFD_POOL_MINER_KIT_V1", "status": "pre-activation-compatibility-prerelease",
                   "version": version, "source_commit": commit, "kind": args.kind, "platform": args.platform,
                   "baseline_release": "v1.0.20", "baseline_archive": args.baseline.name,
                   "baseline_archive_sha256": candidate.sha256(args.baseline), "release_approved": False,
                   "scope": "pool-nonce-search", "full_mainnet_fork_qualification": "pending",
                   "windows_authenticode": "valid-timestamped" if windows else "not-applicable-linux-payload",
                   "payload_platform": "windows-x86_64" if windows else "linux-x86_64",
                   "files": {n: {"bytes": len(d), "sha256": hashlib.sha256(d).hexdigest()} for n, d in sorted(files.items())}}
        (stage / "MINER-KIT.json").write_bytes(candidate.canonical(receipt))
        epoch = int(candidate.output(["git", "show", "-s", "--format=%ct", commit], cwd=ROOT))
        create = integrity.create_deterministic_zip if windows or wsl else integrity.create_deterministic_tar_gz
        create(stage, archive, epoch)
    print(json.dumps({"archive": str(archive), "sha256": candidate.sha256(archive), "source_commit": commit}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, integrity.IntegrityError) as error:
        sys.exit(str(error))
