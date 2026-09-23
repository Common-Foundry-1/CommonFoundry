#!/usr/bin/env python3
"""Build and inventory the frozen mainnet pool dashboard; do not approve release.

The build starts from Git blobs at an exact clean HEAD, not the ignored local
``node_modules`` or ``dist`` trees. Outputs are create-new and are not signatures,
independent reproduction evidence, or permission to publish.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time

import package_mainnet as package

Error = package.Error
SOURCE_PREFIX = "apps/pool-dashboard/"
MANIFEST_SCHEMA = "CMFD_MAINNET_POOL_DASHBOARD_ASSETS_V1"
EVIDENCE_SCHEMA = "CMFD_MAINNET_POOL_DASHBOARD_BUILD_EVIDENCE_V1"
MAX_TOOL_OUTPUT = 1024 * 1024


def identity(data: bytes) -> dict:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def require_frozen_checkout(repo: Path, commit: str) -> None:
    package.nonzero_hex(commit, 40, "frozen source commit")
    package.integrity._regular_directory(repo, "source repository")
    if package.integrity._run_git(repo, "rev-parse", "HEAD") != commit:
        raise Error("dashboard build requires the exact checked-out frozen source commit")
    if package.integrity._run_git(repo, "status", "--porcelain", "--untracked-files=normal"):
        raise Error("dashboard build requires a clean frozen source checkout")


def frozen_sources(repo: Path, commit: str) -> dict[str, bytes]:
    """Copy only regular tracked dashboard blobs, never ignored build output."""
    listing = package.integrity._run_git_bytes(
        repo, "ls-tree", "-rz", "--full-tree", commit, "--", "apps/pool-dashboard"
    )
    files: dict[str, bytes] = {}
    for row in listing.split(b"\0"):
        if not row:
            continue
        try:
            metadata, raw_name = row.split(b"\t", 1)
            mode, kind, _oid = metadata.split(b" ")
            name = raw_name.decode("utf-8", "strict")
        except (ValueError, UnicodeError) as error:
            raise Error("invalid dashboard Git tree entry") from error
        if mode not in (b"100644", b"100755") or kind != b"blob":
            raise Error(f"dashboard source contains a symlink or special entry: {name}")
        if not name.startswith(SOURCE_PREFIX):
            raise Error(f"unexpected dashboard Git path: {name}")
        relative = name[len(SOURCE_PREFIX):]
        parts = relative.split("/")
        if not relative or any(part in ("", ".", "..") for part in parts) or "\\" in relative:
            raise Error(f"unsafe dashboard Git path: {name}")
        if relative in files:
            raise Error(f"duplicate dashboard Git path: {name}")
        files[relative] = package.integrity._tracked_blob_at(repo, commit, name)
    if not {"package.json", "package-lock.json", "index.html", "vite.config.ts"} <= files.keys():
        raise Error("frozen dashboard source is incomplete")
    try:
        manifest = json.loads(files["package.json"])
        lock = json.loads(files["package-lock.json"])
    except (ValueError, UnicodeError) as error:
        raise Error("dashboard package or lockfile is not valid JSON") from error
    if not isinstance(manifest, dict) or not isinstance(lock, dict) or lock.get("lockfileVersion") != 3:
        raise Error("dashboard requires an npm package-lock v3")
    root_package = lock.get("packages", {}).get("") if isinstance(lock.get("packages"), dict) else None
    if (not isinstance(root_package, dict)
            or manifest.get("name") != lock.get("name") or manifest.get("version") != lock.get("version")
            or manifest.get("name") != root_package.get("name")
            or manifest.get("version") != root_package.get("version")):
        raise Error("dashboard package and lockfile identities disagree")
    return files


def run_tool(arguments: list[str], cwd: Path, timeout: int) -> bytes:
    """Bound duration and combined output while invoking the tool without a shell."""
    try:
        child = subprocess.Popen(arguments, cwd=cwd, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    except OSError as error:
        raise Error(f"dashboard command failed: {arguments[0]} {arguments[1:]}") from error
    result: queue.Queue = queue.Queue(maxsize=1)
    def read():
        try:
            result.put(child.stdout.read(MAX_TOOL_OUTPUT + 1))
        except OSError as error:
            result.put(error)
    reader = threading.Thread(target=read, daemon=True)
    try:
        reader.start()
        deadline = time.monotonic() + timeout
        data = None
        while child.poll() is None:
            try:
                data = result.get_nowait()
            except queue.Empty:
                pass
            if isinstance(data, bytes) and len(data) > MAX_TOOL_OUTPUT:
                raise Error("dashboard command output exceeded 1 MiB")
            if isinstance(data, OSError):
                raise Error("dashboard command output could not be read") from data
            if time.monotonic() >= deadline:
                raise Error("dashboard command timed out")
            time.sleep(0.05)
        if data is None:
            try:
                data = result.get(timeout=1)
            except queue.Empty as error:
                raise Error("dashboard command output did not close") from error
        if not isinstance(data, bytes) or len(data) > MAX_TOOL_OUTPUT:
            raise Error("dashboard command output exceeded 1 MiB")
        if child.returncode:
            detail = data.decode("utf-8", "replace")[-1200:].strip()
            raise Error(f"dashboard command failed ({child.returncode}): {arguments[1:]}: {detail}")
        return data
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
        reader.join(timeout=1)
        if not reader.is_alive():
            child.stdout.close()


def inventory(dist: Path, commit: str) -> tuple[bytes, dict[str, bytes]]:
    package.integrity._regular_directory(dist, "new dashboard dist")
    files: dict[str, dict] = {}
    for path in dist.rglob("*"):
        name = path.relative_to(dist).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode) and name == "assets":
            continue
        if not stat.S_ISREG(mode) or not package.dashboard_asset_name(name):
            raise Error(f"dashboard dist contains a symlink or unexpected entry: {name}")
        with package.integrity._stable_regular_handle(path, f"dashboard asset {name}") as (_, handle, opened):
            if not 0 < opened.st_size <= package.MAX_DASHBOARD_FILE_BYTES:
                raise Error(f"dashboard asset has invalid size: {name}")
            data = handle.read(package.MAX_DASHBOARD_FILE_BYTES + 1)
        files[name] = identity(data)
    manifest = {"schema": MANIFEST_SCHEMA, "source_commit": commit, "files": files}
    manifest_bytes = package.canonical(manifest)
    package.validate_dashboard_manifest(manifest_bytes, commit)
    assets = package.dashboard_assets(dist, manifest)
    return manifest_bytes, assets


def output_preflight(repo: Path, dist: Path, manifest: Path, evidence: Path, verify_dist: bool) -> None:
    if len({str(path.absolute()).casefold() for path in (dist, manifest, evidence)}) != 3:
        raise Error("dashboard output paths must be distinct")
    repo_location = repo.resolve(strict=True)
    if any(path.resolve(strict=False).is_relative_to(repo_location) for path in (dist, manifest, evidence)):
        raise Error("dashboard outputs must be outside the frozen source repository")
    dist_location = dist.resolve(strict=False)
    if any(path.resolve(strict=False).is_relative_to(dist_location) for path in (manifest, evidence)):
        raise Error("dashboard manifest and evidence must be outside the dist tree")
    for path, label in ((manifest, "manifest"), (evidence, "build evidence")):
        package.integrity._regular_directory(path.parent, f"{label} parent")
        if path.exists() or path.is_symlink():
            raise Error(f"{label} already exists: {path}")
    if verify_dist:
        package.integrity._regular_directory(dist, "existing dashboard dist")
    else:
        package.integrity._regular_directory(dist.parent, "dashboard dist parent")
        if dist.exists() or dist.is_symlink():
            raise Error(f"dashboard dist already exists: {dist}")


def write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(data)


def prepare(*, repo: Path, commit: str, dist: Path, manifest_path: Path,
            evidence_path: Path, verify_dist: bool = False) -> dict:
    require_frozen_checkout(repo, commit)
    output_preflight(repo, dist, manifest_path, evidence_path, verify_dist)
    sources = frozen_sources(repo, commit)
    node = shutil.which("node")
    npm = shutil.which("npm")
    if not node or not npm:
        raise Error("Node.js and npm are required to build the reviewed dashboard")
    toolchain = {}
    for label, command in (("node", node), ("npm", npm)):
        result = run_tool([command, "--version"], repo, 30)
        version = result.decode("utf-8", "strict").strip()
        if not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
            raise Error(f"invalid {label} version output")
        toolchain[label] = {"executable": str(Path(command).resolve()), "version": version}
    commands = []
    with tempfile.TemporaryDirectory(prefix="cmfd-dashboard-build-") as temporary:
        work = Path(temporary) / "apps" / "pool-dashboard"
        work.mkdir(parents=True)
        for name, data in sources.items():
            target = work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        for arguments, limit in (([npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"], 900),
                                 ([npm, "run", "build"], 600)):
            result = run_tool(arguments, work, limit)
            commands.append({"argv": ["npm", *arguments[1:]],
                             "combined_output_bytes": len(result),
                             "combined_output_sha256": hashlib.sha256(result).hexdigest()})
        for name, expected in sources.items():
            path = work / name
            with package.integrity._stable_regular_handle(path, f"staged dashboard source {name}") as (_, handle, _):
                if handle.read() != expected:
                    raise Error(f"dashboard build changed frozen source: {name}")
        manifest_bytes, assets = inventory(work / "dist", commit)
        if verify_dist:
            package.dashboard_assets(dist, package.validate_dashboard_manifest(manifest_bytes, commit))
        require_frozen_checkout(repo, commit)
        output_preflight(repo, dist, manifest_path, evidence_path, verify_dist)
        if not verify_dist:
            dist.mkdir()
            for name, data in assets.items():
                target = dist / name
                target.parent.mkdir(parents=True, exist_ok=True)
                write_new(target, data)
            package.dashboard_assets(dist, package.validate_dashboard_manifest(manifest_bytes, commit))
        evidence = {"schema": EVIDENCE_SCHEMA, "source_commit": commit,
                    "source_tree_sha256": hashlib.sha256(package.canonical({name: identity(data) for name, data in sources.items()})).hexdigest(),
                    "package_lock": identity(sources["package-lock.json"]),
                    "toolchain": toolchain, "commands": commands,
                    "dashboard_manifest": identity(manifest_bytes),
                    "dist_mode": "compared_existing" if verify_dist else "created_from_isolated_build",
                    "independent_reproduction_claim": False, "release_approved": False}
        write_new(evidence_path, package.canonical(evidence))
        write_new(manifest_path, manifest_bytes)
    return {"manifest": str(manifest_path), "dist": str(dist), "evidence": str(evidence_path),
            "source_commit": commit, "files": len(assets), "release_approved": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--commit", required=True)
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--verify-dist", action="store_true", help="compare an existing dist against a fresh isolated build")
    args = parser.parse_args()
    for label in ("repo", "dist", "manifest", "evidence"):
        if not getattr(args, label).is_absolute():
            parser.error(f"--{label} must be an absolute path")
    try:
        print(json.dumps(prepare(repo=args.repo, commit=args.commit, dist=args.dist,
                                 manifest_path=args.manifest, evidence_path=args.evidence,
                                 verify_dist=args.verify_dist), sort_keys=True))
    except (Error, OSError, UnicodeError, ValueError, TypeError) as error:
        parser.exit(1, f"Mainnet dashboard preparation failed: {error}\n")


if __name__ == "__main__":
    main()
