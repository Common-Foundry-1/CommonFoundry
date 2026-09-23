#!/usr/bin/env python3
"""Assemble native mainnet packages; never sign, publish, or grant release approval.

Run separately on Windows and Linux against binaries built from the frozen
commit. The compiled runtimes must authenticate the same prelaunch plan. No
beacon, live chain, private key, model download, or mining is needed here.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import threading
import time

import release_integrity as integrity

Error = integrity.IntegrityError
SOURCE_TIME = 1790960400
LAUNCH_TIME = 1791046800
SOURCE_UTC = "2026-10-02T17:00:00Z"
LAUNCH_UTC = "2026-10-03T17:00:00Z"
BEACON_ROUND = 32747812
BEACON_POLICY = {
    "chain_hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    "public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1"
                  "fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
    "scheme": "bls-unchained-g1-rfc9380",
    "genesis_time": 1692803367,
    "period_seconds": 3,
    "round": BEACON_ROUND,
}
MAX_INFO = 128 * 1024
FIXED = "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
SHARED = "packaging/production-v4-pool/shared"
PLATFORMS = ("windows-x86_64", "linux-x86_64")
PLAN_SCHEMA = "CMFD_MAINNET_LAUNCH_PLAN_V2"
PLAN_DOMAIN = b"CMFD/MAINNET/LAUNCH-PLAN/V2\0"
NETWORK_DOMAIN = "CMFD/MAINNET/NETWORK-ID/V2"
DASHBOARD_MANIFEST = "production-mainnet/DASHBOARD-ASSETS.json"
CUDA_RUNTIME = "lib/libcudart.so.12"
MAX_DASHBOARD_FILES = 128
MAX_DASHBOARD_FILE_BYTES = 16 * 1024 * 1024
MAX_DASHBOARD_BYTES = 64 * 1024 * 1024
MAX_CUDA_BYTES = 64 * 1024 * 1024
DASHBOARD_EXTENSIONS = {"js", "css", "png", "jpg", "jpeg", "webp", "svg", "ico", "woff", "woff2", "ttf", "otf", "wasm"}


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def strict_json(data: bytes, label: str, maximum: int = MAX_INFO) -> dict:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise Error(f"duplicate JSON key in {label}: {key}")
            value[key] = item
        return value
    if len(data) > maximum:
        raise Error(f"oversized {label}")
    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Error(f"nonfinite {label}")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Error(f"invalid {label}") from error
    if not isinstance(value, dict):
        raise Error(f"{label} must be an object")
    return value


def nonzero_hex(value: object, length: int, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", value) or set(value) == {"0"}:
        raise Error(f"invalid {label}")
    return value


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    path = integrity._regular_file(path, label)
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise Error(f"oversized {label}")
    return data


def file_identity(path: Path) -> dict:
    size, digest = integrity._sha256_file_with_size(path, "package file")
    return {"bytes": size, "sha256": digest}


def dashboard_asset_name(name: object) -> bool:
    if name == "index.html":
        return True
    if not isinstance(name, str) or not name.startswith("assets/"):
        return False
    basename = name[len("assets/"):]
    match = re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.([A-Za-z0-9]+)", basename)
    return match is not None and match.group(1).lower() in DASHBOARD_EXTENSIONS


def validate_dashboard_manifest(data: bytes, commit: str) -> dict:
    manifest = strict_json(data, "dashboard asset manifest")
    if canonical(manifest) != data or set(manifest) != {"schema", "source_commit", "files"}:
        raise Error("dashboard asset manifest is not canonical or has unexpected fields")
    if manifest["schema"] != "CMFD_MAINNET_POOL_DASHBOARD_ASSETS_V1" or manifest["source_commit"] != commit:
        raise Error("dashboard asset manifest does not bind the frozen source commit")
    files = manifest["files"]
    if not isinstance(files, dict) or not 2 <= len(files) <= MAX_DASHBOARD_FILES:
        raise Error("dashboard asset inventory is missing or oversized")
    if "index.html" not in files or not any(name.endswith(".js") for name in files):
        raise Error("dashboard asset inventory lacks index.html or JavaScript")
    if len({name.casefold() for name in files}) != len(files):
        raise Error("dashboard asset inventory has case-insensitive collisions")
    total = 0
    for name, identity in files.items():
        if not dashboard_asset_name(name) or not isinstance(identity, dict) or set(identity) != {"bytes", "sha256"}:
            raise Error(f"unsafe or malformed dashboard asset: {name}")
        if type(identity["bytes"]) is not int or not 0 < identity["bytes"] <= MAX_DASHBOARD_FILE_BYTES:
            raise Error(f"invalid dashboard asset size: {name}")
        nonzero_hex(identity["sha256"], 64, f"dashboard asset hash: {name}")
        total += identity["bytes"]
    if total > MAX_DASHBOARD_BYTES:
        raise Error("dashboard asset tree exceeds its release limit")
    return manifest


def dashboard_assets(dist: Path, manifest: dict) -> dict[str, bytes]:
    integrity._regular_directory(dist, "dashboard dist")
    found: set[str] = set()
    for path in dist.rglob("*"):
        relative = path.relative_to(dist).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode) and relative == "assets":
            continue
        if not stat.S_ISREG(mode) or not dashboard_asset_name(relative):
            raise Error(f"dashboard dist contains a symlink or unexpected entry: {relative}")
        found.add(relative)
    if found != set(manifest["files"]):
        raise Error("dashboard dist has missing or extra assets relative to its reviewed manifest")
    result = {}
    for name, identity in manifest["files"].items():
        source = dist / name
        with integrity._stable_regular_handle(source, f"dashboard asset {name}") as (_, handle, opened):
            if opened.st_size > MAX_DASHBOARD_FILE_BYTES:
                raise Error(f"dashboard asset exceeds its release limit: {name}")
            data = handle.read(MAX_DASHBOARD_FILE_BYTES + 1)
        if {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} != identity:
            raise Error(f"dashboard asset differs from its reviewed manifest: {name}")
        result[name] = data
    return result


def validate_cuda_runtime_header(header: bytes, size: int) -> None:
    """Check that the pinned runtime is a Linux x86-64 ELF shared object."""
    if len(header) < 64 or header[:4] != b"\x7fELF" or header[4:7] != b"\x02\x01\x01":
        raise Error("CUDA runtime is not a 64-bit little-endian ELF library")
    elf_type, machine, version = struct.unpack_from("<HHI", header, 16)
    ph_offset = struct.unpack_from("<Q", header, 32)[0]
    header_size, ph_size, ph_count = struct.unpack_from("<HHH", header, 52)
    if (elf_type != 3 or machine != 0x3e or version != 1 or header_size != 64
            or ph_offset < 64 or ph_size < 56 or not ph_count
            or ph_offset + ph_size * ph_count > min(size, len(header))):
        raise Error("CUDA runtime is not a valid Linux x86-64 ELF shared library")
    dynamic = executable_load = False
    for index in range(ph_count):
        offset = ph_offset + ph_size * index
        segment_type, flags = struct.unpack_from("<II", header, offset)
        file_offset, _, _, file_size, memory_size, alignment = struct.unpack_from("<QQQQQQ", header, offset + 8)
        if file_offset + file_size > size or memory_size < file_size:
            raise Error("CUDA runtime has an invalid ELF segment")
        if segment_type == 1:
            if not alignment or alignment & (alignment - 1):
                raise Error("CUDA runtime has an invalid ELF load alignment")
            executable_load |= bool(flags & 1 and file_size)
        elif segment_type == 2:
            dynamic |= bool(file_size)
    if not dynamic or not executable_load:
        raise Error("CUDA runtime lacks dynamic or executable ELF segments")


def copy_cuda_runtime(source: Path, target: Path, expected_sha256: str) -> None:
    nonzero_hex(expected_sha256, 64, "reviewed CUDA runtime SHA-256")
    with integrity._stable_regular_handle(source, "CUDA runtime") as (_, handle, opened):
        if not 0 < opened.st_size <= MAX_CUDA_BYTES:
            raise Error("CUDA runtime exceeds its release limit")
        validate_cuda_runtime_header(handle.read(integrity.MAX_EXECUTABLE_HEADER_BYTES), opened.st_size)
        handle.seek(0)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as output:
            shutil.copyfileobj(handle, output)
        identity = file_identity(target)
        if identity != {"bytes": opened.st_size, "sha256": expected_sha256}:
            raise Error("CUDA runtime size or SHA-256 differs from the reviewed pin")
    target.chmod(0o644)


def native_output(executable: Path, arguments: list[str], timeout_seconds: float = 15) -> bytes:
    """Bound process duration and collected bytes; invoke without any shell."""
    child = subprocess.Popen([str(executable), *arguments], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    result: queue.Queue = queue.Queue(maxsize=1)
    def read():
        try:
            result.put(child.stdout.read(MAX_INFO + 1))
        except OSError as error:
            result.put(error)
    reader = threading.Thread(target=read, daemon=True)
    try:
        reader.start()
    except RuntimeError:
        child.kill()
        child.wait(timeout=3)
        child.stdout.close()
        raise
    deadline = time.monotonic() + timeout_seconds
    data = None
    try:
        while child.poll() is None:
            try:
                data = result.get_nowait()
            except queue.Empty:
                pass
            if isinstance(data, bytes) and len(data) > MAX_INFO:
                raise Error("native identity output exceeded its limit")
            if isinstance(data, OSError):
                raise Error("native identity output could not be read") from data
            if time.monotonic() >= deadline:
                raise Error("native identity command timed out")
            time.sleep(0.025)
        if data is None:
            try:
                data = result.get(timeout=1)
            except queue.Empty as error:
                raise Error("native identity output did not close") from error
        if child.returncode or not isinstance(data, bytes) or len(data) > MAX_INFO:
            raise Error("native identity command failed or produced oversized output")
        return data
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
        reader.join(timeout=1)
        if not reader.is_alive():
            child.stdout.close()


def validate_plan(data: bytes) -> dict:
    plan = strict_json(data, "mainnet plan", 32 * 1024)
    if set(plan) != {"schema", "payload", "launch_plan_digest", "network_id"} or plan["schema"] != PLAN_SCHEMA:
        raise Error("unsupported mainnet plan")
    if (json.dumps(plan, indent=2, ensure_ascii=False) + "\n").encode() != data:
        raise Error("mainnet plan is not canonical")
    root = nonzero_hex(plan["launch_plan_digest"], 64, "plan digest")
    network = nonzero_hex(plan["network_id"], 64, "mainnet network ID")
    payload = plan["payload"]
    if not isinstance(payload, dict) or set(payload) != {"rules", "initial_target", "minimum_transaction_fee_atoms", "source_release_unix_seconds", "beacon"}:
        raise Error("invalid mainnet plan payload")
    if canonical(payload["beacon"]) != canonical(BEACON_POLICY):
        raise Error("mainnet plan has an unrecognized beacon policy")
    digest = hashlib.sha256(PLAN_DOMAIN + json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    if digest != root or integrity._rcnet_v2_derived_hash(NETWORK_DOMAIN, bytes.fromhex(root)).hex() != network:
        raise Error("mainnet plan derived identity mismatch")
    try:
        initial_target = nonzero_hex(payload["initial_target"], 64, "mainnet initial target")
        pow_limit = nonzero_hex(payload["rules"]["proof_of_work"]["pow_limit"], 64, "mainnet easiest target")
        if int(initial_target, 16) > int(pow_limit, 16):
            raise Error("mainnet initial target exceeds the easiest target")
        if payload["rules"]["profile"] != "CommonFoundry Mainnet" or payload["source_release_unix_seconds"] != SOURCE_TIME or payload["rules"]["virtual_genesis_timestamp_unix_seconds"] != LAUNCH_TIME or payload["beacon"]["round"] != BEACON_ROUND:
            raise Error("mainnet plan schedule or profile mismatch")
    except (KeyError, TypeError) as error:
        raise Error("mainnet plan is missing launch policy") from error
    # Full compiled rule/economic/approval checks are performed by the native
    # runtimes below. This independent check binds the exact document and dates.
    return plan


def validate_info(data: bytes, plan: dict, commit: str) -> dict:
    info = strict_json(data, "mainnet runtime identity")
    expected = {"format": "commonfoundry-mainnet-launch-info", "format_version": 1,
                "source_commit": commit, "source_release_utc": SOURCE_UTC,
                "mining_start_utc": LAUNCH_UTC, "launch_plan": plan,
                "genesis_policy": "requires_verified_launch_beacon", "beacon_round": BEACON_ROUND}
    expected["activation_evidence_sha256"] = info.get("activation_evidence_sha256")
    expected["mainnet_approval_manifest_sha256"] = info.get("mainnet_approval_manifest_sha256")
    expected["proof_approval_trust"] = info.get("proof_approval_trust")
    if canonical(info) != canonical(expected):
        raise Error("runtime does not match the mainnet plan and source commit")
    nonzero_hex(info["activation_evidence_sha256"], 64, "activation evidence digest")
    nonzero_hex(info["mainnet_approval_manifest_sha256"], 64, "mainnet approval manifest digest")
    trust = info["proof_approval_trust"]
    if not isinstance(trust, dict) or trust.get("contract_schema") != "CMFD_PRODUCTION_V4_ACTIVATION_APPROVAL_SUBJECT_V1":
        raise Error("runtime proof approval trust is absent or not dual-role")
    nonzero_hex(trust.get("qualification_binding_sha256"), 64, "proof qualification binding")
    nonzero_hex(trust.get("ssh_keygen_sha256"), 64, "proof approval verifier pin")
    if not isinstance(trust.get("producer"), dict) or not isinstance(trust.get("independent_reproducer"), dict):
        raise Error("runtime lacks distinct producer/reproducer trust")
    return info


def validate_schedule(schedule: dict, plan: dict) -> None:
    expected = {
        "schema": "CMFD_MAINNET_LAUNCH_SCHEDULE_V1",
        "source_release_unix_seconds": SOURCE_TIME,
        "mining_start_unix_seconds": LAUNCH_TIME,
        "source_release_utc": SOURCE_UTC,
        "mining_start_utc": LAUNCH_UTC,
        "beacon_round": BEACON_ROUND,
    }
    if any(schedule.get(key) != value for key, value in expected.items()) or schedule.get("mainnet_activation_authorized") is not False:
        raise Error("launch helper uses another schedule")
    for key in ("chain_hash", "public_key", "scheme"):
        if schedule.get("beacon_" + key) != plan["payload"]["beacon"].get(key):
            raise Error("launch helper uses another beacon")


def validate_plan_approvals(data: bytes, plan_bytes: bytes) -> dict:
    import mainnet_plan_approval
    try:
        return mainnet_plan_approval.validate_manifest(data, plan_bytes)
    except integrity.activation_approval.ApprovalError as error:
        raise Error(str(error)) from error


def bind_plan_approvals(manifest: dict, data: bytes, info: dict) -> None:
    import mainnet_plan_approval
    try:
        mainnet_plan_approval.bind_manifest_to_runtime(manifest, data, info)
    except integrity.activation_approval.ApprovalError as error:
        raise Error(str(error)) from error


def validate_review_ancestry(repo: Path, review_commit: str, release_commit: str) -> None:
    nonzero_hex(review_commit, 40, "review source commit")
    nonzero_hex(release_commit, 40, "release source commit")
    integrity._run_git(repo, "merge-base", "--is-ancestor", review_commit, release_commit)
    changed = set(integrity._run_git(repo, "diff", "--name-only", "--no-renames", review_commit, release_commit, "--").splitlines())
    allowed = {"crates/cmfd-node/mainnet_release_pin.inc.rs", "crates/cmfd-consensus/mainnet_network_id.inc.rs"}
    if changed - allowed:
        raise Error("release source changed beyond the reviewed mainnet pin files; fresh review is required")


def package_sources(platform: str, kind: str) -> dict[str, str]:
    sources = {"README.md": "packaging/mainnet/USER-GUIDE.md", "LICENSE": "LICENSE",
               "THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md",
               "production-v4-inputs.py": "scripts/production-v4-inputs.py"}
    for name in ("V4-INPUT-CHUNKS.json", "production-v4-rcnet-1-inputs.json", FIXED):
        sources[name] = f"{SHARED}/{name}"
    windows = platform == "windows-x86_64"
    directory = "windows" if windows else "linux"
    if kind == "runtime":
        sources["RECOVERY.md"] = "packaging/mainnet/RECOVERY.md"
        sources["STORAGE-RECOVERY.md"] = "docs/storage-recovery.md"
        sources["mainnet-storage-readiness.py"] = "scripts/mainnet_storage_readiness.py"
        launchers = ("START-WALLET.bat", "START-NODE.bat", "START-RUNTIME.ps1", "PREPARE-RUNTIME.ps1", "PREPARE-MINING.ps1", "PREPARE-MINING.bat") if windows else ("start-wallet.sh", "start-node.sh", "prepare-runtime.sh", "prepare-mining.sh")
        if not windows:
            sources["SERVICE-SETUP.md"] = "packaging/mainnet/linux/SERVICE-SETUP.md"
            for name in ("commonfoundry-mainnet-node.service", "commonfoundry-mainnet-storage.service", "commonfoundry-mainnet-storage.timer"):
                sources[name] = f"packaging/mainnet/linux/{name}"
            for name in ("POOL-SERVICE-SETUP.md", "commonfoundry-mainnet-pool.service",
                         "mainnet-pool-service.py", "mainnet-pool.json.example"):
                sources[name] = f"packaging/mainnet/linux/{name}"
    else:
        launchers = ("START-MINER.bat", "START-MINER.ps1") if windows else ("start-miner.sh",)
    sources.update({name: f"packaging/mainnet/{directory}/{name}" for name in launchers})
    name = "PREPARE-V4-INPUTS.ps1" if windows else "PREPARE-V4-INPUTS.sh"
    sources[name] = f"packaging/production-v4-testnet/{directory}/{name}"
    return sources


def validate_catalog(sources: dict[str, bytes], plan: dict) -> None:
    catalog = strict_json(sources["production-v4-rcnet-1-inputs.json"], "artifact catalog")
    chunks = strict_json(sources["V4-INPUT-CHUNKS.json"], "artifact chunks")
    if catalog.get("schema_version") != 1 or catalog.get("network") != "CommonFoundry RCNet-1" or chunks.get("release") != "v0.1.0-rc.1":
        raise Error("unsupported artifact provenance")
    entries = catalog.get("files", [])
    indexed = {row["name"]: row for row in entries}
    parts = {row["name"]: row for row in chunks.get("files", [])}
    if len(indexed) != 8 or len(entries) != 8 or len(parts) != 7 or len(chunks["files"]) != 7:
        raise Error("artifact inventory is incomplete or duplicated")
    expected = {"MODEL-V2.bank", FIXED} | {
        f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{extension}"
        for bank in range(3) for extension in ("row-major.codeword", "tree")
    }
    if set(indexed) != expected or set(parts) != expected - {FIXED}:
        raise Error("artifact inventory contains unexpected names")
    part_names = set()
    for name, entry in indexed.items():
        nonzero_hex(entry.get("sha256"), 64, "artifact SHA256")
        if type(entry.get("bytes")) is not int or entry["bytes"] <= 0:
            raise Error("invalid artifact size")
        if name == FIXED:
            if len(sources[FIXED]) != entry["bytes"] or hashlib.sha256(sources[FIXED]).hexdigest() != entry["sha256"]:
                raise Error("bundled fixed artifact record differs from catalog")
        elif name not in parts or any(parts[name].get(key) != entry.get(key) for key in ("bytes", "sha256")):
            raise Error("artifact chunk/catalog identities disagree")
        else:
            row = parts[name]
            relative = name if name == "MODEL-V2.bank" else "fixed/" + name
            roles = ["node", "miner", "pool-miner"] if name == "MODEL-V2.bank" else ["miner"]
            if row.get("relative_path") != relative or row.get("roles") != roles:
                raise Error("unsafe artifact path or role mapping")
            total = 0
            for part in row.get("parts", []):
                part_name = part.get("name")
                if not isinstance(part_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", part_name) or part_name.casefold() in part_names:
                    raise Error("unsafe or repeated download part name")
                part_names.add(part_name.casefold())
                nonzero_hex(part.get("sha256"), 64, "part SHA256")
                if type(part.get("bytes")) is not int or part["bytes"] <= 0:
                    raise Error("invalid part size")
                total += part["bytes"]
            if total != row["bytes"]:
                raise Error("download parts do not add up to artifact size")
    for role, name in (("bank", "MODEL-V2.bank"), ("fixed_record", FIXED)):
        identity = plan["payload"]["rules"]["artifacts"][role]
        if identity["bytes"] != indexed[name]["bytes"] or identity["sha256"] != indexed[name]["sha256"]:
            raise Error("artifact catalog does not match the mainnet plan")


def source_snapshot(repo: Path, commit: str, sources: dict[str, str], version: str) -> tuple[dict[str, bytes], int]:
    if integrity._run_git(repo, "rev-parse", "HEAD") != commit or integrity._run_git(repo, "status", "--porcelain", "--untracked-files=normal"):
        raise Error("mainnet packaging requires the exact clean frozen source commit")
    import tomllib
    for relative in ("crates/cmfd-node/Cargo.toml", "crates/cmfd-miner/Cargo.toml", "apps/wallet/src-tauri/Cargo.toml"):
        manifest = tomllib.loads(integrity._tracked_blob_at(repo, commit, relative).decode())
        if manifest["package"]["version"] != version:
            raise Error("package version does not match frozen node, wallet and miner versions")
    return ({name: integrity._tracked_blob_at(repo, commit, relative) for name, relative in sources.items()},
            int(integrity._run_git(repo, "show", "-s", "--format=%ct", commit)))


def copy_executable(source: Path, target: Path, platform: str) -> None:
    integrity._regular_file(source, "input executable")
    original = file_identity(source)
    size = original["bytes"]
    if size > integrity.MAX_RUNTIME_BINARY_BYTES:
        raise Error("input executable exceeds the release limit")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    if file_identity(target) != original:
        raise Error("input executable changed while copying")
    with target.open("rb") as handle:
        header = handle.read(integrity.MAX_EXECUTABLE_HEADER_BYTES)
    validator = integrity._validate_pe_x86_64 if platform == "windows-x86_64" else integrity._validate_elf_x86_64
    validator(header, size, source.name)
    target.chmod(0o755)


def assemble(args: argparse.Namespace) -> Path:
    integrity._require_native_runtime_platform(args.platform)
    commit = nonzero_hex(args.commit, 40, "source commit")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-mainnet\.[0-9]+)?", args.version):
        raise Error("use a mainnet version, not an RC/devnet version")
    if args.kind == "runtime" and (args.node is None or args.wallet is None or args.miner is not None):
        raise Error("runtime packages require node and wallet, not a miner executable")
    if args.kind == "miner" and (args.miner is None or args.node is not None or args.wallet is not None):
        raise Error("miner packages require only the miner executable")
    plan_bytes = read_regular(args.plan, 32 * 1024, "mainnet plan")
    plan = validate_plan(plan_bytes)
    manifest_bytes = read_regular(args.approval_manifest, MAX_INFO, "mainnet approval manifest")
    manifest = validate_plan_approvals(manifest_bytes, plan_bytes)
    validate_review_ancestry(args.repo, manifest["subject"]["review_source_commit"], commit)
    source_paths = package_sources(args.platform, args.kind)
    sources, epoch = source_snapshot(args.repo, commit, source_paths, args.version)
    validate_catalog(sources, plan)
    dashboard_manifest_bytes = read_regular(args.dashboard_manifest, MAX_INFO, "reviewed dashboard asset manifest")
    dashboard_manifest = validate_dashboard_manifest(dashboard_manifest_bytes, commit)
    assets = dashboard_assets(args.dashboard_dist, dashboard_manifest)
    cuda_pin = nonzero_hex(args.cuda_sha256, 64, "reviewed CUDA runtime SHA-256")
    name = f"commonfoundry-mainnet-{args.kind}-{args.platform}-v{args.version}"
    suffix = ".zip" if args.platform == "windows-x86_64" else ".tar.gz"
    output = args.output / (name + suffix)
    if output.exists() or output.is_symlink():
        raise Error(f"package already exists: {output}")
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mainnet-package-", dir=args.output) as temporary:
        stage = Path(temporary) / name
        stage.mkdir()
        for relative, data in sources.items():
            if relative.endswith(".bat"):
                data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            target = stage / relative
            target.write_bytes(data)
            target.chmod(0o755 if relative.endswith((".sh", ".bat")) else 0o644)
        sidecar = stage / "production-mainnet"
        sidecar.mkdir()
        (sidecar / "MAINNET-PLAN.json").write_bytes(plan_bytes)
        (sidecar / "MAINNET-APPROVALS.json").write_bytes(manifest_bytes)
        (sidecar / "DASHBOARD-ASSETS.json").write_bytes(dashboard_manifest_bytes)
        for relative, data in assets.items():
            target = stage / "dashboard" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o644)
        copy_cuda_runtime(args.cuda_runtime, stage / CUDA_RUNTIME, cuda_pin)
        extension = ".exe" if args.platform == "windows-x86_64" else ""
        binaries = {"cmfd-launch": args.launch}
        if args.kind == "runtime":
            binaries.update({"cmfd-node": args.node, "common-foundry-wallet": args.wallet})
        else:
            binaries["cmfd-miner"] = args.miner
        for role, source in binaries.items():
            copy_executable(source, stage / (role + extension), args.platform)
        worker_root = stage / "production-v4" if args.kind == "runtime" else stage
        copy_executable(args.replay_worker, worker_root / "cmfd-v4-replay", "linux-x86_64")
        copy_executable(args.relation_worker, worker_root / "real_bank0_relations", "linux-x86_64")
        before = {path.relative_to(stage).as_posix(): file_identity(path) for path in stage.rglob("*") if path.is_file()}
        executable_names = [role + extension for role in binaries] + [
            ("production-v4/" if args.kind == "runtime" else "") + worker
            for worker in ("cmfd-v4-replay", "real_bank0_relations")
        ]
        if len({before[name]["sha256"] for name in executable_names}) != len(executable_names):
            raise Error("different executable roles must not reuse the same binary")
        directories = {path.relative_to(stage).as_posix() for path in stage.rglob("*") if path.is_dir()}
        identities = {}
        common_info = None
        for role in binaries:
            executable = stage / (role + extension)
            if role == "cmfd-launch":
                schedule = strict_json(native_output(executable, ["schedule"]), "launch schedule")
                validate_schedule(schedule, plan)
                identities[role] = schedule
                continue
            version = native_output(executable, ["--version"]).decode().strip().split()
            if not version or version[-1] != args.version:
                raise Error(f"{role} version mismatch")
            data = native_output(executable, ["runtime-identity" if role == "common-foundry-wallet" else "mainnet-launch-info"])
            if role == "common-foundry-wallet":
                wrapper = strict_json(data, "wallet prelaunch identity")
                if set(wrapper) != {"schema", "role", "package_version", "launch_info_base64"} or wrapper.get("schema") != "CMFD_WALLET_PRELAUNCH_IDENTITY_V1" or wrapper.get("role") != role or wrapper.get("package_version") != args.version:
                    raise Error("wallet did not attest its prelaunch identity")
                try:
                    data = base64.b64decode(wrapper["launch_info_base64"], validate=True)
                except (ValueError, TypeError) as error:
                    raise Error("invalid wallet identity encoding") from error
            info = validate_info(data, plan, commit)
            bind_plan_approvals(manifest, manifest_bytes, info)
            if common_info is not None and info != common_info:
                raise Error("runtime activation identities disagree")
            common_info = info
            identities[role] = info
        after = {path.relative_to(stage).as_posix(): file_identity(path) for path in stage.rglob("*") if path.is_file()}
        if before != after or directories != {path.relative_to(stage).as_posix() for path in stage.rglob("*") if path.is_dir()}:
            raise Error("identity commands modified the staged package")
        receipt = {"schema": "CMFD_MAINNET_PACKAGE_ATTESTATION_V1", "kind": args.kind,
                   "platform": args.platform, "package_version": args.version, "source_commit": commit,
                   "source_date_epoch": epoch, "launch_plan_digest": plan["launch_plan_digest"],
                   "network_id": plan["network_id"], "files": before, "native_identities": identities,
                   "artifact_source_release": "v0.1.0-rc.1", "release_approved": False}
        (stage / "MAINNET-PACKAGE.json").write_bytes(canonical(receipt))
        # Detect a concurrent checkout change before publishing an archive.
        source_snapshot(args.repo, commit, source_paths, args.version)
        writer = integrity.create_deterministic_zip if suffix == ".zip" else integrity.create_deterministic_tar_gz
        writer(stage, output, epoch)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--platform", choices=PLATFORMS, required=True)
    parser.add_argument("--kind", choices=("runtime", "miner"), required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    for name in ("plan", "approval-manifest", "output", "launch", "replay-worker", "relation-worker",
                 "dashboard-dist", "dashboard-manifest", "cuda-runtime"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--cuda-sha256", required=True)
    for name in ("node", "wallet", "miner"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path):
            if not value.is_absolute():
                parser.error(f"--{name} must be an absolute path")
    try:
        output = assemble(args)
        print(json.dumps({"package": str(output), **file_identity(output), "release_approved": False}))
    except (Error, OSError, KeyError, TypeError, ValueError) as error:
        parser.exit(1, f"Mainnet packaging failed: {error}\n")


if __name__ == "__main__":
    main()
