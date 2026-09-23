#!/usr/bin/env python3
"""Offline four-package mainnet preflight. Never extracts or executes archive files.

Checks package bytes against the frozen source and reconciles native producer
receipts. A consistent producer receipt is NOT independent reproduction, a
signature, a cryptographic review, or authorization to launch.
"""
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile

import package_mainnet as package

integrity = package.integrity
Error = package.Error
RECEIPT = "MAINNET-PACKAGE.json"
PLAN = "production-mainnet/MAINNET-PLAN.json"
APPROVALS = "production-mainnet/MAINNET-APPROVALS.json"
MAX_ARCHIVE_BYTES = 3 * 1024 ** 3


def expected_layout(platform: str, kind: str, sources: dict[str, bytes], plan: bytes,
                    dashboard_manifest_bytes: bytes, dashboard_manifest: dict):
    expected = dict(sources)
    expected[PLAN] = plan
    expected[package.DASHBOARD_MANIFEST] = dashboard_manifest_bytes
    expected[package.CUDA_RUNTIME] = None
    asset_identities = {"dashboard/" + name: identity for name, identity in dashboard_manifest["files"].items()}
    expected.update({name: None for name in asset_identities})
    extension = ".exe" if platform == "windows-x86_64" else ""
    roles = ["cmfd-launch", "cmfd-node", "common-foundry-wallet"] if kind == "runtime" else ["cmfd-launch", "cmfd-miner"]
    executable_platforms = {role + extension: platform for role in roles}
    worker_root = "production-v4/" if kind == "runtime" else ""
    executable_platforms.update({worker_root + name: "linux-x86_64" for name in ("cmfd-v4-replay", "real_bank0_relations")})
    for name in executable_platforms:
        expected[name] = None
    expected[RECEIPT] = None
    expected[APPROVALS] = None
    for name, data in list(expected.items()):
        if name.endswith(".bat"):
            expected[name] = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    directories = {""}
    for name in expected:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent
    return expected, directories, executable_platforms, asset_identities


def member_mode(name: str, directory: bool, executables: dict[str, str]) -> int:
    return 0o755 if directory or name in executables or name.endswith((".bat", ".sh")) else 0o644


def member_limit(name: str, expected: dict, executables: dict, assets: dict) -> int:
    if name in executables:
        return integrity.MAX_RUNTIME_BINARY_BYTES
    if name == package.CUDA_RUNTIME:
        return package.MAX_CUDA_BYTES
    if name in assets:
        return assets[name]["bytes"]
    if name in (RECEIPT, APPROVALS):
        return package.MAX_INFO
    return len(expected[name])


def read_member(stream, name: str, size: int, expected: dict, executables: dict,
                assets: dict, cuda_sha256: str) -> dict:
    limit = member_limit(name, expected, executables, assets)
    captured_bytes = (integrity.MAX_EXECUTABLE_HEADER_BYTES if name in executables or name == package.CUDA_RUNTIME
                      else 0 if name in assets else limit)
    size, sha256, _, data = integrity._stream_sha256(
        stream, expected_size=size, maximum_size=limit,
        label=f"mainnet package {name}", capture_bytes=captured_bytes,
    )
    if expected[name] is not None and data != expected[name]:
        raise Error(f"mainnet package file differs from frozen source or plan: {name}")
    if name in executables:
        check = integrity._validate_pe_x86_64 if executables[name] == "windows-x86_64" else integrity._validate_elf_x86_64
        check(data, size, name)
    elif name == package.CUDA_RUNTIME:
        if sha256 != cuda_sha256:
            raise Error("packaged CUDA runtime differs from the reviewed SHA-256 pin")
        package.validate_cuda_runtime_header(data, size)
    elif name in assets and {"bytes": size, "sha256": sha256} != assets[name]:
        raise Error(f"packaged dashboard asset differs from reviewed manifest: {name}")
    return {"bytes": size, "sha256": sha256, "captured": data if name in (RECEIPT, APPROVALS) else None}


def inspect_archive(path: Path, platform: str, root: str, expected: dict, directories: set,
                    executables: dict, assets: dict, cuda_sha256: str, epoch: int):
    # Sort the physical directory name (with its slash), just like the archive
    # writer. For example production-v4-inputs.py precedes production-v4/.
    ordered = sorted(set(expected) | directories, key=lambda name: name + ("/" if name in directories else ""))
    rows = {}
    with integrity._stable_regular_handle(path, "mainnet package archive") as (_, raw, opened):
        if opened.st_size > MAX_ARCHIVE_BYTES:
            raise Error("mainnet archive exceeds its compressed byte limit")
        archive_sha256 = integrity._sha256_handle(raw)
        if platform == "windows-x86_64":
            central, length, count = integrity._validate_zip_framing(
                raw, "mainnet ZIP", maximum_entries=len(ordered), maximum_central_bytes=64 * 1024,
            )
            with zipfile.ZipFile(raw) as archive:
                members = archive.infolist()
                integrity._validate_zip_local_layout(
                    raw, members=members, central_offset=central, central_size=length,
                    expected_entries=count, label="mainnet ZIP",
                )
                names = [root + ("/" + name if name else "") + ("/" if name in directories else "") for name in ordered]
                if archive.comment or [member.filename for member in members] != names:
                    raise Error("mainnet ZIP inventory is missing, duplicated, reordered or unexpected")
                for name, member in zip(ordered, members, strict=True):
                    directory = name in directories
                    mode = member_mode(name, directory, executables)
                    attributes = ((stat.S_IFDIR if directory else stat.S_IFREG) | mode) << 16
                    if directory:
                        attributes |= 0x10
                    if (member.external_attr != attributes or member.create_system != 3
                        or member.compress_type != zipfile.ZIP_DEFLATED or member.comment
                        or member.extra != integrity._zip64_extra(member) or member.flag_bits != 0
                        or member.date_time != integrity._zip_datetime(epoch)
                        or member.is_dir() != directory):
                        raise Error(f"mainnet ZIP metadata is not canonical: {name}")
                    if directory:
                        if member.file_size or member.CRC or archive.read(member):
                            raise Error("mainnet ZIP directory has content")
                    else:
                        with archive.open(member) as stream:
                            rows[name] = read_member(stream, name, member.file_size, expected, executables, assets, cuda_sha256)
        else:
            specifications = []
            for name in ordered:
                directory = name in directories
                exact = 0 if directory else len(expected[name]) if expected[name] is not None else None
                maximum = 0 if directory else member_limit(name, expected, executables, assets)
                specifications.append((root + ("/" + name if name else ""), directory, exact, maximum,
                                       member_mode(name, directory, executables)))
            members, _, _, framing_digest = integrity._scan_canonical_tar_gz(
                raw, expected=specifications, label="mainnet tar.gz", maximum_members=len(ordered), expected_epoch=epoch,
            )
            if framing_digest != archive_sha256:
                raise Error("mainnet tar.gz changed during framing validation")
            raw.seek(0)
            with tarfile.open(fileobj=raw, mode="r:gz") as archive:
                for name, member in zip(ordered, members, strict=True):
                    if name in directories:
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise Error("mainnet tar.gz member is not readable")
                    with stream:
                        rows[name] = read_member(stream, name, member.size, expected, executables, assets, cuda_sha256)
        if integrity._sha256_handle(raw) != archive_sha256:
            raise Error("mainnet archive changed while inspected")
    return rows, {"bytes": opened.st_size, "sha256": archive_sha256}


def validate_receipt(rows: dict, platform: str, kind: str, plan: dict, commit: str, version: str, epoch: int):
    data = rows[RECEIPT]["captured"]
    receipt = package.strict_json(data, "mainnet package receipt")
    keys = {"schema", "kind", "platform", "package_version", "source_commit", "source_date_epoch",
            "launch_plan_digest", "network_id", "files", "native_identities", "artifact_source_release", "release_approved"}
    required = {"schema": "CMFD_MAINNET_PACKAGE_ATTESTATION_V1", "kind": kind, "platform": platform,
                "package_version": version, "source_commit": commit, "source_date_epoch": epoch,
                "launch_plan_digest": plan["launch_plan_digest"], "network_id": plan["network_id"],
                "artifact_source_release": "v0.1.0-rc.1"}
    if (set(receipt) != keys or package.canonical(receipt) != data
        or any(receipt.get(key) != value for key, value in required.items())
        or receipt["release_approved"] is not False or type(receipt["source_date_epoch"]) is not int):
        raise Error("package receipt does not match the expected source, plan, version and platform")
    files = {name: {"bytes": row["bytes"], "sha256": row["sha256"]} for name, row in rows.items() if name != RECEIPT}
    if receipt["files"] != files:
        raise Error("package receipt file hashes do not match the actual archive")
    for row in receipt["files"].values():
        if set(row) != {"bytes", "sha256"} or type(row["bytes"]) is not int:
            raise Error("package receipt has malformed file identities")
    native = receipt["native_identities"]
    roles = {"cmfd-launch", "cmfd-node", "common-foundry-wallet"} if kind == "runtime" else {"cmfd-launch", "cmfd-miner"}
    if not isinstance(native, dict) or set(native) != roles:
        raise Error("package receipt native roles are incomplete")
    extension = ".exe" if platform == "windows-x86_64" else ""
    prefix = "production-v4/" if kind == "runtime" else ""
    binary_names = [role + extension for role in roles] + [prefix + worker for worker in ("cmfd-v4-replay", "real_bank0_relations")]
    if len({files[name]["sha256"] for name in binary_names}) != len(binary_names):
        raise Error("package reuses one binary in distinct executable roles")
    package.validate_schedule(native["cmfd-launch"], plan)
    common = None
    for role in sorted(roles - {"cmfd-launch"}):
        info = package.validate_info(package.canonical(native[role]), plan, commit)
        if common is not None and info != common:
            raise Error("native producer receipts disagree on activation identity")
        common = info
    return receipt, common


def inspect_package(path: Path, repo: Path, platform: str, kind: str, plan_bytes: bytes,
                    commit: str, version: str, dashboard_manifest_bytes: bytes,
                    dashboard_manifest: dict, cuda_sha256: str):
    plan = package.validate_plan(plan_bytes)
    sources, epoch = package.source_snapshot(repo, commit, package.package_sources(platform, kind), version)
    package.validate_catalog(sources, plan)
    expected, directories, executables, assets = expected_layout(
        platform, kind, sources, plan_bytes, dashboard_manifest_bytes, dashboard_manifest)
    root = f"commonfoundry-mainnet-{kind}-{platform}-v{version}"
    suffix = ".zip" if platform == "windows-x86_64" else ".tar.gz"
    if path.name != root + suffix:
        raise Error("mainnet package filename does not match its requested role/platform/version")
    rows, identity = inspect_archive(path, platform, root, expected, directories,
                                     executables, assets, cuda_sha256, epoch)
    receipt, info = validate_receipt(rows, platform, kind, plan, commit, version, epoch)
    manifest_data = rows[APPROVALS]["captured"]
    manifest = package.validate_plan_approvals(manifest_data, plan_bytes)
    package.validate_review_ancestry(repo, manifest["subject"]["review_source_commit"], commit)
    package.bind_plan_approvals(manifest, manifest_data, info)
    return {"name": path.name, **identity, "receipt": receipt, "info": info}


def verify_set(repo: Path, commit: str, version: str, plan_path: Path, archives: dict,
               dashboard_manifest_path: Path, cuda_sha256: str) -> dict:
    package.nonzero_hex(commit, 40, "source commit")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-mainnet\.[0-9]+)?", version):
        raise Error("mainnet preflight does not accept an RC/devnet version")
    expected = {(platform, kind) for platform in package.PLATFORMS for kind in ("runtime", "miner")}
    if set(archives) != expected:
        raise Error("mainnet preflight requires exactly four platform/role packages")
    plan_bytes = package.read_regular(plan_path, 32 * 1024, "mainnet plan")
    plan = package.validate_plan(plan_bytes)
    dashboard_manifest_bytes = package.read_regular(dashboard_manifest_path, package.MAX_INFO, "reviewed dashboard asset manifest")
    dashboard_manifest = package.validate_dashboard_manifest(dashboard_manifest_bytes, commit)
    cuda_sha256 = package.nonzero_hex(cuda_sha256, 64, "reviewed CUDA runtime SHA-256")
    packages = {key: inspect_package(archives[key], repo, *key, plan_bytes, commit, version,
                                     dashboard_manifest_bytes, dashboard_manifest, cuda_sha256)
                for key in sorted(expected)}
    first = next(iter(packages.values()))
    common_info = first["info"]
    schedule = first["receipt"]["native_identities"]["cmfd-launch"]
    workers = None
    pool_assets = None
    for (platform, kind), inspected in packages.items():
        receipt = inspected["receipt"]
        if inspected["info"] != common_info or receipt["native_identities"]["cmfd-launch"] != schedule:
            raise Error("mainnet packages disagree on plan, activation evidence or launch policy")
        prefix = "production-v4/" if kind == "runtime" else ""
        current_workers = {name: receipt["files"][prefix + name] for name in ("cmfd-v4-replay", "real_bank0_relations")}
        if workers is not None and workers != current_workers:
            raise Error("mainnet packages contain different Linux/WSL mining workers")
        workers = current_workers
        current_assets = {name: receipt["files"][name] for name in
                          [package.CUDA_RUNTIME, package.DASHBOARD_MANIFEST,
                           *("dashboard/" + asset for asset in dashboard_manifest["files"])]}
        if pool_assets is not None and pool_assets != current_assets:
            raise Error("mainnet packages contain different pinned pool runtime assets")
        pool_assets = current_assets
    for platform in package.PLATFORMS:
        helper = "cmfd-launch.exe" if platform == "windows-x86_64" else "cmfd-launch"
        if packages[platform, "runtime"]["receipt"]["files"][helper] != packages[platform, "miner"]["receipt"]["files"][helper]:
            raise Error("runtime and miner packages contain different native launch helpers")
    # All source snapshots and package observations refer to the same frozen tree.
    package.source_snapshot(repo, commit, package.package_sources("linux-x86_64", "runtime"), version)
    for key, inspected in packages.items():
        if package.file_identity(archives[key]) != {field: inspected[field] for field in ("bytes", "sha256")}:
            raise Error("mainnet archive set changed during reconciliation")
    return {"schema": "CMFD_MAINNET_PACKAGE_PREFLIGHT_V1", "source_commit": commit, "package_version": version,
            "launch_plan_digest": plan["launch_plan_digest"], "network_id": plan["network_id"],
            "activation_evidence_sha256": common_info["activation_evidence_sha256"],
            "mainnet_approval_manifest_sha256": common_info["mainnet_approval_manifest_sha256"],
            "packages": [{key: row[key] for key in ("name", "bytes", "sha256")} for row in packages.values()],
            "mining_workers": workers, "pool_runtime_assets": pool_assets,
            "consistent": True, "release_approved": False,
            "independent_reproduction_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--dashboard-manifest", type=Path, required=True)
    parser.add_argument("--cuda-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    for platform in ("windows", "linux"):
        for kind in ("runtime", "miner"):
            parser.add_argument(f"--{platform}-{kind}", type=Path, required=True)
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path) and not value.is_absolute():
            parser.error(f"--{name} must be an absolute path")
    try:
        archives = {(platform + "-x86_64", kind): getattr(args, platform + "_" + kind)
                    for platform in ("windows", "linux") for kind in ("runtime", "miner")}
        report = verify_set(args.repo, args.commit, args.version, args.plan, archives,
                            args.dashboard_manifest, args.cuda_sha256)
        integrity._write_new(args.output, package.canonical(report))
        print(package.canonical(report).decode(), end="")
    except (Error, OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile, tarfile.TarError) as error:
        parser.exit(1, f"Mainnet package preflight failed: {error}\n")


if __name__ == "__main__":
    main()
