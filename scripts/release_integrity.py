#!/usr/bin/env python3
"""Fail-closed build receipts, deterministic archives, and release manifests."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

RECEIPT_SCHEMA = "CMFD_NATIVE_BUILD_RECEIPT_V1"
BUILDINFO_SCHEMA = "CMFD_RELEASE_BUILDINFO_V1"
BUILDINFO_NAME = "BUILDINFO.json"
CHECKSUM_NAME = "SHA256SUMS.txt"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_BUILDINFO_BYTES = 4 * 1024 * 1024
MAX_DEB_BYTES = 512 * 1024 * 1024
MAX_DEB_MEMBERS = 100_000
MAX_RELEASE_GATE_JSON_BYTES = 1024 * 1024
FULL_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
HEX256_RE = re.compile(r"[0-9a-f]{64}\Z")
PRODUCTION_RC_NETWORK_INFO_NAME = "NETWORK-INFO.json"
PRODUCTION_V3_ACTIVATION_NAME = "PRODUCTION-V3-ACTIVATION.json"
PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME = (
    "PRODUCTION-V3-QUALIFICATION-MANIFEST.json"
)
PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME = (
    "PRODUCTION-V3-FRESH-PROCESS-VERIFIER.bin"
)
PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME = (
    "PRODUCTION-V3-FRESH-PROCESS-VERIFIER-REPORT.json"
)
RECEIPT_FIELDS = (
    "SCHEMA",
    "TRUST_SCOPE",
    "KIND",
    "GIT_COMMIT",
    "SOURCE_FILES",
    "SOURCE_TREE_SHA256",
    "BUILD_SCRIPT",
    "BUILD_SCRIPT_SHA256",
    "LIBRARY_NAME",
    "LIBRARY_SHA256",
    "LIBRARY_SIZE",
    "TOOLCHAIN",
    "TARGET",
    "ARCHITECTURES",
    "SOURCE_DATE_EPOCH",
    "RECEIPT_SHA256",
)
NATIVE_SOURCES = {
    "cuda": (
        "gpu/CMakeLists.txt",
        "gpu/forgematrix_v2_miner.cu",
    ),
    "opencl": (
        "gpu/CMakeLists.txt",
        "gpu/forgematrix_v2_opencl.cpp",
    ),
}
DEB_AR_MEMBERS = ("debian-binary", "control.tar.gz", "data.tar.gz")


class IntegrityError(RuntimeError):
    """An input failed a release-integrity invariant."""


def is_production_rc_label(label: str) -> bool:
    normalized = label.strip().lower()
    if not normalized or "devnet" in normalized or "testnet" in normalized:
        return False
    tokens = [token for token in re.split(r"[^a-z0-9]+", normalized) if token]
    return (
        "production-rc" in normalized
        or "production_rc" in normalized
        or "mainnet-rc" in normalized
        or any(re.fullmatch(r"rc[0-9]*", token) for token in tokens)
    )


def _bounded_json_object(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    path = _regular_file(path, label)
    data = path.read_bytes()
    if len(data) > MAX_RELEASE_GATE_JSON_BYTES:
        raise IntegrityError(f"{label} exceeds its size limit")
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrityError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise IntegrityError(f"{label} must contain a JSON object")
    return value, data


def validate_production_rc_artifacts(
    *, version: str, commit: str, stage_files: dict[str, Path]
) -> None:
    if not is_production_rc_label(version):
        return

    required = {
        PRODUCTION_RC_NETWORK_INFO_NAME,
        PRODUCTION_V3_ACTIVATION_NAME,
        PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME,
        PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME,
        PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME,
    }
    missing = sorted(required - set(stage_files))
    if missing:
        raise IntegrityError(
            "production RC release gate is blocked; "
            f"missing compiled activation artifacts: {missing}"
        )

    network_info, _ = _bounded_json_object(
        stage_files[PRODUCTION_RC_NETWORK_INFO_NAME], "compiled network information"
    )
    evidence, evidence_bytes = _bounded_json_object(
        stage_files[PRODUCTION_V3_ACTIVATION_NAME], "ProductionV3 activation evidence"
    )
    qualification_manifest, qualification_manifest_bytes = _bounded_json_object(
        stage_files[PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME],
        "ProductionV3 qualification manifest",
    )
    verifier_binary = _regular_file(
        stage_files[PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME],
        "ProductionV3 fresh-process verifier binary",
    )
    verifier_report, verifier_report_bytes = _bounded_json_object(
        stage_files[PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME],
        "ProductionV3 fresh-process verifier report",
    )
    qualification_manifest_sha256 = _sha256_bytes(qualification_manifest_bytes)
    verifier_binary_sha256 = _sha256_file(verifier_binary)
    verifier_report_sha256 = _sha256_bytes(verifier_report_bytes)
    network = network_info.get("network")
    proof = network_info.get("proof_of_work")
    if not isinstance(network, dict) or network.get("name") != "CommonFoundry RCNet-1":
        raise IntegrityError("production RC compiled network profile is not RCNet-1")
    if network.get("network_id") != "72" * 32:
        raise IntegrityError("production RC compiled network ID is not RCNet-1")
    if not isinstance(proof, dict) or proof.get("selection") != "ProductionV3":
        raise IntegrityError("production RC compiled proof selection is not ProductionV3")
    if proof.get("build_source_commit") != commit:
        raise IntegrityError(
            "production RC compiled build source commit does not match the checked-out commit"
        )
    if proof.get("activation_evidence_sha256") != _sha256_bytes(evidence_bytes):
        raise IntegrityError(
            "compiled ProductionV3 selection is not bound to the staged activation evidence"
        )

    qualification_source_commit = qualification_manifest.get("source_commit")
    if (
        not isinstance(qualification_source_commit, str)
        or not FULL_COMMIT_RE.fullmatch(qualification_source_commit)
        or set(qualification_source_commit) == {"0"}
    ):
        raise IntegrityError(
            "ProductionV3 qualification manifest has an invalid source commit"
        )

    expected_evidence = {
        "schema": "CMFD_PRODUCTION_V3_ACTIVATION_V1",
        "source_commit": commit,
        "qualification_source_commit": qualification_source_commit,
        "network_profile": "RCNet-1",
        "proof_selection": "ProductionV3",
        "qualification_manifest_sha256": qualification_manifest_sha256,
        "fresh_process_verifier_binary_sha256": verifier_binary_sha256,
        "fresh_process_verifier_report_sha256": verifier_report_sha256,
    }
    for field, expected in expected_evidence.items():
        if evidence.get(field) != expected:
            raise IntegrityError(
                f"ProductionV3 activation evidence has invalid {field}"
            )
    if qualification_manifest.get("schema") != (
        "CMFD_PRODUCTION_V3_QUALIFICATION_MANIFEST_V1"
    ):
        raise IntegrityError("ProductionV3 qualification manifest schema is unsupported")
    if qualification_manifest.get("status") != (
        "qualification_complete_activation_disabled"
    ):
        raise IntegrityError("ProductionV3 qualification manifest status is invalid")
    if (
        qualification_manifest.get("network_profile") != "RCNet-1"
        or qualification_manifest.get("proof_selection") != "ProductionV3"
    ):
        raise IntegrityError("ProductionV3 qualification manifest identity is invalid")

    qualification = qualification_manifest.get("qualification")
    if not isinstance(qualification, dict):
        raise IntegrityError("ProductionV3 qualification manifest geometry is invalid")
    scratch_floor = qualification.get("scratch_floor_bytes")
    scratch_margin = qualification.get("scratch_margin_bytes")
    required_scratch = qualification.get("required_scratch_bytes")
    available_scratch = qualification.get("available_scratch_bytes_before_producer")
    producer_pid = qualification.get("producer_process_id")
    verifier_pid = qualification.get("verifier_process_id")
    if (
        qualification.get("padded_variables") != 33
        or qualification.get("composed_claims") != 134
        or qualification.get("fresh_process_verifier") is not True
        or scratch_floor != 53_687_091_200
        or not isinstance(scratch_margin, int)
        or isinstance(scratch_margin, bool)
        or scratch_margin <= 0
        or required_scratch != scratch_floor + scratch_margin
        or not isinstance(available_scratch, int)
        or isinstance(available_scratch, bool)
        or available_scratch < required_scratch
        or not isinstance(producer_pid, int)
        or isinstance(producer_pid, bool)
        or producer_pid <= 0
        or not isinstance(verifier_pid, int)
        or isinstance(verifier_pid, bool)
        or verifier_pid <= 0
        or producer_pid == verifier_pid
    ):
        raise IntegrityError("ProductionV3 qualification manifest geometry is invalid")

    if qualification_manifest.get("journal_semantics") != {
        "diagnostic_only": True,
        "completion_marker": False,
        "resumable": False,
        "used_as_completion_evidence": False,
    } or qualification_manifest.get("completion_evidence") != {
        "producer_report": True,
        "fresh_verifier_report": True,
    }:
        raise IntegrityError("ProductionV3 qualification completion semantics are invalid")

    artifacts = qualification_manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise IntegrityError("ProductionV3 qualification manifest artifacts are missing")
    required_bound_roles = {
        "bank",
        "cargo",
        "cargo_config",
        "consensus_executable",
        "record_v2",
        "request",
        "proof",
        "producer_report",
        "journal",
        "rustc",
        "fresh_process_verifier_binary",
        "verifier_report",
    }
    if not required_bound_roles.issubset(artifacts):
        raise IntegrityError(
            "ProductionV3 qualification manifest omits required artifact bindings"
        )
    for role in required_bound_roles:
        row = artifacts.get(role)
        if not isinstance(row, dict):
            raise IntegrityError(
                f"ProductionV3 qualification manifest has invalid {role} binding"
            )
        digest = row.get("sha256")
        size = row.get("bytes")
        if (
            not isinstance(digest, str)
            or not HEX256_RE.fullmatch(digest)
            or set(digest) == {"0"}
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise IntegrityError(
                f"ProductionV3 qualification manifest has invalid {role} binding"
            )

    toolchain = qualification_manifest.get("toolchain")
    if not isinstance(toolchain, dict):
        raise IntegrityError("ProductionV3 qualification toolchain identity is missing")
    toolchain_identity = {
        "cargo_sha256": artifacts["cargo"]["sha256"],
        "cargo_version": toolchain.get("cargo_version"),
        "rustc_sha256": artifacts["rustc"]["sha256"],
        "rustc_version": toolchain.get("rustc_version"),
        "cargo_config_sha256": artifacts["cargo_config"]["sha256"],
        "environment_policy": "CMFD_QUALIFICATION_ALLOWLIST_V1",
    }
    if (
        not isinstance(toolchain_identity["cargo_version"], str)
        or not toolchain_identity["cargo_version"]
        or not isinstance(toolchain_identity["rustc_version"], str)
        or not toolchain_identity["rustc_version"]
        or toolchain.get("cargo_sha256") != toolchain_identity["cargo_sha256"]
        or toolchain.get("rustc_sha256") != toolchain_identity["rustc_sha256"]
        or toolchain.get("cargo_config_sha256")
        != toolchain_identity["cargo_config_sha256"]
        or toolchain.get("environment_policy")
        != toolchain_identity["environment_policy"]
        or toolchain.get("identity_sha256")
        != _sha256_bytes(
            json.dumps(
                toolchain_identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        )
    ):
        raise IntegrityError("ProductionV3 qualification toolchain identity is invalid")

    staged_bindings = {
        "fresh_process_verifier_binary": (
            PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME,
            verifier_binary.stat().st_size,
            verifier_binary_sha256,
        ),
        "verifier_report": (
            PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME,
            len(verifier_report_bytes),
            verifier_report_sha256,
        ),
    }
    for role, (name, size, digest) in staged_bindings.items():
        row = artifacts[role]
        if (
            row.get("file_name") != name
            or row.get("bytes") != size
            or row.get("sha256") != digest
        ):
            raise IntegrityError(
                f"staged ProductionV3 {role} does not match the qualification manifest"
            )

    verifier_expectations = {
        "report_version": 2,
        "network_id": "72" * 32,
        "verifier_only": True,
        "producer_report_checked": True,
        "qualification_journal_checked": True,
    }
    for field, expected in verifier_expectations.items():
        if verifier_report.get(field) != expected:
            raise IntegrityError(
                f"ProductionV3 fresh-process verifier report has invalid {field}"
            )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _regular_file(path: Path, label: str) -> Path:
    candidate = _absolute_path(path)
    try:
        mode = candidate.lstat().st_mode
    except OSError as error:
        raise IntegrityError(f"{label} is missing: {candidate}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise IntegrityError(f"{label} must be a regular, non-symlink file")
    return candidate


def _regular_directory(path: Path, label: str) -> Path:
    candidate = _absolute_path(path)
    try:
        mode = candidate.lstat().st_mode
    except OSError as error:
        raise IntegrityError(f"{label} is missing: {candidate}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise IntegrityError(f"{label} must be a regular, non-symlink directory")
    return candidate


def _run_git(repo: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", b"").decode("utf-8", "replace").strip()
        raise IntegrityError(f"git {' '.join(arguments)} failed: {detail}") from error
    return result.stdout.decode("utf-8", "strict").strip()


def _run_git_bytes(repo: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", b"").decode("utf-8", "replace").strip()
        raise IntegrityError(f"git {' '.join(arguments)} failed: {detail}") from error
    return result.stdout


def _full_commit(value: str) -> str:
    candidate = value.strip().lower()
    if not FULL_COMMIT_RE.fullmatch(candidate):
        raise IntegrityError("expected commit must be a full lowercase Git object ID")
    return candidate


def _assert_clean_exact_repo(repo: Path, expected_commit: str) -> str:
    repo = repo.resolve(strict=True)
    expected = _full_commit(expected_commit)
    actual = _run_git(repo, "rev-parse", "HEAD").lower()
    if actual != expected:
        raise IntegrityError(f"HEAD is {actual}, expected {expected}")
    status_output = _run_git(
        repo, "status", "--porcelain=v1", "--untracked-files=normal"
    )
    if status_output:
        first = status_output.splitlines()[0]
        raise IntegrityError(f"source checkout is dirty: {first}")
    return actual


def _commit_epoch(repo: Path) -> int:
    value = _run_git(repo, "show", "-s", "--format=%ct", "HEAD")
    try:
        epoch = int(value, 10)
    except ValueError as error:
        raise IntegrityError("Git returned an invalid commit timestamp") from error
    if epoch < 0:
        raise IntegrityError("SOURCE_DATE_EPOCH cannot be negative")
    return epoch


def _source_date_epoch(repo: Path | None, explicit: str | int | None) -> int:
    value: str | int | None = explicit
    if value is None:
        value = os.environ.get("SOURCE_DATE_EPOCH")
    if value is None:
        if repo is None:
            raise IntegrityError("SOURCE_DATE_EPOCH is required")
        return _commit_epoch(repo)
    try:
        epoch = int(value)
    except (TypeError, ValueError) as error:
        raise IntegrityError("SOURCE_DATE_EPOCH must be a base-10 integer") from error
    if epoch < 0:
        raise IntegrityError("SOURCE_DATE_EPOCH cannot be negative")
    return epoch


def _safe_repo_relative(value: str) -> str:
    if not value or "\\" in value or "\0" in value or "\n" in value or "\r" in value:
        raise IntegrityError(f"unsafe repository-relative path: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise IntegrityError(f"unsafe repository-relative path: {value!r}")
    return path.as_posix()


def _tracked_file(repo: Path, relative: str) -> Path:
    safe = _safe_repo_relative(relative)
    _run_git(repo, "ls-files", "--error-unmatch", "--", safe)
    path = repo / PurePosixPath(safe)
    if not path.is_file() or path.is_symlink():
        raise IntegrityError(f"tracked input is not a regular file: {safe}")
    return path


def _tracked_blob(repo: Path, relative: str) -> bytes:
    safe = _safe_repo_relative(relative)
    _tracked_file(repo, safe)
    return _run_git_bytes(repo, "cat-file", "blob", f"HEAD:{safe}")


def _tracked_input_file(repo: Path, path: Path, label: str) -> Path:
    candidate = _absolute_path(path if path.is_absolute() else repo / path)
    try:
        relative = candidate.relative_to(repo).as_posix()
    except ValueError as error:
        raise IntegrityError(f"{label} must be inside the source repository") from error
    try:
        return _tracked_file(repo, relative)
    except IntegrityError as error:
        raise IntegrityError(
            f"{label} must be a tracked regular file at the expected commit"
        ) from error


def _native_source_identity(repo: Path, kind: str) -> tuple[tuple[str, ...], str]:
    try:
        source_files = NATIVE_SOURCES[kind]
    except KeyError as error:
        raise IntegrityError(f"unsupported native backend: {kind}") from error
    digest = hashlib.sha256()
    digest.update(b"CMFD-NATIVE-SOURCE-TREE-V1\0")
    for relative in source_files:
        _tracked_file(repo, relative)
        name = relative.encode("utf-8")
        data = _tracked_blob(repo, relative)
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return source_files, digest.hexdigest()


def _single_line(label: str, value: str) -> str:
    normalized = " ".join(value.split())
    if not normalized or "\0" in normalized or "\n" in normalized or "\r" in normalized:
        raise IntegrityError(f"{label} must be a non-empty single-line value")
    return normalized


def _canonical_receipt(fields: dict[str, str]) -> bytes:
    if tuple(fields) != RECEIPT_FIELDS:
        raise IntegrityError(
            "native build receipt fields are missing, reordered, or unexpected"
        )
    return ("".join(f"{key}={fields[key]}\n" for key in RECEIPT_FIELDS)).encode("utf-8")


def _receipt_digest(fields: dict[str, str]) -> str:
    body = "".join(f"{key}={fields[key]}\n" for key in RECEIPT_FIELDS[:-1]).encode(
        "utf-8"
    )
    return _sha256_bytes(b"CMFD-NATIVE-BUILD-RECEIPT-V1\0" + body)


def _read_receipt(path: Path) -> dict[str, str]:
    path = _regular_file(path, "native build receipt")
    data = path.read_bytes()
    if len(data) > MAX_RECEIPT_BYTES:
        raise IntegrityError("native build receipt exceeds its size limit")
    if b"\r" in data or not data.endswith(b"\n"):
        raise IntegrityError(
            "native build receipt is not canonical LF-terminated UTF-8"
        )
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise IntegrityError("native build receipt is not UTF-8") from error
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            raise IntegrityError("native build receipt contains a malformed line")
        key, value = line.split("=", 1)
        if key in fields:
            raise IntegrityError(f"native build receipt repeats {key}")
        fields[key] = value
    if tuple(fields) != RECEIPT_FIELDS or _canonical_receipt(fields) != data:
        raise IntegrityError(
            "native build receipt is noncanonical or has unknown fields"
        )
    if not HEX256_RE.fullmatch(fields["RECEIPT_SHA256"]):
        raise IntegrityError("native build receipt RECEIPT_SHA256 is malformed")
    if fields["RECEIPT_SHA256"] != _receipt_digest(fields):
        raise IntegrityError("native build receipt digest does not match its fields")
    return fields


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_new(path: Path, data: bytes) -> None:
    created = False
    try:
        handle = path.open("xb")
        created = True
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if created and path.exists():
            path.unlink()
        raise


def write_native_build_receipt(
    *,
    repo: Path,
    expected_commit: str,
    kind: str,
    library: Path,
    build_script: str,
    toolchain: str,
    target: str,
    architectures: str,
    output: Path,
    source_date_epoch: str | int | None,
) -> dict[str, str]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    library = _regular_file(library, "native library")
    source_files, source_identity = _native_source_identity(repo, kind)
    script_relative = _safe_repo_relative(build_script)
    epoch = _source_date_epoch(repo, source_date_epoch)
    fields = {
        "SCHEMA": RECEIPT_SCHEMA,
        "TRUST_SCOPE": "IDENTITY_GUARD_ONLY_NOT_AUTHENTICATION",
        "KIND": kind,
        "GIT_COMMIT": commit,
        "SOURCE_FILES": ";".join(source_files),
        "SOURCE_TREE_SHA256": source_identity,
        "BUILD_SCRIPT": script_relative,
        "BUILD_SCRIPT_SHA256": _sha256_bytes(_tracked_blob(repo, script_relative)),
        "LIBRARY_NAME": _single_line("library name", library.name),
        "LIBRARY_SHA256": _sha256_file(library),
        "LIBRARY_SIZE": str(library.stat().st_size),
        "TOOLCHAIN": _single_line("toolchain", toolchain),
        "TARGET": _single_line("target", target),
        "ARCHITECTURES": _single_line("architectures", architectures),
        "SOURCE_DATE_EPOCH": str(epoch),
    }
    fields["RECEIPT_SHA256"] = _receipt_digest(fields)
    output = _absolute_path(output)
    if output.is_symlink():
        raise IntegrityError("native build receipt output cannot be a symbolic link")
    _write_atomic(output, _canonical_receipt(fields))
    return fields


def verify_native_build_receipt(
    *,
    repo: Path,
    expected_commit: str,
    kind: str,
    library: Path,
    receipt: Path,
    expected_build_script: str,
    expected_target: str,
    expected_architectures: str,
    source_date_epoch: str | int | None,
) -> dict[str, str]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    library = _regular_file(library, "native library")
    fields = _read_receipt(receipt)
    source_files, source_identity = _native_source_identity(repo, kind)
    script_relative = _safe_repo_relative(expected_build_script)
    epoch = _source_date_epoch(repo, source_date_epoch)
    expected = {
        "SCHEMA": RECEIPT_SCHEMA,
        "TRUST_SCOPE": "IDENTITY_GUARD_ONLY_NOT_AUTHENTICATION",
        "KIND": kind,
        "GIT_COMMIT": commit,
        "SOURCE_FILES": ";".join(source_files),
        "SOURCE_TREE_SHA256": source_identity,
        "BUILD_SCRIPT": script_relative,
        "BUILD_SCRIPT_SHA256": _sha256_bytes(_tracked_blob(repo, script_relative)),
        "LIBRARY_NAME": library.name,
        "LIBRARY_SHA256": _sha256_file(library),
        "LIBRARY_SIZE": str(library.stat().st_size),
        "TARGET": _single_line("target", expected_target),
        "ARCHITECTURES": _single_line("architectures", expected_architectures),
        "SOURCE_DATE_EPOCH": str(epoch),
    }
    for key, value in expected.items():
        if fields.get(key) != value:
            raise IntegrityError(f"native build receipt mismatch for {key}")
    _single_line("toolchain", fields["TOOLCHAIN"])
    return fields


def _archive_entries(stage: Path) -> list[tuple[Path, str, bool]]:
    stage = _regular_directory(stage, "archive staging path")
    root_name = _safe_repo_relative(stage.name)
    entries: list[tuple[Path, str, bool]] = [(stage, f"{root_name}/", True)]
    descendants = sorted(
        stage.rglob("*"), key=lambda item: item.relative_to(stage).as_posix()
    )
    for path in descendants:
        if path.is_symlink():
            raise IntegrityError(f"archive staging contains a symbolic link: {path}")
        relative = _safe_repo_relative(path.relative_to(stage).as_posix())
        archive_name = f"{root_name}/{relative}"
        if path.is_dir():
            entries.append((path, f"{archive_name}/", True))
        elif path.is_file():
            entries.append((path, archive_name, False))
        else:
            raise IntegrityError(f"archive staging contains a special file: {path}")
    return entries


def _canonical_file_mode(path: Path) -> int:
    executable_suffixes = {".bat", ".cmd", ".dll", ".exe", ".sh", ".so"}
    if path.suffix.lower() in executable_suffixes:
        return 0o755
    try:
        if path.stat().st_mode & 0o111:
            return 0o755
    except OSError as error:
        raise IntegrityError(f"cannot inspect archive mode for {path}") from error
    return 0o644


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    value = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    if value.year < 1980 or value.year > 2107:
        raise IntegrityError("ZIP SOURCE_DATE_EPOCH must be between 1980 and 2107")
    # DOS timestamps store seconds in two-second increments. Canonically round
    # down so an odd SOURCE_DATE_EPOCH verifies after the ZIP is reopened.
    return (
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second - (value.second % 2),
    )


def create_deterministic_zip(stage: Path, output: Path, epoch: int) -> None:
    entries = _archive_entries(stage)
    output = _absolute_path(output)
    if output.is_symlink():
        raise IntegrityError("ZIP output cannot be a symbolic link")
    if output.exists():
        raise IntegrityError(f"archive already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for path, name, is_directory in entries:
                info = zipfile.ZipInfo(name, _zip_datetime(epoch))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.comment = b""
                info.extra = b""
                mode = 0o755 if is_directory else _canonical_file_mode(path)
                file_type = stat.S_IFDIR if is_directory else stat.S_IFREG
                info.external_attr = ((file_type | mode) & 0xFFFF) << 16
                if is_directory:
                    info.external_attr |= 0x10
                    archive.writestr(info, b"")
                else:
                    archive.writestr(info, path.read_bytes())
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    verify_deterministic_zip(stage, output, epoch)


def verify_deterministic_zip(stage: Path, archive_path: Path, epoch: int) -> None:
    expected = _archive_entries(stage)
    archive_path = _regular_file(archive_path, "ZIP archive")
    expected_names = [name for _, name, _ in expected]
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = archive.infolist()
            if archive.comment:
                raise IntegrityError("ZIP archive comment is not canonical")
            if [member.filename for member in members] != expected_names:
                raise IntegrityError(
                    "ZIP entries are missing, reordered, or unexpected"
                )
            if archive.testzip() is not None:
                raise IntegrityError("ZIP CRC verification failed")
            for (path, name, is_directory), member in zip(
                expected, members, strict=True
            ):
                if member.date_time != _zip_datetime(epoch):
                    raise IntegrityError(f"ZIP timestamp is not canonical: {name}")
                expected_mode = 0o755 if is_directory else _canonical_file_mode(path)
                expected_type = stat.S_IFDIR if is_directory else stat.S_IFREG
                expected_attributes = ((expected_type | expected_mode) & 0xFFFF) << 16
                if is_directory:
                    expected_attributes |= 0x10
                if (
                    member.create_system != 3
                    or member.external_attr != expected_attributes
                    or member.is_dir() != is_directory
                ):
                    raise IntegrityError(f"ZIP type or mode is not canonical: {name}")
                if (
                    member.compress_type != zipfile.ZIP_DEFLATED
                    or member.comment
                    or member.extra
                ):
                    raise IntegrityError(f"ZIP metadata is not canonical: {name}")
                if not is_directory and archive.read(member) != path.read_bytes():
                    raise IntegrityError(f"ZIP content differs from staging: {name}")
    except (OSError, zipfile.BadZipFile) as error:
        raise IntegrityError(f"cannot verify ZIP archive: {error}") from error


def create_deterministic_tar_gz(stage: Path, output: Path, epoch: int) -> None:
    entries = _archive_entries(stage)
    output = _absolute_path(output)
    if output.is_symlink():
        raise IntegrityError("tar.gz output cannot be a symbolic link")
    if output.exists():
        raise IntegrityError(f"archive already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with (
            temporary.open("wb") as raw,
            gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch
            ) as zipped,
            tarfile.open(
                fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive,
        ):
            for path, name, is_directory in entries:
                member = tarfile.TarInfo(name.rstrip("/") if is_directory else name)
                member.mtime = epoch
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mode = 0o755 if is_directory else _canonical_file_mode(path)
                if is_directory:
                    member.type = tarfile.DIRTYPE
                    member.size = 0
                    archive.addfile(member)
                else:
                    member.type = tarfile.REGTYPE
                    member.size = path.stat().st_size
                    with path.open("rb") as source:
                        archive.addfile(member, source)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    verify_deterministic_tar_gz(stage, output, epoch)


def verify_deterministic_tar_gz(stage: Path, archive_path: Path, epoch: int) -> None:
    expected = _archive_entries(stage)
    archive_path = _regular_file(archive_path, "tar.gz archive")
    expected_names = [
        name.rstrip("/") if is_directory else name for _, name, is_directory in expected
    ]
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            if [member.name for member in members] != expected_names:
                raise IntegrityError(
                    "tar entries are missing, reordered, or unexpected"
                )
            for (path, name, is_directory), member in zip(
                expected, members, strict=True
            ):
                expected_mode = 0o755 if is_directory else _canonical_file_mode(path)
                if member.mtime != epoch or member.uid != 0 or member.gid != 0:
                    raise IntegrityError(
                        f"tar ownership or timestamp is not canonical: {name}"
                    )
                if member.uname or member.gname or member.mode != expected_mode:
                    raise IntegrityError(f"tar names or mode are not canonical: {name}")
                if is_directory:
                    if not member.isdir() or member.size != 0 or member.linkname:
                        raise IntegrityError(
                            f"tar directory has the wrong type: {name}"
                        )
                else:
                    if (
                        not member.isreg()
                        or member.linkname
                        or member.size != path.stat().st_size
                    ):
                        raise IntegrityError(
                            f"tar file has the wrong type or size: {name}"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None or extracted.read() != path.read_bytes():
                        raise IntegrityError(
                            f"tar content differs from staging: {name}"
                        )
    except (OSError, tarfile.TarError) as error:
        raise IntegrityError(f"cannot verify tar.gz archive: {error}") from error


def _ar_number(field: bytes, label: str, base: int = 10) -> int:
    try:
        text = field.decode("ascii", "strict").strip()
        if not text or not re.fullmatch(r"[0-9]+", text):
            raise ValueError
        return int(text, base)
    except (UnicodeDecodeError, ValueError) as error:
        raise IntegrityError(f"Debian ar header has an invalid {label}") from error


def _deb_ar_members(path: Path) -> dict[str, bytes]:
    path = _regular_file(path, "Debian package")
    if path.stat().st_size > MAX_DEB_BYTES:
        raise IntegrityError("Debian package exceeds its size limit")
    data = path.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        raise IntegrityError("Debian package does not have an ar archive header")
    offset = 8
    rows: list[tuple[str, bytes]] = []
    while offset < len(data):
        if offset + 60 > len(data):
            raise IntegrityError("Debian ar member header is truncated")
        header = data[offset : offset + 60]
        offset += 60
        if header[58:60] != b"`\n":
            raise IntegrityError("Debian ar member header has an invalid trailer")
        try:
            encoded_name = header[:16].decode("ascii", "strict").rstrip()
        except UnicodeDecodeError as error:
            raise IntegrityError("Debian ar member name is not ASCII") from error
        name = encoded_name[:-1] if encoded_name.endswith("/") else encoded_name
        if name not in DEB_AR_MEMBERS:
            raise IntegrityError(f"Debian ar member is unexpected: {name!r}")
        _ar_number(header[16:28], "timestamp")
        _ar_number(header[28:34], "owner")
        _ar_number(header[34:40], "group")
        _ar_number(header[40:48], "mode", 8)
        size = _ar_number(header[48:58], "size")
        end = offset + size
        if end > len(data):
            raise IntegrityError("Debian ar member payload is truncated")
        rows.append((name, data[offset:end]))
        offset = end
        if size % 2:
            if offset >= len(data) or data[offset : offset + 1] != b"\n":
                raise IntegrityError("Debian ar member padding is invalid")
            offset += 1
    names = tuple(name for name, _ in rows)
    if names != DEB_AR_MEMBERS:
        raise IntegrityError("Debian ar members are missing, reordered, or repeated")
    members = dict(rows)
    if members["debian-binary"] != b"2.0\n":
        raise IntegrityError("Debian package format marker is not canonical 2.0")
    return members


def _deb_tar_name(value: str) -> str:
    if not value or "\\" in value or "\0" in value or "\n" in value or "\r" in value:
        raise IntegrityError(f"unsafe Debian tar member name: {value!r}")
    normalized = value[2:] if value.startswith("./") else value
    if normalized == ".":
        return normalized
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or path.as_posix() != normalized
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise IntegrityError(f"unsafe Debian tar member name: {value!r}")
    return normalized


def _deb_tar_manifest(data: bytes, label: str) -> list[dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    seen: set[str] = set()
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member_number, member in enumerate(archive, start=1):
                if member_number > MAX_DEB_MEMBERS:
                    raise IntegrityError(f"Debian {label} tar has too many members")
                name = _deb_tar_name(member.name)
                if name in seen:
                    raise IntegrityError(
                        f"Debian {label} tar repeats member: {name!r}"
                    )
                seen.add(name)
                if member.linkname or member.pax_headers:
                    raise IntegrityError(
                        "Debian "
                        f"{label} tar contains link or extended metadata: {name!r}"
                    )
                row: dict[str, object] = {
                    "mode": member.mode & 0o7777,
                    "name": name,
                }
                if member.isdir():
                    if member.size != 0:
                        raise IntegrityError(
                            f"Debian {label} directory has content: {name!r}"
                        )
                    row["type"] = "directory"
                    if name == ".":
                        if row["mode"] != 0o755:
                            raise IntegrityError(
                                f"Debian {label} root mode is not 0755"
                            )
                        continue
                elif member.isreg() and name != ".":
                    total_size += member.size
                    if total_size > MAX_DEB_BYTES:
                        raise IntegrityError(
                            f"Debian {label} tar exceeds its content size limit"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise IntegrityError(
                            f"Debian {label} file cannot be read: {name!r}"
                        )
                    content = extracted.read()
                    if len(content) != member.size:
                        raise IntegrityError(
                            f"Debian {label} file size is inconsistent: {name!r}"
                        )
                    row.update(
                        {
                            "sha256": _sha256_bytes(content),
                            "size": member.size,
                            "type": "file",
                        }
                    )
                else:
                    raise IntegrityError(
                        f"Debian {label} tar contains a link or special file: {name!r}"
                    )
                rows[name] = row
    except (OSError, tarfile.TarError) as error:
        raise IntegrityError(f"cannot inspect Debian {label} tar: {error}") from error
    return [rows[name] for name in sorted(rows)]


def inspect_debian_package(path: Path) -> str:
    members = _deb_ar_members(path)
    control = _deb_tar_manifest(members["control.tar.gz"], "control")
    payload = _deb_tar_manifest(members["data.tar.gz"], "payload")
    control_by_name = {row["name"]: row for row in control}
    payload_by_name = {row["name"]: row for row in payload}
    if control_by_name.get("control", {}).get("type") != "file":
        raise IntegrityError("Debian control tar lacks a regular control file")
    if payload_by_name.get("usr/bin/common-foundry-wallet", {}).get("type") != "file":
        raise IntegrityError("Debian payload lacks the Common Foundry wallet binary")
    semantic = {
        "control": control,
        "payload": payload,
        "schema": "CMFD_DEB_SEMANTIC_V1",
    }
    return _sha256_bytes(_canonical_json(semantic))


def _inventory_names(path: Path) -> tuple[list[str], bytes]:
    path = _regular_file(path, "release inventory")
    data = path.read_bytes()
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise IntegrityError("release inventory is not UTF-8") from error
    if b"\r" in data or not data.endswith(b"\n"):
        raise IntegrityError("release inventory must be canonical LF-terminated UTF-8")
    names = text.splitlines()
    if not names or names != sorted(set(names)):
        raise IntegrityError("release inventory must be non-empty, sorted, and unique")
    for name in names:
        if name in (BUILDINFO_NAME, CHECKSUM_NAME):
            raise IntegrityError(f"release inventory must not list generated {name}")
        safe = _safe_repo_relative(name)
        if "/" in safe:
            raise IntegrityError("release inventory entries must be flat asset names")
    canonical = ("\n".join(names) + "\n").encode("utf-8")
    if data != canonical:
        raise IntegrityError("release inventory is not canonical")
    return names, data


def _stage_files(stage: Path) -> dict[str, Path]:
    stage = _regular_directory(stage, "release staging path")
    files: dict[str, Path] = {}
    for path in stage.iterdir():
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(
                f"release staging contains a non-regular asset: {path.name}"
            )
        files[path.name] = path
    return files


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _expected_buildinfo(
    *,
    repo: Path,
    commit: str,
    version: str,
    epoch: int,
    inventory_data: bytes,
    assets: dict[str, Path],
) -> dict[str, object]:
    artifact_rows = [
        {
            "name": name,
            "sha256": _sha256_file(assets[name]),
            "size": assets[name].stat().st_size,
        }
        for name in sorted(assets)
    ]
    return {
        "artifact_count": len(artifact_rows),
        "artifacts": artifact_rows,
        "commit": commit,
        "finalizer_sha256": _sha256_bytes(
            _tracked_blob(repo, "scripts/release_integrity.py")
        ),
        "inventory_sha256": _sha256_bytes(inventory_data),
        "schema": BUILDINFO_SCHEMA,
        "source_date_epoch": epoch,
        "source_tree": _run_git(repo, "rev-parse", "HEAD^{tree}").lower(),
        "version": _single_line("version", version),
    }


def _checksum_bytes(assets: dict[str, Path], buildinfo_bytes: bytes) -> bytes:
    rows = {name: _sha256_file(path) for name, path in assets.items()}
    rows[BUILDINFO_NAME] = _sha256_bytes(buildinfo_bytes)
    return ("".join(f"{rows[name]}  {name}\n" for name in sorted(rows))).encode("utf-8")


def _read_buildinfo(path: Path) -> tuple[dict[str, object], bytes]:
    data = path.read_bytes()
    if len(data) > MAX_BUILDINFO_BYTES:
        raise IntegrityError("BUILDINFO.json exceeds its size limit")
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrityError("BUILDINFO.json is not canonical JSON") from error
    if not isinstance(value, dict) or _canonical_json(value) != data:
        raise IntegrityError("BUILDINFO.json is not in canonical form")
    return value, data


def verify_release(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    stage: Path,
    inventory: Path,
    source_date_epoch: str | int | None,
) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    epoch = _source_date_epoch(repo, source_date_epoch)
    inventory = _tracked_input_file(repo, inventory, "release inventory")
    names, inventory_data = _inventory_names(inventory)
    stage_files = _stage_files(stage)
    validate_production_rc_artifacts(
        version=version, commit=commit, stage_files=stage_files
    )
    expected_names = set(names) | {BUILDINFO_NAME, CHECKSUM_NAME}
    if set(stage_files) != expected_names:
        missing = sorted(expected_names - set(stage_files))
        unexpected = sorted(set(stage_files) - expected_names)
        raise IntegrityError(
            f"release inventory mismatch; missing={missing}, unexpected={unexpected}"
        )
    assets = {name: stage_files[name] for name in names}
    expected_info = _expected_buildinfo(
        repo=repo,
        commit=commit,
        version=version,
        epoch=epoch,
        inventory_data=inventory_data,
        assets=assets,
    )
    actual_info, buildinfo_bytes = _read_buildinfo(stage_files[BUILDINFO_NAME])
    if actual_info != expected_info:
        raise IntegrityError(
            "BUILDINFO.json does not match source, inventory, or artifacts"
        )
    checksum_bytes = stage_files[CHECKSUM_NAME].read_bytes()
    expected_checksums = _checksum_bytes(assets, buildinfo_bytes)
    if checksum_bytes != expected_checksums:
        raise IntegrityError(
            "SHA256SUMS.txt is noncanonical or does not match the artifacts"
        )
    return expected_info


def finalize_release(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    stage: Path,
    inventory: Path,
    source_date_epoch: str | int | None,
) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    epoch = _source_date_epoch(repo, source_date_epoch)
    inventory = _tracked_input_file(repo, inventory, "release inventory")
    names, inventory_data = _inventory_names(inventory)
    stage_files = _stage_files(stage)
    validate_production_rc_artifacts(
        version=version, commit=commit, stage_files=stage_files
    )
    if BUILDINFO_NAME in stage_files or CHECKSUM_NAME in stage_files:
        raise IntegrityError("generated release metadata already exists")
    if set(stage_files) != set(names):
        missing = sorted(set(names) - set(stage_files))
        unexpected = sorted(set(stage_files) - set(names))
        raise IntegrityError(
            f"release inventory mismatch; missing={missing}, unexpected={unexpected}"
        )
    assets = {name: stage_files[name] for name in names}
    buildinfo = _expected_buildinfo(
        repo=repo,
        commit=commit,
        version=version,
        epoch=epoch,
        inventory_data=inventory_data,
        assets=assets,
    )
    buildinfo_bytes = _canonical_json(buildinfo)
    checksum_bytes = _checksum_bytes(assets, buildinfo_bytes)
    _write_new(stage / BUILDINFO_NAME, buildinfo_bytes)
    try:
        _write_new(stage / CHECKSUM_NAME, checksum_bytes)
    except Exception:
        (stage / BUILDINFO_NAME).unlink(missing_ok=True)
        raise
    return verify_release(
        repo=repo,
        expected_commit=commit,
        version=version,
        stage=stage,
        inventory=inventory,
        source_date_epoch=epoch,
    )


def _add_repo_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)


def _add_native_common(parser: argparse.ArgumentParser) -> None:
    _add_repo_arguments(parser)
    parser.add_argument("--kind", choices=sorted(NATIVE_SOURCES), required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--source-date-epoch")


def _add_release_common(parser: argparse.ArgumentParser) -> None:
    _add_repo_arguments(parser)
    parser.add_argument("--version", required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--source-date-epoch")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    receipt_write = commands.add_parser(
        "receipt-write", help="write a canonical native build identity receipt"
    )
    _add_native_common(receipt_write)
    receipt_write.add_argument("--build-script", required=True)
    receipt_write.add_argument("--toolchain", required=True)
    receipt_write.add_argument("--target", required=True)
    receipt_write.add_argument("--architectures", required=True)
    receipt_write.add_argument("--output", type=Path, required=True)

    receipt_verify = commands.add_parser(
        "receipt-verify", help="verify a native build identity receipt"
    )
    _add_native_common(receipt_verify)
    receipt_verify.add_argument("--receipt", type=Path, required=True)
    receipt_verify.add_argument("--expected-build-script", required=True)
    receipt_verify.add_argument("--expected-target", required=True)
    receipt_verify.add_argument("--expected-architectures", required=True)

    zip_command = commands.add_parser(
        "archive-zip", help="create and verify a deterministic ZIP"
    )
    zip_command.add_argument("--stage", type=Path, required=True)
    zip_command.add_argument("--output", type=Path, required=True)
    zip_command.add_argument("--source-date-epoch", required=True)

    tar_command = commands.add_parser(
        "archive-tar-gz", help="create and verify a deterministic tar.gz"
    )
    tar_command.add_argument("--stage", type=Path, required=True)
    tar_command.add_argument("--output", type=Path, required=True)
    tar_command.add_argument("--source-date-epoch", required=True)

    deb_inspect = commands.add_parser(
        "deb-inspect", help="fail closed on unsafe Debian members and hash semantics"
    )
    deb_inspect.add_argument("--deb", type=Path, required=True)

    finalize = commands.add_parser(
        "finalize", help="generate and re-verify canonical release metadata"
    )
    _add_release_common(finalize)

    verify = commands.add_parser(
        "verify", help="re-verify canonical release metadata and assets"
    )
    _add_release_common(verify)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "receipt-write":
            result = write_native_build_receipt(
                repo=args.repo,
                expected_commit=args.expected_commit,
                kind=args.kind,
                library=args.library,
                build_script=args.build_script,
                toolchain=args.toolchain,
                target=args.target,
                architectures=args.architectures,
                output=args.output,
                source_date_epoch=args.source_date_epoch,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "receipt-verify":
            result = verify_native_build_receipt(
                repo=args.repo,
                expected_commit=args.expected_commit,
                kind=args.kind,
                library=args.library,
                receipt=args.receipt,
                expected_build_script=args.expected_build_script,
                expected_target=args.expected_target,
                expected_architectures=args.expected_architectures,
                source_date_epoch=args.source_date_epoch,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "archive-zip":
            epoch = _source_date_epoch(None, args.source_date_epoch)
            create_deterministic_zip(args.stage, args.output, epoch)
            print(f"{_sha256_file(args.output)}  {args.output.name}")
        elif args.command == "archive-tar-gz":
            epoch = _source_date_epoch(None, args.source_date_epoch)
            create_deterministic_tar_gz(args.stage, args.output, epoch)
            print(f"{_sha256_file(args.output)}  {args.output.name}")
        elif args.command == "deb-inspect":
            print(inspect_debian_package(args.deb))
        elif args.command == "finalize":
            result = finalize_release(
                repo=args.repo,
                expected_commit=args.expected_commit,
                version=args.version,
                stage=args.stage,
                inventory=args.inventory,
                source_date_epoch=args.source_date_epoch,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "verify":
            result = verify_release(
                repo=args.repo,
                expected_commit=args.expected_commit,
                version=args.version,
                stage=args.stage,
                inventory=args.inventory,
                source_date_epoch=args.source_date_epoch,
            )
            print(json.dumps(result, sort_keys=True))
        else:  # pragma: no cover - argparse guarantees a known command.
            raise IntegrityError("unsupported command")
    except (IntegrityError, OSError) as error:
        print(f"release-integrity: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
