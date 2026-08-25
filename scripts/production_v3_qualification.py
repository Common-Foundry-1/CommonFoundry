#!/usr/bin/env python3
"""Run and bind one Windows production Dory V3 qualification.

This is an operator harness, not an activation switch.  It executes the
feature-gated producer and fresh verifier in separate processes and emits an
activation-evidence *candidate* only after both complete successfully.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Sequence


PRODUCTION_SCRATCH_FLOOR_BYTES = 53_687_091_200
DEFAULT_SCRATCH_MARGIN_BYTES = 17_179_869_184
DEFAULT_MAXIMUM_NATIVE_BLOCK_ROWS = 131_072
DEFAULT_CANCELLATION_GRACE_SECONDS = 120
MANIFEST_SCHEMA = "CMFD_PRODUCTION_V3_QUALIFICATION_MANIFEST_V1"
CANDIDATE_SCHEMA = "CMFD_PRODUCTION_V3_ACTIVATION_CANDIDATE_V1"
RCNET1_NETWORK_ID_HEX = "72" * 32
QUALIFICATION_MANIFEST_NAME = "PRODUCTION-V3-QUALIFICATION-MANIFEST.json"
INDEPENDENT_VERIFIER_BINARY_NAME = "PRODUCTION-V3-INDEPENDENT-VERIFIER.bin"
INDEPENDENT_VERIFIER_REPORT_NAME = "PRODUCTION-V3-INDEPENDENT-VERIFIER-REPORT.json"
FULL_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class QualificationHarnessError(RuntimeError):
    """The qualification harness failed a fail-closed invariant."""


class QualificationInterrupted(QualificationHarnessError):
    """The operator interrupted a child process."""


@dataclass(frozen=True)
class ProcessReceipt:
    argv: tuple[str, ...]
    pid: int
    started_at_utc: str
    finished_at_utc: str
    exit_code: int
    stdout_path: Path
    stderr_path: Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a base-10 integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file_with_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    named = path.stat()
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields) or any(
        getattr(after, field) != getattr(named, field) for field in stable_fields
    ):
        raise QualificationHarnessError(f"file changed while hashing: {path}")
    return digest.hexdigest(), before.st_size


def _sha256_file(path: Path) -> str:
    return _sha256_file_with_size(path)[0]


def _is_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def _regular_file(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise QualificationHarnessError(f"{label} path must be absolute: {path}")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationHarnessError(f"{label} is missing: {path}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or _is_reparse_point(path):
        raise QualificationHarnessError(
            f"{label} must be a regular, non-reparse-point file: {path}"
        )
    return path.resolve(strict=True)


def _regular_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise QualificationHarnessError(f"{label} path must be absolute: {path}")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationHarnessError(f"{label} is missing: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink() or _is_reparse_point(path):
        raise QualificationHarnessError(
            f"{label} must be a regular, non-reparse-point directory: {path}"
        )
    return path.resolve(strict=True)


def _new_absolute_path(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise QualificationHarnessError(f"{label} path must be absolute: {path}")
    parent = _regular_directory(path.parent, f"{label} parent")
    candidate = parent / path.name
    if candidate.exists() or candidate.is_symlink():
        raise QualificationHarnessError(f"{label} path already exists: {candidate}")
    return candidate


def _windows_path_key(path: Path) -> str:
    return ntpath.normcase(ntpath.normpath(str(path)))


def _path_is_within(path: Path, parent: Path) -> bool:
    path_key = _windows_path_key(path)
    parent_key = _windows_path_key(parent).rstrip("\\/")
    return path_key == parent_key or path_key.startswith(parent_key + "\\")


def _require_d_drive_scratch(path: Path) -> None:
    drive, tail = ntpath.splitdrive(str(path))
    if drive.upper() != "D:" or not tail.startswith(("\\", "/")):
        raise QualificationHarnessError(
            "scratch directory must be an explicit absolute D:\\ path"
        )


def required_scratch_bytes(margin_bytes: int) -> int:
    if margin_bytes <= 0:
        raise QualificationHarnessError("scratch margin must be greater than zero")
    return PRODUCTION_SCRATCH_FLOOR_BYTES + margin_bytes


def _preflight_free_space(scratch: Path, margin_bytes: int) -> int:
    available = shutil.disk_usage(scratch.parent).free
    required = required_scratch_bytes(margin_bytes)
    if available < required:
        raise QualificationHarnessError(
            "insufficient D: scratch space: "
            f"need {required} bytes ({PRODUCTION_SCRATCH_FLOOR_BYTES} byte code floor + "
            f"{margin_bytes} byte operator margin), have {available} bytes"
        )
    return available


def _run_git(repo: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise QualificationHarnessError(
            f"git {' '.join(arguments)} failed for {repo}"
        ) from error
    return result.stdout.decode("utf-8", "strict").strip()


def _verify_source(repo: Path, expected_commit: str) -> str:
    if not FULL_COMMIT_RE.fullmatch(expected_commit):
        raise QualificationHarnessError(
            "expected commit must be a full lowercase 40- or 64-character digest"
        )
    actual = _run_git(repo, "rev-parse", "HEAD")
    if actual != expected_commit:
        raise QualificationHarnessError(
            f"source commit mismatch: expected {expected_commit}, found {actual}"
        )
    status = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise QualificationHarnessError(
            "source worktree must be completely clean before qualification"
        )
    return actual


def _sync_file(handle: BinaryIO) -> None:
    handle.flush()
    os.fsync(handle.fileno())


def _signal_child_for_cancellation(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        os.killpg(process.pid, signal.SIGINT)


def _run_process_exact(
    argv: Sequence[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    environment: dict[str, str] | None,
    cancellation_grace_seconds: int,
) -> ProcessReceipt:
    if stdout_path.exists() or stderr_path.exists():
        raise QualificationHarnessError("child output logs must be create-new paths")
    if _windows_path_key(stdout_path) == _windows_path_key(stderr_path):
        raise QualificationHarnessError("child stdout and stderr paths must be distinct")

    started_at = _utc_now()
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    with stdout_path.open("xb", buffering=0) as stdout, stderr_path.open(
        "xb", buffering=0
    ) as stderr:
        try:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )
        except OSError as error:
            _sync_file(stdout)
            _sync_file(stderr)
            raise QualificationHarnessError(f"failed to start {argv[0]}") from error

        interrupted = False
        try:
            exit_code = process.wait()
        except KeyboardInterrupt:
            interrupted = True
            try:
                _signal_child_for_cancellation(process)
            except (OSError, ProcessLookupError):
                pass
            try:
                exit_code = process.wait(timeout=cancellation_grace_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                exit_code = process.wait()
        finally:
            _sync_file(stdout)
            _sync_file(stderr)

    receipt = ProcessReceipt(
        argv=tuple(argv),
        pid=process.pid,
        started_at_utc=started_at,
        finished_at_utc=_utc_now(),
        exit_code=exit_code,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    if interrupted:
        raise QualificationInterrupted(
            "operator interruption requested; no activation-evidence candidate was emitted. "
            "Any journal is diagnostics only and the run cannot be resumed"
        )
    if exit_code != 0:
        raise QualificationHarnessError(
            f"child process exited with code {exit_code}; see {stderr_path}"
        )
    return receipt


def _read_json_object(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    data = _regular_file(path, label).read_bytes()
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationHarnessError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise QualificationHarnessError(f"{label} must contain a JSON object")
    return value, data


def _require_equal(value: object, expected: object, label: str) -> None:
    if value != expected:
        raise QualificationHarnessError(
            f"{label} mismatch: expected {expected!r}, found {value!r}"
        )


def _validate_reports(
    *,
    proof: Path,
    producer_report: Path,
    journal: Path,
    verifier_report: Path,
    producer_stdout: Path,
    verifier_stdout: Path,
    maximum_native_block_rows: int,
) -> tuple[dict[str, object], dict[str, object]]:
    producer, producer_bytes = _read_json_object(producer_report, "producer report")
    verifier, verifier_bytes = _read_json_object(verifier_report, "fresh verifier report")

    if producer_stdout.read_bytes() != producer_bytes:
        raise QualificationHarnessError(
            "producer stdout is not byte-for-byte identical to the persisted producer report"
        )
    if verifier_stdout.read_bytes() != verifier_bytes:
        raise QualificationHarnessError(
            "verifier stdout is not byte-for-byte identical to the persisted verifier report"
        )

    producer_expectations = {
        "report_version": 4,
        "padded_variables": 33,
        "composed_claims": 134,
        "verifier_passes": 2,
        "maximum_native_block_rows": maximum_native_block_rows,
        "network_id": RCNET1_NETWORK_ID_HEX,
        "provisional_scratch_floor_bytes": PRODUCTION_SCRATCH_FLOOR_BYTES,
        "native_resource_projection_complete": True,
        "exact_peak_scratch_instrumented": True,
        "retained_scratch_entries": 0,
        "retained_scratch_logical_bytes": 0,
        "report_output_is_completion_marker": True,
        "publication_crash_atomic": False,
    }
    for field, expected in producer_expectations.items():
        _require_equal(producer.get(field), expected, f"producer report {field}")

    journal_summary = producer.get("qualification_journal")
    if not isinstance(journal_summary, dict):
        raise QualificationHarnessError(
            "producer report qualification_journal must be an object"
        )
    journal_expectations = {
        "journal_version": 1,
        "event_count": 16,
        "journal_bytes": journal.stat().st_size,
        "diagnostic_only": True,
        "completion_marker": False,
        "resumable": False,
    }
    for field, expected in journal_expectations.items():
        _require_equal(
            journal_summary.get(field), expected, f"producer journal summary {field}"
        )

    _require_equal(producer.get("wire_bytes"), proof.stat().st_size, "producer wire_bytes")
    verifier_expectations = {
        "report_version": 2,
        "wire_bytes": proof.stat().st_size,
        "verifier_only": True,
        "producer_report_checked": True,
        "qualification_journal_checked": True,
    }
    for field, expected in verifier_expectations.items():
        _require_equal(verifier.get(field), expected, f"verifier report {field}")

    for field in (
        "network_id",
        "block_height",
        "nonce",
        "request_digest",
        "record_digest",
        "model_identity_digest",
        "setup_identity",
        "wire_blake3_digest",
    ):
        _require_equal(verifier.get(field), producer.get(field), f"cross-report {field}")
    _require_equal(
        verifier.get("qualification_journal"),
        journal_summary,
        "cross-report qualification_journal",
    )
    return producer, verifier


def _artifact(path: Path) -> dict[str, object]:
    digest, size = _sha256_file_with_size(path)
    return {
        "file_name": path.name,
        "bytes": size,
        "sha256": digest,
    }


def _artifact_bindings(paths: dict[str, Path]) -> dict[str, dict[str, object]]:
    return {role: _artifact(path) for role, path in paths.items()}


def _write_json_create_new(path: Path, value: dict[str, object]) -> bytes:
    encoded = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with path.open("xb") as handle:
        handle.write(encoded)
        _sync_file(handle)
    return encoded


def _copy_file_create_new(source: Path, destination: Path) -> None:
    source_digest, source_size = _sha256_file_with_size(source)
    with source.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer, length=8 * 1024 * 1024)
        _sync_file(writer)
    destination_digest, destination_size = _sha256_file_with_size(destination)
    if destination_size != source_size or destination_digest != source_digest:
        raise QualificationHarnessError(
            "independent verifier binary copy did not preserve the exact executable bytes"
        )


def finalize_evidence(
    *,
    repo: Path,
    expected_commit: str,
    bank: Path,
    record: Path,
    request: Path,
    proof: Path,
    producer_report: Path,
    journal: Path,
    verifier_report: Path,
    consensus_executable: Path,
    independent_verifier_binary: Path,
    build_stdout: Path,
    build_stderr: Path,
    producer_stdout: Path,
    producer_stderr: Path,
    verifier_stdout: Path,
    verifier_stderr: Path,
    manifest_output: Path,
    candidate_output: Path,
    maximum_native_block_rows: int,
    scratch_floor_bytes: int,
    scratch_margin_bytes: int,
    available_scratch_bytes: int,
    build_receipt: ProcessReceipt,
    producer_receipt: ProcessReceipt,
    verifier_receipt: ProcessReceipt,
    preverified_artifacts: dict[str, dict[str, object]],
) -> tuple[str, str]:
    repo = _regular_directory(repo, "source repository")
    _verify_source(repo, expected_commit)
    if producer_receipt.pid == verifier_receipt.pid:
        raise QualificationHarnessError(
            "producer and verifier must have distinct process identities"
        )
    if scratch_floor_bytes != PRODUCTION_SCRATCH_FLOOR_BYTES:
        raise QualificationHarnessError("harness scratch floor does not match the code floor")
    if available_scratch_bytes < required_scratch_bytes(scratch_margin_bytes):
        raise QualificationHarnessError("recorded scratch preflight does not include the margin")

    files = {
        "bank": _regular_file(bank, "model bank"),
        "record_v2": _regular_file(record, "Record V2"),
        "request": _regular_file(request, "qualification request"),
        "proof": _regular_file(proof, "qualification proof"),
        "producer_report": _regular_file(producer_report, "producer report"),
        "journal": _regular_file(journal, "qualification journal"),
        "verifier_report": _regular_file(verifier_report, "fresh verifier report"),
        "consensus_executable": _regular_file(
            consensus_executable, "feature-gated consensus executable"
        ),
        "independent_verifier_binary": _regular_file(
            independent_verifier_binary, "independent verifier binary"
        ),
        "build_stdout": _regular_file(build_stdout, "build stdout"),
        "build_stderr": _regular_file(build_stderr, "build stderr"),
        "producer_stdout": _regular_file(producer_stdout, "producer stdout"),
        "producer_stderr": _regular_file(producer_stderr, "producer stderr"),
        "verifier_stdout": _regular_file(verifier_stdout, "verifier stdout"),
        "verifier_stderr": _regular_file(verifier_stderr, "verifier stderr"),
    }
    manifest_output = _new_absolute_path(manifest_output, "qualification manifest")
    candidate_output = _new_absolute_path(candidate_output, "activation candidate")
    if _windows_path_key(manifest_output) == _windows_path_key(candidate_output):
        raise QualificationHarnessError("manifest and activation candidate paths must differ")

    for name, receipt, stdout_role, stderr_role in (
        ("build", build_receipt, "build_stdout", "build_stderr"),
        ("producer", producer_receipt, "producer_stdout", "producer_stderr"),
        ("fresh verifier", verifier_receipt, "verifier_stdout", "verifier_stderr"),
    ):
        if receipt.exit_code != 0 or receipt.pid <= 0:
            raise QualificationHarnessError(f"{name} process receipt is not successful")
        if _windows_path_key(receipt.stdout_path) != _windows_path_key(files[stdout_role]):
            raise QualificationHarnessError(f"{name} stdout receipt path is wrong")
        if _windows_path_key(receipt.stderr_path) != _windows_path_key(files[stderr_role]):
            raise QualificationHarnessError(f"{name} stderr receipt path is wrong")

    _validate_reports(
        proof=files["proof"],
        producer_report=files["producer_report"],
        journal=files["journal"],
        verifier_report=files["verifier_report"],
        producer_stdout=files["producer_stdout"],
        verifier_stdout=files["verifier_stdout"],
        maximum_native_block_rows=maximum_native_block_rows,
    )

    required_preverified_roles = {
        "bank",
        "record_v2",
        "request",
        "proof",
        "producer_report",
        "journal",
    }
    if set(preverified_artifacts) != required_preverified_roles:
        raise QualificationHarnessError(
            "preverified artifacts must bind the exact producer and verifier inputs"
        )
    artifacts = _artifact_bindings(files)
    for role, expected in preverified_artifacts.items():
        if role not in artifacts:
            raise QualificationHarnessError(
                f"preverified artifact role is unknown: {role}"
            )
        if artifacts[role] != expected:
            raise QualificationHarnessError(
                f"{role} changed after the bytes were used by qualification"
            )
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "status": "qualification_complete_activation_disabled",
        "source_commit": expected_commit,
        "network_profile": "RCNet-1",
        "proof_selection": "ProductionV3",
        "features": ["dory-bls12-381-prototype", "whir-prototype"],
        "qualification": {
            "padded_variables": 33,
            "composed_claims": 134,
            "maximum_native_block_rows": maximum_native_block_rows,
            "scratch_floor_bytes": scratch_floor_bytes,
            "scratch_margin_bytes": scratch_margin_bytes,
            "required_scratch_bytes": required_scratch_bytes(scratch_margin_bytes),
            "available_scratch_bytes_before_producer": available_scratch_bytes,
            "producer_process_id": producer_receipt.pid,
            "verifier_process_id": verifier_receipt.pid,
            "fresh_process_verifier": producer_receipt.pid != verifier_receipt.pid,
        },
        "processes": {
            "build": _process_manifest(build_receipt),
            "producer": _process_manifest(producer_receipt),
            "fresh_verifier": _process_manifest(verifier_receipt),
        },
        "artifacts": artifacts,
        "journal_semantics": {
            "diagnostic_only": True,
            "completion_marker": False,
            "resumable": False,
            "used_as_completion_evidence": False,
        },
        "completion_evidence": {
            "producer_report": True,
            "fresh_verifier_report": True,
        },
    }
    manifest_bytes = _write_json_create_new(manifest_output, manifest)
    manifest_sha256 = _sha256_bytes(manifest_bytes)
    verifier_binary_sha256 = artifacts["independent_verifier_binary"]["sha256"]
    verifier_report_sha256 = artifacts["verifier_report"]["sha256"]
    if not isinstance(verifier_binary_sha256, str) or not SHA256_RE.fullmatch(
        verifier_binary_sha256
    ):
        raise QualificationHarnessError("independent verifier binary digest is invalid")
    if not isinstance(verifier_report_sha256, str) or not SHA256_RE.fullmatch(
        verifier_report_sha256
    ):
        raise QualificationHarnessError("independent verifier report digest is invalid")

    candidate: dict[str, object] = {
        "schema": CANDIDATE_SCHEMA,
        "status": "candidate_only_not_activated",
        "eligible_for_automatic_activation": False,
        "qualification_source_commit": expected_commit,
        "network_profile": "RCNet-1",
        "proof_selection": "ProductionV3",
        "qualification_manifest_sha256": manifest_sha256,
        "independent_verifier_binary_sha256": verifier_binary_sha256,
        "independent_verifier_report_sha256": verifier_report_sha256,
        "activation_notice": (
            "This candidate does not change the compiled release profile, enable RCNet-1, "
            "or satisfy the production release gate by itself."
        ),
    }
    candidate_bytes = _write_json_create_new(candidate_output, candidate)
    return manifest_sha256, _sha256_bytes(candidate_bytes)


def _process_manifest(receipt: ProcessReceipt) -> dict[str, object]:
    return {
        "argv": list(receipt.argv),
        "pid": receipt.pid,
        "started_at_utc": receipt.started_at_utc,
        "finished_at_utc": receipt.finished_at_utc,
        "exit_code": receipt.exit_code,
        "stdout_sha256": _sha256_file(receipt.stdout_path),
        "stderr_sha256": _sha256_file(receipt.stderr_path),
    }


def _create_output_directory(path: Path) -> Path:
    candidate = _new_absolute_path(path, "output directory")
    try:
        candidate.mkdir()
    except FileExistsError as error:
        raise QualificationHarnessError(
            f"output directory already exists: {candidate}"
        ) from error
    return _regular_directory(candidate, "output directory")


def _prepare_paths(args: argparse.Namespace) -> tuple[Path, Path, Path, Path, Path, Path]:
    repo = _regular_directory(Path(args.repo), "source repository")
    bank = _regular_file(Path(args.bank), "model bank")
    record = _regular_file(Path(args.record), "Record V2")
    request = _regular_file(Path(args.request), "qualification request")
    output = _new_absolute_path(Path(args.output_directory), "output directory")
    scratch = _new_absolute_path(Path(args.scratch_directory), "scratch directory")
    _require_d_drive_scratch(scratch)

    for label, path in (("output directory", output), ("scratch directory", scratch)):
        if _path_is_within(path, repo):
            raise QualificationHarnessError(f"{label} must be outside the source repository")
    if _path_is_within(output, scratch) or _path_is_within(scratch, output):
        raise QualificationHarnessError("output and scratch directories must not overlap")
    for label, path in (("bank", bank), ("Record V2", record), ("request", request)):
        if _path_is_within(path, output) or _path_is_within(path, scratch):
            raise QualificationHarnessError(
                f"{label} input must be outside new output and scratch directories"
            )
    return repo, bank, record, request, output, scratch


def run_qualification(args: argparse.Namespace) -> None:
    if os.name != "nt":
        raise QualificationHarnessError("the operator harness must run on Windows")
    repo, bank, record, request, output, scratch = _prepare_paths(args)
    _verify_source(repo, args.expected_commit)
    initial_available = _preflight_free_space(scratch, args.scratch_margin_bytes)
    preverified_artifacts = _artifact_bindings(
        {
            "bank": bank,
            "record_v2": record,
            "request": request,
        }
    )
    output = _create_output_directory(output)

    build_stdout = output / "build-stdout.log"
    build_stderr = output / "build-stderr.log"
    target_directory = output / "cargo-target"
    cargo = shutil.which("cargo.exe") or shutil.which("cargo")
    if not cargo:
        raise QualificationHarnessError("cargo was not found on PATH")
    build_environment = os.environ.copy()
    build_environment["CARGO_TARGET_DIR"] = str(target_directory)
    build_argv = (
        cargo,
        "build",
        "--release",
        "--locked",
        "-p",
        "cmfd-consensus",
        "--features",
        "dory-bls12-381-prototype,whir-prototype",
    )
    build_receipt = _run_process_exact(
        build_argv,
        cwd=repo,
        stdout_path=build_stdout,
        stderr_path=build_stderr,
        environment=build_environment,
        cancellation_grace_seconds=args.cancellation_grace_seconds,
    )
    consensus_executable = _regular_file(
        target_directory / "release" / "cmfd-consensus.exe",
        "newly built feature-gated consensus executable",
    )
    consensus_executable_sha256 = _sha256_file(consensus_executable)
    _verify_source(repo, args.expected_commit)

    proof = output / "qualification-proof.cmfd"
    producer_report = output / "producer-report.json"
    journal = output / "producer-journal.jsonl"
    producer_stdout = output / "producer-stdout.json"
    producer_stderr = output / "producer-stderr.log"
    available_before_producer = _preflight_free_space(
        scratch, args.scratch_margin_bytes
    )
    producer_argv = (
        str(consensus_executable),
        "dory-v3-qualify",
        "--bank",
        str(bank),
        "--record",
        str(record),
        "--request",
        str(request),
        "--scratch",
        str(scratch),
        "--proof-output",
        str(proof),
        "--report-output",
        str(producer_report),
        "--journal-output",
        str(journal),
        "--maximum-native-block-rows",
        str(args.maximum_native_block_rows),
    )
    if _sha256_file(consensus_executable) != consensus_executable_sha256:
        raise QualificationHarnessError(
            "feature-gated consensus executable changed before producer launch"
        )
    producer_receipt = _run_process_exact(
        producer_argv,
        cwd=repo,
        stdout_path=producer_stdout,
        stderr_path=producer_stderr,
        environment=os.environ.copy(),
        cancellation_grace_seconds=args.cancellation_grace_seconds,
    )
    if scratch.exists():
        raise QualificationHarnessError(
            "producer retained its runner-owned scratch directory; verification is blocked"
        )
    for path, label in (
        (proof, "qualification proof"),
        (producer_report, "producer completion report"),
        (journal, "diagnostic journal"),
    ):
        _regular_file(path, label)
    preverified_artifacts.update(
        _artifact_bindings(
            {
                "proof": proof,
                "producer_report": producer_report,
                "journal": journal,
            }
        )
    )

    verifier_report = output / INDEPENDENT_VERIFIER_REPORT_NAME
    verifier_stdout = output / "fresh-verifier-stdout.json"
    verifier_stderr = output / "fresh-verifier-stderr.log"
    verifier_argv = (
        str(consensus_executable),
        "dory-v3-verify-qualification",
        "--bank",
        str(bank),
        "--record",
        str(record),
        "--request",
        str(request),
        "--proof",
        str(proof),
        "--producer-report",
        str(producer_report),
        "--journal",
        str(journal),
        "--report-output",
        str(verifier_report),
    )
    if _sha256_file(consensus_executable) != consensus_executable_sha256:
        raise QualificationHarnessError(
            "feature-gated consensus executable changed between producer and verifier"
        )
    verifier_receipt = _run_process_exact(
        verifier_argv,
        cwd=repo,
        stdout_path=verifier_stdout,
        stderr_path=verifier_stderr,
        environment=os.environ.copy(),
        cancellation_grace_seconds=args.cancellation_grace_seconds,
    )
    if producer_receipt.pid == verifier_receipt.pid:
        raise QualificationHarnessError("fresh verifier reused the producer process identity")
    if _sha256_file(consensus_executable) != consensus_executable_sha256:
        raise QualificationHarnessError(
            "feature-gated consensus executable changed during verification"
        )

    independent_verifier_binary = output / INDEPENDENT_VERIFIER_BINARY_NAME
    _copy_file_create_new(consensus_executable, independent_verifier_binary)

    manifest_output = output / QUALIFICATION_MANIFEST_NAME
    candidate_output = output / "PRODUCTION-V3-ACTIVATION-CANDIDATE.json"
    manifest_sha256, candidate_sha256 = finalize_evidence(
        repo=repo,
        expected_commit=args.expected_commit,
        bank=bank,
        record=record,
        request=request,
        proof=proof,
        producer_report=producer_report,
        journal=journal,
        verifier_report=verifier_report,
        consensus_executable=consensus_executable,
        independent_verifier_binary=independent_verifier_binary,
        build_stdout=build_stdout,
        build_stderr=build_stderr,
        producer_stdout=producer_stdout,
        producer_stderr=producer_stderr,
        verifier_stdout=verifier_stdout,
        verifier_stderr=verifier_stderr,
        manifest_output=manifest_output,
        candidate_output=candidate_output,
        maximum_native_block_rows=args.maximum_native_block_rows,
        scratch_floor_bytes=PRODUCTION_SCRATCH_FLOOR_BYTES,
        scratch_margin_bytes=args.scratch_margin_bytes,
        available_scratch_bytes=available_before_producer,
        build_receipt=build_receipt,
        producer_receipt=producer_receipt,
        verifier_receipt=verifier_receipt,
        preverified_artifacts=preverified_artifacts,
    )
    print("qualification complete; activation remains disabled")
    print(f"manifest: {manifest_output}")
    print(f"manifest sha256: {manifest_sha256}")
    print(f"candidate: {candidate_output}")
    print(f"candidate sha256: {candidate_sha256}")
    print(f"initial D: free bytes: {initial_available}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one fail-closed Windows n=33 ProductionV3 qualification and emit a "
            "non-activating evidence candidate."
        )
    )
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--bank", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--scratch-directory", required=True, type=Path)
    parser.add_argument(
        "--scratch-margin-bytes",
        type=_positive_int,
        default=DEFAULT_SCRATCH_MARGIN_BYTES,
    )
    parser.add_argument(
        "--maximum-native-block-rows",
        type=_positive_int,
        default=DEFAULT_MAXIMUM_NATIVE_BLOCK_ROWS,
    )
    parser.add_argument(
        "--cancellation-grace-seconds",
        type=_positive_int,
        default=DEFAULT_CANCELLATION_GRACE_SECONDS,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        run_qualification(args)
    except QualificationInterrupted as error:
        print(f"INTERRUPTED: {error}", file=sys.stderr)
        return 130
    except QualificationHarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(
            "INTERRUPTED: activation remains disabled; partial output and journals "
            "are not completion evidence",
            file=sys.stderr,
        )
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
