#!/usr/bin/env python3
"""Run the deterministic ProductionV4 pool qualification gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


REPORT_SCHEMA = "CommonFoundry/ProductionV4/PoolQualification/v1"
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")


class QualificationError(RuntimeError):
    """Raised when the deterministic pool gate cannot be accepted."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def qualification_commands(include_dashboard: bool) -> list[tuple[str, list[str], Path]]:
    root = Path(__file__).resolve().parents[1]
    npm = "npm.cmd" if os.name == "nt" else "npm"
    commands = [
        (
            "node_production_v4_regression_tests",
            [
                "cargo", "test", "-p", "cmfd-node",
                "--features", "production-v4-testnet",
                "--lib",
            ],
            root,
        ),
        (
            "node_strict_clippy",
            [
                "cargo", "clippy", "-p", "cmfd-node",
                "--features", "production-v4-testnet",
                "--all-targets", "--", "-D", "warnings",
            ],
            root,
        ),
    ]
    if include_dashboard:
        dashboard = root / "apps" / "pool-dashboard"
        commands.extend(
            [
                ("pool_dashboard_tests", [npm, "test"], dashboard),
                ("pool_dashboard_build", [npm, "run", "build"], dashboard),
            ]
        )
    return commands


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0 or completed.stderr.strip():
        raise QualificationError(f"git {' '.join(arguments)} failed")
    return completed.stdout.strip()


def validate_source(root: Path, expected_commit: str) -> None:
    if not COMMIT_RE.fullmatch(expected_commit):
        raise QualificationError("source commit must be exactly 40 lowercase hex characters")
    if _git(root, "rev-parse", "HEAD") != expected_commit:
        raise QualificationError("source commit does not match the checked-out HEAD")
    if _git(root, "status", "--porcelain", "--untracked-files=no"):
        raise QualificationError("tracked source tree must be clean")


def _write_log(path: Path, data: bytes) -> dict[str, object]:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
    except FileExistsError as error:
        raise QualificationError(f"refusing to overwrite log {path}") from error
    return {
        "name": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def run_command(
    *,
    name: str,
    command: list[str],
    cwd: Path,
    log_directory: Path,
    timeout_seconds: int,
) -> dict[str, object]:
    started = _utc_now()
    environment = os.environ.copy()
    environment["CARGO_BUILD_JOBS"] = "4"
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationError(f"{name} could not complete: {error}") from error
    stdout = _write_log(log_directory / f"{name}.stdout.log", completed.stdout)
    stderr = _write_log(log_directory / f"{name}.stderr.log", completed.stderr)
    if completed.returncode != 0:
        raise QualificationError(f"{name} exited with code {completed.returncode}")
    return {
        "name": name,
        "command": command,
        "working_directory": str(cwd),
        "started_at_utc": started,
        "finished_at_utc": _utc_now(),
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def write_report(path: Path, report: dict[str, object]) -> bytes:
    encoded = (
        json.dumps(report, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as target:
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
    except FileExistsError as error:
        raise QualificationError(f"refusing to overwrite report {path}") from error
    return encoded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--platform-label", required=True)
    parser.add_argument("--log-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rust-only", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if not args.operator.strip() or not args.platform_label.strip():
            raise QualificationError("operator and platform label must not be empty")
        if args.timeout_seconds <= 0:
            raise QualificationError("timeout must be positive")
        validate_source(root, args.source_commit)
        commands = qualification_commands(not args.rust_only)
        receipts = [
            run_command(
                name=name,
                command=command,
                cwd=cwd,
                log_directory=args.log_directory.resolve(),
                timeout_seconds=args.timeout_seconds,
            )
            for name, command, cwd in commands
        ]
        report = {
            "schema": REPORT_SCHEMA,
            "status": "verified",
            "source_commit": args.source_commit,
            "operator": args.operator.strip(),
            "platform": args.platform_label.strip(),
            "cargo_build_jobs": 4,
            "deterministic_pool_gate_met": True,
            "dashboard_gate_met": not args.rust_only,
            "full_gpu_endurance_gate_met": False,
            "commands": receipts,
        }
        encoded = write_report(args.output.resolve(), report)
    except QualificationError as error:
        print(json.dumps({"status": "rejected", "error": str(error)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "status": "verified",
                "report": str(args.output.resolve()),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
