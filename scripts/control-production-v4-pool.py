#!/usr/bin/env python3
"""Local, fail-closed controls for a packaged ProductionV4 pool."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


STATE_SCHEMA = "CommonFoundry/ProductionV4/PoolProcess/v1"
SHUTDOWN_REQUEST = b"CMFD_POOL_SHUTDOWN_V1\n"
MAX_CONTROL_BYTES = 65_536


class ControlError(RuntimeError):
    """Raised when local pool control state cannot be trusted."""


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        if path.is_symlink():
            raise ControlError(f"control file must not be a symbolic link: {path}")
        stat = path.stat()
    except FileNotFoundError:
        return None
    if not path.is_file() or stat.st_size > MAX_CONTROL_BYTES:
        raise ControlError(f"invalid control file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ControlError(f"could not read control file: {path}") from error
    if not isinstance(value, dict):
        raise ControlError(f"control file must contain an object: {path}")
    return value


def _process_start_ticks(pid: int) -> int | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields_after_name = stat.rsplit(") ", 1)[1].split()
        return int(fields_after_name[19])
    except (FileNotFoundError, IndexError, OSError, UnicodeError, ValueError):
        return None


def running_state(state_path: Path) -> dict[str, object] | None:
    state = _read_json(state_path)
    if state is None:
        return None
    if state.get("schema") != STATE_SCHEMA:
        raise ControlError(f"unsupported process-state schema: {state_path}")
    try:
        pid = int(state["pid"])
        expected_ticks = int(state["process_start_ticks"])
    except (KeyError, TypeError, ValueError) as error:
        raise ControlError(f"invalid process identity: {state_path}") from error
    if pid <= 1:
        raise ControlError(f"unsafe process identity: {state_path}")
    if _process_start_ticks(pid) != expected_ticks:
        return None
    return state


def _remove_stale(state_path: Path, request_path: Path) -> None:
    state_path.unlink(missing_ok=True)
    request_path.unlink(missing_ok=True)


def status(state_path: Path, request_path: Path) -> int:
    state = running_state(state_path)
    if state is None:
        _remove_stale(state_path, request_path)
        print("Pool status: stopped")
        return 3
    dashboard = str(state.get("dashboard_url", ""))
    dashboard_status = "starting or unreachable"
    try:
        with urllib.request.urlopen(dashboard, timeout=2) as response:
            if response.status == 200:
                dashboard_status = "healthy"
    except (OSError, ValueError, urllib.error.URLError):
        pass
    print("Pool status: running")
    print(f"Process ID: {state['pid']}")
    print(f"Dashboard: {dashboard} ({dashboard_status})")
    print(f"Log: {state.get('log_file', 'unavailable')}")
    return 0


def stop(state_path: Path, request_path: Path, timeout_seconds: int) -> int:
    state = running_state(state_path)
    if state is None:
        _remove_stale(state_path, request_path)
        print("Pool is already stopped.")
        return 0
    request_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with request_path.open("xb") as target:
            target.write(SHUTDOWN_REQUEST)
            target.flush()
            os.fsync(target.fileno())
    except FileExistsError:
        if request_path.is_symlink() or request_path.read_bytes() != SHUTDOWN_REQUEST:
            raise ControlError(f"refusing malformed shutdown request: {request_path}")
    pid = int(state["pid"])
    expected_ticks = int(state["process_start_ticks"])
    print(f"Graceful shutdown requested for process {pid}.")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _process_start_ticks(pid) != expected_ticks:
            _remove_stale(state_path, request_path)
            print("Pool stopped cleanly.")
            return 0
        time.sleep(0.25)
    raise ControlError(
        f"pool did not stop within {timeout_seconds} seconds; it was not force-killed; "
        f"inspect {state.get('log_file', 'the pool log')}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "stop"))
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).parent / "pool-data")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be between 1 and 600")
    control = args.data_dir.resolve() / "pool-control"
    state_path = control / "pool-state.json"
    request_path = control / "shutdown.request"
    try:
        if args.action == "status":
            return status(state_path, request_path)
        return stop(state_path, request_path, args.timeout_seconds)
    except (ControlError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
