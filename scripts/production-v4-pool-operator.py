#!/usr/bin/env python3
"""Loopback-only operator console for a packaged ProductionV4 pool."""

from __future__ import annotations

import argparse
import ctypes
import json
import mimetypes
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import deque
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


STATE_SCHEMA = "CommonFoundry/ProductionV4/PoolProcess/v1"
SETTINGS_SCHEMA = "CommonFoundry/ProductionV4/PoolSettings/v1"
SHUTDOWN_REQUEST = b"CMFD_POOL_SHUTDOWN_V1\n"
MAX_CONTROL_BYTES = 65_536
MAX_REQUEST_BYTES = 8_192
WINDOWS_EPOCH_TICKS = 504_911_232_000_000_000


class OperatorError(RuntimeError):
    """Raised when an operator action cannot be completed safely."""


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        if path.is_symlink():
            raise OperatorError(f"control file must not be a symbolic link: {path}")
        stat = path.stat()
    except FileNotFoundError:
        return None
    if not path.is_file() or stat.st_size > MAX_CONTROL_BYTES:
        raise OperatorError(f"invalid control file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OperatorError(f"could not read control file: {path}") from error
    if not isinstance(value, dict):
        raise OperatorError(f"control file must contain an object: {path}")
    return value


def _linux_process_start_ticks(pid: int) -> int | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        return int(stat.rsplit(") ", 1)[1].split()[19])
    except (FileNotFoundError, IndexError, OSError, UnicodeError, ValueError):
        return None


def _windows_process_start_ticks(pid: int) -> int | None:
    if os.name != "nt":
        return None
    process_query_limited_information = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return None
    creation = ctypes.c_uint64()
    exit_time = ctypes.c_uint64()
    kernel = ctypes.c_uint64()
    user = ctypes.c_uint64()
    try:
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return None
        return int(creation.value) + WINDOWS_EPOCH_TICKS
    finally:
        kernel32.CloseHandle(handle)


def _process_start_identity(pid: int) -> int | None:
    if os.name == "nt":
        return _windows_process_start_ticks(pid)
    return _linux_process_start_ticks(pid)


def _atomic_write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    if path.exists() and path.is_symlink():
        raise OperatorError(f"settings file must not be a symbolic link: {path}")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as target:
            json.dump(value, target, ensure_ascii=True, indent=2)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _loopback_http_url(value: object) -> str:
    parsed = urllib.parse.urlparse(str(value))
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise OperatorError("saved dashboard URL is not loopback HTTP")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OperatorError("saved dashboard URL contains unsupported components")
    return parsed.geturl()


class PoolOperator:
    def __init__(self, bundle_dir: Path, data_dir: Path, assets_dir: Path, bind: str) -> None:
        self.bundle_dir = bundle_dir.resolve()
        self.data_dir = data_dir.resolve()
        self.assets_dir = assets_dir.resolve()
        self.bind = bind
        self.control_dir = self.data_dir / "pool-control"
        self.state_file = self.control_dir / "pool-state.json"
        self.settings_file = self.control_dir / "pool-settings.json"
        self.shutdown_file = self.control_dir / "shutdown.request"
        self.csrf_token = secrets.token_urlsafe(32)
        self.action_lock = threading.Lock()
        self.events: deque[dict[str, object]] = deque(maxlen=24)
        self.record_event("Operator console started", f"Listening on {bind}", "Console")

    def record_event(self, event: str, details: str, source: str) -> None:
        self.events.appendleft(
            {
                "time_unix_seconds": int(time.time()),
                "event": event,
                "details": details,
                "source": source,
            }
        )

    def settings(self) -> dict[str, object] | None:
        settings = _read_json(self.settings_file)
        if settings is None:
            return None
        if settings.get("schema") != SETTINGS_SCHEMA:
            raise OperatorError(f"unsupported settings schema: {self.settings_file}")
        return settings

    def running_state(self) -> dict[str, object] | None:
        state = _read_json(self.state_file)
        if state is None:
            return None
        if state.get("schema") != STATE_SCHEMA:
            raise OperatorError(f"unsupported process-state schema: {self.state_file}")
        try:
            pid = int(state["pid"])
            identity_key = "process_start_utc_ticks" if os.name == "nt" else "process_start_ticks"
            expected_identity = int(state[identity_key])
        except (KeyError, TypeError, ValueError) as error:
            raise OperatorError(f"invalid process identity: {self.state_file}") from error
        if pid <= 1 or _process_start_identity(pid) != expected_identity:
            return None
        return state

    def _uptime_seconds(self, state: dict[str, object]) -> int | None:
        try:
            if os.name == "nt":
                started_ticks = int(state["process_start_utc_ticks"])
                now_ticks = int((datetime.now(UTC) - datetime(1, 1, 1, tzinfo=UTC)).total_seconds() * 10_000_000)
                return max(0, (now_ticks - started_ticks) // 10_000_000)
            pid = int(state["pid"])
            started_ticks = int(state["process_start_ticks"])
            clock_ticks = os.sysconf("SC_CLK_TCK")
            boot_uptime = float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])
            return max(0, int(boot_uptime - (started_ticks / clock_ticks)))
        except (KeyError, OSError, TypeError, ValueError):
            return None

    def _pool_snapshot(self, state: dict[str, object]) -> tuple[dict[str, object] | None, str | None]:
        try:
            dashboard_url = _loopback_http_url(state.get("dashboard_url"))
            endpoint = urllib.parse.urljoin(dashboard_url, "api/v1/pool")
            request = urllib.request.Request(endpoint, headers={"Accept": "application/json"})
            with urllib.request.urlopen(request, timeout=2) as response:
                if response.status != HTTPStatus.OK:
                    return None, f"dashboard returned HTTP {response.status}"
                if int(response.headers.get("Content-Length", "0") or 0) > 2_000_000:
                    return None, "dashboard response was unexpectedly large"
                payload = response.read(2_000_001)
                if len(payload) > 2_000_000:
                    return None, "dashboard response was unexpectedly large"
                value = json.loads(payload)
                if not isinstance(value, dict):
                    return None, "dashboard response was not an object"
                return value, None
        except (OperatorError, OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as error:
            return None, str(error)

    def status(self) -> dict[str, object]:
        settings = self.settings()
        state = self.running_state()
        snapshot = None
        dashboard_error = None
        if state is not None:
            snapshot, dashboard_error = self._pool_snapshot(state)
        public_settings = None
        if settings is not None:
            public_settings = {
                "public_numeric_address": settings.get("public_numeric_address"),
                "private_bind_address": settings.get("private_bind_address"),
                "pool_port": settings.get("pool_port"),
                "p2p_bind": settings.get("p2p_bind"),
                "dashboard_bind": settings.get("dashboard_bind"),
                "operator_fee_bps": int(settings.get("operator_fee_bps", 300)),
                "pplns_window_shares": int(settings.get("pplns_window_shares", 0)),
            }
        return {
            "generated_at_unix_seconds": int(time.time()),
            "platform": "windows" if os.name == "nt" else "linux",
            "operator_bind": self.bind,
            "action_busy": self.action_lock.locked(),
            "pool": {
                "running": state is not None,
                "pid": int(state["pid"]) if state is not None else None,
                "uptime_seconds": self._uptime_seconds(state) if state is not None else None,
                "dashboard_url": state.get("dashboard_url") if state is not None else None,
                "dashboard_healthy": snapshot is not None,
                "dashboard_error": dashboard_error,
                "log_file": state.get("log_file") if state is not None else self._latest_log_file(),
            },
            "settings": public_settings,
            "snapshot": snapshot,
            "paths": {
                "data_directory": str(self.data_dir),
                "settings_file": str(self.settings_file),
            },
            "events": list(self.events),
        }

    def save_settings(self, payload: dict[str, object]) -> None:
        settings = self.settings()
        if settings is None:
            raise OperatorError("saved pool settings are unavailable; start the pool once first")
        fee = payload.get("operator_fee_bps")
        window = payload.get("pplns_window_shares")
        if isinstance(fee, bool) or not isinstance(fee, int) or not 0 <= fee <= 10_000:
            raise OperatorError("operator_fee_bps must be an integer from 0 through 10000")
        if isinstance(window, bool) or not isinstance(window, int) or not 0 <= window <= 65_536:
            raise OperatorError("pplns_window_shares must be 0 or an integer through 65536")
        settings["operator_fee_bps"] = fee
        settings["pplns_window_shares"] = window
        _atomic_write_json(self.settings_file, settings)
        window_label = "automatic" if window == 0 else f"{window} shares"
        self.record_event("Settings saved", f"Fee {fee / 100:.2f}%; window {window_label}", "Operator")

    def _write_shutdown_request(self) -> None:
        self.control_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with self.shutdown_file.open("xb") as target:
                target.write(SHUTDOWN_REQUEST)
                target.flush()
                os.fsync(target.fileno())
        except FileExistsError:
            if self.shutdown_file.is_symlink() or self.shutdown_file.read_bytes() != SHUTDOWN_REQUEST:
                raise OperatorError(f"refusing malformed shutdown request: {self.shutdown_file}")

    def stop_pool(self, timeout_seconds: int = 180) -> None:
        state = self.running_state()
        if state is None:
            raise OperatorError("pool is already stopped")
        pid = int(state["pid"])
        identity_key = "process_start_utc_ticks" if os.name == "nt" else "process_start_ticks"
        expected_identity = int(state[identity_key])
        self._write_shutdown_request()
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if _process_start_identity(pid) != expected_identity:
                self.state_file.unlink(missing_ok=True)
                self.shutdown_file.unlink(missing_ok=True)
                self.record_event("Pool stopped", "Graceful shutdown completed", "Control")
                return
            time.sleep(0.25)
        raise OperatorError("pool did not stop within 180 seconds; it was not force-killed")

    def start_pool(self) -> None:
        if self.running_state() is not None:
            raise OperatorError("pool is already running")
        if self.settings() is None:
            raise OperatorError("saved pool settings are unavailable; run the pool launcher once first")
        if os.name == "nt":
            start_script = self.bundle_dir / "START-POOL.ps1"
            if not start_script.is_file():
                raise OperatorError(f"pool launcher is missing: {start_script}")
            subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(start_script),
                    "-DataDirectory",
                    str(self.data_dir),
                ],
                cwd=self.bundle_dir,
                creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP,
                close_fds=True,
            )
        else:
            start_script = self.bundle_dir / "START-POOL.sh"
            if not start_script.is_file():
                raise OperatorError(f"pool launcher is missing: {start_script}")
            launch_log = self.data_dir / "logs" / "operator-launch.log"
            launch_log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            stream = launch_log.open("ab")
            try:
                subprocess.Popen(
                    ["bash", str(start_script), "", "", str(self.data_dir)],
                    cwd=self.bundle_dir,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    close_fds=True,
                )
            finally:
                stream.close()
        self.record_event("Pool launch requested", "Starting with saved settings", "Control")

    def run_action(self, action: str) -> None:
        if action == "start":
            self.start_pool()
            return
        if action == "stop":
            self.stop_pool()
            return
        if action == "restart":
            self.stop_pool()
            self.start_pool()
            self.record_event("Pool restart requested", "Graceful stop followed by start", "Control")
            return
        raise OperatorError("unsupported operator action")

    def _latest_log_file(self) -> str | None:
        log_dir = self.data_dir / "logs"
        try:
            candidates = [path for path in log_dir.glob("pool-*.log") if path.is_file() and not path.is_symlink()]
            return str(max(candidates, key=lambda path: path.stat().st_mtime)) if candidates else None
        except OSError:
            return None

    def log_tail(self, max_bytes: int = 96_000) -> dict[str, object]:
        state = self.running_state()
        candidate = str(state.get("log_file", "")) if state is not None else self._latest_log_file()
        if not candidate:
            return {"path": None, "text": "No pool log is available yet."}
        log_path = Path(candidate).resolve()
        log_root = (self.data_dir / "logs").resolve()
        if log_path.parent != log_root or log_path.is_symlink() or not log_path.is_file():
            raise OperatorError("saved log path is outside the pool log directory")
        size = log_path.stat().st_size
        with log_path.open("rb") as source:
            if size > max_bytes:
                source.seek(-max_bytes, os.SEEK_END)
            data = source.read(max_bytes)
        return {"path": str(log_path), "text": data.decode("utf-8", errors="replace")}


class OperatorHandler(BaseHTTPRequestHandler):
    server_version = "CommonFoundryOperator/1"

    @property
    def operator(self) -> PoolOperator:
        return self.server.operator  # type: ignore[attr-defined]

    def log_message(self, format_string: str, *args: object) -> None:
        print(f"{self.address_string()} - {format_string % args}")

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-CMFD-Operator", "1")

    def _send_json(self, status: HTTPStatus, value: dict[str, object]) -> None:
        payload = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json(status, {"ok": False, "error": message})

    def _trusted_host(self) -> bool:
        host = self.headers.get("Host", "").lower()
        port = self.server.server_port
        return host in {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def _authorized_mutation(self) -> bool:
        port = self.server.server_port
        origin = self.headers.get("Origin", "")
        if origin and origin.lower() not in {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            f"http://[::1]:{port}",
        }:
            return False
        return secrets.compare_digest(
            self.headers.get("X-CMFD-Operator-CSRF", ""), self.operator.csrf_token
        )

    def _read_body(self) -> dict[str, object]:
        if self.headers.get_content_type() != "application/json":
            raise OperatorError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise OperatorError("invalid Content-Length") from error
        if not 0 <= length <= MAX_REQUEST_BYTES:
            raise OperatorError("request body is too large")
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as error:
            raise OperatorError("request body is not valid JSON") from error
        if not isinstance(value, dict):
            raise OperatorError("request body must be a JSON object")
        return value

    def do_GET(self) -> None:
        if not self._trusted_host():
            self._send_error(HTTPStatus.FORBIDDEN, "operator console accepts loopback hosts only")
            return
        route = urllib.parse.urlparse(self.path).path
        try:
            if route == "/api/v1/operator/session":
                self._send_json(HTTPStatus.OK, {"ok": True, "csrf_token": self.operator.csrf_token})
            elif route == "/api/v1/operator/status":
                self._send_json(HTTPStatus.OK, {"ok": True, **self.operator.status()})
            elif route == "/api/v1/operator/log":
                self._send_json(HTTPStatus.OK, {"ok": True, **self.operator.log_tail()})
            elif route.startswith("/api/"):
                self._send_error(HTTPStatus.NOT_FOUND, "operator API route not found")
            else:
                self._serve_asset(route)
        except OperatorError as error:
            self._send_error(HTTPStatus.CONFLICT, str(error))
        except OSError as error:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(error))

    def do_POST(self) -> None:
        if not self._trusted_host() or not self._authorized_mutation():
            self._send_error(HTTPStatus.FORBIDDEN, "operator authorization failed")
            return
        route = urllib.parse.urlparse(self.path).path
        try:
            payload = self._read_body()
            if not self.operator.action_lock.acquire(blocking=False):
                self._send_error(HTTPStatus.CONFLICT, "another operator action is still running")
                return
            try:
                if route == "/api/v1/operator/settings":
                    self.operator.save_settings(payload)
                elif route.startswith("/api/v1/operator/action/"):
                    self.operator.run_action(route.rsplit("/", 1)[-1])
                else:
                    self._send_error(HTTPStatus.NOT_FOUND, "operator API route not found")
                    return
            finally:
                self.operator.action_lock.release()
            self._send_json(HTTPStatus.OK, {"ok": True})
        except OperatorError as error:
            self._send_error(HTTPStatus.CONFLICT, str(error))
        except OSError as error:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(error))

    def _serve_asset(self, route: str) -> None:
        relative = "index.html" if route in {"", "/"} else route.lstrip("/")
        candidate = (self.operator.assets_dir / relative).resolve()
        if self.operator.assets_dir not in candidate.parents and candidate != self.operator.assets_dir:
            self._send_error(HTTPStatus.FORBIDDEN, "invalid asset path")
            return
        if not candidate.is_file() or candidate.is_symlink():
            candidate = self.operator.assets_dir / "index.html"
        if not candidate.is_file():
            self._send_error(HTTPStatus.NOT_FOUND, "operator dashboard assets are missing")
            return
        payload = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class OperatorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], operator: PoolOperator) -> None:
        self.operator = operator
        super().__init__(address, OperatorHandler)


def _parse_bind(value: str) -> tuple[str, int]:
    if value.count(":") != 1:
        raise argparse.ArgumentTypeError("bind must use loopback IPv4 in HOST:PORT form")
    host, port_text = value.rsplit(":", 1)
    if host != "127.0.0.1":
        raise argparse.ArgumentTypeError("operator console must bind to 127.0.0.1")
    try:
        port = int(port_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("bind port must be an integer") from error
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("bind port must be between 1 and 65535")
    return host, port


def _existing_console(url: str) -> bool:
    try:
        request = urllib.request.Request(f"{url}api/v1/operator/session", headers={"Host": urllib.parse.urlparse(url).netloc})
        with urllib.request.urlopen(request, timeout=1) as response:
            return response.status == HTTPStatus.OK and response.headers.get("X-CMFD-Operator") == "1"
    except (OSError, ValueError, urllib.error.URLError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--assets-dir", type=Path)
    parser.add_argument("--bind", type=_parse_bind, default=_parse_bind("127.0.0.1:19448"))
    parser.add_argument("--open-browser", action="store_true")
    args = parser.parse_args()
    bundle_dir = args.bundle_dir.resolve()
    data_dir = (args.data_dir or bundle_dir / "pool-data").resolve()
    assets_dir = (args.assets_dir or bundle_dir / "operator-dashboard").resolve()
    host, port = args.bind
    url = f"http://{host}:{port}/"
    if _existing_console(url):
        if args.open_browser:
            webbrowser.open(url)
        print(f"Operator console is already running: {url}")
        return 0
    if not (assets_dir / "index.html").is_file():
        print(f"ERROR: built operator dashboard is missing: {assets_dir}", file=sys.stderr)
        return 1
    operator = PoolOperator(bundle_dir, data_dir, assets_dir, f"{host}:{port}")
    try:
        server = OperatorServer((host, port), operator)
    except OSError as error:
        print(f"ERROR: could not start operator console on {url}: {error}", file=sys.stderr)
        return 1
    if args.open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    print(f"Common Foundry Pool Operator Console: {url}")
    print("Local access only. Press Ctrl+C to stop the console; the pool keeps running.")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
