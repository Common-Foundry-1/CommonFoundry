"""Loopback-only, bounded mainnet UTXO proof-origin transport.

This service is separate from the explorer failover router. It accepts only
the Germany node or the dedicated reverse tunnel from the Proxmox relay.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import threading
import time
from collections import deque
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable


MAINNET_NETWORK_ID = "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62"
NETWORK_HEADER = "X-CMFD-Network-Id"
OUTPOINT_PATH = re.compile(r"^/v1/explorer/utxo/[0-9a-f]{64}/(0|[1-9][0-9]{0,9})$")
MAX_RESPONSE_BYTES = 4096
UPSTREAM_PORT = 29443
LISTEN_PORT = 29457
MODE_PORTS = {
    "germany": (29457, 29443),
    "proxmox": (29458, 29459),
}


def valid_outpoint_path(path: str) -> bool:
    match = OUTPOINT_PATH.fullmatch(path)
    return match is not None and int(match.group(1)) <= 0xFFFF_FFFF


class RateLimiter:
    def __init__(
        self,
        *,
        per_ip: int = 600,
        global_limit: int = 10_000,
        period: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.per_ip = per_ip
        self.global_limit = global_limit
        self.period = period
        self.clock = clock
        self._lock = threading.Lock()
        self._global: deque[float] = deque()
        self._by_ip: dict[str, deque[float]] = {}

    def allow(self, ip: str | None) -> bool:
        now = self.clock()
        cutoff = now - self.period
        with self._lock:
            while self._global and self._global[0] <= cutoff:
                self._global.popleft()
            if len(self._global) >= self.global_limit:
                return False
            if ip is not None:
                bucket = self._by_ip.get(ip)
                if bucket is None:
                    if len(self._by_ip) >= self.global_limit:
                        self._by_ip = {
                            key: values
                            for key, values in self._by_ip.items()
                            if values and values[-1] > cutoff
                        }
                    if len(self._by_ip) >= self.global_limit:
                        return False
                    bucket = deque()
                    self._by_ip[ip] = bucket
                while bucket and bucket[0] <= cutoff:
                    bucket.popleft()
                if len(bucket) >= self.per_ip:
                    return False
                bucket.append(now)
            self._global.append(now)
            return True


class ProofServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64

    def __init__(
        self,
        address: tuple[str, int] = ("127.0.0.1", LISTEN_PORT),
        *,
        upstream_port: int = UPSTREAM_PORT,
        expected_network_id: str = MAINNET_NETWORK_ID,
        limiter: RateLimiter | None = None,
    ) -> None:
        if address[0] != "127.0.0.1":
            raise ValueError("proof origin must bind to IPv4 loopback")
        self.upstream_port = upstream_port
        self.expected_network_id = expected_network_id
        self.limiter = limiter or RateLimiter()
        self._slots = threading.BoundedSemaphore(32)
        super().__init__(address, ProofHandler)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class ProofHandler(BaseHTTPRequestHandler):
    server: ProofServer
    server_version = "CMFDProofOrigin"

    def version_string(self) -> str:
        return self.server_version

    def setup(self) -> None:
        self.request.settimeout(5.0)
        super().setup()

    def log_message(self, _format: str, *_args) -> None:
        # Paths disclose which public outpoints a wallet is checking.
        pass

    def respond(self, status: int, body: bytes, *, network_id: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if network_id is not None:
            self.send_header(NETWORK_HEADER, network_id)
        if status == 405:
            self.send_header("Allow", "GET")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def error(self, status: int, code: str) -> None:
        self.respond(status, json.dumps({"error": code}, separators=(",", ":")).encode())

    def do_GET(self) -> None:
        if not valid_outpoint_path(self.path):
            self.error(404, "not_found")
            return
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length") not in (None, "0"):
            self.error(400, "invalid_request")
            return
        raw_ip = self.headers.get("CF-Connecting-IP")
        try:
            ip = str(ipaddress.ip_address(raw_ip.strip())) if raw_ip is not None else None
        except ValueError:
            self.error(400, "invalid_client_ip")
            return
        if not self.server.limiter.allow(ip):
            self.error(429, "rate_limited")
            return

        connection = HTTPConnection("127.0.0.1", self.server.upstream_port, timeout=5.0)
        try:
            connection.request("GET", self.path, headers={"Accept": "application/json"})
            upstream = connection.getresponse()
            if upstream.status not in (200, 404):
                self.error(503, "proof_node_unavailable")
                return
            if upstream.getheader(NETWORK_HEADER) != self.server.expected_network_id:
                self.error(503, "proof_network_mismatch")
                return
            content_type = upstream.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                self.error(502, "proof_response_invalid")
                return
            declared = upstream.getheader("Content-Length")
            if declared is not None and (not declared.isdecimal() or int(declared) > MAX_RESPONSE_BYTES):
                self.error(502, "proof_response_invalid")
                return
            body = upstream.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                self.error(502, "proof_response_invalid")
                return
            self.respond(upstream.status, body, network_id=self.server.expected_network_id)
        except (OSError, HTTPException, TimeoutError):
            self.error(503, "proof_node_unavailable")
        finally:
            connection.close()

    def do_POST(self) -> None:
        self.error(405, "method_not_allowed")

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST
    do_HEAD = do_POST


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=tuple(MODE_PORTS), required=True)
    mode = parser.parse_args().mode
    listen_port, upstream_port = MODE_PORTS[mode]
    with ProofServer(("127.0.0.1", listen_port), upstream_port=upstream_port) as server:
        print(f"CMFD {mode} proof origin listening on 127.0.0.1:{listen_port}", flush=True)
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
