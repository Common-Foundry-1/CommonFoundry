"""Boundary tests for the Germany and Proxmox UTXO proof transports."""

from __future__ import annotations

import sys
import socket
import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cmfd_utxo_proof_proxy import (  # noqa: E402
    MAINNET_NETWORK_ID,
    MODE_PORTS,
    NETWORK_HEADER,
    ProofServer,
    RateLimiter,
    valid_outpoint_path,
)


TXID = "ab" * 32
PATH = f"/v1/explorer/utxo/{TXID}/0"


class Backend(BaseHTTPRequestHandler):
    status = 200
    network_id = MAINNET_NETWORK_ID
    content_type = "application/json"
    body = b'{"available":true}'
    declare_length = True
    seen: list[str] = []

    def do_GET(self) -> None:
        type(self).seen.append(self.path)
        self.send_response(type(self).status)
        self.send_header(NETWORK_HEADER, type(self).network_id)
        self.send_header("Content-Type", type(self).content_type)
        if type(self).declare_length:
            self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, _format: str, *_args) -> None:
        pass


class ProofProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        Backend.status = 200
        Backend.network_id = MAINNET_NETWORK_ID
        Backend.content_type = "application/json"
        Backend.body = b'{"available":true}'
        Backend.declare_length = True
        Backend.seen = []
        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()
        self.proxy = ProofServer(
            ("127.0.0.1", 0),
            upstream_port=self.backend.server_port,
            limiter=RateLimiter(per_ip=100, global_limit=100),
        )
        self.proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.proxy_thread.start()

    def tearDown(self) -> None:
        self.proxy.shutdown()
        self.proxy.server_close()
        self.proxy_thread.join(timeout=2)
        self.backend.shutdown()
        self.backend.server_close()
        self.backend_thread.join(timeout=2)

    def request(self, path: str, *, method: str = "GET", headers: dict[str, str] | None = None):
        connection = HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=7)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_exact_route_forwards_only_identified_json_from_fixed_backend(self) -> None:
        status, headers, body = self.request(PATH)
        self.assertEqual(status, 200)
        self.assertEqual(headers[NETWORK_HEADER], MAINNET_NETWORK_ID)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body, Backend.body)
        self.assertEqual(Backend.seen, [PATH])
        Backend.status = 404
        Backend.body = b'{"error":"not_found"}'
        status, headers, body = self.request(PATH)
        self.assertEqual(status, 404)
        self.assertEqual(headers[NETWORK_HEADER], MAINNET_NETWORK_ID)
        self.assertEqual(body, Backend.body)

    def test_malformed_routes_and_mutating_methods_never_reach_backend(self) -> None:
        for path in (
            f"/v1/explorer/utxo/{TXID.upper()}/0",
            f"/v1/explorer/utxo/{TXID}/00",
            f"/v1/explorer/utxo/{TXID}/4294967296",
            f"/v1/explorer/utxo/{TXID}/0?x=1",
            "/v1/explorer/block/1",
        ):
            self.assertFalse(valid_outpoint_path(path))
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request(PATH, method="POST")[0], 405)
        self.assertEqual(self.request(PATH, headers={"Content-Length": "1"})[0], 400)
        self.assertEqual(Backend.seen, [])

    def test_wrong_network_redirect_and_oversize_fail_closed(self) -> None:
        Backend.network_id = "00" * 32
        self.assertEqual(self.request(PATH)[0], 503)
        Backend.network_id = MAINNET_NETWORK_ID
        Backend.status = 302
        self.assertEqual(self.request(PATH)[0], 503)
        Backend.status = 200
        Backend.body = b"x" * 4097
        self.assertEqual(self.request(PATH)[0], 502)
        Backend.declare_length = False
        self.assertEqual(self.request(PATH)[0], 502)
        Backend.body = b"{}"
        Backend.content_type = "text/html"
        self.assertEqual(self.request(PATH)[0], 502)

    def test_unavailable_backend_fails_closed_without_network_header(self) -> None:
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            self.proxy.upstream_port = unused.getsockname()[1]
        status, headers, _body = self.request(PATH)
        self.assertEqual(status, 503)
        self.assertNotIn(NETWORK_HEADER, headers)

    def test_invalid_client_ip_and_rate_limit_fail_closed(self) -> None:
        self.assertEqual(self.request(PATH, headers={"CF-Connecting-IP": "not-an-ip"})[0], 400)
        self.proxy.limiter = RateLimiter(per_ip=1, global_limit=2)
        headers = {"CF-Connecting-IP": "192.0.2.1"}
        self.assertEqual(self.request(PATH, headers=headers)[0], 200)
        self.assertEqual(self.request(PATH, headers=headers)[0], 429)
        self.assertEqual(self.request(PATH, headers={"CF-Connecting-IP": "192.0.2.2"})[0], 200)
        self.assertEqual(self.request(PATH, headers={"CF-Connecting-IP": "192.0.2.3"})[0], 429)
        self.assertEqual(Backend.seen, [PATH, PATH])

    def test_limiter_resets_after_window_and_server_cannot_bind_publicly(self) -> None:
        self.assertEqual(MODE_PORTS["germany"], (29457, 29443))
        self.assertEqual(MODE_PORTS["proxmox"], (29458, 29459))
        self.assertNotIn(29453, (MODE_PORTS["germany"][1], MODE_PORTS["proxmox"][1]))
        self.assertNotIn(29455, (MODE_PORTS["germany"][1], MODE_PORTS["proxmox"][1]))
        self.assertNotIn(29456, (MODE_PORTS["germany"][1], MODE_PORTS["proxmox"][1]))
        now = [100.0]
        limiter = RateLimiter(per_ip=1, global_limit=1, clock=lambda: now[0])
        self.assertTrue(limiter.allow("192.0.2.1"))
        self.assertFalse(limiter.allow("192.0.2.1"))
        now[0] += 61
        self.assertTrue(limiter.allow("192.0.2.1"))
        with self.assertRaises(ValueError):
            ProofServer(("0.0.0.0", 0))


if __name__ == "__main__":
    unittest.main()
