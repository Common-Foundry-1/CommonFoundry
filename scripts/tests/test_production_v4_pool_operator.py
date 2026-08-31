from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1]
SCRIPT = SCRIPTS / "production-v4-pool-operator.py"
SPEC = importlib.util.spec_from_file_location("production_v4_pool_operator", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
OPERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OPERATOR)


class PoolOperatorTests(unittest.TestCase):
    def make_operator(self, root: Path) -> object:
        assets = root / "operator-dashboard"
        assets.mkdir()
        (assets / "index.html").write_text("operator", encoding="utf-8")
        return OPERATOR.PoolOperator(root, root / "pool-data", assets, "127.0.0.1:22448")

    def write_settings(self, operator: object) -> None:
        operator.control_dir.mkdir(parents=True)
        operator.settings_file.write_text(
            json.dumps(
                {
                    "schema": OPERATOR.SETTINGS_SCHEMA,
                    "public_numeric_address": "203.0.113.20",
                    "private_bind_address": "192.168.1.20",
                    "pool_port": 22445,
                    "p2p_bind": "0.0.0.0:22444",
                    "dashboard_bind": "127.0.0.1:22446",
                    "operator_fee_bps": 300,
                    "pplns_window_shares": 0,
                    "unrelated_setting": "preserved",
                }
            ),
            encoding="utf-8",
        )

    def test_only_loopback_bind_is_accepted(self) -> None:
        self.assertEqual(OPERATOR._parse_bind("127.0.0.1:22448"), ("127.0.0.1", 22448))
        with self.assertRaises(Exception):
            OPERATOR._parse_bind("0.0.0.0:22448")

    def test_settings_update_is_bounded_and_preserves_other_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-operator-") as directory:
            operator = self.make_operator(Path(directory))
            self.write_settings(operator)
            operator.save_settings({"operator_fee_bps": 250, "pplns_window_shares": 512})
            saved = json.loads(operator.settings_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["operator_fee_bps"], 250)
            self.assertEqual(saved["pplns_window_shares"], 512)
            self.assertEqual(saved["unrelated_setting"], "preserved")
            with self.assertRaises(OPERATOR.OperatorError):
                operator.save_settings({"operator_fee_bps": 10_001, "pplns_window_shares": 0})

    def test_stop_uses_exact_graceful_shutdown_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-operator-") as directory:
            operator = self.make_operator(Path(directory))
            identity_key = "process_start_utc_ticks" if OPERATOR.os.name == "nt" else "process_start_ticks"
            state = {"schema": OPERATOR.STATE_SCHEMA, "pid": 4321, identity_key: 9876, "log_file": "ignored"}
            calls = 0

            def identity(_pid: int) -> int | None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return 9876
                self.assertEqual(operator.shutdown_file.read_bytes(), OPERATOR.SHUTDOWN_REQUEST)
                return None

            with (
                mock.patch.object(operator, "running_state", return_value=state),
                mock.patch.object(OPERATOR, "_process_start_identity", side_effect=identity),
                mock.patch.object(OPERATOR.time, "sleep"),
            ):
                operator.stop_pool(timeout_seconds=1)
            self.assertFalse(operator.shutdown_file.exists())

    def test_status_exposes_only_editable_settings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-operator-") as directory:
            operator = self.make_operator(Path(directory))
            self.write_settings(operator)
            with mock.patch.object(operator, "running_state", return_value=None):
                status = operator.status()
            serialized = json.dumps(status)
            self.assertNotIn("unrelated_setting", serialized)
            self.assertEqual(status["settings"]["operator_fee_bps"], 300)

    def test_http_mutations_require_csrf_token(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-operator-") as directory:
            operator = self.make_operator(Path(directory))
            self.write_settings(operator)
            server = OPERATOR.OperatorServer(("127.0.0.1", 0), operator)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"http://127.0.0.1:{server.server_port}/api/v1/operator/settings"
            body = json.dumps({"operator_fee_bps": 250, "pplns_window_shares": 0}).encode()
            try:
                request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(request, timeout=2)
                self.assertEqual(denied.exception.code, 403)
                denied.exception.close()

                allowed = urllib.request.Request(
                    url,
                    data=body,
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "X-CMFD-Operator-CSRF": operator.csrf_token,
                        "Origin": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                with urllib.request.urlopen(allowed, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                self.assertEqual(operator.settings()["operator_fee_bps"], 250)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
