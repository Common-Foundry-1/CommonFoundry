from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1]
SCRIPT = SCRIPTS / "control-production-v4-pool.py"
SPEC = importlib.util.spec_from_file_location("production_v4_pool_control", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class PoolControlTests(unittest.TestCase):
    def write_state(self, root: Path, *, pid: int = 4321, ticks: int = 9876) -> Path:
        control = root / "pool-control"
        control.mkdir()
        state = control / "pool-state.json"
        state.write_text(
            json.dumps(
                {
                    "schema": CONTROL.STATE_SCHEMA,
                    "pid": pid,
                    "process_start_ticks": ticks,
                    "dashboard_url": "http://127.0.0.1:1/",
                    "log_file": str(root / "pool.log"),
                }
            ),
            encoding="utf-8",
        )
        return state

    def test_process_identity_includes_start_ticks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-pool-control-") as directory:
            state = self.write_state(Path(directory))
            with mock.patch.object(CONTROL, "_process_start_ticks", return_value=9876):
                self.assertEqual(CONTROL.running_state(state)["pid"], 4321)
            with mock.patch.object(CONTROL, "_process_start_ticks", return_value=9877):
                self.assertIsNone(CONTROL.running_state(state))

    def test_stop_writes_exact_authenticated_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-pool-control-") as directory:
            root = Path(directory)
            state = self.write_state(root)
            request = state.parent / "shutdown.request"
            calls = 0

            def process_ticks(_pid: int) -> int | None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return 9876
                self.assertEqual(request.read_bytes(), CONTROL.SHUTDOWN_REQUEST)
                return None

            with (
                mock.patch.object(CONTROL, "_process_start_ticks", side_effect=process_ticks),
                mock.patch.object(CONTROL.time, "sleep"),
            ):
                self.assertEqual(CONTROL.stop(state, request, 1), 0)
            self.assertFalse(state.exists())
            self.assertFalse(request.exists())

    def test_stop_rejects_malformed_existing_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-pool-control-") as directory:
            root = Path(directory)
            state = self.write_state(root)
            request = state.parent / "shutdown.request"
            request.write_bytes(b"stop\n")
            with mock.patch.object(CONTROL, "_process_start_ticks", return_value=9876):
                with self.assertRaises(CONTROL.ControlError):
                    CONTROL.stop(state, request, 1)

    def test_control_files_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-pool-control-") as directory:
            state = Path(directory) / "state.json"
            state.write_bytes(b"x" * (CONTROL.MAX_CONTROL_BYTES + 1))
            with self.assertRaises(CONTROL.ControlError):
                CONTROL.running_state(state)


if __name__ == "__main__":
    unittest.main()
