from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1]
SCRIPT = SCRIPTS / "production-v4-pool-qualification.py"
SPEC = importlib.util.spec_from_file_location("production_v4_pool_qualification", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
QUALIFICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFICATION)


class PoolQualificationTests(unittest.TestCase):
    def test_core_gate_is_exact_and_dashboard_is_optional(self) -> None:
        core = QUALIFICATION.qualification_commands(False)
        full = QUALIFICATION.qualification_commands(True)
        self.assertEqual(
            [name for name, _command, _cwd in core],
            [
                "node_production_v4_regression_tests",
                "node_strict_clippy",
            ],
        )
        self.assertEqual(
            [name for name, _command, _cwd in full[2:]],
            ["pool_dashboard_tests", "pool_dashboard_build"],
        )
        expected_npm = "npm.cmd" if os.name == "nt" else "npm"
        self.assertEqual(full[2][1][0], expected_npm)
        self.assertTrue(
            all(
                command[1] == f"+{QUALIFICATION.rust_toolchain()}"
                for _name, command, _cwd in core
            )
        )

    def test_source_commit_format_is_fail_closed(self) -> None:
        root = Path(__file__).resolve().parents[2]
        for value in ["", "A" * 40, "0" * 39, "g" * 40, "0" * 64]:
            with self.subTest(value=value):
                with self.assertRaises(QUALIFICATION.QualificationError):
                    QUALIFICATION.validate_source(root, value)

    def test_report_and_logs_are_create_new(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-pool-qualification-") as directory:
            root = Path(directory)
            log = root / "gate.log"
            identity = QUALIFICATION._write_log(log, b"green\n")
            self.assertEqual(identity["bytes"], 6)
            with self.assertRaises(QUALIFICATION.QualificationError):
                QUALIFICATION._write_log(log, b"replacement")

            report = root / "report.json"
            encoded = QUALIFICATION.write_report(report, {"status": "verified"})
            self.assertEqual(json.loads(encoded), {"status": "verified"})
            with self.assertRaises(QUALIFICATION.QualificationError):
                QUALIFICATION.write_report(report, {"status": "replacement"})


if __name__ == "__main__":
    unittest.main()
