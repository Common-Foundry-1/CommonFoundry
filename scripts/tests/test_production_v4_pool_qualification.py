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
    def test_windows_pool_scripts_resolve_the_default_data_dir_after_parameter_binding(
        self,
    ) -> None:
        for name in ["run-production-v4-pool.ps1", "control-production-v4-pool.ps1"]:
            with self.subTest(script=name):
                script = (SCRIPTS / name).read_text(encoding="utf-8")
                parameter_block, body = script.split("\n)\n", 1)
                self.assertNotIn("$PSScriptRoot", parameter_block)
                self.assertIn(
                    "$DataDirectory = Join-Path $PSScriptRoot 'pool-data'", body
                )

    def test_operator_controls_cover_both_platforms(self) -> None:
        root = Path(__file__).resolve().parents[2]
        required = [
            "scripts/control-production-v4-pool.ps1",
            "scripts/control-production-v4-pool.py",
            "packaging/production-v4-pool/windows/POOL-STATUS.bat",
            "packaging/production-v4-pool/windows/STOP-POOL.bat",
            "packaging/production-v4-pool/windows/RESTART-POOL.bat",
            "packaging/production-v4-pool/windows/INSTALL-POOL-AUTOSTART.bat",
            "packaging/production-v4-pool/linux/POOL-STATUS.sh",
            "packaging/production-v4-pool/linux/STOP-POOL.sh",
            "packaging/production-v4-pool/linux/RESTART-POOL.sh",
            "packaging/production-v4-pool/linux/INSTALL-POOL-SERVICE.sh",
        ]
        self.assertTrue(all((root / path).is_file() for path in required))

    def test_core_gate_is_exact_and_dashboard_is_optional(self) -> None:
        core = QUALIFICATION.qualification_commands(False)
        full = QUALIFICATION.qualification_commands(True)
        self.assertEqual(
            [name for name, _command, _cwd in core],
            [
                "pool_control_tests",
                "node_production_v4_regression_tests",
                "node_strict_clippy",
            ],
        )
        self.assertEqual(
            [name for name, _command, _cwd in full[3:]],
            ["pool_dashboard_tests", "pool_dashboard_build"],
        )
        expected_npm = "npm.cmd" if os.name == "nt" else "npm"
        self.assertEqual(full[3][1][0], expected_npm)
        self.assertTrue(
            all(
                command[1] == f"+{QUALIFICATION.rust_toolchain()}"
                for _name, command, _cwd in core[1:]
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
