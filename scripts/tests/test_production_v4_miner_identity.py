#!/usr/bin/env python3
"""Focused tests for the Linux ProductionV4 miner identity gate."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "scripts" / "run-production-v4-miner.sh"
HEREDOC_START = 'NETWORK_ID="$(python3 - "$INPUT_MANIFEST" "$CMFD_MINER" <<\'PY\'\n'
HEREDOC_END = '\nPY\n)"'


def identity_validator_source() -> str:
    source = LAUNCHER.read_text(encoding="utf-8")
    start = source.index(HEREDOC_START) + len(HEREDOC_START)
    end = source.index(HEREDOC_END, start)
    return source[start:end]


class ProductionV4MinerIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.network_id = "12" * 32
        self.manifest = self.directory / "inputs.json"
        self.manifest.write_text(
            json.dumps({"network_id": self.network_id}), encoding="utf-8"
        )
        self.mock_miner = self.directory / "network-info"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def identity(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "format": "commonfoundry-miner-network-info",
            "format_version": 1,
            "network_id": self.network_id,
            "network_name": "CommonFoundry ProductionV4 Testnet-1",
            "network_profile": "ProductionV4 Testnet-1",
            "proof_selection": "ProductionV4",
            "build_source_commit": None,
        }
        value.update(overrides)
        return value

    def run_validator(
        self, output: bytes, *, stderr: bytes = b""
    ) -> subprocess.CompletedProcess[bytes]:
        self.mock_miner.write_text(
            "import sys\n"
            f"sys.stdout.buffer.write({output!r})\n"
            f"sys.stderr.buffer.write({stderr!r})\n",
            encoding="utf-8",
        )
        return subprocess.run(
            [
                sys.executable,
                "-c",
                identity_validator_source(),
                str(self.manifest),
                sys.executable,
            ],
            cwd=self.directory,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @staticmethod
    def canonical(value: dict[str, object]) -> bytes:
        return (
            json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")

    def test_accepts_exact_production_v4_testnet_identity(self) -> None:
        result = self.run_validator(self.canonical(self.identity()))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout.strip(), self.network_id.encode())

    def test_rejects_wrong_network_or_proof(self) -> None:
        for identity in (
            self.identity(network_id="34" * 32),
            self.identity(proof_selection="ProductionV3"),
        ):
            with self.subTest(identity=identity):
                result = self.run_validator(self.canonical(identity))
                self.assertNotEqual(result.returncode, 0)

    def test_rejects_duplicate_or_noncanonical_json(self) -> None:
        canonical = self.canonical(self.identity())
        duplicate = canonical.replace(
            b'"network_id":"',
            b'"network_id":"'
            + self.network_id.encode()
            + b'","network_id":"',
            1,
        )
        for output in (duplicate, canonical.replace(b'{"format"', b'{ "format"', 1)):
            with self.subTest(output=output):
                result = self.run_validator(output)
                self.assertNotEqual(result.returncode, 0)

    def test_rejects_success_diagnostics_or_invalid_source_commit(self) -> None:
        diagnostic = self.run_validator(self.canonical(self.identity()), stderr=b"warning\n")
        self.assertNotEqual(diagnostic.returncode, 0)
        invalid_commit = self.run_validator(
            self.canonical(self.identity(build_source_commit="AA" * 20))
        )
        self.assertNotEqual(invalid_commit.returncode, 0)


if __name__ == "__main__":
    unittest.main()
