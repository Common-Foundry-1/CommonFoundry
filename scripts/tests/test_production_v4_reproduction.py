from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

import blake3

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import production_v4_reproduction as reproduction


class ReproductionEvidenceTests(unittest.TestCase):
    def test_published_spec_and_vector_are_self_consistent(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        specifications = reproduction.verify_frozen_spec(repo_root)
        vector = reproduction.verify_core_vector(repo_root)
        self.assertEqual(len(specifications), 3)
        self.assertEqual(vector["rejections_verified"], 5)

    def test_file_identity_hashes_in_bounded_chunks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-v4-reproduction-") as temporary:
            path = Path(temporary) / "artifact.bin"
            value = bytes(range(251)) * 40_000
            path.write_bytes(value)
            identity = reproduction.file_identity(path)
            self.assertEqual(identity["bytes"], len(value))
            self.assertEqual(identity["sha256"], hashlib.sha256(value).hexdigest())
            self.assertEqual(identity["blake3"], blake3.blake3(value).hexdigest())

    def test_report_write_is_canonical_and_create_new(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-v4-reproduction-") as temporary:
            path = Path(temporary) / "report.json"
            report = {"z": 1, "a": "value"}
            encoded = reproduction.write_new(path, report)
            self.assertEqual(encoded, b'{"a":"value","z":1}\n')
            with self.assertRaisesRegex(reproduction.ReproductionError, "overwrite"):
                reproduction.write_new(path, report)

    def test_toolchain_report_always_captures_python(self) -> None:
        versions = reproduction.toolchain_versions()
        self.assertIn("python", versions)
        self.assertTrue(versions["python"])

    def test_changed_vector_is_rejected(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="cmfd-v4-reproduction-") as temporary:
            copied_root = Path(temporary)
            destination = copied_root / "docs/consensus"
            destination.mkdir(parents=True)
            source = repo_root / "docs/consensus/production-v4-core-vector-v1.json"
            vector = json.loads(source.read_text(encoding="utf-8"))
            vector["expected"]["work_digest"] = "00" * 32
            (destination / source.name).write_text(json.dumps(vector), encoding="utf-8")
            with self.assertRaisesRegex(
                reproduction.ReproductionError, "derived values mismatch"
            ):
                reproduction.verify_core_vector(copied_root)


if __name__ == "__main__":
    unittest.main()
