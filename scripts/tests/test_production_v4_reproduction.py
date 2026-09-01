from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_testnet_template_network_matches_authenticated_manifest(self) -> None:
        reproduction._require_testnet_template_network(
            {"network_id": bytes.fromhex(reproduction.EXPECTED_NETWORK_ID)},
            {"network_id": reproduction.EXPECTED_NETWORK_ID},
        )

    def test_report_rejects_rcnet_template_before_proof_verification(self) -> None:
        rcnet_network_id = bytes.fromhex(
            "3e99d45959c19c0053d8e9fef34875b57b46a8a1ce330637daddab515bc7b92d"
        )
        with (
            mock.patch.object(reproduction, "toolchain_versions", return_value={}),
            mock.patch.object(reproduction, "verify_frozen_spec", return_value={}),
            mock.patch.object(reproduction, "verify_core_vector", return_value={}),
            mock.patch.object(
                reproduction,
                "verify_artifacts",
                return_value=({"network_id": reproduction.EXPECTED_NETWORK_ID}, []),
            ),
            mock.patch.object(
                reproduction,
                "parse_template",
                return_value=({"network_id": rcnet_network_id}, {}),
            ),
            mock.patch.object(reproduction, "verify") as verifier,
        ):
            with self.assertRaisesRegex(
                reproduction.ReproductionError, "authenticated input manifest"
            ):
                reproduction.build_report(
                    repo_root=Path("unused-repo"),
                    source_commit="a" * 40,
                    operator="independent-reproducer",
                    input_manifest=Path("unused-input-manifest.json"),
                    model_bank=Path("unused-model-bank"),
                    fixed_record=Path("unused-fixed-record.json"),
                    artifact_dir=Path("unused-artifacts"),
                    template=Path("unused-template.json"),
                    proof=Path("unused-proof.bin"),
                    fresh_generation_attested=False,
                    generation_commands=[],
                )
            verifier.assert_not_called()

    def test_matching_rcnet_template_and_manifest_are_not_testnet_qualification(self) -> None:
        rcnet_network_id = (
            "3e99d45959c19c0053d8e9fef34875b57b46a8a1ce330637daddab515bc7b92d"
        )
        with self.assertRaisesRegex(
            reproduction.ReproductionError, "qualified Testnet-1 network"
        ):
            reproduction._require_testnet_template_network(
                {"network_id": bytes.fromhex(rcnet_network_id)},
                {"network_id": rcnet_network_id},
            )


if __name__ == "__main__":
    unittest.main()
