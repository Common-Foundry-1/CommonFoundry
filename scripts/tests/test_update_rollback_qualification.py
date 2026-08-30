from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import release_integrity as integrity
import update_rollback_qualification as qualification


DRIVER = r'''from __future__ import annotations
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["CMFD_QUAL_INSTALL_ROOT"])
active = root / "ACTIVE.json"

def identity(prefix: str) -> dict[str, object]:
    return {
        "checksum_sha256": os.environ[f"CMFD_QUAL_{prefix}_CHECKSUM"],
        "commit": os.environ[f"CMFD_QUAL_{prefix}_COMMIT"],
        "healthy": True,
        "network_id": os.environ["CMFD_QUAL_NETWORK_ID"],
        "network_name": os.environ["CMFD_QUAL_NETWORK_NAME"],
        "schema": "CMFD_INSTALLED_RELEASE_PROBE_V1",
        "version": os.environ[f"CMFD_QUAL_{prefix}_VERSION"],
        "virtual_genesis_hash": os.environ["CMFD_QUAL_VIRTUAL_GENESIS_HASH"],
    }

def write(prefix: str) -> None:
    temporary = root / "ACTIVE.json.new"
    temporary.write_text(
        json.dumps(identity(prefix), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(active)

action = sys.argv[1]
if action == "install_baseline":
    write("BASELINE")
elif action in {"apply_candidate", "reapply_candidate"}:
    write("CANDIDATE")
elif action == "attempt_interrupted_candidate":
    (root / "candidate.partial").write_bytes(b"partial")
    if os.environ.get("CMFD_TEST_BAD_INTERRUPT") == "1":
        write("CANDIDATE")
    raise SystemExit(17)
elif action == "restart_candidate":
    if not active.exists():
        raise SystemExit(18)
elif action == "rollback":
    write("BASELINE")
elif action == "probe_active":
    sys.stdout.buffer.write(active.read_bytes())
else:
    raise SystemExit(19)
'''


class UpdateRollbackQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.baseline_stage = self.root / "baseline"
        self.candidate_stage = self.root / "candidate"
        self.baseline_stage.mkdir()
        self.candidate_stage.mkdir()
        self.driver = self.root / "driver.py"
        self.driver.write_text(DRIVER, encoding="utf-8", newline="\n")
        self.scenario = self.root / "scenario.json"
        command = ["{python}", str(self.driver), "ACTION"]
        commands = {
            name: [*command[:-1], name]
            for name in qualification.COMMAND_NAMES
        }
        self.scenario.write_bytes(
            integrity._canonical_json(
                {
                    "commands": commands,
                    "platform": qualification._host_platform_label(),
                    "schema": qualification.SCENARIO_SCHEMA,
                    "timeout_seconds": 30,
                }
            )
        )
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_bytes(b"trusted signer\n")
        self.verifier = self.root / "ssh-keygen"
        self.verifier.write_bytes(b"verifier")
        self.install_root = self.root / "installed"
        self.report = self.root / "report.json"
        self.network_id = "a" * 64
        self.genesis = "b" * 64
        self.baseline = self.release(
            self.baseline_stage,
            commit="1" * 40,
            version="1.0.0-rc.1",
            checksum="c" * 64,
        )
        self.candidate = self.release(
            self.candidate_stage,
            commit="2" * 40,
            version="1.0.0-rc.2",
            checksum="d" * 64,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def release(
        self, stage: Path, *, commit: str, version: str, checksum: str
    ) -> dict[str, object]:
        network = {
            "network": {
                "name": "CommonFoundry RCNet-1",
                "network_id": self.network_id,
                "virtual_genesis_hash": self.genesis,
            },
            "proof_of_work": {"build_source_commit": commit},
        }
        (stage / integrity.PRODUCTION_RC_NETWORK_INFO_NAME).write_bytes(
            integrity._canonical_json(network)
        )
        return {
            "commit": commit,
            "files": [
                {
                    "name": integrity.PRODUCTION_RC_NETWORK_INFO_NAME,
                    "sha256": integrity._sha256_file(
                        stage / integrity.PRODUCTION_RC_NETWORK_INFO_NAME
                    ),
                    "size": (
                        stage / integrity.PRODUCTION_RC_NETWORK_INFO_NAME
                    ).stat().st_size,
                }
            ],
            "schema": "CMFD_AUTHENTICATED_DOWNLOAD_V1",
            "signature": {
                "allowed_signers_sha256": "7" * 64,
                "checksum_sha256": checksum,
                "namespace": integrity.RELEASE_SIGNATURE_NAMESPACE,
                "signer_identity": "release@example.invalid",
                "verifier_sha256": "8" * 64,
            },
            "source_tree": "e" * 40,
            "version": version,
        }

    def run_qualification(self) -> dict[str, object]:
        return qualification.qualify_update_rollback(
            baseline_stage=self.baseline_stage,
            candidate_stage=self.candidate_stage,
            allowed_signers=self.allowed,
            signer_identity="release@example.invalid",
            ssh_keygen=self.verifier,
            scenario_path=self.scenario,
            install_root=self.install_root,
            report_path=self.report,
        )

    @mock.patch(
        "update_rollback_qualification.integrity.verify_signed_download"
    )
    def test_complete_update_restart_rollback_reapply_sequence(self, verify) -> None:
        verify.side_effect = [
            self.baseline,
            self.candidate,
            self.baseline,
            self.candidate,
        ]
        report = self.run_qualification()
        self.assertEqual(report["status"], "qualified")
        self.assertEqual(len(report["steps"]), 6)
        self.assertEqual(
            [step["active"]["version"] for step in report["steps"]],
            [
                "1.0.0-rc.1",
                "1.0.0-rc.1",
                "1.0.0-rc.2",
                "1.0.0-rc.2",
                "1.0.0-rc.1",
                "1.0.0-rc.2",
            ],
        )
        self.assertEqual(
            json.loads(self.report.read_text(encoding="utf-8")), report
        )
        self.assertTrue((self.install_root / "candidate.partial").exists())

    @mock.patch(
        "update_rollback_qualification.integrity.verify_signed_download"
    )
    def test_interrupted_update_must_leave_baseline_active(self, verify) -> None:
        verify.side_effect = [self.baseline, self.candidate]
        self.driver.write_text(
            DRIVER.replace(
                'if os.environ.get("CMFD_TEST_BAD_INTERRUPT") == "1":', "if True:"
            ),
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "wrong active release"
        ):
            self.run_qualification()
        self.assertFalse(self.report.exists())

    @mock.patch(
        "update_rollback_qualification.integrity.verify_signed_download"
    )
    def test_authentication_failure_prevents_installation(self, verify) -> None:
        verify.side_effect = integrity.IntegrityError("bad signature")
        with self.assertRaisesRegex(
            qualification.QualificationError, "authentication failed"
        ):
            self.run_qualification()
        self.assertFalse(self.install_root.exists())
        self.assertFalse(self.report.exists())

    @mock.patch(
        "update_rollback_qualification.integrity.verify_signed_download"
    )
    def test_candidate_must_be_newer_and_on_the_same_network(self, verify) -> None:
        self.candidate["version"] = "1.0.0-rc.1"
        verify.side_effect = [self.baseline, self.candidate]
        with self.assertRaisesRegex(qualification.QualificationError, "not newer"):
            self.run_qualification()
        self.assertFalse(self.install_root.exists())

        self.candidate["version"] = "1.0.0-rc.2"
        candidate_network = json.loads(
            (self.candidate_stage / integrity.PRODUCTION_RC_NETWORK_INFO_NAME).read_text(
                encoding="utf-8"
            )
        )
        candidate_network["network"]["network_id"] = "f" * 64
        (self.candidate_stage / integrity.PRODUCTION_RC_NETWORK_INFO_NAME).write_bytes(
            integrity._canonical_json(candidate_network)
        )
        network_path = (
            self.candidate_stage / integrity.PRODUCTION_RC_NETWORK_INFO_NAME
        )
        self.candidate["files"][0]["sha256"] = integrity._sha256_file(network_path)
        self.candidate["files"][0]["size"] = network_path.stat().st_size
        verify.side_effect = [self.baseline, self.candidate]
        with self.assertRaisesRegex(
            qualification.QualificationError, "changes network identity"
        ):
            self.run_qualification()
        self.assertFalse(self.install_root.exists())

    @mock.patch(
        "update_rollback_qualification.integrity.verify_signed_download"
    )
    def test_network_information_cannot_change_after_authentication(
        self, verify
    ) -> None:
        verify.side_effect = [self.baseline, self.candidate]
        candidate_network = json.loads(
            (
                self.candidate_stage / integrity.PRODUCTION_RC_NETWORK_INFO_NAME
            ).read_text(encoding="utf-8")
        )
        candidate_network["network"]["name"] = "substituted"
        (
            self.candidate_stage / integrity.PRODUCTION_RC_NETWORK_INFO_NAME
        ).write_bytes(integrity._canonical_json(candidate_network))
        with self.assertRaisesRegex(
            qualification.QualificationError, "changed after verification"
        ):
            self.run_qualification()
        self.assertFalse(self.install_root.exists())
        self.assertFalse(self.report.exists())

    @mock.patch(
        "update_rollback_qualification.integrity.verify_signed_download"
    )
    def test_candidate_must_use_the_same_trusted_signer_policy(self, verify) -> None:
        self.candidate["signature"]["signer_identity"] = "other@example.invalid"
        verify.side_effect = [self.baseline, self.candidate]
        with self.assertRaisesRegex(
            qualification.QualificationError, "trusted signer policy"
        ):
            self.run_qualification()
        self.assertFalse(self.install_root.exists())
        self.assertFalse(self.report.exists())

    @mock.patch(
        "update_rollback_qualification.integrity.verify_signed_download"
    )
    def test_existing_report_prevents_installation(self, verify) -> None:
        verify.side_effect = [self.baseline, self.candidate]
        self.report.write_bytes(b"existing evidence")
        with self.assertRaisesRegex(
            qualification.QualificationError, "report already exists"
        ):
            self.run_qualification()
        self.assertFalse(self.install_root.exists())
        self.assertEqual(self.report.read_bytes(), b"existing evidence")

    def test_semver_ordering(self) -> None:
        self.assertTrue(qualification._newer("1.0.0", "1.0.0-rc.9"))
        self.assertTrue(qualification._newer("1.0.0-rc.10", "1.0.0-rc.9"))
        self.assertFalse(qualification._newer("1.0.0-rc.2", "1.0.0-rc.2"))
        with self.assertRaises(qualification.QualificationError):
            qualification._newer("1.0.0-rc.01", "1.0.0-rc.1")

    def test_scenario_must_match_the_host_platform(self) -> None:
        scenario = json.loads(self.scenario.read_text(encoding="utf-8"))
        scenario["platform"] = (
            "linux-x86_64"
            if qualification._host_platform_label() == "windows-x86_64"
            else "windows-x86_64"
        )
        self.scenario.write_bytes(integrity._canonical_json(scenario))
        with self.assertRaisesRegex(
            qualification.QualificationError, "targets another platform"
        ):
            self.run_qualification()
        self.assertFalse(self.install_root.exists())


if __name__ == "__main__":
    unittest.main()
