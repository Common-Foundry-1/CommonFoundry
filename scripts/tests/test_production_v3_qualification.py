from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import production_v3_qualification as qualification


class GitFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repository"
        self.artifacts = self.root / "artifacts"
        self.repo.mkdir()
        self.artifacts.mkdir()
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        self.git("init", "--quiet")
        self.git("config", "user.name", "Qualification Test")
        self.git("config", "user.email", "qualification-test@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("add", "README.md")
        self.git("commit", "--quiet", "-m", "fixture")

    def close(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            capture_output=True,
        )
        return result.stdout.decode("utf-8", "strict").strip()

    @property
    def commit(self) -> str:
        return self.git("rev-parse", "HEAD")


def write_json(path: Path, value: dict[str, object]) -> bytes:
    encoded = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    path.write_bytes(encoded)
    return encoded


class QualificationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = GitFixture()
        root = self.fixture.artifacts
        self.bank = root / "MODEL-V2.bank"
        self.record = root / "DORY-V3-MODEL-RECORD-V2.json"
        self.request = root / "qualification-request.json"
        self.proof = root / "qualification-proof.cmfd"
        self.journal = root / "producer-journal.jsonl"
        self.executable = root / "cmfd-consensus.exe"
        self.independent_verifier_binary = (
            root / qualification.INDEPENDENT_VERIFIER_BINARY_NAME
        )
        self.build_stdout = root / "build-stdout.log"
        self.build_stderr = root / "build-stderr.log"
        self.producer_stdout = root / "producer-stdout.json"
        self.producer_stderr = root / "producer-stderr.log"
        self.verifier_stdout = root / "fresh-verifier-stdout.json"
        self.verifier_stderr = root / "fresh-verifier-stderr.log"
        self.producer_report = root / "producer-report.json"
        self.verifier_report = root / qualification.INDEPENDENT_VERIFIER_REPORT_NAME
        self.manifest = root / qualification.QUALIFICATION_MANIFEST_NAME
        self.candidate = root / "PRODUCTION-V3-ACTIVATION-CANDIDATE.json"

        self.bank.write_bytes(b"bank")
        self.record.write_bytes(b"record\n")
        self.request.write_bytes(b"request\n")
        self.proof.write_bytes(b"proof-wire")
        self.journal.write_bytes(b"diagnostic journal fixture\n")
        self.executable.write_bytes(b"executable")
        self.independent_verifier_binary.write_bytes(b"executable")
        self.build_stdout.write_bytes(b"")
        self.build_stderr.write_bytes(b"build diagnostics")
        self.producer_stderr.write_bytes(b"")
        self.verifier_stderr.write_bytes(b"")

        self.journal_summary = {
            "journal_version": 1,
            "run_identity": "11" * 32,
            "final_record_digest": "22" * 32,
            "event_count": 16,
            "journal_bytes": self.journal.stat().st_size,
            "complete_file_digest": "33" * 32,
            "diagnostic_only": True,
            "completion_marker": False,
            "resumable": False,
        }
        shared = {
            "network_id": "72" * 32,
            "block_height": 1,
            "nonce": 0,
            "request_digest": "44" * 32,
            "record_digest": "55" * 32,
            "model_identity_digest": "66" * 32,
            "setup_identity": "77" * 32,
            "wire_blake3_digest": "88" * 32,
        }
        self.producer = {
            "report_version": 4,
            "padded_variables": 33,
            "composed_claims": 134,
            "verifier_passes": 2,
            "maximum_native_block_rows": 131_072,
            **shared,
            "provisional_scratch_floor_bytes": qualification.PRODUCTION_SCRATCH_FLOOR_BYTES,
            "native_resource_projection_complete": True,
            "exact_peak_scratch_instrumented": True,
            "retained_scratch_entries": 0,
            "retained_scratch_logical_bytes": 0,
            "report_output_is_completion_marker": True,
            "publication_crash_atomic": False,
            "wire_bytes": self.proof.stat().st_size,
            "qualification_journal": self.journal_summary,
        }
        self.verifier = {
            "report_version": 2,
            **shared,
            "wire_bytes": self.proof.stat().st_size,
            "verifier_only": True,
            "producer_report_checked": True,
            "qualification_journal_checked": True,
            "qualification_journal": self.journal_summary,
        }
        self._write_reports()

    def tearDown(self) -> None:
        self.fixture.close()

    def _write_reports(self) -> None:
        producer_bytes = write_json(self.producer_report, self.producer)
        verifier_bytes = write_json(self.verifier_report, self.verifier)
        self.producer_stdout.write_bytes(producer_bytes)
        self.verifier_stdout.write_bytes(verifier_bytes)

    def _receipt(self, name: str, pid: int) -> qualification.ProcessReceipt:
        stdout = {
            "build": self.build_stdout,
            "producer": self.producer_stdout,
            "verifier": self.verifier_stdout,
        }[name]
        stderr = {
            "build": self.build_stderr,
            "producer": self.producer_stderr,
            "verifier": self.verifier_stderr,
        }[name]
        return qualification.ProcessReceipt(
            argv=(name,),
            pid=pid,
            started_at_utc="2026-08-25T00:00:00Z",
            finished_at_utc="2026-08-25T00:00:01Z",
            exit_code=0,
            stdout_path=stdout,
            stderr_path=stderr,
        )

    def _preverified_artifacts(self) -> dict[str, dict[str, object]]:
        return qualification._artifact_bindings(
            {
                "bank": self.bank,
                "record_v2": self.record,
                "request": self.request,
                "proof": self.proof,
                "producer_report": self.producer_report,
                "journal": self.journal,
            }
        )

    def finalize(
        self,
        preverified_artifacts: dict[str, dict[str, object]] | None = None,
    ) -> tuple[str, str]:
        if preverified_artifacts is None:
            preverified_artifacts = self._preverified_artifacts()
        return qualification.finalize_evidence(
            repo=self.fixture.repo,
            expected_commit=self.fixture.commit,
            bank=self.bank,
            record=self.record,
            request=self.request,
            proof=self.proof,
            producer_report=self.producer_report,
            journal=self.journal,
            verifier_report=self.verifier_report,
            consensus_executable=self.executable,
            independent_verifier_binary=self.independent_verifier_binary,
            build_stdout=self.build_stdout,
            build_stderr=self.build_stderr,
            producer_stdout=self.producer_stdout,
            producer_stderr=self.producer_stderr,
            verifier_stdout=self.verifier_stdout,
            verifier_stderr=self.verifier_stderr,
            manifest_output=self.manifest,
            candidate_output=self.candidate,
            maximum_native_block_rows=131_072,
            scratch_floor_bytes=qualification.PRODUCTION_SCRATCH_FLOOR_BYTES,
            scratch_margin_bytes=1,
            available_scratch_bytes=qualification.PRODUCTION_SCRATCH_FLOOR_BYTES + 1,
            build_receipt=self._receipt("build", 100),
            producer_receipt=self._receipt("producer", 101),
            verifier_receipt=self._receipt("verifier", 102),
            preverified_artifacts=preverified_artifacts,
        )

    def test_complete_run_emits_bound_nonactivating_candidate(self) -> None:
        manifest_sha256, candidate_sha256 = self.finalize()
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        candidate = json.loads(self.candidate.read_text(encoding="utf-8"))

        self.assertEqual(manifest["source_commit"], self.fixture.commit)
        self.assertFalse(manifest["journal_semantics"]["used_as_completion_evidence"])
        for role in (
            "bank",
            "record_v2",
            "request",
            "proof",
            "producer_report",
            "journal",
            "verifier_report",
        ):
            self.assertRegex(manifest["artifacts"][role]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(candidate["schema"], qualification.CANDIDATE_SCHEMA)
        self.assertEqual(candidate["status"], "candidate_only_not_activated")
        self.assertFalse(candidate["eligible_for_automatic_activation"])
        self.assertEqual(
            candidate["qualification_source_commit"], self.fixture.commit
        )
        self.assertEqual(candidate["qualification_manifest_sha256"], manifest_sha256)
        self.assertEqual(
            candidate["independent_verifier_report_sha256"],
            manifest["artifacts"]["verifier_report"]["sha256"],
        )
        self.assertEqual(
            candidate["independent_verifier_binary_sha256"],
            manifest["artifacts"]["independent_verifier_binary"]["sha256"],
        )
        self.assertEqual(qualification._sha256_file(self.candidate), candidate_sha256)

    def test_existing_outputs_are_never_overwritten(self) -> None:
        self.finalize()
        original_manifest = self.manifest.read_bytes()
        original_candidate = self.candidate.read_bytes()
        with self.assertRaisesRegex(
            qualification.QualificationHarnessError, "already exists"
        ):
            self.finalize()
        self.assertEqual(self.manifest.read_bytes(), original_manifest)
        self.assertEqual(self.candidate.read_bytes(), original_candidate)

    def test_partial_journal_never_becomes_completion_evidence(self) -> None:
        self.producer["report_output_is_completion_marker"] = False
        self._write_reports()
        with self.assertRaisesRegex(
            qualification.QualificationHarnessError,
            "report_output_is_completion_marker",
        ):
            self.finalize()
        self.assertFalse(self.manifest.exists())
        self.assertFalse(self.candidate.exists())

    def test_stdout_must_exactly_match_each_persisted_report(self) -> None:
        self.producer_stdout.write_bytes(self.producer_stdout.read_bytes() + b"extra\n")
        with self.assertRaisesRegex(
            qualification.QualificationHarnessError, "byte-for-byte"
        ):
            self.finalize()

    def test_inputs_cannot_change_after_their_verified_use(self) -> None:
        expected = self._preverified_artifacts()
        self.bank.write_bytes(b"changed bank")
        with self.assertRaisesRegex(
            qualification.QualificationHarnessError,
            "changed after the bytes were used",
        ):
            self.finalize(expected)
        self.assertFalse(self.manifest.exists())
        self.assertFalse(self.candidate.exists())

    def test_non_rcnet_qualification_is_rejected(self) -> None:
        self.producer["network_id"] = "63" * 32
        self.verifier["network_id"] = "63" * 32
        self._write_reports()
        with self.assertRaisesRegex(
            qualification.QualificationHarnessError, "network_id"
        ):
            self.finalize()
        self.assertFalse(self.manifest.exists())
        self.assertFalse(self.candidate.exists())

    def test_unchecked_verifier_report_is_rejected(self) -> None:
        self.verifier["qualification_journal_checked"] = False
        self._write_reports()
        with self.assertRaisesRegex(
            qualification.QualificationHarnessError,
            "qualification_journal_checked",
        ):
            self.finalize()
        self.assertFalse(self.manifest.exists())
        self.assertFalse(self.candidate.exists())

    def test_verifier_must_be_a_distinct_process(self) -> None:
        with self.assertRaisesRegex(
            qualification.QualificationHarnessError, "distinct process"
        ):
            qualification.finalize_evidence(
                repo=self.fixture.repo,
                expected_commit=self.fixture.commit,
                bank=self.bank,
                record=self.record,
                request=self.request,
                proof=self.proof,
                producer_report=self.producer_report,
                journal=self.journal,
                verifier_report=self.verifier_report,
                consensus_executable=self.executable,
                independent_verifier_binary=self.independent_verifier_binary,
                build_stdout=self.build_stdout,
                build_stderr=self.build_stderr,
                producer_stdout=self.producer_stdout,
                producer_stderr=self.producer_stderr,
                verifier_stdout=self.verifier_stdout,
                verifier_stderr=self.verifier_stderr,
                manifest_output=self.manifest,
                candidate_output=self.candidate,
                maximum_native_block_rows=131_072,
                scratch_floor_bytes=qualification.PRODUCTION_SCRATCH_FLOOR_BYTES,
                scratch_margin_bytes=1,
                available_scratch_bytes=qualification.PRODUCTION_SCRATCH_FLOOR_BYTES + 1,
                build_receipt=self._receipt("build", 100),
                producer_receipt=self._receipt("producer", 101),
                verifier_receipt=self._receipt("verifier", 101),
                preverified_artifacts=self._preverified_artifacts(),
            )


class QualificationArgumentTests(unittest.TestCase):
    def test_scratch_floor_always_includes_positive_margin(self) -> None:
        self.assertEqual(
            qualification.required_scratch_bytes(1),
            qualification.PRODUCTION_SCRATCH_FLOOR_BYTES + 1,
        )
        with self.assertRaises(qualification.QualificationHarnessError):
            qualification.required_scratch_bytes(0)

    def test_windows_scratch_must_be_explicitly_on_d_drive(self) -> None:
        qualification._require_d_drive_scratch(Path(r"D:\qualification\scratch"))
        for path in (Path(r"C:\qualification\scratch"), Path(r"D:relative")):
            with self.assertRaisesRegex(
                qualification.QualificationHarnessError, "absolute D"
            ):
                qualification._require_d_drive_scratch(path)

    def test_parser_rejects_zero_margin_and_zero_rows(self) -> None:
        parser = qualification._parser()
        required = [
            "--repo", "C:\\repo",
            "--expected-commit", "1" * 40,
            "--bank", "D:\\bank",
            "--record", "D:\\record",
            "--request", "D:\\request",
            "--output-directory", "D:\\output",
            "--scratch-directory", "D:\\scratch",
        ]
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(required + ["--scratch-margin-bytes", "0"])
            with self.assertRaises(SystemExit):
                parser.parse_args(required + ["--maximum-native-block-rows", "0"])


if __name__ == "__main__":
    unittest.main()
