"""Synthetic qualification data; real cryptographic qualification is separate."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mainnet_qualification as qualification
import package_mainnet as package


def fixture(plan):
    files = {role: {"bytes": 64, "sha256": "a" * 64, "blake3": "b" * 64}
             for role in qualification.FILE_ROLES}
    for role, artifact in (("model_bank", "bank"), ("fixed_artifact_record", "fixed_record")):
        files[role] = copy.deepcopy(plan["payload"]["rules"]["artifacts"][artifact])
    files["qualification_proof"]["bytes"] = 12025320
    return {"schema": qualification.SCHEMA, "qualification_source_commit": "a" * 40,
            "verifier_sources_sha256": "a" * 64, "files": files,
            "declarations": dict(qualification.DECLARATIONS),
            "verifier_result": {
                "schema": "CommonFoundry/ForgeMatrix/V4/IndependentVerificationResult/v1",
                "implemented_stages_accepted": True, "candidate_claims_verified": True,
                "target_met": True, "full_cryptographic_proof_verified": True, "remaining_stages": [],
                "proof": {"bytes": 12025320, "sha256": "a" * 64, "canonical": True},
                "algebra": {"basefold_merkle_and_query_folds_verified": True,
                            "initial_activation_boundaries_verified": True, "basefold_transcripts_replayed": 3,
                            "opening_reductions_verified": 3, "relations_verified": 6}}}


def bind_fixture_source(repo, commit, record):
    record["qualification_source_commit"] = commit
    sources = qualification.verifier_sources(repo, commit)
    record["verifier_sources_sha256"] = qualification.digest(package.canonical(sources))
    data = package.integrity._tracked_blob_at(repo, commit, qualification.VERIFIER)
    record["files"]["fresh_process_verifier_script"] = {
        "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "blake3": package.integrity.blake3.blake3(data).hexdigest()}


class MainnetQualificationTests(unittest.TestCase):
    def setUp(self):
        artifact = {"bytes": 32, "sha256": "b" * 64, "blake3": "c" * 64}
        self.record = fixture({"payload": {"rules": {"artifacts": {"bank": artifact, "fixed_record": artifact}}}})

    def test_internal_record_is_not_a_release_approval(self):
        self.assertEqual(qualification.validate(package.canonical(self.record)), self.record)
        self.assertIs(self.record["declarations"]["independent_reproduction"], False)
        self.assertIs(self.record["declarations"]["mainnet_authorization"], False)

    def test_partial_or_mismatched_proofs_are_rejected(self):
        changes = [lambda r: r["verifier_result"].update(full_cryptographic_proof_verified=False),
                   lambda r: r["verifier_result"].update(candidate_claims_verified=False),
                   lambda r: r["verifier_result"].update(remaining_stages=["unchecked"]),
                   lambda r: r["verifier_result"]["algebra"].update(initial_activation_boundaries_verified=False),
                   lambda r: r["verifier_result"]["algebra"].update(relations_verified=5),
                   lambda r: r["verifier_result"]["proof"].update(sha256="f" * 64),
                   lambda r: r["files"]["qualification_proof"].update(bytes=177),
                   lambda r: r["declarations"].update(external_audit=True),
                   lambda r: r.update(schema="CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_QUALIFICATION_V1")]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                record = copy.deepcopy(self.record)
                change(record)
                with self.assertRaises((qualification.Error, ValueError)):
                    qualification.validate(package.canonical(record))


class MainnetQualificationPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cmfd-internal-qualification-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "source"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / qualification.VERIFIER).write_bytes(b"# synthetic test entry point, never executed\n")
        (self.repo / "scripts/production_v4_transcript.py").write_bytes(b"# synthetic test import\n")
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.commit_source("Synthetic qualification source")
        self.commit = self.git("rev-parse", "HEAD")
        self.paths = {"model_bank": self.root / "model.bank", "fixed_record": self.root / "fixed.json",
                      "proof": self.root / "proof.bin", "statement": self.root / "statement.json"}
        for role, path in self.paths.items():
            path.write_bytes(b"\0" * 12025320 if role == "proof" else role.encode())
        artifacts = {}
        for role, artifact in (("model_bank", "bank"), ("fixed_record", "fixed_record")):
            row = package.integrity._production_v4_file_identity(self.paths[role], role)
            artifacts[artifact] = {k: v for k, v in row.items() if k != "name"}
        payload = {"rules": {"profile": "CommonFoundry Mainnet", "artifacts": artifacts,
                            "virtual_genesis_timestamp_unix_seconds": package.LAUNCH_TIME,
                            "proof_of_work": {"pow_limit": "00" + "ff" * 31}},
                   "initial_target": "000c" + "ff" * 30, "minimum_transaction_fee_atoms": 10000000,
                   "source_release_unix_seconds": package.SOURCE_TIME, "beacon": package.BEACON_POLICY}
        root = hashlib.sha256(package.PLAN_DOMAIN + json.dumps(payload, separators=(",", ":")).encode()).digest()
        self.plan = self.root / "plan.json"
        plan = {"schema": package.PLAN_SCHEMA, "payload": payload, "launch_plan_digest": root.hex(),
                "network_id": package.integrity._rcnet_v2_derived_hash(package.NETWORK_DOMAIN, root).hex()}
        self.plan.write_bytes((json.dumps(plan, indent=2) + "\n").encode())
        self.result = fixture(plan)["verifier_result"]
        self.result["proof"].update(sha256=hashlib.sha256(self.paths["proof"].read_bytes()).hexdigest(), path="private/operator/path")
        self.output = self.root / "qualification.json"

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, check=True).stdout.decode().strip()

    def commit_source(self, message):
        self.git("add", ".")
        self.git("-c", "user.name=Qualification Test", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-qm", message)

    def prepare(self):
        return qualification.prepare(repo=self.repo, commit=self.commit, plan=self.plan, output=self.output, **self.paths)

    def test_preparation_requires_full_verifier_arguments_and_retains_no_private_path(self):
        with mock.patch.object(package, "native_output", return_value=package.canonical(self.result)) as verifier:
            receipt = self.prepare()
        self.assertTrue(receipt["full_cryptographic_proof_verified"])
        self.assertFalse(receipt["mainnet_activation_authorized"])
        args = verifier.call_args.args[1]
        for flag, path in (("--statement", self.paths["statement"]), ("--proof", self.paths["proof"]),
                           ("--model-bank", self.paths["model_bank"]), ("--fixed-artifact-record", self.paths["fixed_record"])):
            self.assertEqual(args[args.index(flag) + 1], str(path))
        record = qualification.validate(self.output.read_bytes())
        self.assertNotIn("path", record["verifier_result"]["proof"])
        qualification.validate_source(self.repo, self.commit, record)
        with self.assertRaisesRegex(qualification.Error, "already exists"):
            self.prepare()

    def test_changed_verifier_source_requires_fresh_qualification(self):
        with mock.patch.object(package, "native_output", return_value=package.canonical(self.result)):
            self.prepare()
        (self.repo / "scripts/production_v4_transcript.py").write_bytes(b"# changed import\n")
        self.commit_source("Changed synthetic verifier")
        with self.assertRaisesRegex(qualification.Error, "fresh qualification"):
            qualification.validate_source(self.repo, self.git("rev-parse", "HEAD"), json.loads(self.output.read_bytes()))

    def test_windows_line_endings_execute_exact_committed_verifier_blobs(self):
        self.git("config", "core.autocrlf", "true")
        source = self.repo / qualification.VERIFIER
        committed = package.integrity._tracked_blob_at(self.repo, self.commit, qualification.VERIFIER)
        source.write_bytes(committed.replace(b"\n", b"\r\n"))
        self.git("add", "--renormalize", "scripts")
        self.git("diff", "--cached", "--quiet")
        self.assertEqual(self.git("status", "--porcelain"), "")
        def check_export(_executable, args, **_kwargs):
            selected = Path(args[0])
            self.assertNotEqual(selected, source)
            self.assertEqual(selected.read_bytes(), committed)
            return package.canonical(self.result)
        with mock.patch.object(package, "native_output", side_effect=check_export):
            self.prepare()
        qualification.validate_source(self.repo, self.commit, json.loads(self.output.read_bytes()))

    def test_partial_result_and_input_replacement_cannot_publish_qualification(self):
        result = copy.deepcopy(self.result)
        result["full_cryptographic_proof_verified"] = False
        with mock.patch.object(package, "native_output", return_value=package.canonical(result)):
            with self.assertRaisesRegex(qualification.Error, "full_cryptographic"):
                self.prepare()
        self.assertFalse(self.output.exists())
        def replace_input(*_args, **_kwargs):
            self.paths["statement"].write_bytes(b"replaced during verification")
            return package.canonical(self.result)
        with mock.patch.object(package, "native_output", side_effect=replace_input):
            with self.assertRaisesRegex(qualification.Error, "changed during"):
                self.prepare()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
