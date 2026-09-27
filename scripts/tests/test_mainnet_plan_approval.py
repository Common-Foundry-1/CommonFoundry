"""Real temporary SSH signatures over synthetic review inputs, never real approvals."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mainnet_plan_approval as mainnet
import package_mainnet as package
import production_v4_activation_approval as signatures
import test_mainnet_packages as package_fixtures
import mainnet_qualification as qualification_policy
import test_mainnet_qualification as proof_fixtures


class MainnetPlanApprovalTests(unittest.TestCase):
    def setUp(self):
        self.fixture = package_fixtures.MainnetPackageTests("test_all_five_packages_are_deterministic_and_self_contained")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        executable = shutil.which("ssh-keygen")
        if not executable:
            self.skipTest("OpenSSH ssh-keygen unavailable")
        self.verifier = Path(executable)
        self.keys = {}
        self.policies = {}
        for role in mainnet.ROLES:
            key = self.root / (role + "-temporary-test-key")
            subprocess.run([executable, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], capture_output=True, check=True)
            public = key.with_suffix(".pub").read_text().split()
            policy = self.root / (role + ".allowed_signers")
            policy.write_bytes(f'{role}@example.invalid namespaces="{signatures.NAMESPACES[role]}" {public[0]} {public[1]}\n'.encode())
            self.keys[role], self.policies[role] = key, policy
        self.policy_args = dict(producer_allowed_signers=self.policies[signatures.PRODUCER_ROLE],
                                producer_signer_identity="producer@example.invalid")
        authority = signatures.parse_allowed_signers_authority(self.policies["producer"].read_bytes(),
            signer_identity="producer@example.invalid", role="producer")
        self.trust = {"producer": {"signer_identity": "producer@example.invalid", **authority},
                      "ssh_keygen_sha256": hashlib.sha256(self.verifier.read_bytes()).hexdigest()}
        self.plan = copy.deepcopy(self.fixture.plan)
        for role, artifact, letter in (("model_bank", "bank", "a"), ("fixed_artifact_record", "fixed_record", "b")):
            self.plan["payload"]["rules"]["artifacts"][artifact]["blake3"] = letter * 64
        self.qualification = proof_fixtures.fixture(self.plan)
        self.plan_bytes = self.encode_plan(self.plan)
        self.qualification_bytes = signatures.canonical_json(self.qualification)
        self.trust_bytes = signatures.canonical_json(self.trust)
        self.subject = mainnet.build_subject(plan_bytes=self.plan_bytes, qualification_bytes=self.qualification_bytes,
                                            review_commit="a" * 40, trust_bytes=self.trust_bytes)

    def encode_plan(self, plan):
        root = hashlib.sha256(package.PLAN_DOMAIN + json.dumps(plan["payload"], separators=(",", ":")).encode()).digest()
        plan["launch_plan_digest"] = root.hex()
        plan["network_id"] = package.integrity._rcnet_v2_derived_hash(package.NETWORK_DOMAIN, root).hex()
        return (json.dumps(plan, indent=2) + "\n").encode()

    def signed_material(self, subject=None):
        subject = self.subject if subject is None else subject
        prepared = mainnet.prepare_payloads(subject=subject, expected_trust=self.trust, **self.policy_args)
        material = {**self.policy_args, "ssh_keygen": self.verifier, "expected_verifier_sha256": self.trust["ssh_keygen_sha256"]}
        for role, prefix in ((signatures.PRODUCER_ROLE, "producer"),):
            path = self.root / (prefix + ".approval.json")
            path.write_bytes(prepared["payloads"][role])
            subprocess.run([str(self.verifier), "-Y", "sign", "-f", str(self.keys[role]), "-n", signatures.NAMESPACES[role], str(path)], capture_output=True, check=True)
            material[prefix + "_approval"] = path
            material[prefix + "_signature"] = Path(str(path) + ".sig")
        return material

    def test_one_real_signature_produces_plan_bound_manifest(self):
        manifest = mainnet.verify_approval(subject=self.subject, expected_trust=self.trust, **self.signed_material())
        encoded = signatures.canonical_json(manifest)
        self.assertEqual(mainnet.validate_manifest(encoded, self.plan_bytes), manifest)
        runtime = {"mainnet_approval_manifest_sha256": mainnet.digest(encoded),
                   "proof_approval_trust": {**self.trust, "contract_schema": qualification_policy.TRUST_SCHEMA,
                       "independent_reproducer": None, "qualification_binding_sha256": self.subject["qualification_binding_sha256"]}}
        mainnet.bind_manifest_to_runtime(manifest, encoded, runtime)
        runtime["mainnet_approval_manifest_sha256"] = "9" * 64
        with self.assertRaisesRegex(signatures.ApprovalError, "compiled pin"):
            mainnet.bind_manifest_to_runtime(manifest, encoded, runtime)

    def test_modified_plan_with_rewritten_payload_cannot_reuse_old_signatures(self):
        material = self.signed_material()
        changed = copy.deepcopy(self.plan)
        changed["payload"]["minimum_transaction_fee_atoms"] += 1
        subject = mainnet.build_subject(plan_bytes=self.encode_plan(changed), qualification_bytes=self.qualification_bytes,
                                        review_commit="a" * 40, trust_bytes=self.trust_bytes)
        rewritten = mainnet.prepare_payloads(subject=subject, expected_trust=self.trust, **self.policy_args)
        material["producer_approval"].write_bytes(rewritten["payloads"][signatures.PRODUCER_ROLE])
        with self.assertRaisesRegex(signatures.ApprovalError, "signature is invalid"):
            mainnet.verify_approval(subject=subject, expected_trust=self.trust, **material)

    def test_wrong_namespace_signature_is_rejected(self):
        material = self.signed_material()
        material["producer_signature"].unlink()
        subprocess.run([str(self.verifier), "-Y", "sign", "-f", str(self.keys["producer"]),
            "-n", signatures.NAMESPACES["independent_reproducer"], str(material["producer_approval"])], capture_output=True, check=True)
        with self.assertRaisesRegex(signatures.ApprovalError, "signature is invalid"):
            mainnet.verify_approval(subject=self.subject, expected_trust=self.trust, **material)

    def test_another_key_and_an_rc_payload_cannot_replace_owner_approval(self):
        material = self.signed_material()
        wrong_key = self.root / "unauthorized-test-key"
        subprocess.run([str(self.verifier), "-q", "-t", "ed25519", "-N", "", "-f", str(wrong_key)], capture_output=True, check=True)
        material["producer_signature"].unlink()
        subprocess.run([str(self.verifier), "-Y", "sign", "-f", str(wrong_key),
            "-n", signatures.NAMESPACES["producer"], str(material["producer_approval"])], capture_output=True, check=True)
        with self.assertRaisesRegex(signatures.ApprovalError, "signature is invalid"):
            mainnet.verify_approval(subject=self.subject, expected_trust=self.trust, **material)
        material["producer_signature"].unlink()
        original = material["producer_approval"].read_bytes()
        material["producer_approval"].write_bytes(original.replace(mainnet.ROLE_SCHEMA.encode(), b"CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_ROLE_APPROVAL_V1"))
        subprocess.run([str(self.verifier), "-Y", "sign", "-f", str(self.keys["producer"]),
            "-n", signatures.NAMESPACES["producer"], str(material["producer_approval"])], capture_output=True, check=True)
        material["producer_approval"].write_bytes(original)
        with self.assertRaisesRegex(signatures.ApprovalError, "signature is invalid"):
            mainnet.verify_approval(subject=self.subject, expected_trust=self.trust, **material)

    def test_second_approval_is_rejected_not_silently_ignored(self):
        manifest = mainnet.verify_approval(subject=self.subject, expected_trust=self.trust, **self.signed_material())
        manifest["approvals"]["independent_reproducer"] = copy.deepcopy(manifest["approvals"]["producer"])
        with self.assertRaises(signatures.ApprovalError):
            mainnet.validate_manifest(signatures.canonical_json(manifest), self.plan_bytes)

    def test_rc_entry_point_stays_rc_only(self):
        with self.assertRaises(signatures.ApprovalError):
            signatures.validate_subject(self.subject)

    def test_unknown_or_same_signer_and_verifier_substitution_are_rejected(self):
        wrong = copy.deepcopy(self.trust)
        wrong["producer"]["signer_identity"] = "someone-else@example.invalid"
        with self.assertRaises(signatures.ApprovalError):
            mainnet.prepare_payloads(subject=self.subject, expected_trust=wrong, **self.policy_args)
        same = {**self.trust, "independent_reproducer": self.trust["producer"]}
        with self.assertRaises(signatures.ApprovalError):
            mainnet.prepare_payloads(subject=self.subject, expected_trust=same, **self.policy_args)
        material = self.signed_material()
        material["expected_verifier_sha256"] = "f" * 64
        with self.assertRaisesRegex(signatures.ApprovalError, "precommitted trust"):
            mainnet.verify_approval(subject=self.subject, expected_trust=self.trust, **material)

    def test_qualification_artifact_or_subject_mutation_is_rejected(self):
        changed = copy.deepcopy(self.qualification)
        changed["files"]["model_bank"]["sha256"] = "8" * 64
        with self.assertRaisesRegex(signatures.ApprovalError, "artifacts disagree"):
            mainnet.build_subject(plan_bytes=self.plan_bytes, qualification_bytes=signatures.canonical_json(changed),
                                  review_commit="a" * 40, trust_bytes=self.trust_bytes)
        for field in ("extra", "mining_start_unix_seconds"):
            changed = dict(self.subject, **{field: 1})
            with self.assertRaises(signatures.ApprovalError):
                mainnet.validate_subject(changed)

    def test_reviewed_history_allows_only_pin_files(self):
        with mock.patch.object(package.integrity, "_run_git", side_effect=["", "crates/cmfd-node/mainnet_release_pin.inc.rs\ncrates/cmfd-consensus/mainnet_network_id.inc.rs"]):
            package.validate_review_ancestry(self.fixture.repo, "a" * 40, "b" * 40)
        with mock.patch.object(package.integrity, "_run_git", side_effect=["", "crates/cmfd-consensus/src/pow.rs"]):
            with self.assertRaisesRegex(package.Error, "fresh review"):
                package.validate_review_ancestry(self.fixture.repo, "a" * 40, "b" * 40)

    def test_cli_requires_committed_trust_and_verifies_without_real_keys(self):
        repo = self.root / "review-source"
        repo.mkdir()
        trust_path = repo / "approval-trust.json"
        trust_path.write_bytes(self.trust_bytes)
        verifier_source = repo / qualification_policy.VERIFIER
        verifier_source.parent.mkdir()
        verifier_source.write_bytes(b"# synthetic qualification source; not a real verifier\n")
        def git(*args):
            return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True).stdout.decode().strip()
        git("init", "--quiet")
        git("config", "core.autocrlf", "false")
        git("add", ".")
        git("-c", "user.name=Approval Test", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-qm", "Temporary public trust fixture")
        commit = git("rev-parse", "HEAD")
        proof_fixtures.bind_fixture_source(repo, commit, self.qualification)
        qualification_path = self.root / "qualification.json"
        qualification_path.write_bytes(signatures.canonical_json(self.qualification))
        plan_path = self.root / "plan.json"
        plan_path.write_bytes(self.plan_bytes)
        pending = self.root / "pending-requests"
        script = self.fixture.repo / "scripts/mainnet_plan_approval.py"
        common = ["--repo", str(repo), "--review-commit", commit, "--plan", str(plan_path),
                  "--qualification-subject", str(qualification_path), "--trust", str(trust_path),
                  "--producer-policy", str(self.policy_args["producer_allowed_signers"]),
                  "--producer-identity", self.policy_args["producer_signer_identity"]]
        result = subprocess.run([sys.executable, str(script), "prepare", *common, "--output", str(pending)], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        verify = [sys.executable, str(script), "verify", *common, "--output", str(self.root / "manifest.json"),
                  "--ssh-keygen", str(self.verifier), "--ssh-keygen-sha256", self.trust["ssh_keygen_sha256"]]
        for role, prefix in ((signatures.PRODUCER_ROLE, "producer"),):
            payload = pending / f"{role}.approval.json"
            subprocess.run([str(self.verifier), "-Y", "sign", "-f", str(self.keys[role]), "-n", signatures.NAMESPACES[role], str(payload)], capture_output=True, check=True)
            verify.extend([f"--{prefix}-approval", str(payload), f"--{prefix}-signature", str(payload) + ".sig"])
        result = subprocess.run(verify, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["signatures_verified"])
        self.assertFalse(json.loads(result.stdout)["mainnet_activation_authorized"])
        original = (self.root / "manifest.json").read_bytes()
        again = subprocess.run(verify, capture_output=True, timeout=20)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual((self.root / "manifest.json").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
