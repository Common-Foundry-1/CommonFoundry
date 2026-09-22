"""Candidate generation from synthetic qualification data and disposable signatures."""
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate_mainnet_pins as pins
import mainnet_plan_approval as approval
import production_v4_activation_approval as signatures
import test_mainnet_plan_approval as approval_fixtures


class MainnetPinGenerationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = approval_fixtures.MainnetPlanApprovalTests("test_two_real_signatures_produce_plan_bound_manifest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.repo = self.root / "pin-review-source"
        self.repo.mkdir()
        self.trust_path = self.repo / "packaging/mainnet/APPROVAL-TRUST.json"
        self.trust_path.parent.mkdir(parents=True, exist_ok=True)
        self.trust_path.write_bytes(self.fixture.trust_bytes)
        self.source_pins = []
        for relative in ("crates/cmfd-node/mainnet_release_pin.inc.rs", "crates/cmfd-consensus/mainnet_network_id.inc.rs"):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"None\n")
            self.source_pins.append(path)
        def git(*args):
            return subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, check=True).stdout.decode().strip()
        self.git = git
        git("init", "--quiet")
        git("config", "core.autocrlf", "false")
        git("add", ".")
        git("-c", "user.name=Pin Test", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-qm", "Synthetic pin-review source")
        self.commit = git("rev-parse", "HEAD")
        self.qualification = copy.deepcopy(self.fixture.qualification)
        for field in ("activation_source_commit", "artifact_generation_source_commit", "qualification_source_commit"):
            self.qualification[field] = self.commit
        files = self.qualification["files"]
        self.fields = {
            "schema": "CMFD_PRODUCTION_V4_ACTIVATION_V1", "qualification_source_commit": self.commit,
            "qualification_manifest_sha256": files["independent_reproduction_report"]["sha256"],
            "fresh_process_verifier_binary_sha256": files["fresh_process_verifier_script"]["sha256"],
            "fresh_process_verifier_report_sha256": files["fresh_process_verifier_report"]["sha256"],
            "core_spec_sha256": pins.integrity.PRODUCTION_V4_CORE_SPEC_SHA256,
            "core_vector_sha256": pins.integrity.PRODUCTION_V4_CORE_VECTOR_SHA256,
            "proof_algebra_sha256": pins.integrity.PRODUCTION_V4_PROOF_ALGEBRA_SHA256,
            "approval_trust": {**self.fixture.trust, "contract_schema": signatures.SUBJECT_SCHEMA,
                               "qualification_binding_sha256": signatures.qualification_binding_sha256(files)},
        }
        self.proof_bytes = pins.integrity._render_production_v4_activation_pin(self.fields)
        self.qualification["source_pin_sha256"] = approval.digest(self.proof_bytes)
        self.qualification_path = self.root / "qualification-subject.json"
        self.qualification_path.write_bytes(signatures.canonical_json(self.qualification))
        self.plan = copy.deepcopy(self.fixture.plan)
        self.plan["payload"]["rules"].update({
            "proof_of_work": {"pow_limit": "00" + "ff" * 31},
            "reward_destinations": {
                "steward_xonly_public_key": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "community_xonly_public_key": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            },
        })
        self.plan_bytes = self.fixture.encode_plan(self.plan)
        self.plan_path = self.root / "plan.json"
        self.plan_path.write_bytes(self.plan_bytes)
        self.subject = approval.build_subject(plan_bytes=self.plan_bytes, qualification_bytes=self.qualification_path.read_bytes(),
                                              review_commit=self.commit, trust_bytes=self.fixture.trust_bytes)
        self.material = self.fixture.signed_material(self.subject)
        self.manifest = approval.verify_pair(subject=self.subject, expected_trust=self.fixture.trust, **self.material)
        self.manifest_path = self.root / "manifest.json"
        self.manifest_path.write_bytes(signatures.canonical_json(self.manifest))
        self.proof_path = self.root / "proof-pin.review"
        self.proof_path.write_bytes(self.proof_bytes)

    def generate(self, output=None):
        return pins.generate(repo=self.repo, review_commit=self.commit, plan=self.plan_path,
                             qualification=self.qualification_path, trust=self.trust_path, proof_pin=self.proof_path,
                             approval_manifest=self.manifest_path, output=output or self.root / "candidates", material=self.material)

    def test_candidates_bind_plan_manifest_and_leave_source_unarmed(self):
        report = self.generate()
        self.assertFalse(report["source_pins_applied"])
        self.assertFalse(report["mainnet_activation_authorized"])
        self.assertEqual(self.git("status", "--porcelain"), "")
        for source in self.source_pins:
            self.assertEqual(source.read_bytes(), b"None\n")
        for name, row in report["files"].items():
            data = (self.root / "candidates" / name).read_bytes()
            self.assertEqual(row, {"bytes": len(data), "sha256": approval.digest(data)})
        rendered = (self.root / "candidates" / "mainnet_release_pin.inc.rs").read_text()
        self.assertIn("initial_target: " + pins.byte_array(self.plan["payload"]["initial_target"]), rendered)
        with self.assertRaises(FileExistsError):
            self.generate()

    def test_parser_rejects_arbitrary_rust_and_noncanonical_targets(self):
        self.assertEqual(pins.parse_reviewed_proof_pin(self.proof_bytes), self.fields)
        for data in (b"None\n", self.proof_bytes.replace(b"\n", b"\r\n"), self.proof_bytes + b"const EVIL: u8 = 1;\n",
                     self.proof_bytes.replace(b'"CMFD_PRODUCTION_V4_ACTIVATION_V1"', b'include!("elsewhere.rs")')):
            with self.subTest(data=data[:40]), self.assertRaises((pins.Error, signatures.ApprovalError)):
                pins.parse_reviewed_proof_pin(data)

    def test_pin_renderer_rejects_zero_or_too_easy_initial_target(self):
        for value in ("00" * 32, "ff" * 32):
            changed = copy.deepcopy(self.plan)
            changed["payload"]["initial_target"] = value
            with self.subTest(value=value), self.assertRaises(pins.Error):
                pins.render_mainnet_pins(changed, self.manifest_path.read_bytes(), self.proof_bytes)

    def test_changed_signed_target_or_qualification_binding_is_rejected(self):
        changed = copy.deepcopy(self.fields)
        changed["fresh_process_verifier_report_sha256"] = "8" * 64
        self.proof_path.write_bytes(pins.integrity._render_production_v4_activation_pin(changed))
        with self.assertRaisesRegex(pins.Error, "signed qualification target"):
            self.generate()
        self.assertFalse((self.root / "candidates").exists())
        with self.assertRaisesRegex(pins.Error, "qualified reports"):
            pins.validate_proof_binding(changed, self.proof_bytes, self.qualification, self.fixture.trust)

    def test_tampered_or_unsigned_manifest_is_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed["approvals"]["producer"]["signature_sha256"] = "8" * 64
        self.manifest_path.write_bytes(signatures.canonical_json(changed))
        with self.assertRaisesRegex(pins.Error, "freshly verified"):
            self.generate()
        self.manifest_path.write_bytes(signatures.canonical_json(self.manifest))
        self.material["producer_signature"].write_bytes(b"not a signature")
        with self.assertRaises(signatures.ApprovalError):
            self.generate()
        self.assertFalse((self.root / "candidates").exists())

    def test_source_directory_is_never_a_candidate_destination(self):
        with self.assertRaisesRegex(pins.Error, "outside the source"):
            self.generate(self.repo / "new-pins")
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_cli_creates_candidates_without_applying_them(self):
        script = self.fixture.fixture.repo / "scripts/generate_mainnet_pins.py"
        arguments = [sys.executable, str(script), "--repo", str(self.repo), "--review-commit", self.commit,
                     "--plan", str(self.plan_path), "--qualification-subject", str(self.qualification_path),
                     "--trust", str(self.trust_path), "--proof-pin", str(self.proof_path),
                     "--approval-manifest", str(self.manifest_path), "--output", str(self.root / "cli-candidates")]
        mapping = {"producer_allowed_signers": "producer-policy", "producer_signer_identity": "producer-identity",
                   "reproducer_allowed_signers": "reproducer-policy", "reproducer_signer_identity": "reproducer-identity",
                   "expected_verifier_sha256": "ssh-keygen-sha256"}
        for name, value in self.material.items():
            arguments.extend(["--" + mapping.get(name, name.replace("_", "-")), str(value)])
        result = subprocess.run(arguments, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["source_pins_applied"])
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_publication_failure_removes_only_its_own_outputs(self):
        original = pins.integrity._write_new
        calls = 0
        def fail_second(path, data):
            nonlocal calls
            calls += 1
            if calls == 2:
                (path.parent / "operator-note.txt").write_text("keep me")
                raise OSError("simulated publication failure")
            return original(path, data)
        with mock.patch.object(pins.integrity, "_write_new", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "simulated"):
                self.generate()
        self.assertEqual([path.name for path in (self.root / "candidates").iterdir()], ["operator-note.txt"])

    @unittest.skipUnless(shutil.which("rustc"), "Rust compiler unavailable")
    def test_generated_literals_compile_against_actual_release_struct_definitions(self):
        self.generate()
        source = (self.fixture.fixture.repo / "crates/cmfd-node/release_gate.rs").read_text()
        definitions = []
        for name in ("ProductionV4ActivationEvidence", "ProductionV4ActivationSignerTrust", "ProductionV4ActivationApprovalTrust", "MainnetReleaseConfiguration"):
            match = re.search(r"pub struct " + name + r" \{[^}]+\}", source)
            self.assertIsNotNone(match, name)
            definitions.append(match.group())
        directory = self.root / "candidates"
        program = self.root / "pin-syntax.rs"
        program.write_text('#![allow(dead_code)]\n' + '\n'.join(definitions) + '\n' +
                           'const CONFIG: Option<MainnetReleaseConfiguration> = include!(' + json.dumps((directory / "mainnet_release_pin.inc.rs").as_posix()) + ');\n' +
                           'const NETWORK: Option<[u8;32]> = include!(' + json.dumps((directory / "mainnet_network_id.inc.rs").as_posix()) + ');\n' +
                           'fn main() { assert_eq!(CONFIG.unwrap().network_id, NETWORK.unwrap()); }\n')
        binary = self.root / ("pin-syntax.exe" if sys.platform == "win32" else "pin-syntax")
        compiled = subprocess.run(["rustc", "--edition=2024", "--crate-name", "pin_syntax", str(program), "-o", str(binary)], capture_output=True, timeout=30)
        self.assertEqual(compiled.returncode, 0, compiled.stderr.decode())
        subprocess.run([str(binary)], check=True, capture_output=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
