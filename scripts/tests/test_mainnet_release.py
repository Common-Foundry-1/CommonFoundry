"""Release-gate tests with synthetic binaries/data and real disposable signatures."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate_mainnet_pins as pins
import mainnet_plan_approval as approval
import mainnet_release as release
import package_mainnet as package
import prepare_mainnet_dashboard as dashboard
import production_v4_activation_approval as signatures
import test_generate_mainnet_pins as pin_fixtures
import test_mainnet_qualification as qualification_fixtures
import mainnet_qualification as qualification_policy


class MainnetReleaseTests(unittest.TestCase):
    def setUp(self):
        self.fixture = pin_fixtures.MainnetPinGenerationTests("test_candidates_bind_plan_manifest_and_leave_source_unarmed")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.repo = self.fixture.root, self.fixture.repo
        self.plan_fixture = self.fixture.fixture
        self.package_fixture = self.plan_fixture.fixture
        real_repo = self.package_fixture.repo
        paths = set()
        for platform, kind in package.PACKAGE_ROLES:
            paths.update(package.package_sources(platform, kind).values())
        for relative in paths:
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((real_repo / relative).read_bytes().replace(b"\r\n", b"\n"))
        for relative in (*package.integrity.SOURCE_LOCK_FILES, "scripts/release_integrity.py"):
            if relative == "apps/pool-dashboard/package-lock.json":
                continue
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((real_repo / relative).read_bytes().replace(b"\r\n", b"\n"))
        dashboard_package = {"name": "fixture-pool-dashboard", "version": "1.0.4"}
        dashboard_lock = {**dashboard_package, "lockfileVersion": 3,
                          "packages": {"": dashboard_package}}
        for name, blob in {
            "package.json": package.canonical(dashboard_package),
            "package-lock.json": package.canonical(dashboard_lock),
            "index.html": b"<div id='root'></div>\n",
            "vite.config.ts": b"export default {};\n",
        }.items():
            target = self.repo / "apps/pool-dashboard" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
        self.inventory = self.repo / "packaging/releases/mainnet.inventory"
        self.inventory.parent.mkdir(parents=True, exist_ok=True)
        inventory_names = release.BASE_EVIDENCE | set(release.archive_names("1.0.4").values()) | {release.REPRODUCTION, release.REPRODUCTION_SIGNATURE}
        self.inventory.write_bytes(("\n".join(sorted(inventory_names)) + "\n").encode())
        for relative in ("crates/cmfd-node/Cargo.toml", "crates/cmfd-miner/Cargo.toml", "apps/wallet/src-tauri/Cargo.toml"):
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'[package]\nversion="1.0.4"\n')
        self.git("add", ".")
        self.git("-c", "user.name=Release Test", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-qm", "Synthetic reviewed release tree")
        self.review_commit = self.git("rev-parse", "HEAD")
        qualification_fixtures.bind_fixture_source(self.repo, self.review_commit, self.fixture.qualification)
        self.fixture.qualification_path.write_bytes(package.canonical(self.fixture.qualification))
        self.fixture.fields = qualification_policy.proof_pin_fields(self.fixture.qualification, self.plan_fixture.trust)
        self.fixture.proof_bytes = package.integrity._render_production_v4_activation_pin(self.fixture.fields)
        self.fixture.proof_path.write_bytes(self.fixture.proof_bytes)
        self.subject = approval.build_subject(plan_bytes=self.fixture.plan_bytes,
                       qualification_bytes=self.fixture.qualification_path.read_bytes(),
                       review_commit=self.review_commit, trust_bytes=self.plan_fixture.trust_bytes)
        for name in ("producer_signature",):
            self.fixture.material[name].unlink()
        self.material = self.plan_fixture.signed_material(self.subject)
        self.manifest = approval.verify_approval(subject=self.subject, expected_trust=self.plan_fixture.trust, **self.material)
        self.fixture.manifest_path.write_bytes(signatures.canonical_json(self.manifest))
        candidates = pins.render_mainnet_pins(self.fixture.plan, self.fixture.manifest_path.read_bytes(), self.fixture.proof_bytes)
        for path in self.fixture.source_pins:
            path.write_bytes(candidates[path.name])
        self.git("add", ".")
        self.git("-c", "user.name=Release Test", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-qm", "Apply only synthetic mainnet pins")
        self.commit = self.git("rev-parse", "HEAD")
        fixture = self.package_fixture
        fixture.repo = self.repo
        fixture.commit = self.commit
        dashboard_manifest = json.loads(fixture.dashboard_manifest_path.read_bytes())
        dashboard_manifest["source_commit"] = self.commit
        fixture.dashboard_manifest_path.write_bytes(package.canonical(dashboard_manifest))
        frozen_dashboard = dashboard.frozen_sources(self.repo, self.commit)
        dashboard_evidence_path = self.root / release.DASHBOARD_BUILD_EVIDENCE
        dashboard_evidence_path.write_bytes(package.canonical({
            "schema": dashboard.EVIDENCE_SCHEMA, "source_commit": self.commit,
            "source_tree_sha256": hashlib.sha256(package.canonical({
                name: dashboard.identity(blob) for name, blob in frozen_dashboard.items()})).hexdigest(),
            "package_lock": dashboard.identity(frozen_dashboard["package-lock.json"]),
            "toolchain": {"node": {"executable": "/usr/bin/node", "version": "v22.0.0"},
                          "npm": {"executable": "/usr/bin/npm", "version": "11.0.0"}},
            "commands": [{"argv": ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
                          "combined_output_bytes": 2, "combined_output_sha256": hashlib.sha256(b"ci").hexdigest()},
                         {"argv": ["npm", "run", "build"],
                          "combined_output_bytes": 5, "combined_output_sha256": hashlib.sha256(b"built").hexdigest()}],
            "dashboard_manifest": dashboard.identity(fixture.dashboard_manifest_path.read_bytes()),
            "dist_mode": "created_from_isolated_build", "independent_reproduction_claim": False,
            "release_approved": False,
        }))
        cuda_pin_path = self.root / release.CUDA_RUNTIME_PIN
        cuda_pin_path.write_bytes((fixture.cuda_sha256 + "\n").encode())
        fixture.plan = self.fixture.plan
        fixture.plan_path = self.fixture.plan_path
        fixture.approval_path = self.fixture.manifest_path
        fixture.info.update({"source_commit": self.commit, "launch_plan": self.fixture.plan,
                             "mainnet_approval_manifest_sha256": approval.digest(self.fixture.manifest_path.read_bytes()),
                             "proof_approval_trust": self.fixture.fields["approval_trust"]})
        self.first, self.second = self.root / "producer-stage", self.root / "reproducer-stage"
        self.first.mkdir()
        for platform, kind in package.PACKAGE_ROLES:
            archive = fixture.assemble(fixture.args(platform, kind, "release-" + platform + kind))
            shutil.copyfile(archive, self.first / archive.name)
        evidence = {release.PLAN: self.fixture.plan_path, release.MANIFEST: self.fixture.manifest_path,
                    release.QUALIFICATION: self.fixture.qualification_path, release.TRUST: self.fixture.trust_path,
                    release.PROOF_PIN: self.fixture.proof_path,
                    release.DASHBOARD_ASSETS: fixture.dashboard_manifest_path,
                    release.DASHBOARD_BUILD_EVIDENCE: dashboard_evidence_path,
                    release.CUDA_RUNTIME_PIN: cuda_pin_path}
        for role, prefix in ((signatures.PRODUCER_ROLE, "producer"),):
            names = release.ROLE_FILES[role]
            for name, key in zip(names, (prefix + "_approval", prefix + "_signature", prefix + "_allowed_signers")):
                evidence[name] = self.material[key]
        for name, path in evidence.items():
            shutil.copyfile(path, self.first / name)
        shutil.copytree(self.first, self.second)

    def git(self, *arguments):
        env = dict(os.environ, GIT_AUTHOR_DATE="@1789840000 +0000", GIT_COMMITTER_DATE="@1789840000 +0000")
        return subprocess.run(["git", "-C", str(self.repo), *arguments], env=env, check=True, capture_output=True).stdout.decode().strip()

    def common(self):
        return dict(repo=self.repo, commit=self.commit, version="1.0.4", verifier=self.plan_fixture.verifier,
                    expected_verifier_sha256=self.plan_fixture.trust["ssh_keygen_sha256"])

    def prepare(self, output=None):
        return release.prepare_reproduction(**self.common(), producer_stage=self.first, reproducer_stage=self.second,
                                             output=output or self.first / release.REPRODUCTION)

    def sign_reproduction(self):
        subprocess.run([str(self.plan_fixture.verifier), "-Y", "sign", "-f",
                        str(self.plan_fixture.keys[signatures.PRODUCER_ROLE]), "-n",
                        signatures.NAMESPACES[signatures.PRODUCER_ROLE], str(self.first / release.REPRODUCTION)],
                       check=True, capture_output=True)

    def test_real_signatures_and_reproduced_archives_pass_the_mainnet_gate(self):
        result = self.prepare()
        self.assertTrue(result["byte_identical"])
        self.assertTrue(result["owner_attestation_required"])
        self.assertFalse(result["independent_reproduction_claim"])
        self.assertFalse(result["release_approved"])
        self.sign_reproduction()
        files = package.integrity._stage_files(self.first)
        checked = release.validate_release(**self.common(), files=files)
        self.assertEqual(checked["statement"]["source_commit"], self.commit)
        self.assertEqual(checked["statement"]["review_evidence"][release.DASHBOARD_BUILD_EVIDENCE],
                         package.file_identity(self.first / release.DASHBOARD_BUILD_EVIDENCE))
        # The ordinary finalizer/verification entry point must not skip mainnet.
        package.integrity.validate_production_rc_artifacts(version="1.0.4", commit=self.commit,
            stage_files=files, repo=self.repo, activation_ssh_keygen=self.plan_fixture.verifier,
            activation_ssh_keygen_sha256=self.plan_fixture.trust["ssh_keygen_sha256"])

    def test_unsigned_reproduction_is_not_release_authorization(self):
        self.prepare()
        with self.assertRaisesRegex(package.Error, "inventory"):
            release.validate_release(**self.common(), files=package.integrity._stage_files(self.first))

    def test_reviewed_pool_asset_evidence_is_required_and_bound_to_archives(self):
        pin = self.first / release.CUDA_RUNTIME_PIN
        original = pin.read_bytes()
        pin.write_bytes(("b" * 64 + "\n").encode())
        with self.assertRaisesRegex(package.Error, "CUDA runtime"):
            self.prepare()
        pin.write_bytes(original)
        manifest = self.first / release.DASHBOARD_ASSETS
        value = json.loads(manifest.read_bytes())
        value["source_commit"] = "b" * 40
        manifest.write_bytes(package.canonical(value))
        with self.assertRaisesRegex(package.Error, "frozen source commit"):
            self.prepare()

    def test_dashboard_build_evidence_is_required_and_bound_to_frozen_inputs(self):
        path = self.first / release.DASHBOARD_BUILD_EVIDENCE
        original = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(package.Error, "inventory"):
            self.prepare()
        path.write_bytes(original)
        for field, value, message in (
            ("source_commit", "b" * 40, "frozen source commit"),
            ("source_tree_sha256", "b" * 64, "frozen source tree"),
            ("package_lock", {"bytes": 1, "sha256": "b" * 64}, "package-lock.json"),
            ("dashboard_manifest", {"bytes": 1, "sha256": "b" * 64}, "DASHBOARD-ASSETS.json"),
            ("release_approved", True, "cannot claim"),
            ("commands", [], "command sequence"),
            ("unexpected", "field", "unexpected fields"),
        ):
            with self.subTest(field=field):
                record = json.loads(original)
                record[field] = value
                path.write_bytes(package.canonical(record))
                with self.assertRaisesRegex(package.Error, message):
                    self.prepare()
        path.write_bytes(original)
        with self.assertRaisesRegex(package.Error, "not canonical"):
            path.write_bytes(json.dumps(json.loads(original), indent=2).encode())
            self.prepare()
        path.write_bytes(original)

    def test_dashboard_build_record_is_bound_by_reproduction_signature(self):
        self.prepare()
        self.sign_reproduction()
        path = self.first / release.DASHBOARD_BUILD_EVIDENCE
        record = json.loads(path.read_bytes())
        record["toolchain"]["node"]["version"] = "v22.1.0"
        path.write_bytes(package.canonical(record))
        with self.assertRaisesRegex(package.Error, "exact staged release"):
            release.validate_release(**self.common(), files=package.integrity._stage_files(self.first))

    def test_standard_finalizer_cli_runs_the_mainnet_gate_and_generates_checksums(self):
        self.prepare()
        self.sign_reproduction()
        script = Path(__file__).resolve().parents[1] / "release_integrity.py"
        command = [sys.executable, str(script), "finalize", "--repo", str(self.repo), "--expected-commit", self.commit,
                   "--version", "1.0.4", "--stage", str(self.first), "--inventory", str(self.inventory),
                   "--activation-ssh-keygen", str(self.plan_fixture.verifier),
                   "--activation-ssh-keygen-sha256", self.plan_fixture.trust["ssh_keygen_sha256"]]
        result = subprocess.run(command, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue((self.first / package.integrity.CHECKSUM_NAME).is_file())
        self.assertTrue((self.first / package.integrity.SOURCE_SBOM_NAME).is_file())
        self.assertFalse((self.first / package.integrity.CHECKSUM_SIGNATURE_NAME).exists())
        command[2] = "verify"
        result = subprocess.run(command, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_generic_non_rc_version_cannot_bypass_mainnet_checks(self):
        with self.assertRaisesRegex(package.Error, "mainnet finalization"):
            package.integrity.validate_production_rc_artifacts(version="1.0.4", commit=self.commit,
                stage_files=package.integrity._stage_files(self.first), repo=self.repo)

    def test_same_stage_or_same_archive_is_not_independent_reproduction(self):
        with self.assertRaisesRegex(package.Error, "different directories"):
            release.prepare_reproduction(**self.common(), producer_stage=self.first, reproducer_stage=self.first,
                                         output=self.root / "statement.json")
        name = next(iter(release.archive_names("1.0.4").values()))
        (self.second / name).unlink()
        os.link(self.first / name, self.second / name)
        with self.assertRaisesRegex(package.Error, "same archive"):
            self.prepare()

    def test_two_valid_but_different_package_sets_are_rejected(self):
        name = release.archive_names("1.0.4")["windows-x86_64", "miner"]
        archive = self.second / name
        with zipfile.ZipFile(archive) as handle:
            rows = [(row, handle.read(row)) for row in handle.infolist()]
        miner_bytes = next(data for row, data in rows if row.filename.endswith("/cmfd-miner.exe"))
        changed = miner_bytes[:-1] + bytes([miner_bytes[-1] ^ 1])
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
            for row, data in rows:
                if row.filename.endswith("/cmfd-miner.exe"):
                    data = changed
                elif row.filename.endswith("/MAINNET-PACKAGE.json"):
                    receipt = json.loads(data)
                    receipt["files"]["cmfd-miner.exe"] = {"bytes": len(changed), "sha256": hashlib.sha256(changed).hexdigest()}
                    data = package.canonical(receipt)
                handle.writestr(row, data)
        with self.assertRaisesRegex(package.Error, "identities differ"):
            self.prepare()
        self.assertFalse((self.first / release.REPRODUCTION).exists())

    def test_late_archive_change_is_rejected_after_signature_verification(self):
        self.prepare()
        self.sign_reproduction()
        original = release.verify_reproduction_signature
        archive = self.first / next(iter(release.archive_names("1.0.4").values()))
        def verify_then_change(**kwargs):
            original(**kwargs)
            archive.write_bytes(archive.read_bytes() + b"changed after signature check")
        with mock.patch.object(release, "verify_reproduction_signature", side_effect=verify_then_change):
            with self.assertRaisesRegex(package.Error, "changed during signature"):
                release.validate_release(**self.common(), files=package.integrity._stage_files(self.first))

    def test_tampered_statement_and_wrong_namespace_cannot_authorize_release(self):
        self.prepare()
        self.sign_reproduction()
        path = self.first / release.REPRODUCTION
        original = path.read_bytes()
        value = json.loads(original)
        value["packages"][0]["sha256"] = "8" * 64
        path.write_bytes(signatures.canonical_json(value))
        with self.assertRaisesRegex(package.Error, "exact staged release"):
            release.validate_release(**self.common(), files=package.integrity._stage_files(self.first))
        path.write_bytes(original)
        (self.first / release.REPRODUCTION_SIGNATURE).unlink()
        subprocess.run([str(self.plan_fixture.verifier), "-Y", "sign", "-f", str(self.plan_fixture.keys[signatures.PRODUCER_ROLE]),
                        "-n", signatures.NAMESPACES[signatures.REPRODUCER_ROLE], str(path)], check=True, capture_output=True)
        with self.assertRaises(signatures.ApprovalError):
            release.validate_release(**self.common(), files=package.integrity._stage_files(self.first))

    def test_modified_committed_pin_is_rejected_even_with_valid_plan_signatures(self):
        path = self.fixture.source_pins[0]
        path.write_bytes(path.read_bytes().replace(b"0xff", b"0xfe", 1))
        self.git("add", ".")
        self.git("-c", "user.name=Release Test", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-qm", "Tamper synthetic pin")
        self.commit = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(package.Error, "exact reviewed candidates"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
