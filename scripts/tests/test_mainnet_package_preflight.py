"""Adversarial offline preflight of synthetic mainnet package sets."""
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import package_mainnet as package
import verify_mainnet_packages as preflight
import test_mainnet_packages as fixtures


class MainnetPreflightTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.MainnetPackageTests("test_all_four_packages_are_deterministic_and_self_contained")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.archives = {}
        for platform in package.PLATFORMS:
            for kind in ("runtime", "miner"):
                args = self.fixture.args(platform, kind, platform + kind)
                self.archives[platform, kind] = self.fixture.assemble(args)

    def verify(self, archives=None):
        with mock.patch.object(package, "source_snapshot", side_effect=self.fixture.sources), \
             mock.patch.object(package, "validate_review_ancestry"), \
             mock.patch.object(package, "native_output", side_effect=AssertionError("preflight executed an archive member")):
            return preflight.verify_set(self.fixture.repo, self.fixture.commit, "1.0.0", self.fixture.plan_path, self.archives if archives is None else archives)

    def rewrite(self, key, transform, *, refresh_receipt=False, epoch=1789840000):
        archive = self.archives[key]
        content = self.fixture.contents(archive)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as handle:
                modes = {member.filename.split("/", 1)[1]: (member.external_attr >> 16) & 0o777 for member in handle.infolist() if not member.is_dir()}
        else:
            with tarfile.open(archive) as handle:
                modes = {member.name.split("/", 1)[1]: member.mode for member in handle.getmembers() if member.isfile()}
        transform(content)
        if refresh_receipt:
            receipt = json.loads(content[preflight.RECEIPT])
            receipt["files"] = {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in content.items() if name != preflight.RECEIPT}
            content[preflight.RECEIPT] = package.canonical(receipt)
        with tempfile.TemporaryDirectory(dir=self.fixture.root) as temporary:
            root = Path(temporary) / archive.name.removesuffix(".zip").removesuffix(".tar.gz")
            root.mkdir()
            for name, data in content.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(modes.get(name, 0o644))
            archive.unlink()
            writer = package.integrity.create_deterministic_zip if archive.suffix == ".zip" else package.integrity.create_deterministic_tar_gz
            writer(root, archive, epoch)

    def test_consistent_set_is_verified_without_executing_or_approving(self):
        report = self.verify()
        self.assertTrue(report["consistent"])
        self.assertFalse(report["release_approved"])
        self.assertFalse(report["independent_reproduction_verified"])
        self.assertEqual(len(report["packages"]), 4)
        for row in report["packages"]:
            archive = next(path for path in self.archives.values() if path.name == row["name"])
            self.assertEqual(row["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_cli_uses_frozen_git_source_and_writes_report_without_overwrite(self):
        real_repo = self.fixture.repo
        frozen = self.fixture.root / "frozen-fixture-source"
        frozen.mkdir()
        sources = set()
        for platform in package.PLATFORMS:
            for kind in ("runtime", "miner"):
                sources.update(package.package_sources(platform, kind).values())
        for relative in sources:
            target = frozen / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((real_repo / relative).read_bytes().replace(b"\r\n", b"\n"))
        for relative in ("crates/cmfd-node/Cargo.toml", "crates/cmfd-miner/Cargo.toml", "apps/wallet/src-tauri/Cargo.toml"):
            target = frozen / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'[package]\nversion="1.0.0"\n')
        env = dict(os.environ, GIT_AUTHOR_DATE="@1789840000 +0000", GIT_COMMITTER_DATE="@1789840000 +0000")
        def git(*arguments):
            return subprocess.run(["git", "-C", str(frozen), *arguments], env=env, capture_output=True, check=True).stdout.decode().strip()
        git("init", "--quiet")
        git("config", "core.autocrlf", "false")
        git("add", ".")
        git("-c", "user.name=Package Test", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "--quiet", "-m", "Synthetic package test source")
        self.fixture.repo = frozen
        self.fixture.commit = git("rev-parse", "HEAD")
        self.fixture.info["source_commit"] = self.fixture.commit
        self.fixture.approval_subject["review_source_commit"] = self.fixture.commit
        self.fixture.approval_manifest["subject_sha256"] = hashlib.sha256(package.canonical(self.fixture.approval_subject)).hexdigest()
        self.fixture.approval_path.write_bytes(package.canonical(self.fixture.approval_manifest))
        self.fixture.info["mainnet_approval_manifest_sha256"] = hashlib.sha256(self.fixture.approval_path.read_bytes()).hexdigest()
        archives = {}
        for platform in package.PLATFORMS:
            for kind in ("runtime", "miner"):
                archives[platform, kind] = self.fixture.assemble(self.fixture.args(platform, kind, "cli-" + platform + kind))
        output = self.fixture.root / "preflight.json"
        command = [sys.executable, str(real_repo / "scripts/verify_mainnet_packages.py"),
                   "--repo", str(frozen), "--commit", self.fixture.commit, "--version", "1.0.0",
                   "--plan", str(self.fixture.plan_path), "--output", str(output)]
        for (platform, kind), archive in archives.items():
            command.extend(["--" + platform.split("-")[0] + "-" + kind, str(archive)])
        run = subprocess.run(command, capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        original = output.read_bytes()
        report = json.loads(original)
        self.assertTrue(report["consistent"])
        self.assertFalse(report["release_approved"])
        self.assertEqual(report["source_commit"], self.fixture.commit)
        again = subprocess.run(command, capture_output=True, timeout=20)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(output.read_bytes(), original)

    def test_missing_platform_or_role_is_rejected(self):
        partial = dict(self.archives)
        partial.pop(("linux-x86_64", "miner"))
        with self.assertRaisesRegex(package.Error, "four"):
            self.verify(partial)

    def test_source_script_change_is_rejected_even_with_forged_receipt(self):
        self.rewrite(("windows-x86_64", "runtime"), lambda files: files.__setitem__("START-WALLET.bat", b"@echo tampered\r\n"), refresh_receipt=True)
        with self.assertRaisesRegex(package.Error, "frozen source|size limit"):
            self.verify()

    def test_changed_binary_without_receipt_update_is_rejected(self):
        def change(files):
            data = bytearray(files["cmfd-miner.exe"])
            data[-1] ^= 1
            files["cmfd-miner.exe"] = bytes(data)
        self.rewrite(("windows-x86_64", "miner"), change)
        with self.assertRaisesRegex(package.Error, "hashes"):
            self.verify()

    def test_cross_platform_worker_drift_is_rejected_even_with_updated_receipt(self):
        def change(files):
            data = bytearray(files["cmfd-v4-replay"])
            data[-1] ^= 1
            files["cmfd-v4-replay"] = bytes(data)
        self.rewrite(("linux-x86_64", "miner"), change, refresh_receipt=True)
        with self.assertRaisesRegex(package.Error, "different Linux/WSL"):
            self.verify()

    def test_same_platform_launch_helper_drift_is_rejected(self):
        def change(files):
            data = bytearray(files["cmfd-launch.exe"])
            data[-1] ^= 1
            files["cmfd-launch.exe"] = bytes(data)
        self.rewrite(("windows-x86_64", "miner"), change, refresh_receipt=True)
        with self.assertRaisesRegex(package.Error, "different native launch"):
            self.verify()

    def test_distinct_worker_roles_cannot_reuse_one_binary(self):
        self.rewrite(("linux-x86_64", "miner"), lambda files: files.__setitem__("real_bank0_relations", files["cmfd-v4-replay"]), refresh_receipt=True)
        with self.assertRaisesRegex(package.Error, "distinct executable roles"):
            self.verify()

    def test_activation_evidence_drift_is_rejected(self):
        def change(files):
            receipt = json.loads(files[preflight.RECEIPT])
            receipt["native_identities"]["cmfd-miner"]["activation_evidence_sha256"] = "4" * 64
            files[preflight.RECEIPT] = package.canonical(receipt)
        self.rewrite(("linux-x86_64", "miner"), change)
        with self.assertRaisesRegex(package.Error, "disagree on plan"):
            self.verify()

    def test_receipt_cannot_claim_release_approval(self):
        def change(files):
            receipt = json.loads(files[preflight.RECEIPT])
            receipt["release_approved"] = True
            files[preflight.RECEIPT] = package.canonical(receipt)
        self.rewrite(("windows-x86_64", "runtime"), change)
        with self.assertRaisesRegex(package.Error, "receipt does not match"):
            self.verify()

    def test_preloaded_beacon_is_rejected_even_if_receipted(self):
        self.rewrite(("linux-x86_64", "runtime"), lambda files: files.__setitem__("production-mainnet/LAUNCH-BEACON.json", b"{}\n"), refresh_receipt=True)
        with self.assertRaisesRegex(package.Error, "missing, reordered, or unexpected"):
            self.verify()

    def test_replaced_approval_manifest_is_rejected_even_if_receipted(self):
        def change(files):
            manifest = json.loads(files[preflight.APPROVALS])
            manifest["approvals"]["producer"]["signature_sha256"] = "e" * 64
            files[preflight.APPROVALS] = package.canonical(manifest)
        self.rewrite(("linux-x86_64", "miner"), change, refresh_receipt=True)
        with self.assertRaisesRegex(package.Error, "compiled pin"):
            self.verify()

    def test_zip_and_gzip_trailers_are_rejected(self):
        for platform in package.PLATFORMS:
            archive = self.archives[platform, "miner"]
            original = archive.read_bytes()
            archive.write_bytes(original + b"untracked trailing data")
            with self.assertRaises(package.Error):
                self.verify()
            archive.write_bytes(original)

    def test_zip_duplicate_and_symlink_members_are_rejected(self):
        archive = self.archives["windows-x86_64", "runtime"]
        for variant in ("duplicate", "symlink"):
            original = archive.read_bytes()
            with zipfile.ZipFile(archive, "a", compression=zipfile.ZIP_DEFLATED) as handle:
                if variant == "duplicate":
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        handle.writestr(handle.infolist()[0], b"")
                else:
                    row = zipfile.ZipInfo("outside")
                    row.create_system = 3
                    row.external_attr = (stat.S_IFLNK | 0o777) << 16
                    handle.writestr(row, b"../../wallet.key")
            with self.assertRaises(package.Error):
                self.verify()
            archive.write_bytes(original)

    def test_expected_zip_member_cannot_be_a_symlink(self):
        archive = self.archives["windows-x86_64", "runtime"]
        with zipfile.ZipFile(archive) as handle:
            members = [(copy.copy(row), handle.read(row)) for row in handle.infolist()]
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
            for row, data in members:
                if row.filename.endswith("/README.md"):
                    row.external_attr = (stat.S_IFLNK | 0o644) << 16
                handle.writestr(row, data)
        with self.assertRaisesRegex(package.Error, "metadata is not canonical"):
            self.verify()

    def test_oversized_tar_member_is_rejected_before_its_body_is_read(self):
        archive = self.archives["linux-x86_64", "miner"]
        with tarfile.open(archive) as handle:
            offset = next(row.offset for row in handle.getmembers() if row.name.endswith("/cmfd-miner"))
        raw = bytearray(gzip.decompress(archive.read_bytes()))
        raw[offset + 124:offset + 136] = f"{package.integrity.MAX_RUNTIME_BINARY_BYTES + 1:011o}\0".encode()
        raw[offset + 148:offset + 156] = b"        "
        checksum = sum(raw[offset:offset + 512])
        raw[offset + 148:offset + 156] = f"{checksum:06o}\0 ".encode()
        archive.write_bytes(gzip.compress(raw, mtime=1789840000))
        with self.assertRaisesRegex(package.Error, "size limit"):
            self.verify()

    def test_late_archive_change_is_caught_before_reporting(self):
        calls = 0
        def snapshot(*args):
            nonlocal calls
            calls += 1
            if calls == 5:
                archive = self.archives["linux-x86_64", "miner"]
                archive.write_bytes(archive.read_bytes() + b"changed after inspection")
            return self.fixture.sources(*args)
        with mock.patch.object(package, "source_snapshot", side_effect=snapshot), mock.patch.object(package, "validate_review_ancestry"):
            with self.assertRaisesRegex(package.Error, "set changed"):
                preflight.verify_set(self.fixture.repo, self.fixture.commit, "1.0.0", self.fixture.plan_path, self.archives)

    def test_wrong_archive_epoch_is_rejected(self):
        self.rewrite(("linux-x86_64", "runtime"), lambda _: None, epoch=1789840010)
        with self.assertRaisesRegex(package.Error, "epoch|timestamp|gzip header"):
            self.verify()

    def test_json_type_substitution_is_rejected(self):
        value = copy.deepcopy(self.fixture.info)
        value["format_version"] = True
        with self.assertRaises(package.Error):
            package.validate_info(package.canonical(value), self.fixture.plan, self.fixture.commit)

    def test_substituted_beacon_key_cannot_be_accepted_as_a_new_plan(self):
        value = copy.deepcopy(self.fixture.plan)
        value["payload"]["beacon"]["public_key"] = "4" * 192
        root = hashlib.sha256(b"CMFD/MAINNET/LAUNCH-PLAN/V1\0" + json.dumps(value["payload"], separators=(",", ":")).encode()).digest()
        value["launch_plan_digest"] = root.hex()
        value["network_id"] = package.integrity._rcnet_v2_derived_hash("CMFD/MAINNET/NETWORK-ID/V1", root).hex()
        with self.assertRaisesRegex(package.Error, "beacon policy"):
            package.validate_plan((json.dumps(value, indent=2) + "\n").encode())


if __name__ == "__main__":
    unittest.main()
