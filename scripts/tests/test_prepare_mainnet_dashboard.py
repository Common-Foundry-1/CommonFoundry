"""Offline release-boundary tests; no real npm install or release approval."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import package_mainnet as package
import prepare_mainnet_dashboard as dashboard


class PrepareDashboardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cmfd-dashboard-test-", dir=Path(__file__).resolve().parents[3])
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.app = self.repo / "apps" / "pool-dashboard"
        self.app.mkdir(parents=True)
        (self.repo / ".gitignore").write_text("apps/pool-dashboard/dist/\napps/pool-dashboard/node_modules/\n", encoding="utf-8")
        (self.app / "package.json").write_text(json.dumps({"name": "fixture", "version": "1.0.0", "scripts": {"build": "fake"}}), encoding="utf-8")
        (self.app / "package-lock.json").write_text(json.dumps({"name": "fixture", "version": "1.0.0", "lockfileVersion": 3,
                                                                    "packages": {"": {"name": "fixture", "version": "1.0.0"}}}), encoding="utf-8")
        (self.app / "index.html").write_text("<div id='root'></div>\n", encoding="utf-8")
        (self.app / "vite.config.ts").write_text("export default {};\n", encoding="utf-8")
        self.git("init", "--quiet")
        self.git("config", "user.name", "Dashboard Test")
        self.git("config", "user.email", "dashboard-test@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("add", ".gitignore", "apps/pool-dashboard")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "frozen fixture")
        self.commit = self.git("rev-parse", "HEAD")
        self.dist = self.root / "prepared-dist"
        self.manifest = self.root / "DASHBOARD-ASSETS.json"
        self.evidence = self.root / "DASHBOARD-BUILD-EVIDENCE.json"
        self.asset = b"console.log('frozen dashboard');\n"

    def git(self, *arguments):
        result = subprocess.run(["git", "-C", str(self.repo), *arguments], capture_output=True)
        if result.returncode:
            self.fail(result.stderr.decode("utf-8", "replace"))
        return result.stdout.decode().strip()

    def fake_command(self, arguments, cwd, timeout):
        if arguments[1:] == ["--version"]:
            return b"v22.0.0\n" if "node" in arguments[0] else b"11.0.0\n"
        if arguments[1:] == ["ci", "--ignore-scripts", "--no-audit", "--no-fund"]:
            return b"installed from lock\n"
        self.assertEqual(arguments[1:], ["run", "build"])
        destination = cwd / "dist"
        (destination / "assets").mkdir(parents=True)
        (destination / "index.html").write_bytes(b'<script src="/assets/app-a1.js"></script>\n')
        (destination / "assets" / "app-a1.js").write_bytes(self.asset)
        return b"built from tracked fixture\n"

    def prepare(self, **overrides):
        params = {"repo": self.repo, "commit": self.commit, "dist": self.dist,
                  "manifest_path": self.manifest, "evidence_path": self.evidence}
        params.update(overrides)
        with mock.patch.object(dashboard.shutil, "which", side_effect=lambda name: str(self.root / ("node.exe" if name == "node" else "npm.cmd"))), \
             mock.patch.object(dashboard, "run_tool", side_effect=self.fake_command):
            return dashboard.prepare(**params)

    def test_create_new_manifest_and_evidence_from_frozen_sources(self):
        # Ignored prior build output in checkout must never be copied as input.
        old = self.app / "dist" / "assets" / "old.js"
        old.parent.mkdir(parents=True)
        old.write_bytes(b"stale")
        outcome = self.prepare()
        manifest_bytes = self.manifest.read_bytes()
        manifest = package.validate_dashboard_manifest(manifest_bytes, self.commit)
        self.assertEqual(manifest_bytes, package.canonical(manifest))
        self.assertEqual(set(manifest["files"]), {"index.html", "assets/app-a1.js"})
        self.assertEqual(package.dashboard_assets(self.dist, manifest)["assets/app-a1.js"], self.asset)
        evidence = json.loads(self.evidence.read_bytes())
        self.assertEqual(evidence["schema"], dashboard.EVIDENCE_SCHEMA)
        self.assertEqual(evidence["package_lock"], dashboard.identity((self.app / "package-lock.json").read_bytes()))
        self.assertEqual(evidence["dashboard_manifest"], dashboard.identity(manifest_bytes))
        self.assertEqual(evidence["dist_mode"], "created_from_isolated_build")
        self.assertFalse(evidence["independent_reproduction_claim"])
        self.assertFalse(outcome["release_approved"])
        with self.assertRaisesRegex(dashboard.Error, "already exists"):
            self.prepare()

    def test_existing_dist_is_compared_against_fresh_build(self):
        self.prepare()
        first = self.manifest.read_bytes()
        second_manifest = self.root / "second-manifest.json"
        second_evidence = self.root / "second-evidence.json"
        self.prepare(manifest_path=second_manifest, evidence_path=second_evidence, verify_dist=True)
        self.assertEqual(first, second_manifest.read_bytes())
        self.assertEqual(json.loads(second_evidence.read_bytes())["dist_mode"], "compared_existing")
        (self.dist / "assets" / "app-a1.js").write_bytes(b"changed")
        third_manifest = self.root / "third-manifest.json"
        third_evidence = self.root / "third-evidence.json"
        with self.assertRaisesRegex(dashboard.Error, "differs from its reviewed manifest"):
            self.prepare(manifest_path=third_manifest, evidence_path=third_evidence, verify_dist=True)
        self.assertFalse(third_manifest.exists())
        self.assertFalse(third_evidence.exists())

    def test_dirty_or_wrong_commit_cannot_prepare(self):
        with self.assertRaisesRegex(dashboard.Error, "exact checked-out"):
            self.prepare(commit="a" * 40)
        (self.app / "index.html").write_bytes(b"modified")
        with self.assertRaisesRegex(dashboard.Error, "clean frozen"):
            self.prepare()
        self.assertFalse(self.manifest.exists())

    def test_manifest_cannot_be_written_inside_dist(self):
        with self.assertRaisesRegex(dashboard.Error, "outside the dist tree"):
            self.prepare(manifest_path=self.dist / "DASHBOARD-ASSETS.json")
        self.assertFalse(self.dist.exists())

    def test_outputs_cannot_dirty_the_frozen_repository(self):
        with self.assertRaisesRegex(dashboard.Error, "outside the frozen source repository"):
            self.prepare(dist=self.repo / "build-output")
        with self.assertRaisesRegex(dashboard.Error, "outside the frozen source repository"):
            self.prepare(manifest_path=self.repo / "DASHBOARD-ASSETS.json")
        with self.assertRaisesRegex(dashboard.Error, "outside the frozen source repository"):
            self.prepare(evidence_path=self.repo / "DASHBOARD-BUILD-EVIDENCE.json")
        self.assertFalse((self.repo / "build-output").exists())

    def test_unexpected_built_asset_is_rejected_before_output(self):
        original = self.fake_command
        def extra(arguments, cwd, timeout):
            result = original(arguments, cwd, timeout)
            if arguments[1:] == ["run", "build"]:
                (cwd / "dist" / "unexpected.txt").write_bytes(b"extra")
            return result
        self.fake_command = extra
        with self.assertRaisesRegex(dashboard.Error, "unexpected entry"):
            self.prepare()
        self.assertFalse(self.dist.exists())
        self.assertFalse(self.manifest.exists())

    def test_frozen_source_symlink_mode_is_rejected(self):
        row = b"120000 blob " + b"a" * 40 + b"\tapps/pool-dashboard/evil\x00"
        with mock.patch.object(dashboard.package.integrity, "_run_git_bytes", return_value=row):
            with self.assertRaisesRegex(dashboard.Error, "symlink or special"):
                dashboard.frozen_sources(self.repo, self.commit)

    def test_build_must_not_mutate_lockfile(self):
        original = self.fake_command
        def mutate(arguments, cwd, timeout):
            result = original(arguments, cwd, timeout)
            if arguments[1:] == ["run", "build"]:
                (cwd / "package-lock.json").write_bytes(b"modified")
            return result
        self.fake_command = mutate
        with self.assertRaisesRegex(dashboard.Error, "changed frozen source"):
            self.prepare()
        self.assertFalse(self.manifest.exists())

    def test_frozen_package_and_lockfile_must_agree(self):
        lock = self.app / "package-lock.json"
        changed = json.loads(lock.read_bytes())
        changed["packages"][""]["version"] = "0.9.0"
        lock.write_text(json.dumps(changed), encoding="utf-8")
        self.git("add", "apps/pool-dashboard/package-lock.json")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "stale lock fixture")
        self.commit = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(dashboard.Error, "lockfile identities disagree"):
            self.prepare()
        self.assertFalse(self.manifest.exists())

    def test_tool_runner_caps_output_and_time(self):
        self.assertEqual(dashboard.run_tool([sys.executable, "-c", "print('ok')"], self.root, 5).strip(), b"ok")
        with self.assertRaisesRegex(dashboard.Error, "output exceeded 1 MiB"):
            dashboard.run_tool([sys.executable, "-c", f"import sys; sys.stdout.write('x' * {dashboard.MAX_TOOL_OUTPUT + 1})"], self.root, 5)
        with self.assertRaisesRegex(dashboard.Error, "timed out"):
            dashboard.run_tool([sys.executable, "-c", "import time; time.sleep(5)"], self.root, 0.1)


if __name__ == "__main__":
    unittest.main()
