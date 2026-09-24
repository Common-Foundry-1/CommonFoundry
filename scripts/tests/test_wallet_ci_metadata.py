import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wallet_ci_metadata import metadata


class WalletCiMetadataTests(unittest.TestCase):
    def test_current_source_paths_follow_actual_version(self):
        repo = Path(__file__).resolve().parents[2]
        expected = json.loads((repo / "apps/wallet/package.json").read_bytes())["version"]
        for platform in ("Windows", "Linux"):
            result = metadata(repo, platform)
            self.assertEqual(result["version"], expected)
            if result["rc_packaging"] == "true":
                self.assertIn(expected, result["bundle_path"])
                self.assertIn(expected, result["bootstrap_path"])
            else:
                self.assertEqual(result["network_feature"], "production-mainnet")
                self.assertEqual(result["tauri_config"], "src-tauri/tauri.mainnet.conf.json")
                self.assertEqual(result["bundle_args"], "--no-bundle")
                self.assertEqual(result["bootstrap_path"], "")

    def test_mismatched_versions_and_unsafe_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wallet = root / "apps/wallet"
            (wallet / "src-tauri").mkdir(parents=True)
            (root / "crates/cmfd-node").mkdir(parents=True)
            base = {"version": "0.1.0-rc.9", "productName": "Common Foundry Wallet"}
            (wallet / "src-tauri/tauri.conf.json").write_text(json.dumps(base))
            (wallet / "src-tauri/tauri.rcnet.conf.json").write_text("{}")
            (wallet / "package.json").write_text(json.dumps({"version": base["version"]}))
            (wallet / "package-lock.json").write_text(json.dumps({"version": base["version"], "packages": {"": {"version": base["version"]}}}))
            for path in (wallet / "src-tauri/Cargo.toml", root / "crates/cmfd-node/Cargo.toml"):
                path.write_text('[package]\nversion="0.1.0-rc.9"\n')
            self.assertIn("rc.9", metadata(root, "Linux")["bundle_path"])
            self.assertEqual(metadata(root, "Windows")["network_feature"], "production-rc")
            self.assertEqual(metadata(root, "Linux")["rc_packaging"], "true")
            (wallet / "package.json").write_text('{"version":"0.1.0-rc.8"}')
            with self.assertRaisesRegex(ValueError, "versions disagree"):
                metadata(root, "Linux")
            base["productName"] = 'wrong\nname'
            (wallet / "src-tauri/tauri.conf.json").write_text(json.dumps(base))
            with self.assertRaisesRegex(ValueError, "unsafe"):
                metadata(root, "Windows")

    def test_ci_builds_the_selected_profile_and_does_not_relabel_rc_packages(self):
        source = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text()
        desktop = source.split("  desktop:\n", 1)[1]
        self.assertIn("--features ${{ steps.desktop_metadata.outputs.network_feature }}", desktop)
        self.assertIn("--config ${{ steps.desktop_metadata.outputs.tauri_config }}", desktop)
        self.assertIn("${{ steps.desktop_metadata.outputs.bundle_args }}", desktop)
        self.assertNotIn("--features production-rc", desktop)
        for step in ("Normalize and verify Linux AppImage", "Normalize Linux deb package",
                     "Package complete RCNet runtime bootstrap (Windows)",
                     "Package complete RCNet runtime bootstrap (Linux)"):
            block = desktop.split("- name: " + step, 1)[1].split("\n      - ", 1)[0]
            self.assertIn("steps.desktop_metadata.outputs.rc_packaging == 'true'", block)
