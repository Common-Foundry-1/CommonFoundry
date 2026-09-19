"""Bounded package fixtures exercise the downloader release gate, not real keys."""
import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release_integrity as integrity
from test_release_integrity import pe_x86_64_fixture, elf_x86_64_fixture


class RuntimeBootstrapIntegrityTests(unittest.TestCase):
    def test_source_input_manifest_matches_every_download_chunk_identity(self):
        shared = Path(__file__).resolve().parents[2] / "packaging/production-v4-pool/shared"
        inputs = json.loads((shared / "production-v4-rcnet-1-inputs.json").read_bytes())
        chunks = json.loads((shared / "V4-INPUT-CHUNKS.json").read_bytes())
        indexed = {item["name"]: item for item in chunks["files"]}
        for item in inputs["files"]:
            if item["name"] == integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD:
                bundled = (shared / item["name"]).read_bytes()
                self.assertEqual(item["bytes"], len(bundled))
                self.assertEqual(item["sha256"], hashlib.sha256(bundled).hexdigest())
                continue
            self.assertIn(item["name"], indexed)
            self.assertEqual(item["bytes"], indexed[item["name"]]["bytes"])
            self.assertEqual(item["sha256"], indexed[item["name"]]["sha256"])

    def test_release_inventory_is_canonical_and_complete(self):
        repo = Path(__file__).resolve().parents[2]
        names, _ = integrity._inventory_names(
            repo / "packaging/releases/v0.1.0-rc.5.inventory"
        )
        self.assertEqual(len(names), 26)
        for platform, extension in (("linux-x86_64", ".tar.gz"), ("windows-x86_64", ".zip")):
            self.assertIn(f"commonfoundry-rc-runtime-bootstrap-{platform}-v0.1.0-rc.5{extension}", names)
            self.assertIn(f"RUNTIME-ATTESTATION-{platform.upper()}.json", names)
        self.assertIn("commonfoundry-miner-v0.1.0-rc.5-linux-x86_64-gnu.tar.gz", names)
        self.assertIn("commonfoundry-miner-v0.1.0-rc.5-windows-x86_64-wsl2.zip", names)
        self.assertIn("cmfd-v4-replay", names)
        self.assertIn("real_bank0_relations", names)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = Path(__file__).resolve().parents[2]
        self.version = "0.1.0-rc.5"
        self.commit = "1" * 40
        self.epoch = 1_700_000_000
        shared = "packaging/production-v4-pool/shared"
        runtime = "packaging/production-rc/runtime"
        common = {
            "README.md": f"{runtime}/README.md", "LICENSE": "LICENSE",
            "THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md",
            "MINING-WORKERS.json": f"{runtime}/MINING-WORKERS.json",
            "production-v4-inputs.py": "scripts/production-v4-inputs.py",
            "V4-INPUT-CHUNKS.json": f"{shared}/V4-INPUT-CHUNKS.json",
            "production-v4-rcnet-1-inputs.json": f"{shared}/production-v4-rcnet-1-inputs.json",
            integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD: f"{shared}/{integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD}",
        }
        inputs = json.loads((self.repo / common["production-v4-rcnet-1-inputs.json"]).read_bytes())
        self.network = {
            "network": {"network_id": inputs["network_id"]},
            "proof_of_work": {"selection": "ProductionV4", "artifacts": {
                role: {"bytes": str(row["bytes"]), "sha256": row["sha256"]}
                for role, row in zip(("bank", "fixed_record"), inputs["files"][:2])
            }},
        }
        network_bytes = (json.dumps(self.network, indent=2) + "\n").encode()
        wallet_bytes = integrity._canonical_json({
            "schema": integrity.WALLET_RUNTIME_IDENTITY_SCHEMA,
            "role": integrity.WALLET_RUNTIME_IDENTITY_ROLE,
            "package_version": self.version,
            "network_info_base64": base64.b64encode(network_bytes).decode(),
        })
        self.files = {}
        self.packages = {}
        self.sources = {}
        workers = []
        for name in ("cmfd-v4-replay", "real_bank0_relations"):
            data = elf_x86_64_fixture(name.encode())
            path = self.root / name
            path.write_bytes(data)
            self.files[name] = path
            workers.append({"name": name, "bytes": len(data), "sha256": integrity._sha256_bytes(data)})
        for platform, suffix, extension, fixture, scripts in (
            ("windows-x86_64", ".exe", ".zip", pe_x86_64_fixture, ("PREPARE-RCNET-RUNTIME.ps1", "START-WALLET.bat", "PREPARE-MINING.bat", "PREPARE-MINING.ps1")),
            ("linux-x86_64", "", ".tar.gz", elf_x86_64_fixture, ("prepare-rcnet-runtime.sh", "start-wallet.sh", "prepare-mining.sh")),
        ):
            name = f"commonfoundry-rc-runtime-bootstrap-{platform}-v{self.version}"
            package = self.root / name
            package.mkdir()
            paths = dict(common)
            paths.update({name: f"{runtime}/{'windows' if suffix else 'linux'}/{name}" for name in scripts})
            if suffix:
                paths["PREPARE-V4-INPUTS.ps1"] = "packaging/production-v4-testnet/windows/PREPARE-V4-INPUTS.ps1"
            for name, relative in paths.items():
                data = (self.repo / relative).read_bytes().replace(b"\r\n", b"\n")
                if name == "MINING-WORKERS.json":
                    manifest = json.loads(data)
                    manifest["workers"] = workers
                    data = integrity._canonical_json(manifest)
                self.sources[relative] = data
                (package / name).write_bytes(data)
            binaries = {}
            for role, name in (("node", f"cmfd-node{suffix}"), ("wallet", f"common-foundry-wallet{suffix}")):
                data = fixture(role.encode())
                (package / name).write_bytes(data)
                self.files[name] = self.root / name
                self.files[name].write_bytes(data)
                binaries[f"{role}_sha256"] = integrity._sha256_bytes(data)
            archive = self.root / (package.name + extension)
            writer = integrity.create_deterministic_zip if suffix else integrity.create_deterministic_tar_gz
            writer(package, archive, self.epoch)
            self.files[archive.name] = archive
            self.packages[platform] = (package, archive, writer)
            attestation = {
                "schema": integrity.PRODUCTION_V4_RUNTIME_ATTESTATION_SCHEMA,
                "platform": platform, "source_commit": self.commit, **binaries,
                "network_info_sha256": integrity._sha256_bytes(network_bytes),
                "network_info_base64": base64.b64encode(network_bytes).decode(),
                "wallet_runtime_identity_sha256": integrity._sha256_bytes(wallet_bytes),
                "wallet_runtime_identity_base64": base64.b64encode(wallet_bytes).decode(),
            }
            path = self.root / f"RUNTIME-ATTESTATION-{platform.upper()}.json"
            path.write_bytes(integrity._canonical_json(attestation))
            self.files[path.name] = path

    def verify(self):
        with mock.patch.object(integrity, "_tracked_blob", side_effect=lambda repo, relative: self.sources[relative]), mock.patch.object(integrity, "_source_date_epoch", return_value=self.epoch):
            return integrity.validate_production_rc_runtime_packages(
                stage_files=self.files, staged_network_info=self.network,
                commit=self.commit, version=self.version, repo=self.repo,
            )

    def test_complete_windows_and_linux_packages_pass(self):
        self.assertEqual(set(self.verify()), {"windows-x86_64", "linux-x86_64"})

    def test_missing_platform_is_rejected(self):
        _, archive, _ = self.packages["linux-x86_64"]
        del self.files[archive.name]
        with self.assertRaisesRegex(integrity.IntegrityError, "incomplete"):
            self.verify()

    def test_missing_mining_worker_is_rejected(self):
        del self.files["real_bank0_relations"]
        with self.assertRaisesRegex(integrity.IntegrityError, "missing mining worker"):
            self.verify()

    def test_changed_mining_worker_is_rejected(self):
        path = self.files["cmfd-v4-replay"]
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with self.assertRaisesRegex(integrity.IntegrityError, "hash mismatch"):
            self.verify()

    def test_changed_bundled_downloader_is_rejected(self):
        package, archive, writer = self.packages["windows-x86_64"]
        (package / "PREPARE-RCNET-RUNTIME.ps1").write_bytes(b"changed downloader")
        archive.unlink()
        writer(package, archive, self.epoch)
        with self.assertRaises(integrity.IntegrityError):
            self.verify()

    def test_missing_bundled_file_is_rejected(self):
        package, archive, writer = self.packages["linux-x86_64"]
        (package / "V4-INPUT-CHUNKS.json").unlink()
        archive.unlink()
        writer(package, archive, self.epoch)
        with self.assertRaises(integrity.IntegrityError):
            self.verify()

    def test_stale_native_attestation_is_rejected(self):
        path = self.files["RUNTIME-ATTESTATION-WINDOWS-X86_64.json"]
        value = json.loads(path.read_bytes())
        value["source_commit"] = "2" * 40
        path.write_bytes(integrity._canonical_json(value))
        with self.assertRaisesRegex(integrity.IntegrityError, "identity"):
            self.verify()

    def test_manifest_bank_mismatch_is_rejected(self):
        self.network["proof_of_work"]["artifacts"]["bank"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(integrity.IntegrityError, "compiled identity"):
            self.verify()

    def test_mixed_full_and_bootstrap_formats_are_rejected(self):
        self.files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME] = self.root / "unused"
        with self.assertRaisesRegex(integrity.IntegrityError, "mix"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
