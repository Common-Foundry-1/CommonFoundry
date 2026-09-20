"""Mainnet package fixtures: real archive/metadata checks, simulated runtime IPC.

Fixtures are not release binaries, activation evidence, or approval records.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import package_mainnet as packages
import mainnet_plan_approval as mainnet_approval
import production_v4_activation_approval as signature_contract
from test_release_integrity import pe_x86_64_fixture, elf_x86_64_fixture


class MainnetPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cmfd-mainnet-package-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = Path(__file__).resolve().parents[2]
        self.commit = "a" * 40
        catalog = json.loads((self.repo / packages.SHARED / "production-v4-rcnet-1-inputs.json").read_bytes())
        assets = {row["name"]: row for row in catalog["files"]}
        self.plan = {
            "schema": "CMFD_MAINNET_LAUNCH_PLAN_V1",
            "payload": {
                "rules": {"profile": "CommonFoundry Mainnet", "virtual_genesis_timestamp_unix_seconds": packages.LAUNCH_TIME,
                          "artifacts": {role: {"bytes": assets[name]["bytes"], "sha256": assets[name]["sha256"]}
                                        for role, name in (("bank", "MODEL-V2.bank"), ("fixed_record", packages.FIXED))}},
                "minimum_transaction_fee_atoms": 1, "source_release_unix_seconds": packages.SOURCE_TIME,
                "beacon": copy.deepcopy(packages.BEACON_POLICY),
            }, "launch_plan_digest": "", "network_id": "",
        }
        self.plan["launch_plan_digest"] = hashlib.sha256(b"CMFD/MAINNET/LAUNCH-PLAN/V1\0" + json.dumps(self.plan["payload"], separators=(",", ":")).encode()).hexdigest()
        self.plan["network_id"] = packages.integrity._rcnet_v2_derived_hash("CMFD/MAINNET/NETWORK-ID/V1", bytes.fromhex(self.plan["launch_plan_digest"])).hex()
        self.plan_path = self.root / "MAINNET-PLAN.json"
        self.plan_path.write_bytes((json.dumps(self.plan, indent=2) + "\n").encode())
        # Synthetic producer records for archive tests, not real approvals.
        authorities = {}
        approvals = {}
        for index, role in enumerate(signature_contract.ROLES, 1):
            key_hash = str(index) * 64
            authority = {"signer_identity": role + "@example.invalid", "key_blob_sha256": key_hash,
                         "allowed_signers_sha256": str(index + 2) * 64, "key_type": "ssh-ed25519",
                         "key_fingerprint": "SHA256:" + base64.b64encode(bytes.fromhex(key_hash)).decode().rstrip("=")}
            authorities[role] = authority
            approvals[role] = {**authority, "namespace": signature_contract.NAMESPACES[role],
                               "approval_sha256": str(index + 4) * 64, "signature_sha256": str(index + 6) * 64}
        self.approval_subject = {
            "schema": mainnet_approval.SUBJECT_SCHEMA, "phase": "mainnet_plan", "review_source_commit": self.commit,
            "launch_plan_sha256": hashlib.sha256(self.plan_path.read_bytes()).hexdigest(),
            "launch_plan_bytes": self.plan_path.stat().st_size, "launch_plan_digest": self.plan["launch_plan_digest"],
            "network_id": self.plan["network_id"], "source_release_unix_seconds": packages.SOURCE_TIME,
            "mining_start_unix_seconds": packages.LAUNCH_TIME, "genesis_policy": "requires_verified_launch_beacon",
            "proof_qualification_subject_sha256": "9" * 64, "qualification_binding_sha256": "b" * 64,
            "approval_trust_sha256": hashlib.sha256(signature_contract.canonical_json({**authorities, "ssh_keygen_sha256": "c" * 64})).hexdigest(),
        }
        self.approval_manifest = {"schema": mainnet_approval.MANIFEST_SCHEMA, "subject": self.approval_subject,
                                  "subject_sha256": hashlib.sha256(signature_contract.canonical_json(self.approval_subject)).hexdigest(),
                                  "approvals": approvals}
        self.approval_path = self.root / "MAINNET-APPROVALS.json"
        self.approval_path.write_bytes(signature_contract.canonical_json(self.approval_manifest))
        self.info = {"format": "commonfoundry-mainnet-launch-info", "format_version": 1,
                     "source_commit": self.commit, "source_release_utc": packages.SOURCE_UTC,
                     "mining_start_utc": packages.LAUNCH_UTC, "launch_plan": self.plan,
                     "genesis_policy": "requires_verified_launch_beacon", "beacon_round": packages.BEACON_ROUND,
                     "activation_evidence_sha256": "3" * 64,
                     "mainnet_approval_manifest_sha256": hashlib.sha256(self.approval_path.read_bytes()).hexdigest(),
                     "proof_approval_trust": {"contract_schema": signature_contract.SUBJECT_SCHEMA,
                                               "qualification_binding_sha256": "b" * 64, "ssh_keygen_sha256": "c" * 64,
                                               **authorities}}
        self.calls = []

    def args(self, platform="windows-x86_64", kind="runtime", output="output"):
        windows = platform.startswith("windows")
        fixture = pe_x86_64_fixture if windows else elf_x86_64_fixture
        binaries = self.root / platform
        binaries.mkdir(exist_ok=True)
        for role in ("cmfd-node", "common-foundry-wallet", "cmfd-miner", "cmfd-launch"):
            (binaries / role).write_bytes(fixture(role.encode()))
        for role in ("cmfd-v4-replay", "real_bank0_relations"):
            (binaries / role).write_bytes(elf_x86_64_fixture(role.encode()))
        return argparse.Namespace(repo=self.repo, platform=platform, kind=kind, commit=self.commit,
                                  version="1.0.0", plan=self.plan_path, approval_manifest=self.approval_path, output=self.root / output,
                                  node=binaries / "cmfd-node" if kind == "runtime" else None,
                                  wallet=binaries / "common-foundry-wallet" if kind == "runtime" else None,
                                  miner=binaries / "cmfd-miner" if kind == "miner" else None,
                                  launch=binaries / "cmfd-launch", replay_worker=binaries / "cmfd-v4-replay",
                                  relation_worker=binaries / "real_bank0_relations")

    def sources(self, repo, commit, paths, version):
        return {name: (repo / relative).read_bytes().replace(b"\r\n", b"\n") for name, relative in paths.items()}, 1789840000

    def output(self, executable, arguments):
        self.calls.append((executable.name, arguments))
        if arguments == ["--version"]:
            return b"1.0.0\n"
        if arguments == ["schedule"]:
            beacon = self.plan["payload"]["beacon"]
            return packages.canonical({"schema": "CMFD_MAINNET_LAUNCH_SCHEDULE_V1",
                                       "source_release_unix_seconds": packages.SOURCE_TIME, "mining_start_unix_seconds": packages.LAUNCH_TIME,
                                       "source_release_utc": packages.SOURCE_UTC, "mining_start_utc": packages.LAUNCH_UTC,
                                       "beacon_round": packages.BEACON_ROUND, "mainnet_activation_authorized": False,
                                       **{"beacon_" + key: beacon[key] for key in ("chain_hash", "public_key", "scheme")}})
        if arguments == ["runtime-identity"]:
            return packages.canonical({"schema": "CMFD_WALLET_PRELAUNCH_IDENTITY_V1", "role": "common-foundry-wallet",
                                       "package_version": "1.0.0", "launch_info_base64": base64.b64encode(packages.canonical(self.info)).decode()})
        self.assertEqual(arguments, ["mainnet-launch-info"])
        return packages.canonical(self.info)

    def assemble(self, args, output=None, sources=None):
        with mock.patch.object(packages.integrity, "_require_native_runtime_platform"), \
             mock.patch.object(packages, "validate_review_ancestry"), \
             mock.patch.object(packages, "source_snapshot", side_effect=sources or self.sources), \
             mock.patch.object(packages, "native_output", side_effect=output or self.output):
            return packages.assemble(args)

    def contents(self, archive):
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as handle:
                return {name.split("/", 1)[1]: handle.read(name) for name in handle.namelist() if not name.endswith("/")}
        with tarfile.open(archive) as handle:
            return {row.name.split("/", 1)[1]: handle.extractfile(row).read() for row in handle.getmembers() if row.isfile()}

    def test_all_four_packages_are_deterministic_and_self_contained(self):
        for platform in packages.PLATFORMS:
            for kind in ("runtime", "miner"):
                with self.subTest(platform=platform, kind=kind):
                    args = self.args(platform, kind, platform + kind)
                    archive = self.assemble(args)
                    content = self.contents(archive)
                    receipt = json.loads(content.pop("MAINNET-PACKAGE.json"))
                    self.assertFalse(receipt["release_approved"])
                    self.assertEqual(receipt["files"], {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in content.items()})
                    self.assertEqual(content["production-mainnet/MAINNET-PLAN.json"], self.plan_path.read_bytes())
                    self.assertNotIn("production-mainnet/LAUNCH-BEACON.json", content)
                    if kind == "runtime":
                        # The fixture models frozen Git blobs, not checkout CRLF.
                        self.assertEqual(content["RECOVERY.md"], (self.repo / "packaging/mainnet/RECOVERY.md").read_bytes().replace(b"\r\n", b"\n"))
                        self.assertEqual(content["STORAGE-RECOVERY.md"], (self.repo / "docs/storage-recovery.md").read_bytes().replace(b"\r\n", b"\n"))
                    worker = "production-v4/" if kind == "runtime" else ""
                    self.assertIn(worker + "cmfd-v4-replay", content)
                    self.assertIn(worker + "real_bank0_relations", content)
                    args.output = self.root / (platform + kind + "-repeat")
                    repeat = self.assemble(args)
                    self.assertEqual(archive.read_bytes(), repeat.read_bytes())
        self.assertFalse(any(arguments == ["network-info"] for _, arguments in self.calls))

    def test_source_commit_or_approval_identity_mismatch_is_rejected(self):
        def output(executable, arguments):
            data = self.output(executable, arguments)
            if arguments == ["mainnet-launch-info"]:
                value = json.loads(data)
                value["source_commit"] = "b" * 40
                return packages.canonical(value)
            return data
        args = self.args()
        with self.assertRaisesRegex(packages.Error, "source commit"):
            self.assemble(args, output=output)
        self.assertEqual(list(args.output.iterdir()), [])
        def differing_approval(executable, arguments):
            if arguments == ["mainnet-launch-info"]:
                value = copy.deepcopy(self.info)
                value["activation_evidence_sha256"] = "4" * 64
                return packages.canonical(value)
            return self.output(executable, arguments)
        with self.assertRaisesRegex(packages.Error, "activation identities disagree"):
            self.assemble(args, output=differing_approval)

    def test_legacy_wallet_identity_cannot_be_packaged_as_mainnet(self):
        def output(executable, arguments):
            if arguments == ["runtime-identity"]:
                return packages.canonical({"schema": "CMFD_WALLET_RUNTIME_IDENTITY_V1"})
            return self.output(executable, arguments)
        with self.assertRaisesRegex(packages.Error, "prelaunch identity"):
            self.assemble(self.args(), output=output)

    def test_wrong_schedule_and_executable_version_are_rejected(self):
        for failure in ("schedule", "version"):
            def output(executable, arguments):
                if failure == "version" and arguments == ["--version"]:
                    return b"0.1.0-rc.5\n"
                data = self.output(executable, arguments)
                if failure == "schedule" and arguments == ["schedule"]:
                    value = json.loads(data)
                    value["beacon_round"] -= 1
                    return packages.canonical(value)
                return data
            with self.assertRaises(packages.Error):
                self.assemble(self.args(), output=output)

    def test_identity_side_effects_prevent_archive_publication(self):
        for mode in ("file", "directory", "executable"):
            args = self.args(output=mode)
            def output(executable, arguments):
                if mode == "file":
                    (executable.parent / "wallet.key").write_bytes(b"unexpected")
                elif mode == "directory":
                    (executable.parent / "chain-data").mkdir(exist_ok=True)
                else:
                    executable.write_bytes(b"modified")
                return self.output(executable, arguments)
            with self.assertRaisesRegex(packages.Error, "modified the staged package"):
                self.assemble(args, output=output)
            self.assertEqual(list(args.output.iterdir()), [])

    def test_catalog_mismatches_and_path_traversal_are_rejected(self):
        for mode in ("hash", "path", "part", "roles", "record"):
            def sources(*args):
                values, epoch = self.sources(*args)
                if mode == "record":
                    values[packages.FIXED] += b"\n"
                else:
                    document = json.loads(values["V4-INPUT-CHUNKS.json"])
                    row = document["files"][0]
                    if mode == "hash": row["sha256"] = "f" * 64
                    elif mode == "path": row["relative_path"] = "../wallet.key"
                    elif mode == "part": row["parts"][0]["name"] = "C:\\wallet.key"
                    else: row["roles"] = ["miner"]
                    values["V4-INPUT-CHUNKS.json"] = packages.canonical(document)
                return values, epoch
            with self.assertRaises(packages.Error):
                self.assemble(self.args(), sources=sources)

    def test_wrong_architecture_and_missing_worker_are_rejected_before_execution(self):
        args = self.args()
        args.node.write_bytes(elf_x86_64_fixture(b"wrong platform"))
        with self.assertRaisesRegex(packages.Error, "PE"):
            self.assemble(args)
        self.assertEqual(self.calls, [])
        args = self.args()
        args.relation_worker.unlink()
        with self.assertRaises(packages.Error):
            self.assemble(args)
        self.assertEqual(self.calls, [])

    def test_no_overwrite_or_rc_label_escape(self):
        args = self.args()
        archive = self.assemble(args)
        original = archive.read_bytes()
        with self.assertRaisesRegex(packages.Error, "already exists"):
            self.assemble(args)
        self.assertEqual(archive.read_bytes(), original)
        args.version = "0.1.0-rc.5"
        with self.assertRaisesRegex(packages.Error, "mainnet version"):
            self.assemble(args)

    def test_distinct_worker_roles_require_distinct_binary_content(self):
        args = self.args()
        args.relation_worker.write_bytes(args.replay_worker.read_bytes())
        with self.assertRaisesRegex(packages.Error, "same binary"):
            self.assemble(args)
        self.assertEqual(self.calls, [])

    def test_plan_approval_manifest_must_match_compiled_pin_and_trust(self):
        args = self.args()
        changed = copy.deepcopy(self.approval_manifest)
        changed["approvals"]["producer"]["signature_sha256"] = "e" * 64
        args.approval_manifest.write_bytes(signature_contract.canonical_json(changed))
        with self.assertRaisesRegex(packages.Error, "compiled pin"):
            self.assemble(args)
        args.approval_manifest.write_bytes(signature_contract.canonical_json(self.approval_manifest))
        def wrong_trust(executable, arguments):
            data = self.output(executable, arguments)
            if arguments == ["mainnet-launch-info"]:
                info = json.loads(data)
                info["proof_approval_trust"]["qualification_binding_sha256"] = "d" * 64
                return packages.canonical(info)
            return data
        with self.assertRaisesRegex(packages.Error, "qualification/trust"):
            self.assemble(args, output=wrong_trust)

    def test_plan_mutation_duplicate_keys_and_noncanonical_documents_are_rejected(self):
        packages.validate_plan(self.plan_path.read_bytes())
        changed = copy.deepcopy(self.plan)
        changed["payload"]["rules"]["profile"] = "CommonFoundry RCNet-1"
        with self.assertRaises(packages.Error):
            packages.validate_plan((json.dumps(changed, indent=2) + "\n").encode())
        with self.assertRaisesRegex(packages.Error, "canonical"):
            packages.validate_plan(packages.canonical(self.plan))
        with self.assertRaisesRegex(packages.Error, "duplicate"):
            packages.strict_json(b'{"a":1,"a":2}', "fixture")
        with self.assertRaises(packages.Error):
            packages.strict_json(b'{"a":NaN}', "fixture")

    def test_dirty_source_never_qualifies_as_frozen_commit(self):
        with mock.patch.object(packages.integrity, "_run_git", side_effect=[self.commit, " M Cargo.toml"]):
            with self.assertRaisesRegex(packages.Error, "clean frozen"):
                packages.source_snapshot(self.repo, self.commit, {}, "1.0.0")

    def test_native_command_output_is_bounded(self):
        self.assertEqual(packages.native_output(Path(sys.executable), ["-c", "print('identity')"]), b"identity\r\n" if sys.platform == "win32" else b"identity\n")
        with self.assertRaisesRegex(packages.Error, "oversized|limit"):
            packages.native_output(Path(sys.executable), ["-c", f"print('x' * {packages.MAX_INFO + 1})"])
        with self.assertRaisesRegex(packages.Error, "timed out"):
            packages.native_output(Path(sys.executable), ["-c", "import time; time.sleep(5)"], timeout_seconds=0.1)


if __name__ == "__main__":
    unittest.main()
