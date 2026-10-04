"""Mainnet package fixtures: real archive/metadata checks, simulated runtime IPC.

Fixtures are not release binaries, activation evidence, or approval records.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import struct
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


def cuda_shared_x86_64_fixture(label: bytes = b"CUDA 12 test fixture") -> bytes:
    encoded = bytearray(192 + len(label))
    encoded[:4] = b"\x7fELF"
    encoded[4:7] = b"\x02\x01\x01"
    struct.pack_into("<HHI", encoded, 16, 3, 0x3e, 1)
    struct.pack_into("<Q", encoded, 32, 64)
    struct.pack_into("<HHH", encoded, 52, 64, 56, 2)
    struct.pack_into("<IIQQQQQQ", encoded, 64, 1, 5, 0, 0x400000, 0, len(encoded), len(encoded), 0x1000)
    struct.pack_into("<IIQQQQQQ", encoded, 120, 2, 4, 176, 0x4000b0, 0, 16, 16, 8)
    encoded[192:] = label
    return bytes(encoded)


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
            "schema": packages.PLAN_SCHEMA,
            "payload": {
                "rules": {"profile": "CommonFoundry Mainnet", "virtual_genesis_timestamp_unix_seconds": packages.LAUNCH_TIME,
                          "proof_of_work": {"pow_limit": "003f" + "ff" * 30},
                          "artifacts": {role: {"bytes": assets[name]["bytes"], "sha256": assets[name]["sha256"]}
                                        for role, name in (("bank", "MODEL-V2.bank"), ("fixed_record", packages.FIXED))}},
                "initial_target": f"{(2**246 // 5) - 1:064x}",
                "minimum_transaction_fee_atoms": 1, "source_release_unix_seconds": packages.SOURCE_TIME,
                "beacon": copy.deepcopy(packages.BEACON_POLICY),
            }, "launch_plan_digest": "", "network_id": "",
        }
        self.plan["launch_plan_digest"] = hashlib.sha256(packages.PLAN_DOMAIN + json.dumps(self.plan["payload"], separators=(",", ":")).encode()).hexdigest()
        self.plan["network_id"] = packages.integrity._rcnet_v2_derived_hash(packages.NETWORK_DOMAIN, bytes.fromhex(self.plan["launch_plan_digest"])).hex()
        self.plan_path = self.root / "MAINNET-PLAN.json"
        self.plan_path.write_bytes((json.dumps(self.plan, indent=2) + "\n").encode())
        # Synthetic producer records for archive tests, not real approvals.
        authorities = {}
        approvals = {}
        for index, role in enumerate(mainnet_approval.ROLES, 1):
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
                     "proof_approval_trust": {"contract_schema": "CMFD_MAINNET_SINGLE_SIGNER_APPROVAL_SUBJECT_V1",
                                               "qualification_binding_sha256": "b" * 64, "ssh_keygen_sha256": "c" * 64,
                                               "independent_reproducer": None,
                                               **authorities}}
        self.dashboard_dist = self.root / "dashboard-dist"
        dashboard = {"index.html": b'<script type="module" src="/assets/app-a1.js"></script>\n',
                     "assets/app-a1.js": b"console.log('mainnet pool');\n"}
        for name, data in dashboard.items():
            target = self.dashboard_dist / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.dashboard_manifest_path = self.root / "DASHBOARD-ASSETS.json"
        self.dashboard_manifest_path.write_bytes(packages.canonical({
            "schema": "CMFD_MAINNET_POOL_DASHBOARD_ASSETS_V1", "source_commit": self.commit,
            "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                      for name, data in dashboard.items()},
        }))
        self.cuda_runtime_path = self.root / "libcudart.so.12"
        self.cuda_runtime_path.write_bytes(cuda_shared_x86_64_fixture())
        self.cuda_sha256 = hashlib.sha256(self.cuda_runtime_path.read_bytes()).hexdigest()
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
                                  version="1.0.4", plan=self.plan_path, approval_manifest=self.approval_path, output=self.root / output,
                                  node=binaries / "cmfd-node" if kind == "runtime" else None,
                                  wallet=binaries / "common-foundry-wallet" if kind == "runtime" else None,
                                  miner=binaries / "cmfd-miner" if kind in ("miner", "hiveos") else None,
                                  launch=binaries / "cmfd-launch", replay_worker=binaries / "cmfd-v4-replay",
                                  relation_worker=binaries / "real_bank0_relations",
                                  dashboard_dist=self.dashboard_dist, dashboard_manifest=self.dashboard_manifest_path,
                                  cuda_runtime=self.cuda_runtime_path, cuda_sha256=self.cuda_sha256)

    def test_starting_target_is_explicit_bounded_and_not_an_old_plan_default(self):
        def encode(plan):
            root = hashlib.sha256(packages.PLAN_DOMAIN + json.dumps(plan["payload"], separators=(",", ":")).encode()).digest()
            plan["launch_plan_digest"] = root.hex()
            plan["network_id"] = packages.integrity._rcnet_v2_derived_hash(packages.NETWORK_DOMAIN, root).hex()
            return (json.dumps(plan, indent=2) + "\n").encode()
        self.assertEqual(packages.validate_plan(encode(copy.deepcopy(self.plan))), self.plan)
        for target in ("00" * 32, "ff" * 32, True, "0", None):
            changed = copy.deepcopy(self.plan)
            changed["payload"]["initial_target"] = target
            with self.subTest(target=target), self.assertRaises(packages.Error):
                packages.validate_plan(encode(changed))
        for mutation in ("missing", "old_schema"):
            changed = copy.deepcopy(self.plan)
            if mutation == "missing":
                del changed["payload"]["initial_target"]
            else:
                changed["schema"] = "CMFD_MAINNET_LAUNCH_PLAN_V1"
            with self.subTest(mutation=mutation), self.assertRaises(packages.Error):
                packages.validate_plan(encode(changed))

    def sources(self, repo, commit, paths, version):
        return {name: (repo / relative).read_bytes().replace(b"\r\n", b"\n") for name, relative in paths.items()}, 1789840000

    def output(self, executable, arguments, **_kwargs):
        self.calls.append((executable.name, arguments))
        if arguments == ["--version"]:
            return b"1.0.4\n"
        if arguments == ["network-info"]:
            self.assertEqual(executable.name, "real_bank0_relations")
            return packages.canonical({"schema": "CMFD_PRODUCTION_V4_PROOF_WORKER_NETWORK_V1",
                                       "role": "real_bank0_relations", "mainnet_network_id": self.plan["network_id"],
                                       "legacy_network_ids": ["1" * 64, "2" * 64]})
        if arguments == ["schedule"]:
            beacon = self.plan["payload"]["beacon"]
            return packages.canonical({"schema": "CMFD_MAINNET_LAUNCH_SCHEDULE_V1",
                                       "source_release_unix_seconds": packages.SOURCE_TIME, "mining_start_unix_seconds": packages.LAUNCH_TIME,
                                       "source_release_utc": packages.SOURCE_UTC, "mining_start_utc": packages.LAUNCH_UTC,
                                       "beacon_round": packages.BEACON_ROUND, "mainnet_activation_authorized": False,
                                       **{"beacon_" + key: beacon[key] for key in ("chain_hash", "public_key", "scheme")}})
        if arguments == ["runtime-identity"]:
            return packages.canonical({"schema": "CMFD_WALLET_PRELAUNCH_IDENTITY_V1", "role": "common-foundry-wallet",
                                       "package_version": "1.0.4", "launch_info_base64": base64.b64encode(packages.canonical(self.info)).decode()})
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

    def test_all_five_packages_are_deterministic_and_self_contained(self):
        for platform, kind in packages.PACKAGE_ROLES:
            with self.subTest(platform=platform, kind=kind):
                args = self.args(platform, kind, platform + kind)
                archive = self.assemble(args)
                content = self.contents(archive)
                receipt = json.loads(content.pop("MAINNET-PACKAGE.json"))
                self.assertFalse(receipt["release_approved"])
                self.assertEqual(receipt["files"], {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in content.items()})
                self.assertEqual(content["production-mainnet/MAINNET-PLAN.json"], self.plan_path.read_bytes())
                self.assertNotIn("production-mainnet/LAUNCH-BEACON.json", content)
                self.assertEqual(content[packages.DASHBOARD_MANIFEST], self.dashboard_manifest_path.read_bytes())
                self.assertEqual(content[packages.CUDA_RUNTIME], self.cuda_runtime_path.read_bytes())
                self.assertEqual(content["dashboard/index.html"], (self.dashboard_dist / "index.html").read_bytes())
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
        self.assertTrue(any(name == "real_bank0_relations" and arguments == ["network-info"] for name, arguments in self.calls))

    def test_linux_packages_reject_a_legacy_only_proof_worker(self):
        def legacy(executable, arguments, **kwargs):
            result = self.output(executable, arguments, **kwargs)
            if arguments == ["network-info"]:
                info = json.loads(result)
                info["mainnet_network_id"] = None
                return packages.canonical(info)
            return result
        for kind in ("runtime", "miner"):
            args = self.args("linux-x86_64", kind, "legacy-" + kind)
            with self.subTest(kind=kind), self.assertRaisesRegex(packages.Error, "proof worker.*mainnet"):
                self.assemble(args, output=legacy)
            self.assertEqual(list(args.output.iterdir()), [])

    def test_worker_network_identity_rejects_unknown_or_malformed_data(self):
        good = json.loads(self.output(Path("real_bank0_relations"), ["network-info"]))
        self.assertEqual(packages.validate_proof_worker_network(packages.canonical(good), self.plan), good)
        mutations = [("mainnet_network_id", "f" * 64), ("legacy_network_ids", [["1" * 64], "2" * 64]),
                     ("legacy_network_ids", ["1" * 64] * 2), ("role", "cmfd-v4-replay"),
                     ("legacy_network_ids", [self.plan["network_id"], "2" * 64])]
        for key, value in mutations:
            changed = {**good, key: value}
            with self.subTest(key=key, value=value), self.assertRaises(packages.Error):
                packages.validate_proof_worker_network(packages.canonical(changed), self.plan)

    def test_linux_staging_rejects_filesystem_that_loses_permissions(self):
        args = self.args("linux-x86_64", "runtime", "bad-modes")
        original = packages.integrity._canonical_file_mode
        def bad_mode(path):
            return 0o755 if path.name == "MAINNET-PACKAGE.json" else original(path)
        with mock.patch.object(packages.integrity, "_canonical_file_mode", side_effect=bad_mode):
            with self.assertRaisesRegex(packages.Error, "POSIX executable permissions"):
                self.assemble(args)
        self.assertEqual(list(args.output.iterdir()), [])

    def test_dashboard_tree_rejects_extra_missing_tampered_and_symlink_assets(self):
        args = self.args()
        extra = self.dashboard_dist / "unexpected.txt"
        extra.write_bytes(b"not reviewed")
        with self.assertRaisesRegex(packages.Error, "unexpected entry"):
            self.assemble(args)
        extra.unlink()
        script = self.dashboard_dist / "assets/app-a1.js"
        original = script.read_bytes()
        script.write_bytes(b"different script")
        with self.assertRaisesRegex(packages.Error, "differs from its reviewed manifest"):
            self.assemble(args)
        script.write_bytes(original)
        script.unlink()
        with self.assertRaisesRegex(packages.Error, "missing or extra"):
            self.assemble(args)
        try:
            script.symlink_to(self.dashboard_dist / "index.html")
        except OSError:
            return  # Windows may not permit fixture symlink creation.
        with self.assertRaisesRegex(packages.Error, "symlink"):
            self.assemble(args)

    def test_dashboard_manifest_must_bind_exact_frozen_commit_and_inventory(self):
        args = self.args()
        changed = json.loads(self.dashboard_manifest_path.read_bytes())
        changed["source_commit"] = "b" * 40
        self.dashboard_manifest_path.write_bytes(packages.canonical(changed))
        with self.assertRaisesRegex(packages.Error, "frozen source commit"):
            self.assemble(args)
        changed["source_commit"] = self.commit
        changed["files"]["assets/../../wallet.key"] = changed["files"]["index.html"]
        self.dashboard_manifest_path.write_bytes(packages.canonical(changed))
        with self.assertRaisesRegex(packages.Error, "unsafe or malformed"):
            self.assemble(args)

    def test_cuda_runtime_must_be_pinned_x86_64_elf_shared_library(self):
        args = self.args()
        args.cuda_sha256 = "1" * 64
        with self.assertRaisesRegex(packages.Error, "reviewed pin"):
            self.assemble(args)
        original = self.cuda_runtime_path.read_bytes()
        for offset, value in ((18, b"\xb7\x00"), (16, b"\x02\x00")):
            changed = bytearray(original)
            changed[offset:offset + len(value)] = value
            self.cuda_runtime_path.write_bytes(changed)
            args.cuda_sha256 = hashlib.sha256(changed).hexdigest()
            with self.subTest(offset=offset), self.assertRaisesRegex(packages.Error, "Linux x86-64 ELF shared library"):
                self.assemble(args)
        self.cuda_runtime_path.write_bytes(original)
        self.assertEqual(self.calls, [])

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
                packages.source_snapshot(self.repo, self.commit, {}, "1.0.4")

    def test_native_command_output_is_bounded(self):
        self.assertEqual(packages.native_output(Path(sys.executable), ["-c", "print('identity')"]), b"identity\r\n" if sys.platform == "win32" else b"identity\n")
        with self.assertRaisesRegex(packages.Error, "oversized|limit"):
            packages.native_output(Path(sys.executable), ["-c", f"print('x' * {packages.MAX_INFO + 1})"])
        with self.assertRaisesRegex(packages.Error, "timed out"):
            packages.native_output(Path(sys.executable), ["-c", "import time; time.sleep(5)"], timeout_seconds=0.1)


class CommittedOwnerPlanTests(unittest.TestCase):
    """Validate public owner records only; never open real custody files.

    The exact-byte guard requires explicit review if the launch plan changes.
    These checks are not signatures, private-key checks or launch approval.
    """

    def setUp(self):
        self.repo = Path(__file__).resolve().parents[2]
        self.root = self.repo / "packaging/mainnet"
        self.plan_bytes = (self.root / "MAINNET-PLAN.json").read_bytes()
        self.plan = packages.validate_plan(self.plan_bytes)

    def test_owner_plan_identity_and_approved_parameters(self):
        self.assertEqual(hashlib.sha256(self.plan_bytes).hexdigest(),
                         "f0f9cd3921162734cdc5aa8da1b59f9835a1e6f6270bf3794d60c0ad62a70a77")
        self.assertEqual(self.plan["launch_plan_digest"],
                         "2133726558490606e89a8fe3499f32c9a35722ed0022e09b7cd1cd30239d04af")
        self.assertEqual(self.plan["network_id"],
                         "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62")
        payload = self.plan["payload"]
        self.assertEqual(payload["initial_target"],
                         "000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb")
        self.assertEqual(payload["rules"]["proof_of_work"]["pow_limit"],
                         "003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        self.assertEqual(payload["source_release_unix_seconds"], 1790960400)
        self.assertEqual(payload["rules"]["virtual_genesis_timestamp_unix_seconds"], 1791046800)
        self.assertEqual(payload["beacon"]["round"], 32747812)
        self.assertEqual(payload["minimum_transaction_fee_atoms"], 10000000)

    def test_owner_plan_matches_packaged_artifact_catalog(self):
        for platform in ("windows-x86_64", "linux-x86_64"):
            for kind in ("runtime", "miner"):
                with self.subTest(platform=platform, kind=kind):
                    sources = {name: (self.repo / path).read_bytes()
                               for name, path in packages.package_sources(platform, kind).items()}
                    packages.validate_catalog(sources, self.plan)

    def test_committed_release_policy_has_only_the_selected_mainnet_owner_key(self):
        encoded = (self.root / "APPROVAL-TRUST.json").read_bytes()
        trust = packages.strict_json(encoded, "mainnet owner trust")
        self.assertEqual(packages.canonical(trust), encoded)
        self.assertEqual(set(trust), {"producer", "ssh_keygen_sha256"})
        policy = (self.root / "MAINNET-PRODUCER.allowed_signers").read_bytes()
        authority = {"signer_identity": trust["producer"]["signer_identity"],
                     **signature_contract.parse_allowed_signers_authority(policy,
                         signer_identity=trust["producer"]["signer_identity"], role="producer")}
        self.assertEqual(authority, trust["producer"])
        self.assertEqual(authority["key_blob_sha256"],
                         "700d53b1ff212ffa710d5e56a4e13788f5b76f8b83428b2ed5d3a1fffe1afdf9")
        packages.nonzero_hex(trust["ssh_keygen_sha256"], 64, "mainnet SSH verifier digest")

    def test_release_instructions_match_selected_signer_and_complete_inventory(self):
        trust = packages.strict_json((self.root / "APPROVAL-TRUST.json").read_bytes(),
                                     "mainnet owner trust")
        fingerprint = trust["producer"]["key_fingerprint"]
        instructions = (self.repo / "docs/mainnet-release-verification.md").read_text()
        guide = (self.root / "USER-GUIDE.md").read_text()
        self.assertIn(fingerprint, instructions)
        self.assertIn(fingerprint, guide)
        self.assertIn(hashlib.sha256((self.root / "MAINNET-RELEASE.allowed_signers").read_bytes()).hexdigest(),
                      instructions)
        self.assertIn("five archives", instructions)
        self.assertNotIn("including the four archives", instructions)

    def test_custody_record_is_public_only_and_matches_each_plan_role(self):
        data = (self.root / "REWARD-CUSTODY.json").read_bytes()
        report = packages.strict_json(data, "public owner custody", 8192)
        self.assertEqual(data, (json.dumps(report, indent=2) + "\n").encode())
        self.assertEqual(set(report), {"schema", "launch_plan_digest", "network_id", "wallets",
                                       "backups_authenticated", "mainnet_activation_authorized"})
        self.assertEqual(report["schema"], "CMFD_MAINNET_REWARD_CUSTODY_V1")
        for field in ("launch_plan_digest", "network_id"):
            self.assertEqual(report[field], self.plan[field])
        self.assertIs(report["backups_authenticated"], True)
        self.assertIs(report["mainnet_activation_authorized"], False)
        self.assertEqual([row["role"] for row in report["wallets"]], ["steward", "community"])
        destinations = self.plan["payload"]["rules"]["reward_destinations"]
        hashes = set()
        for wallet in report["wallets"]:
            role = wallet["role"]
            self.assertEqual(set(wallet), {"role", "destination", "encrypted_wallet_sha256",
                                           "encrypted_backup_sha256"})
            self.assertEqual(wallet["destination"], destinations[role + "_xonly_public_key"])
            packages.integrity._require_xonly_public_key(wallet["destination"], role)
            for field in ("encrypted_wallet_sha256", "encrypted_backup_sha256"):
                packages.nonzero_hex(wallet[field], 64, field)
                hashes.add(wallet[field])
        self.assertEqual(len(hashes), 4)
        self.assertEqual(len(set(destinations.values())), 2)


if __name__ == "__main__":
    unittest.main()
