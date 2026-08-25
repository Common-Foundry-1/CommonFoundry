from __future__ import annotations

import gzip
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import release_integrity as integrity


class GitFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()
        self.write(".gitignore", "target/\n")
        self.write("README.md", "fixture\n")
        self.write("gpu/CMakeLists.txt", "project(fixture)\n")
        self.write("gpu/forgematrix_v2_miner.cu", "// cuda fixture\n")
        self.write("gpu/forgematrix_v2_tensor_core.cu", "// tensor fixture\n")
        self.write("gpu/forgematrix_v2_opencl.cpp", "// opencl fixture\n")
        self.write("scripts/build-cuda-miner.ps1", "Write-Output cuda\n")
        self.write("scripts/build-opencl-miner.ps1", "Write-Output opencl\n")
        self.write("scripts/release_integrity.py", "# release finalizer fixture\n")
        self.write("packaging/releases/test.inventory", "a.bin\nb.txt\n")
        self.git("init", "--quiet")
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("add", "--", ".gitignore", "README.md", "gpu", "packaging", "scripts")
        self.git("commit", "--quiet", "-m", "fixture")

    def close(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
        return path

    def git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
        )
        return result.stdout.decode("utf-8", "strict").strip()

    @property
    def commit(self) -> str:
        return self.git("rev-parse", "HEAD")


class NativeBuildReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = GitFixture()
        self.library = self.fixture.write("target/native/miner.dll", b"native-v1")
        self.receipt = Path(f"{self.library}.build-receipt")

    def tearDown(self) -> None:
        self.fixture.close()

    def write_receipt(self) -> None:
        integrity.write_native_build_receipt(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            kind="cuda",
            library=self.library,
            build_script="scripts/build-cuda-miner.ps1",
            toolchain="nvcc 12.9; cmake 4.2",
            target="x86_64-pc-windows-msvc",
            architectures="sm_70;sm_75;sm_86;sm_89;sm_120;compute_70",
            output=self.receipt,
            source_date_epoch=1_700_000_000,
        )

    def verify_receipt(self) -> dict[str, str]:
        return integrity.verify_native_build_receipt(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            kind="cuda",
            library=self.library,
            receipt=self.receipt,
            expected_build_script="scripts/build-cuda-miner.ps1",
            expected_target="x86_64-pc-windows-msvc",
            expected_architectures="sm_70;sm_75;sm_86;sm_89;sm_120;compute_70",
            source_date_epoch=1_700_000_000,
        )

    def test_valid_receipt_roundtrip(self) -> None:
        self.write_receipt()
        fields = self.verify_receipt()
        self.assertEqual(fields["GIT_COMMIT"], self.fixture.commit)
        self.assertEqual(fields["LIBRARY_SHA256"], integrity._sha256_file(self.library))
        self.assertIn("gpu/forgematrix_v2_tensor_core.cu", fields["SOURCE_FILES"])
        self.assertEqual(
            fields["TRUST_SCOPE"], "IDENTITY_GUARD_ONLY_NOT_AUTHENTICATION"
        )

    def test_stale_receipt_is_rejected_after_source_commit_changes(self) -> None:
        self.write_receipt()
        self.fixture.write("gpu/forgematrix_v2_miner.cu", "// cuda fixture v2\n")
        self.fixture.git("add", "--", "gpu/forgematrix_v2_miner.cu")
        self.fixture.git("commit", "--quiet", "-m", "change native source")
        with self.assertRaisesRegex(integrity.IntegrityError, "GIT_COMMIT"):
            self.verify_receipt()

    def test_altered_library_is_rejected(self) -> None:
        self.write_receipt()
        self.library.write_bytes(b"native-v1 altered")
        with self.assertRaisesRegex(integrity.IntegrityError, "LIBRARY_SHA256"):
            self.verify_receipt()

    def test_mismatched_architecture_is_rejected(self) -> None:
        self.write_receipt()
        with self.assertRaisesRegex(integrity.IntegrityError, "ARCHITECTURES"):
            integrity.verify_native_build_receipt(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                kind="cuda",
                library=self.library,
                receipt=self.receipt,
                expected_build_script="scripts/build-cuda-miner.ps1",
                expected_target="x86_64-pc-windows-msvc",
                expected_architectures="sm_89",
                source_date_epoch=1_700_000_000,
            )

    def test_symlinked_library_is_rejected(self) -> None:
        target = self.fixture.write("target/native/other.dll", b"native-v1")
        link = self.fixture.root / "target/native/link.dll"
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symbolic links are unavailable: {error}")
        with self.assertRaisesRegex(integrity.IntegrityError, "non-symlink"):
            integrity.write_native_build_receipt(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                kind="cuda",
                library=link,
                build_script="scripts/build-cuda-miner.ps1",
                toolchain="nvcc 12.9; cmake 4.2",
                target="x86_64-pc-windows-msvc",
                architectures="sm_70;sm_75;sm_86;sm_89;sm_120;compute_70",
                output=self.receipt,
                source_date_epoch=1_700_000_000,
            )


class DeterministicArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.epoch = 1_700_000_001

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def stage(self, parent: str, first_mtime: int, second_mtime: int) -> Path:
        stage = self.root / parent / "commonfoundry-package"
        stage.mkdir(parents=True)
        binary = stage / "cmfd-miner.exe"
        readme = stage / "README.txt"
        binary.write_bytes(b"miner bytes\0\1")
        readme.write_text("read me\n", encoding="utf-8", newline="\n")
        os.utime(binary, (first_mtime, first_mtime))
        os.utime(readme, (second_mtime, second_mtime))
        return stage

    def test_zip_and_tar_gz_are_independent_of_source_mtimes(self) -> None:
        stage_a = self.stage("one", int(time.time()) - 100, int(time.time()) - 50)
        stage_b = self.stage("two", int(time.time()) + 50, int(time.time()) + 100)
        zip_a = self.root / "one.zip"
        zip_b = self.root / "two.zip"
        tar_a = self.root / "one.tar.gz"
        tar_b = self.root / "two.tar.gz"
        integrity.create_deterministic_zip(stage_a, zip_a, self.epoch)
        integrity.create_deterministic_zip(stage_b, zip_b, self.epoch)
        integrity.create_deterministic_tar_gz(stage_a, tar_a, self.epoch)
        integrity.create_deterministic_tar_gz(stage_b, tar_b, self.epoch)
        self.assertEqual(zip_a.read_bytes(), zip_b.read_bytes())
        self.assertEqual(tar_a.read_bytes(), tar_b.read_bytes())

    def test_symlinked_stage_root_is_rejected(self) -> None:
        stage = self.stage("real", 1, 2)
        link = self.root / "linked-stage"
        try:
            link.symlink_to(stage, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symbolic links are unavailable: {error}")
        with self.assertRaisesRegex(integrity.IntegrityError, "non-symlink"):
            integrity._archive_entries(link)

    @unittest.skipIf(os.name == "nt", "backslash is a separator on Windows")
    def test_backslash_archive_member_is_rejected(self) -> None:
        stage = self.stage("unsafe", 1, 2)
        (stage / "..\\escape").write_bytes(b"escape")
        with self.assertRaisesRegex(integrity.IntegrityError, "unsafe"):
            integrity._archive_entries(stage)

    def test_tar_symlink_member_is_rejected(self) -> None:
        stage = self.root / "tar" / "package"
        stage.mkdir(parents=True)
        (stage / "x").write_bytes(b"same")
        (stage / "y").write_bytes(b"same")
        archive_path = self.root / "symlink.tar.gz"
        with (
            archive_path.open("wb") as raw,
            gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=self.epoch
            ) as zipped,
            tarfile.open(
                fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive,
        ):
            directory = tarfile.TarInfo("package")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.mtime = self.epoch
            archive.addfile(directory)
            symlink = tarfile.TarInfo("package/x")
            symlink.type = tarfile.SYMTYPE
            symlink.linkname = "y"
            symlink.mode = 0o644
            symlink.mtime = self.epoch
            archive.addfile(symlink)
            regular = tarfile.TarInfo("package/y")
            regular.type = tarfile.REGTYPE
            regular.mode = 0o644
            regular.mtime = self.epoch
            regular.size = 4
            archive.addfile(regular, io.BytesIO(b"same"))
        with self.assertRaisesRegex(integrity.IntegrityError, "wrong type"):
            integrity.verify_deterministic_tar_gz(stage, archive_path, self.epoch)

    def test_zip_symlink_member_is_rejected(self) -> None:
        stage = self.root / "zip" / "package"
        stage.mkdir(parents=True)
        (stage / "x").write_bytes(b"../escape")
        archive_path = self.root / "symlink.zip"
        timestamp = integrity._zip_datetime(self.epoch)
        with zipfile.ZipFile(
            archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            directory = zipfile.ZipInfo("package/", timestamp)
            directory.create_system = 3
            directory.compress_type = zipfile.ZIP_DEFLATED
            directory.external_attr = ((stat.S_IFDIR | 0o755) & 0xFFFF) << 16
            directory.external_attr |= 0x10
            archive.writestr(directory, b"")
            symlink = zipfile.ZipInfo("package/x", timestamp)
            symlink.create_system = 3
            symlink.compress_type = zipfile.ZIP_DEFLATED
            symlink.external_attr = ((stat.S_IFLNK | 0o644) & 0xFFFF) << 16
            archive.writestr(symlink, b"../escape")
        with self.assertRaisesRegex(integrity.IntegrityError, "type or mode"):
            integrity.verify_deterministic_zip(stage, archive_path, self.epoch)


class DebianPackageInspectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def tar_gz(
        rows: list[tuple[str, str, bytes | str]], epoch: int, owner: int
    ) -> bytes:
        buffer = io.BytesIO()
        with (
            gzip.GzipFile(
                filename="", mode="wb", fileobj=buffer, mtime=epoch
            ) as zipped,
            tarfile.open(
                fileobj=zipped, mode="w", format=tarfile.GNU_FORMAT
            ) as archive,
        ):
            for name, kind, value in rows:
                member = tarfile.TarInfo(name)
                member.mtime = epoch
                member.uid = owner
                member.gid = owner
                member.mode = 0o755 if kind == "directory" else 0o644
                if kind == "directory":
                    member.type = tarfile.DIRTYPE
                    archive.addfile(member)
                elif kind == "file":
                    assert isinstance(value, bytes)
                    member.type = tarfile.REGTYPE
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))
                elif kind == "symlink":
                    assert isinstance(value, str)
                    member.type = tarfile.SYMTYPE
                    member.linkname = value
                    archive.addfile(member)
                else:  # pragma: no cover - fixture helper contract.
                    raise AssertionError(kind)
        return buffer.getvalue()

    @staticmethod
    def ar(rows: list[tuple[str, bytes]], epoch: int, owner: int) -> bytes:
        output = bytearray(b"!<arch>\n")
        for name, content in rows:
            fields = (
                f"{name}/".ljust(16)
                + str(epoch).ljust(12)
                + str(owner).ljust(6)
                + str(owner).ljust(6)
                + f"{0o100644:o}".ljust(8)
                + str(len(content)).ljust(10)
                + "`\n"
            )
            output.extend(fields.encode("ascii"))
            output.extend(content)
            if len(content) % 2:
                output.extend(b"\n")
        return bytes(output)

    def package(
        self,
        name: str,
        epoch: int,
        owner: int = 0,
        control_rows: list[tuple[str, str, bytes | str]] | None = None,
        payload_rows: list[tuple[str, str, bytes | str]] | None = None,
        ar_order: tuple[str, ...] = integrity.DEB_AR_MEMBERS,
    ) -> Path:
        control = self.tar_gz(
            control_rows
            or [("./control", "file", b"Package: common-foundry-wallet\n")],
            epoch,
            owner,
        )
        payload = self.tar_gz(
            payload_rows
            or [
                (".", "directory", b""),
                ("./usr", "directory", b""),
                ("./usr/bin", "directory", b""),
                ("./usr/bin/common-foundry-wallet", "file", b"wallet"),
            ],
            epoch,
            owner,
        )
        members = {
            "debian-binary": b"2.0\n",
            "control.tar.gz": control,
            "data.tar.gz": payload,
        }
        path = self.root / name
        path.write_bytes(
            self.ar([(member, members[member]) for member in ar_order], epoch, owner)
        )
        return path

    def test_semantic_hash_ignores_only_container_time_and_owner(self) -> None:
        first = self.package("first.deb", 1_700_000_000, 0)
        second = self.package("second.deb", 1_800_000_000, 1001)
        self.assertNotEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            integrity.inspect_debian_package(first),
            integrity.inspect_debian_package(second),
        )

    def test_optional_canonical_root_directory_is_container_metadata(self) -> None:
        without_root = self.package(
            "without-root.deb",
            1_700_000_000,
            payload_rows=[
                ("./usr", "directory", b""),
                ("./usr/bin", "directory", b""),
                ("./usr/bin/common-foundry-wallet", "file", b"wallet"),
            ],
        )
        with_root = self.package(
            "with-root.deb",
            1_800_000_000,
            control_rows=[
                (".", "directory", b""),
                ("./control", "file", b"Package: common-foundry-wallet\n"),
            ],
        )
        self.assertEqual(
            integrity.inspect_debian_package(without_root),
            integrity.inspect_debian_package(with_root),
        )

    def test_symlinked_payload_is_rejected_before_extraction(self) -> None:
        package = self.package(
            "symlink.deb",
            1_700_000_000,
            payload_rows=[
                (".", "directory", b""),
                ("./usr", "directory", b""),
                ("./usr/bin", "directory", b""),
                ("./usr/bin/common-foundry-wallet", "symlink", "../../escape"),
            ],
        )
        with self.assertRaisesRegex(integrity.IntegrityError, "contains link"):
            integrity.inspect_debian_package(package)

    def test_parent_traversal_member_is_rejected_before_extraction(self) -> None:
        package = self.package(
            "traversal.deb",
            1_700_000_000,
            payload_rows=[
                ("../escape", "file", b"escape"),
                ("usr/bin/common-foundry-wallet", "file", b"wallet"),
            ],
        )
        with self.assertRaisesRegex(integrity.IntegrityError, "unsafe"):
            integrity.inspect_debian_package(package)

    def test_reordered_ar_members_are_rejected(self) -> None:
        package = self.package(
            "reordered.deb",
            1_700_000_000,
            ar_order=("control.tar.gz", "debian-binary", "data.tar.gz"),
        )
        with self.assertRaisesRegex(integrity.IntegrityError, "reordered"):
            integrity.inspect_debian_package(package)


class ProductionRcGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.commit = "1" * 40

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, name: str, value: object) -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return path

    def valid_stage_files(self) -> dict[str, Path]:
        launch_root = bytes(range(1, 33)).hex()
        network_id = bytes(range(33, 65)).hex()
        virtual_genesis = bytes(range(65, 97)).hex()
        pow_limit = "00" + "ff" * 31
        steward = bytes(range(97, 129)).hex()
        community = bytes(range(129, 161)).hex()
        record = {
            "record_version": 2,
            "record_digest": "11" * 32,
            "manifest_digest": "22" * 32,
            "model_identity_digest": "33" * 32,
            "suite_digest": "44" * 32,
            "setup_identity": "55" * 32,
            "padded_variables": 33,
            "commitment_root": "66" * 32,
        }
        services = {
            "bootstrap_ipv4": "8.8.8.8",
            "rpc_port": 19443,
            "p2p_port": 19444,
            "pool_port": 19445,
        }
        rewards = {
            "steward_xonly_public_key": steward,
            "community_xonly_public_key": community,
        }
        consensus = {
            "network_protocol_version": 1,
            "block_version": 1,
            "transaction_version": 1,
            "wire_version": 1,
            "maximum_future_offset_seconds": 86400,
            "target_spacing_seconds": 60,
            "coinbase_maturity_blocks": 100,
            "median_time_window": 11,
            "max_block_transactions": 1024,
            "max_transaction_inputs": 128,
            "max_transaction_outputs": 128,
            "max_block_aggregate_inputs": 4096,
            "max_block_aggregate_outputs": 4096,
            "max_block_signature_checks": 2048,
            "max_coinbase_outputs": 3,
            "consensus_signature_bytes": 64,
            "dgw_window": 180,
            "wire_header_bytes": 16,
            "max_transaction_bytes": 65536,
            "max_proof_bytes": 262144,
            "max_block_bytes": 1048576,
        }
        monetary_policy = {
            "atoms_per_coin": 100000000,
            "initial_subsidy_atoms": 50000000000,
            "tail_height": 2628001,
            "tail_subsidy_atoms": 500000000,
            "steward_percent": 25,
            "community_percent": 5,
        }
        launch_candidate = self.write_json(
            integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME,
            {
                "schema": "CMFD_RCNET_LAUNCH_CANDIDATE_V1",
                "payload": {
                    "profile": "CommonFoundry RCNet-1",
                    "record_v2": record,
                    "virtual_genesis_timestamp_unix_seconds": 1_800_000_000,
                    "services": services,
                    "consensus": consensus,
                    "proof_of_work": {
                        "algorithm_version": 2,
                        "proof_version": 1,
                        "banks": 1,
                        "layers_per_bank": 4,
                        "maximum_structured_proof_bytes": 262144,
                        "pow_limit": pow_limit,
                    },
                    "monetary_policy": monetary_policy,
                    "reward_destinations": rewards,
                },
                "launch_root": launch_root,
                "network_id": network_id,
                "virtual_genesis_hash": virtual_genesis,
            },
        )
        verifier_binary = self.root / integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME
        verifier_binary.write_bytes(b"fresh-process verifier fixture")
        verifier_report = self.write_json(
            integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME,
            {
                "network_id": network_id,
                "producer_report_checked": True,
                "qualification_journal_checked": True,
                "report_version": 2,
                "verifier_only": True,
            },
        )
        artifact_rows = {
            role: {
                "bytes": 1,
                "file_name": f"{role}.fixture",
                "sha256": "4" * 64,
            }
            for role in (
                "bank",
                "cargo",
                "cargo_config",
                "consensus_executable",
                "record_v2",
                "request",
                "proof",
                "producer_report",
                "journal",
                "rustc",
            )
        }
        artifact_rows["fresh_process_verifier_binary"] = {
            "bytes": verifier_binary.stat().st_size,
            "file_name": integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME,
            "sha256": integrity._sha256_file(verifier_binary),
        }
        artifact_rows["verifier_report"] = {
            "bytes": verifier_report.stat().st_size,
            "file_name": integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME,
            "sha256": integrity._sha256_file(verifier_report),
        }
        toolchain_identity = {
            "cargo_sha256": artifact_rows["cargo"]["sha256"],
            "cargo_version": "cargo fixture",
            "rustc_sha256": artifact_rows["rustc"]["sha256"],
            "rustc_version": "rustc fixture",
            "cargo_config_sha256": artifact_rows["cargo_config"]["sha256"],
            "environment_policy": "CMFD_QUALIFICATION_ALLOWLIST_V1",
        }
        qualification_manifest = self.write_json(
            integrity.PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME,
            {
                "artifacts": artifact_rows,
                "network_profile": "RCNet-1",
                "proof_selection": "ProductionV3",
                "completion_evidence": {
                    "fresh_verifier_report": True,
                    "producer_report": True,
                },
                "journal_semantics": {
                    "completion_marker": False,
                    "diagnostic_only": True,
                    "resumable": False,
                    "used_as_completion_evidence": False,
                },
                "qualification": {
                    "available_scratch_bytes_before_producer": 70_866_960_384,
                    "composed_claims": 134,
                    "fresh_process_verifier": True,
                    "padded_variables": 33,
                    "producer_process_id": 101,
                    "required_scratch_bytes": 70_866_960_384,
                    "scratch_floor_bytes": 53_687_091_200,
                    "scratch_margin_bytes": 17_179_869_184,
                    "verifier_process_id": 102,
                },
                "schema": "CMFD_PRODUCTION_V3_QUALIFICATION_MANIFEST_V1",
                "source_commit": "9" * 40,
                "status": "qualification_complete_activation_disabled",
                "toolchain": {
                    **toolchain_identity,
                    "identity_sha256": integrity._sha256_bytes(
                        json.dumps(
                            toolchain_identity,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=True,
                        ).encode("utf-8")
                    ),
                },
            },
        )
        evidence = self.write_json(
            integrity.PRODUCTION_V3_ACTIVATION_NAME,
            {
                "fresh_process_verifier_binary_sha256": integrity._sha256_file(
                    verifier_binary
                ),
                "fresh_process_verifier_report_sha256": integrity._sha256_file(
                    verifier_report
                ),
                "network_profile": "RCNet-1",
                "proof_selection": "ProductionV3",
                "qualification_manifest_sha256": integrity._sha256_file(
                    qualification_manifest
                ),
                "qualification_source_commit": "9" * 40,
                "schema": "CMFD_PRODUCTION_V3_ACTIVATION_V1",
                "source_commit": self.commit,
            },
        )
        network_info = self.write_json(
            integrity.PRODUCTION_RC_NETWORK_INFO_NAME,
            {
                "network": {
                    "name": "CommonFoundry RCNet-1",
                    "network_id": network_id,
                    "virtual_genesis_hash": virtual_genesis,
                    "virtual_genesis_timestamp_unix_seconds": "1800000000",
                },
                "proof_of_work": {
                    "activation_evidence_sha256": integrity._sha256_file(evidence),
                    "build_source_commit": self.commit,
                    "selection": "ProductionV3",
                    "pow_limit": pow_limit,
                    "algorithm_version": 2,
                    "proof_version": 1,
                    "banks": 1,
                    "layers_per_bank": 4,
                    "maximum_structured_proof_bytes": "262144",
                    "model": {
                        "record_digest": record["record_digest"],
                        "manifest_digest": record["manifest_digest"],
                        "model_identity_digest": record["model_identity_digest"],
                        "suite_digest": record["suite_digest"],
                        "setup_identity": record["setup_identity"],
                        "padded_variables": record["padded_variables"],
                    },
                },
                "services": {
                    "rpc_port": services["rpc_port"],
                    "p2p_port": services["p2p_port"],
                    "pool_port": services["pool_port"],
                    "bootstrap_peer": f"{services['bootstrap_ipv4']}:{services['p2p_port']}",
                },
                "reward_destinations": rewards,
                "consensus": {
                    "versions": {
                        field: consensus[field]
                        for field in (
                            "network_protocol_version",
                            "block_version",
                            "transaction_version",
                            "wire_version",
                        )
                    },
                    "limits": {
                        field: str(value)
                        for field, value in consensus.items()
                        if field
                        not in {
                            "network_protocol_version",
                            "block_version",
                            "transaction_version",
                            "wire_version",
                        }
                    },
                },
                "monetary_policy": {
                    field: value if field.endswith("_percent") else str(value)
                    for field, value in monetary_policy.items()
                },
            },
        )
        return {
            integrity.PRODUCTION_RC_NETWORK_INFO_NAME: network_info,
            integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME: launch_candidate,
            integrity.PRODUCTION_V3_ACTIVATION_NAME: evidence,
            integrity.PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME: qualification_manifest,
            integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME: verifier_binary,
            integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME: verifier_report,
        }

    def test_production_rc_labels_exclude_devnet_candidates(self) -> None:
        for label in ("production-rc1", "mainnet-rc.2", "v1.0.0-rc1"):
            self.assertTrue(integrity.is_production_rc_label(label), label)
        for label in ("0.1.0-devnet.14", "v0.1.0-devnet.14-rc1", "debug"):
            self.assertFalse(integrity.is_production_rc_label(label), label)

    def test_production_rc_without_compiled_evidence_fails_closed(self) -> None:
        with self.assertRaisesRegex(integrity.IntegrityError, "missing compiled"):
            integrity.validate_production_rc_artifacts(
                version="1.0.0-rc1", commit=self.commit, stage_files={}
            )

    def test_devnet_or_v2_compiled_identity_is_rejected(self) -> None:
        stage_files = self.valid_stage_files()
        network_info = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        value = json.loads(network_info.read_text(encoding="utf-8"))
        value["network"]["name"] = "CommonFoundry Devnet-0"
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, value)
        with self.assertRaisesRegex(integrity.IntegrityError, "not RCNet-1"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1",
                commit=self.commit,
                stage_files=stage_files,
            )

    def test_complete_compiled_identity_and_evidence_pass(self) -> None:
        integrity.validate_production_rc_artifacts(
            version="production-rc1",
            commit=self.commit,
            stage_files=self.valid_stage_files(),
        )

    def test_launch_candidate_unknown_fields_are_rejected(self) -> None:
        stage_files = self.valid_stage_files()
        path = stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME]
        candidate = json.loads(path.read_text(encoding="utf-8"))
        candidate["payload"]["unknown"] = True
        self.write_json(integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, candidate)
        with self.assertRaisesRegex(integrity.IntegrityError, "unknown fields"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_placeholder_identity_and_documentation_bootstrap_are_rejected(self) -> None:
        stage_files = self.valid_stage_files()
        path = stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME]
        candidate = json.loads(path.read_text(encoding="utf-8"))
        candidate["network_id"] = "72" * 32
        self.write_json(integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, candidate)
        with self.assertRaisesRegex(integrity.IntegrityError, "placeholder"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

        stage_files = self.valid_stage_files()
        path = stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME]
        candidate = json.loads(path.read_text(encoding="utf-8"))
        candidate["payload"]["services"]["bootstrap_ipv4"] = "203.0.113.9"
        self.write_json(integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, candidate)
        with self.assertRaisesRegex(integrity.IntegrityError, "RFC 5737"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_development_reward_and_pow_limit_mutation_are_rejected(self) -> None:
        stage_files = self.valid_stage_files()
        path = stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME]
        candidate = json.loads(path.read_text(encoding="utf-8"))
        candidate["payload"]["reward_destinations"]["steward_xonly_public_key"] = (
            next(iter(integrity.INSECURE_DEV_REWARD_DESTINATIONS))
        )
        self.write_json(integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, candidate)
        with self.assertRaisesRegex(integrity.IntegrityError, "insecure development"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

        stage_files = self.valid_stage_files()
        path = stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME]
        candidate = json.loads(path.read_text(encoding="utf-8"))
        candidate["payload"]["proof_of_work"]["pow_limit"] = "01" + "ff" * 31
        self.write_json(integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, candidate)
        with self.assertRaisesRegex(integrity.IntegrityError, "proof-of-work limit"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_dynamic_release_commit_must_match_the_checkout(self) -> None:
        stage_files = self.valid_stage_files()
        network_path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network = json.loads(network_path.read_text(encoding="utf-8"))
        network["proof_of_work"]["build_source_commit"] = "8" * 40
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network)
        with self.assertRaisesRegex(integrity.IntegrityError, "checked-out commit"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1",
                commit=self.commit,
                stage_files=stage_files,
            )

    def test_arbitrary_nonzero_hashes_do_not_satisfy_the_gate(self) -> None:
        stage_files = self.valid_stage_files()
        evidence_path = stage_files[integrity.PRODUCTION_V3_ACTIVATION_NAME]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["qualification_manifest_sha256"] = "f" * 64
        self.write_json(integrity.PRODUCTION_V3_ACTIVATION_NAME, evidence)
        network_path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network = json.loads(network_path.read_text(encoding="utf-8"))
        network["proof_of_work"]["activation_evidence_sha256"] = (
            integrity._sha256_file(evidence_path)
        )
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network)
        with self.assertRaisesRegex(
            integrity.IntegrityError, "qualification_manifest_sha256"
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1",
                commit=self.commit,
                stage_files=stage_files,
            )

    def test_tampered_verifier_binary_is_rejected(self) -> None:
        stage_files = self.valid_stage_files()
        stage_files[
            integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME
        ].write_bytes(b"tampered verifier")
        with self.assertRaisesRegex(
            integrity.IntegrityError, "fresh_process_verifier_binary_sha256"
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1",
                commit=self.commit,
                stage_files=stage_files,
            )

    def test_tampered_verifier_report_is_rejected(self) -> None:
        stage_files = self.valid_stage_files()
        report = stage_files[
            integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME
        ]
        report.write_bytes(report.read_bytes() + b"\n")
        with self.assertRaisesRegex(
            integrity.IntegrityError, "fresh_process_verifier_report_sha256"
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1",
                commit=self.commit,
                stage_files=stage_files,
            )

    def test_unbound_toolchain_identity_is_rejected(self) -> None:
        stage_files = self.valid_stage_files()
        manifest_path = stage_files[
            integrity.PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME
        ]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["toolchain"]["cargo_sha256"] = "f" * 64
        self.write_json(integrity.PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME, manifest)
        evidence_path = stage_files[integrity.PRODUCTION_V3_ACTIVATION_NAME]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["qualification_manifest_sha256"] = integrity._sha256_file(
            manifest_path
        )
        self.write_json(integrity.PRODUCTION_V3_ACTIVATION_NAME, evidence)
        network_path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network = json.loads(network_path.read_text(encoding="utf-8"))
        network["proof_of_work"]["activation_evidence_sha256"] = (
            integrity._sha256_file(evidence_path)
        )
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network)
        with self.assertRaisesRegex(integrity.IntegrityError, "toolchain identity"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1",
                commit=self.commit,
                stage_files=stage_files,
            )


class ReleaseFinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = GitFixture()
        self.stage = self.fixture.root / "target/release-assets"
        self.stage.mkdir(parents=True)
        self.inventory = self.fixture.root / "packaging/releases/test.inventory"
        self.epoch = 1_700_000_000

    def tearDown(self) -> None:
        self.fixture.close()

    def make_valid_assets(self) -> None:
        (self.stage / "a.bin").write_bytes(b"alpha")
        (self.stage / "b.txt").write_bytes(b"beta\n")

    def test_valid_finalize_and_verify_roundtrip(self) -> None:
        self.make_valid_assets()
        result = integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        verified = integrity.verify_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        self.assertEqual(result, verified)
        buildinfo_bytes = (self.stage / integrity.BUILDINFO_NAME).read_bytes()
        self.assertEqual(buildinfo_bytes[-1:], b"\n")
        self.assertEqual(
            json.loads(buildinfo_bytes.decode("utf-8"))["commit"],
            self.fixture.commit,
        )

    def test_dirty_source_is_rejected(self) -> None:
        self.make_valid_assets()
        self.fixture.write("README.md", "dirty\n")
        with self.assertRaisesRegex(integrity.IntegrityError, "dirty"):
            integrity.finalize_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )

    def test_production_rc_finalization_fails_before_metadata_is_written(self) -> None:
        self.make_valid_assets()
        with self.assertRaisesRegex(integrity.IntegrityError, "missing compiled"):
            integrity.finalize_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="1.0.0-rc1",
                stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )
        self.assertFalse((self.stage / integrity.BUILDINFO_NAME).exists())

    def test_wrong_expected_commit_is_rejected(self) -> None:
        self.make_valid_assets()
        with self.assertRaisesRegex(integrity.IntegrityError, "HEAD is"):
            integrity.finalize_release(
                repo=self.fixture.root,
                expected_commit="0" * 40,
                version="0.1.0-test",
                stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )

    def test_untracked_inventory_is_rejected(self) -> None:
        self.make_valid_assets()
        untracked = self.fixture.root / "target/untracked.inventory"
        untracked.write_text("a.bin\nb.txt\n", encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(integrity.IntegrityError, "tracked regular file"):
            integrity.finalize_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                stage=self.stage,
                inventory=untracked,
                source_date_epoch=self.epoch,
            )

    def test_modified_tracked_inventory_is_rejected_as_dirty(self) -> None:
        self.make_valid_assets()
        self.inventory.write_text("a.bin\n", encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(integrity.IntegrityError, "dirty"):
            integrity.finalize_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )

    def test_unexpected_inventory_entry_is_rejected(self) -> None:
        self.make_valid_assets()
        (self.stage / "unexpected.bin").write_bytes(b"unexpected")
        with self.assertRaisesRegex(integrity.IntegrityError, "unexpected"):
            integrity.finalize_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )

    def test_altered_finalized_asset_is_rejected(self) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        (self.stage / "a.bin").write_bytes(b"tampered")
        with self.assertRaisesRegex(integrity.IntegrityError, "BUILDINFO"):
            integrity.verify_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )


if __name__ == "__main__":
    unittest.main()
