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
