from __future__ import annotations

import base64
import copy
import gzip
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import blake3

SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import release_integrity as integrity


def pe_x86_64_fixture(
    label: bytes, machine: int = 0x8664, characteristics: int = 0x0022
) -> bytes:
    pe_offset = 0x80
    optional_size = 0xF0
    encoded = bytearray(0x400)
    encoded[0:2] = b"MZ"
    struct.pack_into("<I", encoded, 0x3C, pe_offset)
    encoded[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<HH", encoded, pe_offset + 4, machine, 1)
    struct.pack_into("<HH", encoded, pe_offset + 20, optional_size, characteristics)
    optional = pe_offset + 24
    struct.pack_into("<H", encoded, optional, 0x020B)
    struct.pack_into("<I", encoded, optional + 4, 0x200)
    struct.pack_into("<I", encoded, optional + 16, 0x1000)
    struct.pack_into("<I", encoded, optional + 20, 0x1000)
    struct.pack_into("<Q", encoded, optional + 24, 0x140000000)
    struct.pack_into("<II", encoded, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", encoded, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", encoded, optional + 68, 3)
    struct.pack_into("<I", encoded, optional + 108, 16)
    section = optional + optional_size
    encoded[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", encoded, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", encoded, section + 36, 0x60000020)
    encoded[0x200 : 0x200 + len(label)] = label
    return bytes(encoded)


def elf_x86_64_fixture(label: bytes, machine: int = 0x003E) -> bytes:
    encoded = bytearray(64 + 56 + len(label))
    encoded[0:4] = b"\x7fELF"
    encoded[4:7] = bytes((2, 1, 1))
    struct.pack_into("<HHI", encoded, 16, 3, machine, 1)
    struct.pack_into("<Q", encoded, 24, 0x400078)
    struct.pack_into("<Q", encoded, 32, 64)
    struct.pack_into("<HHH", encoded, 52, 64, 56, 1)
    struct.pack_into("<II", encoded, 64, 1, 5)
    struct.pack_into("<QQQQQQ", encoded, 72, 0, 0x400000, 0x400000, len(encoded), len(encoded), 0x1000)
    encoded[120:] = label
    return bytes(encoded)


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
        self.write(
            "Cargo.lock",
            """# fixture lockfile
version = 4

[[package]]
name = "fixture"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"
""",
        )
        package_lock = json.dumps(
            {
                "lockfileVersion": 3,
                "name": "fixture",
                "packages": {
                    "": {"name": "fixture", "version": "0.1.0"},
                    "node_modules/react": {
                        "integrity": "sha512-Zml4dHVyZQ==",
                        "version": "19.0.0",
                    },
                },
                "requires": True,
                "version": "0.1.0",
            },
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        self.write("apps/wallet/package-lock.json", package_lock)
        self.write("apps/pool-dashboard/package-lock.json", package_lock)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git(
            "add",
            "--",
            ".gitignore",
            "Cargo.lock",
            "README.md",
            "apps",
            "gpu",
            "packaging",
            "scripts",
        )
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


class ReleaseSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.stage = self.root / "stage"
        self.stage.mkdir()
        (self.stage / integrity.CHECKSUM_NAME).write_bytes(b"00  artifact.zip\n")
        (self.stage / integrity.CHECKSUM_SIGNATURE_NAME).write_bytes(b"signature")
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text(
            "release@example.invalid ssh-ed25519 AAAAfixture\n", encoding="utf-8"
        )
        self.verifier = self.root / "ssh-keygen"
        self.verifier.write_bytes(b"verifier")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @mock.patch("release_integrity.subprocess.run")
    def test_signature_verification_is_bound_to_policy_and_namespace(self, run) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, b"Good signature\n", b"")
        receipt = integrity.verify_release_signature(
            stage=self.stage,
            allowed_signers=self.allowed,
            signer_identity="release@example.invalid",
            ssh_keygen=self.verifier,
        )
        command = run.call_args.args[0]
        self.assertEqual(command[1:3], ["-Y", "verify"])
        self.assertIn(integrity.RELEASE_SIGNATURE_NAMESPACE, command)
        self.assertEqual(run.call_args.kwargs["input"], b"00  artifact.zip\n")
        self.assertEqual(receipt["signer_identity"], "release@example.invalid")

    @mock.patch("release_integrity.subprocess.run")
    def test_bad_signature_and_identity_fail_closed(self, run) -> None:
        run.return_value = subprocess.CompletedProcess([], 255, b"", b"bad signature")
        with self.assertRaisesRegex(integrity.IntegrityError, "invalid"):
            integrity.verify_release_signature(
                stage=self.stage,
                allowed_signers=self.allowed,
                signer_identity="release@example.invalid",
                ssh_keygen=self.verifier,
            )
        with self.assertRaisesRegex(integrity.IntegrityError, "identity"):
            integrity.verify_release_signature(
                stage=self.stage,
                allowed_signers=self.allowed,
                signer_identity="bad identity",
                ssh_keygen=self.verifier,
            )

    def test_ephemeral_openssh_signature_round_trip(self) -> None:
        executable = shutil.which("ssh-keygen")
        if executable is None:
            self.skipTest("OpenSSH ssh-keygen is unavailable")
        signature = self.stage / integrity.CHECKSUM_SIGNATURE_NAME
        signature.unlink()
        key = self.root / "release-key"
        subprocess.run(
            [
                executable,
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "release@example.invalid",
                "-f",
                str(key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                executable,
                "-Y",
                "sign",
                "-f",
                str(key),
                "-n",
                integrity.RELEASE_SIGNATURE_NAMESPACE,
                str(self.stage / integrity.CHECKSUM_NAME),
            ],
            check=True,
            capture_output=True,
        )
        public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        self.allowed.write_text(
            f"release@example.invalid {public_key}\n", encoding="utf-8"
        )
        receipt = integrity.verify_release_signature(
            stage=self.stage,
            allowed_signers=self.allowed,
            signer_identity="release@example.invalid",
            ssh_keygen=Path(executable),
        )
        self.assertEqual(receipt["namespace"], integrity.RELEASE_SIGNATURE_NAMESPACE)
        (self.stage / integrity.CHECKSUM_NAME).write_bytes(b"11  artifact.zip\n")
        with self.assertRaisesRegex(integrity.IntegrityError, "invalid"):
            integrity.verify_release_signature(
                stage=self.stage,
                allowed_signers=self.allowed,
                signer_identity="release@example.invalid",
                ssh_keygen=Path(executable),
            )


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

    def rewrite_first_tar_header(
        self,
        archive: Path,
        *,
        name: bytes | None = None,
        size: int | None = None,
        member_type: bytes | None = None,
    ) -> None:
        payload = bytearray(gzip.decompress(archive.read_bytes()))
        header = bytearray(payload[: integrity.TAR_BLOCK_BYTES])
        if name is not None:
            self.assertLessEqual(len(name), 100)
            header[:100] = name.ljust(100, b"\0")
        if size is not None:
            header[124:136] = tarfile.itn(size, 12, tarfile.GNU_FORMAT)
        if member_type is not None:
            self.assertEqual(len(member_type), 1)
            header[156:157] = member_type
        header[148:156] = b" " * 8
        header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
        payload[: integrity.TAR_BLOCK_BYTES] = header
        with archive.open("wb") as raw, gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=self.epoch
        ) as zipped:
            zipped.write(payload)

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

    def test_zip_rejects_prefix_and_trailer_bytes(self) -> None:
        for kind in ("prefix", "trailer"):
            with self.subTest(kind=kind):
                stage = self.stage(kind, 1, 2)
                archive = self.root / f"{kind}.zip"
                integrity.create_deterministic_zip(stage, archive, self.epoch)
                original = archive.read_bytes()
                archive.write_bytes(
                    b"prefix" + original if kind == "prefix" else original + b"trailer"
                )
                with self.assertRaisesRegex(
                    integrity.IntegrityError, "prefix|trailer|endpoint"
                ):
                    integrity.verify_deterministic_zip(stage, archive, self.epoch)

    def test_tar_rejects_a_trailing_or_concatenated_stream(self) -> None:
        stage = self.stage("tar-trailer", 1, 2)
        archive = self.root / "trailer.tar.gz"
        integrity.create_deterministic_tar_gz(stage, archive, self.epoch)
        archive.write_bytes(archive.read_bytes() + gzip.compress(b"second stream"))
        with self.assertRaisesRegex(
            integrity.IntegrityError, "concatenated|trailer|endpoint"
        ):
            integrity.verify_deterministic_tar_gz(stage, archive, self.epoch)

    def test_tar_rejects_a_noncanonical_gzip_os_byte_before_tarfile(self) -> None:
        stage = self.stage("tar-gzip-os", 1, 2)
        archive = self.root / "gzip-os.tar.gz"
        integrity.create_deterministic_tar_gz(stage, archive, self.epoch)
        encoded = bytearray(archive.read_bytes())
        self.assertEqual(encoded[9], 255)
        encoded[9] = 3
        archive.write_bytes(encoded)
        with (
            mock.patch.object(
                integrity.tarfile,
                "open",
                side_effect=AssertionError(
                    "tarfile.open called before gzip header rejection"
                ),
            ) as tar_open,
            self.assertRaisesRegex(integrity.IntegrityError, "gzip header"),
        ):
            integrity.verify_deterministic_tar_gz(stage, archive, self.epoch)
        tar_open.assert_not_called()

    def test_tar_decompression_is_bounded_by_expected_output(self) -> None:
        archive = self.root / "large-logical-output.tar.gz"
        with (
            archive.open("wb") as raw,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=self.epoch) as zipped,
        ):
            zipped.write(b"\0" * integrity.TAR_RECORD_BYTES)

        decoder = integrity.zlib.decompressobj(16 + integrity.zlib.MAX_WBITS)

        class RecordingDecoder:
            def __init__(self) -> None:
                self.maximum_lengths: list[int] = []

            def decompress(self, data: bytes, maximum_length: int = 0) -> bytes:
                self.maximum_lengths.append(maximum_length)
                return decoder.decompress(data, maximum_length)

            def flush(self, maximum_length: int = integrity.zlib.DEF_BUF_SIZE) -> bytes:
                self.maximum_lengths.append(maximum_length)
                return decoder.flush(maximum_length)

            def __getattr__(self, name: str) -> object:
                return getattr(decoder, name)

        recording = RecordingDecoder()
        with (
            archive.open("rb") as raw,
            mock.patch.object(integrity.zlib, "decompressobj", return_value=recording),
            self.assertRaisesRegex(integrity.IntegrityError, "output|endpoint"),
        ):
            integrity._validate_gzip_tar_framing(
                raw,
                members=[],
                logical_end=16 * 1024 * 1024 * 1024,
                label="bounded tar",
                expected_epoch=self.epoch,
            )
        self.assertTrue(recording.maximum_lengths)
        self.assertNotIn(0, recording.maximum_lengths)
        self.assertLessEqual(
            max(recording.maximum_lengths), integrity.MAX_GZIP_OUTPUT_CHUNK_BYTES
        )

    def test_tar_oversized_first_member_fails_before_seekable_enumeration(self) -> None:
        stage = self.stage("tar-oversized-first", 1, 2)
        archive = self.root / "oversized-first.tar.gz"
        integrity.create_deterministic_tar_gz(stage, archive, self.epoch)
        self.rewrite_first_tar_header(
            archive, size=integrity.MAX_ARCHIVE_MEMBER_BYTES + 1
        )
        real_open = integrity.tarfile.open
        with mock.patch.object(
            integrity.tarfile, "open", wraps=real_open
        ) as recorded, self.assertRaisesRegex(
            integrity.IntegrityError, "numeric field|wrong size"
        ):
            integrity.verify_deterministic_tar_gz(stage, archive, self.epoch)
        recorded.assert_not_called()

    def test_tar_wrong_first_member_fails_before_seekable_enumeration(self) -> None:
        stage = self.stage("tar-wrong-first", 1, 2)
        archive = self.root / "wrong-first.tar.gz"
        integrity.create_deterministic_tar_gz(stage, archive, self.epoch)
        self.rewrite_first_tar_header(archive, name=b"wrong-package")
        real_open = integrity.tarfile.open
        with mock.patch.object(
            integrity.tarfile, "open", wraps=real_open
        ) as recorded, self.assertRaisesRegex(
            integrity.IntegrityError, "missing, reordered, or unexpected"
        ):
            integrity.verify_deterministic_tar_gz(stage, archive, self.epoch)
        recorded.assert_not_called()

    def test_tar_rejects_an_alternate_name_prefix_split_before_tarfile(self) -> None:
        stage = self.stage("tar-name-prefix", 1, 2)
        archive = self.root / "alternate-name-prefix.tar.gz"
        integrity.create_deterministic_tar_gz(stage, archive, self.epoch)
        with tarfile.open(archive, "r:gz") as parsed:
            member = next(
                item for item in parsed if item.name.endswith("/README.txt")
            )
        payload = bytearray(gzip.decompress(archive.read_bytes()))
        header = bytearray(
            payload[member.offset : member.offset + integrity.TAR_BLOCK_BYTES]
        )
        header[:100] = b"README.txt".ljust(100, b"\0")
        header[345:500] = stage.name.encode("ascii").ljust(155, b"\0")
        header[148:156] = b" " * 8
        header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
        payload[member.offset : member.offset + integrity.TAR_BLOCK_BYTES] = header
        with archive.open("wb") as raw, gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=self.epoch
        ) as zipped:
            zipped.write(payload)
        with (
            mock.patch.object(
                integrity.tarfile,
                "open",
                side_effect=AssertionError(
                    "tarfile.open called before name/prefix rejection"
                ),
            ) as tar_open,
            self.assertRaisesRegex(integrity.IntegrityError, "name/prefix split"),
        ):
            integrity.verify_deterministic_tar_gz(stage, archive, self.epoch)
        tar_open.assert_not_called()

    def test_tar_extension_headers_fail_before_payload_or_tarfile(self) -> None:
        for member_type in (
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
        ):
            with self.subTest(member_type=member_type):
                stage = self.stage(f"tar-extension-{member_type.hex()}", 1, 2)
                archive = self.root / f"extension-{member_type.hex()}.tar.gz"
                integrity.create_deterministic_tar_gz(stage, archive, self.epoch)
                self.rewrite_first_tar_header(
                    archive,
                    size=integrity.MAX_ARCHIVE_MEMBER_BYTES + 1,
                    member_type=member_type,
                )
                decoder = integrity.zlib.decompressobj(
                    16 + integrity.zlib.MAX_WBITS
                )

                class RecordingDecoder:
                    def __init__(self) -> None:
                        self.maximum_lengths: list[int] = []

                    def decompress(
                        self, data: bytes, maximum_length: int = 0
                    ) -> bytes:
                        self.maximum_lengths.append(maximum_length)
                        return decoder.decompress(data, maximum_length)

                    def __getattr__(self, name: str) -> object:
                        return getattr(decoder, name)

                recording = RecordingDecoder()
                with (
                    mock.patch.object(
                        integrity.zlib, "decompressobj", return_value=recording
                    ),
                    mock.patch.object(
                        integrity.tarfile,
                        "open",
                        side_effect=AssertionError(
                            "tarfile.open called before extension rejection"
                        ),
                    ) as tar_open,
                    self.assertRaisesRegex(integrity.IntegrityError, "wrong type"),
                ):
                    integrity.verify_deterministic_tar_gz(
                        stage, archive, self.epoch
                    )
                tar_open.assert_not_called()
                self.assertTrue(recording.maximum_lengths)
                self.assertLessEqual(
                    max(recording.maximum_lengths), integrity.TAR_BLOCK_BYTES
                )

    def test_tar_nonzero_file_padding_is_rejected(self) -> None:
        stage = self.stage("tar-padding", 1, 2)
        archive = self.root / "padding.tar.gz"
        integrity.create_deterministic_tar_gz(stage, archive, self.epoch)
        with tarfile.open(archive, "r:gz") as parsed:
            member = next(item for item in parsed if item.name.endswith("README.txt"))
        payload = bytearray(gzip.decompress(archive.read_bytes()))
        payload[member.offset_data + member.size] = 1
        with archive.open("wb") as raw, gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=self.epoch
        ) as zipped:
            zipped.write(payload)
        with self.assertRaisesRegex(integrity.IntegrityError, "nonzero tar padding"):
            integrity.verify_deterministic_tar_gz(stage, archive, self.epoch)

    def test_archive_publication_does_not_replace_a_racing_destination(self) -> None:
        stage = self.stage("publish-race", 1, 2)
        output = self.root / "raced.zip"
        original_link = os.link

        def race(source: object, destination: object, **kwargs: object) -> None:
            Path(destination).write_bytes(b"racer-owned")
            original_link(source, destination, **kwargs)

        with mock.patch.object(os, "link", side_effect=race), self.assertRaisesRegex(
            integrity.IntegrityError, "already exists"
        ):
            integrity.create_deterministic_zip(stage, output, self.epoch)
        self.assertEqual(output.read_bytes(), b"racer-owned")

    def test_staging_inventory_is_bounded_before_archiving(self) -> None:
        stage = self.stage("bounded", 1, 2)
        with mock.patch.object(integrity, "MAX_ARCHIVE_MEMBERS", 2), self.assertRaisesRegex(
            integrity.IntegrityError, "too many members"
        ):
            integrity._archive_entries(stage)

    def test_zip_unknown_extra_field_is_rejected(self) -> None:
        stage = self.stage("zip-extra", 1, 2)
        archive_path = self.root / "extra.zip"
        timestamp = integrity._zip_datetime(self.epoch)
        with zipfile.ZipFile(
            archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for path, name, is_directory in integrity._archive_entries(stage):
                info = zipfile.ZipInfo(name, timestamp)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                mode = 0o755 if is_directory else integrity._canonical_file_mode(path)
                kind = stat.S_IFDIR if is_directory else stat.S_IFREG
                info.external_attr = ((kind | mode) & 0xFFFF) << 16
                if is_directory:
                    info.external_attr |= 0x10
                if name.endswith("README.txt"):
                    info.extra = b"\xfe\xca\x00\x00"
                archive.writestr(info, b"" if is_directory else path.read_bytes())
        with self.assertRaisesRegex(integrity.IntegrityError, "metadata"):
            integrity.verify_deterministic_zip(stage, archive_path, self.epoch)

    def test_zip_directory_content_and_flags_are_rejected(self) -> None:
        stage = self.stage("zip-directory", 1, 2)
        timestamp = integrity._zip_datetime(self.epoch)
        archive_path = self.root / "directory-content.zip"
        with zipfile.ZipFile(
            archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for path, name, is_directory in integrity._archive_entries(stage):
                info = zipfile.ZipInfo(name, timestamp)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                mode = 0o755 if is_directory else integrity._canonical_file_mode(path)
                kind = stat.S_IFDIR if is_directory else stat.S_IFREG
                info.external_attr = ((kind | mode) & 0xFFFF) << 16
                if is_directory:
                    info.external_attr |= 0x10
                content = b"not empty" if name == "commonfoundry-package/" else (
                    b"" if is_directory else path.read_bytes()
                )
                archive.writestr(info, content)
        with self.assertRaisesRegex(integrity.IntegrityError, "directory content"):
            integrity.verify_deterministic_zip(stage, archive_path, self.epoch)

        archive_path = self.root / "flags.zip"
        integrity.create_deterministic_zip(stage, archive_path, self.epoch)
        encoded = bytearray(archive_path.read_bytes())
        local = encoded.find(b"PK\x03\x04")
        central = encoded.find(b"PK\x01\x02")
        struct.pack_into("<H", encoded, local + 6, 0x0008)
        struct.pack_into("<H", encoded, central + 8, 0x0008)
        archive_path.write_bytes(encoded)
        with self.assertRaisesRegex(integrity.IntegrityError, "metadata"):
            integrity.verify_deterministic_zip(stage, archive_path, self.epoch)

    def test_tar_pax_metadata_is_rejected(self) -> None:
        stage = self.stage("tar-pax", 1, 2)
        archive_path = self.root / "pax.tar.gz"
        with (
            archive_path.open("wb") as raw,
            gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=self.epoch
            ) as zipped,
            tarfile.open(
                fileobj=zipped,
                mode="w",
                format=tarfile.PAX_FORMAT,
                pax_headers={"comment": "noncanonical"},
            ) as archive,
        ):
            for path, name, is_directory in integrity._archive_entries(stage):
                member = tarfile.TarInfo(name.rstrip("/") if is_directory else name)
                member.mtime = self.epoch
                member.uid = member.gid = 0
                member.mode = 0o755 if is_directory else integrity._canonical_file_mode(path)
                if is_directory:
                    member.type = tarfile.DIRTYPE
                    archive.addfile(member)
                else:
                    member.type = tarfile.REGTYPE
                    member.size = path.stat().st_size
                    with path.open("rb") as source:
                        archive.addfile(member, source)
        with self.assertRaisesRegex(integrity.IntegrityError, "PAX"):
            integrity.verify_deterministic_tar_gz(stage, archive_path, self.epoch)

    def test_zip64_metadata_is_canonical_for_streamed_large_members(self) -> None:
        stage = self.stage("zip64", 1, 2)
        archive_path = self.root / "zip64.zip"
        original_limit = zipfile.ZIP64_LIMIT
        try:
            zipfile.ZIP64_LIMIT = 8
            integrity.create_deterministic_zip(stage, archive_path, self.epoch)
            with zipfile.ZipFile(archive_path, "r") as archive:
                self.assertTrue(any(member.extra for member in archive.infolist()))
        finally:
            zipfile.ZIP64_LIMIT = original_limit

    def test_small_streamed_zip_members_do_not_carry_zip64_local_extras(self) -> None:
        stage = self.stage("small-zip", 1, 2)
        archive_path = self.root / "small.zip"
        integrity.create_deterministic_zip(stage, archive_path, self.epoch)
        with archive_path.open("rb") as raw, zipfile.ZipFile(raw, "r") as archive:
            for member in archive.infolist():
                raw.seek(member.header_offset + 26)
                name_length, extra_length = struct.unpack("<HH", raw.read(4))
                raw.seek(name_length, os.SEEK_CUR)
                self.assertEqual(extra_length, 0)

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
    MODEL_MANIFEST = {"format_version": 2, "bank_count": 1, "layers_per_bank": 4}
    RECORD_V2 = {
        "record_version": 2,
        "suite_digest": "44" * 32,
        "manifest": MODEL_MANIFEST,
        "manifest_digest": "22" * 32,
        "model_identity": {"identity_version": 1},
        "model_identity_digest": "33" * 32,
        "setup_identity": "55" * 32,
        "padded_variables": 33,
        "commitment_root": "66" * 32,
        "record_digest": "11" * 32,
    }
    RUNTIME_ARTIFACTS = {
        integrity.PRODUCTION_V3_PACKAGE_BANK: b"bounded production model bank fixture",
        integrity.PRODUCTION_V3_PACKAGE_MANIFEST: (
            json.dumps(MODEL_MANIFEST, indent=2) + "\n"
        ).encode("utf-8"),
        integrity.PRODUCTION_V3_PACKAGE_RECORD_V2: (
            json.dumps(RECORD_V2, indent=2) + "\n"
        ).encode("utf-8"),
    }
    WINDOWS_WORKER = pe_x86_64_fixture(b"Windows production proof worker")
    LINUX_WORKER = elf_x86_64_fixture(b"Linux production proof worker")

    @staticmethod
    def runtime_binary(platform: str, role: str) -> bytes:
        label = f"{platform} {role}".encode("ascii")
        if platform == "windows-x86_64":
            return pe_x86_64_fixture(label)
        return elf_x86_64_fixture(label)

    @staticmethod
    def wallet_runtime_identity_bytes(
        network_bytes: bytes, version: str = "1.0.0-rc1"
    ) -> bytes:
        return integrity._canonical_json(
            {
                "network_info_base64": base64.b64encode(network_bytes).decode("ascii"),
                "package_version": version,
                "role": integrity.WALLET_RUNTIME_IDENTITY_ROLE,
                "schema": integrity.WALLET_RUNTIME_IDENTITY_SCHEMA,
            }
        )

    def runtime_command_runner(
        self,
        network_bytes: bytes,
        *,
        version: str = "1.0.0-rc1",
        wallet_network_bytes: bytes | None = None,
        wallet_returncode: int = 0,
        wallet_stderr: bytes = b"",
        wallet_stdout: bytes | None = None,
    ):
        def run(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            if command[-1] == "network-info":
                return subprocess.CompletedProcess(
                    command, 0, stdout=network_bytes, stderr=b""
                )
            if command[-1] == "runtime-identity":
                stdout = (
                    wallet_stdout
                    if wallet_stdout is not None
                    else self.wallet_runtime_identity_bytes(
                        network_bytes
                        if wallet_network_bytes is None
                        else wallet_network_bytes,
                        version,
                    )
                )
                return subprocess.CompletedProcess(
                    command,
                    wallet_returncode,
                    stdout=stdout,
                    stderr=wallet_stderr,
                )
            raise AssertionError(f"unexpected runtime command: {command}")

        return run

    @staticmethod
    def runtime_identity_pin_patch(
        network_info: dict[str, object], candidate: dict[str, object]
    ):
        artifacts = network_info["proof_of_work"]["artifacts"]
        bank = artifacts["bank"]
        fixed_record = artifacts["fixed_record"]
        return mock.patch.multiple(
            integrity,
            PRODUCTION_RC_LAUNCH_ROOT=candidate["launch_root"],
            PRODUCTION_RC_NETWORK_ID=candidate["network_id"],
            PRODUCTION_RC_VIRTUAL_GENESIS_HASH=candidate["virtual_genesis_hash"],
            PRODUCTION_V4_MODEL_BANK_FILE_BYTES=int(bank["bytes"]),
            PRODUCTION_V4_MODEL_BANK_FILE_BLAKE3=bank["blake3"],
            PRODUCTION_V4_MODEL_BANK_FILE_SHA256=bank["sha256"],
            PRODUCTION_V4_FIXED_RECORD_FILE_BYTES=int(fixed_record["bytes"]),
            PRODUCTION_V4_FIXED_RECORD_FILE_BLAKE3=fixed_record["blake3"],
            PRODUCTION_V4_FIXED_RECORD_FILE_SHA256=fixed_record["sha256"],
        )

    def runtime_writer_fixture(
        self, platform: str
    ) -> tuple[dict[str, Path], dict[str, object], dict[str, object]]:
        inputs = self.root / f"writer-inputs-{platform}-{time.time_ns()}"
        inputs.mkdir()
        suffix = ".exe" if platform == "windows-x86_64" else ""
        node = inputs / f"node-input{suffix}"
        wallet = inputs / f"wallet-input{suffix}"
        node.write_bytes(self.runtime_binary(platform, "node"))
        wallet.write_bytes(self.runtime_binary(platform, "wallet"))
        bank = inputs / "bank-input.bin"
        bank.write_bytes(b"bounded ProductionV4 model bank fixture")
        fixed_record = inputs / "fixed-record-input.json"
        fixed_record.write_bytes(
            (
                SCRIPT_DIRECTORY.parent
                / "packaging/production-v4-pool/shared"
                / integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD
            ).read_bytes()
        )
        artifacts = {
            "bank": {
                "bytes": str(bank.stat().st_size),
                "blake3": integrity._blake3_bytes(bank.read_bytes()),
                "sha256": integrity._sha256_file(bank),
            },
            "fixed_record": {
                "bytes": str(fixed_record.stat().st_size),
                "blake3": integrity._blake3_bytes(fixed_record.read_bytes()),
                "sha256": integrity._sha256_file(fixed_record),
            },
        }
        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["virtual_genesis_timestamp_unix_seconds"] = int(
            integrity.PRODUCTION_RC_VIRTUAL_GENESIS_TIMESTAMP
        )
        candidate["payload"]["proof_of_work"]["pow_limit"] = (
            integrity.PRODUCTION_RC_POW_LIMIT
        )
        for role in ("bank", "fixed_record"):
            candidate["payload"]["artifacts"][role] = {
                "bytes": int(artifacts[role]["bytes"]),
                "blake3": artifacts[role]["blake3"],
                "sha256": artifacts[role]["sha256"],
            }
        self.refresh_v2_candidate_derivations(candidate)
        network_info["format"] = "commonfoundry-network-info"
        network_info["format_version"] = 1
        network_info["consensus"]["consensus_fingerprint"] = (
            integrity.PRODUCTION_RC_CONSENSUS_FINGERPRINT
        )
        network_info["data_directories"] = {
            "node": "commonfoundry-rcnet1",
            "wallet": "rcnet-1",
        }
        network_info["services"]["bootstrap_peer"] = (
            integrity.PRODUCTION_RC_BOOTSTRAP_PEER
        )
        network_info["network"] = {
            "name": "CommonFoundry RCNet-1",
            "network_id": candidate["network_id"],
            "virtual_genesis_hash": candidate["virtual_genesis_hash"],
            "virtual_genesis_timestamp_unix_seconds": (
                integrity.PRODUCTION_RC_VIRTUAL_GENESIS_TIMESTAMP
            ),
        }
        proof = network_info["proof_of_work"]
        proof.update(
            {
                "profile": "ForgeMatrix-v4 transparent BaseFold",
                "build_source_commit": self.commit,
                "activation_evidence_sha256": integrity._sha256_bytes(
                    b"activation evidence fixture"
                ),
                "pow_limit": integrity.PRODUCTION_RC_POW_LIMIT,
                "proof_system_digest": integrity.PRODUCTION_V4_PROOF_SYSTEM_DIGEST,
                "model_manifest_digest": integrity.PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
                "fixed_artifact_record_digest": (
                    integrity.PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST
                ),
                "artifacts": artifacts,
            }
        )
        return (
            {
                "node": node,
                "wallet": wallet,
                "model_bank": bank,
                "fixed_record": fixed_record,
            },
            network_info,
            candidate,
        )

    def v4_attestation_fixture(
        self,
    ) -> tuple[Path, Path, bytes, dict[str, object], dict[str, object]]:
        inputs, network_info, candidate = self.runtime_writer_fixture(
            "windows-x86_64"
        )
        container = self.root / f"v4-attestation-{time.time_ns()}"
        package = container / "package"
        output_directory = container / "output"
        package.mkdir(parents=True)
        output_directory.mkdir()
        (package / "cmfd-node.exe").write_bytes(inputs["node"].read_bytes())
        (package / "common-foundry-wallet.exe").write_bytes(
            inputs["wallet"].read_bytes()
        )
        network_bytes = (json.dumps(network_info, indent=2) + "\n").encode("utf-8")
        output = output_directory / integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME
        return package, output, network_bytes, network_info, candidate

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

    @staticmethod
    def refresh_v2_candidate_derivations(candidate: dict[str, object]) -> None:
        payload_bytes = json.dumps(
            candidate["payload"], ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        launch_root = blake3.blake3(
            payload_bytes,
            derive_key_context="CMFD/RCNET/LAUNCH-ROOT/V2",
        ).digest()
        candidate["launch_root"] = launch_root.hex()
        candidate["network_id"] = blake3.blake3(
            launch_root,
            derive_key_context="CMFD/RCNET/NETWORK-ID/V2",
        ).hexdigest()
        candidate["virtual_genesis_hash"] = blake3.blake3(
            launch_root,
            derive_key_context="CMFD/RCNET/VIRTUAL-GENESIS/V2",
        ).hexdigest()

    def make_exact_production_v4_candidate(
        self, candidate: dict[str, object]
    ) -> dict[str, object]:
        payload = candidate["payload"]
        artifacts = payload["artifacts"]
        artifacts["bank"] = {
            "bytes": integrity.PRODUCTION_V4_MODEL_BANK_FILE_BYTES,
            "blake3": integrity.PRODUCTION_V4_MODEL_BANK_FILE_BLAKE3,
            "sha256": integrity.PRODUCTION_V4_MODEL_BANK_FILE_SHA256,
        }
        artifacts["fixed_record"] = {
            "bytes": integrity.PRODUCTION_V4_FIXED_RECORD_FILE_BYTES,
            "blake3": integrity.PRODUCTION_V4_FIXED_RECORD_FILE_BLAKE3,
            "sha256": integrity.PRODUCTION_V4_FIXED_RECORD_FILE_SHA256,
        }
        payload["virtual_genesis_timestamp_unix_seconds"] = int(
            integrity.PRODUCTION_RC_VIRTUAL_GENESIS_TIMESTAMP
        )
        payload["proof_of_work"]["pow_limit"] = integrity.PRODUCTION_RC_POW_LIMIT
        payload["reward_destinations"] = {
            "steward_xonly_public_key": (
                "6989a615231a86558b8ebf1f0b0011cf4fb1e0209f68a7b1274f3877e3b16a6b"
            ),
            "community_xonly_public_key": (
                "2d7066df96297c41f8e4bb3be218cefb822ff1e7dc6cc648f47f92a9c0c88ef8"
            ),
        }
        consensus_fields = (
            "network_protocol_version",
            "block_version",
            "transaction_version",
            "wire_version",
            "maximum_future_offset_seconds",
            "target_spacing_seconds",
            "coinbase_maturity_blocks",
            "median_time_window",
            "max_block_transactions",
            "max_transaction_inputs",
            "max_transaction_outputs",
            "max_block_aggregate_inputs",
            "max_block_aggregate_outputs",
            "max_block_signature_checks",
            "max_coinbase_outputs",
            "consensus_signature_bytes",
            "dgw_window",
            "wire_header_bytes",
            "max_transaction_bytes",
            "max_proof_bytes",
            "max_block_bytes",
        )
        proof_fields = (
            "selection",
            "wire_type",
            "algorithm_version",
            "proof_version",
            "banks",
            "layers_per_bank",
            "exact_transparent_proof_bytes",
            "pow_limit",
        )
        monetary_fields = (
            "atoms_per_coin",
            "initial_subsidy_atoms",
            "tail_height",
            "tail_subsidy_atoms",
            "steward_percent",
            "community_percent",
        )
        artifact_fields = (
            "bank",
            "fixed_record",
            "fixed_record_version",
            "proof_system_digest",
            "model_manifest_digest",
            "fixed_artifact_format_digest",
            "fixed_artifact_record_digest",
        )
        canonical_payload = {
            "profile": payload["profile"],
            "artifacts": {field: artifacts[field] for field in artifact_fields},
            "virtual_genesis_timestamp_unix_seconds": payload[
                "virtual_genesis_timestamp_unix_seconds"
            ],
            "consensus": {field: payload["consensus"][field] for field in consensus_fields},
            "proof_of_work": {
                field: payload["proof_of_work"][field] for field in proof_fields
            },
            "monetary_policy": {
                field: payload["monetary_policy"][field] for field in monetary_fields
            },
            "reward_destinations": {
                "steward_xonly_public_key": payload["reward_destinations"][
                    "steward_xonly_public_key"
                ],
                "community_xonly_public_key": payload["reward_destinations"][
                    "community_xonly_public_key"
                ],
            },
        }
        exact = {
            "schema": candidate["schema"],
            "payload": canonical_payload,
            "launch_root": candidate["launch_root"],
            "network_id": candidate["network_id"],
            "virtual_genesis_hash": candidate["virtual_genesis_hash"],
        }
        self.refresh_v2_candidate_derivations(exact)
        self.assertEqual(exact["launch_root"], integrity.PRODUCTION_RC_LAUNCH_ROOT)
        self.assertEqual(exact["network_id"], integrity.PRODUCTION_RC_NETWORK_ID)
        self.assertEqual(
            exact["virtual_genesis_hash"], integrity.PRODUCTION_RC_VIRTUAL_GENESIS_HASH
        )
        return exact

    def valid_v2_candidate_and_network_info(
        self,
    ) -> tuple[dict[str, object], dict[str, object]]:
        bank_bytes = b"ProductionV4 model bank fixture"
        fixed_record_bytes = b"ProductionV4 fixed-artifact record fixture"
        artifact_files = {
            "bank": {
                "bytes": len(bank_bytes),
                "blake3": blake3.blake3(bank_bytes).hexdigest(),
                "sha256": integrity._sha256_bytes(bank_bytes),
            },
            "fixed_record": {
                "bytes": len(fixed_record_bytes),
                "blake3": blake3.blake3(fixed_record_bytes).hexdigest(),
                "sha256": integrity._sha256_bytes(fixed_record_bytes),
            },
        }
        consensus = {
            "network_protocol_version": 2,
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
            "max_proof_bytes": 13 * 1024 * 1024,
            "max_block_bytes": 16 * 1024 * 1024,
        }
        monetary_policy = {
            "atoms_per_coin": 100000000,
            "initial_subsidy_atoms": 50000000000,
            "tail_height": 2628001,
            "tail_subsidy_atoms": 500000000,
            "steward_percent": 25,
            "community_percent": 5,
        }
        rewards = {
            "steward_xonly_public_key": (
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ),
            "community_xonly_public_key": (
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
            ),
        }
        payload = {
            "profile": "CommonFoundry RCNet-1",
            "artifacts": {
                "bank": artifact_files["bank"],
                "fixed_record": artifact_files["fixed_record"],
                "fixed_record_version": 1,
                "proof_system_digest": integrity.PRODUCTION_V4_PROOF_SYSTEM_DIGEST,
                "model_manifest_digest": integrity.PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
                "fixed_artifact_format_digest": (
                    integrity.PRODUCTION_V4_FIXED_ARTIFACT_FORMAT_DIGEST
                ),
                "fixed_artifact_record_digest": (
                    integrity.PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST
                ),
            },
            "virtual_genesis_timestamp_unix_seconds": 1_800_000_000,
            "consensus": consensus,
            "proof_of_work": {
                "selection": "ProductionV4",
                "wire_type": 4,
                "algorithm_version": 4,
                "proof_version": 1,
                "banks": 3,
                "layers_per_bank": 128,
                "exact_transparent_proof_bytes": 12_025_320,
                "pow_limit": "00" + "ff" * 31,
            },
            "monetary_policy": monetary_policy,
            "reward_destinations": rewards,
        }
        candidate: dict[str, object] = {
            "schema": integrity.RCNET_LAUNCH_CANDIDATE_V2_SCHEMA,
            "payload": payload,
            "launch_root": "",
            "network_id": "",
            "virtual_genesis_hash": "",
        }
        self.refresh_v2_candidate_derivations(candidate)
        proof = payload["proof_of_work"]
        artifacts = payload["artifacts"]
        network_info = {
            "network": {
                "name": "CommonFoundry RCNet-1",
                "network_id": candidate["network_id"],
                "virtual_genesis_hash": candidate["virtual_genesis_hash"],
                "virtual_genesis_timestamp_unix_seconds": "1800000000",
            },
            "proof_of_work": {
                "selection": proof["selection"],
                "wire_type": proof["wire_type"],
                "algorithm_version": proof["algorithm_version"],
                "proof_version": proof["proof_version"],
                "pow_limit": proof["pow_limit"],
                "exact_transparent_proof_bytes": str(
                    proof["exact_transparent_proof_bytes"]
                ),
                "proof_system_digest": artifacts["proof_system_digest"],
                "model_manifest_digest": artifacts["model_manifest_digest"],
                "fixed_artifact_record_digest": artifacts[
                    "fixed_artifact_record_digest"
                ],
                "artifacts": {
                    name: {
                        "bytes": str(identity["bytes"]),
                        "blake3": identity["blake3"],
                        "sha256": identity["sha256"],
                    }
                    for name, identity in artifact_files.items()
                },
            },
            "services": {
                "rpc_port": 19443,
                "p2p_port": 19444,
                "pool_port": 19445,
                "bootstrap_peer": "192.0.2.1:19444",
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
        }
        return candidate, network_info

    def write_runtime_package(
        self,
        *,
        platform: str,
        worker: bytes | None,
        runtime_artifacts: dict[str, bytes],
        runtime_binaries: dict[str, bytes] | None = None,
        selection: str = "ProductionV3",
    ) -> Path:
        container = self.root / f"runtime-{platform}-{time.time_ns()}"
        stage = container / integrity._runtime_package_root(platform)
        stage.mkdir(parents=True)
        executable_suffix = ".exe" if platform == "windows-x86_64" else ""
        for name in (
            f"cmfd-node{executable_suffix}",
            f"common-foundry-wallet{executable_suffix}",
        ):
            path = stage / name
            role = "node" if name.startswith("cmfd-node") else "wallet"
            path.write_bytes(
                (runtime_binaries or {}).get(
                    role, self.runtime_binary(platform, role)
                )
            )
            path.chmod(0o755)
        if worker is not None:
            worker_path = stage / f"cmfd-proof-worker{executable_suffix}"
            worker_path.write_bytes(worker)
            worker_path.chmod(0o755)
        artifact_directory = stage / integrity._runtime_artifact_directory(selection)
        artifact_directory.mkdir()
        for name, data in runtime_artifacts.items():
            (artifact_directory / name).write_bytes(data)

        if platform == "windows-x86_64":
            package = self.root / integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME
            package.unlink(missing_ok=True)
            integrity.create_deterministic_zip(stage, package, 1_700_000_000)
        else:
            package = self.root / integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME
            package.unlink(missing_ok=True)
            integrity.create_deterministic_tar_gz(stage, package, 1_700_000_000)
        return package

    def refresh_activation_chain(self, stage_files: dict[str, Path]) -> None:
        qualification = stage_files[integrity.PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME]
        evidence_path = stage_files[integrity.PRODUCTION_V3_ACTIVATION_NAME]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["qualification_manifest_sha256"] = integrity._sha256_file(qualification)
        self.write_json(integrity.PRODUCTION_V3_ACTIVATION_NAME, evidence)
        network_path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network = json.loads(network_path.read_text(encoding="utf-8"))
        network["proof_of_work"]["activation_evidence_sha256"] = integrity._sha256_file(
            evidence_path
        )
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network)

    def rewrite_windows_runtime_root(self, package: Path, replacement_root: str) -> None:
        rewritten = self.root / f"rewritten-{time.time_ns()}.zip"
        with (
            zipfile.ZipFile(package, "r") as source,
            zipfile.ZipFile(
                rewritten,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
                strict_timestamps=True,
            ) as destination,
        ):
            members = source.infolist()
            original_root = members[0].filename.rstrip("/")
            for member in members:
                info = copy.copy(member)
                info.filename = replacement_root + member.filename[len(original_root) :]
                if member.is_dir():
                    destination.writestr(info, b"")
                else:
                    with destination.open(info, "w", force_zip64=True) as output:
                        output.write(source.read(member))
        rewritten.replace(package)

    def rewrite_linux_tar_header(
        self, package: Path, member_suffix: str, mutate: object
    ) -> None:
        compressed = package.read_bytes()
        epoch = struct.unpack_from("<I", compressed, 4)[0]
        decoded = bytearray(gzip.decompress(compressed))
        with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
            member = next(item for item in archive if item.name.endswith(member_suffix))
        header = bytearray(decoded[member.offset : member.offset + integrity.TAR_BLOCK_BYTES])
        mutate(header)
        header[148:156] = b"        "
        header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
        decoded[member.offset : member.offset + integrity.TAR_BLOCK_BYTES] = header
        with (
            package.open("wb") as raw,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as zipped,
        ):
            zipped.write(decoded)

    def write_runtime_attestation(
        self,
        *,
        platform: str,
        network_info: dict[str, object],
        worker: bytes | None,
    ) -> Path:
        network_bytes = (
            json.dumps(network_info, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        name = (
            integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME
            if platform == "windows-x86_64"
            else integrity.PRODUCTION_RC_LINUX_ATTESTATION_NAME
        )
        attestation = {
            "schema": (
                integrity.PRODUCTION_RC_RUNTIME_ATTESTATION_SCHEMA
                if worker is not None
                else integrity.PRODUCTION_V4_RUNTIME_ATTESTATION_SCHEMA
            ),
            "platform": platform,
            "source_commit": self.commit,
            "node_sha256": integrity._sha256_bytes(
                self.runtime_binary(platform, "node")
            ),
            "wallet_sha256": integrity._sha256_bytes(
                self.runtime_binary(platform, "wallet")
            ),
            "network_info_sha256": integrity._sha256_bytes(network_bytes),
            "network_info_base64": base64.b64encode(network_bytes).decode("ascii"),
        }
        if worker is not None:
            attestation["worker_sha256"] = integrity._sha256_bytes(worker)
        else:
            wallet_identity = self.wallet_runtime_identity_bytes(
                network_bytes, "production-rc1"
            )
            attestation["wallet_runtime_identity_base64"] = base64.b64encode(
                wallet_identity
            ).decode("ascii")
            attestation["wallet_runtime_identity_sha256"] = integrity._sha256_bytes(
                wallet_identity
            )
        return self.write_json(name, attestation)

    def valid_stage_files(self) -> dict[str, Path]:
        launch_root = bytes(range(1, 33)).hex()
        network_id = bytes(range(33, 65)).hex()
        virtual_genesis = bytes(range(65, 97)).hex()
        pow_limit = "00" + "ff" * 31
        steward = bytes(range(97, 129)).hex()
        community = bytes(range(129, 161)).hex()
        runtime_artifacts = self.RUNTIME_ARTIFACTS
        artifact_identities = {
            role: {
                "bytes": str(len(runtime_artifacts[name])),
                "blake3": integrity._blake3_bytes(runtime_artifacts[name]),
                "sha256": integrity._sha256_bytes(runtime_artifacts[name]),
            }
            for role, name in (
                ("bank", integrity.PRODUCTION_V3_PACKAGE_BANK),
                ("manifest", integrity.PRODUCTION_V3_PACKAGE_MANIFEST),
                ("record_v2", integrity.PRODUCTION_V3_PACKAGE_RECORD_V2),
            )
        }
        windows_worker = self.WINDOWS_WORKER
        linux_worker = self.LINUX_WORKER
        record = {
            field: self.RECORD_V2[field]
            for field in (
                "record_version",
                "record_digest",
                "manifest_digest",
                "model_identity_digest",
                "suite_digest",
                "setup_identity",
                "padded_variables",
                "commitment_root",
            )
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
            "network_protocol_version": 2,
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
        for role, name in (
            ("bank", integrity.PRODUCTION_V3_PACKAGE_BANK),
            ("record_v2", integrity.PRODUCTION_V3_PACKAGE_RECORD_V2),
        ):
            artifact_rows[role] = {
                "bytes": len(runtime_artifacts[name]),
                "file_name": name,
                "sha256": integrity._sha256_bytes(runtime_artifacts[name]),
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
                "artifacts": artifact_identities,
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
                "runtime_verifier_workers": {
                    "windows_x86_64_sha256": integrity._sha256_bytes(windows_worker),
                    "linux_x86_64_sha256": integrity._sha256_bytes(linux_worker),
                },
                "schema": "CMFD_PRODUCTION_V3_ACTIVATION_V1",
                "source_commit": self.commit,
            },
        )
        network_info_value = {
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
                    "runtime_verifier_worker_sha256": integrity._sha256_bytes(
                        windows_worker
                    ),
                    "runtime_verifier_workers": {
                        "windows_x86_64_sha256": integrity._sha256_bytes(
                            windows_worker
                        ),
                        "linux_x86_64_sha256": integrity._sha256_bytes(linux_worker),
                    },
                    "artifacts": artifact_identities,
                    "model": {
                        "record_version": record["record_version"],
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
            }
        network_info = self.write_json(
            integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network_info_value
        )
        windows_package = self.write_runtime_package(
            platform="windows-x86_64",
            worker=windows_worker,
            runtime_artifacts=runtime_artifacts,
        )
        linux_package = self.write_runtime_package(
            platform="linux-x86_64",
            worker=linux_worker,
            runtime_artifacts=runtime_artifacts,
        )
        windows_attestation = self.write_runtime_attestation(
            platform="windows-x86_64",
            network_info=network_info_value,
            worker=windows_worker,
        )
        linux_network_info = json.loads(json.dumps(network_info_value))
        linux_network_info["proof_of_work"]["runtime_verifier_worker_sha256"] = (
            integrity._sha256_bytes(linux_worker)
        )
        linux_attestation = self.write_runtime_attestation(
            platform="linux-x86_64",
            network_info=linux_network_info,
            worker=linux_worker,
        )
        return {
            integrity.PRODUCTION_RC_NETWORK_INFO_NAME: network_info,
            integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME: launch_candidate,
            integrity.PRODUCTION_V3_ACTIVATION_NAME: evidence,
            integrity.PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME: qualification_manifest,
            integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME: verifier_binary,
            integrity.PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME: verifier_report,
            integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME: windows_package,
            integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME: linux_package,
            integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME: windows_attestation,
            integrity.PRODUCTION_RC_LINUX_ATTESTATION_NAME: linux_attestation,
        }

    def valid_v4_stage_files(self) -> dict[str, Path]:
        def identity(name: str, data: bytes) -> dict[str, object]:
            return {
                "name": name,
                "bytes": len(data),
                "sha256": integrity._sha256_bytes(data),
                "blake3": integrity._blake3_bytes(data),
            }

        fixed_record_bytes = (
            SCRIPT_DIRECTORY.parent
            / "packaging/production-v4-pool/shared"
            / integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD
        ).read_bytes()
        runtime_artifacts = {
            integrity.PRODUCTION_V4_PACKAGE_BANK: b"bounded ProductionV4 model bank fixture",
            integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD: fixed_record_bytes,
        }
        artifact_identities = {
            "bank": {
                "bytes": str(integrity.PRODUCTION_V4_MODEL_BANK_FILE_BYTES),
                "blake3": integrity.PRODUCTION_V4_MODEL_BANK_FILE_BLAKE3,
                "sha256": integrity.PRODUCTION_V4_MODEL_BANK_FILE_SHA256,
            },
            "fixed_record": {
                "bytes": str(integrity.PRODUCTION_V4_FIXED_RECORD_FILE_BYTES),
                "blake3": integrity.PRODUCTION_V4_FIXED_RECORD_FILE_BLAKE3,
                "sha256": integrity.PRODUCTION_V4_FIXED_RECORD_FILE_SHA256,
            },
        }
        candidate, network_info_value = self.valid_v2_candidate_and_network_info()
        candidate = self.make_exact_production_v4_candidate(candidate)
        network_info_value["network"]["network_id"] = candidate["network_id"]
        network_info_value["network"]["virtual_genesis_hash"] = candidate[
            "virtual_genesis_hash"
        ]
        network_info_value["network"]["virtual_genesis_timestamp_unix_seconds"] = str(
            candidate["payload"]["virtual_genesis_timestamp_unix_seconds"]
        )
        network_info_value["reward_destinations"] = candidate["payload"][
            "reward_destinations"
        ]
        proof = network_info_value["proof_of_work"]
        proof["profile"] = "ForgeMatrix-v4 transparent BaseFold"
        proof["build_source_commit"] = self.commit
        proof["activation_evidence_sha256"] = ""
        proof["artifacts"] = artifact_identities
        proof["pow_limit"] = candidate["payload"]["proof_of_work"]["pow_limit"]
        launch_candidate = self.write_json(
            integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, candidate
        )

        verifier_bytes = b"fresh-process ProductionV4 verifier fixture"
        verifier_script = self.root / integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME
        verifier_script.write_bytes(verifier_bytes)
        proof_sha256 = "7" * 64
        specification_rows = []
        for path, sha256 in integrity.PRODUCTION_V4_FROZEN_SPEC_SHA256.items():
            marker = path.encode("utf-8")
            specification_rows.append(
                {
                    "name": Path(path).name,
                    "path": path,
                    "bytes": len(marker),
                    "sha256": sha256,
                    "blake3": integrity._blake3_bytes(marker),
                }
            )
        qualification_artifacts = [
            *(identity(name, data) for name, data in runtime_artifacts.items()),
            *(
                identity(
                    f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}",
                    f"bank {bank} {suffix} fixture".encode(),
                )
                for bank in range(3)
                for suffix in ("json", "codeword", "row-major.codeword", "tree")
            ),
        ]
        qualification_rows = {row["name"]: row for row in qualification_artifacts}
        for role, name in (
            ("bank", integrity.PRODUCTION_V4_PACKAGE_BANK),
            ("fixed_record", integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD),
        ):
            qualification_rows[name].update(
                {
                    "bytes": int(artifact_identities[role]["bytes"]),
                    "sha256": artifact_identities[role]["sha256"],
                    "blake3": artifact_identities[role]["blake3"],
                }
            )
        statement_derived = {
            "challenge_digest": "12" * 32,
            "final_activation_digest": "34" * 32,
            "work_digest": "00" * 31 + "01",
            "transcript_statement_digest": "56" * 32,
        }
        qualification_statement = {
            "schema": "CommonFoundry/ForgeMatrix/V4/IndependentVerifierInput/v1",
            "block": {
                "network_id": candidate["network_id"],
                "previous_block": "78" * 32,
                "transaction_root": "9a" * 32,
                "height": 1,
                "timestamp": int(integrity.PRODUCTION_RC_VIRTUAL_GENESIS_TIMESTAMP) + 60,
                "target": integrity.PRODUCTION_RC_POW_LIMIT,
            },
            "candidate": {
                "algorithm_version": 4,
                "proof_version": 1,
                "nonce": 7,
                "proof_system_digest": integrity.PRODUCTION_V4_PROOF_SYSTEM_DIGEST,
                "model_manifest_digest": integrity.PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
                "challenge_digest": statement_derived["challenge_digest"],
                "final_activation_digest": statement_derived["final_activation_digest"],
                "work_digest": statement_derived["work_digest"],
            },
        }
        qualification_manifest = self.write_json(
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME,
            {
                "schema": "CommonFoundry/ForgeMatrix/V4/IndependentReproductionReport/v1",
                "status": "verified",
                "reproduction_complete": True,
                "fresh_generation_attested": True,
                "operator": "independent reproducer",
                "reproducer_source_commit": "9" * 40,
                "artifact_generation_source_commit": "8" * 40,
                "environment": {
                    "system": "fixture-os",
                    "release": "fixture-release",
                    "machine": "x86_64",
                    "python": "3.fixture",
                    "byteorder": "little",
                },
                "toolchains": {
                    "python": "python fixture",
                    "git": "git fixture",
                    "rustc": "rustc fixture",
                    "cargo": "cargo fixture",
                    "nvcc": "nvcc fixture",
                },
                "generation_commands": ["generate fixture artifacts"],
                "frozen_specifications": specification_rows,
                "core_vector": {
                    "schema": "CommonFoundry/ForgeMatrix/V4/CoreCanonicalVector/v1",
                    "derived": {
                        "challenge_digest": "523a47eb90c07299243a1aa8fa7ca07a67b0527dfbd6b367bb14a3ea8dbb6a23",
                        "final_activation_digest": "c9802d97d27707d05cf38db9286866c4fbd40a5a5a76809cb654b4d3f221844b",
                        "work_digest": "e9c3ec2fd53ab08340e58a642733a6d528e476ce19a9247e0983d6f71ee2606a",
                        "transcript_statement_digest": "9c3e50fa124dbb2df551ec893c44d1a9813b6245d0f981e1a4e10884e4bd0387",
                    },
                    "rejections_verified": 5,
                },
                "input_manifest": identity(
                    integrity.PRODUCTION_V4_RCNET_INPUT_MANIFEST_NAME,
                    b"input manifest fixture",
                ),
                "artifacts": qualification_artifacts,
                "proof_verification": {
                    "implemented_stages_accepted": True,
                    "full_cryptographic_proof_verified": True,
                    "candidate_claims_verified": False,
                    "proof": {
                        "schema": "CommonFoundry/ForgeMatrix/V4/WireConformanceResult/v1",
                        "bytes": 12_025_320,
                        "sha256": proof_sha256,
                        "canonical": True,
                    },
                    "derived": statement_derived,
                    "target": integrity.PRODUCTION_RC_POW_LIMIT,
                    "target_met": True,
                },
                "statement": qualification_statement,
            },
        )
        mutation_names = (
            "truncated",
            "trailing-byte",
            "noncanonical-field",
            "final-activation",
            "relation-round",
            "fixed-merkle-path",
            "fri-query",
            "grinding-witness",
        )
        verifier_report = self.write_json(
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME,
            {
                "schema": "CommonFoundry/ForgeMatrix/V4/IndependentVerifierQualification/v1",
                "status": "verified",
                "source_commit": "9" * 40,
                "operator": "independent verifier",
                "fresh_process_verifier": True,
                "verifier_files": [
                    identity(
                        name,
                        verifier_bytes
                        if name == "production-v4-independent-verifier.py"
                        else f"{name} fixture".encode(),
                    )
                    for name in (
                        "production-v4-verify-qualification.py",
                        "production-v4-independent-verifier.py",
                        "production_v4_independent_verifier.py",
                        "production_v4_transcript.py",
                        "production_v4_poseidon.py",
                        "production_v4_wire.py",
                    )
                ],
                "known_valid_proof": {
                    "name": "known-valid.proof",
                    "bytes": 12_025_320,
                    "sha256": proof_sha256,
                    "blake3": "6" * 64,
                },
                "statement_derivation": {
                    "command": ["python", "verify", "--derive-statement"],
                    "result": {
                        "schema": "CommonFoundry/ForgeMatrix/V4/IndependentVerificationResult/v1",
                        "implemented_stages_accepted": True,
                        "full_cryptographic_proof_verified": False,
                        "candidate_claims_verified": False,
                        "proof": {
                            "bytes": 12_025_320,
                            "sha256": proof_sha256,
                        },
                        "derived": statement_derived,
                        "target": integrity.PRODUCTION_RC_POW_LIMIT,
                        "target_met": True,
                    },
                },
                "known_valid_result": {
                    "command": ["python", "verify", "known-valid.proof"],
                    "result": {
                        "schema": "CommonFoundry/ForgeMatrix/V4/IndependentVerificationResult/v1",
                        "implemented_stages_accepted": True,
                        "full_cryptographic_proof_verified": True,
                        "candidate_claims_verified": True,
                        "proof": {
                            "bytes": 12_025_320,
                            "sha256": proof_sha256,
                        },
                        "derived": statement_derived,
                        "target": integrity.PRODUCTION_RC_POW_LIMIT,
                        "target_met": True,
                    },
                },
                "mutation_rejections": [
                    {
                        "mutation": mutation,
                        "proof": {
                            **identity(
                                f"proof-{mutation}.bin",
                                f"{mutation} fixture".encode(),
                            ),
                            "bytes": (
                                12_025_319
                                if mutation == "truncated"
                                else 12_025_321
                                if mutation == "trailing-byte"
                                else 12_025_320
                            ),
                        },
                        "error": "rejected fixture mutation",
                        "command": ["python", "verify", f"proof-{mutation}.bin"],
                    }
                    for mutation in mutation_names
                ],
            },
        )
        evidence = self.write_json(
            integrity.PRODUCTION_V4_ACTIVATION_NAME,
            {
                "artifacts": artifact_identities,
                "core_spec_sha256": integrity.PRODUCTION_V4_CORE_SPEC_SHA256,
                "core_vector_sha256": integrity.PRODUCTION_V4_CORE_VECTOR_SHA256,
                "fresh_process_verifier_binary_sha256": integrity._sha256_file(
                    verifier_script
                ),
                "fresh_process_verifier_report_sha256": integrity._sha256_file(
                    verifier_report
                ),
                "network_profile": "RCNet-1",
                "proof_algebra_sha256": integrity.PRODUCTION_V4_PROOF_ALGEBRA_SHA256,
                "proof_selection": "ProductionV4",
                "qualification_manifest_sha256": integrity._sha256_file(
                    qualification_manifest
                ),
                "qualification_source_commit": "9" * 40,
                "schema": "CMFD_PRODUCTION_V4_ACTIVATION_V1",
                "source_commit": self.commit,
            },
        )
        proof["activation_evidence_sha256"] = integrity._sha256_file(evidence)
        network_info = self.write_json(
            integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network_info_value
        )
        windows_package = self.write_runtime_package(
            platform="windows-x86_64",
            worker=None,
            runtime_artifacts=runtime_artifacts,
            selection="ProductionV4",
        )
        linux_package = self.write_runtime_package(
            platform="linux-x86_64",
            worker=None,
            runtime_artifacts=runtime_artifacts,
            selection="ProductionV4",
        )
        windows_attestation = self.write_runtime_attestation(
            platform="windows-x86_64", network_info=network_info_value, worker=None
        )
        linux_attestation = self.write_runtime_attestation(
            platform="linux-x86_64", network_info=network_info_value, worker=None
        )
        return {
            integrity.PRODUCTION_RC_NETWORK_INFO_NAME: network_info,
            integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME: launch_candidate,
            integrity.PRODUCTION_V4_ACTIVATION_NAME: evidence,
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME: qualification_manifest,
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME: verifier_script,
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME: verifier_report,
            integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME: windows_package,
            integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME: linux_package,
            integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME: windows_attestation,
            integrity.PRODUCTION_RC_LINUX_ATTESTATION_NAME: linux_attestation,
        }

    def activation_writer_fixture(
        self,
    ) -> tuple[dict[str, Path], GitFixture]:
        stage_files = self.valid_v4_stage_files()
        candidate_path = stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME]
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        candidate_path.write_bytes(
            integrity._canonical_rcnet_v2_candidate(
                candidate, integrity._validate_production_v4_rcnet_candidate(candidate)
            )
        )
        repository = GitFixture()
        for name in integrity.PRODUCTION_V4_VERIFIER_FILE_NAMES:
            repository.write(f"scripts/{name}", (SCRIPT_DIRECTORY / name).read_bytes())
        for relative in integrity.PRODUCTION_V4_FROZEN_SPEC_SHA256:
            repository.write(relative, (SCRIPT_DIRECTORY.parent / relative).read_bytes())
        repository.write(integrity.PRODUCTION_V4_ACTIVATION_PIN_RELATIVE, "None\n")
        repository.git(
            "add",
            "--",
            "crates",
            "docs",
            "scripts",
        )
        repository.git("commit", "--quiet", "-m", "activation inputs")
        self.addCleanup(repository.close)

        def identity(name: str, data: bytes) -> dict[str, object]:
            return {
                "name": name,
                "bytes": len(data),
                "sha256": integrity._sha256_bytes(data),
                "blake3": integrity._blake3_bytes(data),
            }

        verifier_path = stage_files[
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME
        ]
        verifier_path.write_bytes(
            (SCRIPT_DIRECTORY / "production-v4-independent-verifier.py").read_bytes()
        )
        qualification_path = stage_files[
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
        ]
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        qualification["reproducer_source_commit"] = repository.commit
        qualification["artifact_generation_source_commit"] = repository.commit
        for row in qualification["frozen_specifications"]:
            data = (SCRIPT_DIRECTORY.parent / row["path"]).read_bytes()
            row.update(identity(row["name"], data))

        artifact_rows = {row["name"]: row for row in qualification["artifacts"]}
        input_files = [
            {
                "name": name,
                "bytes": artifact_rows[name]["bytes"],
                "sha256": artifact_rows[name]["sha256"],
            }
            for name in integrity.PRODUCTION_V4_RCNET_INPUT_NAMES
        ]
        input_manifest = {
            "schema_version": 1,
            "network": integrity.PRODUCTION_V4_RCNET_NETWORK_NAME,
            "network_id": integrity.PRODUCTION_RC_NETWORK_ID,
            "source_commit": repository.commit,
            "total_bytes": sum(row["bytes"] for row in input_files),
            "files": input_files,
        }
        input_manifest_path = self.root / integrity.PRODUCTION_V4_RCNET_INPUT_MANIFEST_NAME
        input_manifest_path.write_bytes(integrity._canonical_json(input_manifest))
        qualification["input_manifest"] = identity(
            input_manifest_path.name, input_manifest_path.read_bytes()
        )
        qualification_path.write_bytes(integrity._canonical_json(qualification))

        report_path = stage_files[
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
        ]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["source_commit"] = repository.commit
        report["verifier_files"] = [
            identity(name, (SCRIPT_DIRECTORY / name).read_bytes())
            for name in integrity.PRODUCTION_V4_VERIFIER_FILE_NAMES
        ]
        report_path.write_bytes(integrity._canonical_json(report))

        activation_inputs = Path(
            tempfile.mkdtemp(prefix="activation-inputs-", dir=self.root)
        )
        artifact_directory = activation_inputs / "fixed-artifacts"
        artifact_directory.mkdir()
        for bank in range(3):
            for suffix in ("json", "codeword", "row-major.codeword", "tree"):
                name = f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}"
                (artifact_directory / name).write_bytes(
                    f"bank {bank} {suffix} fixture".encode()
                )
        model_bank = activation_inputs / integrity.PRODUCTION_V4_PACKAGE_BANK
        model_bank.write_bytes(b"placeholder model bank")
        fixed_record = activation_inputs / integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD
        fixed_record.write_bytes(
            (
                SCRIPT_DIRECTORY.parent
                / "packaging/production-v4-pool/shared"
                / integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD
            ).read_bytes()
        )
        proof_path = activation_inputs / str(report["known_valid_proof"]["name"])
        proof_path.write_bytes(b"placeholder proof")
        template_path = activation_inputs / "template.json"
        template_path.write_bytes(integrity._canonical_json({"fixture": True}))
        stage_files.update(
            {
                "__activation_artifact_directory": artifact_directory,
                "__activation_fixed_record": fixed_record,
                "__activation_input_manifest": input_manifest_path,
                "__activation_model_bank": model_bank,
                "__activation_proof": proof_path,
                "__activation_template": template_path,
            }
        )
        return stage_files, repository

    def write_activation_phase(
        self,
        *,
        phase: str,
        stage_files: dict[str, Path],
        repository: GitFixture,
        output: Path,
        expected_commit: str | None = None,
    ) -> dict[str, object]:
        with (
            mock.patch.object(
                integrity, "_validate_production_v4_activation_artifacts"
            ),
            mock.patch.object(integrity, "_replay_production_v4_verifier"),
        ):
            return integrity.create_production_v4_activation(
                phase=phase,
                repo=repository.root,
                expected_commit=expected_commit or repository.commit,
                candidate=stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME],
                input_manifest=stage_files["__activation_input_manifest"],
                qualification_manifest=stage_files[
                    integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
                ],
                verifier_report=stage_files[
                    integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
                ],
                verifier_script=stage_files[
                    integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME
                ],
                template=stage_files["__activation_template"],
                proof=stage_files["__activation_proof"],
                model_bank=stage_files["__activation_model_bank"],
                fixed_record=stage_files["__activation_fixed_record"],
                artifact_directory=stage_files["__activation_artifact_directory"],
                output=output,
            )

    def test_production_v4_activation_pin_is_blocked_without_signed_approvals(
        self,
    ) -> None:
        stage_files, repository = self.activation_writer_fixture()
        pin_output = self.root / "reviewed-production-v4-pin.inc.rs"
        with self.assertRaisesRegex(integrity.IntegrityError, "signed producer"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=pin_output,
            )
        self.assertFalse(pin_output.exists())
        self.assertEqual(
            (repository.root / integrity.PRODUCTION_V4_ACTIVATION_PIN_RELATIVE).read_bytes(),
            b"None\n",
        )

    def test_production_v4_activation_pin_requires_real_role_signatures(self) -> None:
        ssh_keygen_value = shutil.which("ssh-keygen")
        if ssh_keygen_value is None:
            self.skipTest("OpenSSH ssh-keygen is unavailable")
        ssh_keygen = Path(ssh_keygen_value)
        stage_files, repository = self.activation_writer_fixture()
        producer_key = self.root / "producer-approval-key"
        reproducer_key = self.root / "reproducer-approval-key"
        for key in (producer_key, reproducer_key):
            subprocess.run(
                [
                    str(ssh_keygen),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(key),
                ],
                check=True,
                capture_output=True,
            )
        producer_identity = "producer@example.test"
        reproducer_identity = "reproducer@example.test"

        def policy_for(key: Path, identity: str, role: str) -> Path:
            public_fields = key.with_suffix(".pub").read_text(encoding="ascii").split()
            policy = self.root / f"{role}.allowed_signers"
            policy.write_text(
                f'{identity} namespaces="{integrity.activation_approval.NAMESPACES[role]}" '
                f"{public_fields[0]} {public_fields[1]}\n",
                encoding="ascii",
                newline="\n",
            )
            return policy

        producer_policy = policy_for(
            producer_key, producer_identity, integrity.activation_approval.PRODUCER_ROLE
        )
        reproducer_policy = policy_for(
            reproducer_key,
            reproducer_identity,
            integrity.activation_approval.REPRODUCER_ROLE,
        )
        verifier_sha256 = integrity._sha256_file(ssh_keygen)
        request_directory = self.root / "activation-approval-request"
        request_directory.mkdir()
        common = {
            "phase": "pin",
            "repo": repository.root,
            "expected_commit": repository.commit,
            "candidate": stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME],
            "input_manifest": stage_files["__activation_input_manifest"],
            "qualification_manifest": stage_files[
                integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
            ],
            "verifier_report": stage_files[
                integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
            ],
            "verifier_script": stage_files[
                integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME
            ],
            "template": stage_files["__activation_template"],
            "proof": stage_files["__activation_proof"],
            "model_bank": stage_files["__activation_model_bank"],
            "fixed_record": stage_files["__activation_fixed_record"],
            "artifact_directory": stage_files["__activation_artifact_directory"],
            "producer_allowed_signers": producer_policy,
            "producer_signer_identity": producer_identity,
            "reproducer_allowed_signers": reproducer_policy,
            "reproducer_signer_identity": reproducer_identity,
            "ssh_keygen": ssh_keygen,
            "expected_ssh_keygen_sha256": verifier_sha256,
        }
        with (
            mock.patch.object(
                integrity, "_validate_production_v4_activation_artifacts"
            ),
            mock.patch.object(integrity, "_replay_production_v4_verifier"),
        ):
            request = integrity.create_production_v4_activation_approval_request(
                output_directory=request_directory, **common
            )
        producer_approval = (
            request_directory
            / "PRODUCTION-V4-ACTIVATION-PIN-PRODUCER-APPROVAL.json"
        )
        reproducer_approval = (
            request_directory
            / "PRODUCTION-V4-ACTIVATION-PIN-REPRODUCER-APPROVAL.json"
        )
        review_target = request_directory / "PRODUCTION-V4-ACTIVATION-PIN-TARGET.review"
        self.assertEqual(request["phase"], "pin")
        self.assertTrue(producer_approval.is_file())
        self.assertTrue(reproducer_approval.is_file())
        self.assertTrue(review_target.is_file())
        self.assertEqual(
            (repository.root / integrity.PRODUCTION_V4_ACTIVATION_PIN_RELATIVE).read_bytes(),
            b"None\n",
        )
        for role, key, approval in (
            (integrity.activation_approval.PRODUCER_ROLE, producer_key, producer_approval),
            (
                integrity.activation_approval.REPRODUCER_ROLE,
                reproducer_key,
                reproducer_approval,
            ),
        ):
            subprocess.run(
                [
                    str(ssh_keygen),
                    "-Y",
                    "sign",
                    "-f",
                    str(key),
                    "-n",
                    integrity.activation_approval.NAMESPACES[role],
                    str(approval),
                ],
                check=True,
                capture_output=True,
            )
        pin_output = self.root / "reviewed-production-v4-pin.inc.rs"
        with (
            mock.patch.object(
                integrity, "_validate_production_v4_activation_artifacts"
            ),
            mock.patch.object(integrity, "_replay_production_v4_verifier"),
        ):
            result = integrity.create_production_v4_activation(
                output=pin_output,
                producer_approval=producer_approval,
                producer_signature=producer_approval.with_suffix(".json.sig"),
                reproducer_approval=reproducer_approval,
                reproducer_signature=reproducer_approval.with_suffix(".json.sig"),
                **common,
            )
        self.assertEqual(pin_output.read_bytes(), review_target.read_bytes())
        self.assertEqual(result["approval_receipt"]["phase"], "pin")

        repository.write(
            integrity.PRODUCTION_V4_ACTIVATION_PIN_RELATIVE,
            pin_output.read_bytes(),
        )
        repository.git(
            "add", "--", integrity.PRODUCTION_V4_ACTIVATION_PIN_RELATIVE
        )
        repository.git("commit", "--quiet", "-m", "activate reviewed ProductionV4 pin")
        evidence_commit = repository.commit
        evidence_common = {
            **common,
            "phase": "evidence",
            "expected_commit": evidence_commit,
        }
        with (
            mock.patch.object(
                integrity, "_validate_production_v4_activation_artifacts"
            ),
            mock.patch.object(integrity, "_replay_production_v4_verifier"),
        ):
            validated = integrity._validate_production_v4_activation_inputs(
                repo=repository.root,
                candidate_path=evidence_common["candidate"],
                input_manifest_path=evidence_common["input_manifest"],
                qualification_manifest_path=evidence_common["qualification_manifest"],
                verifier_report_path=evidence_common["verifier_report"],
                verifier_script_path=evidence_common["verifier_script"],
                template_path=evidence_common["template"],
                proof_path=evidence_common["proof"],
                model_bank_path=evidence_common["model_bank"],
                fixed_record_path=evidence_common["fixed_record"],
                artifact_directory=evidence_common["artifact_directory"],
            )
        evidence_trust = integrity._production_v4_approval_trust(
            common_files=validated["approval_files"],
            producer_allowed_signers=producer_policy,
            producer_signer_identity=producer_identity,
            reproducer_allowed_signers=reproducer_policy,
            reproducer_signer_identity=reproducer_identity,
            expected_ssh_keygen_sha256=verifier_sha256,
        )
        evidence_pin_fields = integrity._production_v4_pin_fields_with_trust(
            validated["pin_fields"], evidence_trust
        )
        self.assertEqual(
            integrity._render_production_v4_activation_pin(evidence_pin_fields),
            pin_output.read_bytes(),
        )
        _, intended_evidence = integrity._production_v4_activation_evidence(
            validated=validated,
            pin_fields=evidence_pin_fields,
            commit=evidence_commit,
        )
        network_info_path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network_info = json.loads(network_info_path.read_text(encoding="utf-8"))
        network_info.update(
            {
                "format": "commonfoundry-network-info",
                "format_version": 1,
                "data_directories": {
                    "node": "commonfoundry-rcnet1",
                    "wallet": "rcnet-1",
                },
            }
        )
        network_info["services"] = {
            **integrity.PRODUCTION_RC_SERVICE_PORTS,
            "bootstrap_peer": integrity.PRODUCTION_RC_BOOTSTRAP_PEER,
        }
        network_info["consensus"]["consensus_fingerprint"] = (
            integrity.PRODUCTION_RC_CONSENSUS_FINGERPRINT
        )
        network_info["proof_of_work"]["build_source_commit"] = evidence_commit
        network_info["proof_of_work"]["activation_evidence_sha256"] = (
            integrity._sha256_bytes(intended_evidence)
        )
        network_info_path.write_text(
            json.dumps(network_info, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        evidence_common["network_info"] = network_info_path
        evidence_request_directory = self.root / "activation-evidence-request"
        evidence_request_directory.mkdir()
        with (
            mock.patch.object(
                integrity, "_validate_production_v4_activation_artifacts"
            ),
            mock.patch.object(integrity, "_replay_production_v4_verifier"),
        ):
            evidence_request = (
                integrity.create_production_v4_activation_approval_request(
                    output_directory=evidence_request_directory,
                    **evidence_common,
                )
            )
        producer_evidence_approval = (
            evidence_request_directory
            / "PRODUCTION-V4-ACTIVATION-EVIDENCE-PRODUCER-APPROVAL.json"
        )
        reproducer_evidence_approval = (
            evidence_request_directory
            / "PRODUCTION-V4-ACTIVATION-EVIDENCE-REPRODUCER-APPROVAL.json"
        )
        for role, key, approval in (
            (
                integrity.activation_approval.PRODUCER_ROLE,
                producer_key,
                producer_evidence_approval,
            ),
            (
                integrity.activation_approval.REPRODUCER_ROLE,
                reproducer_key,
                reproducer_evidence_approval,
            ),
        ):
            subprocess.run(
                [
                    str(ssh_keygen),
                    "-Y",
                    "sign",
                    "-f",
                    str(key),
                    "-n",
                    integrity.activation_approval.NAMESPACES[role],
                    str(approval),
                ],
                check=True,
                capture_output=True,
            )
        evidence_output_directory = self.root / "activation-evidence-output"
        evidence_output_directory.mkdir()
        evidence_output = (
            evidence_output_directory / integrity.PRODUCTION_V4_ACTIVATION_NAME
        )
        with (
            mock.patch.object(
                integrity, "_validate_production_v4_activation_artifacts"
            ),
            mock.patch.object(integrity, "_replay_production_v4_verifier"),
        ):
            evidence_result = integrity.create_production_v4_activation(
                output=evidence_output,
                producer_approval=producer_evidence_approval,
                producer_signature=producer_evidence_approval.with_suffix(".json.sig"),
                reproducer_approval=reproducer_evidence_approval,
                reproducer_signature=reproducer_evidence_approval.with_suffix(
                    ".json.sig"
                ),
                **evidence_common,
            )
        self.assertEqual(evidence_output.read_bytes(), intended_evidence)
        self.assertEqual(evidence_result["approval_receipt"]["phase"], "evidence")
        self.assertEqual(evidence_request["phase"], "evidence")

        final_stage_files = {
            name: path
            for name, path in stage_files.items()
            if not name.startswith("__")
        }
        final_stage_files[integrity.PRODUCTION_V4_ACTIVATION_NAME] = evidence_output
        final_stage_files[integrity.PRODUCTION_V4_PRODUCER_APPROVAL_NAME] = (
            producer_evidence_approval
        )
        final_stage_files[
            integrity.PRODUCTION_V4_PRODUCER_APPROVAL_SIGNATURE_NAME
        ] = producer_evidence_approval.with_suffix(".json.sig")
        final_stage_files[integrity.PRODUCTION_V4_PRODUCER_ALLOWED_SIGNERS_NAME] = (
            producer_policy
        )
        final_stage_files[integrity.PRODUCTION_V4_REPRODUCER_APPROVAL_NAME] = (
            reproducer_evidence_approval
        )
        final_stage_files[
            integrity.PRODUCTION_V4_REPRODUCER_APPROVAL_SIGNATURE_NAME
        ] = reproducer_evidence_approval.with_suffix(".json.sig")
        final_stage_files[integrity.PRODUCTION_V4_REPRODUCER_ALLOWED_SIGNERS_NAME] = (
            reproducer_policy
        )
        with mock.patch.object(integrity, "validate_production_rc_runtime_packages"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1",
                commit=evidence_commit,
                stage_files=final_stage_files,
                repo=repository.root,
                activation_ssh_keygen=ssh_keygen,
                activation_ssh_keygen_sha256=verifier_sha256,
            )
        with (
            mock.patch.object(integrity, "validate_production_rc_runtime_packages"),
            mock.patch.object(
                integrity,
                "_tracked_blob",
                return_value=b"None\n",
            ),
            self.assertRaisesRegex(
                integrity.IntegrityError, "tracked ProductionV4 activation pin"
            ),
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1",
                commit=evidence_commit,
                stage_files=final_stage_files,
                repo=repository.root,
                activation_ssh_keygen=ssh_keygen,
                activation_ssh_keygen_sha256=verifier_sha256,
            )
        final_stage_files[integrity.PRODUCTION_V4_PRODUCER_APPROVAL_NAME] = (
            producer_approval
        )
        with (
            mock.patch.object(integrity, "validate_production_rc_runtime_packages"),
            self.assertRaisesRegex(integrity.IntegrityError, "not for evidence phase"),
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1",
                commit=evidence_commit,
                stage_files=final_stage_files,
                repo=repository.root,
                activation_ssh_keygen=ssh_keygen,
                activation_ssh_keygen_sha256=verifier_sha256,
            )

    def test_production_v4_approval_request_final_sweep_detects_earlier_mutation(
        self,
    ) -> None:
        repository = self.root / "approval-request-repo"
        repository.mkdir()
        output_directory = self.root / "approval-request-race"
        output_directory.mkdir()
        verifier = self.root / "approval-request-verifier"
        verifier.write_bytes(b"trusted verifier fixture")
        verifier_sha256 = integrity._sha256_file(verifier)
        commit = "1" * 40
        producer_trust = {"signer_identity": "producer@example.test"}
        reproducer_trust = {"signer_identity": "reproducer@example.test"}
        trust = {
            "producer": producer_trust,
            "independent_reproducer": reproducer_trust,
        }
        prepared = {
            "authorities": {
                integrity.activation_approval.PRODUCER_ROLE: producer_trust,
                integrity.activation_approval.REPRODUCER_ROLE: reproducer_trust,
            },
            "payloads": {
                integrity.activation_approval.PRODUCER_ROLE: b"producer payload\n",
                integrity.activation_approval.REPRODUCER_ROLE: b"reproducer payload\n",
            },
        }
        real_write = integrity._write_new_verified
        first_path: Path | None = None
        calls = 0

        def mutate_after_last_write(**kwargs):
            nonlocal calls, first_path
            identity = real_write(**kwargs)
            calls += 1
            if first_path is None:
                first_path = kwargs["path"]
            if calls == 3:
                original_stat = first_path.stat()
                original = first_path.read_bytes()
                first_path.write_bytes(b"x" * len(original))
                os.utime(
                    first_path,
                    ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                )
            return identity

        with (
            mock.patch.object(
                integrity, "_assert_clean_exact_repo", return_value=commit
            ),
            mock.patch.object(
                integrity,
                "_validate_production_v4_activation_inputs",
                return_value={
                    "approval_files": {},
                    "generation_commit": commit,
                    "pin_fields": {},
                    "qualification_commit": commit,
                },
            ),
            mock.patch.object(
                integrity, "_production_v4_approval_trust", return_value=trust
            ),
            mock.patch.object(
                integrity, "_render_production_v4_activation_pin", return_value=b"pin\n"
            ),
            mock.patch.object(integrity, "_validate_production_v4_activation_history"),
            mock.patch.object(
                integrity,
                "_production_v4_approval_subject",
                return_value={"phase": "pin"},
            ),
            mock.patch.object(
                integrity.activation_approval,
                "prepare_approval_payloads",
                return_value=prepared,
            ),
            mock.patch.object(
                integrity, "_write_new_verified", side_effect=mutate_after_last_write
            ),
            self.assertRaisesRegex(integrity.IntegrityError, "output changed"),
        ):
            integrity.create_production_v4_activation_approval_request(
                phase="pin",
                repo=repository,
                expected_commit=commit,
                candidate=self.root / "candidate",
                input_manifest=self.root / "input-manifest",
                qualification_manifest=self.root / "qualification-manifest",
                verifier_report=self.root / "verifier-report",
                verifier_script=self.root / "verifier-script",
                template=self.root / "template",
                proof=self.root / "proof",
                model_bank=self.root / "model-bank",
                fixed_record=self.root / "fixed-record",
                artifact_directory=self.root / "artifact-directory",
                output_directory=output_directory,
                producer_allowed_signers=self.root / "producer-policy",
                producer_signer_identity="producer@example.test",
                reproducer_allowed_signers=self.root / "reproducer-policy",
                reproducer_signer_identity="reproducer@example.test",
                ssh_keygen=verifier,
                expected_ssh_keygen_sha256=verifier_sha256,
            )
        self.assertEqual(list(output_directory.iterdir()), [])

    def test_production_v4_activation_pin_rendering_omits_final_commit(self) -> None:
        fields = {
            "schema": "CMFD_PRODUCTION_V4_ACTIVATION_V1",
            "qualification_source_commit": "1" * 40,
            "qualification_manifest_sha256": "2" * 64,
            "fresh_process_verifier_binary_sha256": "3" * 64,
            "fresh_process_verifier_report_sha256": "4" * 64,
            "core_spec_sha256": "5" * 64,
            "core_vector_sha256": "6" * 64,
            "proof_algebra_sha256": "7" * 64,
            "approval_trust": {
                "contract_schema": integrity.activation_approval.SUBJECT_SCHEMA,
                "qualification_binding_sha256": "8" * 64,
                "ssh_keygen_sha256": "9" * 64,
                "producer": {
                    "signer_identity": "producer@example.test",
                    "allowed_signers_sha256": "a" * 64,
                    "key_blob_sha256": "b" * 64,
                    "key_fingerprint": "SHA256:"
                    + base64.b64encode(bytes.fromhex("b" * 64))
                    .decode("ascii")
                    .rstrip("="),
                    "key_type": "ssh-ed25519",
                },
                "independent_reproducer": {
                    "signer_identity": "reproducer@example.test",
                    "allowed_signers_sha256": "c" * 64,
                    "key_blob_sha256": "d" * 64,
                    "key_fingerprint": "SHA256:"
                    + base64.b64encode(bytes.fromhex("d" * 64))
                    .decode("ascii")
                    .rstrip("="),
                    "key_type": "ssh-ed25519",
                },
            },
        }
        rendered = integrity._render_production_v4_activation_pin(fields)
        self.assertTrue(rendered.startswith(b"Some(ProductionV4ActivationEvidence {\n"))
        self.assertNotIn(b"\n    source_commit:", rendered)

    def test_production_v4_approval_trust_rejects_malformed_or_shared_values(
        self,
    ) -> None:
        def fingerprint(digest: str) -> str:
            return "SHA256:" + base64.b64encode(bytes.fromhex(digest)).decode(
                "ascii"
            ).rstrip("=")

        valid = {
            "contract_schema": integrity.activation_approval.SUBJECT_SCHEMA,
            "qualification_binding_sha256": "8" * 64,
            "ssh_keygen_sha256": "9" * 64,
            "producer": {
                "signer_identity": "producer@example.test",
                "allowed_signers_sha256": "a" * 64,
                "key_blob_sha256": "b" * 64,
                "key_fingerprint": fingerprint("b" * 64),
                "key_type": "ssh-ed25519",
            },
            "independent_reproducer": {
                "signer_identity": "reproducer@example.test",
                "allowed_signers_sha256": "c" * 64,
                "key_blob_sha256": "d" * 64,
                "key_fingerprint": fingerprint("d" * 64),
                "key_type": "ssh-ed25519",
            },
        }
        mutations: list[tuple[str, object]] = []
        non_string = copy.deepcopy(valid)
        non_string["producer"]["signer_identity"] = 123
        mutations.append(("signer identity", non_string))
        zero_verifier = copy.deepcopy(valid)
        zero_verifier["ssh_keygen_sha256"] = "0" * 64
        mutations.append(("verifier", zero_verifier))
        zero_policy = copy.deepcopy(valid)
        zero_policy["producer"]["allowed_signers_sha256"] = "0" * 64
        mutations.append(("policy", zero_policy))
        wrong_fingerprint = copy.deepcopy(valid)
        wrong_fingerprint["producer"]["key_fingerprint"] = fingerprint("e" * 64)
        mutations.append(("fingerprint", wrong_fingerprint))
        certificate = copy.deepcopy(valid)
        certificate["producer"]["key_type"] = "ssh-ed25519-cert-v01@openssh.com"
        mutations.append(("certificate", certificate))
        dss = copy.deepcopy(valid)
        dss["producer"]["key_type"] = "ssh-dss"
        mutations.append(("DSS", dss))
        for field in (
            "signer_identity",
            "allowed_signers_sha256",
            "key_blob_sha256",
            "key_fingerprint",
        ):
            shared = copy.deepcopy(valid)
            shared["independent_reproducer"][field] = shared["producer"][field]
            mutations.append((f"shared {field}", shared))
        for label, value in mutations:
            with self.subTest(label=label), self.assertRaises(
                integrity.IntegrityError
            ):
                integrity._validate_production_v4_approval_trust_fields(value)

    def test_production_v4_activation_evidence_before_pin_is_rejected(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        evidence_directory = self.root / "activation-evidence-output"
        evidence_directory.mkdir()
        output = evidence_directory / integrity.PRODUCTION_V4_ACTIVATION_NAME
        with self.assertRaisesRegex(integrity.IntegrityError, "pin does not match"):
            self.write_activation_phase(
                phase="evidence",
                stage_files=stage_files,
                repository=repository,
                output=output,
            )
        self.assertFalse(output.exists())

    def test_production_v4_activation_rejects_dirty_or_wrong_commit(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        output = self.root / "reviewed-pin.inc.rs"
        with self.assertRaisesRegex(integrity.IntegrityError, "HEAD is"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=output,
                expected_commit="a" * 40,
            )
        repository.write("untracked-dirty-file", "dirty\n")
        with self.assertRaisesRegex(integrity.IntegrityError, "checkout is dirty"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=output,
            )
        self.assertFalse(output.exists())

    def test_production_v4_activation_refuses_output_collision(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        output = self.root / "reviewed-pin.inc.rs"
        output.write_bytes(b"existing")
        with self.assertRaisesRegex(integrity.IntegrityError, "already exists"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=output,
            )
        self.assertEqual(output.read_bytes(), b"existing")

    def test_production_v4_activation_rejects_verifier_script_drift(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        stage_files[
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME
        ].write_bytes(b"different verifier script")
        with self.assertRaisesRegex(integrity.IntegrityError, "byte-identical"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "reviewed-pin.inc.rs",
            )

    def test_production_v4_activation_rejects_frozen_spec_drift(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        relative = next(iter(integrity.PRODUCTION_V4_FROZEN_SPEC_SHA256))
        repository.write(relative, b"changed frozen specification\n")
        repository.git("add", "--", relative)
        repository.git("commit", "--quiet", "-m", "drift frozen spec")
        with self.assertRaisesRegex(integrity.IntegrityError, "frozen specification"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "reviewed-pin.inc.rs",
            )

    def test_production_v4_activation_rejects_verifier_report_drift(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        report_path = stage_files[
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
        ]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        entrypoint = next(
            row
            for row in report["verifier_files"]
            if row["name"] == "production-v4-independent-verifier.py"
        )
        entrypoint["sha256"] = (
            ("0" if entrypoint["sha256"][0] != "0" else "1")
            + entrypoint["sha256"][1:]
        )
        self.write_json(integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME, report)
        with self.assertRaisesRegex(integrity.IntegrityError, "not bound"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "reviewed-pin.inc.rs",
            )

    def test_production_v4_activation_rejects_noncanonical_inputs(self) -> None:
        for name in (
            integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME,
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME,
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME,
        ):
            with self.subTest(name=name):
                stage_files, repository = self.activation_writer_fixture()
                path = stage_files[name]
                value = json.loads(path.read_text(encoding="utf-8"))
                if name == integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME:
                    path.write_bytes(integrity._canonical_json(value))
                else:
                    path.write_text(
                        json.dumps(value, indent=2) + "\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                with self.assertRaisesRegex(integrity.IntegrityError, "not canonical"):
                    self.write_activation_phase(
                        phase="pin",
                        stage_files=stage_files,
                        repository=repository,
                        output=self.root / f"reviewed-{name}.inc.rs",
                    )

    def test_production_v4_activation_rejects_testnet_manifest_and_statement(
        self,
    ) -> None:
        stage_files, repository = self.activation_writer_fixture()
        manifest_path = stage_files["__activation_input_manifest"]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["network"] = "CommonFoundry ProductionV4 Testnet-1"
        manifest["network_id"] = (
            "b9e55d5a5e80c8e3d73bf81b199bc643ac9367436962c28b6aacdc37f3809962"
        )
        manifest_path.write_bytes(integrity._canonical_json(manifest))
        qualification_path = stage_files[
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
        ]
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        manifest_bytes = manifest_path.read_bytes()
        qualification["input_manifest"] = {
            "name": manifest_path.name,
            "bytes": len(manifest_bytes),
            "sha256": integrity._sha256_bytes(manifest_bytes),
            "blake3": integrity._blake3_bytes(manifest_bytes),
        }
        qualification_path.write_bytes(integrity._canonical_json(qualification))
        with self.assertRaisesRegex(integrity.IntegrityError, "not bound to the RCNet"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "testnet-manifest-pin.inc.rs",
            )

        stage_files, repository = self.activation_writer_fixture()
        canonical_path = stage_files["__activation_input_manifest"]
        testnet_path = canonical_path.with_name("production-v4-testnet-1-inputs.json")
        testnet_path.write_bytes(canonical_path.read_bytes())
        stage_files["__activation_input_manifest"] = testnet_path
        qualification_path = stage_files[
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
        ]
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        qualification["input_manifest"]["name"] = testnet_path.name
        qualification_path.write_bytes(integrity._canonical_json(qualification))
        with self.assertRaisesRegex(integrity.IntegrityError, "input manifest"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "testnet-name-pin.inc.rs",
            )

        stage_files, repository = self.activation_writer_fixture()
        qualification_path = stage_files[
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
        ]
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        qualification["statement"]["block"]["network_id"] = (
            "b9e55d5a5e80c8e3d73bf81b199bc643ac9367436962c28b6aacdc37f3809962"
        )
        qualification_path.write_bytes(integrity._canonical_json(qualification))
        with self.assertRaisesRegex(integrity.IntegrityError, "RCNet candidate"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "testnet-statement-pin.inc.rs",
            )

    def test_production_v4_activation_rejects_manifest_identity_drift(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        qualification_path = stage_files[
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
        ]
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        qualification["input_manifest"]["sha256"] = "ab" * 32
        qualification_path.write_bytes(integrity._canonical_json(qualification))
        with self.assertRaisesRegex(integrity.IntegrityError, "does not match qualification"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "manifest-drift-pin.inc.rs",
            )

    def test_production_v4_activation_requires_canonical_rcnet_manifest(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        manifest_path = stage_files["__activation_input_manifest"]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        qualification_path = stage_files[
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
        ]
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        manifest_bytes = manifest_path.read_bytes()
        qualification["input_manifest"].update(
            {
                "bytes": len(manifest_bytes),
                "sha256": integrity._sha256_bytes(manifest_bytes),
                "blake3": integrity._blake3_bytes(manifest_bytes),
            }
        )
        qualification_path.write_bytes(integrity._canonical_json(qualification))
        with self.assertRaisesRegex(integrity.IntegrityError, "not canonical"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "noncanonical-manifest-pin.inc.rs",
            )

    def test_production_v4_activation_rejects_derived_report_drift(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        report_path = stage_files[
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
        ]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["statement_derivation"]["result"]["derived"]["challenge_digest"] = (
            "ab" * 32
        )
        report_path.write_bytes(integrity._canonical_json(report))
        with self.assertRaisesRegex(integrity.IntegrityError, "qualification statement"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "derived-drift-pin.inc.rs",
            )

    def test_production_v4_activation_requires_resolvable_source_commits(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        qualification_path = stage_files[
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
        ]
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        qualification["reproducer_source_commit"] = "9" * 40
        qualification_path.write_bytes(integrity._canonical_json(qualification))
        report_path = stage_files[
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
        ]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["source_commit"] = "9" * 40
        report_path.write_bytes(integrity._canonical_json(report))
        with self.assertRaisesRegex(integrity.IntegrityError, "does not resolve"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "unresolved-commit-pin.inc.rs",
            )

    def test_production_v4_activation_requires_related_source_commits(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        sibling = repository.git(
            "commit-tree", "HEAD^{tree}", "-p", "HEAD~1", "-m", "sibling qualification"
        )
        qualification_path = stage_files[
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
        ]
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        qualification["reproducer_source_commit"] = sibling
        qualification_path.write_bytes(integrity._canonical_json(qualification))
        report_path = stage_files[
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
        ]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["source_commit"] = sibling
        report_path.write_bytes(integrity._canonical_json(report))
        with self.assertRaisesRegex(integrity.IntegrityError, "required Git ancestry"):
            self.write_activation_phase(
                phase="pin",
                stage_files=stage_files,
                repository=repository,
                output=self.root / "unrelated-commit-pin.inc.rs",
            )

    def test_production_v4_activation_reopens_artifact_bytes(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        with (
            mock.patch.object(integrity, "_replay_production_v4_verifier"),
            self.assertRaisesRegex(integrity.IntegrityError, "MODEL-V2.bank"),
        ):
            integrity._validate_production_v4_activation_inputs(
                repo=repository.root,
                candidate_path=stage_files[
                    integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME
                ],
                input_manifest_path=stage_files["__activation_input_manifest"],
                qualification_manifest_path=stage_files[
                    integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
                ],
                verifier_report_path=stage_files[
                    integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
                ],
                verifier_script_path=stage_files[
                    integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME
                ],
                template_path=stage_files["__activation_template"],
                proof_path=stage_files["__activation_proof"],
                model_bank_path=stage_files["__activation_model_bank"],
                fixed_record_path=stage_files["__activation_fixed_record"],
                artifact_directory=stage_files["__activation_artifact_directory"],
            )

    def test_production_v4_evidence_rejects_unrelated_pin_commit_changes(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        pin_bytes = b"Some(ProductionV4ActivationEvidence { /* fixture */ })\n"
        repository.write(integrity.PRODUCTION_V4_ACTIVATION_PIN_RELATIVE, pin_bytes)
        repository.write("crates/cmfd-node/src/unrelated.rs", "// unrelated\n")
        repository.git("add", "--", "crates")
        repository.git("commit", "--quiet", "-m", "pin plus unrelated source")
        evidence_directory = self.root / "unrelated-pin-evidence"
        evidence_directory.mkdir()
        with (
            mock.patch.object(
                integrity, "_render_production_v4_activation_pin", return_value=pin_bytes
            ),
            self.assertRaisesRegex(integrity.IntegrityError, "change only"),
        ):
            self.write_activation_phase(
                phase="evidence",
                stage_files=stage_files,
                repository=repository,
                output=evidence_directory / integrity.PRODUCTION_V4_ACTIVATION_NAME,
            )

    def test_production_v4_pin_only_transition_reaches_approval_boundary(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        pin_bytes = b"Some(ProductionV4ActivationEvidence { /* fixture */ })\n"
        repository.write(integrity.PRODUCTION_V4_ACTIVATION_PIN_RELATIVE, pin_bytes)
        repository.git("add", "--", integrity.PRODUCTION_V4_ACTIVATION_PIN_RELATIVE)
        repository.git("commit", "--quiet", "-m", "pin reviewed ProductionV4 evidence")
        evidence_directory = self.root / "pin-only-evidence"
        evidence_directory.mkdir()
        output = evidence_directory / integrity.PRODUCTION_V4_ACTIVATION_NAME
        with (
            mock.patch.object(
                integrity, "_render_production_v4_activation_pin", return_value=pin_bytes
            ),
            self.assertRaisesRegex(integrity.IntegrityError, "signed producer"),
        ):
            self.write_activation_phase(
                phase="evidence",
                stage_files=stage_files,
                repository=repository,
                output=output,
            )
        self.assertFalse(output.exists())

    def test_production_v4_activation_replay_rejects_fresh_result_drift(self) -> None:
        stage_files, repository = self.activation_writer_fixture()
        qualification = json.loads(
            stage_files[integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME].read_text(
                encoding="utf-8"
            )
        )
        report = json.loads(
            stage_files[
                integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
            ].read_text(encoding="utf-8")
        )

        def replay_result(_: Path, arguments: list[str]) -> dict[str, object]:
            if "--write-statement" in arguments:
                statement_path = Path(arguments[arguments.index("--write-statement") + 1])
                statement_path.write_bytes(
                    integrity._canonical_json(qualification["statement"])
                )
                return copy.deepcopy(report["statement_derivation"]["result"])
            result = copy.deepcopy(report["known_valid_result"]["result"])
            result["derived"]["work_digest"] = "ab" * 32
            return result

        with (
            mock.patch.object(
                integrity, "_run_production_v4_verifier", side_effect=replay_result
            ) as verifier,
            self.assertRaisesRegex(integrity.IntegrityError, "does not reproduce"),
        ):
            integrity._replay_production_v4_verifier(
                repo=repository.root,
                template=stage_files["__activation_template"],
                proof=stage_files["__activation_proof"],
                fixed_record=stage_files["__activation_fixed_record"],
                model_bank=stage_files["__activation_model_bank"],
                qualification_manifest=qualification,
                verifier_report=report,
                qualification_statement=qualification["statement"],
            )
        self.assertEqual(verifier.call_count, 2)

    def test_self_consistent_nonlaunch_v4_candidate_is_not_authority(self) -> None:
        candidate, _ = self.valid_v2_candidate_and_network_info()
        integrity._validate_rcnet_launch_candidate_v2(candidate)
        with self.assertRaisesRegex(integrity.IntegrityError, "immutable launch_root"):
            integrity._validate_production_v4_rcnet_candidate(candidate)

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

    def test_production_rc_rejects_source_like_release_assets(self) -> None:
        stage_files = self.valid_stage_files()
        source = self.root / "CommonFoundry-1.0.0-rc1-source.zip"
        source.write_bytes(b"source")
        stage_files[source.name] = source
        with self.assertRaisesRegex(integrity.IntegrityError, "source-like asset"):
            integrity.validate_production_rc_artifacts(
                version="1.0.0-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_production_rc_rejects_arbitrary_python_source_assets(self) -> None:
        for name in (
            "helper.py",
            "PRODUCTION-V4-FRESH-PROCESS-VERIFIER-copy.py",
        ):
            with self.subTest(name=name):
                stage_files = self.valid_v4_stage_files()
                source = self.root / name
                source.write_bytes(b"print('not audited')\n")
                stage_files[name] = source
                with self.assertRaisesRegex(
                    integrity.IntegrityError, "source-like asset"
                ):
                    integrity.validate_production_rc_artifacts(
                        version="1.0.0-rc1",
                        commit=self.commit,
                        stage_files=stage_files,
                    )

    def test_production_v4_verifier_evidence_uses_exact_script_name(self) -> None:
        self.assertEqual(
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME,
            "PRODUCTION-V4-FRESH-PROCESS-VERIFIER.py",
        )
        stage_files = self.valid_v4_stage_files()
        self.assertIn(
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME,
            stage_files,
        )
        with (
            mock.patch.object(integrity, "validate_production_rc_runtime_packages"),
            self.assertRaisesRegex(integrity.IntegrityError, "signed producer"),
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_production_v4_verifier_script_must_match_qualified_entrypoint(self) -> None:
        stage_files = self.valid_v4_stage_files()
        stage_files[
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME
        ].write_bytes(b"tampered verifier script\n")
        with self.assertRaisesRegex(
            integrity.IntegrityError, "verifier script is not bound"
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_production_v3_does_not_allow_the_v4_verifier_script(self) -> None:
        stage_files = self.valid_stage_files()
        script = self.root / integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME
        script.write_bytes(b"print('wrong proof selection')\n")
        stage_files[script.name] = script
        with self.assertRaisesRegex(integrity.IntegrityError, "source-like asset"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_production_rc_allows_generated_source_sbom(self) -> None:
        stage_files = self.valid_stage_files()
        sbom = self.root / integrity.SOURCE_SBOM_NAME
        sbom.write_bytes(b"{}\n")
        stage_files[sbom.name] = sbom
        integrity.validate_production_rc_artifacts(
            version="1.0.0-rc1", commit=self.commit, stage_files=stage_files
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

    def test_production_v4_exact_stage_stays_closed_without_signed_approvals(
        self,
    ) -> None:
        stage_files = self.valid_v4_stage_files()
        with (
            mock.patch.object(integrity, "validate_production_rc_runtime_packages"),
            self.assertRaisesRegex(integrity.IntegrityError, "signed producer"),
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_production_v4_runtime_rejects_packaged_proof_worker(self) -> None:
        stage_files = self.valid_v4_stage_files()
        runtime_artifacts = {
            integrity.PRODUCTION_V4_PACKAGE_BANK: b"bounded ProductionV4 model bank fixture",
            integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD: next(
                path
                for name, path in integrity._inspect_runtime_package_archive(
                    stage_files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME],
                    "windows-x86_64",
                    selection="ProductionV4",
                ).items()
                if name.endswith(integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD)
            )["captured"],
        }
        stage_files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME] = (
            self.write_runtime_package(
                platform="windows-x86_64",
                worker=self.WINDOWS_WORKER,
                runtime_artifacts=runtime_artifacts,
                selection="ProductionV4",
            )
        )
        with self.assertRaises(integrity.IntegrityError):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_production_v4_runtime_artifact_mutation_is_rejected(self) -> None:
        stage_files = self.valid_v4_stage_files()
        network_info = json.loads(
            stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME].read_text(
                encoding="utf-8"
            )
        )
        original_rows = integrity._inspect_runtime_package_archive(
            stage_files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME],
            "windows-x86_64",
            selection="ProductionV4",
        )
        fixed_record = original_rows[
            "production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
        ]["captured"]
        bank = bytearray(b"bounded ProductionV4 model bank fixture")
        bank[-1] ^= 1
        replacement = self.write_runtime_package(
            platform="windows-x86_64",
            worker=None,
            runtime_artifacts={
                integrity.PRODUCTION_V4_PACKAGE_BANK: bytes(bank),
                integrity.PRODUCTION_V4_PACKAGE_FIXED_RECORD: fixed_record,
            },
            selection="ProductionV4",
        )
        with self.assertRaisesRegex(integrity.IntegrityError, "model bank"):
            integrity._validate_runtime_package(
                path=replacement,
                platform="windows-x86_64",
                staged_network_info=network_info,
            )

    def test_production_v4_activation_must_be_canonical_and_bound(self) -> None:
        stage_files = self.valid_v4_stage_files()
        evidence_path = stage_files[integrity.PRODUCTION_V4_ACTIVATION_NAME]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence_path.write_text(
            json.dumps(evidence, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        with self.assertRaisesRegex(integrity.IntegrityError, "not canonical"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

        stage_files = self.valid_v4_stage_files()
        network_path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network_info = json.loads(network_path.read_text(encoding="utf-8"))
        network_info["proof_of_work"]["activation_evidence_sha256"] = "a" * 64
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network_info)
        with self.assertRaisesRegex(integrity.IntegrityError, "not bound"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_production_v4_missing_qualification_evidence_fails_closed(self) -> None:
        stage_files = self.valid_v4_stage_files()
        del stage_files[integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME]
        with self.assertRaisesRegex(integrity.IntegrityError, "missing required ProductionV4"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_production_v4_qualification_spec_hashes_are_frozen(self) -> None:
        stage_files = self.valid_v4_stage_files()
        qualification_path = stage_files[
            integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME
        ]
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        qualification["frozen_specifications"][0]["sha256"] = "a" * 64
        self.write_json(integrity.PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME, qualification)
        with self.assertRaisesRegex(integrity.IntegrityError, "do not match the release"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_production_v4_mutation_proof_shape_is_frozen(self) -> None:
        stage_files = self.valid_v4_stage_files()
        report_path = stage_files[
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME
        ]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["mutation_rejections"][0]["proof"]["bytes"] = 1
        self.write_json(
            integrity.PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME, report
        )
        with self.assertRaisesRegex(integrity.IntegrityError, "mutation proof identity"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_every_required_qualification_artifact_has_a_bounded_identity(self) -> None:
        cases = (("request", "sha256", "not-a-digest"), ("journal", "bytes", 0))
        for role, field, replacement in cases:
            with self.subTest(role=role, field=field):
                stage_files = self.valid_stage_files()
                path = stage_files[integrity.PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME]
                manifest = json.loads(path.read_text(encoding="utf-8"))
                manifest["artifacts"][role][field] = replacement
                self.write_json(integrity.PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME, manifest)
                self.refresh_activation_chain(stage_files)
                with self.assertRaisesRegex(
                    integrity.IntegrityError, f"invalid {role} binding"
                ):
                    integrity.validate_production_rc_artifacts(
                        version="production-rc1",
                        commit=self.commit,
                        stage_files=stage_files,
                    )

    def test_runtime_executables_must_match_the_platform_architecture(self) -> None:
        cases = (
            (
                "windows-x86_64",
                "node",
                pe_x86_64_fixture(b"wrong Windows architecture", machine=0x014C),
                "x86-64 PE",
            ),
            (
                "linux-x86_64",
                "wallet",
                elf_x86_64_fixture(b"wrong Linux architecture", machine=0x00B7),
                "x86-64 ELF",
            ),
            (
                "windows-x86_64",
                "wallet",
                pe_x86_64_fixture(
                    b"DLL masquerading as a wallet", characteristics=0x2022
                ),
                "DLL",
            ),
            (
                "windows-x86_64",
                "node",
                pe_x86_64_fixture(b"truncated optional header")[:0x98],
                r"PE32\+ executable header",
            ),
        )
        for platform, role, binary, message in cases:
            with self.subTest(platform=platform, role=role):
                stage_files = self.valid_stage_files()
                package = self.write_runtime_package(
                    platform=platform,
                    worker=(
                        self.WINDOWS_WORKER
                        if platform == "windows-x86_64"
                        else self.LINUX_WORKER
                    ),
                    runtime_artifacts=self.RUNTIME_ARTIFACTS,
                    runtime_binaries={role: binary},
                )
                name = (
                    integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME
                    if platform == "windows-x86_64"
                    else integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME
                )
                stage_files[name] = package
                with self.assertRaisesRegex(integrity.IntegrityError, message):
                    integrity.validate_production_rc_artifacts(
                        version="production-rc1",
                        commit=self.commit,
                        stage_files=stage_files,
                    )

    def test_runtime_archive_trailer_and_extra_member_are_rejected(self) -> None:
        stage_files = self.valid_stage_files()
        windows = stage_files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME]
        windows.write_bytes(windows.read_bytes() + b"trailer")
        with self.assertRaisesRegex(integrity.IntegrityError, "trailer|endpoint"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

        stage_files = self.valid_stage_files()
        windows = stage_files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME]
        with zipfile.ZipFile(windows, "a") as archive:
            archive.writestr("unexpected-source.rs", b"source")
        with self.assertRaisesRegex(integrity.IntegrityError, "too many|unexpected"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_runtime_zip_limits_are_checked_before_zipfile_materialization(self) -> None:
        stage_files = self.valid_stage_files()
        package = stage_files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME]
        encoded = bytearray(package.read_bytes())
        endpoint = len(encoded) - 22
        struct.pack_into("<HH", encoded, endpoint + 8, 9, 9)
        package.write_bytes(encoded)
        with (
            mock.patch.object(
                integrity.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZipFile opened before entry bound"),
            ),
            self.assertRaisesRegex(integrity.IntegrityError, "too many entries"),
        ):
            integrity._inspect_runtime_package_archive(package, "windows-x86_64")

        stage_files = self.valid_stage_files()
        package = stage_files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME]
        with (
            mock.patch.object(
                integrity, "MAX_RUNTIME_ZIP_CENTRAL_DIRECTORY_BYTES", 1
            ),
            mock.patch.object(
                integrity.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZipFile opened before directory bound"),
            ),
            self.assertRaisesRegex(integrity.IntegrityError, "central directory"),
        ):
            integrity._inspect_runtime_package_archive(package, "windows-x86_64")

    def test_runtime_root_name_is_exact_and_windows_safe(self) -> None:
        for invalid_root in ("CON", "runtime.", "runtime ", "bad\x01root"):
            with self.subTest(root=repr(invalid_root)):
                stage_files = self.valid_stage_files()
                package = stage_files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME]
                self.rewrite_windows_runtime_root(package, invalid_root)
                with self.assertRaisesRegex(
                    integrity.IntegrityError, "root directory|unsafe member"
                ):
                    integrity.validate_production_rc_artifacts(
                        version="production-rc1",
                        commit=self.commit,
                        stage_files=stage_files,
                    )

    def test_runtime_tar_rejects_oversized_members_before_stream_advance(self) -> None:
        stage_files = self.valid_stage_files()
        package = stage_files[integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME]

        def oversize(header: bytearray) -> None:
            header[124:136] = f"{integrity.MAX_RUNTIME_BINARY_BYTES + 1:011o}\0".encode(
                "ascii"
            )

        self.rewrite_linux_tar_header(package, "/cmfd-node", oversize)
        with (
            mock.patch.object(
                integrity.tarfile,
                "open",
                side_effect=AssertionError(
                    "tarfile.open called before oversized binary rejection"
                ),
            ) as tar_open,
            self.assertRaisesRegex(integrity.IntegrityError, "size limit"),
        ):
            integrity._inspect_runtime_package_archive(package, "linux-x86_64")
        tar_open.assert_not_called()

    def test_runtime_tar_rejects_contiguous_file_type(self) -> None:
        stage_files = self.valid_stage_files()
        package = stage_files[integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME]

        def contiguous(header: bytearray) -> None:
            header[156:157] = tarfile.CONTTYPE

        self.rewrite_linux_tar_header(package, "/cmfd-node", contiguous)
        with self.assertRaisesRegex(integrity.IntegrityError, "type"):
            integrity._inspect_runtime_package_archive(package, "linux-x86_64")

    def test_runtime_tar_extensions_fail_before_payload_or_tarfile(self) -> None:
        root = integrity.PRODUCTION_RC_RUNTIME_ROOTS["linux-x86_64"]
        for member_type in (
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
        ):
            with self.subTest(member_type=member_type):
                stage_files = self.valid_stage_files()
                package = stage_files[
                    integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME
                ]

                def extension(header: bytearray) -> None:
                    header[124:136] = tarfile.itn(
                        integrity.MAX_ARCHIVE_MEMBER_BYTES + 1,
                        12,
                        tarfile.GNU_FORMAT,
                    )
                    header[156:157] = member_type

                self.rewrite_linux_tar_header(package, root, extension)
                with (
                    mock.patch.object(
                        integrity.tarfile,
                        "open",
                        side_effect=AssertionError(
                            "tarfile.open called before extension rejection"
                        ),
                    ) as tar_open,
                    self.assertRaisesRegex(integrity.IntegrityError, "wrong type"),
                ):
                    integrity._inspect_runtime_package_archive(
                        package, "linux-x86_64"
                    )
                tar_open.assert_not_called()

    def test_runtime_directory_metadata_must_be_canonical(self) -> None:
        stage_files = self.valid_stage_files()
        original = stage_files[integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME]
        rows: list[tuple[tarfile.TarInfo, bytes | None]] = []
        with tarfile.open(original, "r:gz") as source:
            for member in source:
                extracted = source.extractfile(member) if member.isreg() else None
                rows.append((copy.copy(member), extracted.read() if extracted else None))
        replacement = self.root / "noncanonical-runtime.tar.gz"
        with (
            replacement.open("wb") as raw,
            gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=1_700_000_000
            ) as zipped,
            tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive,
        ):
            for member, content in rows:
                if member.isdir() and member.name.endswith("/production-v3"):
                    member.mode = 0o700
                archive.addfile(member, io.BytesIO(content) if content is not None else None)
        stage_files[integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME] = replacement
        with self.assertRaisesRegex(integrity.IntegrityError, "metadata"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_replacement_pins_cannot_bypass_qualification_binding(self) -> None:
        stage_files = self.valid_stage_files()
        network_path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        evidence_path = stage_files[integrity.PRODUCTION_V3_ACTIVATION_NAME]
        network = json.loads(network_path.read_text(encoding="utf-8"))
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        replacement = integrity._sha256_bytes(b"replacement bank")
        network["proof_of_work"]["artifacts"]["bank"]["sha256"] = replacement
        evidence["artifacts"]["bank"]["sha256"] = replacement
        self.write_json(integrity.PRODUCTION_V3_ACTIVATION_NAME, evidence)
        network["proof_of_work"]["activation_evidence_sha256"] = (
            integrity._sha256_file(evidence_path)
        )
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network)
        with self.assertRaisesRegex(integrity.IntegrityError, "qualification evidence"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_packaged_node_attestation_is_required_and_cross_bound(self) -> None:
        stage_files = self.valid_stage_files()
        del stage_files[integrity.PRODUCTION_RC_LINUX_ATTESTATION_NAME]
        with self.assertRaisesRegex(integrity.IntegrityError, "runtime package"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

        stage_files = self.valid_stage_files()
        attestation_path = stage_files[integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME]
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        attestation["node_sha256"] = "ab" * 32
        self.write_json(integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME, attestation)
        with self.assertRaisesRegex(integrity.IntegrityError, "node_sha256"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

        stage_files = self.valid_stage_files()
        attestation_path = stage_files[integrity.PRODUCTION_RC_LINUX_ATTESTATION_NAME]
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        network_bytes = base64.b64decode(attestation["network_info_base64"])
        attested_network = json.loads(network_bytes)
        attested_network["services"]["p2p_port"] += 1
        network_bytes = (
            json.dumps(attested_network, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        attestation["network_info_base64"] = base64.b64encode(network_bytes).decode(
            "ascii"
        )
        attestation["network_info_sha256"] = integrity._sha256_bytes(network_bytes)
        self.write_json(integrity.PRODUCTION_RC_LINUX_ATTESTATION_NAME, attestation)
        with self.assertRaisesRegex(integrity.IntegrityError, "staged network identity"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_final_runtime_validation_rechecks_wallet_identity_evidence(self) -> None:
        _, network_info, _ = self.runtime_writer_fixture("windows-x86_64")
        attestation_path = self.write_runtime_attestation(
            platform="windows-x86_64", network_info=network_info, worker=None
        )
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        wallet_identity = json.loads(
            base64.b64decode(attestation["wallet_runtime_identity_base64"])
        )
        wallet_identity["package_version"] = "production-rc2"
        wallet_identity_bytes = integrity._canonical_json(wallet_identity)
        attestation["wallet_runtime_identity_base64"] = base64.b64encode(
            wallet_identity_bytes
        ).decode("ascii")
        attestation["wallet_runtime_identity_sha256"] = integrity._sha256_bytes(
            wallet_identity_bytes
        )
        self.write_json(integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME, attestation)
        with self.assertRaisesRegex(integrity.IntegrityError, "runtime identity is invalid"):
            integrity._validate_runtime_attestation(
                path=attestation_path,
                platform="windows-x86_64",
                commit=self.commit,
                version="production-rc1",
                rows={
                    "cmfd-node.exe": {
                        "sha256": integrity._sha256_bytes(
                            self.runtime_binary("windows-x86_64", "node")
                        )
                    },
                    "common-foundry-wallet.exe": {
                        "sha256": integrity._sha256_bytes(
                            self.runtime_binary("windows-x86_64", "wallet")
                        )
                    },
                },
                staged_network_info=network_info,
            )

    def test_final_runtime_validation_rejects_noncanonical_attestation(self) -> None:
        _, network_info, _ = self.runtime_writer_fixture("windows-x86_64")
        attestation_path = self.write_runtime_attestation(
            platform="windows-x86_64", network_info=network_info, worker=None
        )
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        attestation_path.write_text(
            json.dumps(attestation, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(integrity.IntegrityError, "not canonical"):
            integrity._validate_runtime_attestation(
                path=attestation_path,
                platform="windows-x86_64",
                commit=self.commit,
                version="production-rc1",
                rows={
                    "cmfd-node.exe": {
                        "sha256": integrity._sha256_bytes(
                            self.runtime_binary("windows-x86_64", "node")
                        )
                    },
                    "common-foundry-wallet.exe": {
                        "sha256": integrity._sha256_bytes(
                            self.runtime_binary("windows-x86_64", "wallet")
                        )
                    },
                },
                staged_network_info=network_info,
            )

    def test_attestation_writer_runs_the_packaged_node(self) -> None:
        package = self.root / "attested-package"
        package.mkdir()
        node = package / "cmfd-node.exe"
        wallet = package / "common-foundry-wallet.exe"
        worker = package / "cmfd-proof-worker.exe"
        node.write_bytes(self.runtime_binary("windows-x86_64", "node"))
        wallet.write_bytes(self.runtime_binary("windows-x86_64", "wallet"))
        worker.write_bytes(self.WINDOWS_WORKER)
        network_bytes = (
            json.dumps(
                {
                    "proof_of_work": {
                        "build_source_commit": self.commit,
                        "runtime_verifier_worker_sha256": integrity._sha256_file(worker),
                        "selection": "ProductionV3",
                    }
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        output = self.root / integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME
        completed = subprocess.CompletedProcess(
            [str(node), "network-info"], 0, stdout=network_bytes, stderr=b""
        )
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            attestation = integrity.create_runtime_network_info_attestation(
                platform="windows-x86_64",
                package_directory=package,
                commit=self.commit,
                output=output,
            )
        run.assert_called_once()
        self.assertEqual(attestation["node_sha256"], integrity._sha256_file(node))
        self.assertEqual(base64.b64decode(attestation["network_info_base64"]), network_bytes)

    def test_v4_attestation_writer_omits_the_legacy_proof_worker(self) -> None:
        _, network_info, candidate = self.runtime_writer_fixture("windows-x86_64")
        package = self.root / "attested-v4-package"
        package.mkdir()
        node = package / "cmfd-node.exe"
        wallet = package / "common-foundry-wallet.exe"
        node.write_bytes(self.runtime_binary("windows-x86_64", "node"))
        wallet.write_bytes(self.runtime_binary("windows-x86_64", "wallet"))
        network_bytes = (json.dumps(network_info, indent=2) + "\n").encode("utf-8")
        output = self.root / integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME
        with (
            self.runtime_identity_pin_patch(network_info, candidate),
            mock.patch.object(
                subprocess,
                "run",
                side_effect=self.runtime_command_runner(network_bytes),
            ) as run,
        ):
            attestation = integrity.create_runtime_network_info_attestation(
                platform="windows-x86_64",
                package_directory=package,
                commit=self.commit,
                output=output,
                version="1.0.0-rc1",
            )
        self.assertEqual(
            [call.args[0][-1] for call in run.call_args_list],
            ["network-info", "runtime-identity"],
        )
        self.assertEqual(
            attestation["schema"], integrity.PRODUCTION_V4_RUNTIME_ATTESTATION_SCHEMA
        )
        self.assertNotIn("worker_sha256", attestation)
        wallet_identity = base64.b64decode(
            attestation["wallet_runtime_identity_base64"], validate=True
        )
        self.assertEqual(
            base64.b64decode(json.loads(wallet_identity)["network_info_base64"]),
            network_bytes,
        )

    def test_v4_attestation_rejects_arbitrary_wallet_output(self) -> None:
        package, output, network_bytes, network_info, candidate = (
            self.v4_attestation_fixture()
        )
        with (
            self.runtime_identity_pin_patch(network_info, candidate),
            mock.patch.object(
                subprocess,
                "run",
                side_effect=self.runtime_command_runner(
                    network_bytes, wallet_stdout=network_bytes
                ),
            ),
            self.assertRaisesRegex(integrity.IntegrityError, "runtime identity"),
        ):
            integrity.create_runtime_network_info_attestation(
                platform="windows-x86_64",
                package_directory=package,
                commit=self.commit,
                output=output,
                version="1.0.0-rc1",
            )
        self.assertFalse(output.exists())

    def test_v4_attestation_rejects_wrong_wallet_network_or_artifacts(self) -> None:
        for mutation in ("network", "bank"):
            with self.subTest(mutation=mutation):
                package, output, network_bytes, network_info, candidate = (
                    self.v4_attestation_fixture()
                )
                wallet_network = copy.deepcopy(network_info)
                if mutation == "network":
                    wallet_network["network"]["network_id"] = "ab" * 32
                else:
                    wallet_network["proof_of_work"]["artifacts"]["bank"]["sha256"] = (
                        "cd" * 32
                    )
                wallet_network_bytes = (
                    json.dumps(wallet_network, indent=2) + "\n"
                ).encode("utf-8")
                with (
                    self.runtime_identity_pin_patch(network_info, candidate),
                    mock.patch.object(
                        subprocess,
                        "run",
                        side_effect=self.runtime_command_runner(
                            network_bytes, wallet_network_bytes=wallet_network_bytes
                        ),
                    ),
                    self.assertRaisesRegex(
                        integrity.IntegrityError, "packaged-node network identity"
                    ),
                ):
                    integrity.create_runtime_network_info_attestation(
                        platform="windows-x86_64",
                        package_directory=package,
                        commit=self.commit,
                        output=output,
                        version="1.0.0-rc1",
                    )
                self.assertFalse(output.exists())

    def test_v4_attestation_rejects_missing_or_invalid_source_commit(self) -> None:
        for source_commit in (None, "not-a-commit"):
            with self.subTest(source_commit=source_commit):
                package, output, _, network_info, candidate = self.v4_attestation_fixture()
                proof = network_info["proof_of_work"]
                if source_commit is None:
                    del proof["build_source_commit"]
                else:
                    proof["build_source_commit"] = source_commit
                network_bytes = (json.dumps(network_info, indent=2) + "\n").encode(
                    "utf-8"
                )
                with (
                    self.runtime_identity_pin_patch(network_info, candidate),
                    mock.patch.object(
                        subprocess,
                        "run",
                        side_effect=self.runtime_command_runner(network_bytes),
                    ),
                    self.assertRaisesRegex(
                        integrity.IntegrityError, "unexpected compiled identity"
                    ),
                ):
                    integrity.create_runtime_network_info_attestation(
                        platform="windows-x86_64",
                        package_directory=package,
                        commit=self.commit,
                        output=output,
                        version="1.0.0-rc1",
                    )
                self.assertFalse(output.exists())

    def test_v4_attestation_rejects_unclean_wallet_execution(self) -> None:
        cases = (
            {"wallet_returncode": 1},
            {"wallet_stderr": b"unexpected warning\n"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                package, output, network_bytes, network_info, candidate = (
                    self.v4_attestation_fixture()
                )
                with (
                    self.runtime_identity_pin_patch(network_info, candidate),
                    mock.patch.object(
                        subprocess,
                        "run",
                        side_effect=self.runtime_command_runner(
                            network_bytes, **overrides
                        ),
                    ),
                    self.assertRaisesRegex(
                        integrity.IntegrityError,
                        "wallet runtime-identity execution was not clean",
                    ),
                ):
                    integrity.create_runtime_network_info_attestation(
                        platform="windows-x86_64",
                        package_directory=package,
                        commit=self.commit,
                        output=output,
                        version="1.0.0-rc1",
                    )
                self.assertFalse(output.exists())

    def test_v4_attestation_requires_canonical_exact_version_identity(self) -> None:
        for mutation in ("noncanonical", "wrong-version"):
            with self.subTest(mutation=mutation):
                package, output, network_bytes, network_info, candidate = (
                    self.v4_attestation_fixture()
                )
                identity = json.loads(self.wallet_runtime_identity_bytes(network_bytes))
                if mutation == "wrong-version":
                    identity["package_version"] = "1.0.0-rc2"
                    wallet_stdout = integrity._canonical_json(identity)
                    message = "runtime identity is invalid"
                else:
                    wallet_stdout = (json.dumps(identity, indent=2) + "\n").encode(
                        "utf-8"
                    )
                    message = "runtime identity is not canonical"
                with (
                    self.runtime_identity_pin_patch(network_info, candidate),
                    mock.patch.object(
                        subprocess,
                        "run",
                        side_effect=self.runtime_command_runner(
                            network_bytes, wallet_stdout=wallet_stdout
                        ),
                    ),
                    self.assertRaisesRegex(integrity.IntegrityError, message),
                ):
                    integrity.create_runtime_network_info_attestation(
                        platform="windows-x86_64",
                        package_directory=package,
                        commit=self.commit,
                        output=output,
                        version="1.0.0-rc1",
                    )
                self.assertFalse(output.exists())

    def test_v4_attestation_rejects_non_release_artifact_pins(self) -> None:
        package, output, _, network_info, candidate = self.v4_attestation_fixture()
        network_info["proof_of_work"]["artifacts"]["fixed_record"]["sha256"] = (
            "ef" * 32
        )
        bank = network_info["proof_of_work"]["artifacts"]["bank"]
        network_bytes = (json.dumps(network_info, indent=2) + "\n").encode("utf-8")
        with (
            mock.patch.multiple(
                integrity,
                PRODUCTION_RC_NETWORK_ID=candidate["network_id"],
                PRODUCTION_RC_VIRTUAL_GENESIS_HASH=candidate["virtual_genesis_hash"],
                PRODUCTION_V4_MODEL_BANK_FILE_BYTES=int(bank["bytes"]),
                PRODUCTION_V4_MODEL_BANK_FILE_BLAKE3=bank["blake3"],
                PRODUCTION_V4_MODEL_BANK_FILE_SHA256=bank["sha256"],
            ),
            mock.patch.object(
                subprocess,
                "run",
                side_effect=self.runtime_command_runner(network_bytes),
            ),
            self.assertRaisesRegex(integrity.IntegrityError, "release pin"),
        ):
            integrity.create_runtime_network_info_attestation(
                platform="windows-x86_64",
                package_directory=package,
                commit=self.commit,
                output=output,
                version="1.0.0-rc1",
            )
        self.assertFalse(output.exists())

    def test_runtime_package_writer_is_deterministic_and_fully_reverified(self) -> None:
        for platform in ("windows-x86_64", "linux-x86_64"):
            with self.subTest(platform=platform):
                inputs, network_info, candidate = self.runtime_writer_fixture(platform)
                network_bytes = (
                    json.dumps(network_info, indent=2, ensure_ascii=False) + "\n"
                ).encode("utf-8")
                first = self.root / f"writer-first-{platform}"
                second = self.root / f"writer-second-{platform}"
                first.mkdir()
                second.mkdir()
                with (
                    mock.patch.object(
                        integrity, "_assert_clean_exact_repo", return_value=self.commit
                    ) as clean,
                    mock.patch.object(
                        integrity, "validate_production_rc_source_versions"
                    ) as versions,
                    mock.patch.object(integrity, "_require_native_runtime_platform"),
                    self.runtime_identity_pin_patch(network_info, candidate),
                    mock.patch.object(
                        subprocess,
                        "run",
                        side_effect=self.runtime_command_runner(network_bytes),
                    ) as run,
                ):
                    first_result = integrity.create_production_v4_runtime_package(
                        repo=self.root,
                        expected_commit=self.commit,
                        version="1.0.0-rc1",
                        platform=platform,
                        output_directory=first,
                        source_date_epoch=1_700_000_000,
                        **inputs,
                    )
                    second_result = integrity.create_production_v4_runtime_package(
                        repo=self.root,
                        expected_commit=self.commit,
                        version="1.0.0-rc1",
                        platform=platform,
                        output_directory=second,
                        source_date_epoch=1_700_000_000,
                        **inputs,
                    )
                self.assertEqual(clean.call_count, 4)
                self.assertEqual(versions.call_count, 2)
                self.assertEqual(
                    [call.args[0][-1] for call in run.call_args_list],
                    [
                        "network-info",
                        "runtime-identity",
                        "network-info",
                        "runtime-identity",
                    ],
                )
                versions.assert_has_calls(
                    [
                        mock.call(
                            repo=self.root,
                            version="1.0.0-rc1",
                            commit=self.commit,
                        ),
                        mock.call(
                            repo=self.root,
                            version="1.0.0-rc1",
                            commit=self.commit,
                        ),
                    ]
                )
                archive_name = first_result["archive"]["name"]
                attestation_name = first_result["attestation"]["name"]
                self.assertEqual(
                    (first / archive_name).read_bytes(),
                    (second / archive_name).read_bytes(),
                )
                self.assertEqual(
                    (first / attestation_name).read_bytes(),
                    (second / attestation_name).read_bytes(),
                )
                self.assertEqual(first_result, second_result)
                rows = integrity._inspect_runtime_package_archive(
                    first / archive_name, platform, selection="ProductionV4"
                )
                expected_files, worker = integrity._runtime_package_paths(
                    platform, "ProductionV4"
                )
                self.assertEqual(set(rows), expected_files)
                self.assertIsNone(worker)

    def test_runtime_package_writer_rejects_the_wrong_candidate_identity(self) -> None:
        platform = "windows-x86_64"
        inputs, network_info, candidate = self.runtime_writer_fixture(platform)
        network_info["network"]["network_id"] = "ab" * 32
        network_bytes = (json.dumps(network_info, indent=2) + "\n").encode("utf-8")
        completed = subprocess.CompletedProcess(
            [str(inputs["node"]), "network-info"],
            0,
            stdout=network_bytes,
            stderr=b"",
        )
        output = self.root / "wrong-candidate-output"
        output.mkdir()
        with (
            mock.patch.object(
                integrity, "_assert_clean_exact_repo", return_value=self.commit
            ),
            mock.patch.object(integrity, "validate_production_rc_source_versions"),
            mock.patch.object(integrity, "_require_native_runtime_platform"),
            mock.patch.object(
                integrity, "PRODUCTION_RC_NETWORK_ID", candidate["network_id"]
            ),
            mock.patch.object(
                integrity,
                "PRODUCTION_RC_VIRTUAL_GENESIS_HASH",
                candidate["virtual_genesis_hash"],
            ),
            mock.patch.object(subprocess, "run", return_value=completed),
            self.assertRaisesRegex(integrity.IntegrityError, "immutable RCNet-1"),
        ):
            integrity.create_production_v4_runtime_package(
                repo=self.root,
                expected_commit=self.commit,
                version="1.0.0-rc1",
                platform=platform,
                output_directory=output,
                source_date_epoch=1_700_000_000,
                **inputs,
            )
        self.assertEqual(list(output.iterdir()), [])

    def test_runtime_package_identity_binds_consensus_policy_and_rewards(self) -> None:
        mutations = (
            lambda network: network["consensus"].__setitem__(
                "consensus_fingerprint", "ab" * 32
            ),
            lambda network: network["consensus"]["limits"].__setitem__(
                "target_spacing_seconds", "61"
            ),
            lambda network: network["monetary_policy"].__setitem__(
                "tail_height", "2628002"
            ),
            lambda network: network["reward_destinations"].__setitem__(
                "steward_xonly_public_key",
                network["reward_destinations"]["community_xonly_public_key"],
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                _, network_info, candidate = self.runtime_writer_fixture(
                    "windows-x86_64"
                )
                mutate(network_info)
                with (
                    self.runtime_identity_pin_patch(network_info, candidate),
                    self.assertRaises(integrity.IntegrityError),
                ):
                    integrity._validate_production_v4_runtime_identity(
                        network_info, self.commit
                    )

    def test_runtime_package_identity_rejects_unsafe_operational_defaults(self) -> None:
        mutations = (
            lambda network: network["services"].__setitem__("rpc_port", 29443),
            lambda network: network["services"].__setitem__(
                "bootstrap_peer", "8.8.8.8:19444"
            ),
            lambda network: network["data_directories"].__setitem__(
                "wallet", "devnet-0"
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                _, network_info, candidate = self.runtime_writer_fixture(
                    "windows-x86_64"
                )
                mutate(network_info)
                with (
                    self.runtime_identity_pin_patch(network_info, candidate),
                    self.assertRaises(integrity.IntegrityError),
                ):
                    integrity._validate_production_v4_runtime_identity(
                        network_info, self.commit
                    )

    def test_runtime_package_identity_rejects_boolean_format_version(self) -> None:
        _, network_info, candidate = self.runtime_writer_fixture("windows-x86_64")
        network_info["format_version"] = True
        with (
            self.runtime_identity_pin_patch(network_info, candidate),
            self.assertRaisesRegex(integrity.IntegrityError, "unsupported"),
        ):
            integrity._validate_production_v4_runtime_identity(
                network_info, self.commit
            )

    def test_v4_attestation_requires_canonical_node_network_information(self) -> None:
        package, output, _, network_info, candidate = self.v4_attestation_fixture()
        noncanonical = integrity._canonical_json(network_info)
        with (
            self.runtime_identity_pin_patch(network_info, candidate),
            mock.patch.object(
                subprocess,
                "run",
                side_effect=self.runtime_command_runner(noncanonical),
            ),
            self.assertRaisesRegex(
                integrity.IntegrityError, "network information is not canonical"
            ),
        ):
            integrity.create_runtime_network_info_attestation(
                platform="windows-x86_64",
                package_directory=package,
                commit=self.commit,
                output=output,
                version="1.0.0-rc1",
            )
        self.assertFalse(output.exists())

    def test_v4_attestation_rejects_one_binary_in_both_runtime_roles(self) -> None:
        package, output, network_bytes, network_info, candidate = (
            self.v4_attestation_fixture()
        )
        (package / "common-foundry-wallet.exe").write_bytes(
            (package / "cmfd-node.exe").read_bytes()
        )
        with (
            self.runtime_identity_pin_patch(network_info, candidate),
            mock.patch.object(
                subprocess,
                "run",
                side_effect=self.runtime_command_runner(network_bytes),
            ),
            self.assertRaisesRegex(
                integrity.IntegrityError, "executables are not distinct"
            ),
        ):
            integrity.create_runtime_network_info_attestation(
                platform="windows-x86_64",
                package_directory=package,
                commit=self.commit,
                output=output,
                version="1.0.0-rc1",
            )
        self.assertFalse(output.exists())

    def test_runtime_package_writer_refuses_existing_outputs(self) -> None:
        platform = "windows-x86_64"
        inputs, _, _ = self.runtime_writer_fixture(platform)
        output = self.root / "existing-runtime-output"
        output.mkdir()
        archive = output / integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME
        archive.write_bytes(b"existing archive")
        with (
            mock.patch.object(
                integrity, "_assert_clean_exact_repo", return_value=self.commit
            ),
            mock.patch.object(integrity, "validate_production_rc_source_versions"),
            mock.patch.object(integrity, "_require_native_runtime_platform"),
            self.assertRaisesRegex(integrity.IntegrityError, "already exists"),
        ):
            integrity.create_production_v4_runtime_package(
                repo=self.root,
                expected_commit=self.commit,
                version="1.0.0-rc1",
                platform=platform,
                output_directory=output,
                source_date_epoch=1_700_000_000,
                **inputs,
            )
        self.assertEqual(archive.read_bytes(), b"existing archive")
        self.assertFalse(
            (output / integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME).exists()
        )

    def test_runtime_package_writer_rolls_back_its_published_archive(self) -> None:
        platform = "windows-x86_64"
        inputs, network_info, candidate = self.runtime_writer_fixture(platform)
        network_bytes = (json.dumps(network_info, indent=2) + "\n").encode("utf-8")
        output = self.root / "runtime-publication-failure"
        output.mkdir()
        publish = integrity._publish_new_archive
        published_names: list[str] = []

        def interrupt_attestation_publish(
            source: Path, destination: Path
        ) -> tuple[int, int, int, int, int]:
            if destination.parent == output:
                published_names.append(destination.name)
            if destination == output / integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME:
                raise KeyboardInterrupt("fixture publication interruption")
            return publish(source, destination)

        with (
            mock.patch.object(
                integrity, "_assert_clean_exact_repo", return_value=self.commit
            ),
            mock.patch.object(integrity, "validate_production_rc_source_versions"),
            mock.patch.object(integrity, "_require_native_runtime_platform"),
            self.runtime_identity_pin_patch(network_info, candidate),
            mock.patch.object(
                subprocess,
                "run",
                side_effect=self.runtime_command_runner(network_bytes),
            ),
            mock.patch.object(
                integrity,
                "_publish_new_archive",
                side_effect=interrupt_attestation_publish,
            ),
            self.assertRaisesRegex(KeyboardInterrupt, "publication interruption"),
        ):
            integrity.create_production_v4_runtime_package(
                repo=self.root,
                expected_commit=self.commit,
                version="1.0.0-rc1",
                platform=platform,
                output_directory=output,
                source_date_epoch=1_700_000_000,
                **inputs,
            )
        self.assertEqual(
            published_names,
            [
                integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME,
                integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME,
            ],
        )
        self.assertEqual(list(output.iterdir()), [])

    def test_runtime_package_rechecks_checkout_before_publication(self) -> None:
        platform = "windows-x86_64"
        inputs, network_info, candidate = self.runtime_writer_fixture(platform)
        network_bytes = (json.dumps(network_info, indent=2) + "\n").encode("utf-8")
        output = self.root / "runtime-late-dirty-checkout"
        output.mkdir()
        with (
            mock.patch.object(
                integrity,
                "_assert_clean_exact_repo",
                side_effect=(
                    self.commit,
                    integrity.IntegrityError("source checkout became dirty"),
                ),
            ) as clean,
            mock.patch.object(integrity, "validate_production_rc_source_versions"),
            mock.patch.object(integrity, "_require_native_runtime_platform"),
            self.runtime_identity_pin_patch(network_info, candidate),
            mock.patch.object(
                subprocess,
                "run",
                side_effect=self.runtime_command_runner(network_bytes),
            ),
            self.assertRaisesRegex(integrity.IntegrityError, "became dirty"),
        ):
            integrity.create_production_v4_runtime_package(
                repo=self.root,
                expected_commit=self.commit,
                version="1.0.0-rc1",
                platform=platform,
                output_directory=output,
                source_date_epoch=1_700_000_000,
                **inputs,
            )
        self.assertEqual(clean.call_count, 2)
        self.assertEqual(list(output.iterdir()), [])

    def test_create_new_publication_removes_output_on_durability_failure(self) -> None:
        temporary = self.root / "pending-archive"
        temporary.write_bytes(b"complete archive bytes")
        output_directory = self.root / "durability-output"
        output_directory.mkdir()
        output = output_directory / "archive.zip"
        with (
            mock.patch.object(
                integrity,
                "_sync_directory",
                side_effect=OSError("fixture directory flush failure"),
            ),
            self.assertRaises(integrity.IntegrityError),
        ):
            integrity._publish_new_archive(temporary, output)
        self.assertFalse(output.exists())
        self.assertEqual(temporary.read_bytes(), b"complete archive bytes")

    def test_runtime_package_requires_the_native_x86_64_target(self) -> None:
        platform_module = integrity.host_platform
        with (
            mock.patch.object(platform_module, "system", return_value="Windows"),
            mock.patch.object(platform_module, "machine", return_value="AMD64"),
        ):
            integrity._require_native_runtime_platform("windows-x86_64")
            with self.assertRaisesRegex(integrity.IntegrityError, "native linux"):
                integrity._require_native_runtime_platform("linux-x86_64")
        with (
            mock.patch.object(platform_module, "system", return_value="Linux"),
            mock.patch.object(platform_module, "machine", return_value="aarch64"),
            self.assertRaisesRegex(integrity.IntegrityError, "x86_64 host"),
        ):
            integrity._native_runtime_platform()

    def test_runtime_packages_are_required_on_both_platforms(self) -> None:
        for missing in (
            integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME,
            integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME,
        ):
            stage_files = self.valid_stage_files()
            del stage_files[missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(
                integrity.IntegrityError, "runtime package"
            ):
                integrity.validate_production_rc_artifacts(
                    version="production-rc1",
                    commit=self.commit,
                    stage_files=stage_files,
                )

    def test_runtime_package_requires_the_exact_sidecar_layout(self) -> None:
        stage_files = self.valid_stage_files()
        replacement = self.write_runtime_package(
            platform="linux-x86_64",
            worker=self.LINUX_WORKER,
            runtime_artifacts={
                name: data
                for name, data in self.RUNTIME_ARTIFACTS.items()
                if name != integrity.PRODUCTION_V3_PACKAGE_RECORD_V2
            },
        )
        stage_files[integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME] = replacement
        with self.assertRaisesRegex(
            integrity.IntegrityError, "layout mismatch|missing, reordered"
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_packaged_worker_must_match_staged_network_info(self) -> None:
        stage_files = self.valid_stage_files()
        replacement = self.write_runtime_package(
            platform="windows-x86_64",
            worker=pe_x86_64_fixture(b"different Windows proof worker"),
            runtime_artifacts=self.RUNTIME_ARTIFACTS,
        )
        stage_files[integrity.PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME] = replacement
        with self.assertRaisesRegex(integrity.IntegrityError, "proof worker"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_staged_platform_worker_pins_must_be_distinct(self) -> None:
        stage_files = self.valid_stage_files()
        path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network = json.loads(path.read_text(encoding="utf-8"))
        network["proof_of_work"]["runtime_verifier_workers"][
            "linux_x86_64_sha256"
        ] = network["proof_of_work"]["runtime_verifier_workers"][
            "windows_x86_64_sha256"
        ]
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network)
        with self.assertRaisesRegex(
            integrity.IntegrityError, "runtime_verifier_workers"
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_selected_worker_must_be_one_of_the_platform_pins(self) -> None:
        stage_files = self.valid_stage_files()
        path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network = json.loads(path.read_text(encoding="utf-8"))
        network["proof_of_work"]["runtime_verifier_worker_sha256"] = (
            integrity._sha256_bytes(b"uncompiled proof worker")
        )
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network)
        with self.assertRaisesRegex(integrity.IntegrityError, "not a compiled platform pin"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_packaged_artifact_blake3_must_match_staged_network_info(self) -> None:
        stage_files = self.valid_stage_files()
        path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network = json.loads(path.read_text(encoding="utf-8"))
        network["proof_of_work"]["artifacts"]["bank"]["blake3"] = "ab" * 32
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network)
        with self.assertRaisesRegex(integrity.IntegrityError, "artifacts"):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_packaged_artifact_must_match_staged_network_info(self) -> None:
        stage_files = self.valid_stage_files()
        replacement = self.write_runtime_package(
            platform="linux-x86_64",
            worker=self.LINUX_WORKER,
            runtime_artifacts={
                integrity.PRODUCTION_V3_PACKAGE_BANK: b"tampered production model bank",
                integrity.PRODUCTION_V3_PACKAGE_MANIFEST: self.RUNTIME_ARTIFACTS[
                    integrity.PRODUCTION_V3_PACKAGE_MANIFEST
                ],
                integrity.PRODUCTION_V3_PACKAGE_RECORD_V2: self.RUNTIME_ARTIFACTS[
                    integrity.PRODUCTION_V3_PACKAGE_RECORD_V2
                ],
            },
        )
        stage_files[integrity.PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME] = replacement
        with self.assertRaisesRegex(
            integrity.IntegrityError, "model bank|MODEL-V2.bank"
        ):
            integrity.validate_production_rc_artifacts(
                version="production-rc1", commit=self.commit, stage_files=stage_files
            )

    def test_launch_candidate_unknown_fields_are_rejected(self) -> None:
        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["unknown"] = True
        with self.assertRaisesRegex(integrity.IntegrityError, "unknown fields"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

    def test_v2_launch_candidate_matches_compiled_production_v4(self) -> None:
        candidate, network_info = self.valid_v2_candidate_and_network_info()
        integrity._validate_rcnet_launch_candidate(candidate, network_info)

    def test_placeholder_identity_is_rejected(self) -> None:
        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["network_id"] = "72" * 32
        with self.assertRaisesRegex(integrity.IntegrityError, "placeholder"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

    def test_v2_candidate_excludes_operational_services(self) -> None:
        candidate, network_info = self.valid_v2_candidate_and_network_info()
        self.assertNotIn("services", candidate["payload"])
        network_info["services"].update(
            {
                "rpc_port": 28443,
                "p2p_port": 28444,
                "pool_port": 28445,
                "bootstrap_peer": "203.0.113.9:28444",
            }
        )
        integrity._validate_rcnet_launch_candidate(candidate, network_info)

    def test_development_reward_and_pow_limit_mutation_are_rejected(self) -> None:
        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["reward_destinations"]["steward_xonly_public_key"] = (
            next(iter(integrity.INSECURE_DEV_REWARD_DESTINATIONS))
        )
        with self.assertRaisesRegex(integrity.IntegrityError, "insecure development"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["proof_of_work"]["pow_limit"] = "01" + "ff" * 31
        self.refresh_v2_candidate_derivations(candidate)
        network_info["network"]["network_id"] = candidate["network_id"]
        network_info["network"]["virtual_genesis_hash"] = candidate[
            "virtual_genesis_hash"
        ]
        with self.assertRaisesRegex(integrity.IntegrityError, "proof-of-work parameters"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

    def test_v2_derived_identity_mutations_are_rejected(self) -> None:
        errors = {
            "launch_root": "launch root is not derived",
            "network_id": "network ID is not derived",
            "virtual_genesis_hash": "virtual genesis is not derived",
        }
        for field, message in errors.items():
            candidate, network_info = self.valid_v2_candidate_and_network_info()
            value = candidate[field]
            candidate[field] = ("0" if value[0] != "0" else "1") + value[1:]
            with self.subTest(field=field), self.assertRaisesRegex(
                integrity.IntegrityError, message
            ):
                integrity._validate_rcnet_launch_candidate(candidate, network_info)

    def test_v2_artifact_mutations_are_rejected(self) -> None:
        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["artifacts"]["bank"]["sha256"] = "ab" * 32
        with self.assertRaisesRegex(integrity.IntegrityError, "launch root is not derived"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["artifacts"]["bank"]["sha256"] = "ab" * 32
        self.refresh_v2_candidate_derivations(candidate)
        network_info["network"]["network_id"] = candidate["network_id"]
        network_info["network"]["virtual_genesis_hash"] = candidate[
            "virtual_genesis_hash"
        ]
        with self.assertRaisesRegex(integrity.IntegrityError, "artifacts"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["artifacts"]["proof_system_digest"] = "ab" * 32
        with self.assertRaisesRegex(integrity.IntegrityError, "frozen consensus"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

    def test_v2_consensus_and_monetary_policy_are_frozen(self) -> None:
        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["consensus"]["target_spacing_seconds"] += 1
        with self.assertRaisesRegex(integrity.IntegrityError, "frozen ProductionV4"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["monetary_policy"]["tail_height"] += 1
        with self.assertRaisesRegex(integrity.IntegrityError, "frozen values"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

    def test_v2_timestamp_and_rewards_are_bound_into_the_launch_root(self) -> None:
        candidate, network_info = self.valid_v2_candidate_and_network_info()
        candidate["payload"]["virtual_genesis_timestamp_unix_seconds"] += 1
        with self.assertRaisesRegex(integrity.IntegrityError, "launch root is not derived"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

        candidate, network_info = self.valid_v2_candidate_and_network_info()
        rewards = candidate["payload"]["reward_destinations"]
        rewards["steward_xonly_public_key"] = rewards["community_xonly_public_key"]
        with self.assertRaisesRegex(integrity.IntegrityError, "launch root is not derived"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

    def test_v1_candidate_is_rejected_for_production_v4(self) -> None:
        stage_files = self.valid_stage_files()
        candidate_path = stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME]
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        _, network_info = self.valid_v2_candidate_and_network_info()
        with self.assertRaisesRegex(integrity.IntegrityError, "only for compiled ProductionV3"):
            integrity._validate_rcnet_launch_candidate(candidate, network_info)

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


class ProductionRcVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = GitFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def commit_versions(self, version: str, *, node_version: str | None = None) -> None:
        for relative in integrity.PRODUCTION_RC_VERSION_FILES:
            selected = (
                node_version
                if relative == "crates/cmfd-node/Cargo.toml" and node_version is not None
                else version
            )
            if relative.endswith(".json"):
                content = json.dumps(
                    {"name": "fixture", "version": selected},
                    sort_keys=True,
                    separators=(",", ":"),
                ) + "\n"
            else:
                content = (
                    "[package]\n"
                    f'name = "{Path(relative).parent.name}"\n'
                    f'version = "{selected}"\n'
                )
            self.fixture.write(relative, content)
        self.fixture.git("add", "--", "apps", "crates")
        self.fixture.git("commit", "--quiet", "-m", "release versions")

    def test_production_rc_requires_one_exact_version_in_every_package(self) -> None:
        self.commit_versions("1.0.0-rc1")
        integrity.validate_production_rc_source_versions(
            repo=self.fixture.root, version="1.0.0-rc1"
        )

    def test_production_rc_rejects_a_stale_devnet_component_version(self) -> None:
        self.commit_versions("1.0.0-rc1", node_version="0.1.0-devnet.14")
        with self.assertRaisesRegex(integrity.IntegrityError, "cmfd-node/Cargo.toml"):
            integrity.validate_production_rc_source_versions(
                repo=self.fixture.root, version="1.0.0-rc1"
            )

    def test_source_versions_can_be_read_from_the_captured_commit(self) -> None:
        self.commit_versions("1.0.0-rc1")
        captured = self.fixture.commit
        captured_epoch = integrity._commit_epoch(self.fixture.root, captured)
        self.commit_versions("1.0.0-rc2")
        integrity.validate_production_rc_source_versions(
            repo=self.fixture.root,
            version="1.0.0-rc1",
            commit=captured,
        )
        with self.assertRaises(integrity.IntegrityError):
            integrity.validate_production_rc_source_versions(
                repo=self.fixture.root,
                version="1.0.0-rc1",
                commit=self.fixture.commit,
            )
        with mock.patch.dict(os.environ, clear=False):
            os.environ.pop("SOURCE_DATE_EPOCH", None)
            self.assertEqual(
                integrity._source_date_epoch(self.fixture.root, None, captured),
                captured_epoch,
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

    def signed_download_inputs(self) -> tuple[Path, Path, dict[str, object]]:
        signature_path = self.stage / integrity.CHECKSUM_SIGNATURE_NAME
        signature_path.write_bytes(b"signature")
        allowed = self.fixture.write("target/allowed_signers", "trusted key\n")
        verifier = self.fixture.write("target/ssh-keygen", b"verifier")
        receipt = {
            "allowed_signers_sha256": integrity._sha256_file(allowed),
            "checksum_sha256": integrity._sha256_file(
                self.stage / integrity.CHECKSUM_NAME
            ),
            "namespace": integrity.RELEASE_SIGNATURE_NAMESPACE,
            "signature_sha256": integrity._sha256_file(signature_path),
            "signer_identity": "release@example.invalid",
            "verifier_sha256": integrity._sha256_file(verifier),
        }
        return allowed, verifier, receipt

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

    @mock.patch("release_integrity.verify_release_signature")
    def test_signed_download_verifies_without_source_access(self, verify_signature) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        allowed, verifier, receipt = self.signed_download_inputs()
        verify_signature.return_value = receipt
        result = integrity.verify_signed_download(
            stage=self.stage,
            allowed_signers=allowed,
            signer_identity="release@example.invalid",
            ssh_keygen=verifier,
        )
        self.assertEqual(result["schema"], "CMFD_AUTHENTICATED_DOWNLOAD_V1")
        self.assertEqual(result["commit"], self.fixture.commit)
        self.assertEqual(result["file_count"], 5)

    def test_signed_download_real_openssh_round_trip(self) -> None:
        executable = shutil.which("ssh-keygen")
        if executable is None:
            self.skipTest("OpenSSH ssh-keygen is unavailable")
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        key = self.fixture.root / "target/release-key"
        subprocess.run(
            [
                executable,
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "release@example.invalid",
                "-f",
                str(key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                executable,
                "-Y",
                "sign",
                "-f",
                str(key),
                "-n",
                integrity.RELEASE_SIGNATURE_NAMESPACE,
                str(self.stage / integrity.CHECKSUM_NAME),
            ],
            check=True,
            capture_output=True,
        )
        allowed = self.fixture.write(
            "target/allowed_signers",
            "release@example.invalid "
            + key.with_suffix(".pub").read_text(encoding="utf-8"),
        )
        result = integrity.verify_signed_download(
            stage=self.stage,
            allowed_signers=allowed,
            signer_identity="release@example.invalid",
            ssh_keygen=Path(executable),
        )
        self.assertEqual(result["commit"], self.fixture.commit)

    @mock.patch("release_integrity.verify_release_signature")
    def test_signed_download_rejects_corrupt_asset(self, verify_signature) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        allowed, verifier, receipt = self.signed_download_inputs()
        verify_signature.return_value = receipt
        (self.stage / "a.bin").write_bytes(b"omega")
        with self.assertRaisesRegex(integrity.IntegrityError, "digest is invalid"):
            integrity.verify_signed_download(
                stage=self.stage,
                allowed_signers=allowed,
                signer_identity="release@example.invalid",
                ssh_keygen=verifier,
            )

    @mock.patch("release_integrity.verify_release_signature")
    def test_signed_download_rejects_noncanonical_checksum(self, verify_signature) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        checksum_path = self.stage / integrity.CHECKSUM_NAME
        checksum_path.write_bytes(
            b"".join(reversed(checksum_path.read_bytes().splitlines(keepends=True)))
        )
        allowed, verifier, receipt = self.signed_download_inputs()
        verify_signature.return_value = receipt
        with self.assertRaisesRegex(integrity.IntegrityError, "not sorted"):
            integrity.verify_signed_download(
                stage=self.stage,
                allowed_signers=allowed,
                signer_identity="release@example.invalid",
                ssh_keygen=verifier,
            )

    def test_two_verified_release_stages_compare_byte_for_byte(self) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        second_stage = self.fixture.root / "target/second-release-assets"
        shutil.copytree(self.stage, second_stage)
        report = integrity.compare_reproducible_releases(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            first_stage=self.stage,
            second_stage=second_stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        self.assertTrue(report["reproducible"])
        self.assertEqual(report["file_count"], 6)
        self.assertEqual(
            report["schema"], integrity.REPRODUCIBLE_COMPARISON_SCHEMA
        )

    def test_finalized_sbom_and_provenance_bind_source_and_artifacts(self) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        sbom = json.loads(
            (self.stage / integrity.SOURCE_SBOM_NAME).read_text(encoding="utf-8")
        )
        provenance = json.loads(
            (self.stage / integrity.PROVENANCE_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(sbom["component_count"], 4)
        self.assertEqual(sbom["commit"], self.fixture.commit)
        self.assertEqual(provenance["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(
            {subject["name"] for subject in provenance["subject"]},
            {"a.bin", "b.txt"},
        )
        self.assertEqual(
            provenance["predicate"]["sourceSbom"]["digest"]["sha256"],
            integrity._sha256_file(self.stage / integrity.SOURCE_SBOM_NAME),
        )

    def test_altered_source_sbom_is_rejected(self) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        (self.stage / integrity.SOURCE_SBOM_NAME).write_bytes(b"{}\n")
        with self.assertRaisesRegex(integrity.IntegrityError, "SOURCE-SBOM"):
            integrity.verify_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )

    def test_two_valid_but_different_release_stages_are_rejected(self) -> None:
        self.make_valid_assets()
        second_stage = self.fixture.root / "target/second-release-assets"
        second_stage.mkdir(parents=True)
        (second_stage / "a.bin").write_bytes(b"omega")
        (second_stage / "b.txt").write_bytes(b"beta\n")
        for stage in (self.stage, second_stage):
            integrity.finalize_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                stage=stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )
        with self.assertRaisesRegex(integrity.IntegrityError, "content: a.bin"):
            integrity.compare_reproducible_releases(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                first_stage=self.stage,
                second_stage=second_stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )

    def test_release_stage_cannot_be_compared_to_itself(self) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        with self.assertRaisesRegex(
            integrity.IntegrityError, "different directories"
        ):
            integrity.compare_reproducible_releases(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                first_stage=self.stage,
                second_stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
            )

    @mock.patch("release_integrity.verify_release_signature")
    def test_signed_verify_requires_and_checks_detached_signature(self, verify_signature) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        allowed = self.fixture.write("target/allowed_signers", "trusted key\n")
        verifier = self.fixture.write("target/ssh-keygen", b"verifier")
        with self.assertRaisesRegex(integrity.IntegrityError, "missing"):
            integrity.verify_signed_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
                allowed_signers=allowed,
                signer_identity="release@example.invalid",
                ssh_keygen=verifier,
            )
        (self.stage / integrity.CHECKSUM_SIGNATURE_NAME).write_bytes(b"signature")
        checksum_sha256 = integrity._sha256_bytes(
            (self.stage / integrity.CHECKSUM_NAME).read_bytes()
        )
        verify_signature.return_value = {
            "checksum_sha256": checksum_sha256,
            "signer_identity": "release@example.invalid",
        }
        result = integrity.verify_signed_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
            allowed_signers=allowed,
            signer_identity="release@example.invalid",
            ssh_keygen=verifier,
        )
        self.assertEqual(
            result["signature"]["signer_identity"], "release@example.invalid"
        )
        verify_signature.assert_called_once()

    @mock.patch("release_integrity.verify_release_signature")
    def test_signed_verify_rejects_checksum_swap_between_phases(self, verify_signature) -> None:
        self.make_valid_assets()
        integrity.finalize_release(
            repo=self.fixture.root,
            expected_commit=self.fixture.commit,
            version="0.1.0-test",
            stage=self.stage,
            inventory=self.inventory,
            source_date_epoch=self.epoch,
        )
        (self.stage / integrity.CHECKSUM_SIGNATURE_NAME).write_bytes(b"signature")
        allowed = self.fixture.write("target/allowed_signers", "trusted key\n")
        verifier = self.fixture.write("target/ssh-keygen", b"verifier")
        verify_signature.return_value = {
            "checksum_sha256": "0" * 64,
            "signer_identity": "release@example.invalid",
        }
        with self.assertRaisesRegex(integrity.IntegrityError, "changed"):
            integrity.verify_signed_release(
                repo=self.fixture.root,
                expected_commit=self.fixture.commit,
                version="0.1.0-test",
                stage=self.stage,
                inventory=self.inventory,
                source_date_epoch=self.epoch,
                allowed_signers=allowed,
                signer_identity="release@example.invalid",
                ssh_keygen=verifier,
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
