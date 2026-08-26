from __future__ import annotations

import base64
import copy
import gzip
import io
import json
import os
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

    def write_runtime_package(
        self,
        *,
        platform: str,
        worker: bytes,
        runtime_artifacts: dict[str, bytes],
        runtime_binaries: dict[str, bytes] | None = None,
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
        worker_path = stage / f"cmfd-proof-worker{executable_suffix}"
        worker_path.write_bytes(worker)
        worker_path.chmod(0o755)
        artifact_directory = stage / integrity.PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY
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
        worker: bytes,
    ) -> Path:
        network_bytes = (
            json.dumps(network_info, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        name = (
            integrity.PRODUCTION_RC_WINDOWS_ATTESTATION_NAME
            if platform == "windows-x86_64"
            else integrity.PRODUCTION_RC_LINUX_ATTESTATION_NAME
        )
        return self.write_json(
            name,
            {
                "schema": integrity.PRODUCTION_RC_RUNTIME_ATTESTATION_SCHEMA,
                "platform": platform,
                "source_commit": self.commit,
                "node_sha256": integrity._sha256_bytes(
                    self.runtime_binary(platform, "node")
                ),
                "wallet_sha256": integrity._sha256_bytes(
                    self.runtime_binary(platform, "wallet")
                ),
                "worker_sha256": integrity._sha256_bytes(worker),
                "network_info_sha256": integrity._sha256_bytes(network_bytes),
                "network_info_base64": base64.b64encode(network_bytes).decode("ascii"),
            },
        )

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

    def test_rcnet_service_ports_are_fixed_for_the_binary_release(self) -> None:
        stage_files = self.valid_stage_files()
        candidate_path = stage_files[integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME]
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        candidate["payload"]["services"].update(
            {"rpc_port": 28443, "p2p_port": 28444, "pool_port": 28445}
        )
        self.write_json(integrity.PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, candidate)
        network_path = stage_files[integrity.PRODUCTION_RC_NETWORK_INFO_NAME]
        network = json.loads(network_path.read_text(encoding="utf-8"))
        network["services"].update(
            {
                "rpc_port": 28443,
                "p2p_port": 28444,
                "pool_port": 28445,
                "bootstrap_peer": "8.8.8.8:28444",
            }
        )
        self.write_json(integrity.PRODUCTION_RC_NETWORK_INFO_NAME, network)
        with self.assertRaisesRegex(integrity.IntegrityError, "RPC 19443"):
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
