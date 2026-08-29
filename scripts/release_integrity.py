#!/usr/bin/env python3
"""Fail-closed build receipts, deterministic archives, and release manifests."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath

try:
    import blake3
except ImportError:  # Production runtime inspection reports the actionable error.
    blake3 = None

RECEIPT_SCHEMA = "CMFD_NATIVE_BUILD_RECEIPT_V1"
BUILDINFO_SCHEMA = "CMFD_RELEASE_BUILDINFO_V1"
BUILDINFO_NAME = "BUILDINFO.json"
CHECKSUM_NAME = "SHA256SUMS.txt"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_BUILDINFO_BYTES = 4 * 1024 * 1024
MAX_DEB_BYTES = 512 * 1024 * 1024
MAX_DEB_MEMBERS = 100_000
MAX_RELEASE_GATE_JSON_BYTES = 1024 * 1024
MAX_RUNTIME_BINARY_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024 * 1024
MAX_RUNTIME_ARTIFACT_BYTES = MAX_ARCHIVE_MEMBER_BYTES
MAX_EXECUTABLE_HEADER_BYTES = 64 * 1024
MAX_RUNTIME_ARCHIVE_MEMBERS = 8
MAX_ARCHIVE_MEMBERS = 100_000
MAX_RUNTIME_ZIP_CENTRAL_DIRECTORY_BYTES = 64 * 1024
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_GZIP_OUTPUT_CHUNK_BYTES = 64 * 1024
TAR_BLOCK_BYTES = 512
TAR_RECORD_BYTES = 10_240
FULL_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
HEX256_RE = re.compile(r"[0-9a-f]{64}\Z")
PRODUCTION_RC_NETWORK_INFO_NAME = "NETWORK-INFO.json"
PRODUCTION_RC_LAUNCH_CANDIDATE_NAME = "RCNET-LAUNCH-CANDIDATE.json"
PRODUCTION_V3_ACTIVATION_NAME = "PRODUCTION-V3-ACTIVATION.json"
PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME = (
    "PRODUCTION-V3-QUALIFICATION-MANIFEST.json"
)
PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME = (
    "PRODUCTION-V3-FRESH-PROCESS-VERIFIER.bin"
)
PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME = (
    "PRODUCTION-V3-FRESH-PROCESS-VERIFIER-REPORT.json"
)
PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME = (
    "commonfoundry-rc-runtime-windows-x86_64.zip"
)
PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME = (
    "commonfoundry-rc-runtime-linux-x86_64.tar.gz"
)
PRODUCTION_RC_WINDOWS_ATTESTATION_NAME = "RUNTIME-ATTESTATION-WINDOWS-X86_64.json"
PRODUCTION_RC_LINUX_ATTESTATION_NAME = "RUNTIME-ATTESTATION-LINUX-X86_64.json"
PRODUCTION_RC_RUNTIME_ATTESTATION_SCHEMA = "CMFD_RUNTIME_NETWORK_INFO_ATTESTATION_V1"
PRODUCTION_RC_RUNTIME_ROOTS = {
    "windows-x86_64": "commonfoundry-rc-runtime-windows-x86_64",
    "linux-x86_64": "commonfoundry-rc-runtime-linux-x86_64",
}
PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY = "production-v3"
PRODUCTION_V3_PACKAGE_BANK = "MODEL-V2.bank"
PRODUCTION_V3_PACKAGE_MANIFEST = "MODEL-V2.manifest.json"
PRODUCTION_V3_PACKAGE_RECORD_V2 = "DORY-V3-MODEL-RECORD-V2.json"
INSECURE_DEV_REWARD_DESTINATIONS = {
    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
    "6360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7",
}
PRODUCTION_RC_SERVICE_PORTS = {
    "rpc_port": 19_443,
    "p2p_port": 19_444,
    "pool_port": 19_445,
}
PRODUCTION_RC_VERSION_FILES = (
    "apps/wallet/package.json",
    "apps/wallet/src-tauri/Cargo.toml",
    "apps/wallet/src-tauri/tauri.conf.json",
    "apps/wallet/src-tauri/tauri.rcnet.conf.json",
    "crates/cmfd-miner/Cargo.toml",
    "crates/cmfd-node/Cargo.toml",
    "crates/cmfd-proof-worker/Cargo.toml",
)
SOURCE_ASSET_TOKEN_RE = re.compile(
    r"(?:^|[-_.])(source|sources|src)(?:[-_.]|$)", re.IGNORECASE
)
RECEIPT_FIELDS = (
    "SCHEMA",
    "TRUST_SCOPE",
    "KIND",
    "GIT_COMMIT",
    "SOURCE_FILES",
    "SOURCE_TREE_SHA256",
    "BUILD_SCRIPT",
    "BUILD_SCRIPT_SHA256",
    "LIBRARY_NAME",
    "LIBRARY_SHA256",
    "LIBRARY_SIZE",
    "TOOLCHAIN",
    "TARGET",
    "ARCHITECTURES",
    "SOURCE_DATE_EPOCH",
    "RECEIPT_SHA256",
)
NATIVE_SOURCES = {
    "cuda": (
        "gpu/CMakeLists.txt",
        "gpu/forgematrix_v2_miner.cu",
        "gpu/forgematrix_v2_tensor_core.cu",
    ),
    "opencl": (
        "gpu/CMakeLists.txt",
        "gpu/forgematrix_v2_opencl.cpp",
    ),
}
DEB_AR_MEMBERS = ("debian-binary", "control.tar.gz", "data.tar.gz")


class IntegrityError(RuntimeError):
    """An input failed a release-integrity invariant."""


def is_production_rc_label(label: str) -> bool:
    normalized = label.strip().lower()
    if not normalized or "devnet" in normalized or "testnet" in normalized:
        return False
    tokens = [token for token in re.split(r"[^a-z0-9]+", normalized) if token]
    return (
        "production-rc" in normalized
        or "production_rc" in normalized
        or "mainnet-rc" in normalized
        or any(re.fullmatch(r"rc[0-9]*", token) for token in tokens)
    )


def reject_production_rc_source_assets(stage_files: dict[str, Path]) -> None:
    """Keep reviewed binary stages from accidentally carrying source bundles."""
    for name in stage_files:
        normalized = name.strip().lower()
        if (
            SOURCE_ASSET_TOKEN_RE.search(normalized)
            or normalized in {"cargo.toml", "cargo.lock"}
            or normalized.endswith((".crate", ".rs"))
        ):
            raise IntegrityError(
                f"production RC binary release contains a source-like asset: {name}"
            )


def _bounded_json_object(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    with _stable_regular_handle(path, label) as (_, handle, _):
        data = handle.read(MAX_RELEASE_GATE_JSON_BYTES + 1)
    if len(data) > MAX_RELEASE_GATE_JSON_BYTES:
        raise IntegrityError(f"{label} exceeds its size limit")
    try:
        value = _json_object_bytes(data, label)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrityError(f"{label} is not valid UTF-8 JSON") from error
    return value, data


def _json_object_bytes(data: bytes, label: str) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise IntegrityError(f"{label} repeats JSON field {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            data.decode("utf-8", "strict"), object_pairs_hook=unique_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrityError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise IntegrityError(f"{label} must contain a JSON object")
    return value


def _runtime_package_paths(platform: str) -> tuple[set[str], str]:
    if platform == "windows-x86_64":
        suffix = ".exe"
    elif platform == "linux-x86_64":
        suffix = ""
    else:  # pragma: no cover - callers use the two frozen release targets.
        raise IntegrityError(f"unsupported production runtime platform: {platform}")
    worker = f"cmfd-proof-worker{suffix}"
    return (
        {
            f"cmfd-node{suffix}",
            f"common-foundry-wallet{suffix}",
            worker,
            f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/{PRODUCTION_V3_PACKAGE_BANK}",
            f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/{PRODUCTION_V3_PACKAGE_MANIFEST}",
            f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/{PRODUCTION_V3_PACKAGE_RECORD_V2}",
        },
        worker,
    )


def _runtime_package_root(platform: str) -> str:
    try:
        return PRODUCTION_RC_RUNTIME_ROOTS[platform]
    except KeyError as error:  # pragma: no cover - callers use frozen targets.
        raise IntegrityError(f"unsupported production runtime platform: {platform}") from error


def _runtime_member_relative(
    name: str, *, root: str | None, expected_root: str
) -> tuple[str, str]:
    if (
        "\\" in name
        or "\x00" in name
        or name.startswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise IntegrityError("production runtime package has an unsafe member name")
    raw = name[:-1] if name.endswith("/") else name
    parts = raw.split("/")
    if not raw or any(part in ("", ".", "..") or ":" in part for part in parts):
        raise IntegrityError("production runtime package has an unsafe member name")
    selected_root = parts[0]
    if selected_root != expected_root:
        raise IntegrityError(
            f"production runtime package root directory must be {expected_root}"
        )
    if root is not None and selected_root != root:
        raise IntegrityError("production runtime package has more than one root directory")
    if len(parts) == 1:
        return selected_root, ""
    return selected_root, PurePosixPath(*parts[1:]).as_posix()


def _stream_sha256(
    stream: object,
    *,
    expected_size: int,
    maximum_size: int,
    label: str,
    capture_bytes: int,
) -> tuple[int, str, str, bytes]:
    if expected_size < 0 or expected_size > maximum_size:
        raise IntegrityError(f"{label} exceeds its size limit")
    digest = hashlib.sha256()
    if blake3 is None:
        raise IntegrityError(
            "ProductionV3 package inspection requires the pinned Python blake3 dependency"
        )
    blake3_digest = blake3.blake3()
    count = 0
    captured = bytearray()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        count += len(chunk)
        if count > maximum_size:
            raise IntegrityError(f"{label} exceeds its size limit")
        digest.update(chunk)
        blake3_digest.update(chunk)
        if len(captured) < capture_bytes:
            captured.extend(chunk[: capture_bytes - len(captured)])
    if count != expected_size:
        raise IntegrityError(f"{label} size changed while it was inspected")
    return count, digest.hexdigest(), blake3_digest.hexdigest(), bytes(captured)


def _runtime_member_limit(relative: str) -> int:
    if relative.endswith((PRODUCTION_V3_PACKAGE_MANIFEST, PRODUCTION_V3_PACKAGE_RECORD_V2)):
        return MAX_RELEASE_GATE_JSON_BYTES
    if relative.startswith(f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/"):
        return MAX_RUNTIME_ARTIFACT_BYTES
    return MAX_RUNTIME_BINARY_BYTES


def _zip64_extra(member: zipfile.ZipInfo) -> bytes:
    values: list[int] = []
    if member.file_size > zipfile.ZIP64_LIMIT or member.compress_size > zipfile.ZIP64_LIMIT:
        values.extend((member.file_size, member.compress_size))
    if member.header_offset > zipfile.ZIP64_LIMIT:
        values.append(member.header_offset)
    if not values:
        return b""
    return struct.pack(f"<HH{'Q' * len(values)}", 1, 8 * len(values), *values)


def _validate_zip_framing(
    handle: object,
    label: str,
    *,
    maximum_entries: int = MAX_ARCHIVE_MEMBERS,
    maximum_central_bytes: int = MAX_ZIP_CENTRAL_DIRECTORY_BYTES,
) -> tuple[int, int, int]:
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size < 26:
        raise IntegrityError(f"{label} is too short")
    handle.seek(0)
    if handle.read(4) != b"PK\x03\x04":
        raise IntegrityError(f"{label} has a prefix or invalid first local header")
    handle.seek(-22, os.SEEK_END)
    end = handle.read(22)
    if len(end) != 22 or end[:4] != b"PK\x05\x06" or end[-2:] != b"\0\0":
        raise IntegrityError(f"{label} has a comment, trailer, or invalid endpoint")
    _, disk, central_disk, disk_entries, total_entries, central_size, central_offset, _ = (
        struct.unpack("<4sHHHHIIH", end)
    )
    end_offset = size - 22
    uses_zip64 = (
        disk_entries == 0xFFFF
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    )
    locator_offset = end_offset - 20
    if locator_offset >= 0:
        handle.seek(locator_offset)
        locator = handle.read(20)
    else:
        locator = b""
    uses_zip64 = uses_zip64 or (
        len(locator) == 20 and locator[:4] == b"PK\x06\x07"
    )
    if uses_zip64:
        if len(locator) != 20 or locator[:4] != b"PK\x06\x07":
            raise IntegrityError(f"{label} has invalid ZIP64 framing")
        _, locator_disk, zip64_offset, total_disks = struct.unpack("<4sIQI", locator)
        handle.seek(zip64_offset)
        zip64_end = handle.read(56)
        if len(zip64_end) != 56 or zip64_end[:4] != b"PK\x06\x06":
            raise IntegrityError(f"{label} has invalid ZIP64 endpoint")
        (
            _,
            record_size,
            _,
            _,
            zip64_disk,
            zip64_central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
        ) = struct.unpack("<4sQHHIIQQQQ", zip64_end)
        if (
            record_size != 44
            or locator_disk != 0
            or total_disks != 1
            or zip64_disk != 0
            or zip64_central_disk != 0
            or disk_entries != total_entries
            or zip64_offset + 56 != locator_offset
            or disk != 0
            or central_disk != 0
        ):
            raise IntegrityError(f"{label} has noncanonical ZIP64 metadata")
        logical_central_end = zip64_offset
    else:
        if disk != 0 or central_disk != 0 or disk_entries != total_entries:
            raise IntegrityError(f"{label} is a multi-disk or invalid ZIP")
        logical_central_end = end_offset
    if total_entries > maximum_entries:
        raise IntegrityError(f"{label} has too many entries")
    if (
        central_size > maximum_central_bytes
        or central_size < total_entries * 46
    ):
        raise IntegrityError(f"{label} central directory exceeds its bounds")
    if central_offset + central_size != logical_central_end:
        raise IntegrityError(f"{label} has bytes outside its logical ZIP endpoint")
    handle.seek(0)
    return central_offset, central_size, total_entries


def _validate_zip_local_layout(
    handle: object,
    *,
    members: list[zipfile.ZipInfo],
    central_offset: int,
    central_size: int,
    expected_entries: int,
    label: str,
) -> None:
    if len(members) != expected_entries:
        raise IntegrityError(f"{label} entry count does not match its endpoint")
    ordered = sorted(members, key=lambda member: member.header_offset)
    cursor = 0
    for member in ordered:
        if member.header_offset != cursor:
            raise IntegrityError(f"{label} has a gap or unknown local record")
        handle.seek(cursor)
        header = handle.read(30)
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise IntegrityError(f"{label} has an invalid local header")
        (
            _,
            _,
            flags,
            compression,
            _,
            _,
            crc,
            compressed_size,
            file_size,
            name_length,
            extra_length,
        ) = struct.unpack("<4sHHHHHIIIHH", header)
        name = handle.read(name_length)
        extra = handle.read(extra_length)
        expected_name = member.filename.encode("ascii", "strict")
        if (
            name != expected_name
            or flags != 0
            or compression != zipfile.ZIP_DEFLATED
            or crc != member.CRC
        ):
            raise IntegrityError(f"{label} has noncanonical local metadata")
        expected_extra = b""
        if file_size == 0xFFFFFFFF and compressed_size == 0xFFFFFFFF:
            expected_extra = struct.pack(
                "<HHQQ", 1, 16, member.file_size, member.compress_size
            )
        elif file_size != member.file_size or compressed_size != member.compress_size:
            raise IntegrityError(f"{label} local sizes do not match its directory")
        elif (
            member.file_size > zipfile.ZIP64_LIMIT
            or member.compress_size > zipfile.ZIP64_LIMIT
        ):
            # Seekable ZipFile writers may patch the 32-bit local sizes while
            # retaining the ZIP64 size record selected before compression.
            expected_extra = struct.pack(
                "<HHQQ", 1, 16, member.file_size, member.compress_size
            )
        if extra != expected_extra:
            raise IntegrityError(f"{label} has noncanonical local ZIP64 metadata")
        cursor += 30 + name_length + extra_length + member.compress_size
    if cursor != central_offset:
        raise IntegrityError(f"{label} has bytes before its central directory")
    cursor = central_offset
    for member in members:
        handle.seek(cursor)
        header = handle.read(46)
        if len(header) != 46 or header[:4] != b"PK\x01\x02":
            raise IntegrityError(f"{label} has an invalid central-directory record")
        flags, compression = struct.unpack_from("<HH", header, 8)
        crc, compressed_size, file_size = struct.unpack_from("<III", header, 16)
        name_length, extra_length, comment_length, disk_start = struct.unpack_from(
            "<HHHH", header, 28
        )
        external_attributes, local_offset = struct.unpack_from("<II", header, 38)
        name = handle.read(name_length)
        extra = handle.read(extra_length)
        comment = handle.read(comment_length)
        if (
            name != member.filename.encode("ascii", "strict")
            or extra != member.extra
            or comment != member.comment
            or flags != member.flag_bits
            or compression != member.compress_type
            or crc != member.CRC
            or compressed_size not in (member.compress_size, 0xFFFFFFFF)
            or file_size not in (member.file_size, 0xFFFFFFFF)
            or disk_start != 0
            or external_attributes != member.external_attr
            or local_offset not in (member.header_offset, 0xFFFFFFFF)
        ):
            raise IntegrityError(f"{label} has noncanonical central-directory metadata")
        cursor += 46 + name_length + extra_length + comment_length
    if cursor != central_offset + central_size:
        raise IntegrityError(f"{label} has an unknown central-directory record")
    handle.seek(0)


def _tar_logical_end(member: tarfile.TarInfo) -> int:
    if member.isdir():
        return member.offset + TAR_BLOCK_BYTES
    return member.offset_data + (
        (member.size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES
    ) * TAR_BLOCK_BYTES


def _validate_tar_member_offsets(members: list[tarfile.TarInfo], label: str) -> int:
    cursor = 0
    for member in members:
        if member.offset != cursor:
            raise IntegrityError(f"{label} has a gap or hidden metadata record")
        cursor = _tar_logical_end(member)
    return cursor


def _canonical_gzip_epoch(
    handle: object, label: str, expected_epoch: int | None = None
) -> int:
    handle.seek(0)
    header = handle.read(10)
    if (
        len(header) != 10
        or header[:3] != b"\x1f\x8b\x08"
        or header[3] != 0
        or header[8] != 2
        or header[9] != 255
    ):
        raise IntegrityError(f"{label} has a noncanonical gzip header")
    epoch = struct.unpack_from("<I", header, 4)[0]
    if expected_epoch is not None and epoch != expected_epoch:
        raise IntegrityError(f"{label} has a noncanonical gzip header")
    handle.seek(0)
    return epoch


class _CappedGzipReader:
    def __init__(
        self, handle: object, label: str, expected_epoch: int | None = None
    ) -> None:
        self.handle = handle
        self.label = label
        self.gzip_epoch = _canonical_gzip_epoch(handle, label, expected_epoch)
        self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.compressed_digest = hashlib.sha256()
        self.pending = b""
        self.decoded = bytearray()
        self.complete = False

    def _fill(self, maximum_output: int) -> None:
        maximum_output = min(MAX_GZIP_OUTPUT_CHUNK_BYTES, max(1, maximum_output))
        while not self.decoded and not self.complete:
            if self.pending:
                before = len(self.pending)
                try:
                    decoded = self.decoder.decompress(
                        self.pending, maximum_output
                    )
                except zlib.error as error:
                    raise IntegrityError(
                        f"{self.label} has invalid gzip framing"
                    ) from error
                self.pending = self.decoder.unconsumed_tail
                if self.decoder.unused_data:
                    raise IntegrityError(
                        f"{self.label} has a concatenated stream or trailer"
                    )
                if decoded:
                    self.decoded.extend(decoded)
                    return
                if self.pending and len(self.pending) == before:
                    raise IntegrityError(
                        f"{self.label} gzip decoder made no progress"
                    )
                continue
            if self.decoder.eof:
                if self.handle.read(1):
                    raise IntegrityError(
                        f"{self.label} has a concatenated stream or trailer"
                    )
                self.complete = True
                return
            chunk = self.handle.read(MAX_GZIP_OUTPUT_CHUNK_BYTES)
            if chunk:
                self.compressed_digest.update(chunk)
                self.pending = chunk
                continue
            try:
                decoded = self.decoder.decompress(b"", maximum_output)
            except zlib.error as error:
                raise IntegrityError(
                    f"{self.label} has invalid gzip framing"
                ) from error
            if self.decoder.unused_data:
                raise IntegrityError(
                    f"{self.label} has a concatenated stream or trailer"
                )
            if decoded:
                self.decoded.extend(decoded)
                return
            if not self.decoder.eof:
                raise IntegrityError(f"{self.label} has an incomplete gzip stream")

    def read(self, maximum_bytes: int) -> bytes:
        if maximum_bytes <= 0:
            return b""
        if not self.decoded:
            self._fill(maximum_bytes)
        count = min(maximum_bytes, len(self.decoded))
        value = bytes(self.decoded[:count])
        del self.decoded[:count]
        return value

    def read_exact(self, count: int) -> bytes:
        value = bytearray()
        while len(value) < count:
            chunk = self.read(count - len(value))
            if not chunk:
                raise IntegrityError(f"{self.label} tar stream is truncated")
            value.extend(chunk)
        return bytes(value)

    def finish(self) -> str:
        if self.read(1):
            raise IntegrityError(f"{self.label} has a noncanonical tar/gzip endpoint")
        if not self.complete:
            raise IntegrityError(f"{self.label} has an incomplete gzip stream")
        return self.compressed_digest.hexdigest()


def _canonical_tar_octal(field: bytes, label: str) -> int:
    if (
        len(field) < 2
        or field[-1:] != b"\0"
        or any(value < ord("0") or value > ord("7") for value in field[:-1])
    ):
        raise IntegrityError(f"{label} has a noncanonical tar numeric field")
    return int(field[:-1], 8)


def _canonical_tar_ascii(field: bytes, label: str) -> str:
    terminator = field.find(b"\0")
    raw = field if terminator < 0 else field[:terminator]
    if terminator >= 0 and any(field[terminator:]):
        raise IntegrityError(f"{label} has a noncanonical tar text field")
    try:
        return raw.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise IntegrityError(f"{label} has a non-ASCII tar text field") from error


def _canonical_ustar_name_fields(name: str, label: str) -> tuple[bytes, bytes]:
    try:
        encoded_name = name.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise IntegrityError(f"{label} expected tar path is not ASCII") from error
    prefix = b""
    if len(encoded_name) > 100:
        components = name.split("/")
        for index in range(1, len(components)):
            candidate_prefix = "/".join(components[:index]).encode("ascii")
            candidate_name = "/".join(components[index:]).encode("ascii")
            if len(candidate_prefix) <= 155 and len(candidate_name) <= 100:
                prefix = candidate_prefix
                encoded_name = candidate_name
                break
        else:
            raise IntegrityError(f"{label} expected tar path does not fit USTAR")
    return encoded_name.ljust(100, b"\0"), prefix.ljust(155, b"\0")


def _scan_canonical_tar_gz(
    handle: object,
    *,
    expected: list[tuple[str, bool, int | None, int, int]],
    label: str,
    maximum_members: int,
    expected_epoch: int | None = None,
) -> tuple[list[tarfile.TarInfo], int, int, str]:
    if len(expected) > maximum_members:
        raise IntegrityError(f"{label} has too many expected members")
    reader = _CappedGzipReader(handle, label, expected_epoch)
    members: list[tarfile.TarInfo] = []
    mtimes: set[int] = set()
    cursor = 0
    while True:
        header = reader.read_exact(TAR_BLOCK_BYTES)
        if not any(header):
            if any(reader.read_exact(TAR_BLOCK_BYTES)):
                raise IntegrityError(f"{label} has a noncanonical tar endpoint")
            logical_end = cursor
            break
        checksum = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
        encoded_checksum = f"{checksum:06o}\0 ".encode("ascii")
        if len(encoded_checksum) != 8 or header[148:156] != encoded_checksum:
            raise IntegrityError(f"{label} has an invalid tar header checksum")
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            raise IntegrityError(f"{label} does not use canonical USTAR framing")
        member_type = header[156:157]
        if member_type not in (tarfile.REGTYPE, tarfile.DIRTYPE):
            raise IntegrityError(
                f"{label} tar member has the wrong type; PAX/GNU extensions and "
                "non-regular members are forbidden"
            )
        index = len(members)
        if index >= len(expected) or index >= maximum_members:
            raise IntegrityError(f"{label} entries are missing, reordered, or unexpected")
        expected_name, is_directory, exact_size, maximum_size, expected_mode = expected[
            index
        ]
        name = _canonical_tar_ascii(header[:100], label)
        prefix = _canonical_tar_ascii(header[345:500], label)
        physical_name = f"{prefix}/{name}" if prefix else name
        expected_physical_name = (
            f"{expected_name}/" if is_directory else expected_name
        )
        expected_type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
        if physical_name != expected_physical_name:
            raise IntegrityError(f"{label} entries are missing, reordered, or unexpected")
        canonical_name, canonical_prefix = _canonical_ustar_name_fields(
            expected_physical_name, label
        )
        if header[:100] != canonical_name or header[345:500] != canonical_prefix:
            raise IntegrityError(
                f"{label} tar name/prefix split is not canonical: {expected_name}"
            )
        if member_type != expected_type:
            raise IntegrityError(f"{label} tar member has the wrong type: {expected_name}")
        mode = _canonical_tar_octal(header[100:108], label)
        uid = _canonical_tar_octal(header[108:116], label)
        gid = _canonical_tar_octal(header[116:124], label)
        size = _canonical_tar_octal(header[124:136], label)
        mtime = _canonical_tar_octal(header[136:148], label)
        if (
            mode != expected_mode
            or uid != 0
            or gid != 0
            or any(header[157:257])
            or any(header[265:345])
            or any(header[500:512])
        ):
            raise IntegrityError(f"{label} tar member metadata is not canonical")
        if expected_epoch is not None and mtime != expected_epoch:
            raise IntegrityError(f"{label} tar timestamp is not canonical")
        if exact_size is not None and size != exact_size:
            raise IntegrityError(f"{label} tar member has the wrong size: {expected_name}")
        if size > maximum_size:
            raise IntegrityError(f"{label} tar member exceeds its size limit: {expected_name}")
        mtimes.add(mtime)
        member = tarfile.TarInfo(expected_name)
        member.type = member_type
        member.mode = mode
        member.uid = uid
        member.gid = gid
        member.size = size
        member.mtime = mtime
        member.offset = cursor
        member.offset_data = cursor + TAR_BLOCK_BYTES
        members.append(member)
        remaining = size
        while remaining:
            chunk = reader.read(min(remaining, MAX_GZIP_OUTPUT_CHUNK_BYTES))
            if not chunk:
                raise IntegrityError(f"{label} tar member payload is truncated")
            remaining -= len(chunk)
        padding = (-size) % TAR_BLOCK_BYTES
        if padding and any(reader.read_exact(padding)):
            raise IntegrityError(f"{label} has nonzero tar padding")
        cursor += TAR_BLOCK_BYTES + size + padding
    if len(members) != len(expected):
        raise IntegrityError(f"{label} entries are missing, reordered, or unexpected")
    minimum_end = logical_end + 2 * TAR_BLOCK_BYTES
    expected_end = (
        (minimum_end + TAR_RECORD_BYTES - 1) // TAR_RECORD_BYTES
    ) * TAR_RECORD_BYTES
    trailing_padding = expected_end - minimum_end
    while trailing_padding:
        chunk = reader.read(min(trailing_padding, MAX_GZIP_OUTPUT_CHUNK_BYTES))
        if not chunk:
            raise IntegrityError(f"{label} tar endpoint is truncated")
        if any(chunk):
            raise IntegrityError(f"{label} has nonzero tar padding")
        trailing_padding -= len(chunk)
    digest = reader.finish()
    if len(mtimes) != 1:
        raise IntegrityError(f"{label} tar timestamps are not canonical")
    epoch = next(iter(mtimes))
    if reader.gzip_epoch != epoch:
        raise IntegrityError(f"{label} gzip and tar timestamps do not match")
    handle.seek(0)
    return members, logical_end, epoch, digest


def _validate_gzip_tar_framing(
    handle: object,
    *,
    members: list[tarfile.TarInfo],
    logical_end: int,
    label: str,
    expected_epoch: int | None = None,
) -> str:
    _canonical_gzip_epoch(handle, label, expected_epoch)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    compressed_digest = hashlib.sha256()
    total = 0
    tail = bytearray()
    minimum_end = logical_end + 2 * TAR_BLOCK_BYTES
    expected_end = (
        (minimum_end + TAR_RECORD_BYTES - 1) // TAR_RECORD_BYTES
    ) * TAR_RECORD_BYTES
    zero_ranges = sorted(
        [
            (member.offset_data + member.size, _tar_logical_end(member))
            for member in members
            if member.isreg() and member.size % TAR_BLOCK_BYTES
        ]
        + [(logical_end, expected_end)]
    )
    zero_index = 0

    def accept_decoded(decoded: bytes) -> None:
        nonlocal total, zero_index
        remaining = expected_end - total
        if len(decoded) > remaining:
            raise IntegrityError(f"{label} decompressed output exceeds its bound")
        chunk_start = total
        chunk_end = chunk_start + len(decoded)
        while zero_index < len(zero_ranges) and zero_ranges[zero_index][1] <= chunk_start:
            zero_index += 1
        check_index = zero_index
        while check_index < len(zero_ranges) and zero_ranges[check_index][0] < chunk_end:
            zero_start, zero_end = zero_ranges[check_index]
            overlap_start = max(chunk_start, zero_start)
            overlap_end = min(chunk_end, zero_end)
            if any(decoded[overlap_start - chunk_start : overlap_end - chunk_start]):
                raise IntegrityError(f"{label} has nonzero tar padding")
            if zero_end > chunk_end:
                break
            check_index += 1
        zero_index = check_index
        total = chunk_end
        tail.extend(decoded)
        if len(tail) > 2 * TAR_RECORD_BYTES:
            del tail[: len(tail) - 2 * TAR_RECORD_BYTES]

    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        compressed_digest.update(chunk)
        pending = chunk
        while pending:
            remaining = expected_end - total
            if remaining < 0:
                raise IntegrityError(f"{label} decompressed output exceeds its bound")
            maximum_output = min(MAX_GZIP_OUTPUT_CHUNK_BYTES, remaining + 1)
            before = len(pending)
            try:
                decoded = decoder.decompress(pending, maximum_output)
            except zlib.error as error:
                raise IntegrityError(f"{label} has invalid gzip framing") from error
            pending = decoder.unconsumed_tail
            accept_decoded(decoded)
            if decoder.unused_data:
                raise IntegrityError(f"{label} has a concatenated stream or trailer")
            if pending and not decoded and len(pending) == before:
                raise IntegrityError(f"{label} gzip decoder made no progress")
    while True:
        remaining = expected_end - total
        if remaining < 0:
            raise IntegrityError(f"{label} decompressed output exceeds its bound")
        try:
            decoded = decoder.decompress(
                b"", min(MAX_GZIP_OUTPUT_CHUNK_BYTES, remaining + 1)
            )
        except zlib.error as error:
            raise IntegrityError(f"{label} has invalid gzip framing") from error
        accept_decoded(decoded)
        if decoder.unused_data:
            raise IntegrityError(f"{label} has a concatenated stream or trailer")
        if not decoded:
            break
    padding = total - logical_end
    if (
        not decoder.eof
        or decoder.unused_data
        or total != expected_end
        or padding < 2 * TAR_BLOCK_BYTES
        or padding > len(tail)
        or any(tail[-padding:])
    ):
        raise IntegrityError(f"{label} has a noncanonical tar/gzip endpoint")
    handle.seek(0)
    return compressed_digest.hexdigest()


def _validate_runtime_member_metadata(
    *, platform: str, member: object, relative: str, is_directory: bool
) -> None:
    expected_mode = 0o755 if is_directory or not relative.startswith(
        f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/"
    ) else 0o644
    if platform == "windows-x86_64":
        if not isinstance(member, zipfile.ZipInfo):  # pragma: no cover
            raise IntegrityError("internal ZIP member contract is invalid")
        expected_type = stat.S_IFDIR if is_directory else stat.S_IFREG
        expected_attributes = ((expected_type | expected_mode) & 0xFFFF) << 16
        if is_directory:
            expected_attributes |= 0x10
        if (
            member.create_system != 3
            or member.external_attr != expected_attributes
            or member.compress_type != zipfile.ZIP_DEFLATED
            or member.comment
            or member.extra != _zip64_extra(member)
            or member.flag_bits != 0
            or (is_directory and (member.file_size != 0 or member.CRC != 0))
        ):
            raise IntegrityError(
                f"{platform} runtime package metadata is not canonical: {member.filename}"
            )
        return
    if not isinstance(member, tarfile.TarInfo):  # pragma: no cover
        raise IntegrityError("internal tar member contract is invalid")
    expected_type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
    if (
        member.type != expected_type
        or member.uid != 0
        or member.gid != 0
        or member.uname
        or member.gname
        or member.mode != expected_mode
        or member.linkname
        or member.pax_headers
        or member.devmajor != 0
        or member.devminor != 0
        or (is_directory and member.size != 0)
    ):
        raise IntegrityError(
            f"{platform} runtime package metadata is not canonical: {member.name}"
        )


def _inspect_runtime_members(
    *, platform: str, members: object, open_member: object
) -> dict[str, dict[str, object]]:
    expected, _ = _runtime_package_paths(platform)
    expected_root = _runtime_package_root(platform)
    expected_order = sorted(
        expected | {"", PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}
    )
    rows: dict[str, dict[str, object]] = {}
    root: str | None = None
    seen: set[str] = set()
    seen_order: list[str] = []
    for member, name, is_directory, is_regular, size in members:
        root, relative = _runtime_member_relative(
            name, root=root, expected_root=expected_root
        )
        if relative in seen:
            raise IntegrityError(f"{platform} runtime package has duplicate members")
        seen.add(relative)
        seen_order.append(relative)
        _validate_runtime_member_metadata(
            platform=platform,
            member=member,
            relative=relative,
            is_directory=is_directory,
        )
        if is_directory:
            if relative not in ("", PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY):
                raise IntegrityError(f"{platform} runtime package has an unexpected directory")
            continue
        if not is_regular or not relative or relative in rows:
            raise IntegrityError(f"{platform} runtime package contains a linked or special member")
        if relative not in expected:
            raise IntegrityError(f"{platform} runtime package has an unexpected member")
        source = open_member(member)
        if source is None:
            raise IntegrityError(f"{platform} runtime member cannot be read")
        with source:
            capture_bytes = (
                size
                if relative.endswith(
                    (PRODUCTION_V3_PACKAGE_MANIFEST, PRODUCTION_V3_PACKAGE_RECORD_V2)
                )
                else MAX_EXECUTABLE_HEADER_BYTES
                if not relative.startswith(f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/")
                else 0
            )
            actual_size, digest, blake3_hash, captured = _stream_sha256(
                source,
                expected_size=size,
                maximum_size=_runtime_member_limit(relative),
                label=f"{platform} runtime {relative}",
                capture_bytes=capture_bytes,
            )
        rows[relative] = {
            "bytes": actual_size,
            "sha256": digest,
            "blake3": blake3_hash,
            "captured": captured,
        }
    if seen_order != expected_order or set(rows) != expected:
        raise IntegrityError(
            f"{platform} runtime package layout mismatch; "
            f"missing={sorted(expected - set(rows))}, unexpected={sorted(set(rows) - expected)}"
        )
    return rows


def _preflight_runtime_tar_gz(
    handle: object,
    platform: str,
    expected_artifact_sizes: dict[str, int] | None = None,
) -> tuple[list[tarfile.TarInfo], int, int, str]:
    expected, _ = _runtime_package_paths(platform)
    expected_root = _runtime_package_root(platform)
    expected_order = sorted(
        expected | {"", PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}
    )
    expected_artifact_sizes = expected_artifact_sizes or {}
    specifications: list[tuple[str, bool, int | None, int, int]] = []
    for relative in expected_order:
        is_directory = relative in (
            "",
            PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY,
        )
        name = expected_root if not relative else f"{expected_root}/{relative}"
        exact_size = 0 if is_directory else expected_artifact_sizes.get(relative)
        maximum_size = 0 if is_directory else _runtime_member_limit(relative)
        mode = 0o755 if is_directory or not relative.startswith(
            f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/"
        ) else 0o644
        specifications.append(
            (name, is_directory, exact_size, maximum_size, mode)
        )
    return _scan_canonical_tar_gz(
        handle,
        expected=specifications,
        label="Linux runtime tar.gz",
        maximum_members=MAX_RUNTIME_ARCHIVE_MEMBERS,
    )


def _inspect_runtime_package_archive(
    path: Path,
    platform: str,
    expected_artifact_sizes: dict[str, int] | None = None,
) -> dict[str, dict[str, object]]:
    package = _regular_file(path, f"{platform} runtime package")
    try:
        if platform == "windows-x86_64":
            with _stable_regular_handle(
                package, "Windows runtime ZIP"
            ) as (_, raw, _):
                initial_digest = _sha256_handle(raw)
                central_offset, central_size, expected_entries = _validate_zip_framing(
                    raw,
                    "Windows runtime ZIP",
                    maximum_entries=MAX_RUNTIME_ARCHIVE_MEMBERS,
                    maximum_central_bytes=MAX_RUNTIME_ZIP_CENTRAL_DIRECTORY_BYTES,
                )
                with zipfile.ZipFile(raw, "r") as archive:
                    if archive.comment:
                        raise IntegrityError("Windows runtime ZIP has a comment")
                    infos = archive.infolist()
                    if len(infos) > MAX_RUNTIME_ARCHIVE_MEMBERS:
                        raise IntegrityError("Windows runtime ZIP has too many members")
                    _validate_zip_local_layout(
                        raw,
                        members=infos,
                        central_offset=central_offset,
                        central_size=central_size,
                        expected_entries=expected_entries,
                        label="Windows runtime ZIP",
                    )
                    members = []
                    for member in infos:
                        mode = (member.external_attr >> 16) & 0xFFFF
                        file_type = stat.S_IFMT(mode)
                        regular = file_type in (0, stat.S_IFREG)
                        members.append(
                            (
                                member,
                                member.filename,
                                member.is_dir(),
                                regular,
                                member.file_size,
                            )
                        )
                    rows = _inspect_runtime_members(
                        platform=platform,
                        members=members,
                        open_member=lambda member: archive.open(member, "r"),
                    )
                if _sha256_handle(raw) != initial_digest:
                    raise IntegrityError("Windows runtime ZIP changed during inspection")
                return rows
        with _stable_regular_handle(
            package, "Linux runtime tar.gz"
        ) as (_, raw, _):
            initial_digest = _sha256_handle(raw)
            _, _, _, framing_digest = _preflight_runtime_tar_gz(
                raw, platform, expected_artifact_sizes
            )
            if framing_digest != initial_digest:
                raise IntegrityError("Linux runtime tar.gz changed during framing validation")
            raw.seek(0)
            with tarfile.open(fileobj=raw, mode="r|gz") as archive:
                rows = _inspect_runtime_members(
                    platform=platform,
                    members=(
                        (
                            member,
                            member.name,
                            member.type == tarfile.DIRTYPE,
                            member.type == tarfile.REGTYPE,
                            member.size,
                        )
                        for member in archive
                    ),
                    open_member=archive.extractfile,
                )
            if _sha256_handle(raw) != initial_digest:
                raise IntegrityError("Linux runtime tar.gz changed during inspection")
            return rows
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise IntegrityError(f"cannot inspect {platform} runtime package: {error}") from error


def _compiled_runtime_worker(proof: dict[str, object], platform: str) -> str:
    workers = _require_exact_fields(
        proof.get("runtime_verifier_workers"),
        {"windows_x86_64_sha256", "linux_x86_64_sha256"},
        "compiled runtime proof-worker identities",
    )
    return _require_hex256(
        workers[f"{platform.replace('-', '_')}_sha256"],
        f"compiled {platform} runtime proof worker",
        reject_repeated=True,
    )


def _validate_pe_x86_64(header: bytes, size: int, label: str) -> None:
    if len(header) < 0x40 or header[:2] != b"MZ":
        raise IntegrityError(f"{label} is not a valid PE executable")
    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(header):
        raise IntegrityError(f"{label} has an invalid PE header offset")
    if header[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise IntegrityError(f"{label} has an invalid PE signature")
    machine, section_count = struct.unpack_from("<HH", header, pe_offset + 4)
    if machine != 0x8664:
        raise IntegrityError(f"{label} is not an x86-64 PE executable")
    optional_size, characteristics = struct.unpack_from("<HH", header, pe_offset + 20)
    optional_offset = pe_offset + 24
    section_table_end = optional_offset + optional_size + section_count * 40
    if (
        section_count == 0
        or section_count > 96
        or optional_size < 0x70
        or optional_offset + optional_size > size
        or optional_offset + optional_size > len(header)
        or section_table_end > size
        or section_table_end > len(header)
    ):
        raise IntegrityError(f"{label} has an invalid PE32+ executable header")
    entrypoint = struct.unpack_from("<I", header, optional_offset + 16)[0]
    section_alignment, file_alignment = struct.unpack_from(
        "<II", header, optional_offset + 32
    )
    image_size, headers_size = struct.unpack_from("<II", header, optional_offset + 56)
    if (
        struct.unpack_from("<H", header, optional_offset)[0] != 0x020B
        or not (characteristics & 0x0002)
        or characteristics & 0x2000
        or entrypoint == 0
        or file_alignment < 0x200
        or section_alignment < file_alignment
        or image_size == 0
        or headers_size < section_table_end
        or headers_size > size
    ):
        if characteristics & 0x2000:
            raise IntegrityError(f"{label} is a DLL, not an executable image")
        raise IntegrityError(f"{label} has an invalid PE32+ executable header")
    entrypoint_section = False
    for index in range(section_count):
        offset = optional_offset + optional_size + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", header, offset + 8
        )
        section_characteristics = struct.unpack_from("<I", header, offset + 36)[0]
        if raw_size and (raw_offset < headers_size or raw_offset + raw_size > size):
            raise IntegrityError(f"{label} has an invalid PE section range")
        span = max(virtual_size, raw_size)
        if (
            span
            and virtual_address <= entrypoint < virtual_address + span
            and section_characteristics & 0x20000000
        ):
            entrypoint_section = True
    if not entrypoint_section:
        raise IntegrityError(f"{label} PE entry point is not in executable code")


def _validate_elf_x86_64(header: bytes, size: int, label: str) -> None:
    if (
        len(header) < 64
        or header[:4] != b"\x7fELF"
        or header[4] != 2
        or header[5] != 1
        or header[6] != 1
    ):
        raise IntegrityError(f"{label} is not a valid 64-bit little-endian ELF executable")
    executable_type, machine, version = struct.unpack_from("<HHI", header, 16)
    entrypoint = struct.unpack_from("<Q", header, 24)[0]
    program_offset = struct.unpack_from("<Q", header, 32)[0]
    header_size, program_entry_size, program_count = struct.unpack_from("<HHH", header, 52)
    program_end = program_offset + program_entry_size * program_count
    if machine != 0x003E:
        raise IntegrityError(f"{label} is not an x86-64 ELF executable")
    if (
        executable_type not in (2, 3)
        or version != 1
        or header_size != 64
        or program_offset < header_size
        or program_entry_size < 56
        or program_count == 0
        or program_end > size
        or program_end > len(header)
    ):
        raise IntegrityError(f"{label} has an invalid ELF executable header")
    executable_load = False
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        segment_type, flags = struct.unpack_from("<II", header, offset)
        file_offset, virtual_address, _, file_size, memory_size, alignment = (
            struct.unpack_from("<QQQQQQ", header, offset + 8)
        )
        if segment_type != 1:
            continue
        if (
            file_offset + file_size > size
            or memory_size < file_size
            or alignment == 0
            or alignment & (alignment - 1)
        ):
            raise IntegrityError(f"{label} has an invalid ELF load segment")
        if (
            flags & 0x1
            and virtual_address <= entrypoint < virtual_address + memory_size
        ):
            executable_load = True
    if not executable_load:
        raise IntegrityError(f"{label} has no executable ELF entry point")


def _validate_runtime_rows(
    *,
    rows: dict[str, dict[str, object]],
    platform: str,
    staged_network_info: dict[str, object],
) -> None:
    _, worker_name = _runtime_package_paths(platform)
    for name in (
        worker_name,
        f"cmfd-node{'.exe' if platform == 'windows-x86_64' else ''}",
        f"common-foundry-wallet{'.exe' if platform == 'windows-x86_64' else ''}",
    ):
        header = rows[name]["captured"]
        if not isinstance(header, bytes):  # pragma: no cover - internal row contract.
            raise IntegrityError(f"{platform} runtime {name} header is unavailable")
        if platform == "windows-x86_64":
            _validate_pe_x86_64(header, rows[name]["bytes"], f"{platform} runtime {name}")
        else:
            _validate_elf_x86_64(header, rows[name]["bytes"], f"{platform} runtime {name}")

    proof = staged_network_info.get("proof_of_work")
    if not isinstance(proof, dict):
        raise IntegrityError("staged NETWORK-INFO proof identity is missing")
    expected_worker = _compiled_runtime_worker(proof, platform)
    if rows[worker_name]["sha256"] != expected_worker:
        raise IntegrityError(
            f"{platform} packaged proof worker does not match NETWORK-INFO.json"
        )

    pins = proof.get("artifacts")
    if not isinstance(pins, dict) or set(pins) != {"bank", "manifest", "record_v2"}:
        raise IntegrityError(f"{platform} runtime artifact identity pins are incomplete")
    file_names = {
        "bank": PRODUCTION_V3_PACKAGE_BANK,
        "manifest": PRODUCTION_V3_PACKAGE_MANIFEST,
        "record_v2": PRODUCTION_V3_PACKAGE_RECORD_V2,
    }
    labels = {"bank": "model bank", "manifest": "model manifest", "record_v2": "Record V2"}
    for role, file_name in file_names.items():
        pin = _require_exact_fields(
            pins.get(role), {"bytes", "blake3", "sha256"}, f"{platform} {role} pin"
        )
        try:
            expected_bytes = int(pin["bytes"])
        except (TypeError, ValueError) as error:
            raise IntegrityError(f"{platform} {role} byte length is invalid") from error
        if str(expected_bytes) != pin["bytes"] or expected_bytes <= 0:
            raise IntegrityError(f"{platform} {role} byte length is invalid")
        expected_blake3 = _require_hex256(
            pin["blake3"], f"{platform} {role} BLAKE3", reject_repeated=False
        )
        expected_sha256 = _require_hex256(
            pin["sha256"], f"{platform} {role} SHA-256", reject_repeated=False
        )
        relative = f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/{file_name}"
        row = rows[relative]
        if (
            row["bytes"] != expected_bytes
            or row["sha256"] != expected_sha256
            or row["blake3"] != expected_blake3
        ):
            raise IntegrityError(
                f"{platform} packaged {labels[role]} does not match NETWORK-INFO.json"
            )

    manifest_row = rows[
        f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/{PRODUCTION_V3_PACKAGE_MANIFEST}"
    ]
    record_row = rows[
        f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/{PRODUCTION_V3_PACKAGE_RECORD_V2}"
    ]
    manifest = _json_object_bytes(
        manifest_row["captured"], f"{platform} packaged model manifest"
    )
    record = _json_object_bytes(
        record_row["captured"], f"{platform} packaged Record V2"
    )
    _require_exact_fields(
        record,
        {
            "record_version",
            "suite_digest",
            "manifest",
            "manifest_digest",
            "model_identity",
            "model_identity_digest",
            "setup_identity",
            "padded_variables",
            "commitment_root",
            "record_digest",
        },
        f"{platform} packaged Record V2",
    )
    if record["manifest"] != manifest:
        raise IntegrityError(
            f"{platform} packaged model manifest does not match Record V2"
        )
    model = proof.get("model")
    for field in (
        "record_version",
        "record_digest",
        "manifest_digest",
        "model_identity_digest",
        "suite_digest",
        "setup_identity",
        "padded_variables",
    ):
        if not isinstance(model, dict) or model.get(field) != record[field]:
            raise IntegrityError(
                f"{platform} packaged Record V2 does not match NETWORK-INFO.json"
            )


def _validate_runtime_package(
    *,
    path: Path,
    platform: str,
    staged_network_info: dict[str, object],
) -> dict[str, dict[str, object]]:
    proof = staged_network_info.get("proof_of_work")
    pins = proof.get("artifacts") if isinstance(proof, dict) else None
    if not isinstance(pins, dict) or set(pins) != {"bank", "manifest", "record_v2"}:
        raise IntegrityError(f"{platform} runtime artifact identity pins are incomplete")
    expected_artifact_sizes: dict[str, int] = {}
    for role, file_name in (
        ("bank", PRODUCTION_V3_PACKAGE_BANK),
        ("manifest", PRODUCTION_V3_PACKAGE_MANIFEST),
        ("record_v2", PRODUCTION_V3_PACKAGE_RECORD_V2),
    ):
        pin = _require_exact_fields(
            pins.get(role), {"bytes", "blake3", "sha256"}, f"{platform} {role} pin"
        )
        try:
            expected_size = int(pin["bytes"])
        except (TypeError, ValueError) as error:
            raise IntegrityError(f"{platform} {role} byte length is invalid") from error
        relative = f"{PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY}/{file_name}"
        if (
            str(expected_size) != pin["bytes"]
            or expected_size <= 0
            or expected_size > _runtime_member_limit(relative)
        ):
            raise IntegrityError(f"{platform} {role} byte length is invalid")
        expected_artifact_sizes[relative] = expected_size
    rows = _inspect_runtime_package_archive(
        path, platform, expected_artifact_sizes
    )
    _validate_runtime_rows(
        rows=rows, platform=platform, staged_network_info=staged_network_info
    )
    return rows


def _validate_runtime_attestation(
    *,
    path: Path,
    platform: str,
    commit: str,
    rows: dict[str, dict[str, object]],
    staged_network_info: dict[str, object],
) -> None:
    attestation, _ = _bounded_json_object(
        path, f"{platform} packaged-node network-info attestation"
    )
    _require_exact_fields(
        attestation,
        {
            "schema",
            "platform",
            "source_commit",
            "node_sha256",
            "wallet_sha256",
            "worker_sha256",
            "network_info_sha256",
            "network_info_base64",
        },
        f"{platform} packaged-node network-info attestation",
    )
    if (
        attestation["schema"] != PRODUCTION_RC_RUNTIME_ATTESTATION_SCHEMA
        or attestation["platform"] != platform
        or attestation["source_commit"] != commit
    ):
        raise IntegrityError(f"{platform} packaged-node attestation identity is invalid")
    encoded = attestation["network_info_base64"]
    if not isinstance(encoded, str) or len(encoded) > 2 * MAX_RELEASE_GATE_JSON_BYTES:
        raise IntegrityError(f"{platform} attested network information is invalid")
    try:
        network_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IntegrityError(
            f"{platform} attested network information is not canonical base64"
        ) from error
    if base64.b64encode(network_bytes).decode("ascii") != encoded:
        raise IntegrityError(
            f"{platform} attested network information is not canonical base64"
        )
    if len(network_bytes) > MAX_RELEASE_GATE_JSON_BYTES:
        raise IntegrityError(f"{platform} attested network information exceeds its limit")
    if attestation["network_info_sha256"] != _sha256_bytes(network_bytes):
        raise IntegrityError(f"{platform} attested network information digest is invalid")
    attested_network = _json_object_bytes(
        network_bytes, f"{platform} attested packaged-node network information"
    )
    expected_network = json.loads(json.dumps(staged_network_info))
    expected_proof = expected_network.get("proof_of_work")
    if not isinstance(expected_proof, dict):  # pragma: no cover - validated caller contract.
        raise IntegrityError("staged NETWORK-INFO proof identity is missing")
    expected_proof["runtime_verifier_worker_sha256"] = _compiled_runtime_worker(
        expected_proof, platform
    )
    if attested_network != expected_network:
        raise IntegrityError(
            f"{platform} packaged node did not report the staged network identity"
        )
    suffix = ".exe" if platform == "windows-x86_64" else ""
    expected_hashes = {
        "node_sha256": rows[f"cmfd-node{suffix}"]["sha256"],
        "wallet_sha256": rows[f"common-foundry-wallet{suffix}"]["sha256"],
        "worker_sha256": rows[f"cmfd-proof-worker{suffix}"]["sha256"],
    }
    for field, expected in expected_hashes.items():
        if attestation[field] != expected:
            raise IntegrityError(
                f"{platform} packaged-node attestation has invalid {field}"
            )


def validate_production_rc_runtime_packages(
    *,
    stage_files: dict[str, Path],
    staged_network_info: dict[str, object],
    commit: str,
) -> dict[str, dict[str, dict[str, object]]]:
    missing = [
        name
        for name in (
            PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME,
            PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME,
            PRODUCTION_RC_WINDOWS_ATTESTATION_NAME,
            PRODUCTION_RC_LINUX_ATTESTATION_NAME,
        )
        if name not in stage_files
    ]
    if missing:
        raise IntegrityError(
            f"production RC release gate is blocked; missing Windows/Linux runtime package: {missing}"
        )
    proof = staged_network_info.get("proof_of_work")
    if not isinstance(proof, dict):
        raise IntegrityError("staged NETWORK-INFO proof identity is missing")
    windows_worker = _compiled_runtime_worker(proof, "windows-x86_64")
    linux_worker = _compiled_runtime_worker(proof, "linux-x86_64")
    if windows_worker == linux_worker:
        raise IntegrityError("Windows/Linux runtime proof-worker identities are not distinct")
    selected_worker = _require_hex256(
        proof.get("runtime_verifier_worker_sha256"),
        "selected runtime proof worker",
        reject_repeated=True,
    )
    if selected_worker not in {windows_worker, linux_worker}:
        raise IntegrityError("selected runtime proof worker is not a compiled platform pin")
    windows_rows = _validate_runtime_package(
        path=stage_files[PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME],
        platform="windows-x86_64",
        staged_network_info=staged_network_info,
    )
    linux_rows = _validate_runtime_package(
        path=stage_files[PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME],
        platform="linux-x86_64",
        staged_network_info=staged_network_info,
    )
    _validate_runtime_attestation(
        path=stage_files[PRODUCTION_RC_WINDOWS_ATTESTATION_NAME],
        platform="windows-x86_64",
        commit=commit,
        rows=windows_rows,
        staged_network_info=staged_network_info,
    )
    _validate_runtime_attestation(
        path=stage_files[PRODUCTION_RC_LINUX_ATTESTATION_NAME],
        platform="linux-x86_64",
        commit=commit,
        rows=linux_rows,
        staged_network_info=staged_network_info,
    )
    return {
        "windows-x86_64": windows_rows,
        "linux-x86_64": linux_rows,
    }


def create_runtime_network_info_attestation(
    *, platform: str, package_directory: Path, commit: str, output: Path
) -> dict[str, object]:
    commit = _full_commit(commit)
    package_directory = _regular_directory(
        package_directory, f"{platform} runtime package directory"
    )
    expected_name = (
        PRODUCTION_RC_WINDOWS_ATTESTATION_NAME
        if platform == "windows-x86_64"
        else PRODUCTION_RC_LINUX_ATTESTATION_NAME
        if platform == "linux-x86_64"
        else None
    )
    if expected_name is None:
        raise IntegrityError(f"unsupported production runtime platform: {platform}")
    output = _absolute_path(output)
    if output.name != expected_name:
        raise IntegrityError(f"{platform} runtime attestation must be named {expected_name}")
    suffix = ".exe" if platform == "windows-x86_64" else ""
    paths = {
        "node_sha256": package_directory / f"cmfd-node{suffix}",
        "wallet_sha256": package_directory / f"common-foundry-wallet{suffix}",
        "worker_sha256": package_directory / f"cmfd-proof-worker{suffix}",
    }
    identities: dict[str, str] = {}
    for field, path in paths.items():
        with _stable_regular_handle(path, f"{platform} packaged {path.name}") as (
            _,
            handle,
            opened,
        ):
            header = handle.read(MAX_EXECUTABLE_HEADER_BYTES)
            if platform == "windows-x86_64":
                _validate_pe_x86_64(header, opened.st_size, path.name)
            else:
                _validate_elf_x86_64(header, opened.st_size, path.name)
            identities[field] = _sha256_handle(handle)
    try:
        process = subprocess.run(
            [str(paths["node_sha256"]), "network-info"],
            cwd=package_directory,
            check=False,
            capture_output=True,
            timeout=20 * 60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IntegrityError(
            f"{platform} packaged node network-info execution failed"
        ) from error
    if process.returncode != 0 or process.stderr or len(process.stdout) > MAX_RELEASE_GATE_JSON_BYTES:
        raise IntegrityError(
            f"{platform} packaged node network-info execution was not clean"
        )
    network = _json_object_bytes(
        process.stdout, f"{platform} packaged-node network information"
    )
    proof = network.get("proof_of_work")
    if (
        not isinstance(proof, dict)
        or proof.get("selection") != "ProductionV3"
        or proof.get("build_source_commit") != commit
        or proof.get("runtime_verifier_worker_sha256") != identities["worker_sha256"]
    ):
        raise IntegrityError(
            f"{platform} packaged node reported an unexpected compiled identity"
        )
    for field, path in paths.items():
        if _sha256_file(path) != identities[field]:
            raise IntegrityError(f"{platform} packaged executable changed during attestation")
    attestation: dict[str, object] = {
        "network_info_base64": base64.b64encode(process.stdout).decode("ascii"),
        "network_info_sha256": _sha256_bytes(process.stdout),
        "node_sha256": identities["node_sha256"],
        "platform": platform,
        "schema": PRODUCTION_RC_RUNTIME_ATTESTATION_SCHEMA,
        "source_commit": commit,
        "wallet_sha256": identities["wallet_sha256"],
        "worker_sha256": identities["worker_sha256"],
    }
    _write_new(output, _canonical_json(attestation))
    return attestation


def _require_exact_fields(
    value: object, fields: set[str], label: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise IntegrityError(f"{label} has missing or unknown fields")
    return value


def _require_hex256(value: object, label: str, *, reject_repeated: bool) -> str:
    if not isinstance(value, str) or not HEX256_RE.fullmatch(value):
        raise IntegrityError(f"{label} is not a 32-byte lowercase hexadecimal value")
    raw = bytes.fromhex(value)
    if raw == bytes(32) or (reject_repeated and len(set(raw)) == 1):
        raise IntegrityError(f"{label} is zero or a known placeholder")
    return value


def _validate_rcnet_launch_candidate(
    candidate: dict[str, object], network_info: dict[str, object]
) -> None:
    _require_exact_fields(
        candidate,
        {"schema", "payload", "launch_root", "network_id", "virtual_genesis_hash"},
        "RCNet launch candidate",
    )
    if candidate["schema"] != "CMFD_RCNET_LAUNCH_CANDIDATE_V1":
        raise IntegrityError("RCNet launch candidate schema is unsupported")
    payload = _require_exact_fields(
        candidate["payload"],
        {
            "profile",
            "record_v2",
            "virtual_genesis_timestamp_unix_seconds",
            "services",
            "consensus",
            "proof_of_work",
            "monetary_policy",
            "reward_destinations",
        },
        "RCNet launch payload",
    )
    if payload["profile"] != "CommonFoundry RCNet-1":
        raise IntegrityError("RCNet launch candidate profile is invalid")
    launch_root = _require_hex256(candidate["launch_root"], "RCNet launch root", reject_repeated=True)
    network_id = _require_hex256(candidate["network_id"], "RCNet network ID", reject_repeated=True)
    genesis = _require_hex256(
        candidate["virtual_genesis_hash"], "RCNet virtual genesis", reject_repeated=True
    )
    if len({launch_root, network_id, genesis}) != 3:
        raise IntegrityError("RCNet launch root and derived identities are not distinct")

    record = _require_exact_fields(
        payload["record_v2"],
        {
            "record_version",
            "record_digest",
            "manifest_digest",
            "model_identity_digest",
            "suite_digest",
            "setup_identity",
            "padded_variables",
            "commitment_root",
        },
        "RCNet Record V2 identity",
    )
    if record["record_version"] != 2 or record["padded_variables"] != 33:
        raise IntegrityError("RCNet Record V2 identity has invalid geometry")
    for field in (
        "record_digest",
        "manifest_digest",
        "model_identity_digest",
        "suite_digest",
        "setup_identity",
        "commitment_root",
    ):
        _require_hex256(record[field], f"RCNet Record V2 {field}", reject_repeated=False)

    services = _require_exact_fields(
        payload["services"],
        {"bootstrap_ipv4", "rpc_port", "p2p_port", "pool_port"},
        "RCNet service parameters",
    )
    try:
        bootstrap = ipaddress.IPv4Address(services["bootstrap_ipv4"])
    except (ipaddress.AddressValueError, TypeError) as error:
        raise IntegrityError("RCNet bootstrap IPv4 address is invalid") from error
    if bootstrap in ipaddress.IPv4Network("192.0.2.0/24") or bootstrap in ipaddress.IPv4Network(
        "198.51.100.0/24"
    ) or bootstrap in ipaddress.IPv4Network("203.0.113.0/24"):
        raise IntegrityError("RCNet bootstrap is an RFC 5737 documentation address")
    ports = [services.get(name) for name in ("rpc_port", "p2p_port", "pool_port")]
    if any(not isinstance(port, int) or isinstance(port, bool) or not 0 < port <= 65535 for port in ports) or len(set(ports)) != 3:
        raise IntegrityError("RCNet service ports are invalid")
    if any(services[name] != port for name, port in PRODUCTION_RC_SERVICE_PORTS.items()):
        raise IntegrityError(
            "RCNet service ports must reserve loopback RPC 19443, public P2P 19444, "
            "and closed-by-default pool 19445"
        )

    proof = _require_exact_fields(
        payload["proof_of_work"],
        {
            "algorithm_version",
            "proof_version",
            "banks",
            "layers_per_bank",
            "maximum_structured_proof_bytes",
            "pow_limit",
        },
        "RCNet proof-of-work parameters",
    )
    pow_limit = _require_hex256(proof["pow_limit"], "RCNet proof-of-work limit", reject_repeated=False)
    rewards = _require_exact_fields(
        payload["reward_destinations"],
        {"steward_xonly_public_key", "community_xonly_public_key"},
        "RCNet reward destinations",
    )
    for field in ("steward_xonly_public_key", "community_xonly_public_key"):
        destination = _require_hex256(rewards[field], f"RCNet {field}", reject_repeated=False)
        if destination in INSECURE_DEV_REWARD_DESTINATIONS:
            raise IntegrityError("RCNet reward destination is a known insecure development key")

    consensus = _require_exact_fields(payload["consensus"], {
        "network_protocol_version", "block_version", "transaction_version", "wire_version",
        "maximum_future_offset_seconds", "target_spacing_seconds", "coinbase_maturity_blocks",
        "median_time_window", "max_block_transactions", "max_transaction_inputs",
        "max_transaction_outputs", "max_block_aggregate_inputs", "max_block_aggregate_outputs",
        "max_block_signature_checks", "max_coinbase_outputs", "consensus_signature_bytes",
        "dgw_window", "wire_header_bytes", "max_transaction_bytes", "max_proof_bytes",
        "max_block_bytes",
    }, "RCNet consensus parameters")
    monetary_policy = _require_exact_fields(payload["monetary_policy"], {
        "atoms_per_coin", "initial_subsidy_atoms", "tail_height", "tail_subsidy_atoms",
        "steward_percent", "community_percent",
    }, "RCNet monetary policy")

    network = network_info.get("network")
    compiled_proof = network_info.get("proof_of_work")
    compiled_services = network_info.get("services")
    compiled_rewards = network_info.get("reward_destinations")
    compiled_consensus = network_info.get("consensus")
    compiled_monetary_policy = network_info.get("monetary_policy")
    if not isinstance(network, dict) or (
        network.get("network_id") != network_id
        or network.get("virtual_genesis_hash") != genesis
        or network.get("virtual_genesis_timestamp_unix_seconds")
        != str(payload["virtual_genesis_timestamp_unix_seconds"])
    ):
        raise IntegrityError("compiled RCNet identity does not match the launch candidate")
    if not isinstance(compiled_proof, dict) or compiled_proof.get("pow_limit") != pow_limit:
        raise IntegrityError("compiled RCNet proof-of-work limit does not match the launch candidate")
    for field in ("algorithm_version", "proof_version", "banks", "layers_per_bank"):
        if compiled_proof.get(field) != proof[field]:
            raise IntegrityError(
                "compiled RCNet proof-of-work parameters do not match the launch candidate"
            )
    if compiled_proof.get("maximum_structured_proof_bytes") != str(
        proof["maximum_structured_proof_bytes"]
    ):
        raise IntegrityError(
            "compiled RCNet proof-of-work parameters do not match the launch candidate"
        )
    if not isinstance(compiled_services, dict) or (
        compiled_services.get("rpc_port") != ports[0]
        or compiled_services.get("p2p_port") != ports[1]
        or compiled_services.get("pool_port") != ports[2]
        or compiled_services.get("bootstrap_peer") != f"{bootstrap}:{ports[1]}"
    ):
        raise IntegrityError("compiled RCNet services do not match the launch candidate")
    if not isinstance(compiled_rewards, dict) or compiled_rewards != rewards:
        raise IntegrityError("compiled RCNet reward destinations do not match the launch candidate")
    model = compiled_proof.get("model")
    for field in ("record_digest", "manifest_digest", "model_identity_digest", "suite_digest", "setup_identity", "padded_variables"):
        if not isinstance(model, dict) or model.get(field) != record[field]:
            raise IntegrityError("compiled RCNet Record V2 identity does not match the launch candidate")
    if not isinstance(compiled_consensus, dict):
        raise IntegrityError("compiled RCNet consensus parameters are missing")
    versions = compiled_consensus.get("versions")
    limits = compiled_consensus.get("limits")
    version_fields = {
        "network_protocol_version",
        "block_version",
        "transaction_version",
        "wire_version",
    }
    for field in version_fields:
        if not isinstance(versions, dict) or versions.get(field) != consensus[field]:
            raise IntegrityError(
                "compiled RCNet consensus parameters do not match the launch candidate"
            )
    for field in set(consensus) - version_fields:
        if not isinstance(limits, dict) or limits.get(field) != str(consensus[field]):
            raise IntegrityError(
                "compiled RCNet consensus parameters do not match the launch candidate"
            )
    if not isinstance(compiled_monetary_policy, dict):
        raise IntegrityError("compiled RCNet monetary policy is missing")
    for field, value in monetary_policy.items():
        expected = value if field.endswith("_percent") else str(value)
        if compiled_monetary_policy.get(field) != expected:
            raise IntegrityError(
                "compiled RCNet monetary policy does not match the launch candidate"
            )


def validate_production_rc_artifacts(
    *, version: str, commit: str, stage_files: dict[str, Path]
) -> None:
    if not is_production_rc_label(version):
        return

    reject_production_rc_source_assets(stage_files)

    required = {
        PRODUCTION_RC_NETWORK_INFO_NAME,
        PRODUCTION_RC_LAUNCH_CANDIDATE_NAME,
        PRODUCTION_V3_ACTIVATION_NAME,
        PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME,
        PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME,
        PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME,
    }
    missing = sorted(required - set(stage_files))
    if missing:
        raise IntegrityError(
            "production RC release gate is blocked; "
            f"missing compiled activation artifacts: {missing}"
        )

    network_info, _ = _bounded_json_object(
        stage_files[PRODUCTION_RC_NETWORK_INFO_NAME], "compiled network information"
    )
    launch_candidate, _ = _bounded_json_object(
        stage_files[PRODUCTION_RC_LAUNCH_CANDIDATE_NAME], "RCNet launch candidate"
    )
    evidence, evidence_bytes = _bounded_json_object(
        stage_files[PRODUCTION_V3_ACTIVATION_NAME], "ProductionV3 activation evidence"
    )
    qualification_manifest, qualification_manifest_bytes = _bounded_json_object(
        stage_files[PRODUCTION_V3_QUALIFICATION_MANIFEST_NAME],
        "ProductionV3 qualification manifest",
    )
    verifier_binary = _regular_file(
        stage_files[PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME],
        "ProductionV3 fresh-process verifier binary",
    )
    verifier_report, verifier_report_bytes = _bounded_json_object(
        stage_files[PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME],
        "ProductionV3 fresh-process verifier report",
    )
    qualification_manifest_sha256 = _sha256_bytes(qualification_manifest_bytes)
    verifier_binary_size, verifier_binary_sha256 = _sha256_file_with_size(
        verifier_binary, "ProductionV3 fresh-process verifier binary"
    )
    verifier_report_sha256 = _sha256_bytes(verifier_report_bytes)
    network = network_info.get("network")
    proof = network_info.get("proof_of_work")
    if not isinstance(network, dict) or network.get("name") != "CommonFoundry RCNet-1":
        raise IntegrityError("production RC compiled network profile is not RCNet-1")
    _validate_rcnet_launch_candidate(launch_candidate, network_info)
    if not isinstance(proof, dict) or proof.get("selection") != "ProductionV3":
        raise IntegrityError("production RC compiled proof selection is not ProductionV3")
    if proof.get("build_source_commit") != commit:
        raise IntegrityError(
            "production RC compiled build source commit does not match the checked-out commit"
        )
    if proof.get("activation_evidence_sha256") != _sha256_bytes(evidence_bytes):
        raise IntegrityError(
            "compiled ProductionV3 selection is not bound to the staged activation evidence"
        )
    qualification_source_commit = qualification_manifest.get("source_commit")
    if (
        not isinstance(qualification_source_commit, str)
        or not FULL_COMMIT_RE.fullmatch(qualification_source_commit)
        or set(qualification_source_commit) == {"0"}
    ):
        raise IntegrityError(
            "ProductionV3 qualification manifest has an invalid source commit"
        )

    expected_evidence = {
        "artifacts": proof.get("artifacts"),
        "schema": "CMFD_PRODUCTION_V3_ACTIVATION_V1",
        "source_commit": commit,
        "qualification_source_commit": qualification_source_commit,
        "network_profile": "RCNet-1",
        "proof_selection": "ProductionV3",
        "qualification_manifest_sha256": qualification_manifest_sha256,
        "fresh_process_verifier_binary_sha256": verifier_binary_sha256,
        "fresh_process_verifier_report_sha256": verifier_report_sha256,
        "runtime_verifier_workers": proof.get("runtime_verifier_workers"),
    }
    _require_exact_fields(
        evidence, set(expected_evidence), "ProductionV3 activation evidence"
    )
    for field, expected in expected_evidence.items():
        if evidence.get(field) != expected:
            raise IntegrityError(
                f"ProductionV3 activation evidence has invalid {field}"
            )
    if qualification_manifest.get("schema") != (
        "CMFD_PRODUCTION_V3_QUALIFICATION_MANIFEST_V1"
    ):
        raise IntegrityError("ProductionV3 qualification manifest schema is unsupported")
    if qualification_manifest.get("status") != (
        "qualification_complete_activation_disabled"
    ):
        raise IntegrityError("ProductionV3 qualification manifest status is invalid")
    if (
        qualification_manifest.get("network_profile") != "RCNet-1"
        or qualification_manifest.get("proof_selection") != "ProductionV3"
    ):
        raise IntegrityError("ProductionV3 qualification manifest identity is invalid")

    qualification = qualification_manifest.get("qualification")
    if not isinstance(qualification, dict):
        raise IntegrityError("ProductionV3 qualification manifest geometry is invalid")
    scratch_floor = qualification.get("scratch_floor_bytes")
    scratch_margin = qualification.get("scratch_margin_bytes")
    required_scratch = qualification.get("required_scratch_bytes")
    available_scratch = qualification.get("available_scratch_bytes_before_producer")
    producer_pid = qualification.get("producer_process_id")
    verifier_pid = qualification.get("verifier_process_id")
    if (
        qualification.get("padded_variables") != 33
        or qualification.get("composed_claims") != 134
        or qualification.get("fresh_process_verifier") is not True
        or scratch_floor != 53_687_091_200
        or not isinstance(scratch_margin, int)
        or isinstance(scratch_margin, bool)
        or scratch_margin <= 0
        or required_scratch != scratch_floor + scratch_margin
        or not isinstance(available_scratch, int)
        or isinstance(available_scratch, bool)
        or available_scratch < required_scratch
        or not isinstance(producer_pid, int)
        or isinstance(producer_pid, bool)
        or producer_pid <= 0
        or not isinstance(verifier_pid, int)
        or isinstance(verifier_pid, bool)
        or verifier_pid <= 0
        or producer_pid == verifier_pid
    ):
        raise IntegrityError("ProductionV3 qualification manifest geometry is invalid")

    if qualification_manifest.get("journal_semantics") != {
        "diagnostic_only": True,
        "completion_marker": False,
        "resumable": False,
        "used_as_completion_evidence": False,
    } or qualification_manifest.get("completion_evidence") != {
        "producer_report": True,
        "fresh_verifier_report": True,
    }:
        raise IntegrityError("ProductionV3 qualification completion semantics are invalid")

    artifacts = qualification_manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise IntegrityError("ProductionV3 qualification manifest artifacts are missing")
    required_bound_roles = {
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
        "fresh_process_verifier_binary",
        "verifier_report",
    }
    if not required_bound_roles.issubset(artifacts):
        raise IntegrityError(
            "ProductionV3 qualification manifest omits required artifact bindings"
        )
    for role in required_bound_roles:
        row = artifacts.get(role)
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("sha256"), str)
            or not HEX256_RE.fullmatch(row["sha256"])
            or set(row["sha256"]) == {"0"}
            or not isinstance(row.get("bytes"), int)
            or isinstance(row["bytes"], bool)
            or row["bytes"] <= 0
        ):
            raise IntegrityError(
                f"ProductionV3 qualification manifest has invalid {role} binding"
            )

    compiled_artifacts = _require_exact_fields(
        proof.get("artifacts"),
        {"bank", "manifest", "record_v2"},
        "compiled ProductionV3 artifact identities",
    )
    for role, expected_name in (
        ("bank", PRODUCTION_V3_PACKAGE_BANK),
        ("record_v2", PRODUCTION_V3_PACKAGE_RECORD_V2),
    ):
        pin = _require_exact_fields(
            compiled_artifacts[role],
            {"bytes", "blake3", "sha256"},
            f"compiled ProductionV3 {role} identity",
        )
        row = artifacts[role]
        try:
            compiled_bytes = int(pin["bytes"])
        except (TypeError, ValueError) as error:
            raise IntegrityError(
                f"compiled ProductionV3 {role} byte length is invalid"
            ) from error
        if (
            str(compiled_bytes) != pin["bytes"]
            or row.get("file_name") != expected_name
            or row.get("bytes") != compiled_bytes
            or row.get("sha256") != pin["sha256"]
        ):
            raise IntegrityError(
                f"compiled ProductionV3 {role} does not match qualification evidence"
            )
    toolchain = qualification_manifest.get("toolchain")
    if not isinstance(toolchain, dict):
        raise IntegrityError("ProductionV3 qualification toolchain identity is missing")
    toolchain_identity = {
        "cargo_sha256": artifacts["cargo"]["sha256"],
        "cargo_version": toolchain.get("cargo_version"),
        "rustc_sha256": artifacts["rustc"]["sha256"],
        "rustc_version": toolchain.get("rustc_version"),
        "cargo_config_sha256": artifacts["cargo_config"]["sha256"],
        "environment_policy": "CMFD_QUALIFICATION_ALLOWLIST_V1",
    }
    if (
        not isinstance(toolchain_identity["cargo_version"], str)
        or not toolchain_identity["cargo_version"]
        or not isinstance(toolchain_identity["rustc_version"], str)
        or not toolchain_identity["rustc_version"]
        or toolchain.get("cargo_sha256") != toolchain_identity["cargo_sha256"]
        or toolchain.get("rustc_sha256") != toolchain_identity["rustc_sha256"]
        or toolchain.get("cargo_config_sha256")
        != toolchain_identity["cargo_config_sha256"]
        or toolchain.get("environment_policy")
        != toolchain_identity["environment_policy"]
        or toolchain.get("identity_sha256")
        != _sha256_bytes(
            json.dumps(
                toolchain_identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        )
    ):
        raise IntegrityError("ProductionV3 qualification toolchain identity is invalid")

    staged_bindings = {
        "fresh_process_verifier_binary": (
            PRODUCTION_V3_FRESH_PROCESS_VERIFIER_BINARY_NAME,
            verifier_binary_size,
            verifier_binary_sha256,
        ),
        "verifier_report": (
            PRODUCTION_V3_FRESH_PROCESS_VERIFIER_REPORT_NAME,
            len(verifier_report_bytes),
            verifier_report_sha256,
        ),
    }
    for role, (name, size, digest) in staged_bindings.items():
        row = artifacts[role]
        if (
            row.get("file_name") != name
            or row.get("bytes") != size
            or row.get("sha256") != digest
        ):
            raise IntegrityError(
                f"staged ProductionV3 {role} does not match the qualification manifest"
            )

    verifier_expectations = {
        "report_version": 2,
        "network_id": network["network_id"],
        "verifier_only": True,
        "producer_report_checked": True,
        "qualification_journal_checked": True,
    }
    for field, expected in verifier_expectations.items():
        if verifier_report.get(field) != expected:
            raise IntegrityError(
                f"ProductionV3 fresh-process verifier report has invalid {field}"
            )
    validate_production_rc_runtime_packages(
        stage_files=stage_files, staged_network_info=network_info, commit=commit
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _blake3_bytes(data: bytes) -> str:
    if blake3 is None:
        raise IntegrityError(
            "ProductionV3 package inspection requires the pinned Python blake3 dependency"
        )
    return blake3.blake3(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_file_with_size(path, "hashed file")[1]


def _sha256_file_with_size(path: Path, label: str) -> tuple[int, str]:
    with _stable_regular_handle(path, label) as (_, handle, opened):
        return opened.st_size, _sha256_handle(handle)


def _sha256_handle(handle: object) -> str:
    handle.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    handle.seek(0)
    return digest.hexdigest()


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _regular_file(path: Path, label: str) -> Path:
    candidate = _absolute_path(path)
    try:
        mode = candidate.lstat().st_mode
    except OSError as error:
        raise IntegrityError(f"{label} is missing: {candidate}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise IntegrityError(f"{label} must be a regular, non-symlink file")
    return candidate


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
    )


@contextlib.contextmanager
def _stable_regular_handle(path: Path, label: str):
    candidate = _regular_file(path, label)
    before = candidate.lstat()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise IntegrityError(f"cannot open {label}: {candidate}") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stat_identity(before) != _stat_identity(opened)
        ):
            raise IntegrityError(f"{label} changed before it could be opened")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            yield candidate, handle, opened
        try:
            after = candidate.lstat()
        except OSError as error:
            raise IntegrityError(f"{label} changed while it was inspected") from error
        if _stat_identity(after) != _stat_identity(opened):
            raise IntegrityError(f"{label} changed while it was inspected")
    finally:
        os.close(descriptor)


def _regular_directory(path: Path, label: str) -> Path:
    candidate = _absolute_path(path)
    try:
        mode = candidate.lstat().st_mode
    except OSError as error:
        raise IntegrityError(f"{label} is missing: {candidate}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise IntegrityError(f"{label} must be a regular, non-symlink directory")
    return candidate


def _run_git(repo: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", b"").decode("utf-8", "replace").strip()
        raise IntegrityError(f"git {' '.join(arguments)} failed: {detail}") from error
    return result.stdout.decode("utf-8", "strict").strip()


def _run_git_bytes(repo: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", b"").decode("utf-8", "replace").strip()
        raise IntegrityError(f"git {' '.join(arguments)} failed: {detail}") from error
    return result.stdout


def _full_commit(value: str) -> str:
    candidate = value.strip().lower()
    if not FULL_COMMIT_RE.fullmatch(candidate):
        raise IntegrityError("expected commit must be a full lowercase Git object ID")
    return candidate


def _assert_clean_exact_repo(repo: Path, expected_commit: str) -> str:
    repo = repo.resolve(strict=True)
    expected = _full_commit(expected_commit)
    actual = _run_git(repo, "rev-parse", "HEAD").lower()
    if actual != expected:
        raise IntegrityError(f"HEAD is {actual}, expected {expected}")
    status_output = _run_git(
        repo, "status", "--porcelain=v1", "--untracked-files=normal"
    )
    if status_output:
        first = status_output.splitlines()[0]
        raise IntegrityError(f"source checkout is dirty: {first}")
    return actual


def _commit_epoch(repo: Path) -> int:
    value = _run_git(repo, "show", "-s", "--format=%ct", "HEAD")
    try:
        epoch = int(value, 10)
    except ValueError as error:
        raise IntegrityError("Git returned an invalid commit timestamp") from error
    if epoch < 0:
        raise IntegrityError("SOURCE_DATE_EPOCH cannot be negative")
    return epoch


def _source_date_epoch(repo: Path | None, explicit: str | int | None) -> int:
    value: str | int | None = explicit
    if value is None:
        value = os.environ.get("SOURCE_DATE_EPOCH")
    if value is None:
        if repo is None:
            raise IntegrityError("SOURCE_DATE_EPOCH is required")
        return _commit_epoch(repo)
    try:
        epoch = int(value)
    except (TypeError, ValueError) as error:
        raise IntegrityError("SOURCE_DATE_EPOCH must be a base-10 integer") from error
    if epoch < 0:
        raise IntegrityError("SOURCE_DATE_EPOCH cannot be negative")
    return epoch


def _safe_repo_relative(value: str) -> str:
    if not value or "\\" in value or "\0" in value or "\n" in value or "\r" in value:
        raise IntegrityError(f"unsafe repository-relative path: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise IntegrityError(f"unsafe repository-relative path: {value!r}")
    return path.as_posix()


def _tracked_file(repo: Path, relative: str) -> Path:
    safe = _safe_repo_relative(relative)
    _run_git(repo, "ls-files", "--error-unmatch", "--", safe)
    path = repo / PurePosixPath(safe)
    if not path.is_file() or path.is_symlink():
        raise IntegrityError(f"tracked input is not a regular file: {safe}")
    return path


def _tracked_blob(repo: Path, relative: str) -> bytes:
    safe = _safe_repo_relative(relative)
    _tracked_file(repo, safe)
    return _run_git_bytes(repo, "cat-file", "blob", f"HEAD:{safe}")


def _manifest_version(repo: Path, relative: str) -> str:
    data = _tracked_blob(repo, relative)
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise IntegrityError(f"release version manifest is not UTF-8: {relative}") from error
    if relative.endswith(".json"):
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:
            raise IntegrityError(
                f"release version manifest is not valid JSON: {relative}"
            ) from error
        version = value.get("version") if isinstance(value, dict) else None
    else:
        package = re.search(
            r"(?ms)^\[package\]\s*$\n(.*?)(?=^\[|\Z)",
            text,
        )
        package_version = (
            re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', package.group(1))
            if package is not None
            else None
        )
        version = package_version.group(1) if package_version is not None else None
    if not isinstance(version, str) or not version:
        raise IntegrityError(f"release version manifest has no package version: {relative}")
    return _single_line(f"version in {relative}", version)


def validate_production_rc_source_versions(*, repo: Path, version: str) -> None:
    if not is_production_rc_label(version):
        return
    mismatches: dict[str, str] = {}
    for relative in PRODUCTION_RC_VERSION_FILES:
        actual = _manifest_version(repo, relative)
        if actual != version:
            mismatches[relative] = actual
    if mismatches:
        details = ", ".join(
            f"{relative}={actual}" for relative, actual in sorted(mismatches.items())
        )
        raise IntegrityError(
            f"production RC version {version} does not match package manifests: {details}"
        )


def _tracked_input_file(repo: Path, path: Path, label: str) -> Path:
    candidate = _absolute_path(path if path.is_absolute() else repo / path)
    try:
        relative = candidate.relative_to(repo).as_posix()
    except ValueError as error:
        raise IntegrityError(f"{label} must be inside the source repository") from error
    try:
        return _tracked_file(repo, relative)
    except IntegrityError as error:
        raise IntegrityError(
            f"{label} must be a tracked regular file at the expected commit"
        ) from error


def _native_source_identity(repo: Path, kind: str) -> tuple[tuple[str, ...], str]:
    try:
        source_files = NATIVE_SOURCES[kind]
    except KeyError as error:
        raise IntegrityError(f"unsupported native backend: {kind}") from error
    digest = hashlib.sha256()
    digest.update(b"CMFD-NATIVE-SOURCE-TREE-V1\0")
    for relative in source_files:
        _tracked_file(repo, relative)
        name = relative.encode("utf-8")
        data = _tracked_blob(repo, relative)
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return source_files, digest.hexdigest()


def _single_line(label: str, value: str) -> str:
    normalized = " ".join(value.split())
    if not normalized or "\0" in normalized or "\n" in normalized or "\r" in normalized:
        raise IntegrityError(f"{label} must be a non-empty single-line value")
    return normalized


def _canonical_receipt(fields: dict[str, str]) -> bytes:
    if tuple(fields) != RECEIPT_FIELDS:
        raise IntegrityError(
            "native build receipt fields are missing, reordered, or unexpected"
        )
    return ("".join(f"{key}={fields[key]}\n" for key in RECEIPT_FIELDS)).encode("utf-8")


def _receipt_digest(fields: dict[str, str]) -> str:
    body = "".join(f"{key}={fields[key]}\n" for key in RECEIPT_FIELDS[:-1]).encode(
        "utf-8"
    )
    return _sha256_bytes(b"CMFD-NATIVE-BUILD-RECEIPT-V1\0" + body)


def _read_receipt(path: Path) -> dict[str, str]:
    path = _regular_file(path, "native build receipt")
    data = path.read_bytes()
    if len(data) > MAX_RECEIPT_BYTES:
        raise IntegrityError("native build receipt exceeds its size limit")
    if b"\r" in data or not data.endswith(b"\n"):
        raise IntegrityError(
            "native build receipt is not canonical LF-terminated UTF-8"
        )
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise IntegrityError("native build receipt is not UTF-8") from error
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            raise IntegrityError("native build receipt contains a malformed line")
        key, value = line.split("=", 1)
        if key in fields:
            raise IntegrityError(f"native build receipt repeats {key}")
        fields[key] = value
    if tuple(fields) != RECEIPT_FIELDS or _canonical_receipt(fields) != data:
        raise IntegrityError(
            "native build receipt is noncanonical or has unknown fields"
        )
    if not HEX256_RE.fullmatch(fields["RECEIPT_SHA256"]):
        raise IntegrityError("native build receipt RECEIPT_SHA256 is malformed")
    if fields["RECEIPT_SHA256"] != _receipt_digest(fields):
        raise IntegrityError("native build receipt digest does not match its fields")
    return fields


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_new(path: Path, data: bytes) -> None:
    created = False
    try:
        handle = path.open("xb")
        created = True
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if created and path.exists():
            path.unlink()
        raise


def _publish_new_archive(temporary: Path, output: Path) -> None:
    try:
        os.link(temporary, output, follow_symlinks=False)
    except FileExistsError as error:
        raise IntegrityError(f"archive already exists: {output}") from error
    except OSError as error:
        raise IntegrityError(f"cannot publish archive without replacement: {output}") from error
    temporary.unlink()


def write_native_build_receipt(
    *,
    repo: Path,
    expected_commit: str,
    kind: str,
    library: Path,
    build_script: str,
    toolchain: str,
    target: str,
    architectures: str,
    output: Path,
    source_date_epoch: str | int | None,
) -> dict[str, str]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    library = _regular_file(library, "native library")
    source_files, source_identity = _native_source_identity(repo, kind)
    script_relative = _safe_repo_relative(build_script)
    epoch = _source_date_epoch(repo, source_date_epoch)
    fields = {
        "SCHEMA": RECEIPT_SCHEMA,
        "TRUST_SCOPE": "IDENTITY_GUARD_ONLY_NOT_AUTHENTICATION",
        "KIND": kind,
        "GIT_COMMIT": commit,
        "SOURCE_FILES": ";".join(source_files),
        "SOURCE_TREE_SHA256": source_identity,
        "BUILD_SCRIPT": script_relative,
        "BUILD_SCRIPT_SHA256": _sha256_bytes(_tracked_blob(repo, script_relative)),
        "LIBRARY_NAME": _single_line("library name", library.name),
        "LIBRARY_SHA256": _sha256_file(library),
        "LIBRARY_SIZE": str(library.stat().st_size),
        "TOOLCHAIN": _single_line("toolchain", toolchain),
        "TARGET": _single_line("target", target),
        "ARCHITECTURES": _single_line("architectures", architectures),
        "SOURCE_DATE_EPOCH": str(epoch),
    }
    fields["RECEIPT_SHA256"] = _receipt_digest(fields)
    output = _absolute_path(output)
    if output.is_symlink():
        raise IntegrityError("native build receipt output cannot be a symbolic link")
    _write_atomic(output, _canonical_receipt(fields))
    return fields


def verify_native_build_receipt(
    *,
    repo: Path,
    expected_commit: str,
    kind: str,
    library: Path,
    receipt: Path,
    expected_build_script: str,
    expected_target: str,
    expected_architectures: str,
    source_date_epoch: str | int | None,
) -> dict[str, str]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    library = _regular_file(library, "native library")
    fields = _read_receipt(receipt)
    source_files, source_identity = _native_source_identity(repo, kind)
    script_relative = _safe_repo_relative(expected_build_script)
    epoch = _source_date_epoch(repo, source_date_epoch)
    expected = {
        "SCHEMA": RECEIPT_SCHEMA,
        "TRUST_SCOPE": "IDENTITY_GUARD_ONLY_NOT_AUTHENTICATION",
        "KIND": kind,
        "GIT_COMMIT": commit,
        "SOURCE_FILES": ";".join(source_files),
        "SOURCE_TREE_SHA256": source_identity,
        "BUILD_SCRIPT": script_relative,
        "BUILD_SCRIPT_SHA256": _sha256_bytes(_tracked_blob(repo, script_relative)),
        "LIBRARY_NAME": library.name,
        "LIBRARY_SHA256": _sha256_file(library),
        "LIBRARY_SIZE": str(library.stat().st_size),
        "TARGET": _single_line("target", expected_target),
        "ARCHITECTURES": _single_line("architectures", expected_architectures),
        "SOURCE_DATE_EPOCH": str(epoch),
    }
    for key, value in expected.items():
        if fields.get(key) != value:
            raise IntegrityError(f"native build receipt mismatch for {key}")
    _single_line("toolchain", fields["TOOLCHAIN"])
    return fields


def _archive_entries(stage: Path) -> list[tuple[Path, str, bool]]:
    stage = _regular_directory(stage, "archive staging path")
    root_name = _safe_repo_relative(stage.name)
    entries: list[tuple[Path, str, bool]] = [(stage, f"{root_name}/", True)]
    pending = [stage]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as scan:
                children = []
                for child in scan:
                    if len(entries) + len(children) >= MAX_ARCHIVE_MEMBERS:
                        raise IntegrityError("archive staging has too many members")
                    children.append(child)
        except OSError as error:
            raise IntegrityError(f"cannot enumerate archive staging: {directory}") from error
        child_directories: list[Path] = []
        for child in sorted(children, key=lambda value: value.name):
            path = Path(child.path)
            try:
                mode = child.stat(follow_symlinks=False).st_mode
            except OSError as error:
                raise IntegrityError(f"cannot inspect archive staging member: {path}") from error
            if stat.S_ISLNK(mode):
                raise IntegrityError(f"archive staging contains a symbolic link: {path}")
            relative = _safe_repo_relative(path.relative_to(stage).as_posix())
            archive_name = f"{root_name}/{relative}"
            if stat.S_ISDIR(mode):
                entries.append((path, f"{archive_name}/", True))
                child_directories.append(path)
            elif stat.S_ISREG(mode):
                entries.append((path, archive_name, False))
            else:
                raise IntegrityError(f"archive staging contains a special file: {path}")
        pending.extend(reversed(child_directories))
    return sorted(entries, key=lambda row: row[1])


def _canonical_file_mode(path: Path) -> int:
    executable_suffixes = {".bat", ".cmd", ".dll", ".exe", ".sh", ".so"}
    executable_names = {"cmfd-node", "common-foundry-wallet", "cmfd-proof-worker"}
    if path.suffix.lower() in executable_suffixes or path.name in executable_names:
        return 0o755
    try:
        if path.stat().st_mode & 0o111:
            return 0o755
    except OSError as error:
        raise IntegrityError(f"cannot inspect archive mode for {path}") from error
    return 0o644


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    value = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    if value.year < 1980 or value.year > 2107:
        raise IntegrityError("ZIP SOURCE_DATE_EPOCH must be between 1980 and 2107")
    # DOS timestamps store seconds in two-second increments. Canonically round
    # down so an odd SOURCE_DATE_EPOCH verifies after the ZIP is reopened.
    return (
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second - (value.second % 2),
    )


def create_deterministic_zip(stage: Path, output: Path, epoch: int) -> None:
    entries = _archive_entries(stage)
    output = _absolute_path(output)
    if output.is_symlink():
        raise IntegrityError("ZIP output cannot be a symbolic link")
    if output.exists():
        raise IntegrityError(f"archive already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for path, name, is_directory in entries:
                info = zipfile.ZipInfo(name, _zip_datetime(epoch))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.comment = b""
                info.extra = b""
                mode = 0o755 if is_directory else _canonical_file_mode(path)
                file_type = stat.S_IFDIR if is_directory else stat.S_IFREG
                info.external_attr = ((file_type | mode) & 0xFFFF) << 16
                if is_directory:
                    info.external_attr |= 0x10
                    archive.writestr(info, b"")
                else:
                    with _stable_regular_handle(
                        path, f"ZIP staging member {name}"
                    ) as (_, source, opened):
                        info.file_size = opened.st_size
                        with archive.open(
                            info,
                            "w",
                            force_zip64=opened.st_size > zipfile.ZIP64_LIMIT,
                        ) as destination:
                            shutil.copyfileobj(source, destination, length=1024 * 1024)
        _publish_new_archive(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    verify_deterministic_zip(stage, output, epoch)


def verify_deterministic_zip(stage: Path, archive_path: Path, epoch: int) -> None:
    expected = _archive_entries(stage)
    archive_path = _regular_file(archive_path, "ZIP archive")
    expected_names = [name for _, name, _ in expected]
    try:
        with _stable_regular_handle(
            archive_path, "ZIP archive"
        ) as (_, raw, _):
            initial_digest = _sha256_handle(raw)
            central_offset, central_size, expected_entries = _validate_zip_framing(
                raw,
                "ZIP archive",
                maximum_entries=MAX_ARCHIVE_MEMBERS,
                maximum_central_bytes=MAX_ZIP_CENTRAL_DIRECTORY_BYTES,
            )
            with zipfile.ZipFile(raw, "r") as archive:
                members = archive.infolist()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise IntegrityError("ZIP archive has too many members")
                _validate_zip_local_layout(
                    raw,
                    members=members,
                    central_offset=central_offset,
                    central_size=central_size,
                    expected_entries=expected_entries,
                    label="ZIP archive",
                )
                if archive.comment:
                    raise IntegrityError("ZIP archive comment is not canonical")
                if [member.filename for member in members] != expected_names:
                    raise IntegrityError(
                        "ZIP entries are missing, reordered, or unexpected"
                    )
                for (path, name, is_directory), member in zip(
                    expected, members, strict=True
                ):
                    if member.date_time != _zip_datetime(epoch):
                        raise IntegrityError(f"ZIP timestamp is not canonical: {name}")
                    expected_mode = 0o755 if is_directory else _canonical_file_mode(path)
                    expected_type = stat.S_IFDIR if is_directory else stat.S_IFREG
                    expected_attributes = ((expected_type | expected_mode) & 0xFFFF) << 16
                    if is_directory:
                        expected_attributes |= 0x10
                    if (
                        member.create_system != 3
                        or member.external_attr != expected_attributes
                        or member.is_dir() != is_directory
                    ):
                        raise IntegrityError(f"ZIP type or mode is not canonical: {name}")
                    expected_extra = _zip64_extra(member)
                    if (
                        member.compress_type != zipfile.ZIP_DEFLATED
                        or member.comment
                        or member.extra != expected_extra
                        or member.flag_bits != 0
                    ):
                        raise IntegrityError(f"ZIP metadata is not canonical: {name}")
                    if is_directory:
                        if member.file_size != 0 or member.CRC != 0 or archive.read(member):
                            raise IntegrityError(
                                f"ZIP directory content is not canonical: {name}"
                            )
                    else:
                        with _stable_regular_handle(
                            path, f"ZIP staging member {name}"
                        ) as (_, source, _), archive.open(member, "r") as packaged:
                            while True:
                                expected_chunk = source.read(1024 * 1024)
                                packaged_chunk = packaged.read(1024 * 1024)
                                if expected_chunk != packaged_chunk:
                                    raise IntegrityError(
                                        f"ZIP content differs from staging: {name}"
                                    )
                                if not expected_chunk:
                                    break
            if _sha256_handle(raw) != initial_digest:
                raise IntegrityError("ZIP archive changed during verification")
    except (OSError, zipfile.BadZipFile) as error:
        raise IntegrityError(f"cannot verify ZIP archive: {error}") from error


def create_deterministic_tar_gz(stage: Path, output: Path, epoch: int) -> None:
    entries = _archive_entries(stage)
    output = _absolute_path(output)
    if output.is_symlink():
        raise IntegrityError("tar.gz output cannot be a symbolic link")
    if output.exists():
        raise IntegrityError(f"archive already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with (
            temporary.open("wb") as raw,
            gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch
            ) as zipped,
            tarfile.open(
                fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive,
        ):
            for path, name, is_directory in entries:
                member = tarfile.TarInfo(name.rstrip("/") if is_directory else name)
                member.mtime = epoch
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mode = 0o755 if is_directory else _canonical_file_mode(path)
                if is_directory:
                    member.type = tarfile.DIRTYPE
                    member.size = 0
                    archive.addfile(member)
                else:
                    member.type = tarfile.REGTYPE
                    with _stable_regular_handle(
                        path, f"tar staging member {name}"
                    ) as (_, source, opened):
                        member.size = opened.st_size
                        archive.addfile(member, source)
        _publish_new_archive(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    verify_deterministic_tar_gz(stage, output, epoch)


def _preflight_expected_tar_gz(
    handle: object, expected: list[tuple[Path, str, bool]], epoch: int
) -> tuple[list[tarfile.TarInfo], int, str]:
    specifications: list[tuple[str, bool, int | None, int, int]] = []
    for path, name, is_directory in expected:
        expected_name = name.rstrip("/") if is_directory else name
        if is_directory:
            expected_size = 0
        else:
            with _stable_regular_handle(
                path, f"tar staging member {name}"
            ) as (_, _, opened):
                expected_size = opened.st_size
            if expected_size > MAX_ARCHIVE_MEMBER_BYTES:
                raise IntegrityError(
                    f"tar staging member exceeds its size limit: {name}"
                )
        specifications.append(
            (
                expected_name,
                is_directory,
                expected_size,
                expected_size,
                0o755 if is_directory else _canonical_file_mode(path),
            )
        )
    members, logical_end, _, digest = _scan_canonical_tar_gz(
        handle,
        expected=specifications,
        label="tar.gz archive",
        maximum_members=MAX_ARCHIVE_MEMBERS,
        expected_epoch=epoch,
    )
    return members, logical_end, digest


def verify_deterministic_tar_gz(stage: Path, archive_path: Path, epoch: int) -> None:
    expected = _archive_entries(stage)
    archive_path = _regular_file(archive_path, "tar.gz archive")
    expected_names = [
        name.rstrip("/") if is_directory else name for _, name, is_directory in expected
    ]
    try:
        with _stable_regular_handle(
            archive_path, "tar.gz archive"
        ) as (_, raw, _):
            initial_digest = _sha256_handle(raw)
            _, _, framing_digest = _preflight_expected_tar_gz(raw, expected, epoch)
            if framing_digest != initial_digest:
                raise IntegrityError("tar.gz archive changed during framing validation")
            raw.seek(0)
            with tarfile.open(fileobj=raw, mode="r:gz") as archive:
                if archive.pax_headers:
                    raise IntegrityError("tar archive has global PAX metadata")
                members = []
                logical_end = 0
                for member in archive:
                    if len(members) >= MAX_ARCHIVE_MEMBERS:
                        raise IntegrityError("tar archive has too many members")
                    members.append(member)
                    logical_end = max(logical_end, _tar_logical_end(member))
                logical_end = _validate_tar_member_offsets(members, "tar archive")
                if [member.name for member in members] != expected_names:
                    raise IntegrityError(
                        "tar entries are missing, reordered, or unexpected"
                    )
                for (path, name, is_directory), member in zip(
                    expected, members, strict=True
                ):
                    expected_mode = (
                        0o755 if is_directory else _canonical_file_mode(path)
                    )
                    if member.mtime != epoch or member.uid != 0 or member.gid != 0:
                        raise IntegrityError(
                            f"tar ownership or timestamp is not canonical: {name}"
                        )
                    if (
                        member.uname
                        or member.gname
                        or member.mode != expected_mode
                        or member.pax_headers
                        or member.devmajor != 0
                        or member.devminor != 0
                    ):
                        raise IntegrityError(f"tar names or mode are not canonical: {name}")
                    if is_directory:
                        if (
                            member.type != tarfile.DIRTYPE
                            or member.size != 0
                            or member.linkname
                        ):
                            raise IntegrityError(
                                f"tar directory has the wrong type: {name}"
                            )
                    else:
                        with _stable_regular_handle(
                            path, f"tar staging member {name}"
                        ) as (_, source, opened):
                            if (
                                member.type != tarfile.REGTYPE
                                or member.linkname
                                or member.size != opened.st_size
                            ):
                                raise IntegrityError(
                                    f"tar file has the wrong type or size: {name}"
                                )
                            extracted = archive.extractfile(member)
                            if extracted is None:
                                raise IntegrityError(f"tar member cannot be read: {name}")
                            with extracted:
                                while True:
                                    expected_chunk = source.read(1024 * 1024)
                                    packaged_chunk = extracted.read(1024 * 1024)
                                    if expected_chunk != packaged_chunk:
                                        raise IntegrityError(
                                            f"tar content differs from staging: {name}"
                                        )
                                    if not expected_chunk:
                                        break
            if _sha256_handle(raw) != initial_digest:
                raise IntegrityError("tar.gz archive changed during verification")
    except (OSError, tarfile.TarError) as error:
        raise IntegrityError(f"cannot verify tar.gz archive: {error}") from error


def _ar_number(field: bytes, label: str, base: int = 10) -> int:
    try:
        text = field.decode("ascii", "strict").strip()
        if not text or not re.fullmatch(r"[0-9]+", text):
            raise ValueError
        return int(text, base)
    except (UnicodeDecodeError, ValueError) as error:
        raise IntegrityError(f"Debian ar header has an invalid {label}") from error


def _deb_ar_members(path: Path) -> dict[str, bytes]:
    path = _regular_file(path, "Debian package")
    if path.stat().st_size > MAX_DEB_BYTES:
        raise IntegrityError("Debian package exceeds its size limit")
    data = path.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        raise IntegrityError("Debian package does not have an ar archive header")
    offset = 8
    rows: list[tuple[str, bytes]] = []
    while offset < len(data):
        if offset + 60 > len(data):
            raise IntegrityError("Debian ar member header is truncated")
        header = data[offset : offset + 60]
        offset += 60
        if header[58:60] != b"`\n":
            raise IntegrityError("Debian ar member header has an invalid trailer")
        try:
            encoded_name = header[:16].decode("ascii", "strict").rstrip()
        except UnicodeDecodeError as error:
            raise IntegrityError("Debian ar member name is not ASCII") from error
        name = encoded_name[:-1] if encoded_name.endswith("/") else encoded_name
        if name not in DEB_AR_MEMBERS:
            raise IntegrityError(f"Debian ar member is unexpected: {name!r}")
        _ar_number(header[16:28], "timestamp")
        _ar_number(header[28:34], "owner")
        _ar_number(header[34:40], "group")
        _ar_number(header[40:48], "mode", 8)
        size = _ar_number(header[48:58], "size")
        end = offset + size
        if end > len(data):
            raise IntegrityError("Debian ar member payload is truncated")
        rows.append((name, data[offset:end]))
        offset = end
        if size % 2:
            if offset >= len(data) or data[offset : offset + 1] != b"\n":
                raise IntegrityError("Debian ar member padding is invalid")
            offset += 1
    names = tuple(name for name, _ in rows)
    if names != DEB_AR_MEMBERS:
        raise IntegrityError("Debian ar members are missing, reordered, or repeated")
    members = dict(rows)
    if members["debian-binary"] != b"2.0\n":
        raise IntegrityError("Debian package format marker is not canonical 2.0")
    return members


def _deb_tar_name(value: str) -> str:
    if not value or "\\" in value or "\0" in value or "\n" in value or "\r" in value:
        raise IntegrityError(f"unsafe Debian tar member name: {value!r}")
    normalized = value[2:] if value.startswith("./") else value
    if normalized == ".":
        return normalized
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or path.as_posix() != normalized
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise IntegrityError(f"unsafe Debian tar member name: {value!r}")
    return normalized


def _deb_tar_manifest(data: bytes, label: str) -> list[dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    seen: set[str] = set()
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member_number, member in enumerate(archive, start=1):
                if member_number > MAX_DEB_MEMBERS:
                    raise IntegrityError(f"Debian {label} tar has too many members")
                name = _deb_tar_name(member.name)
                if name in seen:
                    raise IntegrityError(
                        f"Debian {label} tar repeats member: {name!r}"
                    )
                seen.add(name)
                if member.linkname or member.pax_headers:
                    raise IntegrityError(
                        "Debian "
                        f"{label} tar contains link or extended metadata: {name!r}"
                    )
                row: dict[str, object] = {
                    "mode": member.mode & 0o7777,
                    "name": name,
                }
                if member.isdir():
                    if member.size != 0:
                        raise IntegrityError(
                            f"Debian {label} directory has content: {name!r}"
                        )
                    row["type"] = "directory"
                    if name == ".":
                        if row["mode"] != 0o755:
                            raise IntegrityError(
                                f"Debian {label} root mode is not 0755"
                            )
                        continue
                elif member.isreg() and name != ".":
                    total_size += member.size
                    if total_size > MAX_DEB_BYTES:
                        raise IntegrityError(
                            f"Debian {label} tar exceeds its content size limit"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise IntegrityError(
                            f"Debian {label} file cannot be read: {name!r}"
                        )
                    content = extracted.read()
                    if len(content) != member.size:
                        raise IntegrityError(
                            f"Debian {label} file size is inconsistent: {name!r}"
                        )
                    row.update(
                        {
                            "sha256": _sha256_bytes(content),
                            "size": member.size,
                            "type": "file",
                        }
                    )
                else:
                    raise IntegrityError(
                        f"Debian {label} tar contains a link or special file: {name!r}"
                    )
                rows[name] = row
    except (OSError, tarfile.TarError) as error:
        raise IntegrityError(f"cannot inspect Debian {label} tar: {error}") from error
    return [rows[name] for name in sorted(rows)]


def inspect_debian_package(path: Path) -> str:
    members = _deb_ar_members(path)
    control = _deb_tar_manifest(members["control.tar.gz"], "control")
    payload = _deb_tar_manifest(members["data.tar.gz"], "payload")
    control_by_name = {row["name"]: row for row in control}
    payload_by_name = {row["name"]: row for row in payload}
    if control_by_name.get("control", {}).get("type") != "file":
        raise IntegrityError("Debian control tar lacks a regular control file")
    if payload_by_name.get("usr/bin/common-foundry-wallet", {}).get("type") != "file":
        raise IntegrityError("Debian payload lacks the Common Foundry wallet binary")
    semantic = {
        "control": control,
        "payload": payload,
        "schema": "CMFD_DEB_SEMANTIC_V1",
    }
    return _sha256_bytes(_canonical_json(semantic))


def _inventory_names(path: Path) -> tuple[list[str], bytes]:
    with _stable_regular_handle(path, "release inventory") as (_, handle, _):
        data = handle.read(MAX_BUILDINFO_BYTES + 1)
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise IntegrityError("release inventory is not UTF-8") from error
    if b"\r" in data or not data.endswith(b"\n"):
        raise IntegrityError("release inventory must be canonical LF-terminated UTF-8")
    names = text.splitlines()
    if not names or names != sorted(set(names)):
        raise IntegrityError("release inventory must be non-empty, sorted, and unique")
    for name in names:
        if name in (BUILDINFO_NAME, CHECKSUM_NAME):
            raise IntegrityError(f"release inventory must not list generated {name}")
        safe = _safe_repo_relative(name)
        if "/" in safe:
            raise IntegrityError("release inventory entries must be flat asset names")
    canonical = ("\n".join(names) + "\n").encode("utf-8")
    if data != canonical:
        raise IntegrityError("release inventory is not canonical")
    return names, data


def _stage_files(stage: Path) -> dict[str, Path]:
    stage = _regular_directory(stage, "release staging path")
    files: dict[str, Path] = {}
    with os.scandir(stage) as scan:
        entries = []
        for entry in scan:
            if len(entries) >= MAX_ARCHIVE_MEMBERS:
                raise IntegrityError("release staging has too many assets")
            entries.append(entry)
    for entry in entries:
        path = Path(entry.path)
        mode = entry.stat(follow_symlinks=False).st_mode
        if not stat.S_ISREG(mode):
            raise IntegrityError(
                f"release staging contains a non-regular asset: {path.name}"
            )
        files[path.name] = path
    return files


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _expected_buildinfo(
    *,
    repo: Path,
    commit: str,
    version: str,
    epoch: int,
    inventory_data: bytes,
    assets: dict[str, Path],
) -> dict[str, object]:
    artifact_rows = []
    for name in sorted(assets):
        size, digest = _sha256_file_with_size(
            assets[name], f"staged release asset {name}"
        )
        artifact_rows.append({"name": name, "sha256": digest, "size": size})
    return {
        "artifact_count": len(artifact_rows),
        "artifacts": artifact_rows,
        "commit": commit,
        "finalizer_sha256": _sha256_bytes(
            _tracked_blob(repo, "scripts/release_integrity.py")
        ),
        "inventory_sha256": _sha256_bytes(inventory_data),
        "schema": BUILDINFO_SCHEMA,
        "source_date_epoch": epoch,
        "source_tree": _run_git(repo, "rev-parse", "HEAD^{tree}").lower(),
        "version": _single_line("version", version),
    }


def _checksum_bytes(assets: dict[str, Path], buildinfo_bytes: bytes) -> bytes:
    rows = {name: _sha256_file(path) for name, path in assets.items()}
    rows[BUILDINFO_NAME] = _sha256_bytes(buildinfo_bytes)
    return ("".join(f"{rows[name]}  {name}\n" for name in sorted(rows))).encode("utf-8")


def _read_buildinfo(path: Path) -> tuple[dict[str, object], bytes]:
    with _stable_regular_handle(path, BUILDINFO_NAME) as (_, handle, _):
        data = handle.read(MAX_BUILDINFO_BYTES + 1)
    if len(data) > MAX_BUILDINFO_BYTES:
        raise IntegrityError("BUILDINFO.json exceeds its size limit")
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrityError("BUILDINFO.json is not canonical JSON") from error
    if not isinstance(value, dict) or _canonical_json(value) != data:
        raise IntegrityError("BUILDINFO.json is not in canonical form")
    return value, data


def verify_release(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    stage: Path,
    inventory: Path,
    source_date_epoch: str | int | None,
) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    epoch = _source_date_epoch(repo, source_date_epoch)
    inventory = _tracked_input_file(repo, inventory, "release inventory")
    names, inventory_data = _inventory_names(inventory)
    stage_files = _stage_files(stage)
    validate_production_rc_artifacts(
        version=version, commit=commit, stage_files=stage_files
    )
    validate_production_rc_source_versions(repo=repo, version=version)
    expected_names = set(names) | {BUILDINFO_NAME, CHECKSUM_NAME}
    if set(stage_files) != expected_names:
        missing = sorted(expected_names - set(stage_files))
        unexpected = sorted(set(stage_files) - expected_names)
        raise IntegrityError(
            f"release inventory mismatch; missing={missing}, unexpected={unexpected}"
        )
    assets = {name: stage_files[name] for name in names}
    expected_info = _expected_buildinfo(
        repo=repo,
        commit=commit,
        version=version,
        epoch=epoch,
        inventory_data=inventory_data,
        assets=assets,
    )
    actual_info, buildinfo_bytes = _read_buildinfo(stage_files[BUILDINFO_NAME])
    if actual_info != expected_info:
        raise IntegrityError(
            "BUILDINFO.json does not match source, inventory, or artifacts"
        )
    checksum_bytes = stage_files[CHECKSUM_NAME].read_bytes()
    expected_checksums = _checksum_bytes(assets, buildinfo_bytes)
    if checksum_bytes != expected_checksums:
        raise IntegrityError(
            "SHA256SUMS.txt is noncanonical or does not match the artifacts"
        )
    return expected_info


def finalize_release(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    stage: Path,
    inventory: Path,
    source_date_epoch: str | int | None,
) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    epoch = _source_date_epoch(repo, source_date_epoch)
    inventory = _tracked_input_file(repo, inventory, "release inventory")
    names, inventory_data = _inventory_names(inventory)
    stage_files = _stage_files(stage)
    validate_production_rc_artifacts(
        version=version, commit=commit, stage_files=stage_files
    )
    validate_production_rc_source_versions(repo=repo, version=version)
    if BUILDINFO_NAME in stage_files or CHECKSUM_NAME in stage_files:
        raise IntegrityError("generated release metadata already exists")
    if set(stage_files) != set(names):
        missing = sorted(set(names) - set(stage_files))
        unexpected = sorted(set(stage_files) - set(names))
        raise IntegrityError(
            f"release inventory mismatch; missing={missing}, unexpected={unexpected}"
        )
    assets = {name: stage_files[name] for name in names}
    buildinfo = _expected_buildinfo(
        repo=repo,
        commit=commit,
        version=version,
        epoch=epoch,
        inventory_data=inventory_data,
        assets=assets,
    )
    buildinfo_bytes = _canonical_json(buildinfo)
    checksum_bytes = _checksum_bytes(assets, buildinfo_bytes)
    _write_new(stage / BUILDINFO_NAME, buildinfo_bytes)
    try:
        _write_new(stage / CHECKSUM_NAME, checksum_bytes)
    except Exception:
        (stage / BUILDINFO_NAME).unlink(missing_ok=True)
        raise
    return verify_release(
        repo=repo,
        expected_commit=commit,
        version=version,
        stage=stage,
        inventory=inventory,
        source_date_epoch=epoch,
    )


def _add_repo_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)


def _add_native_common(parser: argparse.ArgumentParser) -> None:
    _add_repo_arguments(parser)
    parser.add_argument("--kind", choices=sorted(NATIVE_SOURCES), required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--source-date-epoch")


def _add_release_common(parser: argparse.ArgumentParser) -> None:
    _add_repo_arguments(parser)
    parser.add_argument("--version", required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--source-date-epoch")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    receipt_write = commands.add_parser(
        "receipt-write", help="write a canonical native build identity receipt"
    )
    _add_native_common(receipt_write)
    receipt_write.add_argument("--build-script", required=True)
    receipt_write.add_argument("--toolchain", required=True)
    receipt_write.add_argument("--target", required=True)
    receipt_write.add_argument("--architectures", required=True)
    receipt_write.add_argument("--output", type=Path, required=True)

    receipt_verify = commands.add_parser(
        "receipt-verify", help="verify a native build identity receipt"
    )
    _add_native_common(receipt_verify)
    receipt_verify.add_argument("--receipt", type=Path, required=True)
    receipt_verify.add_argument("--expected-build-script", required=True)
    receipt_verify.add_argument("--expected-target", required=True)
    receipt_verify.add_argument("--expected-architectures", required=True)

    zip_command = commands.add_parser(
        "archive-zip", help="create and verify a deterministic ZIP"
    )
    zip_command.add_argument("--stage", type=Path, required=True)
    zip_command.add_argument("--output", type=Path, required=True)
    zip_command.add_argument("--source-date-epoch", required=True)

    tar_command = commands.add_parser(
        "archive-tar-gz", help="create and verify a deterministic tar.gz"
    )
    tar_command.add_argument("--stage", type=Path, required=True)
    tar_command.add_argument("--output", type=Path, required=True)
    tar_command.add_argument("--source-date-epoch", required=True)

    deb_inspect = commands.add_parser(
        "deb-inspect", help="fail closed on unsafe Debian members and hash semantics"
    )
    deb_inspect.add_argument("--deb", type=Path, required=True)

    runtime_attestation = commands.add_parser(
        "runtime-attest",
        help="run a packaged node and create its platform network-info attestation",
    )
    runtime_attestation.add_argument(
        "--platform", choices=("windows-x86_64", "linux-x86_64"), required=True
    )
    runtime_attestation.add_argument("--package-directory", type=Path, required=True)
    runtime_attestation.add_argument("--expected-commit", required=True)
    runtime_attestation.add_argument("--output", type=Path, required=True)

    finalize = commands.add_parser(
        "finalize", help="generate and re-verify canonical release metadata"
    )
    _add_release_common(finalize)

    verify = commands.add_parser(
        "verify", help="re-verify canonical release metadata and assets"
    )
    _add_release_common(verify)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "receipt-write":
            result = write_native_build_receipt(
                repo=args.repo,
                expected_commit=args.expected_commit,
                kind=args.kind,
                library=args.library,
                build_script=args.build_script,
                toolchain=args.toolchain,
                target=args.target,
                architectures=args.architectures,
                output=args.output,
                source_date_epoch=args.source_date_epoch,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "receipt-verify":
            result = verify_native_build_receipt(
                repo=args.repo,
                expected_commit=args.expected_commit,
                kind=args.kind,
                library=args.library,
                receipt=args.receipt,
                expected_build_script=args.expected_build_script,
                expected_target=args.expected_target,
                expected_architectures=args.expected_architectures,
                source_date_epoch=args.source_date_epoch,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "archive-zip":
            epoch = _source_date_epoch(None, args.source_date_epoch)
            create_deterministic_zip(args.stage, args.output, epoch)
            print(f"{_sha256_file(args.output)}  {args.output.name}")
        elif args.command == "archive-tar-gz":
            epoch = _source_date_epoch(None, args.source_date_epoch)
            create_deterministic_tar_gz(args.stage, args.output, epoch)
            print(f"{_sha256_file(args.output)}  {args.output.name}")
        elif args.command == "deb-inspect":
            print(inspect_debian_package(args.deb))
        elif args.command == "runtime-attest":
            result = create_runtime_network_info_attestation(
                platform=args.platform,
                package_directory=args.package_directory,
                commit=args.expected_commit,
                output=args.output,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "finalize":
            result = finalize_release(
                repo=args.repo,
                expected_commit=args.expected_commit,
                version=args.version,
                stage=args.stage,
                inventory=args.inventory,
                source_date_epoch=args.source_date_epoch,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "verify":
            result = verify_release(
                repo=args.repo,
                expected_commit=args.expected_commit,
                version=args.version,
                stage=args.stage,
                inventory=args.inventory,
                source_date_epoch=args.source_date_epoch,
            )
            print(json.dumps(result, sort_keys=True))
        else:  # pragma: no cover - argparse guarantees a known command.
            raise IntegrityError("unsupported command")
    except (IntegrityError, OSError) as error:
        print(f"release-integrity: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
