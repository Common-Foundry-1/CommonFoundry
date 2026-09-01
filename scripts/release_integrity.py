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
import platform as host_platform
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

import production_v4_activation_approval as activation_approval
import tomllib

try:
    import blake3
except ImportError:  # Production runtime inspection reports the actionable error.
    blake3 = None

RECEIPT_SCHEMA = "CMFD_NATIVE_BUILD_RECEIPT_V1"
BUILDINFO_SCHEMA = "CMFD_RELEASE_BUILDINFO_V1"
REPRODUCIBLE_COMPARISON_SCHEMA = "CMFD_REPRODUCIBLE_RELEASE_COMPARISON_V1"
BUILDINFO_NAME = "BUILDINFO.json"
SOURCE_SBOM_NAME = "SOURCE-SBOM.json"
PROVENANCE_NAME = "PROVENANCE.intoto.jsonl"
CHECKSUM_NAME = "SHA256SUMS.txt"
CHECKSUM_SIGNATURE_NAME = "SHA256SUMS.txt.sig"
RELEASE_SIGNATURE_NAMESPACE = "commonfoundry-release"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_BUILDINFO_BYTES = 4 * 1024 * 1024
MAX_SOURCE_LOCK_BYTES = 16 * 1024 * 1024
MAX_SOURCE_COMPONENTS = 100_000
MAX_SOURCE_SBOM_BYTES = 32 * 1024 * 1024
MAX_PROVENANCE_BYTES = 4 * 1024 * 1024
MAX_CHECKSUM_BYTES = 4 * 1024 * 1024
MAX_RELEASE_SIGNATURE_BYTES = 64 * 1024
MAX_ALLOWED_SIGNERS_BYTES = 1024 * 1024
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
SIGNER_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}\Z")
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
PRODUCTION_V4_ACTIVATION_NAME = "PRODUCTION-V4-ACTIVATION.json"
PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME = (
    "PRODUCTION-V4-QUALIFICATION-MANIFEST.json"
)
PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME = (
    "PRODUCTION-V4-FRESH-PROCESS-VERIFIER.py"
)
PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME = (
    "PRODUCTION-V4-FRESH-PROCESS-VERIFIER-REPORT.json"
)
PRODUCTION_V4_PRODUCER_APPROVAL_NAME = (
    "PRODUCTION-V4-ACTIVATION-PRODUCER-APPROVAL.json"
)
PRODUCTION_V4_PRODUCER_APPROVAL_SIGNATURE_NAME = (
    "PRODUCTION-V4-ACTIVATION-PRODUCER-APPROVAL.json.sig"
)
PRODUCTION_V4_PRODUCER_ALLOWED_SIGNERS_NAME = (
    "PRODUCTION-V4-ACTIVATION-PRODUCER.allowed_signers"
)
PRODUCTION_V4_REPRODUCER_APPROVAL_NAME = (
    "PRODUCTION-V4-ACTIVATION-REPRODUCER-APPROVAL.json"
)
PRODUCTION_V4_REPRODUCER_APPROVAL_SIGNATURE_NAME = (
    "PRODUCTION-V4-ACTIVATION-REPRODUCER-APPROVAL.json.sig"
)
PRODUCTION_V4_REPRODUCER_ALLOWED_SIGNERS_NAME = (
    "PRODUCTION-V4-ACTIVATION-REPRODUCER.allowed_signers"
)
PRODUCTION_V4_ACTIVATION_PIN_RELATIVE = (
    "crates/cmfd-node/production_v4_activation_pin.inc.rs"
)
PRODUCTION_V4_VERIFIER_ENTRYPOINT_RELATIVE = (
    "scripts/production-v4-independent-verifier.py"
)
PRODUCTION_V4_RCNET_INPUT_MANIFEST_NAME = "production-v4-rcnet-1-inputs.json"
PRODUCTION_V4_RCNET_NETWORK_NAME = "CommonFoundry RCNet-1"
PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME = (
    "commonfoundry-rc-runtime-windows-x86_64.zip"
)
PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME = (
    "commonfoundry-rc-runtime-linux-x86_64.tar.gz"
)
PRODUCTION_RC_WINDOWS_ATTESTATION_NAME = "RUNTIME-ATTESTATION-WINDOWS-X86_64.json"
PRODUCTION_RC_LINUX_ATTESTATION_NAME = "RUNTIME-ATTESTATION-LINUX-X86_64.json"
PRODUCTION_RC_RUNTIME_ATTESTATION_SCHEMA = "CMFD_RUNTIME_NETWORK_INFO_ATTESTATION_V1"
PRODUCTION_V4_RUNTIME_ATTESTATION_SCHEMA = "CMFD_RUNTIME_NETWORK_INFO_ATTESTATION_V3"
WALLET_RUNTIME_IDENTITY_SCHEMA = "CMFD_WALLET_RUNTIME_IDENTITY_V1"
WALLET_RUNTIME_IDENTITY_ROLE = "common-foundry-wallet"
PRODUCTION_RC_RUNTIME_ROOTS = {
    "windows-x86_64": "commonfoundry-rc-runtime-windows-x86_64",
    "linux-x86_64": "commonfoundry-rc-runtime-linux-x86_64",
}
PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY = "production-v3"
PRODUCTION_V3_PACKAGE_BANK = "MODEL-V2.bank"
PRODUCTION_V3_PACKAGE_MANIFEST = "MODEL-V2.manifest.json"
PRODUCTION_V3_PACKAGE_RECORD_V2 = "DORY-V3-MODEL-RECORD-V2.json"
PRODUCTION_V4_PACKAGE_ARTIFACT_DIRECTORY = "production-v4"
PRODUCTION_V4_PACKAGE_BANK = "MODEL-V2.bank"
PRODUCTION_V4_PACKAGE_FIXED_RECORD = "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
PRODUCTION_V4_MODEL_BANK_FILE_BYTES = 6_442_975_416
PRODUCTION_V4_MODEL_BANK_FILE_BLAKE3 = (
    "b8be8450b933dc759aa34f2d60e73cf4eac3064407c6a9f48372175abe87b6ac"
)
PRODUCTION_V4_MODEL_BANK_FILE_SHA256 = (
    "5f9b213c3bda51b74e4ebabb26607b67385d613aa8d99af915a48ab063e17d4e"
)
PRODUCTION_V4_FIXED_RECORD_FILE_BYTES = 6_973
PRODUCTION_V4_FIXED_RECORD_FILE_BLAKE3 = (
    "3c9587fb833234cdfa88b97502a89abba613b9002c16bb6483b34d5399deebd0"
)
PRODUCTION_V4_FIXED_RECORD_FILE_SHA256 = (
    "ea218831aa567e486426ded77c84a5752a817329c496e3557c6d43577f0afe79"
)
PRODUCTION_V4_RCNET_INPUT_NAMES = (
    PRODUCTION_V4_PACKAGE_BANK,
    PRODUCTION_V4_PACKAGE_FIXED_RECORD,
    *(
        f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}"
        for bank in range(3)
        for suffix in ("row-major.codeword", "tree")
    ),
)
PRODUCTION_V4_VERIFIER_FILE_NAMES = (
    "production-v4-verify-qualification.py",
    "production-v4-independent-verifier.py",
    "production_v4_independent_verifier.py",
    "production_v4_transcript.py",
    "production_v4_poseidon.py",
    "production_v4_wire.py",
)
PRODUCTION_V4_ACTIVATION_APPROVAL_ERROR = (
    "ProductionV4 activation requires signed producer and independent reproducer "
    "approval payloads, identities, and trusted allowed-signers authorities"
)
PRODUCTION_V4_CORE_SPEC_SHA256 = (
    "507075fb6d22b7ac0968508b18c48a09a017806e7d4e0454b71f8ae88440df84"
)
PRODUCTION_V4_CORE_VECTOR_SHA256 = (
    "c885ae499a65c5bb965e08f4894a0d2768d823b0e23979958f00e3db73e0b168"
)
PRODUCTION_V4_PROOF_ALGEBRA_SHA256 = (
    "5a686ad518a7d957b8af908fb52cd58056e63da4dab578a40d4ef097654aaf33"
)
PRODUCTION_V4_FROZEN_SPEC_SHA256 = {
    "docs/consensus/production-v4-core-spec-v1.md": PRODUCTION_V4_CORE_SPEC_SHA256,
    "docs/consensus/production-v4-core-vector-v1.json": PRODUCTION_V4_CORE_VECTOR_SHA256,
    "docs/consensus/production-v4-proof-algebra-v1.md": PRODUCTION_V4_PROOF_ALGEBRA_SHA256,
}
INSECURE_DEV_REWARD_DESTINATIONS = {
    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
    "6360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7",
}
PRODUCTION_RC_SERVICE_PORTS = {
    "rpc_port": 19_443,
    "p2p_port": 19_444,
    "pool_port": 19_445,
}
PRODUCTION_RC_BOOTSTRAP_PEER = "173.249.35.251:19444"
PRODUCTION_RC_CONSENSUS_FINGERPRINT = (
    "fadb0d51f3df9a33a414dac2b8a82f8c6f17b84c8ab665aae9da07c406d215d4"
)
RCNET_LAUNCH_CANDIDATE_V2_SCHEMA = "CMFD_RCNET_LAUNCH_CANDIDATE_V2"
RCNET_LAUNCH_ROOT_V2_CONTEXT = "CMFD/RCNET/LAUNCH-ROOT/V2"
RCNET_NETWORK_ID_V2_CONTEXT = "CMFD/RCNET/NETWORK-ID/V2"
RCNET_VIRTUAL_GENESIS_V2_CONTEXT = "CMFD/RCNET/VIRTUAL-GENESIS/V2"
PRODUCTION_RC_NETWORK_ID = (
    "3e99d45959c19c0053d8e9fef34875b57b46a8a1ce330637daddab515bc7b92d"
)
PRODUCTION_RC_LAUNCH_ROOT = (
    "748f32c069e721221b8ba17df358eb35ec0e05d93f3a31ee0c1a135c87bb7b85"
)
PRODUCTION_RC_VIRTUAL_GENESIS_HASH = (
    "a572b6ce50978511ce8771db6603a602faccf3802cf0d4791c1ce4e467ba6b71"
)
PRODUCTION_RC_VIRTUAL_GENESIS_TIMESTAMP = "1788800400"
PRODUCTION_RC_POW_LIMIT = (
    "003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)
PRODUCTION_V4_PROOF_SYSTEM_DIGEST = (
    "e849e3bfc83f8f8dd0f1fc1100879417718ba2bffb92af5cd649b61c720675a3"
)
PRODUCTION_V4_MODEL_MANIFEST_DIGEST = (
    "68f6fe674f75a363c62c275ebb11fa74aa089e9bbde5bcb952ec35b8890b575c"
)
PRODUCTION_V4_FIXED_ARTIFACT_FORMAT_DIGEST = (
    "1c26e090041e96e5ef805747b87cf5bd591d5d127a3b86dee5cca5945e57df44"
)
PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST = (
    "2efd2c4244bbd7808547b85266987544233fbe339f445135b07843aa8893d45e"
)
PRODUCTION_RC_VERSION_FILES = (
    "apps/wallet/package.json",
    "apps/wallet/src-tauri/Cargo.toml",
    "apps/wallet/src-tauri/tauri.conf.json",
    "apps/wallet/src-tauri/tauri.rcnet.conf.json",
    "crates/cmfd-miner/Cargo.toml",
    "crates/cmfd-node/Cargo.toml",
    "crates/cmfd-proof-worker/Cargo.toml",
)
SOURCE_LOCK_FILES = (
    "Cargo.lock",
    "apps/pool-dashboard/package-lock.json",
    "apps/wallet/package-lock.json",
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


def reject_production_rc_source_assets(
    stage_files: dict[str, Path],
    *,
    allowed_source_assets: frozenset[str] = frozenset(),
) -> None:
    """Keep reviewed binary stages from accidentally carrying source bundles."""
    for name in stage_files:
        if name in {
            BUILDINFO_NAME,
            SOURCE_SBOM_NAME,
            PROVENANCE_NAME,
            CHECKSUM_NAME,
            CHECKSUM_SIGNATURE_NAME,
        } or name in allowed_source_assets:
            continue
        normalized = name.strip().lower()
        if (
            SOURCE_ASSET_TOKEN_RE.search(normalized)
            or normalized in {"cargo.toml", "cargo.lock"}
            or normalized.endswith((".crate", ".py", ".rs"))
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


def _runtime_artifact_directory(selection: str) -> str:
    if selection == "ProductionV3":
        return PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY
    if selection == "ProductionV4":
        return PRODUCTION_V4_PACKAGE_ARTIFACT_DIRECTORY
    raise IntegrityError(f"unsupported production proof selection: {selection}")


def _runtime_package_paths(
    platform: str, selection: str = "ProductionV3"
) -> tuple[set[str], str | None]:
    if platform == "windows-x86_64":
        suffix = ".exe"
    elif platform == "linux-x86_64":
        suffix = ""
    else:  # pragma: no cover - callers use the two frozen release targets.
        raise IntegrityError(f"unsupported production runtime platform: {platform}")
    artifact_directory = _runtime_artifact_directory(selection)
    worker = f"cmfd-proof-worker{suffix}" if selection == "ProductionV3" else None
    if selection == "ProductionV4":
        artifacts = {
            f"{artifact_directory}/{PRODUCTION_V4_PACKAGE_BANK}",
            f"{artifact_directory}/{PRODUCTION_V4_PACKAGE_FIXED_RECORD}",
        }
    else:
        artifacts = {
            f"{artifact_directory}/{PRODUCTION_V3_PACKAGE_BANK}",
            f"{artifact_directory}/{PRODUCTION_V3_PACKAGE_MANIFEST}",
            f"{artifact_directory}/{PRODUCTION_V3_PACKAGE_RECORD_V2}",
        }
    return (
        {
            f"cmfd-node{suffix}",
            f"common-foundry-wallet{suffix}",
            *({worker} if worker is not None else set()),
            *artifacts,
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
            "production runtime inspection requires the pinned Python blake3 dependency"
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


def _runtime_member_limit(relative: str, selection: str = "ProductionV3") -> int:
    if relative.endswith(
        (
            PRODUCTION_V3_PACKAGE_MANIFEST,
            PRODUCTION_V3_PACKAGE_RECORD_V2,
            PRODUCTION_V4_PACKAGE_FIXED_RECORD,
        )
    ):
        return MAX_RELEASE_GATE_JSON_BYTES
    if relative.startswith(f"{_runtime_artifact_directory(selection)}/"):
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
    *,
    platform: str,
    member: object,
    relative: str,
    is_directory: bool,
    selection: str = "ProductionV3",
) -> None:
    artifact_directory = _runtime_artifact_directory(selection)
    expected_mode = 0o755 if is_directory or not relative.startswith(
        f"{artifact_directory}/"
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
    *,
    platform: str,
    members: object,
    open_member: object,
    selection: str = "ProductionV3",
) -> dict[str, dict[str, object]]:
    expected, _ = _runtime_package_paths(platform, selection)
    artifact_directory = _runtime_artifact_directory(selection)
    expected_root = _runtime_package_root(platform)
    expected_order = sorted(expected | {"", artifact_directory})
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
            selection=selection,
        )
        if is_directory:
            if relative not in ("", artifact_directory):
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
                    (
                        PRODUCTION_V3_PACKAGE_MANIFEST,
                        PRODUCTION_V3_PACKAGE_RECORD_V2,
                        PRODUCTION_V4_PACKAGE_FIXED_RECORD,
                    )
                )
                else MAX_EXECUTABLE_HEADER_BYTES
                if not relative.startswith(f"{artifact_directory}/")
                else 0
            )
            actual_size, digest, blake3_hash, captured = _stream_sha256(
                source,
                expected_size=size,
                maximum_size=_runtime_member_limit(relative, selection),
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
    selection: str = "ProductionV3",
) -> tuple[list[tarfile.TarInfo], int, int, str]:
    expected, _ = _runtime_package_paths(platform, selection)
    artifact_directory = _runtime_artifact_directory(selection)
    expected_root = _runtime_package_root(platform)
    expected_order = sorted(expected | {"", artifact_directory})
    expected_artifact_sizes = expected_artifact_sizes or {}
    specifications: list[tuple[str, bool, int | None, int, int]] = []
    for relative in expected_order:
        is_directory = relative in (
            "",
            artifact_directory,
        )
        name = expected_root if not relative else f"{expected_root}/{relative}"
        exact_size = 0 if is_directory else expected_artifact_sizes.get(relative)
        maximum_size = (
            0 if is_directory else _runtime_member_limit(relative, selection)
        )
        mode = 0o755 if is_directory or not relative.startswith(
            f"{artifact_directory}/"
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
    selection: str = "ProductionV3",
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
                        selection=selection,
                    )
                if _sha256_handle(raw) != initial_digest:
                    raise IntegrityError("Windows runtime ZIP changed during inspection")
                return rows
        with _stable_regular_handle(
            package, "Linux runtime tar.gz"
        ) as (_, raw, _):
            initial_digest = _sha256_handle(raw)
            _, _, _, framing_digest = _preflight_runtime_tar_gz(
                raw, platform, expected_artifact_sizes, selection
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
                    selection=selection,
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


def _json_byte_array_hex(value: object, label: str) -> str:
    if (
        not isinstance(value, list)
        or len(value) != 32
        or any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or not 0 <= item <= 255
            for item in value
        )
    ):
        raise IntegrityError(f"{label} is not an exact 32-byte array")
    return bytes(value).hex()


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


def _validate_runtime_rows_v3(
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


def _validate_runtime_rows_v4(
    *,
    rows: dict[str, dict[str, object]],
    platform: str,
    staged_network_info: dict[str, object],
) -> None:
    suffix = ".exe" if platform == "windows-x86_64" else ""
    for name in (f"cmfd-node{suffix}", f"common-foundry-wallet{suffix}"):
        header = rows[name]["captured"]
        if not isinstance(header, bytes):  # pragma: no cover - internal row contract.
            raise IntegrityError(f"{platform} runtime {name} header is unavailable")
        if platform == "windows-x86_64":
            _validate_pe_x86_64(header, rows[name]["bytes"], f"{platform} runtime {name}")
        else:
            _validate_elf_x86_64(header, rows[name]["bytes"], f"{platform} runtime {name}")

    proof = staged_network_info.get("proof_of_work")
    if not isinstance(proof, dict) or proof.get("selection") != "ProductionV4":
        raise IntegrityError("staged NETWORK-INFO proof identity is not ProductionV4")
    pins = proof.get("artifacts")
    if not isinstance(pins, dict) or set(pins) != {"bank", "fixed_record"}:
        raise IntegrityError(f"{platform} runtime artifact identity pins are incomplete")
    file_names = {
        "bank": PRODUCTION_V4_PACKAGE_BANK,
        "fixed_record": PRODUCTION_V4_PACKAGE_FIXED_RECORD,
    }
    labels = {"bank": "model bank", "fixed_record": "fixed artifact record"}
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
        relative = f"{PRODUCTION_V4_PACKAGE_ARTIFACT_DIRECTORY}/{file_name}"
        row = rows[relative]
        if (
            row["bytes"] != expected_bytes
            or row["sha256"] != expected_sha256
            or row["blake3"] != expected_blake3
        ):
            raise IntegrityError(
                f"{platform} packaged {labels[role]} does not match NETWORK-INFO.json"
            )
    if pins["fixed_record"] != {
        "bytes": str(PRODUCTION_V4_FIXED_RECORD_FILE_BYTES),
        "blake3": PRODUCTION_V4_FIXED_RECORD_FILE_BLAKE3,
        "sha256": PRODUCTION_V4_FIXED_RECORD_FILE_SHA256,
    }:
        raise IntegrityError(
            f"{platform} fixed artifact record does not match the immutable ProductionV4 file"
        )

    record_row = rows[
        f"{PRODUCTION_V4_PACKAGE_ARTIFACT_DIRECTORY}/{PRODUCTION_V4_PACKAGE_FIXED_RECORD}"
    ]
    record_bytes = record_row["captured"]
    if not isinstance(record_bytes, bytes):  # pragma: no cover - internal row contract.
        raise IntegrityError(f"{platform} packaged fixed artifact record is unavailable")
    record = _json_object_bytes(
        record_bytes, f"{platform} packaged fixed artifact record"
    )
    _require_exact_fields(
        record,
        {
            "record_version",
            "proof_system_digest",
            "manifest",
            "manifest_digest",
            "artifact_format_digest",
            "banks",
            "record_digest",
        },
        f"{platform} packaged fixed artifact record",
    )
    canonical_record = (
        json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if record_bytes != canonical_record:
        raise IntegrityError(
            f"{platform} packaged fixed artifact record is not canonical pretty JSON"
        )
    record_digests = {
        "proof_system_digest": _json_byte_array_hex(
            record["proof_system_digest"],
            f"{platform} fixed artifact proof-system digest",
        ),
        "model_manifest_digest": _json_byte_array_hex(
            record["manifest_digest"],
            f"{platform} fixed artifact model-manifest digest",
        ),
        "fixed_artifact_record_digest": _json_byte_array_hex(
            record["record_digest"],
            f"{platform} fixed artifact record digest",
        ),
    }
    if (
        record["record_version"] != 1
        or not isinstance(record["manifest"], dict)
        or not isinstance(record["banks"], list)
        or len(record["banks"]) != 3
        or _json_byte_array_hex(
            record["artifact_format_digest"],
            f"{platform} fixed artifact format digest",
        )
        != PRODUCTION_V4_FIXED_ARTIFACT_FORMAT_DIGEST
        or record_digests
        != {
            "proof_system_digest": PRODUCTION_V4_PROOF_SYSTEM_DIGEST,
            "model_manifest_digest": PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            "fixed_artifact_record_digest": PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST,
        }
        or any(proof.get(field) != expected for field, expected in record_digests.items())
    ):
        raise IntegrityError(
            f"{platform} packaged fixed artifact record does not match frozen ProductionV4 identity"
        )


def _validate_runtime_rows(
    *,
    rows: dict[str, dict[str, object]],
    platform: str,
    staged_network_info: dict[str, object],
) -> None:
    proof = staged_network_info.get("proof_of_work")
    selection = proof.get("selection") if isinstance(proof, dict) else None
    if selection == "ProductionV3":
        _validate_runtime_rows_v3(
            rows=rows, platform=platform, staged_network_info=staged_network_info
        )
        return
    if selection == "ProductionV4":
        _validate_runtime_rows_v4(
            rows=rows, platform=platform, staged_network_info=staged_network_info
        )
        return
    raise IntegrityError("staged NETWORK-INFO proof selection is unsupported")


def _validate_runtime_package(
    *,
    path: Path,
    platform: str,
    staged_network_info: dict[str, object],
) -> dict[str, dict[str, object]]:
    proof = staged_network_info.get("proof_of_work")
    selection = proof.get("selection") if isinstance(proof, dict) else None
    if selection == "ProductionV3":
        artifact_directory = PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY
        artifact_files = (
            ("bank", PRODUCTION_V3_PACKAGE_BANK),
            ("manifest", PRODUCTION_V3_PACKAGE_MANIFEST),
            ("record_v2", PRODUCTION_V3_PACKAGE_RECORD_V2),
        )
    elif selection == "ProductionV4":
        artifact_directory = PRODUCTION_V4_PACKAGE_ARTIFACT_DIRECTORY
        artifact_files = (
            ("bank", PRODUCTION_V4_PACKAGE_BANK),
            ("fixed_record", PRODUCTION_V4_PACKAGE_FIXED_RECORD),
        )
    else:
        raise IntegrityError("staged NETWORK-INFO proof selection is unsupported")
    pins = proof.get("artifacts") if isinstance(proof, dict) else None
    if not isinstance(pins, dict) or set(pins) != {role for role, _ in artifact_files}:
        raise IntegrityError(f"{platform} runtime artifact identity pins are incomplete")
    expected_artifact_sizes: dict[str, int] = {}
    for role, file_name in artifact_files:
        pin = _require_exact_fields(
            pins.get(role), {"bytes", "blake3", "sha256"}, f"{platform} {role} pin"
        )
        try:
            expected_size = int(pin["bytes"])
        except (TypeError, ValueError) as error:
            raise IntegrityError(f"{platform} {role} byte length is invalid") from error
        relative = f"{artifact_directory}/{file_name}"
        if (
            str(expected_size) != pin["bytes"]
            or expected_size <= 0
            or expected_size > _runtime_member_limit(relative, selection)
        ):
            raise IntegrityError(f"{platform} {role} byte length is invalid")
        expected_artifact_sizes[relative] = expected_size
    rows = _inspect_runtime_package_archive(
        path, platform, expected_artifact_sizes, selection
    )
    _validate_runtime_rows(
        rows=rows, platform=platform, staged_network_info=staged_network_info
    )
    return rows


def _validate_wallet_runtime_identity(
    identity_bytes: bytes,
    *,
    platform: str,
    version: str,
    network_bytes: bytes,
) -> dict[str, object]:
    if len(identity_bytes) > MAX_RELEASE_GATE_JSON_BYTES:
        raise IntegrityError(f"{platform} wallet runtime identity exceeds its size limit")
    identity = _json_object_bytes(
        identity_bytes, f"{platform} packaged-wallet runtime identity"
    )
    if identity_bytes != _canonical_json(identity):
        raise IntegrityError(f"{platform} packaged-wallet runtime identity is not canonical")
    _require_exact_fields(
        identity,
        {"network_info_base64", "package_version", "role", "schema"},
        f"{platform} packaged-wallet runtime identity",
    )
    if (
        identity["schema"] != WALLET_RUNTIME_IDENTITY_SCHEMA
        or identity["role"] != WALLET_RUNTIME_IDENTITY_ROLE
        or identity["package_version"] != version
    ):
        raise IntegrityError(f"{platform} packaged-wallet runtime identity is invalid")
    encoded = identity["network_info_base64"]
    if not isinstance(encoded, str) or len(encoded) > 2 * MAX_RELEASE_GATE_JSON_BYTES:
        raise IntegrityError(
            f"{platform} packaged-wallet runtime network identity is invalid"
        )
    try:
        wallet_network_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IntegrityError(
            f"{platform} packaged-wallet runtime network identity is not canonical base64"
        ) from error
    if base64.b64encode(wallet_network_bytes).decode("ascii") != encoded:
        raise IntegrityError(
            f"{platform} packaged-wallet runtime network identity is not canonical base64"
        )
    if wallet_network_bytes != network_bytes:
        raise IntegrityError(
            f"{platform} packaged wallet did not report the packaged-node network identity"
        )
    return identity


def _validate_runtime_attestation(
    *,
    path: Path,
    platform: str,
    commit: str,
    version: str,
    rows: dict[str, dict[str, object]],
    staged_network_info: dict[str, object],
) -> None:
    attestation, attestation_bytes = _bounded_json_object(
        path, f"{platform} packaged-node network-info attestation"
    )
    if attestation_bytes != _canonical_json(attestation):
        raise IntegrityError(
            f"{platform} packaged-node network-info attestation is not canonical"
        )
    proof = staged_network_info.get("proof_of_work")
    selection = proof.get("selection") if isinstance(proof, dict) else None
    common_fields = {
        "schema",
        "platform",
        "source_commit",
        "node_sha256",
        "wallet_sha256",
        "network_info_sha256",
        "network_info_base64",
    }
    if selection == "ProductionV3":
        expected_fields = common_fields | {"worker_sha256"}
        expected_schema = PRODUCTION_RC_RUNTIME_ATTESTATION_SCHEMA
    elif selection == "ProductionV4":
        expected_fields = common_fields | {
            "wallet_runtime_identity_sha256",
            "wallet_runtime_identity_base64",
        }
        expected_schema = PRODUCTION_V4_RUNTIME_ATTESTATION_SCHEMA
    else:
        raise IntegrityError("staged NETWORK-INFO proof selection is unsupported")
    _require_exact_fields(
        attestation,
        expected_fields,
        f"{platform} packaged-node network-info attestation",
    )
    if (
        attestation["schema"] != expected_schema
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
    expected_network = staged_network_info
    if selection == "ProductionV3":
        expected_network = json.loads(json.dumps(staged_network_info))
        expected_proof = expected_network.get("proof_of_work")
        if not isinstance(expected_proof, dict):  # pragma: no cover
            raise IntegrityError("staged NETWORK-INFO proof identity is missing")
        expected_proof["runtime_verifier_worker_sha256"] = _compiled_runtime_worker(
            expected_proof, platform
        )
    if attested_network != expected_network:
        raise IntegrityError(
            f"{platform} packaged node did not report the staged network identity"
        )
    if selection == "ProductionV4":
        wallet_encoded = attestation["wallet_runtime_identity_base64"]
        if (
            not isinstance(wallet_encoded, str)
            or len(wallet_encoded) > 2 * MAX_RELEASE_GATE_JSON_BYTES
        ):
            raise IntegrityError(f"{platform} attested wallet runtime identity is invalid")
        try:
            wallet_identity_bytes = base64.b64decode(wallet_encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise IntegrityError(
                f"{platform} attested wallet runtime identity is not canonical base64"
            ) from error
        if (
            base64.b64encode(wallet_identity_bytes).decode("ascii") != wallet_encoded
            or attestation["wallet_runtime_identity_sha256"]
            != _sha256_bytes(wallet_identity_bytes)
        ):
            raise IntegrityError(
                f"{platform} attested wallet runtime identity is invalid"
            )
        _validate_wallet_runtime_identity(
            wallet_identity_bytes,
            platform=platform,
            version=version,
            network_bytes=network_bytes,
        )
        canonical_network_bytes = (
            json.dumps(attested_network, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        if network_bytes != canonical_network_bytes:
            raise IntegrityError(
                f"{platform} attested packaged-node network information is not canonical"
            )
    suffix = ".exe" if platform == "windows-x86_64" else ""
    expected_hashes = {
        "node_sha256": rows[f"cmfd-node{suffix}"]["sha256"],
        "wallet_sha256": rows[f"common-foundry-wallet{suffix}"]["sha256"],
    }
    if expected_hashes["node_sha256"] == expected_hashes["wallet_sha256"]:
        raise IntegrityError(
            f"{platform} packaged node and wallet executables are not distinct"
        )
    if selection == "ProductionV3":
        expected_hashes["worker_sha256"] = rows[f"cmfd-proof-worker{suffix}"]["sha256"]
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
    version: str,
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
    selection = proof.get("selection")
    if selection == "ProductionV3":
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
    elif selection != "ProductionV4":
        raise IntegrityError("staged NETWORK-INFO proof selection is unsupported")
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
        version=version,
        rows=windows_rows,
        staged_network_info=staged_network_info,
    )
    _validate_runtime_attestation(
        path=stage_files[PRODUCTION_RC_LINUX_ATTESTATION_NAME],
        platform="linux-x86_64",
        commit=commit,
        version=version,
        rows=linux_rows,
        staged_network_info=staged_network_info,
    )
    return {
        "windows-x86_64": windows_rows,
        "linux-x86_64": linux_rows,
    }


def create_runtime_network_info_attestation(
    *,
    platform: str,
    package_directory: Path,
    commit: str,
    output: Path,
    version: str | None = None,
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
    selection = proof.get("selection") if isinstance(proof, dict) else None
    if not isinstance(proof, dict) or proof.get("build_source_commit") != commit:
        raise IntegrityError(
            f"{platform} packaged node reported an unexpected compiled identity"
        )
    worker_path = package_directory / f"cmfd-proof-worker{suffix}"
    if selection == "ProductionV3":
        paths["worker_sha256"] = worker_path
        with _stable_regular_handle(
            worker_path, f"{platform} packaged {worker_path.name}"
        ) as (_, handle, opened):
            header = handle.read(MAX_EXECUTABLE_HEADER_BYTES)
            if platform == "windows-x86_64":
                _validate_pe_x86_64(header, opened.st_size, worker_path.name)
            else:
                _validate_elf_x86_64(header, opened.st_size, worker_path.name)
            identities["worker_sha256"] = _sha256_handle(handle)
        if proof.get("runtime_verifier_worker_sha256") != identities["worker_sha256"]:
            raise IntegrityError(
                f"{platform} packaged node reported an unexpected proof-worker identity"
            )
        schema = PRODUCTION_RC_RUNTIME_ATTESTATION_SCHEMA
    elif selection == "ProductionV4":
        if os.path.lexists(worker_path):
            raise IntegrityError(
                f"{platform} ProductionV4 runtime must not contain a proof worker"
            )
        if version is None:
            raise IntegrityError(
                f"{platform} ProductionV4 runtime attestation requires an expected package version"
            )
        version = _single_line("expected package version", version)
        if not is_production_rc_label(version):
            raise IntegrityError(
                f"{platform} ProductionV4 runtime package version is not an RC label"
            )
        _validate_production_v4_runtime_identity(network, commit)
        canonical_network_bytes = (
            json.dumps(network, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        if process.stdout != canonical_network_bytes:
            raise IntegrityError(
                f"{platform} packaged-node network information is not canonical"
            )
        try:
            wallet_process = subprocess.run(
                [str(paths["wallet_sha256"]), "runtime-identity"],
                cwd=package_directory,
                check=False,
                capture_output=True,
                timeout=20 * 60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise IntegrityError(
                f"{platform} packaged wallet runtime-identity execution failed"
            ) from error
        if (
            wallet_process.returncode != 0
            or wallet_process.stderr
            or len(wallet_process.stdout) > MAX_RELEASE_GATE_JSON_BYTES
        ):
            raise IntegrityError(
                f"{platform} packaged wallet runtime-identity execution was not clean"
            )
        _validate_wallet_runtime_identity(
            wallet_process.stdout,
            platform=platform,
            version=version,
            network_bytes=process.stdout,
        )
        schema = PRODUCTION_V4_RUNTIME_ATTESTATION_SCHEMA
    else:
        raise IntegrityError(
            f"{platform} packaged node reported an unsupported proof selection"
        )
    for field, path in paths.items():
        if _sha256_file(path) != identities[field]:
            raise IntegrityError(f"{platform} packaged executable changed during attestation")
    if identities["node_sha256"] == identities["wallet_sha256"]:
        raise IntegrityError(
            f"{platform} packaged node and wallet executables are not distinct"
        )
    attestation: dict[str, object] = {
        "network_info_base64": base64.b64encode(process.stdout).decode("ascii"),
        "network_info_sha256": _sha256_bytes(process.stdout),
        "node_sha256": identities["node_sha256"],
        "platform": platform,
        "schema": schema,
        "source_commit": commit,
        "wallet_sha256": identities["wallet_sha256"],
    }
    if selection == "ProductionV3":
        attestation["worker_sha256"] = identities["worker_sha256"]
    else:
        attestation["wallet_runtime_identity_base64"] = base64.b64encode(
            wallet_process.stdout
        ).decode("ascii")
        attestation["wallet_runtime_identity_sha256"] = _sha256_bytes(
            wallet_process.stdout
        )
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


def _validate_rcnet_launch_candidate_v1(
    candidate: dict[str, object], network_info: dict[str, object]
) -> None:
    _require_exact_fields(
        candidate,
        {"schema", "payload", "launch_root", "network_id", "virtual_genesis_hash"},
        "RCNet launch candidate",
    )
    if candidate["schema"] != "CMFD_RCNET_LAUNCH_CANDIDATE_V1":
        raise IntegrityError("RCNet launch candidate schema is unsupported")
    compiled_proof = network_info.get("proof_of_work")
    if not isinstance(compiled_proof, dict) or compiled_proof.get("selection") != "ProductionV3":
        raise IntegrityError(
            "legacy RCNet launch candidate is valid only for compiled ProductionV3"
        )
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
        network.get("name") != payload["profile"]
        or network.get("network_id") != network_id
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


def _require_unsigned_integer(
    value: object, label: str, *, positive: bool = False
) -> int:
    minimum = 1 if positive else 0
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= (1 << 64) - 1
    ):
        qualifier = "positive " if positive else ""
        raise IntegrityError(f"{label} is not a {qualifier}unsigned integer")
    return value


def _require_xonly_public_key(value: object, label: str) -> str:
    encoded = _require_hex256(value, label, reject_repeated=False)
    coordinate = int(encoded, 16)
    field_prime = (1 << 256) - (1 << 32) - 977
    if coordinate >= field_prime:
        raise IntegrityError(f"{label} is not a valid secp256k1 x-only public key")
    curve_value = (pow(coordinate, 3, field_prime) + 7) % field_prime
    if pow(curve_value, (field_prime - 1) // 2, field_prime) != 1:
        raise IntegrityError(f"{label} is not a valid secp256k1 x-only public key")
    return encoded


def _require_rcnet_v2_file_identity(value: object, label: str) -> dict[str, object]:
    identity = _require_exact_fields(value, {"bytes", "blake3", "sha256"}, label)
    _require_unsigned_integer(identity["bytes"], f"{label} byte length", positive=True)
    _require_hex256(identity["blake3"], f"{label} BLAKE3", reject_repeated=False)
    _require_hex256(identity["sha256"], f"{label} SHA-256", reject_repeated=False)
    return identity


def _rcnet_v2_derived_hash(context: str, data: bytes) -> bytes:
    if blake3 is None:
        raise IntegrityError(
            "the Python blake3 module is required to validate an RCNet launch candidate"
        )
    return blake3.blake3(data, derive_key_context=context).digest()


def _validate_rcnet_launch_candidate_v2(
    candidate: dict[str, object], network_info: dict[str, object] | None = None
) -> dict[str, object]:
    _require_exact_fields(
        candidate,
        {"schema", "payload", "launch_root", "network_id", "virtual_genesis_hash"},
        "RCNet launch candidate",
    )
    if candidate["schema"] != RCNET_LAUNCH_CANDIDATE_V2_SCHEMA:
        raise IntegrityError("RCNet launch candidate schema is unsupported")
    payload = _require_exact_fields(
        candidate["payload"],
        {
            "profile",
            "artifacts",
            "virtual_genesis_timestamp_unix_seconds",
            "consensus",
            "proof_of_work",
            "monetary_policy",
            "reward_destinations",
        },
        "RCNet launch payload",
    )
    if payload["profile"] != "CommonFoundry RCNet-1":
        raise IntegrityError("RCNet launch candidate profile is invalid")

    artifacts = _require_exact_fields(
        payload["artifacts"],
        {
            "bank",
            "fixed_record",
            "fixed_record_version",
            "proof_system_digest",
            "model_manifest_digest",
            "fixed_artifact_format_digest",
            "fixed_artifact_record_digest",
        },
        "RCNet ProductionV4 artifacts",
    )
    bank = _require_rcnet_v2_file_identity(
        artifacts["bank"], "RCNet ProductionV4 bank identity"
    )
    fixed_record = _require_rcnet_v2_file_identity(
        artifacts["fixed_record"], "RCNet ProductionV4 fixed-record identity"
    )
    _require_unsigned_integer(
        artifacts["fixed_record_version"],
        "RCNet ProductionV4 fixed-record version",
        positive=True,
    )
    expected_artifact_fields = {
        "fixed_record_version": 1,
        "proof_system_digest": PRODUCTION_V4_PROOF_SYSTEM_DIGEST,
        "model_manifest_digest": PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
        "fixed_artifact_format_digest": PRODUCTION_V4_FIXED_ARTIFACT_FORMAT_DIGEST,
        "fixed_artifact_record_digest": PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST,
    }
    for field, expected in expected_artifact_fields.items():
        if artifacts[field] != expected:
            raise IntegrityError(
                f"RCNet ProductionV4 {field} does not match the frozen consensus value"
            )

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
    consensus = _require_exact_fields(
        payload["consensus"], set(consensus_fields), "RCNet consensus parameters"
    )
    for field in consensus_fields:
        _require_unsigned_integer(consensus[field], f"RCNet consensus {field}")
    expected_consensus = {
        "network_protocol_version": 2,
        "block_version": 1,
        "transaction_version": 1,
        "wire_version": 1,
        "maximum_future_offset_seconds": 86_400,
        "target_spacing_seconds": 60,
        "coinbase_maturity_blocks": 100,
        "median_time_window": 11,
        "max_block_transactions": 1_024,
        "max_transaction_inputs": 128,
        "max_transaction_outputs": 128,
        "max_block_aggregate_inputs": 4_096,
        "max_block_aggregate_outputs": 4_096,
        "max_block_signature_checks": 2_048,
        "max_coinbase_outputs": 3,
        "consensus_signature_bytes": 64,
        "dgw_window": 180,
        "wire_header_bytes": 16,
        "max_transaction_bytes": 65_536,
        "max_proof_bytes": 13 * 1024 * 1024,
        "max_block_bytes": 16 * 1024 * 1024,
    }
    if consensus != expected_consensus:
        raise IntegrityError("RCNet consensus does not match the frozen ProductionV4 values")

    timestamp = _require_unsigned_integer(
        payload["virtual_genesis_timestamp_unix_seconds"],
        "RCNet virtual genesis timestamp",
        positive=True,
    )
    if timestamp > (1 << 64) - 1 - consensus["maximum_future_offset_seconds"]:
        raise IntegrityError("RCNet virtual genesis timestamp future-offset calculation overflows")

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
    proof = _require_exact_fields(
        payload["proof_of_work"], set(proof_fields), "RCNet proof-of-work parameters"
    )
    expected_proof_fields = {
        "selection": "ProductionV4",
        "wire_type": 4,
        "algorithm_version": 4,
        "proof_version": 1,
        "banks": 3,
        "layers_per_bank": 128,
        "exact_transparent_proof_bytes": 12_025_320,
    }
    for field in (
        "wire_type",
        "algorithm_version",
        "proof_version",
        "banks",
        "layers_per_bank",
        "exact_transparent_proof_bytes",
    ):
        _require_unsigned_integer(proof[field], f"RCNet proof-of-work {field}")
    for field, expected in expected_proof_fields.items():
        if proof[field] != expected:
            raise IntegrityError(
                f"RCNet {field} does not match the frozen ProductionV4 value"
            )
    _require_hex256(
        proof["pow_limit"], "RCNet proof-of-work limit", reject_repeated=False
    )

    monetary_fields = (
        "atoms_per_coin",
        "initial_subsidy_atoms",
        "tail_height",
        "tail_subsidy_atoms",
        "steward_percent",
        "community_percent",
    )
    monetary_policy = _require_exact_fields(
        payload["monetary_policy"], set(monetary_fields), "RCNet monetary policy"
    )
    for field in monetary_fields:
        _require_unsigned_integer(monetary_policy[field], f"RCNet monetary policy {field}")
    if monetary_policy != {
        "atoms_per_coin": 100_000_000,
        "initial_subsidy_atoms": 50_000_000_000,
        "tail_height": 2_628_001,
        "tail_subsidy_atoms": 500_000_000,
        "steward_percent": 25,
        "community_percent": 5,
    }:
        raise IntegrityError("RCNet monetary policy does not match the frozen values")

    reward_fields = ("steward_xonly_public_key", "community_xonly_public_key")
    rewards = _require_exact_fields(
        payload["reward_destinations"], set(reward_fields), "RCNet reward destinations"
    )
    for field in reward_fields:
        destination = _require_xonly_public_key(rewards[field], f"RCNet {field}")
        if destination in INSECURE_DEV_REWARD_DESTINATIONS:
            raise IntegrityError("RCNet reward destination is a known insecure development key")

    canonical_payload = {
        "profile": payload["profile"],
        "artifacts": {
            "bank": {
                "bytes": bank["bytes"],
                "blake3": bank["blake3"],
                "sha256": bank["sha256"],
            },
            "fixed_record": {
                "bytes": fixed_record["bytes"],
                "blake3": fixed_record["blake3"],
                "sha256": fixed_record["sha256"],
            },
            "fixed_record_version": artifacts["fixed_record_version"],
            "proof_system_digest": artifacts["proof_system_digest"],
            "model_manifest_digest": artifacts["model_manifest_digest"],
            "fixed_artifact_format_digest": artifacts["fixed_artifact_format_digest"],
            "fixed_artifact_record_digest": artifacts["fixed_artifact_record_digest"],
        },
        "virtual_genesis_timestamp_unix_seconds": timestamp,
        "consensus": {field: consensus[field] for field in consensus_fields},
        "proof_of_work": {field: proof[field] for field in proof_fields},
        "monetary_policy": {
            field: monetary_policy[field] for field in monetary_fields
        },
        "reward_destinations": {field: rewards[field] for field in reward_fields},
    }
    payload_bytes = json.dumps(
        canonical_payload, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    expected_launch_root = _rcnet_v2_derived_hash(
        RCNET_LAUNCH_ROOT_V2_CONTEXT, payload_bytes
    )
    launch_root = _require_hex256(
        candidate["launch_root"], "RCNet launch root", reject_repeated=True
    )
    if launch_root != expected_launch_root.hex():
        raise IntegrityError("RCNet launch root is not derived from the canonical V2 payload")
    expected_network_id = _rcnet_v2_derived_hash(
        RCNET_NETWORK_ID_V2_CONTEXT, expected_launch_root
    ).hex()
    network_id = _require_hex256(
        candidate["network_id"], "RCNet network ID", reject_repeated=True
    )
    if network_id != expected_network_id:
        raise IntegrityError("RCNet network ID is not derived from the V2 launch root")
    expected_genesis = _rcnet_v2_derived_hash(
        RCNET_VIRTUAL_GENESIS_V2_CONTEXT, expected_launch_root
    ).hex()
    genesis = _require_hex256(
        candidate["virtual_genesis_hash"],
        "RCNet virtual genesis",
        reject_repeated=True,
    )
    if genesis != expected_genesis:
        raise IntegrityError("RCNet virtual genesis is not derived from the V2 launch root")
    if len({launch_root, network_id, genesis}) != 3:
        raise IntegrityError("RCNet launch root and derived identities are not distinct")

    validated = {
        "artifacts": artifacts,
        "bank": bank,
        "canonical_payload": canonical_payload,
        "consensus": consensus,
        "fixed_record": fixed_record,
        "genesis": genesis,
        "launch_root": launch_root,
        "monetary_policy": monetary_policy,
        "network_id": network_id,
        "proof": proof,
        "rewards": rewards,
        "timestamp": timestamp,
    }
    if network_info is None:
        return validated

    network = network_info.get("network")
    compiled_proof = network_info.get("proof_of_work")
    compiled_rewards = network_info.get("reward_destinations")
    compiled_consensus = network_info.get("consensus")
    compiled_monetary_policy = network_info.get("monetary_policy")
    if not isinstance(network, dict) or (
        network.get("network_id") != network_id
        or network.get("virtual_genesis_hash") != genesis
        or network.get("virtual_genesis_timestamp_unix_seconds") != str(timestamp)
    ):
        raise IntegrityError("compiled RCNet identity does not match the launch candidate")
    if not isinstance(compiled_proof, dict):
        raise IntegrityError("compiled RCNet ProductionV4 parameters are missing")
    compiled_proof_fields = (
        "selection",
        "wire_type",
        "algorithm_version",
        "proof_version",
        "pow_limit",
    )
    for field in compiled_proof_fields:
        actual = compiled_proof.get(field)
        if actual != proof[field] or type(actual) is not type(proof[field]):
            raise IntegrityError(
                "compiled RCNet proof-of-work parameters do not match the launch candidate"
            )
    if compiled_proof.get("exact_transparent_proof_bytes") != str(
        proof["exact_transparent_proof_bytes"]
    ):
        raise IntegrityError(
            "compiled RCNet proof-of-work parameters do not match the launch candidate"
        )
    compiled_digest_fields = (
        "proof_system_digest",
        "model_manifest_digest",
        "fixed_artifact_record_digest",
    )
    for field in compiled_digest_fields:
        if compiled_proof.get(field) != artifacts[field]:
            raise IntegrityError(
                "compiled RCNet ProductionV4 digests do not match the launch candidate"
            )
    compiled_artifacts = compiled_proof.get("artifacts")
    if not isinstance(compiled_artifacts, dict):
        raise IntegrityError("compiled RCNet ProductionV4 artifact identities are missing")
    for field, identity in (("bank", bank), ("fixed_record", fixed_record)):
        compiled_identity = compiled_artifacts.get(field)
        if not isinstance(compiled_identity, dict) or compiled_identity != {
            "bytes": str(identity["bytes"]),
            "blake3": identity["blake3"],
            "sha256": identity["sha256"],
        }:
            raise IntegrityError(
                "compiled RCNet ProductionV4 artifacts do not match the launch candidate"
            )
    if not isinstance(compiled_rewards, dict) or compiled_rewards != rewards:
        raise IntegrityError("compiled RCNet reward destinations do not match the launch candidate")
    if not isinstance(compiled_consensus, dict):
        raise IntegrityError("compiled RCNet consensus parameters are missing")
    versions = compiled_consensus.get("versions")
    limits = compiled_consensus.get("limits")
    version_fields = set(consensus_fields[:4])
    for field in consensus_fields:
        if field in version_fields:
            actual = versions.get(field) if isinstance(versions, dict) else None
            expected = consensus[field]
        else:
            actual = limits.get(field) if isinstance(limits, dict) else None
            expected = str(consensus[field])
        if actual != expected or type(actual) is not type(expected):
            raise IntegrityError(
                "compiled RCNet consensus parameters do not match the launch candidate"
            )
    if not isinstance(compiled_monetary_policy, dict):
        raise IntegrityError("compiled RCNet monetary policy is missing")
    for field in monetary_fields:
        value = monetary_policy[field]
        expected = value if field.endswith("_percent") else str(value)
        actual = compiled_monetary_policy.get(field)
        if actual != expected or type(actual) is not type(expected):
            raise IntegrityError(
                "compiled RCNet monetary policy does not match the launch candidate"
            )
    return validated


def _validate_production_v4_rcnet_candidate(
    candidate: dict[str, object], network_info: dict[str, object] | None = None
) -> dict[str, object]:
    validated = _validate_rcnet_launch_candidate_v2(candidate, network_info)
    expected_identity = {
        "launch_root": PRODUCTION_RC_LAUNCH_ROOT,
        "network_id": PRODUCTION_RC_NETWORK_ID,
        "genesis": PRODUCTION_RC_VIRTUAL_GENESIS_HASH,
        "timestamp": int(PRODUCTION_RC_VIRTUAL_GENESIS_TIMESTAMP),
    }
    for field, expected in expected_identity.items():
        if validated[field] != expected:
            raise IntegrityError(
                f"RCNet launch candidate does not match the immutable {field}"
            )
    proof = validated["proof"]
    if not isinstance(proof, dict) or proof.get("pow_limit") != PRODUCTION_RC_POW_LIMIT:
        raise IntegrityError("RCNet launch candidate does not match the immutable pow_limit")
    expected_artifacts = {
        "bank": {
            "bytes": PRODUCTION_V4_MODEL_BANK_FILE_BYTES,
            "blake3": PRODUCTION_V4_MODEL_BANK_FILE_BLAKE3,
            "sha256": PRODUCTION_V4_MODEL_BANK_FILE_SHA256,
        },
        "fixed_record": {
            "bytes": PRODUCTION_V4_FIXED_RECORD_FILE_BYTES,
            "blake3": PRODUCTION_V4_FIXED_RECORD_FILE_BLAKE3,
            "sha256": PRODUCTION_V4_FIXED_RECORD_FILE_SHA256,
        },
    }
    for role, expected in expected_artifacts.items():
        if validated[role] != expected:
            raise IntegrityError(
                f"RCNet launch candidate does not match the immutable ProductionV4 {role}"
            )
    return validated


def _validate_rcnet_launch_candidate(
    candidate: dict[str, object], network_info: dict[str, object]
) -> None:
    validated = _require_exact_fields(
        candidate,
        {"schema", "payload", "launch_root", "network_id", "virtual_genesis_hash"},
        "RCNet launch candidate",
    )
    if validated["schema"] == RCNET_LAUNCH_CANDIDATE_V2_SCHEMA:
        _validate_rcnet_launch_candidate_v2(candidate, network_info)
        return
    if validated["schema"] == "CMFD_RCNET_LAUNCH_CANDIDATE_V1":
        _validate_rcnet_launch_candidate_v1(candidate, network_info)
        return
    raise IntegrityError("RCNet launch candidate schema is unsupported")


def _validate_production_v3_rc_artifacts(
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
        stage_files=stage_files,
        staged_network_info=network_info,
        commit=commit,
        version=version,
    )


def _validate_report_file_identity(value: object, label: str) -> dict[str, object]:
    row = _require_exact_fields(value, {"name", "bytes", "sha256", "blake3"}, label)
    name = row["name"]
    byte_count = row["bytes"]
    if (
        not isinstance(name, str)
        or not name
        or PurePosixPath(name).name != name
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count <= 0
    ):
        raise IntegrityError(f"{label} has an invalid name or byte length")
    _require_hex256(row["sha256"], f"{label} SHA-256", reject_repeated=False)
    _require_hex256(row["blake3"], f"{label} BLAKE3", reject_repeated=False)
    return row


def _validate_production_v4_statement(
    value: object, expected_network_id: str
) -> dict[str, object]:
    statement = _require_exact_fields(
        value,
        {"schema", "block", "candidate"},
        "ProductionV4 qualification statement",
    )
    if (
        statement["schema"]
        != "CommonFoundry/ForgeMatrix/V4/IndependentVerifierInput/v1"
    ):
        raise IntegrityError("ProductionV4 qualification statement schema is invalid")
    block = _require_exact_fields(
        statement["block"],
        {
            "network_id",
            "previous_block",
            "transaction_root",
            "height",
            "timestamp",
            "target",
        },
        "ProductionV4 qualification statement block",
    )
    for field in ("network_id", "previous_block", "transaction_root", "target"):
        _require_hex256(
            block[field],
            f"ProductionV4 qualification statement {field}",
            reject_repeated=False,
        )
    if block["network_id"] != expected_network_id:
        raise IntegrityError(
            "ProductionV4 qualification statement is not bound to the RCNet candidate"
        )
    for field in ("height", "timestamp"):
        _require_unsigned_integer(
            block[field], f"ProductionV4 qualification statement {field}"
        )
    if int(str(block["target"]), 16) == 0:
        raise IntegrityError("ProductionV4 qualification statement target is zero")

    candidate = _require_exact_fields(
        statement["candidate"],
        {
            "algorithm_version",
            "proof_version",
            "nonce",
            "proof_system_digest",
            "model_manifest_digest",
            "challenge_digest",
            "final_activation_digest",
            "work_digest",
        },
        "ProductionV4 qualification statement candidate",
    )
    for field in ("algorithm_version", "proof_version", "nonce"):
        _require_unsigned_integer(
            candidate[field], f"ProductionV4 qualification statement {field}"
        )
    if (
        candidate["algorithm_version"] != 4
        or candidate["proof_version"] != 1
        or candidate["proof_system_digest"] != PRODUCTION_V4_PROOF_SYSTEM_DIGEST
        or candidate["model_manifest_digest"] != PRODUCTION_V4_MODEL_MANIFEST_DIGEST
    ):
        raise IntegrityError("ProductionV4 qualification statement identity is invalid")
    for field in (
        "proof_system_digest",
        "model_manifest_digest",
        "challenge_digest",
        "final_activation_digest",
        "work_digest",
    ):
        _require_hex256(
            candidate[field],
            f"ProductionV4 qualification statement {field}",
            reject_repeated=False,
        )
    if int(str(candidate["work_digest"]), 16) > int(str(block["target"]), 16):
        raise IntegrityError("ProductionV4 qualification statement does not meet its target")
    return statement


def _validate_production_v4_derived(
    value: object, statement: dict[str, object], label: str
) -> dict[str, object]:
    derived = _require_exact_fields(
        value,
        {
            "challenge_digest",
            "final_activation_digest",
            "work_digest",
            "transcript_statement_digest",
        },
        label,
    )
    candidate = statement["candidate"]
    if not isinstance(candidate, dict):  # pragma: no cover - validated statement contract.
        raise IntegrityError("ProductionV4 qualification statement candidate is missing")
    for field in derived:
        _require_hex256(derived[field], f"{label} {field}", reject_repeated=False)
    for field in ("challenge_digest", "final_activation_digest", "work_digest"):
        if derived[field] != candidate[field]:
            raise IntegrityError(f"{label} does not match the qualification statement")
    return derived


def _validate_production_v4_qualification_manifest(
    manifest: dict[str, object], proof: dict[str, object], expected_network_id: str
) -> tuple[
    str,
    str,
    tuple[int, str],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    _require_exact_fields(
        manifest,
        {
            "schema",
            "status",
            "reproduction_complete",
            "fresh_generation_attested",
            "operator",
            "reproducer_source_commit",
            "artifact_generation_source_commit",
            "environment",
            "toolchains",
            "generation_commands",
            "frozen_specifications",
            "core_vector",
            "input_manifest",
            "artifacts",
            "proof_verification",
            "statement",
        },
        "ProductionV4 qualification manifest",
    )
    source_commit = manifest["reproducer_source_commit"]
    generation_commit = manifest["artifact_generation_source_commit"]
    if (
        manifest["schema"]
        != "CommonFoundry/ForgeMatrix/V4/IndependentReproductionReport/v1"
        or manifest["status"] != "verified"
        or manifest["reproduction_complete"] is not True
        or manifest["fresh_generation_attested"] is not True
        or not isinstance(manifest["operator"], str)
        or not manifest["operator"].strip()
        or not isinstance(source_commit, str)
        or not FULL_COMMIT_RE.fullmatch(source_commit)
        or set(source_commit) == {"0"}
        or not isinstance(generation_commit, str)
        or not FULL_COMMIT_RE.fullmatch(generation_commit)
        or set(generation_commit) == {"0"}
    ):
        raise IntegrityError("ProductionV4 qualification manifest is incomplete or invalid")

    environment = _require_exact_fields(
        manifest["environment"],
        {"system", "release", "machine", "python", "byteorder"},
        "ProductionV4 qualification environment",
    )
    if environment["byteorder"] != "little" or any(
        not isinstance(environment[field], str) or not environment[field].strip()
        for field in ("system", "release", "machine", "python")
    ):
        raise IntegrityError("ProductionV4 qualification environment is invalid")
    toolchains = _require_exact_fields(
        manifest["toolchains"],
        {"python", "git", "rustc", "cargo", "nvcc"},
        "ProductionV4 qualification toolchains",
    )
    if any(
        not isinstance(toolchains[field], str) or not toolchains[field].strip()
        for field in ("python", "rustc", "cargo", "nvcc")
    ) or (
        toolchains["git"] is not None
        and (
            not isinstance(toolchains["git"], str)
            or not toolchains["git"].strip()
        )
    ):
        raise IntegrityError("ProductionV4 qualification toolchain identity is incomplete")
    commands = manifest["generation_commands"]
    if (
        not isinstance(commands, list)
        or not commands
        or any(not isinstance(command, str) or not command.strip() for command in commands)
    ):
        raise IntegrityError("ProductionV4 qualification generation commands are incomplete")

    specifications = manifest["frozen_specifications"]
    if not isinstance(specifications, list):
        raise IntegrityError("ProductionV4 frozen specification identities are missing")
    specification_hashes: dict[str, str] = {}
    for value in specifications:
        row = _require_exact_fields(
            value,
            {"name", "path", "bytes", "sha256", "blake3"},
            "ProductionV4 frozen specification identity",
        )
        path = row["path"]
        if (
            not isinstance(path, str)
            or _safe_repo_relative(path) != path
            or row["name"] != PurePosixPath(path).name
            or not isinstance(row["bytes"], int)
            or isinstance(row["bytes"], bool)
            or row["bytes"] <= 0
        ):
            raise IntegrityError("ProductionV4 frozen specification identity is invalid")
        _require_hex256(
            row["blake3"],
            "ProductionV4 frozen specification BLAKE3",
            reject_repeated=False,
        )
        _require_hex256(
            row["sha256"],
            "ProductionV4 frozen specification SHA-256",
            reject_repeated=False,
        )
        if path in specification_hashes:
            raise IntegrityError("ProductionV4 frozen specification identity is duplicated")
        specification_hashes[path] = row["sha256"]
    if specification_hashes != PRODUCTION_V4_FROZEN_SPEC_SHA256:
        raise IntegrityError(
            "ProductionV4 frozen specification identities do not match the release"
        )

    core_vector = _require_exact_fields(
        manifest["core_vector"],
        {"schema", "derived", "rejections_verified"},
        "ProductionV4 core-vector qualification",
    )
    derived = _require_exact_fields(
        core_vector["derived"],
        {
            "challenge_digest",
            "final_activation_digest",
            "work_digest",
            "transcript_statement_digest",
        },
        "ProductionV4 core-vector derived identity",
    )
    expected_derived = {
        "challenge_digest": "523a47eb90c07299243a1aa8fa7ca07a67b0527dfbd6b367bb14a3ea8dbb6a23",
        "final_activation_digest": "c9802d97d27707d05cf38db9286866c4fbd40a5a5a76809cb654b4d3f221844b",
        "work_digest": "e9c3ec2fd53ab08340e58a642733a6d528e476ce19a9247e0983d6f71ee2606a",
        "transcript_statement_digest": "9c3e50fa124dbb2df551ec893c44d1a9813b6245d0f981e1a4e10884e4bd0387",
    }
    if (
        core_vector["schema"]
        != "CommonFoundry/ForgeMatrix/V4/CoreCanonicalVector/v1"
        or core_vector["rejections_verified"] != 5
        or derived != expected_derived
    ):
        raise IntegrityError("ProductionV4 core-vector qualification is invalid")

    input_manifest = _validate_report_file_identity(
        manifest["input_manifest"], "ProductionV4 qualification input manifest"
    )
    if input_manifest["name"] != PRODUCTION_V4_RCNET_INPUT_MANIFEST_NAME:
        raise IntegrityError("ProductionV4 qualification input manifest identity is invalid")
    artifact_values = manifest["artifacts"]
    if not isinstance(artifact_values, list) or not artifact_values:
        raise IntegrityError("ProductionV4 qualification artifact identities are missing")
    artifact_rows: dict[str, dict[str, object]] = {}
    for value in artifact_values:
        row = _validate_report_file_identity(value, "ProductionV4 qualification artifact")
        name = str(row["name"])
        if name in artifact_rows:
            raise IntegrityError("ProductionV4 qualification artifact identity is duplicated")
        artifact_rows[name] = row
    expected_artifact_names = {
        PRODUCTION_V4_PACKAGE_BANK,
        PRODUCTION_V4_PACKAGE_FIXED_RECORD,
        *(
            f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}"
            for bank in range(3)
            for suffix in ("json", "codeword", "row-major.codeword", "tree")
        ),
    }
    if set(artifact_rows) != expected_artifact_names:
        raise IntegrityError("ProductionV4 qualification artifact set is incomplete")
    compiled_artifacts = _require_exact_fields(
        proof.get("artifacts"),
        {"bank", "fixed_record"},
        "compiled ProductionV4 artifact identities",
    )
    for role, name in (
        ("bank", PRODUCTION_V4_PACKAGE_BANK),
        ("fixed_record", PRODUCTION_V4_PACKAGE_FIXED_RECORD),
    ):
        pin = _require_exact_fields(
            compiled_artifacts[role],
            {"bytes", "blake3", "sha256"},
            f"compiled ProductionV4 {role} identity",
        )
        report_row = artifact_rows.get(name)
        try:
            compiled_bytes = int(pin["bytes"])
        except (TypeError, ValueError) as error:
            raise IntegrityError(
                f"compiled ProductionV4 {role} byte length is invalid"
            ) from error
        if (
            str(compiled_bytes) != pin["bytes"]
            or compiled_bytes <= 0
            or report_row is None
            or report_row["bytes"] != compiled_bytes
            or report_row["sha256"] != pin["sha256"]
            or report_row["blake3"] != pin["blake3"]
        ):
            raise IntegrityError(
                f"compiled ProductionV4 {role} does not match qualification evidence"
            )

    statement = _validate_production_v4_statement(
        manifest["statement"], expected_network_id
    )
    verification = manifest["proof_verification"]
    if (
        not isinstance(verification, dict)
        or verification.get("implemented_stages_accepted") is not True
        or verification.get("full_cryptographic_proof_verified") is not True
        or verification.get("candidate_claims_verified") is not False
    ):
        raise IntegrityError("ProductionV4 qualification proof verification is incomplete")
    proof_result = verification.get("proof")
    if (
        not isinstance(proof_result, dict)
        or proof_result.get("schema")
        != "CommonFoundry/ForgeMatrix/V4/WireConformanceResult/v1"
        or proof_result.get("canonical") is not True
        or proof_result.get("bytes") != 12_025_320
    ):
        raise IntegrityError("ProductionV4 qualification proof identity is invalid")
    proof_sha256 = _require_hex256(
        proof_result.get("sha256"),
        "ProductionV4 qualification proof SHA-256",
        reject_repeated=False,
    )
    verification_derived = _validate_production_v4_derived(
        verification.get("derived"), statement, "ProductionV4 qualification derived values"
    )
    statement_block = statement["block"]
    if (
        not isinstance(statement_block, dict)  # pragma: no cover - validated above.
        or verification.get("target") != statement_block["target"]
        or verification.get("target_met") is not True
    ):
        raise IntegrityError("ProductionV4 qualification target evidence is invalid")
    return (
        str(source_commit),
        str(generation_commit),
        (12_025_320, proof_sha256),
        statement,
        input_manifest,
        verification_derived,
    )


def _validate_production_v4_verifier_report(
    report: dict[str, object],
    qualification_source_commit: str,
    qualification_proof: tuple[int, str],
    qualification_statement: dict[str, object],
    qualification_derived: dict[str, object],
    verifier_script_identity: tuple[int, str, str],
) -> None:
    _require_exact_fields(
        report,
        {
            "schema",
            "status",
            "source_commit",
            "operator",
            "fresh_process_verifier",
            "verifier_files",
            "known_valid_proof",
            "statement_derivation",
            "known_valid_result",
            "mutation_rejections",
        },
        "ProductionV4 fresh-process verifier report",
    )
    if (
        report["schema"]
        != "CommonFoundry/ForgeMatrix/V4/IndependentVerifierQualification/v1"
        or report["status"] != "verified"
        or report["source_commit"] != qualification_source_commit
        or report["fresh_process_verifier"] is not True
        or not isinstance(report["operator"], str)
        or not report["operator"].strip()
    ):
        raise IntegrityError("ProductionV4 fresh-process verifier report is invalid")
    verifier_files = report["verifier_files"]
    if not isinstance(verifier_files, list) or not verifier_files:
        raise IntegrityError("ProductionV4 fresh-process verifier files are missing")
    verifier_rows: dict[str, dict[str, object]] = {}
    for value in verifier_files:
        row = _validate_report_file_identity(
            value, "ProductionV4 fresh-process verifier file"
        )
        name = str(row["name"])
        if name in verifier_rows:
            raise IntegrityError("ProductionV4 fresh-process verifier file is duplicated")
        verifier_rows[name] = row
    expected_verifier_names = set(PRODUCTION_V4_VERIFIER_FILE_NAMES)
    if set(verifier_rows) != expected_verifier_names:
        raise IntegrityError("ProductionV4 fresh-process verifier file set is incomplete")
    script_bytes, script_sha256, script_blake3 = verifier_script_identity
    verifier_entrypoint = verifier_rows["production-v4-independent-verifier.py"]
    if (
        verifier_entrypoint["bytes"] != script_bytes
        or verifier_entrypoint["sha256"] != script_sha256
        or verifier_entrypoint["blake3"] != script_blake3
    ):
        raise IntegrityError(
            "staged ProductionV4 verifier script is not bound by the verifier report"
        )
    known_proof = _validate_report_file_identity(
        report["known_valid_proof"], "ProductionV4 known-valid proof"
    )
    if (known_proof["bytes"], known_proof["sha256"]) != qualification_proof:
        raise IntegrityError(
            "ProductionV4 verifier report proof does not match qualification evidence"
        )
    statement_derivation = _require_exact_fields(
        report["statement_derivation"],
        {"command", "result"},
        "ProductionV4 statement derivation",
    )
    known_valid = _require_exact_fields(
        report["known_valid_result"],
        {"command", "result"},
        "ProductionV4 known-valid verifier result",
    )
    for label, value in (
        ("statement derivation", statement_derivation),
        ("known-valid verification", known_valid),
    ):
        command = value["command"]
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(item, str) or not item for item in command)
            or not isinstance(value["result"], dict)
        ):
            raise IntegrityError(f"ProductionV4 {label} evidence is invalid")
    if (
        statement_derivation["result"].get("schema")
        != "CommonFoundry/ForgeMatrix/V4/IndependentVerificationResult/v1"
        or statement_derivation["result"].get("implemented_stages_accepted") is not True
        or statement_derivation["result"].get("full_cryptographic_proof_verified")
        is not False
        or statement_derivation["result"].get("candidate_claims_verified") is not False
        or known_valid["result"].get("schema")
        != "CommonFoundry/ForgeMatrix/V4/IndependentVerificationResult/v1"
        or known_valid["result"].get("implemented_stages_accepted") is not True
        or known_valid["result"].get("full_cryptographic_proof_verified") is not True
        or known_valid["result"].get("candidate_claims_verified") is not True
    ):
        raise IntegrityError(
            "ProductionV4 fresh-process verifier acceptance evidence is invalid"
        )
    for label, result in (
        ("statement derivation", statement_derivation["result"]),
        ("known-valid verification", known_valid["result"]),
    ):
        result_proof = result.get("proof")
        if (
            not isinstance(result_proof, dict)
            or result_proof.get("bytes") != known_proof["bytes"]
            or result_proof.get("sha256") != known_proof["sha256"]
        ):
            raise IntegrityError(f"ProductionV4 {label} proof identity is invalid")
        result_derived = _validate_production_v4_derived(
            result.get("derived"),
            qualification_statement,
            f"ProductionV4 {label} derived values",
        )
        statement_block = qualification_statement["block"]
        if (
            result_derived != qualification_derived
            or not isinstance(statement_block, dict)  # pragma: no cover - validated above.
            or result.get("target") != statement_block["target"]
            or result.get("target_met") is not True
        ):
            raise IntegrityError(
                f"ProductionV4 {label} is not bound to the qualification statement"
            )

    mutation_values = report["mutation_rejections"]
    expected_mutations = {
        "truncated": 12_025_319,
        "trailing-byte": 12_025_321,
        "noncanonical-field": 12_025_320,
        "final-activation": 12_025_320,
        "relation-round": 12_025_320,
        "fixed-merkle-path": 12_025_320,
        "fri-query": 12_025_320,
        "grinding-witness": 12_025_320,
    }
    if not isinstance(mutation_values, list):
        raise IntegrityError("ProductionV4 mutation rejection evidence is missing")
    observed_mutations: set[str] = set()
    observed_proof_digests: set[tuple[object, object]] = set()
    for value in mutation_values:
        row = _require_exact_fields(
            value,
            {"mutation", "proof", "error", "command"},
            "ProductionV4 mutation rejection",
        )
        mutation = row["mutation"]
        command = row["command"]
        if (
            not isinstance(mutation, str)
            or mutation in observed_mutations
            or not isinstance(row["error"], str)
            or not row["error"].strip()
            or not isinstance(command, list)
            or not command
            or any(not isinstance(item, str) or not item for item in command)
        ):
            raise IntegrityError("ProductionV4 mutation rejection evidence is invalid")
        proof_row = _validate_report_file_identity(
            row["proof"], f"ProductionV4 {mutation} mutation proof"
        )
        proof_digests = (proof_row["sha256"], proof_row["blake3"])
        if (
            mutation not in expected_mutations
            or proof_row["name"] != f"proof-{mutation}.bin"
            or proof_row["bytes"] != expected_mutations[mutation]
            or proof_row["sha256"] == known_proof["sha256"]
            or proof_row["blake3"] == known_proof["blake3"]
            or proof_digests in observed_proof_digests
        ):
            raise IntegrityError("ProductionV4 mutation proof identity is invalid")
        observed_proof_digests.add(proof_digests)
        observed_mutations.add(mutation)
    if observed_mutations != set(expected_mutations):
        raise IntegrityError("ProductionV4 mutation rejection set is incomplete")


def _production_v4_evidence_subject_from_approval(
    *, approval_path: Path, approval_trust: dict[str, object]
) -> tuple[dict[str, object], dict[str, object]]:
    approval, approval_bytes = _bounded_json_object(
        approval_path, "ProductionV4 producer activation approval"
    )
    if approval_bytes != activation_approval.canonical_json(approval):
        raise IntegrityError("ProductionV4 producer approval is not canonical JSON")
    _require_exact_fields(
        approval,
        {
            "schema",
            "role",
            "namespace",
            "signer_identity",
            "trusted_authority",
            "subject",
        },
        "ProductionV4 producer activation approval",
    )
    if (
        approval["schema"] != activation_approval.APPROVAL_SCHEMA
        or approval["role"] != activation_approval.PRODUCER_ROLE
        or approval["namespace"]
        != activation_approval.NAMESPACES[activation_approval.PRODUCER_ROLE]
    ):
        raise IntegrityError("ProductionV4 producer approval role is invalid")
    subject = approval["subject"]
    try:
        activation_approval.validate_subject(subject)
    except activation_approval.ApprovalError as error:
        raise IntegrityError(str(error)) from error
    if not isinstance(subject, dict) or subject.get("phase") != "evidence":
        raise IntegrityError("ProductionV4 staged approval is not for evidence phase")
    files = subject.get("files")
    if not isinstance(files, dict):  # pragma: no cover - validated above.
        raise IntegrityError("ProductionV4 staged approval file bindings are unavailable")
    common_files = {
        role: files[role] for role in activation_approval.COMMON_FILE_ROLES
    }
    try:
        binding = activation_approval.qualification_binding_sha256(common_files)
    except activation_approval.ApprovalError as error:
        raise IntegrityError(str(error)) from error
    if binding != approval_trust["qualification_binding_sha256"]:
        raise IntegrityError(
            "ProductionV4 producer approval files do not match the compiled qualification binding"
        )
    return subject, common_files


def _production_v4_staged_common_files(
    *,
    common_files: dict[str, object],
    launch_candidate_bytes: bytes,
    qualification_manifest: dict[str, object],
    qualification_manifest_bytes: bytes,
    qualification_input_manifest: dict[str, object],
    verifier_report: dict[str, object],
    verifier_report_bytes: bytes,
    verifier_script_size: int,
    verifier_script_sha256: str,
    verifier_script_blake3: str,
) -> dict[str, object]:
    rebuilt = json.loads(json.dumps(common_files))
    rebuilt["launch_candidate"] = _production_v4_approval_identity(
        PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, launch_candidate_bytes
    )
    rebuilt["rcnet_input_manifest"] = dict(qualification_input_manifest)
    rebuilt["independent_reproduction_report"] = _production_v4_approval_identity(
        PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME, qualification_manifest_bytes
    )
    rebuilt["fresh_process_verifier_report"] = _production_v4_approval_identity(
        PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME, verifier_report_bytes
    )
    rebuilt["fresh_process_verifier_script"] = {
        "name": PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME,
        "bytes": verifier_script_size,
        "sha256": verifier_script_sha256,
        "blake3": verifier_script_blake3,
    }
    rebuilt["qualification_proof"] = dict(
        _validate_report_file_identity(
            verifier_report["known_valid_proof"], "ProductionV4 known-valid proof"
        )
    )
    artifact_values = qualification_manifest.get("artifacts")
    if not isinstance(artifact_values, list):  # pragma: no cover - validated upstream.
        raise IntegrityError("ProductionV4 qualification artifacts are unavailable")
    artifacts = {
        str(row["name"]): row
        for row in artifact_values
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    rebuilt["model_bank"] = dict(artifacts[PRODUCTION_V4_PACKAGE_BANK])
    rebuilt["fixed_artifact_record"] = dict(
        artifacts[PRODUCTION_V4_PACKAGE_FIXED_RECORD]
    )
    for bank in range(3):
        for suffix, role_suffix in (
            ("json", "json"),
            ("codeword", "codeword"),
            ("row-major.codeword", "row_major_codeword"),
            ("tree", "tree"),
        ):
            rebuilt[f"fixed_bank_{bank}_{role_suffix}"] = dict(
                artifacts[f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}"]
            )
    return rebuilt


def _validate_production_v4_rc_artifacts(
    *,
    version: str,
    commit: str,
    stage_files: dict[str, Path],
    repo: Path | None = None,
    activation_ssh_keygen: Path | None = None,
    activation_ssh_keygen_sha256: str | None = None,
) -> None:
    required = {
        PRODUCTION_RC_NETWORK_INFO_NAME,
        PRODUCTION_RC_LAUNCH_CANDIDATE_NAME,
        PRODUCTION_V4_ACTIVATION_NAME,
        PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME,
        PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME,
        PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME,
    }
    missing = sorted(required - set(stage_files))
    if missing:
        raise IntegrityError(
            "production RC release gate is blocked; "
            f"missing required ProductionV4 release artifacts: {missing}"
        )
    network_info, network_info_bytes = _bounded_json_object(
        stage_files[PRODUCTION_RC_NETWORK_INFO_NAME], "compiled network information"
    )
    launch_candidate, launch_candidate_bytes = _bounded_json_object(
        stage_files[PRODUCTION_RC_LAUNCH_CANDIDATE_NAME], "RCNet launch candidate"
    )
    evidence, evidence_bytes = _bounded_json_object(
        stage_files[PRODUCTION_V4_ACTIVATION_NAME], "ProductionV4 activation evidence"
    )
    qualification_manifest, qualification_manifest_bytes = _bounded_json_object(
        stage_files[PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME],
        "ProductionV4 qualification manifest",
    )
    verifier_script = _regular_file(
        stage_files[PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME],
        "ProductionV4 fresh-process verifier script",
    )
    verifier_report, verifier_report_bytes = _bounded_json_object(
        stage_files[PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME],
        "ProductionV4 fresh-process verifier report",
    )
    if evidence_bytes != _canonical_json(evidence):
        raise IntegrityError("ProductionV4 activation evidence is not canonical JSON")
    if qualification_manifest_bytes != _canonical_json(qualification_manifest):
        raise IntegrityError("ProductionV4 qualification manifest is not canonical JSON")
    if verifier_report_bytes != _canonical_json(verifier_report):
        raise IntegrityError("ProductionV4 verifier report is not canonical JSON")
    with _stable_regular_handle(
        verifier_script, "ProductionV4 fresh-process verifier script"
    ) as (_, verifier_handle, verifier_stat):
        if verifier_stat.st_size <= 0:
            raise IntegrityError("ProductionV4 fresh-process verifier script size is invalid")
        (
            verifier_script_size,
            verifier_script_sha256,
            verifier_script_blake3,
            _,
        ) = _stream_sha256(
            verifier_handle,
            expected_size=verifier_stat.st_size,
            maximum_size=MAX_RUNTIME_BINARY_BYTES,
            label="ProductionV4 fresh-process verifier script",
            capture_bytes=0,
        )

    network = network_info.get("network")
    proof = _require_exact_fields(
        network_info.get("proof_of_work"),
        {
            "selection",
            "profile",
            "build_source_commit",
            "activation_evidence_sha256",
            "wire_type",
            "pow_limit",
            "algorithm_version",
            "proof_version",
            "proof_system_digest",
            "model_manifest_digest",
            "fixed_artifact_record_digest",
            "exact_transparent_proof_bytes",
            "artifacts",
        },
        "compiled ProductionV4 proof identity",
    )
    if not isinstance(network, dict) or network.get("name") != "CommonFoundry RCNet-1":
        raise IntegrityError("production RC compiled network profile is not RCNet-1")
    if (
        proof["selection"] != "ProductionV4"
        or proof["profile"] != "ForgeMatrix-v4 transparent BaseFold"
    ):
        raise IntegrityError("production RC compiled proof selection is not ProductionV4")
    if proof["build_source_commit"] != commit:
        raise IntegrityError(
            "production RC compiled build source commit does not match the checked-out commit"
        )
    expected_proof_identity = {
        "wire_type": 4,
        "algorithm_version": 4,
        "proof_version": 1,
        "proof_system_digest": PRODUCTION_V4_PROOF_SYSTEM_DIGEST,
        "model_manifest_digest": PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
        "fixed_artifact_record_digest": PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST,
        "exact_transparent_proof_bytes": "12025320",
    }
    if any(proof.get(field) != expected for field, expected in expected_proof_identity.items()):
        raise IntegrityError("production RC compiled ProductionV4 proof identity is invalid")
    validated_candidate = _validate_production_v4_rcnet_candidate(
        launch_candidate, network_info
    )

    (
        qualification_source_commit,
        qualification_generation_commit,
        qualification_proof,
        qualification_statement,
        qualification_input_manifest,
        qualification_derived,
    ) = _validate_production_v4_qualification_manifest(
        qualification_manifest, proof, str(launch_candidate["network_id"])
    )
    _validate_production_v4_verifier_report(
        verifier_report,
        qualification_source_commit,
        qualification_proof,
        qualification_statement,
        qualification_derived,
        (verifier_script_size, verifier_script_sha256, verifier_script_blake3),
    )
    expected_evidence = {
        "artifacts": proof["artifacts"],
        "core_spec_sha256": PRODUCTION_V4_CORE_SPEC_SHA256,
        "core_vector_sha256": PRODUCTION_V4_CORE_VECTOR_SHA256,
        "fresh_process_verifier_binary_sha256": verifier_script_sha256,
        "fresh_process_verifier_report_sha256": _sha256_bytes(verifier_report_bytes),
        "network_profile": "RCNet-1",
        "proof_algebra_sha256": PRODUCTION_V4_PROOF_ALGEBRA_SHA256,
        "proof_selection": "ProductionV4",
        "qualification_manifest_sha256": _sha256_bytes(qualification_manifest_bytes),
        "qualification_source_commit": qualification_source_commit,
        "schema": "CMFD_PRODUCTION_V4_ACTIVATION_V1",
        "source_commit": commit,
    }
    evidence_fields = set(evidence)
    legacy_fields = set(expected_evidence)
    trusted_fields = legacy_fields | {"activation_approval_trust"}
    if evidence_fields not in (legacy_fields, trusted_fields):
        raise IntegrityError("ProductionV4 activation evidence has missing or unknown fields")
    for field, expected in expected_evidence.items():
        if evidence.get(field) != expected:
            raise IntegrityError(f"ProductionV4 activation evidence has invalid {field}")
    if proof["activation_evidence_sha256"] != _sha256_bytes(evidence_bytes):
        raise IntegrityError(
            "compiled ProductionV4 selection is not bound to the staged activation evidence"
        )
    validate_production_rc_runtime_packages(
        stage_files=stage_files,
        staged_network_info=network_info,
        commit=commit,
        version=version,
    )
    approval_names = {
        PRODUCTION_V4_PRODUCER_APPROVAL_NAME,
        PRODUCTION_V4_PRODUCER_APPROVAL_SIGNATURE_NAME,
        PRODUCTION_V4_PRODUCER_ALLOWED_SIGNERS_NAME,
        PRODUCTION_V4_REPRODUCER_APPROVAL_NAME,
        PRODUCTION_V4_REPRODUCER_APPROVAL_SIGNATURE_NAME,
        PRODUCTION_V4_REPRODUCER_ALLOWED_SIGNERS_NAME,
    }
    if approval_names - set(stage_files):
        raise IntegrityError(PRODUCTION_V4_ACTIVATION_APPROVAL_ERROR)
    if evidence_fields == legacy_fields:
        raise IntegrityError(PRODUCTION_V4_ACTIVATION_APPROVAL_ERROR)
    approval_trust = _validate_production_v4_approval_trust_fields(
        evidence["activation_approval_trust"]
    )
    if (
        repo is None
        or activation_ssh_keygen is None
        or activation_ssh_keygen_sha256 is None
    ):
        raise IntegrityError(PRODUCTION_V4_ACTIVATION_APPROVAL_ERROR)
    if approval_trust["ssh_keygen_sha256"] != activation_ssh_keygen_sha256:
        raise IntegrityError(
            "ProductionV4 activation verifier digest does not match compiled trust"
        )
    pin_fields = {
        "schema": evidence["schema"],
        "qualification_source_commit": evidence["qualification_source_commit"],
        "qualification_manifest_sha256": evidence["qualification_manifest_sha256"],
        "fresh_process_verifier_binary_sha256": evidence[
            "fresh_process_verifier_binary_sha256"
        ],
        "fresh_process_verifier_report_sha256": evidence[
            "fresh_process_verifier_report_sha256"
        ],
        "core_spec_sha256": evidence["core_spec_sha256"],
        "core_vector_sha256": evidence["core_vector_sha256"],
        "proof_algebra_sha256": evidence["proof_algebra_sha256"],
        "approval_trust": approval_trust,
    }
    pin_bytes = _render_production_v4_activation_pin(pin_fields)
    if _tracked_blob(repo, PRODUCTION_V4_ACTIVATION_PIN_RELATIVE) != pin_bytes:
        raise IntegrityError(
            "tracked ProductionV4 activation pin does not match staged evidence and approval trust"
        )
    _validate_production_v4_activation_history(
        phase="evidence",
        repo=repo,
        commit=commit,
        generation_commit=qualification_generation_commit,
        qualification_commit=qualification_source_commit,
        pin_bytes=pin_bytes,
    )
    _, common_files = _production_v4_evidence_subject_from_approval(
        approval_path=stage_files[PRODUCTION_V4_PRODUCER_APPROVAL_NAME],
        approval_trust=approval_trust,
    )
    common_files = _production_v4_staged_common_files(
        common_files=common_files,
        launch_candidate_bytes=launch_candidate_bytes,
        qualification_manifest=qualification_manifest,
        qualification_manifest_bytes=qualification_manifest_bytes,
        qualification_input_manifest=qualification_input_manifest,
        verifier_report=verifier_report,
        verifier_report_bytes=verifier_report_bytes,
        verifier_script_size=verifier_script_size,
        verifier_script_sha256=verifier_script_sha256,
        verifier_script_blake3=verifier_script_blake3,
    )
    try:
        common_binding = activation_approval.qualification_binding_sha256(
            common_files
        )
    except activation_approval.ApprovalError as error:
        raise IntegrityError(str(error)) from error
    if common_binding != approval_trust["qualification_binding_sha256"]:
        raise IntegrityError(
            "staged ProductionV4 qualification evidence does not match compiled approval trust"
        )
    canonical_network_info = (
        json.dumps(network_info, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if network_info_bytes != canonical_network_info:
        raise IntegrityError("compiled ProductionV4 NETWORK-INFO.json is not canonical")
    subject_files = {
        **common_files,
        "activation_evidence": _production_v4_approval_identity(
            PRODUCTION_V4_ACTIVATION_NAME, evidence_bytes
        ),
        "compiled_network_info": _production_v4_approval_identity(
            PRODUCTION_RC_NETWORK_INFO_NAME, network_info_bytes
        ),
    }
    try:
        subject = activation_approval.build_subject(
            phase="evidence",
            activation_source_commit=commit,
            artifact_generation_source_commit=qualification_generation_commit,
            qualification_source_commit=qualification_source_commit,
            network=_production_v4_approval_network(
                launch_candidate, validated_candidate
            ),
            source_pin_sha256=_sha256_bytes(pin_bytes),
            files=subject_files,
        )
    except activation_approval.ApprovalError as error:
        raise IntegrityError(str(error)) from error
    producer_trust = approval_trust["producer"]
    reproducer_trust = approval_trust["independent_reproducer"]
    if not isinstance(producer_trust, dict) or not isinstance(
        reproducer_trust, dict
    ):  # pragma: no cover - validated above.
        raise IntegrityError("ProductionV4 approval signer trust is unavailable")
    approval_receipt = _verify_production_v4_activation_approvals(
        subject=subject,
        approval_trust=approval_trust,
        producer_approval=stage_files[PRODUCTION_V4_PRODUCER_APPROVAL_NAME],
        producer_signature=stage_files[
            PRODUCTION_V4_PRODUCER_APPROVAL_SIGNATURE_NAME
        ],
        producer_allowed_signers=stage_files[
            PRODUCTION_V4_PRODUCER_ALLOWED_SIGNERS_NAME
        ],
        producer_signer_identity=producer_trust["signer_identity"],
        reproducer_approval=stage_files[PRODUCTION_V4_REPRODUCER_APPROVAL_NAME],
        reproducer_signature=stage_files[
            PRODUCTION_V4_REPRODUCER_APPROVAL_SIGNATURE_NAME
        ],
        reproducer_allowed_signers=stage_files[
            PRODUCTION_V4_REPRODUCER_ALLOWED_SIGNERS_NAME
        ],
        reproducer_signer_identity=reproducer_trust["signer_identity"],
        ssh_keygen=activation_ssh_keygen,
        expected_ssh_keygen_sha256=activation_ssh_keygen_sha256,
    )
    receipt_approvals = approval_receipt.get("approvals")
    if not isinstance(receipt_approvals, dict):  # pragma: no cover - verifier contract.
        raise IntegrityError("ProductionV4 approval verification receipt is malformed")
    approval_rechecks = (
        (
            PRODUCTION_V4_PRODUCER_APPROVAL_NAME,
            receipt_approvals[activation_approval.PRODUCER_ROLE]["approval_sha256"],
        ),
        (
            PRODUCTION_V4_PRODUCER_APPROVAL_SIGNATURE_NAME,
            receipt_approvals[activation_approval.PRODUCER_ROLE]["signature_sha256"],
        ),
        (
            PRODUCTION_V4_PRODUCER_ALLOWED_SIGNERS_NAME,
            producer_trust["allowed_signers_sha256"],
        ),
        (
            PRODUCTION_V4_REPRODUCER_APPROVAL_NAME,
            receipt_approvals[activation_approval.REPRODUCER_ROLE]["approval_sha256"],
        ),
        (
            PRODUCTION_V4_REPRODUCER_APPROVAL_SIGNATURE_NAME,
            receipt_approvals[activation_approval.REPRODUCER_ROLE]["signature_sha256"],
        ),
        (
            PRODUCTION_V4_REPRODUCER_ALLOWED_SIGNERS_NAME,
            reproducer_trust["allowed_signers_sha256"],
        ),
    )
    for name, expected_sha256 in approval_rechecks:
        if _sha256_file(stage_files[name]) != expected_sha256:
            raise IntegrityError(f"ProductionV4 staged approval changed: {name}")
    for name, expected_bytes in (
        (PRODUCTION_RC_NETWORK_INFO_NAME, network_info_bytes),
        (PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, launch_candidate_bytes),
        (PRODUCTION_V4_ACTIVATION_NAME, evidence_bytes),
        (PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME, qualification_manifest_bytes),
        (PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME, verifier_report_bytes),
    ):
        if _sha256_file(stage_files[name]) != _sha256_bytes(expected_bytes):
            raise IntegrityError(f"ProductionV4 staged approval input changed: {name}")
    if _sha256_file(verifier_script) != verifier_script_sha256:
        raise IntegrityError("ProductionV4 staged verifier script changed")


def validate_production_rc_artifacts(
    *,
    version: str,
    commit: str,
    stage_files: dict[str, Path],
    repo: Path | None = None,
    activation_ssh_keygen: Path | None = None,
    activation_ssh_keygen_sha256: str | None = None,
) -> None:
    if not is_production_rc_label(version):
        return
    reject_production_rc_source_assets(
        stage_files,
        allowed_source_assets=frozenset(
            {PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME}
        ),
    )
    common = {PRODUCTION_RC_NETWORK_INFO_NAME, PRODUCTION_RC_LAUNCH_CANDIDATE_NAME}
    missing = sorted(common - set(stage_files))
    if missing:
        raise IntegrityError(
            "production RC release gate is blocked; "
            f"missing compiled activation artifacts: {missing}"
        )
    network_info, _ = _bounded_json_object(
        stage_files[PRODUCTION_RC_NETWORK_INFO_NAME], "compiled network information"
    )
    proof = network_info.get("proof_of_work")
    selection = proof.get("selection") if isinstance(proof, dict) else None
    if selection == "ProductionV3":
        _validate_production_v3_rc_artifacts(
            version=version, commit=commit, stage_files=stage_files
        )
        return
    if selection == "ProductionV4":
        _validate_production_v4_rc_artifacts(
            version=version,
            commit=commit,
            stage_files=stage_files,
            repo=repo,
            activation_ssh_keygen=activation_ssh_keygen,
            activation_ssh_keygen_sha256=activation_ssh_keygen_sha256,
        )
        return
    raise IntegrityError("production RC compiled proof selection is unsupported")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _blake3_bytes(data: bytes) -> str:
    if blake3 is None:
        raise IntegrityError(
            "production release inspection requires the pinned Python blake3 dependency"
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


def _commit_epoch(repo: Path, revision: str = "HEAD") -> int:
    if revision != "HEAD":
        revision = _full_commit(revision)
    value = _run_git(repo, "show", "-s", "--format=%ct", revision)
    try:
        epoch = int(value, 10)
    except ValueError as error:
        raise IntegrityError("Git returned an invalid commit timestamp") from error
    if epoch < 0:
        raise IntegrityError("SOURCE_DATE_EPOCH cannot be negative")
    return epoch


def _source_date_epoch(
    repo: Path | None, explicit: str | int | None, commit: str | None = None
) -> int:
    value: str | int | None = explicit
    if value is None:
        value = os.environ.get("SOURCE_DATE_EPOCH")
    if value is None:
        if repo is None:
            raise IntegrityError("SOURCE_DATE_EPOCH is required")
        return _commit_epoch(repo, commit or "HEAD")
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


def _manifest_version(
    repo: Path, relative: str, commit: str | None = None
) -> str:
    data = (
        _tracked_blob(repo, relative)
        if commit is None
        else _tracked_blob_at(repo, commit, relative)
    )
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


def validate_production_rc_source_versions(
    *, repo: Path, version: str, commit: str | None = None
) -> None:
    if not is_production_rc_label(version):
        return
    if commit is not None:
        commit = _full_commit(commit)
    mismatches: dict[str, str] = {}
    for relative in PRODUCTION_RC_VERSION_FILES:
        actual = _manifest_version(repo, relative, commit)
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


def _stat_object_identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _sync_directory(path: Path) -> None:
    directory = _regular_directory(path, "durability directory")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        create_file.restype = wintypes.HANDLE
        flush_file_buffers = kernel32.FlushFileBuffers
        flush_file_buffers.argtypes = (wintypes.HANDLE,)
        flush_file_buffers.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        handle = create_file(
            str(directory),
            0x40000000,  # GENERIC_WRITE
            0x00000007,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            None,
            3,  # OPEN_EXISTING
            0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), f"cannot open directory: {directory}")
        try:
            if not flush_file_buffers(handle):
                raise OSError(
                    ctypes.get_last_error(), f"cannot flush directory: {directory}"
                )
        finally:
            close_handle(handle)
        return
    descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_regular_file(path: Path, label: str) -> tuple[int, int, int, int, int]:
    candidate = _regular_file(path, label)
    before = candidate.lstat()
    descriptor = os.open(
        candidate,
        os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(opened):
            raise IntegrityError(f"{label} changed before it could be synchronized")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    after = candidate.lstat()
    if _stat_identity(after) != _stat_identity(opened):
        raise IntegrityError(f"{label} changed while it was synchronized")
    return _stat_identity(opened)


def _write_new(path: Path, data: bytes) -> tuple[int, int, int, int, int]:
    path = _absolute_path(path)
    created_identity: tuple[int, int, int] | None = None
    complete_identity: tuple[int, int, int, int, int] | None = None
    try:
        handle = path.open("xb")
        with handle:
            created_identity = _stat_object_identity(os.fstat(handle.fileno()))
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            complete_identity = _stat_identity(os.fstat(handle.fileno()))
        _sync_directory(path.parent)
    except BaseException:
        if created_identity is not None:
            try:
                current = path.lstat()
                if _stat_object_identity(current) != created_identity:
                    raise IntegrityError(f"new output changed during cleanup: {path}")
                path.unlink()
                _sync_directory(path.parent)
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                raise IntegrityError(f"cannot clean up new output: {path}") from cleanup_error
        raise
    if complete_identity is None:  # pragma: no cover - a successful write sets it.
        raise IntegrityError(f"new output identity is unavailable: {path}")
    return complete_identity


def _write_new_verified(
    *,
    path: Path,
    data: bytes,
    parent_identity: tuple[int, int, int],
    label: str,
) -> tuple[int, int, int, int, int]:
    path = _absolute_path(path)
    if _stat_object_identity(path.parent.lstat()) != parent_identity:
        raise IntegrityError(f"{label} output directory changed before publication")
    created = _write_new(path, data)
    try:
        if _stat_object_identity(path.parent.lstat()) != parent_identity:
            raise IntegrityError(f"{label} output directory changed during publication")
        with _stable_regular_handle(path, label) as (_, handle, opened):
            written = handle.read(len(data) + 1)
        if _stat_identity(opened) != created or written != data:
            raise IntegrityError(f"{label} changed during publication")
    except BaseException:
        try:
            current = path.lstat()
            if _stat_identity(current) != created:
                raise IntegrityError(f"{label} changed during cleanup")
            path.unlink()
            _sync_directory(path.parent)
        except FileNotFoundError:
            pass
        except BaseException as cleanup_error:
            raise IntegrityError(f"cannot clean up {label}") from cleanup_error
        raise
    return created


def _remove_exact_new(
    path: Path, identity: tuple[int, int, int, int, int], label: str
) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if _stat_identity(current) != identity:
        raise IntegrityError(f"{label} changed before cleanup")
    path.unlink()
    _sync_directory(path.parent)


def _publish_new_archive(
    temporary: Path, output: Path
) -> tuple[int, int, int, int, int]:
    temporary = _regular_file(temporary, "temporary archive")
    output = _absolute_path(output)
    temporary_identity = _sync_regular_file(temporary, "temporary archive")
    published_identity: tuple[int, int, int, int, int] | None = None
    try:
        try:
            os.link(temporary, output, follow_symlinks=False)
        except FileExistsError as error:
            raise IntegrityError(f"archive already exists: {output}") from error
        except OSError as error:
            raise IntegrityError(
                f"cannot publish archive without replacement: {output}"
            ) from error
        published_identity = _stat_identity(output.lstat())
        if published_identity != temporary_identity:
            raise IntegrityError(f"published archive identity is unstable: {output}")
        _sync_directory(output.parent)
        temporary.unlink()
        _sync_directory(temporary.parent)
        return published_identity
    except BaseException:
        if published_identity is not None:
            try:
                current = output.lstat()
                if _stat_identity(current) != published_identity:
                    raise IntegrityError(f"published archive changed during cleanup: {output}")
                output.unlink()
                _sync_directory(output.parent)
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                raise IntegrityError(
                    f"cannot clean up unpublished archive: {output}"
                ) from cleanup_error
        raise


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


def _native_runtime_platform() -> str:
    system = host_platform.system().lower()
    machine = host_platform.machine().lower()
    if machine not in {"amd64", "x86_64"}:
        raise IntegrityError(
            f"production runtime packaging requires an x86_64 host, found {machine or 'unknown'}"
        )
    if system == "windows":
        return "windows-x86_64"
    if system == "linux":
        return "linux-x86_64"
    raise IntegrityError(
        f"production runtime packaging is unsupported on {system or 'unknown'}"
    )


def _require_native_runtime_platform(platform: str) -> None:
    if platform not in PRODUCTION_RC_RUNTIME_ROOTS:
        raise IntegrityError(f"unsupported production runtime platform: {platform}")
    actual = _native_runtime_platform()
    if actual != platform:
        raise IntegrityError(
            f"{platform} runtime package must be assembled on a native {platform} host; "
            f"current host is {actual}"
        )


def _copy_runtime_input(
    source: Path, destination: Path, *, label: str, mode: int
) -> None:
    if os.path.lexists(destination):  # pragma: no cover - private temporary staging.
        raise IntegrityError(f"runtime staging destination already exists: {destination}")
    created = False
    try:
        with _stable_regular_handle(source, label) as (_, input_handle, opened):
            output_handle = destination.open("xb")
            created = True
            with output_handle:
                shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
                output_handle.flush()
                os.fsync(output_handle.fileno())
            if destination.stat().st_size != opened.st_size:
                raise IntegrityError(f"{label} was not copied completely")
        destination.chmod(mode)
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def _network_info_from_runtime_attestation(
    attestation: dict[str, object], platform: str
) -> tuple[dict[str, object], bytes]:
    encoded = attestation.get("network_info_base64")
    if not isinstance(encoded, str) or len(encoded) > 2 * MAX_RELEASE_GATE_JSON_BYTES:
        raise IntegrityError(f"{platform} runtime attestation has invalid network information")
    try:
        network_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IntegrityError(
            f"{platform} runtime attestation has invalid network information"
        ) from error
    if (
        len(network_bytes) > MAX_RELEASE_GATE_JSON_BYTES
        or base64.b64encode(network_bytes).decode("ascii") != encoded
        or attestation.get("network_info_sha256") != _sha256_bytes(network_bytes)
    ):
        raise IntegrityError(f"{platform} runtime attestation has invalid network information")
    return (
        _json_object_bytes(network_bytes, f"{platform} packaged-node network information"),
        network_bytes,
    )


def _runtime_unsigned_decimal(value: object, label: str) -> int:
    if (
        not isinstance(value, str)
        or len(value) > 20
        or not re.fullmatch(r"0|[1-9][0-9]*", value)
    ):
        raise IntegrityError(f"{label} is not a canonical unsigned decimal string")
    parsed = int(value, 10)
    if parsed > (1 << 64) - 1:
        raise IntegrityError(f"{label} exceeds the unsigned 64-bit range")
    return parsed


def _production_v4_runtime_candidate(
    network_info: dict[str, object],
) -> dict[str, object]:
    network = _require_exact_fields(
        network_info["network"],
        {
            "name",
            "network_id",
            "virtual_genesis_hash",
            "virtual_genesis_timestamp_unix_seconds",
        },
        "packaged-node network identity",
    )
    proof = _require_exact_fields(
        network_info["proof_of_work"],
        {
            "selection",
            "profile",
            "build_source_commit",
            "activation_evidence_sha256",
            "wire_type",
            "pow_limit",
            "algorithm_version",
            "proof_version",
            "proof_system_digest",
            "model_manifest_digest",
            "fixed_artifact_record_digest",
            "exact_transparent_proof_bytes",
            "artifacts",
        },
        "packaged-node ProductionV4 identity",
    )
    artifacts = _require_exact_fields(
        proof["artifacts"],
        {"bank", "fixed_record"},
        "packaged-node ProductionV4 artifacts",
    )
    consensus_identity = _require_exact_fields(
        network_info["consensus"],
        {"consensus_fingerprint", "versions", "limits"},
        "packaged-node consensus identity",
    )
    if (
        consensus_identity["consensus_fingerprint"]
        != PRODUCTION_RC_CONSENSUS_FINGERPRINT
    ):
        raise IntegrityError(
            "packaged node does not report the RCNet consensus fingerprint"
        )
    version_fields = (
        "network_protocol_version",
        "block_version",
        "transaction_version",
        "wire_version",
    )
    limit_fields = (
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
    versions = _require_exact_fields(
        consensus_identity["versions"],
        set(version_fields),
        "packaged-node consensus versions",
    )
    limits = _require_exact_fields(
        consensus_identity["limits"],
        set(limit_fields),
        "packaged-node consensus limits",
    )
    for field in version_fields:
        _require_unsigned_integer(
            versions[field], f"packaged-node consensus {field}"
        )
    consensus = {
        **{field: versions[field] for field in version_fields},
        **{
            field: _runtime_unsigned_decimal(
                limits[field], f"packaged-node consensus {field}"
            )
            for field in limit_fields
        },
    }

    monetary_fields = (
        "atoms_per_coin",
        "initial_subsidy_atoms",
        "tail_height",
        "tail_subsidy_atoms",
        "steward_percent",
        "community_percent",
    )
    monetary_identity = _require_exact_fields(
        network_info["monetary_policy"],
        set(monetary_fields),
        "packaged-node monetary policy",
    )
    monetary_policy: dict[str, object] = {}
    for field in monetary_fields:
        value = monetary_identity[field]
        if field.endswith("_percent"):
            _require_unsigned_integer(value, f"packaged-node monetary policy {field}")
            monetary_policy[field] = value
        else:
            monetary_policy[field] = _runtime_unsigned_decimal(
                value, f"packaged-node monetary policy {field}"
            )

    rewards = _require_exact_fields(
        network_info["reward_destinations"],
        {"steward_xonly_public_key", "community_xonly_public_key"},
        "packaged-node reward destinations",
    )
    candidate_artifacts: dict[str, object] = {}
    for role in ("bank", "fixed_record"):
        identity = _require_exact_fields(
            artifacts[role],
            {"bytes", "blake3", "sha256"},
            f"packaged-node ProductionV4 {role}",
        )
        candidate_artifacts[role] = {
            "bytes": _runtime_unsigned_decimal(
                identity["bytes"],
                f"packaged-node ProductionV4 {role} byte length",
            ),
            "blake3": identity["blake3"],
            "sha256": identity["sha256"],
        }
    candidate_artifacts.update(
        {
            "fixed_record_version": 1,
            "proof_system_digest": proof["proof_system_digest"],
            "model_manifest_digest": proof["model_manifest_digest"],
            "fixed_artifact_format_digest": PRODUCTION_V4_FIXED_ARTIFACT_FORMAT_DIGEST,
            "fixed_artifact_record_digest": proof[
                "fixed_artifact_record_digest"
            ],
        }
    )
    return {
        "schema": RCNET_LAUNCH_CANDIDATE_V2_SCHEMA,
        "payload": {
            "profile": network["name"],
            "artifacts": candidate_artifacts,
            "virtual_genesis_timestamp_unix_seconds": _runtime_unsigned_decimal(
                network["virtual_genesis_timestamp_unix_seconds"],
                "packaged-node virtual genesis timestamp",
            ),
            "consensus": consensus,
            "proof_of_work": {
                "selection": proof["selection"],
                "wire_type": proof["wire_type"],
                "algorithm_version": proof["algorithm_version"],
                "proof_version": proof["proof_version"],
                "banks": 3,
                "layers_per_bank": 128,
                "exact_transparent_proof_bytes": _runtime_unsigned_decimal(
                    proof["exact_transparent_proof_bytes"],
                    "packaged-node exact transparent proof byte length",
                ),
                "pow_limit": proof["pow_limit"],
            },
            "monetary_policy": monetary_policy,
            "reward_destinations": rewards,
        },
        "launch_root": PRODUCTION_RC_LAUNCH_ROOT,
        "network_id": network["network_id"],
        "virtual_genesis_hash": network["virtual_genesis_hash"],
    }


def _validate_production_v4_runtime_identity(
    network_info: dict[str, object], commit: str
) -> None:
    _require_exact_fields(
        network_info,
        {
            "format",
            "format_version",
            "network",
            "consensus",
            "proof_of_work",
            "services",
            "data_directories",
            "monetary_policy",
            "reward_destinations",
        },
        "packaged-node network information",
    )
    if (
        network_info["format"] != "commonfoundry-network-info"
        or network_info["format_version"] != 1
        or type(network_info["format_version"]) is not int
    ):
        raise IntegrityError("packaged node reported an unsupported network-info format")
    services = _require_exact_fields(
        network_info["services"],
        {"rpc_port", "p2p_port", "pool_port", "bootstrap_peer"},
        "packaged-node service identity",
    )
    if any(
        services[field] != expected
        for field, expected in PRODUCTION_RC_SERVICE_PORTS.items()
    ):
        raise IntegrityError(
            "packaged node does not report the reserved RCNet service ports"
        )
    if services["bootstrap_peer"] != PRODUCTION_RC_BOOTSTRAP_PEER:
        raise IntegrityError(
            "packaged node does not report the reviewed RCNet bootstrap peer"
        )
    data_directories = _require_exact_fields(
        network_info["data_directories"],
        {"node", "wallet"},
        "packaged-node data-directory identity",
    )
    if data_directories != {"node": "commonfoundry-rcnet1", "wallet": "rcnet-1"}:
        raise IntegrityError(
            "packaged node does not report the isolated RCNet data-directory identities"
        )
    network = _require_exact_fields(
        network_info["network"],
        {
            "name",
            "network_id",
            "virtual_genesis_hash",
            "virtual_genesis_timestamp_unix_seconds",
        },
        "packaged-node network identity",
    )
    if network != {
        "name": "CommonFoundry RCNet-1",
        "network_id": PRODUCTION_RC_NETWORK_ID,
        "virtual_genesis_hash": PRODUCTION_RC_VIRTUAL_GENESIS_HASH,
        "virtual_genesis_timestamp_unix_seconds": (
            PRODUCTION_RC_VIRTUAL_GENESIS_TIMESTAMP
        ),
    }:
        raise IntegrityError(
            "packaged node does not match the immutable RCNet-1 launch candidate identity"
        )
    proof = _require_exact_fields(
        network_info["proof_of_work"],
        {
            "selection",
            "profile",
            "build_source_commit",
            "activation_evidence_sha256",
            "wire_type",
            "pow_limit",
            "algorithm_version",
            "proof_version",
            "proof_system_digest",
            "model_manifest_digest",
            "fixed_artifact_record_digest",
            "exact_transparent_proof_bytes",
            "artifacts",
        },
        "packaged-node ProductionV4 identity",
    )
    expected = {
        "selection": "ProductionV4",
        "profile": "ForgeMatrix-v4 transparent BaseFold",
        "build_source_commit": commit,
        "wire_type": 4,
        "pow_limit": PRODUCTION_RC_POW_LIMIT,
        "algorithm_version": 4,
        "proof_version": 1,
        "proof_system_digest": PRODUCTION_V4_PROOF_SYSTEM_DIGEST,
        "model_manifest_digest": PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
        "fixed_artifact_record_digest": PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST,
        "exact_transparent_proof_bytes": "12025320",
    }
    if any(proof.get(field) != value for field, value in expected.items()):
        raise IntegrityError(
            "packaged node does not report the expected RCNet-1 ProductionV4 identity"
        )
    _require_hex256(
        proof["activation_evidence_sha256"],
        "packaged-node ProductionV4 activation evidence",
        reject_repeated=True,
    )
    artifacts = _require_exact_fields(
        proof["artifacts"],
        {"bank", "fixed_record"},
        "packaged-node ProductionV4 artifacts",
    )
    expected_artifacts = {
        "bank": {
            "bytes": str(PRODUCTION_V4_MODEL_BANK_FILE_BYTES),
            "blake3": PRODUCTION_V4_MODEL_BANK_FILE_BLAKE3,
            "sha256": PRODUCTION_V4_MODEL_BANK_FILE_SHA256,
        },
        "fixed_record": {
            "bytes": str(PRODUCTION_V4_FIXED_RECORD_FILE_BYTES),
            "blake3": PRODUCTION_V4_FIXED_RECORD_FILE_BLAKE3,
            "sha256": PRODUCTION_V4_FIXED_RECORD_FILE_SHA256,
        },
    }
    for role in ("bank", "fixed_record"):
        pin = _require_exact_fields(
            artifacts[role],
            {"bytes", "blake3", "sha256"},
            f"packaged-node ProductionV4 {role}",
        )
        try:
            byte_count = int(pin["bytes"])
        except (TypeError, ValueError) as error:
            raise IntegrityError(
                f"packaged-node ProductionV4 {role} byte length is invalid"
            ) from error
        if str(byte_count) != pin["bytes"] or byte_count <= 0:
            raise IntegrityError(
                f"packaged-node ProductionV4 {role} byte length is invalid"
            )
        _require_hex256(
            pin["blake3"],
            f"packaged-node ProductionV4 {role} BLAKE3",
            reject_repeated=False,
        )
        _require_hex256(
            pin["sha256"],
            f"packaged-node ProductionV4 {role} SHA-256",
            reject_repeated=False,
        )
        if pin != expected_artifacts[role]:
            raise IntegrityError(
                f"packaged-node ProductionV4 {role} does not match the release pin"
            )
    _validate_production_v4_rcnet_candidate(
        _production_v4_runtime_candidate(network_info), network_info
    )


def _remove_published_runtime_outputs(
    outputs: list[tuple[Path, tuple[int, int, int, int, int]]]
) -> None:
    failures: list[str] = []
    synchronized: set[Path] = set()
    for path, expected_identity in reversed(outputs):
        try:
            current = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            failures.append(f"{path}: {error}")
            continue
        if _stat_identity(current) != expected_identity:
            failures.append(f"{path}: identity changed")
            continue
        try:
            path.unlink()
            synchronized.add(path.parent)
        except OSError as error:
            failures.append(f"{path}: {error}")
    for directory in sorted(synchronized, key=os.fspath):
        try:
            _sync_directory(directory)
        except (OSError, IntegrityError) as error:
            failures.append(f"{directory}: {error}")
    if failures:
        raise IntegrityError(
            "cannot durably roll back runtime publication: " + "; ".join(failures)
        )


def create_production_v4_runtime_package(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    platform: str,
    node: Path,
    wallet: Path,
    model_bank: Path,
    fixed_record: Path,
    output_directory: Path,
    source_date_epoch: str | int | None,
) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    if not is_production_rc_label(version):
        raise IntegrityError("production runtime package version is not an RC label")
    validate_production_rc_source_versions(repo=repo, version=version, commit=commit)
    _require_native_runtime_platform(platform)
    output_directory = _regular_directory(
        output_directory, "production runtime output directory"
    )
    epoch = _source_date_epoch(repo, source_date_epoch, commit)
    archive_name = (
        PRODUCTION_RC_WINDOWS_RUNTIME_PACKAGE_NAME
        if platform == "windows-x86_64"
        else PRODUCTION_RC_LINUX_RUNTIME_PACKAGE_NAME
    )
    attestation_name = (
        PRODUCTION_RC_WINDOWS_ATTESTATION_NAME
        if platform == "windows-x86_64"
        else PRODUCTION_RC_LINUX_ATTESTATION_NAME
    )
    archive_output = output_directory / archive_name
    attestation_output = output_directory / attestation_name
    for output in (archive_output, attestation_output):
        if os.path.lexists(output):
            raise IntegrityError(f"production runtime output already exists: {output}")

    suffix = ".exe" if platform == "windows-x86_64" else ""
    with tempfile.TemporaryDirectory(
        prefix=".cmfd-runtime-package-", dir=output_directory
    ) as temporary_name:
        temporary = Path(temporary_name)
        package_directory = temporary / _runtime_package_root(platform)
        package_directory.mkdir()
        artifact_directory = package_directory / PRODUCTION_V4_PACKAGE_ARTIFACT_DIRECTORY
        artifact_directory.mkdir()
        for source, destination, label, mode in (
            (
                node,
                package_directory / f"cmfd-node{suffix}",
                f"{platform} node executable",
                0o755,
            ),
            (
                wallet,
                package_directory / f"common-foundry-wallet{suffix}",
                f"{platform} wallet executable",
                0o755,
            ),
            (
                model_bank,
                artifact_directory / PRODUCTION_V4_PACKAGE_BANK,
                "ProductionV4 model bank",
                0o644,
            ),
            (
                fixed_record,
                artifact_directory / PRODUCTION_V4_PACKAGE_FIXED_RECORD,
                "ProductionV4 fixed artifact record",
                0o644,
            ),
        ):
            _copy_runtime_input(source, destination, label=label, mode=mode)

        temporary_attestation = temporary / attestation_name
        attestation = create_runtime_network_info_attestation(
            platform=platform,
            package_directory=package_directory,
            commit=commit,
            output=temporary_attestation,
            version=version,
        )
        network_info, _ = _network_info_from_runtime_attestation(
            attestation, platform
        )
        _validate_production_v4_runtime_identity(network_info, commit)

        temporary_archive = temporary / archive_name
        if platform == "windows-x86_64":
            create_deterministic_zip(package_directory, temporary_archive, epoch)
        else:
            create_deterministic_tar_gz(package_directory, temporary_archive, epoch)
        rows = _validate_runtime_package(
            path=temporary_archive,
            platform=platform,
            staged_network_info=network_info,
        )
        _validate_runtime_attestation(
            path=temporary_attestation,
            platform=platform,
            commit=commit,
            version=version,
            rows=rows,
            staged_network_info=network_info,
        )
        result: dict[str, object] = {
            "archive": {
                "bytes": temporary_archive.stat().st_size,
                "name": archive_name,
                "sha256": _sha256_file(temporary_archive),
            },
            "attestation": {
                "bytes": temporary_attestation.stat().st_size,
                "name": attestation_name,
                "sha256": _sha256_file(temporary_attestation),
            },
            "platform": platform,
            "source_commit": commit,
            "source_date_epoch": epoch,
            "version": version,
        }
        published: list[tuple[Path, tuple[int, int, int, int, int]]] = []
        try:
            _assert_clean_exact_repo(repo, commit)
            # The durable attestation is published last as the logical set commit;
            # final validation rejects an archive left alone by power loss.
            for source, output in (
                (temporary_archive, archive_output),
                (temporary_attestation, attestation_output),
            ):
                published.append((output, _publish_new_archive(source, output)))
        except BaseException:
            try:
                _remove_published_runtime_outputs(published)
            except BaseException as cleanup_error:
                raise IntegrityError(
                    "runtime package publication failed and rollback was incomplete"
                ) from cleanup_error
            raise
    return result


def _canonical_rcnet_v2_candidate(
    candidate: dict[str, object], validated: dict[str, object]
) -> bytes:
    canonical = {
        "schema": RCNET_LAUNCH_CANDIDATE_V2_SCHEMA,
        "payload": validated["canonical_payload"],
        "launch_root": validated["launch_root"],
        "network_id": validated["network_id"],
        "virtual_genesis_hash": validated["genesis"],
    }
    if candidate != canonical:
        raise IntegrityError("RCNet launch candidate is not the canonical V2 candidate")
    return (json.dumps(canonical, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _production_v4_file_identity(
    path: Path, label: str, *, expected_name: str | None = None
) -> dict[str, object]:
    path = _regular_file(path, label)
    if expected_name is not None and path.name != expected_name:
        raise IntegrityError(f"{label} must be named {expected_name}")
    with _stable_regular_handle(path, label) as (_, handle, opened):
        size, sha256, blake3_hash, _ = _stream_sha256(
            handle,
            expected_size=opened.st_size,
            maximum_size=MAX_RUNTIME_ARTIFACT_BYTES,
            label=label,
            capture_bytes=0,
        )
    return {
        "name": path.name,
        "bytes": size,
        "sha256": sha256,
        "blake3": blake3_hash,
    }


def _validate_production_v4_rcnet_input_manifest(
    path: Path,
    *,
    expected_network_id: str,
    expected_source_commit: str,
    expected_identity: dict[str, object],
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    path = _regular_file(path, "ProductionV4 RCNet input manifest")
    if path.name != PRODUCTION_V4_RCNET_INPUT_MANIFEST_NAME:
        raise IntegrityError(
            "ProductionV4 RCNet input manifest must have its canonical RCNet name"
        )
    manifest, manifest_bytes = _bounded_json_object(
        path, "ProductionV4 RCNet input manifest"
    )
    if manifest_bytes != _canonical_json(manifest):
        raise IntegrityError("ProductionV4 RCNet input manifest is not canonical JSON")
    _require_exact_fields(
        manifest,
        {"schema_version", "network", "network_id", "source_commit", "total_bytes", "files"},
        "ProductionV4 RCNet input manifest",
    )
    if (
        manifest["schema_version"] != 1
        or manifest["network"] != PRODUCTION_V4_RCNET_NETWORK_NAME
        or manifest["network_id"] != expected_network_id
        or manifest["source_commit"] != expected_source_commit
    ):
        raise IntegrityError(
            "ProductionV4 RCNet input manifest is not bound to the RCNet candidate and generation commit"
        )
    files = manifest["files"]
    if not isinstance(files, list) or len(files) != len(PRODUCTION_V4_RCNET_INPUT_NAMES):
        raise IntegrityError("ProductionV4 RCNet input manifest file set is incomplete")
    rows: dict[str, dict[str, object]] = {}
    observed_names: list[str] = []
    total_bytes = 0
    for value in files:
        row = _require_exact_fields(
            value,
            {"name", "bytes", "sha256"},
            "ProductionV4 RCNet input identity",
        )
        name = row["name"]
        if not isinstance(name, str) or name in rows:
            raise IntegrityError("ProductionV4 RCNet input file name is invalid")
        byte_count = _require_unsigned_integer(
            row["bytes"], f"ProductionV4 RCNet input {name} byte length", positive=True
        )
        if byte_count > MAX_RUNTIME_ARTIFACT_BYTES:
            raise IntegrityError(f"ProductionV4 RCNet input {name} exceeds its size limit")
        _require_hex256(
            row["sha256"],
            f"ProductionV4 RCNet input {name} SHA-256",
            reject_repeated=False,
        )
        observed_names.append(name)
        rows[name] = row
        total_bytes += byte_count
    if tuple(observed_names) != PRODUCTION_V4_RCNET_INPUT_NAMES:
        raise IntegrityError("ProductionV4 RCNet input manifest file order is not canonical")
    if manifest["total_bytes"] != total_bytes:
        raise IntegrityError("ProductionV4 RCNet input manifest total byte count is invalid")
    exact_inputs = {
        PRODUCTION_V4_PACKAGE_BANK: (
            PRODUCTION_V4_MODEL_BANK_FILE_BYTES,
            PRODUCTION_V4_MODEL_BANK_FILE_SHA256,
        ),
        PRODUCTION_V4_PACKAGE_FIXED_RECORD: (
            PRODUCTION_V4_FIXED_RECORD_FILE_BYTES,
            PRODUCTION_V4_FIXED_RECORD_FILE_SHA256,
        ),
    }
    for name, (byte_count, sha256) in exact_inputs.items():
        if rows[name]["bytes"] != byte_count or rows[name]["sha256"] != sha256:
            raise IntegrityError(
                f"ProductionV4 RCNet input manifest has invalid immutable identity for {name}"
            )
    actual_identity = {
        "name": path.name,
        "bytes": len(manifest_bytes),
        "sha256": _sha256_bytes(manifest_bytes),
        "blake3": _blake3_bytes(manifest_bytes),
    }
    if actual_identity != expected_identity:
        raise IntegrityError(
            "ProductionV4 RCNet input manifest does not match qualification evidence"
        )
    return manifest, rows


def _validate_production_v4_activation_artifacts(
    *,
    input_rows: dict[str, dict[str, object]],
    qualification_manifest: dict[str, object],
    verifier_report: dict[str, object],
    model_bank: Path,
    fixed_record: Path,
    artifact_directory: Path,
    proof: Path,
) -> dict[str, dict[str, object]]:
    artifact_values = qualification_manifest["artifacts"]
    if not isinstance(artifact_values, list):  # pragma: no cover - validated upstream.
        raise IntegrityError("ProductionV4 qualification artifact identities are missing")
    qualification_rows = {
        str(row["name"]): row for row in artifact_values if isinstance(row, dict)
    }
    artifact_directory = _regular_directory(
        artifact_directory, "ProductionV4 fixed-artifact directory"
    )
    paths = {
        PRODUCTION_V4_PACKAGE_BANK: model_bank,
        PRODUCTION_V4_PACKAGE_FIXED_RECORD: fixed_record,
        **{
            f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}": artifact_directory
            / f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}"
            for bank in range(3)
            for suffix in ("json", "codeword", "row-major.codeword", "tree")
        },
    }
    identities: dict[str, dict[str, object]] = {}
    for name, path in paths.items():
        actual = _production_v4_file_identity(
            path, f"ProductionV4 artifact {name}", expected_name=name
        )
        expected = qualification_rows.get(name)
        if actual != expected:
            raise IntegrityError(
                f"ProductionV4 artifact {name} does not match qualification evidence"
            )
        input_row = input_rows.get(name)
        if input_row is not None and (
            actual["bytes"] != input_row["bytes"]
            or actual["sha256"] != input_row["sha256"]
        ):
            raise IntegrityError(
                f"ProductionV4 artifact {name} does not match the RCNet input manifest"
            )
        identities[name] = actual

    known_proof = _validate_report_file_identity(
        verifier_report["known_valid_proof"], "ProductionV4 known-valid proof"
    )
    proof_identity = _production_v4_file_identity(
        proof, "ProductionV4 known-valid proof", expected_name=str(known_proof["name"])
    )
    if proof_identity != known_proof:
        raise IntegrityError(
            "ProductionV4 known-valid proof does not match verifier evidence"
        )
    identities[str(proof_identity["name"])] = proof_identity
    return identities


def _validate_production_v4_verifier_sources(
    repo: Path, verifier_report: dict[str, object]
) -> None:
    values = verifier_report["verifier_files"]
    if not isinstance(values, list):  # pragma: no cover - validated upstream.
        raise IntegrityError("ProductionV4 fresh-process verifier files are missing")
    reported = {str(row["name"]): row for row in values if isinstance(row, dict)}
    for name in PRODUCTION_V4_VERIFIER_FILE_NAMES:
        tracked = _tracked_blob(repo, f"scripts/{name}")
        expected = {
            "name": name,
            "bytes": len(tracked),
            "sha256": _sha256_bytes(tracked),
            "blake3": _blake3_bytes(tracked),
        }
        if reported.get(name) != expected:
            raise IntegrityError(
                f"tracked ProductionV4 verifier source does not match qualification evidence: {name}"
            )


def _resolve_production_v4_commit(repo: Path, value: str, label: str) -> str:
    commit = _full_commit(value)
    try:
        resolved = _run_git(
            repo, "rev-parse", "--verify", f"{commit}^{{commit}}"
        ).lower()
    except IntegrityError as error:
        raise IntegrityError(f"{label} does not resolve in the exact source repository") from error
    if resolved != commit:
        raise IntegrityError(f"{label} does not resolve to its exact Git commit")
    return commit


def _require_production_v4_ancestor(
    repo: Path, ancestor: str, descendant: str, label: str
) -> None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise IntegrityError(f"cannot inspect {label} Git ancestry") from error
    if result.returncode != 0:
        raise IntegrityError(f"{label} is not on the required Git ancestry")


def _tracked_blob_at(repo: Path, commit: str, relative: str) -> bytes:
    commit = _full_commit(commit)
    safe = _safe_repo_relative(relative)
    return _run_git_bytes(repo, "cat-file", "blob", f"{commit}:{safe}")


def _validate_production_v4_activation_history(
    *,
    phase: str,
    repo: Path,
    commit: str,
    generation_commit: str,
    qualification_commit: str,
    pin_bytes: bytes,
) -> None:
    generation_commit = _resolve_production_v4_commit(
        repo, generation_commit, "ProductionV4 artifact-generation source commit"
    )
    qualification_commit = _resolve_production_v4_commit(
        repo, qualification_commit, "ProductionV4 qualification source commit"
    )
    _require_production_v4_ancestor(
        repo,
        generation_commit,
        qualification_commit,
        "ProductionV4 artifact-generation commit",
    )
    ancestry_tip = commit
    if phase == "pin":
        if _tracked_blob(repo, PRODUCTION_V4_ACTIVATION_PIN_RELATIVE) != b"None\n":
            raise IntegrityError(
                "ProductionV4 pin phase requires the tracked activation pin to be None"
            )
    else:
        if _tracked_blob(repo, PRODUCTION_V4_ACTIVATION_PIN_RELATIVE) != pin_bytes:
            raise IntegrityError(
                "tracked ProductionV4 activation pin does not match validated evidence"
            )
        revision = _run_git(repo, "rev-list", "--parents", "-n", "1", commit).split()
        if len(revision) != 2:
            raise IntegrityError(
                "ProductionV4 activation commit must have exactly one parent"
            )
        ancestry_tip = revision[1]
        changed = _run_git(
            repo,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "--no-renames",
            "-r",
            commit,
        ).splitlines()
        if changed != [PRODUCTION_V4_ACTIVATION_PIN_RELATIVE]:
            raise IntegrityError(
                "ProductionV4 activation commit must change only the reviewed source pin"
            )
        if (
            _tracked_blob_at(repo, ancestry_tip, PRODUCTION_V4_ACTIVATION_PIN_RELATIVE)
            != b"None\n"
            or _tracked_blob(repo, PRODUCTION_V4_ACTIVATION_PIN_RELATIVE) != pin_bytes
        ):
            raise IntegrityError(
                "ProductionV4 activation commit is not the exact None-to-reviewed-pin transition"
            )
    _require_production_v4_ancestor(
        repo,
        qualification_commit,
        ancestry_tip,
        "ProductionV4 qualification commit",
    )


def _run_production_v4_verifier(repo: Path, arguments: list[str]) -> dict[str, object]:
    entrypoint = _tracked_file(repo, PRODUCTION_V4_VERIFIER_ENTRYPOINT_RELATIVE)
    try:
        completed = subprocess.run(
            [sys.executable, str(entrypoint), *arguments, "--json"],
            cwd=repo,
            check=False,
            capture_output=True,
            timeout=3_600,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IntegrityError("ProductionV4 fresh-process verifier could not complete") from error
    if (
        len(completed.stdout) > MAX_RELEASE_GATE_JSON_BYTES
        or len(completed.stderr) > MAX_RELEASE_GATE_JSON_BYTES
    ):
        raise IntegrityError("ProductionV4 fresh-process verifier output exceeds its bound")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise IntegrityError(
            f"ProductionV4 fresh-process verifier rejected qualification inputs: {detail[:500]}"
        )
    return _json_object_bytes(
        completed.stdout, "ProductionV4 fresh-process verifier result"
    )


def _normalized_production_v4_verifier_result(
    value: dict[str, object],
) -> dict[str, object]:
    normalized = json.loads(json.dumps(value))
    proof = normalized.get("proof")
    if isinstance(proof, dict):
        proof.pop("path", None)
    return normalized


def _replay_production_v4_verifier(
    *,
    repo: Path,
    template: Path,
    proof: Path,
    fixed_record: Path,
    model_bank: Path,
    qualification_manifest: dict[str, object],
    verifier_report: dict[str, object],
    qualification_statement: dict[str, object],
) -> None:
    template_path = _regular_file(template, "ProductionV4 RCNet proof template")
    _, template_bytes = _bounded_json_object(
        template_path, "ProductionV4 RCNet proof template"
    )
    proof = _regular_file(proof, "ProductionV4 known-valid proof")
    fixed_record = _regular_file(fixed_record, "ProductionV4 fixed-artifact record")
    model_bank = _regular_file(model_bank, "ProductionV4 model bank")
    with tempfile.TemporaryDirectory(prefix="cmfd-v4-activation-replay-") as temporary:
        statement_path = Path(temporary) / "statement.json"
        derived = _run_production_v4_verifier(
            repo,
            [
                "--template",
                str(template_path),
                "--proof",
                str(proof),
                "--write-statement",
                str(statement_path),
            ],
        )
        replayed_statement, _ = _bounded_json_object(
            statement_path, "replayed ProductionV4 qualification statement"
        )
        if replayed_statement != qualification_statement:
            raise IntegrityError(
                "replayed ProductionV4 statement does not match qualification evidence"
            )
        verified = _run_production_v4_verifier(
            repo,
            [
                "--statement",
                str(statement_path),
                "--proof",
                str(proof),
                "--fixed-artifact-record",
                str(fixed_record),
                "--model-bank",
                str(model_bank),
            ],
        )

    statement_derivation = verifier_report["statement_derivation"]
    known_valid = verifier_report["known_valid_result"]
    if not isinstance(statement_derivation, dict) or not isinstance(known_valid, dict):
        raise IntegrityError("ProductionV4 verifier replay evidence is malformed")
    expected_derived = statement_derivation.get("result")
    expected_verified = known_valid.get("result")
    if (
        not isinstance(expected_derived, dict)
        or not isinstance(expected_verified, dict)
        or _normalized_production_v4_verifier_result(derived)
        != _normalized_production_v4_verifier_result(expected_derived)
        or _normalized_production_v4_verifier_result(verified)
        != _normalized_production_v4_verifier_result(expected_verified)
    ):
        raise IntegrityError(
            "fresh ProductionV4 verifier replay does not reproduce the recorded report"
        )
    reproduction_result = qualification_manifest["proof_verification"]
    if not isinstance(reproduction_result, dict):  # pragma: no cover - validated upstream.
        raise IntegrityError("ProductionV4 qualification proof verification is missing")
    expected_reproduction = json.loads(json.dumps(verified))
    expected_reproduction["candidate_claims_verified"] = False
    if _normalized_production_v4_verifier_result(
        reproduction_result
    ) != _normalized_production_v4_verifier_result(expected_reproduction):
        raise IntegrityError(
            "ProductionV4 reproduction result does not match fresh full verification"
        )
    _, template_bytes_after = _bounded_json_object(
        template_path, "ProductionV4 RCNet proof template"
    )
    if template_bytes_after != template_bytes:
        raise IntegrityError("ProductionV4 RCNet proof template changed during replay")
    qualification_rows = {
        str(row["name"]): row
        for row in qualification_manifest["artifacts"]
        if isinstance(row, dict)
    }
    for path, name in (
        (model_bank, PRODUCTION_V4_PACKAGE_BANK),
        (fixed_record, PRODUCTION_V4_PACKAGE_FIXED_RECORD),
    ):
        if _production_v4_file_identity(
            path, f"ProductionV4 replay input {name}", expected_name=name
        ) != qualification_rows[name]:
            raise IntegrityError(f"ProductionV4 replay input {name} changed during replay")
    known_proof = _validate_report_file_identity(
        verifier_report["known_valid_proof"], "ProductionV4 known-valid proof"
    )
    if _production_v4_file_identity(
        proof,
        "ProductionV4 replay known-valid proof",
        expected_name=str(known_proof["name"]),
    ) != known_proof:
        raise IntegrityError("ProductionV4 known-valid proof changed during replay")


def _production_v4_approval_identity(name: str, data: bytes) -> dict[str, object]:
    return {
        "name": name,
        "bytes": len(data),
        "sha256": _sha256_bytes(data),
        "blake3": _blake3_bytes(data),
    }


def _production_v4_approval_network(
    candidate: dict[str, object], validated: dict[str, object]
) -> dict[str, object]:
    payload = candidate.get("payload")
    if not isinstance(payload, dict):  # pragma: no cover - validated candidate contract.
        raise IntegrityError("RCNet launch candidate payload is unavailable")
    proof = payload.get("proof_of_work")
    timestamp = payload.get("virtual_genesis_timestamp_unix_seconds")
    if not isinstance(proof, dict) or not isinstance(timestamp, int):
        raise IntegrityError("RCNet launch candidate approval identity is unavailable")
    return {
        "profile": PRODUCTION_V4_RCNET_NETWORK_NAME,
        "launch_root": validated["launch_root"],
        "network_id": validated["network_id"],
        "virtual_genesis_hash": validated["genesis"],
        "virtual_genesis_timestamp_unix_seconds": timestamp,
        "pow_limit": proof["pow_limit"],
    }


def _production_v4_approval_common_files(
    *,
    candidate_bytes: bytes,
    input_manifest: dict[str, object],
    qualification_manifest_bytes: bytes,
    qualification_manifest: dict[str, object],
    verifier_report_bytes: bytes,
    verifier_report: dict[str, object],
    verifier_script_size: int,
    verifier_script_sha256: str,
    verifier_script_blake3: str,
    template_path: Path,
) -> dict[str, object]:
    artifact_values = qualification_manifest.get("artifacts")
    if not isinstance(artifact_values, list):  # pragma: no cover - validated upstream.
        raise IntegrityError("ProductionV4 qualification artifact identities are unavailable")
    artifacts = {
        str(row["name"]): row
        for row in artifact_values
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    known_proof = _validate_report_file_identity(
        verifier_report.get("known_valid_proof"), "ProductionV4 known-valid proof"
    )
    template = _production_v4_file_identity(
        template_path, "ProductionV4 RCNet proof template"
    )
    template["name"] = "PRODUCTION-V4-RCNET-PROOF-TEMPLATE.json"
    files: dict[str, object] = {
        "launch_candidate": _production_v4_approval_identity(
            PRODUCTION_RC_LAUNCH_CANDIDATE_NAME, candidate_bytes
        ),
        "rcnet_input_manifest": dict(input_manifest),
        "independent_reproduction_report": _production_v4_approval_identity(
            PRODUCTION_V4_QUALIFICATION_MANIFEST_NAME, qualification_manifest_bytes
        ),
        "fresh_process_verifier_report": _production_v4_approval_identity(
            PRODUCTION_V4_FRESH_PROCESS_VERIFIER_REPORT_NAME, verifier_report_bytes
        ),
        "fresh_process_verifier_script": {
            "name": PRODUCTION_V4_FRESH_PROCESS_VERIFIER_SCRIPT_NAME,
            "bytes": verifier_script_size,
            "sha256": verifier_script_sha256,
            "blake3": verifier_script_blake3,
        },
        "rcnet_proof_template": template,
        "qualification_proof": dict(known_proof),
        "model_bank": dict(artifacts[PRODUCTION_V4_PACKAGE_BANK]),
        "fixed_artifact_record": dict(
            artifacts[PRODUCTION_V4_PACKAGE_FIXED_RECORD]
        ),
    }
    for bank in range(3):
        for suffix, role_suffix in (
            ("json", "json"),
            ("codeword", "codeword"),
            ("row-major.codeword", "row_major_codeword"),
            ("tree", "tree"),
        ):
            name = f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}"
            try:
                files[f"fixed_bank_{bank}_{role_suffix}"] = dict(artifacts[name])
            except KeyError as error:  # pragma: no cover - validated upstream.
                raise IntegrityError(
                    f"ProductionV4 qualification artifact identity is missing: {name}"
                ) from error
    try:
        activation_approval.qualification_binding_sha256(files)
    except activation_approval.ApprovalError as error:
        raise IntegrityError(str(error)) from error
    return files


def _validate_production_v4_activation_inputs(
    *,
    repo: Path,
    candidate_path: Path,
    input_manifest_path: Path,
    qualification_manifest_path: Path,
    verifier_report_path: Path,
    verifier_script_path: Path,
    template_path: Path,
    proof_path: Path,
    model_bank_path: Path,
    fixed_record_path: Path,
    artifact_directory: Path,
) -> dict[str, object]:
    candidate, candidate_bytes = _bounded_json_object(
        candidate_path, "RCNet launch candidate"
    )
    validated_candidate = _validate_production_v4_rcnet_candidate(candidate)
    if candidate_bytes != _canonical_rcnet_v2_candidate(candidate, validated_candidate):
        raise IntegrityError("RCNet launch candidate is not canonical pretty JSON")
    candidate_artifacts = {
        "bank": validated_candidate["bank"],
        "fixed_record": validated_candidate["fixed_record"],
    }
    if any(not isinstance(identity, dict) for identity in candidate_artifacts.values()):
        raise IntegrityError("RCNet launch candidate artifact identities are unavailable")
    artifact_pins = {
        role: {
            "bytes": str(identity["bytes"]),
            "blake3": identity["blake3"],
            "sha256": identity["sha256"],
        }
        for role, identity in candidate_artifacts.items()
    }
    proof = {"artifacts": artifact_pins}

    qualification_manifest, qualification_manifest_bytes = _bounded_json_object(
        qualification_manifest_path, "ProductionV4 qualification manifest"
    )
    if qualification_manifest_bytes != _canonical_json(qualification_manifest):
        raise IntegrityError("ProductionV4 qualification manifest is not canonical JSON")
    (
        qualification_source_commit,
        qualification_generation_commit,
        qualification_proof,
        qualification_statement,
        qualification_input_manifest,
        qualification_derived,
    ) = _validate_production_v4_qualification_manifest(
        qualification_manifest, proof, str(validated_candidate["network_id"])
    )

    specification_rows = qualification_manifest["frozen_specifications"]
    if not isinstance(specification_rows, list):  # pragma: no cover - validated above.
        raise IntegrityError("ProductionV4 frozen specification identities are missing")
    reported_specifications = {
        str(row["path"]): row for row in specification_rows if isinstance(row, dict)
    }
    for relative, expected_sha256 in PRODUCTION_V4_FROZEN_SPEC_SHA256.items():
        tracked = _tracked_blob(repo, relative)
        row = reported_specifications.get(relative)
        if (
            _sha256_bytes(tracked) != expected_sha256
            or row is None
            or row.get("bytes") != len(tracked)
            or row.get("sha256") != expected_sha256
            or row.get("blake3") != _blake3_bytes(tracked)
        ):
            raise IntegrityError(
                f"tracked ProductionV4 frozen specification does not match qualification evidence: {relative}"
            )

    verifier_script_path = _regular_file(
        verifier_script_path, "ProductionV4 fresh-process verifier script"
    )
    with _stable_regular_handle(
        verifier_script_path, "ProductionV4 fresh-process verifier script"
    ) as (_, verifier_handle, verifier_stat):
        if verifier_stat.st_size <= 0:
            raise IntegrityError("ProductionV4 fresh-process verifier script is empty")
        (
            verifier_script_size,
            verifier_script_sha256,
            verifier_script_blake3,
            verifier_script_bytes,
        ) = _stream_sha256(
            verifier_handle,
            expected_size=verifier_stat.st_size,
            maximum_size=MAX_RELEASE_GATE_JSON_BYTES,
            label="ProductionV4 fresh-process verifier script",
            capture_bytes=MAX_RELEASE_GATE_JSON_BYTES,
        )
    tracked_verifier = _tracked_blob(repo, PRODUCTION_V4_VERIFIER_ENTRYPOINT_RELATIVE)
    if verifier_script_bytes != tracked_verifier:
        raise IntegrityError(
            "ProductionV4 verifier script is not byte-identical to the tracked HEAD entrypoint"
        )

    verifier_report, verifier_report_bytes = _bounded_json_object(
        verifier_report_path, "ProductionV4 fresh-process verifier report"
    )
    if verifier_report_bytes != _canonical_json(verifier_report):
        raise IntegrityError("ProductionV4 verifier report is not canonical JSON")
    _validate_production_v4_verifier_report(
        verifier_report,
        qualification_source_commit,
        qualification_proof,
        qualification_statement,
        qualification_derived,
        (verifier_script_size, verifier_script_sha256, verifier_script_blake3),
    )
    _validate_production_v4_verifier_sources(repo, verifier_report)

    _, input_rows = _validate_production_v4_rcnet_input_manifest(
        input_manifest_path,
        expected_network_id=str(validated_candidate["network_id"]),
        expected_source_commit=qualification_generation_commit,
        expected_identity=qualification_input_manifest,
    )
    _validate_production_v4_activation_artifacts(
        input_rows=input_rows,
        qualification_manifest=qualification_manifest,
        verifier_report=verifier_report,
        model_bank=model_bank_path,
        fixed_record=fixed_record_path,
        artifact_directory=artifact_directory,
        proof=proof_path,
    )
    _replay_production_v4_verifier(
        repo=repo,
        template=template_path,
        proof=proof_path,
        fixed_record=fixed_record_path,
        model_bank=model_bank_path,
        qualification_manifest=qualification_manifest,
        verifier_report=verifier_report,
        qualification_statement=qualification_statement,
    )

    approval_files = _production_v4_approval_common_files(
        candidate_bytes=candidate_bytes,
        input_manifest=qualification_input_manifest,
        qualification_manifest_bytes=qualification_manifest_bytes,
        qualification_manifest=qualification_manifest,
        verifier_report_bytes=verifier_report_bytes,
        verifier_report=verifier_report,
        verifier_script_size=verifier_script_size,
        verifier_script_sha256=verifier_script_sha256,
        verifier_script_blake3=verifier_script_blake3,
        template_path=template_path,
    )

    pin_fields = {
        "schema": "CMFD_PRODUCTION_V4_ACTIVATION_V1",
        "qualification_source_commit": qualification_source_commit,
        "qualification_manifest_sha256": _sha256_bytes(qualification_manifest_bytes),
        "fresh_process_verifier_binary_sha256": verifier_script_sha256,
        "fresh_process_verifier_report_sha256": _sha256_bytes(verifier_report_bytes),
        "core_spec_sha256": PRODUCTION_V4_CORE_SPEC_SHA256,
        "core_vector_sha256": PRODUCTION_V4_CORE_VECTOR_SHA256,
        "proof_algebra_sha256": PRODUCTION_V4_PROOF_ALGEBRA_SHA256,
    }
    return {
        "approval_files": approval_files,
        "approval_network": _production_v4_approval_network(
            candidate, validated_candidate
        ),
        "artifacts": artifact_pins,
        "generation_commit": qualification_generation_commit,
        "pin_fields": pin_fields,
        "qualification_commit": qualification_source_commit,
    }


def _production_v4_approval_trust(
    *,
    common_files: dict[str, object],
    producer_allowed_signers: Path,
    producer_signer_identity: str,
    reproducer_allowed_signers: Path,
    reproducer_signer_identity: str,
    expected_ssh_keygen_sha256: str,
) -> dict[str, object]:
    _require_hex256(
        expected_ssh_keygen_sha256,
        "trusted OpenSSH verifier SHA-256",
        reject_repeated=False,
    )
    try:
        authorities = activation_approval.load_trusted_authorities(
            producer_allowed_signers=producer_allowed_signers,
            producer_signer_identity=producer_signer_identity,
            reproducer_allowed_signers=reproducer_allowed_signers,
            reproducer_signer_identity=reproducer_signer_identity,
        )
        binding = activation_approval.qualification_binding_sha256(common_files)
    except activation_approval.ApprovalError as error:
        raise IntegrityError(str(error)) from error
    return {
        "contract_schema": activation_approval.SUBJECT_SCHEMA,
        "qualification_binding_sha256": binding,
        "ssh_keygen_sha256": expected_ssh_keygen_sha256,
        "producer": authorities[activation_approval.PRODUCER_ROLE],
        "independent_reproducer": authorities[activation_approval.REPRODUCER_ROLE],
    }


def _production_v4_pin_fields_with_trust(
    base_fields: dict[str, object], approval_trust: dict[str, object]
) -> dict[str, object]:
    return {**base_fields, "approval_trust": approval_trust}


def _validate_production_v4_approval_trust_fields(
    value: object,
) -> dict[str, object]:
    trust = _require_exact_fields(
        value,
        {
            "contract_schema",
            "qualification_binding_sha256",
            "ssh_keygen_sha256",
            "producer",
            "independent_reproducer",
        },
        "ProductionV4 activation approval trust",
    )
    if trust["contract_schema"] != activation_approval.SUBJECT_SCHEMA:
        raise IntegrityError("ProductionV4 activation approval contract schema is invalid")
    _require_hex256(
        trust["qualification_binding_sha256"],
        "ProductionV4 qualification binding SHA-256",
        reject_repeated=False,
    )
    _require_hex256(
        trust["ssh_keygen_sha256"],
        "ProductionV4 trusted OpenSSH verifier SHA-256",
        reject_repeated=False,
    )
    for role in ("producer", "independent_reproducer"):
        row = _require_exact_fields(
            trust[role],
            {
                "signer_identity",
                "allowed_signers_sha256",
                "key_blob_sha256",
                "key_fingerprint",
                "key_type",
            },
            f"ProductionV4 {role} approval trust",
        )
        if (
            not isinstance(row["signer_identity"], str)
            or not SIGNER_IDENTITY_RE.fullmatch(row["signer_identity"])
        ):
            raise IntegrityError(f"ProductionV4 {role} approval signer identity is invalid")
        for field in ("allowed_signers_sha256", "key_blob_sha256"):
            _require_hex256(
                row[field],
                f"ProductionV4 {role} {field}",
                reject_repeated=False,
            )
        if (
            not isinstance(row["key_fingerprint"], str)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", row["key_fingerprint"])
            or not isinstance(row["key_type"], str)
            or not SIGNER_IDENTITY_RE.fullmatch(row["key_type"])
            or "-cert-v01@openssh.com" in row["key_type"]
            or row["key_type"].startswith("ssh-dss")
        ):
            raise IntegrityError(f"ProductionV4 {role} approval key identity is invalid")
        expected_fingerprint = "SHA256:" + base64.b64encode(
            bytes.fromhex(row["key_blob_sha256"])
        ).decode("ascii").rstrip("=")
        if row["key_fingerprint"] != expected_fingerprint:
            raise IntegrityError(
                f"ProductionV4 {role} key fingerprint does not match its key digest"
            )
    producer = trust["producer"]
    reproducer = trust["independent_reproducer"]
    if not isinstance(producer, dict) or not isinstance(reproducer, dict):
        raise IntegrityError("ProductionV4 approval trust is malformed")
    if any(
        producer[field] == reproducer[field]
        for field in (
            "signer_identity",
            "allowed_signers_sha256",
            "key_blob_sha256",
            "key_fingerprint",
        )
    ):
        raise IntegrityError(
            "ProductionV4 producer and independent reproducer authorities must differ"
        )
    return trust


def _render_production_v4_activation_pin(pin_fields: dict[str, object]) -> bytes:
    fields = (
        "schema",
        "qualification_source_commit",
        "qualification_manifest_sha256",
        "fresh_process_verifier_binary_sha256",
        "fresh_process_verifier_report_sha256",
        "core_spec_sha256",
        "core_vector_sha256",
        "proof_algebra_sha256",
    )
    _require_exact_fields(
        pin_fields, {*fields, "approval_trust"}, "ProductionV4 activation source pin"
    )
    lines = ["Some(ProductionV4ActivationEvidence {"]
    for field in fields:
        value = pin_fields[field]
        if not isinstance(value, str):  # pragma: no cover - internal validated contract.
            raise IntegrityError(f"ProductionV4 activation source pin has invalid {field}")
        lines.append(f'    {field}: "{value}",')
    trust = _validate_production_v4_approval_trust_fields(pin_fields["approval_trust"])
    lines.append("    approval_trust: ProductionV4ActivationApprovalTrust {")
    lines.append(f'        contract_schema: "{trust["contract_schema"]}",')
    lines.append(
        "        qualification_binding_sha256: "
        f'"{trust["qualification_binding_sha256"]}",'
    )
    lines.append(f'        ssh_keygen_sha256: "{trust["ssh_keygen_sha256"]}",')
    for role in ("producer", "independent_reproducer"):
        signer = trust[role]
        if not isinstance(signer, dict):  # pragma: no cover - validated above.
            raise IntegrityError("ProductionV4 approval signer trust is unavailable")
        lines.append(f"        {role}: ProductionV4ActivationSignerTrust {{")
        for field in (
            "signer_identity",
            "allowed_signers_sha256",
            "key_blob_sha256",
            "key_fingerprint",
            "key_type",
        ):
            lines.append(f'            {field}: "{signer[field]}",')
        lines.append("        },")
    lines.append("    },")
    lines.append("})")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _production_v4_activation_evidence(
    *, validated: dict[str, object], pin_fields: dict[str, object], commit: str
) -> tuple[dict[str, object], bytes]:
    approval_trust = _validate_production_v4_approval_trust_fields(
        pin_fields.get("approval_trust")
    )
    evidence = {
        "activation_approval_trust": approval_trust,
        "artifacts": validated["artifacts"],
        "core_spec_sha256": pin_fields["core_spec_sha256"],
        "core_vector_sha256": pin_fields["core_vector_sha256"],
        "fresh_process_verifier_binary_sha256": pin_fields[
            "fresh_process_verifier_binary_sha256"
        ],
        "fresh_process_verifier_report_sha256": pin_fields[
            "fresh_process_verifier_report_sha256"
        ],
        "network_profile": "RCNet-1",
        "proof_algebra_sha256": pin_fields["proof_algebra_sha256"],
        "proof_selection": "ProductionV4",
        "qualification_manifest_sha256": pin_fields[
            "qualification_manifest_sha256"
        ],
        "qualification_source_commit": pin_fields["qualification_source_commit"],
        "schema": pin_fields["schema"],
        "source_commit": commit,
    }
    return evidence, _canonical_json(evidence)


def _production_v4_approval_subject(
    *,
    phase: str,
    commit: str,
    validated: dict[str, object],
    pin_bytes: bytes,
    evidence_bytes: bytes | None,
    network_info: Path | None,
) -> dict[str, object]:
    common_files = validated.get("approval_files")
    network = validated.get("approval_network")
    generation_commit = validated.get("generation_commit")
    qualification_commit = validated.get("qualification_commit")
    if (
        not isinstance(common_files, dict)
        or not isinstance(network, dict)
        or not isinstance(generation_commit, str)
        or not isinstance(qualification_commit, str)
    ):
        raise IntegrityError("ProductionV4 activation approval inputs are unavailable")
    files = json.loads(json.dumps(common_files))
    if phase == "evidence":
        if evidence_bytes is None or network_info is None:
            raise IntegrityError(
                "ProductionV4 evidence approval requires compiled NETWORK-INFO.json"
            )
        network_value, network_bytes = _bounded_json_object(
            network_info, "compiled ProductionV4 NETWORK-INFO.json"
        )
        canonical_network = (
            json.dumps(network_value, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        if network_bytes != canonical_network:
            raise IntegrityError("compiled ProductionV4 NETWORK-INFO.json is not canonical")
        _validate_production_v4_runtime_identity(network_value, commit)
        proof = network_value.get("proof_of_work")
        if (
            not isinstance(proof, dict)
            or proof.get("activation_evidence_sha256")
            != _sha256_bytes(evidence_bytes)
        ):
            raise IntegrityError(
                "compiled ProductionV4 NETWORK-INFO.json is not bound to activation evidence"
            )
        files["activation_evidence"] = _production_v4_approval_identity(
            PRODUCTION_V4_ACTIVATION_NAME, evidence_bytes
        )
        files["compiled_network_info"] = _production_v4_approval_identity(
            PRODUCTION_RC_NETWORK_INFO_NAME, network_bytes
        )
    elif network_info is not None:
        raise IntegrityError("ProductionV4 pin approval must not include NETWORK-INFO.json")
    try:
        return activation_approval.build_subject(
            phase=phase,
            activation_source_commit=commit,
            artifact_generation_source_commit=generation_commit,
            qualification_source_commit=qualification_commit,
            network=network,
            source_pin_sha256=_sha256_bytes(pin_bytes),
            files=files,
        )
    except activation_approval.ApprovalError as error:
        raise IntegrityError(str(error)) from error


def _required_production_v4_approval_path(value: Path | None, label: str) -> Path:
    if value is None:
        raise IntegrityError(PRODUCTION_V4_ACTIVATION_APPROVAL_ERROR)
    return value


def _verify_production_v4_activation_approvals(
    *,
    subject: dict[str, object],
    approval_trust: dict[str, object],
    producer_approval: Path | None,
    producer_signature: Path | None,
    producer_allowed_signers: Path | None,
    producer_signer_identity: str | None,
    reproducer_approval: Path | None,
    reproducer_signature: Path | None,
    reproducer_allowed_signers: Path | None,
    reproducer_signer_identity: str | None,
    ssh_keygen: Path | None,
    expected_ssh_keygen_sha256: str | None,
) -> dict[str, object]:
    if (
        producer_signer_identity is None
        or reproducer_signer_identity is None
        or expected_ssh_keygen_sha256 is None
    ):
        raise IntegrityError(PRODUCTION_V4_ACTIVATION_APPROVAL_ERROR)
    trust = _validate_production_v4_approval_trust_fields(approval_trust)
    expected_trust = {
        activation_approval.PRODUCER_ROLE: trust["producer"],
        activation_approval.REPRODUCER_ROLE: trust["independent_reproducer"],
    }
    if trust["ssh_keygen_sha256"] != expected_ssh_keygen_sha256:
        raise IntegrityError("trusted OpenSSH verifier digest does not match the source pin")
    try:
        return activation_approval.verify_approval_pair(
            subject=subject,
            producer_approval=_required_production_v4_approval_path(
                producer_approval, "producer approval"
            ),
            producer_signature=_required_production_v4_approval_path(
                producer_signature, "producer approval signature"
            ),
            producer_allowed_signers=_required_production_v4_approval_path(
                producer_allowed_signers, "producer allowed-signers authority"
            ),
            producer_signer_identity=producer_signer_identity,
            reproducer_approval=_required_production_v4_approval_path(
                reproducer_approval, "independent reproducer approval"
            ),
            reproducer_signature=_required_production_v4_approval_path(
                reproducer_signature, "independent reproducer approval signature"
            ),
            reproducer_allowed_signers=_required_production_v4_approval_path(
                reproducer_allowed_signers,
                "independent reproducer allowed-signers authority",
            ),
            reproducer_signer_identity=reproducer_signer_identity,
            ssh_keygen=_required_production_v4_approval_path(
                ssh_keygen, "trusted OpenSSH verifier"
            ),
            expected_verifier_sha256=expected_ssh_keygen_sha256,
            expected_trust=expected_trust,
        )
    except activation_approval.ApprovalError as error:
        raise IntegrityError(str(error)) from error


def create_production_v4_activation(
    *,
    phase: str,
    repo: Path,
    expected_commit: str,
    candidate: Path,
    input_manifest: Path,
    qualification_manifest: Path,
    verifier_report: Path,
    verifier_script: Path,
    template: Path,
    proof: Path,
    model_bank: Path,
    fixed_record: Path,
    artifact_directory: Path,
    output: Path,
    network_info: Path | None = None,
    producer_approval: Path | None = None,
    producer_signature: Path | None = None,
    producer_allowed_signers: Path | None = None,
    producer_signer_identity: str | None = None,
    reproducer_approval: Path | None = None,
    reproducer_signature: Path | None = None,
    reproducer_allowed_signers: Path | None = None,
    reproducer_signer_identity: str | None = None,
    ssh_keygen: Path | None = None,
    expected_ssh_keygen_sha256: str | None = None,
) -> dict[str, object]:
    if phase not in {"pin", "evidence"}:
        raise IntegrityError("ProductionV4 activation phase must be pin or evidence")
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    output_parent = _regular_directory(
        output.parent.resolve(strict=True), "ProductionV4 activation output directory"
    )
    output_parent_identity = _stat_object_identity(output_parent.lstat())
    output = output_parent / output.name
    if os.path.lexists(output):
        raise IntegrityError(f"ProductionV4 activation output already exists: {output}")
    tracked_pin = (repo / PRODUCTION_V4_ACTIVATION_PIN_RELATIVE).resolve(strict=False)
    if phase == "pin" and os.path.normcase(
        str(output.resolve(strict=False))
    ) == os.path.normcase(str(tracked_pin)):
        raise IntegrityError(
            "pin phase cannot write the tracked ProductionV4 activation include"
        )
    if phase == "evidence" and output.name != PRODUCTION_V4_ACTIVATION_NAME:
        raise IntegrityError(
            f"ProductionV4 activation evidence must be named {PRODUCTION_V4_ACTIVATION_NAME}"
        )

    validated = _validate_production_v4_activation_inputs(
        repo=repo,
        candidate_path=candidate,
        input_manifest_path=input_manifest,
        qualification_manifest_path=qualification_manifest,
        verifier_report_path=verifier_report,
        verifier_script_path=verifier_script,
        template_path=template,
        proof_path=proof,
        model_bank_path=model_bank,
        fixed_record_path=fixed_record,
        artifact_directory=artifact_directory,
    )
    base_pin_fields = validated["pin_fields"]
    common_files = validated.get("approval_files")
    if not isinstance(base_pin_fields, dict) or not isinstance(
        common_files, dict
    ):  # pragma: no cover - internal contract.
        raise IntegrityError("ProductionV4 activation pin fields are unavailable")
    generation_commit = validated["generation_commit"]
    qualification_commit = validated["qualification_commit"]
    if not isinstance(generation_commit, str) or not isinstance(
        qualification_commit, str
    ):  # pragma: no cover - internal validated contract.
        raise IntegrityError("ProductionV4 activation source commits are unavailable")
    preflight_pin = b""
    if phase == "evidence":
        current_pin = _tracked_blob(repo, PRODUCTION_V4_ACTIVATION_PIN_RELATIVE)
        if current_pin != b"None\n":
            preflight_pin = current_pin
    _validate_production_v4_activation_history(
        phase=phase,
        repo=repo,
        commit=commit,
        generation_commit=generation_commit,
        qualification_commit=qualification_commit,
        pin_bytes=preflight_pin,
    )
    if (
        producer_signer_identity is None
        or reproducer_signer_identity is None
        or expected_ssh_keygen_sha256 is None
    ):
        raise IntegrityError(PRODUCTION_V4_ACTIVATION_APPROVAL_ERROR)
    producer_policy = _required_production_v4_approval_path(
        producer_allowed_signers, "producer allowed-signers authority"
    )
    reproducer_policy = _required_production_v4_approval_path(
        reproducer_allowed_signers, "independent reproducer allowed-signers authority"
    )
    approval_trust = _production_v4_approval_trust(
        common_files=common_files,
        producer_allowed_signers=producer_policy,
        producer_signer_identity=producer_signer_identity,
        reproducer_allowed_signers=reproducer_policy,
        reproducer_signer_identity=reproducer_signer_identity,
        expected_ssh_keygen_sha256=expected_ssh_keygen_sha256,
    )
    pin_fields = _production_v4_pin_fields_with_trust(
        base_pin_fields, approval_trust
    )
    pin_bytes = _render_production_v4_activation_pin(pin_fields)
    _validate_production_v4_activation_history(
        phase=phase,
        repo=repo,
        commit=commit,
        generation_commit=generation_commit,
        qualification_commit=qualification_commit,
        pin_bytes=pin_bytes,
    )
    _assert_clean_exact_repo(repo, commit)
    evidence_bytes = None
    if phase == "evidence":
        _, evidence_bytes = _production_v4_activation_evidence(
            validated=validated, pin_fields=pin_fields, commit=commit
        )
    subject = _production_v4_approval_subject(
        phase=phase,
        commit=commit,
        validated=validated,
        pin_bytes=pin_bytes,
        evidence_bytes=evidence_bytes,
        network_info=network_info,
    )
    receipt = _verify_production_v4_activation_approvals(
        subject=subject,
        approval_trust=approval_trust,
        producer_approval=producer_approval,
        producer_signature=producer_signature,
        producer_allowed_signers=producer_policy,
        producer_signer_identity=producer_signer_identity,
        reproducer_approval=reproducer_approval,
        reproducer_signature=reproducer_signature,
        reproducer_allowed_signers=reproducer_policy,
        reproducer_signer_identity=reproducer_signer_identity,
        ssh_keygen=ssh_keygen,
        expected_ssh_keygen_sha256=expected_ssh_keygen_sha256,
    )
    _assert_clean_exact_repo(repo, commit)
    output_bytes = pin_bytes if phase == "pin" else evidence_bytes
    if output_bytes is None:  # pragma: no cover - phase contract above.
        raise IntegrityError("ProductionV4 activation output bytes are unavailable")
    _write_new_verified(
        path=output,
        data=output_bytes,
        parent_identity=output_parent_identity,
        label="ProductionV4 activation output",
    )
    return {
        "phase": phase,
        "output": _production_v4_approval_identity(output.name, output_bytes),
        "approval_receipt": receipt,
    }


def create_production_v4_activation_approval_request(
    *,
    phase: str,
    repo: Path,
    expected_commit: str,
    candidate: Path,
    input_manifest: Path,
    qualification_manifest: Path,
    verifier_report: Path,
    verifier_script: Path,
    template: Path,
    proof: Path,
    model_bank: Path,
    fixed_record: Path,
    artifact_directory: Path,
    output_directory: Path,
    producer_allowed_signers: Path,
    producer_signer_identity: str,
    reproducer_allowed_signers: Path,
    reproducer_signer_identity: str,
    ssh_keygen: Path,
    expected_ssh_keygen_sha256: str,
    network_info: Path | None = None,
) -> dict[str, object]:
    if phase not in {"pin", "evidence"}:
        raise IntegrityError("ProductionV4 activation phase must be pin or evidence")
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    output_directory = _regular_directory(
        output_directory.resolve(strict=True),
        "ProductionV4 approval-request output directory",
    )
    output_parent_identity = _stat_object_identity(output_directory.lstat())
    _require_hex256(
        expected_ssh_keygen_sha256,
        "trusted OpenSSH verifier SHA-256",
        reject_repeated=False,
    )
    if _sha256_file(ssh_keygen) != expected_ssh_keygen_sha256:
        raise IntegrityError("OpenSSH verifier does not match its expected SHA-256")

    validated = _validate_production_v4_activation_inputs(
        repo=repo,
        candidate_path=candidate,
        input_manifest_path=input_manifest,
        qualification_manifest_path=qualification_manifest,
        verifier_report_path=verifier_report,
        verifier_script_path=verifier_script,
        template_path=template,
        proof_path=proof,
        model_bank_path=model_bank,
        fixed_record_path=fixed_record,
        artifact_directory=artifact_directory,
    )
    base_pin_fields = validated.get("pin_fields")
    common_files = validated.get("approval_files")
    if not isinstance(base_pin_fields, dict) or not isinstance(common_files, dict):
        raise IntegrityError("ProductionV4 activation approval inputs are unavailable")
    approval_trust = _production_v4_approval_trust(
        common_files=common_files,
        producer_allowed_signers=producer_allowed_signers,
        producer_signer_identity=producer_signer_identity,
        reproducer_allowed_signers=reproducer_allowed_signers,
        reproducer_signer_identity=reproducer_signer_identity,
        expected_ssh_keygen_sha256=expected_ssh_keygen_sha256,
    )
    pin_fields = _production_v4_pin_fields_with_trust(
        base_pin_fields, approval_trust
    )
    pin_bytes = _render_production_v4_activation_pin(pin_fields)
    generation_commit = validated.get("generation_commit")
    qualification_commit = validated.get("qualification_commit")
    if not isinstance(generation_commit, str) or not isinstance(
        qualification_commit, str
    ):
        raise IntegrityError("ProductionV4 activation source commits are unavailable")
    _validate_production_v4_activation_history(
        phase=phase,
        repo=repo,
        commit=commit,
        generation_commit=generation_commit,
        qualification_commit=qualification_commit,
        pin_bytes=pin_bytes,
    )
    evidence_bytes = None
    if phase == "evidence":
        _, evidence_bytes = _production_v4_activation_evidence(
            validated=validated, pin_fields=pin_fields, commit=commit
        )
    subject = _production_v4_approval_subject(
        phase=phase,
        commit=commit,
        validated=validated,
        pin_bytes=pin_bytes,
        evidence_bytes=evidence_bytes,
        network_info=network_info,
    )
    try:
        prepared = activation_approval.prepare_approval_payloads(
            subject=subject,
            producer_allowed_signers=producer_allowed_signers,
            producer_signer_identity=producer_signer_identity,
            reproducer_allowed_signers=reproducer_allowed_signers,
            reproducer_signer_identity=reproducer_signer_identity,
        )
    except activation_approval.ApprovalError as error:
        raise IntegrityError(str(error)) from error
    authorities = prepared.get("authorities")
    payloads = prepared.get("payloads")
    expected_authorities = {
        activation_approval.PRODUCER_ROLE: approval_trust["producer"],
        activation_approval.REPRODUCER_ROLE: approval_trust[
            "independent_reproducer"
        ],
    }
    if authorities != expected_authorities or not isinstance(payloads, dict):
        raise IntegrityError("ProductionV4 approval preparation changed its trust inputs")
    producer_payload = payloads.get(activation_approval.PRODUCER_ROLE)
    reproducer_payload = payloads.get(activation_approval.REPRODUCER_ROLE)
    if not isinstance(producer_payload, bytes) or not isinstance(
        reproducer_payload, bytes
    ):
        raise IntegrityError("ProductionV4 approval payload bytes are unavailable")
    target_bytes = pin_bytes if phase == "pin" else evidence_bytes
    if target_bytes is None:  # pragma: no cover - phase contract above.
        raise IntegrityError("ProductionV4 approval review target is unavailable")

    prefix = f"PRODUCTION-V4-ACTIVATION-{phase.upper()}"
    outputs = {
        f"{prefix}-PRODUCER-APPROVAL.json": producer_payload,
        f"{prefix}-REPRODUCER-APPROVAL.json": reproducer_payload,
        f"{prefix}-TARGET.review": target_bytes,
    }
    paths = {name: output_directory / name for name in outputs}
    existing = sorted(name for name, path in paths.items() if os.path.lexists(path))
    if existing:
        raise IntegrityError(
            f"ProductionV4 approval-request outputs already exist: {existing}"
        )
    _assert_clean_exact_repo(repo, commit)
    if _sha256_file(ssh_keygen) != expected_ssh_keygen_sha256:
        raise IntegrityError("OpenSSH verifier changed during approval preparation")
    written: list[tuple[Path, tuple[int, int, int, int, int], str]] = []
    try:
        for name, data in outputs.items():
            path = paths[name]
            identity = _write_new_verified(
                path=path,
                data=data,
                parent_identity=output_parent_identity,
                label=f"ProductionV4 approval-request output {name}",
            )
            written.append((path, identity, name))
        if _stat_object_identity(output_directory.lstat()) != output_parent_identity:
            raise IntegrityError(
                "ProductionV4 approval-request output directory changed during publication"
            )
        for path, identity, name in written:
            expected = outputs[name]
            with _stable_regular_handle(
                path, f"ProductionV4 approval-request output {name}"
            ) as (_, handle, opened):
                actual = handle.read(len(expected) + 1)
            if _stat_identity(opened) != identity or actual != expected:
                raise IntegrityError(
                    f"ProductionV4 approval-request output changed: {name}"
                )
        _assert_clean_exact_repo(repo, commit)
        if _sha256_file(ssh_keygen) != expected_ssh_keygen_sha256:
            raise IntegrityError("OpenSSH verifier changed during approval publication")
    except BaseException:
        cleanup_errors: list[str] = []
        for path, identity, name in reversed(written):
            try:
                _remove_exact_new(
                    path,
                    identity,
                    f"ProductionV4 approval-request output {name}",
                )
            except BaseException as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            raise IntegrityError(
                "cannot clean up ProductionV4 approval-request outputs: "
                + "; ".join(cleanup_errors)
            )
        raise
    return {
        "phase": phase,
        "subject_sha256": _sha256_bytes(activation_approval.canonical_json(subject)),
        "ssh_keygen_sha256": expected_ssh_keygen_sha256,
        "outputs": {
            name: _production_v4_approval_identity(name, data)
            for name, data in outputs.items()
        },
    }


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
        if name in (
            BUILDINFO_NAME,
            SOURCE_SBOM_NAME,
            PROVENANCE_NAME,
            CHECKSUM_NAME,
            CHECKSUM_SIGNATURE_NAME,
        ):
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


def _source_lock_blobs(repo: Path) -> dict[str, bytes]:
    blobs = {}
    for relative in SOURCE_LOCK_FILES:
        data = _tracked_blob(repo, relative)
        if len(data) > MAX_SOURCE_LOCK_BYTES:
            raise IntegrityError(f"source lockfile exceeds its size limit: {relative}")
        blobs[relative] = data
    return blobs


def _npm_package_name(location: str, package: dict[str, object]) -> str:
    declared = package.get("name")
    if isinstance(declared, str) and declared:
        return _single_line("npm package name", declared)
    marker = "node_modules/"
    if marker not in location:
        raise IntegrityError(f"npm lockfile package has no name: {location}")
    return _single_line("npm package name", location.rsplit(marker, 1)[1])


def _expected_source_sbom(
    *, repo: Path, commit: str, version: str
) -> dict[str, object]:
    blobs = _source_lock_blobs(repo)
    try:
        cargo = tomllib.loads(blobs["Cargo.lock"].decode("utf-8", "strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise IntegrityError("Cargo.lock is not valid UTF-8 TOML") from error
    packages = cargo.get("package")
    if not isinstance(packages, list):
        raise IntegrityError("Cargo.lock has no package inventory")
    components: list[dict[str, object]] = []
    for package in packages:
        if not isinstance(package, dict):
            raise IntegrityError("Cargo.lock package inventory is malformed")
        name = package.get("name")
        locked_version = package.get("version")
        if not isinstance(name, str) or not isinstance(locked_version, str):
            raise IntegrityError("Cargo.lock package identity is malformed")
        component: dict[str, object] = {
            "ecosystem": "cargo",
            "name": _single_line("Cargo package name", name),
            "version": _single_line("Cargo package version", locked_version),
        }
        source = package.get("source")
        checksum = package.get("checksum")
        if source is not None:
            if not isinstance(source, str):
                raise IntegrityError("Cargo.lock package source is malformed")
            component["source"] = _single_line("Cargo package source", source)
        if checksum is not None:
            if not isinstance(checksum, str) or not HEX256_RE.fullmatch(checksum):
                raise IntegrityError("Cargo.lock package checksum is malformed")
            component["sha256"] = checksum
        if isinstance(source, str) and source.startswith("registry+") and checksum is None:
            raise IntegrityError("Cargo registry package lacks a checksum")
        components.append(component)
    for relative in SOURCE_LOCK_FILES[1:]:
        try:
            lock = json.loads(blobs[relative].decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise IntegrityError(f"npm lockfile is not valid UTF-8 JSON: {relative}") from error
        npm_packages = lock.get("packages") if isinstance(lock, dict) else None
        if (
            not isinstance(lock, dict)
            or lock.get("lockfileVersion") != 3
            or not isinstance(npm_packages, dict)
        ):
            raise IntegrityError(f"npm lockfile does not use package-lock v3: {relative}")
        for location, package in npm_packages.items():
            if location == "":
                continue
            if not isinstance(location, str) or not isinstance(package, dict):
                raise IntegrityError(f"npm package inventory is malformed: {relative}")
            locked_version = package.get("version")
            integrity = package.get("integrity")
            if not isinstance(locked_version, str) or not isinstance(integrity, str):
                raise IntegrityError(f"npm package identity is incomplete: {relative}")
            if len(integrity) > 4096:
                raise IntegrityError(f"npm package integrity is too long: {relative}")
            development = package.get("dev", False)
            if not isinstance(development, bool):
                raise IntegrityError(f"npm package development flag is malformed: {relative}")
            components.append(
                {
                    "development": development,
                    "ecosystem": "npm",
                    "integrity": _single_line("npm package integrity", integrity),
                    "lockfile": relative,
                    "location": _single_line("npm package location", location),
                    "name": _npm_package_name(location, package),
                    "version": _single_line("npm package version", locked_version),
                }
            )
    if not components or len(components) > MAX_SOURCE_COMPONENTS:
        raise IntegrityError("source dependency inventory has an invalid component count")
    components.sort(
        key=lambda component: (
            component["ecosystem"],
            component["name"],
            component["version"],
            component.get("lockfile", ""),
            component.get("location", ""),
            component.get("source", ""),
        )
    )
    manifests = [
        {"path": relative, "sha256": _sha256_bytes(blobs[relative])}
        for relative in SOURCE_LOCK_FILES
    ]
    return {
        "commit": commit,
        "component_count": len(components),
        "components": components,
        "manifests": manifests,
        "schema": "CMFD_SOURCE_DEPENDENCY_SBOM_V1",
        "scope": "source-lockfiles",
        "source_tree": _run_git(repo, "rev-parse", "HEAD^{tree}").lower(),
        "version": _single_line("version", version),
    }


def _expected_release_provenance(
    *, buildinfo: dict[str, object], source_sbom_bytes: bytes
) -> dict[str, object]:
    artifacts = buildinfo["artifacts"]
    if not isinstance(artifacts, list):
        raise IntegrityError("release artifact inventory is malformed")
    subjects = [
        {"digest": {"sha256": artifact["sha256"]}, "name": artifact["name"]}
        for artifact in artifacts
    ]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {
            "inventorySha256": buildinfo["inventory_sha256"],
            "source": {
                "digest": {
                    "gitCommit": buildinfo["commit"],
                    "gitTree": buildinfo["source_tree"],
                },
                "uri": "git+https://github.com/Common-Foundry-1/CommonFoundry.git",
            },
            "sourceDateEpoch": buildinfo["source_date_epoch"],
            "sourceSbom": {
                "digest": {"sha256": _sha256_bytes(source_sbom_bytes)},
                "name": SOURCE_SBOM_NAME,
            },
            "tool": {
                "digest": {"sha256": buildinfo["finalizer_sha256"]},
                "name": "scripts/release_integrity.py",
            },
            "version": buildinfo["version"],
        },
        "predicateType": "https://commonfoundry.org/attestations/release-assembly/v1",
        "subject": subjects,
    }


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


def _checksum_bytes(
    assets: dict[str, Path], generated_files: dict[str, bytes]
) -> bytes:
    rows = {name: _sha256_file(path) for name, path in assets.items()}
    rows.update(
        {name: _sha256_bytes(data) for name, data in generated_files.items()}
    )
    return ("".join(f"{rows[name]}  {name}\n" for name in sorted(rows))).encode("utf-8")


def _read_bounded_generated_file(path: Path, label: str, maximum: int) -> bytes:
    with _stable_regular_handle(path, label) as (_, handle, opened):
        if opened.st_size > maximum:
            raise IntegrityError(f"{label} exceeds its size limit")
        return handle.read(maximum + 1)


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


def _checksum_manifest(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise IntegrityError("SHA256SUMS.txt is not UTF-8") from error
    if not data or b"\r" in data or not data.endswith(b"\n"):
        raise IntegrityError("SHA256SUMS.txt is not canonical LF-terminated text")
    rows: dict[str, str] = {}
    names = []
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00-\x1f\x7f]+)", line)
        if match is None:
            raise IntegrityError("SHA256SUMS.txt has a malformed row")
        digest, name = match.groups()
        safe = _safe_repo_relative(name)
        if safe != name or "/" in safe:
            raise IntegrityError("SHA256SUMS.txt contains a non-flat asset name")
        if name in rows:
            raise IntegrityError("SHA256SUMS.txt contains a duplicate asset")
        rows[name] = digest
        names.append(name)
    if names != sorted(names):
        raise IntegrityError("SHA256SUMS.txt rows are not sorted")
    return rows


def _authenticated_download_buildinfo(
    *, stage_files: dict[str, Path], checksum_rows: dict[str, str]
) -> tuple[dict[str, object], bytes]:
    buildinfo, buildinfo_bytes = _read_buildinfo(stage_files[BUILDINFO_NAME])
    expected_fields = {
        "artifact_count",
        "artifacts",
        "commit",
        "finalizer_sha256",
        "inventory_sha256",
        "schema",
        "source_date_epoch",
        "source_tree",
        "version",
    }
    _require_exact_fields(buildinfo, expected_fields, BUILDINFO_NAME)
    if buildinfo["schema"] != BUILDINFO_SCHEMA:
        raise IntegrityError("BUILDINFO.json schema is unsupported")
    commit = _full_commit(buildinfo["commit"])
    source_tree = buildinfo["source_tree"]
    if not isinstance(source_tree, str) or not FULL_COMMIT_RE.fullmatch(source_tree):
        raise IntegrityError("BUILDINFO.json source tree is malformed")
    for field in ("finalizer_sha256", "inventory_sha256"):
        if not isinstance(buildinfo[field], str) or not HEX256_RE.fullmatch(
            buildinfo[field]
        ):
            raise IntegrityError(f"BUILDINFO.json {field} is malformed")
    epoch = buildinfo["source_date_epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise IntegrityError("BUILDINFO.json source epoch is malformed")
    version = buildinfo["version"]
    if not isinstance(version, str):
        raise IntegrityError("BUILDINFO.json version is malformed")
    _single_line("BUILDINFO.json version", version)
    artifacts = buildinfo["artifacts"]
    count = buildinfo["artifact_count"]
    if (
        not isinstance(artifacts, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(artifacts)
        or count < 1
        or count > MAX_ARCHIVE_MEMBERS
    ):
        raise IntegrityError("BUILDINFO.json artifact count is malformed")
    expected_asset_names = set(checksum_rows) - {
        BUILDINFO_NAME,
        SOURCE_SBOM_NAME,
        PROVENANCE_NAME,
    }
    artifact_names = []
    for artifact in artifacts:
        row = _require_exact_fields(
            artifact, {"name", "sha256", "size"}, "BUILDINFO.json artifact"
        )
        name = row["name"]
        digest = row["sha256"]
        size = row["size"]
        if not isinstance(name, str) or _safe_repo_relative(name) != name or "/" in name:
            raise IntegrityError("BUILDINFO.json artifact name is malformed")
        if not isinstance(digest, str) or not HEX256_RE.fullmatch(digest):
            raise IntegrityError("BUILDINFO.json artifact digest is malformed")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > (1 << 63) - 1
        ):
            raise IntegrityError("BUILDINFO.json artifact size is malformed")
        if checksum_rows.get(name) != digest:
            raise IntegrityError("BUILDINFO.json artifact digest is not in SHA256SUMS.txt")
        artifact_names.append(name)
    if artifact_names != sorted(set(artifact_names)):
        raise IntegrityError("BUILDINFO.json artifacts are not sorted and unique")
    if set(artifact_names) != expected_asset_names:
        raise IntegrityError("BUILDINFO.json artifact inventory is incomplete")
    buildinfo["commit"] = commit
    return buildinfo, buildinfo_bytes


def verify_release_signature(
    *,
    stage: Path,
    allowed_signers: Path,
    signer_identity: str,
    ssh_keygen: Path,
) -> dict[str, object]:
    """Verify the canonical checksum file with an explicitly trusted SSH signer."""

    stage = _regular_directory(stage, "release staging path")
    if not SIGNER_IDENTITY_RE.fullmatch(signer_identity):
        raise IntegrityError("release signer identity is malformed")
    verifier = _regular_file(ssh_keygen, "OpenSSH signature verifier")
    allowed = _regular_file(allowed_signers, "trusted release signer policy")
    signature = _regular_file(
        stage / CHECKSUM_SIGNATURE_NAME, "release checksum signature"
    )
    with _stable_regular_handle(
        stage / CHECKSUM_NAME, "release checksum file"
    ) as (_, checksum_handle, checksum_stat):
        if checksum_stat.st_size > MAX_CHECKSUM_BYTES:
            raise IntegrityError("release checksum file exceeds its size limit")
        checksum = checksum_handle.read(MAX_CHECKSUM_BYTES + 1)
    with _stable_regular_handle(signature, "release checksum signature") as (
        _,
        signature_handle,
        signature_stat,
    ):
        if signature_stat.st_size > MAX_RELEASE_SIGNATURE_BYTES:
            raise IntegrityError("release checksum signature exceeds its size limit")
        signature_bytes = signature_handle.read(MAX_RELEASE_SIGNATURE_BYTES + 1)
    with _stable_regular_handle(allowed, "trusted release signer policy") as (
        _,
        allowed_handle,
        allowed_stat,
    ):
        if allowed_stat.st_size > MAX_ALLOWED_SIGNERS_BYTES:
            raise IntegrityError("trusted release signer policy exceeds its size limit")
        allowed_bytes = allowed_handle.read(MAX_ALLOWED_SIGNERS_BYTES + 1)
    verifier_sha256 = _sha256_file(verifier)
    try:
        with tempfile.TemporaryDirectory(prefix="cmfd-release-signature-") as directory:
            verification_directory = Path(directory)
            allowed_copy = verification_directory / "allowed_signers"
            signature_copy = verification_directory / CHECKSUM_SIGNATURE_NAME
            _write_new(allowed_copy, allowed_bytes)
            _write_new(signature_copy, signature_bytes)
            completed = subprocess.run(
                [
                    str(verifier),
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed_copy),
                    "-I",
                    signer_identity,
                    "-n",
                    RELEASE_SIGNATURE_NAMESPACE,
                    "-s",
                    str(signature_copy),
                ],
                cwd=stage,
                input=checksum,
                check=False,
                capture_output=True,
                timeout=30,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IntegrityError("release signature verifier could not run") from error
    if _sha256_file(verifier) != verifier_sha256:
        raise IntegrityError("release signature verifier changed during verification")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise IntegrityError(f"release checksum signature is invalid: {detail}")
    return {
        "allowed_signers_sha256": _sha256_bytes(allowed_bytes),
        "checksum_sha256": _sha256_bytes(checksum),
        "namespace": RELEASE_SIGNATURE_NAMESPACE,
        "signature_sha256": _sha256_bytes(signature_bytes),
        "signer_identity": signer_identity,
        "verifier_sha256": verifier_sha256,
    }


def verify_signed_download(
    *,
    stage: Path,
    allowed_signers: Path,
    signer_identity: str,
    ssh_keygen: Path,
) -> dict[str, object]:
    """Authenticate a complete binary release without requiring source access."""

    stage = _regular_directory(stage, "downloaded release directory")
    signature = verify_release_signature(
        stage=stage,
        allowed_signers=allowed_signers,
        signer_identity=signer_identity,
        ssh_keygen=ssh_keygen,
    )
    checksum_bytes = _read_bounded_generated_file(
        stage / CHECKSUM_NAME, CHECKSUM_NAME, MAX_CHECKSUM_BYTES
    )
    if _sha256_bytes(checksum_bytes) != signature["checksum_sha256"]:
        raise IntegrityError("release checksum changed after signature verification")
    checksum_rows = _checksum_manifest(checksum_bytes)
    generated = {BUILDINFO_NAME, SOURCE_SBOM_NAME, PROVENANCE_NAME}
    if not generated.issubset(checksum_rows):
        raise IntegrityError("signed release checksum omits required release evidence")
    if CHECKSUM_NAME in checksum_rows or CHECKSUM_SIGNATURE_NAME in checksum_rows:
        raise IntegrityError("signed release checksum includes recursive metadata")
    stage_files = _stage_files(stage)
    expected_files = set(checksum_rows) | {CHECKSUM_NAME, CHECKSUM_SIGNATURE_NAME}
    if set(stage_files) != expected_files:
        missing = sorted(expected_files - set(stage_files))
        unexpected = sorted(set(stage_files) - expected_files)
        raise IntegrityError(
            f"signed release inventory mismatch; missing={missing}, unexpected={unexpected}"
        )
    file_rows = []
    file_sizes: dict[str, int] = {}
    for name in sorted(checksum_rows):
        size, digest = _sha256_file_with_size(
            stage_files[name], f"signed release file {name}"
        )
        if digest != checksum_rows[name]:
            raise IntegrityError(f"signed release file digest is invalid: {name}")
        file_sizes[name] = size
        file_rows.append({"name": name, "sha256": digest, "size": size})
    buildinfo, _ = _authenticated_download_buildinfo(
        stage_files=stage_files, checksum_rows=checksum_rows
    )
    for artifact in buildinfo["artifacts"]:
        if file_sizes[artifact["name"]] != artifact["size"]:
            raise IntegrityError("BUILDINFO.json artifact size does not match its file")
    source_sbom_bytes = _read_bounded_generated_file(
        stage_files[SOURCE_SBOM_NAME], SOURCE_SBOM_NAME, MAX_SOURCE_SBOM_BYTES
    )
    try:
        source_sbom = _json_object_bytes(source_sbom_bytes, SOURCE_SBOM_NAME)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrityError("SOURCE-SBOM.json is not valid UTF-8 JSON") from error
    if _canonical_json(source_sbom) != source_sbom_bytes:
        raise IntegrityError("SOURCE-SBOM.json is not canonical JSON")
    components = source_sbom.get("components")
    if (
        source_sbom.get("schema") != "CMFD_SOURCE_DEPENDENCY_SBOM_V1"
        or source_sbom.get("scope") != "source-lockfiles"
        or source_sbom.get("commit") != buildinfo["commit"]
        or source_sbom.get("source_tree") != buildinfo["source_tree"]
        or source_sbom.get("version") != buildinfo["version"]
        or not isinstance(components, list)
        or source_sbom.get("component_count") != len(components)
        or len(components) > MAX_SOURCE_COMPONENTS
    ):
        raise IntegrityError("SOURCE-SBOM.json identity is inconsistent")
    provenance_bytes = _read_bounded_generated_file(
        stage_files[PROVENANCE_NAME], PROVENANCE_NAME, MAX_PROVENANCE_BYTES
    )
    expected_provenance = _canonical_json(
        _expected_release_provenance(
            buildinfo=buildinfo, source_sbom_bytes=source_sbom_bytes
        )
    )
    if provenance_bytes != expected_provenance:
        raise IntegrityError("PROVENANCE.intoto.jsonl is inconsistent")
    if _sha256_file(stage / CHECKSUM_NAME) != signature["checksum_sha256"]:
        raise IntegrityError("release checksum changed during download verification")
    if _sha256_file(stage / CHECKSUM_SIGNATURE_NAME) != signature["signature_sha256"]:
        raise IntegrityError("release signature changed during download verification")
    if _sha256_file(allowed_signers) != signature["allowed_signers_sha256"]:
        raise IntegrityError("trusted release signer policy changed during verification")
    if _sha256_file(ssh_keygen) != signature["verifier_sha256"]:
        raise IntegrityError("release signature verifier changed during verification")
    return {
        "commit": buildinfo["commit"],
        "file_count": len(file_rows),
        "files": file_rows,
        "schema": "CMFD_AUTHENTICATED_DOWNLOAD_V1",
        "signature": signature,
        "source_tree": buildinfo["source_tree"],
        "version": buildinfo["version"],
    }


def _verify_release(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    stage: Path,
    inventory: Path,
    source_date_epoch: str | int | None,
    required_generated_files: frozenset[str] = frozenset(),
    activation_ssh_keygen: Path | None = None,
    activation_ssh_keygen_sha256: str | None = None,
) -> tuple[dict[str, object], str]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    epoch = _source_date_epoch(repo, source_date_epoch)
    inventory = _tracked_input_file(repo, inventory, "release inventory")
    names, inventory_data = _inventory_names(inventory)
    stage_files = _stage_files(stage)
    validate_production_rc_artifacts(
        version=version,
        commit=commit,
        stage_files=stage_files,
        repo=repo,
        activation_ssh_keygen=activation_ssh_keygen,
        activation_ssh_keygen_sha256=activation_ssh_keygen_sha256,
    )
    validate_production_rc_source_versions(repo=repo, version=version)
    if not required_generated_files.issubset({CHECKSUM_SIGNATURE_NAME}):
        raise IntegrityError("unsupported generated release file requirement")
    expected_names = set(names) | {
        BUILDINFO_NAME,
        SOURCE_SBOM_NAME,
        PROVENANCE_NAME,
        CHECKSUM_NAME,
        *required_generated_files,
    }
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
    source_sbom_bytes = _canonical_json(
        _expected_source_sbom(repo=repo, commit=commit, version=version)
    )
    actual_source_sbom = _read_bounded_generated_file(
        stage_files[SOURCE_SBOM_NAME], SOURCE_SBOM_NAME, MAX_SOURCE_SBOM_BYTES
    )
    if actual_source_sbom != source_sbom_bytes:
        raise IntegrityError("SOURCE-SBOM.json does not match the tracked lockfiles")
    provenance_bytes = _canonical_json(
        _expected_release_provenance(
            buildinfo=expected_info, source_sbom_bytes=source_sbom_bytes
        )
    )
    actual_provenance = _read_bounded_generated_file(
        stage_files[PROVENANCE_NAME], PROVENANCE_NAME, MAX_PROVENANCE_BYTES
    )
    if actual_provenance != provenance_bytes:
        raise IntegrityError(
            "PROVENANCE.intoto.jsonl does not match the release assembly"
        )
    with _stable_regular_handle(
        stage_files[CHECKSUM_NAME], "release checksum file"
    ) as (_, checksum_handle, checksum_stat):
        if checksum_stat.st_size > MAX_CHECKSUM_BYTES:
            raise IntegrityError("release checksum file exceeds its size limit")
        checksum_bytes = checksum_handle.read(MAX_CHECKSUM_BYTES + 1)
    expected_checksums = _checksum_bytes(
        assets,
        {
            BUILDINFO_NAME: buildinfo_bytes,
            PROVENANCE_NAME: provenance_bytes,
            SOURCE_SBOM_NAME: source_sbom_bytes,
        },
    )
    if checksum_bytes != expected_checksums:
        raise IntegrityError(
            "SHA256SUMS.txt is noncanonical or does not match the artifacts"
        )
    return expected_info, _sha256_bytes(checksum_bytes)


def verify_release(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    stage: Path,
    inventory: Path,
    source_date_epoch: str | int | None,
    required_generated_files: frozenset[str] = frozenset(),
    activation_ssh_keygen: Path | None = None,
    activation_ssh_keygen_sha256: str | None = None,
) -> dict[str, object]:
    release, _ = _verify_release(
        repo=repo,
        expected_commit=expected_commit,
        version=version,
        stage=stage,
        inventory=inventory,
        source_date_epoch=source_date_epoch,
        required_generated_files=required_generated_files,
        activation_ssh_keygen=activation_ssh_keygen,
        activation_ssh_keygen_sha256=activation_ssh_keygen_sha256,
    )
    return release


def verify_signed_release(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    stage: Path,
    inventory: Path,
    source_date_epoch: str | int | None,
    allowed_signers: Path,
    signer_identity: str,
    ssh_keygen: Path,
    activation_ssh_keygen: Path | None = None,
    activation_ssh_keygen_sha256: str | None = None,
) -> dict[str, object]:
    release, checksum_sha256 = _verify_release(
        repo=repo,
        expected_commit=expected_commit,
        version=version,
        stage=stage,
        inventory=inventory,
        source_date_epoch=source_date_epoch,
        required_generated_files=frozenset({CHECKSUM_SIGNATURE_NAME}),
        activation_ssh_keygen=activation_ssh_keygen,
        activation_ssh_keygen_sha256=activation_ssh_keygen_sha256,
    )
    signature = verify_release_signature(
        stage=stage,
        allowed_signers=allowed_signers,
        signer_identity=signer_identity,
        ssh_keygen=ssh_keygen,
    )
    if signature["checksum_sha256"] != checksum_sha256:
        raise IntegrityError("release checksum changed during signed verification")
    return {"release": release, "signature": signature}


def compare_reproducible_releases(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    first_stage: Path,
    second_stage: Path,
    inventory: Path,
    source_date_epoch: str | int | None,
    activation_ssh_keygen: Path | None = None,
    activation_ssh_keygen_sha256: str | None = None,
) -> dict[str, object]:
    """Require two independently staged releases to be byte-identical."""

    first_stage = _regular_directory(first_stage, "first independent release stage")
    second_stage = _regular_directory(second_stage, "second independent release stage")
    if os.path.samefile(first_stage, second_stage):
        raise IntegrityError("independent release stages must be different directories")
    common = {
        "repo": repo,
        "expected_commit": expected_commit,
        "version": version,
        "inventory": inventory,
        "source_date_epoch": source_date_epoch,
        "activation_ssh_keygen": activation_ssh_keygen,
        "activation_ssh_keygen_sha256": activation_ssh_keygen_sha256,
    }
    first_release = verify_release(stage=first_stage, **common)
    second_release = verify_release(stage=second_stage, **common)
    first_files = _stage_files(first_stage)
    second_files = _stage_files(second_stage)
    if set(first_files) != set(second_files):
        raise IntegrityError("independent release file inventories differ")
    rows = []
    generated = {
        BUILDINFO_NAME,
        SOURCE_SBOM_NAME,
        PROVENANCE_NAME,
        CHECKSUM_NAME,
    }
    ordered_names = sorted(
        first_files, key=lambda candidate: (candidate in generated, candidate)
    )
    for name in ordered_names:
        with _stable_regular_handle(
            first_files[name], f"first independent release file {name}"
        ) as (_, first_handle, first_stat):
            with _stable_regular_handle(
                second_files[name], f"second independent release file {name}"
            ) as (_, second_handle, second_stat):
                if first_stat.st_size != second_stat.st_size:
                    raise IntegrityError(
                        f"independent release file differs in size: {name}"
                    )
                digest = hashlib.sha256()
                while True:
                    first_chunk = first_handle.read(1024 * 1024)
                    second_chunk = second_handle.read(1024 * 1024)
                    if first_chunk != second_chunk:
                        raise IntegrityError(
                            f"independent release file differs in content: {name}"
                        )
                    if not first_chunk:
                        break
                    digest.update(first_chunk)
        rows.append(
            {"name": name, "sha256": digest.hexdigest(), "size": first_stat.st_size}
        )
    if first_release != second_release:
        raise IntegrityError("independent release build metadata differs")
    return {
        "commit": first_release["commit"],
        "file_count": len(rows),
        "files": rows,
        "reproducible": True,
        "schema": REPRODUCIBLE_COMPARISON_SCHEMA,
        "version": first_release["version"],
    }


def finalize_release(
    *,
    repo: Path,
    expected_commit: str,
    version: str,
    stage: Path,
    inventory: Path,
    source_date_epoch: str | int | None,
    activation_ssh_keygen: Path | None = None,
    activation_ssh_keygen_sha256: str | None = None,
) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    commit = _assert_clean_exact_repo(repo, expected_commit)
    epoch = _source_date_epoch(repo, source_date_epoch)
    inventory = _tracked_input_file(repo, inventory, "release inventory")
    names, inventory_data = _inventory_names(inventory)
    stage_files = _stage_files(stage)
    validate_production_rc_artifacts(
        version=version,
        commit=commit,
        stage_files=stage_files,
        repo=repo,
        activation_ssh_keygen=activation_ssh_keygen,
        activation_ssh_keygen_sha256=activation_ssh_keygen_sha256,
    )
    validate_production_rc_source_versions(repo=repo, version=version)
    generated_names = {
        BUILDINFO_NAME,
        SOURCE_SBOM_NAME,
        PROVENANCE_NAME,
        CHECKSUM_NAME,
        CHECKSUM_SIGNATURE_NAME,
    }
    if generated_names.intersection(stage_files):
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
    source_sbom_bytes = _canonical_json(
        _expected_source_sbom(repo=repo, commit=commit, version=version)
    )
    if len(source_sbom_bytes) > MAX_SOURCE_SBOM_BYTES:
        raise IntegrityError("SOURCE-SBOM.json exceeds its size limit")
    provenance_bytes = _canonical_json(
        _expected_release_provenance(
            buildinfo=buildinfo, source_sbom_bytes=source_sbom_bytes
        )
    )
    if len(provenance_bytes) > MAX_PROVENANCE_BYTES:
        raise IntegrityError("PROVENANCE.intoto.jsonl exceeds its size limit")
    generated_files = {
        BUILDINFO_NAME: buildinfo_bytes,
        PROVENANCE_NAME: provenance_bytes,
        SOURCE_SBOM_NAME: source_sbom_bytes,
    }
    checksum_bytes = _checksum_bytes(assets, generated_files)
    written: list[Path] = []
    try:
        for name, data in generated_files.items():
            path = stage / name
            _write_new(path, data)
            written.append(path)
        _write_new(stage / CHECKSUM_NAME, checksum_bytes)
        written.append(stage / CHECKSUM_NAME)
    except Exception:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    return verify_release(
        repo=repo,
        expected_commit=commit,
        version=version,
        stage=stage,
        inventory=inventory,
        source_date_epoch=epoch,
        activation_ssh_keygen=activation_ssh_keygen,
        activation_ssh_keygen_sha256=activation_ssh_keygen_sha256,
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
    parser.add_argument("--activation-ssh-keygen", type=Path)
    parser.add_argument("--activation-ssh-keygen-sha256")


def _add_production_v4_activation_inputs(parser: argparse.ArgumentParser) -> None:
    _add_repo_arguments(parser)
    parser.add_argument("--phase", choices=("pin", "evidence"), required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--qualification-manifest", type=Path, required=True)
    parser.add_argument("--verifier-report", type=Path, required=True)
    parser.add_argument("--verifier-script", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--model-bank", type=Path, required=True)
    parser.add_argument("--fixed-record", type=Path, required=True)
    parser.add_argument("--artifact-directory", type=Path, required=True)
    parser.add_argument("--network-info", type=Path)


def _add_production_v4_approval_trust(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--producer-allowed-signers", type=Path, required=True)
    parser.add_argument("--producer-signer-identity", required=True)
    parser.add_argument("--reproducer-allowed-signers", type=Path, required=True)
    parser.add_argument("--reproducer-signer-identity", required=True)
    parser.add_argument("--ssh-keygen", type=Path, required=True)
    parser.add_argument("--expected-ssh-keygen-sha256", required=True)


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
    runtime_attestation.add_argument("--expected-version")
    runtime_attestation.add_argument("--output", type=Path, required=True)

    runtime_package = commands.add_parser(
        "runtime-package",
        help="assemble and attest one native ProductionV4 RC runtime package",
    )
    _add_repo_arguments(runtime_package)
    runtime_package.add_argument("--version", required=True)
    runtime_package.add_argument(
        "--platform", choices=("windows-x86_64", "linux-x86_64"), required=True
    )
    runtime_package.add_argument("--node", type=Path, required=True)
    runtime_package.add_argument("--wallet", type=Path, required=True)
    runtime_package.add_argument("--model-bank", type=Path, required=True)
    runtime_package.add_argument("--fixed-record", type=Path, required=True)
    runtime_package.add_argument("--output-directory", type=Path, required=True)
    runtime_package.add_argument("--source-date-epoch")

    production_v4_activation = commands.add_parser(
        "production-v4-activation",
        help="render a reviewed ProductionV4 source pin or final activation evidence",
    )
    _add_production_v4_activation_inputs(production_v4_activation)
    _add_production_v4_approval_trust(production_v4_activation)
    production_v4_activation.add_argument(
        "--producer-approval", type=Path, required=True
    )
    production_v4_activation.add_argument(
        "--producer-signature", type=Path, required=True
    )
    production_v4_activation.add_argument(
        "--reproducer-approval", type=Path, required=True
    )
    production_v4_activation.add_argument(
        "--reproducer-signature", type=Path, required=True
    )
    production_v4_activation.add_argument("--output", type=Path, required=True)

    production_v4_approval_request = commands.add_parser(
        "production-v4-approval-request",
        help="derive create-new ProductionV4 approval payloads without activating",
    )
    _add_production_v4_activation_inputs(production_v4_approval_request)
    _add_production_v4_approval_trust(production_v4_approval_request)
    production_v4_approval_request.add_argument(
        "--output-directory", type=Path, required=True
    )

    finalize = commands.add_parser(
        "finalize", help="generate and re-verify canonical release metadata"
    )
    _add_release_common(finalize)

    verify = commands.add_parser(
        "verify", help="re-verify canonical release metadata and assets"
    )
    _add_release_common(verify)
    verify_signed = commands.add_parser(
        "verify-signed", help="verify release metadata, assets, and trusted signature"
    )
    _add_release_common(verify_signed)
    verify_signed.add_argument("--allowed-signers", type=Path, required=True)
    verify_signed.add_argument("--signer-identity", required=True)
    verify_signed.add_argument("--ssh-keygen", type=Path, required=True)
    verify_download = commands.add_parser(
        "verify-download",
        help="authenticate a complete release without a source checkout",
    )
    verify_download.add_argument("--stage", type=Path, required=True)
    verify_download.add_argument("--allowed-signers", type=Path, required=True)
    verify_download.add_argument("--signer-identity", required=True)
    verify_download.add_argument("--ssh-keygen", type=Path, required=True)
    compare = commands.add_parser(
        "compare", help="verify and compare two independent release stages"
    )
    _add_repo_arguments(compare)
    compare.add_argument("--version", required=True)
    compare.add_argument("--first-stage", type=Path, required=True)
    compare.add_argument("--second-stage", type=Path, required=True)
    compare.add_argument("--inventory", type=Path, required=True)
    compare.add_argument("--source-date-epoch")
    compare.add_argument("--activation-ssh-keygen", type=Path)
    compare.add_argument("--activation-ssh-keygen-sha256")
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
                version=args.expected_version,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "runtime-package":
            result = create_production_v4_runtime_package(
                repo=args.repo,
                expected_commit=args.expected_commit,
                version=args.version,
                platform=args.platform,
                node=args.node,
                wallet=args.wallet,
                model_bank=args.model_bank,
                fixed_record=args.fixed_record,
                output_directory=args.output_directory,
                source_date_epoch=args.source_date_epoch,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "production-v4-activation":
            result = create_production_v4_activation(
                phase=args.phase,
                repo=args.repo,
                expected_commit=args.expected_commit,
                candidate=args.candidate,
                input_manifest=args.input_manifest,
                qualification_manifest=args.qualification_manifest,
                verifier_report=args.verifier_report,
                verifier_script=args.verifier_script,
                template=args.template,
                proof=args.proof,
                model_bank=args.model_bank,
                fixed_record=args.fixed_record,
                artifact_directory=args.artifact_directory,
                output=args.output,
                network_info=args.network_info,
                producer_approval=args.producer_approval,
                producer_signature=args.producer_signature,
                producer_allowed_signers=args.producer_allowed_signers,
                producer_signer_identity=args.producer_signer_identity,
                reproducer_approval=args.reproducer_approval,
                reproducer_signature=args.reproducer_signature,
                reproducer_allowed_signers=args.reproducer_allowed_signers,
                reproducer_signer_identity=args.reproducer_signer_identity,
                ssh_keygen=args.ssh_keygen,
                expected_ssh_keygen_sha256=args.expected_ssh_keygen_sha256,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "production-v4-approval-request":
            result = create_production_v4_activation_approval_request(
                phase=args.phase,
                repo=args.repo,
                expected_commit=args.expected_commit,
                candidate=args.candidate,
                input_manifest=args.input_manifest,
                qualification_manifest=args.qualification_manifest,
                verifier_report=args.verifier_report,
                verifier_script=args.verifier_script,
                template=args.template,
                proof=args.proof,
                model_bank=args.model_bank,
                fixed_record=args.fixed_record,
                artifact_directory=args.artifact_directory,
                output_directory=args.output_directory,
                network_info=args.network_info,
                producer_allowed_signers=args.producer_allowed_signers,
                producer_signer_identity=args.producer_signer_identity,
                reproducer_allowed_signers=args.reproducer_allowed_signers,
                reproducer_signer_identity=args.reproducer_signer_identity,
                ssh_keygen=args.ssh_keygen,
                expected_ssh_keygen_sha256=args.expected_ssh_keygen_sha256,
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
                activation_ssh_keygen=args.activation_ssh_keygen,
                activation_ssh_keygen_sha256=args.activation_ssh_keygen_sha256,
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
                activation_ssh_keygen=args.activation_ssh_keygen,
                activation_ssh_keygen_sha256=args.activation_ssh_keygen_sha256,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "verify-signed":
            result = verify_signed_release(
                repo=args.repo,
                expected_commit=args.expected_commit,
                version=args.version,
                stage=args.stage,
                inventory=args.inventory,
                source_date_epoch=args.source_date_epoch,
                allowed_signers=args.allowed_signers,
                signer_identity=args.signer_identity,
                ssh_keygen=args.ssh_keygen,
                activation_ssh_keygen=args.activation_ssh_keygen,
                activation_ssh_keygen_sha256=args.activation_ssh_keygen_sha256,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "verify-download":
            result = verify_signed_download(
                stage=args.stage,
                allowed_signers=args.allowed_signers,
                signer_identity=args.signer_identity,
                ssh_keygen=args.ssh_keygen,
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "compare":
            result = compare_reproducible_releases(
                repo=args.repo,
                expected_commit=args.expected_commit,
                version=args.version,
                first_stage=args.first_stage,
                second_stage=args.second_stage,
                inventory=args.inventory,
                source_date_epoch=args.source_date_epoch,
                activation_ssh_keygen=args.activation_ssh_keygen,
                activation_ssh_keygen_sha256=args.activation_ssh_keygen_sha256,
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
