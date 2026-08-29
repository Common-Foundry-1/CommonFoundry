#!/usr/bin/env python3
"""Independent structural checker for a ProductionV4 transparent proof.

This intentionally does not import the Rust consensus implementation. It checks
the exact pinned layout and canonical field encodings. It does not perform
cryptographic proof verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import struct
import tempfile
from pathlib import Path


FIELD_MODULUS = 0x7F000001
OUTER_MAGIC = b"CMV4PF01"
OUTER_VERSION = 1
BANKS = 3
OUTER_HEADER_BYTES = 16
FINAL_ACTIVATION_BYTES = 2_097_152
DIGEST_BYTES = 32
RELATION_REPETITION_BYTES = 4_672
RELATION_REPETITIONS = 2
OPENING_MAGIC = b"CMV4BF01"
OPENING_VERSION = 1
OPENING_CLAIMS = 16
OPENING_HEADER_BYTES = 16
OPENING_BYTES = 3_300_008
BANK_BYTES = DIGEST_BYTES + RELATION_REPETITIONS * RELATION_REPETITION_BYTES + OPENING_BYTES
TRANSPARENT_PROOF_BYTES = OUTER_HEADER_BYTES + FINAL_ACTIVATION_BYTES + BANKS * BANK_BYTES


class ConformanceError(ValueError):
    """Raised when an input is not a canonical ProductionV4 proof encoding."""


def _u32(buffer: mmap.mmap, offset: int) -> int:
    return struct.unpack_from("<I", buffer, offset)[0]


def _require_header(
    buffer: mmap.mmap, offset: int, magic: bytes, version: int, count: int, label: str
) -> None:
    if buffer[offset : offset + 8] != magic:
        raise ConformanceError(f"{label}: invalid magic at byte {offset}")
    if _u32(buffer, offset + 8) != version:
        raise ConformanceError(f"{label}: unsupported version at byte {offset + 8}")
    if _u32(buffer, offset + 12) != count:
        raise ConformanceError(f"{label}: invalid count at byte {offset + 12}")


def _require_canonical_fields(buffer: mmap.mmap, start: int, end: int, label: str) -> int:
    if start % 4 != 0 or end < start or (end - start) % 4 != 0:
        raise ConformanceError(f"{label}: internal field range is not u32-aligned")
    count = 0
    view = memoryview(buffer)[start:end]
    try:
        for (value,) in struct.iter_unpack("<I", view):
            if value >= FIELD_MODULUS:
                offset = start + count * 4
                raise ConformanceError(
                    f"{label}: noncanonical KoalaBear field {value} at byte {offset}"
                )
            count += 1
    finally:
        view.release()
    return count


def inspect_proof(path: Path) -> dict[str, object]:
    size = path.stat().st_size
    if size != TRANSPARENT_PROOF_BYTES:
        raise ConformanceError(
            f"wrong exact length: got {size}, expected {TRANSPARENT_PROOF_BYTES}"
        )

    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        _require_header(data, 0, OUTER_MAGIC, OUTER_VERSION, BANKS, "transparent proof")
        field_count = _require_canonical_fields(
            data,
            OUTER_HEADER_BYTES,
            OUTER_HEADER_BYTES + FINAL_ACTIVATION_BYTES,
            "final activation",
        )
        banks: list[dict[str, int]] = []
        for bank in range(BANKS):
            bank_offset = OUTER_HEADER_BYTES + FINAL_ACTIVATION_BYTES + bank * BANK_BYTES
            relation_offset = bank_offset + DIGEST_BYTES
            opening_offset = relation_offset + RELATION_REPETITIONS * RELATION_REPETITION_BYTES
            _require_canonical_fields(data, bank_offset, relation_offset, f"bank {bank} commitment")
            _require_canonical_fields(data, relation_offset, opening_offset, f"bank {bank} relations")
            _require_header(
                data,
                opening_offset,
                OPENING_MAGIC,
                OPENING_VERSION,
                OPENING_CLAIMS,
                f"bank {bank} opening",
            )
            _require_canonical_fields(
                data,
                opening_offset + OPENING_HEADER_BYTES,
                opening_offset + OPENING_BYTES,
                f"bank {bank} opening payload",
            )
            banks.append(
                {
                    "bank": bank,
                    "offset": bank_offset,
                    "relations_offset": relation_offset,
                    "opening_offset": opening_offset,
                }
            )
        sha256 = hashlib.sha256(data).hexdigest()

    return {
        "schema": "CommonFoundry/ForgeMatrix/V4/WireConformanceResult/v1",
        "path": str(path.resolve()),
        "bytes": size,
        "sha256": sha256,
        "canonical": True,
        "cryptographically_verified": False,
        "final_activation_fields": field_count,
        "banks": banks,
    }


def _write_structural_fixture(path: Path) -> None:
    fixture = bytearray(TRANSPARENT_PROOF_BYTES)
    fixture[:8] = OUTER_MAGIC
    struct.pack_into("<II", fixture, 8, OUTER_VERSION, BANKS)
    for bank in range(BANKS):
        bank_offset = OUTER_HEADER_BYTES + FINAL_ACTIVATION_BYTES + bank * BANK_BYTES
        opening_offset = bank_offset + DIGEST_BYTES + RELATION_REPETITIONS * RELATION_REPETITION_BYTES
        fixture[opening_offset : opening_offset + 8] = OPENING_MAGIC
        struct.pack_into("<II", fixture, opening_offset + 8, OPENING_VERSION, OPENING_CLAIMS)
    path.write_bytes(fixture)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="cmfd-v4-wire-") as directory:
        fixture = Path(directory) / "structural-proof.bin"
        _write_structural_fixture(fixture)
        result = inspect_proof(fixture)
        if result["bytes"] != TRANSPARENT_PROOF_BYTES or not result["canonical"]:
            raise AssertionError("canonical structural fixture was not accepted")

        with fixture.open("r+b") as target:
            target.seek(OUTER_HEADER_BYTES)
            target.write(struct.pack("<I", FIELD_MODULUS))
        try:
            inspect_proof(fixture)
        except ConformanceError as error:
            if "noncanonical KoalaBear field" not in str(error):
                raise AssertionError(f"unexpected rejection: {error}") from error
        else:
            raise AssertionError("noncanonical field was accepted")

        with fixture.open("r+b") as target:
            target.seek(OUTER_HEADER_BYTES)
            target.write(b"\0\0\0\0")
            target.seek(0, os.SEEK_END)
            target.write(b"\0")
        try:
            inspect_proof(fixture)
        except ConformanceError as error:
            if "wrong exact length" not in str(error):
                raise AssertionError(f"unexpected rejection: {error}") from error
        else:
            raise AssertionError("trailing byte was accepted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proof", nargs="?", type=Path, help="transparent-proof.bin to inspect")
    parser.add_argument("--json", action="store_true", help="emit a JSON result")
    parser.add_argument("--self-test", action="store_true", help="run bounded positive/negative checks")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("ProductionV4 wire conformance self-test: PASS")
        return 0
    if args.proof is None:
        parser.error("proof is required unless --self-test is used")

    try:
        result = inspect_proof(args.proof)
    except (OSError, ConformanceError) as error:
        if args.json:
            print(json.dumps({"canonical": False, "error": str(error)}, sort_keys=True))
        else:
            print(f"NONCONFORMING: {error}")
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"CONFORMING: {result['bytes']} bytes, canonical fields and fixed topology; "
            "cryptographic verification not performed"
        )
        print(f"SHA-256: {result['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
