#!/usr/bin/env python3
"""Independent structural checker for a ProductionV4 transparent proof.

This intentionally does not import the Rust consensus implementation. It checks
the exact pinned layout and canonical field encodings. It does not perform
cryptographic proof verification.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import tempfile
from pathlib import Path

from production_v4_wire import (
    ConformanceError,
    FIELD_MODULUS,
    OUTER_HEADER_BYTES,
    TRANSPARENT_PROOF_BYTES,
    inspect_proof,
    write_structural_fixture,
)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="cmfd-v4-wire-") as directory:
        fixture = Path(directory) / "structural-proof.bin"
        write_structural_fixture(fixture)
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
