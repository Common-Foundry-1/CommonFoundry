#!/usr/bin/env python3
"""Qualify the independent ProductionV4 verifier in fresh processes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from production_v4_reproduction import canonical_json, file_identity, write_new
from production_v4_wire import (
    BANK_BYTES,
    DIGEST_BYTES,
    FIELD_MODULUS,
    FINAL_ACTIVATION_BYTES,
    OPENING_BYTES,
    OUTER_HEADER_BYTES,
    RELATION_REPETITION_BYTES,
    RELATION_REPETITIONS,
    TRANSPARENT_PROOF_BYTES,
)


REPORT_SCHEMA = "CommonFoundry/ForgeMatrix/V4/IndependentVerifierQualification/v1"
FIXED_COMPONENT_PATH_OFFSET = 283_856
FIRST_FRI_QUERY_OFFSET = 715_888


class QualificationError(ValueError):
    """Raised when a fresh verifier process violates the qualification contract."""


def _opening_offset(bank: int = 0) -> int:
    bank_offset = OUTER_HEADER_BYTES + FINAL_ACTIVATION_BYTES + bank * BANK_BYTES
    return bank_offset + DIGEST_BYTES + RELATION_REPETITIONS * RELATION_REPETITION_BYTES


MUTATIONS = {
    "truncated": ("truncate", TRANSPARENT_PROOF_BYTES - 1),
    "trailing-byte": ("append", 0),
    "noncanonical-field": ("write", OUTER_HEADER_BYTES, FIELD_MODULUS),
    "final-activation": ("increment", OUTER_HEADER_BYTES),
    "relation-round": (
        "increment",
        OUTER_HEADER_BYTES + FINAL_ACTIVATION_BYTES + DIGEST_BYTES,
    ),
    "fixed-merkle-path": (
        "increment",
        _opening_offset() + FIXED_COMPONENT_PATH_OFFSET,
    ),
    "fri-query": ("increment", _opening_offset() + FIRST_FRI_QUERY_OFFSET),
    "grinding-witness": ("increment", _opening_offset() + OPENING_BYTES - 8),
}


def mutate_proof(source: Path, destination: Path, mutation: str) -> None:
    """Create exactly one named malformed proof without modifying the source."""

    if mutation not in MUTATIONS:
        raise QualificationError(f"unknown proof mutation {mutation}")
    action = MUTATIONS[mutation]
    shutil.copyfile(source, destination)
    if action[0] == "truncate":
        destination.write_bytes(destination.read_bytes()[: int(action[1])])
        return
    if action[0] == "append":
        with destination.open("ab") as target:
            target.write(bytes([int(action[1])]))
        return
    offset = int(action[1])
    with destination.open("r+b", buffering=0) as target:
        target.seek(offset)
        if action[0] == "write":
            value = int(action[2])
        else:
            encoded = target.read(4)
            if len(encoded) != 4:
                raise QualificationError(f"mutation offset is outside proof: {mutation}")
            value = (struct.unpack("<I", encoded)[0] + 1) % FIELD_MODULUS
            target.seek(offset)
        target.write(struct.pack("<I", value))


def _parse_result(completed: subprocess.CompletedProcess[str]) -> dict[str, object]:
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise QualificationError(
            f"verifier emitted non-JSON output: {completed.stdout[:200]!r}"
        ) from error
    if not isinstance(value, dict):
        raise QualificationError("verifier result must be a JSON object")
    return value


def _run_verifier(
    verifier: Path, arguments: list[str], *, expect_accept: bool
) -> tuple[dict[str, object], list[str]]:
    command = [sys.executable, str(verifier), *arguments, "--json"]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    result = _parse_result(completed)
    accepted = completed.returncode == 0
    if accepted != expect_accept:
        outcome = "accepted" if accepted else "rejected"
        raise QualificationError(
            f"fresh verifier process {outcome} unexpectedly: {result}"
        )
    if expect_accept:
        if result.get("implemented_stages_accepted") is not True:
            raise QualificationError("accepted verifier result omits implemented-stage success")
    elif (
        result.get("implemented_stages_accepted") is not False
        or result.get("full_cryptographic_proof_verified") is not False
        or not isinstance(result.get("error"), str)
    ):
        raise QualificationError("rejected verifier result is not fail-closed")
    return result, command


def qualify(
    *,
    verifier: Path,
    template: Path,
    proof: Path,
    fixed_record: Path,
    model_bank: Path,
    source_commit: str,
    operator: str,
) -> dict[str, object]:
    if not operator.strip():
        raise QualificationError("operator must not be empty")
    if len(source_commit) not in (40, 64) or any(
        character not in "0123456789abcdef" for character in source_commit
    ):
        raise QualificationError("source commit must be lowercase 40- or 64-hex")
    if proof.stat().st_size != TRANSPARENT_PROOF_BYTES:
        raise QualificationError("known-valid proof has the wrong exact length")

    with tempfile.TemporaryDirectory(prefix="cmfd-v4-verifier-qualification-") as temporary:
        root = Path(temporary)
        statement = root / "statement.json"
        derived, derive_command = _run_verifier(
            verifier,
            [
                "--template", str(template),
                "--proof", str(proof),
                "--write-statement", str(statement),
            ],
            expect_accept=True,
        )
        if derived.get("full_cryptographic_proof_verified") is not False:
            raise QualificationError("binding-only statement derivation reported full verification")
        valid, valid_command = _run_verifier(
            verifier,
            [
                "--statement", str(statement),
                "--proof", str(proof),
                "--fixed-artifact-record", str(fixed_record),
                "--model-bank", str(model_bank),
            ],
            expect_accept=True,
        )
        if (
            valid.get("full_cryptographic_proof_verified") is not True
            or valid.get("candidate_claims_verified") is not True
        ):
            raise QualificationError("known-valid proof did not pass full fresh-process verification")

        rejected = []
        for name in MUTATIONS:
            mutated = root / f"proof-{name}.bin"
            mutate_proof(proof, mutated, name)
            result, command = _run_verifier(
                verifier,
                [
                    "--statement", str(statement),
                    "--proof", str(mutated),
                    "--fixed-artifact-record", str(fixed_record),
                ],
                expect_accept=False,
            )
            rejected.append(
                {
                    "mutation": name,
                    "proof": file_identity(mutated),
                    "error": result["error"],
                    "command": command,
                }
            )

    verifier_files = [
        Path(__file__).resolve(),
        verifier,
        verifier.with_name("production_v4_independent_verifier.py"),
        verifier.with_name("production_v4_transcript.py"),
        verifier.with_name("production_v4_poseidon.py"),
        verifier.with_name("production_v4_wire.py"),
    ]
    return {
        "schema": REPORT_SCHEMA,
        "status": "verified",
        "source_commit": source_commit,
        "operator": operator.strip(),
        "fresh_process_verifier": True,
        "verifier_files": [file_identity(path) for path in verifier_files],
        "known_valid_proof": file_identity(proof),
        "statement_derivation": {
            "command": derive_command,
            "result": derived,
        },
        "known_valid_result": {
            "command": valid_command,
            "result": valid,
        },
        "mutation_rejections": rejected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--fixed-artifact-record", type=Path, required=True)
    parser.add_argument("--model-bank", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = qualify(
            verifier=args.verifier.resolve(),
            template=args.template.resolve(),
            proof=args.proof.resolve(),
            fixed_record=args.fixed_artifact_record.resolve(),
            model_bank=args.model_bank.resolve(),
            source_commit=args.source_commit,
            operator=args.operator,
        )
        encoded = write_new(args.output.resolve(), report)
    except (OSError, QualificationError, subprocess.SubprocessError, ValueError) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "status": "verified",
                "report": str(args.output.resolve()),
                "bytes": len(encoded),
                "sha256": hashlib.sha256(canonical_json(report)).hexdigest(),
                "mutations_rejected": len(report["mutation_rejections"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
