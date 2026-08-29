#!/usr/bin/env python3
"""Run the independent ProductionV4 verification stages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from production_v4_independent_verifier import (
    VerificationError,
    parse_statement,
    parse_template,
    verify,
)
from production_v4_transcript import TranscriptVerificationError
from production_v4_wire import ConformanceError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--template", type=Path, help="existing miner template.json")
    inputs.add_argument(
        "--statement", type=Path, help="strict independent statement JSON"
    )
    parser.add_argument(
        "--proof", type=Path, required=True, help="transparent-proof.bin"
    )
    parser.add_argument(
        "--fixed-artifact-record",
        type=Path,
        help="trusted fixed-artifact record; enables transcript and algebra checks",
    )
    parser.add_argument(
        "--model-bank",
        type=Path,
        help="authenticated MODEL-V2.bank; enables public initial-boundary checks",
    )
    parser.add_argument(
        "--write-statement",
        type=Path,
        help="write the derived strict statement (template mode only)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the verification result as JSON"
    )
    args = parser.parse_args()

    if args.write_statement is not None and args.template is None:
        parser.error("--write-statement requires --template")

    try:
        if args.template is not None:
            block, candidate = parse_template(args.template)
            require_claims = False
        else:
            block, candidate = parse_statement(args.statement)
            require_claims = True
        result, statement = verify(
            args.proof,
            block,
            candidate,
            require_claims,
            args.fixed_artifact_record,
            args.model_bank,
        )
        if args.write_statement is not None:
            args.write_statement.write_text(
                json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
    except (
        OSError,
        ConformanceError,
        TranscriptVerificationError,
        VerificationError,
    ) as error:
        failure = {
            "schema": "CommonFoundry/ForgeMatrix/V4/IndependentVerificationResult/v1",
            "implemented_stages_accepted": False,
            "full_cryptographic_proof_verified": False,
            "error": str(error),
        }
        if args.json:
            print(json.dumps(failure, indent=2, sort_keys=True))
        else:
            print(f"REJECTED: {error}")
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        claim_scope = "and candidate claims " if require_claims else ""
        print(f"ACCEPTED: public bindings {claim_scope}match; target met")
        if args.fixed_artifact_record is not None:
            print("Independent transcript, relations, openings, and BaseFold: ACCEPTED")
        if result["full_cryptographic_proof_verified"]:
            print("Full cryptographic proof verification: ACCEPTED")
        else:
            print("Full cryptographic proof verification: INCOMPLETE")
            print("Remaining: " + "; ".join(result["remaining_stages"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
