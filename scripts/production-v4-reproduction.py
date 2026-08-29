#!/usr/bin/env python3
"""Verify and record a ProductionV4 independent reproduction."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from production_v4_reproduction import (
    ReproductionError,
    build_report,
    canonical_json,
    write_new,
)
from production_v4_independent_verifier import VerificationError
from production_v4_transcript import TranscriptVerificationError
from production_v4_wire import ConformanceError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--model-bank", type=Path, required=True)
    parser.add_argument("--fixed-artifact-record", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--attest-fresh-generation",
        action="store_true",
        help="attest that artifact-dir was generated fresh using the recorded commands",
    )
    parser.add_argument(
        "--generation-command",
        action="append",
        default=[],
        help="exact generation command; repeat in execution order",
    )
    args = parser.parse_args()
    try:
        report = build_report(
            repo_root=args.repo_root.resolve(),
            source_commit=args.source_commit,
            operator=args.operator,
            input_manifest=args.input_manifest.resolve(),
            model_bank=args.model_bank.resolve(),
            fixed_record=args.fixed_artifact_record.resolve(),
            artifact_dir=args.artifact_dir.resolve(),
            template=args.template.resolve(),
            proof=args.proof.resolve(),
            fresh_generation_attested=args.attest_fresh_generation,
            generation_commands=args.generation_command,
        )
        encoded = write_new(args.output.resolve(), report)
    except (
        OSError,
        ConformanceError,
        ReproductionError,
        TranscriptVerificationError,
        VerificationError,
    ) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "status": "verified",
                "reproduction_complete": report["reproduction_complete"],
                "report": str(args.output.resolve()),
                "bytes": len(encoded),
                "sha256": hashlib.sha256(canonical_json(report)).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
