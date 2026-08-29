#!/usr/bin/env python3
"""Create canonical evidence from ProductionV4 sanitizer fuzz logs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from production_v4_reproduction import canonical_json, file_identity, write_new


REPORT_SCHEMA = "CommonFoundry/ForgeMatrix/V4/FuzzCampaignReport/v1"
TARGETS = {
    "production_v4_proof_decode": 13_631_489,
    "production_v4_block_decode": 16_777_217,
    "production_v4_peer_block_decode": 16_777_237,
}
FORBIDDEN = (
    "ERROR: AddressSanitizer",
    "ERROR: libFuzzer",
    "SUMMARY: AddressSanitizer",
    "Test unit written to",
    "deadly signal",
)
HEX_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


class FuzzReportError(ValueError):
    """Raised when a fuzz log is incomplete or reports a finding."""


def parse_campaign(path: Path, target: str) -> dict[str, object]:
    if target not in TARGETS:
        raise FuzzReportError(f"unsupported fuzz target {target}")
    if path.stat().st_size > 16 * 1024 * 1024:
        raise FuzzReportError(f"fuzz log exceeds the 16 MiB evidence limit: {path}")
    text = path.read_text(encoding="utf-8")
    if any(marker.lower() in text.lower() for marker in FORBIDDEN):
        raise FuzzReportError(f"fuzz campaign reported a finding: {target}")
    running = next((line for line in text.splitlines() if "Running `" in line), None)
    if running is None or f"/{target} " not in running:
        raise FuzzReportError(f"fuzz log does not identify target {target}")
    required = (
        f"-max_len={TARGETS[target]}",
        "-timeout=10",
        "-rss_limit_mb=4096",
        "-malloc_limit_mb=1024",
    )
    if any(flag not in running for flag in required):
        raise FuzzReportError(f"fuzz campaign limits are not pinned: {target}")
    seed = re.search(r"seed corpus: files: (\d+) min: (\d+)b max: (\d+)b", text)
    if seed is None or int(seed.group(3)) < 12_025_320:
        raise FuzzReportError(f"fuzz campaign omitted the full-size proof seed: {target}")
    completed = re.findall(r"Done (\d+) runs in (\d+) second\(s\)", text)
    if not completed:
        raise FuzzReportError(f"fuzz campaign did not finish cleanly: {target}")
    runs, seconds = (int(value) for value in completed[-1])
    rss_values = [int(value) for value in re.findall(r"rss: (\d+)Mb", text)]
    if runs == 0 or seconds == 0 or not rss_values:
        raise FuzzReportError(f"fuzz campaign summary is incomplete: {target}")
    return {
        "target": target,
        "runs": runs,
        "seconds": seconds,
        "peak_rss_mb": max(rss_values),
        "seed_files": int(seed.group(1)),
        "maximum_seed_bytes": int(seed.group(3)),
        "maximum_input_bytes": TARGETS[target],
        "timeout_seconds": 10,
        "rss_limit_mb": 4096,
        "malloc_limit_mb": 1024,
        "log": file_identity(path),
    }


def build_report(
    logs: dict[str, Path], source_commit: str, operator: str, minimum_seconds: int
) -> dict[str, object]:
    if HEX_COMMIT.fullmatch(source_commit) is None:
        raise FuzzReportError("source commit must be lowercase 40- or 64-hex")
    if not operator.strip():
        raise FuzzReportError("operator must not be empty")
    if minimum_seconds <= 0:
        raise FuzzReportError("minimum campaign seconds must be positive")
    if set(logs) != set(TARGETS):
        raise FuzzReportError("all three ProductionV4 fuzz targets are required")
    campaigns = [parse_campaign(logs[target], target) for target in TARGETS]
    return {
        "schema": REPORT_SCHEMA,
        "status": "verified",
        "source_commit": source_commit,
        "operator": operator.strip(),
        "sanitizer": "AddressSanitizer through cargo-fuzz/libFuzzer",
        "minimum_seconds_per_target": minimum_seconds,
        "campaign_gate_met": all(
            int(campaign["seconds"]) >= minimum_seconds for campaign in campaigns
        ),
        "campaigns": campaigns,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof-log", type=Path, required=True)
    parser.add_argument("--block-log", type=Path, required=True)
    parser.add_argument("--peer-block-log", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--minimum-seconds-per-target", type=int, default=86_400)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    logs = {
        "production_v4_proof_decode": args.proof_log.resolve(),
        "production_v4_block_decode": args.block_log.resolve(),
        "production_v4_peer_block_decode": args.peer_block_log.resolve(),
    }
    try:
        report = build_report(
            logs,
            args.source_commit,
            args.operator,
            args.minimum_seconds_per_target,
        )
        encoded = write_new(args.output.resolve(), report)
    except (OSError, UnicodeError, FuzzReportError, ValueError) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "status": "verified",
                "campaign_gate_met": report["campaign_gate_met"],
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
