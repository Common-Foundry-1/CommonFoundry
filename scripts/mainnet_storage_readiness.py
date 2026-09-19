#!/usr/bin/env python3
"""Read-only storage planning for the current ForgeMatrix V4 implementation.

No pruning, service changes, wallet reads, or network requests. Estimates use
target block spacing, not a guaranteed daily arrival limit. Side branches,
checkpoints, backups and other workloads can require additional space.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from fractions import Fraction
import json
from pathlib import Path
import shutil
import stat

GIB = 1024 ** 3
PROOF_BYTES = 12_025_320
MAX_BLOCK_BYTES = 16 * 1024 * 1024
MAX_STATE_DELTA_BYTES = 1024 * 1024
RECORD_OVERHEAD_BYTES = 56 + 32
TARGET_SPACING_SECONDS = 60


def ceiling(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


def forecast(*, total_bytes: int, available_bytes: int, block_log_bytes: int,
             horizon_days: int, reserve_gib: int, additional_artifact_bytes: int,
             records_per_canonical_block: Fraction) -> dict:
    integers = (total_bytes, available_bytes, block_log_bytes, horizon_days, reserve_gib, additional_artifact_bytes)
    if any(type(value) is not int or value < 0 for value in integers):
        raise ValueError("storage quantities must be nonnegative integers")
    if total_bytes == 0 or available_bytes > total_bytes or not 1 <= horizon_days <= 3650:
        raise ValueError("invalid capacity or planning horizon")
    if not 1 <= records_per_canonical_block <= 16:
        raise ValueError("record multiplier must be between 1 and 16")
    blocks_per_day = Fraction(86400, TARGET_SPACING_SECONDS)
    maximum_record = MAX_BLOCK_BYTES + MAX_STATE_DELTA_BYTES + RECORD_OVERHEAD_BYTES
    proof_only_rate = ceiling(PROOF_BYTES * blocks_per_day)
    scenario_rate = ceiling(maximum_record * blocks_per_day * records_per_canonical_block)
    reserve = reserve_gib * GIB
    usable = max(0, available_bytes - reserve - additional_artifact_bytes)
    scenario_requirement = horizon_days * scenario_rate + reserve + additional_artifact_bytes
    # Startup guard only preserves the operational reserve and room for two
    # maximum records. A 30-day planning shortfall does not prevent a restart.
    reserve_requirement = reserve + additional_artifact_bytes + 2 * maximum_record
    return {
        "schema": "CMFD_STORAGE_PLANNING_V1",
        "proof_profile": "ForgeMatrix V4 transparent BaseFold",
        "total_bytes": total_bytes, "available_bytes": available_bytes,
        "block_log_bytes": block_log_bytes, "reserve_bytes": reserve,
        "additional_artifact_bytes": additional_artifact_bytes,
        "target_spacing_seconds": TARGET_SPACING_SECONDS,
        "proof_bytes_per_block": PROOF_BYTES,
        "maximum_v2_record_bytes": maximum_record,
        "assumed_records_per_canonical_block": str(records_per_canonical_block),
        "proof_only_bytes_per_day_at_target_spacing": proof_only_rate,
        "record_scenario_bytes_per_day_at_target_spacing": scenario_rate,
        "proof_only_gib_per_day_at_target_spacing": round(proof_only_rate / GIB, 4),
        "record_scenario_gib_per_day_at_target_spacing": round(scenario_rate / GIB, 4),
        "horizon_days": horizon_days,
        "scenario_required_available_bytes": scenario_requirement,
        "scenario_additional_capacity_bytes": max(0, scenario_requirement - available_bytes),
        "horizon_fits_scenario": available_bytes >= scenario_requirement,
        "days_until_reserve_in_scenario": round(usable / scenario_rate, 2),
        "reserve_satisfied": available_bytes >= reserve_requirement,
        "pruning_available": False,
        "assumptions": [
            "target spacing is an average, not a guaranteed block arrival cap",
            "record scenario includes maximum block and undo sizes plus an explicit branch multiplier",
            "checkpoints, additional backups and unrelated future disk use are not included",
            "this report neither prunes history nor qualifies a mainnet deployment",
        ],
    }


def inspect(data_dir: Path, **options) -> dict:
    if not data_dir.is_absolute() or not data_dir.is_dir():
        raise ValueError("data directory must be an existing absolute directory")
    usage = shutil.disk_usage(data_dir)
    log = data_dir / "blocks.log"
    try:
        metadata = log.lstat()
    except FileNotFoundError:
        log_bytes = 0
    else:
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("blocks.log must be a regular file, not a symlink")
        log_bytes = metadata.st_size
    report = forecast(total_bytes=usage.total, available_bytes=usage.free,
                      block_log_bytes=log_bytes, **options)
    report.update({"data_directory": str(data_dir), "observed_at_utc": datetime.now(timezone.utc).isoformat()})
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--horizon-days", type=int, default=30)
    parser.add_argument("--reserve-gib", type=int, default=20)
    parser.add_argument("--additional-artifact-bytes", type=int, default=0)
    parser.add_argument("--records-per-canonical-block", type=Fraction, default=Fraction(5, 4))
    parser.add_argument("--enforce-reserve", action="store_true",
                        help="return failure below the reserve; does not stop an existing service")
    args = parser.parse_args()
    try:
        report = inspect(args.data_dir, horizon_days=args.horizon_days, reserve_gib=args.reserve_gib,
                         additional_artifact_bytes=args.additional_artifact_bytes,
                         records_per_canonical_block=args.records_per_canonical_block)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 3 if args.enforce_reserve and not report["reserve_satisfied"] else 0
    except (OSError, ValueError) as error:
        parser.exit(2, f"Storage inspection failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
