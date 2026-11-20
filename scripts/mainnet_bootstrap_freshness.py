#!/usr/bin/env python3
"""Assess when a published trusted mainnet bootstrap needs a new capture.

This checks operational age and fork compatibility only. It does not
authenticate the manifest, the node height, or historical chain state.
"""

import argparse
import json
from pathlib import Path


SCHEMA = "CMFD_TRUSTED_PRUNED_BOOTSTRAP_V1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--tip-height", required=True, type=int)
    parser.add_argument("--max-lag-blocks", type=int, default=7200)
    args = parser.parse_args()

    if args.tip_height < 0 or args.max_lag_blocks < 0:
        parser.error("heights and lag limit must be nonnegative")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if (
        manifest.get("schema") != SCHEMA
        or manifest.get("trust_mode") != "official-trusted-pruned-checkpoint"
        or manifest.get("state_is_consensus_proof") is not False
    ):
        parser.error("unsupported bootstrap manifest or trust mode")
    height = manifest.get("height")
    activation = manifest.get("compact_activation_height")
    if not isinstance(height, int) or height < 0:
        parser.error("manifest height is invalid")
    if not isinstance(activation, int) or activation <= 0:
        parser.error("manifest compact activation height is invalid")
    if args.tip_height < height:
        parser.error("node tip is below the published bootstrap; check network and inputs")

    lag = args.tip_height - height
    reasons = []
    if lag > args.max_lag_blocks:
        reasons.append("lag_limit_exceeded")
    if height < activation <= args.tip_height:
        reasons.append("bootstrap_predates_compact_activation")

    print(
        json.dumps(
            {
                "release_tag": manifest.get("release_tag"),
                "bootstrap_height": height,
                "tip_height": args.tip_height,
                "lag_blocks": lag,
                "max_lag_blocks": args.max_lag_blocks,
                "compact_activation_height": activation,
                "refresh_recommended": bool(reasons),
                "reasons": reasons,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
