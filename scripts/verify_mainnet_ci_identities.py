"""Read-only native mainnet identity check; never starts a node or a wallet GUI."""
import argparse
import base64
import json
from pathlib import Path

import package_mainnet as package


def verify(repo: Path, commit: str, node: Path, wallet: Path) -> dict:
    package.nonzero_hex(commit, 40, "source commit")
    plan = package.validate_plan((repo / "packaging/mainnet/MAINNET-PLAN.json").read_bytes())
    node_info = package.validate_info(package.native_output(node, ["mainnet-launch-info"]), plan, commit)
    wrapper = package.strict_json(package.native_output(wallet, ["runtime-identity"]), "wallet prelaunch identity")
    if (set(wrapper) != {"schema", "role", "package_version", "launch_info_base64"}
            or wrapper["schema"] != "CMFD_WALLET_PRELAUNCH_IDENTITY_V1"
            or wrapper["role"] != "common-foundry-wallet"):
        raise package.Error("wallet did not return its mainnet prelaunch identity")
    expected_version = json.loads((repo / "apps/wallet/package.json").read_bytes())["version"]
    if wrapper["package_version"] != expected_version:
        raise package.Error("wallet package version differs from source")
    wallet_info = package.validate_info(base64.b64decode(wrapper["launch_info_base64"], validate=True), plan, commit)
    if node_info != wallet_info:
        raise package.Error("mainnet node and wallet identities disagree")
    return {"schema": "CMFD_MAINNET_CI_IDENTITY_CHECK_V1", "source_commit": commit,
            "network_id": plan["network_id"], "package_version": expected_version,
            "consistent": True, "mainnet_started": False, "release_approved": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--wallet", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(package.canonical(verify(Path(__file__).resolve().parents[1], args.commit,
                                       args.node.resolve(strict=True), args.wallet.resolve(strict=True))).decode(), end="")
    except (OSError, ValueError, KeyError, TypeError, package.Error) as error:
        parser.exit(1, f"Mainnet native identity check failed: {error}\n")
