#!/usr/bin/env python3
"""Fail-closed mainnet pool service launcher. This file does not install/start itself.

The separate service account, paths and numeric ports deliberately cannot import
RC pool state. The native mainnet runtime remains the authority for launch-plan,
beacon, model and consensus validation; this wrapper checks deployment inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

INSTALL_BASE = Path("/opt/commonfoundry-mainnet-pool")
ROOT = INSTALL_BASE / "current"
STATE = Path("/var/lib/commonfoundry-mainnet-pool")
RUNTIME = Path("/run/commonfoundry-mainnet-pool")
CONFIG_BASE = Path("/etc/commonfoundry-mainnet-pool")
RC_CERTIFICATE_SHA256 = "a4868a78e9d4d46bbb3c7867bd43bacbb4e8bb0a0ac61e54444b16250d525dc0"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GPU_UUID = re.compile(r"GPU-[0-9a-fA-F-]{36}\Z")
SCHEMA = "CommonFoundry/MainnetPoolService/v1"
MARKER_SCHEMA = "CommonFoundry/MainnetPoolDeployment/v1"
ARTIFACT_NAMES = {"MODEL-V2.bank", "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"} | {
    f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{extension}"
    for bank in range(3) for extension in ("row-major.codeword", "tree")
}
HASH_FIELDS = (
    "expected_network_id", "expected_plan_digest", "expected_node_sha256",
    "expected_launch_sha256", "expected_replay_worker_sha256",
    "expected_proof_worker_sha256", "expected_cuda_runtime_sha256",
    "expected_dashboard_index_sha256", "expected_tls_certificate_sha256",
    "expected_tls_private_key_sha256", "forbidden_rc_certificate_sha256",
    "forbidden_rc_private_key_sha256", "forbidden_rc_wallet_file_sha256",
)
NUMBER_FIELDS = {
    "worker_threads": (1, 96), "share_leading_zero_bits": (0, 7),
    "minimum_payout_atoms": (1, 2**64 - 1),
    "payout_fee_atoms": (1, 2**64 - 1), "operator_fee_bps": (0, 10_000),
    "pplns_window_shares": (0, 65_536),
}
CONFIG_FIELDS = {"schema", "public_numeric_ip", "private_bind_ip", "mainnet_seed",
                 "gpu_uuid", "automatic_payouts", *HASH_FIELDS, *NUMBER_FIELDS}
# Optional: relay nodes the pool also treats as static peers (announced to first,
# compressed block frames). Same numeric IP:29444 form as mainnet_seed.
# Optional: proof pruning window (newest full blocks kept), as `--prune-keep-blocks`.
# Optional: largest pool ledger snapshot in bytes, as `--pool-ledger-max-bytes`
# (node default 64 MiB; large pools outgrow it).
# Optional: shares replayed together in one GPU batch, as `--pool-share-batch-size`
# (node default 1 = no batching), and the longest a share waits for its batch,
# as `--pool-share-batch-wait-ms` (node default 100).
OPTIONAL_FIELDS = {"mainnet_relays", "prune_keep_blocks", "pool_ledger_max_bytes",
                   "share_batch_size", "share_batch_wait_ms"}
MIN_PRUNE_KEEP_BLOCKS = 288
MIN_POOL_LEDGER_MAX_BYTES = 1024 * 1024
MAX_POOL_LEDGER_MAX_BYTES = 1024 * 1024 * 1024
MAX_SHARE_BATCH_SIZE = 64
MAX_SHARE_BATCH_WAIT_MS = 1000
MAX_RELAYS = 8
COMPETING_UNITS = (
    "commonfoundry-pool-public.service", "commonfoundry-pool-ai01.service",
    "catstack-owner-zcl.service", "vast-idle-xmrig.service",
)


class PreflightError(Exception):
    pass


def strict_json(data: bytes, label: str, maximum: int = 128 * 1024) -> dict:
    if len(data) > maximum:
        raise PreflightError(f"{label} exceeds {maximum} bytes")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise PreflightError(f"duplicate key in {label}: {key}")
            value[key] = item
        return value
    try:
        result = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PreflightError(f"invalid {label}") from exc
    if not isinstance(result, dict):
        raise PreflightError(f"{label} must be an object")
    return result


def regular(path: Path, label: str, *, static: bool = False) -> os.stat_result:
    try:
        details = path.lstat()
    except OSError as exc:
        raise PreflightError(f"missing {label}: {path}") from exc
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise PreflightError(f"{label} must be one regular non-symlink file: {path}")
    if static and os.name == "posix":
        if details.st_uid != 0 or stat.S_IMODE(details.st_mode) & 0o022:
            raise PreflightError(f"{label} must be root-owned and not group/world-writable: {path}")
    return details


def sha256(path: Path, label: str, *, static: bool = False) -> tuple[str, int]:
    before = regular(path, label, static=static)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    after = regular(path, label, static=static)
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise PreflightError(f"{label} changed during hashing: {path}")
    return digest.hexdigest(), before.st_size


def bounded_file(path: Path, label: str, maximum: int = 128 * 1024, *, static: bool = False) -> bytes:
    details = regular(path, label, static=static)
    if details.st_size > maximum:
        raise PreflightError(f"{label} exceeds {maximum} bytes")
    content = path.read_bytes()
    if len(content) != details.st_size:
        raise PreflightError(f"{label} changed while being read")
    return content


def require_hash(path: Path, expected: str, label: str, *, static: bool = False) -> None:
    actual, _ = sha256(path, label, static=static)
    if actual != expected:
        raise PreflightError(f"{label} SHA-256 mismatch: {path}")


def parse_numeric_ip(value: object, label: str, *, public: bool) -> str:
    if not isinstance(value, str):
        raise PreflightError(f"{label} must be a numeric IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PreflightError(f"{label} must be a numeric IP address") from exc
    if address.is_unspecified or address.is_loopback or address.is_multicast or (public and not address.is_global):
        raise PreflightError(f"{label} is not an appropriate {'public ' if public else ''}address")
    return address.compressed


def parse_seed(value: object, label: str = "mainnet_seed") -> str:
    if not isinstance(value, str):
        raise PreflightError(f"{label} must be a numeric IP and port")
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
    else:
        host, separator, port = value.rpartition(":")
    if not separator or port != "29444":
        raise PreflightError(f"{label} must use the mainnet seed P2P port 29444")
    address = parse_numeric_ip(host, label, public=True)
    return f"[{address}]:29444" if ":" in address else f"{address}:29444"


def parse_relays(value: object, seed: str) -> list:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_RELAYS:
        raise PreflightError(f"mainnet_relays must list 1 to {MAX_RELAYS} relay nodes")
    relays = [parse_seed(item, "mainnet_relays") for item in value]
    if len(set(relays)) != len(relays) or seed in relays:
        raise PreflightError("mainnet_relays must be distinct from each other and from mainnet_seed")
    return relays


def validate_config(config: dict) -> dict:
    fields = set(config)
    if not CONFIG_FIELDS <= fields or fields - CONFIG_FIELDS - OPTIONAL_FIELDS or config.get("schema") != SCHEMA:
        raise PreflightError("pool.json is incomplete or has unexpected fields")
    for field in HASH_FIELDS:
        if (not isinstance(config[field], str) or not HEX64.fullmatch(config[field])
                or config[field] == "0" * 64):
            raise PreflightError(f"{field} must be a final lowercase SHA-256 value")
    for field, (minimum, maximum) in NUMBER_FIELDS.items():
        if type(config[field]) is not int or not minimum <= config[field] <= maximum:
            raise PreflightError(f"{field} must be an approved integer from {minimum} to {maximum}")
    if config["minimum_payout_atoms"] <= config["payout_fee_atoms"]:
        raise PreflightError("minimum payout must exceed the burned payout fee")
    if config["automatic_payouts"] is not True:
        raise PreflightError("automatic mainnet payouts require explicit approval and activation")
    if not isinstance(config["gpu_uuid"], str) or not GPU_UUID.fullmatch(config["gpu_uuid"]):
        raise PreflightError("gpu_uuid must be one exact NVIDIA GPU UUID")
    config = dict(config)
    config["public_numeric_ip"] = parse_numeric_ip(config["public_numeric_ip"], "public_numeric_ip", public=True)
    config["private_bind_ip"] = parse_numeric_ip(config["private_bind_ip"], "private_bind_ip", public=False)
    config["mainnet_seed"] = parse_seed(config["mainnet_seed"])
    if "mainnet_relays" in config:
        config["mainnet_relays"] = parse_relays(config["mainnet_relays"], config["mainnet_seed"])
    if "prune_keep_blocks" in config and (
            type(config["prune_keep_blocks"]) is not int
            or not MIN_PRUNE_KEEP_BLOCKS <= config["prune_keep_blocks"] <= 2**32):
        raise PreflightError(f"prune_keep_blocks must be an integer of at least {MIN_PRUNE_KEEP_BLOCKS}")
    if "pool_ledger_max_bytes" in config and (
            type(config["pool_ledger_max_bytes"]) is not int
            or not MIN_POOL_LEDGER_MAX_BYTES <= config["pool_ledger_max_bytes"] <= MAX_POOL_LEDGER_MAX_BYTES):
        raise PreflightError(f"pool_ledger_max_bytes must be an integer from {MIN_POOL_LEDGER_MAX_BYTES} "
                             f"to {MAX_POOL_LEDGER_MAX_BYTES}")
    for field, maximum in (("share_batch_size", MAX_SHARE_BATCH_SIZE),
                           ("share_batch_wait_ms", MAX_SHARE_BATCH_WAIT_MS)):
        if field in config and (type(config[field]) is not int or not 1 <= config[field] <= maximum):
            raise PreflightError(f"{field} must be an integer from 1 to {maximum}")
    for fresh, old in (("expected_tls_certificate_sha256", "forbidden_rc_certificate_sha256"),
                       ("expected_tls_private_key_sha256", "forbidden_rc_private_key_sha256")):
        if config[fresh] == config[old]:
            raise PreflightError("mainnet TLS material must not reuse RC material")
    if config["expected_tls_certificate_sha256"] == RC_CERTIFICATE_SHA256:
        raise PreflightError("known AI01 RC pool certificate cannot be used on mainnet")
    if config["expected_replay_worker_sha256"] == config["expected_proof_worker_sha256"]:
        raise PreflightError("replay and proof workers must be distinct executables")
    return config


def check_isolation(root: Path, state: Path, config_path: Path, install_base: Path, config_base: Path) -> None:
    try:
        if not root.resolve(strict=True).is_relative_to((install_base / "releases").resolve(strict=True)):
            raise PreflightError("current must resolve beneath the dedicated mainnet-pool releases directory")
        if config_path.resolve(strict=True).parent != config_base.resolve(strict=True):
            raise PreflightError("pool.json must reside in the dedicated mainnet-pool config directory")
        if state.is_symlink() or not state.is_dir():
            raise PreflightError("mainnet pool state must be a real dedicated directory")
        if os.name == "posix":
            details = state.stat()
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
                raise PreflightError("mainnet pool state must be owned by the service and private")
    except OSError as exc:
        raise PreflightError("dedicated mainnet pool path is missing") from exc
    forbidden = (
        Path("/opt/commonfoundry-pool-ai01"), Path("/var/lib/commonfoundry-pool-ai01"),
        Path("/var/lib/commonfoundry-pool-public"), Path("/var/lib/commonfoundry-mainnet"),
        Path("/etc/commonfoundry-pool-public"), Path("/etc/commonfoundry-pool-ai01"),
    )
    for candidate in (root.resolve(), state.resolve(), config_path.resolve()):
        if any(candidate == old or candidate.is_relative_to(old) for old in forbidden):
            raise PreflightError("RC or seed paths cannot be reused by the mainnet pool")


def native_launch_info(node: Path) -> dict:
    try:
        result = subprocess.run([str(node), "mainnet-launch-info"], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=15, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError("the pinned mainnet node rejected mainnet-launch-info") from exc
    return strict_json(result.stdout, "mainnet-launch-info")


def validate_info(info: dict, config: dict) -> tuple[dict, dict]:
    if info.get("format") != "commonfoundry-mainnet-launch-info" or info.get("genesis_policy") != "requires_verified_launch_beacon":
        raise PreflightError("node is not a beacon-gated mainnet build")
    plan = info.get("launch_plan")
    if not isinstance(plan, dict) or plan.get("launch_plan_digest") != config["expected_plan_digest"] or plan.get("network_id") != config["expected_network_id"]:
        raise PreflightError("mainnet launch plan/network ID differs from approved pool configuration")
    try:
        minimum_fee = plan["payload"]["minimum_transaction_fee_atoms"]
        if type(minimum_fee) is not int or minimum_fee <= 0 or config["payout_fee_atoms"] < minimum_fee:
            raise ValueError("payout fee is below the pinned mainnet burn minimum")
        artifacts = plan["payload"]["rules"]["artifacts"]
        bank, record = artifacts["bank"], artifacts["fixed_record"]
        for row in (bank, record):
            if not HEX64.fullmatch(row["sha256"]) or type(row["bytes"]) is not int or row["bytes"] <= 0:
                raise ValueError("invalid artifact identity")
    except (KeyError, TypeError, ValueError) as exc:
        raise PreflightError("mainnet plan or payout fee lacks approved rule identities") from exc
    return bank, record


def check_artifacts(root: Path, config: dict, bank: dict, record: dict) -> None:
    static_files = {
        "node": (root / "cmfd-node", "expected_node_sha256"),
        "launch helper": (root / "cmfd-launch", "expected_launch_sha256"),
        "replay worker": (root / "production-v4/cmfd-v4-replay", "expected_replay_worker_sha256"),
        "proof worker": (root / "production-v4/real_bank0_relations", "expected_proof_worker_sha256"),
        "CUDA runtime": (root / "lib/libcudart.so.12", "expected_cuda_runtime_sha256"),
        "dashboard index": (root / "dashboard/index.html", "expected_dashboard_index_sha256"),
    }
    for label, (path, field) in static_files.items():
        require_hash(path, config[field], label, static=True)
    catalog_path = root / "production-v4-rcnet-1-inputs.json"
    catalog = strict_json(bounded_file(catalog_path, "signed artifact catalog", static=True),
                          "signed artifact catalog")
    rows = catalog.get("files")
    if catalog.get("schema_version") != 1 or not isinstance(rows, list) or len(rows) != 8 or {row.get("name") for row in rows if isinstance(row, dict)} != ARTIFACT_NAMES:
        raise PreflightError("ProductionV4 catalog is incomplete or unexpected")
    for row in rows:
        name = row["name"]
        if not isinstance(row.get("sha256"), str) or not HEX64.fullmatch(row["sha256"]) or type(row.get("bytes")) is not int or row["bytes"] <= 0:
            raise PreflightError(f"invalid catalog identity for {name}")
        artifact = root / "production-v4" / (name if name == "MODEL-V2.bank" else f"fixed/{name}")
        digest, size = sha256(artifact, f"model input {name}", static=True)
        if (digest, size) != (row["sha256"], row["bytes"]):
            raise PreflightError(f"model input mismatch: {name}")
        if name in ("MODEL-V2.bank", "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"):
            expected = bank if name == "MODEL-V2.bank" else record
            if (digest, size) != (expected["sha256"], expected["bytes"]):
                raise PreflightError(f"mainnet plan artifact mismatch: {name}")
    require_hash(root / "production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json",
                 record["sha256"], "node fixed record", static=True)


def check_state(state: Path, config: dict) -> tuple[Path, Path]:
    data = state / "data"
    scratch = state / "scratch"
    marker = state / "mainnet-pool-deployment.json"
    if data.is_symlink() or scratch.is_symlink() or marker.is_symlink():
        raise PreflightError("pool state must not use symlinks")
    if data.exists() and not data.is_dir() or scratch.exists() and not scratch.is_dir():
        raise PreflightError("pool data/scratch must be real directories")
    identity = {"schema": MARKER_SCHEMA, "plan_digest": config["expected_plan_digest"],
                "network_id": config["expected_network_id"],
                "certificate_sha256": config["expected_tls_certificate_sha256"]}
    if marker.exists():
        if strict_json(bounded_file(marker, "mainnet pool deployment marker", 4096),
                       "mainnet pool deployment marker", 4096) != identity:
            raise PreflightError("mainnet pool state belongs to another plan or TLS identity")
    elif data.exists() and any(data.iterdir()):
        raise PreflightError("first mainnet pool start requires an empty fresh data directory")
    wallet = data / "wallet.key"
    if wallet.exists():
        digest, _ = sha256(wallet, "pool wallet")
        if digest == config["forbidden_rc_wallet_file_sha256"]:
            raise PreflightError("RC encrypted wallet file was copied into mainnet pool state")
    return data, scratch


def check_gpu(expected_uuid: str) -> None:
    try:
        result = subprocess.run(["/usr/bin/nvidia-smi", "--query-gpu=uuid", "--format=csv,noheader"],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError("NVIDIA GPU or driver is unavailable") from exc
    if expected_uuid not in result.stdout.splitlines():
        raise PreflightError("the approved pool GPU UUID is not present")


def check_competing_services() -> None:
    for unit in COMPETING_UNITS:
        try:
            result = subprocess.run(["/usr/bin/systemctl", "show", "--property=ActiveState",
                                     "--value", unit], stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=5, check=True, text=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise PreflightError(f"could not prove {unit} inactive") from exc
        if result.stdout.strip() not in ("inactive", "failed"):
            raise PreflightError(f"{unit} is not inactive; do not overlap RC/owner mining with mainnet")


def check_gpu_idle(expected_uuid: str) -> None:
    """Do not share the approved pool GPU with a leftover compute workload."""
    try:
        result = subprocess.run(
            ["/usr/bin/nvidia-smi", "--query-compute-apps=gpu_uuid,pid", "--format=csv,noheader"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=True, text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError("could not prove the mainnet pool GPU idle") from exc
    for line in result.stdout.splitlines():
        row = [field.strip() for field in line.split(",")]
        if len(row) != 2 or not GPU_UUID.fullmatch(row[0]) or not row[1].isdigit():
            raise PreflightError("could not classify an NVIDIA compute process")
        if row[0] == expected_uuid:
            raise PreflightError("approved pool GPU still has an active compute process")


def credentials(config: dict, base: Path) -> tuple[Path, Path]:
    try:
        directory = base.lstat()
    except OSError as exc:
        raise PreflightError("private pool runtime credential directory is missing") from exc
    if not stat.S_ISDIR(directory.st_mode):
        raise PreflightError("pool runtime credential directory must not be a symlink")
    if os.name == "posix" and (directory.st_uid != os.geteuid() or directory.st_mode & 0o077):
        raise PreflightError("pool runtime credential directory must be service-owned and private")
    passphrase = base / "wallet-passphrase"
    private_key = base / "pool-private-key"
    for path in (passphrase, private_key):
        metadata = regular(path, "pool runtime credential")
        if os.name == "posix" and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
            raise PreflightError("pool runtime credentials must be service-owned and 0600 or stricter")
    size = regular(passphrase, "pool wallet passphrase").st_size
    if not 12 <= size <= 1024:
        raise PreflightError("pool wallet passphrase must contain 12 to 1024 bytes")
    require_hash(private_key, config["expected_tls_private_key_sha256"], "mainnet TLS private key")
    return passphrase, private_key


def build_command(root: Path, state: Path, credential_base: Path, config: dict) -> list[str]:
    def socket(address: str, port: int) -> str:
        return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    pin = config["expected_tls_certificate_sha256"]
    return [
        str(root / "cmfd-node"), "--data-dir", str(state / "data"),
        "--wallet-passphrase-file", str(credential_base / "wallet-passphrase"),
        "--production-v4-bank", str(root / "production-v4/MODEL-V2.bank"),
        "--production-v4-fixed-record", str(root / "production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"),
        "-vv", "pool-serve", "--bind", socket(config["private_bind_ip"], 29445),
        "--p2p-bind", socket(config["private_bind_ip"], 29454),
        "--peer", config["mainnet_seed"],
        *[argument for relay in config.get("mainnet_relays", []) for argument in ("--peer", relay)],
        "--no-default-seeds", "--allow-public-peers",
        "--allow-public-pool-clients", "--allow-address-only-payouts",
        "--certificate", str(CONFIG_BASE / "pool-cert.der"),
        "--private-key", str(credential_base / "pool-private-key"),
        "--production-v4-pool-replay-worker", str(root / "production-v4/cmfd-v4-replay"),
        "--production-v4-pool-proof-worker", str(root / "production-v4/real_bank0_relations"),
        "--production-v4-pool-scratch", str(state / "scratch"),
        "--share-leading-zero-bits", str(config["share_leading_zero_bits"]),
        "--enable-mainnet-payouts", "--pool-minimum-payout-atoms", str(config["minimum_payout_atoms"]),
        "--pool-payout-fee-atoms", str(config["payout_fee_atoms"]),
        "--pool-operator-fee-bps", str(config["operator_fee_bps"]),
        "--pool-pplns-window-shares", str(config["pplns_window_shares"]),
        "--pool-dashboard-assets", str(root / "dashboard"),
        "--pool-dashboard-bind", "127.0.0.1:29446",
        "--pool-public-url", f"cmfd+tls://{socket(config['public_numeric_ip'], 29445)}?pin={pin}",
        "--shutdown-request-file", str(state / "shutdown.request"),
        *(("--prune-keep-blocks", str(config["prune_keep_blocks"])) if "prune_keep_blocks" in config else ()),
        *(("--pool-ledger-max-bytes", str(config["pool_ledger_max_bytes"]))
          if "pool_ledger_max_bytes" in config else ()),
        *(("--pool-share-batch-size", str(config["share_batch_size"]))
          if "share_batch_size" in config else ()),
        *(("--pool-share-batch-wait-ms", str(config["share_batch_wait_ms"]))
          if "share_batch_wait_ms" in config else ()),
    ]


def preflight(config_path: Path, root: Path, state: Path, config_base: Path, install_base: Path,
              credential_base: Path) -> tuple[dict, Path, Path]:
    config = validate_config(strict_json(bounded_file(config_path, "mainnet pool config", static=True),
                                         "mainnet pool config"))
    check_isolation(root, state, config_path, install_base, config_base)
    require_hash(CONFIG_BASE / "pool-cert.der", config["expected_tls_certificate_sha256"],
                 "mainnet pool certificate", static=True)
    credentials(config, credential_base)
    require_hash(root / "cmfd-node", config["expected_node_sha256"], "node", static=True)
    info = native_launch_info(root / "cmfd-node")
    bank, record = validate_info(info, config)
    plan = strict_json(bounded_file(root / "production-mainnet/MAINNET-PLAN.json",
                                    "mainnet launch plan", 32 * 1024, static=True),
                       "mainnet launch plan", 32 * 1024)
    if plan != info["launch_plan"]:
        raise PreflightError("on-disk mainnet launch plan differs from native pinned launch info")
    check_artifacts(root, config, bank, record)
    data, scratch = check_state(state, config)
    check_gpu(config["gpu_uuid"])
    return config, data, scratch


def write_marker(state: Path, config: dict) -> None:
    marker = state / "mainnet-pool-deployment.json"
    if marker.exists():
        return
    identity = {"schema": MARKER_SCHEMA, "plan_digest": config["expected_plan_digest"],
                "network_id": config["expected_network_id"],
                "certificate_sha256": config["expected_tls_certificate_sha256"]}
    encoded = (json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", metavar="POOL_JSON", type=Path)
    mode.add_argument("--run", metavar="POOL_JSON", type=Path)
    args = parser.parse_args()
    config_path = args.check or args.run
    if config_path != CONFIG_BASE / "pool.json":
        raise PreflightError("only the dedicated /etc/commonfoundry-mainnet-pool/pool.json is accepted")
    # The unit copies systemd's potentially ACL-backed credentials into its
    # private runtime directory. Do not weaken the native wallet's 0600 policy.
    if os.environ.get("RUNTIME_DIRECTORY") != str(RUNTIME):
        raise PreflightError("the dedicated systemd RuntimeDirectory is required")
    config, data, scratch = preflight(config_path, ROOT, STATE, CONFIG_BASE, INSTALL_BASE,
                                      RUNTIME)
    if args.check:
        print("Mainnet pool preflight passed; no beacon was fetched and no service was started.")
        return 0
    data.mkdir(mode=0o700, exist_ok=True)
    scratch.mkdir(mode=0o700, exist_ok=True)
    print("Waiting for the pinned mainnet launch beacon; no RC fallback is permitted.", flush=True)
    subprocess.run([str(ROOT / "cmfd-launch"), "fetch", "--runtime", str(ROOT / "cmfd-node"), "--wait"], check=True)
    regular(ROOT / "production-mainnet/LAUNCH-BEACON.json", "verified launch-beacon sidecar")
    # The node independently revalidates this beacon and compiled plan before opening state.
    check_competing_services()
    check_gpu_idle(config["gpu_uuid"])
    write_marker(STATE, config)
    environment = dict(os.environ, CUDA_VISIBLE_DEVICES=config["gpu_uuid"],
                       RAYON_NUM_THREADS=str(config["worker_threads"]),
                       LD_LIBRARY_PATH=str(ROOT / "lib"))
    os.execve(str(ROOT / "cmfd-node"), build_command(ROOT, STATE, RUNTIME, config), environment)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (PreflightError, OSError, subprocess.CalledProcessError) as exc:
        print(f"Mainnet pool did not start: {exc}", file=sys.stderr)
        sys.exit(1)
