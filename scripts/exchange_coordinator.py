#!/usr/bin/env python3
"""Single-writer reference coordinator for the durable exchange deposit feed.

The coordinator uses an explicit poll/ack outbox. Poll persists an exact event
page before presenting it; ack advances the durable cursor only for that batch.
This demonstrates process-restart-safe, at-least-once consumption without
claiming physical power-loss durability or making any customer-crediting or
confirmation-policy decision for an exchange.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterator

import exchange_conformance as conformance


STATE_SCHEMA = "CMFD_EXCHANGE_COORDINATOR_STATE_V2"
BATCH_SCHEMA = "CMFD_EXCHANGE_DEPOSIT_BATCH_V1"
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1


class CoordinatorError(RuntimeError):
    pass


def state_envelope(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "state": state,
        "state_sha256": conformance.sha256_hex(conformance.canonical_json(state)),
    }


def load_state(path: Path) -> dict[str, Any]:
    try:
        envelope = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CoordinatorError("coordinator state is unreadable or invalid JSON") from error
    if not isinstance(envelope, dict) or envelope.get("schema") != STATE_SCHEMA:
        raise CoordinatorError("coordinator state schema is invalid")
    state = envelope.get("state")
    if not isinstance(state, dict) or envelope.get("state_sha256") != conformance.sha256_hex(
        conformance.canonical_json(state)
    ):
        raise CoordinatorError("coordinator state digest does not match")
    if set(state) != {
        "network_id",
        "consensus_fingerprint",
        "committed_cursor",
        "pending",
        "last_ack",
    }:
        raise CoordinatorError("coordinator state fields are invalid")
    conformance.validate_hex32(state["network_id"], "state network id")
    conformance.validate_hex32(
        state["consensus_fingerprint"], "state consensus fingerprint"
    )
    canonical_u64(state["committed_cursor"], "committed cursor")
    validate_last_ack(state["last_ack"], state["committed_cursor"])
    if state["pending"] is not None:
        validate_batch(state["pending"], state)
    return state


def validate_last_ack(receipt: Any, committed_cursor: str) -> None:
    if receipt is None:
        return
    if not isinstance(receipt, dict) or set(receipt) != {
        "batch_id",
        "after_cursor",
        "next_cursor",
    }:
        raise CoordinatorError("last acknowledgement receipt fields are invalid")
    if not isinstance(receipt["batch_id"], str) or not conformance.HEX32.fullmatch(
        receipt["batch_id"]
    ):
        raise CoordinatorError("last acknowledgement batch id is invalid")
    after_cursor = canonical_u64(
        receipt["after_cursor"], "last acknowledgement after_cursor"
    )
    next_cursor = canonical_u64(
        receipt["next_cursor"], "last acknowledgement next_cursor"
    )
    if after_cursor > next_cursor or receipt["next_cursor"] != committed_cursor:
        raise CoordinatorError("last acknowledgement receipt does not match the cursor")


def validate_batch(batch: Any, state: dict[str, Any]) -> None:
    if not isinstance(batch, dict) or batch.get("schema") != BATCH_SCHEMA:
        raise CoordinatorError("pending deposit batch schema is invalid")
    if set(batch) != {
        "schema",
        "api_version",
        "network_id",
        "consensus_fingerprint",
        "indexed_tip",
        "after_cursor",
        "next_cursor",
        "high_watermark",
        "has_more",
        "events",
        "batch_id",
    }:
        raise CoordinatorError("pending deposit batch fields are invalid")
    if batch.get("api_version") != conformance.CHAIN_API_VERSION:
        raise CoordinatorError("pending deposit batch API version is invalid")
    if batch.get("network_id") != state["network_id"] or batch.get(
        "consensus_fingerprint"
    ) != state["consensus_fingerprint"]:
        raise CoordinatorError("pending deposit batch identity does not match state")
    if batch.get("after_cursor") != state["committed_cursor"]:
        raise CoordinatorError("pending batch does not begin at the committed cursor")
    after_cursor = canonical_u64(batch.get("after_cursor"), "pending batch after_cursor")
    next_cursor = canonical_u64(batch.get("next_cursor"), "pending batch next_cursor")
    high_watermark = canonical_u64(
        batch.get("high_watermark"), "pending batch high_watermark"
    )
    if after_cursor > next_cursor or next_cursor > high_watermark:
        raise CoordinatorError("pending batch cursors are out of order")
    indexed_tip = batch.get("indexed_tip")
    if (
        not isinstance(indexed_tip, dict)
        or set(indexed_tip) != {"height", "hash"}
        or not isinstance(indexed_tip.get("hash"), str)
        or not conformance.HEX32.fullmatch(indexed_tip["hash"])
    ):
        raise CoordinatorError("pending batch indexed tip is invalid")
    unsigned_json_integer(indexed_tip.get("height"), "pending batch indexed tip height")
    events = batch.get("events")
    if not isinstance(events, list) or len(events) > 1000:
        raise CoordinatorError("pending batch events are invalid")
    prior = after_cursor
    for event in events:
        validate_event(event, prior + 1)
        prior += 1
    if prior != next_cursor:
        raise CoordinatorError("pending batch cursor does not match its events")
    if type(batch.get("has_more")) is not bool or batch["has_more"] != (
        next_cursor < high_watermark
    ):
        raise CoordinatorError("pending batch has_more is invalid")
    expected_id = batch_id({key: value for key, value in batch.items() if key != "batch_id"})
    if batch.get("batch_id") != expected_id:
        raise CoordinatorError("pending batch id does not match its exact content")


def batch_id(batch_without_id: dict[str, Any]) -> str:
    return conformance.sha256_hex(conformance.canonical_json(batch_without_id))


def canonical_u64(value: Any, label: str, minimum: int = 0) -> int:
    if (
        not isinstance(value, str)
        or len(value) > 20
        or not conformance.DECIMAL.fullmatch(value)
    ):
        raise CoordinatorError(f"{label} is not a canonical unsigned decimal string")
    parsed = int(value)
    if not minimum <= parsed <= MAX_U64:
        raise CoordinatorError(f"{label} is outside its unsigned 64-bit range")
    return parsed


def unsigned_json_integer(value: Any, label: str, maximum: int = MAX_U64) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise CoordinatorError(f"{label} is outside its unsigned integer range")
    return value


def validate_label(value: Any) -> None:
    if not isinstance(value, str):
        raise CoordinatorError("deposit event label is not a string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise CoordinatorError("deposit event label is not visible ASCII") from error
    if not 1 <= len(encoded) <= 128 or any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise CoordinatorError("deposit event label is not 1-128 visible ASCII bytes")


def validate_event(event: Any, expected_cursor: int) -> None:
    if not isinstance(event, dict):
        raise CoordinatorError("deposit event is not an object")
    required = {
        "cursor",
        "added_cursor",
        "kind",
        "label",
        "destination_hex",
        "txid",
        "vout",
        "value_atoms",
        "spendable_height",
        "coinbase",
        "blockhash",
        "blockheight",
        "blocktime",
    }
    if set(event) != required:
        raise CoordinatorError("deposit event fields do not match the pinned contract")
    cursor = canonical_u64(event["cursor"], "deposit event cursor", 1)
    added_cursor = canonical_u64(event["added_cursor"], "deposit event added_cursor", 1)
    if cursor != expected_cursor:
        raise CoordinatorError("deposit events are not contiguous after the committed cursor")
    kind = event.get("kind")
    if kind == "deposit_added":
        if added_cursor != cursor:
            raise CoordinatorError("added deposit event does not identify its own cursor")
    elif kind == "deposit_removed":
        if added_cursor >= cursor:
            raise CoordinatorError("removed deposit event does not identify an earlier addition")
    else:
        raise CoordinatorError("deposit event kind is unsupported")
    validate_label(event.get("label"))
    for field in ("destination_hex", "txid", "blockhash"):
        value = event.get(field)
        if not isinstance(value, str) or not conformance.HEX32.fullmatch(value):
            raise CoordinatorError(f"deposit event {field} is not a canonical 32-byte value")
    unsigned_json_integer(event.get("vout"), "deposit event vout", MAX_U32)
    canonical_u64(event.get("value_atoms"), "deposit event value_atoms")
    unsigned_json_integer(event.get("spendable_height"), "deposit event spendable_height")
    if type(event.get("coinbase")) is not bool:
        raise CoordinatorError("deposit event coinbase is not a boolean")
    if unsigned_json_integer(event.get("blockheight"), "deposit event blockheight") == 0:
        raise CoordinatorError("deposit event blockheight must be positive")
    unsigned_json_integer(event.get("blocktime"), "deposit event blocktime")


def initialize_state(path: Path, network_id: str, fingerprint: str) -> dict[str, Any]:
    if not path.is_absolute():
        raise CoordinatorError("state path must be absolute")
    state = {
        "network_id": conformance.validate_hex32(network_id, "network id"),
        "consensus_fingerprint": conformance.validate_hex32(
            fingerprint, "consensus fingerprint"
        ),
        "committed_cursor": "0",
        "pending": None,
        "last_ack": None,
    }
    write_create_new(path, state_envelope(state))
    return state


def poll_once(state: dict[str, Any], client: conformance.Rpc, limit: int) -> dict[str, Any]:
    if state["pending"] is not None:
        return state["pending"]
    if not 1 <= limit <= 1000:
        raise CoordinatorError("page limit must be between 1 and 1000")
    info = client.call("getexchangeinfo", [])
    if not isinstance(info, dict) or info.get("network_id") != state["network_id"] or info.get(
        "consensus_fingerprint"
    ) != state["consensus_fingerprint"]:
        raise CoordinatorError("live RPC identity does not match the coordinator pins")
    deposit_index = info.get("deposit_index")
    if (
        info.get("api_version") != conformance.CHAIN_API_VERSION
        or info.get("status") != "integration_preview"
        or info.get("production_ready") is not False
        or not isinstance(deposit_index, dict)
        or deposit_index.get("healthy") is not True
    ):
        raise CoordinatorError("live RPC capability or deposit-index health is incompatible")
    page = client.call("getdepositevents", [state["committed_cursor"], limit])
    if not isinstance(page, dict) or page.get("network_id") != state["network_id"] or page.get(
        "consensus_fingerprint"
    ) != state["consensus_fingerprint"]:
        raise CoordinatorError("deposit event page identity does not match the coordinator pins")
    events = page.get("events")
    next_cursor = page.get("next_cursor")
    high_watermark = page.get("high_watermark")
    if (
        page.get("api_version") != conformance.CHAIN_API_VERSION
        or not isinstance(events, list)
        or len(events) > limit
        or not isinstance(next_cursor, str)
        or not isinstance(high_watermark, str)
    ):
        raise CoordinatorError("deposit event page fields are invalid")
    if not conformance.DECIMAL.fullmatch(next_cursor) or not conformance.DECIMAL.fullmatch(
        high_watermark
    ):
        raise CoordinatorError("deposit event page cursors are not canonical")
    indexed_tip = page.get("indexed_tip")
    if (
        not isinstance(indexed_tip, dict)
        or set(indexed_tip) != {"height", "hash"}
        or not isinstance(indexed_tip.get("hash"), str)
        or not conformance.HEX32.fullmatch(indexed_tip["hash"])
    ):
        raise CoordinatorError("deposit event page indexed tip is invalid")
    unsigned_json_integer(indexed_tip.get("height"), "deposit event page indexed tip height")
    prior = int(state["committed_cursor"])
    for event in events:
        validate_event(event, prior + 1)
        prior += 1
    next_value = canonical_u64(next_cursor, "deposit page next_cursor")
    high_value = canonical_u64(high_watermark, "deposit page high_watermark")
    if prior != next_value or next_value > high_value:
        raise CoordinatorError("deposit page cursor does not match its events")
    if type(page.get("has_more")) is not bool or page["has_more"] != (
        next_value < high_value
    ):
        raise CoordinatorError("deposit page has_more disagrees with its high watermark")
    batch_without_id = {
        "schema": BATCH_SCHEMA,
        "api_version": conformance.CHAIN_API_VERSION,
        "network_id": state["network_id"],
        "consensus_fingerprint": state["consensus_fingerprint"],
        "indexed_tip": {
            "height": indexed_tip["height"],
            "hash": indexed_tip["hash"],
        },
        "after_cursor": state["committed_cursor"],
        "next_cursor": next_cursor,
        "high_watermark": high_watermark,
        "has_more": page["has_more"],
        "events": events,
    }
    return {**batch_without_id, "batch_id": batch_id(batch_without_id)}


def persist_pending(path: Path, state: dict[str, Any], batch: dict[str, Any]) -> dict[str, Any]:
    candidate = dict(state)
    candidate["pending"] = batch
    atomic_replace(path, state_envelope(candidate))
    return candidate


def acknowledge(path: Path, state: dict[str, Any], expected_batch_id: str) -> dict[str, Any]:
    pending = state["pending"]
    if pending is None:
        last_ack = state["last_ack"]
        if last_ack is not None and last_ack["batch_id"] == expected_batch_id:
            return state
        raise CoordinatorError("there is no pending deposit batch to acknowledge")
    if pending["batch_id"] != expected_batch_id:
        raise CoordinatorError("batch id does not match the durable pending batch")
    candidate = dict(state)
    candidate["committed_cursor"] = pending["next_cursor"]
    candidate["pending"] = None
    candidate["last_ack"] = {
        "batch_id": pending["batch_id"],
        "after_cursor": pending["after_cursor"],
        "next_cursor": pending["next_cursor"],
    }
    atomic_replace(path, state_envelope(candidate))
    return candidate


def write_create_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    try:
        with path.open("xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        sync_parent_directory(path)
    except FileExistsError as error:
        raise CoordinatorError("state or output path already exists") from error


def atomic_replace(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.new")
    if temporary.exists():
        raise CoordinatorError("coordinator temporary state path already exists")
    data = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    try:
        with temporary.open("xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_parent_directory(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def sync_parent_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def state_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock:
        if os.name == "nt":
            import msvcrt

            lock.seek(0, os.SEEK_END)
            if lock.tell() == 0:
                lock.write(b"0")
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def emit(value: dict[str, Any], output: Path | None) -> None:
    if output is None:
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        if not output.is_absolute():
            raise CoordinatorError("batch output path must be absolute")
        write_create_new(output, value)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init")
    initialize.add_argument("--state", required=True, type=Path)
    initialize.add_argument("--network-id", required=True)
    initialize.add_argument("--consensus-fingerprint", required=True)
    poll = commands.add_parser("poll")
    poll.add_argument("--state", required=True, type=Path)
    poll.add_argument("--endpoint", required=True)
    poll.add_argument("--authentication-file", required=True, type=Path)
    poll.add_argument("--limit", type=int, default=100)
    poll.add_argument("--timeout-seconds", type=float, default=10.0)
    poll.add_argument("--output", type=Path)
    ack = commands.add_parser("ack")
    ack.add_argument("--state", required=True, type=Path)
    ack.add_argument("--batch-id", required=True)
    status = commands.add_parser("status")
    status.add_argument("--state", required=True, type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if not args.state.is_absolute():
            raise CoordinatorError("state path must be absolute")
        with state_lock(args.state):
            if args.command == "init":
                emit(
                    state_envelope(
                        initialize_state(
                            args.state, args.network_id, args.consensus_fingerprint
                        )
                    ),
                    None,
                )
            elif args.command == "poll":
                state = load_state(args.state)
                client = conformance.RpcClient(
                    args.endpoint, args.authentication_file, args.timeout_seconds
                )
                batch = poll_once(state, client, args.limit)
                if state["pending"] is None:
                    persist_pending(args.state, state, batch)
                emit(batch, args.output)
            elif args.command == "ack":
                state = acknowledge(args.state, load_state(args.state), args.batch_id)
                emit(state_envelope(state), None)
            else:
                emit(state_envelope(load_state(args.state)), None)
        return 0
    except (CoordinatorError, conformance.ConformanceError) as error:
        print(f"exchange coordinator failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
