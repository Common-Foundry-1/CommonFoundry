from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import exchange_conformance as conformance
import exchange_coordinator as coordinator


class CountingRpc:
    def __init__(self, page: dict[str, Any]) -> None:
        self.page = page
        self.calls: list[str] = []

    def call(self, method: str, params: list[Any]) -> Any:
        del params
        self.calls.append(method)
        if method == "getexchangeinfo":
            return {
                "api_version": conformance.CHAIN_API_VERSION,
                "status": "integration_preview",
                "production_ready": False,
                "network_id": "11" * 32,
                "consensus_fingerprint": "22" * 32,
                "deposit_index": {"healthy": True},
            }
        if method == "getdepositevents":
            return {
                "api_version": conformance.CHAIN_API_VERSION,
                "indexed_tip": {"height": 2, "hash": "66" * 32},
                **self.page,
            }
        raise AssertionError(method)


def event(cursor: int, kind: str = "deposit_added") -> dict[str, Any]:
    return {
        "cursor": str(cursor),
        "added_cursor": "1",
        "kind": kind,
        "label": "account-001",
        "destination_hex": "33" * 32,
        "txid": "44" * 32,
        "vout": 0,
        "value_atoms": "10",
        "spendable_height": 2,
        "coinbase": False,
        "blockhash": "55" * 32,
        "blockheight": 1,
        "blocktime": 1_700_000_000,
    }


class ExchangeCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state_path = Path(self.temporary.name).resolve() / "coordinator.json"
        self.state = coordinator.initialize_state(
            self.state_path, "11" * 32, "22" * 32
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_poll_persists_outbox_before_ack_advances_cursor(self) -> None:
        client = CountingRpc({
            "network_id": "11" * 32,
            "consensus_fingerprint": "22" * 32,
            "events": [event(1), event(2, "deposit_removed")],
            "next_cursor": "2",
            "high_watermark": "2",
            "has_more": False,
        })
        batch = coordinator.poll_once(self.state, client, 100)
        pending = coordinator.persist_pending(self.state_path, self.state, batch)
        reopened = coordinator.load_state(self.state_path)
        self.assertEqual(reopened, pending)
        self.assertEqual(reopened["committed_cursor"], "0")
        self.assertEqual(reopened["pending"]["batch_id"], batch["batch_id"])

        acknowledged = coordinator.acknowledge(
            self.state_path, reopened, batch["batch_id"]
        )
        self.assertEqual(acknowledged["committed_cursor"], "2")
        self.assertIsNone(acknowledged["pending"])
        self.assertEqual(
            acknowledged["last_ack"],
            {
                "batch_id": batch["batch_id"],
                "after_cursor": "0",
                "next_cursor": "2",
            },
        )
        self.assertEqual(coordinator.load_state(self.state_path), acknowledged)

    def test_ack_retry_after_durable_replace_is_idempotent(self) -> None:
        client = CountingRpc({
            "network_id": "11" * 32,
            "consensus_fingerprint": "22" * 32,
            "events": [event(1)],
            "next_cursor": "1",
            "high_watermark": "1",
            "has_more": False,
        })
        batch = coordinator.poll_once(self.state, client, 100)
        pending = coordinator.persist_pending(self.state_path, self.state, batch)

        # Model a process dying after atomic_replace committed but before the
        # CLI acknowledgement response reached its caller.
        committed = coordinator.acknowledge(
            self.state_path, pending, batch["batch_id"]
        )
        reopened = coordinator.load_state(self.state_path)
        retried = coordinator.acknowledge(
            self.state_path, reopened, batch["batch_id"]
        )
        self.assertEqual(retried, committed)
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator.acknowledge(self.state_path, reopened, "99" * 32)

    def test_pending_batch_replays_without_an_rpc_call(self) -> None:
        client = CountingRpc({
            "network_id": "11" * 32,
            "consensus_fingerprint": "22" * 32,
            "events": [],
            "next_cursor": "0",
            "high_watermark": "0",
            "has_more": False,
        })
        first = coordinator.poll_once(self.state, client, 10)
        pending = coordinator.persist_pending(self.state_path, self.state, first)
        replay_client = CountingRpc({})
        self.assertEqual(coordinator.poll_once(pending, replay_client, 10), first)
        self.assertEqual(replay_client.calls, [])

    def test_noncontiguous_or_wrong_network_page_fails_closed(self) -> None:
        gap = CountingRpc({
            "network_id": "11" * 32,
            "consensus_fingerprint": "22" * 32,
            "events": [event(2)],
            "next_cursor": "2",
            "high_watermark": "2",
            "has_more": False,
        })
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator.poll_once(self.state, gap, 100)
        wrong = CountingRpc({
            "network_id": "99" * 32,
            "consensus_fingerprint": "22" * 32,
            "events": [],
            "next_cursor": "0",
            "high_watermark": "0",
            "has_more": False,
        })
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator.poll_once(self.state, wrong, 100)

    def test_state_digest_corruption_is_rejected(self) -> None:
        envelope = json.loads(self.state_path.read_text(encoding="utf-8"))
        envelope["state"]["committed_cursor"] = "9"
        self.state_path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator.load_state(self.state_path)

    def test_malformed_page_and_event_fields_fail_closed(self) -> None:
        invalid_events = []
        for field, value in (
            ("added_cursor", "0"),
            ("label", "customer name"),
            ("destination_hex", "not-a-key"),
            ("txid", "AA" * 32),
            ("vout", -1),
            ("value_atoms", "01"),
            ("spendable_height", -1),
            ("coinbase", 0),
            ("blockhash", "00"),
            ("blockheight", 0),
            ("blocktime", -1),
        ):
            changed = event(1)
            changed[field] = value
            invalid_events.append(changed)
        extra = event(1)
        extra["untrusted_extra"] = "must not be persisted"
        invalid_events.append(extra)

        for invalid in invalid_events:
            with self.subTest(invalid=invalid):
                client = CountingRpc({
                    "network_id": "11" * 32,
                    "consensus_fingerprint": "22" * 32,
                    "events": [invalid],
                    "next_cursor": "1",
                    "high_watermark": "1",
                    "has_more": False,
                })
                with self.assertRaises(coordinator.CoordinatorError):
                    coordinator.poll_once(self.state, client, 100)

        integer_has_more = CountingRpc({
            "network_id": "11" * 32,
            "consensus_fingerprint": "22" * 32,
            "events": [],
            "next_cursor": "0",
            "high_watermark": "0",
            "has_more": 0,
        })
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator.poll_once(self.state, integer_has_more, 100)

    def test_page_limit_and_cursor_digit_bounds_are_enforced(self) -> None:
        oversized = CountingRpc({
            "network_id": "11" * 32,
            "consensus_fingerprint": "22" * 32,
            "events": [event(1), event(2)],
            "next_cursor": "2",
            "high_watermark": "2",
            "has_more": False,
        })
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator.poll_once(self.state, oversized, 1)
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator.canonical_u64("9" * 5000, "hostile cursor")

    def test_batch_id_binds_every_event_field(self) -> None:
        client = CountingRpc({
            "network_id": "11" * 32,
            "consensus_fingerprint": "22" * 32,
            "events": [event(1)],
            "next_cursor": "1",
            "high_watermark": "1",
            "has_more": False,
        })
        batch = coordinator.poll_once(self.state, client, 100)
        changed = json.loads(json.dumps(batch))
        changed["events"][0]["value_atoms"] = "11"
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator.validate_batch(changed, {**self.state, "pending": changed})
        self.assertRegex(batch["batch_id"], conformance.HEX32)

        changed = json.loads(json.dumps(batch))
        changed["events"][0]["coinbase"] = 0
        changed["batch_id"] = coordinator.batch_id(
            {key: value for key, value in changed.items() if key != "batch_id"}
        )
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator.validate_batch(changed, {**self.state, "pending": changed})

    def test_repeated_locking_does_not_grow_the_lock_file(self) -> None:
        for _ in range(3):
            with coordinator.state_lock(self.state_path):
                pass
        lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        self.assertLessEqual(lock_path.stat().st_size, 1)


if __name__ == "__main__":
    unittest.main()
