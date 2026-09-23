from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "mainnet_dropout_rehearsal.py"
SPEC = importlib.util.spec_from_file_location("mainnet_dropout_rehearsal", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
REHEARSAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REHEARSAL)


def config() -> dict:
    workers = [f"rehearsal-gpu-{number:02d}" for number in range(20)]
    return {
        "schema": REHEARSAL.CONFIG_SCHEMA,
        "node_b_url": "http://127.0.0.1:29443/v1/status",
        "pool_url": "http://127.0.0.1:29446/api/v1/pool",
        "network_id": "a" * 64,
        "consensus_fingerprint": "b" * 64,
        "initial_target": REHEARSAL.INITIAL_TARGET_5X,
        "pow_limit": REHEARSAL.POW_LIMIT_RC,
        "minimum_phase_seconds": 30,
        "maximum_transition_seconds": 10,
        "phases": [
            {"gpu_count": 20, "workers": workers, "minimum_blocks": 2},
            {"gpu_count": 5, "workers": workers[:5], "minimum_blocks": 2},
            {"gpu_count": 1, "workers": workers[:1], "minimum_blocks": 2},
        ],
    }


def sample(settings: dict, seconds: int, active: int, height: int) -> dict:
    tip = f"{height:064x}"
    peer = {"successful_sessions": 1, "remote_tip": tip, "active_connections": 1}
    common = {
        "network_id": settings["network_id"],
        "consensus_fingerprint": settings["consensus_fingerprint"],
        "proof_profile": "ProductionV4",
        "accepted_height": height,
        "tip": tip,
        "expected_target": settings["initial_target"],
        "storage_healthy": True,
        "proof_verification_mode": "in_process",
        "proof_verification_active": 0,
        "proof_verification_queued": 0,
        "peers": [peer],
    }
    workers = [
        {
            "worker": name,
            "connected": index < active,
            "stale_shares": 0,
            "telemetry_age_seconds": 1 if index < active else None,
            "reported_work_rate_fw_per_second": 25.0 if index < active else 0.0,
        }
        for index, name in enumerate(settings["phases"][0]["workers"])
    ]
    return {
        "schema": REHEARSAL.SAMPLE_SCHEMA,
        "sample_started_monotonic_ns": seconds * 1_000_000_000,
        "sample_finished_monotonic_ns": seconds * 1_000_000_000 + 1,
        "wall_time_unix_ns": 1_000_000_000_000 + seconds * 1_000_000_000,
        "node_a": dict(common),
        "node_b": dict(common),
        "pool": {**common, "current_job_id": "c" * 64, "workers": workers},
        "errors": [],
    }


def evidence(settings: dict) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict]]:
    samples = [
        sample(settings, 0, 20, 0), sample(settings, 31, 20, 1),
        sample(settings, 32, 20, 2), sample(settings, 40, 5, 2),
        sample(settings, 71, 5, 3), sample(settings, 72, 5, 4),
        sample(settings, 80, 1, 4), sample(settings, 111, 1, 5),
        sample(settings, 112, 1, 6),
    ]
    winners = []
    proofs = []
    admissions = []
    switches = []
    for height in range(1, 7):
        worker = settings["phases"][0 if height <= 2 else 1 if height <= 4 else 2]["workers"][0]
        winners.append({
            "network_id": settings["network_id"],
            "height": height, "nonce": height, "worker": worker,
            "worker_job_reported_work_units": 1024, "worker_job_search_seconds": 30.0,
            "worker_job_elapsed_seconds": 31.0,
        })
        proofs.append({
            "network_id": settings["network_id"],
            "height": height, "nonce": height, "parent": f"{height - 1:064x}",
            "search_replay_seconds": 2.0, "full_replay_seconds": 3.0,
            "proof_seconds": 15.0, "pool_evaluation_wall_seconds": 21.0,
            "proof_bytes": 12_025_320,
        })
        admissions.append({
            "network_id": settings["network_id"],
            "height": height, "nonce": height, "parent": f"{height - 1:064x}",
            "block_id": f"{height:064x}", "node_submission_seconds": 0.5,
        })
        switches.append({
            "network_id": settings["network_id"], "worker": worker,
            "new_height": height + 1, "previous_job_reported_work_units": 1024,
            "previous_job_search_seconds": 30.0,
        })
    return samples, winners, proofs, admissions, switches


class DropoutRehearsalTests(unittest.TestCase):
    def test_poll_uses_pool_node_and_independent_node_b(self) -> None:
        settings = config()
        fixture = sample(settings, 0, 0, 0)
        def response(url: str) -> dict:
            return {"pool": fixture["pool"]} if url == settings["pool_url"] else fixture["node_b"]
        with mock.patch.object(REHEARSAL, "_fetch_json", side_effect=response):
            with ThreadPoolExecutor(max_workers=2) as executor:
                observed = REHEARSAL._poll(executor, settings)
        REHEARSAL.validate_sample_identity(observed, settings, initial=True)
        self.assertEqual(observed["node_a"]["tip"], fixture["pool"]["tip"])
        self.assertEqual(observed["node_b"]["tip"], fixture["node_b"]["tip"])

    def test_capture_refuses_wrong_genesis_before_creating_output(self) -> None:
        settings = config()
        first = sample(settings, 0, 0, 0)
        first["node_b"]["expected_target"] = REHEARSAL.POW_LIMIT_RC
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            config_path.write_text(json.dumps(settings), encoding="utf-8")
            output = root / "evidence"
            with mock.patch.object(REHEARSAL, "_poll", return_value=first):
                with self.assertRaises(REHEARSAL.RehearsalError):
                    REHEARSAL.capture(config_path, output, 1, 1)
            self.assertFalse(output.exists())

    def test_config_requires_loopback_and_exact_step_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config()), encoding="utf-8")
            self.assertEqual(REHEARSAL.load_config(path)["initial_target"], REHEARSAL.INITIAL_TARGET_5X)
            settings = config()
            settings["pool_url"] = "http://example.com/api/v1/pool"
            path.write_text(json.dumps(settings), encoding="utf-8")
            with self.assertRaises(REHEARSAL.RehearsalError):
                REHEARSAL.load_config(path)
            settings = config()
            settings["phases"][2]["workers"] = ["not-a-survivor"]
            path.write_text(json.dumps(settings), encoding="utf-8")
            with self.assertRaises(REHEARSAL.RehearsalError):
                REHEARSAL.load_config(path)

    def test_complete_synthetic_evidence_is_measurement_only(self) -> None:
        settings = config()
        report = REHEARSAL.analyze(settings, *evidence(settings))
        self.assertTrue(report["measurement_complete"])
        self.assertFalse(report["final_setting_approved"])
        self.assertFalse(report["mainnet_activation_approved"])
        self.assertFalse(report["physical_gpu_identity_verified"])
        self.assertFalse(report["exact_package_identity_verified"])
        self.assertEqual([phase["observed_blocks"] for phase in report["phases"]], [2, 2, 2])
        self.assertEqual(report["phases"][0]["median_aggregate_reported_search_fw_per_second"], 500.0)
        self.assertEqual(report["phases"][2]["first_block_after_phase_seconds"], 31.0)

    def test_missing_proof_or_p2p_fails_closed(self) -> None:
        settings = config()
        samples, winners, proofs, admissions, switches = evidence(settings)
        self.assertFalse(REHEARSAL.analyze(settings, samples, winners, proofs[:-1], admissions, switches)["measurement_complete"])
        for row in samples:
            row["node_b"]["peers"] = []
        self.assertFalse(REHEARSAL.analyze(settings, samples, winners, proofs, admissions, switches)["measurement_complete"])

    def test_skipped_height_and_identity_drift_fail(self) -> None:
        settings = config()
        samples, winners, proofs, admissions, switches = evidence(settings)
        samples[2]["node_a"]["accepted_height"] = 3
        with self.assertRaises(REHEARSAL.RehearsalError):
            REHEARSAL.analyze(settings, samples, winners, proofs, admissions, switches)
        samples, winners, proofs, admissions, switches = evidence(settings)
        samples[4]["node_b"]["network_id"] = "c" * 64
        self.assertFalse(REHEARSAL.analyze(settings, samples, winners, proofs, admissions, switches)["measurement_complete"])
        samples, winners, proofs, admissions, switches = evidence(settings)
        samples[4]["node_b"]["expected_target"] = REHEARSAL.POW_LIMIT_RC
        self.assertFalse(REHEARSAL.analyze(settings, samples, winners, proofs, admissions, switches)["measurement_complete"])

    def test_wrong_winner_or_rewinding_stale_counter_fails(self) -> None:
        settings = config()
        samples, winners, proofs, admissions, switches = evidence(settings)
        winners[-1]["worker"] = settings["phases"][0]["workers"][-1]
        self.assertFalse(REHEARSAL.analyze(settings, samples, winners, proofs, admissions, switches)["measurement_complete"])
        samples, winners, proofs, admissions, switches = evidence(settings)
        samples[6]["pool"]["workers"][0]["stale_shares"] = 2
        self.assertFalse(REHEARSAL.analyze(settings, samples, winners, proofs, admissions, switches)["measurement_complete"])

    def test_missing_job_switch_fails_closed(self) -> None:
        settings = config()
        samples, winners, proofs, admissions, _switches = evidence(settings)
        self.assertFalse(REHEARSAL.analyze(settings, samples, winners, proofs, admissions)["measurement_complete"])

    def test_missing_five_gpu_phase_fails_closed(self) -> None:
        settings = config()
        samples, winners, proofs, admissions, switches = evidence(settings)
        for row in samples[3:6]:
            row["pool"]["workers"][5]["connected"] = True
        self.assertFalse(REHEARSAL.analyze(settings, samples, winners, proofs, admissions, switches)["measurement_complete"])

    def test_create_new_report_and_log_event_parse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "REPORT.json"
            REHEARSAL._atomic_new_json(report, {"ok": True})
            with self.assertRaises(FileExistsError):
                REHEARSAL._atomic_new_json(report, {"ok": False})
            log = root / "pool.log"
            log.write_text('prefix CMFD_DROPOUT_POOL_PROOF {"height":1,"nonce":2}\n', encoding="utf-8")
            self.assertEqual(REHEARSAL._events([log], "proof"), [{"height": 1, "nonce": 2}])

    def test_analyze_cli_writes_sha_linked_report(self) -> None:
        settings = config()
        samples, winners, proofs, admissions, switches = evidence(settings)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            captured = root / "capture"
            captured.mkdir()
            (captured / "CONFIG.json").write_text(json.dumps(settings), encoding="utf-8")
            (captured / "CAPTURE.json").write_text(json.dumps({"completed": True}), encoding="utf-8")
            (captured / "SAMPLES.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in samples), encoding="utf-8"
            )
            miner_log = root / "miner.log"
            pool_log = root / "pool.log"
            miner_log.write_text(
                "".join("CMFD_DROPOUT_MINER_WINNER " + json.dumps(row) + "\n" for row in winners)
                + "".join("CMFD_DROPOUT_MINER_JOB_SWITCH " + json.dumps(row) + "\n" for row in switches),
                encoding="utf-8",
            )
            pool_log.write_text(
                "".join("CMFD_DROPOUT_POOL_PROOF " + json.dumps(row) + "\n" for row in proofs)
                + "".join("CMFD_DROPOUT_POOL_ADMISSION " + json.dumps(row) + "\n" for row in admissions),
                encoding="utf-8",
            )
            report_path = root / "REPORT.json"
            arguments = [
                "analyze", "--capture", str(captured), "--miner-log", str(miner_log),
                "--pool-log", str(pool_log), "--output", str(report_path),
            ]
            self.assertEqual(REHEARSAL.main(arguments), 0)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["measurement_complete"])
            self.assertEqual(report["input_sha256"][str(miner_log)], REHEARSAL._sha256(miner_log))
            self.assertEqual(REHEARSAL.main(arguments), 2)


if __name__ == "__main__":
    unittest.main()
