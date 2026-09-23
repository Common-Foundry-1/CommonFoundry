#!/usr/bin/env python3
"""Read-only 20 -> 5 -> 1 GPU qualification collector and fail-closed analyzer.

This tool never starts/stops miners or nodes. The operator stages an isolated
ProductionV4 network and drops workers manually; the tool only polls loopback
status endpoints and analyzes retained logs. It never approves difficulty.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit


CONFIG_SCHEMA = "CommonFoundry/DropoutRehearsalConfig/v1"
SAMPLE_SCHEMA = "CommonFoundry/DropoutRehearsalSample/v1"
REPORT_SCHEMA = "CommonFoundry/DropoutRehearsalReport/v1"
INITIAL_TARGET_5X = "000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb"
POW_LIMIT_RC = "003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
MAX_CAPTURE_SECONDS = 6 * 60 * 60
MAX_RESPONSE_BYTES = 2_000_000
EVENT_PREFIXES = {
    "CMFD_DROPOUT_MINER_WINNER ": "winner",
    "CMFD_DROPOUT_MINER_JOB_SWITCH ": "job_switch",
    "CMFD_DROPOUT_POOL_PROOF ": "proof",
    "CMFD_DROPOUT_POOL_ADMISSION ": "admission",
}


class RehearsalError(ValueError):
    pass


def _hex32(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise RehearsalError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _loopback_url(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise RehearsalError(f"{path} URL must be a string")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != path
        or parsed.port is None
    ):
        raise RehearsalError(f"URL must be exact loopback http://127.0.0.1:PORT{path}")
    return value


def load_config(path: Path) -> dict:
    if not path.is_absolute() or not path.is_file():
        raise RehearsalError("config must be an existing absolute file")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or config.get("schema") != CONFIG_SCHEMA:
        raise RehearsalError("wrong rehearsal config schema")
    for key, endpoint in (
        ("node_b_url", "/v1/status"),
        ("pool_url", "/api/v1/pool"),
    ):
        _loopback_url(config.get(key), endpoint)
    if urlsplit(config["node_b_url"]).port == urlsplit(config["pool_url"]).port:
        raise RehearsalError("node B and pool dashboard must use independent endpoints")
    _hex32(config.get("network_id"), "network_id")
    _hex32(config.get("consensus_fingerprint"), "consensus_fingerprint")
    if config.get("initial_target") != INITIAL_TARGET_5X:
        raise RehearsalError("this harness requires the specified 5x starting target")
    if config.get("pow_limit") != POW_LIMIT_RC:
        raise RehearsalError("this harness requires the RC minimum target")
    phases = config.get("phases")
    if not isinstance(phases, list) or len(phases) != 3:
        raise RehearsalError("phases must contain exactly 20, 5 and 1 workers")
    prior: set[str] | None = None
    for phase, expected in zip(phases, (20, 5, 1), strict=True):
        if not isinstance(phase, dict) or phase.get("gpu_count") != expected:
            raise RehearsalError("phase GPU counts must be 20, 5, 1")
        workers = phase.get("workers")
        if (
            not isinstance(workers, list)
            or len(workers) != expected
            or any(not isinstance(name, str) or not name for name in workers)
            or len(set(workers)) != expected
        ):
            raise RehearsalError(f"phase {expected} needs {expected} distinct worker names")
        current = set(workers)
        if prior is not None and not current < prior:
            raise RehearsalError("each dropout phase must retain a strict subset of workers")
        prior = current
        if not isinstance(phase.get("minimum_blocks"), int) or phase["minimum_blocks"] < 2:
            raise RehearsalError("each phase must require at least two real blocks")
    if (
        not isinstance(config.get("minimum_phase_seconds"), int)
        or not 30 <= config["minimum_phase_seconds"] <= MAX_CAPTURE_SECONDS
    ):
        raise RehearsalError("minimum_phase_seconds must be 30..21600")
    if (
        not isinstance(config.get("maximum_transition_seconds"), int)
        or not 1 <= config["maximum_transition_seconds"] <= 120
    ):
        raise RehearsalError("maximum_transition_seconds must be 1..120")
    return config


def _fetch_json(url: str) -> dict:
    parsed = urlsplit(url)
    connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=2)
    try:
        connection.request("GET", parsed.path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise RehearsalError(f"HTTP {response.status} at {url}")
        body = response.read(MAX_RESPONSE_BYTES + 1)
    finally:
        connection.close()
    if len(body) > MAX_RESPONSE_BYTES:
        raise RehearsalError("status response exceeded 2 MB")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise RehearsalError("status response was not an object")
    return value


def _node_status(value: dict) -> dict:
    return {
        key: value.get(key)
        for key in (
            "network_id", "consensus_fingerprint", "proof_profile", "accepted_height",
            "tip", "expected_target", "storage_healthy", "proof_verification_active",
            "proof_verification_queued", "proof_verification_mode", "peers",
        )
    }


def _pool_status(value: dict) -> dict:
    pool = value.get("pool")
    if not isinstance(pool, dict):
        raise RehearsalError("dashboard response has no pool object")
    return {
        key: pool.get(key)
        for key in (
            "network_id", "consensus_fingerprint", "proof_profile", "accepted_height", "tip",
            "expected_target", "storage_healthy", "peers", "current_job_id", "active_connections",
            "active_share_verifications", "queued_share_verifications", "workers",
        )
    }


def _poll(executor: ThreadPoolExecutor, config: dict) -> dict:
    started = time.monotonic_ns()
    urls = [config[key] for key in ("node_b_url", "pool_url")]
    futures = [executor.submit(_fetch_json, url) for url in urls]
    fetched: list[dict | None] = []
    errors: list[str] = []
    for label, future in zip(("node_b", "pool"), futures, strict=True):
        try:
            fetched.append(future.result())
        except (OSError, ValueError, http.client.HTTPException, json.JSONDecodeError) as error:
            fetched.append(None)
            errors.append(f"{label}: {error}")
    try:
        pool = _pool_status(fetched[1]) if fetched[1] is not None else None
    except RehearsalError as error:
        pool = None
        errors.append(f"pool: {error}")
    return {
        "schema": SAMPLE_SCHEMA,
        "sample_started_monotonic_ns": started,
        "sample_finished_monotonic_ns": time.monotonic_ns(),
        "wall_time_unix_ns": time.time_ns(),
        "node_a": {key: pool.get(key) for key in (
            "network_id", "consensus_fingerprint", "proof_profile", "accepted_height", "tip",
            "expected_target", "storage_healthy", "peers",
        )} if pool is not None else None,
        "node_b": _node_status(fetched[0]) if fetched[0] is not None else None,
        "pool": pool,
        "errors": errors,
    }


def _atomic_new_json(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def capture(config_path: Path, output: Path, seconds: int, interval: float) -> int:
    config = load_config(config_path)
    if not 1 <= seconds <= MAX_CAPTURE_SECONDS:
        raise RehearsalError("capture duration must be 1..21600 seconds")
    if not 0.5 <= interval <= 30 or not math.isfinite(interval):
        raise RehearsalError("sample interval must be 0.5..30 seconds")
    if not output.is_absolute() or output.exists():
        raise RehearsalError("output must be an absent absolute directory")
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = _poll(executor, config)
        if first["errors"]:
            raise RehearsalError("initial endpoints unavailable: " + "; ".join(first["errors"]))
        validate_sample_identity(first, config, initial=True)
        output.mkdir()
        _atomic_new_json(output / "CONFIG.json", config)
        count = 0
        completed = True
        deadline = time.monotonic() + seconds
        try:
            with (output / "SAMPLES.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
                sample = first
                while True:
                    stream.write(json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n")
                    stream.flush()
                    count += 1
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(min(interval, max(0, deadline - time.monotonic())))
                    sample = _poll(executor, config)
        except KeyboardInterrupt:
            completed = False
        _atomic_new_json(output / "CAPTURE.json", {
            "schema": "CommonFoundry/DropoutRehearsalCapture/v1",
            "completed": completed,
            "samples": count,
            "requested_seconds": seconds,
            "interval_seconds": interval,
        })
    return 0 if completed else 130


def validate_sample_identity(sample: dict, config: dict, *, initial: bool = False) -> None:
    for label in ("node_a", "node_b"):
        node = sample.get(label)
        if not isinstance(node, dict):
            raise RehearsalError(f"{label} status is missing")
        if node.get("network_id") != config["network_id"]:
            raise RehearsalError(f"{label} network ID mismatch")
        if node.get("consensus_fingerprint") != config["consensus_fingerprint"]:
            raise RehearsalError(f"{label} consensus fingerprint mismatch")
        if node.get("proof_profile") != "ProductionV4":
            raise RehearsalError(f"{label} is not ProductionV4")
        if node.get("storage_healthy") is not True:
            raise RehearsalError(f"{label} storage is not healthy")
        if label == "node_b" and not isinstance(node.get("proof_verification_mode"), str):
            raise RehearsalError("node B did not report its proof-verification mode")
        if initial and (
            node.get("accepted_height") != 0 or node.get("expected_target") != INITIAL_TARGET_5X
        ):
            raise RehearsalError(f"{label} was not observed at the exact 5x genesis target")
    pool = sample.get("pool")
    if not isinstance(pool, dict):
        raise RehearsalError("pool status is missing")
    if initial and (
        pool.get("accepted_height") != 0
        or sample["node_a"].get("tip") != sample["node_b"].get("tip")
    ):
        raise RehearsalError("pool and node B did not start at the same genesis")


def _read_jsonl(path: Path, maximum_bytes: int) -> list[dict]:
    if not path.is_file() or path.stat().st_size > maximum_bytes:
        raise RehearsalError(f"missing or oversized evidence: {path}")
    rows = []
    with path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if len(line) > MAX_RESPONSE_BYTES:
                raise RehearsalError(f"oversized line {number}: {path}")
            value = json.loads(line)
            if not isinstance(value, dict):
                raise RehearsalError(f"non-object line {number}: {path}")
            rows.append(value)
    return rows


def _events(paths: list[Path], kind: str) -> list[dict]:
    events = []
    for path in paths:
        if not path.is_file() or path.stat().st_size > 200_000_000:
            raise RehearsalError(f"missing or oversized {kind} log: {path}")
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                for prefix, event_kind in EVENT_PREFIXES.items():
                    if event_kind != kind:
                        continue
                    offset = line.find(prefix)
                    if offset >= 0:
                        event = json.loads(line[offset + len(prefix):])
                        if not isinstance(event, dict):
                            raise RehearsalError(f"malformed {kind} event in {path}")
                        events.append(event)
    return events


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _phase_worker_names(sample: dict) -> set[str]:
    workers = sample["pool"].get("workers")
    if not isinstance(workers, list):
        raise RehearsalError("pool worker list is missing")
    names = [row.get("worker") for row in workers if isinstance(row, dict)]
    if (len(names) != len(workers)
            or any(not isinstance(name, str) or not name for name in names)
            or len(names) != len(set(names))):
        raise RehearsalError("pool worker names are missing or duplicated")
    return {row["worker"] for row in workers if row.get("connected") is True}


def _first_seen_blocks(samples: list[dict], key: str) -> list[dict]:
    blocks: list[dict] = []
    previous_height = 0
    for index, sample in enumerate(samples):
        node = sample[key]
        height = node.get("accepted_height")
        tip = node.get("tip")
        if not isinstance(height, int) or height < previous_height or not isinstance(tip, str):
            raise RehearsalError(f"{key} invalid or rewinding height/tip")
        if height > previous_height:
            if height != previous_height + 1:
                raise RehearsalError(f"{key} skipped a block between status samples")
            blocks.append({"height": height, "tip": tip, "sample_index": index,
                           "observed_monotonic_ns": sample["sample_finished_monotonic_ns"]})
        previous_height = height
    return blocks


def _hex_target_within_limit(target: str, limit: str) -> bool:
    return (
        len(target) == 64
        and all(character in "0123456789abcdef" for character in target)
        and 0 < int(target, 16) <= int(limit, 16)
    )


def _positive_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def _recovery_window_seconds(blocks: list[dict], phase_start_ns: int) -> float | None:
    # This is only a descriptive observation; a passing window is not a
    # stability guarantee or policy approval. Null means no such window was seen.
    for index in range(60, len(blocks)):
        span = blocks[index]["observed_monotonic_ns"] - blocks[index - 60]["observed_monotonic_ns"]
        if span / 60e9 <= 90:
            return (blocks[index]["observed_monotonic_ns"] - phase_start_ns) / 1e9
    return None


def analyze(config: dict, samples: list[dict], miner_events: list[dict],
            proof_events: list[dict], admission_events: list[dict],
            job_switch_events: list[dict] | None = None) -> dict:
    job_switch_events = job_switch_events or []
    errors: list[str] = []
    if len(samples) < 2 or samples[0].get("schema") != SAMPLE_SCHEMA:
        raise RehearsalError("at least two schema-valid samples are required")
    last_monotonic = -1
    for sample in samples:
        if sample.get("schema") != SAMPLE_SCHEMA:
            raise RehearsalError("wrong sample schema")
        observed = sample.get("sample_finished_monotonic_ns")
        if not isinstance(observed, int) or observed <= last_monotonic:
            raise RehearsalError("sample monotonic times are not increasing")
        last_monotonic = observed
        if sample.get("errors"):
            errors.append(f"endpoint failure at sample {len(errors)}: {sample['errors']}")
            continue
        if not all(isinstance(sample.get(key), dict) for key in ("node_a", "node_b", "pool")):
            errors.append("sample lacks a complete pool and two-node status set")
            continue
        try:
            validate_sample_identity(sample, config)
        except RehearsalError as error:
            errors.append(str(error))
        for key in ("node_a", "node_b"):
            target = sample[key].get("expected_target")
            if not isinstance(target, str) or not _hex_target_within_limit(target, config["pow_limit"]):
                errors.append(f"{key} target is invalid or easier than the RC floor")
        if (
            sample["node_a"].get("tip") == sample["node_b"].get("tip")
            and sample["node_a"].get("accepted_height") == sample["node_b"].get("accepted_height")
            and sample["node_a"].get("expected_target") != sample["node_b"].get("expected_target")
        ):
            errors.append("nodes agree on tip but disagree on next work target")
    valid = [sample for sample in samples if not sample.get("errors") and all(
        isinstance(sample.get(key), dict) for key in ("node_a", "node_b", "pool")
    )]
    if not valid:
        raise RehearsalError("no complete samples")
    validate_sample_identity(valid[0], config, initial=True)
    expected_sets = [set(phase["workers"]) for phase in config["phases"]]
    stage = -1
    stage_samples: list[list[dict]] = [[], [], []]
    all_workers = expected_sets[0]
    transitional: list[dict] = []
    for sample in valid:
        actual = _phase_worker_names(sample)
        if actual - all_workers:
            errors.append("unexpected connected worker outside the isolated 20-GPU cohort")
        if actual in expected_sets:
            next_stage = expected_sets.index(actual)
            if next_stage < stage or next_stage > stage + 1:
                errors.append("worker cohort rebounded or skipped a dropout stage")
            else:
                if transitional:
                    elapsed = (sample["sample_finished_monotonic_ns"] - transitional[0]["sample_finished_monotonic_ns"]) / 1e9
                    if elapsed > config["maximum_transition_seconds"]:
                        errors.append("dropout transition exceeded configured bound")
                    transitional.clear()
                stage = next_stage
                stage_samples[stage].append(sample)
        elif stage >= 0:
            transitional.append(sample)
    if transitional:
        errors.append("capture ended during an unobserved worker-cohort transition")
    a_blocks = _first_seen_blocks(valid, "node_a")
    b_blocks = _first_seen_blocks(valid, "node_b")
    b_by_tip = {block["tip"]: block for block in b_blocks}
    admissions = {(event.get("height"), event.get("block_id")): event for event in admission_events}
    if len(admissions) != len(admission_events):
        errors.append("duplicate pool admission event")
    proofs = {(event.get("height"), event.get("nonce")): event for event in proof_events}
    if len(proofs) != len(proof_events):
        errors.append("duplicate pool proof event")
    winners = {(event.get("height"), event.get("nonce")): event for event in miner_events}
    if len(winners) != len(miner_events):
        errors.append("duplicate miner winner event")
    phase_reports = []
    for index, (phase, rows) in enumerate(zip(config["phases"], stage_samples, strict=True)):
        if not rows:
            errors.append(f"{phase['gpu_count']}-GPU phase never observed")
            phase_reports.append({"gpu_count": phase["gpu_count"], "observed": False})
            continue
        start = rows[0]["sample_finished_monotonic_ns"]
        end = rows[-1]["sample_finished_monotonic_ns"]
        dwell = (end - start) / 1e9
        if dwell < config["minimum_phase_seconds"]:
            errors.append(f"{phase['gpu_count']}-GPU phase shorter than minimum dwell")
        stage_blocks = [block for block in a_blocks if start <= block["observed_monotonic_ns"] <= end]
        if len(stage_blocks) < phase["minimum_blocks"]:
            errors.append(f"{phase['gpu_count']}-GPU phase has too few observed blocks")
        if not any(
            isinstance(peer, dict)
            and peer.get("successful_sessions", 0) > 0
            and peer.get("remote_tip") == row["node_a"].get("tip")
            for row in rows for peer in (row["node_b"].get("peers") or [])
        ):
            errors.append(f"{phase['gpu_count']}-GPU phase lacks a same-tip P2P session on node B")
        block_reports = []
        for block in stage_blocks:
            admission = admissions.get((block["height"], block["tip"]))
            nonce = admission.get("nonce") if admission else None
            proof = proofs.get((block["height"], nonce))
            winner = winners.get((block["height"], nonce))
            peer = b_by_tip.get(block["tip"])
            if not all((admission, proof, winner, peer)):
                errors.append(f"missing winner/proof/admission/P2P evidence at height {block['height']}")
            if any(event is not None and event.get("network_id") != config["network_id"]
                   for event in (admission, proof, winner)):
                errors.append(f"timing log network identity mismatch at height {block['height']}")
            if proof is not None and proof.get("proof_bytes") != 12_025_320:
                errors.append(f"unexpected ProductionV4 proof size at height {block['height']}")
            if winner is not None and winner.get("worker") not in phase["workers"]:
                errors.append(f"winner at height {block['height']} is outside the observed GPU cohort")
            if proof is not None and admission is not None and proof.get("parent") != admission.get("parent"):
                errors.append(f"replay/admission parent mismatch at height {block['height']}")
            for event, fields in (
                (winner, ("worker_job_search_seconds", "worker_job_elapsed_seconds", "worker_job_reported_work_units")),
                (proof, ("search_replay_seconds", "full_replay_seconds", "proof_seconds", "pool_evaluation_wall_seconds", "proof_bytes")),
                (admission, ("node_submission_seconds",)),
            ):
                if event is not None and any(
                    not _positive_number(event.get(field))
                    for field in fields
                ):
                    errors.append(f"invalid timing or work count at height {block['height']}")
            if winner is not None and _positive_number(winner.get("worker_job_elapsed_seconds")) \
                    and _positive_number(winner.get("worker_job_search_seconds")) \
                    and winner["worker_job_elapsed_seconds"] < winner["worker_job_search_seconds"]:
                errors.append(f"worker search time exceeds wall time at height {block['height']}")
            if proof is not None and all(_positive_number(proof.get(field)) for field in (
                "search_replay_seconds", "full_replay_seconds", "proof_seconds", "pool_evaluation_wall_seconds"
            )) and proof["pool_evaluation_wall_seconds"] + 0.001 < sum(proof[field] for field in (
                "search_replay_seconds", "full_replay_seconds", "proof_seconds"
            )):
                errors.append(f"pool stage times exceed evaluation wall time at height {block['height']}")
            p2p_observation_seconds = None
            if peer is not None:
                p2p_observation_seconds = max(0, peer["observed_monotonic_ns"] - block["observed_monotonic_ns"]) / 1e9
            block_reports.append({
                "height": block["height"], "block_id": block["tip"],
                "winner_worker": winner.get("worker") if winner else None,
                "winner_worker_reported_work_units": winner.get("worker_job_reported_work_units") if winner else None,
                "winner_worker_search_seconds": winner.get("worker_job_search_seconds") if winner else None,
                "winner_worker_elapsed_seconds": winner.get("worker_job_elapsed_seconds") if winner else None,
                "pool_search_replay_seconds": proof.get("search_replay_seconds") if proof else None,
                "pool_full_replay_seconds": proof.get("full_replay_seconds") if proof else None,
                "pool_proof_seconds": proof.get("proof_seconds") if proof else None,
                "pool_evaluation_wall_seconds": proof.get("pool_evaluation_wall_seconds") if proof else None,
                "pool_proof_bytes": proof.get("proof_bytes") if proof else None,
                "pool_node_submission_seconds": admission.get("node_submission_seconds") if admission else None,
                "node_b_p2p_first_observed_lag_seconds": p2p_observation_seconds,
            })
        rates = []
        for row in rows:
            workers = {worker["worker"]: worker for worker in row["pool"]["workers"]}
            if all(worker in workers and workers[worker].get("telemetry_age_seconds") is not None
                   and workers[worker]["telemetry_age_seconds"] <= 30 for worker in phase["workers"]):
                rate = sum(workers[worker]["reported_work_rate_fw_per_second"]
                           for worker in phase["workers"])
                if math.isfinite(rate) and rate > 0:
                    rates.append(rate)
        if not rates:
            errors.append(f"{phase['gpu_count']}-GPU phase lacks fresh search-rate samples")
        first_workers = {worker["worker"]: worker for worker in rows[0]["pool"]["workers"]}
        last_workers = {worker["worker"]: worker for worker in rows[-1]["pool"]["workers"]}
        stale_delta = 0
        for name in phase["workers"]:
            if name not in first_workers or name not in last_workers:
                errors.append(f"missing stale-share counter for {name}")
                continue
            difference = last_workers[name]["stale_shares"] - first_workers[name]["stale_shares"]
            if difference < 0:
                errors.append(f"stale-share counter rewound for {name}")
            stale_delta += max(0, difference)
        first_block_seconds = ((stage_blocks[0]["observed_monotonic_ns"] - start) / 1e9
                               if stage_blocks else None)
        phase_switches = [event for event in job_switch_events
                          if event.get("worker") in phase["workers"]
                          and event.get("new_height") in {block["height"] + 1 for block in stage_blocks}
                          and event.get("network_id") == config["network_id"]]
        if stage_blocks and not phase_switches:
            errors.append(f"{phase['gpu_count']}-GPU phase lacks superseded-job telemetry")
        phase_reports.append({
            "gpu_count": phase["gpu_count"], "observed": True,
            "dwell_seconds": dwell, "observed_blocks": len(stage_blocks),
            "first_block_after_phase_seconds": first_block_seconds,
            "observed_block_intervals_seconds": [
                (right["observed_monotonic_ns"] - left["observed_monotonic_ns"]) / 1e9
                for left, right in zip(stage_blocks, stage_blocks[1:])
            ],
            "first_10_interval_mean_seconds": (
                (stage_blocks[10]["observed_monotonic_ns"] - stage_blocks[0]["observed_monotonic_ns"]) / 1e10
                if len(stage_blocks) >= 11 else None
            ),
            "first_60_interval_mean_seconds": (
                (stage_blocks[60]["observed_monotonic_ns"] - stage_blocks[0]["observed_monotonic_ns"]) / 6e10
                if len(stage_blocks) >= 61 else None
            ),
            "first_60_interval_at_or_below_90s_recovery_seconds": _recovery_window_seconds(stage_blocks, start),
            "first_observed_next_target": rows[0]["node_a"].get("expected_target"),
            "last_observed_next_target": rows[-1]["node_a"].get("expected_target"),
            "median_aggregate_reported_search_fw_per_second": statistics.median(rates) if rates else None,
            "fresh_rate_samples": len(rates), "stale_share_delta": stale_delta,
            "superseded_job_events": len(phase_switches),
            "max_queued_share_verifications_observed": max(
                int(row["pool"].get("queued_share_verifications") or 0) for row in rows
            ),
            "node_b_verification_mode": rows[-1]["node_b"].get("proof_verification_mode"),
            "max_node_b_proof_verifications_active_observed": max(
                int(row["node_b"].get("proof_verification_active") or 0) for row in rows
            ),
            "max_node_b_proof_verifications_queued_observed": max(
                int(row["node_b"].get("proof_verification_queued") or 0) for row in rows
            ),
            "blocks": block_reports,
        })
    return {
        "schema": REPORT_SCHEMA,
        "network_id": config["network_id"],
        "consensus_fingerprint": config["consensus_fingerprint"],
        "initial_target": config["initial_target"],
        "pow_limit": config["pow_limit"],
        "measurement_complete": not errors,
        "physical_gpu_identity_verified": False,
        "separate_host_identity_verified": False,
        "exact_package_identity_verified": False,
        "final_setting_approved": False,
        "mainnet_activation_approved": False,
        "limitations": [
            "Operational telemetry is untrusted; retain original process logs and package identities.",
            "Connected worker names do not independently prove 20 distinct physical GPUs.",
            "Two loopback endpoints and peer counters do not independently prove separate physical hosts.",
            "First-seen P2P lag is poll-resolution-limited, not exact network latency.",
            "Observed search FW/s is not a complete-block production rate or a recovery SLA.",
            "No difficulty/recovery policy is selected by this tool.",
        ],
        "errors": errors,
        "phases": phase_reports,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    take = sub.add_parser("capture", help="poll two loopback endpoints into a create-new directory")
    take.add_argument("--config", type=Path, required=True)
    take.add_argument("--output", type=Path, required=True)
    take.add_argument("--seconds", type=int, required=True)
    take.add_argument("--interval", type=float, default=1)
    check = sub.add_parser("analyze", help="analyze captured samples and retained miner/pool logs")
    check.add_argument("--capture", type=Path, required=True)
    check.add_argument("--miner-log", type=Path, action="append", required=True)
    check.add_argument("--pool-log", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            return capture(args.config, args.output, args.seconds, args.interval)
        if not args.capture.is_absolute() or not args.output.is_absolute() or args.output.exists():
            raise RehearsalError("capture/output must be absolute and report output absent")
        config_path = args.capture / "CONFIG.json"
        config = load_config(config_path)
        capture_receipt = json.loads((args.capture / "CAPTURE.json").read_text(encoding="utf-8"))
        samples_path = args.capture / "SAMPLES.jsonl"
        samples = _read_jsonl(samples_path, 500_000_000)
        miners = _events(args.miner_log, "winner")
        proofs = _events([args.pool_log], "proof")
        admissions = _events([args.pool_log], "admission")
        switches = _events(args.miner_log, "job_switch")
        report = analyze(config, samples, miners, proofs, admissions, switches)
        if not capture_receipt.get("completed"):
            report["errors"].append("capture was interrupted before its bounded duration")
            report["measurement_complete"] = False
        inputs = [config_path, args.capture / "CAPTURE.json", samples_path, args.pool_log, *args.miner_log]
        report["input_sha256"] = {str(path): _sha256(path) for path in inputs}
        _atomic_new_json(args.output, report)
        print(f"wrote {args.output}; measurement_complete={report['measurement_complete']}")
        return 0 if report["measurement_complete"] else 1
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        print(f"rehearsal: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
