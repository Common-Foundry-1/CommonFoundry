#!/usr/bin/env python3
"""Qualify authenticated release update, restart, and rollback behavior."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import release_integrity as integrity


SCENARIO_SCHEMA = "CMFD_UPDATE_ROLLBACK_SCENARIO_V1"
PROBE_SCHEMA = "CMFD_INSTALLED_RELEASE_PROBE_V1"
REPORT_SCHEMA = "CMFD_UPDATE_ROLLBACK_QUALIFICATION_V1"
MAX_SCENARIO_BYTES = 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_COMMAND_TOKENS = 128
COMMAND_NAMES = {
    "apply_candidate",
    "attempt_interrupted_candidate",
    "install_baseline",
    "probe_active",
    "reapply_candidate",
    "restart_candidate",
    "rollback",
}
SEMVER_RE = re.compile(
    r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
PLACEHOLDERS = {
    "{baseline_stage}": "baseline_stage",
    "{candidate_stage}": "candidate_stage",
    "{install_root}": "install_root",
    "{python}": "python",
    "{scenario_directory}": "scenario_directory",
}


class QualificationError(RuntimeError):
    """An update/rollback qualification invariant failed."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _host_platform_label() -> str:
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64"}:
        raise QualificationError("update qualification host is not x86-64")
    if sys.platform == "win32":
        return "windows-x86_64"
    if sys.platform.startswith("linux"):
        return "linux-x86_64"
    raise QualificationError("update qualification host operating system is unsupported")


def _read_scenario(path: Path) -> tuple[dict[str, object], bytes]:
    path = integrity._regular_file(path, "update qualification scenario")
    with integrity._stable_regular_handle(path, "update qualification scenario") as (
        _,
        handle,
        opened,
    ):
        if opened.st_size > MAX_SCENARIO_BYTES:
            raise QualificationError("update qualification scenario exceeds its size limit")
        data = handle.read(MAX_SCENARIO_BYTES + 1)
    try:
        scenario = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError("update qualification scenario is not valid JSON") from error
    if not isinstance(scenario, dict) or integrity._canonical_json(scenario) != data:
        raise QualificationError("update qualification scenario is not canonical JSON")
    if set(scenario) != {"commands", "platform", "schema", "timeout_seconds"}:
        raise QualificationError("update qualification scenario has unknown or missing fields")
    if scenario["schema"] != SCENARIO_SCHEMA:
        raise QualificationError("update qualification scenario schema is unsupported")
    if scenario["platform"] not in {"linux-x86_64", "windows-x86_64"}:
        raise QualificationError("update qualification platform is unsupported")
    timeout = scenario["timeout_seconds"]
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or timeout < 1
        or timeout > 3600
    ):
        raise QualificationError("update qualification timeout is invalid")
    commands = scenario["commands"]
    if not isinstance(commands, dict) or set(commands) != COMMAND_NAMES:
        raise QualificationError("update qualification commands are incomplete")
    for name, command in commands.items():
        if (
            not isinstance(command, list)
            or not command
            or len(command) > MAX_COMMAND_TOKENS
            or any(
                not isinstance(token, str)
                or not token
                or len(token) > 4096
                or "\x00" in token
                or "\r" in token
                or "\n" in token
                for token in command
            )
        ):
            raise QualificationError(f"update qualification command is invalid: {name}")
    return scenario, data


def _semver(value: object) -> tuple[int, int, int, tuple[tuple[int, object], ...] | None]:
    if not isinstance(value, str):
        raise QualificationError("authenticated release version is not a string")
    match = SEMVER_RE.fullmatch(value)
    if match is None:
        raise QualificationError(f"authenticated release version is not SemVer: {value}")
    major, minor, patch, prerelease = match.groups()
    parsed_prerelease = None
    if prerelease is not None:
        identifiers = []
        for identifier in prerelease.split("."):
            if identifier.isdigit():
                if len(identifier) > 1 and identifier.startswith("0"):
                    raise QualificationError(
                        f"authenticated release version is not SemVer: {value}"
                    )
                identifiers.append((0, int(identifier)))
            else:
                identifiers.append((1, identifier))
        parsed_prerelease = tuple(identifiers)
    return int(major), int(minor), int(patch), parsed_prerelease


def _newer(candidate: object, baseline: object) -> bool:
    candidate_version = _semver(candidate)
    baseline_version = _semver(baseline)
    if candidate_version[:3] != baseline_version[:3]:
        return candidate_version[:3] > baseline_version[:3]
    candidate_pre = candidate_version[3]
    baseline_pre = baseline_version[3]
    if candidate_pre is None:
        return baseline_pre is not None
    if baseline_pre is None:
        return False
    for candidate_id, baseline_id in zip(candidate_pre, baseline_pre):
        if candidate_id == baseline_id:
            continue
        if candidate_id[0] != baseline_id[0]:
            return candidate_id[0] < baseline_id[0]
        return candidate_id[1] > baseline_id[1]
    return len(candidate_pre) > len(baseline_pre)


def _release_identity(stage: Path, receipt: dict[str, object]) -> dict[str, str]:
    files = receipt.get("files")
    rows = (
        {
            row.get("name"): row
            for row in files
            if isinstance(row, dict) and isinstance(row.get("name"), str)
        }
        if isinstance(files, list)
        else {}
    )
    network_row = rows.get(integrity.PRODUCTION_RC_NETWORK_INFO_NAME)
    if not isinstance(network_row, dict):
        raise QualificationError("authenticated release omits NETWORK-INFO.json")
    path = stage / integrity.PRODUCTION_RC_NETWORK_INFO_NAME
    network_bytes = integrity._read_bounded_generated_file(
        path,
        "authenticated release network information",
        integrity.MAX_RELEASE_GATE_JSON_BYTES,
    )
    if (
        network_row.get("sha256") != _sha256(network_bytes)
        or network_row.get("size") != len(network_bytes)
    ):
        raise QualificationError("authenticated NETWORK-INFO.json changed after verification")
    try:
        value = integrity._json_object_bytes(
            network_bytes, "authenticated release network information"
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError("authenticated network information is invalid") from error
    if integrity._canonical_json(value) != network_bytes:
        raise QualificationError("authenticated network information is not canonical")
    network = value.get("network")
    proof = value.get("proof_of_work")
    if not isinstance(network, dict) or not isinstance(proof, dict):
        raise QualificationError("authenticated network information is incomplete")
    network_id = network.get("network_id")
    genesis = network.get("virtual_genesis_hash")
    name = network.get("name")
    commit = receipt.get("commit")
    version = receipt.get("version")
    signature = receipt.get("signature")
    checksum = signature.get("checksum_sha256") if isinstance(signature, dict) else None
    if (
        not isinstance(network_id, str)
        or not integrity.HEX256_RE.fullmatch(network_id)
        or not isinstance(genesis, str)
        or not integrity.HEX256_RE.fullmatch(genesis)
        or not isinstance(name, str)
        or not name
        or not isinstance(commit, str)
        or not integrity.FULL_COMMIT_RE.fullmatch(commit)
        or proof.get("build_source_commit") != commit
        or not isinstance(version, str)
        or not isinstance(checksum, str)
        or not integrity.HEX256_RE.fullmatch(checksum)
    ):
        raise QualificationError("authenticated release identity is inconsistent")
    return {
        "checksum_sha256": checksum,
        "commit": commit,
        "network_id": network_id,
        "network_name": name,
        "version": version,
        "virtual_genesis_hash": genesis,
    }


def _expand_command(command: list[str], values: dict[str, str]) -> list[str]:
    expanded = []
    for token in command:
        result = token
        for placeholder, key in PLACEHOLDERS.items():
            result = result.replace(placeholder, values[key])
        if re.search(r"\{[A-Za-z_][A-Za-z0-9_]*\}", result):
            raise QualificationError(f"unknown command placeholder: {result}")
        expanded.append(result)
    return expanded


def _run_command(
    *,
    name: str,
    command: list[str],
    values: dict[str, str],
    environment: dict[str, str],
    install_root: Path,
    timeout: int,
    expect_success: bool,
) -> tuple[bytes, dict[str, object]]:
    expanded = _expand_command(command, values)
    with tempfile.TemporaryDirectory(prefix="cmfd-qualification-output-") as directory:
        stdout_path = Path(directory) / "stdout"
        stderr_path = Path(directory) / "stderr"
        try:
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                completed = subprocess.run(
                    expanded,
                    cwd=install_root,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    check=False,
                    timeout=timeout,
                )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise QualificationError(f"qualification command could not complete: {name}") from error
        stdout_size = stdout_path.stat().st_size
        stderr_size = stderr_path.stat().st_size
        if (
            stdout_size > MAX_COMMAND_OUTPUT_BYTES
            or stderr_size > MAX_COMMAND_OUTPUT_BYTES
        ):
            raise QualificationError(f"qualification command output is too large: {name}")
        stdout_bytes = stdout_path.read_bytes()
        stderr_bytes = stderr_path.read_bytes()
    succeeded = completed.returncode == 0
    if succeeded != expect_success:
        expected = "succeed" if expect_success else "fail"
        raise QualificationError(f"qualification command did not {expected}: {name}")
    return stdout_bytes, {
        "command": name,
        "exit_code": completed.returncode,
        "stderr_bytes": len(stderr_bytes),
        "stderr_sha256": _sha256(stderr_bytes),
        "stdout_bytes": len(stdout_bytes),
        "stdout_sha256": _sha256(stdout_bytes),
    }


def _probe_active(
    *, stdout: bytes, expected: dict[str, str]
) -> dict[str, object]:
    try:
        probe = json.loads(stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError("installed release probe is not valid JSON") from error
    if not isinstance(probe, dict) or integrity._canonical_json(probe) != stdout:
        raise QualificationError("installed release probe is not canonical JSON")
    expected_probe = {
        **expected,
        "healthy": True,
        "schema": PROBE_SCHEMA,
    }
    if probe != expected_probe:
        raise QualificationError("installed release probe reported the wrong active release")
    return probe


def qualify_update_rollback(
    *,
    baseline_stage: Path,
    candidate_stage: Path,
    allowed_signers: Path,
    signer_identity: str,
    ssh_keygen: Path,
    scenario_path: Path,
    install_root: Path,
    report_path: Path,
) -> dict[str, object]:
    baseline_stage = integrity._regular_directory(
        baseline_stage, "baseline authenticated release"
    )
    candidate_stage = integrity._regular_directory(
        candidate_stage, "candidate authenticated release"
    )
    if os.path.samefile(baseline_stage, candidate_stage):
        raise QualificationError("baseline and candidate releases must be different")
    scenario_path = integrity._regular_file(
        scenario_path, "update qualification scenario"
    )
    scenario, scenario_bytes = _read_scenario(scenario_path)
    if scenario["platform"] != _host_platform_label():
        raise QualificationError("update qualification scenario targets another platform")
    try:
        baseline_receipt = integrity.verify_signed_download(
            stage=baseline_stage,
            allowed_signers=allowed_signers,
            signer_identity=signer_identity,
            ssh_keygen=ssh_keygen,
        )
        candidate_receipt = integrity.verify_signed_download(
            stage=candidate_stage,
            allowed_signers=allowed_signers,
            signer_identity=signer_identity,
            ssh_keygen=ssh_keygen,
        )
    except integrity.IntegrityError as error:
        raise QualificationError(f"release authentication failed: {error}") from error
    baseline = _release_identity(baseline_stage, baseline_receipt)
    candidate = _release_identity(candidate_stage, candidate_receipt)
    baseline_signature = baseline_receipt.get("signature")
    candidate_signature = candidate_receipt.get("signature")
    trust_fields = {
        "allowed_signers_sha256",
        "namespace",
        "signer_identity",
        "verifier_sha256",
    }
    if not isinstance(baseline_signature, dict) or not isinstance(
        candidate_signature, dict
    ):
        raise QualificationError("authenticated release signer receipt is incomplete")
    trust = {field: baseline_signature.get(field) for field in trust_fields}
    if (
        any(not isinstance(value, str) or not value for value in trust.values())
        or trust != {field: candidate_signature.get(field) for field in trust_fields}
    ):
        raise QualificationError("baseline and candidate do not share one trusted signer policy")
    if not _newer(candidate["version"], baseline["version"]):
        raise QualificationError("candidate release is not newer than the baseline")
    for field in ("network_id", "network_name", "virtual_genesis_hash"):
        if candidate[field] != baseline[field]:
            raise QualificationError(f"candidate release changes network identity: {field}")
    install_root = Path(os.path.abspath(os.fspath(install_root)))
    parent = integrity._regular_directory(
        install_root.parent, "update qualification install parent"
    )
    if install_root.exists():
        raise QualificationError("update qualification install root already exists")
    for protected in (baseline_stage, candidate_stage):
        if install_root.is_relative_to(protected) or protected.is_relative_to(
            install_root
        ):
            raise QualificationError("update qualification install root overlaps a release")
    report_path = Path(os.path.abspath(os.fspath(report_path)))
    if report_path.exists():
        raise QualificationError("update qualification report already exists")
    integrity._regular_directory(
        report_path.parent, "update qualification report parent"
    )
    if report_path.is_relative_to(install_root):
        raise QualificationError("update qualification report must be outside the install root")
    install_root.mkdir(mode=0o700)
    if not install_root.is_dir() or install_root.parent != parent:
        raise QualificationError("update qualification install root could not be created")
    values = {
        "baseline_stage": str(baseline_stage),
        "candidate_stage": str(candidate_stage),
        "install_root": str(install_root),
        "python": sys.executable,
        "scenario_directory": str(scenario_path.parent),
    }
    inherited_names = {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {
        name: value for name, value in os.environ.items() if name in inherited_names
    }
    environment.update(
        {
            "CMFD_QUAL_BASELINE_CHECKSUM": baseline["checksum_sha256"],
            "CMFD_QUAL_BASELINE_COMMIT": baseline["commit"],
            "CMFD_QUAL_BASELINE_VERSION": baseline["version"],
            "CMFD_QUAL_CANDIDATE_CHECKSUM": candidate["checksum_sha256"],
            "CMFD_QUAL_CANDIDATE_COMMIT": candidate["commit"],
            "CMFD_QUAL_CANDIDATE_VERSION": candidate["version"],
            "CMFD_QUAL_INSTALL_ROOT": str(install_root),
            "CMFD_QUAL_NETWORK_ID": baseline["network_id"],
            "CMFD_QUAL_NETWORK_NAME": baseline["network_name"],
            "CMFD_QUAL_VIRTUAL_GENESIS_HASH": baseline["virtual_genesis_hash"],
        }
    )
    commands = scenario["commands"]
    timeout = scenario["timeout_seconds"]
    steps = []

    def action_and_probe(
        action: str, expected: dict[str, str], *, expect_success: bool = True
    ) -> None:
        _, action_receipt = _run_command(
            name=action,
            command=commands[action],
            values=values,
            environment=environment,
            install_root=install_root,
            timeout=timeout,
            expect_success=expect_success,
        )
        probe_stdout, probe_receipt = _run_command(
            name="probe_active",
            command=commands["probe_active"],
            values=values,
            environment=environment,
            install_root=install_root,
            timeout=timeout,
            expect_success=True,
        )
        probe = _probe_active(stdout=probe_stdout, expected=expected)
        steps.append(
            {"action": action_receipt, "active": probe, "probe": probe_receipt}
        )

    action_and_probe("install_baseline", baseline)
    action_and_probe(
        "attempt_interrupted_candidate", baseline, expect_success=False
    )
    action_and_probe("apply_candidate", candidate)
    action_and_probe("restart_candidate", candidate)
    action_and_probe("rollback", baseline)
    action_and_probe("reapply_candidate", candidate)
    try:
        if (
            integrity.verify_signed_download(
                stage=baseline_stage,
                allowed_signers=allowed_signers,
                signer_identity=signer_identity,
                ssh_keygen=ssh_keygen,
            )
            != baseline_receipt
            or integrity.verify_signed_download(
                stage=candidate_stage,
                allowed_signers=allowed_signers,
                signer_identity=signer_identity,
                ssh_keygen=ssh_keygen,
            )
            != candidate_receipt
        ):
            raise QualificationError("authenticated release receipt changed during qualification")
    except integrity.IntegrityError as error:
        raise QualificationError(
            f"release reauthentication failed after qualification: {error}"
        ) from error
    report = {
        "baseline": baseline,
        "candidate": candidate,
        "platform": scenario["platform"],
        "scenario_sha256": _sha256(scenario_bytes),
        "schema": REPORT_SCHEMA,
        "status": "qualified",
        "steps": steps,
        "trust": trust,
    }
    integrity._write_new(report_path, integrity._canonical_json(report))
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-stage", type=Path, required=True)
    parser.add_argument("--candidate-stage", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--signer-identity", required=True)
    parser.add_argument("--ssh-keygen", type=Path, required=True)
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        report = qualify_update_rollback(
            baseline_stage=args.baseline_stage,
            candidate_stage=args.candidate_stage,
            allowed_signers=args.allowed_signers,
            signer_identity=args.signer_identity,
            ssh_keygen=args.ssh_keygen,
            scenario_path=args.scenario,
            install_root=args.install_root,
            report_path=args.report,
        )
    except (QualificationError, integrity.IntegrityError, OSError) as error:
        print(f"update-rollback-qualification: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
