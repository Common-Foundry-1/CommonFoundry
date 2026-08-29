"""Fail-closed ProductionV4 artifact and proof reproduction evidence.

This module does not import the Rust consensus implementation. It authenticates
the frozen specification, canonical vector, generated fixed artifacts, model
bank, and one full proof with the independent Python verifier.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

import blake3
from production_v4_independent_verifier import (
    ALGORITHM_VERSION,
    MODEL_MANIFEST_DIGEST,
    PROOF_SYSTEM_DIGEST,
    PROOF_VERSION,
    challenge_digest,
    final_activation_digest_from_bytes,
    parse_template,
    transcript_statement_digest,
    verify,
    work_digest,
)
from production_v4_transcript import (
    PINNED_FIXED_RECORD_DIGEST,
    authenticate_model_bank,
    parse_fixed_commitments,
)
from production_v4_wire import FINAL_ACTIVATION_BYTES, TRANSPARENT_PROOF_BYTES


REPORT_SCHEMA = "CommonFoundry/ForgeMatrix/V4/IndependentReproductionReport/v1"
VECTOR_SCHEMA = "CommonFoundry/ForgeMatrix/V4/CoreCanonicalVector/v1"
EXPECTED_NETWORK = "CommonFoundry ProductionV4 Testnet-1"
EXPECTED_NETWORK_ID = "b9e55d5a5e80c8e3d73bf81b199bc643ac9367436962c28b6aacdc37f3809962"
EXPECTED_INPUT_NAMES = {
    "MODEL-V2.bank",
    "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json",
    *(f"FORGEMATRIX-V4-FIXED-BANK-{bank}.row-major.codeword" for bank in range(3)),
    *(f"FORGEMATRIX-V4-FIXED-BANK-{bank}.tree" for bank in range(3)),
}
FROZEN_SPEC_SHA256 = {
    "docs/consensus/production-v4-core-spec-v1.md":
        "507075fb6d22b7ac0968508b18c48a09a017806e7d4e0454b71f8ae88440df84",
    "docs/consensus/production-v4-core-vector-v1.json":
        "c885ae499a65c5bb965e08f4894a0d2768d823b0e23979958f00e3db73e0b168",
    "docs/consensus/production-v4-proof-algebra-v1.md":
        "5a686ad518a7d957b8af908fb52cd58056e63da4dab578a40d4ef097654aaf33",
}
EXPECTED_WIRE = {
    "transparent_proof_exact_bytes": TRANSPARENT_PROOF_BYTES,
    "transparent_proof_max_bytes": 13_631_259,
    "proof_frame_max_bytes": 13_631_488,
    "block_frame_max_bytes": 16_777_216,
}
EXPECTED_REJECTIONS = [
    ["transparent-proof-truncated", "bytes", 12_025_319, "Length"],
    ["transparent-proof-trailing-byte", "bytes", 12_025_321, "Length"],
    ["transparent-proof-noncanonical-field", "field_value", 2_130_706_433, "Field"],
    ["proof-frame-over-limit", "bytes", 13_631_489, "SizeLimit"],
    ["block-frame-over-limit", "bytes", 16_777_217, "SizeLimit"],
]
HEX_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
HASH_CHUNK_BYTES = 8 * 1024 * 1024


class ReproductionError(ValueError):
    """Raised when reproduction evidence cannot be accepted."""


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReproductionError(f"failed to load {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReproductionError(f"{path}: top-level JSON value must be an object")
    return value


def canonical_json(value: object) -> bytes:
    """Encode canonical, LF-terminated evidence JSON."""

    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def write_new(path: Path, value: object) -> bytes:
    """Create evidence once, flush it, and verify the exact stored bytes."""

    encoded = canonical_json(value)
    try:
        with path.open("xb") as target:
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
    except FileExistsError as error:
        raise ReproductionError(f"refusing to overwrite existing report {path}") from error
    if path.read_bytes() != encoded:
        raise ReproductionError(f"stored report does not match canonical bytes: {path}")
    return encoded


def file_identity(path: Path) -> dict[str, object]:
    """Hash a stable file with bounded memory using SHA-256 and BLAKE3."""

    before = path.stat()
    sha256 = hashlib.sha256()
    blake = blake3.blake3()
    buffer = bytearray(HASH_CHUNK_BYTES)
    view = memoryview(buffer)
    counted = 0
    with path.open("rb", buffering=0) as source:
        while True:
            read = source.readinto(buffer)
            if read == 0:
                break
            sha256.update(view[:read])
            blake.update(view[:read])
            counted += read
    view.release()
    after = path.stat()
    if (
        before.st_size != counted
        or after.st_size != counted
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise ReproductionError(f"file changed while hashing: {path}")
    return {
        "name": path.name,
        "bytes": counted,
        "sha256": sha256.hexdigest(),
        "blake3": blake.hexdigest(),
    }


def toolchain_versions() -> dict[str, str | None]:
    """Capture the compiler identities visible to the reproducer process."""

    commands = {
        "git": ["git", "--version"],
        "rustc": ["rustc", "--version", "--verbose"],
        "cargo": ["cargo", "--version", "--verbose"],
        "nvcc": ["nvcc", "--version"],
    }
    versions: dict[str, str | None] = {"python": sys.version.replace("\n", " ")}
    for name, command in commands.items():
        if shutil.which(command[0]) is None:
            versions[name] = None
            continue
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = (result.stdout + result.stderr).strip()
        versions[name] = output if result.returncode == 0 else None
    return versions


def verify_frozen_spec(repo_root: Path) -> list[dict[str, object]]:
    results = []
    for relative, expected in FROZEN_SPEC_SHA256.items():
        path = repo_root / Path(relative)
        identity = file_identity(path)
        if identity["sha256"] != expected:
            raise ReproductionError(f"frozen specification identity mismatch: {relative}")
        identity["path"] = relative
        results.append(identity)
    return results


def verify_core_vector(repo_root: Path) -> dict[str, object]:
    path = repo_root / "docs/consensus/production-v4-core-vector-v1.json"
    vector = _load_json(path)
    if vector.get("schema") != VECTOR_SCHEMA:
        raise ReproductionError("ProductionV4 core vector schema mismatch")
    if vector.get("algorithm_version") != ALGORITHM_VERSION:
        raise ReproductionError("ProductionV4 core vector algorithm mismatch")
    if vector.get("proof_version") != PROOF_VERSION:
        raise ReproductionError("ProductionV4 core vector proof version mismatch")
    if vector.get("proof_system_digest") != PROOF_SYSTEM_DIGEST.hex():
        raise ReproductionError("ProductionV4 core vector proof-system digest mismatch")
    if vector.get("model_manifest_digest") != MODEL_MANIFEST_DIGEST.hex():
        raise ReproductionError("ProductionV4 core vector model-manifest digest mismatch")
    if vector.get("fixed_artifact_record_digest") != PINNED_FIXED_RECORD_DIGEST.hex():
        raise ReproductionError("ProductionV4 core vector fixed-record digest mismatch")
    if vector.get("wire") != EXPECTED_WIRE:
        raise ReproductionError("ProductionV4 core vector wire limits mismatch")
    if vector.get("rejections") != EXPECTED_REJECTIONS:
        raise ReproductionError("ProductionV4 core vector rejection set mismatch")

    block_json = vector.get("block")
    activation_json = vector.get("final_activation")
    expected = vector.get("expected")
    if not all(isinstance(value, dict) for value in (block_json, activation_json, expected)):
        raise ReproductionError("ProductionV4 core vector sections are malformed")
    block_json = dict(block_json)
    activation_json = dict(activation_json)
    expected = dict(expected)
    if activation_json != {
        "encoding": "524288 canonical KoalaBear u32 little-endian values, all zero",
        "field_count": 524_288,
        "fill_value": 0,
    }:
        raise ReproductionError("ProductionV4 core vector activation description mismatch")
    try:
        block = {
            "network_id": bytes.fromhex(str(block_json["network_id"])),
            "previous_block": bytes.fromhex(str(block_json["previous_block"])),
            "transaction_root": bytes.fromhex(str(block_json["transaction_root"])),
            "height": block_json["height"],
            "timestamp": block_json["timestamp"],
            "target": bytes.fromhex(str(block_json["target"])),
        }
        candidate = {
            "algorithm_version": ALGORITHM_VERSION,
            "proof_version": PROOF_VERSION,
            "nonce": vector["nonce"],
            "proof_system_digest": PROOF_SYSTEM_DIGEST,
            "model_manifest_digest": MODEL_MANIFEST_DIGEST,
        }
    except (KeyError, ValueError) as error:
        raise ReproductionError("ProductionV4 core vector inputs are malformed") from error
    challenge = challenge_digest(block, candidate)
    activation = final_activation_digest_from_bytes(
        challenge, bytes(FINAL_ACTIVATION_BYTES)
    )
    work = work_digest(candidate, challenge, activation)
    statement = transcript_statement_digest(block, candidate, challenge, activation, work)
    derived = {
        "challenge_digest": challenge.hex(),
        "final_activation_digest": activation.hex(),
        "work_digest": work.hex(),
        "transcript_statement_digest": statement.hex(),
    }
    if expected != derived:
        raise ReproductionError("ProductionV4 core vector derived values mismatch")
    return {"schema": VECTOR_SCHEMA, "derived": derived, "rejections_verified": 5}


def load_input_manifest(path: Path) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    manifest = _load_json(path)
    if set(manifest) != {
        "schema_version", "network", "network_id", "source_commit", "total_bytes", "files"
    }:
        raise ReproductionError("ProductionV4 input manifest keys are not canonical")
    if (
        manifest["schema_version"] != 1
        or manifest["network"] != EXPECTED_NETWORK
        or manifest["network_id"] != EXPECTED_NETWORK_ID
    ):
        raise ReproductionError("ProductionV4 input manifest identity mismatch")
    if not isinstance(manifest["source_commit"], str) or not HEX_COMMIT.fullmatch(
        manifest["source_commit"]
    ):
        raise ReproductionError("ProductionV4 input manifest source commit is invalid")
    files = manifest["files"]
    if not isinstance(files, list):
        raise ReproductionError("ProductionV4 input manifest files must be an array")
    entries: dict[str, dict[str, object]] = {}
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"name", "bytes", "sha256"}:
            raise ReproductionError("ProductionV4 input manifest file entry is malformed")
        name = entry["name"]
        if not isinstance(name, str) or name in entries:
            raise ReproductionError("ProductionV4 input manifest file name is invalid")
        if (
            isinstance(entry["bytes"], bool)
            or not isinstance(entry["bytes"], int)
            or entry["bytes"] < 0
            or not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
        ):
            raise ReproductionError(f"ProductionV4 input identity is invalid: {name}")
        entries[name] = entry
    if set(entries) != EXPECTED_INPUT_NAMES:
        raise ReproductionError("ProductionV4 input manifest file set mismatch")
    if manifest["total_bytes"] != sum(int(entry["bytes"]) for entry in entries.values()):
        raise ReproductionError("ProductionV4 input manifest total byte count mismatch")
    return manifest, entries


def _require_manifest_identity(
    identity: dict[str, object], entry: dict[str, object]
) -> None:
    if identity["bytes"] != entry["bytes"] or identity["sha256"] != entry["sha256"]:
        raise ReproductionError(f"input identity mismatch: {entry['name']}")


def verify_artifacts(
    input_manifest: Path,
    model_bank: Path,
    fixed_record: Path,
    artifact_dir: Path,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    manifest, entries = load_input_manifest(input_manifest)
    identities = []
    model_identity = file_identity(model_bank)
    _require_manifest_identity(model_identity, entries["MODEL-V2.bank"])
    identities.append(model_identity)
    fixed_identity = file_identity(fixed_record)
    _require_manifest_identity(
        fixed_identity, entries["FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"]
    )
    identities.append(fixed_identity)

    parse_fixed_commitments(fixed_record, PROOF_SYSTEM_DIGEST, MODEL_MANIFEST_DIGEST)
    authenticate_model_bank(fixed_record, model_bank, MODEL_MANIFEST_DIGEST)
    record = _load_json(fixed_record)
    banks = record.get("banks")
    if not isinstance(banks, list) or len(banks) != 3:
        raise ReproductionError("fixed artifact record bank set is malformed")
    for bank, record_bank in enumerate(banks):
        if not isinstance(record_bank, dict):
            raise ReproductionError(f"fixed artifact record bank {bank} is malformed")
        metadata_path = artifact_dir / f"FORGEMATRIX-V4-FIXED-BANK-{bank}.json"
        if _load_json(metadata_path) != record_bank:
            raise ReproductionError(f"fixed artifact metadata mismatch for bank {bank}")
        identities.append(file_identity(metadata_path))

        canonical_path = artifact_dir / f"FORGEMATRIX-V4-FIXED-BANK-{bank}.codeword"
        canonical = file_identity(canonical_path)
        if (
            canonical["bytes"] != record_bank.get("codeword_bytes")
            or canonical["blake3"] != bytes(record_bank["codeword_blake3"]).hex()
        ):
            raise ReproductionError(f"canonical codeword mismatch for bank {bank}")
        identities.append(canonical)

        for suffix in ("row-major.codeword", "tree"):
            name = f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}"
            identity = file_identity(artifact_dir / name)
            _require_manifest_identity(identity, entries[name])
            if suffix == "tree" and identity["blake3"] != bytes(
                record_bank["tree_blake3"]
            ).hex():
                raise ReproductionError(f"fixed Merkle tree mismatch for bank {bank}")
            identities.append(identity)
    return manifest, identities


def build_report(
    *,
    repo_root: Path,
    source_commit: str,
    operator: str,
    input_manifest: Path,
    model_bank: Path,
    fixed_record: Path,
    artifact_dir: Path,
    template: Path,
    proof: Path,
    fresh_generation_attested: bool,
    generation_commands: list[str],
) -> dict[str, object]:
    if HEX_COMMIT.fullmatch(source_commit) is None:
        raise ReproductionError("reproducer source commit must be lowercase 40- or 64-hex")
    if not operator.strip():
        raise ReproductionError("reproducer operator must not be empty")
    if fresh_generation_attested and not generation_commands:
        raise ReproductionError("fresh generation attestation requires generation commands")
    if any(not command.strip() for command in generation_commands):
        raise ReproductionError("generation commands must not be empty")
    toolchains = toolchain_versions()
    if fresh_generation_attested and any(
        toolchains[name] is None for name in ("rustc", "cargo", "nvcc")
    ):
        raise ReproductionError(
            "fresh generation attestation requires visible rustc, cargo, and nvcc versions"
        )
    specs = verify_frozen_spec(repo_root)
    vector = verify_core_vector(repo_root)
    manifest, artifacts = verify_artifacts(
        input_manifest, model_bank, fixed_record, artifact_dir
    )
    block, candidate = parse_template(template)
    proof_result, statement = verify(
        proof,
        block,
        candidate,
        False,
        fixed_record,
        model_bank,
    )
    if not proof_result["full_cryptographic_proof_verified"]:
        raise ReproductionError("independent full cryptographic proof verification is incomplete")
    return {
        "schema": REPORT_SCHEMA,
        "status": "verified",
        "reproduction_complete": fresh_generation_attested,
        "fresh_generation_attested": fresh_generation_attested,
        "operator": operator.strip(),
        "reproducer_source_commit": source_commit,
        "artifact_generation_source_commit": manifest["source_commit"],
        "environment": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "byteorder": sys.byteorder,
        },
        "toolchains": toolchains,
        "generation_commands": generation_commands,
        "frozen_specifications": specs,
        "core_vector": vector,
        "input_manifest": file_identity(input_manifest),
        "artifacts": artifacts,
        "proof_verification": proof_result,
        "statement": statement,
    }
