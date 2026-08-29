"""Independent ProductionV4 verifier, implemented without consensus-library imports.

The current implementation verifies exact proof framing, canonical field
encodings, all public BLAKE3 bindings, pinned proof identities, and the work
target. It deliberately reports the unimplemented algebraic stages instead of
claiming full cryptographic verification.
"""

from __future__ import annotations

import json
import mmap
import struct
from collections.abc import Iterable
from pathlib import Path

import blake3
from production_v4_transcript import (
    parse_fixed_commitments,
    verify_transcript_and_algebra,
)
from production_v4_wire import (
    FINAL_ACTIVATION_BYTES,
    FINAL_ACTIVATION_FIELDS,
    OUTER_HEADER_BYTES,
    inspect_proof,
)

ALGORITHM_VERSION = 4
PROOF_VERSION = 1
CORE_BINDING_VERSION = 1
PROOF_SYSTEM_DIGEST = bytes.fromhex(
    "e849e3bfc83f8f8dd0f1fc1100879417718ba2bffb92af5cd649b61c720675a3"
)
MODEL_MANIFEST_DIGEST = bytes.fromhex(
    "68f6fe674f75a363c62c275ebb11fa74aa089e9bbde5bcb952ec35b8890b575c"
)
CHALLENGE_CONTEXT = "CommonFoundry/ForgeMatrix/V4/Challenge/v1"
FINAL_ACTIVATION_CONTEXT = "CommonFoundry/ForgeMatrix/V4/FinalActivation/v1"
WORK_CONTEXT = "CommonFoundry/ForgeMatrix/V4/Work/v1"
TRANSCRIPT_STATEMENT_CONTEXT = "CommonFoundry/ForgeMatrix/V4/TranscriptStatement/v1"
STATEMENT_SCHEMA = "CommonFoundry/ForgeMatrix/V4/IndependentVerifierInput/v1"

BLOCK_KEYS = {
    "network_id",
    "previous_block",
    "transaction_root",
    "height",
    "timestamp",
    "target",
}
CANDIDATE_KEYS = {
    "algorithm_version",
    "proof_version",
    "nonce",
    "proof_system_digest",
    "model_manifest_digest",
    "challenge_digest",
    "final_activation_digest",
    "work_digest",
}


class VerificationError(ValueError):
    """Raised when an independent verification condition fails."""


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _derive(context: str, parts: Iterable[bytes | bytearray | memoryview]) -> bytes:
    hasher = blake3.blake3(derive_key_context=context)
    for part in parts:
        hasher.update(part)
    return hasher.digest()


def _require_exact_keys(
    value: dict[str, object], expected: set[str], label: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise VerificationError(
            f"{label}: key mismatch; missing={missing}, extra={extra}"
        )


def _require_uint(value: object, bits: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerificationError(f"{label}: expected an unsigned {bits}-bit integer")
    if value < 0 or value >= 1 << bits:
        raise VerificationError(f"{label}: value is outside unsigned {bits}-bit range")
    return value


def _hex32(value: object, label: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise VerificationError(f"{label}: expected exactly 64 hexadecimal characters")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise VerificationError(f"{label}: invalid hexadecimal value") from error
    if len(decoded) != 32:
        raise VerificationError(f"{label}: expected exactly 32 bytes")
    return decoded


def _byte_array32(value: object, label: str) -> bytes:
    if not isinstance(value, list) or len(value) != 32:
        raise VerificationError(f"{label}: expected an array of exactly 32 bytes")
    decoded = bytearray()
    for index, item in enumerate(value):
        decoded.append(_require_uint(item, 8, f"{label}[{index}]"))
    return bytes(decoded)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"failed to load {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{path}: top-level JSON value must be an object")
    return value


def parse_template(path: Path) -> tuple[dict[str, object], dict[str, object]]:
    """Parse the public block context from an existing miner template."""

    value = _load_json(path)
    if _require_uint(value.get("format_version"), 32, "template.format_version") != 1:
        raise VerificationError("template.format_version: expected 1")
    challenge = value.get("challenge")
    if not isinstance(challenge, dict):
        raise VerificationError("template.challenge: expected an object")
    missing = BLOCK_KEYS - set(challenge)
    if missing:
        raise VerificationError(f"template.challenge: missing keys {sorted(missing)}")
    block = {
        "network_id": _byte_array32(challenge["network_id"], "challenge.network_id"),
        "previous_block": _byte_array32(
            challenge["previous_block"], "challenge.previous_block"
        ),
        "transaction_root": _byte_array32(
            challenge["transaction_root"], "challenge.transaction_root"
        ),
        "height": _require_uint(challenge["height"], 64, "challenge.height"),
        "timestamp": _require_uint(challenge["timestamp"], 64, "challenge.timestamp"),
        "target": _byte_array32(challenge["target"], "challenge.target"),
    }
    candidate = {
        "algorithm_version": ALGORITHM_VERSION,
        "proof_version": PROOF_VERSION,
        "nonce": _require_uint(value.get("nonce"), 64, "template.nonce"),
        "proof_system_digest": PROOF_SYSTEM_DIGEST,
        "model_manifest_digest": MODEL_MANIFEST_DIGEST,
    }
    return block, candidate


def parse_statement(path: Path) -> tuple[dict[str, object], dict[str, object]]:
    """Parse the strict, portable independent-verifier statement format."""

    value = _load_json(path)
    _require_exact_keys(value, {"schema", "block", "candidate"}, "statement")
    if value["schema"] != STATEMENT_SCHEMA:
        raise VerificationError(f"statement.schema: expected {STATEMENT_SCHEMA}")
    block_value = value["block"]
    candidate_value = value["candidate"]
    if not isinstance(block_value, dict) or not isinstance(candidate_value, dict):
        raise VerificationError("statement block and candidate must be objects")
    _require_exact_keys(block_value, BLOCK_KEYS, "statement.block")
    _require_exact_keys(candidate_value, CANDIDATE_KEYS, "statement.candidate")
    block = {
        "network_id": _hex32(block_value["network_id"], "block.network_id"),
        "previous_block": _hex32(block_value["previous_block"], "block.previous_block"),
        "transaction_root": _hex32(
            block_value["transaction_root"], "block.transaction_root"
        ),
        "height": _require_uint(block_value["height"], 64, "block.height"),
        "timestamp": _require_uint(block_value["timestamp"], 64, "block.timestamp"),
        "target": _hex32(block_value["target"], "block.target"),
    }
    candidate = {
        "algorithm_version": _require_uint(
            candidate_value["algorithm_version"], 32, "candidate.algorithm_version"
        ),
        "proof_version": _require_uint(
            candidate_value["proof_version"], 32, "candidate.proof_version"
        ),
        "nonce": _require_uint(candidate_value["nonce"], 64, "candidate.nonce"),
        "proof_system_digest": _hex32(
            candidate_value["proof_system_digest"], "candidate.proof_system_digest"
        ),
        "model_manifest_digest": _hex32(
            candidate_value["model_manifest_digest"], "candidate.model_manifest_digest"
        ),
        "challenge_digest": _hex32(
            candidate_value["challenge_digest"], "candidate.challenge_digest"
        ),
        "final_activation_digest": _hex32(
            candidate_value["final_activation_digest"],
            "candidate.final_activation_digest",
        ),
        "work_digest": _hex32(candidate_value["work_digest"], "candidate.work_digest"),
    }
    return block, candidate


def challenge_digest(block: dict[str, object], candidate: dict[str, object]) -> bytes:
    return _derive(
        CHALLENGE_CONTEXT,
        (
            _u32(CORE_BINDING_VERSION),
            block["network_id"],
            block["previous_block"],
            block["transaction_root"],
            _u64(block["height"]),
            _u64(block["timestamp"]),
            block["target"],
            _u32(candidate["algorithm_version"]),
            _u32(candidate["proof_version"]),
            candidate["proof_system_digest"],
            candidate["model_manifest_digest"],
            _u64(candidate["nonce"]),
        ),
    )


def final_activation_digest_from_bytes(challenge: bytes, activation: bytes) -> bytes:
    if len(activation) != FINAL_ACTIVATION_BYTES:
        raise VerificationError(
            f"final activation: got {len(activation)} bytes, expected {FINAL_ACTIVATION_BYTES}"
        )
    return _derive(
        FINAL_ACTIVATION_CONTEXT,
        (challenge, _u64(FINAL_ACTIVATION_FIELDS), activation),
    )


def final_activation_digest_from_proof(challenge: bytes, proof_path: Path) -> bytes:
    with (
        proof_path.open("rb") as source,
        mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as proof,
    ):
        activation = memoryview(proof)[
            OUTER_HEADER_BYTES : OUTER_HEADER_BYTES + FINAL_ACTIVATION_BYTES
        ]
        try:
            return _derive(
                FINAL_ACTIVATION_CONTEXT,
                (challenge, _u64(FINAL_ACTIVATION_FIELDS), activation),
            )
        finally:
            activation.release()


def work_digest(
    candidate: dict[str, object], challenge: bytes, activation: bytes
) -> bytes:
    return _derive(
        WORK_CONTEXT,
        (
            _u32(CORE_BINDING_VERSION),
            _u32(candidate["algorithm_version"]),
            _u32(candidate["proof_version"]),
            candidate["proof_system_digest"],
            candidate["model_manifest_digest"],
            challenge,
            activation,
        ),
    )


def transcript_statement_digest(
    block: dict[str, object],
    candidate: dict[str, object],
    challenge: bytes,
    activation: bytes,
    work: bytes,
) -> bytes:
    return _derive(
        TRANSCRIPT_STATEMENT_CONTEXT,
        (
            _u32(CORE_BINDING_VERSION),
            block["network_id"],
            block["previous_block"],
            block["transaction_root"],
            _u64(block["height"]),
            _u64(block["timestamp"]),
            block["target"],
            _u32(candidate["algorithm_version"]),
            _u32(candidate["proof_version"]),
            _u64(candidate["nonce"]),
            candidate["proof_system_digest"],
            candidate["model_manifest_digest"],
            challenge,
            activation,
            work,
        ),
    )


def _require_equal(label: str, actual: object, expected: object) -> None:
    if actual != expected:
        actual_text = actual.hex() if isinstance(actual, bytes) else str(actual)
        expected_text = expected.hex() if isinstance(expected, bytes) else str(expected)
        raise VerificationError(f"{label}: got {actual_text}, expected {expected_text}")


def _json_statement(
    block: dict[str, object], candidate: dict[str, object], derived: dict[str, bytes]
) -> dict[str, object]:
    return {
        "schema": STATEMENT_SCHEMA,
        "block": {
            "network_id": block["network_id"].hex(),
            "previous_block": block["previous_block"].hex(),
            "transaction_root": block["transaction_root"].hex(),
            "height": block["height"],
            "timestamp": block["timestamp"],
            "target": block["target"].hex(),
        },
        "candidate": {
            "algorithm_version": candidate["algorithm_version"],
            "proof_version": candidate["proof_version"],
            "nonce": candidate["nonce"],
            "proof_system_digest": candidate["proof_system_digest"].hex(),
            "model_manifest_digest": candidate["model_manifest_digest"].hex(),
            "challenge_digest": derived["challenge_digest"].hex(),
            "final_activation_digest": derived["final_activation_digest"].hex(),
            "work_digest": derived["work_digest"].hex(),
        },
    }


def verify(
    proof_path: Path,
    block: dict[str, object],
    candidate: dict[str, object],
    require_candidate_claims: bool,
    fixed_artifact_record: Path | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    """Verify the implemented independent stages and return result plus statement."""

    wire = inspect_proof(proof_path)
    _require_equal(
        "algorithm version", candidate["algorithm_version"], ALGORITHM_VERSION
    )
    _require_equal("proof version", candidate["proof_version"], PROOF_VERSION)
    _require_equal(
        "proof-system digest", candidate["proof_system_digest"], PROOF_SYSTEM_DIGEST
    )
    _require_equal(
        "model-manifest digest",
        candidate["model_manifest_digest"],
        MODEL_MANIFEST_DIGEST,
    )

    challenge = challenge_digest(block, candidate)
    activation = final_activation_digest_from_proof(challenge, proof_path)
    work = work_digest(candidate, challenge, activation)
    statement_digest = transcript_statement_digest(
        block, candidate, challenge, activation, work
    )
    if require_candidate_claims:
        _require_equal("challenge digest", candidate["challenge_digest"], challenge)
        _require_equal(
            "final-activation digest", candidate["final_activation_digest"], activation
        )
        _require_equal("work digest", candidate["work_digest"], work)
    if work > block["target"]:
        raise VerificationError(
            f"work target: digest {work.hex()} is greater than target {block['target'].hex()}"
        )

    derived = {
        "challenge_digest": challenge,
        "final_activation_digest": activation,
        "work_digest": work,
        "transcript_statement_digest": statement_digest,
    }
    algebra = None
    if fixed_artifact_record is not None:
        fixed_commitments = parse_fixed_commitments(
            fixed_artifact_record,
            candidate["proof_system_digest"],
            candidate["model_manifest_digest"],
        )
        algebra = verify_transcript_and_algebra(
            proof_path,
            statement_digest,
            challenge,
            fixed_commitments,
        )
    verified_stages = [
        "exact transparent-proof framing",
        "canonical KoalaBear field encodings",
        "pinned algorithm and artifact identities",
        "challenge BLAKE3 binding",
        "final-activation BLAKE3 binding",
        "work BLAKE3 binding and target comparison",
        "transcript-statement BLAKE3 binding",
    ]
    remaining_stages = [
        "KoalaBear extension-field and Poseidon transcript replay",
        "relation equations and claim routing",
        "Merkle authentication paths",
        "BaseFold folding and terminal low-degree checks",
    ]
    if algebra is not None:
        verified_stages.extend(
            [
                "KoalaBear extension-field and Poseidon transcript replay",
                "six matrix, shift, and cubic relation repetitions",
                "opening-claim routing and three opening-reduction sumchecks",
                "BaseFold batching, FRI-message, grinding, and query transcripts",
            ]
        )
        remaining_stages = [
            "public initial-activation boundary evaluations",
            "BaseFold component and FRI Merkle authentication paths",
            "BaseFold query-fold equations and final low-degree checks",
        ]
    result = {
        "schema": "CommonFoundry/ForgeMatrix/V4/IndependentVerificationResult/v1",
        "implemented_stages_accepted": True,
        "full_cryptographic_proof_verified": False,
        "candidate_claims_verified": require_candidate_claims,
        "proof": wire,
        "algebra": algebra,
        "derived": {name: value.hex() for name, value in derived.items()},
        "target": block["target"].hex(),
        "target_met": True,
        "verified_stages": verified_stages,
        "remaining_stages": remaining_stages,
    }
    return result, _json_statement(block, candidate, derived)
