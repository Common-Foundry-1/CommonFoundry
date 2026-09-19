#!/usr/bin/env python3
"""Fail-closed signed approvals for ProductionV4 activation.

This module deliberately does not choose signer identities or trust roots.  It
turns caller-supplied, dedicated OpenSSH allowed-signers authorities into a
canonical pair of role-scoped approval payloads and verifies their detached
signatures over the exact bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

SUBJECT_SCHEMA = "CMFD_PRODUCTION_V4_ACTIVATION_APPROVAL_SUBJECT_V1"
APPROVAL_SCHEMA = "CMFD_PRODUCTION_V4_ACTIVATION_ROLE_APPROVAL_V1"
RECEIPT_SCHEMA = "CMFD_PRODUCTION_V4_ACTIVATION_APPROVAL_RECEIPT_V1"

PRODUCER_ROLE = "producer"
REPRODUCER_ROLE = "independent_reproducer"
ROLES = (PRODUCER_ROLE, REPRODUCER_ROLE)
PHASES = ("pin", "evidence")
NAMESPACES = {
    PRODUCER_ROLE: "commonfoundry-production-v4-activation-producer-v1",
    REPRODUCER_ROLE: (
        "commonfoundry-production-v4-activation-independent-reproducer-v1"
    ),
}

COMMON_FILE_ROLES = frozenset(
    {
        "launch_candidate",
        "rcnet_input_manifest",
        "independent_reproduction_report",
        "fresh_process_verifier_report",
        "fresh_process_verifier_script",
        "rcnet_proof_template",
        "qualification_proof",
        "model_bank",
        "fixed_artifact_record",
        "fixed_bank_0_json",
        "fixed_bank_0_codeword",
        "fixed_bank_0_row_major_codeword",
        "fixed_bank_0_tree",
        "fixed_bank_1_json",
        "fixed_bank_1_codeword",
        "fixed_bank_1_row_major_codeword",
        "fixed_bank_1_tree",
        "fixed_bank_2_json",
        "fixed_bank_2_codeword",
        "fixed_bank_2_row_major_codeword",
        "fixed_bank_2_tree",
    }
)
EVIDENCE_ONLY_FILE_ROLES = frozenset(
    {"activation_evidence", "compiled_network_info"}
)

MAX_JSON_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_ALLOWED_SIGNERS_BYTES = 1024 * 1024
MAX_VERIFIER_BYTES = 64 * 1024 * 1024
MAX_VERIFIER_OUTPUT_BYTES = 64 * 1024
HEX256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SIGNER_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}\Z")
KEY_TYPE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}\Z")


class ApprovalError(RuntimeError):
    """An approval artifact, authority, or signature failed closed."""


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    identity: tuple[int, int, int, int, int]
    data: bytes


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _exact_fields(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ApprovalError(f"{label} has unexpected, missing, or repeated fields")
    return value


def _json_object(data: bytes, label: str) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ApprovalError(f"{label} repeats JSON field {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            data.decode("utf-8", "strict"), object_pairs_hook=unique_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApprovalError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ApprovalError(f"{label} must contain a JSON object")
    return value


def _hex256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not HEX256_RE.fullmatch(value)
        or set(value) == {"0"}
    ):
        raise ApprovalError(f"{label} must be a nonzero lowercase 256-bit digest")
    return value


def _commit(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not COMMIT_RE.fullmatch(value)
        or set(value) == {"0"}
    ):
        raise ApprovalError(f"{label} must be a full nonzero lowercase commit ID")
    return value


def _file_binding(value: object, label: str) -> dict[str, object]:
    row = _exact_fields(value, {"name", "bytes", "sha256", "blake3"}, label)
    name = row["name"]
    byte_count = row["bytes"]
    if (
        not isinstance(name, str)
        or not name
        or "\\" in name
        or PurePosixPath(name).name != name
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count <= 0
        or byte_count > (1 << 63) - 1
    ):
        raise ApprovalError(f"{label} has an invalid name or byte count")
    _hex256(row["sha256"], f"{label} SHA-256")
    _hex256(row["blake3"], f"{label} BLAKE3")
    return row


def validate_subject(value: object) -> dict[str, object]:
    subject = _exact_fields(
        value,
        {
            "schema",
            "phase",
            "activation_source_commit",
            "artifact_generation_source_commit",
            "qualification_source_commit",
            "network",
            "source_pin_sha256",
            "files",
        },
        "ProductionV4 activation approval subject",
    )
    phase = subject["phase"]
    if subject["schema"] != SUBJECT_SCHEMA or phase not in PHASES:
        raise ApprovalError("ProductionV4 activation approval subject schema or phase is invalid")
    _commit(subject["activation_source_commit"], "activation source commit")
    _commit(
        subject["artifact_generation_source_commit"],
        "artifact-generation source commit",
    )
    _commit(subject["qualification_source_commit"], "qualification source commit")
    _hex256(subject["source_pin_sha256"], "activation source-pin SHA-256")

    network = _exact_fields(
        subject["network"],
        {
            "profile",
            "launch_root",
            "network_id",
            "virtual_genesis_hash",
            "virtual_genesis_timestamp_unix_seconds",
            "pow_limit",
        },
        "ProductionV4 activation approval network",
    )
    if network["profile"] != "CommonFoundry RCNet-1":
        raise ApprovalError("ProductionV4 activation approval is not for RCNet-1")
    for field in ("launch_root", "network_id", "virtual_genesis_hash", "pow_limit"):
        _hex256(network[field], f"ProductionV4 activation approval {field}")
    timestamp = network["virtual_genesis_timestamp_unix_seconds"]
    if (
        not isinstance(timestamp, int)
        or isinstance(timestamp, bool)
        or timestamp <= 0
        or timestamp > (1 << 63) - 1
    ):
        raise ApprovalError("ProductionV4 activation approval timestamp is invalid")

    files = subject["files"]
    expected_roles = set(COMMON_FILE_ROLES)
    if phase == "evidence":
        expected_roles.update(EVIDENCE_ONLY_FILE_ROLES)
    files = _exact_fields(files, expected_roles, "ProductionV4 approval file bindings")
    for role in sorted(expected_roles):
        _file_binding(files[role], f"ProductionV4 approval {role}")
    return subject


def build_subject(
    *,
    phase: str,
    activation_source_commit: str,
    artifact_generation_source_commit: str,
    qualification_source_commit: str,
    network: dict[str, object],
    source_pin_sha256: str,
    files: dict[str, object],
) -> dict[str, object]:
    subject: dict[str, object] = {
        "schema": SUBJECT_SCHEMA,
        "phase": phase,
        "activation_source_commit": activation_source_commit,
        "artifact_generation_source_commit": artifact_generation_source_commit,
        "qualification_source_commit": qualification_source_commit,
        "network": network,
        "source_pin_sha256": source_pin_sha256,
        "files": files,
    }
    validate_subject(subject)
    return subject


def qualification_binding_sha256(files: object) -> str:
    bindings = _exact_fields(
        files, set(COMMON_FILE_ROLES), "ProductionV4 qualification file bindings"
    )
    for role in sorted(COMMON_FILE_ROLES):
        _file_binding(bindings[role], f"ProductionV4 qualification {role}")
    return hashlib.sha256(canonical_json(bindings)).hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
    )


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _snapshot(path: Path, label: str, maximum: int) -> FileSnapshot:
    candidate = _absolute(path)
    try:
        before = candidate.lstat()
    except OSError as error:
        raise ApprovalError(f"{label} is missing: {candidate}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ApprovalError(f"{label} must be a regular, non-symlink file")
    if before.st_size <= 0 or before.st_size > maximum:
        raise ApprovalError(f"{label} is empty or exceeds its size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise ApprovalError(f"cannot open {label}: {candidate}") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stat_identity(before) != _stat_identity(opened)
        ):
            raise ApprovalError(f"{label} changed before it could be opened")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != opened.st_size or len(data) > maximum:
            raise ApprovalError(f"{label} changed or exceeds its size limit")
    finally:
        os.close(descriptor)
    try:
        after = candidate.lstat()
    except OSError as error:
        raise ApprovalError(f"{label} changed while it was inspected") from error
    if _stat_identity(after) != _stat_identity(opened):
        raise ApprovalError(f"{label} changed while it was inspected")
    return FileSnapshot(candidate, _stat_identity(opened), bytes(data))


def _assert_snapshot_current(snapshot: FileSnapshot, label: str) -> None:
    try:
        current = _snapshot(snapshot.path, label, len(snapshot.data))
    except ApprovalError as error:
        raise ApprovalError(f"{label} changed during approval verification") from error
    if current.identity != snapshot.identity or current.data != snapshot.data:
        raise ApprovalError(f"{label} changed during approval verification")


def _ssh_key_blob_type(blob: bytes) -> str:
    if len(blob) < 4:
        raise ApprovalError("trusted signer public-key blob is truncated")
    length = struct.unpack(">I", blob[:4])[0]
    if length == 0 or length > 256 or 4 + length >= len(blob):
        raise ApprovalError("trusted signer public-key blob is malformed")
    try:
        return blob[4 : 4 + length].decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ApprovalError("trusted signer public-key type is not ASCII") from error


def parse_allowed_signers_authority(
    data: bytes, *, signer_identity: str, role: str
) -> dict[str, str]:
    if role not in ROLES:
        raise ApprovalError("ProductionV4 approval role is invalid")
    if not SIGNER_IDENTITY_RE.fullmatch(signer_identity):
        raise ApprovalError(f"{role} signer identity is malformed")
    namespace = NAMESPACES[role]
    try:
        text = data.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ApprovalError(f"{role} allowed-signers authority is not ASCII") from error
    if not text.endswith("\n") or "\r" in text or text.count("\n") != 1:
        raise ApprovalError(
            f"{role} allowed-signers authority must be one canonical LF-terminated line"
        )
    fields = text[:-1].split(" ")
    if len(fields) != 4 or any(not field for field in fields):
        raise ApprovalError(
            f"{role} allowed-signers authority must contain one dedicated signer key"
        )
    principal, options, key_type, encoded_key = fields
    if principal != signer_identity:
        raise ApprovalError(f"{role} allowed-signers principal does not match its signer identity")
    if options != f'namespaces="{namespace}"':
        raise ApprovalError(f"{role} allowed-signers namespace restriction is not exact")
    if (
        not KEY_TYPE_RE.fullmatch(key_type)
        or "-cert-v01@openssh.com" in key_type
        or key_type.startswith("ssh-dss")
    ):
        raise ApprovalError(f"{role} allowed-signers key type is unsupported")
    try:
        blob = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ApprovalError(f"{role} allowed-signers public key is not canonical base64") from error
    if not blob or base64.b64encode(blob).decode("ascii") != encoded_key:
        raise ApprovalError(f"{role} allowed-signers public key is not canonical base64")
    if _ssh_key_blob_type(blob) != key_type:
        raise ApprovalError(f"{role} allowed-signers key type does not match its key blob")
    key_digest = hashlib.sha256(blob).digest()
    fingerprint = base64.b64encode(key_digest).decode("ascii").rstrip("=")
    return {
        "allowed_signers_sha256": hashlib.sha256(data).hexdigest(),
        "key_blob_sha256": key_digest.hex(),
        "key_fingerprint": f"SHA256:{fingerprint}",
        "key_type": key_type,
    }


def _role_approval(
    *,
    subject: dict[str, object],
    role: str,
    signer_identity: str,
    authority: dict[str, str],
) -> dict[str, object]:
    return {
        "schema": APPROVAL_SCHEMA,
        "role": role,
        "namespace": NAMESPACES[role],
        "signer_identity": signer_identity,
        "trusted_authority": authority,
        "subject": subject,
    }


def load_trusted_authorities(
    *,
    producer_allowed_signers: Path,
    producer_signer_identity: str,
    reproducer_allowed_signers: Path,
    reproducer_signer_identity: str,
) -> dict[str, object]:
    if producer_signer_identity == reproducer_signer_identity:
        raise ApprovalError("producer and independent reproducer identities must differ")
    producer_policy = _snapshot(
        producer_allowed_signers,
        "producer allowed-signers authority",
        MAX_ALLOWED_SIGNERS_BYTES,
    )
    reproducer_policy = _snapshot(
        reproducer_allowed_signers,
        "independent reproducer allowed-signers authority",
        MAX_ALLOWED_SIGNERS_BYTES,
    )
    producer_authority = parse_allowed_signers_authority(
        producer_policy.data,
        signer_identity=producer_signer_identity,
        role=PRODUCER_ROLE,
    )
    reproducer_authority = parse_allowed_signers_authority(
        reproducer_policy.data,
        signer_identity=reproducer_signer_identity,
        role=REPRODUCER_ROLE,
    )
    if producer_authority["key_blob_sha256"] == reproducer_authority["key_blob_sha256"]:
        raise ApprovalError("producer and independent reproducer keys must differ")
    if producer_authority["allowed_signers_sha256"] == reproducer_authority[
        "allowed_signers_sha256"
    ]:
        raise ApprovalError("producer and independent reproducer authorities must differ")
    _assert_snapshot_current(producer_policy, "producer allowed-signers authority")
    _assert_snapshot_current(
        reproducer_policy, "independent reproducer allowed-signers authority"
    )
    authorities = {
        PRODUCER_ROLE: {
            "signer_identity": producer_signer_identity,
            **producer_authority,
        },
        REPRODUCER_ROLE: {
            "signer_identity": reproducer_signer_identity,
            **reproducer_authority,
        },
    }
    return authorities


def prepare_approval_payloads(
    *,
    subject: dict[str, object],
    producer_allowed_signers: Path,
    producer_signer_identity: str,
    reproducer_allowed_signers: Path,
    reproducer_signer_identity: str,
) -> dict[str, object]:
    validate_subject(subject)
    authorities = load_trusted_authorities(
        producer_allowed_signers=producer_allowed_signers,
        producer_signer_identity=producer_signer_identity,
        reproducer_allowed_signers=reproducer_allowed_signers,
        reproducer_signer_identity=reproducer_signer_identity,
    )
    payloads = {
        PRODUCER_ROLE: canonical_json(
            _role_approval(
                subject=subject,
                role=PRODUCER_ROLE,
                signer_identity=producer_signer_identity,
                authority={
                    field: value
                    for field, value in authorities[PRODUCER_ROLE].items()
                    if field != "signer_identity"
                },
            )
        ),
        REPRODUCER_ROLE: canonical_json(
            _role_approval(
                subject=subject,
                role=REPRODUCER_ROLE,
                signer_identity=reproducer_signer_identity,
                authority={
                    field: value
                    for field, value in authorities[REPRODUCER_ROLE].items()
                    if field != "signer_identity"
                },
            )
        ),
    }
    if any(len(payload) > MAX_JSON_BYTES for payload in payloads.values()):
        raise ApprovalError("ProductionV4 activation approval payload exceeds its size limit")
    return {"authorities": authorities, "payloads": payloads}


def _write_exclusive(path: Path, data: bytes, *, executable: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o700 if executable else 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    if executable:
        path.chmod(0o700)


def _verify_signature(
    *,
    verifier: Path,
    allowed_signers: Path,
    signer_identity: str,
    namespace: str,
    signature: Path,
    payload: bytes,
    environment: dict[str, str],
) -> None:
    try:
        completed = subprocess.run(
            [
                str(verifier),
                "-Y",
                "verify",
                "-f",
                str(allowed_signers),
                "-I",
                signer_identity,
                "-n",
                namespace,
                "-s",
                str(signature),
            ],
            cwd=verifier.parent,
            input=payload,
            check=False,
            capture_output=True,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ApprovalError("OpenSSH ProductionV4 approval verifier could not run") from error
    if (
        len(completed.stdout) > MAX_VERIFIER_OUTPUT_BYTES
        or len(completed.stderr) > MAX_VERIFIER_OUTPUT_BYTES
    ):
        raise ApprovalError("OpenSSH ProductionV4 approval verifier output exceeds its bound")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        if not detail:
            detail = completed.stdout.decode("utf-8", "replace").strip()
        raise ApprovalError(
            "ProductionV4 activation approval signature is invalid "
            f"(exit {completed.returncode}): {detail[:500]}"
        )


def _verification_environment(root: Path, original_verifier: Path) -> dict[str, str]:
    private = str(root)
    environment = {
        "HOME": private,
        "USERPROFILE": private,
        "TMP": private,
        "TEMP": private,
        "TMPDIR": private,
        "LANG": "C",
        "LC_ALL": "C",
    }
    if os.name == "nt":
        import ctypes

        buffer = ctypes.create_unicode_buffer(32_768)
        length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
        if length == 0 or length >= len(buffer):
            raise ApprovalError("cannot obtain the trusted Windows system directory")
        system_root = Path(buffer.value)
        if not system_root.is_absolute() or not system_root.anchor:
            raise ApprovalError("trusted Windows system directory is not absolute")
        environment["SystemRoot"] = str(system_root)
        environment["WINDIR"] = str(system_root)
        system32 = str(system_root / "System32")
        environment["PATH"] = os.pathsep.join(
            (str(original_verifier.parent), system32)
        )
        environment["ProgramData"] = str(Path(system_root.anchor) / "ProgramData")
    return environment


def _expected_trust_matches(
    authorities: dict[str, dict[str, str]],
    expected: dict[str, object] | None,
) -> None:
    if expected is None:
        return
    trusted = _exact_fields(expected, set(ROLES), "compiled ProductionV4 approval trust")
    for role in ROLES:
        row = _exact_fields(
            trusted[role],
            {
                "signer_identity",
                "allowed_signers_sha256",
                "key_blob_sha256",
                "key_fingerprint",
                "key_type",
            },
            f"compiled {role} approval trust",
        )
        for field in (
            "signer_identity",
            "allowed_signers_sha256",
            "key_blob_sha256",
            "key_fingerprint",
            "key_type",
        ):
            if row[field] != authorities[role][field]:
                raise ApprovalError(f"{role} approval authority does not match the compiled trust pin")


def verify_approval_pair(
    *,
    subject: dict[str, object],
    producer_approval: Path,
    producer_signature: Path,
    producer_allowed_signers: Path,
    producer_signer_identity: str,
    reproducer_approval: Path,
    reproducer_signature: Path,
    reproducer_allowed_signers: Path,
    reproducer_signer_identity: str,
    ssh_keygen: Path,
    expected_verifier_sha256: str,
    expected_trust: dict[str, object] | None = None,
) -> dict[str, object]:
    _hex256(expected_verifier_sha256, "trusted OpenSSH verifier SHA-256")
    if subject.get("phase") == "evidence" and expected_trust is None:
        raise ApprovalError(
            "evidence approval verification requires precommitted compiled trust descriptors"
        )
    prepared = prepare_approval_payloads(
        subject=subject,
        producer_allowed_signers=producer_allowed_signers,
        producer_signer_identity=producer_signer_identity,
        reproducer_allowed_signers=reproducer_allowed_signers,
        reproducer_signer_identity=reproducer_signer_identity,
    )
    return _verify_prepared_pair(
        subject=subject, prepared=prepared,
        producer_approval=producer_approval, producer_signature=producer_signature,
        producer_allowed_signers=producer_allowed_signers,
        producer_signer_identity=producer_signer_identity,
        reproducer_approval=reproducer_approval, reproducer_signature=reproducer_signature,
        reproducer_allowed_signers=reproducer_allowed_signers,
        reproducer_signer_identity=reproducer_signer_identity,
        ssh_keygen=ssh_keygen, expected_verifier_sha256=expected_verifier_sha256,
        expected_trust=expected_trust,
    )


def _verify_prepared_pair(
    *, subject: dict[str, object], prepared: dict[str, object],
    producer_approval: Path, producer_signature: Path,
    producer_allowed_signers: Path, producer_signer_identity: str,
    reproducer_approval: Path, reproducer_signature: Path,
    reproducer_allowed_signers: Path, reproducer_signer_identity: str,
    ssh_keygen: Path, expected_verifier_sha256: str,
    expected_trust: dict[str, object] | None,
) -> dict[str, object]:
    """Shared signature mechanics; callers must build their exact typed subject.

    The public V4 entry point above retains its RC-only subject validation.
    Mainnet plan approvals use a distinct subject and role-payload schema, while
    retaining the dedicated V4 activation key authorities and SSH namespaces.
    """
    _hex256(expected_verifier_sha256, "trusted OpenSSH verifier SHA-256")
    authorities = prepared["authorities"]
    payloads = prepared["payloads"]
    if not isinstance(authorities, dict) or not isinstance(payloads, dict):
        raise ApprovalError("ProductionV4 approval preparation failed")
    _expected_trust_matches(authorities, expected_trust)

    snapshots: dict[str, FileSnapshot] = {
        "verifier": _snapshot(
            ssh_keygen, "OpenSSH ProductionV4 approval verifier", MAX_VERIFIER_BYTES
        ),
        "producer_approval": _snapshot(
            producer_approval, "producer approval payload", MAX_JSON_BYTES
        ),
        "producer_signature": _snapshot(
            producer_signature, "producer approval signature", MAX_SIGNATURE_BYTES
        ),
        "producer_policy": _snapshot(
            producer_allowed_signers,
            "producer allowed-signers authority",
            MAX_ALLOWED_SIGNERS_BYTES,
        ),
        "reproducer_approval": _snapshot(
            reproducer_approval,
            "independent reproducer approval payload",
            MAX_JSON_BYTES,
        ),
        "reproducer_signature": _snapshot(
            reproducer_signature,
            "independent reproducer approval signature",
            MAX_SIGNATURE_BYTES,
        ),
        "reproducer_policy": _snapshot(
            reproducer_allowed_signers,
            "independent reproducer allowed-signers authority",
            MAX_ALLOWED_SIGNERS_BYTES,
        ),
    }
    for role, prefix in (
        (PRODUCER_ROLE, "producer"),
        (REPRODUCER_ROLE, "reproducer"),
    ):
        if hashlib.sha256(snapshots[f"{prefix}_policy"].data).hexdigest() != authorities[
            role
        ]["allowed_signers_sha256"]:
            raise ApprovalError(f"{role} allowed-signers authority changed during preparation")
    for role, snapshot_name in (
        (PRODUCER_ROLE, "producer_approval"),
        (REPRODUCER_ROLE, "reproducer_approval"),
    ):
        payload = payloads[role]
        snapshot = snapshots[snapshot_name]
        if not isinstance(payload, bytes) or snapshot.data != payload:
            raise ApprovalError(f"{role} approval payload is not the exact canonical expected JSON")
        if _json_object(snapshot.data, f"{role} approval payload") != _json_object(
            payload, f"expected {role} approval payload"
        ):
            raise ApprovalError(f"{role} approval payload is invalid")

    verifier_snapshot = snapshots["verifier"]
    verifier_sha256 = hashlib.sha256(verifier_snapshot.data).hexdigest()
    if verifier_sha256 != expected_verifier_sha256:
        raise ApprovalError("OpenSSH ProductionV4 approval verifier does not match its trust pin")
    suffix = verifier_snapshot.path.suffix if os.name == "nt" else ""
    with tempfile.TemporaryDirectory(prefix="cmfd-v4-activation-approval-") as directory:
        root = Path(directory)
        verifier_copy = root / f"ssh-keygen{suffix}"
        _write_exclusive(verifier_copy, verifier_snapshot.data, executable=True)
        environment = _verification_environment(root, verifier_snapshot.path)
        for role, prefix in (
            (PRODUCER_ROLE, "producer"),
            (REPRODUCER_ROLE, "reproducer"),
        ):
            policy_copy = root / f"{prefix}.allowed_signers"
            signature_copy = root / f"{prefix}.approval.sig"
            _write_exclusive(policy_copy, snapshots[f"{prefix}_policy"].data)
            _write_exclusive(signature_copy, snapshots[f"{prefix}_signature"].data)
            _verify_signature(
                verifier=verifier_copy,
                allowed_signers=policy_copy,
                signer_identity=(
                    producer_signer_identity
                    if role == PRODUCER_ROLE
                    else reproducer_signer_identity
                ),
                namespace=NAMESPACES[role],
                signature=signature_copy,
                payload=payloads[role],
                environment=environment,
            )

    for name, snapshot in snapshots.items():
        _assert_snapshot_current(snapshot, name.replace("_", " "))
    return {
        "schema": RECEIPT_SCHEMA,
        "phase": subject["phase"],
        "subject_sha256": hashlib.sha256(canonical_json(subject)).hexdigest(),
        "verifier_sha256": verifier_sha256,
        "approvals": {
            PRODUCER_ROLE: {
                "signer_identity": producer_signer_identity,
                "namespace": NAMESPACES[PRODUCER_ROLE],
                "allowed_signers_sha256": authorities[PRODUCER_ROLE][
                    "allowed_signers_sha256"
                ],
                "key_blob_sha256": authorities[PRODUCER_ROLE]["key_blob_sha256"],
                "key_fingerprint": authorities[PRODUCER_ROLE]["key_fingerprint"],
                "key_type": authorities[PRODUCER_ROLE]["key_type"],
                "approval_sha256": hashlib.sha256(
                    snapshots["producer_approval"].data
                ).hexdigest(),
                "signature_sha256": hashlib.sha256(
                    snapshots["producer_signature"].data
                ).hexdigest(),
            },
            REPRODUCER_ROLE: {
                "signer_identity": reproducer_signer_identity,
                "namespace": NAMESPACES[REPRODUCER_ROLE],
                "allowed_signers_sha256": authorities[REPRODUCER_ROLE][
                    "allowed_signers_sha256"
                ],
                "key_blob_sha256": authorities[REPRODUCER_ROLE]["key_blob_sha256"],
                "key_fingerprint": authorities[REPRODUCER_ROLE]["key_fingerprint"],
                "key_type": authorities[REPRODUCER_ROLE]["key_type"],
                "approval_sha256": hashlib.sha256(
                    snapshots["reproducer_approval"].data
                ).hexdigest(),
                "signature_sha256": hashlib.sha256(
                    snapshots["reproducer_signature"].data
                ).hexdigest(),
            },
        },
    }
