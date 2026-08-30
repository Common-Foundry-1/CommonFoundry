#!/usr/bin/env python3
"""Create and verify dual-signed Common Foundry release-key transitions."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from production_v4_reproduction import ReproductionError, canonical_json, write_new

TRANSITION_SCHEMA = "CommonFoundry/ReleaseKeyTransition/v1"
REPORT_SCHEMA = "CommonFoundry/ReleaseKeyTransitionVerification/v1"
SIGNATURE_NAMESPACE = "commonfoundry-release-key-transition"
MAX_TRANSITION_BYTES = 64 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}\Z")
RELEASE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
APPROVER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 @._+-]{0,127}\Z")
UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class TransitionError(ValueError):
    """Raised when transition evidence is malformed or unauthenticated."""


def read_regular_file(path: Path, label: str, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise TransitionError(f"cannot inspect {label} {path}: {error}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise TransitionError(f"{label} must be a regular non-symlink file: {path}")
    if before.st_size == 0 or before.st_size > maximum:
        raise TransitionError(f"{label} has an invalid size: {path}")
    try:
        data = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise TransitionError(f"cannot read {label} {path}: {error}") from error
    if (
        len(data) != before.st_size
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
    ):
        raise TransitionError(f"{label} changed while being read: {path}")
    return data


def parse_public_key_text(text: str, label: str) -> dict[str, str]:
    lines = text.splitlines()
    if len(lines) != 1:
        raise TransitionError(f"{label} must contain exactly one public key")
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise TransitionError(f"{label} must be one OpenSSH Ed25519 public key")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as error:
        raise TransitionError(f"{label} has invalid public-key base64") from error
    algorithm, offset = read_ssh_string(blob, 0, label)
    key_bytes, offset = read_ssh_string(blob, offset, label)
    if algorithm != b"ssh-ed25519" or len(key_bytes) != 32 or offset != len(blob):
        raise TransitionError(f"{label} has an invalid Ed25519 public-key blob")
    fingerprint = (
        base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    )
    return {
        "algorithm": "ssh-ed25519",
        "public_key": f"ssh-ed25519 {fields[1]}",
        "fingerprint": f"SHA256:{fingerprint}",
    }


def read_ssh_string(blob: bytes, offset: int, label: str) -> tuple[bytes, int]:
    if len(blob) - offset < 4:
        raise TransitionError(f"{label} has a truncated public-key blob")
    length = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4
    end = offset + length
    if end > len(blob):
        raise TransitionError(f"{label} has a truncated public-key blob")
    return blob[offset:end], end


def read_public_key(path: Path, label: str) -> dict[str, str]:
    data = read_regular_file(path, label, MAX_PUBLIC_KEY_BYTES)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise TransitionError(f"{label} is not ASCII") from error
    return parse_public_key_text(text, label)


def parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise TransitionError(
            f"{label} must be an RFC 3339 UTC timestamp to whole seconds"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TransitionError(f"{label} is not a valid UTC timestamp") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise TransitionError(f"{label} must be UTC")
    return parsed


def validate_transition(record: object) -> dict[str, object]:
    if not isinstance(record, dict):
        raise TransitionError("transition must be a JSON object")
    expected = {
        "schema",
        "signature_namespace",
        "signer_identity",
        "old_key",
        "new_key",
        "reason",
        "approved_at_utc",
        "first_release",
        "overlap_ends_utc",
        "approvers",
    }
    if set(record) != expected:
        raise TransitionError("transition fields do not match the version-1 schema")
    if record["schema"] != TRANSITION_SCHEMA:
        raise TransitionError("transition schema is unsupported")
    if record["signature_namespace"] != SIGNATURE_NAMESPACE:
        raise TransitionError("transition signature namespace is invalid")
    identity = record["signer_identity"]
    if not isinstance(identity, str) or IDENTITY_RE.fullmatch(identity) is None:
        raise TransitionError("signer identity is malformed")
    release = record["first_release"]
    if not isinstance(release, str) or RELEASE_RE.fullmatch(release) is None:
        raise TransitionError("first release is malformed")
    reason = record["reason"]
    if (
        not isinstance(reason, str)
        or reason != reason.strip()
        or not (8 <= len(reason) <= 512)
    ):
        raise TransitionError("transition reason must contain 8 to 512 characters")
    approvers = record["approvers"]
    if (
        not isinstance(approvers, list)
        or len(approvers) < 2
        or any(
            not isinstance(approver, str)
            or approver != approver.strip()
            or APPROVER_RE.fullmatch(approver) is None
            for approver in approvers
        )
        or len(set(approvers)) != len(approvers)
        or approvers != sorted(approvers)
    ):
        raise TransitionError("approvers must be at least two unique sorted names")
    approved = parse_utc(record["approved_at_utc"], "approval time")
    overlap_ends = parse_utc(record["overlap_ends_utc"], "overlap end")
    if overlap_ends <= approved:
        raise TransitionError("overlap end must be after approval time")

    parsed_keys = []
    for field in ("old_key", "new_key"):
        key = record[field]
        if not isinstance(key, dict) or set(key) != {
            "algorithm",
            "public_key",
            "fingerprint",
        }:
            raise TransitionError(f"{field} fields are malformed")
        parsed = parse_public_key_text(str(key["public_key"]), field)
        if key != parsed:
            raise TransitionError(f"{field} is not canonical")
        parsed_keys.append(parsed)
    if parsed_keys[0]["public_key"] == parsed_keys[1]["public_key"]:
        raise TransitionError("old and new release keys must differ")
    return record


def build_transition(
    *,
    signer_identity: str,
    old_public_key: Path,
    new_public_key: Path,
    reason: str,
    approved_at_utc: str,
    first_release: str,
    overlap_ends_utc: str,
    approvers: list[str],
) -> dict[str, object]:
    record: dict[str, object] = {
        "schema": TRANSITION_SCHEMA,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "signer_identity": signer_identity,
        "old_key": read_public_key(old_public_key, "old public key"),
        "new_key": read_public_key(new_public_key, "new public key"),
        "reason": reason.strip(),
        "approved_at_utc": approved_at_utc,
        "first_release": first_release,
        "overlap_ends_utc": overlap_ends_utc,
        "approvers": sorted(approvers),
    }
    return validate_transition(record)


def load_canonical_transition(path: Path) -> tuple[dict[str, object], bytes]:
    encoded = read_regular_file(path, "transition record", MAX_TRANSITION_BYTES)
    try:
        record = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransitionError("transition record is not valid UTF-8 JSON") from error
    validated = validate_transition(record)
    if canonical_json(validated) != encoded:
        raise TransitionError("transition record is not canonical JSON")
    return validated, encoded


def verify_signature(
    *,
    ssh_keygen: str,
    transition: bytes,
    signature: bytes,
    key: dict[str, str],
    identity: str,
    label: str,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="cmfd-release-key-transition-"
    ) as temporary:
        root = Path(temporary)
        allowed = root / "allowed_signers"
        signature_path = root / f"{label}.sig"
        allowed.write_text(f"{identity} {key['public_key']}\n", encoding="ascii")
        signature_path.write_bytes(signature)
        try:
            result = subprocess.run(
                [
                    ssh_keygen,
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed),
                    "-I",
                    identity,
                    "-n",
                    SIGNATURE_NAMESPACE,
                    "-s",
                    str(signature_path),
                ],
                input=transition,
                capture_output=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise TransitionError(
                f"cannot run ssh-keygen for {label} signature: {error}"
            ) from error
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise TransitionError(f"{label} signature verification failed: {detail}")


def verify_transition(
    *,
    transition_path: Path,
    old_public_key_path: Path,
    new_public_key_path: Path,
    old_signature_path: Path,
    new_signature_path: Path,
    ssh_keygen: str,
) -> dict[str, object]:
    record, transition = load_canonical_transition(transition_path)
    old_key = read_public_key(old_public_key_path, "trusted old public key")
    new_key = read_public_key(new_public_key_path, "expected new public key")
    if old_key != record["old_key"] or new_key != record["new_key"]:
        raise TransitionError("supplied public keys do not match the transition record")
    old_signature = read_regular_file(
        old_signature_path, "old-key signature", MAX_SIGNATURE_BYTES
    )
    new_signature = read_regular_file(
        new_signature_path, "new-key signature", MAX_SIGNATURE_BYTES
    )
    if old_signature == new_signature:
        raise TransitionError("old-key and new-key signatures must differ")
    identity = str(record["signer_identity"])
    verify_signature(
        ssh_keygen=ssh_keygen,
        transition=transition,
        signature=old_signature,
        key=old_key,
        identity=identity,
        label="old-key",
    )
    verify_signature(
        ssh_keygen=ssh_keygen,
        transition=transition,
        signature=new_signature,
        key=new_key,
        identity=identity,
        label="new-key",
    )
    return {
        "schema": REPORT_SCHEMA,
        "status": "verified",
        "transition_sha256": hashlib.sha256(transition).hexdigest(),
        "old_signature_sha256": hashlib.sha256(old_signature).hexdigest(),
        "new_signature_sha256": hashlib.sha256(new_signature).hexdigest(),
        "signer_identity": identity,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "old_key_fingerprint": old_key["fingerprint"],
        "new_key_fingerprint": new_key["fingerprint"],
        "first_release": record["first_release"],
        "overlap_ends_utc": record["overlap_ends_utc"],
        "dual_signature_gate_met": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser(
        "create", help="create a canonical transition record"
    )
    create.add_argument("--signer-identity", required=True)
    create.add_argument("--old-public-key", type=Path, required=True)
    create.add_argument("--new-public-key", type=Path, required=True)
    create.add_argument("--reason", required=True)
    create.add_argument("--approved-at-utc", required=True)
    create.add_argument("--first-release", required=True)
    create.add_argument("--overlap-ends-utc", required=True)
    create.add_argument("--approver", action="append", required=True)
    create.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="verify both transition signatures")
    verify.add_argument("--transition", type=Path, required=True)
    verify.add_argument("--old-public-key", type=Path, required=True)
    verify.add_argument("--new-public-key", type=Path, required=True)
    verify.add_argument("--old-signature", type=Path, required=True)
    verify.add_argument("--new-signature", type=Path, required=True)
    verify.add_argument(
        "--ssh-keygen", default=shutil.which("ssh-keygen") or "ssh-keygen"
    )
    verify.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "create":
            record = build_transition(
                signer_identity=args.signer_identity,
                old_public_key=args.old_public_key.resolve(),
                new_public_key=args.new_public_key.resolve(),
                reason=args.reason,
                approved_at_utc=args.approved_at_utc,
                first_release=args.first_release,
                overlap_ends_utc=args.overlap_ends_utc,
                approvers=args.approver,
            )
            encoded = write_new(args.output.resolve(), record)
            result = {
                "status": "created",
                "transition": str(args.output.resolve()),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "old_key_fingerprint": record["old_key"]["fingerprint"],
                "new_key_fingerprint": record["new_key"]["fingerprint"],
            }
        else:
            report = verify_transition(
                transition_path=args.transition.resolve(),
                old_public_key_path=args.old_public_key.resolve(),
                new_public_key_path=args.new_public_key.resolve(),
                old_signature_path=args.old_signature.resolve(),
                new_signature_path=args.new_signature.resolve(),
                ssh_keygen=args.ssh_keygen,
            )
            encoded = write_new(args.output.resolve(), report)
            result = {
                "status": "verified",
                "report": str(args.output.resolve()),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "dual_signature_gate_met": True,
            }
    except (OSError, ReproductionError, TransitionError) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
