#!/usr/bin/env python3
"""Prepare and verify role-scoped mainnet plan approvals. Never signs or activates.

The existing proof-qualification gate remains required. Different signing keys
are checked cryptographically; actual organizational independence and review
quality must still be established by the operator.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

import package_mainnet as package
import production_v4_activation_approval as signatures

SUBJECT_SCHEMA = "CMFD_MAINNET_PLAN_APPROVAL_SUBJECT_V1"
ROLE_SCHEMA = "CMFD_MAINNET_PLAN_ROLE_APPROVAL_V1"
MANIFEST_SCHEMA = "CMFD_MAINNET_PLAN_APPROVAL_MANIFEST_V1"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_subject(*, plan_bytes: bytes, qualification_bytes: bytes,
                  review_commit: str, trust_bytes: bytes) -> dict:
    plan = package.validate_plan(plan_bytes)
    if len(qualification_bytes) > signatures.MAX_JSON_BYTES:
        raise signatures.ApprovalError("proof qualification subject exceeds its bound")
    qualification = signatures._json_object(qualification_bytes, "proof qualification subject")
    signatures.validate_subject(qualification)
    if qualification["phase"] != "pin" or signatures.canonical_json(qualification) != qualification_bytes:
        raise signatures.ApprovalError("mainnet requires the canonical pin-phase proof qualification subject")
    files = qualification["files"]
    for role, artifact in (("model_bank", "bank"), ("fixed_artifact_record", "fixed_record")):
        expected = plan["payload"]["rules"]["artifacts"][artifact]
        for field in ("bytes", "sha256", "blake3"):
            if files[role].get(field) != expected.get(field):
                raise signatures.ApprovalError("mainnet plan and qualified proof artifacts disagree")
    subject = {
        "schema": SUBJECT_SCHEMA, "phase": "mainnet_plan",
        "review_source_commit": review_commit,
        "launch_plan_sha256": digest(plan_bytes), "launch_plan_bytes": len(plan_bytes),
        "launch_plan_digest": plan["launch_plan_digest"], "network_id": plan["network_id"],
        "source_release_unix_seconds": package.SOURCE_TIME,
        "mining_start_unix_seconds": package.LAUNCH_TIME,
        "genesis_policy": "requires_verified_launch_beacon",
        "proof_qualification_subject_sha256": digest(qualification_bytes),
        "qualification_binding_sha256": signatures.qualification_binding_sha256(files),
        "approval_trust_sha256": digest(trust_bytes),
    }
    validate_subject(subject)
    return subject


def validate_subject(subject: object) -> dict:
    value = signatures._exact_fields(subject, {
        "schema", "phase", "review_source_commit", "launch_plan_sha256", "launch_plan_bytes",
        "launch_plan_digest", "network_id", "source_release_unix_seconds", "mining_start_unix_seconds",
        "genesis_policy", "proof_qualification_subject_sha256", "qualification_binding_sha256",
        "approval_trust_sha256",
    }, "mainnet plan approval subject")
    if value["schema"] != SUBJECT_SCHEMA or value["phase"] != "mainnet_plan":
        raise signatures.ApprovalError("not a mainnet plan approval subject")
    signatures._commit(value["review_source_commit"], "mainnet review commit")
    for field in ("launch_plan_sha256", "launch_plan_digest", "network_id",
                  "proof_qualification_subject_sha256", "qualification_binding_sha256", "approval_trust_sha256"):
        signatures._hex256(value[field], field)
    if type(value["launch_plan_bytes"]) is not int or not 0 < value["launch_plan_bytes"] <= 32 * 1024:
        raise signatures.ApprovalError("invalid approved plan size")
    for field, expected in (("source_release_unix_seconds", package.SOURCE_TIME),
                            ("mining_start_unix_seconds", package.LAUNCH_TIME)):
        if type(value[field]) is not int or value[field] != expected:
            raise signatures.ApprovalError("approved mainnet schedule differs from the fixed schedule")
    if value["genesis_policy"] != "requires_verified_launch_beacon":
        raise signatures.ApprovalError("approved mainnet genesis policy differs")
    return value


def prepare_payloads(*, subject: dict, expected_trust: dict,
                     producer_allowed_signers: Path, producer_signer_identity: str,
                     reproducer_allowed_signers: Path, reproducer_signer_identity: str) -> dict:
    validate_subject(subject)
    if expected_trust is None or digest(signatures.canonical_json(expected_trust)) != subject["approval_trust_sha256"]:
        raise signatures.ApprovalError("mainnet approval trust is missing or differs from the signed subject")
    signatures._exact_fields(expected_trust, set(signatures.ROLES) | {"ssh_keygen_sha256"}, "mainnet approval trust")
    signatures._hex256(expected_trust["ssh_keygen_sha256"], "precommitted SSH verifier digest")
    authorities = signatures.load_trusted_authorities(
        producer_allowed_signers=producer_allowed_signers, producer_signer_identity=producer_signer_identity,
        reproducer_allowed_signers=reproducer_allowed_signers, reproducer_signer_identity=reproducer_signer_identity,
    )
    signatures._expected_trust_matches(authorities, {role: expected_trust[role] for role in signatures.ROLES})
    payloads = {}
    for role in signatures.ROLES:
        authority = authorities[role]
        payloads[role] = signatures.canonical_json({
            "schema": ROLE_SCHEMA, "role": role, "namespace": signatures.NAMESPACES[role],
            "signer_identity": authority["signer_identity"],
            "trusted_authority": {key: value for key, value in authority.items() if key != "signer_identity"},
            "subject": subject,
        })
    return {"authorities": authorities, "payloads": payloads}


def verify_pair(*, subject: dict, expected_trust: dict, **material) -> dict:
    policy_arguments = {key: material[key] for key in (
        "producer_allowed_signers", "producer_signer_identity",
        "reproducer_allowed_signers", "reproducer_signer_identity",
    )}
    prepared = prepare_payloads(subject=subject, expected_trust=expected_trust, **policy_arguments)
    if material["expected_verifier_sha256"] != expected_trust["ssh_keygen_sha256"]:
        raise signatures.ApprovalError("SSH verifier selection differs from the precommitted trust policy")
    receipt = signatures._verify_prepared_pair(
        subject=subject, prepared=prepared,
        expected_trust={role: expected_trust[role] for role in signatures.ROLES}, **material,
    )
    # The pinned manifest contains only signed material/authority identities.
    # Transient verifier-path/host details are not added to the plan pin. The
    # selected verifier must already match the precommitted policy above.
    return {"schema": MANIFEST_SCHEMA, "subject": subject,
            "subject_sha256": receipt["subject_sha256"], "approvals": receipt["approvals"]}


def validate_manifest(data: bytes, plan_bytes: bytes) -> dict:
    if len(data) > package.MAX_INFO:
        raise signatures.ApprovalError("mainnet approval manifest exceeds its bound")
    manifest = signatures._json_object(data, "mainnet approval manifest")
    signatures._exact_fields(manifest, {"schema", "subject", "subject_sha256", "approvals"}, "mainnet approval manifest")
    if len(data) > package.MAX_INFO or manifest["schema"] != MANIFEST_SCHEMA or signatures.canonical_json(manifest) != data:
        raise signatures.ApprovalError("mainnet approval manifest is not canonical")
    subject = validate_subject(manifest["subject"])
    plan = package.validate_plan(plan_bytes)
    if (manifest["subject_sha256"] != digest(signatures.canonical_json(subject))
        or subject["launch_plan_sha256"] != digest(plan_bytes) or subject["launch_plan_bytes"] != len(plan_bytes)
        or subject["launch_plan_digest"] != plan["launch_plan_digest"] or subject["network_id"] != plan["network_id"]):
        raise signatures.ApprovalError("mainnet approval manifest belongs to another plan")
    approvals = signatures._exact_fields(manifest["approvals"], set(signatures.ROLES), "mainnet approval roles")
    for role, row in approvals.items():
        signatures._exact_fields(row, {"signer_identity", "namespace", "allowed_signers_sha256", "key_blob_sha256",
                                      "key_fingerprint", "key_type", "approval_sha256", "signature_sha256"}, role)
        for field in ("allowed_signers_sha256", "key_blob_sha256", "approval_sha256", "signature_sha256"):
            signatures._hex256(row[field], field)
        if not isinstance(row["signer_identity"], str) or not signatures.SIGNER_IDENTITY_RE.fullmatch(row["signer_identity"]):
            raise signatures.ApprovalError("invalid mainnet signer identity")
        if row["namespace"] != signatures.NAMESPACES[role]:
            raise signatures.ApprovalError("mainnet approval has the wrong role namespace")
        key_type = row["key_type"]
        if not isinstance(key_type, str) or not signatures.KEY_TYPE_RE.fullmatch(key_type) or "-cert-v01@openssh.com" in key_type or key_type.startswith("ssh-dss"):
            raise signatures.ApprovalError("mainnet approval key type is unsupported")
        fingerprint = "SHA256:" + base64.b64encode(bytes.fromhex(row["key_blob_sha256"])).decode().rstrip("=")
        if row["key_fingerprint"] != fingerprint:
            raise signatures.ApprovalError("mainnet approval key fingerprint disagrees")
    producer, reproducer = (approvals[role] for role in signatures.ROLES)
    if any(producer[field] == reproducer[field] for field in ("signer_identity", "key_blob_sha256", "allowed_signers_sha256")):
        raise signatures.ApprovalError("mainnet approval roles must have distinct identities and keys")
    return manifest


def bind_manifest_to_runtime(manifest: dict, data: bytes, runtime: dict) -> None:
    if digest(data) != runtime["mainnet_approval_manifest_sha256"]:
        raise signatures.ApprovalError("mainnet approval manifest does not match the compiled pin")
    trust = runtime["proof_approval_trust"]
    expected = {role: trust[role] for role in signatures.ROLES}
    trust_policy = {**expected, "ssh_keygen_sha256": trust["ssh_keygen_sha256"]}
    subject = manifest["subject"]
    if (subject["qualification_binding_sha256"] != trust["qualification_binding_sha256"]
        or subject["approval_trust_sha256"] != digest(signatures.canonical_json(trust_policy))):
        raise signatures.ApprovalError("mainnet plan approvals do not bind the compiled proof qualification/trust")
    signatures._expected_trust_matches(manifest["approvals"], expected)


def load_inputs(repo: Path, review_commit: str, plan: Path, qualification: Path, trust: Path):
    package.integrity._assert_clean_exact_repo(repo, review_commit)
    trust_relative = trust.resolve(strict=True).relative_to(repo.resolve(strict=True)).as_posix()
    snapshots = {
        "plan": signatures._snapshot(plan, "mainnet plan", 32 * 1024),
        "qualification": signatures._snapshot(qualification, "proof qualification subject", signatures.MAX_JSON_BYTES),
        "trust": signatures._snapshot(trust, "mainnet approval trust", signatures.MAX_JSON_BYTES),
    }
    if package.integrity._tracked_blob_at(repo, review_commit, trust_relative) != snapshots["trust"].data:
        raise signatures.ApprovalError("approval trust must match the exact committed review source")
    expected_trust = signatures._json_object(snapshots["trust"].data, "mainnet approval trust")
    if signatures.canonical_json(expected_trust) != snapshots["trust"].data:
        raise signatures.ApprovalError("mainnet approval trust is not canonical")
    subject = build_subject(plan_bytes=snapshots["plan"].data,
                            qualification_bytes=snapshots["qualification"].data,
                            review_commit=review_commit, trust_bytes=snapshots["trust"].data)
    qualification_subject = signatures._json_object(snapshots["qualification"].data, "proof qualification subject")
    for field in ("activation_source_commit", "artifact_generation_source_commit", "qualification_source_commit"):
        # The existing proof gate authenticates the full qualification artifacts.
        # Here we additionally refuse a subject from unrelated future/source history.
        package.integrity._run_git(repo, "merge-base", "--is-ancestor", qualification_subject[field], review_commit)
    return subject, expected_trust, snapshots


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--review-commit", required=True)
    for name in ("plan", "qualification-subject", "trust", "producer-policy", "reproducer-policy", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--producer-identity", required=True)
    parser.add_argument("--reproducer-identity", required=True)
    for name in ("producer-approval", "producer-signature", "reproducer-approval", "reproducer-signature", "ssh-keygen"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--ssh-keygen-sha256")
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path) and not value.is_absolute():
            parser.error(f"--{name} must be an absolute path")
    try:
        subject, trust, snapshots = load_inputs(args.repo, args.review_commit, args.plan, args.qualification_subject, args.trust)
        policies = dict(producer_allowed_signers=args.producer_policy, producer_signer_identity=args.producer_identity,
                        reproducer_allowed_signers=args.reproducer_policy, reproducer_signer_identity=args.reproducer_identity)
        if args.action == "prepare":
            prepared = prepare_payloads(subject=subject, expected_trust=trust, **policies)
            for label, snapshot in snapshots.items():
                signatures._assert_snapshot_current(snapshot, label)
            package.integrity._assert_clean_exact_repo(args.repo, args.review_commit)
            # Create a new directory; never replace an earlier review request.
            args.output.mkdir(parents=False, exist_ok=False)
            for role, payload in prepared["payloads"].items():
                package.integrity._write_new(args.output / f"{role}.approval.json", payload)
            package.integrity._write_new(args.output / "SUBJECT.json", signatures.canonical_json(subject))
        else:
            if any(value is None for value in (args.producer_approval, args.producer_signature,
                                               args.reproducer_approval, args.reproducer_signature,
                                               args.ssh_keygen, args.ssh_keygen_sha256)):
                raise signatures.ApprovalError("verify requires both approvals/signatures and a hash-pinned SSH verifier")
            manifest = verify_pair(subject=subject, expected_trust=trust, **policies,
                                   producer_approval=args.producer_approval, producer_signature=args.producer_signature,
                                   reproducer_approval=args.reproducer_approval, reproducer_signature=args.reproducer_signature,
                                   ssh_keygen=args.ssh_keygen, expected_verifier_sha256=args.ssh_keygen_sha256)
            for label, snapshot in snapshots.items():
                signatures._assert_snapshot_current(snapshot, label)
            package.integrity._assert_clean_exact_repo(args.repo, args.review_commit)
            encoded = signatures.canonical_json(manifest)
            package.integrity._write_new(args.output, encoded)
            print(json.dumps({"manifest_sha256": digest(encoded), "launch_plan_digest": subject["launch_plan_digest"],
                              "signatures_verified": True, "mainnet_activation_authorized": False}))
    except (OSError, ValueError, KeyError, signatures.ApprovalError, package.Error) as error:
        parser.exit(1, f"Mainnet approval failed: {error}\n")


if __name__ == "__main__":
    main()
