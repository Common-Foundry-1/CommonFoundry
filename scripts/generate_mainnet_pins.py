#!/usr/bin/env python3
"""Render mainnet pin candidates from verified approvals; never edits source pins.

The proof target must already have passed the ProductionV4 qualification gate.
This bridge re-verifies plan signatures and all signed target bindings. It does
not manufacture qualification evidence, choose recipients, or activate a node.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import mainnet_plan_approval as approval
import package_mainnet as package
import production_v4_activation_approval as signatures

integrity = package.integrity
Error = integrity.IntegrityError
PIN_FIELDS = (
    "schema", "qualification_source_commit", "qualification_manifest_sha256",
    "fresh_process_verifier_binary_sha256", "fresh_process_verifier_report_sha256",
    "core_spec_sha256", "core_vector_sha256", "proof_algebra_sha256",
)
SIGNER_FIELDS = ("signer_identity", "allowed_signers_sha256", "key_blob_sha256", "key_fingerprint", "key_type")


def parse_reviewed_proof_pin(data: bytes) -> dict:
    """Parse only the canonical generated literal, never evaluate Rust source."""
    if len(data) > 64 * 1024:
        raise Error("reviewed proof pin is oversized")
    try:
        lines = iter(data.decode("utf-8", "strict").splitlines())
        def line(expected):
            if next(lines) != expected:
                raise Error("proof pin is not the canonical generated literal")
        def field(name, indentation):
            source = next(lines)
            prefix = " " * indentation + name + ": "
            if not source.startswith(prefix) or not source.endswith(","):
                raise Error("proof pin field layout is invalid")
            value = json.loads(source[len(prefix):-1])
            if not isinstance(value, str):
                raise Error("proof pin field must be a string literal")
            return value
        line("Some(ProductionV4ActivationEvidence {")
        fields = {name: field(name, 4) for name in PIN_FIELDS}
        if fields["schema"] != "CMFD_PRODUCTION_V4_ACTIVATION_V1":
            raise Error("mainnet cannot reuse single-producer RC activation")
        signatures._commit(fields["qualification_source_commit"], "proof qualification commit")
        for name in PIN_FIELDS[2:]:
            signatures._hex256(fields[name], name)
        line("    approval_trust: ProductionV4ActivationApprovalTrust {")
        trust = {name: field(name, 8) for name in ("contract_schema", "qualification_binding_sha256", "ssh_keygen_sha256")}
        for role in signatures.ROLES:
            prefix = "Some(" if role == signatures.REPRODUCER_ROLE else ""
            suffix = ")" if prefix else ""
            line(f"        {role}: {prefix}ProductionV4ActivationSignerTrust {{")
            trust[role] = {name: field(name, 12) for name in SIGNER_FIELDS}
            line(f"        }}{suffix},")
        line("    },")
        line("})")
        if next(lines, None) is not None:
            raise Error("proof pin contains trailing content")
    except (StopIteration, UnicodeError, json.JSONDecodeError) as error:
        raise Error("proof pin is not a supported canonical literal") from error
    fields["approval_trust"] = integrity._validate_production_v4_approval_trust_fields(trust)
    if trust["contract_schema"] != signatures.SUBJECT_SCHEMA:
        raise Error("mainnet proof target must use dual-party trust")
    if integrity._render_production_v4_activation_pin(fields) != data:
        raise Error("proof pin does not round-trip to its canonical literal")
    return fields


def validate_proof_binding(fields: dict, pin_bytes: bytes, qualification: dict, trust_policy: dict) -> None:
    if approval.digest(pin_bytes) != qualification["source_pin_sha256"]:
        raise Error("proof target differs from the signed qualification target")
    if fields["qualification_source_commit"] != qualification["qualification_source_commit"]:
        raise Error("proof target qualification commit mismatch")
    expected = {
        "qualification_manifest_sha256": qualification["files"]["independent_reproduction_report"]["sha256"],
        "fresh_process_verifier_binary_sha256": qualification["files"]["fresh_process_verifier_script"]["sha256"],
        "fresh_process_verifier_report_sha256": qualification["files"]["fresh_process_verifier_report"]["sha256"],
        "core_spec_sha256": integrity.PRODUCTION_V4_CORE_SPEC_SHA256,
        "core_vector_sha256": integrity.PRODUCTION_V4_CORE_VECTOR_SHA256,
        "proof_algebra_sha256": integrity.PRODUCTION_V4_PROOF_ALGEBRA_SHA256,
    }
    if any(fields[name] != value for name, value in expected.items()):
        raise Error("proof target disagrees with the qualified reports or frozen specifications")
    expected_trust = {**trust_policy, "contract_schema": signatures.SUBJECT_SCHEMA,
                      "qualification_binding_sha256": signatures.qualification_binding_sha256(qualification["files"])}
    if fields["approval_trust"] != expected_trust:
        raise Error("proof target authority/binding differs from the committed review policy")


def byte_array(value: str) -> str:
    package.nonzero_hex(value, 64, "mainnet binary identity")
    return "[" + ", ".join("0x" + value[index:index + 2] for index in range(0, 64, 2)) + "]"


def render_mainnet_pins(plan: dict, manifest_bytes: bytes, proof_pin_bytes: bytes) -> dict[str, bytes]:
    fields = parse_reviewed_proof_pin(proof_pin_bytes)
    rules = plan["payload"]["rules"]
    pow_limit = package.nonzero_hex(rules["proof_of_work"]["pow_limit"], 64, "mainnet easiest target")
    initial_target = package.nonzero_hex(plan["payload"]["initial_target"], 64, "mainnet starting target")
    if int(initial_target, 16) > int(pow_limit, 16):
        raise Error("mainnet starting target exceeds the easiest target")
    rewards = rules["reward_destinations"]
    steward = integrity._require_xonly_public_key(rewards["steward_xonly_public_key"], "steward reward key")
    community = integrity._require_xonly_public_key(rewards["community_xonly_public_key"], "community reward key")
    # Only validated string literals are rendered. No external Rust statements,
    # macros, includes, source paths or environment expressions are accepted.
    proof_expression = integrity._render_production_v4_activation_pin(fields).decode()[5:-2]
    lines = ["Some(MainnetReleaseConfiguration {"]
    for name, value in (("launch_plan_digest", plan["launch_plan_digest"]), ("network_id", plan["network_id"]),
                        ("pow_limit", pow_limit), ("initial_target", initial_target), ("steward_reward_destination", steward),
                        ("community_reward_destination", community)):
        lines.append(f"    {name}: {byte_array(value)},")
    lines.append(f'    approval_manifest_sha256: "{approval.digest(manifest_bytes)}",')
    lines.append("    activation: " + proof_expression.replace("\n", "\n    ") + ",")
    lines.append("})")
    return {"mainnet_release_pin.inc.rs": ("\n".join(lines) + "\n").encode(),
            "mainnet_network_id.inc.rs": ("Some(" + byte_array(plan["network_id"]) + ")\n").encode()}


def generate(*, repo: Path, review_commit: str, plan: Path, qualification: Path, trust: Path,
             proof_pin: Path, approval_manifest: Path, output: Path, material: dict) -> dict:
    subject, trust_policy, snapshots = approval.load_inputs(repo, review_commit, plan, qualification, trust)
    proof_snapshot = signatures._snapshot(proof_pin, "reviewed proof pin", 64 * 1024)
    manifest_snapshot = signatures._snapshot(approval_manifest, "mainnet approval manifest", package.MAX_INFO)
    verified = approval.verify_pair(subject=subject, expected_trust=trust_policy, **material)
    if signatures.canonical_json(verified) != manifest_snapshot.data:
        raise Error("supplied mainnet manifest is not the freshly verified signature result")
    fields = parse_reviewed_proof_pin(proof_snapshot.data)
    qualification_document = signatures._json_object(snapshots["qualification"].data, "qualification subject")
    validate_proof_binding(fields, proof_snapshot.data, qualification_document, trust_policy)
    plan_document = package.validate_plan(snapshots["plan"].data)
    candidate = render_mainnet_pins(plan_document, manifest_snapshot.data, proof_snapshot.data)
    for label, snapshot in {**snapshots, "proof_pin": proof_snapshot, "approval_manifest": manifest_snapshot}.items():
        signatures._assert_snapshot_current(snapshot, label)
    integrity._assert_clean_exact_repo(repo, review_commit)
    # A candidate directory must be outside source. Actual pin application is
    # explicit and reviewed; this generator cannot arm the repository itself.
    destination = output.resolve(strict=False)
    source = repo.resolve(strict=True)
    if destination == source or source in destination.parents:
        raise Error("pin candidates must be written outside the source repository")
    destination.mkdir(parents=False, exist_ok=False)
    written = []
    try:
        for name, data in candidate.items():
            path = destination / name
            identity = integrity._write_new(path, data)
            written.append((path, identity))
        report = {"schema": "CMFD_MAINNET_PIN_CANDIDATES_V1", "review_source_commit": review_commit,
                  "launch_plan_digest": plan_document["launch_plan_digest"], "network_id": plan_document["network_id"],
                  "mainnet_approval_manifest_sha256": approval.digest(manifest_snapshot.data),
                  "proof_pin_sha256": approval.digest(proof_snapshot.data),
                  "files": {name: {"bytes": len(data), "sha256": approval.digest(data)} for name, data in candidate.items()},
                  "source_pins_applied": False, "mainnet_activation_authorized": False}
        path = destination / "PIN-REVIEW.json"
        identity = integrity._write_new(path, signatures.canonical_json(report))
        written.append((path, identity))
        for label, snapshot in {**snapshots, "proof_pin": proof_snapshot, "approval_manifest": manifest_snapshot}.items():
            signatures._assert_snapshot_current(snapshot, label)
        integrity._assert_clean_exact_repo(repo, review_commit)
    except BaseException:
        for path, identity in reversed(written):
            integrity._remove_exact_new(path, identity, "new mainnet pin candidate")
        # Never recursively remove a directory or a concurrently added file.
        try:
            destination.rmdir()
        except OSError:
            pass
        raise
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--review-commit", required=True)
    for name in ("plan", "qualification-subject", "trust", "proof-pin", "approval-manifest", "output",
                 "producer-policy", "producer-approval", "producer-signature",
                 "reproducer-policy", "reproducer-approval", "reproducer-signature", "ssh-keygen"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("producer-identity", "reproducer-identity", "ssh-keygen-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path) and not value.is_absolute():
            parser.error(f"--{name} must be an absolute path")
    try:
        report = generate(repo=args.repo, review_commit=args.review_commit, plan=args.plan,
                          qualification=args.qualification_subject, trust=args.trust, proof_pin=args.proof_pin,
                          approval_manifest=args.approval_manifest, output=args.output, material={
                              "producer_allowed_signers": args.producer_policy, "producer_signer_identity": args.producer_identity,
                              "producer_approval": args.producer_approval, "producer_signature": args.producer_signature,
                              "reproducer_allowed_signers": args.reproducer_policy, "reproducer_signer_identity": args.reproducer_identity,
                              "reproducer_approval": args.reproducer_approval, "reproducer_signature": args.reproducer_signature,
                              "ssh_keygen": args.ssh_keygen, "expected_verifier_sha256": args.ssh_keygen_sha256,
                          })
        print(signatures.canonical_json(report).decode(), end="")
    except (OSError, ValueError, KeyError, TypeError, Error, signatures.ApprovalError) as error:
        parser.exit(1, f"Mainnet pin generation failed: {error}\n")


if __name__ == "__main__":
    main()
