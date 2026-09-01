#!/usr/bin/env python3
"""Prepare and verify an explicit single-producer ProductionV4 RC activation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import production_v4_activation_approval as activation_approval
import release_integrity as integrity

SUBJECT_SCHEMA = "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_APPROVAL_SUBJECT_V1"
ACTIVATION_SCHEMA = "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_ACTIVATION_V1"
ROLE_APPROVAL_SCHEMA = "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_ROLE_APPROVAL_V1"
QUALIFICATION_SCHEMA = "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_QUALIFICATION_V1"
VERIFIER_REPORT_SCHEMA = "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_VERIFIER_REPORT_V1"
RECEIPT_SCHEMA = "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_APPROVAL_RECEIPT_V1"
NAMESPACE = activation_approval.NAMESPACES[activation_approval.PRODUCER_ROLE]
PIN_RELATIVE = Path("crates/cmfd-node/production_v4_activation_pin.inc.rs")
VERIFIER_RELATIVE = Path("scripts/production-v4-independent-verifier.py")

PIN_FIELDS_NAME = "RCNET1-SINGLE-PRODUCER-PIN-FIELDS.json"
PROPOSED_PIN_NAME = "RCNET1-PROPOSED-ACTIVATION-PIN.inc.rs"
STRICT_STATEMENT_NAME = "RCNET1-BLOCK1-STRICT-STATEMENT.json"
VERIFIER_REPORT_NAME = "RCNET1-FRESH-VERIFIER-REPORT.json"
QUALIFICATION_NAME = "RCNET1-SINGLE-PRODUCER-QUALIFICATION.json"
APPROVAL_NAME = "RCNET1-PRODUCER-ACTIVATION-APPROVAL.json"
REVIEW_NAME = "REVIEW-BEFORE-SIGNING.txt"

DECLARATIONS = {
    "experimental_release_candidate_only": True,
    "external_audit": False,
    "independent_reproduction": False,
    "mainnet_authorization": False,
}


class SingleProducerError(RuntimeError):
    """The RC-only activation preparation or verification failed closed."""


def canonical_json(value: object) -> bytes:
    return activation_approval.canonical_json(value)


def _git(repo: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise SingleProducerError(f"git {' '.join(arguments)} failed: {detail[:500]}")
    return completed.stdout


def _clean_source_commit(repo: Path) -> str:
    repo = repo.resolve(strict=True)
    if _git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise SingleProducerError("activation source tree must be completely clean")
    commit = _git(repo, "rev-parse", "HEAD").decode("ascii", "strict").strip()
    try:
        activation_approval._commit(commit, "activation source commit")
    except activation_approval.ApprovalError as error:
        raise SingleProducerError(str(error)) from error
    return commit


def _require_unpinned_source(repo: Path) -> None:
    pin = repo / PIN_RELATIVE
    try:
        data = pin.read_bytes()
    except OSError as error:
        raise SingleProducerError("ProductionV4 activation pin cannot be read") from error
    if data not in (b"None\n", b"None\r\n"):
        raise SingleProducerError("ProductionV4 activation source is already pinned")


def _identity(path: Path, label: str) -> dict[str, object]:
    try:
        row = integrity._production_v4_file_identity(path, label)
    except integrity.IntegrityError as error:
        raise SingleProducerError(str(error)) from error
    return {
        "name": path.name,
        "bytes": row["bytes"],
        "sha256": row["sha256"],
        "blake3": row["blake3"],
    }


def _canonical_candidate(path: Path) -> tuple[dict[str, object], dict[str, object]]:
    try:
        candidate, candidate_bytes = integrity._bounded_json_object(
            path, "RCNet launch candidate"
        )
        validated = integrity._validate_production_v4_rcnet_candidate(candidate)
        if candidate_bytes != integrity._canonical_rcnet_v2_candidate(
            candidate, validated
        ):
            raise SingleProducerError("RCNet launch candidate is not canonical")
    except integrity.IntegrityError as error:
        raise SingleProducerError(str(error)) from error
    return candidate, validated


def _network(candidate: dict[str, object], validated: dict[str, object]) -> dict[str, object]:
    payload = candidate.get("payload")
    proof = payload.get("proof_of_work") if isinstance(payload, dict) else None
    if not isinstance(proof, dict):
        raise SingleProducerError("RCNet launch candidate proof policy is unavailable")
    return {
        "profile": "CommonFoundry RCNet-1",
        "launch_root": candidate["launch_root"],
        "network_id": validated["network_id"],
        "virtual_genesis_hash": candidate["virtual_genesis_hash"],
        "virtual_genesis_timestamp_unix_seconds": validated[
            "virtual_genesis_timestamp_unix_seconds"
        ],
        "pow_limit": proof["pow_limit"],
    }


def _parse_json_output(data: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SingleProducerError(f"{label} did not emit valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise SingleProducerError(f"{label} did not emit a JSON object")
    return value


def validate_verifier_result(
    value: object, *, require_candidate_claims: bool
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SingleProducerError("ProductionV4 verifier result is malformed")
    required = {
        "implemented_stages_accepted": True,
        "target_met": True,
    }
    if require_candidate_claims:
        required.update(
            {
                "candidate_claims_verified": True,
                "full_cryptographic_proof_verified": True,
            }
        )
    for field, expected in required.items():
        if value.get(field) is not expected:
            raise SingleProducerError(
                f"ProductionV4 verifier did not establish required result: {field}"
            )
    if require_candidate_claims and value.get("remaining_stages") != []:
        raise SingleProducerError("ProductionV4 verifier left cryptographic stages pending")
    return value


def _run_verifier(
    *,
    repo: Path,
    template: Path,
    statement: Path,
    proof: Path,
    fixed_record: Path,
    model_bank: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    verifier = repo / VERIFIER_RELATIVE

    def run(arguments: list[str], label: str) -> dict[str, object]:
        try:
            completed = subprocess.run(
                [sys.executable, str(verifier), *arguments, "--json"],
                cwd=repo,
                check=False,
                capture_output=True,
                timeout=900,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SingleProducerError(f"{label} could not run") from error
        if len(completed.stdout) > 1024 * 1024 or len(completed.stderr) > 1024 * 1024:
            raise SingleProducerError(f"{label} output exceeded its bound")
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace").strip()
            if not detail:
                detail = completed.stdout.decode("utf-8", "replace").strip()
            raise SingleProducerError(f"{label} rejected the proof: {detail[:1000]}")
        return _parse_json_output(completed.stdout, label)

    template_result = run(
        [
            "--template",
            str(template),
            "--proof",
            str(proof),
            "--write-statement",
            str(statement),
        ],
        "ProductionV4 template verifier",
    )
    validate_verifier_result(template_result, require_candidate_claims=False)
    statement_result = run(
        [
            "--statement",
            str(statement),
            "--proof",
            str(proof),
            "--fixed-artifact-record",
            str(fixed_record),
            "--model-bank",
            str(model_bank),
        ],
        "ProductionV4 strict-statement verifier",
    )
    validate_verifier_result(statement_result, require_candidate_claims=True)
    return template_result, statement_result


def build_pin_fields(
    *,
    source_commit: str,
    qualification_manifest_sha256: str,
    verifier_script_sha256: str,
    verifier_report_sha256: str,
    qualification_binding_sha256: str,
    ssh_keygen_sha256: str,
    signer_identity: str,
    authority: dict[str, str],
) -> dict[str, object]:
    return {
        "schema": ACTIVATION_SCHEMA,
        "qualification_source_commit": source_commit,
        "qualification_manifest_sha256": qualification_manifest_sha256,
        "fresh_process_verifier_binary_sha256": verifier_script_sha256,
        "fresh_process_verifier_report_sha256": verifier_report_sha256,
        "core_spec_sha256": integrity.PRODUCTION_V4_CORE_SPEC_SHA256,
        "core_vector_sha256": integrity.PRODUCTION_V4_CORE_VECTOR_SHA256,
        "proof_algebra_sha256": integrity.PRODUCTION_V4_PROOF_ALGEBRA_SHA256,
        "approval_trust": {
            "contract_schema": SUBJECT_SCHEMA,
            "qualification_binding_sha256": qualification_binding_sha256,
            "ssh_keygen_sha256": ssh_keygen_sha256,
            "producer": {"signer_identity": signer_identity, **authority},
            "independent_reproducer": None,
        },
    }


def build_approval(
    *,
    source_commit: str,
    network: dict[str, object],
    signer_identity: str,
    authority: dict[str, str],
    qualification_manifest: dict[str, object],
    verifier_report: dict[str, object],
    strict_statement: dict[str, object],
    pin_fields: dict[str, object],
    proposed_pin: dict[str, object],
) -> dict[str, object]:
    subject = {
        "schema": SUBJECT_SCHEMA,
        "activation_source_commit": source_commit,
        "declarations": DECLARATIONS,
        "network": network,
        "qualification_manifest": qualification_manifest,
        "fresh_verifier_report": verifier_report,
        "strict_statement": strict_statement,
        "pin_fields": pin_fields,
        "proposed_activation_pin": proposed_pin,
    }
    return {
        "schema": ROLE_APPROVAL_SCHEMA,
        "role": activation_approval.PRODUCER_ROLE,
        "namespace": NAMESPACE,
        "signer_identity": signer_identity,
        "trusted_authority": authority,
        "subject": subject,
    }


def _write(path: Path, data: bytes) -> None:
    if path.exists():
        raise SingleProducerError(f"refusing to overwrite {path}")
    path.write_bytes(data)


def prepare(
    *,
    repo: Path,
    candidate: Path,
    template: Path,
    proof: Path,
    proof_log: Path,
    model_bank: Path,
    fixed_record: Path,
    allowed_signers: Path,
    signer_identity: str,
    ssh_keygen: Path,
    output_directory: Path,
) -> Path:
    repo = repo.resolve(strict=True)
    source_commit = _clean_source_commit(repo)
    _require_unpinned_source(repo)
    if output_directory.exists():
        raise SingleProducerError("approval output directory already exists")
    try:
        output_directory.resolve().relative_to(repo)
    except ValueError:
        pass
    else:
        raise SingleProducerError("approval output directory must be outside the source tree")

    candidate_value, validated_candidate = _canonical_candidate(candidate)
    network = _network(candidate_value, validated_candidate)
    policy_data = allowed_signers.resolve(strict=True).read_bytes()
    try:
        authority = activation_approval.parse_allowed_signers_authority(
            policy_data,
            signer_identity=signer_identity,
            role=activation_approval.PRODUCER_ROLE,
        )
    except activation_approval.ApprovalError as error:
        raise SingleProducerError(str(error)) from error
    ssh_identity = _identity(ssh_keygen, "OpenSSH approval verifier")
    verifier = repo / VERIFIER_RELATIVE
    tracked_verifier = _git(repo, "show", f"HEAD:{VERIFIER_RELATIVE.as_posix()}")
    if verifier.read_bytes() != tracked_verifier:
        raise SingleProducerError("verifier entrypoint is not byte-identical to tracked HEAD")

    output_directory.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix="cmfd-rc-approval-", dir=output_directory.parent)
    )
    try:
        statement_path = temporary / STRICT_STATEMENT_NAME
        template_result, statement_result = _run_verifier(
            repo=repo,
            template=template.resolve(strict=True),
            statement=statement_path,
            proof=proof.resolve(strict=True),
            fixed_record=fixed_record.resolve(strict=True),
            model_bank=model_bank.resolve(strict=True),
        )
        strict_statement = _parse_json_output(
            statement_path.read_bytes(), "ProductionV4 strict statement"
        )
        canonical_statement = canonical_json(strict_statement)
        statement_path.write_bytes(canonical_statement)

        proof_identity = _identity(proof, "ProductionV4 qualification proof")
        reported_proof = statement_result.get("proof")
        if (
            not isinstance(reported_proof, dict)
            or reported_proof.get("bytes") != proof_identity["bytes"]
            or reported_proof.get("sha256") != proof_identity["sha256"]
        ):
            raise SingleProducerError("fresh verifier proof identity does not match the input")
        candidate_artifacts = candidate_value["payload"]["artifacts"]
        model_identity = _identity(model_bank, "ProductionV4 model bank")
        fixed_identity = _identity(fixed_record, "ProductionV4 fixed record")
        for role, actual in (("bank", model_identity), ("fixed_record", fixed_identity)):
            expected = candidate_artifacts[role]
            if any(expected[field] != actual[field] for field in ("bytes", "sha256", "blake3")):
                raise SingleProducerError(
                    f"{role} identity does not match the RCNet launch candidate"
                )

        verifier_report_value = {
            "schema": VERIFIER_REPORT_SCHEMA,
            "activation_source_commit": source_commit,
            "template_derivation_result": template_result,
            "strict_statement_result": statement_result,
        }
        verifier_report_bytes = canonical_json(verifier_report_value)
        verifier_report_path = temporary / VERIFIER_REPORT_NAME
        _write(verifier_report_path, verifier_report_bytes)

        artifacts = {
            "fixed_artifact_record": fixed_identity,
            "fresh_verifier_entrypoint": _identity(
                verifier, "ProductionV4 fresh verifier entrypoint"
            ),
            "launch_candidate": _identity(candidate, "RCNet launch candidate"),
            "model_bank": model_identity,
            "proof_generation_log": _identity(proof_log, "ProductionV4 proof log"),
            "proof_template": _identity(template, "ProductionV4 proof template"),
            "qualification_proof": proof_identity,
            "strict_statement": _identity(statement_path, "ProductionV4 strict statement"),
            "verifier_report": _identity(
                verifier_report_path, "ProductionV4 verifier report"
            ),
        }
        qualification_value = {
            "schema": QUALIFICATION_SCHEMA,
            "activation_source_commit": source_commit,
            "declarations": DECLARATIONS,
            "network": network,
            "artifacts": artifacts,
            "verification": {
                "candidate_claims_verified": True,
                "full_cryptographic_proof_verified": True,
                "target_met": True,
            },
        }
        qualification_bytes = canonical_json(qualification_value)
        qualification_path = temporary / QUALIFICATION_NAME
        _write(qualification_path, qualification_bytes)
        qualification_identity = _identity(
            qualification_path, "ProductionV4 RC qualification manifest"
        )
        qualification_binding = hashlib.sha256(qualification_bytes).hexdigest()

        pin_fields = build_pin_fields(
            source_commit=source_commit,
            qualification_manifest_sha256=qualification_identity["sha256"],
            verifier_script_sha256=artifacts["fresh_verifier_entrypoint"]["sha256"],
            verifier_report_sha256=artifacts["verifier_report"]["sha256"],
            qualification_binding_sha256=qualification_binding,
            ssh_keygen_sha256=ssh_identity["sha256"],
            signer_identity=signer_identity,
            authority=authority,
        )
        pin_fields_path = temporary / PIN_FIELDS_NAME
        _write(pin_fields_path, canonical_json(pin_fields))
        try:
            proposed_pin_bytes = integrity._render_production_v4_activation_pin(pin_fields)
        except integrity.IntegrityError as error:
            raise SingleProducerError(str(error)) from error
        proposed_pin_path = temporary / PROPOSED_PIN_NAME
        _write(proposed_pin_path, proposed_pin_bytes)

        approval_value = build_approval(
            source_commit=source_commit,
            network=network,
            signer_identity=signer_identity,
            authority=authority,
            qualification_manifest=qualification_identity,
            verifier_report=artifacts["verifier_report"],
            strict_statement=artifacts["strict_statement"],
            pin_fields=_identity(pin_fields_path, "ProductionV4 pin fields"),
            proposed_pin=_identity(proposed_pin_path, "ProductionV4 proposed source pin"),
        )
        approval_bytes = canonical_json(approval_value)
        approval_path = temporary / APPROVAL_NAME
        _write(approval_path, approval_bytes)
        review = (
            "Common Foundry RCNet-1 single-producer activation\n\n"
            f"SIGN THIS FILE: {output_directory / APPROVAL_NAME}\n"
            f"Approval SHA-256: {hashlib.sha256(approval_bytes).hexdigest()}\n"
            f"Activation source commit: {source_commit}\n"
            f"Network ID: {network['network_id']}\n"
            f"Signer: {signer_identity}\n"
            f"Key fingerprint: {authority['key_fingerprint']}\n\n"
            "Declarations: experimental RC only; no independent reproduction; "
            "no external audit; no mainnet authorization.\n"
        ).encode("utf-8")
        _write(temporary / REVIEW_NAME, review)
        if _clean_source_commit(repo) != source_commit:
            raise SingleProducerError("activation source commit changed during preparation")
        _require_unpinned_source(repo)
        os.replace(temporary, output_directory)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return output_directory / APPROVAL_NAME


def _bundle_identity(directory: Path, name: str, label: str) -> dict[str, object]:
    return _identity(directory / name, label)


def verify_signature(
    *,
    repo: Path,
    bundle_directory: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    ssh_keygen: Path,
    install_pin: bool,
) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    source_commit = _clean_source_commit(repo)
    _require_unpinned_source(repo)
    bundle_directory = bundle_directory.resolve(strict=True)
    approval_path = bundle_directory / APPROVAL_NAME
    approval_bytes = approval_path.read_bytes()
    approval = _parse_json_output(approval_bytes, "producer activation approval")
    if approval_bytes != canonical_json(approval):
        raise SingleProducerError("producer activation approval is not canonical JSON")
    if (
        approval.get("schema") != ROLE_APPROVAL_SCHEMA
        or approval.get("role") != activation_approval.PRODUCER_ROLE
        or approval.get("namespace") != NAMESPACE
        or approval.get("signer_identity") != signer_identity
    ):
        raise SingleProducerError("producer activation approval role or scope is invalid")
    subject = approval.get("subject")
    if not isinstance(subject, dict) or subject.get("schema") != SUBJECT_SCHEMA:
        raise SingleProducerError("producer activation approval subject is invalid")
    if subject.get("activation_source_commit") != source_commit:
        raise SingleProducerError("producer activation approval is for a different source commit")
    if subject.get("declarations") != DECLARATIONS:
        raise SingleProducerError("producer activation declarations are not the RC-only policy")

    policy_data = allowed_signers.resolve(strict=True).read_bytes()
    try:
        authority = activation_approval.parse_allowed_signers_authority(
            policy_data,
            signer_identity=signer_identity,
            role=activation_approval.PRODUCER_ROLE,
        )
    except activation_approval.ApprovalError as error:
        raise SingleProducerError(str(error)) from error
    if approval.get("trusted_authority") != authority:
        raise SingleProducerError("approval signer authority does not match trusted policy")

    expected_bundle = {
        "qualification_manifest": _bundle_identity(
            bundle_directory, QUALIFICATION_NAME, "qualification manifest"
        ),
        "fresh_verifier_report": _bundle_identity(
            bundle_directory, VERIFIER_REPORT_NAME, "fresh verifier report"
        ),
        "strict_statement": _bundle_identity(
            bundle_directory, STRICT_STATEMENT_NAME, "strict statement"
        ),
        "pin_fields": _bundle_identity(bundle_directory, PIN_FIELDS_NAME, "pin fields"),
        "proposed_activation_pin": _bundle_identity(
            bundle_directory, PROPOSED_PIN_NAME, "proposed activation pin"
        ),
    }
    for field, identity in expected_bundle.items():
        if subject.get(field) != identity:
            raise SingleProducerError(f"signed {field} identity does not match the bundle")

    pin_fields_bytes = (bundle_directory / PIN_FIELDS_NAME).read_bytes()
    pin_fields = _parse_json_output(pin_fields_bytes, "ProductionV4 pin fields")
    if pin_fields_bytes != canonical_json(pin_fields):
        raise SingleProducerError("ProductionV4 pin fields are not canonical JSON")
    try:
        expected_pin = integrity._render_production_v4_activation_pin(pin_fields)
    except integrity.IntegrityError as error:
        raise SingleProducerError(str(error)) from error
    proposed_pin = (bundle_directory / PROPOSED_PIN_NAME).read_bytes()
    if proposed_pin != expected_pin:
        raise SingleProducerError("proposed activation pin does not match its signed fields")
    trust = pin_fields.get("approval_trust")
    if not isinstance(trust, dict) or trust.get("producer") != {
        "signer_identity": signer_identity,
        **authority,
    }:
        raise SingleProducerError("proposed activation pin signer trust is invalid")
    if trust.get("independent_reproducer") is not None:
        raise SingleProducerError("single-producer pin claims an independent reproducer")
    if (
        pin_fields.get("schema") != ACTIVATION_SCHEMA
        or pin_fields.get("qualification_source_commit") != source_commit
        or pin_fields.get("qualification_manifest_sha256")
        != expected_bundle["qualification_manifest"]["sha256"]
        or pin_fields.get("fresh_process_verifier_report_sha256")
        != expected_bundle["fresh_verifier_report"]["sha256"]
        or trust.get("qualification_binding_sha256")
        != expected_bundle["qualification_manifest"]["sha256"]
    ):
        raise SingleProducerError("proposed activation pin does not bind this RC qualification")
    ssh_identity = _identity(ssh_keygen, "OpenSSH approval verifier")
    if trust.get("ssh_keygen_sha256") != ssh_identity["sha256"]:
        raise SingleProducerError("OpenSSH verifier does not match the signed trust pin")

    signature = signature.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="cmfd-rc-signature-verify-") as directory:
        private = Path(directory)
        verifier_copy = private / f"ssh-keygen{ssh_keygen.suffix if os.name == 'nt' else ''}"
        policy_copy = private / "producer.allowed_signers"
        signature_copy = private / "producer-approval.sig"
        activation_approval._write_exclusive(
            verifier_copy, ssh_keygen.read_bytes(), executable=True
        )
        activation_approval._write_exclusive(policy_copy, policy_data)
        activation_approval._write_exclusive(signature_copy, signature.read_bytes())
        environment = activation_approval._verification_environment(private, ssh_keygen)
        try:
            activation_approval._verify_signature(
                verifier=verifier_copy,
                allowed_signers=policy_copy,
                signer_identity=signer_identity,
                namespace=NAMESPACE,
                signature=signature_copy,
                payload=approval_bytes,
                environment=environment,
            )
        except activation_approval.ApprovalError as error:
            raise SingleProducerError(str(error)) from error

    if install_pin:
        (repo / PIN_RELATIVE).write_bytes(proposed_pin)
    return {
        "schema": RECEIPT_SCHEMA,
        "activation_source_commit": source_commit,
        "approval_sha256": hashlib.sha256(approval_bytes).hexdigest(),
        "signature_sha256": hashlib.sha256(signature.read_bytes()).hexdigest(),
        "installed": install_pin,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare", help="prepare the exact JSON to sign")
    for target in (prepare_parser,):
        target.add_argument("--repo", type=Path, required=True)
        target.add_argument("--candidate", type=Path, required=True)
        target.add_argument("--template", type=Path, required=True)
        target.add_argument("--proof", type=Path, required=True)
        target.add_argument("--proof-log", type=Path, required=True)
        target.add_argument("--model-bank", type=Path, required=True)
        target.add_argument("--fixed-record", type=Path, required=True)
        target.add_argument("--allowed-signers", type=Path, required=True)
        target.add_argument("--signer-identity", required=True)
        target.add_argument("--ssh-keygen", type=Path, required=True)
        target.add_argument("--output-directory", type=Path, required=True)
    verify_parser = subparsers.add_parser(
        "verify", help="verify the producer signature and optionally install the pin"
    )
    verify_parser.add_argument("--repo", type=Path, required=True)
    verify_parser.add_argument("--bundle-directory", type=Path, required=True)
    verify_parser.add_argument("--signature", type=Path, required=True)
    verify_parser.add_argument("--allowed-signers", type=Path, required=True)
    verify_parser.add_argument("--signer-identity", required=True)
    verify_parser.add_argument("--ssh-keygen", type=Path, required=True)
    verify_parser.add_argument("--install-pin", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "prepare":
            approval = prepare(
                repo=args.repo,
                candidate=args.candidate,
                template=args.template,
                proof=args.proof,
                proof_log=args.proof_log,
                model_bank=args.model_bank,
                fixed_record=args.fixed_record,
                allowed_signers=args.allowed_signers,
                signer_identity=args.signer_identity,
                ssh_keygen=args.ssh_keygen,
                output_directory=args.output_directory,
            )
            print(approval)
        else:
            receipt = verify_signature(
                repo=args.repo,
                bundle_directory=args.bundle_directory,
                signature=args.signature,
                allowed_signers=args.allowed_signers,
                signer_identity=args.signer_identity,
                ssh_keygen=args.ssh_keygen,
                install_pin=args.install_pin,
            )
            print(canonical_json(receipt).decode("utf-8"), end="")
    except (OSError, SingleProducerError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
