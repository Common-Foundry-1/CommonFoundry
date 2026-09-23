#!/usr/bin/env python3
"""Reverify a complete preserved V4 proof for an owner-signed mainnet release.

This is internal verification using the independent verifier implementation,
not organizationally independent review, a mainnet block, or release approval.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
import tempfile

import package_mainnet as package
import production_v4_activation_approval as signatures

SCHEMA = "CMFD_MAINNET_INTERNAL_PROOF_QUALIFICATION_V1"
TRUST_SCHEMA = "CMFD_MAINNET_SINGLE_SIGNER_APPROVAL_SUBJECT_V1"
ACTIVATION_SCHEMA = "CMFD_MAINNET_SINGLE_SIGNER_PROOF_ACTIVATION_V1"
VERIFIER = "scripts/production-v4-independent-verifier.py"
FILE_ROLES = {"model_bank", "fixed_artifact_record", "qualification_proof",
              "strict_statement", "fresh_process_verifier_script"}
DECLARATIONS = {"internal_verification": True, "independent_reproduction": False,
                "external_audit": False, "mainnet_authorization": False,
                "scope": "preserved_full_proof_not_live_mainnet"}
Error = package.Error


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verifier_sources(repo: Path, commit: str) -> dict:
    # Bind all tracked Python sources, including the verifier's local imports,
    # rather than just its thin CLI entry point. Ignore caches and site packages.
    rows = package.integrity._run_git_bytes(repo, "ls-tree", "-rz", commit, "--", "scripts")
    files = {}
    for row in rows.split(b"\0"):
        if not row:
            continue
        metadata, encoded_name = row.split(b"\t", 1)
        name = encoded_name.decode("utf-8", "strict")
        if not name.endswith(".py") or "/tests/" in name:
            continue
        if not name.startswith("scripts/") or "\\" in name or any(part in ("", ".", "..") for part in name.split("/")):
            raise Error("proof qualification source contains an unsafe Python path")
        if metadata.split()[:2] not in ([b"100644", b"blob"], [b"100755", b"blob"]):
            raise Error("proof qualification source contains a special Python entry")
        data = package.integrity._tracked_blob_at(repo, commit, name)
        files[name] = {"bytes": len(data), "sha256": digest(data)}
    if VERIFIER not in files:
        raise Error("proof verifier is absent from the reviewed source")
    return files


def validate(data: bytes) -> dict:
    record = package.strict_json(data, "internal proof qualification", signatures.MAX_JSON_BYTES)
    expected = {"schema", "qualification_source_commit", "verifier_sources_sha256",
                "files", "verifier_result", "declarations"}
    if set(record) != expected or record["schema"] != SCHEMA or package.canonical(record) != data:
        raise Error("mainnet requires a canonical internal proof qualification record")
    signatures._commit(record["qualification_source_commit"], "qualification source commit")
    package.nonzero_hex(record["verifier_sources_sha256"], 64, "verifier source digest")
    if package.canonical(record["declarations"]) != package.canonical(DECLARATIONS):
        raise Error("internal proof qualification cannot claim independent review or authorization")
    files = signatures._exact_fields(record["files"], FILE_ROLES, "qualified proof inputs")
    for role, row in files.items():
        signatures._exact_fields(row, {"bytes", "sha256", "blake3"}, role)
        if type(row["bytes"]) is not int or row["bytes"] <= 0:
            raise Error("qualified proof input size is invalid")
        for field in ("sha256", "blake3"):
            package.nonzero_hex(row[field], 64, role + " " + field)
    if files["qualification_proof"]["bytes"] != 12025320:
        raise Error("qualified proof does not have the complete V4 framing")
    result = record["verifier_result"]
    if not isinstance(result, dict) or result.get("schema") != "CommonFoundry/ForgeMatrix/V4/IndependentVerificationResult/v1":
        raise Error("invalid full-proof verifier result")
    for flag in ("implemented_stages_accepted", "candidate_claims_verified", "target_met", "full_cryptographic_proof_verified"):
        if result.get(flag) is not True:
            raise Error("full-proof verification did not establish " + flag)
    if result.get("remaining_stages") != []:
        raise Error("full-proof verification left stages incomplete")
    proof = result.get("proof")
    if (not isinstance(proof, dict) or proof.get("canonical") is not True
            or any(proof.get(field) != files["qualification_proof"][field] for field in ("bytes", "sha256"))):
        raise Error("full-proof verification record belongs to another proof")
    algebra = result.get("algebra")
    required_algebra = {"basefold_merkle_and_query_folds_verified": True,
                       "initial_activation_boundaries_verified": True,
                       "basefold_transcripts_replayed": 3, "opening_reductions_verified": 3,
                       "relations_verified": 6}
    if not isinstance(algebra, dict) or any(
            type(algebra.get(k)) is not type(v) or algebra.get(k) != v for k, v in required_algebra.items()):
        raise Error("full-proof verification lacks complete algebra and boundary checks")
    return record


def validate_source(repo: Path, review_commit: str, record: dict) -> None:
    commit = record["qualification_source_commit"]
    package.integrity._run_git(repo, "merge-base", "--is-ancestor", commit, review_commit)
    for source_commit in {commit, review_commit}:
        sources = verifier_sources(repo, source_commit)
        if digest(package.canonical(sources)) != record["verifier_sources_sha256"]:
            raise Error("proof verifier source changed; fresh qualification is required")
        row = record["files"]["fresh_process_verifier_script"]
        if any(row[field] != sources[VERIFIER][field] for field in ("bytes", "sha256")):
            raise Error("proof qualification did not use the reviewed verifier entry point")


def proof_pin_fields(record: dict, trust: dict) -> dict:
    validate(package.canonical(record))
    signatures._exact_fields(trust, {"producer", "ssh_keygen_sha256"}, "one-signer mainnet trust")
    binding = digest(package.canonical(record))
    approval_trust = package.integrity._validate_production_v4_approval_trust_fields({
        **trust, "independent_reproducer": None, "contract_schema": TRUST_SCHEMA,
        "qualification_binding_sha256": binding,
    })
    return {
        "schema": ACTIVATION_SCHEMA, "qualification_source_commit": record["qualification_source_commit"],
        "qualification_manifest_sha256": binding,
        "fresh_process_verifier_binary_sha256": record["files"]["fresh_process_verifier_script"]["sha256"],
        "fresh_process_verifier_report_sha256": digest(package.canonical(record["verifier_result"])),
        "core_spec_sha256": package.integrity.PRODUCTION_V4_CORE_SPEC_SHA256,
        "core_vector_sha256": package.integrity.PRODUCTION_V4_CORE_VECTOR_SHA256,
        "proof_algebra_sha256": package.integrity.PRODUCTION_V4_PROOF_ALGEBRA_SHA256,
        "approval_trust": approval_trust,
    }


def prepare(*, repo: Path, commit: str, plan: Path, proof: Path, statement: Path,
            model_bank: Path, fixed_record: Path, output: Path) -> dict:
    package.integrity._assert_clean_exact_repo(repo, commit)
    if output.resolve(strict=False).is_relative_to(repo.resolve()):
        raise Error("proof qualification output must be outside source")
    if output.exists() or output.is_symlink():
        raise Error("proof qualification output already exists")
    sources = verifier_sources(repo, commit)
    # Git may check Python out as CRLF on Windows. Execute exact committed
    # blobs, not host-normalized bytes or ignored files from the working tree.
    with tempfile.TemporaryDirectory(prefix="cmfd-mainnet-proof-verifier-") as temporary:
        exported = Path(temporary)
        for relative in sources:
            target = exported / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(package.integrity._tracked_blob_at(repo, commit, relative))
        return _prepare_with_verifier(repo=repo, commit=commit, plan=plan, proof=proof, statement=statement,
            model_bank=model_bank, fixed_record=fixed_record, output=output,
            sources=sources, verifier=exported / VERIFIER)


def _prepare_with_verifier(*, repo: Path, commit: str, plan: Path, proof: Path, statement: Path,
                           model_bank: Path, fixed_record: Path, output: Path,
                           sources: dict, verifier: Path) -> dict:
    paths = {"model_bank": model_bank, "fixed_artifact_record": fixed_record,
             "qualification_proof": proof, "strict_statement": statement,
             "fresh_process_verifier_script": verifier}
    def identities():
        return {role: {key: value for key, value in package.integrity._production_v4_file_identity(path, role).items()
                       if key != "name"} for role, path in paths.items()}
    files = identities()
    plan_snapshot = signatures._snapshot(plan, "mainnet plan", 32 * 1024)
    launch = package.validate_plan(plan_snapshot.data)
    for role, artifact in (("model_bank", "bank"), ("fixed_artifact_record", "fixed_record")):
        if files[role] != launch["payload"]["rules"]["artifacts"][artifact]:
            raise Error("qualification input does not match the mainnet plan: " + role)
    raw_result = package.native_output(Path(sys.executable), [str(verifier),
        "--statement", str(statement), "--proof", str(proof), "--fixed-artifact-record", str(fixed_record),
        "--model-bank", str(model_bank), "--json"], timeout_seconds=1800)
    result = package.strict_json(raw_result, "fresh-process full-proof result", signatures.MAX_JSON_BYTES)
    # Remove the local absolute path from shareable evidence; identity is bound
    # by content, not by the operator's filesystem location.
    proof_result = result.get("proof")
    if not isinstance(proof_result, dict):
        raise Error("fresh-process verifier did not report the proof identity")
    proof_result.pop("path", None)
    record = {"schema": SCHEMA, "qualification_source_commit": commit,
              "verifier_sources_sha256": digest(package.canonical(sources)), "files": files,
              "verifier_result": result, "declarations": DECLARATIONS}
    data = package.canonical(record)
    validate(data)
    validate_source(repo, commit, record)
    if identities() != files:
        raise Error("proof qualification input changed during verification")
    signatures._assert_snapshot_current(plan_snapshot, "mainnet plan")
    package.integrity._assert_clean_exact_repo(repo, commit)
    package.integrity._write_new(output, data)
    return {"qualification_sha256": digest(data), "full_cryptographic_proof_verified": True,
            "independent_reproduction": False, "mainnet_activation_authorized": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    for name in ("repo", "plan", "proof", "statement", "model-bank", "fixed-record", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if any(isinstance(value, Path) and not value.is_absolute() for value in vars(args).values()):
        parser.error("all paths must be absolute")
    try:
        print(package.canonical(prepare(**vars(args))).decode(), end="")
    except (OSError, ValueError, KeyError, TypeError, Error, signatures.ApprovalError) as error:
        parser.exit(1, f"Mainnet proof qualification failed: {error}\n")


if __name__ == "__main__":
    main()
