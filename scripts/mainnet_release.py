#!/usr/bin/env python3
"""Mainnet release gate and unsigned independent-build attestation preparation.

No signing, pin application, public publication, or network activation occurs.
The actual independent reproducer must review and sign the resulting statement.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import tempfile

import generate_mainnet_pins as pins
import mainnet_plan_approval as approval
import package_mainnet as package
import prepare_mainnet_dashboard as dashboard
import production_v4_activation_approval as signatures
import verify_mainnet_packages as preflight

integrity = package.integrity
Error = integrity.IntegrityError
TRUST_SOURCE = "packaging/mainnet/APPROVAL-TRUST.json"
PLAN = "MAINNET-PLAN.json"
MANIFEST = "MAINNET-APPROVALS.json"
QUALIFICATION = "MAINNET-QUALIFICATION-SUBJECT.json"
TRUST = "MAINNET-APPROVAL-TRUST.json"
PROOF_PIN = "PRODUCTION-V4-REVIEWED-PIN.review"
DASHBOARD_ASSETS = "DASHBOARD-ASSETS.json"
DASHBOARD_BUILD_EVIDENCE = "DASHBOARD-BUILD-EVIDENCE.json"
CUDA_RUNTIME_PIN = "CUDA-RUNTIME-SHA256.txt"
REPRODUCTION = "MAINNET-REPRODUCTION.json"
REPRODUCTION_SIGNATURE = REPRODUCTION + ".sig"
REPRODUCTION_SCHEMA = "CMFD_MAINNET_BINARY_REPRODUCTION_V1"
REPRODUCTION_STATEMENT = "I independently rebuilt the reviewed source and reproduced the exact four package archives identified in this statement."
ROLE_FILES = {
    "producer": ("MAINNET-PLAN-PRODUCER-APPROVAL.json", "MAINNET-PLAN-PRODUCER-APPROVAL.json.sig", "MAINNET-PRODUCER.allowed_signers"),
    "independent_reproducer": ("MAINNET-PLAN-REPRODUCER-APPROVAL.json", "MAINNET-PLAN-REPRODUCER-APPROVAL.json.sig", "MAINNET-REPRODUCER.allowed_signers"),
}
BASE_EVIDENCE = {PLAN, MANIFEST, QUALIFICATION, TRUST, PROOF_PIN, DASHBOARD_ASSETS,
                 DASHBOARD_BUILD_EVIDENCE,
                 CUDA_RUNTIME_PIN} | {name for names in ROLE_FILES.values() for name in names}
GENERATED = {integrity.BUILDINFO_NAME, integrity.SOURCE_SBOM_NAME, integrity.PROVENANCE_NAME,
             integrity.CHECKSUM_NAME, integrity.CHECKSUM_SIGNATURE_NAME}


def archive_names(version: str) -> dict:
    return {(platform, kind): f"commonfoundry-mainnet-{kind}-{platform}-v{version}" +
            (".zip" if platform == "windows-x86_64" else ".tar.gz")
            for platform in package.PLATFORMS for kind in ("runtime", "miner")}


def plan_material(files: dict, trust: dict, verifier: Path) -> dict:
    result = {"ssh_keygen": verifier, "expected_verifier_sha256": trust["ssh_keygen_sha256"]}
    for role, prefix in ((signatures.PRODUCER_ROLE, "producer"), (signatures.REPRODUCER_ROLE, "reproducer")):
        request, signature, policy = ROLE_FILES[role]
        result.update({prefix + "_approval": files[request], prefix + "_signature": files[signature],
                       prefix + "_allowed_signers": files[policy], prefix + "_signer_identity": trust[role]["signer_identity"]})
    return result


def validate_dashboard_build_evidence(*, repo: Path, commit: str, data: bytes,
                                      manifest: bytes) -> dict:
    """Bind the first-person build record to the exact frozen dashboard source and assets."""
    evidence = package.strict_json(data, "dashboard build evidence", signatures.MAX_JSON_BYTES)
    fields = {"schema", "source_commit", "source_tree_sha256", "package_lock",
              "toolchain", "commands", "dashboard_manifest", "dist_mode",
              "independent_reproduction_claim", "release_approved"}
    if package.canonical(evidence) != data or set(evidence) != fields:
        raise Error("dashboard build evidence is not canonical or has unexpected fields")
    if evidence["schema"] != dashboard.EVIDENCE_SCHEMA or evidence["source_commit"] != commit:
        raise Error("dashboard build evidence does not bind the frozen source commit")
    sources = dashboard.frozen_sources(repo, commit)
    source_tree = hashlib.sha256(package.canonical(
        {name: dashboard.identity(blob) for name, blob in sources.items()})).hexdigest()
    if evidence["source_tree_sha256"] != source_tree:
        raise Error("dashboard build evidence does not bind the frozen source tree")
    if evidence["package_lock"] != dashboard.identity(sources["package-lock.json"]):
        raise Error("dashboard build evidence does not bind the frozen package-lock.json")
    if evidence["dashboard_manifest"] != dashboard.identity(manifest):
        raise Error("dashboard build evidence does not bind DASHBOARD-ASSETS.json")
    toolchain = evidence["toolchain"]
    if not isinstance(toolchain, dict) or set(toolchain) != {"node", "npm"}:
        raise Error("dashboard build evidence has an invalid toolchain")
    for name, record in toolchain.items():
        if not isinstance(record, dict) or set(record) != {"executable", "version"}:
            raise Error(f"dashboard build evidence has an invalid {name} toolchain record")
        executable, version = record["executable"], record["version"]
        if (not isinstance(executable, str) or not 0 < len(executable) <= 4096
                or any(ord(char) < 32 for char in executable)
                or not isinstance(version, str)
                or not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version)):
            raise Error(f"dashboard build evidence has invalid {name} toolchain metadata")
    commands = evidence["commands"]
    expected = (["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
                ["npm", "run", "build"])
    if not isinstance(commands, list) or len(commands) != len(expected):
        raise Error("dashboard build evidence has an invalid command sequence")
    for record, argv in zip(commands, expected):
        if (not isinstance(record, dict)
                or set(record) != {"argv", "combined_output_bytes", "combined_output_sha256"}
                or record["argv"] != argv
                or type(record["combined_output_bytes"]) is not int
                or not 0 <= record["combined_output_bytes"] <= dashboard.MAX_TOOL_OUTPUT):
            raise Error("dashboard build evidence has an invalid command record")
        package.nonzero_hex(record["combined_output_sha256"], 64, "dashboard command output SHA-256")
    if evidence["dist_mode"] not in ("created_from_isolated_build", "compared_existing"):
        raise Error("dashboard build evidence has an invalid dist mode")
    if evidence["independent_reproduction_claim"] is not False or evidence["release_approved"] is not False:
        raise Error("dashboard build evidence cannot claim independent reproduction or release approval")
    return evidence


def validate_base(*, repo: Path, commit: str, version: str, files: dict,
                  verifier: Path, expected_verifier_sha256: str, final: bool) -> dict:
    integrity._assert_clean_exact_repo(repo, commit)
    names = archive_names(version)
    required = BASE_EVIDENCE | set(names.values())
    if final:
        required |= {REPRODUCTION, REPRODUCTION_SIGNATURE}
    allowed = required | GENERATED
    if not required <= set(files) or set(files) - allowed:
        raise Error("mainnet release inventory is incomplete or contains unexpected files")
    snapshots = {name: signatures._snapshot(files[name], name, signatures.MAX_JSON_BYTES) for name in BASE_EVIDENCE}
    manifest = approval.validate_manifest(snapshots[MANIFEST].data, snapshots[PLAN].data)
    review_commit = manifest["subject"]["review_source_commit"]
    trust_path = repo / TRUST_SOURCE
    subject, trust, review_snapshots = approval.load_inputs(
        repo, review_commit, files[PLAN], files[QUALIFICATION], trust_path, release_commit=commit,
    )
    if snapshots[TRUST].data != review_snapshots["trust"].data:
        raise Error("staged mainnet trust policy differs from the committed review policy")
    if expected_verifier_sha256 != trust["ssh_keygen_sha256"]:
        raise Error("mainnet release verifier differs from the precommitted policy")
    verified = approval.verify_pair(subject=subject, expected_trust=trust, **plan_material(files, trust, verifier))
    if signatures.canonical_json(verified) != snapshots[MANIFEST].data:
        raise Error("mainnet plan approval manifest does not match fresh signature verification")
    qualification = signatures._json_object(snapshots[QUALIFICATION].data, "qualification subject")
    proof_fields = pins.parse_reviewed_proof_pin(snapshots[PROOF_PIN].data)
    pins.validate_proof_binding(proof_fields, snapshots[PROOF_PIN].data, qualification, trust)
    plan = package.validate_plan(snapshots[PLAN].data)
    candidates = pins.render_mainnet_pins(plan, snapshots[MANIFEST].data, snapshots[PROOF_PIN].data)
    for relative, name in (("crates/cmfd-node/mainnet_release_pin.inc.rs", "mainnet_release_pin.inc.rs"),
                           ("crates/cmfd-consensus/mainnet_network_id.inc.rs", "mainnet_network_id.inc.rs")):
        if integrity._tracked_blob_at(repo, commit, relative) != candidates[name]:
            raise Error("committed mainnet pins are not the exact reviewed candidates")
    package.validate_dashboard_manifest(snapshots[DASHBOARD_ASSETS].data, commit)
    validate_dashboard_build_evidence(repo=repo, commit=commit,
                                      data=snapshots[DASHBOARD_BUILD_EVIDENCE].data,
                                      manifest=snapshots[DASHBOARD_ASSETS].data)
    cuda_pin_bytes = snapshots[CUDA_RUNTIME_PIN].data
    try:
        cuda_pin = cuda_pin_bytes.decode("ascii").removesuffix("\n")
    except UnicodeError as error:
        raise Error("CUDA runtime pin must be ASCII hexadecimal") from error
    package.nonzero_hex(cuda_pin, 64, "reviewed CUDA runtime SHA-256")
    if cuda_pin_bytes != (cuda_pin + "\n").encode():
        raise Error("CUDA runtime pin is not canonical")
    inspected = preflight.verify_set(repo, commit, version, files[PLAN],
                                     {key: files[name] for key, name in names.items()},
                                     files[DASHBOARD_ASSETS], cuda_pin)
    if inspected["mainnet_approval_manifest_sha256"] != approval.digest(snapshots[MANIFEST].data):
        raise Error("package and staged mainnet approval manifests disagree")
    for name, snapshot in {**snapshots, **review_snapshots}.items():
        signatures._assert_snapshot_current(snapshot, name)
    # The source-free evidence files are part of the independent statement too.
    evidence = {name: {"bytes": len(row.data), "sha256": approval.digest(row.data)} for name, row in sorted(snapshots.items())}
    statement = {"schema": REPRODUCTION_SCHEMA, "statement": REPRODUCTION_STATEMENT,
                 "role": signatures.REPRODUCER_ROLE,
                 "namespace": signatures.NAMESPACES[signatures.REPRODUCER_ROLE],
                 "signer_identity": trust[signatures.REPRODUCER_ROLE]["signer_identity"],
                 "source_commit": commit, "review_source_commit": review_commit, "package_version": version,
                 "launch_plan_digest": plan["launch_plan_digest"], "network_id": plan["network_id"],
                 "mainnet_approval_manifest_sha256": approval.digest(snapshots[MANIFEST].data),
                 "packages": inspected["packages"], "review_evidence": evidence}
    return {"statement": statement, "trust": trust, "preflight": inspected}


def verify_reproduction_signature(*, payload: bytes, files: dict, trust: dict, verifier: Path) -> None:
    role = signatures.REPRODUCER_ROLE
    snapshots = {
        "request": signatures._snapshot(files[REPRODUCTION], "mainnet reproduction statement", signatures.MAX_JSON_BYTES),
        "signature": signatures._snapshot(files[REPRODUCTION_SIGNATURE], "mainnet reproduction signature", signatures.MAX_SIGNATURE_BYTES),
        "policy": signatures._snapshot(files[ROLE_FILES[role][2]], "reproducer public policy", signatures.MAX_ALLOWED_SIGNERS_BYTES),
        "verifier": signatures._snapshot(verifier, "trusted SSH verifier", signatures.MAX_VERIFIER_BYTES),
    }
    if snapshots["request"].data != payload:
        raise Error("mainnet reproduction statement does not bind the exact staged release")
    if approval.digest(snapshots["verifier"].data) != trust["ssh_keygen_sha256"]:
        raise Error("mainnet reproduction verifier differs from its trusted digest")
    authority = signatures.parse_allowed_signers_authority(snapshots["policy"].data,
                 signer_identity=trust[role]["signer_identity"], role=role)
    if {"signer_identity": trust[role]["signer_identity"], **authority} != trust[role]:
        raise Error("reproduction signer differs from the committed authority")
    with tempfile.TemporaryDirectory(prefix="cmfd-mainnet-reproduction-") as temporary:
        root = Path(temporary)
        executable = root / ("ssh-keygen" + verifier.suffix)
        policy = root / "reproducer.allowed_signers"
        signature = root / "reproduction.sig"
        signatures._write_exclusive(executable, snapshots["verifier"].data, executable=True)
        signatures._write_exclusive(policy, snapshots["policy"].data)
        signatures._write_exclusive(signature, snapshots["signature"].data)
        signatures._verify_signature(verifier=executable, allowed_signers=policy,
                                     signer_identity=trust[role]["signer_identity"], namespace=signatures.NAMESPACES[role],
                                     signature=signature, payload=payload,
                                     environment=signatures._verification_environment(root, verifier))
    for name, snapshot in snapshots.items():
        signatures._assert_snapshot_current(snapshot, name)


def validate_release(*, repo: Path, commit: str, version: str, files: dict,
                     verifier: Path, expected_verifier_sha256: str) -> dict:
    result = validate_base(repo=repo, commit=commit, version=version, files=files,
                           verifier=verifier, expected_verifier_sha256=expected_verifier_sha256, final=True)
    payload = signatures.canonical_json(result["statement"])
    verify_reproduction_signature(payload=payload, files=files, trust=result["trust"], verifier=verifier)
    assert_statement_files(result["statement"], files)
    integrity._assert_clean_exact_repo(repo, commit)
    return result


def assert_statement_files(statement: dict, files: dict) -> None:
    expected = {row["name"]: {"bytes": row["bytes"], "sha256": row["sha256"]} for row in statement["packages"]}
    expected.update(statement["review_evidence"])
    for name, identity in expected.items():
        if package.file_identity(files[name]) != identity:
            raise Error("mainnet release changed during signature verification or comparison")


def prepare_reproduction(*, repo: Path, commit: str, version: str,
                         producer_stage: Path, reproducer_stage: Path,
                         verifier: Path, expected_verifier_sha256: str, output: Path) -> dict:
    first_root = integrity._regular_directory(producer_stage, "producer stage")
    second_root = integrity._regular_directory(reproducer_stage, "reproducer stage")
    if first_root.samefile(second_root):
        raise Error("reproduction stages must be different directories")
    first_files, second_files = integrity._stage_files(first_root), integrity._stage_files(second_root)
    first = validate_base(repo=repo, commit=commit, version=version, files=first_files,
                          verifier=verifier, expected_verifier_sha256=expected_verifier_sha256, final=False)
    second = validate_base(repo=repo, commit=commit, version=version, files=second_files,
                           verifier=verifier, expected_verifier_sha256=expected_verifier_sha256, final=False)
    if first["statement"] != second["statement"]:
        raise Error("producer and reproducer package/evidence identities differ")
    for name in archive_names(version).values():
        if first_files[name].samefile(second_files[name]):
            raise Error("the same archive file cannot serve as two reproduced builds")
        if package.file_identity(first_files[name]) != package.file_identity(second_files[name]):
            raise Error("reproduced archive bytes differ")
    assert_statement_files(first["statement"], first_files)
    assert_statement_files(second["statement"], second_files)
    integrity._assert_clean_exact_repo(repo, commit)
    encoded = signatures.canonical_json(first["statement"])
    integrity._write_new(output, encoded)
    return {"statement_sha256": approval.digest(encoded), "byte_identical": True,
            "independent_attestation_required": True, "release_approved": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    for name in ("producer-stage", "reproducer-stage", "ssh-keygen", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--ssh-keygen-sha256", required=True)
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path) and not value.is_absolute():
            parser.error(f"--{name} must be an absolute path")
    try:
        result = prepare_reproduction(repo=args.repo, commit=args.commit, version=args.version,
                                      producer_stage=args.producer_stage, reproducer_stage=args.reproducer_stage,
                                      verifier=args.ssh_keygen, expected_verifier_sha256=args.ssh_keygen_sha256, output=args.output)
        print(signatures.canonical_json(result).decode(), end="")
    except (OSError, ValueError, KeyError, TypeError, Error, signatures.ApprovalError) as error:
        parser.exit(1, f"Mainnet reproduction preparation failed: {error}\n")


if __name__ == "__main__":
    main()
