from __future__ import annotations

import base64
import copy
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import production_v4_activation_approval as approval


def public_key(seed: int) -> tuple[str, str]:
    key_type = "ssh-ed25519"
    encoded_type = key_type.encode("ascii")
    key = bytes([seed]) * 32
    blob = (
        struct.pack(">I", len(encoded_type))
        + encoded_type
        + struct.pack(">I", len(key))
        + key
    )
    return key_type, base64.b64encode(blob).decode("ascii")


class ProductionV4ActivationApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cmfd-v4-approval-test-")
        self.root = Path(self.temporary.name)
        self.producer_identity = "producer@example.invalid"
        self.reproducer_identity = "reproducer@example.invalid"
        self.producer_policy = self.write_policy(
            "producer.allowed_signers",
            role=approval.PRODUCER_ROLE,
            identity=self.producer_identity,
            seed=1,
        )
        self.reproducer_policy = self.write_policy(
            "reproducer.allowed_signers",
            role=approval.REPRODUCER_ROLE,
            identity=self.reproducer_identity,
            seed=2,
        )
        self.verifier = self.root / "ssh-keygen"
        self.verifier.write_bytes(b"trusted verifier")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_policy(self, name: str, *, role: str, identity: str, seed: int) -> Path:
        key_type, encoded = public_key(seed)
        path = self.root / name
        path.write_text(
            f'{identity} namespaces="{approval.NAMESPACES[role]}" '
            f"{key_type} {encoded}\n",
            encoding="ascii",
            newline="\n",
        )
        return path

    def subject(self, phase: str = "pin") -> dict[str, object]:
        roles = set(approval.COMMON_FILE_ROLES)
        if phase == "evidence":
            roles.update(approval.EVIDENCE_ONLY_FILE_ROLES)
        files = {}
        for role in roles:
            digest = hashlib.sha256(role.encode("ascii")).hexdigest()
            files[role] = {
                "name": f"{role}.bin",
                "bytes": len(role) + 1,
                "sha256": digest,
                "blake3": digest,
            }
        return approval.build_subject(
            phase=phase,
            activation_source_commit="1" * 40,
            artifact_generation_source_commit="2" * 40,
            qualification_source_commit="3" * 40,
            network={
                "profile": "CommonFoundry RCNet-1",
                "launch_root": "4" * 64,
                "network_id": "5" * 64,
                "virtual_genesis_hash": "6" * 64,
                "virtual_genesis_timestamp_unix_seconds": 1_788_800_400,
                "pow_limit": "7" * 64,
            },
            source_pin_sha256="8" * 64,
            files=files,
        )

    def prepare_files(
        self, subject: dict[str, object] | None = None
    ) -> tuple[dict[str, object], dict[str, Path]]:
        subject = subject or self.subject()
        prepared = approval.prepare_approval_payloads(
            subject=subject,
            producer_allowed_signers=self.producer_policy,
            producer_signer_identity=self.producer_identity,
            reproducer_allowed_signers=self.reproducer_policy,
            reproducer_signer_identity=self.reproducer_identity,
        )
        payloads = prepared["payloads"]
        self.assertIsInstance(payloads, dict)
        paths = {
            "producer_approval": self.root / "producer.approval.json",
            "producer_signature": self.root / "producer.approval.sig",
            "reproducer_approval": self.root / "reproducer.approval.json",
            "reproducer_signature": self.root / "reproducer.approval.sig",
        }
        paths["producer_approval"].write_bytes(payloads[approval.PRODUCER_ROLE])
        paths["reproducer_approval"].write_bytes(payloads[approval.REPRODUCER_ROLE])
        paths["producer_signature"].write_bytes(b"producer signature")
        paths["reproducer_signature"].write_bytes(b"reproducer signature")
        return prepared, paths

    def verify(self, subject: dict[str, object], paths: dict[str, Path], **kwargs):
        verifier_sha256 = hashlib.sha256(self.verifier.read_bytes()).hexdigest()
        return approval.verify_approval_pair(
            subject=subject,
            producer_allowed_signers=self.producer_policy,
            producer_signer_identity=self.producer_identity,
            reproducer_allowed_signers=self.reproducer_policy,
            reproducer_signer_identity=self.reproducer_identity,
            ssh_keygen=self.verifier,
            expected_verifier_sha256=verifier_sha256,
            **paths,
            **kwargs,
        )

    @mock.patch.object(approval.subprocess, "run")
    def test_pair_is_bound_to_exact_payloads_roles_and_namespaces(self, run) -> None:
        subject = self.subject()
        _, paths = self.prepare_files(subject)
        run.return_value = subprocess.CompletedProcess([], 0, b"Good signature\n", b"")

        receipt = self.verify(subject, paths)

        self.assertEqual(run.call_count, 2)
        producer_call, reproducer_call = run.call_args_list
        self.assertEqual(
            producer_call.kwargs["input"], paths["producer_approval"].read_bytes()
        )
        self.assertEqual(
            reproducer_call.kwargs["input"], paths["reproducer_approval"].read_bytes()
        )
        self.assertIn(approval.NAMESPACES[approval.PRODUCER_ROLE], producer_call.args[0])
        self.assertIn(
            approval.NAMESPACES[approval.REPRODUCER_ROLE], reproducer_call.args[0]
        )
        self.assertNotEqual(
            receipt["approvals"][approval.PRODUCER_ROLE]["key_blob_sha256"],
            receipt["approvals"][approval.REPRODUCER_ROLE]["key_blob_sha256"],
        )

    @mock.patch.object(approval.subprocess, "run")
    def test_verifier_uses_a_minimal_private_environment(self, run) -> None:
        subject = self.subject()
        _, paths = self.prepare_files(subject)
        run.return_value = subprocess.CompletedProcess([], 0, b"Good signature\n", b"")
        injected = {
            "LD_PRELOAD": "/attacker/preload.so",
            "LD_LIBRARY_PATH": "/attacker/lib",
            "DYLD_INSERT_LIBRARIES": "/attacker/dylib",
            "OPENSSL_CONF": "/attacker/openssl.cnf",
            "SSH_SK_PROVIDER": "/attacker/provider.so",
            "PYTHONPATH": "/attacker/python",
        }
        with mock.patch.dict(os.environ, injected, clear=False):
            self.verify(subject, paths)
        for invocation in run.call_args_list:
            environment = invocation.kwargs["env"]
            for name in injected:
                self.assertNotIn(name, environment)
            self.assertEqual(environment["HOME"], environment["TMP"])
            self.assertEqual(Path(environment["HOME"]), Path(invocation.kwargs["cwd"]))
            if os.name != "nt":
                self.assertNotIn("PATH", environment)

    def test_self_approval_and_same_key_are_rejected(self) -> None:
        subject = self.subject()
        with self.assertRaisesRegex(approval.ApprovalError, "identities must differ"):
            approval.prepare_approval_payloads(
                subject=subject,
                producer_allowed_signers=self.producer_policy,
                producer_signer_identity=self.producer_identity,
                reproducer_allowed_signers=self.reproducer_policy,
                reproducer_signer_identity=self.producer_identity,
            )
        duplicate_key = self.write_policy(
            "duplicate-key.allowed_signers",
            role=approval.REPRODUCER_ROLE,
            identity=self.reproducer_identity,
            seed=1,
        )
        with self.assertRaisesRegex(approval.ApprovalError, "keys must differ"):
            approval.prepare_approval_payloads(
                subject=subject,
                producer_allowed_signers=self.producer_policy,
                producer_signer_identity=self.producer_identity,
                reproducer_allowed_signers=duplicate_key,
                reproducer_signer_identity=self.reproducer_identity,
            )

    def test_qualification_binding_digest_covers_every_common_file(self) -> None:
        files = self.subject()["files"]
        original = approval.qualification_binding_sha256(files)
        changed = copy.deepcopy(files)
        changed["rcnet_proof_template"]["sha256"] = "a" * 64
        self.assertNotEqual(original, approval.qualification_binding_sha256(changed))

    @mock.patch.object(approval.subprocess, "run")
    def test_role_swap_and_phase_replay_are_rejected_before_openssh(self, run) -> None:
        pin_subject = self.subject("pin")
        _, paths = self.prepare_files(pin_subject)
        producer = paths["producer_approval"].read_bytes()
        paths["producer_approval"].write_bytes(paths["reproducer_approval"].read_bytes())
        paths["reproducer_approval"].write_bytes(producer)
        with self.assertRaisesRegex(approval.ApprovalError, "exact canonical"):
            self.verify(pin_subject, paths)
        self.assert_not_called(run)

        prepared, paths = self.prepare_files(pin_subject)
        with self.assertRaisesRegex(approval.ApprovalError, "exact canonical"):
            self.verify(
                self.subject("evidence"),
                paths,
                expected_trust=prepared["authorities"],
            )
        self.assert_not_called(run)

    @staticmethod
    def assert_not_called(run: mock.Mock) -> None:
        if run.call_count:
            raise AssertionError("OpenSSH must not run for a malformed approval payload")

    @mock.patch.object(approval.subprocess, "run")
    def test_unsigned_or_mutated_json_is_rejected(self, run) -> None:
        subject = self.subject()
        _, paths = self.prepare_files(subject)
        paths["producer_signature"].unlink()
        with self.assertRaisesRegex(approval.ApprovalError, "signature.*missing"):
            self.verify(subject, paths)
        self.assert_not_called(run)

        _, paths = self.prepare_files(subject)
        paths["producer_approval"].write_bytes(
            paths["producer_approval"].read_bytes().replace(b'"phase":"pin"', b'"phase":"PIN"')
        )
        with self.assertRaisesRegex(approval.ApprovalError, "exact canonical"):
            self.verify(subject, paths)
        self.assert_not_called(run)

    @mock.patch.object(approval.subprocess, "run")
    def test_alternate_authority_is_rejected_by_compiled_trust(self, run) -> None:
        subject = self.subject()
        prepared, paths = self.prepare_files(subject)
        authorities = prepared["authorities"]
        expected = {
            approval.PRODUCER_ROLE: {
                "signer_identity": self.producer_identity,
                **authorities[approval.PRODUCER_ROLE],
            },
            approval.REPRODUCER_ROLE: {
                "signer_identity": self.reproducer_identity,
                **authorities[approval.REPRODUCER_ROLE],
            },
        }
        wrong = copy.deepcopy(expected)
        wrong[approval.PRODUCER_ROLE]["allowed_signers_sha256"] = "a" * 64
        with self.assertRaisesRegex(approval.ApprovalError, "compiled trust pin"):
            self.verify(subject, paths, expected_trust=wrong)
        self.assert_not_called(run)

    @mock.patch.object(approval.subprocess, "run")
    def test_evidence_requires_precommitted_trust_and_verifier_digest(self, run) -> None:
        subject = self.subject("evidence")
        prepared, paths = self.prepare_files(subject)
        with self.assertRaisesRegex(approval.ApprovalError, "precommitted compiled trust"):
            self.verify(subject, paths)
        self.assert_not_called(run)

        verifier_sha256 = hashlib.sha256(self.verifier.read_bytes()).hexdigest()
        self.verifier.write_bytes(b"fake verifier that always returns zero")
        with self.assertRaisesRegex(approval.ApprovalError, "verifier.*trust pin"):
            approval.verify_approval_pair(
                subject=subject,
                producer_allowed_signers=self.producer_policy,
                producer_signer_identity=self.producer_identity,
                reproducer_allowed_signers=self.reproducer_policy,
                reproducer_signer_identity=self.reproducer_identity,
                ssh_keygen=self.verifier,
                expected_verifier_sha256=verifier_sha256,
                expected_trust=prepared["authorities"],
                **paths,
            )
        self.assert_not_called(run)

    @mock.patch.object(approval.subprocess, "run")
    def test_signature_mutation_during_verification_is_rejected(self, run) -> None:
        subject = self.subject()
        _, paths = self.prepare_files(subject)
        original = paths["producer_signature"].read_bytes()
        original_stat = paths["producer_signature"].stat()

        def mutate_once(*_args, **_kwargs):
            if run.call_count == 1:
                paths["producer_signature"].write_bytes(b"x" * len(original))
                os.utime(
                    paths["producer_signature"],
                    ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                )
            return subprocess.CompletedProcess([], 0, b"Good signature\n", b"")

        run.side_effect = mutate_once
        with self.assertRaisesRegex(approval.ApprovalError, "changed during"):
            self.verify(subject, paths)

    def test_symlinked_authority_is_rejected(self) -> None:
        link = self.root / "producer-link.allowed_signers"
        try:
            link.symlink_to(self.producer_policy)
        except OSError:
            self.skipTest("symlinks are unavailable")
        with self.assertRaisesRegex(approval.ApprovalError, "non-symlink"):
            approval.prepare_approval_payloads(
                subject=self.subject(),
                producer_allowed_signers=link,
                producer_signer_identity=self.producer_identity,
                reproducer_allowed_signers=self.reproducer_policy,
                reproducer_signer_identity=self.reproducer_identity,
            )

    def test_real_openssh_two_role_round_trip_and_tamper_rejection(self) -> None:
        executable = shutil.which("ssh-keygen")
        if executable is None:
            self.skipTest("OpenSSH ssh-keygen is unavailable")
        identities = (
            (approval.PRODUCER_ROLE, self.producer_identity, "real-producer-key"),
            (approval.REPRODUCER_ROLE, self.reproducer_identity, "real-reproducer-key"),
        )
        policies: dict[str, Path] = {}
        keys: dict[str, Path] = {}
        for role, identity, name in identities:
            key = self.root / name
            subprocess.run(
                [
                    executable,
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    identity,
                    "-f",
                    str(key),
                ],
                check=True,
                capture_output=True,
            )
            public = key.with_suffix(".pub").read_text(encoding="ascii").split()
            policy = self.root / f"real-{role}.allowed_signers"
            policy.write_text(
                f'{identity} namespaces="{approval.NAMESPACES[role]}" '
                f"{public[0]} {public[1]}\n",
                encoding="ascii",
                newline="\n",
            )
            keys[role] = key
            policies[role] = policy

        subject = self.subject()
        prepared = approval.prepare_approval_payloads(
            subject=subject,
            producer_allowed_signers=policies[approval.PRODUCER_ROLE],
            producer_signer_identity=self.producer_identity,
            reproducer_allowed_signers=policies[approval.REPRODUCER_ROLE],
            reproducer_signer_identity=self.reproducer_identity,
        )
        paths: dict[str, Path] = {}
        for role, prefix in (
            (approval.PRODUCER_ROLE, "producer"),
            (approval.REPRODUCER_ROLE, "reproducer"),
        ):
            payload_path = self.root / f"real-{prefix}.approval.json"
            payload_path.write_bytes(prepared["payloads"][role])
            subprocess.run(
                [
                    executable,
                    "-Y",
                    "sign",
                    "-f",
                    str(keys[role]),
                    "-n",
                    approval.NAMESPACES[role],
                    str(payload_path),
                ],
                check=True,
                capture_output=True,
            )
            paths[f"{prefix}_approval"] = payload_path
            paths[f"{prefix}_signature"] = Path(f"{payload_path}.sig")

        receipt = approval.verify_approval_pair(
            subject=subject,
            producer_allowed_signers=policies[approval.PRODUCER_ROLE],
            producer_signer_identity=self.producer_identity,
            reproducer_allowed_signers=policies[approval.REPRODUCER_ROLE],
            reproducer_signer_identity=self.reproducer_identity,
            ssh_keygen=Path(executable),
            expected_verifier_sha256=hashlib.sha256(
                Path(executable).read_bytes()
            ).hexdigest(),
            **paths,
        )
        self.assertEqual(receipt["phase"], "pin")
        paths["producer_approval"].write_bytes(
            paths["producer_approval"].read_bytes().replace(b'"phase":"pin"', b'"phase":"PIN"')
        )
        with self.assertRaisesRegex(approval.ApprovalError, "exact canonical"):
            approval.verify_approval_pair(
                subject=subject,
                producer_allowed_signers=policies[approval.PRODUCER_ROLE],
                producer_signer_identity=self.producer_identity,
                reproducer_allowed_signers=policies[approval.REPRODUCER_ROLE],
                reproducer_signer_identity=self.reproducer_identity,
                ssh_keygen=Path(executable),
                expected_verifier_sha256=hashlib.sha256(
                    Path(executable).read_bytes()
                ).hexdigest(),
                **paths,
            )


if __name__ == "__main__":
    unittest.main()
