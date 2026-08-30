from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "release-key-transition.py"
SPEC = importlib.util.spec_from_file_location("release_key_transition", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TRANSITION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSITION)


class ReleaseKeyTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cmfd-key-transition-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def public_key(self, name: str, value: int) -> Path:
        algorithm = b"ssh-ed25519"
        key = bytes([value]) * 32
        blob = (
            len(algorithm).to_bytes(4, "big")
            + algorithm
            + len(key).to_bytes(4, "big")
            + key
        )
        encoded = TRANSITION.base64.b64encode(blob).decode("ascii")
        path = self.root / name
        path.write_text(f"ssh-ed25519 {encoded} test\n", encoding="ascii")
        return path

    def transition(self, old_key: Path, new_key: Path) -> dict[str, object]:
        return TRANSITION.build_transition(
            signer_identity="release@example.invalid",
            old_public_key=old_key,
            new_public_key=new_key,
            reason="Scheduled offline release-key rotation",
            approved_at_utc="2026-09-01T12:00:00Z",
            first_release="v1.0.0-rc.2",
            overlap_ends_utc="2026-10-01T12:00:00Z",
            approvers=["Operator B", "Operator A"],
        )

    def test_record_is_canonical_and_binds_distinct_keys(self) -> None:
        old_key = self.public_key("old.pub", 1)
        new_key = self.public_key("new.pub", 2)
        record = self.transition(old_key, new_key)
        self.assertEqual(record["approvers"], ["Operator A", "Operator B"])
        self.assertNotEqual(
            record["old_key"]["fingerprint"], record["new_key"]["fingerprint"]
        )
        path = self.root / "transition.json"
        TRANSITION.write_new(path, record)
        loaded, encoded = TRANSITION.load_canonical_transition(path)
        self.assertEqual(loaded, record)
        self.assertEqual(encoded, TRANSITION.canonical_json(record))

    def test_duplicate_approvers_and_same_key_are_rejected(self) -> None:
        old_key = self.public_key("old.pub", 1)
        with self.assertRaisesRegex(TRANSITION.TransitionError, "approvers"):
            TRANSITION.build_transition(
                signer_identity="release@example.invalid",
                old_public_key=old_key,
                new_public_key=self.public_key("new.pub", 2),
                reason="Scheduled offline release-key rotation",
                approved_at_utc="2026-09-01T12:00:00Z",
                first_release="v1.0.0-rc.2",
                overlap_ends_utc="2026-10-01T12:00:00Z",
                approvers=["Operator A", "Operator A"],
            )
        with self.assertRaisesRegex(TRANSITION.TransitionError, "must differ"):
            self.transition(old_key, old_key)

    def test_noncanonical_or_wrong_algorithm_public_key_is_rejected(self) -> None:
        wrong = self.root / "wrong.pub"
        wrong.write_text("ssh-rsa AAAA\n", encoding="ascii")
        with self.assertRaisesRegex(TRANSITION.TransitionError, "Ed25519"):
            TRANSITION.read_public_key(wrong, "test key")

        valid = self.public_key("valid.pub", 3)
        valid.write_text(
            valid.read_text(encoding="ascii") + "extra\n", encoding="ascii"
        )
        with self.assertRaisesRegex(TRANSITION.TransitionError, "exactly one"):
            TRANSITION.read_public_key(valid, "test key")

    def test_timestamps_and_approvers_are_canonical(self) -> None:
        old_key = self.public_key("old.pub", 1)
        new_key = self.public_key("new.pub", 2)
        with self.assertRaisesRegex(TRANSITION.TransitionError, "whole seconds"):
            TRANSITION.build_transition(
                signer_identity="release@example.invalid",
                old_public_key=old_key,
                new_public_key=new_key,
                reason="Scheduled offline release-key rotation",
                approved_at_utc="2026-09-01T12:00:00.000Z",
                first_release="v1.0.0-rc.2",
                overlap_ends_utc="2026-10-01T12:00:00Z",
                approvers=["Operator A", "Operator B"],
            )
        with self.assertRaisesRegex(TRANSITION.TransitionError, "approvers"):
            TRANSITION.build_transition(
                signer_identity="release@example.invalid",
                old_public_key=old_key,
                new_public_key=new_key,
                reason="Scheduled offline release-key rotation",
                approved_at_utc="2026-09-01T12:00:00Z",
                first_release="v1.0.0-rc.2",
                overlap_ends_utc="2026-10-01T12:00:00Z",
                approvers=["Operator A ", "Operator B"],
            )

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is required")
    def test_real_old_and_new_signatures_verify_and_mutation_fails(self) -> None:
        ssh_keygen = str(shutil.which("ssh-keygen"))
        old_private = self.root / "old"
        new_private = self.root / "new"
        for key in (old_private, new_private):
            subprocess.run(
                [ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True,
                capture_output=True,
            )
        record = self.transition(
            old_private.with_suffix(".pub"), new_private.with_suffix(".pub")
        )
        transition_path = self.root / "transition.json"
        TRANSITION.write_new(transition_path, record)

        signatures = []
        for label, key in (("old", old_private), ("new", new_private)):
            subprocess.run(
                [
                    ssh_keygen,
                    "-Y",
                    "sign",
                    "-f",
                    str(key),
                    "-n",
                    TRANSITION.SIGNATURE_NAMESPACE,
                    str(transition_path),
                ],
                check=True,
                capture_output=True,
            )
            destination = self.root / f"{label}.sig"
            transition_path.with_suffix(".json.sig").replace(destination)
            signatures.append(destination)

        report = TRANSITION.verify_transition(
            transition_path=transition_path,
            old_public_key_path=old_private.with_suffix(".pub"),
            new_public_key_path=new_private.with_suffix(".pub"),
            old_signature_path=signatures[0],
            new_signature_path=signatures[1],
            ssh_keygen=ssh_keygen,
        )
        self.assertTrue(report["dual_signature_gate_met"])

        mutated = dict(record)
        mutated["reason"] = "Unauthorized mutation after both signatures"
        mutated_path = self.root / "mutated.json"
        TRANSITION.write_new(mutated_path, mutated)
        with self.assertRaisesRegex(TRANSITION.TransitionError, "verification failed"):
            TRANSITION.verify_transition(
                transition_path=mutated_path,
                old_public_key_path=old_private.with_suffix(".pub"),
                new_public_key_path=new_private.with_suffix(".pub"),
                old_signature_path=signatures[0],
                new_signature_path=signatures[1],
                ssh_keygen=ssh_keygen,
            )


if __name__ == "__main__":
    unittest.main()
