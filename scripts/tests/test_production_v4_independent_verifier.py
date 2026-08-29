from __future__ import annotations

import copy
import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import production_v4_independent_verifier as verifier  # noqa: E402
from production_v4_wire import write_structural_fixture  # noqa: E402


class CoreBindingVectorTests(unittest.TestCase):
    def test_published_core_vector(self) -> None:
        vector_path = (
            Path(__file__).resolve().parents[2]
            / "docs"
            / "consensus"
            / "production-v4-core-vector-v1.json"
        )
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        block_json = vector["block"]
        block = {
            "network_id": bytes.fromhex(block_json["network_id"]),
            "previous_block": bytes.fromhex(block_json["previous_block"]),
            "transaction_root": bytes.fromhex(block_json["transaction_root"]),
            "height": block_json["height"],
            "timestamp": block_json["timestamp"],
            "target": bytes.fromhex(block_json["target"]),
        }
        candidate = {
            "algorithm_version": vector["algorithm_version"],
            "proof_version": vector["proof_version"],
            "nonce": vector["nonce"],
            "proof_system_digest": bytes.fromhex(vector["proof_system_digest"]),
            "model_manifest_digest": bytes.fromhex(vector["model_manifest_digest"]),
        }
        expected = vector["expected"]

        challenge = verifier.challenge_digest(block, candidate)
        activation = verifier.final_activation_digest_from_bytes(
            challenge, bytes(verifier.FINAL_ACTIVATION_BYTES)
        )
        work = verifier.work_digest(candidate, challenge, activation)
        statement = verifier.transcript_statement_digest(
            block, candidate, challenge, activation, work
        )

        self.assertEqual(challenge.hex(), expected["challenge_digest"])
        self.assertEqual(activation.hex(), expected["final_activation_digest"])
        self.assertEqual(work.hex(), expected["work_digest"])
        self.assertEqual(statement.hex(), expected["transcript_statement_digest"])


class IndependentStatementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="cmfd-v4-independent-")
        self.root = Path(self.directory.name)
        self.proof = self.root / "proof.bin"
        write_structural_fixture(self.proof)
        self.block = {
            "network_id": bytes.fromhex("b9e55d5a5e80c8e3d73bf81b199bc643ac9367436962c28b6aacdc37f3809962"),
            "previous_block": bytes(32),
            "transaction_root": bytes([1]) * 32,
            "height": 1,
            "timestamp": 2,
            "target": bytes([255]) * 32,
        }
        self.candidate = {
            "algorithm_version": verifier.ALGORITHM_VERSION,
            "proof_version": verifier.PROOF_VERSION,
            "nonce": 3,
            "proof_system_digest": verifier.PROOF_SYSTEM_DIGEST,
            "model_manifest_digest": verifier.MODEL_MANIFEST_DIGEST,
        }
        _, self.statement = verifier.verify(
            self.proof, self.block, self.candidate, require_candidate_claims=False
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _parse(self, statement: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
        path = self.root / "statement.json"
        path.write_text(json.dumps(statement), encoding="utf-8")
        return verifier.parse_statement(path)

    def test_strict_statement_accepts_all_recomputed_claims(self) -> None:
        block, candidate = self._parse(self.statement)
        result, _ = verifier.verify(
            self.proof, block, candidate, require_candidate_claims=True
        )
        self.assertTrue(result["implemented_stages_accepted"])
        self.assertTrue(result["candidate_claims_verified"])
        self.assertFalse(result["full_cryptographic_proof_verified"])

    def test_mutated_final_activation_is_rejected(self) -> None:
        mutated_proof = self.root / "mutated-proof.bin"
        shutil.copyfile(self.proof, mutated_proof)
        with mutated_proof.open("r+b") as target:
            target.seek(verifier.OUTER_HEADER_BYTES)
            target.write(struct.pack("<I", 1))
        block, candidate = self._parse(self.statement)
        with self.assertRaisesRegex(verifier.VerificationError, "final-activation digest"):
            verifier.verify(mutated_proof, block, candidate, require_candidate_claims=True)

    def test_mutated_candidate_claims_are_rejected(self) -> None:
        for field in ("challenge_digest", "final_activation_digest", "work_digest"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.statement)
                original = mutated["candidate"][field]
                mutated["candidate"][field] = ("00" if original[:2] != "00" else "01") + original[2:]
                block, candidate = self._parse(mutated)
                with self.assertRaisesRegex(verifier.VerificationError, field.replace("_", "[- ]")):
                    verifier.verify(self.proof, block, candidate, require_candidate_claims=True)

    def test_wrong_pinned_identity_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.statement)
        mutated["candidate"]["proof_system_digest"] = "00" * 32
        block, candidate = self._parse(mutated)
        with self.assertRaisesRegex(verifier.VerificationError, "proof-system digest"):
            verifier.verify(self.proof, block, candidate, require_candidate_claims=True)

    def test_work_above_target_is_rejected(self) -> None:
        block = dict(self.block)
        block["target"] = bytes(32)
        with self.assertRaisesRegex(verifier.VerificationError, "work target"):
            verifier.verify(self.proof, block, self.candidate, require_candidate_claims=False)

    def test_statement_rejects_extra_keys(self) -> None:
        mutated = copy.deepcopy(self.statement)
        mutated["candidate"]["ignored"] = True
        with self.assertRaisesRegex(verifier.VerificationError, "key mismatch"):
            self._parse(mutated)


if __name__ == "__main__":
    unittest.main()
