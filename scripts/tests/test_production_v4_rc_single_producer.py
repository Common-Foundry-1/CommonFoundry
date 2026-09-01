from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import production_v4_rc_single_producer as single


class SingleProducerRcActivationTests(unittest.TestCase):
    def authority(self) -> dict[str, str]:
        digest = "ab" * 32
        return {
            "allowed_signers_sha256": "cd" * 32,
            "key_blob_sha256": digest,
            "key_fingerprint": "SHA256:"
            + base64.b64encode(bytes.fromhex(digest)).decode("ascii").rstrip("="),
            "key_type": "ssh-ed25519",
        }

    def test_pin_contract_is_explicitly_rc_only_and_has_no_reproducer(self) -> None:
        fields = single.build_pin_fields(
            source_commit="1" * 40,
            qualification_manifest_sha256="2" * 64,
            verifier_script_sha256="3" * 64,
            verifier_report_sha256="4" * 64,
            qualification_binding_sha256="5" * 64,
            ssh_keygen_sha256="6" * 64,
            signer_identity="producer@example.test",
            authority=self.authority(),
        )
        self.assertEqual(fields["schema"], single.ACTIVATION_SCHEMA)
        self.assertEqual(
            fields["approval_trust"]["contract_schema"], single.SUBJECT_SCHEMA
        )
        self.assertIsNone(fields["approval_trust"]["independent_reproducer"])

    def test_approval_discloses_all_absent_assurances(self) -> None:
        approval = single.build_approval(
            source_commit="1" * 40,
            network={"network_id": "2" * 64},
            signer_identity="producer@example.test",
            authority=self.authority(),
            qualification_manifest={"sha256": "3" * 64},
            verifier_report={"sha256": "4" * 64},
            strict_statement={"sha256": "5" * 64},
            pin_fields={"sha256": "6" * 64},
            proposed_pin={"sha256": "7" * 64},
        )
        self.assertEqual(approval["subject"]["declarations"], single.DECLARATIONS)
        self.assertFalse(single.DECLARATIONS["independent_reproduction"])
        self.assertFalse(single.DECLARATIONS["external_audit"])
        self.assertFalse(single.DECLARATIONS["mainnet_authorization"])

    def test_full_verification_and_candidate_claims_are_required(self) -> None:
        accepted = {
            "implemented_stages_accepted": True,
            "target_met": True,
            "candidate_claims_verified": True,
            "full_cryptographic_proof_verified": True,
            "remaining_stages": [],
        }
        self.assertIs(
            single.validate_verifier_result(
                accepted, require_candidate_claims=True
            ),
            accepted,
        )
        for field in (
            "target_met",
            "candidate_claims_verified",
            "full_cryptographic_proof_verified",
        ):
            rejected = dict(accepted)
            rejected[field] = False
            with self.subTest(field=field), self.assertRaises(single.SingleProducerError):
                single.validate_verifier_result(
                    rejected, require_candidate_claims=True
                )


if __name__ == "__main__":
    unittest.main()
