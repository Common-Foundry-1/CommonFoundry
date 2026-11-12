"""Reject misleading source identities and fork capabilities before packaging."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("compact_candidate", SCRIPTS / "package-compact-miner-candidate.py")
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)


class CandidateIdentityTests(unittest.TestCase):
    def setUp(self):
        self.commit = "12" * 20
        self.fork = json.loads(candidate.MANIFEST.read_bytes())
        self.network = {
            "format": "commonfoundry-miner-network-info",
            "format_version": 1,
            "network_id": self.fork["network_id"],
            "proof_selection": "ProductionV4",
            "build_source_commit": self.commit,
        }
        self.compatibility = {
            "format": "commonfoundry-pool-miner-compatibility",
            "format_version": 1,
            "network_id": self.fork["network_id"],
            "build_source_commit": self.commit,
            "accepted_consensus_fingerprints": [self.fork["predecessor_fingerprint"], self.fork["consensus_fingerprint"]],
            "pool_protocol_version": 2,
            "compact_mainnet_activation_height": self.fork["activation_height"],
            "compact_mainnet_proof_system_digest": self.fork["at_and_after_activation"]["proof_system_digest"],
            "compact_mainnet_block_proof_generation": False,
            "activates_mainnet_fork": False,
            "scope": "pool-nonce-search",
        }

    def test_accepts_only_the_pinned_pool_candidate(self):
        candidate.validate_reports(self.network, self.compatibility, self.commit, self.fork)

    def test_rejects_wrong_network_or_source_identity(self):
        for key, value in {"network_id": "77" * 32, "build_source_commit": "34" * 20,
                           "proof_selection": "ProductionV4Direct"}.items():
            with self.subTest(key=key):
                changed = copy.deepcopy(self.network)
                changed[key] = value
                with self.assertRaises(ValueError):
                    candidate.validate_reports(changed, self.compatibility, self.commit, self.fork)

    def test_rejects_extra_fingerprints_wrong_boundary_and_overstated_capabilities(self):
        mutations = {
            "accepted_consensus_fingerprints": self.compatibility["accepted_consensus_fingerprints"] + ["77" * 32],
            "network_id": "77" * 32,
            "build_source_commit": "34" * 20,
            "compact_mainnet_activation_height": 67_536,
            "compact_mainnet_proof_system_digest": "77" * 32,
            "compact_mainnet_block_proof_generation": True,
            "activates_mainnet_fork": True,
            "scope": "solo-mining",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                changed = copy.deepcopy(self.compatibility)
                changed[key] = value
                with self.assertRaises(ValueError):
                    candidate.validate_reports(self.network, changed, self.commit, self.fork)


if __name__ == "__main__":
    unittest.main()
