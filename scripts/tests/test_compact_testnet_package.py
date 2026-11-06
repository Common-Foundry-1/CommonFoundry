import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "packaging/compact-proof-testnet/launch.py"
spec = importlib.util.spec_from_file_location("compact_launcher", SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class CompactPackageTests(unittest.TestCase):
    def test_corrupted_payload_and_foreign_network_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            payload = root / "cmfd-node"
            payload.write_bytes(b"verified payload")
            manifest = {"network_id": launcher.NETWORK, "files": {
                "cmfd-node": {"bytes": payload.stat().st_size, "sha256": launcher.sha256(payload)}}}
            pin = root / "PACKAGE-MANIFEST.json"
            pin.write_text(json.dumps(manifest))
            launcher.verify(root)
            payload.write_bytes(b"modified payload")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                launcher.verify(root)
            manifest["network_id"] = "00" * 32
            pin.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "network identity"):
                launcher.verify(root)

    def test_unsafe_manifest_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "PACKAGE-MANIFEST.json").write_text(json.dumps({
                "network_id": launcher.NETWORK,
                "files": {"../outside": {"bytes": 1, "sha256": "00" * 32}}}))
            with self.assertRaisesRegex(ValueError, "unsafe package"):
                launcher.verify(root)

    def test_public_pool_command_has_pinned_workers_separate_gpus_and_seed(self):
        with tempfile.TemporaryDirectory() as d, patch.object(launcher, "ROOT", Path(d)):
            args = argparse.Namespace(action="pool", public_ip="2001:db8::1", bind_ip="::",
                pool_port=23445, p2p_bind="[::]:23444", share_bits=4, work_bank="auto",
                replay_gpu="0", proof_gpu="1", enable_payouts=False, peer=None, check=True)
            command = launcher.build_command(args, Path(d) / "inputs", Path(d) / "testnet")
            self.assertIn("[::]:23445", command)
            self.assertEqual(command[command.index("--production-v4-pool-proof-gpu") + 1], "1")
            self.assertEqual(command[command.index("--production-v4-pool-replay-gpu") + 1], "0")
            self.assertIn(launcher.SEED, command)
            self.assertIn("--no-default-seeds", command)
            self.assertNotIn("--enable-mainnet-payouts", command)

    def test_role_downloads_and_failure_propagation(self):
        for role, expected in (("pool", "miner"), ("miner", "pool-miner"), ("node", "node")):
            with patch.object(launcher.subprocess, "run") as run:
                launcher.prepare(Path("/test/inputs"), role)
                command = run.call_args.args[0]
                self.assertEqual(command[command.index("--role") + 1], expected)
                self.assertTrue(run.call_args.kwargs["check"])


if __name__ == "__main__":
    unittest.main()
