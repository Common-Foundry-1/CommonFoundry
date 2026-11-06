import argparse
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "packaging/compact-proof-testnet/launch.py"
spec = importlib.util.spec_from_file_location("compact_launcher", SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class CompactPackageTests(unittest.TestCase):
    def test_archive_keeps_the_kit_version_after_copying_binary_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            for name in ("cmfd-node", "cmfd-miner", "cmfd-v4-replay", "cmfd-direct-prover"):
                (artifacts / name).write_bytes(b"test binary")
            output = root / "output"
            script = SOURCE.parents[2] / "scripts/package-compact-testnet.py"
            subprocess.run([sys.executable, str(script), "--artifacts", str(artifacts),
                "--output", str(output), "--source-commit", "a" * 40], check=True,
                capture_output=True, text=True)
            archive = output / "commonfoundry-compact-testnet-v0.2.0-linux-x86_64.tar.gz"
            self.assertTrue(archive.is_file())
            with tarfile.open(archive) as packaged:
                self.assertIn("commonfoundry-compact-testnet-v0.2.0-linux-x86_64/BUILD-INFO.json",
                    packaged.getnames())

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
                replay_gpu="0", proof_gpu="1", enable_payouts=False, peer=None, check=True,
                ram_witness_dir=None, serial_gpu=False)
            command = launcher.build_command(args, Path(d) / "inputs", Path(d) / "testnet")
            self.assertIn("[::]:23445", command)
            self.assertEqual(command[command.index("--production-v4-pool-proof-gpu") + 1], "1")
            self.assertEqual(command[command.index("--production-v4-pool-replay-gpu") + 1], "0")
            self.assertIn(launcher.SEED, command)
            self.assertIn("--no-default-seeds", command)
            self.assertNotIn("--enable-mainnet-payouts", command)

            args.ram_witness_dir = Path("/dev/shm/private-test-witness")
            args.serial_gpu = True
            command = launcher.build_command(args, Path(d) / "inputs", Path(d) / "testnet")
            self.assertEqual(command[command.index("--production-v4-pool-scratch") + 1],
                str(args.ram_witness_dir))
            self.assertEqual(command[command.index("--data-dir") + 1], str(Path(d) / "testnet"))
            self.assertIn("--production-v4-pool-serial-gpu", command)

    def test_ram_witnesses_require_private_bounded_ram_and_host_reserve(self):
        cases = [
            ({}, None),
            ({"filesystem": "ext2"}, "must use tmpfs"),
            ({"mount": False}, "dedicated bounded"),
            ({"capacity": 3 * 1024**3}, "capped at 2 GiB"),
            ({"free": 1024**3}, "1.65 GB free"),
            ({"memory_kib": 7 * 1024**2}, "8 GiB available"),
            ({"mode": 0o40755}, "owned by this user"),
            ({"uid": 2000}, "owned by this user"),
            ({"symlink": True}, "existing Linux tmpfs"),
        ]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for values, error in cases:
                with self.subTest(values=values), ExitStack() as stack:
                    stack.enter_context(patch.object(launcher.sys, "platform", "linux"))
                    stack.enter_context(patch.object(launcher.os, "geteuid", return_value=1000, create=True))
                    stack.enter_context(patch.object(Path, "is_symlink", return_value=values.get("symlink", False)))
                    stack.enter_context(patch.object(Path, "stat", return_value=SimpleNamespace(
                        st_mode=values.get("mode", 0o40700), st_uid=values.get("uid", 1000))))
                    stack.enter_context(patch.object(launcher.os.path, "ismount", return_value=values.get("mount", True)))
                    stack.enter_context(patch.object(launcher.subprocess, "check_output", return_value=values.get("filesystem", "tmpfs") + "\n"))
                    stack.enter_context(patch.object(launcher.os, "statvfs", return_value=SimpleNamespace(
                        f_blocks=values.get("capacity", 2 * 1024**3) // 4096,
                        f_bavail=values.get("free", 2 * 1024**3) // 4096, f_frsize=4096), create=True))
                    stack.enter_context(patch.object(Path, "read_text", return_value=
                        f"MemAvailable: {values.get('memory_kib', 16 * 1024**2)} kB\n"))
                    if error:
                        with self.assertRaisesRegex(ValueError, error):
                            launcher.validate_ram_witness_directory(root)
                    else:
                        self.assertEqual(launcher.validate_ram_witness_directory(root), root.resolve())

    def test_shared_gpu_miner_yields_only_when_requested(self):
        args = argparse.Namespace(action="miner", pool="cmfd+tls://127.0.0.1:23445?pin=" + "a" * 64,
            address="test-address", worker="rig", gpu="0", yield_gpu_on_share=False)
        command = launcher.build_command(args, Path("/inputs"), Path("/miner-data"))
        self.assertNotIn("--yield-gpu-on-share", command)
        args.yield_gpu_on_share = True
        command = launcher.build_command(args, Path("/inputs"), Path("/miner-data"))
        self.assertIn("--yield-gpu-on-share", command)

    def test_role_downloads_and_failure_propagation(self):
        for role, expected in (("pool", "miner"), ("miner", "pool-miner"), ("node", "node")):
            with patch.object(launcher.subprocess, "run") as run:
                launcher.prepare(Path("/test/inputs"), role)
                command = run.call_args.args[0]
                self.assertEqual(command[command.index("--role") + 1], expected)
                self.assertTrue(run.call_args.kwargs["check"])

    def test_sealed_handoff_requires_private_ram_and_serial_worker_lifetime(self):
        for options in ([], ["--serial-gpu"], ["--ram-witness-dir", "/private-witness"]):
            with self.subTest(options=options), \
                    patch.object(sys, "argv", ["launch.py", "pool", "--public-ip", "127.0.0.1", "--check", "--sealed-witness"] + options), \
                    patch.object(launcher, "verify"), \
                    patch.object(launcher, "validate_ram_witness_directory", return_value=Path("/private-witness")):
                with self.assertRaisesRegex(ValueError, "requires --ram-witness-dir and --serial-gpu"):
                    launcher.main()

    def test_sealed_profile_selects_tested_startup_defaults_and_preserves_overrides(self):
        for inherited, expected in (({}, "EAGER"), ({"CUDA_MODULE_LOADING": "LAZY"}, "LAZY")):
            with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, inherited, clear=True), \
                    patch.object(sys, "argv", ["launch.py", "pool", "--public-ip", "127.0.0.1",
                        "--check", "--data-dir", d, "--sealed-witness", "--serial-gpu",
                        "--ram-witness-dir", "/private-witness"]), \
                    patch.object(launcher, "verify"), \
                    patch.object(launcher, "validate_ram_witness_directory", return_value=Path("/private-witness")), \
                    patch("builtins.print"):
                launcher.main()
                self.assertEqual(os.environ["CMFD_REPLAY_SEALED_EXPORT"], "1")
                self.assertEqual(os.environ["CMFD_REPLAY_PARALLEL_LOAD"], "1")
                self.assertEqual(os.environ["CUDA_MODULE_LOADING"], expected)


if __name__ == "__main__":
    unittest.main()
