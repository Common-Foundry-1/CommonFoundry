"""Storage projections and isolated service-template contracts; no live changes."""
import ast
import os
from fractions import Fraction
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mainnet_storage_readiness as storage


class StorageReadinessTests(unittest.TestCase):
    def defaults(self, **overrides):
        values = dict(total_bytes=310911414272, available_bytes=294038781952,
                      block_log_bytes=1106437356, horizon_days=30, reserve_gib=20,
                      additional_artifact_bytes=0, records_per_canonical_block=Fraction(5, 4))
        values.update(overrides)
        return storage.forecast(**values)

    def test_current_seed_size_is_not_a_thirty_day_storage_plan(self):
        result = self.defaults()
        self.assertEqual(result["proof_only_bytes_per_day_at_target_spacing"], 17_316_460_800)
        self.assertEqual(result["maximum_v2_record_bytes"], 17 * 1024 * 1024 + 88)
        self.assertEqual(result["record_scenario_bytes_per_day_at_target_spacing"], (17 * 1024 * 1024 + 88) * 1800)
        self.assertFalse(result["horizon_fits_scenario"])
        self.assertTrue(result["reserve_satisfied"])
        self.assertGreater(result["scenario_additional_capacity_bytes"], 600 * storage.GIB)

    def test_reserve_is_not_confused_with_thirty_day_restarting_requirement(self):
        ample = self.defaults(total_bytes=2 * 1024 ** 4, available_bytes=1024 ** 4)
        self.assertTrue(ample["horizon_fits_scenario"])
        self.assertTrue(ample["reserve_satisfied"])
        low = self.defaults(available_bytes=20 * storage.GIB)
        self.assertFalse(low["reserve_satisfied"])
        self.assertEqual(low["days_until_reserve_in_scenario"], 0)
        normal = self.defaults(available_bytes=50 * storage.GIB)
        self.assertFalse(normal["horizon_fits_scenario"])
        self.assertTrue(normal["reserve_satisfied"])

    def test_additional_inputs_and_fractional_record_counts_are_explicit(self):
        base = self.defaults()
        with_inputs = self.defaults(additional_artifact_bytes=6442982389)
        self.assertEqual(with_inputs["scenario_required_available_bytes"] - base["scenario_required_available_bytes"], 6442982389)
        self.assertEqual(storage.ceiling(Fraction(7, 3)), 3)
        single = self.defaults(records_per_canonical_block=Fraction(1))
        self.assertLess(single["record_scenario_bytes_per_day_at_target_spacing"], base["record_scenario_bytes_per_day_at_target_spacing"])

    def test_invalid_quantities_are_rejected(self):
        for values in ({"available_bytes": -1}, {"horizon_days": 0}, {"reserve_gib": -1},
                       {"total_bytes": 0}, {"records_per_canonical_block": Fraction(1, 2)},
                       {"records_per_canonical_block": Fraction(17)}, {"block_log_bytes": True}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.defaults(**values)

    def test_inspection_reads_metadata_only_and_creates_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "blocks.log").write_bytes(b"test block log")
            (root / "wallet.key").write_bytes(b"not a real key; never read")
            before = {path.name: path.read_bytes() for path in root.iterdir()}
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("file contents read")):
                result = storage.inspect(root, horizon_days=30, reserve_gib=20,
                                         additional_artifact_bytes=0, records_per_canonical_block=Fraction(5, 4))
            self.assertEqual(result["block_log_bytes"], len(b"test block log"))
            self.assertEqual(before, {path.name: path.read_bytes() for path in root.iterdir()})

    def test_cli_reserve_failure_is_explicit_and_does_not_create_a_log(self):
        script = Path(__file__).resolve().parents[1] / "mainnet_storage_readiness.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reserve = shutil.disk_usage(root).total // storage.GIB + 1
            result = subprocess.run([sys.executable, str(script), "--data-dir", str(root),
                                     "--reserve-gib", str(reserve), "--enforce-reserve"],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn(b'"reserve_satisfied": false', result.stdout)
            self.assertEqual(list(root.iterdir()), [])

    def test_assumptions_track_actual_rust_storage_constants(self):
        repo = Path(__file__).resolve().parents[2]
        def value(relative, name):
            match = re.search(r"\bconst " + name + r": (?:usize|u64) = ([0-9_ *+]+);", (repo / relative).read_text())
            self.assertIsNotNone(match, name)
            def calculate(node):
                if isinstance(node, ast.Constant) and type(node.value) is int:
                    return node.value
                if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
                    left, right = calculate(node.left), calculate(node.right)
                    return left + right if isinstance(node.op, ast.Add) else left * right
                raise AssertionError("unsupported constant expression")
            return calculate(ast.parse(match.group(1), mode="eval").body)
        self.assertEqual(value("crates/cmfd-consensus/src/wire.rs", "PRODUCTION_V4_MAX_BLOCK_BYTES"), storage.MAX_BLOCK_BYTES)
        self.assertEqual(value("crates/cmfd-consensus/src/chain/state_delta.rs", "MAX_REVERSIBLE_STATE_DELTA_BYTES"), storage.MAX_STATE_DELTA_BYTES)
        self.assertEqual(value("crates/cmfd-consensus/src/difficulty.rs", "TARGET_SPACING_SECONDS"), storage.TARGET_SPACING_SECONDS)
        header = value("crates/cmfd-node/src/lib.rs", "RECORD_V2_HEADER_BYTES")
        checksum = value("crates/cmfd-node/src/lib.rs", "RECORD_CHECKSUM_BYTES")
        self.assertEqual(header + checksum, storage.RECORD_OVERHEAD_BYTES)
        codec = (repo / "crates/cmfd-consensus/src/forgematrix_v4_proof_codec.rs").read_text()
        proof = re.search(r"assert!\(FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES == ([0-9_]+)\)", codec)
        self.assertEqual(int(proof.group(1).replace("_", "")), storage.PROOF_BYTES)

    def test_service_does_not_reuse_rc_paths_and_gates_node_start(self):
        repo = Path(__file__).resolve().parents[2]
        source = (repo / "packaging/mainnet/linux/commonfoundry-mainnet-node.service").read_text()
        prestart = [line for line in source.splitlines() if line.startswith("ExecStartPre=")]
        self.assertIn("mainnet-launch-info", prestart[0])
        self.assertIn("--enforce-reserve", prestart[1])
        self.assertIn("cmfd-launch fetch", prestart[-1])
        self.assertIn("--wait", prestart[-1])
        credential_copy = next(index for index, line in enumerate(prestart) if "/usr/bin/install " in line)
        models = "/opt/commonfoundry-mainnet/current/production-v4/"
        for name in ("MODEL-V2.bank", "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"):
            for flag in ("-f", "-r"):
                probe = "ExecStartPre=/usr/bin/test " + flag + " " + models + name
                self.assertIn(probe, prestart)
                self.assertLess(prestart.index(probe), len(prestart) - 1)
                self.assertLess(prestart.index(probe), credential_copy)
        self.assertIn("--bind 127.0.0.1:29443 --p2p-bind 0.0.0.0:29444", source)
        self.assertIn("User=commonfoundry-mainnet\n", source)
        self.assertIn("TimeoutStartSec=infinity", source)
        self.assertNotIn("/opt/commonfoundry/", source)
        self.assertNotIn("/var/lib/commonfoundry ", source)
        self.assertNotIn("19444", source)

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "effective service-identity permission check requires an isolated Linux root test process")
    def test_root_prepared_models_need_read_only_service_group_access(self):
        import pwd
        identity = pwd.getpwnam("nobody")
        with tempfile.TemporaryDirectory(prefix="cmfd-service-permissions-") as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            models = root / "production-v4"
            models.mkdir(mode=0o700)
            files = [models / "MODEL-V2.bank", models / "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"]
            for path in files:
                path.write_bytes(b"public model fixture")
                path.chmod(0o600)

            def probe(flag, path):
                return subprocess.run(["/usr/bin/test", flag, str(path)],
                    user=identity.pw_uid, group=identity.pw_gid, extra_groups=[],
                    capture_output=True, timeout=5).returncode

            for path in files:
                self.assertNotEqual(probe("-r", path), 0)
            os.chown(models, 0, identity.pw_gid)
            models.chmod(0o750)
            for path in files:
                os.chown(path, 0, identity.pw_gid)
                path.chmod(0o640)
                self.assertEqual(probe("-f", path), 0)
                self.assertEqual(probe("-r", path), 0)
                self.assertNotEqual(probe("-w", path), 0)
                opened = subprocess.run(["/usr/bin/head", "-c", "1", str(path)],
                    user=identity.pw_uid, group=identity.pw_gid, extra_groups=[],
                    capture_output=True, timeout=5)
                self.assertEqual(opened.returncode, 0, opened.stderr)
                self.assertEqual(opened.stdout, b"p")
            self.assertNotEqual(probe("-w", models), 0)

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("systemd-analyze"), "systemd syntax verification is Linux-only")
    def test_systemd_parser_accepts_templates_without_installing_them(self):
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            paths = []
            for original in (repo / "packaging/mainnet/linux").glob("commonfoundry-mainnet-*.*"):
                if original.suffix not in (".service", ".timer"):
                    continue
                # Only executable existence is stubbed. No service is installed
                # or started; all original policy and path directives are parsed.
                source = re.sub(r"(?m)^(ExecStart(?:Pre)?)=.*$", r"\1=/usr/bin/true", original.read_text())
                path = Path(temporary) / original.name
                path.write_text(source)
                paths.append(str(path))
            result = subprocess.run(["systemd-analyze", "verify", *paths], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
