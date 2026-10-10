"""Offline, non-deploying checks for the staged Linux mainnet pool service."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[2] / "packaging/mainnet/linux"
spec = importlib.util.spec_from_file_location("mainnet_pool_service", SOURCE / "mainnet-pool-service.py")
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MainnetPoolServiceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.install = self.base / "opt/commonfoundry-mainnet-pool"
        self.root = self.install / "releases/v1"
        self.state = self.base / "var/lib/commonfoundry-mainnet-pool"
        self.config_base = self.base / "etc/commonfoundry-mainnet-pool"
        self.credential_base = self.base / "run/credentials"
        for directory in (self.root, self.state, self.config_base, self.credential_base):
            directory.mkdir(parents=True)
        self.state.chmod(0o700)
        self.credential_base.chmod(0o700)
        self.assets = {
            "cmfd-node": b"mainnet node binary",
            "cmfd-launch": b"mainnet launch helper",
            "production-v4/cmfd-v4-replay": b"mainnet replay worker",
            "production-v4/real_bank0_relations": b"mainnet proof worker",
            "lib/libcudart.so.12": b"CUDA 12 runtime",
            "dashboard/index.html": b"<html>mainnet pool</html>",
            "production-v4/MODEL-V2.bank": b"distinct model bank",
            "production-v4/fixed/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json": b"fixed record",
            "production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json": b"fixed record",
        }
        for bank in range(3):
            for extension in ("row-major.codeword", "tree"):
                name = f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{extension}"
                self.assets[f"production-v4/fixed/{name}"] = name.encode()
        for name, content in self.assets.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        rows = []
        for name in sorted(pool.ARTIFACT_NAMES):
            path = self.root / "production-v4" / (name if name == "MODEL-V2.bank" else f"fixed/{name}")
            content = path.read_bytes()
            rows.append({"name": name, "bytes": len(content), "sha256": digest(content)})
        (self.root / "production-v4-rcnet-1-inputs.json").write_text(
            json.dumps({"schema_version": 1, "files": rows}), encoding="utf-8")
        self.plan = {"launch_plan_digest": "1" * 64, "network_id": "2" * 64,
                     "payload": {"minimum_transaction_fee_atoms": 1, "rules": {"artifacts": {
                         "bank": {"sha256": rows_by_name(rows, "MODEL-V2.bank")["sha256"],
                                  "bytes": rows_by_name(rows, "MODEL-V2.bank")["bytes"]},
                         "fixed_record": {"sha256": rows_by_name(rows, "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json")["sha256"],
                                          "bytes": rows_by_name(rows, "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json")["bytes"]},
                     }}}}
        sidecar = self.root / "production-mainnet/MAINNET-PLAN.json"
        sidecar.parent.mkdir()
        sidecar.write_text(json.dumps(self.plan), encoding="utf-8")
        self.info = {"format": "commonfoundry-mainnet-launch-info",
                     "genesis_policy": "requires_verified_launch_beacon", "launch_plan": self.plan}
        cert = b"fresh mainnet certificate"
        key = b"fresh mainnet private key"
        (self.config_base / "pool-cert.der").write_bytes(cert)
        (self.credential_base / "pool-private-key").write_bytes(key)
        (self.credential_base / "wallet-passphrase").write_bytes(b"fresh random passphrase")
        (self.credential_base / "pool-private-key").chmod(0o600)
        (self.credential_base / "wallet-passphrase").chmod(0o600)
        self.config = {
            "schema": pool.SCHEMA, "expected_network_id": self.plan["network_id"],
            "expected_plan_digest": self.plan["launch_plan_digest"],
            "public_numeric_ip": "8.8.8.8", "private_bind_ip": "192.168.1.42",
            "mainnet_seed": "9.9.9.9:29444",
            "gpu_uuid": "GPU-01234567-89ab-cdef-0123-456789abcdef", "worker_threads": 16,
            "expected_node_sha256": digest(self.assets["cmfd-node"]),
            "expected_launch_sha256": digest(self.assets["cmfd-launch"]),
            "expected_replay_worker_sha256": digest(self.assets["production-v4/cmfd-v4-replay"]),
            "expected_proof_worker_sha256": digest(self.assets["production-v4/real_bank0_relations"]),
            "expected_cuda_runtime_sha256": digest(self.assets["lib/libcudart.so.12"]),
            "expected_dashboard_index_sha256": digest(self.assets["dashboard/index.html"]),
            "expected_tls_certificate_sha256": digest(cert),
            "expected_tls_private_key_sha256": digest(key),
            "forbidden_rc_certificate_sha256": pool.RC_CERTIFICATE_SHA256,
            "forbidden_rc_private_key_sha256": "3" * 64,
            "forbidden_rc_wallet_file_sha256": "4" * 64,
            "share_leading_zero_bits": 7, "minimum_payout_atoms": 100,
            "payout_fee_atoms": 1, "operator_fee_bps": 0,
            "pplns_window_shares": 0, "automatic_payouts": True,
        }
        self.config_path = self.config_base / "pool.json"
        self.save_config()

    def save_config(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")

    def preflight(self):
        actual_regular = pool.regular
        def no_owner_check(path, label, *, static=False):
            return actual_regular(path, label, static=False)
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base), \
             mock.patch.object(pool, "regular", side_effect=no_owner_check), \
             mock.patch.object(pool, "native_launch_info", return_value=self.info), \
             mock.patch.object(pool, "check_gpu"):
            return pool.preflight(self.config_path, self.root, self.state, self.config_base,
                                  self.install, self.credential_base)

    def test_complete_isolated_preflight_and_mainnet_command(self):
        config, data, scratch = self.preflight()
        self.assertEqual(data, self.state / "data")
        self.assertEqual(scratch, self.state / "scratch")
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertIn("--enable-mainnet-payouts", command)
        self.assertNotIn("--enable-testnet-payouts", command)
        self.assertIn("--no-default-seeds", command)
        self.assertEqual(command[command.index("--bind") + 1], "192.168.1.42:29445")
        self.assertEqual(command[command.index("--p2p-bind") + 1], "192.168.1.42:29454")
        self.assertEqual(command[command.index("--pool-dashboard-bind") + 1], "127.0.0.1:29446")
        self.assertTrue(command[command.index("--pool-public-url") + 1].endswith(
            "?pin=" + self.config["expected_tls_certificate_sha256"]))
        self.assertNotIn("19445", " ".join(command))
        self.assertNotIn("/var/lib/commonfoundry-pool-public", " ".join(command))

    def test_optional_relays_become_additional_static_peers(self):
        self.config["mainnet_relays"] = ["1.1.1.1:29444", "[2606:4700:4700::1111]:29444"]
        self.save_config()
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        peers = [command[index + 1] for index, argument in enumerate(command) if argument == "--peer"]
        self.assertEqual(peers, ["9.9.9.9:29444", "1.1.1.1:29444", "[2606:4700:4700::1111]:29444"])
        for bad in (["1.1.1.1:29445"], ["9.9.9.9:29444"], ["1.1.1.1:29444"] * 2,
                    ["127.0.0.1:29444"], ["203.0.113.5:29444"], "1.1.1.1:29444", []):
            self.config["mainnet_relays"] = bad
            self.save_config()
            with self.assertRaisesRegex(pool.PreflightError, "mainnet_relays"):
                self.preflight()
        del self.config["mainnet_relays"]
        self.config["unexpected_field"] = 1
        self.save_config()
        with self.assertRaisesRegex(pool.PreflightError, "unexpected fields"):
            self.preflight()

    def test_optional_prune_window_becomes_prune_keep_blocks(self):
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertNotIn("--prune-keep-blocks", command)
        self.config["prune_keep_blocks"] = 720
        self.save_config()
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertEqual(command[command.index("--prune-keep-blocks") + 1], "720")
        for bad in (287, 0, -1, "720", 720.0, True, None, 2**32 + 1):
            self.config["prune_keep_blocks"] = bad
            self.save_config()
            with self.assertRaisesRegex(pool.PreflightError, "prune_keep_blocks"):
                self.preflight()

    def test_optional_pool_ledger_limit_becomes_pool_ledger_max_bytes(self):
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertNotIn("--pool-ledger-max-bytes", command)
        self.config["pool_ledger_max_bytes"] = 256 * 1024 * 1024
        self.save_config()
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertEqual(command[command.index("--pool-ledger-max-bytes") + 1], str(256 * 1024 * 1024))
        for bad in (1024 * 1024 - 1, 0, -1, "268435456", 268435456.0, True, None, 1024 * 1024 * 1024 + 1):
            self.config["pool_ledger_max_bytes"] = bad
            self.save_config()
            with self.assertRaisesRegex(pool.PreflightError, "pool_ledger_max_bytes"):
                self.preflight()

    def test_optional_share_batching_becomes_pool_share_batch_flags(self):
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertNotIn("--pool-share-batch-size", command)
        self.assertNotIn("--pool-share-batch-wait-ms", command)
        self.config["share_batch_size"] = 8
        self.config["share_batch_wait_ms"] = 50
        self.save_config()
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertEqual(command[command.index("--pool-share-batch-size") + 1], "8")
        self.assertEqual(command[command.index("--pool-share-batch-wait-ms") + 1], "50")
        for field, maximum in (("share_batch_size", 64), ("share_batch_wait_ms", 1000)):
            for bad in (0, -1, maximum + 1, "8", 8.0, True, None):
                self.config[field] = bad
                self.save_config()
                with self.assertRaisesRegex(pool.PreflightError, field):
                    self.preflight()
            self.config[field] = 8

    def test_optional_replay_gpus_become_replay_gpu_flags_and_are_checked(self):
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertNotIn("--production-v4-pool-replay-gpu", command)
        gpus = ["GPU-11111111-2222-3333-4444-555555555555",
                "GPU-66666666-7777-8888-9999-aaaaaaaaaaaa"]
        self.config["replay_gpus"] = gpus
        self.save_config()
        actual_regular = pool.regular
        def no_owner_check(path, label, *, static=False):
            return actual_regular(path, label, static=False)
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base), \
             mock.patch.object(pool, "regular", side_effect=no_owner_check), \
             mock.patch.object(pool, "native_launch_info", return_value=self.info), \
             mock.patch.object(pool, "check_gpu") as check_gpu:
            config, _, _ = pool.preflight(self.config_path, self.root, self.state, self.config_base,
                                          self.install, self.credential_base)
        self.assertEqual([call.args[0] for call in check_gpu.call_args_list],
                         [self.config["gpu_uuid"], *gpus])
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        flagged = [command[index + 1] for index, value in enumerate(command)
                   if value == "--production-v4-pool-replay-gpu"]
        self.assertEqual(flagged, gpus)
        for bad in ([], gpus[:1] * 2, ["0"], ["GPU-short"], "GPU-11111111-2222-3333-4444-555555555555",
                    [gpus[0]] * 17, [1], None):
            self.config["replay_gpus"] = bad
            self.save_config()
            with self.assertRaisesRegex(pool.PreflightError, "replay_gpus"):
                self.preflight()

    def test_optional_bonus_reserve_becomes_pool_bonus_flags(self):
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        for flag in ("--pool-bonus-rate-bps", "--pool-bonus-sponsor", "--pool-bonus-scan-from-height"):
            self.assertNotIn(flag, command)
        sponsor = "ab" * 32
        self.config["bonus_rate_bps"] = 1000
        self.config["bonus_sponsor"] = sponsor
        self.save_config()
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertEqual(command[command.index("--pool-bonus-rate-bps") + 1], "1000")
        self.assertEqual(command[command.index("--pool-bonus-sponsor") + 1], sponsor)
        self.assertNotIn("--pool-bonus-scan-from-height", command)
        self.config["bonus_scan_from_height"] = 0
        self.save_config()
        config, _, _ = self.preflight()
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base):
            command = pool.build_command(self.root, self.state, self.credential_base, config)
        self.assertEqual(command[command.index("--pool-bonus-scan-from-height") + 1], "0")
        for bad in (-1, "4200", 4200.0, True, None, 2**64):
            self.config["bonus_scan_from_height"] = bad
            self.save_config()
            with self.assertRaisesRegex(pool.PreflightError, "bonus_scan_from_height"):
                self.preflight()
        del self.config["bonus_scan_from_height"]
        for bad in (0, -1, 10_001, "1000", 1000.0, True, None):
            self.config["bonus_rate_bps"] = bad
            self.save_config()
            with self.assertRaisesRegex(pool.PreflightError, "bonus_rate_bps"):
                self.preflight()
        self.config["bonus_rate_bps"] = 1000
        for bad in ("AB" * 32, "ab" * 31, "zz" * 32, 1, None):
            self.config["bonus_sponsor"] = bad
            self.save_config()
            with self.assertRaisesRegex(pool.PreflightError, "bonus_sponsor"):
                self.preflight()
        for lone in ("bonus_rate_bps", "bonus_sponsor", "bonus_scan_from_height"):
            self.config.pop("bonus_rate_bps", None)
            self.config.pop("bonus_sponsor", None)
            self.config[lone] = sponsor if lone == "bonus_sponsor" else 1000
            self.save_config()
            with self.assertRaisesRegex(pool.PreflightError, "bonus_"):
                self.preflight()
            del self.config[lone]

    def test_placeholder_or_legacy_payout_config_fails_closed(self):
        self.config["operator_fee_bps"] = "SET_APPROVED_MAINNET_VALUE"
        self.save_config()
        with self.assertRaisesRegex(pool.PreflightError, "operator_fee_bps"):
            self.preflight()
        self.config["operator_fee_bps"] = 0
        self.config["automatic_payouts"] = False
        self.save_config()
        with self.assertRaisesRegex(pool.PreflightError, "automatic mainnet payouts"):
            self.preflight()
        self.config["automatic_payouts"] = True
        self.config["expected_proof_worker_sha256"] = "0" * 64
        self.save_config()
        with self.assertRaisesRegex(pool.PreflightError, "expected_proof_worker_sha256"):
            self.preflight()

    def test_payout_threshold_and_fee_must_match_mainnet_plan(self):
        self.config["minimum_payout_atoms"] = 1
        self.save_config()
        with self.assertRaisesRegex(pool.PreflightError, "minimum payout"):
            self.preflight()
        self.config["minimum_payout_atoms"] = 100
        self.plan["payload"]["minimum_transaction_fee_atoms"] = 2
        self.save_config()
        with self.assertRaisesRegex(pool.PreflightError, "payout fee"):
            self.preflight()

    def test_reused_rc_certificate_or_private_key_rejected(self):
        self.config["expected_tls_certificate_sha256"] = pool.RC_CERTIFICATE_SHA256
        with self.assertRaisesRegex(pool.PreflightError, "TLS material|known AI01"):
            pool.validate_config(self.config)
        self.config["expected_tls_certificate_sha256"] = digest(b"fresh mainnet certificate")
        self.config["forbidden_rc_private_key_sha256"] = self.config["expected_tls_private_key_sha256"]
        with self.assertRaisesRegex(pool.PreflightError, "TLS material"):
            pool.validate_config(self.config)

    def test_copied_rc_wallet_or_existing_unmarked_data_rejected(self):
        data = self.state / "data"
        data.mkdir()
        (data / "wallet.key").write_bytes(b"copied encrypted RC wallet")
        self.config["forbidden_rc_wallet_file_sha256"] = digest(b"copied encrypted RC wallet")
        self.save_config()
        with self.assertRaisesRegex(pool.PreflightError, "empty fresh data"):
            self.preflight()
        pool.write_marker(self.state, self.config)
        with self.assertRaisesRegex(pool.PreflightError, "RC encrypted wallet"):
            self.preflight()

    def test_changed_plan_worker_and_model_are_rejected(self):
        self.plan["launch_plan_digest"] = "5" * 64
        with self.assertRaisesRegex(pool.PreflightError, "launch plan/network ID"):
            self.preflight()
        self.plan["launch_plan_digest"] = "1" * 64
        worker = self.root / "production-v4/real_bank0_relations"
        worker.write_bytes(b"different worker")
        with self.assertRaisesRegex(pool.PreflightError, "proof worker SHA-256 mismatch"):
            self.preflight()
        worker.write_bytes(self.assets["production-v4/real_bank0_relations"])
        bank = self.root / "production-v4/MODEL-V2.bank"
        bank.write_bytes(b"different model")
        with self.assertRaisesRegex(pool.PreflightError, "model input mismatch"):
            self.preflight()

    def test_deployment_marker_binds_plan_and_certificate(self):
        pool.write_marker(self.state, self.config)
        self.preflight()
        self.config["expected_plan_digest"] = "6" * 64
        self.save_config()
        with self.assertRaisesRegex(pool.PreflightError, "launch plan/network ID|belongs to another"):
            self.preflight()

    def test_beacon_failure_never_execs_or_marks_pool(self):
        actual_regular = pool.regular
        def no_owner_check(path, label, *, static=False):
            return actual_regular(path, label, static=False)
        with mock.patch.object(pool, "ROOT", self.root), \
             mock.patch.object(pool, "STATE", self.state), \
             mock.patch.object(pool, "INSTALL_BASE", self.install), \
             mock.patch.object(pool, "CONFIG_BASE", self.config_base), \
             mock.patch.object(pool, "RUNTIME", self.credential_base), \
             mock.patch.object(pool, "regular", side_effect=no_owner_check), \
             mock.patch.object(pool, "native_launch_info", return_value=self.info), \
             mock.patch.object(pool, "check_gpu"), \
             mock.patch.object(pool, "check_competing_services") as competing, \
             mock.patch.object(pool, "check_gpu_idle") as gpu_idle, \
             mock.patch.object(pool.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "fetch")) as fetch, \
             mock.patch.object(pool.os, "execve") as execute, \
             mock.patch.object(sys, "argv", ["launcher", "--run", str(self.config_path)]), \
             mock.patch.dict(pool.os.environ, {"RUNTIME_DIRECTORY": str(self.credential_base)}):
            with self.assertRaises(subprocess.CalledProcessError):
                pool.main()
        fetch.assert_called_once_with([str(self.root / "cmfd-launch"), "fetch", "--runtime",
                                       str(self.root / "cmfd-node"), "--wait"], check=True)
        execute.assert_not_called()
        competing.assert_not_called()
        gpu_idle.assert_not_called()
        self.assertFalse((self.state / "mainnet-pool-deployment.json").exists())

    def test_successful_fetch_precedes_native_pool_exec(self):
        beacon = self.root / "production-mainnet/LAUNCH-BEACON.json"
        beacon.write_text("verified fixture", encoding="utf-8")
        actual_regular = pool.regular
        sequence = []
        def no_owner_check(path, label, *, static=False):
            return actual_regular(path, label, static=False)
        def fetched(*_args, **_kwargs):
            sequence.append("fetch")
        def checked():
            sequence.append("competing-services")
        def idle(_uuid):
            sequence.append("gpu-idle")
        def executed(*_args, **_kwargs):
            sequence.append("exec")
        with mock.patch.object(pool, "ROOT", self.root), \
             mock.patch.object(pool, "STATE", self.state), \
             mock.patch.object(pool, "INSTALL_BASE", self.install), \
             mock.patch.object(pool, "CONFIG_BASE", self.config_base), \
             mock.patch.object(pool, "RUNTIME", self.credential_base), \
             mock.patch.object(pool, "regular", side_effect=no_owner_check), \
             mock.patch.object(pool, "native_launch_info", return_value=self.info), \
             mock.patch.object(pool, "check_gpu"), \
             mock.patch.object(pool, "check_competing_services", side_effect=checked), \
             mock.patch.object(pool, "check_gpu_idle", side_effect=idle), \
             mock.patch.object(pool.subprocess, "run", side_effect=fetched) as fetch, \
             mock.patch.object(pool.os, "execve", side_effect=executed) as execute, \
             mock.patch.object(sys, "argv", ["launcher", "--run", str(self.config_path)]), \
             mock.patch.dict(pool.os.environ, {"RUNTIME_DIRECTORY": str(self.credential_base)}):
            self.assertEqual(pool.main(), 1)  # mocked execve returns, unlike the real call
        fetch.assert_called_once()
        execute.assert_called_once()
        self.assertEqual(sequence, ["fetch", "competing-services", "gpu-idle", "exec"])
        self.assertIn("--enable-mainnet-payouts", execute.call_args.args[1])
        self.assertTrue((self.state / "mainnet-pool-deployment.json").exists())
        command = execute.call_args.args[1]
        self.assertEqual(command[command.index("--wallet-passphrase-file") + 1],
                         str(self.credential_base / "wallet-passphrase"))
        self.assertEqual(command[command.index("--private-key") + 1],
                         str(self.credential_base / "pool-private-key"))

    def test_runtime_directory_cannot_be_redirected_by_environment(self):
        with mock.patch.object(pool, "CONFIG_BASE", self.config_base), \
             mock.patch.object(pool, "preflight") as preflight, \
             mock.patch.object(sys, "argv", ["launcher", "--check", str(self.config_path)]), \
             mock.patch.dict(pool.os.environ, {"RUNTIME_DIRECTORY": str(self.base / "other"),
                                                "CREDENTIALS_DIRECTORY": str(self.credential_base)}):
            with self.assertRaisesRegex(pool.PreflightError, "dedicated systemd RuntimeDirectory"):
                pool.main()
        preflight.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Unix credential mode checks")
    def test_group_readable_runtime_credentials_rejected(self):
        for name in ("wallet-passphrase", "pool-private-key"):
            path = self.credential_base / name
            path.chmod(0o640)
            with self.assertRaisesRegex(pool.PreflightError, "0600 or stricter"):
                pool.credentials(self.config, self.credential_base)
            path.chmod(0o600)

    @unittest.skipUnless(os.name == "posix", "Unix runtime mode/symlink checks")
    def test_nonprivate_or_symlink_runtime_directory_rejected(self):
        self.credential_base.chmod(0o750)
        with self.assertRaisesRegex(pool.PreflightError, "service-owned and private"):
            pool.credentials(self.config, self.credential_base)
        self.credential_base.chmod(0o700)
        alias = self.base / "runtime-alias"
        alias.symlink_to(self.credential_base)
        with self.assertRaisesRegex(pool.PreflightError, "must not be a symlink"):
            pool.credentials(self.config, alias)

    def test_competing_rc_pool_refuses_start_without_stopping_it(self):
        result = subprocess.CompletedProcess([], 0, stdout="active\n", stderr="")
        with mock.patch.object(pool.subprocess, "run", return_value=result) as inspect:
            with self.assertRaisesRegex(pool.PreflightError, "not inactive"):
                pool.check_competing_services()
        self.assertEqual(inspect.call_args.args[0][:2], ["/usr/bin/systemctl", "show"])
        self.assertNotIn("stop", inspect.call_args.args[0])

    def test_busy_or_unclassifiable_gpu_refuses_mainnet_pool_start(self):
        uuid = self.config["gpu_uuid"]
        for response in (f"{uuid}, 8486\n", "N/A, N/A\n"):
            result = subprocess.CompletedProcess([], 0, stdout=response, stderr="")
            with mock.patch.object(pool.subprocess, "run", return_value=result):
                with self.assertRaises(pool.PreflightError):
                    pool.check_gpu_idle(uuid)
        result = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch.object(pool.subprocess, "run", return_value=result):
            pool.check_gpu_idle(uuid)

    def test_rc_path_and_symlink_state_are_rejected(self):
        with self.assertRaisesRegex(pool.PreflightError, "dedicated mainnet-pool releases"):
            pool.check_isolation(self.base, self.state, self.config_path, self.install, self.config_base)
        with mock.patch.object(type(self.state), "is_symlink", return_value=True):
            with self.assertRaisesRegex(pool.PreflightError, "real dedicated directory"):
                pool.check_isolation(self.root, self.state, self.config_path, self.install, self.config_base)

    def test_unit_never_enables_or_starts_and_uses_separate_identity(self):
        unit = (SOURCE / "commonfoundry-mainnet-pool.service").read_text(encoding="utf-8")
        self.assertIn("User=commonfoundry-mainnet-pool", unit)
        self.assertIn("StateDirectory=commonfoundry-mainnet-pool", unit)
        self.assertIn("mainnet-launch-info", unit)
        self.assertIn("LoadCredential=wallet-passphrase:/etc/commonfoundry-mainnet-pool/", unit)
        self.assertIn("RuntimeDirectoryMode=0700", unit)
        for name in ("wallet-passphrase", "pool-private-key"):
            copy = (f"ExecStartPre=/usr/bin/install --mode=0600 %d/{name} "
                    f"/run/commonfoundry-mainnet-pool/{name}")
            self.assertIn(copy, unit)
            self.assertLess(unit.index("cmfd-node mainnet-launch-info"), unit.index(copy))
            self.assertLess(unit.index(copy), unit.index("ExecStart=/usr/bin/python3"))
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ProtectClock=true", unit)
        self.assertIn("DevicePolicy=closed", unit)
        self.assertNotIn("DeviceAllow=char-nvidia", unit)
        self.assertNotIn("DeviceAllow=/dev/nvidia*", unit)
        self.assertNotIn("Conflicts=commonfoundry-pool-public", unit)
        self.assertNotIn("ExecStartPost=systemctl", unit)
        self.assertNotIn("enable --now", unit)


def rows_by_name(rows: list[dict], name: str) -> dict:
    return next(row for row in rows if row["name"] == name)


if __name__ == "__main__":
    unittest.main()
