"""Launcher ordering tests with local stubs; no mining or network requests."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class MainnetLauncherTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parents[2]
        self.temporary = tempfile.TemporaryDirectory(prefix="cmfd-mainnet-launcher-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.log = self.root / "calls.txt"
        self.bash = Path("C:/Program Files/Git/bin/bash.exe") if os.name == "nt" else Path(shutil.which("bash") or "/bin/bash")
        self.assertTrue(self.bash.is_file(), "bash is required for launcher qualification")
        for source in (self.repo / "packaging/mainnet/linux").glob("*.sh"):
            shutil.copyfile(source, self.root / source.name)
        for name in ("cmfd-node", "cmfd-launch", "common-foundry-wallet", "prepare-runtime.sh", "cmfd-miner", "PREPARE-V4-INPUTS.sh"):
            text = f'''#!/usr/bin/env bash
printf '%s|%s\\n' '{name}' "$*" >> "$CMFD_TEST_LOG"
[[ "${{CMFD_TEST_FAIL:-}}" != '{name}' ]] || exit 9
exit 0
'''
            path = self.root / name
            path.write_text(text, encoding="utf-8", newline="\n")
            path.chmod(0o755)

    def invoke(self, script, *arguments, fail=""):
        env = dict(os.environ, CMFD_TEST_LOG=self.log.as_posix(), CMFD_TEST_FAIL=fail, CMFD_WORKER_NAME="test-rig")
        result = subprocess.run([str(self.bash), (self.root / script).as_posix(), *arguments], env=env, capture_output=True, timeout=10)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return result, calls

    def test_wallet_opens_for_preparation_without_waiting_for_launch(self):
        result, calls = self.invoke("start-wallet.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([line.split("|")[0] for line in calls], ["cmfd-node", "prepare-runtime.sh", "common-foundry-wallet"])
        self.assertIn("mainnet-launch-info", calls[0])

    def test_wallet_does_not_start_if_input_preparation_fails(self):
        result, calls = self.invoke("start-wallet.sh", fail="prepare-runtime.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(line.startswith("common-foundry-wallet|") for line in calls))

    def test_wrong_runtime_stops_before_any_input_preparation(self):
        result, calls = self.invoke("start-wallet.sh", fail="cmfd-node")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)

    def test_miner_arguments_and_launch_gate_precede_pool_connection(self):
        wallet = "ab" * 32
        pool = "cmfd+tls://8.8.8.8:29445?pin=" + "cd" * 32
        result, calls = self.invoke("start-miner.sh", wallet, pool)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([line.split("|")[0] for line in calls], ["cmfd-miner", "PREPARE-V4-INPUTS.sh", "cmfd-launch", "cmfd-miner"])
        self.assertIn("mainnet-launch-info", calls[0])
        self.assertIn("--wait", calls[2])
        self.assertIn("pool --pool " + pool, calls[3])
        self.assertIn("--miner " + wallet, calls[3])

    def test_linux_miner_gpu_selection_is_isolated_and_default_is_unchanged(self):
        wallet = "ab" * 32
        pool = "cmfd+tls://8.8.8.8:29445?pin=" + "cd" * 32
        result, calls = self.invoke("start-miner.sh", wallet, pool, "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--gpu 2", calls[-1])
        self.assertIn("pool-search-gpu-2", calls[-1])
        self.assertTrue((self.root / "work/logs/miner-gpu-2.log").is_file())
        self.log.unlink()
        result, calls = self.invoke("start-miner.sh", wallet, pool)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--gpu", calls[-1])
        self.assertIn("work/pool-search --stats-seconds", calls[-1])

    def test_linux_rc_miner_uses_the_same_optional_gpu_isolation(self):
        shutil.copyfile(
            self.repo / "packaging/production-rc/miner/linux/start-miner.sh",
            self.root / "rc-start-miner.sh",
        )
        wallet = "ab" * 32
        pool = "cmfd+tls://8.8.8.8:29445?pin=" + "cd" * 32
        uuid = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        result, calls = self.invoke("rc-start-miner.sh", wallet, pool, uuid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--gpu " + uuid, calls[-1])
        self.assertIn("pool-search-gpu-" + uuid, calls[-1])

    @unittest.skipUnless(os.name == "nt", "native PowerShell launcher execution is Windows-only")
    def test_windows_mainnet_and_rc_miners_pass_selected_gpu_and_isolate_paths(self):
        powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        build = self.root / "build-miner-probe.ps1"
        build.write_text('''$ErrorActionPreference = 'Stop'
$source = @'
using System;
using System.IO;
using System.Reflection;
public class MinerProbe {
  public static void Main(string[] args) {
    string name = Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location);
    File.AppendAllText(Environment.GetEnvironmentVariable("CMFD_TEST_LOG"), name + "|" + String.Join(" ", args) + "\\n");
  }
}
'@
Add-Type -TypeDefinition $source -OutputAssembly (Join-Path $PSScriptRoot 'miner-probe.exe') -OutputType ConsoleApplication
''', encoding="utf-8")
        built = subprocess.run([powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(build)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        for name in ("cmfd-miner.exe", "cmfd-launch.exe"):
            shutil.copyfile(self.root / "miner-probe.exe", self.root / name)
        (self.root / "PREPARE-V4-INPUTS.ps1").write_text('param($Role,$FallbackReleaseBase)\n[IO.File]::AppendAllText($env:CMFD_TEST_LOG,"prepare|$Role`n")\n', encoding="utf-8")
        shutil.copyfile(self.repo / "packaging/mainnet/windows/START-MINER.ps1", self.root / "START-MAINNET-MINER.ps1")
        shutil.copyfile(self.repo / "packaging/production-rc/miner/windows/START-MINER.ps1", self.root / "START-RC-MINER.ps1")
        wallet = "ab" * 32
        pool = "cmfd+tls://8.8.8.8:29445?pin=" + "cd" * 32
        env = dict(os.environ, CMFD_TEST_LOG=str(self.log))
        env.pop("CUDA_VISIBLE_DEVICES", None)
        env.pop("CMFD_GPU", None)
        for script, expected_prefix in (("START-MAINNET-MINER.ps1", ["cmfd-miner", "prepare", "cmfd-launch", "cmfd-miner"]),
                                        ("START-RC-MINER.ps1", ["prepare", "cmfd-miner"])):
            with self.subTest(script=script):
                self.log.unlink(missing_ok=True)
                arguments = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(self.root / script),
                             "-WalletAddress", wallet, "-PoolUrl", pool, "-WorkerName", "rig", "-GpuSelector", "2"]
                result = subprocess.run(arguments, env=env, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.log.read_text().splitlines()
                self.assertEqual([line.split("|")[0] for line in calls], expected_prefix)
                self.assertIn("--gpu 2", calls[-1])
                self.assertIn("pool-search-gpu-2", calls[-1])
                self.assertTrue((self.root / "work/logs/miner-gpu-2.log").is_file())
        self.log.unlink()
        result = subprocess.run(arguments[:-2] + ["-GpuSelector", ""], env=env, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--gpu", self.log.read_text().splitlines()[-1])
        self.assertIn("pool-search", self.log.read_text().splitlines()[-1])

    def test_miner_does_not_start_after_failed_beacon_or_invalid_address(self):
        pool = "cmfd+tls://8.8.8.8:29445?pin=" + "cd" * 32
        result, calls = self.invoke("start-miner.sh", "bad-address", pool)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        result, calls = self.invoke("start-miner.sh", "ab" * 32, pool, fail="cmfd-launch")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(line.startswith("cmfd-miner|pool ") for line in calls))

    @unittest.skipUnless(os.name == "nt", "native PowerShell launcher execution is Windows-only")
    def test_windows_wallet_opens_before_beacon_but_node_stays_gated(self):
        powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        build = self.root / "build-probe.ps1"
        build.write_text('''$ErrorActionPreference = 'Stop'
$source = @'
using System;
using System.IO;
using System.Reflection;
public class Probe {
  public static void Main(string[] args) {
    string name = Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location);
    File.AppendAllText(Environment.GetEnvironmentVariable("CMFD_TEST_LOG"), name + "|" + String.Join(" ", args) + "\\n");
    if (Environment.GetEnvironmentVariable("CMFD_TEST_FAIL") == name) Environment.Exit(9);
  }
}
'@
Add-Type -TypeDefinition $source -OutputAssembly (Join-Path $PSScriptRoot 'probe.exe') -OutputType ConsoleApplication
''', encoding="utf-8")
        result = subprocess.run([powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(build)], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("cmfd-node.exe", "cmfd-launch.exe", "common-foundry-wallet.exe"):
            shutil.copyfile(self.root / "probe.exe", self.root / name)
        shutil.copyfile(self.repo / "packaging/mainnet/windows/START-RUNTIME.ps1", self.root / "START-RUNTIME.ps1")
        (self.root / "PREPARE-RUNTIME.ps1").write_text('param($Destination)\n[IO.File]::AppendAllText($env:CMFD_TEST_LOG,"prepare|$Destination`n")\n', encoding="utf-8")
        arguments = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(self.root / "START-RUNTIME.ps1"), "-Mode", "Wallet"]
        env = dict(os.environ, CMFD_TEST_LOG=str(self.log), CMFD_TEST_FAIL="cmfd-launch")
        result = subprocess.run(arguments, env=env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([line.split("|")[0] for line in self.log.read_text().splitlines()], ["cmfd-node", "prepare", "common-foundry-wallet"])
        self.log.unlink()
        passphrase = self.root / "passphrase.txt"
        passphrase.write_text("test passphrase only", encoding="utf-8")
        arguments[-1] = "Node"
        arguments.extend(["-WalletPassphraseFile", str(passphrase)])
        result = subprocess.run(arguments, env=env, capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("|--data-dir" in line for line in self.log.read_text().splitlines()))
        self.log.unlink()
        env["CMFD_TEST_FAIL"] = ""
        result = subprocess.run(arguments, env=env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([line.split("|")[0] for line in self.log.read_text().splitlines()], ["cmfd-node", "prepare", "cmfd-launch", "cmfd-node"])


if __name__ == "__main__":
    unittest.main()
