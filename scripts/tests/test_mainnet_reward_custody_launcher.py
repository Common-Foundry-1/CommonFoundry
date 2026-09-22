"""Windows guided setup integration with disposable keys and public fixture passwords.

Set CMFD_CUSTODY_TEST_NODE to a locally built production-v4 node to run these.
No real operator wallet, password, or release approval is used.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "prepare-mainnet-reward-wallets.ps1"
NODE = os.environ.get("CMFD_CUSTODY_TEST_NODE")
PASSWORD = "public fixture 猫 🔒 ' $ & | 7392"
INITIAL = "000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb"
LIMIT = "003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"


def ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@unittest.skipUnless(os.name == "nt" and NODE, "requires Windows and CMFD_CUSTODY_TEST_NODE")
class GuidedRewardCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cmfd-guided-custody-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.node = Path(NODE).resolve()
        self.shell = shutil.which("powershell.exe")
        if not self.shell:
            self.skipTest("Windows PowerShell unavailable")
        with self.node.open("rb") as stream:
            self.digest = hashlib.file_digest(stream, "sha256").hexdigest()

    def invoke(self, *, wrong_confirmation=False, wrong_hash=False):
        confirm = PASSWORD + ("-wrong" if wrong_confirmation else "")
        code = (
            "$ErrorActionPreference='Stop'; "
            # Reproduce the UTF-8 BOM console mode on the Windows CI runner.
            "[Console]::InputEncoding=New-Object Text.UTF8Encoding($true); "
            f"$a=ConvertTo-SecureString {ps_literal(PASSWORD)} -AsPlainText -Force; "
            f"$b=ConvertTo-SecureString {ps_literal(confirm)} -AsPlainText -Force; "
            f"$result=& {ps_literal(str(SCRIPT))} -NodePath {ps_literal(str(self.node))} "
            f"-ExpectedNodeSha256 {ps_literal('0' * 64 if wrong_hash else self.digest)} "
            f"-PowLimit {LIMIT} -InitialTarget {INITIAL} "
            f"-WalletParent {ps_literal(str(self.root / 'wallet parent with spaces'))} "
            f"-BackupParent {ps_literal(str(self.root / 'backup parent with spaces'))} "
            "-Password $a -PasswordConfirmation $b; "
            "Write-Output ('CUSTODYTEST_RESULT=' + (($result | ConvertFrom-Json) | ConvertTo-Json -Depth 8 -Compress))"
        )
        environment = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
        # Do not feed PowerShell 7's bundled module path to Windows PowerShell 5.
        return subprocess.run([self.shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", code], capture_output=True, text=True, timeout=180, env=environment)

    def test_guided_setup_and_independent_raw_stdin_readback(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        report = json.loads(result.stdout.split("CUSTODYTEST_RESULT=", 1)[1].strip())
        self.assertEqual(report["status"], "prepared_and_verified_not_activated")
        self.assertFalse(report["custody"]["mainnet_activation_authorized"])
        self.assertEqual(len(report["custody"]["wallets"]), 2)
        # Bypass PowerShell's stream writer for this independent check: any BOM,
        # newline or encoding transformation during setup would fail here.
        command = [str(self.node), "mainnet-custody-verify", "--expected-plan-digest", report["custody"]["launch_plan_digest"], "--shared-passphrase-stdin"]
        for flag, key in [("--wallets-directory", "wallets_directory"), ("--backups-directory", "backups_directory"), ("--public-directory", "public_directory")]:
            command += [flag, report[key]]
        checked = subprocess.run(command, input=PASSWORD.encode(), capture_output=True, timeout=90)
        self.assertEqual(checked.returncode, 0, checked.stderr.decode())
        self.assertEqual(json.loads(checked.stdout), report["custody"])
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(PASSWORD.encode(), path.read_bytes(), str(path))
                self.assertNotEqual(path.suffix, ".passphrase")

    def test_wrong_password_confirmation_creates_no_wallets(self):
        result = self.invoke(wrong_confirmation=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Passwords did not match", result.stderr)
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_binary_hash_mismatch_creates_no_wallets(self):
        result = self.invoke(wrong_hash=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Node SHA-256 mismatch", result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
