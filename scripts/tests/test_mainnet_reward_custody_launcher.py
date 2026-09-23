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
STEWARD_PASSWORD = "public steward fixture 猫 🔒 ' $ & | 7392"
COMMUNITY_PASSWORD = "public community fixture 狐 🔑 ' $ & | 4826"
DISTINCT_MAGIC = b"CMFD/REWARD-CUSTODY/TWO-PASSWORDS/V1\0"
INITIAL = "000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb"
LIMIT = "003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"


def ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def distinct_frame(steward: str, community: str) -> bytes:
    frame = bytearray(DISTINCT_MAGIC)
    for password in (steward, community):
        encoded = password.encode("utf-8")
        frame.extend(len(encoded).to_bytes(2, "little"))
        frame.extend(encoded)
    return bytes(frame)


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

    def invoke(self, *, wrong_confirmation=False, wrong_community_confirmation=False, same_passwords=False, wrong_hash=False):
        community = STEWARD_PASSWORD if same_passwords else COMMUNITY_PASSWORD
        steward_confirm = STEWARD_PASSWORD + ("-wrong" if wrong_confirmation else "")
        community_confirm = community + ("-wrong" if wrong_community_confirmation else "")
        code = (
            "$ErrorActionPreference='Stop'; "
            # Reproduce the UTF-8 BOM console mode on the Windows CI runner.
            "[Console]::InputEncoding=New-Object Text.UTF8Encoding($true); "
            f"$steward=ConvertTo-SecureString {ps_literal(STEWARD_PASSWORD)} -AsPlainText -Force; "
            f"$stewardConfirm=ConvertTo-SecureString {ps_literal(steward_confirm)} -AsPlainText -Force; "
            f"$community=ConvertTo-SecureString {ps_literal(community)} -AsPlainText -Force; "
            f"$communityConfirm=ConvertTo-SecureString {ps_literal(community_confirm)} -AsPlainText -Force; "
            f"$result=& {ps_literal(str(SCRIPT))} -NodePath {ps_literal(str(self.node))} "
            f"-ExpectedNodeSha256 {ps_literal('0' * 64 if wrong_hash else self.digest)} "
            f"-PowLimit {LIMIT} -InitialTarget {INITIAL} "
            f"-WalletParent {ps_literal(str(self.root / 'wallet parent with spaces'))} "
            f"-BackupParent {ps_literal(str(self.root / 'backup parent with spaces'))} "
            "-StewardPassword $steward -StewardPasswordConfirmation $stewardConfirm "
            "-CommunityPassword $community -CommunityPasswordConfirmation $communityConfirm; "
            "Write-Output ('CUSTODYTEST_RESULT=' + (($result | ConvertFrom-Json) | ConvertTo-Json -Depth 8 -Compress))"
        )
        environment = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
        # Do not feed PowerShell 7's bundled module path to Windows PowerShell 5.
        return subprocess.run([self.shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", code], capture_output=True, text=True, timeout=180, env=environment)

    def test_guided_two_password_setup_and_independent_raw_stdin_readback(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        for password in (STEWARD_PASSWORD, COMMUNITY_PASSWORD):
            self.assertNotIn(password, result.stdout + result.stderr)
        report = json.loads(result.stdout.split("CUSTODYTEST_RESULT=", 1)[1].strip())
        self.assertEqual(report["status"], "prepared_and_verified_not_activated")
        self.assertFalse(report["custody"]["mainnet_activation_authorized"])
        self.assertEqual(len(report["custody"]["wallets"]), 2)
        # Bypass PowerShell's stream writer for this independent check: any BOM,
        # newline or encoding transformation during setup would fail here.
        command = [str(self.node), "mainnet-custody-verify", "--expected-plan-digest", report["custody"]["launch_plan_digest"], "--distinct-passphrases-stdin"]
        for flag, key in [("--wallets-directory", "wallets_directory"), ("--backups-directory", "backups_directory"), ("--public-directory", "public_directory")]:
            command += [flag, report[key]]
        checked = subprocess.run(command, input=distinct_frame(STEWARD_PASSWORD, COMMUNITY_PASSWORD), capture_output=True, timeout=90)
        self.assertEqual(checked.returncode, 0, checked.stderr.decode())
        self.assertEqual(json.loads(checked.stdout), report["custody"])
        wrong = subprocess.run(command, input=distinct_frame(STEWARD_PASSWORD, "wrong community fixture password"), capture_output=True, timeout=90)
        self.assertNotEqual(wrong.returncode, 0)
        for path in self.root.rglob("*"):
            if path.is_file():
                for password in (STEWARD_PASSWORD, COMMUNITY_PASSWORD):
                    self.assertNotIn(password.encode(), path.read_bytes(), str(path))
                self.assertNotEqual(path.suffix, ".passphrase")

    def test_wrong_password_confirmation_creates_no_wallets(self):
        result = self.invoke(wrong_confirmation=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Steward password confirmation did not match", result.stderr)
        self.assertNotIn(STEWARD_PASSWORD, result.stdout + result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_community_confirmation_creates_no_wallets(self):
        result = self.invoke(wrong_community_confirmation=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Community password confirmation did not match", result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_same_password_for_both_roles_is_rejected_before_output(self):
        result = self.invoke(same_passwords=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("passwords must differ", result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_binary_hash_mismatch_creates_no_wallets(self):
        result = self.invoke(wrong_hash=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Node SHA-256 mismatch", result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
