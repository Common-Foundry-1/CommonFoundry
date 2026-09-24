"""Native identity CLI regression fixtures, not running wallets or launch approval."""
import base64
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_mainnet_ci_identities as check
import test_mainnet_packages as fixtures


class MainnetCiIdentityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.MainnetPackageTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.repo = self.fixture.root / "ci-source"
        (self.repo / "packaging/mainnet").mkdir(parents=True)
        (self.repo / "apps/wallet").mkdir(parents=True)
        (self.repo / "packaging/mainnet/MAINNET-PLAN.json").write_bytes(self.fixture.plan_path.read_bytes())
        (self.repo / "apps/wallet/package.json").write_text('{"version":"1.0.0"}')

    def run_check(self, output=None, commit=None):
        with mock.patch.object(check.package, "native_output", side_effect=output or self.fixture.output):
            return check.verify(self.repo, commit or self.fixture.commit, Path("cmfd-node"), Path("common-foundry-wallet"))

    def test_matching_prelaunch_identities_pass_without_starting_mainnet(self):
        result = self.run_check()
        self.assertTrue(result["consistent"])
        self.assertFalse(result["mainnet_started"])
        self.assertFalse(result["release_approved"])
        self.assertEqual(self.fixture.calls, [("cmfd-node", ["mainnet-launch-info"]),
                                             ("common-foundry-wallet", ["runtime-identity"])])

    def test_old_source_cannot_be_reported_as_new_ci_build(self):
        with self.assertRaises(check.package.Error):
            self.run_check(commit="b" * 40)

    def test_wallet_approval_mismatch_is_rejected(self):
        def changed(executable, arguments):
            output = self.fixture.output(executable, arguments)
            if arguments == ["runtime-identity"]:
                wrapper = json.loads(output)
                info = copy.deepcopy(self.fixture.info)
                info["activation_evidence_sha256"] = "f" * 64
                wrapper["launch_info_base64"] = base64.b64encode(check.package.canonical(info)).decode()
                return check.package.canonical(wrapper)
            return output
        with self.assertRaisesRegex(check.package.Error, "disagree"):
            self.run_check(output=changed)

    def test_wrong_wallet_version_and_legacy_identity_are_rejected(self):
        for mutation in ("version", "schema"):
            def changed(executable, arguments):
                output = self.fixture.output(executable, arguments)
                if arguments == ["runtime-identity"]:
                    wrapper = json.loads(output)
                    wrapper["package_version" if mutation == "version" else "schema"] = "legacy"
                    return check.package.canonical(wrapper)
                return output
            with self.subTest(mutation=mutation), self.assertRaises(check.package.Error):
                self.run_check(output=changed)
