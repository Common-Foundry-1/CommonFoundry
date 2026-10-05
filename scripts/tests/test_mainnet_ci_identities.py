"""Native identity CLI regression fixtures, not running wallets or launch approval."""
import base64
import copy
import hashlib
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
        (self.repo / "apps/wallet/package.json").write_text('{"version":"1.0.9"}')

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

    def test_ci_stages_only_the_public_plan_before_querying_mainnet_binaries(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text()
        desktop = workflow.split("  desktop:\n", 1)[1]
        stage = "- name: Stage public mainnet plan beside CI executables"
        verify = "- name: Verify mainnet node and wallet identities"
        self.assertLess(desktop.index(stage), desktop.index(verify))
        step = desktop.split(stage, 1)[1].split("\n      - ", 1)[0]
        self.assertIn("steps.desktop_metadata.outputs.network_feature == 'production-mainnet'", step)
        self.assertIn("Path('packaging/mainnet/MAINNET-PLAN.json')", step)
        self.assertIn("Path('target/release/production-mainnet/MAINNET-PLAN.json')", step)
        self.assertIn("target.open('xb')", step)
        self.assertNotIn("LAUNCH-BEACON", step)

    def test_ci_checks_mainnet_feature_warnings_and_preserves_active_qualification(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text()
        mainnet_checks = workflow.split("  rust-v4:\n", 1)[1].split("\n  rust:\n", 1)[0]
        self.assertIn("components: clippy", mainnet_checks)
        self.assertIn(
            "cargo clippy --locked -p cmfd-node --lib --tests --features production-mainnet -- -D warnings",
            mainnet_checks,
        )
        concurrency = workflow.split("concurrency:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn(
            "cancel-in-progress: ${{ github.ref != 'refs/heads/release/mainnet-readiness' && "
            "github.ref != 'refs/heads/release/mainnet-gpu-compatibility' }}",
            concurrency,
        )


class MainnetReleasePolicyTests(unittest.TestCase):
    def test_release_checksum_policy_uses_the_selected_mainnet_key(self):
        repo = Path(__file__).resolve().parents[2]
        root = repo / "packaging/mainnet"
        release = (root / "MAINNET-RELEASE.allowed_signers").read_text().splitlines()
        producer = (root / "MAINNET-PRODUCER.allowed_signers").read_text().splitlines()
        selected = json.loads((root / "SIGNER-SELECTION.json").read_bytes())
        trust = json.loads((root / "APPROVAL-TRUST.json").read_bytes())
        self.assertEqual(len(release), 1)
        self.assertEqual(len(producer), 1)
        release_parts, producer_parts = release[0].split(), producer[0].split()
        self.assertEqual(len(release_parts), 4)
        self.assertEqual(len(producer_parts), 4)
        self.assertEqual(release_parts[:3], [
            selected["signer_identity"], 'namespaces="commonfoundry-release"', "ssh-ed25519",
        ])
        self.assertEqual(producer_parts[0], release_parts[0])
        self.assertEqual(producer_parts[2:], release_parts[2:])
        self.assertNotEqual(producer_parts[1], release_parts[1])
        key_blob = base64.b64decode(release_parts[3], validate=True)
        key_hash = hashlib.sha256(key_blob).digest()
        fingerprint = "SHA256:" + base64.b64encode(key_hash).decode().rstrip("=")
        self.assertEqual(key_hash.hex(), trust["producer"]["key_blob_sha256"])
        self.assertEqual(fingerprint, selected["selected_fingerprint"])
        self.assertEqual(fingerprint, trust["producer"]["key_fingerprint"])
