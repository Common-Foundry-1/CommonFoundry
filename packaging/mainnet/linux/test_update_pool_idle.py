import contextlib
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('updater', Path(__file__).with_name('update-pool-idle.py'))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class UpdaterTests(unittest.TestCase):
    def test_fixed_policy_and_activation(self):
        self.assertEqual(updater.sha(updater.POLICY), updater.POLICY_SHA)
        self.assertEqual(datetime.datetime.fromtimestamp(updater.ACTIVATION, datetime.timezone.utc).isoformat(),
                         '2026-10-03T17:00:00+00:00')

    def test_before_launch_does_nothing(self):
        with patch.object(updater.sys, 'argv', ['update']), patch.object(updater.os, 'geteuid', return_value=0), \
             patch.object(updater.platform, 'system', return_value='Linux'), \
             patch.object(updater.platform, 'machine', return_value='x86_64'), \
             patch.object(updater.time, 'time', return_value=updater.ACTIVATION-1), \
             patch.object(updater, 'command') as command, patch.object(updater.urllib.request, 'urlopen') as download, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(updater.main(), 0)
            command.assert_not_called()
            download.assert_not_called()

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'isolated Linux root fixture required')
    def test_install_and_rollback(self):
        for failure in (None, 'plan', 'start', 'stop'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                runtime = root/'runtime'
                runtime.mkdir()
                config = root/'pool.json'
                external = root/'external.py'
                original = {'wallet_file': '/private/wallet', 'model_path': '/large/model',
                            'peers': ['seed'], 'operator_fee_bps': 0, 'minimum_payout_atoms': 1000000000,
                            'expected_node_sha256': 'old', 'idle_gpu_search': False}
                config.write_text(json.dumps(original))
                os.chmod(config, 0o640)
                targets = [runtime/'cmfd-node', runtime/'mainnet-pool-service.py', config, external]
                for target in (targets[0], targets[1], external):
                    target.write_bytes(b'original-'+target.name.encode())
                    os.chmod(target, 0o755)
                before = {target: target.read_bytes() for target in targets}
                calls = []
                plan_count = 0
                failed = False

                def run(*args, **kwargs):
                    nonlocal plan_count, failed
                    calls.append(args)
                    output = b''
                    if args[-1] == 'mainnet-launch-info':
                        plan_count += 1
                        output = json.dumps({'launch_plan': {'digest': 'changed' if failure == 'plan' and plan_count == 2 else 'same'}}).encode()
                    if args[:2] in [('systemctl', 'start'), ('systemctl', 'stop')] and args[1] == failure and not failed:
                        failed = True
                        raise subprocess.CalledProcessError(1, args)
                    return subprocess.CompletedProcess(args, 0, stdout=output)

                files = {'cmfd-node': b'new-node', 'mainnet-pool-service.py': b'new-launcher'}
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    if failure:
                        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                            updater.apply_update(files, config, runtime, external, root, run)
                        self.assertEqual({target: target.read_bytes() for target in targets}, before)
                        self.assertEqual(calls[-1][:2], ('systemctl', 'start'))
                    else:
                        backup = updater.apply_update(files, config, runtime, external, root, run)
                        self.assertEqual(json.loads(config.read_text()), dict(original, expected_node_sha256=updater.NODE_SHA, idle_gpu_search=True))
                        self.assertEqual(targets[0].read_bytes(), b'new-node')
                        self.assertEqual(targets[1].read_bytes(), b'new-launcher')
                        self.assertEqual(external.read_bytes(), b'new-launcher')
                        self.assertEqual((backup/'pool.json').read_bytes(), before[config])
                self.assertEqual(config.stat().st_mode & 0o777, 0o640)

    def test_corrupt_download_rejected_before_signature(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(updater.urllib.request, 'urlopen', side_effect=lambda *a, **k: io.BytesIO(b'corrupt')), \
             patch.object(updater, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                updater.verified_files(Path(tmp))
            command.assert_not_called()

    @unittest.skipUnless(os.environ.get('CMFD_TEST_PUBLIC_DOWNLOAD') == '1', 'optional read-only public download')
    def test_public_download_and_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = updater.verified_files(Path(tmp))
            self.assertEqual(updater.sha(files['cmfd-node']), updater.NODE_SHA)
            self.assertIn('mainnet-pool-service.py', files)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'isolated Linux root fixture required')
    def test_reject_symlink_before_service_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root/'pool.json'
            config.write_text('{}')
            (root/'cmfd-node').symlink_to(config)
            with patch.object(updater, 'command') as run:
                with self.assertRaises(ValueError):
                    updater.apply_update({}, config, root, root/'missing', root, run)
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
