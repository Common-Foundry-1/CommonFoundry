import importlib.util
from pathlib import Path
import tempfile
import contextlib
import io
import json
import os
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('launcher',Path(__file__).resolve().parents[2]/'packaging/compact-proof-testnet/launch.py')
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)

class LauncherTests(unittest.TestCase):
    def test_dedicated_residency_is_explicit_and_excludes_other_sharing_modes(self):
        base=['launch.py','pool','--public-ip','127.0.0.1','--proof-gpu','0','--replay-gpu','0','--keep-replay-resident','--check']
        with patch.object(sys,'platform','linux'),patch.object(sys,'argv',base),patch.object(launcher,'verify') as verify:
            with self.assertRaises(ValueError):launcher.main()
            verify.assert_not_called()
        output=io.StringIO()
        with patch.object(sys,'platform','linux'),patch.object(sys,'argv',base+['--serial-gpu']),patch.object(launcher,'verify'),contextlib.redirect_stdout(output):
            launcher.main()
        raw=output.getvalue();command=json.loads(raw[raw.index('[\n'):])
        self.assertIn('--production-v4-pool-keep-replay-resident',command)
        for arguments,platform in [(base+['--serial-gpu','--shared-model'],'linux'),(base+['--serial-gpu'],'win32')]:
            with patch.object(sys,'platform',platform),patch.object(sys,'argv',arguments),patch.object(launcher,'verify') as verify:
                with self.assertRaises(ValueError):launcher.main()
                verify.assert_not_called()

    def test_shared_socket_uses_the_validated_ram_directory(self):
        arguments=['launch.py','pool','--public-ip','127.0.0.1','--proof-gpus','0,1','--replay-gpu','1',
                   '--serial-gpu','--shared-model','--ram-witness-dir','relative-ram','--check']
        with patch.object(sys,'argv',arguments),patch.object(launcher,'verify'),patch.object(launcher,'validate_ram_witness_directory',return_value=Path('/run/private-ram')),patch.dict(os.environ,{},clear=False),contextlib.redirect_stdout(io.StringIO()):
            launcher.main()
            self.assertEqual(os.environ['CMFD_SHARED_REPLAY_SOCKET'],'/run/private-ram/model.sock')

    def test_shared_model_uses_second_gpu_proxy_and_excludes_gpu_witness(self):
        arguments=['launch.py','pool','--public-ip','127.0.0.1','--proof-gpus','0,1',
                   '--replay-gpu','1','--serial-gpu','--shared-model','--check']
        output=io.StringIO()
        with patch.object(sys,'argv',arguments),patch.object(launcher,'verify'),patch.dict(os.environ,{},clear=False),contextlib.redirect_stdout(output):
            launcher.main()
            self.assertEqual(os.environ['CMFD_SHARED_MODEL'],'1')
            self.assertEqual(os.environ['CMFD_WITNESS_PIPELINE'],'1')
            self.assertEqual(os.environ['CMFD_DEVICE_RELATIONS'],'1')
            self.assertEqual(os.environ['CMFD_REPLAY_GPU_IPC'],'0')
            self.assertTrue(os.environ['CMFD_SHARED_REPLAY_SOCKET'].endswith('/pool-scratch/model.sock'))
        raw=output.getvalue();command=json.loads(raw[raw.index('[\n'):])
        self.assertTrue(command[command.index('--production-v4-pool-replay-worker')+1].endswith('/cmfd-resident-replay'))
        with patch.object(sys,'argv',arguments+['--gpu-witness']),patch.object(launcher,'verify') as verify:
            with self.assertRaises(ValueError):launcher.main()
            verify.assert_not_called()
    def test_gpu_witness_command_requires_serial_replay_and_sets_transport(self):
        arguments=['launch.py','pool','--public-ip','127.0.0.1','--proof-gpus','0,1',
                   '--replay-gpu','0','--serial-gpu','--gpu-witness','--check']
        output=io.StringIO()
        with patch.object(sys,'argv',arguments),patch.object(launcher,'verify') as verify,patch.dict(os.environ,{},clear=False),contextlib.redirect_stdout(output):
            launcher.main()
            self.assertEqual(os.environ['CMFD_REPLAY_GPU_IPC'],'1')
            self.assertEqual(os.environ['CMFD_REPLAY_SEALED_EXPORT'],'0')
            self.assertEqual(os.environ['CUDA_MODULE_LOADING'],'LAZY')
            verify.assert_called_once()
        raw=output.getvalue();command=json.loads(raw[raw.index('[\n'):])
        self.assertIn('--production-v4-pool-proof-gpus',command)
        self.assertIn('--production-v4-pool-serial-gpu',command)
        with patch.object(sys,'argv',[x for x in arguments if x!='--serial-gpu']),patch.object(launcher,'verify') as verify:
            with self.assertRaises(ValueError):launcher.main()
            verify.assert_not_called()

    def arguments(self):
        return SimpleNamespace(action='pool',public_ip='127.0.0.1',bind_ip='127.0.0.1',
            pool_port=23445,check=True,share_bits=4,ram_witness_dir=None,work_bank='streamed',
            peer=['127.0.0.1:23444'],replay_gpu=['2','3'],proof_gpu=None,proof_gpus='0,1',
            serial_gpu=False,enable_payouts=False,p2p_bind='127.0.0.1:23444')
    def test_four_card_layout_selects_split_worker_and_preserves_both_replays(self):
        with tempfile.TemporaryDirectory() as work,patch.object(launcher,'ROOT',Path(work)):
            command=launcher.build_command(self.arguments(),Path(work)/'inputs',Path(work)/'data')
        at=command.index('--production-v4-pool-proof-worker')
        self.assertTrue(command[at+1].endswith('/cmfd-direct-multigpu-prover'))
        self.assertEqual(command.count('--production-v4-pool-replay-gpu'),2)
        self.assertIn('--production-v4-pool-proof-gpus',command)
        self.assertNotIn('--production-v4-pool-serial-gpu',command)
    def test_single_card_layout_retains_original_worker(self):
        args=self.arguments();args.proof_gpu='0';args.proof_gpus=None;args.replay_gpu=['0'];args.serial_gpu=True
        with tempfile.TemporaryDirectory() as work,patch.object(launcher,'ROOT',Path(work)):
            command=launcher.build_command(args,Path(work)/'inputs',Path(work)/'data')
        at=command.index('--production-v4-pool-proof-worker')
        self.assertTrue(command[at+1].endswith('/cmfd-direct-prover'))
        self.assertIn('--production-v4-pool-serial-gpu',command)
        self.assertNotIn('--production-v4-pool-proof-gpus',command)

if __name__=='__main__':unittest.main()
