import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('fork_router',ROOT/'packaging/compact-proof-mainnet/fork-prover.py')
router=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(router)

def template(height):
    return {'format_version':1,'challenge':{'network_id':list(bytes.fromhex(router.NETWORK)),'height':height}}

class MainnetForkRouterTests(unittest.TestCase):
    def test_frozen_height_selects_both_proof_versions_including_rollback(self):
        self.assertEqual(router.proof_mode(template(65535)),'legacy')
        self.assertEqual([router.proof_mode(template(h)) for h in [67534,67535,67536,67534]],['legacy','compact','compact','legacy'])

    def test_unknown_network_or_height_is_rejected(self):
        for h in [0,-1,True,'67535',1<<64]:
            with self.subTest(height=h),self.assertRaises(ValueError):router.proof_mode(template(h))
        value=template(67535);value['challenge']['network_id'][0]^=1
        with self.assertRaises(ValueError):router.proof_mode(value)

    def test_worker_switching_follows_frozen_jobs_and_preserves_wire_requests(self):
        events=[]
        class Worker:
            def __init__(self,mode,args,root):self.mode=mode;events.append(('start',mode))
            def prove(self,request):events.append(('prove',self.mode,request))
            def close(self):events.append(('close',self.mode))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'template.json'
            def requests():
                for height in [67534,67535,67536,67534]:
                    path.write_text(json.dumps(template(height)))
                    yield f'RUN\t{path}\tprefix\tfinal\tproof\n'
                yield 'QUIT\n'
            with mock.patch.object(router,'Worker',Worker),mock.patch.object(sys,'argv',['fork-prover','--server',router.NETWORK,'model','fixed']),mock.patch.object(sys,'stdin',requests()),mock.patch.object(sys,'stdout',io.StringIO()),mock.patch.dict(router.os.environ,{'CMFD_SHARED_MODEL':'0'}):router.main()
        self.assertEqual([e[1] for e in events if e[0]=='start'],['legacy','compact','legacy'])
        self.assertEqual([e[1] for e in events if e[0]=='prove'],['legacy','compact','compact','legacy'])
        self.assertEqual(len([e for e in events if e[0]=='close']),3)
        self.assertTrue(all(e[2].startswith('RUN\t') for e in events if e[0]=='prove'))

if __name__=='__main__':unittest.main()
