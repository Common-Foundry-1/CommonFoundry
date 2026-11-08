import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import fcntl
import io
import json
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('coordinator', Path(__file__).with_name('coordinator.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CoordinatorTests(unittest.TestCase):
    def test_shared_model_reuses_both_workers_and_sealed_pre_only_transport(self):
        workers=[]
        class Process:
            def __init__(self,pid):self.pid=pid;self.alive=True
            def poll(self):return None if self.alive else 0
        class Worker:
            def __init__(self,executable,role,gpu,args,scratch,cache=None):
                self.role=role;self.process=Process(100+len(workers));self.command=None;workers.append(self)
            def send(self,value):self.command=value
            def receive(self,expected,deadline,monitor):
                if 'ready' in expected:return {'event':'ready','role':self.role,'network_id':'network','proof_version':2,'proof_system_digest':'e8d7ed68504e5ff76548a74beff735b22c3bb442cddf9b7dd119e943a58e3dc7','cache':{'pid':100},'shared_model':True}
                if 'reset' in expected:return {'event':'reset'}
                if self.role=='fixed':return {'event':'fixed_done','id':0}
                prefix=Path(self.command['prefix'])
                assert Path(str(prefix)+'-host-pre-only.json').exists()
                for bank in range(3):assert Path(str(prefix)+f'-bank{bank}-pre.bin').stat().st_size==4
                return {'event':'done','report':{'verified':True,'wire_bytes':1}}
            def close(self):self.process.alive=False
        class Monitor:
            def __init__(self,devices):self.peak=[1]*len(devices)
            def check(self):pass
            def close(self):pass
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'CMFD_SHARED_MODEL':'1'}),patch.object(c,'Worker',Worker),patch.object(c,'Monitor',Monitor),patch.object(c,'TRACE_BYTES',8):
            root=Path(directory)
            os.environ['CMFD_SHARED_REPLAY_SOCKET']=str(root/'model.sock')
            (root/'template').write_bytes(b'{}');(root/'final').write_bytes(b'1234')
            (root/'trace-host-pre-only.json').write_text(json.dumps({'schema':'CMFD_HOST_PRE_ONLY_V1'}))
            for bank in range(3):(root/f'trace-bank{bank}-pre.bin').write_bytes(b'1234')
            session=c.ResidentSession('worker',['network','model','fixed'],['GPU-a','GPU-b'])
            try:
                for index in range(2):
                    report=session.prove(root/'template',root/'trace',root/'final',root/f'output{index}')
                    self.assertFalse(report['dynamic_process_exited'])
                    self.assertEqual(report['dynamic_worker_reused'],index>0)
                    self.assertTrue(all(worker.process.alive for worker in workers))
            finally:session.close()
        self.assertEqual([worker.role for worker in workers],['fixed','dynamic'])
        self.assertTrue(all(not worker.process.alive for worker in workers))

    def test_resident_weights_survive_two_jobs_and_dynamic_gpu_exits_before_reset(self):
        created=[];events=[]
        class Process:
            def __init__(self,pid):self.pid=pid;self.alive=True
            def poll(self):return None if self.alive else 0
        class FakeWorker:
            def __init__(self,executable,role,gpu,args,scratch,cache=None):
                self.role=role;self.process=Process(314 if role=='fixed' else 315+len(created))
                self.step=0;created.append(self)
                descriptor=scratch/'witness-gpu-witness.json'
                if role=='dynamic' and descriptor.exists():
                    self.gpu_source=json.loads(descriptor.read_text())['source_prefix']
            def send(self,command):
                events.append((self.role,command['op']))
                if command['op']=='reset':self.assert_dynamic_dead()
            def assert_dynamic_dead(self):
                assert all(not w.process.alive for w in created if w.role=='dynamic')
            def receive(self,expected,deadline,monitor):
                if 'ready' in expected:
                    return {'event':'ready','role':self.role,'network_id':'network','proof_version':2,
                        'proof_system_digest':'e8d7ed68504e5ff76548a74beff735b22c3bb442cddf9b7dd119e943a58e3dc7',
                        'cache':{'pid':314}}
                if self.role=='fixed':
                    if 'reset' in expected:return {'event':'reset'}
                    return {'event':'fixed_done','id':1,'elements':524288}
                self.step+=1
                if self.step==1:return {'event':'fixed_request','op':'weights','id':1}
                return {'event':'done','report':{'verified':True,'wire_bytes':1}}
            def close(self):self.process.alive=False
        class FakeMonitor:
            def __init__(self,devices):self.peak=[10,20]
            def check(self):pass
            def close(self):pass
        with tempfile.TemporaryDirectory() as work:
            root=Path(work)
            for bank in range(3):(root/f'trace-bank{bank}-dynamic.bin').write_bytes(b'12345678')
            (root/'template').write_bytes(b'{}');(root/'final').write_bytes(b'1234')
            with patch.object(c,'TRACE_BYTES',8),patch.object(c,'Worker',FakeWorker),patch.object(c,'Monitor',FakeMonitor):
                session=c.ResidentSession('worker',['network','model','fixed'],['GPU-a','GPU-b'])
                try:
                    for i in range(2):
                        if i==1:
                            # The GPU transport must not require any host trace files,
                            # and acknowledgement paths come from our own request.
                            for bank in range(3):(root/f'trace-bank{bank}-dynamic.bin').unlink()
                            (root/'trace-gpu-witness.json').write_text(json.dumps({'source_prefix':'/untrusted/path'}))
                        report=session.prove(root/'template',root/'trace',root/'final',root/f'output{i}')
                        self.assertTrue(created[0].process.alive)
                        self.assertTrue(report['dynamic_process_exited'])
                        self.assertEqual(report['fixed_weights_reused'],i==1)
                        self.assertEqual(report['fixed_vector_bytes'],8<<20)
                        if i==1:self.assertEqual(created[-1].gpu_source,str(root/'trace'))
                finally:session.close()
        self.assertEqual([w.role for w in created],['fixed','dynamic','dynamic'])
        self.assertFalse(created[0].process.alive)
    def test_worker_overrides_inherited_cuda_mask_and_eager_loading(self):
        captured={}
        class Process:
            def __init__(self, command, **kwargs):
                captured.update(kwargs['env']);self.stdin=io.StringIO();self.stdout=io.StringIO()
            def poll(self):return 0
        with tempfile.TemporaryDirectory() as work, patch.dict(os.environ,{'CUDA_VISIBLE_DEVICES':'wrong','CUDA_MODULE_LOADING':'EAGER'}),patch.object(c.subprocess,'Popen',Process):
            worker=c.Worker('worker','pcs','GPU-second',['network','model','fixed'],Path(work))
            worker.close()
        self.assertEqual(captured['CUDA_VISIBLE_DEVICES'],'GPU-second')
        self.assertEqual(captured['CUDA_MODULE_LOADING'],'LAZY')
        self.assertEqual(captured['CMFD_MULTI_GPU_STAGE'],'pcs')
    def test_aliases_resolve_before_distinctness_check(self):
        inventory = [(0, 'GPU-first'), (1, 'GPU-second')]
        self.assertEqual(c.resolve_devices('1,0', inventory), ['GPU-second', 'GPU-first'])
        for value in ['0,GPU-first', 'GPU-first,GPU-first', '0', '0,1,2', '0, 1', '0,2']:
            with self.assertRaises(ValueError):
                c.resolve_devices(value, inventory)

    def test_one_snapshot_remains_immutable_for_both_readers(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'trace'
            path.write_bytes(b'original')
            fd = c.freeze(path, 8)
            try:
                path.write_bytes(b'changed!')
                self.assertEqual(os.pread(fd, 8, 0), b'original')
                seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
                self.assertEqual(seals & c.REQUIRED_SEALS, c.REQUIRED_SEALS)
                with self.assertRaises(OSError):
                    os.pwrite(fd, b'x', 0)
                a = c.freeze(f'/proc/self/fd/{fd}', 8)
                try:
                    self.assertEqual(os.fstat(a).st_ino, os.fstat(fd).st_ino)
                finally:
                    os.close(a)
            finally:
                os.close(fd)

    def test_wrong_shape_rejected_before_worker_launch(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'trace'
            path.write_bytes(b'x')
            with self.assertRaises(ValueError):
                c.freeze(path, 8)

    def test_failed_relation_stage_closes_both_workers_and_witnesses(self):
        closed=[]
        class FakeWorker:
            def __init__(self, executable, role, gpu, args, scratch):
                self.role=role
                self.alive=True
                self.process=self
            def poll(self):return None if self.alive else 0
            def send(self, command):pass
            def receive(self, expected, deadline, monitor):
                if 'ready' in expected:return {'event':'ready'}
                if 'prepared' in expected:return {'event':'prepared','roots':[[0]*8]*3,'seconds':1}
                raise RuntimeError('relation stage failed')
            def close(self):self.alive=False;closed.append(self.role)
        class FakeMonitor:
            def __init__(self, devices):self.peak=[0,0]
            def close(self):closed.append('monitor')
        with tempfile.TemporaryDirectory() as work:
            root=Path(work)
            for bank in range(3):(root/f'trace-bank{bank}-dynamic.bin').write_bytes(b'12345678')
            (root/'template').write_bytes(b'{}');(root/'final').write_bytes(b'1234')
            before=len(list(Path('/proc/self/fd').iterdir()))
            with patch.object(c,'TRACE_BYTES',8),patch.object(c,'Worker',FakeWorker),patch.object(c,'Monitor',FakeMonitor):
                with self.assertRaisesRegex(RuntimeError,'relation stage failed'):
                    c.prove('worker',['network','model','fixed'],['GPU-a','GPU-b'],root/'template',root/'trace',root/'final',root/'out')
            self.assertEqual(closed,['relations','pcs','monitor'])
            self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)
            self.assertFalse((root/'out').exists())


if __name__ == '__main__':
    unittest.main()
