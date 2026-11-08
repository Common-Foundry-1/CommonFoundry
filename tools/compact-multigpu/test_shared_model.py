import importlib.util,os,socket,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('shared_model',Path(__file__).with_name('shared_model.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class SharedModelTests(unittest.TestCase):
    def test_stale_socket_is_recovered_and_live_owner_is_preserved(self):
        class Session:
            def replay(self,value):return {'ok':True}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);model=root/'model';model.write_bytes(b'model')
            with socket.socket(socket.AF_UNIX) as stale:stale.bind(str(root/'rpc'))
            (root/'rpc').chmod(0o600)
            server=m.Server(root/'rpc',Session(),model)
            try:
                with self.assertRaises(BlockingIOError):m.Server(root/'rpc',Session(),model)
                self.assertTrue(m.request(root/'rpc',{'op':'ping','model':str(model)})['ok'])
            finally:server.close()
    def test_private_rpc_checks_model_and_returns_worker_errors(self):
        class Session:
            def replay(self,value):
                if value['op']=='bad':raise ValueError('invalid replay')
                return {'ok':True,'model_reload_bytes':0}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);model=root/'model';model.write_bytes(b'model')
            server=m.Server(root/'rpc',Session(),model)
            try:
                self.assertTrue(m.request(root/'rpc',{'op':'ping','model':str(model)})['resident'])
                self.assertEqual(m.request(root/'rpc',{'op':'trim'})['model_reload_bytes'],0)
                with self.assertRaisesRegex(RuntimeError,'invalid replay'):m.request(root/'rpc',{'op':'bad'})
                other=root/'other';other.write_bytes(b'other')
                with self.assertRaisesRegex(RuntimeError,'differs'):m.request(root/'rpc',{'op':'ping','model':str(other)})
            finally:server.close()
            self.assertFalse((root/'rpc').exists())
    def test_world_readable_directory_and_other_owner_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755)
            with self.assertRaises(PermissionError):m.private_parent(root/'rpc')
            root.chmod(0o700)
        class Connection:
            def getsockopt(self,*args):return struct.pack('3i',123,os.geteuid()+1,0)
        with self.assertRaises(PermissionError):m.peer(Connection())
if __name__=='__main__':unittest.main()
