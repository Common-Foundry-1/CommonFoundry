#!/usr/bin/env python3
"""Coordinate two isolated GPUs producing one consensus-v2 compact proof.

The normal pool RUN/READY/DONE protocol is retained. Each RUN owns two short-
lived CUDA workers; both have exited before DONE allows model reload. No mining
process, clock, power setting or service is managed by this program.
"""
import contextlib
import ctypes
import fcntl
import json
import os
from pathlib import Path
import queue
import re
import signal
import secrets
import subprocess
import sys
import tempfile
import threading
import time

CAP = (15 << 29) if os.environ.get('CMFD_SHARED_MODEL')=='1' else (29 << 28)
TRACE_BYTES = 512 << 20
MAX_LINE = 1 << 20
REQUIRED_SEALS = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_GROW |
                  fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_WRITE)


def resolve_devices(selectors, inventory):
    """Resolve aliases before accepting the two-device invariant."""
    parts = selectors.split(',')
    if len(parts) != 2 or any(x != x.strip() or not x for x in parts):
        raise ValueError('select exactly two GPUs, for example 0,1')
    result = []
    for part in parts:
        matches = [uuid for index, uuid in inventory
                   if part == str(index) or part == uuid]
        if len(matches) != 1:
            raise ValueError('GPU selector must be a full UUID or inventory index')
        result.append(matches[0])
    if result[0] == result[1]:
        raise ValueError('the two GPU selectors resolve to the same physical GPU')
    return result


def devices():
    output = subprocess.check_output([
        'nvidia-smi', '--query-gpu=index,uuid', '--format=csv,noheader,nounits'],
        text=True, timeout=10)
    inventory = [(int(a.strip()), b.strip()) for a, b in
                 (line.split(',', 1) for line in output.splitlines())]
    return resolve_devices(os.environ['CMFD_DIRECT_MULTI_GPU_DEVICES'], inventory)


def freeze(path, size):
    """One immutable inode shared by both stages, never independent snapshots."""
    source = os.open(path, os.O_RDONLY)
    try:
        if os.fstat(source).st_size != size:
            raise ValueError('wrong replay trace length')
        try:
            seals = fcntl.fcntl(source, fcntl.F_GET_SEALS)
        except OSError:
            seals = 0
        if seals & REQUIRED_SEALS == REQUIRED_SEALS:
            return os.dup(source)
        fd = os.memfd_create('cmfd-multi-gpu-witness', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            remaining = size
            while remaining:
                data = os.read(source, min(4 << 20, remaining))
                if not data:
                    raise ValueError('replay trace shrank during snapshot')
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                remaining -= len(data)
            if os.read(source, 1) or os.fstat(source).st_size != size:
                raise ValueError('replay trace grew during snapshot')
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, REQUIRED_SEALS)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(source)


class Worker:
    def __init__(self, executable, role, gpu, args, scratch, cache=None):
        self.role = role
        log_dir=Path(os.environ.get('CMFD_MULTI_GPU_LOG_DIR',str(scratch)))
        log_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.log = open(log_dir / (role + '.log'), 'w')
        self.events = queue.Queue()
        env = dict(os.environ, CUDA_VISIBLE_DEVICES=gpu, CMFD_MULTI_GPU_STAGE=role,
                   CUDA_MODULE_LOADING='LAZY',
                   CMFD_V4_PROOF_PRELOAD='0', CMFD_V4_PROOF_PINNED_TRACES='0',
                   RAYON_NUM_THREADS=os.environ.get('CMFD_MULTI_GPU_CPU_THREADS', '2'))
        if cache is not None:
            env['CMFD_MULTI_SHARED_FIXED']=json.dumps(cache,separators=(',',':'))
        if role in ('fixed','dynamic'):
            env.setdefault('CMFD_FIXED_ROW_IO','pread')
            env.setdefault('CMFD_FIXED_IO_WORKERS','16')
        if role=='fixed':
            env['CMFD_TRIM_COMPONENT_POOL']='1'
            if os.environ.get('CMFD_MULTI_GPU_LOG_DIR'):
                env['CMFD_COMPONENT_MEMORY_TRACE']='1'
        self.process = subprocess.Popen([executable, '--multi-worker', role, *args],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.log, text=True, bufsize=1, env=env)
        def read():
            try:
                while True:
                    line = self.process.stdout.readline(MAX_LINE + 1)
                    if not line:
                        break
                    if len(line) > MAX_LINE or not line.endswith('\n'):
                        raise ValueError('oversized worker event')
                    self.events.put(json.loads(line))
            except BaseException as error:
                self.events.put(error)
            finally:
                self.events.put(RuntimeError(role + ' worker closed its pipe'))
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()

    def send(self, value):
        line = json.dumps(value, separators=(',', ':')) + '\n'
        if len(line) > MAX_LINE:
            raise ValueError('oversized command')
        self.process.stdin.write(line)
        self.process.stdin.flush()

    def receive(self, expected, deadline, monitor):
        while True:
            monitor.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('multi-GPU proof deadline expired')
            try:
                value = self.events.get(timeout=min(.1, remaining))
            except queue.Empty:
                continue
            if isinstance(value, BaseException):
                raise value
            if value.get('event') not in expected:
                raise ValueError('unexpected worker event: ' + str(value.get('event')))
            return value

    def close(self):
        if self.process.poll() is None:
            with contextlib.suppress(Exception):
                self.send({'op': 'quit'})
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.process.stdin.close()
        self.process.stdout.close()
        self.reader.join(timeout=1)
        self.log.close()


class Monitor:
    """NVML total-device peaks include context and all transient allocations."""
    class Memory(ctypes.Structure):
        _fields_ = [('total', ctypes.c_ulonglong), ('free', ctypes.c_ulonglong),
                    ('used', ctypes.c_ulonglong)]

    def __init__(self, uuids):
        self.nvml = ctypes.CDLL('libnvidia-ml.so.1')
        if self.nvml.nvmlInit_v2() != 0:
            raise RuntimeError('NVML initialization failed')
        self.handles = []
        for uuid in uuids:
            handle = ctypes.c_void_p()
            if self.nvml.nvmlDeviceGetHandleByUUID(uuid.encode(), ctypes.byref(handle)):
                raise RuntimeError('NVML GPU lookup failed')
            self.handles.append(handle)
        self.peak = [0 for _ in uuids]
        self.error = None
        self.stop = threading.Event()
        def sample():
            while not self.stop.is_set():
                for i, handle in enumerate(self.handles):
                    memory = self.Memory()
                    if self.nvml.nvmlDeviceGetMemoryInfo(handle, ctypes.byref(memory)):
                        self.error = RuntimeError('NVML sampling failed')
                        return
                    self.peak[i] = max(self.peak[i], memory.used)
                    if memory.used > CAP:
                        self.error = RuntimeError(f'GPU exceeded {CAP/(1<<30):g} GiB total-device ceiling')
                        return
                # Host RAM is shared and small on two-card rigs. Abort before OOM.
                available = next(int(line.split()[1]) << 10 for line in
                                 Path('/proc/meminfo').read_text().splitlines()
                                 if line.startswith('MemAvailable:'))
                if available < (1 << 30):
                    self.error = RuntimeError('less than 1 GiB host RAM reserve')
                    return
                self.stop.wait(.01)
        self.thread = threading.Thread(target=sample, daemon=True)
        self.thread.start()

    def check(self):
        if self.error:
            raise self.error

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.nvml.nvmlShutdown()


def prove(executable, args, selected, template, prefix, final, output):
    start = time.monotonic()
    deadline = start + min(600, int(os.environ.get('CMFD_MULTI_GPU_MAX_SECONDS', '600')))
    workers = []
    fds = []
    monitor = None
    # Disk stores only small control artifacts; trace/codeword transport is RAM.
    with tempfile.TemporaryDirectory(prefix='cmfd-multi-gpu-') as work:
        scratch = Path(work)
        try:
            for bank in range(3):
                fd = freeze(f'{prefix}-bank{bank}-dynamic.bin', TRACE_BYTES)
                fds.append(fd)
                (scratch / f'witness-bank{bank}-dynamic.bin').symlink_to(
                    f'/proc/{os.getpid()}/fd/{fd}')
            # Bound and freeze the small public statement files for both stages.
            for name, source, limit in [('template.json', template, 65536),
                                        ('final.bin', final, 2 << 20)]:
                with open(source, 'rb') as file:
                    data = file.read(limit + 1)
                if len(data) > limit:
                    raise ValueError('oversized public input')
                (scratch / name).write_bytes(data)
            job = dict(template=str(scratch / 'template.json'),
                       prefix=str(scratch / 'witness'),
                       final_path=str(scratch / 'final.bin'),
                       bundle=str(scratch / 'bundle.bin'), output=str(output))
            monitor = Monitor(selected)
            b = Worker(executable, 'pcs', selected[1], args, scratch)
            workers.append(b)
            b.receive({'ready'}, deadline, monitor)
            b.send(dict(job, op='prepare'))
            committed = b.receive({'prepared'}, deadline, monitor)
            a = Worker(executable, 'relations', selected[0], args, scratch)
            workers.append(a)
            a.receive({'ready'}, deadline, monitor)
            a.send(dict(job, op='relations', roots=committed['roots']))
            related = a.receive({'relations_done'}, deadline, monitor)
            b.send(dict(job, op='finish'))
            request = b.receive({'rlc_request'}, deadline, monitor)
            a.send(dict(job, op='rlc', coefficients=request['coefficients']))
            combined = a.receive({'rlc_done'}, deadline, monitor)
            b.send(dict(op='rlc_result', path=combined['path']))
            done = b.receive({'done'}, deadline, monitor)
            monitor.check()
            report = dict(done['report'], gpu_uuids=selected,
                          peak_total_device_bytes=monitor.peak,
                          commit_seconds=committed['seconds'],
                          relations_and_reductions_seconds=related['seconds'],
                          final_rlc_seconds=combined['seconds'],
                          total_with_startup_seconds=time.monotonic() - start)
            Path(str(output) + '.multigpu.json').write_text(json.dumps(report, indent=2) + '\n')
            return report
        except BaseException as error:
            failure={'complete':False,'error':str(error),'gpu_uuids':selected,
                     'elapsed_seconds':time.monotonic()-start,
                     'peak_total_device_bytes':monitor.peak if monitor else None}
            Path(str(output)+'.multigpu-failed.json').write_text(json.dumps(failure,indent=2)+'\n')
            raise
        finally:
            # No DONE on a failed job. Close both CUDA processes on every exit.
            for worker in reversed(workers):
                with contextlib.suppress(Exception):
                    worker.close()
            still_running = [worker.role for worker in workers if worker.process.poll() is None]
            if monitor:
                monitor.close()
            for fd in fds:
                os.close(fd)
            if os.environ.get('CMFD_MULTI_GPU_LOG_DIR'):
                destination = Path(os.environ['CMFD_MULTI_GPU_LOG_DIR'])
                destination.mkdir(parents=True, exist_ok=True)
                for path in scratch.glob('*.log'):
                    (destination / path.name).write_bytes(path.read_bytes())
            if still_running:
                raise RuntimeError('GPU workers did not exit: ' + ','.join(still_running))


class ResidentSession:
    """Keep immutable weights on GPU B; only GPU A is leased to replay."""
    def __init__(self, executable, args, selected):
        self.executable=executable;self.args=args;self.selected=selected
        parent=None
        if os.environ.get('CMFD_SHARED_MODEL')=='1':
            from shared_model import private_parent
            endpoint=Path(os.environ['CMFD_SHARED_REPLAY_SOCKET']);private_parent(endpoint);parent=endpoint.parent
        self.scratch=tempfile.TemporaryDirectory(prefix='cmfd-resident-fixed-',dir=parent)
        self.fixed=None;self.dynamic=None;self.jobs=0;self.capture=None
        self.lock=threading.RLock()
        start=time.monotonic();monitor=Monitor([selected[1]])
        try:
            self.fixed=Worker(executable,'fixed',selected[1],args,Path(self.scratch.name))
            ready=self.fixed.receive({'ready'},start+600,monitor)
            self.cache=ready['cache']
            if os.environ.get('CMFD_SHARED_MODEL')=='1' and ready.get('shared_model') is not True:
                raise ValueError('worker does not provide resident model replay')
            if (ready['role']!='fixed' or ready['network_id']!=args[0] or ready['proof_version']!=2
                or ready['proof_system_digest']!='e8d7ed68504e5ff76548a74beff735b22c3bb442cddf9b7dd119e943a58e3dc7'
                or self.cache['pid']!=self.fixed.process.pid):
                raise ValueError('fixed worker/cache identity differs')
            self.startup_peak=monitor.peak[0]
            self.startup_seconds=time.monotonic()-start
            monitor.check()
            if os.environ.get('CMFD_SHARED_MODEL')=='1':
                self.dynamic=Worker(executable,'dynamic',selected[0],args,Path(self.scratch.name),cache=self.cache)
                self.dynamic.receive({'ready'},start+600,monitor)
        except BaseException:
            self.close();raise
        finally:
            monitor.close()

    def close(self):
        if self.dynamic is not None:self.dynamic.close();self.dynamic=None
        if self.fixed is not None:
            self.fixed.close()
            if self.fixed.process.poll() is None:
                raise RuntimeError('fixed GPU worker did not exit')
        self.scratch.cleanup()

    def replay(self,value):
        if os.environ.get('CMFD_SHARED_MODEL')!='1':raise ValueError('resident replay is not enabled')
        operation=value.get('op')
        if operation not in ('trim','replay'):raise ValueError('unsupported replay request')
        command={'op':'replay_trim' if operation=='trim' else 'replay','id':0}
        if operation=='replay':
            mode=value['mode']
            if mode not in ('search','full','batch','digest'):raise ValueError('invalid replay mode')
            prefix=Path(value['prefix']);parent=prefix.parent
            if not prefix.is_absolute() or '..' in prefix.parts or parent.is_symlink():raise ValueError('private absolute replay path required')
            info=parent.stat()
            if info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('replay directory is not private')
            command.update(replay_mode=mode,replay_coefficients=str(value['coefficients']),prefix=str(prefix),
                           replay_batch_size=value.get('batch_size',0),replay_challenges=value.get('challenges',''))
        with self.lock:
            start=time.monotonic()
            pipeline=operation=='replay' and os.environ.get('CMFD_WITNESS_PIPELINE')=='1'
            capture_mode=pipeline and value['mode']=='full'
            monitor=Monitor(self.selected if capture_mode else [self.selected[1]])
            prefetch_started=False
            try:
                if operation=='replay' and self.capture is not None:
                    self.dynamic.send({'op':'discard_capture'});self.dynamic.receive({'discarded'},start+600,monitor);self.capture=None
                if capture_mode:
                    if self.dynamic is None or self.dynamic.process.poll() is not None:
                        if self.dynamic is not None:self.dynamic.close()
                        self.dynamic=Worker(self.executable,'dynamic',self.selected[0],self.args,Path(self.scratch.name),cache=self.cache)
                        self.dynamic.receive({'ready'},start+600,monitor)
                    capture_id=secrets.token_hex(16)
                    self.dynamic.send(dict(op='prefetch',prefix=command['prefix'],replay_coefficients=command['replay_coefficients'],provider_pid=self.fixed.process.pid,capture_id=capture_id))
                    prefetch_started=True
                self.fixed.send(command);reply=self.fixed.receive({'fixed_done'},start+600,monitor)
                if reply.get('id')!=0:raise ValueError('replay response identity differs')
                if capture_mode:
                    captured=self.dynamic.receive({'captured'},start+600,monitor)
                    if captured.get('capture_id')!=capture_id:raise ValueError('stream capture response differs')
                    self.capture=dict(id=capture_id,prefix=str(Path(command['prefix']).parent.resolve(strict=True)/Path(command['prefix']).name),stats=captured['stats'])
                monitor.check()
                return dict(ok=True,seconds=time.monotonic()-start,model_reload_bytes=0,peak_total_device_bytes=monitor.peak,
                            stream_capture=self.capture['stats'] if capture_mode else None)
            except BaseException:
                if prefetch_started:
                    self.capture=None
                    if self.dynamic is not None:self.dynamic.close();self.dynamic=None
                raise
            finally:monitor.close()

    def prove(self, template, prefix, final, output):
        with self.lock:
            if os.environ.get('CMFD_SHARED_MODEL')=='1':self.replay({'op':'trim'})
            return self._prove(template,prefix,final,output)

    def _prove(self, template, prefix, final, output):
        start=time.monotonic();deadline=start+min(600,int(os.environ.get('CMFD_MULTI_GPU_MAX_SECONDS','600')))
        self.jobs+=1;fds=[];worker=None;monitor=None;rpc_count=0;vector_bytes=0
        with tempfile.TemporaryDirectory(prefix='cmfd-resident-job-',dir=self.scratch.name if self.dynamic is not None else None) as work:
            scratch=Path(work)
            try:
                capture_id=''
                pipelined=os.environ.get('CMFD_WITNESS_PIPELINE')=='1'
                if pipelined:
                    source=Path(prefix);source=str(source.parent.resolve(strict=True)/source.name)
                    if self.capture is None or self.capture['prefix']!=source:raise ValueError('proof has no matching prefetched witness')
                    capture_id=self.capture['id']
                gpu_descriptor=Path(str(prefix)+'-gpu-witness.json')
                if pipelined:pass
                elif gpu_descriptor.exists():
                    if gpu_descriptor.is_symlink():raise ValueError('GPU witness descriptor is a symlink')
                    with gpu_descriptor.open('rb') as file:data=file.read(65537)
                    if len(data)>65536:raise ValueError('oversized GPU witness descriptor')
                    descriptor=json.loads(data)
                    source_prefix=Path(prefix)
                    if not source_prefix.is_absolute() or '..' in source_prefix.parts:raise ValueError('GPU witness prefix must be absolute')
                    descriptor['source_prefix']=str(source_prefix.parent.resolve(strict=True)/source_prefix.name)
                    (scratch/'witness-gpu-witness.json').write_text(json.dumps(descriptor))
                else:
                    host=Path(str(prefix)+'-host-pre-only.json')
                    if host.exists():
                        with host.open('rb') as file:data=file.read(65537)
                        if len(data)>65536:raise ValueError('oversized preactivation descriptor')
                        descriptor=json.loads(data)
                        if descriptor.get('schema')!='CMFD_HOST_PRE_ONLY_V1':raise ValueError('preactivation descriptor schema')
                        (scratch/'witness-host-pre-only.json').write_text(json.dumps(descriptor))
                    for bank in range(3):
                        suffix='pre' if host.exists() else 'dynamic';size=TRACE_BYTES//2 if host.exists() else TRACE_BYTES
                        fd=freeze(f'{prefix}-bank{bank}-{suffix}.bin',size);fds.append(fd)
                        (scratch/f'witness-bank{bank}-{suffix}.bin').symlink_to(f'/proc/{os.getpid()}/fd/{fd}')
                for name,source,limit in [('template.json',template,65536),('final.bin',final,2<<20)]:
                    with open(source,'rb') as file:data=file.read(limit+1)
                    if len(data)>limit:raise ValueError('oversized resident public input')
                    (scratch/name).write_bytes(data)
                monitor=Monitor(self.selected)
                persistent=self.dynamic is not None
                worker=self.dynamic if persistent else Worker(self.executable,'dynamic',self.selected[0],self.args,scratch,cache=self.cache)
                if not persistent:worker.receive({'ready'},deadline,monitor)
                worker.send(dict(op='prove',template=str(scratch/'template.json'),prefix=str(scratch/'witness'),final_path=str(scratch/'final.bin'),output=str(output),capture_id=capture_id))
                expected_id=1
                while True:
                    message=worker.receive({'fixed_request','done'},deadline,monitor)
                    if message['event']=='done':
                        if not persistent:
                            worker.close()
                            if worker.process.poll() is None:raise RuntimeError('dynamic GPU was not released')
                        self.fixed.send({'op':'reset'})
                        self.fixed.receive({'reset'},deadline,monitor)
                        monitor.check()
                        report=dict(message['report'],gpu_uuids=self.selected,
                            peak_total_device_bytes=monitor.peak,fixed_startup_peak_bytes=self.startup_peak,
                            session_startup_seconds=self.startup_seconds,
                            winning_proof_seconds=time.monotonic()-start,
                            fixed_rpc_count=rpc_count,fixed_vector_bytes=vector_bytes,
                            fixed_weights_reused=self.jobs>1,dynamic_process_exited=not persistent,
                            dynamic_worker_pid=worker.process.pid,dynamic_worker_reused=persistent and self.jobs>1,
                            fixed_worker_pid=self.fixed.process.pid)
                        report['witness_pipeline']=pipelined
                        Path(str(output)+'.multigpu.json').write_text(json.dumps(report,indent=2)+'\n')
                        return report
                    if message.get('id')!=expected_id or message.get('op') not in {'weights','evaluate','begin','step','combined'}:
                        raise ValueError('invalid resident fixed request order or operation')
                    self.fixed.send(message)
                    reply=self.fixed.receive({'fixed_done'},deadline,monitor)
                    if reply['id']!=expected_id:raise ValueError('fixed response identity differs')
                    expected_id+=1;rpc_count+=1;vector_bytes+=reply.get('elements',0)*16
                    reply['op']='fixed_response';worker.send(reply)
            except BaseException as error:
                failure=dict(complete=False,error=str(error),elapsed_seconds=time.monotonic()-start,
                             peak_total_device_bytes=monitor.peak if monitor else None,fixed_rpc_count=rpc_count)
                Path(str(output)+'.multigpu-failed.json').write_text(json.dumps(failure,indent=2)+'\n')
                if os.environ.get('CMFD_WITNESS_PIPELINE')=='1' and self.dynamic is not None:
                    failed=self.dynamic;self.dynamic=None;failed.close()
                    if worker is failed:worker=None
                raise
            finally:
                if os.environ.get('CMFD_WITNESS_PIPELINE')=='1':self.capture=None
                if worker is not None:
                    if worker is not self.dynamic:worker.close()
                    if os.environ.get('CMFD_MULTI_GPU_LOG_DIR'):
                        log=Path(worker.log.name)
                        if log.exists():
                            log.with_name(f'dynamic-{self.jobs}.log').write_bytes(log.read_bytes())
                if monitor:monitor.close()
                for fd in fds:os.close(fd)


def main():
    executable = str(Path(os.environ['CMFD_DIRECT_MULTI_GPU_WORKER']).resolve(strict=True))
    args = sys.argv[1:]
    if args == ['network-info']:
        return subprocess.call([executable, 'network-info'])
    if len(args) != 4 or args[0] != '--server':
        raise ValueError('usage: --server NETWORK MODEL ARTIFACTS')
    # The running fixed worker confirms its compiled chain/proof identity
    # before READY. Avoid a redundant CUDA-linked identity subprocess here.
    selected = devices()
    session=ResidentSession(executable,args[1:],selected)
    replay_server=None
    try:
        if os.environ.get('CMFD_SHARED_MODEL')=='1':
            from shared_model import Server
            replay_server=Server(os.environ['CMFD_SHARED_REPLAY_SOCKET'],session,args[2])
        print('CMFD_V4_PROOF_READY', flush=True)
        for line in sys.stdin:
            line=line.rstrip('\n')
            if line=='QUIT':break
            parts=line.split('\t')
            if len(parts)!=5 or parts[0]!='RUN':raise ValueError('invalid pool RUN command')
            report=session.prove(*parts[1:])
            print('CMFD_MULTI_GPU_REPORT '+json.dumps(report),file=sys.stderr,flush=True)
            print('CMFD_V4_PROOF_DONE',flush=True)
    finally:
        if replay_server is not None:replay_server.close()
        session.close()


if __name__ == '__main__':
    def terminate(signum, frame):
        raise InterruptedError('coordinator interrupted')
    signal.signal(signal.SIGTERM, terminate)
    main()
