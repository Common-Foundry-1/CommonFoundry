#!/usr/bin/env python3
"""Route pool proof requests by their frozen block height, including reorgs."""
import ctypes
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time

NETWORK = '88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62'
HEIGHT = 67535
READY = 'CMFD_V4_PROOF_READY'
DONE = 'CMFD_V4_PROOF_DONE'


def proof_mode(template, network=NETWORK):
    if template.get('format_version') != 1:
        raise ValueError('unsupported frozen template')
    challenge = template.get('challenge', {})
    if challenge.get('network_id') != list(bytes.fromhex(network)):
        raise ValueError('frozen template belongs to another network')
    height = challenge.get('height')
    if type(height) is not int or not 1 <= height <= (1 << 64) - 1:
        raise ValueError('invalid frozen block height')
    return 'legacy' if height < HEIGHT else 'compact'


class Worker:
    def __init__(self, mode, arguments, root):
        self.mode = mode
        environment = dict(os.environ)
        compact_program = 'cmfd-direct-multigpu-prover' if environment.get('CMFD_DIRECT_MULTI_GPU_DEVICES') else 'cmfd-direct-multigpu-worker'
        program = root / ('real_bank0_relations' if mode == 'legacy' else compact_program)
        if mode == 'compact':
            environment.setdefault('CMFD_DEVICE_RELATIONS', '1')
        if mode == 'legacy' and environment.get('CMFD_DIRECT_MULTI_GPU_DEVICES'):
            # Legacy proof workers use one device. The compact coordinator
            # separately resolves both UUIDs and isolates its CUDA children.
            environment['CUDA_VISIBLE_DEVICES'] = environment['CMFD_DIRECT_MULTI_GPU_DEVICES'].split(',')[0]
        self.process = subprocess.Popen([sys.executable, str(root/'fork-prover.py'), '--child-program', str(program), '--server', *arguments],
                                        env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, bufsize=1)
        self.events = queue.Queue()
        def read():
            try:
                for line in self.process.stdout:
                    self.events.put(line.rstrip('\n'))
            finally:
                self.events.put(None)
        self.thread = threading.Thread(target=read, daemon=True)
        self.thread.start()
        try:
            self.until(READY, 600)
        except BaseException:
            self.close()
            raise

    def until(self, marker, budget):
        deadline = time.monotonic() + budget
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('proof worker deadline expired')
            line = self.events.get(timeout=remaining)
            if line is None:
                raise RuntimeError('proof worker ended before ' + marker)
            if line == marker:
                return
            print(line, file=sys.stderr, flush=True)

    def prove(self, request):
        self.process.stdin.write(request + '\n')
        self.process.stdin.flush()
        self.until(DONE, 900)

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write('QUIT\n')
                self.process.stdin.flush()
                self.process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=10)
        self.process.stdin.close()
        self.process.stdout.close()
        self.thread.join(timeout=2)


def main():
    if len(sys.argv) != 5 or sys.argv[1] != '--server' or sys.argv[2] != NETWORK:
        raise ValueError('usage: --server PINNED_MAINNET_NETWORK MODEL ARTIFACTS')
    if os.environ.get('CMFD_SHARED_MODEL') == '1':
        raise ValueError('mainnet fork routing requires standard serial replay/proof handoff')
    root = Path(__file__).resolve().parent
    arguments = sys.argv[2:]
    worker = None
    print(READY, flush=True)
    try:
        for line in sys.stdin:
            line = line.rstrip('\n')
            if line == 'QUIT':
                break
            fields = line.split('\t')
            if len(fields) != 5 or fields[0] != 'RUN':
                raise ValueError('invalid pool proof request')
            template = Path(fields[1])
            if not template.is_absolute() or template.stat().st_size > 128 * 1024 * 1024:
                raise ValueError('invalid frozen template path or size')
            mode = proof_mode(json.loads(template.read_bytes()))
            if worker is None or worker.mode != mode:
                if worker is not None:
                    worker.close()
                worker = Worker(mode, arguments, root)
            worker.prove(line)
            print(DONE, flush=True)
    finally:
        if worker is not None:
            worker.close()


if __name__ == '__main__':
    if len(sys.argv)>2 and sys.argv[1]=='--child-program':
        # A persistent-worker timeout kills the router. Its CUDA child must
        # then exit too, before a retry can allocate another model/prover.
        parent=os.getppid()
        if parent<=1 or ctypes.CDLL(None).prctl(1,signal.SIGKILL,0,0,0)!=0:
            raise RuntimeError('cannot install proof child parent-death guard')
        if os.getppid()!=parent:
            raise RuntimeError('proof router exited during child startup')
        os.execv(sys.argv[2],sys.argv[2:])
    def terminate(signum, frame):
        raise InterruptedError('fork proof router interrupted')
    signal.signal(signal.SIGTERM, terminate)
    main()
