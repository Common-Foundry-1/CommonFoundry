#!/usr/bin/env python3
"""Check a new replay worker against your current one on this GPU.

Both workers replay the same 64 random inputs, one at a time and in batches
of 1 to 64, plus one full (proof-path) replay. Every output is compared
byte for byte (SHA-256 per lane), and the speed of each worker is printed.
Stop the pool first: the check needs the GPU and loads the model once per
worker. It takes about 5 to 15 minutes. Only the Python 3 standard library
is used.

  python3 check-replay.py --bank /path/MODEL-V2.bank \
      --old /path/current/cmfd-v4-replay --new production-v4/cmfd-v4-replay
"""
import argparse
import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

LANE_BYTES = 128 * 4096 * 4          # one final activation
PER_LANE = (384 + 1) * 20            # one coefficient set
SIZES = (1, 2, 3, 4, 8, 16, 32, 64)


class Worker:
    def __init__(self, path, bank):
        self.process = subprocess.Popen(
            [path, "--server", bank], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.banner = self.wait("CMFD_V4_REPLAY_READY")

    def wait(self, marker):
        lines = []
        for line in self.process.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            if line == marker:
                return lines
        sys.exit("worker stopped:\n" + "\n".join(lines[-15:]))

    def run(self, fields):
        started = time.time()
        self.process.stdin.write("\t".join(fields) + "\n")
        self.process.stdin.flush()
        self.wait("CMFD_V4_REPLAY_DONE")
        return time.time() - started

    def close(self):
        self.process.stdin.write("QUIT\n")
        self.process.stdin.flush()
        self.process.wait(timeout=60)


def lane_hashes(path, count):
    with open(path, "rb") as handle:
        data = handle.read()
    if len(data) != count * LANE_BYTES:
        sys.exit(f"{path} has {len(data)} bytes, expected {count * LANE_BYTES}")
    return [hashlib.sha256(data[i * LANE_BYTES:(i + 1) * LANE_BYTES]).hexdigest()
            for i in range(count)]


def check(label, path, bank, lanes, scratch):
    worker = Worker(path, bank)
    for line in worker.banner:
        if line.startswith(("device=", "gemm_backend", "fused_self_check")):
            print(f"  {label}: {line}", flush=True)
    result = {"single": [], "batch": {}, "speed": {}}
    coefficients = os.path.join(scratch, "c.bin")
    prefix = os.path.join(scratch, "o")
    seconds = 0.0
    for lane in lanes[:8]:
        with open(coefficients, "wb") as handle:
            handle.write(lane)
        seconds += worker.run(["RUN", "search", coefficients, prefix])
        result["single"] += lane_hashes(prefix + "-final-activation.bin", 1)
    result["speed"]["one at a time"] = 8 / seconds
    for size in SIZES:
        hashes, seconds = [], 0.0
        for start in range(0, len(lanes), size):
            chunk = lanes[start:start + size]
            with open(coefficients, "wb") as handle:
                handle.write(b"".join(chunk))
            seconds += worker.run(["RUNBATCH", str(len(chunk)), coefficients, prefix])
            hashes += lane_hashes(prefix + "-final-activation.bin", len(chunk))
        result["batch"][size] = hashes
        result["speed"][f"batch {size}"] = len(lanes) / seconds
    with open(coefficients, "wb") as handle:
        handle.write(lanes[0])
    worker.run(["RUN", "full", coefficients, prefix])
    full = {}
    for name in sorted(os.listdir(scratch)):
        if name.startswith("o-"):
            digest = hashlib.sha256()
            with open(os.path.join(scratch, name), "rb") as handle:
                for block in iter(lambda: handle.read(1 << 24), b""):
                    digest.update(block)
            full[name] = digest.hexdigest()
    result["full"] = full
    worker.close()
    for name in os.listdir(scratch):
        os.remove(os.path.join(scratch, name))
    for name, value in result["speed"].items():
        print(f"  {label}: {name:14} {value:6.2f} replays/s", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bank", required=True, help="MODEL-V2.bank")
    parser.add_argument("--old", required=True, help="the replay worker you run now")
    parser.add_argument("--new", required=True, help="the replay worker from this kit")
    parser.add_argument("--scratch", help="empty work folder (default: a new temp folder)")
    args = parser.parse_args()
    scratch = args.scratch or tempfile.mkdtemp(prefix="cmfd-check-replay-")
    os.makedirs(scratch, exist_ok=True)
    rng = random.Random(20261008)
    lanes = [bytes(rng.getrandbits(8) for _ in range(PER_LANE)) for _ in range(64)]
    print("old worker", flush=True)
    old = check("old", args.old, args.bank, lanes, scratch)
    print("new worker", flush=True)
    new = check("new", args.new, args.bank, lanes, scratch)
    if not args.scratch:
        shutil.rmtree(scratch, ignore_errors=True)
    reference = old["batch"][1]
    problems = []
    if old["single"] != reference[:8] or new["single"] != reference[:8]:
        problems.append("one at a time")
    for size in SIZES:
        if old["batch"][size] != reference or new["batch"][size] != reference:
            problems.append(f"batch {size}")
    if new["full"] != old["full"]:
        problems.append("full replay")
    if problems:
        print("RESULT: DIFFERENT on " + ", ".join(problems) + " - do not use the new worker; please send us this output")
        sys.exit(1)
    print("RESULT: IDENTICAL - one at a time, every batch size and the full replay match byte for byte")


if __name__ == "__main__":
    main()
