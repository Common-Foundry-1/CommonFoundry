# Shared resident-model qualification

The post-proof model reload is removed. Replay and the fixed prover share one
immutable 6 GiB model on GPU B; GPU A handles dynamic proving. Replay decodes
one layer into a 16 MiB scratch allocation instead of loading another full
model. Both workers persist across winners, with per-proof workspace reuse
bounded at 4 GiB and explicitly released after each proof.

Post-proof replay completed in **0.127 and 0.105 seconds**, replacing the
previous **16.774-second model reload** on the same Rig06 x1 risers. A real
loopback pool with a separate GPU miner accepted two consecutive blocks while
keeping a single resident model instance and transferring zero model bytes
after startup.

| Live pool measurement | Block 1 | Block 2 |
| --- | ---: | ---: |
| Pool evaluation | 11.1213 s | 10.6253 s |
| Node admission | 0.9576 s | 0.9403 s |
| Evaluation plus local admission | **12.0789 s** | **11.5656 s** |
| Full replay and witness export | 2.3563 s | 2.3481 s |
| Proof-worker request | 8.4483 s | 7.9932 s |
| Packet | 5,642,096 bytes | 5,677,498 bytes |

This is not yet the five-second full path. The remaining transfer bottleneck is
the 768 MiB witness moving from GPU B through RAM to GPU A. Export and upload
take about **4.7 seconds combined on PCIe Gen2 x1**. The second live native
proof interval was 7.2062 seconds, of which 2.3531 seconds was input upload;
the remaining 4.8530 seconds includes proof computation, encoding and complete
producer CPU verification. That partial interval is not the full mining delay.
Startup, nonce search and WAN propagation are outside the live acceptance
figures above.

Two additional standalone winners passed the complete CPU verifier and fresh
CPU-only nodes. Modified packets were rejected with HTTP 422, leaving each
fresh node at height zero; the honest packets advanced each to height one.
The nodes used in-process proof verification with no work-replay rule.

The complete test peaked at **6.775 GiB on dynamic GPU A and 7.463 GiB on model
GPU B**, under a 7.5 GiB total-device ceiling. The separate test miner peaked
at 6.834 GiB. These were physical 16 GiB RTX 4070 Ti SUPER cards. The measured
envelope screens an 8 GiB headless-device budget; physical 8 GB RTX 3080 mobile
qualification remains a separate canary.

All supplied preactivation words remain validated in kernel-sealed snapshots,
and the descriptor binds them to the requested nonce/template. GPU checks
confirm the captured activations and lifted values before proof construction.
Qualification exposed an upload/compute ordering race: CUDA's default-stream
upload had to complete before the SDK's nonblocking stream derived activations.
The fix synchronizes that handoff; the complete CPU verifier remains mandatory.

The packet, six commitments, log blowup 1, 270 queries and 16 grinding bits are
unchanged. This producer optimization needs no additional consensus fork.
The original fast GPU-witness mode remains available; it has lower individual
proof latency on these risers but reloads the model before the next replay.
The two modes have separate recorded timings rather than a universal speed claim.

Checks passed: 22 prover CPU tests, six GPU differential tests, 29 pool tests
and 15 coordinator/launcher/RPC tests. Batch sizes 2, 32 and 64, batch digests,
and full replay after a large batch matched exactly. Independent replay through
the unchanged reference executable matched both standalone final vectors.
An actual pool startup recovered a deliberately abandoned private socket.
An owner-only lease protects the socket, and worker temporary paths now remain
inside pool scratch.

The main rehearsal's restoration helper hit a process-exit race after the
checks completed. Its independent watchdog restored mining successfully.
The helper now tolerates exited PIDs, and the final restart smoke restored
mining normally. All six Pearl owner GPUs returned to their unchanged command
and configuration, 810 MHz memory locks and 230 W limits, with a fresh accepted
share. Test-created user-state locks were removed or existing state preserved.

The rig payload and RAM scratch were removed: **61,597,281,490 bytes reclaimed**.
Four identified empty worker directories were also removed. Evidence is saved
locally in `target/compact-multigpu-shared-model-20261108/FINAL-EVIDENCE.tar.gz`;
its SHA-256 is
`b1120ffb8bf83c8e9a4a2af16b10c0ae58f97cbec60cd15b4faf674f2b6b9d4c`.
`FINAL-QUALIFICATION.json` records the exact native artifacts, benchmark control
files, later restart improvements, source hashes and test scope. The candidate
is local; published v0.3.0 and mainnet were not changed.

## Operator command

```sh
./START-POOL.sh --public-ip YOUR_POOL_IP \
  --proof-gpus 0,1 --replay-gpu 1 --serial-gpu --shared-model \
  --ram-witness-dir /run/cmfd-witness
```

GPU 0 is the dynamic prover and GPU 1 owns the shared model. Reserve both for
the pool; mining clients connect normally and can use separate GPUs or hosts.
The launcher's witness path must be a private 2 GiB tmpfs mount owned by the
pool user. The benchmark used a private directory on `/dev/shm`; its witness
files stayed below 2 GiB, with host-memory monitoring active throughout.
