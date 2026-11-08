# Pipelined witness transfer qualification

Overlapping witness export and upload reduced Rig06's average full local block
acceptance by **2.683 seconds (22.7%)** in this two-block sample. The candidate
keeps one resident model and both proof workers alive. It transfers immutable
witness chunks while replay is exporting them, instead of waiting for the
entire export, freezing another host copy and uploading it afterward.

| Same Rig06, live local pool | v0.4.0 block 1 | Candidate block 1 | v0.4.0 block 2 | Candidate block 2 |
| --- | ---: | ---: | ---: | ---: |
| Full replay / witness handoff | 2.3563 s | 2.5925 s | 2.3481 s | 2.6162 s |
| Proof-worker request | 8.4483 s | 5.3034 s | 7.9932 s | 5.0677 s |
| Complete pool evaluation | 11.1213 s | 8.3133 s | 10.6253 s | 8.0649 s |
| Node admission | 0.9576 s | 0.9634 s | 0.9403 s | 0.9369 s |
| **Full local acceptance** | **12.0789 s** | **9.2767 s** | **11.5656 s** | **9.0018 s** |
| Proof packet | 5,642,096 B | 5,684,041 B | 5,677,498 B | 5,658,716 B |

These are separate two-block samples on the same physical machine, not a
paired-nonce statistical benchmark. Each candidate block was mined by an
independent GPU client, proved by the pool, and accepted by the CPU node.
Startup, the nonce-search interval and WAN propagation are excluded. The
candidate's one-time worker startup was 45.972 seconds. The complete path
remains above the five-second goal; the roughly five-second proof-worker
interval does not include replay or node admission.

## Transfer and security

GPU B publishes 48 chunks of 16 MiB each: 768 MiB in total. Each chunk is held
in a memfd sealed against writes, resizing and seal changes before publication.
GPU A verifies the provider PID, ownership, exact length and all four seals,
then maps the chunk read-only. CUDA registered all 48 chunks directly on this
host; the bounded 16 MiB pinned fallback was not needed. Host chunks remain
alive until capture completes, so provider trimming cannot race an upload.

A prefetch starts before export and waits for the chunks. After every upload,
an explicit synchronization preserves the default-stream / SDK-stream ordering.
GPU A validates every supplied field word, reconstructs the exact cubed
activations, and checks capture/lift consistency. It retains owned GPU traces.
A single-use capture token and the full 7,700-byte coefficient vector bind those
traces to the subsequent nonce/template. A new replay discards an unused
capture; failure closes the dynamic worker and clears the capture. The next
request can recreate the worker.

The proof format, transcript, six commitments, log blowup 1, 270 queries and
16 grinding bits are unchanged. Complete producer CPU verification and
independent node proof verification remain enabled. This producer-side
optimization adds no consensus change to the compact-proof testnet.

## Correctness and resource results

- 23 native CPU tests and six GPU differential tests passed.
- 16 controller, launcher and replay-RPC tests passed, including capture
  ordering, cancellation, single use, wrong-prefix rejection and recovery.
- Two additional standalone winning proofs passed the full CPU verifier.
  Fresh CPU nodes rejected both corrupted packets with HTTP 422 at height zero,
  then accepted the honest packets with HTTP 200 at height one. They used
  in-process proof verification without a work-replay rule.
- Reference replay matched both final vectors byte for byte. Batches of 2,
  32 and 64, batch digests and full replay after the large batch matched exactly.
- Both workers persisted between winners. The live pool used one resident
  model and reloaded zero model bytes after startup. Post-proof search resumed
  in 0.106 and 0.124 seconds in the standalone tests.
- Peak total device use was **6.775 GiB on A, 7.463 GiB on B** and 6.834 GiB on
  the independent miner. The 7.5 GiB whole-device guard sampled every 10 ms.
  These were physical 16 GiB RTX 4070 Ti SUPER cards on PCIe Gen2 x1 risers;
  a physical 8 GB / RTX 3080 mobile test remains unmeasured.

The standalone profiles place relations/openings at **2.796–2.902 seconds**,
joint BaseFold at 1.081–1.089 seconds, and complete producer CPU verification at
0.547–0.556 seconds. Relations/openings is now the largest measured proof
stage. Initial commitments are only 0.179–0.255 seconds. The next substantial
gain needs to come from those computations or further transfer/compute overlap;
removing verification or lowering proof parameters is outside this approach.

## Restoration, evidence and use

All six owner GPUs returned to the unchanged mining command/configuration,
810 MHz memory locks and 230 W power limits. Fresh accepted shares were
observed after restoration, including accepted share 12 with zero rejects.
Test GPU processes and transient services exited. The private RAM directory
and **61,574,104,042 bytes** of rig scratch were removed after copying and
hash-verifying the evidence locally.

The test service's final cleanup initially rejected its empty `model.sock.lock`
lease because the harness allowlist omitted that filename. This happened after
all proof checks and successful mining restoration. The lease was then checked
for ownership, zero length and an exclusive lock, removed, and the private RAM
directory removed. The local harness allowlist is corrected. The service exit
is recorded separately from the successful proof results.

Evidence: `target/compact-witness-pipeline-20261108/FINAL-EVIDENCE.tar.gz`, SHA-256
`bc5afe51fbaa817358eaac9dbb3f0fd8136ce1b74ee812fefa8514ea0f2812a1`.
`FINAL-QUALIFICATION.json` records the build identities, source hashes,
measurements, restoration and cleanup receipts. This is a local research
candidate based on published source `e0b16e233cfcedd3fffba4559d5a5f7b918e7522`;
the published v0.4.0 kit and public seed have not been changed.

Build the matching worker with `tools/compact-multigpu/prepare-shared-model.py`
and the pinned CUDA/Rust environment. Its default output is the separate
`target/compact-witness-pipeline-20261108` directory. With the matching worker
and controller installed, set `CMFD_WITNESS_PIPELINE=1` alongside the existing
`--shared-model` pool configuration. The pipeline is opt-in; the existing
sequential path remains available when the variable is omitted.
