# RTX 50-series miner qualification

Measured September 6, 2026. Source commit:
`619334c2cdcc57063a248e31dab7e67c6e9d3540`.

The update improves large-batch activation reuse on SM120 and removes repeated
four-byte BLAKE3 calls from the miner's CPU validation step. It preserves all
field validation, output bytes, network identity, verifier behavior, clock
settings, and configured power limits.

## Changes

The SM120 worker selects the existing locality-oriented integer Tensor Core
kernel for batches of at least 32 forwards: 128x256x64 threadblocks,
64x64x64 warp tiles, 16x8x32 MMA, three pipeline stages, and CUTLASS identity
swizzle 8. Adjacent output-column tiles reuse activation rows before sweeping
the rest of the batch. Batch 32 has a 64 MiB activation matrix, 16 MiB layer
weights, and 256 MiB accumulator output. This mapping reduces repeated
activation reads; timing supports the locality explanation, but DRAM traffic
was not directly profiled.

Smaller SM120 batches and full single-forward proofs retain the previously
qualified 128x128x128 kernel. The threshold preserves small-batch latency:
the wider prototype did not consistently help at batches 4 and 8. SM89 keeps
its existing locality kernel. Other devices and compute-75 PTX fallback keep
the legacy kernel. Both SM120 kernel images must report loaded PTX version
at least 80 before their dispatch is enabled.

The client still validates every canonical little-endian field element.
After validation, it hashes the complete nonce activation with one BLAKE3
update instead of 524,288 four-byte updates. Domain separation, challenge,
length, byte order, digest, and errors are unchanged. The consensus digest
and the offline CLI helper are unchanged.

## RTX 5070 Ti: isolated kernel comparison

Hardware: mini43, GPU `GPU-797a08ac-d698-f280-84b4-16b968d475c9`.
The native miner agent stopped Pearl and CPU mining for each bounded test;
an empty GPU process list was verified. Native mining was restored between
windows, guarded by an independent restoration timer. The existing 265 W
limit and 7001 MHz memory setting were retained.

| Measurement | Previous SM120 worker | Updated worker |
| --- | ---: | ---: |
| Full-model batch 32 GPU rate | 12.09 FW/s | 29.02 FW/s |
| Full-model batch 64 GPU rate | 11.97 FW/s | 29.26 FW/s |
| Live console median, unchanged client | 11.29 FW/s | 24.63 FW/s |
| Live console range | 11.21–11.66 FW/s | 24.53–25.56 FW/s |
| Median reported power | 155.505 W | 226.62 W |
| Accepted / rejected / stale shares | 7 / 0 / 0 | 20 / 0 / 0 |
| Pool blocks | 1 | 0 |
| Bounded client duration | 105.82 s | 150.92 s |

The kernel-only live rate improved 2.182x. Power draw increased with useful
GPU work; the power-limit setting stayed unchanged. Final multiarchitecture
worker qualification independently measured 29.02 FW/s at batch 32 and
29.26 FW/s at batch 64. CUDA event times exclude host output transfer,
validation, and pool interaction. Live console rates include the synchronous
search work, including host validation, but exclude time spent waiting for
share submission and separate pool polling.

## RTX 5090 GPU comparison

TIM's existing 400 W limit and clock settings were retained. Its miner was
stopped during worker tests, but the local pool also uses the GPU for share
and block verification. These results therefore have a shared-GPU limitation.

Batch 32 remained approximately 54 GPU FW/s, with no clear kernel-only gain.
At batch 64, the earlier tile was approximately 36–37 GPU FW/s while the
locality tile reached approximately 52–54 GPU FW/s. The production miner uses
batch 32; the batch-64 result is not a claim about its live rate. The main
additional 5090 opportunity in this update is reducing CPU validation time.

## CPU validation measurement

On the native Windows host, seven alternating rounds hashed the same complete
32-forward output, with validation included and all digests compared:

| Full 64 MiB batch | Median | Range |
| --- | ---: | ---: |
| Existing four-byte hash updates | 159.6116 ms | 157.5399–166.7649 ms |
| Complete-nonce hash updates | 8.3777 ms | 8.0618–11.2003 ms |

This saves 151.2339 ms per fully inspected batch. A search that finds a share
early can inspect fewer nonces, so this is a CPU benchmark rather than a
predicted live-rate increase.

## Final client and worker live qualification

The RTX 5070 Ti ran the exact final Linux client and worker for 150.42 seconds,
exiting successfully. Its median console rate was **27.59 FW/s**
(27.53–27.70 FW/s), with median reported consumption of **252.41 W** under the
unchanged 265 W limit. That is 2.444x the 11.29 FW/s baseline and 12.02% above
the 24.63 FW/s kernel-only run.

The console recorded 26 accepted, two rejected, and one stale share. The pool
ledger recorded 26 accepted and one rejected share, classified as stale, with
the worker disconnected after the test. The pool advanced from height 18 to
19 during the run. There was no ledger-recorded invalid-work rejection.
The extra console failure was not classified by a captured response code;
an existing pool-retry reporting issue is a plausible explanation, not a
confirmed diagnosis. These counts are retained rather than describing the
combined run as reject-free.

mini43 returned to native Pearl at approximately 174.5 TH/s, with a fresh
accepted share at 19:37:09 UTC and a fresh CPU-miner acceptance. No Common
Foundry process or pool socket remains; all five restoration timers are
inactive. The temporary model was removed from `/dev/shm`, leaving about
9.4 GB available memory. The native configuration hash stayed
`d57b71871b5b29d2996ec338c15907b2c0c094b250b6c39de8e2d7ea167ea931`,
with the original 265 W cap and 7001 MHz memory setting.

TIM's RTX 5090 then ran the previous and final client/worker pairs sequentially
against the same RCNet pool:

| RTX 5090 live measurement | Previous pair | Final pair |
| --- | ---: | ---: |
| Console samples | 16 | 23 |
| Median rate | 29.535 FW/s | 34.84 FW/s |
| Rate range | 28.82–31.62 FW/s | 34.26–35.15 FW/s |
| Median reported power | 300.57 W | 281.87 W |
| Pool accepted / rejected / stale | 16 / 0 / 0 | 29 / 0 / 0 |
| Bounded wall duration, including startup | 110 s | 160 s |

The live median increased **17.96%**. Startup accounts for approximately
26–31 seconds of each wall duration. Both test worker identities disconnected
at completion. The candidate's last console sample showed 27 acceptances;
the final pool ledger confirmed 29 after the remaining submissions. The
local pool/proof worker continued sharing this GPU. Power values are medians
of instantaneous console readings, not energy-normalized efficiency results.

The exact qualified client and worker were installed into TIM's existing
standalone miner folder, with both previous binaries backed up under
`C:\Source\_ops\commonfoundry-blackwell-20260906\tim-before-update`.
The original command line, payout, pool, worker name, and visible console were
preserved. Installation verification at 19:40:03.749 UTC confirmed matching
binary hashes and a fresh pool acceptance, with the connected miner reporting
approximately 34.73 FW/s. Historic TIM rejection counters precede this
installation; the bounded final-candidate test had zero rejected or stale
shares. TIM remains on Common Foundry; mini43 is back on Pearl.

## Correctness and compatibility

- RTX 5070 Ti: randomized batches 1, 16, 31, 32, and 64 matched the previous
  optimized worker byte-for-byte, including batch prefixes. All three complete
  intermediate replay banks matched. Compute-75 PTX-only output matched all
  five batch shapes and selected `sm75_m8n8k16`.
- RTX 5090: randomized batches 1, 32, and 64, batch prefixes, and all three
  full intermediate replay banks matched the previous optimized worker.
  Compute-75 PTX-only output matched all three batch shapes.
- All worker startup CPU differential checks reported `EXACT`.
- Five focused pool-module tests passed under `production-rc`, including a
  complete 2 MiB activation digest compared with the unchanged consensus
  implementation and rejection of noncanonical first and last field values.
  Formatting and diff checks passed.
- Both delivered clients report RCNet-1 network ID
  `3e99d45959c19c0053d8e9fef34875b57b46a8a1ce330637daddab515bc7b92d`,
  ProductionV4, and source commit `619334c2cdcc57063a248e31dab7e67c6e9d3540`.
  The existing activation gate and its qualification pins are unchanged.

Full trace equality qualifies proof inputs. It does not constitute a new
standalone end-to-end proof latency benchmark. Live tests are short acceptance
runs, and other physical 50-series models were not measured.

## Build and delivery

CUDA worker: CUDA 12.8.93, CUTLASS 3.9.2 commit
`ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e`, `nvcc -O3 -std=c++17`.
Native SM75, SM86, SM89, and SM120 images plus compute-75 PTX are included.
The Windows client uses rustc 1.94.1 and static CRT. The Linux x86_64 client
uses rustc 1.98.0. Both use locked release builds with `production-rc`, release
label `0.1.0-rc.5`, and the truthful signed source commit above.

| Artifact | SHA256 |
| --- | --- |
| Cross-generation worker | `34d200619e1f3eb2a197e08ab27209edc3ea4a818832d11776445294e09b0ba9` |
| Windows client | `4d30f4f63525ce5ccf0acae633ec6ea109cb75a9ffb23b865b34a16635becf23` |
| Linux client | `54b91f81b4b5b9a44132eba38113f1c05900a7a7a823d4a2a92fe0f4ec8c3884` |
| PTX-only qualification worker | `0ffaf76a6f4da72bc32e1e90fb6be9b94c8ea87356b0abc12b54def89f5d8f8a` |
| Previous optimized worker | `2ed754f6e10e832a453ad1ca9673f0671fbb234351583cf60722c4732d2d8a83` |
| Unchanged model | `5f9b213c3bda51b74e4ebabb26607b67385d613aa8d99af915a48ab063e17d4e` |

The drop-in update packages contain the worker, the correct OS client,
installation/rollback instructions, license and notices, checksums, build
provenance, source patch, and this validation record. They are local performance
updates; public signed release assets were not replaced.

Raw build logs, CPU timings, worker qualification, live logs, telemetry, and
restoration records are under
`C:\Source\_ops\commonfoundry-blackwell-20260906`.
