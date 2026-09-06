# Ada replay kernel qualification

Measured September 6, 2026 on mini18, RTX 4070 Ti SUPER
`GPU-dd3821fd-5e73-2eb4-389b-a3a0fbf68765`, NVIDIA driver 580.173.02.
Production worker: CUDA 12.8, pinned CUTLASS 3.9.2 commit
`ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e`.

## Change and cause

SM89 now selects an SM80-compatible integer Tensor Core GEMM with
128x256x64 threadblocks, 64x64x64 warp tiles, 16x8x32 MMA, three pipeline
stages, and CUTLASS identity swizzle 8. Adjacent output-column tiles reuse the
same activation rows before traversing the rest of the large batch.

The old 128x128 tile and swizzle 1 traverse all batch rows before advancing
to another output-column tile. A batch 32 multiplication has a 64 MiB
activation matrix, 16 MiB weights, and 256 MiB output. Microbenchmarks that
changed only tile order isolated a large locality improvement; this supports
the cache-reuse explanation, but does not measure DRAM traffic.
The CUDA driver reports 48 MiB of L2 cache on this card, smaller than the
batch's activation matrix alone.

| Warm matrix test, batch 32 | Time per GEMM |
| --- | ---: |
| Original SM75, 128x128x64, swizzle 1 | 7.77 ms |
| Same SM75 kernel, swizzle 8 | 2.22–2.30 ms |
| SM80, 128x128x64, swizzle 1 | 7.78 ms |
| SM80, 128x256x64, swizzle 1 | 4.43 ms |
| Selected SM80, 128x256x64, swizzle 8 | 1.923–1.924 ms |

The microbench used CUDA 13.2 native SM89, compared every INT32 output against
the legacy kernel, repeated batch 32, and checked batch 1. Production tests
below use CUDA 12.8. The selected kernel uses 72 KiB shared memory, within
Ada's 99 KiB per-block limit; CUTLASS performs the required dynamic-memory
opt-in. [NVIDIA Ada tuning guide](https://docs.nvidia.com/cuda/ada-tuning-guide/)

## Controlled full-model performance

Pearl was fully stopped through its native agent command, and GPU process
enumeration confirmed no remaining compute client before each test.
The original 260 W power limit, 2640 MHz configured core setting, 5001 MHz
memory setting, and mining configuration were preserved. Actual boost clocks
and power draw naturally respond to workload.

The same 384-layer model and 32-lane input fixture were used for three original
and three updated runs:

| Measurement | Original cross-generation worker | Ada worker |
| --- | ---: | ---: |
| GPU batch times | 3.586853 / 3.580562 / 3.585952 s | 1.322975 / 1.323624 / 1.322929 s |
| Mean GPU throughput | 8.93 FW/s | 24.18 FW/s |
| Throughput ratio | 1.00x | 2.71x |

The multiarchitecture deliverable independently reproduced 1.322673 s for a
random batch 32 and 2.621551 s for batch 64 during qualification. GPU times
exclude host output transfer, validation, and pool interactions.

The same standalone client then ran each worker against the same live pool:

| Live console measurement | Original worker | Ada worker |
| --- | ---: | ---: |
| Run duration | 107.13 s | 150.39 s |
| Median rate | 8.33 FW/s | 20.285 FW/s |
| Rate range | 8.27–8.48 FW/s | 20.06–20.98 FW/s |
| Median reported power | 139.45 W | 198.59 W |
| Accepted / rejected / stale shares | 7 / 0 / 0 | 20 / 0 / 0 |
| Pool blocks | 0 | 1 |

Live throughput increased 2.435x (+143.5%). These are short console samples;
the rate and power medians imply approximately 1.71x work per watt. Power
draw increased as more GPU work was performed, with the same 260 W limit.
Both clients and the bounded test service exited successfully. Native Pearl
and CPU mining were restored with their original command arguments and
configuration hash, and no Common Foundry test processes remained.
Detailed restoration evidence is recorded in the local RESULTS.md and logs.

### Correction to the earlier 4070 comparison

The earlier result, 4.05 FW/s in the GPU benchmark and 3.75 FW/s in the console,
came from a test that suspended Pearl's host processes without establishing
exclusive GPU use. That procedure can leave GPU work in flight and is not a
valid isolated throughput baseline. With Pearl fully stopped, the same
original worker measured 8.93 FW/s in the GPU benchmark.
The 2.71x improvement above uses the corrected, exclusive-GPU original and
candidate measurements. The earlier 5070 test fully stopped Pearl and is
unaffected. A third-party 3060 Ti report still lacks matching build/workload
details and was not used to calculate this speedup.

## Correctness and compatibility

The worker's mathematical operations, coefficient decoding, field reduction,
activation, output encodings, model, verifier, and protocol are unchanged.
The new tile mapping keeps independent output tiles with `beta = 0` and
`split_k_slices = 1`.

- Startup CPU differential: EXACT for legacy, Ada native, and PTX fallback.
- One randomized coefficient fixture seeded 4070, sliced into batches 1/32/64.
  Every complete native and fallback output matches the legacy worker.
- Batch 1 matches the first lane of the larger batches; the entire batch 32
  output matches the first 32 lanes of batch 64.
- Full single-lane replay: final output matches batch 1, and all three 512 MiB
  intermediate bank files match the original byte-for-byte. This validates
  proof-input trace equality; no new end-to-end proof benchmark was run.
- All six initial deterministic batch 32 outputs match SHA256
  `af00acd819105bff07257d3b711f5ba66a49e88c9a81d6cf0b0889c48de1da08`.
- SM89 dispatch requires loaded `ptxVersion >= 80`. The compute_75-only build
  selected `sm75_m8n8k16` and passed the same randomized batch comparisons.
- SM120 retains the previously qualified kernel. Other devices retain legacy
  dispatch. Other physical 40-series GPUs have not been tested.

Candidate markers: `sm80_m16n8k32_128x256_sw8` on native SM89,
`sm75_m8n8k16` on the PTX-only fallback.

## Artifact and reproduction

Candidate worker SHA256:
`af424e38bb91aa7a711afb56bd005dbab5f5781b22a9bcb8b928b869ffb2053b`

Legacy reference SHA256:
`e01d2e4d4b4e7eeac40111c0bb3f88acebbca7a752b4a8e9b22b09a4f2c4a434`

Model SHA256:
`5f9b213c3bda51b74e4ebabb26607b67385d613aa8d99af915a48ab063e17d4e`

Native images: SM75, SM86, SM89, SM120; fallback: compute_75 PTX.
The source was built with `nvcc -O3 -std=c++17`, the pinned CUTLASS include
directory, and one `-gencode arch=compute_N,code=sm_N` per native image plus
`-gencode arch=compute_75,code=compute_75`.

Local scripts, build log, checksums, telemetry, benchmark outputs, qualification
manifest, live logs, and restoration records are under
`C:\Source\_ops\commonfoundry-ada-performance-20260906`.
Remote large trace evidence remains under the corresponding
`/opt/commonfoundry-ada-performance-20260906/qualification` directory.
The public signed release packages were not replaced.
