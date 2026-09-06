# RTX 5090 replay kernel qualification

Measured on September 6, 2026 against RC5 source
`ae00bcacde01aaf1e54dcc0297d388165d677af2`, with an RTX 5090, Windows driver
610.88, WSL2, CUDA 12.8, and pinned CUTLASS 3.9.2.

The previous replay worker used the SM75 `8x8x16` integer MMA with a
`128x128x64` threadblock and a two-stage synchronous pipeline on every GPU.
SM12.0 now selects the SM80-compatible `16x8x32` integer MMA with a
`128x128x128` threadblock and a three-stage asynchronous pipeline. Integer
accumulation, field reduction, activation, model bytes, and protocol are unchanged.

Other GPU architectures retain the original kernel. A kernel image compiled
from compute_75 PTX also retains the original kernel, even on an SM12.0 GPU:
dispatch checks the loaded function's PTX virtual architecture before selecting
the newer implementation. Both paths run the existing CPU differential check.

## Measurements

The GPU's existing 400 W limit and clock settings were unchanged. Pool replay
and proof workers remained on the same GPU throughout testing. Power readings
therefore describe the whole GPU, including pool work.

| Measurement | Original RC5 | Optimized worker |
| --- | --- | --- |
| Live console search rate | 9.51 FW/s | 27.56–29.71 FW/s over the first minute |
| Live console power readings | 397.65 W | 283.77–337.14 W over the first minute |
| Full-model GPU search, 32 lanes | 2.652–2.915 seconds | 0.546–0.634 seconds |
| Full-model GPU search rate | 10.98–12.07 FW/s | 50.49–58.65 FW/s |

The original worker was measured both before and after the optimized worker,
with five batches per run. The live result is about three times faster; the
GPU-only result excludes output-file transfer and client-side checking and
must not be presented as the live miner rate. The first minute of live mining
accepted six shares with zero rejected or stale shares in that miner session.
At 2 minutes 32 seconds, the same session had 19 accepted shares, zero rejected
or stale shares, and one pool block using the unchanged pool proof worker.

## Correctness and compatibility

- All fifteen deterministic 32-lane batches produced the same complete final
  activation SHA-256: `af00acd819105bff07257d3b711f5ba66a49e88c9a81d6cf0b0889c48de1da08`.
- Independent random coefficients tested batches of 1, 32, and 64. Every
  output byte matched RC5, including agreement of the first lane across sizes.
- All three full intermediate dynamic trace files and the final activation
  matched RC5 byte for byte for the random single-lane fixture. This covers all
  384 layers and both preactivation and activation traces.
- Native SM12.0 and a separately built compute_75-only PTX executable both
  passed the CPU differential and full-model batch comparisons. The PTX-only
  executable reported the legacy backend. Environment switches alone were
  not used as evidence of fallback selection.
- The candidate includes native SM75, SM86, SM89, and SM120 images plus
  compute_75 PTX. Physical 20/30/40-series performance was not retested.

The installed candidate worker SHA-256 is
`2ed754f6e10e832a453ad1ca9673f0671fbb234351583cf60722c4732d2d8a83`.
The original RC5 worker SHA-256 is
`d963d838ec319d4471722335a2c2da17f9cee7a777ab4e9218d3c224f4bb7728`.
This is a local miner candidate; the signed public RC5 packages were not replaced.
