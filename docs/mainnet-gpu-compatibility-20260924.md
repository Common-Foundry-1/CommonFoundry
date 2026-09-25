# Mainnet replay compatibility candidate - September 24, 2026

This is a private source/build checkpoint, not a signed replacement release or
approval to start mainnet. The signed `a8b23ec` baseline remains preserved.

## Gap and implementation

The signed baseline replay worker contains only SM89 and SM120 native images,
with no PTX fallback. That is narrower than the requested Volta and RTX 20-50
pool-miner coverage. The replay/search worker now has a separate build target
matrix: SM70, SM75, SM80, SM86, SM89, SM90 and SM120, plus compute_70 PTX.

Volta and the portable compute_70 image use a tiled signed INT8 DP4A kernel with
INT32 accumulation. The maximum production dot product magnitude is 2^26, within
INT32. Native Turing retains the existing SM75 Tensor Core path, and native Ada
and Blackwell retain their existing optimized paths. Four-limb reconstruction,
field reduction, model identity, proof relation and work digest are unchanged.

The worker's `--self-test` adds CPU differential checks for partial tiles, signed
extrema and K=4096. Those tests are implemented but have not yet been executed
on the new candidate GPU binary. A forced compute_70 run on a recent card is not
physical Volta qualification.

## Build evidence completed

- The new build helper checks the pinned, clean CUTLASS checkout, every compiler
  target and the actual native/PTX output images. Existing workers are preserved.
- Sixteen GPU-free replay-build regression tests passed, including rejection of
  missing targets, wrong PTX, unsupported reproducibility options and reused
  intermediate directories. Exact default/dual build-plan tests passed.
- The combined Linux build/service/launcher run passed 36 tests, with two
  Windows-only cases skipped. A separate native Windows launcher run passed all
  nine cases, including those two Windows paths.
- Two initial unseeded compilations differed. Both artifacts and their logs are
  retained as failed reproducibility evidence, not accepted release inputs.
- With pinned CUDA 12.9.1 and the builder's `--reproducible` mode, two new builds
  using different output and intermediate directories matched byte-for-byte:
  3,212,024 bytes; SHA-256
  `f820434ab3c1743036c59da6fced71275e1a8b677a25afff72ee137f04af39e4`.
- Both matching outputs contain all seven native targets and compute_70 PTX.
  This is an internal same-toolchain repeat build, not external reproduction.
  A subsequent canonical committed-source export produced different bytes
  (`f3482f74c6eaacb408592b3173d0a34181ca47c2e6a0c7b1ae59d847a42cb451`):
  CUDA's anonymous-namespace kernel names included an absolute-path hash.
  Therefore the matching worktree outputs are not final release candidates.
- A compile-only two-directory fixture confirmed that a stable named namespace
  removes that path dependence. The replay source now uses `cmfd_v4_replay`;
  clean-source full-target rebuilds and all GPU qualification remain required.

Compiler symbol seeding does not seed cryptographic randomness or mining nonces.
Keep the toolchain, dependency checkout, source hashes, intermediates and logs
with the candidate; reproduce again from the frozen final source before signing.

## Runtime and release checks still required

1. Isolated native and forced-PTX self-tests on the exact candidate bytes.
2. Full-model replay and search equality against the authenticated reference,
   complete resulting proof generation and separate CPU proof verification.
3. Physical older-card checks and multi-GPU accepted-share qualification; record
   exact GPUs, drivers and memory capacity rather than inferring coverage from
   successful compilation.
4. Final frozen-source reproduction, package assembly, updated qualification
   evidence and fresh signatures for every changed artifact.

The resident-model 32-lane search requires approximately 6.45 GiB before driver
and display overhead. The current path does not fit a 6 GB GPU. An 8 GB capacity
target is not a completed hardware test. Pool-client replay/search support does
not imply that the full proof worker supports all of these GPU generations.

AI01's public RC pool was still active during this checkpoint. No new GPU test
ran, no live service was stopped and no mainnet service was enabled. An owner
decision to pause the RC pool for isolated checks is pending. The source and
mining publication schedule remains October 2 and October 3 respectively,
at noon America/Chicago (17:00 UTC).
