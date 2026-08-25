# ForgeMatrix v2 CUDA miner

The activated path in this optional backend accelerates the exact tiny
ForgeMatrix-v2 relation used by Common Foundry Devnet-0. It works in both
**Solo** and **Pool** mode in the desktop wallet. If the library is absent, the
wallet uses the CPU reference evaluator.

The library also contains a separate dormant evaluator for the exact 6 GiB
production geometry described below. That evaluator is not wired into mining
or consensus activation, and it is not the succinct prover. Mainnet remains
disabled.

## Supported NVIDIA generations

The packaged fat library contains native CUDA images for:

| Architecture | CUDA target | Representative cards |
| --- | --- | --- |
| Volta | `sm_70` | Tesla V100, Titan V, Quadro GV100 |
| RTX 20 series (Turing) | `sm_75` | RTX 2060 through RTX 2080 Ti |
| RTX 30 series (Ampere) | `sm_86` | RTX 3060 through RTX 3090 Ti |
| RTX 40 series (Ada) | `sm_89` | RTX 4060 through RTX 4090 |
| RTX 50 series (Blackwell) | `sm_120` | RTX 5060 through RTX 5090 |

A `compute_70` PTX image is included for the DP4A path, and a `compute_75` PTX
image carries the signed-INT8 Tensor Core kernel to compatible newer NVIDIA
architectures that do not have an exact native image in the package.
CUDA Toolkit 12.9 is used intentionally because it can compile both Volta and
Blackwell targets. CUDA 13 removed offline compilation support for Volta. The
prebuilt library uses the static CUDA runtime, so testers need a compatible
NVIDIA driver but do not need to install the CUDA toolkit.

The desktop wallet drives one selected GPU. The separate `cmfd-miner` package
automatically drives every supported GPU in a rig with one CUDA context and
worker per device. Its normal mode receives immutable mining templates from a
node rather than synchronizing another chain database. See
[Standalone CUDA miner](standalone-miner.md) for its Windows batch-file setup
and multi-GPU behavior.

## Exact trust boundary

1. Rust derives the consensus-bound BLAKE3 challenge and rejection-sampled mask
   coefficients for a bounded nonce batch.
2. CUDA evaluates the centered INT8 inputs and weights. The inner products use
   exact signed `INT8 x INT8` DP4A accumulation into INT32, followed by the
   specified transition-field cubic and canonical byte reduction.
3. Rust constructs the output and work digests and checks the requested target.
4. Any candidate below the solo or pool target is fully recomputed by the Rust
   consensus implementation. A disagreement disables CUDA and falls back to
   CPU; an accelerator result is never sufficient to accept a block or credit
   a pool share.

This design makes a CUDA bug a performance or availability failure rather than
a consensus bypass. The displayed `matrix attempts/s` measures complete nonce
attempts through this pipeline, not raw GPU TOPS.

## Dormant production-geometry evaluator

The same library now contains a separate, fail-closed production evaluator.
It does **not** replace the tiny Devnet ABI and it is not selected by the node,
wallet, or standalone miner. Its fixed geometry is:

- 128 activation rows by 4,096 columns;
- 384 ordered 4,096 by 4,096 weight layers in three 128-layer banks;
- 524,288 activation bytes and 6,442,450,944 authenticated weight bytes;
- 385 challenge-mask stages with 20 canonical coefficients per nonce.

Construction requires the non-serializable
`BankAuthenticatedDoryV3ModelCommitmentRecordV2` capability used by the Dory V3
verifier plus its exact deterministic setup. Rust validates the complete
production Record V2 and setup before allocating GPU state. The manifest,
three-bank role layout, Dory model identity, and record/model digests are then
taken only from that capability; callers cannot supply a separate legacy
`ModelPcsIdentity` or loose manifest.

While the model bank is streamed, its header, payload roots, length, and EOF are
reauthenticated against the capability's manifest. Canonical Goldilocks model
elements are converted back to centered INT8 and uploaded in order. A usable
context is published only after the full 6,442,975,232-byte payload
authenticates and CUDA confirms every role byte was uploaded. The context
retains the complete immutable Dory identity plus both Record V2 binding
digests so it can be compared with the verifier capability. A read error,
altered byte, different manifest or record, setup mismatch, skipped chunk,
missing production ABI, non-CUDA backend, or unsupported GPU destroys the
provisional context.

The evaluator has two exact residency modes. `FullDevice` retains all
6,442,450,944 weight bytes in VRAM and transposes them once at finalization.
`HostBacked` retains the same authenticated bytes in owned host memory and
streams one canonical 16 MiB layer into one 16 MiB device buffer, then
transposes it into a second 16 MiB device buffer. Its fixed device allocation
is about 36 MiB plus coefficients and CUDA runtime overhead, so a 6 GB RTX 2060
does not need a reduced model or geometry. `Auto` selects full residency only
when current free VRAM can hold the complete allocation; explicit selection
fails instead of silently changing modes.

Both modes use exact signed `INT8 x INT8 -> INT32` accumulation, the same
coordinate mask, the 134,217,689 transition-field cubic, and reduction modulo
251 as Rust. `Auto` selects the pinned CUTLASS 3.9.2 Tensor Core GEMM on compute
capability 7.5 and newer. Volta uses the exact DP4A engine, as does a library
intentionally built without CUTLASS. Explicit `TensorCore` or `Dp4a` selection
fails rather than silently changing engines. The maximum absolute inner
product is `4,096 x 125 x 125 = 64,000,000`, so every prefix and final sum is
within signed INT32 even though the generated Tensor Core instruction is the
saturating signed-INT8 form.

There is no dummy power loop. CUTLASS is header-only and compiled into the
existing static-CUDA-runtime DLL, so the package does not add a cuBLAS,
CUTLASS, or CUDA Toolkit runtime installation requirement. The source is
pinned to CUTLASS commit
`ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e`; configuration rejects any other
checkout, and binary packages include its BSD-3-Clause notice.

The qualification seam runs the same transpose, selected matrix engine, mask,
cubic, and output encoding code without activating production consensus:

```powershell
$env:CMFD_CUDA_MINER_LIBRARY = '<absolute-path-to-cmfd-forgematrix-v2-miner.dll>'
cargo run --release -p cmfd-cuda --example production_differential
```

On August 25, 2026, an RTX 5090 (driver 610.88, compute capability 12.0) with a
CUDA 12.9.86 build matched Rust byte-for-byte for both forced residency modes
and both forced matrix engines:

| Vector | Residency | Engine | Values | BLAKE3 output digest | GPU time |
| --- | --- | --- | ---: | --- | ---: |
| Dense 4 x 32 | Host backed | DP4A | 128 | `bd24f76f7269c861b72d904240d5a862233a4dd759564cf1e0c5811326e2ece5` | 85.682 ms |
| Dense 4 x 32 | Host backed | Tensor Core | 128 | `bd24f76f7269c861b72d904240d5a862233a4dd759564cf1e0c5811326e2ece5` | 1.188 ms |
| Dense 4 x 32 | Full device | DP4A | 128 | `bd24f76f7269c861b72d904240d5a862233a4dd759564cf1e0c5811326e2ece5` | 0.865 ms |
| Dense 4 x 32 | Full device | Tensor Core | 128 | `bd24f76f7269c861b72d904240d5a862233a4dd759564cf1e0c5811326e2ece5` | 0.475 ms |
| Full-K bound 2 x 4,096 | Host backed | DP4A | 8,192 | `697bc338594beb7d9f56d89b2a4753df837cbb2f301607064f444f29b2ad8fbf` | 5.501 ms |
| Full-K bound 2 x 4,096 | Host backed | Tensor Core | 8,192 | `697bc338594beb7d9f56d89b2a4753df837cbb2f301607064f444f29b2ad8fbf` | 5.208 ms |
| Full-K bound 2 x 4,096 | Full device | DP4A | 8,192 | `697bc338594beb7d9f56d89b2a4753df837cbb2f301607064f444f29b2ad8fbf` | 3.551 ms |
| Full-K bound 2 x 4,096 | Full device | Tensor Core | 8,192 | `697bc338594beb7d9f56d89b2a4753df837cbb2f301607064f444f29b2ad8fbf` | 3.066 ms |
| One full 128 x 4,096 layer | Host backed | DP4A | 524,288 | `36661181f19654dc9d8f40bccf296372e511fb48aff18cba05762c28553e08bd` | 16.094 ms |
| One full 128 x 4,096 layer | Host backed | Tensor Core | 524,288 | `36661181f19654dc9d8f40bccf296372e511fb48aff18cba05762c28553e08bd` | 5.571 ms |
| One full 128 x 4,096 layer | Full device | DP4A | 524,288 | `36661181f19654dc9d8f40bccf296372e511fb48aff18cba05762c28553e08bd` | 12.864 ms |
| One full 128 x 4,096 layer | Full device | Tensor Core | 524,288 | `36661181f19654dc9d8f40bccf296372e511fb48aff18cba05762c28553e08bd` | 4.086 ms |

Those timings include qualification allocation, upload, and weight transpose;
the first row also includes CUDA context initialization. They are not
steady-state hashrate. The full-K vector drives every 4,096-term accumulator to
either +64,000,000 or -64,000,000 before the field transition and matched the
independent Rust result in every forced mode. A separate zero-centered canary
forced each residency mode, uploaded all three banks, traversed all 384 layers,
and matched its analytical all-zero 524,288-byte output:

| Residency | Engine | Allocation | Upload | Finalize | One nonce |
| --- | --- | ---: | ---: | ---: | ---: |
| Host backed | DP4A | 0.082 s | 1.258 s | 0.000 s | 6.055 s |
| Host backed | Tensor Core | 0.000 s | 1.078 s | 0.000 s | 0.505 s |
| Full device | DP4A | 0.010 s | 0.354 s | 0.006 s | 5.782 s |
| Full device | Tensor Core | 0.010 s | 0.372 s | 0.005 s | 0.129 s |

The canary proves exact buffer shape, layer traversal, and matching output in
both storage paths and both matrix engines. A 64-nonce sustained FullDevice
Tensor Core run took 7.743 seconds (0.1210 seconds per nonce). Across 70 busy
100 ms telemetry samples, the RTX 5090 reported maximum utilization of 99%,
median 172.24 W and maximum 172.45 W, a maximum 3,097 MHz graphics clock,
maximum 43 C, and maximum 10,614 MiB total device-memory use as reported by
`nvidia-smi` on the active desktop GPU. These measurements
come from the exact production geometry and contain no synthetic power-burn
kernel.

The all-zero canary is deliberately simple enough to have an independently
known output. It does not prove the identity or output of the ceremony model.
A build with CUTLASS omitted was also checked separately: `Auto` selected DP4A,
while an explicit Tensor Core request failed closed with no active context.

A complete authenticated 384-layer ceremony-model run and winning-nonce proof
remain required before this path can be selected for an activated network.

## Build on Windows

Requirements:

- NVIDIA CUDA Toolkit 12.8 or 12.9;
- Visual Studio 2022 C++ Build Tools;
- CMake and Ninja;
- Git, to acquire and verify the pinned CUTLASS source;
- the Rust toolchain used by the repository.

From the repository root:

```powershell
$releaseCommit = '<full-lowercase-release-commit>'
.\scripts\build-cuda-miner.ps1 -ExpectedCommit $releaseCommit
```

The script acquires the exact pinned CUTLASS commit, builds
`target\gpu-miner-build\cmfd-forgematrix-v2-miner.dll`,
checks for native `sm_70`, `sm_75`, `sm_86`, `sm_89`, and `sm_120` images,
confirms both the `compute_70` DP4A and `compute_75` Tensor Core PTX fallbacks,
runs the Devnet CPU/CUDA differential, and then runs the dense and
production-geometry Rust/CUDA vectors above. It also emits an identity-only
`.build-receipt`; this receipt detects mixed inputs but is not a signature or
authenticated build attestation.
An existing verified checkout may be supplied with `-CutlassRoot`; the build
still rejects it unless its HEAD is the pinned commit and its worktree is clean.

To build a Windows wallet installer that bundles the library:

```powershell
$env:CMFD_RELEASE_COMMIT = '<full-release-commit>'
Set-Location .\apps\wallet
npm ci
npm run desktop:build:cuda:windows
```

For a raw wallet executable, place `cmfd-forgematrix-v2-miner.dll` beside
`common-foundry-wallet.exe`. An operator may instead set
`CMFD_CUDA_MINER_LIBRARY` to the DLL's absolute path.

## Tester procedure for RTX 20 and RTX 30

Record the release tag, DLL SHA-256, Windows version, NVIDIA driver, exact GPU,
and VRAM size. Then:

1. Launch the CUDA-enabled wallet and open **Mining**.
2. Start Solo mining. Confirm the Engine row names the NVIDIA GPU and its CUDA
   capability instead of `CPU reference evaluator`.
3. Run for at least 15 minutes. Record attempts/s, blocks found, restarts, and
   any `CUDA unavailable; CPU fallback active` message.
4. Stop and restart mining twice. Close and reopen the wallet once, then repeat.
5. If a pool endpoint is available, run Pool mode for at least 15 minutes and
   record accepted/rejected shares. A correct backend should not cause a rise in
   rejected shares.
6. Attach sanitized screenshots and logs to the Devnet test issue. Do not post
   wallet keys, pool private keys, private IP addresses, or personal paths.

The RTX 20/30 result is not considered complete from startup alone. It should
include sustained work, a clean stop/restart, and either an accepted solo block
or accepted pool shares.
